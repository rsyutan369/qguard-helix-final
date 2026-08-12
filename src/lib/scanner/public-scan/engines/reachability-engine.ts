/**
 * QGuard Helix — Endpoint Reachability Engine
 *
 * One TCP connect to the assessed port, before any cryptographic probing.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every other engine in this bundle assumes the port answers. When it does not,
 * each one discovers that independently and pays its own timeout for the
 * privilege: the TLS engine spent 3 × 15s on the primary handshake, the
 * certificate engine another 16s, the HTTP engine 8s more. Measured against a
 * filtered port that a single TCP connect refuses in 200ms, the assessment took
 * **66.7 seconds** and then reported four stages as "FAILED" — which reads to an
 * operator as "this endpoint failed four security controls" when the truth is
 * "nothing answered on port 443, so nothing was measured".
 *
 * Reachability is therefore established ONCE, cheaply, and shared. It is not an
 * optimisation bolted onto the side: it is the fact every downstream verdict
 * depends on, so measuring it separately is what lets the report distinguish
 *
 *     "the endpoint answered and its cryptography is weak"      (a finding)
 * from
 *     "the endpoint did not answer"                             (no finding)
 *
 * which the platform's status contract (see `contract.ts`) requires and which no
 * amount of downstream timeout handling can reconstruct after the fact.
 *
 * WHAT IT DOES NOT DO
 * -------------------
 * It never upgrades a verdict. A successful TCP connect proves only that
 * something accepted a socket — TLS, certificate and HTTP evidence still come
 * from the engines that actually measure them. This engine can only establish
 * that the doorbell rang.
 */

import net from 'node:net'
import { safeLookup, checkHostSyntax, BlockedAddressError } from '../safe-dns'
import { type EngineResult, type Evidence, runEngine } from './contract'

/**
 * Default ceiling for one connect attempt.
 *
 * Sized against SYN retransmission, which is what a genuinely slow-but-alive
 * endpoint actually looks like: the initial SYN is retried at ~1s and ~3s, so 4s
 * still catches a host that lost two SYNs in a row — and the whole probe is
 * repeated once on top of that. Round-trip time is not the constraint; even the
 * longest intercontinental path is under 400ms, so this is ten times the latency
 * any reachable endpoint needs.
 *
 * It exists to bound SILENCE, not slowness. A server too slow to complete a TCP
 * handshake in 4s twice has already failed the budget of every real client.
 */
export const REACHABILITY_TIMEOUT_MS = 4_000

/**
 * The five outcomes, kept distinct because they demand different words in the
 * report and different actions from the reader:
 *
 *   open         The port accepted a TCP connection. Assessment proceeds.
 *   refused      RST / ECONNREFUSED. Nothing is listening — a *definitive*
 *                answer, and the fastest one. The service is not deployed here.
 *   filtered     No response within the budget. A firewall or ACL is silently
 *                dropping packets. Indistinguishable from "host down" from
 *                outside, and stated as such rather than guessed at.
 *   unreachable  The network itself rejected the route (EHOSTUNREACH /
 *                ENETUNREACH). The address is not routable from here.
 *   blocked      SSRF containment refused the target (private/reserved space).
 *                A scanner decision, never a statement about the endpoint.
 *   unresolved   No usable address record. Nothing to connect to.
 */
export type ReachabilityState =
  | 'open'
  | 'refused'
  | 'filtered'
  | 'unreachable'
  | 'blocked'
  | 'unresolved'

export interface ReachabilityIntelligence {
  state: ReachabilityState
  /** True only for `open`. The single predicate every downstream engine reads. */
  reachable: boolean
  /** Measured TCP connect time in ms. Null when no connection was established. */
  tcpConnectMs: number | null
  /** The address the socket actually connected to (or last attempted). */
  address: string | null
  /** Socket error code, verbatim, when there was one. */
  code: string | null
  /** Operator-readable statement of what happened, safe to render directly. */
  detail: string
  /**
   * Compact form for places that repeat the reason — surface cards, per-module
   * details, chart captions. `detail` is a full sentence and is right for the one
   * place that explains the outcome; echoing it on four cards and three
   * observations turned every panel into the same 120-character paragraph.
   */
  summary: string
  /**
   * The reason downstream engines quote when they report Unknown. Null when the
   * port is open, because then there is nothing to excuse.
   */
  unreachableReason: string | null
}

export function emptyReachability(detail = 'Reachability not probed.'): ReachabilityIntelligence {
  return {
    state: 'filtered',
    reachable: false,
    tcpConnectMs: null,
    address: null,
    code: null,
    detail,
    summary: 'reachability not probed',
    unreachableReason: detail,
  }
}

/** Compact reason phrase, one per state. Reads correctly after "Not collected — ". */
function summaryFor(state: ReachabilityState, port: number, connectMs: number | null): string {
  switch (state) {
    case 'open':
      return connectMs === null ? `port ${port} open` : `port ${port} open · TCP ${connectMs}ms`
    case 'refused':
      return `port ${port} refused the connection`
    case 'filtered':
      return `port ${port} did not answer`
    case 'unreachable':
      return 'the address is not routable'
    case 'blocked':
      return 'the target is outside public address space'
    case 'unresolved':
      return 'the hostname does not resolve'
  }
}

/** Map a socket error onto the outcome vocabulary above. */
function classifyError(err: NodeJS.ErrnoException): { state: ReachabilityState; detail: string } {
  if (err instanceof BlockedAddressError || err.code === 'SSRF_BLOCKED') {
    return { state: 'blocked', detail: err.message }
  }
  switch (err.code) {
    case 'ECONNREFUSED':
      return { state: 'refused', detail: 'Connection refused — nothing is listening on this port.' }
    case 'ECONNRESET':
      // A reset during the TCP handshake is a refusal wearing different
      // clothing: something on the path actively rejected the connection.
      return { state: 'refused', detail: 'Connection reset during the TCP handshake.' }
    case 'EHOSTUNREACH':
      return { state: 'unreachable', detail: 'Host unreachable — no route to this address.' }
    case 'ENETUNREACH':
      return { state: 'unreachable', detail: 'Network unreachable — the address is not routable from the scanner.' }
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return { state: 'unresolved', detail: 'The hostname could not be resolved to a public address.' }
    case 'ETIMEDOUT':
      return { state: 'filtered', detail: 'Connection attempt timed out at the network layer.' }
    default:
      return {
        state: 'filtered',
        detail: `TCP connection failed: ${err.code ?? err.message}`,
      }
  }
}

/**
 * A single TCP connect, SSRF-contained by BOTH halves of the model in
 * `safe-dns`: `checkHostSyntax` for literal addresses and `safeLookup` for
 * resolved ones.
 *
 * Both are required, and the first is easy to forget. Node's `net.connect`
 * SKIPS the `lookup` hook entirely when `host` is already an IP address, so a
 * pinning lookup alone cannot see — let alone block — `169.254.169.254` or
 * `10.0.0.5`. Passing `lookup` and calling it contained is precisely the mistake
 * the header comment in `safe-dns.ts` exists to warn about, and the check
 * harness asserts loopback is refused here for exactly that reason.
 *
 * Nothing is written to the socket. It is destroyed the instant the connection
 * is established — this measures reachability, it does not speak any protocol.
 */
export function probeReachability(
  host: string,
  port: number,
  timeoutMs: number = REACHABILITY_TIMEOUT_MS,
): Promise<ReachabilityIntelligence> {
  return new Promise((resolve) => {
    const startedAt = Date.now()
    let settled = false
    let address: string | null = net.isIP(host) ? host : null

    // Literal-address and blocked-name check, before a packet is sent.
    const syntax = checkHostSyntax(host)
    if (!syntax.ok) {
      const detail = syntax.message ?? 'Target is not permitted for public assessment.'
      resolve({
        state: 'blocked',
        reachable: false,
        tcpConnectMs: null,
        address,
        code: syntax.code ?? 'PRIVATE_TARGET',
        detail,
        summary: summaryFor('blocked', port, null),
        unreachableReason: detail,
      })
      return
    }

    const finish = (value: Omit<ReachabilityIntelligence, 'reachable' | 'unreachableReason' | 'summary'>) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket.destroy()
      } catch {
        /* already torn down */
      }
      const reachable = value.state === 'open'
      resolve({
        ...value,
        summary: summaryFor(value.state, port, value.tcpConnectMs),
        reachable,
        unreachableReason: reachable ? null : value.detail,
      })
    }

    const socket = net.connect({
      host,
      port,
      lookup: safeLookup,
    })

    socket.on('lookup', (_err, resolved) => {
      if (typeof resolved === 'string' && resolved) address = resolved
    })

    socket.on('connect', () => {
      const ms = Date.now() - startedAt
      // `remoteAddress` is the authoritative answer to "what did we reach",
      // whereas the lookup event only reports what was offered.
      address = socket.remoteAddress ?? address
      finish({
        state: 'open',
        tcpConnectMs: ms,
        address,
        code: null,
        detail: `TCP connect succeeded in ${ms}ms${address ? ` to ${address}` : ''}.`,
      })
    })

    socket.on('error', (err: NodeJS.ErrnoException) => {
      const { state, detail } = classifyError(err)
      finish({ state, tcpConnectMs: null, address, code: err.code ?? null, detail })
    })

    const timer = setTimeout(
      () =>
        finish({
          state: 'filtered',
          tcpConnectMs: null,
          address,
          code: null,
          detail: `No response on port ${port} within ${timeoutMs}ms — the port is filtered or the host is down.`,
        }),
      timeoutMs,
    )
  })
}

/**
 * States that are DEFINITIVE on one sample, because the network answered.
 *
 * The evidence asymmetry the named-group probe already relies on applies here
 * too: a RST, an ICMP unreachable or a resolver failure is a response, and a
 * response cannot be manufactured by packet loss. Silence can — so `filtered`
 * (no response at all) is the one verdict that gets confirmed before the whole
 * assessment is stood down on the strength of it.
 */
const DEFINITIVE_STATES: ReadonlySet<ReachabilityState> = new Set<ReachabilityState>([
  'open',
  'refused',
  'unreachable',
  'blocked',
  'unresolved',
])

export async function runReachabilityEngine(
  host: string,
  port: number,
  timeoutMs: number = REACHABILITY_TIMEOUT_MS,
  /** Wall-clock the engine may spend in total, including the confirming probe. */
  budgetMs: number = REACHABILITY_TIMEOUT_MS * 2 + 500,
): Promise<EngineResult<ReachabilityIntelligence>> {
  return runEngine('endpoint-reachability', emptyReachability(), async () => {
    const startedAt = Date.now()
    const perProbe = Math.max(1_000, Math.min(timeoutMs, budgetMs))
    let data = await probeReachability(host, port, perProbe)
    let confirmed = false

    // Silence is falsifiable; everything else already answered. Standing the
    // entire assessment down on a single dropped SYN would turn one lost packet
    // into a report that says nothing about the target, so it is re-probed once
    // when there is budget for it.
    if (!DEFINITIVE_STATES.has(data.state)) {
      const remaining = budgetMs - (Date.now() - startedAt)
      if (remaining > 1_400) {
        await new Promise((resolve) => setTimeout(resolve, 400))
        const second = await probeReachability(host, port, Math.max(1_000, Math.min(perProbe, remaining - 400)))
        confirmed = true
        // A second attempt that connects overturns the first outright — that is
        // precisely the transient-loss case this pass exists to catch.
        if (second.reachable) {
          data = second
        } else {
          // Both fields carry the SAME sentence. They are rendered in different
          // places (the stage rail reads `unreachableReason`, the report header
          // reads `detail`) and a reader seeing two subtly different accounts of
          // one measurement has no way to tell which is authoritative.
          const detail = `${second.detail} Confirmed on a second attempt.`
          data = { ...second, detail, unreachableReason: detail }
        }
      }
    }

    const evidence: Evidence[] = [
      {
        label: 'TCP reachability',
        observedValue: data.reachable
          ? `open · ${data.tcpConnectMs}ms`
          : `${data.state} · ${data.code ?? 'no response'}`,
        detectionMethod: 'TLS handshake',
        evidenceSource: confirmed
          ? `two TCP connect attempts to ${data.address ?? host}:${port}`
          : `TCP connect to ${data.address ?? host}:${port}`,
        confidence: 100,
      },
    ]

    return {
      data,
      // The engine reached a conclusion in every branch — "refused" is an
      // answer, not a failure to measure. `ok` reports that the probe ran, and
      // `data.state` carries what it found.
      ok: true,
      confidence: 100,
      evidence,
      notes: data.reachable
        ? []
        : [
            `Port ${port} did not accept a TCP connection (${data.state}${confirmed ? ', confirmed on a second attempt' : ''}). ` +
              'TLS, certificate and HTTP controls are reported as Unknown — not as failures — because no evidence could be collected from this endpoint.',
          ],
      error: null,
    }
  })
}
