/**
 * QGuard Helix — TLS Intelligence Engine
 *
 * Protocol negotiation, cipher suites, ALPN, named groups (including hybrid
 * post-quantum groups), session resumption, compression, renegotiation and
 * forward secrecy.
 *
 * The protocol / cipher enumeration is delegated to the platform's existing
 * `web-scanner/tls-analyzer`, so /public-scan and /dashboard/scanner observe the
 * edge through exactly the same code path. This engine adds the properties that
 * analyser does not expose, and the named-group probing that turns post-quantum
 * readiness from an inference into a measurement.
 */

import tls from 'node:tls'
import net from 'node:net'
import { safeLookup } from '../safe-dns'
import { analyzeTls } from '../../web-scanner/tls-analyzer'
import type { CipherSuiteDetail, TlsAnalysisResult } from '../../web-scanner/types'
import {
  type Evidence,
  type EngineResult,
  type ObservationSink,
  clampScore,
  observationEmitter,
  runEngine,
} from './contract'

const HANDSHAKE_TIMEOUT = 8_000
const GROUP_PROBE_TIMEOUT = 5_000
/**
 * Wall-clock ceiling for the whole named-group phase. Probing is deliberately
 * sequential and now covers twice as many groups with a confirmation pass, so
 * an unresponsive endpoint could otherwise walk the scan straight into the
 * request timeout. When the budget runs out the remaining groups are recorded
 * as INCONCLUSIVE and said so in the notes — never as rejected.
 */
const GROUP_PHASE_BUDGET_MS = 40_000

/**
 * Courtesy gap between consecutive probes.
 *
 * This is not padding. A public scanner that fires thirty back-to-back TLS
 * handshakes at a stranger's edge is the direct cause of the throttling that
 * corrupts its own measurements — the RST that comes back reads exactly like
 * "group not supported". Spacing the probes is what makes a sequential sweep
 * of this size safe to point at production infrastructure, and it is why the
 * results are trustworthy enough to sample rather than guess.
 */
const PROBE_PACING_MS = 150

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * Named groups probed individually. Offering exactly one group and observing
 * whether the handshake completes is the only way to prove hybrid PQ support
 * from outside: Node does not expose the negotiated TLS 1.3 group.
 *
 * Three kinds, and they are NOT interchangeable:
 *
 *   hybrid      ECDHE + ML-KEM. The deployable post-quantum answer today: the
 *               classical half keeps the session safe if ML-KEM is broken, the
 *               ML-KEM half defeats harvest-now-decrypt-later.
 *   pure-pq     Standalone ML-KEM, no classical hedge. Real, registered, and
 *               increasingly offered — but a different risk posture, so it is
 *               reported separately and never folded into the hybrid count.
 *   classical   The migration surface. Which curves and which finite-field
 *               groups an endpoint still accepts is what a migration plan is
 *               built from: a server pinned to ffdhe2048 has a different path
 *               than one on X25519, and "brainpool accepted" tells a European
 *               compliance team something "TLS 1.3 enabled" does not.
 */
type GroupKind = 'hybrid' | 'pure-pq' | 'classical'

const HYBRID_PQ_GROUPS = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024'] as const
const PURE_PQ_GROUPS = ['MLKEM512', 'MLKEM768', 'MLKEM1024'] as const
const CLASSICAL_GROUPS = [
  'X25519',
  'P-256',
  'P-384',
  'P-521',
  'X448',
  'brainpoolP256r1tls13',
  'brainpoolP384r1tls13',
  'brainpoolP512r1tls13',
  'ffdhe2048',
  'ffdhe3072',
  'ffdhe4096',
] as const

function groupKind(group: string): GroupKind {
  if ((HYBRID_PQ_GROUPS as readonly string[]).includes(group)) return 'hybrid'
  if ((PURE_PQ_GROUPS as readonly string[]).includes(group)) return 'pure-pq'
  return 'classical'
}

/**
 * How many times a group is sampled before its verdict is believed.
 *
 * Post-quantum groups get three because they carry the report's headline claim:
 * asserting or denying ML-KEM support on one handshake against a rate-limiting
 * edge is how a scanner ends up publishing the wrong answer to the only
 * question most visitors came to ask.
 */
function samplesFor(kind: GroupKind): number {
  return kind === 'classical' ? 2 : 3
}

/**
 * Groups the LOCAL OpenSSL build cannot even offer.
 *
 * `tls.connect` throws synchronously for an unknown `ecdhCurve`, and that throw
 * means "this scanner cannot test it", not "the endpoint refused it". Probing
 * such a group and recording a rejection would publish a negative result the
 * scan never actually measured. The set is computed once against a socket that
 * is destroyed immediately — no packet is sent to anyone.
 */
let locallyUnsupportedGroups: ReadonlySet<string> | null = null

function localGroupSupport(): ReadonlySet<string> {
  if (locallyUnsupportedGroups) return locallyUnsupportedGroups
  const unsupported = new Set<string>()
  for (const group of [...HYBRID_PQ_GROUPS, ...CLASSICAL_GROUPS]) {
    try {
      // Port 1 on the loopback interface: the options are validated by OpenSSL
      // during construction, which is the check we want, and the socket is torn
      // down before it can complete a connection. Nothing leaves the machine.
      const probe = tls.connect({ host: '127.0.0.1', port: 1, ecdhCurve: group })
      probe.on('error', () => {})
      probe.destroy()
    } catch {
      unsupported.add(group)
    }
  }
  locallyUnsupportedGroups = unsupported
  return unsupported
}

/** ML-KEM parameter set carried by each hybrid group, per the TLS registry. */
export const HYBRID_GROUP_KEM: Record<string, string> = {
  X25519MLKEM768: 'ML-KEM-768',
  SecP256r1MLKEM768: 'ML-KEM-768',
  SecP384r1MLKEM1024: 'ML-KEM-1024',
}

/**
 * The two halves of each hybrid group, named separately.
 *
 * A hybrid group is a COMBINATION, and a report that prints only the registry
 * name ("X25519MLKEM768") makes the reader decode it. Both components are named
 * so the evidence line can state what protects the session classically and what
 * protects it against a CRQC — they are different guarantees with different
 * failure modes, and collapsing them loses the whole point of hybrid.
 */
export const HYBRID_GROUP_COMPONENTS: Record<string, { classical: string; postQuantum: string }> = {
  X25519MLKEM768: { classical: 'X25519 (Curve25519 ECDHE)', postQuantum: 'ML-KEM-768 (FIPS 203)' },
  SecP256r1MLKEM768: { classical: 'secp256r1 / P-256 ECDHE', postQuantum: 'ML-KEM-768 (FIPS 203)' },
  SecP384r1MLKEM1024: { classical: 'secp384r1 / P-384 ECDHE', postQuantum: 'ML-KEM-1024 (FIPS 203)' },
}

export const GROUP_LABELS: Record<string, string> = {
  X25519MLKEM768: 'X25519 + ML-KEM-768 (hybrid)',
  SecP256r1MLKEM768: 'P-256 + ML-KEM-768 (hybrid)',
  SecP384r1MLKEM1024: 'P-384 + ML-KEM-1024 (hybrid)',
  X25519: 'X25519 (ECDHE)',
  'P-256': 'secp256r1 (ECDHE)',
  'P-384': 'secp384r1 (ECDHE)',
  'P-521': 'secp521r1 (ECDHE)',
  X448: 'X448 (ECDHE)',
  brainpoolP256r1tls13: 'brainpoolP256r1 (ECDHE)',
  brainpoolP384r1tls13: 'brainpoolP384r1 (ECDHE)',
  brainpoolP512r1tls13: 'brainpoolP512r1 (ECDHE)',
  ffdhe2048: 'ffdhe2048 (finite-field DHE)',
  ffdhe3072: 'ffdhe3072 (finite-field DHE)',
  ffdhe4096: 'ffdhe4096 (finite-field DHE)',
  MLKEM512: 'ML-KEM-512 (standalone PQ)',
  MLKEM768: 'ML-KEM-768 (standalone PQ)',
  MLKEM1024: 'ML-KEM-1024 (standalone PQ)',
}

export interface TlsTiming {
  tcpConnectMs: number | null
  tlsHandshakeMs: number | null
  totalMs: number | null
}

export interface TlsIntelligence {
  handshake: TlsAnalysisResult | null
  supportedProtocols: string[]
  legacyProtocols: string[]
  negotiatedProtocol: string | null
  negotiatedCipher: string | null
  cipherSuites: CipherSuiteDetail[]

  alpn: string | null
  alpnOffered: string[]
  http2: boolean

  hybridGroups: string[]
  /**
   * Standalone ML-KEM groups accepted (no classical hedge). Kept separate from
   * `hybridGroups` on purpose — see `probeNamedGroups`.
   */
  pureKemGroups: string[]
  classicalGroups: string[]
  primaryGroup: string | null
  groupsProbed: boolean
  /**
   * Groups where the handshake completed but the server ignored our offer, so
   * nothing can be concluded about them either way.
   */
  inconclusiveGroups: string[]
  /**
   * False when hybrid ML-KEM probing was skipped because the endpoint does not
   * negotiate TLS 1.3 — the groups are then genuinely unsupported, not untested.
   */
  hybridProbed: boolean
  /** Groups the local OpenSSL build cannot offer, so nothing was measured. */
  untestableGroups: string[]
  /** Groups whose repeat samples disagreed — the endpoint answered unstably. */
  unstableGroups: string[]
  /** Handshakes actually spent enumerating groups. Provenance, not an estimate. */
  groupHandshakes: number

  forwardSecrecy: boolean
  forwardSecrecyBasis: string
  staticRsaAccepted: boolean

  sessionTickets: boolean | null
  sessionReuse: boolean | null
  compression: string | null
  secureRenegotiation: boolean | null

  timing: TlsTiming
  error: string | null
}

export function emptyTls(error: string | null = null): TlsIntelligence {
  return {
    handshake: null,
    supportedProtocols: [],
    legacyProtocols: [],
    negotiatedProtocol: null,
    negotiatedCipher: null,
    cipherSuites: [],
    alpn: null,
    alpnOffered: ['h2', 'http/1.1'],
    http2: false,
    hybridGroups: [],
    pureKemGroups: [],
    classicalGroups: [],
    primaryGroup: null,
    groupsProbed: false,
    inconclusiveGroups: [],
    hybridProbed: false,
    untestableGroups: [],
    unstableGroups: [],
    groupHandshakes: 0,
    forwardSecrecy: false,
    forwardSecrecyBasis: 'No handshake completed.',
    staticRsaAccepted: false,
    sessionTickets: null,
    sessionReuse: null,
    compression: null,
    secureRenegotiation: null,
    timing: { tcpConnectMs: null, tlsHandshakeMs: null, totalMs: null },
    error,
  }
}

// ─── Named-group probing ──────────────────────────────────────────────────────

/**
 * `inconclusive` is distinct from `rejected`: the handshake completed, but the
 * server ignored our offered group list, so the result says nothing about that
 * group and must not be reported either way.
 */
type GroupProbeResult = 'accepted' | 'rejected' | 'inconclusive' | 'transient'

/** Errors meaning "throttled or dropped", not "group unsupported". */
const TRANSIENT_CODES = new Set(['ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED', 'EPIPE', 'EAI_AGAIN'])

/**
 * Offer exactly one named group and decide whether the server actually used it.
 *
 * A completed handshake is NOT sufficient evidence on its own. Offering only
 * `X25519MLKEM768` to a TLS 1.2-only server produced a successful handshake that
 * negotiated `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` — the server ignored the
 * group list entirely. Counting that as "hybrid ML-KEM accepted" would have
 * credited post-quantum readiness to a server that cannot do TLS 1.3 at all,
 * which is the single most damaging false positive this scanner could produce.
 *
 * So the negotiated connection is inspected:
 *  • Hybrid ML-KEM groups live only in the TLS 1.3 `key_share` extension, so
 *    anything that did not negotiate TLS 1.3 is a rejection.
 *  • Under TLS 1.3 the key share always comes from the offered groups, so a
 *    completed 1.3 handshake proves the single offered group was used.
 *  • Under TLS 1.2 an EC group is only proven used if an ECDHE suite was
 *    negotiated. A fallback to DHE or static RSA means our list was ignored.
 */
function probeGroup(
  host: string,
  port: number,
  group: string,
  isHybrid: boolean,
): Promise<GroupProbeResult> {
  return new Promise((resolve) => {
    let settled = false
    const finish = (value: GroupProbeResult) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket?.destroy()
      } catch {
        /* already torn down */
      }
      resolve(value)
    }

    let socket: tls.TLSSocket | undefined
    try {
      // An ecdhCurve name the local OpenSSL build does not know throws
      // synchronously — that means "cannot test", not "not supported".
      socket = tls.connect(
        {
          host,
          port,
          servername: net.isIP(host) ? undefined : host,
          lookup: safeLookup,
          // nosemgrep: bypass-tls-verification -- assessment probe, not a client.
          // "Does this endpoint accept group X" must be answerable for
          // endpoints with expired or untrusted chains. Nothing is sent.
          rejectUnauthorized: false,
          // Hybrid groups are TLS 1.3-only; pinning the floor stops a 1.2
          // fallback from masquerading as post-quantum support.
          minVersion: isHybrid ? 'TLSv1.3' : 'TLSv1.2',
          ecdhCurve: group,
          timeout: GROUP_PROBE_TIMEOUT,
        },
        () => {
          const protocol = socket?.getProtocol() ?? ''
          const cipher = socket?.getCipher()?.standardName ?? socket?.getCipher()?.name ?? ''

          if (protocol === 'TLSv1.3') {
            // TLS 1.3 derives the key share from the offered groups — proven.
            finish('accepted')
            return
          }
          if (isHybrid) {
            // A hybrid group cannot have been used outside TLS 1.3.
            finish('rejected')
            return
          }
          // TLS 1.2: only an ECDHE suite proves the EC group was used.
          finish(/ECDHE/i.test(cipher) ? 'accepted' : 'inconclusive')
        },
      )
    } catch {
      // The local OpenSSL cannot offer this group. That is a limitation of the
      // scanner, not an answer about the endpoint — pre-filtering means this is
      // rarely reached, and when it is it must not read as a rejection.
      resolve('inconclusive')
      return
    }

    socket.on('error', (err: NodeJS.ErrnoException) =>
      finish(TRANSIENT_CODES.has(err.code ?? '') ? 'transient' : 'rejected'),
    )
    socket.on('timeout', () => finish('transient'))
    const timer = setTimeout(() => finish('transient'), GROUP_PROBE_TIMEOUT)
  })
}

/**
 * Named-group enumeration.
 *
 * STRICTLY SEQUENTIAL, AND DELIBERATELY SLOW
 * ------------------------------------------
 * One probe at a time, never a batch. Firing probes concurrently trips the
 * per-IP connection limits of CDNs and load balancers, and a throttled RST is
 * indistinguishable from "group not supported" — a false negative on the single
 * most important measurement this scanner makes. The previous two-at-a-time
 * batching was a compromise for wall-clock time; measurement integrity is worth
 * more than the seconds it saved, and the live hero now has real events to show
 * for the duration.
 *
 * EVERY RESULT IS CONFIRMED
 * -------------------------
 * Each group is sampled TWICE. When the two samples agree the answer is taken.
 * When they disagree — which is exactly what a rate-limited endpoint produces —
 * a third sample breaks the tie, and the disagreement is recorded so the report
 * can say the measurement was unstable rather than pretending it was clean.
 *
 * `supportsTls13` short-circuits the hybrid probes entirely: a server that never
 * negotiates TLS 1.3 cannot support a TLS 1.3-only group, so that is answered
 * from evidence already in hand rather than by doomed handshakes.
 */
async function probeNamedGroups(
  host: string,
  port: number,
  supportsTls13: boolean,
  emit: ObservationSink,
) {
  const unsupportedLocally = localGroupSupport()
  // ML-KEM groups, hybrid or standalone, exist only in the TLS 1.3 key_share.
  // An endpoint that never negotiates 1.3 is answered from evidence in hand.
  const requested = [
    ...(supportsTls13 ? [...HYBRID_PQ_GROUPS, ...PURE_PQ_GROUPS] : []),
    ...CLASSICAL_GROUPS,
  ]
  const untestable = requested.filter((group) => unsupportedLocally.has(group))
  const groups = requested.filter((group) => !unsupportedLocally.has(group))

  const deadline = Date.now() + GROUP_PHASE_BUDGET_MS
  const verdicts = new Map<string, GroupProbeResult>()
  const unstable: string[] = []
  const budgetSkipped: string[] = []
  /** Handshakes actually spent — reported as provenance, never estimated. */
  let handshakes = 0

  for (const group of groups) {
    const kind = groupKind(group)
    const pq = kind !== 'classical'
    const label = GROUP_LABELS[group] ?? group

    if (Date.now() >= deadline) {
      budgetSkipped.push(group)
      verdicts.set(group, 'inconclusive')
      continue
    }

    emit({
      surface: pq ? 'quantum' : 'tls',
      label: group,
      detail: `Offering ${label} in isolation`,
      status: 'info',
      severity: 'info',
    })

    // Sample the group several times. A single answer from an edge that is
    // rate-limiting is an opinion, not a measurement.
    const samples: GroupProbeResult[] = []
    const wanted = samplesFor(kind)
    for (let attempt = 0; attempt < wanted; attempt += 1) {
      if (attempt > 0) await sleep(PROBE_PACING_MS)
      // Every ML-KEM group, hybrid or standalone, lives only in the TLS 1.3
      // key_share — so both get the 1.3 floor and the 1.3-only interpretation.
      samples.push(await probeGroup(host, port, group, pq))
      handshakes += 1
      // Once the remaining samples cannot change a unanimous answer, stop
      // spending handshakes on the target.
      if (samples.length >= 2 && new Set(samples).size === 1 && Date.now() >= deadline) break
    }

    // Plurality wins. `transient` is kept as its own answer through the tally:
    // a connection that is consistently reset for one offered group is the
    // endpoint refusing that group, and calling it "inconclusive" would bury a
    // real negative result.
    const tally = new Map<GroupProbeResult, number>()
    for (const sample of samples) tally.set(sample, (tally.get(sample) ?? 0) + 1)
    const ranked = [...tally.entries()].sort((a, b) => b[1] - a[1])
    const agreed = tally.size === 1

    let verdict: GroupProbeResult
    if (agreed) {
      verdict = samples[0]
    } else if (ranked[0][1] > ranked[1][1]) {
      verdict = ranked[0][0]
      unstable.push(group)
    } else {
      // A genuine split with no plurality. Nothing is claimed.
      verdict = 'inconclusive'
      unstable.push(group)
    }

    // A consistently reset connection for a single offered group means the
    // endpoint has no key share it is willing to use — a refusal.
    if (verdict === 'transient') verdict = 'rejected'
    verdicts.set(group, verdict)

    emit({
      surface: pq ? 'quantum' : 'tls',
      label: group,
      detail:
        verdict === 'accepted'
          ? `${label} accepted${kind === 'hybrid' ? ' — hybrid ML-KEM confirmed' : kind === 'pure-pq' ? ' — standalone ML-KEM confirmed' : ''}`
          : verdict === 'rejected'
            ? `${label} not offered by this endpoint`
            : `${label} inconclusive — endpoint answered inconsistently`,
      status: verdict === 'accepted' ? 'pass' : verdict === 'rejected' ? 'info' : 'warning',
      severity: verdict === 'inconclusive' ? 'low' : 'none',
      postQuantum: kind === 'hybrid' && verdict === 'accepted',
    })

    await sleep(PROBE_PACING_MS)
  }

  for (const group of untestable) {
    verdicts.set(group, 'inconclusive')
  }

  const accepted = groups.filter((group) => verdicts.get(group) === 'accepted')
  const inconclusive = [...verdicts.entries()]
    .filter(([, verdict]) => verdict === 'inconclusive')
    .map(([group]) => group)

  return {
    hybridGroups: accepted.filter((group) => groupKind(group) === 'hybrid'),
    // Standalone ML-KEM is reported on its own and deliberately NOT merged into
    // `hybridGroups`: the grading model scores hybrid deployment, and quietly
    // counting a no-classical-hedge group as hybrid would inflate readiness.
    pureKemGroups: accepted.filter((group) => groupKind(group) === 'pure-pq'),
    classicalGroups: accepted.filter((group) => groupKind(group) === 'classical'),
    inconclusiveGroups: inconclusive,
    hybridProbed: supportsTls13,
    untestableGroups: untestable,
    unstableGroups: unstable,
    budgetSkippedGroups: budgetSkipped,
    handshakes,
  }
}

// ─── Session / ALPN / renegotiation probe ─────────────────────────────────────

interface SessionProbe {
  alpn: string | null
  sessionTickets: boolean | null
  sessionReuse: boolean | null
  compression: string | null
  timing: TlsTiming
}

/**
 * One handshake that offers ALPN and captures session-resumption behaviour,
 * then a second connection replaying the session to see whether the server
 * actually honours resumption.
 */
function probeSession(host: string, port: number): Promise<SessionProbe> {
  return new Promise((resolve) => {
    let settled = false
    const startedAt = Date.now()
    let tcpConnectedAt: number | null = null
    let ticketSeen = false

    const finish = (value: SessionProbe) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket.destroy()
      } catch {
        /* already torn down */
      }
      resolve(value)
    }

    const socket = tls.connect(
      {
        host,
        port,
        servername: net.isIP(host) ? undefined : host,
        lookup: safeLookup,
        // nosemgrep: bypass-tls-verification -- assessment probe, not a client.
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
        timeout: HANDSHAKE_TIMEOUT,
      },
      () => {
        const secureAt = Date.now()
        const session = socket.getSession()

        const timing: TlsTiming = {
          tcpConnectMs: tcpConnectedAt === null ? null : tcpConnectedAt - startedAt,
          tlsHandshakeMs: tcpConnectedAt === null ? null : secureAt - tcpConnectedAt,
          totalMs: secureAt - startedAt,
        }

        const base: SessionProbe = {
          alpn: socket.alpnProtocol || null,
          // A session blob being issued at all is the ticket signal.
          sessionTickets: ticketSeen || Boolean(session),
          sessionReuse: null,
          compression: null,
          timing,
        }

        if (!session) {
          finish(base)
          return
        }

        // Replay the session to see whether the server honours resumption.
        const replay = tls.connect(
          {
            host,
            port,
            servername: net.isIP(host) ? undefined : host,
            lookup: safeLookup,
            // nosemgrep: bypass-tls-verification -- assessment probe, not a client.
            rejectUnauthorized: false,
            session,
            timeout: GROUP_PROBE_TIMEOUT,
          },
          () => {
            const reused = replay.isSessionReused()
            replay.destroy()
            finish({ ...base, sessionReuse: reused })
          },
        )
        replay.on('error', () => {
          replay.destroy()
          finish(base)
        })
        replay.on('timeout', () => {
          replay.destroy()
          finish(base)
        })
      },
    )

    socket.on('connect', () => {
      tcpConnectedAt = Date.now()
    })
    socket.on('session', () => {
      ticketSeen = true
    })
    socket.on('error', () =>
      finish({
        alpn: null,
        sessionTickets: null,
        sessionReuse: null,
        compression: null,
        timing: { tcpConnectMs: null, tlsHandshakeMs: null, totalMs: null },
      }),
    )
    socket.on('timeout', () =>
      finish({
        alpn: null,
        sessionTickets: null,
        sessionReuse: null,
        compression: null,
        timing: { tcpConnectMs: null, tlsHandshakeMs: null, totalMs: null },
      }),
    )

    const timer = setTimeout(
      () =>
        finish({
          alpn: null,
          sessionTickets: null,
          sessionReuse: null,
          compression: null,
          timing: { tcpConnectMs: null, tlsHandshakeMs: null, totalMs: null },
        }),
      HANDSHAKE_TIMEOUT,
    )
  })
}

// ─── Forward secrecy ──────────────────────────────────────────────────────────

export function deriveForwardSecrecy(
  handshake: TlsAnalysisResult | null,
  hybridGroups: string[],
  classicalGroups: string[],
): { enabled: boolean; basis: string } {
  // TLS 1.3 removes every static key-transport suite from the protocol, so a
  // completed 1.3 handshake IS proof of forward secrecy — regardless of what
  // Node reports for the ephemeral key (it returns {} for TLS 1.3).
  if (handshake?.tlsVersion === 'TLSv1.3' || handshake?.supportedProtocols.includes('TLSv1.3')) {
    return { enabled: true, basis: 'TLS 1.3 mandates ephemeral (EC)DHE — every session key is forward secret.' }
  }
  const accepted = [...hybridGroups, ...classicalGroups]
  if (accepted.length) {
    return {
      enabled: true,
      basis: `Ephemeral key agreement confirmed by offering ${GROUP_LABELS[accepted[0]] ?? accepted[0]} in isolation.`,
    }
  }
  if (/ecdhe|dhe|x25519|ffdhe/i.test(handshake?.keyExchange ?? '')) {
    return { enabled: true, basis: `Ephemeral key agreement negotiated: ${handshake?.keyExchange}.` }
  }
  return { enabled: false, basis: 'No ephemeral key agreement observed at the edge.' }
}

/** Display string for the negotiated key exchange. */
export function describeKeyExchange(intel: TlsIntelligence): string {
  if (intel.primaryGroup) {
    return intel.hybridGroups.length
      ? `Hybrid ECDHE + ML-KEM (${intel.primaryGroup})`
      : `ECDHE (${intel.primaryGroup})`
  }
  const raw = intel.handshake?.keyExchange ?? ''
  if (raw && raw !== 'unknown') return raw
  if (intel.handshake?.tlsVersion === 'TLSv1.3') return 'ECDHE (TLS 1.3 ephemeral)'
  return 'unknown'
}

/**
 * `analyzeTls` with transient-failure retry.
 *
 * The analyser opens ~12 sockets to enumerate protocols and cipher suites. Hosts
 * that rate-limit per source IP (CDNs, and deliberately-misconfigured test
 * endpoints like badssl.com) reset some of those connections under that burst,
 * and a reset on the *primary* handshake made the whole engine report
 * "TLS Handshake FAILED" for an endpoint that was plainly reachable — the
 * certificate engine, which already retried, returned a full chain from the same
 * host in the same scan. Reporting a reachable endpoint as unreachable is the
 * worst failure mode this scanner has, so a reset is retried with backoff before
 * it is believed.
 *
 * Only transient signatures are retried. A genuine refusal (handshake failure,
 * unsupported protocol, DNS NXDOMAIN, SSRF block) is a real answer and is
 * returned on the first attempt without wasting the scan's time budget.
 */
const TRANSIENT_HANDSHAKE_PATTERNS = [
  /ECONNRESET/i,
  /ETIMEDOUT/i,
  /EPIPE/i,
  /EAI_AGAIN/i,
  /socket hang up/i,
  /timeout/i,
]

function isTransientHandshakeError(message: string): boolean {
  return TRANSIENT_HANDSHAKE_PATTERNS.some((pattern) => pattern.test(message))
}

async function analyzeTlsResilient(
  host: string,
  port: number,
): Promise<{ handshake: TlsAnalysisResult | null; error: string | null; attempts: number }> {
  const maxAttempts = 3
  let lastError: string | null = null

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return { handshake: await analyzeTls(host, port), error: null, attempts: attempt }
    } catch (err) {
      lastError = (err as Error).message
      // A definitive answer is not worth retrying.
      if (!isTransientHandshakeError(lastError) || attempt === maxAttempts) break
      // Back off so the retry does not land inside the same rate-limit window
      // that reset the previous attempt.
      await new Promise((resolve) => setTimeout(resolve, attempt * 600))
    }
  }

  return { handshake: null, error: lastError, attempts: maxAttempts }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

export async function runTlsEngine(
  host: string,
  port: number,
  onObservation?: ObservationSink,
): Promise<EngineResult<TlsIntelligence>> {
  return runEngine('tls-intelligence', emptyTls(), async () => {
    const evidence: Evidence[] = []
    const notes: string[] = []
    const emit = observationEmitter(onObservation)

    const { handshake, error, attempts } = await analyzeTlsResilient(host, port)
    if (!handshake) {
      const data = emptyTls(error)
      notes.push(
        `TLS handshake did not complete after ${attempts} attempt${attempts === 1 ? '' : 's'}; protocol and cipher controls report Unknown.`,
      )
      emit({
        surface: 'tls',
        label: 'TLS handshake',
        detail: error ?? 'Handshake could not be completed',
        status: 'critical',
        severity: 'high',
        verdict: 'No handshake',
      })
      return { data, ok: false, confidence: 0, evidence, notes, error }
    }
    if (attempts > 1) {
      notes.push(`TLS handshake succeeded on attempt ${attempts} after a transient connection reset.`)
    }

    const protocols = handshake.supportedProtocols
    const legacy = protocols.filter((protocol) => protocol === 'TLSv1' || protocol === 'TLSv1.1')
    const supportsTls13 = protocols.includes('TLSv1.3') || handshake.tlsVersion === 'TLSv1.3'

    emit({
      surface: 'tls',
      label: 'Protocol enumeration',
      detail: `${protocols.join(' / ') || 'none'} accepted`,
      status: legacy.length ? 'warning' : 'pass',
      severity: legacy.length ? 'medium' : 'none',
      verdict: legacy.length ? 'Legacy exposed' : supportsTls13 ? 'Secure' : 'Dated',
    })
    emit({
      surface: 'tls',
      label: 'Negotiated suite',
      detail: `${handshake.cipherSuite} · ${handshake.cipherSuites.length} suite(s) enumerated`,
      status: 'info',
      severity: 'info',
    })
    emit({
      surface: 'quantum',
      label: 'Named-group enumeration',
      detail: supportsTls13
        ? 'Probing hybrid ML-KEM and classical groups, one per handshake'
        : 'TLS 1.3 not offered — ML-KEM groups cannot exist on this endpoint',
      status: 'info',
      severity: 'info',
      // The quantum surface has no workflow stage of its own until the crypto
      // engine runs at the very end, so without this the card would sit on
      // "Standby" through the phase that is visibly interrogating it.
      verdict: supportsTls13 ? 'Probing groups' : 'Classical only',
    })

    // Sequential by design: analyzeTls already opens ~12 sockets enumerating
    // protocols and suites. Stacking more concurrent probes on top produces
    // throttled resets that read as unsupported.
    const groups = await probeNamedGroups(host, port, supportsTls13, emit)
    const session = await probeSession(host, port)

    const fs = deriveForwardSecrecy(handshake, groups.hybridGroups, groups.classicalGroups)

    const data: TlsIntelligence = {
      handshake,
      supportedProtocols: protocols,
      legacyProtocols: legacy,
      negotiatedProtocol: handshake.tlsVersion,
      negotiatedCipher: handshake.cipherSuite,
      cipherSuites: handshake.cipherSuites,
      alpn: session.alpn,
      alpnOffered: ['h2', 'http/1.1'],
      http2: session.alpn === 'h2',
      hybridGroups: groups.hybridGroups,
      pureKemGroups: groups.pureKemGroups,
      classicalGroups: groups.classicalGroups,
      primaryGroup: groups.hybridGroups[0] ?? groups.classicalGroups[0] ?? null,
      groupsProbed: true,
      inconclusiveGroups: groups.inconclusiveGroups,
      hybridProbed: groups.hybridProbed,
      untestableGroups: groups.untestableGroups,
      unstableGroups: groups.unstableGroups,
      groupHandshakes: groups.handshakes,
      forwardSecrecy: fs.enabled,
      forwardSecrecyBasis: fs.basis,
      staticRsaAccepted: handshake.cipherSuites.some((suite) => suite.category === 'rsa-kex'),
      sessionTickets: session.sessionTickets,
      sessionReuse: session.sessionReuse,
      // TLS-level compression was removed in TLS 1.3 and is disabled by every
      // modern stack (CRIME). Node does not expose it; report Not Applicable
      // rather than guessing.
      compression: null,
      // RFC 5746 secure renegotiation is mandatory in every supported OpenSSL
      // build and unobservable from a Node client; not asserted.
      secureRenegotiation: null,
      timing: session.timing,
      error: null,
    }

    evidence.push({
      label: 'Negotiated protocol',
      observedValue: handshake.tlsVersion,
      detectionMethod: 'TLS handshake',
      evidenceSource: `${host}:${port}`,
      confidence: 100,
    })
    evidence.push({
      label: 'Accepted protocols',
      observedValue: protocols.join(', ') || 'none',
      detectionMethod: 'TLS protocol probe',
      evidenceSource: `${protocols.length} per-version handshakes`,
      confidence: 100,
    })
    evidence.push({
      label: 'Negotiated cipher suite',
      observedValue: handshake.cipherSuite,
      detectionMethod: 'TLS handshake',
      evidenceSource: `${host}:${port}`,
      confidence: 100,
    })
    evidence.push({
      label: 'Named key-agreement groups',
      observedValue: [...groups.hybridGroups, ...groups.classicalGroups].join(', ') || 'none accepted',
      detectionMethod: 'TLS named-group probe',
      evidenceSource: groups.hybridProbed
        ? `each group offered in isolation and re-sampled for agreement · ${groups.handshakes} handshake(s)`
        : `classical groups only — endpoint does not negotiate TLS 1.3 · ${groups.handshakes} handshake(s)`,
      confidence: 100,
    })
    evidence.push({
      label: 'Named-group measurement stability',
      observedValue: groups.unstableGroups.length
        ? `${groups.unstableGroups.length} group(s) answered inconsistently: ${groups.unstableGroups.join(', ')}`
        : 'every group returned the same verdict on repeat sampling',
      detectionMethod: 'TLS named-group probe',
      evidenceSource: `${groups.handshakes} handshake(s), minimum two samples per group`,
      confidence: 100,
    })
    evidence.push({
      label: 'Hybrid post-quantum key agreement',
      observedValue: groups.hybridGroups.length
        ? groups.hybridGroups.join(', ')
        : groups.hybridProbed
          ? 'no hybrid ML-KEM group accepted'
          : 'not available — TLS 1.3 not supported by this endpoint',
      detectionMethod: 'TLS named-group probe',
      evidenceSource: groups.hybridProbed
        ? 'X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 offered under a TLS 1.3 floor'
        : 'derived from the protocol probe — ML-KEM groups exist only in TLS 1.3 key_share',
      confidence: 100,
    })
    if (session.alpn) {
      evidence.push({
        label: 'ALPN',
        observedValue: session.alpn,
        detectionMethod: 'TLS handshake',
        evidenceSource: 'ALPN extension',
        confidence: 100,
      })
    }
    if (groups.pureKemGroups.length) {
      evidence.push({
        label: 'Standalone ML-KEM key agreement',
        observedValue: groups.pureKemGroups.join(', '),
        detectionMethod: 'TLS named-group probe',
        evidenceSource: 'each group offered in isolation under a TLS 1.3 floor',
        confidence: 100,
      })
      notes.push(
        `Standalone ML-KEM accepted: ${groups.pureKemGroups.join(', ')}. Reported separately from hybrid support — a standalone KEM has no classical hedge, so it is not counted toward hybrid deployment readiness.`,
      )
    }
    if (groups.hybridGroups.length) {
      notes.push(`Hybrid post-quantum key agreement accepted: ${groups.hybridGroups.join(', ')}.`)
    } else if (!groups.hybridProbed) {
      notes.push(
        'Hybrid ML-KEM groups were not probed: the endpoint does not negotiate TLS 1.3, where those groups are defined. They are reported as unsupported, not untested.',
      )
    }
    if (groups.inconclusiveGroups.length) {
      notes.push(
        `Inconclusive for ${groups.inconclusiveGroups.join(', ')}: the endpoint either ignored the offered group list or throttled the probe, so nothing is claimed either way.`,
      )
    }
    if (groups.unstableGroups.length) {
      notes.push(
        `Repeat sampling disagreed for ${groups.unstableGroups.join(', ')}; the verdict shown is the majority of three handshakes. An endpoint that answers the same offer differently is usually rate-limiting the probe.`,
      )
    }
    if (groups.untestableGroups.length) {
      notes.push(
        `Not tested: ${groups.untestableGroups.join(', ')} — the scanner's own TLS stack cannot offer these groups, so no claim is made about the endpoint.`,
      )
    }
    if (groups.budgetSkippedGroups.length) {
      notes.push(
        `Named-group probing hit its ${GROUP_PHASE_BUDGET_MS / 1000}s budget; ${groups.budgetSkippedGroups.join(', ')} were left unmeasured and are reported as inconclusive.`,
      )
    }

    const confidence = clampScore(
      40 + (protocols.length >= 4 ? 20 : 10) + (groups.hybridGroups.length + groups.classicalGroups.length ? 25 : 0) + (session.alpn ? 15 : 5),
    )

    return { data, ok: true, confidence, evidence, notes, error: null }
  })
}
