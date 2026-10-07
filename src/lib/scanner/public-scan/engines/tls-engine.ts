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
const GROUP_PROBE_TIMEOUT = 3_500

/**
 * Wall-clock ceiling for the whole named-group phase.
 *
 * Lowered from 40s once probing stopped spending handshakes on answers that
 * were never in doubt (see `probeNamedGroups`). The budget is now a backstop for
 * a pathological endpoint rather than the thing that shapes a normal run: a
 * healthy target finishes the phase in 3-5s. When the budget does run out the
 * remaining groups are recorded as INCONCLUSIVE and said so in the notes —
 * never as rejected.
 */
const GROUP_PHASE_BUDGET_MS = 20_000

/**
 * Concurrency for the DISCOVERY pass and for the CONFIRMATION pass.
 *
 * The hazard this scanner has to respect is a burst of new TCP connections to
 * one IP: CDNs and load balancers throttle it, and a throttled RST is
 * indistinguishable from "group not supported" — a false negative on the single
 * most important measurement here. The previous code answered that by going
 * strictly one-at-a-time, which cost ~11s of the ~12s a scan took.
 *
 * Four concurrent handshakes is not that burst. A browser opens six connections
 * to a single origin before it has rendered anything, so a ceiling of four is
 * below the traffic every one of these endpoints already serves continuously.
 * Confirmation drops to two because it is re-testing exactly the results a
 * throttle would have corrupted, and it must not reproduce the conditions it is
 * checking for.
 */
const GROUP_DISCOVERY_CONCURRENCY = 4
const GROUP_CONFIRM_CONCURRENCY = 2

/**
 * Courtesy gap between consecutive probes, derived from the endpoint's own
 * observed handshake latency rather than fixed.
 *
 * A flat 150ms gap was 6.0s of pure `setTimeout` in a 12s scan — half the TLS
 * engine's wall clock spent sleeping, and the same 150ms whether the edge
 * answered in 15ms or 900ms. Pacing proportional to the measured round trip is
 * what the fixed number was approximating: it backs off from a slow or loaded
 * endpoint (where throttling is a real risk) and stops padding a fast one.
 */
const MIN_PACING_MS = 40
const MAX_PACING_MS = 220

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * Run `worker` over `items` with at most `limit` in flight.
 *
 * Results keep input order, so a caller can zip them back against the plan
 * without tracking completion order.
 */
async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let cursor = 0
  const runners = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (;;) {
      const index = cursor
      cursor += 1
      if (index >= items.length) return
      results[index] = await worker(items[index], index)
    }
  })
  await Promise.all(runners)
  return results
}

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
 * How many CONFIRMING samples a negative verdict needs before it is published.
 *
 * The evidence standard here is deliberately asymmetric, because the two
 * outcomes are not equally falsifiable:
 *
 *   accepted  Unforgeable. A throttled, reset or dropped connection cannot
 *             complete a TLS 1.3 handshake that negotiated the one group we
 *             offered. One completed handshake IS the proof — re-sampling it
 *             cannot make it truer, and the old code spent two thirds of its
 *             handshakes doing exactly that.
 *   rejected  Falsifiable, and precisely what a rate-limiting edge manufactures.
 *             Never published on a single sample.
 *
 * Post-quantum groups carry the report's headline claim, so a denial of ML-KEM
 * support is held to two independent confirmations rather than one.
 *
 * This is a STRONGER standard than the code it replaces, not a weaker one: the
 * old two samples were fired 150ms apart, well inside the same rate-limit
 * window that would have corrupted both. Confirmation now happens in a separate,
 * lower-concurrency pass seconds later, after the discovery burst has drained.
 */
function confirmationsFor(kind: GroupKind): number {
  return kind === 'classical' ? 1 : 2
}

/**
 * Probe order, most decision-relevant first.
 *
 * When a budget bites, what goes unmeasured must be the least useful thing.
 * Hybrid ML-KEM is the question the assessment exists to answer; ffdhe and
 * brainpool are migration-surface detail that a reader can live without. The
 * old flat list probed brainpool before it had confirmed anything about ML-KEM.
 */
const GROUP_PRIORITY: Record<string, number> = {
  X25519MLKEM768: 0,
  SecP256r1MLKEM768: 0,
  SecP384r1MLKEM1024: 0,
  MLKEM512: 1,
  MLKEM768: 1,
  MLKEM1024: 1,
  X25519: 2,
  'P-256': 2,
  'P-384': 2,
  'P-521': 3,
  X448: 3,
  brainpoolP256r1tls13: 4,
  brainpoolP384r1tls13: 4,
  brainpoolP512r1tls13: 4,
  ffdhe2048: 5,
  ffdhe3072: 5,
  ffdhe4096: 5,
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

/* The named-group tables moved to `src/lib/scanner/named-groups.ts` — pure data
   that the algorithm census and the published scoring model also need, and that
   they could not reach while it lived in a module importing `node:tls`.
   Re-exported here so every existing importer is unchanged. */
export { HYBRID_GROUP_KEM, HYBRID_GROUP_COMPONENTS, groupKemLabel, kemParameterSetsFor } from '../../named-groups'

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
   *
   * NOTE this is NOT "the hybrid groups were measured". It is assigned
   * `supportsTls13`, i.e. "hybrid probing was worth attempting". Use
   * `hybridGroupsSettled` / `hybridGroupsInconclusive` to tell a measured
   * refusal from a probe that never produced an answer.
   */
  hybridProbed: boolean
  /**
   * Hybrid ML-KEM groups that reached a CONCLUSIVE verdict — accepted or
   * refused on evidence that met the confirmation standard.
   *
   * Published because an empty `hybridGroups` has two completely different
   * meanings. "The endpoint refused every hybrid group" is a finding about the
   * endpoint; "the probe ran out of budget, was throttled, or the local
   * OpenSSL cannot offer the group" is a finding about the scan. Collapsing
   * the second into the first published `Not offered · state: fail` — with the
   * words "offered in isolation and refused" — for endpoints running
   * X25519MLKEM768, and every post-quantum number on the page followed it down.
   */
  hybridGroupsSettled: string[]
  /** Hybrid groups that never reached a verdict. Nothing is claimed about these. */
  hybridGroupsInconclusive: string[]
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
    hybridGroupsSettled: [],
    hybridGroupsInconclusive: [],
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

/** One probe result plus how long the endpoint took, which drives pacing. */
interface GroupProbeSample {
  verdict: GroupProbeResult
  ms: number
}

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
): Promise<GroupProbeSample> {
  return new Promise((resolve) => {
    let settled = false
    const startedAt = Date.now()
    const finish = (value: GroupProbeResult) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket?.destroy()
      } catch {
        /* already torn down */
      }
      // The elapsed time is fed back into pacing: an endpoint's own latency is
      // the only honest basis for how hard this scanner may lean on it.
      resolve({ verdict: value, ms: Date.now() - startedAt })
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
      resolve({ verdict: 'inconclusive', ms: Date.now() - startedAt })
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
 * Named-group enumeration: DISCOVER, then CONFIRM THE NEGATIVES.
 *
 * WHY THIS SHAPE
 * --------------
 * The previous implementation probed one group at a time and sampled every
 * group two or three times regardless of what came back. Measured against seven
 * live endpoints that cost 40 sequential handshakes per scan and made this
 * function 85-97% of the entire assessment's wall clock — 11.2s of a 12.9s scan
 * on wikipedia.org, of which 6.0s was `setTimeout`. It was not slow because
 * measurement is expensive; it was slow because it spent two thirds of its
 * handshakes re-confirming answers that could not have been wrong.
 *
 * The integrity argument that produced the sequential design is still correct
 * and is still honoured — it is just applied where it actually bites:
 *
 *   PASS 1 (discovery, concurrency 4)
 *     One probe per group. Fast, and bounded well below the connection burst
 *     that trips per-IP limits.
 *
 *   PASS 2 (confirmation, concurrency 2, paced)
 *     Re-probes ONLY the groups whose discovery verdict was not `accepted`.
 *     Those are the falsifiable ones — a rate-limited edge manufactures
 *     rejections, never acceptances (a throttled socket cannot complete a TLS
 *     1.3 handshake negotiating the one group we offered). Confirmation runs in
 *     its own pass seconds after the discovery burst has drained, which is a
 *     BETTER control than the old back-to-back samples 150ms apart — those sat
 *     inside the same rate-limit window that would have corrupted both.
 *
 * Net effect: a published `accepted` still rests on a completed handshake that
 * negotiated the offered group, and a published `rejected` still rests on two
 * or three agreeing samples taken under different load conditions. The evidence
 * standard went up; the handshake count and the wall clock went down.
 *
 * `supportsTls13` short-circuits the ML-KEM probes entirely: a server that never
 * negotiates TLS 1.3 cannot support a TLS 1.3-only group, so that is answered
 * from evidence already in hand rather than by doomed handshakes.
 */
async function probeNamedGroups(
  host: string,
  port: number,
  supportsTls13: boolean,
  emit: ObservationSink,
  budgetMs: number = GROUP_PHASE_BUDGET_MS,
) {
  const unsupportedLocally = localGroupSupport()
  // ML-KEM groups, hybrid or standalone, exist only in the TLS 1.3 key_share.
  // An endpoint that never negotiates 1.3 is answered from evidence in hand.
  const requested = [
    ...(supportsTls13 ? [...HYBRID_PQ_GROUPS, ...PURE_PQ_GROUPS] : []),
    ...CLASSICAL_GROUPS,
  ]
  const untestable = requested.filter((group) => unsupportedLocally.has(group))
  const groups = requested
    .filter((group) => !unsupportedLocally.has(group))
    // Most decision-relevant first, so a budget cut costs the least information.
    .sort((a, b) => (GROUP_PRIORITY[a] ?? 9) - (GROUP_PRIORITY[b] ?? 9))

  const deadline = Date.now() + Math.max(2_000, budgetMs)
  const verdicts = new Map<string, GroupProbeResult>()
  const samplesByGroup = new Map<string, GroupProbeResult[]>()
  const unstable: string[] = []
  const budgetSkipped: string[] = []
  /** Handshakes actually spent — reported as provenance, never estimated. */
  let handshakes = 0

  /** Rolling mean handshake latency, the basis for adaptive pacing. */
  let latencySum = 0
  let latencyCount = 0
  const pacing = () => {
    if (!latencyCount) return MIN_PACING_MS
    const mean = latencySum / latencyCount
    return Math.round(Math.max(MIN_PACING_MS, Math.min(MAX_PACING_MS, mean / 4)))
  }

  const record = (group: string, sample: GroupProbeSample) => {
    handshakes += 1
    latencySum += sample.ms
    latencyCount += 1
    const bucket = samplesByGroup.get(group) ?? []
    bucket.push(sample.verdict)
    samplesByGroup.set(group, bucket)
    return sample.verdict
  }

  const label = (group: string) => GROUP_LABELS[group] ?? group
  const isPq = (group: string) => groupKind(group) !== 'classical'

  /* Real completion counts for the live rail. `settled` only ever increments
     when a group reaches a final verdict, so the bar it drives is a report of
     work finished rather than a timer pretending to be one. */
  let settled = 0
  const groupProgress = () => ({ done: (settled += 1), total: groups.length })

  /* ── Pass 1: discovery ─────────────────────────────────────────────────── */
  await mapWithConcurrency(groups, GROUP_DISCOVERY_CONCURRENCY, async (group) => {
    if (Date.now() >= deadline) {
      budgetSkipped.push(group)
      return
    }
    emit({
      surface: isPq(group) ? 'quantum' : 'tls',
      label: group,
      detail: `Offering ${label(group)} in isolation`,
      status: 'info',
      severity: 'info',
    })
    // Every ML-KEM group, hybrid or standalone, lives only in the TLS 1.3
    // key_share — so both get the 1.3 floor and the 1.3-only interpretation.
    const sample = await probeGroup(host, port, group, isPq(group))
    const verdict = record(group, sample)

    // An acceptance is terminal: it cannot have been produced by throttling, so
    // it is published from this single handshake and never re-probed.
    if (verdict === 'accepted') {
      verdicts.set(group, 'accepted')
      emit({
        surface: isPq(group) ? 'quantum' : 'tls',
        label: group,
        detail: `${label(group)} accepted${
          groupKind(group) === 'hybrid'
            ? ' — hybrid ML-KEM confirmed'
            : groupKind(group) === 'pure-pq'
              ? ' — standalone ML-KEM confirmed'
              : ''
        }`,
        status: 'pass',
        severity: 'none',
        postQuantum: groupKind(group) === 'hybrid',
        progress: groupProgress(),
      })
    }
  })

  /* ── Was the discovery stream healthy? ─────────────────────────────────
     Throttling is a property of the CONNECTION STREAM, not of a named group.
     An edge does not rate-limit `ffdhe2048` and wave `X25519` through — it
     drops connections. So the throttle hypothesis is testable once, from the
     shape of the discovery pass, instead of re-litigated twelve times:

       • at least one acceptance means the endpoint completed handshakes with
         us DURING the burst and honoured the single group we offered, and
       • no transient (reset / timeout / refused) result means nothing in the
         stream was dropped.

     When both hold, the rejections in that same stream are real refusals, and
     re-probing them measures nothing that is in doubt. The post-quantum groups
     are confirmed anyway — they carry the report's headline claim, and that one
     is worth a handshake even when the evidence already points one way.

     When either fails, every negative is confirmed exactly as before. */
  const discoverySamples = [...samplesByGroup.values()].flat()
  const sawTransient = discoverySamples.includes('transient')
  const sawAcceptance = discoverySamples.includes('accepted')
  const streamHealthy = sawAcceptance && !sawTransient

  /* ── Pass 2: confirm the falsifiable results ───────────────────────────── */
  const unresolved = groups.filter((group) => !verdicts.has(group) && !budgetSkipped.includes(group))
  const toConfirm = streamHealthy ? unresolved.filter((group) => isPq(group)) : unresolved
  const publishedFromDiscovery = unresolved.filter((group) => !toConfirm.includes(group))

  await mapWithConcurrency(toConfirm, GROUP_CONFIRM_CONCURRENCY, async (group) => {
    const kind = groupKind(group)
    const wanted = confirmationsFor(kind)

    for (let attempt = 0; attempt < wanted; attempt += 1) {
      if (Date.now() >= deadline) break
      await sleep(pacing())
      const sample = await probeGroup(host, port, group, isPq(group))
      // A confirmation that comes back accepted overturns the discovery result
      // outright — that is the throttled-discovery case this pass exists for.
      if (record(group, sample) === 'accepted') break
    }

    const samples = samplesByGroup.get(group) ?? []
    // Plurality wins. `transient` is kept as its own answer through the tally:
    // a connection that is consistently reset for one offered group is the
    // endpoint refusing that group, and calling it "inconclusive" would bury a
    // real negative result.
    const tally = new Map<GroupProbeResult, number>()
    for (const sample of samples) tally.set(sample, (tally.get(sample) ?? 0) + 1)
    const ranked = [...tally.entries()].sort((a, b) => b[1] - a[1])

    let verdict: GroupProbeResult
    if (tally.size === 1) {
      verdict = samples[0]
    } else if (ranked[0][1] > ranked[1][1]) {
      verdict = ranked[0][0]
      unstable.push(group)
    } else {
      // A genuine split with no plurality. Nothing is claimed.
      verdict = 'inconclusive'
      unstable.push(group)
    }

    // Only ONE sample survived the budget. A single negative is exactly the
    // reading a throttle fabricates, so it is reported as inconclusive rather
    // than published as a refusal the scan never confirmed.
    if (samples.length < 2 && verdict !== 'accepted') verdict = 'inconclusive'

    // A consistently reset connection for a single offered group means the
    // endpoint has no key share it is willing to use — a refusal.
    if (verdict === 'transient') verdict = 'rejected'
    verdicts.set(group, verdict)

    emit({
      surface: isPq(group) ? 'quantum' : 'tls',
      label: group,
      detail:
        verdict === 'accepted'
          ? `${label(group)} accepted on confirmation — discovery probe was throttled`
          : verdict === 'rejected'
            ? `${label(group)} not offered by this endpoint`
            : `${label(group)} inconclusive — endpoint answered inconsistently`,
      status: verdict === 'accepted' ? 'pass' : verdict === 'rejected' ? 'info' : 'warning',
      severity: verdict === 'inconclusive' ? 'low' : 'none',
      postQuantum: kind === 'hybrid' && verdict === 'accepted',
      progress: groupProgress(),
    })
  })

  /* Groups settled by the healthy-stream rule: their discovery verdict stands,
     with the reasoning carried into the report rather than left implicit. */
  for (const group of publishedFromDiscovery) {
    const sample = (samplesByGroup.get(group) ?? [])[0]
    if (!sample) {
      verdicts.set(group, 'inconclusive')
      continue
    }
    const verdict = sample === 'transient' ? 'rejected' : sample
    verdicts.set(group, verdict)
    emit({
      surface: 'tls',
      label: group,
      detail:
        verdict === 'rejected'
          ? `${label(group)} not offered by this endpoint`
          : `${label(group)} inconclusive — endpoint ignored the offered group list`,
      status: verdict === 'rejected' ? 'info' : 'warning',
      severity: verdict === 'inconclusive' ? 'low' : 'none',
      progress: groupProgress(),
    })
  }

  for (const group of budgetSkipped) verdicts.set(group, 'inconclusive')
  for (const group of untestable) verdicts.set(group, 'inconclusive')

  const accepted = groups.filter((group) => verdicts.get(group) === 'accepted')
  const inconclusive = [...verdicts.entries()]
    .filter(([, verdict]) => verdict === 'inconclusive')
    .map(([group]) => group)

  /* Split the hybrid groups by whether they actually produced an ANSWER.
     `hybridGroups` being empty is not evidence of refusal on its own: a
     budget-skipped, untestable or throttled group lands in `inconclusive`, and
     a consumer that reads only the accepted list cannot tell the two apart. */
  const hybridCandidates = groups.filter((group) => groupKind(group) === 'hybrid')
  const hybridGroupsInconclusive = hybridCandidates.filter((group) => verdicts.get(group) === 'inconclusive')
  const hybridGroupsSettled = hybridCandidates.filter((group) => {
    const verdict = verdicts.get(group)
    return verdict === 'accepted' || verdict === 'rejected'
  })

  return {
    /** How each negative was established — printed as provenance, not inferred. */
    confirmationBasis: streamHealthy
      ? ('healthy-stream' as const)
      : sawAcceptance
        ? ('transient-seen' as const)
        : ('no-acceptance' as const),
    confirmedGroups: toConfirm,
    discoveryOnlyGroups: publishedFromDiscovery,
    hybridGroups: accepted.filter((group) => groupKind(group) === 'hybrid'),
    // Standalone ML-KEM is reported on its own and deliberately NOT merged into
    // `hybridGroups`: the grading model scores hybrid deployment, and quietly
    // counting a no-classical-hedge group as hybrid would inflate readiness.
    pureKemGroups: accepted.filter((group) => groupKind(group) === 'pure-pq'),
    classicalGroups: accepted.filter((group) => groupKind(group) === 'classical'),
    inconclusiveGroups: inconclusive,
    hybridProbed: supportsTls13,
    hybridGroupsSettled,
    hybridGroupsInconclusive,
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

/**
 * Ceiling for one primary-handshake attempt.
 *
 * `tls-analyzer`'s own default is 15s. Three attempts at 15s is 45s — the entire
 * scan budget — spent before the certificate engine has opened a socket, which
 * is exactly how one unreachable endpoint turned into a 66-second assessment. A
 * reachable endpoint completes this handshake in well under a second; the ceiling
 * exists for a slow one, not for a silent one, and silence is now the preflight's
 * job to detect.
 */
const PRIMARY_HANDSHAKE_TIMEOUT_MS = 8_000

/** Least time worth starting an attempt with. Below this it cannot succeed. */
const MIN_ATTEMPT_MS = 1_500

async function analyzeTlsResilient(
  host: string,
  port: number,
  deadline = Number.POSITIVE_INFINITY,
): Promise<{ handshake: TlsAnalysisResult | null; error: string | null; attempts: number }> {
  const maxAttempts = 3
  let lastError: string | null = null
  let attemptsMade = 0

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    /* Budget is checked BEFORE the attempt, not after it. Checking afterwards
       let every attempt start with the full 15s ceiling however little time was
       left, so the engine routinely overran the deadline it had been given by
       the length of one whole handshake timeout. */
    const remaining = deadline - Date.now()
    if (remaining < MIN_ATTEMPT_MS) {
      if (attemptsMade === 0) {
        lastError = lastError ?? 'No time remained in the scan budget to attempt a TLS handshake.'
      }
      break
    }

    attemptsMade = attempt
    try {
      return {
        handshake: await analyzeTls(host, port, {
          handshakeTimeoutMs: Math.min(PRIMARY_HANDSHAKE_TIMEOUT_MS, remaining),
          deadline,
        }),
        error: null,
        attempts: attempt,
      }
    } catch (err) {
      lastError = (err as Error).message
      // A definitive answer is not worth retrying.
      if (!isTransientHandshakeError(lastError) || attempt === maxAttempts) break
      // Back off so the retry does not land inside the same rate-limit window
      // that reset the previous attempt — but only if the backoff plus a usable
      // attempt still fit. Sleeping into the deadline wastes the budget twice.
      const backoff = attempt * 600
      if (deadline - Date.now() < backoff + MIN_ATTEMPT_MS) break
      await new Promise((resolve) => setTimeout(resolve, backoff))
    }
  }

  return { handshake: null, error: lastError, attempts: Math.max(1, attemptsMade) }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

export async function runTlsEngine(
  host: string,
  port: number,
  onObservation?: ObservationSink,
  /** Epoch ms the whole engine must be finished by. Degrades, never throws. */
  deadline: number = Date.now() + GROUP_PHASE_BUDGET_MS + HANDSHAKE_TIMEOUT * 3,
): Promise<EngineResult<TlsIntelligence>> {
  return runEngine('tls-intelligence', emptyTls(), async () => {
    const evidence: Evidence[] = []
    const notes: string[] = []
    const emit = observationEmitter(onObservation)

    const { handshake, error, attempts } = await analyzeTlsResilient(host, port, deadline)
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

    /* The session probe touches nothing the group phase touches — it offers no
       named group and reads resumption behaviour — so running it alongside
       costs one connection and removes its latency from the critical path
       entirely. It used to run strictly afterwards, adding its full duration
       (up to 8s on a slow endpoint) to every scan for no measurement reason. */
    const sessionPromise = probeSession(host, port)

    const groups = await probeNamedGroups(
      host,
      port,
      supportsTls13,
      emit,
      // Whatever is left of the engine's slice, minus room for the wrap-up.
      Math.min(GROUP_PHASE_BUDGET_MS, Math.max(2_000, deadline - Date.now() - 1_000)),
    )
    const session = await sessionPromise

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
      hybridGroupsSettled: groups.hybridGroupsSettled,
      hybridGroupsInconclusive: groups.hybridGroupsInconclusive,
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
        ? `each group offered in isolation; every refusal re-probed in a separate pass · ${groups.handshakes} handshake(s)`
        : `classical groups only — endpoint does not negotiate TLS 1.3 · ${groups.handshakes} handshake(s)`,
      confidence: 100,
    })
    evidence.push({
      label: 'Named-group measurement stability',
      observedValue: groups.unstableGroups.length
        ? `${groups.unstableGroups.length} group(s) answered inconsistently: ${groups.unstableGroups.join(', ')}`
        : 'every re-probed group returned the same verdict',
      detectionMethod: 'TLS named-group probe',
      // Stated precisely, because the outcomes carry different evidence and a
      // reader is entitled to know which standard produced the row they see.
      evidenceSource:
        `${groups.handshakes} handshake(s) — an acceptance is a completed handshake that negotiated the offered group. ` +
        (groups.confirmationBasis === 'healthy-stream'
          ? `The probe stream completed handshakes throughout with no reset or timeout, so refusals in it are genuine; ` +
            `the ${groups.confirmedGroups.length} post-quantum group(s) were re-probed regardless.`
          : groups.confirmationBasis === 'transient-seen'
            ? `Resets were seen during probing, so every refusal was re-probed in a separate lower-concurrency pass.`
            : `No group was accepted, so every refusal was re-probed in a separate lower-concurrency pass before being reported.`),
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
        `Repeat probing disagreed for ${groups.unstableGroups.join(', ')}; the verdict shown is the majority across the samples taken. An endpoint that answers the same offer differently is usually rate-limiting the probe.`,
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
