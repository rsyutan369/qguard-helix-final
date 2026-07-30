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
  clampScore,
  runEngine,
} from './contract'

const HANDSHAKE_TIMEOUT = 8_000
const GROUP_PROBE_TIMEOUT = 5_000
/** Probes per batch — kept low so per-IP connection limits are not tripped. */
const GROUP_PROBE_BATCH = 2

/**
 * Named groups probed individually. Offering exactly one group and observing
 * whether the handshake completes is the only way to prove hybrid PQ support
 * from outside: Node does not expose the negotiated TLS 1.3 group.
 */
const HYBRID_PQ_GROUPS = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024'] as const
const CLASSICAL_GROUPS = ['X25519', 'P-256', 'P-384', 'P-521'] as const

/** ML-KEM parameter set carried by each hybrid group, per the TLS registry. */
export const HYBRID_GROUP_KEM: Record<string, string> = {
  X25519MLKEM768: 'ML-KEM-768',
  SecP256r1MLKEM768: 'ML-KEM-768',
  SecP384r1MLKEM1024: 'ML-KEM-1024',
}

export const GROUP_LABELS: Record<string, string> = {
  X25519MLKEM768: 'X25519 + ML-KEM-768 (hybrid)',
  SecP256r1MLKEM768: 'P-256 + ML-KEM-768 (hybrid)',
  SecP384r1MLKEM1024: 'P-384 + ML-KEM-1024 (hybrid)',
  X25519: 'X25519 (ECDHE)',
  'P-256': 'secp256r1 (ECDHE)',
  'P-384': 'secp384r1 (ECDHE)',
  'P-521': 'secp521r1 (ECDHE)',
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
    classicalGroups: [],
    primaryGroup: null,
    groupsProbed: false,
    inconclusiveGroups: [],
    hybridProbed: false,
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
      resolve('rejected')
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
 * Probes run in small sequential batches. Firing them all at once trips the
 * per-IP connection limits of CDNs and load balancers, and a throttled RST is
 * indistinguishable from "group not supported" — a false negative on the single
 * most important measurement this scanner makes. Transient failures are retried
 * once before being recorded as unsupported.
 *
 * `supportsTls13` short-circuits the hybrid probes entirely: a server that never
 * negotiates TLS 1.3 cannot support a TLS 1.3-only group, so that is answered
 * from evidence already in hand rather than by three doomed handshakes.
 */
async function probeNamedGroups(host: string, port: number, supportsTls13: boolean) {
  const hybridToProbe = supportsTls13 ? [...HYBRID_PQ_GROUPS] : []
  const groups = [...hybridToProbe, ...CLASSICAL_GROUPS]
  const isHybrid = (group: string) => (HYBRID_PQ_GROUPS as readonly string[]).includes(group)
  const results: GroupProbeResult[] = []

  for (let index = 0; index < groups.length; index += GROUP_PROBE_BATCH) {
    const batch = groups.slice(index, index + GROUP_PROBE_BATCH)
    results.push(
      ...(await Promise.all(batch.map((group) => probeGroup(host, port, group, isHybrid(group))))),
    )
  }
  for (let index = 0; index < results.length; index += 1) {
    if (results[index] !== 'transient') continue
    results[index] = await probeGroup(host, port, groups[index], isHybrid(groups[index]))
  }

  const accepted = groups.filter((_group, index) => results[index] === 'accepted')
  const inconclusive = groups.filter((_group, index) => results[index] === 'inconclusive')

  return {
    hybridGroups: accepted.filter(isHybrid),
    classicalGroups: accepted.filter((group) => !isHybrid(group)),
    inconclusiveGroups: inconclusive,
    hybridProbed: supportsTls13,
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

export async function runTlsEngine(host: string, port: number): Promise<EngineResult<TlsIntelligence>> {
  return runEngine('tls-intelligence', emptyTls(), async () => {
    const evidence: Evidence[] = []
    const notes: string[] = []

    const { handshake, error, attempts } = await analyzeTlsResilient(host, port)
    if (!handshake) {
      const data = emptyTls(error)
      notes.push(
        `TLS handshake did not complete after ${attempts} attempt${attempts === 1 ? '' : 's'}; protocol and cipher controls report Unknown.`,
      )
      return { data, ok: false, confidence: 0, evidence, notes, error }
    }
    if (attempts > 1) {
      notes.push(`TLS handshake succeeded on attempt ${attempts} after a transient connection reset.`)
    }

    const protocols = handshake.supportedProtocols
    const legacy = protocols.filter((protocol) => protocol === 'TLSv1' || protocol === 'TLSv1.1')
    const supportsTls13 = protocols.includes('TLSv1.3') || handshake.tlsVersion === 'TLSv1.3'

    // Sequential by design: analyzeTls already opens ~12 sockets enumerating
    // protocols and suites. Stacking more concurrent probes on top produces
    // throttled resets that read as unsupported.
    const groups = await probeNamedGroups(host, port, supportsTls13)
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
      classicalGroups: groups.classicalGroups,
      primaryGroup: groups.hybridGroups[0] ?? groups.classicalGroups[0] ?? null,
      groupsProbed: true,
      inconclusiveGroups: groups.inconclusiveGroups,
      hybridProbed: groups.hybridProbed,
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
        ? 'each group offered in isolation and confirmed used by the negotiated suite'
        : 'classical groups only — endpoint does not negotiate TLS 1.3',
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
    if (groups.hybridGroups.length) {
      notes.push(`Hybrid post-quantum key agreement accepted: ${groups.hybridGroups.join(', ')}.`)
    } else if (!groups.hybridProbed) {
      notes.push(
        'Hybrid ML-KEM groups were not probed: the endpoint does not negotiate TLS 1.3, where those groups are defined. They are reported as unsupported, not untested.',
      )
    }
    if (groups.inconclusiveGroups.length) {
      notes.push(
        `Inconclusive for ${groups.inconclusiveGroups.join(', ')}: the handshake completed but the server ignored the offered group list, so nothing is claimed either way.`,
      )
    }

    const confidence = clampScore(
      40 + (protocols.length >= 4 ? 20 : 10) + (groups.hybridGroups.length + groups.classicalGroups.length ? 25 : 0) + (session.alpn ? 15 : 5),
    )

    return { data, ok: true, confidence, evidence, notes, error: null }
  })
}
