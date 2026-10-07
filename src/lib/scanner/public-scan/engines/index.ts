/**
 * QGuard Helix — Public Scan Intelligence Engine™
 * Module registry and orchestrator.
 *
 * Runs the independent engines with the concurrency each one can safely take,
 * then returns a single evidence bundle. No engine can fail the scan: each
 * returns a result envelope, so a dead HTTP origin still produces a complete
 * TLS + certificate + DNS assessment with the HTTP controls marked Unknown.
 *
 * SCHEDULING
 * ----------
 * A TCP reachability preflight runs FIRST (see `reachability-engine`), because
 * every cryptographic verdict downstream is conditional on the port answering.
 * Establishing that once, in one connect, is what stops each engine paying its
 * own timeout to rediscover a dead port — and, more importantly, is what lets
 * the report say "nothing answered" instead of accusing the endpoint of failing
 * four controls it was never asked about.
 *
 * After the preflight, DNS and HTTP are independent of TLS and run alongside it.
 * TLS and certificate probing are serialised because `analyzeTls` alone opens
 * ~12 sockets to enumerate protocols and cipher suites; stacking more concurrent
 * handshakes on top trips CDN per-IP connection limits, and a throttled RST is
 * indistinguishable from "not supported" — a false negative on the very
 * measurements this scanner exists to make.
 *
 * DNS runs regardless of reachability: whether a name resolves is real, useful
 * evidence even when the service behind it is down, and it is the first thing an
 * operator needs in order to tell "wrong DNS" from "dead service".
 */

import { runCertificateEngine, emptyCertificate, type CertificateIntelligence } from './certificate-engine'
import { runCryptoEngine, notAssessedCrypto, type CryptoIntelligenceData } from './crypto-engine'
import { runDnsEngine, emptyDns, type DnsIntelligence } from './dns-engine'
import { runHttpEngine, emptyHttp, type HttpIntelligence } from './http-engine'
import {
  runReachabilityEngine,
  emptyReachability,
  REACHABILITY_TIMEOUT_MS,
  type ReachabilityIntelligence,
} from './reachability-engine'
import { runTlsEngine, emptyTls, type TlsIntelligence } from './tls-engine'
import {
  type EngineResult,
  type Evidence,
  type ObservationSink,
  clampScore,
  observationEmitter,
  unmeasuredResult,
} from './contract'

export * from './contract'
export * from './dns-engine'
export * from './http-engine'
export * from './tls-engine'
export * from './certificate-engine'
export * from './crypto-engine'
export * from './reachability-engine'

/** One entry per engine, for the scanner-capability disclosure. */
export const ENGINE_REGISTRY = [
  { id: 'endpoint-reachability', name: 'Endpoint Reachability Engine', covers: ['TCP connect', 'Port state', 'Connect latency', 'Route reachability'] },
  { id: 'dns-intelligence', name: 'DNS Intelligence Engine', covers: ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'DNSSEC', 'SPF', 'DKIM', 'DMARC'] },
  { id: 'tls-intelligence', name: 'TLS Intelligence Engine', covers: ['Protocol versions', 'Cipher suites', 'ALPN', 'Named groups', 'Hybrid PQ groups', 'Session resumption', 'Forward secrecy'] },
  { id: 'certificate-intelligence', name: 'Certificate Intelligence Engine', covers: ['Chain', 'Trust verification', 'SAN/CN', 'Key + signature', 'Validity', 'OCSP', 'SCT / CT', 'CRL', 'Must-staple'] },
  { id: 'http-security', name: 'HTTP Security Engine', covers: ['HSTS', 'CSP', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy', 'COOP', 'COEP', 'CORP', 'CDN/WAF fingerprint'] },
  { id: 'cryptographic-intelligence', name: 'Cryptographic Intelligence Engine', covers: ['Algorithm catalogue', 'Classification', 'Post-quantum readiness', 'Quantum Risk Engine'] },
] as const

export interface ScanEvidenceBundle {
  host: string
  port: number
  /**
   * The preflight. `reachability.data.reachable === false` is the single
   * predicate that explains every Unknown in the rest of the bundle.
   */
  reachability: EngineResult<ReachabilityIntelligence>
  dns: EngineResult<DnsIntelligence>
  tls: EngineResult<TlsIntelligence>
  certificate: EngineResult<CertificateIntelligence>
  http: EngineResult<HttpIntelligence>
  crypto: EngineResult<CryptoIntelligenceData>
  /** Flattened, de-duplicated observations from every engine. */
  evidence: Evidence[]
  notes: string[]
  /** 0-100 across all engines, weighted by how much each contributes. */
  confidence: number
  totalMs: number
}

/**
 * Total wall-clock the engine bundle is allowed, when a caller does not say.
 *
 * This is a DEGRADE-BY deadline, not a kill switch: engines that run out of
 * budget return what they measured and mark the rest inconclusive, so a slow
 * endpoint yields a partial assessment rather than an error page. The value is
 * set so the assessment stays inside the caller's own request timeout with room
 * to compose and send the report.
 */
export const DEFAULT_SCAN_BUDGET_MS = 45_000

export interface OrchestratorOptions {
  host: string
  port: number
  /**
   * Called as each engine finishes, for SSE progress.
   *
   * `unmeasured` distinguishes "this module could not be run, so there is no
   * verdict" from "this module ran and the target failed". The rail paints them
   * differently on purpose — see `PublicScanStageState`.
   */
  onEngine?: (engine: string, ok: boolean, detail: string, unmeasured?: boolean) => void
  /** Called as individual measurements land, for the live visualization. */
  onObservation?: ObservationSink
  /** Called when an engine begins, so the rail reflects real start times. */
  onEngineStart?: (engine: string) => void
  /**
   * Wall-clock ceiling for the whole bundle. Engines degrade gracefully when it
   * expires — they never throw, so the report is always composable.
   */
  budgetMs?: number
}

export async function runScanEngines(options: OrchestratorOptions): Promise<ScanEvidenceBundle> {
  const { host, port, onEngine, onEngineStart } = options
  const startedAt = Date.now()
  const deadline = startedAt + (options.budgetMs ?? DEFAULT_SCAN_BUDGET_MS)
  const emit = observationEmitter(options.onObservation)

/** CAA is answered only when a resolver replied AND the RFC 8659 climb reached
    the registrable domain. Either gap leaves issuance policy Unknown. */
const caaAnswered = (dns: { caaQueryable: boolean; caaClimbComplete: boolean }) =>
  dns.caaQueryable && dns.caaClimbComplete

  // DNS and HTTP touch different infrastructure than the TLS probes, so they
  // run alongside the TLS chain without competing for the same connection pool.
  onEngineStart?.('dns-intelligence')
  /* DNS gets a slice of the budget rather than the whole thing. It runs beside
     TLS and so is normally free, but it fans out to two DoH resolvers across a
     dozen record types and was measured at 11.6s on one run — the moment TLS
     got faster it would have become the critical path itself. */
  const dnsPromise = runDnsEngine(host, Math.min(8_000, deadline - Date.now())).then((result) => {
    onEngine?.(
      'dns-intelligence',
      result.ok,
      `${result.data.addressCount} address(es), CAA ${
        !result.data.caaQueryable || !result.data.caaClimbComplete
          ? 'unknown'
          : result.data.caaPresent
            ? 'present'
            : 'absent'
      }`,
    )
    emit({
      surface: 'dns',
      label: 'Address resolution',
      detail: result.data.addressCount
        ? `${result.data.addressCount} address(es) resolved · ${result.data.resolvedVia}`
        : 'No public address records',
      status: result.data.addressCount ? 'pass' : 'critical',
      severity: result.data.addressCount ? 'none' : 'high',
      verdict: result.data.addressCount ? 'Resolved' : 'Unresolved',
    })
    emit({
      surface: 'dns',
      label: 'CAA issuance policy',
      /* `caaAnswered`: a resolver replied AND the RFC 8659 climb reached the
         registrable domain. Short of that the row says Unknown — issuance policy
         is inherited up the tree, so a leaf NODATA is not "Open issuance". */
      detail: !result.data.caaQueryable
        ? 'CAA not observable from this resolver'
        : !result.data.caaClimbComplete
          ? 'CAA undetermined — the climb to the registrable domain did not complete'
          : result.data.caaPresent
            ? `CAA record found · ${result.data.caaRecords.length} issuer(s)`
            : 'No CAA issuance policy',
      status: !caaAnswered(result.data) ? 'info' : result.data.caaPresent ? 'pass' : 'warning',
      severity: !caaAnswered(result.data) ? 'info' : result.data.caaPresent ? 'none' : 'low',
      verdict: !caaAnswered(result.data) ? 'Partial' : result.data.caaPresent ? 'Secure' : 'Open issuance',
    })
    return result
  })

  /* ── Preflight ────────────────────────────────────────────────────────────
     One TCP connect, before anything expensive. It drives no stage of its own:
     the TLS stage owns the transport in the UI rail, and this is the evidence
     that stage reports when the port never answered. */
  const reachabilityResult = await runReachabilityEngine(
    host,
    port,
    REACHABILITY_TIMEOUT_MS,
    Math.max(2_000, Math.min(REACHABILITY_TIMEOUT_MS * 2 + 500, deadline - Date.now() - 2_000)),
  )
  const reachability = reachabilityResult.data
  emit({
    surface: 'tls',
    label: 'TCP reachability',
    detail: reachability.detail,
    /* An unreachable port is `info`, not `critical`, and the distinction is not
       softening the result — it is putting it in the right register. The hero's
       surfaces report CRYPTOGRAPHIC verdicts; a critical status paints the
       transport card red, which says "this endpoint's transport security is
       broken" when what was actually established is that there is no endpoint
       answering to assess. The unreachability itself is stated prominently by
       the stage rail, the report header, the TCP Connect step and Sophia. */
    status: 'info',
    severity: 'info',
    // Only the unreachable case claims the surface headline: when the port is
    // open this is a prerequisite, not the transport verdict, and letting it
    // write "Reachable" would overwrite the protocol result seconds later.
    ...(reachability.reachable ? {} : { verdict: 'Unreachable' }),
  })

  if (!reachability.reachable) {
    return unreachableBundle(host, port, startedAt, reachabilityResult, dnsPromise, onEngineStart, onEngine, emit)
  }

  onEngineStart?.('http-security')
  const httpPromise = runHttpEngine(host, port).then((result) => {
    // HSTS is scored as its own control and reported on its own card, so the
    // transport-header tally EXCLUDES it — exactly as `http-security` in
    // controls.ts does. Counting every header here made the live hero say
    // "4/9 hardened" while the report's Findings and Encryption Score panels
    // both said "3 of 8" for the same scan.
    // Same denominator as the `http-security` control: HSTS is scored
    // separately, and a header superseded by an equivalent control is exempt.
    const transport = result.data.headers.filter(
      (h) => h.name !== 'strict-transport-security' && h.status !== 'Not Applicable',
    )
    const hardened = transport.filter((h) => h.status === 'Healthy').length
    const ratio = hardened / Math.max(1, transport.length)
    onEngine?.(
      'http-security',
      result.ok,
      result.data.reachable
        ? `HTTP ${result.data.statusCode} · ${hardened}/${transport.length} hardened`
        : 'origin unreachable',
    )
    emit({
      surface: 'headers',
      label: 'Transport security headers',
      detail: result.data.reachable
        ? `${hardened}/${transport.length} headers hardened · HTTP ${result.data.statusCode}`
        : (result.data.error ?? 'Origin did not answer over HTTPS'),
      status: !result.data.reachable ? 'critical' : ratio >= 0.8 ? 'pass' : ratio >= 0.5 ? 'warning' : 'critical',
      severity: !result.data.reachable ? 'medium' : ratio >= 0.5 ? 'low' : 'medium',
      verdict: !result.data.reachable ? 'Unreachable' : ratio >= 0.8 ? 'Good' : ratio >= 0.5 ? 'Fair' : 'Weak',
    })
    return result
  })

  onEngineStart?.('tls-intelligence')
  /* TLS is the critical path and the reason the bundle has a budget at all, so
     it is handed everything left after reserving a slice for the certificate
     and crypto engines that must still run after it. */
  const tlsResult = await runTlsEngine(host, port, options.onObservation, deadline - 6_000)
  onEngine?.(
    'tls-intelligence',
    tlsResult.ok,
    tlsResult.ok
      ? `${tlsResult.data.negotiatedProtocol} · ${tlsResult.data.supportedProtocols.length} protocols · ${
          tlsResult.data.hybridGroups.length ? `hybrid PQ (${tlsResult.data.hybridGroups[0]})` : 'classical groups only'
        }`
      : tlsResult.error ?? 'handshake failed',
  )

  onEngineStart?.('certificate-intelligence')
  const certificateResult = await runCertificateEngine(host, port, options.onObservation)
  onEngine?.(
    'certificate-intelligence',
    certificateResult.ok,
    certificateResult.ok
      ? `${certificateResult.data.sanCount} SAN(s) · chain depth ${certificateResult.data.chainDepth} · ${
          certificateResult.data.chainTrusted ? 'trusted' : 'NOT trusted'
        }`
      : certificateResult.error ?? 'chain unavailable',
  )

  const [dnsResult, httpResult] = await Promise.all([dnsPromise, httpPromise])

  onEngineStart?.('cryptographic-intelligence')
  const cryptoResult = await runCryptoEngine(
    tlsResult.data,
    certificateResult.data,
    httpResult.data.hsts.status === 'Healthy',
  )
  emitCryptoStage(cryptoResult, tlsResult, onEngine, emit)

  const engines = [dnsResult, tlsResult, certificateResult, httpResult, cryptoResult]

  // Weighted so a missing HTTP origin does not read as a broken scan when the
  // cryptographic evidence — the point of the assessment — is complete.
  const weights: Record<string, number> = {
    'dns-intelligence': 15,
    'tls-intelligence': 35,
    'certificate-intelligence': 25,
    'http-security': 15,
    'cryptographic-intelligence': 10,
  }
  const confidence = clampScore(
    engines.reduce((sum, engine) => sum + engine.confidence * (weights[engine.engine] ?? 0), 0) / 100,
  )

  return {
    host,
    port,
    reachability: reachabilityResult,
    dns: dnsResult,
    tls: tlsResult,
    certificate: certificateResult,
    http: httpResult,
    crypto: cryptoResult,
    evidence: [reachabilityResult, ...engines].flatMap((engine) => engine.evidence),
    notes: [reachabilityResult, ...engines].flatMap((engine) => engine.notes),
    confidence,
    totalMs: Date.now() - startedAt,
  }
}

/**
 * Publish the cryptographic-intelligence stage.
 *
 * Extracted because it has to say two very different things and used to say only
 * one of them: the rail detail was `PQ readiness 0% · quantum risk Low` printed
 * UNCONDITIONALLY, so an endpoint that never completed a handshake got a stage
 * marked FAILED whose own text quoted a readiness percentage and a reassuring
 * risk level. Both numbers were computed from an empty evidence set — the
 * classic "absence of evidence rendered as good news".
 */
function emitCryptoStage(
  cryptoResult: EngineResult<CryptoIntelligenceData>,
  tlsResult: EngineResult<TlsIntelligence>,
  onEngine: OrchestratorOptions['onEngine'],
  emit: ObservationSink,
): void {
  const crypto = cryptoResult.data
  const hybrid = tlsResult.data.hybridGroups.length > 0

  if (!crypto.assessed) {
    // The engine ran and correctly concluded that nothing was observable. That
    // is a completed module with an unmeasured result — reported as such, with
    // no score attached, so the rail cannot imply a verdict that does not exist.
    onEngine?.(
      'cryptographic-intelligence',
      false,
      crypto.notAssessedReason ?? 'Not assessed — no handshake or certificate evidence to score.',
      true,
    )
    emit({
      surface: 'quantum',
      label: 'Post-quantum readiness',
      detail: crypto.notAssessedReason ?? 'No cryptographic evidence was collected, so readiness was not scored.',
      status: 'info',
      severity: 'info',
      verdict: 'Not measured',
    })
    return
  }

  onEngine?.(
    'cryptographic-intelligence',
    cryptoResult.ok,
    `PQ readiness ${crypto.postQuantumReadiness}% · quantum risk ${crypto.quantumRisk}`,
  )
  emit({
    surface: 'quantum',
    label: 'Post-quantum readiness',
    detail: hybrid
      ? `ML-KEM key establishment active (${tlsResult.data.primaryGroup}) · readiness ${crypto.postQuantumReadiness}%`
      : `Hybrid not detected · classical key establishment only · readiness ${crypto.postQuantumReadiness}%`,
    status: hybrid ? 'pass' : 'warning',
    severity: hybrid ? 'none' : 'medium',
    verdict: hybrid ? 'Hybrid ready' : (crypto.postQuantumReadiness ?? 0) >= 40 ? 'Fair' : 'Classical only',
    postQuantum: hybrid,
  })
}

/**
 * The bundle for an endpoint whose port never accepted a TCP connection.
 *
 * Everything that depends on a handshake is marked `unmeasured` with the SAME
 * reason string, so the rail, the controls, the findings table and the executive
 * summary all quote one explanation instead of four independently-worded
 * guesses. Nothing here is scored: an endpoint that did not answer has not
 * failed anything.
 *
 * DNS still completes — it was already in flight and it is the evidence that
 * distinguishes "the name points somewhere wrong" from "the service is down".
 */
async function unreachableBundle(
  host: string,
  port: number,
  startedAt: number,
  reachabilityResult: EngineResult<ReachabilityIntelligence>,
  dnsPromise: Promise<EngineResult<DnsIntelligence>>,
  onEngineStart: OrchestratorOptions['onEngineStart'],
  onEngine: OrchestratorOptions['onEngine'],
  emit: ObservationSink,
): Promise<ScanEvidenceBundle> {
  const reachability = reachabilityResult.data
  /* `reason` is the full sentence and belongs where the outcome is EXPLAINED —
     once, on the TLS stage, which owns the transport. `short` is the compact
     phrase for the places that merely have to say why they are empty; echoing
     the full sentence on three stages and three surface cards rendered the same
     paragraph six times over. */
  const reason = reachability.unreachableReason ?? `Port ${port} did not answer.`
  const short = reachability.summary

  const tls = unmeasuredResult('tls-intelligence', emptyTls(reason), reason)
  const certificate = unmeasuredResult('certificate-intelligence', emptyCertificate(reason), reason)
  const http = unmeasuredResult('http-security', emptyHttp(reason), reason)
  const crypto = unmeasuredResult(
    'cryptographic-intelligence',
    notAssessedCrypto(`Not assessed — ${short}, so no handshake or certificate evidence exists to score.`),
    reason,
  )

  // Each stage is announced started and then immediately resolved as
  // unavailable, so the rail shows the same six steps rather than silently
  // leaving three of them on "Waiting" forever.
  onEngineStart?.('tls-intelligence')
  onEngine?.('tls-intelligence', false, reason, true)
  onEngineStart?.('certificate-intelligence')
  onEngine?.('certificate-intelligence', false, `Chain not collected — ${short}`, true)
  onEngineStart?.('http-security')
  onEngine?.('http-security', false, `Headers not collected — ${short}`, true)

  emit({
    surface: 'certificate',
    label: 'Certificate chain',
    detail: `Not collected — ${short}`,
    status: 'info',
    severity: 'info',
    verdict: 'Not measured',
  })
  emit({
    surface: 'headers',
    label: 'Transport security headers',
    detail: `Not collected — ${short}`,
    status: 'info',
    severity: 'info',
    verdict: 'Not measured',
  })

  onEngineStart?.('cryptographic-intelligence')
  emitCryptoStage(crypto, tls, onEngine, emit)

  const dns = await dnsPromise

  return {
    host,
    port,
    reachability: reachabilityResult,
    dns,
    tls,
    certificate,
    http,
    crypto,
    evidence: [...reachabilityResult.evidence, ...dns.evidence],
    notes: [...reachabilityResult.notes, ...dns.notes],
    // DNS is the only cryptographic-assessment weight that was earned, so
    // confidence reflects exactly that and nothing else.
    confidence: clampScore((dns.confidence * 15) / 100),
    totalMs: Date.now() - startedAt,
  }
}

/** Empty bundle used when a scan cannot start at all. */
export function emptyBundle(host: string, port: number, error: string): ScanEvidenceBundle {
  const wrap = <T>(engine: string, data: T): EngineResult<T> => ({
    engine,
    data,
    ok: false,
    confidence: 0,
    evidence: [],
    notes: [],
    error,
    durationMs: 0,
  })
  return {
    host,
    port,
    reachability: wrap('endpoint-reachability', emptyReachability(error)),
    dns: wrap('dns-intelligence', emptyDns(host)),
    tls: wrap('tls-intelligence', emptyTls(error)),
    certificate: wrap('certificate-intelligence', emptyCertificate(error)),
    http: wrap('http-security', emptyHttp(error)),
    // `notAssessedCrypto` rather than a hand-written payload. The inline literal
    // this replaces published `quantumRisk: 'Critical', quantumRiskScore: 100`
    // for the no-evidence case, while `computeQuantumRisk` published `'Low'` for
    // the very same case — two contradictory fabrications for one condition,
    // both invented. There is now exactly one representation of "not assessed".
    crypto: wrap('cryptographic-intelligence', notAssessedCrypto(error)),
    evidence: [],
    notes: [],
    confidence: 0,
    totalMs: 0,
  }
}
