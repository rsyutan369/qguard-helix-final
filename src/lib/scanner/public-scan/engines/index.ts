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
 * DNS and HTTP are independent of TLS and run alongside it. TLS and certificate
 * probing are serialised because `analyzeTls` alone opens ~12 sockets to
 * enumerate protocols and cipher suites; stacking more concurrent handshakes on
 * top trips CDN per-IP connection limits, and a throttled RST is
 * indistinguishable from "not supported" — a false negative on the very
 * measurements this scanner exists to make.
 */

import { runCertificateEngine, emptyCertificate, type CertificateIntelligence } from './certificate-engine'
import { runCryptoEngine, type CryptoIntelligenceData } from './crypto-engine'
import { runDnsEngine, emptyDns, type DnsIntelligence } from './dns-engine'
import { runHttpEngine, emptyHttp, type HttpIntelligence } from './http-engine'
import { runTlsEngine, emptyTls, type TlsIntelligence } from './tls-engine'
import {
  type EngineResult,
  type Evidence,
  type ObservationSink,
  clampScore,
  observationEmitter,
} from './contract'

export * from './contract'
export * from './dns-engine'
export * from './http-engine'
export * from './tls-engine'
export * from './certificate-engine'
export * from './crypto-engine'

/** One entry per engine, for the scanner-capability disclosure. */
export const ENGINE_REGISTRY = [
  { id: 'dns-intelligence', name: 'DNS Intelligence Engine', covers: ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'DNSSEC', 'SPF', 'DKIM', 'DMARC'] },
  { id: 'tls-intelligence', name: 'TLS Intelligence Engine', covers: ['Protocol versions', 'Cipher suites', 'ALPN', 'Named groups', 'Hybrid PQ groups', 'Session resumption', 'Forward secrecy'] },
  { id: 'certificate-intelligence', name: 'Certificate Intelligence Engine', covers: ['Chain', 'Trust verification', 'SAN/CN', 'Key + signature', 'Validity', 'OCSP', 'SCT / CT', 'CRL', 'Must-staple'] },
  { id: 'http-security', name: 'HTTP Security Engine', covers: ['HSTS', 'CSP', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy', 'COOP', 'COEP', 'CORP', 'CDN/WAF fingerprint'] },
  { id: 'cryptographic-intelligence', name: 'Cryptographic Intelligence Engine', covers: ['Algorithm catalogue', 'Classification', 'Post-quantum readiness', 'Quantum Risk Engine'] },
] as const

export interface ScanEvidenceBundle {
  host: string
  port: number
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
  /** Called as each engine finishes, for SSE progress. */
  onEngine?: (engine: string, ok: boolean, detail: string) => void
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
        result.data.caaQueryable ? (result.data.caaPresent ? 'present' : 'absent') : 'unknown'
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
      detail: !result.data.caaQueryable
        ? 'CAA not observable from this resolver'
        : result.data.caaPresent
          ? `CAA record found · ${result.data.caaRecords.length} issuer(s)`
          : 'No CAA issuance policy',
      status: !result.data.caaQueryable ? 'info' : result.data.caaPresent ? 'pass' : 'warning',
      severity: !result.data.caaQueryable ? 'info' : result.data.caaPresent ? 'none' : 'low',
      verdict: !result.data.caaQueryable ? 'Partial' : result.data.caaPresent ? 'Secure' : 'Open issuance',
    })
    return result
  })

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
  onEngine?.(
    'cryptographic-intelligence',
    cryptoResult.ok,
    `PQ readiness ${cryptoResult.data.postQuantumReadiness}% · quantum risk ${cryptoResult.data.quantumRisk}`,
  )
  emit({
    surface: 'quantum',
    label: 'Post-quantum readiness',
    detail: tlsResult.data.hybridGroups.length
      ? `ML-KEM key establishment active (${tlsResult.data.primaryGroup}) · readiness ${cryptoResult.data.postQuantumReadiness}%`
      : `Hybrid not detected · classical key establishment only · readiness ${cryptoResult.data.postQuantumReadiness}%`,
    status: tlsResult.data.hybridGroups.length ? 'pass' : 'warning',
    severity: tlsResult.data.hybridGroups.length ? 'none' : 'medium',
    verdict: tlsResult.data.hybridGroups.length
      ? 'Hybrid ready'
      : cryptoResult.data.postQuantumReadiness >= 40
        ? 'Fair'
        : 'Classical only',
    postQuantum: tlsResult.data.hybridGroups.length > 0,
  })

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
    dns: dnsResult,
    tls: tlsResult,
    certificate: certificateResult,
    http: httpResult,
    crypto: cryptoResult,
    evidence: engines.flatMap((engine) => engine.evidence),
    notes: engines.flatMap((engine) => engine.notes),
    confidence,
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
    dns: wrap('dns-intelligence', emptyDns(host)),
    tls: wrap('tls-intelligence', emptyTls(error)),
    certificate: wrap('certificate-intelligence', emptyCertificate(error)),
    http: wrap('http-security', emptyHttp(error)),
    crypto: wrap('cryptographic-intelligence', {
      algorithms: [],
      keyExchange: 'unknown',
      keyExchangeClass: 'Classical',
      forwardSecrecy: 'Not observed',
      hybridObserved: false,
      pqSignatureObserved: false,
      hybridGroups: [],
      kemParameterSets: [],
      postQuantumReadiness: 0,
      readinessReasons: [],
      quantumRisk: 'Critical',
      quantumRiskScore: 100,
      riskFactors: [],
      migrationTargets: [],
    } as CryptoIntelligenceData),
    evidence: [],
    notes: [],
    confidence: 0,
    totalMs: 0,
  }
}
