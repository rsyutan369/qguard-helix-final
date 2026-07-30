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
import { type EngineResult, type Evidence, clampScore } from './contract'

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

export interface OrchestratorOptions {
  host: string
  port: number
  /** Called as each engine finishes, for SSE progress. */
  onEngine?: (engine: string, ok: boolean, detail: string) => void
}

export async function runScanEngines(options: OrchestratorOptions): Promise<ScanEvidenceBundle> {
  const { host, port, onEngine } = options
  const startedAt = Date.now()

  // DNS and HTTP touch different infrastructure than the TLS probes, so they
  // run alongside the TLS chain without competing for the same connection pool.
  const dnsPromise = runDnsEngine(host).then((result) => {
    onEngine?.(
      'dns-intelligence',
      result.ok,
      `${result.data.addressCount} address(es), CAA ${
        result.data.caaQueryable ? (result.data.caaPresent ? 'present' : 'absent') : 'unknown'
      }`,
    )
    return result
  })

  const httpPromise = runHttpEngine(host, port).then((result) => {
    onEngine?.(
      'http-security',
      result.ok,
      result.data.reachable
        ? `HTTP ${result.data.statusCode} · ${result.data.headers.filter((h) => h.status === 'Healthy').length}/${result.data.headers.length} hardened`
        : 'origin unreachable',
    )
    return result
  })

  const tlsResult = await runTlsEngine(host, port)
  onEngine?.(
    'tls-intelligence',
    tlsResult.ok,
    tlsResult.ok
      ? `${tlsResult.data.negotiatedProtocol} · ${tlsResult.data.supportedProtocols.length} protocols · ${
          tlsResult.data.hybridGroups.length ? `hybrid PQ (${tlsResult.data.hybridGroups[0]})` : 'classical groups only'
        }`
      : tlsResult.error ?? 'handshake failed',
  )

  const certificateResult = tlsResult.ok
    ? await runCertificateEngine(host, port)
    : { ...(await runCertificateEngine(host, port)) }
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
