/**
 * QGuard Web Scanner — the platform's PUBLISHED scoring model, applied to
 * authenticated scan evidence.
 *
 * WHY THIS EXISTS
 * The web scanner used to grade on a private five-dimension model
 * (certificate / TLS / cipher / app-crypto / PQC) while /public-scan graded on
 * the twelve published categories in `SCORE_CATEGORY_DEFS`. The same host
 * therefore scored differently depending on which surface you looked at, with
 * no way to reconcile the two. This module maps what the authenticated scanner
 * observes onto those same twelve categories, with the same weights, so one
 * host produces one score whichever surface reports it.
 *
 * WHAT THIS SCANNER CANNOT SEE
 * OCSP stapling, Certificate Transparency and DNS CAA are public-edge DNS/TLS
 * extension probes that the authenticated scanner does not perform. They are
 * returned `applicable: false` — excluded from the weighted mean with their
 * weight redistributed — never scored 0. That is the difference between "we
 * looked and it is absent" and "we did not look", and it is the whole reason a
 * dashboard score can legitimately sit a point or two from a public one.
 */
import {
  postQuantumReadinessFromSignals,
  SCORE_CATEGORY_DEFS,
  weightedCategoryScore,
} from '../public-scan/grading-model'
import type {
  ApiSecurityResult,
  CertificateInfo,
  DetectionRuleResult,
  GitRepoScanResult,
  TlsAnalysisResult,
  WebCryptoScanResult,
  WebScanFinding,
} from './types'

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)))

export interface PublishedScoreCategory {
  key: string
  label: string
  weight: number
  /** 0-100 posture. Meaningless unless `applicable`. */
  score: number
  applicable: boolean
  /** The measurement this score was read from — shown verbatim in the UI. */
  observed: string
}

export interface PublishedScoringInput {
  tlsResult: TlsAnalysisResult | null
  certInfo: CertificateInfo | null
  apiResult: ApiSecurityResult | null
  repoResult: GitRepoScanResult | null
  webCryptoResult: WebCryptoScanResult | null
  ruleResults: DetectionRuleResult[]
  findings: WebScanFinding[]
}

const PQ_PATTERN = /ml-kem|ml-dsa|kyber|dilithium|slh-dsa|sphincs|falcon|frodo/i
const STATIC_RSA_PATTERN = /(^|_)RSA_WITH/i
const WEAK_CIPHER_PATTERN = /3DES|_DES_|RC4|NULL|EXPORT|MD5/i

/* ─── Individual categories ─────────────────────────────────────────────── */

/** TLS protocol versions the endpoint accepts. */
function tlsConfiguration(tls: TlsAnalysisResult | null): { score: number; observed: string } | null {
  if (!tls) return null
  const protocols = tls.supportedProtocols ?? []
  const observed = protocols.length ? protocols.join(', ') : tls.tlsVersion
  if (protocols.some((protocol) => /SSLv2|SSLv3/i.test(protocol))) return { score: 0, observed }
  if (protocols.some((protocol) => /TLSv1(\.0)?$|TLSv1\.1/i.test(protocol))) return { score: 45, observed }
  if (protocols.includes('TLSv1.3')) return { score: protocols.includes('TLSv1.2') ? 90 : 100, observed }
  if (protocols.includes('TLSv1.2')) return { score: 70, observed }
  return { score: /1\.3/.test(tls.tlsVersion) ? 100 : /1\.2/.test(tls.tlsVersion) ? 70 : 45, observed }
}

/** Strength of the negotiated suite and of everything else still accepted. */
function cipherSuites(tls: TlsAnalysisResult | null): { score: number; observed: string } | null {
  if (!tls) return null
  const suites = tls.cipherSuites ?? []
  const negotiated = tls.cipherSuite || ''
  let score = 100

  if (!/GCM|CHACHA20|POLY1305|CCM/i.test(negotiated)) score -= 20
  if (WEAK_CIPHER_PATTERN.test(negotiated)) score -= 40
  if (/CBC/i.test(negotiated)) score -= 20

  // Everything the server still ACCEPTS counts, not just what it chose.
  const staticRsa = suites.filter((suite) => STATIC_RSA_PATTERN.test(suite.name) || suite.category === 'rsa-kex')
  const weak = suites.filter((suite) => WEAK_CIPHER_PATTERN.test(suite.name))
  const cbc = suites.filter((suite) => /CBC/i.test(suite.name))
  if (staticRsa.length) score -= 50
  if (weak.length) score -= 40
  else if (cbc.length) score -= 15

  const observed = negotiated
    ? `${negotiated}${suites.length ? ` · ${suites.length} suite(s) enumerated` : ''}${staticRsa.length ? ' · static RSA accepted' : ''}`
    : `${suites.length} suite(s) enumerated`
  return { score: clamp(score), observed }
}

/** Leaf certificate algorithm, lifecycle and chain quality. */
function certificates(cert: CertificateInfo | null): { score: number; observed: string } | null {
  if (!cert) return null
  let score = 100
  const algorithm = (cert.publicKeyAlgorithm || '').toLowerCase()

  if (cert.isExpired) score -= 60
  if (cert.isSelfSigned) score -= 30

  if (PQ_PATTERN.test(algorithm)) score -= 0
  else if (algorithm.includes('rsa')) score -= cert.publicKeySize < 2048 ? 40 : 25
  else if (algorithm.includes('ec') || algorithm.includes('ed')) score -= 20
  else score -= 25

  if (/sha-?1|md5/i.test(cert.signatureAlgorithm || '')) score -= 40
  if ((cert.chain ?? []).some((entry) => entry.isExpired)) score -= 20

  const validityDays = certificateValidityDays(cert)
  const observed = `${cert.publicKeyAlgorithm}${cert.publicKeySize ? ` ${cert.publicKeySize}` : ''}${
    validityDays !== null ? ` · ${validityDays}-day lifetime` : ''
  }${cert.isExpired ? ' · EXPIRED' : ''}`
  return { score: clamp(score), observed }
}

/** Strength of the negotiated key-agreement mechanism. */
function keyExchange(tls: TlsAnalysisResult | null): { score: number; observed: string } | null {
  if (!tls) return null
  const kex = `${tls.keyExchange || ''} ${tls.negotiatedCurve || ''} ${tls.cipherSuite || ''}`
  const observed = `${tls.keyExchange || 'not observed'}${tls.negotiatedCurve ? ` (${tls.negotiatedCurve})` : ''}`
  if (PQ_PATTERN.test(kex)) return { score: 100, observed }
  if (/ECDHE|X25519|X448/i.test(kex)) return { score: 70, observed }
  if (/DHE/i.test(kex)) return { score: (tls.ephemeralKeySize ?? 0) >= 2048 ? 60 : 40, observed }
  if (/RSA/i.test(kex)) return { score: 20, observed }
  return { score: 40, observed }
}

/** Whether every session the endpoint will agree to is forward secret. */
function forwardSecrecy(tls: TlsAnalysisResult | null): { score: number; observed: string } | null {
  if (!tls) return null
  const ephemeral =
    Boolean(tls.ephemeralKeyType) || /ECDHE|DHE|X25519|X448|ML-KEM|Kyber/i.test(tls.keyExchange || '')
  const staticRsa = (tls.cipherSuites ?? []).filter(
    (suite) => STATIC_RSA_PATTERN.test(suite.name) || suite.category === 'rsa-kex',
  )
  if (!ephemeral) return { score: 0, observed: 'no ephemeral key agreement' }
  // Preferring ECDHE while still accepting static-RSA key transport is not full
  // forward secrecy — a client that asks for those suites gets none.
  return staticRsa.length
    ? { score: 70, observed: `${tls.keyExchange || 'ephemeral'} · ${staticRsa.length} static-RSA suite(s) still accepted` }
    : { score: 100, observed: `${tls.keyExchange || 'ephemeral'}${tls.negotiatedCurve ? ` (${tls.negotiatedCurve})` : ''}` }
}

/** Transport-security response headers, excluding HSTS (scored separately). */
function httpSecurityHeaders(api: ApiSecurityResult | null): { score: number; observed: string } | null {
  const headers = (api?.securityHeaders ?? []).filter((header) => header.name.toLowerCase() !== 'strict-transport-security')
  if (!api || headers.length === 0) return null
  const hardened = headers.filter((header) => header.secure).length
  return {
    score: clamp((hardened / headers.length) * 100),
    observed: `${hardened}/${headers.length} transport headers hardened`,
  }
}

function hsts(api: ApiSecurityResult | null): { score: number; observed: string } | null {
  if (!api?.securityHeaders?.length) return null
  const header = api.securityHeaders.find((entry) => entry.name.toLowerCase() === 'strict-transport-security')
  if (!header) return { score: 0, observed: 'absent' }
  if (!header.present) return { score: 0, observed: 'absent' }
  if (!header.secure) return { score: 50, observed: 'present, weak max-age' }
  const value = header.value ?? ''
  const preload = /preload/i.test(value)
  const subdomains = /includeSubDomains/i.test(value)
  return {
    score: preload && subdomains ? 100 : subdomains ? 90 : 80,
    observed: `enforced${subdomains ? ' · includeSubDomains' : ''}${preload ? ' · preload' : ''}`,
  }
}

/**
 * Share of the observed cryptographic material that is not quantum-vulnerable.
 * Application-code patterns count here too — repository and Web Crypto findings
 * are observations about the algorithms in use, which is exactly what this
 * category measures.
 */
function cryptographicAlgorithms(input: PublishedScoringInput): { score: number; observed: string } | null {
  const observedAlgorithms: Array<{ name: string; vulnerable: boolean }> = []
  const push = (name: string | null | undefined, vulnerable: boolean) => {
    const clean = (name ?? '').trim()
    if (!clean || observedAlgorithms.some((entry) => entry.name === clean)) return
    observedAlgorithms.push({ name: clean, vulnerable: vulnerable && !PQ_PATTERN.test(clean) })
  }

  if (input.tlsResult) {
    push(input.tlsResult.keyExchange, true)
    push(input.tlsResult.negotiatedCurve, true)
    push(input.tlsResult.signatureAlgorithm, true)
    for (const suite of input.tlsResult.cipherSuites ?? []) push(suite.encryption, false)
    for (const protocol of input.tlsResult.supportedProtocols ?? []) {
      push(protocol, /TLSv1(\.0)?$|TLSv1\.1|SSLv/i.test(protocol))
    }
  }
  if (input.certInfo) {
    push(input.certInfo.publicKeyAlgorithm, true)
    push(input.certInfo.signatureAlgorithm, /sha-?1|md5|rsa|ecdsa/i.test(input.certInfo.signatureAlgorithm || ''))
  }
  for (const pattern of input.repoResult?.patterns ?? []) push(pattern.algorithm, pattern.threatLevel !== 'SAFE')
  for (const pattern of input.webCryptoResult?.patterns ?? []) push(pattern.algorithm, pattern.threatLevel !== 'SAFE')

  if (observedAlgorithms.length === 0) return null
  const safe = observedAlgorithms.filter((entry) => !entry.vulnerable).length
  return {
    score: clamp((safe / observedAlgorithms.length) * 100),
    observed: `${observedAlgorithms.length} algorithms observed · ${safe} quantum-safe`,
  }
}

function certificateValidityDays(cert: CertificateInfo | null): number | null {
  if (!cert?.validFrom || !cert?.validTo) return null
  const from = Date.parse(cert.validFrom)
  const to = Date.parse(cert.validTo)
  if (!Number.isFinite(from) || !Number.isFinite(to)) return null
  return Math.max(0, Math.round((to - from) / 86400000))
}

/* ─── Assembly ──────────────────────────────────────────────────────────── */

/**
 * Build all twelve published categories from authenticated scan evidence.
 * Categories this scanner cannot probe come back `applicable: false` with the
 * reason in `observed`, so the UI can list every category — as /public-scan
 * does — without implying a measurement that never happened.
 */
export function buildPublishedCategories(input: PublishedScoringInput): PublishedScoreCategory[] {
  const { tlsResult, certInfo, apiResult } = input

  const pq =
    tlsResult || certInfo
      ? postQuantumReadinessFromSignals({
          hybridObserved: PQ_PATTERN.test(
            `${tlsResult?.keyExchange ?? ''} ${tlsResult?.negotiatedCurve ?? ''} ${tlsResult?.cipherSuite ?? ''}`,
          ),
          pqSignatureObserved: PQ_PATTERN.test(
            `${certInfo?.signatureAlgorithm ?? ''} ${certInfo?.publicKeyAlgorithm ?? ''} ${tlsResult?.signatureAlgorithm ?? ''}`,
          ),
          tls13Offered: (tlsResult?.supportedProtocols ?? []).includes('TLSv1.3'),
          certificateValidityDays: certificateValidityDays(certInfo),
          // Not probed by the authenticated scanner — the model simply does not
          // award these two allowances rather than pretending to observe them.
          certificateTransparency: false,
          hstsEnforced: Boolean(
            apiResult?.securityHeaders?.find(
              (header) => header.name.toLowerCase() === 'strict-transport-security' && header.secure,
            ),
          ),
        })
      : null

  const NOT_PROBED = 'not observable from an authenticated network scan'

  const measured: Record<string, { score: number; observed: string } | null> = {
    'tls-configuration': tlsConfiguration(tlsResult),
    'cipher-suites': cipherSuites(tlsResult),
    certificates: certificates(certInfo),
    'key-exchange': keyExchange(tlsResult),
    'forward-secrecy': forwardSecrecy(tlsResult),
    'http-security-headers': httpSecurityHeaders(apiResult),
    hsts: hsts(apiResult),
    // Public-edge probes the authenticated scanner does not perform.
    'ocsp-stapling': null,
    'certificate-transparency': null,
    'dns-caa': null,
    'cryptographic-algorithms': cryptographicAlgorithms(input),
    'post-quantum-readiness': pq ? { score: pq.score, observed: `${pq.score}% readiness` } : null,
  }

  const UNPROBED = new Set(['ocsp-stapling', 'certificate-transparency', 'dns-caa'])

  return SCORE_CATEGORY_DEFS.map((def) => {
    const row = measured[def.key] ?? null
    return {
      key: def.key,
      label: def.label,
      weight: def.weight,
      score: row?.score ?? 0,
      applicable: row !== null,
      observed: row?.observed ?? (UNPROBED.has(def.key) ? NOT_PROBED : 'not observed'),
    }
  })
}

/**
 * The composite posture (0-100, higher is better) over the published model.
 * Exposure — what the rest of the scanner persists as `riskScore` — is
 * `100 - this`.
 */
export function publishedPostureScore(categories: PublishedScoreCategory[]): number {
  return weightedCategoryScore(categories)
}
