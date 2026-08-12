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
 * WHAT THIS SCANNER CAN AND CANNOT SEE
 * A category is `applicable: false` — excluded from the weighted mean with its
 * weight redistributed, never scored 0 — whenever the evidence behind it was not
 * collected for this target. That is the difference between "we looked and it is
 * absent" and "we did not look".
 *
 * OCSP stapling, Certificate Transparency and DNS CAA used to be permanently
 * inapplicable here on the grounds that an authenticated scan cannot probe them.
 * That stopped being true when the edge engine joined this pipeline: it staples,
 * counts SCTs and queries CAA on every web target, and the dashboard already
 * renders those readings. Scoring them as unmeasured while the UI displayed the
 * measurement was itself an inconsistency, so they are now scored from the edge
 * bundle when it exists and inapplicable only when it does not.
 *
 * WHY `edgeIntelligence` IS NOT OPTIONAL SUGAR
 * Node's `getEphemeralKeyInfo()` is empty for TLS 1.3, so `tlsResult.keyExchange`
 * reads `"ECDHE (TLS 1.3 key_share)"` on EVERY modern endpoint. Scoring the key
 * exchange, the algorithm census and post-quantum readiness from that label
 * scored a live X25519MLKEM768 endpoint as classical — the headline, the category
 * bars and every surface card derived from them were all wrong together, and
 * consistently so, which is why it read as a design choice rather than a bug.
 * Measured evidence is passed in and takes precedence over the socket label
 * wherever the two disagree.
 */
import {
  postQuantumReadinessFromSignals,
  SCORE_CATEGORY_DEFS,
  weightedCategoryScore,
} from '../public-scan/grading-model'
import { measuredKeyAgreement, type EdgeIntelligence, type MeasuredKeyAgreement } from './edge-intelligence-model'
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
  /**
   * The public-edge measurement for this target, when the edge phase ran.
   *
   * Optional in the TYPE only so historical callers keep compiling; every
   * category below treats its absence as "not measured" rather than as a
   * negative result, so omitting it can never manufacture a passing score.
   */
  edgeIntelligence?: EdgeIntelligence | null
}

const PQ_PATTERN = /ml-kem|ml-dsa|kyber|dilithium|slh-dsa|sphincs|falcon|frodo/i
const STATIC_RSA_PATTERN = /(^|_)RSA_WITH/i
const WEAK_CIPHER_PATTERN = /3DES|_DES_|RC4|NULL|EXPORT|MD5/i

/* ─── Individual categories ─────────────────────────────────────────────── */

/** TLS protocol versions the endpoint accepts. */
function tlsConfiguration(
  tls: TlsAnalysisResult | null,
  edge: EdgeIntelligence | null,
): { score: number; observed: string } | null {
  if (!tls) return null
  /* The edge engine probes every version individually; the socket only ever
     knows the one it negotiated. Where both have an answer the probed list is
     the stronger evidence and wins. */
  const protocols = edge?.transport.supportedProtocols?.length
    ? edge.transport.supportedProtocols
    : (tls.supportedProtocols ?? [])
  const observed = protocols.length ? protocols.join(', ') : tls.tlsVersion
  if (protocols.some((protocol) => /SSLv2|SSLv3/i.test(protocol))) return { score: 0, observed }
  if (protocols.some((protocol) => /TLSv1(\.0)?$|TLSv1\.1/i.test(protocol))) return { score: 45, observed }
  if (protocols.includes('TLSv1.3')) return { score: protocols.includes('TLSv1.2') ? 90 : 100, observed }
  if (protocols.includes('TLSv1.2')) return { score: 70, observed }
  return { score: /1\.3/.test(tls.tlsVersion) ? 100 : /1\.2/.test(tls.tlsVersion) ? 70 : 45, observed }
}

/** Strength of the negotiated suite and of everything else still accepted. */
function cipherSuites(
  tls: TlsAnalysisResult | null,
  edge: EdgeIntelligence | null,
): { score: number; observed: string } | null {
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
  /* Static-RSA key transport is the one penalty a hybrid key agreement must
     NEVER offset. ML-KEM lives only in the TLS 1.3 key_share, so a client that
     negotiates one of these suites gets a session with no forward secrecy and
     no post-quantum protection at all. */
  const staticRsaAccepted = staticRsa.length > 0 || edge?.transport.staticRsaAccepted === true
  if (staticRsaAccepted) score -= 50
  if (weak.length) score -= 40
  else if (cbc.length) score -= 15

  const observed = negotiated
    ? `${negotiated}${suites.length ? ` · ${suites.length} suite(s) enumerated` : ''}${staticRsaAccepted ? ' · static RSA accepted' : ''}`
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

/**
 * Strength of the negotiated key-agreement mechanism.
 *
 * The MEASURED group decides. `tls.keyExchange` is consulted only when named-group
 * probing never ran, and its TLS 1.3 value is a protocol guarantee ("some ephemeral
 * (EC)DHE group was used", RFC 8446) — not a statement about WHICH group, which it
 * cannot make. Reading it as one is what scored a hybrid endpoint 70/100.
 */
function keyExchange(
  tls: TlsAnalysisResult | null,
  kem: MeasuredKeyAgreement,
): { score: number; observed: string } | null {
  if (!tls) return null

  if (kem.hybrid) {
    return {
      score: 100,
      observed: `${kem.group} — ${kem.classicalComponent} + ${kem.postQuantumComponent}, accepted in isolation across ${kem.handshakes} handshake(s)`,
    }
  }
  if (kem.pureKem) {
    /* Real post-quantum key agreement, but with no classical hedge: a flaw in
       the lattice assumption has no fallback. Strong, not perfect. */
    return { score: 90, observed: `${kem.group} — post-quantum only, no classical hedge` }
  }

  const kex = `${tls.keyExchange || ''} ${tls.negotiatedCurve || ''} ${tls.cipherSuite || ''}`
  const probedSuffix = kem.probed ? ' · every hybrid ML-KEM group was offered in isolation and refused' : ''
  const observed = `${tls.keyExchange || 'not observed'}${tls.negotiatedCurve ? ` (${tls.negotiatedCurve})` : ''}${probedSuffix}`
  if (PQ_PATTERN.test(kex)) return { score: 100, observed }
  if (/ECDHE|X25519|X448/i.test(kex)) return { score: 70, observed }
  if (/DHE/i.test(kex)) return { score: (tls.ephemeralKeySize ?? 0) >= 2048 ? 60 : 40, observed }
  if (/RSA/i.test(kex)) return { score: 20, observed }
  return { score: 40, observed }
}

/** Whether every session the endpoint will agree to is forward secret. */
function forwardSecrecy(
  tls: TlsAnalysisResult | null,
  edge: EdgeIntelligence | null,
  kem: MeasuredKeyAgreement,
): { score: number; observed: string } | null {
  if (!tls) return null
  const ephemeral =
    kem.kemApplied ||
    edge?.transport.forwardSecrecy === true ||
    Boolean(tls.ephemeralKeyType) ||
    /ECDHE|DHE|X25519|X448|ML-KEM|Kyber/i.test(tls.keyExchange || '')
  const staticRsa = (tls.cipherSuites ?? []).filter(
    (suite) => STATIC_RSA_PATTERN.test(suite.name) || suite.category === 'rsa-kex',
  )
  const staticRsaAccepted = staticRsa.length > 0 || edge?.transport.staticRsaAccepted === true
  const label = kem.group ?? tls.keyExchange ?? 'ephemeral'
  if (!ephemeral) return { score: 0, observed: 'no ephemeral key agreement' }
  // Preferring ECDHE while still accepting static-RSA key transport is not full
  // forward secrecy — a client that asks for those suites gets none.
  return staticRsaAccepted
    ? {
        score: 70,
        observed: `${label} · ${staticRsa.length || 'some'} static-RSA suite(s) still accepted`,
      }
    : { score: 100, observed: `${label}${tls.negotiatedCurve ? ` (${tls.negotiatedCurve})` : ''}` }
}

/* ─── Public-edge categories ────────────────────────────────────────────────
   Measured by the edge engine, which now runs inside this pipeline. Each returns
   null — inapplicable, weight redistributed — when the edge phase did not reach
   the target, so "not probed" never renders as a failing zero. */

function ocspStapling(edge: EdgeIntelligence | null): { score: number; observed: string } | null {
  const cert = edge?.certificate
  if (!cert?.probed) return null
  if (cert.ocspStapled) return { score: 100, observed: 'stapled in the handshake' }
  /* A must-staple certificate that does not staple is a hard failure: relying
     parties are instructed to refuse the connection. Absent stapling without
     that commitment is a latency and privacy weakness, not a broken control. */
  if (cert.mustStaple) return { score: 0, observed: 'must-staple asserted but no response stapled' }
  return { score: 40, observed: cert.ocspUri ? 'not stapled — responder reachable off-path' : 'not stapled' }
}

function certificateTransparency(edge: EdgeIntelligence | null): { score: number; observed: string } | null {
  const cert = edge?.certificate
  if (!cert?.probed) return null
  if (!cert.sctPresent) return { score: 0, observed: 'no SCTs in the certificate, handshake or stapled response' }
  // Chrome's CT policy floor is two independent logs for most lifetimes.
  return { score: cert.sctCount >= 2 ? 100 : 70, observed: `${cert.sctCount} SCT(s)` }
}

function dnsCaa(edge: EdgeIntelligence | null): { score: number; observed: string } | null {
  const dns = edge?.dns
  // Not queryable is not the same as absent — a blocked resolver is unmeasured.
  if (!dns?.probed || !dns.caaQueryable) return null
  if (!dns.caaPresent) return { score: 0, observed: 'no CAA record — any CA may issue for this name' }
  return {
    score: 100,
    observed: `${dns.caaRecords.length} CAA record(s)${dns.caaAtName ? ` at ${dns.caaAtName}` : ''}`,
  }
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
function cryptographicAlgorithms(
  input: PublishedScoringInput,
  kem: MeasuredKeyAgreement,
): { score: number; observed: string } | null {
  const observedAlgorithms: Array<{ name: string; vulnerable: boolean }> = []
  const push = (name: string | null | undefined, vulnerable: boolean) => {
    const clean = (name ?? '').trim()
    if (!clean || observedAlgorithms.some((entry) => entry.name === clean)) return
    observedAlgorithms.push({ name: clean, vulnerable: vulnerable && !PQ_PATTERN.test(clean) })
  }

  if (input.tlsResult) {
    /* The key agreement is entered as the MEASURED group, never as the socket's
       generic TLS 1.3 label. Pushing `"ECDHE (TLS 1.3 key_share)"` as vulnerable
       counted a hybrid ML-KEM handshake against the very census that is supposed
       to notice it had migrated. */
    if (kem.kemApplied && kem.group) {
      push(kem.group, false)
      push(kem.classicalComponent, true)
      push(kem.postQuantumComponent, false)
    } else {
      push(input.tlsResult.keyExchange, true)
      push(input.tlsResult.negotiatedCurve, true)
    }
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
  const edge = input.edgeIntelligence ?? null
  const kem = measuredKeyAgreement(edge)

  const edgeCert = edge?.certificate
  const pq =
    tlsResult || certInfo
      ? postQuantumReadinessFromSignals({
          /* MEASURED, not pattern-matched. The old expression tested the socket's
             key-exchange label for "ML-KEM", which a TLS 1.3 handshake never
             contains, so this forfeited the model's 55-point hybrid allowance on
             every hybrid endpoint in existence. */
          hybridObserved: kem.hybrid || kem.pureKem,
          pqSignatureObserved:
            edge?.quantum.pqSignatureObserved === true ||
            PQ_PATTERN.test(
              `${certInfo?.signatureAlgorithm ?? ''} ${certInfo?.publicKeyAlgorithm ?? ''} ${tlsResult?.signatureAlgorithm ?? ''}`,
            ),
          tls13Offered:
            (edge?.transport.supportedProtocols ?? tlsResult?.supportedProtocols ?? []).includes('TLSv1.3'),
          certificateValidityDays: certificateValidityDays(certInfo) ?? edgeCert?.validityDays ?? null,
          // Now a real reading whenever the edge phase ran, and a plain `false`
          // only when it did not — the model awards no allowance either way, but
          // a present SCT set is no longer discarded.
          certificateTransparency: edgeCert?.probed ? edgeCert.sctPresent : false,
          hstsEnforced:
            edge?.http.hsts.present === true
              ? edge.http.hsts.status.toLowerCase().includes('enforc') || edge.http.hsts.maxAge !== null
              : Boolean(
                  apiResult?.securityHeaders?.find(
                    (header) => header.name.toLowerCase() === 'strict-transport-security' && header.secure,
                  ),
                ),
        })
      : null

  const NOT_PROBED = 'the public-edge phase did not reach this target, so this control was not measured'

  const measured: Record<string, { score: number; observed: string } | null> = {
    'tls-configuration': tlsConfiguration(tlsResult, edge),
    'cipher-suites': cipherSuites(tlsResult, edge),
    certificates: certificates(certInfo),
    'key-exchange': keyExchange(tlsResult, kem),
    'forward-secrecy': forwardSecrecy(tlsResult, edge, kem),
    'http-security-headers': httpSecurityHeaders(apiResult),
    hsts: hsts(apiResult),
    // Measured by the edge engine that now runs inside this pipeline.
    'ocsp-stapling': ocspStapling(edge),
    'certificate-transparency': certificateTransparency(edge),
    'dns-caa': dnsCaa(edge),
    'cryptographic-algorithms': cryptographicAlgorithms(input, kem),
    'post-quantum-readiness': pq
      ? { score: pq.score, observed: `${pq.score}% readiness · ${pq.reasons.slice(0, 2).join(' · ') || 'measured from the observed edge surface'}` }
      : null,
  }

  const EDGE_MEASURED = new Set(['ocsp-stapling', 'certificate-transparency', 'dns-caa'])

  return SCORE_CATEGORY_DEFS.map((def) => {
    const row = measured[def.key] ?? null
    return {
      key: def.key,
      label: def.label,
      weight: def.weight,
      score: row?.score ?? 0,
      applicable: row !== null,
      observed: row?.observed ?? (EDGE_MEASURED.has(def.key) ? NOT_PROBED : 'not observed'),
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
