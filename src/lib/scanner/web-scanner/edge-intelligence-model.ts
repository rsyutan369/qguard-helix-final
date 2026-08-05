/**
 * QGuard Web Scanner — Public Edge Intelligence: isomorphic model.
 *
 * The SHAPE of the public-edge evidence bundle, plus the pure derivations that
 * turn it into operator-facing verdicts. Nothing here touches a socket, a
 * resolver or a file — deliberately.
 *
 * WHY IT IS SPLIT FROM THE COLLECTOR
 * ----------------------------------
 * `edge-intelligence.ts` runs the probes, so it transitively imports node:tls,
 * node:dns and node:https. The dashboard renders the same verdicts in the
 * browser. Importing the collector from a client component just to reach one
 * display helper would drag the whole Node surface into the browser bundle, and
 * the usual escape — retyping the shape and rewriting the helper on the client
 * — is precisely how a UI ends up disagreeing with the backend that produced
 * its numbers.
 *
 * So the contract and the derivations live here, on both sides of the wire, and
 * the collector imports them like everyone else.
 */

/* ─────────────────────────────────────────────────────────────────── model ── */

/** How a control renders. `unknown` means "not measured", never "failed". */
export type EdgeControlState = 'pass' | 'fail' | 'partial' | 'info' | 'unknown'

/** One measured control, with the evidence that produced its verdict. */
export interface EdgeControl {
  /** Operator-facing verdict, e.g. `Applied`, `Enforced`, `Not offered`. */
  value: string
  state: EdgeControlState
  detail: string
  /** Supporting observations, shown verbatim. Empty when nothing was measured. */
  evidence: Array<{ label: string; value: string }>
}

export interface EdgePostQuantumKeyAgreement extends EdgeControl {
  /** Groups accepted with a classical hedge (ECDHE + ML-KEM). */
  hybridGroups: string[]
  /** Standalone ML-KEM groups — real, but a different risk posture. */
  pureKemGroups: string[]
  classicalGroups: string[]
  primaryGroup: string | null
  kemParameterSets: string[]
  classicalComponent: string | null
  postQuantumComponent: string | null
  /** True when named-group probing ran at all. */
  probed: boolean
  /** True when the TLS 1.3-only hybrid groups were reachable to probe. */
  hybridProbed: boolean
  /** Handshakes actually spent. Provenance, never an estimate. */
  handshakes: number
  inconclusiveGroups: string[]
  unstableGroups: string[]
  untestableGroups: string[]
  confidence: number
}

export interface EdgeTransport {
  negotiatedProtocol: string | null
  supportedProtocols: string[]
  legacyProtocols: string[]
  negotiatedCipher: string | null
  keyExchange: string
  forwardSecrecy: boolean
  forwardSecrecyBasis: string
  staticRsaAccepted: boolean
  alpn: string | null
  alpnOffered: string[]
  http2: boolean
  /** False when no handshake completed, so ALPN is unknown rather than absent. */
  alpnProbed: boolean
  sessionTickets: boolean | null
  sessionReuse: boolean | null
  handshakeMs: number | null
  error: string | null
}

export interface EdgeCertificateSurface {
  probed: boolean
  ocspStapled: boolean
  ocspResponderState: string
  ocspResponderDetail: string | null
  ocspUri: string | null
  mustStaple: boolean
  crlDistributionPoints: string[]
  sctPresent: boolean
  sctCount: number
  subjectAltNames: string[]
  sanCount: number
  isWildcard: boolean
  chainDepth: number
  chainTrusted: boolean | null
  trustError: string | null
  hostnameMatches: boolean | null
  daysRemaining: number
  validityDays: number
  error: string | null
}

export interface EdgeDnsSurface {
  probed: boolean
  addresses: string[]
  addressCount: number
  caaQueryable: boolean
  caaPresent: boolean
  caaRecords: string[]
  caaSource: string | null
  caaAtName: string | null
  dnssecQueryable: boolean
  dnssecSigned: boolean
  dnssecValidated: boolean
  spf: string | null
  dmarc: string | null
  transports: string[]
  resolvedVia: string
  error: string | null
}

export interface EdgeHttpHeader {
  name: string
  group: string
  present: boolean
  value: string | null
  status: string
  weakness: string | null
  supersededBy: string | null
}

export interface EdgeHttpSurface {
  probed: boolean
  reachable: boolean
  statusCode: number | null
  httpVersion: string | null
  hsts: {
    present: boolean
    status: string
    raw: string | null
    maxAge: number | null
    includeSubDomains: boolean
    preload: boolean
    preloadEligible: boolean
    preloadBlockers: string[]
  }
  headers: EdgeHttpHeader[]
  /** Transport headers hardened / applicable. HSTS is scored on its own card. */
  hardenedCount: number
  applicableCount: number
  fingerprint: {
    server: string | null
    poweredBy: string | null
    cdn: string | null
    waf: string | null
    cloudProvider: string | null
    reverseProxy: string | null
    signals: string[]
  }
  error: string | null
}

/**
 * The quantum verdict, derived from transport + certificate evidence only.
 *
 * `Vulnerable` and `Hybrid-protected` are the same vocabulary /public-scan
 * publishes, so the two surfaces classify one host identically.
 */
export type EdgeQuantumVulnerability =
  | 'Quantum-safe'
  | 'Hybrid-protected'
  | 'Classical only'
  | 'High Risk'
  | 'Vulnerable'
  | 'Unknown'

export interface EdgeQuantumSurface {
  hybridObserved: boolean
  pqSignatureObserved: boolean
  keyExchange: string
  keyExchangeClass: string
  forwardSecrecy: string
  kemParameterSets: string[]
  postQuantumReadiness: number
  readinessReasons: string[]
  quantumRisk: 'Low' | 'Medium' | 'High' | 'Critical'
  quantumRiskScore: number
  riskFactors: Array<{ factor: string; observed: string; impact: string; explanation: string }>
  vulnerability: EdgeQuantumVulnerability
  vulnerabilityReason: string
  migrationTargets: Array<{ name: string; standard: string; replaces: string; rationale: string }>
}

export interface EdgeIntelligence {
  host: string
  port: number
  probedAt: string
  durationMs: number
  /** 0-100 across the five engines, weighted by contribution. */
  confidence: number
  notes: string[]
  pqKeyAgreement: EdgePostQuantumKeyAgreement
  transport: EdgeTransport
  certificate: EdgeCertificateSurface
  dns: EdgeDnsSurface
  http: EdgeHttpSurface
  quantum: EdgeQuantumSurface
}


/* ─────────────────────────────────────────────────── quantum vulnerability ── */

/**
 * The Cryptographic Intelligence headline verdict.
 *
 * Previously derived by regex over FINDING TITLES: any finding whose algorithm
 * string mentioned ML-KEM or ML-DSA flipped the whole estate to
 * "Hybrid-protected". Recommendation-shaped titles ("Migrate to ML-KEM-768")
 * and Scanner_2 migration entries both match that pattern, which is how
 * expired.badssl.com — TLS 1.2 only, expired chain, static RSA accepted, zero
 * post-quantum anything — was reported as hybrid-protected.
 *
 * The verdict now comes from the transport and certificate measurements alone:
 *
 *   Quantum-safe       hybrid key agreement AND a post-quantum certificate
 *                      signature. Both halves of the session survive a CRQC.
 *   Hybrid-protected   hybrid key agreement, classical authentication. Recorded
 *                      traffic stays confidential; impersonation is still a
 *                      future risk, which is a materially lower exposure.
 *   Vulnerable         a Critical quantum-risk factor with no hybrid protection
 *                      — the key exchange is fully recoverable.
 *   High Risk          no hybrid, worst factor High (e.g. classical certificate
 *                      key with legacy protocol exposure).
 *   Classical only     measured, classical throughout, nothing rated High.
 *   Unknown            no transport evidence. Never guessed.
 */
export function classifyQuantumVulnerability(input: {
  hasTransportEvidence: boolean
  hybridObserved: boolean
  pqSignatureObserved: boolean
  quantumRisk: 'Low' | 'Medium' | 'High' | 'Critical'
  hybridProbed: boolean
  supportsTls13: boolean
  /**
   * Critical factors that are NOT the key exchange — static RSA key transport,
   * deprecated protocol versions, a collision-broken signature hash.
   *
   * These matter even when hybrid IS deployed, and they are the one way a
   * reassuring headline can still be wrong: hybrid ML-KEM lives only in the TLS
   * 1.3 key_share, so an endpoint that also accepts TLS 1.0 or a static-RSA
   * suite offers a path with NO post-quantum protection at all. An attacker who
   * can force that path gets the classical-only session, and the hybrid group
   * protects nothing. Naming those factors in the verdict's reason is what
   * stops "Hybrid-protected" from reading as "finished".
   */
  residualCriticalFactors?: string[]
}): { vulnerability: EdgeQuantumVulnerability; reason: string } {
  const residual = (input.residualCriticalFactors ?? []).filter(Boolean)
  const downgradeCaveat = residual.length
    ? ` However, ${residual.join(' and ')} ${residual.length === 1 ? 'remains' : 'remain'} rated Critical: a session forced onto that path carries no post-quantum protection at all, so the hybrid group does not cover every connection this endpoint will accept.`
    : ''

  if (!input.hasTransportEvidence) {
    return {
      vulnerability: 'Unknown',
      reason: 'No TLS handshake completed for this target, so no quantum exposure verdict is claimed.',
    }
  }
  if (input.hybridObserved && input.pqSignatureObserved) {
    return {
      vulnerability: 'Quantum-safe',
      reason:
        'Hybrid ML-KEM key agreement and a post-quantum certificate signature were both observed — confidentiality and authentication survive a CRQC.' +
        downgradeCaveat,
    }
  }
  if (input.hybridObserved) {
    return {
      vulnerability: 'Hybrid-protected',
      reason:
        'Hybrid ML-KEM key agreement is in use, so traffic recorded today cannot be decrypted by a future CRQC. The certificate chain is still signed with classical algorithms, so authentication remains a migration target.' +
        downgradeCaveat,
    }
  }
  if (input.quantumRisk === 'Critical') {
    return {
      vulnerability: 'Vulnerable',
      reason: input.supportsTls13
        ? 'No hybrid post-quantum group is accepted; the session secret rests on classical key agreement and is recoverable by a CRQC from traffic recorded today.'
        : 'The endpoint does not negotiate TLS 1.3, so no post-quantum key agreement is possible, and the classical key exchange in use is fully recoverable by a CRQC.',
    }
  }
  if (input.quantumRisk === 'High') {
    return {
      vulnerability: 'High Risk',
      reason:
        'No post-quantum key agreement was accepted, and the certificate public key is classical — authentication is forgeable once a CRQC exists.',
    }
  }
  return {
    vulnerability: 'Classical only',
    reason:
      'Every primitive observed at the edge is classical. Nothing is rated high-impact yet, but no post-quantum protection is deployed.',
  }
}


/* ──────────────────────────────────────────────────── edge attribution ────── */

/**
 * The single-line answer for the "Edge Infrastructure" control.
 *
 * Attribution is only ever reported from headers the origin actually sent. A
 * host behind no CDN is a real answer ("Origin-served") and must not render the
 * same as a host whose headers were never read.
 */
export function describeEdgeInfrastructure(edge: EdgeIntelligence): EdgeControl {
  const fingerprint = edge.http.fingerprint
  const parts = [
    fingerprint.cdn ? `CDN ${fingerprint.cdn}` : null,
    fingerprint.waf ? `WAF ${fingerprint.waf}` : null,
    fingerprint.cloudProvider ? `Cloud ${fingerprint.cloudProvider}` : null,
    fingerprint.reverseProxy ? `Proxy ${fingerprint.reverseProxy}` : null,
  ].filter(Boolean) as string[]

  const evidence: Array<{ label: string; value: string }> = []
  if (fingerprint.server) evidence.push({ label: 'Server', value: fingerprint.server })
  if (fingerprint.poweredBy) evidence.push({ label: 'X-Powered-By', value: fingerprint.poweredBy })
  if (fingerprint.cdn) evidence.push({ label: 'CDN', value: fingerprint.cdn })
  if (fingerprint.waf) evidence.push({ label: 'WAF', value: fingerprint.waf })
  if (fingerprint.cloudProvider) evidence.push({ label: 'Cloud', value: fingerprint.cloudProvider })
  if (fingerprint.reverseProxy) evidence.push({ label: 'Reverse proxy', value: fingerprint.reverseProxy })
  if (fingerprint.signals.length) {
    evidence.push({ label: 'Attribution signals', value: fingerprint.signals.join(', ') })
  }

  if (!edge.http.reachable) {
    return {
      value: 'Not observed',
      state: 'unknown',
      detail:
        edge.http.error
          ? `The origin did not answer over HTTPS (${edge.http.error}), so no response headers were available to attribute infrastructure from.`
          : 'The origin did not answer over HTTPS, so no response headers were available to attribute infrastructure from.',
      evidence,
    }
  }

  if (!parts.length) {
    return {
      value: fingerprint.server ? `Origin-served (${fingerprint.server})` : 'Origin-served',
      state: 'info',
      detail:
        'Response headers carry no CDN, WAF, cloud or reverse-proxy signature — the origin appears to serve traffic directly. This is a measured absence, not an unread control.',
      evidence,
    }
  }

  return {
    value: parts.join(' · '),
    state: 'info',
    detail: `Infrastructure attributed from response-header signatures: ${fingerprint.signals.join(', ') || 'vendor-specific headers'}.`,
    evidence,
  }
}
