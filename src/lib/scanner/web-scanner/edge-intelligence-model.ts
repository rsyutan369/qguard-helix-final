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
  /**
   * Hybrid groups that reached a conclusive verdict, and those that did not.
   *
   * A negative post-quantum claim is only publishable when a hybrid group was
   * actually refused. Without this split, an empty `hybridGroups` — which is
   * also what a throttled, budget-skipped or locally-unsupported probe
   * produces — was read as a refusal, and the page published
   * "Not offered · every hybrid ML-KEM group was offered in isolation and
   * refused" for endpoints measurably running X25519MLKEM768.
   *
   * Optional on the TYPE so snapshots persisted before this field existed keep
   * deserialising; `measuredKeyAgreement` treats `undefined` as "the old
   * pipeline made no split", never as "settled".
   */
  hybridGroupsSettled?: string[]
  hybridGroupsInconclusive?: string[]
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
  /** The RFC 8659 climb reached a conclusion; `caaPresent: false` is only a
      measured absence under this flag. */
  caaClimbComplete: boolean
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
  /**
   * Hybrid key agreement, and every path the endpoint accepts carries it.
   */
  | 'Hybrid-protected'
  /**
   * Hybrid key agreement measured, but the endpoint ALSO accepts a path the
   * hybrid group cannot reach — static RSA key transport, or a pre-1.3
   * protocol. The caveat used to live only in the reason string while the
   * verdict word stayed "Hybrid-protected", and a one-word verdict on a card
   * face is what gets read: a Google endpoint accepting four static-RSA suites
   * was published as hybrid-protected directly above its own
   * "Static RSA accepted: Yes · 4 suite(s)" row.
   */
  | 'Hybrid — partial coverage'
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
  /**
   * Null when the named-group probe never ran (no handshake completed). 0 is the
   * worst MEASURED readiness on this scale, so a target that refused every
   * connection must not be published at 0% — it was not assessed.
   */
  postQuantumReadiness: number | null
  readinessReasons: string[]
  /** Null when no primitive was observed. An empty factor set is not "Low". */
  quantumRisk: 'Low' | 'Medium' | 'High' | 'Critical' | null
  quantumRiskScore: number | null
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


/* ────────────────────────────────────────────── measured key agreement ────── */

/**
 * The measured post-quantum key-agreement verdict for an endpoint.
 *
 * WHY EVERY CONSUMER MUST COME THROUGH HERE
 * -----------------------------------------
 * `tls.getEphemeralKeyInfo()` returns an EMPTY object for a TLS 1.3 handshake,
 * so `TlsAnalysisResult.keyExchange` degrades to the literal string
 * `"ECDHE (TLS 1.3 key_share)"` on every modern endpoint regardless of the group
 * that was actually negotiated, and `negotiatedCurve` is null. Any consumer that
 * substring-tests that label concludes "classical ECDHE" for an endpoint running
 * X25519MLKEM768 — which is how a live hybrid host came to be scored, graded and
 * coloured as classical-only across the whole assessment.
 *
 * The named-group prober is the ONLY component that knows the answer: it offers
 * each group in isolation under a TLS 1.3 floor and records what the endpoint
 * accepted. This module is the single place that reading is interpreted, so the
 * detection rules, the published scoring model, the cipher-suite analyzer and
 * the dashboard cannot reach four different conclusions from one measurement.
 */
export interface MeasuredKeyAgreement {
  /** True when named-group probing ran at all. False ⇒ everything below is unknown, not negative. */
  probed: boolean
  /**
   * True when at least one HYBRID group reached a conclusive verdict.
   *
   * `probed` covers the group probe as a whole, and the classical groups
   * usually settle even when the hybrid ones do not — they are cheaper and are
   * attempted first. So `probed && !hybrid` does NOT license "hybrid was
   * refused", and every consumer that phrased it that way ("every hybrid ML-KEM
   * group was offered in isolation and refused") was making a claim from the
   * absence of an answer.
   */
  hybridSettled: boolean
  /** Classical hedge + ML-KEM accepted together — the recommended migration posture. */
  hybrid: boolean
  /** Standalone ML-KEM accepted with no classical hedge. */
  pureKem: boolean
  /** `hybrid || pureKem` — session secrets on this channel are out of Shor's reach. */
  kemApplied: boolean
  /** The group the verdict rests on, e.g. `X25519MLKEM768`. Null when none was accepted. */
  group: string | null
  /** Operator-facing label for the key agreement, e.g. `X25519MLKEM768 (hybrid)`. */
  label: string | null
  /** Named classical half of a hybrid construction, e.g. `X25519 (Curve25519 ECDHE)`. */
  classicalComponent: string | null
  /** Named post-quantum half, e.g. `ML-KEM-768 (FIPS 203)`. */
  postQuantumComponent: string | null
  /** Handshakes spent reaching this verdict. Provenance, never an estimate. */
  handshakes: number
  confidence: number
}

/** The verdict for an endpoint no probe ever reached. Never a negative result. */
export const UNPROBED_KEY_AGREEMENT: MeasuredKeyAgreement = {
  probed: false,
  hybridSettled: false,
  hybrid: false,
  pureKem: false,
  kemApplied: false,
  group: null,
  label: null,
  classicalComponent: null,
  postQuantumComponent: null,
  handshakes: 0,
  confidence: 0,
}

/**
 * Resolve the measured key agreement from an edge bundle.
 *
 * Accepts `null`/`undefined` and returns {@link UNPROBED_KEY_AGREEMENT} so a
 * caller with no edge evidence gets "not measured" rather than "no PQC" — the
 * distinction the whole honesty contract rests on.
 */
export function measuredKeyAgreement(edge: EdgeIntelligence | null | undefined): MeasuredKeyAgreement {
  const pq = edge?.pqKeyAgreement
  if (!pq?.probed) return UNPROBED_KEY_AGREEMENT

  /* `state === 'pass'` is required for the hybrid verdict because a partial
     result means some groups were inconclusive: the prober saw an accept it
     could not reproduce. A pure-KEM accept needs no such gate — there is no
     classical hedge to be uncertain about, only the group itself. */
  const hybrid = pq.state === 'pass' && pq.hybridGroups.length > 0
  const pureKem = !hybrid && pq.pureKemGroups.length > 0
  const group = hybrid ? (pq.primaryGroup ?? pq.hybridGroups[0]) : pureKem ? pq.pureKemGroups[0] : null

  /* An acceptance settles the question by itself — it is unforgeable, a
     throttled connection cannot fake one. Otherwise a hybrid group has to have
     been conclusively refused. Snapshots written before the split carry no
     lists; they fall back to the old reading rather than being retro-actively
     turned into "unmeasured". */
  const hybridSettled = hybrid || pureKem || hybridProbeSettled(pq)

  return {
    probed: true,
    hybridSettled,
    hybrid,
    pureKem,
    kemApplied: hybrid || pureKem,
    group,
    label: group ? `${group}${hybrid ? ' (hybrid)' : ' (no classical hedge)'}` : null,
    classicalComponent: hybrid ? pq.classicalComponent : null,
    postQuantumComponent: hybrid || pureKem ? pq.postQuantumComponent : null,
    handshakes: pq.handshakes,
    confidence: pq.confidence,
  }
}

/**
 * Did the hybrid probe actually produce an ANSWER for this endpoint?
 *
 * The one predicate every negative post-quantum claim has to pass. Four
 * independent consumers phrased "no hybrid group was accepted" as a finding
 * about the endpoint — the Not-offered verdict, detection rules PQC-002 and
 * PQC-003, the orchestrator's key-exchange finding text and the /public-scan
 * control — and all four reached it from an empty accepted-list, which is also
 * what a throttled or budget-skipped probe produces. Stating the rule once is
 * what stops the fifth consumer from reintroducing it.
 *
 * An ACCEPTANCE settles the question by itself: a reset connection cannot forge
 * a successful handshake. Otherwise a hybrid group has to have been
 * conclusively refused.
 */
export function hybridProbeSettled(
  pq:
    | {
        hybridGroups?: string[] | null
        pureKemGroups?: string[] | null
        hybridGroupsSettled?: string[] | null
      }
    | null
    | undefined,
): boolean {
  if (!pq) return false
  if ((pq.hybridGroups?.length ?? 0) > 0 || (pq.pureKemGroups?.length ?? 0) > 0) return true
  // Snapshots written before the split carry no list: keep the old reading
  // rather than retro-actively turning every stored verdict into "unmeasured".
  if (pq.hybridGroupsSettled === undefined || pq.hybridGroupsSettled === null) return true
  return pq.hybridGroupsSettled.length > 0
}

/**
 * Shorthand for "are the session secrets on this channel out of Shor's reach?".
 *
 * Deliberately narrower than "has any PQC been observed anywhere": a repository
 * that imports liboqs has adopted PQC but has not protected this handshake.
 */
export function measuredKemApplied(edge: EdgeIntelligence | null | undefined): boolean {
  return measuredKeyAgreement(edge).kemApplied
}

/* ───────────────────────────────────────────────── transport-header tally ── */

/** One transport-security header reading, as either probe reports it. */
export interface HeaderTallySource {
  name?: string | null
  present?: boolean | null
  secure?: boolean | null
  status?: string | null
}

export interface HeaderTally {
  /** Null when nothing was measured — never 0, which reads as "all failed". */
  hardened: number | null
  applicable: number | null
  /** `4/9 hardened`, or the reason it could not be measured. */
  label: string
  /** Which probe the reading came from, so the panel can state its provenance. */
  source: 'edge' | 'api-probe' | 'none'
}

/**
 * ONE transport-header tally for the whole page.
 *
 * ── The defect this removes ─────────────────────────────────────────────────
 * Three readers each counted their own population for one scan:
 *
 *   published-scoring.ts   `apiSecurityResult.securityHeaders` minus HSTS, with
 *                          no notion of applicability      →  "4/9 hardened"
 *   Observed Attack Surface  the edge model's applicable set →  "3/8 hardened"
 *   Code & Dependencies      every probed header, HSTS included
 *
 * So the score decomposition and the surface row published different ratios for
 * the same headers, on the same card, at the same time.
 *
 * The edge model is the better measurement — it drops headers that are not
 * applicable or are superseded by a stronger one, and it scores HSTS on its own
 * control — so it wins wherever it exists. The API probe's list is the fallback
 * for records written before the edge engine ran, and it excludes HSTS too, so
 * the two sources at least count the same KIND of thing.
 */
export function headerTally(
  edgeHttp: { reachable?: boolean | null; hardenedCount?: number | null; applicableCount?: number | null; error?: string | null } | null | undefined,
  apiHeaders: readonly HeaderTallySource[] | null | undefined,
): HeaderTally {
  if (edgeHttp?.reachable && (edgeHttp.applicableCount ?? 0) > 0) {
    const hardened = edgeHttp.hardenedCount ?? 0
    const applicable = edgeHttp.applicableCount ?? 0
    return { hardened, applicable, label: `${hardened}/${applicable} hardened`, source: 'edge' }
  }

  // HSTS is scored on its own control, so it never enters this denominator.
  const nonHsts = (apiHeaders ?? []).filter(
    (header) => String(header.name ?? '').toLowerCase() !== 'strict-transport-security',
  )
  if (nonHsts.length > 0) {
    const hardened = nonHsts.filter((header) => header.secure === true).length
    return {
      hardened,
      applicable: nonHsts.length,
      label: `${hardened}/${nonHsts.length} hardened`,
      source: 'api-probe',
    }
  }

  return {
    hardened: null,
    applicable: null,
    label:
      edgeHttp && edgeHttp.reachable === false
        ? `not measured — the origin did not answer over HTTPS (${edgeHttp.error ?? 'no response'})`
        : 'not measured — no HTTPS response headers were collected',
    source: 'none',
  }
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
  /** Null when nothing was observed — handled by the `hasTransportEvidence` gate. */
  quantumRisk: 'Low' | 'Medium' | 'High' | 'Critical' | null
  hybridProbed: boolean
  /**
   * True when at least one hybrid ML-KEM group reached a conclusive verdict.
   *
   * Every negative branch below asserts "no hybrid post-quantum group is
   * accepted". That is a measurement, and it is only available when a hybrid
   * group was actually settled. When the probe was throttled, budget-skipped or
   * locally untestable the honest verdict is Unknown — the certificate and
   * protocol risk factors are still reported on their own rows, so nothing is
   * hidden by withholding the endpoint-wide word.
   *
   * Optional so callers written before the split keep compiling; `undefined`
   * means "this pipeline made no split" and preserves the previous behaviour
   * rather than silently turning every historical verdict into Unknown.
   */
  hybridMeasured?: boolean
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
      reason: 'Named key-agreement groups were not probed for this target, so no endpoint-wide quantum exposure verdict is claimed from group probing.',
    }
  }
  if (input.hybridObserved && input.pqSignatureObserved) {
    return {
      /* THE VERDICT WORD CARRIES THE CAVEAT, NOT JUST THE REASON.
         `downgradeCaveat` is appended below either way, but a reader who sees
         only the verdict must not be told the endpoint is finished when a
         Critical residual factor means a session can avoid the hybrid group
         entirely. */
      vulnerability: residual.length ? 'Hybrid — partial coverage' : 'Quantum-safe',
      reason:
        'Hybrid ML-KEM key agreement and a post-quantum certificate signature were both observed — confidentiality and authentication survive a CRQC.' +
        downgradeCaveat,
    }
  }
  if (input.hybridObserved) {
    return {
      vulnerability: residual.length ? 'Hybrid — partial coverage' : 'Hybrid-protected',
      reason:
        'Hybrid ML-KEM key agreement is in use, so traffic recorded today cannot be decrypted by a future CRQC. The certificate chain is still signed with classical algorithms, so authentication remains a migration target.' +
        downgradeCaveat,
    }
  }
  /* No hybrid group was observed — but "not observed" is only a finding about
     the endpoint once a hybrid group has actually been refused. */
  if (input.hybridMeasured === false) {
    return {
      vulnerability: 'Unknown',
      reason:
        'No hybrid ML-KEM group reached a conclusive verdict on this run, so it is not established whether this endpoint offers post-quantum key agreement. The certificate and protocol risk factors below are measured and stand on their own; the endpoint-wide quantum verdict is withheld until group probing settles.',
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
