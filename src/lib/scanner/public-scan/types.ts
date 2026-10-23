/**
 * QGuard Helix — Public Quantum Exposure Assessment™
 * Type contract for the unauthenticated, edge-only public scanner.
 *
 * SCOPE DISCIPLINE (enforced by construction):
 * Everything in this contract is derivable from *publicly observable* Internet
 * edge evidence — the TLS handshake, the served X.509 chain, public DNS records
 * and HTTP response headers. Nothing here may be sourced from source code,
 * internal PKI, key management, cloud workloads or governance systems: those
 * belong to the authenticated Enterprise platform and are reported as `unknown`.
 */

import type {
  CertificateInfo,
  CipherSuiteDetail,
  ThreatLevel,
  TlsAnalysisResult,
} from '../web-scanner/types'

// ─── Scan lifecycle ───────────────────────────────────────────────────────────

export type PublicScanStageKey =
  | 'dns'
  | 'tls'
  | 'certificate'
  | 'headers'
  | 'quantum'
  | 'report'

/**
 * `failed` and `unavailable` are NOT the same claim, and the distinction is the
 * whole reason this union has five members:
 *
 *   complete     The module ran and produced a verdict.
 *   failed       The module ran and could not reach a conclusion — a scanner
 *                fault, or an endpoint that answered in a way it could not parse.
 *   unavailable  The module could not run at all, because a prerequisite was
 *                absent (the port never accepted a TCP connection). There is
 *                nothing to report about the target, and the rail must not paint
 *                a red cross that reads as "this endpoint failed the control".
 *   skipped      Deliberately not run — not applicable to this target.
 *
 * An assessment of an endpoint that is simply down used to render as four red
 * FAILED rows, which is an accusation the evidence does not support.
 */
export type PublicScanStageState =
  | 'waiting'
  | 'running'
  | 'complete'
  | 'failed'
  | 'unavailable'
  | 'skipped'

export interface PublicScanStage {
  key: PublicScanStageKey
  label: string
  description: string
  state: PublicScanStageState
  detail?: string
  startedAt?: string
  completedAt?: string
}

export const PUBLIC_SCAN_STAGES: ReadonlyArray<Pick<PublicScanStage, 'key' | 'label' | 'description'>> = [
  { key: 'dns', label: 'DNS Resolution', description: 'Resolving public records and CAA policy' },
  { key: 'tls', label: 'TLS Handshake', description: 'Negotiating protocols and cipher suites' },
  { key: 'certificate', label: 'Certificate Collection', description: 'Reading the served X.509 chain' },
  { key: 'headers', label: 'Security Header Analysis', description: 'Inspecting HTTP transport controls' },
  { key: 'quantum', label: 'Quantum Assessment', description: 'Scoring post-quantum exposure' },
  { key: 'report', label: 'Executive Report', description: 'Composing the executive assessment' },
] as const

// ─── Handshake visualization ──────────────────────────────────────────────────

export interface HandshakeStep {
  key: string
  label: string
  value: string
  observed: boolean
  /** Secondary evidence line — what the value was read from. */
  detail: string
  /** Measured wall-clock milliseconds for this phase, when the probe timed it. */
  timingMs: number | null
}

/** Wall-clock timings measured on the scanner's own TLS connection. */
export interface HandshakeTiming {
  tcpConnectMs: number | null
  tlsHandshakeMs: number | null
  totalMs: number | null
  httpResponseMs: number | null
}

// ─── Executive summary ────────────────────────────────────────────────────────

/**
 * `N/A` is emitted when too little of the edge was observable to grade
 * honestly. The eleven graded values match the published Score-to-Grade
 * Mapping exactly (grading-model.ts) — this is not an independent scale.
 */
export type SecurityGrade = 'A+' | 'A' | 'A-' | 'B+' | 'B' | 'B-' | 'C+' | 'C' | 'C-' | 'D' | 'F' | 'N/A'
export type RiskBand = 'Very Low' | 'Low' | 'Moderate' | 'Elevated' | 'High' | 'Critical' | 'Not assessable'
export type ComplexityBand = 'Low' | 'Medium' | 'High' | 'Very High' | 'Unknown'

export interface ExecutiveSummary {
  grade: SecurityGrade
  /** Rating from the published grade table (Elite/Excellent/Good/Fair/Weak/Critical). */
  gradeLabel: string
  gradeDetail: string
  /** Hex color from the published grade table's Color column; ACCENT.slate when ungradeable. */
  gradeColor: string
  /**
   * 0-100 weighted mean of the ten non-PQ categories only, renormalized among
   * themselves. An informative sub-metric — it does NOT drive the grade.
   *
   * **Null when the assessment is not gradeable.** On a higher-is-better scale 0
   * is the worst possible measured result, so publishing 0 for an endpoint that
   * never answered stated that its encryption had been examined and found
   * critical. Null is rendered as "—" and cannot be mistaken for a measurement.
   */
  classicalScore: number | null
  /** 0-100 post-quantum readiness observable at the edge; null when unmeasured. */
  postQuantumReadiness: number | null
  /**
   * WHICH key-agreement answer the readiness rests on. Every label that used to
   * be inferred from the percentage ("≥ 60 means hybrid") reads this instead: a
   * hybrid endpoint without TLS 1.3 in its enumerated list scores 55-58 and was
   * captioned "no hybrid key agreement offered" beside its own accepted group.
   */
  postQuantumKeyAgreement: 'hybrid' | 'pure-kem' | 'classical' | 'not-measured'
  /** A post-quantum signature algorithm appears in the served chain. */
  postQuantumSignatureObserved: boolean
  /** One sentence stating the measured key-agreement case, for compact slots. */
  postQuantumDetail: string
  /**
   * 0-100 weighted mean across all 12 published categories (grading-model.ts).
   * This — not classicalScore — is what scoreToGrade() maps to a letter grade.
   * Null when coverage is below MIN_GRADEABLE_COVERAGE, for the same reason.
   */
  encryptionScore: number | null
  encryptionBand: string
  businessRisk: RiskBand
  businessRiskDetail: string
  migrationComplexity: ComplexityBand
  migrationComplexityDetail: string
  confidence: number
  confidenceDetail: string
  confidenceFactors: string[]
  /**
   * Share (0-100) of the declared scoring weight that was actually observable.
   * Below MIN_GRADEABLE_COVERAGE the grade is withheld as `N/A` — a target that
   * refused the handshake has not earned an F, it simply was not measured.
   */
  evidenceCoverage: number
  gradeable: boolean
  scope: string
}

export interface ScoreComponent {
  key: string
  label: string
  /** 0-100 score for this dimension. Meaningless when `applicable` is false. */
  score: number
  /** Declared contribution to the classical score. All weights sum to 100. */
  weight: number
  /**
   * False when the dimension could not be observed at all (e.g. the DNS
   * resolver was unreachable). Inapplicable dimensions are excluded from the
   * score and their weight is redistributed — an unobservable control is never
   * scored as a failure.
   */
  applicable: boolean
  observed: string
  detail: string
}

// ─── Findings ─────────────────────────────────────────────────────────────────

/**
 * Seven-state status model (Public_Scan_Intelligence_Engines).
 * Re-exported from the engine contract so findings, controls and engine
 * modules all speak one vocabulary — the four negative states are NOT
 * interchangeable and conflating them is how a scanner ends up lying.
 */
export type { ControlStatus } from './engines/contract'
export type FindingStatus = import('./engines/contract').ControlStatus

/**
 * The single source of truth for every assessed control.
 *
 * Executive Summary, Encryption Score, Public Attack Surface, Public Findings
 * and Executive Recommendations are all *projections* of this one array. That
 * is deliberate: when each panel derived its own status independently, the same
 * control could read Pass in one card and Fail in another. Deriving all of them
 * from one evaluation makes cross-panel agreement structural rather than
 * something that has to be re-checked by hand after every change.
 */
export interface ControlState {
  key: string
  /** Name used in the findings table. */
  control: string
  /** Short name used in the compact attack-surface list. */
  shortLabel: string
  status: FindingStatus
  severity: ThreatLevel
  /** Compact value for the attack-surface row, e.g. "Pass", "3 certs". */
  value: string
  /** Full finding text for the findings table. */
  finding: string
  evidence: string
  businessImpact: string
  quantumImpact: string
  nextStep: string
  /** 0-100 for this control; null when it could not be observed. */
  score: number | null
  /** Scoring weight. 0 when the control is reported but not scored. */
  weight: number
  /** Human-readable statement of what was measured, shown in the decomposition. */
  observed: string
  detail: string
  /** Whether this control appears in the compact attack-surface list. */
  inAttackSurface: boolean
  /** Whether this control appears in the findings table. */
  inFindings: boolean
  /**
   * True for rows that report *what exists* rather than pass/fail (address
   * count, chain size, covered names). These render as neutral info. Declared
   * explicitly rather than inferred from `score === null`, because an
   * unscored control can still be a genuine pass/fail — post-quantum key
   * agreement is scored by the PQ model, not the classical weighted mean.
   */
  isInventory: boolean
}

export interface PublicFinding {
  id: string
  control: string
  finding: string
  status: FindingStatus
  severity: ThreatLevel
  businessImpact: string
  quantumImpact: string
  nextStep: string
  /** Raw observable this row was derived from (kept for the evidence drawer). */
  evidence: string
}

// ─── Cryptographic intelligence ───────────────────────────────────────────────

export interface CryptoIntelligence {
  /**
   * Projection of the Cryptographic Intelligence Engine's algorithm catalogue —
   * the SAME array the `cryptographic-algorithms` score category counts. This
   * panel used to build its own, shorter list, so the Encryption Score could
   * report "7 algorithms observed" beside a panel listing four.
   */
  observedAlgorithms: Array<{
    name: string
    role: string
    quantumVulnerable: boolean
    /** Engine classification: Quantum Safe / Hybrid / Classical / Legacy / Deprecated. */
    classification: string
    /** Where the value was read from, e.g. "named-group probe". */
    evidenceSource: string
  }>
  keyExchange: string
  /**
   * `Not measured` and `Not observed` are different answers.
   *
   * `Not observed` means the handshake WAS read and carried no ephemeral key
   * agreement — a measured absence, and a real failure. `Not measured` means no
   * handshake was read at all, so nothing can be said either way. Collapsing the
   * two published the strongest possible negative for an endpoint that simply
   * never answered, while the Findings table said "Unknown" for the same fact.
   */
  forwardSecrecy: 'Enabled' | 'Partial' | 'Not observed' | 'Not measured'
  /**
   * `Unknown` is a first-class verdict, not a fallback. The panel used to report
   * `Vulnerable` — with the reason "No hybrid or post-quantum key agreement
   * offered" — for endpoints where no handshake ever happened. Nothing was
   * offered to us because we were never able to ask.
   */
  /**
   * `PQ-protected` is standalone ML-KEM key agreement: session secrets are out
   * of Shor's reach, but there is no classical hedge, so it is not "hybrid".
   * It used to fall through to `Vulnerable`, the strongest negative available,
   * while the score decomposition credited the same group as post-quantum.
   */
  quantumVulnerability: 'Vulnerable' | 'Hybrid-protected' | 'PQ-protected' | 'Quantum-safe' | 'Unknown'
  quantumVulnerabilityReason: string
  migrationTargets: Array<{ name: string; standard: string; replaces: string }>
  confidence: number
}

// ─── Public attack surface ────────────────────────────────────────────────────

export type SurfaceStatus = 'pass' | 'partial' | 'fail' | 'info' | 'unknown'

export interface AttackSurfaceItem {
  key: string
  label: string
  value: string
  status: SurfaceStatus
  detail: string
}

// ─── Quantum exposure timeline ────────────────────────────────────────────────

export type TimelinePhaseState = 'now' | 'active' | 'future' | 'target'

export interface TimelinePhase {
  key: string
  title: string
  description: string
  state: TimelinePhaseState
  horizon: string
}

// ─── Recommendations ──────────────────────────────────────────────────────────

export type RecommendationPriority = 'Critical' | 'High' | 'Medium' | 'Low'

export interface Recommendation {
  id: string
  title: string
  priority: RecommendationPriority
  businessImpact: string
  effort: string
  /**
   * Modelled point gain on the composite encryption score if this action is
   * taken, computed by re-running the published scoring model with the relevant
   * dimension set to its passing value. `null` when the action improves
   * something this scan cannot score (e.g. internal inventory).
   */
  scoreGain: number | null
  /** Which score the gain applies to, so the number is never free-floating. */
  scoreGainTarget: 'encryption' | null
  /** Plain-English statement of how scoreGain was derived. */
  scoreGainBasis: string
  rationale: string
  /**
   * Where and how to make this change on the platform the scan actually
   * detected — the concrete directive or console path, with the detection
   * basis attributed. `null` when no platform was identified, or when nothing
   * accurate can be said for that platform/topic pair: a wrong config snippet
   * costs the reader a failed change window, so silence is the safer answer.
   */
  remediation?: string | null
}

// ─── Governance (always unknown from a public scan) ───────────────────────────

export interface GovernanceItem {
  key: string
  label: string
  status: 'Unknown'
  reason: string
}

// ─── Enterprise footprint estimate ────────────────────────────────────────────

/**
 * Counted, not estimated. Every tile in the Enterprise Opportunity panel is a
 * direct count of something the scan observed, with the observation named. No
 * multipliers, no invented headcounts — a public scan cannot see application
 * counts or crypto-asset inventories, and claiming otherwise would be the exact
 * fabrication this scanner exists to argue against.
 */
export interface FootprintMetric {
  key: string
  label: string
  value: number
  /** What was counted, e.g. "DNS names on the served certificate". */
  countedFrom: string
  /** True when this is a floor (more exist that the edge cannot see). */
  isLowerBound: boolean
}

export interface FootprintEstimate {
  metrics: FootprintMetric[]
  exposureLevel: string
  recommendedAssessment: string
  /** Explicit statement that these are edge counts, not estimates of the estate. */
  basis: string
  /** What an authenticated assessment would add, named rather than numbered. */
  notCounted: string[]
}

// ─── Sophia narrative ─────────────────────────────────────────────────────────

export interface SophiaAssessment {
  headline: string
  narrative: string
  cannotValidate: string[]
  recommendation: string
}

// ─── Raw evidence (edge only) ─────────────────────────────────────────────────

export interface DnsEvidence {
  addresses: string[]
  addressCount: number
  caaRecords: string[]
  caaPresent: boolean
  /**
   * False when the authoritative resolver itself was unreachable. A CAA
   * *query failure* is not the same as "no CAA policy" — the report must say
   * Unknown rather than Fail, and the score must drop the dimension entirely.
   */
  caaQueryable: boolean
  /**
   * False when the RFC 8659 climb stopped before reaching the registrable
   * domain. Issuance policy is inherited up the tree, so a leaf NODATA answer
   * establishes nothing on its own — `caaPresent: false` is a measured absence
   * only under this flag. `www.cloudflare.com` publishes no CAA RRset of its
   * own; `cloudflare.com` publishes eleven.
   */
  caaClimbComplete: boolean
  /** False when only the OS stub resolver answered (no record-type queries). */
  resolverAvailable: boolean
  nameservers: string[]
  mxHosts: string[]
  resolvedVia: string
  error: string | null
}

/**
 * Named key-agreement groups the endpoint actually accepts, established by
 * offering one group at a time. This is the only way to prove hybrid
 * post-quantum support from the outside — Node does not expose the negotiated
 * TLS 1.3 group.
 */
export interface KeyAgreementEvidence {
  probed: boolean
  /**
   * At least one HYBRID group reached a conclusive verdict.
   *
   * `probed` covers the group probe as a whole, and the classical groups settle
   * first and cheapest — so `probed && !hybridGroups.length` does NOT license
   * "hybrid was refused". Post-quantum readiness carries 55 of its 100 points on
   * the hybrid signal, so scoring a throttled probe as a refusal publishes the
   * strongest possible negative from no evidence at all.
   */
  hybridSettled: boolean
  hybridGroups: string[]
  /**
   * Standalone ML-KEM groups accepted — post-quantum key agreement with NO
   * classical hedge. Reported separately from `hybridGroups` and never merged
   * into it: the grading model scores hybrid deployment, and a standalone KEM
   * is a different (and, today, less deployable) posture. The named-group probe
   * measures these, so the report states them rather than discarding them.
   */
  pureKemGroups: string[]
  classicalGroups: string[]
  /** Preferred group description for display, e.g. "X25519MLKEM768". */
  primaryGroup: string | null
  forwardSecrecy: boolean
  forwardSecrecyBasis: string
}

export interface HttpEvidence {
  reachable: boolean
  statusCode: number | null
  finalUrl: string | null
  /** True when the response came back from a different origin than requested. */
  redirected: boolean
  redirectedToHttps: boolean
  responseMs: number | null
  server: string | null
  poweredBy: string | null
  alpn: string | null
  headers: Array<{
    name: string
    value: string | null
    present: boolean
    secure: boolean
    required: boolean
    recommendation: string
    /**
     * False when the header is absent but its protection is delivered by
     * another header (X-Frame-Options superseded by CSP frame-ancestors).
     * Inapplicable headers are excluded from the hardened tally entirely —
     * counting them would fail a site for omitting a header browsers ignore.
     */
    applicable: boolean
    /** The superseding control, when `applicable` is false. */
    supersededBy: string | null
  }>
  error: string | null
}

export interface CertificateEvidence {
  subjectAltNames: string[]
  sanCount: number
  ocspStapled: boolean
  ocspUri: string | null
  /**
   * Whether the advertised OCSP responder actually answered a live request.
   * `not-advertised` (the certificate never promised revocation) and
   * `unreachable` (it promised and cannot deliver) are different failures and
   * are never flattened into one.
   */
  ocspResponderState: 'reachable' | 'unreachable' | 'not-advertised' | 'not-probed'
  ocspResponderDetail: string | null
  mustStaple: boolean
  signedCertificateTimestamps: boolean
  sctCount: number
  chainDepth: number
  daysRemaining: number
  validityDays: number
  isWildcard: boolean
  /**
   * Result of real chain verification against the system trust store
   * (`socket.authorized`). The probe connects with rejectUnauthorized:false so
   * it can OBSERVE broken chains, but Node still runs verification and reports
   * the verdict here — no claim about issuer trust is made without it.
   */
  chainTrusted: boolean
  trustError: string | null
}

export interface PublicScanEvidence {
  tls: TlsAnalysisResult | null
  certificate: CertificateInfo | null
  certificateExtras: CertificateEvidence | null
  cipherSuites: CipherSuiteDetail[]
  keyAgreement: KeyAgreementEvidence
  dns: DnsEvidence
  http: HttpEvidence
  timing: HandshakeTiming
  /** The port the assessment actually connected to. */
  port: number
  /** ALPN protocol negotiated on the scanner's own connection. */
  alpn: string | null
  /**
   * Full output of the Public Scan Intelligence Engine — every module's raw
   * data, structured evidence and confidence. The flattened fields above are
   * an adapter over this so the report contract stayed stable when the modular
   * engine replaced the single-file probe.
   */
  engines: import('./engines').ScanEvidenceBundle
}

// ─── Assessment scope disclosure ──────────────────────────────────────────────

export interface AssessmentScope {
  analyzed: string[]
  notAnalyzed: string[]
  statement: string
}

// ─── Complete report ──────────────────────────────────────────────────────────

export interface PublicScanReport {
  scanId: string
  target: {
    input: string
    host: string
    port: number
    displayUrl: string
  }
  startedAt: string
  completedAt: string
  durationMs: number
  cached: boolean
  degraded: boolean
  degradedReason: string | null
  /**
   * True when the assessed port did not accept a TCP connection, so no
   * cryptographic evidence exists at all.
   *
   * Distinct from `degraded`: a degraded report measured *some* of the edge and
   * withheld the rest. An unreachable target produced no measurement to withhold,
   * and every panel must say so rather than rendering the absence as a low score.
   */
  unreachable: boolean
  /** Measured transport reachability — the prerequisite for everything below. */
  reachability: {
    state: import('./engines/reachability-engine').ReachabilityState
    reachable: boolean
    /** Real TCP connect time in ms; null when no connection was established. */
    tcpConnectMs: number | null
    address: string | null
    /** Full sentence. Use where the outcome is explained — once. */
    detail: string
    /** Compact phrase ("port 443 did not answer") for repeated slots. */
    summary: string
  }

  executive: ExecutiveSummary
  scoreComponents: ScoreComponent[]
  handshake: HandshakeStep[]
  findings: PublicFinding[]
  intelligence: CryptoIntelligence
  attackSurface: AttackSurfaceItem[]
  timeline: TimelinePhase[]
  recommendations: Recommendation[]
  governance: GovernanceItem[]
  footprint: FootprintEstimate
  sophia: SophiaAssessment
  scope: AssessmentScope
  evidence: PublicScanEvidence
}

// ─── Streaming events ─────────────────────────────────────────────────────────

export type PublicScanEvent =
  | { type: 'scan-start'; scanId: string; target: string; timestamp: string }
  | { type: 'stage'; scanId: string; stage: PublicScanStage; timestamp: string }
  | { type: 'scan-complete'; scanId: string; report: PublicScanReport; timestamp: string }
  | { type: 'error'; scanId: string; code: string; message: string; timestamp: string }
