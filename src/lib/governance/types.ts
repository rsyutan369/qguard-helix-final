/**
 * Enterprise Governance, Compliance, Audit & Regulatory model — shared types.
 *
 * One vocabulary for four dashboards:
 *   /dashboard/compliance          Compliance Command Center
 *   /dashboard/quantum-governance  Quantum & Crypto Governance
 *   /dashboard/audit-vault         Audit & Evidence Vault
 *   /dashboard/regulatory-mapping  Regulatory Mapping
 *
 * The chain every page walks is the same object graph:
 *
 *   Framework → Requirement → Control → Asset → Finding → Evidence → Audit Event
 *
 * MEASUREMENT HONESTY
 * -------------------
 * Every score in this model is nullable and paired with `measured`. A control
 * with no supporting tenant evidence is `not-assessed` with a `null` score — it
 * is never silently graded 0 (which reads as "failing") or 100 (which reads as
 * "compliant"). Aggregate scores are computed over MEASURED controls only, and
 * publish their own denominator so the UI can state what the number covers.
 */

/* ------------------------------------------------------------------ */
/* Primitives                                                          */
/* ------------------------------------------------------------------ */

export type ControlStatus =
  /** Every in-scope subject satisfies the control. */
  | 'compliant'
  /** Some subjects satisfy it; others do not. */
  | 'partial'
  /** In-scope subjects fail the control. */
  | 'non-compliant'
  /** No evidence exists to judge it — NOT a failure. */
  | 'not-assessed'
  /** Explicitly scoped out by a tenant-recorded exception. */
  | 'not-applicable'

export type GovernanceSeverity = 'critical' | 'high' | 'medium' | 'low'

export type FreshnessState = 'fresh' | 'aging' | 'stale' | 'unknown'

export type RetentionState = 'active' | 'expiring' | 'expired' | 'unspecified'

export type IntegrityState =
  /** Digest recomputed and equal to the anchored digest — no drift. */
  | 'verified'
  /** Digest recomputed and DIFFERENT from the anchored digest. */
  | 'mismatch'
  /** Digest computed this read, but never anchored — nothing to compare against. */
  | 'unanchored'
  /** Anchoring store unavailable (schema not applied). */
  | 'unavailable'

export type ControlDomain =
  | 'inventory'
  | 'algorithm'
  | 'transport'
  | 'certificate'
  | 'key'
  | 'data'
  | 'quantum'
  | 'monitoring'
  | 'remediation'
  | 'audit'
  | 'governance'

export const CONTROL_DOMAIN_LABEL: Record<ControlDomain, string> = {
  inventory: 'Cryptographic Inventory',
  algorithm: 'Algorithm Policy',
  transport: 'Transport Security',
  certificate: 'Certificate Lifecycle',
  key: 'Key Management',
  data: 'Data Protection',
  quantum: 'Post-Quantum Readiness',
  monitoring: 'Continuous Monitoring',
  remediation: 'Finding Remediation',
  audit: 'Audit & Evidence',
  governance: 'Policy Governance',
}

export const CONTROL_STATUS_LABEL: Record<ControlStatus, string> = {
  compliant: 'Compliant',
  partial: 'Partially Compliant',
  'non-compliant': 'Non-Compliant',
  'not-assessed': 'Not Assessed',
  'not-applicable': 'Not Applicable',
}

/* ------------------------------------------------------------------ */
/* Catalog: framework → requirement → control                          */
/* ------------------------------------------------------------------ */

/**
 * A regulatory framework or standard.
 *
 * The catalog holds only the STRUCTURE (which requirements exist and what they
 * ask for). Nothing about a tenant's compliance is stored here — status always
 * comes from evaluating the tenant's own evidence.
 */
export interface FrameworkDefinition {
  id: string
  name: string
  shortName: string
  authority: string
  version: string
  /** What this framework governs, in one sentence, for the drill-down header. */
  scope: string
  /** Matches free-text framework labels found on stored compliance evidence. */
  aliases: RegExp
  /** External reference for the requirement text. */
  reference: string
  category: 'standard' | 'regulation' | 'certification' | 'directive'
}

export interface RequirementDefinition {
  id: string
  frameworkId: string
  /** The clause / article / control number as the framework itself numbers it. */
  code: string
  title: string
  /** Paraphrased obligation — never reproduced verbatim from the source text. */
  summary: string
  /** Controls that, together, satisfy this requirement. */
  controlIds: string[]
}

export interface ControlDefinition {
  id: string
  code: string
  title: string
  /** What the control is trying to guarantee. */
  objective: string
  domain: ControlDomain
  /** Which evaluator computes this control's status from tenant evidence. */
  evaluator: string
  /**
   * What has to be true, in the platform's own terms, for the control to pass.
   * Rendered in the drill-down so a status is always explainable.
   */
  criterion: string
  /** Where a user goes to act on a failure. */
  remediationRoute: string
  /** Which evidence sources can satisfy this control. */
  evidenceSources: string[]
  /** Relative weight in the aggregate compliance score. */
  weight: number
}

/* ------------------------------------------------------------------ */
/* Evaluated records                                                   */
/* ------------------------------------------------------------------ */

/** A concrete subject (asset, certificate, key, component) a control judged. */
export interface ControlSubject {
  id: string
  label: string
  type: string
  /** True when this subject satisfies the control. */
  pass: boolean
  /** Why it passed or failed, in one line. */
  reason: string
  assetId: string | null
  severity: GovernanceSeverity | null
  /** Deep link to the record this subject came from. */
  href: string | null
  source: { table: string; recordId: string }
  observedAt: string | null
}

export interface ControlRecord {
  id: string
  code: string
  title: string
  objective: string
  criterion: string
  domain: ControlDomain
  status: ControlStatus
  /** 0–100 over the in-scope population, or null when not measured. */
  score: number | null
  /** False when no tenant evidence exists for this control. */
  measured: boolean
  /** Plain-language statement of what produced the status. */
  basis: string
  /** In-scope subjects. */
  population: number
  satisfied: number
  failing: number
  severity: GovernanceSeverity | null
  owner: string | null
  ownerSource: 'assigned' | 'inherited' | 'unassigned'
  /** Every framework requirement this control helps satisfy. */
  requirementIds: string[]
  frameworkIds: string[]
  /** Assets implicated in a failure. */
  affectedAssetIds: string[]
  affectedAssetCount: number
  /** Linked finding + evidence ids for the traceability chain. */
  findingIds: string[]
  evidenceIds: string[]
  /** Bounded sample of failing subjects for the drawer; full set is paged. */
  failingSubjects: ControlSubject[]
  passingSample: ControlSubject[]
  lastValidatedAt: string | null
  evidenceFreshness: FreshnessState
  evidenceAgeDays: number | null
  remediationRoute: string
  evidenceSources: string[]
  weight: number
  /** Tenant-recorded exception, when one exists. */
  exception: ControlException | null
}

export interface ControlException {
  id: string
  reason: string
  approvedBy: string
  approvedAt: string | null
  expiresAt: string | null
  expired: boolean
}

export interface RequirementRecord {
  id: string
  frameworkId: string
  code: string
  title: string
  summary: string
  controlIds: string[]
  status: ControlStatus
  score: number | null
  measured: boolean
  controlsTotal: number
  controlsMeasured: number
  controlsCompliant: number
  controlsFailing: number
  evidenceCount: number
  lastValidatedAt: string | null
  evidenceFreshness: FreshnessState
  /** Controls with no evidence — the "missing evidence" list. */
  unmeasuredControlIds: string[]
}

export interface FrameworkRecord {
  id: string
  name: string
  shortName: string
  authority: string
  version: string
  scope: string
  reference: string
  category: FrameworkDefinition['category']
  status: ControlStatus
  /** Compliance percentage over MEASURED controls in this framework. */
  score: number | null
  measured: boolean
  requirementsTotal: number
  requirementsMeasured: number
  requirementsCompliant: number
  requirementsPartial: number
  requirementsFailing: number
  requirementsUnassessed: number
  controlsTotal: number
  controlsMeasured: number
  /** Coverage = measured requirements / total requirements. */
  coverage: number
  evidenceCount: number
  /** Evidence rows the tenant stored that name this framework explicitly. */
  attestedEvidenceCount: number
  openFindings: number
  criticalFindings: number
  lastValidatedAt: string | null
  evidenceFreshness: FreshnessState
}

/* ------------------------------------------------------------------ */
/* Unified evidence model (§9)                                         */
/* ------------------------------------------------------------------ */

export type EvidenceKind =
  | 'attestation'
  | 'scan'
  | 'finding'
  | 'inventory'
  | 'certificate'
  | 'key'
  | 'runtime'
  | 'migration'
  | 'vault'
  | 'audit'
  | 'policy'

export interface EvidenceIntegrity {
  algorithm: 'SHA3-256'
  /** Digest over the canonical (sorted-key) content of the source record. */
  digest: string
  computedAt: string
  state: IntegrityState
  /** When the digest was first anchored, if it was. */
  anchoredAt: string | null
  /** Honest statement of what the integrity state does and does not prove. */
  assurance: string
}

export interface EvidenceRetention {
  /** Retention window applied to this evidence class, in days. */
  periodDays: number | null
  expiresAt: string | null
  state: RetentionState
  /** Which policy set the window. */
  policyId: string | null
}

export interface EvidenceCustodyEntry {
  at: string | null
  actor: string
  action: string
  source: string
}

/**
 * One evidence record, traceable to tenant, asset, scan, finding, control,
 * framework, requirement, policy, actor, timestamp, source and integrity —
 * the complete §9 chain.
 */
export interface EvidenceRecord {
  id: string
  kind: EvidenceKind
  title: string
  description: string
  /** Verbatim status recorded on the source row, when it has one. */
  statusLabel: string | null
  /** Does this record support or contradict its control(s)? */
  outcome: 'supporting' | 'contradicting' | 'informational'
  severity: GovernanceSeverity | null

  /* provenance */
  source: { table: string; recordId: string; collector: string }
  actor: string
  actorType: 'user' | 'agent' | 'connector' | 'platform' | 'unknown'
  occurredAt: string | null
  recordedAt: string | null

  /* relationships */
  assetId: string | null
  assetName: string | null
  scanId: string | null
  findingId: string | null
  controlIds: string[]
  frameworkIds: string[]
  requirementIds: string[]
  policyIds: string[]

  /* lifecycle */
  integrity: EvidenceIntegrity
  retention: EvidenceRetention
  freshness: FreshnessState
  ageDays: number | null
  custody: EvidenceCustodyEntry[]
  href: string | null
}

/* ------------------------------------------------------------------ */
/* Audit trail (§7)                                                    */
/* ------------------------------------------------------------------ */

export type AuditCategory =
  | 'authentication'
  | 'administration'
  | 'policy'
  | 'asset'
  | 'scan'
  | 'finding'
  | 'compliance'
  | 'evidence'
  | 'migration'
  | 'key'
  | 'certificate'
  | 'vault'
  | 'access'

export const AUDIT_CATEGORY_LABEL: Record<AuditCategory, string> = {
  authentication: 'Authentication',
  administration: 'Administrative Action',
  policy: 'Policy Change',
  asset: 'Asset Change',
  scan: 'Scan Activity',
  finding: 'Finding Change',
  compliance: 'Compliance Change',
  evidence: 'Evidence Change',
  migration: 'Migration Event',
  key: 'Key Lifecycle',
  certificate: 'Certificate Lifecycle',
  vault: 'Vault Operation',
  access: 'Access Event',
}

export interface AuditEvent {
  id: string
  at: string | null
  category: AuditCategory
  action: string
  actor: string
  actorType: EvidenceRecord['actorType']
  subject: string
  subjectType: string
  outcome: 'success' | 'failure' | 'denied' | 'informational'
  severity: GovernanceSeverity
  detail: string
  ipAddress: string | null
  source: { table: string; recordId: string }
  assetId: string | null
  evidenceId: string | null
  controlIds: string[]
  frameworkIds: string[]
  href: string | null
  /** True only for sources with no update path in the platform. */
  appendOnlySource: boolean
}

/* ------------------------------------------------------------------ */
/* Crypto policy engine (§6)                                           */
/* ------------------------------------------------------------------ */

export type PolicyCategory =
  | 'approved-algorithms'
  | 'forbidden-algorithms'
  | 'key-strength'
  | 'transport'
  | 'post-quantum'
  | 'certificate'
  | 'key-lifecycle'
  | 'data-protection'
  | 'crypto-agility'
  | 'quantum-risk'

export const POLICY_CATEGORY_LABEL: Record<PolicyCategory, string> = {
  'approved-algorithms': 'Approved Algorithms',
  'forbidden-algorithms': 'Forbidden Algorithms',
  'key-strength': 'Minimum Key Strength',
  transport: 'TLS / Transport',
  'post-quantum': 'Post-Quantum Requirements',
  certificate: 'Certificate Requirements',
  'key-lifecycle': 'Key Lifecycle',
  'data-protection': 'Encryption Requirements',
  'crypto-agility': 'Cryptographic Agility',
  'quantum-risk': 'Quantum Risk Thresholds',
}

export type PolicyEnforcement = 'enforced' | 'monitored' | 'disabled'

export interface PolicyParameterDefinition {
  key: string
  label: string
  type: 'number' | 'boolean' | 'string-list'
  value: number | boolean | string[]
  unit?: string
  hint: string
}

export interface PolicyRuleDefinition {
  id: string
  title: string
  category: PolicyCategory
  /** Paraphrased rationale + the standard that motivates it. */
  rationale: string
  standard: string
  defaultEnforcement: PolicyEnforcement
  defaultSeverity: GovernanceSeverity
  parameters: PolicyParameterDefinition[]
  /** Controls this rule feeds. */
  controlIds: string[]
  evaluator: string
  remediationRoute: string
}

export interface PolicyViolation {
  id: string
  policyId: string
  subject: string
  subjectType: string
  assetId: string | null
  assetName: string | null
  severity: GovernanceSeverity
  observed: string
  expected: string
  detail: string
  detectedAt: string | null
  source: { table: string; recordId: string }
  href: string | null
}

export interface PolicyRecord {
  id: string
  title: string
  category: PolicyCategory
  rationale: string
  standard: string
  enforcement: PolicyEnforcement
  severity: GovernanceSeverity
  parameters: PolicyParameterDefinition[]
  controlIds: string[]
  remediationRoute: string
  /** True when a tenant row overrides the platform default. */
  tenantConfigured: boolean
  updatedAt: string | null
  updatedBy: string | null
  /* evaluation */
  measured: boolean
  evaluated: number
  compliantSubjects: number
  violations: number
  criticalViolations: number
  adherence: number | null
  basis: string
  violationSample: PolicyViolation[]
  lastEvaluatedAt: string
}

/* ------------------------------------------------------------------ */
/* Gaps, scores, reconciliation                                        */
/* ------------------------------------------------------------------ */

export type GapKind =
  | 'missing-control'
  | 'failing-control'
  | 'weak-control'
  | 'missing-evidence'
  | 'stale-evidence'
  | 'expired-evidence'
  | 'unmapped-asset'
  | 'open-finding'
  | 'policy-violation'
  | 'pqc-gap'
  | 'expired-exception'

export const GAP_KIND_LABEL: Record<GapKind, string> = {
  'missing-control': 'Missing Control',
  'failing-control': 'Failing Control',
  'weak-control': 'Weak Control',
  'missing-evidence': 'Missing Evidence',
  'stale-evidence': 'Stale Evidence',
  'expired-evidence': 'Expired Evidence',
  'unmapped-asset': 'Unmapped Asset',
  'open-finding': 'Unresolved Finding',
  'policy-violation': 'Policy Violation',
  'pqc-gap': 'PQC Compliance Gap',
  'expired-exception': 'Expired Exception',
}

export interface GovernanceGap {
  id: string
  kind: GapKind
  title: string
  detail: string
  severity: GovernanceSeverity
  /** How many records sit behind this gap. */
  count: number
  domain: ControlDomain
  controlIds: string[]
  frameworkIds: string[]
  requirementIds: string[]
  assetIds: string[]
  route: string
  /** What closing it changes, in the platform's own measured terms. */
  impact: string
  detectedAt: string | null
}

/**
 * A headline number plus everything needed to defend it.
 * `measured: false` means "we cannot compute this" — never "it is zero".
 */
export interface GovernanceScore {
  id: string
  label: string
  value: number | null
  measured: boolean
  unit: 'percent' | 'count' | 'score'
  /** How the number was derived, in one sentence. */
  basis: string
  /** The population the number covers. */
  denominator: number
  numerator: number
  tone: 'good' | 'warning' | 'critical' | 'neutral'
  /** Where clicking the tile goes. */
  route: string | null
  hint: string
}

export interface ReconciliationRow {
  metric: string
  value: number | null
  /** The canonical producer of this figure. */
  source: string
  /** Other surfaces that publish the same figure. */
  alsoShownOn: string[]
  /** Any deliberate scope difference, stated explicitly. */
  scopeNote: string
  agrees: boolean
}

export interface ReconciliationReport {
  generatedAt: string
  rows: ReconciliationRow[]
  /** Non-empty when a figure could not be reconciled with its canonical source. */
  discrepancies: string[]
  note: string
}

/* ------------------------------------------------------------------ */
/* Asset compliance projection                                         */
/* ------------------------------------------------------------------ */

export interface AssetComplianceRecord {
  assetId: string
  name: string
  type: string
  environment: string
  owner: string
  criticality: string
  internetFacing: boolean
  posture: string
  postureLabel: string
  riskScore: number
  readinessScore: number
  /** Controls this asset is in scope for, and how many it satisfies. */
  controlsInScope: number
  controlsFailing: number
  failingControlIds: string[]
  openFindings: number
  criticalFindings: number
  policyViolations: number
  evidenceCount: number
  attestedFrameworks: string[]
  status: ControlStatus
  lastEvidenceAt: string | null
  evidenceFreshness: FreshnessState
  href: string
}

/* ------------------------------------------------------------------ */
/* Telemetry health                                                    */
/* ------------------------------------------------------------------ */

export type GovernancePipelineStatus =
  | 'live'
  | 'inventory-only'
  | 'awaiting-evidence'
  | 'no-sources'

export interface GovernanceTelemetry {
  pipelineStatus: GovernancePipelineStatus
  agentsOnline: number
  agentsTotal: number
  connectorsActive: number
  connectorsTotal: number
  runningScans: number
  lastScanAt: string | null
  lastRuntimeEventAt: string | null
  lastAuditEventAt: string | null
  lastEvidenceAt: string | null
  /** Row counts per contributing table — the provenance footer. */
  sourceCounts: Record<string, number>
  /** True when any source query hit its row cap. */
  truncated: boolean
  /** Tables that returned nothing (missing table or genuinely empty). */
  absentSources: string[]
  /** True when the evidence-anchor store is available. */
  anchoringAvailable: boolean
  /** True when tenant policy overrides can be persisted. */
  policyStoreAvailable: boolean
}

/* ------------------------------------------------------------------ */
/* Facets (§14 global filtering)                                       */
/* ------------------------------------------------------------------ */

export interface GovernanceFacets {
  frameworks: Array<{ id: string; label: string; count: number }>
  domains: Array<{ id: string; label: string; count: number }>
  statuses: Array<{ id: string; label: string; count: number }>
  environments: Array<{ id: string; label: string; count: number }>
  owners: Array<{ id: string; label: string; count: number }>
  criticalities: Array<{ id: string; label: string; count: number }>
  severities: Array<{ id: string; label: string; count: number }>
  auditCategories: Array<{ id: string; label: string; count: number }>
  evidenceKinds: Array<{ id: string; label: string; count: number }>
  policyCategories: Array<{ id: string; label: string; count: number }>
}

/* ------------------------------------------------------------------ */
/* Trend                                                               */
/* ------------------------------------------------------------------ */

export interface GovernanceTrendPoint {
  label: string
  date: string
  /** Evidence records recorded that day. */
  evidence: number
  /** Audit events recorded that day. */
  auditEvents: number
  /** Findings opened that day. */
  findingsOpened: number
  /** Findings resolved that day. */
  findingsResolved: number
  /** Policy violations detected that day. */
  violations: number
  /** True when the day is inside the observed evidence window. */
  observed: boolean
}

/* ------------------------------------------------------------------ */
/* The model                                                           */
/* ------------------------------------------------------------------ */

export interface GovernanceIntelligence {
  generatedAt: string
  /** Newest governance-relevant observation of any kind. */
  latestEvidenceAt: string | null
  hasData: boolean
  stale: boolean
  staleSinceHours: number | null

  scores: {
    compliance: GovernanceScore
    controlCoverage: GovernanceScore
    evidenceCoverage: GovernanceScore
    evidenceFreshness: GovernanceScore
    policyAdherence: GovernanceScore
    pqcGovernance: GovernanceScore
    auditIntegrity: GovernanceScore
    governance: GovernanceScore
    quantumReadiness: GovernanceScore
    quantumRisk: GovernanceScore
  }

  frameworks: FrameworkRecord[]
  requirements: RequirementRecord[]
  controls: ControlRecord[]
  policies: PolicyRecord[]
  evidence: EvidenceRecord[]
  auditEvents: AuditEvent[]
  gaps: GovernanceGap[]
  assets: AssetComplianceRecord[]

  trend: GovernanceTrendPoint[]
  facets: GovernanceFacets
  telemetry: GovernanceTelemetry
  reconciliation: ReconciliationReport

  /** Counts used by every page header, so no two pages can disagree. */
  totals: {
    frameworks: number
    requirements: number
    controls: number
    controlsMeasured: number
    controlsCompliant: number
    controlsPartial: number
    controlsFailing: number
    controlsUnassessed: number
    controlsNotApplicable: number
    criticalGaps: number
    gaps: number
    policies: number
    policiesEnforced: number
    policyViolations: number
    criticalPolicyViolations: number
    evidence: number
    evidenceStale: number
    evidenceExpired: number
    evidenceAnchored: number
    evidenceMismatched: number
    auditEvents: number
    auditFailures: number
    assets: number
    assetsCompliant: number
    assetsFailing: number
    assetsUnassessed: number
    openFindings: number
    criticalFindings: number
    /* canonical estate figures — mirrored from the QR snapshot */
    cryptoComponents: number
    vulnerableComponents: number
    pqcReadyComponents: number
    certificates: number
    keys: number
  }
}
