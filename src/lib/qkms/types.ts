/**
 * Canonical QKMS model — ONE key estate, seven projections.
 *
 * `/dashboard/qkms/overview`, `/inventory`, `/lifecycle`, `/governance`,
 * `/rotation`, `/readiness` and `/risk-analysis` all read this structure, so a
 * given key cannot carry a different identity, lifecycle state, rotation state,
 * posture or risk score depending on which page happens to be open.
 *
 * ── Identity rules (brief section 3) ────────────────────────────────────────
 *   keyId       `key:fp:<fingerprint>` when key material carries a fingerprint,
 *               else `key:qkms:<uuid>` / `key:gen:<uuid>` for rows this platform
 *               owns, else `key:d:<hash of asset+algorithm+purpose+backend>`.
 *               Never contains a row id of a source that can be re-scanned, so
 *               the id survives re-discovery.
 *   versionId   `<keyId>#v<n>` — a key version is addressable on its own.
 *   evidence    every statement carries { table, recordId, observedAt }, which
 *               is what makes a finding traceable back to the scan or telemetry
 *               row that produced it.
 *
 * ── Evidence rule (brief sections 2, 19) ────────────────────────────────────
 * Nothing here is synthesised. A field that could not be measured is `null` and
 * renders as "Not observed" — never as 0, and never as a healthy verdict.
 * `unknown` is a first-class value in every vocabulary for exactly this reason.
 */

/* ------------------------------------------------------------------ */
/* Shared vocabulary                                                   */
/* ------------------------------------------------------------------ */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/**
 * Post-quantum posture of a KEY.
 *
 * Deliberately not the transport `PqcPosture`: a symmetric key and a key
 * agreement face different quantum threats — Grover halves the former, Shor
 * breaks the latter. Sharing one vocabulary is what makes a platform publish
 * AES-256-GCM as a critical quantum vulnerability.
 */
/**
 * The basis of a key's posture (audit brief §3F: "Do not infer quantum safety
 * solely from an algorithm name or a declared configuration").
 *
 *   observed   a certificate, the CBOM or an agent scan saw the algorithm
 *   generated  this platform generated the key, so its algorithm is known
 *   declared   only a registry entry names the algorithm — unverified
 *   none       no source names an algorithm at all
 */
export type PostureEvidence = 'observed' | 'generated' | 'declared' | 'none'

export type KeyPqcPosture =
  /** ML-KEM / ML-DSA / SLH-DSA key material. */
  | 'post-quantum'
  /** Classical + PQC composite, e.g. X25519 + ML-KEM-768. */
  | 'hybrid'
  /** AES-256, ChaCha20, SHA3 — quantum-resistant at adequate size. */
  | 'quantum-resistant-symmetric'
  /** AES-128 and similar: weakened by Grover, not broken. */
  | 'weakened-symmetric'
  /** RSA / ECDSA / ECDH / Ed25519 / X25519 — Shor-breakable. */
  | 'quantum-vulnerable'
  /** Already broken classically: DES, 3DES, RC4, MD5, SHA-1, RSA-1024. */
  | 'deprecated'
  /** No algorithm could be read from any source. */
  | 'unknown'

/** What the estate must actually DO about a key. Separate from its posture. */
export type MigrationRequirement = 'none' | 'monitor' | 'recommended' | 'required' | 'unknown'

/** Cryptographic role of the key — decides which PQC family replaces it. */
export type KeyClass =
  | 'key-establishment'
  | 'signature'
  | 'symmetric-encryption'
  | 'hash-kdf'
  | 'certificate'
  | 'unknown'

/**
 * Lifecycle state (brief section 11).
 *
 * `unknown` exists because a key discovered by a scanner carries no lifecycle
 * metadata at all — calling that "Active" is a fabrication.
 */
export type LifecycleState =
  | 'discovered'
  | 'pending-activation'
  | 'active'
  | 'in-use'
  | 'rotation-due'
  | 'rotation-overdue'
  | 'rotated'
  | 'suspended'
  | 'expired'
  | 'revoked'
  | 'retired'
  | 'decommissioned'
  | 'unknown'

/** Render order for the lifecycle funnel. Terminal states sort last. */
export const LIFECYCLE_ORDER: LifecycleState[] = [
  'discovered',
  'pending-activation',
  'active',
  'in-use',
  'rotation-due',
  'rotation-overdue',
  'rotated',
  'suspended',
  'expired',
  'revoked',
  'retired',
  'decommissioned',
  'unknown',
]

export const LIFECYCLE_LABEL: Record<LifecycleState, string> = {
  discovered: 'Discovered',
  'pending-activation': 'Pending Activation',
  active: 'Active',
  'in-use': 'In Use',
  'rotation-due': 'Rotation Due',
  'rotation-overdue': 'Rotation Overdue',
  rotated: 'Rotated',
  suspended: 'Suspended',
  expired: 'Expired',
  revoked: 'Revoked',
  retired: 'Retired',
  decommissioned: 'Decommissioned',
  unknown: 'Unknown',
}

/**
 * Rotation state.
 *
 * `unknown` is returned when the key has no rotation policy, no last-rotated
 * timestamp AND no expiry — there is nothing to be healthy about. The previous
 * implementation returned `Healthy` there, which turned missing governance into
 * a clean bill of health.
 */
export type RotationState =
  | 'healthy'
  | 'due'
  | 'overdue'
  | 'in-progress'
  | 'failed'
  | 'blocked'
  | 'never-rotated'
  | 'not-applicable'
  | 'unknown'

export const ROTATION_LABEL: Record<RotationState, string> = {
  healthy: 'Healthy',
  due: 'Due',
  overdue: 'Overdue',
  'in-progress': 'In Progress',
  failed: 'Failed',
  blocked: 'Blocked',
  'never-rotated': 'Never Rotated',
  'not-applicable': 'Not Applicable',
  unknown: 'Unknown',
}

/** Custody class of the storage backend holding the key. */
export type CustodyClass =
  | 'hsm'
  | 'cloud-kms'
  | 'vault'
  | 'platform-vault'
  | 'software-keystore'
  | 'unmanaged'
  | 'unknown'

export const CUSTODY_LABEL: Record<CustodyClass, string> = {
  hsm: 'HSM',
  'cloud-kms': 'Cloud KMS',
  vault: 'Vault',
  'platform-vault': 'Platform Vault',
  'software-keystore': 'Software Keystore',
  unmanaged: 'Unmanaged',
  unknown: 'Unknown',
}

/** Where a statement came from. Rendered next to every finding. */
export type QkmsEvidenceSource =
  | 'qkms-registry'
  | 'generated-key'
  | 'certificate-store'
  | 'crypto-inventory'
  | 'runtime-telemetry'
  | 'agent-scan'
  | 'scan-finding'
  | 'exposure'
  | 'security-event'
  | 'vault-audit'
  | 'qkms-audit'
  | 'compliance-evidence'
  | 'migration-job'
  | 'rotation-job'
  | 'entropy-service'
  | 'policy-evaluation'

export interface QkmsEvidenceRef {
  source: QkmsEvidenceSource
  /** The row that carries the statement — clickable provenance. */
  table: string
  recordId: string
  observedAt: string | null
  detail: string
  /** Correlation ids the brief asks to be surfaced (section 10, 19). */
  scanId?: string | null
  telemetryId?: string | null
  findingId?: string | null
}

/* ------------------------------------------------------------------ */
/* Risk                                                                */
/* ------------------------------------------------------------------ */

export type RiskFactorKey =
  | 'algorithm'
  | 'quantum'
  | 'lifecycle'
  | 'rotation'
  | 'ownership'
  | 'custody'
  | 'exposure'

export interface RiskFactor {
  key: RiskFactorKey
  label: string
  /** Percent of the total score this factor can contribute. Sums to 100. */
  weight: number
  /** 0–100 for this factor alone. */
  score: number
  /** score × weight / 100 — what it actually added to the headline. */
  contribution: number
  /** Why the factor scored what it scored, in the operator's language. */
  reason: string
  /** `false` when the input the factor needs was never observed. */
  measured: boolean
}

export interface KeyRiskAssessment {
  /** 0–100. THE risk score. Computed once, never recomputed downstream. */
  score: number
  level: RiskLevel
  factors: RiskFactor[]
  /** Ordered worst-first; what an operator should read as the cause. */
  drivers: string[]
  recommendedAction: string
  /** How much of the score rests on measured (not assumed) inputs, 0–100. */
  confidence: number
  evidence: QkmsEvidenceRef[]
}

export const RISK_WEIGHTS: Array<{ key: RiskFactorKey; label: string; weight: number }> = [
  { key: 'algorithm', label: 'Algorithm strength', weight: 22 },
  { key: 'quantum', label: 'Quantum exposure', weight: 20 },
  { key: 'lifecycle', label: 'Lifecycle & expiry', weight: 15 },
  { key: 'rotation', label: 'Rotation compliance', weight: 14 },
  { key: 'ownership', label: 'Ownership & governance', weight: 11 },
  { key: 'custody', label: 'Custody & storage', weight: 10 },
  { key: 'exposure', label: 'Exposure & blast radius', weight: 8 },
]

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

/** A concrete row that contributed to a key record — the action target. */
export interface KeyRecordRef {
  table: string
  recordId: string
  /** true when this platform can write to the row (rotate/revoke/own it). */
  writable: boolean
}

export interface KeyVersion {
  id: string
  version: number
  /** `active` for the version currently in use. */
  status: 'active' | 'superseded' | 'revoked' | 'pending' | 'unknown'
  algorithm: string
  createdAt: string | null
  activatedAt: string | null
  supersededAt: string | null
  /** The version this one replaced, when the chain is known. */
  previousVersionId: string | null
  evidence: QkmsEvidenceRef | null
}

/**
 * What this platform can actually DO to a key (brief section 24).
 *
 * A key observed in a TLS certificate scan is a read-only observation: QKMS can
 * record a work order against it but cannot revoke it. Rendering a Revoke
 * button there would be a control that only appears functional.
 */
export interface KeyCapabilities {
  /** Can raise a governed rotation work order. */
  requestRotation: boolean
  /** Can record the rotation as executed and mint a new version record. */
  recordRotation: boolean
  /** Can mark the key record revoked in a table this platform owns. */
  revoke: boolean
  assignOwner: boolean
  decommission: boolean
  /** Why an unavailable capability is unavailable — shown in the UI. */
  reason: string
}

export interface ManagedKey {
  /* Identity ------------------------------------------------------- */
  id: string
  /** Human label: alias when known, else the algorithm + purpose. */
  label: string
  alias: string | null
  fingerprint: string | null
  /** Rows that produced this key, newest evidence first. */
  records: KeyRecordRef[]
  sources: QkmsEvidenceSource[]

  /* Cryptography --------------------------------------------------- */
  algorithm: string
  /** Canonical grouping label from the shared suite decomposer. */
  family: string
  keyClass: KeyClass
  keyType: string
  keySize: number | null
  purpose: string
  posture: KeyPqcPosture
  migrationRequirement: MigrationRequirement
  /** Plain-language justification for `posture` — never a bare verdict. */
  postureReason: string
  /** What the posture rests on. Only `observed` / `generated` can make a key PQC-ready. */
  postureEvidence: PostureEvidence
  /** Set when the registry DECLARES one algorithm and a scan OBSERVED another. */
  algorithmConflict: { declared: string; observed: string } | null

  /* Ownership & placement ------------------------------------------ */
  owner: string | null
  assetId: string | null
  assetName: string | null
  serviceName: string | null
  applicationName: string | null
  environment: string
  certificateIds: string[]

  /* Custody -------------------------------------------------------- */
  backend: string
  custody: CustodyClass
  storageReference: string | null
  hsmBacked: boolean
  exportable: boolean | null
  entropySource: string | null

  /* Lifecycle ------------------------------------------------------ */
  lifecycle: LifecycleState
  lifecycleReason: string
  rotation: RotationState
  rotationReason: string
  version: number
  versions: KeyVersion[]
  createdAt: string | null
  activatedAt: string | null
  lastUsedAt: string | null
  lastRotatedAt: string | null
  nextRotationDueAt: string | null
  expiresAt: string | null
  decommissionedAt: string | null
  /** Whole days since creation; null when creation was never observed. */
  ageDays: number | null
  /** Days until expiry; negative when expired; null when no expiry is known. */
  daysToExpiry: number | null

  /* Usage & relationships ------------------------------------------ */
  /** Runtime events attributable to this key. `null` = never measured. */
  runtimeUsage: number | null
  linkedCertificates: Array<{ id: string; subject: string; algorithm: string; expiresAt: string | null; status: string }>
  linkedMigrationJobs: Array<{ id: string; status: string; summary: string; updatedAt: string | null }>
  linkedRotationJobs: string[]
  /** Assets/services that break if this key is rotated badly. */
  blastRadius: number

  /* Governance & risk ---------------------------------------------- */
  violationIds: string[]
  complianceStatus: 'compliant' | 'violation' | 'evidence-required' | 'not-evaluated'
  risk: KeyRiskAssessment
  capabilities: KeyCapabilities

  /* Freshness ------------------------------------------------------ */
  lastObservedAt: string | null
  lastPolicyEvaluationAt: string | null
  evidence: QkmsEvidenceRef[]
  auditTrail: Array<{ id: string; eventType: string; summary: string; actor: string; at: string | null }>
}

/** The light row shipped in list projections — the table never needs the rest. */
export interface KeyIndexEntry {
  id: string
  label: string
  algorithm: string
  family: string
  keyClass: KeyClass
  keyType: string
  owner: string | null
  assetName: string | null
  environment: string
  backend: string
  custody: CustodyClass
  posture: KeyPqcPosture
  migrationRequirement: MigrationRequirement
  lifecycle: LifecycleState
  rotation: RotationState
  version: number
  createdAt: string | null
  lastUsedAt: string | null
  lastRotatedAt: string | null
  expiresAt: string | null
  daysToExpiry: number | null
  riskScore: number
  riskLevel: RiskLevel
  violations: number
  complianceStatus: ManagedKey['complianceStatus']
  postureEvidence: PostureEvidence
  lastObservedAt: string | null
}

/* ------------------------------------------------------------------ */
/* Governance                                                          */
/* ------------------------------------------------------------------ */

export type PolicyRule =
  | 'blocked-algorithm'
  | 'algorithm-not-allowed'
  | 'missing-owner'
  | 'hsm-required'
  | 'unapproved-custody'
  | 'export-not-allowed'
  | 'max-key-age-exceeded'
  | 'rotation-interval-exceeded'
  | 'expired-key-in-use'
  | 'pqc-migration-required'
  | 'decommission-overdue'

export const POLICY_RULE_LABEL: Record<PolicyRule, string> = {
  'blocked-algorithm': 'Blocked algorithm in use',
  'algorithm-not-allowed': 'Algorithm outside approved list',
  'missing-owner': 'No accountable owner',
  'hsm-required': 'HSM protection required but absent',
  'unapproved-custody': 'Key stored outside an approved backend',
  'export-not-allowed': 'Exportable key where export is prohibited',
  'max-key-age-exceeded': 'Key age exceeds policy maximum',
  'rotation-interval-exceeded': 'Rotation interval exceeded',
  'expired-key-in-use': 'Expired key still in use',
  'pqc-migration-required': 'PQC migration required by policy',
  'decommission-overdue': 'Decommission overdue',
}

export interface QkmsPolicy {
  id: string
  name: string
  description: string
  /** `tenant` policies are rows the tenant created; `baseline` ship with QKMS. */
  origin: 'tenant' | 'baseline'
  enabled: boolean
  severity: Severity
  environmentScope: string
  allowedAlgorithms: string[]
  blockedAlgorithms: string[]
  maxKeyAgeDays: number | null
  rotationIntervalDays: number | null
  requireOwner: boolean
  requireHsm: boolean
  allowExport: boolean
  requirePqc: boolean
  owner: string
  /** Keys this policy's scope actually selected. The violation denominator. */
  keysInScope: number
  violations: number
  /**
   * Percent of in-scope keys with no violation of this policy. `null` when the
   * policy evaluated nothing — disabled, or no key in its scope — which is not
   * 100% compliance.
   */
  compliance: number | null
  /** Whether this policy was actually evaluated against keys. */
  evaluation: 'evaluated' | 'disabled' | 'no-keys-in-scope'
  updatedAt: string | null
}

export interface GovernanceViolation {
  id: string
  rule: PolicyRule
  policyId: string
  policyName: string
  keyId: string
  keyLabel: string
  severity: Severity
  detail: string
  remediation: string
  detectedAt: string
  evidence: QkmsEvidenceRef[]
}

export interface StorageBackendPosture {
  id: string
  name: string
  provider: string
  custody: CustodyClass
  location: string
  protectionLevel: string
  hsmBacked: boolean
  /** `configured` only when a tenant row declares it; else `observed`. */
  status: 'configured' | 'observed' | 'unverified'
  keys: number
  violations: number
  lastVerifiedAt: string | null
  evidence: QkmsEvidenceRef[]
}

/**
 * Entropy posture (brief section 12).
 *
 * The four states are deliberately distinct and each requires its own evidence.
 * `available` is NOT claimed from the platform's general capability — only from
 * a tenant row that advertises the source.
 */
export type EntropyStatus = 'detected' | 'configured' | 'available' | 'not-available'

export interface EntropyPosture {
  status: EntropyStatus
  /** Source name only when something actually reported one. */
  source: string | null
  events: number
  latestAt: string | null
  detail: string
  /** Keys whose entropy source could be attributed at all. */
  attributedKeys: number
  distribution: DistributionRow[]
  evidence: QkmsEvidenceRef[]
}

/* ------------------------------------------------------------------ */
/* Rotation                                                            */
/* ------------------------------------------------------------------ */

/**
 * Rotation work-order state machine.
 *
 * QKMS does not hold the private material of a discovered third-party key, so
 * it cannot perform the cryptographic rotation itself. What it CAN do — and
 * what these states record — is govern the operation end to end: request,
 * approve, execute, validate, and hold the evidence. Nothing here ever claims
 * key material was replaced by this platform.
 */
export type RotationJobStatus =
  | 'requested'
  | 'approved'
  | 'in-progress'
  | 'awaiting-validation'
  | 'completed'
  | 'failed'
  | 'cancelled'

export const ROTATION_JOB_LABEL: Record<RotationJobStatus, string> = {
  requested: 'Requested',
  approved: 'Approved',
  'in-progress': 'In Progress',
  'awaiting-validation': 'Awaiting Validation',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

/** The governed transitions. Anything else is rejected server-side. */
export const ROTATION_TRANSITIONS: Record<RotationJobStatus, RotationJobStatus[]> = {
  requested: ['approved', 'cancelled'],
  approved: ['in-progress', 'cancelled'],
  'in-progress': ['awaiting-validation', 'failed'],
  'awaiting-validation': ['completed', 'failed'],
  completed: [],
  failed: ['requested'],
  cancelled: [],
}

export interface RotationJob {
  id: string
  keyId: string | null
  keyLabel: string
  owner: string | null
  assetName: string | null
  status: RotationJobStatus
  reason: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  previousVersion: number | null
  newVersion: number | null
  requestedBy: string | null
  approvedBy: string | null
  requestedAt: string | null
  startedAt: string | null
  completedAt: string | null
  failureReason: string | null
  /** `passed` requires post-rotation evidence, not merely a completed job. */
  validationStatus: 'not-started' | 'pending' | 'passed' | 'failed'
  validationDetail: string
  auditEventIds: string[]
  evidence: QkmsEvidenceRef[]
  /** Transitions the caller may request right now, given their capabilities. */
  allowedTransitions: RotationJobStatus[]
}

export interface RotationPosture {
  /** Keys whose rotation state could be determined at all. The denominator. */
  governedKeys: number
  healthy: number
  due: number
  overdue: number
  inProgress: number
  failed: number
  neverRotated: number
  /** `null` when no key in the estate has a determinable rotation state. */
  healthPercent: number | null
  /** Completed ÷ terminal jobs. `null` when no job has ever terminated. */
  successRate: number | null
  jobsTotal: number
  jobsActive: number
  jobsCompleted: number
  jobsFailed: number
  /** Assets + certificates + services touched by the current rotation queue. */
  blastRadius: number
  nextDueAt: string | null
}

/* ------------------------------------------------------------------ */
/* Readiness & migration gate                                          */
/* ------------------------------------------------------------------ */

export interface ReadinessBand {
  key: string
  label: string
  /** Keys this band applies to. `0` means the band is NOT APPLICABLE. */
  applicable: number
  /** Ready on OBSERVED or platform-GENERATED evidence. */
  ready: number
  /** PQC by registry declaration only — unverified, NOT counted in `ready`. */
  declared: number
  /** `null` when the band has no applicable key — never rendered as 0%. */
  percent: number | null
  detail: string
}

export type PrecheckDecision = 'pass' | 'warn' | 'block' | 'not-evaluated'

export interface GatePrecheck {
  id: string
  label: string
  decision: PrecheckDecision
  /** Records that produced the decision. */
  count: number
  detail: string
  requiredAction: string
  /** Key ids that fail this precheck — the drill-down target. */
  keyIds: string[]
}

export type MigrationGateState =
  | 'BLOCKED'
  | 'NOT_READY'
  | 'READY'
  | 'MIGRATION_IN_PROGRESS'
  | 'MIGRATED'
  | 'VALIDATION_REQUIRED'

export const GATE_LABEL: Record<MigrationGateState, string> = {
  BLOCKED: 'Blocked',
  NOT_READY: 'Not Ready',
  READY: 'Ready',
  MIGRATION_IN_PROGRESS: 'Migration In Progress',
  MIGRATED: 'Migrated',
  VALIDATION_REQUIRED: 'Validation Required',
}

export interface MigrationGate {
  state: MigrationGateState
  /** Why the gate decided what it decided. Never a bare status. */
  why: string
  blockers: string[]
  requiredActions: string[]
  evidence: QkmsEvidenceRef[]
  prechecks: GatePrecheck[]
  /** Prechecks passed ÷ prechecks evaluated. `null` when none evaluable. */
  score: number | null
  evaluatedAt: string
}

export interface PqcReadiness {
  /** PQC/hybrid keys ÷ keys that need a PQC decision. `null` when none do. */
  overall: number | null
  /** Keys counted ready in `overall` — evidenced PQC or hybrid material. */
  verifiedReady: number
  /** Keys whose PQC posture rests on a registry declaration alone. */
  declaredOnly: number
  /** Keys that need a post-quantum decision — `overall`'s denominator. */
  decisionScope: number
  bands: ReadinessBand[]
  postureCounts: Record<KeyPqcPosture, number>
  requirementCounts: Record<MigrationRequirement, number>
  gate: MigrationGate
}

/* ------------------------------------------------------------------ */
/* Aggregates                                                          */
/* ------------------------------------------------------------------ */

export interface DistributionRow {
  label: string
  count: number
  percent: number
  /** Ids behind the bar, so every chart segment drills down. */
  keyIds?: string[]
  /** The model's posture for the keys behind this row (most common), so the
   *  UI colours by classification instead of re-deriving it from a label. */
  posture?: KeyPqcPosture
}

/**
 * Headline metrics.
 *
 * Every field is a count of ONE unit and states which. The previous model
 * summed keys with finding rows into `weakAlgorithms`, producing a headline no
 * table could reconcile.
 */
export interface QkmsMetrics {
  /* keys */
  totalKeys: number
  activeKeys: number
  inUseKeys: number
  expiredKeys: number
  expiringSoonKeys: number
  rotationDueKeys: number
  rotationOverdueKeys: number
  neverRotatedKeys: number
  deprecatedKeys: number
  quantumVulnerableKeys: number
  pqcReadyKeys: number
  /** PQC or hybrid by registry declaration only — unverified, excluded from readiness. */
  declaredPqcKeys: number
  hybridKeys: number
  keysRequiringMigration: number
  orphanedKeys: number
  unmanagedCustodyKeys: number
  hsmProtectedKeys: number
  exportableProductionKeys: number
  criticalRiskKeys: number
  highRiskKeys: number
  /* violations (unit: violation, NOT key) */
  governanceViolations: number
  keysWithViolations: number
  /* evidence (unit: record) */
  auditEvidenceRecords: number
  /* scores, null when not computable */
  averageRiskScore: number | null
  pqcReadinessPercent: number | null
  custodyCoveragePercent: number | null
  auditReadinessPercent: number | null
  rotationHealthPercent: number | null
}

export type PipelineStatus =
  | 'active'
  | 'scan-running'
  | 'partial'
  | 'stale'
  | 'awaiting-key-evidence'
  | 'no-sources'

export interface QkmsTelemetryHealth {
  pipelineStatus: PipelineStatus
  agentsOnline: number
  agentsTotal: number
  connectorsActive: number
  connectorsTotal: number
  runningScans: number
  lastScanAt: string | null
  lastRuntimeEventAt: string | null
  lastKeyEventAt: string | null
  lastRotationAt: string | null
  lastPolicyEvaluationAt: string | null
  sourceCounts: Record<string, number>
  sources: Array<{ id: string; label: string; table: string; count: number; latestAt: string | null; status: 'live' | 'stale' | 'waiting' }>
  /** true when a row cap was hit and the model is a bounded sample. */
  truncated: boolean
  absentSources: string[]
  /** Auxiliary sources whose query FAILED (not empty) — figures that use them are incomplete. */
  degradedSources: string[]
}

export interface AuditEvidenceRecord {
  id: string
  title: string
  eventType: string
  actor: string
  keyId: string | null
  keyLabel: string | null
  at: string | null
  source: QkmsEvidenceSource
  table: string
  before: unknown
  after: unknown
}

/* ------------------------------------------------------------------ */
/* The model                                                           */
/* ------------------------------------------------------------------ */

export interface QkmsIntelligence {
  generatedAt: string
  latestEvidenceAt: string | null
  /** false ⇒ every surface renders the honest zero state, not empty charts. */
  hasData: boolean

  keys: ManagedKey[]
  metrics: QkmsMetrics

  lifecycle: {
    counts: Record<LifecycleState, number>
    funnel: Array<{ state: LifecycleState; label: string; count: number; percent: number; keyIds: string[] }>
    ageBuckets: DistributionRow[]
    expiryBuckets: DistributionRow[]
    attention: {
      expired: string[]
      expiringSoon: string[]
      overdueRotation: string[]
      neverRotated: string[]
      longLived: string[]
      orphaned: string[]
      unused: string[]
    }
  }

  governance: {
    policies: QkmsPolicy[]
    violations: GovernanceViolation[]
    violationsByRule: DistributionRow[]
    violationsBySeverity: DistributionRow[]
    backends: StorageBackendPosture[]
    entropy: EntropyPosture
  }

  rotation: {
    posture: RotationPosture
    jobs: RotationJob[]
    queue: string[]
    stateCounts: Record<RotationState, number>
  }

  readiness: PqcReadiness

  risk: {
    distribution: DistributionRow[]
    factorAverages: Array<{ key: RiskFactorKey; label: string; weight: number; average: number; measuredKeys: number }>
    /** Key ids ordered worst-first. */
    ranked: string[]
    remediation: Array<{ keyId: string; keyLabel: string; action: string; score: number; level: RiskLevel; rationale: string }>
  }

  distributions: {
    algorithms: DistributionRow[]
    families: DistributionRow[]
    keyClasses: DistributionRow[]
    owners: DistributionRow[]
    environments: DistributionRow[]
    custody: DistributionRow[]
    postures: DistributionRow[]
  }

  audit: AuditEvidenceRecord[]
  telemetry: QkmsTelemetryHealth
}

/** The seven pages. */
export type QkmsMode = 'overview' | 'inventory' | 'lifecycle' | 'governance' | 'rotation' | 'readiness' | 'risk-analysis'

export const QKMS_MODES: QkmsMode[] = ['overview', 'inventory', 'lifecycle', 'governance', 'rotation', 'readiness', 'risk-analysis']
