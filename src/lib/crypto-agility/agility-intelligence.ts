/**
 * QGuard Helix — Crypto Agility Intelligence Engine (isomorphic, pure).
 *
 * Single source of truth for CRYPTO AGILITY: how quickly and safely the tenant
 * can CHANGE its cryptography without breaking applications, infrastructure,
 * identity, PKI, trust relationships, vendors or business operations.
 *
 * Module positioning (deliberately NOT another inventory view)
 * -----------------------------------------------------------
 *   CBOM / Inventory       → what cryptography exists
 *   Quantum Readiness      → how exposed we are to quantum risk
 *   Crypto Agility (HERE)  → how easily we can CHANGE it
 *   Migration Planner      → what to migrate and in what order
 *   Migration Sandbox      → what happens if we do
 *   Live Migration Ops     → execute the approved change
 *
 * Reuse contract
 * --------------
 * Every asset fact (posture, risk, algorithms, certificates, dependencies,
 * compatibility, blast radius, owner) comes from the SHARED asset intelligence
 * engine (src/lib/migration/asset-intelligence.ts) that the Quantum Readiness
 * snapshot and Migration Planner already use. Ownership/control-domain facts
 * come from the SHARED Shared-Responsibility engine. This module derives only
 * agility-specific intelligence on top; it never re-derives posture, so an asset
 * can never read differently here than on any other page.
 *
 * Evidence discipline
 * -------------------
 *  - A domain with no supporting evidence scores `null` ("Insufficient
 *    Evidence") and is EXCLUDED from the weighted mean, with the remaining
 *    weights renormalised. Missing evidence is never converted into 0, and
 *    `unknown` never implies "safe".
 *  - Every domain, finding and matrix row carries the `basis` string that
 *    explains which real rows produced it.
 *  - Nothing is fabricated. No synthetic counts, no placeholder scores.
 */

import {
  EVIDENCE_UNAVAILABLE,
  classifyAlgorithm,
  clamp,
  num,
  recordOf,
  str,
  type AlgorithmClass,
  type AssetMigrationRecord,
  type AssetPortfolio,
  type Row,
} from '@/lib/migration/asset-intelligence'
import type {
  ResponsibilityDomain,
  SharedResponsibilityIntelligence,
} from '@/lib/shared-responsibility/types'
// The Trust Agility domain consumes the SHARED trust model published by the
// Trust Chain Analyzer so the two pages can never report different numbers.
import { computeTrustAgility } from '@/lib/ecosystem/external-trust-intelligence'
// Job status and validation are read through the platform's ONE rule set, so a
// sandbox simulation can never count as an operational transition here while
// Live Migration and the orchestration model say otherwise.
import { orchestrationStatus, migrationPathCheck } from '@/lib/migration/orchestration-model'
import { isPassingValidation, isSimulationRow } from '@/lib/migration/job-safety'
import type { SourceRead, SourceReadState } from '@/lib/source-read'

export { EVIDENCE_UNAVAILABLE }

/* ================================================================== */
/* Evidence sources (a failed query is not an empty table)             */
/* ================================================================== */

export type AgilitySourceState = SourceReadState

/**
 * What the router actually managed to read. A source whose query failed is
 * `unavailable`: every figure that depends on it is withheld (null + reason)
 * instead of being computed from an empty list that only LOOKS like "none".
 */
export type AgilitySourceStatus = SourceRead

/* ================================================================== */
/* Algorithm status (explicit, disjoint)                               */
/* ================================================================== */

/**
 * Every distinct algorithm carries exactly ONE status, decided in this order:
 *   unsupported → deprecated → (approved list: approved | configured) → detected → unknown
 */
export type AlgorithmStatus = 'unsupported' | 'deprecated' | 'configured' | 'approved' | 'detected' | 'unknown'

export const ALGORITHM_STATUS_ORDER: readonly AlgorithmStatus[] = ['unsupported', 'deprecated', 'configured', 'approved', 'detected', 'unknown'] as const

export const ALGORITHM_STATUS_LABEL: Record<AlgorithmStatus, string> = {
  unsupported: 'Unsupported',
  deprecated: 'Deprecated',
  configured: 'Configured',
  approved: 'Approved',
  detected: 'Detected',
  unknown: 'Unknown',
}

export const ALGORITHM_STATUS_DEFINITION: Record<AlgorithmStatus, string> = {
  unsupported:
    'Prohibited: cryptographically broken or below the platform floor (policy BLOCK — MD5, SHA-1, RC4, DES/3DES, RSA below 2048, TLS 1.0/1.1, SSL). There is no compliant way to keep it.',
  deprecated:
    'Quantum-vulnerable or policy WARN (RSA 2048+, ECDSA, ECDH, DH, DSA, Ed25519/X25519 on their own, TLS 1.2, AES-128). Permitted only during the transition — a replacement is required.',
  configured:
    'On the approved list (ML-KEM, ML-DSA, SLH-DSA, approved hybrids, AES-256-GCM, ChaCha20-Poly1305, SHA-3/SHAKE, TLS 1.3) but evidenced ONLY in source code or configuration. Not observed in operation, so it is not counted as deployed.',
  approved:
    'On the approved list AND observed in use by a discovery scan of a live endpoint or certificate, or by runtime telemetry. A statement about the algorithm — it does not make any asset PQC-ready.',
  detected:
    'Observed, but on neither the approved nor the deprecated list (for example SHA-256/384, HMAC, HKDF, AES-256 with an unconfirmed mode, or pre-standard PQC names such as Kyber or Dilithium). No policy verdict; kept inventoried.',
  unknown: 'A cryptographic value whose algorithm family or role could not be determined from the evidence.',
}

/** The cryptographic job an algorithm does — decides which replacement is valid. */
export type AlgorithmRole = 'key-establishment' | 'signature' | 'public-key' | 'symmetric' | 'hash' | 'kdf' | 'protocol' | 'cipher-suite' | 'unknown'

export const ALGORITHM_ROLE_LABEL: Record<AlgorithmRole, string> = {
  'key-establishment': 'Key establishment',
  signature: 'Digital signature',
  'public-key': 'Public key (role unconfirmed)',
  symmetric: 'Symmetric encryption',
  hash: 'Hashing',
  kdf: 'Key derivation / MAC',
  protocol: 'Transport protocol',
  'cipher-suite': 'TLS cipher suite',
  unknown: 'Role not determined',
}

/** Approved destination per role (FIPS 203 / 204 / 205, FIPS 197, FIPS 202, RFC 8446). */
export const APPROVED_TARGET_BY_ROLE: Record<AlgorithmRole, { target: string; standard: string } | null> = {
  'key-establishment': { target: 'ML-KEM-768 (hybrid X25519MLKEM768)', standard: 'FIPS 203' },
  signature: { target: 'ML-DSA-65 (SLH-DSA for long-lived roots)', standard: 'FIPS 204 / FIPS 205' },
  'public-key': { target: 'ML-KEM-768 if used for key establishment · ML-DSA-65 if used for signatures', standard: 'FIPS 203 / FIPS 204' },
  symmetric: { target: 'AES-256-GCM', standard: 'FIPS 197 / SP 800-38D' },
  hash: { target: 'SHA3-256 / SHA3-512', standard: 'FIPS 202' },
  kdf: { target: 'HKDF-SHA3-256', standard: 'SP 800-56C / FIPS 202' },
  protocol: { target: 'TLS 1.3 with the X25519MLKEM768 group', standard: 'RFC 8446 / FIPS 203' },
  'cipher-suite': { target: 'TLS_AES_256_GCM_SHA384 + X25519MLKEM768', standard: 'RFC 8446 / FIPS 203' },
  unknown: null,
}

/** Where an algorithm was evidenced. Only `runtime`, `scan` and `certificate` are operational evidence. */
export type EvidenceProvenance = 'runtime' | 'scan' | 'certificate' | 'source' | 'config'

export const PROVENANCE_LABEL: Record<EvidenceProvenance, string> = {
  runtime: 'Runtime telemetry',
  scan: 'Discovery scan',
  certificate: 'Served certificate',
  source: 'Source code',
  config: 'Configuration file',
}

/** One measurable input to a domain score. Unmeasured factors are excluded and their weight redistributed. */
export interface ScoreFactor {
  key: string
  label: string
  /** Nominal weight within the domain (0–1). */
  weight: number
  /** Weight after redistribution over the MEASURED factors; 0 when unmeasured. */
  effectiveWeight: number
  /** 0–100, or null when unmeasured. Never a stand-in constant. */
  value: number | null
  measured: boolean
  basis: string
}

/* ================================================================== */
/* Vocabulary                                                          */
/* ================================================================== */

/** How replaceable a cryptographic implementation is today. */
export type AgilityState = 'agile' | 'conditional' | 'rigid' | 'blocked' | 'unknown'

export const AGILITY_STATE_LABEL: Record<AgilityState, string> = {
  agile: 'Agile',
  conditional: 'Conditionally Agile',
  rigid: 'Rigid',
  blocked: 'Blocked',
  unknown: 'Unknown',
}

export const AGILITY_STATE_DEFINITION: Record<AgilityState, string> = {
  agile: 'Configuration-driven and replaceable without code or architecture change.',
  conditional: 'Can be changed, but requires coordinated dependencies or manual intervention.',
  rigid: 'Requires code or architecture change before the cryptography can be replaced.',
  blocked: 'Cannot currently be migrated because of a known unresolved dependency.',
  unknown: 'Insufficient evidence to determine replaceability — this is NOT a statement that it is safe.',
}

/** The answer to "can this be replaced without modifying application logic?" */
export type ReplaceabilityClass = 'configuration' | 'library' | 'code' | 'architecture' | 'vendor' | 'unknown'

export const REPLACEABILITY_LABEL: Record<ReplaceabilityClass, string> = {
  configuration: 'Configuration Only',
  library: 'Library Upgrade',
  code: 'Code Modification',
  architecture: 'Architecture Modification',
  vendor: 'Vendor Dependency',
  unknown: 'Insufficient Evidence',
}

/** Ordered worst → best; used to pick the dominant class for a group. */
const REPLACEABILITY_RANK: Record<ReplaceabilityClass, number> = {
  vendor: 5,
  architecture: 4,
  code: 3,
  library: 2,
  configuration: 1,
  unknown: 0,
}

export type EvidenceConfidence = 'high' | 'medium' | 'low' | 'none'

export type ControlDomain = ResponsibilityDomain

export const CONTROL_DOMAIN_LABEL: Record<ControlDomain, string> = {
  customer: 'Customer-Controlled',
  provider: 'Provider-Controlled',
  ecosystem: 'Ecosystem-Dependent',
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

export type MigrationReadinessState = 'ready' | 'conditional' | 'blocked' | 'unknown'

export const MIGRATION_READINESS_LABEL: Record<MigrationReadinessState, string> = {
  ready: 'Ready',
  conditional: 'Conditionally Ready',
  blocked: 'Blocked',
  unknown: 'Unknown',
}

/* ================================================================== */
/* Agility domains                                                     */
/* ================================================================== */

export type AgilityDomainKey =
  | 'application'
  | 'algorithm'
  | 'protocol'
  | 'certificate'
  | 'key'
  | 'library'
  | 'infrastructure'
  | 'identity'
  | 'trust'
  | 'vendor'
  | 'runtime'

interface DomainDefinition {
  key: AgilityDomainKey
  label: string
  question: string
  weight: number
  route: string
}

/**
 * Domain weights sum to 100. Weighting favours the layers that most often
 * decide whether a cryptographic change is a config flag or a re-architecture.
 */
export const AGILITY_DOMAINS: readonly DomainDefinition[] = [
  { key: 'application', label: 'Application Agility', question: 'Can applications change cryptographic algorithms without major code changes?', weight: 12, route: '/dashboard/assets' },
  { key: 'algorithm', label: 'Algorithm Replaceability', question: 'Can algorithms be replaced without redesigning applications?', weight: 12, route: '/dashboard/cbom' },
  { key: 'protocol', label: 'Protocol Agility', question: 'Can TLS and protocol configurations transition to new cryptographic suites?', weight: 11, route: '/dashboard/protocol-analytics' },
  { key: 'certificate', label: 'Certificate Agility', question: 'Can certificates and trust chains be replaced quickly and safely?', weight: 10, route: '/dashboard/pki-visibility' },
  { key: 'library', label: 'Library / Provider Agility', question: 'Can cryptographic libraries and providers be upgraded safely?', weight: 10, route: '/dashboard/cbom_explorer' },
  { key: 'key', label: 'Key Agility', question: 'Can keys be rotated or replaced without operational disruption?', weight: 9, route: '/dashboard/qkms' },
  { key: 'infrastructure', label: 'Infrastructure Agility', question: 'Can cryptographic configuration change across servers, containers and clusters?', weight: 8, route: '/dashboard/multi-cloud-telemetry' },
  { key: 'identity', label: 'Identity Agility', question: 'Can authentication and signing mechanisms transition to PQC?', weight: 8, route: '/dashboard/pqauth' },
  { key: 'trust', label: 'Trust Agility', question: 'Can trust anchors, CA chains and federation dependencies change safely?', weight: 7, route: '/dashboard/trust-chain-analyzer' },
  { key: 'vendor', label: 'Vendor / Ecosystem Agility', question: 'Can external vendors support the cryptographic transition?', weight: 7, route: '/dashboard/vendor-pqc-readiness' },
  { key: 'runtime', label: 'Runtime Agility', question: 'Can cryptographic changes and drift be detected during operation?', weight: 6, route: '/dashboard/runtime-crypto-intel' },
] as const

export interface AgilityDomain {
  key: AgilityDomainKey
  label: string
  question: string
  weight: number
  route: string
  /** null ⇒ Insufficient Evidence. Never coerced to 0. */
  score: number | null
  state: AgilityState
  /** % of the relevant population that actually carries evidence. */
  evidenceCoverage: number
  confidence: EvidenceConfidence
  /** Inverse-of-score risk contribution, only when scored. */
  risk: number | null
  riskLevel: string
  blockers: number
  affectedAssets: number
  /** Score points recoverable by clearing this domain's blockers. */
  improvementOpportunity: number
  /** Human-readable derivation — which real rows produced this score. */
  basis: string
  /** Ranked, evidence-backed actions for this domain. */
  actions: string[]
  /** The factors behind `score`, each flagged measured/unmeasured with its redistributed weight. */
  factors: ScoreFactor[]
}

/* ================================================================== */
/* Records                                                             */
/* ================================================================== */

export interface CouplingFinding {
  id: string
  type:
    | 'hardcoded-algorithm'
    | 'hardcoded-cipher-suite'
    | 'hardcoded-key-size'
    | 'embedded-certificate'
    | 'embedded-public-key'
    | 'static-trust-anchor'
    | 'hardcoded-certificate-path'
    | 'vendor-locked-crypto'
    | 'legacy-crypto-provider'
    | 'embedded-crypto-config'
    | 'manual-certificate-management'
    | 'manual-key-management'
    | 'undocumented-dependency'
  title: string
  severity: Severity
  assetId: string
  asset: string
  environment: string
  owner: string
  /** The real detected value / row that produced this finding. */
  evidence: string
  evidenceSource: string
  dependencyCount: number
  agilityImpact: number
  agilityImpactLabel: string
  remediation: string
  controlDomain: ControlDomain
  domain: AgilityDomainKey
  route: string
}

export interface ReplaceabilityRow {
  id: string
  currentAlgorithm: string
  classification: AlgorithmClass
  proposedReplacement: string
  standard: string
  rationale: string
  assets: number
  assetNames: string[]
  instances: number
  replaceability: ReplaceabilityClass
  replaceabilityLabel: string
  dependencies: number
  migrationComplexity: 'Low' | 'Medium' | 'High' | 'Unknown'
  compatibility: string
  compatibilityScore: number | null
  risk: Severity
  status: AgilityState
  /** Distribution of the per-asset replaceability verdicts behind this row. */
  breakdown: Record<ReplaceabilityClass, number>
  basis: string
  /** What the algorithm does — decides which approved target is valid. */
  role: AlgorithmRole
  roleLabel: string
  /** Exactly one of the disjoint algorithm statuses. */
  algorithmStatus: AlgorithmStatus
  statusReason: string
  /** true for deprecated / unsupported — the rows the transition matrix counts. */
  needsTransition: boolean
  /** Asset-level evidence counts by provenance (an asset may contribute to several). */
  provenance: Record<EvidenceProvenance, number>
  /** Observed by a scan, served certificate or runtime telemetry — not only declared. */
  observedInOperation: boolean
  /** Assets running this algorithm whose agility verdict is Rigid or Blocked. */
  blockedAssets: number
  blockedAssetNames: string[]
}

/** One lane of the algorithm-transition matrix: every algorithm of a role → the approved target. */
export interface TransitionLane {
  role: AlgorithmRole
  label: string
  target: string | null
  standard: string | null
  algorithms: number
  instances: number
  assets: number
  /** Instances per status — sums to `instances`. */
  byStatus: Record<AlgorithmStatus, number>
  /** Instances that are deprecated or unsupported. */
  needsTransition: number
  /** Distinct assets in this lane that need a transition AND are Rigid/Blocked. */
  blockedAssets: number
  rowIds: string[]
}

export interface AlgorithmStatusSummary {
  status: AlgorithmStatus
  label: string
  definition: string
  algorithms: number
  instances: number
}

export interface AgilityBlocker {
  id: string
  category:
    | 'hardcoded-crypto'
    | 'unsupported-library'
    | 'legacy-protocol'
    | 'certificate-dependency'
    | 'trust-dependency'
    | 'vendor-dependency'
    | 'application-incompatibility'
    | 'infrastructure-dependency'
    | 'identity-dependency'
    | 'unknown-dependency'
  categoryLabel: string
  title: string
  severity: Severity
  count: number
  affectedAssets: string[]
  affectedAssetIds: string[]
  businessImpact: string
  owner: string
  controlDomain: ControlDomain
  remediation: string
  domain: AgilityDomainKey
  route: string
  basis: string
}

export interface ResponsibilityRow {
  id: string
  finding: string
  asset: string
  owner: string
  userAction: string
  priority: Severity
  controlDomain: ControlDomain
  controlDomainLabel: string
  status: string
  occurrences: number
  agilityState: AgilityState
}

export interface AgilityAssetRow {
  id: string
  name: string
  type: string
  environment: string
  owner: string
  businessCriticality: string
  internetFacing: boolean
  hasEvidence: boolean
  /**
   * false ⇒ this asset's evidence (edge scan only) could not have revealed
   * application-level coupling. Its verdict is capped at Conditional and the
   * application-agility domain excludes it, because silence is not proof.
   */
  couplingAssessed: boolean
  agilityState: AgilityState
  agilityScore: number | null
  replaceability: ReplaceabilityClass
  replaceabilityLabel: string
  readiness: MigrationReadinessState
  readinessLabel: string
  currentAlgorithms: string[]
  targetAlgorithms: string[]
  dependencies: number
  blockers: number
  blockerReasons: string[]
  couplingFindings: number
  componentCount: number
  vulnerableComponentCount: number
  riskScore: number
  priority: string
  controlDomain: ControlDomain
  migrationStatus: string
  nextAction: string
  nextActionRoute: string
  lastEvidenceAt: string | null
  basis: string
  /** Every point that moved this asset's agility score, in order, so the number is traceable. */
  scoreFactors: Array<{ label: string; points: number; basis: string }>
  /** Latest OPERATIONAL migration job (sandbox simulations excluded) — null when none. */
  operationalJob: { status: string; updatedAt: string | null; targetAlgorithm: string } | null
  /** Latest validation record passed (completed-but-unvalidated is NOT validated). */
  validated: boolean
  /** Distinct algorithms on this asset per status. */
  algorithmStatusCounts: Record<AlgorithmStatus, number>
}

export interface AgilityDistributionBucket {
  state: AgilityState
  label: string
  definition: string
  count: number
  share: number
}

/* ---- Coupling / dependency graph --------------------------------- */

export type CouplingLayer =
  | 'application'
  | 'library'
  | 'algorithm'
  | 'certificate'
  | 'pki'
  | 'trust-anchor'
  | 'identity'
  | 'vendor'

export const COUPLING_LAYER_ORDER: readonly CouplingLayer[] = [
  'application',
  'library',
  'algorithm',
  'certificate',
  'pki',
  'trust-anchor',
  'identity',
  'vendor',
] as const

export const COUPLING_LAYER_LABEL: Record<CouplingLayer, string> = {
  application: 'Application',
  library: 'Crypto Library',
  algorithm: 'Algorithm',
  certificate: 'Certificate',
  pki: 'PKI / CA',
  'trust-anchor': 'Trust Anchor',
  identity: 'Identity Provider',
  vendor: 'Vendor / External',
}

export interface CouplingNode {
  id: string
  label: string
  layer: CouplingLayer
  agilityState: AgilityState
  /**
   * The asset's own risk score for application/identity nodes; null for
   * library, algorithm, certificate, PKI, anchor and vendor nodes — no risk is
   * invented for a node that has no measured risk of its own.
   */
  risk: number | null
  /** Assets that transit this node — the node's blast radius. */
  assetIds: string[]
  assetCount: number
  algorithm: string
  replaceability: ReplaceabilityClass
  controlDomain: ControlDomain
  detail: string
  route: string
  /** Algorithm status for algorithm nodes; null elsewhere. */
  algorithmStatus: AlgorithmStatus | null
  /** Evidence-backed reasons this node blocks a safe transition (empty ⇒ none recorded). */
  blockers: string[]
  /** Used by more than one graphed asset — a change here moves several systems at once. */
  shared: boolean
}

export interface CouplingEdge {
  source: string
  target: string
  kind: 'uses' | 'implements' | 'signs' | 'issued-by' | 'anchors' | 'federates' | 'depends-on'
  weight: number
  agilityState: AgilityState
}

export interface CouplingGraph {
  nodes: CouplingNode[]
  edges: CouplingEdge[]
  layers: Array<{ layer: CouplingLayer; label: string; count: number }>
  note: string
  /** Graphed assets vs evaluated assets — the graph is a bounded slice and says so. */
  shownAssets: number
  evaluatedAssets: number
  /** Nodes that carry at least one recorded blocker. */
  blockingNodes: number
}

/* ---- Policy ------------------------------------------------------ */

export type PolicyVerdict = 'required' | 'preferred' | 'allow' | 'warn' | 'block'

export interface PolicyRule {
  id: string
  subject: string
  verdict: PolicyVerdict
  rationale: string
  standard: string
}

export interface PolicyViolation {
  ruleId: string
  subject: string
  verdict: PolicyVerdict
  severity: Severity
  observed: string
  assets: number
  assetNames: string[]
  instances: number
  remediation: string
}

export type PolicyExceptionState = 'active' | 'expired' | 'requested' | 'rejected' | 'other'

export interface PolicyEvaluation {
  policyName: string
  version: string
  source: 'platform-mandatory-stack' | 'tenant-configured'
  evaluated: boolean
  /**
   * What the platform does with a violation. No enforcement point (policy
   * engine, CI gate, TLS policy push) reports to this module, so the policy is
   * EVALUATED against evidence — it is not enforced, and the page says so.
   */
  enforcement: { mode: 'evaluation-only'; detail: string }
  rules: PolicyRule[]
  violations: PolicyViolation[]
  compliancePct: number | null
  compliantInstances: number
  evaluatedInstances: number
  exceptions: Array<{ id: string; policy: string; justification: string; status: string; state: PolicyExceptionState; expiresAt: string | null }>
  /** false when the exceptions table could not be read — "0 exceptions" would then be a guess. */
  exceptionsAvailable: boolean
  basis: string
}

/* ---- Configuration-change tracking -------------------------------- */

export interface ConfigurationChange {
  id: string
  at: string | null
  kind: 'migration-completed' | 'migration-failed' | 'migration-in-progress' | 'config-event' | 'runtime-observation'
  asset: string
  assetId: string
  detail: string
  algorithm: string
  /** For completed migrations: whether a passing validation record exists. */
  validated: boolean | null
  source: string
  route: string
}

export interface ChangeTracking {
  /** Recorded changes only — never inferred. */
  changes: ConfigurationChange[]
  total: number
  lastChangeAt: string | null
  sources: string[]
  note: string
}

/* ---- Runtime + drift --------------------------------------------- */

export interface RuntimeCryptoEvent {
  id: string
  observedAt: string | null
  asset: string
  assetId: string
  eventType: string
  algorithm: string
  source: string
  severity: Severity
  status: string
  route: string
}

export type DriftDirection = 'improving' | 'stable' | 'degrading' | 'critical' | 'unknown'

export interface AgilityDriftPoint {
  label: string
  at: string
  agilityScore: number | null
  vulnerableShare: number | null
  pqcShare: number | null
  evidenceCount: number
}

export interface AgilityDrift {
  direction: DriftDirection
  deltaPoints: number | null
  windowLabel: string
  signals: Array<{ label: string; count: number; tone: 'good' | 'warning' | 'critical' | 'neutral'; detail: string }>
  trend: AgilityDriftPoint[]
  basis: string
}

export interface AssessmentHistoryPoint {
  at: string
  label: string
  /**
   * Only present on the LIVE point. Reconstructed points cannot carry an agility
   * score: agility depends on coupling, ownership and dependency evidence that
   * has no historical snapshot. Publishing a reconstructed number here — and
   * then diffing it against the live score — would compare two different scales.
   */
  agilityScore: number | null
  /** PQC component adoption at this point. Same scale across every point. */
  pqcAdoptionPct: number | null
  /** Quantum-vulnerable component share at this point. Same scale across every point. */
  vulnerableSharePct: number | null
  migrationReadinessPct: number | null
  blockers: number
  policyCompliancePct: number | null
  assetsEvaluated: number
  componentsObserved: number
  drift: DriftDirection
  reconstructed: boolean
}

/* ---- Lifecycle --------------------------------------------------- */

export interface LifecycleStage {
  key: string
  label: string
  description: string
  status: 'complete' | 'active' | 'pending' | 'blocked'
  /** A real share with a stated denominator, or null when no share applies. */
  progressPct: number | null
  /** Numerator / denominator behind progressPct (null when no share applies). */
  count: number
  of: number | null
  metric: string
  route: string
  module: string
}

/* ---- Sandbox impact preview -------------------------------------- */

export interface ChangeImpactPreview {
  /** Always 'projection': this is arithmetic over evidence already held, never a simulation. */
  kind: 'projection'
  assetId: string
  asset: string
  fromAlgorithm: string
  toAlgorithm: string
  /** The asset itself plus every recorded dependency relationship. */
  assetsAffected: number
  dependencies: number
  potentialFailures: Array<{ label: string; detail: string; severity: Severity }>
  compatibility: string
  compatibilityScore: number
  trustImpact: string
  migrationRisk: string
  migrationRiskScore: number
  expectedRemediation: string[]
  replaceability: ReplaceabilityClass
  /** Role consistency of the proposed path (shared rule with PQC Orchestration). */
  roleCheck: { check: 'consistent' | 'role-mismatch' | 'unverifiable'; note: string }
  basis: string
}

/* ---- Recommendations (Sophia-facing) ----------------------------- */

export interface AgilityRecommendation {
  id: string
  title: string
  detail: string
  severity: Severity
  /**
   * Upper bound on the headline gain, computed on the PUBLISHED score's own
   * renormalised weights — or null when it cannot be modelled without
   * re-running the evidence (blocker clearance is not modelled here).
   */
  expectedScoreGain: number | null
  affectedAssets: number
  dependencyReductionPct: number | null
  controlDomain: ControlDomain
  action: string
  route: string
  evidence: string[]
}

/* ---- KPIs -------------------------------------------------------- */

export interface AgilityKpi {
  key: string
  label: string
  value: string
  numeric: number | null
  detail: string
  tone: 'good' | 'warning' | 'critical' | 'neutral' | 'info' | 'ai'
  route: string
  basis: string
  filter?: { kind: 'state'; value: AgilityState } | { kind: 'readiness'; value: MigrationReadinessState }
}

/* ================================================================== */
/* Aggregate                                                           */
/* ================================================================== */

export interface CryptoAgilityIntelligence {
  generatedAt: string
  lastAssessmentAt: string | null
  hasData: boolean
  evidenceCoverage: number
  confidence: EvidenceConfidence

  score: {
    agilityScore: number | null
    agilityLevel: string
    migrationReadinessPct: number | null
    assetsEvaluated: number
    /** Evaluated assets whose evidence could reveal application-level coupling. */
    couplingAssessed: number
    criticalBlockers: number
    scoredWeight: number
    blockerPenalty: number
    explanation: string
    formula: string
    components: Array<{ label: string; weight: number; score: number | null; contribution: number; basis: string }>
  }

  kpis: AgilityKpi[]
  domains: AgilityDomain[]
  distribution: AgilityDistributionBucket[]
  assets: AgilityAssetRow[]
  coupling: CouplingFinding[]
  replaceability: ReplaceabilityRow[]
  /** Algorithm-transition matrix: one lane per role, current algorithms → approved target. */
  transitions: TransitionLane[]
  /** Distinct algorithms and instances per status — sums to the replaceability rows. */
  algorithmStatus: AlgorithmStatusSummary[]
  /** Recorded values excluded because they are scanner finding titles, not algorithms. */
  excludedFindingTitles: number
  /** Recorded configuration changes (operational migrations, config events, runtime observations). */
  changeTracking: ChangeTracking
  /** Which evidence sources were read, and how. */
  sources: AgilitySourceStatus[]
  /** The single most valuable next step the evidence supports. */
  nextStep: { label: string; detail: string; route: string; tone: 'action' | 'warning' | 'calm' }
  blockers: AgilityBlocker[]
  responsibility: ResponsibilityRow[]
  graph: CouplingGraph
  lifecycle: LifecycleStage[]
  policy: PolicyEvaluation
  runtimeEvents: RuntimeCryptoEvent[]
  drift: AgilityDrift
  history: AssessmentHistoryPoint[]
  recommendations: AgilityRecommendation[]
  readiness: {
    ready: number
    conditional: number
    blocked: number
    unknown: number
    pct: number | null
  }
  filters: {
    environments: string[]
    owners: string[]
    algorithms: string[]
    controlDomains: ControlDomain[]
  }
  evidence: {
    sources: string[]
    assets: number
    components: number
    certificates: number
    runtimeEvents: number
    relationships: number
    scanSessions: number
    note: string
  }
}

/* ================================================================== */
/* Inputs                                                              */
/* ================================================================== */

export interface AgilitySnapshotFacts {
  hasData: boolean
  lastAssessmentAt: string | null
  scores: { quantumReadiness: number; pqcAdoption: number; quantumRisk: number; hndlRisk: number }
  inventory: {
    assetsAssessed: number
    cryptoComponents: number
    vulnerableComponents: number
    pqcReadyComponents: number
    certificatesAnalyzed: number
    keysDiscovered: number
    trustRelationships: number
    cloudAccounts: number
    domainsScanned: number
  }
  sharedResponsibility: SharedResponsibilityIntelligence | null
}

export interface AgilityInputs {
  /** Per-asset dossiers from the SHARED asset intelligence engine. */
  assets: AssetMigrationRecord[]
  portfolioSummary: AssetPortfolio['summary']
  snapshot: AgilitySnapshotFacts
  /** Raw tenant rows used only for agility-specific signals. */
  cryptoInventory: Row[]
  cryptoExposures: Row[]
  certificates: Row[]
  runtimeEvents: Row[]
  generatedKeys: Row[]
  migrationJobs: Row[]
  scanSessions: Row[]
  securityEvents: Row[]
  connectorAccounts: Row[]
  relationships: Row[]
  policyExceptions: Row[]
  /**
   * Read status of each raw source. Omitted (fixtures) ⇒ every source is
   * treated as read. A source marked `unavailable` withholds the figures that
   * depend on it.
   */
  sourceHealth?: AgilitySourceStatus[]
  now?: number
}

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

function pctOf(part: number, total: number): number {
  if (!total || total <= 0) return 0
  return clamp((part / total) * 100)
}

function severityFromScore(score: number): Severity {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 35) return 'medium'
  if (score > 0) return 'low'
  return 'info'
}

function normalizeSeverity(raw: string): Severity {
  const s = raw.toLowerCase()
  if (s.includes('critical')) return 'critical'
  if (s.includes('high')) return 'high'
  if (s.includes('medium') || s.includes('moderate') || s.includes('warn')) return 'medium'
  if (s.includes('low')) return 'low'
  return 'info'
}

export function agilityLevelFromScore(score: number | null): string {
  if (score === null) return 'Unknown'
  if (score >= 85) return 'Excellent'
  if (score >= 70) return 'Strong'
  if (score >= 50) return 'Moderate'
  if (score >= 30) return 'Weak'
  return 'Critical'
}

function riskLevelFromScore(score: number | null): string {
  if (score === null) return 'Unknown'
  if (score >= 80) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 40) return 'Elevated'
  if (score >= 20) return 'Moderate'
  if (score > 0) return 'Low'
  return 'Minimal'
}

function confidenceFromCoverage(coverage: number, hasAnyEvidence: boolean): EvidenceConfidence {
  if (!hasAnyEvidence) return 'none'
  if (coverage >= 75) return 'high'
  if (coverage >= 40) return 'medium'
  return 'low'
}

function stateFromScore(score: number | null, blockers: number): AgilityState {
  if (score === null) return 'unknown'
  if (blockers > 0 && score < 40) return 'blocked'
  if (score >= 75) return 'agile'
  if (score >= 45) return 'conditional'
  return 'rigid'
}

function isoOrNull(value: unknown): string | null {
  const s = str(value)
  if (!s) return null
  return Number.isFinite(new Date(s).getTime()) ? s : null
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

const MANAGED_ISSUER_MARKERS = [
  "let's encrypt",
  'letsencrypt',
  'acme',
  'amazon',
  'aws certificate',
  'google trust',
  'cloudflare',
  'azure',
  'digicert managed',
  'zerossl',
  'certmanager',
  'cert-manager',
  'vault',
]

const DEPRECATED_LIBRARY_MARKERS = [
  'openssl 1.0',
  'openssl 1.1',
  'libressl 2',
  'bouncycastle 1.5',
  'bouncy castle 1.5',
  'cryptoapi',
  'jce 1.7',
  'nss 3.1',
  'gnutls 2',
  'pycrypto',
  'md5crypt',
  'jsrsasign 8',
  'node-forge 0.',
  'crypto-js 3',
]

/**
 * Broken primitives.
 *
 * The digit classes use a negative lookahead on a following DIGIT rather than
 * `\b`, because X.509/OpenSSL spell these as `sha1WithRSAEncryption` and
 * `md5WithRSAEncryption` — where `\b` fails and the broken primitive would be
 * silently missed. SHA-256/384/512 and SHA3-* still do not match.
 */

/* ------------------------------------------------------------------ */
/* Primitive vs. finding-title discrimination                          */
/* ------------------------------------------------------------------ */

/**
 * Scanners write FINDING TITLES into the same `algorithm` field they use for
 * real primitives ("No ML-KEM Support", "Missing HSTS", "HNDL Risk: High",
 * "ECDSA Certificate Detected"). Upstream modules tolerate that because they
 * present those rows as findings.
 *
 * This module must not: an Algorithm Replaceability Matrix that offers to
 * migrate "Regulatory Compliance Gap" to ML-KEM-768 is nonsense, and — worse —
 * "No ML-KEM Support" contains "ML-KEM", so a naive classifier reads a finding
 * that PQC is MISSING as evidence that the asset is already quantum-safe.
 *
 * So agility scoring, the matrix, the graph and policy evaluation all run
 * through this gate. Rejected strings are not discarded silently: they simply
 * are not treated as cryptography, and the counts that mention them say so.
 */
const FINDING_PHRASE_RE =
  /^(no|missing|lack(ing)?|absent|unsupported|weak|insecure|deprecated|legacy|unknown|potential|possible)\b|\b(risk|gap|deadline|strategy|surface|disclosure|compliance|posture|score|rating|warning|advisory|recommendation|issue|finding|vulnerabilit|exposure|support|pinning|policy)\b|\b(detected|observed|enabled|disabled|required|expired|expiring)$|:/i

const PRIMITIVE_RE = new RegExp(
  [
    '^(TLS|SSL)_[A-Z0-9_]+$', // cipher suites
    '\\bTLS\\s?v?1\\.[0-3]\\b',
    '\\bSSL\\s?v?[23]\\b',
    '\\bRSA(SSA|ES)?\\b',
    '\\bECDSA\\b',
    '\\bECDHE?\\b',
    '\\bEdDSA\\b',
    '\\bEd(25519|448)\\b',
    '\\bX(25519|448)\\b',
    '\\bDSA\\b',
    '\\bDH\\b',
    '\\bDIFFIE\\b',
    '\\bAES\\b',
    '\\bCHACHA20?\\b',
    '\\bPOLY1305\\b',
    '\\b3?DES\\b',
    '\\bRC4\\b',
    '\\bBLOWFISH\\b',
    '\\bCAMELLIA\\b',
    '\\bSHA-?(1|224|256|384|512)\\b',
    '\\bSHA3-?(256|384|512)\\b',
    '\\bSHAKE(128|256)\\b',
    '\\bMD5\\b',
    '\\bHMAC\\b',
    '\\bHKDF\\b',
    '\\bPBKDF2\\b',
    '\\bBCRYPT\\b',
    '\\bSCRYPT\\b',
    '\\bARGON2\\b',
    '\\bML-?KEM\\b',
    '\\bML-?DSA\\b',
    '\\bSLH-?DSA\\b',
    '\\bKYBER\\b',
    '\\bDILITHIUM\\b',
    '\\bFALCON\\b',
    '\\bSPHINCS\\b',
    '\\bFRODOKEM\\b',
    '\\bBIKE\\b',
    '\\bHQC\\b',
    '\\bSECP\\d',
    '\\bPRIME256V1\\b',
    '\\bBRAINPOOL',
    '\\bP-(256|384|521)\\b',
    '\\bECPUBLICKEY\\b',
    '\\bGOST\\b',
    /*
     * X.509 signature algorithms in their concatenated spelling —
     * "SHA256withRSA", "sha1WithRSAEncryption", "SHA384withECDSA".
     *
     * Every token above is `\b`-anchored, and there is no word boundary inside
     * "withRSA": `h` and `R` are both word characters, so `\bRSA\b` cannot see
     * it, and `SHA256` fails its trailing boundary for the same reason. The
     * most common way a certificate records its algorithm therefore read as a
     * scanner finding title and was excluded from every primitive count.
     */
    'WITH(RSA|DSA|ECDSA|ED25519)',
  ].join('|'),
  'i',
)

/**
 * True when `value` names a real cryptographic primitive, protocol version,
 * cipher suite or curve — as opposed to a scanner finding title.
 */
export function isCryptographicPrimitive(value: string): boolean {
  const text = value.trim()
  if (!text) return false
  // A cipher-suite constant is unambiguous even though it contains "_WITH_".
  if (/^(TLS|SSL)_[A-Z0-9_]+$/.test(text)) return true
  if (FINDING_PHRASE_RE.test(text)) return false
  // Sentences are findings, not primitives.
  if (text.split(/\s+/).length > 5) return false
  return PRIMITIVE_RE.test(text)
}

/* ================================================================== */
/* Algorithm role + status (one rule set for status AND policy)        */
/* ================================================================== */

/**
 * Token boundary that treats `_` and `-` as separators. `\b` cannot be used:
 * in a cipher-suite constant ("TLS_RSA_WITH_RC4_128_SHA") the underscore is a
 * word character, so `\bRC4\b` never matches and RC4 read as compliant.
 */
const tok = (body: string) => new RegExp(`(?<![A-Z0-9])(?:${body})(?![A-Z0-9])`, 'i')

const ROLE_PATTERNS = {
  cipherSuite: /^(TLS|SSL)_[A-Z0-9_]+$|^(ECDHE|DHE|EDH|RSA|PSK|AECDH|ADH|SRP)(-[A-Z0-9]+){2,}$/i,
  protocol: /^(D?TLS|SSL)[\s_-]?v?\d/i,
  kem: /ML-?KEM|KYBER|FRODO-?KEM|(?<![A-Z0-9])BIKE(?![A-Z0-9])|(?<![A-Z0-9])HQC(?![A-Z0-9])|MCELIECE|(?<![A-Z0-9])(X25519|X448|ECDHE?|DHE?|EDH|FFDHE\d*|DIFFIE)(?![A-Z])/i,
  signature: /ML-?DSA|SLH-?DSA|DILITHIUM|FALCON|FN-?DSA|SPHINCS|(?<![A-Z0-9])(ECDSA|EDDSA|ED25519|ED448|RSASSA|RSA-?PSS)(?![A-Z])|(?<![A-Z0-9-])DSA(?![A-Z])|WITH-?(RSA|ECDSA|DSA|ED25519)|(?<![A-Z0-9])[REP]S(256|384|512)(?![A-Z0-9])/i,
  publicKey: /(?<![A-Z0-9])(RSA|ECC|EC-?KEY|ECPUBLICKEY|EL-?GAMAL)|SECP\d+[RK]1|PRIME256V1|BRAINPOOL|(?<![A-Z0-9])P-?(256|384|521)(?!\d)/i,
  symmetric: /(?<![A-Z0-9])(AES|CHACHA20|3DES|DES|DES-?EDE3?|RC4|ARC4|RC2|BLOWFISH|CAMELLIA|TWOFISH|IDEA|SEED)/i,
  hash: /SHA-?\d|SHA3|SHAKE|(?<![A-Z0-9])MD5(?!\d)|BLAKE2/i,
  kdf: /HMAC|HKDF|PBKDF2|BCRYPT|SCRYPT|ARGON2|POLY1305/i,
}

/**
 * The cryptographic job an algorithm string does. RSA and bare elliptic
 * curves are used for BOTH key establishment and signatures, so they stay
 * `public-key` (role unconfirmed) unless the evidence is a certificate.
 */
export function algorithmRole(algorithm: string, asCertificate = false): AlgorithmRole {
  const value = algorithm.trim()
  if (!value) return 'unknown'
  if (ROLE_PATTERNS.cipherSuite.test(value)) return 'cipher-suite'
  if (ROLE_PATTERNS.protocol.test(value)) return 'protocol'
  if (ROLE_PATTERNS.signature.test(value)) return 'signature'
  if (ROLE_PATTERNS.kem.test(value)) return 'key-establishment'
  if (ROLE_PATTERNS.publicKey.test(value)) return asCertificate ? 'signature' : 'public-key'
  if (ROLE_PATTERNS.kdf.test(value)) return 'kdf'
  if (ROLE_PATTERNS.symmetric.test(value)) return 'symmetric'
  if (ROLE_PATTERNS.hash.test(value)) return 'hash'
  return 'unknown'
}

interface AlgorithmRule {
  id: string
  subject: string
  verdict: PolicyVerdict
  /** The status a match assigns; transport-only rules carry null. */
  status: 'unsupported' | 'deprecated' | null
  test: (algorithm: string, keySize: number) => boolean
  rationale: string
  standard: string
}

const isRsa = (a: string) => /(?<![A-Z0-9])RSA|WITH-?RSA/i.test(a)

/**
 * The platform mandatory PQC stack as ONE ordered rule list. The algorithm
 * status and the policy evaluation both read it, so "Deprecated" in the
 * matrix and "WARN" in the policy panel can never disagree. Aligned with the
 * deprecated list in `.claude/skills/_shared/pqc-standards.md`.
 */
const ALGORITHM_RULES: readonly AlgorithmRule[] = [
  { id: 'pol-broken-hash', subject: 'SHA-1 / MD5', verdict: 'block', status: 'unsupported', test: (a) => /MD5(?!\d)|SHA-?1(?!\d)/i.test(a), rationale: 'Collision-broken hashes must not appear in any signing or integrity path.', standard: 'FIPS 202 / SP 800-131A' },
  { id: 'pol-legacy-cipher', subject: 'RC4 / RC2 / DES / 3DES / NULL / EXPORT ciphers', verdict: 'block', status: 'unsupported', test: (a) => tok('RC4|ARC4|ARCFOUR|RC2|3DES|DES|DES-?EDE3?|DES-?CBC3?|TRIPLE-?DES|TDEA|NULL|ENULL|ANULL|EXPORT\\d*').test(a), rationale: 'Broken or export-grade ciphers provide no meaningful confidentiality today, let alone against a quantum adversary.', standard: 'SP 800-131A / RFC 7465' },
  { id: 'pol-rsa-weak', subject: 'RSA / DSA below 2048 bits', verdict: 'block', status: 'unsupported', test: (a, k) => /(RSA|DSA)[-_ ]?(512|768|1024)(?!\d)/i.test(a) || (isRsa(a) && k > 0 && k < 2048), rationale: 'Below the 112-bit classical floor; already non-compliant before any quantum threat.', standard: 'NIST SP 800-131A' },
  { id: 'pol-tls-legacy', subject: 'TLS 1.0 / 1.1 / SSL', verdict: 'block', status: 'unsupported', test: (a) => LEGACY_TRANSPORT_RE.test(a), rationale: 'Formally deprecated by RFC 8996; cannot carry modern or hybrid cryptography and must be disabled.', standard: 'RFC 8996' },
  { id: 'pol-tls12', subject: 'TLS 1.2', verdict: 'warn', status: 'deprecated', test: (a) => tok('TLS[\\s_-]?V?1[._]?2').test(a), rationale: 'Cannot negotiate hybrid PQC named groups; blocks protocol agility.', standard: 'RFC 8446' },
  { id: 'pol-aes128', subject: 'AES-128', verdict: 'warn', status: 'deprecated', test: (a) => /AES[-_ ]?128(?!\d)/i.test(a), rationale: 'Grover halves symmetric strength; 128-bit keys fall below the post-quantum margin.', standard: 'FIPS 197' },
  { id: 'pol-rsa', subject: 'RSA (2048-bit and above)', verdict: 'warn', status: 'deprecated', test: (a) => isRsa(a) || /(?<![A-Z0-9])[RP]S(256|384|512)(?![A-Z0-9])/i.test(a), rationale: 'Broken by Shor; deprecated after 2030 and disallowed after 2035 under NIST IR 8547. Plan the ML-KEM (key establishment) or ML-DSA (signature) replacement.', standard: 'NIST IR 8547' },
  { id: 'pol-classical-pk', subject: 'ECDSA / ECDH / DH / DSA / EdDSA / X25519 (standalone)', verdict: 'warn', status: 'deprecated', test: (a) => /(?<![A-Z0-9])(ECDSA|ECDHE?|ECC|EDDSA|ED25519|ED448|X25519|X448|DHE?|EDH|FFDHE\d*|EL-?GAMAL)(?![A-Z])|(?<![A-Z0-9-])DSA(?![A-Z])|WITH-?(ECDSA|DSA)|DIFFIE|SECP\d+[RK]1|PRIME256V1|BRAINPOOL|(?<![A-Z0-9])P-?(256|384|521)(?!\d)|(?<![A-Z0-9])ES(256|384|512)(?![A-Z0-9])|EC-?KEY|ECPUBLICKEY/i.test(a), rationale: 'Quantum-vulnerable (Shor). Acceptable only as the classical half of an approved hybrid (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65).', standard: 'NIST IR 8547 / CNSA 2.0' },
  { id: 'pol-legacy-block-cipher', subject: 'Blowfish / IDEA / 64-bit block ciphers', verdict: 'warn', status: 'deprecated', test: (a) => tok('BLOWFISH|BF-CBC|IDEA|CAST5').test(a), rationale: '64-bit block ciphers are exposed to birthday-bound attacks (Sweet32); replace with AES-256-GCM.', standard: 'SP 800-131A' },
] as const

const LEGACY_TRANSPORT_RE = /(?<![A-Z0-9])(SSL|TLS)[\s_-]?v?1[._]?[01](?![\d.])|(?<![A-Z0-9])SSL[\s_-]?v?[23](?!\d)|^TLSv?1$|^SSLv?\d/i

/** Approved, standardised post-quantum primitives (and hybrids that contain one). */
const APPROVED_PQC_RE = /ML-?KEM|ML-?DSA|SLH-?DSA/i
/** Post-quantum candidates and pre-standard names — not a FIPS 203/204/205 parameter set. */
const CANDIDATE_PQC_RE = /KYBER|DILITHIUM|FALCON|FN-?DSA|SPHINCS|FRODO|(?<![A-Z0-9])BIKE(?![A-Z0-9])|(?<![A-Z0-9])HQC(?![A-Z0-9])|MCELIECE/i
/** Approved classical baselines (FIPS 197 / 202, RFC 8446). */
const APPROVED_CLASSICAL: ReadonlyArray<[RegExp, string]> = [
  [/AES[-_ ]?256[-_ ]?GCM/i, 'AES-256-GCM is the approved symmetric baseline (FIPS 197 / SP 800-38D).'],
  [/CHACHA20[-_ ]?POLY1305/i, 'ChaCha20-Poly1305 is an approved AEAD.'],
  [/SHA3-?(256|384|512)(?!\d)|SHAKE(128|256)/i, 'SHA-3 / SHAKE are the approved hash functions (FIPS 202).'],
  [/(?<![A-Z0-9])TLS[\s_-]?v?1[._]?3(?!\d)/i, 'TLS 1.3 is the required transport baseline for hybrid key exchange.'],
  [/HKDF[-_ ]?SHA3/i, 'HKDF-SHA3-256 is the approved KDF.'],
]
/** Primitives with no policy verdict (neither approved nor deprecated). */
const NEUTRAL_FAMILY_RE = /SHA-?(224|256|384|512)(?!\d)|SHA3|HMAC|HKDF|PBKDF2|BCRYPT|SCRYPT|ARGON2|(?<![A-Z0-9])AES|CAMELLIA|POLY1305|CHACHA20|GOST|BLAKE2|TWOFISH|SEED/i

export interface AlgorithmVerdict {
  status: AlgorithmStatus
  role: AlgorithmRole
  /** The ALGORITHM_RULES entry that decided an unsupported / deprecated status. */
  ruleId: string | null
  reason: string
}

/**
 * THE algorithm status decision. `observedInOperation` is the evidence the
 * engine holds that the algorithm runs (scan of a live endpoint, served
 * certificate, runtime telemetry). An approved-list algorithm without it is
 * `configured`, never `approved` — a string in a config file proves nothing
 * about what is deployed.
 */
export function classifyAlgorithmStatus(
  algorithm: string,
  context: { minKeySize?: number; asCertificate?: boolean; observedInOperation: boolean },
): AlgorithmVerdict {
  const value = algorithm.trim()
  const role = algorithmRole(value, Boolean(context.asCertificate))
  if (!value || !isCryptographicPrimitive(value)) {
    return { status: 'unknown', role, ruleId: null, reason: 'The recorded value is not a recognisable cryptographic primitive.' }
  }
  // A key-encapsulation mechanism cannot sign: a certificate "signed with
  // ML-KEM" is an inconsistent record, not evidence of a PQC certificate.
  if (context.asCertificate && /ML-?KEM|KYBER/i.test(value) && !/ML-?DSA|SLH-?DSA/i.test(value)) {
    return { status: 'unknown', role: 'unknown', ruleId: null, reason: 'Recorded as a certificate algorithm, but ML-KEM is a key-encapsulation mechanism (FIPS 203) and cannot sign a certificate — the record is inconsistent.' }
  }
  const keySize = context.minKeySize ?? 0
  for (const rule of ALGORITHM_RULES) {
    if (rule.status === 'unsupported' && rule.test(value, keySize)) {
      return { status: 'unsupported', role, ruleId: rule.id, reason: `${rule.subject}: ${rule.rationale}` }
    }
  }
  if (APPROVED_PQC_RE.test(value)) {
    return context.observedInOperation
      ? { status: 'approved', role, ruleId: null, reason: 'Standardised post-quantum primitive (FIPS 203/204/205) observed in operation.' }
      : { status: 'configured', role, ruleId: null, reason: 'Standardised post-quantum primitive, but evidenced only in source code or configuration — not yet observed in operation.' }
  }
  if (CANDIDATE_PQC_RE.test(value)) {
    return { status: 'detected', role, ruleId: null, reason: 'Post-quantum candidate or pre-standard name — not a FIPS 203/204/205 parameter set. Confirm the deployed algorithm before counting it as approved.' }
  }
  for (const rule of ALGORITHM_RULES) {
    if (rule.status === 'deprecated' && rule.test(value, keySize)) {
      return { status: 'deprecated', role, ruleId: rule.id, reason: `${rule.subject}: ${rule.rationale}` }
    }
  }
  for (const [pattern, why] of APPROVED_CLASSICAL) {
    if (pattern.test(value)) {
      return context.observedInOperation
        ? { status: 'approved', role, ruleId: null, reason: `${why} Observed in operation.` }
        : { status: 'configured', role, ruleId: null, reason: `${why} Evidenced only in source code or configuration.` }
    }
  }
  if (NEUTRAL_FAMILY_RE.test(value)) {
    return { status: 'detected', role, ruleId: null, reason: 'Recognised primitive with no approved or deprecated verdict in the platform policy.' }
  }
  return { status: 'unknown', role, ruleId: null, reason: 'The algorithm family could not be determined from the recorded value.' }
}

/** Approved destination for an algorithm in its role ("no transition" for approved-list algorithms). */
export function approvedTargetFor(role: AlgorithmRole, status: AlgorithmStatus): { target: string; standard: string } {
  if (status === 'approved') return { target: 'No transition required', standard: '—' }
  if (status === 'configured') return { target: 'No transition — confirm it in operation', standard: '—' }
  if (status === 'detected') {
    const mapped = APPROVED_TARGET_BY_ROLE[role]
    return mapped ? { target: `Optional: ${mapped.target}`, standard: mapped.standard } : { target: 'No policy target', standard: '—' }
  }
  const mapped = APPROVED_TARGET_BY_ROLE[role]
  return mapped ?? { target: 'Determine the role, then map to ML-KEM-768 or ML-DSA-65', standard: 'FIPS 203 / FIPS 204' }
}

/* ================================================================== */
/* Coupling analysis                                                   */
/* ================================================================== */

interface CouplingContext {
  assetsById: Map<string, AssetMigrationRecord>
  inventoryByAsset: Map<string, Row[]>
  exposuresByAsset: Map<string, Row[]>
  certificatesByAsset: Map<string, Row[]>
  keyRotationAssetIds: Set<string>
  providerLockedAssets: Map<string, string>
}

/**
 * A cryptographic component is "code-located" when its evidence carries a
 * source-code position (file/path/line). That is the platform's real signal for
 * cryptography embedded in application code rather than configuration.
 */
function codeLocationOf(metadata: Record<string, unknown>): string {
  const candidates = [
    metadata.file,
    metadata.filePath,
    metadata.file_path,
    metadata.path,
    metadata.sourceFile,
    metadata.source_file,
    metadata.location,
  ]
  for (const candidate of candidates) {
    const value = str(candidate)
    if (!value) continue
    // A URL/host is an observation target, not a source-code position.
    if (/^https?:\/\//i.test(value)) continue
    if (/[\\/].+\.(ts|tsx|js|jsx|py|java|go|rb|cs|cpp|c|h|php|rs|kt|swift|scala|m|mm|sh|yaml|yml|json|xml|properties|conf|cfg|ini|env|tf|gradle|pom)$/i.test(value)) return value
    if (/[\\/]/.test(value) && !/\s/.test(value)) return value
  }
  const line = num(metadata.line || metadata.lineNumber || metadata.line_number)
  if (line > 0) {
    const near = str(metadata.snippet || metadata.context)
    if (near) return `line ${line}`
  }
  return ''
}

function hardcodedSignal(text: string): boolean {
  return /hard.?cod|embedded|inline|literal|static\s+(key|cert|algorithm|cipher)|pinned/i.test(text)
}

function buildCouplingFindings(inputs: AgilityInputs, ctx: CouplingContext): CouplingFinding[] {
  const findings: CouplingFinding[] = []
  const seen = new Set<string>()

  const push = (finding: CouplingFinding) => {
    const key = `${finding.type}|${finding.assetId}|${finding.evidence}`.toLowerCase()
    if (seen.has(key)) return
    seen.add(key)
    findings.push(finding)
  }

  const assetMeta = (assetId: string) => {
    const asset = ctx.assetsById.get(assetId)
    return {
      asset: asset?.name || EVIDENCE_UNAVAILABLE,
      environment: asset?.environment || 'unknown',
      owner: asset?.owner || 'Unassigned',
      dependencies: asset?.blastRadius ?? 0,
      record: asset,
    }
  }

  /* ---- 1. Cryptography embedded in application code ---------------- */
  for (const item of inputs.cryptoInventory) {
    const assetId = str(item.asset_id)
    if (!assetId) continue
    const metadata = recordOf(item.metadata)
    const location = codeLocationOf(metadata)
    const itemType = str(item.item_type).toLowerCase()
    const algorithm = str(item.algorithm) || str(item.name)
    const meta = assetMeta(assetId)
    const klass = classifyAlgorithm(algorithm)

    if (location && algorithm) {
      const isConfigFile = /\.(ya?ml|json|xml|properties|conf|cfg|ini|env|tf|toml)$/i.test(location)
      const type = isConfigFile ? 'embedded-crypto-config' : 'hardcoded-algorithm'
      push({
        id: `coupling-inv-${str(item.id)}`,
        type,
        title: isConfigFile
          ? `Cryptographic configuration embedded in ${location.split(/[\\/]/).pop()}`
          : `Hard-coded ${algorithm} in application source`,
        severity: klass === 'vulnerable' ? 'high' : isConfigFile ? 'low' : 'medium',
        assetId,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: `${algorithm} @ ${location}`,
        evidenceSource: 'CBOM (crypto_inventory)',
        dependencyCount: meta.dependencies,
        agilityImpact: isConfigFile ? 35 : klass === 'vulnerable' ? 85 : 65,
        agilityImpactLabel: isConfigFile ? 'Config change required' : 'Code change required',
        remediation: isConfigFile
          ? 'Externalise the cryptographic settings into the managed crypto-policy layer so algorithm changes ship without a redeploy.'
          : 'Replace the literal algorithm reference with a policy-driven crypto provider interface so the primitive becomes a configuration value.',
        controlDomain: 'customer',
        domain: isConfigFile ? 'infrastructure' : 'application',
        route: `/dashboard/assets?asset=${encodeURIComponent(assetId)}`,
      })
    }

    if (num(item.key_size) > 0 && location && !isConfigLike(location)) {
      push({
        id: `coupling-keysize-${str(item.id)}`,
        type: 'hardcoded-key-size',
        title: `Fixed ${num(item.key_size)}-bit key size bound to source`,
        severity: 'medium',
        assetId,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: `${algorithm} ${num(item.key_size)}-bit @ ${location}`,
        evidenceSource: 'CBOM (crypto_inventory)',
        dependencyCount: meta.dependencies,
        agilityImpact: 55,
        agilityImpactLabel: 'Code change required',
        remediation: 'Parameterise key sizes through the crypto policy so PQC parameter sets can be adopted without editing code.',
        controlDomain: 'customer',
        domain: 'key',
        route: `/dashboard/assets?asset=${encodeURIComponent(assetId)}`,
      })
    }

    if (itemType === 'certificate' && location) {
      push({
        id: `coupling-embcert-${str(item.id)}`,
        type: 'embedded-certificate',
        title: 'Certificate embedded in the application artefact',
        severity: 'high',
        assetId,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: `${str(item.name) || 'certificate'} @ ${location}`,
        evidenceSource: 'CBOM (crypto_inventory)',
        dependencyCount: meta.dependencies,
        agilityImpact: 80,
        agilityImpactLabel: 'Rebuild + redeploy required',
        remediation: 'Move the certificate into the managed trust store / secret manager so re-issuance does not require rebuilding the artefact.',
        controlDomain: 'customer',
        domain: 'certificate',
        route: '/dashboard/pki-visibility',
      })
    }

    if (itemType === 'key' && location) {
      push({
        id: `coupling-embkey-${str(item.id)}`,
        type: 'embedded-public-key',
        title: 'Public key material pinned in the application artefact',
        severity: 'high',
        assetId,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: `${str(item.name) || 'key'} @ ${location}`,
        evidenceSource: 'CBOM (crypto_inventory)',
        dependencyCount: meta.dependencies,
        agilityImpact: 78,
        agilityImpactLabel: 'Rebuild + redeploy required',
        remediation: 'Resolve keys at runtime from QKMS/KMS instead of pinning them in the build, so rotation is an operational action.',
        controlDomain: 'customer',
        domain: 'key',
        route: '/dashboard/qkms',
      })
    }

    if (itemType === 'library') {
      const name = `${str(item.name)} ${algorithm}`.toLowerCase()
      const deprecated = DEPRECATED_LIBRARY_MARKERS.some((marker) => name.includes(marker))
      if (deprecated || (item.is_vulnerable === true && klass === 'vulnerable')) {
        push({
          id: `coupling-lib-${str(item.id)}`,
          type: 'legacy-crypto-provider',
          title: `Legacy cryptographic provider: ${str(item.name) || algorithm}`,
          severity: deprecated ? 'high' : 'medium',
          assetId,
          asset: meta.asset,
          environment: meta.environment,
          owner: meta.owner,
          evidence: `${str(item.name) || algorithm}${location ? ` @ ${location}` : ''}`,
          evidenceSource: 'CBOM (crypto_inventory)',
          dependencyCount: meta.dependencies,
          agilityImpact: 70,
          agilityImpactLabel: 'Library upgrade required',
          remediation: 'Upgrade to a provider exposing ML-KEM / ML-DSA (OpenSSL 3.x + oqsprovider or an equivalent PQC-capable stack).',
          controlDomain: 'customer',
          domain: 'library',
          route: '/dashboard/cbom_explorer',
        })
      }
    }

    const pinnedSuite = str(metadata.cipherSuite || metadata.cipher_suite || metadata.ciphers)
    if (pinnedSuite && location) {
      push({
        id: `coupling-suite-${str(item.id)}`,
        type: 'hardcoded-cipher-suite',
        title: 'Cipher suite list pinned in the application',
        severity: 'medium',
        assetId,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: `${pinnedSuite} @ ${location}`,
        evidenceSource: 'CBOM (crypto_inventory)',
        dependencyCount: meta.dependencies,
        agilityImpact: 60,
        agilityImpactLabel: 'Code change required',
        remediation: 'Drive cipher-suite and named-group selection from the TLS policy so hybrid groups can be enabled centrally.',
        controlDomain: 'customer',
        domain: 'protocol',
        route: '/dashboard/protocol-analytics',
      })
    }
  }

  /* ---- 2. Exposures explicitly recorded as coupling ---------------- */
  for (const exposure of inputs.cryptoExposures) {
    const assetId = str(exposure.asset_id)
    if (!assetId) continue
    const type = str(exposure.exposure_type).toLowerCase()
    const detected = str(exposure.detected_value)
    const description = str(exposure.description)
    const meta = assetMeta(assetId)
    const severity = normalizeSeverity(str(exposure.severity))
    const haystack = `${type} ${description} ${detected}`

    if (type.includes('deprecated_lib') || type.includes('deprecated-lib')) {
      push({
        id: `coupling-exp-lib-${str(exposure.id)}`,
        type: 'legacy-crypto-provider',
        title: 'Deprecated cryptographic library in use',
        severity,
        assetId,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: detected || description || type,
        evidenceSource: 'Crypto Exposures',
        dependencyCount: meta.dependencies,
        agilityImpact: 72,
        agilityImpactLabel: 'Library upgrade required',
        remediation: 'Replace the deprecated provider with a maintained PQC-capable library before scheduling the algorithm swap.',
        controlDomain: 'customer',
        domain: 'library',
        route: '/dashboard/cbom_explorer',
      })
      continue
    }

    if (type.includes('insecure_key_mgmt') || type.includes('key_mgmt') || /manual.*key|key.*manual/i.test(haystack)) {
      push({
        id: `coupling-exp-key-${str(exposure.id)}`,
        type: 'manual-key-management',
        title: 'Manually managed key material',
        severity,
        assetId,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: detected || description || type,
        evidenceSource: 'Crypto Exposures',
        dependencyCount: meta.dependencies,
        agilityImpact: 68,
        agilityImpactLabel: 'Manual operation required',
        remediation: 'Bring the key under QKMS custody with an automated rotation policy so PQC key material can be issued on demand.',
        controlDomain: 'customer',
        domain: 'key',
        route: '/dashboard/qkms',
      })
      continue
    }

    // Only exposures that genuinely describe certificate COUPLING qualify. A
    // broad `includes('cert')` swept in observations like "No Certificate
    // Pinning" and reported them as embedded certificates — a coupling claim
    // the evidence does not support.
    if (/exposed_cert|embedded_cert|hardcoded_cert|cert_path|pinned_cert|cert_dependency/.test(type)) {
      push({
        id: `coupling-exp-cert-${str(exposure.id)}`,
        type: 'embedded-certificate',
        title: 'Certificate dependency recorded against this asset',
        severity,
        assetId,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: detected || description || type,
        evidenceSource: 'Crypto Exposures',
        dependencyCount: meta.dependencies,
        agilityImpact: 65,
        agilityImpactLabel: 'Certificate re-issuance required',
        remediation: 'Automate issuance for this certificate so the chain can be re-issued under ML-DSA without a manual change window.',
        controlDomain: 'customer',
        domain: 'certificate',
        route: '/dashboard/pki-visibility',
      })
      continue
    }

    if (hardcodedSignal(haystack)) {
      push({
        id: `coupling-exp-hard-${str(exposure.id)}`,
        type: 'hardcoded-algorithm',
        title: 'Hard-coded cryptography reported by discovery',
        severity,
        assetId,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: detected || description || type,
        evidenceSource: 'Crypto Exposures',
        dependencyCount: meta.dependencies,
        agilityImpact: 82,
        agilityImpactLabel: 'Code change required',
        remediation: 'Externalise the cryptographic choice behind the platform crypto-policy interface.',
        controlDomain: 'customer',
        domain: 'application',
        route: `/dashboard/assets?asset=${encodeURIComponent(assetId)}`,
      })
    }
  }

  /* ---- 3. Static / self-signed trust anchors ----------------------- */
  for (const cert of inputs.certificates) {
    const assetId = str(cert.asset_id)
    const issuer = str(cert.issuer)
    const subject = str(cert.name) || str(cert.subject)
    if (!issuer) continue
    const meta = assetId ? assetMeta(assetId) : { asset: subject || EVIDENCE_UNAVAILABLE, environment: 'unknown', owner: 'Unassigned', dependencies: 0, record: undefined }
    const selfSigned = Boolean(subject) && issuer.trim().toLowerCase() === subject.trim().toLowerCase()
    const internal = /self|internal|private|corp\b|\bca\b root/i.test(issuer)

    if (selfSigned || internal) {
      push({
        id: `coupling-anchor-${str(cert.id)}`,
        type: 'static-trust-anchor',
        title: selfSigned ? 'Self-signed trust anchor' : 'Privately operated trust anchor',
        severity: selfSigned ? 'high' : 'medium',
        assetId: assetId || `cert:${str(cert.id)}`,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: `${subject || 'certificate'} issued by ${issuer}`,
        evidenceSource: 'Certificate Inventory',
        dependencyCount: meta.dependencies,
        agilityImpact: selfSigned ? 75 : 55,
        agilityImpactLabel: 'Trust distribution required',
        remediation: 'Every relying party must trust the replacement anchor before the chain can move to ML-DSA — stage anchor distribution ahead of re-issuance.',
        controlDomain: 'customer',
        domain: 'trust',
        route: '/dashboard/trust-chain-analyzer',
      })
    }

    const managed = MANAGED_ISSUER_MARKERS.some((marker) => issuer.toLowerCase().includes(marker))
    if (!managed && cert.is_quantum_safe !== true) {
      push({
        id: `coupling-manualcert-${str(cert.id)}`,
        type: 'manual-certificate-management',
        title: 'Certificate has no automated issuance evidence',
        severity: 'medium',
        assetId: assetId || `cert:${str(cert.id)}`,
        asset: meta.asset,
        environment: meta.environment,
        owner: meta.owner,
        evidence: `${subject || 'certificate'} · issuer ${issuer}`,
        evidenceSource: 'Certificate Inventory',
        dependencyCount: meta.dependencies,
        agilityImpact: 50,
        agilityImpactLabel: 'Manual operation required',
        remediation: 'Automate issuance (ACME or managed CA) so hybrid certificates can be rolled out without manual change windows.',
        controlDomain: 'customer',
        domain: 'certificate',
        route: '/dashboard/pki-visibility',
      })
    }
  }

  /* ---- 4. Vendor-locked cryptography (shared responsibility) ------- */
  const sr = inputs.snapshot.sharedResponsibility
  if (sr) {
    for (const finding of sr.findings) {
      if (finding.domain === 'customer') continue
      if (finding.customerActionable === 'yes') continue
      const assetId = findByAssetName(ctx.assetsById, finding.asset)
      const meta = assetId ? assetMeta(assetId) : { asset: finding.asset, environment: 'unknown', owner: finding.responsibleParty, dependencies: 0, record: undefined }
      push({
        id: `coupling-vendor-${finding.id}`,
        type: 'vendor-locked-crypto',
        title: `${finding.responsibleParty} controls this cryptography`,
        severity: normalizeSeverity(finding.severity),
        assetId: assetId || `sr:${finding.id}`,
        asset: meta.asset,
        environment: meta.environment,
        owner: finding.responsibleParty,
        evidence: `${finding.algorithm || finding.title} · ${finding.attribution.reason}`,
        evidenceSource: 'Shared Responsibility Engine',
        dependencyCount: finding.dependencyChain.nodes.length,
        agilityImpact: finding.customerActionable === 'no' ? 90 : 60,
        agilityImpactLabel: finding.customerActionable === 'no' ? 'Vendor dependency' : 'Partial customer control',
        remediation: finding.actionability.recommendedAction,
        controlDomain: finding.domain,
        domain: finding.domain === 'ecosystem' ? 'trust' : 'vendor',
        route: '/dashboard/vendor-pqc-readiness',
      })
    }
  }

  /* ---- 5. Undocumented dependencies (no accountable owner) --------- */
  for (const asset of inputs.assets) {
    if (!asset.hasEvidence) continue
    if (asset.blastRadius === 0) continue
    if (asset.owner && !/unassigned|unknown/i.test(asset.owner)) continue
    push({
      id: `coupling-owner-${asset.id}`,
      type: 'undocumented-dependency',
      title: 'Cryptographic dependency with no accountable owner',
      severity: asset.blastRadius > 4 ? 'high' : 'medium',
      assetId: asset.id,
      asset: asset.name,
      environment: asset.environment,
      owner: 'Unassigned',
      evidence: `${asset.blastRadius} trust relationship(s), owner not recorded`,
      evidenceSource: 'Trust Fabric + Asset Inventory',
      dependencyCount: asset.blastRadius,
      agilityImpact: 45,
      agilityImpactLabel: 'Approval path undefined',
      remediation: 'Assign an accountable service owner so the change can be approved and executed.',
      controlDomain: 'customer',
      domain: 'application',
      route: `/dashboard/assets?asset=${encodeURIComponent(asset.id)}`,
    })
  }

  return findings.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.agilityImpact - a.agilityImpact || b.dependencyCount - a.dependencyCount,
  )
}

/**
 * Assets whose evidence set COULD reveal cryptographic coupling.
 *
 * Requires at least one of: a component carrying a source/config location, an
 * inventoried crypto library, or runtime telemetry. An edge-only scan yields
 * none of these, so its silence about coupling proves nothing.
 */
function observableCouplingAssets(inputs: AgilityInputs): Set<string> {
  const ids = new Set<string>()
  for (const item of inputs.cryptoInventory) {
    const assetId = str(item.asset_id)
    if (!assetId) continue
    if (str(item.item_type).toLowerCase() === 'library' || codeLocationOf(recordOf(item.metadata))) ids.add(assetId)
  }
  for (const exposure of inputs.cryptoExposures) {
    const assetId = str(exposure.asset_id)
    if (!assetId) continue
    const haystack = `${str(exposure.exposure_type)} ${str(exposure.description)} ${str(exposure.detected_value)}`
    if (hardcodedSignal(haystack) || /deprecated_lib|insecure_key_mgmt/.test(str(exposure.exposure_type).toLowerCase())) ids.add(assetId)
  }
  for (const event of inputs.runtimeEvents) {
    const assetId = str(event.asset_id)
    if (assetId) ids.add(assetId)
  }
  return ids
}

function isConfigLike(location: string): boolean {
  return /\.(ya?ml|json|xml|properties|conf|cfg|ini|env|tf|toml)$/i.test(location)
}

function findByAssetName(assetsById: Map<string, AssetMigrationRecord>, name: string): string | null {
  if (!name) return null
  const needle = name.trim().toLowerCase()
  for (const [id, asset] of assetsById) {
    if (asset.name.trim().toLowerCase() === needle) return id
    if (asset.hostname && asset.hostname.trim().toLowerCase() === needle) return id
  }
  return null
}

/* ================================================================== */
/* Per-asset replaceability + agility state                            */
/* ================================================================== */

interface AssetAgilityDerivation {
  state: AgilityState
  score: number | null
  replaceability: ReplaceabilityClass
  readiness: MigrationReadinessState
  blockerReasons: string[]
  couplingFindings: CouplingFinding[]
  controlDomain: ControlDomain
  /** false ⇒ the evidence set could not have revealed coupling even if it exists. */
  couplingObservable: boolean
  basis: string
  /** Every point that moved the score, in order — the number is fully traceable. */
  scoreFactors: Array<{ label: string; points: number; basis: string }>
  operationalJob: OperationalJob | null
  validated: boolean
}

/**
 * Transport/protocol versions observed for an asset.
 *
 * Scanners record protocol versions in two places: `tlsConfiguration.protocols`
 * (runtime telemetry) and, for edge scans, as entries in the algorithm list
 * ("TLSv1.1"). Reading only the former made a tenant with deprecated TLS in its
 * CBOM report "0 endpoints expose deprecated versions".
 */
function protocolVersionsFor(asset: AssetMigrationRecord): string[] {
  const versions = new Set<string>(asset.tlsConfiguration.protocols)
  for (const algo of asset.algorithms) {
    if (/^(TLS|SSL)\s?v?\d/i.test(algo.algorithm.trim())) versions.add(algo.algorithm.trim())
  }
  return [...versions].sort()
}

/** One legacy-transport rule for every reader (status, policy, blockers, preview). */
const LEGACY_PROTOCOL_RE = LEGACY_TRANSPORT_RE

/** Base agility points per replaceability class — the starting point of every per-asset score. */
export const REPLACEABILITY_BASE_POINTS: Record<ReplaceabilityClass, number> = {
  configuration: 92,
  library: 72,
  code: 48,
  architecture: 28,
  vendor: 18,
  unknown: 0,
}

/**
 * THE per-asset agility verdict.
 *
 * Deliberately conservative: an asset only reads `agile` when its cryptography
 * is genuinely configuration-driven AND nothing upstream gates the change.
 * No evidence ⇒ `unknown` (never `agile`, never scored 0).
 *
 * `couplingObservable` guards the most dangerous inference on this page. Absence
 * of coupling findings is NOT proof of decoupling: an edge-scanned domain yields
 * transport and certificate evidence only, so nothing could have revealed
 * hard-coded cryptography inside the application even if it exists. Where
 * coupling could not be observed, the verdict is capped at Conditional and says
 * so, instead of reporting a confident "Agile".
 *
 * Migration state is read from OPERATIONAL jobs only (sandbox simulations are
 * excluded through the shared `isSimulationJob`), and a completed migration
 * earns credit only with a passing validation record.
 */
function deriveAssetAgility(
  asset: AssetMigrationRecord,
  couplingByAsset: Map<string, CouplingFinding[]>,
  providerLocked: Map<string, string>,
  couplingObservableAssets: Set<string>,
  latestJob: OperationalJob | null,
): AssetAgilityDerivation {
  const coupling = couplingByAsset.get(asset.id) || []
  const validated = isPassingValidation(asset.validation.lastStatus)

  if (!asset.hasEvidence) {
    return {
      state: 'unknown',
      score: null,
      replaceability: 'unknown',
      readiness: 'unknown',
      blockerReasons: ['No cryptographic evidence has been captured for this asset.'],
      couplingFindings: coupling,
      controlDomain: 'customer',
      couplingObservable: false,
      basis: `${EVIDENCE_UNAVAILABLE} — asset discovered but not cryptographically assessed.`,
      scoreFactors: [],
      operationalJob: latestJob,
      validated,
    }
  }

  const couplingObservable = couplingObservableAssets.has(asset.id) || asset.evidence.runtimeEvents > 0

  const blockerReasons: string[] = []

  /* --- Replaceability class: worst binding constraint wins --------- */
  const constraints: ReplaceabilityClass[] = ['configuration']
  const raise = (next: ReplaceabilityClass, reason: string) => {
    constraints.push(next)
    if (reason) blockerReasons.push(reason)
  }

  const vendorLock = providerLocked.get(asset.id)
  if (vendorLock) raise('vendor', `Cryptography is controlled by ${vendorLock}.`)

  for (const finding of coupling) {
    switch (finding.type) {
      case 'vendor-locked-crypto':
        raise('vendor', finding.title)
        break
      case 'static-trust-anchor':
        raise('architecture', 'Trust anchor must be redistributed before the chain can change.')
        break
      case 'hardcoded-algorithm':
      case 'hardcoded-cipher-suite':
      case 'hardcoded-key-size':
      case 'embedded-certificate':
      case 'embedded-public-key':
        raise('code', finding.title)
        break
      case 'legacy-crypto-provider':
        raise('library', finding.title)
        break
      case 'embedded-crypto-config':
      case 'manual-certificate-management':
      case 'manual-key-management':
      case 'hardcoded-certificate-path':
      case 'undocumented-dependency':
        // Operationally awkward but still configuration-level work.
        blockerReasons.push(finding.title)
        break
    }
  }

  // Deprecated transport forces at least a library/platform upgrade.
  const legacyProtocol = protocolVersionsFor(asset).some((p) => LEGACY_PROTOCOL_RE.test(p))
  if (legacyProtocol) raise('library', 'Deprecated TLS/SSL version observed — the stack must be upgraded before hybrid groups can negotiate.')

  // Broken primitives are never a pure config swap. Read through the shared
  // status rules: `\bRC4\b` never matched "TLS_RSA_WITH_RC4_128_SHA".
  const broken = asset.algorithms.filter((a) => {
    if (!isCryptographicPrimitive(a.algorithm) || algorithmRole(a.algorithm) === 'protocol') return false
    return classifyAlgorithmStatus(a.algorithm, { minKeySize: a.keySizes[0], observedInOperation: false }).status === 'unsupported'
  })
  if (broken.length) {
    raise('code', `Prohibited primitive (${broken.slice(0, 3).map((a) => a.algorithm).join(', ')}) detected — call sites must be updated, not reconfigured.`)
  }

  // A wide blast radius makes the change an architecture-coordination problem.
  if (asset.blastRadius > 8) {
    raise('architecture', `${asset.blastRadius} trust relationship(s) must negotiate the replacement stack simultaneously.`)
  }

  const compatibilityBlocked = asset.compatibility.score > 0 && asset.compatibility.score < 50
  if (compatibilityBlocked) blockerReasons.push('Compatibility risks must be cleared before cutover.')
  const jobFailed = latestJob !== null && (latestJob.status === 'failed' || latestJob.status === 'rolled_back')
  if (jobFailed) blockerReasons.push('The latest operational migration job for this asset failed and must be resolved.')

  const replaceability = constraints.reduce<ReplaceabilityClass>(
    (worst, candidate) => (REPLACEABILITY_RANK[candidate] > REPLACEABILITY_RANK[worst] ? candidate : worst),
    'configuration',
  )

  /* --- Score: traceable, factor by factor -------------------------- */
  const scoreFactors: AssetAgilityDerivation['scoreFactors'] = []
  let score = REPLACEABILITY_BASE_POINTS[replaceability]
  scoreFactors.push({ label: `Base: ${REPLACEABILITY_LABEL[replaceability]}`, points: score, basis: 'Starting points for the hardest binding constraint on this asset.' })
  const adjust = (points: number, label: string, basis: string) => {
    if (!points) return
    score += points
    scoreFactors.push({ label, points: Math.round(points * 10) / 10, basis })
  }
  const pqcSignedCerts = asset.certificates.filter((c) => PQC_SIGNATURE_RE.test(c.algorithm)).length
  if (asset.certificates.length && pqcSignedCerts === asset.certificates.length) {
    adjust(4, 'Every certificate carries an ML-DSA / SLH-DSA signature', `${pqcSignedCerts} certificate(s) — read from the certificate's own signature algorithm, not a quantum-safe flag.`)
  }
  const hybridKex = asset.tlsConfiguration.keyExchange.filter((k) => /ML-?KEM/i.test(k))
  if (hybridKex.length) adjust(6, 'Hybrid / ML-KEM key exchange observed at runtime', hybridKex.slice(0, 2).join(', '))
  if (asset.tlsConfiguration.protocols.some((p) => /1\.3/.test(p))) adjust(4, 'TLS 1.3 observed', 'Hybrid groups can be enabled without a protocol upgrade.')
  if (coupling.length) adjust(-Math.min(18, coupling.length * 4), `${coupling.length} coupling finding(s)`, '−4 per finding, capped at −18.')
  if (asset.blastRadius > 2) adjust(-Math.min(12, (asset.blastRadius - 2) * 1.5), `${asset.blastRadius} dependency relationship(s)`, '−1.5 per relationship beyond two, capped at −12.')
  if (jobFailed) adjust(-12, 'Latest operational migration failed', `${latestJob?.name || 'job'} — ${latestJob?.status}.`)
  if (latestJob?.status === 'completed') {
    if (validated) adjust(8, 'Completed and validated migration', 'A change has already been executed and passed validation on this asset.')
    else scoreFactors.push({ label: 'Completed migration — not validated', points: 0, basis: 'A completed job earns no credit until a passing validation record exists.' })
  }
  if (!asset.owner || /unassigned|unknown/i.test(asset.owner)) adjust(-5, 'No accountable owner', 'Nobody is recorded to approve or execute the change.')

  // Coupling could not be observed ⇒ the confident end of the scale is not
  // available. The cap is a disclosed rule, shown as its own factor.
  if (!couplingObservable) {
    blockerReasons.push(
      'Application-level cryptographic coupling has not been assessed for this asset — only transport/certificate evidence exists, so configuration-replaceability cannot be confirmed.',
    )
    if (score > 60) {
      scoreFactors.push({ label: 'Capped at 60: coupling not assessed', points: Math.round((60 - score) * 10) / 10, basis: 'Without source, library or runtime visibility the asset cannot claim end-to-end configuration replaceability.' })
      score = 60
    }
  }

  const finalScore = Math.round(clamp(score))

  /* --- State ------------------------------------------------------- */
  const hardBlocked = replaceability === 'vendor' || jobFailed || compatibilityBlocked

  let state: AgilityState
  if (hardBlocked) state = 'blocked'
  else if (replaceability === 'architecture' || replaceability === 'code') state = 'rigid'
  else if (!couplingObservable || replaceability === 'library' || coupling.length > 0 || blockerReasons.length > 0) state = 'conditional'
  else state = 'agile'

  /* --- Migration readiness ----------------------------------------- */
  let readiness: MigrationReadinessState
  if (state === 'blocked') readiness = 'blocked'
  else if (state === 'agile' && asset.compatibility.score >= 70) readiness = 'ready'
  else readiness = 'conditional'

  const controlDomain: ControlDomain = vendorLock ? 'provider' : coupling.some((c) => c.controlDomain === 'ecosystem') ? 'ecosystem' : 'customer'

  return {
    state,
    score: finalScore,
    replaceability,
    readiness,
    blockerReasons: unique(blockerReasons).slice(0, 6),
    couplingFindings: coupling,
    controlDomain,
    couplingObservable,
    basis: `${REPLACEABILITY_LABEL[replaceability]} · ${coupling.length} coupling finding(s) · ${asset.blastRadius} dependency relationship(s) · compatibility ${asset.compatibility.score}/100 · coupling ${couplingObservable ? 'assessed' : 'NOT assessed (no source, library or runtime visibility)'} · derived from ${asset.evidence.sources.join(', ') || 'asset evidence'}.`,
    scoreFactors,
    operationalJob: latestJob,
    validated,
  }
}

/* ================================================================== */
/* Domain scoring                                                      */
/* ================================================================== */

interface DomainComputation {
  score: number | null
  coverage: number
  blockers: number
  affectedAssets: number
  basis: string
  actions: string[]
  factors: ScoreFactor[]
}

type FactorInput = Omit<ScoreFactor, 'effectiveWeight' | 'measured'>

/**
 * A domain score as the weighted mean of its MEASURED factors. An unmeasured
 * factor (value null) is excluded and its weight redistributed over the
 * measured ones — it is never scored as 0 or as a stand-in constant. Returns a
 * null score when no factor is measured.
 */
function scoreFromFactors(inputs: FactorInput[]): { score: number | null; factors: ScoreFactor[] } {
  const measuredWeight = inputs.reduce((sum, f) => sum + (f.value === null ? 0 : f.weight), 0)
  const factors: ScoreFactor[] = inputs.map((f) => ({
    ...f,
    value: f.value === null ? null : Math.round(clamp(f.value)),
    measured: f.value !== null,
    effectiveWeight: f.value === null || measuredWeight <= 0 ? 0 : Math.round((f.weight / measuredWeight) * 1000) / 1000,
  }))
  if (measuredWeight <= 0) return { score: null, factors }
  const score = inputs.reduce((sum, f) => sum + (f.value === null ? 0 : clamp(f.value) * f.weight), 0) / measuredWeight
  return { score: Math.round(clamp(score)), factors }
}

function scoreDomains(
  inputs: AgilityInputs,
  assetRows: AgilityAssetRow[],
  derivations: Map<string, AssetAgilityDerivation>,
  coupling: CouplingFinding[],
): AgilityDomain[] {
  const evaluated = inputs.assets.filter((a) => a.hasEvidence)
  const total = inputs.assets.length
  const couplingByDomain = new Map<AgilityDomainKey, CouplingFinding[]>()
  for (const finding of coupling) {
    const list = couplingByDomain.get(finding.domain) || []
    list.push(finding)
    couplingByDomain.set(finding.domain, list)
  }

  const sr = inputs.snapshot.sharedResponsibility
  const now = inputs.now ?? Date.now()

  const compute: Record<AgilityDomainKey, () => DomainComputation> = {
    /* ---- Application ---------------------------------------------- */
    application: () => {
      if (!evaluated.length) return none('No asset carries cryptographic evidence yet.')
      // Only assets whose coupling COULD be observed may be scored. Counting an
      // edge-scanned asset as "config-driven" would score the absence of source
      // visibility as if it were proof of decoupling.
      const assessable = assetRows.filter((r) => r.hasEvidence && r.couplingAssessed)
      const unassessed = assetRows.filter((r) => r.hasEvidence && !r.couplingAssessed).length
      if (!assessable.length) {
        return none(
          `Coupling could not be assessed on any of the ${evaluated.length} evaluated asset(s) — none carries source, library or runtime visibility, so application-level replaceability is unmeasured.`,
        )
      }
      const rigid = assessable.filter((r) => r.replaceability === 'code' || r.replaceability === 'architecture')
      const findings = couplingByDomain.get('application') || []
      const configDriven = assessable.filter((r) => r.replaceability === 'configuration' || r.replaceability === 'library')
      const scored = scoreFromFactors([
        { key: 'config-driven', label: 'Coupling-assessed assets replaceable by configuration or a library upgrade', weight: 1, value: pctOf(configDriven.length, assessable.length), basis: `${configDriven.length} of ${assessable.length} coupling-assessed asset(s).` },
      ])
      return {
        score: scored.score,
        factors: scored.factors,
        // Coverage is the share of evaluated assets whose coupling is observable.
        coverage: pctOf(assessable.length, Math.max(1, evaluated.length)),
        blockers: rigid.length,
        affectedAssets: rigid.length + unassessed,
        basis: `${configDriven.length} of ${assessable.length} asset(s) with source, library or runtime visibility can change cryptography without code or architecture work; ${findings.length} application-coupling finding(s) recorded.${unassessed ? ` ${unassessed} further asset(s) have transport/certificate evidence only, so their application coupling is unmeasured and excluded.` : ''}`,
        actions: [
          rigid.length
            ? `Externalise cryptographic configuration on ${rigid.length} rigid application(s).`
            : 'Maintain the abstraction layer and re-scan after each release to detect newly embedded cryptography.',
          unassessed
            ? `Run a source or agent scan on ${unassessed} asset(s) currently assessed from the edge only — their application coupling is unknown, not absent.`
            : 'Introduce a crypto-provider abstraction so primitives stay policy values.',
        ],
      }
    },

    /* ---- Algorithm replaceability --------------------------------- */
    algorithm: () => {
      const algorithms = new Map<string, { instances: number; klass: AlgorithmClass }>()
      let rejected = 0
      for (const asset of evaluated) {
        for (const algo of asset.algorithms) {
          // Scanner finding titles share the `algorithm` field with real
          // primitives; scoring over them would fabricate cryptography.
          if (!isCryptographicPrimitive(algo.algorithm)) {
            rejected += 1
            continue
          }
          const entry = algorithms.get(algo.algorithm) || { instances: 0, klass: algo.classification }
          entry.instances += algo.instances
          algorithms.set(algo.algorithm, entry)
        }
      }
      if (!algorithms.size) {
        return none(
          rejected > 0
            ? `${rejected} recorded value(s) are scanner finding titles rather than cryptographic primitives, so no algorithm could be scored.`
            : 'No algorithm has been resolved from tenant evidence.',
        )
      }
      // Credit per instance, read through the SHARED status rules: approved-list
      // primitives count fully, transitional ones half, prohibited ones zero.
      let replaceable = 0
      let totalInstances = 0
      const isProhibited = (name: string) => algorithmRole(name) !== 'protocol' && classifyAlgorithmStatus(name, { observedInOperation: false }).status === 'unsupported'
      for (const [name, entry] of algorithms) {
        totalInstances += entry.instances
        const status = classifyAlgorithmStatus(name, { observedInOperation: false }).status
        if (status === 'configured' || status === 'approved' || entry.klass === 'pqc' || entry.klass === 'hybrid') replaceable += entry.instances
        else if (status !== 'unsupported') replaceable += entry.instances * 0.5
      }
      const broken = [...algorithms.keys()].filter(isProhibited)
      const scored = scoreFromFactors([
        { key: 'replaceable-instances', label: 'Instances on an approved or transitional primitive', weight: 1, value: pctOf(replaceable, totalInstances), basis: 'Approved-list (PQC, hybrid, AES-256-GCM, SHA-3, TLS 1.3) = 1, deprecated or unclassified = 0.5, prohibited = 0, per instance.' },
      ])
      return {
        score: scored.score,
        factors: scored.factors,
        coverage: pctOf(evaluated.length, total),
        blockers: broken.length,
        affectedAssets: evaluated.filter((a) => a.algorithms.some((x) => isCryptographicPrimitive(x.algorithm) && isProhibited(x.algorithm))).length,
        basis: `${algorithms.size} distinct cryptographic primitive(s) across ${totalInstances} instance(s); ${broken.length} prohibited primitive(s) require call-site changes rather than a swap.${rejected ? ` ${rejected} recorded value(s) were scanner finding titles and are excluded from algorithm scoring.` : ''}`,
        actions: broken.length
          ? [`Replace ${broken.join(', ')} — these cannot be swapped by configuration.`, 'Map every remaining classical primitive to its FIPS 203/204/205 target in the replaceability matrix.']
          : ['Adopt the hybrid ML-KEM-768 / ML-DSA-65 targets published in the replaceability matrix.'],
      }
    },

    /* ---- Protocol -------------------------------------------------- */
    protocol: () => {
      const withTransport = evaluated.filter((a) => protocolVersionsFor(a).length || a.tlsConfiguration.keyExchange.length)
      if (!withTransport.length) return none('No transport telemetry (TLS protocol / key exchange) has been observed.')
      const modern = withTransport.filter((a) => protocolVersionsFor(a).some((p) => /1\.3/.test(p)))
      const hybrid = withTransport.filter((a) =>
        a.tlsConfiguration.keyExchange.some((k) => classifyAlgorithm(k) === 'pqc' || classifyAlgorithm(k) === 'hybrid') ||
        a.algorithms.some((x) => isCryptographicPrimitive(x.algorithm) && (classifyAlgorithm(x.algorithm) === 'pqc' || classifyAlgorithm(x.algorithm) === 'hybrid')),
      )
      const legacy = withTransport.filter((a) => protocolVersionsFor(a).some((p) => LEGACY_PROTOCOL_RE.test(p)))
      const scored = scoreFromFactors([
        { key: 'tls13', label: 'Endpoints negotiating TLS 1.3', weight: 0.5, value: pctOf(modern.length, withTransport.length), basis: `${modern.length} of ${withTransport.length} endpoint(s) with transport telemetry.` },
        { key: 'hybrid-group', label: 'Endpoints negotiating a hybrid / ML-KEM group', weight: 0.3, value: pctOf(hybrid.length, withTransport.length), basis: `${hybrid.length} of ${withTransport.length} endpoint(s).` },
        { key: 'no-legacy-tls', label: 'Endpoints free of TLS 1.0 / 1.1 / SSL', weight: 0.2, value: 100 - pctOf(legacy.length, withTransport.length), basis: `${legacy.length} endpoint(s) still expose a deprecated version.` },
      ])
      return {
        score: scored.score,
        factors: scored.factors,
        coverage: pctOf(withTransport.length, Math.max(1, evaluated.length)),
        blockers: legacy.length,
        affectedAssets: withTransport.length - hybrid.length,
        basis: `${modern.length}/${withTransport.length} measured endpoint(s) negotiate TLS 1.3, ${hybrid.length} negotiate a hybrid/PQC group, ${legacy.length} still expose deprecated versions.`,
        actions: legacy.length
          ? [`Retire deprecated TLS on ${legacy.length} endpoint(s) — hybrid groups cannot negotiate below TLS 1.3.`, 'Enable X25519MLKEM768 in the TLS policy once TLS 1.3 is universal.']
          : ['Enable the X25519MLKEM768 named group across the remaining TLS 1.3 endpoints.'],
      }
    },

    /* ---- Certificate ----------------------------------------------- */
    certificate: () => {
      const certs = inputs.certificates
      if (!certs.length) return none('No certificate inventory is connected — certificate agility cannot be measured.')
      const managed = certs.filter((c) => MANAGED_ISSUER_MARKERS.some((m) => str(c.issuer).toLowerCase().includes(m)))
      const expiringSoon = certs.filter((c) => {
        const notAfter = isoOrNull(c.not_after)
        if (!notAfter) return false
        const days = (new Date(notAfter).getTime() - now) / 86400000
        return days <= 30
      })
      // PQC-signed is read from the certificate's OWN signature algorithm, not a
      // quantum-safe flag (an ML-KEM "signature" would be an inconsistent record).
      const pqcCapable = certs.filter((c) => PQC_SIGNATURE_RE.test(str(c.algorithm)))
      const scored = scoreFromFactors([
        { key: 'managed-issuance', label: 'Certificates with automated-issuance evidence', weight: 0.55, value: pctOf(managed.length, certs.length), basis: `${managed.length} of ${certs.length} issued by a managed / ACME issuer.` },
        { key: 'pqc-signed', label: 'Certificates signed with ML-DSA / SLH-DSA', weight: 0.25, value: pctOf(pqcCapable.length, certs.length), basis: `${pqcCapable.length} of ${certs.length}.` },
        { key: 'not-expiring', label: 'Certificates not expiring within 30 days', weight: 0.2, value: 100 - pctOf(expiringSoon.length, certs.length), basis: `${expiringSoon.length} expire within 30 days.` },
      ])
      return {
        score: scored.score,
        factors: scored.factors,
        coverage: pctOf(certs.length, Math.max(certs.length, inputs.snapshot.inventory.certificatesAnalyzed)),
        blockers: certs.length - managed.length,
        affectedAssets: unique(certs.map((c) => str(c.asset_id)).filter(Boolean)).length,
        basis: `${managed.length}/${certs.length} certificate(s) show automated issuance evidence, ${pqcCapable.length} carry an ML-DSA / SLH-DSA signature, ${expiringSoon.length} expire within 30 days.`,
        actions: certs.length - managed.length > 0
          ? [`Automate issuance for ${certs.length - managed.length} manually managed certificate(s).`, 'Validate that the issuing CA can sign ML-DSA-65 / hybrid chains.']
          : ['Confirm the managed CA supports ML-DSA-65 issuance and pilot a hybrid chain.'],
      }
    },

    /* ---- Key -------------------------------------------------------- */
    key: () => {
      const keys = inputs.generatedKeys
      // Sandbox simulations rotate nothing — only operational jobs count.
      const rotationJobs = splitMigrationJobs(inputs.migrationJobs).operational.filter((j) => /rotat|key/i.test(`${j.jobType} ${j.name}`))
      const custody = inputs.connectorAccounts.filter((a) => /kms|hsm|vault|key/i.test(str(a.provider)))
      const keyCoupling = (couplingByDomain.get('key') || []).length
      if (!keys.length && !rotationJobs.length && !custody.length && !inputs.snapshot.inventory.keysDiscovered) {
        return none('No key inventory, rotation job or KMS/HSM custody evidence exists.')
      }
      const pqcKeys = keys.filter((k) => classifyAlgorithm(str(k.algorithm)) === 'pqc' || classifyAlgorithm(str(k.algorithm)) === 'hybrid')
      const scored = scoreFromFactors([
        { key: 'pqc-keys', label: 'Managed keys of a PQC / hybrid type', weight: 0.35, value: keys.length ? pctOf(pqcKeys.length, keys.length) : null, basis: keys.length ? `${pqcKeys.length} of ${keys.length} managed key(s).` : 'No managed key inventory — unmeasured, weight redistributed.' },
        { key: 'rotation', label: 'Recorded operational key-rotation job', weight: 0.25, value: rotationJobs.length ? 100 : 0, basis: `${rotationJobs.length} operational rotation job(s) recorded (simulations excluded).` },
        { key: 'custody', label: 'KMS / HSM custody integration connected', weight: 0.2, value: custody.length ? 100 : 0, basis: `${custody.length} KMS/HSM/vault connector(s).` },
        { key: 'no-key-coupling', label: 'Free of embedded / manual key dependencies', weight: 0.2, value: 100 - Math.min(100, keyCoupling * 20), basis: `${keyCoupling} key-coupling finding(s); −20 each.` },
      ])
      // Coverage is the share of the THREE signal families that carry evidence
      // (inventory / rotation / custody). Counting rows instead would claim 100%
      // coverage from key rows alone while rotation and custody are unmeasured —
      // a low score reported with false confidence.
      const keySignals = [keys.length > 0, rotationJobs.length > 0, custody.length > 0].filter(Boolean).length
      return {
        score: scored.score,
        factors: scored.factors,
        coverage: pctOf(keySignals, 3),
        blockers: keyCoupling,
        affectedAssets: unique((couplingByDomain.get('key') || []).map((c) => c.assetId)).length,
        basis: `${keys.length} managed key(s) (${pqcKeys.length} PQC/hybrid), ${rotationJobs.length} rotation job(s), ${custody.length} KMS/HSM custody integration(s), ${keyCoupling} key-coupling finding(s).`,
        actions: [
          custody.length ? 'Verify HSM/KMS firmware exposes ML-KEM / ML-DSA key types.' : 'Connect a PQC-capable KMS/HSM so key material can be issued without manual handling.',
          keyCoupling ? `Remove ${keyCoupling} embedded/manual key dependency(ies).` : 'Keep rotation automated and evidence-backed.',
        ],
      }
    },

    /* ---- Library ---------------------------------------------------- */
    library: () => {
      const libraries = inputs.cryptoInventory.filter((i) => str(i.item_type).toLowerCase() === 'library')
      const legacyFindings = couplingByDomain.get('library') || []
      if (!libraries.length && !legacyFindings.length) {
        return none('No cryptographic library or provider component has been inventoried.')
      }
      const pqcCapable = libraries.filter((l) => {
        const text = `${str(l.name)} ${str(l.algorithm)}`.toLowerCase()
        return /liboqs|oqs|openssl 3|bouncycastle 1\.7|bc 1\.7|ml-kem|ml-dsa|pqclean/.test(text) || l.is_quantum_safe === true
      })
      const scored = scoreFromFactors([
        { key: 'pqc-providers', label: 'Inventoried providers exposing PQC primitives', weight: 0.7, value: libraries.length ? pctOf(pqcCapable.length, libraries.length) : null, basis: libraries.length ? `${pqcCapable.length} of ${libraries.length} provider(s).` : 'No library component inventoried — unmeasured, weight redistributed.' },
        { key: 'no-legacy-provider', label: 'Free of deprecated-provider findings', weight: 0.3, value: 100 - Math.min(100, legacyFindings.length * 15), basis: `${legacyFindings.length} legacy-provider finding(s); −15 each.` },
      ])
      const libraryAssets = unique([...libraries.map((l) => str(l.asset_id)), ...legacyFindings.map((f) => f.assetId)].filter(Boolean)).length
      return {
        score: scored.score,
        factors: scored.factors,
        // Share of evaluated assets with ANY provider evidence — not a constant.
        coverage: pctOf(libraryAssets, Math.max(1, evaluated.length)),
        blockers: legacyFindings.length,
        affectedAssets: unique(legacyFindings.map((f) => f.assetId)).length,
        basis: libraries.length
          ? `${pqcCapable.length}/${libraries.length} inventoried provider(s) expose PQC primitives; ${legacyFindings.length} legacy-provider finding(s) recorded.`
          : `${legacyFindings.length} legacy-provider finding(s) recorded; no library component inventoried yet.`,
        actions: legacyFindings.length
          ? [`Upgrade ${legacyFindings.length} deprecated provider(s) to a PQC-capable build (OpenSSL 3.x + oqsprovider).`, 'Pin the provider version in the crypto policy so upgrades are auditable.']
          : ['Record provider versions in the CBOM so upgrade readiness stays measurable.'],
      }
    },

    /* ---- Infrastructure --------------------------------------------- */
    infrastructure: () => {
      const connectors = inputs.connectorAccounts
      const configFindings = (couplingByDomain.get('infrastructure') || []).length
      const managedEnvironments = unique(evaluated.map((a) => a.environment.toLowerCase()).filter((e) => e && e !== 'unknown'))
      if (!connectors.length && !managedEnvironments.length) {
        return none('No cloud/infrastructure connector or environment classification is available.')
      }
      const classified = evaluated.filter((a) => a.environment && a.environment.toLowerCase() !== 'unknown').length
      const scored = scoreFromFactors([
        { key: 'connector', label: 'Infrastructure platform connected for central change', weight: 0.4, value: connectors.length ? 100 : 0, basis: `${connectors.length} cloud / infrastructure connector(s).` },
        { key: 'environment', label: 'Evaluated assets with a classified environment', weight: 0.3, value: evaluated.length ? pctOf(classified, evaluated.length) : null, basis: `${classified} of ${evaluated.length} evaluated asset(s).` },
        { key: 'no-embedded-config', label: 'Free of embedded cryptographic configuration', weight: 0.3, value: 100 - Math.min(100, configFindings * 10), basis: `${configFindings} embedded-configuration finding(s); −10 each.` },
      ])
      return {
        score: scored.score,
        factors: scored.factors,
        coverage: pctOf(connectors.length ? evaluated.length : 0, Math.max(1, total)),
        blockers: configFindings,
        affectedAssets: unique((couplingByDomain.get('infrastructure') || []).map((f) => f.assetId)).length,
        basis: `${connectors.length} infrastructure connector(s), ${managedEnvironments.length} classified environment(s), ${configFindings} embedded-configuration finding(s).`,
        actions: connectors.length
          ? ['Push the crypto policy through the connected platforms so a single change reaches every node.', configFindings ? `Externalise ${configFindings} embedded configuration block(s).` : 'Keep configuration drift monitored.']
          : ['Connect the cloud/infrastructure platforms so cryptographic configuration can be changed centrally.'],
      }
    },

    /* ---- Identity ---------------------------------------------------- */
    identity: () => {
      const identityAssets = evaluated.filter((a) =>
        /identity|auth|idp|sso|oauth|oidc|token|jwt|saml|directory|ldap/i.test(`${a.type} ${a.name}`) ||
        a.algorithms.some((x) => /ECDSA|\bDSA\b|ED25519|ML-DSA|RS256|ES256/i.test(x.algorithm)),
      )
      if (!identityAssets.length) return none('No identity, token-signing or federation asset has been discovered.')
      const pqcSigning = identityAssets.filter((a) => a.algorithms.some((x) => classifyAlgorithm(x.algorithm) === 'pqc' || classifyAlgorithm(x.algorithm) === 'hybrid'))
      const rigid = identityAssets.filter((a) => {
        const d = derivations.get(a.id)
        return d?.replaceability === 'code' || d?.replaceability === 'architecture' || d?.replaceability === 'vendor'
      })
      const scored = scoreFromFactors([
        { key: 'pqc-signing', label: 'Identity assets already signing with PQC / hybrid material', weight: 0.5, value: pctOf(pqcSigning.length, identityAssets.length), basis: `${pqcSigning.length} of ${identityAssets.length}.` },
        { key: 'not-rigid', label: 'Identity assets changeable without code, architecture or vendor work', weight: 0.5, value: 100 - pctOf(rigid.length, identityAssets.length), basis: `${rigid.length} of ${identityAssets.length} are rigid.` },
      ])
      return {
        score: scored.score,
        factors: scored.factors,
        coverage: pctOf(identityAssets.length, Math.max(1, evaluated.length)),
        blockers: rigid.length,
        affectedAssets: identityAssets.length,
        basis: `${identityAssets.length} identity/signing asset(s): ${pqcSigning.length} already sign with PQC or hybrid material, ${rigid.length} require code, architecture or vendor change.`,
        actions: [
          'Introduce dual-signing (Ed25519 + ML-DSA-65) so relying parties can verify during the transition.',
          rigid.length ? `Unblock ${rigid.length} rigid identity asset(s) before the signature cutover.` : 'Validate token verification against ML-DSA-65 in the sandbox.',
        ],
      }
    },

    /* ---- Trust -------------------------------------------------------- */
    // Delegated to the SHARED trust-agility model that the Trust Chain Analyzer
    // publishes, so the Crypto Agility "Trust Agility" domain and the Trust
    // Chain Analyzer's headline score are the SAME number by construction
    // rather than two opinions that drift apart.
    trust: () => {
      const anchorFindings = couplingByDomain.get('trust') || []
      if (!evaluated.length) {
        return none('No trust relationship or trust-anchor evidence has been recorded against an assessed asset.')
      }
      const agility = computeTrustAgility({
        certificates: inputs.certificates,
        assets: inputs.assets.map((a) => ({ id: a.id, name: a.name, type: a.type, environment: a.environment })),
        assetRelationships: inputs.relationships,
        cryptoInventory: inputs.cryptoInventory,
        now,
      })
      if (agility.score === null) {
        return none('No certificate, anchor or federation evidence could be measured, so trust agility is unscored.')
      }
      const deepAssets = evaluated.filter((a) => a.blastRadius > 6)
      const weakest = [...agility.breakdown]
        .filter((row) => row.score !== null)
        .sort((a, b) => (a.score as number) - (b.score as number))[0]
      return {
        score: agility.score,
        // The shared model's own breakdown, so the factors match the Trust Chain Analyzer's.
        factors: (() => {
          const measuredWeight = agility.breakdown.reduce((sum, row) => sum + (row.score === null ? 0 : row.weight), 0)
          return agility.breakdown.map((row) => ({
            key: row.key,
            label: row.label,
            weight: row.weight / 100,
            effectiveWeight: row.score === null || measuredWeight <= 0 ? 0 : Math.round((row.weight / measuredWeight) * 1000) / 1000,
            value: row.score,
            measured: row.score !== null,
            basis: row.basis,
          }))
        })(),
        coverage: agility.coverage,
        blockers: anchorFindings.length,
        affectedAssets: unique(anchorFindings.map((f) => f.assetId)).length + deepAssets.length,
        basis: `${agility.basis} Weakest dimension: ${weakest ? `${weakest.label} (${weakest.score}/100) — ${weakest.basis}` : 'not determined'} Shared with the Trust Chain Analyzer.`,
        actions: anchorFindings.length
          ? [`Plan anchor redistribution for ${anchorFindings.length} static trust anchor(s) before re-issuance.`, 'Stage cross-signed hybrid chains so relying parties never lose trust.']
          : ['Model the cross-signing sequence for the PQC root before the CA cutover.'],
      }
    },

    /* ---- Vendor ------------------------------------------------------- */
    vendor: () => {
      if (!sr || !sr.hasData || !sr.providerBreakdown.length) {
        return none('No provider or vendor dependency has been attributed from evidence.')
      }
      const providers = sr.providerBreakdown.filter((p) => p.domain !== 'customer')
      if (!providers.length) return none('All attributed cryptography is customer-controlled; no vendor dependency to score.')
      const shipping = providers.filter((p) => p.pqRoadmapStatus === 'shipping')
      const inProgress = providers.filter((p) => p.pqRoadmapStatus === 'in_progress' || p.pqRoadmapStatus === 'announced')
      const unknownRoadmap = providers.filter((p) => p.pqRoadmapStatus === 'unknown')
      const scored = scoreFromFactors([
        { key: 'roadmap', label: 'Providers shipping (full credit) or with an announced / in-progress PQC roadmap (half credit)', weight: 1, value: pctOf(shipping.length, providers.length) + pctOf(inProgress.length, providers.length) * 0.5, basis: `${shipping.length} shipping, ${inProgress.length} in progress or announced, of ${providers.length}.` },
      ])
      return {
        score: scored.score,
        factors: scored.factors,
        coverage: pctOf(sr.attribution.attributed, Math.max(1, sr.attribution.attributed + sr.attribution.unattributed)),
        blockers: providers.length - shipping.length,
        affectedAssets: sr.widgets.providerFindings + sr.widgets.vendorFindings,
        basis: `${providers.length} attributed vendor/ecosystem provider(s): ${shipping.length} shipping PQC, ${inProgress.length} in progress or announced, ${unknownRoadmap.length} with no published roadmap.`,
        actions: [
          unknownRoadmap.length ? `Request a PQC roadmap from ${unknownRoadmap.length} provider(s) with no published position.` : 'Track provider PQC release notes for cutover windows.',
          'Record vendor PQC commitments as contractual migration dependencies.',
        ],
      }
    },

    /* ---- Runtime ------------------------------------------------------ */
    runtime: () => {
      const events = inputs.runtimeEvents
      if (!events.length) {
        return none('No runtime cryptographic telemetry has been observed — cryptographic change and drift cannot be detected in operation.')
      }
      const observedAssets = unique(events.map((e) => str(e.asset_id)).filter(Boolean))
      const coverage = pctOf(observedAssets.length, Math.max(1, total))
      const recent = events.filter((e) => {
        const at = isoOrNull(e.observed_at) || isoOrNull(e.created_at)
        return at ? now - new Date(at).getTime() <= 7 * 86400000 : false
      })
      const scored = scoreFromFactors([
        { key: 'runtime-coverage', label: 'Assets under runtime cryptographic telemetry', weight: 0.6, value: coverage, basis: `${observedAssets.length} of ${total} asset(s).` },
        { key: 'recency', label: 'Runtime events observed in the last 7 days', weight: 0.4, value: pctOf(recent.length, Math.max(1, events.length)), basis: `${recent.length} of ${events.length} event(s).` },
      ])
      return {
        score: scored.score,
        factors: scored.factors,
        coverage,
        blockers: Math.max(0, total - observedAssets.length),
        affectedAssets: Math.max(0, total - observedAssets.length),
        basis: `${events.length} runtime crypto event(s) across ${observedAssets.length}/${total} asset(s); ${recent.length} observed in the last 7 days.`,
        actions: [
          coverage < 100 ? `Extend runtime collectors to the remaining ${Math.max(0, total - observedAssets.length)} asset(s).` : 'Runtime coverage is complete — keep collectors healthy.',
          'Alert on newly observed classical primitives so agility regressions surface immediately.',
        ],
      }
    },
  }

  function none(reason: string): DomainComputation {
    return { score: null, coverage: 0, blockers: 0, affectedAssets: 0, basis: `${EVIDENCE_UNAVAILABLE} — ${reason}`, actions: [], factors: [] }
  }

  // A domain whose source query FAILED is withheld, never scored from the
  // empty list the failure left behind.
  const unreadable = new Map((inputs.sourceHealth || []).filter((s) => s.state === 'unavailable').map((s) => [s.key, s.label]))

  return AGILITY_DOMAINS.map((definition) => {
    const missing = DOMAIN_SOURCES[definition.key].filter((key) => unreadable.has(key)).map((key) => unreadable.get(key) as string)
    // Hard floor: with no cryptographically assessed asset, NO agility domain is
    // measurable. Several domains score from the ABSENCE of bad evidence (no
    // deprecated provider, no static anchor), which on an empty tenant would
    // otherwise read as a perfect 100 — the exact "missing data becomes a good
    // number" failure this engine exists to prevent.
    const result = missing.length
      ? none(`${missing.join(', ')} could not be read, so this domain is withheld rather than scored from an empty list.`)
      : evaluated.length === 0
        ? none('No asset has been cryptographically assessed, so no agility domain can be measured.')
        : compute[definition.key]()
    const hasEvidence = result.score !== null
    const confidence = confidenceFromCoverage(result.coverage, hasEvidence)
    let state = stateFromScore(result.score, result.blockers)
    // A high score derived from thin coverage must not be published as "Agile".
    // The number stays honest; the VERDICT is capped until coverage supports it.
    if (state === 'agile' && (confidence === 'low' || confidence === 'none')) state = 'conditional'
    const risk = result.score === null ? null : Math.round(clamp(100 - result.score))
    return {
      key: definition.key,
      label: definition.label,
      question: definition.question,
      weight: definition.weight,
      route: definition.route,
      score: result.score,
      state,
      evidenceCoverage: Math.round(result.coverage),
      confidence,
      risk,
      riskLevel: riskLevelFromScore(risk),
      blockers: result.blockers,
      affectedAssets: result.affectedAssets,
      improvementOpportunity: result.score === null ? 0 : Math.round(((100 - result.score) * definition.weight) / 100),
      basis: result.basis,
      actions: result.actions,
      factors: result.factors,
    }
  })
}

/** Raw sources each domain is computed from (keys match `AgilitySourceStatus.key`). */
const DOMAIN_SOURCES: Record<AgilityDomainKey, string[]> = {
  application: ['crypto_inventory', 'crypto_exposures'],
  algorithm: ['crypto_inventory'],
  protocol: ['crypto_inventory'],
  certificate: ['certificates'],
  key: ['generated_keys', 'migration_jobs', 'connector_accounts'],
  library: ['crypto_inventory'],
  infrastructure: ['connector_accounts', 'crypto_exposures'],
  identity: ['crypto_inventory'],
  trust: ['certificates', 'asset_relationships'],
  vendor: [],
  runtime: ['runtime_crypto_events'],
}

/* ================================================================== */
/* Replaceability matrix                                               */
/* ================================================================== */

/** assetId → UPPER-CASED algorithm → where it was evidenced. */
type ProvenanceIndex = Map<string, Map<string, Set<EvidenceProvenance>>>

/**
 * Where each (asset, algorithm) pair was evidenced, from the raw rows. A CBOM
 * component carrying a code location is `source` or `config` (by file type);
 * one without a location came from a discovery scan of a live target. Served
 * certificates and runtime telemetry are operational by definition.
 */
function buildProvenanceIndex(inputs: AgilityInputs): ProvenanceIndex {
  const index: ProvenanceIndex = new Map()
  const note = (assetId: string, algorithm: string, provenance: EvidenceProvenance) => {
    const key = algorithm.trim().toUpperCase()
    if (!assetId || !key) return
    const byAlgo = index.get(assetId) || new Map<string, Set<EvidenceProvenance>>()
    const set = byAlgo.get(key) || new Set<EvidenceProvenance>()
    set.add(provenance)
    byAlgo.set(key, set)
    index.set(assetId, byAlgo)
  }
  for (const item of inputs.cryptoInventory) {
    const location = codeLocationOf(recordOf(item.metadata))
    note(str(item.asset_id), str(item.algorithm), location ? (isConfigLike(location) ? 'config' : 'source') : 'scan')
  }
  for (const cert of inputs.certificates) note(str(cert.asset_id), str(cert.algorithm), 'certificate')
  for (const event of inputs.runtimeEvents) note(str(event.asset_id), str(event.algorithm), 'runtime')
  return index
}

const OPERATIONAL_PROVENANCE: ReadonlySet<EvidenceProvenance> = new Set(['runtime', 'scan', 'certificate'])

const STATUS_RANK: Record<AlgorithmStatus, number> = { unsupported: 0, deprecated: 1, unknown: 2, detected: 3, configured: 4, approved: 5 }

function buildReplaceabilityMatrix(
  inputs: AgilityInputs,
  derivations: Map<string, AssetAgilityDerivation>,
  provenanceIndex: ProvenanceIndex,
): { rows: ReplaceabilityRow[]; rejected: number } {
  interface Bucket {
    classification: AlgorithmClass
    target: string
    standard: string
    rationale: string
    instances: number
    assetIds: Set<string>
    assetNames: string[]
    dependencies: number
    severityRank: number
    compatibilitySum: number
    compatibilityCount: number
    breakdown: Record<ReplaceabilityClass, number>
    minKeySize: number
    provenance: Record<EvidenceProvenance, number>
    certificateOnly: boolean
    blockedAssetIds: Set<string>
    blockedAssetNames: string[]
  }

  const buckets = new Map<string, Bucket>()

  let rejected = 0
  for (const asset of inputs.assets) {
    if (!asset.hasEvidence) continue
    const derivation = derivations.get(asset.id)
    for (const algo of asset.algorithms) {
      // A matrix row proposes a migration path, so it may only ever describe a
      // real primitive. Scanner finding titles are excluded, not "migrated".
      if (!isCryptographicPrimitive(algo.algorithm)) {
        rejected += 1
        continue
      }
      const key = algo.algorithm.toUpperCase()
      const bucket = buckets.get(key) || {
        classification: algo.classification,
        target: algo.target,
        standard: algo.standard,
        rationale: algo.rationale,
        instances: 0,
        assetIds: new Set<string>(),
        assetNames: [],
        dependencies: 0,
        severityRank: 0,
        compatibilitySum: 0,
        compatibilityCount: 0,
        breakdown: { configuration: 0, library: 0, code: 0, architecture: 0, vendor: 0, unknown: 0 },
        minKeySize: 0,
        provenance: { runtime: 0, scan: 0, certificate: 0, source: 0, config: 0 },
        certificateOnly: true,
        blockedAssetIds: new Set<string>(),
        blockedAssetNames: [],
      }
      bucket.instances += algo.instances
      const smallest = algo.keySizes[0] ?? 0
      if (smallest > 0 && (bucket.minKeySize === 0 || smallest < bucket.minKeySize)) bucket.minKeySize = smallest
      if (!bucket.assetIds.has(asset.id)) {
        bucket.assetIds.add(asset.id)
        if (bucket.assetNames.length < 12) bucket.assetNames.push(asset.name)
        bucket.dependencies += asset.blastRadius
        bucket.compatibilitySum += asset.compatibility.score
        bucket.compatibilityCount += 1
        bucket.breakdown[derivation?.replaceability ?? 'unknown'] += 1
        const provenance = provenanceIndex.get(asset.id)?.get(key)
        for (const p of provenance ?? []) bucket.provenance[p] += 1
        if (!provenance || [...provenance].some((p) => p !== 'certificate')) bucket.certificateOnly = false
        if (derivation && (derivation.state === 'rigid' || derivation.state === 'blocked')) {
          bucket.blockedAssetIds.add(asset.id)
          if (bucket.blockedAssetNames.length < 12) bucket.blockedAssetNames.push(asset.name)
        }
      }
      bucket.severityRank = Math.max(bucket.severityRank, SEVERITY_RANK[normalizeSeverity(algo.severity)])
      buckets.set(key, bucket)
    }
  }

  const rows: ReplaceabilityRow[] = []
  for (const [algorithm, bucket] of buckets) {
    // The row's replaceability is the WORST binding constraint across the assets
    // that run this algorithm — a swap is only as easy as its hardest instance.
    let replaceability: ReplaceabilityClass = 'unknown'
    for (const [klass, count] of Object.entries(bucket.breakdown) as Array<[ReplaceabilityClass, number]>) {
      if (count > 0 && REPLACEABILITY_RANK[klass] > REPLACEABILITY_RANK[replaceability]) replaceability = klass
    }

    const compatibilityScore = bucket.compatibilityCount ? Math.round(bucket.compatibilitySum / bucket.compatibilityCount) : null
    const complexity: ReplaceabilityRow['migrationComplexity'] =
      replaceability === 'unknown'
        ? 'Unknown'
        : replaceability === 'configuration'
          ? 'Low'
          : replaceability === 'library'
            ? 'Medium'
            : 'High'

    const observedInOperation = (Object.keys(bucket.provenance) as EvidenceProvenance[]).some((p) => OPERATIONAL_PROVENANCE.has(p) && bucket.provenance[p] > 0)
    const verdict = classifyAlgorithmStatus(algorithm, { minKeySize: bucket.minKeySize, asCertificate: bucket.certificateOnly, observedInOperation })
    const target = approvedTargetFor(verdict.role, verdict.status)
    const needsTransition = verdict.status === 'unsupported' || verdict.status === 'deprecated'
    const alreadySafe = verdict.status === 'approved' || verdict.status === 'configured'
    const status: AgilityState = alreadySafe
      ? 'agile'
      : replaceability === 'unknown'
        ? 'unknown'
        : replaceability === 'vendor'
          ? 'blocked'
          : replaceability === 'configuration'
            ? 'agile'
            : replaceability === 'library'
              ? 'conditional'
              : 'rigid'

    rows.push({
      id: `repl-${algorithm.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
      currentAlgorithm: algorithm,
      classification: bucket.classification,
      // Role-correct target from the shared map: ML-KEM only for key
      // establishment, ML-DSA / SLH-DSA only for signatures.
      proposedReplacement: needsTransition || verdict.status === 'detected' ? target.target : bucket.target === 'Already quantum-safe' ? 'No transition required' : target.target,
      standard: target.standard === '—' ? bucket.standard : target.standard,
      rationale: needsTransition ? verdict.reason : bucket.rationale,
      assets: bucket.assetIds.size,
      assetNames: bucket.assetNames,
      instances: bucket.instances,
      replaceability,
      replaceabilityLabel: REPLACEABILITY_LABEL[replaceability],
      dependencies: bucket.dependencies,
      migrationComplexity: complexity,
      compatibility:
        compatibilityScore === null
          ? EVIDENCE_UNAVAILABLE
          : compatibilityScore >= 75
            ? 'High — hybrid mode preserves classical peers'
            : compatibilityScore >= 50
              ? 'Medium — stage behind a compatibility gate'
              : 'Low — peers must be upgraded first',
      compatibilityScore,
      risk: alreadySafe ? 'low' : (Object.keys(SEVERITY_RANK) as Severity[]).find((s) => SEVERITY_RANK[s] === bucket.severityRank) || 'medium',
      status,
      breakdown: bucket.breakdown,
      basis: `${bucket.instances} instance(s) across ${bucket.assetIds.size} asset(s); the row adopts the hardest per-asset verdict (${REPLACEABILITY_LABEL[replaceability]}).`,
      role: verdict.role,
      roleLabel: ALGORITHM_ROLE_LABEL[verdict.role],
      algorithmStatus: verdict.status,
      statusReason: verdict.reason,
      needsTransition,
      provenance: bucket.provenance,
      observedInOperation,
      blockedAssets: bucket.blockedAssetIds.size,
      blockedAssetNames: bucket.blockedAssetNames,
    })
  }

  return {
    rows: rows.sort(
      (a, b) =>
        STATUS_RANK[a.algorithmStatus] - STATUS_RANK[b.algorithmStatus] ||
        REPLACEABILITY_RANK[b.replaceability] - REPLACEABILITY_RANK[a.replaceability] ||
        b.instances - a.instances ||
        a.id.localeCompare(b.id),
    ),
    rejected,
  }
}

/** One lane per role: every algorithm doing that job → the approved target. */
function buildTransitionLanes(rows: ReplaceabilityRow[]): TransitionLane[] {
  const roleOrder: AlgorithmRole[] = ['key-establishment', 'signature', 'public-key', 'protocol', 'cipher-suite', 'symmetric', 'hash', 'kdf', 'unknown']
  const blank = (): Record<AlgorithmStatus, number> => ({ unsupported: 0, deprecated: 0, configured: 0, approved: 0, detected: 0, unknown: 0 })
  return roleOrder
    .map((role) => {
      const laneRows = rows.filter((row) => row.role === role)
      if (!laneRows.length) return null
      const byStatus = blank()
      for (const row of laneRows) byStatus[row.algorithmStatus] += row.instances
      const mapped = APPROVED_TARGET_BY_ROLE[role]
      const blocked = new Set<string>()
      for (const row of laneRows) if (row.needsTransition) for (const name of row.blockedAssetNames) blocked.add(name)
      return {
        role,
        label: ALGORITHM_ROLE_LABEL[role],
        target: mapped?.target ?? null,
        standard: mapped?.standard ?? null,
        algorithms: laneRows.length,
        instances: laneRows.reduce((sum, row) => sum + row.instances, 0),
        assets: unique(laneRows.flatMap((row) => row.assetNames)).length,
        byStatus,
        needsTransition: byStatus.unsupported + byStatus.deprecated,
        blockedAssets: blocked.size,
        rowIds: laneRows.map((row) => row.id),
      } satisfies TransitionLane
    })
    .filter((lane): lane is TransitionLane => lane !== null)
}

/** Distinct algorithms and instances per status — the counts sum to the matrix rows. */
function summarizeAlgorithmStatus(rows: ReplaceabilityRow[]): AlgorithmStatusSummary[] {
  return ALGORITHM_STATUS_ORDER.map((status) => {
    const matching = rows.filter((row) => row.algorithmStatus === status)
    return {
      status,
      label: ALGORITHM_STATUS_LABEL[status],
      definition: ALGORITHM_STATUS_DEFINITION[status],
      algorithms: matching.length,
      instances: matching.reduce((sum, row) => sum + row.instances, 0),
    }
  })
}

/* ================================================================== */
/* Blockers                                                            */
/* ================================================================== */

const BLOCKER_CATEGORY_LABEL: Record<AgilityBlocker['category'], string> = {
  'hardcoded-crypto': 'Hard-coded cryptography',
  'unsupported-library': 'Unsupported library',
  'legacy-protocol': 'Legacy protocol',
  'certificate-dependency': 'Certificate dependency',
  'trust-dependency': 'Trust dependency',
  'vendor-dependency': 'Vendor dependency',
  'application-incompatibility': 'Application incompatibility',
  'infrastructure-dependency': 'Infrastructure dependency',
  'identity-dependency': 'Identity dependency',
  'unknown-dependency': 'Unknown dependency',
}

function buildBlockers(
  inputs: AgilityInputs,
  coupling: CouplingFinding[],
  assetRows: AgilityAssetRow[],
): AgilityBlocker[] {
  const groups = new Map<AgilityBlocker['category'], CouplingFinding[]>()
  const add = (category: AgilityBlocker['category'], finding: CouplingFinding) => {
    const list = groups.get(category) || []
    list.push(finding)
    groups.set(category, list)
  }

  for (const finding of coupling) {
    switch (finding.type) {
      case 'hardcoded-algorithm':
      case 'hardcoded-cipher-suite':
      case 'hardcoded-key-size':
      case 'embedded-crypto-config':
        add('hardcoded-crypto', finding)
        break
      case 'legacy-crypto-provider':
        add('unsupported-library', finding)
        break
      case 'embedded-certificate':
      case 'manual-certificate-management':
      case 'hardcoded-certificate-path':
        add('certificate-dependency', finding)
        break
      case 'static-trust-anchor':
        add('trust-dependency', finding)
        break
      case 'vendor-locked-crypto':
        add('vendor-dependency', finding)
        break
      case 'embedded-public-key':
      case 'manual-key-management':
        add('infrastructure-dependency', finding)
        break
      case 'undocumented-dependency':
        add('unknown-dependency', finding)
        break
    }
  }

  const blockers: AgilityBlocker[] = []

  for (const [category, findings] of groups) {
    const worst = findings.reduce((acc, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[acc.severity] ? f : acc), findings[0])
    const assetIds = unique(findings.map((f) => f.assetId))
    const domains = unique(findings.map((f) => f.controlDomain))
    blockers.push({
      id: `blocker-${category}`,
      category,
      categoryLabel: BLOCKER_CATEGORY_LABEL[category],
      title: worst.title,
      severity: worst.severity,
      count: findings.length,
      affectedAssets: unique(findings.map((f) => f.asset)).slice(0, 12),
      affectedAssetIds: assetIds,
      businessImpact: businessImpactFor(category, findings, assetRows),
      owner: unique(findings.map((f) => f.owner)).slice(0, 3).join(', ') || 'Unassigned',
      controlDomain: domains.includes('provider') ? 'provider' : domains.includes('ecosystem') ? 'ecosystem' : 'customer',
      remediation: worst.remediation,
      domain: worst.domain,
      route: worst.route,
      basis: `${findings.length} finding(s) across ${assetIds.length} asset(s), evidence from ${unique(findings.map((f) => f.evidenceSource)).join(', ')}.`,
    })
  }

  /* ---- Legacy protocol is a transport blocker, not a coupling row --- */
  const legacyTransport = inputs.assets.filter(
    (a) => a.hasEvidence && protocolVersionsFor(a).some((p) => LEGACY_PROTOCOL_RE.test(p)),
  )
  if (legacyTransport.length) {
    blockers.push({
      id: 'blocker-legacy-protocol',
      category: 'legacy-protocol',
      categoryLabel: BLOCKER_CATEGORY_LABEL['legacy-protocol'],
      title: 'Deprecated TLS/SSL versions block hybrid key exchange',
      severity: 'high',
      count: legacyTransport.length,
      affectedAssets: legacyTransport.map((a) => a.name).slice(0, 12),
      affectedAssetIds: legacyTransport.map((a) => a.id),
      businessImpact: 'Hybrid PQC named groups only negotiate on TLS 1.3 — every client of these endpoints must be upgraded before the cutover.',
      owner: unique(legacyTransport.map((a) => a.owner)).slice(0, 3).join(', ') || 'Unassigned',
      controlDomain: 'customer',
      remediation: 'Enforce TLS 1.3 on these endpoints, then enable X25519MLKEM768 in the transport policy.',
      domain: 'protocol',
      route: '/dashboard/protocol-analytics',
      basis: `${legacyTransport.length} asset(s) with an observed TLS 1.0/1.1/SSL protocol in transport telemetry.`,
    })
  }

  /* ---- Application incompatibility --------------------------------- */
  const incompatible = inputs.assets.filter((a) => a.hasEvidence && a.compatibility.score > 0 && a.compatibility.score < 50)
  if (incompatible.length) {
    blockers.push({
      id: 'blocker-app-incompat',
      category: 'application-incompatibility',
      categoryLabel: BLOCKER_CATEGORY_LABEL['application-incompatibility'],
      title: 'Assets scored below the compatibility gate',
      severity: 'high',
      count: incompatible.length,
      affectedAssets: incompatible.map((a) => a.name).slice(0, 12),
      affectedAssetIds: incompatible.map((a) => a.id),
      businessImpact: 'Cutover would break peers that cannot negotiate the replacement stack.',
      owner: unique(incompatible.map((a) => a.owner)).slice(0, 3).join(', ') || 'Unassigned',
      controlDomain: 'customer',
      remediation: 'Resolve the recorded compatibility notes, then re-run the change in the Migration Sandbox before scheduling.',
      domain: 'application',
      route: '/dashboard/migration-sandbox',
      basis: `${incompatible.length} asset(s) with a compatibility score below 50 in the shared asset model.`,
    })
  }

  /* ---- Identity dependency ----------------------------------------- */
  const identityBlocked = assetRows.filter(
    (r) => r.agilityState !== 'agile' && /identity|auth|idp|sso|oauth|oidc|token|jwt|saml/i.test(`${r.type} ${r.name}`),
  )
  if (identityBlocked.length) {
    blockers.push({
      id: 'blocker-identity',
      category: 'identity-dependency',
      categoryLabel: BLOCKER_CATEGORY_LABEL['identity-dependency'],
      title: 'Identity and token-signing dependencies gate the signature migration',
      severity: 'medium',
      count: identityBlocked.length,
      affectedAssets: identityBlocked.map((r) => r.name).slice(0, 12),
      affectedAssetIds: identityBlocked.map((r) => r.id),
      businessImpact: 'Every relying party must verify the new signature algorithm before the old keys can be retired.',
      owner: unique(identityBlocked.map((r) => r.owner)).slice(0, 3).join(', ') || 'Unassigned',
      controlDomain: 'customer',
      remediation: 'Roll out dual-signing (Ed25519 + ML-DSA-65) and confirm verification across every relying party.',
      domain: 'identity',
      route: '/dashboard/pqauth',
      basis: `${identityBlocked.length} identity-related asset(s) are not yet configuration-replaceable.`,
    })
  }

  return blockers.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count)
}

function businessImpactFor(
  category: AgilityBlocker['category'],
  findings: CouplingFinding[],
  assetRows: AgilityAssetRow[],
): string {
  const ids = new Set(findings.map((f) => f.assetId))
  const rows = assetRows.filter((r) => ids.has(r.id))
  const internetFacing = rows.filter((r) => r.internetFacing).length
  const production = rows.filter((r) => /prod/i.test(r.environment)).length
  const dependents = rows.reduce((sum, r) => sum + r.dependencies, 0)
  const scope = `${rows.length || ids.size} asset(s)${production ? `, ${production} in production` : ''}${internetFacing ? `, ${internetFacing} internet-facing` : ''}, ${dependents} dependent relationship(s)`

  switch (category) {
    case 'hardcoded-crypto':
      return `Each algorithm change requires a code change, review and release cycle — ${scope}.`
    case 'unsupported-library':
      return `The runtime cannot express ML-KEM/ML-DSA until the provider is upgraded — ${scope}.`
    case 'certificate-dependency':
      return `Certificate re-issuance needs a manual change window, delaying the hybrid chain rollout — ${scope}.`
    case 'trust-dependency':
      return `Relying parties must trust a replacement anchor before the chain can move — ${scope}.`
    case 'vendor-dependency':
      return `The change cannot be executed by this organisation; it depends on the provider's roadmap — ${scope}.`
    case 'infrastructure-dependency':
      return `Key and configuration changes require operational handling instead of a policy push — ${scope}.`
    case 'unknown-dependency':
      return `No accountable owner exists to approve or execute the change — ${scope}.`
    default:
      return scope
  }
}

/* ================================================================== */
/* Coupling / dependency graph                                         */
/* ================================================================== */

function buildCouplingGraph(
  inputs: AgilityInputs,
  derivations: Map<string, AssetAgilityDerivation>,
  coupling: CouplingFinding[],
  provenanceIndex: ProvenanceIndex,
  maxAssets = 40,
): CouplingGraph {
  const nodes = new Map<string, CouplingNode>()
  const edges: CouplingEdge[] = []
  const edgeKeys = new Set<string>()

  type NodeInput = Omit<CouplingNode, 'algorithmStatus' | 'blockers' | 'shared'> & Partial<Pick<CouplingNode, 'algorithmStatus' | 'blockers'>>
  const addNode = (input: NodeInput) => {
    const node: CouplingNode = { ...input, algorithmStatus: input.algorithmStatus ?? null, blockers: input.blockers ?? [], shared: false }
    const existing = nodes.get(node.id)
    if (existing) {
      existing.assetIds = unique([...existing.assetIds, ...node.assetIds])
      existing.assetCount = existing.assetIds.length
      if (node.risk !== null) existing.risk = existing.risk === null ? node.risk : Math.max(existing.risk, node.risk)
      existing.blockers = unique([...existing.blockers, ...node.blockers])
      if (REPLACEABILITY_RANK[node.replaceability] > REPLACEABILITY_RANK[existing.replaceability]) {
        existing.replaceability = node.replaceability
        existing.agilityState = node.agilityState
      }
      return
    }
    nodes.set(node.id, node)
  }

  const addEdge = (source: string, target: string, kind: CouplingEdge['kind'], state: AgilityState) => {
    const key = `${source}→${target}`
    if (edgeKeys.has(key)) {
      const existing = edges.find((e) => `${e.source}→${e.target}` === key)
      if (existing) existing.weight += 1
      return
    }
    edgeKeys.add(key)
    edges.push({ source, target, kind, weight: 1, agilityState: state })
  }

  const couplingByAsset = new Map<string, CouplingFinding[]>()
  for (const finding of coupling) {
    const list = couplingByAsset.get(finding.assetId) || []
    list.push(finding)
    couplingByAsset.set(finding.assetId, list)
  }

  const librariesByAsset = new Map<string, Row[]>()
  for (const item of inputs.cryptoInventory) {
    if (str(item.item_type).toLowerCase() !== 'library') continue
    const assetId = str(item.asset_id)
    if (!assetId) continue
    const list = librariesByAsset.get(assetId) || []
    list.push(item)
    librariesByAsset.set(assetId, list)
  }

  // Rank by how much the asset limits agility, then take a bounded slice so the
  // graph stays renderable on large estates (§32 — never load every node).
  const evaluatedCount = inputs.assets.filter((a) => a.hasEvidence).length
  const ranked = [...inputs.assets]
    .filter((a) => a.hasEvidence)
    .sort((a, b) => {
      const da = derivations.get(a.id)
      const db = derivations.get(b.id)
      return (da?.score ?? 100) - (db?.score ?? 100) || b.blastRadius - a.blastRadius
    })
    .slice(0, maxAssets)

  const sr = inputs.snapshot.sharedResponsibility

  for (const asset of ranked) {
    const derivation = derivations.get(asset.id)
    const state = derivation?.state ?? 'unknown'
    const appId = `app:${asset.id}`
    addNode({
      id: appId,
      label: asset.name,
      layer: 'application',
      agilityState: state,
      risk: asset.riskScore,
      assetIds: [asset.id],
      assetCount: 1,
      algorithm: asset.algorithms[0]?.algorithm || EVIDENCE_UNAVAILABLE,
      replaceability: derivation?.replaceability ?? 'unknown',
      controlDomain: derivation?.controlDomain ?? 'customer',
      detail: `${asset.type} · ${asset.environment} · owner ${asset.owner} · ${asset.componentCount} component(s), ${asset.blastRadius} dependency relationship(s).`,
      route: `/dashboard/assets?asset=${encodeURIComponent(asset.id)}`,
      blockers: derivation?.blockerReasons ?? [],
    })

    /* -- Library layer -- */
    const libs = librariesByAsset.get(asset.id) || []
    for (const lib of libs.slice(0, 3)) {
      const label = str(lib.name) || str(lib.algorithm) || 'crypto provider'
      const libId = `lib:${label.toLowerCase()}`
      const deprecated = DEPRECATED_LIBRARY_MARKERS.some((m) => label.toLowerCase().includes(m))
      addNode({
        id: libId,
        label,
        layer: 'library',
        agilityState: deprecated ? 'rigid' : lib.is_quantum_safe === true ? 'agile' : 'conditional',
        risk: null,
        assetIds: [asset.id],
        assetCount: 1,
        algorithm: str(lib.algorithm) || EVIDENCE_UNAVAILABLE,
        replaceability: deprecated ? 'library' : 'configuration',
        controlDomain: 'customer',
        detail: deprecated ? 'Deprecated provider — must be upgraded before PQC primitives are available.' : 'Cryptographic provider inventoried for this asset.',
        route: '/dashboard/cbom_explorer',
        blockers: deprecated ? [`Deprecated provider (${label}) — no PQC primitives until it is upgraded.`] : [],
      })
      addEdge(appId, libId, 'uses', state)
    }

    /* -- Algorithm layer -- */
    for (const algo of asset.algorithms.filter((a) => isCryptographicPrimitive(a.algorithm)).slice(0, 4)) {
      const algoId = `alg:${algo.algorithm.toUpperCase()}`
      const provenance = provenanceIndex.get(asset.id)?.get(algo.algorithm.trim().toUpperCase())
      const verdict = classifyAlgorithmStatus(algo.algorithm, {
        minKeySize: algo.keySizes[0],
        observedInOperation: [...(provenance ?? [])].some((p) => OPERATIONAL_PROVENANCE.has(p)),
      })
      const algoState: AgilityState =
        verdict.status === 'approved' || verdict.status === 'configured' ? 'agile' : verdict.status === 'unsupported' ? 'rigid' : 'conditional'
      addNode({
        id: algoId,
        label: algo.algorithm,
        layer: 'algorithm',
        agilityState: algoState,
        risk: null,
        algorithmStatus: verdict.status,
        blockers: verdict.status === 'unsupported' ? [verdict.reason] : [],
        assetIds: [asset.id],
        assetCount: 1,
        algorithm: algo.algorithm,
        replaceability: algo.classification === 'pqc' ? 'configuration' : derivation?.replaceability ?? 'unknown',
        controlDomain: derivation?.controlDomain ?? 'customer',
        detail: `${algo.instances} instance(s) · target ${algo.target} (${algo.standard}).`,
        route: '/dashboard/cbom',
      })
      const parent = libs.length ? `lib:${(str(libs[0].name) || str(libs[0].algorithm) || 'crypto provider').toLowerCase()}` : appId
      addEdge(parent, algoId, 'implements', algoState)
    }

    /* -- Certificate + PKI layers -- */
    for (const cert of asset.certificates.slice(0, 3)) {
      const certId = `cert:${cert.id}`
      const pqcSigned = PQC_SIGNATURE_RE.test(cert.algorithm)
      const certState: AgilityState = pqcSigned ? 'agile' : 'conditional'
      addNode({
        id: certId,
        label: cert.name,
        layer: 'certificate',
        agilityState: certState,
        risk: null,
        assetIds: [asset.id],
        assetCount: 1,
        algorithm: cert.algorithm,
        replaceability: pqcSigned ? 'configuration' : 'library',
        controlDomain: 'customer',
        detail: `${cert.algorithm}${cert.keySize ? ` ${cert.keySize}-bit` : ''} · ${cert.daysToExpiry === null ? 'expiry unknown' : `${cert.daysToExpiry} day(s) to expiry`}.`,
        route: '/dashboard/pki-visibility',
      })
      addEdge(appId, certId, 'signs', certState)

      const issuer = cert.issuer && cert.issuer !== EVIDENCE_UNAVAILABLE ? cert.issuer : ''
      if (issuer) {
        const caId = `pki:${issuer.toLowerCase()}`
        const managed = MANAGED_ISSUER_MARKERS.some((m) => issuer.toLowerCase().includes(m))
        addNode({
          id: caId,
          label: issuer,
          layer: 'pki',
          agilityState: managed ? 'conditional' : 'rigid',
          risk: null,
          assetIds: [asset.id],
          assetCount: 1,
          algorithm: cert.algorithm,
          replaceability: managed ? 'configuration' : 'architecture',
          controlDomain: managed ? 'provider' : 'customer',
          detail: managed ? 'Managed issuer — re-issuance can be automated.' : 'No automated issuance evidence; re-issuance needs a change window.',
          route: '/dashboard/pki-visibility',
          blockers: managed ? [] : ['No automated issuance evidence — every leaf must be re-issued by hand in a change window.'],
        })
        addEdge(certId, caId, 'issued-by', managed ? 'conditional' : 'rigid')

        const anchorFinding = coupling.find((c) => c.type === 'static-trust-anchor' && c.assetId === asset.id)
        if (anchorFinding) {
          const anchorId = `anchor:${issuer.toLowerCase()}`
          addNode({
            id: anchorId,
            label: `${issuer} root`,
            layer: 'trust-anchor',
            agilityState: 'rigid',
            risk: null,
            assetIds: [asset.id],
            assetCount: 1,
            algorithm: cert.algorithm,
            replaceability: 'architecture',
            controlDomain: 'customer',
            detail: 'Static trust anchor — every relying party must trust the replacement before the chain can change.',
            route: '/dashboard/trust-chain-analyzer',
            blockers: [anchorFinding.evidence],
          })
          addEdge(caId, anchorId, 'anchors', 'rigid')
        }
      }
    }

    /* -- Identity layer -- */
    if (/identity|auth|idp|sso|oauth|oidc|token|jwt|saml|directory|ldap/i.test(`${asset.type} ${asset.name}`)) {
      const idpId = `idp:${asset.id}`
      addNode({
        id: idpId,
        label: `${asset.name} (identity)`,
        layer: 'identity',
        agilityState: state,
        risk: asset.riskScore,
        assetIds: [asset.id],
        assetCount: 1,
        algorithm: asset.algorithms.find((a) => /DSA|ED25519|RS256|ES256/i.test(a.algorithm))?.algorithm || EVIDENCE_UNAVAILABLE,
        replaceability: derivation?.replaceability ?? 'unknown',
        controlDomain: derivation?.controlDomain ?? 'customer',
        detail: 'Token signing / federation surface — relying parties must verify the replacement signature algorithm.',
        route: '/dashboard/pqauth',
        blockers: derivation?.blockerReasons ?? [],
      })
      addEdge(appId, idpId, 'federates', state)
    }

    /* -- Vendor layer (evidence-attributed only) -- */
    const vendorFinding = couplingByAsset.get(asset.id)?.find((c) => c.type === 'vendor-locked-crypto')
    if (vendorFinding) {
      const vendorId = `vendor:${vendorFinding.owner.toLowerCase()}`
      addNode({
        id: vendorId,
        label: vendorFinding.owner,
        layer: 'vendor',
        agilityState: 'blocked',
        risk: null,
        assetIds: [asset.id],
        assetCount: 1,
        algorithm: EVIDENCE_UNAVAILABLE,
        replaceability: 'vendor',
        controlDomain: vendorFinding.controlDomain,
        detail: vendorFinding.remediation,
        route: '/dashboard/vendor-pqc-readiness',
        blockers: [`${vendorFinding.owner} controls this cryptography — the change waits on the provider.`],
      })
      addEdge(appId, vendorId, 'depends-on', 'blocked')
    }
  }

  /* -- Real asset-to-asset trust dependencies between graphed apps -- */
  const graphedAssetIds = new Set(ranked.map((a) => a.id))
  for (const asset of ranked) {
    for (const dependency of asset.dependencies) {
      if (!graphedAssetIds.has(dependency.id)) continue
      addEdge(`app:${asset.id}`, `app:${dependency.id}`, 'depends-on', derivations.get(dependency.id)?.state ?? 'unknown')
    }
  }

  const nodeList = [...nodes.values()]
  for (const node of nodeList) node.shared = node.assetCount > 1
  const layers = COUPLING_LAYER_ORDER.map((layer) => ({
    layer,
    label: COUPLING_LAYER_LABEL[layer],
    count: nodeList.filter((n) => n.layer === layer).length,
  })).filter((l) => l.count > 0)

  // Provider readiness note — never invented, only reported when attributed.
  const providerNote = sr && sr.providerBreakdown.length
    ? ` ${sr.providerBreakdown.filter((p) => p.domain !== 'customer').length} external provider(s) attributed from evidence.`
    : ''

  return {
    nodes: nodeList,
    edges,
    layers,
    note: `Projection of the tenant's existing CBOM, certificate inventory, trust fabric and shared-responsibility attribution — no separate graph store. Showing the ${ranked.length} least-agile of ${evaluatedCount} evaluated asset(s).${providerNote}`,
    shownAssets: ranked.length,
    evaluatedAssets: evaluatedCount,
    blockingNodes: nodeList.filter((n) => n.blockers.length > 0).length,
  }
}

/* ================================================================== */
/* Policy evaluation                                                   */
/* ================================================================== */

/**
 * The platform MANDATORY PQC STACK. Algorithm rules are ALGORITHM_RULES — the
 * same list that decides an algorithm's status — so a policy WARN and a
 * "Deprecated" status are one decision. Transport rules are evaluated once per
 * asset; the preferred/required entries document the approved targets.
 * When a tenant-configured policy engine exists, `source` flips to
 * 'tenant-configured' and its rules replace these.
 */
const TRANSPORT_RULES: ReadonlyArray<PolicyRule & { test: (protocols: string[]) => boolean }> = [
  { id: 'pol-tls-legacy', subject: 'TLS 1.0 / 1.1 / SSL', verdict: 'block', rationale: 'Formally deprecated by RFC 8996; cannot carry modern or hybrid cryptography and must be disabled.', standard: 'RFC 8996', test: (protocols) => protocols.some((p) => LEGACY_TRANSPORT_RE.test(p) || LEGACY_PROTOCOL_RE.test(p)) },
  { id: 'pol-tls12', subject: 'TLS 1.2', verdict: 'warn', rationale: 'Cannot negotiate hybrid PQC named groups; blocks protocol agility.', standard: 'RFC 8446', test: (protocols) => protocols.some((p) => /1\.2/.test(p)) },
  { id: 'pol-tls13', subject: 'TLS 1.3', verdict: 'required', rationale: 'Required baseline before X25519MLKEM768 can be negotiated.', standard: 'RFC 8446', test: (protocols) => protocols.length > 0 && !protocols.some((p) => /1\.3/.test(p)) },
]

const TARGET_RULES: readonly PolicyRule[] = [
  { id: 'pol-hybrid-kem', subject: 'X25519 + ML-KEM-768', verdict: 'preferred', rationale: 'Platform-preferred key establishment — protects against harvest-now-decrypt-later while preserving interoperability.', standard: 'FIPS 203' },
  { id: 'pol-mldsa', subject: 'ML-DSA-65 (SLH-DSA for long-lived roots)', verdict: 'preferred', rationale: 'Platform-preferred digital signature for certificates, tokens and code signing.', standard: 'FIPS 204 / FIPS 205' },
  { id: 'pol-aes256', subject: 'AES-256-GCM', verdict: 'required', rationale: 'Required symmetric baseline for a 128-bit post-quantum security margin.', standard: 'FIPS 197 / SP 800-38D' },
  { id: 'pol-sha3', subject: 'SHA3-256 / SHA3-512', verdict: 'preferred', rationale: 'Platform-preferred hash functions.', standard: 'FIPS 202' },
]

const PLATFORM_POLICY_RULES: readonly PolicyRule[] = [
  ...ALGORITHM_RULES.filter((rule) => rule.id !== 'pol-tls-legacy' && rule.id !== 'pol-tls12').map(({ id, subject, verdict, rationale, standard }) => ({ id, subject, verdict, rationale, standard })),
  ...TRANSPORT_RULES.map(({ id, subject, verdict, rationale, standard }) => ({ id, subject, verdict, rationale, standard })),
  ...TARGET_RULES,
]

function exceptionState(status: string, expiresAt: string | null, now: number): PolicyExceptionState {
  const s = status.toLowerCase()
  if (/reject|denied|declin/.test(s)) return 'rejected'
  if (expiresAt && new Date(expiresAt).getTime() < now) return 'expired'
  if (/approv|active|grant/.test(s)) return 'active'
  if (/request|pending|submit|review/.test(s) || !s) return 'requested'
  return 'other'
}

function evaluatePolicy(inputs: AgilityInputs, now: number, exceptionsAvailable: boolean): PolicyEvaluation {
  const violationMap = new Map<string, { assets: Set<string>; names: string[]; instances: number; observed: Set<string> }>()
  let evaluatedInstances = 0
  let compliantInstances = 0
  // Transport posture is evaluated PER ASSET, not per algorithm instance, and a
  // protocol-version string in the algorithm list is covered by it — counting
  // it again as a "compliant algorithm instance" double-counted one fact.
  let transportUnits = 0
  let compliantTransportUnits = 0

  const record = (ruleId: string, assetId: string, assetName: string, instances: number, observed: string) => {
    const entry = violationMap.get(ruleId) || { assets: new Set<string>(), names: [], instances: 0, observed: new Set<string>() }
    entry.assets.add(assetId)
    if (entry.names.length < 10 && !entry.names.includes(assetName)) entry.names.push(assetName)
    entry.instances += instances
    entry.observed.add(observed)
    violationMap.set(ruleId, entry)
  }

  for (const asset of inputs.assets) {
    if (!asset.hasEvidence) continue
    const protocols = protocolVersionsFor(asset)
    for (const algo of asset.algorithms) {
      // Policy rules apply to cryptography, not to scanner finding titles.
      if (!isCryptographicPrimitive(algo.algorithm)) continue
      if (algorithmRole(algo.algorithm) === 'protocol') continue
      evaluatedInstances += algo.instances
      const keySize = algo.keySizes[0] ?? 0
      // First matching rule only — one instance is one violation, never two.
      const rule = ALGORITHM_RULES.find((r) => r.status !== null && r.test(algo.algorithm, keySize))
      // An approved hybrid (X25519MLKEM768, Ed25519+ML-DSA) contains a classical
      // half by design; it is not a standalone classical algorithm.
      const hybrid = APPROVED_PQC_RE.test(algo.algorithm)
      if (rule && !(hybrid && rule.status === 'deprecated')) {
        record(rule.id, asset.id, asset.name, algo.instances, keySize ? `${algo.algorithm} ${keySize}-bit` : algo.algorithm)
      } else {
        compliantInstances += algo.instances
      }
    }

    if (protocols.length) {
      transportUnits += 1
      let transportViolated = false
      for (const rule of TRANSPORT_RULES) {
        if (!rule.test(protocols)) continue
        transportViolated = true
        record(rule.id, asset.id, asset.name, 1, protocols.join(', '))
      }
      if (!transportViolated) compliantTransportUnits += 1
    }
  }

  const rulesById = new Map<string, PolicyRule>([
    ...ALGORITHM_RULES.map((r) => [r.id, r] as [string, PolicyRule]),
    ...TRANSPORT_RULES.map((r) => [r.id, r] as [string, PolicyRule]),
  ])
  const violations: PolicyViolation[] = [...violationMap.entries()].map(([ruleId, entry]) => {
    const rule = rulesById.get(ruleId)!
    return {
      ruleId,
      subject: rule.subject,
      verdict: rule.verdict,
      severity: rule.verdict === 'block' ? 'critical' : rule.verdict === 'required' ? 'high' : 'medium',
      observed: [...entry.observed].slice(0, 6).join(', ') || EVIDENCE_UNAVAILABLE,
      assets: entry.assets.size,
      assetNames: entry.names,
      instances: entry.instances,
      remediation: rule.rationale,
    }
  })
  violations.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.instances - a.instances || a.ruleId.localeCompare(b.ruleId))

  const evaluatedUnits = evaluatedInstances + transportUnits
  const compliantUnits = compliantInstances + compliantTransportUnits

  const exceptions = inputs.policyExceptions.map((row) => {
    const status = str(row.status) || 'requested'
    const expiresAt = isoOrNull(row.expiration_date)
    return {
      id: str(row.id),
      policy: str(row.policy_violated) || 'Recorded exception',
      justification: str(row.justification) || EVIDENCE_UNAVAILABLE,
      status,
      state: exceptionState(status, expiresAt, now),
      expiresAt,
    }
  })

  return {
    policyName: 'QGuard Helix Mandatory PQC Stack',
    version: 'qguard-pqc-stack-v2',
    source: 'platform-mandatory-stack',
    evaluated: evaluatedUnits > 0,
    enforcement: {
      mode: 'evaluation-only',
      detail: 'Violations are evaluated against discovered evidence on every assessment. No enforcement point (policy engine, CI gate or TLS policy push) reports to this module, so the policy is not enforced here — enforce it through Live Migration Ops and the owning platforms.',
    },
    rules: [...PLATFORM_POLICY_RULES],
    violations,
    // Compliance spans BOTH unit kinds: algorithm instances and per-asset
    // transport posture.
    compliancePct: evaluatedUnits > 0 ? Math.round(pctOf(compliantUnits, evaluatedUnits)) : null,
    compliantInstances: compliantUnits,
    evaluatedInstances: evaluatedUnits,
    exceptions,
    exceptionsAvailable,
    basis: evaluatedUnits > 0
      ? `${evaluatedInstances} algorithm instance(s) and ${transportUnits} asset transport posture(s) evaluated against ${PLATFORM_POLICY_RULES.length} platform rules; ${violations.length} rule(s) violated. No tenant-configured policy engine is connected, so the platform mandatory stack is authoritative. Recorded exceptions are listed, not applied: their policy field is free text that cannot be matched to a rule reliably.`
      : `${EVIDENCE_UNAVAILABLE} — no algorithm instance or transport posture has been observed, so policy compliance cannot be evaluated.`,
  }
}

/* ================================================================== */
/* Runtime events, configuration changes, drift + history               */
/* ================================================================== */

interface OperationalJob {
  id: string
  assetId: string
  name: string
  jobType: string
  status: ReturnType<typeof orchestrationStatus>
  updatedAt: string | null
  targetAlgorithm: string
}

/**
 * Split migration jobs into OPERATIONAL work and sandbox simulations, through
 * the platform's shared predicates. A failed or completed simulation is not a
 * cryptographic change to any production asset.
 */
export function splitMigrationJobs(rows: Row[]): { operational: OperationalJob[]; simulations: Row[] } {
  const operational: OperationalJob[] = []
  const simulations: Row[] = []
  for (const row of rows) {
    if (isSimulationRow(row)) {
      simulations.push(row)
      continue
    }
    operational.push({
      id: str(row.id),
      assetId: str(row.asset_id),
      name: str(row.name),
      jobType: str(row.job_type),
      status: orchestrationStatus(row.status),
      updatedAt: isoOrNull(row.updated_at) || isoOrNull(row.created_at),
      targetAlgorithm: str(row.target_algorithm),
    })
  }
  return { operational, simulations }
}

/** Latest operational job per asset; withdrawn (stopped/cancelled) work is ignored. */
function latestOperationalJobByAsset(jobs: OperationalJob[]): Map<string, OperationalJob> {
  const latest = new Map<string, OperationalJob>()
  for (const job of jobs) {
    if (!job.assetId || job.status === 'stopped') continue
    const current = latest.get(job.assetId)
    const at = job.updatedAt ? Date.parse(job.updatedAt) : 0
    const currentAt = current?.updatedAt ? Date.parse(current.updatedAt) : 0
    if (!current || at > currentAt || (at === currentAt && job.id > current.id)) latest.set(job.assetId, job)
  }
  return latest
}

const byTimeThenId = <T extends { id: string }>(at: (row: T) => string | null) => (a: T, b: T) => {
  const ta = at(a) ? Date.parse(at(a) as string) : 0
  const tb = at(b) ? Date.parse(at(b) as string) : 0
  return tb - ta || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
}

/** Runtime OBSERVATIONS only — what collectors saw, with their own timestamps. */
function buildRuntimeEvents(inputs: AgilityInputs): RuntimeCryptoEvent[] {
  const assetsById = new Map(inputs.assets.map((a) => [a.id, a]))
  const events: RuntimeCryptoEvent[] = []
  for (const row of inputs.runtimeEvents.slice(0, 120)) {
    const assetId = str(row.asset_id)
    const asset = assetsById.get(assetId)
    const algorithm = str(row.algorithm) || str(row.key_exchange_algorithm) || str(row.cipher_suite) || EVIDENCE_UNAVAILABLE
    const isPqc = row.is_pqc === true
    const isLegacy = row.is_legacy === true
    const hndl = row.hndl_risk === true
    events.push({
      id: `rt-${str(row.id)}`,
      observedAt: isoOrNull(row.observed_at) || isoOrNull(row.created_at),
      asset: asset?.name || str(row.asset_name) || EVIDENCE_UNAVAILABLE,
      assetId,
      eventType: isPqc ? 'PQC / hybrid algorithm observed' : isLegacy ? 'Legacy algorithm observed' : hndl ? 'Harvest-now-decrypt-later exposure observed' : 'Cryptographic use observed',
      algorithm,
      source: 'Runtime Crypto Telemetry',
      severity: normalizeSeverity(str(row.severity)),
      // The collector's flag is reported as an observation — not as a
      // compliance verdict, which needs the policy evaluation.
      status: isPqc ? 'PQC observed' : isLegacy ? 'Legacy observed' : 'Observed',
      route: assetId ? `/dashboard/assets?asset=${encodeURIComponent(assetId)}` : '/dashboard/runtime-crypto-intel',
    })
  }
  return events.sort(byTimeThenId((e) => e.observedAt)).slice(0, 40)
}

const CONFIG_EVENT_RE = /crypto|cert|key|tls|algorithm|cipher|rotat|policy|provider|library|config/i

/**
 * Configuration-change tracking from RECORDED rows only: operational migration
 * jobs (simulations excluded) and security events that describe a
 * cryptographic configuration change. Nothing is inferred; when no row exists
 * the tracker says so.
 */
function buildChangeTracking(
  inputs: AgilityInputs,
  operational: OperationalJob[],
  validatedAssetIds: Set<string>,
  securityEventsAvailable: boolean,
  jobsAvailable: boolean,
): ChangeTracking {
  const assetsById = new Map(inputs.assets.map((a) => [a.id, a]))
  const changes: ConfigurationChange[] = []
  for (const job of operational) {
    const kind: ConfigurationChange['kind'] | null =
      job.status === 'completed' ? 'migration-completed'
        : job.status === 'failed' || job.status === 'rolled_back' ? 'migration-failed'
          : job.status === 'running' || job.status === 'validating' ? 'migration-in-progress'
            : null
    if (!kind) continue
    const validated = kind === 'migration-completed' ? validatedAssetIds.has(job.assetId) : null
    changes.push({
      id: `job-${job.id}`,
      at: job.updatedAt,
      kind,
      asset: assetsById.get(job.assetId)?.name || job.name || EVIDENCE_UNAVAILABLE,
      assetId: job.assetId,
      detail: kind === 'migration-completed'
        ? validated ? `Migration completed and a passing validation is recorded.` : `Migration completed — no passing validation recorded, so the change is NOT verified.`
        : kind === 'migration-failed' ? `Migration ${job.status === 'rolled_back' ? 'rolled back' : 'failed'} — the asset remains on its previous cryptography.`
          : `Migration ${job.status} (${job.jobType || 'migration'}).`,
      algorithm: job.targetAlgorithm || EVIDENCE_UNAVAILABLE,
      validated,
      source: 'Migration Jobs (operational)',
      route: '/dashboard/live-migration',
    })
  }
  for (const row of inputs.securityEvents) {
    const type = str(row.event_type)
    if (!CONFIG_EVENT_RE.test(type) || /sandbox|simulation/i.test(type)) continue
    changes.push({
      id: `sec-${str(row.id)}`,
      at: isoOrNull(row.created_at),
      kind: 'config-event',
      asset: str(row.resource_name) || EVIDENCE_UNAVAILABLE,
      assetId: '',
      detail: str(row.message) || type.replace(/[_-]/g, ' '),
      algorithm: EVIDENCE_UNAVAILABLE,
      validated: null,
      source: 'Security Events',
      route: '/dashboard/audit-vault',
    })
  }
  changes.sort(byTimeThenId((c) => c.at))
  const sources = [
    jobsAvailable ? 'Migration Jobs (operational, simulations excluded)' : '',
    securityEventsAvailable ? 'Security Events (cryptographic configuration types)' : '',
  ].filter(Boolean)
  const unreadable = [!jobsAvailable ? 'migration jobs' : '', !securityEventsAvailable ? 'security events' : ''].filter(Boolean)
  return {
    changes: changes.slice(0, 40),
    total: changes.length,
    lastChangeAt: changes[0]?.at ?? null,
    sources,
    note: unreadable.length
      ? `${unreadable.join(' and ')} could not be read — the change log is incomplete, not empty.`
      : changes.length
        ? `${changes.length} recorded change(s). Sandbox simulations are excluded; a completed migration counts as verified only with a passing validation record.`
        : 'No cryptographic configuration change has been recorded for this tenant. Changes appear here when Live Migration executes a job or a cryptographic configuration event is logged.',
  }
}

const MONTH_LABEL = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/**
 * Reconstructs the component trend from evidence TIMESTAMPS the tenant
 * already holds, bucketed by UTC CALENDAR MONTH. Bucket edges are anchored to
 * the evidence, never to the time of the request: anchoring them to `now`
 * moved every point on every recompute, so the live stream re-sent the full
 * payload each tick although nothing had changed. The final point is the live
 * assessment, stamped with the latest evidence time.
 */
function buildHistory(
  inputs: AgilityInputs,
  currentScore: number | null,
  currentBlockers: number,
  policyPct: number | null,
  currentReadinessPct: number | null,
): AssessmentHistoryPoint[] {
  const dated = inputs.cryptoInventory
    .map((item) => ({
      at: isoOrNull(item.discovered_at) || isoOrNull(item.created_at),
      vulnerable: item.is_vulnerable === true || classifyAlgorithm(str(item.algorithm)) === 'vulnerable',
      pqc: item.is_quantum_safe === true || ['pqc', 'hybrid'].includes(classifyAlgorithm(str(item.algorithm))),
    }))
    .filter((row): row is { at: string; vulnerable: boolean; pqc: boolean } => Boolean(row.at))
    .map((row) => ({ ...row, ms: Date.parse(row.at) }))
    .filter((row) => Number.isFinite(row.ms))

  if (dated.length < 2) return []

  const monthKey = (ms: number) => {
    const d = new Date(ms)
    return d.getUTCFullYear() * 12 + d.getUTCMonth()
  }
  const months = unique(dated.map((r) => monthKey(r.ms))).sort((a, b) => a - b).slice(-6)
  const latestMs = Math.max(...dated.map((r) => r.ms))

  const points: AssessmentHistoryPoint[] = months.map((key) => {
    const year = Math.floor(key / 12)
    const month = key % 12
    const end = Date.UTC(year, month + 1, 1) - 1
    const upTo = dated.filter((r) => r.ms <= end)
    return {
      at: new Date(end).toISOString(),
      label: `${MONTH_LABEL[month]} ${String(year).slice(2)}`,
      // No agility score for a reconstructed point: coupling, ownership and
      // dependency evidence has no historical snapshot.
      agilityScore: null,
      pqcAdoptionPct: Math.round(pctOf(upTo.filter((r) => r.pqc).length, upTo.length)),
      vulnerableSharePct: Math.round(pctOf(upTo.filter((r) => r.vulnerable).length, upTo.length)),
      migrationReadinessPct: null,
      blockers: 0,
      policyCompliancePct: null,
      assetsEvaluated: 0,
      componentsObserved: upTo.length,
      drift: 'unknown',
      reconstructed: true,
    }
  })

  if (points.length) {
    // The last month bucket already holds every dated component, so it IS the
    // live composition; it carries the live figures and the latest evidence time.
    const last = points[points.length - 1]
    last.agilityScore = currentScore
    last.blockers = currentBlockers
    last.policyCompliancePct = policyPct
    last.migrationReadinessPct = currentReadinessPct
    last.assetsEvaluated = inputs.assets.filter((a) => a.hasEvidence).length
    last.reconstructed = false
    last.label = 'Latest'
    last.at = new Date(latestMs).toISOString()
  }

  for (let index = 1; index < points.length; index += 1) {
    const prev = points[index - 1].pqcAdoptionPct
    const curr = points[index].pqcAdoptionPct
    if (prev === null || curr === null) continue
    points[index].drift = curr > prev + 2 ? 'improving' : curr < prev - 10 ? 'critical' : curr < prev - 2 ? 'degrading' : 'stable'
  }

  return points
}

function buildDrift(
  inputs: AgilityInputs,
  history: AssessmentHistoryPoint[],
  coupling: CouplingFinding[],
  operational: OperationalJob[],
  now: number,
): AgilityDrift {
  // Windows are genuinely time-bounded: a count changes when an event ages
  // past 30 days, which is a real change of state, not recompute noise.
  const windowMs = 30 * 86400000
  const within = (iso: string | null) => (iso ? now - Date.parse(iso) <= windowMs : false)
  const recentRuntime = inputs.runtimeEvents.filter((e) => within(isoOrNull(e.observed_at) || isoOrNull(e.created_at)))
  const newLegacy = recentRuntime.filter((e) => e.is_legacy === true).length
  const newPqc = recentRuntime.filter((e) => e.is_pqc === true).length
  const newCertificates = inputs.certificates.filter((c) => within(isoOrNull(c.created_at))).length
  const staticAnchors = coupling.filter((c) => c.type === 'static-trust-anchor').length
  const providerChanges = inputs.securityEvents.filter((e) => /provider|library|crypto_config|configuration/i.test(str(e.event_type)) && within(isoOrNull(e.created_at))).length
  const failedChanges = operational.filter((j) => (j.status === 'failed' || j.status === 'rolled_back') && within(j.updatedAt)).length

  const signals: AgilityDrift['signals'] = [
    { label: 'Legacy algorithms re-observed', count: newLegacy, tone: newLegacy > 0 ? 'critical' : 'neutral', detail: 'Runtime events flagged as legacy cryptography in the last 30 days.' },
    { label: 'PQC / hybrid observations', count: newPqc, tone: newPqc > 0 ? 'good' : 'neutral', detail: 'Runtime events negotiating post-quantum or hybrid primitives in the last 30 days.' },
    { label: 'New certificates introduced', count: newCertificates, tone: newCertificates > 0 ? 'warning' : 'neutral', detail: 'Certificates first recorded in the last 30 days — each adds a chain that must be re-issued.' },
    { label: 'Static trust anchors', count: staticAnchors, tone: staticAnchors > 0 ? 'warning' : 'neutral', detail: 'Self-signed or privately operated anchors currently recorded; they gate chain replacement.' },
    { label: 'Provider / configuration events', count: providerChanges, tone: 'neutral', detail: 'Security events describing a cryptographic provider or configuration change in the last 30 days.' },
    { label: 'Failed cryptographic changes', count: failedChanges, tone: failedChanges > 0 ? 'critical' : 'neutral', detail: 'Operational migration jobs (simulations excluded) that failed or rolled back in the last 30 days.' },
  ]

  let direction: DriftDirection = 'unknown'
  let deltaPoints: number | null = null

  // Direction is measured on PQC ADOPTION, the only series recorded identically
  // at every historical point. It is NOT the agility score.
  const adoption = history.filter((p) => p.pqcAdoptionPct !== null)
  if (adoption.length >= 2) {
    const first = adoption[adoption.length - 2].pqcAdoptionPct as number
    const last = adoption[adoption.length - 1].pqcAdoptionPct as number
    deltaPoints = last - first
    if (deltaPoints > 2) direction = 'improving'
    else if (deltaPoints < -10) direction = 'critical'
    else if (deltaPoints < -2) direction = 'degrading'
    else direction = 'stable'
  }
  // Newly re-observed legacy cryptography is a live regression even if the
  // CBOM composition has not moved; a failed operational change is critical.
  if (newLegacy > 0 && (direction === 'stable' || direction === 'improving')) direction = 'degrading'
  if (failedChanges > 0 && direction !== 'unknown') direction = 'critical'

  const basisParts: string[] = []
  if (adoption.length >= 2) {
    basisParts.push(`PQC component share moved ${deltaPoints !== null && deltaPoints > 0 ? '+' : ''}${deltaPoints} point(s) between the last two monthly evidence buckets.`)
  } else {
    basisParts.push(`${EVIDENCE_UNAVAILABLE} — evidence from at least two calendar months is required to measure a component trend.`)
  }
  basisParts.push(
    inputs.runtimeEvents.length
      ? `${recentRuntime.length} runtime event(s), ${newCertificates} new certificate(s) and ${failedChanges} failed operational change(s) in the last 30 days.`
      : 'No runtime cryptographic telemetry, so live drift cannot be observed in operation.',
  )

  return {
    direction,
    deltaPoints,
    windowLabel: adoption.length >= 2 ? 'PQC component share · last two monthly buckets' : 'Last 30 days',
    signals,
    trend: history.map((p) => ({
      label: p.label,
      at: p.at,
      agilityScore: p.agilityScore,
      vulnerableShare: p.vulnerableSharePct,
      pqcShare: p.pqcAdoptionPct,
      evidenceCount: p.componentsObserved,
    })),
    basis: basisParts.join(' '),
  }
}

/* ================================================================== */
/* Lifecycle                                                           */
/* ================================================================== */

/**
 * The transition pipeline. Every stage is a REAL share with a stated
 * denominator, or a count with no share — existence of one row never reads as
 * "100% complete" (one sandbox job used to mark Simulate complete for the
 * whole estate; one scan session marked Repeat complete).
 */
function buildLifecycle(
  inputs: AgilityInputs,
  assetRows: AgilityAssetRow[],
  blockers: AgilityBlocker[],
  operational: OperationalJob[],
  simulations: Row[],
  validatedAssetIds: Set<string>,
): LifecycleStage[] {
  const evaluated = assetRows.filter((r) => r.hasEvidence)
  const assessed = evaluated.filter((r) => r.couplingAssessed)
  const decoupled = assessed.filter((r) => r.replaceability === 'configuration').length
  const evaluatedIds = new Set(evaluated.map((r) => r.id))
  const simulatedAssets = unique(simulations.map((j) => str(j.asset_id)).filter((id) => evaluatedIds.has(id))).length
  const live = operational.filter((j) => j.status !== 'stopped')
  const completedJobs = live.filter((j) => j.status === 'completed')
  const completedAssets = unique(completedJobs.map((j) => j.assetId).filter(Boolean))
  const validatedCompleted = completedAssets.filter((id) => validatedAssetIds.has(id)).length
  const monitored = unique(inputs.runtimeEvents.map((e) => str(e.asset_id)).filter(Boolean)).length
  const completedScans = inputs.scanSessions.filter((s) => /complete|done|success/i.test(str(s.status)))
  const latestScan = completedScans
    .map((s) => isoOrNull(s.completed_at) || isoOrNull(s.created_at))
    .filter((v): v is string => Boolean(v))
    .sort()
    .pop() ?? null

  const share = (
    key: string, label: string, description: string, count: number, of: number,
    metric: string, route: string, module: string, blocked = false,
  ): LifecycleStage => {
    const progressPct = of > 0 ? Math.round(pctOf(count, of)) : null
    return {
      key,
      label,
      description,
      status: blocked ? 'blocked' : progressPct === null ? 'pending' : progressPct >= 100 ? 'complete' : progressPct > 0 ? 'active' : 'pending',
      progressPct,
      count,
      of: of > 0 ? of : null,
      metric,
      route,
      module,
    }
  }
  const tally = (key: string, label: string, description: string, count: number, metric: string, route: string, module: string): LifecycleStage => ({
    key, label, description, status: count > 0 ? 'complete' : 'pending', progressPct: null, count, of: null, metric, route, module,
  })

  return [
    tally('discover', 'Discover', 'Find every cryptographic asset and dependency.', assetRows.length, `${assetRows.length} asset(s) discovered`, '/dashboard/scanner', 'PQC Scanner'),
    share('map', 'Map', 'Bind cryptographic evidence to each asset.', evaluated.length, assetRows.length, `${evaluated.length} of ${assetRows.length} asset(s) carry cryptographic evidence`, '/dashboard/cbom_explorer', 'CBOM Explorer'),
    share('assess', 'Assess coupling', 'Evidence deep enough to see hard-coded cryptography (source, library or runtime).', assessed.length, evaluated.length, `${assessed.length} of ${evaluated.length} evaluated asset(s) coupling-assessed`, '/dashboard/scanner', 'PQC Scanner'),
    share(
      'decouple', 'Decouple', 'Externalise cryptography so a change becomes configuration.',
      decoupled, assessed.length, `${decoupled} of ${assessed.length} coupling-assessed asset(s) configuration-replaceable`,
      '/dashboard/crypto-agility', 'Crypto Agility',
      blockers.some((b) => b.category === 'hardcoded-crypto' && b.severity === 'critical'),
    ),
    share('simulate', 'Simulate', 'Prove the change in the digital twin before touching production.', simulatedAssets, evaluated.length, `${simulatedAssets} of ${evaluated.length} evaluated asset(s) have a sandbox simulation`, '/dashboard/migration-sandbox', 'Migration Sandbox'),
    share('migrate', 'Migrate', 'Execute the approved change (operational jobs only — simulations excluded).', completedJobs.length, live.length, `${completedJobs.length} of ${live.length} operational job(s) completed`, '/dashboard/live-migration', 'Live Migration Ops'),
    share('validate', 'Validate', 'A completed change counts only with a passing validation record.', validatedCompleted, completedAssets.length, `${validatedCompleted} of ${completedAssets.length} migrated asset(s) validated`, '/dashboard/migration-timeline', 'Migration Timeline'),
    share('monitor', 'Monitor', 'Detect cryptographic drift in operation.', monitored, assetRows.length, `${monitored} of ${assetRows.length} asset(s) under runtime telemetry`, '/dashboard/runtime-crypto-intel', 'Runtime Crypto Intelligence'),
    tally('rescan', 'Re-scan', 'Re-run discovery so newly introduced cryptography is caught.', completedScans.length, latestScan ? `${completedScans.length} completed scan(s) · latest ${latestScan.slice(0, 10)}` : 'No completed scan recorded', '/dashboard/scanner', 'PQC Scanner'),
  ]
}

/* ================================================================== */
/* Recommendations                                                     */
/* ================================================================== */

function buildRecommendations(
  domains: AgilityDomain[],
  blockers: AgilityBlocker[],
  coupling: CouplingFinding[],
  assetRows: AgilityAssetRow[],
  policy: PolicyEvaluation,
  dependencyRelationships: number,
  relationshipsTouching: (assetIds: Set<string>) => number,
): AgilityRecommendation[] {
  const recommendations: AgilityRecommendation[] = []

  for (const blocker of blockers.slice(0, 5)) {
    const affected = new Set(blocker.affectedAssetIds)
    recommendations.push({
      id: `rec-${blocker.id}`,
      title: `Resolve ${blocker.count} ${blocker.categoryLabel.toLowerCase()} finding(s)`,
      detail: `${blocker.remediation} ${blocker.businessImpact}`,
      severity: blocker.severity,
      // Clearing a blocker changes evidence the score is computed from; the
      // effect is not modelled here, so no "+N points" is promised.
      expectedScoreGain: null,
      affectedAssets: blocker.affectedAssetIds.length,
      // Share of the recorded dependency relationships with an end on an affected asset.
      dependencyReductionPct: dependencyRelationships > 0 ? Math.round(pctOf(relationshipsTouching(affected), dependencyRelationships)) : null,
      controlDomain: blocker.controlDomain,
      action: blocker.controlDomain === 'customer' ? 'Create Remediation Plan' : 'Track Provider Dependency',
      route: blocker.route,
      evidence: coupling
        .filter((c) => affected.has(c.assetId))
        .slice(0, 4)
        .map((c) => `${c.asset}: ${c.evidence}`),
    })
  }

  const weakestScored = domains
    .filter((d) => d.score !== null)
    .sort((a, b) => (a.score as number) - (b.score as number) || a.key.localeCompare(b.key))[0]
  if (weakestScored && weakestScored.actions.length) {
    recommendations.push({
      id: `rec-domain-${weakestScored.key}`,
      title: `Lift ${weakestScored.label} — currently ${weakestScored.score}/100`,
      detail: `${weakestScored.actions[0]} ${weakestScored.basis}`,
      severity: (weakestScored.score as number) < 40 ? 'high' : 'medium',
      // Upper bound on the PUBLISHED score: the domain's renormalised weight
      // times its remaining headroom (before the blocker penalty).
      expectedScoreGain: weakestScored.improvementOpportunity,
      affectedAssets: weakestScored.affectedAssets,
      dependencyReductionPct: null,
      controlDomain: 'customer',
      action: 'Open Domain Detail',
      route: weakestScored.route,
      evidence: [weakestScored.basis],
    })
  }

  const unmeasured = domains.filter((d) => d.score === null)
  if (unmeasured.length) {
    recommendations.push({
      id: 'rec-evidence',
      title: `Close the evidence gap on ${unmeasured.length} unmeasured agility domain(s)`,
      detail: `${unmeasured.map((d) => d.label).join(', ')} cannot be scored. Unknown is not safe — these domains are excluded from the score, so the headline describes only what is measured.`,
      severity: 'medium',
      expectedScoreGain: null,
      affectedAssets: 0,
      dependencyReductionPct: null,
      controlDomain: 'customer',
      action: 'Run Discovery Scan',
      route: '/dashboard/scanner',
      evidence: unmeasured.map((d) => `${d.label}: ${d.basis}`),
    })
  }

  const criticalViolation = policy.violations.find((v) => v.severity === 'critical')
  if (criticalViolation) {
    recommendations.push({
      id: `rec-policy-${criticalViolation.ruleId}`,
      title: `Policy BLOCK: ${criticalViolation.subject} in use on ${criticalViolation.assets} asset(s)`,
      detail: `${criticalViolation.remediation} Observed: ${criticalViolation.observed}.`,
      severity: 'critical',
      expectedScoreGain: null,
      affectedAssets: criticalViolation.assets,
      dependencyReductionPct: null,
      controlDomain: 'customer',
      action: 'Create Remediation Plan',
      route: '/dashboard/quantum-remediation',
      evidence: criticalViolation.assetNames,
    })
  }

  return recommendations
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.expectedScoreGain ?? -1) - (a.expectedScoreGain ?? -1) || a.id.localeCompare(b.id))
    .slice(0, 8)
}

/* ================================================================== */
/* Change impact preview (sandbox pre-flight)                          */
/* ================================================================== */

const PQC_SIGNATURE_RE = /ML-?DSA|SLH-?DSA/i

/**
 * Deterministic impact PROJECTION for a proposed cryptographic change.
 *
 * Arithmetic over evidence the platform already holds — it does NOT simulate.
 * Execution belongs to the Migration Sandbox digital twin
 * (`POST /api/v1/sandbox/simulate`), which the page hands off to. The proposed
 * path is checked with the SAME role rule PQC Orchestration uses, so an
 * ML-KEM "replacement" for a signature is reported, never projected as fine.
 */
export function previewChangeImpact(
  inputs: AgilityInputs,
  derivations: Map<string, AssetAgilityDerivation>,
  assetId: string,
  fromAlgorithm?: string,
  toAlgorithm?: string,
): ChangeImpactPreview | null {
  const asset = inputs.assets.find((a) => a.id === assetId)
  if (!asset) return null
  const derivation = derivations.get(assetId)

  const certAlgorithms = new Set(asset.certificates.map((c) => c.algorithm.toUpperCase()))
  const primitives = asset.algorithms.filter((a) => isCryptographicPrimitive(a.algorithm))
  const verdictOf = (algorithm: string) => {
    const row = primitives.find((a) => a.algorithm.toUpperCase() === algorithm.toUpperCase())
    return classifyAlgorithmStatus(algorithm, {
      minKeySize: row?.keySizes[0],
      asCertificate: certAlgorithms.has(algorithm.toUpperCase()),
      // Status of a deprecated/unsupported algorithm does not depend on this;
      // the preview never upgrades anything to "approved".
      observedInOperation: false,
    })
  }
  const worst = primitives.find((a) => verdictOf(a.algorithm).status === 'unsupported') ?? primitives.find((a) => verdictOf(a.algorithm).status === 'deprecated')
  const from = fromAlgorithm || worst?.algorithm || primitives[0]?.algorithm || EVIDENCE_UNAVAILABLE
  const fromVerdict = verdictOf(from)
  const to = toAlgorithm || approvedTargetFor(fromVerdict.role, fromVerdict.status).target
  const roleHint = fromVerdict.role === 'signature' ? 'signature' : fromVerdict.role === 'key-establishment' || fromVerdict.role === 'protocol' || fromVerdict.role === 'cipher-suite' ? 'key-exchange' : ''
  const roleCheck = migrationPathCheck(from, to, roleHint)

  const potentialFailures: ChangeImpactPreview['potentialFailures'] = []
  for (const dependency of asset.dependencies.slice(0, 8)) {
    potentialFailures.push({
      label: `${dependency.name} — ${dependency.relationship}`,
      detail:
        dependency.direction === 'upstream'
          ? 'This peer calls the asset; it must accept the replacement stack or the call path fails after cutover.'
          : 'The asset calls this peer; the peer must negotiate the replacement stack or the dependency breaks.',
      severity: dependency.posture === 'vulnerable' ? 'high' : dependency.riskScore >= 60 ? 'medium' : 'low',
    })
  }
  if (protocolVersionsFor(asset).some((p) => LEGACY_PROTOCOL_RE.test(p))) {
    potentialFailures.push({
      label: 'Deprecated TLS clients',
      detail: 'Clients pinned below TLS 1.3 cannot negotiate a hybrid named group and will fail the handshake.',
      severity: 'high',
    })
  }
  for (const cert of asset.certificates.filter((c) => !PQC_SIGNATURE_RE.test(c.algorithm)).slice(0, 3)) {
    potentialFailures.push({
      label: `${cert.name} — certificate chain`,
      detail: 'The classical chain must be re-issued from a CA that can sign ML-DSA; un-reissued leaves stay classical after cutover.',
      severity: cert.daysToExpiry !== null && cert.daysToExpiry < 30 ? 'high' : 'medium',
    })
  }
  if (roleCheck.check === 'role-mismatch') {
    potentialFailures.unshift({ label: 'Proposed algorithm does the wrong job', detail: roleCheck.note, severity: 'critical' })
  }
  if (!potentialFailures.length) {
    potentialFailures.push({
      label: 'No recorded dependency would be affected',
      detail: 'No peer relationship, legacy transport or classical certificate is recorded for this asset. Absence of a record is not proof that nothing depends on it — run the change in the Migration Sandbox.',
      severity: 'info',
    })
  }

  const trustDeps = asset.dependencies.filter((d) => /trust|cert|identity|kms|federat|sign/i.test(d.relationship)).length
  const migrationRiskScore = Math.round(
    clamp(asset.riskScore * 0.35 + (100 - asset.compatibility.score) * 0.35 + Math.min(100, asset.blastRadius * 8) * 0.3),
  )

  return {
    kind: 'projection',
    assetId,
    asset: asset.name,
    fromAlgorithm: from,
    toAlgorithm: to,
    assetsAffected: 1 + asset.blastRadius,
    dependencies: asset.blastRadius,
    potentialFailures,
    compatibility: asset.compatibility.level,
    compatibilityScore: asset.compatibility.score,
    trustImpact: trustDeps
      ? `${trustDeps} trust relationship(s) re-negotiate under the replacement chain.`
      : 'No trust-chain relationship recorded for this asset.',
    migrationRisk: riskLevelFromScore(migrationRiskScore),
    migrationRiskScore,
    expectedRemediation: asset.recommendations.slice(0, 5).map((r) => r.title),
    replaceability: derivation?.replaceability ?? 'unknown',
    roleCheck,
    basis: `Projection over ${asset.evidence.sources.join(', ') || 'asset evidence'}: migration risk = 0.35 × asset risk (${asset.riskScore}) + 0.35 × (100 − compatibility ${asset.compatibility.score}) + 0.30 × min(100, 8 × ${asset.blastRadius} dependency relationship(s)). This preview does not simulate — the Migration Sandbox digital twin runs the change.`,
  }
}

/* ================================================================== */
/* Engine entry point                                                  */
/* ================================================================== */

export function buildCryptoAgilityIntelligence(inputs: AgilityInputs): CryptoAgilityIntelligence {
  const now = inputs.now ?? Date.now()
  const assetsById = new Map(inputs.assets.map((a) => [a.id, a]))

  /* ---- 1. Coupling analysis --------------------------------------- */
  const providerLocked = new Map<string, string>()
  const sr = inputs.snapshot.sharedResponsibility
  if (sr) {
    for (const finding of sr.findings) {
      if (finding.domain === 'customer' || finding.customerActionable === 'yes') continue
      const id = findByAssetName(assetsById, finding.asset)
      if (id && !providerLocked.has(id)) providerLocked.set(id, finding.responsibleParty)
    }
  }

  const ctx: CouplingContext = {
    assetsById,
    inventoryByAsset: new Map(),
    exposuresByAsset: new Map(),
    certificatesByAsset: new Map(),
    keyRotationAssetIds: new Set(),
    providerLockedAssets: providerLocked,
  }
  const coupling = buildCouplingFindings(inputs, ctx)

  const couplingByAsset = new Map<string, CouplingFinding[]>()
  for (const finding of coupling) {
    const list = couplingByAsset.get(finding.assetId) || []
    list.push(finding)
    couplingByAsset.set(finding.assetId, list)
  }

  /* ---- 2. Per-asset agility --------------------------------------- */
  // Sources the router could not read. Fixtures omit `sourceHealth`: every
  // source then counts as read.
  const sourceStatus = inputs.sourceHealth ?? defaultSourceHealth(inputs)
  const readable = (key: string) => !sourceStatus.some((s) => s.key === key && s.state === 'unavailable')

  const { operational, simulations } = splitMigrationJobs(inputs.migrationJobs)
  const latestJobs = latestOperationalJobByAsset(operational)
  const validatedAssetIds = new Set(inputs.assets.filter((a) => isPassingValidation(a.validation.lastStatus)).map((a) => a.id))
  const provenanceIndex = buildProvenanceIndex(inputs)

  const couplingObservableAssets = observableCouplingAssets(inputs)
  const derivations = new Map<string, AssetAgilityDerivation>()
  for (const asset of inputs.assets) {
    derivations.set(asset.id, deriveAssetAgility(asset, couplingByAsset, providerLocked, couplingObservableAssets, latestJobs.get(asset.id) ?? null))
  }

  const assetRows: AgilityAssetRow[] = inputs.assets.map((asset) => {
    const derivation = derivations.get(asset.id)!
    const algorithmStatusCounts: Record<AlgorithmStatus, number> = { unsupported: 0, deprecated: 0, configured: 0, approved: 0, detected: 0, unknown: 0 }
    for (const algo of asset.algorithms) {
      if (!isCryptographicPrimitive(algo.algorithm)) continue
      const provenance = provenanceIndex.get(asset.id)?.get(algo.algorithm.trim().toUpperCase())
      const status = classifyAlgorithmStatus(algo.algorithm, {
        minKeySize: algo.keySizes[0],
        asCertificate: Boolean(provenance && provenance.size === 1 && provenance.has('certificate')),
        observedInOperation: [...(provenance ?? [])].some((p) => OPERATIONAL_PROVENANCE.has(p)),
      }).status
      algorithmStatusCounts[status] += 1
    }
    const targets = unique(asset.algorithms.filter((a) => a.classification !== 'pqc').map((a) => a.target)).slice(0, 3)
    const nextAction =
      derivation.state === 'blocked'
        ? 'Resolve blocker'
        : derivation.state === 'unknown'
          ? 'Run discovery scan'
          : derivation.readiness === 'ready'
            ? 'Run in Migration Sandbox'
            : 'Decouple cryptography'
    const nextActionRoute =
      derivation.state === 'unknown'
        ? '/dashboard/scanner'
        : derivation.readiness === 'ready'
          ? '/dashboard/migration-sandbox'
          : `/dashboard/assets?asset=${encodeURIComponent(asset.id)}`

    return {
      id: asset.id,
      name: asset.name,
      type: asset.type,
      environment: asset.environment,
      owner: asset.owner,
      businessCriticality: asset.businessCriticality,
      internetFacing: asset.internetFacing,
      hasEvidence: asset.hasEvidence,
      couplingAssessed: derivation.couplingObservable,
      agilityState: derivation.state,
      agilityScore: derivation.score,
      replaceability: derivation.replaceability,
      replaceabilityLabel: REPLACEABILITY_LABEL[derivation.replaceability],
      readiness: derivation.readiness,
      readinessLabel: MIGRATION_READINESS_LABEL[derivation.readiness],
      currentAlgorithms: unique(asset.algorithms.map((a) => a.algorithm)).slice(0, 4),
      targetAlgorithms: targets,
      dependencies: asset.blastRadius,
      blockers: derivation.blockerReasons.length,
      blockerReasons: derivation.blockerReasons,
      couplingFindings: derivation.couplingFindings.length,
      componentCount: asset.componentCount,
      vulnerableComponentCount: asset.vulnerableComponentCount,
      riskScore: asset.riskScore,
      priority: asset.priority,
      controlDomain: derivation.controlDomain,
      migrationStatus: asset.migrationStatus,
      nextAction,
      nextActionRoute,
      lastEvidenceAt: asset.lastEvidenceAt,
      basis: derivation.basis,
      scoreFactors: derivation.scoreFactors,
      operationalJob: derivation.operationalJob
        ? { status: derivation.operationalJob.status, updatedAt: derivation.operationalJob.updatedAt, targetAlgorithm: derivation.operationalJob.targetAlgorithm }
        : null,
      validated: derivation.validated,
      algorithmStatusCounts,
    }
  })

  /* ---- 3. Distribution -------------------------------------------- */
  const stateOrder: AgilityState[] = ['agile', 'conditional', 'rigid', 'blocked', 'unknown']
  const distribution: AgilityDistributionBucket[] = stateOrder.map((state) => {
    const count = assetRows.filter((r) => r.agilityState === state).length
    return {
      state,
      label: AGILITY_STATE_LABEL[state],
      definition: AGILITY_STATE_DEFINITION[state],
      count,
      share: Math.round(pctOf(count, Math.max(1, assetRows.length))),
    }
  })

  /* ---- 4. Domains -------------------------------------------------- */
  const domains = scoreDomains(inputs, assetRows, derivations, coupling)

  /* ---- 5. Blockers, matrix, graph, policy -------------------------- */
  const blockers = buildBlockers(inputs, coupling, assetRows)
  const matrix = buildReplaceabilityMatrix(inputs, derivations, provenanceIndex)
  const replaceability = matrix.rows
  const transitions = buildTransitionLanes(replaceability)
  const algorithmStatus = summarizeAlgorithmStatus(replaceability)
  const graph = buildCouplingGraph(inputs, derivations, coupling, provenanceIndex)
  const policy = evaluatePolicy(inputs, now, readable('quantum_governance_exceptions'))

  /* ---- 6. Headline score ------------------------------------------- */
  const scored = domains.filter((d) => d.score !== null)
  const scoredWeight = scored.reduce((sum, d) => sum + d.weight, 0)
  const weightedSum = scored.reduce((sum, d) => sum + (d.score as number) * d.weight, 0)
  const rawScore = scoredWeight > 0 ? weightedSum / scoredWeight : null

  // Unresolved CRITICAL blockers cap the ceiling: an estate with a blocked
  // change is not agile no matter how well the measurable domains score. The
  // penalty is bounded so it can never dominate the evidence.
  const criticalBlockers = blockers.filter((b) => b.severity === 'critical').length
  const highBlockers = blockers.filter((b) => b.severity === 'high').length
  const blockedAssets = assetRows.filter((r) => r.agilityState === 'blocked').length
  const blockerPenalty = rawScore === null
    ? 0
    : Math.min(18, criticalBlockers * 5 + highBlockers * 2 + Math.min(6, Math.round(pctOf(blockedAssets, Math.max(1, assetRows.length)) / 10)))

  const agilityScore = rawScore === null ? null : Math.round(clamp(rawScore - blockerPenalty))

  const readyCount = assetRows.filter((r) => r.readiness === 'ready').length
  const conditionalCount = assetRows.filter((r) => r.readiness === 'conditional').length
  const blockedCount = assetRows.filter((r) => r.readiness === 'blocked').length
  const unknownCount = assetRows.filter((r) => r.readiness === 'unknown').length
  const evaluatedForReadiness = readyCount + conditionalCount + blockedCount
  const migrationReadinessPct = evaluatedForReadiness > 0
    ? Math.round(clamp(((readyCount + conditionalCount * 0.5) / evaluatedForReadiness) * 100))
    : null

  /* ---- 7. History + drift ------------------------------------------ */
  const history = buildHistory(inputs, agilityScore, blockers.length, policy.compliancePct, migrationReadinessPct)
  const drift = buildDrift(inputs, history, coupling, operational, now)

  /* ---- 8. Responsibility matrix ------------------------------------ */
  const stateByAssetName = new Map(assetRows.map((r) => [r.name.toLowerCase(), r.agilityState]))
  const responsibility: ResponsibilityRow[] = sr
    ? sr.matrix.map((row) => ({
        id: row.findingId,
        finding: row.finding,
        asset: row.asset,
        owner: row.owner,
        userAction: row.action,
        priority: normalizeSeverity(row.priority),
        controlDomain: row.domain,
        controlDomainLabel: CONTROL_DOMAIN_LABEL[row.domain],
        status: row.status,
        occurrences: row.occurrences,
        agilityState: stateByAssetName.get(row.asset.toLowerCase()) ?? 'unknown',
      }))
    : []

  // Coupling findings that the ownership engine did not already carry — the
  // agility-specific rows an operator must still own.
  const seenFindings = new Set(responsibility.map((r) => `${r.finding}|${r.asset}`.toLowerCase()))
  for (const finding of coupling.slice(0, 40)) {
    const key = `${finding.title}|${finding.asset}`.toLowerCase()
    if (seenFindings.has(key)) continue
    seenFindings.add(key)
    responsibility.push({
      id: finding.id,
      finding: finding.title,
      asset: finding.asset,
      owner: finding.owner,
      userAction: finding.remediation,
      priority: finding.severity,
      controlDomain: finding.controlDomain,
      controlDomainLabel: CONTROL_DOMAIN_LABEL[finding.controlDomain],
      status: 'Open',
      occurrences: 1,
      agilityState: stateByAssetName.get(finding.asset.toLowerCase()) ?? 'unknown',
    })
  }
  responsibility.sort((a, b) => SEVERITY_RANK[b.priority] - SEVERITY_RANK[a.priority] || b.occurrences - a.occurrences)

  /* ---- 9. Lifecycle + recommendations + runtime -------------------- */
  const lifecycle = buildLifecycle(inputs, assetRows, blockers, operational, simulations, validatedAssetIds)
  const relEnds = (r: Row) => [str(r.source_asset_id || r.parent_asset_id || r.from_asset_id), str(r.target_asset_id || r.child_asset_id || r.to_asset_id)]
  const recommendations = buildRecommendations(
    domains, blockers, coupling, assetRows, policy,
    inputs.relationships.length,
    (ids) => inputs.relationships.filter((r) => relEnds(r).some((id) => ids.has(id))).length,
  )
  const runtimeEvents = buildRuntimeEvents(inputs)
  const changeTracking = buildChangeTracking(inputs, operational, validatedAssetIds, readable('security_events'), readable('migration_jobs'))

  /* ---- 10. KPIs ---------------------------------------------------- */
  const kpis: AgilityKpi[] = [
    {
      key: 'agility-score',
      label: 'Crypto Agility Score',
      value: agilityScore === null ? 'Unknown' : `${agilityScore}`,
      numeric: agilityScore,
      detail: agilityLevelFromScore(agilityScore),
      tone: agilityScore === null ? 'neutral' : agilityScore >= 70 ? 'good' : agilityScore >= 50 ? 'warning' : 'critical',
      route: '#agility-posture',
      basis: `Weighted mean of ${scored.length}/${domains.length} measurable domain(s) (${scoredWeight}% of total weight) minus a ${blockerPenalty}-point blocker penalty.`,
    },
    {
      key: 'migration-readiness',
      label: 'Migration Readiness',
      value: migrationReadinessPct === null ? 'Unknown' : `${migrationReadinessPct}%`,
      numeric: migrationReadinessPct,
      detail: `${readyCount} ready · ${conditionalCount} conditional · ${blockedCount} blocked`,
      tone: migrationReadinessPct === null ? 'neutral' : migrationReadinessPct >= 70 ? 'good' : migrationReadinessPct >= 40 ? 'warning' : 'critical',
      route: '#migration-readiness',
      basis: `(ready + conditional×0.5) / ${evaluatedForReadiness} evaluated asset(s). ${unknownCount} asset(s) have no evidence and are excluded.`,
    },
    {
      key: 'assets-evaluated',
      label: 'Assets Evaluated',
      value: `${assetRows.filter((r) => r.hasEvidence).length}`,
      numeric: assetRows.filter((r) => r.hasEvidence).length,
      detail: `of ${assetRows.length} discovered`,
      tone: 'neutral',
      route: '#agility-assets',
      basis: 'Assets carrying at least one cryptographic evidence row (CBOM, scan, certificate or runtime).',
    },
    {
      key: 'critical-blockers',
      label: 'Critical Blockers',
      value: `${criticalBlockers + highBlockers}`,
      numeric: criticalBlockers + highBlockers,
      detail: `${criticalBlockers} critical · ${highBlockers} high`,
      tone: criticalBlockers > 0 ? 'critical' : highBlockers > 0 ? 'warning' : 'good',
      route: '#agility-blockers',
      basis: 'Blocker groups at critical or high severity derived from real coupling, transport and vendor evidence.',
    },
    {
      key: 'agile-assets',
      label: 'Agile Assets',
      value: `${distribution[0].count}`,
      numeric: distribution[0].count,
      detail: `${distribution[0].share}% configuration-replaceable`,
      tone: 'good',
      route: '#agility-assets',
      basis: AGILITY_STATE_DEFINITION.agile,
      filter: { kind: 'state', value: 'agile' },
    },
    {
      key: 'conditional-assets',
      label: 'Conditional Assets',
      value: `${distribution[1].count}`,
      numeric: distribution[1].count,
      detail: `${distribution[1].share}% need coordination`,
      tone: 'warning',
      route: '#agility-assets',
      basis: AGILITY_STATE_DEFINITION.conditional,
      filter: { kind: 'state', value: 'conditional' },
    },
    {
      key: 'rigid-assets',
      label: 'Rigid Assets',
      value: `${distribution[2].count}`,
      numeric: distribution[2].count,
      detail: `${distribution[2].share}% need code/architecture change`,
      tone: 'warning',
      route: '#agility-assets',
      basis: AGILITY_STATE_DEFINITION.rigid,
      filter: { kind: 'state', value: 'rigid' },
    },
    {
      key: 'blocked-assets',
      label: 'Blocked Assets',
      value: `${distribution[3].count}`,
      numeric: distribution[3].count,
      detail: `${distribution[3].share}% cannot migrate today`,
      tone: 'critical',
      route: '#agility-blockers',
      basis: AGILITY_STATE_DEFINITION.blocked,
      filter: { kind: 'state', value: 'blocked' },
    },
    {
      key: 'unknown-assets',
      label: 'Unknown Assets',
      value: `${distribution[4].count}`,
      numeric: distribution[4].count,
      detail: 'Unknown is not safe',
      tone: 'neutral',
      route: '/dashboard/scanner',
      basis: AGILITY_STATE_DEFINITION.unknown,
      filter: { kind: 'state', value: 'unknown' },
    },
    {
      key: 'critical-dependencies',
      label: 'Critical Dependencies',
      value: `${assetRows.reduce((sum, r) => sum + r.dependencies, 0)}`,
      numeric: assetRows.reduce((sum, r) => sum + r.dependencies, 0),
      detail: `${graph.edges.length} coupling edge(s) mapped`,
      tone: 'info',
      route: '#coupling-graph',
      basis: 'Trust-fabric relationships that must re-negotiate when the cryptography changes.',
    },
    {
      key: 'crypto-drift',
      label: 'Crypto Agility Drift',
      value: drift.direction === 'unknown' ? 'Unknown' : drift.direction.charAt(0).toUpperCase() + drift.direction.slice(1),
      numeric: drift.deltaPoints,
      detail: drift.deltaPoints === null ? drift.windowLabel : `PQC adoption ${drift.deltaPoints > 0 ? '+' : ''}${drift.deltaPoints} pts`,
      tone: drift.direction === 'improving' ? 'good' : drift.direction === 'critical' ? 'critical' : drift.direction === 'degrading' ? 'warning' : 'neutral',
      route: '#agility-drift',
      basis: drift.basis,
    },
    {
      key: 'policy-compliance',
      label: 'Policy Compliance',
      value: policy.compliancePct === null ? 'Unknown' : `${policy.compliancePct}%`,
      numeric: policy.compliancePct,
      detail: `${policy.violations.length} rule(s) violated`,
      tone: policy.compliancePct === null ? 'neutral' : policy.compliancePct >= 80 ? 'good' : policy.compliancePct >= 50 ? 'warning' : 'critical',
      route: '#agility-policy',
      basis: policy.basis,
    },
    {
      key: 'automation-coverage',
      label: 'Automation Coverage',
      value: (() => {
        const certDomain = domains.find((d) => d.key === 'certificate')
        const keyDomain = domains.find((d) => d.key === 'key')
        const parts = [certDomain?.score, keyDomain?.score].filter((s): s is number => s !== null && s !== undefined)
        return parts.length ? `${Math.round(parts.reduce((a, b) => a + b, 0) / parts.length)}%` : 'Unknown'
      })(),
      numeric: (() => {
        const certDomain = domains.find((d) => d.key === 'certificate')
        const keyDomain = domains.find((d) => d.key === 'key')
        const parts = [certDomain?.score, keyDomain?.score].filter((s): s is number => s !== null && s !== undefined)
        return parts.length ? Math.round(parts.reduce((a, b) => a + b, 0) / parts.length) : null
      })(),
      detail: 'Certificate + key lifecycle automation',
      tone: 'info',
      route: '#agility-posture',
      basis: 'Mean of the Certificate Agility and Key Agility domain scores — the two lifecycle domains that decide whether a change is automated or manual.',
    },
  ]

  /* ---- 11. Coverage + confidence ----------------------------------- */
  const evaluatedAssets = assetRows.filter((r) => r.hasEvidence).length
  const evidenceCoverage = Math.round(pctOf(evaluatedAssets, Math.max(1, assetRows.length)))
  const domainCoverage = Math.round(pctOf(scoredWeight, 100))
  const overallCoverage = Math.round((evidenceCoverage + domainCoverage) / 2)

  const sources = unique([
    inputs.cryptoInventory.length ? 'CBOM (crypto_inventory)' : '',
    inputs.cryptoExposures.length ? 'Crypto Exposures' : '',
    inputs.certificates.length ? 'Certificate Inventory' : '',
    inputs.runtimeEvents.length ? 'Runtime Crypto Telemetry' : '',
    inputs.relationships.length ? 'Trust Fabric (asset_relationships)' : '',
    operational.length ? 'Migration Jobs (operational)' : '',
    inputs.generatedKeys.length ? 'Key Inventory' : '',
    inputs.connectorAccounts.length ? 'Cloud Connectors' : '',
    sr && sr.hasData ? 'Shared Responsibility Engine' : '',
    inputs.scanSessions.length ? 'PQC Scan Sessions' : '',
  ].filter(Boolean))

  const explanationParts: string[] = []
  if (agilityScore === null) {
    explanationParts.push(
      `${EVIDENCE_UNAVAILABLE}. No agility domain could be measured from tenant evidence, so no Crypto Agility Score is published. Running a discovery scan is the first step.`,
    )
  } else {
    const weakest = scored.slice().sort((a, b) => (a.score as number) - (b.score as number))[0]
    explanationParts.push(
      `The Crypto Agility Score of ${agilityScore}/100 (${agilityLevelFromScore(agilityScore)}) is the evidence-weighted mean of ${scored.length} measurable domain(s) covering ${scoredWeight}% of the model's weight, reduced by ${blockerPenalty} point(s) for unresolved blockers.`,
    )
    if (weakest) {
      explanationParts.push(`${weakest.label} is the largest drag at ${weakest.score}/100 — ${weakest.basis}`)
    }
    explanationParts.push(
      `${distribution[0].count} asset(s) are configuration-replaceable, ${distribution[2].count} require code or architecture change and ${distribution[3].count} are blocked by a dependency.`,
    )
    if (domains.some((d) => d.score === null)) {
      explanationParts.push(
        `${domains.filter((d) => d.score === null).length} domain(s) are excluded for lack of evidence and their weight is renormalised — the score describes what is measured, not what is unknown.`,
      )
    }
  }

  return {
    generatedAt: new Date(now).toISOString(),
    lastAssessmentAt: inputs.snapshot.lastAssessmentAt,
    hasData: inputs.snapshot.hasData && assetRows.length > 0,
    evidenceCoverage: overallCoverage,
    confidence: confidenceFromCoverage(overallCoverage, agilityScore !== null),

    score: {
      agilityScore,
      agilityLevel: agilityLevelFromScore(agilityScore),
      migrationReadinessPct,
      assetsEvaluated: evaluatedAssets,
      couplingAssessed: assetRows.filter((r) => r.hasEvidence && r.couplingAssessed).length,
      criticalBlockers: criticalBlockers + highBlockers,
      scoredWeight,
      blockerPenalty,
      explanation: explanationParts.join(' '),
      formula: 'Crypto Agility Score = Σ(domain score × domain weight) ÷ Σ(weight of MEASURED domains) − bounded blocker penalty (max 18). Domains without evidence are excluded and their weight renormalised — never scored as 0.',
      components: domains.map((d) => ({
        label: d.label,
        weight: d.weight,
        score: d.score,
        contribution: d.score === null ? 0 : Math.round(((d.score * d.weight) / Math.max(1, scoredWeight)) * 10) / 10,
        basis: d.basis,
      })),
    },

    kpis,
    domains,
    distribution,
    assets: assetRows,
    coupling,
    replaceability,
    transitions,
    algorithmStatus,
    excludedFindingTitles: matrix.rejected,
    changeTracking,
    sources: sourceStatus,
    nextStep: deriveNextStep({ evaluatedAssets, totalAssets: assetRows.length, policy, blockers, domains, replaceability, recommendations, sources: sourceStatus }),
    blockers,
    responsibility: responsibility.slice(0, 60),
    graph,
    lifecycle,
    policy,
    runtimeEvents,
    drift,
    history,
    recommendations,
    readiness: {
      ready: readyCount,
      conditional: conditionalCount,
      blocked: blockedCount,
      unknown: unknownCount,
      pct: migrationReadinessPct,
    },
    filters: {
      environments: unique(assetRows.map((r) => r.environment)).filter(Boolean).sort(),
      owners: unique(assetRows.map((r) => r.owner)).filter(Boolean).sort(),
      algorithms: unique(replaceability.map((r) => r.currentAlgorithm)).sort(),
      controlDomains: ['customer', 'provider', 'ecosystem'],
    },
    evidence: {
      sources,
      assets: assetRows.length,
      components: inputs.snapshot.inventory.cryptoComponents,
      certificates: inputs.certificates.length,
      runtimeEvents: inputs.runtimeEvents.length,
      relationships: inputs.relationships.length,
      scanSessions: inputs.scanSessions.length,
      note: sources.length
        ? `Derived from ${sources.length} live evidence source(s): ${sources.join(', ')}.`
        : `${EVIDENCE_UNAVAILABLE} — no cryptographic evidence exists for this tenant yet.`,
    },
  }
}

/** Every source counted as read — used when the caller (a fixture) supplies no read status. */
function defaultSourceHealth(inputs: AgilityInputs): AgilitySourceStatus[] {
  const rows: Array<[string, string, Row[]]> = [
    ['crypto_inventory', 'CBOM components', inputs.cryptoInventory],
    ['crypto_exposures', 'Crypto exposures', inputs.cryptoExposures],
    ['certificates', 'Certificates', inputs.certificates],
    ['runtime_crypto_events', 'Runtime telemetry', inputs.runtimeEvents],
    ['generated_keys', 'Key inventory', inputs.generatedKeys],
    ['migration_jobs', 'Migration jobs', inputs.migrationJobs],
    ['pqc_scan_sessions', 'Scan sessions', inputs.scanSessions],
    ['security_events', 'Security events', inputs.securityEvents],
    ['connector_accounts', 'Connectors', inputs.connectorAccounts],
    ['asset_relationships', 'Trust fabric', inputs.relationships],
    ['quantum_governance_exceptions', 'Policy exceptions', inputs.policyExceptions],
  ]
  return rows.map(([key, label, list]) => ({
    key, label, state: list.length ? 'ok' : 'empty', rows: list.length, limit: null,
    detail: list.length ? `${list.length} row(s) read.` : 'Read — no rows recorded.',
  }))
}

/**
 * The single most valuable next step the evidence supports, in a fixed order:
 * nothing assessed → an unreadable source → a prohibited algorithm in use → a
 * critical blocker → unmeasured domains → the top recommendation → calm.
 */
function deriveNextStep(ctx: {
  evaluatedAssets: number
  totalAssets: number
  policy: PolicyEvaluation
  blockers: AgilityBlocker[]
  domains: AgilityDomain[]
  replaceability: ReplaceabilityRow[]
  recommendations: AgilityRecommendation[]
  sources: AgilitySourceStatus[]
}): CryptoAgilityIntelligence['nextStep'] {
  if (ctx.evaluatedAssets === 0) {
    return {
      label: 'Run a discovery scan',
      detail: ctx.totalAssets
        ? `${ctx.totalAssets} asset(s) are discovered but none carries cryptographic evidence, so agility cannot be measured.`
        : 'No asset is discovered yet. A scan inventories the cryptography every agility figure is computed from.',
      route: '/dashboard/scanner',
      tone: 'action',
    }
  }
  const unreadable = ctx.sources.filter((s) => s.state === 'unavailable')
  if (unreadable.length) {
    return {
      label: 'Refresh the assessment',
      detail: `${unreadable.map((s) => s.label).join(', ')} could not be read on the last assessment. Figures that depend on them are withheld — refresh to retry.`,
      route: '/dashboard/crypto-agility',
      tone: 'warning',
    }
  }
  const prohibited = ctx.replaceability.filter((r) => r.algorithmStatus === 'unsupported')
  if (prohibited.length) {
    const assets = unique(prohibited.flatMap((r) => r.assetNames)).length
    return {
      label: 'Create a remediation plan',
      detail: `${prohibited.length} prohibited algorithm(s) (${prohibited.slice(0, 3).map((r) => r.currentAlgorithm).join(', ')}) are in use on ${assets} asset(s). They have no compliant transition period — replace them first.`,
      route: '/dashboard/migration-planner',
      tone: 'warning',
    }
  }
  const critical = ctx.blockers.find((b) => b.severity === 'critical')
  if (critical) {
    return { label: 'Resolve the blocker', detail: `${critical.title}: ${critical.remediation}`, route: critical.route, tone: 'warning' }
  }
  const unmeasured = ctx.domains.filter((d) => d.score === null)
  if (unmeasured.length >= Math.ceil(ctx.domains.length / 2)) {
    return {
      label: 'Close the evidence gap',
      detail: `${unmeasured.length} of ${ctx.domains.length} agility domains cannot be measured (${unmeasured.slice(0, 3).map((d) => d.label).join(', ')}…). Connect the missing evidence so the score describes the estate, not a slice of it.`,
      route: '/dashboard/scanner',
      tone: 'action',
    }
  }
  const top = ctx.recommendations[0]
  if (top) return { label: top.action, detail: `${top.title}. ${top.detail}`, route: top.route, tone: top.severity === 'critical' || top.severity === 'high' ? 'warning' : 'action' }
  return {
    label: 'Keep monitoring',
    detail: 'No blocker, prohibited algorithm or evidence gap is recorded. Re-scan after each release so newly introduced cryptography is caught.',
    route: '/dashboard/drift',
    tone: 'calm',
  }
}

/** Exposed for the change-impact preview route, which needs the same derivations. */
export function deriveAgilityDerivations(inputs: AgilityInputs): Map<string, AssetAgilityDerivation> {
  const assetsById = new Map(inputs.assets.map((a) => [a.id, a]))
  const providerLocked = new Map<string, string>()
  const sr = inputs.snapshot.sharedResponsibility
  if (sr) {
    for (const finding of sr.findings) {
      if (finding.domain === 'customer' || finding.customerActionable === 'yes') continue
      const id = findByAssetName(assetsById, finding.asset)
      if (id && !providerLocked.has(id)) providerLocked.set(id, finding.responsibleParty)
    }
  }
  const coupling = buildCouplingFindings(inputs, {
    assetsById,
    inventoryByAsset: new Map(),
    exposuresByAsset: new Map(),
    certificatesByAsset: new Map(),
    keyRotationAssetIds: new Set(),
    providerLockedAssets: providerLocked,
  })
  const couplingByAsset = new Map<string, CouplingFinding[]>()
  for (const finding of coupling) {
    const list = couplingByAsset.get(finding.assetId) || []
    list.push(finding)
    couplingByAsset.set(finding.assetId, list)
  }
  const couplingObservableAssets = observableCouplingAssets(inputs)
  const latestJobs = latestOperationalJobByAsset(splitMigrationJobs(inputs.migrationJobs).operational)
  const derivations = new Map<string, AssetAgilityDerivation>()
  for (const asset of inputs.assets) {
    derivations.set(asset.id, deriveAssetAgility(asset, couplingByAsset, providerLocked, couplingObservableAssets, latestJobs.get(asset.id) ?? null))
  }
  return derivations
}

export type { AssetAgilityDerivation }
