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

export { EVIDENCE_UNAVAILABLE }

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
  risk: number
  /** Assets that transit this node — the node's blast radius. */
  assetIds: string[]
  assetCount: number
  algorithm: string
  replaceability: ReplaceabilityClass
  controlDomain: ControlDomain
  detail: string
  route: string
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

export interface PolicyEvaluation {
  policyName: string
  version: string
  source: 'platform-mandatory-stack' | 'tenant-configured'
  lastEvaluatedAt: string
  evaluated: boolean
  rules: PolicyRule[]
  violations: PolicyViolation[]
  compliancePct: number | null
  compliantInstances: number
  evaluatedInstances: number
  exceptions: Array<{ id: string; policy: string; justification: string; status: string; expiresAt: string | null }>
  basis: string
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
  progressPct: number
  metric: string
  route: string
  module: string
}

/* ---- Sandbox impact preview -------------------------------------- */

export interface ChangeImpactPreview {
  assetId: string
  asset: string
  fromAlgorithm: string
  toAlgorithm: string
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
  basis: string
}

/* ---- Recommendations (Sophia-facing) ----------------------------- */

export interface AgilityRecommendation {
  id: string
  title: string
  detail: string
  severity: Severity
  expectedScoreGain: number
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
const BROKEN_PRIMITIVE_RE = /SHA-?1(?!\d)|MD5(?!\d)|\bRC4\b|\b3DES\b|\bDES\b|RSA-?(?:512|1024)\b|DSA-?1024\b/i

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
  return [...versions]
}

const LEGACY_PROTOCOL_RE = /(TLS|SSL)\s?v?1\.[01]\b|\bSSL\s?v?[23]\b|^TLSv1$/i

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
 */
function deriveAssetAgility(
  asset: AssetMigrationRecord,
  couplingByAsset: Map<string, CouplingFinding[]>,
  providerLocked: Map<string, string>,
  couplingObservableAssets: Set<string>,
): AssetAgilityDerivation {
  const coupling = couplingByAsset.get(asset.id) || []

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
    }
  }

  const couplingObservable = couplingObservableAssets.has(asset.id) || asset.evidence.runtimeEvents > 0

  const blockerReasons: string[] = []

  /* --- Replaceability class: worst binding constraint wins --------- */
  // Constraints are collected, then reduced by rank. A swap is only as easy as
  // its hardest binding constraint.
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

  // Broken primitives are never a pure config swap.
  if (asset.algorithms.some((a) => BROKEN_PRIMITIVE_RE.test(a.algorithm))) {
    raise('code', 'Broken primitive (SHA-1/MD5/RC4/DES/RSA-1024 class) detected — call sites must be updated.')
  }

  // A wide blast radius makes the change an architecture-coordination problem.
  if (asset.blastRadius > 8) {
    raise('architecture', `${asset.blastRadius} trust relationship(s) must negotiate the replacement stack simultaneously.`)
  }

  if (asset.compatibility.score > 0 && asset.compatibility.score < 50) {
    blockerReasons.push('Compatibility risks must be cleared before cutover.')
  }
  if (asset.migrationStatus === 'Failed') {
    blockerReasons.push('A migration job for this asset failed and must be resolved.')
  }

  const replaceability = constraints.reduce<ReplaceabilityClass>(
    (worst, candidate) => (REPLACEABILITY_RANK[candidate] > REPLACEABILITY_RANK[worst] ? candidate : worst),
    'configuration',
  )

  /* --- Score: 100 = pure configuration change, nothing gating ------ */
  const base: Record<ReplaceabilityClass, number> = {
    configuration: 92,
    library: 72,
    code: 48,
    architecture: 28,
    vendor: 18,
    unknown: 0,
  }
  let score = base[replaceability]

  // Evidence-derived adjustments, all bounded.
  if (asset.certificates.length && asset.certificates.every((c) => c.quantumSafe)) score += 4
  if (asset.tlsConfiguration.keyExchange.some((k) => classifyAlgorithm(k) === 'pqc' || classifyAlgorithm(k) === 'hybrid')) score += 6
  if (asset.tlsConfiguration.protocols.some((p) => /1\.3/.test(p))) score += 4
  if (asset.posture === 'pqc') score += 5
  score -= Math.min(18, coupling.length * 4)
  score -= Math.min(12, Math.max(0, asset.blastRadius - 2) * 1.5)
  if (asset.migrationStatus === 'Failed') score -= 12
  if (asset.migrationStatus === 'Completed') score += 8
  if (!asset.owner || /unassigned/i.test(asset.owner)) score -= 5

  // Coupling could not be observed ⇒ the confident end of the scale is not
  // available. The transport-level facts still score, but the asset cannot claim
  // to be configuration-replaceable end-to-end.
  if (!couplingObservable) {
    blockerReasons.push(
      'Application-level cryptographic coupling has not been assessed for this asset — only transport/certificate evidence exists, so configuration-replaceability cannot be confirmed.',
    )
    score = Math.min(score, 60)
  }

  const finalScore = Math.round(clamp(score))

  /* --- State ------------------------------------------------------- */
  const hardBlocked =
    replaceability === 'vendor' ||
    asset.migrationStatus === 'Failed' ||
    (asset.validation.cutoverBlocked && asset.validation.blockerReason !== '')

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

  if (asset.validation.cutoverBlocked && asset.validation.blockerReason) {
    if (!blockerReasons.includes(asset.validation.blockerReason)) blockerReasons.push(asset.validation.blockerReason)
  }

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
      return {
        score: Math.round(pctOf(configDriven.length, assessable.length)),
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
      let replaceable = 0
      let totalInstances = 0
      for (const [name, entry] of algorithms) {
        totalInstances += entry.instances
        const klass = entry.klass
        if (klass === 'pqc' || klass === 'hybrid') replaceable += entry.instances
        else if (!BROKEN_PRIMITIVE_RE.test(name)) replaceable += entry.instances * 0.5
      }
      const score = pctOf(replaceable, totalInstances)
      const broken = [...algorithms.keys()].filter((a) => BROKEN_PRIMITIVE_RE.test(a))
      return {
        score: Math.round(score),
        coverage: pctOf(evaluated.length, total),
        blockers: broken.length,
        affectedAssets: evaluated.filter((a) => a.algorithms.some((x) => BROKEN_PRIMITIVE_RE.test(x.algorithm))).length,
        basis: `${algorithms.size} distinct cryptographic primitive(s) across ${totalInstances} instance(s); ${broken.length} broken primitive(s) require call-site changes rather than a swap.${rejected ? ` ${rejected} recorded value(s) were scanner finding titles and are excluded from algorithm scoring.` : ''}`,
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
      const score = clamp(pctOf(modern.length, withTransport.length) * 0.6 + pctOf(hybrid.length, withTransport.length) * 0.4 - pctOf(legacy.length, withTransport.length) * 0.2)
      return {
        score: Math.round(score),
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
      const pqcCapable = certs.filter((c) => c.is_quantum_safe === true)
      const score = clamp(
        pctOf(managed.length, certs.length) * 0.55 +
          pctOf(pqcCapable.length, certs.length) * 0.25 +
          (100 - pctOf(expiringSoon.length, certs.length)) * 0.2,
      )
      return {
        score: Math.round(score),
        coverage: pctOf(certs.length, Math.max(certs.length, inputs.snapshot.inventory.certificatesAnalyzed)),
        blockers: certs.length - managed.length,
        affectedAssets: unique(certs.map((c) => str(c.asset_id)).filter(Boolean)).length,
        basis: `${managed.length}/${certs.length} certificate(s) show automated issuance evidence, ${pqcCapable.length} are PQC-capable, ${expiringSoon.length} expire within 30 days.`,
        actions: certs.length - managed.length > 0
          ? [`Automate issuance for ${certs.length - managed.length} manually managed certificate(s).`, 'Validate that the issuing CA can sign ML-DSA-65 / hybrid chains.']
          : ['Confirm the managed CA supports ML-DSA-65 issuance and pilot a hybrid chain.'],
      }
    },

    /* ---- Key -------------------------------------------------------- */
    key: () => {
      const keys = inputs.generatedKeys
      const rotationJobs = inputs.migrationJobs.filter((j) => /rotat|key/i.test(`${str(j.job_type)} ${str(j.name)}`))
      const custody = inputs.connectorAccounts.filter((a) => /kms|hsm|vault|key/i.test(str(a.provider)))
      const keyCoupling = (couplingByDomain.get('key') || []).length
      if (!keys.length && !rotationJobs.length && !custody.length && !inputs.snapshot.inventory.keysDiscovered) {
        return none('No key inventory, rotation job or KMS/HSM custody evidence exists.')
      }
      const pqcKeys = keys.filter((k) => classifyAlgorithm(str(k.algorithm)) === 'pqc' || classifyAlgorithm(str(k.algorithm)) === 'hybrid')
      const score = clamp(
        (keys.length ? pctOf(pqcKeys.length, keys.length) : 0) * 0.4 +
          (rotationJobs.length ? 100 : 0) * 0.3 +
          (custody.length ? 100 : 0) * 0.3 -
          Math.min(25, keyCoupling * 5),
      )
      // Coverage is the share of the THREE signal families that carry evidence
      // (inventory / rotation / custody). Counting rows instead would claim 100%
      // coverage from key rows alone while rotation and custody are unmeasured —
      // a low score reported with false confidence.
      const keySignals = [keys.length > 0, rotationJobs.length > 0, custody.length > 0].filter(Boolean).length
      return {
        score: Math.round(score),
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
      const score = libraries.length
        ? clamp(pctOf(pqcCapable.length, libraries.length) * 0.7 + (100 - pctOf(legacyFindings.length, Math.max(1, libraries.length))) * 0.3)
        : clamp(100 - legacyFindings.length * 15)
      return {
        score: Math.round(score),
        coverage: libraries.length ? pctOf(libraries.length, Math.max(1, evaluated.length)) : 25,
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
      const score = clamp(
        (connectors.length ? Math.min(100, connectors.length * 25) : 0) * 0.5 +
          pctOf(managedEnvironments.length, Math.max(1, managedEnvironments.length + (evaluated.length && !managedEnvironments.length ? 1 : 0))) * 0.3 +
          (100 - Math.min(100, configFindings * 10)) * 0.2,
      )
      return {
        score: Math.round(score),
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
      const score = clamp(pctOf(pqcSigning.length, identityAssets.length) * 0.5 + (100 - pctOf(rigid.length, identityAssets.length)) * 0.5)
      return {
        score: Math.round(score),
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
      const score = clamp(pctOf(shipping.length, providers.length) * 100 / 100 + pctOf(inProgress.length, providers.length) * 0.5)
      return {
        score: Math.round(clamp(score)),
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
      const score = clamp(coverage * 0.6 + pctOf(recent.length, Math.max(1, events.length)) * 0.4)
      return {
        score: Math.round(score),
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
    return { score: null, coverage: 0, blockers: 0, affectedAssets: 0, basis: `${EVIDENCE_UNAVAILABLE} — ${reason}`, actions: [] }
  }

  return AGILITY_DOMAINS.map((definition) => {
    // Hard floor: with no cryptographically assessed asset, NO agility domain is
    // measurable. Several domains score from the ABSENCE of bad evidence (no
    // deprecated provider, no static anchor), which on an empty tenant would
    // otherwise read as a perfect 100 — the exact "missing data becomes a good
    // number" failure this engine exists to prevent.
    const result = evaluated.length === 0
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
    }
  })
}

/* ================================================================== */
/* Replaceability matrix                                               */
/* ================================================================== */

function buildReplaceabilityMatrix(
  inputs: AgilityInputs,
  derivations: Map<string, AssetAgilityDerivation>,
): ReplaceabilityRow[] {
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
      }
      bucket.instances += algo.instances
      if (!bucket.assetIds.has(asset.id)) {
        bucket.assetIds.add(asset.id)
        if (bucket.assetNames.length < 12) bucket.assetNames.push(asset.name)
        bucket.dependencies += asset.blastRadius
        bucket.compatibilitySum += asset.compatibility.score
        bucket.compatibilityCount += 1
        bucket.breakdown[derivation?.replaceability ?? 'unknown'] += 1
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

    const alreadySafe = bucket.classification === 'pqc'
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
      proposedReplacement: bucket.target,
      standard: bucket.standard,
      rationale: bucket.rationale,
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
      basis: `${bucket.instances} instance(s) across ${bucket.assetIds.size} asset(s); the row adopts the hardest per-asset verdict (${REPLACEABILITY_LABEL[replaceability]}).${rejected ? ` ${rejected} recorded value(s) were scanner finding titles, not primitives, and are excluded from this matrix.` : ''}`,
    })
  }

  const classRank = (c: AlgorithmClass) => (c === 'vulnerable' ? 0 : c === 'unknown' ? 1 : c === 'hybrid' ? 2 : 3)
  return rows.sort(
    (a, b) =>
      classRank(a.classification) - classRank(b.classification) ||
      REPLACEABILITY_RANK[b.replaceability] - REPLACEABILITY_RANK[a.replaceability] ||
      b.instances - a.instances,
  )
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
  maxAssets = 40,
): CouplingGraph {
  const nodes = new Map<string, CouplingNode>()
  const edges: CouplingEdge[] = []
  const edgeKeys = new Set<string>()

  const addNode = (node: CouplingNode) => {
    const existing = nodes.get(node.id)
    if (existing) {
      existing.assetIds = unique([...existing.assetIds, ...node.assetIds])
      existing.assetCount = existing.assetIds.length
      existing.risk = Math.max(existing.risk, node.risk)
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
        risk: deprecated ? 70 : 30,
        assetIds: [asset.id],
        assetCount: 1,
        algorithm: str(lib.algorithm) || EVIDENCE_UNAVAILABLE,
        replaceability: deprecated ? 'library' : 'configuration',
        controlDomain: 'customer',
        detail: deprecated ? 'Deprecated provider — must be upgraded before PQC primitives are available.' : 'Cryptographic provider inventoried for this asset.',
        route: '/dashboard/cbom_explorer',
      })
      addEdge(appId, libId, 'uses', state)
    }

    /* -- Algorithm layer -- */
    for (const algo of asset.algorithms.filter((a) => isCryptographicPrimitive(a.algorithm)).slice(0, 4)) {
      const algoId = `alg:${algo.algorithm.toUpperCase()}`
      const algoState: AgilityState =
        algo.classification === 'pqc' ? 'agile' : BROKEN_PRIMITIVE_RE.test(algo.algorithm) ? 'rigid' : 'conditional'
      addNode({
        id: algoId,
        label: algo.algorithm,
        layer: 'algorithm',
        agilityState: algoState,
        risk: algo.classification === 'vulnerable' ? 80 : algo.classification === 'pqc' ? 5 : 40,
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
      const certState: AgilityState = cert.quantumSafe ? 'agile' : 'conditional'
      addNode({
        id: certId,
        label: cert.name,
        layer: 'certificate',
        agilityState: certState,
        risk: cert.quantumSafe ? 10 : 55,
        assetIds: [asset.id],
        assetCount: 1,
        algorithm: cert.algorithm,
        replaceability: cert.quantumSafe ? 'configuration' : 'library',
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
          risk: managed ? 35 : 65,
          assetIds: [asset.id],
          assetCount: 1,
          algorithm: cert.algorithm,
          replaceability: managed ? 'configuration' : 'architecture',
          controlDomain: managed ? 'provider' : 'customer',
          detail: managed ? 'Managed issuer — re-issuance can be automated.' : 'No automated issuance evidence; re-issuance needs a change window.',
          route: '/dashboard/pki-visibility',
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
            risk: 70,
            assetIds: [asset.id],
            assetCount: 1,
            algorithm: cert.algorithm,
            replaceability: 'architecture',
            controlDomain: 'customer',
            detail: 'Static trust anchor — every relying party must trust the replacement before the chain can change.',
            route: '/dashboard/trust-chain-analyzer',
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
        risk: 85,
        assetIds: [asset.id],
        assetCount: 1,
        algorithm: EVIDENCE_UNAVAILABLE,
        replaceability: 'vendor',
        controlDomain: vendorFinding.controlDomain,
        detail: vendorFinding.remediation,
        route: '/dashboard/vendor-pqc-readiness',
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
    note: `Projection of the tenant's existing CBOM, certificate inventory, trust fabric and shared-responsibility attribution — no separate graph store. Showing the ${ranked.length} least-agile evaluated asset(s).${providerNote}`,
  }
}

/* ================================================================== */
/* Policy evaluation                                                   */
/* ================================================================== */

/**
 * Rules mirror the platform's MANDATORY PQC STACK (src/lib/crypto/mandatory-pqc-stack.ts)
 * expressed as agility verdicts. When a tenant-configured policy engine exists,
 * `source` flips to 'tenant-configured' and its rules replace these.
 */
const PLATFORM_POLICY_RULES: readonly PolicyRule[] = [
  { id: 'pol-rsa-weak', subject: 'RSA < 2048', verdict: 'block', rationale: 'Below the 112-bit classical floor; broken by Shor and already non-compliant.', standard: 'NIST SP 800-131A' },
  { id: 'pol-rsa-2048', subject: 'RSA 2048', verdict: 'warn', rationale: 'Deprecated for new use by 2030 under NIST IR 8547; plan the ML-KEM / ML-DSA replacement now.', standard: 'NIST IR 8547' },
  { id: 'pol-rsa-3072', subject: 'RSA 3072+', verdict: 'allow', rationale: 'Acceptable classical strength during the transition, but still quantum-vulnerable.', standard: 'NIST SP 800-57' },
  { id: 'pol-tls-legacy', subject: 'TLS 1.0 / 1.1 / SSL', verdict: 'block', rationale: 'Formally deprecated by RFC 8996; cannot carry modern or hybrid cryptography and must be disabled.', standard: 'RFC 8996' },
  { id: 'pol-tls12', subject: 'TLS 1.2', verdict: 'warn', rationale: 'Cannot negotiate hybrid PQC named groups; blocks protocol agility.', standard: 'RFC 8446' },
  { id: 'pol-tls13', subject: 'TLS 1.3', verdict: 'required', rationale: 'Required baseline before X25519MLKEM768 can be negotiated.', standard: 'RFC 8446' },
  { id: 'pol-x25519', subject: 'X25519', verdict: 'allow', rationale: 'Forward-secret classical key exchange; acceptable only as the classical half of a hybrid group.', standard: 'RFC 7748' },
  { id: 'pol-hybrid-kem', subject: 'X25519 + ML-KEM-768', verdict: 'preferred', rationale: 'Platform-preferred key establishment — protects against harvest-now-decrypt-later while preserving interoperability.', standard: 'FIPS 203' },
  { id: 'pol-mldsa', subject: 'ML-DSA-65', verdict: 'preferred', rationale: 'Platform-preferred digital signature for certificates, tokens and code signing.', standard: 'FIPS 204' },
  { id: 'pol-aes128', subject: 'AES-128', verdict: 'warn', rationale: 'Grover halves symmetric strength; 128-bit keys fall below the post-quantum margin.', standard: 'FIPS 197' },
  { id: 'pol-aes256', subject: 'AES-256-GCM', verdict: 'required', rationale: 'Required symmetric baseline for a 128-bit post-quantum security margin.', standard: 'FIPS 197 / SP 800-38D' },
  { id: 'pol-broken-hash', subject: 'SHA-1 / MD5', verdict: 'block', rationale: 'Collision-broken hashes must not appear in any signing or integrity path.', standard: 'FIPS 202' },
] as const

interface PolicyMatch {
  ruleId: string
  test: (algorithm: string, keySize: number, protocols: string[]) => boolean
}

const POLICY_MATCHERS: readonly PolicyMatch[] = [
  { ruleId: 'pol-rsa-weak', test: (a, k) => /^RSA/i.test(a) && k > 0 && k < 2048 },
  { ruleId: 'pol-rsa-2048', test: (a, k) => /^RSA/i.test(a) && (k === 2048 || (k === 0 && /2048/.test(a))) },
  { ruleId: 'pol-aes128', test: (a) => /AES-?128/i.test(a) },
  { ruleId: 'pol-broken-hash', test: (a) => /SHA-?1\b|\bMD5\b/i.test(a) },
  { ruleId: 'pol-tls-legacy', test: (_a, _k, protocols) => protocols.some((p) => LEGACY_PROTOCOL_RE.test(p)) },
  { ruleId: 'pol-tls12', test: (_a, _k, protocols) => protocols.some((p) => /1\.2/.test(p)) },
  { ruleId: 'pol-tls13', test: (_a, _k, protocols) => protocols.length > 0 && !protocols.some((p) => /1\.3/.test(p)) },
] as const

const TRANSPORT_RULE_IDS = new Set(['pol-tls-legacy', 'pol-tls12', 'pol-tls13'])

function evaluatePolicy(inputs: AgilityInputs, now: number): PolicyEvaluation {
  const violationMap = new Map<string, { assets: Set<string>; names: string[]; instances: number; observed: Set<string> }>()
  let evaluatedInstances = 0
  let compliantInstances = 0
  // Transport posture is evaluated PER ASSET, not per algorithm instance. It is
  // counted as its own compliance unit so the headline percentage can never read
  // "100% compliant" while a transport rule is violated.
  let transportUnits = 0
  let compliantTransportUnits = 0

  for (const asset of inputs.assets) {
    if (!asset.hasEvidence) continue
    // Protocol versions arrive either as transport telemetry or as inventory
    // entries ("TLSv1.1"); both must reach the transport rules.
    const protocols = protocolVersionsFor(asset)
    for (const algo of asset.algorithms) {
      // Policy rules apply to cryptography, not to scanner finding titles —
      // counting those as "compliant instances" would inflate the percentage.
      if (!isCryptographicPrimitive(algo.algorithm)) continue
      evaluatedInstances += algo.instances
      const keySize = algo.keySizes[0] ?? 0
      let violated = false
      for (const matcher of POLICY_MATCHERS) {
        if (TRANSPORT_RULE_IDS.has(matcher.ruleId)) continue
        if (!matcher.test(algo.algorithm, keySize, protocols)) continue
        violated = true
        const entry = violationMap.get(matcher.ruleId) || { assets: new Set<string>(), names: [], instances: 0, observed: new Set<string>() }
        entry.assets.add(asset.id)
        if (entry.names.length < 10 && !entry.names.includes(asset.name)) entry.names.push(asset.name)
        entry.instances += algo.instances
        entry.observed.add(keySize ? `${algo.algorithm} ${keySize}-bit` : algo.algorithm)
        violationMap.set(matcher.ruleId, entry)
      }
      if (!violated) compliantInstances += algo.instances
    }

    // Transport rules are asset-scoped, not per algorithm instance.
    if (protocols.length) {
      transportUnits += 1
      let transportViolated = false
      for (const matcher of POLICY_MATCHERS) {
        if (!TRANSPORT_RULE_IDS.has(matcher.ruleId)) continue
        if (!matcher.test('', 0, protocols)) continue
        transportViolated = true
        const entry = violationMap.get(matcher.ruleId) || { assets: new Set<string>(), names: [], instances: 0, observed: new Set<string>() }
        entry.assets.add(asset.id)
        if (entry.names.length < 10 && !entry.names.includes(asset.name)) entry.names.push(asset.name)
        entry.instances += 1
        for (const p of protocols) entry.observed.add(p)
        violationMap.set(matcher.ruleId, entry)
      }
      if (!transportViolated) compliantTransportUnits += 1
    }
  }

  const rulesById = new Map(PLATFORM_POLICY_RULES.map((r) => [r.id, r]))
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
  violations.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.instances - a.instances)

  const evaluatedUnits = evaluatedInstances + transportUnits
  const compliantUnits = compliantInstances + compliantTransportUnits

  const exceptions = inputs.policyExceptions.map((row) => ({
    id: str(row.id),
    policy: str(row.policy_violated) || 'Recorded exception',
    justification: str(row.justification) || EVIDENCE_UNAVAILABLE,
    status: str(row.status) || 'requested',
    expiresAt: isoOrNull(row.expiration_date),
  }))

  return {
    policyName: 'QGuard Helix Mandatory PQC Stack',
    version: 'qguard-pqc-stack-v1',
    source: 'platform-mandatory-stack',
    lastEvaluatedAt: new Date(now).toISOString(),
    evaluated: evaluatedUnits > 0,
    rules: [...PLATFORM_POLICY_RULES],
    violations,
    // Compliance spans BOTH unit kinds: algorithm instances and per-asset
    // transport posture. Counting only instances reported "100% compliant" on a
    // tenant whose transport violated a BLOCK rule.
    compliancePct: evaluatedUnits > 0 ? Math.round(pctOf(compliantUnits, evaluatedUnits)) : null,
    compliantInstances: compliantUnits,
    evaluatedInstances: evaluatedUnits,
    exceptions,
    basis: evaluatedUnits > 0
      ? `${evaluatedInstances} algorithm instance(s) and ${transportUnits} asset transport posture(s) evaluated against ${PLATFORM_POLICY_RULES.length} platform rules; ${violations.length} rule(s) violated. No tenant-configured policy engine is connected, so the platform mandatory stack is authoritative.`
      : `${EVIDENCE_UNAVAILABLE} — no algorithm instance or transport posture has been observed, so policy compliance cannot be evaluated.`,
  }
}

/* ================================================================== */
/* Runtime events + drift + history                                    */
/* ================================================================== */

function buildRuntimeEvents(inputs: AgilityInputs): RuntimeCryptoEvent[] {
  const assetsById = new Map(inputs.assets.map((a) => [a.id, a]))
  const events: RuntimeCryptoEvent[] = []

  for (const row of inputs.runtimeEvents.slice(0, 60)) {
    const assetId = str(row.asset_id)
    const asset = assetsById.get(assetId)
    const algorithm = str(row.algorithm) || EVIDENCE_UNAVAILABLE
    const isPqc = row.is_pqc === true
    const isLegacy = row.is_legacy === true
    const hndl = row.hndl_risk === true
    const eventType = isPqc
      ? 'PQC algorithm observed'
      : isLegacy
        ? 'Legacy algorithm observed'
        : hndl
          ? 'Harvest-now-decrypt-later exposure'
          : 'Cryptographic use observed'
    events.push({
      id: `rt-${str(row.id)}`,
      observedAt: isoOrNull(row.observed_at) || isoOrNull(row.created_at),
      asset: asset?.name || str(row.asset_name) || EVIDENCE_UNAVAILABLE,
      assetId,
      eventType,
      algorithm,
      source: 'Runtime Crypto Telemetry',
      severity: normalizeSeverity(str(row.severity)),
      status: isPqc ? 'Compliant' : isLegacy ? 'Policy violation' : 'Observed',
      route: assetId ? `/dashboard/assets?asset=${encodeURIComponent(assetId)}` : '/dashboard/runtime-crypto-intel',
    })
  }

  for (const row of inputs.securityEvents.slice(0, 30)) {
    const type = str(row.event_type)
    if (!/crypto|cert|key|tls|algorithm|rotat|policy|drift/i.test(type)) continue
    events.push({
      id: `sec-${str(row.id)}`,
      observedAt: isoOrNull(row.created_at),
      asset: str(row.resource_name) || EVIDENCE_UNAVAILABLE,
      assetId: '',
      eventType: type.replace(/_/g, ' '),
      algorithm: EVIDENCE_UNAVAILABLE,
      source: 'Security Events',
      severity: normalizeSeverity(str(row.severity)),
      status: 'Recorded',
      route: '/dashboard/audit-vault',
    })
  }

  for (const job of inputs.migrationJobs.slice(0, 20)) {
    const status = str(job.status).toLowerCase()
    if (!/complete|fail|running/.test(status)) continue
    events.push({
      id: `job-${str(job.id)}`,
      observedAt: isoOrNull(job.updated_at) || isoOrNull(job.created_at),
      asset: str(job.name) || EVIDENCE_UNAVAILABLE,
      assetId: str(job.asset_id),
      eventType: /fail/.test(status) ? 'Cryptographic change failed' : /complete/.test(status) ? 'Cryptographic change completed' : 'Cryptographic change in progress',
      algorithm: str(job.target_algorithm) || EVIDENCE_UNAVAILABLE,
      source: 'Migration Jobs',
      severity: /fail/.test(status) ? 'high' : 'info',
      status: /fail/.test(status) ? 'Needs investigation' : 'Change recorded',
      route: '/dashboard/live-migration',
    })
  }

  return events
    .sort((a, b) => new Date(b.observedAt || 0).getTime() - new Date(a.observedAt || 0).getTime())
    .slice(0, 40)
}

/**
 * Reconstructs the agility trend from evidence TIMESTAMPS the tenant already
 * holds. Each bucket recomputes the vulnerable / PQC share from the components
 * discovered on or before that date, so the series is real tenant history —
 * explicitly flagged `reconstructed` because it is derived from discovery
 * timestamps rather than stored assessment rows.
 */
function buildHistory(
  inputs: AgilityInputs,
  currentScore: number | null,
  currentBlockers: number,
  policyPct: number | null,
  currentReadinessPct: number | null,
  now: number,
): AssessmentHistoryPoint[] {
  const dated = inputs.cryptoInventory
    .map((item) => ({
      at: isoOrNull(item.discovered_at) || isoOrNull(item.created_at),
      vulnerable: item.is_vulnerable === true || classifyAlgorithm(str(item.algorithm)) === 'vulnerable',
      pqc: item.is_quantum_safe === true || ['pqc', 'hybrid'].includes(classifyAlgorithm(str(item.algorithm))),
    }))
    .filter((row): row is { at: string; vulnerable: boolean; pqc: boolean } => Boolean(row.at))

  if (dated.length < 2) return []

  const times = dated.map((r) => new Date(r.at).getTime()).sort((a, b) => a - b)
  const earliest = times[0]
  const span = now - earliest
  if (span <= 0) return []

  const bucketCount = Math.min(6, Math.max(2, Math.ceil(span / (30 * 86400000))))
  const points: AssessmentHistoryPoint[] = []

  for (let index = 1; index <= bucketCount; index += 1) {
    const cutoff = earliest + (span * index) / bucketCount
    const upTo = dated.filter((r) => new Date(r.at).getTime() <= cutoff)
    if (!upTo.length) continue
    const vulnerable = upTo.filter((r) => r.vulnerable).length
    const pqc = upTo.filter((r) => r.pqc).length
    points.push({
      at: new Date(cutoff).toISOString(),
      label: new Date(cutoff).toLocaleDateString('en-US', { month: 'short', year: '2-digit' }),
      // No agility score for a reconstructed point: coupling, ownership and
      // dependency evidence has no historical snapshot, so the number simply
      // does not exist. The two component shares below DO, and they share one
      // scale across every point — including the live one.
      agilityScore: null,
      pqcAdoptionPct: Math.round(pctOf(pqc, upTo.length)),
      vulnerableSharePct: Math.round(pctOf(vulnerable, upTo.length)),
      migrationReadinessPct: null,
      blockers: 0,
      policyCompliancePct: null,
      assetsEvaluated: 0,
      componentsObserved: upTo.length,
      drift: 'unknown',
      reconstructed: true,
    })
  }

  if (points.length) {
    // The final point is the LIVE assessment, measured the same way as every
    // number on the page — it replaces the reconstructed bucket at "now".
    const last = points[points.length - 1]
    last.agilityScore = currentScore
    last.blockers = currentBlockers
    last.policyCompliancePct = policyPct
    last.migrationReadinessPct = currentReadinessPct
    last.assetsEvaluated = inputs.assets.filter((a) => a.hasEvidence).length
    last.reconstructed = false
    last.label = 'Now'
    last.at = new Date(now).toISOString()
  }

  // Drift between points is computed on PQC ADOPTION — the one series that is
  // measured identically at every point. Diffing a reconstructed proxy against
  // the live agility score would compare two different scales and report a
  // movement that never happened.
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
  now: number,
): AgilityDrift {
  const windowMs = 30 * 86400000
  const recentRuntime = inputs.runtimeEvents.filter((e) => {
    const at = isoOrNull(e.observed_at) || isoOrNull(e.created_at)
    return at ? now - new Date(at).getTime() <= windowMs : false
  })
  const newLegacy = recentRuntime.filter((e) => e.is_legacy === true).length
  const newPqc = recentRuntime.filter((e) => e.is_pqc === true).length
  const newCertificates = inputs.certificates.filter((c) => {
    const at = isoOrNull(c.created_at)
    return at ? now - new Date(at).getTime() <= windowMs : false
  }).length
  const newAnchors = coupling.filter((c) => c.type === 'static-trust-anchor').length
  const providerChanges = inputs.securityEvents.filter((e) => /provider|library|crypto_config|configuration/i.test(str(e.event_type))).length
  const failedChanges = inputs.migrationJobs.filter((j) => /fail/i.test(str(j.status))).length

  const signals: AgilityDrift['signals'] = [
    { label: 'Legacy algorithms re-observed', count: newLegacy, tone: newLegacy > 0 ? 'critical' : 'good', detail: 'Runtime events flagged as legacy cryptography in the last 30 days.' },
    { label: 'PQC / hybrid observations', count: newPqc, tone: newPqc > 0 ? 'good' : 'neutral', detail: 'Runtime events negotiating post-quantum or hybrid primitives in the last 30 days.' },
    { label: 'New certificates introduced', count: newCertificates, tone: newCertificates > 0 ? 'warning' : 'neutral', detail: 'Certificates first recorded in the last 30 days — each adds a chain that must be re-issued.' },
    { label: 'Static trust anchors', count: newAnchors, tone: newAnchors > 0 ? 'warning' : 'good', detail: 'Self-signed or privately operated anchors that gate chain replacement.' },
    { label: 'Provider / configuration changes', count: providerChanges, tone: providerChanges > 0 ? 'neutral' : 'neutral', detail: 'Recorded security events describing a cryptographic provider or configuration change.' },
    { label: 'Failed cryptographic changes', count: failedChanges, tone: failedChanges > 0 ? 'critical' : 'good', detail: 'Migration jobs that failed and left the asset on its original stack.' },
  ]

  let direction: DriftDirection = 'unknown'
  let deltaPoints: number | null = null

  // Direction is measured on PQC ADOPTION, the only series recorded identically
  // at every historical point. It is NOT the agility score — the score has no
  // historical snapshot, and diffing the two scales would invent a movement.
  const adoption = history.filter((p) => p.pqcAdoptionPct !== null)
  if (adoption.length >= 2) {
    const first = adoption[adoption.length - 2].pqcAdoptionPct as number
    const last = adoption[adoption.length - 1].pqcAdoptionPct as number
    deltaPoints = last - first
    if (failedChanges > 0 && deltaPoints <= 0) direction = 'critical'
    else if (deltaPoints > 2) direction = 'improving'
    else if (deltaPoints < -10) direction = 'critical'
    else if (deltaPoints < -2) direction = 'degrading'
    else direction = 'stable'
  }
  // A degrading runtime signal overrides a flat component trend: newly
  // re-observed legacy cryptography is a live regression even if the CBOM
  // composition has not moved.
  if (newLegacy > 0 && (direction === 'stable' || direction === 'improving')) direction = 'degrading'
  if (failedChanges > 0 && direction !== 'unknown') direction = 'critical'

  const basisParts: string[] = []
  if (adoption.length >= 2) {
    basisParts.push(`PQC component adoption moved ${deltaPoints !== null && deltaPoints > 0 ? '+' : ''}${deltaPoints} point(s) between the last two evidence buckets.`)
  } else {
    basisParts.push(`${EVIDENCE_UNAVAILABLE} — at least two dated evidence buckets are required to measure a component-adoption trend.`)
  }
  basisParts.push(
    inputs.runtimeEvents.length
      ? `${recentRuntime.length} runtime event(s), ${newCertificates} new certificate(s) and ${failedChanges} failed change(s) in the last 30 days.`
      : 'No runtime cryptographic telemetry, so live drift cannot be observed in operation.',
  )

  return {
    direction,
    deltaPoints,
    windowLabel: adoption.length >= 2 ? 'PQC adoption · last two evidence buckets' : 'Last 30 days',
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

function buildLifecycle(inputs: AgilityInputs, assetRows: AgilityAssetRow[], blockers: AgilityBlocker[], coupling: CouplingFinding[]): LifecycleStage[] {
  const evaluated = assetRows.filter((r) => r.hasEvidence)
  const total = Math.max(1, assetRows.length)
  const decoupled = evaluated.filter((r) => r.replaceability === 'configuration').length
  const sandboxJobs = inputs.migrationJobs.filter((j) => /sandbox/i.test(`${str(j.job_type)} ${str(j.name)}`)).length
  const executed = inputs.migrationJobs.filter((j) => /complete|done|success/i.test(str(j.status))).length
  const running = inputs.migrationJobs.filter((j) => /running|in_progress|executing/i.test(str(j.status))).length
  const validated = inputs.assets.filter((a) => a.validation.validated).length
  const monitored = unique(inputs.runtimeEvents.map((e) => str(e.asset_id)).filter(Boolean)).length

  const stage = (
    key: string,
    label: string,
    description: string,
    progressPct: number,
    metric: string,
    route: string,
    module: string,
    blocked = false,
  ): LifecycleStage => ({
    key,
    label,
    description,
    status: blocked ? 'blocked' : progressPct >= 100 ? 'complete' : progressPct > 0 ? 'active' : 'pending',
    progressPct: Math.round(clamp(progressPct)),
    metric,
    route,
    module,
  })

  return [
    stage('discover', 'Discover', 'Find every cryptographic asset and dependency.', assetRows.length ? 100 : 0, `${assetRows.length} asset(s) discovered`, '/dashboard/scanner', 'PQC Scanner'),
    stage('map', 'Map', 'Map cryptographic dependencies and coupling.', pctOf(evaluated.length, total), `${evaluated.length}/${assetRows.length} asset(s) with evidence`, '/dashboard/cbom_explorer', 'CBOM Explorer'),
    stage('assess', 'Assess', 'Score replaceability, rigidity and blockers.', evaluated.length ? 100 : 0, `${coupling.length} coupling finding(s) assessed`, '#agility-posture', 'Crypto Agility'),
    stage(
      'decouple',
      'Decouple',
      'Externalise cryptography so changes become configuration.',
      pctOf(decoupled, Math.max(1, evaluated.length)),
      `${decoupled}/${evaluated.length} asset(s) configuration-replaceable`,
      '#coupling-analysis',
      'Crypto Agility',
      blockers.some((b) => b.category === 'hardcoded-crypto' && b.severity === 'critical'),
    ),
    stage('simulate', 'Simulate', 'Prove the change in the digital twin before touching production.', sandboxJobs ? 100 : 0, sandboxJobs ? `${sandboxJobs} sandbox simulation(s)` : 'No simulation run yet', '/dashboard/migration-sandbox', 'Migration Sandbox'),
    stage('migrate', 'Migrate', 'Execute the approved cryptographic change.', pctOf(executed, Math.max(1, executed + running)), `${executed} completed, ${running} running`, '/dashboard/live-migration', 'Live Migration Ops'),
    stage('validate', 'Validate', 'Prove the new stack from real evidence.', pctOf(validated, Math.max(1, evaluated.length)), `${validated} asset(s) with a passing validation record`, '/dashboard/migration-timeline', 'Migration Operations'),
    stage('monitor', 'Monitor', 'Detect cryptographic drift in operation.', pctOf(monitored, total), `${monitored}/${assetRows.length} asset(s) under runtime telemetry`, '/dashboard/runtime-crypto-intel', 'Runtime Crypto Intelligence'),
    stage('repeat', 'Repeat', 'Re-run discovery so newly introduced cryptography is caught.', inputs.scanSessions.length ? 100 : 0, `${inputs.scanSessions.length} scan session(s) recorded`, '/dashboard/scanner', 'PQC Scanner'),
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
): AgilityRecommendation[] {
  const recommendations: AgilityRecommendation[] = []

  for (const blocker of blockers.slice(0, 5)) {
    const domain = domains.find((d) => d.key === blocker.domain)
    // Expected gain = the share of this domain's remaining headroom that clearing
    // the blocker recovers, weighted by the domain's weight. Bounded and derived.
    const headroom = domain && domain.score !== null ? (100 - domain.score) * (domain.weight / 100) : 0
    const share = domain && domain.blockers > 0 ? Math.min(1, blocker.count / domain.blockers) : 0.5
    const gain = Math.max(1, Math.round(headroom * share))
    const dependencyTotal = assetRows.reduce((sum, r) => sum + r.dependencies, 0)
    const affectedDependencies = assetRows
      .filter((r) => blocker.affectedAssetIds.includes(r.id))
      .reduce((sum, r) => sum + r.dependencies, 0)

    recommendations.push({
      id: `rec-${blocker.id}`,
      title: `Resolve ${blocker.count} ${blocker.categoryLabel.toLowerCase()} finding(s)`,
      detail: `${blocker.remediation} ${blocker.businessImpact}`,
      severity: blocker.severity,
      expectedScoreGain: gain,
      affectedAssets: blocker.affectedAssetIds.length,
      dependencyReductionPct: dependencyTotal > 0 ? Math.round(pctOf(affectedDependencies, dependencyTotal)) : null,
      controlDomain: blocker.controlDomain,
      action: blocker.controlDomain === 'customer' ? 'Create Remediation Plan' : 'Track Provider Dependency',
      route: blocker.route,
      evidence: coupling
        .filter((c) => blocker.affectedAssetIds.includes(c.assetId))
        .slice(0, 4)
        .map((c) => `${c.asset}: ${c.evidence}`),
    })
  }

  const weakestScored = domains
    .filter((d) => d.score !== null)
    .sort((a, b) => (a.score as number) - (b.score as number))[0]
  if (weakestScored && weakestScored.actions.length) {
    recommendations.push({
      id: `rec-domain-${weakestScored.key}`,
      title: `Lift ${weakestScored.label} — currently ${weakestScored.score}/100`,
      detail: `${weakestScored.actions[0]} ${weakestScored.basis}`,
      severity: (weakestScored.score as number) < 40 ? 'high' : 'medium',
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
      detail: `${unmeasured.map((d) => d.label).join(', ')} cannot be scored. Unknown is not safe — these domains are excluded from the score, so the headline understates the unknown risk until evidence exists.`,
      severity: 'medium',
      expectedScoreGain: 0,
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
      expectedScoreGain: 0,
      affectedAssets: criticalViolation.assets,
      dependencyReductionPct: null,
      controlDomain: 'customer',
      action: 'Create Remediation Plan',
      route: '/dashboard/quantum-remediation',
      evidence: criticalViolation.assetNames,
    })
  }

  return recommendations
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.expectedScoreGain - a.expectedScoreGain)
    .slice(0, 8)
}

/* ================================================================== */
/* Change impact preview (sandbox pre-flight)                          */
/* ================================================================== */

/**
 * Deterministic impact preview for a proposed cryptographic change.
 *
 * This is a PRE-FLIGHT projection over evidence the platform already holds — it
 * does NOT simulate. Execution belongs to the Migration Sandbox / Digital Twin
 * (`POST /api/v1/sandbox/simulate`), which this preview links into.
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

  const from = fromAlgorithm || asset.algorithms.find((a) => a.classification === 'vulnerable')?.algorithm || asset.algorithms[0]?.algorithm || EVIDENCE_UNAVAILABLE
  const matching = asset.algorithms.find((a) => a.algorithm.toUpperCase() === from.toUpperCase())
  const to = toAlgorithm || matching?.target || 'ML-KEM-768 / ML-DSA-65 hybrid stack'

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
  for (const cert of asset.certificates.filter((c) => !c.quantumSafe).slice(0, 3)) {
    potentialFailures.push({
      label: `${cert.name} — certificate chain`,
      detail: 'The classical chain must be re-issued from a PQC-capable CA; un-reissued leaves become invalid at cutover.',
      severity: cert.daysToExpiry !== null && cert.daysToExpiry < 30 ? 'high' : 'medium',
    })
  }
  if (!potentialFailures.length) {
    potentialFailures.push({
      label: 'No dependency failure predicted',
      detail: 'No peer, transport or certificate dependency in the tenant evidence would break under this change.',
      severity: 'info',
    })
  }

  const trustDeps = asset.dependencies.filter((d) => /trust|cert|identity|kms|federat/i.test(d.relationship)).length
  const migrationRiskScore = Math.round(
    clamp(asset.riskScore * 0.35 + (100 - asset.compatibility.score) * 0.35 + Math.min(100, asset.blastRadius * 8) * 0.3),
  )

  return {
    assetId,
    asset: asset.name,
    fromAlgorithm: from,
    toAlgorithm: to,
    assetsAffected: 1 + asset.dependencies.length,
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
    basis: `Projection over ${asset.evidence.sources.join(', ') || 'asset evidence'}. Execution runs in the Migration Sandbox digital twin — this preview does not simulate.`,
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
  const couplingObservableAssets = observableCouplingAssets(inputs)
  const derivations = new Map<string, AssetAgilityDerivation>()
  for (const asset of inputs.assets) {
    derivations.set(asset.id, deriveAssetAgility(asset, couplingByAsset, providerLocked, couplingObservableAssets))
  }

  const assetRows: AgilityAssetRow[] = inputs.assets.map((asset) => {
    const derivation = derivations.get(asset.id)!
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
  const replaceability = buildReplaceabilityMatrix(inputs, derivations)
  const graph = buildCouplingGraph(inputs, derivations, coupling)
  const policy = evaluatePolicy(inputs, now)

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
  const history = buildHistory(inputs, agilityScore, blockers.length, policy.compliancePct, migrationReadinessPct, now)
  const drift = buildDrift(inputs, history, coupling, now)

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
  const lifecycle = buildLifecycle(inputs, assetRows, blockers, coupling)
  const recommendations = buildRecommendations(domains, blockers, coupling, assetRows, policy)
  const runtimeEvents = buildRuntimeEvents(inputs)

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
    inputs.migrationJobs.length ? 'Migration Jobs' : '',
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
  const derivations = new Map<string, AssetAgilityDerivation>()
  for (const asset of inputs.assets) {
    derivations.set(asset.id, deriveAssetAgility(asset, couplingByAsset, providerLocked, couplingObservableAssets))
  }
  return derivations
}

export type { AssetAgilityDerivation }
