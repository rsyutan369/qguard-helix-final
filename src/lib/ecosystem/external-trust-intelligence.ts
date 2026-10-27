/**
 * QGuard Helix — External Trust & Ecosystem Intelligence Engine (isomorphic, pure).
 *
 * ONE engine behind FOUR pages, so they cannot drift:
 *
 *   Vendor PQC Readiness      → who do we depend on?
 *   Ecosystem Dependency Map  → what do we depend on?
 *   Trust Chain Analyzer      → what trust relationships exist?
 *   Hybrid Crypto Lab         → will the new crypto work?
 *
 * Every page renders a projection of the SAME computation over the SAME tenant
 * rows, so a vendor's readiness, an ecosystem node's risk and a trust chain's
 * verdict are the same fact expressed four ways — never four derivations that
 * disagree.
 *
 * Reuse contract
 * --------------
 *  - Vendor identity / PQ roadmap / ownership domain come from the SHARED
 *    Shared-Responsibility provider catalog + attribution engine.
 *  - Algorithm classification comes from the SHARED asset-intelligence engine.
 *  - `computeTrustAgility()` is exported so the Crypto Agility page's Trust
 *    domain consumes THIS function rather than re-deriving trust posture.
 *
 * Evidence discipline
 * -------------------
 *  - A vendor's CLAIM and QGuard's MEASUREMENT are separate fields and are
 *    never merged (§14). A promise is not a capability.
 *  - Missing evidence resolves to `unknown` and is never converted into a safe
 *    status (§5). Absence of a finding is not evidence of health.
 *  - Every derived status carries the `basis` string that produced it.
 */

import {
  EVIDENCE_UNAVAILABLE,
  classifyAlgorithm,
  clamp,
  num,
  recordOf,
  str,
  type Row,
} from '@/lib/migration/asset-intelligence'
import { PROVIDER_CATALOG } from '@/lib/shared-responsibility/provider-catalog'
import type { PqRoadmapStatus, ProviderProfile, ResponsibilityDomain } from '@/lib/shared-responsibility/types'

export { EVIDENCE_UNAVAILABLE }

/* ================================================================== */
/* 1 — Shared status vocabulary (§7)                                   */
/* ================================================================== */

export type Readiness = 'ready' | 'hybrid-ready' | 'preparing' | 'committed' | 'not-ready' | 'unknown'
export type EvidenceState = 'complete' | 'partial' | 'requested' | 'pending' | 'overdue' | 'rejected' | 'unknown'
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown'
export type DependencyKind = 'direct' | 'indirect' | 'critical' | 'optional' | 'unknown'
export type TrustState = 'trusted' | 'valid' | 'expiring' | 'weak' | 'broken' | 'unknown'
export type ExperimentOutcome = 'passed' | 'passed-with-warnings' | 'conditional' | 'failed' | 'not-evaluated'
export type CheckVerdict = 'pass' | 'fail' | 'unknown'

export const READINESS_LABEL: Record<Readiness, string> = {
  ready: 'Ready',
  'hybrid-ready': 'Hybrid Ready',
  preparing: 'Preparing',
  committed: 'Committed',
  'not-ready': 'Not Ready',
  unknown: 'Unknown',
}

export const EVIDENCE_LABEL: Record<EvidenceState, string> = {
  complete: 'Complete',
  partial: 'Partial',
  requested: 'Requested',
  pending: 'Pending',
  overdue: 'Overdue',
  rejected: 'Rejected',
  unknown: 'Unknown',
}

export const RISK_LABEL: Record<RiskLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  unknown: 'Unknown',
}

export const DEPENDENCY_LABEL: Record<DependencyKind, string> = {
  direct: 'Direct',
  indirect: 'Indirect',
  critical: 'Critical',
  optional: 'Optional',
  unknown: 'Unknown',
}

export const TRUST_LABEL: Record<TrustState, string> = {
  trusted: 'Trusted',
  valid: 'Valid',
  expiring: 'Expiring',
  weak: 'Weak',
  broken: 'Broken',
  unknown: 'Unknown',
}

export const EXPERIMENT_LABEL: Record<ExperimentOutcome, string> = {
  passed: 'Passed',
  'passed-with-warnings': 'Passed with Warnings',
  conditional: 'Conditional',
  failed: 'Failed',
  'not-evaluated': 'Not Evaluated',
}

const RISK_RANK: Record<RiskLevel, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }
export const riskRank = (risk: RiskLevel): number => RISK_RANK[risk]

/* ================================================================== */
/* 2 — Small shared helpers                                            */
/* ================================================================== */

function pctOf(part: number, total: number): number {
  if (!total || total <= 0) return 0
  return clamp((part / total) * 100)
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function isoOrNull(value: unknown): string | null {
  const text = str(value)
  if (!text) return null
  return Number.isFinite(new Date(text).getTime()) ? text : null
}

function normalizeSeverityToRisk(value: unknown): RiskLevel {
  const text = str(value).toLowerCase()
  if (!text) return 'unknown'
  if (text.includes('critical')) return 'critical'
  if (text.includes('high')) return 'high'
  if (text.includes('medium') || text.includes('moderate') || text.includes('warn')) return 'medium'
  if (text.includes('low') || text.includes('info')) return 'low'
  return 'unknown'
}

function titleCase(value: unknown, fallback = ''): string {
  const text = str(value).replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
  if (!text) return fallback
  return text.replace(/\b\w/g, (char) => char.toUpperCase())
}

function normalizeHost(value: unknown): string {
  return str(value).replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').toLowerCase()
}

function rootDomain(value: unknown): string {
  const host = normalizeHost(value)
  if (!host) return ''
  const parts = host.split('.').filter(Boolean)
  return parts.length <= 2 ? host : parts.slice(-2).join('.')
}

/** Issuers that demonstrate AUTOMATED issuance — the real certificate-agility signal. */
const MANAGED_ISSUER_MARKERS = [
  "let's encrypt", 'letsencrypt', 'acme', 'amazon', 'aws certificate', 'google trust',
  'cloudflare', 'azure', 'digicert managed', 'zerossl', 'cert-manager', 'certmanager', 'vault',
]

export function issuerLooksManaged(issuer: string): boolean {
  const text = issuer.toLowerCase()
  return MANAGED_ISSUER_MARKERS.some((marker) => text.includes(marker))
}

/**
 * Broken/deprecated signature primitives.
 *
 * X.509 records signature algorithms as `sha1WithRSAEncryption`,
 * `md5WithRSAEncryption`, `ecdsa-with-SHA1` — so a `\b`-anchored pattern
 * ("SHA-?1\b") MISSES the most common real-world spelling, because the digit is
 * followed immediately by a word character. That silently reported SHA-1 signed
 * certificates as healthy. A negative lookahead on a following DIGIT is used
 * instead: it still matches `sha1With…` while never matching SHA-256/384/512
 * or SHA3-256.
 */
const WEAK_SIGNATURE_RE = /SHA-?1(?!\d)|MD5(?!\d)|MD2(?!\d)|RSA-?(?:512|1024)\b|DSA-?1024\b/i

/* ================================================================== */
/* 3 — Vendor domain                                                   */
/* ================================================================== */

export type StandardKey = 'nist-pqc' | 'fips-140' | 'tls-1-3' | 'cnsa-2' | 'internal-crypto-policy'
export type StandardAlignment = 'aligned' | 'partial' | 'not-aligned' | 'not-applicable' | 'unknown'

export const STANDARD_LABEL: Record<StandardKey, string> = {
  'nist-pqc': 'NIST PQC (FIPS 203/204/205)',
  'fips-140': 'FIPS 140-3 validation',
  'tls-1-3': 'TLS 1.3 transport baseline',
  'cnsa-2': 'CNSA 2.0 timelines',
  'internal-crypto-policy': 'Internal cryptographic policy',
}

export const ALIGNMENT_LABEL: Record<StandardAlignment, string> = {
  aligned: 'Aligned',
  partial: 'Partial',
  'not-aligned': 'Not Aligned',
  'not-applicable': 'Not Applicable',
  unknown: 'Unknown',
}

export interface StandardsAlignmentRow {
  key: StandardKey
  label: string
  applicable: boolean
  alignment: StandardAlignment
  evidence: string
  lastVerifiedAt: string | null
  basis: string
}

export type MigrationSupportLevel = 'full' | 'partial' | 'roadmap-only' | 'none' | 'unknown'

export const MIGRATION_SUPPORT_LABEL: Record<MigrationSupportLevel, string> = {
  full: 'Full Support',
  partial: 'Partial Support',
  'roadmap-only': 'Roadmap Only',
  none: 'No Support',
  unknown: 'Unknown',
}

export type ObligationState = 'covered' | 'partially-covered' | 'under-review' | 'missing' | 'expired' | 'unknown'

export const OBLIGATION_LABEL: Record<ObligationState, string> = {
  covered: 'Covered',
  'partially-covered': 'Partially Covered',
  'under-review': 'Under Review',
  missing: 'Missing',
  expired: 'Expired',
  unknown: 'Unknown',
}

export interface ContractualObligation {
  key: string
  label: string
  state: ObligationState
  detail: string
  basis: string
}

export type EvidenceRequestType =
  | 'pqc-roadmap'
  | 'algorithm-support-matrix'
  | 'tls-pqc-statement'
  | 'certificate-roadmap'
  | 'key-management-roadmap'
  | 'crypto-architecture'
  | 'migration-timeline'
  | 'product-version-support'
  | 'security-compliance-docs'

export const EVIDENCE_REQUEST_LABEL: Record<EvidenceRequestType, string> = {
  'pqc-roadmap': 'PQC roadmap',
  'algorithm-support-matrix': 'Algorithm support matrix',
  'tls-pqc-statement': 'TLS / PQC support statement',
  'certificate-roadmap': 'Certificate roadmap',
  'key-management-roadmap': 'Key management roadmap',
  'crypto-architecture': 'Cryptographic architecture',
  'migration-timeline': 'Migration timeline',
  'product-version-support': 'Product version support',
  'security-compliance-docs': 'Security / compliance documentation',
}

export type EvidenceRequestStage =
  | 'requested'
  | 'vendor-responded'
  | 'evidence-received'
  | 'under-review'
  | 'accepted'
  | 'rejected'

export const EVIDENCE_STAGE_LABEL: Record<EvidenceRequestStage, string> = {
  requested: 'Requested',
  'vendor-responded': 'Vendor Responded',
  'evidence-received': 'Evidence Received',
  'under-review': 'Under Review',
  accepted: 'Accepted',
  rejected: 'Rejected',
}

export const EVIDENCE_STAGE_ORDER: readonly EvidenceRequestStage[] = [
  'requested', 'vendor-responded', 'evidence-received', 'under-review', 'accepted',
] as const

export interface EvidenceRequestRecord {
  id: string
  vendor: string
  requestType: EvidenceRequestType
  requestLabel: string
  stage: EvidenceRequestStage
  owner: string
  requestedAt: string | null
  dueAt: string | null
  respondedAt: string | null
  reviewer: string
  responseSummary: string
  evidenceRef: string
  overdue: boolean
  notes: string
}

export interface VendorRiskFactor {
  key: string
  label: string
  score: number
  weight: number
  contribution: number
  evidence: string
}

export interface VendorRoadmapStage {
  key: 'current' | 'hybrid' | 'pqc' | 'legacy-retirement'
  label: string
  /** What the vendor says. Never treated as capability. */
  vendorCommitment: string
  vendorTargetDate: string | null
  /** What QGuard measured from tenant evidence. */
  qguardAssessment: string
  assessed: boolean
}

export interface VendorPqcPosition {
  currentAlgorithms: string[]
  supportedAlgorithms: string[]
  hybridSupport: CheckVerdict
  kemSupport: CheckVerdict
  signatureSupport: CheckVerdict
  tlsSupport: CheckVerdict
  certificateSupport: CheckVerdict
  keyManagementSupport: CheckVerdict
  /** Per-capability provenance: 'measured' | 'vendor-claim' | 'none'. */
  provenance: Record<string, 'measured' | 'vendor-claim' | 'none'>
  basis: string
}

export interface VendorRecord {
  id: string
  name: string
  category: string
  domain: ResponsibilityDomain
  services: string[]
  businessOwner: string
  technicalOwner: string
  criticality: RiskLevel
  environments: string[]

  /** What the vendor publicly commits to (catalog roadmap / assessment row). */
  vendorCommitment: Readiness
  vendorCommitmentBasis: string
  /** What QGuard actually measured on this vendor's observed surfaces. */
  assessedReadiness: Readiness
  assessedReadinessBasis: string
  /** Conservative combination used for roll-ups: never better than measured. */
  readiness: Readiness

  pqRoadmapStatus: PqRoadmapStatus
  position: VendorPqcPosition
  standards: StandardsAlignmentRow[]
  standardsSummary: StandardAlignment
  evidenceState: EvidenceState
  evidenceBasis: string
  openRequests: number
  overdueRequests: number
  obligations: ContractualObligation[]
  obligationSummary: ObligationState
  migrationSupport: MigrationSupportLevel
  migrationSupportDetail: string[]
  roadmap: VendorRoadmapStage[]

  risk: RiskLevel
  riskScore: number
  riskFactors: VendorRiskFactor[]
  riskExplanation: string

  linkedAssetIds: string[]
  linkedAssetCount: number
  observedHosts: string[]
  certificateCount: number
  signalCount: number
  lastAssessmentAt: string | null
  nextReviewAt: string | null
  hasEvidence: boolean
  reference?: string
}

/* ================================================================== */
/* 4 — Ecosystem domain                                                */
/* ================================================================== */

export type EcosystemNodeKind =
  | 'vendor' | 'service' | 'application' | 'identity' | 'pki'
  | 'crypto' | 'protocol' | 'infrastructure' | 'business-service'

export const NODE_KIND_LABEL: Record<EcosystemNodeKind, string> = {
  vendor: 'Vendor',
  service: 'Service',
  application: 'Application',
  identity: 'Identity',
  pki: 'PKI',
  crypto: 'Crypto',
  protocol: 'Protocol',
  infrastructure: 'Infrastructure',
  'business-service': 'Business Service',
}

export type EcosystemEdgeKind =
  | 'consumes' | 'authenticates-with' | 'secured-by' | 'issued-by'
  | 'anchored-by' | 'implements' | 'federates-with' | 'hosted-on' | 'depends-on'

export interface EcosystemNode {
  id: string
  label: string
  kind: EcosystemNodeKind
  external: boolean
  owner: string
  environment: string
  criticality: RiskLevel
  readiness: Readiness
  risk: RiskLevel
  dependencyKind: DependencyKind
  /** Tenant assets that transit this node. */
  assetIds: string[]
  vendorId: string | null
  algorithms: string[]
  detail: string
  evidenceSources: string[]
  hasEvidence: boolean
  route: string
}

export interface EcosystemEdge {
  source: string
  target: string
  kind: EcosystemEdgeKind
  /** false ⇒ inferred from co-occurrence, not an explicit relationship row. */
  explicit: boolean
  risk: RiskLevel
  basis: string
}

export interface BlastRadiusResult {
  nodeId: string
  label: string
  directDependencies: number
  indirectDependencies: number
  applicationsAffected: number
  businessServices: number
  trustRelationships: number
  migrationPlans: number
  criticalServices: number
  affectedNodeIds: string[]
  depths: Array<{ depth: number; nodeIds: string[] }>
  basis: string
}

export interface SinglePointOfFailure {
  nodeId: string
  label: string
  kind: EcosystemNodeKind
  downstreamConsumers: number
  alternativesObserved: number
  readiness: Readiness
  criticality: RiskLevel
  evidenceState: EvidenceState
  risk: RiskLevel
  reasons: string[]
  basis: string
}

export interface MigrationBottleneck {
  nodeId: string
  label: string
  vendorId: string | null
  blockedAssets: number
  affectedAssetNames: string[]
  reason: string
  vendorStatus: Readiness
  evidenceState: EvidenceState
  alternatives: string[]
  recommendedAction: string
  route: string
  risk: RiskLevel
}

export interface UnknownDependency {
  id: string
  label: string
  kind: EcosystemNodeKind
  reason: string
  affectedAssetIds: string[]
  recommendedAction: string
}

export interface DependencyChainStep {
  nodeId: string
  label: string
  kind: EcosystemNodeKind
  depth: number
  risk: RiskLevel
  readiness: Readiness
}

/* ================================================================== */
/* 5 — Trust domain                                                    */
/* ================================================================== */

export type TrustNodeKind =
  | 'root-ca' | 'intermediate-ca' | 'certificate' | 'service'
  | 'application' | 'trust-anchor' | 'identity-provider' | 'federation' | 'vendor'

export const TRUST_NODE_LABEL: Record<TrustNodeKind, string> = {
  'root-ca': 'Root CA',
  'intermediate-ca': 'Intermediate CA',
  certificate: 'Certificate',
  service: 'Service',
  application: 'Application',
  'trust-anchor': 'Trust Anchor',
  'identity-provider': 'Identity Provider',
  federation: 'Federation',
  vendor: 'Vendor',
}

export interface TrustNode {
  id: string
  label: string
  kind: TrustNodeKind
  state: TrustState
  algorithm: string
  keySize: number
  external: boolean
  vendorId: string | null
  detail: string
}

export interface CertificateDetail {
  id: string
  subject: string
  issuer: string
  notBefore: string | null
  notAfter: string | null
  daysToExpiry: number | null
  signatureAlgorithm: string
  publicKeyAlgorithm: string
  keySize: number
  quantumSafe: boolean
  renewalMechanism: 'automated' | 'manual' | 'unknown'
  owner: string
  environment: string
  assetId: string | null
  trustAnchor: string
  chainNodeIds: string[]
  state: TrustState
  basis: string
}

export type TrustFindingKind =
  | 'broken-chain' | 'expiring-certificate' | 'weak-algorithm' | 'legacy-signature'
  | 'unknown-ca' | 'external-ca-dependency' | 'static-trust-anchor'
  | 'manual-renewal' | 'missing-automation' | 'pqc-compatibility' | 'vendor-dependency'

export const TRUST_FINDING_LABEL: Record<TrustFindingKind, string> = {
  'broken-chain': 'Broken chain',
  'expiring-certificate': 'Expiring certificate',
  'weak-algorithm': 'Weak algorithm',
  'legacy-signature': 'Legacy signature',
  'unknown-ca': 'Unknown CA',
  'external-ca-dependency': 'External CA dependency',
  'static-trust-anchor': 'Static trust anchor',
  'manual-renewal': 'Manual renewal',
  'missing-automation': 'Missing automation',
  'pqc-compatibility': 'PQC compatibility issue',
  'vendor-dependency': 'Vendor dependency',
}

export interface TrustFinding {
  id: string
  kind: TrustFindingKind
  title: string
  severity: RiskLevel
  chainId: string | null
  evidence: string
  evidenceSource: string
  affectedAssetIds: string[]
  affectedAssetNames: string[]
  recommendedAction: string
  route: string
}

export interface TrustChain {
  id: string
  name: string
  nodes: TrustNode[]
  edges: Array<{ source: string; target: string }>
  state: TrustState
  risk: RiskLevel
  external: boolean
  vendorId: string | null
  certificate: CertificateDetail | null
  assetIds: string[]
  assetNames: string[]
  findingIds: string[]
  /** Proposed post-quantum chain — labelled as proposal, never as available fact. */
  proposed: {
    nodes: TrustNode[]
    feasibility: 'supported' | 'requires-ca-support' | 'unknown'
    note: string
  }
  migrationImpact: {
    applications: number
    services: number
    certificates: number
    trustAnchors: number
    vendorDependencies: number
    compatibilityIssues: string[]
  }
  basis: string
}

export interface TrustAgilityBreakdown {
  key: 'certificate-replaceability' | 'ca-agility' | 'trust-anchor-agility' | 'federation-agility' | 'renewal-automation' | 'pqc-compatibility'
  label: string
  score: number | null
  weight: number
  basis: string
}

export interface TrustAgility {
  score: number | null
  level: string
  breakdown: TrustAgilityBreakdown[]
  coverage: number
  basis: string
}

/* ================================================================== */
/* 6 — Lab domain                                                      */
/* ================================================================== */

export type KeyExchangeOption = 'X25519' | 'ML-KEM-768' | 'X25519+ML-KEM-768'
export type SignatureOption = 'Ed25519' | 'ML-DSA-65' | 'Ed25519+ML-DSA-65'
export type SymmetricOption = 'AES-256-GCM'
export type KdfOption = 'HKDF-SHA3-256' | 'HKDF-SHA-256'
export type HashOption = 'SHA3-256' | 'SHA3-512'

export const KEY_EXCHANGE_OPTIONS: readonly KeyExchangeOption[] = ['X25519', 'ML-KEM-768', 'X25519+ML-KEM-768'] as const
export const SIGNATURE_OPTIONS: readonly SignatureOption[] = ['Ed25519', 'ML-DSA-65', 'Ed25519+ML-DSA-65'] as const
export const SYMMETRIC_OPTIONS: readonly SymmetricOption[] = ['AES-256-GCM'] as const
export const KDF_OPTIONS: readonly KdfOption[] = ['HKDF-SHA3-256', 'HKDF-SHA-256'] as const
export const HASH_OPTIONS: readonly HashOption[] = ['SHA3-256', 'SHA3-512'] as const

export interface ExperimentConfiguration {
  protocol: 'TLS 1.3' | 'TLS 1.2'
  keyExchange: KeyExchangeOption
  signature: SignatureOption
  symmetric: SymmetricOption
  kdf: KdfOption
  hash: HashOption
}

export type ExecutionMode = 'simulation' | 'controlled-test'

export const EXECUTION_MODE_LABEL: Record<ExecutionMode, string> = {
  simulation: 'Simulation — evidence projection, no connection made',
  'controlled-test': 'Controlled Test — live read-only handshake probe',
}

export interface ExperimentTarget {
  kind: 'asset' | 'endpoint' | 'vendor' | 'certificate'
  id: string
  label: string
  host: string
  port: number
  environment: string
  vendorId: string | null
  assetId: string | null
}

export interface ConfigValidationIssue {
  field: keyof ExperimentConfiguration | 'combination'
  message: string
}

export interface ExperimentCheck {
  key: 'protocol' | 'crypto' | 'certificate' | 'trust-chain' | 'application' | 'vendor' | 'policy'
  label: string
  verdict: CheckVerdict
  detail: string
  /** How this verdict was reached — measured beats inferred, and we say which. */
  method: 'measured' | 'evidence-derived' | 'not-evaluated'
}

export interface ExperimentFinding {
  id: string
  title: string
  severity: RiskLevel
  component: string
  evidence: string
  likelyCause: string
  affectedDependencies: string[]
  recommendedAction: string
  route: string
}

export interface ExperimentRecord {
  id: string
  createdAt: string
  target: ExperimentTarget
  currentConfiguration: Partial<ExperimentConfiguration> & { observed: string[] }
  proposedConfiguration: ExperimentConfiguration
  executionMode: ExecutionMode
  outcome: ExperimentOutcome
  checks: ExperimentCheck[]
  findings: ExperimentFinding[]
  risk: RiskLevel
  durationMs: number
  evidenceGenerated: boolean
  evidenceId: string | null
  /** Always true — a laboratory result never proves production security (§52). */
  requiresProductionValidation: boolean
  basis: string
  /** What a controlled-test handshake actually negotiated; null for simulations. */
  probe: ExperimentProbe | null
}

/**
 * The stored outcome of a READ-ONLY handshake probe. Only facts the TLS engine
 * observed — `untestableGroups` lists groups the local TLS build could not
 * offer, which are therefore unmeasured rather than refused.
 */
export interface ExperimentProbe {
  measured: boolean
  negotiatedProtocol: string | null
  supportedProtocols: string[]
  legacyProtocols: string[]
  hybridGroups: string[]
  pureKemGroups: string[]
  hybridProbed: boolean
  untestableGroups: string[]
  forwardSecrecy: boolean
  certificateAlgorithm: string | null
  certificateIssuer: string | null
  certificateDaysToExpiry: number | null
  chainLength: number
  error: string | null
}

function toExperimentProbe(value: unknown): ExperimentProbe | null {
  const probe = recordOf(value)
  if (!Object.keys(probe).length) return null
  const list = (entry: unknown) => (Array.isArray(entry) ? entry.map((item) => str(item)).filter(Boolean) : [])
  const nullable = (entry: unknown) => str(entry) || null
  return {
    measured: probe.measured === true,
    negotiatedProtocol: nullable(probe.negotiatedProtocol),
    supportedProtocols: list(probe.supportedProtocols),
    legacyProtocols: list(probe.legacyProtocols),
    hybridGroups: list(probe.hybridGroups),
    pureKemGroups: list(probe.pureKemGroups),
    hybridProbed: probe.hybridProbed === true,
    untestableGroups: list(probe.untestableGroups),
    forwardSecrecy: probe.forwardSecrecy === true,
    certificateAlgorithm: nullable(probe.certificateAlgorithm),
    certificateIssuer: nullable(probe.certificateIssuer),
    certificateDaysToExpiry: probe.certificateDaysToExpiry === null || probe.certificateDaysToExpiry === undefined
      ? null
      : num(probe.certificateDaysToExpiry),
    chainLength: num(probe.chainLength),
    error: nullable(probe.error),
  }
}

/* ================================================================== */
/* 7 — Aggregate + inputs                                              */
/* ================================================================== */

export interface ExternalTrustInputs {
  assets: Row[]
  assetRelationships: Row[]
  certificates: Row[]
  cryptoInventory: Row[]
  cryptoExposures: Row[]
  scanResults: Row[]
  scannerEvidence: Row[]
  scannerAlerts: Row[]
  runtimeEvents: Row[]
  connectorAccounts: Row[]
  vendorAssessments: Row[]
  trustFindings: Row[]
  migrationJobs: Row[]
  complianceEvidence: Row[]
  evidenceRequests: Row[]
  experiments: Row[]
  now?: number
}

export interface ExternalTrustIntelligence {
  generatedAt: string
  hasData: boolean
  evidence: {
    sources: string[]
    assets: number
    certificates: number
    relationships: number
    vendorAssessments: number
    connectors: number
    runtimeEvents: number
    note: string
  }
  vendors: {
    records: VendorRecord[]
    summary: {
      assessed: number
      ready: number
      hybridReady: number
      preparingOrCommitted: number
      notReady: number
      unknown: number
      evidencePending: number
      criticalRisks: number
      overallReadinessPct: number | null
      readinessBasis: string
    }
    distribution: Array<{ readiness: Readiness; label: string; count: number; share: number }>
    evidenceRequests: EvidenceRequestRecord[]
    persistenceAvailable: boolean
  }
  ecosystem: {
    nodes: EcosystemNode[]
    edges: EcosystemEdge[]
    summary: {
      externalDependencies: number
      criticalDependencies: number
      vendorDependencies: number
      singlePointsOfFailure: number
      unknownDependencies: number
      migrationBlockers: number
    }
    singlePointsOfFailure: SinglePointOfFailure[]
    bottlenecks: MigrationBottleneck[]
    unknowns: UnknownDependency[]
    recommendations: Array<{ id: string; title: string; detail: string; action: string; route: string; risk: RiskLevel }>
  }
  trust: {
    chains: TrustChain[]
    findings: TrustFinding[]
    certificates: CertificateDetail[]
    agility: TrustAgility
    summary: {
      chains: number
      criticalChains: number
      expiringCertificates: number
      legacyAlgorithms: number
      externalTrustDependencies: number
      unknownRelationships: number
    }
  }
  lab: {
    targets: ExperimentTarget[]
    experiments: ExperimentRecord[]
    summary: {
      experiments: number
      passed: number
      conditional: number
      failed: number
      compatibilityIssues: number
      evidenceGenerated: number
    }
    persistenceAvailable: boolean
  }
}

/* ================================================================== */
/* 8 — Vendor derivation                                               */
/* ================================================================== */

interface VendorAccumulator {
  id: string
  name: string
  profile: ProviderProfile | null
  category: string
  domain: ResponsibilityDomain
  services: Set<string>
  hosts: Set<string>
  assetIds: Set<string>
  environments: Set<string>
  algorithms: Map<string, number>
  certificates: Row[]
  signals: number
  vulnerableSignals: number
  pqcSignals: number
  tlsProtocols: Set<string>
  assessment: Row | null
  connector: Row | null
  lastSeen: string | null
  sources: Set<string>
}

const CATALOG_BY_ID = new Map(PROVIDER_CATALOG.map((profile) => [profile.id, profile]))

/**
 * Matches observed evidence against the shared provider catalog.
 *
 * `strict` restricts matching to STRUCTURAL fingerprints (hostname, CNAME,
 * connector provider) or the provider's own name. Generic keywords are excluded
 * there because a tenant-named vendor like "Acme Payments" would otherwise be
 * silently rebranded as whichever catalog provider claims the keyword
 * "payments" — replacing the customer's own supplier with someone else's.
 *
 * Loose matching stays available for observed HOSTS, where keyword evidence is
 * the only signal available and the risk of mis-branding is far lower.
 */
function matchProvider(text: string, mode: 'loose' | 'strict' = 'loose'): ProviderProfile | null {
  const haystack = text.toLowerCase()
  if (!haystack.trim()) return null
  for (const profile of PROVIDER_CATALOG) {
    if (profile.domain === 'customer') continue
    const fingerprints = profile.fingerprints
    const structural = [
      ...(fingerprints.hostname || []),
      ...(fingerprints.cname || []),
      ...(fingerprints.connectorProvider || []),
    ]
    if (structural.some((needle) => needle && haystack.includes(needle.toLowerCase()))) return profile
    if (haystack.includes(profile.name.toLowerCase())) return profile
    if (mode === 'strict') continue
    if ((fingerprints.keywords || []).some((needle) => needle && haystack.includes(needle.toLowerCase()))) return profile
  }
  return null
}

function vendorIdFor(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'vendor'
}

function readinessFromRoadmap(status: PqRoadmapStatus): Readiness {
  switch (status) {
    case 'shipping': return 'ready'
    case 'in_progress': return 'preparing'
    case 'announced': return 'committed'
    case 'not_applicable': return 'unknown'
    default: return 'unknown'
  }
}

const READINESS_RANK: Record<Readiness, number> = {
  ready: 5, 'hybrid-ready': 4, preparing: 3, committed: 2, 'not-ready': 1, unknown: 0,
}

/** Conservative combine: the published readiness never exceeds what was measured. */
function combineReadiness(commitment: Readiness, assessed: Readiness): Readiness {
  if (assessed === 'unknown') return commitment === 'ready' || commitment === 'hybrid-ready' ? 'committed' : commitment
  if (READINESS_RANK[assessed] >= READINESS_RANK[commitment]) return assessed
  return assessed
}

function buildVendors(inputs: ExternalTrustInputs, now: number): {
  records: VendorRecord[]
  requests: EvidenceRequestRecord[]
} {
  const accumulators = new Map<string, VendorAccumulator>()
  const assetById = new Map(inputs.assets.map((asset) => [str(asset.id), asset]))

  /**
   * `preserveName` keeps the tenant's own label authoritative. A vendor the
   * customer explicitly recorded must never be displayed under a catalog
   * provider's name just because a profile attached to it.
   */
  const ensure = (name: string, profile: ProviderProfile | null, source: string, preserveName = false): VendorAccumulator => {
    const id = profile && !preserveName ? profile.id : vendorIdFor(name)
    const existing = accumulators.get(id)
    if (existing) {
      existing.sources.add(source)
      if (profile && !existing.profile) {
        existing.profile = profile
        existing.category = profile.category
        existing.domain = profile.domain
        if (!preserveName) existing.name = profile.name
      }
      return existing
    }
    const created: VendorAccumulator = {
      id,
      name: profile && !preserveName ? profile.name : titleCase(name, name),
      profile,
      category: profile ? profile.category : 'unknown',
      domain: profile ? profile.domain : 'provider',
      services: new Set<string>(),
      hosts: new Set<string>(),
      assetIds: new Set<string>(),
      environments: new Set<string>(),
      algorithms: new Map<string, number>(),
      certificates: [],
      signals: 0,
      vulnerableSignals: 0,
      pqcSignals: 0,
      tlsProtocols: new Set<string>(),
      assessment: null,
      connector: null,
      lastSeen: null,
      sources: new Set<string>([source]),
    }
    accumulators.set(id, created)
    return created
  }

  const touch = (acc: VendorAccumulator, at: string | null) => {
    if (!at) return
    if (!acc.lastSeen || new Date(at).getTime() > new Date(acc.lastSeen).getTime()) acc.lastSeen = at
  }

  /* ---- Tenant-managed vendor assessments (explicit) ---------------- */
  for (const row of inputs.vendorAssessments) {
    const name = str(row.vendor_name) || str(row.name)
    if (!name) continue
    // Strict matching + name preservation: the tenant named this supplier, so
    // the catalog may enrich it but must never rename or absorb it.
    const profile = matchProvider(name, 'strict')
    const acc = ensure(name, profile, 'vendor_assessments', true)
    acc.assessment = row
    if (str(row.category)) acc.category = str(row.category)
    touch(acc, isoOrNull(row.last_assessed_at) || isoOrNull(row.updated_at) || isoOrNull(row.created_at))
  }

  /* ---- Connected platforms ----------------------------------------- */
  for (const row of inputs.connectorAccounts) {
    const provider = str(row.provider)
    const display = str(row.display_name)
    const name = display || provider
    if (!name) continue
    const profile = matchProvider(`${provider} ${display}`)
    const acc = ensure(name, profile, 'connector_accounts')
    acc.connector = row
    acc.services.add(titleCase(provider, provider))
    touch(acc, isoOrNull(row.last_sync_at) || isoOrNull(row.updated_at))
  }

  /* ---- Certificate issuers are CA vendors -------------------------- */
  for (const cert of inputs.certificates) {
    const issuer = str(cert.issuer)
    if (!issuer) continue
    const profile = matchProvider(issuer)
    const acc = ensure(issuer, profile, 'certificates')
    acc.certificates.push(cert)
    acc.services.add('Certificate issuance')
    const algorithm = str(cert.algorithm)
    if (algorithm) acc.algorithms.set(algorithm, (acc.algorithms.get(algorithm) || 0) + 1)
    const assetId = str(cert.asset_id)
    if (assetId) {
      acc.assetIds.add(assetId)
      const asset = assetById.get(assetId)
      if (asset) acc.environments.add(str(asset.environment) || 'unknown')
    }
    acc.signals += 1
    if (cert.is_quantum_safe === true) acc.pqcSignals += 1
    else if (classifyAlgorithm(algorithm) === 'vulnerable') acc.vulnerableSignals += 1
    touch(acc, isoOrNull(cert.updated_at) || isoOrNull(cert.created_at))
  }

  /* ---- Observed external hosts (runtime + scanner evidence) -------- */
  const hostRows: Array<[string, Row[]]> = [
    ['runtime_crypto_events', inputs.runtimeEvents],
    ['scanner_evidence', inputs.scannerEvidence],
  ]
  for (const [source, rows] of hostRows) {
    for (const row of rows) {
      const host = normalizeHost(row.host || row.target || row.asset_name)
      if (!host) continue
      const domainName = rootDomain(host)
      const profile = matchProvider(`${host} ${str(row.asset_name)} ${str(row.package_name)}`)
      // Only EXTERNAL hosts become vendors. A host matching a tenant asset name
      // is our own surface, not a supplier.
      const isOwnAsset = inputs.assets.some((asset) => normalizeHost(asset.name) === host)
      if (!profile && isOwnAsset) continue
      const acc = ensure(profile ? profile.name : domainName, profile, source)
      acc.hosts.add(host)
      const algorithm = str(row.algorithm) || str(row.observed_algorithm) || str(row.key_exchange_algorithm)
      if (algorithm) acc.algorithms.set(algorithm, (acc.algorithms.get(algorithm) || 0) + 1)
      const protocol = str(row.protocol) || str(row.tls_version)
      if (protocol) acc.tlsProtocols.add(protocol)
      const assetId = str(row.asset_id)
      if (assetId) acc.assetIds.add(assetId)
      acc.signals += 1
      if (row.is_pqc === true || classifyAlgorithm(algorithm) === 'pqc' || classifyAlgorithm(algorithm) === 'hybrid') acc.pqcSignals += 1
      if (row.is_legacy === true || classifyAlgorithm(algorithm) === 'vulnerable') acc.vulnerableSignals += 1
      touch(acc, isoOrNull(row.observed_at) || isoOrNull(row.created_at))
    }
  }

  /* ---- Evidence requests ------------------------------------------- */
  const requests: EvidenceRequestRecord[] = inputs.evidenceRequests.map((row) => {
    const dueAt = isoOrNull(row.due_at)
    const stage = (str(row.stage) || 'requested') as EvidenceRequestStage
    const settled = stage === 'accepted' || stage === 'rejected'
    return {
      id: str(row.id),
      vendor: str(row.vendor_name),
      requestType: (str(row.request_type) || 'pqc-roadmap') as EvidenceRequestType,
      requestLabel: EVIDENCE_REQUEST_LABEL[(str(row.request_type) || 'pqc-roadmap') as EvidenceRequestType] || titleCase(row.request_type),
      stage,
      owner: str(row.owner) || 'Unassigned',
      requestedAt: isoOrNull(row.requested_at) || isoOrNull(row.created_at),
      dueAt,
      respondedAt: isoOrNull(row.responded_at),
      reviewer: str(row.reviewer) || 'Unassigned',
      responseSummary: str(row.response_summary),
      evidenceRef: str(row.evidence_ref),
      overdue: Boolean(dueAt && !settled && new Date(dueAt).getTime() < now),
      notes: str(row.notes),
    }
  })
  const requestsByVendor = new Map<string, EvidenceRequestRecord[]>()
  for (const request of requests) {
    const key = vendorIdFor(request.vendor)
    const list = requestsByVendor.get(key) || []
    list.push(request)
    requestsByVendor.set(key, list)
  }

  /* ---- Materialise records ----------------------------------------- */
  const records: VendorRecord[] = []
  for (const acc of accumulators.values()) {
    const assessment = acc.assessment
    const meta = recordOf(assessment?.metadata)
    const declaredSupport = recordOf(assessment?.support)

    const algorithms = [...acc.algorithms.entries()].sort((a, b) => b[1] - a[1]).map(([name]) => name)
    const pqcAlgorithms = algorithms.filter((a) => ['pqc', 'hybrid'].includes(classifyAlgorithm(a)))
    const classicalAlgorithms = algorithms.filter((a) => classifyAlgorithm(a) === 'vulnerable')

    /* -- Vendor COMMITMENT (claims) -- */
    const roadmapStatus: PqRoadmapStatus = acc.profile?.pqRoadmapStatus ?? 'unknown'
    let commitment: Readiness = readinessFromRoadmap(roadmapStatus)
    let commitmentBasis = acc.profile?.pqRoadmapNote
      ? `Published provider position: ${acc.profile.pqRoadmapNote}`
      : `No published post-quantum position is recorded for this provider.`
    const declaredStatus = str(assessment?.readiness_status)
    if (declaredStatus) {
      const lower = declaredStatus.toLowerCase()
      commitment = lower.includes('quantum ready') || lower.includes('ready') ? 'ready'
        : lower.includes('hybrid') ? 'hybrid-ready'
        : lower.includes('planned') || lower.includes('progress') ? 'preparing'
        : lower.includes('commit') ? 'committed'
        : lower.includes('critical') || lower.includes('high risk') ? 'not-ready'
        : 'unknown'
      commitmentBasis = `Vendor assessment record states "${declaredStatus}". This is a vendor claim, not a measured capability.`
    }

    /* -- QGuard ASSESSMENT (measured) -- */
    let assessed: Readiness = 'unknown'
    let assessedBasis = `${EVIDENCE_UNAVAILABLE} — no cryptographic evidence has been observed on this vendor's surfaces.`
    if (acc.signals > 0) {
      const pqcShare = pctOf(acc.pqcSignals, acc.signals)
      const vulnerableShare = pctOf(acc.vulnerableSignals, acc.signals)
      if (pqcShare >= 80) assessed = 'ready'
      else if (pqcShare > 0) assessed = 'hybrid-ready'
      else if (vulnerableShare >= 50) assessed = 'not-ready'
      else assessed = 'preparing'
      assessedBasis = `${acc.signals} observed signal(s): ${acc.pqcSignals} post-quantum/hybrid, ${acc.vulnerableSignals} quantum-vulnerable${algorithms.length ? ` (${algorithms.slice(0, 3).join(', ')})` : ''}.`
    }

    const readiness = combineReadiness(commitment, assessed)

    /* -- PQC position, with per-capability provenance -- */
    const provenance: VendorPqcPosition['provenance'] = {}
    const verdictFor = (measured: boolean, claimed: boolean, key: string): CheckVerdict => {
      if (measured) { provenance[key] = 'measured'; return 'pass' }
      if (claimed) { provenance[key] = 'vendor-claim'; return 'unknown' }
      provenance[key] = 'none'
      return 'unknown'
    }
    const claims = JSON.stringify(declaredSupport).toLowerCase()
    const position: VendorPqcPosition = {
      currentAlgorithms: algorithms.slice(0, 8),
      supportedAlgorithms: pqcAlgorithms.slice(0, 8),
      hybridSupport: verdictFor(algorithms.some((a) => classifyAlgorithm(a) === 'hybrid'), /hybrid/.test(claims), 'hybrid'),
      kemSupport: verdictFor(algorithms.some((a) => /ML-KEM|KYBER/i.test(a)), /ml-kem|kyber/.test(claims), 'kem'),
      signatureSupport: verdictFor(algorithms.some((a) => /ML-DSA|SLH-DSA|DILITHIUM|SPHINCS/i.test(a)), /ml-dsa|dilithium|slh/.test(claims), 'signature'),
      tlsSupport: verdictFor([...acc.tlsProtocols].some((p) => /1\.3/.test(p)), /tls/.test(claims), 'tls'),
      certificateSupport: verdictFor(acc.certificates.some((c) => c.is_quantum_safe === true), /cert/.test(claims), 'certificate'),
      keyManagementSupport: verdictFor(false, /key|kms|hsm/.test(claims), 'keyManagement'),
      provenance,
      basis: acc.signals
        ? `Measured from ${acc.signals} observed signal(s) across ${[...acc.sources].join(', ')}. Vendor claims are shown separately and never counted as capability.`
        : `${EVIDENCE_UNAVAILABLE} — capability can only be confirmed from observed cryptography or accepted evidence.`,
    }

    /* -- Standards alignment: applicability is evidence-driven -- */
    const standards: StandardsAlignmentRow[] = []
    const pushStandard = (
      key: StandardKey, applicable: boolean, alignment: StandardAlignment, evidence: string, basis: string,
    ) => standards.push({
      key, label: STANDARD_LABEL[key], applicable,
      alignment: applicable ? alignment : 'not-applicable',
      evidence, lastVerifiedAt: acc.lastSeen, basis,
    })

    pushStandard(
      'nist-pqc', acc.signals > 0,
      pqcAlgorithms.length ? (classicalAlgorithms.length ? 'partial' : 'aligned') : acc.signals ? 'not-aligned' : 'unknown',
      pqcAlgorithms.length ? pqcAlgorithms.join(', ') : classicalAlgorithms.slice(0, 3).join(', ') || EVIDENCE_UNAVAILABLE,
      'Applicable wherever the vendor terminates or issues cryptography for this tenant.',
    )
    pushStandard(
      'tls-1-3', acc.tlsProtocols.size > 0,
      [...acc.tlsProtocols].some((p) => /1\.3/.test(p))
        ? ([...acc.tlsProtocols].some((p) => /1\.[012]/.test(p)) ? 'partial' : 'aligned')
        : 'not-aligned',
      [...acc.tlsProtocols].join(', ') || EVIDENCE_UNAVAILABLE,
      'Applicable only where transport telemetry was observed for this vendor.',
    )
    pushStandard(
      'fips-140', acc.certificates.length > 0 || acc.signals > 0, 'unknown',
      EVIDENCE_UNAVAILABLE,
      'FIPS validation cannot be observed from network evidence — it requires vendor documentation.',
    )
    pushStandard(
      'cnsa-2', acc.domain !== 'customer' && acc.signals > 0,
      pqcAlgorithms.length ? 'partial' : 'unknown', EVIDENCE_UNAVAILABLE,
      'CNSA 2.0 applicability depends on the tenant’s regulatory scope; alignment needs vendor attestation.',
    )
    pushStandard(
      'internal-crypto-policy', true,
      classicalAlgorithms.length ? 'not-aligned' : pqcAlgorithms.length ? 'aligned' : 'unknown',
      classicalAlgorithms.slice(0, 3).join(', ') || pqcAlgorithms.slice(0, 3).join(', ') || EVIDENCE_UNAVAILABLE,
      'The platform mandatory PQC stack applies to every vendor surface carrying tenant cryptography.',
    )

    const applicableStandards = standards.filter((s) => s.applicable)
    const standardsSummary: StandardAlignment = !applicableStandards.length ? 'unknown'
      : applicableStandards.every((s) => s.alignment === 'aligned') ? 'aligned'
      : applicableStandards.some((s) => s.alignment === 'not-aligned') ? 'not-aligned'
      : applicableStandards.some((s) => s.alignment === 'partial') ? 'partial'
      : 'unknown'

    /* -- Evidence state -- */
    const vendorRequests = requestsByVendor.get(acc.id) || requestsByVendor.get(vendorIdFor(acc.name)) || []
    const accepted = vendorRequests.filter((r) => r.stage === 'accepted')
    const rejected = vendorRequests.filter((r) => r.stage === 'rejected')
    const overdue = vendorRequests.filter((r) => r.overdue)
    const open = vendorRequests.filter((r) => r.stage !== 'accepted' && r.stage !== 'rejected')
    let evidenceState: EvidenceState = 'unknown'
    let evidenceBasis = 'No evidence has been requested from this vendor yet.'
    if (overdue.length) { evidenceState = 'overdue'; evidenceBasis = `${overdue.length} evidence request(s) are past their due date.` }
    else if (rejected.length && !accepted.length) { evidenceState = 'rejected'; evidenceBasis = `${rejected.length} submitted evidence item(s) were rejected on review.` }
    else if (accepted.length && open.length === 0) { evidenceState = 'complete'; evidenceBasis = `${accepted.length} evidence item(s) accepted; no open requests.` }
    else if (accepted.length) { evidenceState = 'partial'; evidenceBasis = `${accepted.length} accepted, ${open.length} still open.` }
    else if (open.some((r) => r.stage === 'evidence-received' || r.stage === 'under-review')) { evidenceState = 'pending'; evidenceBasis = `${open.length} request(s) awaiting review.` }
    else if (open.length) { evidenceState = 'requested'; evidenceBasis = `${open.length} request(s) sent, no response recorded yet.` }

    /* -- Contractual obligations -- */
    const contractText = `${str(assessment?.contract_status)} ${JSON.stringify(meta)}`.toLowerCase()
    const obligationFor = (key: string, label: string, needle: RegExp, detail: string): ContractualObligation => {
      let state: ObligationState = 'unknown'
      let basis = 'No contractual evidence recorded for this obligation.'
      if (contractText.trim()) {
        if (needle.test(contractText)) {
          state = /missing|absent|no |none|gap/.test(contractText) ? 'missing'
            : /review|pending/.test(contractText) ? 'under-review'
            : /partial/.test(contractText) ? 'partially-covered' : 'covered'
          basis = `Derived from the recorded contract status on the vendor assessment.`
        } else {
          state = 'missing'
          basis = 'The recorded contract status does not mention this obligation.'
        }
      }
      return { key, label, state, detail, basis }
    }
    const obligations: ContractualObligation[] = [
      obligationFor('pqc-migration', 'PQC migration commitment', /pqc|post.?quantum|quantum/, 'Vendor commits to supporting post-quantum algorithms within an agreed window.'),
      obligationFor('crypto-lifecycle', 'Crypto lifecycle requirements', /lifecycle|rotation|deprecat/, 'Algorithm lifecycle, rotation and deprecation duties are contractually defined.'),
      obligationFor('notification', 'Notification obligations', /notif|disclos|incident/, 'Vendor must notify on cryptographic change, incident or deprecation.'),
      obligationFor('supported-algorithms', 'Supported algorithms', /algorithm|cipher|suite/, 'The contract enumerates the algorithms the vendor must support.'),
      obligationFor('certificate', 'Certificate obligations', /certificate|pki|ca\b/, 'Issuance, re-issuance and chain duties are covered.'),
      obligationFor('key-rotation', 'Key rotation requirements', /key|rotation|hsm|kms/, 'Key custody and rotation duties are covered.'),
    ]
    const obligationSummary: ObligationState = !contractText.trim() ? 'unknown'
      : obligations.some((o) => o.state === 'missing') ? 'missing'
      : obligations.every((o) => o.state === 'covered') ? 'covered'
      : 'partially-covered'

    /* -- Migration support -- */
    const supportDetail: string[] = []
    let migrationSupport: MigrationSupportLevel = 'unknown'
    if (acc.profile) {
      if (roadmapStatus === 'shipping') { migrationSupport = 'full'; supportDetail.push('Provider ships post-quantum support today.') }
      else if (roadmapStatus === 'in_progress') { migrationSupport = 'partial'; supportDetail.push('Provider has post-quantum work in progress.') }
      else if (roadmapStatus === 'announced') { migrationSupport = 'roadmap-only'; supportDetail.push('Provider has announced intent but shipped nothing observable.') }
      else if (roadmapStatus === 'not_applicable') { migrationSupport = 'none'; supportDetail.push('Post-quantum migration does not apply to this provider’s role.') }
    }
    if (acc.profile?.reference) supportDetail.push(`Reference: ${acc.profile.reference}`)
    if (!supportDetail.length) supportDetail.push('No migration documentation, tooling or support statement has been recorded.')

    /* -- Roadmap: commitment vs assessment, kept apart -- */
    const roadmap: VendorRoadmapStage[] = [
      {
        key: 'current', label: 'Current State',
        vendorCommitment: declaredStatus || 'Not stated',
        vendorTargetDate: null,
        qguardAssessment: acc.signals ? `${classicalAlgorithms.length} classical, ${pqcAlgorithms.length} post-quantum primitive(s) observed` : EVIDENCE_UNAVAILABLE,
        assessed: acc.signals > 0,
      },
      {
        key: 'hybrid', label: 'Hybrid Support',
        vendorCommitment: /hybrid/.test(claims) ? 'Claimed' : 'Not stated',
        vendorTargetDate: isoOrNull(meta.hybrid_target || meta.hybridTarget),
        qguardAssessment: position.hybridSupport === 'pass' ? 'Hybrid key exchange observed' : 'Not observed',
        assessed: position.hybridSupport === 'pass',
      },
      {
        key: 'pqc', label: 'PQC Support',
        vendorCommitment: acc.profile?.pqRoadmapNote || (/(ml-kem|ml-dsa)/.test(claims) ? 'Claimed' : 'Not stated'),
        vendorTargetDate: isoOrNull(meta.pqc_target || meta.pqcTarget),
        qguardAssessment: pqcAlgorithms.length ? `Observed: ${pqcAlgorithms.slice(0, 3).join(', ')}` : 'Not observed',
        assessed: pqcAlgorithms.length > 0,
      },
      {
        key: 'legacy-retirement', label: 'Legacy Crypto Retirement',
        vendorCommitment: /retire|deprecat|sunset/.test(contractText) ? 'Contractually referenced' : 'Not stated',
        vendorTargetDate: isoOrNull(meta.legacy_retirement || meta.legacyRetirement),
        qguardAssessment: classicalAlgorithms.length ? `${classicalAlgorithms.length} classical primitive(s) still observed` : acc.signals ? 'No classical primitive observed' : EVIDENCE_UNAVAILABLE,
        assessed: acc.signals > 0,
      },
    ]

    /* -- Risk, from explicit factors -- */
    const criticalityFromAssets = (() => {
      const linked = [...acc.assetIds].map((id) => assetById.get(id)).filter(Boolean) as Row[]
      if (linked.some((a) => /critical/i.test(str(a.criticality)))) return 'critical' as RiskLevel
      if (linked.some((a) => /high/i.test(str(a.criticality)))) return 'high' as RiskLevel
      if (linked.length) return 'medium' as RiskLevel
      return 'unknown' as RiskLevel
    })()

    const factorDefs: Array<[string, string, number, number, string]> = [
      ['criticality', 'Business criticality', criticalityFromAssets === 'critical' ? 100 : criticalityFromAssets === 'high' ? 75 : criticalityFromAssets === 'medium' ? 45 : 30, 22,
        criticalityFromAssets === 'unknown' ? 'No tenant asset is linked to this vendor yet.' : `Highest linked asset criticality is ${RISK_LABEL[criticalityFromAssets]}.`],
      ['readiness', 'Measured PQC readiness', assessed === 'ready' ? 5 : assessed === 'hybrid-ready' ? 30 : assessed === 'preparing' ? 60 : assessed === 'not-ready' ? 95 : 70, 22,
        assessedBasis],
      ['evidence', 'Evidence confidence', evidenceState === 'complete' ? 5 : evidenceState === 'partial' ? 40 : evidenceState === 'overdue' ? 90 : evidenceState === 'rejected' ? 85 : evidenceState === 'unknown' ? 75 : 55, 18, evidenceBasis],
      ['contract', 'Contractual coverage', obligationSummary === 'covered' ? 10 : obligationSummary === 'partially-covered' ? 45 : obligationSummary === 'missing' ? 90 : 70, 14,
        obligationSummary === 'unknown' ? 'No contract status recorded.' : `Obligations are ${OBLIGATION_LABEL[obligationSummary].toLowerCase()}.`],
      ['dependency', 'Migration dependency', Math.min(100, acc.assetIds.size * 12 + acc.certificates.length * 8), 12,
        `${acc.assetIds.size} tenant asset(s) and ${acc.certificates.length} certificate(s) depend on this vendor.`],
      ['replacement', 'Replacement difficulty', acc.profile?.customerInfluence === 'high' ? 25 : acc.profile?.customerInfluence === 'medium' ? 55 : acc.profile?.customerInfluence === 'low' ? 80 : 70, 12,
        acc.profile ? `Customer influence over this provider is ${acc.profile.customerInfluence}.` : 'Provider influence is unknown — assume limited leverage.'],
    ]
    const riskFactors: VendorRiskFactor[] = factorDefs.map(([key, label, score, weight, evidence]) => ({
      key, label, score: Math.round(clamp(score)), weight,
      contribution: Math.round(clamp(score) * (weight / 100) * 10) / 10, evidence,
    }))
    const riskScore = Math.round(riskFactors.reduce((sum, factor) => sum + factor.score * (factor.weight / 100), 0))
    const risk: RiskLevel = riskScore >= 75 ? 'critical' : riskScore >= 55 ? 'high' : riskScore >= 35 ? 'medium' : 'low'
    const topFactor = [...riskFactors].sort((a, b) => b.contribution - a.contribution)[0]

    const nextReview = isoOrNull(meta.next_review || meta.nextReview)

    records.push({
      id: acc.id,
      name: acc.name,
      category: titleCase(acc.category, 'Unknown'),
      domain: acc.domain,
      services: [...acc.services].slice(0, 6),
      businessOwner: str(meta.business_owner || meta.businessOwner) || 'Unassigned',
      technicalOwner: str(meta.technical_owner || meta.technicalOwner) || 'Unassigned',
      criticality: criticalityFromAssets,
      environments: [...acc.environments].filter(Boolean),
      vendorCommitment: commitment,
      vendorCommitmentBasis: commitmentBasis,
      assessedReadiness: assessed,
      assessedReadinessBasis: assessedBasis,
      readiness,
      pqRoadmapStatus: roadmapStatus,
      position,
      standards,
      standardsSummary,
      evidenceState,
      evidenceBasis,
      openRequests: open.length,
      overdueRequests: overdue.length,
      obligations,
      obligationSummary,
      migrationSupport,
      migrationSupportDetail: supportDetail,
      roadmap,
      risk,
      riskScore,
      riskFactors,
      riskExplanation: `Vendor risk scores ${riskScore}/100 (${RISK_LABEL[risk]}), driven mainly by ${topFactor.label.toLowerCase()} — ${topFactor.evidence}`,
      linkedAssetIds: [...acc.assetIds],
      linkedAssetCount: acc.assetIds.size,
      observedHosts: [...acc.hosts].slice(0, 10),
      certificateCount: acc.certificates.length,
      signalCount: acc.signals,
      lastAssessmentAt: acc.lastSeen,
      nextReviewAt: nextReview,
      hasEvidence: acc.signals > 0 || Boolean(assessment),
      reference: acc.profile?.reference,
    })
  }

  records.sort((a, b) => riskRank(b.risk) - riskRank(a.risk) || b.riskScore - a.riskScore || a.name.localeCompare(b.name))
  return { records, requests }
}

/* ================================================================== */
/* 9 — Ecosystem derivation                                            */
/* ================================================================== */

function classifyAssetNode(asset: Row): EcosystemNodeKind {
  const text = `${str(asset.type)} ${str(asset.name)}`.toLowerCase()
  if (/idp|identity|auth|sso|oauth|oidc|saml|directory|ldap/.test(text)) return 'identity'
  if (/ca\b|pki|certificate/.test(text)) return 'pki'
  if (/k8s|kubernetes|cluster|server|host|vm|node|gateway|load|proxy|cdn/.test(text)) return 'infrastructure'
  if (/api|service|endpoint|micro/.test(text)) return 'service'
  if (/payment|billing|checkout|order|business/.test(text)) return 'business-service'
  return 'application'
}

function buildEcosystem(
  inputs: ExternalTrustInputs,
  vendors: VendorRecord[],
  now: number,
): ExternalTrustIntelligence['ecosystem'] {
  const nodes = new Map<string, EcosystemNode>()
  const edges: EcosystemEdge[] = []
  const edgeKeys = new Set<string>()
  const assetById = new Map(inputs.assets.map((asset) => [str(asset.id), asset]))
  const vendorById = new Map(vendors.map((vendor) => [vendor.id, vendor]))

  const addNode = (node: EcosystemNode) => {
    const existing = nodes.get(node.id)
    if (existing) {
      existing.assetIds = unique([...existing.assetIds, ...node.assetIds])
      existing.algorithms = unique([...existing.algorithms, ...node.algorithms])
      existing.evidenceSources = unique([...existing.evidenceSources, ...node.evidenceSources])
      if (riskRank(node.risk) > riskRank(existing.risk)) existing.risk = node.risk
      return existing
    }
    nodes.set(node.id, node)
    return node
  }

  const addEdge = (source: string, target: string, kind: EcosystemEdgeKind, explicit: boolean, risk: RiskLevel, basis: string) => {
    if (source === target) return
    const key = `${source}→${target}`
    if (edgeKeys.has(key)) return
    edgeKeys.add(key)
    edges.push({ source, target, kind, explicit, risk, basis })
  }

  /* ---- Tenant assets ------------------------------------------------ */
  for (const asset of inputs.assets) {
    const id = `asset:${str(asset.id)}`
    const criticality = normalizeSeverityToRisk(asset.criticality)
    addNode({
      id,
      label: str(asset.name) || 'Unnamed asset',
      kind: classifyAssetNode(asset),
      external: false,
      owner: str(asset.service_owner) || 'Unassigned',
      environment: str(asset.environment) || 'unknown',
      criticality: criticality === 'unknown' ? 'medium' : criticality,
      readiness: 'unknown',
      risk: 'unknown',
      dependencyKind: 'direct',
      assetIds: [str(asset.id)],
      vendorId: null,
      algorithms: [],
      detail: `${str(asset.type) || 'asset'} · ${str(asset.environment) || 'unknown'} environment`,
      evidenceSources: ['assets'],
      hasEvidence: true,
      route: `/dashboard/assets?asset=${encodeURIComponent(str(asset.id))}`,
    })
  }

  /* ---- Explicit asset relationships --------------------------------- */
  for (const rel of inputs.assetRelationships) {
    const source = str(rel.source_asset_id || rel.parent_asset_id || rel.from_asset_id)
    const target = str(rel.target_asset_id || rel.child_asset_id || rel.to_asset_id)
    if (!source || !target) continue
    if (!nodes.has(`asset:${source}`) || !nodes.has(`asset:${target}`)) continue
    addEdge(`asset:${source}`, `asset:${target}`, 'depends-on', true, 'unknown', `asset_relationships row: ${str(rel.relationship_type) || 'depends-on'}`)
  }

  /* ---- Vendors ------------------------------------------------------ */
  for (const vendor of vendors) {
    const id = `vendor:${vendor.id}`
    addNode({
      id,
      label: vendor.name,
      kind: 'vendor',
      external: true,
      owner: vendor.businessOwner,
      environment: vendor.environments[0] || 'unknown',
      criticality: vendor.criticality,
      readiness: vendor.readiness,
      risk: vendor.risk,
      dependencyKind: vendor.linkedAssetCount > 0 ? 'direct' : 'unknown',
      assetIds: vendor.linkedAssetIds,
      vendorId: vendor.id,
      algorithms: vendor.position.currentAlgorithms,
      detail: `${vendor.category} · ${READINESS_LABEL[vendor.readiness]} · ${vendor.linkedAssetCount} linked asset(s)`,
      evidenceSources: ['vendor intelligence'],
      hasEvidence: vendor.hasEvidence,
      route: `/dashboard/vendor-pqc-readiness?vendor=${encodeURIComponent(vendor.id)}`,
    })
    for (const assetId of vendor.linkedAssetIds) {
      if (!nodes.has(`asset:${assetId}`)) continue
      addEdge(`asset:${assetId}`, id, 'consumes', true, vendor.risk, `Asset consumes cryptography attributed to ${vendor.name}.`)
    }
  }

  /* ---- PKI + certificates ------------------------------------------- */
  for (const cert of inputs.certificates) {
    const issuer = str(cert.issuer)
    const assetId = str(cert.asset_id)
    if (!issuer) continue
    const caId = `pki:${issuer.toLowerCase()}`
    const managed = issuerLooksManaged(issuer)
    addNode({
      id: caId,
      label: issuer,
      kind: 'pki',
      external: true,
      owner: 'Certificate Authority',
      environment: 'external',
      criticality: 'high',
      readiness: cert.is_quantum_safe === true ? 'ready' : 'unknown',
      risk: managed ? 'medium' : 'high',
      dependencyKind: 'critical',
      assetIds: assetId ? [assetId] : [],
      vendorId: vendors.find((v) => v.name.toLowerCase() === issuer.toLowerCase())?.id ?? null,
      algorithms: [str(cert.algorithm)].filter(Boolean),
      detail: managed ? 'Managed issuer — issuance can be automated.' : 'No automated issuance evidence recorded.',
      evidenceSources: ['certificates'],
      hasEvidence: true,
      route: '/dashboard/pki-visibility',
    })
    if (assetId && nodes.has(`asset:${assetId}`)) {
      addEdge(`asset:${assetId}`, caId, 'issued-by', true, managed ? 'medium' : 'high', `Certificate "${str(cert.name) || str(cert.subject)}" issued by ${issuer}.`)
    }
  }

  /* ---- Crypto + protocol nodes from observed inventory --------------- */
  for (const item of inputs.cryptoInventory) {
    const assetId = str(item.asset_id)
    if (!assetId || !nodes.has(`asset:${assetId}`)) continue
    const itemType = str(item.item_type).toLowerCase()
    const algorithm = str(item.algorithm)
    if (itemType === 'library' && str(item.name)) {
      const libId = `crypto:${str(item.name).toLowerCase()}`
      addNode({
        id: libId, label: str(item.name), kind: 'crypto', external: true,
        owner: 'Provider', environment: 'runtime',
        criticality: 'medium',
        readiness: item.is_quantum_safe === true ? 'ready' : 'unknown',
        risk: item.is_vulnerable === true ? 'high' : 'unknown',
        dependencyKind: 'direct', assetIds: [assetId], vendorId: null,
        algorithms: [algorithm].filter(Boolean),
        detail: 'Cryptographic provider inventoried on this asset.',
        evidenceSources: ['crypto_inventory'], hasEvidence: true,
        route: '/dashboard/cbom_explorer',
      })
      addEdge(`asset:${assetId}`, libId, 'implements', true, 'unknown', 'CBOM library component bound to this asset.')
    }
    const protocol = str(item.protocol)
    if (protocol) {
      const protoId = `protocol:${protocol.toLowerCase()}`
      addNode({
        id: protoId, label: protocol, kind: 'protocol', external: false,
        owner: 'Platform', environment: 'transport',
        criticality: 'medium',
        readiness: /1\.3/.test(protocol) ? 'preparing' : 'not-ready',
        risk: /1\.[01]|SSL/i.test(protocol) ? 'high' : 'low',
        dependencyKind: 'direct', assetIds: [assetId], vendorId: null,
        algorithms: [algorithm].filter(Boolean),
        detail: `Transport protocol observed on ${str(item.name) || 'this asset'}.`,
        evidenceSources: ['crypto_inventory'], hasEvidence: true,
        route: '/dashboard/protocol-analytics',
      })
      addEdge(`asset:${assetId}`, protoId, 'secured-by', true, 'unknown', 'Protocol observed in the CBOM for this asset.')
    }
  }

  /* ---- Roll readiness/risk down onto asset nodes --------------------- */
  for (const node of nodes.values()) {
    if (node.kind === 'vendor' || node.external) continue
    const incidentVendors = edges
      .filter((edge) => edge.source === node.id)
      .map((edge) => nodes.get(edge.target))
      .filter((target): target is EcosystemNode => Boolean(target) && target!.kind === 'vendor')
    if (incidentVendors.length) {
      node.risk = incidentVendors.reduce<RiskLevel>((worst, vendor) => (riskRank(vendor.risk) > riskRank(worst) ? vendor.risk : worst), 'unknown')
      node.readiness = incidentVendors.reduce<Readiness>(
        (worst, vendor) => (READINESS_RANK[vendor.readiness] < READINESS_RANK[worst] ? vendor.readiness : worst),
        'ready',
      )
    }
  }

  const nodeList = [...nodes.values()]
  const externalNodes = nodeList.filter((node) => node.external)

  /* ---- Downstream adjacency (who depends on X) ----------------------- */
  const dependents = new Map<string, Set<string>>()
  for (const edge of edges) {
    const set = dependents.get(edge.target) || new Set<string>()
    set.add(edge.source)
    dependents.set(edge.target, set)
  }

  /* ---- Single points of failure -------------------------------------- */
  const spofs: SinglePointOfFailure[] = []
  for (const node of externalNodes) {
    const consumers = dependents.get(node.id)?.size ?? 0
    if (consumers === 0) continue
    const sameKind = externalNodes.filter((other) => other.kind === node.kind && other.id !== node.id).length
    const vendor = node.vendorId ? vendorById.get(node.vendorId) : undefined
    const evidenceState = vendor?.evidenceState ?? 'unknown'
    const reasons: string[] = []
    if (consumers >= 2) reasons.push(`${consumers} tenant dependencies transit this node.`)
    if (sameKind === 0) reasons.push('No alternative provider of the same kind is present in the estate.')
    if (node.readiness === 'not-ready' || node.readiness === 'unknown') reasons.push(`Post-quantum readiness is ${READINESS_LABEL[node.readiness]}.`)
    if (node.criticality === 'critical' || node.criticality === 'high') reasons.push(`Linked assets carry ${RISK_LABEL[node.criticality]} criticality.`)
    if (evidenceState === 'unknown' || evidenceState === 'overdue') reasons.push(`Vendor evidence is ${EVIDENCE_LABEL[evidenceState]}.`)
    // A single point of failure needs concentration AND fragility — never one alone.
    if (reasons.length < 2 || consumers < 2) continue
    spofs.push({
      nodeId: node.id, label: node.label, kind: node.kind,
      downstreamConsumers: consumers, alternativesObserved: sameKind,
      readiness: node.readiness, criticality: node.criticality, evidenceState,
      risk: riskRank(node.risk) >= riskRank('high') ? node.risk : consumers >= 4 ? 'high' : 'medium',
      reasons,
      basis: `${consumers} dependent node(s), ${sameKind} alternative(s) of the same kind observed in this tenant's evidence.`,
    })
  }
  spofs.sort((a, b) => riskRank(b.risk) - riskRank(a.risk) || b.downstreamConsumers - a.downstreamConsumers)

  /* ---- Migration bottlenecks ------------------------------------------ */
  const bottlenecks: MigrationBottleneck[] = []
  for (const vendor of vendors) {
    if (vendor.readiness === 'ready') continue
    if (vendor.linkedAssetCount === 0) continue
    const names = vendor.linkedAssetIds
      .map((id) => str(assetById.get(id)?.name))
      .filter(Boolean)
    bottlenecks.push({
      nodeId: `vendor:${vendor.id}`,
      label: vendor.name,
      vendorId: vendor.id,
      blockedAssets: vendor.linkedAssetCount,
      affectedAssetNames: names.slice(0, 10),
      reason: vendor.assessedReadiness === 'unknown'
        ? 'No post-quantum capability has been observed on this vendor’s surfaces, so dependent assets cannot be migrated with confidence.'
        : `Measured readiness is ${READINESS_LABEL[vendor.assessedReadiness]}; dependent assets inherit that ceiling.`,
      vendorStatus: vendor.readiness,
      evidenceState: vendor.evidenceState,
      alternatives: externalNodes
        .filter((node) => node.kind === 'vendor' && node.vendorId !== vendor.id && node.readiness === 'ready')
        .map((node) => node.label).slice(0, 3),
      recommendedAction: vendor.evidenceState === 'unknown'
        ? 'Request a PQC roadmap and algorithm support matrix from this vendor.'
        : 'Validate the proposed configuration in the Hybrid Crypto Lab before sequencing dependent assets.',
      route: `/dashboard/vendor-pqc-readiness?vendor=${encodeURIComponent(vendor.id)}`,
      risk: vendor.risk,
    })
  }
  bottlenecks.sort((a, b) => riskRank(b.risk) - riskRank(a.risk) || b.blockedAssets - a.blockedAssets)

  /* ---- Unknown dependencies -------------------------------------------- */
  const unknowns: UnknownDependency[] = []
  for (const node of nodeList) {
    if (node.kind === 'vendor' && !node.hasEvidence) {
      unknowns.push({
        id: node.id, label: node.label, kind: node.kind,
        reason: 'Vendor is referenced by evidence but carries no observed cryptographic signal or assessment.',
        affectedAssetIds: node.assetIds,
        recommendedAction: 'Run an assessment or request evidence so this dependency can be scored.',
      })
      continue
    }
    if (!node.external) continue
    if (node.readiness === 'unknown' && node.assetIds.length > 0) {
      unknowns.push({
        id: node.id, label: node.label, kind: node.kind,
        reason: 'External dependency with no post-quantum readiness evidence — its migration behaviour is undetermined.',
        affectedAssetIds: node.assetIds,
        recommendedAction: 'Investigate this dependency before it becomes a migration failure point.',
      })
    }
  }
  // Assets with no recorded relationship at all are undocumented dependencies.
  for (const node of nodeList) {
    if (node.external) continue
    const hasAny = edges.some((edge) => edge.source === node.id || edge.target === node.id)
    if (hasAny) continue
    unknowns.push({
      id: node.id, label: node.label, kind: node.kind,
      reason: 'No dependency relationship of any kind has been recorded for this asset.',
      affectedAssetIds: node.assetIds,
      recommendedAction: 'Map this asset’s upstream and downstream dependencies so blast radius can be computed.',
    })
  }

  /* ---- Recommendations --------------------------------------------------- */
  const recommendations: ExternalTrustIntelligence['ecosystem']['recommendations'] = []
  const evidenceGapVendors = vendors.filter((v) => v.evidenceState === 'unknown' && v.linkedAssetCount > 0)
  if (evidenceGapVendors.length) {
    recommendations.push({
      id: 'rec-request-evidence',
      title: `Request PQC evidence from ${evidenceGapVendors.length} vendor(s)`,
      detail: `${evidenceGapVendors.slice(0, 3).map((v) => v.name).join(', ')}${evidenceGapVendors.length > 3 ? ` and ${evidenceGapVendors.length - 3} more` : ''} carry tenant dependencies with no evidence on file.`,
      action: 'Request Evidence', route: '/dashboard/vendor-pqc-readiness', risk: 'high',
    })
  }
  if (spofs.length) {
    recommendations.push({
      id: 'rec-spof',
      title: `Identify an alternate provider for ${spofs[0].label}`,
      detail: `${spofs[0].label} concentrates ${spofs[0].downstreamConsumers} dependencies with ${spofs[0].alternativesObserved} observed alternative(s).`,
      action: 'Analyze Blast Radius', route: '/dashboard/ecosystem-dependency-map', risk: spofs[0].risk,
    })
  }
  if (bottlenecks.length) {
    recommendations.push({
      id: 'rec-bottleneck',
      title: `Validate ${bottlenecks[0].label} in the Hybrid Crypto Lab`,
      detail: `${bottlenecks[0].label} currently gates ${bottlenecks[0].blockedAssets} asset(s) from migrating.`,
      action: 'Run Hybrid Test', route: '/dashboard/hybrid-crypto-lab', risk: bottlenecks[0].risk,
    })
  }
  if (unknowns.length) {
    recommendations.push({
      id: 'rec-unknowns',
      title: `Investigate ${unknowns.length} relationship(s) with insufficient evidence`,
      detail: 'Undocumented trust and dependency relationships are the most common source of migration failure.',
      action: 'Investigate Unknowns', route: '/dashboard/ecosystem-dependency-map', risk: 'medium',
    })
  }

  const criticalDependencies = externalNodes.filter((node) => node.dependencyKind === 'critical' || node.criticality === 'critical' || riskRank(node.risk) >= riskRank('high')).length

  return {
    nodes: nodeList,
    edges,
    summary: {
      externalDependencies: externalNodes.length,
      criticalDependencies,
      vendorDependencies: externalNodes.filter((node) => node.kind === 'vendor').length,
      singlePointsOfFailure: spofs.length,
      unknownDependencies: unknowns.length,
      migrationBlockers: bottlenecks.length,
    },
    singlePointsOfFailure: spofs.slice(0, 20),
    bottlenecks: bottlenecks.slice(0, 20),
    unknowns: unknowns.slice(0, 60),
    recommendations,
  }
}

/**
 * Breadth-first blast radius over the ecosystem graph.
 *
 * Traverses DEPENDENTS (who would be affected if this node changed), which is
 * the direction that matters for migration impact. Bounded by depth so a dense
 * estate cannot produce an unbounded walk.
 */
export function computeEcosystemBlastRadius(
  nodes: EcosystemNode[],
  edges: EcosystemEdge[],
  nodeId: string,
  migrationJobAssetIds: Set<string> = new Set(),
  maxDepth = 5,
): BlastRadiusResult | null {
  const byId = new Map(nodes.map((node) => [node.id, node]))
  const root = byId.get(nodeId)
  if (!root) return null

  const incoming = new Map<string, string[]>()
  for (const edge of edges) {
    const list = incoming.get(edge.target) || []
    list.push(edge.source)
    incoming.set(edge.target, list)
  }

  const visited = new Set<string>([nodeId])
  const depths: Array<{ depth: number; nodeIds: string[] }> = []
  let frontier = [nodeId]
  let direct = 0

  for (let depth = 1; depth <= maxDepth && frontier.length; depth += 1) {
    const next: string[] = []
    for (const current of frontier) {
      for (const dependent of incoming.get(current) || []) {
        if (visited.has(dependent)) continue
        visited.add(dependent)
        next.push(dependent)
      }
    }
    if (!next.length) break
    if (depth === 1) direct = next.length
    depths.push({ depth, nodeIds: next })
    frontier = next
  }

  const affected = [...visited].filter((id) => id !== nodeId)
  const affectedNodes = affected.map((id) => byId.get(id)).filter((node): node is EcosystemNode => Boolean(node))
  const affectedAssetIds = unique(affectedNodes.flatMap((node) => node.assetIds))

  return {
    nodeId,
    label: root.label,
    directDependencies: direct,
    indirectDependencies: Math.max(0, affected.length - direct),
    applicationsAffected: affectedNodes.filter((node) => node.kind === 'application').length,
    businessServices: affectedNodes.filter((node) => node.kind === 'business-service').length,
    trustRelationships: affectedNodes.filter((node) => node.kind === 'pki' || node.kind === 'identity').length,
    migrationPlans: affectedAssetIds.filter((id) => migrationJobAssetIds.has(id)).length,
    criticalServices: affectedNodes.filter((node) => node.criticality === 'critical').length,
    affectedNodeIds: affected,
    depths,
    basis: `Breadth-first traversal of ${edges.length} recorded relationship(s) from ${root.label}, bounded at depth ${maxDepth}. Only relationships present in tenant evidence are traversed — undocumented dependencies are reported separately.`,
  }
}

/** Ordered dependency chain from a node up to its deepest external root. */
export function computeDependencyChain(
  nodes: EcosystemNode[],
  edges: EcosystemEdge[],
  nodeId: string,
  maxDepth = 6,
): DependencyChainStep[] {
  const byId = new Map(nodes.map((node) => [node.id, node]))
  const outgoing = new Map<string, string[]>()
  for (const edge of edges) {
    const list = outgoing.get(edge.source) || []
    list.push(edge.target)
    outgoing.set(edge.source, list)
  }
  const steps: DependencyChainStep[] = []
  const seen = new Set<string>()
  let frontier = [nodeId]
  for (let depth = 0; depth <= maxDepth && frontier.length; depth += 1) {
    const next: string[] = []
    for (const id of frontier) {
      if (seen.has(id)) continue
      seen.add(id)
      const node = byId.get(id)
      if (!node) continue
      steps.push({ nodeId: id, label: node.label, kind: node.kind, depth, risk: node.risk, readiness: node.readiness })
      next.push(...(outgoing.get(id) || []))
    }
    frontier = next
  }
  return steps
}

/* ================================================================== */
/* 10 — Trust derivation                                               */
/* ================================================================== */

function certificateState(cert: Row, daysToExpiry: number | null, now: number): TrustState {
  const meta = recordOf(cert.metadata)
  const algorithm = `${str(cert.algorithm)} ${str(meta.signature_algorithm || meta.signatureAlgorithm)}`
  if (WEAK_SIGNATURE_RE.test(algorithm)) return 'weak'
  if (daysToExpiry !== null && daysToExpiry < 0) return 'broken'
  if (daysToExpiry !== null && daysToExpiry <= 30) return 'expiring'
  if (cert.is_quantum_safe === true) return 'trusted'
  if (str(cert.status).toLowerCase().includes('revoked')) return 'broken'
  if (!str(cert.issuer)) return 'unknown'
  return 'valid'
}

function buildTrust(
  inputs: ExternalTrustInputs,
  vendors: VendorRecord[],
  now: number,
): ExternalTrustIntelligence['trust'] {
  const assetById = new Map(inputs.assets.map((asset) => [str(asset.id), asset]))
  const chains: TrustChain[] = []
  const findings: TrustFinding[] = []
  const certificates: CertificateDetail[] = []

  const pushFinding = (finding: TrustFinding) => {
    if (findings.some((existing) => existing.id === finding.id)) return
    findings.push(finding)
  }

  for (const cert of inputs.certificates) {
    const id = str(cert.id)
    const subject = str(cert.subject) || str(cert.name) || 'Certificate'
    const issuer = str(cert.issuer)
    const notAfter = isoOrNull(cert.not_after)
    const daysToExpiry = notAfter ? Math.round((new Date(notAfter).getTime() - now) / 86400000) : null
    const assetId = str(cert.asset_id) || null
    const asset = assetId ? assetById.get(assetId) : undefined
    const algorithm = str(cert.algorithm) || EVIDENCE_UNAVAILABLE
    const managed = issuer ? issuerLooksManaged(issuer) : false
    const state = certificateState(cert, daysToExpiry, now)
    const vendor = vendors.find((v) => v.name.toLowerCase() === issuer.toLowerCase()) ?? null

    const chainId = `chain-${id}`
    const leafNode: TrustNode = {
      id: `cert:${id}`, label: subject, kind: 'certificate', state,
      algorithm, keySize: num(cert.key_size), external: false, vendorId: null,
      detail: `${algorithm}${num(cert.key_size) ? ` ${num(cert.key_size)}-bit` : ''}`,
    }
    const chainNodes: TrustNode[] = []
    const chainEdges: Array<{ source: string; target: string }> = []

    if (asset) {
      const appNode: TrustNode = {
        id: `asset:${assetId}`, label: str(asset.name) || 'Asset', kind: 'application',
        state: 'unknown', algorithm: EVIDENCE_UNAVAILABLE, keySize: 0, external: false, vendorId: null,
        detail: `${str(asset.type) || 'asset'} · ${str(asset.environment) || 'unknown'}`,
      }
      chainNodes.push(appNode)
      chainEdges.push({ source: appNode.id, target: leafNode.id })
    }
    chainNodes.push(leafNode)

    let anchorLabel = EVIDENCE_UNAVAILABLE
    if (issuer) {
      const selfSigned = subject.trim().toLowerCase() === issuer.trim().toLowerCase()
      const caNode: TrustNode = {
        id: `ca:${issuer.toLowerCase()}`,
        label: issuer,
        kind: selfSigned ? 'root-ca' : 'intermediate-ca',
        state: managed ? 'valid' : 'unknown',
        algorithm, keySize: 0, external: true,
        vendorId: vendor?.id ?? null,
        detail: managed ? 'Managed issuer with automated issuance evidence.' : 'No automated issuance evidence recorded.',
      }
      chainNodes.push(caNode)
      chainEdges.push({ source: leafNode.id, target: caNode.id })

      if (!selfSigned) {
        const rootNode: TrustNode = {
          id: `anchor:${issuer.toLowerCase()}`, label: `${issuer} root`, kind: 'trust-anchor',
          state: 'unknown', algorithm: EVIDENCE_UNAVAILABLE, keySize: 0, external: true,
          vendorId: vendor?.id ?? null,
          detail: 'Root of trust inferred from the issuer chain; root certificate evidence was not captured.',
        }
        chainNodes.push(rootNode)
        chainEdges.push({ source: caNode.id, target: rootNode.id })
        anchorLabel = rootNode.label
      } else {
        anchorLabel = caNode.label
      }
    }

    const detail: CertificateDetail = {
      id, subject, issuer: issuer || EVIDENCE_UNAVAILABLE,
      notBefore: isoOrNull(cert.not_before),
      notAfter, daysToExpiry,
      // `certificates` carries no signature_algorithm column, so the signature
      // is taken from metadata when the scanner recorded it and otherwise falls
      // back to the public-key algorithm — never invented.
      signatureAlgorithm: str(recordOf(cert.metadata).signature_algorithm || recordOf(cert.metadata).signatureAlgorithm) || algorithm,
      publicKeyAlgorithm: algorithm,
      keySize: num(cert.key_size),
      quantumSafe: cert.is_quantum_safe === true,
      renewalMechanism: managed ? 'automated' : issuer ? 'manual' : 'unknown',
      owner: str(asset?.service_owner) || 'Unassigned',
      environment: str(asset?.environment) || 'unknown',
      assetId,
      trustAnchor: anchorLabel,
      chainNodeIds: chainNodes.map((node) => node.id),
      state,
      basis: `certificates row ${id}; issuer "${issuer || 'not recorded'}"; ${notAfter ? `expires ${notAfter}` : 'no expiry recorded'}.`,
    }
    certificates.push(detail)

    /* -- Findings, each backed by the row that produced it -- */
    const affectedAssetIds = assetId ? [assetId] : []
    const affectedAssetNames = asset ? [str(asset.name)] : []
    const finding = (kind: TrustFindingKind, severity: RiskLevel, evidence: string, action: string, route: string) =>
      pushFinding({
        id: `tf-${kind}-${id}`, kind, title: TRUST_FINDING_LABEL[kind], severity,
        chainId, evidence, evidenceSource: 'Certificate Inventory',
        affectedAssetIds, affectedAssetNames, recommendedAction: action, route,
      })

    if (!issuer) finding('unknown-ca', 'high', `${subject} has no recorded issuer.`, 'Re-scan this certificate so its issuer and chain can be established.', '/dashboard/pki-visibility')
    if (daysToExpiry !== null && daysToExpiry < 0) finding('broken-chain', 'critical', `${subject} expired ${Math.abs(daysToExpiry)} day(s) ago.`, 'Re-issue immediately — dependent trust paths are already failing.', '/dashboard/pki-visibility')
    else if (daysToExpiry !== null && daysToExpiry <= 30) finding('expiring-certificate', 'high', `${subject} expires in ${daysToExpiry} day(s).`, 'Renew before expiry and prefer a PQC-capable issuer.', '/dashboard/pki-visibility')
    if (WEAK_SIGNATURE_RE.test(`${algorithm} ${detail.signatureAlgorithm}`)) finding('weak-algorithm', 'critical', `${subject} uses ${detail.signatureAlgorithm}.`, 'Re-issue with an approved signature algorithm.', '/dashboard/pki-visibility')
    if (classifyAlgorithm(algorithm) === 'vulnerable') finding('pqc-compatibility', 'high', `${subject} public key is ${algorithm}, which Shor breaks.`, 'Plan re-issuance under ML-DSA-65 or a hybrid chain.', '/dashboard/hybrid-crypto-lab')
    if (issuer && !managed) finding('manual-renewal', 'medium', `${issuer} shows no automated issuance evidence.`, 'Automate issuance (ACME or managed CA) so re-issuance is not a change window.', '/dashboard/pki-visibility')
    if (issuer && subject.trim().toLowerCase() === issuer.trim().toLowerCase()) finding('static-trust-anchor', 'high', `${subject} is self-signed and acts as its own anchor.`, 'Every relying party must trust the replacement before this chain can change.', '/dashboard/trust-chain-analyzer')
    if (vendor) finding('vendor-dependency', vendor.risk === 'critical' ? 'critical' : 'medium', `Chain depends on ${vendor.name} (readiness ${READINESS_LABEL[vendor.readiness]}).`, 'Track the vendor’s PQC commitment before scheduling re-issuance.', `/dashboard/vendor-pqc-readiness?vendor=${encodeURIComponent(vendor.id)}`)
    else if (issuer) finding('external-ca-dependency', 'medium', `Chain terminates at externally operated issuer ${issuer}.`, 'Confirm the CA can sign ML-DSA before committing to a migration date.', '/dashboard/vendor-pqc-readiness')

    const chainFindingIds = findings.filter((f) => f.chainId === chainId).map((f) => f.id)
    const chainRisk = chainFindingIds.length
      ? findings.filter((f) => f.chainId === chainId).reduce<RiskLevel>((worst, f) => (riskRank(f.severity) > riskRank(worst) ? f.severity : worst), 'unknown')
      : 'low'

    /* -- Proposed chain: a proposal, never a claim of availability -- */
    const proposedNodes: TrustNode[] = chainNodes.map((node) => {
      if (node.kind === 'certificate') {
        return { ...node, id: `${node.id}:proposed`, algorithm: 'ML-DSA-65 (hybrid with Ed25519)', state: 'trusted', detail: 'Proposed PQC-compatible certificate (FIPS 204).' }
      }
      if (node.kind === 'intermediate-ca' || node.kind === 'root-ca') {
        return { ...node, id: `${node.id}:proposed`, label: `${node.label} (PQC-capable)`, state: 'unknown', detail: 'Requires the issuing CA to support ML-DSA signing — not verified.' }
      }
      return { ...node, id: `${node.id}:proposed` }
    })

    chains.push({
      id: chainId,
      name: subject,
      nodes: chainNodes,
      edges: chainEdges,
      state,
      risk: chainRisk,
      external: Boolean(issuer),
      vendorId: vendor?.id ?? null,
      certificate: detail,
      assetIds: affectedAssetIds,
      assetNames: affectedAssetNames,
      findingIds: chainFindingIds,
      proposed: {
        nodes: proposedNodes,
        feasibility: detail.quantumSafe ? 'supported' : issuer ? 'requires-ca-support' : 'unknown',
        note: detail.quantumSafe
          ? 'This chain already presents post-quantum material.'
          : `Migrating this chain requires ${issuer || 'the issuing CA'} to sign ML-DSA certificates. QGuard Helix has not verified that capability — confirm with the CA before planning a date.`,
      },
      migrationImpact: {
        applications: asset ? 1 : 0,
        services: asset ? 1 : 0,
        certificates: 1,
        trustAnchors: anchorLabel === EVIDENCE_UNAVAILABLE ? 0 : 1,
        vendorDependencies: vendor ? 1 : 0,
        compatibilityIssues: [
          ...(classifyAlgorithm(algorithm) === 'vulnerable' ? ['Leaf public key is quantum-vulnerable and must be re-issued.'] : []),
          ...(managed ? [] : ['No issuance automation — re-issuance requires a manual change window.']),
        ],
      },
      basis: `Derived from certificates row ${id} and its recorded issuer chain.`,
    })
  }

  /* ---- Trust findings already recorded by discovery ------------------ */
  for (const row of inputs.trustFindings) {
    const assetId = str(row.asset_id)
    const asset = assetId ? assetById.get(assetId) : undefined
    pushFinding({
      id: `tsd-${str(row.id)}`,
      kind: 'broken-chain',
      title: str(row.title) || 'Trust-state finding',
      severity: normalizeSeverityToRisk(row.severity),
      chainId: null,
      evidence: str(row.detail) || str(row.title),
      evidenceSource: 'Trust-State Discovery',
      affectedAssetIds: assetId ? [assetId] : [],
      affectedAssetNames: asset ? [str(asset.name)] : [],
      recommendedAction: 'Resolve in Trust-State Discovery, then re-run the analyzer.',
      route: '/dashboard/trust-state-discovery',
    })
  }

  findings.sort((a, b) => riskRank(b.severity) - riskRank(a.severity))
  chains.sort((a, b) => riskRank(b.risk) - riskRank(a.risk) || a.name.localeCompare(b.name))

  const agility = computeTrustAgility({
    certificates: inputs.certificates,
    assets: inputs.assets,
    assetRelationships: inputs.assetRelationships,
    cryptoInventory: inputs.cryptoInventory,
    now,
  })

  return {
    chains,
    findings,
    certificates,
    agility,
    summary: {
      chains: chains.length,
      criticalChains: chains.filter((chain) => chain.risk === 'critical' || chain.risk === 'high').length,
      expiringCertificates: certificates.filter((cert) => cert.daysToExpiry !== null && cert.daysToExpiry <= 30).length,
      legacyAlgorithms: unique(certificates.filter((cert) => WEAK_SIGNATURE_RE.test(cert.signatureAlgorithm) || classifyAlgorithm(cert.publicKeyAlgorithm) === 'vulnerable').map((cert) => cert.publicKeyAlgorithm)).length,
      externalTrustDependencies: unique(chains.filter((chain) => chain.external).map((chain) => chain.certificate?.issuer)).filter(Boolean).length,
      unknownRelationships: chains.filter((chain) => chain.state === 'unknown').length +
        inputs.assets.filter((asset) => !inputs.assetRelationships.some((rel) =>
          str(rel.source_asset_id) === str(asset.id) || str(rel.target_asset_id) === str(asset.id))).length,
    },
  }
}

/* ================================================================== */
/* 11 — Trust agility (shared with Crypto Agility)                     */
/* ================================================================== */

export interface TrustAgilityInputs {
  certificates: Row[]
  assets: Row[]
  assetRelationships: Row[]
  cryptoInventory: Row[]
  now?: number
}

/**
 * THE trust-agility model. Exported so the Crypto Agility page's Trust domain
 * consumes this exact computation instead of deriving a second opinion — the two
 * pages therefore cannot disagree about how replaceable the trust fabric is.
 *
 * Returns `score: null` when nothing measurable exists. An absence of anchors or
 * certificates is NOT a perfect score.
 */
export function computeTrustAgility(inputs: TrustAgilityInputs): TrustAgility {
  const now = inputs.now ?? Date.now()
  const certificates = inputs.certificates
  const breakdown: TrustAgilityBreakdown[] = []

  const push = (key: TrustAgilityBreakdown['key'], label: string, score: number | null, weight: number, basis: string) =>
    breakdown.push({ key, label, score, weight, basis })

  if (!certificates.length) {
    push('certificate-replaceability', 'Certificate Replaceability', null, 25, `${EVIDENCE_UNAVAILABLE} — no certificate inventory is connected.`)
    push('ca-agility', 'CA Agility', null, 20, `${EVIDENCE_UNAVAILABLE} — no issuer evidence is available.`)
    push('trust-anchor-agility', 'Trust Anchor Agility', null, 20, `${EVIDENCE_UNAVAILABLE} — no trust anchor has been observed.`)
    push('renewal-automation', 'Renewal Automation', null, 15, `${EVIDENCE_UNAVAILABLE} — issuance automation cannot be assessed.`)
    push('pqc-compatibility', 'PQC Compatibility', null, 10, `${EVIDENCE_UNAVAILABLE} — no certificate algorithms observed.`)
  } else {
    const managed = certificates.filter((cert) => issuerLooksManaged(str(cert.issuer)))
    const selfSigned = certificates.filter((cert) => {
      const subject = str(cert.subject) || str(cert.name)
      const issuer = str(cert.issuer)
      return subject && issuer && subject.trim().toLowerCase() === issuer.trim().toLowerCase()
    })
    const expired = certificates.filter((cert) => {
      const notAfter = isoOrNull(cert.not_after)
      return notAfter ? new Date(notAfter).getTime() < now : false
    })
    const pqcCapable = certificates.filter((cert) => cert.is_quantum_safe === true)
    const distinctIssuers = unique(certificates.map((cert) => str(cert.issuer).toLowerCase()).filter(Boolean))

    push('certificate-replaceability', 'Certificate Replaceability',
      Math.round(clamp(pctOf(managed.length, certificates.length) * 0.8 + (100 - pctOf(expired.length, certificates.length)) * 0.2)), 25,
      `${managed.length}/${certificates.length} certificate(s) show automated issuance; ${expired.length} expired.`)

    push('ca-agility', 'CA Agility',
      Math.round(clamp(distinctIssuers.length > 1 ? 70 : 40)), 20,
      distinctIssuers.length > 1
        ? `${distinctIssuers.length} distinct issuer(s) observed — a second issuance path exists.`
        : `All certificates chain to a single issuer (${distinctIssuers[0] || 'unrecorded'}); there is no observed alternative.`)

    push('trust-anchor-agility', 'Trust Anchor Agility',
      Math.round(clamp(100 - pctOf(selfSigned.length, certificates.length) * 1.2)), 20,
      `${selfSigned.length}/${certificates.length} certificate(s) are self-signed anchors that every relying party must be re-configured to trust.`)

    push('renewal-automation', 'Renewal Automation',
      Math.round(pctOf(managed.length, certificates.length)), 15,
      `${managed.length}/${certificates.length} certificate(s) are issued by a managed/ACME-style authority.`)

    push('pqc-compatibility', 'PQC Compatibility',
      Math.round(pctOf(pqcCapable.length, certificates.length)), 10,
      `${pqcCapable.length}/${certificates.length} certificate(s) present post-quantum material.`)
  }

  // Federation agility needs identity evidence, which certificates alone cannot give.
  const identityAssets = inputs.assets.filter((asset) =>
    /idp|identity|auth|sso|oauth|oidc|saml|federation|directory|ldap/i.test(`${str(asset.type)} ${str(asset.name)}`))
  if (identityAssets.length) {
    const federated = inputs.assetRelationships.filter((rel) => /federat|trust|identity/i.test(str(rel.relationship_type))).length
    push('federation-agility', 'Federation Agility',
      Math.round(clamp(federated > 0 ? 60 : 35)), 10,
      federated > 0
        ? `${federated} federation/trust relationship(s) are mapped across ${identityAssets.length} identity asset(s).`
        : `${identityAssets.length} identity asset(s) exist but no federation relationship has been mapped, so the change path is undocumented.`)
  } else {
    push('federation-agility', 'Federation Agility', null, 10, `${EVIDENCE_UNAVAILABLE} — no identity or federation asset has been discovered.`)
  }

  const scored = breakdown.filter((row) => row.score !== null)
  const scoredWeight = scored.reduce((sum, row) => sum + row.weight, 0)
  const score = scoredWeight > 0
    ? Math.round(clamp(scored.reduce((sum, row) => sum + (row.score as number) * row.weight, 0) / scoredWeight))
    : null

  const level = score === null ? 'Unknown'
    : score >= 85 ? 'Excellent' : score >= 70 ? 'Strong' : score >= 50 ? 'Moderate' : score >= 30 ? 'Weak' : 'Critical'

  return {
    score,
    level,
    breakdown,
    coverage: Math.round(pctOf(scoredWeight, 100)),
    basis: score === null
      ? `${EVIDENCE_UNAVAILABLE} — no trust evidence could be measured, so no trust agility score is published.`
      : `Weighted mean of ${scored.length}/${breakdown.length} measurable dimension(s) covering ${scoredWeight}% of the model. Unmeasured dimensions are excluded and their weight renormalised — never scored as zero.`,
  }
}

/* ================================================================== */
/* 12 — Lab: configuration validation                                  */
/* ================================================================== */

/**
 * Validates a proposed configuration against algorithm PURPOSE.
 *
 * ML-KEM is key establishment only; ML-DSA/SLH-DSA are signatures only. A UI
 * that lets a user put ML-KEM in the signature slot would teach the exact
 * misconception the platform exists to prevent, so invalid combinations are
 * rejected here rather than rendered.
 */
export function validateExperimentConfiguration(config: Partial<ExperimentConfiguration>): ConfigValidationIssue[] {
  const issues: ConfigValidationIssue[] = []

  if (!config.keyExchange) issues.push({ field: 'keyExchange', message: 'A key establishment algorithm is required.' })
  else if (!KEY_EXCHANGE_OPTIONS.includes(config.keyExchange)) {
    issues.push({ field: 'keyExchange', message: `${config.keyExchange} is not an approved key establishment option.` })
  }
  if (config.keyExchange && /ML-DSA|SLH-DSA|Ed25519/i.test(config.keyExchange)) {
    issues.push({ field: 'keyExchange', message: 'Signature algorithms cannot perform key establishment. Use ML-KEM-768 or the X25519+ML-KEM-768 hybrid.' })
  }

  if (!config.signature) issues.push({ field: 'signature', message: 'A signature algorithm is required.' })
  else if (!SIGNATURE_OPTIONS.includes(config.signature)) {
    issues.push({ field: 'signature', message: `${config.signature} is not an approved signature option.` })
  }
  if (config.signature && /ML-KEM|KYBER/i.test(config.signature)) {
    issues.push({ field: 'signature', message: 'ML-KEM is a key encapsulation mechanism, not a signature algorithm. Use ML-DSA-65 (FIPS 204).' })
  }

  if (config.symmetric && !SYMMETRIC_OPTIONS.includes(config.symmetric)) {
    issues.push({ field: 'symmetric', message: `${config.symmetric} is not an approved symmetric cipher. AES-256-GCM is required.` })
  }
  if (config.kdf && !KDF_OPTIONS.includes(config.kdf)) {
    issues.push({ field: 'kdf', message: `${config.kdf} is not an approved key derivation function.` })
  }
  if (config.hash && !HASH_OPTIONS.includes(config.hash)) {
    issues.push({ field: 'hash', message: `${config.hash} is not an approved hash.` })
  }

  // Hybrid groups only negotiate on TLS 1.3.
  if (config.protocol === 'TLS 1.2' && config.keyExchange && /ML-KEM/i.test(config.keyExchange)) {
    issues.push({ field: 'combination', message: 'Hybrid and post-quantum named groups only negotiate under TLS 1.3. Raise the protocol floor before testing this key exchange.' })
  }

  return issues
}

/** The platform-recommended configuration for a target, from its observed crypto. */
export function recommendConfiguration(observedAlgorithms: string[], observedProtocols: string[]): ExperimentConfiguration {
  const hasTls13 = observedProtocols.some((protocol) => /1\.3/.test(protocol))
  return {
    protocol: hasTls13 ? 'TLS 1.3' : 'TLS 1.3',
    keyExchange: 'X25519+ML-KEM-768',
    signature: 'Ed25519+ML-DSA-65',
    symmetric: 'AES-256-GCM',
    kdf: 'HKDF-SHA3-256',
    hash: 'SHA3-256',
  }
}

/**
 * The ONE `hybrid_crypto_experiments` row → `ExperimentRecord` projection.
 *
 * Both the read path (experiment history) and the write path (the response to
 * POST /lab/experiments) MUST go through this function. They previously did
 * not: the write path returned the raw snake_case row, so a freshly-run
 * experiment had no `target`, `executionMode`, `durationMs`, `checks`,
 * `findings` or `basis`, and the result view crashed on `result.target.label`
 * — taking the whole page down with it. One row shape, one record shape,
 * one mapper (§Single Source of Truth).
 *
 * Accepts a row that has not been persisted yet (no `id`/`created_at`), so an
 * ephemeral result is the same shape as a stored one.
 */
export function toExperimentRecord(row: Row, now = Date.now()): ExperimentRecord {
  const payload = recordOf(row.payload)
  const result = recordOf(row.result)
  return {
    id: str(row.id),
    createdAt: isoOrNull(row.created_at) || new Date(now).toISOString(),
    target: (payload.target as ExperimentTarget) ?? {
      kind: 'endpoint', id: '', label: str(row.target_label) || EVIDENCE_UNAVAILABLE,
      host: str(row.target_host), port: num(row.target_port) || 443,
      environment: str(row.environment) || 'unknown', vendorId: str(row.vendor_id) || null,
      assetId: str(row.asset_id) || null,
    },
    currentConfiguration: (payload.currentConfiguration as ExperimentRecord['currentConfiguration']) ?? { observed: [] },
    proposedConfiguration: (payload.proposedConfiguration as ExperimentConfiguration) ?? {
      protocol: 'TLS 1.3', keyExchange: 'X25519+ML-KEM-768', signature: 'Ed25519+ML-DSA-65',
      symmetric: 'AES-256-GCM', kdf: 'HKDF-SHA3-256', hash: 'SHA3-256',
    },
    executionMode: (str(row.execution_mode) || 'simulation') as ExecutionMode,
    outcome: (str(row.outcome) || 'not-evaluated') as ExperimentOutcome,
    checks: Array.isArray(result.checks) ? (result.checks as ExperimentCheck[]) : [],
    findings: Array.isArray(result.findings) ? (result.findings as ExperimentFinding[]) : [],
    risk: normalizeSeverityToRisk(row.risk),
    durationMs: num(row.duration_ms),
    evidenceGenerated: Boolean(row.evidence_id),
    evidenceId: str(row.evidence_id) || null,
    requiresProductionValidation: true,
    basis: str(result.basis) || 'Recorded laboratory experiment.',
    probe: toExperimentProbe(result.probe),
  }
}

/* ================================================================== */
/* 13 — Engine entry point                                             */
/* ================================================================== */

export function buildExternalTrustIntelligence(inputs: ExternalTrustInputs): ExternalTrustIntelligence {
  const now = inputs.now ?? Date.now()

  const { records: vendorRecords, requests } = buildVendors(inputs, now)
  const ecosystem = buildEcosystem(inputs, vendorRecords, now)
  const trust = buildTrust(inputs, vendorRecords, now)

  /* ---- Vendor roll-up -------------------------------------------------- */
  const assessedVendors = vendorRecords.filter((vendor) => vendor.hasEvidence)
  const counts = {
    ready: vendorRecords.filter((v) => v.readiness === 'ready').length,
    hybridReady: vendorRecords.filter((v) => v.readiness === 'hybrid-ready').length,
    preparing: vendorRecords.filter((v) => v.readiness === 'preparing').length,
    committed: vendorRecords.filter((v) => v.readiness === 'committed').length,
    notReady: vendorRecords.filter((v) => v.readiness === 'not-ready').length,
    unknown: vendorRecords.filter((v) => v.readiness === 'unknown').length,
  }
  const scoredForReadiness = vendorRecords.filter((v) => v.assessedReadiness !== 'unknown')
  const overallReadinessPct = scoredForReadiness.length
    ? Math.round(clamp(scoredForReadiness.reduce((sum, vendor) =>
        sum + (vendor.assessedReadiness === 'ready' ? 100 : vendor.assessedReadiness === 'hybrid-ready' ? 70 : vendor.assessedReadiness === 'preparing' ? 40 : 10), 0) / scoredForReadiness.length))
    : null

  const distribution = (['ready', 'hybrid-ready', 'preparing', 'committed', 'not-ready', 'unknown'] as Readiness[]).map((readiness) => {
    const count = vendorRecords.filter((vendor) => vendor.readiness === readiness).length
    return { readiness, label: READINESS_LABEL[readiness], count, share: Math.round(pctOf(count, Math.max(1, vendorRecords.length))) }
  })

  /* ---- Lab targets come from real assets/hosts ------------------------- */
  const targets: ExperimentTarget[] = []
  for (const asset of inputs.assets) {
    const meta = recordOf(asset.metadata)
    const host = normalizeHost(meta.hostname || meta.host || meta.fqdn || meta.domain || meta.url || asset.name)
    if (!host || !/\.[a-z]{2,}$/i.test(host)) continue
    targets.push({
      kind: 'asset',
      id: str(asset.id),
      label: str(asset.name) || host,
      host,
      port: num(meta.port) || 443,
      environment: str(asset.environment) || 'unknown',
      vendorId: null,
      assetId: str(asset.id),
    })
  }
  for (const vendor of vendorRecords) {
    for (const host of vendor.observedHosts.slice(0, 3)) {
      if (targets.some((target) => target.host === host)) continue
      targets.push({
        kind: 'vendor', id: `${vendor.id}:${host}`, label: `${vendor.name} — ${host}`,
        host, port: 443, environment: 'external', vendorId: vendor.id, assetId: null,
      })
    }
  }

  const experiments: ExperimentRecord[] = inputs.experiments.map((row) => toExperimentRecord(row, now))

  const sources = unique([
    inputs.assets.length ? 'Asset Inventory' : '',
    inputs.certificates.length ? 'Certificate Inventory' : '',
    inputs.assetRelationships.length ? 'Trust Fabric (asset_relationships)' : '',
    inputs.vendorAssessments.length ? 'Vendor Assessments' : '',
    inputs.connectorAccounts.length ? 'Cloud Connectors' : '',
    inputs.runtimeEvents.length ? 'Runtime Crypto Telemetry' : '',
    inputs.scannerEvidence.length ? 'Scanner Evidence' : '',
    inputs.cryptoInventory.length ? 'CBOM (crypto_inventory)' : '',
    inputs.trustFindings.length ? 'Trust-State Discovery' : '',
    inputs.evidenceRequests.length ? 'Vendor Evidence Requests' : '',
    inputs.experiments.length ? 'Hybrid Crypto Lab' : '',
  ].filter(Boolean))

  const hasData = vendorRecords.length > 0 || ecosystem.nodes.length > 0 || trust.chains.length > 0

  return {
    generatedAt: new Date(now).toISOString(),
    hasData,
    evidence: {
      sources,
      assets: inputs.assets.length,
      certificates: inputs.certificates.length,
      relationships: inputs.assetRelationships.length,
      vendorAssessments: inputs.vendorAssessments.length,
      connectors: inputs.connectorAccounts.length,
      runtimeEvents: inputs.runtimeEvents.length,
      note: sources.length
        ? `Derived from ${sources.length} live evidence source(s): ${sources.join(', ')}.`
        : `${EVIDENCE_UNAVAILABLE} — no external trust evidence exists for this tenant yet.`,
    },
    vendors: {
      records: vendorRecords,
      summary: {
        assessed: assessedVendors.length,
        ready: counts.ready,
        hybridReady: counts.hybridReady,
        preparingOrCommitted: counts.preparing + counts.committed,
        notReady: counts.notReady,
        unknown: counts.unknown,
        evidencePending: vendorRecords.filter((v) => v.evidenceState === 'requested' || v.evidenceState === 'pending' || v.evidenceState === 'overdue').length,
        criticalRisks: vendorRecords.filter((v) => v.risk === 'critical').length,
        overallReadinessPct,
        readinessBasis: overallReadinessPct === null
          ? `${EVIDENCE_UNAVAILABLE} — no vendor has measurable readiness evidence, so no overall figure is published.`
          : `Mean of MEASURED readiness across ${scoredForReadiness.length} vendor(s) with observed cryptography. ${counts.unknown} vendor(s) have no measurable evidence and are excluded rather than counted as ready.`,
      },
      distribution,
      evidenceRequests: requests,
      persistenceAvailable: true,
    },
    ecosystem,
    trust,
    lab: {
      targets: targets.slice(0, 200),
      experiments,
      summary: {
        experiments: experiments.length,
        passed: experiments.filter((experiment) => experiment.outcome === 'passed').length,
        conditional: experiments.filter((experiment) => experiment.outcome === 'conditional' || experiment.outcome === 'passed-with-warnings').length,
        failed: experiments.filter((experiment) => experiment.outcome === 'failed').length,
        compatibilityIssues: experiments.reduce((sum, experiment) => sum + experiment.findings.length, 0),
        evidenceGenerated: experiments.filter((experiment) => experiment.evidenceGenerated).length,
      },
      persistenceAvailable: true,
    },
  }
}
