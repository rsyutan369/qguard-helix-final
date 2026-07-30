/**
 * Shared Responsibility Quantum Migration Intelligence Engine™ — normalized model.
 *
 * This is the single source of truth for cryptographic OWNERSHIP across QGuard
 * Helix. Every finding is classified into a responsibility domain (customer /
 * provider / ecosystem) with provider attribution, edge-vs-origin TLS
 * intelligence, a migration-dependency graph and layered confidence — so the
 * scanner, dashboards, Sophia, reporting, certification and the migration
 * planner all consume the identical model.
 *
 * The module is PURE and isomorphic: no Supabase, no Express, no I/O. Callers
 * adapt their real tenant rows into `OwnershipFindingInput` and receive the
 * normalized `SharedResponsibilityIntelligence` back.
 */

import type { RemediationAuthority, ScanTargetType } from '@/types/scanner.types'

/** The three ownership domains every finding is classified into. */
export type ResponsibilityDomain = 'customer' | 'provider' | 'ecosystem'

/** Can the customer directly remediate this finding today? */
export type CustomerActionability = 'yes' | 'no' | 'partial'

/** Why a migration cannot proceed until an upstream dependency completes. */
export type MigrationDependencyStatus =
  | 'ready'
  | 'blocked'
  | 'waiting_provider'
  | 'waiting_browser'
  | 'waiting_vendor'
  | 'waiting_hardware'
  | 'waiting_standards'

export type FindingPriority = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export type FindingSeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe'
export type BusinessImpactLevel = 'critical' | 'high' | 'medium' | 'low'
export type MigrationComplexity = 'low' | 'medium' | 'high'

/** How a provider profile is grouped in the catalog. */
export type ProviderCategory =
  | 'cdn_edge'
  | 'cloud_certificate'
  | 'load_balancer'
  | 'managed_database'
  | 'managed_kubernetes'
  | 'hosting_platform'
  | 'saas'
  | 'identity_provider'
  | 'payment'
  | 'communications'
  | 'browser'
  | 'operating_system'
  | 'crypto_library'
  | 'runtime'
  | 'hardware'
  | 'standards_body'
  | 'certificate_authority'
  | 'unknown'

export type PqRoadmapStatus = 'shipping' | 'in_progress' | 'announced' | 'unknown' | 'not_applicable'
export type CustomerInfluence = 'none' | 'low' | 'medium' | 'high'

/**
 * Evidence-only fingerprints used to attribute a finding/asset to a provider.
 * Every field is a list of case-insensitive substrings (or exact tokens) matched
 * against real tenant evidence — no network probing is performed.
 */
export interface ProviderFingerprint {
  /** Hostname / URL substrings, e.g. "cloudfront.net", ".vercel.app". */
  hostname?: string[]
  /** Observed CNAME / DNS chain markers. */
  cname?: string[]
  /** HTTP Server / Via / X-* header markers, when present in evidence. */
  header?: string[]
  /** Scanner target types that imply this provider category. */
  targetType?: ScanTargetType[]
  /** `connector_accounts.provider` values that imply this provider. */
  connectorProvider?: string[]
  /** Generic name / metadata keywords. */
  keywords?: string[]
}

/** A provider or ecosystem participant with its PQ posture and ownership rules. */
export interface ProviderProfile {
  id: string
  name: string
  domain: ResponsibilityDomain
  category: ProviderCategory
  fingerprints: ProviderFingerprint
  pqRoadmapStatus: PqRoadmapStatus
  pqRoadmapNote?: string
  customerInfluence: CustomerInfluence
  migrationDependencyStatus: MigrationDependencyStatus
  reference?: string
}

/** Result of attributing a finding to a provider (or an honest "unattributed"). */
export interface ProviderAttribution {
  providerId: string | null
  providerName: string
  domain: ResponsibilityDomain
  category: ProviderCategory
  confidence: number
  method: 'connector' | 'hostname' | 'header' | 'target-type' | 'metadata' | 'keyword' | 'authority' | 'default'
  reason: string
  /** false ⇒ no evidence matched; ownership defaulted (never fabricated). */
  attributed: boolean
  pqRoadmapStatus: PqRoadmapStatus
  pqRoadmapNote?: string
  customerInfluence: CustomerInfluence
  reference?: string
}

export type DependencyRole =
  | 'customer'
  | 'provider'
  | 'cdn'
  | 'browser'
  | 'ca'
  | 'standards'
  | 'tls_library'
  | 'os'
  | 'hardware'
  | 'runtime'
export type DependencyNodeStatus = 'complete' | 'in_progress' | 'blocked' | 'pending'

export interface DependencyNode {
  id: string
  label: string
  role: DependencyRole
  status: DependencyNodeStatus
  /** true ⇒ this node currently gates downstream migration. */
  blocking: boolean
  note?: string
}

export interface DependencyChain {
  nodes: DependencyNode[]
  criticalPath: string[]
  blockedBy: string | null
  migrationDependencyStatus: MigrationDependencyStatus
  summary: string
}

/** A single TLS termination layer (edge vs origin must never be conflated). */
export interface TlsLayer {
  layer: 'edge' | 'origin' | 'application' | 'database'
  owner: string
  domain: ResponsibilityDomain
  managed: boolean
  customerControl: CustomerActionability
  observedProtocol?: string
  observedAlgorithm?: string
  hybridSupported: 'yes' | 'no' | 'unknown'
  recommendation: string
}

export interface EdgeOriginIntelligence {
  isProviderFronted: boolean
  edge: TlsLayer | null
  origin: TlsLayer | null
  layers: TlsLayer[]
  summary: string
}

export interface OwnershipConfidence {
  overall: number
  ownership: number
  actionability: number
  providerAttribution: number
}

export interface OwnershipEvidence {
  detectionMethod: string
  evidenceSource: string
  confidence: number
  ownershipReason: string
  actionabilityReason: string
  providerAttributionReason: string
}

export interface ActionabilityAssessment {
  canCustomerFix: CustomerActionability
  label: string
  reason: string
  recommendedAction: string
  allowedActions: string[]
}

export interface FindingReference {
  label: string
  url: string
}

export interface BusinessImpact {
  level: BusinessImpactLevel
  summary: string
}

/**
 * The normalized ownership-classified finding. This supersets — and reconciles
 * with — the existing `RemediationModel` on `ScanFinding` (backward compatible:
 * consumers keep their old fields, this adds ownership metadata).
 */
export interface OwnershipFinding {
  id: string
  title: string
  description: string
  severity: FindingSeverityLevel
  priority: FindingPriority
  quantumRiskScore: number

  domain: ResponsibilityDomain
  ownerType: string
  responsibleParty: string
  remediationDomain: string

  customerActionable: CustomerActionability
  providerDependency: string | null
  ecosystemDependency: string | null

  actionability: ActionabilityAssessment
  migrationDependencyStatus: MigrationDependencyStatus
  businessImpact: BusinessImpact
  migrationComplexity: MigrationComplexity
  estimatedEffort: string
  estimatedTimeline: string

  attribution: ProviderAttribution
  dependencyChain: DependencyChain
  edgeOrigin: EdgeOriginIntelligence | null
  confidence: OwnershipConfidence
  evidence: OwnershipEvidence
  references: FindingReference[]

  /** Matrix / table conveniences (derived, kept on the finding for consumers). */
  recommendedAction: string
  status: string
  asset: string
  assetType: string
  algorithm: string
}

/**
 * Adapter input — callers map their real tenant rows (snapshot findings, scanner
 * intelligence findings, crypto inventory, runtime events) into this shape.
 */
export interface OwnershipFindingInput {
  id: string
  title?: string
  description?: string
  algorithm?: string
  category?: string
  location?: string
  assetId?: string
  assetName?: string
  assetType?: string
  environment?: string
  severity?: string
  quantumRiskScore?: number
  isHNDL?: boolean
  provider?: string
  host?: string
  protocol?: string
  metadata?: Record<string, unknown>
  remediationAuthority?: RemediationAuthority
  evidenceSource?: string
  evidenceConfidence?: 'high' | 'medium' | 'low'
  detectionMethod?: string
  observedAt?: string | null
}

/** Tenant-wide signals that improve attribution (all evidence-derived). */
export interface AttributionContext {
  /** `connector_accounts.provider` values connected by the tenant. */
  connectorProviders?: string[]
}

/**
 * One CONSOLIDATED ownership row.
 *
 * The scanner emits one finding per detected instance, so the same cryptographic
 * exposure on the same asset arrives many times (different detection channel,
 * category or evidence string). Rendering those raw is what produced identical
 * repeated matrix rows in the dashboards and every export. A matrix row is
 * therefore an ownership GROUP — one cryptographic exposure under one owner —
 * and carries the instance/asset counts that make the consolidation auditable.
 */
export interface SharedResponsibilityMatrixRow {
  findingId: string
  finding: string
  owner: string
  action: string
  priority: FindingPriority
  status: string
  domain: ResponsibilityDomain
  customerActionable: CustomerActionability
  migrationDependencyStatus: MigrationDependencyStatus
  /** The asset this exposure was observed on — its own column, not part of `finding`. */
  asset: string
  /** Raw scanner finding instances consolidated into this row (>= 1). */
  occurrences: number
  /** Distinct raw detection labels merged into this row (evidence traceability). */
  detectionLabels: string[]
  /** Highest severity observed across the consolidated instances. */
  severity: FindingSeverityLevel
}

export interface DomainReadiness {
  domain: ResponsibilityDomain | 'overall'
  score: number
  level: string
  total: number
  resolved: number
  actionable: number
  blocked: number
}

export interface SeverityBucket {
  critical: number
  high: number
  medium: number
  low: number
}

export interface MigrationWave {
  wave: number
  name: string
  domain: ResponsibilityDomain | 'mixed'
  description: string
  findingCount: number
  status: 'ready' | 'in_progress' | 'blocked' | 'waiting' | 'complete'
  dependencyStatus: MigrationDependencyStatus
  estimatedTimeline: string
  blockedBy: string | null
}

export interface ProviderBreakdownRow {
  providerId: string
  name: string
  domain: ResponsibilityDomain
  category: ProviderCategory
  count: number
  pqRoadmapStatus: PqRoadmapStatus
  customerInfluence: CustomerInfluence
  avgConfidence: number
  reference?: string
}

export interface SharedResponsibilityWidgets {
  customerFindings: number
  providerFindings: number
  vendorFindings: number
  browserDependencies: number
  cloudDependencies: number
  migrationBlockers: number
  actionableFindings: number
  waitingDependencies: number
  migrationProgress: number
  providerReadiness: number
}

export interface SharedResponsibilityTotals {
  findings: number
  customer: number
  provider: number
  ecosystem: number
  actionable: number
  waiting: number
  blocked: number
  resolved: number
}

export interface EdgeOriginSummary {
  providerFrontedAssets: number
  edgeManaged: number
  originCustomerControlled: number
  summary: string
}

export interface AttributionSummary {
  attributed: number
  unattributed: number
  avgConfidence: number
}

/** The full aggregate consumed by the dashboard, Executive strip, reports, etc. */
export interface SharedResponsibilityIntelligence {
  generatedAt: string
  hasData: boolean
  totals: SharedResponsibilityTotals
  readiness: {
    overall: DomainReadiness
    customer: DomainReadiness
    provider: DomainReadiness
    ecosystem: DomainReadiness
  }
  domainDistribution: { customer: number; provider: number; ecosystem: number }
  severityByDomain: { customer: SeverityBucket; provider: SeverityBucket; ecosystem: SeverityBucket }
  matrix: SharedResponsibilityMatrixRow[]
  findings: OwnershipFinding[]
  blockers: OwnershipFinding[]
  waves: MigrationWave[]
  widgets: SharedResponsibilityWidgets
  providerBreakdown: ProviderBreakdownRow[]
  edgeOrigin: EdgeOriginSummary
  attribution: AttributionSummary
}
