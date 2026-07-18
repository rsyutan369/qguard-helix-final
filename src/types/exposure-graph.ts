/**
 * Quantum Exposure Graph™ — Enterprise Cryptographic Dependency & Migration
 * Intelligence contract shared by the Express router
 * (src/api-server/exposure-graph.ts), the isomorphic intelligence engine
 * (src/lib/exposure-graph-intel.ts), the frontend hook
 * (src/hooks/use-exposure-graph.ts) and the offline verification tool
 * (tools/exposure-graph-check.ts).
 *
 * Every field is derived from real, tenant-scoped evidence (assets,
 * asset_relationships, CBOM / crypto_inventory, certificates, runtime crypto
 * telemetry, connector accounts, migration jobs). Values that are planning
 * estimates are explicitly named as estimates. No fabricated telemetry.
 */

/** Cryptographic posture of a node — the five-state legend of the graph. */
export type NodePosture = 'vulnerable' | 'hybrid' | 'pqc' | 'migrating' | 'unknown'

/** Discovered tenant asset vs. derived external/third-party entity. */
export type NodeKind = 'asset' | 'external'

export type PriorityLabel = 'Critical' | 'High' | 'Medium' | 'Low'

/** Normalized enterprise asset category (drives icons, tiers, grouping). */
export type AssetCategory =
  | 'certificate-authority'
  | 'kms'
  | 'hsm'
  | 'identity-provider'
  | 'pki'
  | 'vpn-gateway'
  | 'load-balancer'
  | 'api'
  | 'database'
  | 'kubernetes'
  | 'container'
  | 'cloud-resource'
  | 'server'
  | 'vm'
  | 'workstation'
  | 'web-application'
  | 'saas'
  | 'email'
  | 'dns'
  | 'directory'
  | 'ssh-server'
  | 'tls-endpoint'
  | 'vendor'
  | 'service'

/** Trust classification of a graph edge. */
export type EdgeTrustClass =
  | 'tls'
  | 'mtls'
  | 'certificate-chain'
  | 'api'
  | 'ssh'
  | 'vpn'
  | 'identity'
  | 'kms'
  | 'service-mesh'
  | 'cloud'
  | 'communication'
  | 'dependency'

export interface NodeCertificate {
  name: string
  algorithm: string
  issuer: string
  notAfter: string | null
  quantumSafe: boolean
  expiringSoon: boolean
}

export interface ExposureGraphNode {
  id: string
  label: string
  kind: NodeKind
  category: AssetCategory
  type: string
  environment: string
  region: string
  owner: string
  businessCriticality: PriorityLabel
  posture: NodePosture
  riskScore: number
  priority: PriorityLabel
  priorityScore: number
  priorityDrivers: string[]
  internetFacing: boolean
  migrationTier: number
  tierLabel: string
  algorithms: string[]
  protocols: string[]
  certificates: NodeCertificate[]
  dependencies: number
  dependents: number
  blastRadius: number
  findingsCount: number
  /** External nodes only — vendor / provider / issuer identity. */
  vendor?: string
}

export interface ExposureGraphEdge {
  id: string
  source: string
  target: string
  /** Raw relationship label from evidence (e.g. depends-on, issued-by). */
  type: string
  trustClass: EdgeTrustClass
  /** Cryptographic algorithm observed securing this link, when evidenced. */
  algorithm: string | null
  /** Posture of the link's observed crypto (unknown when unobserved). */
  posture: NodePosture
  /** True when the link carries quantum-vulnerable crypto or joins a critical pair. */
  critical: boolean
}

export interface ThirdPartyDependency {
  id: string
  vendor: string
  category: string
  connectedAssets: number
  connectedAssetNames: string[]
  algorithms: string[]
  tlsVersion: string | null
  certificate: string | null
  readiness: NodePosture
  riskLevel: PriorityLabel
  migrationCompatibility: string
  businessCriticality: PriorityLabel
}

export interface MigrationWaveEntry {
  wave: number
  tierLabel: string
  rationale: string
  nodes: Array<{ id: string; label: string; posture: NodePosture; riskScore: number; dependents: number }>
}

export interface MigrationCluster {
  id: string
  reason: string
  nodes: Array<{ id: string; label: string; posture: NodePosture }>
}

export interface MigrationBlocker {
  id: string
  label: string
  reason: string
  blockedDependents: number
}

export interface AdvisorRecommendation {
  id: string
  title: string
  detail: string
  severity: 'critical' | 'high' | 'medium' | 'low' | string
  confidencePct: number
  category: string
}

export interface AdvisorEstimates {
  migrationComplexity: number
  complexityLevel: string
  businessImpact: PriorityLabel
  compatibilityScorePct: number
  estimatedDurationWeeks: number
  parallelWorkstreams: number
  confidencePct: number
}

export interface ExposureSummary {
  totalAssets: number
  quantumVulnerable: number
  hybridAssets: number
  pqcReadyAssets: number
  migrationInProgress: number
  unknownPosture: number
  thirdPartyDependencies: number
  trustRelationships: number
  criticalTrustRelationships: number
  internetFacingAssets: number
  highRiskAssets: number
  legacyCryptoAssets: number
  certificateChains: number
  pkiObjects: number
  maxBlastRadius: number
  migrationReadinessScore: number
  quantumReadinessScore: number
  quantumRiskScore: number
}

export interface RiskPriorityRow {
  id: string
  label: string
  category: AssetCategory
  environment: string
  posture: NodePosture
  priority: PriorityLabel
  priorityScore: number
  drivers: string[]
  riskScore: number
  internetFacing: boolean
  dependents: number
  certificateRisk: boolean
}

export interface ExposureIntelligence {
  generatedAt: string | null
  lastAssessmentAt: string | null
  hasData: boolean
  summary: ExposureSummary
  graph: { nodes: ExposureGraphNode[]; edges: ExposureGraphEdge[] }
  thirdParty: ThirdPartyDependency[]
  migrationOrder: { waves: MigrationWaveEntry[]; clusters: MigrationCluster[]; blockers: MigrationBlocker[] }
  advisor: { recommendations: AdvisorRecommendation[]; estimates: AdvisorEstimates }
  riskPrioritization: RiskPriorityRow[]
  evidence: { sources: string[]; note: string }
}

/* ------------------------------------------------------------------ */
/* Client-side analytical results (computed from the graph contract)  */
/* ------------------------------------------------------------------ */

export interface BlastRadiusResult {
  nodeId: string
  direct: string[]
  indirect: string[]
  /** Affected nodes reached through certificate/identity/KMS trust edges. */
  trustChain: string[]
  depths: Record<string, number>
  totalAffected: number
  internetFacing: number
  businessCritical: number
  environments: string[]
  affectedByTier: Array<{ tierLabel: string; count: number }>
}

export interface ImpactItem {
  label: string
  detail: string
  severity: PriorityLabel
}

export interface ProposedAlgorithmChange {
  from: string
  to: string
  kind: string
}

export interface MigrationImpactAnalysis {
  nodeId: string
  currentState: {
    algorithms: string[]
    protocols: string[]
    certificates: number
    vulnerableCertificates: number
    trustRelationships: number
    dependencies: number
    dependents: number
    communicationPaths: number
  }
  proposedMigration: ProposedAlgorithmChange[]
  potentialInterruptions: ImpactItem[]
  requiredRemediation: ImpactItem[]
  affected: {
    direct: number
    indirect: number
    trustChain: number
    internetFacing: number
    businessCritical: number
    environments: string[]
  }
  estimatedRisk: PriorityLabel
  /** Planning estimate — bounded window, not a measured value. */
  estimatedDowntimeHours: { min: number; max: number }
  compatibilityScorePct: number
  confidencePct: number
  evidenceNote: string
}

export const EMPTY_EXPOSURE_INTELLIGENCE: ExposureIntelligence = {
  generatedAt: null,
  lastAssessmentAt: null,
  hasData: false,
  summary: {
    totalAssets: 0,
    quantumVulnerable: 0,
    hybridAssets: 0,
    pqcReadyAssets: 0,
    migrationInProgress: 0,
    unknownPosture: 0,
    thirdPartyDependencies: 0,
    trustRelationships: 0,
    criticalTrustRelationships: 0,
    internetFacingAssets: 0,
    highRiskAssets: 0,
    legacyCryptoAssets: 0,
    certificateChains: 0,
    pkiObjects: 0,
    maxBlastRadius: 0,
    migrationReadinessScore: 0,
    quantumReadinessScore: 0,
    quantumRiskScore: 0,
  },
  graph: { nodes: [], edges: [] },
  thirdParty: [],
  migrationOrder: { waves: [], clusters: [], blockers: [] },
  advisor: {
    recommendations: [],
    estimates: {
      migrationComplexity: 0,
      complexityLevel: 'Minimal',
      businessImpact: 'Low',
      compatibilityScorePct: 0,
      estimatedDurationWeeks: 0,
      parallelWorkstreams: 1,
      confidencePct: 0,
    },
  },
  riskPrioritization: [],
  evidence: { sources: [], note: '' },
}
