/**
 * Canonical Cryptographic Trust & Telemetry model.
 *
 * ONE model, four projections. `/dashboard/trust-dashboard`,
 * `/dashboard/trust-state-discovery`, `/dashboard/certificate-telemetry` and
 * `/dashboard/multi-cloud-telemetry` all read this structure, so a certificate,
 * an asset, a cloud resource or a score cannot carry a different value
 * depending on which of the four pages happens to be open.
 *
 * Composition rule (brief sections 7, 8 and 17): this module OWNS nothing that
 * another engine already owns. Certificates, endpoints, TLS findings and trust
 * chains are the records `buildTlsPkiIntelligence()` produced - the same objects
 * PKI Visibility and TLS Telemetry render. Estate scores come from the Quantum
 * Readiness snapshot. Per-asset posture comes from the Migration Planner
 * portfolio. What this model adds is the TRUST layer over them: relationship
 * discovery, trust-state classification, cloud normalisation, lifecycle
 * intelligence and reconciliation - none of which existed as a shared engine.
 *
 * Evidence rule (brief sections 1, 13 and 16): nothing here is synthesised. A
 * quantity that could not be measured is `null` and renders as "Not observed" -
 * never as 0, never as "healthy". Every score carries the basis it was computed
 * on and the share of the estate that basis actually covers.
 */

import type {
  EvidenceRef,
  EvidenceSource,
  PkiCertificate,
  PqcPosture,
  RiskLevel,
  Severity,
  TelemetryHealth,
  TlsEndpoint,
  TlsFinding,
  TrustChainNode,
} from '@/lib/tls-pki/types'

export type {
  EvidenceRef,
  EvidenceSource,
  PkiCertificate,
  PqcPosture,
  RiskLevel,
  Severity,
  TelemetryHealth,
  TlsEndpoint,
  TlsFinding,
  TrustChainNode,
}

/* ================================================================== */
/* Trust state vocabulary (brief section 4)                            */
/* ================================================================== */

/**
 * The single trust-state vocabulary. Every discovered subject - a certificate,
 * a CA, an endpoint, a service, a cloud resource - resolves to exactly one of
 * these on every page.
 *
 * `unknown` is a first-class state, not a failure: a subject we have inventory
 * for but no measurement of is genuinely unknown, and saying so is the honest
 * answer. It must never be silently folded into `healthy`.
 */
export type TrustState =
  | 'trusted'
  | 'healthy'
  | 'degraded'
  | 'at-risk'
  | 'critical'
  | 'expired'
  | 'invalid'
  | 'quantum-vulnerable'
  | 'pqc-ready'
  | 'migration-required'
  | 'unknown'

export const TRUST_STATE_LABEL: Record<TrustState, string> = {
  trusted: 'Trusted',
  healthy: 'Healthy',
  degraded: 'Degraded',
  'at-risk': 'At Risk',
  critical: 'Critical',
  expired: 'Expired',
  invalid: 'Invalid',
  'quantum-vulnerable': 'Quantum Vulnerable',
  'pqc-ready': 'PQC Ready',
  'migration-required': 'Migration Required',
  unknown: 'Unknown',
}

/** Severity ordering used for every "worst first" sort in the model. */
export const TRUST_STATE_RANK: Record<TrustState, number> = {
  critical: 9,
  invalid: 8,
  expired: 7,
  'quantum-vulnerable': 6,
  'at-risk': 5,
  'migration-required': 4,
  degraded: 3,
  unknown: 2,
  'pqc-ready': 1,
  healthy: 1,
  trusted: 0,
}

/* ================================================================== */
/* Scores (brief section 3)                                            */
/* ================================================================== */

/**
 * A score that can explain itself.
 *
 * `measured` is the honesty gate: when the estate carries no evidence for this
 * dimension the score is `null` and the tile renders "Not measured" instead of
 * a 0 that would read as catastrophic or a 100 that would read as perfect.
 * `coveragePercent` states how much of the population the score was actually
 * computed over, so a 100 derived from two of four hundred assets cannot be
 * mistaken for estate-wide health.
 */
export interface TrustScore {
  key: string
  label: string
  /** 0-100, or null when nothing in the tenant can support the statement. */
  value: number | null
  measured: boolean
  /** What the score was computed from, in operator language. */
  basis: string
  /** Population the score covers, e.g. "84 of 137 certificates". */
  denominator: string
  coveragePercent: number
  /** Plain-language reason for the current value - shown on hover and in drawers. */
  reason: string
  tone: 'critical' | 'warning' | 'good' | 'info' | 'neutral'
  /** Where clicking the score takes the user (brief section 11). */
  href: string
}

/* ================================================================== */
/* KPIs (brief section 3)                                              */
/* ================================================================== */

/** Every KPI links to the records that produce it - brief section 11. */
export interface TrustKpi {
  key: string
  label: string
  value: number | null
  measured: boolean
  detail: string
  tone: 'critical' | 'warning' | 'good' | 'info' | 'neutral'
  href: string
  /** Ids the number is made of, so the drill-down shows exactly these rows. */
  scopeIds: string[]
  hint: string
}

/* ================================================================== */
/* Trust nodes and relationships (brief section 4)                     */
/* ================================================================== */

export type TrustNodeKind =
  | 'root-ca'
  | 'intermediate-ca'
  | 'certificate'
  | 'tls-endpoint'
  | 'service'
  | 'application'
  | 'api'
  | 'domain'
  | 'cloud-resource'
  | 'kubernetes-workload'
  | 'container'
  | 'load-balancer'
  | 'gateway'
  | 'identity-system'
  | 'encryption-service'
  | 'key-management'
  | 'asset'

export const TRUST_NODE_LABEL: Record<TrustNodeKind, string> = {
  'root-ca': 'Root CA',
  'intermediate-ca': 'Intermediate CA',
  certificate: 'Certificate',
  'tls-endpoint': 'TLS Endpoint',
  service: 'Service',
  application: 'Application',
  api: 'API',
  domain: 'Domain',
  'cloud-resource': 'Cloud Resource',
  'kubernetes-workload': 'Kubernetes Workload',
  container: 'Container',
  'load-balancer': 'Load Balancer',
  gateway: 'Gateway',
  'identity-system': 'Identity System',
  'encryption-service': 'Encryption Service',
  'key-management': 'Key Management',
  asset: 'Asset',
}

/**
 * The layer a node occupies in the trust hierarchy. Drives the graph's vertical
 * ordering: Root CA (0) at the top down to Cloud Resource (6).
 */
export const TRUST_NODE_TIER: Record<TrustNodeKind, number> = {
  'root-ca': 0,
  'intermediate-ca': 1,
  certificate: 2,
  'tls-endpoint': 3,
  domain: 3,
  'load-balancer': 3,
  gateway: 3,
  service: 4,
  api: 4,
  'identity-system': 4,
  'key-management': 4,
  'encryption-service': 4,
  application: 5,
  'kubernetes-workload': 5,
  container: 5,
  asset: 5,
  'cloud-resource': 6,
}

export interface TrustNode {
  id: string
  kind: TrustNodeKind
  label: string
  /** Secondary identifier - host, resource path, issuer DN. */
  subtitle: string

  state: TrustState
  stateReason: string
  posture: PqcPosture
  riskLevel: RiskLevel
  riskScore: number

  /** Canonical platform ids, so a node links straight into the other modules. */
  assetId: string | null
  certificateId: string | null
  endpointId: string | null

  environment: string
  owner: string
  provider: string
  providerLabel: string
  account: string
  region: string

  /** Nodes that would be impacted if this one failed (brief section 4). */
  dependentCount: number
  /** Nodes this one relies on. */
  dependencyCount: number

  quantumVulnerable: boolean
  /**
   * Soonest certificate expiry that affects this node. `null` where no
   * certificate governs it - never 0, which would read as "expires today".
   */
  daysToExpiry: number | null

  findingIds: string[]
  criticalFindings: number
  highFindings: number

  /** True when the node came from a measurement, false when only inferred. */
  measured: boolean
  evidenceSources: EvidenceSource[]
  lastObservedAt: string | null
  /** Deep link into the owning module for this subject. */
  href: string
}

export type TrustEdgeKind =
  | 'issued'
  | 'signs-for'
  | 'protects'
  | 'deployed-on'
  | 'depends-on'
  | 'hosts'
  | 'communicates-with'
  | 'terminates-tls'
  | 'manages-keys'
  | 'runs-in'

export interface TrustRelationship {
  id: string
  from: string
  to: string
  kind: TrustEdgeKind
  label: string
  /** Trust health of the RELATIONSHIP, which can differ from either endpoint. */
  state: TrustState
  /** Why the relationship is in that state. */
  reason: string
  /** Where the edge was learned from - inventory, chain, or measurement. */
  source: 'certificate-chain' | 'asset-relationship' | 'deployment' | 'runtime' | 'cloud-attribution'
  measured: boolean
}

/** One end-to-end path through the hierarchy, for the chain inspector. */
export interface TrustChainPath {
  id: string
  nodeIds: string[]
  /** Worst state anywhere on the path - a chain is only as good as its weakest link. */
  state: TrustState
  /** The specific link that determines the path state. */
  weakestNodeId: string
  weakestReason: string
  /** Assets that lose service if this path breaks. */
  blastRadius: number
  daysToExpiry: number | null
  complete: boolean
  /** Why the chain is incomplete, when it is. */
  incompleteReason: string
}

/* ================================================================== */
/* Certificate lifecycle intelligence (brief section 5)                */
/* ================================================================== */

export type ExpiryBand = 'expired' | 'critical' | 'high' | 'warning' | 'healthy' | 'unknown'

export const EXPIRY_BAND_LABEL: Record<ExpiryBand, string> = {
  expired: 'Expired',
  critical: 'Critical - 7 days or less',
  high: 'High risk - 30 days or less',
  warning: 'Warning - 60 days or less',
  healthy: 'Healthy - over 60 days',
  unknown: 'No expiry recorded',
}

export const EXPIRY_BAND_ORDER: ExpiryBand[] = ['expired', 'critical', 'high', 'warning', 'healthy', 'unknown']

/** One validated aspect of a certificate or its chain (brief section 5). */
export interface ChainCheck {
  key:
    | 'root-ca'
    | 'intermediate-ca'
    | 'chain-complete'
    | 'chain-order'
    | 'signature'
    | 'validity'
    | 'revocation'
    | 'hostname'
    | 'algorithm-strength'
    | 'key-strength'
    | 'tls-compatibility'
  label: string
  /**
   * `not-evaluated` is used wherever the platform genuinely cannot check the
   * property from the evidence it holds (revocation without an OCSP responder
   * reading, for example). It is never reported as a pass.
   */
  status: 'pass' | 'fail' | 'warn' | 'not-evaluated'
  /** Operator-facing explanation of exactly why - brief section 5 requires this. */
  detail: string
  severity: Severity | null
}

export interface CertificateTrustRecord {
  certificateId: string
  /** Aggregate of the checks below. */
  state: TrustState
  band: ExpiryBand
  checks: ChainCheck[]
  failedChecks: number
  warnChecks: number
  notEvaluatedChecks: number
  /** Chain path this certificate sits on, when one could be assembled. */
  chainPathId: string | null
  /** Endpoints/assets that would break at expiry - brief section 4 and 11. */
  affectedNodeIds: string[]
  affectedAssetCount: number
  /** Renewal signal, only when a real migration/renewal record exists. */
  renewal: {
    status: 'not-started' | 'planned' | 'in-progress' | 'renewed' | 'failed' | 'unknown'
    detail: string
    lastAttemptAt: string | null
  }
  owner: string
  ownerKnown: boolean
  /** Certificate exists in inventory but is bound to no endpoint or asset. */
  orphan: boolean
  deploymentKnown: boolean
  provider: CloudProviderId
  providerLabel: string
  account: string
  region: string
  environment: string
  tlsVersions: string[]
  remediation: string
}

export interface CertificateIntelligence {
  lifecycle: { valid: number; expiring: number; expired: number; revoked: number; notYetValid: number; unknown: number }
  bands: Array<{ band: ExpiryBand; label: string; count: number; percent: number; certificateIds: string[] }>
  issuers: Array<{
    issuer: string
    certificates: number
    expiring: number
    expired: number
    quantumVulnerable: number
    pqcReady: number
    averageRisk: number
    certificateIds: string[]
  }>
  algorithmDistribution: Array<{ label: string; count: number; percent: number; posture: PqcPosture; certificateIds: string[] }>
  /** Expiry horizon over the next 12 months, built from real notAfter values. */
  expiryTimeline: Array<{ label: string; date: string; count: number; certificateIds: string[] }>
  /** Certificates observed entering the estate per day - a real discovery trend. */
  discoveryTrend: Array<{ label: string; date: string; discovered: number; expiring: number }>
  chainValidation: { passed: number; failed: number; warned: number; notEvaluated: number }
  orphans: string[]
  ownerless: string[]
  undeployed: string[]
  duplicates: Array<{ key: string; label: string; certificateIds: string[] }>
  renewalFailures: string[]
  /** Certificate count reconciled against every other module - section 7. */
  reconciledTotal: number
}

/* ================================================================== */
/* Cloud estate (brief section 6)                                      */
/* ================================================================== */

export type CloudProviderId =
  | 'aws'
  | 'azure'
  | 'gcp'
  | 'kubernetes'
  | 'private-cloud'
  | 'hybrid'
  | 'oracle'
  | 'ibm'
  | 'alibaba'
  | 'digitalocean'
  | 'cloudflare'
  | 'other'
  | 'unattributed'

export const CLOUD_PROVIDER_LABEL: Record<CloudProviderId, string> = {
  aws: 'Amazon Web Services',
  azure: 'Microsoft Azure',
  gcp: 'Google Cloud',
  kubernetes: 'Kubernetes',
  'private-cloud': 'Private Cloud',
  hybrid: 'Hybrid Cloud',
  oracle: 'Oracle Cloud',
  ibm: 'IBM Cloud',
  alibaba: 'Alibaba Cloud',
  digitalocean: 'DigitalOcean',
  cloudflare: 'Cloudflare',
  other: 'Other Cloud',
  unattributed: 'Unattributed',
}

export type EncryptionState = 'encrypted' | 'partially-encrypted' | 'unencrypted' | 'not-observed'

export interface CloudResource {
  id: string
  assetId: string | null
  name: string
  resourceType: string
  service: string
  provider: CloudProviderId
  providerLabel: string
  /** Account / subscription / project, exactly as the tenant recorded it. */
  account: string
  accountLabel: string
  region: string
  environment: string
  owner: string

  encryptionState: EncryptionState
  encryptionAlgorithms: string[]
  keyManagement: string
  keyManagementKnown: boolean

  certificateIds: string[]
  tlsVersions: string[]
  posture: PqcPosture
  state: TrustState
  stateReason: string
  riskLevel: RiskLevel
  riskScore: number
  quantumVulnerable: boolean
  complianceState: 'compliant' | 'non-compliant' | 'exception' | 'not-assessed'
  complianceDetail: string

  findingIds: string[]
  criticalFindings: number

  lastSeenAt: string | null
  lastTelemetryAt: string | null
  /** How the provider was determined - the honesty trail for section 6. */
  attribution: {
    method: string
    confidence: number
    reason: string
    /** false => provider is a generic bucket, not a named cloud. */
    attributed: boolean
  }
  evidenceSources: EvidenceSource[]
  href: string
}

export interface CloudRegionPosture {
  provider: CloudProviderId
  providerLabel: string
  region: string
  resources: number
  encrypted: number
  unencrypted: number
  notObserved: number
  certificates: number
  expiringCertificates: number
  quantumVulnerable: number
  pqcReady: number
  criticalFindings: number
  /** 0-100, or null when nothing in the region carries an encryption reading. */
  trustScore: number | null
  measured: boolean
  state: TrustState
  /** Region deviates materially from the provider mean - measured, not guessed. */
  anomaly: string | null
}

export interface CloudProviderPosture {
  provider: CloudProviderId
  providerLabel: string
  connected: boolean
  connectorStatus: string
  connectorCount: number
  lastSyncAt: string | null
  accounts: Array<{ id: string; label: string; resources: number; regions: string[] }>
  regions: string[]
  resources: number
  encryptedResources: number
  unencryptedResources: number
  encryptionCoverage: number | null
  certificates: number
  expiringCertificates: number
  expiredCertificates: number
  kmsResources: number
  kmsProviders: string[]
  weakCryptoResources: number
  quantumVulnerableResources: number
  pqcReadyResources: number
  tls13Endpoints: number
  legacyTlsEndpoints: number
  criticalFindings: number
  highFindings: number
  trustScore: number | null
  measured: boolean
  state: TrustState
  stateReason: string
  lastTelemetryAt: string | null
}

export interface CloudEstate {
  /** True only when at least one resource could be attributed to a real cloud. */
  hasCloudEvidence: boolean
  connectorsConfigured: number
  connectorsActive: number
  providers: CloudProviderPosture[]
  regions: CloudRegionPosture[]
  resources: CloudResource[]
  totals: {
    resources: number
    attributedResources: number
    unattributedResources: number
    encrypted: number
    unencrypted: number
    encryptionNotObserved: number
    certificates: number
    quantumVulnerable: number
    pqcReady: number
    kmsManaged: number
  }
  /** Cross-cloud drift: same service configured differently per provider. */
  drift: Array<{
    id: string
    title: string
    detail: string
    severity: Severity
    providers: CloudProviderId[]
    resourceIds: string[]
  }>
  anomalies: Array<{
    id: string
    title: string
    detail: string
    severity: Severity
    provider: CloudProviderId
    region: string
    resourceIds: string[]
  }>
  /** Weak / quantum-vulnerable algorithm spread across clouds. */
  algorithmSpread: Array<{
    algorithm: string
    posture: PqcPosture
    total: number
    byProvider: Array<{ provider: CloudProviderId; providerLabel: string; count: number }>
  }>
}

/* ================================================================== */
/* Events (brief section 9)                                            */
/* ================================================================== */

export type TrustEventKind =
  | 'asset-discovered'
  | 'asset-removed'
  | 'certificate-discovered'
  | 'certificate-expiring'
  | 'certificate-expired'
  | 'certificate-renewed'
  | 'trust-chain-failure'
  | 'tls-configuration-changed'
  | 'algorithm-changed'
  | 'quantum-vulnerable-detected'
  | 'pqc-migration-completed'
  | 'cloud-resource-discovered'
  | 'cloud-encryption-changed'
  | 'regional-posture-changed'
  | 'scan-completed'
  | 'agent-telemetry'
  | 'finding-created'
  | 'finding-resolved'

export const TRUST_EVENT_LABEL: Record<TrustEventKind, string> = {
  'asset-discovered': 'Asset discovered',
  'asset-removed': 'Asset removed',
  'certificate-discovered': 'Certificate discovered',
  'certificate-expiring': 'Certificate expiring',
  'certificate-expired': 'Certificate expired',
  'certificate-renewed': 'Certificate renewed',
  'trust-chain-failure': 'Trust-chain failure',
  'tls-configuration-changed': 'TLS configuration changed',
  'algorithm-changed': 'Cryptographic algorithm changed',
  'quantum-vulnerable-detected': 'Quantum-vulnerable asset detected',
  'pqc-migration-completed': 'PQC migration completed',
  'cloud-resource-discovered': 'Cloud resource discovered',
  'cloud-encryption-changed': 'Cloud encryption changed',
  'regional-posture-changed': 'Regional trust posture changed',
  'scan-completed': 'Scanner completed',
  'agent-telemetry': 'Agent telemetry received',
  'finding-created': 'Critical finding created',
  'finding-resolved': 'Finding resolved',
}

export interface TrustEvent {
  id: string
  kind: TrustEventKind
  label: string
  title: string
  detail: string
  severity: Severity
  subject: string
  subjectHref: string | null
  assetId: string | null
  certificateId: string | null
  provider: CloudProviderId | null
  region: string
  at: string | null
  source: string
  sourceTable: string
}

/* ================================================================== */
/* Reconciliation (brief section 16)                                   */
/* ================================================================== */

export interface ReconciliationIssue {
  id: string
  kind:
    | 'missing-relationship'
    | 'duplicate-certificate'
    | 'orphan-certificate'
    | 'missing-cloud-mapping'
    | 'missing-trust-relationship'
    | 'stale-telemetry'
    | 'conflicting-asset-state'
    | 'inconsistent-certificate-state'
    | 'unknown-algorithm'
    | 'ownerless-asset'
  title: string
  detail: string
  severity: Severity
  count: number
  /** The table the discrepancy lives in - "identify the source", section 16. */
  sourceTable: string
  affectedIds: string[]
  remediation: string
  href: string
}

/**
 * Cross-module count agreement.
 *
 * Each line names a figure this model publishes and the module it must equal.
 * `agrees` is computed, not asserted: when it is false the UI says which way
 * the numbers differ rather than silently rendering one of them.
 */
export interface CrossModuleCheck {
  key: string
  label: string
  value: number
  comparedWith: string
  comparedValue: number
  agrees: boolean
  note: string
}

export interface ReconciliationReport {
  issues: ReconciliationIssue[]
  crossModule: CrossModuleCheck[]
  /** 0-100 data-quality reading over the checks that could be evaluated. */
  dataQuality: number
  dataQualityMeasured: boolean
  evaluatedChecks: number
}

/* ================================================================== */
/* The model                                                           */
/* ================================================================== */

export interface TrustFabricIntelligence {
  generatedAt: string
  latestEvidenceAt: string | null
  hasData: boolean
  /** True when telemetry has not advanced inside the freshness window. */
  stale: boolean
  staleSinceHours: number | null

  scores: TrustScore[]
  kpis: TrustKpi[]

  nodes: TrustNode[]
  relationships: TrustRelationship[]
  chainPaths: TrustChainPath[]
  trustChains: TrustChainNode[]
  /** Counts per trust state across every discovered subject. */
  stateDistribution: Array<{ state: TrustState; label: string; count: number; percent: number; nodeIds: string[] }>
  /** Counts per node kind - the "what did discovery actually find" table. */
  kindDistribution: Array<{ kind: TrustNodeKind; label: string; count: number; measured: number; nodeIds: string[] }>

  certificates: PkiCertificate[]
  certificateTrust: CertificateTrustRecord[]
  certificateIntel: CertificateIntelligence

  endpoints: TlsEndpoint[]
  findings: TlsFinding[]

  cloud: CloudEstate

  events: TrustEvent[]
  /** Posture over time, from real evidence timestamps - section 3. */
  trend: Array<{
    label: string
    date: string
    certificatesObserved: number
    findingsOpened: number
    quantumVulnerable: number
    observations: number
  }>

  reconciliation: ReconciliationReport
  telemetry: TelemetryHealth

  /** Filter vocabularies, derived from the data actually present - section 10. */
  facets: {
    environments: string[]
    providers: Array<{ id: CloudProviderId; label: string }>
    accounts: Array<{ id: string; label: string; provider: CloudProviderId }>
    regions: string[]
    assetTypes: string[]
    algorithms: string[]
    tlsVersions: string[]
    issuers: string[]
    owners: string[]
  }
}
