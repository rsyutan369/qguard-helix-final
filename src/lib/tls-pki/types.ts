/**
 * Canonical TLS & PKI intelligence model.
 *
 * ONE model, four projections. `/dashboard/tls-telemetry`,
 * `/dashboard/pki-visibility`, `/dashboard/protocol-analytics` and
 * `/dashboard/tls-orchestrator` all read this structure, so a given endpoint,
 * certificate or finding cannot carry a different identity, posture or count
 * depending on which page happens to be open.
 *
 * Identity rules (brief section 3):
 *   - endpointId    `asset:<assetId>` when the observation is bound to a tenant
 *                   asset, otherwise `host:<normalized host>`. Stable across
 *                   scans because it never contains a row id.
 *   - certificateId `cert:<serial>` when a serial is known, else a digest of
 *                   subject + issuer. Rows from `certificates`,
 *                   `crypto_inventory` and `scanner_evidence` describing the
 *                   same certificate collapse onto one record.
 *   - findingId     derived from `findingIdentityKey()` in the scanner's own
 *                   module, so a finding shown here is the same finding CBOM,
 *                   Assets and the Quantum Readiness Engine show.
 *
 * Evidence rule (brief sections 1 and 14): nothing here is synthesised. A field
 * that could not be measured is `null` and renders as "Not observed" - never as
 * 0, never as "secure".
 */

/* ------------------------------------------------------------------ */
/* Shared vocabulary                                                   */
/* ------------------------------------------------------------------ */

/** Section 15 - the single classification vocabulary shared by all four pages. */
export type PqcPosture =
  | 'quantum-safe'
  | 'hybrid-ready'
  | 'pqc-ready'
  | 'migration-required'
  | 'quantum-vulnerable'
  | 'legacy'
  | 'unknown'

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

/** Where a statement came from. Rendered next to every finding (section 14). */
export type EvidenceSource =
  | 'runtime-telemetry'
  | 'agent-scan'
  | 'network-scan'
  | 'certificate-store'
  | 'crypto-inventory'
  | 'scan-finding'
  | 'exposure'
  | 'security-event'

/**
 * HOW a transport fact was obtained — the distinction between what clients
 * actually negotiate and what a server merely accepts.
 *
 *   live-traffic      a runtime agent saw this in a real connection
 *   scanner-probe     an active scan offered it and the server accepted it
 *                     (e.g. TLS 1.0 accepted when ONLY TLS 1.0 was offered)
 *   inventory-record  read from a stored record (certificate store)
 */
export type ObservationBasis = 'live-traffic' | 'scanner-probe' | 'inventory-record'

export function observationBasisFor(source: EvidenceSource): ObservationBasis {
  if (source === 'runtime-telemetry') return 'live-traffic'
  if (source === 'certificate-store') return 'inventory-record'
  return 'scanner-probe'
}

export interface EvidenceRef {
  source: EvidenceSource
  /** The row that carries the statement - clickable provenance. */
  recordId: string
  table: string
  observedAt: string | null
  detail: string
}

/* ------------------------------------------------------------------ */
/* Transport observations                                              */
/* ------------------------------------------------------------------ */

/**
 * One measured transport fact about an endpoint.
 *
 * Deliberately narrow: a row only becomes an observation when it actually names
 * a protocol version, a suite, a key agreement, a signature or a certificate.
 * Policy findings ("No OCSP Stapling") are findings, not observations - filing
 * them here is what previously produced algorithm charts full of rule names.
 */
export interface TlsObservation {
  id: string
  endpointId: string
  assetId: string | null
  kind: 'protocol' | 'cipher-suite' | 'key-exchange' | 'signature' | 'certificate'
  /** Raw measured string, exactly as observed. */
  observed: string
  /** Canonical grouping label from the suite decomposer. */
  family: string
  posture: PqcPosture
  /** true / false only when the observation determines it; null means N/A. */
  forwardSecrecy: boolean | null
  severity: Severity | null
  observedAt: string | null
  evidence: EvidenceRef
  /** How this fact was obtained. A merged fact keeps the strongest basis (live traffic wins). */
  basis: ObservationBasis
  /**
   * Handshakes represented by this observation, when the telemetry actually
   * carries a count. `null` means the source recorded a configuration fact, not
   * a traffic volume - the surface then shows "observations", never a
   * fabricated connection number.
   */
  handshakes: number | null
  /** The agent explicitly reported a failed or downgraded negotiation. */
  failed: boolean
  downgrade: boolean
}

/** TLS protocol versions, ordered oldest to newest for stable rendering. */
export const TLS_VERSION_ORDER = ['SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'] as const
export type TlsVersionLabel = (typeof TLS_VERSION_ORDER)[number] | 'Unknown'

/* ------------------------------------------------------------------ */
/* Endpoints                                                           */
/* ------------------------------------------------------------------ */

export interface TlsEndpoint {
  id: string
  assetId: string | null
  name: string
  host: string
  port: number | null
  assetType: string
  environment: string
  owner: string
  internetFacing: boolean

  /* ---- measured transport posture ---- */
  /** Highest protocol version actually observed, or null. */
  negotiatedVersion: TlsVersionLabel | null
  observedVersions: TlsVersionLabel[]
  cipherSuites: string[]
  keyExchange: string[]
  signatureAlgorithms: string[]
  forwardSecrecy: boolean | null

  /* ---- classification (identical vocabulary on all four pages) ---- */
  posture: PqcPosture
  postureReason: string
  riskLevel: RiskLevel
  riskScore: number
  /** Mirrors the Quantum Readiness / Migration Planner reading for this asset. */
  quantumVulnerable: boolean

  /* ---- lifecycle ---- */
  certificateIds: string[]
  /** Soonest certificate expiry across this endpoint's certificates. */
  daysToExpiry: number | null
  findingIds: string[]
  criticalFindings: number
  highFindings: number

  /* ---- orchestration ---- */
  migrationStatus: string
  migrationProgressPct: number
  queued: boolean
  remediationActions: string[]

  /* ---- freshness ---- */
  lastObservedAt: string | null
  evidenceSources: EvidenceSource[]
  /** Total observations backing this endpoint - the honest denominator. */
  observationCount: number
  handshakeCount: number | null
  /**
   * True when a protocol version, cipher suite or key agreement was actually
   * observed here. An endpoint known only through a certificate is real, but it
   * has never been seen NEGOTIATING anything, so it is excluded from every TLS
   * percentage rather than diluting the denominator.
   */
  hasTransportEvidence: boolean
  /**
   * How this endpoint's protocol / suite / key-agreement facts were obtained.
   * `scanner-probe` means "the server ACCEPTS these when offered", not "clients
   * negotiate these"; only `live-traffic` describes real connections.
   * null when there is no transport evidence.
   */
  transportBasis: 'live-traffic' | 'scanner-probe' | 'mixed' | null
}

/* ------------------------------------------------------------------ */
/* Certificates                                                        */
/* ------------------------------------------------------------------ */

export type CertificateLifecycle = 'valid' | 'expiring' | 'expired' | 'revoked' | 'not-yet-valid' | 'unknown'

export interface PkiCertificate {
  id: string
  name: string
  subject: string
  /** Subject alternative names, when the source recorded them. */
  san: string[]
  issuer: string
  serialNumber: string | null
  fingerprint: string | null

  assetId: string | null
  assetName: string
  endpointId: string | null

  publicKeyAlgorithm: string
  /** Display-ready "algorithm + size", computed once so no surface doubles it. */
  algorithmLabel: string
  keySize: number | null
  signatureAlgorithm: string | null

  notBefore: string | null
  notAfter: string | null
  daysToExpiry: number | null
  lifecycle: CertificateLifecycle

  posture: PqcPosture
  selfSigned: boolean
  /** Issuer could not be matched to any observed CA in this tenant. */
  unknownIssuer: boolean
  riskLevel: RiskLevel
  riskScore: number
  migrationPriority: number

  sources: EvidenceSource[]
  evidence: EvidenceRef[]
  lastObservedAt: string | null
}

/** One node of the observed trust hierarchy: Root -> Intermediate -> Leaf. */
export interface TrustChainNode {
  id: string
  label: string
  kind: 'root' | 'intermediate' | 'leaf'
  posture: PqcPosture
  certificateIds: string[]
  /** Endpoints that depend on this node - the blast radius. */
  endpointIds: string[]
  children: TrustChainNode[]
  /**
   * `true` when a certificate for this node exists in the tenant's inventory,
   * `false` when the node was inferred from an issuer string alone. An inferred
   * CA is drawn dimmed and labelled "issuer name only, not measured".
   */
  measured: boolean
}

/* ------------------------------------------------------------------ */
/* Findings                                                            */
/* ------------------------------------------------------------------ */

export interface TlsFinding {
  id: string
  title: string
  category: 'protocol' | 'cipher' | 'key-exchange' | 'certificate' | 'configuration' | 'quantum'
  severity: Severity
  endpointId: string | null
  assetId: string | null
  assetName: string
  /** The measured value the finding is about, e.g. `TLS 1.0` or `RSA-2048`. */
  observed: string
  impact: string
  remediation: string
  /** Standard the remediation follows, e.g. `FIPS 203`, `RFC 8996`. */
  standard: string
  evidence: EvidenceRef[]
  firstObservedAt: string | null
  lastObservedAt: string | null
  /** Current lifecycle position of the fix, from real migration state. */
  migrationStatus: string
  instances: number
}

/* ------------------------------------------------------------------ */
/* Protocol analytics                                                  */
/* ------------------------------------------------------------------ */

export interface DistributionRow {
  label: string
  count: number
  percent: number
  posture: PqcPosture
  /** Endpoints this row is measured on - enables Protocol -> Asset drill-down. */
  endpointIds: string[]
}

export interface ProtocolAnalytics {
  /** Denominator label so a percentage can never be read against the wrong base. */
  basis: 'observations' | 'endpoints'
  totalObservations: number
  versionDistribution: DistributionRow[]
  cipherDistribution: DistributionRow[]
  keyExchangeDistribution: DistributionRow[]
  signatureDistribution: DistributionRow[]
  forwardSecrecy: { withFs: number; withoutFs: number; notApplicable: number }
  /** Endpoints whose best observed version is below TLS 1.2 (RFC 8996). */
  legacyEndpointIds: string[]
  /** Observations that recorded a handshake failure - measured only. */
  handshakeFailures: number
  handshakeFailuresMeasured: boolean
  /** Endpoints where a downgrade was explicitly flagged by an agent. */
  downgradeEndpointIds: string[]
  downgradeMeasured: boolean
  anomalies: Array<{
    id: string
    title: string
    detail: string
    severity: Severity
    endpointIds: string[]
  }>
  /** PQC adoption over the observed window, from real observation timestamps. */
  adoptionTrend: Array<{ label: string; date: string; pqc: number; hybrid: number; classical: number }>
}

/* ------------------------------------------------------------------ */
/* Posture (the shared header on all four pages)                       */
/* ------------------------------------------------------------------ */

export interface PqcTlsPosture {
  /** Endpoints carrying at least one measured transport observation. */
  tlsEnabledAssets: number
  /** Assets in the tenant with no transport evidence at all. */
  assetsWithoutTransportEvidence: number

  tls13Endpoints: number
  tls12Endpoints: number
  legacyEndpoints: number
  unknownVersionEndpoints: number

  hybridEndpoints: number
  pqcEndpoints: number
  classicalOnlyEndpoints: number
  quantumVulnerableEndpoints: number

  x25519Observations: number
  hybridMlKemObservations: number
  mlKemObservations: number

  weakCipherEndpoints: number
  certificatesAtRisk: number
  certificatesExpiring30d: number
  certificatesExpired: number

  migrationReadyEndpoints: number
  remediationRequiredEndpoints: number

  /** 0-100. Share of measured endpoints that are hybrid or post-quantum. */
  pqcAdoptionPercent: number
  /**
   * Estate-wide readiness taken from the Quantum Readiness snapshot - the same
   * number the QR Engine, Migration Planner and reports publish.
   */
  quantumReadinessScore: number
  quantumRiskScore: number
  quantumRiskLevel: string

  /** Coverage honesty: what fraction of assets we can actually speak to. */
  transportCoveragePercent: number
}

/* ------------------------------------------------------------------ */
/* Orchestration                                                       */
/* ------------------------------------------------------------------ */

export type OrchestrationStatus =
  | 'not-started'
  | 'planned'
  | 'ready'
  | 'in-progress'
  | 'validating'
  | 'completed'
  | 'failed'
  | 'rolled-back'

export type OrchestrationActionKind =
  | 'tls-upgrade'
  | 'certificate-replacement'
  | 'cipher-update'
  | 'key-exchange-migration'
  | 'hybrid-tls-enablement'
  | 'pqc-migration'
  | 'configuration-remediation'

export interface OrchestrationItem {
  id: string
  endpointId: string
  assetId: string | null
  assetName: string
  host: string
  environment: string
  internetFacing: boolean

  action: OrchestrationActionKind
  actionLabel: string
  /** Exactly what must change, in operator language. */
  changeSummary: string
  /** The measured value that triggered this item. */
  currentState: string
  targetState: string
  standard: string

  status: OrchestrationStatus
  statusDetail: string
  progressPct: number
  queued: boolean

  priority: number
  severity: Severity
  riskScore: number
  blastRadius: number
  estimatedEffortHours: number

  findingIds: string[]
  certificateIds: string[]
  evidence: EvidenceRef[]

  /** Which operations the backend can genuinely perform for this item. */
  availableActions: Array<'queue' | 'unqueue' | 'plan' | 'rescan' | 'evidence'>
  blockedReason: string | null
  lastChangeAt: string | null
}

export interface ConfigurationDrift {
  id: string
  endpointId: string
  assetName: string
  detail: string
  previous: string
  current: string
  detectedAt: string | null
  severity: Severity
}

export interface OrchestrationState {
  items: OrchestrationItem[]
  statusCounts: Record<OrchestrationStatus, number>
  queueDepth: number
  drift: ConfigurationDrift[]
  driftMeasured: boolean
  /** Real migration jobs touching TLS/PKI assets. */
  activeJobs: Array<{
    id: string
    assetId: string | null
    assetName: string
    jobType: string
    status: string
    progress: number
    targetAlgorithm: string
    updatedAt: string | null
  }>
  /** Migration plans that already cover these endpoints. */
  plans: Array<{ id: string; name: string; status: string; assetCount: number; updatedAt: string | null }>
  validation: {
    validated: number
    pending: number
    failed: number
    lastValidatedAt: string | null
  }
}

/* ------------------------------------------------------------------ */
/* Telemetry health and freshness                                      */
/* ------------------------------------------------------------------ */

export type PipelineStatus =
  | 'live'
  | 'scan-running'
  | 'inventory-only'
  | 'stale'
  | 'awaiting-telemetry'
  | 'no-collectors'

export interface TelemetryHealth {
  pipelineStatus: PipelineStatus
  agentsOnline: number
  agentsTotal: number
  connectorsActive: number
  connectorsTotal: number
  runningScans: number
  lastScanAt: string | null
  lastRuntimeEventAt: string | null
  lastCertificateObservationAt: string | null
  lastConfigurationChangeAt: string | null
  /** Row counts actually consulted, for the provenance panel. */
  sourceCounts: Record<string, number>
  /** True when a detail query hit its row cap - the UI must then say "at least". */
  truncated: boolean
}

/* ------------------------------------------------------------------ */
/* The model                                                           */
/* ------------------------------------------------------------------ */

export interface TlsPkiIntelligence {
  generatedAt: string
  /** Newest evidence timestamp anywhere in the model (section 16). */
  latestEvidenceAt: string | null
  hasData: boolean

  posture: PqcTlsPosture
  endpoints: TlsEndpoint[]
  observations: TlsObservation[]
  certificates: PkiCertificate[]
  trustChains: TrustChainNode[]
  findings: TlsFinding[]
  protocol: ProtocolAnalytics
  orchestration: OrchestrationState
  telemetry: TelemetryHealth

  /** Timeline of measured TLS/PKI evidence, bucketed by day. */
  timeline: Array<{
    label: string
    date: string
    observations: number
    certificates: number
    findings: number
  }>

  /**
   * Certificate rollups. Part of the MODEL rather than the presentation layer,
   * so the lifecycle counts, the expiry horizon, the issuer table and the
   * algorithm chart are one computation that every reader shares.
   */
  pki: {
    lifecycle: { valid: number; expiring: number; expired: number; revoked: number; notYetValid: number; unknown: number }
    expiryBuckets: Array<{ label: string; count: number; percent: number; certificateIds: string[] }>
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
  }
}
