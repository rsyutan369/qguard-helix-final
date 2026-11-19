/**
 * Real Time Scanning — the shared event and graph contract.
 *
 * The live canvas is a pure projection of an append-only event log. The
 * backend runner appends events as the EXISTING scanner engines report
 * (`executeWebScan` + the public-edge intelligence engine); the browser replays
 * the same log through the same reducer (`graph-reducer.ts`). Snapshot, live
 * stream, page refresh and timeline replay therefore all produce the same graph
 * from the same records — there is no second derivation to drift.
 *
 * Pure types only: imported by the Express runner AND the React page.
 */

export type LiveScanStatus =
  | 'idle'
  | 'starting'
  | 'running'
  | 'paused'
  | 'cancelling'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled'

export const TERMINAL_STATUSES: readonly LiveScanStatus[] = ['completed', 'partial', 'failed', 'cancelled']

export type LiveEventType =
  | 'scan.started'
  | 'scan.progress'
  | 'scan.paused'
  | 'scan.resumed'
  | 'scan.completed'
  | 'scan.failed'
  | 'scan.cancelled'
  | 'scan.heartbeat'
  | 'asset.discovered'
  | 'asset.updated'
  | 'certificate.discovered'
  | 'certificate.analyzed'
  | 'algorithm.detected'
  | 'relationship.created'
  | 'relationship.updated'
  | 'relationship.removed'
  | 'finding.created'
  | 'finding.updated'
  | 'finding.resolved'
  | 'evidence.recorded'

/** The six discovery lanes, left to right. */
export type LaneId = 'sources' | 'trust' | 'certificates' | 'algorithms' | 'relying' | 'findings'

export const LANES: ReadonlyArray<{ id: LaneId; title: string; hint: string }> = [
  { id: 'sources', title: 'Sources & Assets', hint: 'Scanner, domains, addresses, TLS endpoints' },
  { id: 'trust', title: 'Trust Anchors & CAs', hint: 'Issuing CAs, roots, trust store' },
  { id: 'certificates', title: 'Certificates', hint: 'Leaf and chain certificates as presented' },
  { id: 'algorithms', title: 'Algorithms', hint: 'Public key, signature, key establishment' },
  { id: 'relying', title: 'Relying Systems & Vendors', hint: 'Served applications, edge and CA operators' },
  { id: 'findings', title: 'Quantum Findings', hint: 'Evidence-backed risks and migration needs' },
]

export type NodeKind =
  | 'scanner'
  | 'asset'
  | 'address'
  | 'endpoint'
  | 'ca'
  | 'trust-store'
  | 'certificate'
  | 'algorithm'
  | 'application'
  | 'vendor'
  | 'finding'

export const NODE_LANE: Record<NodeKind, LaneId> = {
  scanner: 'sources',
  asset: 'sources',
  address: 'sources',
  endpoint: 'sources',
  ca: 'trust',
  'trust-store': 'trust',
  certificate: 'certificates',
  algorithm: 'algorithms',
  application: 'relying',
  vendor: 'relying',
  finding: 'findings',
}

/**
 * Node status vocabulary. `unknown` is never rendered green: a missing
 * observation is not a pass.
 *
 * validated — measured good (trusted chain, PQC/hybrid measured)
 * observed  — directly observed, no risk verdict attached
 * active    — currently being scanned
 * exposure  — quantum-migration exposure (classical public-key crypto)
 * critical  — critical / high finding or already-invalid cryptography
 * failed    — the measurement itself failed (no handshake, DNS failure)
 * unknown   — not measured / incomplete
 */
export type NodeStatus = 'validated' | 'observed' | 'active' | 'exposure' | 'critical' | 'failed' | 'unknown'

export type RelationshipType =
  | 'SCANNED_BY'
  | 'RESOLVES_TO'
  | 'HOSTS_SERVICE'
  | 'PRESENTS_CERTIFICATE'
  | 'ISSUED_BY'
  | 'SIGNED_BY'
  | 'CHAIN_VALIDATED_TO'
  | 'TRUSTED_BY_STORE'
  | 'USES_PUBLIC_KEY_ALGORITHM'
  | 'USES_SIGNATURE_ALGORITHM'
  | 'NEGOTIATED_KEY_ESTABLISHMENT'
  | 'BACKED_BY'
  | 'DEPENDS_ON'
  | 'SERVES_APPLICATION'
  | 'HTTP_RESPONSE_FROM'
  | 'MANAGED_BY_VENDOR'
  | 'AFFECTED_BY_FINDING'
  | 'REQUIRES_MIGRATION'

/**
 * How an edge is known.
 *
 * validated — cryptographically verified (trust-store path validation passed)
 * observed  — directly observed on the wire (endpoint presented this certificate)
 * inferred  — derived from a signal that does not prove the relationship
 *             (CDN attribution from response headers, issuer NAME without a
 *             validated path) — always drawn dashed
 * inventory — read from the tenant's own asset records
 * failed    — the verification was attempted and failed
 */
export type EdgeVerification = 'validated' | 'observed' | 'inferred' | 'inventory' | 'failed'

export type EdgeRisk = 'none' | 'exposure' | 'critical'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/**
 * Finding exposure classes, kept separate on purpose: a classical RSA key is a
 * migration exposure, an expired certificate is an existing misconfiguration,
 * and neither is the same thing as "we could not measure".
 */
export type ExposureClass =
  | 'quantum-migration'
  | 'misconfiguration'
  | 'invalid-cryptography'
  | 'unsupported-capability'
  | 'unknown-migration-status'

export type FindingType =
  | 'QUANTUM_VULNERABLE_PUBLIC_KEY'
  | 'CLASSICAL_KEY_EXCHANGE_OBSERVED'
  | 'CLASSICAL_SIGNATURE_DEPENDENCY'
  | 'CERTIFICATE_EXPIRED'
  | 'CERTIFICATE_EXPIRING'
  | 'CERTIFICATE_CHAIN_INVALID'
  | 'UNTRUSTED_CERTIFICATE_AUTHORITY'
  | 'HOSTNAME_VALIDATION_FAILED'
  | 'LEGACY_TLS_CONFIGURATION'
  | 'PQC_READINESS_UNKNOWN'
  | 'PQC_MIGRATION_REQUIRED'
  | 'VENDOR_MIGRATION_DEPENDENCY'
  | 'CERTIFICATE_HYGIENE'
  | 'DNS_POLICY_GAP'
  | 'SCAN_INCOMPLETE'
  | 'CRYPTO_POSTURE'

export type FindingStatus = 'open' | 'resolved' | 'suppressed' | 'accepted' | 'unknown'

export type EvidenceSource =
  | 'dns-resolution'
  | 'tls-handshake'
  | 'certificate-chain'
  | 'named-group-probe'
  | 'http-response'
  | 'scanner-finding'
  | 'inventory-record'
  | 'policy-evaluation'

export interface LiveEvidence {
  id: string
  sourceType: EvidenceSource
  scanId: string
  observedAt: string
  /** host:port or hostname the observation came from. */
  sourceEndpoint: string
  /** Engine + module that produced the observation. */
  engine: string
  validationResult: string
  /** The observed values, verbatim from the engine. */
  observed: Record<string, unknown>
  /** SHA-256 of the canonical JSON of `observed` — tamper evidence. */
  contentHash: string
}

export interface LiveNode {
  id: string
  kind: NodeKind
  label: string
  sublabel?: string
  status: NodeStatus
  /** Scan targets this entity was observed for (shared certs/CAs/algorithms list several). */
  targets: string[]
  observedAt: string
  /** Sequence of the event that created the node — drives "newly discovered". */
  firstSeq: number
  /** Sequence of the latest event that changed it — out-of-order guard. */
  lastSeq: number
  evidenceIds: string[]
  /** Kind-specific facts, all from engine output. Missing means not observed. */
  data: Record<string, unknown>
}

export interface LiveEdge {
  id: string
  source: string
  target: string
  type: RelationshipType
  verification: EdgeVerification
  risk: EdgeRisk
  /** Human-readable source of the evidence, e.g. "TLS handshake (served chain)". */
  evidenceSource: string
  evidenceId: string | null
  observedAt: string
  confidence: number | null
  scanId: string
  /** Why the edge exists, in one sentence. */
  basis: string
  firstSeq: number
  lastSeq: number
}

export interface LiveFinding {
  id: string
  ruleId: string
  ruleVersion: string
  type: FindingType
  title: string
  description: string
  severity: Severity
  exposure: ExposureClass
  affectedNodeIds: string[]
  affectedTargets: string[]
  evidenceIds: string[]
  /** Actual observed values that triggered the rule. */
  observed: Record<string, string>
  detectedAt: string
  firstSeen: string
  lastSeen: string
  status: FindingStatus
  remediation: string
  standards: string[]
  /** Engine module that produced it, or `live-policy` for the PKI rules. */
  sourceModule: string
}

export interface AssetAssessment {
  runId: string
  target: string
  scanStatus: LiveScanStatus
  assessment: 'scanning' | 'completed' | 'incomplete'
}

export interface AssetFindingObservation extends AssetAssessment {
  finding: LiveFinding
  observedAt: string
}

export interface ActivityLine {
  title: string
  detail: string
  severity?: Severity | 'validated'
  entityId?: string
  target?: string
}

export interface LiveScanConfig {
  name: string
  targets: string[]
  /** Targets scanned in parallel. Bounded server-side. */
  concurrency: number
  /** Per-target probe budget in seconds. Bounded server-side. */
  targetTimeoutSec: number
  /** Days before expiry at which CERTIFICATE_EXPIRING fires. */
  expiringWithinDays: number
  trustStore: 'platform-default'
}

export interface RunMeta {
  id: string
  name: string
  status: LiveScanStatus
  stage: string
  createdAt: string
  startedAt: string | null
  endedAt: string | null
  targets: string[]
  completedTargets: string[]
  failedTargets: string[]
  activeTargets: string[]
  config: LiveScanConfig
  /** Linked PQC Scanner session (pqc_scan_sessions.id) — the persisted record. */
  sessionId: string | null
  persistence: 'database' | 'memory' | 'none'
  errorSummary: string | null
}

export interface LiveEvent {
  /** `${scanId}:${seq}` — globally unique, idempotency key. */
  id: string
  scanId: string
  tenantId: string
  /** Monotonic per scan, starting at 1. */
  seq: number
  type: LiveEventType
  at: string
  entityId: string | null
  version: number
  payload: LiveEventPayload
  activity: ActivityLine | null
}

export interface LiveEventPayload {
  run?: Partial<RunMeta>
  node?: LiveNode
  edge?: LiveEdge
  edgeId?: string
  finding?: LiveFinding
  evidence?: LiveEvidence
  progress?: { stage: string; message: string; target?: string; module?: string; percent?: number }
}

/** Run listing row for scan history. */
export interface RunListItem {
  id: string
  name: string
  status: LiveScanStatus
  createdAt: string
  endedAt: string | null
  targets: string[]
  sessionId: string | null
  findings: number | null
  source: 'live' | 'stored'
}
