export type PQAuthMode =
  | 'overview'
  | 'discovery'
  | 'trust-graph'
  | 'token-intelligence'
  | 'exposure-analysis'
  | 'compatibility'
  | 'digital-twin'
  | 'migration-center'
  | 'runtime-telemetry'
  | 'compliance'
  | 'qkms';

/**
 * A row as it leaves the server. Built by an explicit allow-list projection —
 * raw database rows are never spread into the payload, because several source
 * tables carry session-token hashes, agent token hashes, IP addresses and user
 * agents that must never reach the browser or the JSON export.
 */
export type PQAuthRow = {
  id: string;
  sourceTable: string;
  name: string;
  type: string | null;
  status: string | null;
  severity: string | null;
  algorithm: string | null;
  assetId: string | null;
  detail: string | null;
  lastUpdated: string | null;
};

export type PQAuthAlgorithmExposure = {
  id: string;
  label: string;
  count: number;
  family: string;
  replacement: string;
  risk: string;
  sourceTables: string[];
  latestAt: string | null;
};

export type PQAuthComplianceRow = {
  id: string;
  label: string;
  score: number;
  evidence: string;
  evidenceCount: number;
  sourceTables: string[];
  latestAt: string | null;
  /**
   * True only when evidence matching THIS framework was found. When false the
   * framework has not been assessed and the score carries no meaning — the UI
   * must render "Not Assessed" rather than a percentage. Evidence belonging to
   * another framework is never borrowed to stand in for this one.
   */
  assessed: boolean;
};

export type PQAuthCountRow = {
  id: string;
  label: string;
  count: number;
  detail: string;
  status?: string;
  sourceTables?: string[];
};

export type PQAuthRuntimeMetric = {
  id: string;
  label: string;
  value: number;
  detail: string;
  /**
   * True only when the value was measured from runtime telemetry. Inventory
   * counts are never substituted for runtime observations, so when no runtime
   * evidence exists the UI shows "Awaiting telemetry" instead of a zero that
   * would read as "no failures".
   */
  measured: boolean;
};

/**
 * Per-source read result. `unavailable` means the query FAILED — its zeros are
 * not measurements — which is different from `empty` (read, no rows).
 */
export type PQAuthSourceHealth = {
  id: string;
  label: string;
  table: string;
  count: number;
  latestAt: string | null;
  state: 'ok' | 'empty' | 'unavailable' | 'truncated';
};

/* ================================================================== */
/* Identity model — built ONLY from structured identity evidence       */
/* (identity_providers, identity_signing_keys,                         */
/*  identity_trust_relationships, identity_discovery_probes) plus the  */
/* tenant's own assets, certificates, migration jobs and runtime       */
/* events. See src/lib/pqauth/identity-model.ts.                        */
/* ================================================================== */

export type IdentityQuantumClass = 'safe' | 'hybrid' | 'vulnerable' | 'unknown';

/** How old a piece of discovery evidence is. `stale` = older than 7 days. */
export type EvidenceAge = 'fresh' | 'stale' | 'never';

export type PQAuthEndpoint = { kind: string; url: string; insecureTransport: boolean };

export type PQAuthProvider = {
  id: string;
  issuer: string;
  protocol: string;
  displayName: string;
  /** Named only when the issuer host proves the vendor; null otherwise. */
  vendor: string | null;
  host: string | null;
  /** The tenant asset this provider was discovered from. */
  assetId: string | null;
  assetName: string | null;
  quantumClass: IdentityQuantumClass;
  signingAlgorithmsSupported: string[];
  keyEncryptionAlgorithmsSupported: string[];
  contentEncryptionAlgorithmsSupported: string[];
  grantTypesSupported: string[];
  endpoints: PQAuthEndpoint[];
  jwksUri: string | null;
  keyCount: number;
  /** Keys present in the most recent JWKS read. */
  publishedKeyCount: number;
  vulnerableKeyCount: number;
  sourceUrl: string | null;
  discoveryMethod: string | null;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  age: EvidenceAge;
  /** Tenant assets that declare trust in this provider. */
  dependentAssetIds: string[];
};

export type PQAuthSigningKey = {
  id: string;
  providerId: string;
  providerLabel: string;
  /** JWKS `kid` (public metadata), shortened for display. */
  keyId: string;
  keyType: string;
  /** JWK `alg` as published; null when the JWKS did not state one. */
  algorithm: string | null;
  /** `algorithm`, or the key-type-derived label when no `alg` was stated. */
  displayAlgorithm: string;
  use: string;
  keySize: number | null;
  curve: string | null;
  quantumClass: IdentityQuantumClass;
  purpose: string;
  pqcTarget: string | null;
  standard: string | null;
  rationale: string | null;
  sourceUrl: string | null;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  /** `no-longer-published`: absent from the provider's most recent JWKS read (rotated out). */
  lifecycle: 'published' | 'no-longer-published';
  /** Raw signature size of THIS primitive, when it is a signing key of known size. */
  signatureBytes: number | null;
};

export type PQAuthProbeOutcome = 'found' | 'not-found' | 'unparseable' | 'error';

export type PQAuthProbeRecord = {
  id: string;
  url: string;
  method: string;
  httpStatus: number | null;
  outcome: PQAuthProbeOutcome;
  detail: string | null;
  observedAt: string | null;
};

/**
 * Discovery result for one host, from its most recent probe run.
 *  identity-found  at least one well-known document parsed into a provider
 *  no-identity     every probe answered and none served identity metadata (proof of absence)
 *  incomplete      a document answered but could not be parsed, or some probes failed
 *  failed          no probe reached the host (timeouts / network errors)
 */
export type PQAuthHostResult = 'identity-found' | 'no-identity' | 'incomplete' | 'failed';

export type PQAuthDiscoveryHost = {
  host: string;
  assetId: string | null;
  assetName: string | null;
  runId: string | null;
  lastProbedAt: string | null;
  result: PQAuthHostResult;
  explanation: string;
  probes: PQAuthProbeRecord[];
  providerIds: string[];
};

export type PQAuthDiscoveryRun = {
  runId: string;
  startedAt: string | null;
  finishedAt: string | null;
  hosts: number;
  probes: number;
  found: number;
  notFound: number;
  unparseable: number;
  errors: number;
};

export type PQAuthScopeAsset = {
  assetId: string;
  name: string;
  type: string | null;
  host: string | null;
  eligible: boolean;
  /** Why the asset can or cannot be probed. */
  reason: string;
  lastProbedAt: string | null;
};

/** An identity discovery run that is genuinely executing on the server right now. */
export type PQAuthActiveRun = {
  runId: string;
  status: 'running' | 'completed' | 'failed';
  startedAt: string;
  finishedAt: string | null;
  hostsTotal: number;
  hostsDone: number;
  currentHost: string | null;
  providersFound: number;
  error: string | null;
};

export type PQAuthStageStatus = 'complete' | 'attention' | 'pending' | 'not-started';

export type PQAuthDiscoveryStage = {
  id: string;
  label: string;
  description: string;
  count: number;
  status: PQAuthStageStatus;
};

export type PQAuthDiscoveryModel = {
  scope: PQAuthScopeAsset[];
  runs: PQAuthDiscoveryRun[];
  hosts: PQAuthDiscoveryHost[];
  activeRun: PQAuthActiveRun | null;
  lastRunAt: string | null;
  stages: PQAuthDiscoveryStage[];
};

export type PQAuthGraphNodeKind = 'asset' | 'provider' | 'key' | 'certificate';

export type PQAuthGraphNode = {
  id: string;
  kind: PQAuthGraphNodeKind;
  label: string;
  sublabel: string;
  status: IdentityQuantumClass;
  /** Id in the node's own source table. */
  refId: string;
  assetId: string | null;
  sourceTable: string;
  sourceUrl: string | null;
  lastSeenAt: string | null;
};

/**
 * observed   read directly from a protocol document or a foreign key
 * declared   a document published by one party names the other
 * inferred   recorded by a source that marked it inferred
 * unresolved a recorded relationship whose endpoint is not in the inventory
 */
export type PQAuthEdgeConfidence = 'observed' | 'declared' | 'inferred' | 'unresolved';

export type PQAuthGraphEdge = {
  id: string;
  from: string;
  to: string;
  type: string;
  label: string;
  confidence: PQAuthEdgeConfidence;
  evidence: string;
  sourceTable: string;
  sourceUrl: string | null;
  lastSeenAt: string | null;
};

export type PQAuthTrustGraph = {
  nodes: PQAuthGraphNode[];
  edges: PQAuthGraphEdge[];
};

export type PQAuthAdvertisedAlgorithm = {
  providerId: string;
  providerLabel: string;
  algorithm: string;
  /** signing | key-management | content-encryption */
  role: string;
  quantumClass: IdentityQuantumClass;
  pqcTarget: string | null;
};

export type PQAuthTokenProjection = {
  keyRef: string;
  providerLabel: string;
  currentAlgorithm: string;
  currentSignatureBytes: number;
  targetAlgorithm: string;
  targetSignatureBytes: number;
  /** Growth of the base64url signature segment of a compact JWS, in bytes. */
  encodedDeltaBytes: number;
  expansion: number;
};

export type PQAuthTokenModel = {
  keys: PQAuthSigningKey[];
  advertised: PQAuthAdvertisedAlgorithm[];
  conflicts: Array<{ providerId: string; providerLabel: string; detail: string }>;
  runtime: {
    measured: boolean;
    operations: number;
    byAlgorithm: Array<{ algorithm: string; count: number; quantumClass: IdentityQuantumClass }>;
    latestAt: string | null;
  };
  projections: PQAuthTokenProjection[];
};

export type PQAuthCompatStatus = 'supported' | 'conditional' | 'unsupported' | 'not-verified' | 'not-applicable';

export type PQAuthCompatCell = { status: PQAuthCompatStatus; summary: string };

export type PQAuthCompatIssue = {
  id: string;
  providerId: string;
  dimension: string;
  status: PQAuthCompatStatus;
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** 1. What component is affected. */
  component: string;
  /** 2. What the compatibility issue is. */
  issue: string;
  /** 3. Why it matters. */
  why: string;
  /** 4. What dependency or limitation causes it. */
  cause: string;
  /** 5. What supported remediation or migration option is available. */
  remediation: string;
  evidence: string;
  sourceUrl: string | null;
};

export type PQAuthCompatibilityModel = {
  dimensions: Array<{ id: string; label: string; description: string }>;
  rows: Array<{ providerId: string; providerLabel: string; protocol: string; cells: Record<string, PQAuthCompatCell> }>;
  issues: PQAuthCompatIssue[];
  counts: Record<PQAuthCompatStatus, number>;
};

/**
 * proposed   planned, not yet approved for execution
 * queued     approved and waiting for the executor
 * executing  the executor reports it running
 * completed  the executor reports it finished — NOT yet proven
 * validated  completed AND a later discovery observed the target posture
 * failed     failed, cancelled, blocked or rolled back
 */
export type PQAuthJobState = 'proposed' | 'queued' | 'executing' | 'completed' | 'validated' | 'failed';

export type PQAuthMigrationJob = {
  id: string;
  name: string;
  jobType: string | null;
  assetId: string | null;
  assetName: string | null;
  rawStatus: string;
  state: PQAuthJobState;
  /** Sandbox / dry-run job: never a production change. */
  simulation: boolean;
  sourceAlgorithm: string | null;
  targetAlgorithm: string | null;
  progress: number | null;
  startedAt: string | null;
  completedAt: string | null;
  updatedAt: string | null;
  validation: { status: 'validated' | 'awaiting-rediscovery' | 'regressed' | 'not-applicable'; detail: string };
  /** Signature workloads must target ML-DSA/SLH-DSA, key establishment ML-KEM. */
  roleCheck: { ok: boolean | null; detail: string };
  rollback: { available: boolean | null; detail: string };
};

export type PQAuthGateStatus = 'complete' | 'in-progress' | 'blocked' | 'not-started';

export type PQAuthMigrationGate = {
  id: string;
  label: string;
  description: string;
  status: PQAuthGateStatus;
  evidence: string;
  href: string | null;
};

export type PQAuthMigrationModel = {
  identityAssetIds: string[];
  jobs: PQAuthMigrationJob[];
  /** All tenant migration jobs, identity-scoped or not. */
  tenantJobCount: number;
  counts: Record<PQAuthJobState, number>;
  gates: PQAuthMigrationGate[];
};

export type PQAuthTwinImpact = {
  providerId: string;
  providerLabel: string;
  keysAffected: number;
  currentEncodedBytes: number;
  projectedEncodedBytes: number;
  deltaBytes: number;
  jwksDeltaBytes: number;
  dependents: number;
};

export type PQAuthTwinScenario = {
  id: string;
  label: string;
  description: string;
  standard: string;
  applicable: boolean;
  reason: string;
  impacts: PQAuthTwinImpact[];
  totals: { providers: number; keys: number; maxDeltaBytes: number; dependents: number };
  /** The exact model inputs the projection used — every number is traceable. */
  inputs: string[];
};

export type PQAuthTwinModel = {
  sync: {
    status: 'in-sync' | 'partial' | 'stale' | 'drift' | 'never-synced';
    lastSyncAt: string | null;
    detail: string;
  };
  entities: Array<{
    providerId: string;
    label: string;
    quantumClass: IdentityQuantumClass;
    age: EvidenceAge;
    assetId: string | null;
    keys: number;
    vulnerableKeys: number;
    dependents: number;
    conflicts: string[];
  }>;
  conflicts: Array<{ providerId: string; kind: string; detail: string }>;
  scenarios: PQAuthTwinScenario[];
};

export type PQAuthNextAction = {
  id: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  detail: string;
  href: string;
};

export type PQAuthIdentityModel = {
  providers: PQAuthProvider[];
  discovery: PQAuthDiscoveryModel;
  graph: PQAuthTrustGraph;
  tokens: PQAuthTokenModel;
  compatibility: PQAuthCompatibilityModel;
  migration: PQAuthMigrationModel;
  twin: PQAuthTwinModel;
  readiness: {
    safeKeys: number;
    hybridKeys: number;
    vulnerableKeys: number;
    unknownKeys: number;
    /** (safe + hybrid) / classified keys, 0–100; null when no key has been classified. */
    coverage: number | null;
  };
  nextActions: PQAuthNextAction[];
};

export type PQAuthMetrics = {
  totalAssets: number;
  totalComponents: number;
  totalFindings: number;
  criticalFindings: number;
  vulnerableComponents: number;
  pqcReadyComponents: number;
  classicalExposureSignals: number;
  certificateSignals: number;
  qkmsKeySignals: number;
};

export type PQAuthSnapshot = {
  generatedAt: string | null;
  mode: string;
  /** True when the tenant has any evidence at all in the sources PQAuth reads. */
  hasEvidence: boolean;
  identity: PQAuthIdentityModel;
  /** Estate-wide classical algorithm signals (Exposure Analysis). */
  algorithms: PQAuthAlgorithmExposure[];
  exposureRows: PQAuthRow[];
  runtimeEvents: PQAuthRow[];
  runtimeMetrics: PQAuthRuntimeMetric[];
  complianceRows: PQAuthComplianceRow[];
  qkmsKeyDomains: PQAuthCountRow[];
  lifecycleControls: PQAuthCountRow[];
  sourceHealth: PQAuthSourceHealth[];
  metrics: PQAuthMetrics;
};
