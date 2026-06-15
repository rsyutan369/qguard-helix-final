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

export type PQAuthRow = Record<string, unknown>;

export type PQAuthSignal = {
  id: string;
  label: string;
  count: number;
  category: string;
  sourceTables: string[];
  latestAt: string | null;
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

export type PQAuthTrustNode = {
  id: string;
  label: string;
  detail: string;
  x: number;
  y: number;
  color: string;
  icon: string;
  sourceTable: string;
  assetId: string | null;
  correlationId: string;
  latestAt: string | null;
};

export type PQAuthTrustEdge = {
  id: string;
  from: string;
  to: string;
  label: string;
  sourceTable: string;
  correlationId: string;
};

export type PQAuthMigrationPhase = {
  id: string;
  label: string;
  objective: string;
  status: 'complete' | 'active' | 'review' | 'waiting';
  score: number;
  evidence: number;
  sourceTables: string[];
};

export type PQAuthComplianceRow = {
  id: string;
  label: string;
  score: number;
  evidence: string;
  evidenceCount: number;
  sourceTables: string[];
  latestAt: string | null;
};

export type PQAuthCompatibilitySurface = {
  id: string;
  label: string;
  count: number;
  score: number;
  icon: string;
  sourceTables: string[];
  latestAt: string | null;
};

export type PQAuthTokenImpact = {
  id: string;
  current: string;
  currentSize: number;
  target: string;
  pqcSize: number;
  expansion: number;
  risk: string;
  projected: boolean;
  sourceTable: string;
  telemetryId: string | null;
  latestAt: string | null;
};

export type PQAuthDigitalTwinScenario = {
  id: string;
  label: string;
  active: boolean;
  detail: string;
  status: 'active' | 'waiting' | 'review';
  sourceTables: string[];
  evidence: number;
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
};

export type PQAuthSourceHealth = {
  id: string;
  label: string;
  table: string;
  count: number;
  latestAt: string | null;
  status: 'live' | 'stale' | 'waiting';
  percent: number;
};

export type PQAuthFreshness = {
  lastTelemetryReceived: string | null;
  lastScanTimestamp: string | null;
  lastIdentitySync: string | null;
  lastOAuthDiscovery: string | null;
  lastJwtAnalysis: string | null;
  lastRiskCalculation: string | null;
  lastComplianceEvaluation: string | null;
};

export type PQAuthLineage = {
  source: string;
  originService: string;
  generatedAt: string;
  correlationId: string;
  sourceTables: string[];
  telemetryIds: string[];
};

export type PQAuthIntegrity = {
  duplicateRecords: number;
  normalizedRecords: number;
  deterministicTransforms: boolean;
  staleSources: number;
  activeSources: number;
};

export type PQAuthMetrics = {
  identityRiskScore: number;
  readinessScore: number;
  oauthReadiness: number;
  oidcReadiness: number;
  jwtMigrationScore: number;
  trustReadiness: number;
  slhDsaReadiness: number;
  totalAssets: number;
  totalComponents: number;
  totalFindings: number;
  criticalFindings: number;
  vulnerableComponents: number;
  pqcReadyComponents: number;
  tokenImpactBlockers: number;
  compatibilityBlockers: number;
  runtimeSignals: number;
  totalIdentityProviders: number;
  authenticationFlows: number;
  tokenRecords: number;
  trustDependencies: number;
  gatewaySignals: number;
  authServiceSignals: number;
  classicalExposureSignals: number;
  certificateSignals: number;
  qkmsKeySignals: number;
  activeJwtSignatures: number;
  pqcReadySystems: number;
  quantumVulnerableSystems: number;
};

export type PQAuthSnapshot = {
  generatedAt: string | null;
  hasEvidence: boolean;
  mode: string;
  providers: PQAuthSignal[];
  gateways: PQAuthSignal[];
  authServices: PQAuthSignal[];
  flows: PQAuthSignal[];
  algorithms: PQAuthAlgorithmExposure[];
  identityRows: PQAuthRow[];
  exposureRows: PQAuthRow[];
  tokenRows: PQAuthRow[];
  dependencies: PQAuthRow[];
  runtimeEvents: PQAuthRow[];
  trustNodes: PQAuthTrustNode[];
  trustEdges: PQAuthTrustEdge[];
  phases: PQAuthMigrationPhase[];
  complianceRows: PQAuthComplianceRow[];
  compatibilitySurfaces: PQAuthCompatibilitySurface[];
  tokenImpacts: PQAuthTokenImpact[];
  digitalTwinScenarios: PQAuthDigitalTwinScenario[];
  failurePredictions: PQAuthCountRow[];
  rollbackGates: PQAuthCountRow[];
  runtimeMetrics: PQAuthRuntimeMetric[];
  qkmsKeyDomains: PQAuthCountRow[];
  lifecycleControls: PQAuthCountRow[];
  sourceHealth: PQAuthSourceHealth[];
  freshness: PQAuthFreshness;
  lineage: PQAuthLineage;
  integrity: PQAuthIntegrity;
  metrics: PQAuthMetrics;
};

export const EMPTY_PQAUTH_SNAPSHOT: PQAuthSnapshot = {
  generatedAt: null,
  hasEvidence: false,
  mode: 'backend',
  providers: [],
  gateways: [],
  authServices: [],
  flows: [],
  algorithms: [],
  identityRows: [],
  exposureRows: [],
  tokenRows: [],
  dependencies: [],
  runtimeEvents: [],
  trustNodes: [],
  trustEdges: [],
  phases: [],
  complianceRows: [],
  compatibilitySurfaces: [],
  tokenImpacts: [],
  digitalTwinScenarios: [],
  failurePredictions: [],
  rollbackGates: [],
  runtimeMetrics: [],
  qkmsKeyDomains: [],
  lifecycleControls: [],
  sourceHealth: [],
  freshness: {
    lastTelemetryReceived: null,
    lastScanTimestamp: null,
    lastIdentitySync: null,
    lastOAuthDiscovery: null,
    lastJwtAnalysis: null,
    lastRiskCalculation: null,
    lastComplianceEvaluation: null,
  },
  lineage: {
    source: 'api-server/pqauth-dashboard',
    originService: 'PQAuth Identity Migration Engine',
    generatedAt: '',
    correlationId: '',
    sourceTables: [],
    telemetryIds: [],
  },
  integrity: {
    duplicateRecords: 0,
    normalizedRecords: 0,
    deterministicTransforms: true,
    staleSources: 0,
    activeSources: 0,
  },
  metrics: {
    identityRiskScore: 0,
    readinessScore: 0,
    oauthReadiness: 0,
    oidcReadiness: 0,
    jwtMigrationScore: 0,
    trustReadiness: 0,
    slhDsaReadiness: 0,
    totalAssets: 0,
    totalComponents: 0,
    totalFindings: 0,
    criticalFindings: 0,
    vulnerableComponents: 0,
    pqcReadyComponents: 0,
    tokenImpactBlockers: 0,
    compatibilityBlockers: 0,
    runtimeSignals: 0,
    totalIdentityProviders: 0,
    authenticationFlows: 0,
    tokenRecords: 0,
    trustDependencies: 0,
    gatewaySignals: 0,
    authServiceSignals: 0,
    classicalExposureSignals: 0,
    certificateSignals: 0,
    qkmsKeySignals: 0,
    activeJwtSignatures: 0,
    pqcReadySystems: 0,
    quantumVulnerableSystems: 0,
  },
};
