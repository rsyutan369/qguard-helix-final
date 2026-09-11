/**
 * Dashboard Scanner — shared domain types.
 *
 * Extracted from ScannerDashboard so the intelligence derivations (`_intel.ts`),
 * the visualization bridge (`_hero.tsx`) and the result sections (`_sections.tsx`)
 * all speak the same vocabulary instead of re-declaring it. These mirror the
 * payloads emitted by `/api/v1/scanner/stream` and persisted by
 * `/api/v1/scanner/history` — nothing here is invented client-side.
 */

/* The public-edge evidence shape is IMPORTED, not mirrored.
   Every other evidence type in this file is a hand-maintained copy of a backend
   shape, and that is exactly how they drift. `edge-intelligence-model` is the
   isomorphic half of the engine — pure types and pure derivations, no sockets —
   so the browser gets the real contract instead of a copy of it. */
import type { EdgeIntelligence } from '@/lib/scanner/web-scanner/edge-intelligence-model';

export type { EdgeIntelligence };

export type ScanStatus = 'idle' | 'queued' | 'running' | 'analyzing' | 'completed' | 'failed' | 'cancelled';

export type TabId = 'setup' | 'overview' | 'findings' | 'logs' | 'history' | 'agents' | 'settings';

export type ThreatLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';

export type DefensiveFinding = {
  id: string;
  algorithm: string;
  category: string;
  location: string;
  threatLevel: ThreatLevel;
  status: string;
  description: string;
  recommendation: string;
  pqcReplacement: string | null;
  keySize: number | null;
  evidence: string;
  detectionMethod: string;
  source: string;
};

export type ScanSummary = {
  targetsScanned: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  safe: number;
  vulnerable: number;
  pqcReady: number;
  /** Exposure score, 0-100, higher is worse. */
  riskScore: number;
  /** Posture score, 0-100, higher is better. Backend computes `100 - riskScore`. */
  qScore: number;
};

export type LogEntry = {
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS';
  message: string;
  phase?: string;
  severity?: ThreatLevel;
  elapsed?: string;
  moduleName?: string;
};

export type ModuleStatus = 'Queued' | 'Running' | 'Completed' | 'Failed' | 'Skipped' | 'No findings';

export type ModuleState = {
  id: string;
  name: string;
  status: ModuleStatus;
  target?: string;
  startedAt: string | null;
  completedAt: string | null;
  durationMs: number | null;
  findingsCount: number;
  severityCounts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
  };
  error: string | null;
  /**
   * Why a module ended in a non-measuring state, verbatim from the backend.
   *
   * The scanner's module ledger never publishes a `Skipped` without one, so the
   * UI can always answer "skipped because of what?". Optional only because
   * scans persisted before the ledger existed have no reason recorded.
   */
  reason?: string | null;
  /** True when `Skipped` means "does not apply here", not "was not reached". */
  notApplicable?: boolean;
};

/**
 * The execution ledger the scanner publishes with every terminal frame. It is
 * the authoritative answer to "did every module report?", and the reason the
 * dashboard no longer has to infer a module's fate from its absence.
 */
export type ModuleLedger = {
  total: number;
  measured: number;
  failed: number;
  notApplicable: number;
  unresolved: number;
  findings: number;
};

/**
 * The published weighted risk decomposition the web-scanner returns per target.
 * Every member is an EXPOSURE value (0-100, higher is worse) — including
 * `pqcReadiness`, which measures how far the target is from being PQ-ready.
 * Posture is `100 - risk`; see WEIGHTS in lib/scanner/web-scanner/risk-scoring.
 */
export type ScanRiskBreakdown = {
  certificateRisk: number;
  tlsConfigRisk: number;
  cipherSuiteRisk: number;
  appCryptoRisk: number;
  pqcReadiness: number;
};

/**
 * Which entries of `ScanRiskBreakdown` are measurements. A `false` entry means
 * the dimension was excluded from the weighted score and must render as "not
 * measured", never as a posture of 100.
 */
export type ScanRiskApplicability = {
  certificateRisk: boolean;
  tlsConfigRisk: boolean;
  cipherSuiteRisk: boolean;
  appCryptoRisk: boolean;
  pqcReadiness: boolean;
};

/**
 * One category of the platform's published twelve-category scoring model, as
 * returned per target by the scanner. This is the SAME model /public-scan grades
 * against — same keys, same weights, same grade table.
 */
export type PublishedScoreCategory = {
  key: string;
  label: string;
  weight: number;
  score: number;
  applicable: boolean;
  observed: string;
};

export type ScanConfidence = {
  confidence: number;
  label: string;
  factors: string[];
};

/* --- Evidence shapes, mirroring lib/scanner/web-scanner/types.ts ----------- */

export type TlsProtocolProbe = {
  protocol: string;
  supported: boolean;
  cipherSuite: string | null;
  keyExchange: string | null;
  error?: string;
};

export type CipherSuiteDetail = {
  name: string;
  standardName?: string;
  category?: string;
  keyExchange?: string;
  authentication?: string;
  encryption?: string;
  quantumVulnerable?: boolean;
  riskLevel?: ThreatLevel;
};

export type TlsAnalysis = {
  tlsVersion: string;
  cipherSuite: string;
  keyExchange: string;
  signatureAlgorithm: string;
  supportedProtocols: string[];
  protocolSupport?: TlsProtocolProbe[];
  negotiatedCurve: string | null;
  serverName?: string;
  cipherSuites?: CipherSuiteDetail[];
  ephemeralKeyType?: string | null;
  ephemeralKeySize?: number | null;
};

export type CertificateChainEntry = {
  subject: string;
  issuer: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeySize: number;
  validTo: string;
  isExpired: boolean;
};

export type CertificateInfo = {
  subject?: Record<string, string>;
  issuer?: Record<string, string>;
  publicKeyAlgorithm: string;
  publicKeySize: number;
  signatureAlgorithm: string;
  validFrom: string;
  validTo: string;
  serialNumber?: string;
  isExpired: boolean;
  isSelfSigned: boolean;
  chain?: CertificateChainEntry[];
};

export type SecurityHeader = {
  name: string;
  value: string | null;
  present: boolean;
  secure: boolean;
  recommendation?: string;
};

export type ApiSecurityResult = {
  hostname?: string;
  endpointsProbed?: number;
  securityHeaders?: SecurityHeader[];
  apiFindings?: unknown[];
};

export type GitRepoScanResult = {
  repoUrl?: string;
  repoName?: string;
  filesScanned?: number;
  totalFiles?: number;
  patterns?: Array<{ algorithm?: string; threatLevel?: ThreatLevel; file?: string }>;
  accessible?: boolean;
  notice?: string;
  visibility?: string;
  defaultBranch?: string;
};

export type WebCryptoScanResult = {
  url?: string;
  pagesScanned?: number;
  scriptsAnalyzed?: number;
  patterns?: Array<{ algorithm?: string; category?: string; threatLevel?: ThreatLevel }>;
};

/** One target's completed result, as emitted on `scan-complete`. */
export type ScanResultRecord = {
  scanId?: string;
  target?: string;
  targetType?: string;
  startedAt?: string;
  completedAt?: string;
  durationMs?: number | null;
  status?: string;
  riskScore?: number;
  qScore?: number;
  riskLevel?: ThreatLevel;
  findings?: DefensiveFinding[];
  certificateInfo?: CertificateInfo | null;
  tlsVersion?: string | null;
  metadata?: {
    targetType?: string;
    tlsAnalysis?: TlsAnalysis | null;
    cipherSuiteBreakdown?: Record<string, unknown> | null;
    repoScanResult?: GitRepoScanResult | null;
    webCryptoResult?: WebCryptoScanResult | null;
    apiSecurityResult?: ApiSecurityResult | null;
    pqcRecommendations?: unknown[];
    riskBreakdown?: ScanRiskBreakdown | null;
    riskBreakdownApplicable?: ScanRiskApplicability | null;
    scoreCategories?: PublishedScoreCategory[] | null;
    riskMeasuredWeight?: number;
    detectionRuleResults?: unknown[];
    runtimeHealth?: unknown;
    scanConfidence?: ScanConfidence | null;
    /**
     * Measured public-edge surface. Absent on repository targets (no public
     * edge) and on scans persisted before this engine existed — consumers MUST
     * treat `undefined` as "not measured", never as a negative verdict.
     */
    edgeIntelligence?: EdgeIntelligence | null;
  } | null;
};

/** PQC migration guidance, verbatim from the scanner_2 migration engine. */
export type PqcRecommendation = {
  classicalAlgorithm: string;
  recommendedPQC: string;
  alternativePQC: string[];
  migrationType: string;
  migrationComplexity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  migrationSteps: string[];
  nistStandard: string;
  estimatedEffort: string;
};

export type HndlRisk = {
  id: string;
  targetName: string;
  algorithm: string;
  dataType: string;
  exposurePeriod: string;
  riskExplanation: string;
  mitigationAction: string;
  urgencyLevel: 'immediate' | 'soon' | 'planned';
  estimatedQDayImpact: string;
};

/** The Scanner_2 enterprise pass, as emitted on `scan-complete`. */
export type EnterpriseScanner2 = {
  observedFindings?: unknown[];
  enrichedFindings?: Array<{ id?: string; fingerprintId?: string | null; detectedAlgorithm?: string; severity?: string }>;
  ruleResults?: Array<{ ruleId?: string; ruleName?: string; severity?: string; category?: string }>;
  hndlRisks?: HndlRisk[];
  attackAssessment?: {
    riskScore: number;
    classification: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    detectedAssets: Record<string, number>;
    estimatedBreakWindow: { earliest: number; latest: number };
    attackCorrelations: Array<{ id: string; source: string; sourceType: string; finding: string; chain: string; riskLevel: string }>;
  } | null;
  quantumRiskScore?: {
    overall: number;
    level: string;
    criticalCount: number;
    highCount: number;
    moderateCount: number;
    lowCount: number;
    totalFindings: number;
    hndlRiskCount: number;
    /** Categories actually observed. Absent on records written before the
     *  aggregate stopped scoring unobserved categories at a passing 850. */
    measuredCategories?: string[];
    /** Share of the model's weight that was measured, 0-1. */
    measuredWeight?: number;
  } | null;
  quantumReadiness?: {
    score: number;
    label: string;
    color: string;
    assetsRequiringMigration: Record<string, number>;
    /* Two populations, named. `totalAssets` was previously filled with the
       FINDING count, which the Quantum Posture card printed as
       "N of M inventoried asset(s)" on single-asset tenants. Both counts are
       now returned and both are optional here so historical records still
       render. */
    totalAssets: number;
    quantumSafeAssets: number;
    totalFindings?: number;
    quantumSafeFindings?: number;
    notAssessed?: boolean;
  } | null;
  migrationRecommendations?: PqcRecommendation[];
};

export type HistoryEntry = {
  scanId: string;
  userId: string;
  target: string;
  scanType: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  status: string;
  detectedComponents: number;
  vulnerableFindings: number;
  pqcReadyFindings: number;
  riskScore: number | null;
  qScore: number | null;
  telemetry: any[];
  moduleStates?: ModuleState[];
  moduleLedger?: ModuleLedger | null;
  scannerModulesUsed?: string[];
  summary?: ScanSummary | null;
  findings?: DefensiveFinding[];
  recommendations?: string[];
  enterpriseScanner2?: EnterpriseScanner2 | null;
  results?: ScanResultRecord[];
  errorLogs: string[];
  linkedCbomRecords: string[];
  linkedAssetRecords: string[];
  linkedExposureNodes: string[];
};

export type ScheduledScan = {
  id: string;
  scheduledFor: string;
  createdAt: string;
  status: 'scheduled';
  targets: string[];
};

export type HistoryTimeframe = 'last7' | 'all';
