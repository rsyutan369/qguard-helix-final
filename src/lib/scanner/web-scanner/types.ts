/**
 * QGuard Web Scanner — Unified Type Definitions
 * Types for the Quantum Vulnerability Detection Engine
 */

// ─── Target Types ─────────────────────────────────────────────────────────────

import type { PublishedScoreCategory } from './published-scoring'
/* Type-only, so no runtime cycle is created: `edge-intelligence` imports
   `TlsAnalysisResult` back from here, and both sides are erased at compile
   time. The shape lives beside the engine that produces it. */
import type { EdgeIntelligence } from './edge-intelligence'

export type WebScanTargetType = 'url' | 'domain' | 'ip' | 'github'
export type ThreatLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE'

// ─── TLS Analysis ─────────────────────────────────────────────────────────────

export interface TlsAnalysisResult {
  tlsVersion: string
  cipherSuite: string
  keyExchange: string
  signatureAlgorithm: string
  supportedProtocols: string[]
  protocolSupport: TlsProtocolProbe[]
  negotiatedCurve: string | null
  serverName: string
  peerCertificate: CertificateInfo | null
  cipherSuites: CipherSuiteDetail[]
  ephemeralKeyType: string | null
  ephemeralKeySize: number | null
}

export interface TlsProtocolProbe {
  protocol: string
  supported: boolean
  cipherSuite: string | null
  keyExchange: string | null
  error?: string
}

// ─── Certificate Parsing ──────────────────────────────────────────────────────

export interface CertificateInfo {
  subject: Record<string, string>
  issuer: Record<string, string>
  publicKeyAlgorithm: string
  publicKeySize: number
  signatureAlgorithm: string
  signatureOid: string
  validFrom: string
  validTo: string
  serialNumber: string
  fingerprint: string
  isExpired: boolean
  isSelfSigned: boolean
  chain: CertificateChainEntry[]
  detectedOids: OidClassification[]
}

export interface CertificateChainEntry {
  subject: string
  issuer: string
  signatureAlgorithm: string
  publicKeyAlgorithm: string
  publicKeySize: number
  validTo: string
  isExpired: boolean
}

// ─── OID Classification ──────────────────────────────────────────────────────

export type OidCategory =
  | 'rsa'
  | 'ecc'
  | 'dh'
  | 'dsa'
  | 'hash'
  | 'pqc'
  | 'symmetric'
  | 'legacy'
  | 'ca-identifier'
  | 'extension'

export type QuantumThreat = 'shor' | 'grover' | 'both' | 'classical-broken' | 'safe'

export interface OidClassification {
  oid: string
  name: string
  category: OidCategory
  quantumVulnerable: boolean
  quantumThreat: QuantumThreat
  pqcReplacement: string | null
  description: string
}

// ─── Cipher Suite Analysis ────────────────────────────────────────────────────

export type CipherSuiteCategory =
  | 'rsa-kex'
  | 'ecdhe-rsa'
  | 'ecdhe-ecdsa'
  | 'dhe-rsa'
  | 'dhe-dss'
  | 'tls13'
  | 'other'

export interface CipherSuiteDetail {
  name: string
  standardName: string
  category: CipherSuiteCategory
  keyExchange: string
  authentication: string
  encryption: string
  mac: string
  quantumVulnerable: boolean
  riskLevel: ThreatLevel
  description: string
}

// ─── GitHub Repo Scanning ─────────────────────────────────────────────────────

export interface GitRepoScanResult {
  repoUrl: string
  repoName: string
  filesScanned: number
  totalFiles: number
  patterns: GitCryptoMatch[]
  /** false when the repo tree could not be read (private / not found / rate-limited / empty). Not a hard failure. */
  accessible?: boolean
  /** Human-readable reason when a non-fatal access limitation occurred. */
  notice?: string
  /** Actionable next step for the user (e.g. supply a token). */
  recommendation?: string
  /** Repository visibility once resolved. */
  visibility?: 'public' | 'private' | 'unknown'
  /** Resolved default branch used for the tree read. */
  defaultBranch?: string
}

export interface GitCryptoMatch {
  file: string
  line: number
  pattern: string
  category: string
  algorithm: string
  snippet: string
  threatLevel: ThreatLevel
  description: string
}

// ─── Web Crypto Scanning ──────────────────────────────────────────────────────

export interface WebCryptoScanResult {
  url: string
  pagesScanned: number
  scriptsAnalyzed: number
  patterns: WebCryptoMatch[]
}

export interface WebCryptoMatch {
  source: string
  line: number
  pattern: string
  category: string
  algorithm: string
  snippet: string
  threatLevel: ThreatLevel
  description: string
}

// ─── API Security Scanning ────────────────────────────────────────────────────

export interface ApiSecurityResult {
  hostname: string
  endpointsProbed: number
  securityHeaders: SecurityHeader[]
  apiFindings: ApiSecurityFinding[]
}

export interface SecurityHeader {
  name: string
  value: string | null
  present: boolean
  secure: boolean
  required?: boolean
  recommendation: string
}

export interface ApiSecurityFinding {
  endpoint: string
  findingType: string
  algorithm: string
  threatLevel: ThreatLevel
  description: string
  recommendation: string
}

// ─── Detection Rules ──────────────────────────────────────────────────────────

export type DetectionRuleCategory =
  | 'certificate-risk'
  | 'tls-config'
  | 'hashing'
  | 'app-crypto'
  | 'pqc-readiness'
  | 'long-term-quantum-risk'

export interface DetectionRule {
  id: string
  name: string
  category: DetectionRuleCategory
  severity: ThreatLevel
  description: string
  remediation: string
  evaluate: (context: DetectionContext) => DetectionRuleResult | null
}

export interface DetectionContext {
  findings: WebScanFinding[]
  tlsResult: TlsAnalysisResult | null
  certInfo: CertificateInfo | null
  apiResult: ApiSecurityResult | null
  repoResult: GitRepoScanResult | null
  webCryptoResult: WebCryptoScanResult | null
  /**
   * Measured public-edge evidence, when the target has a public edge.
   *
   * The post-quantum rules previously tested `tlsResult.cipherSuite.includes
   * ('Kyber')`. That can never be true: TLS 1.3 suite names carry no
   * key-exchange token (`TLS_AES_256_GCM_SHA384`) and Node does not expose the
   * negotiated group, so PQC-001/002/003 fired on every endpoint on Earth —
   * including the ones that genuinely negotiate X25519MLKEM768. Rules that
   * assert something about post-quantum support must read the named-group
   * measurement, and must return null when it is absent rather than guess.
   */
  edgeIntelligence?: EdgeIntelligence | null
}

export interface DetectionRuleResult {
  ruleId: string
  ruleName: string
  category: DetectionRuleCategory
  severity: ThreatLevel
  triggered: boolean
  details: string
  remediation: string
}

// ─── PQC Recommendations ─────────────────────────────────────────────────────

export interface PQCMigrationDetail {
  currentAlgorithm: string
  recommendedPQC: string
  alternativePQC: string[]
  migrationType: string
  migrationComplexity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  migrationSteps: string[]
  nistStandard: string
  estimatedEffort: string
}

// ─── Risk Scoring ─────────────────────────────────────────────────────────────

export interface WebScanRiskBreakdown {
  certificateRisk: number
  tlsConfigRisk: number
  cipherSuiteRisk: number
  appCryptoRisk: number
  pqcReadiness: number
}

/**
 * Which risk dimensions were actually measured.
 *
 * `WebScanRiskBreakdown` always carries five numbers so the persisted shape
 * never changes, but a dimension the scan could not observe is excluded from
 * the weighted score entirely — this map is how consumers tell a measurement
 * (`true`) from a filler zero (`false`). Rendering an inapplicable dimension as
 * a posture of 100 is exactly the misreading this exists to prevent.
 */
export interface WebScanRiskApplicability {
  certificateRisk: boolean
  tlsConfigRisk: boolean
  cipherSuiteRisk: boolean
  appCryptoRisk: boolean
  pqcReadiness: boolean
}

export interface WebScanRiskScore {
  overallScore: number
  riskLevel: ThreatLevel
  quantumReadinessScore: number
  quantumReadinessLevel: QuantumReadinessLevel
  legacyQScore: number
  breakdown: WebScanRiskBreakdown
  breakdownApplicable: WebScanRiskApplicability
  /**
   * The platform's published twelve-category model, which `overallScore` is the
   * weighted mean of. This is the decomposition users are shown, and the reason
   * this surface and /public-scan grade the same host the same way.
   */
  scoreCategories: PublishedScoreCategory[]
  /** Sum of the published-category weights that contributed, out of 100. */
  measuredWeight: number
}

export type QuantumReadinessLevel =
  | 'quantum-safe'
  | 'moderate-risk'
  | 'vulnerable'
  | 'critical-risk'

// ─── Unified Finding ──────────────────────────────────────────────────────────

export interface WebScanFinding {
  id: string
  phase: string
  algorithm: string
  location: string
  threatLevel: ThreatLevel
  category: string
  description: string
  recommendation: string
  quantumBreakTime: string
  classicalBreakTime: string
  oid?: string
  cipherSuiteDetail?: CipherSuiteDetail
  repoFilePath?: string
  lineNumber?: number
  pqcRecommendation?: PQCMigrationDetail
}

// ─── Complete Scan Result ─────────────────────────────────────────────────────

export interface WebScanCompleteResult {
  scanId: string
  target: string
  targetType: WebScanTargetType
  scanDuration: number
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  safeCount: number
  overallRiskScore: number
  riskLevel: ThreatLevel
  quantumReadinessScore: number
  quantumReadinessLevel: QuantumReadinessLevel
  legacyQScore: number
  findings: WebScanFinding[]
  tlsAnalysis: TlsAnalysisResult | null
  certificateInfo: CertificateInfo | null
  cipherSuiteBreakdown: CipherSuiteDetail[]
  repoScanResult: GitRepoScanResult | null
  webCryptoResult: WebCryptoScanResult | null
  apiSecurityResult: ApiSecurityResult | null
  pqcRecommendations: PQCMigrationDetail[]
  riskBreakdown: WebScanRiskBreakdown
  /** Which entries of `riskBreakdown` are measurements rather than filler. */
  riskBreakdownApplicable?: WebScanRiskApplicability
  /** The published twelve-category decomposition behind the overall score. */
  scoreCategories?: PublishedScoreCategory[]
  /** Sum of the published-category weights that contributed, out of 100. */
  riskMeasuredWeight?: number
  detectionRuleResults: DetectionRuleResult[]
  runtimeHealth?: unknown
  scanConfidence?: { confidence: number; label: string; factors: string[] }
  /**
   * The public-edge evidence bundle: post-quantum named-group probing, ALPN,
   * OCSP stapling, Certificate Transparency, CAA, DNSSEC, transport-security
   * headers and edge attribution.
   *
   * Absent for target types with no public edge (a repository URL), and absent
   * on scans persisted before this engine existed — consumers must treat
   * `undefined` as "not measured", never as a negative verdict.
   */
  edgeIntelligence?: EdgeIntelligence | null
}

// ─── SSE Event Types ──────────────────────────────────────────────────────────

export type SSEEventType =
  | 'scan-start'
  | 'engine-status'
  | 'phase-start'
  | 'phase-complete'
  | 'module-start'
  | 'module-complete'
  | 'scan-metrics'
  | 'finding'
  | 'scan-complete'
  | 'error'

export interface SSEEvent {
  type: SSEEventType
  scanId: string
  timestamp: string
  [key: string]: unknown
}

// ─── Crypto Pattern (for regex scanning) ──────────────────────────────────────

export interface CryptoPattern {
  id: number
  regex: RegExp
  label: string
  category: string
  algorithm: string
  threatLevel: ThreatLevel
  languages: string[]
  description: string
}
