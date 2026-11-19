/**
 * Canonical data-protection intelligence model — Encryption Monitoring.
 *
 * The TLS/PKI suite owns TRANSPORT: protocol versions, cipher-suite
 * negotiation, key agreement and certificates. This module owns what protects
 * DATA: symmetric ciphers, hashes and MACs, key-derivation functions, key
 * material, data-at-rest policy, vault protection and the crypto operations an
 * agent actually observed.
 *
 * The split is not cosmetic. Before this refactor both pages classified rows
 * with a substring test that matched nearly every cryptographic record in the
 * tenant, so Encryption Monitoring was a relabelled second copy of the TLS
 * pages — with a second, contradictory set of numbers (70% PQC-ready against
 * the Quantum Readiness Engine's 33%, 23 "encrypted assets" on a 2-asset
 * estate, 338 key rotations with zero keys).
 *
 * ── The quantum model here is GROVER, not Shor ─────────────────────────────
 * RSA and ECC are BROKEN by Shor: a CRQC recovers the private key outright.
 * Symmetric and hash primitives are only WEAKENED by Grover, which delivers a
 * quadratic speedup and so halves the effective security level. AES-256 keeps
 * ~128 bits and is CNSA 2.0 approved; AES-128 drops to ~64 bits and is
 * weakened, not broken. Publishing AES-256-GCM as "quantum vulnerable" is a
 * documented past defect of this platform, and `strengthOf()` exists to make
 * repeating it impossible.
 */

/* ------------------------------------------------------------------ */
/* Shared vocabulary                                                   */
/* ------------------------------------------------------------------ */

/**
 * Data-protection strength verdict.
 *
 * Deliberately a DIFFERENT vocabulary from the TLS pages' `PqcPosture`,
 * because the underlying threat is different. Using one shared label set would
 * force a symmetric cipher to be described in the language of key agreement.
 */
export type ProtectionStrength =
  | 'quantum-safe' // AES-256, ChaCha20-Poly1305, SHA-384+, SHA-3
  | 'post-quantum' // ML-KEM / ML-DSA key material protecting data
  | 'adequate' // AES-192, SHA-256 — sound today, below CNSA 2.0
  | 'weakened' // AES-128 — Grover halves it to ~64-bit, not broken
  /**
   * RSA / ECC wrapping data: sound TODAY, recovered outright by Shor on a CRQC.
   * Deliberately distinct from `broken`. Collapsing the two labelled RSA-2048
   * "Broken", which both overstates today's risk and contradicts the TLS pages,
   * where the same primitive is correctly "Quantum Vulnerable".
   */
  | 'quantum-vulnerable'
  | 'broken' // 3DES, DES, RC4, SHA-1, MD5, ECB — broken by classical cryptanalysis
  | 'unknown'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

/** Which layer of the data-protection stack an observation belongs to. */
export type ProtectionLayer =
  | 'symmetric' // bulk data encryption
  | 'hash' // integrity / digest
  | 'mac' // authentication tag / HMAC
  | 'kdf' // key derivation, password hashing
  | 'key-material' // generated or managed keys
  | 'at-rest' // storage / database / volume encryption policy
  | 'vault' // platform vault protection
  | 'application' // library, JWT, config-declared crypto

export type EvidenceSource =
  | 'runtime-telemetry'
  | 'agent-scan'
  | 'crypto-inventory'
  | 'key-store'
  | 'vault'
  | 'scan-finding'
  | 'exposure'
  | 'security-event'

export interface EvidenceRef {
  source: EvidenceSource
  recordId: string
  table: string
  observedAt: string | null
  detail: string
}

/* ------------------------------------------------------------------ */
/* Cryptographic strength                                              */
/* ------------------------------------------------------------------ */

/**
 * The quantitative security statement behind a strength verdict.
 *
 * Both numbers are published so the UI never has to assert a verdict without
 * showing its arithmetic.
 */
export interface StrengthProfile {
  /** Classical security level in bits, when the primitive determines one. */
  classicalBits: number | null
  /**
   * Effective bits against a quantum adversary.
   * Symmetric: halved by Grover. Hash preimage: halved. `null` when the
   * primitive is already broken classically, where a quantum figure would be
   * meaningless.
   */
  quantumBits: number | null
  strength: ProtectionStrength
  /** One sentence an operator can act on. */
  rationale: string
  /** The standard that sets the bar, e.g. `CNSA 2.0`, `NIST SP 800-131A`. */
  standard: string
  /** Approved replacement when the primitive does not meet the bar. */
  target: string | null
}

/* ------------------------------------------------------------------ */
/* Observations                                                        */
/* ------------------------------------------------------------------ */

/**
 * One measured data-protection fact.
 *
 * As with the TLS engine, a row becomes an observation only when it NAMES a
 * primitive. Policy and configuration findings are findings, not observations.
 */
export interface EncryptionObservation {
  id: string
  layer: ProtectionLayer
  /** Raw measured string, exactly as recorded. */
  observed: string
  /** Canonical grouping label from the suite decomposer. */
  family: string
  strength: StrengthProfile

  assetId: string | null
  assetName: string
  /** Where in the estate this was seen: host, file, package, service. */
  location: string

  /** Runtime operation this primitive was used for, when recorded. */
  operation: string | null
  /** Times this primitive was observed. Never a fabricated traffic volume. */
  occurrences: number

  observedAt: string | null
  evidence: EvidenceRef
}

/* ------------------------------------------------------------------ */
/* Algorithm rollup — the inventory rows the page renders              */
/* ------------------------------------------------------------------ */

export interface AlgorithmRow {
  /** Canonical algorithm label, e.g. `AES-256-GCM`. */
  label: string
  layer: ProtectionLayer
  strength: StrengthProfile
  /** Distinct observations backing this row. */
  observations: number
  /** Assets it was measured on — enables Algorithm → Asset drill-down. */
  assetIds: string[]
  assetNames: string[]
  /** Operations it was seen performing, when runtime recorded them. */
  operations: string[]
  percent: number
  firstObservedAt: string | null
  lastObservedAt: string | null
  evidence: EvidenceRef[]
}

/* ------------------------------------------------------------------ */
/* Key material                                                        */
/* ------------------------------------------------------------------ */

export type KeyLifecycle = 'active' | 'expiring' | 'expired' | 'revoked' | 'rotated' | 'unknown'

export interface KeyRecord {
  id: string
  label: string
  algorithm: string
  bitLength: number | null
  strength: StrengthProfile
  /** How the key material was generated: QRNG, CSPRNG, HSM, imported. */
  entropySource: string
  /** 0-1 quality score recorded at generation, when the source provided one. */
  qualityScore: number | null
  lifecycle: KeyLifecycle
  createdAt: string | null
  expiresAt: string | null
  daysToExpiry: number | null
  revokedAt: string | null
  /** Set when this key replaced another — real rotation evidence. */
  rotatedFromId: string | null
  fingerprint: string | null
  riskLevel: RiskLevel
  riskScore: number
}

export interface KeyInventory {
  /** True when the tenant has any key material at all. */
  measured: boolean
  total: number
  keys: KeyRecord[]
  lifecycle: Record<KeyLifecycle, number>
  entropySources: Array<{ label: string; count: number; percent: number }>
  /**
   * Rotations actually evidenced by a `rotated_from` link. Never inferred from
   * key count or age — the previous page reported 338 rotations for 0 keys.
   */
  rotationsObserved: number
  /** Keys with no expiry recorded: lifecycle cannot be stated for these. */
  withoutExpiry: number
  averageQuality: number | null
}

/* ------------------------------------------------------------------ */
/* Data at rest                                                        */
/* ------------------------------------------------------------------ */

export interface AtRestRecord {
  id: string
  /** Storage surface: bucket, database, volume, container, vault. */
  surface: string
  assetId: string | null
  assetName: string
  /** Encryption algorithm the policy or evidence names, when it does. */
  algorithm: string | null
  strength: StrengthProfile | null
  /** true / false only when the evidence states it; null = not determined. */
  encrypted: boolean | null
  /** Who holds the key: provider-managed, customer-managed, platform. */
  keyCustody: string
  detail: string
  evidence: EvidenceRef
  observedAt: string | null
}

export interface AtRestCoverage {
  /** True when any at-rest evidence exists at all. */
  measured: boolean
  records: AtRestRecord[]
  encrypted: number
  unencrypted: number
  undetermined: number
  /** Assets with at least one at-rest evidence record. */
  assetsCovered: number
  coveragePercent: number
}

/* ------------------------------------------------------------------ */
/* Vault protection                                                    */
/* ------------------------------------------------------------------ */

export interface VaultProtection {
  measured: boolean
  files: number
  encrypted: number
  /** Files whose ML-DSA signature has been verified. */
  signatureVerified: number
  signatureUnverified: number
  algorithms: Array<{ label: string; count: number; strength: StrengthProfile }>
  totalBytes: number
  lastActivityAt: string | null
}

/* ------------------------------------------------------------------ */
/* Crypto operations                                                   */
/* ------------------------------------------------------------------ */

export interface OperationProfile {
  /** True when a runtime source reports operations at all. */
  measured: boolean
  total: number
  byOperation: Array<{ operation: string; count: number; percent: number }>
  /** Daily buckets from real observation timestamps. */
  timeline: Array<{ label: string; date: string; encrypt: number; decrypt: number; sign: number; verify: number; other: number }>
}

/* ------------------------------------------------------------------ */
/* Findings                                                            */
/* ------------------------------------------------------------------ */

export interface EncryptionFinding {
  id: string
  title: string
  layer: ProtectionLayer
  severity: Severity
  assetId: string | null
  assetName: string
  /** The measured primitive the finding is about. */
  observed: string
  impact: string
  remediation: string
  standard: string
  /** Whether quantum changes this verdict, and how. Prevents Shor/Grover mixups. */
  quantumRelevance: string
  evidence: EvidenceRef[]
  firstObservedAt: string | null
  lastObservedAt: string | null
  instances: number
}

/* ------------------------------------------------------------------ */
/* Posture                                                             */
/* ------------------------------------------------------------------ */

export interface DataProtectionPosture {
  /** Distinct data-protection primitives measured across the estate. */
  algorithmsObserved: number
  observationsAnalysed: number

  quantumSafeAlgorithms: number
  adequateAlgorithms: number
  weakenedAlgorithms: number
  /** RSA / ECC protecting data — Shor-breakable, but sound today. */
  quantumVulnerableAlgorithms: number
  /** Broken by classical cryptanalysis; quantum is irrelevant to the verdict. */
  brokenAlgorithms: number

  /** Share of identified cipher and hash labels matching CNSA 2.0 algorithm families. */
  cnsa2CompliancePercent: number
  /** Denominator behind the percentage above, stated so it can be checked. */
  cnsa2Assessed: number

  keysManaged: number
  keysAtRisk: number
  atRestAssetsCovered: number
  atRestCoveragePercent: number
  vaultFilesProtected: number

  /** Estate-wide scores reproduced verbatim from the Quantum Readiness snapshot. */
  quantumReadinessScore: number
  quantumRiskScore: number
  quantumRiskLevel: string
  hndlRiskScore: number
  hndlRiskLevel: string

  /** Assets with any data-protection evidence, and the estate total. */
  assetsWithEvidence: number
  assetsTotal: number
  /**
   * Observations that could not be resolved to a tenant asset — a library on an
   * unmapped host, a process with no asset binding. Real evidence, reported
   * separately so it can never inflate the coverage denominator.
   */
  unattributedObservations: number
  evidenceCoveragePercent: number
}

/* ------------------------------------------------------------------ */
/* Telemetry health                                                    */
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
  lastKeyEventAt: string | null
  lastVaultActivityAt: string | null
  sourceCounts: Record<string, number>
  truncated: boolean
  /**
   * Sources that returned nothing. Rendered explicitly so a zero on the page is
   * always attributable to a missing source rather than read as a clean result.
   */
  absentSources: string[]
}

/* ------------------------------------------------------------------ */
/* The model                                                           */
/* ------------------------------------------------------------------ */

export interface EncryptionIntelligence {
  generatedAt: string
  latestEvidenceAt: string | null
  hasData: boolean

  posture: DataProtectionPosture
  observations: EncryptionObservation[]

  /** Algorithm inventories, one per layer of the data-protection stack. */
  symmetric: AlgorithmRow[]
  hashes: AlgorithmRow[]
  macs: AlgorithmRow[]
  kdfs: AlgorithmRow[]
  application: AlgorithmRow[]

  keys: KeyInventory
  atRest: AtRestCoverage
  vault: VaultProtection
  operations: OperationProfile
  findings: EncryptionFinding[]
  telemetry: TelemetryHealth

  timeline: Array<{ label: string; date: string; observations: number; operations: number; findings: number }>
}
