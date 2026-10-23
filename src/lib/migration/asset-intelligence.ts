/**
 * QGuard Helix — Asset Migration Intelligence Engine (isomorphic, pure).
 *
 * Single source of truth for ASSET-LEVEL post-quantum migration intelligence.
 *
 * Why this module exists
 * ----------------------
 * The Quantum Readiness snapshot (src/api-server/quantum-readiness.ts) derives
 * tenant-wide posture from raw tenant rows. The Migration Planner needs the same
 * evidence expressed PER ASSET so an operator can review and migrate one asset at
 * a time. If both sides re-implemented "is this asset vulnerable?" they would
 * drift, and the platform would show conflicting numbers on different pages.
 *
 * So the risk/posture derivation lives HERE and is consumed by BOTH:
 *   - computeSnapshot()          → tenant totals (inventory, exposure graph, …)
 *   - buildAssetPortfolio()      → per-asset dossiers (Migration Planner)
 *
 * Consequence (enforced by tools/migration-assets-check.ts):
 *   Σ assets with posture 'vulnerable' === snapshot.inventory.quantumVulnerableAssets
 *   asset.riskScore                    === exposureGraph node riskScore
 *   asset.posture                      === exposure graph node posture
 *
 * Everything is derived from real tenant rows. When evidence is missing the
 * record says so (`hasEvidence: false`, "Evidence Not Available") — nothing is
 * fabricated.
 */

/* ------------------------------------------------------------------ */
/* Primitives                                                          */
/* ------------------------------------------------------------------ */

export type Row = Record<string, unknown>

export const EVIDENCE_UNAVAILABLE = 'Evidence Not Available'

export function str(value: unknown): string {
  return typeof value === 'string' ? value : value == null ? '' : String(value)
}
export function num(value: unknown): number {
  const n = Number(value)
  return Number.isFinite(n) ? n : 0
}
export function clamp(value: number, min = 0, max = 100): number {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, value))
}
export function recordOf(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
}

const QUANTUM_VULNERABLE_PREFIXES = ['RSA', 'ECC', 'ECDSA', 'ECDH', 'DH', 'DSA', 'ELGAMAL', 'EL-GAMAL']
const QUANTUM_VULNERABLE_EXACT = ['SHA-1', 'SHA1', 'MD5', '3DES', 'DES', 'RC4']
const PQC_MARKERS = ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'KYBER', 'DILITHIUM', 'SPHINCS', 'FALCON', 'FRODOKEM', 'BIKE', 'HQC']
const HYBRID_MARKERS = ['HYBRID', 'X25519+ML-KEM', 'ED25519+ML-DSA', 'X25519MLKEM']

export type AlgorithmClass = 'vulnerable' | 'pqc' | 'hybrid' | 'unknown'

/** Canonical algorithm classification. Shared with the QR snapshot. */
export function classifyAlgorithm(raw: string): AlgorithmClass {
  const algo = raw.toUpperCase().trim()
  if (!algo) return 'unknown'
  if (HYBRID_MARKERS.some((m) => algo.includes(m))) return 'hybrid'
  if (PQC_MARKERS.some((m) => algo.includes(m))) return 'pqc'
  if (QUANTUM_VULNERABLE_EXACT.includes(algo)) return 'vulnerable'
  if (QUANTUM_VULNERABLE_PREFIXES.some((p) => algo.startsWith(p))) return 'vulnerable'
  return 'unknown'
}

/** Canonical internet-exposure heuristic. Shared with the QR snapshot. */
export function isInternetFacing(asset: Row): boolean {
  const env = str(asset.environment).toLowerCase()
  if (['public', 'internet', 'dmz', 'external', 'edge'].some((e) => env.includes(e))) return true
  const meta = recordOf(asset.metadata)
  if (meta.internet_facing === true || meta.public === true) return true
  const exposure = str(meta.exposure || meta.exposure_level).toLowerCase()
  if (exposure.includes('internet') || exposure.includes('public') || exposure.includes('external')) return true
  const type = str(asset.type).toLowerCase()
  if (/web|domain|tls|endpoint|site|host|gateway|cdn|proxy|load|dns|ingress|api/i.test(type)) return true
  const name = str(asset.name)
  if (/^https?:\/\//i.test(name) || /\.[a-z]{2,}(?::\d+)?$/i.test(name)) return true
  return false
}

/** Canonical severity → weight. Shared with the QR snapshot. */
export function severityWeight(sev: string): number {
  const s = sev.toLowerCase()
  if (s.includes('critical')) return 100
  if (s.includes('high')) return 75
  if (s.includes('medium') || s.includes('moderate')) return 50
  if (s.includes('low')) return 25
  return 10
}

/* ------------------------------------------------------------------ */
/* Canonical 0–100 risk banding                                        */
/* ------------------------------------------------------------------ */

export type RiskBandKey = 'critical' | 'high' | 'elevated' | 'moderate' | 'low' | 'minimal'

export interface RiskBand {
  key: RiskBandKey
  /** Exactly the string `levelFromRisk` returns — they are the same table. */
  label: string
  /** Inclusive lower bound on the canonical 0–100 scale. */
  min: number
  hex: string
}

/**
 * THE risk banding table. Ordered low → high so meters and legends can render
 * it directly, which is why the graph legend, the node colouring and the Node
 * Inspector meter cannot disagree: they all read this one array rather than
 * each keeping a private set of thresholds (they used to, and they drifted —
 * the map coloured at >10/>5/>2 while the API coloured at >=3/>=2).
 */
export const RISK_BANDS: readonly RiskBand[] = [
  { key: 'minimal', label: 'Minimal', min: 0, hex: '#10b981' },
  { key: 'low', label: 'Low', min: 1, hex: '#22c55e' },
  { key: 'moderate', label: 'Moderate', min: 20, hex: '#eab308' },
  { key: 'elevated', label: 'Elevated', min: 40, hex: '#f59e0b' },
  { key: 'high', label: 'High', min: 60, hex: '#f97316' },
  { key: 'critical', label: 'Critical', min: 80, hex: '#ef4444' },
] as const

/**
 * An asset the scanners have produced no risk evidence for. NOT a band —
 * "we did not measure this" is a third state that must never render as a
 * green pass (see the data-integrity contract, rule 3).
 */
export const UNASSESSED_BAND = { key: 'unassessed', label: 'Not Assessed', hex: '#64748b' } as const

/**
 * Map a weighted exposure load onto a canonical 0-100 risk score (lower-better).
 *
 * Diminishing returns rather than a linear penalty, because a linear model
 * pegs: the Migration Sandbox formula this replaced
 * (`100 - critical*15 - high*8 - ...`) hit its bound at seven critical
 * exposures, so every real estate produced the same score and the metric
 * carried no information. Strictly increasing in load and asymptotic to 100.
 */
export function riskScoreFromLoad(load: number, halfLife = 60) {
  const safe = Math.max(0, Number(load) || 0)
  return Math.max(0, Math.min(100, Math.round(100 * (1 - Math.exp(-safe / halfLife)))))
}

/** Resolve a canonical 0–100 risk score to its band. */
export function riskBandFor(score: number): RiskBand {
  const value = clamp(num(score))
  // Stop above `low`: any score that is positive but under the moderate floor
  // is Low, including fractional scores below 1. Preserves the exact `> 0`
  // semantics callers of `levelFromRisk` have always had.
  for (let i = RISK_BANDS.length - 1; i >= 2; i -= 1) {
    if (value >= RISK_BANDS[i].min) return RISK_BANDS[i]
  }
  return value > 0 ? RISK_BANDS[1] : RISK_BANDS[0]
}

/** Canonical risk label. Derived from RISK_BANDS so the two cannot drift. */
export function levelFromRisk(score: number): string {
  return riskBandFor(score).label
}
export function levelFromReadiness(score: number): string {
  if (score >= 85) return 'Quantum-Ready'
  if (score >= 65) return 'Advanced'
  if (score >= 45) return 'Developing'
  if (score >= 25) return 'Early Stage'
  if (score > 0) return 'Initial'
  return 'Not Started'
}

/* ------------------------------------------------------------------ */
/* Canonical readiness blend                                           */
/* ------------------------------------------------------------------ */

/**
 * Weights of the quantum readiness blend. A factor that was not measured is
 * EXCLUDED and the remaining weights renormalised (data-integrity rule 3).
 *
 * There is deliberately no governance term. It used to contribute a constant
 * 60 points whenever a scan session existed — a number no evidence produced,
 * which lifted every tenant's readiness by ~10 points. Governance maturity
 * returns to the blend only when a real governance evidence source feeds it.
 */
export const READINESS_WEIGHTS = { pqcAdoption: 0.45, riskPosture: 0.25, runtimeVisibility: 0.15 } as const

export interface ReadinessBlendInputs {
  /** 0–100 share of quantum-relevant components that are PQC-ready (hybrid ½). */
  pqcAdoption: number
  /** 0–100, LOWER is better. */
  quantumRisk: number
  /** True only when runtime crypto telemetry was actually observed. */
  runtimeMeasured: boolean
}

/**
 * THE quantum readiness blend. The tenant snapshot, the scoped report model and
 * the per-asset dossiers all call this, so the three can never weight the same
 * evidence differently (they used to carry three copies of the formula).
 */
export function blendQuantumReadiness(inputs: ReadinessBlendInputs): number {
  const w = READINESS_WEIGHTS
  const runtime = inputs.runtimeMeasured ? w.runtimeVisibility : 0
  const weightSum = w.pqcAdoption + w.riskPosture + runtime
  const raw = clamp(num(inputs.pqcAdoption)) * w.pqcAdoption + (100 - clamp(num(inputs.quantumRisk))) * w.riskPosture + (inputs.runtimeMeasured ? 100 * runtime : 0)
  return Math.round(clamp(raw / weightSum))
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

/** Mean severity of the finding population on a 0–100 scale (0 when there are none). */
export function severityPressureFrom(sev: SeverityCounts): number {
  const total = sev.critical + sev.high + sev.medium + sev.low
  if (total <= 0) return 0
  return clamp(((sev.critical * 4 + sev.high * 2.5 + sev.medium * 1 + sev.low * 0.4) / total) * 22)
}

/**
 * THE tenant quantum-risk composite (0–100, lower-better), shared by the QR
 * snapshot and the scoped report model.
 */
export function quantumRiskFrom(inputs: { severityPressure: number; vulnerableSharePct: number; internetSharePct: number }): number {
  return Math.round(clamp(inputs.severityPressure * 0.45 + inputs.vulnerableSharePct * 0.4 + inputs.internetSharePct * 0.15))
}

/**
 * THE migration schedule model (tenant snapshot + scoped reports).
 *
 * Scope is measured in COMPONENTS; assets add a bounded per-asset cutover and
 * validation overhead (0.2 wk each) rather than being summed with components —
 * those assets are vulnerable BECAUSE of the components already counted.
 * Calendar duration is bounded by parallel workstreams once single-lane work
 * would exceed ~2 years (cap 64 lanes); small estates run one lane.
 */
export function estimateMigrationSchedule(inputs: {
  vulnerableComponents: number
  vulnerableAssets: number
  migrationComplexity: number
  hasData: boolean
}): { effortWeeks: number; parallelWorkstreams: number; migrationTimelineWeeks: number } {
  const remaining = Math.max(0, num(inputs.vulnerableComponents))
  const effortWeeks = (remaining * 0.6 + Math.max(0, num(inputs.vulnerableAssets)) * 0.2) * (1 + clamp(num(inputs.migrationComplexity)) / 200)
  const parallelWorkstreams = Math.min(64, Math.max(1, Math.ceil(effortWeeks / 104)))
  const migrationTimelineWeeks = inputs.hasData ? Math.max(remaining > 0 ? 2 : 0, Math.round(effortWeeks / parallelWorkstreams)) : 0
  return { effortWeeks, parallelWorkstreams, migrationTimelineWeeks }
}

/* ------------------------------------------------------------------ */
/* Canonical per-asset risk + posture model                            */
/* ------------------------------------------------------------------ */

export type Posture = 'pqc' | 'hybrid' | 'vulnerable'

export interface PostureModelInputs {
  assets: Row[]
  scanResults: Row[]
  cryptoExposures: Row[]
  cryptoInventory: Row[]
  runtimeEvents: Row[]
}

export interface PostureModel {
  assetRisk: Map<string, number>
  assetPosture: Map<string, Posture>
  vulnerableAssetIds: Set<string>
  pqcAssetIds: Set<string>
  /**
   * Assets at least one input row (scan result, exposure, CBOM component or
   * runtime event) was recorded against. An asset OUTSIDE this set still gets
   * the 'hybrid' posture — that is the historical contract every consumer
   * reconciles against — but it has not been measured, and a surface that
   * reports posture must say so rather than call it "in progress".
   */
  evidencedAssetIds: Set<string>
  counts: {
    pqcReadyAssets: number
    hybridAssets: number
    quantumVulnerableAssets: number
    internetFacing: number
    /** Subset of `hybridAssets` with no crypto evidence at all. */
    unassessedAssets: number
  }
}

/**
 * THE canonical per-asset risk + posture derivation.
 *
 * Both the Quantum Readiness snapshot and the Migration Planner asset portfolio
 * call this, so an asset can never read "Quantum-Vulnerable" on one page and
 * "PQC-Ready" on another.
 */
export function deriveAssetPostureModel(inputs: PostureModelInputs): PostureModel {
  const assetRisk = new Map<string, number>()
  const bumpAsset = (assetId: string, weight: number) => {
    if (!assetId) return
    assetRisk.set(assetId, Math.max(assetRisk.get(assetId) || 0, weight))
  }
  for (const result of inputs.scanResults) bumpAsset(str(result.asset_id), severityWeight(str(result.threat_level)))
  for (const exposure of inputs.cryptoExposures) bumpAsset(str(exposure.asset_id), severityWeight(str(exposure.severity)))
  for (const item of inputs.cryptoInventory) if (item.is_vulnerable === true) bumpAsset(str(item.asset_id), 65)
  for (const event of inputs.runtimeEvents) {
    if (event.is_legacy === true || event.hndl_risk === true) bumpAsset(str(event.asset_id), Math.max(60, num(event.risk_score)))
    else if (num(event.risk_score) > 0) bumpAsset(str(event.asset_id), num(event.risk_score))
  }

  const vulnerableAssetIds = new Set<string>()
  const pqcAssetIds = new Set<string>()
  for (const result of inputs.scanResults) {
    if (classifyAlgorithm(str(result.algorithm)) === 'vulnerable') vulnerableAssetIds.add(str(result.asset_id))
  }
  for (const item of inputs.cryptoInventory) {
    if (item.is_vulnerable === true) vulnerableAssetIds.add(str(item.asset_id))
    if (item.is_quantum_safe === true) pqcAssetIds.add(str(item.asset_id))
  }

  const evidencedAssetIds = new Set<string>()
  for (const rows of [inputs.scanResults, inputs.cryptoExposures, inputs.cryptoInventory, inputs.runtimeEvents]) {
    for (const row of rows) {
      const id = str(row.asset_id)
      if (id) evidencedAssetIds.add(id)
    }
  }

  const assetPosture = new Map<string, Posture>()
  const counts = { pqcReadyAssets: 0, hybridAssets: 0, quantumVulnerableAssets: 0, internetFacing: 0, unassessedAssets: 0 }
  for (const asset of inputs.assets) {
    const id = str(asset.id)
    const isVuln = vulnerableAssetIds.has(id) || (assetRisk.get(id) || 0) >= 50
    const isPqc = pqcAssetIds.has(id) && !isVuln
    const posture: Posture = isVuln ? 'vulnerable' : isPqc ? 'pqc' : 'hybrid'
    assetPosture.set(id, posture)
    if (posture === 'vulnerable') counts.quantumVulnerableAssets += 1
    else if (posture === 'pqc') counts.pqcReadyAssets += 1
    else {
      counts.hybridAssets += 1
      if (!evidencedAssetIds.has(id)) counts.unassessedAssets += 1
    }
    if (isInternetFacing(asset)) counts.internetFacing += 1
  }

  return { assetRisk, assetPosture, vulnerableAssetIds, pqcAssetIds, evidencedAssetIds, counts }
}

/** Display label for a posture — identical wording to the QR top-risk table. */
export function postureLabel(posture: Posture): string {
  return posture === 'pqc' ? 'PQC-Ready' : posture === 'vulnerable' ? 'Quantum-Vulnerable' : 'Hybrid / In-Progress'
}

/* ------------------------------------------------------------------ */
/* PQC target mapping (FIPS 203/204/205)                               */
/* ------------------------------------------------------------------ */

export interface PqcTarget {
  target: string
  standard: string
  rationale: string
  category: 'key-establishment' | 'signature' | 'symmetric' | 'hash' | 'protocol'
}

/**
 * Maps an observed classical primitive to its NIST-approved replacement.
 * ML-KEM is key establishment ONLY; signatures map to ML-DSA / SLH-DSA.
 */
export function pqcTargetFor(algorithm: string, context = ''): PqcTarget {
  const algo = `${algorithm}`.toUpperCase()
  const ctx = `${context}`.toLowerCase()

  if (/SHA-?1\b|\bMD5\b/.test(algo)) {
    return { target: 'SHA3-256', standard: 'FIPS 202', rationale: 'Broken/deprecated hash — replace with SHA3-256 (Grover-resistant at 128-bit security).', category: 'hash' }
  }
  if (/\b(3DES|DES|RC4)\b/.test(algo)) {
    return { target: 'AES-256-GCM', standard: 'FIPS 197 / SP 800-38D', rationale: 'Legacy symmetric cipher — replace with AES-256-GCM for Grover-resistant 128-bit post-quantum strength.', category: 'symmetric' }
  }
  if (/AES-?128|AES128/.test(algo)) {
    return { target: 'AES-256-GCM', standard: 'FIPS 197 / SP 800-38D', rationale: 'Grover halves symmetric strength — AES-256 restores a 128-bit post-quantum margin.', category: 'symmetric' }
  }
  if (/TLS\s?1\.[01]|SSL/.test(algo) || /tls\s?1\.[01]/.test(ctx)) {
    return { target: 'TLS 1.3 + X25519MLKEM768', standard: 'RFC 8446 / FIPS 203', rationale: 'Deprecated transport — move to TLS 1.3 and negotiate the hybrid X25519MLKEM768 group.', category: 'protocol' }
  }
  if (/ECDSA|\bDSA\b|ED25519/.test(algo) || /signature|signing|code.?sign|jwt|token/.test(ctx)) {
    return { target: 'ML-DSA-65 (hybrid with Ed25519)', standard: 'FIPS 204', rationale: 'Quantum-vulnerable digital signature — migrate to ML-DSA-65, hybridised with Ed25519 during transition.', category: 'signature' }
  }
  if (/ECDH|X25519|\bDH\b|DIFFIE/.test(algo) || /key.?exchange|kex|handshake|tls/.test(ctx)) {
    return { target: 'ML-KEM-768 (hybrid X25519MLKEM768)', standard: 'FIPS 203', rationale: 'Quantum-vulnerable key establishment — migrate to ML-KEM-768 in hybrid mode to protect against harvest-now-decrypt-later.', category: 'key-establishment' }
  }
  if (/^RSA/.test(algo)) {
    // RSA is used for both; certificates/signing → ML-DSA, transport → ML-KEM.
    if (/cert|ca\b|pki|sign|jwt|token|firmware/.test(ctx)) {
      return { target: 'ML-DSA-65 (hybrid with RSA during transition)', standard: 'FIPS 204', rationale: 'RSA signatures are broken by Shor — re-issue with ML-DSA-65 hybrid certificates.', category: 'signature' }
    }
    return { target: 'ML-KEM-768 (hybrid X25519MLKEM768)', standard: 'FIPS 203', rationale: 'RSA key transport is broken by Shor — migrate key establishment to hybrid ML-KEM-768.', category: 'key-establishment' }
  }
  if (/^ECC|SECP|P-?256|P-?384/.test(algo)) {
    return { target: 'ML-KEM-768 + ML-DSA-65 (hybrid)', standard: 'FIPS 203 / FIPS 204', rationale: 'Elliptic-curve primitives are broken by Shor — migrate key establishment and signatures to the hybrid PQC stack.', category: 'key-establishment' }
  }
  return { target: 'ML-KEM-768 / ML-DSA-65 hybrid stack', standard: 'FIPS 203 / FIPS 204', rationale: 'Classical primitive with no quantum-resistant guarantee — adopt the platform hybrid PQC stack.', category: 'key-establishment' }
}

/* ------------------------------------------------------------------ */
/* Asset dossier types                                                 */
/* ------------------------------------------------------------------ */

export interface AssetAlgorithmRow {
  algorithm: string
  classification: AlgorithmClass
  instances: number
  keySizes: number[]
  protocols: string[]
  target: string
  standard: string
  rationale: string
  severity: string
}

export interface AssetCertificateRow {
  id: string
  name: string
  algorithm: string
  keySize: number
  issuer: string
  notAfter: string | null
  daysToExpiry: number | null
  quantumSafe: boolean
  status: string
}

export interface AssetFindingRow {
  id: string
  title: string
  severity: string
  algorithm: string
  source: string
  description: string
  detectedAt: string | null
  instances: number
}

export interface AssetDependencyRow {
  id: string
  name: string
  direction: 'upstream' | 'downstream'
  relationship: string
  posture: Posture | 'unknown'
  riskScore: number
}

export interface PriorityFactor {
  key: string
  label: string
  score: number
  weight: number
  contribution: number
  evidence: string
}

export interface AssetMigrationRecord {
  /* ---- identity (canonical, matches every other module) ---- */
  id: string
  name: string
  type: string
  hostname: string
  environment: string
  region: string
  owner: string
  businessCriticality: string
  tags: string[]
  internetFacing: boolean
  discoveredAt: string | null
  lastEvidenceAt: string | null

  /* ---- headline scores ---- */
  hasEvidence: boolean
  riskScore: number
  riskLevel: string
  readinessScore: number
  readinessLevel: string
  posture: Posture
  postureLabel: string
  priority: string
  priorityScore: number
  hndlScore: number
  hndlLevel: string
  successProbabilityPct: number

  /* ---- migration state ---- */
  migrationStatus: string
  migrationProgressPct: number
  migrationStatusDetail: string
  estimatedEffortHours: number
  estimatedDurationLabel: string
  estimatedDowntime: string
  queued: boolean

  /* ---- cryptographic posture ---- */
  cryptoPostureSummary: string
  componentCount: number
  vulnerableComponentCount: number
  pqcComponentCount: number
  hybridComponentCount: number
  algorithms: AssetAlgorithmRow[]
  certificates: AssetCertificateRow[]
  tlsConfiguration: { protocols: string[]; cipherSuites: string[]; keyExchange: string[]; forwardSecrecy: string; summary: string }

  /* ---- analysis ---- */
  findings: AssetFindingRow[]
  severityCounts: { critical: number; high: number; medium: number; low: number }
  dependencies: AssetDependencyRow[]
  blastRadius: number
  priorityFactors: PriorityFactor[]
  riskAnalysis: { categories: Array<{ key: string; label: string; score: number }>; overall: number; overallLevel: string; explanation: string }
  businessImpact: { revenueImpact: string; operationalImpact: string; complianceImpact: string; customerFacing: boolean; dependents: number; summary: string }
  compatibility: { level: string; score: number; notes: string[] }
  recommendations: Array<{ id: string; title: string; detail: string; severity: string; standard: string; effort: string }>
  rollbackStrategy: { available: boolean; strategy: string; steps: string[]; recoveryObjective: string }
  requiredApprovals: Array<{ role: string; reason: string; required: boolean }>
  compliance: Array<{ framework: string; control: string; status: string; detail: string }>
  timeline: Array<{ phase: string; durationHours: number; owner: string; description: string }>
  /**
   * `cutoverBlocked` is a BLOCKER check (evidence present, compatibility viable,
   * no failed job) — deliberately NOT a claim that the asset has been validated.
   * `validated` is the separate, evidence-backed statement.
   */
  validation: { records: number; lastStatus: string; lastAt: string | null; cutoverBlocked: boolean; blockerReason: string; validated: boolean }
  jobs: Array<{ id: string; status: string; progress: number; jobType: string; targetAlgorithm: string; updatedAt: string }>
  evidence: { sources: string[]; scanResults: number; exposures: number; runtimeEvents: number; certificates: number; components: number; note: string }
}

export interface AssetPortfolioInputs {
  assets: Row[]
  cryptoInventory: Row[]
  scanResults: Row[]
  cryptoExposures: Row[]
  certificates: Row[]
  runtimeEvents: Row[]
  relationships: Row[]
  migrationJobs: Row[]
  validationLogs: Row[]
  complianceEvidence: Row[]
  queuedAssetIds?: string[]
  now?: number
}

export interface AssetPortfolio {
  generatedAt: string
  assets: AssetMigrationRecord[]
  summary: {
    total: number
    quantumVulnerable: number
    hybrid: number
    pqcReady: number
    internetFacing: number
    criticalPriority: number
    highPriority: number
    notStarted: number
    inProgress: number
    completed: number
    queued: number
    averageReadiness: number
    totalEffortHours: number
  }
  recommendedOrder: Array<{ rank: number; assetId: string; name: string; priority: string; priorityScore: number; riskScore: number; rationale: string }>
}

/* ------------------------------------------------------------------ */
/* Engine                                                              */
/* ------------------------------------------------------------------ */

function groupBy<T>(rows: T[], key: (row: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>()
  for (const row of rows) {
    const k = key(row)
    if (!k) continue
    const bucket = map.get(k)
    if (bucket) bucket.push(row)
    else map.set(k, [row])
  }
  return map
}

function hostnameFor(asset: Row): string {
  const meta = recordOf(asset.metadata)
  const candidate = str(meta.hostname || meta.host || meta.fqdn || meta.domain || meta.url || meta.endpoint || meta.ip_address || meta.ip)
  if (candidate) return candidate.replace(/^https?:\/\//i, '').replace(/\/$/, '')
  const name = str(asset.name)
  if (/^https?:\/\//i.test(name)) return name.replace(/^https?:\/\//i, '').replace(/\/$/, '')
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?$/i.test(name)) return name
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(name)) return name
  return EVIDENCE_UNAVAILABLE
}

function criticalityFor(asset: Row): string {
  const raw = str(asset.criticality).trim()
  if (raw) return raw.charAt(0).toUpperCase() + raw.slice(1).toLowerCase()
  const meta = recordOf(asset.metadata)
  const metaValue = str(meta.criticality || meta.business_criticality).trim()
  if (metaValue) return metaValue.charAt(0).toUpperCase() + metaValue.slice(1).toLowerCase()
  // Derived, never invented: production + internet-facing assets carry the
  // business weight the estate assigns them implicitly.
  const env = str(asset.environment).toLowerCase()
  if (/prod/.test(env)) return isInternetFacing(asset) ? 'High' : 'Medium'
  if (/stag|uat|test|qa/.test(env)) return 'Low'
  if (/dev/.test(env)) return 'Low'
  return 'Medium'
}

function criticalityScore(label: string): number {
  const l = label.toLowerCase()
  if (l.includes('critical') || l.includes('mission')) return 100
  if (l.includes('high')) return 78
  if (l.includes('medium') || l.includes('moderate')) return 50
  if (l.includes('low')) return 25
  return 40
}

function tagsFor(asset: Row): string[] {
  const meta = recordOf(asset.metadata)
  const raw = meta.tags ?? meta.labels
  if (Array.isArray(raw)) return raw.map((t) => str(t)).filter(Boolean).slice(0, 8)
  return []
}

function isoOrNull(value: unknown): string | null {
  const s = str(value)
  if (!s) return null
  const t = new Date(s).getTime()
  return Number.isFinite(t) ? s : null
}

function latest(values: Array<string | null>): string | null {
  const valid = values.filter((v): v is string => Boolean(v) && Number.isFinite(new Date(v as string).getTime()))
  if (!valid.length) return null
  return valid.sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0]
}

function durationLabel(hours: number): string {
  if (!hours) return EVIDENCE_UNAVAILABLE
  if (hours < 8) return `${Math.max(1, Math.round(hours))} hours`
  const days = hours / 8
  if (days < 10) return `${Math.round(days * 10) / 10} days`
  const weeks = days / 5
  return `${Math.round(weeks * 10) / 10} weeks`
}

function migrationStateFor(jobs: Row[]): { status: string; progress: number; detail: string } {
  if (!jobs.length) return { status: 'Not Started', progress: 0, detail: 'No migration job has been created for this asset.' }
  const norm = (j: Row) => str(j.status).toLowerCase()
  const cancelled = jobs.filter((j) => /cancel/.test(norm(j)))
  // A cancelled job is withdrawn work — it must not keep counting as active
  // migration progress on this asset, or the planner and Live Migration would
  // disagree about what is still in flight.
  const live = jobs.filter((j) => !/cancel/.test(norm(j)))
  if (!live.length) {
    return { status: 'Not Started', progress: 0, detail: `${cancelled.length} migration job(s) were cancelled; no active job remains for this asset.` }
  }
  const failed = live.filter((j) => /fail|error/.test(norm(j)))
  const running = live.filter((j) => /running|in_progress|in-progress|executing|active|migrating/.test(norm(j)))
  const validating = live.filter((j) => /validat|verify/.test(norm(j)))
  const queued = live.filter((j) => /queue|pending|awaiting|scheduled/.test(norm(j)))
  const completed = live.filter((j) => /complete|done|success/.test(norm(j)))
  const avg = Math.round(live.reduce((s, j) => s + clamp(num(j.progress)), 0) / live.length)
  const jobs_ = live

  if (failed.length) return { status: 'Failed', progress: avg, detail: `${failed.length} migration job(s) failed and require operator attention.` }
  if (running.length) return { status: 'In Progress', progress: avg, detail: `${running.length} migration job(s) executing.` }
  if (validating.length) return { status: 'Validating', progress: Math.max(avg, 80), detail: `${validating.length} job(s) in post-migration validation.` }
  if (queued.length) return { status: 'Queued', progress: avg, detail: `${queued.length} job(s) queued for agent claim.` }
  if (completed.length === jobs_.length) return { status: 'Completed', progress: 100, detail: `All ${completed.length} migration job(s) completed.` }
  return { status: 'Planned', progress: avg, detail: `${jobs_.length} migration job(s) recorded.` }
}

function complianceFrameworksFor(params: {
  evidenceRows: Row[]
  internetFacing: boolean
  hasCertificates: boolean
  vulnerableComponents: number
  environment: string
}): Array<{ framework: string; control: string; status: string; detail: string }> {
  if (params.evidenceRows.length) {
    const seen = new Set<string>()
    const mapped: Array<{ framework: string; control: string; status: string; detail: string }> = []
    for (const row of params.evidenceRows) {
      const framework = str(row.framework) || 'Framework'
      const control = str(row.control_id) || 'Control'
      const key = `${framework}::${control}`
      if (seen.has(key)) continue
      seen.add(key)
      mapped.push({
        framework,
        control,
        status: str(row.status) || 'unknown',
        detail: str(row.description) || 'Recorded compliance evidence for this asset.',
      })
      if (mapped.length >= 8) break
    }
    return mapped
  }

  // No stored evidence rows: emit a DERIVED control mapping, explicitly labelled
  // as derived so it is never mistaken for audited evidence.
  const gap = params.vulnerableComponents > 0
  const rows: Array<{ framework: string; control: string; status: string; detail: string }> = [
    {
      framework: 'NIST IR 8547 (derived)',
      control: 'Transition to PQC standards',
      status: gap ? 'gap' : 'partial',
      detail: gap
        ? `${params.vulnerableComponents} quantum-vulnerable component(s) remain on this asset; NIST deprecates 112-bit classical strength by 2030.`
        : 'No quantum-vulnerable components detected on this asset.',
    },
    {
      framework: 'CNSA 2.0 (derived)',
      control: 'Approved quantum-resistant algorithms',
      status: gap ? 'gap' : 'partial',
      detail: gap ? 'Asset must adopt ML-KEM / ML-DSA to satisfy CNSA 2.0 timelines.' : 'Asset aligns with approved algorithm families.',
    },
  ]
  if (params.internetFacing) {
    rows.push({
      framework: 'PCI DSS 4.0.1 (derived)',
      control: 'Req. 4 — Strong cryptography in transit',
      status: gap ? 'gap' : 'partial',
      detail: 'Internet-facing asset: transport cryptography is in scope for cardholder-data protection requirements.',
    })
  }
  if (params.hasCertificates) {
    rows.push({
      framework: 'NIST SP 800-57 (derived)',
      control: 'Key management lifecycle',
      status: 'partial',
      detail: 'Certificates bound to this asset require lifecycle governance and PQC re-issuance planning.',
    })
  }
  if (/prod/i.test(params.environment)) {
    rows.push({
      framework: 'ISO/IEC 27001 (derived)',
      control: 'A.8.24 — Use of cryptography',
      status: gap ? 'gap' : 'partial',
      detail: 'Production asset cryptography must be governed by an approved cryptographic control policy.',
    })
  }
  return rows
}

/**
 * Builds the per-asset migration dossiers for a tenant.
 *
 * Every score is derived from the supplied tenant rows only. The posture model
 * is the canonical one shared with the Quantum Readiness snapshot.
 */
export function buildAssetPortfolio(inputs: AssetPortfolioInputs): AssetPortfolio {
  const now = inputs.now ?? Date.now()
  const queued = new Set((inputs.queuedAssetIds || []).map((id) => str(id)))

  const model = deriveAssetPostureModel({
    assets: inputs.assets,
    scanResults: inputs.scanResults,
    cryptoExposures: inputs.cryptoExposures,
    cryptoInventory: inputs.cryptoInventory,
    runtimeEvents: inputs.runtimeEvents,
  })

  const inventoryByAsset = groupBy(inputs.cryptoInventory, (r) => str(r.asset_id))
  const scanByAsset = groupBy(inputs.scanResults, (r) => str(r.asset_id))
  const exposureByAsset = groupBy(inputs.cryptoExposures, (r) => str(r.asset_id))
  const certByAsset = groupBy(inputs.certificates, (r) => str(r.asset_id))
  const runtimeByAsset = groupBy(inputs.runtimeEvents, (r) => str(r.asset_id))
  const jobsByAsset = groupBy(inputs.migrationJobs, (r) => str(r.asset_id))
  const complianceByAsset = groupBy(inputs.complianceEvidence, (r) => str(r.asset_id))
  const assetNameById = new Map(inputs.assets.map((a) => [str(a.id), str(a.name) || 'Unnamed asset']))

  // Dependency adjacency (both directions), tolerant of the several column
  // namings the platform's relationship tables use.
  const relSource = (r: Row) => str(r.source_asset_id || r.parent_asset_id || r.from_asset_id)
  const relTarget = (r: Row) => str(r.target_asset_id || r.child_asset_id || r.to_asset_id)
  const downstream = new Map<string, Row[]>()
  const upstream = new Map<string, Row[]>()
  for (const rel of inputs.relationships) {
    const s = relSource(rel)
    const t = relTarget(rel)
    if (!s || !t) continue
    const d = downstream.get(s)
    if (d) d.push(rel); else downstream.set(s, [rel])
    const u = upstream.get(t)
    if (u) u.push(rel); else upstream.set(t, [rel])
  }

  // Validation logs are not consistently asset-scoped across the platform; match
  // by asset_id when present, otherwise by the job ids belonging to the asset.
  const validationByAsset = groupBy(inputs.validationLogs, (r) => str(r.asset_id))
  // migration_id is the real column on migration_validation_logs; the other two
  // are accepted so agent-written and legacy rows keep matching.
  const validationByJob = groupBy(inputs.validationLogs, (r) => str(r.migration_id || r.migration_job_id || r.job_id))

  const records: AssetMigrationRecord[] = inputs.assets.map((asset) => {
    const id = str(asset.id)
    const components = inventoryByAsset.get(id) || []
    const scans = scanByAsset.get(id) || []
    const exposures = exposureByAsset.get(id) || []
    const certs = certByAsset.get(id) || []
    const runtime = runtimeByAsset.get(id) || []
    const jobs = jobsByAsset.get(id) || []
    const complianceRows = complianceByAsset.get(id) || []

    const riskScore = Math.round(model.assetRisk.get(id) || 0)
    const posture = model.assetPosture.get(id) || 'hybrid'
    const internetFacing = isInternetFacing(asset)
    const environment = str(asset.environment) || 'unknown'
    const businessCriticality = criticalityFor(asset)

    /* ---- component posture ---- */
    let vulnerableComponentCount = 0
    let pqcComponentCount = 0
    let hybridComponentCount = 0
    for (const item of components) {
      if (item.is_quantum_safe === true) pqcComponentCount += 1
      else if (item.is_vulnerable === true) vulnerableComponentCount += 1
      else {
        const klass = classifyAlgorithm(str(item.algorithm))
        if (klass === 'pqc') pqcComponentCount += 1
        else if (klass === 'hybrid') hybridComponentCount += 1
        else if (klass === 'vulnerable') vulnerableComponentCount += 1
      }
    }
    const componentCount = components.length

    /* ---- algorithm rollup ---- */
    const algoMap = new Map<string, { instances: number; keySizes: Set<number>; protocols: Set<string>; severity: string }>()
    const noteAlgorithm = (algorithm: string, keySize: number, protocol: string, severity: string) => {
      const key = algorithm.trim()
      if (!key) return
      const entry = algoMap.get(key) || { instances: 0, keySizes: new Set<number>(), protocols: new Set<string>(), severity: 'medium' }
      entry.instances += 1
      if (keySize > 0) entry.keySizes.add(keySize)
      if (protocol) entry.protocols.add(protocol)
      if (severityWeight(severity) > severityWeight(entry.severity)) entry.severity = severity
      algoMap.set(key, entry)
    }
    for (const item of components) noteAlgorithm(str(item.algorithm), num(item.key_size), str(item.protocol), str(item.exposure_level) || 'medium')
    for (const row of scans) noteAlgorithm(str(row.algorithm), 0, '', str(row.threat_level) || 'high')
    for (const cert of certs) noteAlgorithm(str(cert.algorithm), num(cert.key_size), 'X.509', cert.is_quantum_safe === true ? 'low' : 'high')
    for (const event of runtime) noteAlgorithm(str(event.algorithm), 0, str(event.cipher_suite), str(event.severity) || 'medium')

    const algorithms: AssetAlgorithmRow[] = [...algoMap.entries()]
      .map(([algorithm, entry]) => {
        const classification = classifyAlgorithm(algorithm)
        const mapping = pqcTargetFor(algorithm, `${str(asset.type)} ${str(asset.name)} ${[...entry.protocols].join(' ')}`)
        return {
          algorithm,
          classification,
          instances: entry.instances,
          keySizes: [...entry.keySizes].sort((a, b) => a - b),
          protocols: [...entry.protocols],
          target: classification === 'pqc' ? 'Already quantum-safe' : mapping.target,
          standard: classification === 'pqc' ? 'FIPS 203/204/205' : mapping.standard,
          rationale: classification === 'pqc' ? 'This primitive already meets NIST PQC standards — no migration required.' : mapping.rationale,
          severity: classification === 'vulnerable' ? entry.severity : classification === 'pqc' ? 'low' : 'medium',
        }
      })
      .sort((a, b) => {
        const rank = (c: AlgorithmClass) => (c === 'vulnerable' ? 0 : c === 'unknown' ? 1 : c === 'hybrid' ? 2 : 3)
        return rank(a.classification) - rank(b.classification) || b.instances - a.instances
      })

    /* ---- certificates ---- */
    const certificates: AssetCertificateRow[] = certs.map((cert) => {
      const notAfter = isoOrNull(cert.not_after)
      const daysToExpiry = notAfter ? Math.round((new Date(notAfter).getTime() - now) / 86400000) : null
      return {
        id: str(cert.id),
        name: str(cert.name) || str(cert.subject) || 'Certificate',
        algorithm: str(cert.algorithm) || EVIDENCE_UNAVAILABLE,
        keySize: num(cert.key_size),
        issuer: str(cert.issuer) || EVIDENCE_UNAVAILABLE,
        notAfter,
        daysToExpiry,
        quantumSafe: cert.is_quantum_safe === true,
        status: str(cert.status) || (daysToExpiry !== null && daysToExpiry < 0 ? 'expired' : 'active'),
      }
    })
    const soonestExpiry = certificates
      .map((c) => c.daysToExpiry)
      .filter((d): d is number => typeof d === 'number')
      .sort((a, b) => a - b)[0]

    /* ---- TLS configuration ---- */
    const protocols = new Set<string>()
    const cipherSuites = new Set<string>()
    const keyExchange = new Set<string>()
    for (const item of components) {
      const proto = str(item.protocol)
      if (proto) protocols.add(proto)
      if (/^(TLS|SSL|SSH|IKE)/i.test(str(item.name))) protocols.add(str(item.name))
    }
    for (const event of runtime) {
      const proto = str(event.protocol)
      if (proto) protocols.add(proto)
      const suite = str(event.cipher_suite)
      if (suite) cipherSuites.add(suite)
      const kex = str(event.key_exchange_algorithm)
      if (kex) keyExchange.add(kex)
    }
    const protocolList = [...protocols].slice(0, 8)
    const suiteList = [...cipherSuites].slice(0, 8)
    const kexList = [...keyExchange].slice(0, 8)
    const pqcKex = kexList.some((k) => classifyAlgorithm(k) === 'pqc' || classifyAlgorithm(k) === 'hybrid')
    const forwardSecrecy = kexList.length
      ? kexList.some((k) => /ECDHE|DHE|X25519/i.test(k)) ? 'Forward secrecy observed' : 'No forward-secret key exchange observed'
      : EVIDENCE_UNAVAILABLE
    const tlsConfiguration = {
      protocols: protocolList,
      cipherSuites: suiteList,
      keyExchange: kexList,
      forwardSecrecy,
      summary: protocolList.length || suiteList.length || kexList.length
        ? `${protocolList.length ? protocolList.join(', ') : 'protocol not observed'}${pqcKex ? ' · hybrid/PQC key exchange observed' : kexList.length ? ' · classical key exchange only' : ''}`
        : `${EVIDENCE_UNAVAILABLE} — no transport telemetry captured for this asset.`,
    }

    /* ---- findings ---- */
    const findingMap = new Map<string, AssetFindingRow>()
    const addFinding = (row: AssetFindingRow) => {
      const key = `${row.severity}|${row.algorithm}|${row.title}`.toLowerCase()
      const existing = findingMap.get(key)
      if (existing) {
        existing.instances += row.instances
        existing.detectedAt = latest([existing.detectedAt, row.detectedAt])
      } else findingMap.set(key, { ...row })
    }
    for (const row of scans) {
      addFinding({
        id: str(row.id),
        title: `${str(row.algorithm) || 'Quantum-vulnerable algorithm'} detected`,
        severity: (str(row.threat_level) || 'medium').toLowerCase(),
        algorithm: str(row.algorithm) || '—',
        source: 'PQC Scanner',
        description: str(row.description) || 'Detected by the cryptographic discovery scanner.',
        detectedAt: isoOrNull(row.created_at),
        instances: 1,
      })
    }
    for (const row of exposures) {
      addFinding({
        id: str(row.id),
        title: str(row.exposure_type) || 'Cryptographic exposure',
        severity: (str(row.severity) || 'medium').toLowerCase(),
        algorithm: str(row.detected_value) || '—',
        source: 'Crypto Exposure',
        description: str(row.description) || 'Recorded cryptographic exposure.',
        detectedAt: isoOrNull(row.created_at),
        instances: 1,
      })
    }
    const findings = [...findingMap.values()].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity)).slice(0, 40)
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const f of findings) {
      const s = f.severity
      if (s.includes('critical')) severityCounts.critical += f.instances
      else if (s.includes('high')) severityCounts.high += f.instances
      else if (s.includes('medium') || s.includes('moderate')) severityCounts.medium += f.instances
      else if (s.includes('low')) severityCounts.low += f.instances
    }

    /* ---- dependencies ---- */
    const dependencyRows: AssetDependencyRow[] = []
    for (const rel of downstream.get(id) || []) {
      const other = relTarget(rel)
      dependencyRows.push({
        id: other,
        name: assetNameById.get(other) || other,
        direction: 'downstream',
        relationship: str(rel.relationship_type) || 'depends-on',
        posture: model.assetPosture.get(other) || 'unknown',
        riskScore: Math.round(model.assetRisk.get(other) || 0),
      })
    }
    for (const rel of upstream.get(id) || []) {
      const other = relSource(rel)
      dependencyRows.push({
        id: other,
        name: assetNameById.get(other) || other,
        direction: 'upstream',
        relationship: str(rel.relationship_type) || 'depends-on',
        posture: model.assetPosture.get(other) || 'unknown',
        riskScore: Math.round(model.assetRisk.get(other) || 0),
      })
    }
    const dependencies = dependencyRows.slice(0, 24)
    const dependents = (upstream.get(id) || []).length
    const blastRadius = dependencyRows.length

    /* ---- evidence coverage ---- */
    const hasEvidence = componentCount > 0 || scans.length > 0 || exposures.length > 0 || certs.length > 0 || runtime.length > 0

    /* ---- readiness (asset-scoped analogue of the tenant readiness model) ---- */
    const assetPqcAdoption = componentCount > 0 ? ((pqcComponentCount + hybridComponentCount * 0.5) / componentCount) * 100 : 0
    const readinessScore = hasEvidence
      ? blendQuantumReadiness({ pqcAdoption: assetPqcAdoption, quantumRisk: riskScore, runtimeMeasured: runtime.length > 0 })
      : 0

    /* ---- HNDL exposure ---- */
    const hndlEvents = runtime.filter((e) => e.hndl_risk === true).length
    const vulnerableShare = componentCount > 0 ? (vulnerableComponentCount / componentCount) * 100 : posture === 'vulnerable' ? 100 : 0
    const hndlScore = hasEvidence
      ? Math.round(
          clamp(
            vulnerableShare * 0.45 +
              (runtime.length ? (hndlEvents / runtime.length) * 100 : 0) * 0.25 +
              (internetFacing ? 100 : 0) * 0.2 +
              (criticalityScore(businessCriticality) >= 78 ? 100 : 0) * 0.1,
          ),
        )
      : 0

    /* ---- migration state ---- */
    const state = migrationStateFor(jobs)
    const jobIds = new Set(jobs.map((j) => str(j.id)))
    const validations = [
      ...(validationByAsset.get(id) || []),
      ...[...validationByJob.entries()].filter(([jobId]) => jobIds.has(jobId)).flatMap(([, rows]) => rows),
    ]
    const lastValidation = validations
      .slice()
      .sort((a, b) => new Date(str(b.created_at)).getTime() - new Date(str(a.created_at)).getTime())[0]

    /* ---- effort ---- */
    const envMultiplier = /prod/i.test(environment) ? 1.4 : /stag|uat/i.test(environment) ? 1.1 : 0.9
    const rawEffort =
      6 + componentCount * 1.5 + vulnerableComponentCount * 1.5 + certs.length * 2 + blastRadius * 1 + (internetFacing ? 4 : 0)
    const estimatedEffortHours = hasEvidence ? Math.round(rawEffort * envMultiplier) : 0

    /* ---- compatibility ---- */
    const compatibilityNotes: string[] = []
    let compatibilityScore = 82
    if (algorithms.some((a) => /RSA|ECDSA|ECDH/i.test(a.algorithm))) {
      compatibilityNotes.push('Hybrid X25519MLKEM768 / ML-DSA-65 preserves interoperability with classical peers during transition.')
    }
    if (protocolList.some((p) => /1\.[01]/.test(p))) {
      compatibilityScore -= 25
      compatibilityNotes.push('Deprecated TLS versions observed — clients must be upgraded to TLS 1.3 before hybrid groups can negotiate.')
    }
    if (certs.length && !certs.some((c) => c.is_quantum_safe === true)) {
      compatibilityScore -= 10
      compatibilityNotes.push('Certificate chain is fully classical — hybrid certificate issuance requires a CA that supports ML-DSA.')
    }
    if (blastRadius > 6) {
      compatibilityScore -= 12
      compatibilityNotes.push(`${blastRadius} trust relationship(s) must negotiate the new stack — stage the cutover behind a compatibility gate.`)
    }
    if (!hasEvidence) {
      compatibilityScore = 0
      compatibilityNotes.push('No cryptographic evidence for this asset — run a discovery scan before assessing compatibility.')
    }
    compatibilityScore = Math.round(clamp(compatibilityScore))

    /* ---- success probability ---- */
    const successProbabilityPct = hasEvidence
      ? Math.round(clamp(96 - riskScore * 0.12 - blastRadius * 1.5 - (soonestExpiry !== undefined && soonestExpiry < 0 ? 8 : 0) - (compatibilityScore < 60 ? 10 : 0), 45, 98))
      : 0

    /* ---- priority factors (the enterprise prioritisation model) ---- */
    const legacyScore = clamp(vulnerableShare)
    const unsupportedScore = algorithms.some((a) => /SHA-?1|MD5|RC4|3DES|\bDES\b|RSA-?1024/i.test(a.algorithm)) ? 100 : legacyScore > 0 ? 40 : 0
    const regulatoryScore = /prod/i.test(environment) ? (internetFacing ? 90 : 65) : 30
    const customerImpactScore = internetFacing ? (criticalityScore(businessCriticality) >= 78 ? 100 : 70) : criticalityScore(businessCriticality) >= 78 ? 55 : 25
    const certExpiryScore = soonestExpiry === undefined ? 0 : soonestExpiry < 0 ? 100 : soonestExpiry <= 30 ? 85 : soonestExpiry <= 90 ? 55 : 20
    const dependencyScore = clamp(blastRadius * 8)
    const confidenceScore = clamp(100 - successProbabilityPct)

    const factorDefs: Array<[string, string, number, number, string]> = [
      ['hndl', 'Harvest Now, Decrypt Later exposure', hndlScore, 18, hndlEvents ? `${hndlEvents} runtime event(s) flagged HNDL risk.` : `${Math.round(vulnerableShare)}% of components are quantum-vulnerable.`],
      ['criticality', 'Business criticality', criticalityScore(businessCriticality), 16, `Asset criticality recorded as ${businessCriticality}.`],
      ['internet', 'Internet exposure', internetFacing ? 100 : 15, 14, internetFacing ? 'Asset is internet-facing.' : 'Asset is internal only.'],
      ['legacy', 'Legacy cryptography', legacyScore, 14, `${vulnerableComponentCount} of ${componentCount || 0} component(s) quantum-vulnerable.`],
      ['unsupported', 'Unsupported / broken algorithms', unsupportedScore, 10, unsupportedScore >= 100 ? 'Broken primitives (SHA-1/MD5/RC4/DES/RSA-1024 class) detected.' : 'No broken primitives detected.'],
      ['regulatory', 'Regulatory requirements', regulatoryScore, 8, `${environment} environment${internetFacing ? ', in-scope for transport-security mandates' : ''}.`],
      ['customer', 'Customer impact', customerImpactScore, 6, internetFacing ? 'Customer-facing surface.' : 'No direct customer surface detected.'],
      ['certificate', 'Certificate expiration', certExpiryScore, 6, soonestExpiry === undefined ? 'No certificates bound to this asset.' : soonestExpiry < 0 ? 'Certificate expired.' : `Nearest certificate expires in ${soonestExpiry} day(s).`],
      ['dependency', 'Dependency complexity', dependencyScore, 5, `${blastRadius} trust relationship(s) in the blast radius.`],
      ['confidence', 'Migration confidence risk', confidenceScore, 3, `Estimated success probability ${successProbabilityPct}%.`],
    ]
    const priorityFactors: PriorityFactor[] = factorDefs.map(([key, label, score, weight, evidence]) => ({
      key,
      label,
      score: Math.round(clamp(score)),
      weight,
      contribution: Math.round(clamp(score) * (weight / 100) * 10) / 10,
      evidence,
    }))
    const priorityScore = hasEvidence ? Math.round(priorityFactors.reduce((s, f) => s + f.score * (f.weight / 100), 0)) : 0
    const priority = priorityScore >= 75 ? 'Critical' : priorityScore >= 55 ? 'High' : priorityScore >= 35 ? 'Medium' : 'Low'

    /* ---- asset risk analysis ---- */
    const riskCategories = [
      { key: 'technical', label: 'Technical Risk', score: Math.round(clamp(legacyScore * 0.6 + riskScore * 0.4)) },
      { key: 'operational', label: 'Operational Risk', score: Math.round(clamp(dependencyScore * 0.5 + (100 - compatibilityScore) * 0.5)) },
      { key: 'business', label: 'Business Risk', score: Math.round(clamp(criticalityScore(businessCriticality) * 0.5 + (internetFacing ? 100 : 20) * 0.5)) },
      { key: 'compliance', label: 'Compliance Risk', score: Math.round(clamp(regulatoryScore * 0.6 + unsupportedScore * 0.4)) },
      { key: 'quantum', label: 'Quantum Risk', score: Math.round(clamp(hndlScore)) },
    ]
    const overallRisk = Math.round(clamp(riskCategories.reduce((s, c) => s + c.score, 0) / riskCategories.length))
    const topCategory = [...riskCategories].sort((a, b) => b.score - a.score)[0]

    /* ---- recommendations ---- */
    const recommendations: Array<{ id: string; title: string; detail: string; severity: string; standard: string; effort: string }> = []
    const seenTargets = new Set<string>()
    for (const algo of algorithms) {
      if (algo.classification === 'pqc') continue
      if (algo.classification === 'unknown' && vulnerableComponentCount === 0) continue
      const key = `${algo.target}`
      if (seenTargets.has(key)) continue
      seenTargets.add(key)
      recommendations.push({
        id: `rec-${algo.algorithm.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
        title: `Migrate ${algo.algorithm} → ${algo.target}`,
        detail: algo.rationale,
        severity: algo.classification === 'vulnerable' ? (severityWeight(algo.severity) >= 100 ? 'critical' : 'high') : 'medium',
        standard: algo.standard,
        effort: algo.instances > 8 ? 'High' : algo.instances > 3 ? 'Medium' : 'Low',
      })
      if (recommendations.length >= 8) break
    }
    if (certificates.some((c) => !c.quantumSafe)) {
      recommendations.push({
        id: 'rec-cert',
        title: 'Re-issue certificates with hybrid ML-DSA chains',
        detail: `${certificates.filter((c) => !c.quantumSafe).length} classical certificate(s) bound to this asset must be re-issued from a PQC-capable CA.`,
        severity: soonestExpiry !== undefined && soonestExpiry <= 30 ? 'high' : 'medium',
        standard: 'FIPS 204 / NIST SP 800-57',
        effort: 'Medium',
      })
    }
    if (runtime.length === 0) {
      recommendations.push({
        id: 'rec-runtime',
        title: 'Enable runtime cryptographic telemetry',
        detail: 'No runtime crypto events observed for this asset — runtime visibility is required to validate the cutover and prove PQC adoption.',
        severity: 'medium',
        standard: 'NIST IR 8547 §5',
        effort: 'Low',
      })
    }
    if (!recommendations.length) {
      recommendations.push({
        id: 'rec-none',
        title: hasEvidence ? 'No migration action required' : 'Run a discovery scan for this asset',
        detail: hasEvidence
          ? 'All observed cryptography on this asset already meets NIST PQC standards. Keep monitoring for drift.'
          : 'No cryptographic evidence has been captured for this asset yet.',
        severity: 'low',
        standard: hasEvidence ? 'FIPS 203/204/205' : '—',
        effort: 'Low',
      })
    }

    /* ---- rollback ---- */
    const rollbackAvailable = hasEvidence
    const rollbackStrategy = {
      available: rollbackAvailable,
      strategy: hybridComponentCount > 0 || algorithms.some((a) => a.target.includes('hybrid') || a.target.includes('Hybrid'))
        ? 'Hybrid dual-stack rollback'
        : 'Configuration snapshot rollback',
      steps: rollbackAvailable
        ? [
            'Capture a pre-migration cryptographic snapshot (algorithms, certificates, configuration) with SHA3-256 integrity.',
            'Deploy the PQC stack in hybrid mode so classical peers keep negotiating during the window.',
            'Monitor runtime telemetry for handshake failures against the pre-cutover baseline.',
            'On regression, disable the PQC named group / revert to the snapshotted certificate chain.',
            'Re-validate the restored posture and record the rollback in the audit vault.',
          ]
        : ['No evidence captured — a rollback plan cannot be prepared until this asset is scanned.'],
      recoveryObjective: rollbackAvailable ? (internetFacing ? 'RTO ≤ 15 minutes (hybrid fallback)' : 'RTO ≤ 60 minutes') : EVIDENCE_UNAVAILABLE,
    }

    /* ---- approvals ---- */
    const requiredApprovals = [
      { role: 'Asset Owner', reason: `Accountable owner for ${str(asset.name) || 'this asset'} (${str(asset.service_owner) || 'Unassigned'}).`, required: true },
      { role: 'Security Engineering', reason: 'Validates the target PQC stack and the cryptographic control mapping.', required: true },
      {
        role: 'Change Advisory Board',
        reason: /prod/i.test(environment) ? 'Production change requires CAB approval before cutover.' : 'Non-production change — CAB approval optional.',
        required: /prod/i.test(environment),
      },
      {
        role: 'Compliance / GRC',
        reason: internetFacing ? 'Internet-facing transport cryptography is in regulatory scope.' : 'Internal asset — compliance sign-off advisory.',
        required: internetFacing,
      },
    ]

    /* ---- per-asset timeline ---- */
    const effort = estimatedEffortHours
    const timeline = effort
      ? [
          { phase: 'Assess', durationHours: Math.max(1, Math.round(effort * 0.15)), owner: 'Security Engineering', description: 'Confirm inventory, dependencies and target stack for this asset.' },
          { phase: 'Prepare', durationHours: Math.max(1, Math.round(effort * 0.2)), owner: str(asset.service_owner) || 'Asset Owner', description: 'Provision hybrid keys/certificates and stage configuration.' },
          { phase: 'Pilot', durationHours: Math.max(1, Math.round(effort * 0.2)), owner: 'Infrastructure Team', description: 'Enable the hybrid stack behind a compatibility gate and observe telemetry.' },
          { phase: 'Cutover', durationHours: Math.max(1, Math.round(effort * 0.25)), owner: 'Infrastructure Team', description: 'Promote the PQC stack to primary and retire classical-only paths.' },
          { phase: 'Validate', durationHours: Math.max(1, Math.round(effort * 0.2)), owner: 'Security Engineering', description: 'Prove PQC adoption from runtime telemetry and record compliance evidence.' },
        ]
      : []

    /* ---- crypto posture summary ---- */
    const topAlgorithms = algorithms.slice(0, 3).map((a) => a.algorithm)
    const cryptoPostureSummary = hasEvidence
      ? `${topAlgorithms.length ? topAlgorithms.join(', ') : 'No algorithms resolved'}${protocolList.length ? ` · ${protocolList[0]}` : ''} · ${vulnerableComponentCount}/${componentCount || 0} vulnerable`
      : EVIDENCE_UNAVAILABLE

    const downtime = !hasEvidence
      ? EVIDENCE_UNAVAILABLE
      : algorithms.some((a) => a.target.toLowerCase().includes('hybrid'))
        ? 'Near-zero — hybrid cutover keeps classical peers negotiating'
        : /prod/i.test(environment)
          ? 'Maintenance window required (est. 15–45 min)'
          : 'Rolling restart, no user-visible downtime expected'

    return {
      id,
      name: str(asset.name) || 'Unnamed asset',
      type: str(asset.type) || 'asset',
      hostname: hostnameFor(asset),
      environment,
      region: str(asset.region) || EVIDENCE_UNAVAILABLE,
      owner: str(asset.service_owner) || 'Unassigned',
      businessCriticality,
      tags: tagsFor(asset),
      internetFacing,
      discoveredAt: isoOrNull(asset.created_at),
      lastEvidenceAt: latest([
        isoOrNull(asset.updated_at),
        ...scans.map((r) => isoOrNull(r.created_at)),
        ...runtime.map((r) => isoOrNull(r.observed_at) || isoOrNull(r.created_at)),
        ...components.map((r) => isoOrNull(r.discovered_at) || isoOrNull(r.created_at)),
      ]),

      hasEvidence,
      riskScore,
      riskLevel: levelFromRisk(riskScore),
      readinessScore,
      readinessLevel: levelFromReadiness(readinessScore),
      posture,
      postureLabel: postureLabel(posture),
      priority,
      priorityScore,
      hndlScore,
      hndlLevel: levelFromRisk(hndlScore),
      successProbabilityPct,

      migrationStatus: state.status,
      migrationProgressPct: state.progress,
      migrationStatusDetail: state.detail,
      estimatedEffortHours,
      estimatedDurationLabel: durationLabel(estimatedEffortHours),
      estimatedDowntime: downtime,
      queued: queued.has(id),

      cryptoPostureSummary,
      componentCount,
      vulnerableComponentCount,
      pqcComponentCount,
      hybridComponentCount,
      algorithms,
      certificates,
      tlsConfiguration,

      findings,
      severityCounts,
      dependencies,
      blastRadius,
      priorityFactors,
      riskAnalysis: {
        categories: riskCategories,
        overall: overallRisk,
        overallLevel: levelFromRisk(overallRisk),
        explanation: hasEvidence
          ? `Migration risk for this asset scores ${overallRisk}/100, driven primarily by ${topCategory.label.toLowerCase()} (${topCategory.score}/100). ${vulnerableComponentCount} of ${componentCount} cryptographic component(s) are quantum-vulnerable, ${blastRadius} dependency relationship(s) are in the blast radius, and the asset is ${internetFacing ? 'internet-facing' : 'internal only'}.`
          : `${EVIDENCE_UNAVAILABLE}. Scan this asset to compute its migration risk.`,
      },
      businessImpact: {
        revenueImpact: internetFacing && criticalityScore(businessCriticality) >= 78 ? 'High' : internetFacing ? 'Medium' : 'Low',
        operationalImpact: blastRadius > 6 ? 'High' : blastRadius > 2 ? 'Medium' : 'Low',
        complianceImpact: unsupportedScore >= 100 ? 'High' : vulnerableComponentCount > 0 ? 'Medium' : 'Low',
        customerFacing: internetFacing,
        dependents,
        summary: hasEvidence
          ? `${dependents} asset(s) depend on this ${str(asset.type) || 'asset'}. ${internetFacing ? 'It is customer-facing, so migration must preserve availability.' : 'It is internal, so a maintenance window is available.'}`
          : EVIDENCE_UNAVAILABLE,
      },
      compatibility: {
        level: compatibilityScore >= 75 ? 'High' : compatibilityScore >= 50 ? 'Medium' : compatibilityScore > 0 ? 'Low' : 'Unknown',
        score: compatibilityScore,
        notes: compatibilityNotes.length ? compatibilityNotes : ['No compatibility blockers detected for the target PQC stack.'],
      },
      recommendations,
      rollbackStrategy,
      requiredApprovals,
      compliance: complianceFrameworksFor({
        evidenceRows: complianceRows,
        internetFacing,
        hasCertificates: certificates.length > 0,
        vulnerableComponents: vulnerableComponentCount,
        environment,
      }),
      timeline,
      validation: (() => {
        const blockerReason = !hasEvidence
          ? 'No cryptographic evidence — scan this asset first.'
          : state.status === 'Failed'
            ? 'A migration job for this asset failed and must be resolved.'
            : compatibilityScore < 50
              ? 'Compatibility risks must be cleared before cutover.'
              : ''
        return {
          records: validations.length,
          lastStatus: lastValidation ? str(lastValidation.status) || 'unknown' : 'Not validated',
          lastAt: lastValidation ? isoOrNull(lastValidation.created_at) : null,
          cutoverBlocked: blockerReason !== '',
          blockerReason,
          // Only a real passing validation record proves the asset is validated —
          // never inferred from the absence of blockers.
          validated: validations.some((v) => /pass|success|complete|valid/i.test(str(v.status))),
        }
      })(),
      jobs: jobs.slice(0, 10).map((job) => ({
        id: str(job.id),
        status: str(job.status) || 'unknown',
        progress: Math.round(clamp(num(job.progress))),
        jobType: str(job.job_type) || 'migration',
        targetAlgorithm: str(job.target_algorithm) || '—',
        updatedAt: str(job.updated_at) || str(job.created_at),
      })),
      evidence: {
        sources: [
          components.length ? 'CBOM (crypto_inventory)' : null,
          scans.length ? 'PQC Scanner' : null,
          exposures.length ? 'Crypto Exposures' : null,
          certs.length ? 'Certificate Inventory' : null,
          runtime.length ? 'Runtime Telemetry' : null,
          dependencyRows.length ? 'Trust Fabric' : null,
          jobs.length ? 'Migration Jobs' : null,
        ].filter((s): s is string => Boolean(s)),
        scanResults: scans.length,
        exposures: exposures.length,
        runtimeEvents: runtime.length,
        certificates: certs.length,
        components: componentCount,
        note: hasEvidence
          ? `Derived from ${componentCount} component(s), ${scans.length} scan finding(s), ${certs.length} certificate(s) and ${runtime.length} runtime event(s) bound to this asset.`
          : `${EVIDENCE_UNAVAILABLE}. This asset has been discovered but not yet cryptographically assessed.`,
      },
    }
  })

  /* ---- portfolio-level rollup ---- */
  const summary = {
    total: records.length,
    quantumVulnerable: records.filter((r) => r.posture === 'vulnerable').length,
    hybrid: records.filter((r) => r.posture === 'hybrid').length,
    pqcReady: records.filter((r) => r.posture === 'pqc').length,
    internetFacing: records.filter((r) => r.internetFacing).length,
    criticalPriority: records.filter((r) => r.priority === 'Critical').length,
    highPriority: records.filter((r) => r.priority === 'High').length,
    notStarted: records.filter((r) => r.migrationStatus === 'Not Started').length,
    inProgress: records.filter((r) => ['In Progress', 'Queued', 'Validating', 'Planned'].includes(r.migrationStatus)).length,
    completed: records.filter((r) => r.migrationStatus === 'Completed').length,
    queued: records.filter((r) => r.queued).length,
    averageReadiness: records.length ? Math.round(records.reduce((s, r) => s + r.readinessScore, 0) / records.length) : 0,
    totalEffortHours: records.reduce((s, r) => s + r.estimatedEffortHours, 0),
  }

  const recommendedOrder = [...records]
    .filter((r) => r.hasEvidence)
    .sort((a, b) => b.priorityScore - a.priorityScore || b.riskScore - a.riskScore || a.name.localeCompare(b.name))
    .slice(0, 25)
    .map((record, index) => {
      const top = [...record.priorityFactors].sort((a, b) => b.contribution - a.contribution)[0]
      return {
        rank: index + 1,
        assetId: record.id,
        name: record.name,
        priority: record.priority,
        priorityScore: record.priorityScore,
        riskScore: record.riskScore,
        rationale: top ? `${top.label} — ${top.evidence}` : 'Ranked by composite migration priority.',
      }
    })

  return {
    generatedAt: new Date(now).toISOString(),
    assets: records.sort((a, b) => b.priorityScore - a.priorityScore || b.riskScore - a.riskScore || a.name.localeCompare(b.name)),
    summary,
    recommendedOrder,
  }
}
