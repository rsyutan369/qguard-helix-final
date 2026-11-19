/**
 * Asset register — the ONE derivation behind /dashboard/assets and its reports.
 *
 * Pure and isomorphic (no React, no Supabase, no Express): the page panels, the
 * report builder and `tools/asset-register-check.ts` all call the same
 * functions, so a figure in an exported report is the figure on the screen by
 * construction rather than by two implementations happening to agree
 * (`qguard-data-integrity` rule 1).
 *
 * Inputs are the scanner-intelligence snapshot the page already streams, plus
 * the Quantum Readiness figures and workflow lifecycle it already loads. Nothing
 * here queries, samples or estimates: every count is a count of rows the scanner
 * persisted, every status is decided by rules written down below, and anything
 * the evidence cannot support is reported as unknown with a reason.
 */

import { isCryptographicComponent, normalizeFindingSubject } from '@/lib/scanner/finding-identity'
import { componentPosture, contradictoryFlags, type ComponentPosture } from '@/lib/scanner/asset-components'
import { algorithmFamily } from '@/lib/governance/subjects'
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'
import { UNASSESSED_BAND, pqcTargetFor, riskBandFor, type RiskBandKey } from '@/lib/migration/asset-intelligence'
import { STALE_AFTER_HOURS, describeAge } from '@/lib/dashboard-freshness'
import { assetScanSources, type AssetScanSource, type ScanSourceKind } from './scan-provenance'

/* ================================================================== */
/* Vocabulary                                                          */
/* ================================================================== */

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type SeverityOrUnrated = Severity | 'unrated'
export type PqcStatus = 'quantum-vulnerable' | 'pqc-ready' | 'needs-review' | 'not-measured'
export type FreshnessState = 'fresh' | 'aging' | 'stale' | 'unknown'
export type RegisterBandKey = RiskBandKey | 'unassessed'
export type ComponentClass =
  | 'cipher-suite'
  | 'key-exchange'
  | 'certificate'
  | 'signature'
  | 'symmetric'
  | 'hash'
  | 'protocol'
  | 'library'
  | 'other'

export const COMPONENT_CLASS_LABEL: Record<ComponentClass, string> = {
  'cipher-suite': 'Cipher suites',
  'key-exchange': 'Key exchange',
  certificate: 'Certificates',
  signature: 'Signatures',
  symmetric: 'Symmetric ciphers',
  hash: 'Hashes & MACs',
  protocol: 'Protocols',
  library: 'Crypto libraries',
  // Rows the component predicate admits (a crypto class prefix, or an
  // algorithm-like token in the title) but that name no primitive the canonical
  // decomposer can parse — in practice finding titles such as "Expired
  // Certificate" or "No Hybrid Crypto". They are counted, because the CBOM and
  // the QR Engine count them, but never labelled as if they were algorithms.
  other: 'Unparsed observations',
}

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low']

export const PQC_STATUS_META: Record<PqcStatus, { label: string; short: string; order: number }> = {
  'quantum-vulnerable': { label: 'Quantum-vulnerable', short: 'Vulnerable', order: 0 },
  'needs-review': { label: 'Needs review', short: 'Review', order: 1 },
  'not-measured': { label: 'Not measured', short: 'Not measured', order: 2 },
  'pqc-ready': { label: 'PQC-ready (scanner-validated)', short: 'PQC-ready', order: 3 },
}

/** Canonical bands, highest first, plus the explicit "not assessed" state. */
export const REGISTER_BANDS: ReadonlyArray<{ key: RegisterBandKey; label: string; hex: string }> = [
  { key: 'critical', label: 'Critical', hex: '#ef4444' },
  { key: 'high', label: 'High', hex: '#f97316' },
  { key: 'elevated', label: 'Elevated', hex: '#f59e0b' },
  { key: 'moderate', label: 'Moderate', hex: '#eab308' },
  { key: 'low', label: 'Low', hex: '#22c55e' },
  { key: 'minimal', label: 'Minimal', hex: '#10b981' },
  { key: 'unassessed', label: UNASSESSED_BAND.label, hex: UNASSESSED_BAND.hex },
]

/** Freshness boundaries. "Stale" is the platform-wide threshold, not a local one. */
export const FRESH_WITHIN_HOURS = 24
export { STALE_AFTER_HOURS }

/* ================================================================== */
/* Inputs — the scanner payload, loosely typed on purpose              */
/* ================================================================== */

type Loose = Record<string, unknown>

export interface RegisterSnapshotInput {
  generatedAt?: string | null
  summary: {
    totalAssets?: number
    totalComponents?: number
    vulnerableComponents?: number
    pqcReadyComponents?: number
    vulnerableAssets?: number
    criticalFindings?: number
    totalFindings?: number
    activeScans?: number
    [key: string]: unknown
  }
  severityCounts?: { critical?: number; high?: number; medium?: number; low?: number; safe?: number }
  assets: { assets: unknown[] }
  history?: { history: unknown[] }
}

/** Quantum Readiness figures the page already loads (null while unavailable). */
export interface RegisterQrInput {
  /** The QR request answered (successfully). */
  resolved: boolean
  hasData: boolean
  readiness: number | null
  readinessLevel: string | null
  risk: number | null
  components: number | null
  vulnerableComponents: number | null
}

export interface RegisterWorkflowState {
  asset: string
  stageId?: string
  /** The workflow engine's own label for its stage — preferred over any local mapping. */
  stageLabel?: string
  stage?: string
  openActions?: number
  validationStatus?: string
  certificationImpactPct?: number
  migrationStatus?: string
}

export interface RegisterInput {
  snapshot: RegisterSnapshotInput
  qr?: RegisterQrInput | null
  workflowStates?: RegisterWorkflowState[] | null
  /** Injected clock — the check tools pin it; the page passes Date.now(). */
  now?: number
}

/* ================================================================== */
/* Output model                                                        */
/* ================================================================== */

export interface RegisterComponent {
  id: string
  name: string
  algorithm: string
  /** What the component is, from the canonical decomposer (suite-anatomy.ts). */
  componentClass: ComponentClass
  classLabel: string
  /**
   * The primitive that carries the quantum risk — "ECDHE + RSA" for a TLS 1.2
   * suite, not the SHA-256 in its MAC. Grouping a suite by whichever primitive
   * a pattern hits first is how "SHA-2: 10 of 11 vulnerable" gets published.
   */
  riskBearing: string
  type: string
  keySize: string | null
  protocol: string | null
  posture: ComponentPosture
  severity: SeverityOrUnrated | 'safe'
  evidence: string | null
  recommendation: string | null
  observedSubject: string | null
  location: string | null
  /** NIST PQC target, consistent with the component's role (see `resolvePqcTarget`). */
  pqcReplacement: string | null
  /**
   * Where the target came from: `scanner` (stored, role-consistent), `corrected`
   * (the stored target named the wrong primitive class — e.g. a KEM for a
   * signature), `derived` (none stored; canonical mapping), `none` (not needed).
   */
  pqcTargetSource: 'scanner' | 'corrected' | 'derived' | 'none'
  instances: number
  lastSeen: string | null
  remediationRoute: string
  contradictory: boolean
}

export interface AssetRegisterRow {
  id: string
  name: string
  type: string
  typeLabel: string
  sources: AssetScanSource[]
  deviceProfile: { agentId: string; hostname: string; subjects: number; resources: Array<{ name: string; type: string }> } | null
  target: string
  host: string
  status: string
  /** Accountable owner from the asset record; null = not recorded (rendered "Unassigned"). */
  owner: string | null
  environment: string | null
  region: string | null
  criticality: string | null
  internetFacing: boolean
  tlsVersion: string | null
  riskScore: number | null
  risk: { key: RegisterBandKey; label: string; hex: string }
  riskSource: 'scanner'
  pqcStatus: PqcStatus
  pqcStatusLabel: string
  pqcStatusReason: string
  components: { total: number; vulnerable: number; pqcReady: number; unclassified: number; instances: number }
  vulnerableSeverity: Record<SeverityOrUnrated, number>
  worstComponentSeverity: Severity | null
  posture: { total: number; flagged: number }
  detectionSignals: number
  algorithms: string[]
  componentList: RegisterComponent[]
  postureList: RegisterComponent[]
  lastScanned: string | null
  lastScannedMs: number | null
  freshness: { state: FreshnessState; ageHours: number | null; label: string }
  scanning: { active: boolean; progress: number | null; status: string | null }
  lifecycle: { stageId: string; label: string; openActions: number; validationStatus: string; certificationImpactPct: number } | null
  contradictoryFlags: number
  evidenceOnly: boolean
  partialAssessment?: boolean
}

export interface RegisterTotals {
  assets: number
  pqcStatus: Record<PqcStatus, number>
  bands: Record<RegisterBandKey, number>
  components: { total: number; vulnerable: number; pqcReady: number; unclassified: number; instances: number }
  vulnerableSeverity: Record<SeverityOrUnrated, number>
  posture: { total: number; flagged: number }
  detectionSignals: number
  freshness: Record<FreshnessState, number>
  scanning: number
  owners: { assigned: number; unassigned: number }
  internetFacing: number
  risk: { assessed: number; mean: number | null; max: number | null; maxAsset: string | null }
  latestScan: string | null
  oldestScan: string | null
  classes: Array<{ key: ComponentClass; label: string; components: number; vulnerable: number; pqcReady: number; unclassified: number }>
  contradictoryFlags: number
}

export type CheckStatus = 'match' | 'diverged' | 'not-applicable'

export interface RegisterCheck {
  id: string
  label: string
  expected: string
  actual: string
  status: CheckStatus
  note: string
}

export interface QrReconciliation {
  state: 'awaiting' | 'no-evidence' | 'match' | 'diverged'
  label: string
  detail: string
}

export interface AssetRegister {
  generatedAt: string | null
  /** Newest observation across the estate — what "last scanned" means for the page. */
  measuredAt: string | null
  rows: AssetRegisterRow[]
  totals: RegisterTotals
  headline: {
    totalAssets: number
    totalComponents: number
    vulnerableComponents: number
    pqcReadyComponents: number
    vulnerableAssets: number
  }
  /** Components the CBOM counts that no asset in the register carries. */
  unattributed: { components: number; vulnerable: number; pqcReady: number }
  findings: { graded: number; total: number; safe: number; bySeverity: Record<Severity, number> }
  activeScans: number
  qr: QrReconciliation
  qrFigures: RegisterQrInput | null
  checks: RegisterCheck[]
}

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

const asRecord = (value: unknown): Loose => (value && typeof value === 'object' ? (value as Loose) : {})
const text = (value: unknown): string => (value === null || value === undefined ? '' : String(value).trim())
const finite = (value: unknown): number | null => {
  if (value === null || value === undefined || value === '') return null
  const n = Number(value)
  return Number.isFinite(n) ? n : null
}
const count = (value: unknown): number => {
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? Math.round(n) : 0
}

export function labelize(value: string): string {
  return (value || 'Unknown').replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export function normalizeSeverity(value: unknown): SeverityOrUnrated | 'safe' {
  const level = text(value).toLowerCase()
  if (!level) return 'unrated'
  if (level.includes('critical')) return 'critical'
  if (level.includes('high')) return 'high'
  if (level.includes('medium') || level.includes('moderate')) return 'medium'
  if (level.includes('low')) return 'low'
  if (level.includes('safe') || level.includes('none') || level.includes('info')) return 'safe'
  return 'unrated'
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }

function emptySeverity(): Record<SeverityOrUnrated, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 }
}

/**
 * Where a component is remediated. Mirrors the module that OWNS each class of
 * change, so a "Remediate" link lands on the workflow that can actually act.
 */
export function remediationRouteFor(component: { type?: string; protocol?: string | null; algorithm?: string; name?: string; evidence?: string | null }) {
  const haystack = [component.type, component.protocol, component.algorithm, component.name, component.evidence]
    .map((value) => text(value).toLowerCase())
    .join(' ')
  if (/hndl|harvest|runtime|shadow|downgrade/.test(haystack)) return '/dashboard/live-migration'
  if (/certificate|pki|x509|issuer|subject/.test(haystack)) return '/dashboard/certificate-telemetry'
  if (/tls|ssl|protocol|cipher|handshake|dhe|ecdhe/.test(haystack)) return '/dashboard/quantum-readiness/remediation'
  if (/library|dependency|package|source|repo|github|client crypto|web crypto/.test(haystack)) return '/dashboard/migration-planner'
  if (/policy|compliance|regulatory|nist/.test(haystack)) return '/dashboard/quantum-governance'
  return '/dashboard/pqc-orchestration'
}

const KEM_TARGET = /ML-?KEM|KYBER|FIPS\s*203/i
const SIGNATURE_TARGET = /ML-?DSA|SLH-?DSA|DILITHIUM|SPHINCS|FIPS\s*20[45]/i

/**
 * A PQC target consistent with what the component DOES.
 *
 * ML-KEM (FIPS 203) is key establishment only; certificates and signatures move
 * to ML-DSA / SLH-DSA (FIPS 204/205). Scans stored before the scanner fixed
 * this (common-issues #14) carry "ML-KEM-768 (FIPS 203)" on certificate
 * signatures, and repeating that in a register or a report would tell an owner
 * to replace a signature with a key-encapsulation mechanism. The stored target
 * is kept whenever it fits the role; otherwise the canonical mapping
 * (`pqcTargetFor`, shared with the QR Engine and the Migration Planner) answers,
 * and the correction is recorded rather than silent.
 */
export function resolvePqcTarget(
  kind: string,
  algorithm: string,
  stored: string | null,
  posture: ComponentPosture,
): { target: string | null; source: RegisterComponent['pqcTargetSource'] } {
  if (posture === 'pqc-ready') return { target: stored || null, source: stored ? 'scanner' : 'none' }
  const signatureRole = kind === 'signature' || kind === 'certificate'
  const keyRole = kind === 'key-exchange' || kind === 'cipher-suite'
  if (stored) {
    const wrongForSignature = signatureRole && KEM_TARGET.test(stored) && !SIGNATURE_TARGET.test(stored)
    const wrongForKey = keyRole && SIGNATURE_TARGET.test(stored) && !KEM_TARGET.test(stored)
    if (!wrongForSignature && !wrongForKey) return { target: stored, source: 'scanner' }
    const context = signatureRole ? 'certificate signature' : 'key exchange handshake'
    return { target: pqcTargetFor(algorithm, context).target, source: 'corrected' }
  }
  if (posture !== 'vulnerable') return { target: null, source: 'none' }
  const context = signatureRole ? 'certificate signature' : keyRole ? 'key exchange handshake' : ''
  return { target: pqcTargetFor(algorithm, context).target, source: 'derived' }
}

function toComponent(raw: unknown, assetId: string, index: number): RegisterComponent {
  const row = asRecord(raw)
  const metadata = asRecord(row.metadata)
  const algorithm = text(row.algorithm) || text(metadata.algorithm) || text(row.name) || 'Unknown'
  const name = text(row.name) || algorithm
  const type = text(row.item_type) || text(metadata.category) || 'cryptography'
  const anatomy = analyzeCryptoObservation({ algorithm, name, itemType: type, protocol: row.protocol }, true)
  const componentClass: ComponentClass = type.toLowerCase() === 'library'
    ? 'library'
    : anatomy.kind === 'policy'
      ? 'other'
      : anatomy.kind
  const posture = componentPosture({ is_vulnerable: Boolean(row.is_vulnerable), is_quantum_safe: Boolean(row.is_quantum_safe) })
  const severity = posture === 'pqc-ready' ? 'safe' : normalizeSeverity(row.exposure_level ?? metadata.severity ?? metadata.threatLevel)
  const evidence = text(metadata.evidence) || null
  const recommendation = text(metadata.recommendation) || null
  const keySize = text(row.key_size ?? metadata.keySize) || null
  const protocol = text(row.protocol ?? metadata.protocol) || null
  const observed = asRecord(metadata.evidenceRecord)
  const target = resolvePqcTarget(anatomy.kind, algorithm, text(metadata.pqcReplacement) || null, posture)
  return {
    id: text(row.id) || `${assetId}-component-${index}`,
    name,
    algorithm,
    componentClass,
    classLabel: COMPONENT_CLASS_LABEL[componentClass],
    riskBearing: anatomy.family || algorithm,
    type,
    keySize,
    protocol,
    posture,
    // A vulnerable component the scanner did not grade stays UNRATED — it is not
    // quietly promoted to "medium", which would invent a severity.
    severity: posture === 'vulnerable' && severity === 'safe' ? 'unrated' : severity,
    evidence,
    recommendation,
    observedSubject: text(metadata.discoveredTarget) || text(observed.assetName || observed.asset_name) || null,
    location: text(observed.filePath || observed.file_path) || text(observed.target) || null,
    pqcReplacement: target.target,
    pqcTargetSource: target.source,
    instances: Math.max(1, count(row.instances) || 1),
    lastSeen: text(row.last_seen_at) || text(row.discovered_at) || text(row.created_at) || null,
    remediationRoute: remediationRouteFor({ type, protocol, algorithm, name, evidence }),
    contradictory: contradictoryFlags({ is_vulnerable: Boolean(row.is_vulnerable), is_quantum_safe: Boolean(row.is_quantum_safe) }),
  }
}

const COMPONENT_ORDER: Record<ComponentPosture, number> = { vulnerable: 0, unclassified: 1, 'pqc-ready': 2 }

function byUrgency(a: RegisterComponent, b: RegisterComponent) {
  const posture = COMPONENT_ORDER[a.posture] - COMPONENT_ORDER[b.posture]
  if (posture) return posture
  const severity = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
  if (severity) return severity
  return (Date.parse(b.lastSeen || '') || 0) - (Date.parse(a.lastSeen || '') || 0)
}

function freshnessFor(lastScannedMs: number | null, now: number) {
  if (!lastScannedMs) return { state: 'unknown' as const, ageHours: null, label: 'No scan timestamp' }
  const ageHours = Math.max(0, (now - lastScannedMs) / 36e5)
  const state: FreshnessState = ageHours <= FRESH_WITHIN_HOURS ? 'fresh' : ageHours <= STALE_AFTER_HOURS ? 'aging' : 'stale'
  return { state, ageHours, label: `${describeAge(ageHours)} ago` }
}

function pqcStatusFor(counts: AssetRegisterRow['components'], worst: Severity | null, postureTotal: number): { status: PqcStatus; reason: string } {
  const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? '' : 's'}`
  if (counts.total === 0) {
    return {
      status: 'not-measured',
      reason: postureTotal > 0
        ? `No cryptographic components measured yet — ${plural(postureTotal, 'configuration observation')} recorded. Rescan to inventory its cryptography.`
        : 'No cryptographic components measured yet. Run an authorized scan to inventory its cryptography.',
    }
  }
  if (counts.vulnerable > 0) {
    return {
      status: 'quantum-vulnerable',
      reason: `${counts.vulnerable} of ${plural(counts.total, 'measured component')} use quantum-vulnerable cryptography${worst ? ` (worst: ${labelize(worst)})` : ''}.`,
    }
  }
  if (counts.pqcReady === counts.total) {
    return {
      status: 'pqc-ready',
      reason: `All ${plural(counts.total, 'measured component')} are classified quantum-safe by the scanner.`,
    }
  }
  return {
    status: 'needs-review',
    reason: `${counts.unclassified} of ${plural(counts.total, 'component')} could not be classified as quantum-safe or vulnerable — manual review required.`,
  }
}

const LIFECYCLE_LABEL: Record<string, string> = {
  monitoring: 'Monitored',
  execution: 'Migrating',
  validation: 'Validating',
}

/* ================================================================== */
/* Row derivation                                                      */
/* ================================================================== */

function deriveRow(
  raw: unknown,
  index: number,
  now: number,
  activeScans: Array<{ hosts: string[]; progress: number | null; status: string }>,
  lifecycleByKey: Map<string, RegisterWorkflowState>,
): AssetRegisterRow {
  const asset = asRecord(raw)
  const metadata = asRecord(asset.metadata)
  const deviceProfile = asRecord(metadata.deviceProfile)
  const resources = new Map<string, { name: string; type: string }>()
  for (const item of Array.isArray(deviceProfile.subjects) ? deviceProfile.subjects : []) {
    const resource = asRecord(item)
    if (text(resource.name)) resources.set(text(resource.name), { name: text(resource.name), type: labelize(text(resource.type) || 'observed resource') })
  }
  for (const name of Object.keys(asRecord(asRecord(metadata.agentBinding).targetRisk))) if (!resources.has(name)) resources.set(name, { name, type: 'Observed resource' })
  const id = text(asset.id) || `asset-${index}`
  const name = text(asset.name) || 'Unnamed asset'
  const type = text(asset.type) || 'asset'
  const target = text(asset.url) || text(asset.domain) || text(asset.ipAddress) || name
  const host = normalizeFindingSubject(target) || normalizeFindingSubject(name) || name.toLowerCase()

  // Components: cryptography only. A snapshot produced before the API split
  // components from findings (e.g. a cached one) still carries finding rows in
  // `cryptoInventory`; they are routed to posture here with the SAME predicate
  // the API uses, so the page is right even before the server answers.
  const inventory = Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory : []
  const classify = (raw: string) => algorithmFamily(raw)
  const componentRows = inventory.filter((row) => isCryptographicComponent(asRecord(row), classify))
  const strayFindingRows = inventory.filter((row) => !isCryptographicComponent(asRecord(row), classify))
  const postureRows = [...(Array.isArray(asset.postureObservations) ? asset.postureObservations : []), ...strayFindingRows]

  const componentList = componentRows.map((row, i) => toComponent(row, id, i)).sort(byUrgency)
  const postureList = postureRows.map((row, i) => toComponent(row, `${id}-posture`, i)).sort(byUrgency)

  const components = {
    total: componentList.length,
    vulnerable: componentList.filter((c) => c.posture === 'vulnerable').length,
    pqcReady: componentList.filter((c) => c.posture === 'pqc-ready').length,
    unclassified: componentList.filter((c) => c.posture === 'unclassified').length,
    instances: componentList.reduce((sum, c) => sum + c.instances, 0),
  }
  const vulnerableSeverity = emptySeverity()
  let worst: Severity | null = null
  for (const component of componentList) {
    if (component.posture !== 'vulnerable') continue
    const key = component.severity === 'safe' ? 'unrated' : component.severity
    vulnerableSeverity[key] += 1
    if (key !== 'unrated' && (!worst || SEVERITY_RANK[key] > SEVERITY_RANK[worst])) worst = key
  }

  const postureFlagged = postureList.filter((c) => c.posture === 'vulnerable').length
  const detectionSignals = Array.isArray(asset.vulnerabilities) ? asset.vulnerabilities.length : count(asset.findingSignalCount)

  // Risk: the scanner's per-asset score, banded by the CANONICAL table. An asset
  // with no evidence at all is "Not Assessed" — never a green Minimal band.
  const evidenceExists = components.total + postureList.length + detectionSignals > 0 || finite(metadata.riskScore) !== null
  const partialAssessment = metadata.partialAssessment === true
  const riskScore = evidenceExists && !partialAssessment ? finite(asset.riskScore) : null
  const band = riskScore === null ? UNASSESSED_BAND : riskBandFor(riskScore)

  const { status: pqcStatus, reason: pqcStatusReason } = pqcStatusFor(components, worst, postureList.length)

  // `lastScannedSource: 'asset-record'` means the API found no scan evidence and
  // fell back to when the asset ROW was written — that is not a scan, and
  // reporting it as "scanned 3d ago" would present an unmeasured asset as
  // recently measured.
  const lastScannedMs = text(asset.lastScannedSource) === 'asset-record' ? null : Date.parse(text(asset.lastScanned)) || null
  const freshness = freshnessFor(lastScannedMs, now)

  const scan = activeScans.find((entry) => entry.hosts.includes(host))
  const lifecycleState = lifecycleByKey.get(name.toLowerCase()) || lifecycleByKey.get(host)
  const stageId = text(lifecycleState?.stageId) || text(lifecycleState?.stage)
  const lifecycle = lifecycleState
    ? {
        stageId: stageId || 'unknown',
        // The engine's own label for all 11 stages. The page used to collapse
        // every stage other than monitoring/execution/validation into
        // "Remediation", misreporting discovery- and planning-stage assets.
        label: text(lifecycleState.stageLabel) || LIFECYCLE_LABEL[stageId] || labelize(stageId || 'unknown'),
        openActions: count(lifecycleState.openActions),
        validationStatus: text(lifecycleState.validationStatus) || 'Pending',
        certificationImpactPct: count(lifecycleState.certificationImpactPct),
      }
    : null

  return {
    id,
    name,
    type,
    typeLabel: labelize(type),
    sources: assetScanSources(asset),
    deviceProfile: metadata.deviceProfile ? { agentId: text(deviceProfile.agentId), hostname: text(deviceProfile.hostname), subjects: resources.size, resources: [...resources.values()].sort((a, b) => a.name.localeCompare(b.name)) } : null,
    target,
    host,
    status: text(asset.status) || 'active',
    owner: text(asset.owner) || null,
    environment: text(asset.environment) || null,
    region: text(asset.region) || null,
    criticality: text(asset.criticality) || null,
    internetFacing: asset.internetFacing === true,
    tlsVersion: text(asset.tlsVersion) || text(metadata.tlsVersion) || null,
    riskScore,
    risk: { key: band.key as RegisterBandKey, label: band.label, hex: band.hex },
    riskSource: 'scanner',
    pqcStatus,
    pqcStatusLabel: PQC_STATUS_META[pqcStatus].label,
    pqcStatusReason,
    components,
    vulnerableSeverity,
    worstComponentSeverity: worst,
    posture: { total: postureList.length, flagged: postureFlagged },
    detectionSignals,
    algorithms: Array.from(new Set(componentList.map((c) => c.algorithm))),
    componentList,
    postureList,
    lastScanned: lastScannedMs ? new Date(lastScannedMs).toISOString() : null,
    lastScannedMs,
    freshness,
    scanning: { active: Boolean(scan), progress: scan?.progress ?? null, status: scan?.status ?? null },
    lifecycle,
    contradictoryFlags: componentList.filter((c) => c.contradictory).length,
    evidenceOnly: Boolean(metadata.generatedFromScannerEvidence),
    partialAssessment,
  }
}

/* ================================================================== */
/* Totals — for ANY subset of rows                                     */
/* ================================================================== */

/**
 * Totals over a set of rows. The page calls it with every row; the report
 * builder calls it with the SELECTED rows. Same function, so a selection's
 * figures are computed exactly the way the page computes the estate's.
 */
export function summarizeRows(rows: AssetRegisterRow[]): RegisterTotals {
  const pqcStatus: Record<PqcStatus, number> = { 'quantum-vulnerable': 0, 'pqc-ready': 0, 'needs-review': 0, 'not-measured': 0 }
  const bands = Object.fromEntries(REGISTER_BANDS.map((band) => [band.key, 0])) as Record<RegisterBandKey, number>
  const components = { total: 0, vulnerable: 0, pqcReady: 0, unclassified: 0, instances: 0 }
  const vulnerableSeverity = emptySeverity()
  const posture = { total: 0, flagged: 0 }
  const freshness: Record<FreshnessState, number> = { fresh: 0, aging: 0, stale: 0, unknown: 0 }
  const classes = new Map<ComponentClass, { key: ComponentClass; label: string; components: number; vulnerable: number; pqcReady: number; unclassified: number }>()
  let detectionSignals = 0
  let scanning = 0
  let ownersAssigned = 0
  let internetFacing = 0
  let contradictory = 0
  let riskSum = 0
  let riskAssessed = 0
  let riskMax: number | null = null
  let riskMaxAsset: string | null = null
  let latest = 0
  let oldest = 0

  for (const row of rows) {
    pqcStatus[row.pqcStatus] += 1
    bands[row.risk.key] += 1
    components.total += row.components.total
    components.vulnerable += row.components.vulnerable
    components.pqcReady += row.components.pqcReady
    components.unclassified += row.components.unclassified
    components.instances += row.components.instances
    for (const key of Object.keys(vulnerableSeverity) as SeverityOrUnrated[]) vulnerableSeverity[key] += row.vulnerableSeverity[key]
    posture.total += row.posture.total
    posture.flagged += row.posture.flagged
    freshness[row.freshness.state] += 1
    detectionSignals += row.detectionSignals
    if (row.scanning.active) scanning += 1
    if (row.owner) ownersAssigned += 1
    if (row.internetFacing) internetFacing += 1
    contradictory += row.contradictoryFlags
    if (row.riskScore !== null) {
      riskAssessed += 1
      riskSum += row.riskScore
      if (riskMax === null || row.riskScore > riskMax) {
        riskMax = row.riskScore
        riskMaxAsset = row.name
      }
    }
    if (row.lastScannedMs) {
      latest = Math.max(latest, row.lastScannedMs)
      oldest = oldest ? Math.min(oldest, row.lastScannedMs) : row.lastScannedMs
    }
    for (const component of row.componentList) {
      const entry = classes.get(component.componentClass) || { key: component.componentClass, label: component.classLabel, components: 0, vulnerable: 0, pqcReady: 0, unclassified: 0 }
      entry.components += 1
      if (component.posture === 'vulnerable') entry.vulnerable += 1
      else if (component.posture === 'pqc-ready') entry.pqcReady += 1
      else entry.unclassified += 1
      classes.set(component.componentClass, entry)
    }
  }

  return {
    assets: rows.length,
    pqcStatus,
    bands,
    components,
    vulnerableSeverity,
    posture,
    detectionSignals,
    freshness,
    scanning,
    owners: { assigned: ownersAssigned, unassigned: rows.length - ownersAssigned },
    internetFacing,
    risk: {
      assessed: riskAssessed,
      mean: riskAssessed ? Math.round(riskSum / riskAssessed) : null,
      max: riskMax,
      maxAsset: riskMaxAsset,
    },
    latestScan: latest ? new Date(latest).toISOString() : null,
    oldestScan: oldest ? new Date(oldest).toISOString() : null,
    classes: Array.from(classes.values()).sort((a, b) => b.vulnerable - a.vulnerable || b.components - a.components || a.label.localeCompare(b.label)),
    contradictoryFlags: contradictory,
  }
}

/* ================================================================== */
/* Register                                                            */
/* ================================================================== */

function activeScanEntries(history: unknown[]) {
  return history
    .map(asRecord)
    .filter((entry) => ['queued', 'running', 'analyzing'].includes(text(entry.status).toLowerCase()))
    .map((entry) => ({
      hosts: text(entry.target)
        .split(',')
        .map((part) => normalizeFindingSubject(part.trim()))
        .filter(Boolean),
      progress: finite(entry.liveProgress),
      status: text(entry.status).toLowerCase(),
    }))
}

function qrReconciliation(qr: RegisterQrInput | null | undefined, headline: AssetRegister['headline']): QrReconciliation {
  if (!qr || !qr.resolved) {
    return { state: 'awaiting', label: 'Awaiting Quantum Readiness Engine', detail: 'The Quantum Readiness assessment has not answered yet.' }
  }
  if (!qr.hasData || qr.components === null) {
    return { state: 'no-evidence', label: 'No QR assessment evidence', detail: 'The Quantum Readiness Engine has no assessment for this tenant yet.' }
  }
  const same = qr.components === headline.totalComponents && qr.vulnerableComponents === headline.vulnerableComponents
  return same
    ? {
        state: 'match',
        label: 'Reconciled with Quantum Readiness Engine',
        detail: `Both engines count ${headline.totalComponents} cryptographic components, ${headline.vulnerableComponents} quantum-vulnerable.`,
      }
    : {
        state: 'diverged',
        label: 'Diverged from Quantum Readiness Engine',
        detail: `Asset register: ${headline.totalComponents} components / ${headline.vulnerableComponents} vulnerable. QR Engine: ${qr.components} / ${qr.vulnerableComponents ?? '—'}. Both are shown; neither is substituted for the other.`,
      }
}

export function buildAssetRegister(input: RegisterInput): AssetRegister {
  const now = input.now ?? Date.now()
  const snapshot = input.snapshot
  const summary = snapshot.summary || {}
  const history = Array.isArray(snapshot.history?.history) ? snapshot.history!.history : []
  const activeScans = activeScanEntries(history)
  const lifecycleByKey = new Map<string, RegisterWorkflowState>()
  for (const state of input.workflowStates || []) {
    const key = text(state.asset).toLowerCase()
    if (!key) continue
    lifecycleByKey.set(key, state)
    const host = normalizeFindingSubject(key)
    if (host && !lifecycleByKey.has(host)) lifecycleByKey.set(host, state)
  }

  const rawAssets = Array.isArray(snapshot.assets?.assets) ? snapshot.assets.assets : []
  const rows = rawAssets.map((asset, index) => deriveRow(asset, index, now, activeScans, lifecycleByKey))
  const totals = summarizeRows(rows)

  const headline = {
    totalAssets: count(summary.totalAssets) || rows.length,
    totalComponents: count(summary.totalComponents),
    vulnerableComponents: count(summary.vulnerableComponents),
    pqcReadyComponents: count(summary.pqcReadyComponents),
    vulnerableAssets: count(summary.vulnerableAssets),
  }
  const unattributed = {
    components: Math.max(0, headline.totalComponents - totals.components.total),
    vulnerable: Math.max(0, headline.vulnerableComponents - totals.components.vulnerable),
    pqcReady: Math.max(0, headline.pqcReadyComponents - totals.components.pqcReady),
  }

  const severity = snapshot.severityCounts || {}
  const bySeverity = { critical: count(severity.critical), high: count(severity.high), medium: count(severity.medium), low: count(severity.low) }
  const graded = bySeverity.critical + bySeverity.high + bySeverity.medium + bySeverity.low

  const checks: RegisterCheck[] = []
  const addCheck = (id: string, label: string, expected: number, actual: number, note: string) => {
    checks.push({ id, label, expected: String(expected), actual: String(actual), status: expected === actual ? 'match' : 'diverged', note })
  }
  addCheck('assets', 'Assets in register = assets reported by the scanner', headline.totalAssets, rows.length, 'Every asset the scanner reports appears as exactly one register row.')
  addCheck(
    'components',
    'Σ per-asset components + unattributed = CBOM components',
    headline.totalComponents,
    totals.components.total + unattributed.components,
    unattributed.components > 0
      ? `${unattributed.components} CBOM component(s) are not attributed to any asset in the register.`
      : 'Every CBOM component belongs to exactly one asset row.',
  )
  addCheck(
    'vulnerable',
    'Σ per-asset quantum-vulnerable = CBOM quantum-vulnerable',
    headline.vulnerableComponents,
    totals.components.vulnerable + unattributed.vulnerable,
    totals.contradictoryFlags > 0
      ? `${totals.contradictoryFlags} component(s) carry conflicting vulnerable and quantum-safe flags and require review.`
      : 'Counted at the component level — the unit the CBOM Explorer and QR Engine use.',
  )
  addCheck('pqc-ready', 'Σ per-asset PQC-ready = CBOM PQC-ready', headline.pqcReadyComponents, totals.components.pqcReady + unattributed.pqcReady, 'Only components the scanner classified quantum-safe are counted.')
  addCheck(
    'partition',
    'Vulnerable + PQC-ready + unclassified = components',
    totals.components.total,
    totals.components.vulnerable + totals.components.pqcReady + totals.components.unclassified,
    'Each component has exactly one posture, so the three counts partition the total.',
  )
  addCheck(
    'vulnerable-assets',
    'Assets with vulnerable cryptography = scanner headline',
    headline.vulnerableAssets,
    totals.pqcStatus['quantum-vulnerable'],
    'An asset is counted when at least one of its components is quantum-vulnerable.',
  )

  return {
    generatedAt: text(snapshot.generatedAt) || null,
    measuredAt: totals.latestScan,
    rows,
    totals,
    headline,
    unattributed,
    findings: { graded, total: count(summary.totalFindings), safe: count(severity.safe), bySeverity },
    activeScans: count(summary.activeScans) || activeScans.length,
    qr: qrReconciliation(input.qr, headline),
    qrFigures: input.qr ?? null,
    checks,
  }
}

/* ================================================================== */
/* Filtering and ordering — shared by the table and the report scope   */
/* ================================================================== */

export type RegisterSort = 'risk' | 'vulnerable' | 'last-scanned' | 'name'

export interface RegisterFilter {
  agentId?: string | null
  sourceKind?: ScanSourceKind | null
  query?: string
  bands?: RegisterBandKey[] | null
  statuses?: PqcStatus[] | null
  freshness?: FreshnessState[] | null
}

export function filterRows(rows: AssetRegisterRow[], filter: RegisterFilter): AssetRegisterRow[] {
  const query = text(filter.query).toLowerCase()
  return rows.filter((row) => {
    if (filter.agentId && !row.sources.some((source) => source.agentId === filter.agentId)) return false
    if (filter.sourceKind && !row.sources.some((source) => source.kind === filter.sourceKind)) return false
    if (filter.bands?.length && !filter.bands.includes(row.risk.key)) return false
    if (filter.statuses?.length && !filter.statuses.includes(row.pqcStatus)) return false
    if (filter.freshness?.length && !filter.freshness.includes(row.freshness.state)) return false
    if (!query) return true
    const haystack = [
      row.name,
      row.typeLabel,
      row.target,
      row.host,
      row.pqcStatusLabel,
      row.risk.label,
      row.owner,
      row.environment,
      ...row.sources.flatMap((source) => [source.label, source.agentName, source.collectorHost, source.collectorPlatform]),
      row.lifecycle?.label,
      ...row.algorithms,
      ...row.componentList.flatMap((c) => [c.name, c.classLabel, c.riskBearing, c.evidence, c.recommendation, c.pqcReplacement]),
    ]
    return haystack.some((value) => text(value).toLowerCase().includes(query))
  })
}

export function sortRows(rows: AssetRegisterRow[], sort: RegisterSort): AssetRegisterRow[] {
  const byName = (a: AssetRegisterRow, b: AssetRegisterRow) => a.name.localeCompare(b.name)
  const copy = [...rows]
  switch (sort) {
    case 'vulnerable':
      return copy.sort((a, b) => b.components.vulnerable - a.components.vulnerable || (b.riskScore ?? -1) - (a.riskScore ?? -1) || byName(a, b))
    case 'last-scanned':
      return copy.sort((a, b) => (b.lastScannedMs || 0) - (a.lastScannedMs || 0) || byName(a, b))
    case 'name':
      return copy.sort(byName)
    case 'risk':
    default:
      return copy.sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1) || b.components.vulnerable - a.components.vulnerable || byName(a, b))
  }
}
