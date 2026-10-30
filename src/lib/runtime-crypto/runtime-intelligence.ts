/**
 * Runtime Cryptographic Intelligence — the pure derivation engine.
 *
 * ── What this module is for ─────────────────────────────────────────────────
 * The Runtime Crypto Intelligence dashboard answers five questions and nothing
 * else:
 *
 *     1. What cryptography is actually running?
 *     2. Is it quantum-safe?
 *     3. What is wrong?
 *     4. What should be fixed first?
 *     5. Did the migration actually change runtime behaviour?
 *
 * It is a runtime VISIBILITY layer, not a second SIEM and not a second copy of
 * the discovery, HNDL, planner or remediation engines. Where another module
 * already owns a number, this engine consumes that number rather than deriving
 * a rival one:
 *
 *   • estate posture, PQC adoption, quantum + HNDL risk scores  → QR snapshot
 *   • per-asset criticality, exposure, migration state, dossier → asset portfolio
 *     (the SHARED asset-intelligence engine behind the Migration Planner)
 *   • algorithm decomposition                                   → suite-anatomy
 *
 * The only thing derived HERE is what runtime evidence — and nothing but
 * runtime evidence — says about live cryptographic behaviour.
 *
 * ── Two rules that shape every function below ──────────────────────────────
 *
 * 1. RUNTIME MEANS RUNTIME. The population is `runtime_crypto_events` and
 *    nothing else. The previous implementation silently substituted scan
 *    findings, certificates, vault logs and migration jobs when no runtime
 *    telemetry existed, and published the result as live runtime activity. A
 *    tenant with zero agents reported a busy runtime. When there is no runtime
 *    evidence this engine reports NO runtime evidence, and separately offers
 *    what discovery already knows — explicitly labelled as discovery.
 *
 * 2. CLASSIFY THE PRIMITIVE, NOT THE STRING. A TLS observation names up to four
 *    primitives across three columns; the quantum risk lives in the key
 *    agreement, which for TLS 1.3 is NOT in the cipher-suite name at all
 *    (`TLS_AES_256_GCM_SHA384` carries no key exchange). Every observation is
 *    decomposed with `analyzeCryptoObservation` and the verdict is taken from
 *    the risk-bearing primitive. Matching `/AES.?256/` against a suite string is
 *    what once published AES-256-GCM as a critical quantum vulnerability.
 *
 * Pure and dependency-free (no Supabase, no Express) so the server, the browser
 * and `tools/runtime-crypto-intel-check.ts` all read one model.
 */

import {
  analyzeCryptoObservation,
  type QuantumClass,
  type SuiteAnatomy,
} from '@/lib/crypto/suite-anatomy'
import {
  EVIDENCE_UNAVAILABLE,
  clamp,
  num,
  pqcTargetFor,
  recordOf,
  str,
  type AssetMigrationRecord,
  type Row,
} from '@/lib/migration/asset-intelligence'
import type { SourceRead } from '@/lib/source-read'
import { isSimulationRow } from '@/lib/migration/job-safety'

/* ================================================================== */
/* Vocabulary                                                          */
/* ================================================================== */

/** Quantum posture of a runtime observation. `unknown` NEVER reads as safe. */
export type QuantumStatus = QuantumClass

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low'

export type SecurityState = 'excellent' | 'good' | 'attention' | 'high-risk' | 'critical' | 'unknown'

export type TimeWindowKey = '15m' | '1h' | '24h' | '7d' | '30d'

export const TIME_WINDOWS: ReadonlyArray<{ key: TimeWindowKey; label: string; ms: number }> = [
  { key: '15m', label: 'Last 15 minutes', ms: 15 * 60_000 },
  { key: '1h', label: 'Last hour', ms: 60 * 60_000 },
  { key: '24h', label: 'Last 24 hours', ms: 24 * 60 * 60_000 },
  { key: '7d', label: 'Last 7 days', ms: 7 * 24 * 60 * 60_000 },
  { key: '30d', label: 'Last 30 days', ms: 30 * 24 * 60 * 60_000 },
]

export const DEFAULT_WINDOW: TimeWindowKey = '24h'

export function windowFor(key: string | null | undefined) {
  return TIME_WINDOWS.find((w) => w.key === key) ?? TIME_WINDOWS[2]
}

/**
 * User-facing status vocabulary (§5). Risk is never carried by colour alone —
 * every status ships a text label AND a glyph.
 */
export const STATUS_LABEL: Record<QuantumStatus, string> = {
  safe: 'Quantum Safe',
  hybrid: 'Hybrid PQC',
  vulnerable: 'Quantum Risk',
  unknown: 'Needs Review',
}

export const STATUS_GLYPH: Record<QuantumStatus, string> = {
  safe: '✓',
  hybrid: '✓',
  vulnerable: '●',
  unknown: '⚠',
}

/**
 * Plain-language explanation of WHY a posture is what it is (§30). Written for
 * an IT analyst, not a cryptographer.
 */
export const STATUS_WHY: Record<QuantumStatus, string> = {
  safe: 'This algorithm is on the NIST post-quantum list and is not broken by a future quantum computer.',
  hybrid: 'This connection combines a classical and a post-quantum algorithm, so it stays secure even if one of them is broken.',
  vulnerable: 'This algorithm is broken by a large-scale quantum computer. Traffic captured today can be decrypted later.',
  unknown: 'QGuard Helix could not determine which cryptographic primitive this observation used, so it cannot be confirmed safe.',
}

/* ================================================================== */
/* Model                                                               */
/* ================================================================== */

export interface RuntimeEventLinks {
  asset: string | null
  cbom: string
  quantumRisk: string
  hndl: string
  migration: string
}

/** Technical detail — hidden behind "View Technical Details" (§6). */
export interface RuntimeEventTechnical {
  eventId: string
  source: string
  sourceLabel: string
  observedAt: string | null
  host: string | null
  port: number | null
  protocol: string | null
  tlsVersion: string | null
  cipherSuite: string | null
  keyExchange: string | null
  signature: string | null
  bulkCipher: string | null
  mac: string | null
  keySize: number | null
  certificateFingerprint: string | null
  library: string | null
  process: string | null
  /** Sanitised free-form agent metadata — never key material or secrets (§22). */
  attributes: Array<{ label: string; value: string }>
}

export interface RuntimeEvent {
  id: string
  observedAt: string | null
  assetId: string | null
  assetName: string
  environment: string
  /** Friendly operation name: TLS, Signing, Key Exchange, Encryption… */
  operation: string
  /** Display algorithm — the family of the RISK-BEARING primitive. */
  algorithm: string
  /** Exactly what the agent reported, for the technical panel. */
  observedValue: string
  quantumStatus: QuantumStatus
  statusLabel: string
  statusGlyph: string
  risk: RiskLevel
  riskScore: number
  why: string
  recommendedAction: string
  /** NIST replacement for the risk-bearing primitive, when one is needed. */
  pqcTarget: string | null
  pqcStandard: string | null
  flags: {
    downgradeDetected: boolean
    shadowCrypto: boolean
    hndlRisk: boolean
    legacyReported: boolean
    pqcReported: boolean
  }
  priorityFactors: Array<{ label: string; contribution: number; evidence: string }>
  links: RuntimeEventLinks
  technical: RuntimeEventTechnical
}

export type IssueKind =
  | 'quantum-vulnerable'
  | 'pqc-fallback'
  | 'legacy-protocol'
  | 'shadow-crypto'
  | 'hndl-exposure'
  | 'unverified-crypto'
  | 'configuration-drift'

export interface RuntimeIssue {
  id: string
  kind: IssueKind
  /** "What happened" (§7). */
  title: string
  /** "Where" (§7). */
  assetId: string | null
  assetName: string
  environment: string
  severity: RiskLevel
  riskScore: number
  quantumStatus: QuantumStatus
  /** How many runtime observations support this issue. */
  observations: number
  firstSeen: string | null
  lastSeen: string | null
  /** "Risk" — why it matters, in plain language. */
  why: string
  /** "Recommended action" (§7). */
  recommendedAction: string
  actionLabel: string
  actionHref: string
  evidence: string[]
  priorityFactors: Array<{ label: string; contribution: number; evidence: string }>
  /** Representative event id, so the drawer can open the underlying evidence. */
  sampleEventId: string | null
}

export interface RuntimeMixRow {
  key: QuantumStatus
  label: string
  glyph: string
  count: number
  percent: number
}

export interface RuntimeKpis {
  /** Distinct runtime cryptographic observations in the window. */
  activity: number
  activityLabel: string
  activityDetail: string
  quantumSafePct: number | null
  hybridPct: number | null
  vulnerablePct: number | null
  unknownPct: number | null
  activeIssues: number
  criticalIssues: number
}

export interface RuntimeSecurityStatus {
  /** null when there is no runtime evidence — never 0 presented as fact. */
  score: number | null
  state: SecurityState
  stateLabel: string
  headline: string
  mix: RuntimeMixRow[]
  basis: string
  penaltyApplied: number
}

export interface ConfigurationLine {
  label: string
  expected: string
  actual: string | null
  match: 'match' | 'drift' | 'not-observed'
}

export interface RuntimeConfiguration {
  assetId: string | null
  assetName: string
  environment: string
  /** Where "expected" came from: an approved migration target or the baseline. */
  baselineSource: 'migration-target' | 'platform-baseline'
  baselineLabel: string
  status: 'matching' | 'drift' | 'partial'
  statusLabel: string
  lines: ConfigurationLine[]
  observations: number
  lastSeen: string | null
}

export interface MigrationVerification {
  jobId: string
  assetId: string | null
  assetName: string
  before: string | null
  after: string
  completedAt: string | null
  /** Runtime observations of the target primitive AFTER cutover. */
  sessionsVerified: number
  /** Post-cutover observations still using a classical primitive. */
  fallbacks: number
  status: 'confirmed' | 'fallback-detected' | 'not-observed'
  statusLabel: string
  detail: string
  href: string
}

export interface PqcAdoption {
  /** Runtime share — of observations in the window. */
  runtimeSafePct: number | null
  runtimeHybridPct: number | null
  runtimeClassicalPct: number | null
  runtimeUnknownPct: number | null
  /** Estate-wide adoption, straight from the Quantum Readiness snapshot. */
  estateAdoptionPct: number
  estateLabel: string
  /** Only present when BOTH comparison windows hold real observations. */
  trend: { deltaPct: number; label: string; basis: string } | null
  basis: string
}

export interface QuantumRiskCard {
  level: string
  score: number
  vulnerableSharePct: number | null
  headline: string
  /** Assets bucketed by their WORST runtime finding. One unit: assets. */
  breakdown: Array<{ key: string; label: string; glyph: string; count: number }>
  href: string
}

export interface HndlCard {
  highRiskAssets: number
  score: number
  level: string
  headline: string
  topAsset: { id: string | null; name: string; reason: string } | null
  href: string
}

export interface SophiaInsight {
  headline: string
  body: string
  recommendation: string
  evidence: string[]
  question: string
  actionHref: string
  hasFinding: boolean
}

/**
 * Why there is no runtime data — the three cases need different advice.
 *
 *   none              nothing has ever been enrolled. The user must deploy a
 *                     collector or connect a cloud provider.
 *   registered-silent a collector exists but has never sent an event. The
 *                     user must check it, not deploy another one.
 *   reporting         events are flowing.
 *
 * Collapsing the first two into one message sends a user who already has a
 * broken agent off to install a second one.
 */
export type CollectorState = 'none' | 'registered-silent' | 'reporting'

export interface RuntimeTelemetryState {
  /** `runtime` = live agent/connector evidence. `none` = nothing to monitor. */
  mode: 'runtime' | 'none'
  /** Distinguishes 'never configured' from 'configured but silent'. */
  collectorState: CollectorState
  hasRuntimeEvents: boolean
  totalRuntimeEvents: number
  eventsInWindow: number
  /** True when the tenant HAS telemetry but none landed inside the window. */
  windowEmpty: boolean
  latestEventAt: string | null
  oldestEventAt: string | null
  coveredAssets: number
  activeAgents: number
  totalAgents: number
  connectors: number
  sources: Array<{ label: string; count: number; percent: number }>
  /** Row cap hit — used to suppress trend claims that would be truncated. */
  truncated: boolean
}

/** What discovery knows when runtime telemetry is absent — labelled as such. */
export interface DiscoveryFallback {
  assetsAssessed: number
  cryptoComponents: number
  vulnerableComponents: number
  certificatesAnalyzed: number
  pqcAdoptionPct: number
  lastAssessmentAt: string | null
  note: string
}

export interface RuntimeCryptoIntelligence {
  /** Read outcome of every evidence source (published by the router; absent in pure fixtures). */
  reads?: SourceRead[]
  generatedAt: string
  window: { key: TimeWindowKey; label: string; ms: number }
  telemetry: RuntimeTelemetryState
  kpis: RuntimeKpis
  securityStatus: RuntimeSecurityStatus
  events: RuntimeEvent[]
  /** Total matching events before the display cap, so paging is honest. */
  eventTotal: number
  issues: RuntimeIssue[]
  attention: RuntimeIssue[]
  pqcAdoption: PqcAdoption
  configurations: RuntimeConfiguration[]
  migrationVerification: MigrationVerification[]
  quantumRisk: QuantumRiskCard
  hndl: HndlCard
  sophia: SophiaInsight
  filters: { environments: string[]; applications: string[] }
  discovery: DiscoveryFallback
  evidence: { sources: string[]; note: string }
}

/* ================================================================== */
/* Inputs                                                              */
/* ================================================================== */

export interface RuntimeSnapshotFacts {
  hasData: boolean
  lastAssessmentAt: string | null
  scores: {
    quantumReadiness: number
    pqcAdoption: number
    quantumRisk: number
    quantumRiskLevel: string
    hndlRisk: number
    hndlRiskLevel: string
  }
  inventory: {
    assetsAssessed: number
    cryptoComponents: number
    vulnerableComponents: number
    certificatesAnalyzed: number
  }
}

export interface RuntimeIntelInputs {
  snapshot: RuntimeSnapshotFacts
  /** Per-asset dossiers from the SHARED asset-intelligence engine. */
  assets: AssetMigrationRecord[]
  runtimeEvents: Row[]
  migrationJobs: Row[]
  scannerAgents: Row[]
  connectorAccounts: Row[]
  /** True when the runtime event query hit its row cap. */
  runtimeEventsTruncated?: boolean
  window?: TimeWindowKey
  /** Maximum events returned in the payload (the table pages the rest). */
  eventLimit?: number
  now?: number
}

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

const ms = (value: unknown): number => {
  const parsed = Date.parse(str(value))
  return Number.isFinite(parsed) ? parsed : 0
}

const iso = (value: unknown): string | null => {
  const text = str(value)
  return text && Number.isFinite(Date.parse(text)) ? new Date(text).toISOString() : null
}

const pct = (part: number, total: number): number => (total > 0 ? Math.round((part / total) * 100) : 0)

function titleCase(value: unknown): string {
  return str(value)
    .replace(/[_-]+/g, ' ')
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

/**
 * Secret-shaped keys are never forwarded to the browser (§22). The agent
 * ingest endpoint already rejects them; this is the second gate, because a
 * metadata blob written by an older agent or a connector must not become the
 * hole that leaks key material into a dashboard.
 */
const FORBIDDEN_METADATA = /priv|secret|passw|passphrase|token|credential|api[_-]?key|bearer|session|cookie|seed|entropy_pool|pem|pkcs|mnemonic|salt_value/i

/** Values that look like encoded key material, whatever the key is called. */
const KEY_MATERIAL_SHAPE = /-----BEGIN|^[A-Za-z0-9+/]{120,}={0,2}$|^(?:[0-9a-f]{2}:){15,}/i

function sanitizeAttributes(metadata: Record<string, unknown>): Array<{ label: string; value: string }> {
  const out: Array<{ label: string; value: string }> = []
  for (const [key, raw] of Object.entries(metadata)) {
    if (out.length >= 10) break
    if (FORBIDDEN_METADATA.test(key)) {
      out.push({ label: titleCase(key), value: 'REDACTED' })
      continue
    }
    if (raw === null || raw === undefined) continue
    if (typeof raw === 'object') continue
    const value = String(raw).trim()
    if (!value || value.length > 240) continue
    if (KEY_MATERIAL_SHAPE.test(value)) {
      out.push({ label: titleCase(key), value: 'REDACTED' })
      continue
    }
    out.push({ label: titleCase(key), value })
  }
  return out
}

/** Fingerprints are hashes, not secrets — but shown abbreviated, not in full. */
function shortFingerprint(value: unknown): string | null {
  const text = str(value).replace(/\s+/g, '')
  if (!text) return null
  return text.length > 24 ? `${text.slice(0, 12)}…${text.slice(-8)}` : text
}

/**
 * The asset identity every per-asset roll-up must agree on.
 *
 * Two traps live here. First, `str()` returns `''` rather than null, so `??`
 * never falls through it — `asset?.id ?? str(event.asset_name) ?? str(event.host)`
 * silently keys every host-only event on the empty string and merges them into
 * one phantom asset. Ordinary `||` is required. Second, coverage, the quantum-risk
 * breakdown, findings, configuration drift and HNDL exposure are ALL counted per
 * asset; if any two of them derive that key differently the page publishes totals
 * that cannot be reconciled. So they all call this.
 *
 * Returns `''` when nothing identifies the source, letting callers decide between
 * skipping it and bucketing it as unattributed.
 */
function assetKeyFor(event: Row, asset: AssetMigrationRecord | null): string {
  return asset?.id || str(event.asset_id) || str(event.asset_name) || str(event.host) || ''
}

/** Runtime frequency is counted per asset AND primitive family. */
function frequencyKeyFor(event: Row, asset: AssetMigrationRecord | null, family: string): string {
  return `${assetKeyFor(event, asset) || 'unattributed'}::${family}`
}

/* ================================================================== */
/* Observation decomposition                                           */
/* ================================================================== */

interface Decomposition {
  status: QuantumStatus
  /** Display family of the risk-bearing primitive. */
  family: string
  /** The exact string the verdict was taken from. */
  riskBearingValue: string
  keyExchange: SuiteAnatomy | null
  signature: SuiteAnatomy | null
  bulk: SuiteAnatomy | null
  protocolVersion: string | null
}

/** Worst-wins ordering. `unknown` outranks `hybrid`/`safe` but not `vulnerable`. */
const CLASS_RANK: Record<QuantumClass, number> = { vulnerable: 3, unknown: 2, hybrid: 1, safe: 0 }

/**
 * Decompose one runtime event into its primitives and take the verdict from
 * whichever primitive actually carries the quantum risk.
 *
 * The three columns are analysed SEPARATELY on purpose. A TLS 1.3 event stores
 * `cipher_suite = TLS_AES_256_GCM_SHA384` (bulk + MAC only) and the real key
 * agreement in `key_exchange_algorithm`. Reading the verdict off the suite
 * string alone scores a hybrid-PQ endpoint as if it had no key exchange, and
 * scores an AES-256 bulk cipher as the asset's whole posture.
 */
export function decomposeRuntimeEvent(event: Row): Decomposition {
  const cipherSuite = str(event.cipher_suite)
  const kexValue = str(event.key_exchange_algorithm)
  const algorithmValue = str(event.algorithm)
  const tlsVersion = str(event.tls_version)
  const protocol = str(event.protocol)

  const suite = cipherSuite ? analyzeCryptoObservation({ algorithm: cipherSuite, protocol }) : null
  const kexDirect = kexValue ? analyzeCryptoObservation({ algorithm: kexValue, protocol }) : null
  const algo = algorithmValue ? analyzeCryptoObservation({ algorithm: algorithmValue, protocol, itemType: str(event.asset_type) }) : null

  // Key agreement: an explicit key_exchange_algorithm always wins over whatever
  // the suite name happens to embed, because TLS 1.3 suites name no group.
  let keyExchange: SuiteAnatomy | null = null
  if (kexDirect && kexDirect.keyExchange) keyExchange = kexDirect
  else if (suite && suite.keyExchange) keyExchange = suite
  else if (algo && algo.keyExchange) keyExchange = algo

  let signature: SuiteAnatomy | null = null
  if (algo && algo.authentication) signature = algo
  else if (suite && suite.authentication) signature = suite
  else if (kexDirect && kexDirect.authentication) signature = kexDirect

  let bulk: SuiteAnatomy | null = null
  if (suite && suite.bulk) bulk = suite
  else if (algo && algo.bulk) bulk = algo

  const candidates: Array<{ anatomy: SuiteAnatomy; value: string }> = []
  if (keyExchange) candidates.push({ anatomy: keyExchange, value: keyExchange === kexDirect ? kexValue : keyExchange === suite ? cipherSuite : algorithmValue })
  if (signature) candidates.push({ anatomy: signature, value: signature === algo ? algorithmValue : signature === suite ? cipherSuite : kexValue })
  if (bulk) candidates.push({ anatomy: bulk, value: bulk === suite ? cipherSuite : algorithmValue })
  // A hash / protocol / policy observation still carries a verdict of its own.
  if (!candidates.length && algo) candidates.push({ anatomy: algo, value: algorithmValue })
  if (!candidates.length && suite) candidates.push({ anatomy: suite, value: cipherSuite })

  if (!candidates.length) {
    const fallbackValue = tlsVersion || protocol || str(event.event_type)
    return {
      status: 'unknown',
      family: fallbackValue ? titleCase(fallbackValue) : 'Unclassified observation',
      riskBearingValue: fallbackValue,
      keyExchange: null,
      signature: null,
      bulk: null,
      protocolVersion: tlsVersion || null,
    }
  }

  const worst = candidates.reduce((acc, item) =>
    CLASS_RANK[item.anatomy.quantumClass] > CLASS_RANK[acc.anatomy.quantumClass] ? item : acc,
  )

  return {
    status: worst.anatomy.quantumClass,
    family: worst.anatomy.family,
    riskBearingValue: worst.value || worst.anatomy.family,
    keyExchange,
    signature,
    bulk,
    protocolVersion: tlsVersion || null,
  }
}

/* ================================================================== */
/* Operation naming                                                    */
/* ================================================================== */

const OPERATION_LABELS: Array<[RegExp, string]> = [
  [/key[_\s-]?exchange|kex|handshake|kem/i, 'Key Exchange'],
  [/tls|https|ssl|transport/i, 'TLS'],
  [/sign|signature|jwt|dsa|attest/i, 'Signing'],
  [/verify|validation/i, 'Verification'],
  [/decrypt|unwrap/i, 'Decryption'],
  [/encrypt|cipher|wrap/i, 'Encryption'],
  [/rotate|rotation/i, 'Key Rotation'],
  [/key/i, 'Key Usage'],
  [/cert/i, 'Certificate'],
  [/package|library|dependency|module/i, 'Library Load'],
  [/ssh/i, 'SSH'],
  [/vpn|ipsec|ike/i, 'VPN'],
]

function operationLabel(event: Row): string {
  const haystack = `${str(event.operation_type)} ${str(event.event_type)} ${str(event.protocol)} ${str(event.tls_version)}`
  for (const [pattern, label] of OPERATION_LABELS) if (pattern.test(haystack)) return label
  const explicit = str(event.operation_type) || str(event.event_type)
  return explicit ? titleCase(explicit) : 'Cryptographic Operation'
}

const SOURCE_LABELS: Record<string, string> = {
  'local-agent': 'Local Agent',
  agent: 'Local Agent',
  connector: 'Cloud Connector',
  'cloud-connector': 'Cloud Connector',
  network: 'Network Sensor',
  proxy: 'Proxy / Gateway',
}

/* ================================================================== */
/* Risk prioritisation (§8)                                            */
/* ================================================================== */

const CRITICALITY_WEIGHT: Record<string, number> = { critical: 20, high: 13, medium: 6, low: 2 }
const ENVIRONMENT_WEIGHT: Record<string, number> = { production: 10, prod: 10, staging: 4, stage: 4, test: 2, development: 0, dev: 0 }

interface PriorityContext {
  asset: AssetMigrationRecord | null
  /** Observations of this asset+family in the window — runtime frequency. */
  frequency: number
}

/**
 * Impact-weighted priority. RSA-2048 on the Payment API must outrank RSA-2048
 * on a development box, so the algorithm alone never decides the ranking: asset
 * criticality, external exposure, environment, data-sensitivity signals,
 * observed frequency and migration state all move the score.
 *
 * Every contribution is returned as evidence so the drawer can show WHY an
 * issue ranks where it does. Nothing here is random.
 */
function priorityFor(
  status: QuantumStatus,
  event: Row,
  context: PriorityContext,
): { score: number; level: RiskLevel; factors: Array<{ label: string; contribution: number; evidence: string }> } {
  const factors: Array<{ label: string; contribution: number; evidence: string }> = []
  const add = (label: string, contribution: number, evidence: string) => {
    if (contribution === 0) return
    factors.push({ label, contribution, evidence })
  }

  const base = status === 'vulnerable' ? 55 : status === 'unknown' ? 22 : status === 'hybrid' ? 6 : 0
  add('Quantum vulnerability', base, `Runtime primitive classified ${STATUS_LABEL[status]}.`)

  const asset = context.asset
  const criticality = str(asset?.businessCriticality).toLowerCase()
  add('Asset criticality', CRITICALITY_WEIGHT[criticality] ?? 0, criticality ? `Business criticality: ${criticality}.` : '')

  const environment = str(asset?.environment || event.metadata && recordOf(event.metadata).environment).toLowerCase()
  add('Environment', ENVIRONMENT_WEIGHT[environment] ?? 0, environment ? `Observed in ${environment}.` : '')

  if (asset?.internetFacing) add('External exposure', 12, 'Asset is reachable from the internet.')

  if (event.hndl_risk) add('Data sensitivity', 10, 'Agent flagged harvest-now-decrypt-later exposure.')
  else if (asset && num(asset.hndlScore) >= 60) add('Data sensitivity', 8, `Asset HNDL score ${Math.round(num(asset.hndlScore))}.`)

  if (event.downgrade_detected) add('Downgrade observed', 12, 'A negotiated downgrade to weaker cryptography was recorded.')
  if (event.shadow_crypto) add('Shadow cryptography', 8, 'Cryptography outside the approved inventory.')

  // Runtime frequency: a primitive seen constantly matters more than one seen
  // once. Bounded and logarithmic so a chatty agent cannot dominate the ranking.
  const frequency = Math.max(1, context.frequency)
  const frequencyPoints = Math.min(8, Math.round(Math.log10(frequency) * 5))
  add('Runtime frequency', frequencyPoints, `${frequency} observation(s) in the selected window.`)

  const migrationStatus = str(asset?.migrationStatus).toLowerCase()
  if (migrationStatus === 'completed') add('Migration completed', -25, 'A migration for this asset has completed.')
  else if (migrationStatus === 'in-progress' || migrationStatus === 'in_progress' || migrationStatus === 'running') add('Migration in progress', -10, 'Remediation is already under way.')

  let score = clamp(factors.reduce((sum, factor) => sum + factor.contribution, 0), 0, 100)

  // A confirmed post-quantum primitive is never a high-severity runtime risk on
  // its own; only an accompanying operational signal can raise it.
  const hasOperationalSignal = Boolean(event.downgrade_detected || event.shadow_crypto)
  if (status === 'safe' && !hasOperationalSignal) score = Math.min(score, 10)
  if (status === 'hybrid' && !hasOperationalSignal) score = Math.min(score, 24)

  const level: RiskLevel = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low'
  return { score, level, factors }
}

/* ================================================================== */
/* Recommended action (§30)                                            */
/* ================================================================== */

function recommendedActionFor(status: QuantumStatus, decomposition: Decomposition, event: Row): { action: string; target: string | null; standard: string | null } {
  if (event.downgrade_detected) {
    return { action: 'Investigate why the hybrid post-quantum handshake failed and fell back to classical cryptography.', target: null, standard: null }
  }
  if (status === 'vulnerable') {
    const context = `${str(event.operation_type)} ${str(event.event_type)} ${str(event.protocol)}`
    const target = pqcTargetFor(decomposition.riskBearingValue || decomposition.family, context)
    return { action: `Migrate to ${target.target}.`, target: target.target, standard: target.standard }
  }
  if (status === 'unknown') {
    return { action: 'Collect richer telemetry for this endpoint so the primitive can be classified.', target: null, standard: null }
  }
  if (status === 'hybrid') {
    return { action: 'No action required. Keep the hybrid group enabled until pure post-quantum is broadly interoperable.', target: null, standard: null }
  }
  return { action: 'No action required.', target: null, standard: null }
}

/* ================================================================== */
/* Engine                                                              */
/* ================================================================== */

export function buildRuntimeCryptoIntelligence(inputs: RuntimeIntelInputs): RuntimeCryptoIntelligence {
  const now = inputs.now ?? Date.now()
  const window = windowFor(inputs.window)
  const eventLimit = Math.max(20, Math.min(500, inputs.eventLimit ?? 150))
  const windowStart = now - window.ms

  const assetById = new Map<string, AssetMigrationRecord>()
  const assetByName = new Map<string, AssetMigrationRecord>()
  for (const asset of inputs.assets) {
    assetById.set(asset.id, asset)
    if (asset.name) assetByName.set(asset.name.toLowerCase(), asset)
    if (asset.hostname) assetByName.set(asset.hostname.toLowerCase(), asset)
  }

  const allEvents = inputs.runtimeEvents.filter((event) => ms(event.observed_at || event.created_at) > 0)
  const sortedAll = [...allEvents].sort((a, b) => ms(b.observed_at || b.created_at) - ms(a.observed_at || a.created_at))
  const latestEventAt = iso(sortedAll[0]?.observed_at || sortedAll[0]?.created_at)
  const oldestEventAt = iso(sortedAll[sortedAll.length - 1]?.observed_at || sortedAll[sortedAll.length - 1]?.created_at)

  const inWindow = sortedAll.filter((event) => ms(event.observed_at || event.created_at) >= windowStart)

  /* ---- Frequency index: asset + primitive family ------------------- */
  const decompositions = new Map<Row, Decomposition>()
  const frequency = new Map<string, number>()
  const resolveAsset = (event: Row): AssetMigrationRecord | null => {
    const byId = str(event.asset_id) ? assetById.get(str(event.asset_id)) : undefined
    if (byId) return byId
    const name = str(event.asset_name).toLowerCase() || str(event.host).toLowerCase()
    return (name ? assetByName.get(name) : undefined) ?? null
  }
  for (const event of inWindow) {
    const decomposition = decomposeRuntimeEvent(event)
    decompositions.set(event, decomposition)
    const asset = resolveAsset(event)
    const key = frequencyKeyFor(event, asset, decomposition.family)
    frequency.set(key, (frequency.get(key) ?? 0) + 1)
  }

  /* ---- Events ------------------------------------------------------ */
  const events: RuntimeEvent[] = inWindow.slice(0, eventLimit).map((event) => {
    const decomposition = decompositions.get(event) ?? decomposeRuntimeEvent(event)
    const asset = resolveAsset(event)
    const assetName = str(event.asset_name) || asset?.name || str(event.host) || 'Unattributed runtime source'
    const key = frequencyKeyFor(event, asset, decomposition.family)
    const priority = priorityFor(decomposition.status, event, { asset, frequency: frequency.get(key) ?? 1 })
    const recommendation = recommendedActionFor(decomposition.status, decomposition, event)
    const metadata = recordOf(event.metadata)
    const sourceType = str(event.source_type) || 'runtime'

    const why = event.downgrade_detected
      ? 'A post-quantum or hybrid handshake was attempted and the connection fell back to classical cryptography.'
      : STATUS_WHY[decomposition.status]

    return {
      id: str(event.id),
      observedAt: iso(event.observed_at || event.created_at),
      assetId: asset?.id ?? (str(event.asset_id) || null),
      assetName,
      environment: asset?.environment || str(metadata.environment) || 'unspecified',
      operation: operationLabel(event),
      algorithm: decomposition.family,
      observedValue: decomposition.riskBearingValue || decomposition.family,
      quantumStatus: decomposition.status,
      statusLabel: STATUS_LABEL[decomposition.status],
      statusGlyph: STATUS_GLYPH[decomposition.status],
      risk: priority.level,
      riskScore: priority.score,
      why,
      recommendedAction: recommendation.action,
      pqcTarget: recommendation.target,
      pqcStandard: recommendation.standard,
      flags: {
        downgradeDetected: Boolean(event.downgrade_detected),
        shadowCrypto: Boolean(event.shadow_crypto),
        hndlRisk: Boolean(event.hndl_risk),
        legacyReported: Boolean(event.is_legacy),
        pqcReported: Boolean(event.is_pqc),
      },
      priorityFactors: priority.factors,
      links: {
        asset: asset?.id ? `/dashboard/migration-planner?asset=${encodeURIComponent(asset.id)}` : null,
        cbom: '/dashboard/cbom',
        quantumRisk: '/dashboard/quantum-risk-scoring',
        hndl: '/dashboard/harvest-now',
        migration: '/dashboard/migration-planner',
      },
      technical: {
        eventId: str(event.id),
        source: sourceType,
        sourceLabel: SOURCE_LABELS[sourceType] ?? titleCase(sourceType),
        observedAt: iso(event.observed_at || event.created_at),
        host: str(event.host) || null,
        port: event.port === null || event.port === undefined ? null : num(event.port),
        protocol: str(event.protocol) || null,
        tlsVersion: str(event.tls_version) || null,
        cipherSuite: str(event.cipher_suite) || null,
        keyExchange: decomposition.keyExchange?.keyExchange ?? (str(event.key_exchange_algorithm) || null),
        signature: decomposition.signature?.authentication ?? null,
        bulkCipher: decomposition.bulk?.bulk ?? null,
        mac: decomposition.keyExchange?.mac ?? decomposition.bulk?.mac ?? null,
        keySize: event.key_size === null || event.key_size === undefined ? null : num(event.key_size),
        certificateFingerprint: shortFingerprint(event.certificate_fingerprint),
        library: str(event.package_name) ? `${str(event.package_name)}${str(event.package_version) ? ` ${str(event.package_version)}` : ''}` : null,
        process: str(event.process_name) || null,
        attributes: sanitizeAttributes(metadata),
      },
    }
  })

  /* ---- Mix --------------------------------------------------------- */
  const mixCounts: Record<QuantumStatus, number> = { safe: 0, hybrid: 0, vulnerable: 0, unknown: 0 }
  for (const event of inWindow) {
    const decomposition = decompositions.get(event)
    if (decomposition) mixCounts[decomposition.status] += 1
  }
  const total = inWindow.length
  const mixOrder: QuantumStatus[] = ['safe', 'hybrid', 'vulnerable', 'unknown']
  const mixLabels: Record<QuantumStatus, string> = {
    safe: 'Quantum Safe',
    hybrid: 'Hybrid PQC',
    vulnerable: 'Quantum Vulnerable',
    unknown: 'Unknown',
  }
  const mix: RuntimeMixRow[] = mixOrder.map((key) => ({
    key,
    label: mixLabels[key],
    glyph: STATUS_GLYPH[key],
    count: mixCounts[key],
    percent: pct(mixCounts[key], total),
  }))
  // Percentages are rounded independently, so absorb the rounding residue into
  // the largest bucket rather than publishing a mix that does not total 100.
  if (total > 0) {
    const sum = mix.reduce((acc, row) => acc + row.percent, 0)
    if (sum !== 100) {
      const largest = mix.reduce((acc, row) => (row.count > acc.count ? row : acc))
      largest.percent = clamp(largest.percent + (100 - sum), 0, 100)
    }
  }

  /* ---- Issues ------------------------------------------------------ */
  const issues = buildIssues(inWindow, decompositions, resolveAsset, frequency)

  /* ---- Configuration (expected vs actual) -------------------------- */
  // Sandbox simulations never reach a production asset: they neither set the
  // expected algorithm nor await runtime confirmation.
  const operationalJobs = inputs.migrationJobs.filter((job) => !isSimulationRow(job))
  const configurations = buildConfigurations(inWindow, decompositions, resolveAsset, operationalJobs, now)
  for (const configuration of configurations) {
    if (configuration.status !== 'matching') {
      const asset = configuration.assetId ? assetById.get(configuration.assetId) : null
      const driftLines = configuration.lines.filter((line) => line.match === 'drift')
      if (!driftLines.length) continue
      issues.push({
        id: `drift::${configuration.assetId ?? configuration.assetName}`,
        kind: 'configuration-drift',
        title: 'Runtime configuration drift',
        assetId: configuration.assetId,
        assetName: configuration.assetName,
        environment: configuration.environment,
        severity: asset?.internetFacing || str(asset?.businessCriticality).toLowerCase() === 'critical' ? 'high' : 'medium',
        riskScore: asset?.internetFacing ? 58 : 42,
        quantumStatus: 'vulnerable',
        observations: configuration.observations,
        firstSeen: null,
        lastSeen: configuration.lastSeen,
        why: `Runtime cryptography does not match the ${configuration.baselineLabel.toLowerCase()}.`,
        recommendedAction: `Align the runtime configuration with the expected stack: ${driftLines.map((line) => `${line.label} ${line.expected}`).join(', ')}.`,
        actionLabel: 'View',
        actionHref: configuration.assetId ? `/dashboard/migration-planner?asset=${encodeURIComponent(configuration.assetId)}` : '/dashboard/migration-planner',
        evidence: driftLines.map((line) => `${line.label}: expected ${line.expected}, observed ${line.actual ?? 'nothing'}.`),
        priorityFactors: [],
        sampleEventId: null,
      })
    }
  }
  issues.sort((a, b) => b.riskScore - a.riskScore || (ms(b.lastSeen) - ms(a.lastSeen)))

  const criticalIssues = issues.filter((issue) => issue.severity === 'critical').length

  /* ---- Security status --------------------------------------------- */
  const securityStatus = buildSecurityStatus(mix, mixCounts, total, issues)

  /* ---- Telemetry state --------------------------------------------- */
  const activeAgentWindow = now - 15 * 60_000
  const activeAgents = inputs.scannerAgents.filter(
    (agent) => str(agent.status).toLowerCase() === 'active' && ms(agent.last_seen_at) >= activeAgentWindow,
  ).length
  const sourceCounts = new Map<string, number>()
  for (const event of inWindow) {
    const label = SOURCE_LABELS[str(event.source_type)] ?? titleCase(str(event.source_type) || 'Runtime')
    sourceCounts.set(label, (sourceCounts.get(label) ?? 0) + 1)
  }
  // A collector or connector that exists but has never produced an event is a
  // BROKEN pipeline, not a missing one, and the page must say so.
  const collectorsRegistered = inputs.scannerAgents.length + inputs.connectorAccounts.length
  const collectorState: CollectorState =
    allEvents.length > 0 ? 'reporting' : collectorsRegistered > 0 ? 'registered-silent' : 'none'

  const telemetry: RuntimeTelemetryState = {
    mode: allEvents.length > 0 ? 'runtime' : 'none',
    collectorState,
    hasRuntimeEvents: allEvents.length > 0,
    totalRuntimeEvents: allEvents.length,
    eventsInWindow: total,
    windowEmpty: allEvents.length > 0 && total === 0,
    latestEventAt,
    oldestEventAt,
    coveredAssets: new Set(inWindow.map((event) => assetKeyFor(event, resolveAsset(event))).filter(Boolean)).size,
    activeAgents,
    totalAgents: inputs.scannerAgents.length,
    connectors: inputs.connectorAccounts.length,
    sources: Array.from(sourceCounts.entries())
      .map(([label, count]) => ({ label, count, percent: pct(count, total) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6),
    truncated: Boolean(inputs.runtimeEventsTruncated),
  }

  /* ---- KPIs -------------------------------------------------------- */
  const kpis: RuntimeKpis = {
    activity: total,
    activityLabel: total === 1 ? 'observation' : 'observations',
    activityDetail: `distinct cryptographic observations · ${window.label.toLowerCase()}`,
    quantumSafePct: total ? mix[0].percent : null,
    hybridPct: total ? mix[1].percent : null,
    vulnerablePct: total ? mix[2].percent : null,
    unknownPct: total ? mix[3].percent : null,
    activeIssues: issues.length,
    criticalIssues,
  }

  /* ---- PQC adoption ------------------------------------------------ */
  const pqcAdoption = buildPqcAdoption(mix, total, inputs.snapshot, sortedAll, telemetry.truncated, now)

  /* ---- Migration verification -------------------------------------- */
  const migrationVerification = buildMigrationVerification(operationalJobs, sortedAll, assetById, now)

  /* ---- Quantum risk ------------------------------------------------- */
  const worstByAsset = new Map<string, RiskLevel>()
  const rank: Record<RiskLevel, number> = { critical: 3, high: 2, medium: 1, low: 0 }
  for (const event of inWindow) {
    const asset = resolveAsset(event)
    const key = assetKeyFor(event, asset)
    if (!key) continue
    const decomposition = decompositions.get(event)
    if (!decomposition) continue
    const priority = priorityFor(decomposition.status, event, {
      asset,
      frequency: frequency.get(frequencyKeyFor(event, asset, decomposition.family)) ?? 1,
    })
    const current = worstByAsset.get(key)
    if (!current || rank[priority.level] > rank[current]) worstByAsset.set(key, priority.level)
  }
  const assetBuckets = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const level of worstByAsset.values()) assetBuckets[level] += 1
  const quantumRisk: QuantumRiskCard = {
    level: inputs.snapshot.scores.quantumRiskLevel,
    score: inputs.snapshot.scores.quantumRisk,
    vulnerableSharePct: total ? mix[2].percent : null,
    headline: total
      ? `${mix[2].percent}% of runtime cryptographic observations are currently quantum vulnerable.`
      : 'No runtime cryptographic observations in the selected period.',
    breakdown: [
      { key: 'critical', label: 'Critical', glyph: '●', count: assetBuckets.critical },
      { key: 'high', label: 'High', glyph: '●', count: assetBuckets.high },
      { key: 'medium', label: 'Attention', glyph: '◐', count: assetBuckets.medium },
      { key: 'low', label: 'Clear', glyph: '✓', count: assetBuckets.low },
    ],
    href: '/dashboard/quantum-risk-scoring',
  }

  /* ---- HNDL --------------------------------------------------------- */
  const hndl = buildHndlCard(inWindow, decompositions, resolveAsset, inputs.snapshot)

  /* ---- Sophia -------------------------------------------------------- */
  const sophia = buildSophiaInsight(issues, mix, total, telemetry, migrationVerification)

  /* ---- Filters ------------------------------------------------------- */
  const environments = Array.from(new Set(events.map((event) => event.environment).filter((value) => value && value !== 'unspecified'))).sort()
  const applications = Array.from(new Set(inWindow.map((event) => str(event.asset_name) || str(event.host)).filter(Boolean))).sort().slice(0, 200)

  const discovery: DiscoveryFallback = {
    assetsAssessed: inputs.snapshot.inventory.assetsAssessed,
    cryptoComponents: inputs.snapshot.inventory.cryptoComponents,
    vulnerableComponents: inputs.snapshot.inventory.vulnerableComponents,
    certificatesAnalyzed: inputs.snapshot.inventory.certificatesAnalyzed,
    pqcAdoptionPct: inputs.snapshot.scores.pqcAdoption,
    lastAssessmentAt: inputs.snapshot.lastAssessmentAt,
    note: 'Discovered by scans, not observed at runtime. Connect a runtime telemetry source to confirm what is actually executing.',
  }

  return {
    generatedAt: new Date(now).toISOString(),
    window: { key: window.key, label: window.label, ms: window.ms },
    telemetry,
    kpis,
    securityStatus,
    events,
    eventTotal: total,
    issues,
    attention: issues.slice(0, 5),
    pqcAdoption,
    configurations,
    migrationVerification,
    quantumRisk,
    hndl,
    sophia,
    filters: { environments, applications },
    discovery,
    evidence: {
      sources: ['Runtime Crypto Telemetry (agents & connectors)', 'Quantum Readiness Snapshot', 'Asset Intelligence Portfolio', 'Migration Jobs'],
      note: telemetry.hasRuntimeEvents
        ? `Derived from ${total} runtime observation(s) across ${telemetry.coveredAssets} asset(s) in the ${window.label.toLowerCase()}. Estate-wide scores are read from the Quantum Readiness snapshot so every module reports the same posture.`
        : `${EVIDENCE_UNAVAILABLE}. No runtime cryptographic telemetry has been recorded for this tenant.`,
    },
  }
}

/* ================================================================== */
/* Issues                                                              */
/* ================================================================== */

const ISSUE_META: Record<IssueKind, { title: string; actionLabel: string }> = {
  'quantum-vulnerable': { title: 'Quantum-vulnerable algorithm in use', actionLabel: 'View' },
  'pqc-fallback': { title: 'PQC fallback detected', actionLabel: 'Investigate' },
  'legacy-protocol': { title: 'Legacy transport configuration', actionLabel: 'View' },
  'shadow-crypto': { title: 'Unapproved cryptography detected', actionLabel: 'Investigate' },
  'hndl-exposure': { title: 'Harvest-now decrypt-later exposure', actionLabel: 'View' },
  'unverified-crypto': { title: 'Unclassified cryptography', actionLabel: 'View' },
  'configuration-drift': { title: 'Runtime configuration drift', actionLabel: 'View' },
}

const LEGACY_PROTOCOL = /TLS\s?1\.[012]\b|TLSV1\.[012]|SSLV?[23]?\b/i

/**
 * Runtime findings are aggregated per (asset, primitive family, kind), not per
 * event. Two thousand observations of RSA-2048 on one API is ONE issue seen
 * 2000 times — publishing it as 2000 issues is how a dashboard reports a
 * five-figure problem count on a two-asset tenant.
 */
function buildIssues(
  events: Row[],
  decompositions: Map<Row, Decomposition>,
  resolveAsset: (event: Row) => AssetMigrationRecord | null,
  frequency: Map<string, number>,
): RuntimeIssue[] {
  interface Bucket {
    kind: IssueKind
    asset: AssetMigrationRecord | null
    assetId: string | null
    assetName: string
    environment: string
    family: string
    status: QuantumStatus
    observations: number
    first: number
    last: number
    score: number
    level: RiskLevel
    factors: Array<{ label: string; contribution: number; evidence: string }>
    sampleEventId: string | null
    sampleValue: string
    recommendation: string
    evidence: Set<string>
  }

  const buckets = new Map<string, Bucket>()

  for (const event of events) {
    const decomposition = decompositions.get(event)
    if (!decomposition) continue
    const asset = resolveAsset(event)
    const assetKey = assetKeyFor(event, asset) || 'unattributed'
    const assetName = str(event.asset_name) || asset?.name || str(event.host) || 'Unattributed runtime source'

    const kinds: IssueKind[] = []
    if (event.downgrade_detected) kinds.push('pqc-fallback')
    if (event.shadow_crypto) kinds.push('shadow-crypto')
    if (decomposition.status === 'vulnerable') kinds.push('quantum-vulnerable')
    if (decomposition.status === 'unknown') kinds.push('unverified-crypto')
    if (LEGACY_PROTOCOL.test(str(event.tls_version)) || LEGACY_PROTOCOL.test(str(event.protocol))) kinds.push('legacy-protocol')
    if (event.hndl_risk && decomposition.status === 'vulnerable') kinds.push('hndl-exposure')
    if (!kinds.length) continue

    const priority = priorityFor(decomposition.status, event, {
      asset,
      frequency: frequency.get(frequencyKeyFor(event, asset, decomposition.family)) ?? 1,
    })
    const recommendation = recommendedActionFor(decomposition.status, decomposition, event)
    const at = ms(event.observed_at || event.created_at)

    for (const kind of kinds) {
      const key = `${kind}::${assetKey}::${decomposition.family}`
      const existing = buckets.get(key)
      if (existing) {
        existing.observations += 1
        existing.first = Math.min(existing.first, at)
        existing.last = Math.max(existing.last, at)
        if (priority.score > existing.score) {
          existing.score = priority.score
          existing.level = priority.level
          existing.factors = priority.factors
        }
        if (str(event.tls_version)) existing.evidence.add(`Protocol observed: ${str(event.tls_version)}.`)
        continue
      }
      const evidence = new Set<string>()
      evidence.add(`Observed primitive: ${decomposition.riskBearingValue || decomposition.family}.`)
      if (str(event.tls_version)) evidence.add(`Protocol observed: ${str(event.tls_version)}.`)
      if (str(event.host)) evidence.add(`Endpoint: ${str(event.host)}${event.port ? `:${num(event.port)}` : ''}.`)
      if (str(event.package_name)) evidence.add(`Library: ${str(event.package_name)} ${str(event.package_version)}`.trim() + '.')

      buckets.set(key, {
        kind,
        asset,
        assetId: asset?.id ?? (str(event.asset_id) || null),
        assetName,
        environment: asset?.environment || 'unspecified',
        family: decomposition.family,
        status: decomposition.status,
        observations: 1,
        first: at,
        last: at,
        score: priority.score,
        level: priority.level,
        factors: priority.factors,
        sampleEventId: str(event.id) || null,
        sampleValue: decomposition.riskBearingValue || decomposition.family,
        recommendation: recommendation.action,
        evidence,
      })
    }
  }

  return Array.from(buckets.entries())
    .map(([key, bucket]) => {
      const meta = ISSUE_META[bucket.kind]
      const title =
        bucket.kind === 'quantum-vulnerable'
          ? `${bucket.family} in use`
          : bucket.kind === 'unverified-crypto'
            ? `Unclassified cryptography (${bucket.family})`
            : bucket.kind === 'legacy-protocol'
              ? `Legacy transport (${bucket.family})`
              : meta.title
      const why =
        bucket.kind === 'pqc-fallback'
          ? 'A hybrid post-quantum negotiation failed and the session completed with classical cryptography, so the traffic is exposed to harvest-now-decrypt-later.'
          : bucket.kind === 'shadow-crypto'
            ? 'Cryptography is running that is not in the approved inventory, so it is neither governed nor covered by the migration plan.'
            : bucket.kind === 'hndl-exposure'
              ? 'Long-lived confidential data is being protected with a key agreement a future quantum computer can break. Captured traffic can be decrypted retroactively.'
              : bucket.kind === 'legacy-protocol'
                ? 'A deprecated transport version is negotiated at runtime; it cannot offer hybrid post-quantum key agreement.'
                : STATUS_WHY[bucket.status]

      return {
        id: key,
        kind: bucket.kind,
        title,
        assetId: bucket.assetId,
        assetName: bucket.assetName,
        environment: bucket.environment,
        severity: bucket.level,
        riskScore: bucket.score,
        quantumStatus: bucket.status,
        observations: bucket.observations,
        firstSeen: bucket.first ? new Date(bucket.first).toISOString() : null,
        lastSeen: bucket.last ? new Date(bucket.last).toISOString() : null,
        why,
        recommendedAction: bucket.recommendation,
        actionLabel: meta.actionLabel,
        actionHref: bucket.assetId ? `/dashboard/migration-planner?asset=${encodeURIComponent(bucket.assetId)}` : '/dashboard/migration-planner',
        evidence: Array.from(bucket.evidence),
        priorityFactors: bucket.factors,
        sampleEventId: bucket.sampleEventId,
      } satisfies RuntimeIssue
    })
    .sort((a, b) => b.riskScore - a.riskScore || b.observations - a.observations)
}

/* ================================================================== */
/* Runtime security status (§4)                                        */
/* ================================================================== */

const STATE_LABEL: Record<SecurityState, string> = {
  excellent: 'EXCELLENT',
  good: 'GOOD',
  attention: 'ATTENTION',
  'high-risk': 'HIGH RISK',
  critical: 'CRITICAL',
  unknown: 'NO DATA',
}

/**
 * One score, one formula, published on the page.
 *
 * Hybrid deliberately scores below pure post-quantum: it is a transition state,
 * not the destination. `unknown` scores mid-band so an unmeasured estate can
 * never read as excellent — but it is not treated as broken either.
 */
export const SECURITY_WEIGHTS: Record<QuantumStatus, number> = { safe: 100, hybrid: 85, unknown: 50, vulnerable: 0 }

function buildSecurityStatus(
  mix: RuntimeMixRow[],
  counts: Record<QuantumStatus, number>,
  total: number,
  issues: RuntimeIssue[],
): RuntimeSecurityStatus {
  if (total === 0) {
    return {
      score: null,
      state: 'unknown',
      stateLabel: STATE_LABEL.unknown,
      headline: 'No runtime cryptographic activity has been observed in this period.',
      mix,
      basis: 'A runtime security score is only published when runtime evidence exists.',
      penaltyApplied: 0,
    }
  }

  const weighted =
    (counts.safe * SECURITY_WEIGHTS.safe +
      counts.hybrid * SECURITY_WEIGHTS.hybrid +
      counts.unknown * SECURITY_WEIGHTS.unknown +
      counts.vulnerable * SECURITY_WEIGHTS.vulnerable) /
    total

  // Bounded penalty: open critical / high findings pull the headline down, but
  // can never invert the measured mix.
  const critical = issues.filter((issue) => issue.severity === 'critical').length
  const high = issues.filter((issue) => issue.severity === 'high').length
  const penalty = Math.min(15, critical * 4 + high * 2)
  const score = Math.round(clamp(weighted - penalty, 0, 100))

  const state: SecurityState = score >= 90 ? 'excellent' : score >= 75 ? 'good' : score >= 55 ? 'attention' : score >= 35 ? 'high-risk' : 'critical'

  const headline =
    state === 'excellent'
      ? 'Runtime cryptography is post-quantum across almost all observed activity.'
      : state === 'good'
        ? 'Most cryptographic activity is currently using approved algorithms.'
        : state === 'attention'
          ? 'A meaningful share of runtime cryptography still relies on classical algorithms.'
          : state === 'high-risk'
            ? 'Most observed runtime cryptography is quantum vulnerable.'
            : 'Runtime cryptography is almost entirely quantum vulnerable.'

  return {
    score,
    state,
    stateLabel: STATE_LABEL[state],
    headline,
    mix,
    basis: `Weighted share of ${total} runtime observation(s) — Quantum Safe 100, Hybrid PQC 85, Unknown 50, Quantum Vulnerable 0 — less a bounded penalty of up to 15 points for open critical and high findings.`,
    penaltyApplied: penalty,
  }
}

/* ================================================================== */
/* PQC adoption (§9)                                                   */
/* ================================================================== */

function buildPqcAdoption(
  mix: RuntimeMixRow[],
  total: number,
  snapshot: RuntimeSnapshotFacts,
  allEvents: Row[],
  truncated: boolean,
  now: number,
): PqcAdoption {
  const monthMs = 30 * 24 * 60 * 60_000
  let trend: PqcAdoption['trend'] = null

  // A month-over-month claim is only made when BOTH windows hold real
  // observations AND the query was not truncated — a capped result set would
  // silently under-count the older window and manufacture a rosy trend.
  if (!truncated) {
    const currentWindow = allEvents.filter((event) => {
      const at = ms(event.observed_at || event.created_at)
      return at >= now - monthMs && at <= now
    })
    const previousWindow = allEvents.filter((event) => {
      const at = ms(event.observed_at || event.created_at)
      return at >= now - 2 * monthMs && at < now - monthMs
    })
    if (currentWindow.length > 0 && previousWindow.length > 0) {
      const share = (rows: Row[]) => {
        const safe = rows.filter((event) => {
          const decomposition = decomposeRuntimeEvent(event)
          return decomposition.status === 'safe' || decomposition.status === 'hybrid'
        }).length
        return pct(safe, rows.length)
      }
      const delta = share(currentWindow) - share(previousWindow)
      trend = {
        deltaPct: delta,
        label: `${delta > 0 ? '+' : ''}${delta}% since last month`,
        basis: `Post-quantum share of ${currentWindow.length} observation(s) this month vs ${previousWindow.length} last month.`,
      }
    }
  }

  return {
    runtimeSafePct: total ? mix[0].percent : null,
    runtimeHybridPct: total ? mix[1].percent : null,
    runtimeClassicalPct: total ? mix[2].percent : null,
    runtimeUnknownPct: total ? mix[3].percent : null,
    estateAdoptionPct: snapshot.scores.pqcAdoption,
    estateLabel: 'Estate PQC adoption (Quantum Readiness)',
    trend,
    basis: total
      ? `Runtime share is measured over ${total} observation(s). Estate adoption is the Quantum Readiness figure across all discovered cryptography, so the two can legitimately differ — runtime shows what is executing, the estate shows what exists.`
      : 'No runtime observations in this period; only the estate-wide figure is available.',
  }
}

/* ================================================================== */
/* Expected vs actual (§10)                                            */
/* ================================================================== */

const BASELINE = {
  protocol: 'TLS 1.3',
  keyExchange: 'X25519MLKEM768',
  signature: 'ML-DSA-65',
  bulk: 'AES-256-GCM',
}

function matchesExpected(expected: string, actual: string | null): boolean {
  if (!actual) return false
  const normalise = (value: string) => value.toUpperCase().replace(/[\s_-]/g, '')
  const e = normalise(expected)
  const a = normalise(actual)
  if (a.includes(e) || e.includes(a)) return true
  // Family-level equivalence: the expected stack names a target, the runtime
  // names an instance of it (ML-KEM-768 satisfies X25519MLKEM768's PQ half only
  // when hybrid, so this stays deliberately narrow).
  if (/MLKEM/.test(e) && /MLKEM/.test(a) && /X25519/.test(e) === /X25519/.test(a)) return true
  if (/MLDSA/.test(e) && /MLDSA/.test(a)) return true
  if (/AES256/.test(e) && /AES256/.test(a)) return true
  return false
}

function buildConfigurations(
  events: Row[],
  decompositions: Map<Row, Decomposition>,
  resolveAsset: (event: Row) => AssetMigrationRecord | null,
  migrationJobs: Row[],
  _now: number,
): RuntimeConfiguration[] {
  interface Observed {
    asset: AssetMigrationRecord | null
    assetId: string | null
    assetName: string
    environment: string
    protocols: Set<string>
    keyExchanges: Set<string>
    signatures: Set<string>
    bulks: Set<string>
    observations: number
    last: number
  }

  const byAsset = new Map<string, Observed>()
  for (const event of events) {
    const decomposition = decompositions.get(event)
    if (!decomposition) continue
    const asset = resolveAsset(event)
    const key = assetKeyFor(event, asset)
    if (!key) continue
    const entry =
      byAsset.get(key) ??
      ({
        asset,
        assetId: asset?.id ?? (str(event.asset_id) || null),
        assetName: str(event.asset_name) || asset?.name || str(event.host) || 'Unattributed runtime source',
        environment: asset?.environment || 'unspecified',
        protocols: new Set<string>(),
        keyExchanges: new Set<string>(),
        signatures: new Set<string>(),
        bulks: new Set<string>(),
        observations: 0,
        last: 0,
      } satisfies Observed)
    entry.observations += 1
    entry.last = Math.max(entry.last, ms(event.observed_at || event.created_at))
    if (str(event.tls_version)) entry.protocols.add(str(event.tls_version))
    if (decomposition.keyExchange?.keyExchange) entry.keyExchanges.add(decomposition.keyExchange.keyExchange)
    if (decomposition.signature?.authentication) entry.signatures.add(decomposition.signature.authentication)
    if (decomposition.bulk?.bulk) entry.bulks.add(decomposition.bulk.bulk)
    byAsset.set(key, entry)
  }

  // An approved migration target, where one exists, is a stronger statement of
  // "expected" than the platform default — it is what THIS tenant committed to.
  const targetByAsset = new Map<string, string>()
  for (const job of migrationJobs) {
    const assetId = str(job.asset_id)
    const target = str(job.target_algorithm)
    if (assetId && target && !targetByAsset.has(assetId)) targetByAsset.set(assetId, target)
  }

  const configurations: RuntimeConfiguration[] = []
  for (const entry of byAsset.values()) {
    // Only assets whose transport was actually observed can be compared; an
    // asset that only emitted library events has nothing to hold to a stack.
    if (!entry.protocols.size && !entry.keyExchanges.size && !entry.signatures.size) continue

    const migrationTarget = entry.assetId ? targetByAsset.get(entry.assetId) : undefined
    const baselineSource: RuntimeConfiguration['baselineSource'] = migrationTarget ? 'migration-target' : 'platform-baseline'

    const worstOf = (values: Set<string>, expected: string): { actual: string | null; match: ConfigurationLine['match'] } => {
      if (!values.size) return { actual: null, match: 'not-observed' }
      const list = Array.from(values)
      const drifting = list.find((value) => !matchesExpected(expected, value))
      if (drifting) return { actual: list.length > 1 ? `${drifting} (+${list.length - 1} more)` : drifting, match: 'drift' }
      return { actual: list.length > 1 ? `${list[0]} (+${list.length - 1} more)` : list[0], match: 'match' }
    }

    const expectedKex = migrationTarget && /KEM|X25519|ECDH|DH/i.test(migrationTarget) ? migrationTarget : BASELINE.keyExchange
    const expectedSig = migrationTarget && /DSA|RSA|ED25519/i.test(migrationTarget) ? migrationTarget : BASELINE.signature

    const lines: ConfigurationLine[] = [
      { label: 'Protocol', expected: BASELINE.protocol, ...worstOf(entry.protocols, BASELINE.protocol) },
      { label: 'Key exchange', expected: expectedKex, ...worstOf(entry.keyExchanges, expectedKex) },
      { label: 'Signature', expected: expectedSig, ...worstOf(entry.signatures, expectedSig) },
      { label: 'Bulk cipher', expected: BASELINE.bulk, ...worstOf(entry.bulks, BASELINE.bulk) },
    ]

    const drift = lines.filter((line) => line.match === 'drift').length
    const notObserved = lines.filter((line) => line.match === 'not-observed').length
    const status: RuntimeConfiguration['status'] = drift > 0 ? 'drift' : notObserved > 0 ? 'partial' : 'matching'

    configurations.push({
      assetId: entry.assetId,
      assetName: entry.assetName,
      environment: entry.environment,
      baselineSource,
      baselineLabel: migrationTarget ? `Approved migration target (${migrationTarget})` : 'Platform PQC baseline',
      status,
      statusLabel: status === 'matching' ? 'MATCHING' : status === 'drift' ? 'CONFIGURATION DRIFT' : 'PARTIALLY OBSERVED',
      lines,
      observations: entry.observations,
      lastSeen: entry.last ? new Date(entry.last).toISOString() : null,
    })
  }

  const statusRank: Record<RuntimeConfiguration['status'], number> = { drift: 2, partial: 1, matching: 0 }
  return configurations
    .sort((a, b) => statusRank[b.status] - statusRank[a.status] || b.observations - a.observations)
    .slice(0, 12)
}

/* ================================================================== */
/* Migration verification (§11)                                        */
/* ================================================================== */

/**
 * Verification is a claim about EVIDENCE, and it is only made when evidence
 * exists. A completed migration job proves a workflow finished; it does not
 * prove the runtime changed. Only observations recorded AFTER cutover, using
 * the target primitive, can do that — and any post-cutover classical
 * observation on the same asset is reported as a fallback rather than ignored.
 */
function buildMigrationVerification(
  migrationJobs: Row[],
  allEvents: Row[],
  assetById: Map<string, AssetMigrationRecord>,
  now: number,
): MigrationVerification[] {
  const completed = migrationJobs
    .filter((job) => str(job.status).toLowerCase() === 'completed')
    .sort((a, b) => ms(b.completed_at || b.updated_at) - ms(a.completed_at || a.updated_at))
    .slice(0, 6)

  return completed.map((job) => {
    const assetId = str(job.asset_id)
    const asset = assetId ? assetById.get(assetId) : undefined
    const completedAt = ms(job.completed_at || job.updated_at) || now
    const target = str(job.target_algorithm) || 'Post-quantum stack'
    const metadata = recordOf(job.metadata)
    const before = str(metadata.from_algorithm) || str(metadata.source_algorithm) || null

    const assetEvents = allEvents.filter((event) => {
      if (assetId && str(event.asset_id) === assetId) return true
      if (asset?.name && str(event.asset_name).toLowerCase() === asset.name.toLowerCase()) return true
      return false
    })
    const post = assetEvents.filter((event) => ms(event.observed_at || event.created_at) >= completedAt)

    let sessionsVerified = 0
    let fallbacks = 0
    for (const event of post) {
      const decomposition = decomposeRuntimeEvent(event)
      if (decomposition.status === 'safe' || decomposition.status === 'hybrid') sessionsVerified += 1
      else if (decomposition.status === 'vulnerable') fallbacks += 1
    }

    // Precedence matters. A classical observation AFTER cutover is the strongest
    // evidence the change did not take effect, so it outranks the absence of
    // post-quantum traffic — reporting it as merely "not verified" would hide a
    // migration that demonstrably failed at runtime.
    const status: MigrationVerification['status'] =
      fallbacks > 0 ? 'fallback-detected' : sessionsVerified > 0 ? 'confirmed' : 'not-observed'

    const detail =
      status === 'confirmed'
        ? `${sessionsVerified} post-cutover observation(s), all post-quantum. No classical fallback recorded.`
        : status === 'fallback-detected'
          ? sessionsVerified > 0
            ? `${sessionsVerified} post-quantum observation(s) but ${fallbacks} classical fallback(s) since cutover — the migration is not fully effective at runtime.`
            : `${fallbacks} post-cutover observation(s), all still classical. The migration has not changed runtime behaviour.`
          : post.length === 0
            ? 'No runtime observations recorded since cutover, so the change cannot be confirmed at runtime yet.'
            : `${post.length} post-cutover observation(s) recorded, none of them conclusive.`

    return {
      jobId: str(job.id),
      assetId: assetId || null,
      assetName: str(job.name) || asset?.name || 'Migration job',
      before: before || (asset ? asset.algorithms.find((row) => row.classification === 'vulnerable')?.algorithm ?? null : null),
      after: target,
      completedAt: iso(job.completed_at || job.updated_at),
      sessionsVerified,
      fallbacks,
      status,
      statusLabel: status === 'confirmed' ? 'MIGRATION CONFIRMED' : status === 'fallback-detected' ? 'FALLBACK DETECTED' : 'NOT VERIFIED AT RUNTIME',
      detail,
      href: '/dashboard/live-migration',
    }
  })
}

/* ================================================================== */
/* HNDL card (§13)                                                     */
/* ================================================================== */

function buildHndlCard(
  events: Row[],
  decompositions: Map<Row, Decomposition>,
  resolveAsset: (event: Row) => AssetMigrationRecord | null,
  snapshot: RuntimeSnapshotFacts,
): HndlCard {
  const exposed = new Map<string, { name: string; id: string | null; reason: string; score: number }>()

  for (const event of events) {
    const decomposition = decompositions.get(event)
    if (!decomposition) continue
    // HNDL is specifically about KEY AGREEMENT: a captured session is decrypted
    // later by breaking the key exchange, not the bulk cipher. A vulnerable
    // signature does not put recorded traffic at risk.
    const kexClass = decomposition.keyExchange?.quantumClass
    const isExposed = Boolean(event.hndl_risk) || kexClass === 'vulnerable'
    if (!isExposed) continue

    const asset = resolveAsset(event)
    const key = assetKeyFor(event, asset)
    if (!key) continue
    const name = str(event.asset_name) || asset?.name || str(event.host) || 'Unattributed runtime source'
    const score = asset ? num(asset.hndlScore) : 0
    const reason = event.hndl_risk
      ? 'Agent flagged long-lived confidential data over a classical key exchange.'
      : `Classical key agreement observed at runtime (${decomposition.keyExchange?.keyExchange ?? decomposition.family}).`
    const existing = exposed.get(key)
    if (!existing || score > existing.score) exposed.set(key, { name, id: asset?.id ?? null, reason, score })
  }

  const list = Array.from(exposed.values()).sort((a, b) => b.score - a.score)

  return {
    highRiskAssets: list.length,
    score: snapshot.scores.hndlRisk,
    level: snapshot.scores.hndlRiskLevel,
    headline: list.length
      ? 'Sensitive traffic is currently protected by a classical key exchange, so it can be captured now and decrypted once a quantum computer exists.'
      : 'No runtime observation used a quantum-vulnerable key exchange in this period.',
    topAsset: list[0] ? { id: list[0].id, name: list[0].name, reason: list[0].reason } : null,
    href: '/dashboard/harvest-now',
  }
}

/* ================================================================== */
/* Sophia insight (§14)                                                */
/* ================================================================== */

/**
 * Sophia states only what the evidence supports. She never claims a migration
 * succeeded without a post-cutover observation, and every conclusion ships the
 * evidence it was drawn from.
 */
function buildSophiaInsight(
  issues: RuntimeIssue[],
  mix: RuntimeMixRow[],
  total: number,
  telemetry: RuntimeTelemetryState,
  verification: MigrationVerification[],
): SophiaInsight {
  if (!telemetry.hasRuntimeEvents) {
    const silent = telemetry.collectorState === 'registered-silent'
    return {
      headline: silent ? 'A collector is enrolled but silent' : 'No collector configured',
      body: silent
        ? `${telemetry.totalAgents} collector agent(s) and ${telemetry.connectors} cloud connector(s) are registered for this tenant, but none has ever sent a cryptographic event. The pipeline is configured and not delivering.`
        : 'No collector agent or cloud connector has been registered, so I have no way to observe what cryptography is actually executing. Discovery results are available, but they describe what EXISTS, not what RUNS.',
      recommendation: silent
        ? 'Check the collector: confirm it is running, that its enrolment token is still valid, and that outbound access to the ingest endpoint is open.'
        : 'Enrol a collector agent, or connect a cloud provider, to start runtime monitoring.',
      evidence: [
        'runtime_crypto_events: 0 rows for this tenant.',
        `Collector agents registered: ${telemetry.totalAgents}. Cloud connectors: ${telemetry.connectors}.`,
      ],
      question: silent
        ? 'My QGuard collector agent is enrolled but has never reported. How do I diagnose it?'
        : 'How do I enrol a runtime cryptographic collector agent in QGuard Helix?',
      actionHref: '/dashboard/agents',
      hasFinding: false,
    }
  }

  if (telemetry.windowEmpty) {
    return {
      headline: 'No activity in this window',
      body: `This tenant has ${telemetry.totalRuntimeEvents} runtime observation(s), but none inside the selected period. The most recent one was recorded at ${telemetry.latestEventAt ?? 'an unknown time'}.`,
      recommendation: 'Widen the time window, or check that the collector is still reporting.',
      evidence: [`Latest runtime observation: ${telemetry.latestEventAt ?? 'unknown'}.`],
      question: 'Why has my runtime crypto collector stopped reporting?',
      actionHref: '/dashboard/agents',
      hasFinding: false,
    }
  }

  if (!issues.length) {
    const fallback = verification.find((row) => row.status === 'fallback-detected')
    return {
      headline: 'No runtime cryptographic risks detected',
      body: `I reviewed ${total} runtime observation(s) in this period. ${mix[0].percent + mix[1].percent}% used post-quantum or hybrid cryptography and none triggered a risk finding.`,
      recommendation: fallback
        ? `Keep watching ${fallback.assetName}: its migration shows ${fallback.fallbacks} classical fallback(s) since cutover.`
        : 'Keep runtime monitoring enabled so any regression is caught as it happens.',
      evidence: [
        `${total} runtime observation(s) analysed.`,
        `Quantum Safe ${mix[0].count}, Hybrid PQC ${mix[1].count}, Vulnerable ${mix[2].count}, Unknown ${mix[3].count}.`,
      ],
      question: 'Summarise my runtime cryptographic posture and what I should watch next.',
      actionHref: '/dashboard/quantum-readiness',
      hasFinding: false,
    }
  }

  const top = issues[0]
  const criticalCount = issues.filter((issue) => issue.severity === 'critical').length

  return {
    headline: `${issues.length} runtime cryptographic issue${issues.length === 1 ? '' : 's'} detected`,
    body: `The most important is ${top.assetName}, which is using ${top.title.replace(/ in use$/, '')} at runtime${top.environment && top.environment !== 'unspecified' ? ` in ${top.environment}` : ''}. ${top.why}`,
    recommendation: top.recommendedAction,
    evidence: [
      `${top.observations} observation(s) of this issue, most recently ${top.lastSeen ?? 'unknown'}.`,
      `Priority ${top.riskScore}/100 — ${top.priorityFactors.slice(0, 3).map((factor) => `${factor.label} ${factor.contribution > 0 ? '+' : ''}${factor.contribution}`).join(', ') || 'no weighting factors recorded'}.`,
      criticalCount ? `${criticalCount} finding(s) rated critical.` : `Highest severity: ${top.severity}.`,
    ],
    question: `Why is ${top.assetName} using ${top.title.replace(/ in use$/, '')} at runtime, and what is the safest way to migrate it?`,
    actionHref: top.actionHref,
    hasFinding: true,
  }
}
