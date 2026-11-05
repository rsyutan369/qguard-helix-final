import { Router, Request, Response, NextFunction } from 'express'
import { buildFinancialExposure, migrationCostUsd as computeMigrationCostUsd } from '@/lib/migration/cost-model'
import { loadCostAssumptions } from './cost-assumptions'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { buildScannerIntelligence, readScannerMemoryRows } from './scanner'
import { buildSharedResponsibility } from '@/lib/shared-responsibility'
import { buildOwnershipInputs } from './shared-responsibility-inputs'
import { collapseCriticalFindings, type RawCriticalFinding } from './critical-findings'
import {
  blendQuantumReadiness,
  classifyAlgorithm,
  deriveAssetPostureModel,
  estimateMigrationSchedule,
  isInternetFacing,
  levelFromReadiness,
  levelFromRisk,
  quantumRiskFrom,
  readinessPostureMeasured,
  severityPressureFrom,
} from '@/lib/migration/asset-intelligence'
import { isCryptographicComponent } from '@/lib/scanner/finding-identity'
import { algorithmFamily } from '@/lib/governance/subjects'
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'
import { syncScoreHistory } from './quantum-readiness-history'
import { payloadFingerprint, streamLiveSnapshot } from './live-snapshot-stream'
import { isMissingTable } from './operational-fleet'

// The per-asset risk/posture derivation, algorithm classification and internet
// exposure heuristic live in the shared migration intelligence engine so the
// Migration Planner's per-asset dossiers and these tenant totals can never
// disagree. Re-exported here because existing modules import them from this file.
export { isInternetFacing }

/**
 * Quantum Readiness Assessment Engine™ — aggregation router.
 *
 * Reads real, tenant-scoped cryptographic inventory, scan findings, certificates,
 * keys, exposures, runtime telemetry and trust relationships from Supabase and
 * derives the consolidated scoring model consumed by every Quantum Readiness
 * sub-page. Every query is tenant-scoped (user_id) and defensive — a missing
 * table degrades to an empty set rather than failing the assessment.
 *
 * No synthetic production metrics are emitted. When a tenant has no evidence the
 * router returns `hasData: false` with zeroed scores so the UI renders
 * evidence-driven empty states.
 */

const router = Router()

/** One readiness factor. `measured: false` ⇒ render "Not measured" with `basis`, never the score. */
export interface ReadinessFactor {
  label: string
  score: number
  measured: boolean
  basis: string
}

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  // Header-only auth (Authorization: Bearer) for both GET / and the SSE
  // GET /stream. The client reads the event stream with fetch() + an
  // Authorization header, never EventSource, so no query-string token is
  // accepted — tokens in URLs leak into logs, proxies and Referer.
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}

router.use(requireAuth)

function str(value: unknown): string {
  return typeof value === 'string' ? value : value == null ? '' : String(value)
}
function num(value: unknown): number {
  const n = Number(value)
  return Number.isFinite(n) ? n : 0
}
function clamp(value: number, min = 0, max = 100): number {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, value))
}
function recordOf(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
}

/**
 * A read failure that is the SAME on every build: the table or column is not
 * provisioned in this environment, or the role may not read it. Reading it as
 * "no rows" is stable, so the snapshot stays consistent.
 */
export function isDeterministicReadGap(error: unknown): boolean {
  if (isMissingTable(error)) return true
  const e = error as { code?: unknown; message?: unknown } | null
  const code = String(e?.code ?? '')
  const message = String(e?.message ?? '').toLowerCase()
  return code === '42703' || code === 'PGRST204' || code === '42501' || message.includes('permission denied')
}

/**
 * A read that failed for a reason that may not recur (network, statement
 * timeout, JWT, 5xx). It must fail the build. Swallowed as `[]`, one blip
 * produced an all-zero "Not started" snapshot for a populated estate, and a
 * failed scanner-intelligence read switched the component population
 * mid-session (readiness 27 ↔ 62 on unchanged data). Either result was cached,
 * streamed to every tab and written to score history.
 */
export class SnapshotReadError extends Error {
  constructor(source: string, cause: unknown) {
    super(`Quantum readiness read of ${source} failed: ${(cause as { message?: string })?.message || String(cause)}`)
    this.name = 'SnapshotReadError'
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Record<string, unknown>[]> {
  let result: { data: unknown; error: unknown }
  try {
    result = await build(client.from(table))
  } catch (error) {
    throw new SnapshotReadError(table, error)
  }
  const { data, error } = result
  if (error) {
    if (!isDeterministicReadGap(error)) throw new SnapshotReadError(table, error)
    console.warn(`Quantum readiness ${table} query skipped:`, (error as { message?: string }).message || error)
    return []
  }
  return table === 'assets' ? ((data || []) as any[]).filter((row) => !row.metadata?.consolidatedIntoAssetId) : (data as Record<string, unknown>[]) || []
}

/**
 * Exact tenant-wide row count (HEAD + count=exact — no rows transferred).
 * The detail queries above are row-capped for memory safety, so a tenant with
 * thousands of assets/components must take its headline counts from these,
 * never from the capped page length. Returns null when the count is
 * unavailable so callers can fall back to the fetched-row length.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function exactCount(client: any, table: string, userId: string, refine?: (query: any) => any): Promise<number | null> {
  try {
    let query = client.from(table).select('id', { count: 'exact', head: true }).eq('user_id', userId)
    if (table === 'assets') query = query.is('metadata->>consolidatedIntoAssetId', null)
    if (refine) query = refine(query)
    const { count, error } = await query
    if (error) return null
    return typeof count === 'number' ? count : null
  } catch {
    return null
  }
}

/**
 * Shared-computation cache for the Quantum Readiness snapshot.
 *
 * The snapshot backs the 9 QR pages, Migration Planner, Harvest Now, the
 * remediation engine, the certification engine and the workflow rail — each
 * with its own fetch/SSE cadence (≥8s). Per-tenant short-TTL single-flight
 * caching collapses that fan-out to one computation per window and gives
 * every module the SAME authoritative snapshot within it (consistent state
 * across pages by construction). Scan writes surface within the TTL, which
 * is below every consumer's own refresh cadence. Failures are never cached.
 */
const SNAPSHOT_CACHE_TTL_MS = 15_000
// Single-flight: one build per tenant, shared even past the TTL while it is
// still running. The previous Map stamped `at` at build START, so a build slower
// than the TTL was duplicated by the next SSE poll — the amplifier behind the
// connect-timeout storm. See lib/single-flight-cache.ts.
const snapshotCache = createSingleFlightCache<Awaited<ReturnType<typeof computeSnapshot>>>(
  SNAPSHOT_CACHE_TTL_MS,
)

export async function buildSnapshot(token: string, userId: string) {
  return snapshotCache.get(userId, () => computeSnapshot(token, userId))
}

async function computeSnapshot(token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  // Tenant planning assumptions (rate, hours/week, per-asset values, budget).
  // Falls back to published defaults when unset or when the schema is not yet
  // applied, so cost surfaces degrade to defaults rather than to nothing.
  const costAssumptions = await loadCostAssumptions(token, userId)

  // eslint-disable-next-line prefer-const -- reassigned by the degraded-store
  // fallback below, which cannot run until the queries have resolved.
  let [
    assets,
    assetRelationships,
    scanResults,
    scanSessions,
    cryptoExposures,
    cryptoInventory,
    certificates,
    generatedKeys,
    runtimeEvents,
    securityEvents,
    scannerAlerts,
    scannerEvidence,
    connectorAccounts,
    vaultFiles,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1500)),
    safeRows(client, 'asset_relationships', (q) => q.select('*').eq('user_id', userId).limit(3000)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2000)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, started_at, completed_at, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(180)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2000)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, discovered_at, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2500)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, not_after, is_quantum_safe, is_expiring_soon, status, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1500)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, quality_score, status, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1500)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, asset_id, algorithm, severity, risk_score, asset_name, asset_type, host, is_pqc, is_legacy, hndl_risk, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(4000)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, severity, category, status, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'scanner_evidence', (q) => q.select('id, observed_algorithm, asset_name, asset_type, host, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1800)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, status').eq('user_id', userId).limit(400)),
    safeRows(client, 'vault_files', (q) => q.select('id, encryption_algorithm, created_at').eq('user_id', userId).limit(800)),
  ])

  // Exact tenant-wide counts (HEAD-only, cheap) so headline inventory numbers
  // stay truthful past the detail-row caps above — a 5,000-asset tenant must
  // report 5,000 assets, not the 1,500-row page.
  const [
    assetsCount,
    certificatesCount,
    keysCount,
    relationshipsCount,
    connectorsCount,
    vaultCount,
    inventoryCount,
    inventoryVulnerableCount,
    inventoryPqcCount,
  ] = await Promise.all([
    exactCount(client, 'assets', userId),
    exactCount(client, 'certificates', userId),
    exactCount(client, 'generated_keys', userId),
    exactCount(client, 'asset_relationships', userId),
    exactCount(client, 'connector_accounts', userId),
    exactCount(client, 'vault_files', userId),
    exactCount(client, 'crypto_inventory', userId),
    exactCount(client, 'crypto_inventory', userId, (q) => q.eq('is_vulnerable', true)),
    exactCount(client, 'crypto_inventory', userId, (q) => q.eq('is_quantum_safe', true)),
  ])

  /* ---- DEGRADED-STORE FALLBACK, DISCLOSED ------------------------------
   *
   * When the database is unreachable the scanner keeps completed results in an
   * in-memory store, and `buildScannerIntelligence` (called below) reads it.
   * That is why this snapshot could report 35 cryptographic COMPONENTS and, in
   * the same breath, 0 ASSETS: the component numbers arrived through the intel
   * view, which is memory-aware, while every raw table read here was not.
   *
   * A tenant then saw the migration workflow say "2 assets · Discovery
   * complete" beside a Quantum Readiness page reporting nothing to assess. Both
   * were reading real data; they were reading different stores.
   *
   * So the raw reads fall back to the SAME store the intel view uses, and the
   * snapshot carries `persistence` so every surface built on it can say the
   * estate is not durable rather than presenting it as though it were.
   */
  let persistence: 'database' | 'memory' = 'database'
  if (assets.length === 0) {
    const memory = readScannerMemoryRows(userId)
    if (memory.assets.length > 0 || memory.inventory.length > 0) {
      persistence = 'memory'
      assets = memory.assets as unknown as typeof assets
      cryptoInventory = memory.inventory as unknown as typeof cryptoInventory
      cryptoExposures = memory.exposures as unknown as typeof cryptoExposures
      scanResults = memory.results as unknown as typeof scanResults
      scanSessions = memory.sessions as unknown as typeof scanSessions
    }
  }

  // ---- Canonical scanner intelligence ----------------------------------
  // Mirror the platform's scanner-intelligence view (same source as harvest-now,
  // assets, CBOM) so the QR pages display the scanner's *expanded* per-instance
  // finding counts, severity distribution and CBOM component stats rather than
  // the raw graded scan rows. Falls back to raw-table computation if unavailable.
  type IntelFinding = { id?: string; algorithm?: string; category?: string; location?: string; threatLevel?: string; status?: string; detectedAt?: string; timestamp?: string; description?: string }
  type IntelSnapshot = {
    summary?: { totalComponents?: number; vulnerableComponents?: number; pqcReadyComponents?: number; pqcReadiness?: number; totalAssets?: number; vulnerableAssets?: number }
    severityCounts?: { critical?: number; high?: number; medium?: number; low?: number; safe?: number }
    findings?: IntelFinding[]
  }
  // The component population comes from this view. Its absence is NOT a cue to
  // fall back to raw crypto_inventory rows: those count every scan's copy of a
  // component (75 rows / 50 "quantum-safe" against the view's 32 / 7 on one
  // tenant), so the fallback published a different readiness for unchanged
  // data. A failed read may also be a cached rejection from another caller's
  // build, which the cache drops on failure, so retry once with this token,
  // then fail the snapshot.
  // The scanner view never throws on a failed read: it degrades to its
  // in-memory store and says so with `mode: 'memory'`. When this snapshot's
  // own reads reached the database and found the estate, a memory-mode view
  // is a degraded read, not a different estate.
  const estateInDatabase = persistence === 'database' && (assets.length > 0 || cryptoInventory.length > 0)
  const readIntel = async (): Promise<IntelSnapshot> => {
    const view = (await buildScannerIntelligence(token, userId)) as IntelSnapshot & { mode?: string }
    if (estateInDatabase && view?.mode === 'memory') throw new Error('scanner tables partially unreadable (degraded to memory store)')
    return view
  }
  let intel: IntelSnapshot | null = null
  try {
    intel = await readIntel()
  } catch {
    try {
      intel = await readIntel()
    } catch (error) {
      throw new SnapshotReadError('scanner intelligence', error)
    }
  }
  const intelSummary = intel?.summary
  const intelSeverity = intel?.severityCounts
  const intelFindings = intel?.findings || []
  const intelHasData = Boolean(intelSummary && ((intelSummary.totalComponents || 0) > 0 || intelFindings.length > 0))

  // ---- Inventory --------------------------------------------------------
  // Exact counts floor the fetched-page lengths; identical for small tenants,
  // truthful for tenants whose tables exceed the detail-row caps.
  const assetsAssessed = Math.max(assets.length, assetsCount ?? 0)
  const certificatesAnalyzed = Math.max(certificates.length, certificatesCount ?? 0)
  const keysDiscovered = Math.max(generatedKeys.length, keysCount ?? 0)
  const trustRelationships = Math.max(assetRelationships.length, relationshipsCount ?? 0)
  const cloudAccounts = Math.max(connectorAccounts.length, connectorsCount ?? 0)
  const dataRepositories = Math.max(vaultFiles.length, vaultCount ?? 0)
  // Scanned domains = distinct scanned targets (evidence/runtime hosts, scan
  // result targets, and discovered web/domain assets). A scanned domain must
  // never read as 0.
  const domainAssetNames = assets
    .filter((a) => /web|domain|tls|endpoint|site|host|app/i.test(str(a.type)) || /\.[a-z]{2,}$/i.test(str(a.name)))
    .map((a) => str(a.name))
  const domainsScanned = new Set(
    [
      ...scannerEvidence.map((e) => str(e.host)),
      ...runtimeEvents.map((e) => str(e.host)),
      ...domainAssetNames,
    ].filter(Boolean),
  ).size

  // ---- Algorithm / CBOM posture ----------------------------------------
  // crypto_inventory is the authoritative Cryptographic Bill of Materials and
  // carries is_vulnerable / is_quantum_safe flags. Use it as the single source
  // of truth for posture so percentages match the platform's scanner
  // intelligence. Only when no CBOM exists do we fall back to scan findings,
  // certificates and keys — summing all sources double-counts the same crypto.
  let vulnerable = 0
  let pqcReady = 0
  let hybrid = 0
  const tally = (klass: 'vulnerable' | 'pqc' | 'hybrid' | 'unknown') => {
    if (klass === 'vulnerable') vulnerable += 1
    else if (klass === 'pqc') pqcReady += 1
    else if (klass === 'hybrid') hybrid += 1
  }

  /*
   * A CBOM component is CRYPTOGRAPHY. `crypto_inventory` also holds scanner
   * FINDINGS, because the scan writer stores `algorithm: finding.algorithm`
   * for every rule it fires — so "No Certificate Pinning" and "Regulatory
   * Compliance Gap" arrive as rows flagged is_vulnerable:true and inflated
   * BOTH sides of the quantum-vulnerable ratio that drives this score. The
   * findings are not lost: the same records live in pqc_scan_results and
   * crypto_exposures, which is what Risk Analysis and Vulnerabilities read.
   */
  const cryptoComponentRows = cryptoInventory.filter((row) => isCryptographicComponent(row, algorithmFamily))
  const findingRowsExcluded = cryptoInventory.length - cryptoComponentRows.length

  if (cryptoComponentRows.length) {
    for (const item of cryptoComponentRows) {
      if (item.is_quantum_safe === true) tally('pqc')
      else if (item.is_vulnerable === true) tally('vulnerable')
      else tally(classifyAlgorithm(str(item.algorithm)))
    }
  } else {
    for (const result of scanResults) tally(classifyAlgorithm(str(result.algorithm)))
    for (const cert of certificates) {
      if (cert.is_quantum_safe === true) tally('pqc')
      else tally(classifyAlgorithm(str(cert.algorithm)))
    }
    for (const key of generatedKeys) tally(classifyAlgorithm(str(key.algorithm)))
    for (const event of runtimeEvents) {
      if (event.is_pqc === true) tally('pqc')
      else if (event.is_legacy === true) tally('vulnerable')
      else tally(classifyAlgorithm(str(event.algorithm)))
    }
  }

  // Mirror the scanner's expanded CBOM component stats when available so the QR
  // posture, PQC-adoption % and component counts match scanner intelligence.
  if (intelHasData && intelSummary) {
    vulnerable = num(intelSummary.vulnerableComponents)
    pqcReady = num(intelSummary.pqcReadyComponents)
    hybrid = 0
  }

  // Exact-count floor: when the authoritative crypto_inventory table holds more
  // components than either the scanner view or the capped detail page (large
  // estates past the row caps), adopt its exact posture counts — headline CBOM
  // numbers and the vulnerable/PQC shares must reflect the full tenant universe.
  const intelTotal = intelHasData && intelSummary ? num(intelSummary.totalComponents) : 0

  /*
   * The exact head-counts (`inventoryCount` and friends) are SQL counts over
   * every crypto_inventory row, so they include the finding rows the JS
   * classifier just excluded. Applying them raw would reinstate the inflated
   * total the moment a tenant grew past the detail-row cap.
   *
   * The measured crypto share of the fetched page is therefore carried onto
   * the exact counts. When the page is not truncated — every tenant inside the
   * 2,500-row cap — that share is computed over the WHOLE table, so the result
   * is exact, not an estimate. `cbomTruncated` marks the case where it is not.
   */
  const cryptoShare = cryptoInventory.length > 0 ? cryptoComponentRows.length / cryptoInventory.length : 1
  const cbomTruncated = inventoryCount !== null && inventoryCount > cryptoInventory.length
  const exactCryptoTotal = inventoryCount === null ? null : Math.round(inventoryCount * cryptoShare)
  const exactVulnerable = inventoryVulnerableCount === null ? null : Math.round(inventoryVulnerableCount * cryptoShare)
  const exactPqc = inventoryPqcCount === null ? null : Math.round(inventoryPqcCount * cryptoShare)

  const cbomExactDominates = exactCryptoTotal !== null && exactCryptoTotal > Math.max(intelTotal, cryptoComponentRows.length, vulnerable + pqcReady + hybrid)
  if (cbomExactDominates) {
    vulnerable = Math.max(vulnerable, exactVulnerable ?? 0)
    pqcReady = Math.max(pqcReady, exactPqc ?? 0)
    hybrid = 0
  }

  const totalCrypto = cbomExactDominates
    ? Math.max(1, exactCryptoTotal ?? 1)
    : intelHasData && intelSummary ? Math.max(1, intelTotal) : vulnerable + pqcReady + hybrid
  const cryptoComponents = cbomExactDominates
    ? (exactCryptoTotal ?? 0)
    : intelHasData && intelSummary ? intelTotal : (cryptoComponentRows.length || totalCrypto)
  const vulnerableComponents = vulnerable
  const pqcReadyComponents = pqcReady + hybrid

  /*
   * Measured sub-populations for the readiness factors. Each factor is computed
   * over the population its label names and is reported `measured: false` when
   * that population is empty. They used to be proxies of one number:
   * "TLS / Protocol Maturity" and "PKI Maturity" were both `100 - vulnerableShare`
   * (the second scaled by 0.8), so neither looked at a single handshake or
   * certificate.
   */
  let hybridComponentRows = 0
  let keyExchangeMeasured = 0
  let keyExchangeQuantumSafe = 0
  for (const item of cryptoComponentRows) {
    const anatomy = analyzeCryptoObservation({ algorithm: item.algorithm, name: item.name, itemType: item.item_type, protocol: item.protocol }, true)
    if (item.is_quantum_safe !== true && anatomy.quantumClass === 'hybrid') hybridComponentRows += 1
    if ((anatomy.kind === 'key-exchange' || anatomy.kind === 'cipher-suite') && anatomy.quantumClass !== 'unknown') {
      keyExchangeMeasured += 1
      if (item.is_quantum_safe === true || anatomy.quantumClass === 'safe' || anatomy.quantumClass === 'hybrid') keyExchangeQuantumSafe += 1
    }
  }
  const quantumSafeCertificates = certificates.filter((cert) => cert.is_quantum_safe === true || classifyAlgorithm(str(cert.algorithm)) !== 'vulnerable' && classifyAlgorithm(str(cert.algorithm)) !== 'unknown').length

  // ---- Per-asset risk, posture & internet exposure -----------------------
  // Derived by the SHARED engine (src/lib/migration/asset-intelligence.ts) that
  // the Migration Planner's per-asset dossiers also use, so an asset's risk
  // score and posture are identical on every page of the platform.
  const postureModel = deriveAssetPostureModel({ assets, scanResults, cryptoExposures, cryptoInventory, runtimeEvents })
  const { assetRisk, assetPosture, evidencedAssetIds } = postureModel
  const pqcReadyAssets = postureModel.counts.pqcReadyAssets
  const hybridAssets = postureModel.counts.hybridAssets
  const unassessedAssets = postureModel.counts.unassessedAssets
  const quantumVulnerableAssets = postureModel.counts.quantumVulnerableAssets
  const internetFacing = postureModel.counts.internetFacing
  /** Display posture: the shared verdict, except that an asset nothing was measured on is 'unknown'. */
  const displayPosture = (assetId: string): 'pqc' | 'hybrid' | 'vulnerable' | 'unknown' =>
    evidencedAssetIds.has(assetId) ? assetPosture.get(assetId) || 'hybrid' : 'unknown'

  /*
   * THERE IS NO FALLBACK FROM ASSETS TO COMPONENTS. An asset count is a count
   * of assets.
   *
   * This used to read:
   *
   *     if (assetsAssessed === 0) {
   *       pqcReadyAssets = pqcReady
   *       hybridAssets = hybrid
   *       quantumVulnerableAssets = vulnerable
   *     }
   *
   * — substituting CBOM component counts into the asset fields whenever the
   * tenant held no assets. The intent was to avoid an empty-looking dashboard
   * for a tenant that had scanned an edge target (real cryptography, no asset
   * inventory). The effect was that a tenant with ZERO assets published "28
   * quantum-vulnerable assets" — a number equal, to the unit, to its 28
   * vulnerable components — and that number then propagated into the executive
   * "Critical Assets" KPI, Business Impact's "Critical Assets at Risk", Threat
   * Intelligence's Shor-at-risk tile, the migration pipeline's remaining count,
   * the governance projection, the HNDL narrative and the Sophia copilot.
   *
   * A component is not an asset. The platform already publishes both units
   * separately (`vulnerableComponents` / `cryptoComponents`), so a surface that
   * wants to report cryptography on an inventory-less tenant reads THOSE, under
   * their own label. Zero assets is the correct answer to "how many assets",
   * and `hasData` already distinguishes it from "measured and clean".
   */

  // ---- Severity distribution -------------------------------------------
  let critical = 0
  let high = 0
  let medium = 0
  let low = 0
  const bumpSeverity = (sev: string) => {
    const s = sev.toLowerCase()
    if (s.includes('critical')) critical += 1
    else if (s.includes('high')) high += 1
    else if (s.includes('medium') || s.includes('moderate')) medium += 1
    else if (s.includes('low')) low += 1
  }
  // Mirror the scanner's expanded per-instance severity distribution. When
  // scanner intelligence is unavailable, fall back to the authoritative graded
  // scan findings (pqc_scan_results), then to crypto_exposures — never summing
  // both, which would double-count the same issue.
  if (intelHasData && intelSeverity) {
    critical = num(intelSeverity.critical)
    high = num(intelSeverity.high)
    medium = num(intelSeverity.medium)
    low = num(intelSeverity.low)
  } else if (scanResults.length) {
    for (const result of scanResults) bumpSeverity(str(result.threat_level))
  } else {
    for (const exposure of cryptoExposures) bumpSeverity(str(exposure.severity))
    for (const alert of scannerAlerts) bumpSeverity(str(alert.severity))
  }

  const totalFindings = critical + high + medium + low

  const hasData =
    assetsAssessed > 0 ||
    scanResults.length > 0 ||
    scanSessions.length > 0 ||
    certificatesAnalyzed > 0 ||
    keysDiscovered > 0 ||
    cryptoInventory.length > 0 ||
    runtimeEvents.length > 0

  // ---- Scoring model ----------------------------------------------------
  // The composites live in src/lib/migration/asset-intelligence.ts so the
  // scoped report model (ReportScope) and the per-asset dossiers weight the
  // same evidence identically.
  const severityPressure = severityPressureFrom({ critical, high, medium, low })
  const vulnerableShare = totalCrypto > 0 ? (vulnerable / totalCrypto) * 100 : 0
  const internetShare = assetsAssessed > 0 ? (internetFacing / assetsAssessed) * 100 : 0
  const quantumRisk = hasData ? quantumRiskFrom({ severityPressure, vulnerableSharePct: vulnerableShare, internetSharePct: internetShare }) : 0

  const pqcAdoption = totalCrypto > 0 ? ((pqcReady + hybrid * 0.5) / totalCrypto) * 100 : 0
  // Runtime visibility is a MEASURED signal: non-zero only when real runtime
  // crypto telemetry exists. Scan sessions alone do not observe runtime paths,
  // so they no longer grant a 55-point proxy (reports showed "Runtime
  // Visibility 55" next to "Runtime Telemetry: No Data" — a contradiction).
  // When runtime is not measured the factor is EXCLUDED from the readiness
  // blend and the remaining weights are renormalised, instead of silently
  // scoring an unmeasured factor.
  const runtimeMeasured = runtimeEvents.length > 0
  /**
   * Newest runtime observation, published so consumers can distinguish
   * "telemetry exists" from "telemetry is CURRENT".
   *
   * `runtimeMeasured` alone is true for a single event of any age, which let
   * the workflow rail claim "Runtime telemetry live — posture is continuously
   * monitored" on a tenant whose newest event was 15 hours old and whose only
   * collector had never sent a heartbeat. This value is additive: it does not
   * change the readiness blend above, only what consumers are able to assert.
   */
  const latestRuntimeEventMs = runtimeEvents.reduce((best, event) => {
    const ms = Math.max(Date.parse(str(event.observed_at)) || 0, Date.parse(str(event.created_at)) || 0)
    return ms > best ? ms : best
  }, 0)
  const latestRuntimeEventAt = latestRuntimeEventMs ? new Date(latestRuntimeEventMs).toISOString() : null

  const postureMeasured = readinessPostureMeasured({ cryptoComponents, findings: { critical, high, medium, low } })
  const quantumReadiness = hasData ? blendQuantumReadiness({ pqcAdoption, quantumRisk, runtimeMeasured, postureMeasured }) : 0

  const hndlEvents = runtimeEvents.filter((e) => e.hndl_risk === true).length
  const hndlEventShare = runtimeEvents.length > 0 ? (hndlEvents / runtimeEvents.length) * 100 : 0
  const classicalVaultShare = dataRepositories > 0
    ? (vaultFiles.filter((f) => classifyAlgorithm(str(f.encryption_algorithm)) !== 'pqc').length / dataRepositories) * 100
    : 0
  const hndlRisk = hasData
    ? Math.round(clamp(vulnerableShare * 0.4 + hndlEventShare * 0.25 + classicalVaultShare * 0.2 + internetShare * 0.15))
    : 0

  const cryptoExposure = hasData ? Math.round(clamp(vulnerableShare * 0.6 + internetShare * 0.4)) : 0

  const dependencyDepth = assetsAssessed > 0 ? clamp((trustRelationships / assetsAssessed) * 40) : 0
  const footprint = clamp((assetsAssessed / 50) * 20 + (certificatesAnalyzed / 50) * 15 + (cloudAccounts / 5) * 15)
  const migrationComplexity = hasData ? Math.round(clamp(dependencyDepth * 0.4 + footprint * 0.4 + vulnerableShare * 0.2)) : 0

  /* Migration scope is measured in COMPONENTS. `quantumVulnerableAssets` used to
     be added to `vulnerable` here, which mixes units (assets + components) AND
     double-counts — those assets are vulnerable precisely BECAUSE of the
     components already counted. Assets now enter through a per-asset cutover
     overhead below, which is a real and separately-scaled cost. */
  const remaining = vulnerable
  const cutoverAssets = quantumVulnerableAssets
  const migrationEffort = hasData ? Math.round(clamp((remaining / Math.max(1, totalCrypto)) * 100)) : 0

  // Effort scales linearly with remaining scope; CALENDAR duration must not — a
  // large estate runs parallel migration workstreams (app teams migrate their
  // own stacks). Workstreams are added once single-lane execution would exceed
  // ~2 years of wave work (capped at 64 parallel lanes ≈ one team per ~110
  // components on a mega estate), so a 5,000-component estate plans a bounded
  // multi-year calendar instead of an absurd multi-thousand-week single lane.
  // For small estates (1 workstream) the numbers are identical to the original
  // model.
  // Component work + bounded per-asset cutover/validation overhead (0.2 wk each):
  // change windows, scheduling and post-change verification are paid per asset
  // however many components it carries.
  const { parallelWorkstreams, migrationTimelineWeeks } = estimateMigrationSchedule({
    vulnerableComponents: remaining,
    vulnerableAssets: cutoverAssets,
    migrationComplexity,
    hasData,
  })
  // Rate and hours/week are TENANT assumptions, not platform constants
  // (src/lib/migration/cost-model.ts). Defaults apply until a tenant sets theirs.
  const migrationCostUsd = computeMigrationCostUsd(migrationTimelineWeeks, parallelWorkstreams, costAssumptions)

  /* Business value — ONE model, shared with the Executive Command Center, so the
     planner and the executive page can no longer publish different exposure. */
  const businessCriticalTagged = assets.filter((a) =>
    ['critical', 'high'].includes(String((a as Record<string, unknown>).criticality || '').toLowerCase()),
  ).length
  const businessValue = buildFinancialExposure(
    { vulnerableAssets: quantumVulnerableAssets, taggedCriticalAssets: businessCriticalTagged, pqcReadyAssets },
    costAssumptions,
  )

  // ---- Factor breakdowns ------------------------------------------------
  // Terminology: this factor measures the CBOM component share (pqcReady /
  // totalCrypto are cryptographic COMPONENTS, not assets) — labelled accordingly
  // so it can never be confused with the asset-level `pqcReadyAssets` count.
  //
  // `measured: false` factors carry score 0 only for contract compatibility —
  // every consumer must branch on `measured` and render "Not measured" with the
  // basis, never the 0 (data-integrity rule 3).
  const pct = (part: number, whole: number) => Math.round(clamp(whole > 0 ? (part / whole) * 100 : 0))
  const readinessFactors: ReadinessFactor[] = [
    {
      label: 'PQC-Ready Components',
      score: pct(pqcReadyComponents, totalCrypto),
      measured: cryptoComponents > 0,
      basis: cryptoComponents > 0
        ? `${pqcReadyComponents} of ${cryptoComponents} quantum-relevant CBOM component(s) are post-quantum or hybrid`
        : 'No cryptographic inventory recorded yet',
    },
    {
      label: 'Hybrid Crypto Adoption',
      score: pct(hybridComponentRows, cryptoComponentRows.length),
      measured: cryptoComponentRows.length > 0,
      basis: cryptoComponentRows.length > 0
        ? `${hybridComponentRows} of ${cryptoComponentRows.length} CBOM component(s) negotiate a hybrid classical + PQC primitive`
        : 'No cryptographic inventory recorded yet',
    },
    {
      label: 'TLS / Key Exchange PQC Coverage',
      score: pct(keyExchangeQuantumSafe, keyExchangeMeasured),
      measured: keyExchangeMeasured > 0,
      basis: keyExchangeMeasured > 0
        ? `${keyExchangeQuantumSafe} of ${keyExchangeMeasured} observed key exchange(s) / cipher suite(s) use ML-KEM or a hybrid group`
        : 'No key exchange or cipher suite observed — scan a TLS, SSH or VPN endpoint',
    },
    {
      label: 'PKI Quantum Readiness',
      score: pct(quantumSafeCertificates, certificates.length),
      measured: certificates.length > 0,
      basis: certificates.length > 0
        ? `${quantumSafeCertificates} of ${certificates.length} certificate(s) carry a PQC or hybrid signature`
        : 'No certificate inventory recorded yet',
    },
    {
      label: 'Crypto-Agility Readiness',
      score: 0,
      measured: false,
      basis: 'Not part of this assessment — measured by the Crypto Agility Engine',
    },
    {
      label: 'Governance Maturity',
      score: 0,
      measured: false,
      basis: 'No governance evidence source feeds this assessment — excluded from the readiness score',
    },
    {
      label: 'Runtime Visibility',
      score: runtimeMeasured ? 100 : 0,
      measured: runtimeMeasured,
      basis: runtimeMeasured
        ? `${runtimeEvents.length} runtime crypto event(s) observed${latestRuntimeEventAt ? `, newest ${latestRuntimeEventAt}` : ''}`
        : 'No runtime crypto telemetry — excluded from the readiness score',
    },
  ]
  const riskFactors = [
    { label: 'RSA / ECC Exposure', score: Math.round(clamp(vulnerableShare)), severity: levelFromRisk(vulnerableShare) },
    { label: 'HNDL Exposure', score: hndlRisk, severity: levelFromRisk(hndlRisk) },
    { label: 'Internet-Facing Exposure', score: Math.round(clamp(internetShare)), severity: levelFromRisk(internetShare) },
    { label: 'Critical Asset Dependency', score: Math.round(clamp(dependencyDepth)), severity: levelFromRisk(dependencyDepth) },
    { label: 'Severity Pressure', score: Math.round(severityPressure), severity: levelFromRisk(severityPressure) },
  ]

  // ---- Critical findings ------------------------------------------------
  // Mirror the scanner's expanded findings (critical/high) when available so the
  // QR findings table matches scanner intelligence; otherwise use graded scan rows.
  const assetNameById = new Map<string, Record<string, unknown>>(assets.map((a) => [str(a.id), a]))
  type CriticalFinding = RawCriticalFinding

  // Map raw scanner evidence into display rows. The scanner emits one finding per
  // detected instance, so the same algorithm on the same asset shows up many times.
  const rawCriticalFindings: CriticalFinding[] = intelHasData && intelFindings.length
    ? intelFindings
        .filter((f) => {
          const t = str(f.threatLevel).toLowerCase()
          return t.includes('critical') || t.includes('high')
        })
        .map((f, index) => ({
          id: str(f.id) || `intel-${index}`,
          title: `${str(f.algorithm) || str(f.category) || 'Quantum-vulnerable algorithm'} detected`,
          asset: str(f.location) || 'Unknown asset',
          assetType: str(f.category) || 'asset',
          environment: 'unknown',
          severity: str(f.threatLevel).toLowerCase() || 'high',
          algorithm: str(f.algorithm) || '—',
          detectedAt: str(f.detectedAt) || str(f.timestamp) || null,
          instances: 1,
        }))
    : scanResults
        .filter((r) => {
          const t = str(r.threat_level).toLowerCase()
          return t.includes('critical') || t.includes('high')
        })
        .map((r) => {
          const asset = assetNameById.get(str(r.asset_id))
          return {
            id: str(r.id),
            title: `${str(r.algorithm) || 'Quantum-vulnerable algorithm'} detected`,
            asset: str(asset?.name) || str(r.asset_id) || 'Unknown asset',
            assetType: str(asset?.type) || 'asset',
            environment: str(asset?.environment) || 'unknown',
            severity: str(r.threat_level) || 'high',
            algorithm: str(r.algorithm) || '—',
            detectedAt: str(r.created_at) || null,
            instances: 1,
          }
        })

  // Collapse identical evidence into one record per algorithm + canonical asset +
  // environment + severity, carrying the true instance count and every merged
  // detection location. See src/api-server/critical-findings.ts for why the raw
  // location cannot be the key.
  const collapsedCriticalFindings = collapseCriticalFindings(rawCriticalFindings)
  const criticalFindings = collapsedCriticalFindings.slice(0, 24)
  /* Totals over the WHOLE collapsed set, so a panel listing the first 24 can say
     so — and so its instance column can be reconciled with the severity counts. */
  const criticalFindingsSummary = {
    records: collapsedCriticalFindings.length,
    instances: collapsedCriticalFindings.reduce((sum, f) => sum + Math.max(1, Number(f.instances) || 1), 0),
    shown: criticalFindings.length,
  }

  // ---- Recommended actions ---------------------------------------------
  const recommendedActions: Array<{ id: string; title: string; detail: string; severity: string; route: string }> = []
  if (vulnerable > 0) {
    recommendedActions.push({
      id: 'rec-vuln',
      // `vulnerable` counts CBOM COMPONENTS (protocol versions and suites
      // included), not distinct algorithms — labelled as the unit it is.
      title: `Remediate ${vulnerable} quantum-vulnerable CBOM component${vulnerable === 1 ? '' : 's'}`,
      detail: 'Replace RSA/ECC primitives with ML-KEM / ML-DSA or hybrid equivalents.',
      severity: 'critical',
      route: '/dashboard/crypto-agility',
    })
  }
  if (quantumVulnerableAssets > 0) {
    recommendedActions.push({
      id: 'rec-assets',
      title: `Prioritise ${quantumVulnerableAssets} quantum-vulnerable asset${quantumVulnerableAssets === 1 ? '' : 's'}`,
      detail: 'Sequence these into the next migration wave via the AI Migration Advisor.',
      severity: 'high',
      route: '/dashboard/quantum-readiness/ai-migration-advisor',
    })
  }
  if (hndlRisk >= 40) {
    recommendedActions.push({
      id: 'rec-hndl',
      title: 'Mitigate Harvest-Now-Decrypt-Later exposure',
      detail: 'Re-encrypt long-lived sensitive data under PQC envelopes.',
      severity: 'high',
      route: '/dashboard/harvest-now',
    })
  }
  if (certificatesAnalyzed === 0) {
    recommendedActions.push({
      id: 'rec-pki',
      title: 'Connect PKI / certificate inventory',
      detail: 'Certificate evidence is required to score PKI maturity accurately.',
      severity: 'medium',
      route: '/dashboard/pki-visibility',
    })
  }
  if (!hasData) {
    recommendedActions.push({
      id: 'rec-scan',
      title: 'Run your first PQC discovery scan',
      detail: 'Discover cryptographic assets to begin the quantum readiness assessment.',
      severity: 'medium',
      route: '/dashboard/scanner',
    })
  }

  // ---- Top risk assets --------------------------------------------------
  const topRiskAssets = assets
    .map((a) => ({
      asset: str(a.name) || 'Unnamed asset',
      assetType: str(a.type) || 'asset',
      environment: str(a.environment) || 'unknown',
      owner: str(a.service_owner) || 'Unassigned',
      riskScore: Math.round(assetRisk.get(str(a.id)) || 0),
      status: ({ pqc: 'PQC-Ready', vulnerable: 'Quantum-Vulnerable', hybrid: 'Hybrid / In-Progress', unknown: 'Not Assessed' } as const)[displayPosture(str(a.id))],
    }))
    .filter((a) => a.riskScore > 0 || quantumVulnerableAssets === 0)
    .sort((x, y) => y.riskScore - x.riskScore)
    .slice(0, 10)

  // ---- Posture by asset type ---------------------------------------------
  // The per-asset verdict of the SHARED posture model, rolled up by the raw
  // `assets.type`, so a consumer that groups assets into categories (the
  // Executive Asset Inventory) reports "at risk" from the same verdict as the
  // Quantum-Vulnerable Assets KPI — not from the business-criticality tag, which
  // read "0 at risk" beside "1 quantum-vulnerable asset".
  const assetTypePostureMap = new Map<string, { type: string; total: number; quantumVulnerable: number }>()
  for (const asset of assets) {
    const type = str(asset.type) || 'unknown'
    const entry = assetTypePostureMap.get(type) || { type, total: 0, quantumVulnerable: 0 }
    entry.total += 1
    if (assetPosture.get(str(asset.id)) === 'vulnerable') entry.quantumVulnerable += 1
    assetTypePostureMap.set(type, entry)
  }
  const assetTypePosture = [...assetTypePostureMap.values()]

  // ---- Exposure graph ---------------------------------------------------
  const rankedAssets =[...assets].sort((a, b) => (assetRisk.get(str(b.id)) || 0) - (assetRisk.get(str(a.id)) || 0)).slice(0, 40)
  const nodes = rankedAssets.map((a) => ({
    id: str(a.id),
    label: str(a.name) || 'asset',
    type: str(a.type) || 'asset',
    environment: str(a.environment) || 'unknown',
    riskScore: Math.round(assetRisk.get(str(a.id)) || 0),
    posture: displayPosture(str(a.id)),
    internetFacing: isInternetFacing(a),
  }))
  const nodeIds = new Set(nodes.map((n) => n.id))
  const relSource = (r: Record<string, unknown>) => str(r.source_asset_id || r.parent_asset_id || r.from_asset_id)
  const relTarget = (r: Record<string, unknown>) => str(r.target_asset_id || r.child_asset_id || r.to_asset_id)
  const edges = assetRelationships
    .filter((r) => nodeIds.has(relSource(r)) && nodeIds.has(relTarget(r)))
    .slice(0, 140)
    .map((r) => ({ source: relSource(r), target: relTarget(r), type: str(r.relationship_type) || 'depends-on' }))

  // ---- Risk / readiness trend ------------------------------------------
  // The trend is the headline scores' OWN recorded history. It used to be a
  // per-session `100 - findings / assets` ratio — a different metric, drawn
  // under the "Readiness" and "Risk" legends beside scores it did not match.
  // In-memory (degraded) reads are not recorded: they are not durable evidence.
  const scoreHistory = persistence === 'database'
    ? await syncScoreHistory(
        client,
        userId,
        hasData
          ? {
              quantumReadiness,
              quantumRisk,
              hndlRisk,
              pqcAdoption: Math.round(clamp(pqcAdoption)),
              assetsAssessed,
              cryptoComponents,
              vulnerableComponents,
              criticalFindings: critical,
              highFindings: high,
            }
          : null,
      )
    : { available: false, reason: 'The assessment database is unreachable — showing in-memory scan results, which are not recorded as history.', points: [] }
  const riskTrend = scoreHistory.points.map((p) => ({ label: p.label, readiness: p.readiness, risk: p.risk, recordedAt: p.recordedAt }))

  // ---- Assessment progress ---------------------------------------------
  /* Named, so a consumer can say WHICH evidence is missing rather than
     printing a bare percentage. `assessmentProgress` is derived from this list
     and nothing else. */
  const evidenceSources = [
    { id: 'assets', label: 'Asset inventory', present: assetsAssessed > 0 },
    { id: 'scans', label: 'Discovery scans', present: scanResults.length > 0 || scanSessions.length > 0 },
    { id: 'certificates', label: 'Certificates', present: certificatesAnalyzed > 0 },
    { id: 'keys', label: 'Key inventory', present: keysDiscovered > 0 },
    { id: 'relationships', label: 'Asset relationships', present: trustRelationships > 0 },
    { id: 'runtime', label: 'Runtime telemetry', present: runtimeEvents.length > 0 },
    { id: 'cbom', label: 'Cryptographic inventory', present: cryptoInventory.length > 0 },
  ]
  const assessmentProgress = Math.round((evidenceSources.filter((source) => source.present).length / evidenceSources.length) * 100)
  const assessmentStatus = !hasData ? 'not_started' : assessmentProgress >= 85 ? 'complete' : 'in_progress'

  const allTimestamps = [
    ...scanSessions.map((s) => str(s.completed_at) || str(s.created_at)),
    ...scanResults.map((r) => str(r.created_at)),
    ...runtimeEvents.map((e) => str(e.observed_at) || str(e.created_at)),
  ].filter(Boolean)
  const lastAssessmentAt = allTimestamps.length
    ? allTimestamps.sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0]
    : null

  // ---- Shared Responsibility (ownership) intelligence -------------------
  // Classify findings into customer / provider / ecosystem ownership domains so
  // every consumer of the snapshot (QR pages, Executive, Reporting, Certification,
  // Migration Planner) inherits the SAME tri-part readiness by construction. The
  // full findings/matrix detail is served by /api/v1/migration-intelligence; the
  // snapshot carries a bounded summary. Evidence-derived attribution only — no
  // provider is guessed without matching tenant evidence.
  // Build ownership inputs via the SHARED adapter — the identical logic the
  // /api/v1/migration-intelligence router uses — so the snapshot's tri-part
  // readiness and ownership distribution (consumed by the Report Center,
  // Executive strip, certification and migration planner) match the flagship
  // Migration Intelligence dashboard exactly. `intel` carries the scanner
  // findings + assets used for evidence-derived attribution.
  const connectorProviders = connectorAccounts.map((a) => str(a.provider)).filter(Boolean)
  const srInputs = buildOwnershipInputs(intel, { criticalFindings })
  const sharedResponsibility = buildSharedResponsibility(srInputs, {
    context: { connectorProviders },
    baselineOverall: quantumReadiness,
    maxFindings: 12,
    maxMatrix: 24,
    maxBlockers: 8,
  })

  return {
    generatedAt: new Date().toISOString(),
    lastAssessmentAt,
    assessmentProgress,
    evidenceSources,
    assessmentStatus,
    hasData,
    /**
     * Which store answered. 'memory' means the database was unreachable and the
     * scanner's in-process results were read instead: real scan output, but not
     * durable. Every surface built on this snapshot can therefore disclose a
     * degraded read instead of presenting it as the tenant's stored estate.
     */
    persistence,
    scores: {
      quantumReadiness,
      quantumReadinessLevel: levelFromReadiness(quantumReadiness),
      quantumRisk,
      quantumRiskLevel: levelFromRisk(quantumRisk),
      hndlRisk,
      hndlRiskLevel: levelFromRisk(hndlRisk),
      cryptoExposure,
      cryptoExposureLevel: levelFromRisk(cryptoExposure),
      migrationComplexity,
      migrationComplexityLevel: levelFromRisk(migrationComplexity),
      migrationEffort,
      pqcAdoption: Math.round(clamp(pqcAdoption)),
    },
    inventory: {
      assetsAssessed,
      certificatesAnalyzed,
      keysDiscovered,
      trustRelationships,
      domainsScanned,
      identitiesAnalyzed: 0,
      cloudAccounts,
      dataRepositories,
      pqcReadyAssets,
      hybridAssets,
      /** Subset of `hybridAssets` with no crypto evidence at all — not measured, not "in progress". */
      unassessedAssets,
      quantumVulnerableAssets,
      cryptoComponents,
      vulnerableComponents,
      /**
       * Provenance for the component total, so any surface can explain why it
       * differs from the raw crypto_inventory row count: findings live in the
       * same table and are counted in pqc_scan_results / crypto_exposures
       * instead. `cbomTruncated` is true only past the detail-row cap, where
       * the crypto share is carried onto the exact head-count.
       */
      cryptoInventoryRows: cryptoInventory.length,
      findingRowsExcluded,
      cbomTruncated,
      pqcReadyComponents,
    },
    riskDistribution: { critical, high, medium, low },
    sharedResponsibility,
    readinessFactors,
    riskFactors,
    criticalFindings,
    criticalFindingsSummary,
    recommendedActions,
    topRiskAssets,
    assetTypePosture,
    exposureGraph: { nodes, edges },
    riskTrend,
    /** Whether `riskTrend` can exist, and why not when it cannot. */
    scoreHistory: { available: scoreHistory.available, reason: scoreHistory.reason, points: scoreHistory.points.length },
    estimates: { migrationTimelineWeeks, migrationCostUsd, parallelWorkstreams },
    costAssumptions,
    businessValue,
    telemetry: {
      runtimeEvents: runtimeEvents.length,
      scanResults: scanResults.length,
      scanSessions: scanSessions.length,
      securityEvents: securityEvents.length,
      certificates: certificatesAnalyzed,
      keys: keysDiscovered,
      assets: assetsAssessed,
      connectors: cloudAccounts,
      latestEventAt: lastAssessmentAt,
      /** Newest RUNTIME observation specifically — see the note at its source. */
      latestRuntimeEventAt,
    },
  }
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const snapshot = await buildSnapshot(token!, user!.id)
    res.json({ data: { ...snapshot, fingerprint: payloadFingerprint(snapshot) } })
  } catch (error) {
    console.error('Quantum readiness aggregation error:', error)
    res.status(500).json({ error: { code: 'QUANTUM_READINESS_ERROR', message: 'Failed to compute quantum readiness assessment' } })
  }
})

/**
 * Live assessment stream for the nine Quantum Readiness pages. The snapshot is
 * sent once, then again only when its content changes; between changes an
 * `-unchanged` frame proves the estate was re-checked. The 8s tick is a cache
 * read inside the 15s single-flight window, so open tabs cost one build.
 */
router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, {
    event: 'quantum-readiness',
    build: () => buildSnapshot(token!, user!.id),
    intervalMs: 8_000,
  })
})

export default router
