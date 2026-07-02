import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildScannerIntelligence } from './scanner'

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

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

const QUANTUM_VULNERABLE_PREFIXES = ['RSA', 'ECC', 'ECDSA', 'ECDH', 'DH', 'DSA', 'ELGAMAL', 'EL-GAMAL']
const QUANTUM_VULNERABLE_EXACT = ['SHA-1', 'SHA1', 'MD5', '3DES', 'DES', 'RC4']
const PQC_MARKERS = ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'KYBER', 'DILITHIUM', 'SPHINCS', 'FALCON', 'FRODOKEM', 'BIKE', 'HQC']
const HYBRID_MARKERS = ['HYBRID', 'X25519+ML-KEM', 'ED25519+ML-DSA', 'X25519MLKEM']

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  // Header-only auth (Authorization: Bearer). No query-string token fallback —
  // this router exposes JSON only (no SSE/EventSource), so there is no need to
  // accept tokens in the URL where they could leak into logs, proxies or Referer.
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

function classifyAlgorithm(raw: string): 'vulnerable' | 'pqc' | 'hybrid' | 'unknown' {
  const algo = raw.toUpperCase().trim()
  if (!algo) return 'unknown'
  if (HYBRID_MARKERS.some((m) => algo.includes(m))) return 'hybrid'
  if (PQC_MARKERS.some((m) => algo.includes(m))) return 'pqc'
  if (QUANTUM_VULNERABLE_EXACT.includes(algo)) return 'vulnerable'
  if (QUANTUM_VULNERABLE_PREFIXES.some((p) => algo.startsWith(p))) return 'vulnerable'
  return 'unknown'
}

function levelFromRisk(score: number): string {
  if (score >= 80) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 40) return 'Elevated'
  if (score >= 20) return 'Moderate'
  if (score > 0) return 'Low'
  return 'Minimal'
}
function levelFromReadiness(score: number): string {
  if (score >= 85) return 'Quantum-Ready'
  if (score >= 65) return 'Advanced'
  if (score >= 45) return 'Developing'
  if (score >= 25) return 'Early Stage'
  if (score > 0) return 'Initial'
  return 'Not Started'
}
function severityWeight(sev: string): number {
  const s = sev.toLowerCase()
  if (s.includes('critical')) return 100
  if (s.includes('high')) return 75
  if (s.includes('medium') || s.includes('moderate')) return 50
  if (s.includes('low')) return 25
  return 10
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Record<string, unknown>[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Quantum readiness ${table} query skipped:`, error.message || error)
      return []
    }
    return (data as Record<string, unknown>[]) || []
  } catch (error) {
    console.warn(`Quantum readiness ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

function isInternetFacing(asset: Record<string, unknown>): boolean {
  const env = str(asset.environment).toLowerCase()
  if (['public', 'internet', 'dmz', 'external', 'edge'].some((e) => env.includes(e))) return true
  const meta = recordOf(asset.metadata)
  if (meta.internet_facing === true || meta.public === true) return true
  const exposure = str(meta.exposure || meta.exposure_level).toLowerCase()
  if (exposure.includes('internet') || exposure.includes('public') || exposure.includes('external')) return true
  // Domain / website / TLS-endpoint / gateway assets are internet-facing by
  // nature — a scanned public domain (e.g. "qguardhelix.com") must not read as
  // internal. Mirror the domain-asset heuristic used for `domainsScanned`.
  const type = str(asset.type).toLowerCase()
  if (/web|domain|tls|endpoint|site|host|gateway|cdn|proxy|load|dns|ingress|api/i.test(type)) return true
  const name = str(asset.name)
  if (/^https?:\/\//i.test(name) || /\.[a-z]{2,}(?::\d+)?$/i.test(name)) return true
  return false
}

export async function buildSnapshot(token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
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
  let intel: IntelSnapshot | null = null
  try {
    intel = (await buildScannerIntelligence(token, userId)) as IntelSnapshot
  } catch {
    intel = null
  }
  const intelSummary = intel?.summary
  const intelSeverity = intel?.severityCounts
  const intelFindings = intel?.findings || []
  const intelHasData = Boolean(intelSummary && ((intelSummary.totalComponents || 0) > 0 || intelFindings.length > 0))

  // ---- Inventory --------------------------------------------------------
  const assetsAssessed = assets.length
  const certificatesAnalyzed = certificates.length
  const keysDiscovered = generatedKeys.length
  const trustRelationships = assetRelationships.length
  const cloudAccounts = connectorAccounts.length
  const dataRepositories = vaultFiles.length
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
      ...scanResults.map((r) => str(r.target_name)),
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

  if (cryptoInventory.length) {
    for (const item of cryptoInventory) {
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

  const totalCrypto = intelHasData && intelSummary ? Math.max(1, num(intelSummary.totalComponents)) : vulnerable + pqcReady + hybrid
  const cryptoComponents = intelHasData && intelSummary ? num(intelSummary.totalComponents) : (cryptoInventory.length || totalCrypto)
  const vulnerableComponents = intelHasData && intelSummary ? num(intelSummary.vulnerableComponents) : vulnerable
  const pqcReadyComponents = intelHasData && intelSummary ? num(intelSummary.pqcReadyComponents) : pqcReady + hybrid

  // ---- Per-asset risk ---------------------------------------------------
  const assetRisk = new Map<string, number>()
  const bumpAsset = (assetId: string, weight: number) => {
    if (!assetId) return
    assetRisk.set(assetId, Math.max(assetRisk.get(assetId) || 0, weight))
  }
  for (const result of scanResults) bumpAsset(str(result.asset_id), severityWeight(str(result.threat_level)))
  for (const exposure of cryptoExposures) bumpAsset(str(exposure.asset_id), severityWeight(str(exposure.severity)))
  for (const item of cryptoInventory) if (item.is_vulnerable === true) bumpAsset(str(item.asset_id), 65)
  for (const event of runtimeEvents) {
    if (event.is_legacy === true || event.hndl_risk === true) bumpAsset(str(event.asset_id), Math.max(60, num(event.risk_score)))
    else if (num(event.risk_score) > 0) bumpAsset(str(event.asset_id), num(event.risk_score))
  }

  // ---- Asset posture & internet exposure --------------------------------
  const vulnerableAssetIds = new Set<string>()
  const pqcAssetIds = new Set<string>()
  for (const result of scanResults) if (classifyAlgorithm(str(result.algorithm)) === 'vulnerable') vulnerableAssetIds.add(str(result.asset_id))
  for (const item of cryptoInventory) {
    if (item.is_vulnerable === true) vulnerableAssetIds.add(str(item.asset_id))
    if (item.is_quantum_safe === true) pqcAssetIds.add(str(item.asset_id))
  }

  let pqcReadyAssets = 0
  let hybridAssets = 0
  let quantumVulnerableAssets = 0
  let internetFacing = 0
  const assetPosture = new Map<string, 'pqc' | 'hybrid' | 'vulnerable'>()
  for (const asset of assets) {
    const id = str(asset.id)
    const isVuln = vulnerableAssetIds.has(id) || (assetRisk.get(id) || 0) >= 50
    const isPqc = pqcAssetIds.has(id) && !isVuln
    const posture: 'pqc' | 'hybrid' | 'vulnerable' = isVuln ? 'vulnerable' : isPqc ? 'pqc' : 'hybrid'
    assetPosture.set(id, posture)
    if (posture === 'vulnerable') quantumVulnerableAssets += 1
    else if (posture === 'pqc') pqcReadyAssets += 1
    else hybridAssets += 1
    if (isInternetFacing(asset)) internetFacing += 1
  }

  // If no asset-level posture could be derived, fall back to algorithm shares.
  if (assetsAssessed === 0) {
    pqcReadyAssets = pqcReady
    hybridAssets = hybrid
    quantumVulnerableAssets = vulnerable
  }

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
  const severityPressure = totalFindings > 0
    ? clamp(((critical * 4 + high * 2.5 + medium * 1 + low * 0.4) / totalFindings) * 22)
    : 0
  const vulnerableShare = totalCrypto > 0 ? (vulnerable / totalCrypto) * 100 : 0
  const internetShare = assetsAssessed > 0 ? (internetFacing / assetsAssessed) * 100 : 0
  const quantumRisk = hasData
    ? Math.round(clamp(severityPressure * 0.45 + vulnerableShare * 0.4 + internetShare * 0.15))
    : 0

  const pqcAdoption = totalCrypto > 0 ? ((pqcReady + hybrid * 0.5) / totalCrypto) * 100 : 0
  // Runtime visibility is a MEASURED signal: non-zero only when real runtime
  // crypto telemetry exists. Scan sessions alone do not observe runtime paths,
  // so they no longer grant a 55-point proxy (reports showed "Runtime
  // Visibility 55" next to "Runtime Telemetry: No Data" — a contradiction).
  // When runtime is not measured the factor is EXCLUDED from the readiness
  // blend and the remaining weights are renormalised, instead of silently
  // scoring an unmeasured factor.
  const runtimeMeasured = runtimeEvents.length > 0
  const runtimeVisibility = runtimeMeasured ? 100 : 0
  const governanceMaturity = scanSessions.length > 0 ? 60 : 0

  const readinessWeightSum = runtimeMeasured ? 1 : 0.85
  const quantumReadiness = hasData
    ? Math.round(clamp((pqcAdoption * 0.45 + (100 - quantumRisk) * 0.25 + (runtimeMeasured ? runtimeVisibility * 0.15 : 0) + governanceMaturity * 0.15) / readinessWeightSum))
    : 0

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

  const remaining = vulnerable + quantumVulnerableAssets
  const migrationEffort = hasData ? Math.round(clamp((remaining / Math.max(1, totalCrypto + assetsAssessed)) * 100)) : 0

  const baseWeeks = remaining * 0.6 * (1 + migrationComplexity / 200)
  const migrationTimelineWeeks = hasData ? Math.max(remaining > 0 ? 2 : 0, Math.round(baseWeeks)) : 0
  const migrationCostUsd = migrationTimelineWeeks > 0 ? Math.round(migrationTimelineWeeks * 38 * 165) : 0

  // ---- Factor breakdowns ------------------------------------------------
  // Terminology: this factor measures the CBOM component share (pqcReady /
  // totalCrypto are cryptographic COMPONENTS, not assets) — labelled accordingly
  // so it can never be confused with the asset-level `pqcReadyAssets` count.
  const readinessFactors = [
    { label: 'PQC-Ready Components', score: Math.round(clamp(totalCrypto > 0 ? (pqcReady / totalCrypto) * 100 : 0)) },
    { label: 'Hybrid Crypto Adoption', score: Math.round(clamp(totalCrypto > 0 ? (hybrid / totalCrypto) * 100 : 0)) },
    { label: 'TLS / Protocol Maturity', score: Math.round(clamp(domainsScanned > 0 ? 100 - vulnerableShare : 0)) },
    { label: 'PKI Maturity', score: Math.round(clamp(certificatesAnalyzed > 0 ? 100 - vulnerableShare * 0.8 : 0)) },
    { label: 'Crypto-Agility Readiness', score: Math.round(clamp(pqcAdoption)) },
    { label: 'Governance Maturity', score: Math.round(governanceMaturity) },
    { label: 'Runtime Visibility', score: Math.round(runtimeVisibility) },
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
  type CriticalFinding = {
    id: string
    title: string
    asset: string
    assetType: string
    environment: string
    severity: string
    algorithm: string
    detectedAt: string | null
    instances: number
  }

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

  // Collapse identical evidence rows (same finding + algorithm + asset + environment
  // + severity) into a single record, tracking how many raw instances it represents.
  // Keep the earliest detection timestamp so the evidence stays traceable.
  const findingByKey = new Map<string, CriticalFinding>()
  for (const f of rawCriticalFindings) {
    const key = `${f.title}|${f.algorithm}|${f.asset}|${f.environment}|${f.severity}`.toLowerCase()
    const existing = findingByKey.get(key)
    if (existing) {
      existing.instances += 1
      if (f.detectedAt && (!existing.detectedAt || f.detectedAt < existing.detectedAt)) {
        existing.detectedAt = f.detectedAt
      }
    } else {
      findingByKey.set(key, { ...f })
    }
  }
  const criticalFindings = Array.from(findingByKey.values()).slice(0, 24)

  // ---- Recommended actions ---------------------------------------------
  const recommendedActions: Array<{ id: string; title: string; detail: string; severity: string; route: string }> = []
  if (vulnerable > 0) {
    recommendedActions.push({
      id: 'rec-vuln',
      title: `Remediate ${vulnerable} quantum-vulnerable algorithm${vulnerable === 1 ? '' : 's'}`,
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
      status: assetPosture.get(str(a.id)) === 'pqc' ? 'PQC-Ready' : assetPosture.get(str(a.id)) === 'vulnerable' ? 'Quantum-Vulnerable' : 'Hybrid / In-Progress',
    }))
    .filter((a) => a.riskScore > 0 || quantumVulnerableAssets === 0)
    .sort((x, y) => y.riskScore - x.riskScore)
    .slice(0, 10)

  // ---- Exposure graph ---------------------------------------------------
  const rankedAssets = [...assets].sort((a, b) => (assetRisk.get(str(b.id)) || 0) - (assetRisk.get(str(a.id)) || 0)).slice(0, 40)
  const nodes = rankedAssets.map((a) => ({
    id: str(a.id),
    label: str(a.name) || 'asset',
    type: str(a.type) || 'asset',
    environment: str(a.environment) || 'unknown',
    riskScore: Math.round(assetRisk.get(str(a.id)) || 0),
    posture: assetPosture.get(str(a.id)) || 'hybrid',
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
  const riskTrend = scanSessions
    .filter((s) => s.completed_at)
    .sort((a, b) => new Date(str(a.completed_at)).getTime() - new Date(str(b.completed_at)).getTime())
    .slice(-12)
    .map((s) => {
      const total = Math.max(1, num(s.total_assets) || num(s.scanned_assets))
      const findings = num(s.findings_count)
      const readiness = Math.round(clamp(100 - Math.min(100, (findings / total) * 100)))
      return {
        label: new Date(str(s.completed_at)).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        readiness,
        risk: Math.round(clamp(100 - readiness)),
      }
    })

  // ---- Assessment progress ---------------------------------------------
  const signals = [
    assetsAssessed > 0,
    scanResults.length > 0 || scanSessions.length > 0,
    certificatesAnalyzed > 0,
    keysDiscovered > 0,
    trustRelationships > 0,
    runtimeEvents.length > 0,
    cryptoInventory.length > 0,
  ]
  const assessmentProgress = Math.round((signals.filter(Boolean).length / signals.length) * 100)
  const assessmentStatus = !hasData ? 'not_started' : assessmentProgress >= 85 ? 'complete' : 'in_progress'

  const allTimestamps = [
    ...scanSessions.map((s) => str(s.completed_at) || str(s.created_at)),
    ...scanResults.map((r) => str(r.created_at)),
    ...runtimeEvents.map((e) => str(e.observed_at) || str(e.created_at)),
  ].filter(Boolean)
  const lastAssessmentAt = allTimestamps.length
    ? allTimestamps.sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0]
    : null

  return {
    generatedAt: new Date().toISOString(),
    lastAssessmentAt,
    assessmentProgress,
    assessmentStatus,
    hasData,
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
      quantumVulnerableAssets,
      cryptoComponents,
      vulnerableComponents,
      pqcReadyComponents,
    },
    riskDistribution: { critical, high, medium, low },
    readinessFactors,
    riskFactors,
    criticalFindings,
    recommendedActions,
    topRiskAssets,
    exposureGraph: { nodes, edges },
    riskTrend,
    estimates: { migrationTimelineWeeks, migrationCostUsd },
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
    },
  }
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const snapshot = await buildSnapshot(token!, user!.id)
    res.json({ data: snapshot })
  } catch (error) {
    console.error('Quantum readiness aggregation error:', error)
    res.status(500).json({ error: { code: 'QUANTUM_READINESS_ERROR', message: 'Failed to compute quantum readiness assessment' } })
  }
})

export default router
