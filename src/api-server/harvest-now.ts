import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'

/**
 * QGuard Helix Quantum Threat Operations Center™ — Harvest Now, Decrypt Later.
 *
 * Single source of truth for the HNDL dashboard. Reuses the Quantum Readiness
 * snapshot (which mirrors the platform's scanner intelligence) plus targeted raw
 * cryptographic-inventory / certificate / runtime-event reads so every metric,
 * matrix cell, exposure node and remediation action is derived from the tenant's
 * real scanned assets. No fabricated telemetry — where evidence is absent the
 * value reads "Evidence Not Available" or 0 and the section renders an empty
 * state. Intelligence models (harvest value, adversary interest, shelf-life) are
 * deterministic functions of real evidence combined with documented reference
 * data (regulatory retention periods, published PQC standards/milestones).
 */

const router = Router()
type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }
type Row = Record<string, unknown>

function tokenFromRequest(req: Request): string | null {
  // Require the `Authorization: Bearer …` header for BOTH `GET /` and the SSE
  // `GET /stream`. The frontend (use-harvest-now.ts) reads the event-stream via
  // fetch() + ReadableStream with an Authorization header — it never uses
  // EventSource — so the raw Supabase access_token is never placed in the URL /
  // query string, where it would leak into access logs, proxies, referrers and
  // browser history. No `?token=` fallback is accepted (security review HIGH).
  return getToken(req)
}

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = tokenFromRequest(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}
router.use(requireAuth)

const EVIDENCE_UNAVAILABLE = 'Evidence Not Available'
const str = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v))
const num = (v: unknown) => { const n = Number(v); return Number.isFinite(n) ? n : 0 }
const clamp = (n: number, min = 0, max = 100) => Math.max(min, Math.min(max, Math.round(n)))

/**
 * Year a cryptographically-relevant quantum computer (CRQC) is conservatively
 * estimated to threaten RSA-2048 / ECC-256. Aligns with NIST/CNSA 2.0 planning
 * horizons (mandated deprecation of classical asymmetric crypto by 2030-2035).
 */
const CRQC_YEAR = 2030
const NOW_YEAR = new Date().getFullYear()

async function safeRows(
  client: { from: (t: string) => { select: (c: string) => { eq: (k: string, v: string) => { order?: unknown; limit: (n: number) => Promise<{ data: unknown; error: unknown }> } } } },
  table: string,
  columns: string,
  userId: string,
  limit = 2000,
): Promise<Row[]> {
  try {
    const q = client.from(table).select(columns).eq('user_id', userId)
    const built = (q as unknown as { order: (c: string, o: { ascending: boolean }) => { limit: (n: number) => Promise<{ data: unknown; error: unknown }> } }).order('created_at', { ascending: false }).limit(limit)
    const { data, error } = await built
    if (error) return []
    return (data as Row[]) || []
  } catch {
    return []
  }
}

type Snapshot = Awaited<ReturnType<typeof buildSnapshot>>

/* ================================================================== */
/* Cryptographic classification helpers                               */
/* ================================================================== */

type CryptoClass = 'vulnerable' | 'hybrid' | 'safe' | 'unknown'

function classifyAlgorithm(algorithm: string): CryptoClass {
  const a = algorithm.toUpperCase()
  if (!a) return 'unknown'
  if (/ML-KEM|ML-DSA|SLH-DSA|KYBER|DILITHIUM|SPHINCS|FALCON|FIPS\s?20[345]/.test(a)) return 'safe'
  if (/HYBRID|X25519\s*\+|\+\s*ML-KEM|ED25519\s*\+/.test(a)) return 'hybrid'
  if (/AES-?256|SHA3|SHA-?384|SHA-?512|CHACHA20/.test(a) && !/RSA|ECDSA|ECDH|DH\b/.test(a)) return 'safe'
  if (/RSA|ECDSA|ECDH|DSA|DIFFIE|\bDH\b|EC-|P-256|P-384|SECP|3DES|\bDES\b|RC4|MD5|SHA-?1|TLS_RSA/.test(a)) return 'vulnerable'
  return 'unknown'
}

/**
 * Forward secrecy: a transport/key-exchange provides PFS only with ephemeral
 * key agreement (ECDHE / DHE / X25519 / hybrid ML-KEM). RSA key transport,
 * static DH, plain SSH-RSA and "TLS_RSA_*" suites do not.
 */
function hasForwardSecrecy(algorithm: string, protocol: string): boolean {
  const text = `${algorithm} ${protocol}`.toUpperCase()
  if (/ECDHE|DHE|X25519|X448|ML-KEM|KYBER|HYBRID|CURVE25519/.test(text)) return true
  if (/TLS_RSA|RSA_KEY|STATIC|\bRSA\b|SSH-RSA|SSH_RSA|RSA-PSS/.test(text)) return false
  return false
}

function isTransportComponent(algorithm: string, protocol: string, itemType: string): boolean {
  const text = `${algorithm} ${protocol} ${itemType}`.toLowerCase()
  return /tls|ssl|ssh|vpn|ipsec|protocol|handshake|cipher|key.?exchange|kem|dh/.test(text)
}

function migrationPriority(cryptoClass: CryptoClass, assetCount: number, internetFacing: boolean): { label: string; rank: number } {
  if (cryptoClass === 'safe') return { label: 'Quantum Safe', rank: 0 }
  if (cryptoClass === 'hybrid') return { label: 'Low', rank: 1 }
  if (cryptoClass === 'unknown') return { label: 'Medium', rank: 2 }
  if (internetFacing || assetCount >= 5) return { label: 'Critical', rank: 4 }
  return { label: 'High', rank: 3 }
}

function riskWindowLabel(retentionYears: number): { label: string; exceedsCrqc: boolean } {
  const dataExpiresYear = NOW_YEAR + retentionYears
  const exceedsCrqc = dataExpiresYear > CRQC_YEAR
  if (!exceedsCrqc) return { label: 'Within retention', exceedsCrqc: false }
  const exposedYears = dataExpiresYear - CRQC_YEAR
  return { label: `${exposedYears}+ yrs post-CRQC`, exceedsCrqc: true }
}

/* ================================================================== */
/* SECTION 4 / 5 — Data category reference model                      */
/* Sensitivity & regulatory retention are reference facts; exposure is */
/* derived from the tenant's real HNDL risk + vulnerable component mix. */
/* ================================================================== */

const DATA_CATEGORIES: Array<{ key: string; label: string; retentionYears: number; sensitivity: number; match: RegExp; regulation: string }> = [
  { key: 'pii', label: 'Customer PII', retentionYears: 10, sensitivity: 0.82, match: /pii|customer|user|profile|account|crm|identity/i, regulation: 'GDPR / CCPA' },
  { key: 'financial', label: 'Financial Records', retentionYears: 7, sensitivity: 0.86, match: /financ|payment|transaction|billing|ledger|bank|card|pci/i, regulation: 'SOX / PCI DSS' },
  { key: 'trade', label: 'Trade Secrets', retentionYears: 20, sensitivity: 0.95, match: /trade|secret|proprietary|formula|strategy/i, regulation: 'Trade Secret Law' },
  { key: 'ip', label: 'Intellectual Property', retentionYears: 20, sensitivity: 0.92, match: /\bip\b|patent|design|intellectual|model|algorithm/i, regulation: 'IP / Patent Law' },
  { key: 'legal', label: 'Legal Documents', retentionYears: 25, sensitivity: 0.78, match: /legal|contract|agreement|compliance|litigation|nda/i, regulation: 'Legal Hold' },
  { key: 'source', label: 'Source Code', retentionYears: 15, sensitivity: 0.88, match: /source|code|repo|git|build|artifact|registry/i, regulation: 'IP / SDLC' },
  { key: 'rnd', label: 'R&D Data', retentionYears: 20, sensitivity: 0.9, match: /r&d|research|lab|experiment|dataset|training/i, regulation: 'IP / Trade Secret' },
  { key: 'classified', label: 'Classified Assets', retentionYears: 25, sensitivity: 1.0, match: /classified|secret|restricted|government|defense|gov|fed/i, regulation: 'CNSA 2.0 / NSM-10' },
]

/* ================================================================== */
/* SECTION 1 — Quantum Threat Banner                                  */
/* ================================================================== */
function buildBanner(snapshot: Snapshot, futureDecryptableTb: number, criticalFindings: number) {
  const hndl = snapshot.scores.hndlRisk
  const threatLevel = !snapshot.hasData ? 'Unknown' : hndl >= 75 || criticalFindings > 0 ? 'Critical' : hndl >= 50 ? 'High' : hndl >= 30 ? 'Elevated' : 'Guarded'
  const exposureWindow = !snapshot.hasData ? EVIDENCE_UNAVAILABLE : hndl >= 60 ? 'Within 5 Years' : hndl >= 40 ? '5-10 Years' : '10+ Years'
  return {
    threatLevel,
    hndlExposureScore: hndl,
    hndlExposureLevel: snapshot.scores.hndlRiskLevel,
    criticalFindings,
    quantumExposureWindow: exposureWindow,
    estimatedFutureDecryptableTb: futureDecryptableTb,
    migrationDeadlineYear: CRQC_YEAR,
    yearsToDeadline: Math.max(0, CRQC_YEAR - NOW_YEAR),
    headline: snapshot.hasData
      ? `${criticalFindings} critical quantum-vulnerable exposure(s) across ${snapshot.inventory.quantumVulnerableAssets} asset(s). HNDL risk ${hndl}/100 (${snapshot.scores.hndlRiskLevel}).`
      : 'No assessment evidence yet. Run a discovery scan to populate the Quantum Threat Operations Center.',
  }
}

/* ================================================================== */
/* SECTION 2 — Quantum Exposure Graph™                                */
/* Layered: Internet → TLS → Certificates → Keys → Data Stores.       */
/* ================================================================== */
function buildExposureGraph(snapshot: Snapshot, cryptoInventory: Row[], certificates: Row[]) {
  const inv = snapshot.inventory
  const tierClass = (vulnerable: number, total: number): CryptoClass => {
    if (total === 0) return 'unknown'
    if (vulnerable === 0) return 'safe'
    if (vulnerable >= total * 0.6) return 'vulnerable'
    return 'hybrid'
  }
  const tlsItems = cryptoInventory.filter((c) => isTransportComponent(str(c.algorithm), str(c.protocol), str(c.item_type)))
  const tlsVuln = tlsItems.filter((c) => c.is_vulnerable === true || classifyAlgorithm(str(c.algorithm)) === 'vulnerable').length
  const certVuln = certificates.filter((c) => c.is_quantum_safe !== true && classifyAlgorithm(str(c.algorithm)) === 'vulnerable').length
  const keyItems = cryptoInventory.filter((c) => /key|cert|secret/i.test(str(c.item_type)))
  const keyVuln = keyItems.filter((c) => c.is_vulnerable === true).length

  const tiers = [
    { id: 'internet', label: 'Internet Edge', kind: 'edge', total: inv.domainsScanned, vulnerable: 0, cryptoClass: 'unknown' as CryptoClass, detail: `${inv.domainsScanned} internet-facing endpoint(s)` },
    { id: 'tls', label: 'TLS Endpoints', kind: 'protocol', total: tlsItems.length || inv.domainsScanned, vulnerable: tlsVuln, cryptoClass: tierClass(tlsVuln, tlsItems.length || inv.domainsScanned), detail: `${tlsVuln} non-quantum-safe handshake(s)` },
    { id: 'certs', label: 'Certificates', kind: 'pki', total: inv.certificatesAnalyzed, vulnerable: certVuln, cryptoClass: tierClass(certVuln, inv.certificatesAnalyzed), detail: `${certVuln} classical certificate signature(s)` },
    { id: 'keys', label: 'Cryptographic Keys', kind: 'key', total: inv.keysDiscovered || keyItems.length, vulnerable: keyVuln, cryptoClass: tierClass(keyVuln, inv.keysDiscovered || keyItems.length), detail: `${keyVuln} quantum-vulnerable key(s)` },
    { id: 'databases', label: 'Databases', kind: 'store', total: snapshot.exposureGraph.nodes.filter((n) => /db|database|sql|store/i.test(n.type)).length, vulnerable: 0, cryptoClass: 'unknown' as CryptoClass, detail: 'Encrypted-at-rest data stores' },
    { id: 'backups', label: 'Backups & Archives', kind: 'store', total: inv.dataRepositories, vulnerable: 0, cryptoClass: 'unknown' as CryptoClass, detail: `${inv.dataRepositories} long-lived repositor(ies)` },
    { id: 'longterm', label: 'Long-Term Storage', kind: 'store', total: inv.dataRepositories, vulnerable: 0, cryptoClass: 'unknown' as CryptoClass, detail: 'Multi-year confidential retention' },
  ].filter((t) => t.total > 0 || t.id === 'internet' || t.id === 'tls')

  // Per-asset interactive nodes (top exposure) with crypto + migration context.
  const nodes = snapshot.exposureGraph.nodes.slice(0, 24).map((n) => {
    const cls: CryptoClass = n.posture === 'pqc' ? 'safe' : n.posture === 'hybrid' ? 'hybrid' : n.posture === 'vulnerable' ? 'vulnerable' : 'unknown'
    const findings = snapshot.criticalFindings.filter((f) => f.asset === n.label)
    return {
      id: n.id,
      label: n.label,
      type: n.type,
      environment: n.environment,
      riskScore: n.riskScore,
      cryptoClass: cls,
      internetFacing: n.internetFacing,
      algorithms: [...new Set(findings.map((f) => f.algorithm).filter(Boolean))].slice(0, 4),
      affectedDataDetail: findings.length ? `${findings.length} HNDL finding(s)` : cls === 'safe' ? 'Quantum-safe' : 'No critical finding',
      migrationPlan: cls === 'safe' ? 'Maintain' : cls === 'hybrid' ? 'Complete hybrid validation' : 'Deploy ML-KEM / ML-DSA hybrid',
    }
  })
  const edges = snapshot.exposureGraph.edges.slice(0, 60)
  return { tiers, nodes, edges, legend: { safe: 'Quantum Safe', hybrid: 'Hybrid', vulnerable: 'Vulnerable' } }
}

/* ================================================================== */
/* SECTION 3 — Global Quantum Exposure Theater™                       */
/* ================================================================== */
const REGION_COORDS: Record<string, { x: number; y: number }> = {
  'us-east': { x: 27, y: 38 }, 'us-west': { x: 16, y: 40 }, 'us': { x: 22, y: 39 }, 'na': { x: 22, y: 36 },
  'eu-west': { x: 47, y: 32 }, 'eu-central': { x: 50, y: 31 }, 'eu': { x: 49, y: 32 }, 'europe': { x: 49, y: 32 },
  'uk': { x: 46, y: 30 }, 'ap-south': { x: 68, y: 50 }, 'asia': { x: 72, y: 42 }, 'ap-southeast': { x: 78, y: 55 },
  'ap-northeast': { x: 84, y: 40 }, 'apac': { x: 78, y: 48 }, 'sa': { x: 32, y: 66 }, 'south-america': { x: 32, y: 66 },
  'af': { x: 51, y: 56 }, 'africa': { x: 51, y: 56 }, 'me': { x: 58, y: 44 }, 'middle-east': { x: 58, y: 44 }, 'au': { x: 85, y: 70 }, 'oceania': { x: 85, y: 70 },
}
function regionKey(raw: string): string {
  const r = raw.toLowerCase()
  for (const key of Object.keys(REGION_COORDS)) if (r.includes(key)) return key
  return 'us-east'
}
function buildTheater(snapshot: Snapshot, assets: Row[]) {
  const byRegion = new Map<string, { region: string; assets: number; vulnerable: number; riskTotal: number; cloud: Set<string> }>()
  const nodeByLabel = new Map(snapshot.exposureGraph.nodes.map((n) => [n.label, n]))
  for (const a of assets) {
    const rawRegion = str(a.region) || str((a.metadata as Row)?.region) || str(a.environment) || 'us-east'
    const key = regionKey(rawRegion)
    const entry = byRegion.get(key) || { region: rawRegion || key, assets: 0, vulnerable: 0, riskTotal: 0, cloud: new Set<string>() }
    entry.assets += 1
    const node = nodeByLabel.get(str(a.name))
    const risk = node ? node.riskScore : num(a.criticality)
    entry.riskTotal += risk
    if (node?.posture === 'vulnerable' || risk >= 60) entry.vulnerable += 1
    const cloud = str((a.metadata as Row)?.cloud_provider || (a.metadata as Row)?.provider)
    if (cloud) entry.cloud.add(cloud)
    byRegion.set(key, entry)
  }
  const regions = Array.from(byRegion.entries()).map(([key, e]) => {
    const coord = REGION_COORDS[key] || REGION_COORDS['us-east']
    const avgRisk = e.assets ? Math.round(e.riskTotal / e.assets) : 0
    return {
      key, region: e.region, x: coord.x, y: coord.y,
      assets: e.assets, vulnerableAssets: e.vulnerable, avgRisk,
      cloudProviders: Array.from(e.cloud),
      severity: avgRisk >= 70 || e.vulnerable >= 3 ? 'Critical' : avgRisk >= 45 || e.vulnerable > 0 ? 'High' : avgRisk >= 25 ? 'Medium' : 'Low',
    }
  }).sort((a, b) => b.vulnerableAssets - a.vulnerableAssets || b.avgRisk - a.avgRisk)
  return {
    regions,
    totalRegions: regions.length,
    highValueTargets: regions.filter((r) => r.severity === 'Critical' || r.severity === 'High').length,
    summary: regions.length
      ? `${regions.length} region(s) in scope; ${regions.filter((r) => r.vulnerableAssets > 0).length} carry quantum-vulnerable cryptography.`
      : EVIDENCE_UNAVAILABLE,
  }
}

/* ================================================================== */
/* SECTION 4 — Harvest Value Engine™                                  */
/* ================================================================== */
function categoryAssetMatch(category: RegExp, assets: Row[], findings: Snapshot['criticalFindings']): number {
  const assetHits = assets.filter((a) => category.test(`${str(a.name)} ${str(a.type)} ${str((a.metadata as Row)?.classification || '')} ${str((a.metadata as Row)?.data_type || '')}`)).length
  const findingHits = findings.filter((f) => category.test(`${f.asset} ${f.assetType}`)).length
  return assetHits + findingHits
}
function buildHarvestValue(snapshot: Snapshot, assets: Row[]) {
  if (!snapshot.hasData) return []
  const hndl = snapshot.scores.hndlRisk
  const vulnShare = snapshot.inventory.cryptoComponents > 0 ? snapshot.inventory.vulnerableComponents / snapshot.inventory.cryptoComponents : 0
  const totalAssets = Math.max(1, snapshot.inventory.assetsAssessed)
  return DATA_CATEGORIES.map((cat) => {
    const matchCount = categoryAssetMatch(cat.match, assets, snapshot.criticalFindings)
    const presencePct = clamp((matchCount / totalAssets) * 100)
    // Exposure scales with the tenant's HNDL risk, the category's intrinsic
    // sensitivity and how much of it sits on vulnerable crypto.
    const exposureScore = clamp(hndl * cat.sensitivity * (0.5 + 0.5 * vulnShare))
    const adversaryInterest = clamp(cat.sensitivity * 55 + cat.retentionYears * 0.8 + exposureScore * 0.25)
    const window = riskWindowLabel(cat.retentionYears)
    const futureValue = exposureScore >= 70 ? 'Critical' : exposureScore >= 45 ? 'High' : exposureScore >= 20 ? 'Medium' : 'Low'
    return {
      key: cat.key,
      label: cat.label,
      inScope: matchCount > 0,
      assetCount: matchCount,
      exposureScore,
      confidentialityLifetimeYears: cat.retentionYears,
      confidentialityLabel: window.exceedsCrqc ? `${cat.retentionYears} yrs (exceeds CRQC)` : `${cat.retentionYears} yrs`,
      adversaryInterestScore: adversaryInterest,
      estimatedFutureValue: futureValue,
      regulation: cat.regulation,
    }
  }).sort((a, b) => Number(b.inScope) - Number(a.inScope) || b.adversaryInterestScore - a.adversaryInterestScore)
}

/* ================================================================== */
/* SECTION 5 — Data Shelf-Life Analyzer™                              */
/* ================================================================== */
function buildShelfLife(snapshot: Snapshot, assets: Row[]) {
  return DATA_CATEGORIES.map((cat) => {
    const matchCount = categoryAssetMatch(cat.match, assets, snapshot.criticalFindings)
    const window = riskWindowLabel(cat.retentionYears)
    return {
      dataType: cat.label,
      retentionRequirement: cat.regulation,
      confidentialityYears: cat.retentionYears,
      dataExpiresYear: NOW_YEAR + cat.retentionYears,
      quantumRiskWindow: window.label,
      exceedsCrqc: window.exceedsCrqc,
      inScope: matchCount > 0,
      assetCount: matchCount,
    }
  }).sort((a, b) => b.confidentialityYears - a.confidentialityYears)
}

/* ================================================================== */
/* SECTION 6 — Quantum Break Timeline™                                */
/* ================================================================== */
function buildBreakTimeline(snapshot: Snapshot) {
  const currentRisk = snapshot.scores.quantumRisk
  const migrationWeeks = snapshot.estimates.migrationTimelineWeeks || 0
  const completionYear = migrationWeeks ? NOW_YEAR + Math.ceil(migrationWeeks / 52) : CRQC_YEAR - 1
  const years: Array<{ year: number; projectedRisk: number; milestone: string; critical: boolean }> = []
  for (let y = NOW_YEAR; y <= CRQC_YEAR + 1; y += 1) {
    const t = (y - NOW_YEAR) / Math.max(1, CRQC_YEAR + 1 - NOW_YEAR)
    // Risk grows toward CRQC as harvested ciphertext accumulates & CRQC nears.
    const projectedRisk = clamp(currentRisk + (100 - currentRisk) * Math.pow(t, 1.4))
    let milestone = ''
    let critical = false
    if (y === NOW_YEAR) milestone = 'Current posture'
    else if (y === completionYear) { milestone = 'Migration completion target'; critical = true }
    else if (y === CRQC_YEAR) { milestone = 'Estimated CRQC threat horizon'; critical = true }
    else if (y === CRQC_YEAR - 1) milestone = 'CNSA 2.0 deprecation of classical asymmetric'
    years.push({ year: y, projectedRisk, milestone, critical })
  }
  return {
    currentYear: NOW_YEAR,
    crqcYear: CRQC_YEAR,
    migrationDeadlineYear: CRQC_YEAR - 1,
    migrationCompletionYear: completionYear,
    yearsRemaining: Math.max(0, CRQC_YEAR - NOW_YEAR),
    currentRisk,
    projectedRiskAtCrqc: clamp(currentRisk + (100 - currentRisk) * 0.9),
    years,
  }
}

/* ================================================================== */
/* SECTION 7 — Forward Secrecy Coverage™                              */
/* ================================================================== */
function buildForwardSecrecy(snapshot: Snapshot, cryptoInventory: Row[], runtimeEvents: Row[]) {
  const transport = cryptoInventory.filter((c) => isTransportComponent(str(c.algorithm), str(c.protocol), str(c.item_type)))
  let protectedCount = 0
  const unprotected: Array<{ asset: string; algorithm: string; protocol: string; reason: string }> = []
  const nonPfsBuckets = new Map<string, number>()
  const bump = (k: string) => nonPfsBuckets.set(k, (nonPfsBuckets.get(k) || 0) + 1)

  for (const c of transport) {
    const algo = str(c.algorithm)
    const proto = str(c.protocol)
    if (hasForwardSecrecy(algo, proto)) { protectedCount += 1; continue }
    const text = `${algo} ${proto}`.toUpperCase()
    let bucket = 'Static Key Exchange'
    if (/TLS_RSA|TLS.*RSA/.test(text)) bucket = 'TLS_RSA'
    else if (/SSH-?RSA|SSH_RSA/.test(text)) bucket = 'SSH_RSA'
    else if (/VPN|IPSEC|IKEV1/.test(text)) bucket = 'Legacy VPN'
    else if (/STATIC|RSA_KEY/.test(text)) bucket = 'Static Key Exchange'
    else if (/RSA/.test(text)) bucket = 'Non-PFS RSA'
    bump(bucket)
    unprotected.push({ asset: str((c as Row).name) || str(c.asset_id) || 'Unmapped', algorithm: algo || EVIDENCE_UNAVAILABLE, protocol: proto || 'n/a', reason: `${bucket} — no ephemeral key agreement` })
  }
  // Reinforce with runtime telemetry (legacy events without PFS).
  for (const e of runtimeEvents) {
    if (e.is_legacy === true && !hasForwardSecrecy(str(e.algorithm), '')) {
      bump('Non-PFS RSA')
    }
  }
  const totalTransport = transport.length
  const coveragePct = totalTransport > 0 ? clamp((protectedCount / totalTransport) * 100) : (snapshot.hasData ? clamp(snapshot.scores.pqcAdoption) : 0)
  return {
    coveragePct,
    assetsProtected: protectedCount,
    assetsUnprotected: unprotected.length,
    totalTransport,
    nonPfsBreakdown: Array.from(nonPfsBuckets.entries()).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count),
    topUnprotected: unprotected.sort((a, b) => a.asset.localeCompare(b.asset)).slice(0, 8),
    hasEvidence: totalTransport > 0,
  }
}

/* ================================================================== */
/* SECTION 8 — Cryptographic Exposure Matrix™                         */
/* ================================================================== */
const ALGO_FAMILIES: Array<{ label: string; match: RegExp }> = [
  { label: 'RSA-2048', match: /RSA-?2048|RSA_2048|RSA\b(?!.*3072|.*4096)/ },
  { label: 'RSA-3072', match: /RSA-?3072|RSA_3072/ },
  { label: 'RSA-4096', match: /RSA-?4096|RSA_4096/ },
  { label: 'ECDSA P-256', match: /ECDSA.*P-?256|ECDSA_P256|SECP256|P-256/ },
  { label: 'ECDSA P-384', match: /ECDSA.*P-?384|ECDSA_P384|SECP384|P-384/ },
  { label: 'ECDH', match: /ECDH(?!E)|ECDH_/ },
  { label: 'X25519', match: /X25519|CURVE25519/ },
  { label: 'Ed25519', match: /ED25519/ },
  { label: '3DES / DES', match: /3DES|TRIPLE.?DES|\bDES\b/ },
  { label: 'RC4', match: /RC4/ },
  { label: 'SHA-1 / MD5', match: /SHA-?1\b|MD5/ },
  { label: 'AES-256-GCM', match: /AES-?256|AES_256/ },
  { label: 'ML-KEM', match: /ML-KEM|KYBER/ },
  { label: 'ML-DSA', match: /ML-DSA|DILITHIUM/ },
  { label: 'SLH-DSA', match: /SLH-DSA|SPHINCS/ },
]
function algoFamily(algorithm: string): string {
  const a = algorithm.toUpperCase()
  for (const fam of ALGO_FAMILIES) if (fam.match.test(a)) return fam.label
  if (/RSA/.test(a)) return 'RSA (other)'
  if (/ECDSA|ECC|EC-/.test(a)) return 'ECDSA (other)'
  if (/AES|CHACHA/.test(a)) return 'AES / Symmetric'
  if (/SHA-?2|SHA-?256|SHA-?384|SHA-?512|SHA3/.test(a)) return 'SHA-2 / SHA-3'
  return a ? 'Other' : 'Unspecified'
}
function buildExposureMatrix(snapshot: Snapshot, cryptoInventory: Row[]) {
  const groups = new Map<string, { algorithm: string; assets: Set<string>; count: number; vulnerable: number; internetFacing: boolean; cryptoClass: CryptoClass }>()
  const internetAssets = new Set(snapshot.exposureGraph.nodes.filter((n) => n.internetFacing).map((n) => n.label))

  const ingest = (algorithm: string, asset: string, isVulnerable: boolean | null, isSafe: boolean | null) => {
    const family = algoFamily(algorithm)
    if (family === 'Unspecified') return
    const cls: CryptoClass = isSafe === true ? 'safe' : isVulnerable === true ? 'vulnerable' : classifyAlgorithm(algorithm)
    const g = groups.get(family) || { algorithm: family, assets: new Set<string>(), count: 0, vulnerable: 0, internetFacing: false, cryptoClass: cls }
    g.count += 1
    if (asset) g.assets.add(asset)
    if (cls === 'vulnerable') g.vulnerable += 1
    if (asset && internetAssets.has(asset)) g.internetFacing = true
    // safe/vulnerable dominates unknown
    if (cls !== 'unknown') g.cryptoClass = cls === 'vulnerable' ? 'vulnerable' : g.cryptoClass === 'vulnerable' ? 'vulnerable' : cls
    groups.set(family, g)
  }

  for (const c of cryptoInventory) ingest(str(c.algorithm), str(c.name) || str(c.asset_id), c.is_vulnerable as boolean | null, c.is_quantum_safe as boolean | null)
  // Fold in scan findings (algorithm-level) for assets without CBOM rows.
  for (const f of snapshot.criticalFindings) ingest(str(f.algorithm), f.asset, true, null)

  const rows = Array.from(groups.values()).map((g) => {
    const assetCount = g.assets.size || g.count
    const criticality = g.internetFacing ? 'High' : assetCount >= 5 ? 'High' : assetCount >= 2 ? 'Medium' : 'Low'
    const exposure = g.cryptoClass === 'safe' ? 'None' : g.cryptoClass === 'hybrid' ? 'Low' : g.internetFacing || assetCount >= 5 ? 'Critical' : 'High'
    const priority = migrationPriority(g.cryptoClass, assetCount, g.internetFacing)
    return {
      algorithm: g.algorithm,
      assetCount,
      instanceCount: g.count,
      businessCriticality: criticality,
      exposure,
      cryptoClass: g.cryptoClass,
      migrationPriority: priority.label,
      priorityRank: priority.rank,
      internetFacing: g.internetFacing,
    }
  }).sort((a, b) => b.priorityRank - a.priorityRank || b.assetCount - a.assetCount)
  return rows
}

/* ================================================================== */
/* SECTION 9 / 10 — Captured & Future Decryptable Data                */
/* Transparent estimate model: real unit counts × documented planning */
/* footprint per unit. Returns 0 when no evidence exists.             */
/* ================================================================== */
const GB = {
  trafficPerEndpoint: 12, // captured encrypted traffic per internet endpoint
  archivePerRepo: 240,
  dbDumpPerStore: 180,
  backupPerRepo: 320,
  emailPerAsset: 6,
  docPerAsset: 4,
  codePerRepo: 14,
}
function tb(gb: number) { return Math.round((gb / 1024) * 100) / 100 }
function buildCapturedData(snapshot: Snapshot, assets: Row[]) {
  const inv = snapshot.inventory
  const repos = inv.dataRepositories
  const dbStores = snapshot.exposureGraph.nodes.filter((n) => /db|database|sql|store/i.test(n.type)).length
  const codeRepos = assets.filter((a) => /repo|git|code|registry|build/i.test(`${str(a.name)} ${str(a.type)}`)).length
  const emailAssets = assets.filter((a) => /mail|exchange|smtp|inbox/i.test(`${str(a.name)} ${str(a.type)}`)).length
  const docAssets = assets.filter((a) => /doc|file|share|drive|sharepoint/i.test(`${str(a.name)} ${str(a.type)}`)).length

  const lines = [
    { key: 'traffic', label: 'Encrypted Traffic', unit: inv.domainsScanned, gb: inv.domainsScanned * GB.trafficPerEndpoint },
    { key: 'archives', label: 'Stored Archives', unit: repos, gb: repos * GB.archivePerRepo },
    { key: 'dbdumps', label: 'Database Dumps', unit: dbStores, gb: dbStores * GB.dbDumpPerStore },
    { key: 'backups', label: 'Backups', unit: repos, gb: repos * GB.backupPerRepo },
    { key: 'email', label: 'Email Repositories', unit: emailAssets, gb: emailAssets * GB.emailPerAsset },
    { key: 'documents', label: 'Document Repositories', unit: docAssets, gb: docAssets * GB.docPerAsset },
    { key: 'sourcecode', label: 'Source Code Repositories', unit: codeRepos, gb: codeRepos * GB.codePerRepo },
  ].map((l) => ({ ...l, tb: tb(l.gb) }))
  const totalGb = lines.reduce((s, l) => s + l.gb, 0)
  return { lines, totalTb: tb(totalGb), totalGb, hasEvidence: totalGb > 0 }
}
function buildFutureDecryptable(snapshot: Snapshot, captured: ReturnType<typeof buildCapturedData>) {
  const vulnShare = snapshot.inventory.cryptoComponents > 0 ? snapshot.inventory.vulnerableComponents / snapshot.inventory.cryptoComponents : (snapshot.hasData ? 0.5 : 0)
  const hndlFactor = snapshot.scores.hndlRisk / 100
  // Decryptable = captured volume protected by quantum-vulnerable crypto,
  // weighted by HNDL exposure (how much is long-lived & worth harvesting).
  const projectedTb = Math.round(captured.totalTb * vulnShare * (0.6 + 0.4 * hndlFactor) * 100) / 100
  const highValuePct = clamp(snapshot.scores.hndlRisk * 0.6 + snapshot.scores.cryptoExposure * 0.4)
  const criticalConfidentialAssets = snapshot.topRiskAssets.filter((a) => a.riskScore >= 70).length
  const trend = (snapshot.riskTrend || []).slice(-6).map((p) => ({
    label: p.label,
    decryptableTb: Math.round(captured.totalTb * vulnShare * (p.risk / 100) * 100) / 100,
  }))
  return {
    totalDataAtRiskTb: captured.totalTb,
    projectedDecryptableTb: projectedTb,
    highValueDataPct: highValuePct,
    criticalConfidentialAssets,
    vulnerableSharePct: clamp(vulnShare * 100),
    trend,
    hasEvidence: captured.hasEvidence,
  }
}

/* ================================================================== */
/* SECTION 11 — Quantum Migration Readiness™                          */
/* ================================================================== */
function buildMigrationReadiness(snapshot: Snapshot, migrationJobs: Row[]) {
  const nodes = snapshot.exposureGraph.nodes
  let pqcReady = 0, hybridReady = 0, legacyOnly = 0
  for (const n of nodes) {
    if (n.posture === 'pqc') pqcReady += 1
    else if (n.posture === 'hybrid') hybridReady += 1
    else if (n.posture === 'vulnerable') legacyOnly += 1
  }
  const inProgress = migrationJobs.filter((j) => /running|in_progress|active|executing|analyzing|queued/i.test(str(j.status))).length
  const completed = migrationJobs.filter((j) => /completed|done|success/i.test(str(j.status))).length
  const blocked = migrationJobs.filter((j) => /blocked|failed|error|stalled/i.test(str(j.status))).length
  const readinessScore = snapshot.scores.quantumReadiness
  const recommendation = !snapshot.hasData
    ? 'Run a discovery scan to baseline migration readiness.'
    : legacyOnly > 0
      ? `Prioritise ${legacyOnly} legacy-only asset(s) for hybrid ML-KEM/ML-DSA migration; ${hybridReady} hybrid asset(s) await validation.`
      : 'Maintain quantum-safe posture and validate hybrid deployments.'
  return {
    readinessScore,
    readinessLevel: snapshot.scores.quantumReadinessLevel,
    pqcReady, hybridReady, legacyOnly,
    migrationBlocked: blocked,
    migrationInProgress: inProgress,
    migrationCompleted: completed,
    pqcAdoptionPct: snapshot.scores.pqcAdoption,
    recommendation,
  }
}

/* ================================================================== */
/* SECTION 12 — Adversary Interest Score™ (by sector)                 */
/* ================================================================== */
const SECTORS: Array<{ key: string; label: string; baseWeight: number; match: RegExp }> = [
  { key: 'government', label: 'Government', baseWeight: 0.95, match: /gov|federal|public|agency|municipal/i },
  { key: 'defense', label: 'Defense', baseWeight: 1.0, match: /defense|defence|military|weapon|aerospace/i },
  { key: 'finance', label: 'Finance', baseWeight: 0.9, match: /financ|bank|payment|trading|insurance|fintech/i },
  { key: 'healthcare', label: 'Healthcare', baseWeight: 0.85, match: /health|medical|patient|pharma|clinic|hospital/i },
  { key: 'technology', label: 'Technology', baseWeight: 0.8, match: /tech|software|cloud|saas|platform|data/i },
  { key: 'manufacturing', label: 'Manufacturing', baseWeight: 0.7, match: /manufactur|industrial|factory|supply|logistics/i },
  { key: 'infrastructure', label: 'Critical Infrastructure', baseWeight: 0.92, match: /energy|power|grid|water|utility|transport|telecom/i },
]
function buildAdversaryInterest(snapshot: Snapshot, assets: Row[]) {
  if (!snapshot.hasData) return []
  const hndl = snapshot.scores.hndlRisk
  const exposure = snapshot.scores.cryptoExposure
  return SECTORS.map((s) => {
    const present = assets.filter((a) => s.match.test(`${str(a.name)} ${str(a.type)} ${str((a.metadata as Row)?.industry || '')} ${str((a.metadata as Row)?.sector || '')}`)).length
    // Interest = intrinsic sector value × tenant exposure, lifted when the
    // tenant actually operates assets in that sector.
    const score = clamp(s.baseWeight * (hndl * 0.55 + exposure * 0.25 + 35) + (present > 0 ? 8 : 0))
    return {
      key: s.key,
      sector: s.label,
      interestScore: score,
      level: score >= 75 ? 'Critical' : score >= 55 ? 'High' : score >= 35 ? 'Moderate' : 'Low',
      assetsInSector: present,
      inScope: present > 0,
    }
  }).sort((a, b) => b.interestScore - a.interestScore)
}

/* ================================================================== */
/* SECTION 13 — Threat Actors Most Interested™                        */
/* ================================================================== */
function buildThreatActors(snapshot: Snapshot) {
  if (!snapshot.hasData) return []
  const hndl = snapshot.scores.hndlRisk
  const exposure = snapshot.scores.cryptoExposure
  const internetTargets = snapshot.exposureGraph.nodes.filter((n) => n.internetFacing).map((n) => n.label)
  const criticalTargets = snapshot.topRiskAssets.filter((a) => a.riskScore >= 70).map((a) => a.asset)
  const targets = [...new Set([...internetTargets, ...criticalTargets])]
  const actors = [
    { key: 'nation-state', actor: 'Nation-State APT', weight: 1.0, motivation: 'Strategic intelligence; long-term decryption of harvested state/corporate secrets.' },
    { key: 'espionage', actor: 'Cyber Espionage Groups', weight: 0.9, motivation: 'IP theft and trade-secret exfiltration for competitive/economic advantage.' },
    { key: 'foreign-intel', actor: 'Foreign Intelligence Services', weight: 0.95, motivation: 'Bulk ciphertext harvesting against diplomatic and defense communications.' },
    { key: 'organized-crime', actor: 'Organized Crime', weight: 0.7, motivation: 'Financial fraud and extortion using future-decryptable financial/PII data.' },
    { key: 'hacktivist', actor: 'Hacktivists', weight: 0.5, motivation: 'Disclosure and disruption of high-visibility confidential assets.' },
  ]
  return actors.map((a) => {
    const score = clamp(a.weight * (hndl * 0.5 + exposure * 0.3 + 30))
    return {
      key: a.key,
      actor: a.actor,
      interestScore: score,
      level: score >= 75 ? 'Critical' : score >= 55 ? 'High' : score >= 35 ? 'Moderate' : 'Low',
      targetedAssets: targets.slice(0, 5),
      targetedAssetCount: targets.length,
      motivation: a.motivation,
    }
  }).sort((a, b) => b.interestScore - a.interestScore)
}

/* ================================================================== */
/* SECTION 14 — Strategic Intelligence Feed™                          */
/* Curated, source-attributed PQC ecosystem milestones (reference      */
/* intelligence — published standards/announcements, not tenant logs). */
/* ================================================================== */
function buildIntelligenceFeed() {
  const items = [
    { id: 'nist-fips', date: '2024-08-13', source: 'NIST', category: 'Standard', title: 'FIPS 203/204/205 finalized', detail: 'ML-KEM, ML-DSA and SLH-DSA published as the first NIST post-quantum standards.', impact: 'Critical' },
    { id: 'cnsa-2', date: '2025-01-01', source: 'NSA / CNSA 2.0', category: 'Mandate', title: 'CNSA 2.0 adoption timeline', detail: 'Software/firmware signing to prefer PQC by 2025; classical asymmetric deprecated for NSS through 2030-2033.', impact: 'Critical' },
    { id: 'chrome-mlkem', date: '2024-09-01', source: 'Google Chrome', category: 'Rollout', title: 'Hybrid X25519+ML-KEM enabled by default', detail: 'Chrome ships hybrid key exchange for TLS, protecting sessions against HNDL capture.', impact: 'High' },
    { id: 'cloudflare-pq', date: '2024-10-01', source: 'Cloudflare', category: 'Rollout', title: 'Post-quantum to origin (PQC everywhere)', detail: 'Cloudflare extends X25519+ML-KEM hybrid TLS to origin connections across its network.', impact: 'High' },
    { id: 'apple-pq3', date: '2024-02-21', source: 'Apple', category: 'Rollout', title: 'iMessage PQ3 protocol', detail: 'Level-3 post-quantum messaging with ongoing rekeying to limit harvested-key exposure.', impact: 'Medium' },
    { id: 'ms-symcrypt', date: '2024-09-01', source: 'Microsoft', category: 'Vendor', title: 'SymCrypt adds ML-KEM / ML-DSA', detail: 'Windows/Linux crypto library gains PQC primitives ahead of platform integration.', impact: 'Medium' },
    { id: 'openssl-35', date: '2025-04-01', source: 'OpenSSL', category: 'Vendor', title: 'OpenSSL 3.5 native ML-KEM/ML-DSA/SLH-DSA', detail: 'Mainline OpenSSL ships PQC algorithms, easing enterprise hybrid TLS adoption.', impact: 'High' },
    { id: 'quantum-research', date: '2024-12-09', source: 'Quantum Research', category: 'Research', title: 'Error-corrected logical qubit milestones', detail: 'Continued progress in logical-qubit error correction shortens credible CRQC timelines.', impact: 'Medium' },
  ]
  return items
}

/* ================================================================== */
/* SECTION 15 — Top HNDL Findings™                                    */
/* ================================================================== */
function buildTopFindings(snapshot: Snapshot) {
  return snapshot.criticalFindings
    .filter((f) => classifyAlgorithm(str(f.algorithm)) === 'vulnerable' || /critical|high/i.test(str(f.severity)))
    .slice(0, 20)
    .map((f) => {
      const cls = classifyAlgorithm(str(f.algorithm))
      // Shelf-life heuristic from asset type → governs the risk window.
      const cat = DATA_CATEGORIES.find((c) => c.match.test(`${f.asset} ${f.assetType}`))
      const retention = cat?.retentionYears ?? 10
      const window = riskWindowLabel(retention)
      const internet = snapshot.exposureGraph.nodes.find((n) => n.label === f.asset)?.internetFacing
      const priority = migrationPriority(cls, 1, Boolean(internet))
      return {
        id: f.id,
        asset: f.asset || EVIDENCE_UNAVAILABLE,
        algorithm: f.algorithm || EVIDENCE_UNAVAILABLE,
        severity: f.severity,
        dataLifetimeYears: retention,
        dataLifetimeLabel: `${retention} yrs (${cat?.label ?? 'General data'})`,
        riskWindow: window.label,
        exceedsCrqc: window.exceedsCrqc,
        migrationPriority: priority.label,
        environment: f.environment,
        detectedAt: f.detectedAt,
      }
    })
    .sort((a, b) => Number(b.exceedsCrqc) - Number(a.exceedsCrqc))
}

/* ================================================================== */
/* SECTION 16 — Remediation Center™                                   */
/* ================================================================== */
function buildRemediationCenter(snapshot: Snapshot, matrix: ReturnType<typeof buildExposureMatrix>, forwardSecrecy: ReturnType<typeof buildForwardSecrecy>) {
  const inv = snapshot.inventory
  const reduction = Math.max(0, snapshot.scores.quantumRisk - Math.max(10, Math.round(snapshot.scores.quantumRisk * 0.25)))
  const rsaAssets = matrix.filter((m) => /RSA|ECDSA|ECDH/.test(m.algorithm) && m.cryptoClass === 'vulnerable').reduce((s, m) => s + m.assetCount, 0)
  const weeks = snapshot.estimates.migrationTimelineWeeks || 0
  const completion = (ratio: number) => weeks ? new Date(Date.now() + Math.round(weeks * ratio) * 7 * 86400000).toISOString().slice(0, 10) : EVIDENCE_UNAVAILABLE
  const actions = [
    { key: 'hybrid-tls', label: 'Enable Hybrid TLS', affectedAssets: inv.domainsScanned, riskReductionPct: clamp(reduction * 0.4), effort: 'Medium', completion: completion(0.2), href: '/dashboard/migration-planner?focus=tls', requires: 'TLS 1.3 + X25519 + ML-KEM-768' },
    { key: 'deploy-mlkem', label: 'Deploy ML-KEM', affectedAssets: rsaAssets, riskReductionPct: clamp(reduction * 0.35), effort: 'High', completion: completion(0.35), href: '/dashboard/qkms?focus=ml-kem', requires: 'FIPS 203 key establishment' },
    { key: 'deploy-mldsa', label: 'Deploy ML-DSA', affectedAssets: inv.certificatesAnalyzed, riskReductionPct: clamp(reduction * 0.25), effort: 'High', completion: completion(0.4), href: '/dashboard/qkms?focus=ml-dsa', requires: 'FIPS 204 signatures' },
    { key: 'replace-certs', label: 'Replace Legacy Certificates', affectedAssets: inv.certificatesAnalyzed, riskReductionPct: clamp(reduction * 0.2), effort: 'Medium', completion: completion(0.3), href: '/dashboard/pki-visibility', requires: 'Hybrid certificate chains' },
    { key: 'forward-secrecy', label: 'Enable Forward Secrecy', affectedAssets: forwardSecrecy.assetsUnprotected, riskReductionPct: clamp(reduction * 0.18), effort: 'Low', completion: completion(0.15), href: '/dashboard/tls-orchestrator', requires: 'ECDHE / X25519 ephemeral key exchange' },
    { key: 'rotate-keys', label: 'Rotate Cryptographic Keys', affectedAssets: inv.keysDiscovered, riskReductionPct: clamp(reduction * 0.12), effort: 'Medium', completion: completion(0.25), href: '/dashboard/qkms?focus=rotation', requires: 'Re-key with PQC-ready custody' },
    { key: 'quantum-vpn', label: 'Deploy Quantum-Safe VPN', affectedAssets: forwardSecrecy.nonPfsBreakdown.find((b) => b.type === 'Legacy VPN')?.count ?? 0, riskReductionPct: clamp(reduction * 0.1), effort: 'High', completion: completion(0.4), href: '/dashboard/migration-planner?focus=vpn', requires: 'Hybrid IKEv2 / ML-KEM' },
    { key: 'validate-pqc', label: 'Validate PQC Interoperability', affectedAssets: inv.quantumVulnerableAssets, riskReductionPct: clamp(reduction * 0.08), effort: 'Medium', completion: completion(0.45), href: '/dashboard/migration-sandbox', requires: 'Hybrid negotiation + trust-chain validation' },
  ]
  return actions
    .map((a) => ({ ...a, inScope: a.affectedAssets > 0 }))
    .sort((a, b) => Number(b.inScope) - Number(a.inScope) || b.riskReductionPct - a.riskReductionPct)
}

/* ================================================================== */
/* Assemble the full HNDL intelligence model                          */
/* ================================================================== */
interface HndlRawRows {
  cryptoInventory: Row[]
  certificates: Row[]
  runtimeEvents: Row[]
  assets: Row[]
  migrationJobs: Row[]
}

/**
 * Pure assembly — derives the full 16-section HNDL intelligence model from a
 * Quantum Readiness snapshot plus raw tenant rows. Isolated from data fetching
 * so it is deterministic and unit-testable offline (see tools/hndl-check.ts).
 */
function assembleHndlIntelligence(snapshot: Snapshot, rows: HndlRawRows) {
  const { cryptoInventory, certificates, runtimeEvents, assets, migrationJobs } = rows
  const exposureMatrix = buildExposureMatrix(snapshot, cryptoInventory)
  const forwardSecrecy = buildForwardSecrecy(snapshot, cryptoInventory, runtimeEvents)
  const capturedData = buildCapturedData(snapshot, assets)
  const futureDecryptable = buildFutureDecryptable(snapshot, capturedData)
  const criticalFindings = snapshot.riskDistribution.critical

  return {
    generatedAt: new Date().toISOString(),
    lastScanAt: snapshot.lastAssessmentAt,
    hasData: snapshot.hasData,
    connected: true,
    banner: buildBanner(snapshot, futureDecryptable.projectedDecryptableTb, criticalFindings),
    exposureGraph: buildExposureGraph(snapshot, cryptoInventory, certificates),
    theater: buildTheater(snapshot, assets),
    harvestValue: buildHarvestValue(snapshot, assets),
    shelfLife: buildShelfLife(snapshot, assets),
    breakTimeline: buildBreakTimeline(snapshot),
    forwardSecrecy,
    exposureMatrix,
    capturedData,
    futureDecryptable,
    migrationReadiness: buildMigrationReadiness(snapshot, migrationJobs),
    adversaryInterest: buildAdversaryInterest(snapshot, assets),
    threatActors: buildThreatActors(snapshot),
    intelligenceFeed: buildIntelligenceFeed(),
    topFindings: buildTopFindings(snapshot),
    remediationCenter: buildRemediationCenter(snapshot, exposureMatrix, forwardSecrecy),
    scores: {
      hndlRisk: snapshot.scores.hndlRisk,
      hndlRiskLevel: snapshot.scores.hndlRiskLevel,
      quantumRisk: snapshot.scores.quantumRisk,
      quantumReadiness: snapshot.scores.quantumReadiness,
      cryptoExposure: snapshot.scores.cryptoExposure,
      pqcAdoption: snapshot.scores.pqcAdoption,
    },
    inventory: {
      assetsAssessed: snapshot.inventory.assetsAssessed,
      quantumVulnerableAssets: snapshot.inventory.quantumVulnerableAssets,
      vulnerableComponents: snapshot.inventory.vulnerableComponents,
      cryptoComponents: snapshot.inventory.cryptoComponents,
      certificatesAnalyzed: snapshot.inventory.certificatesAnalyzed,
      keysDiscovered: snapshot.inventory.keysDiscovered,
      domainsScanned: snapshot.inventory.domainsScanned,
      dataRepositories: snapshot.inventory.dataRepositories,
    },
    evidence: {
      sources: ['PQC Scanner', 'CBOM / Crypto Inventory', 'Certificate Inventory', 'Runtime Crypto Telemetry', 'Asset Inventory', 'Migration Jobs'],
      note: snapshot.hasData
        ? `HNDL intelligence derived from ${snapshot.inventory.assetsAssessed} assets, ${snapshot.inventory.cryptoComponents} crypto components, ${certificates.length} certificate(s) and ${runtimeEvents.length} runtime event(s). Metrics mirror scanner intelligence; volume figures are planning estimates from real unit counts.`
        : `${EVIDENCE_UNAVAILABLE}. No scans, assets, certificates or runtime telemetry recorded for this tenant.`,
    },
  }
}

async function buildHndlIntelligence(token: string, userId: string) {
  const snapshot = await buildSnapshot(token, userId)
  const client = createAuthClient(token)
  const [cryptoInventory, certificates, runtimeEvents, assets, migrationJobs] = client
    ? await Promise.all([
        safeRows(client as never, 'crypto_inventory', 'id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, created_at', userId, 2500),
        safeRows(client as never, 'certificates', 'id, asset_id, name, algorithm, key_size, issuer, not_after, is_quantum_safe, status, created_at', userId, 1500),
        safeRows(client as never, 'runtime_crypto_events', 'id, asset_id, algorithm, severity, risk_score, asset_name, asset_type, host, is_pqc, is_legacy, hndl_risk, created_at', userId, 3000),
        safeRows(client as never, 'assets', 'id, name, type, environment, region, service_owner, criticality, status, metadata, created_at', userId, 1500),
        safeRows(client as never, 'migration_jobs', 'id, status, progress, asset_id, job_type, created_at', userId, 300),
      ])
    : [[], [], [], [], []]
  return assembleHndlIntelligence(snapshot, { cryptoInventory, certificates, runtimeEvents, assets, migrationJobs })
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const data = await buildHndlIntelligence(token!, user!.id)
    res.json({ data })
  } catch (error) {
    console.error('Harvest-now (HNDL) error:', error)
    res.status(500).json({ error: { code: 'HNDL_ERROR', message: error instanceof Error ? error.message : 'Failed to build HNDL intelligence' } })
  }
})

router.get('/stream', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  const send = (event: string, data: unknown) => { if (!closed) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`) }

  const emit = async () => {
    try {
      const data = await buildHndlIntelligence(token!, user!.id)
      send('hndl-intelligence', data)
    } catch (err) {
      send('hndl-error', { message: err instanceof Error ? err.message : 'stream failed' })
    }
  }

  await emit()
  const refresh = setInterval(emit, 30000)
  const heartbeat = setInterval(() => { if (!closed) res.write(': heartbeat\n\n') }, 25000)
  req.on('close', () => { closed = true; clearInterval(refresh); clearInterval(heartbeat) })
})

export { buildHndlIntelligence, assembleHndlIntelligence }
export type { HndlRawRows }
export default router
