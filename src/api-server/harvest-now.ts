import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'
import { namesCryptography } from '@/lib/scanner/finding-identity'
import { isInternetFacing, levelFromRisk } from '@/lib/migration/asset-intelligence'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { payloadFingerprint, streamLiveSnapshot } from './live-snapshot-stream'

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

/**
 * Does this inventory row record MEASURED cryptography, or a policy finding?
 *
 * The scanner labels each record with its class ("Cipher Suite: …",
 * "Certificate Revocation: …"), so `namesCryptography` can tell them apart —
 * that is what keeps "Information Disclosure" and "No OCSP Stapling" out of the
 * algorithm panels. But a row written WITHOUT a class-prefixed name is not
 * thereby a policy finding: absence of a label is not evidence. Fall back to
 * reading the algorithm itself, so other writers (and fixtures) are not
 * silently erased.
 */
function isMeasuredCryptography(row: Row): boolean {
  const name = str(row.name)
  // The class label only exists in the "<Class>: <value>" form. A name without
  // one ("portal.acme.com", or a bare algorithm) carries no verdict either way,
  // so it must not be read as a policy finding — judge it on its algorithm.
  if (!name.includes(':')) return true
  return namesCryptography(name)
}

/** Human label for an asset id, so panels name the ASSET and not the component. */
function assetLabel(snapshot: Snapshot, assetId: string): string {
  if (!assetId) return ''
  const node = snapshot.exposureGraph.nodes.find((n) => str((n as unknown as Row).id) === assetId)
  if (node?.label) return node.label
  const asset = snapshot.topRiskAssets.find((a) => str((a as unknown as Row).id) === assetId)
  return asset?.asset || ''
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
  // The canonical band of the HNDL score itself (RISK_BANDS). It used to be a
  // private ladder that also escalated to "Critical" on ANY critical finding —
  // findings unrelated to harvest exposure — so nearly every estate read
  // "Critical Threat" whatever its HNDL score said.
  const threatLevel = !snapshot.hasData ? 'Unknown' : levelFromRisk(hndl)
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
    { id: 'internet', label: 'Internet Edge', kind: 'edge', total: inv.domainsScanned, vulnerable: 0, cryptoClass: 'unknown' as CryptoClass, detail: `${inv.domainsScanned} scanned host(s) / domain(s)` },
    { id: 'tls', label: 'TLS Endpoints', kind: 'protocol', total: tlsItems.length || inv.domainsScanned, vulnerable: tlsVuln, cryptoClass: tierClass(tlsVuln, tlsItems.length || inv.domainsScanned), detail: `${tlsVuln} non-quantum-safe handshake(s)` },
    { id: 'certs', label: 'Certificates', kind: 'pki', total: inv.certificatesAnalyzed, vulnerable: certVuln, cryptoClass: tierClass(certVuln, inv.certificatesAnalyzed), detail: `${certVuln} classical certificate signature(s)` },
    { id: 'keys', label: 'Cryptographic Keys', kind: 'key', total: inv.keysDiscovered || keyItems.length, vulnerable: keyVuln, cryptoClass: tierClass(keyVuln, inv.keysDiscovered || keyItems.length), detail: `${keyVuln} quantum-vulnerable key(s)` },
    { id: 'databases', label: 'Databases', kind: 'store', total: snapshot.exposureGraph.nodes.filter((n) => /db|database|sql|store/i.test(n.type)).length, vulnerable: 0, cryptoClass: 'unknown' as CryptoClass, detail: 'Encrypted-at-rest data stores' },
    // One tier for the vault: "Backups" and "Long-Term Storage" used to be two
    // tiers printing the SAME vault-file count, which read as twice the data.
    { id: 'vault', label: 'Encrypted Data Vault', kind: 'store', total: inv.dataRepositories, vulnerable: 0, cryptoClass: 'unknown' as CryptoClass, detail: `${inv.dataRepositories} file(s) held in the Quantum Vault` },
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
/* SECTION 3 — Global Quantum Exposure Theater™ (3D map model)        */
/*                                                                    */
/* Every plotted element is evidence-based:                           */
/*  • sites       — assets whose region/cloud-region metadata maps to */
/*                  a known geographic location (never guessed);      */
/*  • anchors     — certificate-authority trust origins parsed from   */
/*                  REAL issuer DNs (O= / C=) in certificate chains;  */
/*  • assetLinks  — real asset_relationships edges between sites;     */
/*  • trustLinks  — asset → issuing-CA connections from cert chains;  */
/*  • unlocated   — assets with NO location telemetry are listed      */
/*                  honestly instead of being pinned to a fake region.*/
/* ================================================================== */

const REGION_GEO: Array<{ key: string; label: string; lat: number; lon: number; match: RegExp }> = [
  { key: 'au', label: 'Australia (Sydney)', lat: -33.9, lon: 151.2, match: /ap-?southeast-?2|australia|sydney|melbourne|oceania|\bau\b/i },
  { key: 'us-east', label: 'US East (N. Virginia)', lat: 38.9, lon: -77.4, match: /us-?east|eastus|virginia|\bus\b$|\bna\b$/i },
  { key: 'us-west', label: 'US West (Oregon)', lat: 44.1, lon: -120.5, match: /us-?west|westus|oregon|california/i },
  { key: 'us-central', label: 'US Central (Iowa)', lat: 41.9, lon: -93.6, match: /us-?central|centralus|iowa|chicago|texas/i },
  { key: 'ca-central', label: 'Canada (Montreal)', lat: 45.5, lon: -73.6, match: /ca-?central|canada|montreal|toronto/i },
  { key: 'sa-east', label: 'South America (Sao Paulo)', lat: -23.5, lon: -46.6, match: /sa-?east|brazil|sao ?paulo|south ?america|\bsa\b$/i },
  { key: 'eu-west', label: 'EU West (Ireland)', lat: 53.3, lon: -6.3, match: /eu-?west|ireland|dublin/i },
  { key: 'uk', label: 'UK (London)', lat: 51.5, lon: -0.1, match: /\buk\b|united ?kingdom|london|britain/i },
  { key: 'eu-north', label: 'EU North (Stockholm)', lat: 59.3, lon: 18.1, match: /eu-?north|stockholm|sweden|norway|finland/i },
  { key: 'eu-central', label: 'EU Central (Frankfurt)', lat: 50.1, lon: 8.7, match: /eu-?central|frankfurt|germany|westeurope|europe|\beu\b$/i },
  { key: 'me-south', label: 'Middle East (Bahrain)', lat: 26.2, lon: 50.6, match: /me-?south|middle ?east|bahrain|uae|dubai|\bme\b$/i },
  { key: 'af-south', label: 'Africa (Cape Town)', lat: -33.9, lon: 18.4, match: /af-?south|africa|cape ?town|johannesburg|\baf\b$/i },
  { key: 'ap-south', label: 'Asia Pacific (Mumbai)', lat: 19.1, lon: 72.9, match: /ap-?south(?!east)|india|mumbai/i },
  { key: 'ap-northeast', label: 'Asia Pacific (Tokyo)', lat: 35.7, lon: 139.7, match: /ap-?northeast|tokyo|japan|osaka|seoul|korea/i },
  { key: 'ap-east', label: 'Asia Pacific (Hong Kong)', lat: 22.3, lon: 114.2, match: /ap-?east|hong ?kong|shanghai|china/i },
  { key: 'ap-southeast', label: 'Asia Pacific (Singapore)', lat: 1.35, lon: 103.8, match: /ap-?southeast|singapore|apac|asia/i },
]

/** ISO country → centroid, for certificate-authority trust anchors. */
const COUNTRY_GEO: Record<string, { label: string; lat: number; lon: number }> = {
  US: { label: 'United States', lat: 39, lon: -98 }, CA: { label: 'Canada', lat: 56, lon: -106 },
  GB: { label: 'United Kingdom', lat: 54, lon: -2 }, IE: { label: 'Ireland', lat: 53.2, lon: -7.7 },
  BE: { label: 'Belgium', lat: 50.6, lon: 4.5 }, NL: { label: 'Netherlands', lat: 52.2, lon: 5.5 },
  DE: { label: 'Germany', lat: 51, lon: 10 }, FR: { label: 'France', lat: 46.5, lon: 2.4 },
  CH: { label: 'Switzerland', lat: 46.8, lon: 8.2 }, AT: { label: 'Austria', lat: 47.5, lon: 14 },
  SE: { label: 'Sweden', lat: 62, lon: 15 }, PL: { label: 'Poland', lat: 52, lon: 19 },
  ES: { label: 'Spain', lat: 40.2, lon: -3.9 }, IT: { label: 'Italy', lat: 42.5, lon: 12.5 },
  IL: { label: 'Israel', lat: 31.3, lon: 35 }, AE: { label: 'UAE', lat: 24.2, lon: 54 },
  IN: { label: 'India', lat: 21, lon: 78 }, SG: { label: 'Singapore', lat: 1.35, lon: 103.8 },
  JP: { label: 'Japan', lat: 36.2, lon: 138 }, KR: { label: 'South Korea', lat: 36.5, lon: 127.8 },
  CN: { label: 'China', lat: 35, lon: 104 }, AU: { label: 'Australia', lat: -25.3, lon: 134 },
  BR: { label: 'Brazil', lat: -10.8, lon: -52.9 }, ZA: { label: 'South Africa', lat: -29, lon: 24 },
}

/** Map crop used by the theater map (matches world-land-grid.ts). */
const MAP_LAT_MAX = 78
const MAP_LAT_MIN = -56
function mapXY(lat: number, lon: number): { x: number; y: number } {
  return {
    x: Math.round(((lon + 180) / 360) * 1000) / 10,
    y: Math.round(((MAP_LAT_MAX - lat) / (MAP_LAT_MAX - MAP_LAT_MIN)) * 1000) / 10,
  }
}

/** Resolve a raw region/environment string to a geo site — null when unknown. */
function resolveRegion(raw: string): (typeof REGION_GEO)[number] | null {
  const r = raw.trim()
  if (!r) return null
  for (const geo of REGION_GEO) if (geo.match.test(r)) return geo
  return null
}

interface IssuerInfo { org: string; country: string; algorithms: string[] }

/** Parse issuer organisations (+ country + signing algorithms) from an asset's
 *  scanned certificate chain and from certificate-table issuer strings. */
function issuersForAsset(asset: Row, certificates: Row[]): IssuerInfo[] {
  const found = new Map<string, IssuerInfo>()
  const add = (dn: string, algorithm: string) => {
    if (!dn) return
    const org = (/O=([^,]+)/.exec(dn)?.[1] || /CN=([^,]+)/.exec(dn)?.[1] || '').trim()
    if (!org) return
    const country = (/\bC=([A-Z]{2})\b/.exec(dn)?.[1] || '').trim()
    const entry = found.get(org) || { org, country, algorithms: [] }
    if (!entry.country && country) entry.country = country
    if (algorithm && !entry.algorithms.includes(algorithm)) entry.algorithms.push(algorithm)
    found.set(org, entry)
  }
  const chain = ((asset.metadata as Row)?.certificate as Row | undefined)?.chain
  if (Array.isArray(chain)) {
    for (const link of chain as Row[]) add(str(link.issuer), str(link.publicKeyAlgorithm) || str(link.signatureAlgorithm))
  }
  const assetId = str(asset.id)
  for (const c of certificates) {
    if (assetId && str(c.asset_id) === assetId) add(str(c.issuer), str(c.algorithm))
  }
  return Array.from(found.values())
}

function buildTheater(snapshot: Snapshot, assets: Row[], certificates: Row[]) {
  const nodeByLabel = new Map(snapshot.exposureGraph.nodes.map((n) => [n.label, n]))
  const nodeById = new Map(snapshot.exposureGraph.nodes.map((n) => [n.id, n]))

  interface SiteAgg {
    key: string; label: string; lat: number; lon: number
    region: string; assets: number; vulnerable: number; riskTotal: number
    cloud: Set<string>; internetFacing: number
    topAssets: Array<{ name: string; posture: string; riskScore: number; internetFacing: boolean }>
  }
  const byRegion = new Map<string, SiteAgg>()
  const unlocated: Array<{ name: string; posture: string; riskScore: number; internetFacing: boolean; type: string }> = []
  const siteOfAsset = new Map<string, string>() // asset id AND name → site key
  const assetKey = (a: Row) => str(a.id) || str(a.name)

  for (const a of assets) {
    const node = nodeByLabel.get(str(a.name))
    const posture = node?.posture || 'unknown'
    const risk = node ? node.riskScore : num(a.criticality)
    const internetFacing = node?.internetFacing === true
    const rawRegion = str(a.region) || str((a.metadata as Row)?.region) || str((a.metadata as Row)?.cloud_region) || str(a.environment)
    const geo = resolveRegion(rawRegion)
    if (!geo) {
      // No location telemetry — never pin to a fabricated region.
      unlocated.push({ name: str(a.name) || 'Unnamed asset', posture, riskScore: Math.round(risk), internetFacing, type: str(a.type) })
      continue
    }
    siteOfAsset.set(assetKey(a), geo.key)
    if (str(a.name)) siteOfAsset.set(str(a.name), geo.key)
    const entry = byRegion.get(geo.key) || {
      key: geo.key, label: geo.label, lat: geo.lat, lon: geo.lon,
      region: rawRegion || geo.label, assets: 0, vulnerable: 0, riskTotal: 0,
      cloud: new Set<string>(), internetFacing: 0, topAssets: [],
    }
    entry.assets += 1
    entry.riskTotal += risk
    if (posture === 'vulnerable' || risk >= 60) entry.vulnerable += 1
    if (internetFacing) entry.internetFacing += 1
    const cloud = str((a.metadata as Row)?.cloud_provider || (a.metadata as Row)?.provider)
    if (cloud) entry.cloud.add(cloud)
    entry.topAssets.push({ name: str(a.name) || 'Unnamed asset', posture, riskScore: Math.round(risk), internetFacing })
    byRegion.set(geo.key, entry)
  }

  const severityOf = (avgRisk: number, vulnerable: number) =>
    avgRisk >= 70 || vulnerable >= 3 ? 'Critical' : avgRisk >= 45 || vulnerable > 0 ? 'High' : avgRisk >= 25 ? 'Medium' : 'Low'

  const sites = Array.from(byRegion.values()).map((e) => {
    const avgRisk = e.assets ? Math.round(e.riskTotal / e.assets) : 0
    const { x, y } = mapXY(e.lat, e.lon)
    return {
      key: e.key, region: e.region, label: e.label, lat: e.lat, lon: e.lon, x, y,
      assets: e.assets, vulnerableAssets: e.vulnerable, avgRisk,
      internetFacing: e.internetFacing,
      cloudProviders: Array.from(e.cloud),
      topAssets: e.topAssets.sort((a, b) => b.riskScore - a.riskScore).slice(0, 5),
      severity: severityOf(avgRisk, e.vulnerable),
    }
  }).sort((a, b) => b.vulnerableAssets - a.vulnerableAssets || b.avgRisk - a.avgRisk)

  // ---- Certificate-authority trust anchors (real issuer DNs) ----------
  interface AnchorAgg { id: string; name: string; country: string; lat: number | null; lon: number | null; assets: Set<string>; algorithms: Set<string> }
  const anchors = new Map<string, AnchorAgg>()
  const trustLinks: Array<{ asset: string; siteKey: string | null; anchorId: string; vulnerable: boolean }> = []
  for (const a of assets) {
    const assetName = str(a.name) || 'Unnamed asset'
    for (const issuer of issuersForAsset(a, certificates)) {
      const id = issuer.org.toLowerCase().replace(/[^a-z0-9]+/g, '-')
      const geo = issuer.country ? COUNTRY_GEO[issuer.country] : undefined
      const anchor = anchors.get(id) || { id, name: issuer.org, country: issuer.country, lat: geo?.lat ?? null, lon: geo?.lon ?? null, assets: new Set<string>(), algorithms: new Set<string>() }
      anchor.assets.add(assetName)
      for (const alg of issuer.algorithms) anchor.algorithms.add(alg)
      anchors.set(id, anchor)
      const vulnerable = issuer.algorithms.some((alg) => classifyAlgorithm(alg) === 'vulnerable')
      if (!trustLinks.some((t) => t.asset === assetName && t.anchorId === id)) {
        trustLinks.push({ asset: assetName, siteKey: siteOfAsset.get(assetKey(a)) || null, anchorId: id, vulnerable })
      }
    }
  }
  const anchorRows = Array.from(anchors.values()).map((an) => ({
    id: an.id,
    name: an.name,
    country: an.country || null,
    countryLabel: an.country ? COUNTRY_GEO[an.country]?.label ?? an.country : null,
    lat: an.lat, lon: an.lon,
    ...(an.lat != null && an.lon != null ? mapXY(an.lat, an.lon) : { x: null, y: null }),
    certificates: an.assets.size,
    assets: Array.from(an.assets).slice(0, 6),
    quantumSafe: Array.from(an.algorithms).length > 0 && Array.from(an.algorithms).every((alg) => classifyAlgorithm(alg) === 'safe'),
    algorithms: Array.from(an.algorithms).slice(0, 4),
  })).sort((a, b) => b.certificates - a.certificates).slice(0, 12)
  const anchorIds = new Set(anchorRows.map((an) => an.id))

  // ---- Site-to-site links from REAL asset relationships ---------------
  const linkAgg = new Map<string, { from: string; to: string; kind: string; count: number; vulnerable: boolean }>()
  const siteForNode = (nodeId: string) => siteOfAsset.get(nodeId) ?? (nodeById.get(nodeId) ? siteOfAsset.get(nodeById.get(nodeId)!.label) : undefined)
  for (const edge of snapshot.exposureGraph.edges) {
    const fromNode = nodeById.get(edge.source)
    const toNode = nodeById.get(edge.target)
    if (!fromNode || !toNode) continue
    const fromSite = siteForNode(edge.source)
    const toSite = siteForNode(edge.target)
    if (!fromSite || !toSite || fromSite === toSite) continue
    const key = [fromSite, toSite].sort().join('→') + edge.type
    const entry = linkAgg.get(key) || { from: fromSite, to: toSite, kind: edge.type || 'depends-on', count: 0, vulnerable: false }
    entry.count += 1
    if (fromNode.posture === 'vulnerable' || toNode.posture === 'vulnerable') entry.vulnerable = true
    linkAgg.set(key, entry)
  }

  const regions = sites.map(({ key, region, x, y, assets: a, vulnerableAssets, avgRisk, cloudProviders, severity, label, lat, lon, topAssets }) => ({
    key, region, label, lat, lon, x, y, assets: a, vulnerableAssets, avgRisk, cloudProviders, severity, topAssets,
  }))

  return {
    regions,
    totalRegions: regions.length,
    highValueTargets: regions.filter((r) => r.severity === 'Critical' || r.severity === 'High').length,
    summary: regions.length || unlocated.length
      ? `${regions.length} located region(s); ${unlocated.length} asset(s) without location telemetry; ${anchorRows.length} certificate trust anchor(s).`
      : EVIDENCE_UNAVAILABLE,
    map: {
      sites,
      anchors: anchorRows,
      assetLinks: Array.from(linkAgg.values()),
      trustLinks: trustLinks.filter((t) => anchorIds.has(t.anchorId)).slice(0, 40),
      unlocated: unlocated.sort((a, b) => b.riskScore - a.riskScore).slice(0, 12),
      unlocatedTotal: unlocated.length,
      internetFacing: snapshot.exposureGraph.nodes.filter((n) => n.internetFacing).length,
      latRange: { max: MAP_LAT_MAX, min: MAP_LAT_MIN },
    },
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
    /* A category the estate does not hold gets NO score. Previously every
       category was scored regardless, so a tenant with zero classified assets
       still saw "Classified Assets — exposure 39, adversary interest 78". Those
       are null (render as "—"), never 0: a zero would read as "measured, and
       safe", which is a different and equally false claim. */
    const inScope = matchCount > 0
    const exposureScore = inScope ? clamp(hndl * cat.sensitivity * (0.5 + 0.5 * vulnShare)) : null
    const adversaryInterest = inScope ? clamp(cat.sensitivity * 55 + cat.retentionYears * 0.8 + (exposureScore ?? 0) * 0.25) : null
    const window = riskWindowLabel(cat.retentionYears)
    const futureValue = !inScope
      ? 'Not measured'
      : (exposureScore ?? 0) >= 70 ? 'Critical' : (exposureScore ?? 0) >= 45 ? 'High' : (exposureScore ?? 0) >= 20 ? 'Medium' : 'Low'
    return {
      key: cat.key,
      label: cat.label,
      inScope,
      assetCount: matchCount,
      exposureScore,
      confidentialityLifetimeYears: cat.retentionYears,
      confidentialityLabel: window.exceedsCrqc ? `${cat.retentionYears} yrs (exceeds CRQC)` : `${cat.retentionYears} yrs`,
      adversaryInterestScore: adversaryInterest,
      estimatedFutureValue: futureValue,
      regulation: cat.regulation,
    }
  }).sort((a, b) => Number(b.inScope) - Number(a.inScope) || (b.adversaryInterestScore ?? -1) - (a.adversaryInterestScore ?? -1))
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
/**
 * Forward-secrecy coverage over the observations that actually determine it.
 *
 * The previous filter accepted anything whose text contained "tls" — and every
 * inventory row carries protocol "TLSv1.3", so it matched 166 of 166 rows on a
 * live tenant, including 99 `library` rows. Everything that was not recognised
 * as ephemeral was then counted as UNPROTECTED, so the panel reported 117
 * unprotected "assets" for a two-asset estate and listed `No OCSP Stapling`,
 * `Information Disclosure`, `AES-256-GCM` (quantum-safe) and
 * `TLS_AES_256_GCM_SHA384` (TLS 1.3 — forward secret by construction) as
 * lacking forward secrecy.
 *
 * Now: only key-agreement-bearing observations are in scope, a bulk cipher or
 * hash is NOT APPLICABLE rather than unprotected, and counts are reported in
 * their true units — components measured, plus the distinct assets they sit on.
 */
function buildForwardSecrecy(snapshot: Snapshot, cryptoInventory: Row[], runtimeEvents: Row[]) {
  const protectedAssets = new Set<string>()
  const unprotectedAssets = new Set<string>()
  let protectedCount = 0
  let notApplicable = 0
  const unprotected: Array<{ asset: string; algorithm: string; protocol: string; reason: string }> = []
  const nonPfsBuckets = new Map<string, number>()
  const bump = (k: string) => nonPfsBuckets.set(k, (nonPfsBuckets.get(k) || 0) + 1)

  for (const c of cryptoInventory) {
    const anatomy = analyzeCryptoObservation(
      { algorithm: c.algorithm, name: c.name, itemType: c.item_type, protocol: c.protocol },
      isMeasuredCryptography(c),
    )
    // null = the observation has no key agreement, so it can be neither
    // protected nor unprotected. Excluded from BOTH numerator and denominator.
    if (anatomy.forwardSecrecy === null) { notApplicable += 1; continue }

    const assetId = str(c.asset_id)
    if (anatomy.forwardSecrecy) {
      protectedCount += 1
      if (assetId) protectedAssets.add(assetId)
      continue
    }

    if (assetId) unprotectedAssets.add(assetId)
    const bucket =
      anatomy.keyExchange === 'RSA' || /RSA key transport/i.test(anatomy.family)
        ? 'RSA key transport (no PFS)'
        : /Static Diffie/i.test(anatomy.family)
          ? 'Static Diffie-Hellman'
          : 'Non-ephemeral key exchange'
    bump(bucket)
    unprotected.push({
      asset: assetLabel(snapshot, assetId) || str(c.name) || EVIDENCE_UNAVAILABLE,
      algorithm: str(c.algorithm) || EVIDENCE_UNAVAILABLE,
      protocol: str(c.protocol) || 'n/a',
      reason: `${bucket} — recorded sessions stay decryptable if the long-term key is recovered`,
    })
  }

  // Runtime telemetry reinforces the picture but is a different population, so
  // it is reported separately instead of being added to the component counts.
  let runtimeLegacyEvents = 0
  for (const e of runtimeEvents) {
    if (e.is_legacy !== true) continue
    const anatomy = analyzeCryptoObservation({ algorithm: e.algorithm }, true)
    if (anatomy.forwardSecrecy === false) runtimeLegacyEvents += 1
  }

  const measured = protectedCount + unprotected.length
  const coveragePct = measured > 0 ? clamp((protectedCount / measured) * 100) : 0
  return {
    coveragePct,
    // Kept for contract compatibility, but these are COMPONENT counts and the
    // UI labels them as such.
    assetsProtected: protectedCount,
    assetsUnprotected: unprotected.length,
    totalTransport: measured,
    componentsMeasured: measured,
    componentsNotApplicable: notApplicable,
    assetsWithPfs: protectedAssets.size,
    assetsWithoutPfs: unprotectedAssets.size,
    runtimeLegacyEvents,
    nonPfsBreakdown: Array.from(nonPfsBuckets.entries()).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count),
    topUnprotected: unprotected.slice(0, 8),
    hasEvidence: measured > 0,
    basis: measured > 0
      ? `${measured} key-agreement observation(s) measured; ${notApplicable} non-key-exchange component(s) excluded as not applicable.`
      : 'No key-agreement observations recorded — run an authorized scan.',
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
/**
 * Cryptographic Exposure Matrix — grouped by the primitive that carries the risk.
 *
 * Previously grouped by substring: `/AES-?256/` matched
 * `TLS_RSA_WITH_AES_256_GCM_SHA384`, so static-RSA suites were filed under
 * **AES-256-GCM** and one vulnerable member marked the family vulnerable. The
 * top row of the matrix read "AES-256-GCM — Critical, quantum-vulnerable" for
 * an algorithm on the platform's own approved list. `Zone Not DNSSEC-Signed`
 * matched `/EC-/` and became an ECDSA algorithm, and the "Other" bucket — 16
 * policy findings — sorted to the top.
 *
 * Grouping now uses the decomposed key exchange / signature primitive, policy
 * findings are excluded outright, and `assetCount` counts ASSETS (it counted
 * distinct component names: 16 "assets" on a two-asset tenant).
 */
function buildExposureMatrix(snapshot: Snapshot, cryptoInventory: Row[]) {
  type Group = {
    algorithm: string
    assets: Set<string>
    count: number
    internetFacing: boolean
    cryptoClass: CryptoClass
    kind: string
  }
  const groups = new Map<string, Group>()
  const internetAssetIds = new Set(
    snapshot.exposureGraph.nodes.filter((n) => n.internetFacing).map((n) => str((n as unknown as Row).id) || n.label),
  )

  const ingest = (family: string, kind: string, cls: CryptoClass, assetId: string, assetLabelText: string) => {
    const g = groups.get(family) || {
      algorithm: family,
      assets: new Set<string>(),
      count: 0,
      internetFacing: false,
      cryptoClass: cls,
      kind,
    }
    g.count += 1
    if (assetId) g.assets.add(assetId)
    if (assetId && (internetAssetIds.has(assetId) || internetAssetIds.has(assetLabelText))) g.internetFacing = true
    // Worst posture within a family wins, but families no longer mix primitives.
    if (cls === 'vulnerable') g.cryptoClass = 'vulnerable'
    else if (g.cryptoClass !== 'vulnerable' && cls !== 'unknown') g.cryptoClass = cls
    groups.set(family, g)
  }

  for (const c of cryptoInventory) {
    const anatomy = analyzeCryptoObservation(
      { algorithm: c.algorithm, name: c.name, itemType: c.item_type, protocol: c.protocol },
      isMeasuredCryptography(c),
    )
    // A configuration finding is not an algorithm and must never occupy a row
    // in an algorithm matrix.
    if (anatomy.kind === 'policy' || anatomy.kind === 'protocol') continue
    const assetId = str(c.asset_id)
    // Trust the stored verdict when the scanner recorded one; otherwise use the
    // decomposed primitive's posture.
    const cls: CryptoClass =
      c.is_quantum_safe === true ? 'safe' : anatomy.quantumClass === 'hybrid' ? 'hybrid' : (anatomy.quantumClass as CryptoClass)
    ingest(anatomy.family, anatomy.kind, cls, assetId, assetLabel(snapshot, assetId))
  }

  const rows = Array.from(groups.values()).map((g) => {
    const assetCount = g.assets.size
    const criticality = g.internetFacing ? 'High' : assetCount >= 5 ? 'High' : assetCount >= 2 ? 'Medium' : 'Low'
    const exposure =
      g.cryptoClass === 'safe' ? 'None' : g.cryptoClass === 'hybrid' ? 'Low' : g.cryptoClass === 'unknown' ? 'Unknown' : g.internetFacing ? 'Critical' : 'High'
    const priority = migrationPriority(g.cryptoClass, assetCount, g.internetFacing)
    return {
      algorithm: g.algorithm,
      kind: g.kind,
      assetCount,
      instanceCount: g.count,
      businessCriticality: criticality,
      exposure,
      cryptoClass: g.cryptoClass,
      migrationPriority: priority.label,
      priorityRank: priority.rank,
      internetFacing: g.internetFacing,
    }
  }).sort((a, b) => b.priorityRank - a.priorityRank || b.instanceCount - a.instanceCount)
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

  // `unit` is MEASURED (a real count from the estate); `perUnitGb` is a
  // published planning assumption. Both travel with the line so the page can
  // show the arithmetic instead of presenting the product as an observation.
  const lines = [
    { key: 'traffic', label: 'Encrypted Traffic', unit: inv.domainsScanned, unitLabel: 'scanned host', perUnitGb: GB.trafficPerEndpoint },
    { key: 'archives', label: 'Stored Archives', unit: repos, unitLabel: 'vault file', perUnitGb: GB.archivePerRepo },
    { key: 'dbdumps', label: 'Database Dumps', unit: dbStores, unitLabel: 'database asset', perUnitGb: GB.dbDumpPerStore },
    { key: 'backups', label: 'Backups', unit: repos, unitLabel: 'vault file', perUnitGb: GB.backupPerRepo },
    { key: 'email', label: 'Email Repositories', unit: emailAssets, unitLabel: 'mail asset', perUnitGb: GB.emailPerAsset },
    { key: 'documents', label: 'Document Repositories', unit: docAssets, unitLabel: 'document asset', perUnitGb: GB.docPerAsset },
    { key: 'sourcecode', label: 'Source Code Repositories', unit: codeRepos, unitLabel: 'code asset', perUnitGb: GB.codePerRepo },
  ].map((l) => ({ ...l, gb: l.unit * l.perUnitGb, tb: tb(l.unit * l.perUnitGb) }))
  const totalGb = lines.reduce((s, l) => s + l.gb, 0)
  return {
    lines,
    totalTb: tb(totalGb),
    totalGb,
    hasEvidence: totalGb > 0,
    basis: 'Planning estimate: measured unit counts × a published per-unit volume assumption. Not an observation of captured traffic.',
  }
}
function buildFutureDecryptable(snapshot: Snapshot, captured: ReturnType<typeof buildCapturedData>) {
  // No CBOM ⇒ no measured vulnerable share ⇒ nothing is projected decryptable.
  // This used to assume 50% whenever any evidence existed, publishing a
  // decryptable volume no measurement supported.
  const vulnShare = snapshot.inventory.cryptoComponents > 0 ? snapshot.inventory.vulnerableComponents / snapshot.inventory.cryptoComponents : 0
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
  // Exact tenant counts from the shared posture model. These were tallied from
  // `exposureGraph.nodes`, which is the 40 highest-risk assets only, so a large
  // estate under-reported every bucket.
  const inv = snapshot.inventory
  const pqcReady = inv.pqcReadyAssets
  const notAssessed = num(inv.unassessedAssets)
  const hybridReady = Math.max(0, inv.hybridAssets - notAssessed)
  const legacyOnly = inv.quantumVulnerableAssets
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
    pqcReady, hybridReady, legacyOnly, notAssessed,
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
    // Modelled interest = intrinsic sector value × this estate's measured
    // exposure. A sector the estate holds no assets in is NOT scored — it used
    // to be, so every tenant saw "Defense: 72 High" without owning a single
    // defense asset (the same defect Harvest Value already fixed).
    const inScope = present > 0
    const score = inScope ? clamp(s.baseWeight * (hndl * 0.55 + exposure * 0.25 + 35) + 8) : null
    return {
      key: s.key,
      sector: s.label,
      interestScore: score,
      level: score === null ? 'Not in estate' : score >= 75 ? 'Critical' : score >= 55 ? 'High' : score >= 35 ? 'Moderate' : 'Low',
      assetsInSector: present,
      inScope,
    }
  }).sort((a, b) => Number(b.inScope) - Number(a.inScope) || (b.interestScore ?? -1) - (a.interestScore ?? -1))
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
  // A MODELLED relevance, not observed adversary activity: the actor's published
  // HNDL profile weighted by this estate's measured HNDL risk and exposure. The
  // asset list is the estate's harvest-exposed surface (internet-facing or
  // high-risk), which is what such an actor could collect — not a claim that
  // the actor is targeting those assets.
  const basis = `Modelled from HNDL risk ${hndl}/100 and crypto exposure ${exposure}/100 — no threat-intelligence feed is connected, so this is not observed activity.`
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
      basis,
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
/**
 * Remediation scope, counted in the unit each action actually changes.
 *
 * The previous counts were borrowed: "Enable Hybrid TLS" counted every scanned
 * domain, "Deploy ML-DSA" and "Replace Legacy Certificates" counted ALL
 * certificates (quantum-safe ones included), "Rotate Keys" counted every key
 * the tenant ever generated (its own ML-KEM keys among them), "Deploy ML-KEM"
 * summed matrix rows so one asset with three RSA families counted three times,
 * and "Quantum-Safe VPN" read a 'Legacy VPN' bucket that no code produces, so
 * it was always 0.
 */
function measureRemediationScope(rows: HndlRawRows) {
  const classicalKeyExchangeAssets = new Set<string>()
  const internetClassicalAssets = new Set<string>()
  const vpnClassicalAssets = new Set<string>()
  const internetAssetIds = new Set(rows.assets.filter((a) => isInternetFacing(a)).map((a) => str(a.id)))
  for (const c of rows.cryptoInventory) {
    if (c.is_quantum_safe === true) continue
    const anatomy = analyzeCryptoObservation({ algorithm: c.algorithm, name: c.name, itemType: c.item_type, protocol: c.protocol }, isMeasuredCryptography(c))
    if ((anatomy.kind !== 'key-exchange' && anatomy.kind !== 'cipher-suite') || anatomy.quantumClass !== 'vulnerable') continue
    const assetId = str(c.asset_id)
    if (!assetId) continue
    classicalKeyExchangeAssets.add(assetId)
    if (internetAssetIds.has(assetId)) internetClassicalAssets.add(assetId)
    if (/ipsec|ikev?\d?|\bvpn\b|wireguard|openvpn/i.test(`${str(c.name)} ${str(c.item_type)} ${str(c.protocol)}`)) vpnClassicalAssets.add(assetId)
  }
  const classicalCertificates = rows.certificates.filter((c) => c.is_quantum_safe !== true && classifyAlgorithm(str(c.algorithm)) === 'vulnerable').length
  const classicalKeys = (rows.keys || []).filter((k) => classifyAlgorithm(str(k.algorithm)) === 'vulnerable').length
  return {
    classicalKeyExchangeAssets: classicalKeyExchangeAssets.size,
    internetClassicalAssets: internetClassicalAssets.size,
    vpnClassicalAssets: vpnClassicalAssets.size,
    classicalCertificates,
    classicalKeys,
  }
}

function buildRemediationCenter(snapshot: Snapshot, scope: ReturnType<typeof measureRemediationScope>, forwardSecrecy: ReturnType<typeof buildForwardSecrecy>) {
  const inv = snapshot.inventory
  const reduction = Math.max(0, snapshot.scores.quantumRisk - Math.max(10, Math.round(snapshot.scores.quantumRisk * 0.25)))
  const weeks = snapshot.estimates.migrationTimelineWeeks || 0
  const completion = (ratio: number) => weeks ? new Date(Date.now() + Math.round(weeks * ratio) * 7 * 86400000).toISOString().slice(0, 10) : EVIDENCE_UNAVAILABLE
  const actions = [
    { key: 'hybrid-tls', label: 'Enable Hybrid TLS', affectedAssets: scope.internetClassicalAssets, unit: 'internet-facing asset', riskReductionPct: clamp(reduction * 0.4), effort: 'Medium', completion: completion(0.2), href: '/dashboard/tls-orchestrator', requires: 'TLS 1.3 + X25519MLKEM768 hybrid group' },
    { key: 'deploy-mlkem', label: 'Deploy ML-KEM', affectedAssets: scope.classicalKeyExchangeAssets, unit: 'asset', riskReductionPct: clamp(reduction * 0.35), effort: 'High', completion: completion(0.35), href: '/dashboard/qkms/overview', requires: 'FIPS 203 key establishment' },
    { key: 'deploy-mldsa', label: 'Deploy ML-DSA', affectedAssets: scope.classicalCertificates, unit: 'certificate', riskReductionPct: clamp(reduction * 0.25), effort: 'High', completion: completion(0.4), href: '/dashboard/pki-visibility', requires: 'FIPS 204 signatures' },
    { key: 'replace-certs', label: 'Replace Legacy Certificates', affectedAssets: scope.classicalCertificates, unit: 'certificate', riskReductionPct: clamp(reduction * 0.2), effort: 'Medium', completion: completion(0.3), href: '/dashboard/pki-visibility', requires: 'Hybrid certificate chains' },
    { key: 'forward-secrecy', label: 'Enable Forward Secrecy', affectedAssets: num(forwardSecrecy.assetsWithoutPfs), unit: 'asset', riskReductionPct: clamp(reduction * 0.18), effort: 'Low', completion: completion(0.15), href: '/dashboard/tls-orchestrator', requires: 'ECDHE / X25519 ephemeral key exchange' },
    { key: 'rotate-keys', label: 'Rotate Cryptographic Keys', affectedAssets: scope.classicalKeys, unit: 'classical key', riskReductionPct: clamp(reduction * 0.12), effort: 'Medium', completion: completion(0.25), href: '/dashboard/qkms/rotation', requires: 'Re-key with PQC-ready custody' },
    { key: 'quantum-vpn', label: 'Deploy Quantum-Safe VPN', affectedAssets: scope.vpnClassicalAssets, unit: 'VPN asset', riskReductionPct: clamp(reduction * 0.1), effort: 'High', completion: completion(0.4), href: '/dashboard/migration-planner', requires: 'Hybrid IKEv2 / ML-KEM (RFC 9370)' },
    { key: 'validate-pqc', label: 'Validate PQC Interoperability', affectedAssets: inv.quantumVulnerableAssets, unit: 'asset', riskReductionPct: clamp(reduction * 0.08), effort: 'Medium', completion: completion(0.45), href: '/dashboard/migration-sandbox', requires: 'Hybrid negotiation + trust-chain validation' },
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
  /** generated_keys (algorithm only). Optional so older fixtures still assemble. */
  keys?: Row[]
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
    theater: buildTheater(snapshot, assets, certificates),
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
    remediationCenter: buildRemediationCenter(snapshot, measureRemediationScope(rows), forwardSecrecy),
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

async function computeHndlIntelligence(token: string, userId: string) {
  const snapshot = await buildSnapshot(token, userId)
  const client = createAuthClient(token)
  const [cryptoInventory, certificates, runtimeEvents, assets, migrationJobs, keys] = client
    ? await Promise.all([
        safeRows(client as never, 'crypto_inventory', 'id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, created_at', userId, 2500),
        safeRows(client as never, 'certificates', 'id, asset_id, name, algorithm, key_size, issuer, not_after, is_quantum_safe, status, created_at', userId, 1500),
        safeRows(client as never, 'runtime_crypto_events', 'id, asset_id, algorithm, severity, risk_score, asset_name, asset_type, host, is_pqc, is_legacy, hndl_risk, created_at', userId, 3000),
        safeRows(client as never, 'assets', 'id, name, type, environment, region, service_owner, criticality, status, metadata, created_at', userId, 1500),
        safeRows(client as never, 'migration_jobs', 'id, status, progress, asset_id, job_type, created_at', userId, 300),
        safeRows(client as never, 'generated_keys', 'id, algorithm, status, created_at', userId, 1500),
      ])
    : [[], [], [], [], [], []]
  return assembleHndlIntelligence(snapshot, { cryptoInventory, certificates, runtimeEvents, assets, migrationJobs, keys })
}

/* One build per tenant per 15s window, shared by the JSON route, the stream
   and every open tab — this builder adds six table reads on top of the shared
   QR snapshot, and used to run them once per client per tick. */
const hndlCache = createSingleFlightCache<ReturnType<typeof assembleHndlIntelligence>>(15_000)
function buildHndlIntelligence(token: string, userId: string) {
  return hndlCache.get(userId, () => computeHndlIntelligence(token, userId))
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const data = await buildHndlIntelligence(token!, user!.id)
    res.json({ data: { ...data, fingerprint: payloadFingerprint(data) } })
  } catch (error) {
    console.error('Harvest-now (HNDL) error:', error)
    res.status(500).json({ error: { code: 'HNDL_ERROR', message: error instanceof Error ? error.message : 'Failed to build HNDL intelligence' } })
  }
})

router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, {
    event: 'hndl-intelligence',
    build: () => buildHndlIntelligence(token!, user!.id),
    intervalMs: 15_000,
  })
})

export { buildHndlIntelligence, assembleHndlIntelligence }
export type { HndlRawRows }
export default router
