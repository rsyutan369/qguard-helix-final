/**
 * Estate intelligence — normalisation and fingerprint merging.
 *
 * Built for estates with thousands of assets. Raw rows from the shared scanner
 * tables are turned into:
 *   - EstateAsset         one per `assets` row, with owner / environment /
 *                         business service resolved from stored fields only;
 *   - Observation         one per cryptographic `crypto_inventory` row, with the
 *                         canonical quantum verdict (role-aware, never the
 *                         algorithm alone — see scanner/exposure/algorithms.ts);
 *   - CertificateIdentity certificates merged by fingerprint, so one certificate
 *                         deployed on 300 endpoints is ONE thing to replace with
 *                         300 places it is used.
 *
 * Pure: no Express, no Supabase, no React. Shared by the API and check tools.
 */
import {
  classifyQuantum,
  describeAlgorithm,
  inferRole,
  parseKeySize,
  severityFor,
  type CanonicalAlgorithm,
} from '@/lib/scanner/exposure/algorithms'
import type { CryptoRole, FindingSeverity, QuantumStatus } from '@/lib/scanner/exposure/types'
import { isInternetFacing, recordOf, str, type Row } from '@/lib/migration/asset-intelligence'

export type { Row }

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

export interface TableCoverage {
  table: string
  loaded: number
  /** Rows the tenant holds, when the count was available. */
  total: number | null
  /** True when the loader stopped at its cap — every view must disclose it. */
  truncated: boolean
}

export interface EstateInputs {
  assets: Row[]
  inventory: Row[]
  certificates: Row[]
  relationships: Row[]
  migrationJobs: Row[]
  coverage: TableCoverage[]
  /** Epoch ms; injectable so tests and fixtures are deterministic. */
  now?: number
}

/* ------------------------------------------------------------------ */
/* Assets                                                              */
/* ------------------------------------------------------------------ */

export type EnvironmentKey = 'production' | 'staging' | 'test' | 'development' | 'unknown'
export const ENVIRONMENT_LABEL: Record<EnvironmentKey, string> = {
  production: 'Production', staging: 'Staging', test: 'Test / QA', development: 'Development', unknown: 'Unspecified',
}
/** Rollout order for campaign waves: least critical environments first; unspecified before production. */
export const ENVIRONMENT_ROLLOUT: EnvironmentKey[] = ['development', 'test', 'staging', 'unknown', 'production']

export type CriticalityKey = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

export type OwnerSource = 'service_owner' | 'owner tag' | 'cloud tag' | 'certificate subject'
export const OWNER_SOURCE_LABEL: Record<OwnerSource, string> = {
  service_owner: 'Asset record (service_owner)',
  'owner tag': 'Owner / team tag on the asset',
  'cloud tag': 'Cloud resource tag',
  'certificate subject': 'Certificate subject OU (inferred)',
}

export interface EstateAsset {
  id: string
  name: string
  type: string
  environment: EnvironmentKey
  environmentRaw: string
  owner: string | null
  ownerSource: OwnerSource | null
  /** Business service / application the asset belongs to, when recorded. */
  service: string | null
  criticality: CriticalityKey
  internetFacing: boolean
}

function normaliseEnvironment(raw: string): EnvironmentKey {
  const value = raw.toLowerCase()
  if (!value) return 'unknown'
  if (/\bprod|production|live\b|\bprd\b/.test(value)) return 'production'
  if (/stag|pre-?prod|uat/.test(value)) return 'staging'
  if (/\btest|\bqa\b|\bsit\b/.test(value)) return 'test'
  if (/\bdev|sandbox|local/.test(value)) return 'development'
  return 'unknown'
}

function normaliseCriticality(raw: string): CriticalityKey {
  const value = raw.toLowerCase()
  if (value.includes('crit') || value === 'tier0' || value === 'tier-0' || value === 'p0') return 'critical'
  if (value.includes('high') || value === 'tier1' || value === 'tier-1' || value === 'p1') return 'high'
  if (value.includes('med') || value.includes('moderate') || value === 'tier2' || value === 'p2') return 'medium'
  if (value.includes('low') || value === 'tier3' || value === 'p3') return 'low'
  return 'unknown'
}

const firstString = (...values: unknown[]) => {
  for (const value of values) {
    const text = str(value).trim()
    if (text) return text
  }
  return ''
}

/** Owner from STORED fields only, in order of authority. Never guessed from a name. */
function resolveOwner(asset: Row): { owner: string | null; source: OwnerSource | null } {
  const column = str(asset.service_owner).trim()
  if (column) return { owner: column, source: 'service_owner' }
  const meta = recordOf(asset.metadata)
  const tags = recordOf(meta.tags)
  const tagged = firstString(meta.owner, meta.team, meta.owner_team, meta.ownerTeam, tags.owner, tags.team, tags.Owner, tags.Team)
  if (tagged) return { owner: tagged, source: 'owner tag' }
  const cloud = { ...recordOf(meta.cloud_tags), ...recordOf(meta.cloudTags), ...recordOf(meta.resource_tags) }
  const cloudOwner = firstString(cloud.owner, cloud.Owner, cloud.team, cloud.Team, cloud['cost-center'], cloud.CostCenter)
  if (cloudOwner) return { owner: cloudOwner, source: 'cloud tag' }
  return { owner: null, source: null }
}

export function normaliseAsset(asset: Row): EstateAsset {
  const meta = recordOf(asset.metadata)
  const tags = recordOf(meta.tags)
  const environmentRaw = firstString(asset.environment, meta.environment, tags.environment, tags.env)
  const { owner, source } = resolveOwner(asset)
  return {
    id: str(asset.id),
    name: firstString(asset.name, meta.target, asset.id),
    type: firstString(asset.type, 'asset'),
    environment: normaliseEnvironment(environmentRaw),
    environmentRaw,
    owner,
    ownerSource: source,
    service: firstString(meta.business_service, meta.businessService, meta.application, meta.app, meta.service, tags.service, tags.application) || null,
    criticality: normaliseCriticality(firstString(asset.criticality, meta.criticality, tags.criticality)),
    internetFacing: isInternetFacing(asset),
  }
}

/* ------------------------------------------------------------------ */
/* Observations (crypto_inventory)                                     */
/* ------------------------------------------------------------------ */

export type Actionability = 'quantum' | 'classical' | 'none' | 'unclassified'

export interface Observation {
  id: string
  assetId: string
  algorithm: string
  canonical: CanonicalAlgorithm | null
  role: CryptoRole
  keySize: number | null
  verdict: QuantumStatus
  severity: FindingSeverity
  /**
   * quantum      — a Shor-broken primitive in a quantum-relevant role;
   * classical    — broken today regardless of quantum (SHA-1, 3DES, RSA-1024…);
   * none         — PQC, hybrid or quantum-resistant: nothing to migrate;
   * unclassified — the algorithm is not one the engine recognises.
   */
  actionability: Actionability
  itemType: string
  /** Package / library this observation was found in, when recorded. */
  packageName: string | null
  observedAt: number
  /** Identity of the component, independent of the asset it was seen on. */
  componentKey: string
}

/**
 * Key-size thresholds only mean something for integer-factorisation and
 * finite-field families: RSA/DH/DSA below 2048 bits are broken today. A 256-bit
 * elliptic curve is the normal size, not an undersized key.
 */
const INTEGER_FAMILIES = new Set(['rsa', 'dh', 'dsa'])
function undersizedKey(canonical: CanonicalAlgorithm | null, keySize: number | null) {
  return Boolean(canonical && INTEGER_FAMILIES.has(canonical.family) && keySize !== null && keySize < 2048)
}
/** severityFor escalates keys <= 1024 bits; only pass the size where that rule applies. */
function integerKeySize(canonical: CanonicalAlgorithm | null, keySize: number | null) {
  return canonical && INTEGER_FAMILIES.has(canonical.family) ? keySize : null
}

const LIBRARY_TYPE = /librar|package|dependenc|sdk|module|crate|gem|npm|maven|pip/i

export function observationFromInventory(row: Row): Observation {
  const meta = recordOf(row.metadata)
  const algorithm = firstString(row.algorithm, meta.algorithm, row.name)
  const itemType = firstString(row.item_type, meta.category)
  const keySize = parseKeySize(str(row.key_size ?? meta.keySize ?? '')) ?? null
  const explicitRole = firstString(meta.role) as CryptoRole
  const context = [itemType, row.name, row.protocol, meta.category, meta.detectionMethod].map(str).join(' ')
  const role = inferRole(algorithm, context, explicitRole || undefined)
  const canonical = describeAlgorithm(algorithm)
  let verdict = classifyQuantum({ algorithm, role, keySize, hybridPartner: firstString(meta.hybridPartner, meta.hybrid_partner) || null })
  // The engine does not know the algorithm, but the writer stored a verdict:
  // keep the stored fact rather than discarding it.
  if (verdict.status === 'unknown' && row.is_quantum_safe === true) verdict = { ...verdict, status: 'pqc', quantumRelevant: true }
  if (verdict.status === 'unknown' && row.is_vulnerable === true && canonical) verdict = { ...verdict, status: 'vulnerable', quantumRelevant: true }

  const classicallyWeak = Boolean(canonical?.classicallyWeak) || undersizedKey(canonical, keySize)
  const detection = /potential|pattern|heuristic/i.test(str(meta.detectionMethod)) ? 'potential' : 'observed'
  const severity = severityFor({ quantum: verdict, classicallyWeak, role, detection, keySize: integerKeySize(canonical, keySize) })

  let actionability: Actionability
  if (!canonical && verdict.status === 'unknown') actionability = 'unclassified'
  else if (classicallyWeak) actionability = 'classical'
  else if (verdict.status === 'vulnerable' && verdict.quantumRelevant) actionability = 'quantum'
  else actionability = 'none'

  const packageName = firstString(meta.package_name, meta.packageName, meta.package, meta.library, meta.dependency)
    || (LIBRARY_TYPE.test(itemType) ? firstString(row.name) : '')
  const observedAt = Date.parse(firstString(row.discovered_at, row.created_at)) || 0

  return {
    id: str(row.id),
    assetId: str(row.asset_id),
    algorithm,
    canonical,
    role,
    keySize,
    verdict: verdict.status,
    severity,
    actionability,
    itemType,
    packageName: packageName ? packageName.toLowerCase() : null,
    observedAt,
    componentKey: [canonical?.canonical ?? algorithm.toLowerCase(), keySize ?? '', role, packageName.toLowerCase()].join('|'),
  }
}

/* ------------------------------------------------------------------ */
/* Certificates, merged by fingerprint                                 */
/* ------------------------------------------------------------------ */

export interface CertificateIdentity {
  /** Fingerprint, or serial+issuer when no fingerprint was captured. */
  key: string
  keyBasis: 'fingerprint' | 'serial + issuer' | 'record id'
  subject: string
  issuer: string
  /** Issuer common name, used to group re-issuance work by CA. */
  issuerName: string
  algorithm: string
  canonical: CanonicalAlgorithm | null
  keySize: number | null
  notAfter: number | null
  verdict: QuantumStatus
  actionability: Actionability
  severity: FindingSeverity
  assetIds: Set<string>
  recordIds: string[]
  /** Subject OU, used only as an inferred ownership hint. */
  subjectOu: string | null
  observedAt: number
}

function distinguishedNamePart(dn: string, part: string): string {
  const match = new RegExp(`(?:^|[,/]\\s*)${part}\\s*=\\s*([^,/]+)`, 'i').exec(dn)
  return match ? match[1].trim() : ''
}

/**
 * The CA's name for grouping re-issuance work. Issuers are stored either as a
 * DN ("CN=R3,O=Let's Encrypt") or as bare values in X.509 order
 * ("GB, Greater Manchester, Salford, Sectigo Limited, Sectigo RSA DV Secure Server CA")
 * — where the first value is the COUNTRY, so it must never be picked blindly.
 */
export function issuerDisplayName(issuer: string): string {
  const cn = distinguishedNamePart(issuer, 'CN')
  if (cn) return cn
  if (/=/.test(issuer)) return distinguishedNamePart(issuer, 'O') || 'Unknown issuer'
  const parts = issuer.split(',').map((part) => part.trim()).filter(Boolean)
  if (!parts.length) return 'Unknown issuer'
  const named = parts.filter((part) => /\bCA\b|Authority|Root|Issuing|Certificat|TLS|SSL|Encrypt|Server|\bR\d+\b|\bE\d+\b|Trust|Sign/i.test(part))
  return named.at(-1) ?? parts.at(-1)!
}

export function mergeCertificates(rows: Row[]): CertificateIdentity[] {
  const merged = new Map<string, CertificateIdentity>()
  for (const row of rows) {
    const meta = recordOf(row.metadata)
    const fingerprint = firstString(row.fp, meta.fingerprint, meta.sha256Fingerprint, meta.fingerprint256).toLowerCase().replace(/[^0-9a-f]/g, '')
    const serial = firstString(row.serial_number).toLowerCase()
    const issuer = firstString(row.issuer)
    const key = fingerprint ? `fp:${fingerprint}` : serial && issuer ? `sn:${serial}|${issuer.toLowerCase()}` : `id:${str(row.id)}`
    const existing = merged.get(key)
    const assetId = str(row.asset_id)
    const observedAt = Date.parse(firstString(row.updated_at, row.created_at)) || 0
    if (existing) {
      if (assetId) existing.assetIds.add(assetId)
      existing.recordIds.push(str(row.id))
      existing.observedAt = Math.max(existing.observedAt, observedAt)
      continue
    }
    const algorithm = firstString(row.algorithm)
    const keySize = parseKeySize(str(row.key_size ?? '')) ?? null
    const canonical = describeAlgorithm(algorithm)
    let verdict = classifyQuantum({ algorithm, role: 'certificate', keySize })
    if (row.is_quantum_safe === true && verdict.status !== 'vulnerable') verdict = { ...verdict, status: 'pqc' }
    const classicallyWeak = Boolean(canonical?.classicallyWeak) || undersizedKey(canonical, keySize)
    const severity = severityFor({ quantum: verdict, classicallyWeak, role: 'certificate', detection: 'observed', keySize: integerKeySize(canonical, keySize) })
    const actionability: Actionability = !canonical && verdict.status === 'unknown'
      ? 'unclassified'
      : classicallyWeak ? 'classical' : verdict.status === 'vulnerable' ? 'quantum' : 'none'
    const subject = firstString(row.subject, row.name)
    const notAfter = Date.parse(firstString(row.not_after)) || null
    merged.set(key, {
      key,
      keyBasis: fingerprint ? 'fingerprint' : key.startsWith('sn:') ? 'serial + issuer' : 'record id',
      subject,
      issuer,
      issuerName: issuerDisplayName(issuer),
      algorithm,
      canonical,
      keySize,
      notAfter,
      verdict: verdict.status,
      actionability,
      severity,
      assetIds: new Set(assetId ? [assetId] : []),
      recordIds: [str(row.id)],
      subjectOu: distinguishedNamePart(subject, 'OU') || null,
      observedAt,
    })
  }
  return [...merged.values()]
}

/* ------------------------------------------------------------------ */
/* Shared weights                                                      */
/* ------------------------------------------------------------------ */

export const SEVERITY_RANK: Record<FindingSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
export const SEVERITY_WEIGHT: Record<FindingSeverity, number> = { critical: 1, high: 0.75, medium: 0.5, low: 0.25, info: 0.1 }
export const CRITICALITY_WEIGHT: Record<CriticalityKey, number> = { critical: 1, high: 0.8, medium: 0.6, low: 0.4, unknown: 0.6 }

export function worstSeverity(values: Iterable<FindingSeverity>): FindingSeverity {
  let worst: FindingSeverity = 'info'
  for (const value of values) if (SEVERITY_RANK[value] > SEVERITY_RANK[worst]) worst = value
  return worst
}

/** How much one affected asset contributes to a fix's risk: severity × business criticality × exposure. */
export function assetWeight(severity: FindingSeverity, asset: EstateAsset | undefined): number {
  const criticality = CRITICALITY_WEIGHT[asset?.criticality ?? 'unknown']
  const exposure = asset?.internetFacing ? 1 : 0.7
  return SEVERITY_WEIGHT[severity] * criticality * exposure
}
