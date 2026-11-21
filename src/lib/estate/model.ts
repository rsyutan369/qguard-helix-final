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
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'
import { observationClass } from '@/lib/scanner/finding-identity'

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
  migrationValidations?: Row[]
  plannerQueueAssetIds?: Set<string>
  revision?: string
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

export type OwnerSource = 'service_owner' | 'owner tag' | 'cloud tag'
export const OWNER_SOURCE_LABEL: Record<OwnerSource, string> = {
  service_owner: 'Asset record (service_owner)',
  'owner tag': 'Owner / team tag on the asset',
  'cloud tag': 'Cloud resource tag',
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
  status: string | null
  recordedScanAt: string | null
}

function normaliseEnvironment(raw: string): EnvironmentKey {
  const value = raw.toLowerCase()
  if (!value) return 'unknown'
  if (/stag|pre-?prod|uat/.test(value)) return 'staging'
  if (/\bprod|production|live\b|\bprd\b/.test(value)) return 'production'
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
    const text = typeof value === 'string' ? value.trim() : ''
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
  const tagged = firstString(meta.owner, meta.businessOwner, meta.team, meta.owner_team, meta.ownerTeam, tags.owner, tags.team, tags.Owner, tags.Team)
  if (tagged) return { owner: tagged, source: 'owner tag' }
  const cloud = { ...recordOf(meta.cloud_tags), ...recordOf(meta.cloudTags), ...recordOf(meta.resource_tags) }
  const cloudOwner = firstString(cloud.owner, cloud.Owner, cloud.team, cloud.Team)
  if (cloudOwner) return { owner: cloudOwner, source: 'cloud tag' }
  return { owner: null, source: null }
}

export function normaliseAsset(asset: Row): EstateAsset {
  const meta = recordOf(asset.metadata)
  const tags = recordOf(meta.tags)
  const cloud = { ...recordOf(meta.cloud_tags), ...recordOf(meta.cloudTags), ...recordOf(meta.resource_tags) }
  const environmentRaw = firstString(asset.environment, meta.environment, tags.environment, tags.env, tags.Environment, cloud.environment, cloud.Environment, cloud.env)
  const { owner, source } = resolveOwner(asset)
  const recordedScanAt = Date.parse(firstString(meta.last_scanned_at))
  return {
    id: str(asset.id),
    name: firstString(asset.name, meta.target, asset.id),
    type: firstString(asset.type),
    environment: normaliseEnvironment(environmentRaw),
    environmentRaw,
    owner,
    ownerSource: source,
    service: firstString(meta.business_service, meta.businessService, meta.application, meta.app, meta.service, tags.business_service, tags.service, tags.Service, tags.application, cloud.business_service, cloud.service, cloud.Service, cloud.application) || null,
    criticality: normaliseCriticality(firstString(asset.criticality, meta.criticality, tags.criticality)),
    internetFacing: isInternetFacing(asset),
    status: firstString(asset.status) || null,
    recordedScanAt: Number.isFinite(recordedScanAt) ? new Date(recordedScanAt).toISOString() : null,
  }
}

/* ------------------------------------------------------------------ */
/* Observations (crypto_inventory)                                     */
/* ------------------------------------------------------------------ */

export type Actionability = 'quantum' | 'classical' | 'none' | 'unclassified' | 'context'

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
   * unclassified — the row needs more algorithm evidence.
   * context      — a scanner rule, software inventory or scan diagnostic.
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
const CONTEXT_CLASSES = new Set([
  'rule', 'connectivity', 'certificate revocation', 'certificate transparency', 'dns security',
  'nist compliance', 'repository access', 'repository scan error', 'security headers', 'ssh metadata',
  'policy', 'configuration finding', 'scan diagnostic',
])
const API_CONTEXT_LABELS = new Set(['hsts', 'information disclosure', 'cookie security', 'graphql', 'pgp/gpg', 'oauth'])

function observedPrimitive(algorithm: string): { name: string; role?: CryptoRole; hybrid?: string; suite?: boolean } {
  const annotated = algorithm.match(/^(.+)\s+\((Certificate|Signature|Chain Signature)\)$/i)
  if (annotated) {
    const base = observedPrimitive(annotated[1])
    return { ...base, role: /^certificate$/i.test(annotated[2]) ? 'certificate' : 'signature' }
  }
  const anatomy = analyzeCryptoObservation({ algorithm })
  if (anatomy.kind === 'cipher-suite') {
    const parts = [anatomy.bulk, anatomy.mac]
    const weak = parts.find((part) => describeAlgorithm(part)?.classicallyWeak)
    if (weak) return { name: weak, role: weak === anatomy.bulk ? 'encryption' : 'hashing', suite: true }
    if (anatomy.keyExchange && describeAlgorithm(anatomy.keyExchange)) return { name: anatomy.keyExchange, role: 'key-exchange', suite: true }
    if (anatomy.authentication && describeAlgorithm(anatomy.authentication)) return { name: anatomy.authentication, role: 'signature', suite: true }
    return anatomy.keyExchange?.startsWith('Ephemeral (TLS 1.3') && anatomy.bulk
      ? { name: anatomy.bulk, role: 'encryption', suite: true }
      : { name: '', suite: true } // An unknown suite must not inherit the bulk cipher's verdict.
  }
  if (anatomy.quantumClass === 'hybrid' && (anatomy.kind === 'key-exchange' || anatomy.kind === 'signature')) {
    const role = anatomy.kind === 'key-exchange' ? 'key-exchange' : 'signature'
    return { name: algorithm, role, hybrid: anatomy.family }
  }
  if (/^sha1withrsa(?:encryption)?$/i.test(algorithm)) return { name: 'SHA-1', role: 'signature' }
  if (/^rsaencryption(?:[ -]\d{4})?$|^sha(?:224|256|384|512)withrsa(?:encryption)?$/i.test(algorithm)) {
    return { name: 'RSA', role: algorithm.toLowerCase().startsWith('sha') ? 'signature' : undefined }
  }
  if (/^(?:RS|PS)(256|384|512)$/i.test(algorithm)) return { name: 'RSA', role: 'token-signing' }
  if (/^ES(?:256K?|384|512)$/i.test(algorithm)) return { name: 'ECDSA', role: 'token-signing' }
  if (/^HS(?:256|384|512)$/i.test(algorithm)) return { name: 'HMAC', role: 'authentication' }
  return { name: algorithm }
}

export function observedAlgorithmFamily(algorithm: string): CanonicalAlgorithm | null {
  const primitive = observedPrimitive(algorithm)
  return describeAlgorithm(primitive.hybrid ?? primitive.name)
}

export function observationFromInventory(row: Row): Observation {
  const meta = recordOf(row.metadata)
  const name = firstString(row.name)
  const nameClass = observationClass(name)
  const category = observationClass(meta.category)
  const labelAlgorithm = name.includes(':') ? name.slice(name.indexOf(':') + 1).trim() : name
  const recordedAlgorithm = [firstString(row.algorithm), firstString(meta.algorithm)]
    .find((value) => value && !/^(?:unknown(?: algorithm)?|undetected|n\/a|none|-|pqc-ready)$/i.test(value))
  const labelPrimitive = recordedAlgorithm ? null : observedPrimitive(labelAlgorithm)
  const algorithm = recordedAlgorithm ?? (labelPrimitive && (labelPrimitive.hybrid || describeAlgorithm(labelPrimitive.name)) ? labelAlgorithm : '')
  const itemType = firstString(row.item_type, meta.category)
  const primitive = observedPrimitive(algorithm)
  const canonical = describeAlgorithm(primitive.name)
  const contextOnly = CONTEXT_CLASSES.has(nameClass) || CONTEXT_CLASSES.has(category)
    || (category === 'api security' && API_CONTEXT_LABELS.has(algorithm.toLowerCase()))
    || (category === 'certificate' && /^expired certificate$/i.test(algorithm))
    || (category === 'key exchange' && /^hndl risk:/i.test(algorithm))
    || (LIBRARY_TYPE.test(itemType) && !canonical && !primitive.hybrid)
  const recordedSize = parseKeySize(str(row.key_size ?? meta.keySize ?? ''))
  const embeddedSize = /^(?:rsa(?:encryption)?|dsa|dh|dhe|ffdhe)[-_ ]?\d{4,5}$/i.test(algorithm) ? parseKeySize(algorithm) : null
  // Older scanner writers placed the suite's AES/digest length in key_size.
  const keySize = primitive.suite ? (canonical?.family === 'aes' ? parseKeySize(primitive.name) : null) : recordedSize ?? embeddedSize
  const explicitRole = firstString(meta.role) as CryptoRole
  const context = [itemType, row.name, row.protocol, meta.category, meta.detectionMethod].map(str).join(' ')
  const role = primitive.role ?? inferRole(primitive.name, context, explicitRole || undefined)
  const classification = classifyQuantum({ algorithm: primitive.name, role, keySize, hybridPartner: firstString(meta.hybridPartner, meta.hybrid_partner) || null })
  const verdict = contextOnly ? { ...classification, status: 'not-applicable' as const, quantumRelevant: false }
    : primitive.hybrid ? { ...classification, status: 'hybrid' as const, quantumRelevant: true } : classification

  const classicallyWeak = Boolean(canonical?.classicallyWeak) || undersizedKey(canonical, keySize)
  const detection = /potential|pattern|heuristic/i.test(str(meta.detectionMethod)) ? 'potential' : 'observed'
  const severity = severityFor({ quantum: verdict, classicallyWeak, role, detection, keySize: integerKeySize(canonical, keySize) })

  let actionability: Actionability
  if (contextOnly) actionability = 'context'
  else if (verdict.status === 'unknown') actionability = 'unclassified'
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
    componentKey: [primitive.hybrid?.toLowerCase() ?? canonical?.canonical ?? algorithm.toLowerCase(), keySize ?? '', role, packageName.toLowerCase()].join('|'),
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
  observedAtByAsset: Map<string, number>
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
    const observedAt = Date.parse(firstString(row.evidence_at, meta.observedAt, meta.observed_at, row.updated_at, row.created_at)) || 0
    if (existing) {
      if (assetId) {
        existing.assetIds.add(assetId)
        existing.observedAtByAsset.set(assetId, Math.max(existing.observedAtByAsset.get(assetId) ?? 0, observedAt))
      }
      existing.recordIds.push(str(row.id))
      continue
    }
    const algorithm = firstString(row.algorithm)
    const keySize = parseKeySize(str(row.key_size ?? '')) ?? null
    const primitive = observedPrimitive(algorithm)
    const canonical = describeAlgorithm(primitive.name)
    const classification = classifyQuantum({ algorithm: primitive.name, role: 'certificate', keySize })
    const verdict = primitive.hybrid ? { ...classification, status: 'hybrid' as const, quantumRelevant: true } : classification
    const classicallyWeak = Boolean(canonical?.classicallyWeak) || undersizedKey(canonical, keySize)
    const severity = severityFor({ quantum: verdict, classicallyWeak, role: 'certificate', detection: 'observed', keySize: integerKeySize(canonical, keySize) })
    const actionability: Actionability = verdict.status === 'unknown'
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
      observedAtByAsset: new Map(assetId ? [[assetId, observedAt]] : []),
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
