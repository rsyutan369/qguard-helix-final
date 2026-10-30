/**
 * PQAuth™ identity model — the ONE derivation behind the seven PQAuth pages.
 *
 * ── Why this module exists ─────────────────────────────────────────────────
 * The PQAuth dashboard used to build its "identity inventory" by regex-matching
 * the text of every crypto row. On live tenants that published:
 *
 *   • "Microsoft Entra ID" — from the substring "entra" (as in "central")
 *   • "F5 load balancer" × 306 — from the substring "f5" inside hex hashes
 *   • a trust graph whose edges were a fixed, hard-coded chain drawn whenever
 *     the category nodes existed
 *   • migration phases whose scores were `readiness - phaseIndex × 8`
 *   • "Authentication Failures = 78" — the tenant's critical-finding count
 *
 * The structured identity tables (supabase/pqauth-identity-schema.sql) and the
 * identity-discovery parser already existed but nothing wrote to or read from
 * them. This module reads ONLY those records plus the tenant's own assets,
 * certificates, migration jobs and runtime events, and every value it returns
 * can be traced to a row (and usually a URL).
 *
 * ── Rules every section follows ────────────────────────────────────────────
 *   1. Nothing is inferred from free text. Classification comes from the
 *      protocol fields the discovery parser stored (alg, kty, crv, use).
 *   2. Unmeasured is `null` / `not-verified`, never zero and never a pass.
 *   3. Signatures migrate to ML-DSA / SLH-DSA; key establishment to ML-KEM.
 *      A plan that targets ML-KEM for a signature workload is flagged.
 *   4. A migration is `validated` only when a discovery run AFTER the job
 *      completed observed the target posture. "Completed" alone is a claim.
 *   5. Simulations are labelled simulations and never touch observed state.
 *
 * Pure and dependency-light (no network, no database): exercised offline by
 * `tools/pqauth-identity-check.ts`.
 */

import {
  classifyJoseAlgorithm,
  classifySamlAlgorithm,
  type AlgorithmClassification,
} from '../scanner/identity/identity-discovery'
import { isSafePublicJwksUrl } from '../scanner/identity/identity-probe'
import { isSimulationRow } from '../migration/job-safety'
import type {
  EvidenceAge,
  IdentityQuantumClass,
  PQAuthActiveRun,
  PQAuthAdvertisedAlgorithm,
  PQAuthCompatCell,
  PQAuthCompatibilityModel,
  PQAuthCompatIssue,
  PQAuthCompatStatus,
  PQAuthDiscoveryHost,
  PQAuthDiscoveryModel,
  PQAuthDiscoveryRun,
  PQAuthDiscoveryStage,
  PQAuthEdgeConfidence,
  PQAuthGraphEdge,
  PQAuthGraphNode,
  PQAuthHostResult,
  PQAuthIdentityModel,
  PQAuthJobState,
  PQAuthMigrationGate,
  PQAuthMigrationJob,
  PQAuthMigrationModel,
  PQAuthNextAction,
  PQAuthProbeOutcome,
  PQAuthProbeRecord,
  PQAuthProvider,
  PQAuthScopeAsset,
  PQAuthSigningKey,
  PQAuthTokenModel,
  PQAuthTokenProjection,
  PQAuthTwinModel,
  PQAuthTwinScenario,
} from '../../types/pqauth-dashboard'

/* ================================================================== */
/* Inputs                                                              */
/* ================================================================== */

type Row = Record<string, any>

export interface IdentityModelInput {
  /** Injected so the check tool is deterministic. */
  now?: number
  assets: Row[]
  providers: Row[]
  signingKeys: Row[]
  trustRelationships: Row[]
  probes: Row[]
  assetRelationships: Row[]
  certificates: Row[]
  migrationJobs: Row[]
  runtimeEvents: Row[]
  activeRun: PQAuthActiveRun | null
}

/** Discovery evidence older than this is stale. */
export const IDENTITY_STALE_AFTER_MS = 7 * 24 * 60 * 60 * 1000
const RUNTIME_RECENT_MS = 24 * 60 * 60 * 1000

/* ================================================================== */
/* Published sizes (bytes). Sources: FIPS 204 Table 2, FIPS 205        */
/* Table 2, FIPS 203 Table 3, RFC 7518 / RFC 8037.                      */
/* ================================================================== */

export const PQC_SIZES = {
  'ML-DSA-44': { signature: 2420, publicKey: 1312, standard: 'FIPS 204' },
  'ML-DSA-65': { signature: 3309, publicKey: 1952, standard: 'FIPS 204' },
  'ML-DSA-87': { signature: 4627, publicKey: 2592, standard: 'FIPS 204' },
  'SLH-DSA-SHA2-128s': { signature: 7856, publicKey: 32, standard: 'FIPS 205' },
} as const

export const ML_KEM_768 = { encapsulationKey: 1184, ciphertext: 1088, standard: 'FIPS 203' } as const

/** Length of the unpadded base64url encoding of `bytes` bytes (JWS segments). */
export function base64urlLength(bytes: number): number {
  return Math.ceil((bytes * 4) / 3)
}

const EC_SIGNATURE_BYTES: Record<string, number> = { 'P-256': 64, secp256k1: 64, 'P-384': 96, 'P-521': 132, Ed25519: 64, Ed448: 114 }
const EC_PUBLIC_KEY_BYTES: Record<string, number> = { 'P-256': 64, secp256k1: 64, 'P-384': 96, 'P-521': 132, Ed25519: 32, Ed448: 57 }

/**
 * Raw signature size of a classical or PQC signing key. null when the size is
 * genuinely unknown (an RSA key whose modulus was not published, an
 * unrecognised algorithm) — never a guessed default.
 */
export function signatureBytesFor(algorithm: string | null, keyType: string | null, keySize: number | null, curve: string | null): number | null {
  const alg = String(algorithm ?? '').trim().toUpperCase()
  const kty = String(keyType ?? '').trim().toUpperCase()
  const pqc = alg.match(/^ML-?DSA-?(44|65|87)$/)
  if (pqc) return PQC_SIZES[`ML-DSA-${pqc[1]}` as keyof typeof PQC_SIZES].signature
  if (/^(RS|PS)(256|384|512)$/.test(alg) || (!alg && kty === 'RSA')) return keySize && keySize > 0 ? Math.round(keySize / 8) : null
  if (alg === 'ES256' || alg === 'ES256K') return 64
  if (alg === 'ES384') return 96
  if (alg === 'ES512') return 132
  if (alg === 'EDDSA' || ((!alg || alg === 'EDDSA') && (kty === 'OKP' || kty === 'EC'))) {
    return curve && EC_SIGNATURE_BYTES[curve] ? EC_SIGNATURE_BYTES[curve] : null
  }
  return null
}

function publicKeyBytesFor(keyType: string | null, keySize: number | null, curve: string | null): number | null {
  const kty = String(keyType ?? '').toUpperCase()
  if (kty === 'RSA') return keySize && keySize > 0 ? Math.round(keySize / 8) : null
  if (curve && EC_PUBLIC_KEY_BYTES[curve]) return EC_PUBLIC_KEY_BYTES[curve]
  return null
}

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

const text = (value: unknown): string => (typeof value === 'string' ? value.trim() : value == null ? '' : String(value).trim())
const textOrNull = (value: unknown): string | null => text(value) || null
const strArray = (value: unknown): string[] => (Array.isArray(value) ? value.map((v) => text(v)).filter(Boolean) : [])
const numOrNull = (value: unknown): number | null => {
  const n = Number(value)
  return value === null || value === undefined || value === '' || !Number.isFinite(n) ? null : n
}
const ms = (value: unknown): number => {
  const t = Date.parse(text(value))
  return Number.isFinite(t) ? t : 0
}
const latestIso = (values: unknown[]): string | null => {
  const best = values.map(ms).filter(Boolean).sort((a, b) => b - a)[0]
  return best ? new Date(best).toISOString() : null
}
const recordOf = (value: unknown): Row => {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value as Row
  if (typeof value === 'string' && value.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
    } catch {
      return {}
    }
  }
  return {}
}
const hostOfUrl = (url: string): string | null => {
  try {
    return new URL(url).hostname.toLowerCase() || null
  } catch {
    return null
  }
}
const QUANTUM_CLASSES: IdentityQuantumClass[] = ['safe', 'hybrid', 'vulnerable', 'unknown']
const asClass = (value: unknown): IdentityQuantumClass => {
  const v = text(value).toLowerCase() as IdentityQuantumClass
  return QUANTUM_CLASSES.includes(v) ? v : 'unknown'
}
const shortKid = (kid: string) => (kid.length > 22 ? `${kid.slice(0, 10)}…${kid.slice(-8)}` : kid)
const plural = (n: number, word: string, many = `${word}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? word : many}`

/* ================================================================== */
/* Probe targets — which assets may be probed, and why not             */
/* ================================================================== */

const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i

function hostFromCandidate(candidate: unknown): string | null {
  const value = text(candidate)
  if (!value || value === 'null') return null
  if (value.includes('://')) {
    try {
      const host = new URL(value).hostname.toLowerCase()
      return host || null
    } catch {
      return null
    }
  }
  const bare = value.replace(/\/.*$/, '').replace(/:\d+$/, '').toLowerCase()
  return bare || null
}

/**
 * The host identity discovery may probe for an asset.
 *
 * The tenant's explicit `authorized_target` wins — it is the target the tenant
 * authorized the scanner to reach. Every candidate must also pass the SSRF
 * destination guard: IP literals, loopback, private and internal-TLD hosts are
 * refused, which is reported as an explicit "unsupported" reason rather than
 * silently skipped.
 */
export function assetProbeTarget(asset: Row): { host: string | null; eligible: boolean; reason: string } {
  const metadata = recordOf(asset.metadata)
  const candidates: Array<[unknown, string]> = [
    [metadata.authorized_target, 'Authorized scan target'],
    [metadata.host, 'Asset host'],
    [metadata.hostname, 'Asset host'],
    [metadata.domain, 'Asset domain'],
    [metadata.url, 'Asset URL'],
    [asset.name, 'Asset name'],
  ]
  let sawCandidate: string | null = null
  for (const [candidate, label] of candidates) {
    const host = hostFromCandidate(candidate)
    if (!host) continue
    sawCandidate = sawCandidate ?? host
    if (!HOSTNAME_RE.test(host)) continue
    if (!isSafePublicJwksUrl(`https://${host}/`)) {
      return { host, eligible: false, reason: `${host} is an internal or reserved host — refused by the SSRF guard` }
    }
    return { host, eligible: true, reason: `${label}: ${host}` }
  }
  if (sawCandidate) {
    return {
      host: sawCandidate,
      eligible: false,
      reason: /^\d{1,3}(\.\d{1,3}){3}$|:/.test(sawCandidate)
        ? 'IP-literal targets are not probed — identity metadata is published on named hosts'
        : `"${sawCandidate}" is not a public hostname`,
    }
  }
  return { host: null, eligible: false, reason: 'No hostname is recorded for this asset' }
}

/* ================================================================== */
/* Providers and keys                                                  */
/* ================================================================== */

function ageOf(iso: string | null, now: number): EvidenceAge {
  const t = ms(iso)
  if (!t) return 'never'
  return now - t > IDENTITY_STALE_AFTER_MS ? 'stale' : 'fresh'
}

function buildKeys(rows: Row[], providerLabel: Map<string, string>): PQAuthSigningKey[] {
  // A key absent from its provider's most recent JWKS read has been rotated out.
  const newestByProvider = new Map<string, number>()
  for (const row of rows) {
    const pid = text(row.provider_id)
    newestByProvider.set(pid, Math.max(newestByProvider.get(pid) ?? 0, ms(row.last_seen_at)))
  }
  return rows.map((row) => {
    const providerId = text(row.provider_id)
    const algorithm = textOrNull(row.algorithm)
    const keyType = text(row.key_type) || 'unknown'
    const keySize = numOrNull(row.key_size)
    const curve = textOrNull(row.curve)
    const use = text(row.key_use) || 'unspecified'
    const lastSeen = ms(row.last_seen_at)
    const newest = newestByProvider.get(providerId) ?? 0
    const display = algorithm
      || (keyType === 'RSA' ? (keySize ? `RSA-${keySize}` : 'RSA')
        : keyType === 'OKP' ? `EdDSA ${curve ?? ''}`.trim()
          : keyType === 'EC' ? `ECDSA ${curve ?? ''}`.trim()
            : keyType)
    return {
      id: text(row.id),
      providerId,
      providerLabel: providerLabel.get(providerId) ?? 'Unknown provider',
      keyId: shortKid(text(row.key_id) || text(row.id)),
      keyType,
      algorithm,
      displayAlgorithm: display,
      use,
      keySize,
      curve,
      quantumClass: asClass(row.quantum_class),
      purpose: text(row.crypto_purpose) || 'unknown',
      pqcTarget: textOrNull(row.pqc_target),
      standard: textOrNull(row.standard),
      rationale: textOrNull(row.rationale),
      sourceUrl: textOrNull(row.source_url),
      firstSeenAt: textOrNull(row.first_seen_at),
      lastSeenAt: textOrNull(row.last_seen_at),
      lifecycle: newest && lastSeen && newest - lastSeen > 60_000 ? 'no-longer-published' : 'published',
      signatureBytes: use === 'encryption' ? null : signatureBytesFor(algorithm, keyType, keySize, curve),
    }
  })
}

function buildProviders(rows: Row[], keys: PQAuthSigningKey[], trust: Row[], assetName: Map<string, string>, now: number): PQAuthProvider[] {
  return rows.map((row) => {
    const id = text(row.id)
    const own = keys.filter((key) => key.providerId === id)
    const published = own.filter((key) => key.lifecycle === 'published')
    const assetId = textOrNull(row.asset_id)
    const endpoints = (Array.isArray(row.endpoints) ? row.endpoints : []).map((e: Row) => ({
      kind: text(e.kind) || 'endpoint',
      url: text(e.url),
      insecureTransport: Boolean(e.insecureTransport ?? e.insecure_transport ?? !/^https:\/\//i.test(text(e.url))),
    })).filter((e: { url: string }) => e.url)
    const dependents = Array.from(new Set(
      trust
        .filter((rel) => text(rel.target_provider_id) === id && text(rel.source_asset_id))
        .map((rel) => text(rel.source_asset_id)),
    ))
    const lastSeenAt = textOrNull(row.last_seen_at)
    return {
      id,
      issuer: text(row.issuer),
      protocol: text(row.protocol) || 'oidc',
      displayName: text(row.display_name) || text(row.host) || text(row.issuer),
      vendor: textOrNull(row.vendor),
      host: textOrNull(row.host),
      assetId,
      assetName: assetId ? assetName.get(assetId) ?? null : null,
      quantumClass: asClass(row.quantum_class),
      signingAlgorithmsSupported: strArray(row.signing_algorithms_supported),
      keyEncryptionAlgorithmsSupported: strArray(row.key_encryption_algorithms_supported),
      contentEncryptionAlgorithmsSupported: strArray(row.content_encryption_algorithms_supported),
      grantTypesSupported: strArray(row.grant_types_supported),
      endpoints,
      jwksUri: textOrNull(row.jwks_uri),
      keyCount: own.length,
      publishedKeyCount: published.length,
      vulnerableKeyCount: published.filter((key) => key.use !== 'encryption' && key.quantumClass === 'vulnerable').length,
      sourceUrl: textOrNull(row.source_url),
      discoveryMethod: textOrNull(row.discovery_method),
      firstSeenAt: textOrNull(row.first_seen_at),
      lastSeenAt,
      age: ageOf(lastSeenAt, now),
      dependentAssetIds: dependents,
    }
  }).sort((a, b) => a.issuer.localeCompare(b.issuer))
}

/* ================================================================== */
/* Discovery                                                           */
/* ================================================================== */

const PROBE_OUTCOMES: PQAuthProbeOutcome[] = ['found', 'not-found', 'unparseable', 'error']

function probeRecord(row: Row): PQAuthProbeRecord {
  const outcome = text(row.outcome) as PQAuthProbeOutcome
  return {
    id: text(row.id),
    url: text(row.probe_url),
    method: text(row.method),
    httpStatus: numOrNull(row.http_status),
    outcome: PROBE_OUTCOMES.includes(outcome) ? outcome : 'error',
    detail: textOrNull(row.detail),
    observedAt: textOrNull(row.observed_at) ?? textOrNull(row.created_at),
  }
}

/**
 * Verdict for one host from one run. JWKS probes are excluded from the verdict:
 * they live on whatever host the discovery document names, and only run after a
 * document was found.
 */
export function classifyHostRun(probes: PQAuthProbeRecord[]): { result: PQAuthHostResult; explanation: string } {
  const wellKnown = probes.filter((p) => p.method !== 'jwks')
  if (!wellKnown.length) return { result: 'failed', explanation: 'No well-known identity endpoint was probed on this host.' }
  const found = wellKnown.filter((p) => p.outcome === 'found')
  const errors = wellKnown.filter((p) => p.outcome === 'error')
  const unparseable = wellKnown.filter((p) => p.outcome === 'unparseable')
  const notFound = wellKnown.filter((p) => p.outcome === 'not-found')
  const jwks = probes.filter((p) => p.method === 'jwks')
  const jwksFailed = jwks.filter((p) => p.outcome !== 'found')

  if (found.length) {
    if (jwksFailed.length) {
      return {
        result: 'incomplete',
        explanation: `Identity metadata found at ${plural(found.length, 'endpoint')}, but the signing-key set (JWKS) could not be read: ${jwksFailed[0].detail || `HTTP ${jwksFailed[0].httpStatus ?? 'no response'}`}. Token-signing posture is unverified until it is.`,
      }
    }
    return { result: 'identity-found', explanation: `Identity metadata parsed from ${plural(found.length, 'well-known endpoint')}.` }
  }
  if (errors.length === wellKnown.length) {
    return {
      result: 'failed',
      explanation: /tls|certificate/i.test(errors[0].detail || '')
        ? `No probe could establish a trusted HTTPS connection (${errors[0].detail}). Clients cannot reach any identity metadata here either — fix the host's TLS certificate, then re-run discovery.`
        : `No probe reached the host (${errors[0].detail || 'network error'}). Check that the host is reachable over HTTPS from the scanner, then re-run discovery.`,
    }
  }
  if (errors.length) {
    return {
      result: 'incomplete',
      explanation: `${plural(errors.length, 'probe')} failed (${errors[0].detail || 'network error'}), so absence of identity metadata is not proven. Re-run discovery to complete the check.`,
    }
  }
  // 401/403: the host answered but refused. That is not proof of absence.
  const isDenied = (p: PQAuthProbeRecord) => /^access denied/i.test(p.detail || '')
  const isHtml = (p: PQAuthProbeRecord) => /html/i.test(p.detail || '')
  const denied = unparseable.filter(isDenied)
  const html = unparseable.filter(isHtml)
  const primaryDenied = denied.filter((p) => p.method === 'oidc-discovery' || p.method === 'oauth-as-metadata')
  if (primaryDenied.length) {
    return {
      result: 'incomplete',
      explanation: `${primaryDenied[0].url} refused access (${primaryDenied[0].detail}). A WAF or access policy blocked the OIDC / OAuth metadata probe, so whether this host is an identity provider is not determined. Allow the scanner's requests, or confirm manually.`,
    }
  }
  const odd = unparseable.find((p) => !isDenied(p) && !isHtml(p))
  if (odd) {
    return {
      result: 'incomplete',
      explanation: `${odd.url} answered but was not valid identity metadata (${odd.detail || 'unparseable'}). A misconfigured provider may be publishing a malformed document.`,
    }
  }
  const parts = [
    plural(notFound.length, 'not-found response'),
    ...(html.length ? [`${plural(html.length, 'HTML page')} instead of a metadata document`] : []),
    ...(denied.length ? [`${plural(denied.length, 'SAML path')} refused access`] : []),
  ]
  return {
    result: 'no-identity',
    explanation: `All ${plural(wellKnown.length, 'standard identity path')} answered without identity metadata (${parts.join(', ')}). No OIDC or OAuth 2.0 metadata is published at the standard locations${denied.length ? '; a protected SAML endpoint behind the refused path cannot be ruled out' : ', and no SAML metadata at the common ones'}.`,
  }
}

function buildDiscovery(input: IdentityModelInput, providers: PQAuthProvider[], keys: PQAuthSigningKey[], now: number): PQAuthDiscoveryModel {
  const assetsById = new Map(input.assets.map((a) => [text(a.id), a]))
  const probes = input.probes.map((row) => ({ row, record: probeRecord(row) }))

  // Runs, newest first.
  const runMap = new Map<string, PQAuthProbeRecord[]>()
  const runHosts = new Map<string, Set<string>>()
  for (const { row, record } of probes) {
    const runId = text(row.scan_session_id) || `legacy:${text(row.asset_id) || 'unknown'}`
    if (!runMap.has(runId)) runMap.set(runId, [])
    runMap.get(runId)!.push(record)
    if (!runHosts.has(runId)) runHosts.set(runId, new Set())
    if (record.method !== 'jwks') runHosts.get(runId)!.add(hostOfUrl(record.url) ?? record.url)
  }
  const runs: PQAuthDiscoveryRun[] = Array.from(runMap.entries()).map(([runId, records]) => ({
    runId,
    startedAt: records.map((r) => r.observedAt).filter(Boolean).sort()[0] ?? null,
    finishedAt: latestIso(records.map((r) => r.observedAt)),
    hosts: runHosts.get(runId)?.size ?? 0,
    probes: records.length,
    found: records.filter((r) => r.outcome === 'found').length,
    notFound: records.filter((r) => r.outcome === 'not-found').length,
    unparseable: records.filter((r) => r.outcome === 'unparseable').length,
    errors: records.filter((r) => r.outcome === 'error').length,
  })).sort((a, b) => ms(b.finishedAt) - ms(a.finishedAt))

  // Latest run per probed asset/host.
  const groups = new Map<string, { assetId: string | null; runId: string; records: PQAuthProbeRecord[] }>()
  for (const { row, record } of probes) {
    const assetId = textOrNull(row.asset_id)
    const runId = text(row.scan_session_id) || 'legacy'
    const key = `${assetId ?? hostOfUrl(record.url)}::${runId}`
    if (!groups.has(key)) groups.set(key, { assetId, runId, records: [] })
    groups.get(key)!.records.push(record)
  }
  const latestByTarget = new Map<string, { assetId: string | null; runId: string; records: PQAuthProbeRecord[] }>()
  for (const group of groups.values()) {
    const target = group.assetId ?? hostOfUrl(group.records.find((r) => r.method !== 'jwks')?.url ?? '') ?? 'unknown'
    const current = latestByTarget.get(target)
    const groupAt = ms(latestIso(group.records.map((r) => r.observedAt)))
    if (!current || groupAt > ms(latestIso(current.records.map((r) => r.observedAt)))) latestByTarget.set(target, group)
  }
  const hosts: PQAuthDiscoveryHost[] = Array.from(latestByTarget.values()).map((group) => {
    const verdict = classifyHostRun(group.records)
    const wellKnownUrl = group.records.find((r) => r.method !== 'jwks')?.url ?? group.records[0]?.url ?? ''
    const asset = group.assetId ? assetsById.get(group.assetId) : undefined
    const providerIds = providers
      .filter((p) => (group.assetId && (p.assetId === group.assetId || p.dependentAssetIds.includes(group.assetId))))
      .map((p) => p.id)
    return {
      host: hostOfUrl(wellKnownUrl) ?? wellKnownUrl,
      assetId: group.assetId,
      assetName: asset ? text(asset.name) : null,
      runId: group.runId,
      lastProbedAt: latestIso(group.records.map((r) => r.observedAt)),
      result: verdict.result,
      explanation: verdict.explanation,
      probes: group.records.sort((a, b) => a.method.localeCompare(b.method)),
      providerIds,
    }
  }).sort((a, b) => ms(b.lastProbedAt) - ms(a.lastProbedAt))

  const lastProbedByAsset = new Map(hosts.filter((h) => h.assetId).map((h) => [h.assetId!, h.lastProbedAt]))
  const scope: PQAuthScopeAsset[] = input.assets.map((asset) => {
    const target = assetProbeTarget(asset)
    const id = text(asset.id)
    return {
      assetId: id,
      name: text(asset.name) || id,
      type: textOrNull(asset.type),
      host: target.host,
      eligible: target.eligible,
      reason: target.reason,
      lastProbedAt: lastProbedByAsset.get(id) ?? null,
    }
  }).sort((a, b) => Number(b.eligible) - Number(a.eligible) || a.name.localeCompare(b.name))

  const latestRun = runs[0]
  const eligible = scope.filter((s) => s.eligible).length
  const providersWithJwks = providers.filter((p) => p.jwksUri)
  const jwksMissing = providersWithJwks.filter((p) => p.keyCount === 0).length
  const classified = keys.filter((k) => k.quantumClass !== 'unknown').length
  const linked = providers.filter((p) => p.assetId || p.dependentAssetIds.length).length
  const stages: PQAuthDiscoveryStage[] = [
    {
      id: 'scope', label: 'Scope', description: 'Tenant assets with a public hostname the tenant authorized for scanning.',
      count: eligible, status: eligible ? 'complete' : 'attention',
    },
    {
      id: 'probe', label: 'Probe well-known endpoints', description: 'OIDC discovery, RFC 8414 OAuth metadata and SAML metadata at their standard paths.',
      count: latestRun?.probes ?? 0, status: !latestRun ? 'not-started' : latestRun.errors ? 'attention' : 'complete',
    },
    {
      id: 'parse', label: 'Parse identity metadata', description: 'A provider is recorded only when its document states an issuer / entityID.',
      count: providers.length, status: !latestRun ? 'not-started' : hosts.some((h) => h.result === 'incomplete') ? 'attention' : 'complete',
    },
    {
      id: 'jwks', label: 'Read signing keys (JWKS)', description: 'Only the jwks_uri the document names is fetched, behind the SSRF guard.',
      count: keys.length, status: !providers.length ? 'not-started' : jwksMissing ? 'attention' : 'complete',
    },
    {
      id: 'classify', label: 'Classify quantum posture', description: 'Each key classified from its published alg / kty / crv — signatures to ML-DSA, key transport to ML-KEM.',
      count: classified, status: !keys.length ? (providers.length ? 'pending' : 'not-started') : 'complete',
    },
    {
      id: 'link', label: 'Link to assets & trust', description: 'Providers tied to the asset they were discovered on and the assets that declare trust in them.',
      count: linked, status: !providers.length ? 'not-started' : linked === providers.length ? 'complete' : 'attention',
    },
  ]
  void now
  return {
    scope,
    runs: runs.slice(0, 12),
    hosts,
    activeRun: input.activeRun,
    lastRunAt: latestRun?.finishedAt ?? null,
    stages,
  }
}

/* ================================================================== */
/* Trust graph — real edges only                                       */
/* ================================================================== */

function certificateClass(cert: Row): IdentityQuantumClass {
  if (cert.is_quantum_safe === true) return 'safe'
  const alg = text(cert.algorithm).toLowerCase()
  if (/ml-dsa|slh-dsa|dilithium|sphincs|falcon/.test(alg)) return /rsa|ecdsa|ed25519/.test(alg) ? 'hybrid' : 'safe'
  if (/rsa|ecdsa|\bec\b|ecc|ed25519|ed448|dsa/.test(alg)) return 'vulnerable'
  return 'unknown'
}

function buildGraph(input: IdentityModelInput, providers: PQAuthProvider[], keys: PQAuthSigningKey[]): { nodes: PQAuthGraphNode[]; edges: PQAuthGraphEdge[] } {
  const nodes = new Map<string, PQAuthGraphNode>()
  const edges: PQAuthGraphEdge[] = []
  const assetsById = new Map(input.assets.map((a) => [text(a.id), a]))

  const addAsset = (assetId: string): string => {
    const id = `asset:${assetId}`
    if (nodes.has(id)) return id
    const asset = assetsById.get(assetId)
    nodes.set(id, {
      id,
      kind: 'asset',
      label: asset ? text(asset.name) || assetId : 'Unresolved asset',
      sublabel: asset ? text(asset.type) || 'asset' : 'Not in the asset inventory',
      status: 'unknown',
      refId: assetId,
      assetId,
      sourceTable: 'assets',
      sourceUrl: null,
      lastSeenAt: asset ? textOrNull(asset.updated_at) : null,
    })
    return id
  }

  for (const provider of providers) {
    nodes.set(`provider:${provider.id}`, {
      id: `provider:${provider.id}`,
      kind: 'provider',
      label: provider.vendor ? `${provider.vendor}` : provider.displayName,
      sublabel: `${provider.protocol.toUpperCase()} · ${provider.issuer}`,
      status: provider.quantumClass,
      refId: provider.id,
      assetId: provider.assetId,
      sourceTable: 'identity_providers',
      sourceUrl: provider.sourceUrl,
      lastSeenAt: provider.lastSeenAt,
    })
  }

  for (const key of keys) {
    if (!nodes.has(`provider:${key.providerId}`)) continue
    const id = `key:${key.id}`
    nodes.set(id, {
      id,
      kind: 'key',
      label: key.displayAlgorithm,
      sublabel: `kid ${key.keyId}${key.lifecycle === 'no-longer-published' ? ' · rotated out' : ''}`,
      status: key.quantumClass,
      refId: key.id,
      assetId: null,
      sourceTable: 'identity_signing_keys',
      sourceUrl: key.sourceUrl,
      lastSeenAt: key.lastSeenAt,
    })
    edges.push({
      id: `edge:key:${key.id}`,
      from: `provider:${key.providerId}`,
      to: id,
      type: key.use === 'encryption' ? 'ENCRYPTS_WITH' : 'SIGNS_WITH',
      label: key.use === 'encryption' ? 'encrypts with' : 'signs tokens with',
      confidence: 'observed',
      evidence: `Published in the provider's JWKS (${key.keyType}${key.algorithm ? `, alg ${key.algorithm}` : ', no alg stated'}).`,
      sourceTable: 'identity_signing_keys',
      sourceUrl: key.sourceUrl,
      lastSeenAt: key.lastSeenAt,
    })
  }

  // Recorded identity trust relationships.
  const declaredPairs = new Set<string>()
  for (const rel of input.trustRelationships) {
    const resolve = (providerId: unknown, assetId: unknown): { id: string; resolved: boolean } | null => {
      const pid = text(providerId)
      const aid = text(assetId)
      if (pid) return nodes.has(`provider:${pid}`) ? { id: `provider:${pid}`, resolved: true } : null
      if (aid) {
        const known = assetsById.has(aid)
        return { id: addAsset(aid), resolved: known }
      }
      return null
    }
    const from = resolve(rel.source_provider_id, rel.source_asset_id)
    const to = resolve(rel.target_provider_id, rel.target_asset_id)
    if (!from || !to) continue
    const stated = text(rel.confidence).toLowerCase() as PQAuthEdgeConfidence
    const confidence: PQAuthEdgeConfidence = !from.resolved || !to.resolved
      ? 'unresolved'
      : (['observed', 'declared', 'inferred'] as PQAuthEdgeConfidence[]).includes(stated) ? stated : 'inferred'
    declaredPairs.add(`${from.id}|${to.id}`)
    declaredPairs.add(`${to.id}|${from.id}`)
    const type = text(rel.relationship_type).toUpperCase() || 'TRUSTS'
    edges.push({
      id: `edge:rel:${text(rel.id)}`,
      from: from.id,
      to: to.id,
      type,
      label: type.toLowerCase().replace(/_/g, ' '),
      confidence,
      evidence: text(rel.evidence) || 'Recorded identity trust relationship (no evidence text stored).',
      sourceTable: 'identity_trust_relationships',
      sourceUrl: textOrNull(rel.source_url),
      lastSeenAt: textOrNull(rel.last_seen_at),
    })
  }

  // Provider ↔ the asset it was discovered on (foreign key), unless a trust
  // relationship already describes that pair.
  for (const provider of providers) {
    if (!provider.assetId) continue
    const assetNode = addAsset(provider.assetId)
    const providerNode = `provider:${provider.id}`
    if (declaredPairs.has(`${assetNode}|${providerNode}`)) continue
    edges.push({
      id: `edge:host:${provider.id}`,
      from: assetNode,
      to: providerNode,
      type: 'PUBLISHES',
      label: 'publishes identity metadata',
      confidence: 'observed',
      evidence: `Identity metadata for ${provider.issuer} was read from this asset (${provider.discoveryMethod || 'discovery'}).`,
      sourceTable: 'identity_providers',
      sourceUrl: provider.sourceUrl,
      lastSeenAt: provider.lastSeenAt,
    })
  }

  const identityAssets = new Set(Array.from(nodes.values()).filter((n) => n.kind === 'asset').map((n) => n.refId))

  // Certificates presented by identity assets (certificates.asset_id).
  const certsByAsset = new Map<string, Row[]>()
  for (const cert of input.certificates) {
    const aid = text(cert.asset_id)
    if (!identityAssets.has(aid)) continue
    if (!certsByAsset.has(aid)) certsByAsset.set(aid, [])
    certsByAsset.get(aid)!.push(cert)
  }
  for (const [aid, certs] of certsByAsset) {
    for (const cert of certs.sort((a, b) => ms(b.updated_at) - ms(a.updated_at)).slice(0, 3)) {
      const id = `certificate:${text(cert.id)}`
      nodes.set(id, {
        id,
        kind: 'certificate',
        label: text(cert.algorithm) ? `${text(cert.algorithm)}${numOrNull(cert.key_size) ? `-${cert.key_size}` : ''}` : 'Certificate',
        sublabel: text(cert.subject) || text(cert.name) || 'X.509 certificate',
        status: certificateClass(cert),
        refId: text(cert.id),
        assetId: aid,
        sourceTable: 'certificates',
        sourceUrl: null,
        lastSeenAt: textOrNull(cert.updated_at),
      })
      edges.push({
        id: `edge:cert:${text(cert.id)}`,
        from: `asset:${aid}`,
        to: id,
        type: 'PRESENTS',
        label: 'presents certificate',
        confidence: 'observed',
        evidence: `Certificate recorded for this asset${text(cert.issuer) ? `, issued by ${text(cert.issuer)}` : ''}.`,
        sourceTable: 'certificates',
        sourceUrl: null,
        lastSeenAt: textOrNull(cert.updated_at),
      })
    }
  }

  // Generic asset relationships, only between assets already in the identity graph.
  for (const rel of input.assetRelationships) {
    const s = text(rel.source_asset_id)
    const t = text(rel.target_asset_id)
    if (!identityAssets.has(s) || !identityAssets.has(t)) continue
    const metadata = recordOf(rel.metadata)
    const stated = text(metadata.confidence).toLowerCase() as PQAuthEdgeConfidence
    const type = text(rel.relationship_type).toUpperCase() || 'DEPENDS_ON'
    edges.push({
      id: `edge:asset-rel:${text(rel.id)}`,
      from: `asset:${s}`,
      to: `asset:${t}`,
      type,
      label: type.toLowerCase().replace(/_/g, ' '),
      confidence: (['observed', 'declared'] as PQAuthEdgeConfidence[]).includes(stated) ? stated : 'inferred',
      evidence: text(metadata.evidence) || 'Asset dependency recorded in the asset inventory; how it was established is not stored.',
      sourceTable: 'asset_relationships',
      sourceUrl: null,
      lastSeenAt: textOrNull(rel.created_at),
    })
  }

  return { nodes: Array.from(nodes.values()), edges }
}

/* ================================================================== */
/* Tokens                                                              */
/* ================================================================== */

function classifyAdvertised(alg: string, protocol: string, role: 'signing' | 'key-management' | 'content-encryption'): AlgorithmClassification {
  if (protocol === 'saml2') return classifySamlAlgorithm(alg)
  return classifyJoseAlgorithm(alg, role === 'signing' ? 'signature' : role === 'key-management' ? 'key-encapsulation' : 'symmetric')
}

const isPqcSignature = (alg: string) => /^ML-?DSA|^SLH-?DSA|DILITHIUM|SPHINCS/i.test(alg)

function pqcTargetName(target: string | null): keyof typeof PQC_SIZES {
  const match = String(target ?? '').match(/ML-DSA-(44|65|87)/i)
  return (match ? `ML-DSA-${match[1]}` : 'ML-DSA-65') as keyof typeof PQC_SIZES
}

const TOKEN_OPERATION_RE = /jwt|jws|jwe|token|assertion|introspect|sign|verify/i

function buildTokens(input: IdentityModelInput, providers: PQAuthProvider[], keys: PQAuthSigningKey[]): PQAuthTokenModel {
  const advertised: PQAuthAdvertisedAlgorithm[] = []
  for (const provider of providers) {
    const label = provider.vendor || provider.displayName
    const push = (alg: string, role: 'signing' | 'key-management' | 'content-encryption') => {
      const c = classifyAdvertised(alg, provider.protocol, role)
      advertised.push({ providerId: provider.id, providerLabel: label, algorithm: alg, role, quantumClass: c.quantumClass, pqcTarget: c.pqcTarget })
    }
    provider.signingAlgorithmsSupported.forEach((alg) => push(alg, 'signing'))
    provider.keyEncryptionAlgorithmsSupported.forEach((alg) => push(alg, 'key-management'))
    provider.contentEncryptionAlgorithmsSupported.forEach((alg) => push(alg, 'content-encryption'))
  }

  const conflicts: PQAuthTokenModel['conflicts'] = []
  for (const provider of providers) {
    const label = provider.vendor || provider.displayName
    const published = keys.filter((k) => k.providerId === provider.id && k.lifecycle === 'published' && k.use !== 'encryption')
    const advertisesPqc = provider.signingAlgorithmsSupported.some(isPqcSignature)
    if (advertisesPqc && published.length && !published.some((k) => k.quantumClass === 'safe' || k.quantumClass === 'hybrid')) {
      conflicts.push({ providerId: provider.id, providerLabel: label, detail: 'Advertises a post-quantum signing algorithm, but every key in its JWKS is classical — tokens are still signed classically.' })
    }
    if (provider.signingAlgorithmsSupported.some((alg) => alg.toLowerCase() === 'none')) {
      conflicts.push({ providerId: provider.id, providerLabel: label, detail: 'Advertises alg "none": unsigned tokens may be accepted. This is a critical flaw independent of any quantum threat.' })
    }
  }

  const tokenEvents = input.runtimeEvents.filter((row) => TOKEN_OPERATION_RE.test(`${text(row.event_type)} ${text(row.operation_type)}`))
  const byAlg = new Map<string, number>()
  for (const row of tokenEvents) {
    const alg = text(row.algorithm) || 'unstated'
    byAlg.set(alg, (byAlg.get(alg) ?? 0) + 1)
  }
  const runtime = {
    measured: input.runtimeEvents.length > 0,
    operations: tokenEvents.length,
    byAlgorithm: Array.from(byAlg.entries()).map(([algorithm, count]) => ({
      algorithm,
      count,
      quantumClass: algorithm === 'unstated' ? 'unknown' as IdentityQuantumClass : classifyJoseAlgorithm(algorithm, 'signature').quantumClass,
    })).sort((a, b) => b.count - a.count),
    latestAt: latestIso(tokenEvents.map((row) => row.observed_at ?? row.created_at)),
  }

  const projections: PQAuthTokenProjection[] = keys
    .filter((k) => k.lifecycle === 'published' && k.use !== 'encryption' && k.quantumClass === 'vulnerable' && k.signatureBytes)
    .map((k) => {
      const target = pqcTargetName(k.pqcTarget)
      const targetBytes = PQC_SIZES[target].signature
      const current = k.signatureBytes as number
      return {
        keyRef: k.id,
        providerLabel: k.providerLabel,
        currentAlgorithm: k.displayAlgorithm,
        currentSignatureBytes: current,
        targetAlgorithm: target,
        targetSignatureBytes: targetBytes,
        encodedDeltaBytes: base64urlLength(targetBytes) - base64urlLength(current),
        expansion: Number((targetBytes / current).toFixed(1)),
      }
    })

  return { keys, advertised, conflicts, runtime, projections }
}

/* ================================================================== */
/* Compatibility                                                       */
/* ================================================================== */

const COMPAT_DIMENSIONS = [
  { id: 'token-signing', label: 'Token signing keys', description: 'Keys actually published in the provider JWKS — what signs its tokens today.' },
  { id: 'advertised-signing', label: 'Advertised signing algorithms', description: 'Signing algorithms the discovery document says the provider supports.' },
  { id: 'token-encryption', label: 'Encrypted tokens (JWE)', description: 'Key-management algorithms advertised for encrypted tokens — where ML-KEM applies.' },
  { id: 'transport', label: 'Endpoint transport', description: 'Whether every published endpoint uses HTTPS. TLS key exchange is assessed by the TLS scanner, not here.' },
  { id: 'host-certificate', label: 'Host certificate', description: 'Certificates recorded for the asset that serves the provider metadata.' },
] as const

function emptyCounts(): Record<PQAuthCompatStatus, number> {
  return { supported: 0, conditional: 0, unsupported: 0, 'not-verified': 0, 'not-applicable': 0 }
}

function buildCompatibility(input: IdentityModelInput, providers: PQAuthProvider[], keys: PQAuthSigningKey[]): PQAuthCompatibilityModel {
  const rows: PQAuthCompatibilityModel['rows'] = []
  const issues: PQAuthCompatIssue[] = []
  const counts = emptyCounts()

  for (const provider of providers) {
    const label = provider.vendor ? `${provider.vendor} (${provider.host ?? provider.issuer})` : provider.displayName
    const cells: Record<string, PQAuthCompatCell> = {}
    const issue = (dimension: string, status: PQAuthCompatStatus, severity: PQAuthCompatIssue['severity'], body: Omit<PQAuthCompatIssue, 'id' | 'providerId' | 'dimension' | 'status' | 'severity'>) => {
      issues.push({ id: `${provider.id}:${dimension}`, providerId: provider.id, dimension, status, severity, ...body })
    }

    /* 1. Token signing keys (observed) */
    const signing = keys.filter((k) => k.providerId === provider.id && k.lifecycle === 'published' && k.use !== 'encryption')
    if (provider.protocol === 'saml2') {
      cells['token-signing'] = { status: 'not-verified', summary: 'SAML signing certificates are not extracted from metadata yet.' }
    } else if (!signing.length) {
      cells['token-signing'] = { status: 'not-verified', summary: provider.jwksUri ? 'JWKS named but not read.' : 'No JWKS published.' }
      issue('token-signing', 'not-verified', 'low', {
        component: `${label} — token signing keys`,
        issue: 'The keys that sign this provider\'s tokens have not been observed.',
        why: 'Without the published keys, token-signing quantum posture is unknown — it is not a pass.',
        cause: provider.jwksUri ? `The JWKS at ${provider.jwksUri} could not be read during discovery.` : 'The discovery document does not name a jwks_uri.',
        remediation: 'Re-run identity discovery; if the JWKS is private, record the signing algorithm through the provider\'s admin configuration.',
        evidence: provider.sourceUrl ? `Discovery document: ${provider.sourceUrl}` : 'Discovery record',
        sourceUrl: provider.jwksUri ?? provider.sourceUrl,
      })
    } else {
      const vulnerable = signing.filter((k) => k.quantumClass === 'vulnerable')
      const hybrid = signing.filter((k) => k.quantumClass === 'hybrid')
      const safe = signing.filter((k) => k.quantumClass === 'safe')
      if (vulnerable.length) {
        cells['token-signing'] = { status: 'unsupported', summary: `${vulnerable.length}/${signing.length} keys classical (${Array.from(new Set(vulnerable.map((k) => k.displayAlgorithm))).join(', ')}).` }
        const target = pqcTargetName(vulnerable[0].pqcTarget)
        issue('token-signing', 'unsupported', 'high', {
          component: `${label} — ${plural(vulnerable.length, 'token-signing key')}`,
          issue: `Tokens are signed with ${Array.from(new Set(vulnerable.map((k) => k.displayAlgorithm))).join(', ')}, which a cryptographically relevant quantum computer can forge.`,
          why: 'A forged ID or access token impersonates any user or service that trusts this issuer; every relying application inherits the exposure.',
          cause: 'The provider publishes only classical signing keys (RSA / ECDSA / EdDSA) in its JWKS.',
          remediation: `Introduce ${target} (FIPS 204) signing keys — typically in a hybrid/composite deployment alongside the classical key — then migrate relying parties' validators before retiring the classical key. ML-KEM does not apply: these are signatures.`,
          evidence: `${plural(vulnerable.length, 'key')} in ${vulnerable[0].sourceUrl ?? 'the JWKS'}`,
          sourceUrl: vulnerable[0].sourceUrl,
        })
      } else if (hybrid.length) {
        cells['token-signing'] = { status: 'conditional', summary: `${hybrid.length} hybrid key(s); relying parties must accept the composite format.` }
        issue('token-signing', 'conditional', 'medium', {
          component: `${label} — hybrid signing keys`,
          issue: 'Hybrid signing keys are published; relying-party support is not verified.',
          why: 'Validators that do not understand the hybrid/composite format will reject tokens.',
          cause: 'Hybrid JWS formats are not yet uniformly supported by JOSE libraries.',
          remediation: 'Confirm each relying party\'s JOSE library version supports the composite algorithm before making it the only key.',
          evidence: hybrid[0].sourceUrl ?? 'JWKS',
          sourceUrl: hybrid[0].sourceUrl,
        })
      } else if (safe.length === signing.length) {
        cells['token-signing'] = { status: 'supported', summary: `All ${signing.length} keys post-quantum (${Array.from(new Set(safe.map((k) => k.displayAlgorithm))).join(', ')}).` }
      } else {
        cells['token-signing'] = { status: 'not-verified', summary: `${signing.length - safe.length} key(s) of undetermined posture.` }
      }
    }

    /* 2. Advertised signing algorithms */
    const advertised = provider.signingAlgorithmsSupported
    if (!advertised.length) {
      cells['advertised-signing'] = { status: 'not-verified', summary: 'Document advertises no signing algorithms.' }
    } else if (advertised.some((a) => a.toLowerCase() === 'none')) {
      cells['advertised-signing'] = { status: 'unsupported', summary: 'Advertises alg "none".' }
      issue('advertised-signing', 'unsupported', 'critical', {
        component: `${label} — advertised signing algorithms`,
        issue: 'The provider advertises the "none" algorithm.',
        why: 'Unsigned tokens can be accepted, which allows trivial token forgery today — no quantum computer required.',
        cause: 'alg "none" is listed in the provider\'s *_signing_alg_values_supported.',
        remediation: 'Remove "none" from the provider\'s allowed algorithms and confirm every validator rejects unsigned tokens.',
        evidence: provider.sourceUrl ?? 'Discovery document',
        sourceUrl: provider.sourceUrl,
      })
    } else if (advertised.some(isPqcSignature)) {
      cells['advertised-signing'] = { status: 'supported', summary: `Advertises ${advertised.filter(isPqcSignature).join(', ')}.` }
    } else {
      cells['advertised-signing'] = { status: 'unsupported', summary: `Classical only: ${advertised.slice(0, 4).join(', ')}${advertised.length > 4 ? '…' : ''}.` }
      issue('advertised-signing', 'unsupported', 'medium', {
        component: `${label} — advertised signing algorithms`,
        issue: 'No post-quantum signing algorithm is advertised.',
        why: 'Clients negotiating from the discovery document cannot request ML-DSA-signed tokens, so the migration cannot start client-side.',
        cause: `The provider advertises only ${advertised.slice(0, 4).join(', ')}.`,
        remediation: 'Upgrade or configure the provider to support ML-DSA (FIPS 204); many vendors expose it first behind a preview flag. Track vendor roadmaps in Vendor PQC Readiness.',
        evidence: provider.sourceUrl ?? 'Discovery document',
        sourceUrl: provider.sourceUrl,
      })
    }

    /* 3. Encrypted tokens (JWE key management) */
    const keyMgmt = provider.keyEncryptionAlgorithmsSupported
    if (!keyMgmt.length) {
      cells['token-encryption'] = { status: 'not-applicable', summary: 'Provider does not advertise encrypted tokens.' }
    } else {
      const classes = keyMgmt.map((alg) => classifyJoseAlgorithm(alg, 'key-encapsulation'))
      const classical = classes.filter((c) => c.quantumClass === 'vulnerable')
      const pqc = classes.filter((c) => c.quantumClass === 'safe' || c.quantumClass === 'hybrid')
      if (classical.length && pqc.length) {
        cells['token-encryption'] = { status: 'conditional', summary: `ML-KEM offered alongside ${classical.map((c) => c.algorithm).join(', ')}.` }
      } else if (classical.length) {
        cells['token-encryption'] = { status: 'unsupported', summary: `Classical key transport: ${classical.map((c) => c.algorithm).join(', ')}.` }
        issue('token-encryption', 'unsupported', 'high', {
          component: `${label} — encrypted-token key management`,
          issue: `Encrypted tokens wrap their content key with ${classical.map((c) => c.algorithm).join(', ')}.`,
          why: 'Encrypted tokens captured today can be decrypted later once RSA/ECDH is broken (harvest now, decrypt later).',
          cause: 'Only RSA-OAEP / ECDH-ES key management is advertised for JWE.',
          remediation: 'Adopt ML-KEM-768 (FIPS 203) — hybrid X25519MLKEM768 during transition — for JWE key management. This is key establishment, so ML-KEM is the correct primitive here.',
          evidence: provider.sourceUrl ?? 'Discovery document',
          sourceUrl: provider.sourceUrl,
        })
      } else {
        cells['token-encryption'] = { status: 'supported', summary: `${keyMgmt.join(', ')}.` }
      }
    }

    /* 4. Endpoint transport */
    if (!provider.endpoints.length) {
      cells.transport = { status: 'not-verified', summary: 'No endpoints published.' }
    } else {
      const insecure = provider.endpoints.filter((e) => e.insecureTransport)
      if (insecure.length) {
        cells.transport = { status: 'unsupported', summary: `${insecure.length} endpoint(s) over plain HTTP.` }
        issue('transport', 'unsupported', 'high', {
          component: `${label} — ${insecure.map((e) => e.kind).join(', ')} endpoint`,
          issue: `${insecure[0].url} is published without HTTPS.`,
          why: 'Tokens, codes or keys sent to it travel unencrypted and unauthenticated.',
          cause: 'The discovery document publishes an http:// endpoint URL.',
          remediation: 'Serve the endpoint over TLS 1.3 (with hybrid X25519MLKEM768 key exchange where the stack supports it) and republish the discovery document.',
          evidence: provider.sourceUrl ?? 'Discovery document',
          sourceUrl: provider.sourceUrl,
        })
      } else {
        cells.transport = { status: 'supported', summary: `HTTPS on all ${provider.endpoints.length} endpoints.` }
      }
    }

    /* 5. Host certificate */
    const certs = provider.assetId ? input.certificates.filter((c) => text(c.asset_id) === provider.assetId) : []
    if (!certs.length) {
      cells['host-certificate'] = { status: 'not-verified', summary: 'No certificate recorded for the hosting asset.' }
    } else {
      const classes = certs.map(certificateClass)
      const classical = certs.filter((_, i) => classes[i] === 'vulnerable')
      if (classical.length) {
        cells['host-certificate'] = { status: 'unsupported', summary: `${classical.length}/${certs.length} classical (${Array.from(new Set(classical.map((c) => text(c.algorithm) || 'unknown'))).join(', ')}).` }
        issue('host-certificate', 'unsupported', 'medium', {
          component: `${label} — host certificate`,
          issue: `The asset serving this provider presents a ${text(classical[0].algorithm) || 'classical'} certificate.`,
          why: 'Clients authenticate the provider through this certificate; a forgeable certificate lets an attacker impersonate the provider and its JWKS.',
          cause: 'The certificate chain uses classical RSA/ECDSA signatures.',
          remediation: 'Plan a hybrid or ML-DSA certificate profile with the issuing CA; until CAs issue them, keep the certificate lifetime short and monitor in the Certificate inventory.',
          evidence: `${plural(classical.length, 'certificate')} recorded for the asset`,
          sourceUrl: null,
        })
      } else if (classes.every((c) => c === 'safe' || c === 'hybrid')) {
        cells['host-certificate'] = { status: 'supported', summary: `${certs.length} post-quantum/hybrid certificate(s).` }
      } else {
        cells['host-certificate'] = { status: 'not-verified', summary: 'Certificate algorithm not recorded.' }
      }
    }

    for (const cell of Object.values(cells)) counts[cell.status] += 1
    rows.push({ providerId: provider.id, providerLabel: label, protocol: provider.protocol, cells })
  }

  const rank = { critical: 0, high: 1, medium: 2, low: 3 }
  issues.sort((a, b) => rank[a.severity] - rank[b.severity])
  return { dimensions: COMPAT_DIMENSIONS.map((d) => ({ ...d })), rows, issues, counts }
}

/* ================================================================== */
/* Migration                                                           */
/* ================================================================== */

export function normalizeJobState(status: unknown): Exclude<PQAuthJobState, 'validated'> {
  const s = text(status).toLowerCase()
  if (/fail|error|cancel|abort|blocked|rolled.?back|rollback/.test(s)) return 'failed'
  if (/complete|success|done|finished|validated/.test(s)) return 'completed'
  if (/running|in.?progress|executing|active|deploying/.test(s)) return 'executing'
  if (/queued|scheduled|approved|ready/.test(s)) return 'queued'
  return 'proposed'
}

/** 'signature' | 'kem' | null — the cryptographic ROLE an algorithm string names. */
export function algorithmRole(value: unknown): 'signature' | 'kem' | null {
  const v = text(value).toLowerCase()
  if (!v) return null
  const sig = /ml-?dsa|slh-?dsa|dilithium|sphincs|falcon|\b(rs|ps|es)(256|384|512)\b|eddsa|ed25519|ed448|ecdsa|signature|signing/.test(v)
  const kem = /ml-?kem|kyber|x25519|ecdhe?|\bdh\b|diffie|rsa-oaep|key.?exchange|key.?establish|\bkex\b/.test(v)
  if (sig && !kem) return 'signature'
  if (kem && !sig) return 'kem'
  return null
}

const SIGNATURE_WORKLOAD_RE = /cert|certificate|sign|token|jwt|jws|identity|idp|oidc|saml/i

export function checkTargetRole(jobType: unknown, sourceAlgorithm: unknown, targetAlgorithm: unknown): { ok: boolean | null; detail: string } {
  const target = text(targetAlgorithm)
  if (!target) return { ok: null, detail: 'No target algorithm recorded.' }
  const targetRole = algorithmRole(target)
  const sourceRole = algorithmRole(sourceAlgorithm)
  const signatureWorkload = sourceRole === 'signature' || (sourceRole === null && SIGNATURE_WORKLOAD_RE.test(text(jobType)))
  if (signatureWorkload && targetRole === 'kem') {
    return {
      ok: false,
      detail: `${target} is key establishment only. This ${sourceRole === 'signature' ? `${text(sourceAlgorithm)} signature` : `${text(jobType).replace(/_/g, ' ')}`} workload needs an ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) signature target — ML-KEM cannot sign. Keep ML-KEM for the TLS key exchange and add a signature profile.`,
    }
  }
  if (sourceRole === 'kem' && targetRole === 'signature') {
    return { ok: false, detail: `${target} is a signature scheme; key establishment (${text(sourceAlgorithm)}) migrates to ML-KEM (FIPS 203).` }
  }
  if (targetRole) return { ok: true, detail: `${target} matches the ${targetRole === 'kem' ? 'key-establishment' : 'signature'} role of this workload.` }
  return { ok: null, detail: `Role of ${target} could not be determined from the recorded configuration.` }
}

function buildMigration(input: IdentityModelInput, providers: PQAuthProvider[], now: number): PQAuthMigrationModel {
  const identityAssetIds = Array.from(new Set([
    ...providers.map((p) => p.assetId).filter((id): id is string => Boolean(id)),
    ...providers.flatMap((p) => p.dependentAssetIds),
  ]))
  const identitySet = new Set(identityAssetIds)
  const assetName = new Map(input.assets.map((a) => [text(a.id), text(a.name)]))

  const jobs: PQAuthMigrationJob[] = input.migrationJobs
    .filter((row) => identitySet.has(text(row.asset_id)))
    .map((row) => {
      const metadata = recordOf(row.metadata)
      // The platform-wide definition (Drift, Runtime and Crypto Agility use the same one).
      const simulation = isSimulationRow(row)
      const baseState = normalizeJobState(row.status)
      const sourceAlgorithm = textOrNull(metadata.sourceAlgorithm) ?? textOrNull(metadata.currentAlgorithm)
      const targetAlgorithm = textOrNull(row.target_algorithm) ?? textOrNull(metadata.targetAlgorithm)
      const completedAt = textOrNull(row.completed_at) ?? (baseState === 'completed' ? textOrNull(row.updated_at) : null)
      const assetId = textOrNull(row.asset_id)

      let validation: PQAuthMigrationJob['validation'] = { status: 'not-applicable', detail: 'Validation applies once the job completes.' }
      let state: PQAuthJobState = baseState
      if (baseState === 'completed') {
        if (simulation) {
          validation = { status: 'not-applicable', detail: 'Sandbox / dry-run job — no production change was made, so there is nothing to validate.' }
        } else {
          const rediscovered = providers.filter((p) => p.assetId === assetId && ms(p.lastSeenAt) > ms(completedAt))
          if (!rediscovered.length) {
            validation = { status: 'awaiting-rediscovery', detail: 'Reported complete, but no discovery has observed this asset since. Re-run identity discovery to validate.' }
          } else if (rediscovered.every((p) => p.quantumClass === 'safe' || p.quantumClass === 'hybrid')) {
            validation = { status: 'validated', detail: `Discovery after completion observed ${rediscovered.map((p) => p.quantumClass).join('/')} signing posture.` }
            state = 'validated'
          } else {
            validation = { status: 'regressed', detail: `Discovery after completion still observed ${rediscovered.map((p) => p.quantumClass).join('/')} signing keys — the change did not take effect.` }
          }
        }
      }

      const rollbackId = textOrNull(metadata.lastSnapshotId) ?? textOrNull(recordOf(metadata.rollback).snapshotId)
      const rollback = rollbackId
        ? { available: true, detail: `Snapshot ${rollbackId.slice(0, 8)} recorded${textOrNull(metadata.lastSnapshotAt) ? ` at ${metadata.lastSnapshotAt}` : ''}.` }
        : metadata.rollbackPlan || metadata.rollback
          ? { available: true, detail: 'Rollback plan recorded with the job.' }
          : { available: null, detail: 'No rollback snapshot recorded.' }

      return {
        id: text(row.id),
        name: text(row.name) || text(metadata.assetName) || 'Migration job',
        jobType: textOrNull(row.job_type),
        assetId,
        assetName: (assetId && assetName.get(assetId)) || textOrNull(metadata.assetName),
        rawStatus: text(row.status) || 'unknown',
        state,
        simulation,
        sourceAlgorithm,
        targetAlgorithm,
        progress: numOrNull(row.progress),
        startedAt: textOrNull(row.started_at),
        completedAt,
        updatedAt: textOrNull(row.updated_at),
        validation,
        roleCheck: checkTargetRole(row.job_type, sourceAlgorithm, targetAlgorithm),
        rollback,
      }
    })
    .sort((a, b) => ms(b.updatedAt) - ms(a.updatedAt))

  const counts: Record<PQAuthJobState, number> = { proposed: 0, queued: 0, executing: 0, completed: 0, validated: 0, failed: 0 }
  const production = jobs.filter((j) => !j.simulation)
  for (const job of production) counts[job.state] += 1

  const vulnerableProviders = providers.filter((p) => p.quantumClass === 'vulnerable')
  const unknownProviders = providers.filter((p) => p.quantumClass === 'unknown')
  const probedAny = input.probes.length > 0
  const completedish = production.filter((j) => j.state === 'completed' || j.state === 'validated')
  const regressed = production.filter((j) => j.validation.status === 'regressed')
  const awaiting = production.filter((j) => j.validation.status === 'awaiting-rediscovery')
  const recentRuntime = input.runtimeEvents.filter((row) => now - ms(row.observed_at ?? row.created_at) <= RUNTIME_RECENT_MS && TOKEN_OPERATION_RE.test(`${text(row.event_type)} ${text(row.operation_type)}`))

  const gates: PQAuthMigrationGate[] = [
    {
      id: 'assess', label: 'Assess', description: 'Discover identity providers and classify what signs their tokens.',
      status: !probedAny ? 'not-started' : unknownProviders.length ? 'in-progress' : 'complete',
      evidence: !probedAny
        ? 'No identity discovery has run.'
        : providers.length
          ? `${plural(providers.length, 'provider')} discovered: ${vulnerableProviders.length} quantum-vulnerable, ${unknownProviders.length} undetermined.`
          : 'Discovery ran and found no identity providers on the probed hosts.',
      href: '/dashboard/pqauth/discovery',
    },
    {
      id: 'dependencies', label: 'Dependency analysis', description: 'Map which assets host or trust each provider (blast radius).',
      status: !providers.length ? 'not-started' : 'complete',
      evidence: providers.length
        ? `${plural(identityAssetIds.length, 'asset')} linked to identity providers; ${providers.reduce((s, p) => s + p.dependentAssetIds.length, 0)} declared trust relationship(s).`
        : 'Nothing to map until a provider is discovered.',
      href: '/dashboard/pqauth/trust-graph',
    },
    {
      id: 'plan', label: 'Plan', description: 'A migration job exists for each quantum-vulnerable identity asset.',
      status: production.length ? (vulnerableProviders.every((p) => production.some((j) => j.assetId === p.assetId)) ? 'complete' : 'in-progress') : vulnerableProviders.length ? 'not-started' : (providers.length ? 'complete' : 'not-started'),
      evidence: production.length
        ? `${plural(production.length, 'production job')} on identity assets${jobs.length > production.length ? ` (+${jobs.length - production.length} sandbox)` : ''}.`
        : vulnerableProviders.length
          ? `${plural(vulnerableProviders.length, 'vulnerable provider')} without a migration job.`
          : providers.length ? 'No vulnerable provider requires a job.' : 'No identity providers yet.',
      href: '/dashboard/migration-planner',
    },
    {
      id: 'approve', label: 'Approve', description: 'Jobs move from proposed to queued once approved for execution.',
      status: !production.length ? 'not-started' : counts.proposed ? 'in-progress' : 'complete',
      evidence: production.length ? `${counts.proposed} proposed, ${production.length - counts.proposed} approved or later.` : 'No jobs to approve.',
      href: '/dashboard/migration-planner',
    },
    {
      id: 'execute', label: 'Execute', description: 'The executor reports progress; failures block the gate.',
      status: counts.failed ? 'blocked' : counts.executing ? 'in-progress' : completedish.length && completedish.length === production.length ? 'complete' : 'not-started',
      evidence: production.length ? `${counts.executing} executing, ${completedish.length} reported complete, ${counts.failed} failed.` : 'No jobs executing.',
      href: '/dashboard/live-migration',
    },
    {
      id: 'validate', label: 'Validate', description: 'Re-discovery after completion must observe post-quantum signing keys.',
      status: regressed.length ? 'blocked' : awaiting.length ? 'in-progress' : counts.validated && !awaiting.length ? 'complete' : 'not-started',
      evidence: completedish.length
        ? `${counts.validated} validated, ${awaiting.length} awaiting re-discovery, ${regressed.length} still classical after completion.`
        : 'Nothing has completed yet — no migration is marked validated without re-discovery evidence.',
      href: '/dashboard/pqauth/discovery',
    },
    {
      id: 'monitor', label: 'Monitor', description: 'Runtime token operations observed by agents in the last 24 hours.',
      status: recentRuntime.length ? 'complete' : 'not-started',
      evidence: recentRuntime.length ? `${plural(recentRuntime.length, 'token operation')} observed in 24h.` : 'No runtime identity telemetry in the last 24 hours.',
      href: '/dashboard/pqauth/runtime-telemetry',
    },
  ]

  return { identityAssetIds, jobs, tenantJobCount: input.migrationJobs.length, counts, gates }
}

/* ================================================================== */
/* Digital twin                                                        */
/* ================================================================== */

function buildTwin(
  input: IdentityModelInput,
  providers: PQAuthProvider[],
  keys: PQAuthSigningKey[],
  discovery: PQAuthDiscoveryModel,
  tokens: PQAuthTokenModel,
  migration: PQAuthMigrationModel,
  now: number,
): PQAuthTwinModel {
  const conflicts: PQAuthTwinModel['conflicts'] = []
  for (const c of tokens.conflicts) conflicts.push({ providerId: c.providerId, kind: 'advertised-vs-observed', detail: c.detail })
  for (const provider of providers) {
    if (!provider.assetId) continue
    const host = discovery.hosts.find((h) => h.assetId === provider.assetId)
    if (host && ms(host.lastProbedAt) > ms(provider.lastSeenAt) + 60_000 && !host.providerIds.includes(provider.id)) {
      conflicts.push({ providerId: provider.id, kind: 'not-reobserved', detail: `Not observed in the latest discovery of ${host.host}; last seen ${provider.lastSeenAt ?? 'never'}. The twin keeps the last observation and marks it unconfirmed.` })
    } else if (host && host.result !== 'identity-found' && ms(host.lastProbedAt) >= ms(provider.lastSeenAt) - 60_000 && host.providerIds.includes(provider.id)) {
      conflicts.push({ providerId: provider.id, kind: 'incomplete-read', detail: `Latest discovery of ${host.host} was ${host.result}: ${host.explanation}` })
    }
  }
  for (const job of migration.jobs) {
    if (job.validation.status === 'regressed' && job.assetId) {
      const provider = providers.find((p) => p.assetId === job.assetId)
      if (provider) conflicts.push({ providerId: provider.id, kind: 'migration-not-effective', detail: `Job "${job.name}" reports complete, yet discovery still observes classical keys.` })
    }
  }

  const lastSyncAt = discovery.lastRunAt
  const age = ageOf(lastSyncAt, now)
  const unread = discovery.hosts.filter((h) => h.result === 'failed' || h.result === 'incomplete')
  const sync: PQAuthTwinModel['sync'] = !lastSyncAt
    ? { status: 'never-synced', lastSyncAt: null, detail: 'No identity discovery has run, so the twin has nothing to model.' }
    : age === 'stale'
      ? { status: 'stale', lastSyncAt, detail: 'The newest discovery observation is older than 7 days. Re-run discovery to resynchronise the twin.' }
      : conflicts.length
        ? { status: 'drift', lastSyncAt, detail: `${plural(conflicts.length, 'conflict')} between recorded and newly observed state.` }
        : unread.length
          // A host that could not be read is a gap in the model, not an empty corner of it.
          ? { status: 'partial', lastSyncAt, detail: `${plural(unread.length, 'host')} (${unread.slice(0, 3).map((h) => h.host).join(', ')}) could not be fully read in the latest discovery, so the twin cannot confirm what identity infrastructure ${unread.length === 1 ? 'it hosts' : 'they host'}.` }
          : providers.length
          ? { status: 'in-sync', lastSyncAt, detail: 'Every modelled provider matches its most recent discovery observation.' }
          : { status: 'in-sync', lastSyncAt, detail: 'Discovery is current and found no identity provider on the probed hosts, so the twin is empty — accurately.' }

  const entities = providers.map((p) => ({
    providerId: p.id,
    label: p.vendor || p.displayName,
    quantumClass: p.quantumClass,
    age: p.age,
    assetId: p.assetId,
    keys: p.publishedKeyCount,
    vulnerableKeys: p.vulnerableKeyCount,
    dependents: p.dependentAssetIds.length,
    conflicts: conflicts.filter((c) => c.providerId === p.id).map((c) => c.detail),
  }))

  const published = keys.filter((k) => k.lifecycle === 'published' && k.use !== 'encryption' && k.quantumClass === 'vulnerable')

  const signatureScenario = (
    id: string,
    label: string,
    description: string,
    sizes: { signature: number; publicKey: number; standard: string },
    composite: boolean,
    note: string,
  ): PQAuthTwinScenario => {
    const impacts = providers.map((p) => {
      const own = published.filter((k) => k.providerId === p.id)
      const sized = own.filter((k) => k.signatureBytes)
      if (!own.length) return null
      const current = Math.max(0, ...sized.map((k) => k.signatureBytes as number))
      const projected = composite ? current + sizes.signature : sizes.signature
      const jwksDelta = own.reduce((sum, k) => {
        const pk = publicKeyBytesFor(k.keyType, k.keySize, k.curve) ?? 0
        const next = composite ? pk + sizes.publicKey : sizes.publicKey
        return sum + base64urlLength(next) - base64urlLength(pk)
      }, 0)
      return {
        providerId: p.id,
        providerLabel: p.vendor || p.displayName,
        keysAffected: own.length,
        currentEncodedBytes: current ? base64urlLength(current) : 0,
        projectedEncodedBytes: base64urlLength(projected),
        deltaBytes: base64urlLength(projected) - (current ? base64urlLength(current) : 0),
        jwksDeltaBytes: jwksDelta,
        dependents: p.dependentAssetIds.length,
      }
    }).filter((x): x is NonNullable<typeof x> => Boolean(x))
    return {
      id,
      label,
      description,
      standard: sizes.standard,
      applicable: impacts.length > 0,
      reason: impacts.length ? note : 'No published classical signing key to replace.',
      impacts,
      totals: {
        providers: impacts.length,
        keys: impacts.reduce((s, i) => s + i.keysAffected, 0),
        maxDeltaBytes: Math.max(0, ...impacts.map((i) => i.deltaBytes)),
        dependents: impacts.reduce((s, i) => s + i.dependents, 0),
      },
      inputs: [
        `${plural(published.length, 'published classical signing key')} from identity_signing_keys`,
        `${label}: signature ${sizes.signature.toLocaleString('en-US')} B, public key ${sizes.publicKey.toLocaleString('en-US')} B (${sizes.standard})`,
        'Encoded sizes are unpadded base64url, as carried in a compact JWS and a JWKS',
        ...(composite ? ['Composite size is a lower bound: classical + PQC components, excluding encoding overhead'] : []),
      ],
    }
  }

  const scenarios: PQAuthTwinScenario[] = [
    signatureScenario('ml-dsa-65', 'Sign tokens with ML-DSA-65', 'Replace each classical signing key with ML-DSA-65 — NIST security category 3, the default target for token signing.', PQC_SIZES['ML-DSA-65'], false, 'Recommended default for ID and access tokens.'),
    signatureScenario('ml-dsa-44', 'Sign tokens with ML-DSA-44', 'Smallest ML-DSA parameter set (category 2) — useful where header or cookie budgets are tight.', PQC_SIZES['ML-DSA-44'], false, 'Smaller tokens at a lower security category.'),
    signatureScenario('composite', 'Hybrid: classical + ML-DSA-65', 'Composite signature carrying both the existing classical signature and ML-DSA-65 during transition.', PQC_SIZES['ML-DSA-65'], true, 'Keeps legacy validators working while PQC validators roll out.'),
    signatureScenario('slh-dsa', 'Anchor with SLH-DSA-SHA2-128s', 'Stateless hash-based signatures for long-lived trust anchors — conservative security assumptions, very large signatures.', PQC_SIZES['SLH-DSA-SHA2-128s'], false, 'Suited to long-lived anchors, not per-request tokens.'),
  ]

  const jweProviders = providers.filter((p) => p.keyEncryptionAlgorithmsSupported.some((alg) => classifyJoseAlgorithm(alg, 'key-encapsulation').quantumClass === 'vulnerable'))
  const rsaOaepCt = 256 // RSA-2048 encrypted key — the common JWE default
  scenarios.push({
    id: 'ml-kem-jwe',
    label: 'Encrypt tokens with ML-KEM-768',
    description: 'Replace RSA-OAEP / ECDH-ES key management for encrypted tokens with ML-KEM-768 (key establishment — the role ML-KEM is for).',
    standard: ML_KEM_768.standard,
    applicable: jweProviders.length > 0,
    reason: jweProviders.length ? 'Applies to providers that advertise classical JWE key management.' : 'No provider advertises classical JWE key management.',
    impacts: jweProviders.map((p) => ({
      providerId: p.id,
      providerLabel: p.vendor || p.displayName,
      keysAffected: p.keyEncryptionAlgorithmsSupported.length,
      currentEncodedBytes: base64urlLength(rsaOaepCt),
      projectedEncodedBytes: base64urlLength(ML_KEM_768.ciphertext),
      deltaBytes: base64urlLength(ML_KEM_768.ciphertext) - base64urlLength(rsaOaepCt),
      jwksDeltaBytes: 0,
      dependents: p.dependentAssetIds.length,
    })),
    totals: {
      providers: jweProviders.length,
      keys: jweProviders.reduce((s, p) => s + p.keyEncryptionAlgorithmsSupported.length, 0),
      maxDeltaBytes: jweProviders.length ? base64urlLength(ML_KEM_768.ciphertext) - base64urlLength(rsaOaepCt) : 0,
      dependents: jweProviders.reduce((s, p) => s + p.dependentAssetIds.length, 0),
    },
    inputs: [
      `${plural(jweProviders.length, 'provider')} advertising classical JWE key management`,
      `ML-KEM-768 ciphertext ${ML_KEM_768.ciphertext.toLocaleString('en-US')} B (${ML_KEM_768.standard}) vs RSA-OAEP-2048 encrypted key ${rsaOaepCt} B`,
    ],
  })

  return { sync, entities, conflicts, scenarios }
}

/* ================================================================== */
/* Assembly                                                            */
/* ================================================================== */

function buildNextActions(
  input: IdentityModelInput,
  providers: PQAuthProvider[],
  discovery: PQAuthDiscoveryModel,
  tokens: PQAuthTokenModel,
  compatibility: PQAuthCompatibilityModel,
  migration: PQAuthMigrationModel,
  twin: PQAuthTwinModel,
): PQAuthNextAction[] {
  const actions: PQAuthNextAction[] = []
  const eligible = discovery.scope.filter((s) => s.eligible).length
  if (!input.assets.length || !eligible) {
    actions.push({ id: 'add-target', priority: 'high', title: 'Add a public web target to scan', detail: eligible ? '' : 'Identity discovery probes only the public hostnames the tenant has authorized. None are recorded yet.', href: '/dashboard/scanner' })
  } else if (!discovery.runs.length) {
    actions.push({ id: 'run-discovery', priority: 'high', title: 'Run identity discovery', detail: `${plural(eligible, 'authorized host')} can be probed for OIDC, OAuth 2.0 and SAML metadata.`, href: '/dashboard/pqauth/discovery' })
  }
  for (const issue of compatibility.issues.filter((i) => i.severity === 'critical')) {
    actions.push({ id: `critical:${issue.id}`, priority: 'critical', title: issue.issue, detail: issue.remediation, href: '/dashboard/pqauth/compatibility' })
  }
  const vulnerableKeys = tokens.keys.filter((k) => k.lifecycle === 'published' && k.use !== 'encryption' && k.quantumClass === 'vulnerable')
  const unplanned = providers.filter((p) => p.vulnerableKeyCount > 0 && !migration.jobs.some((j) => !j.simulation && j.assetId === p.assetId))
  if (unplanned.length) {
    actions.push({ id: 'plan-mldsa', priority: 'high', title: `Plan ML-DSA migration for ${plural(unplanned.length, 'provider')}`, detail: `${plural(vulnerableKeys.length, 'classical token-signing key')} have no migration job. Model the token-size impact in the Digital Twin first.`, href: '/dashboard/pqauth/digital-twin' })
  }
  const roleMismatch = migration.jobs.filter((j) => j.roleCheck.ok === false)
  if (roleMismatch.length) {
    actions.push({ id: 'role-mismatch', priority: 'high', title: `Correct the target algorithm on ${plural(roleMismatch.length, 'migration job')}`, detail: roleMismatch[0].roleCheck.detail, href: '/dashboard/pqauth/migration-center' })
  }
  const insecure = compatibility.issues.filter((i) => i.dimension === 'transport')
  if (insecure.length) {
    actions.push({ id: 'insecure-transport', priority: 'high', title: `Enforce HTTPS on ${plural(insecure.length, 'provider')}`, detail: insecure[0].issue, href: '/dashboard/pqauth/compatibility' })
  }
  const awaiting = migration.jobs.filter((j) => j.validation.status === 'awaiting-rediscovery')
  if (awaiting.length) {
    actions.push({ id: 'validate', priority: 'medium', title: `Validate ${plural(awaiting.length, 'completed migration')}`, detail: 'Re-run identity discovery so completion is confirmed by observation.', href: '/dashboard/pqauth/discovery' })
  }
  if (twin.sync.status === 'stale' || twin.sync.status === 'drift') {
    actions.push({ id: 'resync', priority: 'medium', title: twin.sync.status === 'stale' ? 'Resynchronise stale identity evidence' : 'Resolve twin drift', detail: twin.sync.detail, href: twin.sync.status === 'stale' ? '/dashboard/pqauth/discovery' : '/dashboard/pqauth/digital-twin' })
  }
  const incomplete = discovery.hosts.filter((h) => h.result === 'incomplete' || h.result === 'failed')
  if (incomplete.length) {
    actions.push({ id: 'incomplete', priority: 'medium', title: `Complete discovery on ${plural(incomplete.length, 'host')}`, detail: incomplete[0].explanation, href: '/dashboard/pqauth/discovery' })
  }
  if (!tokens.runtime.measured && providers.length) {
    actions.push({ id: 'runtime', priority: 'low', title: 'Deploy runtime agents for token telemetry', detail: 'Discovery reads published metadata only. Runtime agents observe which algorithms actually sign and verify tokens in production.', href: '/dashboard/runtime-crypto-intel' })
  }
  if (!actions.length) {
    actions.push({ id: 'steady', priority: 'low', title: 'No open identity actions', detail: 'Keep discovery current: re-run it after any identity provider change.', href: '/dashboard/pqauth/discovery' })
  }
  const rank = { critical: 0, high: 1, medium: 2, low: 3 }
  return actions.sort((a, b) => rank[a.priority] - rank[b.priority]).slice(0, 6)
}

export function buildIdentityModel(input: IdentityModelInput): PQAuthIdentityModel {
  const now = input.now ?? Date.now()
  const assetName = new Map(input.assets.map((a) => [text(a.id), text(a.name)]))
  const providerLabels = new Map(input.providers.map((p) => [text(p.id), text(p.vendor) || text(p.display_name) || text(p.host) || text(p.issuer)]))
  const keys = buildKeys(input.signingKeys, providerLabels)
  const providers = buildProviders(input.providers, keys, input.trustRelationships, assetName, now)
  const discovery = buildDiscovery(input, providers, keys, now)
  const graph = buildGraph(input, providers, keys)
  const tokens = buildTokens(input, providers, keys)
  const compatibility = buildCompatibility(input, providers, keys)
  const migration = buildMigration(input, providers, now)
  const twin = buildTwin(input, providers, keys, discovery, tokens, migration, now)

  const signing = keys.filter((k) => k.lifecycle === 'published' && k.use !== 'encryption')
  const safeKeys = signing.filter((k) => k.quantumClass === 'safe').length
  const hybridKeys = signing.filter((k) => k.quantumClass === 'hybrid').length
  const vulnerableKeys = signing.filter((k) => k.quantumClass === 'vulnerable').length
  const unknownKeys = signing.filter((k) => k.quantumClass === 'unknown').length
  const classified = safeKeys + hybridKeys + vulnerableKeys

  return {
    providers,
    discovery,
    graph,
    tokens,
    compatibility,
    migration,
    twin,
    readiness: {
      safeKeys,
      hybridKeys,
      vulnerableKeys,
      unknownKeys,
      coverage: classified ? Math.round(((safeKeys + hybridKeys) / classified) * 100) : null,
    },
    nextActions: buildNextActions(input, providers, discovery, tokens, compatibility, migration, twin),
  }
}
