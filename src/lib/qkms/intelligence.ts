/**
 * QKMS intelligence assembler — raw tenant rows in, one canonical model out.
 *
 * Pure and isomorphic: no I/O, no Supabase, no Express. The API server fetches
 * and caches; this module decides what the numbers mean. That split is what
 * lets the same model back seven pages, an export and a check tool without any
 * of them re-deriving a value.
 *
 * ── Counting discipline ────────────────────────────────────────────────────
 * Every metric counts ONE unit and says which. The predecessor published
 *
 *     weakAlgorithms = (keys flagged weak) + (finding rows matching a regex)
 *     findings       = keyTextRows.length + keyPostureFindings
 *
 * — sums across incompatible units. Overview reported 137 "weak algorithms" on
 * an estate whose inventory held four weak keys, and no table could reconcile
 * the difference. Here, keys are counted in keys, violations in violations and
 * evidence in records, and each aggregate carries the key ids behind it so
 * every figure drills down to the rows that produced it.
 */

import type {
  AuditEvidenceRecord,
  DistributionRow,
  GovernanceViolation,
  KeyCapabilities,
  KeyIndexEntry,
  KeyPqcPosture,
  KeyRecordRef,
  KeyRiskAssessment,
  KeyVersion,
  LifecycleState,
  ManagedKey,
  PipelineStatus,
  PostureEvidence,
  QkmsEvidenceRef,
  QkmsEvidenceSource,
  QkmsIntelligence,
  QkmsMetrics,
  QkmsPolicy,
  QkmsTelemetryHealth,
  RiskFactorKey,
  RotationJob,
  RotationJobStatus,
  RotationPosture,
  RotationState,
  Severity,
} from './types'
import { LIFECYCLE_LABEL, LIFECYCLE_ORDER, RISK_WEIGHTS, ROTATION_TRANSITIONS } from './types'
import { classifyKey, inferKeyType, inferPurpose, namesKeyMaterial } from './classify'
import {
  ONE_DAY_MS,
  EXPIRY_WARNING_DAYS,
  LONG_LIVED_DAYS,
  ageBucketOf,
  dateMs,
  expiryBucketOf,
  resolveLifecycle,
  ROTATION_GOVERNED,
} from './lifecycle'
import {
  baselinePolicies,
  buildBackendPosture,
  buildEntropyPosture,
  classifyCustody,
  evaluateGovernance,
  isApprovedCustody,
  policyCoversKey,
  ruleLabel,
} from './governance'
import { assessKeyRisk, riskLevelOf } from './risk'
import { buildMigrationGate, buildPrechecks, buildReadiness, isEvidenced } from './readiness'

type Row = Record<string, unknown>

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

function str(value: unknown, fallback = ''): string {
  if (typeof value === 'string') return value.trim() || fallback
  if (value === null || value === undefined) return fallback
  return String(value).trim() || fallback
}

function nullableStr(value: unknown): string | null {
  const text = str(value)
  if (!text) return null
  if (/^(unknown|unassigned|none|n\/a|null|undefined|-)$/i.test(text)) return null
  return text
}

function num(value: unknown): number | null {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed !== 0 ? parsed : Number.isFinite(parsed) ? parsed : null
}

function positiveNum(value: unknown): number | null {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null
}

function record(value: unknown): Row {
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Row) : {}
    } catch {
      return {}
    }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Row) : {}
}

function iso(value: unknown): string | null {
  const ms = dateMs(value)
  return ms === null ? null : new Date(ms).toISOString()
}

function latest(...values: unknown[]): string | null {
  const times = values.map(dateMs).filter((ms): ms is number => ms !== null)
  return times.length ? new Date(Math.max(...times)).toISOString() : null
}

function rowTimestamp(row: Row): string | null {
  return iso(row.observed_at ?? row.processed_at ?? row.completed_at ?? row.started_at ?? row.last_seen_at
    ?? row.updated_at ?? row.discovered_at ?? row.created_at ?? row.timestamp)
}

/** FNV-1a. Deterministic, dependency-free, and stable across processes. */
function hash(value: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(36).padStart(7, '0')
}

function distribution(
  entries: Array<{ label: string; keyId: string }>,
  limit = 10,
): DistributionRow[] {
  const buckets = new Map<string, string[]>()
  for (const entry of entries) {
    const label = entry.label || 'Unknown'
    const bucket = buckets.get(label)
    if (bucket) bucket.push(entry.keyId)
    else buckets.set(label, [entry.keyId])
  }
  const total = entries.length
  return [...buckets.entries()]
    .sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([label, keyIds]) => ({
      label,
      count: keyIds.length,
      percent: total ? Math.round((keyIds.length / total) * 100) : 0,
      keyIds: keyIds.slice(0, 200),
    }))
}

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

export interface QkmsInputs {
  assets: Row[]
  qkmsKeys: Row[]
  qkmsKeyVersions: Row[]
  qkmsPolicies: Row[]
  qkmsRotationJobs: Row[]
  qkmsAuditEvents: Row[]
  qkmsStorageBackends: Row[]
  generatedKeys: Row[]
  cryptoInventory: Row[]
  certificates: Row[]
  runtimeEvents: Row[]
  scannerEvidence: Row[]
  migrationJobs: Row[]
  complianceEvidence: Row[]
  vaultAuditLogs: Row[]
  qrngEvents: Row[]
  scannerAgents: Row[]
  connectorAccounts: Row[]
  agentHeartbeats: Row[]
  scanSessions: Row[]
  /** true when any query hit its row cap — the model is a bounded sample. */
  truncated: boolean
  /** Auxiliary tables whose query failed; their rows are absent, not empty. */
  degradedSources?: string[]
  now?: number
}

/* ------------------------------------------------------------------ */
/* Raw observation                                                     */
/* ------------------------------------------------------------------ */

interface KeyObservation {
  table: string
  recordId: string
  writable: boolean
  source: QkmsEvidenceSource
  evidenceDetail: string
  observedAt: string | null
  scanId: string | null
  /**
   * A stable identifier for the THING that holds this key, when the source has
   * one — a certificate serial, say. Used for identity when no key fingerprint
   * exists, so two distinct certificates on one host stay two distinct keys
   * however similarly they happen to be labelled.
   */
  identityAnchor: string | null

  alias: string | null
  algorithm: string
  keySize: number | null
  fingerprint: string | null
  status: string
  owner: string | null
  assetId: string | null
  certificateId: string | null
  environment: string
  purpose: string
  backendHint: string
  storageReference: string | null
  entropySource: string | null
  exportable: boolean | null
  hsmBackedDeclared: boolean | null
  rotationIntervalDays: number | null
  version: number | null

  createdAt: string | null
  activatedAt: string | null
  lastUsedAt: string | null
  lastRotatedAt: string | null
  expiresAt: string | null
  decommissionedAt: string | null
  metadata: Row
}

function environmentOf(value: unknown, fallback = 'unknown'): string {
  const text = str(value).toLowerCase()
  if (/prod|live|customer/.test(text)) return 'production'
  if (/stag|preprod|uat|qa\b/.test(text)) return 'staging'
  if (/dev|local|sandbox|test/.test(text)) return 'development'
  return fallback
}

/* ------------------------------------------------------------------ */
/* Identity                                                            */
/* ------------------------------------------------------------------ */

/**
 * The canonical key id (brief section 3).
 *
 * Precedence is deliberate: a fingerprint identifies key MATERIAL, so two rows
 * carrying the same fingerprint are the same key however they were discovered.
 * Registry rows come next because the tenant owns them. Only when neither
 * exists is the id derived — and then from the properties that define the key
 * (where it lives, what it is, what it does), never from a scan row id, which
 * changes on every re-scan and would re-create the key each time.
 */
function identityFor(observation: KeyObservation): string {
  if (observation.fingerprint) {
    return `key:fp:${hash(observation.fingerprint.toLowerCase())}`
  }
  if (observation.table === 'qkms_keys') return `key:qkms:${observation.recordId}`
  if (observation.table === 'generated_keys') return `key:gen:${observation.recordId}`
  if (observation.identityAnchor) return `key:crt:${hash(observation.identityAnchor.toLowerCase())}`

  const parts = [
    observation.assetId || 'unmapped',
    observation.algorithm.toLowerCase() || 'unknown',
    (observation.alias || observation.purpose || '').toLowerCase(),
    observation.backendHint.toLowerCase(),
  ]
  return `key:d:${hash(parts.join('|'))}`
}

/* ------------------------------------------------------------------ */
/* Observation extraction                                              */
/* ------------------------------------------------------------------ */

function fromQkmsKey(row: Row): KeyObservation {
  const metadata = record(row.metadata_json)
  return {
    table: 'qkms_keys',
    recordId: str(row.id),
    writable: true,
    source: 'qkms-registry',
    evidenceDetail: `QKMS registry record for "${str(row.key_alias, 'key')}".`,
    observedAt: iso(row.updated_at ?? row.created_at),
    scanId: null,
    identityAnchor: null,
    alias: nullableStr(row.key_alias),
    algorithm: str(row.algorithm),
    keySize: positiveNum(metadata.key_size),
    fingerprint: nullableStr(metadata.fingerprint),
    status: str(row.status, 'active'),
    owner: nullableStr(row.owner_id),
    assetId: nullableStr(row.asset_id),
    certificateId: nullableStr(row.certificate_id),
    environment: environmentOf(row.environment),
    purpose: str(row.purpose),
    backendHint: str(row.storage_backend),
    storageReference: nullableStr(row.storage_reference),
    entropySource: nullableStr(row.entropy_source),
    exportable: typeof row.exportable === 'boolean' ? row.exportable : null,
    hsmBackedDeclared: typeof row.hsm_backed === 'boolean' ? row.hsm_backed : null,
    rotationIntervalDays: positiveNum(row.rotation_interval_days),
    version: positiveNum(row.version),
    createdAt: iso(row.created_at),
    activatedAt: iso(metadata.activated_at),
    lastUsedAt: iso(row.last_used_at ?? metadata.last_used_at),
    lastRotatedAt: iso(row.last_rotated_at),
    expiresAt: iso(row.expires_at),
    decommissionedAt: iso(row.decommissioned_at),
    metadata,
  }
}

function fromGeneratedKey(row: Row): KeyObservation {
  // `label` historically carried a JSON blob of QKMS attributes.
  const label = record(row.label)
  const metadata = record(row.metadata)
  const merged = { ...label, ...metadata }
  return {
    table: 'generated_keys',
    recordId: str(row.id),
    writable: true,
    source: 'generated-key',
    evidenceDetail: `Key generated by this platform using ${str(row.entropy_source, 'an approved entropy source')}.`,
    observedAt: iso(row.updated_at ?? row.created_at),
    scanId: null,
    identityAnchor: null,
    alias: nullableStr(merged.key_alias ?? merged.name ?? (typeof row.label === 'string' && !str(row.label).startsWith('{') ? row.label : null)),
    algorithm: str(row.algorithm),
    keySize: positiveNum(row.bit_length),
    fingerprint: nullableStr(row.fingerprint),
    status: row.revoked_at ? 'revoked' : str(row.status, 'active'),
    owner: nullableStr(merged.owner),
    assetId: nullableStr(merged.asset_id),
    certificateId: nullableStr(merged.certificate_id),
    environment: environmentOf(merged.environment),
    purpose: str(merged.purpose),
    backendHint: str(merged.storage_backend, 'QGuard platform vault'),
    storageReference: nullableStr(merged.storage_reference),
    entropySource: nullableStr(row.entropy_source),
    exportable: typeof merged.exportable === 'boolean' ? merged.exportable : null,
    hsmBackedDeclared: typeof merged.hsm_backed === 'boolean' ? (merged.hsm_backed as boolean) : null,
    rotationIntervalDays: positiveNum(merged.rotation_interval_days),
    version: positiveNum(merged.version),
    createdAt: iso(row.created_at),
    activatedAt: iso(merged.activated_at),
    lastUsedAt: iso(merged.last_used_at),
    lastRotatedAt: iso(merged.last_rotated_at ?? merged.rotated_at),
    expiresAt: iso(row.expires_at),
    decommissionedAt: null,
    metadata: merged,
  }
}

function fromCryptoInventory(row: Row, assetEnvironment: string): KeyObservation {
  const metadata = record(row.metadata)
  return {
    table: 'crypto_inventory',
    recordId: str(row.id),
    // Scanner-owned: QKMS must not mutate a discovery record.
    writable: false,
    source: 'crypto-inventory',
    evidenceDetail: `Discovered in the cryptographic inventory as "${str(row.name, str(row.item_type, 'component'))}".`,
    observedAt: iso(row.discovered_at ?? row.created_at),
    scanId: nullableStr(row.scan_id ?? row.session_id ?? metadata.scan_id),
    identityAnchor: nullableStr(metadata.serial_number ?? metadata.serial),
    alias: nullableStr(row.name),
    algorithm: str(row.algorithm),
    keySize: positiveNum(row.key_size),
    fingerprint: nullableStr(metadata.fingerprint ?? metadata.fingerprint_sha256),
    status: str(row.status, 'observed'),
    owner: nullableStr(metadata.owner ?? metadata.team),
    assetId: nullableStr(row.asset_id),
    certificateId: nullableStr(metadata.certificate_id),
    environment: environmentOf(metadata.environment, assetEnvironment),
    purpose: str(metadata.purpose ?? row.item_type),
    backendHint: str(metadata.storage_backend ?? metadata.location ?? row.location),
    storageReference: nullableStr(metadata.storage_reference ?? row.file_path),
    entropySource: nullableStr(metadata.entropy_source),
    exportable: typeof metadata.exportable === 'boolean' ? (metadata.exportable as boolean) : null,
    hsmBackedDeclared: null,
    rotationIntervalDays: null,
    version: null,
    /*
     * `created_at` on a discovery row is when the SCANNER saw the key, not when
     * the key was created. Mapping it here gave every freshly-discovered key an
     * age of a few days and a lifecycle of "active" — inventing lifecycle
     * evidence the scan never captured. Only a creation date the scanner
     * actually recorded counts.
     */
    createdAt: iso(metadata.created_at ?? metadata.key_created_at ?? metadata.not_before),
    activatedAt: null,
    lastUsedAt: null,
    lastRotatedAt: iso(metadata.last_rotated_at),
    expiresAt: iso(metadata.expires_at),
    decommissionedAt: null,
    metadata,
  }
}

function fromCertificate(row: Row, assetEnvironment: string): KeyObservation {
  const metadata = record(row.metadata)
  const subject = str(row.subject, str(row.name, 'certificate'))
  return {
    table: 'certificates',
    recordId: str(row.id),
    writable: false,
    source: 'certificate-store',
    evidenceDetail: `Public-key material bound to certificate "${subject}".`,
    observedAt: iso(row.updated_at ?? row.created_at),
    scanId: nullableStr(metadata.scan_id),
    /*
     * A certificate serial is unique per issuer and stable across re-scans, so
     * it is the right identity for the key a certificate binds when no key
     * fingerprint is available. Without it, two DIFFERENT certificates on one
     * host — a renewal, say — collapse into one key whenever their subjects and
     * algorithms happen to match, silently hiding a key from the inventory.
     */
    identityAnchor: nullableStr(row.serial ?? row.serial_number ?? metadata.serial_number),
    alias: nullableStr(subject),
    algorithm: str(row.algorithm ?? row.public_key_algorithm ?? row.signature_algorithm),
    keySize: positiveNum(row.key_size),
    fingerprint: nullableStr(row.fingerprint ?? row.fingerprint_sha256 ?? metadata.fingerprint),
    // A certificate's own status. Expiry is handled by the lifecycle engine
    // from `not_after`; it is NOT an algorithm weakness, which is how the
    // predecessor came to mark every expiring certificate key "weak".
    status: str(row.status, 'observed'),
    owner: nullableStr(row.owner ?? metadata.owner),
    assetId: nullableStr(row.asset_id),
    certificateId: str(row.id),
    environment: environmentOf(metadata.environment, assetEnvironment),
    purpose: 'Certificate and TLS identity',
    backendHint: str(metadata.storage_backend ?? metadata.key_store),
    storageReference: nullableStr(metadata.storage_reference),
    entropySource: null,
    exportable: null,
    hsmBackedDeclared: typeof metadata.hsm_backed === 'boolean' ? (metadata.hsm_backed as boolean) : null,
    rotationIntervalDays: null,
    version: null,
    createdAt: iso(row.not_before ?? row.created_at),
    activatedAt: iso(row.not_before),
    lastUsedAt: null,
    lastRotatedAt: null,
    expiresAt: iso(row.not_after ?? row.expires_at),
    decommissionedAt: null,
    metadata,
  }
}

function fromScannerEvidence(row: Row, assetEnvironment: string): KeyObservation {
  const metadata = record(row.metadata ?? row.details)
  return {
    table: 'scanner_evidence',
    recordId: str(row.id),
    writable: false,
    source: 'agent-scan',
    evidenceDetail: `Key material observed by an agent scan: ${str(row.summary ?? row.description ?? row.evidence_type, 'agent observation')}.`,
    observedAt: iso(row.observed_at ?? row.created_at),
    scanId: nullableStr(row.scan_id ?? row.session_id ?? metadata.scan_id),
    identityAnchor: nullableStr(metadata.serial_number ?? metadata.serial),
    alias: nullableStr(row.name ?? metadata.key_alias),
    algorithm: str(row.algorithm ?? metadata.algorithm),
    keySize: positiveNum(row.key_size ?? metadata.key_size),
    fingerprint: nullableStr(metadata.fingerprint ?? row.fingerprint),
    status: str(row.status, 'observed'),
    owner: nullableStr(metadata.owner),
    assetId: nullableStr(row.asset_id),
    certificateId: nullableStr(metadata.certificate_id),
    environment: environmentOf(metadata.environment, assetEnvironment),
    purpose: str(metadata.purpose),
    backendHint: str(metadata.storage_backend ?? metadata.location ?? row.location ?? row.file_path),
    storageReference: nullableStr(row.file_path ?? metadata.storage_reference),
    entropySource: nullableStr(metadata.entropy_source),
    exportable: typeof metadata.exportable === 'boolean' ? (metadata.exportable as boolean) : null,
    hsmBackedDeclared: null,
    rotationIntervalDays: null,
    version: null,
    // Observation time, not key creation time — see `fromCryptoInventory`.
    createdAt: iso(metadata.created_at ?? metadata.key_created_at),
    activatedAt: null,
    lastUsedAt: iso(row.observed_at),
    lastRotatedAt: iso(metadata.last_rotated_at),
    expiresAt: iso(metadata.expires_at),
    decommissionedAt: null,
    metadata,
  }
}

/* ------------------------------------------------------------------ */
/* Merge                                                               */
/* ------------------------------------------------------------------ */

/** Sources that OBSERVED the key, as opposed to declaring or generating it. */
const OBSERVED_TABLES = new Set(['certificates', 'crypto_inventory', 'scanner_evidence'])

/** Registry rows win over discoveries; discoveries fill gaps registry lacks. */
const SOURCE_PRIORITY: Record<string, number> = {
  qkms_keys: 5,
  generated_keys: 4,
  certificates: 3,
  crypto_inventory: 2,
  scanner_evidence: 1,
}

function mergeObservations(observations: KeyObservation[]): KeyObservation {
  const ordered = [...observations].sort((a, b) =>
    (SOURCE_PRIORITY[b.table] || 0) - (SOURCE_PRIORITY[a.table] || 0)
    || (dateMs(b.observedAt) ?? 0) - (dateMs(a.observedAt) ?? 0))

  const primary = ordered[0]
  const pick = <K extends keyof KeyObservation>(field: K): KeyObservation[K] => {
    for (const observation of ordered) {
      const value = observation[field]
      if (value !== null && value !== undefined && value !== '') return value
    }
    return primary[field]
  }

  return {
    ...primary,
    identityAnchor: pick('identityAnchor'),
    alias: pick('alias'),
    algorithm: str(pick('algorithm')),
    keySize: pick('keySize'),
    fingerprint: pick('fingerprint'),
    owner: pick('owner'),
    assetId: pick('assetId'),
    certificateId: pick('certificateId'),
    // `unknown` is the environment fallback, so prefer any source that resolved one.
    environment: ordered.find((row) => row.environment !== 'unknown')?.environment || 'unknown',
    purpose: str(pick('purpose')),
    backendHint: str(pick('backendHint')),
    storageReference: pick('storageReference'),
    entropySource: pick('entropySource'),
    exportable: ordered.find((row) => row.exportable !== null)?.exportable ?? null,
    hsmBackedDeclared: ordered.find((row) => row.hsmBackedDeclared !== null)?.hsmBackedDeclared ?? null,
    rotationIntervalDays: pick('rotationIntervalDays'),
    version: pick('version'),
    createdAt: ordered.map((row) => row.createdAt).filter(Boolean).sort()[0] || null,
    activatedAt: pick('activatedAt'),
    lastUsedAt: latest(...ordered.map((row) => row.lastUsedAt)),
    lastRotatedAt: latest(...ordered.map((row) => row.lastRotatedAt)),
    expiresAt: pick('expiresAt'),
    decommissionedAt: pick('decommissionedAt'),
    observedAt: latest(...ordered.map((row) => row.observedAt)),
    metadata: ordered.reduce<Row>((acc, row) => ({ ...row.metadata, ...acc }), {}),
  }
}

const PLACEHOLDER_RISK: KeyRiskAssessment = {
  score: 0,
  level: 'none',
  factors: [],
  drivers: [],
  recommendedAction: '',
  confidence: 0,
  evidence: [],
}

/* ------------------------------------------------------------------ */
/* Rotation jobs                                                       */
/* ------------------------------------------------------------------ */

export function normaliseJobStatus(value: string): RotationJobStatus {
  const text = value.toLowerCase()
  if (/cancel/.test(text)) return 'cancelled'
  if (/fail|error/.test(text)) return 'failed'
  if (/complete|done|success|closed/.test(text)) return 'completed'
  if (/valid/.test(text)) return 'awaiting-validation'
  if (/progress|running|executing|active/.test(text)) return 'in-progress'
  if (/approv/.test(text)) return 'approved'
  return 'requested'
}

const TERMINAL_JOB: RotationJobStatus[] = ['completed', 'failed', 'cancelled']

/* ------------------------------------------------------------------ */
/* The assembler                                                       */
/* ------------------------------------------------------------------ */

export function buildQkmsIntelligence(inputs: QkmsInputs): QkmsIntelligence {
  const now = inputs.now ?? Date.now()
  const nowIso = new Date(now).toISOString()

  /* ---- Asset index --------------------------------------------- */
  const assetById = new Map<string, Row>()
  for (const asset of inputs.assets) {
    const id = str(asset.id)
    if (id) assetById.set(id, asset)
  }
  const assetEnvironment = (assetId: string | null): string => {
    if (!assetId) return 'unknown'
    const asset = assetById.get(assetId)
    return asset ? environmentOf(asset.environment) : 'unknown'
  }
  const assetLabel = (assetId: string | null): string | null => {
    if (!assetId) return null
    const asset = assetById.get(assetId)
    return asset ? str(asset.name) || null : null
  }
  const assetOwner = (assetId: string | null): string | null => {
    if (!assetId) return null
    const asset = assetById.get(assetId)
    if (!asset) return null
    const metadata = record(asset.metadata)
    return nullableStr(asset.service_owner ?? asset.owner ?? metadata.owner ?? metadata.team)
  }

  /* ---- Collect observations ------------------------------------ */
  const observations: KeyObservation[] = []

  for (const row of inputs.qkmsKeys) observations.push(fromQkmsKey(row))
  for (const row of inputs.generatedKeys) observations.push(fromGeneratedKey(row))

  /*
   * `crypto_inventory` is the CBOM — a register of cryptographic COMPONENTS
   * observed on an asset. Only the rows that identify key MATERIAL become keys;
   * a protocol version, a cipher suite or a finding title is an observation
   * about cryptography, not a key to govern.
   */
  for (const row of inputs.cryptoInventory) {
    const metadata = record(row.metadata)
    if (!namesKeyMaterial({
      itemType: str(row.item_type),
      name: str(row.name),
      algorithm: str(row.algorithm),
      fingerprint: str(metadata.fingerprint ?? metadata.fingerprint_sha256),
    })) continue
    observations.push(fromCryptoInventory(row, assetEnvironment(nullableStr(row.asset_id))))
  }

  for (const row of inputs.certificates) {
    observations.push(fromCertificate(row, assetEnvironment(nullableStr(row.asset_id))))
  }

  for (const row of inputs.scannerEvidence) {
    const metadata = record(row.metadata ?? row.details)
    if (!namesKeyMaterial({
      itemType: str(row.evidence_type),
      name: str(row.name ?? row.summary ?? row.description),
      algorithm: str(row.algorithm ?? metadata.algorithm),
      fingerprint: str(metadata.fingerprint ?? row.fingerprint),
    })) continue
    observations.push(fromScannerEvidence(row, assetEnvironment(nullableStr(row.asset_id))))
  }

  /* ---- Group by canonical identity ----------------------------- */
  const grouped = new Map<string, KeyObservation[]>()
  for (const observation of observations) {
    const id = identityFor(observation)
    const bucket = grouped.get(id)
    if (bucket) bucket.push(observation)
    else grouped.set(id, [observation])
  }

  /* ---- Version chains ------------------------------------------ */
  const versionsByKeyRef = new Map<string, Row[]>()
  for (const row of inputs.qkmsKeyVersions) {
    const ref = str(row.key_ref)
    if (!ref) continue
    const bucket = versionsByKeyRef.get(ref)
    if (bucket) bucket.push(row)
    else versionsByKeyRef.set(ref, [row])
  }

  /* ---- Rotation jobs indexed by canonical key ref --------------- */
  const jobsByKeyRef = new Map<string, Row[]>()
  for (const row of inputs.qkmsRotationJobs) {
    // `key_ref` carries the canonical id; `key_id` is the legacy UUID column,
    // which could only ever address rows whose id happened to be a UUID and so
    // silently detached jobs from derived keys. Schemas without the key_ref
    // column carry it in evidence_json — the same resolution the job list uses.
    const ref = str(row.key_ref) || str(record(row.evidence_json).key_ref) || str(row.key_id)
    if (!ref) continue
    const bucket = jobsByKeyRef.get(ref)
    if (bucket) bucket.push(row)
    else jobsByKeyRef.set(ref, [row])
  }

  /* ---- Audit events indexed by key ------------------------------ */
  const auditByKeyRef = new Map<string, Row[]>()
  for (const row of inputs.qkmsAuditEvents) {
    const ref = str(row.key_ref) || str(row.key_id)
    if (!ref) continue
    const bucket = auditByKeyRef.get(ref)
    if (bucket) bucket.push(row)
    else auditByKeyRef.set(ref, [row])
  }

  /* ---- Runtime usage index -------------------------------------- */
  /*
   * Attribution rule: an event counts toward a key only when it happened on
   * the SAME ASSET and names the SAME algorithm family. The predecessor matched
   * `text.includes(algorithm.toLowerCase())` across every event in the tenant,
   * so one AES-256-GCM event was attributed to every AES key in the estate at
   * once. A key with no asset binding gets `null` — unattributable, not zero.
   */
  const runtimeByAssetFamily = new Map<string, number>()
  const runtimeAssets = new Set<string>()
  let latestRuntimeAt: string | null = null
  for (const event of inputs.runtimeEvents) {
    const assetId = str(event.asset_id)
    const algorithm = str(event.algorithm) || str(event.key_exchange_algorithm) || str(event.cipher_suite)
    latestRuntimeAt = latest(latestRuntimeAt, rowTimestamp(event))
    if (!assetId || !algorithm) continue
    runtimeAssets.add(assetId)
    const family = classifyKey(algorithm).family
    const slot = `${assetId}::${family}`
    runtimeByAssetFamily.set(slot, (runtimeByAssetFamily.get(slot) || 0) + 1)
  }

  /* ---- Certificates by asset ------------------------------------ */
  const certsByAsset = new Map<string, Row[]>()
  for (const cert of inputs.certificates) {
    const assetId = str(cert.asset_id)
    if (!assetId) continue
    const bucket = certsByAsset.get(assetId)
    if (bucket) bucket.push(cert)
    else certsByAsset.set(assetId, [cert])
  }

  /* ---- Migration jobs by asset ----------------------------------- */
  const migrationByAsset = new Map<string, Row[]>()
  for (const job of inputs.migrationJobs) {
    const assetId = str(job.asset_id)
    if (!assetId) continue
    const bucket = migrationByAsset.get(assetId)
    if (bucket) bucket.push(job)
    else migrationByAsset.set(assetId, [job])
  }

  /* ---- Build managed keys ---------------------------------------- */
  const keys: ManagedKey[] = []

  for (const [id, group] of grouped) {
    const merged = mergeObservations(group)

    /*
     * Posture evidence (audit brief §3F). The registry wins every OTHER field —
     * owner, alias, custody are the tenant's to declare — but not the
     * algorithm: a registry row can only DECLARE one. The algorithm that decides
     * posture is the one this platform generated, else the newest one a source
     * actually observed; a declaration decides it only when nothing observed the
     * key, and is then marked unverified. Letting the declaration win published
     * a key the scanner saw as RSA-2048 as post-quantum because its registry
     * entry said "ML-KEM-768".
     */
    const generatedObservation = group.find((row) => row.table === 'generated_keys' && row.algorithm)
    const observedObservation = group
      .filter((row) => OBSERVED_TABLES.has(row.table) && row.algorithm)
      .sort((a, b) => (SOURCE_PRIORITY[b.table] || 0) - (SOURCE_PRIORITY[a.table] || 0)
        || (dateMs(b.observedAt) ?? 0) - (dateMs(a.observedAt) ?? 0))[0]
    const declaredObservation = group.find((row) => row.table === 'qkms_keys' && row.algorithm)
    const evidenced = generatedObservation || observedObservation || null
    const postureEvidence: PostureEvidence = generatedObservation
      ? 'generated'
      : observedObservation ? 'observed' : declaredObservation ? 'declared' : 'none'
    if (evidenced) {
      merged.algorithm = evidenced.algorithm
      merged.keySize = evidenced.keySize ?? merged.keySize
    }
    const algorithmConflict = declaredObservation && evidenced
      && classifyKey(declaredObservation.algorithm).family !== classifyKey(evidenced.algorithm).family
      ? { declared: declaredObservation.algorithm, observed: evidenced.algorithm }
      : null

    if (!merged.algorithm && !merged.alias) continue

    const classification = classifyKey(
      merged.algorithm,
      merged.keySize,
      `${merged.purpose} ${merged.alias || ''}`,
      // Certificate-borne whenever ANY source is a certificate — a registered
      // certificate key has the registry, not the certificate, as its primary.
      group.some((row) => row.table === 'certificates') ? 'certificate' : '',
    )

    const custodyHints = [
      merged.storageReference || '',
      merged.entropySource || '',
      str(merged.metadata.location),
      merged.table === 'generated_keys' ? 'QGuard platform vault' : '',
    ].join(' ')
    const custody = classifyCustody(merged.backendHint, custodyHints)
    const hsmBacked = merged.hsmBackedDeclared === true || custody.hsmBacked

    const owner = merged.owner || assetOwner(merged.assetId)
    const assetName = assetLabel(merged.assetId)
    const environment = merged.environment !== 'unknown'
      ? merged.environment
      : assetEnvironment(merged.assetId)

    /* Runtime usage — null when unattributable. */
    const runtimeUsage = merged.assetId && runtimeAssets.has(merged.assetId)
      ? runtimeByAssetFamily.get(`${merged.assetId}::${classification.family}`) ?? 0
      : null

    /* Linked certificates. */
    const linkedCertRows = merged.certificateId
      ? inputs.certificates.filter((cert) => str(cert.id) === merged.certificateId)
      : merged.assetId
        ? (certsByAsset.get(merged.assetId) || []).filter((cert) =>
          classifyKey(str(cert.algorithm ?? cert.public_key_algorithm)).family === classification.family)
        : []

    const linkedCertificates = linkedCertRows.slice(0, 12).map((cert) => ({
      id: str(cert.id),
      subject: str(cert.subject, str(cert.name, 'Certificate')),
      algorithm: str(cert.algorithm ?? cert.public_key_algorithm, 'Unknown'),
      expiresAt: iso(cert.not_after ?? cert.expires_at),
      status: str(cert.status, 'observed'),
    }))

    /* Linked migration jobs. */
    const migrationRows = merged.assetId ? migrationByAsset.get(merged.assetId) || [] : []
    const linkedMigrationJobs = migrationRows.slice(0, 8).map((job) => ({
      id: str(job.id),
      status: str(job.status, 'pending'),
      summary: `Migration ${str(job.algorithm_from, 'legacy')} → ${str(job.algorithm_to, 'target')}`,
      updatedAt: rowTimestamp(job),
    }))

    /* Rotation jobs bound to this key. */
    const jobRows = jobsByKeyRef.get(id) || []
    const jobStatuses = jobRows.map((job) => normaliseJobStatus(str(job.status)))
    const rotationInProgress = jobStatuses.some((status) => status === 'approved' || status === 'in-progress' || status === 'awaiting-validation' || status === 'requested')
    const rotationFailed = jobStatuses.length > 0
      && normaliseJobStatus(str([...jobRows].sort((a, b) => (dateMs(rowTimestamp(b)) ?? 0) - (dateMs(rowTimestamp(a)) ?? 0))[0].status)) === 'failed'

    /* Versions. */
    const versionRows = [...(versionsByKeyRef.get(id) || [])].sort((a, b) => (positiveNum(a.version) ?? 0) - (positiveNum(b.version) ?? 0))
    const versions: KeyVersion[] = versionRows.map((row, index) => ({
      id: `${id}#v${positiveNum(row.version) ?? index + 1}`,
      version: positiveNum(row.version) ?? index + 1,
      status: (str(row.status, 'unknown') as KeyVersion['status']),
      algorithm: str(row.algorithm, merged.algorithm),
      createdAt: iso(row.created_at),
      activatedAt: iso(row.activated_at),
      supersededAt: iso(row.superseded_at),
      previousVersionId: index > 0 ? `${id}#v${positiveNum(versionRows[index - 1].version) ?? index}` : null,
      evidence: {
        source: 'qkms-registry',
        table: 'qkms_key_versions',
        recordId: str(row.id),
        observedAt: iso(row.created_at),
        detail: `Version ${positiveNum(row.version) ?? index + 1} of this key.`,
      },
    }))

    const version = merged.version ?? (versions.length ? Math.max(...versions.map((row) => row.version)) : 1)
    if (!versions.length) {
      // Every key has at least the version currently in service. Synthesising
      // the chain would be a fabrication; recording the one we can see is not.
      versions.push({
        id: `${id}#v${version}`,
        version,
        status: 'active',
        algorithm: merged.algorithm,
        createdAt: merged.createdAt,
        activatedAt: merged.activatedAt,
        supersededAt: null,
        previousVersionId: null,
        evidence: null,
      })
    }

    /* Rotation applicability: a published hash has nothing to rotate. */
    const rotationApplicable = classification.keyClass !== 'hash-kdf'

    const lifecycleVerdict = resolveLifecycle({
      status: merged.status,
      createdAt: merged.createdAt,
      activatedAt: merged.activatedAt,
      lastUsedAt: merged.lastUsedAt,
      lastRotatedAt: merged.lastRotatedAt,
      expiresAt: merged.expiresAt,
      decommissionedAt: merged.decommissionedAt,
      rotationIntervalDays: merged.rotationIntervalDays,
      rotationInProgress,
      rotationFailed,
      deprecated: classification.deprecated,
      runtimeUsage,
      rotationApplicable,
      now,
    })

    /* Evidence: one ref per contributing row. */
    const evidence: QkmsEvidenceRef[] = group
      .sort((a, b) => (dateMs(b.observedAt) ?? 0) - (dateMs(a.observedAt) ?? 0))
      .slice(0, 8)
      .map((observation) => ({
        source: observation.source,
        table: observation.table,
        recordId: observation.recordId,
        observedAt: observation.observedAt,
        detail: observation.evidenceDetail,
        scanId: observation.scanId,
        telemetryId: null,
        findingId: null,
      }))

    const auditRows = [...(auditByKeyRef.get(id) || [])]
      .sort((a, b) => (dateMs(rowTimestamp(b)) ?? 0) - (dateMs(rowTimestamp(a)) ?? 0))
      .slice(0, 12)

    const records: KeyRecordRef[] = group.map((observation) => ({
      table: observation.table,
      recordId: observation.recordId,
      writable: observation.writable,
    }))

    const blastRadius = new Set([
      ...(merged.assetId ? [merged.assetId] : []),
      ...linkedCertificates.map((cert) => `cert:${cert.id}`),
      ...linkedMigrationJobs.map((job) => `job:${job.id}`),
    ]).size

    const alias = merged.alias
    const label = alias || `${classification.family} ${inferPurpose(classification).toLowerCase()}`
    const writable = records.some((row) => row.writable)
    const terminal = lifecycleVerdict.lifecycle === 'revoked'
      || lifecycleVerdict.lifecycle === 'decommissioned'
      || lifecycleVerdict.lifecycle === 'retired'

    const capabilities: KeyCapabilities = {
      // A work order can be raised against any live key: it governs the
      // operation, it does not claim to perform the cryptography. Not while one
      // is already open, though — two concurrent orders for one key would each
      // mint a version and race to validate the same material.
      requestRotation: !terminal && !rotationInProgress,
      // Recording an executed rotation mints a version record, which requires a
      // registry row this platform owns.
      recordRotation: !terminal,
      revoke: writable && !terminal,
      // Always available: when no registry row exists the backend materialises
      // one, which is how a scan-discovered key is brought under management.
      assignOwner: !terminal,
      decommission: writable && !terminal,
      reason: terminal
        ? 'The key is in a terminal lifecycle state; no further key operations are accepted.'
        : rotationInProgress
          ? 'A rotation work order is already open for this key; advance or close it before raising another.'
          : writable
          ? 'This key has a QKMS-owned record, so lifecycle operations write directly to it.'
          : 'This key was discovered by scan or telemetry. QKMS will create a governed registry record for it on the first write, and cannot mutate the discovery row itself.',
    }

    keys.push({
      id,
      label,
      alias,
      fingerprint: merged.fingerprint,
      records,
      sources: [...new Set(group.map((observation) => observation.source))],

      algorithm: merged.algorithm || 'Unknown',
      family: classification.family,
      keyClass: classification.keyClass,
      keyType: inferKeyType(classification, `${merged.alias || ''} ${merged.purpose} ${merged.backendHint} ${str(merged.metadata.key_type)}`),
      keySize: merged.keySize,
      purpose: merged.purpose || inferPurpose(classification),
      posture: classification.posture,
      migrationRequirement: classification.migrationRequirement,
      postureReason: [
        algorithmConflict
          ? `The registry declares ${algorithmConflict.declared}, but ${algorithmConflict.observed} was observed; the observed algorithm decides posture.`
          : '',
        classification.reason,
        postureEvidence === 'declared' && (classification.posture === 'post-quantum' || classification.posture === 'hybrid')
          ? 'This posture rests on a registry declaration only — no scan, certificate or platform record has verified the algorithm, so the key is not counted as PQC-ready.'
          : '',
      ].filter(Boolean).join(' '),
      postureEvidence,
      algorithmConflict,

      owner,
      assetId: merged.assetId,
      assetName,
      serviceName: nullableStr(merged.metadata.service ?? merged.metadata.service_name),
      applicationName: nullableStr(merged.metadata.application ?? merged.metadata.app),
      environment,
      certificateIds: linkedCertificates.map((cert) => cert.id),

      backend: custody.backend,
      custody: custody.custody,
      storageReference: merged.storageReference,
      hsmBacked,
      exportable: merged.exportable,
      entropySource: merged.entropySource,

      lifecycle: lifecycleVerdict.lifecycle,
      lifecycleReason: lifecycleVerdict.lifecycleReason,
      rotation: lifecycleVerdict.rotation,
      rotationReason: lifecycleVerdict.rotationReason,
      version,
      versions,
      createdAt: merged.createdAt,
      activatedAt: merged.activatedAt,
      lastUsedAt: merged.lastUsedAt,
      lastRotatedAt: merged.lastRotatedAt,
      nextRotationDueAt: lifecycleVerdict.nextRotationDueAt,
      expiresAt: merged.expiresAt,
      decommissionedAt: merged.decommissionedAt,
      ageDays: lifecycleVerdict.ageDays,
      daysToExpiry: lifecycleVerdict.daysToExpiry,

      runtimeUsage,
      linkedCertificates,
      linkedMigrationJobs,
      linkedRotationJobs: jobRows.map((job) => str(job.id)),
      blastRadius,

      violationIds: [],
      complianceStatus: 'not-evaluated',
      risk: PLACEHOLDER_RISK,
      capabilities,

      lastObservedAt: merged.observedAt,
      lastPolicyEvaluationAt: nowIso,
      evidence,
      auditTrail: auditRows.map((row) => ({
        id: str(row.id),
        eventType: str(row.event_type, 'audit_event'),
        summary: str(row.event_summary, str(row.description, 'QKMS audit event')),
        actor: str(row.actor_id, 'system'),
        at: rowTimestamp(row),
      })),
    })
  }

  /* ---- Policies -------------------------------------------------- */
  const tenantPolicies: QkmsPolicy[] = inputs.qkmsPolicies.map((row) => ({
    id: `policy:${str(row.id)}`,
    name: str(row.name, 'QKMS policy'),
    description: str(row.description, 'Tenant-authored QKMS policy.'),
    origin: 'tenant',
    enabled: row.enabled !== false,
    severity: (str(row.severity, 'medium') as Severity),
    environmentScope: str(row.environment_scope, 'all'),
    allowedAlgorithms: Array.isArray(row.allowed_algorithms) ? (row.allowed_algorithms as string[]) : [],
    blockedAlgorithms: Array.isArray(row.blocked_algorithms) ? (row.blocked_algorithms as string[]) : [],
    maxKeyAgeDays: positiveNum(row.max_key_age_days),
    rotationIntervalDays: positiveNum(row.rotation_interval_days),
    requireOwner: row.require_owner !== false,
    requireHsm: Boolean(row.require_hsm),
    allowExport: Boolean(row.allow_export),
    requirePqc: Boolean(row.require_pqc),
    owner: 'Tenant policy',
    keysInScope: 0,
    violations: 0,
    compliance: null,
    evaluation: 'no-keys-in-scope',
    updatedAt: iso(row.updated_at ?? row.created_at),
  }))

  const tenantNames = new Set(tenantPolicies.map((policy) => policy.name.toLowerCase()))
  const allPolicies = [
    ...tenantPolicies,
    ...baselinePolicies().filter((policy) => !tenantNames.has(policy.name.toLowerCase())),
  ]

  /* ---- Governance ------------------------------------------------ */
  const { violations, policies } = evaluateGovernance(keys, allPolicies, nowIso)

  const violationsByKey = new Map<string, GovernanceViolation[]>()
  for (const row of violations) {
    const bucket = violationsByKey.get(row.keyId)
    if (bucket) bucket.push(row)
    else violationsByKey.set(row.keyId, [row])
  }

  /* ---- Risk (after governance, so violations feed the score) ------ */
  const enabledPolicies = allPolicies.filter((policy) => policy.enabled)
  for (const key of keys) {
    const keyViolations = violationsByKey.get(key.id) || []
    key.violationIds = keyViolations.map((row) => row.id)
    /*
     * "Compliant" means at least one ENABLED policy covers this key and none of
     * them found a violation. Every key carries evidence (it was observed), so
     * the previous `evidence.length ? 'compliant'` marked every key compliant
     * even with every policy switched off — compliance implied by existence.
     */
    const covered = enabledPolicies.some((policy) => policyCoversKey(policy, key))
    key.complianceStatus = keyViolations.length
      ? 'violation'
      : !covered
        ? 'not-evaluated'
        : key.evidence.length || key.auditTrail.length
          ? 'compliant'
          : 'evidence-required'

    const classification = classifyKey(key.algorithm, key.keySize, key.purpose)
    key.risk = assessKeyRisk({
      algorithm: key.algorithm,
      family: key.family,
      keyClass: key.keyClass,
      posture: key.posture,
      migrationRequirement: key.migrationRequirement,
      deprecated: classification.deprecated,
      securityBits: classification.securityBits,
      lifecycle: key.lifecycle,
      lifecycleReason: key.lifecycleReason,
      rotation: key.rotation,
      rotationReason: key.rotationReason,
      ageDays: key.ageDays,
      daysToExpiry: key.daysToExpiry,
      owner: key.owner,
      environment: key.environment,
      custody: key.custody,
      backend: key.backend,
      hsmBacked: key.hsmBacked,
      exportable: key.exportable,
      runtimeUsage: key.runtimeUsage,
      blastRadius: key.blastRadius,
      certificateCount: key.linkedCertificates.length,
      violations: keyViolations,
      evidence: key.evidence,
    })
  }

  keys.sort((a, b) => b.risk.score - a.risk.score || (dateMs(b.lastObservedAt) ?? 0) - (dateMs(a.lastObservedAt) ?? 0))

  const keyById = new Map(keys.map((key) => [key.id, key]))

  /* ---- Storage backends & entropy --------------------------------- */
  const declaredBackends = inputs.qkmsStorageBackends.map((row) => ({
    id: str(row.id),
    name: str(row.name, str(row.provider, 'Storage backend')),
    provider: str(row.provider, str(row.name, 'Storage backend')),
    location: str(row.location, 'Tenant default'),
    protectionLevel: str(row.protection_level),
    hsmBacked: Boolean(row.hsm_backed),
    status: str(row.status, 'configured'),
    lastVerifiedAt: iso(row.last_verified_at ?? row.updated_at),
  }))
  const backends = buildBackendPosture(keys, violations, declaredBackends)
  const entropy = buildEntropyPosture(
    keys,
    inputs.qrngEvents.map((row) => ({ id: str(row.id), algorithm: row.algorithm, created_at: row.created_at })),
    backends,
    nowIso,
  )

  /* ---- Rotation jobs ---------------------------------------------- */
  const jobs: RotationJob[] = inputs.qkmsRotationJobs.map((row) => {
    const evidenceJson = record(row.evidence_json)
    // Schemas without the key_ref column carry it inside evidence_json instead.
    const keyRef = str(row.key_ref) || str(evidenceJson.key_ref) || str(row.key_id) || null
    const key = keyRef ? keyById.get(keyRef) || null : null
    const status = normaliseJobStatus(str(row.status))
    const validationStatus = ((): RotationJob['validationStatus'] => {
      const declared = str(row.validation_status).toLowerCase()
      if (/pass/.test(declared)) return 'passed'
      if (/fail/.test(declared)) return 'failed'
      if (/pending|await/.test(declared)) return 'pending'
      if (status === 'completed') return 'pending'
      if (status === 'awaiting-validation') return 'pending'
      return 'not-started'
    })()

    return {
      id: `job:${str(row.id)}`,
      keyId: keyRef,
      keyLabel: key?.label || str(evidenceJson.key_label, keyRef || 'Unresolved key'),
      owner: key?.owner || nullableStr(row.requested_by),
      assetName: key?.assetName || null,
      status,
      reason: str(row.reason, 'QKMS rotation work order'),
      priority: (['critical', 'high', 'medium', 'low'].includes(str(evidenceJson.priority))
        ? str(evidenceJson.priority)
        : key && key.risk.score >= 80 ? 'critical' : key && key.risk.score >= 60 ? 'high' : 'medium') as RotationJob['priority'],
      previousVersion: positiveNum(row.previous_version),
      newVersion: positiveNum(row.new_version),
      requestedBy: nullableStr(row.requested_by),
      approvedBy: nullableStr(row.approved_by),
      requestedAt: iso(row.created_at),
      startedAt: iso(row.started_at),
      completedAt: iso(row.completed_at),
      failureReason: nullableStr(row.failure_reason),
      validationStatus,
      validationDetail: str(row.validation_detail, validationStatus === 'passed'
        ? 'Post-rotation validation evidence is attached.'
        : validationStatus === 'failed'
          ? 'Post-rotation validation failed; the previous version may still be in service.'
          : validationStatus === 'pending'
            ? 'The work order is complete but post-rotation validation evidence has not been attached.'
            : 'Validation has not started.'),
      auditEventIds: (auditByKeyRef.get(keyRef || '') || []).map((event) => str(event.id)).slice(0, 6),
      evidence: [{
        source: 'rotation-job' as QkmsEvidenceSource,
        table: 'qkms_rotation_jobs',
        recordId: str(row.id),
        observedAt: rowTimestamp(row),
        detail: str(row.reason, 'QKMS rotation work order'),
      }],
      allowedTransitions: ROTATION_TRANSITIONS[status] || [],
    }
  }).sort((a, b) => (dateMs(b.requestedAt) ?? 0) - (dateMs(a.requestedAt) ?? 0))

  /* ---- Counts (one unit each) -------------------------------------- */
  const lifecycleCounts = LIFECYCLE_ORDER.reduce<Record<LifecycleState, number>>((acc, state) => {
    acc[state] = 0
    return acc
  }, {} as Record<LifecycleState, number>)
  const rotationCounts: Record<RotationState, number> = {
    healthy: 0, due: 0, overdue: 0, 'in-progress': 0, failed: 0,
    blocked: 0, 'never-rotated': 0, 'not-applicable': 0, unknown: 0,
  }
  for (const key of keys) {
    lifecycleCounts[key.lifecycle] += 1
    rotationCounts[key.rotation] += 1
  }

  const live = keys.filter((key) => key.lifecycle !== 'revoked' && key.lifecycle !== 'decommissioned' && key.lifecycle !== 'retired')
  const governedRotation = keys.filter((key) => ROTATION_GOVERNED.includes(key.rotation))
  const custodyScope = live.filter((key) => key.custody !== 'unknown')

  const auditRecords: AuditEvidenceRecord[] = [
    ...inputs.qkmsAuditEvents.map((row) => {
      const keyRef = str(row.key_ref) || str(row.key_id) || null
      return {
        id: `audit:qkms:${str(row.id)}`,
        title: str(row.event_summary, str(row.event_type, 'QKMS lifecycle event')),
        eventType: str(row.event_type, 'audit_event'),
        actor: str(row.actor_id, 'system'),
        keyId: keyRef,
        keyLabel: keyRef ? keyById.get(keyRef)?.label ?? null : null,
        at: rowTimestamp(row),
        source: 'qkms-audit' as QkmsEvidenceSource,
        table: 'qkms_audit_events',
        before: row.before_json ?? null,
        after: row.after_json ?? null,
      }
    }),
    ...inputs.vaultAuditLogs.slice(0, 40).map((row) => ({
      id: `audit:vault:${str(row.id)}`,
      title: str(row.event_type, 'Vault custody event'),
      eventType: str(row.event_type, 'vault_event'),
      actor: str(row.actor_id ?? row.user_id, 'system'),
      keyId: null,
      keyLabel: null,
      at: rowTimestamp(row),
      source: 'vault-audit' as QkmsEvidenceSource,
      table: 'vault_audit_logs',
      before: null,
      after: null,
    })),
    ...inputs.complianceEvidence.slice(0, 40).map((row) => ({
      id: `audit:compliance:${str(row.id)}`,
      title: `${str(row.framework, 'Compliance')} ${str(row.control_id)}`.trim(),
      eventType: 'compliance_evidence',
      actor: str(row.collected_by ?? row.user_id, 'system'),
      keyId: null,
      keyLabel: null,
      at: rowTimestamp(row),
      source: 'compliance-evidence' as QkmsEvidenceSource,
      table: 'compliance_evidence',
      before: null,
      after: null,
    })),
  ].sort((a, b) => (dateMs(b.at) ?? 0) - (dateMs(a.at) ?? 0)).slice(0, 120)

  /* ---- Readiness & gate -------------------------------------------- */
  const openMigrationJobs = inputs.migrationJobs.filter((job) => !/complete|done|failed|cancel/i.test(str(job.status))).length
  const completedMigrationJobs = inputs.migrationJobs.filter((job) => /complete|done/i.test(str(job.status))).length
  const openRotationJobs = jobs.filter((job) => !TERMINAL_JOB.includes(job.status)).length
  const unvalidatedRotationJobs = jobs.filter((job) => job.status === 'completed' && job.validationStatus !== 'passed').length

  /*
   * Evidence of KEY OPERATIONS is the QKMS audit trail. Vault custody logs and
   * compliance documents are listed alongside it, but counting them here let an
   * uploaded compliance PDF satisfy "audit evidence is available" — and with it
   * the MIGRATED gate state — for keys no QKMS operation ever touched.
   */
  const keyOperationAuditCount = inputs.qkmsAuditEvents.length
  const prechecks = buildPrechecks(keys, violations, keyOperationAuditCount)
  const gate = buildMigrationGate(keys, prechecks, {
    openMigrationJobs,
    completedMigrationJobs,
    openRotationJobs,
    unvalidatedRotationJobs,
    auditRecordCount: keyOperationAuditCount,
    evidence: keys.slice(0, 4).flatMap((key) => key.evidence.slice(0, 1)),
    nowIso,
  })
  const readiness = buildReadiness(keys, prechecks, gate)

  /* ---- Rotation posture --------------------------------------------- */
  const terminalJobs = jobs.filter((job) => TERMINAL_JOB.includes(job.status))
  const rotationPosture: RotationPosture = {
    governedKeys: governedRotation.length,
    healthy: rotationCounts.healthy,
    due: rotationCounts.due,
    overdue: rotationCounts.overdue,
    inProgress: rotationCounts['in-progress'],
    failed: rotationCounts.failed,
    neverRotated: rotationCounts['never-rotated'],
    healthPercent: governedRotation.length
      ? Math.round((rotationCounts.healthy / governedRotation.length) * 100)
      : null,
    successRate: terminalJobs.length
      ? Math.round((jobs.filter((job) => job.status === 'completed').length / terminalJobs.length) * 100)
      : null,
    jobsTotal: jobs.length,
    jobsActive: openRotationJobs,
    jobsCompleted: jobs.filter((job) => job.status === 'completed').length,
    jobsFailed: jobs.filter((job) => job.status === 'failed').length,
    blastRadius: keys
      .filter((key) => key.rotation === 'due' || key.rotation === 'overdue' || key.rotation === 'failed')
      .reduce((sum, key) => sum + key.blastRadius, 0),
    nextDueAt: keys
      .map((key) => key.nextRotationDueAt)
      .filter((value): value is string => Boolean(value) && (dateMs(value) ?? 0) > now)
      .sort()[0] || null,
  }

  /* ---- Risk aggregates ----------------------------------------------- */
  const riskDistribution: DistributionRow[] = (['critical', 'high', 'medium', 'low', 'none'] as const).map((level) => {
    const matching = keys.filter((key) => key.risk.level === level)
    return {
      label: level === 'none'
        ? 'Minimal (0–14)'
        : level === 'low' ? 'Low (15–34)'
          : level === 'medium' ? 'Medium (35–59)'
            : level === 'high' ? 'High (60–79)' : 'Critical (80–100)',
      count: matching.length,
      percent: keys.length ? Math.round((matching.length / keys.length) * 100) : 0,
      keyIds: matching.map((key) => key.id).slice(0, 200),
    }
  })

  const factorAverages = RISK_WEIGHTS.map((weight) => {
    const factors = keys.map((key) => key.risk.factors.find((factor) => factor.key === weight.key)).filter(Boolean)
    const measured = factors.filter((factor) => factor!.measured)
    return {
      key: weight.key as RiskFactorKey,
      label: weight.label,
      weight: weight.weight,
      average: factors.length ? Math.round(factors.reduce((sum, factor) => sum + factor!.score, 0) / factors.length) : 0,
      measuredKeys: measured.length,
    }
  })

  const remediation = keys
    .filter((key) => key.risk.score >= 35)
    .slice(0, 25)
    .map((key) => ({
      keyId: key.id,
      keyLabel: key.label,
      action: key.risk.recommendedAction,
      score: key.risk.score,
      level: key.risk.level,
      rationale: key.risk.drivers[0] || key.postureReason,
    }))

  /* ---- Telemetry health ----------------------------------------------- */
  const agentsOnline = inputs.scannerAgents.filter((agent) => /online|active|healthy|connected/i.test(str(agent.status))).length
  const connectorsActive = inputs.connectorAccounts.filter((row) => /active|connected|healthy|synced|ok/i.test(str(row.status))).length
  const runningScans = inputs.scanSessions.filter((row) => /running|in_progress|scanning|queued/i.test(str(row.status))).length
  const lastScanAt = latest(...inputs.scanSessions.map(rowTimestamp))

  const sourceSpecs: Array<{ id: string; label: string; table: string; rows: Row[] }> = [
    { id: 'qkms_keys', label: 'QKMS registry', table: 'qkms_keys', rows: inputs.qkmsKeys },
    { id: 'generated_keys', label: 'Generated keys', table: 'generated_keys', rows: inputs.generatedKeys },
    { id: 'crypto_inventory', label: 'Crypto inventory', table: 'crypto_inventory', rows: inputs.cryptoInventory },
    { id: 'certificates', label: 'Certificates', table: 'certificates', rows: inputs.certificates },
    { id: 'scanner_evidence', label: 'Scanner evidence', table: 'scanner_evidence', rows: inputs.scannerEvidence },
    { id: 'runtime_crypto_events', label: 'Runtime telemetry', table: 'runtime_crypto_events', rows: inputs.runtimeEvents },
    { id: 'qkms_rotation_jobs', label: 'Rotation work orders', table: 'qkms_rotation_jobs', rows: inputs.qkmsRotationJobs },
    { id: 'qkms_policies', label: 'QKMS policies', table: 'qkms_policies', rows: inputs.qkmsPolicies },
    { id: 'qkms_audit_events', label: 'QKMS audit', table: 'qkms_audit_events', rows: inputs.qkmsAuditEvents },
    { id: 'qkms_storage_backends', label: 'Storage backends', table: 'qkms_storage_backends', rows: inputs.qkmsStorageBackends },
    { id: 'qrng_events', label: 'Entropy events', table: 'qrng_events', rows: inputs.qrngEvents },
    { id: 'migration_jobs', label: 'Migration jobs', table: 'migration_jobs', rows: inputs.migrationJobs },
    { id: 'compliance_evidence', label: 'Compliance evidence', table: 'compliance_evidence', rows: inputs.complianceEvidence },
    { id: 'vault_audit_logs', label: 'Vault audit', table: 'vault_audit_logs', rows: inputs.vaultAuditLogs },
  ]

  const STALE_MS = 7 * ONE_DAY_MS
  const sources = sourceSpecs.map((spec) => {
    const latestAt = latest(...spec.rows.map(rowTimestamp))
    const latestMs = dateMs(latestAt)
    return {
      id: spec.id,
      label: spec.label,
      table: spec.table,
      count: spec.rows.length,
      latestAt,
      status: (spec.rows.length === 0
        ? 'waiting'
        : latestMs !== null && now - latestMs <= STALE_MS
          ? 'live'
          : 'stale') as 'live' | 'stale' | 'waiting',
    }
  })

  const liveSources = sources.filter((source) => source.status === 'live').length
  const observedSources = sources.filter((source) => source.count > 0).length
  const pipelineStatus: PipelineStatus = runningScans > 0
    ? 'scan-running'
    : liveSources >= 3
      ? 'active'
      : liveSources > 0
        ? 'partial'
        : observedSources > 0
          ? 'stale'
          : inputs.scannerAgents.length || inputs.connectorAccounts.length
            ? 'awaiting-key-evidence'
            : 'no-sources'

  const telemetry: QkmsTelemetryHealth = {
    pipelineStatus,
    agentsOnline,
    agentsTotal: inputs.scannerAgents.length,
    connectorsActive,
    connectorsTotal: inputs.connectorAccounts.length,
    runningScans,
    lastScanAt,
    lastRuntimeEventAt: latestRuntimeAt,
    lastKeyEventAt: latest(...keys.map((key) => key.lastObservedAt)),
    lastRotationAt: latest(...jobs.map((job) => job.completedAt ?? job.startedAt ?? job.requestedAt)),
    lastPolicyEvaluationAt: nowIso,
    sourceCounts: Object.fromEntries(sources.map((source) => [source.table, source.count])),
    sources,
    truncated: inputs.truncated,
    absentSources: sources.filter((source) => source.count === 0).map((source) => source.label),
    degradedSources: inputs.degradedSources || [],
  }

  /* ---- Metrics --------------------------------------------------------- */
  const keysWithViolations = new Set(violations.map((row) => row.keyId)).size
  const riskScores = keys.map((key) => key.risk.score)

  const metrics: QkmsMetrics = {
    totalKeys: keys.length,
    activeKeys: lifecycleCounts.active + lifecycleCounts['in-use'],
    inUseKeys: lifecycleCounts['in-use'],
    expiredKeys: lifecycleCounts.expired,
    expiringSoonKeys: keys.filter((key) => key.daysToExpiry !== null && key.daysToExpiry >= 0 && key.daysToExpiry <= EXPIRY_WARNING_DAYS).length,
    rotationDueKeys: rotationCounts.due,
    rotationOverdueKeys: rotationCounts.overdue,
    neverRotatedKeys: rotationCounts['never-rotated'],
    deprecatedKeys: keys.filter((key) => key.posture === 'deprecated').length,
    quantumVulnerableKeys: keys.filter((key) => key.posture === 'quantum-vulnerable').length,
    // Evidenced only: a registry declaration of ML-KEM is counted in declaredPqcKeys, not here.
    pqcReadyKeys: keys.filter((key) => key.posture === 'post-quantum' && isEvidenced(key)).length,
    hybridKeys: keys.filter((key) => key.posture === 'hybrid' && isEvidenced(key)).length,
    declaredPqcKeys: keys.filter((key) => (key.posture === 'post-quantum' || key.posture === 'hybrid') && !isEvidenced(key)).length,
    keysRequiringMigration: keys.filter((key) => key.migrationRequirement === 'required').length,
    orphanedKeys: live.filter((key) => !key.owner).length,
    unmanagedCustodyKeys: live.filter((key) => key.custody === 'unmanaged' || key.custody === 'unknown').length,
    hsmProtectedKeys: keys.filter((key) => key.hsmBacked).length,
    exportableProductionKeys: keys.filter((key) => key.exportable === true && key.environment === 'production').length,
    criticalRiskKeys: keys.filter((key) => key.risk.level === 'critical').length,
    highRiskKeys: keys.filter((key) => key.risk.level === 'high').length,

    governanceViolations: violations.length,
    keysWithViolations,

    auditEvidenceRecords: auditRecords.length,

    averageRiskScore: riskScores.length ? Math.round(riskScores.reduce((sum, value) => sum + value, 0) / riskScores.length) : null,
    // ONE readiness formula: the header figure is the Readiness page's headline.
    // A second inline definition here differed for deprecated keys of unknown
    // class, so Overview and Readiness could show two percentages for one estate.
    pqcReadinessPercent: readiness.overall,
    custodyCoveragePercent: custodyScope.length
      ? Math.round((custodyScope.filter((key) => isApprovedCustody(key.custody)).length / custodyScope.length) * 100)
      : null,
    // Audit readiness is the share of LIVE keys with at least one QKMS audit
    // record — a governed operation on file. It used to accept "any evidence",
    // and every key has evidence (that is how it was discovered), so the figure
    // was 100% by construction whatever had been audited.
    auditReadinessPercent: live.length
      ? Math.round((live.filter((key) => key.auditTrail.length > 0).length / live.length) * 100)
      : null,
    rotationHealthPercent: rotationPosture.healthPercent,
  }

  /* ---- Lifecycle projections ------------------------------------------- */
  const funnel = LIFECYCLE_ORDER
    .filter((state) => lifecycleCounts[state] > 0 || ['active', 'in-use', 'rotation-due', 'rotation-overdue'].includes(state))
    .map((state) => ({
      state,
      label: LIFECYCLE_LABEL[state],
      count: lifecycleCounts[state],
      percent: keys.length ? Math.round((lifecycleCounts[state] / keys.length) * 100) : 0,
      keyIds: keys.filter((key) => key.lifecycle === state).map((key) => key.id).slice(0, 200),
    }))

  const intelligence: QkmsIntelligence = {
    generatedAt: nowIso,
    latestEvidenceAt: latest(
      telemetry.lastKeyEventAt,
      telemetry.lastRuntimeEventAt,
      telemetry.lastScanAt,
      telemetry.lastRotationAt,
      ...auditRecords.slice(0, 5).map((row) => row.at),
    ),
    hasData: keys.length > 0,

    keys,
    metrics,

    lifecycle: {
      counts: lifecycleCounts,
      funnel,
      ageBuckets: distribution(keys.map((key) => ({ label: ageBucketOf(key.ageDays), keyId: key.id })), 8),
      expiryBuckets: distribution(keys.map((key) => ({ label: expiryBucketOf(key.daysToExpiry), keyId: key.id })), 8),
      attention: {
        expired: keys.filter((key) => key.lifecycle === 'expired').map((key) => key.id),
        expiringSoon: keys.filter((key) => key.daysToExpiry !== null && key.daysToExpiry >= 0 && key.daysToExpiry <= EXPIRY_WARNING_DAYS).map((key) => key.id),
        overdueRotation: keys.filter((key) => key.rotation === 'overdue' || key.rotation === 'failed').map((key) => key.id),
        neverRotated: keys.filter((key) => key.rotation === 'never-rotated').map((key) => key.id),
        longLived: keys.filter((key) => key.ageDays !== null && key.ageDays > LONG_LIVED_DAYS).map((key) => key.id),
        orphaned: live.filter((key) => !key.owner).map((key) => key.id),
        // "Unused" requires runtime measurement to exist and report nothing.
        // A key whose usage was never measured is not unused; it is unmeasured.
        unused: keys.filter((key) => key.runtimeUsage === 0).map((key) => key.id),
      },
    },

    governance: {
      policies,
      violations: violations.sort((a, b) => {
        const rank = (severity: Severity) => (severity === 'critical' ? 4 : severity === 'high' ? 3 : severity === 'medium' ? 2 : severity === 'low' ? 1 : 0)
        return rank(b.severity) - rank(a.severity) || a.keyLabel.localeCompare(b.keyLabel)
      }),
      violationsByRule: distribution(violations.map((row) => ({ label: ruleLabel(row.rule), keyId: row.keyId })), 12),
      violationsBySeverity: distribution(violations.map((row) => ({ label: row.severity, keyId: row.keyId })), 5),
      backends,
      entropy,
    },

    rotation: {
      posture: rotationPosture,
      jobs,
      queue: keys
        .filter((key) => key.rotation === 'overdue' || key.rotation === 'failed' || key.rotation === 'due' || key.rotation === 'never-rotated')
        .sort((a, b) => b.risk.score - a.risk.score)
        .map((key) => key.id),
      stateCounts: rotationCounts,
    },

    readiness,

    risk: {
      distribution: riskDistribution,
      factorAverages,
      ranked: keys.map((key) => key.id),
      remediation,
    },

    distributions: {
      algorithms: withPosture(distribution(keys.map((key) => ({ label: key.algorithm || 'Unknown', keyId: key.id })), 12), keyById),
      families: withPosture(distribution(keys.map((key) => ({ label: key.family, keyId: key.id })), 12), keyById),
      keyClasses: distribution(keys.map((key) => ({ label: key.keyType, keyId: key.id })), 10),
      owners: distribution(keys.map((key) => ({ label: key.owner || 'Unassigned', keyId: key.id })), 10),
      environments: distribution(keys.map((key) => ({ label: key.environment, keyId: key.id })), 6),
      custody: distribution(keys.map((key) => ({ label: key.backend, keyId: key.id })), 10),
      // A post-quantum or hybrid posture resting on a registry declaration alone is
      // its own row: it must not swell the evidenced Post-Quantum bar.
      postures: withPosture(distribution(keys.map((key) => ({
        label: isDeclaredPqc(key) ? `${postureLabel(key.posture)} (declared, unverified)` : postureLabel(key.posture),
        keyId: key.id,
      })), 8), keyById),
    },

    audit: auditRecords,
    telemetry,
  }

  return intelligence
}

/**
 * Tag each distribution row with the model's posture for the keys behind it
 * (the most common one). The pages coloured these rows by regex over the label,
 * which put Ed25519 and X25519 — Shor-breakable — in the neutral colour.
 */
function withPosture(rows: DistributionRow[], keyById: Map<string, ManagedKey>): DistributionRow[] {
  return rows.map((row) => {
    const counts = new Map<KeyPqcPosture, number>()
    for (const id of row.keyIds || []) {
      const posture = keyById.get(id)?.posture
      if (posture) counts.set(posture, (counts.get(posture) || 0) + 1)
    }
    const dominant = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0]
    const ids = row.keyIds || []
    const unverified = ids.length > 0 && ids.every((id) => {
      const key = keyById.get(id)
      return Boolean(key && isDeclaredPqc(key))
    })
    return dominant ? { ...row, posture: dominant, ...(unverified ? { unverified: true } : {}) } : row
  })
}

/** Post-quantum or hybrid by registry declaration only — no observation confirms it. */
function isDeclaredPqc(key: Pick<ManagedKey, 'posture' | 'postureEvidence'>): boolean {
  return (key.posture === 'post-quantum' || key.posture === 'hybrid') && key.postureEvidence === 'declared'
}

export function postureLabel(posture: KeyPqcPosture): string {
  switch (posture) {
    case 'post-quantum': return 'Post-Quantum'
    case 'hybrid': return 'Hybrid'
    case 'quantum-resistant-symmetric': return 'Quantum-Resistant Symmetric'
    case 'weakened-symmetric': return 'Weakened Symmetric'
    case 'quantum-vulnerable': return 'Quantum Vulnerable'
    case 'deprecated': return 'Deprecated'
    default: return 'Unknown'
  }
}

/** The light row every list projection ships instead of the full key. */
export function toIndexEntry(key: ManagedKey): KeyIndexEntry {
  return {
    id: key.id,
    label: key.label,
    algorithm: key.algorithm,
    family: key.family,
    keyClass: key.keyClass,
    keyType: key.keyType,
    owner: key.owner,
    assetName: key.assetName,
    environment: key.environment,
    backend: key.backend,
    custody: key.custody,
    posture: key.posture,
    migrationRequirement: key.migrationRequirement,
    lifecycle: key.lifecycle,
    rotation: key.rotation,
    version: key.version,
    createdAt: key.createdAt,
    lastUsedAt: key.lastUsedAt,
    lastRotatedAt: key.lastRotatedAt,
    expiresAt: key.expiresAt,
    daysToExpiry: key.daysToExpiry,
    riskScore: key.risk.score,
    riskLevel: key.risk.level,
    violations: key.violationIds.length,
    complianceStatus: key.complianceStatus,
    postureEvidence: key.postureEvidence,
    lastObservedAt: key.lastObservedAt,
  }
}

export { riskLevelOf }
