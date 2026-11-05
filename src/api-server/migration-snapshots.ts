import { Router, Request, Response, NextFunction } from 'express'
import { createHash, randomUUID } from 'node:crypto'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { namesCryptography } from '@/lib/scanner/finding-identity'
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'
import type {
  MigrationSnapshot,
  RollbackDisposition,
  SnapshotAuditEntry,
  SnapshotCryptoState,
  SnapshotDashboard,
  SnapshotExecutionRecord,
  SnapshotRestoreResult,
  SnapshotRollbackState,
} from '@/types/migration-snapshot'
import {
  AGENT_ROLLBACK_MIN_VERSION,
  AGENT_COORDINATION_MIN_VERSION,
  HEARTBEAT_ONLINE_WINDOW_MS,
  agentVersionAtLeast,
  type AgentRole,
} from '@/lib/agent-installer/agent-release'
import { enqueueAgentCommand } from './agent-command-queue'
import { agentMayWrite } from './agent-entitlement'
import { executeCloudConnectorRollback } from './cloud-patch-adapters'

/**
 * Migration Snapshot Management™.
 *
 * Captures a complete, integrity-verified snapshot of an asset's cryptographic
 * + configuration state BEFORE any migration/remediation runs, so every change
 * is fully reversible. Pre-migration snapshots are created automatically for
 * jobs entering execution; manual and scheduled snapshots are also supported.
 * Restore drives the existing rollback path; if a migration fails validation
 * and auto-rollback is enabled, the latest valid snapshot is restored
 * automatically. Every snapshot/rollback is audited.
 *
 * Security: tenant-scoped via the caller's RLS client, SHA3-256 integrity hash
 * over the canonical crypto-state, retention-bounded, metadata-only (never
 * plaintext secrets). Degrades gracefully (schemaReady:false) until the schema
 * SQL is applied.
 */

const router = Router()
const CERT_TABLE = 'certificates'
const SNAP_TABLE = 'migration_snapshots'
const AUDIT_TABLE = 'migration_snapshot_audit'
const ACTIVE_JOB_STATES = ['queued', 'awaiting_agent', 'running', 'in_progress', 'executing']
const FAILED_JOB_STATES = ['failed', 'validation_failed', 'error', 'rejected']
const DEFAULT_RETENTION_DAYS = 90

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}
router.use(requireAuth)

/* ---- helpers ---- */
function str(v: unknown): string { return typeof v === 'string' ? v : v == null ? '' : String(v) }
function num(v: unknown): number { const n = Number(v); return Number.isFinite(n) ? n : 0 }
function rec(v: unknown): Record<string, unknown> { return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {} }
function toHex(b: Uint8Array): string { return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('') }

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  const r = value as Record<string, unknown>
  return `{${Object.keys(r).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(r[k])}`).join(',')}}`
}
export function hashState(state: SnapshotCryptoState): { hash: string; bytes: number } {
  const canonical = canonicalize(state)
  const enc = new TextEncoder().encode(canonical)
  return { hash: toHex(sha3_256(enc)), bytes: enc.length }
}

function isMissingTable(error: unknown): boolean {
  const m = str((error as { message?: string })?.message || error)
  return /relation .* does not exist|Could not find the table|schema cache/i.test(m)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function rows(client: any, table: string, build: (q: any) => any, onMissing?: () => void): Promise<Record<string, unknown>[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) { if (isMissingTable(error)) onMissing?.(); else console.warn(`migration-snapshots ${table} query skipped:`, error.message || error); return [] }
    return (data as Record<string, unknown>[]) || []
  } catch (error) {
    console.warn(`migration-snapshots ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

/* ------------------------------------------------------------------ */
/* Capture the REAL crypto/config state of an asset (metadata only)    */
/* ------------------------------------------------------------------ */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function captureCryptoState(client: any, userId: string, assetId: string | null, jobMeta: Record<string, unknown>): Promise<SnapshotCryptoState> {
  const inventory = assetId
    ? await rows(client, 'crypto_inventory', (q) => q.select('algorithm, key_size, protocol, item_type, name, is_quantum_safe, exposure_level').eq('user_id', userId).eq('asset_id', assetId).limit(300))
    : []
  const certs = assetId
    ? await rows(client, CERT_TABLE, (q) => q.select('name, algorithm, key_size, issuer, not_after').eq('user_id', userId).eq('asset_id', assetId).limit(200))
    : []
  const keys = await rows(client, 'generated_keys', (q) => q.select('algorithm, bit_length, status').eq('user_id', userId).order('created_at', { ascending: false }).limit(60))
  return deriveCryptoState(inventory, certs, keys, jobMeta, assetId)
}

/** Pure crypto-state derivation from evidence rows (offline-testable). */
/**
 * Does this inventory row actually name cryptography?
 *
 * TWO gates, because either alone leaks finding titles into the snapshot:
 *
 *  1. `namesCryptography` reads the scanner's own class prefix, rejecting
 *     `API Security: …`, `DNS Security: …`, `Rule (…): …` outright.
 *  2. `analyzeCryptoObservation` must then decompose the algorithm string to
 *     a real primitive. Gate 1 alone still admits rows filed under a crypto
 *     class whose algorithm column holds a title — on a live tenant
 *     `Key Exchange: HNDL Risk: HIGH` and `Certificate: Expired Certificate`
 *     both passed gate 1.
 */
function rowNamesCryptography(row: Record<string, unknown>): boolean {
  if (!namesCryptography(str(row.name))) return false
  const anatomy = analyzeCryptoObservation({
    algorithm: str(row.algorithm),
    name: str(row.name),
    itemType: str(row.item_type),
    protocol: str(row.protocol),
  })
  return anatomy.kind !== 'policy'
}

export function deriveCryptoState(
  inventory: Record<string, unknown>[],
  certs: Record<string, unknown>[],
  keys: Record<string, unknown>[],
  jobMeta: Record<string, unknown>,
  assetId: string | null,
): SnapshotCryptoState {
  const cryptoRows = inventory.filter(rowNamesCryptography)
  const policyRecordsExcluded = inventory.length - cryptoRows.length
  const algorithms = Array.from(new Set([
    ...cryptoRows.map((i) => str(i.algorithm)).filter(Boolean),
    ...certs.map((c) => str(c.algorithm)).filter(Boolean),
    ...(str(jobMeta.fromAlgo || jobMeta.from_algorithm) ? [str(jobMeta.fromAlgo || jobMeta.from_algorithm)] : []),
  ])).slice(0, 40)

  const cipherSuites = Array.from(new Set(cryptoRows.filter((i) => /cipher|tls|kex/i.test(str(i.item_type) + str(i.protocol))).map((i) => str(i.algorithm)).filter(Boolean))).slice(0, 20)
  const tlsRow = cryptoRows.find((i) => /tls/i.test(str(i.protocol) + str(i.item_type)))
  const issuers = Array.from(new Set(certs.map((c) => str(c.issuer)).filter(Boolean))).slice(0, 20)

  const target = rec(jobMeta.target)
  const configPaths = Array.from(new Set([
    str(jobMeta.filePath || jobMeta.path || jobMeta.configPath || target.filePath),
  ].filter(Boolean))).slice(0, 10)

  return {
    algorithms,
    tls: { version: tlsRow ? str(tlsRow.protocol) || 'TLS' : null, cipherSuites, group: str(jobMeta.tlsGroup) || null },
    pki: { issuers, certificateCount: certs.length },
    certificates: certs.slice(0, 40).map((c) => ({ name: str(c.name) || 'certificate', algorithm: str(c.algorithm) || 'unknown', keySize: c.key_size != null ? num(c.key_size) : null, notAfter: c.not_after ? str(c.not_after) : null })),
    keys: keys.slice(0, 30).map((k) => ({ algorithm: str(k.algorithm) || 'unknown', bitLength: k.bit_length != null ? num(k.bit_length) : null, status: str(k.status) || 'active' })),
    configuration: { version: str(jobMeta.configurationVersion) || null, paths: configPaths, source: assetId ? 'crypto-inventory + certificate + key evidence' : 'job metadata' },
    componentCount: inventory.length + certs.length + keys.length,
    policyRecordsExcluded,
  }
}

/* ------------------------------------------------------------------ */
/* Snapshot id + row mapping                                           */
/* ------------------------------------------------------------------ */
/** The executor record persisted on a snapshot, when one exists. */
export function readExecution(meta: Record<string, unknown>): SnapshotExecutionRecord | null {
  const raw = rec(meta.execution)
  const kind = str(raw.kind)
  if (kind !== 'agent-config' && kind !== 'cloud-connector') return null
  return {
    kind,
    agentId: raw.agentId ? str(raw.agentId) : null,
    agentName: raw.agentName ? str(raw.agentName) : null,
    targetPath: raw.targetPath ? str(raw.targetPath) : null,
    backupPath: raw.backupPath ? str(raw.backupPath) : null,
    beforeHash: raw.beforeHash ? str(raw.beforeHash) : null,
    afterHash: raw.afterHash ? str(raw.afterHash) : null,
    connectorId: raw.connectorId ? str(raw.connectorId) : null,
    provider: raw.provider ? str(raw.provider) : null,
    adapter: raw.adapter ? str(raw.adapter) : null,
    rollbackPlan: raw.rollbackPlan && typeof raw.rollbackPlan === 'object' ? (raw.rollbackPlan as Record<string, unknown>) : null,
    recordedAt: str(raw.recordedAt) || str(raw.at),
  }
}

function readRollback(meta: Record<string, unknown>): SnapshotRollbackState | null {
  const raw = rec(meta.rollback)
  const disposition = str(raw.disposition)
  if (!disposition) return null
  return {
    disposition: disposition as SnapshotRollbackState['disposition'],
    requestedAt: str(raw.requestedAt),
    requestedBy: str(raw.requestedBy),
    reason: str(raw.reason),
    executorKind: raw.executorKind === 'agent' || raw.executorKind === 'connector' ? raw.executorKind : null,
    executorId: raw.executorId ? str(raw.executorId) : null,
    executorLabel: raw.executorLabel ? str(raw.executorLabel) : null,
    commandId: raw.commandId ? str(raw.commandId) : null,
    settledAt: raw.settledAt ? str(raw.settledAt) : null,
    verifiedHash: raw.verifiedHash ? str(raw.verifiedHash) : null,
    message: str(raw.message),
  }
}

/**
 * Can this snapshot actually be restored, and if not, why not?
 *
 * Answered here so the API, the dashboard and the report give one answer. A
 * snapshot with no executor record documents what the asset looked like but has
 * nothing able to put it back; offering Restore for it would be the same class
 * of defect as the fabricated rollback this module used to write.
 */
export function restorability(
  status: string,
  execution: SnapshotExecutionRecord | null,
  cryptoState: SnapshotCryptoState,
): { executable: boolean; reason: string | null } {
  if (status === 'deleted') return { executable: false, reason: 'Snapshot has been deleted.' }
  if (status === 'expired') return { executable: false, reason: 'Snapshot passed its retention window and is no longer restorable.' }
  if (status === 'restoring') return { executable: false, reason: 'A rollback is already in flight for this snapshot.' }
  if (!execution) {
    return {
      executable: false,
      reason: cryptoState.componentCount > 0
        ? 'No executor has recorded a change to this asset, so there is nothing to undo. Snapshots capture state; only an agent patch or a connector change can be rolled back.'
        : 'This snapshot captured no cryptographic state, so it cannot be used as a restore source.',
    }
  }
  if (execution.kind === 'agent-config' && (!execution.backupPath || !execution.targetPath || !execution.beforeHash)) {
    return { executable: false, reason: 'The recorded agent change is missing its backup path or pre-change digest, so it cannot be verified before restore.' }
  }
  if (execution.kind === 'cloud-connector' && !execution.rollbackPlan) {
    return { executable: false, reason: 'The connector recorded no provider rollback plan for this change.' }
  }
  return { executable: true, reason: null }
}

export function mapSnapshot(row: Record<string, unknown>): MigrationSnapshot {
  const state = rec(row.crypto_state) as unknown as SnapshotCryptoState
  const meta = rec(row.metadata)
  const execution = readExecution(meta)
  const rollback = readRollback(meta)
  const status = (str(row.status) || 'restorable') as MigrationSnapshot['status']
  /* Integrity is MEASURED on every read: recompute the SHA3-256 over the stored
     state and compare. The `integrity_verified` column records the last verdict
     but is not evidence on its own — it is written `true` at creation, so
     trusting it reports "integrity verified" for rows nobody ever checked. */
  const integrityVerified = hashState(state).hash === str(row.integrity_hash)
  const cryptoState: SnapshotCryptoState = {
    algorithms: Array.isArray(state?.algorithms) ? state.algorithms : [],
    policyRecordsExcluded: num(state?.policyRecordsExcluded),
    tls: state?.tls || { version: null, cipherSuites: [], group: null },
    pki: state?.pki || { issuers: [], certificateCount: 0 },
    certificates: Array.isArray(state?.certificates) ? state.certificates : [],
    keys: Array.isArray(state?.keys) ? state.keys : [],
    configuration: state?.configuration || { version: null, paths: [], source: '' },
    componentCount: num(state?.componentCount),
  }
  const restore = restorability(status, execution, cryptoState)
  return {
    id: str(row.id),
    snapshotId: str(row.snapshot_id),
    assetId: row.asset_id ? str(row.asset_id) : null,
    assetName: str(row.asset_name),
    assetType: str(row.asset_type),
    environment: str(row.environment),
    migrationJobId: row.migration_job_id ? str(row.migration_job_id) : null,
    planId: row.plan_id ? str(row.plan_id) : null,
    status,
    trigger: (str(row.trigger) || 'pre_migration') as MigrationSnapshot['trigger'],
    cryptoState,
    configurationVersion: row.configuration_version ? str(row.configuration_version) : null,
    createdBy: str(row.created_by),
    sizeBytes: num(row.size_bytes),
    retentionDays: num(row.retention_days) || DEFAULT_RETENTION_DAYS,
    expiresAt: row.expires_at ? str(row.expires_at) : null,
    integrityHash: str(row.integrity_hash),
    integrityAlgorithm: str(row.integrity_algorithm) || 'SHA3-256',
    integrityVerified,
    restoredAt: row.restored_at ? str(row.restored_at) : null,
    execution,
    rollback,
    restoreExecutable: restore.executable && integrityVerified,
    restoreBlockedReason: integrityVerified
      ? restore.reason
      : 'Integrity verification failed — the stored state no longer matches its SHA3-256 digest, so restore is blocked.',
    metadata: meta,
    createdAt: str(row.created_at),
    updatedAt: str(row.updated_at) || str(row.created_at),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function writeAudit(client: any, userId: string, args: { snapshotId?: string | null; migrationJobId?: string | null; action: string; actor?: string; reason?: string; detail?: string; approvalStatus?: string; validationResult?: string; restorationStatus?: string; integrityStatus?: string }) {
  try {
    await client.from(AUDIT_TABLE).insert({
      user_id: userId,
      snapshot_id: args.snapshotId || null,
      migration_job_id: args.migrationJobId || null,
      action: args.action,
      actor: args.actor || 'system',
      reason: (args.reason || '').slice(0, 1000),
      detail: (args.detail || '').slice(0, 2000),
      approval_status: args.approvalStatus || 'n/a',
      validation_result: args.validationResult || 'n/a',
      restoration_status: args.restorationStatus || 'n/a',
      integrity_status: args.integrityStatus || 'verified',
    })
  } catch { /* audit best-effort */ }
}

/* ------------------------------------------------------------------ */
/* Create a snapshot                                                   */
/* ------------------------------------------------------------------ */
type CreateSnapshotResult = { ok: true; snapshot: MigrationSnapshot } | { ok: false; schemaMissing: boolean; message: string }
function isCreateFailure(r: CreateSnapshotResult): r is { ok: false; schemaMissing: boolean; message: string } { return !r.ok }

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function createSnapshot(client: any, userId: string, args: {
  assetId: string | null; assetName: string; assetType: string; environment: string
  migrationJobId: string | null; planId: string | null; trigger: 'pre_migration' | 'manual' | 'scheduled'
  jobMeta: Record<string, unknown>; createdBy: string; retentionDays?: number
}): Promise<CreateSnapshotResult> {
  const cryptoState = await captureCryptoState(client, userId, args.assetId, args.jobMeta)
  const { hash, bytes } = hashState(cryptoState)
  // A read-count-next ID races every other agent creating a snapshot. A job's
  // pre-change snapshot is idempotent; manual/scheduled captures are unique.
  const snapshotId = args.trigger === 'pre_migration' && args.migrationJobId
    ? `MSNAP-${createHash('sha3-256').update(`${userId}:${args.migrationJobId}`).digest('hex').slice(0, 32)}`
    : `MSNAP-${randomUUID()}`
  const now = new Date()
  const retentionDays = args.retentionDays || DEFAULT_RETENTION_DAYS
  const configurationVersion = `cfg-${hash.slice(0, 8)}`
  const row = {
    user_id: userId,
    snapshot_id: snapshotId,
    asset_id: args.assetId,
    asset_name: args.assetName || 'Unknown asset',
    asset_type: args.assetType || 'asset',
    environment: args.environment || 'unknown',
    migration_job_id: args.migrationJobId,
    plan_id: args.planId,
    status: 'restorable',
    trigger: args.trigger,
    crypto_state: cryptoState,
    configuration_version: configurationVersion,
    created_by: args.createdBy || 'system',
    size_bytes: bytes,
    retention_days: retentionDays,
    expires_at: new Date(now.getTime() + retentionDays * 86400000).toISOString(),
    integrity_hash: hash,
    integrity_algorithm: 'SHA3-256',
    integrity_verified: true,
    metadata: { capturedComponents: cryptoState.componentCount },
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
  }
  const { data, error } = await client.from(SNAP_TABLE).insert(row).select('*').single()
  if (error) {
    if (error.code === '23505' && args.trigger === 'pre_migration' && args.migrationJobId) {
      const { data: existing } = await client.from(SNAP_TABLE).select('*').eq('user_id', userId).eq('snapshot_id', snapshotId).eq('migration_job_id', args.migrationJobId).maybeSingle()
      if (existing && mapSnapshot(existing).integrityVerified) return { ok: true, snapshot: mapSnapshot(existing) }
    }
    if (isMissingTable(error)) return { ok: false, schemaMissing: true, message: 'Snapshot tables missing — run supabase/migration-snapshots-schema.sql.' }
    return { ok: false, schemaMissing: false, message: error.message || 'Snapshot creation failed' }
  }
  await writeAudit(client, userId, { snapshotId, migrationJobId: args.migrationJobId, action: 'created', actor: args.createdBy, reason: `${args.trigger} snapshot`, detail: `Captured ${cryptoState.componentCount} component(s) · ${bytes} bytes · integrity ${hash.slice(0, 12)}…`, integrityStatus: 'verified' })
  return { ok: true, snapshot: mapSnapshot(data as Record<string, unknown>) }
}

/* ------------------------------------------------------------------ */
/* Pre-change snapshot gate                                            */
/* ------------------------------------------------------------------ */

/**
 * Guarantee a verified pre-change snapshot exists for one job.
 *
 * This is a GATE, called from the agent claim path in `agent-scanner.ts` before
 * a job is handed to an executor. It used to be a dashboard side effect
 * (`ensurePreMigrationSnapshots` ran inside `buildSnapshotDashboard`, i.e. on a
 * GET and on every 20 s SSE tick), which meant a tenant who never opened the
 * Snapshots panel had their hosts patched with no snapshot at all — the backup
 * existed only if somebody happened to be looking at the right screen.
 *
 * Returns `ok:false` when a snapshot could not be created; the caller must then
 * refuse to dispatch the job rather than proceed unprotected.
 */
export async function ensureSnapshotForJob(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  client: any,
  userId: string,
  job: Record<string, unknown>,
  createdBy: string,
): Promise<{ ok: boolean; snapshotId: string | null; schemaMissing: boolean; message: string }> {
  const jobId = str(job.id)
  if (!jobId) return { ok: false, snapshotId: null, schemaMissing: false, message: 'Job has no id' }

  let schemaMissing = false
  const existing = await rows(
    client,
    SNAP_TABLE,
    (q) => q.select('*').eq('user_id', userId).eq('migration_job_id', jobId).eq('trigger', 'pre_migration').limit(1),
    () => { schemaMissing = true },
  )
  if (schemaMissing) {
    return {
      ok: false,
      snapshotId: null,
      schemaMissing: true,
      message: 'Snapshot tables are missing — run supabase/migration-snapshots-schema.sql. No change may be dispatched without a pre-change snapshot.',
    }
  }
  if (existing.length) {
    const row = existing[0]
    if (!mapSnapshot(row).integrityVerified || row.status === 'deleted' || (row.expires_at && Date.parse(str(row.expires_at)) <= Date.now())) {
      return { ok: false, snapshotId: null, schemaMissing: false, message: 'The pre-change snapshot is expired, deleted or fails its integrity check; execution was withheld.' }
    }
    return { ok: true, snapshotId: str(row.snapshot_id), schemaMissing: false, message: 'existing' }
  }

  const assetId = job.asset_id ? str(job.asset_id) : null
  const asset = assetId
    ? (await rows(client, 'assets', (q) => q.select('name, type, environment').eq('user_id', userId).eq('id', assetId).limit(1)))[0]
    : null
  const meta = rec(job.metadata)
  const result = await createSnapshot(client, userId, {
    assetId,
    assetName: str(asset?.name) || str(job.name) || 'Migration asset',
    assetType: str(asset?.type) || str(job.job_type) || 'asset',
    environment: str(asset?.environment) || str(meta.environment) || 'unknown',
    migrationJobId: jobId,
    planId: str(meta.planId || meta.plan_id) || null,
    trigger: 'pre_migration',
    jobMeta: meta,
    createdBy,
  })
  if (isCreateFailure(result)) {
    return { ok: false, snapshotId: null, schemaMissing: result.schemaMissing, message: result.message }
  }
  return { ok: true, snapshotId: result.snapshot.snapshotId, schemaMissing: false, message: 'created' }
}

/* ------------------------------------------------------------------ */
/* Executor record — what makes a snapshot actually restorable         */
/* ------------------------------------------------------------------ */

/**
 * Persist the executor's undo information onto the job's pre-change snapshot.
 *
 * The agent posts the configuration backup it took (`targetPath`, `backupPath`,
 * `beforeHash`) inside the remediation event metadata, and the cloud adapters
 * post a provider `rollbackPlan`. Neither was ever stored: the event metadata
 * was summarised into `executorEvents` (which keeps only type/status/progress)
 * and thrown away. The platform therefore could not roll anything back even in
 * principle, while still offering a Restore button — this is what closes that
 * loop.
 */
export async function recordSnapshotExecution(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  client: any,
  userId: string,
  migrationJobId: string,
  execution: SnapshotExecutionRecord,
): Promise<void> {
  if (!migrationJobId) return
  const snaps = await rows(client, SNAP_TABLE, (q) =>
    q.select('id, metadata').eq('user_id', userId).eq('migration_job_id', migrationJobId).eq('trigger', 'pre_migration').order('created_at', { ascending: false }).limit(1))
  if (!snaps.length) return
  const meta = rec(snaps[0].metadata)
  try {
    await client.from(SNAP_TABLE).update({
      metadata: { ...meta, execution },
      updated_at: new Date().toISOString(),
    }).eq('id', snaps[0].id).eq('user_id', userId)
  } catch (error) {
    console.warn('migration-snapshots: execution record update failed:', (error as Error)?.message || error)
  }
  await writeAudit(client, userId, {
    snapshotId: str(snaps[0].id),
    migrationJobId,
    action: 'execution_recorded',
    actor: execution.agentName || execution.provider || 'executor',
    reason: 'Executor recorded an undoable change',
    detail: execution.kind === 'agent-config'
      ? `Backup ${execution.backupPath} for ${execution.targetPath} (pre-change digest ${str(execution.beforeHash).slice(0, 12)}…)`
      : `${execution.provider || 'cloud'} rollback plan recorded for ${execution.adapter || 'resource'}`,
    integrityStatus: 'verified',
  })
}

/* ------------------------------------------------------------------ */
/* Rollback dispatch — the only path that may claim a restore happened */
/* ------------------------------------------------------------------ */

/**
 * Pick the executor that is genuinely able to undo the recorded change.
 *
 * The important rule is that a file backup lives on the HOST that was patched.
 * "Restoring via" any other agent would restore nothing, so an agent-config
 * change is only ever dispatched to the agent that made it. The previous
 * implementation picked `agents[0]` — any active agent — and then wrote
 * `status: restored`.
 */
interface RollbackExecutor {
  /** null means "no executor is able to undo this change right now". */
  kind: 'agent' | 'connector' | null
  id: string
  label: string
  /** Why there is no executor. Empty when there is one. */
  reason: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  agent: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  connector: any
}

/* One shape rather than a discriminated union: this project compiles with
   `strict` off, where narrowing on a `kind: null` member is unreliable. */
function noExecutor(reason: string): RollbackExecutor {
  return { kind: null, id: '', label: '', reason, agent: null, connector: null }
}

async function resolveRollbackExecutor(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  client: any,
  userId: string,
  execution: SnapshotExecutionRecord | null,
): Promise<RollbackExecutor> {
  if (!execution) {
    return noExecutor('No executor has recorded a change for this asset, so there is nothing to undo.')
  }

  if (execution.kind === 'agent-config') {
    const agentId = str(execution.agentId)
    if (!agentId) return noExecutor('The recorded change does not name the agent that applied it.')
    const agents = await rows(client, 'scanner_agents', (q) =>
      q.select('id, name, hostname, status, version, last_seen_at, revoked_at, metadata, capabilities, user_id').eq('user_id', userId).eq('id', agentId).limit(1))
    const agent = agents[0]
    if (!agent) return noExecutor('The agent that applied this change is no longer enrolled, so its backup cannot be reached.')
    if (agent.revoked_at || str(agent.status) === 'revoked') {
      return noExecutor('The agent that applied this change has been revoked. Re-enrol it on the same host to roll back.')
    }
    const lastSeen = agent.last_seen_at ? Date.parse(str(agent.last_seen_at)) : 0
    if (!lastSeen || Date.now() - lastSeen > HEARTBEAT_ONLINE_WINDOW_MS) {
      return noExecutor(`Agent ${str(agent.name) || agentId} is offline (last heartbeat ${agent.last_seen_at ? str(agent.last_seen_at) : 'never'}). Rollback runs when it reconnects.`)
    }
    /* Same write gate the remediation queue applies: an agent whose tenant has
       downgraded keeps its row but stops being handed host-modifying work. */
    const write = await agentMayWrite(
      client,
      agent as { user_id: string; metadata?: Record<string, unknown>; capabilities?: Record<string, unknown> },
      'remediation',
    )
    if (!write.allowed) {
      const role = str(rec(agent.metadata).role) as AgentRole
      return noExecutor(
        write.reason === 'agent_role_read_only' || write.reason === 'agent_role_unresolved'
          ? `Agent ${str(agent.name) || agentId} holds the read-only ${role || 'collector'} role and cannot write to the host.`
          : write.reason === 'remediation_not_authorized'
            ? `Agent ${str(agent.name) || agentId} is not authorised to write to its host. Grant remediation authority in the Agent Center to roll back through it.`
            : write.reason === 'entitlement_unavailable'
            ? 'The subscription behind this agent could not be verified, so no host-modifying work was dispatched.'
            : 'Your plan no longer includes host-modifying agents, so rollback was not dispatched.',
      )
    }
    /* An older runtime answers an unknown command with "Unsupported command
       type", which would settle as a failed restore and hide the real cause. */
    if (!agentVersionAtLeast(str(agent.version), AGENT_ROLLBACK_MIN_VERSION)) {
      return noExecutor(`Agent ${str(agent.name) || agentId} runs ${str(agent.version) || 'an unknown version'}, which cannot execute rollback. Upgrade it to ${AGENT_ROLLBACK_MIN_VERSION} or later from the Agent Center.`)
    }
    if (!agentVersionAtLeast(str(agent.version), AGENT_COORDINATION_MIN_VERSION)) return noExecutor(`Upgrade this agent to ${AGENT_COORDINATION_MIN_VERSION}+ for coordinated rollback on shared hosts.`)
    return { kind: 'agent', id: str(agent.id), label: `agent ${str(agent.name) || str(agent.hostname) || agentId}`, reason: '', agent, connector: null }
  }

  const connectorId = str(execution.connectorId)
  const connectors = await rows(client, 'connector_accounts', (q) => {
    const base = q.select('id, provider, status, scopes, metadata').eq('user_id', userId).eq('status', 'connected')
    return connectorId ? base.eq('id', connectorId).limit(1) : base.limit(1)
  })
  const connector = connectors[0]
  if (!connector) {
    return noExecutor('The cloud connector that applied this change is no longer connected, so the provider rollback plan cannot be replayed.')
  }
  return { kind: 'connector', id: str(connector.id), label: `${str(connector.provider) || 'cloud'} connector`, reason: '', agent: null, connector }
}

interface DispatchArgs {
  snapshotRow: Record<string, unknown>
  reason: string
  requestedBy: string
  /** `auto` marks a rollback the platform started because validation failed. */
  origin: 'operator' | 'auto'
}

/**
 * Request a rollback and report exactly what happened.
 *
 * Four honest outcomes, never collapsed into "success":
 *   dispatched        — a live executor was handed the work; asset not yet changed
 *   restored          — a connector replayed its plan and the provider confirmed
 *   failed            — the executor tried and could not
 *   awaiting-executor — recorded only; NOTHING on the asset was touched
 */
export async function dispatchSnapshotRollback(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  client: any,
  userId: string,
  args: DispatchArgs,
): Promise<SnapshotRestoreResult> {
  const row = args.snapshotRow
  const snapshotId = str(row.snapshot_id)
  const jobId = row.migration_job_id ? str(row.migration_job_id) : null
  const assetId = row.asset_id ? str(row.asset_id) : null
  const meta = rec(row.metadata)
  const execution = readExecution(meta)
  const now = new Date().toISOString()

  const executor = await resolveRollbackExecutor(client, userId, execution)

  const settle = async (
    disposition: RollbackDisposition,
    snapshotStatus: MigrationSnapshot['status'],
    message: string,
    extra: Partial<SnapshotRollbackState> = {},
  ): Promise<SnapshotRestoreResult> => {
    const rollbackState: SnapshotRollbackState = {
      disposition,
      requestedAt: now,
      requestedBy: args.requestedBy,
      reason: args.reason,
      executorKind: executor.kind,
      executorId: executor.kind ? executor.id : null,
      executorLabel: executor.kind ? executor.label : null,
      commandId: null,
      settledAt: disposition === 'dispatched' ? null : now,
      message,
      ...extra,
    }
    await client.from(SNAP_TABLE).update({
      status: snapshotStatus,
      restored_at: disposition === 'restored' ? now : row.restored_at || null,
      metadata: { ...meta, rollback: rollbackState },
      updated_at: now,
    }).eq('id', row.id).eq('user_id', userId)

    if (jobId) {
      const job = (await rows(client, 'migration_jobs', (q) => q.select('metadata').eq('user_id', userId).eq('id', jobId).limit(1)))[0]
      const jobMeta = rec(job?.metadata)
      /* The job only reads `rolled_back` once the asset really is back. Until
         then it is `rollback_requested`, which is the state the Live Migration
         board renders as "rollback in flight". */
      const jobStatus =
        disposition === 'restored' ? 'rolled_back'
          : disposition === 'failed' ? 'rollback_failed'
            : 'rollback_requested'
      await client.from('migration_jobs').update({
        status: jobStatus,
        metadata: {
          ...jobMeta,
          rolledBackFrom: snapshotId,
          rollbackReason: args.reason,
          rollbackOrigin: args.origin,
          rollbackDisposition: disposition,
          rollbackExecutor: rollbackState.executorKind,
          rollbackRequestedAt: now,
          ...(disposition === 'restored' ? { rolledBackAt: now } : {}),
        },
        updated_at: now,
      }).eq('id', jobId).eq('user_id', userId)

      try {
        await client.from('migration_events').insert({
          user_id: userId,
          migration_id: jobId,
          event_type: `rollback-${disposition}`,
          severity: disposition === 'restored' ? 'info' : disposition === 'failed' ? 'error' : 'warning',
          message,
          metadata: { snapshotId, disposition, executor: rollbackState.executorLabel, origin: args.origin },
          created_at: now,
        })
      } catch { /* event stream is best-effort */ }
    }

    await writeAudit(client, userId, {
      snapshotId,
      migrationJobId: jobId,
      action: args.origin === 'auto' ? 'auto_rollback' : 'restore_requested',
      actor: args.requestedBy,
      reason: args.reason,
      detail: message,
      approvalStatus: args.origin === 'auto' ? 'auto-on-validation-failure' : 'owner-approved',
      validationResult: disposition === 'restored' ? 'restored' : disposition === 'failed' ? 'failed' : 'pending',
      restorationStatus: disposition,
      integrityStatus: 'verified',
    })

    return {
      snapshotId,
      disposition,
      jobId,
      assetId,
      executor: executor.kind ? { kind: executor.kind, id: executor.id, label: executor.label } : null,
      commandId: rollbackState.commandId,
      applied: disposition === 'restored',
      message,
    }
  }

  if (executor.kind === null) {
    return settle(
      'awaiting-executor',
      (str(row.status) || 'restorable') as MigrationSnapshot['status'],
      `Rollback of ${str(row.asset_name)} was RECORDED BUT NOT APPLIED — nothing on the asset changed. ${executor.reason}`,
    )
  }

  if (executor.kind === 'agent') {
    const payload = {
      snapshotId,
      migrationJobId: jobId,
      assetName: str(row.asset_name),
      configurationVersion: str(row.configuration_version),
      targetPath: execution?.targetPath || null,
      backupPath: execution?.backupPath || null,
      beforeHash: execution?.beforeHash || null,
      afterHash: execution?.afterHash || null,
      origin: args.origin,
      reason: args.reason,
      requestedAt: now,
    }
    const outcome = await enqueueAgentCommand(client, executor.agent, 'rollback', {
      payload,
      requestedBy: args.requestedBy,
      /* Per-snapshot, not per-type: two rollbacks of two snapshots are two
         distinct pieces of work and must both reach the agent. */
      dedupeKey: (command) => str(rec(command.payload).snapshotId),
    })
    if (!outcome.ok) {
      return settle('failed', 'restore_failed', `Rollback could not be queued for ${executor.label}: ${outcome.message}`)
    }
    return settle(
      'dispatched',
      'restoring',
      `Rollback queued for ${executor.label}. The asset is only marked restored once that agent confirms it restored ${execution?.targetPath || 'the recorded configuration'} and re-verified the digest.`,
      { commandId: str(outcome.command?.id) || null },
    )
  }

  /* Connector path: the provider rollback plan is replayed synchronously,
     because a cloud API call either succeeds or fails now — there is no remote
     worker to wait for. */
  const result = await executeCloudConnectorRollback({
    connector: executor.connector as never,
    execution: execution as never,
    requestedBy: args.requestedBy,
  })
  if (result.restored) {
    return settle('restored', 'restored', `${executor.label} replayed the recorded rollback plan and the provider confirmed the previous configuration. ${result.detail}`.trim())
  }
  return settle(
    result.attempted ? 'failed' : 'awaiting-executor',
    result.attempted ? 'restore_failed' : (str(row.status) || 'restorable') as MigrationSnapshot['status'],
    result.attempted
      ? `${executor.label} attempted the rollback and it did not complete: ${result.detail}`
      : `Rollback of ${str(row.asset_name)} was RECORDED BUT NOT APPLIED — nothing on the asset changed. ${result.detail}`,
  )
}

/**
 * Settle a rollback the agent has finished.
 *
 * Called from the command acknowledgement handler. This is the ONLY place a
 * snapshot may become `restored`, because this is the only point at which an
 * executor has reported that it restored the file and re-hashed it.
 */
export async function settleAgentRollback(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  client: any,
  userId: string,
  args: {
    snapshotId: string
    commandId: string
    status: 'completed' | 'failed'
    result: Record<string, unknown> | null
    error: string | null
    actor: string
  },
): Promise<void> {
  if (!args.snapshotId) return
  const row = (await rows(client, SNAP_TABLE, (q) => q.select('*').eq('user_id', userId).eq('snapshot_id', args.snapshotId).limit(1)))[0]
  if (!row) return

  const meta = rec(row.metadata)
  const previous = readRollback(meta)
  const now = new Date().toISOString()
  const restoredHash = str(rec(args.result).restoredHash) || null
  const verified = args.status === 'completed' && rec(args.result).verified === true

  const disposition: RollbackDisposition = verified ? 'restored' : 'failed'
  const message = verified
    ? `Agent restored ${str(rec(args.result).targetPath) || 'the recorded configuration'} and re-verified the pre-change digest.`
    : args.status === 'completed'
      ? `Agent reported the restore completed but could not verify the pre-change digest, so the asset is NOT confirmed restored. ${str(rec(args.result).reason)}`.trim()
      : `Agent could not restore the configuration: ${args.error || str(rec(args.result).reason) || 'no reason reported'}`

  const rollbackState: SnapshotRollbackState = {
    disposition,
    requestedAt: previous?.requestedAt || now,
    requestedBy: previous?.requestedBy || args.actor,
    reason: previous?.reason || 'Rollback',
    executorKind: 'agent',
    executorId: previous?.executorId || null,
    executorLabel: previous?.executorLabel || 'agent',
    commandId: args.commandId,
    settledAt: now,
    verifiedHash: restoredHash,
    message,
  }

  await client.from(SNAP_TABLE).update({
    /* A failed restore leaves the snapshot RESTORABLE: the recorded state is
       still good, only the attempt failed, and an operator must be able to try
       again once the cause is fixed. */
    status: verified ? 'restored' : 'restore_failed',
    restored_at: verified ? now : null,
    metadata: { ...meta, rollback: rollbackState },
    updated_at: now,
  }).eq('id', row.id).eq('user_id', userId)

  const jobId = row.migration_job_id ? str(row.migration_job_id) : null
  if (jobId) {
    const job = (await rows(client, 'migration_jobs', (q) => q.select('metadata').eq('user_id', userId).eq('id', jobId).limit(1)))[0]
    const jobMeta = rec(job?.metadata)
    await client.from('migration_jobs').update({
      status: verified ? 'rolled_back' : 'rollback_failed',
      metadata: {
        ...jobMeta,
        rollbackDisposition: disposition,
        rollbackResult: args.result || null,
        rollbackError: args.error || null,
        ...(verified ? { rolledBackAt: now, rolledBackFrom: args.snapshotId } : {}),
      },
      updated_at: now,
    }).eq('id', jobId).eq('user_id', userId)
    try {
      await client.from('migration_events').insert({
        user_id: userId,
        migration_id: jobId,
        event_type: verified ? 'rollback-restored' : 'rollback-failed',
        severity: verified ? 'info' : 'error',
        message,
        metadata: { snapshotId: args.snapshotId, commandId: args.commandId, restoredHash },
        created_at: now,
      })
    } catch { /* best effort */ }
  }

  await writeAudit(client, userId, {
    snapshotId: args.snapshotId,
    migrationJobId: jobId,
    action: verified ? 'restored' : 'rollback_failed',
    actor: args.actor,
    reason: rollbackState.reason,
    detail: message,
    approvalStatus: 'owner-approved',
    validationResult: verified ? 'verified' : 'failed',
    restorationStatus: disposition,
    integrityStatus: verified ? 'verified' : 'unverified',
  })
}

/* ------------------------------------------------------------------ */
/* Dashboard assembly                                                  */
/* ------------------------------------------------------------------ */

/**
 * Read-only.
 *
 * This function used to create up to 25 snapshot rows and rewrite failed
 * migration jobs to `rolled_back` — on a GET, and again on every 20-second SSE
 * tick. Opening a dashboard must never change tenant state, and a rollback must
 * never be a side effect of somebody looking at a page.
 */
export async function buildSnapshotDashboard(token: string, userId: string, _actor: string): Promise<SnapshotDashboard> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Supabase unavailable')
  const missing = { schema: false }

  const snapshotRows = await rows(client, SNAP_TABLE, (q) => q.select('*').eq('user_id', userId).neq('status', 'deleted').order('created_at', { ascending: false }).limit(300), () => { missing.schema = true })
  const auditRows = await rows(client, AUDIT_TABLE, (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(80))

  const snapshots = snapshotRows.map(mapSnapshot)

  /* Expiry is derived for display; the row is only rewritten by the retention
     job / delete route, not by a read. */
  const nowMs = Date.now()
  for (const snap of snapshots) {
    if (snap.status === 'restorable' && snap.expiresAt && new Date(snap.expiresAt).getTime() < nowMs) {
      snap.status = 'expired'
      snap.restoreExecutable = false
      snap.restoreBlockedReason = 'Snapshot passed its retention window and is no longer restorable.'
    }
  }

  const audit: SnapshotAuditEntry[] = auditRows.map((a) => ({
    id: str(a.id), snapshotId: a.snapshot_id ? str(a.snapshot_id) : null, migrationJobId: a.migration_job_id ? str(a.migration_job_id) : null,
    action: str(a.action), actor: str(a.actor), reason: str(a.reason), detail: str(a.detail),
    approvalStatus: str(a.approval_status), validationResult: str(a.validation_result), restorationStatus: str(a.restoration_status), integrityStatus: str(a.integrity_status), createdAt: str(a.created_at),
  }))

  const autoRollbacks = audit.filter((a) => a.action === 'auto_rollback').length
  const manualRollbacks = snapshots.filter((s) => s.rollback?.disposition === 'restored' && s.rollback?.executorKind).length
  const latest = snapshots[0]?.createdAt || null

  return {
    generatedAt: new Date().toISOString(),
    schemaReady: !missing.schema,
    summary: {
      total: snapshots.length,
      /* "Successful" means a CONFIRMED restore, not "a row exists". */
      successful: snapshots.filter((s) => s.status === 'restored').length,
      restorable: snapshots.filter((s) => s.status === 'restorable').length,
      restored: snapshots.filter((s) => s.status === 'restored').length,
      expired: snapshots.filter((s) => s.status === 'expired').length,
      automaticRollbacks: autoRollbacks,
      manualRollbacks,
      storageBytes: snapshots.reduce((sum, s) => sum + s.sizeBytes, 0),
      latestSnapshotAt: latest,
      integrityVerified: snapshots.filter((s) => s.integrityVerified).length,
      integrityFailed: snapshots.filter((s) => !s.integrityVerified).length,
      restoreExecutable: snapshots.filter((s) => s.restoreExecutable).length,
      rollbacksInFlight: snapshots.filter((s) => s.status === 'restoring').length,
      rollbacksFailed: snapshots.filter((s) => s.status === 'restore_failed').length,
      autoRollbackEnabled: true,
    },
    snapshots,
    audit,
  }
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */
router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    res.json({ data: await buildSnapshotDashboard(token!, user!.id, user!.email || 'owner') })
  } catch (error) {
    console.error('migration-snapshots dashboard failed:', error)
    res.status(500).json({ error: { code: 'SNAPSHOT_ERROR', message: 'Unable to build snapshot dashboard' } })
  }
})

router.get('/stream', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' })
  let closed = false
  const send = async () => {
    if (closed) return
    try {
      const data = await buildSnapshotDashboard(token!, user!.id, user!.email || 'owner')
      res.write(`event: snapshot-update\ndata: ${JSON.stringify(data)}\n\n`)
    } catch { res.write(`event: snapshot-error\ndata: {}\n\n`) }
  }
  await send()
  const interval = setInterval(send, 20000)
  const heartbeat = setInterval(() => { if (!closed) res.write(': keep-alive\n\n') }, 10000)
  req.on('close', () => { closed = true; clearInterval(interval); clearInterval(heartbeat) })
})

router.get('/audit', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const auditRows = await rows(client, AUDIT_TABLE, (q) => q.select('*').eq('user_id', user!.id).order('created_at', { ascending: false }).limit(200))
    res.json({ data: { audit: auditRows.map((a) => ({ id: str(a.id), snapshotId: a.snapshot_id ? str(a.snapshot_id) : null, migrationJobId: a.migration_job_id ? str(a.migration_job_id) : null, action: str(a.action), actor: str(a.actor), reason: str(a.reason), detail: str(a.detail), approvalStatus: str(a.approval_status), validationResult: str(a.validation_result), restorationStatus: str(a.restoration_status), integrityStatus: str(a.integrity_status), createdAt: str(a.created_at) })) } })
  } catch (error) {
    console.error('snapshot audit failed:', error)
    res.status(500).json({ error: { code: 'AUDIT_ERROR', message: 'Unable to load snapshot audit log' } })
  }
})

router.post('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const assetId = str(req.body?.assetId).trim() || null
    let assetName = str(req.body?.assetName).trim()
    let assetType = str(req.body?.assetType).trim()
    let environment = str(req.body?.environment).trim()
    const migrationJobId = str(req.body?.migrationJobId).trim() || null
    // Enrich from the asset inventory when only an id is provided.
    if (assetId && (!assetName || !assetType)) {
      const a = (await rows(client, 'assets', (q) => q.select('name, type, environment').eq('user_id', user!.id).eq('id', assetId).limit(1)))[0]
      assetName = assetName || str(a?.name)
      assetType = assetType || str(a?.type)
      environment = environment || str(a?.environment)
    }
    const jobMeta = migrationJobId ? rec((await rows(client, 'migration_jobs', (q) => q.select('metadata').eq('user_id', user!.id).eq('id', migrationJobId).limit(1)))[0]?.metadata) : {}
    const result = await createSnapshot(client, user!.id, {
      assetId, assetName: assetName || 'Manual snapshot', assetType: assetType || 'asset', environment: environment || 'unknown',
      migrationJobId, planId: str(req.body?.planId).trim() || null, trigger: 'manual', jobMeta, createdBy: user!.email || 'owner',
      retentionDays: num(req.body?.retentionDays) || DEFAULT_RETENTION_DAYS,
    })
    if (isCreateFailure(result)) return res.status(result.schemaMissing ? 503 : 500).json({ error: { code: result.schemaMissing ? 'SCHEMA_NOT_APPLIED' : 'SNAPSHOT_FAILED', message: result.message } })
    res.status(201).json({ data: result.snapshot })
  } catch (error) {
    console.error('snapshot create failed:', error)
    res.status(500).json({ error: { code: 'SNAPSHOT_FAILED', message: 'Unable to create snapshot' } })
  }
})

/**
 * Request a rollback of one snapshot.
 *
 * Preconditions are enforced here rather than in the UI, and the response says
 * exactly what happened — `applied:false` when nothing on the asset changed.
 */
router.post('/:snapshotId/restore', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const snapshotId = str(req.params.snapshotId)
    const reason = str(req.body?.reason).trim().slice(0, 1000) || 'Manual restore from snapshot'
    const existing = (await rows(client, SNAP_TABLE, (q) => q.select('*').eq('user_id', user!.id).eq('snapshot_id', snapshotId).limit(1)))[0]
    if (!existing) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Snapshot not found' } })

    const status = str(existing.status) || 'restorable'
    if (status === 'deleted') {
      return res.status(409).json({ error: { code: 'SNAPSHOT_DELETED', message: 'This snapshot has been deleted and cannot be restored.' } })
    }
    if (status === 'restoring') {
      return res.status(409).json({ error: { code: 'ROLLBACK_IN_FLIGHT', message: 'A rollback for this snapshot is already in flight. Wait for the executor to report back.' } })
    }
    const expired = existing.expires_at ? new Date(str(existing.expires_at)).getTime() < Date.now() : false
    if (status === 'expired' || expired) {
      return res.status(409).json({ error: { code: 'SNAPSHOT_EXPIRED', message: 'This snapshot passed its retention window and is no longer a valid restore source.' } })
    }

    // Integrity gate: recompute the hash and refuse to restore a tampered snapshot.
    const { hash } = hashState(rec(existing.crypto_state) as unknown as SnapshotCryptoState)
    const integrityOk = hash === str(existing.integrity_hash)
    if (!integrityOk) {
      await client.from(SNAP_TABLE).update({ integrity_verified: false, updated_at: new Date().toISOString() }).eq('id', existing.id).eq('user_id', user!.id)
      await writeAudit(client, user!.id, { snapshotId, migrationJobId: existing.migration_job_id ? str(existing.migration_job_id) : null, action: 'verified', actor: user!.email || 'owner', reason: 'Integrity check failed during restore', restorationStatus: 'blocked', integrityStatus: 'failed' })
      return res.status(409).json({ error: { code: 'INTEGRITY_FAILED', message: 'Snapshot integrity verification failed — restore blocked.' } })
    }

    const result = await dispatchSnapshotRollback(client, user!.id, {
      snapshotRow: existing,
      reason,
      requestedBy: user!.email || user!.id,
      origin: 'operator',
    })
    res.json({ data: result })
  } catch (error) {
    console.error('snapshot restore failed:', error)
    res.status(500).json({ error: { code: 'RESTORE_FAILED', message: 'Unable to restore snapshot' } })
  }
})

router.post('/:snapshotId/verify', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const snapshotId = str(req.params.snapshotId)
    const existing = (await rows(client, SNAP_TABLE, (q) => q.select('*').eq('user_id', user!.id).eq('snapshot_id', snapshotId).limit(1)))[0]
    if (!existing) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Snapshot not found' } })
    const { hash } = hashState(rec(existing.crypto_state) as unknown as SnapshotCryptoState)
    const ok = hash === str(existing.integrity_hash)
    await client.from(SNAP_TABLE).update({ integrity_verified: ok, updated_at: new Date().toISOString() }).eq('id', existing.id).eq('user_id', user!.id)
    await writeAudit(client, user!.id, { snapshotId, action: 'verified', actor: user!.email || 'owner', reason: 'Manual integrity verification', integrityStatus: ok ? 'verified' : 'failed' })
    res.json({ data: { snapshotId, integrityVerified: ok } })
  } catch (error) {
    console.error('snapshot verify failed:', error)
    res.status(500).json({ error: { code: 'VERIFY_FAILED', message: 'Unable to verify snapshot' } })
  }
})

router.delete('/:snapshotId', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const snapshotId = str(req.params.snapshotId)
    const existing = (await rows(client, SNAP_TABLE, (q) => q.select('id, status, expires_at, snapshot_id').eq('user_id', user!.id).eq('snapshot_id', snapshotId).limit(1)))[0]
    if (!existing) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Snapshot not found' } })
    // Retention policy: a restorable snapshot may only be deleted once expired,
    // unless the caller explicitly forces it.
    const expired = existing.expires_at ? new Date(str(existing.expires_at)).getTime() < Date.now() : false
    if (str(existing.status) === 'restorable' && !expired && req.body?.force !== true) {
      return res.status(409).json({ error: { code: 'RETENTION_PROTECTED', message: 'Snapshot is within its retention period. Force delete to override.' } })
    }
    await client.from(SNAP_TABLE).update({ status: 'deleted', updated_at: new Date().toISOString() }).eq('id', existing.id).eq('user_id', user!.id)
    await writeAudit(client, user!.id, { snapshotId, action: 'deleted', actor: user!.email || 'owner', reason: expired ? 'Expired per retention policy' : 'Force delete', restorationStatus: 'n/a' })
    res.json({ data: { snapshotId, status: 'deleted' } })
  } catch (error) {
    console.error('snapshot delete failed:', error)
    res.status(500).json({ error: { code: 'DELETE_FAILED', message: 'Unable to delete snapshot' } })
  }
})

export default router
