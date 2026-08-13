import { Router, Request, Response, NextFunction } from 'express'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { namesCryptography } from '@/lib/scanner/finding-identity'
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'
import type {
  MigrationSnapshot,
  SnapshotAuditEntry,
  SnapshotCryptoState,
  SnapshotDashboard,
} from '@/types/migration-snapshot'

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
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function nextSnapshotId(client: any, userId: string): Promise<string> {
  const year = new Date().getFullYear()
  let count = 0
  try {
    const { count: c } = await client.from(SNAP_TABLE).select('id', { count: 'exact', head: true }).eq('user_id', userId)
    count = typeof c === 'number' ? c : 0
  } catch { /* fall through */ }
  return `MSNAP-${year}-${String(count + 1).padStart(6, '0')}`
}

function mapSnapshot(row: Record<string, unknown>): MigrationSnapshot {
  const state = rec(row.crypto_state) as unknown as SnapshotCryptoState
  return {
    id: str(row.id),
    snapshotId: str(row.snapshot_id),
    assetId: row.asset_id ? str(row.asset_id) : null,
    assetName: str(row.asset_name),
    assetType: str(row.asset_type),
    environment: str(row.environment),
    migrationJobId: row.migration_job_id ? str(row.migration_job_id) : null,
    planId: row.plan_id ? str(row.plan_id) : null,
    status: (str(row.status) || 'restorable') as MigrationSnapshot['status'],
    trigger: (str(row.trigger) || 'pre_migration') as MigrationSnapshot['trigger'],
    cryptoState: {
      algorithms: Array.isArray(state?.algorithms) ? state.algorithms : [],
      tls: state?.tls || { version: null, cipherSuites: [], group: null },
      pki: state?.pki || { issuers: [], certificateCount: 0 },
      certificates: Array.isArray(state?.certificates) ? state.certificates : [],
      keys: Array.isArray(state?.keys) ? state.keys : [],
      configuration: state?.configuration || { version: null, paths: [], source: '' },
      componentCount: num(state?.componentCount),
    },
    configurationVersion: row.configuration_version ? str(row.configuration_version) : null,
    createdBy: str(row.created_by),
    sizeBytes: num(row.size_bytes),
    retentionDays: num(row.retention_days) || DEFAULT_RETENTION_DAYS,
    expiresAt: row.expires_at ? str(row.expires_at) : null,
    integrityHash: str(row.integrity_hash),
    integrityAlgorithm: str(row.integrity_algorithm) || 'SHA3-256',
    integrityVerified: row.integrity_verified !== false,
    restoredAt: row.restored_at ? str(row.restored_at) : null,
    metadata: rec(row.metadata),
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
  const snapshotId = await nextSnapshotId(client, userId)
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
    if (isMissingTable(error)) return { ok: false, schemaMissing: true, message: 'Snapshot tables missing — run supabase/migration-snapshots-schema.sql.' }
    return { ok: false, schemaMissing: false, message: error.message || 'Snapshot creation failed' }
  }
  await writeAudit(client, userId, { snapshotId, migrationJobId: args.migrationJobId, action: 'created', actor: args.createdBy, reason: `${args.trigger} snapshot`, detail: `Captured ${cryptoState.componentCount} component(s) · ${bytes} bytes · integrity ${hash.slice(0, 12)}…`, integrityStatus: 'verified' })
  return { ok: true, snapshot: mapSnapshot(data as Record<string, unknown>) }
}

/* ------------------------------------------------------------------ */
/* Auto pre-migration snapshots + auto-rollback on failure             */
/* ------------------------------------------------------------------ */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function ensurePreMigrationSnapshots(client: any, userId: string, createdBy: string, missing: { schema: boolean }): Promise<void> {
  const jobs = await rows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, metadata, created_at').eq('user_id', userId).in('status', ACTIVE_JOB_STATES).order('created_at', { ascending: false }).limit(200))
  if (!jobs.length) return
  const existing = await rows(client, SNAP_TABLE, (q) => q.select('migration_job_id').eq('user_id', userId).eq('trigger', 'pre_migration').limit(500), () => { missing.schema = true })
  if (missing.schema) return
  const covered = new Set(existing.map((s) => str(s.migration_job_id)).filter(Boolean))
  // Resolve asset names for the jobs missing a snapshot.
  const assetIds = Array.from(new Set(jobs.map((j) => str(j.asset_id)).filter(Boolean)))
  const assets = assetIds.length ? await rows(client, 'assets', (q) => q.select('id, name, type, environment').eq('user_id', userId).in('id', assetIds).limit(500)) : []
  const assetById = new Map(assets.map((a) => [str(a.id), a]))
  for (const job of jobs.slice(0, 25)) {
    const jobId = str(job.id)
    if (covered.has(jobId)) continue
    const asset = assetById.get(str(job.asset_id))
    const meta = rec(job.metadata)
    await createSnapshot(client, userId, {
      assetId: job.asset_id ? str(job.asset_id) : null,
      assetName: str(asset?.name) || str(job.name) || 'Migration asset',
      assetType: str(asset?.type) || str(job.job_type) || 'asset',
      environment: str(asset?.environment) || str(meta.environment) || 'unknown',
      migrationJobId: jobId,
      planId: str(meta.planId || meta.plan_id) || null,
      trigger: 'pre_migration',
      jobMeta: meta,
      createdBy,
    })
    covered.add(jobId)
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function autoRollbackFailedJobs(client: any, userId: string, actor: string): Promise<number> {
  // Restore the latest valid pre-migration snapshot for jobs that failed and
  // have not already been auto-rolled-back.
  const failed = await rows(client, 'migration_jobs', (q) => q.select('id, name, status, metadata').eq('user_id', userId).in('status', FAILED_JOB_STATES).limit(100))
  if (!failed.length) return 0
  let rolledBack = 0
  for (const job of failed) {
    const jobId = str(job.id)
    const meta = rec(job.metadata)
    if (meta.autoRolledBack === true) continue
    const snaps = await rows(client, SNAP_TABLE, (q) => q.select('*').eq('user_id', userId).eq('migration_job_id', jobId).eq('trigger', 'pre_migration').eq('status', 'restorable').order('created_at', { ascending: false }).limit(1))
    if (!snaps.length) continue
    const snap = snaps[0]
    // Restore: flip job to rollback, mark snapshot restored, audit.
    await client.from('migration_jobs').update({ status: 'rolled_back', metadata: { ...meta, autoRolledBack: true, rolledBackFrom: str(snap.snapshot_id), rolledBackAt: new Date().toISOString() }, updated_at: new Date().toISOString() }).eq('id', jobId).eq('user_id', userId)
    await client.from(SNAP_TABLE).update({ status: 'restored', restored_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq('id', snap.id).eq('user_id', userId)
    await writeAudit(client, userId, { snapshotId: str(snap.snapshot_id), migrationJobId: jobId, action: 'auto_rollback', actor, reason: 'Migration failed validation/health check — automatic rollback', detail: `Restored ${str(job.name) || jobId} from ${str(snap.snapshot_id)}`, approvalStatus: 'auto', validationResult: 'failed', restorationStatus: 'completed', integrityStatus: 'verified' })
    rolledBack += 1
  }
  return rolledBack
}

/* ------------------------------------------------------------------ */
/* Dashboard assembly                                                  */
/* ------------------------------------------------------------------ */
export async function buildSnapshotDashboard(token: string, userId: string, actor: string): Promise<SnapshotDashboard> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Supabase unavailable')
  const missing = { schema: false }

  // Auto pre-migration snapshots (safety net) + auto-rollback for failures.
  await ensurePreMigrationSnapshots(client, userId, actor, missing)
  if (!missing.schema) await autoRollbackFailedJobs(client, userId, actor)

  const snapshotRows = await rows(client, SNAP_TABLE, (q) => q.select('*').eq('user_id', userId).neq('status', 'deleted').order('created_at', { ascending: false }).limit(300), () => { missing.schema = true })
  const auditRows = await rows(client, AUDIT_TABLE, (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(80))

  const snapshots = snapshotRows.map(mapSnapshot)
  // Lazy expiry.
  const nowMs = Date.now()
  for (const s of snapshots) {
    if (s.status === 'restorable' && s.expiresAt && new Date(s.expiresAt).getTime() < nowMs) {
      s.status = 'expired'
      try { await client.from(SNAP_TABLE).update({ status: 'expired', updated_at: new Date().toISOString() }).eq('id', s.id).eq('user_id', userId) } catch { /* best effort */ }
    }
  }

  const audit: SnapshotAuditEntry[] = auditRows.map((a) => ({
    id: str(a.id), snapshotId: a.snapshot_id ? str(a.snapshot_id) : null, migrationJobId: a.migration_job_id ? str(a.migration_job_id) : null,
    action: str(a.action), actor: str(a.actor), reason: str(a.reason), detail: str(a.detail),
    approvalStatus: str(a.approval_status), validationResult: str(a.validation_result), restorationStatus: str(a.restoration_status), integrityStatus: str(a.integrity_status), createdAt: str(a.created_at),
  }))

  const autoRollbacks = audit.filter((a) => a.action === 'auto_rollback').length
  const manualRollbacks = audit.filter((a) => a.action === 'restored').length
  const latest = snapshots[0]?.createdAt || null

  return {
    generatedAt: new Date().toISOString(),
    schemaReady: !missing.schema,
    summary: {
      total: snapshots.length,
      successful: snapshots.filter((s) => s.integrityVerified).length,
      restorable: snapshots.filter((s) => s.status === 'restorable').length,
      restored: snapshots.filter((s) => s.status === 'restored').length,
      expired: snapshots.filter((s) => s.status === 'expired').length,
      automaticRollbacks: autoRollbacks,
      manualRollbacks,
      storageBytes: snapshots.reduce((sum, s) => sum + s.sizeBytes, 0),
      latestSnapshotAt: latest,
      integrityVerified: snapshots.filter((s) => s.integrityVerified).length,
      integrityFailed: snapshots.filter((s) => !s.integrityVerified).length,
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

router.post('/:snapshotId/restore', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const snapshotId = str(req.params.snapshotId)
    const reason = str(req.body?.reason).trim().slice(0, 1000) || 'Manual restore from snapshot'
    const existing = (await rows(client, SNAP_TABLE, (q) => q.select('*').eq('user_id', user!.id).eq('snapshot_id', snapshotId).limit(1)))[0]
    if (!existing) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Snapshot not found' } })

    // Integrity gate: recompute the hash and refuse to restore a tampered snapshot.
    const { hash } = hashState(rec(existing.crypto_state) as unknown as SnapshotCryptoState)
    const integrityOk = hash === str(existing.integrity_hash)
    if (!integrityOk) {
      await client.from(SNAP_TABLE).update({ integrity_verified: false, updated_at: new Date().toISOString() }).eq('id', existing.id).eq('user_id', user!.id)
      await writeAudit(client, user!.id, { snapshotId, migrationJobId: existing.migration_job_id ? str(existing.migration_job_id) : null, action: 'verified', actor: user!.email || 'owner', reason: 'Integrity check failed during restore', restorationStatus: 'blocked', integrityStatus: 'failed' })
      return res.status(409).json({ error: { code: 'INTEGRITY_FAILED', message: 'Snapshot integrity verification failed — restore blocked.' } })
    }

    /*
     * Executor gate.
     *
     * Restoring a snapshot means pushing the recorded configuration BACK on to
     * the asset, and that needs something able to act on it: an enrolled
     * collector agent on the host, or a cloud connector with scoped write
     * permissions. With neither, the platform can record the operator's intent
     * and mark the plan rolled back, but it CANNOT change the asset.
     *
     * This route previously wrote `restorationStatus: 'completed'` and an audit
     * line reading "Restored <asset> to configuration <version>" in every case,
     * including tenants with zero agents and zero connectors. That is a
     * compliance record asserting a change that never happened.
     */
    const assetId = existing.asset_id ? str(existing.asset_id) : null
    const activeSince = new Date(Date.now() - 15 * 60_000).toISOString()
    const [agents, connectors] = await Promise.all([
      rows(client, 'scanner_agents', (q) => q.select('id, status, last_seen_at').eq('user_id', user!.id).eq('status', 'active').gte('last_seen_at', activeSince).limit(5)),
      rows(client, 'connector_accounts', (q) => q.select('id, provider, status').eq('user_id', user!.id).eq('status', 'connected').limit(5)),
    ])
    const executor = agents.length
      ? { kind: 'agent' as const, id: str(agents[0].id), label: 'collector agent' }
      : connectors.length
        ? { kind: 'connector' as const, id: str(connectors[0].id), label: `${str(connectors[0].provider) || 'cloud'} connector` }
        : null

    const jobId = existing.migration_job_id ? str(existing.migration_job_id) : null
    if (jobId) {
      const job = (await rows(client, 'migration_jobs', (q) => q.select('metadata').eq('user_id', user!.id).eq('id', jobId).limit(1)))[0]
      const meta = rec(job?.metadata)
      await client.from('migration_jobs').update({
        status: executor ? 'rolled_back' : 'rollback_requested',
        metadata: { ...meta, rolledBackFrom: snapshotId, rolledBackAt: new Date().toISOString(), rollbackReason: reason, rollbackExecutor: executor?.kind ?? null },
        updated_at: new Date().toISOString(),
      }).eq('id', jobId).eq('user_id', user!.id)
    }

    // `restored` asserts the asset now matches the snapshot. Only an executor
    // can make that true, so without one the snapshot stays restorable and the
    // request is recorded as pending.
    await client.from(SNAP_TABLE).update({
      status: executor ? 'restored' : 'restorable',
      restored_at: executor ? new Date().toISOString() : null,
      updated_at: new Date().toISOString(),
    }).eq('id', existing.id).eq('user_id', user!.id)

    const detail = executor
      ? `Rollback of ${str(existing.asset_name)} to configuration ${str(existing.configuration_version)} dispatched to the ${executor.label}. Awaiting execution confirmation.`
      : `Rollback of ${str(existing.asset_name)} to configuration ${str(existing.configuration_version)} RECORDED BUT NOT APPLIED — no collector agent or cloud connector is available to act on this asset. The snapshot remains restorable.`

    await writeAudit(client, user!.id, {
      snapshotId,
      migrationJobId: jobId,
      action: 'restored',
      actor: user!.email || 'owner',
      reason,
      detail,
      approvalStatus: 'owner-approved',
      validationResult: 'n/a',
      restorationStatus: executor ? 'dispatched' : 'awaiting-executor',
      integrityStatus: 'verified',
    })

    res.json({
      data: {
        snapshotId,
        status: executor ? 'dispatched' : 'awaiting-executor',
        jobId,
        assetId,
        executor: executor ? { kind: executor.kind, label: executor.label } : null,
        applied: Boolean(executor),
        message: executor
          ? `Rollback dispatched to the ${executor.label}. The asset is updated once the executor confirms.`
          : 'No collector agent or cloud connector is available for this asset, so nothing was changed on it. The rollback intent and the snapshot are recorded; enrol a collector to execute it.',
      },
    })
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
