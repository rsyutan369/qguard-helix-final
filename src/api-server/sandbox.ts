import { Router, type NextFunction, type Request, type Response } from 'express'
import { createAuthClient, getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { buildScannerIntelligence } from './scanner'
import { buildSnapshot as buildQuantumReadinessSnapshot } from './quantum-readiness'
import { dedupeGradedObservations, namesCryptography, observationClass } from '@/lib/scanner/finding-identity'
import { riskBandFor, riskScoreFromLoad } from '@/lib/migration/asset-intelligence'
import { isSimulationJob, jobPlanId } from '@/lib/migration/job-safety'
import { describeOperationalWorkflow } from '@/lib/migration/operational-workflow'
import { jobExecutionClass } from './agent-scanner'
import { loadAgentFleet as loadAgentFleetShared, loadPlanApprovals as loadPlanApprovalsShared } from './operational-fleet'
import {
  ENGINE_PIPELINE_STAGES,
  SIMULATION_TYPES,
  assembleTwinIntelligence,
  buildDependencyGraph,
  buildDigitalTwin,
  buildTopology,
  pipelineStageForProgress,
  predictFailures,
  simulationTypeById,
  type TwinBundle,
} from './sandbox-twin'

type AuthenticatedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

const router = Router()
let sandboxSchedulerStarted = false

const ENGINE_NAME = 'qguard-sandbox-orchestrator'
const ACTIVE_JOB_STATUSES = ['pending', 'queued', 'running', 'in_progress', 'executing', 'rollback_requested']
const DELETABLE_SIMULATION_STATUSES = ['completed', 'failed', 'stopped', 'rolled_back']

const ENGINE_PHASES = [
  { id: 'preparation', label: 'Preparation', detail: 'Environment snapshot, dependency inventory, and rollback checkpoint.', at: 0 },
  { id: 'assessment', label: 'Risk Assessment', detail: 'Crypto exposure scoring, compatibility checks, and policy validation.', at: 22 },
  { id: 'execution', label: 'Sandbox Execution', detail: 'PQC replacement plan is exercised against sandbox controls.', at: 48 },
  { id: 'verification', label: 'Verification', detail: 'Handshake, key material, certificate, and application behavior validation.', at: 74 },
  { id: 'finalization', label: 'Finalization', detail: 'Evidence collection, readiness scoring, and report finalization.', at: 94 },
]

function tokenFromRequest(req: Request): string | null {
  const header = getToken(req)
  if (header) return header
  const q = req.query.token
  return typeof q === 'string' && q.length > 0 ? q : null
}

async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = tokenFromRequest(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  req.user = user
  req.token = token
  next()
}

function clientFor(req: AuthenticatedRequest) {
  return req.token ? createAuthClient(req.token) : null
}

function sseHeaders(res: Response) {
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()
}

function writeSse(res: Response, event: string, data: unknown) {
  if (res.writableEnded) return
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
}

function isMissingTable(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return text.includes('42p01') || text.includes('pgrst205') || text.includes('does not exist') || text.includes('could not find the table')
}

function isSchemaShapeError(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return isMissingTable(error)
    || text.includes('42703')
    || text.includes('pgrst204')
    || text.includes('could not find')
    || text.includes('column')
}

// Transient infrastructure failures (dropped keep-alive sockets, gateway
// hiccups, throttling) must never be mistaken for "tenant has no data".
const TRANSIENT_RETRY_DELAYS_MS = [250, 750]

function isTransientQueryError(error: any) {
  const text = `${error?.name || ''} ${error?.code || ''} ${error?.message || ''} ${error?.details || ''} ${error?.cause?.code || ''} ${error?.cause?.message || ''}`.toLowerCase()
  return /fetch failed|network|socket|econnreset|econnrefused|etimedout|epipe|und_err|other side closed|terminated|timeout|timed out|too many requests|rate limit|\b429\b|\b502\b|\b503\b|\b504\b|bad gateway|service unavailable/.test(text)
}

class SnapshotUnavailableError extends Error {
  table: string
  constructor(table: string, detail: string) {
    super(`Sandbox snapshot aborted: "${table}" query failed (${detail})`)
    this.name = 'SnapshotUnavailableError'
    this.table = table
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return value as Record<string, unknown>
}

function pickStr(rec: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const v = rec[key]
    if (typeof v === 'string' && v.trim()) return v.trim()
  }
  return ''
}

function normalizeStatus(s: unknown): string {
  const v = String(s || '').toLowerCase().replace(/\s+/g, '_')
  if (['completed', 'complete', 'done', 'success'].includes(v)) return 'completed'
  // A failed rollback or validation needs an operator — Live Migration reads
  // both as failed. Falling through to 'queued' showed them as waiting to run.
  if (['failed', 'error', 'errored', 'rollback_failed', 'validation_failed'].includes(v)) return 'failed'
  if (['running', 'in_progress', 'executing', 'migrating'].includes(v)) return 'running'
  if (['rollback_requested', 'rollback', 'rolling_back'].includes(v)) return 'rollback_requested'
  if (['rolled_back', 'rollback_complete'].includes(v)) return 'rolled_back'
  if (['stopped', 'stop', 'cancelled', 'canceled'].includes(v)) return 'stopped'
  if (['paused'].includes(v)) return 'paused'
  return 'queued'
}

function clamp(v: number, lo = 0, hi = 100) {
  return Math.max(lo, Math.min(hi, Math.round(v)))
}

function severityRank(s: string) {
  const v = s.toLowerCase()
  if (v === 'critical') return 4
  if (v === 'high') return 3
  if (v === 'medium' || v === 'moderate' || v === 'warning') return 2
  return 1
}

/**
 * PQC replacement for a classical primitive, resolved by USAGE.
 *
 * ML-KEM (FIPS 203) is key establishment ONLY; signatures take ML-DSA (FIPS 204)
 * or SLH-DSA (FIPS 205). Order matters: authentication is tested before key
 * establishment, because "ECDSA certificate" contains neither "rsa" nor
 * "key exchange" but must never resolve to a KEM — and a certificate seen on a
 * TLS asset would otherwise match the `tls` branch and be handed ML-KEM.
 */
function pqcAlgoRec(from: string, context = '') {
  const v = `${from} ${context}`.toLowerCase()
  if (v.includes('sha1') || v.includes('sha-1') || v.includes('md5') || v.includes('hash')) return 'SHA3-256'
  if (v.includes('ecdsa') || v.includes('dsa') || v.includes('sign') || v.includes('certificate')) return 'ML-DSA-65'
  if (v.includes('ecdh') || v.includes('x25519') || v.includes('dh')) return 'X25519 + ML-KEM-768 hybrid'
  if (v.includes('rsa') || v.includes('key exchange') || v.includes('cipher suite') || v.includes('tls')) return 'ML-KEM-768'
  if (v.includes('aes-128') || v.includes('3des') || v.includes('rc4') || v.includes('des')) return 'AES-256-GCM'
  // Usage unknown — do not assert a specific primitive. Naming a KEM here is how
  // policy findings ended up "migrating to ML-KEM-768".
  return 'PQC target pending classification'
}

function quantumRisk(algo: string): 'critical' | 'high' | 'medium' | 'low' {
  const v = algo.toLowerCase()
  if (v.includes('rsa') || v.includes('ecdsa') || v.includes('dh ')) return 'critical'
  if (v.includes('sha1') || v.includes('md5') || v.includes('3des')) return 'high'
  if (v.includes('aes-128') || v.includes('tls 1.2')) return 'medium'
  return 'low'
}

function boolMeta(value: unknown) {
  return value === true || value === 'true' || value === 1 || value === '1'
}

/**
 * An asset's migration risk, from its OWN exposure evidence — the rule the
 * Simulation Builder ranks targets by. Workflow rows use it too: they used to
 * take `quantumRisk(sourceAlgorithm)` alone, which matches only literal "rsa" /
 * "ecdsa" / "dh " and so published "low" for sources recorded as "TLSv1" or
 * "Classical crypto" — a planner cutover on an asset carrying critical
 * exposures read "low" in its Details header, and a simulation the builder had
 * started as critical was listed as low.
 */
function evidenceRiskLevel(invItems: any[], expItems: any[], fallbackAlgorithm: string): 'critical' | 'high' | 'medium' | 'low' {
  const severity = (exposure: any) => String(exposure?.severity || '').toLowerCase()
  if (expItems.some((exposure) => severity(exposure) === 'critical')) return 'critical'
  if (expItems.some((exposure) => severity(exposure) === 'high')) return 'high'
  if (invItems.some((item) => item?.is_vulnerable || item?.is_quantum_safe === false)) return 'medium'
  return quantumRisk(fallbackAlgorithm)
}

// Derives the real cryptographic seed for simulating one tenant asset:
// source algorithm comes from scanned crypto inventory / exposures, never
// from hardcoded defaults, so the simulation reflects what the scanner found.
function assetSimulationSeed(asset: any, invItems: any[], expItems: any[]) {
  const vulnerableItems = invItems.filter((i: any) => i.is_vulnerable || i.is_quantum_safe === false)
  // The source must be a record that actually NAMES cryptography. Taking
  // `vulnerableItems[0].algorithm` in whatever order the query returned picked
  // up policy findings, producing simulations literally named
  // "[DRY RUN] host (No CAA Issuance Policy -> ML-KEM-768)" — a DNS policy gap
  // "migrated" to a key-encapsulation mechanism.
  const cryptoRow = (rows: any[]) => rows.find((i: any) => namesCryptography(i?.name) && String(i?.algorithm || '').trim())
  const seedRow = cryptoRow(vulnerableItems) || cryptoRow(invItems)
  const sourceAlgorithm = String(
    seedRow?.algorithm
    || expItems.find((e: any) => String(e?.detected_value || '').trim())?.detected_value
    || ''
  ).trim() || 'Classical'
  // Usage decides the PQC target (FIPS 203 for key establishment, FIPS 204/205
  // for authentication), so pass the observation class the source came from.
  const context = `${observationClass(seedRow?.name)} ${seedRow?.item_type || ''} ${seedRow?.protocol || ''} ${asset?.type || ''}`
  const targetAlgorithm = pqcAlgoRec(sourceAlgorithm, context)
  const criticalExposures = expItems.filter((e: any) => String(e.severity || '').toLowerCase() === 'critical').length

  return {
    sourceAlgorithm,
    targetAlgorithm,
    // Risk comes from the asset's OWN exposure evidence, with the seed
    // algorithm only as a tiebreaker. Deriving it from the algorithm name alone
    // made a TLS 1.2 endpoint carrying 13 critical exposures read "low",
    // because `quantumRisk()` matches the literal "tls 1.2" and the scanner
    // records "TLSv1.2" — and that level drives the Simulation Builder's risk
    // filter, so the asset was invisible to a "critical/high" selection.
    riskLevel: evidenceRiskLevel(invItems, expItems, sourceAlgorithm),
    inventoryItems: invItems.length,
    vulnerableItems: vulnerableItems.length,
    exposures: expItems.length,
    criticalExposures,
    algorithms: Array.from(new Set(invItems.map((i: any) => String(i.algorithm || '').trim()).filter(Boolean))).slice(0, 8),
  }
}

function groupRowsByAsset(rows: any[]) {
  const map = new Map<string, any[]>()
  for (const row of rows || []) {
    if (!row?.asset_id) continue
    const list = map.get(row.asset_id) || []
    list.push(row)
    map.set(row.asset_id, list)
  }
  return map
}

function textMeta(rec: Record<string, unknown>, keys: string[], fallback = '') {
  const value = pickStr(rec, keys)
  return value || fallback
}

function dateMs(value: unknown) {
  if (typeof value !== 'string' || !value) return 0
  const ms = new Date(value).getTime()
  return Number.isFinite(ms) ? ms : 0
}

// Jobs created through the enterprise Simulation Builder carry
// metadata.pipelineVersion = 2 and progress through the full 14-stage
// enterprise pipeline; older jobs keep the legacy 5-phase engine.
function isEnterprisePipelineJob(meta: Record<string, unknown>) {
  return Number(meta.pipelineVersion) >= 2 || typeof meta.simulationType === 'string'
}

function phaseForProgress(progress: number, status: string, meta: Record<string, unknown>) {
  const explicit = textMeta(meta, ['phase', 'enginePhase', 'currentPhase'])
  const enterprise = isEnterprisePipelineJob(meta)
  if (status === 'rollback_requested' || status === 'rolled_back') {
    return { id: 'rollback', label: 'Rollback', detail: 'Recovery workflow is restoring the previous cryptographic posture.' }
  }
  if (status === 'queued') {
    return { id: 'queued', label: 'Queued', detail: textMeta(meta, ['queueReason'], 'Awaiting sandbox executor capacity.') }
  }
  if (status === 'paused') {
    return { id: 'paused', label: 'Paused', detail: 'Operator paused this workflow.' }
  }
  if (status === 'stopped') {
    return { id: 'stopped', label: 'Stopped', detail: 'Operator stopped this workflow.' }
  }
  if (status === 'failed') {
    return { id: 'failed', label: 'Failed', detail: textMeta(meta, ['failureReason', 'error'], 'Workflow requires operator review.') }
  }
  if (status === 'completed') {
    if (enterprise) {
      const last = ENGINE_PIPELINE_STAGES[ENGINE_PIPELINE_STAGES.length - 1]
      return { id: last.id, label: last.label, detail: last.detail }
    }
    return ENGINE_PHASES[ENGINE_PHASES.length - 1]
  }
  if (enterprise) {
    const stage = pipelineStageForProgress(progress)
    return { id: stage.id, label: stage.label, detail: stage.detail }
  }
  const selected = [...ENGINE_PHASES].reverse().find((phase) => progress >= phase.at) || ENGINE_PHASES[0]
  if (explicit) return { ...selected, id: explicit.toLowerCase().replace(/\s+/g, '_'), label: explicit }
  return selected
}

/* One definition, shared with the agent claim path and Live Migration — see
   `@/lib/migration/job-safety`. This file's copy and migration.ts's copy had
   drifted (only this one honoured `metadata.dryRun`), and the agent claim path
   had none, so a queued dry run was claimable by a real agent. */
function isSandboxSimulationJob(job: any) {
  return isSimulationJob(job)
}

function canDeleteSimulationJob(job: any) {
  return isSandboxSimulationJob(job) && DELETABLE_SIMULATION_STATUSES.includes(normalizeStatus(job?.status))
}

function classifyJobMode(job: any): 'dry_run' | 'simulation' | 'remediation' | 'actual_migration' | 'migration_workflow' {
  const meta = asRecord(job?.metadata)
  if (isSandboxSimulationJob(job)) return boolMeta(meta.dryRun) ? 'dry_run' : 'simulation'
  const source = textMeta(meta, ['source']).toLowerCase()
  const workflow = textMeta(meta, ['workflow']).toLowerCase()
  const jobType = String(job?.job_type || '').toLowerCase()
  if (source === 'harvest-now' || workflow.includes('hndl') || jobType.includes('remediation')) return 'remediation'
  if (boolMeta(meta.productionMigration) || textMeta(meta, ['executionMode', 'runMode']).toLowerCase().includes('production')) return 'actual_migration'
  return 'migration_workflow'
}

function modeLabel(mode: string) {
  if (mode === 'dry_run') return 'Dry Run'
  if (mode === 'simulation') return 'Sandbox Simulation'
  if (mode === 'remediation') return 'Remediation Workflow'
  if (mode === 'actual_migration') return 'Actual Migration'
  return 'Migration Workflow'
}

function jobNoun(job: any) {
  return modeLabel(classifyJobMode(job)).toLowerCase()
}

function estimateSandboxDurationMs(job: any) {
  const meta = asRecord(job?.metadata)
  const explicit = Number(meta.simulatedDurationMs || meta.estimatedDurationMs)
  if (Number.isFinite(explicit) && explicit >= 30000) return explicit
  // Enterprise simulation types carry their own duration profile.
  if (typeof meta.simulationType === 'string') {
    const profile = simulationTypeById(meta.simulationType)
    const scale = boolMeta(meta.dryRun) ? 0.55 : 1
    return Math.round((profile.baseDurationMs + profile.perAssetMs) * scale)
  }
  const base = boolMeta(meta.dryRun) ? 110_000 : 220_000
  const jobText = `${job?.job_type || ''} ${job?.name || ''} ${JSON.stringify(meta)}`.toLowerCase()
  const complexity = /hsm|database|certificate|vpn|tls/.test(jobText) ? 70_000 : 0
  const criticality = /critical|high/.test(jobText) ? 45_000 : 0
  return base + complexity + criticality
}

function engineEta(job: any, status: string, progress: number, meta: Record<string, unknown>) {
  const explicit = textMeta(meta, ['eta', 'estimatedEta', 'estimated_eta', 'remaining'])
  if (explicit) return explicit
  if (status === 'completed') return 'Finished'
  if (status === 'failed') return 'Review required'
  if (status === 'paused') return 'Paused'
  if (status === 'stopped') return 'Stopped'
  if (status === 'rolled_back') return 'Rolled back'
  // Operational (non-sandbox) rollbacks are requests: they wait for an
  // approved executor and are never auto-completed by the sandbox engine.
  if (status === 'rollback_requested' && !isSandboxSimulationJob(job)) return 'Rollback awaiting approved executor'
  if (status === 'queued') return textMeta(meta, ['queueReason'], 'Awaiting executor')
  const started = dateMs(String(job?.started_at || meta.engineStartedAt || job?.updated_at || job?.created_at || ''))
  if (!started || progress <= 0) return 'Calculating'
  const duration = estimateSandboxDurationMs(job)
  const remainingMs = Math.max(0, duration - (Date.now() - started))
  const minutes = Math.max(1, Math.ceil(remainingMs / 60000))
  return minutes >= 60 ? `~${Math.ceil(minutes / 60)}h remaining` : `~${minutes}m remaining`
}

async function insertEngineEvent(client: any, job: any, type: string, message: string, severity = 'info', metadata: Record<string, unknown> = {}) {
  const userId = job.user_id
  if (!userId || !job.id) return
  const { error } = await client.from('migration_events').insert({
    user_id: userId,
    migration_id: job.id,
    event_type: type,
    severity,
    message,
    metadata: { source: ENGINE_NAME, ...metadata },
    created_at: new Date().toISOString(),
  })
  if (error && !isMissingTable(error)) console.warn('[sandbox] engine event insert failed:', error.message)
}

// Every snapshot build used to run the engine unconditionally. Because engine
// writes fire Supabase realtime events that make every open dashboard refetch
// (which builds a snapshot, which runs the engine again...), an unthrottled
// engine turns one running simulation into a self-sustaining write/refetch
// storm. A short per-scope interval keeps progress smooth (~1%/1.1s at the
// fastest) while breaking the feedback loop.
const ADVANCE_MIN_INTERVAL_MS = 2500
const lastAdvanceAt = new Map<string, number>()

async function advanceSandboxJobs(client: any, userId?: string) {
  const throttleKey = userId || '__all__'
  const lastRun = lastAdvanceAt.get(throttleKey) || 0
  if (Date.now() - lastRun < ADVANCE_MIN_INTERVAL_MS) return { advanced: 0, advancedUsers: [] as string[] }
  lastAdvanceAt.set(throttleKey, Date.now())

  let query = client
    .from('migration_jobs')
    .select('id, user_id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at')
    .in('status', ACTIVE_JOB_STATUSES)
    .order('updated_at', { ascending: true })
    .limit(300)

  if (userId) query = query.eq('user_id', userId)

  const { data: rows, error } = await query
  if (error) {
    if (!isMissingTable(error)) console.warn('[sandbox] advance jobs:', error.message)
    return { advanced: 0, advancedUsers: [] as string[] }
  }

  const now = new Date()
  const nowIso = now.toISOString()
  let advanced = 0
  // Tenants whose jobs actually moved, so the caller can drop exactly their
  // cached snapshots instead of waiting out the TTL.
  const advancedUsers = new Set<string>()
  const sandboxRows = (rows || []).filter(isSandboxSimulationJob)

  for (const [index, job] of sandboxRows.entries()) {
    const status = normalizeStatus(job.status)
    const meta = asRecord(job.metadata)
    const progress = clamp(Number(job.progress || 0))
    const updateMeta = {
      ...meta,
      sandboxMode: true,
      engine: ENGINE_NAME,
      lastEngineTickAt: nowIso,
      queuePosition: status === 'queued' ? index + 1 : meta.queuePosition,
    }

    let update: any | null = null
    let event: { type: string; message: string; severity?: string; metadata?: Record<string, unknown> } | null = null

    if (status === 'queued') {
      const queuedAt = dateMs(String(meta.queuedAt || job.created_at || job.updated_at || ''))
      const queueDelay = Math.min(45_000, 8_000 + index * 1500)
      if (queuedAt && now.getTime() - queuedAt < queueDelay) {
        const queueReason = `Executor slot ${index + 1} of ${sandboxRows.length}`
        // Only write when the queue bookkeeping actually changed — an
        // unconditional write here re-triggers realtime → refetch → advance
        // in a tight loop for the whole queue window.
        if (meta.phase !== 'queued' || meta.queueReason !== queueReason || meta.sandboxMode !== true) {
          update = {
            status: 'queued',
            progress: 0,
            updated_at: nowIso,
            metadata: {
              ...updateMeta,
              phase: 'queued',
              queueReason,
            },
          }
        }
      } else {
        update = {
          status: 'running',
          progress: Math.max(progress, 4),
          started_at: job.started_at || nowIso,
          updated_at: nowIso,
          metadata: {
            ...updateMeta,
            engineStartedAt: job.started_at || nowIso,
            phase: 'preparation',
            phaseDetail: ENGINE_PHASES[0].detail,
            queueReason: null,
            simulatedDurationMs: estimateSandboxDurationMs(job),
          },
        }
        event = {
          type: 'sandbox-simulation-running',
          message: `${modeLabel(classifyJobMode(job))} started by ${ENGINE_NAME}: ${job.name || job.id}.`,
          metadata: { phase: 'preparation' },
        }
      }
    } else if (status === 'running') {
      const startedAt = dateMs(String(job.started_at || meta.engineStartedAt || job.created_at || job.updated_at || '')) || now.getTime()
      const duration = estimateSandboxDurationMs(job)
      const elapsed = Math.max(0, now.getTime() - startedAt)
      const nextProgress = clamp((elapsed / duration) * 100)
      // Recompute the phase from real progress ({} = no stored-phase override):
      // passing `meta` here made phaseForProgress echo the previously written
      // phase back, so the engine never detected a transition and never emitted
      // phase events.
      const phase = phaseForProgress(nextProgress, 'running', {})
      const previousPhase = textMeta(meta, ['lastEnginePhase', 'phase'])

      if (nextProgress >= 100) {
        update = {
          status: 'completed',
          progress: 100,
          completed_at: job.completed_at || nowIso,
          updated_at: nowIso,
          metadata: {
            ...updateMeta,
            phase: 'finalization',
            phaseDetail: ENGINE_PHASES[ENGINE_PHASES.length - 1].detail,
            lastEnginePhase: 'finalization',
            engineCompletedAt: nowIso,
          },
        }
        event = {
          type: 'sandbox-simulation-completed',
          severity: 'success',
          message: `${modeLabel(classifyJobMode(job))} completed validation: ${job.name || job.id}.`,
          metadata: { phase: 'finalization', progress: 100 },
        }
      } else if (nextProgress > progress || phase.id !== previousPhase) {
        // Enterprise pipeline jobs accumulate an auditable per-stage history
        // (entered-at + progress) that powers the Migration Pipeline rail.
        const priorHistory = Array.isArray(meta.stageHistory) ? (meta.stageHistory as any[]) : []
        const stageHistory = phase.id !== previousPhase
          ? [...priorHistory, { id: phase.id, label: (phase as any).label || phase.id, enteredAt: nowIso, progress: Math.round(nextProgress) }].slice(-20)
          : priorHistory
        update = {
          status: 'running',
          progress: Math.max(progress, nextProgress),
          updated_at: nowIso,
          metadata: {
            ...updateMeta,
            phase: phase.id,
            phaseDetail: phase.detail,
            lastEnginePhase: phase.id,
            stageHistory,
            simulatedDurationMs: duration,
          },
        }
        if (phase.id !== previousPhase) {
          event = {
            type: 'sandbox-phase-transition',
            message: `${modeLabel(classifyJobMode(job))} entered ${(phase as any).label || phase.id}: ${job.name || job.id}.`,
            metadata: { phase: phase.id, progress: nextProgress },
          }
        }
      }
    } else if (status === 'rollback_requested') {
      const rollbackAt = dateMs(String(meta.rollbackRequestedAt || job.updated_at || nowIso)) || now.getTime()
      const rollbackProgress = clamp(((now.getTime() - rollbackAt) / 45_000) * 100)
      if (rollbackProgress >= 100) {
        const { snapshotId, snapshots } = snapshotEntry(job, 'rollback-complete', nowIso, meta)
        update = {
          status: 'rolled_back',
          progress: 100,
          completed_at: nowIso,
          updated_at: nowIso,
          metadata: {
            ...updateMeta,
            phase: 'rollback',
            phaseDetail: 'Rollback completed and previous cryptographic posture restored.',
            lastRollbackSnapshotId: snapshotId,
            snapshots,
          },
        }
        event = {
          type: 'sandbox-rollback-completed',
          severity: 'warning',
          message: `${modeLabel(classifyJobMode(job))} rollback completed: ${job.name || job.id}.`,
          metadata: { phase: 'rollback', progress: 100, snapshotId },
        }
      } else {
        update = {
          status: 'rollback_requested',
          progress: rollbackProgress,
          updated_at: nowIso,
          metadata: {
            ...updateMeta,
            phase: 'rollback',
            phaseDetail: 'Rollback validation is restoring the previous cryptographic control set.',
            rollbackProgress,
          },
        }
      }
    }

    if (!update) continue
    const { error: updateError } = await client
      .from('migration_jobs')
      .update(update)
      .eq('id', job.id)
      .eq('user_id', job.user_id)
    if (updateError) {
      if (!isMissingTable(updateError)) console.warn('[sandbox] engine update failed:', updateError.message)
      continue
    }
    advanced++
    if (job.user_id) advancedUsers.add(String(job.user_id))
    if (event) await insertEngineEvent(client, job, event.type, event.message, event.severity || 'info', event.metadata || {})
  }

  return { advanced, advancedUsers: [...advancedUsers] }
}

function buildSnapshotState(job: any, meta: Record<string, unknown>, context?: any) {
  const workflows = Array.isArray(context?.workflows) ? context.workflows : []
  const simulations = Array.isArray(context?.simulations) ? context.simulations : []
  const current = [...simulations, ...workflows].find((row: any) => row?.id === job?.id) || {}
  const summary = asRecord(context?.summary)
  const complianceItems = Array.isArray(context?.complianceItems) ? context.complianceItems : []
  const sourceAlgorithm = current.fromAlgo || pickStr(meta, ['sourceAlgorithm', 'source_algorithm', 'fromAlgorithm', 'from_algorithm', 'fromAlgo']) || 'Classical'
  const targetAlgorithm = current.toAlgo || job?.target_algorithm || pickStr(meta, ['targetAlgorithm', 'target_algorithm', 'toAlgo']) || pqcAlgoRec(sourceAlgorithm, job?.job_type || '')
  const status = normalizeStatus(job?.status || current.status)
  const progress = clamp(Number(job?.progress ?? current.progress ?? 0))

  return {
    assetState: {
      assetId: job?.asset_id || current.assetId || null,
      assetName: current.assetName || pickStr(meta, ['assetName', 'asset_name']) || 'Unknown Asset',
      assetType: current.assetType || pickStr(meta, ['assetType', 'asset_type']) || 'service',
      environment: current.environment || pickStr(meta, ['environment']) || 'sandbox',
      owner: current.owner || pickStr(meta, ['owner', 'serviceOwner']) || 'Unassigned',
      criticality: current.criticality || pickStr(meta, ['criticality']) || 'medium',
    },
    riskState: {
      riskLevel: current.riskLevel || quantumRisk(sourceAlgorithm),
      // The tenant's canonical quantum risk at capture (0–100, LOWER is better)
      // — the value the Overview shows. This used to read `summary.riskScore`,
      // a field the summary no longer carries, so every capture recorded 0 (a
      // perfect score on a lower-better scale) or fell through to whatever
      // `riskScore` the job's metadata happened to hold. Null = not assessed.
      quantumRiskScore: typeof summary.quantumRiskScore === 'number' ? summary.quantumRiskScore : null,
      quantumRiskSource: String(summary.quantumRiskSource || 'not-assessed'),
      criticalExposures: Number(summary.criticalExposures ?? 0),
      highExposures: Number(summary.highExposures ?? 0),
      runtimeSignals: Number((context?.riskFactors || []).find((f: any) => f?.label === 'Runtime Crypto Risk Signals')?.count || 0),
    },
    complianceState: {
      score: Number(context?.complianceScore ?? summary.complianceScore ?? meta.complianceScore ?? 0),
      controls: complianceItems.slice(0, 12).map((item: any) => ({
        framework: item.framework,
        control: item.control,
        status: item.status,
        score: item.score,
      })),
    },
    simulationState: {
      id: job?.id,
      name: job?.name || current.name || job?.id,
      status,
      progress,
      phase: current.phase || textMeta(meta, ['phase']) || 'unknown',
      phaseDetail: current.phaseDetail || textMeta(meta, ['phaseDetail']) || '',
      startedAt: job?.started_at || current.startedAt || null,
      completedAt: job?.completed_at || current.completedAt || null,
    },
    migrationState: {
      jobType: job?.job_type || current.migrationType || 'sandbox_pqc_migration',
      strategy: job?.strategy || `${sourceAlgorithm} -> ${targetAlgorithm}`,
      sourceAlgorithm,
      targetAlgorithm,
      runMode: current.runMode || textMeta(meta, ['executionMode', 'runMode']) || classifyJobMode(job),
      engine: textMeta(meta, ['engine'], ENGINE_NAME),
    },
    configurationState: {
      sandboxMode: true,
      dryRun: boolMeta(meta.dryRun),
      executionScope: current.executionScope || textMeta(meta, ['executionScope'], 'sandbox'),
      deploymentControls: meta.deploymentControls || meta.controls || null,
      rollbackPolicy: meta.rollbackPolicy || meta.rollback || 'snapshot-required',
      connector: meta.connector || meta.operator || null,
    },
  }
}

function snapshotEntry(job: any, action: string, now: string, meta: Record<string, unknown>, context?: any) {
  const snapshots = Array.isArray(meta.snapshots) ? [...(meta.snapshots as any[])] : []
  const snapshotId = `snap_${now.replace(/[-:.TZ]/g, '').slice(0, 14)}_${String(job.id || '').slice(0, 8)}`
  const state = buildSnapshotState(job, meta, context)
  snapshots.push({
    id: snapshotId,
    at: now,
    action,
    progress: Number(job.progress || 0),
    status: job.status || 'unknown',
    name: job.name || job.id,
    ...state,
  })
  return { snapshotId, snapshots: snapshots.slice(-25), state }
}

/**
 * Controls that drive the SANDBOX ENGINE, which only ever runs simulations.
 *
 * On an operational job (a planner cutover, a Harvest Now remediation) they
 * would write engine state onto a real migration record: `resume` / `retry`
 * set `running` with no executor behind it and skip the approval re-check Live
 * Migration applies, and `restore_snapshot` wrote `rolled_back` plus "rollback
 * posture validated" although nothing ran on the asset. Operational jobs are
 * executed, paused and rolled back through Live Migration Operations.
 */
const SANDBOX_ENGINE_ONLY_ACTIONS = ['pause', 'resume', 'retry', 'stop', 'restore_snapshot']

function sandboxEngineActionRefusal(job: any, action: string): string | null {
  if (!SANDBOX_ENGINE_ONLY_ACTIONS.includes(action) || isSandboxSimulationJob(job)) return null
  return `"${job?.name || 'This job'}" is an operational migration job, not a sandbox simulation. Its execution, approval and rollback are managed in Live Migration Operations; the sandbox engine never changes it.`
}

function actionUpdate(job: any, action: string, now: string, options: { snapshotId?: string; context?: any } = {}) {
  const meta = asRecord(job.metadata)
  const nextMeta = { ...meta, lastOperatorAction: action, lastOperatorActionAt: now }
  let update: any = { updated_at: now, metadata: nextMeta }

  if (action === 'pause') update = { ...update, status: 'paused', metadata: { ...nextMeta, pausedAt: now, phase: 'paused' } }
  else if (action === 'resume') update = { ...update, status: 'running', started_at: now, metadata: { ...nextMeta, engineStartedAt: now, phase: 'preparation', queueReason: null } }
  else if (action === 'retry') update = { ...update, status: 'running', progress: 0, started_at: now, completed_at: null, metadata: { ...nextMeta, engineStartedAt: now, phase: 'preparation', retryAt: now, queueReason: null } }
  else if (action === 'rollback') update = { ...update, status: 'rollback_requested', progress: 0, metadata: { ...nextMeta, rollbackRequestedAt: now, phase: 'rollback' } }
  else if (action === 'stop') update = { ...update, status: 'stopped', completed_at: now, metadata: { ...nextMeta, stoppedAt: now, phase: 'stopped' } }
  else if (action === 'snapshot') {
    const { snapshotId, snapshots, state } = snapshotEntry(job, action, now, meta, options.context)
    update = { ...update, metadata: { ...nextMeta, snapshots, lastSnapshotId: snapshotId, lastSnapshotAt: now, lastSnapshotState: state } }
  } else if (action === 'restore_snapshot') {
    const snapshots = Array.isArray(meta.snapshots) ? meta.snapshots as Array<Record<string, unknown>> : []
    const requested = options.snapshotId || String(meta.lastSnapshotId || '')
    const selected = [...snapshots].reverse().find((snap) => String(snap.id || '') === requested) || snapshots[snapshots.length - 1]
    const restoredProgress = clamp(Number(selected?.progress ?? job.progress ?? 0))
    update = {
      ...update,
      status: 'rolled_back',
      progress: Math.max(restoredProgress, 100),
      completed_at: now,
      metadata: {
        ...nextMeta,
        phase: 'rollback',
        phaseDetail: selected
          ? `Snapshot ${String(selected.id || 'latest')} restored and rollback posture validated.`
          : 'Snapshot restore requested; no captured snapshot was present, rollback posture validated from current metadata.',
        restoredSnapshotId: selected?.id || null,
        restoredAt: now,
      },
    }
  }

  return update
}

function actionMessage(action: string, jobName: string, noun = 'sandbox simulation') {
  if (action === 'pause') return `Operator paused ${noun} "${jobName}".`
  if (action === 'resume') return `Operator resumed ${noun} "${jobName}".`
  if (action === 'retry') return `Operator retried ${noun} "${jobName}".`
  if (action === 'rollback') return `Operator requested rollback for ${noun} "${jobName}".`
  if (action === 'stop') return `Operator stopped ${noun} "${jobName}".`
  if (action === 'snapshot') return `Operator captured recovery snapshot for ${noun} "${jobName}".`
  if (action === 'restore_snapshot') return `Operator restored a recovery snapshot for ${noun} "${jobName}".`
  if (action === 'delete') return `Operator deleted ${noun} "${jobName}" and purged simulation execution artifacts.`
  return `Operator ${action} action recorded for ${noun} "${jobName}".`
}

function actionSeverity(action: string) {
  return action === 'rollback' || action === 'stop' || action === 'restore_snapshot' || action === 'delete' ? 'warning' : 'info'
}

async function recordOperatorTelemetry(client: any, req: AuthenticatedRequest, jobs: any[], action: string, now: string, mode: 'single' | 'bulk') {
  if (!jobs.length) return
  const userId = req.user!.id
  const eventRows = jobs.map((job) => ({
    user_id: userId,
    migration_id: job.id,
    event_type: `operator-${action}`,
    severity: actionSeverity(action),
    message: actionMessage(action, job.name || job.id, jobNoun(job)),
    metadata: { action, mode, operator: req.user!.email || null, executionMode: classifyJobMode(job) },
    created_at: now,
  }))
  const { error: eventError } = await client.from('migration_events').insert(eventRows)
  if (eventError && !isMissingTable(eventError)) console.warn('[sandbox] operator event insert failed:', eventError.message)

  const securityMessage = mode === 'bulk'
    ? `Sandbox ${action} requested for ${jobs.length} migration job(s).`
    : actionMessage(action, jobs[0]?.name || jobs[0]?.id || 'simulation', jobNoun(jobs[0]))
  const { error: securityError } = await client.from('security_events').insert({
    user_id: userId,
    event_type: `sandbox-${action}`,
    severity: actionSeverity(action),
    message: securityMessage,
    asset_id: null,
    resource_name: mode === 'bulk' ? 'Migration Sandbox' : jobs[0]?.name || jobs[0]?.id || 'Migration Sandbox',
    resource_type: 'migration-sandbox',
    metadata: {
      action,
      mode,
      executionModes: Array.from(new Set(jobs.map((job) => classifyJobMode(job)))),
      jobIds: jobs.map((job) => job.id).filter(Boolean).slice(0, 100),
      affected: jobs.length,
    },
    created_at: now,
  })
  if (securityError && !isMissingTable(securityError)) console.warn('[sandbox] security event insert failed:', securityError.message)

  const { error: auditError } = await client.from('audit_logs').insert({
    user_id: userId,
    action: `sandbox_${action}`,
    entity_type: mode === 'bulk' ? 'migration_jobs' : 'migration_job',
    entity_id: mode === 'single' ? jobs[0]?.id || null : null,
    details: {
      action,
      mode,
      executionModes: Array.from(new Set(jobs.map((job) => classifyJobMode(job)))),
      jobIds: jobs.map((job) => job.id).filter(Boolean).slice(0, 100),
      affected: jobs.length,
    },
    ip_address: req.ip?.replace('::ffff:', '') || null,
    user_agent: String(req.headers['user-agent'] || '').slice(0, 500),
    created_at: now,
  })
  if (auditError && !isMissingTable(auditError)) console.warn('[sandbox] audit log insert failed:', auditError.message)
}

// Rows for one snapshot table. "Table/column not provisioned" is a legitimate
// empty result; any other failure is retried and then ABORTS the snapshot —
// serving a fabricated empty snapshot would make running simulations vanish
// from the UI until the next successful poll.
async function safeRows(client: any, table: string, build: (q: any) => any): Promise<any[]> {
  let lastError: any = null
  for (let attempt = 0; attempt <= TRANSIENT_RETRY_DELAYS_MS.length; attempt++) {
    if (attempt > 0) await sleep(TRANSIENT_RETRY_DELAYS_MS[attempt - 1])
    try {
      const { data, error } = await build(client.from(table))
      if (!error) return data || []
      if (isSchemaShapeError(error)) return []
      lastError = error
      if (!isTransientQueryError(error)) break
    } catch (err) {
      lastError = err
      if (!isTransientQueryError(err)) break
    }
  }
  console.warn(`[sandbox] ${table} query failed; aborting snapshot instead of fabricating empty data:`, lastError?.message || lastError)
  throw new SnapshotUnavailableError(table, String(lastError?.message || 'query failed'))
}

async function safeCount(client: any, table: string, userId: string, apply?: (q: any) => any): Promise<number> {
  try {
    let q = client.from(table).select('id', { count: 'exact', head: true }).eq('user_id', userId)
    if (apply) q = apply(q)
    const { count, error } = await q
    if (error) return 0
    return count || 0
  } catch { return 0 }
}

/*
 * Plan approvals and the agent fleet are read by the shared, tolerant loaders
 * in `./operational-fleet` — the orchestration snapshot needs the same two
 * facts and must reach the same verdicts.
 */
const loadPlanApprovals = (client: any, userId: string, jobs: any[]) => loadPlanApprovalsShared(client, userId, jobs, '[sandbox]')
const loadAgentFleet = (client: any, userId: string) => loadAgentFleetShared(client, userId, '[sandbox]')

async function safeDeleteRelatedRows(client: any, table: string, userId: string, jobId: string, columns: string[]) {
  for (const column of columns) {
    try {
      const { error } = await client.from(table).delete().eq('user_id', userId).eq(column, jobId)
      if (error && !isSchemaShapeError(error)) console.warn(`[sandbox] ${table} cleanup failed:`, error.message)
    } catch {
      // Optional execution-artifact tables are not guaranteed in every tenant schema.
    }
  }
}

async function purgeSimulationArtifacts(client: any, userId: string, jobId: string) {
  const columnNames = ['migration_id', 'migration_job_id', 'job_id', 'simulation_id', 'sandbox_job_id']
  const tables = [
    'migration_events',
    'migration_telemetry',
    'migration_validation_logs',
    'migration_execution_logs',
    'migration_execution_steps',
    'execution_logs',
    'execution_telemetry',
    'sandbox_simulation_events',
    'sandbox_simulation_snapshots',
    'sandbox_simulation_runs',
    'deployment_packages',
    'operator_tasks',
    'patcher_runs',
    'orchestration_jobs',
  ]
  await Promise.all(tables.map((table) => safeDeleteRelatedRows(client, table, userId, jobId, columnNames)))
}

function historyDuration(start: string | null, end: string | null, fallbackUpdated: string | null) {
  const started = dateMs(start || '')
  const finished = dateMs(end || fallbackUpdated || '')
  if (!started || !finished || finished < started) return { durationMs: 0, duration: '--' }
  const ms = finished - started
  const minutes = Math.floor(ms / 60000)
  const seconds = Math.max(0, Math.round((ms % 60000) / 1000))
  if (minutes >= 60) return { durationMs: ms, duration: `${Math.floor(minutes / 60)}h ${minutes % 60}m` }
  if (minutes > 0) return { durationMs: ms, duration: `${minutes}m ${seconds}s` }
  return { durationMs: ms, duration: `${seconds}s` }
}

function riskScoreForSimulation(sim: any) {
  const statusPenalty = sim.status === 'failed' ? 25 : sim.status === 'rolled_back' ? 15 : 0
  const riskPenalty = sim.riskLevel === 'critical' ? 35 : sim.riskLevel === 'high' ? 25 : sim.riskLevel === 'medium' ? 12 : 4
  const progressCredit = Math.round(Number(sim.progress || 0) * 0.35)
  return clamp(100 - riskPenalty - statusPenalty + progressCredit)
}

/**
 * Distinct graded observations across the three tables that store them.
 *
 * `crypto_exposures`, `pqc_scan_results` and `scanner_alerts` are storage views
 * of the SAME scanner observations, so summing their severity counts — which is
 * what this module used to do (`exposures.filter(critical).length +
 * scanResults.filter(critical).length + alerts.filter(critical).length`) —
 * counts one cipher suite up to three times. Measured on a live tenant that
 * reported 22 critical / 50 high where the scanner's de-duplicated view held
 * 13 / 30, so the sandbox disagreed with CBOM, Assets, the QR Engine and the
 * workflow rail about the same estate.
 *
 * Identity comes from the shared `findingIdentityKey` (algorithm + subject +
 * measurement method) so this agrees with the scanner by construction.
 * Preferred source is still `buildScannerIntelligence` — this is the fallback
 * for when that computation is unavailable, and it counts the same UNIT so the
 * two branches never describe different populations.
 */
function gradedObservationRows(input: {
  exposures: any[]
  scanResults: any[]
  scannerAlerts: any[]
  assetName: (assetId: unknown) => string
}) {
  return [
    ...(input.exposures || []).map((row) => ({
      algorithm: row.detected_value || row.exposure_type,
      subject: input.assetName(row.asset_id),
      detectionMethod: '',
      severity: row.severity,
    })),
    ...(input.scanResults || []).map((row) => ({
      algorithm: row.algorithm || row.finding_type,
      subject: input.assetName(row.asset_id),
      detectionMethod: row.metadata?.detectionMethod,
      severity: row.threat_level,
    })),
    ...(input.scannerAlerts || []).map((row) => ({
      algorithm: row.algorithm || row.title || row.alert_type,
      subject: input.assetName(row.asset_id),
      detectionMethod: row.detection_method,
      severity: row.severity || row.threat_level,
    })),
  ]
}

/**
 * Shared-computation cache for the Migration Sandbox snapshot.
 *
 * This snapshot is the most expensive per-request computation in the module: a
 * 14-table tenant load plus the whole twin assembly (digital twin, dependency
 * graph, topology, failure predictions, performance benchmark, business impact,
 * rollback analysis, Sophia, approval gate, telemetry frame), and it now also
 * folds in the scanner-intelligence and Quantum-Readiness snapshots.
 *
 * It was the ONE hot path with no cache, while `/stream` rebuilt it every 8s
 * PER CONNECTED CLIENT. Measured on a two-asset tenant: 128ms served serially,
 * but five concurrent callers took 2.4s of wall clock because each rebuilt the
 * whole thing. That cost scales with (open dashboards × SSE ticks × estate
 * size), which is precisely the shape that stops scaling.
 *
 * Per-tenant, short-TTL and SINGLE-FLIGHT — concurrent callers await the SAME
 * in-flight promise, so an SSE fan-out collapses to one computation. The TTL is
 * deliberately shorter than the 8s stream cadence so a given client's own next
 * poll is still fresh; the win is across simultaneous callers. Failures are
 * never cached, and mutations invalidate explicitly rather than waiting the TTL
 * out (see `buildSandboxPayloadOrNull`).
 */
const SANDBOX_SNAPSHOT_TTL_MS = 5_000
/**
 * How long the snapshot will wait on the Quantum Readiness assessment before
 * rendering without it. Comfortably above a cache hit (~50ms) and far below a
 * cold assessment (~6s), so a warm QR is always used and a cold one never
 * stalls the page.
 */
const QR_SNAPSHOT_DEADLINE_MS = 1_500
const sandboxSnapshotCache = new Map<string, { at: number; promise: Promise<Awaited<ReturnType<typeof buildSandboxPayload>>> }>()

function invalidateSandboxSnapshot(userId: string) {
  sandboxSnapshotCache.delete(userId)
}

/**
 * Cached read path. Every route that only READS the snapshot goes through this;
 * routes that mutate first must invalidate (see `buildSandboxPayloadOrNull`) so
 * they never hand back a pre-mutation payload.
 */
async function getSandboxSnapshot(client: any, userId: string, token?: string | null) {
  const cached = sandboxSnapshotCache.get(userId)
  if (cached && Date.now() - cached.at < SANDBOX_SNAPSHOT_TTL_MS) return cached.promise

  const promise = buildSandboxPayload(client, userId, token)
  sandboxSnapshotCache.set(userId, { at: Date.now(), promise })
  promise.catch(() => sandboxSnapshotCache.delete(userId))

  if (sandboxSnapshotCache.size > 500) {
    const now = Date.now()
    for (const [key, value] of sandboxSnapshotCache) {
      if (now - value.at > SANDBOX_SNAPSHOT_TTL_MS) sandboxSnapshotCache.delete(key)
    }
  }
  return promise
}

async function buildSandboxPayload(client: any, userId: string, token?: string | null) {
  // Kept INSIDE the cached computation on purpose. Simulation progress is
  // derived from elapsed time (`(elapsed / duration) * 100`), not incremented
  // per call, so running the engine less often changes when a row is written,
  // never how fast a simulation completes. It also carries its own 2.5s
  // per-tenant throttle, and the background scheduler is the 15s floor.
  await advanceSandboxJobs(client, userId)

  // The platform's canonical, de-duplicated scanner view. Cached and
  // single-flight inside scanner.ts, and already the shared authority for the
  // QR Engine, Migration Intelligence and the remediation engine — reading it
  // here is what keeps the sandbox's severity counts in lock-step with every
  // other page instead of being a fourth opinion.
  //
  // The QR snapshot is BOUNDED rather than awaited outright. It costs ~6s when
  // its own 15s cache is cold, and blocking on it made a cold sandbox load wait
  // for the whole assessment before rendering anything. Missing the deadline
  // leaves `quantumRiskScore` null — which the UI already renders as "—" — and
  // the next snapshot picks up the now-warm value. Degrading to "not yet
  // assessed" is honest; degrading to the sandbox's own derived number would
  // briefly show a figure that disagrees with the QR command centre, which is
  // the exact divergence this page was fixed to stop.
  // 'deadline' is distinct from null on purpose: "QR answered and this tenant
  // has no assessment evidence" and "QR has not answered yet" call for
  // different behaviour, and collapsing them would publish a divergent risk
  // number in the second case.
  const withDeadline = <T>(promise: Promise<T>, ms: number): Promise<T | null | 'deadline'> => {
    let timer: ReturnType<typeof setTimeout> | undefined
    return Promise.race([
      promise.catch(() => null),
      new Promise<'deadline'>((resolve) => { timer = setTimeout(() => resolve('deadline'), ms) }),
    ]).finally(() => { if (timer) clearTimeout(timer) })
  }

  const [scannerIntel, qrResult] = token
    ? await Promise.all([
        (buildScannerIntelligence(token, userId) as Promise<any>).catch(() => null),
        withDeadline(buildQuantumReadinessSnapshot(token, userId) as Promise<any>, QR_SNAPSHOT_DEADLINE_MS),
      ])
    : [null, null]
  const qrPending = qrResult === 'deadline'
  const qrSnapshot = qrPending ? null : (qrResult as any)

  const [jobs, assets, inventory, exposures, events, scanSessions, certificates, vulns, scanResults, scannerAlerts, runtimeEvents, securityEvents, auditLogs, relationships] = await Promise.all([
    safeRows(client, 'migration_jobs', (q) => q.select('id, user_id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(300)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe, discovered_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(500)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(500)),
    safeRows(client, 'migration_events', (q) => q.select('id, migration_id, event_type, message, severity, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(300)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, completed_at, started_at, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(30)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, not_after, is_quantum_safe, is_expiring_soon, status').eq('user_id', userId).limit(200)),
    safeRows(client, 'vulnerabilities', (q) => q.select('id, asset_id, title, severity, status').eq('user_id', userId).not('status', 'eq', 'resolved').limit(200)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(500)),
    safeRows(client, 'scanner_alerts', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(300)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(500)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(300)),
    safeRows(client, 'audit_logs', (q) => q.select('id, action, entity_type, entity_id, details, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(200)),
    safeRows(client, 'asset_relationships', (q) => q.select('*').eq('user_id', userId).limit(2000)),
  ])

  const assetMap = new Map<string, any>((assets || []).map((a: any) => [a.id, a]))
  const inventoryByAsset = new Map<string, any[]>()
  for (const item of inventory || []) {
    if (!item.asset_id) continue
    const list = inventoryByAsset.get(item.asset_id) || []
    list.push(item)
    inventoryByAsset.set(item.asset_id, list)
  }
  const exposuresByAsset = new Map<string, any[]>()
  for (const exp of exposures || []) {
    if (!exp.asset_id) continue
    const list = exposuresByAsset.get(exp.asset_id) || []
    list.push(exp)
    exposuresByAsset.set(exp.asset_id, list)
  }
  const eventsByJob = new Map<string, any[]>()
  for (const ev of events || []) {
    if (!ev.migration_id) continue
    const list = eventsByJob.get(ev.migration_id) || []
    list.push(ev)
    eventsByJob.set(ev.migration_id, list)
  }

  // Operational (agent-executed) jobs are described by what decides whether
  // they move — the approval on their plan, refusals the agent poll recorded,
  // and whether an agent that may execute them exists — never by the sandbox
  // engine's own queue copy. Both reads are bounded, tolerant, and skipped when
  // the tenant has no operational jobs.
  const operationalJobRows = (jobs || []).filter((job: any) => !isSandboxSimulationJob(job))
  const hasOperationalJobs = operationalJobRows.length > 0
  const [planApprovals, agentFleet] = await Promise.all([
    hasOperationalJobs ? loadPlanApprovals(client, userId, operationalJobRows) : Promise.resolve(null),
    hasOperationalJobs ? loadAgentFleet(client, userId) : Promise.resolve(null),
  ])

  // Active workflows are tenant migration records. Sandbox simulations are a
  // safe subset; remediation and production migration rows remain operational
  // queue records and are not auto-completed by the sandbox engine.
  const workflows = (jobs || []).map((job: any) => {
    const asset = assetMap.get(job.asset_id) || {}
    const meta = asRecord(job.metadata)
    const invItems = inventoryByAsset.get(job.asset_id) || []
    const expItems = exposuresByAsset.get(job.asset_id) || []
    const jobEvents = eventsByJob.get(job.id) || []
    const status = normalizeStatus(job.status)
    const progress = status === 'completed' ? 100 : clamp(Number(job.progress || 0))
    const phase = phaseForProgress(progress, status, meta)
    const runMode = classifyJobMode(job)
    const isSandbox = runMode === 'dry_run' || runMode === 'simulation'
    const fromAlgo = pickStr(meta, ['sourceAlgorithm', 'source_algorithm', 'fromAlgorithm', 'from_algorithm', 'fromAlgo'])
      || (invItems[0]?.algorithm || '')
      || (expItems[0]?.detected_value || '')
      || String(meta.algorithm || '')
      || 'Classical'
    const toAlgo = job.target_algorithm || pickStr(meta, ['targetAlgorithm', 'target_algorithm', 'toAlgo']) || pqcAlgoRec(fromAlgo, job.job_type || '')
    // Same evidence rule as the Simulation Builder, over the snapshot's
    // bounded (most recent 500) inventory/exposure rows. A job with no known
    // asset has only its source algorithm to go on.
    const riskLevel = assetMap.has(job.asset_id) ? evidenceRiskLevel(invItems, expItems, fromAlgo) : quantumRisk(fromAlgo)
    const planId = jobPlanId(job)
    const operational = isSandbox ? null : describeOperationalWorkflow({
      job,
      status,
      progress,
      plan: planId ? planApprovals?.plans.get(planId) || null : null,
      planReadable: !planId || Boolean(planApprovals?.queried.has(planId)),
      executionClass: jobExecutionClass(job),
      agents: agentFleet,
    })

    return {
      id: job.id,
      name: job.name || `Migration: ${asset.name || 'Asset'}`,
      assetId: job.asset_id || null,
      assetName: asset.name || 'Unknown Asset',
      assetType: asset.type || pickStr(meta, ['assetType', 'asset_type']) || 'service',
      environment: asset.environment || pickStr(meta, ['environment']) || 'unknown',
      owner: asset.service_owner || pickStr(meta, ['owner', 'serviceOwner']) || 'Unassigned',
      criticality: (asset.criticality || pickStr(meta, ['criticality']) || 'medium').toLowerCase(),
      fromAlgo,
      toAlgo,
      migrationType: pickStr(meta, ['migrationType', 'migration_type']) || job.job_type || 'PQC Migration',
      runMode,
      runModeLabel: modeLabel(runMode),
      isSandbox,
      isActualMigration: !isSandbox,
      executionScope: isSandbox ? 'sandbox' : textMeta(meta, ['executionScope', 'environment'], asset.environment || 'tenant'),
      engineStatus: isSandbox ? textMeta(meta, ['engine'], ENGINE_NAME) : textMeta(meta, ['executor', 'connector', 'approval_mode'], 'awaiting approved executor'),
      // For an operational job the queue reason is where it really stands —
      // `phaseForProgress` would say "Awaiting sandbox executor capacity.",
      // and no sandbox executor will ever run it.
      queuedReason: status === 'queued'
        ? operational?.headline || textMeta(meta, ['queueReason', 'eta'], 'Awaiting sandbox executor')
        : null,
      eta: engineEta(job, status, progress, meta),
      status,
      progress,
      riskLevel,
      phase: phase.label,
      phaseId: phase.id,
      phaseDetail: operational
        // While an agent runs it, the step it reports is the better detail.
        ? status === 'running' ? textMeta(meta, ['phaseDetail'], operational.headline) : operational.headline
        : textMeta(meta, ['phaseDetail'], phase.detail),
      operational,
      startedAt: job.started_at || null,
      completedAt: job.completed_at || null,
      updatedAt: job.updated_at || job.created_at,
      createdAt: job.created_at,
      eventCount: jobEvents.length,
      // `events` is loaded newest-first, so the head of the list is the recent
      // end. This took `.slice(-5)` — the five OLDEST events in the window —
      // under the heading "Recent Events".
      recentEvents: jobEvents.slice(0, 5).map((ev: any) => ({
        id: ev.id,
        type: ev.event_type || 'event',
        message: ev.message || '',
        severity: ev.severity || 'info',
        timestamp: ev.created_at,
      })),
      metadata: meta,
    }
  })
  const simulations = workflows.filter((job) => job.isSandbox)
  const operationalWorkflows = workflows.filter((job) => !job.isSandbox)

  // ── Risk Analysis ───────────────────────────────────────────────────────────
  const runtimeRiskEvents = (runtimeEvents || []).filter((event: any) => {
    const text = JSON.stringify(event || {}).toLowerCase()
    return /rsa|ecdsa|ecdh|diffie|dh-|tlsv1\.0|tlsv1\.1|ssl|3des|rc4|sha1|md5|fallback|downgrade/.test(text)
  }).length

  // Graded observations, counted ONCE. Prefer the canonical scanner view; fall
  // back to a local de-duplication of the same three tables, which counts the
  // same unit so the two branches can never describe different populations.
  const localGraded = dedupeGradedObservations(gradedObservationRows({
    exposures: exposures || [],
    scanResults: scanResults || [],
    scannerAlerts: scannerAlerts || [],
    assetName: (assetId) => String(assetMap.get(String(assetId))?.name || assetId || ''),
  }))
  const intelSeverity = scannerIntel?.severityCounts
  const gradedObservations = intelSeverity
    ? {
        critical: Number(intelSeverity.critical || 0),
        high: Number(intelSeverity.high || 0),
        medium: Number(intelSeverity.medium || 0),
        low: Number(intelSeverity.low || 0),
        total: Number(intelSeverity.critical || 0) + Number(intelSeverity.high || 0) + Number(intelSeverity.medium || 0) + Number(intelSeverity.low || 0),
      }
    : localGraded
  const gradedObservationsSource = intelSeverity ? 'scanner-intelligence' : 'sandbox-local-dedupe'
  const criticalExposures = gradedObservations.critical
  const highExposures = gradedObservations.high

  const vulnerableInventory = (inventory || []).filter((i: any) => i.is_vulnerable || i.is_quantum_safe === false).length
  const totalInventory = (inventory || []).length
  // Two different facts that were being added together and then reported under
  // the single label "Expiring Certificates" — which contradicted the failure
  // prediction on the same page reading "0 expiring and 2 non-PQC certificate(s)".
  const expiringCertCount = (certificates || []).filter((c: any) => c.is_expiring_soon).length
  const nonPqcCertCount = (certificates || []).filter((c: any) => c.is_quantum_safe === false).length
  const certsNeedingRotation = (certificates || []).filter((c: any) => c.is_expiring_soon || c.is_quantum_safe === false).length
  const expiringCerts = certsNeedingRotation
  // `scanner_alerts` already contribute to the graded-observation counts above;
  // adding them here too counted the same rows twice on one page.
  const openVulns = (vulns || []).length
  const failedJobs = workflows.filter((s) => s.status === 'failed').length
  const completedJobs = workflows.filter((s) => s.status === 'completed').length
  const runningJobs = workflows.filter((s) => s.status === 'running').length
  const queuedJobs = workflows.filter((s) => s.status === 'queued').length
  const pausedJobs = workflows.filter((s) => s.status === 'paused').length
  const totalJobs = workflows.length
  const sandboxRunning = simulations.filter((s) => s.status === 'running').length
  const sandboxCompleted = simulations.filter((s) => s.status === 'completed').length
  const sandboxFailed = simulations.filter((s) => s.status === 'failed').length
  const sandboxQueued = simulations.filter((s) => s.status === 'queued').length
  const sandboxPaused = simulations.filter((s) => s.status === 'paused').length
  const remediationWorkflows = operationalWorkflows.filter((s) => s.runMode === 'remediation').length
  const actualMigrations = operationalWorkflows.filter((s) => s.runMode === 'actual_migration' || s.runMode === 'migration_workflow').length
  const staleQueuedWorkflows = operationalWorkflows.filter((s) => s.status === 'queued' && dateMs(s.updatedAt) < Date.now() - 60 * 60 * 1000).length
  const averageWorkflowProgress = totalJobs > 0 ? Math.round(workflows.reduce((sum, job) => sum + Number(job.progress || 0), 0) / totalJobs) : 0

  /**
   * Canonical quantum risk — 0–100, LOWER IS BETTER, banded by the shared
   * `riskBandFor` table.
   *
   * The previous formula was `100 - (critical*15 + high*8 + …)`, i.e. a
   * higher-is-better POSTURE measure published under a risk name, on a page
   * that renders it beside PQC-readiness and compliance (both higher-better).
   * It also saturated: seven critical exposures alone drove it to 0, so it read
   * "Risk Score 0/100" — a perfect score on a lower-better scale — for any real
   * estate, while the QR Engine reported 75/High for the same tenant. A metric
   * that cannot vary carries no information.
   *
   * Prefer the QR Engine's score when the scanner snapshot carries one, so this
   * page and the Quantum Readiness command centre never disagree; otherwise
   * derive it from the same de-duplicated severity counts on the same scale.
   */
  const derivedQuantumRisk = riskScoreFromLoad(
    criticalExposures * 3 + highExposures * 1.2 + gradedObservations.medium * 0.4 + certsNeedingRotation * 1 + failedJobs * 2 + Math.min(4, runtimeRiskEvents * 0.2),
  )
  // The Quantum Readiness Engine is the platform's risk authority — the same
  // number the QR command centre, the executive dashboard, CBOM Explorer and
  // the Assets page all render. Reading it here (rather than the scanner's
  // per-asset risk mean, which is a DIFFERENT measurement that happens to share
  // the scale) is what stops this page publishing "Quantum Risk 39" against
  // QR's "Quantum Risk 75" for the same estate.
  const qrRisk = Number(qrSnapshot?.scores?.quantumRisk)
  const hasRiskBaseline = gradedObservations.total > 0 || totalInventory > 0
  const qrAnswered = qrSnapshot?.hasData && Number.isFinite(qrRisk)
  const quantumRiskScore = !hasRiskBaseline ? null
    : qrAnswered ? clamp(Math.round(qrRisk))
      // Still waiting on the assessment — withhold rather than publish the
      // locally derived number, which would disagree with the QR command centre
      // for a few seconds and then jump. The next snapshot has QR warm.
      : qrPending ? null
        // QR answered and this tenant has no assessment evidence, so the
        // sandbox's own derivation is the best available measurement.
        : derivedQuantumRisk
  const quantumRiskLevel = quantumRiskScore === null
    ? (qrPending ? 'Awaiting assessment' : 'Not assessed')
    : riskBandFor(quantumRiskScore).label
  const quantumRiskSource = qrAnswered ? 'quantum-readiness-engine'
    : qrPending ? 'awaiting-quantum-readiness'
      : quantumRiskScore === null ? 'not-assessed' : 'sandbox-derived'

  // PQC readiness is a CRYPTO-INVENTORY measure. The old fallback published
  // `completedJobs / totalJobs` under the same name — a migration-job
  // completion rate reported as cryptographic readiness — so a tenant with no
  // inventory and one finished job read "PQC Readiness 100%".
  const hasReadinessBaseline = totalInventory > 0
  const pqcReadiness = hasReadinessBaseline
    ? Math.round(((totalInventory - vulnerableInventory) / totalInventory) * 100)
    : 0

  const riskFactors = [
    { label: 'Critical Crypto Exposures', count: criticalExposures, severity: 'critical' as const, impact: 'high' as const },
    { label: 'High-Risk Exposures', count: highExposures, severity: 'high' as const, impact: 'high' as const },
    { label: 'Vulnerable Inventory Items', count: vulnerableInventory, severity: 'high' as const, impact: 'medium' as const },
    { label: 'Certificates Needing Rotation', count: certsNeedingRotation, severity: 'medium' as const, impact: 'medium' as const },
    { label: 'Open Vulnerabilities', count: openVulns, severity: 'medium' as const, impact: 'medium' as const },
    { label: 'Failed Migration Jobs', count: failedJobs, severity: 'high' as const, impact: 'high' as const },
    { label: 'Runtime Crypto Risk Signals', count: runtimeRiskEvents, severity: 'medium' as const, impact: 'medium' as const },
  ].filter((f) => f.count > 0)

  // ── AI Recommendations ──────────────────────────────────────────────────────
  const recommendations: any[] = []

  if (criticalExposures > 0) {
    const critExps = (exposures || []).filter((e: any) => e.severity === 'critical').slice(0, 3)
    for (const exp of critExps) {
      const asset = assetMap.get(exp.asset_id) || {}
      const from = exp.detected_value || exp.exposure_type || 'legacy algorithm'
      recommendations.push({
        id: `rec-critical-${exp.id}`,
        priority: 1,
        type: 'algorithm_migration',
        title: `Migrate ${from.toUpperCase()} on ${asset.name || 'asset'} immediately`,
        description: `Critical quantum vulnerability detected. This asset is at immediate risk from "Harvest Now, Decrypt Later" attacks.`,
        algorithm: pqcAlgoRec(from),
        asset: asset.name || 'Unknown',
        effort: 'high',
        timeEstimate: '2-4 weeks',
        compliance: ['NIST SP 800-208', 'CNSA 2.0'],
      })
    }
    if (critExps.length === 0) {
      const scannerFinding = [...(scanResults || []), ...(scannerAlerts || [])].find((row: any) => String(row.threat_level || row.severity || '').toLowerCase() === 'critical')
      if (scannerFinding) {
        const asset = assetMap.get(scannerFinding.asset_id) || {}
        const from = scannerFinding.algorithm || scannerFinding.detected_value || scannerFinding.title || scannerFinding.finding_type || 'critical finding'
        recommendations.push({
          id: `rec-critical-scanner-${scannerFinding.id || 'latest'}`,
          priority: 1,
          type: 'scanner_remediation',
          title: `Remediate critical scanner finding on ${asset.name || 'asset'}`,
          description: scannerFinding.description || scannerFinding.message || 'Critical scanner telemetry is blocking safe PQC migration validation.',
          algorithm: pqcAlgoRec(from),
          asset: asset.name || scannerFinding.asset_name || 'Unknown',
          effort: 'high',
          timeEstimate: '2-4 weeks',
          compliance: ['NIST SP 800-208', 'CNSA 2.0'],
        })
      }
    }
  }

  if (runtimeRiskEvents > 0 && recommendations.length < 6) {
    recommendations.push({
      id: 'rec-runtime-risk',
      priority: 2,
      type: 'runtime_crypto_validation',
      title: `Validate ${runtimeRiskEvents} runtime crypto risk signal(s) before cutover`,
      description: 'Runtime telemetry detected classical or downgrade-prone cryptographic behavior that should be resolved before production migration.',
      algorithm: 'Hybrid TLS / ML-KEM validation',
      asset: 'Runtime telemetry',
      effort: 'medium',
      timeEstimate: '1-2 weeks',
      compliance: ['NIST SP 800-208', 'Crypto Agility'],
    })
  }

  if (failedJobs > 0) {
    const failed = workflows.filter((s) => s.status === 'failed').slice(0, 3)
    for (const job of failed) {
      recommendations.push({
        id: `rec-failed-${job.id}`,
        priority: 2,
        type: 'remediation',
        title: `Retry failed migration: ${job.name}`,
        description: `This migration job failed. Review execution logs, validate dependencies, and retry with corrected configuration.`,
        algorithm: job.toAlgo,
        asset: job.assetName,
        effort: 'medium',
        timeEstimate: '1-3 days',
        compliance: ['NIST SP 800-57'],
      })
    }
  }

  if (expiringCerts > 0) {
    recommendations.push({
      id: 'rec-certs',
      priority: 2,
      type: 'certificate_rotation',
      title: `Rotate ${expiringCerts} non-PQC or expiring certificates`,
      description: 'Certificates using classical algorithms or nearing expiry must be replaced with PQC-compliant alternatives.',
      algorithm: 'ML-DSA-65',
      asset: 'Certificate Infrastructure',
      effort: 'medium',
      timeEstimate: '1-2 weeks',
      compliance: ['NIST SP 800-57', 'RFC 9162'],
    })
  }

  if (vulnerableInventory > 0 && recommendations.length < 5) {
    recommendations.push({
      id: 'rec-inventory',
      priority: 3,
      type: 'hybrid_deployment',
      title: `Deploy hybrid cryptography for ${vulnerableInventory} vulnerable assets`,
      description: 'Transition vulnerable crypto assets to hybrid classical+PQC mode to maintain backward compatibility while gaining quantum resistance.',
      algorithm: 'X25519 + ML-KEM-768',
      asset: 'Crypto Inventory',
      effort: 'medium',
      timeEstimate: '2-6 weeks',
      compliance: ['NIST SP 800-208', 'NIST SP 800-131A'],
    })
  }

  if (recommendations.length === 0) {
    recommendations.push({
      id: 'rec-baseline',
      priority: 3,
      type: 'assessment',
      title: 'Run comprehensive PQC discovery scan',
      description: 'Establish your cryptographic baseline by scanning all assets to identify quantum-vulnerable algorithms before planning migrations.',
      algorithm: 'N/A',
      asset: 'All Assets',
      effort: 'low',
      timeEstimate: '1-2 hours',
      compliance: ['NIST SP 800-208'],
    })
  }

  // ── Cryptographic posture indicators per control family ─────────────────────
  //
  // These are SCREENING INDICATORS derived from the tenant's cryptographic
  // evidence, not compliance verdicts. The platform's Compliance dashboard owns
  // control evidence and attestation; a formula over exposure counts cannot
  // decide whether an organisation meets HIPAA or PCI DSS.
  //
  // Two faults are fixed here. Each row now carries the `basis` it was decided
  // from, so no number is unexplained. And `status` DERIVES from `score` through
  // one shared threshold, so the panel can no longer show "PCI DSS · partial"
  // beside a score of 0, or "SOC 2 · compliant" from a formula with a floor.
  const agileReady = totalInventory > 0
  const auditAvailable = (events || []).length > 0 || (securityEvents || []).length > 0 || (auditLogs || []).length > 0
  const hasPostureEvidence = totalInventory > 0 || gradedObservations.total > 0 || (certificates || []).length > 0

  const indicator = (framework: string, control: string, score: number, basis: string, evidence = hasPostureEvidence) => {
    const value = Math.max(0, Math.min(100, Math.round(score)))
    return {
      framework,
      control,
      score: value,
      basis,
      // One threshold for every row — status can never contradict the score.
      status: !evidence ? 'pending' : value >= 85 ? 'met' : value >= 50 ? 'partial' : 'not-met',
    }
  }

  const complianceItems = [
    indicator('NIST PQC Standards', 'FIPS 203/204/205 readiness',
      (pqcReadiness + (criticalExposures === 0 ? 100 : 35)) / 2,
      `${pqcReadiness}% PQC-ready inventory · ${criticalExposures} critical exposure(s)`),
    indicator('NIST Migration Guidance', 'Inventory, prioritization, validation, and evidence',
      totalInventory > 0 ? (totalJobs > 0 ? 88 : 55) : 0,
      `${totalInventory} inventory record(s) · ${totalJobs} migration job(s)`),
    indicator('NIST SP 800-208', 'PQC Algorithm Adoption', pqcReadiness,
      `${pqcReadiness}% of inventory is quantum-safe`, hasReadinessBaseline),
    indicator('NIST SP 800-57 Rev.5', 'Key Management Practices',
      100 - certsNeedingRotation * 15 - failedJobs * 20,
      `${certsNeedingRotation} certificate(s) needing rotation · ${failedJobs} failed job(s)`),
    indicator('NSA CNSA 2.0', 'NSS Algorithm Suite',
      100 - criticalExposures * 20 - highExposures * 10,
      `${criticalExposures} critical · ${highExposures} high exposure(s)`),
    indicator('FIPS 140-3 / 203-205', 'Validated module + approved PQC algorithm usage',
      pqcReadiness * 0.7 + (criticalExposures === 0 ? 30 : 0),
      `${pqcReadiness}% PQC-ready · ${vulnerableInventory} vulnerable record(s)`),
    indicator('ISO 27001', 'Cryptographic controls and change management',
      auditAvailable ? (totalInventory > 0 ? 86 : 62) : 0,
      auditAvailable ? `Audit trail present · ${totalInventory} inventory record(s)` : 'No audit or security events recorded',
      auditAvailable),
    indicator('PCI DSS', 'Strong cryptography, TLS, and key lifecycle evidence',
      100 - certsNeedingRotation * 18 - criticalExposures * 25 - highExposures * 8,
      `${criticalExposures} critical · ${highExposures} high · ${certsNeedingRotation} cert(s) needing rotation`),
    indicator('SOC 2', 'Change auditability and runtime monitoring',
      auditAvailable ? 95 - runtimeRiskEvents * 8 - failedJobs * 12 : 0,
      auditAvailable ? `${runtimeRiskEvents} runtime risk signal(s) · ${failedJobs} failed job(s)` : 'No audit or security events recorded',
      auditAvailable),
    indicator('HIPAA', 'ePHI encryption strength and transmission security',
      100 - criticalExposures * 22 - highExposures * 8 - certsNeedingRotation * 10,
      `${criticalExposures} critical · ${highExposures} high · ${certsNeedingRotation} cert(s) needing rotation`),
    indicator('GDPR', 'Art. 32 state-of-the-art encryption of personal data',
      100 - vulnerableInventory * 4 - criticalExposures * 18,
      `${vulnerableInventory} vulnerable inventory record(s) · ${criticalExposures} critical exposure(s)`),
    indicator('CISA PQC Guidance', 'Quantum-readiness roadmap: inventory, prioritization, migration rehearsal',
      totalInventory > 0 ? (totalJobs > 0 ? 90 : 58) : 0,
      `${totalInventory} inventory record(s) · ${totalJobs} migration job(s)`),
    indicator('Crypto Agility', 'Algorithm Replaceability', agileReady ? 85 : 0,
      agileReady ? `${totalInventory} inventory record(s) available to re-target` : 'No crypto inventory discovered'),
    indicator('Audit Trail', 'Migration Evidence Collection', auditAvailable ? 100 : 0,
      auditAvailable ? `${(events || []).length} migration · ${(auditLogs || []).length} audit event(s)` : 'No migration or audit events recorded',
      auditAvailable),
    indicator('HNDL Posture', 'Harvest-Now-Decrypt-Later', 100 - criticalExposures * 25,
      `${criticalExposures} critical exposure(s) with long-lived confidentiality risk`),
  ]
  const complianceScore = Math.round(complianceItems.reduce((sum, c) => sum + c.score, 0) / complianceItems.length)

  // Workflow phases summarize the live tenant migration pipeline, not just
  // sandbox runs. This keeps queue size, execution, and blockers honest.
  const latestEventAt = (events || [])[0]?.created_at || (securityEvents || [])[0]?.created_at || null
  const runningScans = (scanSessions || []).filter((s: any) => ['running', 'queued', 'analyzing'].includes(String(s.status || '').toLowerCase())).length
  const latestScanProgress = Math.max(0, ...(scanSessions || []).map((s: any) => Number(s.progress || 0)).filter(Number.isFinite))
  const discoveryProgress = (assets || []).length > 0 || totalInventory > 0 ? 100 : latestScanProgress
  const assessmentSignals = criticalExposures + highExposures + openVulns + runtimeRiskEvents
  const planningProgress = totalJobs > 0 ? 100 : assessmentSignals > 0 ? 65 : 0
  const verificationProgress = completedJobs > 0 ? Math.max(35, pqcReadiness) : averageWorkflowProgress >= 70 ? 50 : 0
  const workflowPhases = [
    {
      id: 'preparation',
      label: 'Discovery & Inventory',
      description: 'Assets, CBOM, scanner sessions, and crypto inventory normalized.',
      complete: discoveryProgress >= 100,
      active: runningScans > 0 || discoveryProgress > 0,
      progress: clamp(discoveryProgress),
      count: (assets || []).length + totalInventory,
      running: runningScans,
      queued: 0,
      blocked: 0,
      source: 'assets + crypto_inventory + pqc_scan_sessions',
      updatedAt: (assets || [])[0]?.updated_at || (scanSessions || [])[0]?.updated_at || null,
    },
    {
      id: 'assessment',
      label: 'Risk Assessment',
      description: 'Quantum vulnerability scoring, HNDL exposure, and runtime crypto risk.',
      complete: assessmentSignals > 0 || totalInventory > 0,
      active: runningScans > 0 || assessmentSignals > 0,
      progress: assessmentSignals > 0 ? 100 : totalInventory > 0 ? 70 : 0,
      count: assessmentSignals,
      running: runningScans,
      queued: 0,
      blocked: criticalExposures,
      source: 'crypto_exposures + pqc_scan_results + runtime_crypto_events',
      updatedAt: (scanResults || [])[0]?.created_at || (runtimeEvents || [])[0]?.created_at || null,
    },
    {
      id: 'planning',
      label: 'Migration Planning',
      description: 'Target algorithms, remediation ownership, and rollback strategy assigned.',
      complete: totalJobs > 0,
      active: totalJobs > 0 || assessmentSignals > 0,
      progress: clamp(planningProgress),
      count: totalJobs,
      running: runningJobs,
      queued: queuedJobs,
      blocked: staleQueuedWorkflows,
      source: 'migration_jobs',
      updatedAt: (jobs || [])[0]?.updated_at || null,
    },
    {
      id: 'execution',
      label: 'Execution & Sandbox Validation',
      description: 'Sandbox simulations progress automatically; actual migrations wait for approved executors.',
      complete: totalJobs > 0 && completedJobs === totalJobs,
      active: runningJobs > 0 || sandboxRunning > 0,
      progress: clamp(averageWorkflowProgress),
      count: totalJobs,
      running: runningJobs,
      queued: queuedJobs,
      blocked: staleQueuedWorkflows,
      source: 'migration_jobs + migration_events',
      updatedAt: latestEventAt || (jobs || [])[0]?.updated_at || null,
    },
    {
      id: 'verification',
      label: 'Verification',
      description: 'Compatibility, rollback, compliance evidence, and runtime drift validation.',
      complete: completedJobs > 0 && criticalExposures === 0 && failedJobs === 0,
      active: completedJobs > 0 || runningJobs > 0,
      progress: clamp(verificationProgress),
      count: completedJobs,
      running: runningJobs,
      queued: queuedJobs,
      blocked: failedJobs + criticalExposures,
      source: 'migration_events + security_events + audit_logs',
      updatedAt: latestEventAt,
    },
    {
      id: 'finalization',
      label: 'Finalization',
      description: 'Readiness score, compliance posture, audit report, and executive export.',
      complete: pqcReadiness >= 90 && complianceScore >= 80,
      active: pqcReadiness >= 70 || complianceScore >= 60,
      progress: clamp(Math.round((pqcReadiness + complianceScore) / 2)),
      count: (auditLogs || []).length + (securityEvents || []).length,
      running: 0,
      queued: 0,
      blocked: complianceScore < 70 ? 1 : 0,
      source: 'compliance + audit_logs + security_events',
      updatedAt: (auditLogs || [])[0]?.created_at || latestEventAt,
    },
  ]

  // ── PQC Stack Status ────────────────────────────────────────────────────────
  const algoUsage = (pattern: RegExp) => {
    const inventoryHits = (inventory || []).filter((i: any) => pattern.test(`${i.algorithm || ''} ${i.protocol || ''} ${i.name || ''}`)).length
    const workflowHits = workflows.filter((w) => pattern.test(`${w.fromAlgo || ''} ${w.toAlgo || ''} ${w.migrationType || ''} ${w.name || ''}`)).length
    const runtimeHits = (runtimeEvents || []).filter((event: any) => pattern.test(JSON.stringify(event || ''))).length
    return inventoryHits + workflowHits + runtimeHits
  }
  const pqcStack = [
    { name: 'ML-KEM-768 (Kyber)', standard: 'NIST FIPS 203', status: 'available', usage: algoUsage(/ml-kem|kyber/i) },
    { name: 'X25519 + ML-KEM-768 Hybrid', standard: 'TLS hybrid key exchange', status: 'available', usage: algoUsage(/x25519.*ml-kem|ml-kem.*x25519|hybrid.*kex|hybrid tls/i) },
    { name: 'ML-DSA-65 (Dilithium)', standard: 'NIST FIPS 204', status: 'available', usage: algoUsage(/ml-dsa|dilithium/i) },
    { name: 'Ed25519 + ML-DSA-65 Hybrid', standard: 'Hybrid digital signatures', status: 'available', usage: algoUsage(/ed25519.*ml-dsa|ml-dsa.*ed25519|hybrid.*sign/i) },
    { name: 'SLH-DSA (SPHINCS+)', standard: 'NIST FIPS 205', status: 'available', usage: algoUsage(/slh-dsa|sphincs/i) },
    { name: 'AES-256-GCM', standard: 'NIST FIPS 197', status: 'active', usage: algoUsage(/aes-256-gcm|aes_256_gcm|aes-256/i) },
    { name: 'HKDF-SHA3-256', standard: 'KDF', status: 'active', usage: algoUsage(/hkdf.*sha3-256|sha3-256.*hkdf/i) },
    { name: 'SHA3-256 / SHA3-512', standard: 'NIST FIPS 202', status: 'active', usage: algoUsage(/sha3-256|sha3-512|sha3/i) },
    { name: 'liboqs / OQS Provider / OpenSSL 3.x', standard: 'Open Quantum Safe integration', status: 'available', usage: algoUsage(/liboqs|oqs-provider|oqs openssl|open quantum safe/i) },
  ]

  // ── Summary Metrics ─────────────────────────────────────────────────────────
  const lastScan = (scanSessions || []).find((s: any) => s.status === 'completed')
  const summary = {
    totalSimulations: simulations.length,
    running: sandboxRunning,
    completed: sandboxCompleted,
    failed: sandboxFailed,
    queued: sandboxQueued,
    paused: sandboxPaused,
    totalWorkflows: workflows.length,
    actualMigrations,
    remediationWorkflows,
    runningWorkflows: runningJobs,
    completedWorkflows: completedJobs,
    failedWorkflows: failedJobs,
    queuedWorkflows: queuedJobs,
    pausedWorkflows: pausedJobs,
    blockedWorkflows: staleQueuedWorkflows,
    averageWorkflowProgress,
    backgroundEngine: sandboxRunning > 0 || sandboxQueued > 0 ? 'active' : 'idle',
    lastMigrationEventAt: latestEventAt,
    totalAssets: (assets || []).length,
    vulnerableAssets: new Set((exposures || []).map((e: any) => e.asset_id).filter(Boolean)).size,
    criticalExposures,
    highExposures,
    mediumExposures: gradedObservations.medium,
    gradedObservations: gradedObservations.total,
    // Which computation produced the severity counts, so a reader can tell
    // whether this page is quoting the canonical scanner view or its fallback.
    gradedObservationsSource,
    openVulnerabilities: openVulns,
    pqcReadiness,
    hasReadinessBaseline,
    // 0–100, LOWER IS BETTER, banded by the shared RISK_BANDS table — the same
    // scale and direction as the QR Engine and /dashboard/summary. `null` means
    // not assessed and must never render as 0.
    quantumRiskScore,
    quantumRiskLevel,
    quantumRiskSource,
    complianceScore,
    expiringCerts: expiringCertCount,
    nonPqcCerts: nonPqcCertCount,
    certsNeedingRotation,
    lastScanAt: lastScan?.completed_at || lastScan?.created_at || null,
    completionRate: simulations.length > 0 ? Math.round((sandboxCompleted / simulations.length) * 100) : 0,
    workflowCompletionRate: totalJobs > 0 ? Math.round((completedJobs / totalJobs) * 100) : 0,
  }

  const eventLogs = (events || []).map((ev: any) => ({
    id: ev.id,
    jobId: ev.migration_id,
    type: ev.event_type || 'migration-event',
    message: ev.message || '',
    severity: ev.severity || 'info',
    timestamp: ev.created_at,
  }))
  const securityLogs = (securityEvents || []).map((ev: any) => ({
    id: `security-${ev.id}`,
    jobId: ev.metadata?.jobId || ev.metadata?.migrationId || '',
    type: ev.event_type || 'security-event',
    message: ev.message || '',
    severity: ev.severity || 'info',
    timestamp: ev.created_at,
  }))
  const runtimeLogs = (runtimeEvents || []).slice(0, 80).map((ev: any, index: number) => ({
    id: `runtime-${ev.id || index}`,
    jobId: '',
    type: ev.event_type || ev.operation || ev.algorithm || 'runtime-crypto',
    message: ev.message || ev.description || `Runtime crypto signal observed${ev.algorithm ? `: ${ev.algorithm}` : ''}`,
    severity: JSON.stringify(ev || {}).match(/rsa|ecdsa|tlsv1\.0|tlsv1\.1|ssl|3des|rc4|sha1|md5/i) ? 'warning' : 'info',
    timestamp: ev.created_at || ev.timestamp || ev.observed_at || new Date().toISOString(),
  }))
  const recentLogs = [...eventLogs, ...securityLogs, ...runtimeLogs]
    .sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime())
    .slice(0, 80)
  const history = simulations.map((sim) => {
    const duration = historyDuration(sim.startedAt || sim.createdAt, sim.completedAt, sim.updatedAt)
    const simRiskScore = riskScoreForSimulation(sim)
    const simComplianceScore = clamp(Math.round((complianceScore + (sim.status === 'completed' ? 100 : sim.progress || 0)) / 2))
    return {
      id: sim.id,
      name: sim.name,
      sourceAlgorithm: sim.fromAlgo,
      targetAlgorithm: sim.toAlgo,
      assetName: sim.assetName,
      assetType: sim.assetType,
      assets: sim.assetName && sim.assetName !== 'Unknown Asset' ? 1 : 0,
      riskScore: simRiskScore,
      complianceScore: simComplianceScore,
      status: sim.status,
      durationMs: duration.durationMs,
      duration: duration.duration,
      createdAt: sim.createdAt,
      startedAt: sim.startedAt,
      completedAt: sim.completedAt,
      updatedAt: sim.updatedAt,
      riskLevel: sim.riskLevel,
      runMode: sim.runMode,
      runModeLabel: sim.runModeLabel,
      owner: sim.owner,
      environment: sim.environment,
      snapshots: Array.isArray(sim.metadata?.snapshots) ? (sim.metadata.snapshots as any[]).length : 0,
      eventCount: sim.eventCount,
    }
  })

  // ── Digital Twin & Enterprise Simulation Intelligence ───────────────────────
  // Pure derivation over the same real tenant rows loaded above (sandbox-twin.ts).
  const twinBundle: TwinBundle = {
    assets: assets || [],
    inventory: inventory || [],
    exposures: exposures || [],
    certificates: certificates || [],
    relationships: relationships || [],
    runtimeEvents: runtimeEvents || [],
    vulns: vulns || [],
    scanResults: scanResults || [],
    events: events || [],
    workflows,
  }
  const twinIntelligence = assembleTwinIntelligence(twinBundle, { pqcReadiness, quantumRiskScore, complianceScore })

  return {
    generatedAt: new Date().toISOString(),
    summary,
    simulations,
    history,
    workflows,
    riskFactors,
    recommendations: recommendations.slice(0, 8),
    complianceItems,
    complianceScore,
    workflowPhases,
    pqcStack,
    recentLogs,
    ...twinIntelligence,
  }
}

/**
 * Post-MUTATION snapshot rebuild.
 *
 * Every caller of this has just written to the tenant, so the cached snapshot
 * is stale by construction — it is dropped first, and the fresh result is
 * stored so the SSE tick that lands moments later shows the post-mutation state
 * rather than rebuilding it again. Returning a cached pre-mutation payload here
 * would make an operator action look like it did nothing.
 *
 * Operator actions must not fail (or lose their result) because the trailing
 * snapshot rebuild hit a transient failure — callers treat a null snapshot as
 * "keep current data and refetch".
 */
async function buildSandboxPayloadOrNull(client: any, userId: string, token?: string | null) {
  invalidateSandboxSnapshot(userId)
  try {
    return await getSandboxSnapshot(client, userId, token)
  } catch (err) {
    if (err instanceof SnapshotUnavailableError) return null
    throw err
  }
}

// ── GET /api/v1/sandbox/assets ───────────────────────────────────────────────
// Simulation targets: the tenant's real scanned assets enriched with the
// cryptographic evidence (inventory + exposures) a simulation will exercise.
router.get('/assets', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  try {
    const userId = req.user!.id
    const [assets, inventory, exposures, jobs] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, updated_at, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(300)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe').eq('user_id', userId).limit(1000)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, detected_value').eq('user_id', userId).limit(1000)),
      safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, status, metadata').eq('user_id', userId).limit(500)),
    ])

    const inventoryByAsset = groupRowsByAsset(inventory)
    const exposuresByAsset = groupRowsByAsset(exposures)
    const activeSimulationsByAsset = new Map<string, number>()
    for (const job of jobs || []) {
      if (!job?.asset_id || !isSandboxSimulationJob(job)) continue
      if (!ACTIVE_JOB_STATUSES.includes(normalizeStatus(job.status))) continue
      activeSimulationsByAsset.set(job.asset_id, (activeSimulationsByAsset.get(job.asset_id) || 0) + 1)
    }

    const rows = (assets || []).map((asset: any) => {
      const invItems = inventoryByAsset.get(asset.id) || []
      const expItems = exposuresByAsset.get(asset.id) || []
      const seed = assetSimulationSeed(asset, invItems, expItems)
      return {
        id: asset.id,
        name: asset.name || 'Unnamed asset',
        type: asset.type || 'service',
        environment: asset.environment || 'unknown',
        region: asset.region || null,
        owner: asset.service_owner || 'Unassigned',
        criticality: String(asset.criticality || 'medium').toLowerCase(),
        status: asset.status || 'active',
        sourceAlgorithm: seed.sourceAlgorithm,
        targetAlgorithm: seed.targetAlgorithm,
        riskLevel: seed.riskLevel,
        inventoryItems: seed.inventoryItems,
        vulnerableItems: seed.vulnerableItems,
        exposures: seed.exposures,
        criticalExposures: seed.criticalExposures,
        algorithms: seed.algorithms,
        activeSimulations: activeSimulationsByAsset.get(asset.id) || 0,
        hasEvidence: seed.inventoryItems > 0 || seed.exposures > 0,
        lastSeen: asset.updated_at || asset.created_at || null,
      }
    }).sort((a: any, b: any) => {
      const rank = severityRank(b.riskLevel) - severityRank(a.riskLevel)
      if (rank !== 0) return rank
      return (b.vulnerableItems + b.criticalExposures) - (a.vulnerableItems + a.criticalExposures)
    })

    return res.json({
      data: {
        generatedAt: new Date().toISOString(),
        totalAssets: rows.length,
        vulnerableAssets: rows.filter((row: any) => row.vulnerableItems > 0 || row.criticalExposures > 0).length,
        assetsWithEvidence: rows.filter((row: any) => row.hasEvidence).length,
        assets: rows,
      },
    })
  } catch (err) {
    console.error('[sandbox] assets error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to load simulation targets' } })
  }
})

// ── GET /api/v1/sandbox/snapshot ──────────────────────────────────────────────
router.get('/snapshot', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
  try {
    const payload = await getSandboxSnapshot(client, req.user!.id, req.token)
    return res.json({ data: payload })
  } catch (err) {
    if (err instanceof SnapshotUnavailableError) {
      // Explicit 503 instead of a fabricated empty snapshot: the dashboard
      // keeps its last-known-good data and surfaces the degradation.
      return res.status(503).json({ error: { code: 'SNAPSHOT_UNAVAILABLE', message: err.message } })
    }
    console.error('[sandbox] snapshot error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to build sandbox snapshot' } })
  }
})

// ── GET /api/v1/sandbox/stream (SSE) ─────────────────────────────────────────
router.get('/stream', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  sseHeaders(res)
  writeSse(res, 'connected', { timestamp: new Date().toISOString(), userId: req.user!.id })

  // Goes through the cache: N connected clients ticking within the same window
  // share ONE computation instead of each rebuilding the full snapshot.
  const emit = async () => {
    try {
      const payload = await getSandboxSnapshot(client, req.user!.id, req.token)
      writeSse(res, 'sandbox-update', payload)
    } catch { /* ignore */ }
  }

  await emit()
  const heartbeat = setInterval(() => writeSse(res, 'heartbeat', { ts: Date.now() }), 20000)
  const poll = setInterval(emit, 8000)

  req.on('close', () => {
    clearInterval(heartbeat)
    clearInterval(poll)
    res.end()
  })
})

// ── POST /api/v1/sandbox/jobs/:id/action ─────────────────────────────────────
router.post('/jobs/:id/action', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const action = String(req.body?.action || '').toLowerCase()
  const validActions = ['pause', 'resume', 'retry', 'rollback', 'stop', 'snapshot', 'restore_snapshot', 'delete']
  if (!validActions.includes(action)) {
    return res.status(400).json({ error: { code: 'INVALID_ACTION', message: `Invalid action. Must be one of: ${validActions.join(', ')}` } })
  }

  const { data: job, error: readError } = await client
    .from('migration_jobs')
    .select('id, user_id, asset_id, name, job_type, status, target_algorithm, strategy, metadata, progress, started_at, completed_at, created_at, updated_at')
    .eq('id', req.params.id)
    .eq('user_id', req.user!.id)
    .single()

  if (readError || !job) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Simulation job not found' } })
  }

  const refusal = sandboxEngineActionRefusal(job, action)
  if (refusal) {
    return res.status(409).json({ error: { code: 'OPERATIONAL_JOB', message: refusal } })
  }

  const now = new Date().toISOString()

  if (action === 'delete') {
    if (!canDeleteSimulationJob(job)) {
      return res.status(400).json({
        error: {
          code: 'DELETE_NOT_ALLOWED',
          message: 'Only completed, failed, cancelled/stopped, or rolled-back sandbox simulations can be deleted.',
        },
      })
    }

    await recordOperatorTelemetry(client, req, [job], action, now, 'single')
    await purgeSimulationArtifacts(client, req.user!.id, job.id)

    const { error: deleteError } = await client
      .from('migration_jobs')
      .delete()
      .eq('id', job.id)
      .eq('user_id', req.user!.id)

    if (deleteError) {
      return res.status(500).json({ error: { code: 'DELETE_FAILED', message: 'Failed to delete simulation' } })
    }

    const payload = await buildSandboxPayloadOrNull(client, req.user!.id, req.token)
    return res.json({ data: { success: true, action, jobId: job.id, snapshot: payload } })
  }

  const context = action === 'snapshot' || action === 'restore_snapshot'
    ? (await buildSandboxPayloadOrNull(client, req.user!.id, req.token)) || undefined
    : undefined
  const update = actionUpdate(job, action, now, {
    snapshotId: typeof req.body?.snapshotId === 'string' ? req.body.snapshotId : undefined,
    context,
  })

  const { error: updateError } = await client
    .from('migration_jobs')
    .update(update)
    .eq('id', job.id)
    .eq('user_id', req.user!.id)

  if (updateError) {
    return res.status(500).json({ error: { code: 'UPDATE_FAILED', message: 'Failed to execute action' } })
  }

  await recordOperatorTelemetry(client, req, [job], action, now, 'single')

  const payload = await buildSandboxPayloadOrNull(client, req.user!.id, req.token)
  return res.json({ data: { success: true, action, jobId: job.id, snapshot: payload } })
})

// ── POST /api/v1/sandbox/jobs/:id/approval ───────────────────────────────────
// Production Approval Gate. Records a governed human decision (approve /
// reject / request_review) with full audit evidence. This NEVER migrates or
// mutates production — approval is an evidence artifact consumed by the
// operational migration workflow.
router.post('/jobs/:id/approval', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const decision = String(req.body?.decision || '').toLowerCase()
  const note = typeof req.body?.note === 'string' ? req.body.note.slice(0, 500) : ''
  if (!['approve', 'reject', 'request_review'].includes(decision)) {
    return res.status(400).json({ error: { code: 'INVALID_DECISION', message: 'Decision must be approve, reject, or request_review' } })
  }

  const { data: job, error: readError } = await client
    .from('migration_jobs')
    .select('id, user_id, asset_id, name, job_type, status, metadata, progress, started_at, completed_at, created_at, updated_at')
    .eq('id', req.params.id)
    .eq('user_id', req.user!.id)
    .single()

  if (readError || !job) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Simulation job not found' } })
  }
  if (!isSandboxSimulationJob(job)) {
    return res.status(400).json({ error: { code: 'NOT_A_SIMULATION', message: 'Approval decisions apply to sandbox simulations only.' } })
  }
  const status = normalizeStatus(job.status)
  if (decision === 'approve' && status !== 'completed') {
    return res.status(400).json({ error: { code: 'NOT_COMPLETED', message: 'Only completed simulations can be approved for production planning.' } })
  }

  const now = new Date().toISOString()
  const meta = asRecord(job.metadata)
  const approval = {
    decision,
    decidedBy: req.user!.email || req.user!.id,
    decidedAt: now,
    note: note || null,
    simulationStatusAtDecision: status,
  }
  const approvalHistory = [...(Array.isArray(meta.approvalHistory) ? meta.approvalHistory as any[] : []), approval].slice(-10)

  const { error: updateError } = await client
    .from('migration_jobs')
    .update({ updated_at: now, metadata: { ...meta, approval, approvalHistory } })
    .eq('id', job.id)
    .eq('user_id', req.user!.id)

  if (updateError) {
    return res.status(500).json({ error: { code: 'UPDATE_FAILED', message: 'Failed to record approval decision' } })
  }

  const decisionLabel = decision === 'approve' ? 'approved for production planning' : decision === 'reject' ? 'rejected' : 'sent back for review'
  await insertEngineEvent(client, job, `sandbox-approval-${decision}`, `Simulation "${job.name || job.id}" ${decisionLabel} by ${approval.decidedBy}.`, decision === 'reject' ? 'warning' : 'info', { decision, note: note || null })

  const { error: securityError } = await client.from('security_events').insert({
    user_id: req.user!.id,
    event_type: `sandbox-approval-${decision}`,
    severity: decision === 'reject' ? 'warning' : 'info',
    message: `Production approval gate: simulation "${job.name || job.id}" ${decisionLabel}.`,
    asset_id: job.asset_id || null,
    resource_name: job.name || job.id,
    resource_type: 'migration-sandbox',
    metadata: { decision, jobId: job.id, note: note || null },
    created_at: now,
  })
  if (securityError && !isMissingTable(securityError)) console.warn('[sandbox] approval security event failed:', securityError.message)

  const { error: auditError } = await client.from('audit_logs').insert({
    user_id: req.user!.id,
    action: `sandbox_approval_${decision}`,
    entity_type: 'migration_job',
    entity_id: job.id,
    details: { decision, note: note || null, simulationStatus: status, jobName: job.name || job.id },
    ip_address: req.ip?.replace('::ffff:', '') || null,
    user_agent: String(req.headers['user-agent'] || '').slice(0, 500),
    created_at: now,
  })
  if (auditError && !isMissingTable(auditError)) console.warn('[sandbox] approval audit log failed:', auditError.message)

  const payload = await buildSandboxPayloadOrNull(client, req.user!.id, req.token)
  return res.json({ data: { success: true, decision, jobId: job.id, approval, snapshot: payload } })
})

// ── GET /api/v1/sandbox/twin ─────────────────────────────────────────────────
// Full digital-twin detail (bounded): twin nodes, dependency graph with
// edges, topology heat map, and failure predictions for the twin tabs.
router.get('/twin', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  try {
    const userId = req.user!.id
    const [assets, inventory, exposures, certificates, relationships, runtimeEvents, jobs] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, updated_at, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe').eq('user_id', userId).limit(1500)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, detected_value, created_at').eq('user_id', userId).limit(1500)),
      safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, not_after, is_quantum_safe, is_expiring_soon, status').eq('user_id', userId).limit(500)),
      safeRows(client, 'asset_relationships', (q) => q.select('*').eq('user_id', userId).limit(3000)),
      safeRows(client, 'runtime_crypto_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(500)),
      safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, progress, metadata, completed_at').eq('user_id', userId).limit(500)),
    ])

    const workflows = (jobs || []).map((job: any) => ({
      id: job.id,
      assetId: job.asset_id,
      name: job.name || job.id,
      status: normalizeStatus(job.status),
      progress: Number(job.progress || 0),
      isSandbox: isSandboxSimulationJob(job),
      completedAt: job.completed_at || null,
      metadata: asRecord(job.metadata),
    }))
    const bundle: TwinBundle = {
      assets: assets || [],
      inventory: inventory || [],
      exposures: exposures || [],
      certificates: certificates || [],
      relationships: relationships || [],
      runtimeEvents: runtimeEvents || [],
      vulns: [],
      scanResults: [],
      events: [],
      workflows,
    }
    const twin = buildDigitalTwin(bundle)
    const graph = buildDependencyGraph(bundle)
    const topology = buildTopology(twin)
    const failurePrediction = predictFailures(bundle, graph)

    return res.json({ data: { generatedAt: twin.generatedAt, twin, graph, topology, failurePrediction } })
  } catch (err) {
    if (err instanceof SnapshotUnavailableError) {
      return res.status(503).json({ error: { code: 'SNAPSHOT_UNAVAILABLE', message: err.message } })
    }
    console.error('[sandbox] twin error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to build digital twin' } })
  }
})

// ── POST /api/v1/sandbox/simulate ────────────────────────────────────────────
router.post('/simulate', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const { assetId, assetIds, fromAlgo, toAlgo, migrationType, dryRun, environment, simulationType } = req.body || {}
  const requestedAssetIds: string[] = Array.from(new Set(
    [...(Array.isArray(assetIds) ? assetIds : []), ...(assetId ? [assetId] : [])]
      .map((value) => String(value || '').trim())
      .filter(Boolean)
  ))
  if (!fromAlgo && requestedAssetIds.length === 0) {
    return res.status(400).json({ error: { code: 'MISSING_PARAMS', message: 'Either assetIds or fromAlgo is required' } })
  }
  if (requestedAssetIds.length > 25) {
    return res.status(400).json({ error: { code: 'TOO_MANY_ASSETS', message: 'A single simulation batch supports up to 25 assets.' } })
  }
  if (simulationType && !SIMULATION_TYPES.some((t) => t.id === String(simulationType).toLowerCase())) {
    return res.status(400).json({ error: { code: 'INVALID_SIMULATION_TYPE', message: `Unknown simulation type. Supported: ${SIMULATION_TYPES.map((t) => t.id).join(', ')}` } })
  }
  const simType = simulationTypeById(String(simulationType || (requestedAssetIds.length > 0 ? 'full_enterprise_migration' : 'custom_scenario')))

  const now = new Date().toISOString()
  const userId = req.user!.id
  const baseMeta = {
    dryRun: !!dryRun,
    sandboxMode: true,
    executionMode: dryRun ? 'dry_run' : 'sandbox_simulation',
    engine: ENGINE_NAME,
    phase: 'queued',
    queueReason: 'Awaiting sandbox executor slot',
    queuedAt: now,
    initiatedBy: req.user!.email,
    initiatedAt: now,
    // Enterprise pipeline v2: every new simulation progresses through the
    // 14-stage Discovery → AI Risk Analysis lifecycle inside the digital twin.
    pipelineVersion: 2,
    simulationType: simType.id,
    simulationTypeLabel: simType.label,
    stagePlan: ENGINE_PIPELINE_STAGES.map((stage) => ({ id: stage.id, label: stage.label, at: stage.at })),
  }

  let jobRows: any[] = []

  if (requestedAssetIds.length > 0) {
    // Simulations against assets must run against the tenant's REAL scanned
    // evidence: validate ownership, then seed each job from crypto inventory
    // and exposure records discovered by the scanners.
    let ownedAssets: any[] = []
    let invRows: any[] = []
    let expRows: any[] = []
    try {
      ;[ownedAssets, invRows, expRows] = await Promise.all([
        safeRows(client, 'assets', (q) => q.select('id, name, type, environment, service_owner, criticality, status').eq('user_id', userId).in('id', requestedAssetIds)),
        safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe').eq('user_id', userId).in('asset_id', requestedAssetIds).limit(1000)),
        safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, detected_value').eq('user_id', userId).in('asset_id', requestedAssetIds).limit(1000)),
      ])
    } catch (err) {
      if (err instanceof SnapshotUnavailableError) {
        return res.status(503).json({ error: { code: 'SNAPSHOT_UNAVAILABLE', message: 'Scanned asset evidence is temporarily unavailable; please retry the simulation.' } })
      }
      throw err
    }
    const ownedById = new Map<string, any>((ownedAssets || []).map((a: any) => [String(a.id), a]))
    const missing = requestedAssetIds.filter((id) => !ownedById.has(id))
    if (missing.length > 0) {
      return res.status(404).json({ error: { code: 'ASSET_NOT_FOUND', message: `${missing.length} selected asset(s) were not found in your scanned inventory.` } })
    }

    const inventoryByAsset = groupRowsByAsset(invRows)
    const exposuresByAsset = groupRowsByAsset(expRows)

    jobRows = requestedAssetIds.map((id, index) => {
      const asset = ownedById.get(id)
      const seed = assetSimulationSeed(asset, inventoryByAsset.get(id) || [], exposuresByAsset.get(id) || [])
      const source = String(fromAlgo || seed.sourceAlgorithm)
      const target = String(toAlgo || (fromAlgo ? pqcAlgoRec(source, migrationType || '') : seed.targetAlgorithm))
      const complexityMs = Math.min(120_000, seed.vulnerableItems * 8_000 + seed.criticalExposures * 12_000)
      return {
        user_id: userId,
        asset_id: id,
        name: `${dryRun ? '[DRY RUN] ' : 'Sandbox: '}${asset.name || 'Asset'} (${source} → ${target})`,
        job_type: `sandbox_${simulationType ? simType.id : (migrationType || 'asset_migration')}`,
        status: 'queued',
        target_algorithm: target,
        strategy: `${source} → ${target}`,
        progress: 0,
        started_at: null,
        created_at: now,
        updated_at: now,
        metadata: {
          ...baseMeta,
          sourceAlgorithm: source,
          targetAlgorithm: target,
          assetName: asset.name || 'Unnamed asset',
          assetType: asset.type || 'service',
          environment: environment || asset.environment || 'sandbox',
          owner: asset.service_owner || 'Unassigned',
          criticality: String(asset.criticality || 'medium').toLowerCase(),
          riskLevel: seed.riskLevel,
          evidence: {
            inventoryItems: seed.inventoryItems,
            vulnerableItems: seed.vulnerableItems,
            exposures: seed.exposures,
            criticalExposures: seed.criticalExposures,
            algorithms: seed.algorithms,
            source: 'crypto_inventory + crypto_exposures',
          },
          simulatedDurationMs: Math.round((simType.baseDurationMs + simType.perAssetMs) * (dryRun ? 0.55 : 1)) + complexityMs + index * 8_000,
        },
      }
    })
  } else {
    const targetAlgo = toAlgo || pqcAlgoRec(fromAlgo || 'rsa', migrationType || '')
    jobRows = [{
      user_id: userId,
      asset_id: null,
      name: dryRun ? `[DRY RUN] ${fromAlgo || 'Crypto'} → ${targetAlgo}` : `Sandbox: ${fromAlgo || 'Crypto'} → ${targetAlgo}`,
      job_type: `sandbox_${simulationType ? simType.id : (migrationType || 'pqc_migration')}`,
      status: 'queued',
      target_algorithm: targetAlgo,
      strategy: `${fromAlgo || 'Classical'} → ${targetAlgo}`,
      progress: 0,
      started_at: null,
      created_at: now,
      updated_at: now,
      metadata: {
        ...baseMeta,
        sourceAlgorithm: fromAlgo || 'Classical',
        targetAlgorithm: targetAlgo,
        environment: environment || 'sandbox',
        simulatedDurationMs: Math.round(simType.baseDurationMs * (dryRun ? 0.55 : 1)) + 20_000,
      },
    }]
  }

  const { data: newJobs, error: insertError } = await client
    .from('migration_jobs')
    .insert(jobRows)
    .select()

  if (insertError || !newJobs || newJobs.length === 0) {
    console.error('[sandbox] simulate insert error:', insertError)
    return res.status(500).json({ error: { code: 'INSERT_FAILED', message: 'Failed to create simulation job(s)' } })
  }

  // Emit initial events per job so execution logs trace every simulation.
  const migrationEventInsert = await client.from('migration_events').insert(newJobs.map((job: any) => {
    const meta = asRecord(job.metadata)
    return {
      user_id: userId,
      migration_id: job.id,
      event_type: 'simulation-started',
      severity: 'info',
      message: `Sandbox simulation queued: ${job.name}`,
      metadata: {
        sourceAlgorithm: meta.sourceAlgorithm,
        targetAlgorithm: meta.targetAlgorithm,
        assetName: meta.assetName || null,
        dryRun: !!dryRun,
        engine: ENGINE_NAME,
        status: 'queued',
      },
      created_at: now,
    }
  }))
  if (migrationEventInsert.error && !isMissingTable(migrationEventInsert.error)) console.warn('[sandbox] simulation event insert failed:', migrationEventInsert.error.message)

  const primaryJob = newJobs[0]
  const securityEventInsert = await client.from('security_events').insert({
    user_id: userId,
    event_type: 'sandbox-simulation-started',
    severity: 'info',
    message: newJobs.length > 1
      ? `Migration sandbox started ${newJobs.length} simulations against scanned assets.`
      : `Migration sandbox simulation started: ${primaryJob.name}`,
    asset_id: primaryJob.asset_id || null,
    resource_name: newJobs.length > 1 ? 'Migration Sandbox' : primaryJob.name,
    resource_type: 'migration-sandbox',
    metadata: { migrationType, dryRun: !!dryRun, jobIds: newJobs.map((job: any) => job.id), assetIds: requestedAssetIds },
    created_at: now,
  })
  if (securityEventInsert.error && !isMissingTable(securityEventInsert.error)) console.warn('[sandbox] simulation security event insert failed:', securityEventInsert.error.message)

  const auditLogInsert = await client.from('audit_logs').insert({
    user_id: userId,
    action: 'sandbox_simulation_started',
    entity_type: newJobs.length > 1 ? 'migration_jobs' : 'migration_job',
    entity_id: newJobs.length > 1 ? null : primaryJob.id,
    details: { migrationType, dryRun: !!dryRun, jobIds: newJobs.map((job: any) => job.id), assetIds: requestedAssetIds },
    ip_address: req.ip?.replace('::ffff:', '') || null,
    user_agent: String(req.headers['user-agent'] || '').slice(0, 500),
    created_at: now,
  })
  if (auditLogInsert.error && !isMissingTable(auditLogInsert.error)) console.warn('[sandbox] simulation audit log insert failed:', auditLogInsert.error.message)

  const payload = await buildSandboxPayloadOrNull(client, userId, req.token)
  return res.json({
    data: {
      success: true,
      jobId: primaryJob.id,
      jobName: primaryJob.name,
      jobIds: newJobs.map((job: any) => job.id),
      count: newJobs.length,
      status: 'queued',
      snapshot: payload,
    },
  })
})

// ── POST /api/v1/sandbox/bulk-action ─────────────────────────────────────────
router.post('/bulk-action', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const action = String(req.body?.action || '').toLowerCase()
  const scope = String(req.body?.scope || 'sandbox').toLowerCase() === 'all' ? 'all' : 'sandbox'
  const scopes: Record<string, string[]> = {
    pause: ['running', 'in_progress'],
    resume: ['paused', 'queued'],
    retry: ['failed'],
    rollback: ['running', 'paused', 'completed', 'rollback_requested'],
    stop: ['running', 'in_progress', 'paused', 'queued'],
    snapshot: ['running', 'in_progress', 'paused', 'queued', 'completed', 'failed', 'rollback_requested', 'rolled_back', 'stopped'],
  }

  if (!scopes[action]) {
    return res.status(400).json({ error: { code: 'INVALID_ACTION', message: 'Unsupported bulk action' } })
  }

  const { data: jobs, error: readError } = await client
    .from('migration_jobs')
    .select('id, user_id, name, job_type, status, metadata, progress')
    .eq('user_id', req.user!.id)
    .in('status', scopes[action])

  if (readError) {
    return res.status(500).json({ error: { code: 'READ_FAILED', message: 'Failed to read jobs' } })
  }

  const now = new Date().toISOString()
  let affected = 0
  const affectedJobs: any[] = []
  const eligibleJobs = (jobs || []).filter((job: any) =>
    (scope === 'all' || isSandboxSimulationJob(job)) && !sandboxEngineActionRefusal(job, action))
  for (const job of eligibleJobs) {
    const update = actionUpdate(job, action, now)

    const { error } = await client
      .from('migration_jobs')
      .update(update)
      .eq('id', job.id)
      .eq('user_id', req.user!.id)

    if (!error) {
      affected++
      affectedJobs.push(job)
    }
  }

  await recordOperatorTelemetry(client, req, affectedJobs, action, now, 'bulk')
  const payload = await buildSandboxPayloadOrNull(client, req.user!.id, req.token)
  return res.json({ data: { success: true, action, scope, affected, snapshot: payload } })
})

// ── GET /api/v1/sandbox/risk ──────────────────────────────────────────────────
router.get('/risk', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const [critCount, highCount, totalAssets, totalJobs, failedJobs, completedJobs, vulnCount, expiringCertCount] = await Promise.all([
    safeCount(client, 'crypto_exposures', req.user!.id, (q) => q.eq('severity', 'critical')),
    safeCount(client, 'crypto_exposures', req.user!.id, (q) => q.eq('severity', 'high')),
    safeCount(client, 'assets', req.user!.id),
    safeCount(client, 'migration_jobs', req.user!.id),
    safeCount(client, 'migration_jobs', req.user!.id, (q) => q.eq('status', 'failed')),
    safeCount(client, 'migration_jobs', req.user!.id, (q) => q.eq('status', 'completed')),
    safeCount(client, 'vulnerabilities', req.user!.id, (q) => q.neq('status', 'resolved')),
    safeCount(client, 'certificates', req.user!.id, (q) => q.eq('is_expiring_soon', true)),
  ])

  // Same two corrections as the main snapshot path, which this lightweight
  // endpoint had drifted from:
  //   - `100 - penalties` is a higher-is-better POSTURE score; publishing it as
  //     `riskScore` inverted its meaning, and it saturated to 0 for any real
  //     estate. Quantum risk is 0-100 LOWER-better, banded by RISK_BANDS.
  //   - `completedJobs / totalJobs` is a migration-job completion rate. It is
  //     not PQC readiness and must not be published under that name.
  const quantumRiskScore = riskScoreFromLoad(
    critCount * 3 + highCount * 1.2 + expiringCertCount * 1 + vulnCount * 0.4 + failedJobs * 2,
  )
  const migrationHealth = totalJobs > 0
    ? (failedJobs / totalJobs > 0.3 ? 'critical' : failedJobs > 0 ? 'degraded' : 'healthy')
    : 'no-data'

  return res.json({
    data: {
      quantumRiskScore,
      quantumRiskLevel: riskBandFor(quantumRiskScore).label,
      migrationJobCompletionRate: totalJobs > 0 ? Math.round((completedJobs / totalJobs) * 100) : 0,
      migrationHealth,
      criticalExposures: critCount,
      highExposures: highCount,
      openVulnerabilities: vulnCount,
      expiringCertificates: expiringCertCount,
      failedMigrations: failedJobs,
      totalAssets,
      // This endpoint counts raw `crypto_exposures` rows for speed. The
      // de-duplicated, cross-page-consistent figures live on /snapshot.
      countBasis: 'raw crypto_exposures rows — see /snapshot for de-duplicated observation counts',
      generatedAt: new Date().toISOString(),
    }
  })
})

// ── GET /api/v1/sandbox/export ────────────────────────────────────────────────
router.get('/export', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  try {
    const payload = await getSandboxSnapshot(client, req.user!.id, req.token)
    const format = String(req.query.format || 'json').toLowerCase()
    const simulationId = typeof req.query.simulationId === 'string' ? req.query.simulationId : ''
    const selectedSimulation = simulationId
      ? [...(payload.simulations || []), ...(payload.workflows || [])].find((s: any) => s.id === simulationId)
      : null
    if (simulationId && !selectedSimulation) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Simulation not found' } })
    }
    const snapshots = selectedSimulation && Array.isArray(selectedSimulation.metadata?.snapshots)
      ? selectedSimulation.metadata.snapshots
      : []
    // Enterprise report catalog: targeted payload subsets for audits and
    // change-management approvals. Default (no reportType) keeps the full
    // snapshot export for backwards compatibility.
    const reportType = String(req.query.reportType || '').toLowerCase()
    const p: any = payload
    const reportPayloads: Record<string, () => any> = {
      executive: () => ({ reportType: 'executive-report', summary: p.summary, sophia: p.sophia, approvalGate: p.approvalGate, businessImpact: p.businessImpact, complianceScore: p.complianceScore, timeline: (p.timeline || []).slice(0, 12) }),
      technical: () => ({ reportType: 'technical-report', summary: p.summary, simulations: p.simulations, workflows: p.workflows, digitalTwin: p.digitalTwin, dependencyGraph: p.dependencyGraph, failurePrediction: p.failurePrediction, telemetryFrame: p.telemetryFrame, pqcStack: p.pqcStack }),
      compliance: () => ({ reportType: 'compliance-report', complianceScore: p.complianceScore, complianceItems: p.complianceItems, approvalGate: p.approvalGate, auditEvidence: (p.recentLogs || []).slice(0, 60) }),
      migration: () => ({ reportType: 'migration-report', summary: p.summary, workflows: p.workflows, workflowPhases: p.workflowPhases, history: p.history, timeline: p.timeline }),
      performance: () => ({ reportType: 'performance-report', performanceBenchmark: p.performanceBenchmark, telemetryFrame: p.telemetryFrame }),
      rollback: () => ({ reportType: 'rollback-report', rollbackAnalysis: p.rollbackAnalysis, approvalGate: p.approvalGate, history: (p.history || []).filter((row: any) => row.snapshots > 0 || row.status === 'rolled_back') }),
      risk: () => ({ reportType: 'risk-assessment-report', summary: p.summary, riskFactors: p.riskFactors, failurePrediction: p.failurePrediction, blockers: p.sophia?.detectedBlockers || [], businessImpact: p.businessImpact }),
      twin: () => ({ reportType: 'digital-twin-summary', digitalTwin: p.digitalTwin, dependencyGraph: p.dependencyGraph, topology: p.topology }),
      ai: () => ({ reportType: 'ai-recommendations-report', sophia: p.sophia, recommendations: p.recommendations }),
    }
    if (reportType && !reportPayloads[reportType]) {
      return res.status(400).json({ error: { code: 'INVALID_REPORT_TYPE', message: `Unknown reportType. Supported: ${Object.keys(reportPayloads).join(', ')}` } })
    }

    const exportPayload = selectedSimulation
      ? {
          generatedAt: payload.generatedAt,
          reportType: 'simulation-history-report',
          simulation: selectedSimulation,
          history: (payload.history || []).find((row: any) => row.id === selectedSimulation.id) || null,
          snapshots,
          events: (payload.recentLogs || []).filter((log: any) => log.jobId === selectedSimulation.id),
          complianceItems: payload.complianceItems,
          pqcStack: payload.pqcStack,
          summary: payload.summary,
        }
      : reportType
        ? { generatedAt: payload.generatedAt, ...reportPayloads[reportType]() }
        : payload
    const baseName = selectedSimulation
      ? `qguard-sandbox-${String(selectedSimulation.id).slice(0, 8)}-${new Date().toISOString().slice(0, 10)}`
      : `qguard-sandbox${reportType ? `-${reportType}` : ''}-${new Date().toISOString().slice(0, 10)}`

    if (format === 'csv') {
      const escape = (v: unknown) => {
        const t = String(v ?? '')
        return /[",\n\r]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t
      }
      // Report-type-specific tabular exports; default remains the workflow table.
      let rows: unknown[][]
      if (!selectedSimulation && reportType === 'performance') {
        rows = [
          ['metric', 'unit', 'before', 'after', 'deltaPct', 'improved', 'note'],
          ...((p.performanceBenchmark?.metrics || []) as any[]).map((m) => [m.label, m.unit, m.before, m.after, m.deltaPct, m.improved, m.note]),
        ]
      } else if (!selectedSimulation && reportType === 'compliance') {
        rows = [
          ['framework', 'control', 'status', 'score'],
          ...((p.complianceItems || []) as any[]).map((c) => [c.framework, c.control, c.status, c.score]),
        ]
      } else if (!selectedSimulation && reportType === 'risk') {
        rows = [
          ['category', 'prediction', 'probabilityPct', 'severity', 'affectedAssets', 'evidence', 'recommendation'],
          ...((p.failurePrediction?.predictions || []) as any[]).map((f) => [f.category, f.label, f.probabilityPct, f.severity, (f.affectedAssets || []).join('; '), f.evidence, f.recommendation]),
        ]
      } else if (!selectedSimulation && reportType === 'rollback') {
        rows = [
          ['item', 'covered', 'detail'],
          ...((p.rollbackAnalysis?.restorationChecklist || []) as any[]).map((c) => [c.label, c.covered ? 'yes' : 'no', c.detail]),
          ['RTO (min)', p.rollbackAnalysis?.rtoMinutes ?? '', ''],
          ['RPO (min)', p.rollbackAnalysis?.rpoMinutes ?? '', ''],
          ['Rollback success probability (%)', p.rollbackAnalysis?.successProbabilityPct ?? '', ''],
          ['Predicted downtime (min)', p.rollbackAnalysis?.downtimePredictionMin ?? '', ''],
        ]
      } else if (!selectedSimulation && reportType === 'twin') {
        rows = [
          ['component', 'assets', 'vulnerable', 'critical'],
          ...((p.digitalTwin?.componentGroups || []) as any[]).map((g) => [g.label, g.assets, g.vulnerable, g.critical]),
        ]
      } else if (!selectedSimulation && (reportType === 'executive' || reportType === 'ai')) {
        rows = [
          ['field', 'value'],
          ['Verdict', p.sophia?.verdict ?? ''],
          ['Migration confidence (%)', p.sophia?.migrationConfidencePct ?? ''],
          ['Compatibility score (%)', p.sophia?.compatibilityScorePct ?? ''],
          ['Rollback confidence (%)', p.sophia?.rollbackConfidencePct ?? ''],
          ['AI confidence (%)', p.sophia?.aiConfidencePct ?? ''],
          ['Simulation status', p.approvalGate?.simulationStatus ?? ''],
          ['Production ready', p.approvalGate?.productionReady ? 'yes' : 'no'],
          ['Executive summary', p.sophia?.executiveSummary ?? ''],
          ...((p.sophia?.priorityActions || []) as string[]).map((a, i) => [`Priority action ${i + 1}`, a]),
        ]
      } else {
        const sourceRows = selectedSimulation ? [selectedSimulation] : (payload.workflows || payload.simulations)
        rows = [
          ['id', 'name', 'runMode', 'asset', 'assetType', 'status', 'fromAlgo', 'toAlgo', 'progress', 'riskLevel', 'phase', 'eta', 'owner', 'environment', 'snapshots', 'events'],
          ...sourceRows.map((s: any) => [s.id, s.name, s.runModeLabel || s.runMode || 'workflow', s.assetName, s.assetType, s.status, s.fromAlgo, s.toAlgo, s.progress, s.riskLevel, s.phase, s.eta, s.owner, s.environment, Array.isArray(s.metadata?.snapshots) ? s.metadata.snapshots.length : 0, s.eventCount || 0]),
        ]
      }
      res.setHeader('Content-Type', 'text/csv')
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.csv"`)
      return res.send(rows.map((r) => r.map(escape).join(',')).join('\n'))
    }

    res.setHeader('Content-Type', 'application/json')
    res.setHeader('Content-Disposition', `attachment; filename="${baseName}.json"`)
    return res.send(JSON.stringify(exportPayload, null, 2))
  } catch (err) {
    return res.status(500).json({ error: { code: 'EXPORT_FAILED', message: 'Export failed' } })
  }
})

export function startSandboxScheduler() {
  if (sandboxSchedulerStarted) return
  sandboxSchedulerStarted = true

  const client = getServiceClient()
  if (!client) {
    console.warn('[sandbox] background scheduler disabled: service client is not configured')
    return
  }

  const tick = async () => {
    try {
      // The engine advances jobs behind the cache's back, so any tenant whose
      // jobs actually moved has its snapshot dropped — otherwise a progress
      // change could sit invisible for up to the TTL.
      const { advancedUsers } = await advanceSandboxJobs(client)
      for (const advancedUser of advancedUsers) invalidateSandboxSnapshot(advancedUser)
    } catch (err) {
      console.warn('[sandbox] background scheduler tick failed:', err instanceof Error ? err.message : err)
    }
  }

  void tick()
  const timer = setInterval(tick, 15_000)
  if (typeof (timer as any).unref === 'function') (timer as any).unref()
}

export default router
