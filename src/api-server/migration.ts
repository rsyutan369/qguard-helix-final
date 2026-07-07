import { Router, type NextFunction, type Request, type Response } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import {
  MANDATORY_PQC_REQUIRED_CAPABILITIES,
  MANDATORY_PQC_STACK,
  MANDATORY_PQC_TARGET_ALGORITHMS,
  mandatoryPqcStackMetadata,
  mandatoryPqcTargetForContext,
} from '@/lib/crypto/mandatory-pqc-stack'

type AuthenticatedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

type LiveMigrationStatus = 'running' | 'completed' | 'failed' | 'queued' | 'paused'

type LiveMigrationEvent = {
  id: string
  migrationId: string
  eventType: string
  message: string
  severity: string
  createdAt: string
  metadata: Record<string, unknown>
}

type LiveMigrationJob = {
  id: string
  asset: string
  assetId: string | null
  assetType: string
  environment: string
  owner: string
  criticality: string
  fromAlgo: string
  toAlgo: string
  migrationType: string
  status: LiveMigrationStatus
  rawStatus: string
  progress: number
  eta: string
  startedAt: string | null
  completedAt: string | null
  createdAt: string
  updatedAt: string
  executionStatus: string
  executionBacked: boolean
  isSandbox: boolean
  runMode: string
  agentId: string | null
  agentName: string | null
  agentStatus: string
  currentStep: string
  telemetryCount: number
  validationCount: number
  validationStatus: string
  logs: LiveMigrationEvent[]
  logCount: number
  metadata: Record<string, unknown>
}

type PlannerAction = 'save' | 'export' | 'schedule' | 'start' | 'sandbox'

type MigrationPlanPayload = {
  id: string
  status: string
  action: PlannerAction
  selectedAssets: any[]
  configuration: Record<string, unknown>
  riskData: Record<string, unknown>
  migrationMetadata: Record<string, unknown>
  jobs: any[]
  createdAt: string
  updatedAt: string
  orchestrationUrl: string
  liveMigrationUrl: string
  sandboxUrl: string
}

const PLANNER_CURRENT_ALGORITHMS = ['RSA-2048', 'RSA-4096', 'ECC', 'ECDSA', 'ECDH']
const PLANNER_TARGET_ALGORITHMS = [...MANDATORY_PQC_TARGET_ALGORITHMS]
const PLANNER_BASELINE_TAGS = ['Web Application', 'Tenant Scope', 'Critical', 'High', 'Medium', 'Low', 'Service']
const PLANNER_CONTROL_LABELS: Record<string, string> = {
  rollback: 'Rollback',
  validation: 'Validation Checks',
  compatibility: 'Compatibility Testing',
  hybridMode: 'Hybrid Mode',
  continuousMonitoring: 'Continuous Monitoring',
  complianceValidation: 'Compliance Validation',
}

const router = Router()

function tokenFromRequest(req: Request): string | null {
  const headerToken = getToken(req)
  if (headerToken) return headerToken
  const queryToken = req.query.token
  return typeof queryToken === 'string' && queryToken.length > 0 ? queryToken : null
}

async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = tokenFromRequest(req)
  if (!token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  const user = await getServerUser(token)
  if (!user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  }

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

function isMissingRelation(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return text.includes('pgrst200') || text.includes('relationship') || text.includes('foreign key')
}

function plannerNetworkErrorMessage(error: any, action: string) {
  const text = `${error?.name || ''} ${error?.message || ''} ${error?.cause?.code || ''} ${error?.cause?.message || ''}`
  if (/fetch failed|und_err_socket|socketerror|other side closed/i.test(text)) {
    return `${action} could not complete because the remote database connection closed before returning a response. Please retry; the planner will not keep spinning in the background.`
  }
  return error?.message || `${action} failed`
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return value as Record<string, unknown>
}

function asStringArray(value: unknown, fallback: string[] = []) {
  if (!Array.isArray(value)) return fallback
  return value.map((item) => String(item || '').trim()).filter(Boolean)
}

function uniqueStrings(values: unknown[], fallback: string[] = []) {
  const seen = new Set<string>()
  for (const value of values) {
    const text = String(value || '').trim()
    if (text) seen.add(text)
  }
  return seen.size ? Array.from(seen) : fallback
}

function pickString(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = record[key]
    if (typeof value === 'string' && value.trim()) return value.trim()
    if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  }
  return ''
}

function normalizeStatus(status: unknown): LiveMigrationStatus {
  const value = String(status || 'pending').toLowerCase().replace(/\s+/g, '_')
  if (['completed', 'complete', 'done', 'success', 'successful'].includes(value)) return 'completed'
  if (['failed', 'error', 'errored'].includes(value)) return 'failed'
  if (['running', 'in_progress', 'migrating', 'executing'].includes(value)) return 'running'
  if (['paused', 'cancelled', 'canceled', 'rollback_requested', 'rolled_back'].includes(value)) return 'paused'
  return 'queued'
}

function prettify(value: string | null | undefined, fallback = 'Unknown') {
  if (!value) return fallback
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase())
}

function compareToken(value: unknown) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, '')
}

function matchesToken(value: unknown, selected: unknown) {
  const left = compareToken(value)
  const right = compareToken(selected)
  return Boolean(left && right && (left.includes(right) || right.includes(left)))
}

function normalizePlanTag(value: unknown) {
  const text = String(value || '').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
  return text ? prettify(text) : ''
}

function clampProgress(value: unknown, status: LiveMigrationStatus) {
  if (status === 'completed') return 100
  if (status === 'queued') return 0
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return status === 'failed' ? 0 : 0
  return Math.max(0, Math.min(100, Math.round(numeric)))
}

function nestedAsset(row: any) {
  const asset = row?.assets
  if (Array.isArray(asset)) return asset[0] || null
  return asset || null
}

function firstInventoryAlgorithm(assetId: string | null, inventoryByAsset: Map<string, any[]>) {
  if (!assetId) return ''
  const items = inventoryByAsset.get(assetId) || []
  const vulnerable = items.find((item) => item?.is_vulnerable || item?.is_quantum_safe === false)
  const selected = vulnerable || items[0]
  return typeof selected?.algorithm === 'string' ? selected.algorithm : ''
}

function parseStrategyAlgorithms(strategy: string) {
  const normalized = strategy.replace(/→/g, '->')
  const match = normalized.match(/([A-Za-z0-9+_. -]+?)\s*(?:->| to )\s*([A-Za-z0-9+_. -]+)/i)
  return {
    from: match?.[1]?.trim() || '',
    to: match?.[2]?.trim() || '',
  }
}

function deriveSourceAlgorithm(row: any, metadata: Record<string, unknown>, inventoryByAsset: Map<string, any[]>) {
  const fromMetadata = pickString(metadata, [
    'sourceAlgorithm',
    'source_algorithm',
    'fromAlgorithm',
    'from_algorithm',
    'fromAlgo',
    'currentAlgorithm',
    'current_algorithm',
    'detectedAlgorithm',
    'detected_algorithm',
    'algorithm',
  ])
  if (fromMetadata) return fromMetadata

  const parsed = parseStrategyAlgorithms(String(row?.strategy || ''))
  if (parsed.from) return parsed.from

  const inventoryAlgorithm = firstInventoryAlgorithm(row?.asset_id || null, inventoryByAsset)
  return inventoryAlgorithm || 'Classical'
}

function deriveTargetAlgorithm(row: any, metadata: Record<string, unknown>, context = '') {
  const stackContext = [
    context,
    row?.strategy,
    row?.job_type,
    pickString(metadata, ['sourceAlgorithm', 'source_algorithm', 'assetType', 'asset_type', 'assetName', 'asset_name', 'migrationType', 'migration_type']),
  ].filter(Boolean).join(' ')
  const target = String(row?.target_algorithm || '').trim()
  if (target) return mandatoryPqcTargetForContext(target, stackContext)

  const fromMetadata = pickString(metadata, [
    'targetAlgorithm',
    'target_algorithm',
    'toAlgorithm',
    'to_algorithm',
    'toAlgo',
    'recommendedPqc',
    'recommended_pqc',
    'pqcReplacement',
    'pqc_replacement',
  ])
  if (fromMetadata) return mandatoryPqcTargetForContext(fromMetadata, stackContext)

  const parsed = parseStrategyAlgorithms(String(row?.strategy || ''))
  return mandatoryPqcTargetForContext(parsed.to || 'PQC target pending', stackContext)
}

function deriveEta(row: any, status: LiveMigrationStatus, progress: number, metadata: Record<string, unknown>) {
  const metadataEta = pickString(metadata, ['eta', 'estimatedEta', 'estimated_eta', 'remaining'])
  if (metadataEta) return metadataEta
  if (status === 'completed') return 'Done'
  if (status === 'failed') return 'Failed'
  if (status === 'paused') return 'Paused'
  if (status === 'queued') return 'Pending'
  if (!row?.started_at || progress <= 0) return 'Calculating'

  const elapsedMs = Date.now() - new Date(row.started_at).getTime()
  const totalMs = elapsedMs / (progress / 100)
  const remainingMs = Math.max(0, totalMs - elapsedMs)
  const minutes = Math.max(1, Math.round(remainingMs / 60000))
  return minutes >= 60 ? `~${Math.round(minutes / 60)}h` : `~${minutes}m`
}

function deriveAlgorithmBucket(job: LiveMigrationJob) {
  const haystack = `${job.toAlgo} ${job.fromAlgo} ${job.migrationType} ${pickString(job.metadata, ['strategy'])}`.toUpperCase()
  const isHybrid = haystack.includes('HYBRID') || haystack.includes('+') || haystack.includes('DUAL')
  if (isHybrid && haystack.includes('ML-KEM')) return 'Hybrid (ML-KEM + classical)'
  if (isHybrid && haystack.includes('ML-DSA')) return 'Hybrid (ML-DSA + classical)'
  if (haystack.includes('ML-KEM')) return 'ML-KEM'
  if (haystack.includes('ML-DSA')) return 'ML-DSA'
  if (haystack.includes('SLH-DSA') || haystack.includes('SPHINCS')) return 'SLH-DSA'
  if (haystack.includes('AES')) return 'Symmetric hardening'
  return 'Other PQC transition'
}

function classifyHealth(job: LiveMigrationJob) {
  const explicit = pickString(job.metadata, ['health', 'migrationHealth', 'migration_health']).toLowerCase()
  if (['on_track', 'on track', 'healthy'].includes(explicit)) return 'onTrack'
  if (['at_risk', 'at risk', 'risk'].includes(explicit)) return 'atRisk'
  if (['delayed', 'blocked'].includes(explicit)) return 'delayed'
  if (job.status === 'failed') return 'failed'
  if (job.status === 'paused' || job.status === 'queued') return 'delayed'
  if (job.status === 'running' && job.startedAt) {
    const hours = (Date.now() - new Date(job.startedAt).getTime()) / 3600000
    if (hours > 6 && job.progress < 90) return 'delayed'
    if (hours > 2 && job.progress < 40) return 'atRisk'
  }
  return 'onTrack'
}

function buildTimeline(jobs: LiveMigrationJob[]) {
  const days = Array.from({ length: 7 }, (_, index) => {
    const date = new Date()
    date.setHours(0, 0, 0, 0)
    date.setDate(date.getDate() - (6 - index))
    return {
      key: date.toISOString().slice(0, 10),
      label: date.toLocaleDateString('en-US', { month: 'short', day: '2-digit' }),
      running: 0,
      completed: 0,
      failed: 0,
    }
  })
  const byKey = new Map(days.map((day) => [day.key, day]))

  for (const job of jobs) {
    const timestamp = job.completedAt || job.updatedAt || job.createdAt
    if (!timestamp) continue
    const key = new Date(timestamp).toISOString().slice(0, 10)
    const day = byKey.get(key)
    if (!day) continue
    if (job.status === 'completed') day.completed += 1
    else if (job.status === 'failed') day.failed += 1
    else if (job.status === 'running') day.running += 1
  }

  return days
}

function buildHealth(jobs: LiveMigrationJob[]) {
  const counts = { onTrack: 0, atRisk: 0, delayed: 0, failed: 0 }
  for (const job of jobs) counts[classifyHealth(job) as keyof typeof counts] += 1
  const total = Math.max(jobs.length, 1)
  return [
    { key: 'onTrack', label: 'On Track', count: counts.onTrack, percent: Math.round((counts.onTrack / total) * 100), color: '#30d158' },
    { key: 'atRisk', label: 'At Risk', count: counts.atRisk, percent: Math.round((counts.atRisk / total) * 100), color: '#f6d365' },
    { key: 'delayed', label: 'Delayed', count: counts.delayed, percent: Math.round((counts.delayed / total) * 100), color: '#f59e0b' },
    { key: 'failed', label: 'Failed', count: counts.failed, percent: Math.round((counts.failed / total) * 100), color: '#ff3b30' },
  ]
}

function buildAlgorithmSummary(jobs: LiveMigrationJob[]) {
  const counts = new Map<string, number>()
  for (const job of jobs) {
    const bucket = deriveAlgorithmBucket(job)
    counts.set(bucket, (counts.get(bucket) || 0) + 1)
  }
  const total = Math.max(jobs.length, 1)
  const colors = ['#f6d365', '#30d158', '#00d9ff', '#8b5cf6', '#ff7a3d']
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([label, count], index) => ({
      label,
      count,
      percent: Math.round((count / total) * 100),
      color: colors[index % colors.length],
    }))
}

function buildCsv(snapshot: Awaited<ReturnType<typeof buildLiveMigrationSnapshot>>) {
  const escape = (value: unknown) => {
    const text = String(value ?? '')
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }

  const rows = [
    ['type', 'id', 'asset', 'status', 'source_algorithm', 'target_algorithm', 'progress', 'timestamp', 'message'],
    ...snapshot.jobs.map((job) => [
      'job',
      job.id,
      job.asset,
      job.rawStatus,
      job.fromAlgo,
      job.toAlgo,
      job.progress,
      job.updatedAt,
      `${job.migrationType} | ${job.environment} | ${job.owner}`,
    ]),
    ...snapshot.jobs.flatMap((job) => job.logs.map((log) => [
      'event',
      log.id,
      job.asset,
      log.severity,
      job.fromAlgo,
      job.toAlgo,
      job.progress,
      log.createdAt,
      log.message,
    ])),
  ]

  return rows.map((row) => row.map(escape).join(',')).join('\n')
}

async function safeCount(client: any, table: string, userId: string, apply?: (query: any) => any) {
  try {
    let query = client.from(table).select('id', { count: 'exact', head: true }).eq('user_id', userId)
    if (apply) query = apply(query)
    const { count, error } = await query
    if (error) {
      if (!isMissingTable(error)) console.warn(`[migration-live] Count failed for ${table}:`, error.message)
      return 0
    }
    return count || 0
  } catch {
    return 0
  }
}

async function safeRows(client: any, table: string, userId: string, apply: (query: any) => any) {
  try {
    const { data, error } = await apply(client.from(table)).eq('user_id', userId)
    if (error) {
      if (!isMissingTable(error)) console.warn(`[migration-planner] Query failed for ${table}:`, error.message)
      return []
    }
    return data || []
  } catch (error) {
    console.warn(`[migration-planner] Query crashed for ${table}:`, error instanceof Error ? error.message : error)
    return []
  }
}

function planIdFromMetadata(metadata: Record<string, unknown>) {
  const direct = pickString(metadata, ['planId', 'plan_id', 'migrationPlanId', 'migration_plan_id'])
  if (direct) return direct
  const nested = asRecord(metadata.plan || metadata.migrationPlan)
  return pickString(nested, ['id', 'planId', 'plan_id'])
}

function matchesPlanId(row: any, planId?: string | null) {
  if (!planId) return true
  return planIdFromMetadata(asRecord(row?.metadata)) === planId
}

async function fetchJobs(client: any, userId: string, planId?: string | null) {
  const baseSelect = 'id, user_id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at'
  const withAsset = `${baseSelect}, assets(id, name, type, environment, criticality, service_owner, status)`
  const primary = await client
    .from('migration_jobs')
    .select(withAsset)
    .eq('user_id', userId)
    .order('updated_at', { ascending: false })
    .limit(100)

  if (!primary.error) return (primary.data || []).filter((row: any) => matchesPlanId(row, planId))
  if (isMissingRelation(primary.error)) {
    const fallback = await client
      .from('migration_jobs')
      .select(baseSelect)
      .eq('user_id', userId)
      .order('updated_at', { ascending: false })
      .limit(100)
    if (!fallback.error) return (fallback.data || []).filter((row: any) => matchesPlanId(row, planId))
    if (!isMissingTable(fallback.error)) console.warn('[migration-live] Jobs query failed:', fallback.error.message)
    return []
  }

  if (!isMissingTable(primary.error)) console.warn('[migration-live] Jobs query failed:', primary.error.message)
  return []
}

async function fetchEvents(client: any, userId: string, migrationIds: string[]) {
  if (migrationIds.length === 0) return []
  const { data, error } = await client
    .from('migration_events')
    .select('id, migration_id, event_type, message, severity, metadata, created_at')
    .eq('user_id', userId)
    .in('migration_id', migrationIds)
    .order('created_at', { ascending: true })
    .limit(600)

  if (error) {
    if (!isMissingTable(error)) console.warn('[migration-live] Events query failed:', error.message)
    return []
  }
  return data || []
}

async function fetchExecutionRows(client: any, userId: string, migrationIds: string[]) {
  if (migrationIds.length === 0) return []
  const { data, error } = await client
    .from('migration_execution')
    .select('id, migration_id, plan_id, agent_id, status, progress, current_step, started_at, completed_at, metadata, created_at, updated_at')
    .eq('user_id', userId)
    .in('migration_id', migrationIds)
    .order('updated_at', { ascending: true })
    .limit(1000)

  if (error) {
    if (!isMissingTable(error)) console.warn('[migration-live] Execution query failed:', error.message)
    return []
  }
  return data || []
}

async function fetchTelemetryRows(client: any, userId: string, migrationIds: string[]) {
  if (migrationIds.length === 0) return []
  const { data, error } = await client
    .from('migration_telemetry')
    .select('id, migration_id, agent_id, event_type, metric_type, metric_value, message, metadata, observed_at, created_at')
    .eq('user_id', userId)
    .in('migration_id', migrationIds)
    .order('observed_at', { ascending: true })
    .limit(1200)

  if (error) {
    if (!isMissingTable(error)) console.warn('[migration-live] Telemetry query failed:', error.message)
    return []
  }
  return data || []
}

async function fetchValidationRows(client: any, userId: string, migrationIds: string[]) {
  if (migrationIds.length === 0) return []
  const { data, error } = await client
    .from('migration_validation_logs')
    .select('id, migration_id, agent_id, validation_type, status, evidence, metadata, created_at')
    .eq('user_id', userId)
    .in('migration_id', migrationIds)
    .order('created_at', { ascending: true })
    .limit(1000)

  if (error) {
    if (!isMissingTable(error)) console.warn('[migration-live] Validation query failed:', error.message)
    return []
  }
  return data || []
}

async function fetchAuditRows(client: any, userId: string, planId?: string | null) {
  const query = client
    .from('migration_audit_logs')
    .select('id, plan_id, action, stage, result, details, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(500)
  const { data, error } = planId ? await query.eq('plan_id', planId) : await query

  if (error) {
    if (!isMissingTable(error)) console.warn('[migration-live] Audit query failed:', error.message)
    return []
  }
  return data || []
}

async function fetchAgentRows(client: any, userId: string) {
  const { data, error } = await client
    .from('scanner_agents')
    .select('id, name, hostname, status, version, last_seen_at, metadata')
    .eq('user_id', userId)
    .limit(500)

  if (error) {
    if (!isMissingTable(error)) console.warn('[migration-live] Agent query failed:', error.message)
    return []
  }
  return data || []
}

async function fetchInventory(client: any, userId: string, assetIds: string[]) {
  if (assetIds.length === 0) return []
  const { data, error } = await client
    .from('crypto_inventory')
    .select('id, asset_id, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe, discovered_at')
    .eq('user_id', userId)
    .in('asset_id', assetIds)
    .order('discovered_at', { ascending: false })
    .limit(500)

  if (error) {
    if (!isMissingTable(error)) console.warn('[migration-live] Inventory query failed:', error.message)
    return []
  }
  return data || []
}

async function latestScanAt(client: any, userId: string) {
  try {
    const { data, error } = await client
      .from('pqc_scan_sessions')
      .select('completed_at, started_at, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(1)
    if (error || !data?.length) return null
    return data[0].completed_at || data[0].started_at || data[0].created_at || null
  } catch {
    return null
  }
}

function latestByMigration(rows: any[], key = 'migration_id') {
  const map = new Map<string, any>()
  for (const row of rows) {
    const migrationId = row?.[key]
    if (typeof migrationId === 'string' && migrationId) map.set(migrationId, row)
  }
  return map
}

function groupRowsByMigration(rows: any[], key = 'migration_id') {
  const map = new Map<string, any[]>()
  for (const row of rows) {
    const migrationId = row?.[key]
    if (typeof migrationId !== 'string' || !migrationId) continue
    if (!map.has(migrationId)) map.set(migrationId, [])
    map.get(migrationId)!.push(row)
  }
  return map
}

// Sandbox simulations are executed by the qguard-sandbox-orchestrator engine,
// not by tenant agents. They must surface with their real engine progress on
// the live migration view instead of appearing stuck "waiting for agent".
function isSandboxSimulationRow(row: any, metadata: Record<string, unknown>) {
  const executionMode = pickString(metadata, ['executionMode', 'runMode', 'mode']).toLowerCase()
  const jobType = String(row?.job_type || '').toLowerCase()
  return metadata.sandboxMode === true
    || ['sandbox_simulation', 'dry_run', 'simulation'].includes(executionMode)
    || /sandbox|simulation|dry_run|dry-run/.test(jobType)
    || /^\[dry run\]|^sandbox:/i.test(String(row?.name || ''))
}

function executionEvidenceInMetadata(metadata: Record<string, unknown>) {
  const executorState = asRecord(metadata.executorState)
  const lastExecutorEvent = asRecord(metadata.lastExecutorEvent)
  const assignedAgentId = pickString(metadata, ['assignedAgentId', 'assigned_agent_id'])
  return Boolean(
    assignedAgentId ||
    Object.keys(executorState).length ||
    Object.keys(lastExecutorEvent).length ||
    (Array.isArray(metadata.executorEvents) && metadata.executorEvents.length > 0),
  )
}

function validationStatusFromRows(rows: any[], metadata: Record<string, unknown>) {
  const latest = rows[rows.length - 1]
  const metadataValidation = asRecord(metadata.lastValidation)
  const status = String(latest?.status || metadataValidation.status || '').toLowerCase()
  if (status) return status
  if (metadataValidation.passed === true) return 'passed'
  if (metadataValidation.passed === false) return 'failed'
  return rows.length ? 'recorded' : 'pending'
}

function telemetrySeverity(row: any) {
  const text = `${row?.event_type || ''} ${row?.metric_type || ''} ${row?.message || ''}`.toLowerCase()
  if (/fail|error|critical|rollback/.test(text)) return 'error'
  if (/warn|blocked|manual|pause/.test(text)) return 'warning'
  if (/complete|pass|validated|success/.test(text)) return 'success'
  return 'info'
}

function validationSeverity(row: any) {
  const status = String(row?.status || '').toLowerCase()
  if (/fail|error|blocked/.test(status)) return 'error'
  if (/pass|success|valid/.test(status)) return 'success'
  return 'info'
}

function buildLiveTelemetry(jobs: LiveMigrationJob[], telemetryRows: any[] = [], validationRows: any[] = [], auditRows: any[] = []) {
  const telemetryText = telemetryRows.map((row) => `${row.event_type || ''} ${row.metric_type || ''} ${row.message || ''}`.toLowerCase())
  const logText = jobs.flatMap((job) => job.logs.map((log) => `${log.eventType} ${log.message}`.toLowerCase()))
  const countTelemetry = (pattern: RegExp) => telemetryText.filter((text) => pattern.test(text)).length
  const countLogs = (pattern: RegExp) => logText.filter((text) => pattern.test(text)).length
  const validationEvents = validationRows.length + countTelemetry(/validat|pqc|quantum-safe|readiness/)
  const compatibilityEvents = countTelemetry(/compatib|handshake|fallback|interoperab/)
  const failed = jobs.filter((job) => job.status === 'failed').length
  const running = jobs.filter((job) => job.status === 'running').length
  const waiting = jobs.filter((job) => job.status === 'queued' && !job.executionBacked).length

  return {
    tlsHandshakeEvents: countTelemetry(/tls|handshake|cipher|session/),
    certificateReplacements: countTelemetry(/cert|certificate|issuer|chain/),
    keyRotations: countTelemetry(/key|rotation|kem|envelope/),
    pqcValidationEvents: validationEvents,
    compatibilityChecks: compatibilityEvents,
    systemHealth: failed > 0 ? 'Degraded' : running > 0 ? 'Executing' : waiting > 0 ? 'Awaiting Agent' : jobs.length > 0 ? 'Ready' : 'No active migrations',
    activityFeed: {
      migrationLogs: jobs.flatMap((job) => job.logs).length,
      validationLogs: validationRows.length,
      errorLogs: jobs.flatMap((job) => job.logs).filter((log) => /error|critical|failed/i.test(`${log.severity} ${log.message}`)).length,
      auditLogs: auditRows.length + countLogs(/operator|audit|approve|rollback|pause|resume/),
      complianceLogs: countTelemetry(/compliance|nist|evidence|policy/) + countLogs(/compliance|nist|evidence|policy/),
    },
  }
}

async function buildLiveMigrationSnapshot(client: any, userId: string, planId?: string | null) {
  const jobRows = await fetchJobs(client, userId, planId)
  const migrationIds = jobRows
    .map((row: any) => row.id)
    .filter((id: unknown): id is string => typeof id === 'string' && id.length > 0)
  const assetIds: string[] = Array.from(new Set<string>(
    jobRows
      .map((row: any) => row.asset_id)
      .filter((id: unknown): id is string => typeof id === 'string' && id.length > 0),
  ))
  const [eventRows, executionRows, telemetryRows, validationRows, auditRows, agentRows, inventoryRows, totalAssets, findings, criticalExposures, highExposures, scanAt] = await Promise.all([
    fetchEvents(client, userId, migrationIds),
    fetchExecutionRows(client, userId, migrationIds),
    fetchTelemetryRows(client, userId, migrationIds),
    fetchValidationRows(client, userId, migrationIds),
    fetchAuditRows(client, userId, planId),
    fetchAgentRows(client, userId),
    fetchInventory(client, userId, assetIds),
    safeCount(client, 'assets', userId, (query) => query.eq('status', 'active')),
    safeCount(client, 'pqc_scan_results', userId),
    safeCount(client, 'crypto_exposures', userId, (query) => query.eq('severity', 'critical')),
    safeCount(client, 'crypto_exposures', userId, (query) => query.eq('severity', 'high')),
    latestScanAt(client, userId),
  ])

  const eventsByJob = new Map<string, LiveMigrationEvent[]>()
  for (const event of eventRows) {
    const migrationId = event.migration_id
    if (!eventsByJob.has(migrationId)) eventsByJob.set(migrationId, [])
    eventsByJob.get(migrationId)!.push({
      id: event.id,
      migrationId,
      eventType: event.event_type || 'migration-event',
      message: event.message || '',
      severity: event.severity || 'info',
      createdAt: event.created_at,
      metadata: asRecord(event.metadata),
    })
  }

  const latestExecutionByJob = latestByMigration(executionRows)
  const telemetryByJob = groupRowsByMigration(telemetryRows)
  const validationByJob = groupRowsByMigration(validationRows)
  const agentsById = new Map<string, any>()
  for (const agent of agentRows) {
    if (typeof agent?.id === 'string') agentsById.set(agent.id, agent)
  }

  const inventoryByAsset = new Map<string, any[]>()
  for (const item of inventoryRows) {
    if (!item.asset_id) continue
    if (!inventoryByAsset.has(item.asset_id)) inventoryByAsset.set(item.asset_id, [])
    inventoryByAsset.get(item.asset_id)!.push(item)
  }

  const jobs: LiveMigrationJob[] = jobRows.map((row: any) => {
    const metadata = asRecord(row.metadata)
    const asset = nestedAsset(row)
    const rowStatus = normalizeStatus(row.status)
    const executionRow = latestExecutionByJob.get(row.id) || null
    const executionMetadata = asRecord(executionRow?.metadata)
    const executorState = asRecord(metadata.executorState)
    const jobTelemetryRows = telemetryByJob.get(row.id) || []
    const jobValidationRows = validationByJob.get(row.id) || []
    const isSandbox = isSandboxSimulationRow(row, metadata)
    const sandboxEngineBacked = isSandbox && Boolean(metadata.engine || metadata.lastEngineTickAt || metadata.sandboxMode === true)
    const executionBacked = Boolean(executionRow || jobTelemetryRows.length || executionEvidenceInMetadata(metadata)) || sandboxEngineBacked
    const executionStatus = String(executionRow?.status || executorState.status || (executionBacked ? row.status || 'running' : 'waiting_for_agent'))
    let status = normalizeStatus(executionStatus)
    if (!executionBacked && (rowStatus === 'running' || String(row.status || '').toLowerCase() === 'executing')) status = 'queued'
    if (!executionBacked && rowStatus === 'completed' && validationStatusFromRows(jobValidationRows, metadata) === 'pending') status = 'queued'
    if (rowStatus === 'failed') status = 'failed'
    if (rowStatus === 'paused') status = 'paused'
    const progressSource = executionBacked ? executionRow?.progress ?? executorState.progress ?? row.progress : 0
    const progress = clampProgress(progressSource, status)
    const logs = eventsByJob.get(row.id) || []
    const metadataLogs = Array.isArray(metadata.logs)
      ? metadata.logs
          .filter((log) => typeof log === 'string')
          .map((message, index) => ({
            id: `${row.id}-metadata-${index}`,
            migrationId: row.id,
            eventType: 'metadata-log',
            message: String(message),
            severity: 'info',
            createdAt: row.updated_at || row.created_at,
            metadata: {},
          }))
      : []
    const telemetryLogs: LiveMigrationEvent[] = jobTelemetryRows.map((item: any) => ({
      id: item.id || `${row.id}-telemetry-${item.observed_at || item.created_at}`,
      migrationId: row.id,
      eventType: item.event_type || item.metric_type || 'migration-telemetry',
      message: item.message || prettify(String(item.metric_type || item.event_type || 'migration telemetry')),
      severity: telemetrySeverity(item),
      createdAt: item.observed_at || item.created_at || row.updated_at || row.created_at,
      metadata: asRecord(item.metadata),
    }))
    const validationLogs: LiveMigrationEvent[] = jobValidationRows.map((item: any) => ({
      id: item.id || `${row.id}-validation-${item.created_at}`,
      migrationId: row.id,
      eventType: item.validation_type || 'migration-validation',
      message: `${prettify(String(item.validation_type || 'Migration validation'))}: ${prettify(String(item.status || 'recorded'))}`,
      severity: validationSeverity(item),
      createdAt: item.created_at || row.updated_at || row.created_at,
      metadata: {
        ...asRecord(item.metadata),
        evidence: asRecord(item.evidence),
      },
    }))

    const strategy = String(row.strategy || pickString(metadata, ['strategy']) || '')
    const fromAlgo = deriveSourceAlgorithm(row, metadata, inventoryByAsset)
    const toAlgo = deriveTargetAlgorithm(row, metadata, `${fromAlgo} ${strategy} ${asset?.type || ''} ${asset?.name || ''}`)
    const agentId = String(executionRow?.agent_id || pickString(metadata, ['assignedAgentId', 'assigned_agent_id']) || '')
    const agent = agentId ? agentsById.get(agentId) : null
    const agentName = String(agent?.name || pickString(metadata, ['assignedAgentName', 'assigned_agent_name']) || agent?.hostname || (sandboxEngineBacked ? pickString(metadata, ['engine']) || 'qguard-sandbox-orchestrator' : ''))
    const validationStatus = validationStatusFromRows(jobValidationRows, metadata)
    const startedAt = executionBacked ? executionRow?.started_at || row.started_at || null : null
    const completedAt = status === 'completed' ? executionRow?.completed_at || row.completed_at || null : null
    const sortedLogs = [...logs, ...telemetryLogs, ...validationLogs, ...metadataLogs]
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())

    return {
      id: row.id,
      asset: String(asset?.name || row.name || 'Unnamed migration'),
      assetId: row.asset_id || null,
      assetType: String(asset?.type || pickString(metadata, ['assetType', 'asset_type']) || 'Service'),
      environment: String(asset?.environment || pickString(metadata, ['environment']) || 'Unknown'),
      owner: String(asset?.service_owner || pickString(metadata, ['owner', 'serviceOwner', 'service_owner']) || 'Unassigned'),
      criticality: String(asset?.criticality || pickString(metadata, ['criticality']) || 'medium').toLowerCase(),
      fromAlgo,
      toAlgo,
      migrationType: String(pickString(metadata, ['migrationType', 'migration_type']) || strategy || prettify(row.job_type, 'PQC Migration')),
      status,
      rawStatus: String(row.status || status),
      progress,
      eta: deriveEta({ ...row, started_at: startedAt }, status, progress, metadata),
      startedAt,
      completedAt,
      createdAt: row.created_at || new Date().toISOString(),
      updatedAt: row.updated_at || row.completed_at || row.started_at || row.created_at || new Date().toISOString(),
      executionStatus,
      executionBacked,
      isSandbox,
      runMode: isSandbox ? (metadata.dryRun === true ? 'dry_run' : 'sandbox_simulation') : 'migration_workflow',
      agentId: agentId || null,
      agentName: agentName || null,
      agentStatus: String(agent?.status || (sandboxEngineBacked && !agentId ? 'sandbox-engine' : executionBacked ? 'assigned' : 'unassigned')),
      currentStep: String(
        executionRow?.current_step
        || executorState.currentStep
        || pickString(executionMetadata, ['currentStep'])
        || (sandboxEngineBacked ? pickString(metadata, ['phaseDetail', 'phase']) || 'Sandbox engine executing' : '')
        || (executionBacked ? 'Agent execution reported' : 'Waiting for agent claim')
      ),
      telemetryCount: jobTelemetryRows.length,
      validationCount: jobValidationRows.length,
      validationStatus,
      logs: sortedLogs,
      logCount: sortedLogs.length,
      metadata: {
        ...metadata,
        strategy,
        agentExecution: {
          backed: executionBacked,
          executionStatus,
          agentId: agentId || null,
          agentName: agentName || null,
          agentStatus: agent?.status || null,
          currentStep: executionRow?.current_step || null,
          telemetryCount: jobTelemetryRows.length,
          validationCount: jobValidationRows.length,
          validationStatus,
          sourceTables: ['migration_execution', 'migration_telemetry', 'migration_validation_logs'],
        },
      },
    }
  })

  const total = jobs.length
  const summary = {
    total,
    running: jobs.filter((job) => job.status === 'running').length,
    completed: jobs.filter((job) => job.status === 'completed').length,
    failed: jobs.filter((job) => job.status === 'failed').length,
    queued: jobs.filter((job) => job.status === 'queued').length,
    paused: jobs.filter((job) => job.status === 'paused').length,
    completionRate: total ? Math.round((jobs.filter((job) => job.status === 'completed').length / total) * 100) : 0,
    waitingForAgent: jobs.filter((job) => job.status === 'queued' && !job.executionBacked && !job.isSandbox).length,
    agentBacked: jobs.filter((job) => job.executionBacked).length,
    sandboxSimulations: jobs.filter((job) => job.isSandbox).length,
    verified: jobs.filter((job) => /pass|success|valid/.test(job.validationStatus)).length,
    agentsOnline: agentRows.filter((agent: any) => ['active', 'online', 'telemetry'].includes(String(agent?.status || '').toLowerCase())).length,
    totalAssets,
    findings,
    criticalExposures,
    highExposures,
    lastScanAt: scanAt,
    complianceMode: 'NIST Compliant',
    standardLabel: 'NIST SP 800-208 | NIST SP 800-57 Rev. 5',
  }

  return {
    generatedAt: new Date().toISOString(),
    planId: planId || null,
    summary,
    jobs,
    timeline: buildTimeline(jobs),
    health: buildHealth(jobs),
    algorithmSummary: buildAlgorithmSummary(jobs),
    telemetry: buildLiveTelemetry(jobs, telemetryRows, validationRows, auditRows),
  }
}

type PlannerRangeKey = '7d' | '30d' | '90d' | 'all'

function plannerRange(raw: unknown): { key: PlannerRangeKey; label: string; days: number | null } {
  const value = String(raw || '7d').toLowerCase()
  if (value === '30d') return { key: '30d', label: 'Last 30 Days', days: 30 }
  if (value === '90d') return { key: '90d', label: 'Last 90 Days', days: 90 }
  if (value === 'all') return { key: 'all', label: 'All Time', days: null }
  return { key: '7d', label: 'Last 7 Days', days: 7 }
}

function plannerDateMs(value: unknown) {
  if (!value) return 0
  const time = new Date(String(value)).getTime()
  return Number.isFinite(time) ? time : 0
}

function plannerWindow(range: { days: number | null }) {
  const now = Date.now()
  const days = range.days || 3650
  const start = now - days * 86400000
  const previousStart = now - days * 2 * 86400000
  return { now, start, previousStart, days }
}

function plannerSeverityRank(value: unknown) {
  const normalized = String(value || '').toLowerCase()
  if (normalized.includes('critical')) return 4
  if (normalized.includes('high')) return 3
  if (normalized.includes('medium') || normalized.includes('warning')) return 2
  if (normalized.includes('low') || normalized.includes('info')) return 1
  return 0
}

function plannerIsPqcAlgorithm(value: unknown) {
  return /ml-kem|kyber|ml-dsa|dilithium|slh-dsa|sphincs|falcon|post-quantum|pqc|quantum-safe/i.test(String(value || ''))
}

function plannerIsLegacyAlgorithm(value: unknown) {
  return /rsa|ecdsa|ecdh|diffie|dh\b|dsa|sha-1|sha1|md5|3des|rc4|tls\s*1\.[01]/i.test(String(value || ''))
}

function plannerReplacement(algorithm: unknown, context = '') {
  return mandatoryPqcTargetForContext(algorithm, context)
}

function configuredTargetAlgorithm(asset: any, configuration: Record<string, unknown>) {
  const targets = asStringArray(configuration.targetAlgorithms, PLANNER_TARGET_ALGORITHMS)
  const context = `${asset?.targetSolution || ''} ${asset?.currentAlgorithm || ''} ${asset?.type || ''} ${asset?.name || ''}`
  const direct = targets.find((target) => matchesToken(context, target))
  if (direct) return mandatoryPqcTargetForContext(direct, context)

  const signTarget = targets.find((target) => /mldsa|hybridpki/i.test(compareToken(target)))
  const kemTarget = targets.find((target) => /mlkem|hybridtls/i.test(compareToken(target)))
  const hybridTls = targets.find((target) => /hybridtls/i.test(compareToken(target)))
  const hybridPki = targets.find((target) => /hybridpki/i.test(compareToken(target)))
  const lowered = context.toLowerCase()

  if (/certificate|cert|pki|sign|ecdsa|dsa|jwt|identity/.test(lowered)) {
    return mandatoryPqcTargetForContext(hybridPki || signTarget || targets[0] || 'ML-DSA-65', context)
  }
  if (/tls|api|gateway|vpn|ssh|protocol|handshake|ecdh|dh|rsa|kem|key exchange|web/.test(lowered)) {
    return mandatoryPqcTargetForContext(hybridTls || kemTarget || targets[0] || 'ML-KEM-768', context)
  }
  return mandatoryPqcTargetForContext(targets[0] || asset?.targetSolution || 'PQC target pending', context)
}

function sourceAlgorithmInScope(asset: any, configuration: Record<string, unknown>) {
  const currentAlgorithms = asStringArray(configuration.currentAlgorithms, PLANNER_CURRENT_ALGORITHMS)
  if (!currentAlgorithms.length) return true
  return currentAlgorithms.some((algorithm) => matchesToken(asset?.currentAlgorithm, algorithm))
}

function plannerAssetTags(asset: any, configuration: Record<string, unknown>) {
  const tags = new Set<string>(PLANNER_BASELINE_TAGS.filter((tag) => ['Tenant Scope'].includes(tag)))
  const type = normalizePlanTag(asset?.type)
  const environment = normalizePlanTag(asset?.environment)
  const priority = normalizePlanTag(asset?.priority)

  if (type) tags.add(type)
  if (environment) tags.add(environment)
  if (priority) tags.add(priority)
  if (/web|api|frontend|portal/i.test(`${asset?.type || ''} ${asset?.name || ''}`)) tags.add('Web Application')
  if (/service|api|worker|daemon|gateway/i.test(`${asset?.type || ''} ${asset?.name || ''}`)) tags.add('Service')
  if (Number(asset?.risk || 0) >= 70) tags.add('High')
  if (Number(asset?.risk || 0) >= 85 || String(asset?.priority || '').toLowerCase() === 'critical') tags.add('Critical')
  if (Number(asset?.risk || 0) >= 45 && Number(asset?.risk || 0) < 70) tags.add('Medium')
  if (Number(asset?.risk || 0) < 45) tags.add('Low')

  for (const selected of asStringArray(configuration.tags)) {
    const label = normalizePlanTag(selected)
    if (label) tags.add(label)
  }

  return Array.from(tags)
}

function tagPriorityBoost(asset: any, configuration: Record<string, unknown>) {
  const selected = asStringArray(configuration.tags).map(compareToken).filter(Boolean)
  if (!selected.length) return 0
  const assetTags = plannerAssetTags(asset, configuration).map(compareToken)
  return selected.filter((tag) => assetTags.some((assetTag) => assetTag === tag || assetTag.includes(tag) || tag.includes(assetTag))).length * 8
}

function plannerSequenceScore(asset: any, configuration: Record<string, unknown>) {
  const priorityBoost = String(asset?.priority || '').toLowerCase() === 'critical' ? 25 : String(asset?.priority || '').toLowerCase() === 'high' ? 15 : 0
  const algorithmBoost = sourceAlgorithmInScope(asset, configuration) ? 10 : -8
  return Number(asset?.risk || 0) + priorityBoost + tagPriorityBoost(asset, configuration) + algorithmBoost
}

function phaseLabel(strategy: string, asset: any, index: number, total: number) {
  if (/pilot/i.test(strategy)) return index === 0 ? 'Pilot Deployment' : 'Pilot Expansion'
  if (/department/i.test(strategy)) return `Department: ${prettify(asset?.owner || 'Unassigned')}`
  if (/environment/i.test(strategy)) return `Environment: ${prettify(asset?.environment || 'Unknown')}`
  if (/full/i.test(strategy)) return 'Full Enterprise Rollout'
  const third = Math.ceil(total / 3)
  if (index < third) return 'Stage 1: Critical Services'
  if (index < third * 2) return 'Stage 2: Core Workloads'
  return 'Stage 3: Remaining Scope'
}

function buildExecutionPlan(assets: any[], configuration: Record<string, unknown>) {
  const strategy = String(configuration.deploymentStrategy || 'Staged Rollout')
  const sorted = [...assets].sort((a, b) => plannerSequenceScore(b, configuration) - plannerSequenceScore(a, configuration))
  const groups = new Map<string, any[]>()

  sorted.forEach((asset, index) => {
    const label = phaseLabel(strategy, asset, index, Math.max(1, sorted.length))
    if (!groups.has(label)) groups.set(label, [])
    groups.get(label)!.push(asset)
  })

  const phases = Array.from(groups.entries()).map(([name, items], phaseIndex) => ({
    phaseIndex: phaseIndex + 1,
    name,
    assetCount: items.length,
    scopeKey: compareToken(name) || `phase${phaseIndex + 1}`,
    gateRequired: groups.size > 1 && phaseIndex > 0,
    startsOnApproval: phaseIndex === 0,
  }))

  const assignments = new Map<string, any>()
  let sequence = 1
  for (const phase of phases) {
    const phaseAssets = groups.get(phase.name) || []
    for (const asset of phaseAssets) {
      const key = String(asset.assetId || asset.id)
      assignments.set(key, {
        ...phase,
        sequenceOrder: sequence,
        riskPriorityScore: plannerSequenceScore(asset, configuration),
      })
      sequence += 1
    }
  }

  return { phases, assignments }
}

function preparePlanAssets(assets: any[], configuration: Record<string, unknown>) {
  const executionPlan = buildExecutionPlan(assets, configuration)
  return {
    phases: executionPlan.phases,
    assets: assets.map((asset) => {
      const key = String(asset.assetId || asset.id)
      const assignment = executionPlan.assignments.get(key) || executionPlan.phases[0] || { phaseIndex: 1, name: 'Migration Scope', sequenceOrder: 1, scopeKey: 'scope', gateRequired: false, startsOnApproval: true }
      const targetAlgorithm = configuredTargetAlgorithm(asset, configuration)
      return {
        ...asset,
        targetSolution: targetAlgorithm,
        configuredTargetAlgorithm: targetAlgorithm,
        currentAlgorithmInScope: sourceAlgorithmInScope(asset, configuration),
        tags: plannerAssetTags(asset, configuration),
        phaseIndex: assignment.phaseIndex,
        phaseName: assignment.name,
        sequenceOrder: assignment.sequenceOrder,
        scopeKey: assignment.scopeKey,
        gateRequired: assignment.gateRequired,
        startsOnApproval: assignment.startsOnApproval,
        riskPriorityScore: assignment.riskPriorityScore,
      }
    }),
  }
}

function plannerJobType(row: any) {
  const value = `${row?.type || ''} ${row?.currentAlgorithm || ''} ${row?.targetSolution || ''}`.toLowerCase()
  if (/cert|pki|issuer|ca/.test(value)) return 'cert_transition'
  if (/sign|dsa|jwt|identity/.test(value)) return 'signature_transition'
  if (/tls|vpn|ssh|gateway|api|protocol/.test(value)) return 'protocol_upgrade'
  if (/database|storage|vault|encrypt|aes/.test(value)) return 'encryption_upgrade'
  if (/key/.test(value)) return 'key_rotation'
  return 'pqc_migration'
}

function plannerPriority(score: number): 'Critical' | 'High' | 'Medium' | 'Low' {
  if (score >= 85) return 'Critical'
  if (score >= 70) return 'High'
  if (score >= 45) return 'Medium'
  return 'Low'
}

function plannerStatus(status: LiveMigrationStatus | null, progress: number, risk: number) {
  if (status === 'completed') return 'Completed'
  if (status === 'running') return 'In Progress'
  if (status === 'failed') return 'Blocked'
  if (status === 'paused') return 'Paused'
  if (status === 'queued') return 'Planned'
  if (progress >= 100) return 'Completed'
  return risk >= 70 ? 'Planned' : 'Ready'
}

function plannerStatusClass(status: string) {
  if (status === 'Completed' || status === 'Ready') return 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
  if (status === 'In Progress') return 'bg-sky-500/10 border-sky-500/30 text-sky-300'
  if (status === 'Blocked') return 'bg-red-500/10 border-red-500/30 text-red-300'
  if (status === 'Paused') return 'bg-amber-500/10 border-amber-500/30 text-amber-300'
  return 'bg-[#FFD36B]/10 border-[#FFD36B]/30 text-[#FFD36B]'
}

function plannerPriorityClass(priority: string) {
  if (priority === 'Critical') return 'text-red-400 bg-red-500/10 border-red-500/30'
  if (priority === 'High') return 'text-orange-300 bg-orange-500/10 border-orange-500/30'
  if (priority === 'Medium') return 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30'
  return 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30'
}

function plannerDelta(current: number, previous: number, suffix = '') {
  if (!previous && !current) return { label: `0${suffix}`, positive: true }
  if (!previous) return { label: `+${current}${suffix}`, positive: true }
  const diff = current - previous
  const percent = Math.round((diff / Math.max(1, previous)) * 100)
  return { label: `${percent >= 0 ? '+' : ''}${percent}%${suffix ? ` ${suffix}` : ''}`, positive: percent >= 0 }
}

function plannerFormatDate(value: unknown) {
  const ms = plannerDateMs(value)
  if (!ms) return 'Not scheduled'
  return new Date(ms).toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })
}

function plannerRiskTrend(candidates: any[], jobs: any[], range: { days: number | null }) {
  const { now, days } = plannerWindow(range)
  const bucketCount = Math.min(Math.max(days || 30, 7), 14)
  return Array.from({ length: bucketCount }, (_, index) => {
    const start = now - (bucketCount - index) * 86400000
    const end = start + 86400000
    const completed = jobs.filter((job: any) => normalizeStatus(job.status) === 'completed' && plannerDateMs(job.completed_at || job.updated_at) >= start && plannerDateMs(job.completed_at || job.updated_at) < end).length
    const newRisk = candidates.filter((row) => plannerDateMs(row.detectedAt) >= start && plannerDateMs(row.detectedAt) < end && row.risk >= 70).length
    const base = candidates.length ? Math.round((completed / Math.max(1, candidates.length)) * 100) : 0
    return {
      day: new Date(start).toLocaleDateString('en-US', { month: 'short', day: '2-digit' }),
      value: Math.max(0, Math.min(100, base + Math.max(0, index - newRisk) * 4)),
      completed,
      newRisk,
    }
  })
}

function plannerPhases(now = Date.now()) {
  const base = new Date(now)
  base.setHours(0, 0, 0, 0)
  const addDays = (days: number) => {
    const next = new Date(base)
    next.setDate(next.getDate() + days)
    return next.toLocaleDateString('en-US', { month: 'short', day: '2-digit' })
  }
  return [
    { name: 'Discover & Assess', dates: `${addDays(-14)} - ${addDays(0)}`, start: 0, width: 18, color: 'bg-sky-500 shadow-[0_0_12px_rgba(14,165,233,0.5)]', state: 'completed' },
    { name: 'Plan & Prioritize', dates: `${addDays(0)} - ${addDays(14)}`, start: 13, width: 22, color: 'bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.45)]', state: 'active' },
    { name: 'Pilot Migration', dates: `${addDays(14)} - ${addDays(30)}`, start: 30, width: 21, color: 'bg-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.45)]', state: 'pending' },
    { name: 'Core Migration', dates: `${addDays(30)} - ${addDays(62)}`, start: 48, width: 30, color: 'bg-yellow-500 shadow-[0_0_12px_rgba(234,179,8,0.45)]', state: 'pending' },
    { name: 'Validation', dates: `${addDays(62)} - ${addDays(78)}`, start: 76, width: 16, color: 'bg-violet-500 shadow-[0_0_12px_rgba(139,92,246,0.45)]', state: 'pending' },
    { name: 'Optimization', dates: `${addDays(78)} - ${addDays(90)}`, start: 90, width: 10, color: 'bg-slate-500 shadow-[0_0_12px_rgba(100,116,139,0.45)]', state: 'pending' },
  ]
}

function plannerCandidates(assets: any[], inventory: any[], exposures: any[], jobs: any[], scanResults: any[], runtimeEvents: any[]) {
  const assetMap = new Map<string, any>((assets || []).map((asset) => [asset.id, asset]))
  const byAsset = new Map<string, { inventory: any[]; exposures: any[]; scans: any[]; runtime: any[]; jobs: any[] }>()
  const ensure = (assetId: string | null) => {
    const key = assetId || 'unassigned'
    if (!byAsset.has(key)) byAsset.set(key, { inventory: [], exposures: [], scans: [], runtime: [], jobs: [] })
    return byAsset.get(key)!
  }

  for (const item of inventory || []) ensure(item.asset_id || null).inventory.push(item)
  for (const item of exposures || []) ensure(item.asset_id || null).exposures.push(item)
  for (const item of scanResults || []) ensure(item.asset_id || null).scans.push(item)
  for (const item of runtimeEvents || []) ensure(item.asset_id || null).runtime.push(item)
  for (const item of jobs || []) ensure(item.asset_id || null).jobs.push(item)
  for (const asset of assets || []) ensure(asset.id)

  return Array.from(byAsset.entries()).map(([key, group]) => {
    const asset = assetMap.get(key) || {}
    const allAlgorithms = [
      ...group.inventory.map((item) => item.algorithm || item.protocol || item.name),
      ...group.exposures.map((item) => item.detected_value || item.exposure_type),
      ...group.scans.map((item) => item.algorithm || item.finding_type),
      ...group.runtime.map((item) => item.algorithm || item.key_exchange_algorithm || item.cipher_suite),
    ].filter(Boolean)
    const currentAlgorithm = String(allAlgorithms.find((item) => plannerIsLegacyAlgorithm(item)) || allAlgorithms[0] || 'Classical crypto')
    const severity = Math.max(
      ...group.exposures.map((item) => plannerSeverityRank(item.severity)),
      ...group.scans.map((item) => plannerSeverityRank(item.threat_level)),
      ...group.runtime.map((item) => plannerSeverityRank(item.severity)),
      plannerSeverityRank(asset.criticality),
      0,
    )
    const legacyCount = group.inventory.filter((item) => item.is_vulnerable || plannerIsLegacyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`)).length +
      group.runtime.filter((item) => item.is_legacy || item.downgrade_detected || item.shadow_crypto || item.hndl_risk).length
    const pqcCount = group.inventory.filter((item) => item.is_quantum_safe || plannerIsPqcAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`)).length
    const latestJob = group.jobs.sort((a, b) => plannerDateMs(b.updated_at || b.created_at) - plannerDateMs(a.updated_at || a.created_at))[0]
    const status = latestJob ? normalizeStatus(latestJob.status) : null
    const jobProgress = latestJob ? clampProgress(latestJob.progress, status || 'queued') : 0
    const risk = Math.min(100, severity * 18 + legacyCount * 9 + Math.max(0, group.exposures.length - pqcCount) * 4 + (status === 'failed' ? 18 : 0))
    const priority = plannerPriority(risk)
    const plannedStatus = plannerStatus(status, jobProgress, risk)
    const targetSolution = String(latestJob?.target_algorithm || plannerReplacement(currentAlgorithm, `${asset.type || ''} ${group.exposures[0]?.exposure_type || ''} ${group.scans[0]?.finding_type || ''}`))
    return {
      id: key,
      assetId: key === 'unassigned' ? null : key,
      name: String(asset.name || group.inventory[0]?.name || group.exposures[0]?.resource_name || group.runtime[0]?.asset_name || 'Unassigned cryptographic scope'),
      type: String(asset.type || group.inventory[0]?.item_type || group.runtime[0]?.asset_type || 'Service'),
      environment: String(asset.environment || group.runtime[0]?.environment || 'tenant scope'),
      owner: String(asset.service_owner || 'Unassigned'),
      currentAlgorithm,
      risk,
      priority,
      priorityColor: plannerPriorityClass(priority),
      targetSolution,
      status: plannedStatus,
      statusColor: plannerStatusClass(plannedStatus),
      progress: status === 'completed' ? 100 : jobProgress,
      detectedAt: group.exposures[0]?.updated_at || group.scans[0]?.created_at || group.runtime[0]?.observed_at || group.inventory[0]?.discovered_at || asset.updated_at || asset.created_at || latestJob?.updated_at || null,
      hasActiveJob: Boolean(latestJob && !['completed', 'failed'].includes(status || '')),
      jobId: latestJob?.id || null,
    }
  }).sort((a, b) => b.risk - a.risk)
}

async function buildMigrationPlannerSnapshot(client: any, userId: string, rawRange: unknown) {
  const range = plannerRange(rawRange)
  const window = plannerWindow(range)
  const [
    assets,
    inventory,
    exposures,
    jobs,
    migrationEvents,
    scanSessions,
    scanResults,
    runtimeEvents,
    certificates,
    complianceEvidence,
    migrationPlans,
    planConfigurations,
    migrationScope,
    migrationAssets,
    migrationTasks,
    migrationControls,
    migrationAuditLogs,
  ] = await Promise.all([
    safeRows(client, 'assets', userId, (q) => q.select('id, name, type, environment, service_owner, criticality, status, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'crypto_inventory', userId, (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').order('discovered_at', { ascending: false }).limit(2000)),
    safeRows(client, 'crypto_exposures', userId, (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(2000)),
    safeRows(client, 'migration_jobs', userId, (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'migration_events', userId, (q) => q.select('id, migration_id, event_type, message, severity, metadata, created_at').order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'pqc_scan_sessions', userId, (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, target_scope, started_at, completed_at, created_at, updated_at').order('created_at', { ascending: false }).limit(160)),
    safeRows(client, 'pqc_scan_results', userId, (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').order('created_at', { ascending: false }).limit(2000)),
    safeRows(client, 'runtime_crypto_events', userId, (q) => q.select('id, asset_id, asset_name, asset_type, algorithm, key_exchange_algorithm, cipher_suite, severity, risk_score, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').order('observed_at', { ascending: false }).limit(2000)),
    safeRows(client, 'certificates', userId, (q) => q.select('id, asset_id, name, status, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'compliance_evidence', userId, (q) => q.select('id, asset_id, framework, control_id, status, evidence_type, description, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'migration_plans', userId, (q) => q.select('id, status, selected_asset_ids, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(200)),
    safeRows(client, 'migration_plan_configurations', userId, (q) => q.select('id, plan_id, deployment_strategy, current_algorithms, target_algorithms, controls, tags, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(200)),
    safeRows(client, 'migration_scope', userId, (q) => q.select('id, plan_id, scope_type, scope_value, asset_count, priority_score, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'migration_assets', userId, (q) => q.select('id, plan_id, asset_id, target_algorithm, phase_index, sequence_order, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'migration_tasks', userId, (q) => q.select('id, plan_id, migration_job_id, task_type, status, phase_index, sequence_order, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'migration_controls', userId, (q) => q.select('id, plan_id, control_key, enabled, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'migration_audit_logs', userId, (q) => q.select('id, plan_id, action, stage, result, details, created_at').order('created_at', { ascending: false }).limit(500)),
  ])

  const candidates = plannerCandidates(assets, inventory, exposures, jobs, scanResults, runtimeEvents)
  const scopedCandidates = range.days
    ? candidates.filter((candidate) => !candidate.detectedAt || plannerDateMs(candidate.detectedAt) >= window.start || candidate.hasActiveJob)
    : candidates
  const activeAssets = (assets || []).filter((asset: any) => String(asset.status || 'active').toLowerCase() !== 'archived')
  const activeJobs = (jobs || []).filter((job: any) => !['completed', 'cancelled', 'canceled'].includes(String(job.status || '').toLowerCase()))
  const completedJobs = (jobs || []).filter((job: any) => normalizeStatus(job.status) === 'completed')
  const failedJobs = (jobs || []).filter((job: any) => normalizeStatus(job.status) === 'failed')
  const runningJobs = (jobs || []).filter((job: any) => normalizeStatus(job.status) === 'running')
  const pqcReadyAssets = new Set<string>()
  for (const item of inventory || []) if (item.asset_id && (item.is_quantum_safe || plannerIsPqcAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`))) pqcReadyAssets.add(item.asset_id)
  for (const cert of certificates || []) if (cert.asset_id && (cert.is_quantum_safe || plannerIsPqcAlgorithm(cert.algorithm))) pqcReadyAssets.add(cert.asset_id)
  for (const job of completedJobs || []) if (job.asset_id) pqcReadyAssets.add(job.asset_id)

  const currentAssets = scopedCandidates.length
  const previousCandidates = candidates.filter((candidate) => {
    const time = plannerDateMs(candidate.detectedAt)
    return time >= window.previousStart && time < window.start
  })
  const migratedCurrent = completedJobs.filter((job: any) => !range.days || plannerDateMs(job.completed_at || job.updated_at) >= window.start).length + pqcReadyAssets.size
  const migratedPrevious = completedJobs.filter((job: any) => range.days && plannerDateMs(job.completed_at || job.updated_at) >= window.previousStart && plannerDateMs(job.completed_at || job.updated_at) < window.start).length
  const highPriorityAssets = scopedCandidates.filter((row) => row.risk >= 70).length
  const previousHigh = previousCandidates.filter((row) => row.risk >= 70).length
  const riskReduced = Math.round(Math.min(100, ((completedJobs.length + pqcReadyAssets.size) / Math.max(1, candidates.length + completedJobs.length)) * 100))
  const previousRiskReduced = Math.round(Math.min(100, (migratedPrevious / Math.max(1, previousCandidates.length + migratedPrevious)) * 100))
  const totalJobs = Math.max(1, (jobs || []).length)
  const overallProgress = Math.round(((jobs || []).reduce((sum: number, job: any) => sum + clampProgress(job.progress, normalizeStatus(job.status)), 0) / totalJobs) || riskReduced)
  const remaining = Math.max(0, highPriorityAssets + scopedCandidates.length - completedJobs.length)
  const estimate = new Date(Date.now() + Math.max(7, remaining * 2) * 86400000)

  const topAssets = scopedCandidates.slice(0, 12)
  const priorityLabels = ['Critical', 'High', 'Medium', 'Low']
  const priorityDistribution = priorityLabels.map((label) => {
    const value = scopedCandidates.filter((row) => row.priority === label).length
    return {
      name: label,
      value,
      percent: `${Math.round((value / Math.max(1, scopedCandidates.length)) * 100)}%`,
      color: label === 'Critical' ? '#ef4444' : label === 'High' ? '#f97316' : label === 'Medium' ? '#eab308' : '#10b981',
    }
  })

  const roadmapSteps = [
    { name: 'DISCOVER', progress: activeAssets.length ? 100 : 0, status: activeAssets.length ? 'completed' : 'pending' },
    { name: 'ASSESS', progress: activeAssets.length ? Math.round(((inventory || []).length + (exposures || []).length ? 100 : 35)) : 0, status: (inventory || []).length || (exposures || []).length ? 'completed' : activeAssets.length ? 'active' : 'pending' },
    { name: 'PLAN', progress: Math.min(100, Math.max(0, topAssets.length ? 85 : activeJobs.length ? 70 : 20)), status: activeJobs.length || topAssets.length ? 'active' : 'pending' },
    { name: 'EXECUTE', progress: overallProgress, status: runningJobs.length ? 'active' : completedJobs.length ? 'completed' : activeJobs.length ? 'active' : 'pending' },
    { name: 'VALIDATE', progress: Math.round(Math.min(100, (complianceEvidence || []).length ? 80 : riskReduced / 2)), status: (complianceEvidence || []).length ? 'active' : 'pending' },
    { name: 'COMPLETE', progress: riskReduced >= 90 && failedJobs.length === 0 ? 100 : riskReduced, status: riskReduced >= 90 && failedJobs.length === 0 ? 'completed' : 'pending' },
  ]

  const latestActivity = [
    ...(jobs || []).map((job: any) => job.updated_at || job.completed_at || job.created_at),
    ...(migrationPlans || []).map((plan: any) => plan.updated_at || plan.created_at),
    ...(planConfigurations || []).map((config: any) => config.updated_at || config.created_at),
    ...(migrationTasks || []).map((task: any) => task.updated_at || task.created_at),
    ...(migrationAuditLogs || []).map((log: any) => log.created_at),
    ...(migrationEvents || []).map((event: any) => event.created_at),
    ...(scanSessions || []).map((scan: any) => scan.completed_at || scan.started_at || scan.created_at),
  ].map(plannerDateMs).filter(Boolean).sort((a, b) => b - a)[0] || 0

  return {
    generatedAt: new Date().toISOString(),
    range,
    source: {
      latestActivityAt: latestActivity ? new Date(latestActivity).toISOString() : null,
      latestScanAt: (scanSessions || [])[0]?.completed_at || (scanSessions || [])[0]?.started_at || (scanSessions || [])[0]?.created_at || null,
      tables: {
        assets: assets.length,
        crypto_inventory: inventory.length,
        crypto_exposures: exposures.length,
        migration_jobs: jobs.length,
        migration_plans: migrationPlans.length,
        migration_plan_configurations: planConfigurations.length,
        migration_scope: migrationScope.length,
        migration_assets: migrationAssets.length,
        migration_tasks: migrationTasks.length,
        migration_controls: migrationControls.length,
        migration_audit_logs: migrationAuditLogs.length,
        migration_events: migrationEvents.length,
        pqc_scan_sessions: scanSessions.length,
        pqc_scan_results: scanResults.length,
        runtime_crypto_events: runtimeEvents.length,
        certificates: certificates.length,
        compliance_evidence: complianceEvidence.length,
      },
    },
    metrics: {
      overallProgress,
      assetsInScope: activeAssets.length || currentAssets,
      assetsInScopeDelta: plannerDelta(currentAssets, previousCandidates.length).label,
      migratedAssets: migratedCurrent,
      migratedDelta: plannerDelta(migratedCurrent, migratedPrevious).label,
      highPriorityAssets,
      highPriorityDelta: plannerDelta(highPriorityAssets, previousHigh).label,
      riskReduced,
      riskReducedDelta: plannerDelta(riskReduced, previousRiskReduced).label,
      estimatedCompletion: plannerFormatDate(estimate.toISOString()),
      remainingDays: Math.max(7, remaining * 2),
      activeJobs: activeJobs.length,
      runningJobs: runningJobs.length,
      failedJobs: failedJobs.length,
      completedJobs: completedJobs.length,
    },
    roadmapSteps,
    priorityDistribution,
    topAssets,
    timelinePhases: plannerPhases(),
    riskTrendPoints: plannerRiskTrend(scopedCandidates, jobs, range),
    simulation: {
      confidence: Math.min(99, 72 + Math.min(20, topAssets.length * 2) + (scanSessions.length ? 5 : 0)),
      recommendations: topAssets.slice(0, 3).map((asset) => ({
        title: `Migrate ${asset.name} to ${asset.targetSolution}`,
        detail: `${asset.priority} priority, ${asset.risk}/100 crypto risk, owner ${asset.owner}.`,
      })),
    },
    compliance: {
      nistPqc: riskReduced,
      policyEvidence: complianceEvidence.length,
      quantumReadyAssets: pqcReadyAssets.size,
      openBlockers: failedJobs.length + highPriorityAssets,
    },
  }
}

function plannerAssetFromInput(value: unknown) {
  const record = asRecord(value)
  const assetId = pickString(record, ['assetId', 'asset_id', 'id'])
  if (!assetId) return null
  const name = pickString(record, ['name', 'assetName', 'asset_name']) || 'Selected cryptographic asset'
  const type = pickString(record, ['type', 'assetType', 'asset_type']) || 'Service'
  const environment = pickString(record, ['environment', 'env']) || 'tenant scope'
  const owner = pickString(record, ['owner', 'serviceOwner', 'service_owner']) || 'Unassigned'
  const currentAlgorithm = pickString(record, ['currentAlgorithm', 'sourceAlgorithm', 'algorithm']) || 'Classical crypto'
  const risk = Math.max(0, Math.min(100, Math.round(Number(record.risk || record.riskScore || 0) || 0)))
  const targetSolution = pickString(record, ['targetSolution', 'targetAlgorithm', 'target_algorithm']) || plannerReplacement(currentAlgorithm, `${type} ${name}`)
  const priority = pickString(record, ['priority']) || plannerPriority(risk)
  const status = pickString(record, ['status']) || 'Planned'
  const progress = Math.max(0, Math.min(100, Math.round(Number(record.progress || 0) || 0)))
  return {
    id: pickString(record, ['id']) || assetId,
    assetId,
    name,
    type,
    environment,
    owner,
    currentAlgorithm,
    risk,
    priority,
    priorityColor: pickString(record, ['priorityColor']) || plannerPriorityClass(priority),
    targetSolution,
    status,
    statusColor: pickString(record, ['statusColor']) || plannerStatusClass(status),
    progress,
    detectedAt: pickString(record, ['detectedAt', 'detected_at', 'createdAt', 'updatedAt']) || new Date().toISOString(),
    hasActiveJob: record.hasActiveJob === true,
    jobId: pickString(record, ['jobId', 'job_id']) || null,
  }
}

function buildPlannerHandoffSnapshot(rawRange: unknown, selectedAssets: any[]): Awaited<ReturnType<typeof buildMigrationPlannerSnapshot>> {
  const range = plannerRange(rawRange)
  const now = new Date().toISOString()
  const topAssets = selectedAssets.slice(0, 50)
  const highPriorityAssets = topAssets.filter((asset) => Number(asset.risk || 0) >= 70).length
  const completedJobs = topAssets.filter((asset) => Number(asset.progress || 0) >= 100).length
  const riskReduced = topAssets.length ? Math.round((completedJobs / topAssets.length) * 100) : 0
  const remainingDays = Math.max(1, topAssets.length * 2)
  const priorityLabels = ['Critical', 'High', 'Medium', 'Low']

  return {
    generatedAt: now,
    range,
    source: {
      latestActivityAt: now,
      latestScanAt: null,
      tables: {
        assets: topAssets.length,
        crypto_inventory: 0,
        crypto_exposures: 0,
        migration_jobs: 0,
        migration_plans: 0,
        migration_plan_configurations: 0,
        migration_scope: 0,
        migration_assets: 0,
        migration_tasks: 0,
        migration_controls: 0,
        migration_audit_logs: 0,
        migration_events: 0,
        pqc_scan_sessions: 0,
        pqc_scan_results: 0,
        runtime_crypto_events: 0,
        certificates: 0,
        compliance_evidence: 0,
      },
    },
    metrics: {
      overallProgress: 0,
      assetsInScope: topAssets.length,
      assetsInScopeDelta: '0',
      migratedAssets: completedJobs,
      migratedDelta: '0',
      highPriorityAssets,
      highPriorityDelta: '0',
      riskReduced,
      riskReducedDelta: '0',
      estimatedCompletion: plannerFormatDate(new Date(Date.now() + remainingDays * 86400000).toISOString()),
      remainingDays,
      activeJobs: 0,
      runningJobs: 0,
      failedJobs: 0,
      completedJobs,
    },
    roadmapSteps: [
      { name: 'DISCOVER', progress: 100, status: 'completed' },
      { name: 'ASSESS', progress: 100, status: 'completed' },
      { name: 'PLAN', progress: 90, status: 'active' },
      { name: 'EXECUTE', progress: 0, status: 'pending' },
      { name: 'VALIDATE', progress: 0, status: 'pending' },
      { name: 'COMPLETE', progress: 0, status: 'pending' },
    ],
    priorityDistribution: priorityLabels.map((label) => {
      const value = topAssets.filter((asset) => asset.priority === label).length
      return {
        name: label,
        value,
        percent: `${Math.round((value / Math.max(1, topAssets.length)) * 100)}%`,
        color: label === 'Critical' ? '#ef4444' : label === 'High' ? '#f97316' : label === 'Medium' ? '#eab308' : '#10b981',
      }
    }),
    topAssets,
    timelinePhases: plannerPhases(),
    riskTrendPoints: [],
    simulation: {
      confidence: Math.min(99, 80 + Math.min(12, topAssets.length * 2)),
      recommendations: topAssets.slice(0, 3).map((asset) => ({
        title: `Simulate ${asset.name} in Migration Sandbox`,
        detail: `${asset.priority} priority, ${asset.risk}/100 crypto risk, owner ${asset.owner}.`,
      })),
    },
    compliance: {
      nistPqc: riskReduced,
      policyEvidence: 0,
      quantumReadyAssets: completedJobs,
      openBlockers: highPriorityAssets,
    },
  }
}

function buildPlannerCsv(snapshot: Awaited<ReturnType<typeof buildMigrationPlannerSnapshot>>) {
  const escape = (value: unknown) => {
    const text = String(value ?? '')
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }
  const rows = [
    ['asset', 'type', 'environment', 'owner', 'current_algorithm', 'target_solution', 'risk', 'priority', 'status', 'progress'],
    ...snapshot.topAssets.map((asset: any) => [
      asset.name,
      asset.type,
      asset.environment,
      asset.owner,
      asset.currentAlgorithm,
      asset.targetSolution,
      asset.risk,
      asset.priority,
      asset.status,
      asset.progress,
    ]),
  ]
  return rows.map((row) => row.map(escape).join(',')).join('\n')
}

function scenarioRecommendation(snapshot: Awaited<ReturnType<typeof buildMigrationPlannerSnapshot>>, targetMode: string, optimization: string) {
  const mode = targetMode === 'pure' ? 'Pure quantum-safe' : targetMode === 'dual' ? 'Dual-key legacy bridge' : 'Hybrid classical + PQC'
  const optimizationLabel = optimization === 'latency' ? 'minimum latency' : optimization === 'cost' ? 'cost optimized' : 'highest risk first'
  const ordered = [...snapshot.topAssets].sort((a: any, b: any) => {
    if (optimization === 'latency') return a.type.localeCompare(b.type) || b.risk - a.risk
    if (optimization === 'cost') return a.progress - b.progress || b.risk - a.risk
    return b.risk - a.risk
  })
  const selected = ordered.slice(0, 5)
  const averageRisk = selected.length ? Math.round(selected.reduce((sum: number, item: any) => sum + item.risk, 0) / selected.length) : 0
  return {
    mode,
    optimization: optimizationLabel,
    confidence: snapshot.simulation.confidence,
    estimatedDuration: selected.length ? `${Math.max(1, selected.length * 2)}-${Math.max(2, selected.length * 4)} days` : 'Awaiting assets',
    riskMitigation: Math.min(98, Math.max(snapshot.metrics.riskReduced, averageRisk)),
    assets: selected,
    recommendations: selected.map((asset: any) => ({
      title: `${asset.name}: ${asset.targetSolution}`,
      detail: `${mode} plan using ${optimizationLabel}; current ${asset.currentAlgorithm}, risk ${asset.risk}/100.`,
    })),
    playbook: [
      'Confirm owner and blast radius for selected assets.',
      `Apply ${mode.toLowerCase()} rollout pattern with ${optimizationLabel} scheduling.`,
      'Run migration sandbox compatibility tests before production cutover.',
      'Export audit evidence to compliance and migration timeline after validation.',
    ],
  }
}

function plannerAction(raw: unknown): PlannerAction {
  const value = String(raw || 'save').toLowerCase()
  if (value === 'export') return 'export'
  if (value === 'schedule') return 'schedule'
  if (value === 'start') return 'start'
  if (['sandbox', 'send_to_sandbox', 'migration_sandbox'].includes(value)) return 'sandbox'
  return 'save'
}

function planStatusForAction(action: PlannerAction) {
  if (action === 'schedule') return 'scheduled'
  if (action === 'start') return 'awaiting_agent'
  if (action === 'export' || action === 'sandbox') return 'approved'
  return 'draft'
}

function normalizePlannerConfiguration(raw: unknown) {
  const config = asRecord(raw)
  const controls = asRecord(config.controls)
  const currentAlgorithms = uniqueStrings(asStringArray(config.currentAlgorithms), PLANNER_CURRENT_ALGORITHMS)
  const targetAlgorithms = uniqueStrings([...asStringArray(config.targetAlgorithms), ...PLANNER_TARGET_ALGORITHMS], PLANNER_TARGET_ALGORITHMS)
  const tags = uniqueStrings(asStringArray(config.tags).map(normalizePlanTag).filter(Boolean), [])
  return {
    currentAlgorithms,
    targetAlgorithms,
    deploymentStrategy: pickString(config, ['deploymentStrategy', 'strategy']) || 'Staged Rollout',
    controls: {
      rollback: controls.rollback !== false,
      validation: controls.validation !== false,
      compatibility: controls.compatibility !== false,
      hybridMode: controls.hybridMode !== false,
      continuousMonitoring: controls.continuousMonitoring !== false,
      complianceValidation: controls.complianceValidation !== false,
    },
    scheduleAt: pickString(config, ['scheduleAt', 'scheduledAt']) || null,
    tags,
    notes: pickString(config, ['notes']) || '',
  }
}

function estimatePlanDuration(assetCount: number, strategy: string) {
  const multiplier = /full/i.test(strategy) ? 3 : /department|environment/i.test(strategy) ? 2 : /pilot/i.test(strategy) ? 1 : 2
  const days = Math.max(1, assetCount * multiplier)
  return days === 1 ? '1 day' : `${days}-${days + Math.max(2, assetCount)} days`
}

function estimateDowntime(strategy: string, controls: Record<string, unknown>) {
  if (controls.hybridMode) return 'Near-zero with hybrid cutover'
  if (/full/i.test(strategy)) return 'Maintenance window required'
  if (/pilot|staged|department|environment/i.test(strategy)) return 'Rolling service windows'
  return 'To be validated'
}

function complexityScore(assets: any[], configuration: Record<string, unknown>) {
  const averageRisk = assets.length ? assets.reduce((sum, asset) => sum + Number(asset.risk || 0), 0) / assets.length : 0
  const strategy = String(configuration.deploymentStrategy || '')
  const strategyWeight = /full/i.test(strategy) ? 20 : /department|environment/i.test(strategy) ? 14 : /staged/i.test(strategy) ? 10 : 6
  const targetCount = asStringArray(configuration.targetAlgorithms).length
  return Math.max(0, Math.min(100, Math.round(averageRisk * 0.62 + assets.length * 2 + strategyWeight + targetCount * 2)))
}

function buildPlanPayload({
  planId,
  action,
  selectedAssets,
  configuration,
  snapshot,
  jobs,
  now,
}: {
  planId: string
  action: PlannerAction
  selectedAssets: any[]
  configuration: Record<string, unknown>
  snapshot: Awaited<ReturnType<typeof buildMigrationPlannerSnapshot>>
  jobs: any[]
  now: string
}): MigrationPlanPayload {
  const highRiskAssets = selectedAssets.filter((asset) => Number(asset.risk || 0) >= 70).length
  const pqcReadyAssets = selectedAssets.filter((asset) => /ready|completed/i.test(`${asset.status || ''}`) || Number(asset.progress || 0) >= 100).length
  const nonCompliantAssets = selectedAssets.filter((asset) => !/ready|completed/i.test(`${asset.status || ''}`) && Number(asset.risk || 0) >= 50).length
  const controls = asRecord(configuration.controls)
  const strategyPhases = Array.isArray(configuration.strategyPhases) ? configuration.strategyPhases : []
  const score = complexityScore(selectedAssets, configuration)
  const status = planStatusForAction(action)

  return {
    id: planId,
    status,
    action,
    selectedAssets,
    configuration,
    riskData: {
      currentRiskScore: selectedAssets.length ? Math.round(selectedAssets.reduce((sum, asset) => sum + Number(asset.risk || 0), 0) / selectedAssets.length) : 0,
      projectedRiskReduction: Math.max(snapshot.metrics.riskReduced, Math.round(Math.min(96, score * 0.78))),
      hndlExposure: highRiskAssets,
      complianceImpact: nonCompliantAssets > 0 ? 'Material compliance risk reduction expected' : 'No non-compliant selected assets detected',
      migrationComplexityScore: score,
      highRiskAssets,
      pqcReadyAssets,
      nonCompliantAssets,
      tagInfluenceScore: selectedAssets.reduce((sum, asset) => sum + tagPriorityBoost(asset, configuration), 0),
      currentAlgorithmScopeMatches: selectedAssets.filter((asset) => asset.currentAlgorithmInScope !== false).length,
    },
    migrationMetadata: {
      planId,
      createdBy: 'migration-planner',
      createdAt: now,
      status,
      action,
      estimatedDuration: estimatePlanDuration(selectedAssets.length, String(configuration.deploymentStrategy || '')),
      expectedDowntime: estimateDowntime(String(configuration.deploymentStrategy || ''), controls),
      rollbackAvailable: controls.rollback !== false,
      range: snapshot.range.key,
      totalAssets: selectedAssets.length,
      selectedAssets,
      strategyPhases,
      currentAlgorithms: asStringArray(configuration.currentAlgorithms, PLANNER_CURRENT_ALGORITHMS),
      targetAlgorithms: asStringArray(configuration.targetAlgorithms, PLANNER_TARGET_ALGORITHMS),
      mandatoryPqcStack: MANDATORY_PQC_STACK,
      cryptographicStack: mandatoryPqcStackMetadata(
        asStringArray(configuration.targetAlgorithms, PLANNER_TARGET_ALGORITHMS)[0],
        'migration plan',
      ),
      controls,
      tags: asStringArray(configuration.tags),
      sourceTables: snapshot.source.tables,
      sandboxUrl: `/dashboard/migration-sandbox?planId=${encodeURIComponent(planId)}&source=migration-planner`,
    },
    jobs,
    createdAt: now,
    updatedAt: now,
    orchestrationUrl: `/dashboard/pqc-orchestration?planId=${encodeURIComponent(planId)}`,
    liveMigrationUrl: `/dashboard/live-migration?planId=${encodeURIComponent(planId)}`,
    sandboxUrl: `/dashboard/migration-sandbox?planId=${encodeURIComponent(planId)}&source=migration-planner`,
  }
}

async function upsertPlannerRows(client: any, table: string, rows: any[], onConflict?: string) {
  if (!rows.length) return
  const query = client.from(table).upsert(rows, onConflict ? { onConflict } : undefined)
  const { error } = await query
  if (error && isMissingTable(error)) {
    console.warn(`[migration-planner] ${table} table is missing; planner details remained in migration_plans metadata.`)
    return
  }
  if (error) throw error
}

async function insertPlannerRows(client: any, table: string, rows: any[]) {
  if (!rows.length) return
  const { error } = await client.from(table).insert(rows)
  if (error && isMissingTable(error)) {
    console.warn(`[migration-planner] ${table} table is missing; planner audit detail was skipped.`)
    return
  }
  if (error) throw error
}

function planJobForAsset(plan: MigrationPlanPayload, asset: any) {
  const assetId = String(asset.assetId || asset.id || '')
  return (plan.jobs || []).find((job: any) => {
    const metadata = asRecord(job?.metadata)
    return String(job?.asset_id || metadata.assetId || '') === assetId || String(metadata.assetName || '') === String(asset.name || '')
  })
}

async function persistMigrationPlan(client: any, userId: string, plan: MigrationPlanPayload) {
  const row = {
    id: plan.id,
    user_id: userId,
    status: plan.status,
    selected_asset_ids: plan.selectedAssets.map((asset) => asset.assetId || asset.id).filter(Boolean),
    configuration: plan.configuration,
    risk_data: plan.riskData,
    metadata: plan.migrationMetadata,
    created_at: plan.createdAt,
    updated_at: plan.updatedAt,
    approved_at: ['start', 'export', 'sandbox'].includes(plan.action) ? plan.updatedAt : null,
    scheduled_at: pickString(plan.configuration, ['scheduleAt']) || null,
  }
  const { error } = await client.from('migration_plans').upsert(row)
  if (error && !isMissingTable(error)) throw error
  if (error && isMissingTable(error)) console.warn('[migration-planner] migration_plans table is missing; plan persisted through job metadata and events only.')

  const controls = asRecord(plan.configuration.controls)
  const phases = Array.isArray(plan.configuration.strategyPhases) ? plan.configuration.strategyPhases : []
  const tags = asStringArray(plan.configuration.tags)
  const now = plan.updatedAt

  await upsertPlannerRows(client, 'migration_plan_configurations', [{
    plan_id: plan.id,
    user_id: userId,
    current_algorithms: asStringArray(plan.configuration.currentAlgorithms, PLANNER_CURRENT_ALGORITHMS),
    target_algorithms: asStringArray(plan.configuration.targetAlgorithms, PLANNER_TARGET_ALGORITHMS),
    deployment_strategy: String(plan.configuration.deploymentStrategy || 'Staged Rollout'),
    controls,
    tags,
    schedule_at: pickString(plan.configuration, ['scheduleAt']) || null,
    notes: pickString(plan.configuration, ['notes']) || '',
    metadata: {
      source: 'migration-planner',
      status: plan.status,
      action: plan.action,
      riskData: plan.riskData,
      orchestrationUrl: plan.orchestrationUrl,
      liveMigrationUrl: plan.liveMigrationUrl,
      sandboxUrl: plan.sandboxUrl,
    },
    created_at: plan.createdAt,
    updated_at: now,
  }], 'plan_id,user_id')

  await upsertPlannerRows(client, 'migration_scope', [
    {
      plan_id: plan.id,
      user_id: userId,
      scope_type: 'deployment_strategy',
      scope_value: String(plan.configuration.deploymentStrategy || 'Staged Rollout'),
      asset_count: plan.selectedAssets.length,
      priority_score: Number(plan.riskData.migrationComplexityScore || 0),
      metadata: { phases, tags, source: 'migration-planner' },
      updated_at: now,
    },
    ...phases.map((phase: any) => ({
      plan_id: plan.id,
      user_id: userId,
      scope_type: 'phase',
      scope_value: String(phase.name || `Phase ${phase.phaseIndex || 1}`),
      asset_count: Number(phase.assetCount || 0),
      priority_score: Number(phase.phaseIndex || 1),
      metadata: { ...phase, source: 'migration-planner' },
      updated_at: now,
    })),
    ...tags.map((tag) => ({
      plan_id: plan.id,
      user_id: userId,
      scope_type: 'asset_tag',
      scope_value: tag,
      asset_count: plan.selectedAssets.filter((asset) => plannerAssetTags(asset, plan.configuration).some((assetTag) => matchesToken(assetTag, tag))).length,
      priority_score: 0,
      metadata: { tag, source: 'migration-planner' },
      updated_at: now,
    })),
  ], 'plan_id,user_id,scope_type,scope_value')

  await upsertPlannerRows(client, 'migration_assets', plan.selectedAssets.map((asset) => ({
    plan_id: plan.id,
    user_id: userId,
    asset_id: String(asset.assetId || asset.id),
    asset_name: String(asset.name || 'Unnamed asset'),
    asset_type: String(asset.type || 'Service'),
    environment: String(asset.environment || 'tenant scope'),
    owner: String(asset.owner || 'Unassigned'),
    current_algorithm: String(asset.currentAlgorithm || 'Classical'),
    target_algorithm: mandatoryPqcTargetForContext(
      asset.targetSolution || configuredTargetAlgorithm(asset, plan.configuration),
      `${asset.currentAlgorithm || ''} ${asset.type || ''} ${asset.name || ''}`,
    ),
    priority: String(asset.priority || 'Medium'),
    risk_score: Math.round(Number(asset.risk || 0)),
    readiness_status: String(asset.status || 'Planned'),
    tags: plannerAssetTags(asset, plan.configuration),
    phase_index: Number(asset.phaseIndex || 1),
    sequence_order: Number(asset.sequenceOrder || 1),
    metadata: {
      source: 'migration-planner',
      currentAlgorithmInScope: asset.currentAlgorithmInScope !== false,
      riskPriorityScore: Number(asset.riskPriorityScore || 0),
      phaseName: asset.phaseName,
      scopeKey: asset.scopeKey,
      gateRequired: Boolean(asset.gateRequired),
      mandatoryPqcStack: MANDATORY_PQC_STACK,
      cryptographicStack: mandatoryPqcStackMetadata(
        asset.targetSolution || asset.currentAlgorithm,
        `${asset.type || ''} ${asset.name || ''}`,
      ),
    },
    created_at: plan.createdAt,
    updated_at: now,
  })), 'plan_id,user_id,asset_id')

  await upsertPlannerRows(client, 'migration_tasks', plan.selectedAssets.map((asset) => {
    const job = planJobForAsset(plan, asset)
    return {
      plan_id: plan.id,
      user_id: userId,
      migration_job_id: job?.id || null,
      asset_id: String(asset.assetId || asset.id),
      task_type: plannerJobType(asset),
      phase_index: Number(asset.phaseIndex || 1),
      sequence_order: Number(asset.sequenceOrder || 1),
      status: String(job?.status || (plan.action === 'start' && asset.startsOnApproval ? 'queued' : 'pending')),
      target_algorithm: mandatoryPqcTargetForContext(
        asset.targetSolution || configuredTargetAlgorithm(asset, plan.configuration),
        `${asset.currentAlgorithm || ''} ${asset.type || ''} ${asset.name || ''}`,
      ),
      controls,
      telemetry: {
        planValidation: true,
        databasePersistence: true,
        orchestrationPrepared: true,
        eventBroadcastRegistered: true,
        realtimeRefreshTables: ['migration_plans', 'migration_tasks', 'migration_events', 'deployment_packages', 'execution_queues', 'migration_execution', 'migration_telemetry', 'migration_validation_logs'],
      },
      metadata: {
        source: 'migration-planner',
        planAction: plan.action,
        phaseName: asset.phaseName,
        deploymentStrategy: plan.configuration.deploymentStrategy,
        tags: plannerAssetTags(asset, plan.configuration),
        mandatoryPqcStack: MANDATORY_PQC_STACK,
        cryptographicStack: mandatoryPqcStackMetadata(
          asset.targetSolution || asset.currentAlgorithm,
          `${asset.type || ''} ${asset.name || ''}`,
        ),
      },
      created_at: plan.createdAt,
      updated_at: now,
    }
  }), 'plan_id,user_id,asset_id,task_type')

  await upsertPlannerRows(client, 'migration_controls', Object.entries(PLANNER_CONTROL_LABELS).map(([key, label]) => ({
    plan_id: plan.id,
    user_id: userId,
    control_key: key,
    label,
    enabled: controls[key] !== false,
    enforced_at: now,
    metadata: {
      source: 'migration-planner',
      enforcement: controls[key] !== false ? 'active' : 'disabled_by_operator',
      affects: key === 'rollback'
        ? ['orchestration', 'rollback_actions', 'audit_logs']
        : key === 'compatibility'
          ? ['migration_tasks', 'validation_events', 'live_migration']
          : key === 'complianceValidation'
            ? ['compliance_evidence', 'audit_logs', 'reports']
            : ['migration_tasks', 'telemetry', 'dashboards'],
    },
    created_at: plan.createdAt,
    updated_at: now,
  })), 'plan_id,user_id,control_key')

  await insertPlannerRows(client, 'migration_audit_logs', [
    {
      plan_id: plan.id,
      user_id: userId,
      action: `plan_${plan.action}`,
      stage: 'end_to_end_creation',
      result: 'success',
      details: {
        source: 'migration-planner',
        pipeline: [
          'plan_validation',
          'database_persistence',
          'plan_generation',
          'task_generation',
          'orchestration_preparation',
          'telemetry_registration',
          'event_broadcasting',
          'ui_refresh',
        ],
        selectedAssets: plan.selectedAssets.length,
        configuration: plan.configuration,
        riskData: plan.riskData,
      },
      created_at: now,
    },
  ])

  await insertPlannerRows(client, 'audit_logs', [
    {
      user_id: userId,
      action: `migration_plan_${plan.action}`,
      entity_type: 'migration_plan',
      entity_id: null,
      details: {
        planId: plan.id,
        status: plan.status,
        selectedAssets: plan.selectedAssets.length,
        configuration: plan.configuration,
        orchestrationUrl: plan.orchestrationUrl,
        liveMigrationUrl: plan.liveMigrationUrl,
        sandboxUrl: plan.sandboxUrl,
      },
      created_at: now,
    },
  ])

  if (controls.complianceValidation !== false) {
    await insertPlannerRows(client, 'compliance_evidence', [
      {
        user_id: userId,
        framework: 'NIST PQC Migration',
        control_id: 'MIGRATION_PLAN_CONFIGURATION',
        evidence_type: 'migration_plan',
        description: `Migration plan ${plan.id} captured algorithm, rollout, control, scope, and telemetry configuration for ${plan.selectedAssets.length} asset(s).`,
        status: 'complete',
        metadata: {
          source: 'migration-planner',
          planId: plan.id,
          configuration: plan.configuration,
          riskData: plan.riskData,
          selectedAssetIds: plan.selectedAssets.map((asset) => asset.assetId || asset.id).filter(Boolean),
        },
        created_at: now,
        updated_at: now,
      },
    ])
  }
}

async function fetchPlanJobs(client: any, userId: string, planId: string) {
  const rows = await safeRows(client, 'migration_jobs', userId, (q) => q
    .select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at')
    .order('updated_at', { ascending: false })
    .limit(1200))
  return rows.filter((row: any) => matchesPlanId(row, planId))
}

async function loadMigrationPlan(client: any, userId: string, planId: string): Promise<MigrationPlanPayload | null> {
  let planRow: any = null
  let result: any = null
  try {
    result = await client
      .from('migration_plans')
      .select('id, status, selected_asset_ids, configuration, risk_data, metadata, created_at, updated_at, approved_at, scheduled_at')
      .eq('user_id', userId)
      .eq('id', planId)
      .limit(1)
  } catch (error: any) {
    console.warn('[migration-planner] Plan row lookup failed; falling back to migration job metadata:', error?.message || error)
  }
  if (result && !result.error) planRow = result.data?.[0] || null
  if (result?.error && !isMissingTable(result.error)) throw result.error

  const jobs = await fetchPlanJobs(client, userId, planId)
  if (!planRow && !jobs.length) return null

  const firstMetadata = asRecord(jobs[0]?.metadata)
  const configuration = asRecord(planRow?.configuration || firstMetadata.configuration || firstMetadata.migrationConfiguration)
  const riskData = asRecord(planRow?.risk_data || firstMetadata.riskData)
  const migrationMetadata = asRecord(planRow?.metadata || firstMetadata.plan || firstMetadata.migrationPlan)
  const now = new Date().toISOString()
  const selectedAssets = Array.isArray(migrationMetadata.selectedAssets)
    ? migrationMetadata.selectedAssets
    : jobs.map((job: any) => {
        const metadata = asRecord(job.metadata)
        return {
          id: job.asset_id || job.id,
          assetId: job.asset_id || null,
          name: pickString(metadata, ['assetName']) || String(job.name || '').replace(/^PQC Migration:\s*/i, '') || job.id,
          type: pickString(metadata, ['assetType']) || 'Service',
          environment: pickString(metadata, ['environment']) || 'Unknown',
          owner: pickString(metadata, ['owner']) || 'Unassigned',
          currentAlgorithm: pickString(metadata, ['sourceAlgorithm']) || 'Classical',
          targetSolution: job.target_algorithm || pickString(metadata, ['targetAlgorithm']) || 'PQC target pending',
          risk: Number(metadata.riskScore || 0),
          priority: pickString(metadata, ['priority']) || 'Medium',
          status: job.status,
          progress: Number(job.progress || 0),
        }
      })

  return {
    id: planId,
    status: String(planRow?.status || migrationMetadata.status || firstMetadata.planStatus || 'approved'),
    action: plannerAction(migrationMetadata.action || firstMetadata.planAction || 'start'),
    selectedAssets,
    configuration,
    riskData,
    migrationMetadata,
    jobs,
    createdAt: planRow?.created_at || String(migrationMetadata.createdAt || jobs[0]?.created_at || now),
    updatedAt: planRow?.updated_at || String(migrationMetadata.updatedAt || jobs[0]?.updated_at || now),
    orchestrationUrl: `/dashboard/pqc-orchestration?planId=${encodeURIComponent(planId)}`,
    liveMigrationUrl: `/dashboard/live-migration?planId=${encodeURIComponent(planId)}`,
    sandboxUrl: `/dashboard/migration-sandbox?planId=${encodeURIComponent(planId)}&source=migration-planner`,
  }
}

function jobPhaseIndex(job: any) {
  const execution = asRecord(asRecord(job?.metadata).execution)
  const direct = Number(execution.phaseIndex || asRecord(job?.metadata).phaseIndex || 1)
  return Number.isFinite(direct) && direct > 0 ? Math.round(direct) : 1
}

function nextPhaseForAction(action: string, jobs: any[]) {
  const phases = Array.from(new Set(jobs.map(jobPhaseIndex))).sort((a, b) => a - b)
  if (!phases.length) return 1
  if (action === 'start_execution') return phases[0]
  if (action !== 'approve_next_phase') return null

  const active = jobs
    .filter((job) => ['running', 'completed', 'in_progress'].includes(String(job.status || '').toLowerCase()) || Number(job.progress || 0) > 0)
    .map(jobPhaseIndex)
  const highestActive = active.length ? Math.max(...active) : 0
  return phases.find((phase) => phase > highestActive) || phases[phases.length - 1]
}

function orchestrationActionUpdate(action: string, metadata: Record<string, unknown>, currentProgress: unknown, phaseToStart?: number | null) {
  const now = new Date().toISOString()
  const progress = Number(currentProgress || 0)
  const phaseApprovals = Array.isArray(metadata.phaseApprovals) ? metadata.phaseApprovals : []
  const execution = asRecord(metadata.execution)
  const phaseIndex = Number(execution.phaseIndex || 1)
  const phaseName = String(execution.phaseName || `Phase ${phaseIndex || 1}`)
  const nextMetadata: Record<string, unknown> = {
    ...metadata,
    lastOperatorAction: action,
    lastOperatorActionAt: now,
    orchestrationStage: action === 'start_execution' ? 'execution' : action === 'approve_next_phase' ? 'phase-approved' : action,
    phaseApprovals: action === 'approve_next_phase' ? [...phaseApprovals, now] : phaseApprovals,
    execution: {
      ...execution,
      phaseIndex,
      phaseName,
      sequenceState: phaseToStart && phaseIndex > phaseToStart ? 'waiting_for_prior_phase' : action === 'pause' ? 'paused' : action === 'rollback' ? 'rollback_requested' : 'waiting_for_agent',
      agentRequired: true,
      agentDispatchStatus: action === 'pause' ? 'paused' : action === 'rollback' ? 'rollback_requested' : 'queued_for_agent',
      lastPhaseDecisionAt: now,
    },
  }

  if ((action === 'start_execution' || action === 'approve_next_phase') && phaseToStart && phaseIndex > phaseToStart) {
    return { status: 'pending', updated_at: now, metadata: nextMetadata }
  }
  if ((action === 'start_execution' || action === 'approve_next_phase') && phaseToStart && phaseIndex < phaseToStart) {
    return { updated_at: now, metadata: nextMetadata }
  }
  if (action === 'start_execution') return { status: 'queued', progress: Math.max(0, progress), updated_at: now, metadata: nextMetadata }
  if (action === 'approve_next_phase') return { status: 'queued', progress: Math.max(0, progress), updated_at: now, metadata: nextMetadata }
  return actionUpdate(action, nextMetadata)
}

function actionUpdate(action: string, metadata: Record<string, unknown>, nextStatus?: string) {
  const now = new Date().toISOString()
  const nextMetadata: Record<string, unknown> = {
    ...metadata,
    lastOperatorAction: action,
    lastOperatorActionAt: now,
  }

  if (action === 'pause') return { status: 'paused', updated_at: now, metadata: nextMetadata }
  if (action === 'resume') return { status: 'queued', updated_at: now, metadata: { ...nextMetadata, execution: { ...asRecord(nextMetadata.execution), agentDispatchStatus: 'queued_for_agent', sequenceState: 'waiting_for_agent' } } }
  if (action === 'retry') return { status: 'queued', progress: 0, updated_at: now, metadata: { ...nextMetadata, execution: { ...asRecord(nextMetadata.execution), agentDispatchStatus: 'queued_for_agent', sequenceState: 'waiting_for_agent' } } }
  if (action === 'rollback') return { status: 'rollback_requested', updated_at: now, metadata: nextMetadata }
  if (nextStatus) return { status: nextStatus, updated_at: now, metadata: nextMetadata }
  return { updated_at: now, metadata: nextMetadata }
}

function actionMessage(action: string, jobName: string) {
  if (action === 'start_execution') return `Operator queued agent execution for migration job ${jobName}.`
  if (action === 'pause') return `Operator paused migration job ${jobName}.`
  if (action === 'resume') return `Operator re-queued migration job ${jobName} for agent execution.`
  if (action === 'retry') return `Operator re-queued failed migration job ${jobName} for agent execution.`
  if (action === 'rollback') return `Operator requested rollback for migration job ${jobName}.`
  if (action === 'approve_next_phase') return `Operator approved the next migration phase for agent execution on ${jobName}.`
  return `Operator action ${action} recorded for migration job ${jobName}.`
}

async function insertActionEvents(client: any, userId: string, jobs: any[], action: string) {
  if (!jobs.length) return
  const now = new Date().toISOString()
  const rows = jobs.map((job) => ({
    user_id: userId,
    migration_id: job.id,
    event_type: `operator-${action}`,
    severity: action === 'rollback' ? 'warning' : 'info',
    message: actionMessage(action, job.name || job.id),
    metadata: { action },
    created_at: now,
  }))
  const { error } = await client.from('migration_events').insert(rows)
  if (error && !isMissingTable(error)) console.warn('[migration-live] Action event insert failed:', error.message)
}

function jobDispatchPriority(job: any) {
  const metadata = asRecord(job?.metadata)
  const explicit = Number(metadata.riskPriorityScore || metadata.riskScore || metadata.priorityScore)
  if (Number.isFinite(explicit)) return Math.max(1, Math.min(100, Math.round(explicit)))
  const priority = String(metadata.priority || '').toLowerCase()
  if (priority === 'critical') return 95
  if (priority === 'high') return 80
  if (priority === 'medium') return 55
  return 35
}

async function persistExecutionDispatch(client: any, userId: string, plan: MigrationPlanPayload, jobs: any[], action: string, phaseToStart: number | null | undefined, now: string) {
  if (!['start', 'start_execution', 'resume', 'retry', 'approve_next_phase'].includes(action) || jobs.length === 0) return
  const controls = asRecord(plan.configuration.controls)
  const packageRows: any[] = []
  const orchestrationRows: any[] = []
  const queueRows: any[] = []

  for (const job of jobs) {
    const metadata = asRecord(job.metadata)
    const execution = asRecord(metadata.execution)
    const phaseIndex = Number(execution.phaseIndex || 1)
    const activePhase = !phaseToStart || phaseIndex <= phaseToStart
    const queueStatus = activePhase ? 'queued' : 'blocked'
    const targetStack = mandatoryPqcStackMetadata(
      job.target_algorithm || pickString(metadata, ['targetAlgorithm']) || pickString(metadata, ['sourceAlgorithm']),
      `${job.job_type || ''} ${job.name || ''} ${pickString(metadata, ['assetType', 'assetName'])}`,
    )
    const requiredCapabilities = [
      'pqc-migration',
      ...MANDATORY_PQC_REQUIRED_CAPABILITIES,
      controls.compatibility !== false ? 'compatibility-validation' : null,
      controls.continuousMonitoring !== false ? 'runtime-telemetry' : null,
      controls.rollback !== false ? 'rollback-capable' : null,
    ].filter((item): item is string => Boolean(item))

    packageRows.push({
      plan_id: plan.id,
      user_id: userId,
      migration_job_id: job.id,
      package_type: 'pqc_migration',
      action_type: String(job.job_type || pickString(metadata, ['migrationType', 'migration_type']) || 'pqc_migration'),
      target_algorithm: String(targetStack.targetAlgorithm),
      required_capabilities: requiredCapabilities,
      payload: {
        planId: plan.id,
        migrationJobId: job.id,
        assetId: job.asset_id || pickString(metadata, ['assetId']) || null,
        assetName: pickString(metadata, ['assetName']) || job.name,
        sourceAlgorithm: pickString(metadata, ['sourceAlgorithm']) || null,
        targetAlgorithm: targetStack.targetAlgorithm,
        mandatoryPqcStack: MANDATORY_PQC_STACK,
        cryptographicStack: targetStack,
        controls,
        execution,
      },
      status: activePhase ? 'ready' : 'waiting_for_prior_phase',
      metadata: {
        source: 'pqc-orchestration',
        action,
        dispatchState: queueStatus,
        phaseToStart,
        mandatoryPqcStack: MANDATORY_PQC_STACK,
        cryptographicStack: targetStack,
      },
      created_at: now,
      updated_at: now,
    })

    orchestrationRows.push({
      plan_id: plan.id,
      user_id: userId,
      migration_job_id: job.id,
      status: queueStatus,
      readiness: {
        agentRequired: true,
        packageReady: activePhase,
        validationRequired: controls.validation !== false,
        rollbackEnabled: controls.rollback !== false,
        phaseIndex,
        phaseToStart,
      },
      metadata: {
        source: 'pqc-orchestration',
        action,
        planStatus: plan.status,
        currentStep: activePhase ? 'Queued for agent claim' : 'Waiting for prior phase',
        mandatoryPqcStack: MANDATORY_PQC_STACK,
        cryptographicStack: targetStack,
      },
      created_at: now,
      updated_at: now,
    })

    queueRows.push({
      plan_id: plan.id,
      user_id: userId,
      migration_job_id: job.id,
      queue_status: queueStatus,
      priority: jobDispatchPriority(job),
      available_after: activePhase ? now : null,
      metadata: {
        source: 'pqc-orchestration',
        action,
        requiredCapabilities,
        phaseIndex,
        phaseToStart,
        mandatoryPqcStack: MANDATORY_PQC_STACK,
        cryptographicStack: targetStack,
      },
      created_at: now,
      updated_at: now,
    })
  }

  await upsertPlannerRows(client, 'deployment_packages', packageRows, 'plan_id,user_id,migration_job_id')
  await upsertPlannerRows(client, 'orchestration_jobs', orchestrationRows, 'plan_id,user_id,migration_job_id')
  await upsertPlannerRows(client, 'execution_queues', queueRows, 'plan_id,user_id,migration_job_id')
}

function dispatchPlanFromJob(job: any, now: string): MigrationPlanPayload | null {
  const metadata = asRecord(job?.metadata)
  const planRecord = asRecord(metadata.plan)
  const planId = pickString(metadata, ['planId']) || pickString(planRecord, ['id'])
  if (!planId) return null
  const selectedAssets = Array.isArray(planRecord.selectedAssets) ? planRecord.selectedAssets as any[] : []
  return {
    id: planId,
    status: 'awaiting_agent',
    action: 'start',
    selectedAssets,
    configuration: asRecord(metadata.configuration),
    riskData: asRecord(metadata.riskData),
    migrationMetadata: asRecord(metadata.migrationMetadata || metadata.plan),
    jobs: [job],
    createdAt: String(job.created_at || metadata.createdAt || now),
    updatedAt: now,
    orchestrationUrl: `/dashboard/pqc-orchestration?planId=${encodeURIComponent(planId)}`,
    liveMigrationUrl: `/dashboard/live-migration?planId=${encodeURIComponent(planId)}`,
    sandboxUrl: `/dashboard/migration-sandbox?planId=${encodeURIComponent(planId)}&source=migration-planner`,
  }
}

router.get('/planner', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const snapshot = await buildMigrationPlannerSnapshot(client, req.user!.id, req.query.range)
  res.json({ data: snapshot })
})

router.get('/planner/export', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const snapshot = await buildMigrationPlannerSnapshot(client, req.user!.id, req.query.range)
  const format = String(req.query.format || 'json').toLowerCase()
  const baseName = `qguard-migration-roadmap-${snapshot.range.key}-${new Date().toISOString().slice(0, 10)}`

  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', `attachment; filename="${baseName}.csv"`)
    return res.send(buildPlannerCsv(snapshot))
  }

  res.setHeader('Content-Type', 'application/json')
  res.setHeader('Content-Disposition', `attachment; filename="${baseName}.json"`)
  return res.send(JSON.stringify(snapshot, null, 2))
})

router.get('/planner/stream', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  sseHeaders(res)
  writeSse(res, 'planner-connected', { timestamp: new Date().toISOString() })

  const emitSnapshot = async () => {
    const snapshot = await buildMigrationPlannerSnapshot(client, req.user!.id, req.query.range)
    writeSse(res, 'planner-update', snapshot)
  }

  await emitSnapshot().catch((error) => console.warn('[migration-planner] Initial stream emit failed:', error?.message || error))
  const heartbeat = setInterval(() => writeSse(res, 'heartbeat', { ts: Date.now() }), 15000)
  const poll = setInterval(() => emitSnapshot().catch(() => undefined), 8000)

  req.on('close', () => {
    clearInterval(heartbeat)
    clearInterval(poll)
    res.end()
  })
})

router.post('/planner/scenario', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const targetMode = String(req.body?.targetMode || 'hybrid').toLowerCase()
  const optimization = String(req.body?.optimization || 'risk').toLowerCase()
  const snapshot = await buildMigrationPlannerSnapshot(client, req.user!.id, req.body?.range || req.query.range)
  const scenario = scenarioRecommendation(snapshot, targetMode, optimization)

  await client.from('migration_events').insert({
    user_id: req.user!.id,
    migration_id: null,
    event_type: 'planner-scenario-simulated',
    severity: 'info',
    message: `${scenario.mode} migration scenario simulated with ${scenario.optimization} optimization.`,
    metadata: {
      source: 'migration-planner',
      targetMode,
      optimization,
      confidence: scenario.confidence,
      assets: scenario.assets.map((asset: any) => asset.assetId || asset.id).filter(Boolean).slice(0, 25),
    },
    created_at: new Date().toISOString(),
  }).then(({ error }: any) => {
    if (error && !isMissingTable(error)) console.warn('[migration-planner] Scenario event insert failed:', error.message)
  })

  res.json({ data: scenario })
})

router.post('/planner/create', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const range = req.body?.range || req.query.range
  const action = plannerAction(req.body?.action)
  const limit = Math.max(1, Math.min(50, Number(req.body?.limit || 25)))
  const selectedIds = Array.isArray(req.body?.assetIds) ? new Set(req.body.assetIds.map((id: unknown) => String(id))) : null
  const now = new Date().toISOString()
  const planId = pickString(asRecord(req.body), ['planId', 'id']) || `planner-${Date.now()}`
  const baseConfiguration = normalizePlannerConfiguration(req.body?.configuration)
  const suppliedAssetActions: PlannerAction[] = ['start', 'sandbox']
  const suppliedAssets = suppliedAssetActions.includes(action) && Array.isArray(req.body?.selectedAssets)
    ? req.body.selectedAssets.map(plannerAssetFromInput).filter(Boolean).slice(0, limit)
    : []
  const tenantAssetIds = suppliedAssets.length
    ? new Set((await safeRows(client, 'assets', req.user!.id, (q) => q.select('id').in('id', suppliedAssets.map((asset: any) => asset.assetId)).limit(suppliedAssets.length))).map((asset: any) => String(asset.id)))
    : new Set<string>()
  const verifiedSuppliedAssets = suppliedAssets.filter((asset: any) => tenantAssetIds.has(String(asset.assetId)))
  const snapshot = verifiedSuppliedAssets.length
    ? buildPlannerHandoffSnapshot(range, verifiedSuppliedAssets)
    : await buildMigrationPlannerSnapshot(client, req.user!.id, range)

  const selectedAssetCandidates = (verifiedSuppliedAssets.length ? verifiedSuppliedAssets : snapshot.topAssets)
    .filter((asset: any) => asset.assetId)
    .filter((asset: any) => !selectedIds || selectedIds.has(String(asset.assetId)) || selectedIds.has(String(asset.id)))
    .slice(0, limit)

  if (!selectedAssetCandidates.length) {
    return res.status(400).json({ error: { code: 'NO_ASSETS', message: 'Select at least one discovered asset before creating a migration plan.' } })
  }

  const prepared = preparePlanAssets(selectedAssetCandidates, baseConfiguration)
  const selectedAssets = prepared.assets
  const configuration = {
    ...baseConfiguration,
    strategyPhases: prepared.phases,
    orchestrationRules: {
      strategy: baseConfiguration.deploymentStrategy,
      phaseCount: prepared.phases.length,
      startPolicy: action === 'start' ? 'start_first_phase_immediately' : 'prepare_for_orchestration',
      scopeRestriction: 'tenant_user_assets_only',
      tagPriorityBoost: asStringArray(baseConfiguration.tags).length > 0,
    },
  }

  const existing = action === 'sandbox'
    ? []
    : await safeRows(client, 'migration_jobs', req.user!.id, (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, created_at, updated_at').order('updated_at', { ascending: false }).limit(1200))
  const activeByAsset = new Map<string, any>(
    existing
      .filter((job: any) => {
        const metadata = asRecord(job.metadata)
        const executionMode = pickString(metadata, ['executionMode', 'runMode', 'mode']).toLowerCase()
        const jobType = String(job.job_type || '').toLowerCase()
        const sandboxJob = metadata.sandboxMode === true
          || ['sandbox_simulation', 'dry_run', 'simulation'].includes(executionMode)
          || /sandbox|simulation|dry_run|dry-run/.test(jobType)
        return job.asset_id && !sandboxJob && !['completed', 'failed', 'cancelled', 'canceled'].includes(String(job.status || '').toLowerCase())
      })
      .map((job: any) => [String(job.asset_id), job]),
  )

  const candidates = action === 'sandbox'
    ? []
    : selectedAssets.filter((asset: any) => asset.assetId && !activeByAsset.has(String(asset.assetId)))
  const reusedJobs: any[] = action === 'sandbox'
    ? []
    : selectedAssets
      .map((asset: any) => activeByAsset.get(String(asset.assetId)))
      .filter(Boolean)

  const planPreview = buildPlanPayload({
    planId,
    action,
    selectedAssets,
    configuration,
    snapshot,
    jobs: reusedJobs,
    now,
  })

  const rows = candidates.map((asset: any) => {
    const targetStack = mandatoryPqcStackMetadata(
      asset.targetSolution || asset.currentAlgorithm,
      `${asset.type || ''} ${asset.name || ''} ${plannerJobType(asset)}`,
    )
    const targetAlgorithm = String(targetStack.targetAlgorithm)
    return {
    user_id: req.user!.id,
    asset_id: asset.assetId,
    name: `PQC Migration: ${asset.name}`,
    job_type: plannerJobType(asset),
    status: action === 'start' && asset.startsOnApproval ? 'queued' : 'pending',
    target_algorithm: targetAlgorithm,
    strategy: `${asset.currentAlgorithm} -> ${targetAlgorithm}`,
    progress: 0,
    metadata: {
      source: 'migration-planner',
      workflow: 'post-quantum-migration-plan',
      planId,
      planStatus: planPreview.status,
      planAction: action,
      plan: {
        id: planId,
        status: planPreview.status,
        action,
        createdAt: now,
        selectedAssets,
        orchestrationUrl: planPreview.orchestrationUrl,
        liveMigrationUrl: planPreview.liveMigrationUrl,
        sandboxUrl: planPreview.sandboxUrl,
      },
      configuration,
      riskData: planPreview.riskData,
      migrationMetadata: planPreview.migrationMetadata,
      priority: asset.priority,
      riskScore: asset.risk,
      riskPriorityScore: asset.riskPriorityScore,
      owner: asset.owner,
      environment: asset.environment,
      assetName: asset.name,
      assetType: asset.type,
      sourceAlgorithm: asset.currentAlgorithm,
      targetAlgorithm,
      configuredTargetAlgorithms: configuration.targetAlgorithms,
      configuredCurrentAlgorithms: configuration.currentAlgorithms,
      mandatoryPqcStack: MANDATORY_PQC_STACK,
      cryptographicStack: targetStack,
      currentAlgorithmInScope: asset.currentAlgorithmInScope,
      tags: asset.tags,
      execution: {
        strategy: configuration.deploymentStrategy,
        phaseIndex: asset.phaseIndex,
        phaseName: asset.phaseName,
        sequenceOrder: asset.sequenceOrder,
        totalPhases: prepared.phases.length,
        scopeKey: asset.scopeKey,
        gateRequired: asset.gateRequired,
        startsOnApproval: asset.startsOnApproval,
        agentRequired: true,
        agentDispatchStatus: action === 'start' && asset.startsOnApproval ? 'queued_for_agent' : 'waiting_for_orchestration',
        operatorPatchWorkflow: true,
        sequenceState: action === 'start' && asset.startsOnApproval ? 'waiting_for_agent' : 'pending',
      },
      controls: configuration.controls,
      range: snapshot.range.key,
      createdBy: req.user!.id,
      createdAt: now,
    },
    started_at: null,
    created_at: now,
    updated_at: now,
    }
  })

  let inserted: any[] = []
  if (rows.length) {
    let result: any
    try {
      result = await client
        .from('migration_jobs')
        .insert(rows)
        .select('id, name, asset_id, status, target_algorithm, metadata, created_at, updated_at')
    } catch (error: any) {
      return res.status(503).json({ error: { code: 'PLAN_CREATE_NETWORK_ERROR', message: plannerNetworkErrorMessage(error, 'Migration job creation') } })
    }

    if (result.error) {
      return res.status(500).json({ error: { code: 'PLAN_CREATE_FAILED', message: result.error.message || 'Failed to create migration plan' } })
    }
    inserted = result.data || []
  }

  const allJobs: any[] = [...inserted, ...reusedJobs]
  const plan = buildPlanPayload({
    planId,
    action,
    selectedAssets,
    configuration,
    snapshot,
    jobs: allJobs,
    now,
  })

  let sandboxJobs: any[] = []
  if (action === 'sandbox') {
    const sandboxRows = selectedAssets
      .filter((asset: any) => asset.assetId)
      .map((asset: any, index: number) => {
        const targetStack = mandatoryPqcStackMetadata(
          asset.targetSolution || asset.currentAlgorithm,
          `${asset.type || ''} ${asset.name || ''} sandbox ${plannerJobType(asset)}`,
        )
        const targetAlgorithm = String(targetStack.targetAlgorithm)
        return {
        user_id: req.user!.id,
        asset_id: asset.assetId,
        name: `Sandbox Simulation: ${asset.name}`,
        job_type: `sandbox_${plannerJobType(asset)}`,
        status: 'queued',
        target_algorithm: targetAlgorithm,
        strategy: `${asset.currentAlgorithm} -> ${targetAlgorithm}`,
        progress: 0,
        metadata: {
          source: 'migration-planner',
          workflow: 'migration-sandbox-simulation',
          planId,
          planStatus: plan.status,
          planAction: action,
          sandboxMode: true,
          executionMode: 'sandbox_simulation',
          engine: 'qguard-sandbox-orchestrator',
          phase: 'queued',
          queueReason: 'Queued from Migration Plan approval',
          queuedAt: now,
          simulatedDurationMs: Math.max(150_000, 180_000 + Number(asset.risk || 0) * 1200 + index * 12000),
          initiatedBy: req.user!.email || req.user!.id,
          initiatedAt: now,
          plan: {
            id: planId,
            status: plan.status,
            action,
            createdAt: now,
            selectedAssets,
            sandboxUrl: plan.sandboxUrl,
            orchestrationUrl: plan.orchestrationUrl,
            liveMigrationUrl: plan.liveMigrationUrl,
          },
          configuration,
          riskData: plan.riskData,
          migrationMetadata: plan.migrationMetadata,
          priority: asset.priority,
          riskScore: asset.risk,
          riskPriorityScore: asset.riskPriorityScore,
          owner: asset.owner,
          environment: asset.environment,
          assetName: asset.name,
          assetType: asset.type,
          sourceAlgorithm: asset.currentAlgorithm,
          targetAlgorithm,
          configuredTargetAlgorithms: configuration.targetAlgorithms,
          configuredCurrentAlgorithms: configuration.currentAlgorithms,
          mandatoryPqcStack: MANDATORY_PQC_STACK,
          cryptographicStack: targetStack,
          currentAlgorithmInScope: asset.currentAlgorithmInScope,
          tags: asset.tags,
          controls: configuration.controls,
          execution: {
            strategy: configuration.deploymentStrategy,
            phaseIndex: asset.phaseIndex,
            phaseName: asset.phaseName,
            sequenceOrder: asset.sequenceOrder,
            totalPhases: prepared.phases.length,
            scopeKey: asset.scopeKey,
            gateRequired: asset.gateRequired,
            startsOnApproval: false,
            agentRequired: false,
            agentDispatchStatus: 'not_required_for_sandbox',
            operatorPatchWorkflow: false,
            sequenceState: 'queued_for_sandbox',
          },
          range: snapshot.range.key,
          createdBy: req.user!.id,
          createdAt: now,
        },
        started_at: null,
        created_at: now,
        updated_at: now,
        }
      })

    if (sandboxRows.length) {
      let sandboxResult: any
      try {
        sandboxResult = await client
          .from('migration_jobs')
          .insert(sandboxRows)
          .select('id, name, asset_id, status, target_algorithm, metadata, created_at, updated_at')
      } catch (error: any) {
        return res.status(503).json({ error: { code: 'SANDBOX_CREATE_NETWORK_ERROR', message: plannerNetworkErrorMessage(error, 'Migration sandbox queueing') } })
      }

      if (sandboxResult.error) {
        return res.status(500).json({ error: { code: 'SANDBOX_CREATE_FAILED', message: sandboxResult.error.message || 'Failed to queue migration sandbox simulations' } })
      }
      sandboxJobs = sandboxResult.data || []
    }

    void (async () => {
      try {
        await persistMigrationPlan(client, req.user!.id, plan)

        const sandboxEventRows = sandboxJobs.map((job: any) => ({
          user_id: req.user!.id,
          migration_id: job.id,
          event_type: 'planner-sandbox-simulation-queued',
          severity: 'info',
          message: `Migration Planner queued sandbox simulation ${job.name} targeting ${job.target_algorithm}.`,
          metadata: {
            source: 'migration-planner',
            destination: 'migration-sandbox',
            planId,
            action,
            sandboxMode: true,
            range: snapshot.range.key,
            configuration,
            controls: configuration.controls,
          },
          created_at: now,
        }))
        if (sandboxEventRows.length) {
          const { error: sandboxEventError } = await client.from('migration_events').insert(sandboxEventRows)
          if (sandboxEventError && !isMissingTable(sandboxEventError)) console.warn('[migration-planner] Sandbox event insert failed:', sandboxEventError.message)
        }

        await client.from('migration_events').insert({
          user_id: req.user!.id,
          migration_id: null,
          event_type: 'plan-sandbox-simulations-queued',
          severity: 'info',
          message: `Migration plan ${planId} queued ${sandboxJobs.length} migration sandbox simulation package(s).`,
          metadata: {
            source: 'migration-planner',
            planId,
            action,
            status: plan.status,
            selectedAssets: selectedAssets.length,
            sandboxJobs: sandboxJobs.length,
            sandboxUrl: plan.sandboxUrl,
            strategyPhases: prepared.phases,
            configuration,
            pipeline: [
              'plan_validation',
              'database_persistence',
              'plan_generation',
              'sandbox_simulation_queue',
              'telemetry_registration',
              'event_broadcasting',
              'ui_refresh',
            ],
          },
          created_at: now,
        }).then(({ error: planEventError }: any) => {
          if (planEventError && !isMissingTable(planEventError)) console.warn('[migration-planner] Sandbox lifecycle event failed:', planEventError.message)
        })

        await client.from('security_events').insert({
          user_id: req.user!.id,
          event_type: 'migration-plan-sandbox',
          severity: 'info',
          message: `${selectedAssets.length} asset migration plan ${plan.status} sent to Migration Sandbox from ${snapshot.range.label}.`,
          resource_name: 'Migration Planner',
          resource_type: 'migration_plan',
          metadata: {
            source: 'migration-planner',
            planId,
            action,
            createdJobs: 0,
            reusedJobs: 0,
            sandboxJobs: sandboxJobs.length,
            selectedAssets: selectedAssets.length,
            configuration,
            riskData: plan.riskData,
            sandboxUrl: plan.sandboxUrl,
            range: snapshot.range.key,
          },
          created_at: now,
        }).then(({ error: securityError }: any) => {
          if (securityError && !isMissingTable(securityError)) console.warn('[migration-planner] Sandbox security event failed:', securityError.message)
        })
      } catch (error: any) {
        console.warn('[migration-planner] Background sandbox handoff finalization failed:', error?.message || error)
      }
    })()

    return res.json({
      data: {
        created: 0,
        reused: 0,
        sandboxCreated: sandboxJobs.length,
        jobs: [],
        sandboxJobs,
        planId,
        plan,
        orchestrationUrl: plan.orchestrationUrl,
        liveMigrationUrl: plan.liveMigrationUrl,
        sandboxUrl: plan.sandboxUrl,
        message: `${selectedAssets.length} asset migration plan ${plan.status}; ${sandboxJobs.length} sandbox simulation job(s) queued.`,
      },
    })
  }

  for (const job of reusedJobs) {
    const metadata = asRecord(job.metadata)
    const plannedAsset = selectedAssets.find((asset: any) => String(asset.assetId || asset.id) === String(job.asset_id))
    const targetStack = mandatoryPqcStackMetadata(
      plannedAsset?.targetSolution || job.target_algorithm || pickString(metadata, ['targetAlgorithm']) || plannedAsset?.currentAlgorithm,
      `${plannedAsset?.type || pickString(metadata, ['assetType'])} ${plannedAsset?.name || pickString(metadata, ['assetName'])} ${job.job_type || ''}`,
    )
    const targetAlgorithm = String(targetStack.targetAlgorithm)
    let linkResult: any
    try {
      linkResult = await client
        .from('migration_jobs')
        .update({
          target_algorithm: targetAlgorithm,
          strategy: plannedAsset ? `${plannedAsset.currentAlgorithm} -> ${targetAlgorithm}` : undefined,
          metadata: {
            ...metadata,
            planId,
            planStatus: plan.status,
            planAction: action,
            plan: {
              ...asRecord(metadata.plan),
              id: planId,
              status: plan.status,
              action,
              updatedAt: now,
              selectedAssets,
              orchestrationUrl: plan.orchestrationUrl,
              liveMigrationUrl: plan.liveMigrationUrl,
              sandboxUrl: plan.sandboxUrl,
            },
            configuration,
            riskData: plan.riskData,
            migrationMetadata: plan.migrationMetadata,
            targetAlgorithm,
            configuredTargetAlgorithms: configuration.targetAlgorithms,
            configuredCurrentAlgorithms: configuration.currentAlgorithms,
            mandatoryPqcStack: MANDATORY_PQC_STACK,
            cryptographicStack: targetStack,
            currentAlgorithmInScope: plannedAsset?.currentAlgorithmInScope ?? metadata.currentAlgorithmInScope,
            tags: plannedAsset?.tags || metadata.tags,
            execution: plannedAsset ? {
              strategy: configuration.deploymentStrategy,
              phaseIndex: plannedAsset.phaseIndex,
              phaseName: plannedAsset.phaseName,
              sequenceOrder: plannedAsset.sequenceOrder,
              totalPhases: prepared.phases.length,
              scopeKey: plannedAsset.scopeKey,
              gateRequired: plannedAsset.gateRequired,
              startsOnApproval: plannedAsset.startsOnApproval,
              agentRequired: true,
              agentDispatchStatus: action === 'start' && plannedAsset.startsOnApproval ? 'queued_for_agent' : 'waiting_for_orchestration',
              operatorPatchWorkflow: true,
              sequenceState: action === 'start' && plannedAsset.startsOnApproval ? 'waiting_for_agent' : 'pending',
            } : metadata.execution,
            controls: configuration.controls,
          },
          updated_at: now,
        })
        .eq('id', job.id)
        .eq('user_id', req.user!.id)
    } catch (error: any) {
      return res.status(503).json({ error: { code: 'PLAN_LINK_NETWORK_ERROR', message: plannerNetworkErrorMessage(error, 'Migration job linking') } })
    }
    const linkError = linkResult?.error
    if (linkError) {
      return res.status(500).json({ error: { code: 'PLAN_LINK_FAILED', message: linkError.message || 'Failed to link existing migration jobs to plan' } })
    }
  }

  const finalizePlannerHandoff = async () => {
    await persistMigrationPlan(client, req.user!.id, plan)
    if (action === 'start') {
      await persistExecutionDispatch(client, req.user!.id, plan, allJobs, action, 1, now)
    }

    const eventRows = [
      ...inserted.map((job: any) => ({
        user_id: req.user!.id,
        migration_id: job.id,
        event_type: 'planner-job-created',
        severity: 'info',
        message: `Migration Planner created ${job.name} targeting ${job.target_algorithm}.`,
        metadata: {
          source: 'migration-planner',
          planId,
          action,
          range: snapshot.range.key,
          configuration,
          execution: asRecord(job.metadata).execution,
          controls: configuration.controls,
          mandatoryPqcStack: MANDATORY_PQC_STACK,
          cryptographicStack: asRecord(job.metadata).cryptographicStack || mandatoryPqcStackMetadata(job.target_algorithm),
        },
        created_at: now,
      })),
      ...sandboxJobs.map((job: any) => ({
        user_id: req.user!.id,
        migration_id: job.id,
        event_type: 'planner-sandbox-simulation-queued',
        severity: 'info',
        message: `Migration Planner queued sandbox simulation ${job.name} targeting ${job.target_algorithm}.`,
        metadata: {
          source: 'migration-planner',
          destination: 'migration-sandbox',
          planId,
          action,
          sandboxMode: true,
          range: snapshot.range.key,
          configuration,
          controls: configuration.controls,
          mandatoryPqcStack: MANDATORY_PQC_STACK,
          cryptographicStack: asRecord(job.metadata).cryptographicStack || mandatoryPqcStackMetadata(job.target_algorithm),
        },
        created_at: now,
      })),
    ]
    if (eventRows.length) {
      await Promise.resolve(client.from('migration_events').insert(eventRows)).then(({ error: eventError }: any) => {
        if (eventError && !isMissingTable(eventError)) console.warn('[migration-planner] Plan event insert failed:', eventError.message)
      }).catch((error: any) => {
        console.warn('[migration-planner] Plan event insert crashed:', error?.message || error)
      })
    }

    await Promise.resolve(client.from('migration_events').insert({
      user_id: req.user!.id,
      migration_id: null,
      event_type: action === 'start' ? 'plan-agent-dispatch-queued' : 'plan-created',
      severity: 'info',
      message: action === 'start'
        ? `Migration plan ${planId} queued deployment packages for authenticated agent execution.`
        : `Migration plan ${planId} completed validation, persistence, task generation, orchestration preparation, and telemetry registration.`,
      metadata: {
        source: 'migration-planner',
        planId,
        action,
        status: plan.status,
        selectedAssets: selectedAssets.length,
        sandboxJobs: sandboxJobs.length,
        sandboxUrl: plan.sandboxUrl,
        strategyPhases: prepared.phases,
        configuration,
        pipeline: [
          'plan_validation',
          'database_persistence',
          'plan_generation',
          'task_generation',
          'orchestration_preparation',
          'telemetry_registration',
          'event_broadcasting',
          'ui_refresh',
        ],
      },
      created_at: now,
    })).then(({ error: planEventError }: any) => {
      if (planEventError && !isMissingTable(planEventError)) console.warn('[migration-planner] Plan lifecycle event failed:', planEventError.message)
    }).catch((error: any) => {
      console.warn('[migration-planner] Plan lifecycle event crashed:', error?.message || error)
    })

    await Promise.resolve(client.from('security_events').insert({
      user_id: req.user!.id,
      event_type: action === 'start' ? 'migration-plan-approved' : `migration-plan-${action}`,
      severity: 'info',
      message: `${selectedAssets.length} asset migration plan ${plan.status} from ${snapshot.range.label}.`,
      resource_name: 'Migration Planner',
      resource_type: 'migration_plan',
      metadata: {
        source: 'migration-planner',
        planId,
        action,
        createdJobs: inserted.length,
        reusedJobs: reusedJobs.length,
        sandboxJobs: sandboxJobs.length,
        selectedAssets: selectedAssets.length,
        configuration,
        riskData: plan.riskData,
        sandboxUrl: plan.sandboxUrl,
        range: snapshot.range.key,
      },
      created_at: now,
    })).then(({ error: securityError }: any) => {
      if (securityError && !isMissingTable(securityError)) console.warn('[migration-planner] Security event insert failed:', securityError.message)
    }).catch((error: any) => {
      console.warn('[migration-planner] Security event insert crashed:', error?.message || error)
    })
  }

  const responseData = {
    created: inserted.length,
    reused: reusedJobs.length,
    sandboxCreated: sandboxJobs.length,
    jobs: allJobs,
    sandboxJobs,
    planId,
    plan,
    orchestrationUrl: plan.orchestrationUrl,
    liveMigrationUrl: plan.liveMigrationUrl,
    sandboxUrl: plan.sandboxUrl,
    message: `${selectedAssets.length} asset migration plan ${plan.status}; ${inserted.length} new job(s), ${reusedJobs.length} existing job(s) linked.`,
  }

  if (action === 'start') {
    void finalizePlannerHandoff().catch((error: any) => {
      console.warn('[migration-planner] Background start handoff finalization failed:', error?.message || error)
    })
    return res.json({
      data: {
        ...responseData,
        handoffStatus: 'background_finalizing',
        message: `${selectedAssets.length} asset migration plan ${plan.status}; opening PQC Orchestration while dispatch packages and audit telemetry finish in the background.`,
      },
    })
  }

  try {
    await finalizePlannerHandoff()
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'PLAN_PERSIST_FAILED', message: error?.message || 'Failed to persist migration plan' } })
  }

  let refreshed = snapshot
  try {
    refreshed = await buildMigrationPlannerSnapshot(client, req.user!.id, range)
  } catch (error: any) {
    console.warn('[migration-planner] Post-create planner refresh failed:', error?.message || error)
  }
  res.json({
    data: {
      ...responseData,
      snapshot: refreshed,
    },
  })
})

router.get('/plans/:planId', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const planId = String(req.params.planId || '').trim()
  if (!planId) return res.status(400).json({ error: { code: 'INVALID_PLAN', message: 'Migration plan ID is required' } })

  try {
    const plan = await loadMigrationPlan(client, req.user!.id, planId)
    if (!plan) return res.status(404).json({ error: { code: 'PLAN_NOT_FOUND', message: 'Migration plan not found' } })
    return res.json({ data: plan })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'PLAN_LOAD_FAILED', message: error?.message || 'Failed to load migration plan' } })
  }
})

router.post('/plans/:planId/action', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const planId = String(req.params.planId || '').trim()
  const action = String(req.body?.action || '').toLowerCase()
  if (!['start_execution', 'pause', 'resume', 'rollback', 'approve_next_phase'].includes(action)) {
    return res.status(400).json({ error: { code: 'INVALID_ACTION', message: 'Unsupported orchestration action' } })
  }

  const plan = await loadMigrationPlan(client, req.user!.id, planId)
  if (!plan) return res.status(404).json({ error: { code: 'PLAN_NOT_FOUND', message: 'Migration plan not found' } })

  const jobs = await fetchPlanJobs(client, req.user!.id, planId)
  if (!jobs.length) return res.status(404).json({ error: { code: 'NO_PLAN_JOBS', message: 'No migration jobs are linked to this plan' } })

  const phaseToStart = nextPhaseForAction(action, jobs)
  for (const job of jobs) {
    const { error: updateError } = await client
      .from('migration_jobs')
      .update(orchestrationActionUpdate(action, asRecord(job.metadata), job.progress, phaseToStart))
      .eq('id', job.id)
      .eq('user_id', req.user!.id)
    if (updateError) {
      return res.status(500).json({ error: { code: 'UPDATE_FAILED', message: 'Failed to update plan migration jobs' } })
    }
  }

  await insertActionEvents(client, req.user!.id, jobs, action)

  const now = new Date().toISOString()
  const status = action === 'start_execution' ? 'awaiting_agent' : action === 'pause' ? 'paused' : action === 'resume' ? 'awaiting_agent' : action === 'rollback' ? 'rollback_requested' : 'phase_approved'
  await client
    .from('migration_plans')
    .update({
      status,
      metadata: {
        ...plan.migrationMetadata,
        status,
        lastOperatorAction: action,
        lastOperatorActionAt: now,
        activePhase: phaseToStart,
      },
      updated_at: now,
    })
    .eq('id', planId)
    .eq('user_id', req.user!.id)
    .then(({ error }: any) => {
      if (error && !isMissingTable(error)) console.warn('[migration-planner] Plan action status update failed:', error.message)
    })

  await persistExecutionDispatch(client, req.user!.id, { ...plan, status }, jobs, action, phaseToStart, now)

  await client.from('security_events').insert({
    user_id: req.user!.id,
    event_type: `migration-plan-${action}`,
    severity: action === 'rollback' ? 'warning' : 'info',
    message: `PQC orchestration action ${action.replace(/_/g, ' ')} applied to plan ${planId}.`,
    resource_name: 'PQC Orchestration',
    resource_type: 'migration_plan',
    metadata: {
      source: 'pqc-orchestration',
      planId,
      action,
      affectedJobs: jobs.length,
    },
    created_at: now,
  }).then(({ error }: any) => {
    if (error && !isMissingTable(error)) console.warn('[migration-planner] Orchestration security event failed:', error.message)
  })

  await upsertPlannerRows(client, 'migration_tasks', jobs.map((job: any) => {
    const metadata = asRecord(job.metadata)
    const execution = asRecord(metadata.execution)
    const phaseIndex = Number(execution.phaseIndex || 1)
    const nextStatus = (action === 'start_execution' || action === 'approve_next_phase')
      ? phaseToStart && phaseIndex > phaseToStart
        ? 'pending'
        : 'queued'
      : status
    return {
      plan_id: planId,
      user_id: req.user!.id,
      migration_job_id: job.id,
      asset_id: String(job.asset_id || pickString(metadata, ['assetId']) || job.id),
      task_type: String(job.job_type || plannerJobType(metadata)),
      phase_index: phaseIndex,
      sequence_order: Number(execution.sequenceOrder || 1),
      status: nextStatus,
      target_algorithm: String(job.target_algorithm || pickString(metadata, ['targetAlgorithm']) || 'PQC target pending'),
      controls: plan.configuration.controls || metadata.controls || {},
      telemetry: {
        orchestrationAction: action,
        activePhase: phaseToStart,
        agentDispatchQueued: ['start_execution', 'resume', 'approve_next_phase'].includes(action),
        updatedAt: now,
      },
      metadata: {
        ...metadata,
        source: 'pqc-orchestration',
        lastOperatorAction: action,
        phaseToStart,
      },
      updated_at: now,
    }
  }), 'plan_id,user_id,asset_id,task_type')

  await insertPlannerRows(client, 'migration_audit_logs', [{
    plan_id: planId,
    user_id: req.user!.id,
    action,
    stage: 'orchestration',
    result: 'success',
    details: {
      source: 'pqc-orchestration',
      affectedJobs: jobs.length,
      phaseToStart,
      status,
      executionQueue: ['start_execution', 'resume', 'approve_next_phase'].includes(action) ? 'queued_for_agent' : status,
      controls: plan.configuration.controls,
    },
    created_at: now,
  }])

  const [updatedPlan, liveSnapshot] = await Promise.all([
    loadMigrationPlan(client, req.user!.id, planId),
    buildLiveMigrationSnapshot(client, req.user!.id, planId),
  ])

  return res.json({
    data: {
      action,
      affected: jobs.length,
      plan: updatedPlan,
      liveSnapshot,
      liveMigrationUrl: `/dashboard/live-migration?planId=${encodeURIComponent(planId)}`,
    },
  })
})

router.get('/live', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const planId = typeof req.query.planId === 'string' ? req.query.planId : null
  const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id, planId)
  res.json({ data: snapshot })
})

router.get('/live/export', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const planId = typeof req.query.planId === 'string' ? req.query.planId : null
  const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id, planId)
  const format = String(req.query.format || 'json').toLowerCase()
  const baseName = `qguard-live-migration-${new Date().toISOString().slice(0, 10)}`

  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', `attachment; filename="${baseName}.csv"`)
    return res.send(buildCsv(snapshot))
  }

  res.setHeader('Content-Type', 'application/json')
  res.setHeader('Content-Disposition', `attachment; filename="${baseName}.json"`)
  return res.send(JSON.stringify(snapshot, null, 2))
})

router.get('/live/stream', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  sseHeaders(res)
  writeSse(res, 'connected', { timestamp: new Date().toISOString() })

  const emitSnapshot = async () => {
    const planId = typeof req.query.planId === 'string' ? req.query.planId : null
    const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id, planId)
    writeSse(res, 'migration-update', snapshot)
  }

  await emitSnapshot().catch(() => undefined)
  const heartbeat = setInterval(() => writeSse(res, 'heartbeat', { ts: Date.now() }), 15000)
  const poll = setInterval(() => emitSnapshot().catch(() => undefined), 7000)

  req.on('close', () => {
    clearInterval(heartbeat)
    clearInterval(poll)
    res.end()
  })
})

router.post('/jobs/:id/action', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const action = String(req.body?.action || '').toLowerCase()
  if (!['pause', 'resume', 'retry', 'rollback'].includes(action)) {
    return res.status(400).json({ error: { code: 'INVALID_ACTION', message: 'Unsupported migration action' } })
  }

  const { data: job, error: readError } = await client
    .from('migration_jobs')
    .select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, created_at, updated_at')
    .eq('id', req.params.id)
    .eq('user_id', req.user!.id)
    .single()

  if (readError || !job) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Migration job not found' } })
  }

  const { error: updateError } = await client
    .from('migration_jobs')
    .update(actionUpdate(action, asRecord(job.metadata)))
    .eq('id', job.id)
    .eq('user_id', req.user!.id)

  if (updateError) {
    return res.status(500).json({ error: { code: 'UPDATE_FAILED', message: 'Failed to update migration job' } })
  }

  await insertActionEvents(client, req.user!.id, [job], action)
  if (['resume', 'retry'].includes(action)) {
    const dispatchPlan = dispatchPlanFromJob(job, new Date().toISOString())
    if (dispatchPlan) await persistExecutionDispatch(client, req.user!.id, dispatchPlan, [job], action, null, new Date().toISOString())
  }
  const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id)
  return res.json({ data: { action, jobId: job.id, snapshot } })
})

router.post('/jobs/actions', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const action = String(req.body?.action || '').toLowerCase()
  const planId = typeof req.body?.planId === 'string' && req.body.planId.trim() ? req.body.planId.trim() : null
  const scopes: Record<string, string[]> = {
    pause: ['running', 'in_progress', 'IN_PROGRESS'],
    resume: ['paused', 'pending', 'queued', 'PLANNED'],
    retry: ['failed', 'FAILED'],
  }

  if (!scopes[action]) {
    return res.status(400).json({ error: { code: 'INVALID_ACTION', message: 'Unsupported bulk migration action' } })
  }

  const { data: jobs, error: readError } = await client
    .from('migration_jobs')
    .select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, created_at, updated_at')
    .eq('user_id', req.user!.id)
    .in('status', scopes[action])

  if (readError) {
    return res.status(500).json({ error: { code: 'READ_FAILED', message: 'Failed to read migration jobs' } })
  }

  const scopedJobs = (jobs || []).filter((job: any) => matchesPlanId(job, planId))
  const ids = scopedJobs.map((job: any) => job.id)
  if (ids.length > 0) {
    for (const job of scopedJobs) {
      const { error: updateError } = await client
        .from('migration_jobs')
        .update(actionUpdate(action, asRecord(job.metadata)))
        .eq('id', job.id)
        .eq('user_id', req.user!.id)

      if (updateError) {
        return res.status(500).json({ error: { code: 'UPDATE_FAILED', message: 'Failed to update migration jobs' } })
      }
    }
    await insertActionEvents(client, req.user!.id, scopedJobs, action)
    if (['resume', 'retry'].includes(action)) {
      const now = new Date().toISOString()
      for (const job of scopedJobs) {
        const dispatchPlan = dispatchPlanFromJob(job, now)
        if (dispatchPlan) await persistExecutionDispatch(client, req.user!.id, dispatchPlan, [job], action, null, now)
      }
    }
  }

  const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id)
  return res.json({ data: { action, affected: ids.length, snapshot } })
})

export default router
