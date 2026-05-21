import { Router, type NextFunction, type Request, type Response } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'

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
  logs: LiveMigrationEvent[]
  logCount: number
  metadata: Record<string, unknown>
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

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return value as Record<string, unknown>
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

function deriveTargetAlgorithm(row: any, metadata: Record<string, unknown>) {
  const target = String(row?.target_algorithm || '').trim()
  if (target) return target

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
  if (fromMetadata) return fromMetadata

  const parsed = parseStrategyAlgorithms(String(row?.strategy || ''))
  return parsed.to || 'PQC target pending'
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

async function fetchJobs(client: any, userId: string) {
  const baseSelect = 'id, user_id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at'
  const withAsset = `${baseSelect}, assets(id, name, type, environment, criticality, service_owner, status)`
  const primary = await client
    .from('migration_jobs')
    .select(withAsset)
    .eq('user_id', userId)
    .order('updated_at', { ascending: false })
    .limit(100)

  if (!primary.error) return primary.data || []
  if (isMissingRelation(primary.error)) {
    const fallback = await client
      .from('migration_jobs')
      .select(baseSelect)
      .eq('user_id', userId)
      .order('updated_at', { ascending: false })
      .limit(100)
    if (!fallback.error) return fallback.data || []
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

async function buildLiveMigrationSnapshot(client: any, userId: string) {
  const jobRows = await fetchJobs(client, userId)
  const migrationIds = jobRows
    .map((row: any) => row.id)
    .filter((id: unknown): id is string => typeof id === 'string' && id.length > 0)
  const assetIds: string[] = Array.from(new Set<string>(
    jobRows
      .map((row: any) => row.asset_id)
      .filter((id: unknown): id is string => typeof id === 'string' && id.length > 0),
  ))
  const [eventRows, inventoryRows, totalAssets, findings, criticalExposures, highExposures, scanAt] = await Promise.all([
    fetchEvents(client, userId, migrationIds),
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

  const inventoryByAsset = new Map<string, any[]>()
  for (const item of inventoryRows) {
    if (!item.asset_id) continue
    if (!inventoryByAsset.has(item.asset_id)) inventoryByAsset.set(item.asset_id, [])
    inventoryByAsset.get(item.asset_id)!.push(item)
  }

  const jobs: LiveMigrationJob[] = jobRows.map((row: any) => {
    const metadata = asRecord(row.metadata)
    const asset = nestedAsset(row)
    const status = normalizeStatus(row.status)
    const progress = clampProgress(row.progress, status)
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

    const fromAlgo = deriveSourceAlgorithm(row, metadata, inventoryByAsset)
    const toAlgo = deriveTargetAlgorithm(row, metadata)
    const strategy = String(row.strategy || pickString(metadata, ['strategy']) || '')

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
      eta: deriveEta(row, status, progress, metadata),
      startedAt: row.started_at || null,
      completedAt: row.completed_at || null,
      createdAt: row.created_at || new Date().toISOString(),
      updatedAt: row.updated_at || row.completed_at || row.started_at || row.created_at || new Date().toISOString(),
      logs: [...logs, ...metadataLogs].sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()),
      logCount: logs.length + metadataLogs.length,
      metadata: {
        ...metadata,
        strategy,
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
    summary,
    jobs,
    timeline: buildTimeline(jobs),
    health: buildHealth(jobs),
    algorithmSummary: buildAlgorithmSummary(jobs),
  }
}

function actionUpdate(action: string, metadata: Record<string, unknown>, nextStatus?: string) {
  const now = new Date().toISOString()
  const nextMetadata = {
    ...metadata,
    lastOperatorAction: action,
    lastOperatorActionAt: now,
  }

  if (action === 'pause') return { status: 'paused', updated_at: now, metadata: nextMetadata }
  if (action === 'resume') return { status: 'running', started_at: now, updated_at: now, metadata: nextMetadata }
  if (action === 'retry') return { status: 'running', progress: 0, started_at: now, updated_at: now, metadata: nextMetadata }
  if (action === 'rollback') return { status: 'rollback_requested', updated_at: now, metadata: nextMetadata }
  if (nextStatus) return { status: nextStatus, updated_at: now, metadata: nextMetadata }
  return { updated_at: now, metadata: nextMetadata }
}

function actionMessage(action: string, jobName: string) {
  if (action === 'pause') return `Operator paused migration job ${jobName}.`
  if (action === 'resume') return `Operator resumed migration job ${jobName}.`
  if (action === 'retry') return `Operator retried failed migration job ${jobName}.`
  if (action === 'rollback') return `Operator requested rollback for migration job ${jobName}.`
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

router.get('/live', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id)
  res.json({ data: snapshot })
})

router.get('/live/export', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id)
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
    const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id)
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
    .select('id, name, status, metadata')
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
  const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id)
  return res.json({ data: { action, jobId: job.id, snapshot } })
})

router.post('/jobs/actions', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const action = String(req.body?.action || '').toLowerCase()
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
    .select('id, name, status, metadata')
    .eq('user_id', req.user!.id)
    .in('status', scopes[action])

  if (readError) {
    return res.status(500).json({ error: { code: 'READ_FAILED', message: 'Failed to read migration jobs' } })
  }

  const ids = (jobs || []).map((job: any) => job.id)
  if (ids.length > 0) {
    for (const job of jobs || []) {
      const { error: updateError } = await client
        .from('migration_jobs')
        .update(actionUpdate(action, asRecord(job.metadata)))
        .eq('id', job.id)
        .eq('user_id', req.user!.id)

      if (updateError) {
        return res.status(500).json({ error: { code: 'UPDATE_FAILED', message: 'Failed to update migration jobs' } })
      }
    }
    await insertActionEvents(client, req.user!.id, jobs || [], action)
  }

  const snapshot = await buildLiveMigrationSnapshot(client, req.user!.id)
  return res.json({ data: { action, affected: ids.length, snapshot } })
})

export default router
