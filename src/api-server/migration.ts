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
  const value = `${algorithm || ''} ${context || ''}`.toLowerCase()
  if (/sign|ecdsa|dsa|jwt|certificate|cert|pki/.test(value)) return 'ML-DSA-65 hybrid'
  if (/hash|sha|integrity/.test(value)) return 'SHA-384 / SLH-DSA control'
  if (/database|storage|vault|aes|encrypt|data/.test(value)) return 'AES-256 + ML-KEM envelope'
  if (/vpn|tls|api|gateway|ssh|key exchange|rsa|ecdh|dh|kem/.test(value)) return 'ML-KEM-768 hybrid'
  return 'ML-KEM-768 + ML-DSA-65'
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
  const limit = Math.max(1, Math.min(25, Number(req.body?.limit || 8)))
  const snapshot = await buildMigrationPlannerSnapshot(client, req.user!.id, range)
  const selectedIds = Array.isArray(req.body?.assetIds) ? new Set(req.body.assetIds.map((id: unknown) => String(id))) : null
  const now = new Date().toISOString()
  const planId = `planner-${Date.now()}`

  const existing = await safeRows(client, 'migration_jobs', req.user!.id, (q) => q.select('id, asset_id, status, metadata').order('updated_at', { ascending: false }).limit(1000))
  const activeByAsset = new Set(
    existing
      .filter((job: any) => job.asset_id && !['completed', 'failed', 'cancelled', 'canceled'].includes(String(job.status || '').toLowerCase()))
      .map((job: any) => String(job.asset_id)),
  )

  const candidates = snapshot.topAssets
    .filter((asset: any) => asset.assetId && !activeByAsset.has(String(asset.assetId)))
    .filter((asset: any) => !selectedIds || selectedIds.has(String(asset.assetId)) || selectedIds.has(String(asset.id)))
    .slice(0, limit)

  if (!candidates.length) {
    return res.json({
      data: {
        created: 0,
        skipped: true,
        message: 'No new migration jobs were created because all selected priority assets already have active plans.',
        snapshot,
      },
    })
  }

  const rows = candidates.map((asset: any) => ({
    user_id: req.user!.id,
    asset_id: asset.assetId,
    name: `PQC Migration: ${asset.name}`,
    job_type: plannerJobType(asset),
    status: 'pending',
    target_algorithm: asset.targetSolution,
    strategy: `${asset.currentAlgorithm} -> ${asset.targetSolution}`,
    progress: 0,
    metadata: {
      source: 'migration-planner',
      workflow: 'post-quantum-migration-plan',
      planId,
      priority: asset.priority,
      riskScore: asset.risk,
      owner: asset.owner,
      environment: asset.environment,
      assetType: asset.type,
      sourceAlgorithm: asset.currentAlgorithm,
      targetAlgorithm: asset.targetSolution,
      range: snapshot.range.key,
      createdBy: req.user!.id,
      createdAt: now,
    },
    created_at: now,
    updated_at: now,
  }))

  const { data: inserted, error } = await client
    .from('migration_jobs')
    .insert(rows)
    .select('id, name, asset_id, status, target_algorithm, created_at')

  if (error) {
    return res.status(500).json({ error: { code: 'PLAN_CREATE_FAILED', message: error.message || 'Failed to create migration plan' } })
  }

  const eventRows = (inserted || []).map((job: any) => ({
    user_id: req.user!.id,
    migration_id: job.id,
    event_type: 'planner-job-created',
    severity: 'info',
    message: `Migration Planner created ${job.name} targeting ${job.target_algorithm}.`,
    metadata: {
      source: 'migration-planner',
      planId,
      range: snapshot.range.key,
    },
    created_at: now,
  }))
  if (eventRows.length) {
    const { error: eventError } = await client.from('migration_events').insert(eventRows)
    if (eventError && !isMissingTable(eventError)) console.warn('[migration-planner] Plan event insert failed:', eventError.message)
  }

  await client.from('security_events').insert({
    user_id: req.user!.id,
    event_type: 'migration-plan-created',
    severity: 'info',
    message: `${inserted?.length || 0} migration planner job(s) created from ${snapshot.range.label}.`,
    resource_name: 'Migration Planner',
    resource_type: 'migration_plan',
    metadata: {
      source: 'migration-planner',
      planId,
      createdJobs: inserted?.length || 0,
      range: snapshot.range.key,
    },
    created_at: now,
  }).then(({ error: securityError }: any) => {
    if (securityError && !isMissingTable(securityError)) console.warn('[migration-planner] Security event insert failed:', securityError.message)
  })

  const refreshed = await buildMigrationPlannerSnapshot(client, req.user!.id, range)
  res.json({
    data: {
      created: inserted?.length || 0,
      jobs: inserted || [],
      planId,
      snapshot: refreshed,
      message: `${inserted?.length || 0} migration job(s) created from prioritized asset posture.`,
    },
  })
})

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
