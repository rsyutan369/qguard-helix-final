/**
 * Runtime Telemetry — `/api/v1/dashboard/runtime-telemetry`.
 *
 * Reports the health of the telemetry pipeline itself: collector fleet,
 * ingestion lag, source freshness, signal quality and coverage.
 *
 * This replaces the `runtime` mode of `observability-dashboard.ts`, whose
 * builder accepted a mode discriminator and never read it — so
 * runtime-telemetry, certificate-telemetry and multi-cloud-telemetry all
 * returned byte-identical payloads. Those other two modes still use it and are
 * untouched.
 *
 * Row caps matter more here than on other dashboards: this page reports on the
 * SHAPE of the data, so a truncated fetch would misreport the very thing it
 * exists to measure. Caps are therefore generous, and any source that reaches
 * one is flagged so its count renders as a lower bound.
 */

import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildTelemetryPipelineIntelligence } from '@/lib/telemetry-pipeline/intelligence'
import type { SourceKey, TelemetryPipelineIntelligence } from '@/lib/telemetry-pipeline/types'

type Row = Record<string, unknown>

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value === null || value === undefined ? '' : String(value).trim()
}

function num(value: unknown, fallback = 0): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Row[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`[runtime-telemetry] ${table} query skipped:`, error.message || error)
      return []
    }
    return (data as Row[]) || []
  } catch (error) {
    console.warn(`[runtime-telemetry] ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getToken(req) || (typeof req.query.token === 'string' ? req.query.token : null)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}

/* ------------------------------------------------------------------ */
/* Model + cache                                                       */
/* ------------------------------------------------------------------ */

/** Per-source caps. Reaching one marks the source as truncated. */
const CAP: Record<SourceKey, number> = {
  runtime_crypto_events: 8000,
  scanner_evidence: 5000,
  scanner_alerts: 2500,
  crypto_inventory: 5000,
  pqc_scan_results: 3000,
  crypto_exposures: 3000,
  certificates: 2500,
  generated_keys: 2500,
  security_events: 2500,
  agent_heartbeats: 3000,
  migration_jobs: 1500,
  vault_files: 2500,
}

/**
 * Columns fetched per source.
 *
 * Deliberately narrow: this page needs timestamps, attribution keys and a few
 * shape fields, never payloads. Selecting `*` on `runtime_crypto_events` would
 * pull metadata JSONB for thousands of rows to compute a lag figure.
 */
const SELECT: Record<SourceKey, string> = {
  runtime_crypto_events:
    'id, agent_id, asset_id, source_type, event_type, operation_type, severity, host, algorithm, cipher_suite, tls_version, key_exchange_algorithm, observed_at, created_at',
  scanner_evidence: 'id, agent_id, asset_name, source_type, evidence_type, observed_at, processed_at, created_at',
  scanner_alerts: 'id, agent_id, severity, category, status, created_at, updated_at',
  crypto_inventory: 'id, asset_id, item_type, discovered_at, created_at',
  pqc_scan_results: 'id, asset_id, finding_type, created_at',
  crypto_exposures: 'id, asset_id, exposure_type, created_at, updated_at',
  certificates: 'id, asset_id, created_at, updated_at',
  generated_keys: 'id, status, created_at, updated_at',
  security_events: 'id, asset_id, event_type, severity, created_at',
  agent_heartbeats: 'id, agent_id, status, observed_at, created_at',
  migration_jobs: 'id, asset_id, status, created_at, updated_at',
  vault_files: 'id, encryption_status, created_at, updated_at',
}

/** Ordering column per source, so the cap keeps the NEWEST rows. */
const ORDER: Record<SourceKey, string> = {
  runtime_crypto_events: 'observed_at',
  scanner_evidence: 'observed_at',
  scanner_alerts: 'created_at',
  crypto_inventory: 'discovered_at',
  pqc_scan_results: 'created_at',
  crypto_exposures: 'updated_at',
  certificates: 'updated_at',
  generated_keys: 'created_at',
  security_events: 'created_at',
  agent_heartbeats: 'observed_at',
  migration_jobs: 'updated_at',
  vault_files: 'updated_at',
}

const MODEL_TTL_MS = 15_000
const modelCache = new Map<string, { at: number; promise: Promise<TelemetryPipelineIntelligence> }>()

async function computeModel(token: string, userId: string): Promise<TelemetryPipelineIntelligence> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const keys = Object.keys(SELECT) as SourceKey[]

  const [assets, scannerAgents, connectorAccounts, ...sourceResults] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, environment').eq('user_id', userId).limit(2000)),
    safeRows(client, 'scanner_agents', (q) =>
      q.select('id, name, status, hostname, platform, last_seen_at, metadata, created_at, updated_at').eq('user_id', userId).limit(500),
    ),
    safeRows(client, 'connector_accounts', (q) =>
      q.select('id, provider, status, last_sync_at, created_at, updated_at').eq('user_id', userId).limit(500),
    ),
    ...keys.map((key) =>
      safeRows(client, key, (q) => q.select(SELECT[key]).eq('user_id', userId).order(ORDER[key], { ascending: false }).limit(CAP[key])),
    ),
  ])

  const rowsBySource = {} as Record<SourceKey, Row[]>
  const truncatedSources: SourceKey[] = []
  keys.forEach((key, index) => {
    const data = sourceResults[index] ?? []
    rowsBySource[key] = data
    if (data.length >= CAP[key]) truncatedSources.push(key)
  })

  return buildTelemetryPipelineIntelligence({
    assets: assets.map((asset) => ({
      id: str(asset.id),
      name: str(asset.name) || 'Unnamed asset',
      environment: str(asset.environment) || 'unknown',
    })),
    rowsBySource,
    truncatedSources,
    scannerAgents,
    connectorAccounts,
  })
}

export async function buildRuntimeTelemetryModel(token: string, userId: string, force = false) {
  const cached = modelCache.get(userId)
  if (!force && cached && Date.now() - cached.at < MODEL_TTL_MS) return cached.promise
  const promise = computeModel(token, userId)
  modelCache.set(userId, { at: Date.now(), promise })
  promise.catch(() => modelCache.delete(userId))
  if (modelCache.size > 500) {
    const now = Date.now()
    for (const [key, value] of modelCache) if (now - value.at > MODEL_TTL_MS) modelCache.delete(key)
  }
  return promise
}

/* ------------------------------------------------------------------ */
/* Projection                                                          */
/* ------------------------------------------------------------------ */

const PAGE = { collectors: 50, coverage: 50, findings: 40 } as const

function projectView(model: TelemetryPipelineIntelligence) {
  return {
    generatedAt: model.generatedAt,
    latestEvidenceAt: model.latestEvidenceAt,
    hasData: model.hasData,
    posture: model.posture,
    fleet: { ...model.fleet, collectors: model.fleet.collectors.slice(0, PAGE.collectors) },
    ingestion: model.ingestion,
    throughput: model.throughput,
    sources: model.sources,
    quality: model.quality,
    coverage: { ...model.coverage, records: model.coverage.records.slice(0, PAGE.coverage) },
    findings: model.findings.slice(0, PAGE.findings),
    sourceCounts: model.sourceCounts,
    truncated: model.truncated,
    totals: {
      collectors: model.fleet.total,
      coverageRecords: model.coverage.records.length,
      findings: model.findings.length,
      sources: model.sources.length,
    },
  }
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

const router = Router()
router.use(requireAuth)

const model = (req: AuthedRequest, force = false) => buildRuntimeTelemetryModel(req.token!, req.user!.id, force)

router.get('/', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req, str(req.query.refresh) === '1')
    res.json({ data: projectView(data) })
  } catch (error) {
    console.error('[runtime-telemetry] snapshot failed:', error)
    res.status(500).json({
      error: { code: 'PIPELINE_ERROR', message: error instanceof Error ? error.message : 'Failed to compute telemetry pipeline health' },
    })
  }
})

router.get('/stream', async (req: AuthedRequest, res: Response) => {
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  const send = (event: string, data: unknown) => {
    if (closed) return
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }

  send('connected', { at: new Date().toISOString() })

  let lastGeneratedAt = ''
  const push = async () => {
    try {
      const data = await model(req)
      if (data.generatedAt === lastGeneratedAt) return
      lastGeneratedAt = data.generatedAt
      send('pipeline', projectView(data))
    } catch (error) {
      send('pipeline-error', { message: error instanceof Error ? error.message : 'Telemetry pipeline unavailable' })
    }
  }

  void push()
  const interval = setInterval(() => void push(), 10_000)
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': heartbeat\n\n')
  }, 25_000)

  req.on('close', () => {
    closed = true
    clearInterval(interval)
    clearInterval(heartbeat)
  })
})

/** GET /coverage — server-side filtered, paged asset coverage. */
router.get('/coverage', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const search = str(req.query.search).toLowerCase()
    const health = str(req.query.health).toLowerCase()
    const filtered = data.coverage.records.filter((record) => {
      if (health && health !== 'all' && record.health !== health) return false
      if (search) {
        const haystack = `${record.assetName} ${record.environment} ${record.sources.join(' ')}`.toLowerCase()
        if (!haystack.includes(search)) return false
      }
      return true
    })
    const limit = Math.max(1, Math.min(200, num(req.query.limit) || 50))
    const offset = Math.max(0, num(req.query.offset))
    res.json({ data: { records: filtered.slice(offset, offset + limit), total: filtered.length, limit, offset } })
  } catch (error) {
    console.error('[runtime-telemetry] coverage failed:', error)
    res.status(500).json({ error: { code: 'PIPELINE_ERROR', message: 'Failed to load coverage' } })
  }
})

/** GET /findings — server-side filtered, paged pipeline findings. */
router.get('/findings', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const severity = str(req.query.severity).toLowerCase()
    const stage = str(req.query.stage).toLowerCase()
    const search = str(req.query.search).toLowerCase()
    const filtered = data.findings.filter((finding) => {
      if (severity && severity !== 'all' && finding.severity !== severity) return false
      if (stage && stage !== 'all' && finding.stage !== stage) return false
      if (search && !`${finding.title} ${finding.detail} ${finding.observed}`.toLowerCase().includes(search)) return false
      return true
    })
    const limit = Math.max(1, Math.min(200, num(req.query.limit) || 50))
    const offset = Math.max(0, num(req.query.offset))
    res.json({ data: { findings: filtered.slice(offset, offset + limit), total: filtered.length, limit, offset } })
  } catch (error) {
    console.error('[runtime-telemetry] findings failed:', error)
    res.status(500).json({ error: { code: 'PIPELINE_ERROR', message: 'Failed to load findings' } })
  }
})

export default router
