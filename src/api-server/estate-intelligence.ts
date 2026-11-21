import { Router, type NextFunction, type Request, type Response } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildEstateModel, MAP_DIMENSIONS, type EstateGraphSnapshot, type EstateModel, type GraphLevel, type MapDimension, type Row, type TableCoverage } from '@/lib/estate'
import { SIMULATION_MARKER_SELECT } from '@/lib/migration/job-safety'
import { payloadFingerprint, streamLiveSnapshot } from './live-snapshot-stream'

/**
 * /api/v1/estate-intelligence — fix-centric remediation for large estates.
 *
 * Reads the shared scanner tables (assets, crypto_inventory, certificates,
 * asset_relationships, migration_jobs) for the caller's tenant only, in pages,
 * so a tenant with tens of thousands of rows is read completely instead of
 * stopping at PostgREST's default page. One computed `EstateModel` per tenant is
 * cached briefly (single-flight) and every route answers a bounded slice of it.
 *
 * Read-only. Queuing a campaign wave goes through the existing, tenant-verified
 * Migration Planner queue (`POST /api/v1/migration-planner/queue`), so there is
 * one write path for migration work.
 */

const router = Router()

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  res.setHeader('Cache-Control', 'private, no-store')
  next()
}
router.use(requireAuth)

const str = (value: unknown) => (typeof value === 'string' ? value : value == null ? '' : String(value))

/* ------------------------------------------------------------------ */
/* Paged, tenant-scoped loader                                         */
/* ------------------------------------------------------------------ */

const PAGE = 1000
const PARALLEL_PAGES = 4

interface TableSpec { table: string; columns: string; order: string; cap: number; status?: string }

const TABLES: Record<string, TableSpec> = {
  assets: { table: 'assets', columns: 'id, name, type, environment, service_owner, criticality, status, metadata, updated_at', order: 'updated_at', cap: 25_000 },
  // Only the metadata keys the engine reads — evidence blobs stay in the database.
  inventory: {
    table: 'crypto_inventory',
    columns: 'id, asset_id, item_type, name, algorithm, key_size, protocol, is_vulnerable, is_quantum_safe, discovered_at, created_at, m_role:metadata->>role, m_category:metadata->>category, m_package_name:metadata->>package_name, m_package:metadata->>package, m_library:metadata->>library, m_dependency:metadata->>dependency, m_hybrid:metadata->>hybridPartner, m_detection:metadata->>detectionMethod, m_algorithm:metadata->>algorithm',
    order: 'created_at',
    cap: 100_000,
  },
  certificates: {
    table: 'certificates',
    columns: 'id, asset_id, name, subject, algorithm, key_size, issuer, serial_number, not_after, is_quantum_safe, status, created_at, updated_at, fp:metadata->>fingerprint, evidence_at:metadata->>observedAt',
    order: 'updated_at',
    cap: 50_000,
  },
  relationships: { table: 'asset_relationships', columns: '*', order: 'created_at', cap: 50_000 },
  migrationJobs: { table: 'migration_jobs', columns: `id, asset_id, name, status, job_type, target_algorithm, source_algorithm:metadata->>sourceAlgorithm, created_at, updated_at, completed_at, ${SIMULATION_MARKER_SELECT}`, order: 'updated_at', cap: 25_000 },
  migrationValidations: { table: 'migration_validation_logs', columns: 'id, migration_id, status, created_at', order: 'created_at', cap: 50_000 },
  plannerQueue: { table: 'migration_plans', columns: 'id, selected_asset_ids, updated_at', order: 'updated_at', status: 'migration_queue', cap: 1 },
}

/** Re-assembles the aliased metadata keys into the `metadata` shape the engine reads. */
function inventoryRow(row: Row): Row {
  const metadata: Record<string, unknown> = {}
  const map: Record<string, string> = {
    m_role: 'role', m_category: 'category', m_package_name: 'package_name', m_package: 'package', m_library: 'library',
    m_dependency: 'dependency', m_hybrid: 'hybridPartner', m_detection: 'detectionMethod', m_algorithm: 'algorithm',
  }
  const out: Row = {}
  for (const [key, value] of Object.entries(row)) {
    if (key in map) { if (value != null && value !== '') metadata[map[key]] = value }
    else out[key] = value
  }
  out.metadata = metadata
  return out
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadTable(client: any, userId: string, spec: TableSpec): Promise<{ rows: Row[]; coverage: TableCoverage }> {
  const scoped = (query: any) => {
    const queryForUser = query.eq('user_id', userId)
    return spec.status ? queryForUser.eq('status', spec.status) : queryForUser
  }
  let total: number | null = null
  try {
    const { count, error } = await scoped(client.from(spec.table).select('*', { count: 'exact', head: true }))
    if (error) throw error
    total = typeof count === 'number' ? count : null
  } catch (error) {
    const code = str((error as { code?: string })?.code)
    if (code === 'PGRST205' || code === '42P01') return { rows: [], coverage: { table: spec.table, loaded: 0, total: null, truncated: true } }
    console.warn(`[estate-intelligence] count failed for ${spec.table}:`, (error as Error)?.message || error)
  }

  const target = Math.min(spec.cap, total ?? spec.cap)
  const pages = Math.max(1, Math.ceil(target / PAGE))
  const rows: Row[] = []
  let stoppedEarly = false
  for (let start = 0; start < pages && !stoppedEarly; start += PARALLEL_PAGES) {
    const batch = Array.from({ length: Math.min(PARALLEL_PAGES, pages - start) }, (_, i) => start + i)
    const results = await Promise.all(batch.map(async (page) => {
      const from = page * PAGE
      const { data, error } = await scoped(client.from(spec.table).select(spec.columns))
        .order(spec.order, { ascending: false }).order('id', { ascending: true }).range(from, Math.min(from + PAGE, spec.cap) - 1)
      if (error) throw error
      return (data ?? []) as Row[]
    }))
    for (const page of results) {
      rows.push(...page)
      if (page.length < PAGE) stoppedEarly = true
    }
  }
  const loaded = rows.length
  return {
    rows: spec.table === 'crypto_inventory' ? rows.map(inventoryRow) : rows,
    coverage: { table: spec.table, loaded, total, truncated: total !== null ? loaded < total : loaded >= spec.cap },
  }
}

/* ------------------------------------------------------------------ */
/* Single-flight cache                                                 */
/* ------------------------------------------------------------------ */

const TTL_MS = 10_000
const cache = new Map<string, { at: number | null; promise: Promise<EstateModel> }>()

async function compute(token: string, userId: string): Promise<EstateModel> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')
  const [assets, inventory, certificates, relationships, migrationJobs, migrationValidations, plannerQueue] = await Promise.all([
    loadTable(client, userId, TABLES.assets),
    loadTable(client, userId, TABLES.inventory),
    loadTable(client, userId, TABLES.certificates),
    loadTable(client, userId, TABLES.relationships),
    loadTable(client, userId, TABLES.migrationJobs),
    loadTable(client, userId, TABLES.migrationValidations),
    loadTable(client, userId, TABLES.plannerQueue),
  ])
  const coverage = [assets, inventory, certificates, relationships, migrationJobs, migrationValidations, plannerQueue].map((source) => source.coverage)
  const queueIds = plannerQueue.rows[0]?.selected_asset_ids
  return buildEstateModel({
    assets: assets.rows,
    inventory: inventory.rows,
    certificates: certificates.rows,
    relationships: relationships.rows,
    migrationJobs: migrationJobs.rows,
    migrationValidations: migrationValidations.rows,
    plannerQueueAssetIds: new Set(Array.isArray(queueIds) ? queueIds.map(str).filter(Boolean) : []),
    // Detail-only changes also notify open fix, campaign and map panels.
    revision: payloadFingerprint([assets.rows, inventory.rows, certificates.rows, relationships.rows, migrationJobs.rows, migrationValidations.rows, plannerQueue.rows]),
    coverage,
  })
}

export function buildEstate(token: string, userId: string, force = false): Promise<EstateModel> {
  const cached = cache.get(userId)
  if (cached && (cached.at === null || (!force && Date.now() - cached.at < TTL_MS))) return cached.promise
  const promise = compute(token, userId)
  const entry = { at: null as number | null, promise }
  cache.set(userId, entry)
  void promise.then(
    () => { entry.at = Date.now() },
    () => { if (cache.get(userId) === entry) cache.delete(userId) },
  )
  if (cache.size > 200) {
    const now = Date.now()
    for (const [key, value] of cache) if (value.at !== null && now - value.at > TTL_MS) cache.delete(key)
  }
  return promise
}

function fail(res: Response, code: string, error: unknown) {
  console.error(`[estate-intelligence] ${code}:`, error)
  res.status(500).json({ error: { code, message: 'Unable to compute estate intelligence' } })
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const model = await buildEstate(token!, user!.id, str(req.query.refresh) === '1')
    const data = model.overview()
    res.json({ data: { ...data, fingerprint: payloadFingerprint(data) } })
  } catch (error) { fail(res, 'ESTATE_OVERVIEW_ERROR', error) }
})

router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, {
    event: 'estate-intelligence',
    intervalMs: 15_000,
    build: async () => {
      try { return (await buildEstate(token!, user!.id)).overview() }
      catch { throw new Error('Unable to refresh estate intelligence') }
    },
  })
})

router.get('/fixes/:id', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const model = await buildEstate(token!, user!.id)
    const detail = model.clusterDetail(str(req.params.id), {
      offset: Number(req.query.offset) || 0,
      limit: Number(req.query.limit) || 100,
      status: str(req.query.status) || undefined,
      search: str(req.query.q).slice(0, 120) || undefined,
    })
    if (!detail) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No such fix for this tenant' } })
    res.json({ data: detail })
  } catch (error) { fail(res, 'ESTATE_FIX_ERROR', error) }
})

const LEVELS: GraphLevel[] = ['root-cause', 'neighbourhood', 'campaign']

router.get('/graph', async (req: Request, res: Response) => {
  try {
    const level = str(req.query.level) as GraphLevel
    if (!LEVELS.includes(level)) return res.status(400).json({ error: { code: 'VALIDATION', message: `level must be one of ${LEVELS.join(', ')}` } })
    const focus = str(req.query.focus).slice(0, 200)
    if (level !== 'root-cause' && !/^(fix|asset):[\w:.-]+$/.test(focus)) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'focus must be fix:<id> or asset:<id>' } })
    }
    const { token, user } = req as AuthedRequest
    const model = await buildEstate(token!, user!.id)
    const graph = model.graph(level, focus || null)
    if (!graph) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Nothing to map for that focus in this tenant' } })
    const assets = graph.nodes.flatMap((node) => {
      const asset = node.entity?.type === 'asset' ? model.mapAsset(node.entity.id) : null
      return asset ? [asset] : []
    })
    res.json({ data: { generatedAt: model.generatedAt, revision: model.revision, level, focus: focus || null, graph, assets } satisfies EstateGraphSnapshot })
  } catch (error) { fail(res, 'ESTATE_GRAPH_ERROR', error) }
})

router.get('/search', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const model = await buildEstate(token!, user!.id)
    res.json({ data: model.searchAssets(str(req.query.q).slice(0, 120)) })
  } catch (error) { fail(res, 'ESTATE_SEARCH_ERROR', error) }
})

router.get('/map', async (req: Request, res: Response) => {
  try {
    const dimension = str(req.query.dimension) as MapDimension
    if (!MAP_DIMENSIONS.includes(dimension)) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'dimension must be owner, service, environment or type' } })
    }
    const { token, user } = req as AuthedRequest
    const model = await buildEstate(token!, user!.id)
    res.json({ data: model.overview().maps[dimension] })
  } catch (error) { fail(res, 'ESTATE_MAP_ERROR', error) }
})

router.get('/map/assets', async (req: Request, res: Response) => {
  try {
    const dimension = req.query.dimension as MapDimension
    const key = req.query.group
    if (!MAP_DIMENSIONS.includes(dimension) || typeof key !== 'string' || key.length > 512) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'A valid map dimension and group are required' } })
    }
    const offset = Math.min(25_000, Math.max(0, Math.floor(Number(req.query.offset) || 0)))
    const limit = Math.min(50, Math.max(1, Math.floor(Number(req.query.limit) || 8)))
    const { token, user } = req as AuthedRequest
    const model = await buildEstate(token!, user!.id)
    const detail = model.mapGroupDetail(dimension, key, offset, limit)
    if (!detail) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'This group is unavailable in the current estate snapshot' } })
    res.json({ data: detail })
  } catch (error) { fail(res, 'ESTATE_MAP_ASSETS_ERROR', error) }
})

export default router
