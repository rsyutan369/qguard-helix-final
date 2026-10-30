import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildOrchestrationSnapshot, type OrchestrationSnapshot, type SourceState } from '@/lib/migration/orchestration-model'
import { isSimulationJob, jobPlanId } from '@/lib/migration/job-safety'
import { jobExecutionClass } from './agent-scanner'
import { isMissingTable, loadAgentFleet, loadPlanApprovals } from './operational-fleet'
import { streamLiveSnapshot } from './live-snapshot-stream'

/**
 * PQC Orchestration snapshot — READ-ONLY.
 *
 * Serves the Migration Timeline and PQC Orchestration pages: every operational
 * migration job, the phase it is in, whether its change was verified, and what
 * unblocks it. The derivation lives in the pure `orchestration-model`, so the
 * pages, this router and `tools/orchestrator-check.ts` read one model.
 *
 * This router used to run a "reconciliation loop" inside the GET handler and
 * the SSE tick — re-queueing any job claimed more than five minutes earlier
 * and every failed job. Agents keep their first `claimedAt`, so a long-running
 * cutover was torn from its executor (whose completion event the agent API
 * then refused) and could be claimed by a second agent. Opening a dashboard
 * must never change a customer's migration. Nothing here writes; operator
 * actions go through Live Migration, which re-checks approval and takes the
 * pre-change snapshot.
 *
 * Auth: Authorization header only. The subscription gateway reads the header,
 * so a `?token=` fallback would also have bypassed the Pro gate.
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
  next()
}
router.use(requireAuth)

const JOB_CAP = 2000
const LOG = '[orchestrator]'

type Row = Record<string, unknown>

/**
 * A read that reports whether it succeeded. A failed query is NOT an empty
 * table: the snapshot carries `sources` so the page can say which evidence is
 * missing instead of rendering a confident zero (issue #15/#16).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function readRows(client: any, table: string, build: (q: any) => any): Promise<{ rows: Row[]; state: SourceState }> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      if (isMissingTable(error)) return { rows: [], state: 'ok' }
      console.warn(`${LOG} ${table} query failed:`, error.message || error)
      return { rows: [], state: 'unavailable' }
    }
    return { rows: (data as Row[]) || [], state: 'ok' }
  } catch (error) {
    console.warn(`${LOG} ${table} query threw:`, (error as Error)?.message || error)
    return { rows: [], state: 'unavailable' }
  }
}

async function computeSnapshot(token: string, userId: string): Promise<OrchestrationSnapshot> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  // Real columns only — `migration_jobs` has no `criticality` column, and one
  // unknown column makes PostgREST reject the whole select.
  const jobs = await readRows(client, 'migration_jobs', (q) =>
    q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at')
      .eq('user_id', userId)
      .order('updated_at', { ascending: false })
      .limit(JOB_CAP),
  )
  const operational = jobs.rows.filter((row) => !isSimulationJob(row))
  const jobIds = operational.map((row) => String(row.id)).slice(0, 1000)
  const assetIds = Array.from(new Set(operational.map((row) => String(row.asset_id || '')).filter(Boolean))).slice(0, 1000)
  const hasJobs = operational.length > 0
  const planIds = Array.from(new Set(operational.map((row) => jobPlanId(row)).filter(Boolean))).slice(0, 200)

  const [planApprovals, agents, validations, events, connectors, assets, planDates] = await Promise.all([
    hasJobs ? loadPlanApprovals(client, userId, operational, LOG) : Promise.resolve({ plans: new Map(), queried: new Set<string>() }),
    loadAgentFleet(client, userId, LOG),
    hasJobs
      ? readRows(client, 'migration_validation_logs', (q) =>
          q.select('id, migration_id, validation_type, status, created_at').eq('user_id', userId).in('migration_id', jobIds).order('created_at', { ascending: false }).limit(4000),
        )
      : Promise.resolve({ rows: [], state: 'ok' as SourceState }),
    hasJobs
      ? readRows(client, 'migration_events', (q) =>
          q.select('id, migration_id, event_type, severity, message, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(300),
        )
      : Promise.resolve({ rows: [], state: 'ok' as SourceState }),
    readRows(client, 'connector_accounts', (q) => q.select('id, provider, status').eq('user_id', userId).limit(400)),
    assetIds.length
      ? readRows(client, 'assets', (q) => q.select('id, name').eq('user_id', userId).in('id', assetIds))
      : Promise.resolve({ rows: [], state: 'ok' as SourceState }),
    // Recorded plan dates for the Migration Timeline. Real columns only
    // (dashboard-schema.sql; written by persistMigrationPlan): `scheduled_at`
    // is the planner's scheduleAt, `approved_at` is stamped only on approval.
    // No target completion date is recorded anywhere, so none is read.
    planIds.length
      ? readRows(client, 'migration_plans', (q) =>
          q.select('id, status, created_at, approved_at, scheduled_at').eq('user_id', userId).in('id', planIds),
        )
      : Promise.resolve({ rows: [], state: 'ok' as SourceState }),
  ])

  // The loader returns nothing queried when its read failed; planned jobs then
  // read "approval unreadable" individually, and the page states why.
  const plansUnread = operational.some((row) => jobPlanId(row)) && planApprovals.queried.size === 0
  return buildOrchestrationSnapshot({
    jobs: jobs.rows,
    executionClassOf: (row) => jobExecutionClass(row),
    plans: planApprovals.plans,
    plansQueried: planApprovals.queried,
    agents,
    validations: validations.rows,
    events: events.rows,
    connectors: connectors.rows,
    assetNames: new Map(assets.rows.map((row) => [String(row.id), String(row.name || '')])),
    sources: {
      jobs: jobs.state,
      plans: plansUnread ? 'unavailable' : 'ok',
      agents: agents ? 'ok' : 'unavailable',
      validations: validations.state,
      events: events.state,
      connectors: connectors.state,
      assets: assets.state,
      schedules: planDates.state,
    },
    jobsTruncated: jobs.rows.length >= JOB_CAP,
    planRecords: new Map(planDates.rows.map((row) => [String(row.id), row])),
  })
}

/* ------------------------------------------------------------------ */
/* Per-tenant single-flight cache                                      */
/* ------------------------------------------------------------------ */

const TTL_MS = 10_000
const cache = new Map<string, { at: number; promise: Promise<OrchestrationSnapshot> }>()

export function buildOrchestration(token: string, userId: string, force = false): Promise<OrchestrationSnapshot> {
  const cached = cache.get(userId)
  if (!force && cached && Date.now() - cached.at < TTL_MS) return cached.promise
  const promise = computeSnapshot(token, userId)
  cache.set(userId, { at: Date.now(), promise })
  promise.catch(() => cache.delete(userId))
  if (cache.size > 500) {
    const now = Date.now()
    for (const [key, value] of cache) if (now - value.at > TTL_MS) cache.delete(key)
  }
  return promise
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    res.json({ data: await buildOrchestration(token!, user!.id, req.query.refresh === '1') })
  } catch (error) {
    console.error(`${LOG} snapshot failed:`, error)
    res.status(500).json({ error: { code: 'ORCHESTRATOR_ERROR', message: 'Unable to build the orchestration snapshot' } })
  }
})

/** Full frame when content changes, `orchestrator-unchanged` otherwise (live-snapshot-stream contract). */
router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, {
    event: 'orchestrator',
    build: () => buildOrchestration(token!, user!.id),
    intervalMs: 10_000,
  })
})

/**
 * GET /jobs/:id — execution history and audit evidence for one job: its full
 * event log and every validation record, newest first. Tenant-scoped through
 * the caller's RLS client and an explicit `user_id` filter.
 */
router.get('/jobs/:id', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const id = String(req.params.id || '').trim()
    if (!/^[0-9a-f-]{8,64}$/i.test(id)) {
      return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'A job id is required' } })
    }
    const snapshot = await buildOrchestration(token!, user!.id)
    const job = snapshot.jobs.find((row) => row.id === id) || null
    const client = createAuthClient(token!)
    if (!client) throw new Error('Database connection failed')
    const [owned, events, validations] = await Promise.all([
      job ? Promise.resolve({ rows: [{ id }], state: 'ok' as SourceState }) : readRows(client, 'migration_jobs', (q) => q.select('id').eq('user_id', user!.id).eq('id', id).limit(1)),
      readRows(client, 'migration_events', (q) =>
        q.select('id, event_type, severity, message, metadata, created_at').eq('user_id', user!.id).eq('migration_id', id).order('created_at', { ascending: false }).limit(200),
      ),
      readRows(client, 'migration_validation_logs', (q) =>
        q.select('id, validation_type, status, agent_id, evidence, created_at').eq('user_id', user!.id).eq('migration_id', id).order('created_at', { ascending: false }).limit(100),
      ),
    ])
    if (!owned.rows.length) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Migration job not found' } })
    res.json({
      data: {
        job,
        events: events.rows,
        validations: validations.rows,
        sources: { events: events.state, validations: validations.state },
      },
    })
  } catch (error) {
    console.error(`${LOG} job detail failed:`, error)
    res.status(500).json({ error: { code: 'ORCHESTRATOR_ERROR', message: 'Unable to load the job history' } })
  }
})

export default router
