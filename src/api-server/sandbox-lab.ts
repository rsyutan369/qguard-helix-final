import { Router, type Request, type Response } from 'express'
import { z } from 'zod'
import { createAuthClient, getServiceClient } from '@/lib/supabase-server'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { LAB_BASELINE, LAB_PRIMITIVES, LAB_TLS_GROUPS, labReadiness, tlsCertificateFor, type LabAsset, type LabResult, type LabRun } from '@/lib/migration/sandbox-lab'
import { buildPortfolio } from './migration-planner'
import { streamLiveSnapshot } from './live-snapshot-stream'
import { analyzeLabProposal, buildLabTasks, labCapabilities, runLabWorker } from './sandbox-lab-engine'

type LabRequest = Request & { user?: { id: string }; token?: string }
type Row = LabRun & { user_id: string }
type Db = NonNullable<ReturnType<typeof getServiceClient>>
const router = Router()
const table = 'sandbox_lab_runs'
const fields = 'id,asset_id,source_plan_id,attached_plan_id,attached_at,configuration,asset_snapshot,status,current_operation,results,planned_checks,logs,error,created_at,started_at,finished_at,cleanup_status,updated_at'
const uuid = z.string().uuid()
const planId = z.string().trim().min(1).max(180)
const listings = createSingleFlightCache<{ runs: LabRun[]; total: number }>(1_500)
const createInput = z.object({
  assetId: uuid,
  sourcePlanId: planId.optional(),
  configuration: z.object({
    primitives: z.array(z.enum(LAB_PRIMITIVES)).max(4),
    tlsGroups: z.array(z.enum(LAB_TLS_GROUPS)).max(2),
    testDetected: z.boolean(),
    compareTlsBaseline: z.boolean(),
    analysis: z.boolean(),
  }).strict(),
}).strict()

function fail(res: Response, status: number, message: string) {
  return res.status(status).json({ error: { message } })
}

function context(req: LabRequest) {
  const client = req.token ? createAuthClient(req.token) : null
  return { client, userId: req.user?.id || '' }
}

async function runList(client: Db, userId: string) {
  return listings.get(userId, async () => {
    const { data: runs, count, error } = await client.from(table).select(fields, { count: 'exact' })
      .eq('user_id', userId).order('created_at', { ascending: false }).limit(100)
    if (error) throw new Error('Lab history is unavailable. Confirm that the sandbox lab schema is installed on this database.')
    return { runs: (runs || []) as unknown as LabRun[], total: count ?? 0 }
  })
}

async function originalAsset(token: string, userId: string, assetId: string): Promise<LabAsset | null> {
  const portfolio = await buildPortfolio(token, userId, true)
  const row = portfolio.assets.find((asset) => asset.id === assetId)
  if (!row) return null
  const {
    id, name, type, hostname, environment, owner, hasEvidence, postureLabel, riskLevel, riskScore, hndlLevel, hndlScore,
    discoveredAt, lastEvidenceAt, migrationStatus, algorithms, certificates, tlsConfiguration, findings,
    vulnerableComponentCount, dependencies, recommendations, compatibility,
  } = row
  return {
    id, name, type, hostname, environment, owner, hasEvidence, postureLabel, riskLevel, riskScore, hndlLevel, hndlScore,
    discoveredAt, lastEvidenceAt, migrationStatus, tlsConfiguration, vulnerableComponentCount, compatibility,
    algorithms: algorithms.slice(0, 40), certificates: certificates.slice(0, 30), findings: findings.slice(0, 40),
    dependencies: dependencies.slice(0, 60), recommendations: recommendations.slice(0, 15),
  }
}

async function eligiblePlan(client: Db, userId: string, id: string, assetId: string) {
  const { data, error } = await client.from('migration_plans').select('id')
    .eq('user_id', userId).eq('id', id).neq('status', 'migration_queue')
    .contains('selected_asset_ids', [assetId]).maybeSingle()
  if (error) throw new Error('The migration plan could not be verified.')
  return data !== null
}

router.get('/capabilities', async (req: LabRequest, res) => {
  const { client } = context(req)
  const [data, schema] = await Promise.all([labCapabilities(), client?.from(table).select(fields).limit(0)])
  const storage = schema && !schema.error ? 'available' : 'unavailable'
  return res.json({ data: { ...data, storage, executor: storage === 'available' && Boolean(getServiceClient()) } })
})

router.get('/runs', async (req: LabRequest, res) => {
  const { client, userId } = context(req)
  if (!client) return fail(res, 503, 'The database connection is unavailable.')
  try { return res.json({ data: await runList(client, userId) }) }
  catch (err) { return fail(res, 503, (err as Error).message) }
})

router.get('/stream', (req: LabRequest, res) => {
  const { client, userId } = context(req)
  if (!client) return fail(res, 503, 'The database connection is unavailable.')
  const selectedId = uuid.safeParse(req.query.runId)
  streamLiveSnapshot(req, res, {
    event: 'sandbox-lab',
    build: async () => {
      const listing = await runList(client, userId)
      if (!selectedId.success || listing.runs.some((run) => run.id === selectedId.data)) return listing
      const { data, error } = await client.from(table).select(fields).eq('id', selectedId.data).eq('user_id', userId).maybeSingle()
      if (error) throw new Error('The selected sandbox session could not be refreshed.')
      return data ? { ...listing, runs: [data as unknown as LabRun, ...listing.runs] } : listing
    },
    intervalMs: 2_500,
  })
})

router.get('/runs/:id', async (req: LabRequest, res) => {
  const { client, userId } = context(req)
  const id = uuid.safeParse(req.params.id)
  if (!id.success) return fail(res, 404, 'Sandbox session not found.')
  if (!client) return fail(res, 503, 'The database connection is unavailable.')
  const { data, error } = await client.from(table).select(fields).eq('user_id', userId).eq('id', id.data).maybeSingle()
  if (error) return fail(res, 503, 'The sandbox session could not be loaded.')
  if (!data) return fail(res, 404, 'Sandbox session not found.')
  return res.json({ data })
})

router.post('/runs', async (req: LabRequest, res) => {
  const { client, userId } = context(req)
  const service = getServiceClient()
  const data = createInput.safeParse(req.body)
  if (!data.success) return fail(res, 400, 'Choose one recorded asset and up to four primitive profiles and two TLS profiles.')
  if (!client || !service || !req.token) return fail(res, 503, 'The lab executor or database is unavailable.')
  const { assetId, sourcePlanId } = data.data
  const configuration = data.data.configuration
  configuration.primitives = [...new Set(configuration.primitives)]
  configuration.tlsGroups = [...new Set(configuration.tlsGroups)]
  if (!configuration.primitives.length && !configuration.tlsGroups.length && !configuration.analysis &&
    !configuration.testDetected && !configuration.compareTlsBaseline) return fail(res, 400, 'Select at least one test or analytical review.')
  try {
    const hasProcessTest = configuration.primitives.length || configuration.tlsGroups.length || configuration.testDetected || configuration.compareTlsBaseline
    if (hasProcessTest) {
      const capabilities = await labCapabilities()
      if (!capabilities.worker || configuration.primitives.some((name) => !capabilities.primitives[name]) ||
        configuration.tlsGroups.some((name) => !capabilities.tlsCertificates[name][tlsCertificateFor(configuration)])) {
        return fail(res, 422, 'At least one selected check is unavailable on this lab runtime. Refresh provider capabilities and update the profile.')
      }
    }
    const asset = await originalAsset(req.token, userId, assetId)
    if (!asset) return fail(res, 404, 'The asset was not found in your inventory.')
    if (!asset.hasEvidence) return fail(res, 422, 'Run an assessment for this asset before creating the sandbox.')
    if (sourcePlanId && !await eligiblePlan(client, userId, sourcePlanId, assetId)) return fail(res, 404, 'The plan does not contain this asset.')
    const at = new Date().toISOString()
    const { data: run, error } = await service.from(table).insert({
      user_id: userId, asset_id: assetId, source_plan_id: sourcePlanId ?? null, asset_snapshot: asset, configuration,
      logs: [{ at, message: 'Asset assessment recorded and lab session queued.' }],
    }).select(fields).single()
    if (error?.code === '23505') return fail(res, 409, 'This workspace already has a queued or running lab session.')
    if (error) return fail(res, 503, 'The sandbox session could not be persisted. Confirm that the lab schema is installed.')
    listings.delete(userId)
    startSandboxLabScheduler()
    wakeLab?.()
    return res.status(202).json({ data: run })
  } catch (err) {
    console.warn('[sandbox-lab] run creation failed', (err as Error).message)
    return fail(res, 503, 'The sandbox could not retrieve the required inventory or plan evidence.')
  }
})

router.post('/runs/:id/cancel', async (req: LabRequest, res) => {
  const { userId } = context(req)
  const id = uuid.safeParse(req.params.id)
  if (!id.success) return fail(res, 404, 'Sandbox session not found.')
  const service = getServiceClient()
  if (!service) return fail(res, 503, 'The database connection is unavailable.')
  const at = new Date().toISOString()
  const write = (status: string, patch: Record<string, unknown>) => service.from(table)
    .update({ ...patch, updated_at: at }).eq('user_id', userId).eq('id', id.data).eq('status', status).select(fields).maybeSingle()
  const queued = await write('queued', { status: 'cancelled', current_operation: 'Cancelled before initialization', cleanup_status: 'released', finished_at: at })
  if (queued.error) return fail(res, 503, 'The cancellation could not be recorded.')
  if (queued.data) {
    listings.delete(userId)
    return res.json({ data: queued.data })
  }
  const active = await write('running', { status: 'cancelling', current_operation: 'Ending the isolated lab process' })
  if (active.error) return fail(res, 503, 'The cancellation could not be recorded.')
  if (!active.data) return fail(res, 409, 'There is no cancellable session with that identifier in this workspace.')
  listings.delete(userId)
  return res.json({ data: active.data })
})

router.post('/runs/:id/attach', async (req: LabRequest, res) => {
  const { client, userId } = context(req)
  const service = getServiceClient()
  const id = uuid.safeParse(req.params.id)
  const plan = planId.safeParse(req.body?.planId)
  if (!id.success || !plan.success) return fail(res, 400, 'Choose a completed lab run and a migration plan.')
  if (!client || !service) return fail(res, 503, 'The database connection is unavailable.')
  try {
    const { data, error } = await client.from(table).select(fields).eq('id', id.data).eq('user_id', userId).maybeSingle()
    if (error) return fail(res, 503, 'The lab evidence could not be loaded.')
    if (!data) return fail(res, 404, 'Lab evidence was not found in this workspace.')
    const run = data as unknown as LabRun
    if (run.status !== 'finished' || !run.asset_id || run.cleanup_status !== 'released' ||
      !run.results.some((check) => check.level !== 'analysis' && check.profile !== LAB_BASELINE && check.status === 'passed')) {
      return fail(res, 409, 'Attach a completed, cleaned-up run with a passing proposed execution or emulation check.')
    }
    if (run.attached_plan_id === plan.data) return res.json({ data: run })
    if (run.attached_plan_id) return fail(res, 409, 'This evidence is already attached to a different plan.')
    if (!await eligiblePlan(client, userId, plan.data, run.asset_id)) return fail(res, 404, 'The plan does not contain the tested asset.')
    const at = new Date().toISOString()
    const { data: attached, error: updateError } = await service.from(table)
      .update({ attached_plan_id: plan.data, attached_at: at, updated_at: at, logs: [...run.logs, { at, message: 'Lab evidence attached to a migration proposal.' }] })
      .eq('id', id.data).eq('user_id', userId).eq('status', 'finished').is('attached_plan_id', null).select(fields).maybeSingle()
    if (updateError) return fail(res, 503, 'The attachment could not be saved.')
    if (!attached) return fail(res, 409, 'The evidence link changed. Refresh the run.')
    listings.delete(userId)
    return res.json({ data: attached })
  } catch {
    return fail(res, 503, 'The plan could not be verified.')
  }
})

router.get('/runs/:id/report', async (req: LabRequest, res) => {
  const { client, userId } = context(req)
  const id = uuid.safeParse(req.params.id)
  if (!id.success) return fail(res, 404, 'Sandbox session not found.')
  if (!client) return fail(res, 503, 'The database connection is unavailable.')
  const { data, error } = await client.from(table).select(fields).eq('id', id.data).eq('user_id', userId).maybeSingle()
  if (error) return fail(res, 503, 'The report could not retrieve the persisted test evidence.')
  if (!data) return fail(res, 404, 'Sandbox session not found.')
  const run = data as unknown as LabRun
  const report = {
    kind: 'qguard-sandbox-evidence', version: 1, generatedAt: new Date().toISOString(),
    readiness: labReadiness(run), run,
  }
  res.set('Content-Disposition', `attachment; filename="sandbox-${id.data}.json"`)
  return res.json(report)
})

const schedulerKey = Symbol.for('qguard.sandbox-lab.scheduler')
const slots = 2
let wakeLab: (() => void) | undefined

async function updateRun(client: Db, job: Row, patch: Record<string, unknown>, status: string) {
  const result = await client.from(table).update({ ...patch, updated_at: new Date().toISOString() })
    .eq('id', job.id).eq('user_id', job.user_id).eq('status', status).select('id').maybeSingle()
  if (result.data) listings.delete(job.user_id)
  return result
}

async function processRun(client: Db, run: Row) {
  const controller = new AbortController()
  const results: LabResult[] = []
  const logs = [...run.logs]
  const append = (message: string) => logs.push({ at: new Date().toISOString(), message })
  let writes: Promise<void> = Promise.resolve()
  let writeFailure = false
  let checking = false
  let plannedChecks = 0
  const cancellation = setInterval(async () => {
    if (checking || controller.signal.aborted) return
    checking = true
    try {
      const { data } = await client.from(table).select('status').eq('id', run.id).eq('user_id', run.user_id).maybeSingle()
      if (data?.status === 'cancelling') controller.abort()
    } catch {
      // A temporary read failure must not escape the scheduler or invent state.
    } finally { checking = false }
  }, 500)
  const save = (operation: string) => {
    const atOperation = [...results]
    const logSnapshot = [...logs]
    writes = writes.then(async () => {
      if (writeFailure) return
      const saved = await updateRun(client, run, { current_operation: operation, results: atOperation, planned_checks: plannedChecks, logs: logSnapshot }, 'running')
      if (!saved.error && !saved.data) controller.abort()
      if (saved.error) {
        writeFailure = true
        controller.abort()
      }
    }).catch(() => { writeFailure = true; controller.abort() })
  }
  let failure: string | null = null
  try {
    const prepared = buildLabTasks(run.asset_snapshot, run.configuration)
    plannedChecks = prepared.tasks.length + prepared.results.length + (run.configuration.analysis ? 1 : 0)
    results.push(...prepared.results)
    append(prepared.tasks.length ? 'Initializing restricted local lab process.' : 'Evaluating recorded evidence.')
    save(prepared.tasks.length ? 'Loading runtime and provider' : 'Reviewing asset evidence')
    if (prepared.tasks.length) {
      let delivered = 0
      await runLabWorker({ tasks: prepared.tasks }, (frame) => {
        if (frame.type === 'operation') {
          append(frame.data)
          save(frame.data)
        } else if (frame.type === 'result') {
          delivered++
          results.push(frame.data)
          append(`${frame.data.profile} · ${frame.data.status.replaceAll('_', ' ')}`)
          save('Recording operation evidence')
        }
      }, controller.signal)
      if (delivered !== prepared.tasks.length) throw new Error('The lab process did not return every requested result.')
    }
    if (run.configuration.analysis) results.push(analyzeLabProposal(run.asset_snapshot, run.configuration))
  } catch (err) {
    failure = err instanceof Error ? err.message : 'Lab execution was interrupted.'
    append(failure)
  } finally {
    clearInterval(cancellation)
  }
  await writes
  if (writeFailure) failure = 'An intermediate evidence write failed.'
  const finishedAt = new Date().toISOString()
  append('Lab process and ephemeral test material released.')
  const patch = { results, logs, finished_at: finishedAt, lease_expires_at: null, cleanup_status: 'released' }
  const saved = await updateRun(client, run, {
    ...patch, status: failure ? 'failed' : 'finished', error: failure, current_operation: failure ? 'Lab execution failed' : 'Evidence recorded',
  }, 'running')
  if (!saved.error && !saved.data) await updateRun(client, run, { ...patch, status: 'cancelled', current_operation: 'Cancelled and cleaned up' }, 'cancelling')
}

export function startSandboxLabScheduler() {
  if (wakeLab) return
  const client = getServiceClient()
  if (!client) return
  const registry = globalThis as typeof globalThis & { [schedulerKey]?: () => void }
  registry[schedulerKey]?.()
  let stopped = false
  let draining = false
  let active = 0
  let lastSweep = 0
  let storageRetryAt = 0
  const tick = async () => {
    if (stopped || draining || active >= slots || Date.now() < storageRetryAt) return
    draining = true
    try {
      const now = new Date().toISOString()
      if (Date.now() - lastSweep >= 30_000) {
        const { error } = await client.from(table).update({
          status: 'failed', error: 'The lab executor lease expired. Process cleanup could not be confirmed. Re-run the profile.',
          current_operation: 'Executor interrupted', finished_at: now, updated_at: now, cleanup_status: 'interrupted',
        }).in('status', ['running', 'cancelling']).lt('lease_expires_at', now)
        if (error) {
          storageRetryAt = Date.now() + 30_000
          return
        }
        await client.from(table).update({
          status: 'failed', error: 'The session expired while waiting for an executor.', current_operation: 'Queue expired',
          finished_at: now, updated_at: now, cleanup_status: 'released',
        }).eq('status', 'queued').lt('created_at', new Date(Date.now() - 15 * 60_000).toISOString())
        lastSweep = Date.now()
      }
      const { data } = await client.from(table).select('id,user_id').eq('status', 'queued').order('created_at').limit(slots - active)
      for (const candidate of data || []) {
        if (stopped || active >= slots) break
        const { data: claimed } = await client.from(table).update({
          status: 'running', current_operation: 'Preparing isolated environment', started_at: now, updated_at: now,
          lease_expires_at: new Date(Date.now() + 90_000).toISOString(),
        }).eq('id', candidate.id).eq('user_id', candidate.user_id).eq('status', 'queued').select(`${fields},user_id`).maybeSingle()
        if (!claimed) continue
        active++
        void processRun(client, claimed as unknown as Row)
          .catch(() => console.warn('[sandbox-lab] executor interrupted before final persistence'))
          .finally(() => { active--; wakeLab?.() })
      }
    } finally {
      draining = false
    }
  }
  wakeLab = () => { void tick().catch(() => console.warn('[sandbox-lab] scheduler database operation failed')) }
  const timer = setInterval(wakeLab, 3_000)
  timer.unref()
  registry[schedulerKey] = () => { stopped = true; clearInterval(timer) }
  wakeLab()
}

export default router
