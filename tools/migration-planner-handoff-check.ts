/** Exercises the real planner and operations routers against a private storage fixture. */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import express from 'express'
import { isVerifiedMigrationJob, plannerStageAccess } from '../src/lib/migration/planner-progress'

const owner = randomUUID()
const other = randomUUID()
const expiresAt = Math.floor(Date.now() / 1000) + 600
function token(user: string) {
  return [{ alg: 'HS256', typ: 'JWT' }, { sub: user, exp: expiresAt }].map((value) => Buffer.from(JSON.stringify(value)).toString('base64url')).concat('fixture').join('.')
}

const now = new Date().toISOString()
const makeAsset = (name: string, userId = owner) => ({ id: randomUUID(), user_id: userId, name, status: 'active', type: 'service', created_at: now, updated_at: now })
const high = makeAsset('Critical service')
const chosen = makeAsset('Chosen pilot')
const later = makeAsset('Later wave')
const withdrawn = makeAsset('Withdrawn asset')
const unassessed = makeAsset('Unassessed service')
const otherAsset = makeAsset('Other tenant', other)
type Row = Record<string, any>
const tables = new Map<string, Row[]>([
  ['assets', [high, chosen, later, withdrawn, unassessed, otherAsset]],
  ['crypto_inventory', [high, chosen, later, withdrawn, otherAsset].map((asset) => ({
    id: randomUUID(), user_id: asset.user_id, asset_id: asset.id, item_type: 'algorithm', algorithm: 'RSA-2048',
    protocol: 'TLS', is_vulnerable: true, exposure_level: asset === high ? 'critical' : 'medium', created_at: now, discovered_at: now,
  }))],
])
const jobs = () => tables.get('migration_jobs') || []
const db = createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://localhost')
  const auth = [owner, other].find((id) => req.headers.authorization === `Bearer ${token(id)}`)
  const send = (body: unknown, status = 200) => {
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(body))
  }
  if (url.pathname === '/auth/v1/user') {
    return auth ? send({ id: auth, role: 'authenticated', aud: 'authenticated', email: `${auth === owner ? 'owner' : 'other'}@example.test`, user_metadata: {}, app_metadata: {} }) : send({}, 401)
  }
  const table = url.pathname.split('/').at(-1) || ''
  const rows = tables.get(table) || []
  tables.set(table, rows)
  const filters = [...url.searchParams].filter(([key]) => !['select', 'order', 'limit', 'offset', 'on_conflict'].includes(key))
  const matching = rows.filter((row) => {
    if (auth && row.user_id !== auth) return false
    return filters.every(([key, value]) => {
      const candidate = key.split(/->>?/).reduce<any>((object, field) => object?.[field], row)
      if (value.startsWith('eq.')) return String(candidate) === value.slice(3)
      if (value.startsWith('neq.')) return String(candidate) !== value.slice(4)
      if (value.startsWith('in.(')) return value.slice(4, -1).split(',').includes(String(candidate))
      if (value.startsWith('cs.[')) {
        const scope: string[] = JSON.parse(value.slice(3))
        return scope.every((entry) => candidate?.includes(entry))
      }
      return true
    })
  })
  if (req.method === 'HEAD') {
    res.setHeader('Content-Range', `*/${matching.length}`)
    return res.end()
  }
  if (req.method === 'GET') {
    for (const order of (url.searchParams.get('order') || '').split(',').reverse()) {
      if (!order) continue
      const [column, direction] = order.split('.')
      matching.sort((a, b) => (direction === 'desc' ? -1 : 1) * String(a[column] ?? '').localeCompare(String(b[column] ?? '')))
    }
    const offset = Number(url.searchParams.get('offset') ?? 0)
    const found = matching.slice(offset, offset + Number(url.searchParams.get('limit') ?? matching.length))
    if (req.headers.accept?.includes('vnd.pgrst.object')) return send(found.length === 1 ? found[0] : { code: 'PGRST116' }, found.length === 1 ? 200 : 406)
    return send(found)
  }
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  const body = JSON.parse(Buffer.concat(chunks).toString() || '{}')
  if (req.method === 'PATCH') {
    for (const row of matching) Object.assign(row, body)
    return send(matching)
  }
  const incoming: Row[] = Array.isArray(body) ? body : [body]
  const inserted = incoming.map((record) => {
    if (auth) assert.equal(record.user_id, auth, `${table} writes stay in scope`)
    const existing = record.id && rows.find((row) => row.id === record.id)
    if (existing) return Object.assign(existing, record)
    const row = { id: randomUUID(), ...record }
    rows.push(row)
    return row
  })
  return send(inserted, 201)
})

db.listen(0, '127.0.0.1')
await once(db, 'listening')
Object.assign(process.env, {
  VITE_SUPABASE_URL: `http://127.0.0.1:${(db.address() as { port: number }).port}`,
  VITE_SUPABASE_ANON_KEY: 'fixture-anon', SUPABASE_SERVICE_ROLE_KEY: 'fixture-service',
  VITE_SUPABASE_USE_FALLBACK: 'false', SUPABASE_USE_FALLBACK: 'false',
})

const { default: planner } = await import('../src/api-server/migration-planner')
const { default: migration } = await import('../src/api-server/migration')
const { default: estate } = await import('../src/api-server/estate-intelligence')
const { default: exposure } = await import('../src/api-server/exposure-graph')
const { publishAgentEvent } = await import('../src/api-server/agent-event-bus')
const server = express().use(express.json()).use('/planner', planner).use('/migration', migration).use('/estate', estate).use('/exposure', exposure).listen(0, '127.0.0.1')
await once(server, 'listening')
const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`

async function request(path: string, status: number, body?: unknown, user = owner, method = body ? 'POST' : 'GET') {
  const response = await fetch(`${origin}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token(user)}` },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(15_000),
  })
  const payload = await response.json()
  assert.equal(response.status, status, `${method} ${path} ${JSON.stringify(payload.error)}`)
  return payload.data
}

try {
  const scope = [high.id, chosen.id, later.id, withdrawn.id]
  await request('/migration/planner/create', 409, { action: 'start', assetIds: scope })
  await request('/planner/plans', 400, { name: 'Empty proposal' })
  await request('/planner/plans', 409, { name: 'Unqueued proposal', assetIds: scope })
  await request('/planner/queue', 422, { assetIds: [unassessed.id] })
  await request('/planner/queue', 422, { assetIds: [otherAsset.id] })
  await request('/planner/queue', 200, { assetIds: scope })
  const queue = await request('/planner/queue/reorder', 200, { assetIds: [chosen.id, high.id] })
  assert.deepEqual(queue.entries.map((entry: Row) => entry.assetId), [chosen.id, high.id, later.id, withdrawn.id])
  const rejected = await request('/planner/plans', 201, { assetIds: [high.id], name: 'Rejected fixture proposal' })
  await request(`/planner/plans/${rejected.id}/approval`, 200, { decision: 'reject', reason: 'Fixture change was rejected' })
  await request('/migration/planner/create', 409, { action: 'start', approvalPlanId: rejected.id, assetIds: [high.id] })
  const proposal = await request('/planner/plans', 201, { assetIds: scope, name: 'Fixture proposal' })
  const handoff = { action: 'start', approvalPlanId: proposal.id, assetIds: [chosen.id] }
  await request('/planner/plans', 409, { assetIds: [chosen.id], name: 'Duplicate proposal' })
  assert.equal((await request('/planner/queue', 200)).entries[0].reservation, 'submitted')
  await request(`/planner/plans/${proposal.id}/remove-assets`, 404, { assetIds: [withdrawn.id] }, other)
  await request('/migration/planner/create', 409, handoff)
  const approved = await request(`/planner/plans/${proposal.id}/approval`, 200, { decision: 'approve' })
  const editedQueue = await request(`/planner/queue/${chosen.id}`, 200, undefined, owner, 'DELETE')
  assert.deepEqual(editedQueue.entries.map((entry: Row) => entry.assetId), [high.id, later.id, withdrawn.id])
  await request('/migration/planner/create', 422, handoff)
  const handoffReview = { compatibilityEvidence: 'Fixture interoperability check', changeWindow: 'Fixture window', rollbackReference: 'Fixture restore procedure' }
  await request('/migration/planner/create', 409, { ...handoff, handoffReview }, other)
  const sent = await request('/migration/planner/create', 200, { ...handoff, handoffReview })
  const retried = await request('/migration/planner/create', 200, { ...handoff, handoffReview })
  assert.equal(retried.planId, sent.planId)
  const [first] = jobs()
  assert.equal(jobs().length, 1)
  assert.equal(first.asset_id, chosen.id)
  assert.equal(first.status, 'queued')
  tables.set('pqc_scan_results', [chosen, high, otherAsset].map((asset) => ({
    id: randomUUID(), user_id: asset.user_id, asset_id: asset.id, created_at: now,
  })))
  tables.set('crypto_exposures', [chosen, high, otherAsset].map((asset) => ({
    id: randomUUID(), user_id: asset.user_id, asset_id: asset.id, severity: asset === chosen ? 'high' : 'critical',
  })))
  const selected = await request(`/migration/live?planId=${sent.planId}`, 200)
  assert.deepEqual(selected.jobs.map((job: Row) => job.assetId), [chosen.id])
  assert.equal(selected.summary.totalAssets, 1)
  assert.equal(selected.summary.findings, 1)
  assert.equal(selected.summary.highExposures, 1)
  assert.equal(selected.summary.criticalExposures, 0)
  assert.equal(selected.summary.lastScanAt, now)
  await request(`/planner/plans/${sent.planId}/context`, 409, { assetIds: scope })
  await request(`/planner/plans/${sent.planId}/context`, 200, { assetIds: [chosen.id] })
  assert.deepEqual((await request(`/migration/live?planId=${sent.planId}`, 200)).plannerHandoff.assets.map((asset: Row) => asset.assetId), [chosen.id])
  await request('/planner/queue', 409, { assetIds: [chosen.id] })
  await request(`/planner/plans/${proposal.id}/remove-assets`, 409, { assetIds: [chosen.id] })
  const reduced = await request(`/planner/plans/${proposal.id}/remove-assets`, 200, { assetIds: [withdrawn.id] })
  assert.deepEqual(reduced.assetIds, [chosen.id, high.id, later.id])
  assert.equal((await request('/planner/queue', 200)).entries.find((asset: Row) => asset.assetId === withdrawn.id).reservation, null)
  await request('/migration/planner/create', 409, { ...handoff, assetIds: [chosen.id, high.id], handoffReview })
  await request('/migration/planner/create', 409, { ...handoff, assetIds: [withdrawn.id], handoffReview })
  const remaining = await request('/migration/planner/create', 200, { ...handoff, assetIds: [later.id, high.id], handoffReview })
  const [, pilot, second] = jobs()
  assert.notEqual(remaining.planId, sent.planId)
  assert.equal(pilot.asset_id, high.id)
  assert.equal(second.status, 'pending')
  const scoped = await request(`/migration/live?planId=${remaining.planId}`, 200)
  assert.equal(scoped.summary.queued, 1)
  assert.equal(scoped.summary.held, 1)
  assert.equal(scoped.summary.waitingForAgent, 1)
  const proposals = await request('/planner/plans?proposals=1', 200)
  const tracked = proposals.find((row: Row) => row.id === proposal.id)
  assert.equal(tracked.executions.length, 2)
  assert.equal(tracked.executions.find((item: Row) => item.id === sent.planId).handoffReview.rollbackReference, handoffReview.rollbackReference)
  assert.equal(sent.plan.migrationMetadata.approval.decidedAt, approved.approval.decidedAt)
  const actions = `/migration/plans/${remaining.planId}/action`
  await request(actions, 409, { action: 'approve_next_phase' })
  await request(`/migration/jobs/${second.id}/action`, 409, { action: 'resume' })
  pilot.status = 'completed'
  pilot.metadata.assignedAgentId = randomUUID()
  tables.set('migration_execution', [{ id: randomUUID(), user_id: owner, migration_id: pilot.id, status: 'running', progress: 45, updated_at: now }])
  pilot.metadata.lastValidation = { passed: true }
  const pendingValidation = await request(`/migration/live?planId=${remaining.planId}`, 200)
  assert.equal(pendingValidation.summary.completed, 1, 'current job state takes precedence over the previous execution report')
  assert.equal(pendingValidation.summary.verified, 0, 'metadata without a persisted validation record is unverified')
  const validation = { id: randomUUID(), user_id: owner, migration_id: pilot.id, status: 'invalid', created_at: now }
  tables.set('migration_validation_logs', [validation])
  await request(actions, 409, { action: 'approve_next_phase' })
  validation.status = 'passed'
  await request(actions, 200, { action: 'approve_next_phase' })
  assert.equal(pilot.status, 'completed')
  assert.equal(second.status, 'queued')
  const live = await request(`/migration/live?proposalId=${proposal.id}`, 200)
  assert.deepEqual(new Set(live.jobs.map((job: Row) => job.assetId)), new Set(reduced.assetIds))
  assert.equal((await request(`/migration/live?proposalId=${proposal.id}`, 200, undefined, other)).jobs.length, 0)
  const stream = await fetch(`http://127.0.0.1:${(server.address() as { port: number }).port}/migration/live/stream?planId=${remaining.planId}`, {
    headers: { Authorization: `Bearer ${token(owner)}` }, signal: AbortSignal.timeout(15_000),
  })
  assert.equal(stream.status, 200)
  const reader = stream.body!.pipeThrough(new TextDecoderStream()).getReader()
  try {
    let buffer = ''
    let frame: string | undefined
    while (!frame) {
      const chunk = await reader.read()
      assert.equal(chunk.done, false)
      buffer += chunk.value
      frame = buffer.split('\n\n').slice(0, -1).find((part) => part.includes('event: migration-update'))
    }
    const payload = JSON.parse(frame.split('\ndata: ')[1])
    assert.deepEqual(new Set(payload.jobs.map((job: Row) => job.assetId)), new Set([high.id, later.id]))
    second.status = 'running'
    second.progress = 53
    second.metadata.assignedAgentId = randomUUID()
    publishAgentEvent(owner, 'agent.scan_progress', randomUUID(), { target: withdrawn.name })
    publishAgentEvent(owner, 'agent.migration_progress', second.metadata.assignedAgentId, { jobId: second.id, assetId: later.id })
    buffer = ''
    frame = undefined
    while (!frame) {
      const chunk = await reader.read()
      assert.equal(chunk.done, false)
      buffer += chunk.value
      assert(!buffer.includes('event: agent-event'), 'a scoped stream must not include unrelated raw tenant events')
      frame = buffer.split('\n\n').slice(0, -1).find((part) => part.includes('event: migration-update'))
    }
    const update = JSON.parse(frame.split('\ndata: ')[1])
    assert.equal(update.jobs.find((job: Row) => job.id === second.id).progress, 53)
    assert.equal(update.summary.running, 1)
  } finally { await reader.cancel() }
  const verified = live.jobs.filter(isVerifiedMigrationJob)
  assert.deepEqual(verified.map((job: Row) => job.id), [pilot.id])
  assert.equal(plannerStageAccess({ queued: false, proposed: true, approved: true, verified: verified.length === 3 }).analytics, false)
  second.status = 'completed'
  second.metadata.assignedAgentId = randomUUID()
  first.status = 'completed'
  first.metadata.assignedAgentId = randomUUID()
  for (const job of [first, second]) tables.get('migration_validation_logs')!.push({ ...validation, id: randomUUID(), migration_id: job.id })
  const verifiedFinal = (await request(`/migration/live?proposalId=${proposal.id}`, 200)).jobs.filter(isVerifiedMigrationJob)
  assert.equal(plannerStageAccess({ queued: false, proposed: true, approved: true, verified: verifiedFinal.length === 3 }).analytics, true)

  const cancellationPlan = await request('/planner/plans', 201, { assetIds: [withdrawn.id], name: 'Cancellation fixture' })
  await request(`/planner/plans/${cancellationPlan.id}/approval`, 200, { decision: 'approve' })
  const toCancel = await request('/migration/planner/create', 200, { action: 'start', approvalPlanId: cancellationPlan.id, assetIds: [withdrawn.id], handoffReview })
  const cancelledJobId = toCancel.jobs[0].id
  await request(`/migration/jobs/${cancelledJobId}/action`, 404, { action: 'cancel', planId: sent.planId })
  const result = await request(`/migration/jobs/${cancelledJobId}/action`, 200, { action: 'cancel', planId: toCancel.planId })
  assert.deepEqual(result.snapshot.jobs.map((job: Row) => job.id), [cancelledJobId])
  const removed = await request(`/planner/plans/${cancellationPlan.id}/remove-assets`, 200, { assetIds: [withdrawn.id] })
  assert.equal(removed.status, 'withdrawn')
  assert.equal((await request(`/migration/live?planId=${toCancel.planId}`, 200)).jobs[0].status, 'cancelled')
  assert.equal((await request(`/migration/live?proposalId=${cancellationPlan.id}`, 200)).jobs.length, 0)
  console.log('PASS selective handoff, duplicate checks, submitted asset removal, tenant scope, approval gates, wave validation and scoped SSE')

  const overview = await request('/estate', 200)
  assert.equal(overview.summary.assets, 5)
  assert.equal((await request('/estate', 200, undefined, other)).summary.assets, 1)
  assert.equal((await fetch(`${origin}/estate/stream`)).status, 401)
  const estateStream = await fetch(`${origin}/estate/stream`, {
    headers: { Authorization: `Bearer ${token(owner)}` }, signal: AbortSignal.timeout(45_000),
  })
  assert.match(estateStream.headers.get('content-type') ?? '', /^text\/event-stream/)
  const estateReader = estateStream.body!.pipeThrough(new TextDecoderStream()).getReader()
  let buffer = ''
  const readEstate = async (event = 'estate-intelligence') => {
    for (;;) {
      const end = buffer.indexOf('\n\n')
      if (end !== -1) {
        const frame = buffer.slice(0, end)
        buffer = buffer.slice(end + 2)
        if (frame.startsWith(`event: ${event}\n`)) return JSON.parse(frame.split('\ndata: ')[1])
        assert(!frame.startsWith('event: estate-intelligence-error\n'), frame)
        continue
      }
      const chunk = await estateReader.read()
      assert.equal(chunk.done, false)
      buffer += chunk.value
    }
  }
  try {
    assert.equal((await readEstate()).fingerprint, overview.fingerprint)
    // A name change updates the details while leaving the KPI counts intact.
    chosen.name = 'Renamed pilot fixture'
    otherAsset.name = 'Isolated tenant change'
    const updated = await request('/estate?refresh=1', 200)
    const frame = await readEstate()
    assert.equal(frame.fingerprint, updated.fingerprint)
    assert.notEqual(frame.revision, overview.revision)
    assert.deepEqual(frame.summary, overview.summary)
    const graph = await request(`/estate/graph?level=neighbourhood&focus=asset:${chosen.id}`, 200)
    assert.equal(graph.revision, frame.revision)
    assert.equal(graph.assets.find((asset: Row) => asset.id === chosen.id).name, chosen.name)
    await request(`/estate/graph?level=neighbourhood&focus=asset:${chosen.id}`, 404, undefined, other)
    const unchanged = await readEstate('estate-intelligence-unchanged')
    assert.equal(unchanged.fingerprint, frame.fingerprint)
    assert(Date.parse(unchanged.checkedAt) > Date.parse(frame.generatedAt))
    console.log('PASS estate tenant isolation, authenticated SSE, detail-only revisions and unchanged frames')
  } finally {
    await estateReader.cancel()
  }

  const findings = [
    { id: randomUUID(), user_id: owner, asset_id: chosen.id, algorithm: 'Fixture certificate finding', threat_level: 'high', description: 'Recorded certificate evidence', created_at: now },
    { id: randomUUID(), user_id: owner, asset_id: chosen.id, algorithm: 'Fixture configuration finding', threat_level: 'low', description: 'Recorded configuration evidence', created_at: now },
    { id: randomUUID(), user_id: other, asset_id: otherAsset.id, algorithm: 'Other tenant finding', threat_level: 'critical', created_at: now },
  ]
  tables.set('pqc_scan_results', findings)
  assert.equal((await fetch(`${origin}/exposure/stream?token=${token(owner)}`)).status, 401)
  await request(`/exposure/assets/${otherAsset.id}/findings`, 404)
  await request(`/exposure/assets/${chosen.id}/findings`, 404, undefined, other)
  const graph = await request('/exposure', 200)
  const chosenNode = (data: Row) => data.graph.nodes.find((node: Row) => node.id === chosen.id)
  const page = await request(`/exposure/assets/${chosen.id}/findings?limit=1&offset=1`, 200)
  assert.equal(page.total, chosenNode(graph).findingsCount)
  assert.equal(page.revision, chosenNode(graph).findingsRevision)
  assert.equal(page.findings.length, 1)
  assert.equal(page.offset, 1)
  const all = await request(`/exposure/assets/${chosen.id}/findings`, 200)
  assert(all.findings.some((finding: Row) => finding.description === findings[0].description))
  assert(all.findings.some((finding: Row) => finding.severity === 'low'))
  assert(!all.findings.some((finding: Row) => finding.algorithm === findings[2].algorithm))

  const exposureStream = await fetch(`${origin}/exposure/stream`, {
    headers: { Authorization: `Bearer ${token(owner)}` }, signal: AbortSignal.timeout(40_000),
  })
  assert.match(exposureStream.headers.get('content-type') ?? '', /^text\/event-stream/)
  const exposureReader = exposureStream.body!.pipeThrough(new TextDecoderStream()).getReader()
  let exposureBuffer = ''
  const readExposure = async () => {
    for (;;) {
      const end = exposureBuffer.indexOf('\n\n')
      if (end >= 0) {
        const frame = exposureBuffer.slice(0, end)
        exposureBuffer = exposureBuffer.slice(end + 2)
        if (frame.startsWith('event: exposure-intelligence\n')) return JSON.parse(frame.split('\ndata: ')[1])
        assert(!frame.startsWith('event: exposure-intelligence-error\n'), frame)
        continue
      }
      const chunk = await exposureReader.read()
      assert.equal(chunk.done, false)
      exposureBuffer += chunk.value
    }
  }
  try {
    assert.equal((await readExposure()).fingerprint, graph.fingerprint)
    findings[0].description = 'Updated certificate evidence'
    const updated = await readExposure()
    assert.equal(chosenNode(updated).findingsCount, chosenNode(graph).findingsCount)
    assert.notEqual(chosenNode(updated).findingsRevision, chosenNode(graph).findingsRevision)
    const updatedFindings = await request(`/exposure/assets/${chosen.id}/findings`, 200)
    assert.equal(updatedFindings.revision, chosenNode(updated).findingsRevision)
    assert(updatedFindings.findings.some((finding: Row) => finding.description === findings[0].description))
    console.log('PASS exposure graph tenant isolation, paginated findings, shared snapshot revision and detail-only SSE updates')
  } finally {
    await exposureReader.cancel()
  }
} finally {
  server.closeAllConnections()
  server.close()
  db.closeAllConnections()
  db.close()
}
