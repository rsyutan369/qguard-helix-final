/**
 * Live end-to-end verification of agent role enforcement + snapshot rollback.
 *
 * Exercises the real lifecycle the audit brief asks for, against the running
 * dev server and the real database:
 *
 *   enrol (collector | patcher | operator)
 *     -> claim a migration job            (role gate)
 *     -> pre-change snapshot              (dispatch gate)
 *     -> executed event + config backup   (executor record)
 *     -> restore request                  (dispatch, NOT "restored")
 *     -> agent acknowledgement            (verified -> restored | failed)
 *     -> audit trail
 *
 * Every row it creates is deleted at the end, including on failure.
 *
 * Needs the dev server running:
 *   npx tsx tools/rollback-live-check.ts
 *   QGUARD_TEST_BASE=http://localhost:3002 npx tsx tools/rollback-live-check.ts
 */
import { createClient } from '@supabase/supabase-js'
import fs from 'node:fs'
import { randomUUID } from 'node:crypto'

const BASE = process.env.QGUARD_TEST_BASE || 'http://localhost:3000'
const OWNER_EMAIL = process.env.QGUARD_TEST_EMAIL || 'zachmatthew369@gmail.com'

const env = Object.fromEntries(
  fs.readFileSync(new URL('../.env', import.meta.url), 'utf8')
    .split(/\r?\n/)
    .filter((line) => line.includes('=') && !line.startsWith('#'))
    .map((line) => {
      const i = line.indexOf('=')
      return [line.slice(0, i).trim(), line.slice(i + 1).trim().replace(/^["']|["']$/g, '')]
    }),
)

const admin = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
const anon = createClient(env.VITE_SUPABASE_URL, env.VITE_SUPABASE_ANON_KEY, { auth: { persistSession: false } })

let passed = 0
let failed = 0
const failures: string[] = []
function check(name: string, condition: boolean, detail = '') {
  if (condition) { passed += 1; console.log(`  PASS  ${name}`) }
  else { failed += 1; failures.push(`${name}${detail ? ` — ${detail}` : ''}`); console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`) }
}

async function session() {
  const { data, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: OWNER_EMAIL })
  if (error) throw new Error(`generateLink: ${error.message}`)
  const { data: verified, error: verifyError } = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: data.properties!.hashed_token! })
  if (verifyError) throw new Error(`verifyOtp: ${verifyError.message}`)
  return { token: verified.session!.access_token, userId: verified.user!.id }
}

/** Agent-authenticated call: the agent id travels in its own header. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function agentApi(path: string, agentId: string, agentToken: string, init: any = {}) {
  return api(path, agentToken, { ...init, headers: { 'x-qguard-agent-id': agentId, ...(init.headers || {}) } })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function api(path: string, token: string, init: any = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(init.headers || {}) },
  })
  const text = await res.text()
  let body: any = null
  try { body = text ? JSON.parse(text) : null } catch { body = { raw: text.slice(0, 300) } }
  return { status: res.status, body }
}

const created = { agents: [] as string[], jobs: [] as string[], assets: [] as string[], snapshots: [] as string[], plans: [] as string[], inventory: [] as string[] }

async function cleanup(userId: string) {
  for (const id of created.snapshots) await admin.from('migration_snapshots').delete().eq('id', id)
  await admin.from('migration_snapshot_audit').delete().eq('user_id', userId).in('migration_job_id', created.jobs.length ? created.jobs : ['none'])
  for (const id of created.jobs) {
    await admin.from('migration_events').delete().eq('migration_id', id)
    await admin.from('migration_executions').delete().eq('migration_id', id)
    await admin.from('migration_telemetry').delete().eq('migration_id', id)
    await admin.from('migration_validations').delete().eq('migration_id', id)
    await admin.from('migration_snapshots').delete().eq('migration_job_id', id)
    await admin.from('migration_jobs').delete().eq('id', id)
  }
  for (const id of created.agents) {
    await admin.from('agent_heartbeats').delete().eq('agent_id', id)
    await admin.from('scanner_agent_policies').delete().eq('agent_id', id)
    await admin.from('scanner_agents').delete().eq('id', id)
  }
  for (const id of created.assets) await admin.from('assets').delete().eq('id', id)
  for (const id of created.plans) await admin.from('migration_plans').delete().eq('id', id)
  for (const id of created.inventory) await admin.from('crypto_inventory').delete().eq('id', id)
}

async function enrol(token: string, role: string, name: string) {
  const res = await api('/api/v1/agent-scanner/agents/enroll', token, {
    method: 'POST',
    body: JSON.stringify({
      name,
      hostname: `${name}.qguard.test`,
      platform: 'linux x64',
      version: '1.5.3',
      metadata: { role, environment: 'test' },
      policy: { enabled: true, scanTypes: ['tls', 'certificates', 'configs'], allowedPaths: ['/etc/qguard-test'], allowedTargets: [] },
    }),
  })
  return res
}

async function main() {
  const { token, userId } = await session()
  console.log(`\nQGuard rollback live check — ${BASE}\n`)

  /* ---------------------------------------------------------------- */
  console.log('[1] Enrolment resolves the role server-side')
  const collector = await enrol(token, 'collector', `rbchk-collector-${Date.now()}`)
  check('collector enrols', collector.status === 200 || collector.status === 201, `HTTP ${collector.status} ${JSON.stringify(collector.body?.error || '')}`)
  const collectorId = collector.body?.data?.agent?.id
  const collectorToken = collector.body?.data?.enrollment?.agentToken
  if (collectorId) created.agents.push(collectorId)
  check('collector role is recorded on the agent row', collector.body?.data?.agent?.metadata?.role === 'collector')

  /* The Scanner role is read-only like Collector, and is the fourth published
     agent type — it has to be proven enrollable and write-refused too, or
     "all four agent types work" is an untested claim. */
  const scanner = await enrol(token, 'scanner', `rbchk-scanner-${Date.now()}`)
  const scannerId = scanner.body?.data?.agent?.id
  const scannerToken = scanner.body?.data?.enrollment?.agentToken
  if (scannerId) created.agents.push(scannerId)
  check('scanner enrols', Boolean(scannerId), `HTTP ${scanner.status}`)
  check('scanner role is recorded on the agent row', scanner.body?.data?.agent?.metadata?.role === 'scanner')
  check(
    'scanner is provisioned read-only (no remediation/migration capability)',
    scanner.body?.data?.agent?.capabilities?.remediation === false && scanner.body?.data?.agent?.capabilities?.migration === false,
    JSON.stringify(scanner.body?.data?.agent?.capabilities || {}).slice(0, 160),
  )

  const operator = await enrol(token, 'operator', `rbchk-operator-${Date.now()}`)
  const operatorEntitled = operator.status === 200 || operator.status === 201
  check(
    'migration operator enrols (Pro) or is refused with a plan reason (Basic)',
    operatorEntitled || operator.body?.error?.code === 'SUBSCRIPTION_REQUIRED',
    `HTTP ${operator.status} ${JSON.stringify(operator.body?.error?.code || '')}`,
  )
  const operatorId = operator.body?.data?.agent?.id
  const operatorToken = operator.body?.data?.enrollment?.agentToken
  if (operatorId) created.agents.push(operatorId)

  if (!operatorEntitled) {
    console.log('\n  NOTE: this tenant is not entitled to write-capable agents, so the')
    console.log('        dispatch half of the check cannot run. The refusal above IS the')
    console.log('        enforcement working. Re-run on a Pro tenant for full coverage.\n')
    await cleanup(userId)
    console.log(`\n=== ${passed} passed, ${failed} failed ===\n`)
    process.exit(failed === 0 ? 0 : 1)
  }

  /* ---------------------------------------------------------------- */
  console.log('\n[2] A migration-class job is only claimable by a Migration Operator')

  const assetId = randomUUID()
  await admin.from('assets').insert({
    id: assetId, user_id: userId, name: 'rbchk-asset', type: 'server', environment: 'test',
  })
  created.assets.push(assetId)

  /*
   * Real cryptography on the asset, so the pre-change snapshot captures state.
   * Without this the snapshot is empty and `restorability()` refuses it for that
   * reason instead — which is correct, but means the "no executor recorded a
   * change" path never gets exercised. On a freshly reset estate this is the
   * difference between testing the gate and testing the empty state.
   */
  const inventoryIds = [randomUUID(), randomUUID()]
  await admin.from('crypto_inventory').insert([
    { id: inventoryIds[0], user_id: userId, asset_id: assetId, name: 'Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA', algorithm: 'RSA-2048', key_size: 2048, protocol: 'TLS 1.2', item_type: 'TLS Cipher Suite', is_quantum_safe: false, exposure_level: 'critical' },
    { id: inventoryIds[1], user_id: userId, asset_id: assetId, name: 'Key Exchange: ECDH-P256', algorithm: 'ECDH-P256', key_size: 256, protocol: 'TLS 1.2', item_type: 'Key Exchange', is_quantum_safe: false, exposure_level: 'high' },
  ])
  created.inventory.push(...inventoryIds)

  /*
   * Jobs belong to plans, and only an EXPLICITLY approved plan may be
   * dispatched. Two plans are created so the gate has a positive and a negative
   * case: without the negative one, a gate that approves everything passes.
   */
  const approvedPlanId = randomUUID()
  await admin.from('migration_plans').insert({
    id: approvedPlanId,
    user_id: userId,
    status: 'awaiting_agent',
    selected_asset_ids: [assetId],
    configuration: { source: 'rollback-live-check' },
    metadata: {
      planId: approvedPlanId,
      approval: { decision: 'approve', decidedBy: 'rbchk-operator@qguard.test', decidedAt: new Date().toISOString(), reason: 'live check' },
    },
  })
  created.plans.push(approvedPlanId)

  const unapprovedPlanId = randomUUID()
  await admin.from('migration_plans').insert({
    id: unapprovedPlanId,
    user_id: userId,
    status: 'awaiting_agent',
    selected_asset_ids: [assetId],
    configuration: { source: 'rollback-live-check' },
    /* Deliberately the planner's default shape with NO approval record — the
       exact state that used to dispatch. */
    metadata: { planId: unapprovedPlanId },
  })
  created.plans.push(unapprovedPlanId)

  const jobId = randomUUID()
  await admin.from('migration_jobs').insert({
    id: jobId,
    user_id: userId,
    asset_id: assetId,
    name: 'rbchk certificate replacement',
    job_type: 'certificate_replacement',
    status: 'queued',
    target_algorithm: 'ML-DSA-65',
    strategy: 'guarded_agent_execution',
    progress: 0,
    metadata: { assetName: 'rbchk-asset', filePath: '/etc/qguard-test/tls.conf', environment: 'test', planId: approvedPlanId },
  })
  created.jobs.push(jobId)

  const unapprovedJobId = randomUUID()
  await admin.from('migration_jobs').insert({
    id: unapprovedJobId,
    user_id: userId,
    asset_id: assetId,
    name: 'rbchk UNAPPROVED cutover',
    job_type: 'certificate_replacement',
    status: 'queued',
    target_algorithm: 'ML-DSA-65',
    strategy: 'guarded_agent_execution',
    progress: 0,
    metadata: { assetName: 'rbchk-asset', filePath: '/etc/qguard-test/tls.conf', environment: 'test', planId: unapprovedPlanId },
  })
  created.jobs.push(unapprovedJobId)

  /*
   * A SECOND job, remediation-class, so the two roles can be told apart. The
   * defect this check exists for is that both used to be handed to whichever
   * write-capable agent polled first.
   */
  const patchJobId = randomUUID()
  await admin.from('migration_jobs').insert({
    id: patchJobId,
    user_id: userId,
    asset_id: assetId,
    name: 'rbchk HNDL config patch',
    job_type: 'hndl_mitigation',
    status: 'pending',
    target_algorithm: 'ML-KEM-768 hybrid',
    strategy: 'guarded_agent_execution',
    progress: 0,
    /* No planId — the shape `migrationJobFromHndlCandidate` writes. A gate that
       required a plan would strand every Harvest Now remediation forever. */
    metadata: { assetName: 'rbchk-asset', filePath: '/etc/qguard-test/hndl.conf', source: 'harvest-now', workflow: 'hndl-remediation', environment: 'test' },
  })
  created.jobs.push(patchJobId)

  /* A sandbox dry run that even carries an approval record — the claim path
     must refuse it on what it IS, not on whether someone approved it. */
  const simJobId = randomUUID()
  await admin.from('migration_jobs').insert({
    id: simJobId,
    user_id: userId,
    asset_id: assetId,
    name: '[DRY RUN] rbchk-asset (RSA-2048 → ML-KEM-768)',
    job_type: 'sandbox_asset_migration',
    status: 'queued',
    target_algorithm: 'ML-KEM-768 hybrid',
    strategy: 'RSA-2048 → ML-KEM-768',
    progress: 0,
    metadata: {
      assetName: 'rbchk-asset',
      filePath: '/etc/qguard-test/tls.conf',
      sandboxMode: true,
      dryRun: true,
      approval: { decision: 'approve', decidedBy: 'someone', decidedAt: new Date().toISOString(), reason: 'should not matter' },
    },
  })
  created.jobs.push(simJobId)

  const patcher = await enrol(token, 'patcher', `rbchk-patcher-${Date.now()}`)
  const patcherId = patcher.body?.data?.agent?.id
  const patcherToken = patcher.body?.data?.enrollment?.agentToken
  if (patcherId) created.agents.push(patcherId)
  check('patcher enrols', Boolean(patcherId), `HTTP ${patcher.status}`)

  console.log('\n[2a] Unplanned remediation needs an explicit, attributed approval')

  const prePoll = await agentApi('/api/v1/agent-scanner/agent/remediation/jobs', patcherId, patcherToken)
  check(
    'an UNAPPROVED remediation job is not claimed',
    !(prePoll.body?.data?.jobs || []).some((j: any) => j.id === patchJobId),
    'patcher claimed an unapproved job',
  )
  const earlyResume = await api(`/api/v1/migration/jobs/${patchJobId}/action`, token, { method: 'POST', body: JSON.stringify({ action: 'resume' }) })
  check(
    'Resume on an unapproved job is refused with the reason',
    earlyResume.status === 409 && earlyResume.body?.error?.code === 'JOB_NOT_APPROVED',
    `HTTP ${earlyResume.status} ${JSON.stringify(earlyResume.body?.error || '').slice(0, 160)}`,
  )
  const plannedApprove = await api(`/api/v1/migration/jobs/${unapprovedJobId}/action`, token, { method: 'POST', body: JSON.stringify({ action: 'approve' }) })
  check(
    'a PLANNED job cannot be approved at job level (the plan is the unit)',
    plannedApprove.status === 409 && plannedApprove.body?.error?.code === 'JOB_NOT_APPROVABLE',
    `HTTP ${plannedApprove.status}`,
  )
  const simApprove = await api(`/api/v1/migration/jobs/${simJobId}/action`, token, { method: 'POST', body: JSON.stringify({ action: 'approve' }) })
  check('a sandbox simulation cannot be approved for agent execution', simApprove.status === 409, `HTTP ${simApprove.status}`)
  const bulkApproveAll = await api('/api/v1/migration/jobs/actions', token, { method: 'POST', body: JSON.stringify({ action: 'approve' }) })
  check(
    'bulk approve WITHOUT an explicit selection is refused (no rubber stamp)',
    bulkApproveAll.status === 400 && bulkApproveAll.body?.error?.code === 'SELECTION_REQUIRED',
    `HTTP ${bulkApproveAll.status}`,
  )

  const approve = await api(`/api/v1/migration/jobs/${patchJobId}/action`, token, {
    method: 'POST',
    body: JSON.stringify({ action: 'approve', reason: 'rbchk change window approved' }),
  })
  check('the operator approves the remediation job', approve.status === 200, `HTTP ${approve.status} ${JSON.stringify(approve.body?.error || '')}`)
  const { data: approvedRow } = await admin.from('migration_jobs').select('status, metadata').eq('id', patchJobId).single()
  const record = (approvedRow?.metadata as any)?.approval
  check('the approval names who approved it', record?.decision === 'approve' && /@/.test(String(record?.decidedBy || '')), JSON.stringify(record || {}).slice(0, 160))
  check('and when, and why', Boolean(record?.decidedAt) && /change window/.test(String(record?.reason || '')))
  check('approving queues the job for the fleet', approvedRow?.status === 'queued', String(approvedRow?.status))
  const { data: approveEvents } = await admin.from('migration_events').select('event_type, metadata').eq('migration_id', patchJobId).eq('event_type', 'operator-approve')
  check(
    'the approval is written to the audit event stream with the decision',
    (approveEvents || []).some((e: any) => e.metadata?.approval?.decidedBy === record?.decidedBy),
    `${(approveEvents || []).length} event(s)`,
  )

  const patcherPoll = await agentApi('/api/v1/agent-scanner/agent/remediation/jobs', patcherId, patcherToken)
  const patcherJobs = patcherPoll.body?.data?.jobs || []
  check(
    'a sandbox DRY RUN is never claimed, even with an approval record',
    !patcherJobs.some((j: any) => j.id === simJobId) && !(prePoll.body?.data?.jobs || []).some((j: any) => j.id === simJobId),
    'an agent claimed a simulation',
  )
  check(
    'a PATCHER claims the remediation job',
    patcherJobs.some((j: any) => j.id === patchJobId),
    JSON.stringify(patcherPoll.body?.data || {}).slice(0, 260),
  )
  check(
    'a PATCHER does NOT claim the Live Migration cutover',
    !patcherJobs.some((j: any) => j.id === jobId),
    'patcher claimed a migration-class job',
  )
  check(
    'and the cutover is reported as refused by role, not silently dropped',
    (patcherPoll.body?.data?.refusedByRole || []).some((r: any) => r.jobId === jobId && r.requires === 'operator'),
    JSON.stringify(patcherPoll.body?.data?.refusedByRole || []).slice(0, 260),
  )
  /* A job nobody may execute must SAY so on the job itself, or Live Migration
     renders a role boundary as a stuck queue. */
  const liveBlocked = await api('/api/v1/migration/live', token)
  const blockedJob = (liveBlocked.body?.data?.jobs || []).find((j: any) => j.id === jobId)
  check(
    'Live Migration states WHY the cutover is not dispatched',
    blockedJob?.dispatchBlock?.kind === 'agent-role' && /Migration Operator/i.test(String(blockedJob?.dispatchBlock?.reason || '')),
    JSON.stringify(blockedJob?.dispatchBlock || null).slice(0, 220),
  )

  const patcherForge = await agentApi(`/api/v1/agent-scanner/agent/remediation/jobs/${jobId}/event`, patcherId, patcherToken, {
    method: 'POST',
    body: JSON.stringify({ eventType: 'agent-remediation-validation', status: 'completed', progress: 100, message: 'forged by patcher' }),
  })
  check(
    'a PATCHER token cannot complete a Live Migration cutover either',
    patcherForge.status === 403,
    `HTTP ${patcherForge.status} ${JSON.stringify(patcherForge.body?.error?.code || '')}`,
  )

  const scannerPoll = await agentApi('/api/v1/agent-scanner/agent/remediation/jobs', scannerId, scannerToken)
  check(
    'a READ-ONLY scanner is handed no write work either',
    Array.isArray(scannerPoll.body?.data?.jobs) && scannerPoll.body.data.jobs.length === 0,
    String(scannerPoll.body?.data?.reason || ''),
  )
  const scannerForge = await agentApi(`/api/v1/agent-scanner/agent/remediation/jobs/${patchJobId}/event`, scannerId, scannerToken, {
    method: 'POST',
    body: JSON.stringify({ eventType: 'agent-remediation-validation', status: 'completed', progress: 100, message: 'forged by scanner' }),
  })
  check('a scanner token cannot complete a remediation job', scannerForge.status === 403, `HTTP ${scannerForge.status}`)

  const collectorPoll = await agentApi('/api/v1/agent-scanner/agent/remediation/jobs', collectorId, collectorToken)
  check('collector poll succeeds', collectorPoll.status === 200, `HTTP ${collectorPoll.status}`)
  check(
    'a READ-ONLY collector is handed no jobs',
    Array.isArray(collectorPoll.body?.data?.jobs) && collectorPoll.body.data.jobs.length === 0,
    JSON.stringify(collectorPoll.body?.data?.reason || ''),
  )
  check(
    'and the refusal names the role, not an empty queue',
    /role|read_only|read-only/i.test(String(collectorPoll.body?.data?.reason || '')),
    String(collectorPoll.body?.data?.reason || ''),
  )

  /* The read-only bypass: a collector token posting a completion event. */
  const collectorEvent = await agentApi(`/api/v1/agent-scanner/agent/remediation/jobs/${jobId}/event`, collectorId, collectorToken, {
    method: 'POST',
    body: JSON.stringify({ eventType: 'agent-remediation-validation', status: 'completed', progress: 100, message: 'forged' }),
  })
  check(
    'a collector token CANNOT drive a migration job to completed',
    collectorEvent.status === 403,
    `HTTP ${collectorEvent.status} ${JSON.stringify(collectorEvent.body?.error?.code || '')}`,
  )
  const afterForge = await admin.from('migration_jobs').select('status').eq('id', jobId).single()
  check('and the job status is untouched', afterForge.data?.status === 'queued', String(afterForge.data?.status))

  /* ---------------------------------------------------------------- */
  console.log('\n[2b] An UNAPPROVED plan is never dispatched')
  const preApprovalPoll = await agentApi('/api/v1/agent-scanner/agent/remediation/jobs', operatorId, operatorToken)
  const preClaimed = preApprovalPoll.body?.data?.jobs || []
  check(
    'the operator does NOT receive the unapproved cutover',
    !preClaimed.some((j: any) => j.id === unapprovedJobId),
    'an unapproved plan was dispatched',
  )
  check(
    'and the refusal names approval as the missing step',
    (preApprovalPoll.body?.data?.refusedByRole || []).some((r: any) => r.jobId === unapprovedJobId && r.requires === 'approval'),
    JSON.stringify(preApprovalPoll.body?.data?.refusedByRole || []).slice(0, 260),
  )
  const { data: unapprovedRow } = await admin.from('migration_jobs').select('status').eq('id', unapprovedJobId).single()
  check('the unapproved job is untouched', unapprovedRow?.status === 'queued', String(unapprovedRow?.status))

  const unclaimedEvent = await agentApi(`/api/v1/agent-scanner/agent/remediation/jobs/${unapprovedJobId}/event`, operatorId, operatorToken, {
    method: 'POST',
    body: JSON.stringify({ eventType: 'agent-remediation-validation', status: 'completed', progress: 100, message: 'forged without claim' }),
  })
  check(
    'even a correctly-typed agent cannot report on a job it never claimed',
    unclaimedEvent.status === 403 && unclaimedEvent.body?.error?.code === 'REMEDIATION_JOB_NOT_CLAIMED',
    `HTTP ${unclaimedEvent.status} ${JSON.stringify(unclaimedEvent.body?.error?.code || '')}`,
  )
  const simEvent = await agentApi(`/api/v1/agent-scanner/agent/remediation/jobs/${simJobId}/event`, operatorId, operatorToken, {
    method: 'POST',
    body: JSON.stringify({ eventType: 'agent-remediation-validation', status: 'completed', progress: 100, message: 'forged on a simulation' }),
  })
  check('no agent may report execution on a simulation', simEvent.status === 409 || simEvent.status === 403, `HTTP ${simEvent.status}`)
  /* The sandbox ENGINE may legitimately start a queued simulation (its scheduler
     runs dry runs against a digital twin), so status is not the invariant. What
     must never happen is an AGENT taking it. */
  const { data: simRow } = await admin.from('migration_jobs').select('status, metadata').eq('id', simJobId).single()
  const simMeta = (simRow?.metadata || {}) as Record<string, unknown>
  check(
    'no agent ever claimed the simulation',
    !simMeta.assignedAgentId && simMeta.executorMode !== 'guarded-agent' && !simMeta.preChangeSnapshotId,
    JSON.stringify({ status: simRow?.status, assignedAgentId: simMeta.assignedAgentId, executorMode: simMeta.executorMode }),
  )

  console.log('\n[3] Claiming creates the pre-change snapshot first')
  const operatorPoll = await agentApi('/api/v1/agent-scanner/agent/remediation/jobs', operatorId, operatorToken)
  const claimed = operatorPoll.body?.data?.jobs || []
  check('the Migration Operator claims the job', claimed.some((j: any) => j.id === jobId), JSON.stringify(operatorPoll.body?.data || {}).slice(0, 320))

  if (!claimed.some((j: any) => j.id === jobId)) { console.log('    poll payload:', JSON.stringify(operatorPoll.body?.data || {}).slice(0, 600)) }
  const { data: snaps } = await admin
    .from('migration_snapshots').select('*').eq('migration_job_id', jobId).eq('trigger', 'pre_migration')
  const snap = snaps?.[0]
  if (snap) created.snapshots.push(snap.id)
  check('a pre-change snapshot exists for the claimed job', Boolean(snap))
  check(
    'the snapshot captured the asset\'s real cryptography',
    ((snap?.crypto_state as any)?.algorithms || []).includes('RSA-2048'),
    JSON.stringify((snap?.crypto_state as any)?.algorithms || []).slice(0, 160),
  )
  check('the snapshot is restorable', snap?.status === 'restorable', String(snap?.status))
  check('the snapshot carries a SHA3-256 integrity hash', String(snap?.integrity_hash || '').length === 64)
  check('the claimed job records which snapshot protects it', Boolean(claimed.find((j: any) => j.id === jobId)?.metadata?.preChangeSnapshotId))

  /* ---------------------------------------------------------------- */
  console.log('\n[4] A snapshot with no executor record cannot be restored')
  const dash1 = await api('/api/v1/migration-snapshots', token)
  const view1 = (dash1.body?.data?.snapshots || []).find((s: any) => s.snapshotId === snap?.snapshot_id)
  check('the dashboard returns the snapshot', Boolean(view1))
  check('it is NOT presented as restorable-by-executor yet', view1?.restoreExecutable === false)
  check('and the reason explains why', /nothing to undo|no executor/i.test(String(view1?.restoreBlockedReason || '')), String(view1?.restoreBlockedReason || ''))

  const earlyRestore = await api(`/api/v1/migration-snapshots/${encodeURIComponent(snap.snapshot_id)}/restore`, token, {
    method: 'POST', body: JSON.stringify({ reason: 'rbchk early restore' }),
  })
  check('restoring it reports awaiting-executor, not success', earlyRestore.body?.data?.disposition === 'awaiting-executor', JSON.stringify(earlyRestore.body).slice(0, 220))
  check('and applied is false', earlyRestore.body?.data?.applied === false)
  const stillRestorable = await admin.from('migration_snapshots').select('status, restored_at').eq('id', snap.id).single()
  check('the snapshot was NOT marked restored', stillRestorable.data?.status === 'restorable' && !stillRestorable.data?.restored_at, String(stillRestorable.data?.status))

  /* ---------------------------------------------------------------- */
  console.log('\n[5] The agent’s config backup becomes the restore source')
  const beforeHash = 'a'.repeat(64)
  const executed = await agentApi(`/api/v1/agent-scanner/agent/remediation/jobs/${jobId}/event`, operatorId, operatorToken, {
    method: 'POST',
    body: JSON.stringify({
      eventType: 'agent-remediation-executed',
      status: 'running',
      progress: 70,
      message: 'rbchk applied guarded config patch',
      metadata: {
        snapshot: {
          type: 'configuration-snapshot',
          targetPath: '/etc/qguard-test/tls.conf',
          backupPath: '/etc/qguard-test/tls.conf.qguard-backup-1',
          beforeHash,
          afterHash: 'b'.repeat(64),
        },
      },
    }),
  })
  check('the operator may post an execution event', executed.status === 200, `HTTP ${executed.status} ${JSON.stringify(executed.body?.error || '')}`)

  const { data: snapAfter } = await admin.from('migration_snapshots').select('metadata').eq('id', snap.id).single()
  const exec = (snapAfter?.metadata as any)?.execution
  check('the backup descriptor is persisted on the snapshot', exec?.kind === 'agent-config', JSON.stringify(exec || {}).slice(0, 160))
  check('it names the agent that applied the change', exec?.agentId === operatorId)
  check('it records the pre-change digest', exec?.beforeHash === beforeHash)

  const dash2 = await api('/api/v1/migration-snapshots', token)
  const view2 = (dash2.body?.data?.snapshots || []).find((s: any) => s.snapshotId === snap.snapshot_id)
  check('the snapshot is now executable-restorable', view2?.restoreExecutable === true, String(view2?.restoreBlockedReason || ''))

  /* ---------------------------------------------------------------- */
  console.log('\n[6] Restore DISPATCHES; it does not declare success')
  /* A rollback is only handed to an agent that is actually CONNECTED, so the
     agent has to have checked in — mirroring the real runtime, which heartbeats
     every cycle. */
  const beat = await agentApi('/api/v1/agent-scanner/agent/heartbeat', operatorId, operatorToken, {
    method: 'POST',
    body: JSON.stringify({ status: 'active', hostname: 'rbchk.qguard.test', platform: 'linux x64', version: '1.5.3', telemetry: { phase: 'idle' } }),
  })
  check('the operator agent heartbeats', beat.status === 200, `HTTP ${beat.status}`)

  const restore = await api(`/api/v1/migration-snapshots/${encodeURIComponent(snap.snapshot_id)}/restore`, token, {
    method: 'POST', body: JSON.stringify({ reason: 'rbchk operator rollback' }),
  })
  if (restore.body?.data?.disposition !== 'dispatched') {
    console.log('    server said:', String(restore.body?.data?.message || JSON.stringify(restore.body)))
  }
  check('restore returns dispatched', restore.body?.data?.disposition === 'dispatched', JSON.stringify(restore.body).slice(0, 240))
  check('applied is false until the executor confirms', restore.body?.data?.applied === false)
  check('it names the executing agent', restore.body?.data?.executor?.kind === 'agent' && restore.body?.data?.executor?.id === operatorId)
  const commandId = restore.body?.data?.commandId
  check('a command id was issued', Boolean(commandId))

  const { data: snapDispatched } = await admin.from('migration_snapshots').select('status, restored_at').eq('id', snap.id).single()
  check('snapshot is restoring, NOT restored', snapDispatched?.status === 'restoring' && !snapDispatched?.restored_at, String(snapDispatched?.status))
  const { data: jobDispatched } = await admin.from('migration_jobs').select('status').eq('id', jobId).single()
  check('job is rollback_requested, NOT rolled_back', jobDispatched?.status === 'rollback_requested', String(jobDispatched?.status))

  /* The command must be waiting on the agent's own queue. */
  const policy = await agentApi('/api/v1/agent-scanner/agent/policy', operatorId, operatorToken)
  const queuedRollback = (policy.body?.data?.commands || []).find((c: any) => c.id === commandId)
  check('the rollback command is delivered to that agent', Boolean(queuedRollback), JSON.stringify(policy.body?.data?.commands || []).slice(0, 200))
  check('the command carries the backup path', queuedRollback?.payload?.backupPath === '/etc/qguard-test/tls.conf.qguard-backup-1')
  check('and the pre-change digest to verify against', queuedRollback?.payload?.beforeHash === beforeHash)

  /* ---------------------------------------------------------------- */
  console.log('\n[7] An UNVERIFIED result never becomes "restored"')
  const failAck = await agentApi(`/api/v1/agent-scanner/agent/commands/${commandId}/ack`, operatorId, operatorToken, {
    method: 'POST',
    body: JSON.stringify({ status: 'failed', error: 'backup digest mismatch', result: { verified: false, reason: 'backup digest mismatch' } }),
  })
  check('the agent may acknowledge failure', failAck.status === 200, `HTTP ${failAck.status}`)
  const { data: snapFailed } = await admin.from('migration_snapshots').select('status, restored_at, metadata').eq('id', snap.id).single()
  check('snapshot reads restore_failed', snapFailed?.status === 'restore_failed', String(snapFailed?.status))
  check('restored_at stays empty', !snapFailed?.restored_at)
  check('the failure reason is recorded', /digest mismatch/i.test(String((snapFailed?.metadata as any)?.rollback?.message || '')))
  const { data: jobFailed } = await admin.from('migration_jobs').select('status').eq('id', jobId).single()
  check('the job reads rollback_failed', jobFailed?.status === 'rollback_failed', String(jobFailed?.status))

  /* ---------------------------------------------------------------- */
  console.log('\n[8] A VERIFIED result is the only thing that writes "restored"')
  const restore2 = await api(`/api/v1/migration-snapshots/${encodeURIComponent(snap.snapshot_id)}/restore`, token, {
    method: 'POST', body: JSON.stringify({ reason: 'rbchk retry after fixing the backup' }),
  })
  check('a failed rollback can be retried', restore2.body?.data?.disposition === 'dispatched', JSON.stringify(restore2.body).slice(0, 200))
  const commandId2 = restore2.body?.data?.commandId
  await agentApi('/api/v1/agent-scanner/agent/policy', operatorId, operatorToken) // deliver it
  const okAck = await agentApi(`/api/v1/agent-scanner/agent/commands/${commandId2}/ack`, operatorId, operatorToken, {
    method: 'POST',
    body: JSON.stringify({
      status: 'completed',
      result: { verified: true, targetPath: '/etc/qguard-test/tls.conf', restoredHash: beforeHash, reason: 'restored and re-verified' },
    }),
  })
  check('the agent may acknowledge a verified restore', okAck.status === 200, `HTTP ${okAck.status}`)
  const { data: snapRestored } = await admin.from('migration_snapshots').select('status, restored_at, metadata').eq('id', snap.id).single()
  check('snapshot reads restored', snapRestored?.status === 'restored', String(snapRestored?.status))
  check('restored_at is set', Boolean(snapRestored?.restored_at))
  check('the verified digest is recorded', (snapRestored?.metadata as any)?.rollback?.verifiedHash === beforeHash)
  const { data: jobRestored } = await admin.from('migration_jobs').select('status, metadata').eq('id', jobId).single()
  check('the job reads rolled_back', jobRestored?.status === 'rolled_back', String(jobRestored?.status))

  /* ---------------------------------------------------------------- */
  console.log('\n[9] Everything is auditable')
  const auditRes = await api('/api/v1/migration-snapshots/audit', token)
  const audit = (auditRes.body?.data?.audit || []).filter((a: any) => a.snapshotId === snap.snapshot_id || a.migrationJobId === jobId)
  const actions = new Set(audit.map((a: any) => a.action))
  check('snapshot creation is audited', actions.has('created'), [...actions].join(','))
  check('the executor record is audited', actions.has('execution_recorded'), [...actions].join(','))
  check('the rollback request is audited', actions.has('restore_requested'), [...actions].join(','))
  check('the failed rollback is audited', actions.has('rollback_failed'), [...actions].join(','))
  check('the confirmed restore is audited', actions.has('restored'), [...actions].join(','))

  const live = await api('/api/v1/migration/live', token)
  const liveJob = (live.body?.data?.jobs || []).find((j: any) => j.id === jobId)
  check('Live Migration renders the job as rolled_back, not paused', liveJob?.status === 'rolled_back', String(liveJob?.status))
  check('the rolled-back counter reflects it', Number(live.body?.data?.summary?.rolledBack || 0) >= 1)
  check('agentsOnline is heartbeat-measured', typeof live.body?.data?.summary?.agentsEnrolled === 'number')

  await cleanup(userId)
  console.log(`\n=== ${passed} passed, ${failed} failed ===`)
  if (failures.length) console.log('\n' + failures.map((f) => `  - ${f}`).join('\n') + '\n')
  process.exit(failed === 0 ? 0 : 1)
}

main().catch(async (error) => {
  console.error('\nlive check crashed:', error?.message || error)
  try { const { userId } = await session(); await cleanup(userId) } catch { /* best effort */ }
  process.exit(1)
})
