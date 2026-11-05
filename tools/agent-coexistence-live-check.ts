/** Tenant-isolated live checks: four agents share one real scan profile; claims and metadata race safely. */
import 'dotenv/config'
import assert from 'node:assert/strict'
import { createClient } from '@supabase/supabase-js'
import { createPrivateKey, createPublicKey, randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { AGENT_VERSION, type AgentRole } from '../src/lib/agent-installer/agent-release'
import { generateAgentKeyPair, supportedAlgorithms, signRequest, type AgentKeyPair } from '../src/lib/agent-installer/agent-request-signing'
import { updateTenantRow } from '../src/api-server/tenant-row-update'
import { enqueueAgentCommand } from '../src/api-server/agent-command-queue'
import { cleanupQaTenant } from './qa-tenant-cleanup'

const BASE = process.env.QGUARD_TEST_BASE || 'http://localhost:3000'
const db = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qguard-coexistence-live-'))
const tenants: string[] = []
let checks = 0
const check = (ok: unknown, name: string) => { assert.ok(ok, name); checks++; console.log(`PASS ${name}`) }
type TestAgent = { id: string; token: string; role: AgentRole; keys: AgentKeyPair[] }
const children: ReturnType<typeof spawn>[] = []
async function tenant() {
  const email = `scan-qa-${randomUUID()}@example.test`, password = randomUUID() + '!Qa9'
  const provisioned = await db.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { qa_fixture: true } })
  if (provisioned.error || !provisioned.data.user) throw provisioned.error || new Error('QA provisioning failed')
  const id = provisioned.data.user.id; tenants.push(id)
  const billing = await db.from('billing_subscriptions').insert({ user_id: id, subscription_id: `qa-${randomUUID()}`, plan: 'Pro', status: 'trial', metadata: { qa_fixture: true } })
  if (billing.error) throw billing.error
  const auth = createClient(process.env.VITE_SUPABASE_URL!, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false } })
  const session = await auth.auth.signInWithPassword({ email, password })
  if (session.error || !session.data.session) throw session.error || new Error('QA sign-in failed')
  return { id, token: session.data.session.access_token }
}
async function userApi(owner: { token: string }, endpoint: string, payload: unknown) {
  const response = await fetch(BASE + endpoint, { method: 'POST', headers: { Authorization: `Bearer ${owner.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: AbortSignal.timeout(60_000) })
  const body = await response.json()
  if (!response.ok) throw new Error(`QA request ${endpoint}: ${response.status} ${body.error?.message}`)
  return body.data
}
async function agentApi(agent: TestAgent, endpoint: string) {
  const url = BASE + endpoint
  const response = await fetch(url, { headers: { 'x-qguard-agent-id': agent.id, 'x-qguard-agent-token': agent.token, 'x-qguard-agent-version': AGENT_VERSION, ...signRequest({ method: 'GET', url, agentId: agent.id, body: '', keys: agent.keys }) }, signal: AbortSignal.timeout(90_000) })
  const body = await response.json()
  if (!response.ok) throw new Error(`Agent QA call: ${response.status} ${body.error?.message}`)
  return body.data
}

try {
  const owner = await tenant()
  const asset = await db.from('assets').insert({ user_id: owner.id, name: 'QA shared host', type: 'device', status: 'active', metadata: { qa_fixture: true } }).select('id').single()
  if (asset.error) throw asset.error
  const assetId = asset.data.id
  await fs.writeFile(path.join(dir, 'crypto.cfg'), 'TLS_GROUPS=X25519\nTLS_VERSION=TLSv1.2\n')
  const agents: TestAgent[] = []
  for (const role of ['collector', 'scanner', 'patcher', 'operator', 'patcher'] as AgentRole[]) {
    const data = await userApi(owner, '/api/v1/agent-scanner/agents/enroll', {
      name: `QA coexistence ${role} ${agents.length}`, role, version: AGENT_VERSION, hostname: os.hostname(), environment: 'lab',
      remediationAuthorized: ['patcher', 'operator'].includes(role), migrationAuthorized: role === 'operator',
      binding: { mode: 'existing', assetId, attribution: 'bound' },
      policy: { enabled: true, intervalSeconds: 60, allowedPaths: [dir], allowedTargets: [], scanTypes: ['configs'], alertThreshold: 'moderate' },
      metadata: { role, qa_fixture: true },
    })
    const id = data.enrollment.agentId, token = data.enrollment.agentToken
    const keys = supportedAlgorithms().map(generateAgentKeyPair)
    agents.push({ id, token, role, keys })
  }
  // Real CLI scans run concurrently, each with its own identity and private keys.
  await Promise.all(agents.slice(0, 4).map(async (agent) => {
    const state = path.join(dir, agent.id)
    const child = spawn(process.execPath, [path.resolve('tools/qguard-agent/dist/qguard-agent.cjs'), 'scan'], { windowsHide: true, env: {
      ...process.env, QGUARD_API_URL: BASE, QGUARD_ENVIRONMENT: 'development', QGUARD_AGENT_ID: agent.id, QGUARD_AGENT_TOKEN: agent.token, QGUARD_AGENT_ROLE: agent.role,
      QGUARD_STATE_DIR: state, QGUARD_COORDINATION_DIR: path.join(dir, 'coordination'), QGUARD_NATIVE_RUNTIME_ENABLED: 'false', QGUARD_ENABLE_REMEDIATION: 'false', QGUARD_ENABLE_CONFIG_PATCHES: 'false', QGUARD_ENABLE_MIGRATION: 'false',
    }, timeout: 240_000 })
    children.push(child)
    let error = ''
    child.stderr.on('data', (chunk) => { error += chunk.toString() })
    child.stdout.resume()
    const code = await new Promise<number | null>((resolve, reject) => { child.on('error', reject); child.on('close', resolve) })
    assert.equal(code, 0, `${agent.role} scan: ${error.slice(-300)}`)
    const stored = JSON.parse(await fs.readFile(path.join(state, `signing-keys-${agent.id}.json`), 'utf8'))
    agent.keys = stored.keys.map((key: any) => { const privateKey = createPrivateKey(key.privateKeyPem); return { algorithm: key.algorithm, privateKey, publicKeyDer: createPublicKey(privateKey).export({ type: 'spki', format: 'der' }) } })
  }))
  const profiles = await db.from('assets').select('id,metadata').eq('user_id', owner.id)
  check(!profiles.error && profiles.data?.length === 1 && profiles.data[0].id === assetId, 'four real role scans remain in one explicitly assigned asset profile')
  const sources = profiles.data![0].metadata.scanSources || []
  check(agents.slice(0, 4).every((agent) => sources.some((source: any) => source.agentId === agent.id)), 'simultaneous uploads retain provenance from all four agents')
  const evidence = await db.from('scanner_evidence').select('agent_id').eq('user_id', owner.id)
  check(agents.slice(0, 4).every((agent) => evidence.data?.some((item) => item.agent_id === agent.id)), 'raw observations stay attributed to their actual reporting agent')

  await Promise.all(Array.from({ length: 8 }, (_, i) => updateTenantRow(db, 'assets', owner.id, assetId, (row) => ({ metadata: { ...row.metadata, qaConcurrent: { ...row.metadata.qaConcurrent, [i]: true } } }))))
  const merged = await db.from('assets').select('metadata').eq('user_id', owner.id).eq('id', assetId).single()
  check(Object.keys(merged.data?.metadata.qaConcurrent || {}).length === 8 && merged.data?.metadata.scanSources.length >= 4, 'database compare-and-set retries preserve concurrent metadata and scan sources')
  const current = await db.from('scanner_agents').select('*').eq('user_id', owner.id).eq('id', agents[0].id).single()
  const commands = await Promise.all(Array.from({ length: 8 }, () => enqueueAgentCommand(db, current.data, 'scan', { requestedBy: owner.id })))
  check(commands.every((item) => item.ok) && new Set(commands.map((item) => item.command?.id)).size === 1, 'simultaneous Scan requests produce one command without dropping queue state')

  const approval = { decision: 'approve', decidedBy: owner.id, decidedAt: new Date().toISOString(), reason: 'Isolated concurrency regression fixture' }
  const jobs = await db.from('migration_jobs').insert([
    { user_id: owner.id, asset_id: assetId, name: 'QA guarded config remediation', job_type: 'hndl_mitigation', status: 'queued', target_algorithm: 'ML-KEM-768', strategy: 'guarded_agent_execution', metadata: { approval, filePath: path.join(dir, 'crypto.cfg'), qa_fixture: true } },
    { user_id: owner.id, asset_id: assetId, name: 'QA planned crypto cutover', job_type: 'certificate_replacement', status: 'queued', target_algorithm: 'ML-DSA-65', strategy: 'guarded_agent_execution', metadata: { approval, filePath: path.join(dir, 'crypto.cfg'), qa_fixture: true } },
  ]).select('id,job_type')
  if (jobs.error) throw jobs.error
  const polls = await Promise.all(agents.map((agent) => agentApi(agent, '/api/v1/agent-scanner/agent/remediation/jobs')))
  if (polls[2].jobs.length + polls[4].jobs.length !== 1 || polls[3].jobs.length !== 1) console.log(JSON.stringify(polls.map((poll, i) => ({ role: agents[i].role, jobIds: poll.jobs.map((job: any) => job.id), reason: poll.reason, refused: poll.refusedByRole, snapshot: poll.withheldWithoutSnapshot }))))
  check(polls[0].jobs.length === 0 && polls[1].jobs.length === 0, 'Collector and Scanner cannot claim write jobs')
  const patchId = jobs.data.find((job) => job.job_type === 'hndl_mitigation')!.id
  const cutoverId = jobs.data.find((job) => job.job_type === 'certificate_replacement')!.id
  check(polls[2].jobs.concat(polls[4].jobs).filter((job: any) => job.id === patchId).length === 1, 'two Patchers racing for one job have exactly one atomic claim winner')
  check(polls[3].jobs.length === 1 && polls[3].jobs[0].id === cutoverId && !polls[3].jobs.some((job: any) => job.id === patchId), 'Migration Operator receives its migration job without taking Patcher remediation')
  check(!polls[2].jobs.concat(polls[4].jobs).some((job: any) => job.id === cutoverId), 'Patchers cannot take the Migration Operator cutover')
  const snapshots = await db.from('migration_snapshots').select('snapshot_id,migration_job_id').eq('user_id', owner.id)
  check(!snapshots.error && snapshots.data?.length === 2 && new Set(snapshots.data.map((item) => item.snapshot_id)).size === 2, 'parallel jobs have distinct pre-change snapshots; competing claims reuse one snapshot per job')

  const other = await tenant()
  await assert.rejects(updateTenantRow(db, 'assets', other.id, assetId, () => ({ status: 'archived' })), /not found/)
  check(true, 'coordinated updates cannot access another tenant asset')
  console.log(`${checks} live multi-agent coordination checks passed`)
} finally {
  for (const child of children) if (child.exitCode === null) child.kill()
  for (const id of tenants) {
    for (const table of ['migration_snapshot_audit', 'migration_snapshots', 'migration_events', 'migration_validation_logs', 'migration_telemetry', 'execution_queues', 'orchestration_jobs', 'migration_execution', 'migration_job_steps', 'migration_jobs']) {
      const result = await db.from(table).delete().eq('user_id', id)
      if (result.error && !/42P01|42703|PGRST204|PGRST205/.test(result.error.code || '')) throw new Error(`QA migration cleanup failed: ${table}: ${result.error.message}`)
    }
    await cleanupQaTenant(db, id)
  }
  assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir()))
  await fs.rm(dir, { recursive: true, force: true })
}
