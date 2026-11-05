/**
 * Live proof that the Agent Center's selections are what the control plane
 * enforces — against the real API and database.
 *
 *   - a Patcher enrolled WITHOUT "Authorize configuration remediation" holds
 *     no write capability, is handed no write jobs, and its installer ships
 *     with the host write switch OFF
 *   - granting authority afterwards flips all three; revoking flips them back
 *   - a Migration Operator cannot hold migration authority without remediation
 *   - read-only roles cannot be granted write authority at all
 *   - the Scanner's role ceiling holds at enrolment, at policy edit and at the
 *     agent's own policy pull
 *   - a policy edit for an agent the caller does not own is a 404, not a 200
 *
 * Needs the dev server (QGUARD_TEST_BASE, default http://localhost:3000) and
 * the QA owner account. Every agent it creates is deleted at the end.
 *
 *   npx tsx tools/agent-authority-live-check.ts
 */
import { createClient } from '@supabase/supabase-js'
import fs from 'node:fs'
import { randomUUID } from 'node:crypto'
import { AGENT_VERSION } from '../src/lib/agent-installer/agent-release'

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
const failures: string[] = []
function check(name: string, condition: boolean, detail = '') {
  if (condition) passed += 1
  else failures.push(`${name}${detail ? ` — ${detail}` : ''}`)
  console.log(`  ${condition ? 'PASS' : 'FAIL'}  ${name}${!condition && detail ? ` — ${detail}` : ''}`)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Body = any
async function call(path: string, init: { method?: string; body?: unknown; token?: string; agent?: { id: string; token: string } } = {}) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (init.token) headers.Authorization = `Bearer ${init.token}`
  if (init.agent) {
    headers['x-qguard-agent-id'] = init.agent.id
    headers['x-qguard-agent-token'] = init.agent.token
  }
  const res = await fetch(`${BASE}${path}`, {
    method: init.method || 'GET',
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  })
  const text = await res.text()
  let body: Body = null
  try { body = text ? JSON.parse(text) : null } catch { body = { raw: text.slice(0, 300) } }
  return { status: res.status, body }
}

async function session(): Promise<string> {
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const { data: link } = await admin.auth.admin.generateLink({ type: 'magiclink', email: OWNER_EMAIL })
    const hashed = link?.properties?.hashed_token
    if (hashed) {
      const { data } = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: hashed })
      if (data?.session) return data.session.access_token
    }
    await new Promise((r) => setTimeout(r, 1500 * attempt))
  }
  throw new Error('Could not mint a session for the QA owner account')
}

const created: string[] = []

async function enrol(token: string, body: Record<string, unknown>) {
  // Enrol as the CURRENT release: older versions are refused writes by the coordination gate
  // before authority is even read, which would mask what this check is about.
  const res = await call('/api/v1/agent-scanner/agents/enroll', { method: 'POST', token, body: { version: AGENT_VERSION, ...body } })
  const id = res.body?.data?.agent?.id as string | undefined
  if (id) created.push(id)
  return { ...res, id, agentToken: res.body?.data?.enrollment?.agentToken as string | undefined, agent: res.body?.data?.agent }
}

async function jobsReason(id: string, agentToken: string) {
  const res = await call('/api/v1/agent-scanner/agent/remediation/jobs', { agent: { id, token: agentToken } })
  return { status: res.status, reason: res.body?.data?.reason as string | undefined }
}

async function installerSwitch(token: string, agentId: string, agentToken: string) {
  const res = await call('/api/v1/agent-installer/package', { method: 'POST', token, body: { agentId, platform: 'linux', token: agentToken } })
  const content = String(res.body?.data?.content || '')
  const match = content.match(/QGUARD_ENABLE_REMEDIATION=(\w+)/)
  return { status: res.status, remediation: match ? match[1] : null, error: res.body?.error?.code }
}

async function main() {
  const token = await session()
  console.log(`\nAgent authority live check — ${BASE}\n`)
  const policy = { enabled: true, intervalSeconds: 60, allowedTargets: [], allowedPaths: ['/etc/qguard-authority-check'], scanTypes: ['tls', 'configs'], alertThreshold: 'moderate' }

  console.log('[1] Patcher enrolled with nothing ticked is read-only everywhere')
  const patcher = await enrol(token, { name: `authchk-patcher-${Date.now()}`, role: 'patcher', remediationAuthorized: false, metadata: { role: 'patcher', environment: 'lab' }, policy })
  check('patcher enrols', Boolean(patcher.id && patcher.agentToken), `HTTP ${patcher.status} ${JSON.stringify(patcher.body?.error || '')}`)
  check('stored capabilities: remediation false, config_patches false', patcher.agent?.capabilities?.remediation === false && patcher.agent?.capabilities?.config_patches === false, JSON.stringify({ r: patcher.agent?.capabilities?.remediation, c: patcher.agent?.capabilities?.config_patches }))
  check('stored decision recorded as not authorised', patcher.agent?.metadata?.remediationAuthorized === false)
  if (patcher.id && patcher.agentToken) {
    const poll = await jobsReason(patcher.id, patcher.agentToken)
    check('job poll hands it nothing: remediation_not_authorized', poll.status === 200 && poll.reason === 'remediation_not_authorized', JSON.stringify(poll))
    const pkg = await installerSwitch(token, patcher.id, patcher.agentToken)
    check('installer ships QGUARD_ENABLE_REMEDIATION=false', pkg.status === 200 && pkg.remediation === 'false', JSON.stringify(pkg))

    console.log('\n[2] Granting authority afterwards takes effect; revoking undoes it')
    const grant = await call(`/api/v1/agent-scanner/agents/${patcher.id}/authority`, { method: 'PUT', token, body: { remediation: true } })
    check('grant remediation → 200', grant.status === 200 && grant.body?.data?.authority?.remediation === true, JSON.stringify(grant.body?.error || grant.body?.data?.authority))
    const afterGrant = await jobsReason(patcher.id, patcher.agentToken)
    check('job poll no longer refuses on authority', afterGrant.status === 200 && afterGrant.reason !== 'remediation_not_authorized', JSON.stringify(afterGrant))
    const pkg2 = await installerSwitch(token, patcher.id, patcher.agentToken)
    check('regenerated installer ships QGUARD_ENABLE_REMEDIATION=true', pkg2.remediation === 'true', JSON.stringify(pkg2))
    const migrationOnPatcher = await call(`/api/v1/agent-scanner/agents/${patcher.id}/authority`, { method: 'PUT', token, body: { migration: true } })
    check('a Patcher cannot hold migration authority → 409', migrationOnPatcher.status === 409, `HTTP ${migrationOnPatcher.status}`)
    const revoke = await call(`/api/v1/agent-scanner/agents/${patcher.id}/authority`, { method: 'PUT', token, body: { remediation: false } })
    check('revoke → 200', revoke.status === 200 && revoke.body?.data?.authority?.remediation === false)
    const afterRevoke = await jobsReason(patcher.id, patcher.agentToken)
    check('job poll refuses again at the very next poll', afterRevoke.reason === 'remediation_not_authorized', JSON.stringify(afterRevoke))
  }

  console.log('\n[3] Migration Operator: migration requires remediation')
  const operator = await enrol(token, { name: `authchk-operator-${Date.now()}`, role: 'operator', remediationAuthorized: false, migrationAuthorized: true, metadata: { role: 'operator' }, policy })
  check('operator enrols', Boolean(operator.id), `HTTP ${operator.status}`)
  check('migration ticked without remediation → neither stored', operator.agent?.capabilities?.migration === false && operator.agent?.capabilities?.remediation === false)
  const operatorFull = await enrol(token, { name: `authchk-operator-full-${Date.now()}`, role: 'operator', remediationAuthorized: true, migrationAuthorized: true, metadata: { role: 'operator' }, policy })
  check('both ticked → both stored', operatorFull.agent?.capabilities?.migration === true && operatorFull.agent?.capabilities?.remediation === true)
  if (operatorFull.id && operatorFull.agentToken) {
    const pkg = await installerSwitch(token, operatorFull.id, operatorFull.agentToken)
    check('authorised operator installer ships QGUARD_ENABLE_REMEDIATION=true', pkg.remediation === 'true', JSON.stringify(pkg))
  }

  console.log('\n[4] Read-only roles stay read-only')
  const collector = await enrol(token, { name: `authchk-collector-${Date.now()}`, role: 'collector', remediationAuthorized: true, capabilities: { remediation: true, migration: true }, metadata: { role: 'collector' }, policy })
  check('collector asking for write capability still stored read-only', collector.agent?.capabilities?.remediation === false && collector.agent?.capabilities?.migration === false)
  if (collector.id) {
    const grant = await call(`/api/v1/agent-scanner/agents/${collector.id}/authority`, { method: 'PUT', token, body: { remediation: true } })
    check('granting a collector write authority → 409 AGENT_ROLE_READ_ONLY', grant.status === 409 && grant.body?.error?.code === 'AGENT_ROLE_READ_ONLY', `HTTP ${grant.status}`)
  }

  console.log('\n[5] Scanner role ceiling at enrolment, policy edit and policy pull')
  const scanner = await enrol(token, { name: `authchk-scanner-${Date.now()}`, role: 'scanner', metadata: { role: 'scanner' }, policy: { ...policy, scanTypes: ['tls', 'configs', 'runtime'] } })
  const storedTypes: string[] = scanner.agent?.policy?.scanTypes || []
  check('enrolment: runtime removed from a Scanner', storedTypes.includes('tls') && !storedTypes.includes('runtime'), JSON.stringify(storedTypes))
  check('enrolment: the removal is recorded', (scanner.agent?.metadata?.scanTypesDeniedByRole || []).includes('runtime'))
  if (scanner.id && scanner.agentToken) {
    const edit = await call(`/api/v1/agent-scanner/agents/${scanner.id}/policy`, { method: 'PUT', token, body: { ...policy, scanTypes: ['tls', 'runtime', 'ebpf'] } })
    check('policy edit: runtime/ebpf removed and reported', edit.status === 200 && !edit.body?.data?.policy?.scanTypes?.includes('runtime') && (edit.body?.data?.denied?.role || []).includes('runtime'), JSON.stringify(edit.body?.data || edit.body?.error))
    const pull = await call('/api/v1/agent-scanner/agent/policy', { agent: { id: scanner.id, token: scanner.agentToken } })
    const pulled: string[] = pull.body?.data?.policy?.scanTypes || []
    check('agent policy pull: no runtime for a Scanner', pull.status === 200 && pulled.includes('tls') && !pulled.includes('runtime'), JSON.stringify(pulled))
  }

  console.log('\n[6] Policy edits require ownership')
  const foreign = await call(`/api/v1/agent-scanner/agents/${randomUUID()}/policy`, { method: 'PUT', token, body: policy })
  check('policy edit for an unknown agent → 404 (was 200 + a stray policy row)', foreign.status === 404, `HTTP ${foreign.status}`)
  const foreignAuthority = await call(`/api/v1/agent-scanner/agents/${randomUUID()}/authority`, { method: 'PUT', token, body: { remediation: false } })
  check('authority change for an unknown agent → 404', foreignAuthority.status === 404, `HTTP ${foreignAuthority.status}`)
}

async function cleanup() {
  const token = await session().catch(() => '')
  for (const id of created) {
    if (token) await call(`/api/v1/agent-scanner/agents/${id}`, { method: 'DELETE', token })
    await admin.from('agent_heartbeats').delete().eq('agent_id', id)
    await admin.from('scanner_agent_policies').delete().eq('agent_id', id)
    await admin.from('scanner_agents').delete().eq('id', id)
  }
  const { count } = await admin.from('scanner_agents').select('id', { count: 'exact', head: true }).in('id', created.length ? created : ['00000000-0000-0000-0000-000000000000'])
  console.log(`\n  cleanup: ${created.length} test agents removed (${count ?? 0} remaining)`)
}

main()
  .catch((error) => {
    failures.push(`crashed: ${error?.message || error}`)
    console.error(error)
  })
  .finally(async () => {
    await cleanup().catch((error) => console.error('cleanup failed:', error?.message || error))
    console.log(`\n${failures.length === 0 ? `PASS — ${passed} checks` : `FAIL — ${failures.length} failed, ${passed} passed`}`)
    for (const failure of failures) console.log(`   - ${failure}`)
    process.exitCode = failures.length === 0 ? 0 : 1
  })
