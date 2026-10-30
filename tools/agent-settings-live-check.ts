/**
 * Agent Collector SETTINGS — live proof that a saved policy is the policy the
 * agent runs.
 *
 * The Agents Collector page's Settings section saves through
 * PUT /api/v1/agent-scanner/agents/:id/policy. This check drives that route the
 * way the page does, then runs the SHIPPED agent bundle
 * (tools/qguard-agent/dist/qguard-agent.cjs) over a real lab and asserts on
 * what reached the database:
 *
 *  - the stored policy (policy row AND agent row) is what was sent, minus the
 *    modules the role excludes or the runtime does not implement — and those
 *    removals are reported, never silent;
 *  - a narrowed module set narrows what the agent collects;
 *  - a narrowed path narrows where it reads;
 *  - the alert threshold decides which findings raise alerts;
 *  - "scanning disabled" stops the agent scanning while it keeps checking in;
 *  - the delivery receipt (policyUpdatedAt → policyDeliveredAt) flips to
 *    "in effect" only once the agent has pulled the changed policy;
 *  - another tenant's agent, an unknown agent and a revoked agent are refused.
 *
 * Needs the dev server on :3000, OpenSSL 3.5+ and ssh-keygen on PATH.
 *   npx tsx tools/agent-settings-live-check.ts
 *
 * Every row it creates belongs to the test tenant and is removed at the end.
 */
import { createClient } from '@supabase/supabase-js'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { buildLab } from './agent-lab'

const BASE = process.env.QGUARD_TEST_BASE || 'http://localhost:3000'
const OWNER_EMAIL = process.env.QGUARD_TEST_EMAIL || 'zachmatthew369@gmail.com'
const RUNTIME = path.resolve('tools/qguard-agent/dist/qguard-agent.cjs')

let passed = 0
const failures: string[] = []
function check(name: string, condition: boolean, detail = '') {
  if (condition) passed += 1
  else failures.push(`${name}${detail ? ` — ${detail}` : ''}`)
  console.log(`  ${condition ? 'PASS' : 'FAIL'}  ${name}${!condition && detail ? ` — ${detail}` : ''}`)
}

type Api = { status: number; body: any } // eslint-disable-line @typescript-eslint/no-explicit-any

async function main() {
  const env = Object.fromEntries(
    fs.readFileSync(path.resolve('.env'), 'utf8')
      .split(/\r?\n/)
      .filter((line) => line.includes('=') && !line.startsWith('#'))
      .map((line) => {
        const i = line.indexOf('=')
        return [line.slice(0, i).trim(), line.slice(i + 1).trim().replace(/^["']|["']$/g, '')]
      }),
  )
  const admin = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
  const anon = createClient(env.VITE_SUPABASE_URL, env.VITE_SUPABASE_ANON_KEY, { auth: { persistSession: false } })

  let token = ''
  let userId = ''
  for (let attempt = 1; attempt <= 4 && !token; attempt += 1) {
    const { data: link, error: linkError } = await admin.auth.admin.generateLink({ type: 'magiclink', email: OWNER_EMAIL })
    const { data: verified, error: verifyError } = link?.properties?.hashed_token
      ? await anon.auth.verifyOtp({ type: 'magiclink', token_hash: link.properties.hashed_token })
      : { data: null, error: linkError }
    if (verified?.session) {
      token = verified.session.access_token
      userId = verified.user!.id
    } else {
      console.log(`  (session attempt ${attempt} failed: ${verifyError?.message || linkError?.message || 'no session'})`)
      await new Promise((r) => setTimeout(r, 2000 * attempt))
    }
  }
  if (!token) throw new Error('Could not mint a session for the test tenant')

  const api = async (p: string, init: RequestInit = {}): Promise<Api> => {
    const res = await fetch(`${BASE}${p}`, { ...init, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(init.headers || {}) } })
    const text = await res.text()
    let body: any = null // eslint-disable-line @typescript-eslint/no-explicit-any
    try { body = text ? JSON.parse(text) : null } catch { body = { raw: text.slice(0, 300) } }
    return { status: res.status, body }
  }
  const putPolicy = (id: string, policy: Record<string, unknown>) =>
    api(`/api/v1/agent-scanner/agents/${id}/policy`, { method: 'PUT', body: JSON.stringify({ enabled: true, intervalSeconds: 60, alertThreshold: 'moderate', allowedTargets: [], ...policy }) })
  const runAgent = (agentId: string, agentToken: string) => new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
    const child = spawn(process.execPath, [RUNTIME, 'scan'], {
      env: {
        ...process.env,
        QGUARD_API_URL: BASE,
        QGUARD_AGENT_ID: agentId,
        QGUARD_AGENT_TOKEN: agentToken,
        QGUARD_AGENT_ROLE: 'scanner',
        QGUARD_NATIVE_RUNTIME_ENABLED: 'false',
        QGUARD_ENABLE_REMEDIATION: 'false',
        QGUARD_ENABLE_CONFIG_PATCHES: 'false',
        QGUARD_ENABLE_MIGRATION: 'false',
        // A slow dev server must not make the agent abandon an upload mid-processing.
        QGUARD_REQUEST_TIMEOUT_MS: '120000',
      },
      timeout: 480_000,
    })
    let out = ''
    let err = ''
    child.stdout.on('data', (c) => { out += c })
    child.stderr.on('data', (c) => { err += c })
    child.on('close', (code) => resolve({ code, out, err }))
  })
  const agentRow = async (id: string) => (await admin.from('scanner_agents').select('policy, metadata, status').eq('id', id).single()).data
  const policyRow = async (id: string) => (await admin.from('scanner_agent_policies').select('*').eq('agent_id', id).eq('user_id', userId).maybeSingle()).data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const evidenceSince = async (id: string, since: string) => ((await admin.from('scanner_evidence').select('id, evidence_type, file_path, raw_evidence, created_at').eq('agent_id', id).gte('created_at', since)).data || []) as any[]
  const pause = () => new Promise((r) => setTimeout(r, 1100)) // keep timestamps strictly ordered

  const startedAt = new Date().toISOString()
  const stamp = Date.now().toString(36)
  const lab = fs.mkdtempSync(path.join(os.tmpdir(), 'qguard-settings-lab-'))
  buildLab(lab)
  const agentIds: string[] = []
  const agentNames: string[] = []

  console.log(`\nAgent settings live check — ${BASE}\n  lab: ${lab}`)
  try {
    const name = `settings-check-${stamp}`
    const enrol = await api('/api/v1/agent-scanner/agents/enroll', {
      method: 'POST',
      body: JSON.stringify({
        name,
        role: 'scanner',
        environment: 'lab',
        hostname: os.hostname(),
        platform: `${os.platform()} ${os.arch()}`,
        version: '1.5.5',
        metadata: { role: 'scanner', environment: 'lab', source: 'agent-settings-live-check' },
        policy: { enabled: true, intervalSeconds: 60, scanTypes: ['certificates', 'pki', 'configs', 'libraries', 'packages', 'ssh'], allowedPaths: [lab], allowedTargets: [] },
      }),
    })
    const id = enrol.body?.data?.agent?.id as string
    const agentToken = enrol.body?.data?.enrollment?.agentToken as string
    if (id) { agentIds.push(id); agentNames.push(name) }
    check('a scanner agent enrols', enrol.status === 200 && Boolean(id), `HTTP ${enrol.status}`)

    console.log('\n  delivery receipt')
    const fresh = await agentRow(id)
    check('enrolment records a policy the agent has not yet received', Boolean(fresh?.metadata?.policyUpdatedAt) && !fresh?.metadata?.policyDeliveredAt)
    const first = await runAgent(id, agentToken)
    check('the shipped agent completes its first scan', first.code === 0, `exit ${first.code} ${first.err.slice(0, 200)}`)
    const afterFirst = await agentRow(id)
    check('pulling the policy stamps it delivered (in effect)', Boolean(afterFirst?.metadata?.policyDeliveredAt) && afterFirst!.metadata.policyDeliveredAt >= afterFirst!.metadata.policyUpdatedAt)
    const firstEvidence = await evidenceSince(id, startedAt)
    const firstTypes = new Set(firstEvidence.map((r) => r.evidence_type))
    console.log(`        baseline scan: ${firstEvidence.length} evidence rows — ${[...firstTypes].join(', ')}`)
    check('the broad baseline policy collects several evidence types', firstTypes.size >= 3)
    // Positive control for the threshold test below: under "moderate" this lab DOES raise non-critical alerts.
    const firstIds = new Set(firstEvidence.map((r) => r.id))
    const { data: baselineAlerts } = await admin.from('scanner_alerts').select('severity, evidence_id').eq('agent_id', id)
    const baselineNonCritical = (baselineAlerts || []).filter((a) => a.evidence_id && firstIds.has(a.evidence_id) && a.severity !== 'critical').length
    console.log(`        ${baselineNonCritical} non-critical alert(s) under the moderate baseline threshold`)
    check('under the moderate threshold the same lab raises non-critical alerts (control)', baselineNonCritical > 0)

    /* ── narrow the modules, raise the threshold ── */
    console.log('\n  narrowed modules + threshold')
    await pause()
    const narrowed = await putPolicy(id, { scanTypes: ['certificates', 'runtime', 'cloud'], allowedPaths: [lab], alertThreshold: 'critical', intervalSeconds: 30 })
    check('saving a policy succeeds', narrowed.status === 200, `HTTP ${narrowed.status} ${JSON.stringify(narrowed.body?.error || '')}`)
    check('a module the role excludes is removed AND reported', (narrowed.body?.data?.denied?.role || []).includes('runtime'))
    check('a module the agent does not implement is refused AND reported', (narrowed.body?.data?.denied?.unknown || []).includes('cloud'))
    const stored = await policyRow(id)
    const storedAgent = await agentRow(id)
    check('the policy row holds exactly what the agent will run', JSON.stringify(stored?.scan_types) === JSON.stringify(['certificates']) && stored?.alert_threshold === 'critical' && stored?.interval_seconds === 30)
    check('the agent row carries the same policy', JSON.stringify(storedAgent?.policy?.scanTypes) === JSON.stringify(['certificates']) && storedAgent?.policy?.alertThreshold === 'critical')
    check('the change reads as pending until the agent pulls it', storedAgent?.metadata?.policyUpdatedAt > storedAgent?.metadata?.policyDeliveredAt)
    const narrowedAt = new Date().toISOString()
    await pause()
    const second = await runAgent(id, agentToken)
    check('the agent completes a scan under the narrowed policy', second.code === 0, `exit ${second.code} · ${second.out.slice(-300)} · ${second.err.slice(-300)}`)
    const afterSecond = await agentRow(id)
    check('the narrowed policy is now in effect', afterSecond!.metadata.policyDeliveredAt >= afterSecond!.metadata.policyUpdatedAt)
    const secondEvidence = await evidenceSince(id, narrowedAt)
    const secondTypes = [...new Set(secondEvidence.map((r) => r.evidence_type))]
    console.log(`        narrowed scan: ${secondEvidence.length} evidence rows — ${secondTypes.join(', ')}`)
    check('the agent still collects under the narrowed policy', secondEvidence.length > 0)
    /* Certificates and PKI are one family in the runtime: certificate and key
       files plus the JWKS / SAML documents that publish signing keys — so the
       proof is WHERE it read, not a guess at row types. Config files (app/,
       migrate/), package manifests (deps/) and SSH keys (ssh/) are other
       modules and must be gone. */
    const offModule = secondEvidence.filter((r) => /[\\/](app|migrate|deps|ssh)[\\/]/.test(r.file_path || '') || ['crypto-library', 'ssh-metadata'].includes(r.evidence_type))
    check(
      'it no longer reads config files, package manifests, libraries or SSH keys',
      secondEvidence.length > 0 && offModule.length === 0,
      offModule.map((r) => `${r.evidence_type}:${r.file_path}`).slice(0, 4).join(', '),
    )
    check('everything it collected is certificate, key or identity material (pki/, keys/, identity/)', secondEvidence.every((r) => /[\\/](pki|keys|identity)[\\/]/.test(r.file_path || '')))
    /* Alerts are attributed through the evidence that raised them, not by
       timestamp: a batch received BEFORE the change is still being judged by
       the policy that was in force when it arrived, which is correct. */
    const secondIds = new Set(secondEvidence.map((r) => r.id))
    const { data: agentAlerts } = await admin.from('scanner_alerts').select('severity, category, title, created_at, evidence_id, metadata').eq('agent_id', id)
    const alerts = (agentAlerts || []).filter((a) => a.evidence_id && secondIds.has(a.evidence_id))
    console.log(`        ${alerts.length} alert(s) raised by the narrowed scan's evidence`)
    check(
      'the critical threshold raises alerts for critical findings only',
      alerts.every((a) => a.severity === 'critical'),
      JSON.stringify(alerts.filter((a) => a.severity !== 'critical').slice(0, 3).map((a) => ({ s: a.severity, c: a.category, t: a.title, at: a.created_at, src: a.metadata?.source }))) + ` narrowedAt=${narrowedAt}`,
    )

    /* ── narrow the path ── */
    console.log('\n  narrowed path')
    const pkiOnly = path.join(lab, 'pki')
    await putPolicy(id, { scanTypes: ['certificates', 'configs', 'pki'], allowedPaths: [pkiOnly] })
    const pathAt = new Date().toISOString()
    await pause()
    const third = await runAgent(id, agentToken)
    check('the agent completes a scan under the narrowed path', third.code === 0, `exit ${third.code}`)
    const thirdEvidence = await evidenceSince(id, pathAt)
    const norm = (p: string) => p.replace(/\\/g, '/').toLowerCase()
    const outside = thirdEvidence.filter((r) => r.file_path && !norm(r.file_path).startsWith(norm(pkiOnly)))
    check('it reads only inside the authorised path', thirdEvidence.length > 0 && outside.length === 0, `${outside.length} outside: ${outside.slice(0, 3).map((r) => r.file_path).join(', ')}`)

    /* ── disable ── */
    console.log('\n  scanning disabled')
    await putPolicy(id, { enabled: false, scanTypes: ['certificates'], allowedPaths: [lab] })
    const disabledAt = new Date().toISOString()
    await pause()
    const fourth = await runAgent(id, agentToken)
    check('a disabled agent still runs and checks in', fourth.code === 0 && /disabled/i.test(fourth.out), `exit ${fourth.code}`)
    check('a disabled agent uploads NO evidence', (await evidenceSince(id, disabledAt)).length === 0)
    const { data: beats } = await admin.from('agent_heartbeats').select('status').eq('agent_id', id).gte('observed_at', disabledAt)
    check('it reports itself disabled on its heartbeat', (beats || []).some((b) => b.status === 'disabled'))
    const afterDisable = await agentRow(id)
    check('the disabled policy is recorded as delivered', afterDisable!.metadata.policyDeliveredAt >= afterDisable!.metadata.policyUpdatedAt)

    /* ── refusals ── */
    console.log('\n  refusals')
    const empty = await putPolicy(id, { scanTypes: ['cloud', 'web_application'], allowedPaths: [lab] })
    check('a policy of only unknown modules is refused (400) with the reason', empty.status === 400 && empty.body?.error?.code === 'POLICY_SCOPE_EMPTY' && (empty.body?.error?.detail?.unknown || []).includes('web_application'))
    const unchanged = await policyRow(id)
    check('a refused policy leaves the stored one untouched', unchanged?.enabled === false && JSON.stringify(unchanged?.scan_types) === JSON.stringify(['certificates']))
    const ghost = await putPolicy(randomUUID(), { scanTypes: ['certificates'], allowedPaths: [lab] })
    check('an agent this tenant does not own is refused (404)', ghost.status === 404)
    const { data: foreign } = await admin.from('scanner_agents').select('id, policy').neq('user_id', userId).limit(1).maybeSingle()
    if (foreign?.id) {
      const cross = await putPolicy(foreign.id, { scanTypes: ['certificates'], allowedPaths: ['/tmp'] })
      const after = (await admin.from('scanner_agents').select('policy').eq('id', foreign.id).single()).data
      check('ANOTHER tenant\'s agent is refused (404) and left unchanged', cross.status === 404 && JSON.stringify(after?.policy) === JSON.stringify(foreign.policy))
    }
    const revoke = await api(`/api/v1/agent-scanner/agents/${id}/revoke`, { method: 'POST' })
    const revoked = await putPolicy(id, { scanTypes: ['certificates'], allowedPaths: [lab] })
    check('a revoked agent\'s policy can no longer be changed (409)', revoke.status === 200 && revoked.status === 409)
  } finally {
    console.log('\n  cleanup')
    for (const agentId of agentIds) {
      for (const table of ['crypto_inventory', 'pqc_scan_results', 'crypto_exposures']) {
        await admin.from(table).delete().eq('user_id', userId).eq('metadata->evidenceRecord->>agentId', agentId)
      }
      await admin.from('certificates').delete().eq('user_id', userId).eq('metadata->>agentId', agentId)
      for (const table of ['scanner_alerts', 'scanner_evidence', 'agent_heartbeats', 'scanner_agent_policies', 'runtime_crypto_events']) {
        await admin.from(table).delete().eq('user_id', userId).eq('agent_id', agentId)
      }
    }
    for (const name of agentNames) {
      for (const label of [`agent:${name}`, `agent-runtime:${name}`]) {
        await admin.from('pqc_scan_sessions').delete().eq('user_id', userId).eq('metadata->>sourceLabel', label)
        await admin.from('assets').delete().eq('user_id', userId).eq('metadata->>source', label).gte('created_at', startedAt)
      }
    }
    if (agentIds.length) await admin.from('scanner_agents').delete().eq('user_id', userId).in('id', agentIds)
    fs.rmSync(lab, { recursive: true, force: true })
    const { count: left } = await admin.from('scanner_evidence').select('id', { count: 'exact', head: true }).in('agent_id', agentIds.length ? agentIds : ['-'])
    const { count: assetsLeft } = await admin.from('assets').select('id', { count: 'exact', head: true }).eq('user_id', userId).gte('created_at', startedAt)
    check('cleanup left no rows behind in the test tenant', !left && !assetsLeft, `${left} evidence, ${assetsLeft} assets`)
  }

  console.log(`\n${passed} passed, ${failures.length} failed`)
  if (failures.length) {
    for (const failure of failures) console.log(`  ✗ ${failure}`)
    process.exit(1)
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
