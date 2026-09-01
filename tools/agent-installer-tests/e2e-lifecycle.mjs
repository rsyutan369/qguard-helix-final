/**
 * End-to-end verification of the Agent Installer subsystem.
 *
 * Exercises the real lifecycle against the running dev server:
 *   create -> token -> generate installer -> download runtime (agent creds) ->
 *   verify checksum -> run the actual agent binary -> evidence -> certificates ->
 *   assets/CBOM -> command queue -> ack -> SSE events.
 *
 * Usage: node e2e_agent_installer.mjs
 */

import { createClient } from '@supabase/supabase-js'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const BASE = process.env.QGUARD_TEST_BASE || 'http://localhost:3000'
const OWNER_EMAIL = 'zachmatthew369@gmail.com'

const env = Object.fromEntries(
  fs.readFileSync(new URL('../../.env', import.meta.url), 'utf8')
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
const failures = []

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1
    console.log(`  PASS  ${name}`)
  } else {
    failed += 1
    failures.push(`${name}${detail ? ` — ${detail}` : ''}`)
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

async function session() {
  const { data, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: OWNER_EMAIL })
  if (error) throw new Error(`generateLink: ${error.message}`)
  const tokenHash = data.properties?.hashed_token
  const { data: verified, error: verifyError } = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: tokenHash })
  if (verifyError) throw new Error(`verifyOtp: ${verifyError.message}`)
  return { token: verified.session.access_token, userId: verified.user.id }
}

async function api(pathName, token, init = {}) {
  const response = await fetch(`${BASE}${pathName}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(init.headers || {}),
    },
  })
  const body = await response.json().catch(() => ({}))
  return { status: response.status, body }
}

async function main() {
  console.log('\n=== Qguard Helix Agent Installer — E2E ===\n')

  const { token, userId } = await session()
  console.log(`Tenant: ${userId}\n`)

  /* -------- 1. Release catalog -------- */
  console.log('[1] Release catalog')
  const releases = await api('/api/v1/agent-installer/releases', token)
  check('GET /releases returns 200', releases.status === 200, `got ${releases.status}`)
  const release = releases.body?.data?.current
  check('runtime is published', release?.available === true, release?.reason)
  check('runtime carries a sha256', /^[0-9a-f]{64}$/.test(release?.sha256 || ''))
  check('6 platforms offered', (releases.body?.data?.platforms || []).length === 6)
  check('4 agent roles offered', (releases.body?.data?.roles || []).length === 4)

  /* -------- 2. Create an agent -------- */
  console.log('\n[2] Agent creation + enrollment token')
  const scanRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'qguard-e2e-'))
  fs.writeFileSync(
    path.join(scanRoot, 'server.conf'),
    ['ssl_protocols TLSv1.2;', 'ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;', 'PQC_ENABLED=false'].join('\n'),
    'utf8',
  )
  fs.writeFileSync(
    path.join(scanRoot, 'package.json'),
    JSON.stringify({ name: 'e2e-fixture', dependencies: { 'node-forge': '1.3.1', jsonwebtoken: '9.0.2' } }, null, 2),
    'utf8',
  )

  const created = await api('/api/v1/agent-scanner/agents/enroll', token, {
    method: 'POST',
    body: JSON.stringify({
      name: 'E2E Installer Collector',
      environment: 'lab',
      hostname: 'pending-customer-install',
      platform: 'customer-managed',
      capabilities: { crypto_discovery: true, certificate_discovery: true, tls_inspection: true, telemetry: true },
      policy: {
        enabled: true,
        intervalSeconds: 30,
        allowedTargets: ['cloudflare.com:443'],
        allowedPaths: [scanRoot],
        scanTypes: ['tls', 'certificates', 'pki', 'configs', 'packages', 'libraries'],
        alertThreshold: 'moderate',
      },
      metadata: { role: 'collector', environment: 'lab', source: 'e2e' },
    }),
  })
  check('agent enrolled', created.status === 200, JSON.stringify(created.body).slice(0, 160))
  const agentId = created.body?.data?.enrollment?.agentId
  const agentToken = created.body?.data?.enrollment?.agentToken
  check('one-time token issued', Boolean(agentToken) && agentToken.startsWith('qga_'))

  /* -------- 3. Installer generation for every platform -------- */
  console.log('\n[3] Installer generation')
  const generated = {}
  for (const platform of ['linux', 'windows', 'docker', 'kubernetes', 'powershell', 'cloud-init']) {
    const result = await api('/api/v1/agent-installer/package', token, {
      method: 'POST',
      body: JSON.stringify({ agentId, platform, token: agentToken }),
    })
    const pkg = result.body?.data
    const ok = result.status === 200 && typeof pkg?.content === 'string' && pkg.content.length > 200
    check(`${platform} installer generated`, ok, `${result.status} ${JSON.stringify(result.body).slice(0, 120)}`)
    if (!ok) continue
    generated[platform] = pkg
    const digest = createHash('sha256').update(pkg.content, 'utf8').digest('hex')
    check(`${platform} installer digest matches`, digest === pkg.installerSha256)
    check(`${platform} embeds the runtime digest`, pkg.content.includes(release.sha256))
    check(`${platform} embeds the agent id`, pkg.content.includes(agentId))
    check(`${platform} embeds the enrollment token`, pkg.content.includes(agentToken))
    check(`${platform} does NOT put the token in a URL`, !new RegExp(`[?&][^\\s]*${agentToken}`).test(pkg.content))
  }

  check('linux installer is a bash script', generated.linux?.content.startsWith('#!/usr/bin/env bash'))
  check('linux verifies before installing', /sha256sum/.test(generated.linux?.content || '') && /Checksum mismatch/.test(generated.linux?.content || ''))
  check('linux installs a systemd unit', /\[Install\]/.test(generated.linux?.content || ''))
  check('windows requires Administrator', /IsInRole/.test(generated.windows?.content || ''))
  check('windows verifies via Get-FileHash', /Get-FileHash/.test(generated.windows?.content || ''))
  check('k8s manifest has Namespace+Secret+Deployment', ['kind: Namespace', 'kind: Secret', 'kind: Deployment'].every((k) => (generated.kubernetes?.content || '').includes(k)))
  check('cloud-init is a #cloud-config', (generated['cloud-init']?.content || '').startsWith('#cloud-config'))

  /* -------- 4. Stale-token rejection -------- */
  console.log('\n[4] Token discipline')
  const badToken = await api('/api/v1/agent-installer/package', token, {
    method: 'POST',
    body: JSON.stringify({ agentId, platform: 'linux', token: 'qga_not_a_real_token' }),
  })
  check('stale token is rejected', badToken.status === 409, `got ${badToken.status}`)
  const noToken = await api('/api/v1/agent-installer/package', token, {
    method: 'POST',
    body: JSON.stringify({ agentId, platform: 'linux' }),
  })
  check('missing token is rejected', noToken.status === 409, `got ${noToken.status}`)

  /* -------- 5. Runtime download with agent credentials -------- */
  console.log('\n[5] Runtime download (agent-credentialed)')
  const runtimeResponse = await fetch(`${BASE}/api/v1/agent-installer/runtime`, {
    headers: { 'x-qguard-agent-id': agentId, 'x-qguard-agent-token': agentToken },
  })
  check('runtime download 200', runtimeResponse.status === 200, `got ${runtimeResponse.status}`)
  const runtimeBytes = Buffer.from(await runtimeResponse.arrayBuffer())
  const runtimeDigest = createHash('sha256').update(runtimeBytes).digest('hex')
  check('downloaded runtime matches published digest', runtimeDigest === release.sha256)
  check('digest advertised in response header', runtimeResponse.headers.get('x-qguard-runtime-sha256') === release.sha256)

  const anonRuntime = await fetch(`${BASE}/api/v1/agent-installer/runtime`)
  check('runtime is NOT anonymously downloadable', anonRuntime.status === 401, `got ${anonRuntime.status}`)

  const wrongCred = await fetch(`${BASE}/api/v1/agent-installer/runtime`, {
    headers: { 'x-qguard-agent-id': agentId, 'x-qguard-agent-token': 'qga_wrong' },
  })
  check('runtime rejects a wrong agent token', wrongCred.status === 401, `got ${wrongCred.status}`)

  /* -------- 6. Queue a scan command -------- */
  console.log('\n[6] Command queue')
  const scanCommand = await api(`/api/v1/agent-installer/agents/${agentId}/scan`, token, { method: 'POST' })
  check('scan command queued', scanCommand.status === 200 && scanCommand.body?.data?.command?.type === 'scan')
  check('delivery expectation is honest', /not currently connected|next poll/.test(scanCommand.body?.data?.delivery || ''))
  const duplicate = await api(`/api/v1/agent-installer/agents/${agentId}/scan`, token, { method: 'POST' })
  check('duplicate scan command deduplicated', duplicate.body?.data?.deduplicated === true)

  /* -------- 7. SSE stream -------- */
  console.log('\n[7] Realtime event stream')
  const streamEvents = []
  const controller = new AbortController()
  const streamPromise = (async () => {
    const response = await fetch(`${BASE}/api/v1/agent-installer/events/stream?token=${encodeURIComponent(token)}`, {
      signal: controller.signal,
    })
    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        for (const match of buffer.matchAll(/event: ([^\n]+)/g)) streamEvents.push(match[1])
        buffer = buffer.slice(-2000)
      }
    } catch {
      /* aborted */
    }
  })()
  await new Promise((resolve) => setTimeout(resolve, 800))
  check('stream announces readiness', streamEvents.includes('stream.ready'))

  /* -------- 8. Run the REAL agent runtime -------- */
  console.log('\n[8] Running the published agent runtime')
  const runtimePath = path.join(os.tmpdir(), `qguard-agent-e2e-${Date.now()}.cjs`)
  fs.writeFileSync(runtimePath, runtimeBytes)

  const agentRun = await new Promise((resolve) => {
    const child = spawn(process.execPath, [runtimePath, 'scan'], {
      env: {
        ...process.env,
        QGUARD_API_URL: BASE,
        QGUARD_AGENT_ID: agentId,
        QGUARD_AGENT_TOKEN: agentToken,
        QGUARD_AGENT_ROLE: 'collector',
        QGUARD_NATIVE_RUNTIME_ENABLED: 'false',
      },
      timeout: 180_000,
    })
    let out = ''
    let err = ''
    child.stdout.on('data', (chunk) => { out += chunk })
    child.stderr.on('data', (chunk) => { err += chunk })
    child.on('close', (code) => resolve({ code, out, err }))
  })

  console.log(agentRun.out.split('\n').filter(Boolean).map((line) => `        ${line}`).join('\n'))
  if (agentRun.err) console.log(`        stderr: ${agentRun.err.slice(0, 400)}`)
  check('agent runtime exited cleanly', agentRun.code === 0, `exit ${agentRun.code}`)
  check('agent reported a completed scan', /scan complete/i.test(agentRun.out))

  await new Promise((resolve) => setTimeout(resolve, 1500))
  controller.abort()
  await streamPromise.catch(() => {})

  check('stream delivered scan progress', streamEvents.includes('agent.scan_progress'), streamEvents.join(','))
  check('stream delivered scan completion', streamEvents.includes('agent.scan_completed'))
  check('stream delivered a connection/heartbeat event', streamEvents.some((e) => e === 'agent.connected' || e === 'agent.heartbeat'))

  /* -------- 9. Command was picked up and acknowledged -------- */
  console.log('\n[9] Command execution')
  const jobs = await api(`/api/v1/agent-installer/agents/${agentId}/jobs`, token)
  const history = jobs.body?.data?.history || []
  check('queued command left the queue', (jobs.body?.data?.queued || []).length === 0, JSON.stringify(jobs.body?.data?.queued || []).slice(0, 120))
  check('command recorded as completed', history.some((item) => item.type === 'scan' && item.status === 'completed'))

  /* -------- 10. Evidence + dashboard materialisation -------- */
  console.log('\n[10] Evidence and dashboard materialisation')
  const findings = await api(`/api/v1/agent-installer/agents/${agentId}/findings`, token)
  const evidence = findings.body?.data?.evidence || []
  check('findings endpoint 200', findings.status === 200)
  check('agent produced evidence', evidence.length > 0, `${evidence.length} rows`)
  check('scanned flag is true', findings.body?.data?.scanned === true)
  check('TLS certificate evidence captured', evidence.some((row) => row.evidence_type === 'tls-certificate'))
  check('config evidence captured', evidence.some((row) => row.evidence_type === 'config-reference' || row.file_path))
  check('every evidence row names an algorithm', evidence.every((row) => Boolean(row.observed_algorithm)))
  check('every evidence row has a confidence', evidence.every((row) => Boolean(row.confidence)))

  const health = await api(`/api/v1/agent-installer/agents/${agentId}/health`, token)
  check('health endpoint 200', health.status === 200)
  check('host telemetry reported', health.body?.data?.telemetryAvailable === true)
  check('connection reads Connected', health.body?.data?.connectionState === 'Connected', health.body?.data?.connectionState)
  check('cpu/memory present', Boolean(health.body?.data?.host?.cpuCount) && health.body?.data?.memory?.usedPercent != null)

  const activity = await api(`/api/v1/agent-installer/agents/${agentId}/activity`, token)
  const timeline = activity.body?.data?.activity || []
  check('activity timeline populated', timeline.length > 0, `${timeline.length} entries`)
  check('timeline includes scan stages', timeline.some((entry) => entry.stage))

  const scans = await api(`/api/v1/agent-installer/agents/${agentId}/scans`, token)
  check('scan history recorded', (scans.body?.data?.scans || []).length > 0)

  // Canonical tables the dashboards read.
  const since = new Date(Date.now() - 15 * 60 * 1000).toISOString()
  const { data: certs } = await admin
    .from('certificates')
    .select('id, name, algorithm, key_size, issuer, subject, serial_number, not_after, is_quantum_safe, metadata')
    .eq('user_id', userId)
    .gte('updated_at', since)
  check('certificates materialised for PKI dashboard', (certs || []).length > 0, `${(certs || []).length} rows`)
  const agentCert = (certs || []).find((row) => row.metadata?.agentId === agentId)
  check('certificate is attributed to this agent', Boolean(agentCert))
  check('certificate carries issuer + subject', Boolean(agentCert?.issuer) && Boolean(agentCert?.subject))
  check('certificate carries validity window', Boolean(agentCert?.not_after))
  check('certificate carries a quantum classification', Boolean(agentCert?.metadata?.quantumClassification))
  check('classical cert is NOT marked quantum safe', agentCert?.is_quantum_safe !== true)
  check('certificate records its detection method', agentCert?.metadata?.detectionMethod === 'agent-tls-handshake-observation')

  const { data: inventory } = await admin
    .from('crypto_inventory')
    .select('id, algorithm, is_vulnerable, is_quantum_safe, metadata')
    .eq('user_id', userId)
    .gte('created_at', since)
  check('CBOM rows written', (inventory || []).length > 0, `${(inventory || []).length} rows`)

  const { data: assets } = await admin.from('assets').select('id, name, metadata').eq('user_id', userId).gte('updated_at', since)
  check('assets materialised', (assets || []).length > 0, `${(assets || []).length} rows`)

  const { data: results } = await admin
    .from('pqc_scan_results')
    .select('id, algorithm, threat_level')
    .eq('user_id', userId)
    .gte('created_at', since)
  check('pqc_scan_results written', (results || []).length > 0, `${(results || []).length} rows`)

  const quantumVulnerable = (results || []).filter((row) => ['critical', 'high'].includes(String(row.threat_level)))
  check('quantum-vulnerable findings classified', quantumVulnerable.length > 0, `${quantumVulnerable.length} rows`)

  /* -------- 11. Not-Yet-Assessed discipline -------- */
  console.log('\n[11] Accuracy discipline')
  const fresh = await api('/api/v1/agent-scanner/agents/enroll', token, {
    method: 'POST',
    body: JSON.stringify({
      name: 'E2E Never Installed',
      environment: 'lab',
      policy: { enabled: true, intervalSeconds: 60, allowedTargets: [], allowedPaths: [], scanTypes: ['tls'], alertThreshold: 'moderate' },
      metadata: { role: 'collector', source: 'e2e' },
    }),
  })
  const freshId = fresh.body?.data?.enrollment?.agentId
  const freshFindings = await api(`/api/v1/agent-installer/agents/${freshId}/findings`, token)
  check('never-scanned agent reports scanned=false', freshFindings.body?.data?.scanned === false)
  const freshHealth = await api(`/api/v1/agent-installer/agents/${freshId}/health`, token)
  check('never-installed agent is NOT "Offline"', freshHealth.body?.data?.connectionState === 'Connecting' || freshHealth.body?.data?.connectionState === 'Waiting', freshHealth.body?.data?.connectionState)
  check('never-installed agent has no fabricated telemetry', freshHealth.body?.data?.telemetryAvailable === false && freshHealth.body?.data?.host === null)

  /* -------- 12. Summary + tenant isolation -------- */
  console.log('\n[12] Summary + isolation')
  const summary = await api('/api/v1/agent-installer/summary', token)
  check('summary endpoint 200', summary.status === 200)
  check('summary counts our agents', (summary.body?.data?.summary?.total || 0) >= 2)
  check('summary never leaks a token hash', !JSON.stringify(summary.body).includes('token_hash":"'))
  const connectedCount = summary.body?.data?.summary?.connected || 0
  check('summary shows one connected agent', connectedCount >= 1, `${connectedCount}`)

  const unauth = await fetch(`${BASE}/api/v1/agent-installer/summary`)
  check('summary requires auth', unauth.status === 401)

  /* -------- 13. Revocation -------- */
  console.log('\n[13] Revocation')
  await api(`/api/v1/agent-scanner/agents/${agentId}/revoke`, token, { method: 'POST' })
  const revokedRuntime = await fetch(`${BASE}/api/v1/agent-installer/runtime`, {
    headers: { 'x-qguard-agent-id': agentId, 'x-qguard-agent-token': agentToken },
  })
  check('revoked agent cannot download the runtime', revokedRuntime.status === 401, `got ${revokedRuntime.status}`)
  const revokedCommand = await api(`/api/v1/agent-installer/agents/${agentId}/scan`, token, { method: 'POST' })
  check('revoked agent cannot be commanded', revokedCommand.status === 409, `got ${revokedCommand.status}`)

  /* -------- cleanup -------- */
  await api(`/api/v1/agent-scanner/agents/${agentId}`, token, { method: 'DELETE' })
  await api(`/api/v1/agent-scanner/agents/${freshId}`, token, { method: 'DELETE' })
  fs.rmSync(scanRoot, { recursive: true, force: true })
  fs.rmSync(runtimePath, { force: true })

  console.log(`\n=== ${passed} passed, ${failed} failed ===`)
  if (failures.length) {
    console.log('\nFailures:')
    for (const failure of failures) console.log(`  - ${failure}`)
  }
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error('\nE2E harness error:', error)
  process.exit(1)
})
