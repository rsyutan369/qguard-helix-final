/**
 * Regression guard for the "scan stops at 85%" defect class.
 *
 * A Windows lab agent enrolled with an empty policy (no authorized targets, no
 * authorized paths) ran its whole scan, reached "Calculating quantum exposure"
 * at 85%, and then died: the control plane answered its host-local runtime
 * telemetry with 403 RUNTIME_EVENTS_OUT_OF_POLICY, the agent threw, and no
 * terminal frame was ever emitted. The Agent Center rendered 85% forever and the
 * scan session never closed.
 *
 * Four independent properties have to hold for that to be impossible. This test
 * asserts each of them against the running dev server with a real enrolled agent
 * and the real agent runtime.
 *
 *   1. Host-local telemetry is accepted with an empty policy (authorized by
 *      enrolment, not by the remote-target allowlist).
 *   2. A fully out-of-scope batch is accounted for, not answered with an error
 *      that aborts the scan.
 *   3. Every scan reaches a terminal progress stage - success or failure.
 *   4. A failed scan closes its session instead of reading "Running" forever.
 *
 * Usage: node tools/agent-installer-tests/verify-scan-terminal-state.mjs
 */

import { createClient } from '@supabase/supabase-js'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const BASE = process.env.QGUARD_TEST_BASE || 'http://localhost:3000'

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

let passed = 0
const failures = []

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1
    console.log(`  PASS  ${name}`)
  } else {
    failures.push(`${name}${detail ? ` -- ${detail}` : ''}`)
    console.log(`  FAIL  ${name}${detail ? ` -- ${detail}` : ''}`)
  }
}

function agentFetch(pathName, agentId, token, init = {}) {
  return fetch(`${BASE}${pathName}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      'x-qguard-agent-id': agentId,
      'x-qguard-agent-token': token,
      ...(init.headers || {}),
    },
  })
}

async function main() {
  console.log(`\nScan terminal-state regression guard -> ${BASE}\n`)

  // ---- Enrol a throwaway agent with a deliberately EMPTY policy -------------
  const { data: owner } = await admin.from('profiles').select('id').limit(1).maybeSingle()
  if (!owner) throw new Error('No tenant found to enrol a test agent against.')

  const token = `qg_test_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`
  const tokenHash = await import('node:crypto').then((c) => c.createHash('sha256').update(token).digest('hex'))
  const hostname = os.hostname()

  const { data: agent, error } = await admin.from('scanner_agents').insert({
    user_id: owner.id,
    name: `terminal-state-guard-${Date.now()}`,
    token_hash: tokenHash,
    status: 'active',
    hostname,
    platform: `${os.platform()} ${os.release()} ${os.arch()}`,
    version: '0.0.0-test',
    capabilities: { cbom: true },
    // The exact condition that broke the lab agent: no scope at all.
    policy: { enabled: true, intervalSeconds: 60, allowedTargets: [], allowedPaths: [], scanTypes: ['tls', 'runtime'], alertThreshold: 'moderate' },
    metadata: { source: 'regression-test' },
  }).select('*').single()
  if (error) throw new Error(`Could not enrol test agent: ${error.message}`)
  console.log(`  enrolled ${agent.id} (hostname ${hostname}, empty policy)\n`)

  try {
    // ---- 1. Host-local telemetry is authorized by ENROLMENT ----------------
    console.log('1. Host-local telemetry under an empty policy')
    const selfHost = await agentFetch('/api/v1/agent-scanner/agent/runtime-events', agent.id, token, {
      method: 'POST',
      body: JSON.stringify({
        events: [{
          eventType: 'process-crypto-usage',
          operationType: 'process_crypto_inventory',
          assetName: 'testproc',
          assetType: 'host_process',
          host: hostname,
          algorithm: 'Windows Crypto API (CNG/Schannel)',
          severity: 'low',
          riskScore: 20,
          metadata: { collector: 'regression-test', evidenceClass: 'library-presence' },
          observedAt: new Date().toISOString(),
        }],
      }),
    })
    const selfBody = await selfHost.json().catch(() => ({}))
    check('self-host runtime telemetry is accepted (not 403)', selfHost.status === 200,
      `status ${selfHost.status} ${JSON.stringify(selfBody?.error || '')}`)
    check('accepted count is 1', Number(selfBody?.data?.acceptedEventCount) === 1,
      JSON.stringify(selfBody?.data ?? {}).slice(0, 200))

    // ---- 2. Out-of-scope batches are accounted for, never fatal ------------
    console.log('\n2. A batch naming a host this agent was never authorized for')
    const foreign = await agentFetch('/api/v1/agent-scanner/agent/runtime-events', agent.id, token, {
      method: 'POST',
      body: JSON.stringify({
        events: [{
          eventType: 'tls-protocol',
          operationType: 'tls_handshake',
          assetName: 'someone-elses-host.example.com',
          host: 'someone-elses-host.example.com',
          port: 443,
          algorithm: 'RSA',
          observedAt: new Date().toISOString(),
        }],
      }),
    })
    const foreignBody = await foreign.json().catch(() => ({}))
    check('out-of-scope batch is acknowledged, not errored', foreign.status === 200,
      `status ${foreign.status}`)
    check('out-of-scope batch stores nothing', Number(foreignBody?.data?.acceptedEventCount ?? -1) === 0,
      JSON.stringify(foreignBody?.data ?? {}).slice(0, 200))
    check('rejection is reported to the operator', foreignBody?.data?.outOfPolicy === true,
      JSON.stringify(foreignBody?.data ?? {}).slice(0, 200))

    // ---- 3. The real runtime always reaches a terminal stage ---------------
    console.log('\n3. Full scan with the real agent runtime')
    const runtime = path.resolve('tools/qguard-agent/dist/qguard-agent.cjs')
    if (!fs.existsSync(runtime)) throw new Error(`Agent runtime not built: ${runtime}`)

    const before = new Date().toISOString()
    const scan = await new Promise((resolve) => {
      const child = spawn(process.execPath, [runtime, 'scan'], {
        env: {
          ...process.env,
          QGUARD_API_URL: BASE,
          QGUARD_AGENT_ID: agent.id,
          QGUARD_AGENT_TOKEN: token,
        },
        windowsHide: true,
      })
      let out = ''
      child.stdout.on('data', (d) => { out += d })
      child.stderr.on('data', (d) => { out += d })
      const timer = setTimeout(() => { child.kill(); resolve({ code: null, out, timedOut: true }) }, 180_000)
      child.on('close', (code) => { clearTimeout(timer); resolve({ code, out, timedOut: false }) })
    })
    check('agent process exited cleanly', scan.code === 0 && !scan.timedOut,
      `exit ${scan.code}${scan.timedOut ? ' (timed out)' : ''} :: ${scan.out.slice(-400)}`)

    const { data: frames } = await admin
      .from('agent_heartbeats')
      .select('status,telemetry,observed_at')
      .eq('agent_id', agent.id)
      .gte('observed_at', before)
      .order('observed_at', { ascending: true })

    const stages = (frames || []).filter((f) => f.status === 'scan_progress').map((f) => f.telemetry?.stage)
    const terminal = stages.filter((s) => s === 'scan_complete' || s === 'scan_failed')
    check('a terminal progress stage was emitted', terminal.length > 0, `stages: ${stages.join(' -> ')}`)
    check('progress did not stop at calculating_exposure',
      stages[stages.length - 1] !== 'calculating_exposure', `last stage: ${stages[stages.length - 1]}`)

    const phases = (frames || []).map((f) => f.telemetry?.phase).filter(Boolean)
    check('a terminal heartbeat phase was recorded',
      phases.includes('completed') || phases.includes('failed'), `phases: ${phases.join(', ')}`)

    // ---- 4. The session closes ---------------------------------------------
    console.log('\n4. Scan session closes rather than reading "Running" forever')
    const rows = [...(frames || [])].reverse()
    let pendingStart = null
    let closed = 0
    for (const row of [...rows].reverse()) {
      const phase = row.telemetry?.phase
      if (phase === 'starting') pendingStart = row
      if (phase === 'completed' || phase === 'failed') { closed += 1; pendingStart = null }
    }
    check('the scan session reached a terminal phase', closed > 0 && !pendingStart,
      `closed ${closed}, still open: ${Boolean(pendingStart)}`)

    // ---- 5. Nothing fabricated ---------------------------------------------
    console.log('\n5. No verdict was published without evidence for it')
    const { data: events } = await admin
      .from('runtime_crypto_events')
      .select('event_type,algorithm,protocol,downgrade_detected,shadow_crypto,severity')
      .eq('agent_id', agent.id)
      .limit(1000)
    const bogusDowngrade = (events || []).filter((e) => e.downgrade_detected && !e.protocol)
    check('no downgrade claimed without an observed protocol', bogusDowngrade.length === 0,
      `${bogusDowngrade.length} event(s): ${JSON.stringify(bogusDowngrade.slice(0, 3))}`)
    const presenceCriticals = (events || []).filter(
      (e) => e.event_type === 'process-crypto-usage' && ['critical', 'high'].includes(String(e.severity)),
    )
    check('library presence is not published as critical/high', presenceCriticals.length === 0,
      `${presenceCriticals.length} event(s): ${JSON.stringify(presenceCriticals.slice(0, 3))}`)
    console.log(`  (${(events || []).length} runtime event(s) stored for this agent)`)
  } finally {
    await admin.from('runtime_crypto_events').delete().eq('agent_id', agent.id)
    await admin.from('scanner_evidence').delete().eq('agent_id', agent.id)
    await admin.from('agent_heartbeats').delete().eq('agent_id', agent.id)
    await admin.from('scanner_agents').delete().eq('id', agent.id)
    console.log('\n  test agent and its data removed')
  }

  console.log(`\n${passed} passed, ${failures.length} failed`)
  if (failures.length) {
    console.log('\nFailures:')
    for (const f of failures) console.log(`  - ${f}`)
    process.exit(1)
  }
}

main().catch((error) => {
  console.error(`\nTest harness error: ${error.message}`)
  process.exit(1)
})
