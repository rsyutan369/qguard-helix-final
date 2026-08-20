/**
 * Agent Center — authentication, entitlement and tenant-isolation verification.
 *
 * Answers three questions with evidence rather than assertion:
 *   1. Can an unauthenticated caller reach anything?
 *   2. Can an under-entitled (Starter/Basic) tenant reach the Agent Center API?
 *   3. Can one Pro tenant read, command, or generate installers for ANOTHER
 *      tenant's agents — or see their events, evidence or assets?
 *
 * Victim  : zachmatthew369@gmail.com (Elite)
 * Attacker: teslagreat101@gmail.com  (Pro — entitled, so a 403 cannot mask a
 *           missing ownership check; only a real 404/empty proves isolation)
 *
 * Usage: npm run agent:test:isolation   (dev server must be on :3000)
 */

import { createClient } from '@supabase/supabase-js'
import fs from 'node:fs'

const BASE = 'http://localhost:3000'
const VICTIM = 'zachmatthew369@gmail.com'
const ATTACKER = 'teslagreat101@gmail.com'
const STARTER = 'cybersniper26@gmail.com'
const BASIC = 'threathunter369@gmail.com'

const env = Object.fromEntries(
  fs.readFileSync(new URL('../../.env', import.meta.url), 'utf8')
    .split(/\r?\n/)
    .filter((l) => l.includes('=') && !l.startsWith('#'))
    .map((l) => { const i = l.indexOf('='); return [l.slice(0, i).trim(), l.slice(i + 1).trim().replace(/^["']|["']$/g, '')] }),
)

const admin = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
const anon = createClient(env.VITE_SUPABASE_URL, env.VITE_SUPABASE_ANON_KEY, { auth: { persistSession: false } })

let pass = 0
let fail = 0
const failures = []
const check = (name, ok, detail = '') => {
  if (ok) { pass += 1; console.log(`  PASS  ${name}`) }
  else { fail += 1; failures.push(`${name}${detail ? ` — ${detail}` : ''}`); console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`) }
}

async function sessionFor(email) {
  const link = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (link.error) throw new Error(`${email}: ${link.error.message}`)
  const verified = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: link.data.properties.hashed_token })
  if (verified.error) throw new Error(`${email}: ${verified.error.message}`)
  return { token: verified.data.session.access_token, userId: verified.data.user.id }
}

async function call(path, token, init = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.headers || {}),
    },
  })
  const body = await res.json().catch(() => ({}))
  return { status: res.status, body }
}

console.log('\n=== Agent Center — auth, entitlement & tenant isolation ===\n')

const victim = await sessionFor(VICTIM)
const attacker = await sessionFor(ATTACKER)
const starter = await sessionFor(STARTER)
const basic = await sessionFor(BASIC)

console.log(`victim   ${victim.userId}`)
console.log(`attacker ${attacker.userId}\n`)
if (victim.userId === attacker.userId) {
  console.log('Victim and attacker resolved to the same tenant — test is meaningless.')
  process.exit(1)
}

/* ---------------- 1. Unauthenticated ---------------- */
console.log('[1] Unauthenticated access')
const ANON_PATHS = [
  ['GET', '/api/v1/agent-installer/releases'],
  ['GET', '/api/v1/agent-installer/summary'],
  ['POST', '/api/v1/agent-installer/package'],
  ['GET', '/api/v1/agent-installer/runtime'],
  ['GET', '/api/v1/agent-installer/self'],
  ['POST', '/api/v1/agent-installer/installation-event'],
  ['GET', '/api/v1/agent-installer/events/stream'],
  ['GET', '/api/v1/agent-scanner/agents'],
  ['POST', '/api/v1/agent-scanner/agents/enroll'],
]
for (const [method, path] of ANON_PATHS) {
  const res = await call(path, null, { method, body: method === 'POST' ? '{}' : undefined })
  check(`anonymous ${method} ${path.replace('/api/v1/', '')} rejected`, res.status === 401, `got ${res.status}`)
}

const bogus = await call('/api/v1/agent-installer/summary', 'not-a-real-jwt')
check('forged bearer token rejected', bogus.status === 401, `got ${bogus.status}`)

/* ---------------- 2. Entitlement ---------------- */
console.log('\n[2] Plan entitlement (Agent Center is Pro+)')
for (const [label, who] of [['starter', starter], ['basic', basic]]) {
  const summary = await call('/api/v1/agent-installer/summary', who.token)
  check(`${label} tenant blocked from /summary`, summary.status === 403, `got ${summary.status}`)
  const releases = await call('/api/v1/agent-installer/releases', who.token)
  check(`${label} tenant blocked from /releases`, releases.status === 403, `got ${releases.status}`)
  const enroll = await call('/api/v1/agent-scanner/agents/enroll', who.token, { method: 'POST', body: JSON.stringify({ name: 'should-not-exist' }) })
  check(`${label} tenant cannot enroll an agent`, enroll.status === 403, `got ${enroll.status}`)
}
const proSummary = await call('/api/v1/agent-installer/summary', attacker.token)
check('pro tenant allowed through the gate', proSummary.status === 200, `got ${proSummary.status}`)

/* ---------------- 3. Victim creates an agent ---------------- */
console.log('\n[3] Victim provisions an agent')
const created = await call('/api/v1/agent-scanner/agents/enroll', victim.token, {
  method: 'POST',
  body: JSON.stringify({
    name: 'Isolation Victim Agent',
    environment: 'lab',
    policy: { enabled: true, intervalSeconds: 60, allowedTargets: ['example.com:443'], allowedPaths: [], scanTypes: ['tls'], alertThreshold: 'moderate' },
    metadata: { role: 'collector', source: 'isolation-test' },
  }),
})
check('victim agent created', created.status === 200, JSON.stringify(created.body).slice(0, 140))
const victimAgentId = created.body?.data?.enrollment?.agentId
const victimAgentToken = created.body?.data?.enrollment?.agentToken

const attackerCreated = await call('/api/v1/agent-scanner/agents/enroll', attacker.token, {
  method: 'POST',
  body: JSON.stringify({
    name: 'Isolation Attacker Agent',
    environment: 'lab',
    policy: { enabled: true, intervalSeconds: 60, allowedTargets: [], allowedPaths: [], scanTypes: ['tls'], alertThreshold: 'moderate' },
    metadata: { role: 'collector', source: 'isolation-test' },
  }),
})
const attackerAgentId = attackerCreated.body?.data?.enrollment?.agentId
const attackerAgentToken = attackerCreated.body?.data?.enrollment?.agentToken
check('attacker agent created', attackerCreated.status === 200)

/* ---------------- 4. Cross-tenant reads ---------------- */
console.log('\n[4] Cross-tenant reads (attacker -> victim agent)')
for (const path of ['health', 'activity', 'findings', 'scans', 'jobs']) {
  const res = await call(`/api/v1/agent-installer/agents/${victimAgentId}/${path}`, attacker.token)
  check(`attacker cannot GET /${path} of victim agent`, res.status === 404, `got ${res.status} ${JSON.stringify(res.body).slice(0, 90)}`)
}
const victimOwnHealth = await call(`/api/v1/agent-installer/agents/${victimAgentId}/health`, victim.token)
check('victim CAN read their own agent health', victimOwnHealth.status === 200, `got ${victimOwnHealth.status}`)

/* ---------------- 5. Cross-tenant writes ---------------- */
console.log('\n[5] Cross-tenant commands and installer generation')
for (const action of ['scan', 'upgrade', 'enable', 'disable']) {
  const res = await call(`/api/v1/agent-installer/agents/${victimAgentId}/${action}`, attacker.token, { method: 'POST' })
  check(`attacker cannot POST /${action} on victim agent`, res.status === 404, `got ${res.status}`)
}

const stolenPackage = await call('/api/v1/agent-installer/package', attacker.token, {
  method: 'POST',
  body: JSON.stringify({ agentId: victimAgentId, platform: 'linux', token: victimAgentToken }),
})
check('attacker cannot generate an installer for victim agent (even holding the token)', stolenPackage.status === 404, `got ${stolenPackage.status}`)

for (const [method, path, label] of [
  ['POST', `/api/v1/agent-scanner/agents/${victimAgentId}/revoke`, 'revoke'],
  ['POST', `/api/v1/agent-scanner/agents/${victimAgentId}/token/rotate`, 'token/rotate'],
  ['DELETE', `/api/v1/agent-scanner/agents/${victimAgentId}`, 'delete'],
]) {
  const res = await call(path, attacker.token, { method })
  // A 200 here is a lie even when no row changed: an operator who "revokes" a
  // compromised collector must never be told it worked when it did not.
  check(`attacker ${label} on victim agent denied`, res.status === 404 || res.status === 403, `got ${res.status}`)
}

// The victim's agent must still be intact and usable after all of the above.
const stillThere = await call(`/api/v1/agent-installer/agents/${victimAgentId}/health`, victim.token)
check('victim agent survived the attack attempts', stillThere.status === 200 && !stillThere.body?.data?.revoked)

// Same discipline for ids that simply do not exist.
const ghost = '00000000-0000-4000-8000-000000000000'
const ghostRevoke = await call(`/api/v1/agent-scanner/agents/${ghost}/revoke`, victim.token, { method: 'POST' })
check('revoking a non-existent agent 404s instead of reporting success', ghostRevoke.status === 404, `got ${ghostRevoke.status}`)
const ghostDelete = await call(`/api/v1/agent-scanner/agents/${ghost}`, victim.token, { method: 'DELETE' })
check('deleting a non-existent agent 404s instead of reporting success', ghostDelete.status === 404, `got ${ghostDelete.status}`)

/* ---------------- 5b. Rotation must not destroy agent state ---------------- */
console.log('\n[5b] Token rotation preserves agent state')
await call(`/api/v1/agent-installer/agents/${victimAgentId}/scan`, victim.token, { method: 'POST' })
const beforeRotate = await admin.from('scanner_agents').select('metadata').eq('id', victimAgentId).maybeSingle()
const rotated = await call(`/api/v1/agent-scanner/agents/${victimAgentId}/token/rotate`, victim.token, { method: 'POST' })
check('victim can rotate their own token', rotated.status === 200, `got ${rotated.status}`)
const afterRotate = await admin.from('scanner_agents').select('metadata').eq('id', victimAgentId).maybeSingle()
check('rotation preserves the agent role', afterRotate.data?.metadata?.role === beforeRotate.data?.metadata?.role,
  `${beforeRotate.data?.metadata?.role} -> ${afterRotate.data?.metadata?.role}`)
check('rotation preserves the environment', afterRotate.data?.metadata?.environment === beforeRotate.data?.metadata?.environment)
check('rotation preserves the queued command', (afterRotate.data?.metadata?.commandQueue || []).length === (beforeRotate.data?.metadata?.commandQueue || []).length,
  `${(beforeRotate.data?.metadata?.commandQueue || []).length} -> ${(afterRotate.data?.metadata?.commandQueue || []).length}`)
check('rotation records when it happened', Boolean(afterRotate.data?.metadata?.rotatedAt))

const rotatedToken = rotated.body?.data?.agentToken
const oldTokenNowDead = await fetch(`${BASE}/api/v1/agent-installer/runtime`, {
  headers: { 'x-qguard-agent-id': victimAgentId, 'x-qguard-agent-token': victimAgentToken },
})
check('the pre-rotation token no longer authenticates', oldTokenNowDead.status === 401, `got ${oldTokenNowDead.status}`)
const newTokenWorks = await fetch(`${BASE}/api/v1/agent-installer/self`, {
  headers: { 'x-qguard-agent-id': victimAgentId, 'x-qguard-agent-token': rotatedToken },
})
check('the rotated token authenticates', newTokenWorks.status === 200, `got ${newTokenWorks.status}`)

/** Everything after rotation must use the current credential. */
const liveVictimToken = rotatedToken

/* ---------------- 6. Agent-credential isolation ---------------- */
console.log('\n[6] Agent credential isolation')
const mixedCred = await fetch(`${BASE}/api/v1/agent-installer/runtime`, {
  headers: { 'x-qguard-agent-id': victimAgentId, 'x-qguard-agent-token': attackerAgentToken },
})
check('victim agent id + attacker agent token rejected', mixedCred.status === 401, `got ${mixedCred.status}`)

const attackerAgentSelf = await fetch(`${BASE}/api/v1/agent-installer/self`, {
  headers: { 'x-qguard-agent-id': attackerAgentId, 'x-qguard-agent-token': attackerAgentToken },
}).then((r) => r.json())
check('agent /self returns only its own identity', attackerAgentSelf?.data?.agentId === attackerAgentId)

// An agent credential must not be usable as a user session.
const agentAsUser = await call('/api/v1/agent-installer/summary', victimAgentToken)
check('agent token cannot be used as a user session', agentAsUser.status === 401, `got ${agentAsUser.status}`)

/* ---------------- 7. Listing isolation ---------------- */
console.log('\n[7] Listing isolation')
const attackerSummary = await call('/api/v1/agent-installer/summary', attacker.token)
const attackerAgents = attackerSummary.body?.data?.agents || []
check('attacker summary excludes victim agent', !attackerAgents.some((a) => a.id === victimAgentId))
check('attacker summary includes only their own agents', attackerAgents.every((a) => a.user_id === attacker.userId || a.user_id === undefined))

const victimSummary = await call('/api/v1/agent-installer/summary', victim.token)
const victimAgents = victimSummary.body?.data?.agents || []
check('victim summary excludes attacker agent', !victimAgents.some((a) => a.id === attackerAgentId))
check('summary never exposes a token hash', !JSON.stringify(victimSummary.body).includes('token_hash'))

const scannerList = await call('/api/v1/agent-scanner/agents', attacker.token)
check('agent-scanner list excludes victim agent', !(scannerList.body?.data?.agents || []).some((a) => a.id === victimAgentId))

/* ---------------- 8. Evidence isolation ---------------- */
console.log('\n[8] Evidence isolation')
// Victim's agent uploads evidence; it must never surface for the attacker.
const upload = await fetch(`${BASE}/api/v1/agent-scanner/agent/evidence`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'x-qguard-agent-id': victimAgentId, 'x-qguard-agent-token': liveVictimToken },
  body: JSON.stringify({
    evidence: [{
      evidenceType: 'tls-certificate',
      assetName: 'example.com',
      assetType: 'tls_endpoint',
      target: 'example.com:443',
      host: 'example.com',
      port: 443,
      protocol: 'TLS',
      observedAlgorithm: 'RSA-2048',
      keySize: 2048,
      certificateFingerprint: 'AA:BB:CC:ISOLATION:TEST',
      confidence: 'high',
      rawEvidence: { subject: 'CN=example.com', issuer: 'CN=Isolation Test CA', serialNumber: 'ISO-TEST-1', validFrom: 'Jan 1 00:00:00 2026 GMT', validTo: 'Jan 1 00:00:00 2027 GMT' },
      observedAt: new Date().toISOString(),
    }],
  }),
})
check('victim agent evidence accepted', upload.status === 200, `got ${upload.status}`)

const attackerSeesVictimFindings = await call(`/api/v1/agent-installer/agents/${victimAgentId}/findings`, attacker.token)
check('attacker cannot read victim findings', attackerSeesVictimFindings.status === 404, `got ${attackerSeesVictimFindings.status}`)

const { data: victimEvidence } = await admin.from('scanner_evidence').select('user_id').eq('agent_id', victimAgentId)
check('stored evidence is owned by the victim tenant only',
  (victimEvidence || []).length > 0 && (victimEvidence || []).every((row) => row.user_id === victim.userId),
  `${(victimEvidence || []).length} rows`)

const { data: crossCerts } = await admin
  .from('certificates')
  .select('user_id, serial_number')
  .eq('serial_number', 'ISO-TEST-1')
check('materialised certificate belongs to the victim tenant only',
  (crossCerts || []).every((row) => row.user_id === victim.userId), JSON.stringify(crossCerts || []).slice(0, 120))

const { data: crossAssets } = await admin.from('assets').select('user_id').eq('name', 'example.com')
const attackerOwnsAsset = (crossAssets || []).some((row) => row.user_id === attacker.userId)
check('victim asset was not written into the attacker tenant', !attackerOwnsAsset)

/* ---------------- 8b. Asset binding isolation ---------------- */
console.log('\n[8b] Asset binding is tenant-verified')

// Give each tenant an asset, then try to bind across the boundary.
const { data: victimAsset } = await admin
  .from('assets')
  .insert({ user_id: victim.userId, name: 'isolation-victim-asset.local', type: 'server', environment: 'lab', status: 'active' })
  .select('id')
  .single()
const { data: attackerAsset } = await admin
  .from('assets')
  .insert({ user_id: attacker.userId, name: 'isolation-attacker-asset.local', type: 'server', environment: 'lab', status: 'active' })
  .select('id')
  .single()

const attackerAssets = await call('/api/v1/agent-installer/assets', attacker.token)
check('asset picker returns 200 for an entitled tenant', attackerAssets.status === 200, `got ${attackerAssets.status}`)
const listedIds = (attackerAssets.body?.data?.assets || []).map((a) => a.id)
check('asset picker excludes the other tenant\'s assets', !listedIds.includes(victimAsset.id))
check('asset picker includes the caller\'s own asset', listedIds.includes(attackerAsset.id))
check('asset picker reports the caller\'s own tenant id', attackerAssets.body?.data?.tenantId === attacker.userId)

const crossBind = await call('/api/v1/agent-scanner/agents/enroll', attacker.token, {
  method: 'POST',
  body: JSON.stringify({
    name: 'Cross-Bind Attempt',
    environment: 'lab',
    policy: { enabled: true, intervalSeconds: 60, allowedTargets: [], allowedPaths: [], scanTypes: ['tls'], alertThreshold: 'moderate' },
    // The victim's asset id, plus a name the attacker made up.
    metadata: { role: 'collector', assetId: victimAsset.id, assetName: 'whatever-i-say', source: 'isolation-test' },
  }),
})
check('agent cannot be bound to another tenant\'s asset', crossBind.status === 404, `got ${crossBind.status} ${JSON.stringify(crossBind.body).slice(0, 90)}`)

const ownBind = await call('/api/v1/agent-scanner/agents/enroll', attacker.token, {
  method: 'POST',
  body: JSON.stringify({
    name: 'Own-Bind Agent',
    environment: 'lab',
    policy: { enabled: true, intervalSeconds: 60, allowedTargets: [], allowedPaths: [], scanTypes: ['tls'], alertThreshold: 'moderate' },
    // A deliberately wrong display name — the server must overwrite it from the row.
    metadata: { role: 'collector', assetId: attackerAsset.id, assetName: 'client-supplied-lie', source: 'isolation-test' },
  }),
})
check('agent CAN be bound to the caller\'s own asset', ownBind.status === 200, `got ${ownBind.status}`)
const boundAgentId = ownBind.body?.data?.enrollment?.agentId
const { data: boundRow } = await admin.from('scanner_agents').select('metadata').eq('id', boundAgentId).maybeSingle()
check('bound asset id is stored', boundRow?.metadata?.assetId === attackerAsset.id)
check('asset name is server-resolved, not client-asserted',
  boundRow?.metadata?.assetName === 'isolation-attacker-asset.local', String(boundRow?.metadata?.assetName))

await call(`/api/v1/agent-scanner/agents/${boundAgentId}`, attacker.token, { method: 'DELETE' })
await admin.from('assets').delete().in('id', [victimAsset.id, attackerAsset.id])

/* ---------------- 9. SSE isolation ---------------- */
console.log('\n[9] Realtime stream isolation')
const seen = []
const controller = new AbortController()
const streamDone = (async () => {
  const response = await fetch(`${BASE}/api/v1/agent-installer/events/stream?token=${encodeURIComponent(attacker.token)}`, { signal: controller.signal })
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      for (const m of buffer.matchAll(/event: ([^\n]+)\ndata: ([^\n]+)/g)) seen.push({ event: m[1], data: m[2] })
      buffer = buffer.slice(-4000)
    }
  } catch { /* aborted */ }
})()

await new Promise((r) => setTimeout(r, 500))
// Generate victim-side activity while the attacker is listening.
await call(`/api/v1/agent-installer/agents/${victimAgentId}/scan`, victim.token, { method: 'POST' })
await fetch(`${BASE}/api/v1/agent-scanner/agent/heartbeat`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'x-qguard-agent-id': victimAgentId, 'x-qguard-agent-token': liveVictimToken },
  body: JSON.stringify({ status: 'active', hostname: 'victim-host', platform: 'linux', version: '1.5.0', telemetry: { phase: 'isolation' } }),
})
await new Promise((r) => setTimeout(r, 1500))
controller.abort()
await streamDone.catch(() => {})

const leaked = seen.filter((e) => e.data.includes(victimAgentId))
check('attacker stream received no victim agent events', leaked.length === 0, `${leaked.length} leaked: ${JSON.stringify(leaked).slice(0, 160)}`)
check('attacker stream never names the victim hostname', !seen.some((e) => e.data.includes('victim-host')))

// And the victim DOES receive their own events (proves the test wasn't vacuous).
const victimSeen = []
const vc = new AbortController()
const victimStream = (async () => {
  const response = await fetch(`${BASE}/api/v1/agent-installer/events/stream?token=${encodeURIComponent(victim.token)}`, { signal: vc.signal })
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      for (const m of buffer.matchAll(/event: ([^\n]+)\ndata: ([^\n]+)/g)) victimSeen.push({ event: m[1], data: m[2] })
      buffer = buffer.slice(-4000)
    }
  } catch { /* aborted */ }
})()
await new Promise((r) => setTimeout(r, 400))
await fetch(`${BASE}/api/v1/agent-scanner/agent/heartbeat`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'x-qguard-agent-id': victimAgentId, 'x-qguard-agent-token': liveVictimToken },
  body: JSON.stringify({ status: 'active', hostname: 'victim-host', platform: 'linux', version: '1.5.0', telemetry: { phase: 'isolation-2' } }),
})
await new Promise((r) => setTimeout(r, 1200))
vc.abort()
await victimStream.catch(() => {})
check('victim stream DOES receive victim events (test is not vacuous)',
  victimSeen.some((e) => e.data.includes(victimAgentId)), JSON.stringify(victimSeen.map((e) => e.event)))

/* ---------------- cleanup ---------------- */
await admin.from('certificates').delete().eq('serial_number', 'ISO-TEST-1')
await admin.from('scanner_evidence').delete().eq('agent_id', victimAgentId)
await admin.from('agent_heartbeats').delete().eq('agent_id', victimAgentId)
await admin.from('agent_heartbeats').delete().eq('agent_id', attackerAgentId)
await call(`/api/v1/agent-scanner/agents/${victimAgentId}`, victim.token, { method: 'DELETE' })
await call(`/api/v1/agent-scanner/agents/${attackerAgentId}`, attacker.token, { method: 'DELETE' })

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
if (failures.length) {
  console.log('\nFailures:')
  for (const f of failures) console.log(`  - ${f}`)
}
process.exit(fail === 0 ? 0 : 1)
