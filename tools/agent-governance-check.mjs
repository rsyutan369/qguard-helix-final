/**
 * Migration governance gate — does an un-approved plan reach the agent fleet?
 *
 * `start_execution` is what queues migration_jobs, and a queued job is claimed
 * by an agent that will modify a real host's cryptographic configuration. The
 * approval workflow (POST /migration-planner/plans/:id/approval, which writes
 * `approved` / `rejected`) already existed, but nothing read it at dispatch —
 * so a plan the tenant had explicitly REJECTED, or one still sitting at
 * `pending_approval`, could be pushed to the fleet.
 *
 * The last assertion matters as much as the first: the gate must refuse the two
 * governance states and nothing else, or it becomes a blanket block that stops
 * legitimate migrations.
 *
 * Needs the dev server running. Creates and deletes its own plan + job rows.
 *
 * Run: npm run agent:check:governance
 *      QGUARD_TEST_BASE=http://localhost:3002 npm run agent:check:governance
 */

import { createClient } from '@supabase/supabase-js'
import fs from 'node:fs'
const env = Object.fromEntries(fs.readFileSync(new URL('../.env', import.meta.url), 'utf8').split(/\r?\n/).filter(l => l.includes('=') && !l.startsWith('#')).map(l => { const i = l.indexOf('='); return [l.slice(0, i).trim(), l.slice(i + 1).trim().replace(/^["']|["']$/g, '')] }))
const BASE = process.env.QGUARD_TEST_BASE || 'http://localhost:3002'
const admin = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
const anon = createClient(env.VITE_SUPABASE_URL, env.VITE_SUPABASE_ANON_KEY, { auth: { persistSession: false } })
const link = await admin.auth.admin.generateLink({ type: 'magiclink', email: 'zachmatthew369@gmail.com' })
const v = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: link.data.properties.hashed_token })
const token = v.data.session.access_token
const userId = v.data.user.id

let pass = 0, fail = 0
const check = (n, ok, d = '') => { if (ok) { pass++; console.log('  PASS  ' + n) } else { fail++; console.log('  FAIL  ' + n + (d ? ' — ' + d : '')) } }

const uuid = () => globalThis.crypto.randomUUID()
const made = []

async function makePlan(status) {
  const id = uuid()
  const now = new Date().toISOString()
  const { error } = await admin.from('migration_plans').insert({ id, user_id: userId, status, selected_asset_ids: [], configuration: {}, risk_data: {}, metadata: { name: `approval-gate-probe ${status}` }, created_at: now, updated_at: now })
  if (error) throw new Error('plan insert: ' + error.message)
  const jobId = uuid()
  const { error: jobErr } = await admin.from('migration_jobs').insert({ id: jobId, user_id: userId, name: `approval-gate-probe ${status}`, job_type: 'pqc_migration', status: 'queued', progress: 0, target_algorithm: 'ML-KEM-768 hybrid', metadata: { planId: id, source: 'approval-gate-probe' }, created_at: now, updated_at: now })
  if (jobErr) throw new Error('job insert: ' + jobErr.message)
  made.push({ id, jobId })
  return { id, jobId }
}

const call = async (path, body) => {
  const r = await fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body) })
  return { status: r.status, body: await r.json().catch(() => ({})) }
}

console.log('\n[approval gate] dispatch is refused for un-approved plans\n')
for (const status of ['rejected', 'pending_approval']) {
  const plan = await makePlan(status)
  const res = await call(`/api/v1/migration/plans/${plan.id}/action`, { action: 'start_execution' })
  check(`"${status}" plan refuses start_execution`, res.status === 409, `got ${res.status} ${JSON.stringify(res.body).slice(0, 120)}`)
  check(`the refusal names the reason`, res.body?.error?.code === 'PLAN_NOT_APPROVED', JSON.stringify(res.body?.error ?? {}).slice(0, 120))
  const { data: job } = await admin.from('migration_jobs').select('status').eq('id', plan.jobId).single()
  check(`the job was NOT queued for the fleet`, job?.status === 'queued', `job status ${job?.status}`)
}

const approved = await makePlan('approved')
const ok = await call(`/api/v1/migration/plans/${approved.id}/action`, { action: 'start_execution' })
check('an APPROVED plan still dispatches (gate is not a blanket block)', ok.status === 200 || ok.status === 201, `got ${ok.status} ${JSON.stringify(ok.body).slice(0, 160)}`)

for (const m of made) {
  await admin.from('migration_jobs').delete().eq('id', m.jobId)
  await admin.from('migration_plans').delete().eq('id', m.id)
}
console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail ? 1 : 0)
