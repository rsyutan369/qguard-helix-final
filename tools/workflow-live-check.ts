/**
 * Live verification for the Post-Quantum Migration Workflow™ engine + the
 * Migration Planner approval workflow. Requires a running server and a Basic+
 * account:  REPORT_CHECK_EMAIL=<basic-account> npx tsx tools/workflow-live-check.ts
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const url = process.env.VITE_SUPABASE_URL || ''
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const anonKey = process.env.VITE_SUPABASE_ANON_KEY || ''
const ORIGIN = process.env.WORKFLOW_CHECK_ORIGIN || 'http://localhost:3000'

let failures = 0
const pass = (cond: boolean, msg: string) => {
  console.log(`${cond ? '✓' : '✗ FAIL'} ${msg}`)
  if (!cond) failures += 1
}

async function main() {
  const unauth = await fetch(`${ORIGIN}/api/v1/migration-workflow`)
  pass(unauth.status === 401, `workflow unauthenticated rejected (${unauth.status})`)

  const admin = createClient(url, serviceKey, { auth: { persistSession: false } })
  const { data: link } = await admin.auth.admin.generateLink({ type: 'magiclink', email: process.env.REPORT_CHECK_EMAIL || 'threathunter369@gmail.com' })
  const anon = createClient(url, anonKey, { auth: { persistSession: false } })
  const { data } = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: (link!.properties as { hashed_token?: string }).hashed_token! })
  const tok = data.session!.access_token
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${tok}` }

  // Workflow state
  const started = Date.now()
  const res = await fetch(`${ORIGIN}/api/v1/migration-workflow`, { headers })
  pass(res.status === 200, `workflow state OK (${res.status}, ${Date.now() - started}ms)`)
  const wf = (await res.json()).data
  pass(Array.isArray(wf.stages) && wf.stages.length === 11, `11 lifecycle stages (${wf.stages?.length})`)
  const ids = wf.stages.map((s: { id: string }) => s.id).join(',')
  pass(ids === 'discovery,cbom,assessment,risk,remediation,planning,approval,execution,validation,monitoring,certification', `stage order canonical (${ids})`)
  pass(wf.stages.every((s: { progressPct: number }) => s.progressPct >= 0 && s.progressPct <= 100), 'stage progress bounded')
  pass(typeof wf.overallProgressPct === 'number' && Boolean(wf.currentStageId) && Boolean(wf.nextAction?.route), `overall ${wf.overallProgressPct}% · current=${wf.currentStageId} · next="${wf.nextAction?.title}"`)
  pass(Array.isArray(wf.assetStates), `per-asset lifecycle states (${wf.assetStates?.length})`)
  // Cached second call must be fast.
  const t2 = Date.now()
  const res2 = await fetch(`${ORIGIN}/api/v1/migration-workflow`, { headers })
  const elapsed2 = Date.now() - t2
  pass(res2.status === 200 && elapsed2 < 1500, `cached second call fast (${elapsed2}ms)`)

  // The writable approval and dispatch round-trip runs in the isolated
  // migration-planner-handoff-check. Keep the live probe free of plan writes.
  const submit = await fetch(`${ORIGIN}/api/v1/migration-planner/plans`, { method: 'POST', headers, body: JSON.stringify({ name: 'Workflow Live-Check Plan' }) })
  pass(submit.status === 400, `empty proposal rejected (${submit.status})`)
  const start = await fetch(`${ORIGIN}/api/v1/migration/planner/create`, { method: 'POST', headers, body: JSON.stringify({ action: 'start' }) })
  pass(start.status === 409, `start without an approved proposal rejected (${start.status})`)
  const list = await fetch(`${ORIGIN}/api/v1/migration-planner/plans?proposals=1`, { headers })
  pass(list.status === 200 && Array.isArray((await list.json()).data), 'proposal history loads')

  console.log(`\n${failures === 0 ? 'LIVE WORKFLOW CHECKS PASSED ✓' : `${failures} CHECK(S) FAILED ✗`}`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('live check crashed:', err)
  process.exit(1)
})
