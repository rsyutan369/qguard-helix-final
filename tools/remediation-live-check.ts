import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const url = process.env.VITE_SUPABASE_URL || ''
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const anonKey = process.env.VITE_SUPABASE_ANON_KEY || ''
const ORIGIN = process.env.REMEDIATION_CHECK_ORIGIN || 'http://localhost:3000'

let failures = 0
const pass = (cond: boolean, msg: string) => {
  console.log(`${cond ? '✓' : '✗ FAIL'} ${msg}`)
  if (!cond) failures += 1
}

async function main() {
  // Unauthenticated → 401
  const unauth = await fetch(`${ORIGIN}/api/v1/quantum-remediation`)
  pass(unauth.status === 401, `unauthenticated request rejected (${unauth.status})`)

  // Basic-tier account (same one report-check uses)
  const admin = createClient(url, serviceKey, { auth: { persistSession: false } })
  const { data: link } = await admin.auth.admin.generateLink({ type: 'magiclink', email: process.env.REPORT_CHECK_EMAIL || 'cybersniper26@gmail.com' })
  const tokenHash = (link!.properties as { hashed_token?: string }).hashed_token!
  const anon = createClient(url, anonKey, { auth: { persistSession: false } })
  const { data } = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: tokenHash })
  const tok = data.session!.access_token

  const started = Date.now()
  const res = await fetch(`${ORIGIN}/api/v1/quantum-remediation`, { headers: { Authorization: `Bearer ${tok}` } })
  const elapsed = Date.now() - started
  pass(res.status === 200, `authenticated request OK (${res.status}, ${elapsed}ms)`)
  const plan = (await res.json()).data

  pass(typeof plan.certificationReadinessPct === 'number' && plan.certificationReadinessPct >= 0 && plan.certificationReadinessPct <= 100, `certification readiness ${plan.certificationReadinessPct}% in [0,100]`)
  pass(plan.criteria.length === 10, `10 required criteria evaluated (${plan.criteria.length})`)
  pass(plan.requirements.length === 10, `10 requirement gap cards (${plan.requirements.length})`)
  const queueSum = plan.queues.critical + plan.queues.high + plan.queues.medium + plan.queues.low
  pass(queueSum === plan.actions.length, `queues partition actions (${queueSum} == ${plan.actions.length})`)
  const monotone = plan.ladder.every((s: { readinessPct: number }, i: number) => i === 0 || s.readinessPct >= plan.ladder[i - 1].readinessPct)
  pass(plan.ladder.length >= 2 && monotone, `ladder monotone over real tenant: ${plan.ladder.map((s: { readinessPct: number }) => `${s.readinessPct}%`).join(' → ')}`)
  pass(plan.ladder[0]?.readinessPct === plan.certificationReadinessPct, 'ladder starts at live score')
  pass(plan.advisor.length === 9, `advisor answers (${plan.advisor.length})`)
  pass(plan.hasData ? plan.actions.every((a: { rank: number }, i: number) => a.rank === i + 1) : true, 'ranks sequential')
  pass(Boolean(plan.methodology?.name) && plan.methodology.priorityFactors.length === 8, 'methodology ships with payload')
  if (plan.hasData && plan.actions.length) {
    const first = plan.actions[0]
    console.log(`  → #1 recommendation: ${first.asset} — ${first.recommendation} (+${first.certificationGainPct}%, ${first.effortWeeks}wk, ${first.priority})`)
    pass(first.steps.length >= 3 && first.standards.length > 0 && Boolean(first.integration?.route), 'first action carries playbook steps + standards + deep link')
  }
  console.log(`  → eligible=${plan.certificationEligible} requiredMet=${plan.requiredMet}/${plan.requiredTotal} readiness=${plan.quantumReadiness} vulnTotal=${plan.remainingVulnerabilities.total} estCertDate=${plan.estimatedCertificationDate}`)

  // SSE stream (header-auth) — expect a remediation-update frame
  const controller = new AbortController()
  const sse = await fetch(`${ORIGIN}/api/v1/quantum-remediation/stream`, {
    headers: { Authorization: `Bearer ${tok}`, Accept: 'text/event-stream' },
    signal: controller.signal,
  })
  pass(sse.status === 200 && Boolean(sse.body), `SSE stream connected (${sse.status})`)
  if (sse.body) {
    const reader = sse.body.getReader()
    let buffer = ''
    const deadline = Date.now() + 30000
    let gotFrame = false
    while (Date.now() < deadline && !gotFrame) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += new TextDecoder().decode(value)
      if (buffer.includes('event: remediation-update')) gotFrame = true
    }
    pass(gotFrame, 'SSE emitted remediation-update frame')
    controller.abort()
  }

  console.log(`\n${failures === 0 ? 'LIVE CHECKS PASSED ✓' : `${failures} LIVE CHECK(S) FAILED ✗`}`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('live check crashed:', err)
  process.exit(1)
})
