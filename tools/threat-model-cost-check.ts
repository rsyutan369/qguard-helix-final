/**
 * Live check for the Quantum Threat Model (Shor/Grover decomposition on
 * /api/v1/dashboard/quantum-risk-scoring) and Trust Path Cost
 * (/api/v1/dashboard/tls-telemetry). Run with the dev server up:
 *   npx tsx tools/threat-model-cost-check.ts
 *
 * Requires an explicitly configured QA account with an active Elite subscription.
 * No test subscriptions are created or modified by this check.
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const url = process.env.VITE_SUPABASE_URL || ''
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const anonKey = process.env.VITE_SUPABASE_ANON_KEY || ''
const ORIGIN = 'http://localhost:3000'

const pass = (cond: boolean, msg: string) => {
  console.log(`${cond ? '✓' : '✗'} ${msg}`)
  if (!cond) process.exitCode = 1
}

async function main() {
  const admin = createClient(url, serviceKey, { auth: { persistSession: false } })
  const { data: link, error: linkError } = await admin.auth.admin.generateLink({ type: 'magiclink', email: process.env.PROBE_ELITE_EMAIL || (() => { throw new Error('Set PROBE_ELITE_EMAIL to an authorized QA account') })() })
  if (linkError) throw linkError
  const tokenHash = (link!.properties as { hashed_token?: string }).hashed_token!
  const anon = createClient(url, anonKey, { auth: { persistSession: false } })
  const { data, error: otpError } = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: tokenHash })
  if (otpError) throw otpError
  const tok = data.session!.access_token
  const headers = { Authorization: `Bearer ${tok}` }

  console.log('=== Quantum Risk Scoring: threatModel (Shor/Grover) ===')
  const riskRes = await fetch(`${ORIGIN}/api/v1/dashboard/quantum-risk-scoring`, { headers })
  pass(riskRes.ok, `GET quantum-risk-scoring -> HTTP ${riskRes.status}`)
  const risk = (await riskRes.json()).data || {}
  const tm = risk.threatModel
  pass(!!tm, 'snapshot has threatModel')
  for (const key of ['shorExposed', 'groverWatch', 'hashLegacy', 'pqcProtected'] as const) {
    const row = tm?.[key]
    pass(
      row && typeof row.findings === 'number' && typeof row.affectedAssets === 'number'
        && typeof row.share === 'number' && typeof row.trend === 'number'
        && Array.isArray(row.topAssets) && typeof row.label === 'string' && row.label.length > 0
        && typeof row.urgency === 'string',
      `${key}: findings=${row?.findings} assets=${row?.affectedAssets} share=${row?.share}% urgency=${row?.urgency}`,
    )
  }
  pass(typeof tm?.guidance === 'string' && tm.guidance.length > 20, `guidance: "${String(tm?.guidance).slice(0, 110)}..."`)
  const classified = (tm?.shorExposed?.findings || 0) + (tm?.groverWatch?.findings || 0) + (tm?.hashLegacy?.findings || 0) + (tm?.pqcProtected?.findings || 0)
  pass(classified <= (risk.metrics?.findings ?? 0), `classified findings ${classified} <= total findings ${risk.metrics?.findings}`)

  console.log('\n=== TLS Telemetry: trustPathCost ===')
  const tlsRes = await fetch(`${ORIGIN}/api/v1/dashboard/tls-telemetry`, { headers })
  pass(tlsRes.ok, `GET tls-telemetry -> HTTP ${tlsRes.status}`)
  const tls = (await tlsRes.json()).data || {}
  const cost = tls.trustPathCost
  pass(!!cost, 'snapshot has trustPathCost')
  pass(Array.isArray(cost?.rttProfile), `rttProfile rows=${cost?.rttProfile?.length} [${(cost?.rttProfile || []).map((r: any) => `${r.label}:${r.connections}`).join(' | ')}]`)
  pass(Array.isArray(cost?.kexProfile), `kexProfile rows=${cost?.kexProfile?.length} [${(cost?.kexProfile || []).map((r: any) => `${r.label}:${r.connections}`).join(' | ')}]`)
  pass(Array.isArray(cost?.costliestPaths) && cost.costliestPaths.every((p: any) => p.costIndex >= 0 && p.costIndex <= 100), `costliestPaths=${cost?.costliestPaths?.length} top="${cost?.costliestPaths?.[0]?.path ?? 'none'}" idx=${cost?.costliestPaths?.[0]?.costIndex ?? '-'}`)
  const ho = cost?.hybridOutlook
  pass(ho && ho.addedBytesPerHandshake === 2272 && ho.projectedAddedBytes === Math.max(0, (ho.tls13Eligible - ho.alreadyHybrid)) * 2272, `hybridOutlook: tls13=${ho?.tls13Eligible} hybrid=${ho?.alreadyHybrid} projected=${ho?.projectedAddedBytes}B (arithmetic verified)`)
  pass(typeof cost?.methodology === 'string' && /no latency is fabricated/i.test(cost.methodology), 'methodology caption present (no fabricated latency)')

  // rtt/kex profile connection sums must not exceed total observed connections
  const rttSum = (cost?.rttProfile || []).reduce((s: number, r: any) => s + r.connections, 0)
  pass(rttSum === (tls.metrics?.totalConnections ?? 0), `rttProfile connections ${rttSum} == totalConnections ${tls.metrics?.totalConnections}`)

  console.log('\n=== SPA routes serve ===')
  for (const route of ['/dashboard/quantum-risk-scoring', '/dashboard/tls-telemetry']) {
    const res = await fetch(`${ORIGIN}${route}`)
    pass(res.ok && /text\/html/.test(res.headers.get('content-type') || ''), `GET ${route} -> HTTP ${res.status}`)
  }
}

main().catch((e) => { console.error(e); process.exit(1) })
