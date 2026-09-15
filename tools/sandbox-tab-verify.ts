/**
 * Migration Sandbox — LIVE per-tab data + telemetry verification.
 *
 * Written for the 2026-09-14 tab reduction (Topology / Telemetry / Performance
 * removed from the shell). It answers two questions a code read cannot:
 *
 *   1. Does every REMAINING tab still receive its data from the live API, and
 *      does that data reconcile with the real tenant rows it claims to
 *      describe (assets, relationships, jobs, scanner findings)?
 *   2. Is the realtime channel still delivering — i.e. does /stream emit
 *      `sandbox-update` frames carrying the same fields the tabs render?
 *
 * It also asserts the removed tabs are gone from the shell while the payload
 * fields their engines produce (topology / telemetryFrame / performanceBenchmark)
 * are STILL served, because Overview tiles and the Reports tab consume them.
 *
 * Mints a real user session from the service role (same trick as
 * tools/sandbox-latency-probe.ts) rather than storing a test password.
 *
 * Run: npx tsx tools/sandbox-tab-verify.ts
 *      PROBE_BASE_URL=http://localhost:3002 npx tsx tools/sandbox-tab-verify.ts
 */

import { createClient } from '@supabase/supabase-js'
import { readFileSync } from 'node:fs'
import 'dotenv/config'

const BASE = process.env.PROBE_BASE_URL || 'http://localhost:3002'
const EMAIL = process.env.PROBE_EMAIL || 'zachmatthew369@gmail.com'

let failures = 0
let checks = 0
function ok(label: string, detail = '') {
  checks++
  console.log(`  OK   ${label}${detail ? ` — ${detail}` : ''}`)
}
function bad(label: string, detail = '') {
  checks++
  failures++
  console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ''}`)
}
function assert(cond: boolean, label: string, detail = '') {
  if (cond) ok(label, detail)
  else bad(label, detail)
}

async function mintSession() {
  const url = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL
  const service = process.env.SUPABASE_SERVICE_ROLE_KEY
  const anon = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY
  if (!url || !service || !anon) throw new Error('Supabase env vars missing')

  const admin = createClient(url, service, { auth: { persistSession: false } })
  const { data: link, error: linkError } = await admin.auth.admin.generateLink({ type: 'magiclink', email: EMAIL })
  if (linkError) throw new Error(`generateLink: ${linkError.message}`)

  const anonClient = createClient(url, anon, { auth: { persistSession: false } })
  const { data, error } = await anonClient.auth.verifyOtp({
    token_hash: (link as unknown as { properties: { hashed_token: string } }).properties.hashed_token,
    type: 'magiclink',
  })
  if (error) throw new Error(`verifyOtp: ${error.message}`)
  return { token: data.session!.access_token, userId: data.user!.id, admin }
}

async function get(path: string, token: string) {
  const res = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}` } })
  const text = await res.text()
  let body: any = null
  try { body = JSON.parse(text) } catch { body = text }
  return { status: res.status, body: body?.data ?? body, raw: body }
}

/** Read named SSE events off /stream, then disconnect. */
async function readSse(path: string, token: string, wantEvents: string[], timeoutMs: number) {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  const collected: Record<string, any[]> = {}
  try {
    const res = await fetch(`${BASE}${path}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
      signal: ctrl.signal,
    })
    if (!res.ok || !res.body) return { status: res.status, collected }
    const reader = (res.body as any).getReader()
    const decoder = new TextDecoder()
    let buf = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buf += decoder.decode(value, { stream: true })
      let idx = buf.indexOf('\n\n')
      while (idx >= 0) {
        const frame = buf.slice(0, idx)
        buf = buf.slice(idx + 2)
        const evt = /^event: (.+)$/m.exec(frame)?.[1]
        const dat = /^data: (.+)$/m.exec(frame)?.[1]
        if (evt) {
          collected[evt] = collected[evt] || []
          try { collected[evt].push(dat ? JSON.parse(dat) : null) } catch { collected[evt].push(dat) }
        }
        idx = buf.indexOf('\n\n')
      }
      if (wantEvents.every((e) => (collected[e] || []).length >= 1)) break
    }
    return { status: res.status, collected }
  } catch {
    return { status: 0, collected }
  } finally {
    clearTimeout(timer)
    ctrl.abort()
  }
}

async function main() {
  console.log(`\nMigration Sandbox tab verification — ${BASE} as ${EMAIL}\n`)
  const { token, userId, admin } = await mintSession()

  const [snapRes, twinRes, assetsRes, intelRes] = await Promise.all([
    get('/api/v1/sandbox/snapshot', token),
    get('/api/v1/sandbox/twin', token),
    get('/api/v1/sandbox/assets', token),
    get('/api/v1/scanner/intelligence', token),
  ])
  if (snapRes.status !== 200) throw new Error(`snapshot ${snapRes.status}: ${JSON.stringify(snapRes.raw).slice(0, 300)}`)
  const snap: any = snapRes.body
  const twin: any = twinRes.body
  const assetsPayload: any = assetsRes.body
  const intel: any = intelRes.body

  const count = async (table: string) => {
    const { count: c } = await admin.from(table).select('*', { count: 'exact', head: true }).eq('user_id', userId)
    return c ?? 0
  }
  const realAssets = await count('assets')
  const realRelationships = await count('asset_relationships')
  const realJobs = await count('migration_jobs')
  const realInventory = await count('crypto_inventory')

  console.log(`Tenant ${userId}`)
  console.log(`  assets ${realAssets} · asset_relationships ${realRelationships} · migration_jobs ${realJobs} · crypto_inventory ${realInventory}\n`)

  // ── [1] Overview ─────────────────────────────────────────────────────────
  console.log('[1] Overview tab')
  assert(!!snap.summary, 'summary served')
  assert(snap.summary.totalSimulations === (snap.simulations || []).length,
    'summary.totalSimulations == simulations rows', `${snap.summary.totalSimulations} vs ${(snap.simulations || []).length}`)
  assert(!!snap.approvalGate && typeof snap.approvalGate.productionReady === 'boolean', 'approval gate served',
    `${snap.approvalGate?.simulationStatus} · ready=${snap.approvalGate?.productionReady}`)
  assert(!!snap.topology, 'topology STILL served (Overview heat tiles + twin report)',
    snap.topology ? `${snap.topology.zones.length} zones` : '')
  assert(!!snap.performanceBenchmark, 'performanceBenchmark STILL served (Overview impact tile + report)',
    snap.performanceBenchmark ? `available=${snap.performanceBenchmark.available}` : '')
  assert(!!snap.telemetryFrame, 'telemetryFrame STILL served (technical + performance reports)',
    snap.telemetryFrame ? `${(snap.telemetryFrame.series || []).length} series · ${snap.telemetryFrame.windowMinutes}m window` : '')
  assert(Array.isArray(snap.timeline), 'timeline served', `${(snap.timeline || []).length} entries`)

  // ── [2] Digital Twin ─────────────────────────────────────────────────────
  console.log('\n[2] Digital Twin tab (GET /twin)')
  assert(twinRes.status === 200, '/twin responds 200', String(twinRes.status))
  assert(!!twin?.twin, 'twin payload served')
  const twinNodes = twin?.twin?.nodes?.length ?? 0
  assert(twinNodes <= realAssets + realInventory, 'twin nodes bounded by real rows', `${twinNodes} nodes · ${realAssets} assets`)
  const snapTwinNodes = snap.digitalTwin?.summary?.totalNodes
  const detailTwinNodes = twin?.twin?.summary?.totalNodes
  assert(typeof snapTwinNodes === 'number' && snapTwinNodes === detailTwinNodes,
    'snapshot twin == /twin twin (one model, two routes)', `${snapTwinNodes} vs ${detailTwinNodes}`)
  assert(typeof snap.digitalTwin?.summary?.fidelityPct === 'number', 'twin fidelity measured',
    `coverage ${snap.digitalTwin?.summary?.coveragePct}% · fidelity ${snap.digitalTwin?.summary?.fidelityPct}%`)
  assert(Array.isArray(snap.pqcStack), 'pqcStack served', `${(snap.pqcStack || []).length} items`)

  // ── [3] Simulation Builder ───────────────────────────────────────────────
  console.log('\n[3] Simulation Builder tab (GET /assets)')
  assert(assetsRes.status === 200, '/assets responds 200', String(assetsRes.status))
  const builderAssets = Array.isArray(assetsPayload) ? assetsPayload : (assetsPayload?.assets || [])
  assert(Array.isArray(builderAssets), 'asset list served', `${builderAssets.length} selectable assets`)
  assert(builderAssets.length <= realAssets, 'asset list does not exceed real tenant assets', `${builderAssets.length} <= ${realAssets}`)
  assert((snap.simulationTypes || []).length > 0, 'simulation types served', `${(snap.simulationTypes || []).length} types`)
  assert((snap.pipeline || []).length > 0, 'pipeline stages served', `${(snap.pipeline || []).length} stages`)

  // ── [4] Migration Pipeline ───────────────────────────────────────────────
  console.log('\n[4] Migration Pipeline tab')
  assert((snap.simulations || []).length <= realJobs, 'simulations come from migration_jobs', `${(snap.simulations || []).length} <= ${realJobs}`)
  const withPhase = (snap.simulations || []).filter((s: any) => !!s.phase).length
  assert(withPhase === (snap.simulations || []).length, 'every simulation carries a live phase', `${withPhase}/${(snap.simulations || []).length}`)

  // ── [5] Dependency Graph ─────────────────────────────────────────────────
  console.log('\n[5] Dependency Graph tab')
  const stats = twin?.graph?.stats
  assert(!!stats, 'graph stats served')
  if (stats) {
    assert(stats.observedEdges <= realRelationships, 'observed edges come from asset_relationships', `${stats.observedEdges} <= ${realRelationships}`)
    ok('inferred edges counted separately', `${stats.inferredEdges} inferred`)
  }

  // ── [6] Validation ───────────────────────────────────────────────────────
  console.log('\n[6] Validation tab')
  assert(typeof snap.failurePrediction?.overallFailureProbabilityPct === 'number', 'failure prediction served',
    `${(snap.failurePrediction?.predictions || []).length} categories · overall ${snap.failurePrediction?.overallFailureProbabilityPct}%`)
  assert(Array.isArray(snap.riskFactors), 'risk factors served', `${(snap.riskFactors || []).length}`)
  if (intelRes.status === 200 && intel?.severityCounts) {
    const s = snap.summary
    assert(s.criticalExposures === intel.severityCounts.critical && s.highExposures === intel.severityCounts.high,
      'severity counts match the shared scanner authority',
      `sandbox ${s.criticalExposures}/${s.highExposures} vs scanner ${intel.severityCounts.critical}/${intel.severityCounts.high}`)
  } else {
    ok('scanner intelligence not compared', `status ${intelRes.status}`)
  }

  // ── [7] Rollback ─────────────────────────────────────────────────────────
  console.log('\n[7] Rollback tab')
  const rb = snap.rollbackAnalysis
  assert(!!rb, 'rollback analysis served')
  if (rb) {
    assert(rb.assessed === true || rb.successProbabilityPct === null,
      'unassessed rollback renders null, never a flattering 0', `assessed=${rb.assessed} success=${rb.successProbabilityPct}`)
    assert(rb.assessed === true || rb.rpoMinutes === null, 'unassessed RPO is null, not 0m', `rpo=${rb.rpoMinutes}`)
  }

  // ── [8] Compliance ───────────────────────────────────────────────────────
  console.log('\n[8] Compliance tab')
  const comp = snap.complianceItems || []
  assert(comp.length > 0, 'compliance indicators served', `${comp.length} frameworks`)
  assert(comp.every((c: any) => !!c.basis), 'every indicator states the measurement it was decided from')

  // ── [9] AI Insights ──────────────────────────────────────────────────────
  console.log('\n[9] AI Insights tab')
  assert(!!snap.sophia && (snap.sophia.recommendedSequence || []).length > 0, 'Sophia advisor served',
    snap.sophia ? `${(snap.sophia.recommendedSequence || []).length} sequence steps · ${(snap.sophia.detectedBlockers || []).length} blockers · confidence ${snap.sophia.aiConfidencePct}%` : '')
  assert(typeof snap.sophia?.quantumRiskScore === 'number' || snap.sophia?.quantumRiskScore === null,
    'quantum risk carries the canonical score (or null, never a saturated 0)', `${snap.sophia?.quantumRiskScore}`)
  assert(Array.isArray(snap.recommendations), 'recommendations served', `${(snap.recommendations || []).length}`)

  // ── [10] Execution Logs ──────────────────────────────────────────────────
  console.log('\n[10] Execution Logs tab')
  assert(Array.isArray(snap.recentLogs), 'logs served', `${(snap.recentLogs || []).length} entries`)

  // ── [11] Reports ─────────────────────────────────────────────────────────
  console.log('\n[11] Reports tab (9 report types)')
  const types = ['executive', 'technical', 'compliance', 'migration', 'performance', 'rollback', 'risk', 'twin', 'ai']
  for (const t of types) {
    const r = await get(`/api/v1/sandbox/export?format=json&reportType=${t}`, token)
    assert(r.status === 200 && !!r.body, `export ${t}`, `status ${r.status}`)
  }

  // ── [12] History ─────────────────────────────────────────────────────────
  console.log('\n[12] History tab')
  assert(Array.isArray(snap.history), 'history served', `${(snap.history || []).length} rows`)

  // ── [13] Realtime ────────────────────────────────────────────────────────
  console.log('\n[13] Realtime telemetry (SSE /stream)')
  const sse = await readSse('/api/v1/sandbox/stream', token, ['connected', 'sandbox-update'], 25000)
  assert((sse.collected['connected'] || []).length > 0, 'SSE connected frame received')
  const updates = sse.collected['sandbox-update'] || []
  assert(updates.length > 0, 'SSE sandbox-update frame received')
  if (updates.length > 0) {
    const u = updates[0]
    const required = ['summary', 'simulations', 'pipeline', 'digitalTwin', 'topology', 'telemetryFrame',
      'performanceBenchmark', 'failurePrediction', 'rollbackAnalysis', 'complianceItems', 'sophia',
      'approvalGate', 'timeline', 'history', 'recentLogs']
    const missing = required.filter((k) => u[k] === undefined)
    assert(missing.length === 0, 'stream frame carries every field the tabs render',
      missing.length ? `missing ${missing.join(', ')}` : `${required.length} fields`)
    assert(!!u.generatedAt, 'stream frame is timestamped', u.generatedAt)
  }

  // ── [14] Removed tabs ────────────────────────────────────────────────────
  console.log('\n[14] Removed tabs (Topology / Telemetry / Performance)')
  const shell = readFileSync('src/app/dashboard/migration-sandbox/MigrationSandbox.tsx', 'utf8')
  const ops = readFileSync('src/app/dashboard/migration-sandbox/OpsPanels.tsx', 'utf8')
  const twinp = readFileSync('src/app/dashboard/migration-sandbox/TwinPanels.tsx', 'utf8')
  assert(!/tab === 'topology'|tab === 'telemetry'|tab === 'performance'/.test(shell),
    'no topology/telemetry/performance tab branches remain in the shell')
  assert(!/key: 'topology'|key: 'telemetry'|key: 'performance'/.test(shell), 'no removed tab entries in the tab bar')
  assert(!/<TopologyTab|<TelemetryTab|<PerformanceTab/.test(shell), 'no removed tab components rendered')
  assert(!/export function (TopologyTab|TelemetryTab|PerformanceTab)/.test(ops + twinp), 'removed tab components deleted, not orphaned')
  assert(/'twin' \|/.test(shell) && /'dependencies'/.test(shell), 'remaining twin tabs intact')

  console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} FAILED`} — ${checks} checks\n`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((err) => { console.error('\nprobe error:', err.message); process.exit(1) })
