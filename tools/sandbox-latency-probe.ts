/**
 * Migration Sandbox — LIVE latency + state probe.
 *
 * Answers the question a code read cannot: how long does /api/v1/sandbox/snapshot
 * actually take, and does it stay flat while sandbox simulations are running?
 *
 * `buildSandboxPayload` is the one hot path with NO single-flight cache (unlike
 * `buildScannerIntelligence` and the QR `buildSnapshot`, both 15s-cached), and
 * `/stream` rebuilds it every 8s PER CONNECTED CLIENT — each time running
 * `advanceSandboxJobs` writes plus a 14-table load. This probe measures whether
 * that is a problem in practice.
 *
 * Mints a real user session from the service role (the same trick
 * dashboard-summary-check.ts uses) rather than storing a test password. Requires
 * the dev server on :3000.
 *
 * Run: npx tsx tools/sandbox-latency-probe.ts
 */

import { createClient } from '@supabase/supabase-js'
import 'dotenv/config'

const BASE = process.env.PROBE_BASE_URL || 'http://localhost:3000'
const EMAIL = process.env.PROBE_EMAIL || 'zachmatthew369@gmail.com'

function stats(samples: number[]) {
  const sorted = [...samples].sort((a, b) => a - b)
  return {
    n: sorted.length,
    min: sorted[0],
    median: sorted[Math.floor(sorted.length / 2)],
    max: sorted[sorted.length - 1],
    mean: Math.round(sorted.reduce((s, v) => s + v, 0) / sorted.length),
  }
}

async function mintSession() {
  const url = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL
  const service = process.env.SUPABASE_SERVICE_ROLE_KEY
  const anon = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY
  if (!url || !service || !anon) throw new Error('Supabase env vars missing (VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY)')

  const admin = createClient(url, service, { auth: { persistSession: false } })
  const { data: link, error: linkError } = await admin.auth.admin.generateLink({ type: 'magiclink', email: EMAIL })
  if (linkError) throw new Error(`generateLink: ${linkError.message}`)

  const anonClient = createClient(url, anon, { auth: { persistSession: false } })
  const { data, error } = await anonClient.auth.verifyOtp({
    token_hash: (link as unknown as { properties: { hashed_token: string } }).properties.hashed_token,
    type: 'magiclink',
  })
  if (error) throw new Error(`verifyOtp: ${error.message}`)
  return data.session!.access_token
}

async function timed(path: string, token: string) {
  const t0 = Date.now()
  const res = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}` } })
  const body = await res.json().catch(() => ({}))
  return { ms: Date.now() - t0, status: res.status, body: body?.data ?? body }
}

async function main() {
  console.log(`\nProbing ${BASE} as ${EMAIL}\n`)
  const token = await mintSession()

  // ---- State: are simulations running? --------------------------------
  const first = await timed('/api/v1/sandbox/snapshot', token)
  if (first.status !== 200) throw new Error(`snapshot returned ${first.status}`)
  const snap = first.body as any
  const sims = (snap.simulations || []).map((s: any) => ({ status: s.status, progress: s.progress, phase: s.phase }))
  const active = sims.filter((s: any) => ['running', 'queued'].includes(s.status)).length

  console.log('State')
  console.log(`  simulations        ${sims.length} (${active} active)`)
  for (const s of sims) console.log(`    - ${s.status.padEnd(10)} ${String(s.progress).padStart(3)}%  ${s.phase}`)
  console.log(`  completed          ${snap.summary.completed}`)
  console.log(`  engine             ${snap.summary.backgroundEngine}`)
  console.log(`  approval gate      ${snap.approvalGate.simulationStatus} · productionReady=${snap.approvalGate.productionReady} · ${(snap.approvalGate.eligibleSimulations || []).length} eligible simulation(s)`)
  for (const g of snap.approvalGate.gates) console.log(`    - ${String(g.id).padEnd(22)} ${String(g.value).padEnd(24)} ${g.status}`)
  console.log(`  rollback assessed  ${snap.rollbackAnalysis.assessed} · success ${snap.rollbackAnalysis.successProbabilityPct ?? 'null'} · coverage ${snap.rollbackAnalysis.snapshotCoveragePct ?? 'null'} · RPO ${snap.rollbackAnalysis.rpoMinutes ?? 'null'}`)

  // ---- Cross-page reconciliation --------------------------------------
  const [intel, qr] = await Promise.all([
    timed('/api/v1/scanner/intelligence', token),
    timed('/api/v1/quantum-readiness', token),
  ])
  const i = intel.body as any
  const q = qr.body as any
  console.log('\nReconciliation (sandbox vs scanner vs QR Engine)')
  const row = (label: string, a: unknown, b: unknown, c: unknown) => {
    const ok = String(a) === String(b) && String(b) === String(c)
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label.padEnd(20)} sandbox=${String(a).padEnd(6)} scanner=${String(b).padEnd(6)} qr=${c}`)
    return ok
  }
  let mismatches = 0
  if (!row('critical', snap.summary.criticalExposures, i.severityCounts.critical, q.riskDistribution.critical)) mismatches++
  if (!row('high', snap.summary.highExposures, i.severityCounts.high, q.riskDistribution.high)) mismatches++
  if (!row('quantum risk', snap.summary.quantumRiskScore, q.scores.quantumRisk, q.scores.quantumRisk)) mismatches++
  console.log(`  quantum risk source  ${snap.summary.quantumRiskSource}`)
  console.log(`  severity source      ${snap.summary.gradedObservationsSource}`)

  let failures = 0
  const check = (ok: boolean, label: string, detail = '') => {
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}`)
    if (!ok) failures++
  }
  const TTL_MS = 5_000
  const waitForExpiry = () => new Promise((r) => setTimeout(r, TTL_MS + 1_000))

  // ---- Cost of one real build -----------------------------------------
  // Every sample waits the TTL out first, so these are genuine cold builds
  // rather than cache hits. This is the number that scales with estate size.
  console.log('\nLatency — cold builds (TTL expired before each)')
  const cold: number[] = []
  for (let n = 0; n < 3; n++) {
    await waitForExpiry()
    cold.push((await timed('/api/v1/sandbox/snapshot', token)).ms)
  }
  const coldMs = stats(cold)
  console.log(`  ${JSON.stringify(coldMs)}`)

  console.log('\nLatency — warm hits (immediately after a build)')
  const warm: number[] = []
  for (let n = 0; n < 4; n++) warm.push((await timed('/api/v1/sandbox/snapshot', token)).ms)
  console.log(`  ${JSON.stringify(stats(warm))}`)
  check(stats(warm).median <= coldMs.median, 'a warm hit is never slower than a cold build')

  // ---- Single-flight ---------------------------------------------------
  // `generatedAt` is stamped once per computation, so one distinct value across
  // five responses proves a single computation served them all. Fired straight
  // after expiry so every caller would otherwise start its own cold build —
  // exactly the SSE fan-out that took 2.4s of wall clock before this cache.
  // `generatedAt` is a DETERMINISTIC proof of sharing: it is stamped once per
  // computation, so one distinct value across five responses means one build
  // served them all. Wall clock is reported but NOT asserted — the shared build
  // may also have to rebuild the 15s scanner-intelligence and Quantum-Readiness
  // caches (QR alone is ~6s cold), so its duration measures dependency-cache
  // state rather than anything about this cache.
  console.log('\nSingle-flight — 5 CONCURRENT calls, all arriving cold')
  const priorStamp = (await timed('/api/v1/sandbox/snapshot', token)).body as any
  await waitForExpiry()
  const t0 = Date.now()
  const burst = await Promise.all(Array.from({ length: 5 }, () => timed('/api/v1/sandbox/snapshot', token)))
  const burstWall = Date.now() - t0
  const stamps = new Set(burst.map((b) => (b.body as any).generatedAt))
  console.log(`  ${JSON.stringify(stats(burst.map((b) => b.ms)))}  wallClock=${burstWall}ms  distinctGeneratedAt=${stamps.size}`)
  check(stamps.size === 1, '5 concurrent callers share ONE computation', `${stamps.size} distinct generatedAt`)
  check(
    !stamps.has(priorStamp.generatedAt),
    'and it is a FRESH build, not the pre-expiry entry served on',
  )

  // ---- Mutation invalidation (opt-in: PROBE_MUTATE=1) ------------------
  // The one way this cache can break the product: an operator action returning
  // a cached PRE-mutation snapshot, so the action looks like it did nothing.
  // Writes real rows, so it is opt-in and cleans up after itself.
  if (process.env.PROBE_MUTATE === '1') {
    console.log('\nMutation invalidation (PROBE_MUTATE=1 — creates then deletes a simulation)')
    const assetsRes = await timed('/api/v1/sandbox/assets', token)
    const assetIds = ((assetsRes.body as any).assets || []).slice(0, 1).map((a: any) => a.id)

    // Warm the cache so a stale read would be served if invalidation is missing.
    const before = await timed('/api/v1/sandbox/snapshot', token)
    const beforeCount = ((before.body as any).simulations || []).length

    const created = await fetch(`${BASE}/api/v1/sandbox/simulate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ assetIds, simulationType: 'quick_validation', dryRun: true }),
    }).then((r) => r.json())
    const inPost = ((created.data?.snapshot?.simulations) || []).length
    check(inPost === beforeCount + 1, 'the POST response already reflects the new simulation', `${beforeCount} -> ${inPost}`)

    const nextRead = await timed('/api/v1/sandbox/snapshot', token)
    check(
      ((nextRead.body as any).simulations || []).length === beforeCount + 1,
      'the very next read is post-mutation, not a cached pre-mutation payload',
    )

    const act = async (id: string, action: string) => {
      const res = await fetch(`${BASE}/api/v1/sandbox/jobs/${id}/action`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      })
      // Assert the STATUS, never just the body shape: `body.data?.snapshot ?? []`
      // turns a 400 into a silent pass, which is how this probe first reported
      // a successful cleanup while leaving a simulation behind.
      const body = await res.json().catch(() => ({}))
      return { status: res.status, body }
    }

    for (const id of created.data?.jobIds || []) {
      // Only completed/failed/stopped/rolled-back simulations are deletable, so
      // a fresh queued run has to be stopped first.
      const stopped = await act(id, 'stop')
      check(stopped.status === 200, 'a queued simulation can be stopped', `HTTP ${stopped.status}`)

      const del = await act(id, 'delete')
      check(del.status === 200, 'a stopped simulation can be deleted', `HTTP ${del.status}`)
      check(
        ((del.body.data?.snapshot?.simulations) ?? [{ sentinel: true }]).length === beforeCount,
        'the delete response already reflects the removal',
      )
    }
    const after = await timed('/api/v1/sandbox/snapshot', token)
    const remaining = ((after.body as any).simulations || []).length
    check(remaining === beforeCount, 'tenant restored to its pre-probe state', `${remaining} simulation(s) remain`)
  }

  // ---- TTL -------------------------------------------------------------
  console.log('\nTTL behaviour')
  const a = await timed('/api/v1/sandbox/snapshot', token)
  const b = await timed('/api/v1/sandbox/snapshot', token)
  check((a.body as any).generatedAt === (b.body as any).generatedAt, 'a repeat call inside the TTL is served from cache')
  await waitForExpiry()
  const c = await timed('/api/v1/sandbox/snapshot', token)
  check((c.body as any).generatedAt !== (a.body as any).generatedAt, 'the cache expires — data is never staler than the TTL')

  console.log('\nLatency — cached comparators')
  console.log(`  scanner/intelligence ${intel.ms}ms`)
  console.log(`  quantum-readiness    ${qr.ms}ms`)

  // A cold build is ~1.2-1.9s of genuine work (14-table tenant load + the full
  // twin assembly) and grows with estate size — that is a separate problem from
  // the one this cache solves. What the cache guarantees is that the work runs
  // ONCE PER TENANT per window no matter how many dashboards and SSE streams
  // are watching, so the threshold here is generous and the sharing assertions
  // above are the real test.
  console.log('\nVerdict')
  console.log(`  ${coldMs.median < 5000 ? 'ok  ' : 'SLOW'} cold build ${coldMs.median}ms · warm hit ${stats(warm).median}ms${active > 0 ? ` (with ${active} simulation(s) active)` : ' (no active simulations)'}`)
  if (mismatches > 0) console.log(`  FAIL ${mismatches} cross-page mismatch(es)`)
  console.log(`  ${failures === 0 ? 'ok  ' : 'FAIL'} ${failures === 0 ? 'all cache invariants hold' : `${failures} cache invariant(s) violated`}`)
  process.exitCode = mismatches + failures > 0 ? 1 : 0
}

main().catch((err) => {
  console.error(`\nprobe failed: ${err instanceof Error ? err.message : String(err)}\n`)
  process.exitCode = 1
})
