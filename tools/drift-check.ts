/**
 * Cryptographic Drift engine — offline invariant check.
 *
 *   1. NO BASELINE, NO DRIFT. With fewer than two completed scans the engine
 *      reports no baseline, emits no events and publishes NO stability score.
 *      The implementation this replaces keyword-matched existing findings and
 *      called them drift, so a tenant whose cryptography had not changed still
 *      saw a busy feed on its very first scan.
 *   2. STABILITY IS NEVER 100-FROM-NOTHING. An unmeasured estate scores `null`,
 *      not 100 — the natural default for a "stability" metric is exactly the
 *      reading an unmonitored estate must never produce.
 *   3. PLANNED CHANGE IS NOT DRIFT. A change explained by an approved migration
 *      is classified `planned` and excluded from the unplanned count.
 *   4. DIRECTION IS CORRECT. New vulnerable cryptography is a regression;
 *      cryptography that disappeared is an improvement. Severity worsening on an
 *      unchanged item is a regression too.
 *   5. IDENTITY IS STABLE ACROSS SCANS. The same algorithm on the same asset is
 *      the same item, so a re-scan that changes only row ids and narrative text
 *      produces ZERO drift.
 *   6. RUNTIME DOWNGRADES AGGREGATE per asset+algorithm, not per event.
 *   7. ROLL-UPS RECONCILE with the event list.
 *
 * Run: npx tsx tools/drift-check.ts
 */

import { buildAssetPortfolio, type Row } from '../src/lib/migration/asset-intelligence'
import {
  buildDriftIntelligence,
  filterDriftEvents,
  isUnplanned,
  EMPTY_DRIFT_FILTERS,
  type DriftInputs,
} from '../src/lib/drift/drift-intelligence'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const NOW = Date.parse('2026-08-13T12:00:00Z')
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString()
const hoursAgo = (n: number) => new Date(NOW - n * 3_600_000).toISOString()

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

const assets: Row[] = [
  { id: 'a-pay', name: 'payments.example.com', type: 'api', environment: 'production', service_owner: 'Payments', criticality: 'critical', metadata: { hostname: 'payments.example.com' }, created_at: daysAgo(90), updated_at: daysAgo(1) },
  { id: 'a-edge', name: 'edge.example.com', type: 'web-service', environment: 'production', service_owner: 'Platform', criticality: 'high', metadata: { hostname: 'edge.example.com' }, created_at: daysAgo(90), updated_at: daysAgo(1) },
  { id: 'a-dev', name: 'dev.example.com', type: 'server', environment: 'development', service_owner: 'Platform', criticality: 'low', metadata: { hostname: 'dev.example.com' }, created_at: daysAgo(90), updated_at: daysAgo(1) },
]

const portfolio = buildAssetPortfolio({
  assets, cryptoInventory: [], scanResults: [], cryptoExposures: [], certificates: [], runtimeEvents: [],
  relationships: [], migrationJobs: [], validationLogs: [], complianceEvidence: [], now: NOW,
})

const scanSessions: Row[] = [
  { id: 'session-old', status: 'completed', completed_at: daysAgo(7), created_at: daysAgo(7) },
  { id: 'session-new', status: 'completed', completed_at: daysAgo(1), created_at: daysAgo(1) },
  { id: 'session-running', status: 'running', completed_at: null, created_at: hoursAgo(1) },
]

const scanResults: Row[] = [
  /* ---- baseline (session-old) ---- */
  // Persisted unchanged into the new scan.
  { id: 'r1', scan_session_id: 'session-old', asset_id: 'a-pay', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Signing key', created_at: daysAgo(7) },
  // Disappears in the new scan and IS explained by a completed migration ⇒ planned.
  { id: 'r2', scan_session_id: 'session-old', asset_id: 'a-edge', algorithm: 'ECDHE-RSA-AES128-SHA', threat_level: 'high', description: 'Legacy suite', created_at: daysAgo(7) },
  // Disappears with NO migration ⇒ unplanned improvement.
  { id: 'r3', scan_session_id: 'session-old', asset_id: 'a-dev', algorithm: 'SHA-1', threat_level: 'medium', description: 'Legacy hash', created_at: daysAgo(7) },
  // Severity worsens in the new scan ⇒ regression.
  { id: 'r4', scan_session_id: 'session-old', asset_id: 'a-dev', algorithm: 'AES-128-CBC', threat_level: 'low', description: 'Weak mode', created_at: daysAgo(7) },

  /* ---- current (session-new) ---- */
  // Same item, different row id and different narrative — must NOT be drift.
  { id: 'r5', scan_session_id: 'session-new', asset_id: 'a-pay', algorithm: 'RSA-2048', threat_level: 'critical', description: 'RSA signing key detected on host', created_at: daysAgo(1) },
  // NEW vulnerable crypto with no migration ⇒ regression.
  { id: 'r6', scan_session_id: 'session-new', asset_id: 'a-pay', algorithm: 'X25519', threat_level: 'high', description: 'Classical key exchange', created_at: daysAgo(1) },
  // NEW post-quantum crypto explained by a migration ⇒ planned.
  { id: 'r7', scan_session_id: 'session-new', asset_id: 'a-edge', algorithm: 'X25519MLKEM768', threat_level: 'low', description: 'Hybrid group', created_at: daysAgo(1) },
  // Severity worsened.
  { id: 'r8', scan_session_id: 'session-new', asset_id: 'a-dev', algorithm: 'AES-128-CBC', threat_level: 'high', description: 'Weak mode', created_at: daysAgo(1) },
]

const migrationJobs: Row[] = [
  { id: 'j1', asset_id: 'a-edge', name: 'Edge hybrid TLS cutover', status: 'completed', target_algorithm: 'X25519MLKEM768', completed_at: daysAgo(3), updated_at: daysAgo(3), created_at: daysAgo(10) },
]

const runtimeEvents: Row[] = [
  ...Array.from({ length: 4 }, (_, i) => ({
    id: `d${i}`, asset_id: 'a-pay', asset_name: 'payments.example.com', key_exchange_algorithm: 'X25519',
    downgrade_detected: true, observed_at: hoursAgo(i + 1), created_at: hoursAgo(i + 1),
  })),
  { id: 'not-a-downgrade', asset_id: 'a-pay', asset_name: 'payments.example.com', key_exchange_algorithm: 'X25519MLKEM768', downgrade_detected: false, observed_at: hoursAgo(1), created_at: hoursAgo(1) },
]

const base: DriftInputs = { scanSessions, scanResults, runtimeEvents, migrationJobs, assets: portfolio.assets, now: NOW }
const model = buildDriftIntelligence(base)

/* ------------------------------------------------------------------ */
/* 1-2. No baseline, no drift; no score from nothing                   */
/* ------------------------------------------------------------------ */
console.log('\n1-2. Drift requires a baseline, and stability is never assumed')
{
  const oneScan = buildDriftIntelligence({ ...base, scanSessions: [scanSessions[0], scanSessions[2]] })
  assert(!oneScan.hasBaseline, 'one completed scan ⇒ no baseline', String(oneScan.hasBaseline))
  assert(oneScan.stability.score === null, 'and NO stability score (not 100, not 0)', String(oneScan.stability.score))
  assert(oneScan.stability.level === 'No Baseline', 'the level says so in words', oneScan.stability.level)
  assert(oneScan.events.filter((e) => e.source === 'scan-comparison').length === 0, 'the first scan\'s findings are not published as changes')
  assert(oneScan.postureDelta === null, 'and no posture movement is claimed')
  assert(/run a second scan/i.test(oneScan.baseline.note), 'the page explains what is needed', oneScan.baseline.note.slice(0, 52))

  const noScans = buildDriftIntelligence({ ...base, scanSessions: [], scanResults: [] })
  assert(!noScans.hasBaseline && noScans.stability.score === null, 'zero scans ⇒ no baseline, no score')

  assert(model.hasBaseline, 'two completed scans ⇒ a baseline exists')
  assert(model.baseline.sessionsCompared === 2, 'exactly two sessions are compared', String(model.baseline.sessionsCompared))
  assert(model.baseline.currentSessionId === 'session-new', 'the newest COMPLETED scan is current', String(model.baseline.currentSessionId))
  assert(model.baseline.baselineSessionId === 'session-old', 'the one before it is the baseline', String(model.baseline.baselineSessionId))
  assert(model.stability.score !== null && model.stability.score >= 0 && model.stability.score <= 100, 'stability is bounded', String(model.stability.score))
}

/* ------------------------------------------------------------------ */
/* 3. Planned change is not drift                                      */
/* ------------------------------------------------------------------ */
console.log('\n3. A migration doing its job is not drift')
{
  const hybridAppeared = model.events.find((e) => e.algorithm === 'X25519MLKEM768')!
  assert(Boolean(hybridAppeared), 'the new hybrid group is detected')
  assert(hybridAppeared.driftClass === 'planned', 'and classified as PLANNED, not drift', hybridAppeared.driftClass)
  assert(Boolean(hybridAppeared.explainedBy), 'naming the migration that explains it', String(hybridAppeared.explainedBy))

  const legacyGone = model.events.find((e) => e.algorithm === 'ECDHE-RSA-AES128-SHA')!
  assert(legacyGone.driftClass === 'planned', 'the legacy suite it replaced is planned too', legacyGone.driftClass)

  assert(!isUnplanned(hybridAppeared) && !isUnplanned(legacyGone), 'neither counts as unplanned')
  assert(
    model.kpis.unplannedChanges === model.events.filter(isUnplanned).length,
    'the unplanned KPI excludes planned change',
    `${model.kpis.unplannedChanges}`,
  )
  assert(model.kpis.planned === 2, 'both planned changes are counted separately', String(model.kpis.planned))
}

/* ------------------------------------------------------------------ */
/* 4. Direction is correct                                             */
/* ------------------------------------------------------------------ */
console.log('\n4. Regressions and improvements point the right way')
{
  const newClassical = model.events.find((e) => e.algorithm === 'X25519' && e.source === 'scan-comparison')!
  assert(newClassical.driftClass === 'regression', 'new quantum-vulnerable crypto is a REGRESSION', newClassical.driftClass)
  assert(newClassical.before === null && newClassical.after === 'X25519', 'before/after reflect an appearance', `${newClassical.before} → ${newClassical.after}`)

  const shaGone = model.events.find((e) => e.algorithm === 'SHA-1')!
  assert(shaGone.driftClass === 'improvement', 'an unexplained VULNERABLE disappearance is an IMPROVEMENT', shaGone.driftClass)
  assert(shaGone.before === 'SHA-1' && shaGone.after === null, 'before/after reflect a disappearance', `${shaGone.before} → ${shaGone.after}`)
  assert(/reduced scan coverage/i.test(shaGone.recommendedAction), 'but warns it might be lost coverage, not a fix')

  const worsened = model.events.find((e) => e.algorithm === 'AES-128-CBC')!
  assert(worsened.driftClass === 'regression', 'severity worsening on an unchanged item is a REGRESSION', worsened.driftClass)
  assert(worsened.before === 'low' && worsened.after === 'high', 'and reports the severity move', `${worsened.before} → ${worsened.after}`)

  assert(model.events.every((e) => Boolean(e.why) && Boolean(e.recommendedAction)), 'every change explains itself and names an action')
  assert(model.events.every((e) => e.evidence.length > 0), 'and cites its evidence')
}

/* ------------------------------------------------------------------ */
/* 4b. Coverage change is not posture change                           */
/* ------------------------------------------------------------------ */
console.log('\n4b. Newly seen safe cryptography is COVERAGE, never an improvement')
{
  // A safe algorithm appearing with no migration to explain it: the scan simply
  // saw more than last time. Classifying that as an improvement is what turned a
  // 38-finding baseline into 68 "improvements" against a 46-finding scan.
  const wider = buildDriftIntelligence({
    ...base,
    runtimeEvents: [],
    migrationJobs: [],
    scanSessions: [scanSessions[0], scanSessions[1]],
    scanResults: [
      { id: 'b1', scan_session_id: 'session-old', asset_id: 'a-pay', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Signing key', created_at: daysAgo(7) },
      { id: 'c1', scan_session_id: 'session-new', asset_id: 'a-pay', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Signing key', created_at: daysAgo(1) },
      // Three safe primitives a deeper scan picked up.
      { id: 'c2', scan_session_id: 'session-new', asset_id: 'a-pay', algorithm: 'AES-256-GCM', threat_level: 'low', description: 'Bulk cipher', created_at: daysAgo(1) },
      { id: 'c3', scan_session_id: 'session-new', asset_id: 'a-pay', algorithm: 'SHA3-256', threat_level: 'low', description: 'Hash', created_at: daysAgo(1) },
      { id: 'c4', scan_session_id: 'session-new', asset_id: 'a-pay', algorithm: 'ML-DSA-65', threat_level: 'low', description: 'Signature', created_at: daysAgo(1) },
    ],
  })
  assert(wider.kpis.improvements === 0, 'a deeper scan produces NO improvements', String(wider.kpis.improvements))
  assert(wider.kpis.regressions === 0, 'and no regressions - nothing got worse', String(wider.kpis.regressions))
  assert(wider.kpis.unplannedChanges === 0, 'so there is no unplanned posture change at all', String(wider.kpis.unplannedChanges))
  assert(
    wider.events.filter((e) => e.driftClass === 'coverage').length === 3,
    'the three newly seen safe primitives are COVERAGE changes',
    String(wider.events.filter((e) => e.driftClass === 'coverage').length),
  )
  assert(wider.stability.score === 100, 'and stability stays 100 - a deeper scan is not instability', String(wider.stability.score))
  assert(/coverage change/i.test(wider.stability.statement), 'the statement says so plainly', wider.stability.statement.slice(0, 72))

  // Symmetric case: a safe algorithm dropping out is coverage, not a win.
  const narrower = buildDriftIntelligence({
    ...base,
    runtimeEvents: [],
    migrationJobs: [],
    scanSessions: [scanSessions[0], scanSessions[1]],
    scanResults: [
      { id: 'b1', scan_session_id: 'session-old', asset_id: 'a-pay', algorithm: 'AES-256-GCM', threat_level: 'low', description: 'Bulk cipher', created_at: daysAgo(7) },
      { id: 'b2', scan_session_id: 'session-old', asset_id: 'a-pay', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Signing key', created_at: daysAgo(7) },
      { id: 'c1', scan_session_id: 'session-new', asset_id: 'a-pay', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Signing key', created_at: daysAgo(1) },
    ],
  })
  const aesGone = narrower.events.find((e) => e.algorithm === 'AES-256-GCM')!
  assert(aesGone.driftClass === 'coverage', 'a SAFE algorithm disappearing is coverage, not a security win', aesGone.driftClass)
  assert(narrower.kpis.improvements === 0, 'and it is not counted as an improvement', String(narrower.kpis.improvements))
  assert(/scan coverage/i.test(aesGone.why), 'the explanation names scan coverage', aesGone.why.slice(-40))
}

/* ------------------------------------------------------------------ */
/* 5. Identity is stable across scans                                  */
/* ------------------------------------------------------------------ */
console.log('\n5. A re-scan of unchanged cryptography produces zero drift')
{
  const rsa = model.events.filter((e) => e.algorithm === 'RSA-2048')
  assert(rsa.length === 0, 'RSA-2048 unchanged between scans ⇒ NOT reported as drift', `${rsa.length} event(s)`)

  // The decisive test: re-run the same scan under new row ids and new prose.
  const rescan: Row[] = scanResults
    .filter((r) => r.scan_session_id === 'session-old')
    .map((r, i) => ({ ...r, id: `rescan-${i}`, scan_session_id: 'session-copy', description: `Totally different narrative ${i}`, created_at: daysAgo(1) }))
  const identical = buildDriftIntelligence({
    ...base,
    scanSessions: [scanSessions[0], { id: 'session-copy', status: 'completed', completed_at: daysAgo(1), created_at: daysAgo(1) }],
    scanResults: [...scanResults.filter((r) => r.scan_session_id === 'session-old'), ...rescan],
    runtimeEvents: [],
    migrationJobs: [],
  })
  assert(identical.hasBaseline, 'the identical re-scan still forms a baseline')
  assert(identical.events.length === 0, 'and produces ZERO drift events', `${identical.events.length}`)
  assert(identical.stability.score === 100, 'stability reads 100 only when nothing actually changed', String(identical.stability.score))
  assert(identical.kpis.unplannedChanges === 0, 'no unplanned change is invented')
}

/* ------------------------------------------------------------------ */
/* 6. Runtime downgrades aggregate                                     */
/* ------------------------------------------------------------------ */
console.log('\n6. Runtime downgrades aggregate per asset and algorithm')
{
  const downgrades = model.events.filter((e) => e.source === 'runtime-downgrade')
  assert(downgrades.length === 1, 'four downgrade events on one asset ⇒ ONE finding', String(downgrades.length))
  assert(/4 downgrade event/.test(downgrades[0].evidence.join(' ')), 'and it reports the true count', downgrades[0].evidence[0])
  assert(downgrades[0].driftClass === 'regression', 'a downgrade is a regression', downgrades[0].driftClass)
  assert(model.kpis.runtimeDowngrades === 1, 'the KPI counts distinct downgrade findings', String(model.kpis.runtimeDowngrades))
  assert(
    !model.events.some((e) => e.source === 'runtime-downgrade' && e.algorithm === 'X25519MLKEM768'),
    'a successful hybrid handshake is never counted as a downgrade',
  )
}

/* ------------------------------------------------------------------ */
/* 7. Roll-ups reconcile                                               */
/* ------------------------------------------------------------------ */
console.log('\n7. Every roll-up reconciles with the event list')
{
  const summed = model.summary.reduce((s, r) => s + r.count, 0)
  assert(summed === model.events.length, 'summary buckets sum to the event count', `${summed} vs ${model.events.length}`)
  assert(
    model.summary.find((r) => r.key === 'regression')!.count === model.kpis.regressions,
    'the regression bucket matches its KPI',
  )
  assert(
    model.summary.find((r) => r.key === 'planned')!.count === model.kpis.planned,
    'the planned bucket matches its KPI',
  )
  assert(
    model.summary.some((r) => r.key === 'coverage'),
    'the coverage class has its own bucket',
  )

  const classified = model.events.filter((e) => e.driftClass !== 'coverage').length
  const assetSum = model.byAsset.reduce((s, a) => s + a.regressions + a.improvements + a.planned, 0)
  assert(assetSum === classified, 'the asset roll-up sums to the posture-changing events', `${assetSum} vs ${classified}`)
  assert(model.kpis.assetsChanged === model.byAsset.length, 'the changed-asset KPI matches the roll-up')
  assert(
    model.byAsset.every((a) => a.netChange === a.improvements - a.regressions),
    'net change is improvements minus regressions',
  )

  assert(model.postureDelta !== null, 'posture movement is published when a baseline exists')
  assert(
    model.postureDelta!.delta === model.postureDelta!.currentFindings - model.postureDelta!.baselineFindings,
    'and its delta is the real difference',
  )

  const all = filterDriftEvents(model.events, EMPTY_DRIFT_FILTERS)
  assert(all.length === model.events.length, 'the empty filter is a no-op')
  const regressions = filterDriftEvents(model.events, { ...EMPTY_DRIFT_FILTERS, driftClass: 'regression' })
  assert(regressions.every((e) => e.driftClass === 'regression'), 'class filter is exact')
  assert(regressions.length === model.kpis.regressions, 'and matches the KPI', String(regressions.length))
}

console.log(`\n${failures === 0 ? '✓ All drift detection invariants hold.' : `✗ ${failures} invariant(s) FAILED.`}`)
process.exit(failures === 0 ? 0 : 1)
