/**
 * Offline verification for the Quantum Readiness page family audit
 * (2026-10-21): the nine pages under /dashboard/quantum-readiness, plus
 * /dashboard/harvest-now and /dashboard/quantum-certification.
 *
 * Pins the contracts that audit introduced — each with the defect it replaced
 * as the negative control:
 *
 *   §1  One readiness blend: no constant governance term; unmeasured runtime
 *       excluded and weights renormalised.
 *   §2  Scoped reports use the SAME composites as the engine (they used to keep
 *       a drifted copy: components + assets summed, a hardcoded rate).
 *   §3  Posture model: assets with no evidence are counted as unassessed, and
 *       the buckets still partition the estate.
 *   §4  Exposure Graph posture == the canonical posture model.
 *   §5  Live stream: one full frame, then `-unchanged` until content changes;
 *       nested build stamps do not defeat the fingerprint.
 *   §6  Score history: records on change, not on repeat; a missing table is
 *       reported as unavailable, never drawn as a trend.
 *   §7  Report methodology states governance as Not Measured.
 *
 * No server or Supabase required.
 *
 *   npx tsx tools/quantum-readiness-pages-check.ts
 */
import { EventEmitter } from 'node:events'
import {
  blendQuantumReadiness,
  deriveAssetPostureModel,
  estimateMigrationSchedule,
  quantumRiskFrom,
  severityPressureFrom,
} from '../src/lib/migration/asset-intelligence'
import { migrationCostUsd, DEFAULT_COST_ASSUMPTIONS } from '../src/lib/migration/cost-model'
import { assembleExposureIntelligence, type ExposureRawRows } from '../src/api-server/exposure-graph'
import { payloadFingerprint, streamLiveSnapshot } from '../src/api-server/live-snapshot-stream'
import { syncScoreHistory, scoreHistoryFingerprint, type ScoreHistoryEntry } from '../src/api-server/quantum-readiness-history'
import { scopeSnapshotToAssets } from '../src/services/reporting/ReportScope'
import { buildReadinessMethodology } from '../src/services/reporting/ReportEvidence'
import type { QuantumReadinessSnapshot } from '../src/app/dashboard/quantum-readiness/_shared'

let passed = 0
let failed = 0
function check(name: string, condition: boolean, detail = '') {
  if (condition) {
    passed += 1
    console.log(`  PASS  ${name}${detail ? ` — ${detail}` : ''}`)
  } else {
    failed += 1
    console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

async function main() {
  /* ---------------------------------------------------------------- §1 */
  console.log('\n§1 Readiness blend')
  const worst = blendQuantumReadiness({ pqcAdoption: 0, quantumRisk: 100, runtimeMeasured: false })
  // Negative control: the old blend added 60 × 0.15 for governance whenever a
  // scan existed → (0 + 0 + 9) / 0.85 = 11 for an estate with nothing ready.
  const legacy = Math.round((0 * 0.45 + 0 * 0.25 + 60 * 0.15) / 0.85)
  check('nothing ready + maximal risk scores 0', worst === 0, `got ${worst}; the constant-governance blend gave ${legacy}`)
  const best = blendQuantumReadiness({ pqcAdoption: 100, quantumRisk: 0, runtimeMeasured: true })
  check('fully ready + no risk + runtime scores 100', best === 100, `got ${best}`)
  const noRuntime = blendQuantumReadiness({ pqcAdoption: 50, quantumRisk: 50, runtimeMeasured: false })
  check('unmeasured runtime is excluded, not scored 0', noRuntime === 50, `got ${noRuntime} (a 0 runtime term would give ${Math.round((50 * 0.45 + 50 * 0.25) / 0.85)})`)
  const withRuntime = blendQuantumReadiness({ pqcAdoption: 50, quantumRisk: 50, runtimeMeasured: true })
  check('measured runtime raises readiness', withRuntime > noRuntime, `${noRuntime} → ${withRuntime}`)

  /* ---------------------------------------------------------------- §2 */
  console.log('\n§2 Scoped report model uses the engine composites')
  const snapshot = {
    generatedAt: '2026-10-21T00:00:00.000Z',
    lastAssessmentAt: '2026-10-21T00:00:00.000Z',
    assessmentProgress: 71,
    assessmentStatus: 'in_progress',
    hasData: true,
    scores: { quantumReadiness: 30, quantumReadinessLevel: 'Early Stage', quantumRisk: 60, quantumRiskLevel: 'High', hndlRisk: 50, hndlRiskLevel: 'Elevated', cryptoExposure: 50, cryptoExposureLevel: 'Elevated', migrationComplexity: 30, migrationComplexityLevel: 'Moderate', migrationEffort: 60, pqcAdoption: 20 },
    inventory: { assetsAssessed: 4, certificatesAnalyzed: 2, keysDiscovered: 0, trustRelationships: 0, domainsScanned: 2, identitiesAnalyzed: 0, cloudAccounts: 0, dataRepositories: 0, pqcReadyAssets: 1, hybridAssets: 1, quantumVulnerableAssets: 2, cryptoComponents: 20, vulnerableComponents: 12, pqcReadyComponents: 4 },
    riskDistribution: { critical: 3, high: 4, medium: 2, low: 1 },
    readinessFactors: [
      { label: 'TLS / Key Exchange PQC Coverage', score: 25, measured: true, basis: '1 of 4 key exchanges' },
      { label: 'Governance Maturity', score: 0, measured: false, basis: 'No governance evidence source' },
    ],
    riskFactors: [{ label: 'RSA / ECC Exposure', score: 60, severity: 'High' }, { label: 'Internet-Facing Exposure', score: 50, severity: 'Elevated' }],
    criticalFindings: [
      { id: 'a', title: 'RSA', asset: 'api.acme.com', assetType: 'api', environment: 'production', severity: 'critical', algorithm: 'RSA-2048', detectedAt: null, instances: 2 },
      { id: 'b', title: 'ECDSA', asset: 'portal.acme.com', assetType: 'web', environment: 'production', severity: 'high', algorithm: 'ECDSA-P256', detectedAt: null, instances: 1 },
    ],
    recommendedActions: [],
    topRiskAssets: [
      { asset: 'api.acme.com', assetType: 'api', environment: 'production', owner: 'Platform', riskScore: 100, status: 'Quantum-Vulnerable' },
      { asset: 'portal.acme.com', assetType: 'web', environment: 'production', owner: 'Web', riskScore: 75, status: 'Quantum-Vulnerable' },
      { asset: 'vault.acme.com', assetType: 'database', environment: 'production', owner: 'Data', riskScore: 0, status: 'PQC-Ready' },
      { asset: 'batch.acme.local', assetType: 'server', environment: 'internal', owner: 'Ops', riskScore: 0, status: 'Not Assessed' },
    ],
    exposureGraph: { nodes: [], edges: [] },
    riskTrend: [],
    estimates: { migrationTimelineWeeks: 10, migrationCostUsd: 1, parallelWorkstreams: 1 },
    costAssumptions: DEFAULT_COST_ASSUMPTIONS,
    businessValue: { financialExposureUsd: 0, revenueProtectedUsd: 0, criticalVulnerableAssets: 0, standardVulnerableAssets: 0, criticalityTagged: false },
    telemetry: { runtimeEvents: 0, scanResults: 3, scanSessions: 2, securityEvents: 0, certificates: 2, keys: 0, assets: 4, connectors: 0, latestEventAt: null },
  } as unknown as QuantumReadinessSnapshot
  const scoped = scopeSnapshotToAssets(snapshot, ['api.acme.com', 'portal.acme.com'])
  check('scoping produced a narrower snapshot', scoped !== snapshot && scoped.inventory.assetsAssessed === 2, `${scoped.inventory.assetsAssessed} assets`)
  const s = scoped.scores
  const inv = scoped.inventory
  const totalCrypto = Math.max(1, inv.cryptoComponents)
  // The scoped internet share is published (rounded) as the Internet-Facing
  // risk factor, so ±1 is rounding, not a different formula.
  const scopedInternetShare = scoped.riskFactors.find((f) => /internet/i.test(f.label))?.score ?? 0
  const expectedRisk = quantumRiskFrom({
    severityPressure: severityPressureFrom(scoped.riskDistribution),
    vulnerableSharePct: (inv.vulnerableComponents / totalCrypto) * 100,
    internetSharePct: scopedInternetShare,
  })
  check('scoped quantum risk == shared composite', Math.abs(s.quantumRisk - expectedRisk) <= 1, `${s.quantumRisk} vs ${expectedRisk}`)
  const expectedReadiness = blendQuantumReadiness({ pqcAdoption: s.pqcAdoption, quantumRisk: s.quantumRisk, runtimeMeasured: false })
  // pqcAdoption is published rounded; allow ±1 for that rounding only.
  check('scoped readiness == shared blend (no governance term)', Math.abs(s.quantumReadiness - expectedReadiness) <= 1, `${s.quantumReadiness} vs ${expectedReadiness}`)
  const schedule = estimateMigrationSchedule({ vulnerableComponents: inv.vulnerableComponents, vulnerableAssets: inv.quantumVulnerableAssets, migrationComplexity: s.migrationComplexity, hasData: true })
  const expectedCost = migrationCostUsd(schedule.migrationTimelineWeeks, schedule.parallelWorkstreams, DEFAULT_COST_ASSUMPTIONS)
  check('scoped timeline uses the shared schedule model', scoped.estimates.migrationTimelineWeeks === schedule.migrationTimelineWeeks, `${scoped.estimates.migrationTimelineWeeks} vs ${schedule.migrationTimelineWeeks} wk`)
  check('scoped cost uses tenant cost assumptions', scoped.estimates.migrationCostUsd === expectedCost, `$${scoped.estimates.migrationCostUsd} vs $${expectedCost}`)
  const govFactor = scoped.readinessFactors.find((f) => /governance/i.test(f.label))
  check('scoped governance factor stays unmeasured', govFactor?.measured === false, JSON.stringify(govFactor))
  const tlsFactor = scoped.readinessFactors.find((f) => /tls/i.test(f.label))
  check('tenant-only factor is carried and says so', Boolean(tlsFactor?.basis?.includes('tenant-wide')), tlsFactor?.basis || 'missing')

  /* ---------------------------------------------------------------- §3 */
  console.log('\n§3 Posture model — unassessed assets')
  const assets = [
    { id: 'a1', name: 'api.acme.com', type: 'api' },
    { id: 'a2', name: 'vault.acme.com', type: 'database' },
    { id: 'a3', name: 'batch.acme.local', type: 'server' },
    { id: 'a4', name: 'cache.acme.local', type: 'server' },
  ]
  const model = deriveAssetPostureModel({
    assets,
    scanResults: [{ asset_id: 'a1', algorithm: 'RSA-2048', threat_level: 'critical' }],
    cryptoExposures: [],
    cryptoInventory: [
      { asset_id: 'a2', algorithm: 'ML-KEM-768', is_quantum_safe: true, is_vulnerable: false },
      { asset_id: 'a4', algorithm: 'AES-256-GCM', is_quantum_safe: false, is_vulnerable: false },
    ],
    runtimeEvents: [],
  })
  const c = model.counts
  check('buckets partition the estate', c.pqcReadyAssets + c.hybridAssets + c.quantumVulnerableAssets === assets.length, JSON.stringify(c))
  check('the asset with no evidence is unassessed (and nothing else is)', c.unassessedAssets === 1 && !model.evidencedAssetIds.has('a3'), `${c.unassessedAssets} unassessed`)
  check('unassessed is a subset of the hybrid bucket', c.unassessedAssets <= c.hybridAssets, `${c.unassessedAssets} ≤ ${c.hybridAssets}`)

  /* ---------------------------------------------------------------- §4 */
  console.log('\n§4 Exposure Graph posture == canonical model')
  const rows: ExposureRawRows = {
    assets: assets.map((a) => ({ ...a, environment: 'production' })),
    relationships: [],
    cryptoInventory: [
      { asset_id: 'a2', name: 'vault', algorithm: 'ML-KEM-768', is_quantum_safe: true, is_vulnerable: false },
      { asset_id: 'a4', name: 'cache', algorithm: 'AES-256-GCM', is_quantum_safe: false, is_vulnerable: false },
    ],
    // A classical certificate on an asset the canonical model has no row for.
    // The graph used to count it as vulnerability evidence on its own.
    certificates: [{ asset_id: 'a3', name: 'batch cert', algorithm: 'RSA-2048', issuer: 'CN=Internal CA', is_quantum_safe: false }],
    runtimeEvents: [],
    scanResults: [{ asset_id: 'a1', algorithm: 'RSA-2048', threat_level: 'critical' }],
    cryptoExposures: [],
    connectorAccounts: [],
    migrationJobs: [],
  }
  const graphSnapshot = { ...(snapshot as unknown as Record<string, unknown>), hasData: true } as unknown as Parameters<typeof assembleExposureIntelligence>[0]
  const graph = assembleExposureIntelligence(graphSnapshot, rows)
  check('graph "Quantum Vulnerable" == canonical vulnerable count', graph.summary.quantumVulnerable === c.quantumVulnerableAssets, `${graph.summary.quantumVulnerable} vs ${c.quantumVulnerableAssets}`)
  check('graph "PQC Ready" == canonical PQC-ready count', graph.summary.pqcReadyAssets === c.pqcReadyAssets, `${graph.summary.pqcReadyAssets} vs ${c.pqcReadyAssets}`)
  check('graph marks the unmeasured asset Unknown, not Hybrid', graph.summary.unknownPosture === c.unassessedAssets, `${graph.summary.unknownPosture} unknown`)

  /* ---------------------------------------------------------------- §5 */
  console.log('\n§5 Live snapshot stream')
  const a = { generatedAt: '1', nested: { generatedAt: 'x', value: 1 } }
  const b = { generatedAt: '2', nested: { generatedAt: 'y', value: 1 } }
  const changed = { generatedAt: '3', nested: { generatedAt: 'z', value: 2 } }
  check('build stamps (at any depth) do not change the fingerprint', payloadFingerprint(a) === payloadFingerprint(b))
  check('content changes the fingerprint', payloadFingerprint(a) !== payloadFingerprint(changed))

  const frames: string[] = []
  const req = new EventEmitter()
  const res = {
    status() { return this },
    setHeader() { /* captured implicitly */ },
    flushHeaders() { /* no-op */ },
    write(chunk: string) { frames.push(chunk) },
  }
  let builds = 0
  const sequence = [a, b, b, changed]
  streamLiveSnapshot(req as never, res as never, {
    event: 'qr',
    build: async () => sequence[Math.min(builds++, sequence.length - 1)],
    intervalMs: 25,
    heartbeatMs: 10_000,
  })
  await new Promise((resolve) => setTimeout(resolve, 140))
  req.emit('close')
  const events = frames.map((f) => /^event: (.+)$/m.exec(f)?.[1]).filter(Boolean)
  check('first frame is a full payload', events[0] === 'qr', events.slice(0, 5).join(', '))
  check('repeats are sent as -unchanged frames', events[1] === 'qr-unchanged' && events[2] === 'qr-unchanged', events.slice(0, 5).join(', '))
  check('a content change sends a full frame again', events[3] === 'qr', events.slice(0, 5).join(', '))
  const firstFull = frames[0].slice(frames[0].indexOf('data: ') + 6)
  check('full frames carry their fingerprint', JSON.parse(firstFull).fingerprint === payloadFingerprint(a))
  const after = frames.length
  await new Promise((resolve) => setTimeout(resolve, 80))
  check('closing the request stops the stream', frames.length === after, `${frames.length - after} frame(s) after close`)

  /* ---------------------------------------------------------------- §6 */
  console.log('\n§6 Score history')
  const entry: ScoreHistoryEntry = { quantumReadiness: 30, quantumRisk: 60, hndlRisk: 50, pqcAdoption: 20, assetsAssessed: 4, cryptoComponents: 20, vulnerableComponents: 12, criticalFindings: 3, highFindings: 4 }
  const store = fakeClient({ rows: [] })
  const first = await syncScoreHistory(store, 'tenant-a', entry)
  check('first assessment is recorded', store.inserts.length === 1 && first.points.length === 1, `${store.inserts.length} insert(s)`)
  store.rows = store.inserts.map((row) => ({ ...row }))
  const repeat = await syncScoreHistory(store, 'tenant-a', entry)
  check('an unchanged assessment is not recorded again', store.inserts.length === 1 && repeat.points.length === 1, `${store.inserts.length} insert(s)`)
  const moved = await syncScoreHistory(store, 'tenant-a', { ...entry, quantumReadiness: 31 })
  check('a change inside the 10-minute window is deferred, not dropped', store.inserts.length === 1 && moved.points.length === 1, `${store.inserts.length} insert(s)`)
  const older = fakeClient({ rows: [{ recorded_at: new Date(Date.now() - 11 * 60 * 1000).toISOString(), quantum_readiness: 30, quantum_risk: 60, fingerprint: scoreHistoryFingerprint(entry) }] })
  const later = await syncScoreHistory(older, 'tenant-b', { ...entry, quantumReadiness: 31 })
  check('a change after the window is recorded', older.inserts.length === 1 && later.points.length === 2 && later.points[1].readiness === 31, `${older.inserts.length} insert(s), last=${later.points.at(-1)?.readiness}`)
  check('points run oldest → newest', later.points[0].readiness === 30, later.points.map((p) => p.readiness).join(' → '))
  const noEvidence = fakeClient({ rows: [] })
  await syncScoreHistory(noEvidence, 'tenant-c', null)
  check('a tenant with no evidence records nothing', noEvidence.inserts.length === 0)
  // Last: a missing table is remembered process-wide (the table is global), so
  // every later call in this process would read "unavailable" too.
  const missingStore = fakeClient({ selectError: { code: '42P01', message: 'relation "quantum_readiness_history" does not exist' } })
  const missing = await syncScoreHistory(missingStore, 'tenant-missing', entry)
  check('missing table ⇒ unavailable with a reason, no points, no write', !missing.available && Boolean(missing.reason) && missing.points.length === 0 && missingStore.inserts.length === 0, missing.reason || '')

  /* ---------------------------------------------------------------- §7 */
  console.log('\n§7 Report methodology')
  const methodology = buildReadinessMethodology(snapshot)
  const gov = methodology.factors.find((f) => /governance/i.test(f.factor))
  check('governance is Not Measured with 0 weight', gov?.measured === false && gov.weightPct === 0, JSON.stringify(gov))
  const weightSum = methodology.factors.reduce((sum, f) => sum + f.weightPct, 0)
  check('measured weights renormalise to 100%', Math.abs(weightSum - 100) <= 0.2, `${weightSum}%`)

  console.log(`\n${passed + failed} checks — ${passed} passed, ${failed} failed`)
  process.exit(failed === 0 ? 0 : 1)
}

/** Minimal Supabase query-builder stand-in for quantum_readiness_history. */
function fakeClient(options: { rows?: Array<Record<string, unknown>>; selectError?: { code: string; message: string } }) {
  const client = {
    rows: options.rows || [],
    inserts: [] as Array<Record<string, unknown>>,
    from() {
      const chain = {
        select: () => chain,
        eq: () => chain,
        order: () => chain,
        limit: async () =>
          options.selectError
            ? { data: null, error: options.selectError }
            : { data: [...client.rows].sort((x, y) => Date.parse(String(y.recorded_at)) - Date.parse(String(x.recorded_at))), error: null },
        insert: async (row: Record<string, unknown>) => {
          client.inserts.push(row)
          return { error: null }
        },
      }
      return chain
    },
  }
  return client
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
