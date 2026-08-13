/**
 * Quantum Risk Scoring engine — offline invariant check.
 *
 * The assertions below encode the defects this refactor closed. Each one, if it
 * regressed, would put a false statement about a customer's cryptography on the
 * screen.
 *
 *   1. THE HEADLINE IS READ, NEVER COMPUTED. The score published here is byte-
 *      identical to `snapshot.scores.quantumRisk`. The implementation replaced
 *      computed its own (`assetAvg*0.42 + highest*0.38 + hndl*0.14 + penalty`),
 *      so the page named after the platform's quantum risk was the one surface
 *      that disagreed with it.
 *   2. NO SCORE FLOORS. An asset with no cryptographic evidence has `riskScore:
 *      null`, not 0 and not a criticality-derived number. The old model gave
 *      such an asset 18 points for being business-critical, inventing risk from
 *      an attribute and inflating the estate average.
 *   3. UNASSESSED IS EXCLUDED, NOT COUNTED AS SAFE. Averages and heat cells skip
 *      unassessed assets rather than treating them as low risk.
 *   4. DISTRIBUTIONS RECONCILE. Asset buckets sum to the asset count; finding
 *      buckets sum to the snapshot's own distribution.
 *   5. CANONICAL PASS-THROUGH. Every score card, the factor set, the finding
 *      distribution, the critical findings and the trend equal their snapshot
 *      counterparts exactly.
 *   6. PROJECTIONS ARE BOUNDED AND HONEST. A scenario never projects below 0,
 *      never above the current headline, and a scenario with nothing in scope
 *      reports zero reduction instead of being silently dropped.
 *
 * Run: npx tsx tools/quantum-risk-check.ts
 */

import { buildAssetPortfolio, type Row } from '../src/lib/migration/asset-intelligence'
import {
  buildQuantumRiskIntelligence,
  filterRiskAssets,
  EMPTY_RISK_FILTERS,
  type RiskSnapshotFacts,
} from '../src/lib/quantum-risk/risk-intelligence'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const NOW = Date.parse('2026-08-13T12:00:00Z')
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString()

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

const assets: Row[] = [
  { id: 'a-pay', name: 'Payment API', type: 'api', environment: 'production', service_owner: 'Payments', criticality: 'critical', metadata: { internet_facing: true }, created_at: daysAgo(200), updated_at: daysAgo(1) },
  { id: 'a-auth', name: 'Auth Service', type: 'service', environment: 'production', service_owner: 'Identity', criticality: 'high', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
  { id: 'a-report', name: 'Reporting Worker', type: 'service', environment: 'staging', service_owner: 'Data', criticality: 'medium', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
  // Business-CRITICAL but never scanned. The old model scored it 18 for its
  // criticality alone; it must now be `unassessed` with a null score.
  { id: 'a-ghost', name: 'Unscanned Mainframe', type: 'server', environment: 'production', service_owner: 'Infra', criticality: 'critical', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
]

const cryptoInventory: Row[] = [
  { id: 'c1', asset_id: 'a-pay', item_type: 'algorithm', name: 'payment signing', algorithm: 'RSA-2048', is_vulnerable: true, metadata: {}, discovered_at: daysAgo(10), created_at: daysAgo(10) },
  { id: 'c2', asset_id: 'a-pay', item_type: 'protocol', name: 'edge tls', algorithm: 'ECDHE-RSA-AES256-GCM-SHA384', protocol: 'TLS 1.2', is_vulnerable: true, metadata: {}, discovered_at: daysAgo(10), created_at: daysAgo(10) },
  { id: 'c3', asset_id: 'a-auth', item_type: 'algorithm', name: 'token signing', algorithm: 'ML-DSA-65', is_quantum_safe: true, metadata: {}, discovered_at: daysAgo(10), created_at: daysAgo(10) },
  { id: 'c4', asset_id: 'a-report', item_type: 'algorithm', name: 'batch encrypt', algorithm: 'AES-256-GCM', metadata: {}, discovered_at: daysAgo(10), created_at: daysAgo(10) },
]

const scanResults: Row[] = [
  { id: 's1', asset_id: 'a-pay', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Quantum-vulnerable signing key', finding_type: 'weak_algorithm', created_at: daysAgo(5) },
  { id: 's2', asset_id: 'a-pay', algorithm: 'TLS 1.2', threat_level: 'high', description: 'Deprecated transport', finding_type: 'weak_protocol', created_at: daysAgo(5) },
  { id: 's3', asset_id: 'a-report', algorithm: 'AES-256-GCM', threat_level: 'low', description: 'Approved symmetric cipher', finding_type: 'informational', created_at: daysAgo(5) },
]

const portfolio = buildAssetPortfolio({
  assets,
  cryptoInventory,
  scanResults,
  cryptoExposures: [],
  certificates: [],
  runtimeEvents: [],
  relationships: [],
  migrationJobs: [],
  validationLogs: [],
  complianceEvidence: [],
  now: NOW,
})

const snapshot: RiskSnapshotFacts = {
  hasData: true,
  lastAssessmentAt: daysAgo(1),
  scores: {
    quantumRisk: 67,
    quantumRiskLevel: 'High',
    hndlRisk: 54,
    hndlRiskLevel: 'Elevated',
    cryptoExposure: 71,
    cryptoExposureLevel: 'High',
    quantumReadiness: 38,
    quantumReadinessLevel: 'Developing',
    pqcAdoption: 25,
  },
  inventory: { assetsAssessed: 4, cryptoComponents: 4, vulnerableComponents: 2, quantumVulnerableAssets: 1, certificatesAnalyzed: 0 },
  riskDistribution: { critical: 1, high: 1, medium: 0, low: 1 },
  riskFactors: [
    { label: 'RSA / ECC Exposure', score: 50, severity: 'High' },
    { label: 'HNDL Exposure', score: 54, severity: 'Elevated' },
    { label: 'Internet-Facing Exposure', score: 25, severity: 'Moderate' },
    { label: 'Critical Asset Dependency', score: 0, severity: 'Low' },
    { label: 'Severity Pressure', score: 66, severity: 'High' },
  ],
  criticalFindings: [
    { id: 'f1', title: 'RSA-2048 signing key', asset: 'Payment API', severity: 'critical', algorithm: 'RSA-2048', description: 'Broken by Shor', detectedAt: daysAgo(5) },
  ],
  riskTrend: [
    { label: 'Aug 1', risk: 74, readiness: 26 },
    { label: 'Aug 8', risk: 67, readiness: 33 },
  ],
}

const model = buildQuantumRiskIntelligence({ snapshot, assets: portfolio.assets, now: NOW })

/* ------------------------------------------------------------------ */
/* 1. The headline is read, never computed                             */
/* ------------------------------------------------------------------ */
console.log('\n1. The headline is READ from the canonical snapshot')
{
  assert(model.headline.score === snapshot.scores.quantumRisk, 'headline equals snapshot.scores.quantumRisk exactly', `${model.headline.score} vs ${snapshot.scores.quantumRisk}`)
  assert(model.headline.level === snapshot.scores.quantumRiskLevel, 'headline level equals the snapshot level', model.headline.level)
  assert(model.headline.source === 'quantum-readiness-snapshot', 'provenance is declared on the payload', model.headline.source)

  // The decisive test: change ONLY the snapshot and the page must move with it.
  const shifted = buildQuantumRiskIntelligence({
    snapshot: { ...snapshot, scores: { ...snapshot.scores, quantumRisk: 12, quantumRiskLevel: 'Low' } },
    assets: portfolio.assets,
    now: NOW,
  })
  assert(shifted.headline.score === 12, 'the page follows the snapshot rather than recomputing', String(shifted.headline.score))
  assert(shifted.headline.score !== model.headline.score, 'and is not pinned to an internally derived value')
}

/* ------------------------------------------------------------------ */
/* 2-3. No score floors; unassessed is excluded                        */
/* ------------------------------------------------------------------ */
console.log('\n2-3. Criticality amplifies measured risk — it never creates it')
{
  const ghost = model.assets.find((a) => a.name === 'Unscanned Mainframe')!
  assert(ghost.state === 'unassessed', 'a business-critical asset with no evidence is UNASSESSED', ghost.state)
  assert(ghost.riskScore === null, 'and carries NO risk score (not 0, not a criticality boost)', String(ghost.riskScore))
  assert(ghost.riskLevel === 'Not Assessed', 'its level says so in words', ghost.riskLevel)

  const scored = model.assets.filter((a) => a.riskScore !== null)
  assert(scored.every((a) => a.state === 'assessed'), 'every scored asset has real evidence behind it')
  assert(model.coverage.assetsUnassessed === 1, 'coverage reports the unassessed count', String(model.coverage.assetsUnassessed))
  assert(model.coverage.assetsWithEvidence + model.coverage.assetsUnassessed === model.coverage.assetsAssessed, 'coverage reconciles')

  const cells = model.heatmap.filter((c) => c.averageRisk !== null)
  assert(cells.every((c) => c.averageRisk! >= 0 && c.averageRisk! <= 100), 'heat cells stay in [0,100]')
  // The portfolio normalises criticality labels ("critical" → "Critical"), so
  // the heat key is matched case-insensitively.
  const ghostCell = model.heatmap.find(
    (c) => c.environment.toLowerCase() === 'production' && c.criticality.toLowerCase() === 'critical',
  )
  assert(Boolean(ghostCell), 'the unassessed asset still appears in the heatmap', ghostCell ? `${ghostCell.assets} asset(s)` : 'missing')
  assert(ghostCell?.assets === 2, 'its cell counts it alongside the scored critical asset', String(ghostCell?.assets))
  // The decisive one: production/Critical holds Payment API (100) and the
  // unscanned mainframe. Averaging the unassessed asset in as 0 would report 50
  // and understate the estate's worst cell by half.
  const payment = model.assets.find((a) => a.name === 'Payment API')!
  assert(
    ghostCell?.averageRisk === payment.riskScore,
    'the average covers only assessed assets — an unassessed asset never dilutes it',
    `${ghostCell?.averageRisk} vs ${payment.riskScore} (naive average would be ${Math.round((payment.riskScore ?? 0) / 2)})`,
  )
}

/* ------------------------------------------------------------------ */
/* 4. Distributions reconcile                                          */
/* ------------------------------------------------------------------ */
console.log('\n4. Distributions reconcile with what they decompose')
{
  const assetSum = model.assetDistribution.reduce((s, r) => s + r.count, 0)
  assert(assetSum === model.assets.length, 'asset buckets sum to the asset count', `${assetSum} vs ${model.assets.length}`)

  const unassessedBucket = model.assetDistribution.find((r) => r.key === 'unassessed')!
  assert(unassessedBucket.count === model.coverage.assetsUnassessed, 'the unassessed bucket matches coverage', String(unassessedBucket.count))

  const findingSum = model.findingDistribution.reduce((s, r) => s + r.count, 0)
  const snapshotSum = snapshot.riskDistribution.critical + snapshot.riskDistribution.high + snapshot.riskDistribution.medium + snapshot.riskDistribution.low
  assert(findingSum === snapshotSum, 'finding buckets sum to the snapshot distribution', `${findingSum} vs ${snapshotSum}`)
  assert(
    model.findingDistribution.find((r) => r.key === 'critical')!.count === snapshot.riskDistribution.critical,
    'each finding bucket equals its snapshot counterpart',
  )
}

/* ------------------------------------------------------------------ */
/* 5. Canonical pass-through                                           */
/* ------------------------------------------------------------------ */
console.log('\n5. Every published score traces to a canonical owner')
{
  const byKey = new Map(model.scoreCards.map((c) => [c.key, c]))
  assert(byKey.get('quantum-risk')!.score === snapshot.scores.quantumRisk, 'quantum risk card matches the snapshot')
  assert(byKey.get('hndl')!.score === snapshot.scores.hndlRisk, 'HNDL card matches the snapshot')
  assert(byKey.get('crypto-exposure')!.score === snapshot.scores.cryptoExposure, 'crypto exposure card matches the snapshot')
  assert(byKey.get('readiness')!.score === snapshot.scores.quantumReadiness, 'readiness card matches the snapshot')
  assert(byKey.get('pqc-adoption')!.score === snapshot.scores.pqcAdoption, 'PQC adoption card matches the snapshot')
  assert(model.scoreCards.every((c) => c.source === 'quantum-readiness-snapshot'), 'every card declares its source')

  assert(model.factors.length === snapshot.riskFactors.length, 'the factor set is the snapshot\'s, not a second one', String(model.factors.length))
  assert(
    model.factors.every((f, i) => f.score === snapshot.riskFactors[i].score && f.label === snapshot.riskFactors[i].label),
    'each factor score passes through unchanged',
  )
  const contributions = model.factors.reduce((s, f) => s + f.contributionPct, 0)
  assert(contributions >= 98 && contributions <= 102, 'factor contributions normalise to ~100%', String(contributions))
  assert(model.factors.every((f) => f.what && f.action), 'every factor explains itself and names an action')

  assert(model.trend === snapshot.riskTrend, 'the trend is the snapshot\'s series')
  assert(model.criticalFindings.length === snapshot.criticalFindings.length, 'critical findings pass through', String(model.criticalFindings.length))
}

/* ------------------------------------------------------------------ */
/* 6. Projections are bounded and honest                               */
/* ------------------------------------------------------------------ */
console.log('\n6. Reduction scenarios are bounded projections, never claims')
{
  assert(model.scenarios.length === 4, 'all four scenarios are returned', String(model.scenarios.length))
  assert(
    model.scenarios.every((s) => s.projectedRisk >= 0 && s.projectedRisk <= model.headline.score),
    'no projection escapes [0, current headline]',
  )
  assert(
    model.scenarios.every((s) => s.reductionPoints === model.headline.score - s.projectedRisk),
    'the stated reduction equals the actual delta',
  )
  const notApplicable = model.scenarios.filter((s) => s.assetsAffected === 0)
  assert(
    notApplicable.every((s) => s.reductionPoints === 0),
    'a scenario with nothing in scope claims no reduction',
    `${notApplicable.length} not applicable`,
  )
  assert(
    model.scenarios.some((s) => s.assetsAffected > 0),
    'at least one scenario is actionable on this fixture',
  )

  const empty = buildQuantumRiskIntelligence({
    snapshot: { ...snapshot, hasData: false },
    assets: [],
    now: NOW,
  })
  assert(empty.scoreCards.every((c) => c.score === null), 'with no assessment every card is null, never 0')
  assert(empty.assets.length === 0 && empty.scenarios.every((s) => s.reductionPoints === 0), 'and no scenario claims a reduction')
}

/* ------------------------------------------------------------------ */
/* 7. Filtering                                                        */
/* ------------------------------------------------------------------ */
console.log('\n7. Filtering never changes what a value means')
{
  const all = filterRiskAssets(model.assets, EMPTY_RISK_FILTERS)
  assert(all.length === model.assets.length, 'the empty filter is a no-op', `${all.length}`)

  const production = filterRiskAssets(model.assets, { ...EMPTY_RISK_FILTERS, environment: 'production' })
  assert(production.every((a) => a.environment === 'production'), 'environment filter is exact')
  assert(production.length === 3, 'and matches the fixture', String(production.length))

  const unassessed = filterRiskAssets(model.assets, { ...EMPTY_RISK_FILTERS, level: 'unassessed' })
  assert(unassessed.length === 1 && unassessed[0].name === 'Unscanned Mainframe', 'unassessed is selectable as its own class')

  const search = filterRiskAssets(model.assets, { ...EMPTY_RISK_FILTERS, search: 'payment' })
  assert(search.length === 1 && search[0].name === 'Payment API', 'search matches name')
}

/* ------------------------------------------------------------------ */
/* 8. Cross-module identity                                            */
/* ------------------------------------------------------------------ */
console.log('\n8. An asset reads identically here and in the Migration Planner')
{
  for (const row of model.assets) {
    const source = portfolio.assets.find((a) => a.id === row.id)!
    assert(
      row.state === 'unassessed' || row.riskScore === Math.round(source.riskScore),
      `${row.name}: risk score inherited from the shared portfolio`,
      `${row.riskScore} vs ${Math.round(source.riskScore)}`,
    )
    if (row.state !== 'unassessed') {
      assert(row.postureLabel === source.postureLabel, `${row.name}: posture inherited`, row.postureLabel)
    }
  }
  assert(model.assets.every((r) => r.hndlScore === Math.round(portfolio.assets.find((a) => a.id === r.id)!.hndlScore)), 'HNDL scores inherited')
}

console.log(`\n${failures === 0 ? '✓ All quantum risk scoring invariants hold.' : `✗ ${failures} invariant(s) FAILED.`}`)
process.exit(failures === 0 ? 0 : 1)
