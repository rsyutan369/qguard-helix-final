/**
 * Runtime Cryptographic Intelligence engine — offline invariant check.
 *
 * Exercises the PURE isomorphic engine (no Supabase / server required) against
 * a realistic tenant fixture and asserts the guarantees the dashboard depends
 * on. Each assertion below exists because getting it wrong would publish a
 * false statement about a customer's cryptography.
 *
 *   1. Runtime means runtime — with no runtime events the engine reports no
 *      runtime evidence and publishes NO score, rather than substituting scan
 *      data or presenting 0 as a measurement.
 *   2. The verdict comes from the RISK-BEARING primitive. A TLS 1.3 session
 *      whose suite names only AES-256-GCM is judged on its key exchange, and
 *      AES-256-GCM alone is never reported as quantum vulnerable.
 *   3. Hybrid X25519MLKEM768 reads as hybrid, not classical and not vulnerable.
 *   4. `unknown` never resolves to safe.
 *   5. The runtime mix reconciles: bucket counts sum to the observation total
 *      and percentages sum to exactly 100.
 *   6. Findings are aggregated per asset+primitive, not per event, so N
 *      observations of one problem are ONE issue seen N times.
 *   7. Impact-weighted priority ranks the same algorithm higher on a critical
 *      internet-facing production asset than on a development box.
 *   8. Migration verification never claims success without post-cutover runtime
 *      evidence, and reports fallbacks when they exist.
 *   9. Expected-vs-actual reports drift only against an actual observation, and
 *      never fabricates a "matching" verdict from missing evidence.
 *  10. Sophia states nothing the evidence does not support.
 *  11. Secrets and key material never reach the client payload.
 *  12. A month-over-month adoption trend is withheld when the row set was
 *      truncated or when either window is empty.
 *
 * Run: npx tsx tools/runtime-crypto-intel-check.ts
 */

import { buildAssetPortfolio, type Row } from '../src/lib/migration/asset-intelligence'
import {
  buildRuntimeCryptoIntelligence,
  decomposeRuntimeEvent,
  type RuntimeIntelInputs,
  type RuntimeSnapshotFacts,
} from '../src/lib/runtime-crypto/runtime-intelligence'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const NOW = Date.parse('2026-08-13T12:00:00Z')
const minutesAgo = (n: number) => new Date(NOW - n * 60_000).toISOString()
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString()

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

const assets: Row[] = [
  { id: 'a-pay', name: 'Payment API', type: 'api', environment: 'production', service_owner: 'Payments', criticality: 'critical', metadata: { internet_facing: true, hostname: 'pay.example.com' }, created_at: daysAgo(200), updated_at: daysAgo(1) },
  { id: 'a-auth', name: 'Auth Service', type: 'service', environment: 'production', service_owner: 'Identity', criticality: 'high', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
  { id: 'a-legacy', name: 'Legacy API', type: 'api', environment: 'production', service_owner: 'Platform', criticality: 'medium', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
  { id: 'a-dev', name: 'Dev Sandbox', type: 'server', environment: 'development', service_owner: 'Platform', criticality: 'low', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
]

const cryptoInventory: Row[] = [
  { id: 'c1', asset_id: 'a-pay', item_type: 'algorithm', name: 'payment signing', algorithm: 'RSA-2048', is_vulnerable: true, metadata: {}, discovered_at: daysAgo(10), created_at: daysAgo(10) },
  { id: 'c2', asset_id: 'a-auth', item_type: 'algorithm', name: 'token signing', algorithm: 'ML-DSA-65', is_quantum_safe: true, metadata: {}, discovered_at: daysAgo(10), created_at: daysAgo(10) },
]

const portfolio = buildAssetPortfolio({
  assets,
  cryptoInventory,
  scanResults: [],
  cryptoExposures: [],
  certificates: [],
  runtimeEvents: [],
  relationships: [],
  migrationJobs: [],
  validationLogs: [],
  complianceEvidence: [],
  now: NOW,
})

const snapshot: RuntimeSnapshotFacts = {
  hasData: true,
  lastAssessmentAt: daysAgo(1),
  scores: {
    quantumReadiness: 61,
    pqcAdoption: 44,
    quantumRisk: 58,
    quantumRiskLevel: 'High',
    hndlRisk: 63,
    hndlRiskLevel: 'High',
  },
  inventory: { assetsAssessed: 4, cryptoComponents: 2, vulnerableComponents: 1, certificatesAnalyzed: 0 },
}

const baseEvent = {
  source_type: 'local-agent',
  severity: 'low',
  risk_score: 0,
  is_pqc: false,
  is_legacy: false,
  downgrade_detected: false,
  shadow_crypto: false,
  hndl_risk: false,
  metadata: {},
}

const runtimeEvents: Row[] = [
  // Payment API — TLS 1.3, hybrid group. Suite names ONLY the bulk cipher.
  {
    ...baseEvent, id: 'e1', asset_id: 'a-pay', asset_name: 'Payment API', event_type: 'tls_handshake', operation_type: 'key_exchange',
    protocol: 'TLS', tls_version: 'TLS 1.3', cipher_suite: 'TLS_AES_256_GCM_SHA384', key_exchange_algorithm: 'X25519MLKEM768',
    algorithm: 'ML-DSA-65', host: 'pay.example.com', port: 443, is_pqc: true, observed_at: minutesAgo(3), created_at: minutesAgo(3),
  },
  // Auth Service — ML-DSA signing.
  {
    ...baseEvent, id: 'e2', asset_id: 'a-auth', asset_name: 'Auth Service', event_type: 'jwt_sign', operation_type: 'signing',
    algorithm: 'ML-DSA-65', observed_at: minutesAgo(5), created_at: minutesAgo(5),
  },
  // Legacy API — classical X25519 key exchange over TLS 1.2, seen four times.
  ...[10, 12, 14, 16].map((minute, index) => ({
    ...baseEvent, id: `e-legacy-${index}`, asset_id: 'a-legacy', asset_name: 'Legacy API', event_type: 'tls_handshake',
    operation_type: 'key_exchange', protocol: 'TLS', tls_version: 'TLS 1.2', key_exchange_algorithm: 'X25519',
    cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', hndl_risk: true, is_legacy: true,
    observed_at: minutesAgo(minute), created_at: minutesAgo(minute),
  })),
  // Dev Sandbox — the SAME classical primitive, on a low-criticality dev box.
  {
    ...baseEvent, id: 'e-dev', asset_id: 'a-dev', asset_name: 'Dev Sandbox', event_type: 'tls_handshake', operation_type: 'key_exchange',
    protocol: 'TLS', tls_version: 'TLS 1.2', key_exchange_algorithm: 'X25519', observed_at: minutesAgo(20), created_at: minutesAgo(20),
  },
  // A pure bulk-cipher observation: quantum-resistant, must never read critical.
  {
    ...baseEvent, id: 'e-aes', asset_id: 'a-auth', asset_name: 'Auth Service', event_type: 'data_encrypt', operation_type: 'encryption',
    algorithm: 'AES-256-GCM', observed_at: minutesAgo(7), created_at: minutesAgo(7),
  },
  // An observation whose primitive cannot be determined.
  {
    ...baseEvent, id: 'e-unknown', asset_id: 'a-dev', asset_name: 'Dev Sandbox', event_type: 'crypto_call', operation_type: 'other',
    algorithm: 'proprietary-wrapper-v2', observed_at: minutesAgo(25), created_at: minutesAgo(25),
  },
  // Post-cutover evidence for the Payment API migration (below).
  {
    ...baseEvent, id: 'e-post', asset_id: 'a-pay', asset_name: 'Payment API', event_type: 'jwt_sign', operation_type: 'signing',
    algorithm: 'ML-DSA-65', is_pqc: true, observed_at: minutesAgo(2), created_at: minutesAgo(2),
    // Secret-shaped metadata that must never reach the browser.
    metadata: { region: 'eu-west-1', private_key: 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ', api_token: 'sk_live_abc123' },
  },
]

const migrationJobs: Row[] = [
  { id: 'j1', asset_id: 'a-pay', name: 'Payment API — ML-DSA cutover', job_type: 'signature', status: 'completed', target_algorithm: 'ML-DSA-65', progress: 100, metadata: { from_algorithm: 'RSA-2048' }, completed_at: minutesAgo(30), updated_at: minutesAgo(30), created_at: daysAgo(5) },
  { id: 'j2', asset_id: 'a-legacy', name: 'Legacy API — hybrid TLS', job_type: 'transport', status: 'completed', target_algorithm: 'X25519MLKEM768', progress: 100, metadata: {}, completed_at: minutesAgo(60), updated_at: minutesAgo(60), created_at: daysAgo(5) },
]

const inputs: RuntimeIntelInputs = {
  snapshot,
  assets: portfolio.assets,
  runtimeEvents,
  migrationJobs,
  scannerAgents: [{ id: 'ag1', name: 'collector-01', status: 'active', last_seen_at: minutesAgo(1) }],
  connectorAccounts: [{ id: 'cn1', provider: 'aws', status: 'connected' }],
  runtimeEventsTruncated: false,
  window: '24h',
  now: NOW,
}

const model = buildRuntimeCryptoIntelligence(inputs)

/* ------------------------------------------------------------------ */
/* 1. Runtime means runtime                                            */
/* ------------------------------------------------------------------ */
console.log('\n1. Runtime evidence is never substituted')
{
  const empty = buildRuntimeCryptoIntelligence({ ...inputs, runtimeEvents: [] })
  assert(empty.telemetry.mode === 'none', 'no runtime events ⇒ telemetry mode "none"', empty.telemetry.mode)
  assert(empty.securityStatus.score === null, 'no runtime evidence ⇒ NO score published', String(empty.securityStatus.score))
  assert(empty.kpis.quantumSafePct === null, 'unmeasured percentages are null, not 0', String(empty.kpis.quantumSafePct))
  assert(empty.events.length === 0 && empty.issues.length === 0, 'no fabricated events or issues')
  assert(empty.discovery.assetsAssessed === 4, 'discovery facts still offered, labelled as discovery', String(empty.discovery.assetsAssessed))
}

/* ------------------------------------------------------------------ */
/* 1b. "Never configured" and "configured but silent" are different    */
/* ------------------------------------------------------------------ */
console.log('\n1b. The empty state distinguishes a MISSING pipeline from a BROKEN one')
{
  // Nothing enrolled at all: the user must deploy a collector.
  const nothing = buildRuntimeCryptoIntelligence({ ...inputs, runtimeEvents: [], scannerAgents: [], connectorAccounts: [] })
  assert(nothing.telemetry.collectorState === 'none', 'no agent and no connector ⇒ collectorState "none"', nothing.telemetry.collectorState)
  assert(/no collector configured/i.test(nothing.sophia.headline), 'Sophia says no collector is configured', nothing.sophia.headline)
  assert(/enrol a collector|connect a cloud provider/i.test(nothing.sophia.recommendation), 'and tells the user to enrol one')

  // A collector IS enrolled but has never reported: telling this user to
  // "connect a telemetry source" sends them to install a second broken agent.
  const silent = buildRuntimeCryptoIntelligence({ ...inputs, runtimeEvents: [] })
  assert(silent.telemetry.collectorState === 'registered-silent', 'an enrolled collector with no events ⇒ "registered-silent"', silent.telemetry.collectorState)
  assert(silent.telemetry.totalAgents > 0, 'and the agent count is reported', String(silent.telemetry.totalAgents))
  assert(/enrolled but silent/i.test(silent.sophia.headline), 'Sophia says the collector is silent, not missing', silent.sophia.headline)
  assert(/check the collector/i.test(silent.sophia.recommendation), 'and tells the user to DIAGNOSE it, not deploy another', silent.sophia.recommendation.slice(0, 40))
  assert(
    !/enrol a collector/i.test(silent.sophia.recommendation),
    'never advises enrolling another collector when one already exists',
  )

  // Reporting normally.
  assert(model.telemetry.collectorState === 'reporting', 'with events flowing the state is "reporting"', model.telemetry.collectorState)
  assert(nothing.sophia.headline !== silent.sophia.headline, 'the two empty states never render the same advice')
}

/* ------------------------------------------------------------------ */
/* 2-4. Classification of the risk-bearing primitive                   */
/* ------------------------------------------------------------------ */
console.log('\n2-4. The verdict comes from the risk-bearing primitive')
{
  const byId = new Map(model.events.map((event) => [event.id, event]))
  const pay = byId.get('e1')!
  assert(pay.quantumStatus === 'hybrid', 'TLS 1.3 + X25519MLKEM768 reads as HYBRID', pay.quantumStatus)
  assert(pay.technical.keyExchange === 'X25519MLKEM768', 'key exchange taken from its own column, not the suite name', String(pay.technical.keyExchange))
  assert(pay.technical.bulkCipher === 'AES-256-GCM', 'bulk cipher still decomposed for the technical panel', String(pay.technical.bulkCipher))

  const aes = byId.get('e-aes')!
  assert(aes.quantumStatus === 'safe', 'AES-256-GCM alone is quantum SAFE, never vulnerable', aes.quantumStatus)
  assert(aes.risk === 'low', 'a safe primitive is never a high-severity runtime risk', aes.risk)

  const legacy = model.events.find((event) => event.assetName === 'Legacy API')!
  assert(legacy.quantumStatus === 'vulnerable', 'X25519 alone is classical ⇒ vulnerable', legacy.quantumStatus)

  const unknown = byId.get('e-unknown')!
  assert(unknown.quantumStatus === 'unknown', 'an undecodable primitive is UNKNOWN', unknown.quantumStatus)
  assert(unknown.statusLabel === 'Needs Review', 'unknown never renders as safe', unknown.statusLabel)

  const dsa = byId.get('e2')!
  assert(dsa.quantumStatus === 'safe', 'ML-DSA-65 is a post-quantum signature ⇒ safe', dsa.quantumStatus)

  // Direct engine probe: an RSA cipher suite must be judged on RSA, not AES.
  const rsaSuite = decomposeRuntimeEvent({ cipher_suite: 'TLS_RSA_WITH_AES_256_GCM_SHA384' })
  assert(rsaSuite.status === 'vulnerable', 'TLS_RSA_WITH_AES_256_GCM is vulnerable via RSA key transport', rsaSuite.status)
  assert(/RSA/i.test(rsaSuite.family), 'the family names RSA, not AES-256-GCM', rsaSuite.family)
}

/* ------------------------------------------------------------------ */
/* 5. The mix reconciles                                               */
/* ------------------------------------------------------------------ */
console.log('\n5. The runtime mix reconciles')
{
  const counts = model.securityStatus.mix.reduce((sum, row) => sum + row.count, 0)
  const percents = model.securityStatus.mix.reduce((sum, row) => sum + row.percent, 0)
  assert(counts === model.kpis.activity, 'mix bucket counts sum to the observation total', `${counts} vs ${model.kpis.activity}`)
  assert(percents === 100, 'mix percentages sum to exactly 100', String(percents))
  assert(model.kpis.activity === runtimeEvents.length, 'activity counts every observation in the window', `${model.kpis.activity} vs ${runtimeEvents.length}`)
  assert(
    model.securityStatus.score !== null && model.securityStatus.score >= 0 && model.securityStatus.score <= 100,
    'score is bounded to [0,100]',
    String(model.securityStatus.score),
  )
}

/* ------------------------------------------------------------------ */
/* 6. Findings aggregate per asset + primitive                         */
/* ------------------------------------------------------------------ */
console.log('\n6. Findings aggregate, they do not multiply')
{
  const legacyIssues = model.issues.filter((issue) => issue.assetName === 'Legacy API' && issue.kind === 'quantum-vulnerable')
  assert(legacyIssues.length === 1, 'four X25519 observations on one asset ⇒ ONE issue', String(legacyIssues.length))
  assert(legacyIssues[0].observations === 4, 'the issue records all four observations', String(legacyIssues[0].observations))
  assert(model.kpis.activeIssues === model.issues.length, 'the Active Issues KPI equals the findings list', `${model.kpis.activeIssues} vs ${model.issues.length}`)
  assert(model.attention.length <= 5, 'Attention Required shows at most the top 5', String(model.attention.length))
  assert(
    model.attention.every((issue, index) => index === 0 || model.attention[index - 1].riskScore >= issue.riskScore),
    'Attention Required is ordered by impact-weighted priority',
  )
}

/* ------------------------------------------------------------------ */
/* 7. Impact-weighted prioritisation                                   */
/* ------------------------------------------------------------------ */
console.log('\n7. The same algorithm ranks by business impact')
{
  const legacy = model.issues.find((issue) => issue.assetName === 'Legacy API' && issue.kind === 'quantum-vulnerable')!
  const dev = model.issues.find((issue) => issue.assetName === 'Dev Sandbox' && issue.kind === 'quantum-vulnerable')!
  assert(Boolean(legacy && dev), 'both X25519 findings exist')
  assert(legacy.riskScore > dev.riskScore, 'X25519 on production outranks X25519 on the dev sandbox', `${legacy.riskScore} vs ${dev.riskScore}`)
  assert(legacy.priorityFactors.length > 0, 'the ranking publishes its weighting factors', String(legacy.priorityFactors.length))
  assert(
    legacy.priorityFactors.every((factor) => typeof factor.contribution === 'number' && Number.isFinite(factor.contribution)),
    'every factor carries a finite, explainable contribution',
  )
}

/* ------------------------------------------------------------------ */
/* 8. Migration verification is evidence-gated                         */
/* ------------------------------------------------------------------ */
console.log('\n8. Migration verification never claims what it cannot show')
{
  const pay = model.migrationVerification.find((row) => row.assetId === 'a-pay')!
  const legacy = model.migrationVerification.find((row) => row.assetId === 'a-legacy')!
  assert(pay.status === 'confirmed', 'post-cutover post-quantum observations ⇒ confirmed', pay.status)
  assert(pay.sessionsVerified > 0, 'confirmation is backed by a real observation count', String(pay.sessionsVerified))
  assert(pay.before === 'RSA-2048', 'the "before" algorithm comes from the job record', String(pay.before))
  assert(legacy.status === 'fallback-detected', 'classical traffic after cutover ⇒ fallback detected, not success', legacy.status)
  assert(legacy.fallbacks === 4, 'every post-cutover classical observation is counted', String(legacy.fallbacks))
  assert(
    !model.migrationVerification.some((row) => row.status === 'confirmed' && row.sessionsVerified === 0),
    'no migration is ever confirmed with zero runtime evidence',
  )
}

/* ------------------------------------------------------------------ */
/* 9. Expected vs actual                                               */
/* ------------------------------------------------------------------ */
console.log('\n9. Expected vs actual reports only what was observed')
{
  const legacy = model.configurations.find((row) => row.assetName === 'Legacy API')!
  assert(legacy.status === 'drift', 'TLS 1.2 + X25519 against a hybrid baseline ⇒ drift', legacy.status)
  assert(legacy.baselineSource === 'migration-target', 'the tenant\'s own approved target is the baseline', legacy.baselineSource)

  const pay = model.configurations.find((row) => row.assetName === 'Payment API')!
  assert(pay.lines.every((line) => line.match !== 'match' || line.actual !== null), 'a "match" verdict always cites an observed value')
  assert(
    model.configurations.every((config) => config.status !== 'matching' || config.lines.every((line) => line.match === 'match')),
    'MATCHING is only published when every line actually matched',
  )
  const driftIssue = model.issues.find((issue) => issue.kind === 'configuration-drift' && issue.assetName === 'Legacy API')
  assert(Boolean(driftIssue), 'configuration drift surfaces as an actionable finding')
}

/* ------------------------------------------------------------------ */
/* 10. Sophia                                                          */
/* ------------------------------------------------------------------ */
console.log('\n10. Sophia states only what the evidence supports')
{
  assert(model.sophia.hasFinding, 'with open findings Sophia reports findings')
  assert(model.sophia.evidence.length > 0, 'every insight ships its evidence', String(model.sophia.evidence.length))
  assert(model.sophia.headline.includes(String(model.issues.length)), 'the headline count matches the findings list', model.sophia.headline)

  const empty = buildRuntimeCryptoIntelligence({ ...inputs, runtimeEvents: [] })
  assert(!empty.sophia.hasFinding, 'with no telemetry Sophia claims no findings')
  // The wording differs per collector state (missing pipeline vs broken one),
  // so assert the SUBSTANCE: she cites the zero-row evidence and never claims
  // to know what is executing.
  assert(
    empty.sophia.evidence.some((line) => /runtime_crypto_events: 0/.test(line)),
    'and cites the zero-row evidence directly',
    empty.sophia.evidence[0],
  )
  assert(
    /never sent|not delivering|no way to observe/i.test(empty.sophia.body),
    'stating plainly that nothing is being observed at runtime',
    empty.sophia.body.slice(0, 60),
  )
}

/* ------------------------------------------------------------------ */
/* 11. Privacy                                                         */
/* ------------------------------------------------------------------ */
console.log('\n11. Secrets never reach the payload')
{
  const serialised = JSON.stringify(model)
  assert(!serialised.includes('MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ'), 'private key material is not serialised')
  assert(!serialised.includes('sk_live_abc123'), 'API tokens are not serialised')

  const post = model.events.find((event) => event.id === 'e-post')!
  const redacted = post.technical.attributes.filter((attribute) => attribute.value === 'REDACTED')
  assert(redacted.length === 2, 'both secret-shaped attributes are redacted by name', String(redacted.length))
  assert(
    post.technical.attributes.some((attribute) => attribute.value === 'eu-west-1'),
    'benign collector metadata is still shown',
  )
}

/* ------------------------------------------------------------------ */
/* 12. Trend claims are withheld without full evidence                 */
/* ------------------------------------------------------------------ */
console.log('\n12. Adoption trend is only claimed when it can be measured')
{
  assert(model.pqcAdoption.trend === null, 'no prior-month observations ⇒ no trend claim')

  const withHistory = buildRuntimeCryptoIntelligence({
    ...inputs,
    runtimeEvents: [
      ...runtimeEvents,
      { ...baseEvent, id: 'old-1', asset_id: 'a-legacy', asset_name: 'Legacy API', event_type: 'tls_handshake', operation_type: 'key_exchange', key_exchange_algorithm: 'X25519', observed_at: daysAgo(45), created_at: daysAgo(45) },
      { ...baseEvent, id: 'old-2', asset_id: 'a-legacy', asset_name: 'Legacy API', event_type: 'tls_handshake', operation_type: 'key_exchange', key_exchange_algorithm: 'X25519', observed_at: daysAgo(50), created_at: daysAgo(50) },
    ],
  })
  assert(withHistory.pqcAdoption.trend !== null, 'with both windows populated a trend IS published')
  assert(
    withHistory.pqcAdoption.trend !== null && withHistory.pqcAdoption.trend.deltaPct > 0,
    'the delta reflects the real improvement',
    String(withHistory.pqcAdoption.trend?.deltaPct),
  )

  const truncated = buildRuntimeCryptoIntelligence({
    ...inputs,
    runtimeEventsTruncated: true,
    runtimeEvents: [
      ...runtimeEvents,
      { ...baseEvent, id: 'old-1', asset_id: 'a-legacy', asset_name: 'Legacy API', event_type: 'tls_handshake', operation_type: 'key_exchange', key_exchange_algorithm: 'X25519', observed_at: daysAgo(45), created_at: daysAgo(45) },
    ],
  })
  assert(truncated.pqcAdoption.trend === null, 'a truncated row set suppresses the trend claim')
}

/* ------------------------------------------------------------------ */
/* 13. Cross-module alignment                                          */
/* ------------------------------------------------------------------ */
console.log('\n13. Estate-wide figures are read, never re-derived')
{
  assert(model.pqcAdoption.estateAdoptionPct === snapshot.scores.pqcAdoption, 'PQC adoption mirrors the Quantum Readiness snapshot')
  assert(model.quantumRisk.score === snapshot.scores.quantumRisk, 'quantum risk mirrors the snapshot')
  assert(model.quantumRisk.level === snapshot.scores.quantumRiskLevel, 'quantum risk level mirrors the snapshot')
  assert(model.hndl.score === snapshot.scores.hndlRisk, 'HNDL risk mirrors the snapshot')
  assert(model.hndl.level === snapshot.scores.hndlRiskLevel, 'HNDL level mirrors the snapshot')

  const assetsWithFindings = model.quantumRisk.breakdown.reduce((sum, row) => sum + row.count, 0)
  assert(assetsWithFindings === model.telemetry.coveredAssets, 'the risk breakdown covers every observed asset exactly once', `${assetsWithFindings} vs ${model.telemetry.coveredAssets}`)

  assert(model.hndl.highRiskAssets > 0, 'classical key agreement at runtime is HNDL exposure', String(model.hndl.highRiskAssets))
  assert(
    model.hndl.topAsset?.name === 'Legacy API' || model.hndl.topAsset?.name === 'Dev Sandbox',
    'the highest-risk HNDL asset is one with a classical key exchange',
    String(model.hndl.topAsset?.name),
  )
}

/* ------------------------------------------------------------------ */
/* 14. Window scoping                                                  */
/* ------------------------------------------------------------------ */
console.log('\n14. The time window scopes every runtime figure')
{
  const narrow = buildRuntimeCryptoIntelligence({ ...inputs, window: '15m' })
  assert(narrow.kpis.activity < model.kpis.activity, '15-minute window observes fewer events than 24 hours', `${narrow.kpis.activity} vs ${model.kpis.activity}`)
  assert(narrow.window.key === '15m', 'the payload states the window it was computed for', narrow.window.key)

  const stale = buildRuntimeCryptoIntelligence({
    ...inputs,
    runtimeEvents: [{ ...baseEvent, id: 'stale', asset_id: 'a-pay', asset_name: 'Payment API', event_type: 'tls_handshake', algorithm: 'RSA-2048', observed_at: daysAgo(10), created_at: daysAgo(10) }],
    window: '24h',
  })
  assert(stale.telemetry.windowEmpty, 'telemetry that exists but predates the window is flagged, not hidden')
  assert(stale.securityStatus.score === null, 'an empty window publishes no score rather than 0')
}

console.log(`\n${failures === 0 ? '✓ All runtime cryptographic intelligence invariants hold.' : `✗ ${failures} invariant(s) FAILED.`}`)
process.exit(failures === 0 ? 0 : 1)
