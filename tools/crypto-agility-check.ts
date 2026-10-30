/**
 * Crypto Agility Intelligence Engine — offline invariant check.
 *
 * Exercises the PURE isomorphic engine (no Supabase / server required) against a
 * small but realistic tenant fixture and asserts the guarantees the Crypto
 * Agility Command Center depends on:
 *
 *   1. Asset facts are inherited from the SHARED asset-intelligence engine, so
 *      an asset can never read differently here than on any other page.
 *   2. A domain with no evidence scores `null` and is EXCLUDED from the weighted
 *      mean (weights renormalised) — never coerced to 0.
 *   3. `unknown` never resolves to `agile`, and an asset with no evidence has no
 *      agility score at all.
 *   4. Replaceability is the WORST binding constraint (vendor > architecture >
 *      code > library > configuration), both per asset and per matrix row.
 *   5. Coupling findings never bleed between assets.
 *   6. The policy engine flags the mandatory-stack violations that are really
 *      present, and only those.
 *   7. The blocker penalty is bounded and the headline score stays in [0,100].
 *   8. Distribution buckets reconcile exactly with the asset roll-up.
 *   9. Assessment history's final point is the LIVE score and is not labelled
 *      reconstructed.
 *  10. The change-impact preview projects real dependencies and never claims to
 *      have simulated.
 *
 * Run: npx tsx tools/crypto-agility-check.ts
 */

import { buildAssetPortfolio, type Row } from '../src/lib/migration/asset-intelligence'
import {
  buildCryptoAgilityIntelligence,
  deriveAgilityDerivations,
  previewChangeImpact,
  AGILITY_DOMAINS,
  type AgilityInputs,
} from '../src/lib/crypto-agility/agility-intelligence'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

/* ------------------------------------------------------------------ */
/* Fixture: a tenant with one of every agility archetype               */
/* ------------------------------------------------------------------ */

const NOW = Date.parse('2026-08-10T00:00:00Z')

const assets: Row[] = [
  // a1 — cryptography embedded in source ⇒ RIGID (code modification)
  { id: 'a1', name: 'checkout-api', type: 'api', environment: 'production', service_owner: 'Payments Platform', criticality: 'critical', metadata: {}, created_at: '2026-01-05T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
  // a2 — fully managed, TLS 1.3 + hybrid, managed CA ⇒ AGILE
  { id: 'a2', name: 'edge.company.com', type: 'web-service', environment: 'production', service_owner: 'Platform Team', criticality: 'high', metadata: { hostname: 'edge.company.com' }, created_at: '2026-01-05T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
  // a3 — deprecated provider ⇒ CONDITIONAL (library upgrade)
  { id: 'a3', name: 'reporting-worker', type: 'service', environment: 'staging', service_owner: 'Data Platform', criticality: 'medium', metadata: {}, created_at: '2026-02-05T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
  // a4 — discovered but never assessed ⇒ UNKNOWN
  { id: 'a4', name: 'legacy-batch', type: 'server', environment: 'development', service_owner: 'Unassigned', metadata: {}, created_at: '2026-03-05T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
]

const cryptoInventory: Row[] = [
  // Code-located ⇒ hard-coded algorithm coupling on a1.
  { id: 'c1', asset_id: 'a1', item_type: 'algorithm', name: 'payment signing', algorithm: 'RSA-2048', key_size: 2048, protocol: 'TLS 1.2', is_vulnerable: true, metadata: { file: 'src/payments/sign.ts', line: 42 }, discovered_at: '2026-04-01T00:00:00Z', created_at: '2026-04-01T00:00:00Z' },
  { id: 'c2', asset_id: 'a1', item_type: 'algorithm', name: 'legacy hash', algorithm: 'SHA-1', is_vulnerable: true, metadata: {}, discovered_at: '2026-04-01T00:00:00Z', created_at: '2026-04-01T00:00:00Z' },
  // Config-driven, already hybrid on a2.
  { id: 'c3', asset_id: 'a2', item_type: 'protocol', name: 'edge tls', algorithm: 'X25519MLKEM768', protocol: 'TLS 1.3', is_quantum_safe: true, metadata: {}, discovered_at: '2026-05-01T00:00:00Z', created_at: '2026-05-01T00:00:00Z' },
  { id: 'c4', asset_id: 'a2', item_type: 'algorithm', name: 'edge signing', algorithm: 'ML-DSA-65', is_quantum_safe: true, metadata: {}, discovered_at: '2026-05-01T00:00:00Z', created_at: '2026-05-01T00:00:00Z' },
  // Deprecated provider on a3.
  { id: 'c5', asset_id: 'a3', item_type: 'library', name: 'OpenSSL 1.1.1', algorithm: 'RSA-3072', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
  { id: 'c6', asset_id: 'a3', item_type: 'algorithm', name: 'aes', algorithm: 'AES-128', is_vulnerable: false, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
]

const cryptoExposures: Row[] = [
  { id: 'e1', asset_id: 'a1', exposure_type: 'weak_tls', severity: 'high', description: 'TLS 1.2 with classical key exchange', detected_value: 'TLS 1.2', metadata: {}, created_at: '2026-07-01T00:00:00Z' },
  { id: 'e2', asset_id: 'a3', exposure_type: 'deprecated_lib', severity: 'high', description: 'OpenSSL 1.1.1 reached end of life', detected_value: 'OpenSSL 1.1.1', metadata: {}, created_at: '2026-07-01T00:00:00Z' },
]

const scanResults: Row[] = [
  { id: 's1', asset_id: 'a1', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Quantum-vulnerable signing key', created_at: '2026-07-15T00:00:00Z' },
  { id: 's2', asset_id: 'a3', algorithm: 'RSA-3072', threat_level: 'medium', description: 'Classical key transport', created_at: '2026-07-15T00:00:00Z' },
]

const certificates: Row[] = [
  // Self-signed ⇒ static trust anchor coupling on a1.
  { id: 'x1', asset_id: 'a1', name: 'checkout-internal', subject: 'checkout-internal', algorithm: 'RSA-2048', key_size: 2048, issuer: 'checkout-internal', not_after: '2026-12-01T00:00:00Z', is_quantum_safe: false, status: 'active', created_at: '2026-04-01T00:00:00Z' },
  // Managed issuer ⇒ certificate automation evidence on a2.
  { id: 'x2', asset_id: 'a2', name: 'edge.company.com', subject: 'edge.company.com', algorithm: 'ML-DSA-65', issuer: "Let's Encrypt", not_after: '2027-02-01T00:00:00Z', is_quantum_safe: true, status: 'active', created_at: '2026-05-01T00:00:00Z' },
]

const runtimeEvents: Row[] = [
  { id: 'r1', asset_id: 'a1', asset_name: 'checkout-api', algorithm: 'RSA-2048', key_exchange_algorithm: 'ECDHE-RSA', cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', protocol: 'TLS 1.2', severity: 'high', risk_score: 72, is_legacy: true, hndl_risk: true, observed_at: '2026-08-05T00:00:00Z', created_at: '2026-08-05T00:00:00Z' },
  { id: 'r2', asset_id: 'a2', asset_name: 'edge.company.com', algorithm: 'ML-KEM-768', key_exchange_algorithm: 'X25519MLKEM768', protocol: 'TLS 1.3', severity: 'low', risk_score: 4, is_pqc: true, observed_at: '2026-08-05T00:00:00Z', created_at: '2026-08-05T00:00:00Z' },
]

const relationships: Row[] = [
  { id: 'rel1', source_asset_id: 'a1', target_asset_id: 'a3', relationship_type: 'calls' },
  { id: 'rel2', source_asset_id: 'a2', target_asset_id: 'a1', relationship_type: 'proxies' },
]

const migrationJobs: Row[] = [
  { id: 'j1', asset_id: 'a3', name: 'reporting tls migration', job_type: 'tls_migration', status: 'running', target_algorithm: 'ML-KEM-768', progress: 35, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-06T00:00:00Z' },
]

const portfolio = buildAssetPortfolio({
  assets,
  cryptoInventory,
  scanResults,
  cryptoExposures,
  certificates,
  runtimeEvents,
  relationships,
  migrationJobs,
  validationLogs: [],
  complianceEvidence: [],
  now: NOW,
})

const inputs: AgilityInputs = {
  assets: portfolio.assets,
  portfolioSummary: portfolio.summary,
  snapshot: {
    hasData: true,
    lastAssessmentAt: '2026-08-05T00:00:00Z',
    scores: { quantumReadiness: 48, pqcAdoption: 33, quantumRisk: 61, hndlRisk: 55 },
    inventory: {
      assetsAssessed: 4,
      cryptoComponents: cryptoInventory.length,
      vulnerableComponents: 4,
      pqcReadyComponents: 2,
      certificatesAnalyzed: certificates.length,
      keysDiscovered: 0,
      trustRelationships: relationships.length,
      cloudAccounts: 0,
      domainsScanned: 2,
    },
    sharedResponsibility: null,
  },
  cryptoInventory,
  cryptoExposures,
  certificates,
  runtimeEvents,
  generatedKeys: [],
  migrationJobs,
  scanSessions: [{ id: 'sess1', status: 'completed', findings_count: 4, completed_at: '2026-08-05T00:00:00Z', created_at: '2026-08-05T00:00:00Z' }],
  securityEvents: [],
  connectorAccounts: [],
  relationships,
  policyExceptions: [],
  now: NOW,
}

function main() {
  const intel = buildCryptoAgilityIntelligence(inputs)
  const byId = new Map(intel.assets.map((a) => [a.id, a]))
  const a1 = byId.get('a1')!
  const a2 = byId.get('a2')!
  const a3 = byId.get('a3')!
  const a4 = byId.get('a4')!

  /* ---------------------------------------------------------------- */
  console.log('\n[1] Asset facts are inherited from the shared asset engine')
  const portfolioById = new Map(portfolio.assets.map((a) => [a.id, a]))
  assert(intel.assets.length === portfolio.assets.length, 'every portfolio asset appears exactly once', `${intel.assets.length} vs ${portfolio.assets.length}`)
  assert(
    intel.assets.every((row) => row.riskScore === portfolioById.get(row.id)!.riskScore),
    'risk scores are NOT re-derived (identical to the shared engine)',
  )
  assert(
    intel.assets.every((row) => row.dependencies === portfolioById.get(row.id)!.blastRadius),
    'dependency counts come from the shared blast-radius model',
  )

  /* ---------------------------------------------------------------- */
  console.log('\n[2] Unmeasured domains score null and are excluded, never zero')
  const unmeasured = intel.domains.filter((d) => d.score === null)
  assert(unmeasured.length > 0, 'the fixture leaves at least one domain unmeasured', unmeasured.map((d) => d.key).join(', ') || 'none')
  assert(unmeasured.every((d) => d.basis.startsWith('Evidence Not Available')), 'unmeasured domains say Evidence Not Available')
  assert(unmeasured.every((d) => d.confidence === 'none'), 'unmeasured domains carry no confidence')
  assert(unmeasured.every((d) => d.improvementOpportunity === 0), 'unmeasured domains claim no improvement opportunity')

  const scored = intel.domains.filter((d) => d.score !== null)
  const scoredWeight = scored.reduce((sum, d) => sum + d.weight, 0)
  assert(intel.score.scoredWeight === scoredWeight, 'reported scoredWeight equals the measured domain weight', `${intel.score.scoredWeight} vs ${scoredWeight}`)
  assert(scoredWeight < 100, 'the measured weight is genuinely below 100 (renormalisation is exercised)', `${scoredWeight}%`)

  const expected = Math.round(
    Math.max(0, Math.min(100, scored.reduce((sum, d) => sum + (d.score as number) * d.weight, 0) / scoredWeight - intel.score.blockerPenalty)),
  )
  assert(intel.score.agilityScore === expected, 'headline score = renormalised weighted mean − blocker penalty', `${intel.score.agilityScore} vs ${expected}`)

  const totalWeight = AGILITY_DOMAINS.reduce((sum, d) => sum + d.weight, 0)
  assert(totalWeight === 100, 'domain weights sum to 100', String(totalWeight))

  // The renormalisation must MATTER: scoring the unmeasured domains as 0 would
  // produce a materially different (lower) number.
  const naive = Math.round(scored.reduce((sum, d) => sum + (d.score as number) * d.weight, 0) / 100)
  assert(naive < (intel.score.agilityScore as number), 'treating unmeasured domains as 0 would understate the score', `naive ${naive} vs published ${intel.score.agilityScore}`)

  /* ---------------------------------------------------------------- */
  console.log('\n[3] Unknown is never agile; no evidence means no score')
  assert(a4.agilityState === 'unknown', 'the unassessed asset is Unknown', a4.agilityState)
  assert(a4.agilityScore === null, 'the unassessed asset has NO agility score (not 0)', String(a4.agilityScore))
  assert(a4.readiness === 'unknown', 'its migration readiness is Unknown', a4.readiness)
  assert(a4.replaceability === 'unknown', 'its replaceability is Unknown', a4.replaceability)
  assert(!intel.assets.some((r) => !r.hasEvidence && r.agilityState === 'agile'), 'no evidence-free asset is ever classified Agile')

  /* ---------------------------------------------------------------- */
  console.log('\n[4] Replaceability is the worst binding constraint')
  assert(a1.replaceability === 'code' || a1.replaceability === 'architecture', 'source-embedded crypto forces code/architecture change', a1.replaceability)
  assert(a1.agilityState === 'rigid' || a1.agilityState === 'blocked', 'that asset is Rigid or Blocked, never Agile', a1.agilityState)
  assert(a2.replaceability === 'configuration', 'the managed, hybrid, TLS 1.3 asset is configuration-replaceable', a2.replaceability)
  assert(a2.agilityState === 'agile' || a2.agilityState === 'conditional', 'the managed asset is Agile/Conditional', a2.agilityState)
  assert(a3.replaceability === 'library', 'the deprecated-provider asset needs a library upgrade', a3.replaceability)

  const rsaRow = intel.replaceability.find((r) => r.currentAlgorithm === 'RSA-2048')
  assert(Boolean(rsaRow), 'RSA-2048 appears in the replaceability matrix')
  if (rsaRow) {
    assert(/ML-DSA|ML-KEM/.test(rsaRow.proposedReplacement), 'RSA-2048 maps to an ML-DSA/ML-KEM target', rsaRow.proposedReplacement)
    assert(rsaRow.replaceability === a1.replaceability, 'the row adopts the hardest per-asset verdict', `${rsaRow.replaceability} vs ${a1.replaceability}`)
    assert(rsaRow.status !== 'agile', 'a code-bound algorithm is not reported as Agile', rsaRow.status)
  }
  const pqcRow = intel.replaceability.find((r) => r.currentAlgorithm === 'ML-DSA-65')
  assert(Boolean(pqcRow) && pqcRow!.status === 'agile', 'an already-PQC primitive reads Agile', pqcRow?.status ?? 'missing')

  /* ---------------------------------------------------------------- */
  console.log('\n[5] Coupling findings never bleed between assets')
  const a1Findings = intel.coupling.filter((c) => c.assetId === 'a1')
  const a2Findings = intel.coupling.filter((c) => c.assetId === 'a2')
  assert(a1Findings.some((c) => c.type === 'hardcoded-algorithm'), 'a1 carries the hard-coded algorithm finding')
  assert(a1Findings.some((c) => c.type === 'static-trust-anchor'), 'a1 carries the self-signed trust-anchor finding')
  assert(!a2Findings.some((c) => c.type === 'hardcoded-algorithm'), 'a2 does NOT inherit a1 coupling')
  assert(
    a1Findings.every((c) => c.evidence.includes('RSA-2048') || c.evidence.includes('checkout') || c.evidence.includes('TLS')),
    'every a1 finding cites a1 evidence only',
  )
  assert(
    intel.coupling.every((c) => c.evidence.length > 0 && c.evidenceSource.length > 0),
    'every coupling finding cites real evidence and its source',
  )
  const libFinding = intel.coupling.find((c) => c.type === 'legacy-crypto-provider')
  assert(Boolean(libFinding) && libFinding!.assetId === 'a3', 'the deprecated provider is attributed to a3', libFinding?.assetId ?? 'missing')

  /* ---------------------------------------------------------------- */
  console.log('\n[6] Policy evaluation flags exactly what is present')
  const violated = new Set(intel.policy.violations.map((v) => v.ruleId))
  assert(violated.has('pol-rsa'), 'RSA 2048 raises the WARN rule (pol-rsa: RSA 2048-bit and above)')
  assert(violated.has('pol-broken-hash'), 'SHA-1 raises the BLOCK rule')
  assert(violated.has('pol-aes128'), 'AES-128 raises the WARN rule')
  assert(violated.has('pol-tls12'), 'TLS 1.2 raises the transport WARN rule')
  assert(!violated.has('pol-rsa-weak'), 'no sub-2048 RSA is reported (none exists in the fixture)')
  assert(intel.policy.compliancePct !== null && intel.policy.compliancePct >= 0 && intel.policy.compliancePct <= 100, 'compliance is a real percentage', String(intel.policy.compliancePct))
  assert(intel.policy.evaluatedInstances > 0, 'policy evaluation covered real compliance units', String(intel.policy.evaluatedInstances))
  // The contradiction guard: a page must never read "100% compliant" beside a
  // list of violated rules.
  assert(
    !(intel.policy.compliancePct === 100 && intel.policy.violations.length > 0),
    'compliance never reads 100% while rules are violated',
    `${intel.policy.compliancePct}% with ${intel.policy.violations.length} violation(s)`,
  )

  /* ---------------------------------------------------------------- */
  console.log('\n[7] Score and penalty stay bounded')
  const score = intel.score.agilityScore
  assert(score !== null && score >= 0 && score <= 100, 'the headline score is within [0,100]', String(score))
  assert(intel.score.blockerPenalty >= 0 && intel.score.blockerPenalty <= 18, 'the blocker penalty is bounded at 18', String(intel.score.blockerPenalty))
  assert(
    intel.domains.every((d) => d.score === null || (d.score >= 0 && d.score <= 100)),
    'every measured domain score is within [0,100]',
  )
  assert(
    intel.assets.every((r) => r.agilityScore === null || (r.agilityScore >= 0 && r.agilityScore <= 100)),
    'every per-asset score is within [0,100]',
  )

  /* ---------------------------------------------------------------- */
  console.log('\n[8] Distribution and readiness reconcile exactly')
  const distributionTotal = intel.distribution.reduce((sum, b) => sum + b.count, 0)
  assert(distributionTotal === intel.assets.length, 'distribution buckets sum to the asset count', `${distributionTotal} vs ${intel.assets.length}`)
  for (const bucket of intel.distribution) {
    const actual = intel.assets.filter((r) => r.agilityState === bucket.state).length
    assert(bucket.count === actual, `bucket ${bucket.state} matches the asset roll-up`, `${bucket.count} vs ${actual}`)
  }
  const readinessTotal = intel.readiness.ready + intel.readiness.conditional + intel.readiness.blocked + intel.readiness.unknown
  assert(readinessTotal === intel.assets.length, 'readiness buckets sum to the asset count', `${readinessTotal} vs ${intel.assets.length}`)
  assert(intel.score.assetsEvaluated === intel.assets.filter((r) => r.hasEvidence).length, 'assetsEvaluated counts evidence-bearing assets only')

  const kpiAgile = intel.kpis.find((k) => k.key === 'agile-assets')
  assert(kpiAgile?.numeric === intel.distribution[0].count, 'the Agile KPI matches the distribution bucket', `${kpiAgile?.numeric} vs ${intel.distribution[0].count}`)

  /* ---------------------------------------------------------------- */
  console.log('\n[9] Assessment history never mixes scales')
  assert(intel.history.length >= 2, 'history has at least two points', String(intel.history.length))
  if (intel.history.length) {
    const last = intel.history[intel.history.length - 1]
    assert(last.agilityScore === intel.score.agilityScore, 'the final point carries the LIVE agility score', `${last.agilityScore} vs ${intel.score.agilityScore}`)
    assert(last.reconstructed === false, 'the final point is NOT labelled reconstructed')
    assert(intel.history.slice(0, -1).every((p) => p.reconstructed), 'every earlier point is labelled reconstructed')
    assert(last.assetsEvaluated === intel.score.assetsEvaluated, 'the final point carries the real evaluated-asset count')
    // The scale-mixing defect: a reconstructed point must NEVER carry an agility
    // score, or the drift delta would compare two different models.
    assert(
      intel.history.slice(0, -1).every((p) => p.agilityScore === null),
      'reconstructed points carry NO agility score (no back-filled proxy)',
    )
    assert(
      intel.history.every((p) => p.pqcAdoptionPct !== null && p.vulnerableSharePct !== null),
      'every point carries the component shares that were genuinely measurable',
    )
    assert(
      intel.drift.deltaPoints === null ||
        intel.drift.deltaPoints === (intel.history[intel.history.length - 1].pqcAdoptionPct as number) - (intel.history[intel.history.length - 2].pqcAdoptionPct as number),
      'the drift delta is measured on PQC adoption, not on the agility score',
      String(intel.drift.deltaPoints),
    )
  }

  /* ---------------------------------------------------------------- */
  console.log('\n[10] Change-impact preview projects real dependencies')
  const derivations = deriveAgilityDerivations(inputs)
  const preview = previewChangeImpact(inputs, derivations, 'a1')
  assert(Boolean(preview), 'a preview is produced for a real asset')
  if (preview) {
    assert(preview.assetId === 'a1' && preview.asset === 'checkout-api', 'the preview describes the requested asset')
    assert(preview.dependencies === a1.dependencies, 'dependency count matches the asset row', `${preview.dependencies} vs ${a1.dependencies}`)
    assert(preview.potentialFailures.length > 0, 'at least one potential failure is predicted', String(preview.potentialFailures.length))
    assert(/does not simulate/i.test(preview.basis), 'the preview states it does not simulate')
    assert(preview.migrationRiskScore >= 0 && preview.migrationRiskScore <= 100, 'migration risk is within [0,100]')
  }
  assert(previewChangeImpact(inputs, derivations, 'does-not-exist') === null, 'an unknown asset id yields null (no fabricated preview)')

  /* ---------------------------------------------------------------- */
  console.log('\n[11] Blockers, responsibility and graph stay evidence-bound')
  assert(intel.blockers.length > 0, 'blockers were derived from the fixture', String(intel.blockers.length))
  assert(intel.blockers.every((b) => b.count > 0 && b.basis.length > 0), 'every blocker carries a count and a basis')
  assert(
    intel.blockers.every((b) => b.affectedAssetIds.every((id) => byId.has(id) || id.startsWith('cert:') || id.startsWith('sr:'))),
    'blockers only reference real tenant assets',
  )
  assert(intel.responsibility.every((r) => r.owner.length > 0 && r.userAction.length > 0), 'every responsibility row names an owner and an action')
  assert(
    intel.responsibility.every((r) => ['customer', 'provider', 'ecosystem'].includes(r.controlDomain)),
    'every responsibility row has a valid control domain',
  )
  const graphAssetIds = new Set(intel.graph.nodes.flatMap((n) => n.assetIds))
  assert([...graphAssetIds].every((id) => byId.has(id)), 'graph nodes only reference real tenant assets')
  assert(intel.graph.edges.every((e) => intel.graph.nodes.some((n) => n.id === e.source) && intel.graph.nodes.some((n) => n.id === e.target)), 'every graph edge connects two rendered nodes')
  assert(/projection/i.test(intel.graph.note), 'the graph declares itself a projection of existing data')

  /* ---------------------------------------------------------------- */
  console.log('\n[12] The empty tenant produces no fabricated numbers')
  const emptyIntel = buildCryptoAgilityIntelligence({
    ...inputs,
    assets: [],
    portfolioSummary: { ...portfolio.summary, total: 0 },
    snapshot: {
      ...inputs.snapshot,
      hasData: false,
      sharedResponsibility: null,
      // Mirrors what the router actually serves for a tenant with no evidence.
      inventory: {
        assetsAssessed: 0, cryptoComponents: 0, vulnerableComponents: 0, pqcReadyComponents: 0,
        certificatesAnalyzed: 0, keysDiscovered: 0, trustRelationships: 0, cloudAccounts: 0, domainsScanned: 0,
      },
    },
    cryptoInventory: [],
    cryptoExposures: [],
    certificates: [],
    runtimeEvents: [],
    migrationJobs: [],
    scanSessions: [],
    relationships: [],
  })
  assert(emptyIntel.hasData === false, 'an empty tenant reports hasData=false')
  assert(emptyIntel.score.agilityScore === null, 'no score is published without evidence (not 0)', String(emptyIntel.score.agilityScore))
  assert(emptyIntel.score.migrationReadinessPct === null, 'no migration readiness is published without evidence')
  assert(emptyIntel.policy.compliancePct === null, 'no policy compliance is published without evidence')
  assert(emptyIntel.domains.every((d) => d.score === null), 'no domain is scored without evidence')
  assert(emptyIntel.coupling.length === 0 && emptyIntel.replaceability.length === 0, 'no coupling or replaceability rows are invented')
  assert(emptyIntel.history.length === 0, 'no history is invented')
  assert(emptyIntel.recommendations.some((r) => r.route === '/dashboard/scanner'), 'the empty tenant is told to run a scan')

  /* ---------------------------------------------------------------- */
  console.log('\n[13] Scanner finding titles are never treated as cryptography')
  // Scanners write finding TITLES into the same `algorithm` field as real
  // primitives. A matrix row offering to migrate "Regulatory Compliance Gap" to
  // ML-KEM is nonsense — and "No ML-KEM Support" contains "ML-KEM", so a naive
  // classifier reads a finding that PQC is MISSING as proof it is present.
  const noisyAssets: Row[] = [{ id: 'n1', name: 'noisy.example.com', type: 'web-service', environment: 'production', service_owner: 'Platform', criticality: 'high', metadata: {}, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' }]
  const noisyInventory: Row[] = [
    { id: 'n-c1', asset_id: 'n1', item_type: 'algorithm', name: 'finding', algorithm: 'No ML-KEM Support', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
    { id: 'n-c2', asset_id: 'n1', item_type: 'algorithm', name: 'finding', algorithm: 'Regulatory Compliance Gap', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
    { id: 'n-c3', asset_id: 'n1', item_type: 'algorithm', name: 'finding', algorithm: 'HNDL Risk: High', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
    { id: 'n-c4', asset_id: 'n1', item_type: 'algorithm', name: 'finding', algorithm: 'ECDSA Certificate Detected', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
    { id: 'n-c5', asset_id: 'n1', item_type: 'algorithm', name: 'real', algorithm: 'ecdsa-with-SHA256', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
    { id: 'n-c6', asset_id: 'n1', item_type: 'protocol', name: 'suite', algorithm: 'TLS_RSA_WITH_AES_128_CBC_SHA', protocol: 'TLS 1.2', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
  ]
  const noisyPortfolio = buildAssetPortfolio({
    assets: noisyAssets, cryptoInventory: noisyInventory, scanResults: [], cryptoExposures: [],
    certificates: [], runtimeEvents: [], relationships: [], migrationJobs: [],
    validationLogs: [], complianceEvidence: [], now: NOW,
  })
  const noisyIntel = buildCryptoAgilityIntelligence({
    ...inputs,
    assets: noisyPortfolio.assets,
    portfolioSummary: noisyPortfolio.summary,
    cryptoInventory: noisyInventory,
    cryptoExposures: [], certificates: [], runtimeEvents: [], migrationJobs: [], relationships: [],
  })
  const matrixNames = noisyIntel.replaceability.map((r) => r.currentAlgorithm.toUpperCase())
  assert(!matrixNames.includes('NO ML-KEM SUPPORT'), '"No ML-KEM Support" is NOT offered as a migratable algorithm')
  assert(!matrixNames.includes('REGULATORY COMPLIANCE GAP'), '"Regulatory Compliance Gap" is excluded from the matrix')
  assert(!matrixNames.includes('HNDL RISK: HIGH'), '"HNDL Risk: High" is excluded from the matrix')
  assert(!matrixNames.includes('ECDSA CERTIFICATE DETECTED'), '"ECDSA Certificate Detected" is excluded from the matrix')
  assert(matrixNames.includes('ECDSA-WITH-SHA256'), 'the real primitive ecdsa-with-SHA256 IS in the matrix')
  assert(matrixNames.includes('TLS_RSA_WITH_AES_128_CBC_SHA'), 'a real cipher suite IS in the matrix')
  assert(
    !noisyIntel.replaceability.some((r) => /NO ML-KEM/i.test(r.currentAlgorithm) && r.status === 'agile'),
    'a "PQC is missing" finding is never reported as already quantum-safe',
  )
  assert(
    !noisyIntel.graph.nodes.some((n) => n.layer === 'algorithm' && /gap|risk:|detected|support/i.test(n.label)),
    'finding titles never become algorithm nodes in the graph',
  )
  const algoDomain = noisyIntel.domains.find((d) => d.key === 'algorithm')!
  assert(/finding titles/i.test(algoDomain.basis), 'the algorithm domain discloses how many values it excluded', algoDomain.basis.slice(0, 90))
  const noisyPolicy = noisyIntel.policy
  assert(noisyPolicy.violations.some((v) => v.ruleId === 'pol-tls12'), 'the real TLS 1.2 violation is still detected in noisy data')

  /* ---------------------------------------------------------------- */
  console.log('\n[14] Absence of coupling evidence is never read as decoupling')
  // An edge-scanned asset yields transport + certificate evidence only, so
  // nothing could have revealed hard-coded cryptography inside the application.
  const edgeAssets: Row[] = [{ id: 'edge1', name: 'edge-only.example.com', type: 'web-service', environment: 'production', service_owner: 'Platform', criticality: 'high', metadata: { hostname: 'edge-only.example.com' }, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' }]
  const edgeInventory: Row[] = [
    { id: 'edge-c1', asset_id: 'edge1', item_type: 'algorithm', name: 'sig', algorithm: 'ecdsa-with-SHA256', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
    { id: 'edge-c2', asset_id: 'edge1', item_type: 'protocol', name: 'tls', algorithm: 'TLSv1.3', protocol: 'TLS 1.3', metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
  ]
  const edgeCerts: Row[] = [
    { id: 'edge-x1', asset_id: 'edge1', name: 'edge-only.example.com', subject: 'edge-only.example.com', algorithm: 'ECDSA P-256', issuer: "Let's Encrypt", not_after: '2027-01-01T00:00:00Z', is_quantum_safe: false, status: 'active', created_at: '2026-06-01T00:00:00Z' },
  ]
  const edgePortfolio = buildAssetPortfolio({
    assets: edgeAssets, cryptoInventory: edgeInventory, scanResults: [], cryptoExposures: [],
    certificates: edgeCerts, runtimeEvents: [], relationships: [], migrationJobs: [],
    validationLogs: [], complianceEvidence: [], now: NOW,
  })
  const edgeIntel = buildCryptoAgilityIntelligence({
    ...inputs,
    assets: edgePortfolio.assets, portfolioSummary: edgePortfolio.summary,
    cryptoInventory: edgeInventory, cryptoExposures: [], certificates: edgeCerts,
    runtimeEvents: [], migrationJobs: [], relationships: [],
  })
  const edgeRow = edgeIntel.assets[0]
  assert(edgeRow.couplingAssessed === false, 'an edge-scanned asset is flagged as coupling-not-assessed')
  assert(edgeRow.agilityState !== 'agile', 'it is NOT reported as Agile despite zero coupling findings', edgeRow.agilityState)
  assert(
    edgeRow.blockerReasons.some((r) => /coupling has not been assessed/i.test(r)),
    'the reason says coupling was never assessed',
  )
  assert((edgeRow.agilityScore ?? 0) <= 60, 'its score is capped rather than reading near-perfect', String(edgeRow.agilityScore))
  const edgeAppDomain = edgeIntel.domains.find((d) => d.key === 'application')!
  assert(edgeAppDomain.score === null, 'application agility is unmeasured when no asset has coupling visibility', String(edgeAppDomain.score))
  // ...whereas an asset WITH source visibility is genuinely assessable.
  assert(byId.get('a1')!.couplingAssessed === true, 'a source-scanned asset IS coupling-assessed')

  console.log('\n[15] Deprecated transport recorded as inventory still violates policy')
  const legacyInventory: Row[] = [
    ...edgeInventory,
    { id: 'edge-c3', asset_id: 'edge1', item_type: 'protocol', name: 'tls-legacy', algorithm: 'TLSv1.1', metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
  ]
  const legacyPortfolio = buildAssetPortfolio({
    assets: edgeAssets, cryptoInventory: legacyInventory, scanResults: [], cryptoExposures: [],
    certificates: edgeCerts, runtimeEvents: [], relationships: [], migrationJobs: [],
    validationLogs: [], complianceEvidence: [], now: NOW,
  })
  const legacyIntel = buildCryptoAgilityIntelligence({
    ...inputs,
    assets: legacyPortfolio.assets, portfolioSummary: legacyPortfolio.summary,
    cryptoInventory: legacyInventory, cryptoExposures: [], certificates: edgeCerts,
    runtimeEvents: [], migrationJobs: [], relationships: [],
  })
  assert(
    legacyIntel.policy.violations.some((v) => v.ruleId === 'pol-tls-legacy'),
    'TLS 1.1 recorded as an inventory entry raises the BLOCK rule',
    legacyIntel.policy.violations.map((v) => v.ruleId).join(', ') || 'none',
  )
  const legacyProtocolDomain = legacyIntel.domains.find((d) => d.key === 'protocol')!
  assert(legacyProtocolDomain.blockers > 0, 'the protocol domain counts the deprecated version as a blocker', String(legacyProtocolDomain.blockers))
  assert(
    legacyIntel.blockers.some((b) => b.category === 'legacy-protocol'),
    'a legacy-protocol blocker is published',
  )

  /* ---------------------------------------------------------------- */
  console.log('\n[16] A high score on thin coverage is not published as Agile')
  assert(
    intel.domains.every((d) => !(d.state === 'agile' && (d.confidence === 'low' || d.confidence === 'none'))),
    'no domain reads Agile on low or absent confidence',
    intel.domains.filter((d) => d.state === 'agile').map((d) => `${d.key}:${d.confidence}`).join(', ') || 'none agile',
  )
  const keyDomain = intel.domains.find((d) => d.key === 'key')!
  assert(
    keyDomain.score === null || keyDomain.evidenceCoverage <= 100,
    'key-agility coverage reflects the signal families that carry evidence',
    `${keyDomain.evidenceCoverage}%`,
  )

  /* ---------------------------------------------------------------- */
  console.log('\n[17] Recommendations are bounded and cite evidence')
  assert(intel.recommendations.length > 0 && intel.recommendations.length <= 8, 'recommendations are present and bounded', String(intel.recommendations.length))
  assert(intel.recommendations.every((r) => r.expectedScoreGain === null || (r.expectedScoreGain >= 0 && r.expectedScoreGain <= 100)), 'expected score gains are plausible or withheld (null) when not modelled')
  assert(
    intel.recommendations.every((r) => r.dependencyReductionPct === null || (r.dependencyReductionPct >= 0 && r.dependencyReductionPct <= 100)),
    'dependency-reduction shares are real percentages',
  )
  assert(intel.recommendations.every((r) => r.route.startsWith('/dashboard') || r.route.startsWith('#')), 'every recommendation routes somewhere real')

  /* ---------------------------------------------------------------- */
  console.log('\n[18] Statuses are disjoint, scores traceable, simulations and unreadable sources excluded')
  const statusAlgorithms = intel.algorithmStatus.reduce((sum, s) => sum + s.algorithms, 0)
  assert(statusAlgorithms === intel.replaceability.length, 'every matrix row carries exactly one algorithm status', `${statusAlgorithms} / ${intel.replaceability.length}`)
  const laneAlgorithms = intel.transitions.reduce((sum, lane) => sum + lane.algorithms, 0)
  assert(laneAlgorithms === intel.replaceability.length, 'transition lanes partition the matrix rows', `${laneAlgorithms} / ${intel.replaceability.length}`)
  assert(
    intel.replaceability.every((r) => r.algorithmStatus !== 'approved' || r.observedInOperation),
    'no algorithm is Approved without operational evidence',
  )
  assert(
    !intel.transitions.some((lane) => lane.role === 'signature' && /ML-KEM/.test(lane.target ?? '')),
    'the signature lane never targets ML-KEM',
    intel.transitions.find((l) => l.role === 'signature')?.target ?? 'no signature lane',
  )
  for (const domain of intel.domains.filter((d) => d.score !== null && d.factors.length)) {
    const measured = domain.factors.filter((f) => f.measured)
    const weight = measured.reduce((sum, f) => sum + f.effectiveWeight, 0)
    assert(Math.abs(weight - 1) < 0.01, `${domain.key}: measured factor weights sum to 1`, weight.toFixed(3))
    assert(domain.factors.filter((f) => !f.measured).every((f) => f.value === null && f.effectiveWeight === 0), `${domain.key}: unmeasured factors carry no value and no weight`)
  }
  assert(intel.assets.filter((a) => a.hasEvidence && a.agilityScore !== null).every((a) => a.scoreFactors.length > 0), 'every scored asset publishes its score factors')
  assert(intel.nextStep.label.length > 0 && intel.nextStep.route.startsWith('/'), 'a next step is published with a real route', intel.nextStep.label)

  const withSimulation = buildCryptoAgilityIntelligence({
    ...inputs,
    migrationJobs: [
      ...migrationJobs,
      { id: 'sim1', asset_id: 'a1', name: 'sandbox run', job_type: 'tls_migration', status: 'failed', target_algorithm: 'ML-KEM-768', sandbox_mode: 'true', created_at: '2026-08-07T00:00:00Z', updated_at: '2026-08-07T00:00:00Z' },
    ],
  })
  const a1Before = intel.assets.find((a) => a.id === 'a1')
  const a1After = withSimulation.assets.find((a) => a.id === 'a1')
  assert(a1After?.agilityState === a1Before?.agilityState && a1After?.agilityScore === a1Before?.agilityScore, 'a failed sandbox simulation does not move an asset', `${a1Before?.agilityState}/${a1Before?.agilityScore} → ${a1After?.agilityState}/${a1After?.agilityScore}`)
  assert(!withSimulation.changeTracking.changes.some((c) => c.id === 'job-sim1'), 'a sandbox simulation is not a recorded configuration change')

  const certsUnreadable = buildCryptoAgilityIntelligence({
    ...inputs,
    certificates: [],
    sourceHealth: [{ key: 'certificates', label: 'Certificates', state: 'unavailable', rows: 0, limit: 1500, detail: 'query failed' }],
  })
  const certDomain = certsUnreadable.domains.find((d) => d.key === 'certificate')!
  assert(certDomain.score === null && /could not be read/.test(certDomain.basis), 'an unreadable certificate source withholds the certificate domain', certDomain.basis.slice(0, 90))
  assert(certsUnreadable.nextStep.label === 'Refresh the assessment', 'an unreadable source becomes the next step', certsUnreadable.nextStep.label)

  /* ---------------------------------------------------------------- */
  console.log(`\n${failures === 0 ? '✓ ALL CRYPTO AGILITY INVARIANTS HOLD' : `✗ ${failures} INVARIANT(S) FAILED`}\n`)
  process.exit(failures === 0 ? 0 : 1)
}

main()
