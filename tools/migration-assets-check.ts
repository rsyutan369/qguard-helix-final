/**
 * Asset Migration Intelligence Engine — offline invariant check.
 *
 * Exercises the PURE isomorphic engine (no Supabase / server required) and
 * asserts the guarantees the Migration Planner's asset workspace depends on:
 *
 *   1. Per-asset posture/risk is derived by the SAME model the Quantum Readiness
 *      snapshot uses, so tenant totals and the asset roll-up tally exactly.
 *   2. A dossier only ever describes its own asset (no cross-asset bleed).
 *   3. PQC target mapping is correct (ML-KEM = key establishment, ML-DSA/SLH-DSA
 *      = signatures — never the other way round).
 *   4. Prioritisation uses the enterprise factor model and ranks by it.
 *   5. Assets without evidence read honestly instead of scoring a fabricated
 *      readiness.
 *
 * Run: npx tsx tools/migration-assets-check.ts
 */

import {
  buildAssetPortfolio,
  deriveAssetPostureModel,
  pqcTargetFor,
  type Row,
} from '../src/lib/migration/asset-intelligence'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

/* ---- Fixture: a small but realistic tenant ------------------------- */

const assets: Row[] = [
  { id: 'a1', name: 'portal.company.com', type: 'web-service', environment: 'production', region: 'eu-west-1', service_owner: 'Platform Team', criticality: 'high', metadata: { hostname: 'portal.company.com' }, created_at: '2026-01-02T00:00:00Z', updated_at: '2026-07-01T00:00:00Z' },
  { id: 'a2', name: 'billing-api', type: 'api', environment: 'production', service_owner: 'Billing', criticality: 'critical', metadata: { hostname: '10.4.2.9' }, created_at: '2026-01-02T00:00:00Z', updated_at: '2026-07-01T00:00:00Z' },
  { id: 'a3', name: 'pqc-vault', type: 'service', environment: 'production', service_owner: 'Security', criticality: 'medium', metadata: {}, created_at: '2026-01-02T00:00:00Z', updated_at: '2026-07-01T00:00:00Z' },
  { id: 'a4', name: 'legacy-batch', type: 'server', environment: 'development', service_owner: 'Unassigned', metadata: {}, created_at: '2026-01-02T00:00:00Z', updated_at: '2026-07-01T00:00:00Z' },
]

const cryptoInventory: Row[] = [
  { id: 'c1', asset_id: 'a1', algorithm: 'RSA-2048', key_size: 2048, protocol: 'TLS 1.2', is_vulnerable: true, created_at: '2026-06-01T00:00:00Z' },
  { id: 'c2', asset_id: 'a1', algorithm: 'ECDSA-P256', key_size: 256, protocol: 'TLS 1.2', is_vulnerable: true, created_at: '2026-06-01T00:00:00Z' },
  { id: 'c3', asset_id: 'a2', algorithm: 'RSA-4096', key_size: 4096, protocol: 'TLS 1.3', is_vulnerable: true, created_at: '2026-06-01T00:00:00Z' },
  { id: 'c4', asset_id: 'a3', algorithm: 'ML-KEM-768', is_quantum_safe: true, protocol: 'TLS 1.3', created_at: '2026-06-01T00:00:00Z' },
  { id: 'c5', asset_id: 'a3', algorithm: 'ML-DSA-65', is_quantum_safe: true, created_at: '2026-06-01T00:00:00Z' },
]

const scanResults: Row[] = [
  { id: 's1', asset_id: 'a1', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Quantum-vulnerable key exchange', created_at: '2026-07-01T00:00:00Z' },
  { id: 's2', asset_id: 'a2', algorithm: 'SHA-1', threat_level: 'high', description: 'Broken hash in signing path', created_at: '2026-07-01T00:00:00Z' },
]

const cryptoExposures: Row[] = [
  { id: 'e1', asset_id: 'a1', exposure_type: 'Weak TLS configuration', severity: 'high', description: 'TLS 1.2 with classical key exchange', created_at: '2026-07-01T00:00:00Z' },
]

const certificates: Row[] = [
  { id: 'x1', asset_id: 'a1', name: 'portal.company.com', algorithm: 'RSA-2048', key_size: 2048, issuer: 'Internal CA', not_after: '2026-08-20T00:00:00Z', is_quantum_safe: false, status: 'active' },
  { id: 'x2', asset_id: 'a3', name: 'vault.internal', algorithm: 'ML-DSA-65', issuer: 'PQC CA', not_after: '2027-01-01T00:00:00Z', is_quantum_safe: true, status: 'active' },
]

const runtimeEvents: Row[] = [
  { id: 'r1', asset_id: 'a1', algorithm: 'RSA-2048', key_exchange_algorithm: 'ECDHE-RSA', cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', protocol: 'TLS 1.2', severity: 'high', risk_score: 72, is_legacy: true, hndl_risk: true, observed_at: '2026-08-01T00:00:00Z' },
  { id: 'r2', asset_id: 'a3', algorithm: 'ML-KEM-768', key_exchange_algorithm: 'X25519MLKEM768', protocol: 'TLS 1.3', severity: 'low', risk_score: 5, is_pqc: true, observed_at: '2026-08-01T00:00:00Z' },
]

const relationships: Row[] = [
  { id: 'rel1', source_asset_id: 'a1', target_asset_id: 'a2', relationship_type: 'calls' },
  { id: 'rel2', source_asset_id: 'a2', target_asset_id: 'a3', relationship_type: 'uses-keys-from' },
]

const migrationJobs: Row[] = [
  { id: 'j1', asset_id: 'a2', job_type: 'tls_migration', status: 'running', target_algorithm: 'ML-KEM-768', progress: 40, updated_at: '2026-08-02T00:00:00Z' },
]

const inputs = {
  assets,
  cryptoInventory,
  scanResults,
  cryptoExposures,
  certificates,
  runtimeEvents,
  relationships,
  migrationJobs,
  validationLogs: [{ id: 'v1', migration_job_id: 'j1', status: 'passed', created_at: '2026-08-02T01:00:00Z' }] as Row[],
  complianceEvidence: [] as Row[],
  queuedAssetIds: ['a2'],
  now: Date.parse('2026-08-04T00:00:00Z'),
}

function main() {
  const portfolio = buildAssetPortfolio(inputs)
  const byId = new Map(portfolio.assets.map((a) => [a.id, a]))
  const a1 = byId.get('a1')!
  const a2 = byId.get('a2')!
  const a3 = byId.get('a3')!
  const a4 = byId.get('a4')!

  /* ---------------------------------------------------------------- */
  console.log('\n[1] Canonical posture model is shared with the QR snapshot')
  const model = deriveAssetPostureModel({ assets, scanResults, cryptoExposures, cryptoInventory, runtimeEvents })
  assert(model.counts.quantumVulnerableAssets === portfolio.summary.quantumVulnerable,
    'portfolio vulnerable count === posture model count',
    `${portfolio.summary.quantumVulnerable} vs ${model.counts.quantumVulnerableAssets}`)
  assert(model.counts.pqcReadyAssets === portfolio.summary.pqcReady, 'portfolio PQC-ready count === posture model count')
  assert(model.counts.hybridAssets === portfolio.summary.hybrid, 'portfolio hybrid count === posture model count')
  assert(
    portfolio.summary.quantumVulnerable + portfolio.summary.hybrid + portfolio.summary.pqcReady === portfolio.summary.total,
    'every asset lands in exactly one posture bucket',
    `${portfolio.summary.quantumVulnerable}+${portfolio.summary.hybrid}+${portfolio.summary.pqcReady}=${portfolio.summary.total}`,
  )
  assert(a1.riskScore === Math.round(model.assetRisk.get('a1') || 0), 'per-asset risk score === canonical risk map', String(a1.riskScore))

  /* ---------------------------------------------------------------- */
  console.log('\n[2] Posture classification is correct per asset')
  assert(a1.posture === 'vulnerable' && a1.postureLabel === 'Quantum-Vulnerable', 'RSA/ECDSA web service is Quantum-Vulnerable', a1.postureLabel)
  assert(a3.posture === 'pqc' && a3.postureLabel === 'PQC-Ready', 'ML-KEM/ML-DSA vault is PQC-Ready', a3.postureLabel)
  assert(a4.posture === 'hybrid', 'asset with no crypto evidence defaults to hybrid/in-progress, not vulnerable', a4.posture)

  /* ---------------------------------------------------------------- */
  console.log('\n[3] No cross-asset bleed in a dossier')
  assert(a1.componentCount === 2 && a1.vulnerableComponentCount === 2, 'a1 counts only its own components', `${a1.componentCount}/${a1.vulnerableComponentCount}`)
  assert(a3.componentCount === 2 && a3.pqcComponentCount === 2, 'a3 counts only its own PQC components', `${a3.componentCount}/${a3.pqcComponentCount}`)
  assert(a1.certificates.length === 1 && a1.certificates[0].id === 'x1', 'a1 shows only its own certificate')
  assert(!a1.algorithms.some((x) => /ML-KEM|ML-DSA/.test(x.algorithm)), 'a1 never shows the PQC vault algorithms')
  assert(a1.findings.every((f) => f.source !== 'Migration Jobs'), 'a1 findings come from a1 evidence only')
  assert(a2.jobs.length === 1 && a1.jobs.length === 0, 'migration jobs bind to the owning asset only', `${a2.jobs.length}/${a1.jobs.length}`)
  const componentSum = portfolio.assets.reduce((s, a) => s + a.componentCount, 0)
  assert(componentSum === cryptoInventory.length, 'per-asset component counts sum to the tenant CBOM', `${componentSum}/${cryptoInventory.length}`)

  /* ---------------------------------------------------------------- */
  console.log('\n[4] PQC target mapping (FIPS 203/204/205 correctness)')
  assert(pqcTargetFor('ECDSA-P256', 'code signing').category === 'signature', 'ECDSA → signature family')
  assert(/ML-DSA/.test(pqcTargetFor('ECDSA-P256', 'code signing').target), 'ECDSA maps to ML-DSA, never ML-KEM')
  assert(/ML-KEM/.test(pqcTargetFor('ECDH', 'tls key exchange').target), 'ECDH maps to ML-KEM')
  assert(/ML-DSA/.test(pqcTargetFor('RSA-2048', 'x509 certificate signing').target), 'RSA certificate signing maps to ML-DSA')
  assert(/ML-KEM/.test(pqcTargetFor('RSA-2048', 'tls transport').target), 'RSA transport maps to ML-KEM')
  assert(pqcTargetFor('SHA-1', '').target === 'SHA3-256', 'SHA-1 maps to SHA3-256')
  assert(pqcTargetFor('3DES', '').target === 'AES-256-GCM', '3DES maps to AES-256-GCM')
  assert(a3.algorithms.every((x) => x.classification !== 'pqc' || x.target === 'Already quantum-safe'), 'PQC primitives are not told to migrate')

  /* ---------------------------------------------------------------- */
  console.log('\n[5] Enterprise prioritisation model')
  const factorKeys = a1.priorityFactors.map((f) => f.key)
  for (const key of ['hndl', 'criticality', 'internet', 'legacy', 'unsupported', 'regulatory', 'customer', 'certificate', 'dependency', 'confidence']) {
    assert(factorKeys.includes(key), `prioritisation includes the "${key}" factor`)
  }
  const weightSum = a1.priorityFactors.reduce((s, f) => s + f.weight, 0)
  assert(weightSum === 100, 'priority factor weights sum to 100', String(weightSum))
  assert(a1.priorityScore > a3.priorityScore, 'a vulnerable internet-facing asset outranks a PQC-ready one', `${a1.priorityScore} vs ${a3.priorityScore}`)
  assert(
    portfolio.recommendedOrder.every((row, index, all) => index === 0 || all[index - 1].priorityScore >= row.priorityScore),
    'recommended order is monotonically ranked by priority score',
  )
  assert(portfolio.recommendedOrder[0]?.rationale?.length > 0, 'each ranked asset carries a rationale')

  /* ---------------------------------------------------------------- */
  console.log('\n[6] Evidence honesty')
  assert(a4.hasEvidence === false, 'asset with no crypto evidence is flagged')
  assert(a4.readinessScore === 0 && a4.priorityScore === 0, 'unassessed asset scores 0 rather than a fabricated readiness', `${a4.readinessScore}/${a4.priorityScore}`)
  assert(a4.estimatedEffortHours === 0 && a4.estimatedDurationLabel === 'Evidence Not Available', 'unassessed asset reports no effort estimate')
  assert(a4.evidence.sources.length === 0, 'unassessed asset lists no evidence sources')
  assert(a1.evidence.sources.length >= 3, 'assessed asset lists its real evidence sources', a1.evidence.sources.join('/'))
  assert(a3.tlsConfiguration.keyExchange.includes('X25519MLKEM768'), 'observed hybrid key exchange surfaces on the asset')

  /* ---------------------------------------------------------------- */
  console.log('\n[7] Migration state, dependencies and queue')
  assert(a2.migrationStatus === 'In Progress' && a2.migrationProgressPct === 40, 'running job drives asset migration status', `${a2.migrationStatus}/${a2.migrationProgressPct}`)
  assert(a4.migrationStatus === 'Not Started', 'asset with no jobs reads Not Started')

  // Cancelled jobs are withdrawn work: they must not keep an asset reading as
  // "in migration" once the operator removes it from the Live Migration queue.
  const cancelledOnly = buildAssetPortfolio({
    ...inputs,
    migrationJobs: [{ id: 'j9', asset_id: 'a2', job_type: 'tls_migration', status: 'cancelled', progress: 40, updated_at: '2026-08-02T00:00:00Z' }] as Row[],
  })
  const a2Cancelled = cancelledOnly.assets.find((a) => a.id === 'a2')!
  assert(a2Cancelled.migrationStatus === 'Not Started', 'an asset whose only job was cancelled reads Not Started', a2Cancelled.migrationStatus)
  assert(a2Cancelled.migrationProgressPct === 0, 'cancelled work contributes no migration progress', String(a2Cancelled.migrationProgressPct))
  assert(/cancelled/i.test(a2Cancelled.migrationStatusDetail), 'the cancellation is stated in the status detail', a2Cancelled.migrationStatusDetail)
  assert(a2.validation.records === 1, 'validation logs resolve through the asset job ids', String(a2.validation.records))
  assert(a2.validation.validated === true, 'a passing validation record marks the asset validated')
  assert(a1.validation.validated === false && a1.validation.cutoverBlocked === false,
    'an asset with no validation record is NOT claimed validated, and is not falsely blocked either',
    `${a1.validation.validated}/${a1.validation.cutoverBlocked}`)
  assert(a4.validation.cutoverBlocked === true && /evidence/i.test(a4.validation.blockerReason),
    'an unassessed asset is cutover-blocked with a stated reason', a4.validation.blockerReason)
  assert(a2.queued === true && a1.queued === false, 'queue membership is per asset', `${a2.queued}/${a1.queued}`)
  assert(a1.dependencies.some((d) => d.id === 'a2' && d.direction === 'downstream'), 'downstream dependency resolved')
  assert(a2.dependencies.some((d) => d.id === 'a1' && d.direction === 'upstream'), 'upstream dependency resolved')
  assert(a2.businessImpact.dependents === 1, 'dependents counted from inbound relationships', String(a2.businessImpact.dependents))

  /* ---------------------------------------------------------------- */
  console.log('\n[8] Migration guidance completeness')
  assert(a1.rollbackStrategy.available && a1.rollbackStrategy.steps.length >= 4, 'rollback runbook produced for an assessed asset')
  assert(!a4.rollbackStrategy.available, 'no rollback runbook is invented for an unassessed asset')
  assert(a1.requiredApprovals.some((x) => x.role === 'Change Advisory Board' && x.required), 'production asset requires CAB approval')
  assert(a4.requiredApprovals.some((x) => x.role === 'Change Advisory Board' && !x.required), 'development asset does not require CAB approval')
  assert(a1.timeline.length === 5, 'per-asset timeline has the 5 execution phases', String(a1.timeline.length))
  assert(a1.compliance.some((c) => /PCI DSS/.test(c.framework)), 'internet-facing asset maps to transport-security frameworks')
  assert(a1.compliance.every((c) => /derived/i.test(c.framework)), 'derived control mapping is labelled as derived, not audited evidence')
  assert(a1.recommendations.length > 0 && a1.recommendations.every((r) => r.standard), 'recommendations cite a standard')
  assert(a1.successProbabilityPct > 0 && a1.successProbabilityPct <= 98, 'success probability is bounded', String(a1.successProbabilityPct))
  assert(a1.certificates[0].daysToExpiry !== null && a1.certificates[0].daysToExpiry! < 30, 'certificate expiry is computed against the evaluation time', String(a1.certificates[0].daysToExpiry))

  /* ---------------------------------------------------------------- */
  console.log('\n[9] Empty tenant honesty')
  const empty = buildAssetPortfolio({
    assets: [], cryptoInventory: [], scanResults: [], cryptoExposures: [], certificates: [],
    runtimeEvents: [], relationships: [], migrationJobs: [], validationLogs: [], complianceEvidence: [],
  })
  assert(empty.assets.length === 0 && empty.summary.total === 0, 'empty tenant returns no assets')
  assert(empty.recommendedOrder.length === 0, 'empty tenant recommends nothing')
  assert(empty.summary.averageReadiness === 0, 'empty tenant reports 0 readiness rather than NaN')

  console.log(`\n${failures === 0 ? '✓ ALL CHECKS PASSED' : `✗ ${failures} CHECK(S) FAILED`}\n`)
  process.exit(failures === 0 ? 0 : 1)
}

main()
