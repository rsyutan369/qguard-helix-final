/**
 * External Trust & Ecosystem Intelligence Engine — offline invariant check.
 *
 * Exercises the PURE isomorphic engine (no Supabase / server required) and
 * asserts the guarantees the four pages depend on:
 *
 *   1. A vendor CLAIM is never merged into a measured capability.
 *   2. Missing evidence resolves to `unknown` and never to a safe status.
 *   3. The four page projections describe the SAME vendors/nodes/chains.
 *   4. Blast radius traverses only recorded relationships, and is bounded.
 *   5. A single point of failure needs concentration AND fragility — never one.
 *   6. Trust chains are built only from real certificates; the proposed PQC
 *      chain is a PROPOSAL and says CA support is unverified.
 *   7. Trust agility excludes unmeasured dimensions instead of scoring them 0,
 *      and is the SAME model the Crypto Agility page consumes.
 *   8. Invalid cryptographic combinations are rejected by purpose (ML-KEM is
 *      not a signature; hybrid groups need TLS 1.3).
 *   9. An empty tenant produces no fabricated numbers.
 *
 * Run: npx tsx tools/external-trust-check.ts
 */

import type { Row } from '../src/lib/migration/asset-intelligence'
import {
  buildExternalTrustIntelligence,
  computeDependencyChain,
  computeEcosystemBlastRadius,
  computeTrustAgility,
  toExperimentRecord,
  validateExperimentConfiguration,
  type ExperimentConfiguration,
  type ExternalTrustInputs,
} from '../src/lib/ecosystem/external-trust-intelligence'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const NOW = Date.parse('2026-08-10T00:00:00Z')

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

const assets: Row[] = [
  { id: 'a1', name: 'checkout.company.com', type: 'web-service', environment: 'production', service_owner: 'Payments', criticality: 'critical', metadata: { hostname: 'checkout.company.com' }, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
  { id: 'a2', name: 'identity.company.com', type: 'identity-provider', environment: 'production', service_owner: 'Identity', criticality: 'high', metadata: { hostname: 'identity.company.com' }, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
  { id: 'a3', name: 'reporting-batch', type: 'service', environment: 'staging', service_owner: 'Data', criticality: 'low', metadata: {}, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
]

const assetRelationships: Row[] = [
  { id: 'r1', source_asset_id: 'a1', target_asset_id: 'a2', relationship_type: 'authenticates-with' },
  { id: 'r2', source_asset_id: 'a3', target_asset_id: 'a1', relationship_type: 'calls' },
]

const certificates: Row[] = [
  // Managed issuer, classical key ⇒ valid but PQC-incompatible.
  { id: 'c1', asset_id: 'a1', name: 'checkout.company.com', subject: 'checkout.company.com', algorithm: 'ECDSA P-256', key_size: 256, issuer: "Let's Encrypt", not_before: '2026-05-01T00:00:00Z', not_after: '2026-11-01T00:00:00Z', is_quantum_safe: false, status: 'active', metadata: {}, created_at: '2026-05-01T00:00:00Z', updated_at: '2026-05-01T00:00:00Z' },
  // Self-signed ⇒ static trust anchor + weak signature in metadata.
  { id: 'c2', asset_id: 'a2', name: 'identity-internal', subject: 'identity-internal', algorithm: 'RSA-2048', key_size: 2048, issuer: 'identity-internal', not_before: '2026-01-01T00:00:00Z', not_after: '2026-08-20T00:00:00Z', is_quantum_safe: false, status: 'active', metadata: { signature_algorithm: 'sha1WithRSAEncryption' }, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' },
]

const runtimeEvents: Row[] = [
  { id: 'e1', asset_id: 'a1', asset_name: 'checkout', host: 'api.stripe.com', protocol: 'TLS 1.3', algorithm: 'ECDHE-RSA', key_exchange_algorithm: 'X25519', severity: 'medium', is_legacy: true, observed_at: '2026-08-05T00:00:00Z', created_at: '2026-08-05T00:00:00Z' },
  { id: 'e2', asset_id: 'a2', asset_name: 'identity', host: 'login.microsoftonline.com', protocol: 'TLS 1.3', algorithm: 'X25519MLKEM768', key_exchange_algorithm: 'X25519MLKEM768', severity: 'low', is_pqc: true, observed_at: '2026-08-05T00:00:00Z', created_at: '2026-08-05T00:00:00Z' },
]

const cryptoInventory: Row[] = [
  { id: 'i1', asset_id: 'a1', item_type: 'protocol', name: 'edge tls', algorithm: 'ECDSA P-256', protocol: 'TLS 1.3', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
  { id: 'i2', asset_id: 'a1', item_type: 'library', name: 'OpenSSL 1.1.1', algorithm: 'RSA-2048', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
]

const connectorAccounts: Row[] = [
  { id: 'k1', provider: 'aws', display_name: 'AWS Production', status: 'connected', last_sync_at: '2026-08-08T00:00:00Z', metadata: {} },
]

const vendorAssessments: Row[] = [
  { id: 'v1', vendor_name: 'Acme Payments', category: 'payment', readiness_status: 'Quantum Ready', score: 90, support: { 'ML-KEM': 'Ready' }, contract_status: 'PQC migration clause present; algorithm list agreed', metadata: { business_owner: 'Payments Platform' }, last_assessed_at: '2026-07-01T00:00:00Z', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-07-01T00:00:00Z' },
]

const baseInputs: ExternalTrustInputs = {
  assets, assetRelationships, certificates, cryptoInventory,
  cryptoExposures: [], scanResults: [], scannerEvidence: [], scannerAlerts: [],
  runtimeEvents, connectorAccounts, vendorAssessments,
  trustFindings: [], migrationJobs: [{ id: 'm1', asset_id: 'a1', status: 'queued' }],
  complianceEvidence: [], evidenceRequests: [], experiments: [],
  now: NOW,
}

function main() {
  const intel = buildExternalTrustIntelligence(baseInputs)

  /* ---------------------------------------------------------------- */
  console.log('\n[1] Vendor claims are never merged into measured capability')
  const acme = intel.vendors.records.find((vendor) => vendor.name === 'Acme Payments')
  assert(Boolean(acme), 'the assessed vendor is present')
  if (acme) {
    assert(acme.vendorCommitment === 'ready', 'the vendor CLAIM is recorded as stated', acme.vendorCommitment)
    assert(acme.assessedReadiness === 'unknown', 'no measurement exists, so the ASSESSMENT is unknown', acme.assessedReadiness)
    assert(acme.readiness !== 'ready', 'the published readiness is NOT "ready" on a claim alone', acme.readiness)
    assert(/vendor claim, not a measured capability/i.test(acme.vendorCommitmentBasis), 'the claim is explicitly labelled as a claim')
    assert(
      Object.values(acme.position.provenance).every((value) => value !== 'measured'),
      'no capability is marked measured without observed cryptography',
    )
  }

  /* ---------------------------------------------------------------- */
  console.log('\n[2] Missing evidence never becomes a safe status')
  assert(
    intel.vendors.records.every((vendor) => vendor.hasEvidence || vendor.assessedReadiness === 'unknown'),
    'evidence-free vendors carry no measured readiness',
  )
  assert(
    intel.vendors.records.every((vendor) => vendor.evidenceState !== 'complete' || vendor.openRequests === 0),
    'evidence never reads Complete while requests are open',
  )
  assert(
    !intel.vendors.records.some((vendor) => vendor.assessedReadiness === 'unknown' && vendor.readiness === 'ready'),
    'an unmeasured vendor is never published as Ready',
  )
  const readinessPct = intel.vendors.summary.overallReadinessPct
  assert(readinessPct === null || (readinessPct >= 0 && readinessPct <= 100), 'overall readiness is null or a real percentage', String(readinessPct))
  assert(/excluded rather than counted as ready/i.test(intel.vendors.summary.readinessBasis), 'the roll-up says unmeasured vendors are excluded, not counted')

  /* ---------------------------------------------------------------- */
  console.log('\n[3] The four projections describe the same world')
  const vendorNodeIds = intel.ecosystem.nodes.filter((node) => node.kind === 'vendor').map((node) => node.vendorId)
  assert(
    vendorNodeIds.every((id) => intel.vendors.records.some((vendor) => vendor.id === id)),
    'every vendor node maps to a record in the vendor register',
  )
  assert(
    intel.trust.chains.every((chain) => !chain.vendorId || intel.vendors.records.some((vendor) => vendor.id === chain.vendorId)),
    'every vendor-linked trust chain maps to a real vendor',
  )
  assert(
    intel.trust.summary.chains === intel.trust.chains.length,
    'trust summary count equals the chain list', `${intel.trust.summary.chains} vs ${intel.trust.chains.length}`,
  )
  assert(
    intel.lab.targets.every((target) => !target.assetId || assets.some((asset) => asset.id === target.assetId)),
    'every lab target references a real tenant asset',
  )

  /* ---------------------------------------------------------------- */
  console.log('\n[4] Blast radius traverses only recorded relationships')
  const focus = intel.ecosystem.nodes.find((node) => node.id === 'asset:a2')
  assert(Boolean(focus), 'the identity asset is present as a node')
  const blast = computeEcosystemBlastRadius(intel.ecosystem.nodes, intel.ecosystem.edges, 'asset:a2', new Set(['a1']))
  assert(Boolean(blast), 'blast radius is computed')
  if (blast) {
    // a1 → a2 (authenticates-with) and a3 → a1, so a2's dependents are a1 (direct) then a3 (indirect).
    assert(blast.directDependencies === 1, 'direct dependents are counted from real edges', String(blast.directDependencies))
    assert(blast.indirectDependencies === 1, 'indirect dependents are counted transitively', String(blast.indirectDependencies))
    assert(blast.migrationPlans === 1, 'affected migration plans come from real migration jobs', String(blast.migrationPlans))
    assert(!blast.affectedNodeIds.includes('asset:a2'), 'the root is not counted as its own dependent')
    assert(/bounded at depth/i.test(blast.basis), 'the traversal declares its depth bound')
  }
  const isolated = computeEcosystemBlastRadius(intel.ecosystem.nodes, intel.ecosystem.edges, 'asset:a3')
  assert(isolated?.directDependencies === 0, 'a node with no dependents reports zero, not a guess', String(isolated?.directDependencies))
  assert(computeEcosystemBlastRadius(intel.ecosystem.nodes, intel.ecosystem.edges, 'does-not-exist') === null, 'an unknown node yields null')

  const chain = computeDependencyChain(intel.ecosystem.nodes, intel.ecosystem.edges, 'asset:a3')
  assert(chain.length > 1, 'a dependency chain is produced from real edges', String(chain.length))
  assert(chain[0].depth === 0, 'the chain starts at the requested node')

  /* ---------------------------------------------------------------- */
  console.log('\n[5] A single point of failure needs concentration AND fragility')
  assert(
    intel.ecosystem.singlePointsOfFailure.every((spof) => spof.downstreamConsumers >= 2 && spof.reasons.length >= 2),
    'every SPOF has multiple consumers and multiple reasons',
  )
  assert(
    intel.ecosystem.singlePointsOfFailure.every((spof) => /dependent node/i.test(spof.basis)),
    'every SPOF states the evidence behind it',
  )

  /* ---------------------------------------------------------------- */
  console.log('\n[6] Trust chains come from real certificates only')
  assert(intel.trust.chains.length === certificates.length, 'one chain per discovered certificate', `${intel.trust.chains.length} vs ${certificates.length}`)
  const selfSigned = intel.trust.chains.find((candidate) => candidate.name === 'identity-internal')
  assert(Boolean(selfSigned), 'the self-signed certificate produced a chain')
  if (selfSigned) {
    assert(selfSigned.state === 'weak', 'a SHA-1 signature makes the chain weak', selfSigned.state)
    assert(
      intel.trust.findings.some((finding) => finding.kind === 'static-trust-anchor' && finding.chainId === selfSigned.id),
      'the self-signed anchor is reported as a static trust anchor',
    )
    assert(
      intel.trust.findings.some((finding) => finding.kind === 'weak-algorithm' && finding.chainId === selfSigned.id),
      'the SHA-1 signature is reported as a weak algorithm',
    )
    assert(selfSigned.proposed.feasibility !== 'supported', 'the proposed PQC chain is not claimed as supported')
    assert(/not verified/i.test(selfSigned.proposed.note), 'the proposal states CA support is unverified')
  }
  const managed = intel.trust.chains.find((candidate) => candidate.name === 'checkout.company.com')
  if (managed) {
    assert(managed.certificate?.renewalMechanism === 'automated', 'a managed issuer is recorded as automated renewal')
    assert(
      !intel.trust.findings.some((finding) => finding.kind === 'manual-renewal' && finding.chainId === managed.id),
      'a managed issuer does NOT raise a manual-renewal finding',
    )
  }
  assert(
    intel.trust.findings.every((finding) => finding.evidence.length > 0 && finding.recommendedAction.length > 0),
    'every trust finding cites evidence and a recommended action',
  )
  assert(
    !JSON.stringify(intel.trust).includes('PRIVATE KEY'),
    'no private key material appears anywhere in the trust model',
  )

  /* ---------------------------------------------------------------- */
  console.log('\n[7] Trust agility excludes what it cannot measure')
  const agility = intel.trust.agility
  assert(agility.score !== null, 'the fixture produces a measurable trust agility score', String(agility.score))
  const scored = agility.breakdown.filter((row) => row.score !== null)
  const unscored = agility.breakdown.filter((row) => row.score === null)
  assert(scored.length > 0, 'at least one dimension is measured')
  assert(unscored.every((row) => row.basis.startsWith('Evidence Not Available')), 'unmeasured dimensions say Evidence Not Available')
  const scoredWeight = scored.reduce((sum, row) => sum + row.weight, 0)
  const expected = Math.round(Math.max(0, Math.min(100, scored.reduce((sum, row) => sum + (row.score as number) * row.weight, 0) / scoredWeight)))
  assert(agility.score === expected, 'the score is the renormalised weighted mean of measured dimensions', `${agility.score} vs ${expected}`)
  assert(agility.coverage === Math.round(scoredWeight), 'coverage reports the measured weight', `${agility.coverage} vs ${scoredWeight}`)

  // The same call the Crypto Agility page makes must return the same number.
  const shared = computeTrustAgility({ certificates, assets, assetRelationships, cryptoInventory, now: NOW })
  assert(shared.score === agility.score, 'the shared model returns the identical score to both consumers', `${shared.score} vs ${agility.score}`)

  // No certificates ⇒ no score (an empty PKI is not a perfect one).
  const noCerts = computeTrustAgility({ certificates: [], assets: [], assetRelationships: [], cryptoInventory: [], now: NOW })
  assert(noCerts.score === null, 'no certificates yields NO score, not 100', String(noCerts.score))

  /* ---------------------------------------------------------------- */
  console.log('\n[8] Cryptographic combinations are validated by purpose')
  const valid: ExperimentConfiguration = {
    protocol: 'TLS 1.3', keyExchange: 'X25519+ML-KEM-768', signature: 'Ed25519+ML-DSA-65',
    symmetric: 'AES-256-GCM', kdf: 'HKDF-SHA3-256', hash: 'SHA3-256',
  }
  assert(validateExperimentConfiguration(valid).length === 0, 'the platform mandatory stack validates cleanly')

  const kemAsSignature = validateExperimentConfiguration({ ...valid, signature: 'ML-KEM-768' as never })
  assert(kemAsSignature.length > 0, 'ML-KEM in the signature slot is rejected')
  assert(kemAsSignature.some((issue) => /key encapsulation/i.test(issue.message)), 'the rejection explains ML-KEM is a KEM')

  const signatureAsKem = validateExperimentConfiguration({ ...valid, keyExchange: 'ML-DSA-65' as never })
  assert(signatureAsKem.some((issue) => /cannot perform key establishment/i.test(issue.message)), 'a signature algorithm cannot be used for key establishment')

  const hybridOnTls12 = validateExperimentConfiguration({ ...valid, protocol: 'TLS 1.2' })
  assert(hybridOnTls12.some((issue) => /TLS 1\.3/.test(issue.message)), 'a hybrid group on TLS 1.2 is rejected')

  const weakSymmetric = validateExperimentConfiguration({ ...valid, symmetric: 'AES-128-GCM' as never })
  assert(weakSymmetric.length > 0, 'a non-approved symmetric cipher is rejected')

  /* ---------------------------------------------------------------- */
  console.log('\n[9] The empty tenant produces no fabricated numbers')
  const empty = buildExternalTrustIntelligence({
    assets: [], assetRelationships: [], certificates: [], cryptoInventory: [],
    cryptoExposures: [], scanResults: [], scannerEvidence: [], scannerAlerts: [],
    runtimeEvents: [], connectorAccounts: [], vendorAssessments: [],
    trustFindings: [], migrationJobs: [], complianceEvidence: [],
    evidenceRequests: [], experiments: [], now: NOW,
  })
  assert(empty.hasData === false, 'an empty tenant reports hasData=false')
  assert(empty.vendors.records.length === 0, 'no vendors are invented')
  assert(empty.vendors.summary.overallReadinessPct === null, 'no readiness percentage is published without evidence')
  assert(empty.ecosystem.nodes.length === 0, 'no ecosystem nodes are invented')
  assert(empty.ecosystem.singlePointsOfFailure.length === 0, 'no SPOFs are invented')
  assert(empty.trust.chains.length === 0, 'no trust chains are invented')
  assert(empty.trust.agility.score === null, 'no trust agility score is published without evidence')
  assert(empty.lab.targets.length === 0, 'no lab targets are invented')
  assert(/Evidence Not Available/.test(empty.evidence.note), 'the evidence note states nothing is available')

  /* ---------------------------------------------------------------- */
  console.log('\n[10] Unknowns are surfaced, not hidden')
  assert(
    intel.ecosystem.unknowns.every((unknown) => unknown.reason.length > 0 && unknown.recommendedAction.length > 0),
    'every unknown dependency explains itself and names an action',
  )
  assert(
    intel.ecosystem.summary.unknownDependencies === intel.ecosystem.unknowns.length ||
    intel.ecosystem.unknowns.length === 60,
    'the unknown count matches the surfaced list (or the display cap)',
    `${intel.ecosystem.summary.unknownDependencies} vs ${intel.ecosystem.unknowns.length}`,
  )

  console.log('\n[11] Standards applicability is evidence-driven, not universal')
  for (const vendor of intel.vendors.records) {
    assert(
      vendor.standards.every((standard) => standard.applicable || standard.alignment === 'not-applicable'),
      `${vendor.name}: a non-applicable standard is never given an alignment verdict`,
    )
    assert(
      vendor.standards.some((standard) => !standard.applicable) || vendor.signalCount > 0,
      `${vendor.name}: standards are not blanket-applied to a vendor with no evidence`,
    )
  }

  /* ---------------------------------------------------------------- */
  console.log('\n[12] One experiment shape — the read path and the write path agree')

  // The exact row the API inserts (POST /lab/experiments builds this object).
  const writtenRow: Row = {
    user_id: 'u1', asset_id: 'a1',
    target_label: 'checkout.company.com', target_host: 'checkout.company.com',
    target_port: 443, environment: 'production', vendor_id: 'lets-encrypt',
    execution_mode: 'controlled-test', outcome: 'conditional', risk: 'high', duration_ms: 812,
    payload: {
      target: { kind: 'endpoint', id: 't1', label: 'checkout.company.com', host: 'checkout.company.com', port: 443, environment: 'production', vendorId: 'lets-encrypt', assetId: 'a1' },
      currentConfiguration: { observed: ['ECDSA P-256', 'TLS 1.3'], protocol: 'TLS 1.3' },
      proposedConfiguration: { protocol: 'TLS 1.3', keyExchange: 'X25519+ML-KEM-768', signature: 'Ed25519+ML-DSA-65', symmetric: 'AES-256-GCM', kdf: 'HKDF-SHA3-256', hash: 'SHA3-256' },
    },
    result: {
      checks: [{ key: 'protocol', label: 'Protocol', verdict: 'pass', detail: 'Negotiated TLSv1.3.', method: 'measured' }],
      findings: [{ id: 'f-certificate', title: 'Certificate compatibility issue detected', severity: 'high', component: 'Certificate', evidence: 'Current: ECDSA P-256.', likelyCause: 'Classical chain.', affectedDependencies: [], recommendedAction: 'Analyze the affected trust chains.', route: '/dashboard/trust-chain-analyzer' }],
      basis: 'Controlled test: read-only TLS handshake.',
    },
    created_by: 'owner@example.com',
  }

  // Read path: the same row arriving through the history projection.
  const viaRead = buildExternalTrustIntelligence({
    assets: [], assetRelationships: [], certificates: [], cryptoInventory: [],
    cryptoExposures: [], scanResults: [], scannerEvidence: [], scannerAlerts: [],
    runtimeEvents: [], connectorAccounts: [], vendorAssessments: [],
    trustFindings: [], migrationJobs: [], complianceEvidence: [],
    evidenceRequests: [],
    experiments: [{ ...writtenRow, id: 'e1', created_at: '2026-08-10T00:00:00Z' }],
    now: NOW,
  }).lab.experiments[0]

  // Write path: what POST /lab/experiments now returns.
  const viaWrite = toExperimentRecord({ ...writtenRow, id: 'e1', created_at: '2026-08-10T00:00:00Z' }, NOW)

  const readKeys = Object.keys(viaRead).sort().join(',')
  const writeKeys = Object.keys(viaWrite).sort().join(',')
  assert(readKeys === writeKeys, 'read path and write path publish the SAME field set', writeKeys)
  assert(JSON.stringify(viaRead) === JSON.stringify(viaWrite), 'the two paths produce an identical record for one row')

  // Every field the result view dereferences must be present. `target` is the
  // one that took the page down: `result.target.label` on a raw row threw.
  for (const record of [viaRead, viaWrite]) {
    assert(Boolean(record.target?.label), 'record.target.label is always dereferenceable')
    assert(typeof record.executionMode === 'string' && record.executionMode.length > 0, 'record.executionMode is populated (never undefined)')
    assert(Number.isFinite(record.durationMs), 'record.durationMs is a number (never undefined)')
    assert(Array.isArray(record.checks) && Array.isArray(record.findings), 'record.checks / record.findings are arrays')
    assert(typeof record.basis === 'string' && record.basis.length > 0, 'record.basis is populated')
    assert(record.requiresProductionValidation === true, 'a laboratory record always requires production validation')
  }
  assert(viaWrite.checks.length === 1 && viaWrite.findings.length === 1, 'checks and findings survive the write-path projection')

  // Ephemeral result (schema not applied): no id, no created_at, still complete.
  const ephemeral = toExperimentRecord({ ...writtenRow, id: 'ephemeral-1', created_at: new Date(NOW).toISOString() }, NOW)
  assert(Boolean(ephemeral.target?.label), 'an unstored result still carries a dereferenceable target')
  assert(ephemeral.evidenceGenerated === false, 'an unstored result has generated no evidence')

  // NEGATIVE control: a row whose payload never persisted must still fall back
  // to a usable target rather than yielding undefined.
  const degraded = toExperimentRecord({
    id: 'e2', created_at: '2026-08-10T00:00:00Z', target_label: 'legacy.example.com',
    target_host: 'legacy.example.com', target_port: 8443, environment: 'staging',
    outcome: 'failed', risk: 'critical', duration_ms: 40, payload: null, result: null,
  }, NOW)
  assert(degraded.target.label === 'legacy.example.com', 'a payload-less row falls back to the stored target label')
  assert(degraded.target.port === 8443, 'the fallback target keeps the real port, not a hardcoded 443')
  assert(degraded.target.environment === 'staging', 'the fallback target keeps the real environment, not "unknown"')
  assert(degraded.checks.length === 0 && degraded.findings.length === 0, 'a payload-less row invents no checks or findings')
  assert(degraded.basis.length > 0, 'a payload-less row still states its basis')

  console.log(`\n${failures === 0 ? '✓ ALL EXTERNAL TRUST INVARIANTS HOLD' : `✗ ${failures} INVARIANT(S) FAILED`}\n`)
  process.exit(failures === 0 ? 0 : 1)
}

main()
