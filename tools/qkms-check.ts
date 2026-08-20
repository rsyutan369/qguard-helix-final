/**
 * QKMS Command Center — offline invariant check.
 *
 * Exercises the PURE isomorphic engine (no Supabase / server required) against a
 * tenant fixture holding one of every key archetype, and asserts the guarantees
 * the seven QKMS pages depend on. Each check maps to a defect the predecessor
 * actually shipped, so a regression here is a regression a user would have seen.
 *
 *   1. ML-DSA / SLH-DSA are POST-QUANTUM, never "weak". The predecessor's
 *      `/des|…|dsa|…/` matched the `dsa` inside `ML-DSA-65`, so every PQC
 *      signature key was published as deprecated, forced to `rotationRequired`
 *      and used to BLOCK the migration gate.
 *   2. Classification reads the ALGORITHM only. A key whose metadata mentions
 *      `aes-cbc` or `rc4` is not thereby deprecated.
 *   3. AES-256-GCM is quantum-resistant, not quantum-vulnerable, and requires
 *      no migration.
 *   4. One risk model. `key.risk.score` is the ONLY score, its factor
 *      contributions sum to it, and it is bounded [0,100].
 *   5. A governance violation raises the key's risk (sections 16–17), so
 *      Governance and Risk Analysis cannot disagree about the same key.
 *   6. Counts never mix units: keys are counted in keys, violations in
 *      violations. Every headline reconciles against the key list.
 *   7. Absence of evidence is `unknown`, never `healthy`. A key with no
 *      creation/rotation/expiry evidence is EXCLUDED from rotation health.
 *   8. A readiness band with no applicable key reports `percent: null`
 *      ("Not applicable"), never 0%.
 *   9. Key identity is stable and source-independent: rows describing the same
 *      key material collapse onto one key.
 *  10. The migration gate reports one of six states, with why/blockers/actions,
 *      and BLOCKED wins over everything.
 *  11. Runtime usage is `null` when unattributable — never a fabricated 0 — and
 *      an event is never attributed to every key sharing an algorithm.
 *  12. Capability flags never offer an operation the backend cannot honour.
 *
 * Run: npx tsx tools/qkms-check.ts
 */

import { buildQkmsIntelligence, type QkmsInputs } from '../src/lib/qkms/intelligence'
import { classifyKey } from '../src/lib/qkms/classify'
import { RISK_WEIGHTS } from '../src/lib/qkms/types'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const NOW = Date.parse('2026-08-18T00:00:00Z')
const DAY = 24 * 60 * 60 * 1000
const at = (days: number) => new Date(NOW + days * DAY).toISOString()

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

const assets = [
  { id: 'a1', name: 'checkout-api', type: 'api', environment: 'production', service_owner: 'Payments Platform', criticality: 'critical', metadata: {} },
  // No service_owner: a key on this asset has nothing to inherit, so K2 is
  // genuinely orphaned. (A key DOES inherit its asset's owner when one exists —
  // that is correct, and is why a2 must be ownerless to exercise the rule.)
  { id: 'a2', name: 'edge-gateway', type: 'web-service', environment: 'production', criticality: 'high', metadata: {} },
  { id: 'a3', name: 'batch-runner', type: 'server', environment: 'development', metadata: {} },
]

const inputs: QkmsInputs = {
  assets,

  qkmsKeys: [
    // K1 — post-quantum signing key, HSM, owned, healthy. The check-1 subject:
    // its algorithm contains the substring "dsa".
    {
      id: '11111111-1111-4111-8111-111111111111', tenant_id: 't', key_alias: 'payments-signing',
      key_type: 'Signing key', algorithm: 'ML-DSA-65', purpose: 'Digital signatures',
      owner_id: 'Payments Platform', asset_id: 'a1', storage_backend: 'AWS CloudHSM',
      environment: 'production', status: 'active', hsm_backed: true, exportable: false,
      entropy_source: 'HSM RNG', rotation_interval_days: 365, version: 2,
      last_rotated_at: at(-30), expires_at: at(300), created_at: at(-400), updated_at: at(-1),
      metadata_json: {},
    },
    // K2 — RSA-2048 TLS key in an unmanaged file, no owner, expired, exportable.
    // Should be quantum-vulnerable + a pile of violations + critical risk.
    {
      id: '22222222-2222-4222-8222-222222222222', tenant_id: 't', key_alias: 'legacy-tls',
      key_type: 'TLS / certificate key', algorithm: 'RSA-2048', purpose: 'Certificate and TLS identity',
      owner_id: null, asset_id: 'a2', storage_backend: '/etc/ssl/private/legacy.pem',
      environment: 'production', status: 'active', hsm_backed: false, exportable: true,
      rotation_interval_days: 180, version: 1,
      last_rotated_at: null, expires_at: at(-14), created_at: at(-900), updated_at: at(-2),
      metadata_json: {},
    },
    // K3 — AES-256-GCM data key whose METADATA mentions broken primitives.
    // Check 2 + 3: it must stay quantum-resistant symmetric, no migration.
    {
      id: '33333333-3333-4333-8333-333333333333', tenant_id: 't', key_alias: 'tde-master',
      key_type: 'Database encryption key', algorithm: 'AES-256-GCM', purpose: 'Data encryption',
      owner_id: 'Data Platform', asset_id: 'a1', storage_backend: 'AWS KMS',
      environment: 'production', status: 'active', hsm_backed: false, exportable: false,
      rotation_interval_days: 365, version: 1,
      last_rotated_at: at(-100), expires_at: at(200), created_at: at(-200), updated_at: at(-1),
      metadata_json: { notes: 'migrated off aes-cbc and rc4 in 2019; replaces an md5-based scheme' },
    },
  ],

  qkmsKeyVersions: [
    { id: 'v1', tenant_id: 't', key_ref: 'key:qkms:11111111-1111-4111-8111-111111111111', version: 1, status: 'superseded', algorithm: 'ECDSA P-256', created_at: at(-400), activated_at: at(-400), superseded_at: at(-30) },
    { id: 'v2', tenant_id: 't', key_ref: 'key:qkms:11111111-1111-4111-8111-111111111111', version: 2, status: 'active', algorithm: 'ML-DSA-65', created_at: at(-30), activated_at: at(-30) },
  ],

  qkmsPolicies: [],

  qkmsRotationJobs: [
    { id: 'j1', tenant_id: 't', key_ref: 'key:qkms:22222222-2222-4222-8222-222222222222', status: 'requested', reason: 'Expired production TLS key', created_at: at(-1), validation_status: 'not-started', previous_version: 1, evidence_json: { priority: 'critical' } },
  ],

  qkmsAuditEvents: [
    { id: 'e1', tenant_id: 't', key_ref: 'key:qkms:11111111-1111-4111-8111-111111111111', event_type: 'rotation_completed', actor_id: 'ops@example.com', event_summary: 'Rotated to ML-DSA-65', created_at: at(-30) },
  ],

  qkmsStorageBackends: [
    { id: 'b1', tenant_id: 't', name: 'AWS CloudHSM', provider: 'AWS CloudHSM', location: 'eu-west-1', protection_level: 'FIPS 140-2 Level 3', hsm_backed: true, status: 'configured', last_verified_at: at(-5) },
  ],

  // G1 — a generated key carrying the SAME fingerprint as a certificate row.
  // Check 9: the two must collapse onto one key.
  generatedKeys: [
    {
      id: '44444444-4444-4444-8444-444444444444', algorithm: 'X25519MLKEM768', bit_length: 256,
      entropy_source: 'QRNG', quality_score: 0.99, fingerprint: 'SHARED-FINGERPRINT-ABC',
      status: 'active', expires_at: at(180), created_at: at(-10), updated_at: at(-10),
      label: JSON.stringify({ key_alias: 'edge-hybrid-kex', owner: 'Platform Team', asset_id: 'a2', environment: 'production', storage_backend: 'HashiCorp Vault' }),
      metadata: {},
    },
  ],

  cryptoInventory: [
    // A discovered private key with NO lifecycle metadata at all — check 7.
    { id: 'c1', name: 'SSH host private key', item_type: 'key', algorithm: 'Ed25519', asset_id: 'a3', discovered_at: at(-3), created_at: at(-3), metadata: {} },
    // An observation ABOUT cryptography — a protocol row — is not a key.
    { id: 'c4', name: 'Protocol: TLSv1.2', item_type: 'protocol', algorithm: 'TLSv1.2', asset_id: 'a2', discovered_at: at(-3), created_at: at(-3), metadata: {} },
    // A key-exchange observation names a negotiated algorithm, not key material.
    { id: 'c5', name: 'Key Exchange: ECDHE prime256v1 (256-bit)', item_type: 'key-exchange', algorithm: 'ECDHE prime256v1 (256-bit)', key_size: 256, asset_id: 'a2', discovered_at: at(-3), created_at: at(-3), metadata: {} },
    // A finding TITLE in the algorithm column must NOT become a key.
    { id: 'c2', name: 'Certificate Revocation: No OCSP Stapling', item_type: 'finding', algorithm: 'Information Disclosure', asset_id: 'a2', discovered_at: at(-3), created_at: at(-3), metadata: {} },
    // A library row must NOT become a key.
    { id: 'c3', name: 'openssl', item_type: 'library', algorithm: 'OpenSSL 3.0.2', asset_id: 'a1', discovered_at: at(-3), created_at: at(-3), metadata: {} },
  ],

  certificates: [
    { id: 'cert1', asset_id: 'a2', subject: 'CN=edge.example.com', algorithm: 'X25519MLKEM768', fingerprint: 'SHARED-FINGERPRINT-ABC', not_before: at(-10), not_after: at(180), status: 'valid', created_at: at(-10), updated_at: at(-10), metadata: {} },
    // Two DIFFERENT certificates on one host with identical subject + algorithm
    // — a renewal. They bind different key material and must stay two keys.
    { id: 'cert3', asset_id: 'a1', subject: 'CN=api.example.com', algorithm: 'ECDSA P-256', key_size: 256, serial: 'AAAA1111', not_before: at(-200), not_after: at(-5), status: 'expired', created_at: at(-200), updated_at: at(-5), metadata: {} },
    { id: 'cert4', asset_id: 'a1', subject: 'CN=api.example.com', algorithm: 'ECDSA P-256', key_size: 256, serial: 'BBBB2222', not_before: at(-5), not_after: at(85), status: 'valid', created_at: at(-5), updated_at: at(-5), metadata: {} },
    // Expiring soon — must NOT be classified as a weak algorithm.
    { id: 'cert2', asset_id: 'a1', subject: 'CN=api.example.com', algorithm: 'ML-DSA-65', not_before: at(-300), not_after: at(20), status: 'valid', is_expiring_soon: true, created_at: at(-300), updated_at: at(-1), metadata: {} },
  ],

  // Two AES-256-GCM events on a1 only. Check 11: they must not be attributed to
  // the AES key on a different asset, and keys without an asset get `null`.
  runtimeEvents: [
    { id: 'r1', asset_id: 'a1', algorithm: 'AES-256-GCM', operation_type: 'encrypt', observed_at: at(-1) },
    { id: 'r2', asset_id: 'a1', algorithm: 'AES-256-GCM', operation_type: 'decrypt', observed_at: at(-1) },
    { id: 'r3', asset_id: 'a2', algorithm: 'RSA-2048', operation_type: 'tls-handshake', observed_at: at(-1) },
  ],

  scannerEvidence: [],
  migrationJobs: [],
  complianceEvidence: [],
  vaultAuditLogs: [],
  qrngEvents: [{ id: 'q1', algorithm: 'QRNG', created_at: at(-10) }],
  scannerAgents: [{ id: 'ag1', status: 'online', updated_at: at(-1) }],
  connectorAccounts: [{ id: 'cn1', status: 'active', updated_at: at(-1) }],
  agentHeartbeats: [{ id: 'h1', observed_at: at(-1) }],
  scanSessions: [{ id: 's1', status: 'completed', completed_at: at(-2), created_at: at(-2) }],
  truncated: false,
  now: NOW,
}

const model = buildQkmsIntelligence(inputs)
const byAlias = (needle: string) => model.keys.find((key) => key.label.toLowerCase().includes(needle.toLowerCase()))

/* ------------------------------------------------------------------ */

console.log('\nQKMS Command Center — invariant check\n')
console.log(`  model: ${model.keys.length} keys, ${model.governance.violations.length} violations, gate ${model.readiness.gate.state}\n`)

/* 1 — ML-DSA / SLH-DSA are post-quantum ---------------------------- */
console.log('1. PQC signature algorithms are not "weak"')
{
  const k1 = byAlias('payments-signing')
  assert(Boolean(k1), 'ML-DSA-65 key is present')
  assert(k1?.posture === 'post-quantum', 'ML-DSA-65 classified post-quantum', `got ${k1?.posture}`)
  assert(k1?.migrationRequirement === 'none', 'ML-DSA-65 requires no migration', `got ${k1?.migrationRequirement}`)
  assert(k1?.rotation !== 'overdue', 'ML-DSA-65 is not forced overdue', `got ${k1?.rotation}`)
  for (const algorithm of ['ML-DSA-44', 'ML-DSA-87', 'SLH-DSA', 'SLH-DSA-SHA2-128s', 'ML-KEM-768']) {
    const classified = classifyKey(algorithm)
    assert(classified.posture === 'post-quantum' && !classified.deprecated, `${algorithm} is post-quantum and not deprecated`, classified.posture)
  }
  // The classical ones must still be caught.
  for (const algorithm of ['ECDSA P-256', 'DSA', 'RSA-2048']) {
    assert(classifyKey(algorithm).quantumVulnerable, `${algorithm} is still flagged quantum-vulnerable`)
  }
  assert(classifyKey('RSA-1024').deprecated, 'RSA-1024 is deprecated')
  assert(classifyKey('3DES').deprecated && classifyKey('RC4').deprecated && classifyKey('MD5').deprecated, 'broken primitives still deprecated')
}

/* 2 — classification reads the algorithm, not the blob -------------- */
console.log('\n2. Classification never reads surrounding metadata')
{
  const k3 = byAlias('tde-master')
  assert(Boolean(k3), 'AES-256-GCM key is present')
  assert(k3?.posture === 'quantum-resistant-symmetric', 'metadata mentioning aes-cbc/rc4/md5 did not deprecate the key', `got ${k3?.posture}`)
  assert(k3?.migrationRequirement === 'none', 'symmetric key requires no PQC migration', `got ${k3?.migrationRequirement}`)
}

/* 3 — AES-256 is not a quantum vulnerability ------------------------ */
console.log('\n3. Symmetric and asymmetric are scored on different threats')
{
  const aes = classifyKey('AES-256-GCM')
  const rsa = classifyKey('RSA-2048')
  assert(aes.posture === 'quantum-resistant-symmetric', 'AES-256-GCM is quantum-resistant', aes.posture)
  assert(!aes.quantumVulnerable, 'AES-256-GCM is not quantum-vulnerable')
  assert(classifyKey('AES-128-GCM').posture === 'weakened-symmetric', 'AES-128 is weakened, not broken')
  assert(rsa.quantumVulnerable && rsa.posture === 'quantum-vulnerable', 'RSA-2048 is quantum-vulnerable')
  assert(classifyKey('SHA3-256').posture === 'quantum-resistant-symmetric', 'SHA3-256 is quantum-resistant')
  // An EC key size is not an RSA modulus. Comparing the two marked every
  // 256-bit curve key "broken against classical attack" and blocked the gate.
  for (const ec of ['ECDSA P-256', 'ECDSA-P256', 'ecdsa-with-SHA256', 'Ed25519', 'X25519']) {
    const c = classifyKey(ec, 256)
    assert(c.posture === 'quantum-vulnerable' && !c.deprecated, `${ec} at 256 bits is quantum-vulnerable, NOT deprecated`, c.posture)
  }
  assert(classifyKey('RSA-1024', 1024).deprecated, 'but RSA-1024 is still deprecated')
  assert(!classifyKey('RSA-2048', 2048).deprecated, 'and RSA-2048 is not deprecated')
}

/* 4 — one risk model, and it adds up -------------------------------- */
console.log('\n4. One risk model; factors reconcile with the headline')
{
  assert(RISK_WEIGHTS.reduce((sum, w) => sum + w.weight, 0) === 100, 'risk weights sum to 100')
  let allBounded = true
  let allReconcile = true
  for (const key of model.keys) {
    if (key.risk.score < 0 || key.risk.score > 100) allBounded = false
    const summed = Math.round(key.risk.factors.reduce((sum, factor) => sum + factor.contribution, 0))
    // The score may be raised by a governance floor, never lowered.
    if (key.risk.score < summed - 1) allReconcile = false
    if (key.risk.factors.length !== RISK_WEIGHTS.length) allReconcile = false
  }
  assert(allBounded, 'every risk score is within [0,100]')
  assert(allReconcile, 'every score is at least the sum of its weighted factors, with all 7 factors present')
  assert(model.keys.every((key) => key.risk.recommendedAction.length > 0), 'every key carries a recommended action')
  assert(model.keys.every((key) => key.risk.confidence >= 0 && key.risk.confidence <= 100), 'confidence is a percentage')
}

/* 5 — governance feeds risk ----------------------------------------- */
console.log('\n5. A governance violation is visible in the key\'s risk')
{
  const k2 = byAlias('legacy-tls')
  assert(Boolean(k2), 'unmanaged RSA key is present')
  const k2Violations = model.governance.violations.filter((row) => row.keyId === k2?.id)
  assert(k2Violations.length > 0, 'unmanaged, unowned, expired, exportable RSA key raises violations', `${k2Violations.length}`)
  assert(k2Violations.some((row) => row.rule === 'missing-owner'), 'missing owner detected')
  assert(k2Violations.some((row) => row.rule === 'unapproved-custody'), 'unapproved custody detected')
  assert(k2Violations.some((row) => row.rule === 'export-not-allowed'), 'exportable production key detected')
  assert(k2Violations.some((row) => row.rule === 'pqc-migration-required'), 'PQC migration requirement detected')
  assert(k2?.risk.level === 'critical', 'the key carrying a critical violation is critical risk', `got ${k2?.risk.level} (${k2?.risk.score})`)
  assert((k2?.violationIds.length ?? 0) === k2Violations.length, 'the key lists exactly its own violations')
  assert(k2?.complianceStatus === 'violation', 'compliance status reflects the violations')

  const k1 = byAlias('payments-signing')
  assert((k1?.violationIds.length ?? 1) === 0, 'the compliant HSM-backed PQC key has no violations')
  assert((k1?.risk.score ?? 100) < (k2?.risk.score ?? 0), 'the compliant key scores below the non-compliant one')
}

/* 6 — counts never mix units ---------------------------------------- */
console.log('\n6. Every headline count reconciles against the key list')
{
  const m = model.metrics
  assert(m.totalKeys === model.keys.length, 'totalKeys == keys.length', `${m.totalKeys} vs ${model.keys.length}`)
  assert(m.deprecatedKeys === model.keys.filter((k) => k.posture === 'deprecated').length, 'deprecatedKeys counts keys')
  assert(m.quantumVulnerableKeys === model.keys.filter((k) => k.posture === 'quantum-vulnerable').length, 'quantumVulnerableKeys counts keys')
  assert(m.pqcReadyKeys === model.keys.filter((k) => k.posture === 'post-quantum').length, 'pqcReadyKeys counts keys')
  assert(m.hybridKeys === model.keys.filter((k) => k.posture === 'hybrid').length, 'hybridKeys counts keys')
  assert(m.criticalRiskKeys === model.keys.filter((k) => k.risk.level === 'critical').length, 'criticalRiskKeys counts keys')
  assert(m.governanceViolations === model.governance.violations.length, 'governanceViolations counts violations, not keys')
  assert(model.governance.backends.every((b) => !/detection rule|handshake|cipher suite|—/i.test(b.name)), 'no finding title is rendered as a storage backend')
  assert(m.keysWithViolations === new Set(model.governance.violations.map((v) => v.keyId)).size, 'keysWithViolations counts distinct keys')
  assert(m.keysWithViolations <= m.governanceViolations, 'keys-with-violations never exceeds violation count')
  const funnelTotal = model.lifecycle.funnel.reduce((sum, row) => sum + row.count, 0)
  assert(funnelTotal === model.keys.length, 'lifecycle funnel sums to the key count', `${funnelTotal} vs ${model.keys.length}`)
  const rotationTotal = Object.values(model.rotation.stateCounts).reduce((sum, count) => sum + count, 0)
  assert(rotationTotal === model.keys.length, 'rotation state counts sum to the key count', `${rotationTotal} vs ${model.keys.length}`)
  const riskTotal = model.risk.distribution.reduce((sum, row) => sum + row.count, 0)
  assert(riskTotal === model.keys.length, 'risk distribution sums to the key count', `${riskTotal} vs ${model.keys.length}`)
}

/* 7 — absence is unknown, not healthy -------------------------------- */
console.log('\n7. Absence of evidence is never a healthy verdict')
{
  const ssh = model.keys.find((key) => key.algorithm === 'Ed25519')
  assert(Boolean(ssh), 'the metadata-less discovered key is present')
  assert(ssh?.rotation === 'unknown', 'a key with no creation/rotation/expiry evidence has UNKNOWN rotation', `got ${ssh?.rotation}`)
  assert(ssh?.lifecycle === 'discovered', 'and DISCOVERED lifecycle', `got ${ssh?.lifecycle}`)
  assert(ssh?.ageDays === null, 'its age is null, not 0')
  assert(ssh?.daysToExpiry === null, 'its days-to-expiry is null, not 0')
  const governed = model.rotation.posture.governedKeys
  assert(governed === model.keys.filter((k) => k.rotation !== 'unknown' && k.rotation !== 'not-applicable').length,
    'rotation health excludes keys with no determinable state', `governed=${governed}`)
  // A key may be `healthy` before its first rotation falls due — but only when
  // a creation date establishes that basis, and the reason must say so rather
  // than implying a rotation happened.
  const healthyNeverRotated = model.keys.filter((k) => k.rotation === 'healthy' && !k.lastRotatedAt)
  assert(healthyNeverRotated.every((k) => k.createdAt !== null), 'a "healthy" key with no rotation still has a creation date to anchor the interval')
  assert(healthyNeverRotated.every((k) => /not yet rotated|first rotation/i.test(k.rotationReason)), 'and its reason states it has not yet been rotated', healthyNeverRotated.map((k) => k.rotationReason)[0] || 'n/a')
  assert(!model.keys.some((k) => k.rotation === 'healthy' && !k.lastRotatedAt && !k.createdAt), 'no key is "healthy" with no rotation basis at all')
}

/* 8 — not-applicable is not zero ------------------------------------- */
console.log('\n8. An empty denominator reports null, never 0%')
{
  const bands = model.readiness.bands
  assert(bands.length > 0, 'readiness bands are produced')
  assert(bands.every((band) => (band.applicable === 0) === (band.percent === null)), 'percent is null exactly when nothing is applicable')
  // The bands must not contradict each other on the same page: if signature
  // readiness applies then hybrid adoption applies too, because a certificate
  // key is asymmetric either way.
  const sigBand = bands.find((band) => band.key === 'ml-dsa')
  const hybridBand = bands.find((band) => band.key === 'hybrid')
  assert(
    !(sigBand && sigBand.applicable > 0 && hybridBand && hybridBand.applicable === 0),
    'hybrid adoption applies whenever signature readiness does',
    `signature=${sigBand?.applicable} hybrid=${hybridBand?.applicable}`,
  )
  assert(!bands.some((band) => band.applicable === 0 && band.percent === 0), 'no band reports 0% from an empty denominator')

  // An estate with only symmetric keys must not report 0% signature readiness.
  const symmetricOnly = buildQkmsIntelligence({
    ...inputs,
    qkmsKeys: [inputs.qkmsKeys[2]], generatedKeys: [], cryptoInventory: [], certificates: [], qkmsKeyVersions: [], qkmsRotationJobs: [],
  })
  const mlDsa = symmetricOnly.readiness.bands.find((band) => band.key === 'ml-dsa')
  assert(mlDsa?.applicable === 0 && mlDsa?.percent === null, 'a symmetric-only estate has N/A signature readiness, not 0%')
  assert(symmetricOnly.metrics.pqcReadinessPercent === null, 'and no overall readiness percentage at all')
  assert(symmetricOnly.metrics.custodyCoveragePercent !== 0 || symmetricOnly.keys.every((k) => k.custody === 'unknown'), 'custody coverage is not a phantom zero')
}

/* 9 — identity is stable and source-independent ---------------------- */
console.log('\n9. One key identity across sources')
{
  const hybrid = model.keys.filter((key) => key.family.includes('ML-KEM') || key.algorithm === 'X25519MLKEM768')
  assert(hybrid.length === 1, 'the generated key and the certificate sharing a fingerprint collapse onto ONE key', `got ${hybrid.length}`)
  const merged = hybrid[0]
  assert(merged.records.length >= 2, 'the merged key lists both source rows', `${merged.records.map((r) => r.table).join(', ')}`)
  assert(merged.id.startsWith('key:fp:'), 'fingerprint-identified keys use a fingerprint id', merged.id)
  assert(merged.posture === 'hybrid', 'X25519MLKEM768 is a hybrid composite', merged.posture)

  // Re-running the engine must produce identical ids.
  const rerun = buildQkmsIntelligence(inputs)
  assert(
    rerun.keys.map((k) => k.id).sort().join('|') === model.keys.map((k) => k.id).sort().join('|'),
    'identities are deterministic across runs',
  )
  assert(new Set(model.keys.map((k) => k.id)).size === model.keys.length, 'no duplicate key ids')

  // Renewal: same host, same subject, same algorithm, different serials.
  // Scoped to the ECDSA pair: cert2 on the same host is an ML-DSA key, and is
  // legitimately a third, different key.
  const renewals = model.keys.filter((key) => key.alias === 'CN=api.example.com' && key.family === 'ECDSA P-256')
  assert(renewals.length === 2, 'two certificates that differ only by serial stay TWO keys', `got ${renewals.length}`)
  assert(new Set(renewals.map((k) => k.id)).size === 2, 'and carry distinct identities', renewals.map((k) => k.id).join(','))
  assert(renewals.every((k) => k.id.startsWith('key:crt:')), 'certificate keys are anchored on the certificate serial', renewals.map((k) => k.id).join(','))

  // Findings and libraries are not keys.
  assert(!model.keys.some((k) => k.algorithm === 'Information Disclosure'), 'a finding title never becomes a key')
  assert(!model.keys.some((k) => k.algorithm.startsWith('OpenSSL')), 'a library row never becomes a key')
  assert(!model.keys.some((k) => k.algorithm.startsWith('TLSv')), 'a protocol observation never becomes a key')
  assert(!model.keys.some((k) => k.algorithm.startsWith('ECDHE')), 'a key-exchange observation never becomes a key')
  assert(model.keys.every((k) => !/detection rule|handshake|cipher suite/i.test(k.label)), 'no key is labelled with a finding title')
}

/* 10 — the migration gate ------------------------------------------- */
console.log('\n10. Six-state migration gate with an explanation')
{
  const gate = model.readiness.gate
  const STATES = ['BLOCKED', 'NOT_READY', 'READY', 'MIGRATION_IN_PROGRESS', 'MIGRATED', 'VALIDATION_REQUIRED']
  assert(STATES.includes(gate.state), 'gate reports one of the six states', gate.state)
  assert(gate.why.length > 40, 'gate carries a substantive explanation')
  assert(gate.prechecks.length >= 10, 'gate evaluates the full precheck set', `${gate.prechecks.length}`)
  assert(gate.prechecks.every((row) => ['pass', 'warn', 'block', 'not-evaluated'].includes(row.decision)), 'every precheck has a decision')
  assert(gate.prechecks.every((row) => row.decision !== 'pass' ? row.requiredAction.length > 0 || row.decision === 'not-evaluated' : true), 'a failing precheck states the required action')
  // This fixture has an unowned key and a deprecated-custody key ⇒ BLOCKED.
  assert(gate.state === 'BLOCKED', 'an estate with an unowned production key is BLOCKED', gate.state)
  assert(gate.blockers.length > 0, 'and names its blockers')
  assert(gate.score !== null && gate.score >= 0 && gate.score <= 100, 'gate score is a bounded percentage')

  // A clean estate must not be blocked.
  const clean = buildQkmsIntelligence({
    ...inputs,
    qkmsKeys: [inputs.qkmsKeys[0], inputs.qkmsKeys[2]],
    generatedKeys: [], certificates: [], cryptoInventory: [], qkmsRotationJobs: [],
  })
  assert(clean.readiness.gate.state !== 'BLOCKED', 'a compliant estate is not blocked', clean.readiness.gate.state)
}

/* 11 — runtime usage attribution ------------------------------------- */
console.log('\n11. Runtime usage is attributed, never broadcast')
{
  const aesKey = byAlias('tde-master')
  assert(aesKey?.runtimeUsage === 2, 'the AES key on a1 gets exactly its own two events', `got ${aesKey?.runtimeUsage}`)
  const ssh = model.keys.find((key) => key.algorithm === 'Ed25519')
  assert(ssh?.runtimeUsage === null || ssh?.runtimeUsage === 0, 'a key on an asset with no matching events is 0 or null, never inflated', `got ${ssh?.runtimeUsage}`)
  const signing = byAlias('payments-signing')
  assert(signing?.runtimeUsage === 0, 'the ML-DSA key on a1 gets none of the AES events', `got ${signing?.runtimeUsage}`)
  assert(model.keys.every((key) => key.runtimeUsage === null || key.runtimeUsage <= inputs.runtimeEvents.length), 'no key claims more events than exist')
  // "Unused" requires measurement to have happened.
  assert(model.lifecycle.attention.unused.every((id) => model.keys.find((k) => k.id === id)?.runtimeUsage === 0), 'only measured-zero keys are reported unused')
}

/* 12 — capabilities never over-promise -------------------------------- */
console.log('\n12. Controls are offered only where the backend can honour them')
{
  const discovered = model.keys.find((key) => key.algorithm === 'Ed25519')
  assert(discovered?.capabilities.revoke === false, 'a scan-discovered key cannot be revoked in place')
  assert(discovered?.capabilities.assignOwner === true, 'but its owner CAN be assigned (the registry row is materialised)')
  assert((discovered?.capabilities.reason.length ?? 0) > 20, 'and the reason is stated for the UI to render')
  const registry = byAlias('payments-signing')
  assert(registry?.capabilities.revoke === true, 'a registry-backed key can be revoked')
  assert(model.keys.every((key) => typeof key.capabilities.reason === 'string' && key.capabilities.reason.length > 0), 'every key explains its capability set')
}

/* 13 — evidence and versions ------------------------------------------ */
console.log('\n13. Evidence, versions and audit are traceable')
{
  assert(model.keys.every((key) => key.evidence.length > 0), 'every key carries at least one evidence reference')
  assert(model.keys.every((key) => key.evidence.every((ref) => ref.table && ref.recordId)), 'every reference names a table and a record')
  const versioned = byAlias('payments-signing')
  assert((versioned?.versions.length ?? 0) === 2, 'the version chain is read from qkms_key_versions', `${versioned?.versions.length}`)
  assert(versioned?.version === 2, 'the current version is the highest recorded')
  assert(versioned?.versions[1].previousVersionId === `${versioned?.id}#v1`, 'versions link to their predecessor')
  assert((versioned?.auditTrail.length ?? 0) > 0, 'audit events attach to the key by canonical ref')
  assert(model.rotation.jobs.every((job) => job.keyId === null || model.keys.some((key) => key.id === job.keyId)), 'every rotation job resolves to a real key')
  const job = model.rotation.jobs[0]
  assert(job?.allowedTransitions.length > 0 && !job.allowedTransitions.includes('completed'), 'a requested job cannot jump straight to completed', job?.allowedTransitions.join(','))
}

/* 14 — entropy vocabulary ---------------------------------------------- */
console.log('\n14. Entropy posture is evidence-gated')
{
  const entropy = model.governance.entropy
  assert(['detected', 'configured', 'available', 'not-available'].includes(entropy.status), 'entropy reports one of the four states', entropy.status)
  assert(entropy.status === 'detected', 'QRNG events + a QRNG-attributed key ⇒ detected', entropy.status)
  const noEntropy = buildQkmsIntelligence({ ...inputs, qrngEvents: [], generatedKeys: [] })
  assert(noEntropy.governance.entropy.status !== 'detected', 'without QRNG evidence the status is not "detected"', noEntropy.governance.entropy.status)
  assert(noEntropy.governance.entropy.detail.length > 30, 'and the state is explained')
}

/* 15 — empty tenant ----------------------------------------------------- */
console.log('\n15. An empty tenant produces an honest zero state')
{
  const empty = buildQkmsIntelligence({
    assets: [], qkmsKeys: [], qkmsKeyVersions: [], qkmsPolicies: [], qkmsRotationJobs: [],
    qkmsAuditEvents: [], qkmsStorageBackends: [], generatedKeys: [], cryptoInventory: [],
    certificates: [], runtimeEvents: [], scannerEvidence: [], migrationJobs: [],
    complianceEvidence: [], vaultAuditLogs: [], qrngEvents: [], scannerAgents: [],
    connectorAccounts: [], agentHeartbeats: [], scanSessions: [], truncated: false, now: NOW,
  })
  assert(empty.hasData === false, 'hasData is false')
  assert(empty.metrics.totalKeys === 0, 'no keys are invented')
  assert(empty.metrics.pqcReadinessPercent === null, 'readiness is null, not 100% and not 0%')
  assert(empty.metrics.rotationHealthPercent === null, 'rotation health is null, not 100%')
  assert(empty.metrics.custodyCoveragePercent === null, 'custody coverage is null')
  assert(empty.metrics.averageRiskScore === null, 'average risk is null, not 0')
  assert(empty.readiness.gate.state === 'NOT_READY', 'the gate is NOT_READY, never READY or MIGRATED', empty.readiness.gate.state)
  assert(empty.governance.entropy.status === 'not-available', 'entropy is not-available')
  assert(empty.telemetry.pipelineStatus === 'no-sources', 'the pipeline says it has no sources')
}

/* ------------------------------------------------------------------ */

console.log(`\n${failures === 0 ? '✓ ALL CHECKS PASSED' : `✗ ${failures} CHECK(S) FAILED`}\n`)
process.exit(failures === 0 ? 0 : 1)
