/**
 * Enterprise Governance Command Layer — offline invariant check.
 *
 * Exercises the PURE isomorphic engine (no Supabase / server required) and
 * asserts the guarantees the four pages depend on:
 *
 *   1. Catalog integrity: every requirement points at a control that exists.
 *   2. An EMPTY tenant produces no fabricated compliance. Every control is
 *      "not assessed" with a NULL score, and the headline score is null — never
 *      0 (reads as total failure) and never 100 (reads as full compliance).
 *   3. A framework with no measurable control never borrows another number.
 *   4. Estate figures are MIRRORED from the canonical snapshot, never recounted,
 *      so Governance and Quantum Readiness cannot disagree.
 *   5. The compliance score covers MEASURED controls only, and control coverage
 *      publishes the denominator that makes that honest.
 *   6. Policy violations and the control failures they drive are ONE count, not
 *      two — the control reads its subjects from the policy engine.
 *   7. Unmeasured populations never score: a rule with nothing to evaluate is
 *      `measured: false` with a null adherence, not 100%.
 *   8. Evidence integrity states are honest: unavailable ≠ unanchored ≠ verified,
 *      and a changed record reports `mismatch` rather than silently re-verifying.
 *   9. A live, approved exception scopes a control out — and an EXPIRED one puts
 *      it straight back in scope and raises its own gap.
 *  10. The reconciliation report names a canonical source for every estate figure.
 *  11. The 30-day trend never draws an unobserved day as a measured zero.
 *  12. Cross-view projections describe the SAME model (no view can disagree).
 *
 * Run: npx tsx tools/governance-check.ts
 */

import {
  CATALOG_ORPHANS,
  CONTROL_CATALOG,
  FRAMEWORK_CATALOG,
  POLICY_CATALOG,
  REQUIREMENT_CATALOG,
  buildGovernanceIntelligence,
  buildSubjects,
  contentDigest,
  type CanonicalSnapshot,
  type GovernanceInputs,
  type Row,
} from '../src/lib/governance'
import { buildAssetComplianceScope } from '../src/lib/governance/asset-scope'
import { buildAssetComplianceDocument } from '../src/services/reporting/ComplianceDocument'
import { exportDocument } from '../src/services/reporting/exporters/DocumentExporters'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const NOW = Date.parse('2026-08-18T00:00:00Z')
const daysAgo = (days: number) => new Date(NOW - days * 86_400_000).toISOString()

/* ------------------------------------------------------------------ */
/* Fixtures                                                            */
/* ------------------------------------------------------------------ */

const EMPTY_SNAPSHOT: CanonicalSnapshot = {
  hasData: false,
  scores: { quantumReadiness: 0, quantumRisk: 0, pqcAdoption: 0 },
  inventory: {
    assetsAssessed: 0,
    certificatesAnalyzed: 0,
    keysDiscovered: 0,
    cryptoComponents: 0,
    vulnerableComponents: 0,
    pqcReadyComponents: 0,
    quantumVulnerableAssets: 0,
    pqcReadyAssets: 0,
    hybridAssets: 0,
  },
  riskDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
  telemetry: { latestRuntimeEventAt: null, latestEventAt: null },
}

function emptyInputs(): GovernanceInputs {
  return {
    now: NOW,
    snapshot: EMPTY_SNAPSHOT,
    portfolioAssets: [],
    assets: [],
    cryptoInventory: [],
    certificates: [],
    generatedKeys: [],
    runtimeEvents: [],
    vaultFiles: [],
    scanSessions: [],
    scanResults: [],
    cryptoExposures: [],
    vulnerabilities: [],
    scannerAlerts: [],
    scannerEvidence: [],
    scannerAgents: [],
    connectorAccounts: [],
    agentHeartbeats: [],
    migrationJobs: [],
    migrationPlans: [],
    migrationEvents: [],
    complianceEvidence: [],
    auditLogs: [],
    vaultAuditLogs: [],
    securityEvents: [],
    userSecurityEvents: [],
    authEvents: [],
    policyOverrides: null,
    evidenceAnchors: null,
    controlAssessments: null,
    truncated: false,
    sourceCounts: {},
    absentSources: [],
  }
}

/* A populated tenant: 3 assets, mixed crypto, one expired certificate, one
 * weak RSA key, runtime telemetry, findings, audit records and an attestation. */
const POPULATED_SNAPSHOT: CanonicalSnapshot = {
  hasData: true,
  scores: { quantumReadiness: 42, quantumRisk: 58, pqcAdoption: 33.3 },
  inventory: {
    assetsAssessed: 3,
    certificatesAnalyzed: 2,
    keysDiscovered: 2,
    cryptoComponents: 6,
    vulnerableComponents: 4,
    pqcReadyComponents: 2,
    quantumVulnerableAssets: 2,
    pqcReadyAssets: 1,
    hybridAssets: 0,
  },
  riskDistribution: { critical: 3, high: 5, medium: 2, low: 1 },
  telemetry: { latestRuntimeEventAt: daysAgo(0), latestEventAt: daysAgo(0) },
}

const assets: Row[] = [
  { id: 'a1', name: 'checkout.example.com', type: 'web-service', environment: 'production', service_owner: 'Payments', criticality: 'critical', status: 'active', metadata: { internet_facing: true }, created_at: daysAgo(200), updated_at: daysAgo(1) },
  { id: 'a2', name: 'identity.example.com', type: 'identity-provider', environment: 'production', service_owner: 'Identity', criticality: 'high', status: 'active', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
  // No service_owner ⇒ fails CTL-INV-03.
  { id: 'a3', name: 'batch-reporting', type: 'service', environment: 'staging', criticality: 'low', status: 'active', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
]

const cryptoInventory: Row[] = [
  { id: 'ci1', asset_id: 'a1', item_type: 'tls', name: 'TLS key exchange', algorithm: 'RSA-2048', key_size: 2048, protocol: 'TLS', is_vulnerable: true, is_quantum_safe: false, discovered_at: daysAgo(3), created_at: daysAgo(3) },
  { id: 'ci2', asset_id: 'a1', item_type: 'signature', name: 'Cert signature', algorithm: 'ECDSA P-256', key_size: 256, protocol: 'x509', is_vulnerable: true, is_quantum_safe: false, discovered_at: daysAgo(3), created_at: daysAgo(3) },
  { id: 'ci3', asset_id: 'a2', item_type: 'kem', name: 'PQ key establishment', algorithm: 'ML-KEM-768', key_size: 768, protocol: 'TLS', is_vulnerable: false, is_quantum_safe: true, discovered_at: daysAgo(3), created_at: daysAgo(3) },
  { id: 'ci4', asset_id: 'a2', item_type: 'signature', name: 'PQ signature', algorithm: 'ML-DSA-65', key_size: 0, protocol: 'x509', is_vulnerable: false, is_quantum_safe: true, discovered_at: daysAgo(3), created_at: daysAgo(3) },
  // Deliberately forbidden: SHA-1 ⇒ CTL-ALG-01 must fail.
  { id: 'ci5', asset_id: 'a1', item_type: 'hash', name: 'Legacy digest', algorithm: 'SHA-1', key_size: 0, protocol: '', is_vulnerable: true, is_quantum_safe: false, discovered_at: daysAgo(3), created_at: daysAgo(3) },
  // Unclassifiable ⇒ CTL-INV-02 must fail on it.
  { id: 'ci6', asset_id: 'a3', item_type: 'unknown', name: 'Unidentified primitive', algorithm: '', key_size: 0, protocol: '', is_vulnerable: false, is_quantum_safe: false, discovered_at: daysAgo(3), created_at: daysAgo(3) },
]

const certificates: Row[] = [
  { id: 'cert1', asset_id: 'a1', name: 'checkout.example.com', subject: 'checkout.example.com', issuer: "Let's Encrypt", algorithm: 'SHA256withRSA', key_size: 2048, status: 'active', not_after: daysAgo(-120), is_quantum_safe: false, is_expiring_soon: false, created_at: daysAgo(90), updated_at: daysAgo(2) },
  // Expired ⇒ CTL-CRT-02 must fail, and an audit event must be emitted.
  { id: 'cert2', asset_id: 'a2', name: 'identity.example.com', subject: 'identity.example.com', issuer: 'Internal CA', algorithm: 'SHA1withRSA', key_size: 2048, status: 'active', not_after: daysAgo(10), is_quantum_safe: false, is_expiring_soon: true, created_at: daysAgo(400), updated_at: daysAgo(2) },
]

const generatedKeys: Row[] = [
  { id: 'k1', algorithm: 'ML-KEM-1024', bit_length: 1024, entropy_source: 'qrng', quality_score: 98, status: 'active', expires_at: daysAgo(-200), revoked_at: null, rotated_from: null, label: { purpose: 'vault-dek' }, metadata: {}, created_at: daysAgo(30), updated_at: daysAgo(30) },
  // No entropy source and no expiry ⇒ fails CTL-KEY-02 and CTL-KEY-03.
  { id: 'k2', algorithm: 'RSA-2048', bit_length: 2048, entropy_source: '', quality_score: null, status: 'active', expires_at: null, revoked_at: null, rotated_from: null, label: {}, metadata: {}, created_at: daysAgo(500), updated_at: daysAgo(500) },
]

const runtimeEvents: Row[] = [
  { id: 're1', asset_id: 'a1', asset_name: 'checkout.example.com', host: 'checkout.example.com', event_type: 'tls_handshake', operation_type: 'handshake', severity: 'low', protocol: 'https', tls_version: 'TLSv1.3', cipher_suite: 'TLS_AES_256_GCM_SHA384', key_exchange_algorithm: 'X25519', algorithm: 'X25519', key_size: 256, is_pqc: false, is_legacy: false, downgrade_detected: false, shadow_crypto: false, observed_at: daysAgo(0), created_at: daysAgo(0) },
  // TLS 1.0 ⇒ CTL-TLS-01 must fail.
  { id: 're2', asset_id: 'a2', asset_name: 'identity.example.com', host: 'identity.example.com', event_type: 'tls_handshake', operation_type: 'handshake', severity: 'high', protocol: 'https', tls_version: 'TLSv1.0', cipher_suite: 'TLS_RSA_WITH_AES_128_CBC_SHA', key_exchange_algorithm: 'RSA', algorithm: 'RSA', key_size: 2048, is_pqc: false, is_legacy: true, downgrade_detected: false, shadow_crypto: false, observed_at: daysAgo(0), created_at: daysAgo(0) },
]

function populatedInputs(overrides: Partial<GovernanceInputs> = {}): GovernanceInputs {
  return {
    ...emptyInputs(),
    snapshot: POPULATED_SNAPSHOT,
    portfolioAssets: [
      { id: 'a1', name: 'checkout.example.com', type: 'web-service', environment: 'production', owner: 'Payments', businessCriticality: 'critical', internetFacing: true, riskScore: 78, readinessScore: 30, posture: 'vulnerable', postureLabel: 'Quantum-Vulnerable', severityCounts: { critical: 2, high: 1, medium: 0, low: 0 }, lastEvidenceAt: daysAgo(1) },
      { id: 'a2', name: 'identity.example.com', type: 'identity-provider', environment: 'production', owner: 'Identity', businessCriticality: 'high', internetFacing: true, riskScore: 55, readinessScore: 60, posture: 'hybrid', postureLabel: 'Hybrid / In-Progress', severityCounts: { critical: 1, high: 2, medium: 1, low: 0 }, lastEvidenceAt: daysAgo(1) },
      { id: 'a3', name: 'batch-reporting', type: 'service', environment: 'staging', owner: '', businessCriticality: 'low', internetFacing: false, riskScore: 12, readinessScore: 40, posture: 'unknown', postureLabel: 'Not assessed', severityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, lastEvidenceAt: daysAgo(30) },
    ],
    assets,
    cryptoInventory,
    certificates,
    generatedKeys,
    runtimeEvents,
    scanSessions: [
      { id: 's1', status: 'completed', progress: 100, total_assets: 3, scanned_assets: 3, findings_count: 7, target_scope: 'tenant', started_at: daysAgo(3), completed_at: daysAgo(3), created_at: daysAgo(3), updated_at: daysAgo(3) },
    ],
    scanResults: [
      { id: 'sr1', asset_id: 'a1', finding_type: 'quantum_vulnerable_algorithm', algorithm: 'RSA-2048', threat_level: 'critical', description: 'RSA key exchange is quantum-vulnerable', created_at: daysAgo(3) },
      { id: 'sr2', asset_id: 'a2', finding_type: 'weak_protocol', algorithm: 'TLS 1.0', threat_level: 'high', description: 'Deprecated protocol version negotiated', created_at: daysAgo(3) },
    ],
    vulnerabilities: [
      // Open for 120 days ⇒ breaches the 30-day SLA in CTL-VUL-01.
      { id: 'v1', asset_id: 'a1', title: 'Deprecated cipher suite in use', description: 'CBC mode suite', severity: 'high', status: 'open', source: 'scanner', created_at: daysAgo(120), updated_at: daysAgo(5) },
      { id: 'v2', asset_id: 'a2', title: 'Certificate signed with SHA-1', description: '', severity: 'critical', status: 'resolved', source: 'scanner', created_at: daysAgo(60), updated_at: daysAgo(2) },
    ],
    scannerAgents: [{ id: 'ag1', name: 'collector-01', status: 'online', hostname: 'host-01', platform: 'linux', last_seen_at: daysAgo(0), created_at: daysAgo(60), updated_at: daysAgo(0) }],
    migrationJobs: [
      { id: 'mj1', asset_id: 'a2', name: 'Migrate identity TLS', job_type: 'algorithm', status: 'completed', target_algorithm: 'ML-KEM-768', progress: 100, started_at: daysAgo(20), completed_at: daysAgo(15), created_at: daysAgo(25), updated_at: daysAgo(15) },
    ],
    complianceEvidence: [
      { id: 'ce1', asset_id: 'a1', framework: 'ISO/IEC 27001', control_id: 'A.8.24', evidence_type: 'policy_review', description: 'Annual cryptographic policy review', status: 'compliant', created_at: daysAgo(20), updated_at: daysAgo(20) },
    ],
    auditLogs: [
      { id: 'al1', action: 'asset_created', entity_type: 'asset', entity_id: 'a1', details: {}, ip_address: '10.0.0.1', created_at: daysAgo(1) },
      { id: 'al2', action: 'login_failed', entity_type: 'session', entity_id: null, details: { reason: 'invalid password' }, ip_address: '10.0.0.9', created_at: daysAgo(1) },
    ],
    vaultAuditLogs: [{ id: 'val1', event_type: 'file_encrypted', resource_type: 'vault_file', result: 'success', created_at: daysAgo(2) }],
    vaultFiles: [
      { id: 'vf1', original_filename: 'contract.pdf', mime_type: 'application/pdf', original_size: 1024, encryption_status: 'encrypted', encryption_algorithm: 'AES-256-GCM', signature_status: 'valid', is_deleted: false, is_latest: true, uploaded_at: daysAgo(5), encrypted_at: daysAgo(5), created_at: daysAgo(5), updated_at: daysAgo(5) },
      // Still pending ⇒ CTL-DAT-01 must fail on it.
      { id: 'vf2', original_filename: 'draft.docx', mime_type: 'application/docx', original_size: 512, encryption_status: 'pending', encryption_algorithm: '', signature_status: '', is_deleted: false, is_latest: true, uploaded_at: daysAgo(1), encrypted_at: null, created_at: daysAgo(1), updated_at: daysAgo(1) },
    ],
    sourceCounts: { assets: 3, crypto_inventory: 6, certificates: 2 },
    ...overrides,
  }
}

/* ------------------------------------------------------------------ */
/* 1. Catalog integrity                                                */
/* ------------------------------------------------------------------ */

console.log('\n[1] Catalog integrity')
assert(CATALOG_ORPHANS.length === 0, 'every requirement maps to a control that exists', CATALOG_ORPHANS.join(', '))
assert(CONTROL_CATALOG.length > 0 && FRAMEWORK_CATALOG.length > 0 && REQUIREMENT_CATALOG.length > 0, 'catalog is populated', `${FRAMEWORK_CATALOG.length} frameworks · ${REQUIREMENT_CATALOG.length} requirements · ${CONTROL_CATALOG.length} controls`)
assert(new Set(CONTROL_CATALOG.map((c) => c.id)).size === CONTROL_CATALOG.length, 'control ids are unique')
assert(new Set(REQUIREMENT_CATALOG.map((r) => r.id)).size === REQUIREMENT_CATALOG.length, 'requirement ids are unique')
assert(new Set(FRAMEWORK_CATALOG.map((f) => f.id)).size === FRAMEWORK_CATALOG.length, 'framework ids are unique')
assert(
  REQUIREMENT_CATALOG.every((r) => FRAMEWORK_CATALOG.some((f) => f.id === r.frameworkId)),
  'every requirement belongs to a framework that exists',
)
assert(
  CONTROL_CATALOG.every((c) => POLICY_CATALOG.some((p) => p.controlIds.includes(c.id)) || c.evaluator !== 'policy'),
  'every policy rule references a real control',
  POLICY_CATALOG.filter((p) => p.controlIds.some((id) => !CONTROL_CATALOG.some((c) => c.id === id))).map((p) => p.id).join(', '),
)

/* ------------------------------------------------------------------ */
/* 2. Empty tenant fabricates nothing                                  */
/* ------------------------------------------------------------------ */

console.log('\n[2] Empty tenant fabricates nothing')
const empty = buildGovernanceIntelligence(emptyInputs())

assert(empty.scores.compliance.value === null, 'compliance score is NULL, not 0 and not 100')
assert(empty.scores.compliance.measured === false, 'compliance score reports measured: false')
assert(
  empty.controls.every((c) => c.status === 'not-assessed' && c.score === null),
  'every control is not-assessed with a null score',
  empty.controls.filter((c) => c.status !== 'not-assessed').map((c) => `${c.code}=${c.status}`).join(', '),
)
assert(empty.totals.controlsCompliant === 0 && empty.totals.controlsFailing === 0, 'no control is claimed compliant or failing')
assert(empty.totals.controlsUnassessed === empty.totals.controls, 'all controls counted as unassessed')
assert(
  empty.frameworks.every((f) => f.score === null && f.measured === false),
  'no framework has a score',
  empty.frameworks.filter((f) => f.score !== null).map((f) => f.shortName).join(', '),
)
assert(empty.evidence.length === 0 && empty.auditEvents.length === 0, 'no evidence or audit events invented')
assert(empty.hasData === false, 'hasData is false')
assert(empty.telemetry.pipelineStatus === 'no-sources', 'pipeline status reports no sources', empty.telemetry.pipelineStatus)
assert(
  empty.scores.controlCoverage.value === 0 && empty.scores.controlCoverage.measured === true,
  'control coverage IS measured at 0% — the honest statement that nothing can be assessed',
)

/* ------------------------------------------------------------------ */
/* 3. Frameworks never borrow a score                                  */
/* ------------------------------------------------------------------ */

console.log('\n[3] Frameworks never borrow another number')
const model = buildGovernanceIntelligence(populatedInputs())
const measuredFrameworks = model.frameworks.filter((f) => f.measured)
const unmeasuredFrameworks = model.frameworks.filter((f) => !f.measured)
const transitionReferences = ['nist-ir-8547', 'nist-nccoe-pqc', 'eo-14412', 'omb-m-26-15', 'fips-pqc', 'cnsa-2']
for (const id of transitionReferences) {
  const source = model.frameworks.find((f) => f.id === id)
  const requirements = model.requirements.filter((r) => r.frameworkId === id)
  assert(source?.status === 'not-assessed' && source.score === null && requirements.length > 0 &&
    requirements.every((r) => r.status === 'not-assessed' && r.score === null && r.lastValidatedAt === null),
  `${id} stays unassessed even when the tenant has related measured controls`)
}

assert(unmeasuredFrameworks.every((f) => f.score === null), 'unmeasured frameworks keep a null score')
assert(measuredFrameworks.length > 0, 'at least one framework is measurable on a populated tenant', `${measuredFrameworks.length}`)
const distinctScores = new Set(measuredFrameworks.map((f) => f.score))
assert(
  distinctScores.size > 1 || measuredFrameworks.length === 1,
  'measured frameworks do not all collapse to one identical number (the retired fallback bug)',
  [...distinctScores].join(', '),
)
assert(
  model.frameworks.every((f) => f.coverage >= 0 && f.coverage <= 100),
  'framework coverage is a real percentage of assessable requirements',
)

/* ------------------------------------------------------------------ */
/* 4. Estate figures are mirrored, never recounted                     */
/* ------------------------------------------------------------------ */

console.log('\n[4] Estate figures mirror the canonical snapshot')
assert(model.totals.cryptoComponents === POPULATED_SNAPSHOT.inventory.cryptoComponents, 'cryptoComponents mirrored', `${model.totals.cryptoComponents}`)
assert(model.totals.vulnerableComponents === POPULATED_SNAPSHOT.inventory.vulnerableComponents, 'vulnerableComponents mirrored', `${model.totals.vulnerableComponents}`)
assert(model.totals.pqcReadyComponents === POPULATED_SNAPSHOT.inventory.pqcReadyComponents, 'pqcReadyComponents mirrored')
assert(model.totals.certificates === POPULATED_SNAPSHOT.inventory.certificatesAnalyzed, 'certificates mirrored')
assert(model.totals.keys === POPULATED_SNAPSHOT.inventory.keysDiscovered, 'keys mirrored')
assert(model.totals.criticalFindings === POPULATED_SNAPSHOT.riskDistribution.critical, 'criticalFindings mirrored')
assert(model.scores.quantumReadiness.value === Math.round(POPULATED_SNAPSHOT.scores.quantumReadiness), 'quantumReadiness mirrored')
assert(model.scores.quantumRisk.value === Math.round(POPULATED_SNAPSHOT.scores.quantumRisk), 'quantumRisk mirrored')

const pqcAdoptionControl = model.controls.find((c) => c.id === 'CTL-PQC-03')
assert(
  pqcAdoptionControl?.score === Math.round(POPULATED_SNAPSHOT.scores.pqcAdoption),
  'CTL-PQC-03 publishes the canonical PQC adoption value rather than deriving a rival one',
  `${pqcAdoptionControl?.score} vs ${Math.round(POPULATED_SNAPSHOT.scores.pqcAdoption)}`,
)

/* ------------------------------------------------------------------ */
/* 5. Score covers measured controls only                              */
/* ------------------------------------------------------------------ */

console.log('\n[5] Compliance score covers measured controls only')
const measured = model.controls.filter((c) => c.measured && c.score !== null && c.status !== 'not-applicable')
const totalWeight = measured.reduce((sum, c) => sum + c.weight, 0)
const expected = Math.round(measured.reduce((sum, c) => sum + (c.score ?? 0) * c.weight, 0) / totalWeight)
assert(model.scores.compliance.value === expected, 'compliance score equals the weighted mean over measured controls', `${model.scores.compliance.value} vs ${expected}`)
assert(model.scores.compliance.denominator === model.controls.filter((c) => c.status !== 'not-applicable').length, 'denominator is the in-scope control count')
assert(model.scores.compliance.numerator === measured.length, 'numerator is the measured control count')
assert(
  model.scores.controlCoverage.value === Math.round((measured.length / model.scores.compliance.denominator) * 100),
  'control coverage states what share of the control set is assessable',
)
assert(
  model.controls.some((c) => !c.measured),
  'the populated fixture still has unmeasured controls (so the exclusion is genuinely exercised)',
  `${model.controls.filter((c) => !c.measured).length} unmeasured`,
)

/* ------------------------------------------------------------------ */
/* 6. Policy violations and control failures are ONE count             */
/* ------------------------------------------------------------------ */

console.log('\n[6] Policy violations and control failures are one count')
const forbiddenPolicy = model.policies.find((p) => p.id === 'POL-ALG-FORBIDDEN')!
const forbiddenControl = model.controls.find((c) => c.id === 'CTL-ALG-01')!
assert(forbiddenPolicy.violations > 0, 'SHA-1 in the inventory produces a forbidden-algorithm violation', `${forbiddenPolicy.violations}`)
assert(forbiddenControl.status === 'partial' || forbiddenControl.status === 'non-compliant', 'CTL-ALG-01 fails as a result', forbiddenControl.status)
assert(
  forbiddenControl.population === forbiddenPolicy.evaluated,
  'the control evaluates exactly the population the policy did — one count, not two',
  `${forbiddenControl.population} vs ${forbiddenPolicy.evaluated}`,
)
assert(
  forbiddenControl.failing === forbiddenPolicy.violations,
  'the control failure count equals the policy violation count',
  `${forbiddenControl.failing} vs ${forbiddenPolicy.violations}`,
)

const tlsPolicy = model.policies.find((p) => p.id === 'POL-TLS-MIN')!
assert(tlsPolicy.violations > 0, 'TLS 1.0 endpoint produces a minimum-version violation', `${tlsPolicy.violations}`)
assert(
  tlsPolicy.evaluated === 2,
  'only endpoints with a MEASURED protocol version enter the TLS population',
  `${tlsPolicy.evaluated}`,
)

/* ------------------------------------------------------------------ */
/* 7. Unmeasured populations never score                               */
/* ------------------------------------------------------------------ */

console.log('\n[7] Unmeasured populations never score')
const emptyModel = buildGovernanceIntelligence(emptyInputs())
assert(
  emptyModel.policies.every((p) => p.measured === false && p.adherence === null),
  'on an empty tenant every rule is measured:false with a null adherence — never 100%',
  emptyModel.policies.filter((p) => p.adherence !== null).map((p) => `${p.id}=${p.adherence}`).join(', '),
)
assert(
  emptyModel.policies.every((p) => p.violations === 0 && p.evaluated === 0),
  'no rule invents violations or an evaluated population',
)

// A rule the tenant disabled must report measured:false, not silent compliance.
const disabledModel = buildGovernanceIntelligence(
  populatedInputs({
    policyOverrides: [{ policy_id: 'POL-ALG-FORBIDDEN', enforcement: 'disabled', severity: 'critical', parameters: {}, updated_at: daysAgo(1), updated_by: 'auditor@example.com' }],
  }),
)
const disabledPolicy = disabledModel.policies.find((p) => p.id === 'POL-ALG-FORBIDDEN')!
assert(disabledPolicy.enforcement === 'disabled', 'tenant override switches the rule off')
assert(disabledPolicy.measured === false && disabledPolicy.adherence === null, 'a disabled rule reports measured:false, not 100% adherence')
assert(disabledPolicy.violations === 0, 'a disabled rule reports no violations (nothing was evaluated)')
assert(
  disabledModel.controls.find((c) => c.id === 'CTL-ALG-01')!.status === 'not-assessed',
  'the control it drives becomes not-assessed rather than silently compliant',
  disabledModel.controls.find((c) => c.id === 'CTL-ALG-01')!.status,
)
assert(disabledPolicy.tenantConfigured === true, 'the override is flagged as tenant-configured')

/* ------------------------------------------------------------------ */
/* 8. Evidence integrity states are honest                             */
/* ------------------------------------------------------------------ */

console.log('\n[8] Evidence integrity is honest')
assert(
  model.evidence.every((e) => e.integrity.state === 'unavailable'),
  'with no anchor store every record reports "unavailable" — never a false verified',
  [...new Set(model.evidence.map((e) => e.integrity.state))].join(', '),
)

// Anchor store present but empty ⇒ unanchored.
const unanchored = buildGovernanceIntelligence(populatedInputs({ evidenceAnchors: [] }))
assert(
  unanchored.evidence.every((e) => e.integrity.state === 'unanchored'),
  'with an empty anchor store every record reports "unanchored"',
)

// Anchor the attestation with its true digest ⇒ verified.
const attestation = unanchored.evidence.find((e) => e.id.startsWith('attestation:'))!
const trueDigest = attestation.integrity.digest
const anchoredModel = buildGovernanceIntelligence(
  populatedInputs({ evidenceAnchors: [{ evidence_id: attestation.id, digest: trueDigest, algorithm: 'SHA3-256', anchored_at: daysAgo(19) }] }),
)
const verified = anchoredModel.evidence.find((e) => e.id === attestation.id)!
assert(verified.integrity.state === 'verified', 'a matching anchored digest verifies', verified.integrity.state)
assert(verified.integrity.anchoredAt !== null, 'the anchor timestamp is carried through')
assert(!/immutable/i.test(verified.integrity.assurance), 'the assurance wording never claims immutability', verified.integrity.assurance.slice(0, 60))

// Change the source row ⇒ digest must no longer match.
const tampered = buildGovernanceIntelligence(
  populatedInputs({
    evidenceAnchors: [{ evidence_id: attestation.id, digest: trueDigest, algorithm: 'SHA3-256', anchored_at: daysAgo(19) }],
    complianceEvidence: [
      { id: 'ce1', asset_id: 'a1', framework: 'ISO/IEC 27001', control_id: 'A.8.24', evidence_type: 'policy_review', description: 'Annual cryptographic policy review', status: 'non-compliant', created_at: daysAgo(20), updated_at: daysAgo(20) },
    ],
  }),
)
const mismatched = tampered.evidence.find((e) => e.id === attestation.id)!
assert(mismatched.integrity.state === 'mismatch', 'a changed source record reports "mismatch"', mismatched.integrity.state)
assert(mismatched.integrity.digest !== trueDigest, 'the recomputed digest genuinely differs')
assert(
  tampered.controls.find((c) => c.id === 'CTL-AUD-03')!.severity === 'critical',
  'a digest mismatch escalates the integrity control to critical',
)
assert(contentDigest({ a: 1, b: 2 }) === contentDigest({ b: 2, a: 1 }), 'the digest is canonical (key order independent)')

/* ------------------------------------------------------------------ */
/* 9. Exceptions scope out — and expire back in                        */
/* ------------------------------------------------------------------ */

console.log('\n[9] Exceptions scope out, and expire back in')
const withException = buildGovernanceIntelligence(
  populatedInputs({
    controlAssessments: [
      { id: 'ga1', control_id: 'CTL-ALG-01', owner: 'Crypto Team', exception_reason: 'Legacy digest retired in Q4', exception_approved_by: 'CISO', exception_approved_at: daysAgo(10), exception_expires_at: daysAgo(-90), updated_at: daysAgo(10) },
    ],
  }),
)
const excepted = withException.controls.find((c) => c.id === 'CTL-ALG-01')!
assert(excepted.status === 'not-applicable', 'a live approved exception scopes the control out', excepted.status)
assert(excepted.score === null, 'a scoped-out control carries no score')
assert(
  withException.scores.compliance.denominator === model.scores.compliance.denominator - 1,
  'the scoped-out control leaves the compliance denominator',
)
assert(excepted.owner === 'Crypto Team', 'the recorded owner is carried through')

const expiredException = buildGovernanceIntelligence(
  populatedInputs({
    controlAssessments: [
      { id: 'ga1', control_id: 'CTL-ALG-01', owner: 'Crypto Team', exception_reason: 'Legacy digest retired in Q4', exception_approved_by: 'CISO', exception_approved_at: daysAgo(200), exception_expires_at: daysAgo(30), updated_at: daysAgo(200) },
    ],
  }),
)
const backInScope = expiredException.controls.find((c) => c.id === 'CTL-ALG-01')!
assert(backInScope.status !== 'not-applicable', 'an EXPIRED exception puts the control straight back in scope', backInScope.status)
assert(
  expiredException.gaps.some((g) => g.kind === 'expired-exception'),
  'an expired exception raises its own gap',
)
assert(
  expiredException.controls.find((c) => c.id === 'CTL-GOV-02')!.status !== 'compliant',
  'CTL-GOV-02 (exception governance) fails while an exception is expired',
)

/* ------------------------------------------------------------------ */
/* 10. Reconciliation names a canonical source for every figure        */
/* ------------------------------------------------------------------ */

console.log('\n[10] Reconciliation names a canonical source')
assert(model.reconciliation.rows.length >= 12, 'reconciliation covers the estate + governance figures', `${model.reconciliation.rows.length} rows`)
assert(model.reconciliation.rows.every((r) => r.source.length > 0), 'every row names its canonical producer')
assert(
  model.reconciliation.rows.filter((r) => /Quantum Readiness snapshot/.test(r.source)).length >= 8,
  'estate figures are attributed to the Quantum Readiness snapshot',
)
assert(
  model.reconciliation.rows.every((r) => r.agrees || r.scopeNote.length > 0),
  'any figure that does NOT agree states its scope difference explicitly',
)
const componentsRow = model.reconciliation.rows.find((r) => r.metric === 'Cryptographic components')!
assert(componentsRow.value === model.totals.cryptoComponents, 'the reconciliation value equals the published total')

/* ------------------------------------------------------------------ */
/* 11. The trend never draws an unobserved day as a zero               */
/* ------------------------------------------------------------------ */

console.log('\n[11] Trend distinguishes "no observations" from "measured zero"')
assert(model.trend.length === 30, 'trend covers 30 days', `${model.trend.length}`)
assert(
  model.trend.every((p) => p.observed),
  'a tenant whose earliest evidence predates the window has NO unobserved days — a quiet day there is a genuine measured zero',
)
assert(
  model.trend.filter((p) => p.violations > 0).length <= 1,
  'point-in-time policy violations are not back-filled across history',
)
assert(model.trend.some((p) => p.observed && p.evidence > 0), 'observed days carry real counts')

// A tenant whose FIRST observation is recent must hatch the earlier days
// rather than drawing them as measured zeros.
const recentOnly = buildGovernanceIntelligence(
  populatedInputs({
    assets: [{ id: 'a1', name: 'checkout.example.com', type: 'web-service', environment: 'production', service_owner: 'Payments', criticality: 'critical', status: 'active', metadata: {}, created_at: daysAgo(4), updated_at: daysAgo(4) }],
    cryptoInventory: [{ id: 'ci1', asset_id: 'a1', item_type: 'tls', name: 'TLS key exchange', algorithm: 'RSA-2048', key_size: 2048, protocol: 'TLS', is_vulnerable: true, is_quantum_safe: false, discovered_at: daysAgo(4), created_at: daysAgo(4) }],
    certificates: [],
    generatedKeys: [],
    vaultFiles: [],
    vulnerabilities: [],
    migrationJobs: [],
    complianceEvidence: [],
    auditLogs: [{ id: 'al1', action: 'asset_created', entity_type: 'asset', entity_id: 'a1', details: {}, ip_address: '10.0.0.1', created_at: daysAgo(4) }],
    vaultAuditLogs: [],
    scanSessions: [{ id: 's1', status: 'completed', progress: 100, total_assets: 1, scanned_assets: 1, findings_count: 1, target_scope: 'tenant', started_at: daysAgo(4), completed_at: daysAgo(4), created_at: daysAgo(4), updated_at: daysAgo(4) }],
    scanResults: [{ id: 'sr1', asset_id: 'a1', finding_type: 'quantum_vulnerable_algorithm', algorithm: 'RSA-2048', threat_level: 'critical', description: '', created_at: daysAgo(4) }],
    runtimeEvents: [],
  }),
)
const unobserved = recentOnly.trend.filter((p) => !p.observed)
assert(unobserved.length > 20, 'days before the first observation are marked unobserved', `${unobserved.length} of 30 days`)
assert(
  unobserved.every((p) => p.evidence === 0 && p.auditEvents === 0),
  'unobserved days carry no counts (the UI hatches them rather than drawing a zero)',
)
assert(
  recentOnly.trend.filter((p) => p.observed).length >= 4,
  'days from the first observation onward are observed',
  `${recentOnly.trend.filter((p) => p.observed).length}`,
)

/* ------------------------------------------------------------------ */
/* 12. Cross-view consistency                                          */
/* ------------------------------------------------------------------ */

console.log('\n[12] Cross-view consistency')
// The four page projections read from ONE model. Assert the shared facts that
// each page's header renders are single-sourced.
assert(model.totals.controls === CONTROL_CATALOG.length, 'every page sees the same control catalog size')
assert(
  model.controls.filter((c) => c.domain === 'audit').length > 0 && model.controls.filter((c) => c.domain === 'quantum').length > 0,
  'the Audit Vault and Quantum Governance scopes are both non-empty subsets of the one catalog',
)
assert(
  model.evidence.every((e) => e.controlIds.every((id) => model.controls.some((c) => c.id === id))),
  'every evidence record cites a control that exists in the model',
)
assert(
  model.auditEvents.every((e) => e.controlIds.every((id) => model.controls.some((c) => c.id === id))),
  'every audit event cites a control that exists in the model',
)
assert(
  model.gaps.every((g) => g.controlIds.every((id) => model.controls.some((c) => c.id === id))),
  'every gap cites a control that exists in the model',
)
assert(
  model.requirements.every((r) => model.frameworks.some((f) => f.id === r.frameworkId)),
  'every requirement resolves to a framework in the model',
)
assert(new Set(model.evidence.map((e) => e.id)).size === model.evidence.length, 'evidence ids are unique (no React key collision)')
assert(new Set(model.auditEvents.map((e) => e.id)).size === model.auditEvents.length, 'audit event ids are unique')
assert(new Set(model.gaps.map((g) => g.id)).size === model.gaps.length, 'gap ids are unique')

/* ------------------------------------------------------------------ */
/* 13. Specific control behaviour on the fixture                       */
/* ------------------------------------------------------------------ */

console.log('\n[13] Control behaviour on the fixture')
const byId = new Map(model.controls.map((c) => [c.id, c]))
assert(byId.get('CTL-INV-03')!.failing === 1, 'CTL-INV-03 flags exactly the one asset with no owner', `${byId.get('CTL-INV-03')!.failing}`)
assert(byId.get('CTL-INV-02')!.failing === 1, 'CTL-INV-02 flags exactly the one unclassifiable component', `${byId.get('CTL-INV-02')!.failing}`)
assert(byId.get('CTL-CRT-02')!.status !== 'compliant', 'CTL-CRT-02 fails on the expired certificate', byId.get('CTL-CRT-02')!.status)
assert(byId.get('CTL-DAT-01')!.failing === 1, 'CTL-DAT-01 flags the one object still pending encryption', `${byId.get('CTL-DAT-01')!.failing}`)
assert(byId.get('CTL-VUL-01')!.failing >= 1, 'CTL-VUL-01 flags the finding open past its SLA', `${byId.get('CTL-VUL-01')!.failing}`)
assert(byId.get('CTL-AUD-02')!.failing >= 1, 'CTL-AUD-02 flags the failed login in the audit trail', `${byId.get('CTL-AUD-02')!.failing}`)
assert(
  byId.get('CTL-GOV-03')!.measured === true,
  'CTL-GOV-03 is measured because the tenant has a canonical quantum risk score',
)
assert(
  byId.get('CTL-GOV-03')!.status === 'non-compliant',
  'quantum risk 58 breaches the default ceiling of 40',
  byId.get('CTL-GOV-03')!.status,
)
assert(
  model.auditEvents.some((e) => e.action === 'Certificate Expired'),
  'the expired certificate produces a governance audit event',
)
assert(
  model.evidence.some((e) => e.kind === 'attestation' && e.frameworkIds.includes('iso-27001')),
  'the stored attestation resolves to the ISO 27001 catalog framework',
)
assert(
  model.assets.length === 3 && model.assets.every((a) => a.name.length > 0),
  'every asset appears in the compliance projection',
  `${model.assets.length}`,
)
assert(
  model.assets.find((a) => a.assetId === 'a3')!.owner === 'Unassigned',
  'an asset with no recorded owner reads "Unassigned" rather than a blank',
)

/* ------------------------------------------------------------------ */

console.log('\n13. Asset-scoped controls and report formats')
const fixture = populatedInputs()
const scopeModel = buildGovernanceIntelligence(fixture)
const evaluation = {
  ...fixture, now: NOW, subjects: buildSubjects(fixture), evidence: scopeModel.evidence,
  assessments: fixture.controlAssessments, policies: scopeModel.policies, anchoringAvailable: true,
}
const single = buildAssetComplianceScope(scopeModel, evaluation, fixture.assets.slice(0, 1), fixture.policyOverrides)
const multiple = buildAssetComplianceScope(scopeModel, evaluation, fixture.assets.slice(0, 2), fixture.policyOverrides)
assert(single.assets.length === 1 && single.assets[0].id === 'a1', 'one selected asset is returned')
assert(multiple.assets.length === 2 && multiple.assets.every((row) => row.id === 'a1' || row.id === 'a2'), 'multi-asset selection is exact')
assert(single.evidence.length > 0 && single.evidence.every((row) => row.assetId === 'a1'), 'evidence is strictly attributed to the single selection')
assert(single.violations.every((row) => row.assetId === 'a1') && single.auditEvents.every((row) => row.assetId === 'a1'), 'violations and audit events are scoped')
assert(multiple.evidence.length > single.evidence.length && multiple.evidence.every((row) => row.assetId === 'a1' || row.assetId === 'a2'), 'combined evidence excludes unselected assets')
assert(single.controls.every((row) => row.id !== 'CTL-GOV-03' && row.failingSubjects.every((subject) => subject.assetId === 'a1')), 'tenant-only risk and out-of-scope failures are excluded')
const unknown = buildAssetComplianceScope(scopeModel, evaluation, [{ id: 'a4', name: 'No evidence asset' }], fixture.policyOverrides)
assert(unknown.assets[0].riskScore === null && unknown.latestEvidenceAt === null, 'unobserved assets have no fabricated risk score or evidence timestamp')

const many = Array.from({ length: 42 }, (_, index) => ({ id: `bulk-${index}`, name: `Bulk asset ${index}`, status: 'active' }))
const bulk = buildGovernanceIntelligence(populatedInputs({
  assets: many, portfolioAssets: [],
  cryptoInventory: many.map((row, index) => ({
    id: `bulk-crypto-${index}`, asset_id: row.id, item_type: 'hash', algorithm: 'SHA-1', created_at: daysAgo(2),
  })),
}))
assert(bulk.assets.every((asset) => asset.status === 'non-compliant' && asset.policyViolations > 0), 'assets beyond the policy sample receive their recorded violations')

const telemetry = buildGovernanceIntelligence(populatedInputs({
  scannerAgents: [
    { id: 'old', status: 'online', last_seen_at: daysAgo(3), updated_at: daysAgo(0) },
    { id: 'off', status: 'inactive', last_seen_at: daysAgo(0) },
    { id: 'live', status: 'online', last_seen_at: daysAgo(0) },
  ],
  connectorAccounts: [{ status: 'disconnected' }, { status: 'inactive' }, { status: 'unhealthy' }, { status: 'connected' }],
  scanSessions: [{ status: 'queued' }, { status: 'pending' }, { status: 'running' }],
})).telemetry
assert(telemetry.agentsOnline === 1 && telemetry.connectorsActive === 1 && telemetry.runningScans === 1,
  'stale, disconnected, inactive and queued records never count as active telemetry')

const enterpriseAssets = Array.from({ length: 2000 }, (_, index) => ({ id: `inventory-${index}`, name: `Asset ${index}`, status: 'active' }))
const largeInput = populatedInputs({ assets: enterpriseAssets, portfolioAssets: [], cryptoInventory: [], certificates: [], runtimeEvents: [] })
const estate = buildGovernanceIntelligence(largeInput)
const selectedAtEnd = buildAssetComplianceScope(estate, { ...evaluation, assets: largeInput.assets, subjects: buildSubjects(largeInput), evidence: estate.evidence },
  enterpriseAssets.slice(-100), largeInput.policyOverrides)
assert(estate.assets.length === 2000 && selectedAtEnd.assets.length === 100 && selectedAtEnd.assets[0].id === 'inventory-1900',
  'a 100-asset selection works at the end of a 2,000-asset inventory')

for (const selection of [single, multiple]) {
  const document = buildAssetComplianceDocument(selection, 'technical', daysAgo(0))
  assert(document.tables[0].rows.length === selection.assets.length, 'report matches selected asset count')
  for (const format of ['pdf', 'csv', 'json', 'html'] as const) {
    const result = await exportDocument(document, format)
    const content = await result.blob.text()
    assert(result.blob.size > 0 && result.filename.endsWith(`.${format}`), `${format} export renders the selected scope`)
    if (format === 'pdf') assert(content.startsWith('%PDF-'), 'PDF has a valid file signature')
    else {
      assert(content.includes('checkout.example.com') && !content.includes('batch-reporting'), `${format} includes the selected asset and excludes unrelated assets`)
      assert((selection.assets.length === 2) === content.includes('identity.example.com'), `${format} includes the second asset only in the multi-asset scope`)
    }
  }
}
let rejected = false
try { buildAssetComplianceDocument({ ...single, evidence: multiple.evidence }, 'executive') } catch { rejected = true }
assert(rejected, 'report validation rejects records outside the selection')

console.log(`\n${failures === 0 ? '✓ ALL GOVERNANCE INVARIANTS HOLD' : `✗ ${failures} INVARIANT(S) FAILED`}\n`)
process.exit(failures === 0 ? 0 : 1)
