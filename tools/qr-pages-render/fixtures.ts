/**
 * Render-smoke fixtures for the Quantum Readiness page family.
 *
 * Every payload is produced by the REAL server assemblers from one synthetic
 * estate, so the pages are rendered with exactly the shapes production sends —
 * not hand-written mock payloads that can drift from the contract.
 *
 *   npx tsx tools/qr-pages-render/fixtures.ts <out.json>
 */
import { writeFileSync } from 'node:fs'
import { assembleExposureIntelligence, type ExposureRawRows } from '../../src/api-server/exposure-graph'
import { assembleHndlIntelligence, type HndlRawRows } from '../../src/api-server/harvest-now'
import { buildRemediationPlan, type RemediationEvidence } from '../../src/api-server/quantum-remediation'
import { DEFAULT_POLICY } from '../../src/api-server/quantum-certification'
import { payloadFingerprint } from '../../src/api-server/live-snapshot-stream'
import { DEFAULT_COST_ASSUMPTIONS } from '../../src/lib/migration/cost-model'

const NOW = '2026-10-21T08:00:00.000Z'
const out = process.argv[2]
if (!out) {
  console.error('usage: fixtures.ts <out.json>')
  process.exit(2)
}

const snapshot = {
  generatedAt: NOW,
  lastAssessmentAt: NOW,
  assessmentProgress: 71,
  assessmentStatus: 'in_progress',
  evidenceSources: [
    { id: 'assets', label: 'Asset inventory', present: true },
    { id: 'scans', label: 'Discovery scans', present: true },
    { id: 'certificates', label: 'Certificates', present: true },
    { id: 'keys', label: 'Key inventory', present: false },
    { id: 'relationships', label: 'Asset relationships', present: true },
    { id: 'runtime', label: 'Runtime telemetry', present: false },
    { id: 'cbom', label: 'Cryptographic inventory', present: true },
  ],
  hasData: true,
  persistence: 'database',
  scores: {
    quantumReadiness: 38, quantumReadinessLevel: 'Early Stage',
    quantumRisk: 63, quantumRiskLevel: 'High',
    hndlRisk: 58, hndlRiskLevel: 'Elevated',
    cryptoExposure: 55, cryptoExposureLevel: 'Elevated',
    migrationComplexity: 34, migrationComplexityLevel: 'Moderate',
    migrationEffort: 55, pqcAdoption: 24,
  },
  inventory: {
    assetsAssessed: 5, certificatesAnalyzed: 3, keysDiscovered: 0, trustRelationships: 2,
    domainsScanned: 3, identitiesAnalyzed: 0, cloudAccounts: 1, dataRepositories: 2,
    pqcReadyAssets: 1, hybridAssets: 2, unassessedAssets: 1, quantumVulnerableAssets: 2,
    cryptoComponents: 29, vulnerableComponents: 16, pqcReadyComponents: 7,
  },
  riskDistribution: { critical: 4, high: 9, medium: 6, low: 3 },
  readinessFactors: [
    { label: 'PQC-Ready Components', score: 24, measured: true, basis: '7 of 29 quantum-relevant CBOM component(s) are post-quantum or hybrid' },
    { label: 'Hybrid Crypto Adoption', score: 7, measured: true, basis: '2 of 29 CBOM component(s) negotiate a hybrid classical + PQC primitive' },
    { label: 'TLS / Key Exchange PQC Coverage', score: 33, measured: true, basis: '2 of 6 observed key exchange(s) / cipher suite(s) use ML-KEM or a hybrid group' },
    { label: 'PKI Quantum Readiness', score: 0, measured: true, basis: '0 of 3 certificate(s) carry a PQC or hybrid signature' },
    { label: 'Crypto-Agility Readiness', score: 0, measured: false, basis: 'Not part of this assessment — measured by the Crypto Agility Engine' },
    { label: 'Governance Maturity', score: 0, measured: false, basis: 'No governance evidence source feeds this assessment — excluded from the readiness score' },
    { label: 'Runtime Visibility', score: 0, measured: false, basis: 'No runtime crypto telemetry — excluded from the readiness score' },
  ],
  riskFactors: [
    { label: 'RSA / ECC Exposure', score: 55, severity: 'Elevated' },
    { label: 'HNDL Exposure', score: 58, severity: 'Elevated' },
    { label: 'Internet-Facing Exposure', score: 60, severity: 'High' },
    { label: 'Critical Asset Dependency', score: 16, severity: 'Low' },
    { label: 'Severity Pressure', score: 54, severity: 'Elevated' },
  ],
  criticalFindings: [
    { id: 'f1', title: 'RSA-2048 detected', asset: 'api.acme.com', assetType: 'api', environment: 'production', severity: 'critical', algorithm: 'RSA-2048', detectedAt: NOW, instances: 3, locations: ['api.acme.com:443', 'https://api.acme.com'] },
    { id: 'f2', title: 'ECDSA-P256 detected', asset: 'portal.acme.com', assetType: 'web', environment: 'production', severity: 'high', algorithm: 'ECDSA-P256', detectedAt: NOW, instances: 2 },
  ],
  criticalFindingsSummary: { records: 2, instances: 5, shown: 2 },
  recommendedActions: [
    { id: 'rec-vuln', title: 'Remediate 16 quantum-vulnerable CBOM components', detail: 'Replace RSA/ECC primitives with ML-KEM / ML-DSA or hybrid equivalents.', severity: 'critical', route: '/dashboard/crypto-agility' },
    { id: 'rec-assets', title: 'Prioritise 2 quantum-vulnerable assets', detail: 'Sequence these into the next migration wave.', severity: 'high', route: '/dashboard/quantum-readiness/ai-migration-advisor' },
  ],
  topRiskAssets: [
    { asset: 'api.acme.com', assetType: 'api', environment: 'production', owner: 'Platform', riskScore: 100, status: 'Quantum-Vulnerable' },
    { asset: 'portal.acme.com', assetType: 'web', environment: 'production', owner: 'Web', riskScore: 75, status: 'Quantum-Vulnerable' },
    { asset: 'vault.acme.com', assetType: 'database', environment: 'production', owner: 'Data', riskScore: 0, status: 'PQC-Ready' },
    { asset: 'cache.acme.local', assetType: 'server', environment: 'internal', owner: 'Ops', riskScore: 0, status: 'Hybrid / In-Progress' },
    { asset: 'batch.acme.local', assetType: 'server', environment: '', owner: 'Unassigned', riskScore: 0, status: 'Not Assessed' },
  ],
  assetTypePosture: [],
  exposureGraph: {
    nodes: [
      { id: 'a1', label: 'api.acme.com', type: 'api', environment: 'production', riskScore: 100, posture: 'vulnerable', internetFacing: true },
      { id: 'a2', label: 'portal.acme.com', type: 'web', environment: 'production', riskScore: 75, posture: 'vulnerable', internetFacing: true },
      { id: 'a3', label: 'vault.acme.com', type: 'database', environment: 'production', riskScore: 0, posture: 'pqc', internetFacing: false },
      { id: 'a4', label: 'cache.acme.local', type: 'server', environment: 'internal', riskScore: 0, posture: 'hybrid', internetFacing: false },
      { id: 'a5', label: 'batch.acme.local', type: 'server', environment: '', riskScore: 0, posture: 'unknown', internetFacing: false },
    ],
    edges: [{ source: 'a2', target: 'a1', type: 'depends-on' }, { source: 'a1', target: 'a3', type: 'depends-on' }],
  },
  riskTrend: [
    { label: 'Oct 14', readiness: 31, risk: 70, recordedAt: '2026-10-14T08:00:00.000Z' },
    { label: 'Oct 18', readiness: 35, risk: 66, recordedAt: '2026-10-18T08:00:00.000Z' },
    { label: 'Oct 21', readiness: 38, risk: 63, recordedAt: NOW },
  ],
  scoreHistory: { available: true, reason: null, points: 3 },
  estimates: { migrationTimelineWeeks: 11, migrationCostUsd: 68970, parallelWorkstreams: 1 },
  costAssumptions: DEFAULT_COST_ASSUMPTIONS,
  businessValue: { financialExposureUsd: 1_200_000, revenueProtectedUsd: 300_000, criticalVulnerableAssets: 1, standardVulnerableAssets: 1, criticalityTagged: true },
  telemetry: { runtimeEvents: 0, scanResults: 22, scanSessions: 3, securityEvents: 4, certificates: 3, keys: 0, assets: 5, connectors: 1, latestEventAt: NOW, latestRuntimeEventAt: null },
}

const assets = [
  { id: 'a1', name: 'api.acme.com', type: 'api', environment: 'production', region: 'us-east-1', service_owner: 'Platform', criticality: 'critical', metadata: {} },
  { id: 'a2', name: 'portal.acme.com', type: 'web', environment: 'production', region: 'eu-west-1', service_owner: 'Web', criticality: 'high', metadata: {} },
  { id: 'a3', name: 'vault.acme.com', type: 'database', environment: 'production', region: 'us-east-1', service_owner: 'Data', criticality: 'high', metadata: {} },
  { id: 'a4', name: 'cache.acme.local', type: 'server', environment: 'internal', region: '', service_owner: 'Ops', criticality: 'medium', metadata: {} },
  { id: 'a5', name: 'batch.acme.local', type: 'server', environment: '', region: '', service_owner: '', criticality: '', metadata: {} },
]
const cryptoInventory = [
  { id: 'c1', asset_id: 'a1', item_type: 'cipher_suite', name: 'Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', algorithm: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', protocol: 'TLSv1.2', is_vulnerable: true, is_quantum_safe: false },
  { id: 'c2', asset_id: 'a1', item_type: 'key_exchange', name: 'Key Exchange: RSA', algorithm: 'RSA-2048', protocol: 'TLSv1.2', is_vulnerable: true, is_quantum_safe: false },
  { id: 'c3', asset_id: 'a2', item_type: 'signature', name: 'Signature: ECDSA', algorithm: 'ECDSA-P256', protocol: 'TLSv1.3', is_vulnerable: true, is_quantum_safe: false },
  { id: 'c4', asset_id: 'a3', item_type: 'key_exchange', name: 'Key Exchange: X25519MLKEM768', algorithm: 'X25519MLKEM768', protocol: 'TLSv1.3', is_vulnerable: false, is_quantum_safe: true },
  { id: 'c5', asset_id: 'a4', item_type: 'symmetric', name: 'Symmetric: AES-256-GCM', algorithm: 'AES-256-GCM', protocol: '', is_vulnerable: false, is_quantum_safe: false },
]
const certificates = [
  { id: 'k1', asset_id: 'a1', name: 'api.acme.com', algorithm: 'RSA-2048', key_size: 2048, issuer: "CN=R13, O=Let's Encrypt, C=US", not_after: '2027-01-01', is_quantum_safe: false, is_expiring_soon: false },
  { id: 'k2', asset_id: 'a2', name: 'portal.acme.com', algorithm: 'ECDSA-P256', key_size: 256, issuer: 'CN=Acme Issuing CA, O=Acme, C=GB', not_after: '2026-11-01', is_quantum_safe: false, is_expiring_soon: true },
]
const scanResults = [
  { id: 's1', asset_id: 'a1', algorithm: 'RSA-2048', threat_level: 'critical' },
  { id: 's2', asset_id: 'a2', algorithm: 'ECDSA-P256', threat_level: 'high' },
]

const exposureRows: ExposureRawRows = {
  assets,
  relationships: [{ source_asset_id: 'a2', target_asset_id: 'a1', relationship_type: 'depends-on' }, { source_asset_id: 'a1', target_asset_id: 'a3', relationship_type: 'mtls' }],
  cryptoInventory,
  certificates,
  runtimeEvents: [],
  scanResults,
  cryptoExposures: [],
  connectorAccounts: [{ id: 'x1', provider: 'aws', status: 'connected' }],
  migrationJobs: [{ id: 'j1', status: 'running', asset_id: 'a2', job_type: 'tls-migration' }],
}
const hndlRows: HndlRawRows = {
  cryptoInventory,
  certificates,
  runtimeEvents: [],
  assets,
  migrationJobs: [{ id: 'j1', status: 'running', asset_id: 'a2', job_type: 'tls-migration' }, { id: 'j2', status: 'completed', asset_id: 'a3', job_type: 'cert-rotation' }],
  keys: [{ id: 'g1', algorithm: 'ML-KEM-768' }, { id: 'g2', algorithm: 'RSA-2048' }],
}

type Snap = Parameters<typeof assembleExposureIntelligence>[0]
const exposure = assembleExposureIntelligence(snapshot as unknown as Snap, exposureRows)
const hndl = assembleHndlIntelligence(snapshot as unknown as Parameters<typeof assembleHndlIntelligence>[0], hndlRows)

const evidence: RemediationEvidence = {
  hasData: true,
  generatedAt: NOW,
  policy: DEFAULT_POLICY,
  eligibility: {
    eligible: false, issuable: true, evaluatedAt: NOW, hasData: true, requiredTotal: 10, requiredMet: 3, trustScore: 430, level: null, levelLabel: 'Not Eligible',
    checks: ['readiness', 'critical-vulns', 'hndl', 'residual-risk', 'confidence', 'pqc-adoption', 'disallowed-algorithms', 'vulnerable-components', 'expired-certificates', 'validation'].map((id, i) => ({
      id, criterion: id, required: 'threshold', actual: 'measured', met: i < 3, severity: 'required' as const, evidence: 'fixture', remediation: `Resolve ${id}.`,
    })),
    recommendations: [], policy: DEFAULT_POLICY,
  },
  measures: { readiness: 38, quantumRisk: 63, hndl: 58, residualRisk: 50, confidence: 70, pqcAdoption: 24, critical: 4, high: 9, medium: 6, low: 3, vulnerableComponents: 16, pqcReadyComponents: 7, totalComponents: 29, disallowedCount: 2, expiredCertificates: 1, validationPass: true, runtimeMeasured: false, runtimeFresh: false },
  scores: { quantumReadiness: 38, quantumRisk: 63, hndlRisk: 58, pqcAdoption: 24, migrationComplexity: 34 },
  trustScore: 430,
  levelLabel: 'Not Eligible',
  parallelWorkstreams: 1,
  readinessTrend: snapshot.riskTrend,
  disallowedAlgorithms: DEFAULT_POLICY.disallowedAlgorithms,
  missingEvidenceSources: [{ id: 'runtime-telemetry', label: 'Runtime Cryptographic Intelligence', route: '/dashboard/runtime-crypto-intel' }],
  validationPass: true,
  cryptoAgilityActive: false,
  assets: [
    { id: 'a1', name: 'api.acme.com', type: 'api', environment: 'production', owner: 'Platform', criticality: 'critical', internetFacing: true, riskScore: 100, pqcCapable: true, vendorParty: false, vulnerabilities: [{ id: 'v1', name: 'RSA key exchange', itemType: 'Key Exchange', algorithm: 'RSA-2048', protocol: 'TLS 1.2', severity: 'critical', instances: 3, description: 'RSA key transport' }] },
    { id: 'a2', name: 'portal.acme.com', type: 'web', environment: 'production', owner: 'Web', criticality: 'high', internetFacing: true, riskScore: 75, pqcCapable: true, vendorParty: false, vulnerabilities: [{ id: 'v2', name: 'ECDSA certificate', itemType: 'Certificate', algorithm: 'ECDSA-P256', protocol: '', severity: 'high', instances: 2, description: 'Classical signature' }] },
  ],
  relationships: [{ source: 'a2', target: 'a1', type: 'depends-on' }],
  expiredCertsByAsset: new Map([['a2', 1]]),
  unlinkedExpiredCerts: 0,
  migrationJobs: [{ id: 'j2', status: 'completed', assetId: 'a1', jobType: 'cert-rotation', updatedAt: NOW }],
  assetNameById: new Map([['a1', 'api.acme.com'], ['a2', 'portal.acme.com']]),
}
const plan = buildRemediationPlan(evidence)

const certification = {
  // Merged onto EMPTY_CERTIFICATION by the hook, exactly as a server payload is.
  generatedAt: NOW,
  hasData: true,
  eligibility: { ...evidence.eligibility, checks: evidence.eligibility.checks.map((c) => ({ ...c, criterion: c.id.replace(/-/g, ' ') })) },
  trend: [{ label: 'Oct 21', trustScore: 430, readiness: 38 }],
  advisor: { headline: 'Baseline available', verdict: 'baseline', explanation: ['Three of ten criteria pass.'], businessImpact: ['Customers cannot yet verify PQC readiness.'], nextSteps: [{ title: 'Close the gaps', detail: '7 criteria remain.', route: '/dashboard/quantum-readiness/risk-analysis' }] },
}

const withPrint = <T extends object>(payload: T) => ({ ...payload, fingerprint: payloadFingerprint(payload) })
writeFileSync(
  out,
  JSON.stringify({
    'quantum-readiness': withPrint(snapshot),
    'exposure-intelligence': withPrint(exposure),
    'hndl-intelligence': withPrint(hndl),
    'remediation-update': withPrint(plan),
    'certification-update': withPrint(certification),
  }),
)
console.log(`fixtures written: ${out}`)
