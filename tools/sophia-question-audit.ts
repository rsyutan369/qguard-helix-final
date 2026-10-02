/**
 * Sophia — every-question audit.
 *
 *     npx tsx tools/sophia-question-audit.ts
 *
 * The defect this suite exists for: asking Sophia one of HER OWN suggested
 * questions — "What is pending remediation?" — returned "I could not derive an
 * evidence-backed answer for this question", printed directly above an evidence
 * card reading "6 pending remediation actions". copilot-check and sophia-check
 * both passed at the time, because neither asked the questions Sophia offers.
 *
 * So this suite asks ALL of them — the global suggestions, every page's
 * suggestions, the follow-ups each answer offers, per-asset questions and a
 * realistic corpus — and checks each answer against the CANONICAL engines:
 *   • the remediation plan comes from the real `buildRemediationPlan`,
 *   • the per-asset truth comes from the real `buildAssetRegister`
 *     (the exact derivation /dashboard/assets renders),
 * so an expected value is never a number typed into this file.
 *
 * It also runs the corpus against an EMPTY tenant (no fabricated figures) and as
 * a restricted role (no crash, no leaked denial internals), and proves the
 * longitudinal memory reports change in the right direction.
 */
import { runCopilotQuery, computeChanges, type PriorFigures } from '../src/api-server/copilot-engine'
import { extractQueryFilter, suggestionsForPage } from '../src/api-server/copilot-knowledge'
import { resolveFocus } from '../src/api-server/copilot-answers'
import type { CopilotBuilders, ToolContext } from '../src/api-server/copilot-tools'
import { buildRemediationPlan, type RemediationEvidence } from '../src/api-server/quantum-remediation'
import { DEFAULT_POLICY } from '../src/api-server/quantum-certification'
import { buildAssetRegister, type RegisterSnapshotInput } from '../src/lib/assets/asset-register'
import { EMPTY_MEMORY, type CopilotAnswer, type CopilotRole } from '../src/types/copilot'
import type { EligibilityCheck, EligibilityResult } from '../src/types/quantum-certification'
import type { ExposureIntelligence } from '../src/types/exposure-graph'

let failures = 0
let checks = 0
function assert(cond: boolean, label: string, extra = '') {
  checks += 1
  if (!cond) {
    failures += 1
    console.log(`  ✗ FAIL ${label}${extra ? ` — ${extra}` : ''}`)
  }
}

const USER_ID = 'tenant-acme'
const NOW_MS = Date.now()
const iso = (offsetDays: number) => new Date(NOW_MS + offsetDays * 86400000).toISOString()
const NOW = iso(0)

/* ================================================================== */
/* Ground-truth tenant                                                 */
/* ================================================================== */

const ASSETS = [
  { id: 'a-web', name: 'checkout-web', type: 'web', environment: 'production', service_owner: 'Payments Platform', criticality: 'critical', status: 'active', metadata: { internet_facing: true } },
  { id: 'a-api', name: 'partner-api', type: 'api', environment: 'production', service_owner: '', criticality: 'high', status: 'active', metadata: { internet_facing: true } },
  { id: 'a-db', name: 'orders-db', type: 'database', environment: 'internal', service_owner: 'Data Engineering', criticality: 'high', status: 'active', metadata: {} },
  { id: 'a-hr', name: 'hr-portal', type: 'web', environment: 'internal', service_owner: 'People Ops', criticality: 'medium', status: 'active', metadata: {} },
]

/** Scanner-shaped component rows (real prefixes: `${category}: ${algorithm}`). */
const COMPONENTS: Record<string, Array<Record<string, unknown>>> = {
  'a-web': [
    { id: 'c1', name: 'Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', algorithm: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', item_type: 'Cipher Suite', protocol: 'TLS 1.2', is_vulnerable: true, is_quantum_safe: false, exposure_level: 'critical' },
    { id: 'c2', name: 'Certificate Signature: sha256WithRSAEncryption', algorithm: 'sha256WithRSAEncryption', item_type: 'Certificate Signature', protocol: 'TLS 1.2', is_vulnerable: true, is_quantum_safe: false, exposure_level: 'high' },
    { id: 'c3', name: 'Symmetric Encryption: AES-256-GCM', algorithm: 'AES-256-GCM', item_type: 'Symmetric Encryption', protocol: 'TLS 1.2', is_vulnerable: false, is_quantum_safe: true, exposure_level: 'low' },
  ],
  'a-api': [
    { id: 'c4', name: 'Key Exchange: RSA-2048', algorithm: 'RSA-2048', item_type: 'Key Exchange', protocol: 'TLS 1.2', is_vulnerable: true, is_quantum_safe: false, exposure_level: 'high' },
    { id: 'c5', name: 'Key Exchange: X25519MLKEM768', algorithm: 'X25519MLKEM768', item_type: 'Key Exchange', protocol: 'TLS 1.3', is_vulnerable: false, is_quantum_safe: true, exposure_level: 'low' },
  ],
  'a-db': [
    { id: 'c6', name: 'Signature: ECDSA-P256', algorithm: 'ECDSA-P256', item_type: 'Signature', protocol: 'TLS 1.2', is_vulnerable: true, is_quantum_safe: false, exposure_level: 'medium' },
  ],
  'a-hr': [],
}

const RISK: Record<string, number | null> = { 'a-web': 88, 'a-api': 71, 'a-db': 55, 'a-hr': null }
const INTERNET: Record<string, boolean> = { 'a-web': true, 'a-api': true, 'a-db': false, 'a-hr': false }

/** The scanner-intelligence payload the Assets page streams. */
const SCANNER_INTEL = {
  generatedAt: NOW,
  summary: { totalAssets: 4, totalComponents: 6, vulnerableComponents: 4, pqcReadyComponents: 2, vulnerableAssets: 3, criticalFindings: 2, totalFindings: 10 },
  severityCounts: { critical: 2, high: 3, medium: 4, low: 1, safe: 2 },
  findings: [],
  assets: {
    assets: ASSETS.map((a) => ({
      id: a.id, name: a.name, type: a.type, url: `https://${a.name}.acme.test`, owner: a.service_owner, environment: a.environment,
      criticality: a.criticality, internetFacing: INTERNET[a.id], riskScore: RISK[a.id], tlsVersion: 'TLS 1.2',
      lastScanned: a.id === 'a-hr' ? NOW : iso(-0.1), lastScannedSource: a.id === 'a-hr' ? 'asset-record' : 'scan',
      cryptoInventory: COMPONENTS[a.id], vulnerabilities: COMPONENTS[a.id].filter((c) => c.is_vulnerable),
    })),
  },
  history: { history: [] },
}

const QR_SNAPSHOT = {
  hasData: true, lastAssessmentAt: iso(-0.1), generatedAt: NOW,
  scores: { quantumReadiness: 42, quantumReadinessLevel: 'developing', quantumRisk: 71, quantumRiskLevel: 'high', hndlRisk: 64, hndlRiskLevel: 'high', cryptoExposure: 60, pqcAdoption: 22, migrationComplexity: 40 },
  inventory: { assetsAssessed: 4, certificatesAnalyzed: 4, keysDiscovered: 0, trustRelationships: 2, domainsScanned: 3, quantumVulnerableAssets: 3, pqcReadyAssets: 0, hybridAssets: 0, cryptoComponents: 6, vulnerableComponents: 4, pqcReadyComponents: 2, findingRowsExcluded: 4, cryptoInventoryRows: 10 },
  riskDistribution: { critical: 2, high: 3, medium: 4, low: 1 },
  readinessFactors: [
    { label: 'PQC-Ready Components', score: 33 }, { label: 'Hybrid Crypto Adoption', score: 17 }, { label: 'TLS / Protocol Maturity', score: 40 },
    { label: 'PKI Maturity', score: 52 }, { label: 'Crypto-Agility Readiness', score: 22 }, { label: 'Governance Maturity', score: 61 }, { label: 'Runtime Visibility', score: 12 },
  ],
  riskFactors: [{ label: 'RSA / ECC Exposure', score: 67, severity: 'high' }],
  criticalFindings: [
    { id: 'f1', title: 'RSA key exchange', asset: 'checkout-web', assetType: 'web', environment: 'production', severity: 'critical', algorithm: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', detectedAt: iso(-1), instances: 3, locations: ['checkout-web'] },
    { id: 'f2', title: 'RSA-2048 key exchange', asset: 'partner-api', assetType: 'api', environment: 'production', severity: 'critical', algorithm: 'RSA-2048', detectedAt: iso(-1), instances: 1, locations: ['partner-api'] },
    { id: 'f3', title: 'ECDSA signature', asset: 'orders-db', assetType: 'database', environment: 'internal', severity: 'high', algorithm: 'ECDSA-P256', detectedAt: iso(-1), instances: 2, locations: ['orders-db'] },
  ],
  topRiskAssets: [
    { asset: 'checkout-web', assetType: 'web', environment: 'production', owner: 'Payments Platform', riskScore: 88, status: 'Quantum-Vulnerable' },
    { asset: 'partner-api', assetType: 'api', environment: 'production', owner: 'Unassigned', riskScore: 71, status: 'Quantum-Vulnerable' },
  ],
  recommendedActions: [{ id: 'rec-vuln', title: 'Remediate 4 quantum-vulnerable CBOM components', detail: '', severity: 'critical', route: '/dashboard/crypto-agility' }],
  riskTrend: [],
  estimates: { migrationTimelineWeeks: 10, migrationCostUsd: 0, parallelWorkstreams: 2 },
  sharedResponsibility: {
    totals: { findings: 10, customer: 7, provider: 2, ecosystem: 1, actionable: 7, waiting: 3, blocked: 0, resolved: 0 },
    readiness: {}, widgets: { migrationBlockers: 1 }, matrix: [], findings: [], providerBreakdown: [],
  },
}

/* ---- Certification: 10 required criteria, 5 unmet ------------------ */
const CHECKS: EligibilityCheck[] = [
  { id: 'readiness', criterion: 'Overall Quantum Readiness', required: '≥ 90/100', actual: '42/100', met: false, severity: 'required', evidence: 'QR snapshot', remediation: 'Replace quantum-vulnerable components to lift readiness.' },
  { id: 'critical-vulns', criterion: 'Critical Quantum Vulnerabilities', required: '≤ 0', actual: '2 critical finding(s)', met: false, severity: 'required', evidence: 'Scan findings', remediation: 'Resolve the critical RSA key-exchange findings.' },
  { id: 'hndl', criterion: 'Harvest-Now-Decrypt-Later Exposure', required: '≤ 30/100', actual: '64/100', met: false, severity: 'required', evidence: 'HNDL', remediation: 'Deploy hybrid ML-KEM key establishment.' },
  { id: 'pqc-adoption', criterion: 'PQC Adoption', required: '≥ 60%', actual: '22%', met: false, severity: 'required', evidence: 'CBOM', remediation: 'Adopt ML-KEM / ML-DSA.' },
  { id: 'expired-certificates', criterion: 'Expired Certificates', required: '≤ 0', actual: '1 expired', met: false, severity: 'required', evidence: 'Certificates', remediation: 'Renew the expired certificate.' },
  { id: 'residual-risk', criterion: 'Residual Risk', required: '≤ 40/100', actual: '35/100', met: true, severity: 'required', evidence: 'Report', remediation: '' },
  { id: 'confidence', criterion: 'Assessment Confidence', required: '≥ 60%', actual: '70%', met: true, severity: 'required', evidence: 'Confidence model', remediation: '' },
  { id: 'disallowed-algorithms', criterion: 'Disallowed Legacy Algorithms', required: 'None', actual: '0 hit(s)', met: true, severity: 'required', evidence: 'Inventory', remediation: '' },
  { id: 'vulnerable-components', criterion: 'Quantum-Vulnerable Components', required: '≤ 10', actual: '4 component(s)', met: true, severity: 'required', evidence: 'CBOM', remediation: '' },
  { id: 'validation', criterion: 'Report Self-Validation', required: 'PASS', actual: 'PASS', met: true, severity: 'required', evidence: 'Report engine', remediation: '' },
]
const ELIGIBILITY: EligibilityResult = {
  eligible: false, issuable: true, evaluatedAt: NOW, hasData: true, requiredTotal: 10, requiredMet: 5, trustScore: 540,
  level: 'bronze', levelLabel: 'Bronze — Initial Readiness', checks: CHECKS, recommendations: [], policy: DEFAULT_POLICY,
}

/* ---- Remediation evidence → the REAL Q-REMEDY plan ----------------- */
const vuln = (id: string, algorithm: string, itemType: string, severity: string, instances = 1) => ({
  id, name: `${itemType}: ${algorithm}`, itemType, algorithm, protocol: 'TLS 1.2', severity, instances, description: `${algorithm} observed`,
})
const REMEDIATION_EVIDENCE: RemediationEvidence = {
  hasData: true,
  generatedAt: NOW,
  policy: DEFAULT_POLICY,
  eligibility: ELIGIBILITY,
  measures: { readiness: 42, quantumRisk: 71, hndl: 64, residualRisk: 35, confidence: 70, pqcAdoption: 22, critical: 2, high: 3, medium: 4, low: 1, vulnerableComponents: 4, pqcReadyComponents: 2, totalComponents: 6, disallowedCount: 0, expiredCertificates: 1, validationPass: true, runtimeMeasured: true, runtimeFresh: true },
  scores: { quantumReadiness: 42, quantumRisk: 71, hndlRisk: 64, pqcAdoption: 22, migrationComplexity: 40 },
  trustScore: 540,
  levelLabel: 'Bronze — Initial Readiness',
  parallelWorkstreams: 2,
  readinessTrend: [],
  disallowedAlgorithms: DEFAULT_POLICY.disallowedAlgorithms,
  missingEvidenceSources: [],
  validationPass: true,
  cryptoAgilityActive: false,
  assets: [
    { id: 'a-web', name: 'checkout-web', type: 'web', environment: 'production', owner: 'Payments Platform', criticality: 'critical', internetFacing: true, riskScore: 88, pqcCapable: true, vendorParty: false,
      vulnerabilities: [vuln('v1', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'Cipher Suite', 'critical', 3), vuln('v2', 'sha256WithRSAEncryption', 'Certificate Signature', 'high')] },
    { id: 'a-api', name: 'partner-api', type: 'api', environment: 'production', owner: '', criticality: 'high', internetFacing: true, riskScore: 71, pqcCapable: false, vendorParty: false,
      vulnerabilities: [vuln('v3', 'RSA-2048', 'Key Exchange', 'critical')] },
    { id: 'a-db', name: 'orders-db', type: 'database', environment: 'internal', owner: 'Data Engineering', criticality: 'high', internetFacing: false, riskScore: 55, pqcCapable: true, vendorParty: false,
      vulnerabilities: [vuln('v4', 'ECDSA-P256', 'Signature', 'medium', 2)] },
  ],
  relationships: [{ source: 'a-web', target: 'a-db', type: 'depends-on' }, { source: 'a-api', target: 'a-db', type: 'depends-on' }],
  expiredCertsByAsset: new Map([['a-db', 1]]),
  unlinkedExpiredCerts: 0,
  migrationJobs: [
    { id: 'job-failed-1', status: 'failed', assetId: 'a-api', jobType: 'tls-upgrade', updatedAt: iso(-1) },
    { id: 'job-run-1', status: 'running', assetId: 'a-db', jobType: 'cert-reissue', updatedAt: NOW },
  ],
  assetNameById: new Map(ASSETS.map((a) => [a.id, a.name])),
}
const PLAN = buildRemediationPlan(REMEDIATION_EVIDENCE)
const PENDING = PLAN.actions.filter((a) => a.status !== 'resolved')

/* ---- Exposure graph ------------------------------------------------ */
const EXPOSURE = {
  generatedAt: NOW, lastAssessmentAt: iso(-0.1), hasData: true,
  summary: { totalAssets: 4, quantumVulnerable: 3, hybridAssets: 0, pqcReadyAssets: 0, migrationInProgress: 1, unknownPosture: 1, thirdPartyDependencies: 1, trustRelationships: 2, criticalTrustRelationships: 1, internetFacingAssets: 2, highRiskAssets: 2, legacyCryptoAssets: 3, certificateChains: 2, pkiObjects: 4, maxBlastRadius: 2, migrationReadinessScore: 20, quantumReadinessScore: 42, quantumRiskScore: 71 },
  graph: {
    nodes: [
      { id: 'a-web', label: 'checkout-web', riskScore: 88, posture: 'vulnerable', internetFacing: true, environment: 'production' },
      { id: 'a-api', label: 'partner-api', riskScore: 71, posture: 'vulnerable', internetFacing: true, environment: 'production' },
      { id: 'a-db', label: 'orders-db', riskScore: 55, posture: 'vulnerable', internetFacing: false, environment: 'internal' },
    ],
    edges: [
      { id: 'e1', source: 'a-db', target: 'a-web', trustClass: 'certificate-chain' },
      { id: 'e2', source: 'a-db', target: 'a-api', trustClass: 'data' },
    ],
  },
  thirdParty: [{ id: 'tp1', vendor: 'PayGate Ltd', category: 'Payment processor', connectedAssets: 1, connectedAssetNames: ['checkout-web'], algorithms: ['RSA-2048'], tlsVersion: 'TLS 1.2', certificate: null, readiness: 'vulnerable', riskLevel: 'High', migrationCompatibility: 'Hybrid not yet supported', businessCriticality: 'High' }],
  migrationOrder: { waves: [], clusters: [], blockers: [{ id: 'b1', label: 'orders-db', reason: 'Shared certificate chain anchors 2 dependents', blockedDependents: 2 }] },
  advisor: { recommendations: [], estimates: {} },
  riskPrioritization: [],
  evidence: { sources: ['assets'], note: 'audit fixture' },
} as unknown as ExposureIntelligence

/* ---- Harvest Now (real field names) ---------------------------------- */
const HNDL = {
  hasData: true, lastScanAt: iso(-0.1),
  banner: { threatLevel: 'Critical', hndlExposureScore: 64, hndlExposureLevel: 'high', criticalFindings: 2, quantumExposureWindow: 'Within 5 Years', estimatedFutureDecryptableTb: 1.4, migrationDeadlineYear: 2030, yearsToDeadline: 4, headline: '2 critical quantum-vulnerable exposure(s) across 3 asset(s). HNDL risk 64/100 (high).' },
  forwardSecrecy: {
    coveragePct: 50, assetsProtected: 1, assetsUnprotected: 1, totalTransport: 2, componentsMeasured: 2, componentsNotApplicable: 4, assetsWithPfs: 1, assetsWithoutPfs: 1, runtimeLegacyEvents: 0,
    nonPfsBreakdown: [{ type: 'Static RSA key exchange', count: 1 }],
    topUnprotected: [{ asset: 'partner-api', algorithm: 'RSA-2048', protocol: 'TLS 1.2', reason: 'Static RSA key exchange — recorded sessions stay decryptable if the long-term key is recovered' }],
    hasEvidence: true, basis: '2 key-agreement observation(s) measured; 4 non-key-exchange component(s) excluded as not applicable.',
  },
  futureDecryptable: { totalDataAtRiskTb: 2.1, projectedDecryptableTb: 1.4, highValueDataPct: 40, vulnerableSharePct: 67, hasEvidence: true },
  topFindings: [
    { id: 'f1', asset: 'checkout-web', algorithm: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', severity: 'critical', dataLifetimeYears: 10, dataLifetimeLabel: '10 yrs (Financial)', riskWindow: 'Exceeds CRQC horizon', exceedsCrqc: true, migrationPriority: 'P1', environment: 'production', detectedAt: iso(-1) },
  ],
  remediationCenter: [{ key: 'hybrid-tls', label: 'Enable Hybrid TLS', affectedAssets: 3, riskReductionPct: 22, effort: 'Medium', completion: iso(14), href: '/dashboard/migration-planner?focus=tls', requires: 'TLS 1.3 + X25519 + ML-KEM-768', inScope: true }],
}

const CERTIFICATION = { generatedAt: NOW, hasData: true, eligibility: ELIGIBILITY, certificate: null, certificates: [], history: [], notifications: [], verificationActivity: [], downloads: [], trend: [], renewal: { expiresAt: null, daysRemaining: null, autoRenewEligible: false }, advisor: {}, issuer: null, schemaReady: true }

const WORKFLOW = {
  generatedAt: NOW, hasData: true, overallProgressPct: 34, currentStageId: 'remediation', certificationReadinessPct: PLAN.certificationReadinessPct, certificationEligible: false,
  stages: [
    { id: 'discovery', label: 'Discovery', shortLabel: 'Discover', status: 'complete', progressPct: 100, kpi: '4 assets', detail: '', route: '/dashboard/scanner' },
    { id: 'remediation', label: 'Remediation', shortLabel: 'Remediate', status: 'active', progressPct: 34, kpi: `${PENDING.length} open actions`, detail: '', route: '/dashboard/quantum-readiness/remediation' },
  ],
  nextAction: { stageId: 'remediation', title: 'Work the remediation queue', detail: 'Start with the critical RSA key exchange on checkout-web.', route: '/dashboard/quantum-readiness/remediation' },
  assetLifecycle: [],
  assetStates: [{ asset: 'checkout-web', stageId: 'remediation', stageLabel: 'Remediation', riskScore: 88, openActions: 2, validationStatus: 'Pending', certificationImpactPct: 8 }],
}

const SNAPSHOT_DASHBOARD = {
  generatedAt: NOW, schemaReady: true,
  summary: { total: 2, successful: 2, restorable: 1, restored: 0, expired: 1, automaticRollbacks: 0, manualRollbacks: 0, storageBytes: 2048, latestSnapshotAt: iso(-2) },
  snapshots: [
    { id: 's1', snapshotId: 'SNAP-1001', assetName: 'orders-db', status: 'restorable', integrityVerified: true, restoreExecutable: true, restoreBlockedReason: null, createdAt: iso(-2) },
    { id: 's2', snapshotId: 'SNAP-0999', assetName: 'checkout-web', status: 'expired', integrityVerified: true, restoreExecutable: false, restoreBlockedReason: 'Snapshot expired', createdAt: iso(-40) },
  ],
  audit: [],
}

/* ---- Tenant tables ----------------------------------------------------- */
const TABLES: Record<string, Array<Record<string, unknown>>> = {
  assets: ASSETS.map((a) => ({ ...a, user_id: USER_ID, created_at: iso(-30), updated_at: NOW })),
  crypto_inventory: [
    ...Object.entries(COMPONENTS).flatMap(([assetId, rows]) => rows.map((r) => ({ ...r, asset_id: assetId, user_id: USER_ID, created_at: iso(-0.1), discovered_at: iso(-0.1) }))),
    // Scanner FINDINGS share the table — never components, never algorithms.
    { id: 'p1', asset_id: 'a-web', user_id: USER_ID, name: 'certificate-risk: No Certificate Pinning', algorithm: 'No Certificate Pinning', item_type: 'finding', protocol: '', is_vulnerable: true, is_quantum_safe: false, created_at: NOW },
  ],
  certificates: [
    { id: 'cert-1', asset_id: 'a-db', user_id: USER_ID, name: 'orders-db.acme.test', algorithm: 'sha256WithRSAEncryption', key_size: 2048, issuer: 'Acme Internal CA', not_after: iso(-5), is_quantum_safe: false, is_expiring_soon: false, status: 'expired', updated_at: NOW },
    { id: 'cert-2', asset_id: 'a-web', user_id: USER_ID, name: 'checkout.acme.test', algorithm: 'sha256WithRSAEncryption', key_size: 2048, issuer: 'DigiCert G2', not_after: iso(20), is_quantum_safe: false, is_expiring_soon: true, status: 'active', updated_at: NOW },
    { id: 'cert-3', asset_id: 'a-api', user_id: USER_ID, name: 'legacy-partner.acme.test', algorithm: 'sha1WithRSAEncryption', key_size: 1024, issuer: 'Acme Internal CA', not_after: iso(60), is_quantum_safe: false, is_expiring_soon: false, status: 'active', updated_at: NOW },
    { id: 'cert-4', asset_id: 'a-hr', user_id: USER_ID, name: 'hr.acme.test', algorithm: 'ecdsa-with-SHA256', key_size: 256, issuer: 'DigiCert G2', not_after: iso(200), is_quantum_safe: false, is_expiring_soon: false, status: 'active', updated_at: NOW },
  ],
  scanner_agents: [
    { id: 'ag-1', user_id: USER_ID, name: 'dc1-collector', hostname: 'dc1.acme.internal', platform: 'linux', version: '2.4.0', status: 'active', last_seen_at: iso(-0.0005), revoked_at: null, created_at: iso(-60) },
    { id: 'ag-2', user_id: USER_ID, name: 'branch-collector', hostname: 'branch.acme.internal', platform: 'windows', version: '2.3.1', status: 'active', last_seen_at: iso(-3), revoked_at: null, created_at: iso(-60) },
  ],
  runtime_crypto_events: [
    { id: 'r1', user_id: USER_ID, algorithm: 'RSA-2048', severity: 'high', is_pqc: false, is_legacy: true, hndl_risk: true, observed_at: iso(-0.01) },
    { id: 'r2', user_id: USER_ID, algorithm: 'X25519MLKEM768', severity: 'info', is_pqc: true, is_legacy: false, hndl_risk: false, observed_at: iso(-0.02) },
  ],
  migration_jobs: [
    { id: 'job-failed-1', user_id: USER_ID, asset_id: 'a-api', name: 'partner-api TLS upgrade', job_type: 'tls-upgrade', status: 'failed', target_algorithm: 'X25519MLKEM768', created_at: iso(-2), updated_at: iso(-1) },
    { id: 'job-run-1', user_id: USER_ID, asset_id: 'a-db', name: 'orders-db certificate reissue', job_type: 'cert-reissue', status: 'running', target_algorithm: 'ML-DSA-65', created_at: iso(-1), updated_at: NOW },
  ],
  pqc_scan_sessions: [
    { id: 'scan-2', user_id: USER_ID, status: 'completed', progress: 100, total_assets: 4, scanned_assets: 4, findings_count: 10, started_at: iso(-0.2), completed_at: iso(-0.1), created_at: iso(-0.2) },
    { id: 'scan-1', user_id: USER_ID, status: 'completed', progress: 100, total_assets: 3, scanned_assets: 3, findings_count: 12, started_at: iso(-8), completed_at: iso(-8), created_at: iso(-8) },
  ],
}

/** Supabase-shaped mock that honours eq / is / in so counts and filters are real. */
function makeClient(tables: Record<string, Array<Record<string, unknown>>>, recorder: Array<{ table: string; eqs: Array<[string, unknown]> }> = []) {
  const makeQuery = (table: string) => {
    const state = { table, eqs: [] as Array<[string, unknown]>, ins: [] as Array<[string, unknown[]]>, head: false }
    const rows = () => (tables[table] || []).filter((row) =>
      state.eqs.every(([col, val]) => col === 'user_id' ? row.user_id === val : row[col] === val)
      && state.ins.every(([col, vals]) => vals.includes(row[col])))
    const settle = () => {
      recorder.push({ table, eqs: state.eqs })
      return Promise.resolve(state.head ? { count: rows().length, error: null, data: null } : { data: rows(), error: null })
    }
    const q: Record<string, unknown> = {}
    const chain = () => q
    q.select = (_c: unknown, opts?: { head?: boolean }) => { if (opts?.head) state.head = true; return q }
    q.eq = (col: string, val: unknown) => { state.eqs.push([col, val]); return q }
    q.is = (col: string, val: unknown) => { state.eqs.push([col, val]); return q }
    q.in = (col: string, vals: unknown[]) => { state.ins.push([col, vals]); return q }
    q.or = chain; q.neq = chain; q.order = chain; q.gte = chain; q.lte = chain
    q.limit = () => settle()
    q.maybeSingle = () => { recorder.push({ table, eqs: state.eqs }); return Promise.resolve({ data: rows()[0] || null, error: null }) }
    q.single = q.maybeSingle
    q.then = (res: (v: unknown) => unknown, rej?: (e: unknown) => unknown) => settle().then(res, rej)
    return q
  }
  return { from: (table: string) => makeQuery(table) }
}

const builders = {
  snapshot: async () => QR_SNAPSHOT,
  scannerIntel: async () => SCANNER_INTEL,
  exposure: async () => EXPOSURE,
  remediationPlan: async () => PLAN,
  certification: async () => CERTIFICATION,
  hndl: async () => HNDL,
  workflow: async () => WORKFLOW,
  snapshotDashboard: async () => SNAPSHOT_DASHBOARD,
} as unknown as CopilotBuilders

/** The Assets page's own register over the same payloads — the per-asset truth. */
const REGISTER = buildAssetRegister({
  snapshot: SCANNER_INTEL as unknown as RegisterSnapshotInput,
  qr: { resolved: true, hasData: true, readiness: 42, readinessLevel: 'developing', risk: 71, components: 6, vulnerableComponents: 4 },
  workflowStates: WORKFLOW.assetStates,
  now: NOW_MS,
})

function ctxFor(role: CopilotRole = 'owner', tables = TABLES, recorder?: Array<{ table: string; eqs: Array<[string, unknown]> }>): ToolContext {
  return { token: 't', userId: USER_ID, email: 'ciso@acme.test', role, tier: 'elite', client: makeClient(tables, recorder) }
}

/* ================================================================== */
/* Checks                                                              */
/* ================================================================== */

const DEAD_END = /could not derive an evidence-backed answer/i
const GARBAGE = /\bundefined\b|\bNaN\b|\[object Object\]|\bnull\/|Infinity/
const RAW_TOOL = /\b(get[A-Z]\w+|find[A-Z]\w+|search[A-Z]\w+|explain[A-Z]\w+|generate[A-Z]\w+|approve[A-Z]\w+|reject[A-Z]\w+|rollback[A-Z]\w+|restore[A-Z]\w+|create[A-Z]\w+|simulate[A-Z]\w+)\b/

function answerText(a: CopilotAnswer): string {
  return [
    a.summary,
    ...(a.keyFindings || []),
    ...(a.entities || []).flatMap((t) => [t.title, ...t.rows.flatMap((r) => Object.values(r.cells).map(String))]),
    ...(a.recommendations || []).map((r) => `${r.title} ${r.detail}`),
    a.rootCause || '',
  ].join(' \n ')
}

function entityCells(a: CopilotAnswer, key: string): string[] {
  return (a.entities || []).flatMap((t) => t.rows.map((r) => String(r.cells[key] ?? '')))
}

/** Properties EVERY answer must have, whatever it was asked. */
function universal(q: string, a: CopilotAnswer) {
  const text = answerText(a)
  assert(!DEAD_END.test(text), `[${q}] never dead-ends`, a.summary.slice(0, 90))
  assert(!GARBAGE.test(text), `[${q}] no undefined / NaN / [object Object] in the answer`, (text.match(GARBAGE) || [''])[0])
  assert(!RAW_TOOL.test(a.summary) && !a.reasoning.some((r) => RAW_TOOL.test(r)), `[${q}] no backend tool identifiers in the visible answer`)
  assert(a.summary.trim().length > 20, `[${q}] a substantive summary`)
  assert(!/[^.]\.\.(?!\.)|\)\s*\(|,\s*,|\s{2,}/.test(a.summary), `[${q}] clean prose (no doubled punctuation or spacing)`, (a.summary.match(/.{0,20}([^.]\.\.(?!\.)|\)\s*\(|,\s*,|\s{2,}).{0,20}/) || [''])[0])
  assert(a.confidence.score >= 5 && a.confidence.score <= 98, `[${q}] confidence in range`, String(a.confidence.score))
  if (a.grounding === 'none' || a.grounding === 'digest') assert(a.confidence.score <= 60, `[${q}] ungrounded answers never claim high confidence`, `${a.grounding} ${a.confidence.score}`)
  for (const table of a.entities || []) {
    assert(table.rows.length > 0, `[${q}] entity table "${table.title}" is never an empty shell`)
    assert(table.total >= table.rows.length, `[${q}] entity table total covers its rows`, `${table.total} < ${table.rows.length}`)
  }
}

interface Case {
  q: string
  focus: string | null
  check?: (a: CopilotAnswer) => void
}

const top = PENDING[0]
const registerByRisk = [...REGISTER.rows].filter((r) => r.riskScore !== null).sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0))
const internetFacing = REGISTER.rows.filter((r) => r.internetFacing).map((r) => r.name)
const unmet = CHECKS.filter((c) => !c.met)

const CASES: Case[] = [
  /* ---- The reported question ---------------------------------------- */
  { q: 'What is pending remediation?', focus: 'remediation_queue', check: (a) => {
    assert(new RegExp(`\\b${PENDING.length} remediation action`).test(a.summary), 'pending count is the Remediation Engine\'s own count', a.summary.slice(0, 120))
    assert(a.summary.includes(top.asset), 'names the first action\'s asset', top.asset)
    assert(entityCells(a, 'asset')[0] === top.asset, 'the table is in Q-REMEDY execution order')
    assert(entityCells(a, 'fix').includes(top.recommendation.replace(/[.\s]+$/, '')), 'the table names each recommended fix')
    const crit = PENDING.filter((x) => x.priority === 'critical').length
    assert(a.summary.includes(`${crit} critical`), 'critical count matches the plan', `${crit}`)
    assert(!a.evidence.some((e) => /0 finding\(s\) matched/.test(e.detail || '')), 'no "0 finding(s) matched" evidence from question words')
    assert((a.figures || []).some((f) => f.key === 'remediation.pending' && f.value === PENDING.length), 'records the pending figure for change tracking')
  } },

  /* ---- Global suggestions --------------------------------------------- */
  { q: 'Am I quantum ready?', focus: 'readiness', check: (a) => {
    assert(/^Not yet/.test(a.summary), 'an ineligible tenant is told "Not yet"', a.summary.slice(0, 40))
    assert(a.summary.includes('42/100'), 'the canonical readiness score')
    assert((a.keyFindings || []).some((f) => /readiness/i.test(f)), 'key findings state the readiness')
  } },
  { q: 'Show my most vulnerable assets.', focus: 'most_vulnerable_assets', check: (a) => {
    assert(a.summary.includes(registerByRisk[0].name) && a.summary.includes(`${registerByRisk[0].riskScore}/100`), 'the top asset and score are the Assets page\'s', registerByRisk[0].name)
    assert(!entityCells(a, 'name').includes('hr-portal'), 'an unmeasured asset is not ranked as vulnerable')
  } },
  { q: 'What should I migrate first?', focus: 'migration_priority', check: (a) => {
    assert(a.summary.startsWith(`Start with ${top.asset}`), 'starts with the #1 ranked action', a.summary.slice(0, 60))
    assert(/because of/.test(a.summary), 'explains WHY it ranks first')
  } },
  { q: 'Why has certification not been achieved?', focus: 'certification_gap', check: (a) => {
    assert(a.summary.includes('5 of 10 required criteria'), 'the met/required count is the certification engine\'s', a.summary.slice(0, 80))
    assert(a.summary.includes(unmet[0].criterion), 'names an unmet criterion by its human label', unmet[0].criterion)
    assert(!/critical-vulns|pqc-adoption|\bhndl\b(?! )/.test(a.summary), 'never prints raw criterion ids')
    assert(!!a.rootCause, 'carries an evidence-based root cause')
    assert(entityCells(a, 'criterion').length === CHECKS.length, 'lists every criterion, met and unmet')
  } },
  { q: 'What is my Harvest Now exposure?', focus: 'hndl_exposure', check: (a) => {
    assert(a.summary.includes('Critical') && a.summary.includes('64/100'), 'the measured threat level and score', a.summary.slice(0, 90))
    assert(!/exposure: assessed/i.test(answerText(a)), 'no placeholder "assessed" level')
  } },
  { q: 'Summarize my compliance posture.', focus: 'compliance_posture', check: (a) => {
    assert(/not a formal audit/i.test(a.summary), 'states it is derived, not an audit')
    assert(!/quantum readiness is/i.test(a.summary), 'answers compliance — not a readiness briefing')
  } },
  { q: 'Which certificates are expiring or weak?', focus: 'certificates', check: (a) => {
    const names = entityCells(a, 'name')
    assert(names.includes('orders-db.acme.test'), 'lists the expired certificate')
    assert(names.includes('checkout.acme.test'), 'lists the expiring certificate')
    assert(names.includes('legacy-partner.acme.test'), 'lists the weak (RSA-1024 / SHA-1) certificate')
  } },
  { q: 'Show the blast radius of my riskiest asset.', focus: 'blast_radius', check: (a) => {
    assert(/blast radius|dependents?/i.test(a.summary), 'answers with the blast radius')
  } },
  { q: 'Are my collectors and agents healthy?', focus: 'collectors', check: (a) => {
    assert(a.summary.includes('branch-collector'), 'names the offline collector')
    assert(/1 of 2 collectors is online/.test(a.summary), 'online/fleet counts', a.summary.slice(0, 80))
  } },
  { q: 'Generate an executive summary.', focus: null },

  /* ---- Page suggestions ----------------------------------------------- */
  { q: 'Summarize my latest scan findings.', focus: 'scan_summary', check: (a) => {
    assert(a.summary.includes('10 findings'), 'the latest session\'s finding count', a.summary.slice(0, 90))
  } },
  { q: 'Which findings are critical and why?', focus: 'critical_findings', check: (a) => {
    assert(entityCells(a, 'finding').length === QR_SNAPSHOT.criticalFindings.length, 'lists every consolidated critical/high finding')
    assert(entityCells(a, 'why').every((w) => w.length > 10), 'each finding carries a WHY')
  } },
  { q: 'Which discovered algorithms are quantum-vulnerable?', focus: 'algorithms', check: (a) => {
    const algos = entityCells(a, 'algorithm')
    assert(algos.length > 0 && !algos.some((x) => /AES-256/.test(x)), 'lists only vulnerable algorithms', algos.join(', '))
    assert(!algos.some((x) => /PINNING/i.test(x)), 'a scanner finding is never listed as an algorithm')
  } },
  { q: 'Which assets are internet-facing?', focus: 'assets_list', check: (a) => {
    for (const n of internetFacing) assert(a.summary.includes(n), `names internet-facing asset ${n}`)
    assert(a.summary.startsWith(`${internetFacing.length} assets are internet-facing`), 'count matches the register', a.summary.slice(0, 60))
  } },
  { q: 'Which assets carry the most cryptographic risk?', focus: 'most_vulnerable_assets' },
  { q: 'Show asset dependencies and relationships.', focus: 'dependencies' },
  { q: 'Explain my quantum readiness score.', focus: 'readiness', check: (a) => {
    assert(entityCells(a, 'factor').length === QR_SNAPSHOT.readinessFactors.length, 'every readiness factor is listed')
  } },
  { q: 'What is blocking a higher readiness level?', focus: 'readiness_blockers', check: (a) => {
    assert(a.summary.includes('Runtime Visibility (12/100)'), 'the weakest factor leads', a.summary.slice(0, 120))
  } },
  { q: 'Show my top risk assets.', focus: 'most_vulnerable_assets' },
  { q: 'Am I eligible for Quantum Trust Certification?', focus: 'certification_gap' },
  { q: 'What is blocking certification?', focus: 'certification_gap' },
  { q: 'How do I reach the next certification level?', focus: 'certification_next_level', check: (a) => {
    assert(a.summary.includes('Bronze'), 'states the current standing')
    assert(!(a.migrationStrategy?.steps.length), 'does not answer with a migration playbook')
  } },
  { q: 'Show active and failed migrations.', focus: 'migration_jobs', check: (a) => {
    assert(a.summary.includes('partner-api TLS upgrade'), 'names the failed job')
  } },
  { q: 'Do I have snapshots to roll back to?', focus: 'snapshots', check: (a) => {
    assert(/1 restorable snapshot of 2/.test(a.summary), 'restorable count', a.summary.slice(0, 80))
  } },
  { q: 'What should I migrate next?', focus: 'migration_priority' },
  { q: 'How much of my data is future-decryptable?', focus: 'future_decryptable', check: (a) => {
    assert(/Modelled/.test(a.summary) && /not a measurement/.test(a.summary), 'a modelled figure is labelled as a model')
  } },
  { q: 'Which endpoints lack forward secrecy?', focus: 'forward_secrecy', check: (a) => {
    assert(a.summary.includes('partner-api'), 'names the endpoint without forward secrecy')
  } },
  { q: 'What reduces my HNDL exposure fastest?', focus: 'hndl_reduction' },
  { q: 'Which certificates are quantum-vulnerable?', focus: 'certificates' },
  { q: 'Show expiring certificates.', focus: 'certificates' },
  { q: 'Which issuers anchor my trust chains?', focus: 'certificate_issuers', check: (a) => {
    assert(a.summary.includes('Acme Internal CA') || a.summary.includes('DigiCert G2'), 'names an issuer')
  } },
  { q: 'Walk me through my migration plan.', focus: null, check: (a) => {
    assert(!!a.migrationStrategy?.steps.length, 'a migration walkthrough carries the ordered plan')
  } },
  { q: 'What are the migration blockers?', focus: 'migration_blockers', check: (a) => {
    assert(entityCells(a, 'blocker').includes('orders-db'), 'names the dependency blocker')
    assert(entityCells(a, 'kind').includes('Failed job'), 'includes the failed job')
  } },
  { q: 'Estimate the migration effort.', focus: 'migration_effort', check: (a) => {
    const total = Math.round(PENDING.reduce((s, x) => s + x.effortWeeks, 0) * 10) / 10
    assert(a.summary.includes(`${total} week`), 'effort is the Remediation Engine\'s own total', `${total}`)
  } },

  /* ---- Follow-ups ------------------------------------------------------- */
  { q: 'Which remediation gives the biggest certification gain?', focus: 'remediation_gain' },
  { q: 'Show the critical blockers.', focus: 'critical_blockers' },
  { q: 'Which assets drive the critical risk?', focus: 'most_vulnerable_assets' },
  { q: 'How do I reduce HNDL exposure?', focus: 'hndl_reduction' },
  { q: 'What exactly is blocking certification?', focus: 'certification_gap' },
  { q: 'How close am I to CNSA 2.0?', focus: 'cnsa' },
  { q: 'Show my NIST PQC alignment.', focus: 'nist_alignment' },
  { q: 'Which certificates expire in the next 90 days?', focus: 'certificates', check: (a) => {
    const names = entityCells(a, 'name')
    assert(names.includes('checkout.acme.test') && names.includes('legacy-partner.acme.test'), 'certificates inside the 90-day window are listed')
    assert(!names.includes('hr.acme.test'), 'a certificate expiring in 200 days is outside the window')
  } },
  { q: 'What raises my readiness score fastest?', focus: 'remediation_gain' },
  { q: 'Which collectors are offline?', focus: 'collectors' },
  { q: 'Show recent legacy-crypto events.', focus: 'runtime_events', check: (a) => {
    assert(entityCells(a, 'algorithm').includes('RSA-2048'), 'lists the legacy event')
    assert(!entityCells(a, 'algorithm').includes('X25519MLKEM768'), 'a PQC event is not listed as legacy')
  } },
  { q: 'Show my third-party dependencies.', focus: 'third_parties', check: (a) => {
    assert(a.summary.includes('PayGate Ltd'), 'names the vendor')
  } },
  { q: 'Which trust chains are critical?', focus: 'dependencies' },
  { q: 'Show critical findings.', focus: 'critical_findings' },
  { q: 'Which algorithms were discovered?', focus: 'algorithms' },

  /* ---- A specific asset's real status ----------------------------------- */
  { q: 'What is the status of orders-db?', focus: 'asset_dossier', check: (a) => {
    const row = REGISTER.rows.find((r) => r.name === 'orders-db')!
    assert(a.summary.startsWith('orders-db is'), 'answers about THAT asset', a.summary.slice(0, 40))
    assert(a.summary.toLowerCase().includes(row.pqcStatusLabel.toLowerCase()), 'PQC status is the Assets page\'s', row.pqcStatusLabel)
  } },
  { q: 'Tell me about checkout-web', focus: 'asset_dossier', check: (a) => {
    assert((a.keyFindings || []).some((f) => /Payments Platform/.test(f)), 'states the recorded owner')
    // Regression: every algorithm on the asset used to be listed after "are
    // quantum-vulnerable", so the SAFE AES-256-GCM was reported as vulnerable.
    assert(!/AES-256-GCM/.test(a.summary), 'a quantum-safe algorithm is never listed as vulnerable', a.summary.slice(0, 200))
  } },
  { q: 'Is partner-api PQC-ready?', focus: 'asset_dossier', check: (a) => {
    assert(/partner-api is quantum-vulnerable/i.test(a.summary), 'a direct yes/no from the register row', a.summary.slice(0, 60))
    assert((a.keyFindings || []).some((f) => /not recorded/.test(f)), 'an unowned asset is flagged, not given an owner')
  } },
  { q: 'What is pending remediation for checkout-web?', focus: 'remediation_queue', check: (a) => {
    const assets = entityCells(a, 'asset')
    assert(assets.length > 0 && assets.every((x) => x === 'checkout-web'), 'scoped to the named asset', assets.join(', '))
  } },
  { q: 'Which assets have no owner?', focus: 'assets_list', check: (a) => {
    assert(a.summary.includes('partner-api') && !a.summary.includes('checkout-web'), 'lists only the unowned asset', a.summary.slice(0, 80))
  } },
  { q: 'Which assets have not been scanned?', focus: 'assets_list', check: (a) => {
    assert(a.summary.includes('hr-portal'), 'lists the unmeasured asset')
  } },

  /* ---- The algorithm path keeps working -------------------------------- */
  { q: 'Which internet-facing systems still use RSA and who owns them?', focus: null, check: (a) => {
    const text = answerText(a)
    assert(/checkout-web/.test(text) && /Payments Platform/.test(text), 'names the RSA asset and its owner')
  } },
]

/* ================================================================== */
async function ask(q: string, ctx: ToolContext = ctxFor(), b: CopilotBuilders = builders, priorFigures?: PriorFigures) {
  return (await runCopilotQuery(ctx, q, { ...EMPTY_MEMORY }, () => {}, b, { priorFigures })).answer
}

async function main() {
  console.log(`\nGROUND TRUTH — ${ASSETS.length} assets · ${PENDING.length} pending remediation action(s) (real Q-REMEDY plan) · ${REGISTER.rows.length} register rows`)

  console.log('\n[1] Every suggestion Sophia offers resolves to the right specialist')
  const offered = new Set<string>()
  for (const page of ['/dashboard', '/dashboard/sophia', '/dashboard/scanner', '/dashboard/assets', '/dashboard/quantum-readiness', '/dashboard/quantum-certification', '/dashboard/live-migration', '/dashboard/harvest-now', '/dashboard/pki-visibility', '/dashboard/migration-planner']) {
    for (const s of suggestionsForPage(page)) offered.add(s.text)
  }
  for (const text of offered) {
    assert(CASES.some((c) => c.q === text), `suggestion "${text}" is covered by this audit`)
  }

  console.log(`\n[2] ${CASES.length} questions answered against the canonical engines`)
  const followUps = new Set<string>()
  for (const c of CASES) {
    const a = await ask(c.q)
    // SOPHIA_AUDIT_PRINT=1 prints every answer for human review of the prose.
    if (process.env.SOPHIA_AUDIT_PRINT) console.log(`\n  Q: ${c.q}\n  [${a.focus ?? a.grounding}] ${a.summary}${(a.entities || []).map((t) => `\n    ▸ ${t.title}: ${t.rows.slice(0, 3).map((r) => Object.values(r.cells).slice(0, 3).join(' | ')).join(' ‖ ')}`).join('')}`)
    universal(c.q, a)
    assert((a.focus ?? null) === c.focus, `[${c.q}] routed to ${c.focus ?? 'cross-module agents'}`, `got ${a.focus ?? 'null'}`)
    if (c.focus) assert(a.grounding === 'focused', `[${c.q}] answered by the topic's own module`, a.grounding || 'none')
    if (c.focus && /^(which|show|list)/i.test(c.q)) assert((a.entities || []).length > 0, `[${c.q}] a "which/show" question returns the records, not just a count`)
    c.check?.(a)
    for (const f of a.followUps) followUps.add(f)
  }

  console.log(`\n[3] Every follow-up Sophia offers is itself answerable (${followUps.size})`)
  for (const f of followUps) {
    const a = await ask(f)
    universal(f, a)
    assert(a.grounding !== 'none', `[${f}] follow-up is grounded`, a.grounding || 'none')
  }

  console.log('\n[4] Empty tenant — no fabricated figures, no dead ends')
  const emptyTables: Record<string, Array<Record<string, unknown>>> = {}
  const emptyPlan = buildRemediationPlan({ ...REMEDIATION_EVIDENCE, hasData: false, assets: [], migrationJobs: [] })
  const emptyBuilders = {
    snapshot: async () => ({ ...QR_SNAPSHOT, hasData: false, lastAssessmentAt: null, scores: {}, inventory: {}, riskDistribution: {}, readinessFactors: [], criticalFindings: [], topRiskAssets: [], recommendedActions: [] }),
    scannerIntel: async () => ({ summary: {}, severityCounts: {}, findings: [], assets: { assets: [] }, history: { history: [] } }),
    exposure: async () => ({ ...EXPOSURE, hasData: false, graph: { nodes: [], edges: [] }, thirdParty: [], migrationOrder: { waves: [], clusters: [], blockers: [] }, summary: { ...EXPOSURE.summary, totalAssets: 0, trustRelationships: 0 } }),
    remediationPlan: async () => emptyPlan,
    certification: async () => ({ ...CERTIFICATION, eligibility: { ...ELIGIBILITY, hasData: false, requiredMet: 0, checks: [] } }),
    hndl: async () => ({ ...HNDL, hasData: false, forwardSecrecy: { hasEvidence: false }, futureDecryptable: { hasEvidence: false }, topFindings: [], remediationCenter: [] }),
    workflow: async () => ({ ...WORKFLOW, hasData: false, overallProgressPct: 0, assetStates: [] }),
    snapshotDashboard: async () => ({ ...SNAPSHOT_DASHBOARD, summary: { ...SNAPSHOT_DASHBOARD.summary, total: 0, restorable: 0 }, snapshots: [] }),
  } as unknown as CopilotBuilders
  for (const c of CASES) {
    const a = await ask(c.q, ctxFor('owner', emptyTables), emptyBuilders)
    universal(`empty: ${c.q}`, a)
    const fabricated = (a.entities || []).some((t) => t.rows.length > 0) && !/no |not |nothing|none|yet|empty|scan/i.test(a.summary)
    assert(!fabricated, `[empty: ${c.q}] no records invented for an empty tenant`, a.summary.slice(0, 80))
  }

  console.log('\n[5] Restricted role — answers degrade honestly, never crash')
  for (const c of CASES.slice(0, 12)) {
    const a = await ask(c.q, ctxFor('security_analyst'))
    universal(`analyst: ${c.q}`, a)
  }

  console.log('\n[6] Longitudinal memory — change is reported, in the right direction')
  const first = await ask('What is pending remediation?')
  const prior: PriorFigures = {}
  for (const f of first.figures || []) prior[f.key] = { value: f.key === 'remediation.pending' ? f.value + 3 : f.value, at: iso(-2) }
  const second = await ask('What is pending remediation?', ctxFor(), builders, prior)
  const pendingChange = (second.changes || []).find((c) => c.key === 'remediation.pending')
  assert(!!pendingChange, 'a change is reported for the pending count')
  assert(pendingChange?.delta === -3 && pendingChange.direction === 'improved', 'fewer pending actions reads as improved', JSON.stringify(pendingChange))
  const readinessChange = computeChanges([{ key: 'readiness.score', label: 'Quantum readiness', value: 40, better: 'higher', source: 'x' }], { 'readiness.score': { value: 45, at: iso(-3) } })[0]
  assert(readinessChange?.direction === 'worsened', 'a falling readiness score reads as worsened')
  const recent = computeChanges([{ key: 'k', label: 'k', value: 1, better: 'lower', source: 'x' }], { k: { value: 5, at: new Date(NOW_MS - 60_000).toISOString() } })
  assert(recent.length === 0, 'a reading from a minute ago is not reported as a change')

  console.log('\n[7] Tenant isolation holds across every specialist')
  const recorder: Array<{ table: string; eqs: Array<[string, unknown]> }> = []
  for (const c of CASES) await ask(c.q, ctxFor('owner', TABLES, recorder))
  assert(recorder.length > 0, 'specialists queried the database')
  assert(recorder.every((r) => r.eqs.some(([col, val]) => col === 'user_id' && val === USER_ID)), 'EVERY query is pinned to the authenticated tenant', [...new Set(recorder.filter((r) => !r.eqs.some(([c]) => c === 'user_id')).map((r) => r.table))].join(', '))

  console.log('\n[8] Question words never become filters')
  for (const q of ['What is pending remediation?', 'Which certificates expire in the next 90 days?', 'Show the critical blockers.']) {
    const filter = extractQueryFilter(q)
    assert(filter.query === '', `"${q}" produces no name filter`, JSON.stringify(filter.query))
    assert(filter.mentions.length === 0, `"${q}" produces no asset mention`, filter.mentions.join(','))
    assert(resolveFocus(q, [], 'status', filter) !== null, `"${q}" has a topic owner`)
  }
  assert(extractQueryFilter('Which certificates expire in the next 90 days?').withinDays === 90, 'a named window is read in days')
  assert(extractQueryFilter('What is the status of orders-db?').mentions.includes('orders-db'), 'a real asset name survives as a mention')
  assert(!extractQueryFilter('Which servers are internet-facing?').mentions.length, 'an asset TYPE word is never an asset mention')

  console.log(failures === 0
    ? `\n✓ SOPHIA QUESTION AUDIT PASSED — ${checks} checks across ${CASES.length} questions + ${followUps.size} follow-ups\n`
    : `\n✗ ${failures} of ${checks} CHECK(S) FAILED\n`)
  process.exit(failures === 0 ? 0 : 1)
}

void main()
