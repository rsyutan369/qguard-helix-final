/**
 * Offline verification for the Harvest Now, Decrypt Later intelligence engine
 * (Harvest_Now_Decrypt_Later_Update). Drives the pure assembleHndlIntelligence()
 * with a synthetic-but-realistic Quantum Readiness snapshot + raw tenant rows and
 * asserts all 16 sections derive from evidence — and that an empty snapshot
 * yields empty states (no fabricated values). No server/Supabase required.
 *
 *   npx tsx tools/hndl-check.ts
 */
import { assembleHndlIntelligence, type HndlRawRows } from '../src/api-server/harvest-now'

type AssembleSnapshot = Parameters<typeof assembleHndlIntelligence>[0]
type Row = Record<string, unknown>

const NOW = new Date().toISOString()

const ENTERPRISE_SNAPSHOT = {
  generatedAt: NOW,
  lastAssessmentAt: NOW,
  assessmentProgress: 100,
  assessmentStatus: 'complete',
  hasData: true,
  scores: {
    quantumReadiness: 31, quantumReadinessLevel: 'Emerging',
    quantumRisk: 64, quantumRiskLevel: 'High',
    hndlRisk: 68, hndlRiskLevel: 'High',
    cryptoExposure: 62, cryptoExposureLevel: 'High',
    migrationComplexity: 55, migrationComplexityLevel: 'Medium',
    migrationEffort: 60, pqcAdoption: 14,
  },
  inventory: {
    assetsAssessed: 26, certificatesAnalyzed: 18, keysDiscovered: 33, trustRelationships: 9,
    domainsScanned: 14, identitiesAnalyzed: 7, cloudAccounts: 3, dataRepositories: 6,
    pqcReadyAssets: 2, hybridAssets: 1, quantumVulnerableAssets: 22,
    cryptoComponents: 150, vulnerableComponents: 41, pqcReadyComponents: 18,
  },
  riskDistribution: { critical: 7, high: 12, medium: 15, low: 7 },
  readinessFactors: [{ label: 'TLS', score: 22 }, { label: 'PKI', score: 18 }],
  riskFactors: [{ label: 'Legacy RSA', score: 72, severity: 'critical' }],
  criticalFindings: [
    { id: 'F1', title: 'Legacy RSA cipher', asset: 'portal.acme.com', assetType: 'customer web', environment: 'production', severity: 'critical', algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', detectedAt: NOW },
    { id: 'F2', title: 'RSA-2048 key', asset: 'api.acme.com', assetType: 'financial service', environment: 'production', severity: 'critical', algorithm: 'RSA-2048', detectedAt: NOW },
    { id: 'F3', title: 'ECDSA P-256', asset: 'auth.acme.com', assetType: 'identity', environment: 'production', severity: 'high', algorithm: 'ECDSA-P256-SHA256', detectedAt: NOW },
    { id: 'F4', title: 'SHA-1 cert', asset: 'legacy.acme.com', assetType: 'source code repo', environment: 'staging', severity: 'medium', algorithm: 'SHA-1', detectedAt: NOW },
  ],
  recommendedActions: [{ id: 'R1', title: 'Enable hybrid TLS', detail: 'X25519+ML-KEM', severity: 'critical', route: '/dashboard/migration-planner' }],
  topRiskAssets: [
    { asset: 'portal.acme.com', assetType: 'customer web', environment: 'production', owner: 'Infra', riskScore: 88, status: 'Vulnerable' },
    { asset: 'api.acme.com', assetType: 'financial service', environment: 'production', owner: 'Platform', riskScore: 79, status: 'Vulnerable' },
    { asset: 'auth.acme.com', assetType: 'identity', environment: 'production', owner: 'Unassigned', riskScore: 72, status: 'Vulnerable' },
  ],
  exposureGraph: {
    nodes: [
      { id: 'n1', label: 'portal.acme.com', type: 'customer web', environment: 'production', riskScore: 88, posture: 'vulnerable', internetFacing: true },
      { id: 'n2', label: 'api.acme.com', type: 'financial service', environment: 'production', riskScore: 79, posture: 'vulnerable', internetFacing: true },
      { id: 'n3', label: 'auth.acme.com', type: 'identity', environment: 'production', riskScore: 72, posture: 'hybrid', internetFacing: false },
      { id: 'n4', label: 'vault.acme.com', type: 'database store', environment: 'production', riskScore: 40, posture: 'pqc', internetFacing: false },
    ],
    edges: [{ source: 'n1', target: 'n2', type: 'depends-on' }, { source: 'n2', target: 'n3', type: 'uses' }],
  },
  riskTrend: [{ label: 'Wk1', readiness: 22, risk: 72 }, { label: 'Wk4', readiness: 27, risk: 68 }, { label: 'Wk8', readiness: 31, risk: 64 }],
  estimates: { migrationTimelineWeeks: 26, migrationCostUsd: 168000 },
  telemetry: { runtimeEvents: 4200, scanResults: 980, scanSessions: 12, securityEvents: 140, certificates: 18, keys: 33, assets: 26, connectors: 4, latestEventAt: NOW },
} as unknown as AssembleSnapshot

const ENTERPRISE_ROWS: HndlRawRows = {
  cryptoInventory: [
    { algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', protocol: 'TLS1.2', item_type: 'cipher', name: 'portal.acme.com', is_vulnerable: true, is_quantum_safe: false },
    { algorithm: 'RSA-2048', protocol: 'TLS', item_type: 'key-exchange', name: 'api.acme.com', is_vulnerable: true, is_quantum_safe: false },
    { algorithm: 'ECDHE-RSA-AES128-GCM', protocol: 'TLS1.3', item_type: 'cipher', name: 'web.acme.com', is_vulnerable: false, is_quantum_safe: false },
    { algorithm: 'ECDSA-P256', protocol: 'TLS', item_type: 'signature', name: 'auth.acme.com', is_vulnerable: true, is_quantum_safe: false },
    { algorithm: 'X25519', protocol: 'TLS1.3', item_type: 'key-exchange', name: 'cdn.acme.com', is_vulnerable: false, is_quantum_safe: false },
    { algorithm: 'ML-KEM-768', protocol: 'TLS1.3-hybrid', item_type: 'kem', name: 'vault.acme.com', is_vulnerable: false, is_quantum_safe: true },
    { algorithm: 'SSH-RSA', protocol: 'SSH', item_type: 'key', name: 'bastion.acme.com', is_vulnerable: true, is_quantum_safe: false },
    { algorithm: 'AES-256-GCM', protocol: 'TLS1.3', item_type: 'cipher', name: 'store.acme.com', is_vulnerable: false, is_quantum_safe: true },
  ],
  certificates: [
    { algorithm: 'RSA-2048', name: 'portal.acme.com', is_quantum_safe: false, not_after: '2026-12-01' },
    { algorithm: 'ECDSA-P256', name: 'api.acme.com', is_quantum_safe: false, not_after: '2026-08-01' },
  ],
  runtimeEvents: [
    { algorithm: 'RSA-2048', is_legacy: true, is_pqc: false, hndl_risk: 80, asset_name: 'portal.acme.com' },
    { algorithm: 'ML-KEM-768', is_legacy: false, is_pqc: true, hndl_risk: 5, asset_name: 'vault.acme.com' },
  ],
  assets: [
    { name: 'portal.acme.com', type: 'customer web', environment: 'production', region: 'us-east', criticality: 80, metadata: { cloud_provider: 'AWS', data_type: 'customer pii' } },
    { name: 'api.acme.com', type: 'financial service', environment: 'production', region: 'us-east', criticality: 75, metadata: { cloud_provider: 'AWS', industry: 'finance' } },
    { name: 'auth.acme.com', type: 'identity', environment: 'production', region: 'eu-west', criticality: 70, metadata: { cloud_provider: 'Azure' } },
    { name: 'repo.acme.com', type: 'source code repo', environment: 'production', region: 'eu-west', criticality: 60, metadata: { data_type: 'source code' } },
    { name: 'mail.acme.com', type: 'mail exchange', environment: 'production', region: 'ap-southeast', criticality: 55, metadata: {} },
    { name: 'vault.acme.com', type: 'database store', environment: 'production', region: 'us-east', criticality: 50, metadata: {} },
    // No region telemetry — must land in the honest "unlocated" tray, with a
    // trust link to its certificate authority parsed from the real chain DN.
    {
      name: 'edge-fn.acme.com', type: 'edge function', environment: null, region: null, criticality: 45,
      metadata: { certificate: { chain: [
        { issuer: "CN=R13, O=Let's Encrypt, C=US", publicKeyAlgorithm: 'RSA-2048' },
        { issuer: 'CN=ISRG Root X1, O=Internet Security Research Group, C=US', publicKeyAlgorithm: 'RSA-4096' },
      ] } },
    },
  ],
  migrationJobs: [
    { status: 'running', progress: 40, job_type: 'tls-migration' },
    { status: 'completed', progress: 100, job_type: 'cert-rotation' },
    { status: 'failed', progress: 0, job_type: 'key-rotation' },
  ],
}

const EMPTY_SNAPSHOT = {
  generatedAt: null, lastAssessmentAt: null, assessmentProgress: 0, assessmentStatus: 'not_started', hasData: false,
  scores: { quantumReadiness: 0, quantumReadinessLevel: 'Not Started', quantumRisk: 0, quantumRiskLevel: 'Minimal', hndlRisk: 0, hndlRiskLevel: 'Minimal', cryptoExposure: 0, cryptoExposureLevel: 'Minimal', migrationComplexity: 0, migrationComplexityLevel: 'Minimal', migrationEffort: 0, pqcAdoption: 0 },
  inventory: { assetsAssessed: 0, certificatesAnalyzed: 0, keysDiscovered: 0, trustRelationships: 0, domainsScanned: 0, identitiesAnalyzed: 0, cloudAccounts: 0, dataRepositories: 0, pqcReadyAssets: 0, hybridAssets: 0, quantumVulnerableAssets: 0, cryptoComponents: 0, vulnerableComponents: 0, pqcReadyComponents: 0 },
  riskDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
  readinessFactors: [], riskFactors: [], criticalFindings: [], recommendedActions: [], topRiskAssets: [],
  exposureGraph: { nodes: [], edges: [] }, riskTrend: [], estimates: { migrationTimelineWeeks: 0, migrationCostUsd: 0 },
  telemetry: { runtimeEvents: 0, scanResults: 0, scanSessions: 0, securityEvents: 0, certificates: 0, keys: 0, assets: 0, connectors: 0, latestEventAt: null },
} as unknown as AssembleSnapshot

const EMPTY_ROWS: HndlRawRows = { cryptoInventory: [], certificates: [], runtimeEvents: [], assets: [], migrationJobs: [] }

let failures = 0
const assert = (cond: boolean, msg: string) => { console.log(`  ${cond ? '✓' : '✗'} ${msg}`); if (!cond) failures++ }

function verifyEnterprise() {
  const r = assembleHndlIntelligence(ENTERPRISE_SNAPSHOT, ENTERPRISE_ROWS)
  console.log('=== Enterprise snapshot — 16 sections ===')
  assert(r.hasData === true, 'hasData=true')
  // S1 Banner
  assert(r.banner.threatLevel === 'Critical' && r.banner.hndlExposureScore === 68, `S1 Banner: ${r.banner.threatLevel}, HNDL ${r.banner.hndlExposureScore}, future ${r.banner.estimatedFutureDecryptableTb} TB`)
  // S2 Exposure graph
  assert(r.exposureGraph.tiers.length >= 5 && r.exposureGraph.nodes.length === 4, `S2 Exposure Graph: ${r.exposureGraph.tiers.length} tiers, ${r.exposureGraph.nodes.length} nodes`)
  // S3 Theater (3D map model)
  assert(r.theater.regions.length >= 3 && r.theater.totalRegions === r.theater.regions.length, `S3 Theater: ${r.theater.regions.length} regions, ${r.theater.highValueTargets} high-value`)
  const m = r.theater.map
  assert(m.sites.length === 3 && m.sites.every((s) => Number.isFinite(s.lat) && Number.isFinite(s.lon) && s.x >= 0 && s.x <= 100 && s.y >= 0 && s.y <= 100), `S3 map: ${m.sites.length} located sites w/ real geo (${m.sites.map((s) => s.key).join(', ')})`)
  assert(m.sites.every((s) => (s.topAssets ?? []).length > 0), 'S3 map: every site lists its real assets')
  assert(m.unlocated.length === 1 && m.unlocated[0].name === 'edge-fn.acme.com' && m.unlocatedTotal === 1, `S3 map: unlocated tray honest (${m.unlocated.map((u) => u.name).join(', ')})`)
  const le = m.anchors.find((a) => /encrypt/i.test(a.name))
  assert(!!le && le.country === 'US' && le.x != null && le.quantumSafe === false, `S3 map: CA trust anchor from real issuer DN (${m.anchors.map((a) => `${a.name}@${a.country}`).join('; ')})`)
  assert(m.assetLinks.length === 1 && m.assetLinks[0].from !== m.assetLinks[0].to && m.assetLinks[0].vulnerable === true, `S3 map: cross-region link from real asset_relationships (${m.assetLinks.map((l) => `${l.from}→${l.to}`).join('; ')})`)
  assert(m.trustLinks.some((t) => t.asset === 'edge-fn.acme.com' && t.siteKey === null), 'S3 map: unlocated asset trust-links to its CA without a fabricated location')
  // S4 Harvest value
  assert(r.harvestValue.length === 8 && r.harvestValue.some((h) => h.inScope), `S4 Harvest Value: ${r.harvestValue.length} categories, ${r.harvestValue.filter((h) => h.inScope).length} in scope`)
  // S5 Shelf-life
  assert(r.shelfLife.length === 8 && r.shelfLife.some((s) => s.exceedsCrqc), `S5 Shelf-Life: ${r.shelfLife.length} types, ${r.shelfLife.filter((s) => s.exceedsCrqc).length} exceed CRQC`)
  // S6 Break timeline
  assert(r.breakTimeline.years.length >= 5 && r.breakTimeline.crqcYear === 2030, `S6 Break Timeline: ${r.breakTimeline.years.length} years, CRQC ${r.breakTimeline.crqcYear}, completion ${r.breakTimeline.migrationCompletionYear}`)
  // S7 Forward secrecy
  assert(r.forwardSecrecy.totalTransport > 0 && r.forwardSecrecy.nonPfsBreakdown.some((b) => b.type === 'TLS_RSA'), `S7 Forward Secrecy: ${r.forwardSecrecy.coveragePct}% coverage, ${r.forwardSecrecy.assetsUnprotected} unprotected, buckets [${r.forwardSecrecy.nonPfsBreakdown.map((b) => b.type).join(', ')}]`)
  // S8 Matrix
  const rsa = r.exposureMatrix.find((m) => m.algorithm === 'RSA-2048')
  assert(r.exposureMatrix.length > 0 && !!rsa && rsa.cryptoClass === 'vulnerable', `S8 Exposure Matrix: ${r.exposureMatrix.length} algorithms; RSA-2048 priority=${rsa?.migrationPriority}`)
  // S9 Captured
  assert(r.capturedData.hasEvidence && r.capturedData.totalTb > 0, `S9 Captured Data: ${r.capturedData.totalTb} TB across ${r.capturedData.lines.filter((l) => l.gb > 0).length} sources`)
  // S10 Future decryptable
  assert(r.futureDecryptable.projectedDecryptableTb >= 0 && r.futureDecryptable.projectedDecryptableTb <= r.capturedData.totalTb, `S10 Future Decryptable: ${r.futureDecryptable.projectedDecryptableTb}/${r.futureDecryptable.totalDataAtRiskTb} TB, ${r.futureDecryptable.highValueDataPct}% high-value`)
  // S11 Migration readiness
  assert(r.migrationReadiness.pqcReady === 1 && r.migrationReadiness.legacyOnly === 2 && r.migrationReadiness.migrationInProgress === 1, `S11 Migration Readiness: PQC ${r.migrationReadiness.pqcReady}, hybrid ${r.migrationReadiness.hybridReady}, legacy ${r.migrationReadiness.legacyOnly}, blocked ${r.migrationReadiness.migrationBlocked}`)
  // S12 Adversary interest
  assert(r.adversaryInterest.length === 7, `S12 Adversary Interest: ${r.adversaryInterest.length} sectors; top ${r.adversaryInterest[0]?.sector} (${r.adversaryInterest[0]?.interestScore})`)
  // S13 Threat actors
  assert(r.threatActors.length === 5 && r.threatActors[0].targetedAssetCount > 0, `S13 Threat Actors: ${r.threatActors.length}; top ${r.threatActors[0]?.actor} (${r.threatActors[0]?.interestScore})`)
  // S14 Intelligence feed
  assert(r.intelligenceFeed.length >= 6 && r.intelligenceFeed.every((i) => i.source && i.title), `S14 Intelligence Feed: ${r.intelligenceFeed.length} items`)
  // S15 Top findings
  assert(r.topFindings.length > 0 && r.topFindings.every((f) => f.algorithm && f.riskWindow), `S15 Top Findings: ${r.topFindings.length}; ${r.topFindings.filter((f) => f.exceedsCrqc).length} exceed CRQC`)
  // S16 Remediation
  assert(r.remediationCenter.length === 8 && r.remediationCenter.some((a) => a.inScope), `S16 Remediation Center: ${r.remediationCenter.length} actions, ${r.remediationCenter.filter((a) => a.inScope).length} in scope`)
  // Consistency
  assert(r.scores.hndlRisk === 68 && r.scores.quantumRisk === 64, `Consistency: HNDL ${r.scores.hndlRisk}, quantum risk ${r.scores.quantumRisk} mirror snapshot`)
  assert(r.evidence.sources.length === 6, `Evidence: ${r.evidence.sources.length} sources`)
}

function verifyEmpty() {
  const r = assembleHndlIntelligence(EMPTY_SNAPSHOT, EMPTY_ROWS)
  console.log('\n=== Empty snapshot — no fabricated values ===')
  assert(r.hasData === false, 'hasData=false')
  assert(r.banner.threatLevel === 'Unknown' && r.banner.estimatedFutureDecryptableTb === 0, `Banner: ${r.banner.threatLevel}, future ${r.banner.estimatedFutureDecryptableTb} TB`)
  assert(r.harvestValue.length === 0, `Harvest Value empty (${r.harvestValue.length})`)
  assert(r.adversaryInterest.length === 0, `Adversary Interest empty (${r.adversaryInterest.length})`)
  assert(r.threatActors.length === 0, `Threat Actors empty (${r.threatActors.length})`)
  assert(r.capturedData.hasEvidence === false && r.capturedData.totalTb === 0, `Captured Data: 0 TB, hasEvidence=${r.capturedData.hasEvidence}`)
  assert(r.futureDecryptable.projectedDecryptableTb === 0, `Future Decryptable: 0 TB`)
  assert(r.exposureMatrix.length === 0, `Exposure Matrix empty (${r.exposureMatrix.length})`)
  assert(r.theater.map.sites.length === 0 && r.theater.map.anchors.length === 0 && r.theater.map.unlocated.length === 0, 'Theater map empty — no fabricated sites/anchors')
  assert(r.evidence.note.includes('Evidence Not Available'), 'Evidence note flags unavailable')
}

verifyEnterprise()
verifyEmpty()
console.log(failures === 0 ? '\nAll HNDL section checks passed.' : `\n${failures} check(s) FAILED`)
process.exit(failures === 0 ? 0 : 1)
