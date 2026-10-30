// Fixture copied from tools/quantum-risk-check.ts (lines 45–119) so render cases run the REAL
// derivation over the same evidence the check tool asserts on.
import { buildAssetPortfolio, type Row } from '../../../src/lib/migration/asset-intelligence'
import type { RiskSnapshotFacts } from '../../../src/lib/quantum-risk/risk-intelligence'

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


export { NOW, snapshot, portfolio }
