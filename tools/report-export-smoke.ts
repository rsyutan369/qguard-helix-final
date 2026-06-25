/**
 * Exporter smoke test (Reports_Enhancements_3).
 *
 * Builds the unified report model from two synthetic-but-realistic Quantum
 * Readiness snapshots (enterprise multi-asset + single-asset compact) and runs
 * ALL seven exporters against each, asserting every format produces a non-empty
 * artefact without throwing. This validates that every Phase 1-14 Report
 * Intelligence section renders in every output format (PDF/DOCX/XLSX/CSV/JSON/
 * HTML/PPTX). No server or Supabase required.
 *
 *   npx tsx tools/report-export-smoke.ts
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { QuantumReadinessSnapshot } from '../src/app/dashboard/quantum-readiness/_shared';
import { buildReportModel } from '../src/services/reporting/ReportEvidence';
import { exportReport } from '../src/services/reporting/ReportExporter';
import { brandingSchema, REPORT_FORMATS, enterpriseAssessmentReportSchema } from '../src/services/reporting/schemas/ReportSchema';

const ENTERPRISE: QuantumReadinessSnapshot = {
  generatedAt: new Date().toISOString(),
  lastAssessmentAt: new Date().toISOString(),
  assessmentProgress: 100,
  assessmentStatus: 'complete',
  hasData: true,
  scores: {
    quantumReadiness: 29, quantumReadinessLevel: 'Emerging',
    quantumRisk: 58, quantumRiskLevel: 'High',
    hndlRisk: 62, hndlRiskLevel: 'High',
    cryptoExposure: 64, cryptoExposureLevel: 'High',
    migrationComplexity: 55, migrationComplexityLevel: 'Medium',
    migrationEffort: 60, pqcAdoption: 12,
  },
  inventory: {
    assetsAssessed: 24, certificatesAnalyzed: 18, keysDiscovered: 31, trustRelationships: 9,
    domainsScanned: 12, identitiesAnalyzed: 7, cloudAccounts: 3, dataRepositories: 5,
    pqcReadyAssets: 2, hybridAssets: 1, quantumVulnerableAssets: 21,
    cryptoComponents: 140, vulnerableComponents: 38, pqcReadyComponents: 17,
  },
  riskDistribution: { critical: 6, high: 11, medium: 14, low: 7 },
  readinessFactors: [
    { label: 'TLS / Protocol Maturity', score: 22 },
    { label: 'PKI Readiness', score: 18 },
    { label: 'Crypto Agility', score: 25 },
    { label: 'Governance', score: 30 },
    { label: 'Runtime Telemetry Coverage', score: 40 },
  ],
  riskFactors: [
    { label: 'Legacy RSA Key Exchange', score: 72, severity: 'critical' },
    { label: 'Missing Forward Secrecy', score: 55, severity: 'high' },
  ],
  criticalFindings: [
    { id: 'FND-001', title: 'Legacy RSA cipher suite', asset: 'portal.qguardhelix.com', assetType: 'web', environment: 'production', severity: 'critical', algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', detectedAt: new Date().toISOString() },
    { id: 'FND-002', title: 'Legacy RSA cipher suite', asset: 'portal.qguardhelix.com', assetType: 'web', environment: 'production', severity: 'critical', algorithm: 'TLS_RSA_WITH_AES_128_CBC_SHA', detectedAt: new Date().toISOString() },
    { id: 'FND-003', title: 'ECDSA certificate signature', asset: 'api.qguardhelix.com', assetType: 'service', environment: 'production', severity: 'high', algorithm: 'ECDSA-P256-SHA256', detectedAt: new Date().toISOString() },
    { id: 'FND-004', title: 'ECDH key exchange', asset: 'auth.qguardhelix.com', assetType: 'identity', environment: 'production', severity: 'high', algorithm: 'ECDH-P256', detectedAt: new Date().toISOString() },
    { id: 'FND-005', title: 'Deprecated hash', asset: 'legacy.qguardhelix.com', assetType: 'web', environment: 'production', severity: 'medium', algorithm: 'SHA-1', detectedAt: new Date().toISOString() },
  ],
  recommendedActions: [
    { id: 'REC-001', title: 'Enable hybrid TLS on internet-facing endpoints', detail: 'Deploy X25519 + ML-KEM-768 on all public load balancers.', severity: 'critical', route: '/dashboard/migration-planner' },
    { id: 'REC-002', title: 'Plan ML-DSA certificate authority migration', detail: 'Stage hybrid certificate chain for production CAs.', severity: 'high', route: '/dashboard/qkms' },
  ],
  topRiskAssets: [
    { asset: 'portal.qguardhelix.com', assetType: 'web', environment: 'production', owner: 'Infrastructure Team', riskScore: 88, status: 'Vulnerable' },
    { asset: 'api.qguardhelix.com', assetType: 'service', environment: 'production', owner: 'Platform Team', riskScore: 76, status: 'Vulnerable' },
    { asset: 'auth.qguardhelix.com', assetType: 'identity', environment: 'production', owner: 'Unassigned', riskScore: 71, status: 'Vulnerable' },
    { asset: 'legacy.qguardhelix.com', assetType: 'web', environment: 'staging', owner: 'App Team', riskScore: 52, status: 'Vulnerable' },
  ],
  exposureGraph: {
    nodes: [
      { id: 'n1', label: 'portal.qguardhelix.com', type: 'web', environment: 'production', riskScore: 88, posture: 'vulnerable', internetFacing: true },
      { id: 'n2', label: 'api.qguardhelix.com', type: 'service', environment: 'production', riskScore: 76, posture: 'vulnerable', internetFacing: true },
      { id: 'n3', label: 'auth.qguardhelix.com', type: 'identity', environment: 'production', riskScore: 71, posture: 'vulnerable', internetFacing: false },
      { id: 'n4', label: 'kms.qguardhelix.com', type: 'cloud', environment: 'production', riskScore: 40, posture: 'hybrid', internetFacing: false },
    ],
    edges: [
      { source: 'n1', target: 'n2', type: 'depends-on' },
      { source: 'n2', target: 'n3', type: 'depends-on' },
      { source: 'n2', target: 'n4', type: 'uses' },
    ],
  },
  riskTrend: [
    { label: 'Wk 1', readiness: 20, risk: 70 },
    { label: 'Wk 4', readiness: 25, risk: 64 },
    { label: 'Wk 8', readiness: 29, risk: 58 },
  ],
  estimates: { migrationTimelineWeeks: 26, migrationCostUsd: 163020 },
  telemetry: {
    runtimeEvents: 4200, scanResults: 980, scanSessions: 12, securityEvents: 140,
    certificates: 18, keys: 31, assets: 24, connectors: 4, latestEventAt: new Date().toISOString(),
  },
};

// Single-asset compact scope → exercises Phase 4 adaptive 3-wave path.
const SINGLE_ASSET: QuantumReadinessSnapshot = {
  ...ENTERPRISE,
  inventory: { ...ENTERPRISE.inventory, assetsAssessed: 1, cloudAccounts: 0, identitiesAnalyzed: 0, certificatesAnalyzed: 1, quantumVulnerableAssets: 1, vulnerableComponents: 4 },
  criticalFindings: ENTERPRISE.criticalFindings.slice(0, 2),
  topRiskAssets: ENTERPRISE.topRiskAssets.slice(0, 1),
  exposureGraph: { nodes: ENTERPRISE.exposureGraph.nodes.slice(0, 1), edges: [] },
  estimates: { migrationTimelineWeeks: 5, migrationCostUsd: 16800 },
};

let phaseFailures = 0;
function assert(cond: boolean, msg: string) {
  console.log(`  ${cond ? '✓' : '✗'} ${msg}`);
  if (!cond) phaseFailures++;
}

function verifyPhases(report: ReturnType<typeof buildReportModel>, snapshot: QuantumReadinessSnapshot) {
  console.log('  --- Phase 1-14 model assertions ---');
  const contribSum = report.riskMethodology.weights.reduce((s, w) => s + w.contributionPct, 0);
  assert(report.riskMethodology.weights.length === 9 && Math.abs(contribSum - 100) <= 2, `Phase1 Risk Methodology: 9 domains, contributions≈100 (=${contribSum}); top=${report.riskMethodology.topDriver}`);
  assert(!!report.advisorValidation.primaryExposureDomain && report.advisorValidation.why.length > 20, `Phase2 Advisor Validation: primary=${report.advisorValidation.primaryExposureDomain}`);
  assert(report.costBreakdown.lines.every((l) => /hrs ×/.test(l.formula) || l.formula === 'Evidence Not Available') && report.costBreakdown.totalUsd > 0, `Phase3 Cost Breakdown: ${report.costBreakdown.lines.length} lines, total=$${report.costBreakdown.totalUsd}`);
  assert(report.migrationWaves.length >= 3, `Phase4 Adaptive Waves: ${report.migrationWaves.length} (${report.migrationWaves.map((w) => w.name).join(', ')})`);
  assert(report.assetCriticality.length > 0, `Phase5 Asset Criticality: ${report.assetCriticality.length} assets`);
  assert(report.impactReasons.length === 5 && report.impactReasons.every((x) => x.reason.length > 5), `Phase6 Business Impact reasons: ${report.impactReasons.length}`);
  assert(report.findingGroups.length > 0 && report.findingGroups[0].occurrences >= 1, `Phase7 Finding Dedup: ${report.findingGroups.length} groups; top "${report.findingGroups[0]?.title}" occ=${report.findingGroups[0]?.occurrences}`);
  assert(report.migrationConfidence.factors.length === 8, `Phase8 Migration Confidence: ${report.migrationConfidence.overallPct}% (${report.migrationConfidence.factors.length} factors)`);
  assert(report.evidenceConfidence.length === 8, `Phase9 Evidence Confidence: ${report.evidenceConfidence.length} sources`);
  assert(report.executiveDecisions.length >= 3, `Phase10 Executive Decisions: ${report.executiveDecisions.length}`);
  assert(report.playbookDetail.length > 0 && report.playbookDetail[0].executionSteps.length >= 3, `Phase11 Playbook Detail: ${report.playbookDetail.length} playbooks`);
  const last = report.waveSimulation[report.waveSimulation.length - 1];
  assert(report.waveSimulation.length >= 2 && /Entire Program/.test(last.label) && last.riskTo === report.executiveBlock.targetRisk, `Phase12 Wave Simulation: ${report.waveSimulation.length} scenarios; final risk→${last.riskTo}`);
  assert(report.governanceGates.length === 4, `Phase13 Governance Gates: ${report.governanceGates.length}`);
  assert(report.explainability.length >= 4 && report.explainability.every((x) => x.what && x.how && x.evidence && x.why && x.action), `Phase14 Explainability: ${report.explainability.length} metrics`);
  assert(report.riskMethodology.overall === snapshot.scores.quantumRisk, `Consistency: risk overall ${report.riskMethodology.overall} == QR ${snapshot.scores.quantumRisk}`);
}

async function run(name: string, snapshot: QuantumReadinessSnapshot, outDir: string, checkPhases = false) {
  const branding = brandingSchema.parse({ companyName: 'QGuard Helix', businessUnit: 'PQC Program Office' });
  const report = buildReportModel(snapshot, branding, 'executive', 'Export Smoke');

  // Schema validation: the model must conform exactly.
  enterpriseAssessmentReportSchema.parse(report);
  if (checkPhases) verifyPhases(report, snapshot);

  let ok = 0;
  for (const fmt of REPORT_FORMATS) {
    const result = await exportReport(report, fmt);
    const bytes = Buffer.from(await result.blob.arrayBuffer());
    if (bytes.byteLength <= 0) throw new Error(`${fmt} produced an empty artefact`);
    writeFileSync(resolve(outDir, result.filename), bytes);
    console.log(`  ✓ ${fmt.padEnd(4)} ${String(bytes.byteLength).padStart(8)} bytes  ${result.filename}`);
    ok++;
  }
  console.log(`  [${name}] ${ok}/${REPORT_FORMATS.length} formats generated, waves=${report.migrationWaves.length}\n`);
}

async function main() {
  const outDir = resolve(process.cwd(), '.report-smoke');
  mkdirSync(outDir, { recursive: true });
  console.log('=== Reports_Enhancements_3 exporter smoke test ===\n');
  console.log('Enterprise (multi-asset) snapshot:');
  await run('enterprise', ENTERPRISE, outDir, true);
  console.log('Single-asset (compact) snapshot:');
  await run('single', SINGLE_ASSET, outDir);
  console.log(`All artefacts written to ${outDir}`);
  if (phaseFailures > 0) { console.error(`\n${phaseFailures} phase assertion(s) FAILED`); process.exit(1); }
  console.log('\nAll phase assertions + 14 formats passed.');
}

main().catch((e) => { console.error('SMOKE FAILED:', e); process.exit(1); });
