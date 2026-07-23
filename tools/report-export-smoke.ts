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
import { attachIntegrity } from '../src/services/reporting/ReportEngine';
import { buildReportScope, listSnapshotAssets, scopeSnapshotToAssets } from '../src/services/reporting/ReportScope';
import { exportReport } from '../src/services/reporting/ReportExporter';
import { reportVerificationUrl } from '../src/services/reporting/ReportQr';
import { brandingSchema, REPORT_FORMATS, enterpriseAssessmentReportSchema } from '../src/services/reporting/schemas/ReportSchema';

const ENTERPRISE: QuantumReadinessSnapshot = {
  generatedAt: new Date().toISOString(),
  lastAssessmentAt: new Date().toISOString(),
  assessmentProgress: 100,
  assessmentStatus: 'complete',
  hasData: true,
  // quantumReadiness mirrors the live scoring model exactly so the Readiness
  // Scoring Methodology reconciliation asserts hold:
  //   (12×0.45 + (100−58)×0.25 + 40×0.15 + 30×0.15) = 26.4 → 26
  scores: {
    quantumReadiness: 26, quantumReadinessLevel: 'Emerging',
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
    { label: 'Wk 4', readiness: 24, risk: 64 },
    { label: 'Wk 8', readiness: 26, risk: 58 },
  ],
  estimates: { migrationTimelineWeeks: 26, migrationCostUsd: 163020 },
  telemetry: {
    runtimeEvents: 4200, scanResults: 980, scanSessions: 12, securityEvents: 140,
    certificates: 18, keys: 31, assets: 24, connectors: 4, latestEventAt: new Date().toISOString(),
  },
};

// Single-asset compact scope → exercises Phase 4 adaptive 3-wave path AND the
// I2#1 unmeasured-runtime path (zero runtime telemetry → Runtime Visibility is
// "Not Measured", excluded from the readiness formula, weights renormalised:
//   (12×0.45 + 42×0.25 + 30×0.15) ÷ 0.85 = 24.0 → 24).
const SINGLE_ASSET: QuantumReadinessSnapshot = {
  ...ENTERPRISE,
  scores: { ...ENTERPRISE.scores, quantumReadiness: 24 },
  inventory: { ...ENTERPRISE.inventory, assetsAssessed: 1, cloudAccounts: 0, identitiesAnalyzed: 0, certificatesAnalyzed: 1, quantumVulnerableAssets: 1, vulnerableComponents: 4 },
  readinessFactors: ENTERPRISE.readinessFactors.map((f) => (/runtime/i.test(f.label) ? { ...f, score: 0 } : f)),
  criticalFindings: ENTERPRISE.criticalFindings.slice(0, 2),
  topRiskAssets: ENTERPRISE.topRiskAssets.slice(0, 1),
  exposureGraph: { nodes: ENTERPRISE.exposureGraph.nodes.slice(0, 1), edges: [] },
  estimates: { migrationTimelineWeeks: 5, migrationCostUsd: 16800 },
  telemetry: { ...ENTERPRISE.telemetry, runtimeEvents: 0 },
};

// XL estate — thousands of assets/components. Verifies the engine stays
// enterprise-grade at scale: bounded parallel-workstream calendar (never a
// multi-thousand-week single lane), exact wave/cost reconciliation, true
// tenant-wide asset counts with the capped detail tables disclosed.
// `estimates` mirror the backend parallel-workstream model exactly.
// Readiness reconciles: 8×.45 + (100−71)×.25 + 35×.15 + 60×.15 = 25.1 → 25.
const XL_REMAINING = 9800 + 3400; // vulnerable components + vulnerable assets
const XL_COMPLEXITY = 77;
const XL_EFFORT_WEEKS = XL_REMAINING * 0.6 * (1 + XL_COMPLEXITY / 200);
const XL_WORKSTREAMS = Math.min(64, Math.max(1, Math.ceil(XL_EFFORT_WEEKS / 104)));
const XL_WEEKS = Math.max(2, Math.round(XL_EFFORT_WEEKS / XL_WORKSTREAMS));
const XL_SCALE: QuantumReadinessSnapshot = {
  ...ENTERPRISE,
  scores: {
    quantumReadiness: 25, quantumReadinessLevel: 'Early Stage',
    quantumRisk: 71, quantumRiskLevel: 'High',
    hndlRisk: 66, hndlRiskLevel: 'High',
    cryptoExposure: 88, cryptoExposureLevel: 'Critical',
    migrationComplexity: XL_COMPLEXITY, migrationComplexityLevel: 'Critical',
    migrationEffort: 79, pqcAdoption: 8,
  },
  inventory: {
    assetsAssessed: 4800, certificatesAnalyzed: 2100, keysDiscovered: 3400, trustRelationships: 6200,
    domainsScanned: 900, identitiesAnalyzed: 1200, cloudAccounts: 12, dataRepositories: 260,
    pqcReadyAssets: 300, hybridAssets: 1100, quantumVulnerableAssets: 3400,
    cryptoComponents: 12000, vulnerableComponents: 9800, pqcReadyComponents: 950,
  },
  riskDistribution: { critical: 840, high: 2600, medium: 4100, low: 1660 },
  readinessFactors: [
    { label: 'TLS / Protocol Maturity', score: 9 },
    { label: 'PKI Readiness', score: 14 },
    { label: 'Crypto Agility', score: 11 },
    { label: 'Governance', score: 60 },
    { label: 'Runtime Telemetry Coverage', score: 35 },
  ],
  estimates: { migrationTimelineWeeks: XL_WEEKS, migrationCostUsd: XL_WEEKS * XL_WORKSTREAMS * 38 * 165, parallelWorkstreams: XL_WORKSTREAMS },
  telemetry: { ...ENTERPRISE.telemetry, runtimeEvents: 52000, scanResults: 4000, assets: 4800, certificates: 2100, keys: 3400 },
};

let phaseFailures = 0;
function assert(cond: boolean, msg: string) {
  console.log(`  ${cond ? '✓' : '✗'} ${msg}`);
  if (!cond) phaseFailures++;
}

function verifyPhases(report: ReturnType<typeof buildReportModel>, snapshot: QuantumReadinessSnapshot) {
  console.log('  --- Phase 1-14 model assertions ---');
  const contribSum = report.riskMethodology.weights.reduce((s, w) => s + w.contributionPct, 0);
  // Evidence-filtered: a fully-populated tenant yields up to 9 domains; sparse
  // tenants yield fewer (no fabricated 100%-risk domains). Contributions ≈ 100.
  assert(report.riskMethodology.weights.length >= 3 && report.riskMethodology.weights.length <= 9 && Math.abs(contribSum - 100) <= 2, `Phase1 Risk Methodology: ${report.riskMethodology.weights.length} domains, contributions≈100 (=${contribSum}); top=${report.riskMethodology.topDriver}`);
  // The displayed weighted table must reconstruct the overall score.
  const reconstructed = Math.round(report.riskMethodology.weights.reduce((s, w) => s + w.score * (w.weightPct / 100), 0));
  assert(Math.abs(reconstructed - report.riskMethodology.overall) <= 2, `Phase1 Reconciliation: Σ(score×weight)=${reconstructed} ≈ overall ${report.riskMethodology.overall}`);
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
  const lastWave = report.waveSimulation[report.waveSimulation.length - 2];
  // #2 The "Entire Program" row must be DISTINCT from the last wave row (adds
  // Validation/Optimization/Governance): readiness reaches target, residual risk
  // drops BELOW the migration target — not identical to "all waves complete".
  assert(
    report.waveSimulation.length >= 2 && /Entire Program/.test(last.label) && last.riskTo <= report.executiveBlock.targetRisk && last.readinessTo === report.executiveBlock.targetReadiness && !!lastWave && (last.readinessTo !== lastWave.readinessTo || last.riskTo !== lastWave.riskTo),
    `Phase12 Wave Simulation: ${report.waveSimulation.length} scenarios; program(readiness ${last.readinessTo}, risk ${last.riskTo}) ≠ waves(readiness ${lastWave?.readinessTo}, risk ${lastWave?.riskTo})`,
  );
  assert(report.governanceGates.length === 4, `Phase13 Governance Gates: ${report.governanceGates.length}`);
  assert(report.explainability.length >= 4 && report.explainability.every((x) => x.what && x.how && x.evidence && x.why && x.action), `Phase14 Explainability: ${report.explainability.length} metrics`);
  assert(report.riskMethodology.overall === snapshot.scores.quantumRisk, `Consistency: risk overall ${report.riskMethodology.overall} == QR ${snapshot.scores.quantumRisk}`);

  // --- Correction fixes (Reports_Generation_Corrections) ---
  // #1 Advisor recommends the DOMINANT weighted-risk domain (TLS here), not Identity.
  const topDomainKey = report.riskMethodology.weights[0]?.domain.replace(/\s*Risk$/i, '');
  assert(/tls/i.test(report.advisorValidation.primaryExposureDomain) && /tls|transport/i.test(report.migrationAdvisor.recommendation) && !/identity/i.test(report.migrationAdvisor.recommendation), `Fix#1 Advisor: primary=${report.advisorValidation.primaryExposureDomain}, rec="${report.migrationAdvisor.recommendation}" (top=${topDomainKey})`);
  // #3 A finding group cannot affect more assets than were assessed.
  assert(report.findingGroups.every((g) => g.affectedAssets <= snapshot.inventory.assetsAssessed), `Fix#3 Finding-group asset cap ≤ ${snapshot.inventory.assetsAssessed} assessed`);
  // #5 Every cost line: hours × rate == cost, and lines sum to the total.
  const costLineExact = report.costBreakdown.lines.every((l) => l.hours * l.rateUsd === l.costUsd);
  const costSumExact = report.costBreakdown.lines.reduce((s, l) => s + l.costUsd, 0) === report.costBreakdown.totalUsd && report.costForecast.lines.reduce((s, l) => s + l.costUsd, 0) === report.costForecast.totalUsd;
  assert(costLineExact && costSumExact, `Fix#5 Cost math: line hrs×rate==cost ${costLineExact}, Σlines==total ${costSumExact}`);
  // #6 Top risks are de-duplicated (no repeated finding title).
  const riskTitles = report.executiveBlock.topRisks.map((r) => r.replace(/^[A-Z]+:\s*/, '').replace(/\s*\(.*$/, '').trim().toLowerCase());
  assert(new Set(riskTitles).size === riskTitles.length, `Fix#6 Top risks de-duplicated: ${report.executiveBlock.topRisks.length} unique`);

  // --- Improvements_01 ---
  // I#1 Domain targets are dynamic numbers with a rationale, always above current.
  const domainsOk = report.readinessDomains.every((d) => d.targetScore > 0 && d.targetScore >= d.score && d.targetRationale.length > 20);
  assert(domainsOk, `I#1 Dynamic domain targets: e.g. ${report.readinessDomains[0]?.domain} ${report.readinessDomains[0]?.score}→${report.readinessDomains[0]?.targetScore}`);
  // I#3 Wave risk reductions sum EXACTLY to the executive/program reduction.
  const waveSum = report.migrationWaves.reduce((s, w) => s + w.riskReductionPct, 0);
  assert(waveSum === report.executiveBlock.expectedRiskReductionPct && waveSum === report.riskForecast.reductionPct, `I#3 Σ wave reductions ${waveSum}% == exec ${report.executiveBlock.expectedRiskReductionPct}% == forecast ${report.riskForecast.reductionPct}%`);
  // I#6 Risk methodology: Σ(contribution) reconstructs the overall exactly-ish.
  const contribTotal = Math.round(report.riskMethodology.weights.reduce((s, w) => s + w.contribution, 0));
  assert(report.riskMethodology.weights.every((w) => typeof w.contribution === 'number') && Math.abs(contribTotal - report.riskMethodology.overall) <= 2, `I#6 Σ contribution ${contribTotal} ≈ overall ${report.riskMethodology.overall}`);
  // I#5 Every business-impact reason cites evidence.
  assert(report.impactReasons.every((r) => r.evidence.length > 0), `I#5 Business impact evidence: all ${report.impactReasons.length} reasons cite evidence`);
  // I#7 Dependency chains are richer than "asset → Users".
  assert(report.dependencyAnalysis.chains.some((c) => c.path.split('->').length >= 4), `I#7 Dependency chain depth: ${report.dependencyAnalysis.chains[0]?.path}`);
  // I#8 Roadmap phases carry program-management fields (dates + gates).
  assert(report.roadmap.every((p) => !!p.startDate && !!p.endDate && !!p.gate) && report.roadmap.some((p) => p.criticalPath), `I#8 Program timeline: ${report.roadmap.length} phases with dates/gates/critical-path`);
  // I#9 Executive risk-acceptance register with valid decisions.
  const decisions = new Set(report.riskAcceptance.map((r) => r.decision));
  assert(report.riskAcceptance.length >= 3 && report.riskAcceptance.every((r) => ['Mitigate', 'Accept', 'Transfer', 'Defer'].includes(r.decision)), `I#9 Risk acceptance: ${report.riskAcceptance.length} entries, decisions=${[...decisions].join('/')}`);
  // I#10 Asset-level readiness with per-asset readiness + risk.
  assert(report.assetReadiness.length > 0 && report.assetReadiness.every((a) => typeof a.readiness === 'number' && typeof a.risk === 'number'), `I#10 Asset readiness: ${report.assetReadiness.length} assets (top ${report.assetReadiness[0]?.asset} ${report.assetReadiness[0]?.readiness}/${report.assetReadiness[0]?.risk})`);
  // Architectural — full decision-traceability chain.
  const stages = report.decisionChain.steps.map((s) => s.stage);
  assert(report.decisionChain.steps.length >= 8 && stages.includes('Evidence') && stages.includes('Executive Approval'), `Arch Decision chain: ${report.decisionChain.steps.length} stages`);
}

// Improvements_02 assertions — run for BOTH snapshots (enterprise = runtime
// measured; single-asset = runtime NOT measured / Not Measured path).
function verifyImprovements02(report: ReturnType<typeof buildReportModel>, snapshot: QuantumReadinessSnapshot) {
  console.log('  --- Improvements_02 assertions ---');
  const measured = snapshot.telemetry.runtimeEvents > 0;

  // I2#1 Runtime Visibility consistency: factor mirrors the telemetry evidence.
  const runtimeFactor = report.readinessMethodology.factors.find((f) => /runtime/i.test(f.factor));
  const factorRow = report.pqcReadiness.table.rows.find((r) => /runtime/i.test(String(r[0])));
  assert(!!runtimeFactor && runtimeFactor.measured === measured && (measured || runtimeFactor.score === 'Not Measured'), `I2#1 Runtime factor measured=${runtimeFactor?.measured} score=${runtimeFactor?.score} (telemetry events=${snapshot.telemetry.runtimeEvents})`);
  assert(!factorRow || measured || String(factorRow[1]) === 'Not Measured', `I2#1 Factors table runtime row shows "${factorRow?.[1]}"`);

  // I2#2 Terminology: definitions disambiguate assets vs components.
  assert(report.definitions.length >= 6 && report.definitions.some((d) => d.term === 'PQC-Ready Component') && report.definitions.some((d) => d.term === 'PQC-Ready Asset'), `I2#2 Definitions: ${report.definitions.length} terms incl. component vs asset`);

  // I2#3 Readiness contribution table reconstructs the overall score.
  const readinessSum = Math.round(report.readinessMethodology.factors.reduce((s, f) => s + f.contribution, 0));
  assert(Math.abs(readinessSum - report.readinessMethodology.overall) <= 1, `I2#3 Readiness methodology: Σ contributions ${readinessSum} ≈ overall ${report.readinessMethodology.overall} (±1)`);

  // I2#4 ROI: investment reconciles with the cost engine; every line has a basis.
  assert(report.roiAnalysis.investmentUsd === report.costForecast.totalUsd && report.roiAnalysis.roiMultiple > 0 && report.roiAnalysis.lines.length >= 6 && report.roiAnalysis.lines.every((l) => l.basis.length > 10), `I2#4 ROI: ${report.roiAnalysis.roiMultiple}× on $${report.roiAnalysis.investmentUsd.toLocaleString()} (${report.roiAnalysis.lines.length} lines)`);

  // I2#5 Resource loading: per-team hours + allocation with printed basis.
  assert(report.resourceLoading.length > 0 && report.resourceLoading.every((r) => r.hours > 0 && r.allocationPct > 0 && r.allocationPct <= 100 && r.basis.includes('hrs')), `I2#5 Resource loading: ${report.resourceLoading.length} team(s), e.g. ${report.resourceLoading[0]?.team} ${report.resourceLoading[0]?.allocationPct}%`);

  // I2#6 Asset intelligence: per-asset algorithms / key sizes / effort.
  const ai = report.assetIntelligence[0];
  assert(report.assetIntelligence.length > 0 && !!ai && ai.algorithms.length > 0 && ai.algorithms[0] !== 'Evidence Not Available' && ai.estimatedHours > 0 && ai.keySizes.length > 0, `I2#6 Asset intelligence: ${report.assetIntelligence.length} asset(s); ${ai?.asset}: ${ai?.algorithms.length} algo(s), ${ai?.estimatedHours}h`);

  // I2#7 Compliance gap tracking: Current/Target/Gap/Progress per framework.
  assert(report.compliance.every((c) => c.targetPct > 0 && c.gapPct === Math.max(0, c.targetPct - c.currentPct) && c.progressPct > 0), `I2#7 Compliance progress: e.g. ${report.compliance[0]?.framework} ${report.compliance[0]?.currentPct}%→${report.compliance[0]?.targetPct}% (${report.compliance[0]?.progressPct}% complete)`);

  // I2#8 Top Business Risks in the executive block.
  const tbr = report.executiveBlock.topBusinessRisks;
  assert(tbr.length >= 3 && tbr.some((r) => /internet-facing tls/i.test(r.risk)) && tbr.some((r) => /harvest/i.test(r.risk)) && tbr.every((r) => r.driver.length > 15), `I2#8 Top business risks: ${tbr.length} (${tbr.map((r) => r.risk).join(' | ')})`);

  // I2#9 Benchmarking: org + 3 modeled peers + target, clearly sourced.
  assert(report.benchmarking.rows.length === 5 && report.benchmarking.rows[0].readiness === snapshot.scores.quantumReadiness && /modeled/i.test(report.benchmarking.note), `I2#9 Benchmarking: ${report.benchmarking.rows.map((r) => `${r.cohort}=${r.readiness}`).join(', ')}`);

  // I2#10 Report validation badge: computed at build time and PASSING.
  // 7 checks since R7 added "Target Reconciliation Verified" (domain targets
  // blend back to the programme target risk).
  assert(report.reportValidation.checks.length === 7 && report.reportValidation.checks.some((c) => c.check === 'Target Reconciliation Verified') && report.reportValidation.overall === 'PASS', `I2#10 Report validation: ${report.reportValidation.overall} (${report.reportValidation.checks.filter((c) => c.status === 'pass').length}/${report.reportValidation.checks.length} checks)`);
  for (const c of report.reportValidation.checks.filter((x) => x.status === 'fail')) console.log(`      ✗ FAILING CHECK: ${c.check} — ${c.detail}`);

  // I2#11 Quantum Readiness Index: pillars reconcile; evidence-less pillars Not Measured.
  const pillarSum = Math.round(report.readinessIndex.pillars.reduce((s, p) => s + p.contribution, 0));
  const identityPillar = report.readinessIndex.pillars.find((p) => /identity/i.test(p.pillar));
  assert(report.readinessIndex.pillars.length === 8 && Math.abs(pillarSum - report.readinessIndex.overall) <= 1, `I2#11 Readiness index: 8 pillars, Σ contributions ${pillarSum} ≈ overall ${report.readinessIndex.overall}`);
  assert(!!identityPillar && (snapshot.inventory.identitiesAnalyzed > 0 ? identityPillar.measured : identityPillar.score === 'Not Measured'), `I2#11 Identity pillar: ${identityPillar?.score} (identities=${snapshot.inventory.identitiesAnalyzed})`);

  // I2#12 Policy-driven algorithms: no hard-coded Ed25519+ML-DSA target remains.
  const json = JSON.stringify(report);
  assert(report.cryptoPolicy.profiles.length === 3 && report.cryptoPolicy.activeProfile === 'Default Enterprise' && !json.includes('Ed25519 + ML-DSA-65'), `I2#12 Crypto policy: active=${report.cryptoPolicy.activeProfile}, hard-coded Ed25519 target removed`);
  const certPlaybook = report.playbookDetail.find((p) => /ecdsa|certificate/i.test(p.finding));
  assert(!certPlaybook || certPlaybook.targetState.includes('ML-DSA-65 + ECDSA P-256'), `I2#12 Cert playbook target: "${certPlaybook?.targetState}"`);
}

// Improvements_03 assertions — refinements.
function verifyImprovements03(report: ReturnType<typeof buildReportModel>, snapshot: QuantumReadinessSnapshot) {
  console.log('  --- Improvements_03 assertions ---');
  const measured = snapshot.telemetry.runtimeEvents > 0;

  // I3#1 Confidence taxonomy: four distinct measures, all present.
  const cs = report.confidenceSummary;
  assert(cs.assessmentConfidencePct === report.migrationConfidence.overallPct && cs.migrationPlanConfidencePct === report.migrationAdvisor.confidencePct && /–|Evidence/.test(cs.waveConfidenceRange) && cs.evidenceConfidencePct >= 0 && /Assessment Confidence/.test(cs.note), `I3#1 Confidence taxonomy: assess=${cs.assessmentConfidencePct}% plan=${cs.migrationPlanConfidencePct}% wave=${cs.waveConfidenceRange} evidence=${cs.evidenceConfidencePct}%`);

  // I3#2 ROI assumption is exposed + configurable, and appears as its own line.
  assert(report.roiAnalysis.assumptionsConfigurable && report.roiAnalysis.riskAvoidanceMultiple > 0 && /configurable|ALE|FAIR/i.test(report.roiAnalysis.assumptionBasis) && report.roiAnalysis.lines.some((l) => /assumption/i.test(l.metric)), `I3#2 ROI assumption: ${report.roiAnalysis.riskAvoidanceMultiple}× multiple, configurable=${report.roiAnalysis.assumptionsConfigurable}`);

  // I3#3 Owners are "Unknown" (never "Unassigned") when no accountable owner.
  const jsonStr = JSON.stringify(report);
  const unassignedOwner = report.assetReadiness.some((a) => /^unassigned$/i.test(a.owner)) || report.assetIntelligence.some((a) => /^unassigned$/i.test(a.businessOwner));
  assert(!unassignedOwner, `I3#3 Owners: no "Unassigned" owner values (converted to Unknown)`);
  // Richer owner/business fields present on asset intelligence.
  const ai0 = report.assetIntelligence[0];
  assert(!ai0 || (typeof ai0.businessOwner === 'string' && typeof ai0.businessUnit === 'string' && typeof ai0.businessCriticality === 'string'), `I3#3 Asset owner fields present`);

  // I3#4 Asset intelligence carries platform + primary algorithm + key length fields.
  assert(!ai0 || (typeof ai0.os === 'string' && typeof ai0.platform === 'string' && typeof ai0.hosting === 'string' && typeof ai0.cloudProvider === 'string' && typeof ai0.certExpiry === 'string' && typeof ai0.primaryAlgorithm === 'string' && typeof ai0.keyLength === 'string'), `I3#4 Asset intel richer fields: primary=${ai0?.primaryAlgorithm} key=${ai0?.keyLength} hosting=${ai0?.hosting}`);

  // I3#5 Resource loading has availability + dependencies.
  const rl0 = report.resourceLoading[0];
  assert(!rl0 || (rl0.availabilityPct > 0 && rl0.availabilityPct <= 100 && Array.isArray(rl0.dependencies) && rl0.basis.includes('avail')), `I3#5 Resource loading: ${rl0?.team} avail=${rl0?.availabilityPct}% deps=[${rl0?.dependencies.join(', ')}]`);

  // I3#7 Risk-forecast scenario bands: best/expected/worst present and ordered
  // (worst >= expected >= best at 12 months, since higher risk = worse).
  // R7: scenarios are schedule-anchored — "Funded Programme (Expected)",
  // "Funded Programme (Worst Case — 2× slippage)", "No Funded Programme (Baseline)".
  const sc = report.riskForecast.scenarios;
  const expected = sc.find((s) => /expected/i.test(s.scenario));
  const worst = sc.find((s) => /worst/i.test(s.scenario));
  const baseline = sc.find((s) => /no funded|baseline/i.test(s.scenario));
  // Programmes shorter than ~36 months must land at target/residual by month
  // 36; longer programmes (XL estates) are legitimately still gliding, so we
  // only require a monotonic decline that stays above the residual floor.
  const forecastWeeks = report.executiveBlock.estimatedDurationWeeks || 0;
  const forecastOverhead = Math.max(1, Math.round(forecastWeeks * 0.1));
  const programmeEndMonths = ((forecastWeeks + forecastOverhead * 2) * 12) / 52;
  assert(
    sc.length === 3 && !!expected && !!worst && !!baseline
      && worst.month12 >= expected.month12
      && baseline.month12 === report.riskForecast.currentRisk
      && expected.month36 <= expected.month12
      && expected.month36 >= report.riskForecast.residualRisk
      && (programmeEndMonths > 36 || expected.month36 <= report.riskForecast.targetRisk)
      && sc.every((s) => s.assumption.length > 15),
    `I3#7 Risk scenarios: expected m12=${expected?.month12}, worst m12=${worst?.month12}, baseline m12=${baseline?.month12} (programme ends ~month ${Math.ceil(programmeEndMonths)})`,
  );

  // I3#8 Operational (non-financial) benefits.
  assert(report.operationalBenefits.length >= 5 && report.operationalBenefits.every((b) => b.benefit && b.impact && b.evidence), `I3#8 Operational benefits: ${report.operationalBenefits.length}`);

  // I3#9 Executive maturity model: CMMI 0-5 per domain, current→target with gap.
  const mm = report.maturityModel;
  const runtimeDomain = mm.domains.find((d) => /runtime/i.test(d.domain));
  assert(mm.domains.length >= 6 && mm.domains.every((d) => d.currentLevel >= 0 && d.currentLevel <= 5 && d.targetLevel <= 5 && d.gap === Math.max(0, d.targetLevel - d.currentLevel) && !!d.owner && !!d.timeline), `I3#9 Maturity model: ${mm.domains.length} domains`);
  // Runtime maturity starts at Level 0 when telemetry is not measured.
  assert(!runtimeDomain || measured || runtimeDomain.currentLevel === 0, `I3#9 Runtime maturity level=${runtimeDomain?.currentLevel} (measured=${measured})`);

  // Technical observation — one-decimal percentage in definitions.
  const pqcCompDef = report.definitions.find((d) => d.term === 'PQC-Ready Component');
  assert(!!pqcCompDef && /\d+\.\d%/.test(pqcCompDef.definition), `Obs one-decimal %: "${pqcCompDef?.definition.match(/\([^)]*%\)/)?.[0]}"`);

  void jsonStr;
}

// Improvements_04 assertions — refinements.
function verifyImprovements04(report: ReturnType<typeof buildReportModel>, snapshot: QuantumReadinessSnapshot) {
  console.log('  --- Improvements_04 assertions ---');

  // I4#1 Confidence separation: forecast confidence = entire-programme simulation
  // confidence, and explainability carries BOTH labelled confidence metrics.
  const program = report.waveSimulation[report.waveSimulation.length - 1];
  assert(report.confidenceSummary.migrationForecastConfidencePct === (program?.confidencePct ?? 0), `I4#1 Forecast confidence ${report.confidenceSummary.migrationForecastConfidencePct}% == entire-programme sim ${program?.confidencePct}%`);
  const evidenceConf = report.explainability.find((x) => x.metric === 'Assessment Evidence Confidence');
  const forecastConf = report.explainability.find((x) => x.metric === 'Migration Forecast Confidence');
  assert(!!evidenceConf && !!forecastConf && !report.explainability.some((x) => x.metric === 'Migration Confidence'), `I4#1 Explainability separates evidence vs forecast confidence (no ambiguous "Migration Confidence" metric)`);

  // I4#2 Readiness progression ladder: baseline + one step per wave + target,
  // reconciling exactly with the simulation and executive block.
  const prog = report.readinessProgression;
  const first = prog[0];
  const lastStep = prog[prog.length - 1];
  assert(prog.length === report.waveSimulation.length + 1 && first?.stage === 'Current Readiness' && first.readiness === snapshot.scores.quantumReadiness, `I4#2 Progression: ${prog.length} steps starting at current readiness ${first?.readiness}`);
  assert(!!lastStep && /Target Readiness/.test(lastStep.stage) && lastStep.readiness === report.executiveBlock.targetReadiness && prog.slice(1, -1).every((st, i) => /Projected After Wave/.test(st.stage) && st.readiness === report.waveSimulation[i].readinessTo), `I4#2 Progression reconciles: …→ ${lastStep?.readiness} (target ${report.executiveBlock.targetReadiness})`);

  // I4#3/#7 Asset readiness enriched into an executive inventory.
  const ar0 = report.assetReadiness[0];
  assert(!!ar0 && [ar0.businessUnit, ar0.environment, ar0.criticality, ar0.platform, ar0.cloudProvider, ar0.tlsVersion, ar0.certExpiry, ar0.primaryAlgorithm, ar0.keySize, ar0.pqcStatus, ar0.hndlExposure].every((v) => typeof v === 'string' && v.length > 0), `I4#3/#7 Asset inventory fields: ${ar0?.asset} env=${ar0?.environment} crit=${ar0?.criticality} tls=${ar0?.tlsVersion} alg=${ar0?.primaryAlgorithm} pqc=${ar0?.pqcStatus} hndl=${ar0?.hndlExposure}`);

  // I4#4 Cost effort expressed as engineer-weeks + FTE, arithmetically exact.
  const cb = report.costBreakdown;
  const effortOk = cb.lines.every((l) => l.category === 'Evidence Not Available' || (Math.abs(l.engineerWeeks - l.hours / 40) < 0.06 && Math.abs(l.fte - l.hours / (cb.windowWeeks * 40)) < 0.006 && /FTE/.test(l.effort)));
  assert(effortOk && cb.windowWeeks > 0 && /engineer-weeks/.test(cb.effortNote), `I4#4 Effort expression: total ${cb.totalHours} hrs ≈ ${cb.totalEngineerWeeks} eng-wks ≈ ${cb.totalFte} FTE over ${cb.windowWeeks} wk`);

  // I4#5 Risk-owner approval block on every acceptance entry (never fabricated).
  assert(report.riskAcceptance.every((r) => r.approver.length > 0 && /pending/i.test(r.approvalStatus) && /signature/i.test(r.approvalMethod)), `I4#5 Risk approvals: ${report.riskAcceptance.length} entries pending sign-off (approvers: ${[...new Set(report.riskAcceptance.map((r) => r.approver))].join(', ')})`);

  // I4#6 Playbook operational fields.
  const pb0 = report.playbookDetail[0];
  assert(!!pb0 && [pb0.estimatedDowntime, pb0.maintenanceWindow, pb0.rollbackDuration, pb0.validationOwner, pb0.successKpi, pb0.automationStatus, pb0.slaImpact].every((v) => v && v !== 'Evidence Not Available'), `I4#6 Playbook ops: downtime="${pb0?.estimatedDowntime}" rollback="${pb0?.rollbackDuration}" sla="${pb0?.slaImpact}"`);

  // I4#8 Decimal consistency: count-derived shares print one decimal.
  const readinessBasis = report.readinessMethodology.factors.find((f) => /pqc adoption/i.test(f.factor))?.basis || '';
  assert(/\d+\.\d%/.test(readinessBasis), `I4#8 One-decimal component share in readiness basis: "${readinessBasis.match(/\([^)]*%\)/)?.[0] || readinessBasis.slice(0, 60)}"`);

  // I4#9 Executive Certification Summary — computed, criteria-driven.
  const cert = report.certification;
  const allMet = cert.criteria.every((c) => c.met);
  assert(cert.criteria.length === 6 && cert.certified === (snapshot.hasData && allMet) && /Certified|Not Yet Certified|No Assessment Evidence/.test(cert.certificationStatus), `I4#9 Certification: "${cert.certificationStatus}" (${cert.criteria.filter((c) => c.met).length}/${cert.criteria.length} criteria met)`);
  assert(cert.overallReadiness === snapshot.scores.quantumReadiness && cert.residualRisk === report.riskForecast.residualRisk && cert.assessmentConfidencePct === report.confidenceSummary.assessmentConfidencePct, `I4#9 Certification values copied from validated sections (readiness ${cert.overallReadiness}, residual ${cert.residualRisk})`);
  assert(cert.signedBy.length > 0 && /verify-report|QR/i.test(cert.verificationHint), `I4#9 Signature block: signed by "${cert.signedBy}" (${cert.signedRole}); verification hint present`);
}

// Improvements_05 assertions — refinements. `report` must be integrity-signed.
function verifyImprovements05(report: ReturnType<typeof buildReportModel>, snapshot: QuantumReadinessSnapshot) {
  console.log('  --- Improvements_05 assertions ---');

  // I5#1 Canonical asset count: definitions, executive summary and certification
  // all state the same discovered-asset figure (scope-derived).
  const discovered = report.scope.type === 'custom' ? report.scope.selectedAssetCount : (report.scope.totalAssetCount || snapshot.inventory.assetsAssessed);
  const assetDef = report.definitions.find((d) => d.term === 'Asset');
  assert(!!assetDef && assetDef.definition.includes(`${discovered} `) && /discovered asset/.test(assetDef.definition), `I5#1 Asset definition uses canonical discovered count (${discovered}): "${assetDef?.definition.match(/This (assessment|report's scope)[^.]*\./)?.[0]}"`);
  assert(report.executiveSummary.includes(`identified ${discovered} cryptographic asset`), `I5#1 Executive summary states ${discovered} discovered asset(s)`);
  assert(report.certification.scopeStatement.includes(`${report.scope.totalAssetCount || snapshot.inventory.assetsAssessed} discovered asset`) || report.certification.scopeStatement.includes(`${report.scope.selectedAssetCount} of ${report.scope.totalAssetCount}`), `I5#1 Certification scope consistent: "${report.certification.scopeStatement}"`);

  // I5#2 Evidence sources: only contributing sources listed; unavailable split out.
  const confBySource = new Map(report.evidenceConfidence.map((e) => [e.source, e.confidencePct]));
  const sourcesOk = report.evidence.sources.every((s) => (confBySource.get(s) || 0) > 0);
  const unavailableOk = report.evidence.unavailableSources.every((s) => (confBySource.get(s) || 0) === 0);
  assert(sourcesOk && unavailableOk && report.evidence.sources.length + report.evidence.unavailableSources.length === report.evidenceConfidence.length, `I5#2 Evidence split: ${report.evidence.sources.length} contributing / ${report.evidence.unavailableSources.length} unavailable [${report.evidence.unavailableSources.join(', ') || 'none'}]`);

  // I5#3 Verification URL never carries a development host (Node fallback = prod domain).
  const vurl = reportVerificationUrl(report);
  assert(!!vurl && vurl.startsWith('https://') && !/localhost|127\.0\.0\.1/.test(vurl), `I5#3 Verification URL production-safe: ${vurl?.split('?')[0]}`);

  // I5#4 Certification carries dated milestones = roadmap phases + eligibility review.
  const ms = report.certification.milestones;
  assert(ms.length === report.roadmap.length + 1 && /Certification Eligibility/.test(ms[ms.length - 1]?.milestone || '') && ms.slice(0, -1).every((x) => /\d{4}-\d{2}-\d{2}/.test(x.window)), `I5#4 Milestones: ${ms.length} (roadmap ${report.roadmap.length} + eligibility review); first window "${ms[0]?.window}"`);

  // I5#5 Executive Decision Package: budget/resources/risk dispositions/timeline/ROI/impact.
  const items = report.decisionPackage.map((d) => d.item).join('|');
  assert(report.decisionPackage.length >= 7 && /Budget/.test(items) && /Resource/.test(items) && /Accepted Risks/.test(items) && /Deferred Risks/.test(items) && /Timeline/.test(items) && /ROI/.test(items) && /Business Impact/.test(items), `I5#5 Decision package: ${report.decisionPackage.length} lines [${items}]`);

  // I5#6 Severity distribution carries one-decimal percentage context.
  assert(/Critical: \d+ \(\d+\.\d%\)/.test(report.evidence.notes), `I5#6 Severity percentages: "${report.evidence.notes.match(/Critical[^,]+,/)?.[0]}"`);
}

// Improvements_06 assertions — board-level visual intelligence.
function verifyImprovements06(report: ReturnType<typeof buildReportModel>, snapshot: QuantumReadinessSnapshot) {
  console.log('  --- Improvements_06 assertions ---');

  // §6 Board Snapshot: 60-second view copied from validated sections.
  const b = report.boardSnapshot;
  assert(b.hasData === snapshot.hasData && b.metrics.length === 6 && b.topDecisions.length <= 5, `I6#6 Board snapshot: ${b.metrics.length} metrics, ${b.topDecisions.length} decisions`);
  assert(b.recommendation === report.executiveBlock.executiveRecommendation && b.currentReadiness === report.executiveBlock.currentReadiness && b.targetRisk === report.executiveBlock.targetRisk, `I6#6 Board snapshot reconciles with executive block (readiness ${b.currentReadiness}→${b.targetReadiness}, risk→${b.targetRisk})`);
  assert(/discovered/.test(b.assetBasis) && /inventoried/.test(b.assetBasis) && /requiring migration/.test(b.assetBasis), `I6-minor#2 Asset-count basis explains discovered vs inventoried vs requiring migration: "${b.assetBasis.slice(0, 80)}…"`);

  // §2 Executive Heat Map: full 5×5 grid; every finding group plotted exactly once.
  const h = report.executiveHeatMap;
  const plotted = h.cells.reduce((sum, c) => sum + c.count, 0);
  assert(h.hasData === (report.findingGroups.length > 0), `I6#2 Heat map hasData=${h.hasData} (findingGroups=${report.findingGroups.length})`);
  assert(h.cells.length === 25 && h.impactLabels.length === 5 && h.likelihoodLabels.length === 5, `I6#2 Heat map is a full 5×5 grid (${h.cells.length} cells)`);
  assert(plotted === report.findingGroups.length && h.totalPlotted === report.findingGroups.length, `I6#2 Heat map plots every finding group once (Σcells=${plotted}, totalPlotted=${h.totalPlotted}, groups=${report.findingGroups.length})`);
  assert(h.cells.every((c) => ['critical', 'high', 'medium', 'low', 'minimal'].includes(c.level)), `I6#2 Heat map cells carry a risk zone`);

  // §3 Business Priority Matrix: 4 quadrants covering every remediation action.
  const pm = report.businessPriorityMatrix;
  const matrixItems = pm.quadrants.reduce((sum, q) => sum + q.items.length, 0);
  assert(pm.quadrants.length === 4 && ['quick-wins', 'strategic', 'fill-ins', 'long-term'].every((k) => pm.quadrants.some((q) => q.key === k)), `I6#3 Priority matrix: 4 quadrants (${pm.quadrants.map((q) => q.key).join(', ')})`);
  assert(matrixItems === report.remediationProgram.length, `I6#3 Priority matrix classifies every remediation action (${matrixItems} == ${report.remediationProgram.length})`);

  // §5 Evidence Quality Score: a letter grade per evidence source.
  const eq = report.evidenceQuality;
  assert(eq.rows.length === report.evidenceConfidence.length && eq.rows.every((r) => ['A', 'B', 'C', 'D', 'E', 'Missing'].includes(r.grade)), `I6#5 Evidence quality: ${eq.rows.length} graded source(s), overall ${eq.overallGrade}`);
  assert(eq.gradedSources + eq.missingSources === eq.rows.length && eq.rows.every((r) => (r.grade === 'Missing') === (r.status === 'Missing')), `I6#5 Evidence quality reconciles: ${eq.gradedSources} graded / ${eq.missingSources} missing`);

  // Minor §3 Remediation Campaigns: every finding group rolled into one campaign.
  const camp = report.remediationCampaigns;
  const campFindings = camp.campaigns.reduce((sum, c) => sum + c.findingCount, 0);
  assert(campFindings === report.findingGroups.length && camp.campaigns.every((c, i) => c.priority === `P${i + 1}`), `I6-minor#3 Remediation campaigns: ${camp.campaigns.length} campaign(s) cover all ${report.findingGroups.length} finding group(s)`);

  // §1/§4 + minor §1 Shared Responsibility (only when the snapshot carries it).
  if (report.sharedResponsibility.hasData) {
    const sr = report.sharedResponsibility;
    assert(sr.timeline.length === 3 && sr.timeline.every((t) => ['ready', 'in-progress', 'waiting', 'not-applicable'].includes(t.status)), `I6#4 SR timeline: ${sr.timeline.map((t) => `${t.domain}=${t.status}`).join(', ')}`);
    assert(sr.reconciliationNote.length > 20 && sr.classifiedFindings >= 0 && sr.rawScannerInstances >= 0, `I6-minor#1 SR reconciliation: ${sr.classifiedFindings} classified vs ${sr.rawScannerInstances} raw`);
    assert(b.responsibilitySplit.customer === sr.distribution.customer && b.responsibilitySplit.provider === sr.distribution.provider, `I6#1 Board responsibility split mirrors SR distribution`);
  } else {
    console.log('      (shared-responsibility source absent in this snapshot — SR timeline/reconciliation checks skipped)');
  }
}

// Asset-scoped reporting — select the top-2 risk assets of the enterprise
// snapshot, scope the snapshot, rebuild the model and assert the scoped report
// is filtered, recomputed and still internally consistent (validation = PASS).
async function runScoped(outDir: string) {
  console.log('  --- Asset-scope assertions ---');
  const branding = brandingSchema.parse({ companyName: 'QGuard Helix', businessUnit: 'PQC Program Office' });

  // Universe = exposure nodes (portal/api/auth/kms) ∪ top-risk assets (+legacy)
  // ∪ finding locations (no new ones) = 5 deduped assets, risk-sorted.
  const universe = listSnapshotAssets(ENTERPRISE);
  assert(universe.length === 5 && universe[0].key === 'portal.qguardhelix.com', `Scope universe: ${universe.length} deduped assets, top-risk first (${universe[0].key} @ ${universe[0].riskScore})`);

  // Full-scope / empty selections must pass the snapshot through untouched.
  assert(scopeSnapshotToAssets(ENTERPRISE, universe.map((a) => a.key)) === ENTERPRISE, 'Scope passthrough: selecting every asset returns the original snapshot');
  assert(scopeSnapshotToAssets(ENTERPRISE, []) === ENTERPRISE, 'Scope passthrough: empty selection returns the original snapshot');
  assert(buildReportScope(ENTERPRISE, null).type === 'full', 'Scope block: null selection = full scope');

  const scopeKeys = universe.slice(0, 2).map((a) => a.key); // portal + api
  const scoped = scopeSnapshotToAssets(ENTERPRISE, scopeKeys);
  const scope = buildReportScope(ENTERPRISE, scopeKeys);
  // totalAssetCount is the TRUE tenant inventory count (24), not the capped
  // 5-asset detail list — a large estate must never under-report its scope.
  assert(scope.type === 'custom' && scope.selectedAssetCount === 2 && scope.totalAssetCount === 24 && scope.assets.length === 2 && scope.methodology.length > 0, `Scope block: custom ${scope.selectedAssetCount}/${scope.totalAssetCount}, assets listed, methodology disclosed`);

  // Evidence filtered to the selection: portal carries FND-001/002, api FND-003.
  assert(scoped.criticalFindings.length === 3 && scoped.criticalFindings.every((f) => /^(portal|api)\./.test(f.asset)), `Scoped findings: ${scoped.criticalFindings.length} rows, all on selected assets`);
  assert(scoped.topRiskAssets.length === 2 && scoped.exposureGraph.nodes.length === 2 && scoped.exposureGraph.edges.length === 1, `Scoped graph: ${scoped.exposureGraph.nodes.length} nodes, ${scoped.exposureGraph.edges.length} edge (portal→api kept, api→auth/kms dropped)`);
  assert(scoped.inventory.assetsAssessed === 2 && scoped.inventory.quantumVulnerableAssets === 2 && scoped.inventory.pqcReadyAssets === 0, `Scoped inventory: 2 assessed, 2 vulnerable, 0 PQC-ready`);
  assert(scoped.riskDistribution.critical === 2 && scoped.riskDistribution.high === 1, `Scoped severity: critical=${scoped.riskDistribution.critical}, high=${scoped.riskDistribution.high} (asset-attributed)`);

  // Scores recomputed with the backend formulas for the scoped inputs:
  //   comps: vuln=3 (finding rows), pqc=0 (0 of 2 pqc assets selected), hybrid=round(85×2/24)=7 → total 10
  //   sp=((2×4+1×2.5+1×1+1×0.4)/5)×22=52.36; vs=30; is=100 (both assets internet-facing)
  //   risk = round(52.36×.45+30×.4+100×.15) = 51
  //   pqcAdoption=(0+7×0.5)/10×100=35; readiness = round(35×.45+49×.25+100×.15+60×.15) = 52
  assert(scoped.scores.quantumRisk === 51, `Scoped quantum risk recomputed: ${scoped.scores.quantumRisk} (was ${ENTERPRISE.scores.quantumRisk} tenant-wide)`);
  assert(scoped.scores.quantumReadiness === 52 && scoped.scores.pqcAdoption === 35, `Scoped readiness/adoption recomputed: readiness=${scoped.scores.quantumReadiness}, pqcAdoption=${scoped.scores.pqcAdoption}%`);
  assert(scoped.estimates.migrationCostUsd > 0 && scoped.estimates.migrationCostUsd < ENTERPRISE.estimates.migrationCostUsd, `Scoped cost rescaled: $${scoped.estimates.migrationCostUsd.toLocaleString()} < tenant $${ENTERPRISE.estimates.migrationCostUsd.toLocaleString()}`);

  // Build + validate the scoped report model end-to-end (signed, so the
  // certification page carries the integrity hash + verification QR).
  const report = attachIntegrity(buildReportModel(scoped, branding, 'executive', 'Export Smoke', scope));
  enterpriseAssessmentReportSchema.parse(report);
  assert(report.scope.type === 'custom' && report.scope.assets.length === 2, `Report carries scope: ${report.scope.selectedAssetCount} of ${report.scope.totalAssetCount} assets`);
  assert(/Report scope: 2 of 24/.test(report.executiveSummary), 'Executive summary states the custom scope (2 of 24 — true tenant count)');
  assert(report.reportValidation.overall === 'PASS', `Scoped report validation badge: ${report.reportValidation.overall}`);
  // I5#1 — the Asset definition mirrors the custom scope's canonical counts.
  const scopedAssetDef = report.definitions.find((d) => d.term === 'Asset');
  assert(!!scopedAssetDef && scopedAssetDef.definition.includes('2 of 24 discovered asset(s)'), `I5#1 scoped Asset definition: "${scopedAssetDef?.definition.match(/This report's scope[^.]*\./)?.[0]}"`);
  verifyImprovements05(report, scoped);
  verifyImprovements06(report, scoped);

  let ok = 0;
  for (const fmt of REPORT_FORMATS) {
    const result = await exportReport(report, fmt);
    const bytes = Buffer.from(await result.blob.arrayBuffer());
    if (bytes.byteLength <= 0) throw new Error(`scoped ${fmt} produced an empty artefact`);
    writeFileSync(resolve(outDir, `scoped-${result.filename}`), bytes);
    console.log(`  ✓ ${fmt.padEnd(4)} ${String(bytes.byteLength).padStart(8)} bytes  scoped-${result.filename}`);
    ok++;
  }
  console.log(`  [scoped] ${ok}/${REPORT_FORMATS.length} formats generated, waves=${report.migrationWaves.length}\n`);
}

async function run(name: string, snapshot: QuantumReadinessSnapshot, outDir: string, checkPhases = false) {
  const branding = brandingSchema.parse({ companyName: 'QGuard Helix', businessUnit: 'PQC Program Office' });
  // Signed like production (buildReport): the certification page carries the
  // integrity hash + verification QR in every export format.
  const report = attachIntegrity(buildReportModel(snapshot, branding, 'executive', 'Export Smoke'));

  // Schema validation: the model must conform exactly.
  enterpriseAssessmentReportSchema.parse(report);
  if (checkPhases) verifyPhases(report, snapshot);
  verifyImprovements02(report, snapshot);
  verifyImprovements03(report, snapshot);
  verifyImprovements04(report, snapshot);
  verifyImprovements05(report, snapshot);
  verifyImprovements06(report, snapshot);

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
  return report;
}

// Scale assertions — a thousands-of-assets estate must produce a bounded,
// reconciled, fully-disclosed enterprise programme.
function verifyScale(report: ReturnType<typeof buildReportModel>, snapshot: QuantumReadinessSnapshot) {
  console.log('  --- XL-scale assertions ---');
  assert(report.scope.totalAssetCount === snapshot.inventory.assetsAssessed && report.executiveSummary.includes(String(snapshot.inventory.assetsAssessed)), `Scale: full scope reports the true tenant asset count (${report.scope.totalAssetCount})`);
  assert(/top \d+ assets by risk/.test(report.scope.note), `Scale: scope note discloses capped detail tables: "${report.scope.note}"`);
  const weeks = snapshot.estimates.migrationTimelineWeeks;
  assert(weeks > 0 && weeks <= 200, `Scale: calendar bounded at ${weeks} week(s) via ${snapshot.estimates.parallelWorkstreams} parallel workstream(s) (single-lane would be ${Math.round(XL_EFFORT_WEEKS)}w)`);
  const waveCost = report.migrationWaves.reduce((sum, w) => sum + w.costUsd, 0);
  assert(waveCost === report.costForecast.totalUsd, `Scale: Σ wave costs $${waveCost.toLocaleString()} == cost-forecast budget $${report.costForecast.totalUsd.toLocaleString()}`);
  const waveWeeks = report.migrationWaves.reduce((sum, w) => sum + w.durationWeeks, 0);
  assert(waveWeeks === weeks, `Scale: Σ wave durations ${waveWeeks}w == programme ${weeks}w`);
  assert(report.reportValidation.overall === 'PASS', `Scale: report validation ${report.reportValidation.overall} (${report.reportValidation.checks.filter((c) => c.status === 'pass').length}/${report.reportValidation.checks.length}) on the XL estate`);
  for (const c of report.reportValidation.checks.filter((x) => x.status === 'fail')) console.log(`      ✗ FAILING CHECK: ${c.check} — ${c.detail}`);
}

async function main() {
  const outDir = resolve(process.cwd(), '.report-smoke');
  mkdirSync(outDir, { recursive: true });
  console.log('=== Reports_Enhancements_3 exporter smoke test ===\n');
  console.log('Enterprise (multi-asset) snapshot:');
  await run('enterprise', ENTERPRISE, outDir, true);
  console.log('Single-asset (compact) snapshot:');
  await run('single', SINGLE_ASSET, outDir);
  console.log('XL-scale estate (thousands of assets) snapshot:');
  const xlReport = await run('xl-scale', XL_SCALE, outDir);
  verifyScale(xlReport, XL_SCALE);
  console.log('Asset-scoped (custom selection) report:');
  await runScoped(outDir);
  console.log(`All artefacts written to ${outDir}`);
  if (phaseFailures > 0) { console.error(`\n${phaseFailures} phase assertion(s) FAILED`); process.exit(1); }
  console.log('\nAll phase assertions + 14 formats passed.');
}

main().catch((e) => { console.error('SMOKE FAILED:', e); process.exit(1); });
