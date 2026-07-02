import ExcelJS from 'exceljs';
import type { EnterpriseAssessmentReport, ReportTable } from '../schemas/ReportSchema';

const SEV_FILL: Record<string, string> = {
  critical: 'FFDC2626',
  high: 'FFEA580C',
  medium: 'FFD97706',
  low: 'FF16A34A',
  info: 'FF2563FF',
};

function styleHeader(row: ExcelJS.Row) {
  row.eachCell((cell) => {
    cell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0F172A' } };
    cell.alignment = { vertical: 'middle' };
  });
}

function addTableSheet(workbook: ExcelJS.Workbook, table: ReportTable, sheetName: string) {
  const sheet = workbook.addWorksheet(sheetName.slice(0, 31));
  const header = sheet.addRow(table.columns);
  styleHeader(header);
  table.rows.forEach((row) => sheet.addRow(row));
  sheet.columns.forEach((column) => {
    let max = 12;
    column.eachCell?.({ includeEmpty: true }, (cell) => {
      max = Math.max(max, String(cell.value ?? '').length + 2);
    });
    column.width = Math.min(60, max);
  });
  if (table.rows.length) sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: table.columns.length } };
  return sheet;
}

/**
 * Multi-sheet XLSX export: Summary, Findings (severity conditional formatting +
 * filters), Assets, CBOM, Compliance, Roadmap, Remediation. Inventory-grade
 * artefact for security teams and auditors.
 */
export async function exportExcel(report: EnterpriseAssessmentReport): Promise<Blob> {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = report.branding.companyName;
  workbook.created = new Date(report.meta.generatedAt);

  // Summary sheet
  const summary = workbook.addWorksheet('Summary');
  summary.addRow([report.meta.title]).font = { bold: true, size: 16 };
  summary.addRow([`${report.branding.companyName}${report.branding.businessUnit ? ` — ${report.branding.businessUnit}` : ''}`]);
  summary.addRow([`Classification: ${report.branding.classification} | Version: ${report.meta.version} | Generated: ${new Date(report.meta.generatedAt).toLocaleString()}`]);
  summary.addRow([]);
  const kpiHeader = summary.addRow(['KPI', 'Value', 'Level']);
  styleHeader(kpiHeader);
  report.kpis.forEach((kpi) => summary.addRow([kpi.label, `${kpi.value}${kpi.unit || ''}`, kpi.level || '']));
  summary.addRow([]);
  summary.addRow(['Executive Summary']).font = { bold: true };
  const summaryCell = summary.addRow([report.executiveSummary]).getCell(1);
  summaryCell.alignment = { wrapText: true };
  summary.getColumn(1).width = 40;
  summary.getColumn(2).width = 20;
  summary.getColumn(3).width = 24;

  const usd = (n: number) => (n ? `$${Math.round(n).toLocaleString()}` : 'Evidence Not Available');

  // Actionable findings sheet with severity colouring
  const findings = workbook.addWorksheet('Findings');
  const fHeader = findings.addRow(['ID', 'Severity', 'Title', 'Asset', 'Current State', 'Recommended State', 'Business Impact', 'Complexity', 'Owner', 'Target Date', 'Effort', 'Cost', 'Risk Reduction', 'Dependencies']);
  styleHeader(fHeader);
  if (report.findings.length) {
    report.findings.forEach((f) => {
      const row = findings.addRow([
        f.id, f.severity.toUpperCase(), f.title, f.affectedAssets.join('; ') || 'Evidence Not Available', f.currentState, f.recommendedState,
        f.businessImpact, f.migrationComplexity, f.owner, f.targetDate, f.estimatedEffort, usd(f.estimatedCostUsd), `${f.riskReductionPct}%`, f.dependencies.join('; '),
      ]);
      const sevCell = row.getCell(2);
      sevCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: SEV_FILL[f.severity] || 'FF64748B' } };
      sevCell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    });
    findings.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: 14 } };
  } else {
    findings.addRow(['Evidence Not Available']);
  }
  [10, 10, 28, 18, 22, 26, 28, 11, 18, 12, 12, 12, 12, 26].forEach((width, index) => (findings.getColumn(index + 1).width = width));

  // Program sheets
  addTableSheet(workbook, { title: 'Executive', columns: ['Metric', 'Current', 'Target'], rows: [
    ['Quantum Readiness', report.executiveBlock.currentReadiness, report.executiveBlock.targetReadiness],
    ['Quantum Risk', report.executiveBlock.currentRisk, report.executiveBlock.targetRisk],
    ['HNDL Exposure', report.executiveBlock.currentHndl, report.executiveBlock.targetHndl],
    ['Timeline (weeks)', '-', report.executiveBlock.estimatedDurationWeeks],
    ['Budget', '-', usd(report.executiveBlock.estimatedCostUsd)],
    ['Expected Risk Reduction', '-', `${report.executiveBlock.expectedRiskReductionPct}%`],
  ] }, 'Executive Summary');
  addTableSheet(workbook, { title: 'Business Impact', columns: ['Dimension', 'Value'], rows: [
    ['Customer-Facing Systems', report.businessImpact.customerFacingSystems], ['Mission-Critical Systems', report.businessImpact.missionCriticalSystems],
    ['Third-Party Dependencies', report.businessImpact.thirdPartyDependencies], ['Revenue Impact', report.businessImpact.revenueImpact],
    ['Compliance Impact', report.businessImpact.complianceImpact], ['Financial Impact', report.businessImpact.financialImpact],
    ['HNDL Exposure', report.businessImpact.hndlExposure], ['Quantum Exposure Window', report.businessImpact.quantumExposureWindow],
  ] }, 'Business Impact');
  addTableSheet(workbook, { title: 'Readiness Domains', columns: ['Domain', 'Current', 'Target', 'Risk Level', 'Owner', 'Target Rationale'], rows: report.readinessDomains.map((d) => [d.domain, d.score, d.targetScore, d.riskLevel, d.owner, d.targetRationale]) }, 'Readiness Domains');
  addTableSheet(workbook, { title: 'Migration Waves', columns: ['Wave', 'Focus', 'Priority', 'Owner', 'Duration (wks)', 'Cost', 'Risk Reduction', 'Status', 'Assets'], rows: report.migrationWaves.map((w) => [w.wave, w.name, w.priority, w.owner, w.durationWeeks, usd(w.costUsd), `${w.riskReductionPct}%`, w.status, w.assets.join('; ')]) }, 'Migration Waves');
  addTableSheet(workbook, { title: 'Risk Categories', columns: ['Category', 'Current', 'Target', 'Reduction Potential'], rows: report.riskCategories.map((r) => [r.category, r.currentScore, r.targetScore, `${r.reductionPotentialPct}%`]) }, 'Risk Analysis');
  addTableSheet(workbook, { title: 'Remediation Program', columns: ['Priority', 'Action', 'Owner', 'Affected Assets', 'Cost', 'Effort', 'Risk Reduction', 'Target Date', 'Status'], rows: report.remediationProgram.map((r) => [r.priority, r.action, r.owner, r.affectedAssets.join('; '), usd(r.costUsd), r.effort, `${r.riskReductionPct}%`, r.targetDate, r.status]) }, 'Remediation Program');
  addTableSheet(workbook, { title: 'Cost Forecast', columns: ['Category', 'Estimated Cost'], rows: [...report.costForecast.lines.map((l) => [l.category, usd(l.costUsd)]), ['TOTAL', usd(report.costForecast.totalUsd)], ['Projected Risk-Reduction Value', usd(report.costForecast.projectedRiskReductionValueUsd)]] }, 'Cost Forecast');
  addTableSheet(workbook, { title: 'Governance', columns: ['Role', 'Owner', 'Responsibility'], rows: report.governance.map((g) => [g.role, g.owner, g.responsibility]) }, 'Governance');

  // Report Intelligence (Reports_Enhancements_3) sheets
  addTableSheet(workbook, { title: 'Risk Methodology', columns: ['Risk Domain', 'Domain Risk', 'Weight %', 'Contribution (Risk×Weight)', 'Share %'], rows: [...report.riskMethodology.weights.map((w) => [w.domain, w.score, w.weightPct, w.contribution, w.contributionPct]), ['OVERALL (Σ Contribution)', report.riskMethodology.overall, 100, report.riskMethodology.overall, 100]] }, 'Risk Methodology');
  addTableSheet(workbook, { title: 'Cost Breakdown', columns: ['Category', 'Hours', 'Engineers', 'Rate', 'Cost', 'Formula'], rows: [...report.costBreakdown.lines.map((l) => [l.category, l.hours, l.engineers, usd(l.rateUsd), usd(l.costUsd), l.formula]), ['TOTAL', report.costBreakdown.totalHours, '', '', usd(report.costForecast.totalUsd), '']] }, 'Cost Breakdown');
  addTableSheet(workbook, { title: 'Consolidated Findings', columns: ['Finding', 'Occurrences', 'Affected Assets', 'Impact', 'Evidence'], rows: report.findingGroups.map((g) => [g.title, g.occurrences, g.affectedAssets, g.impact.toUpperCase(), g.evidence.join('; ')]) }, 'Finding Groups');
  addTableSheet(workbook, { title: 'Asset Criticality', columns: ['Asset', 'Business', 'Operational', 'Customer-Facing', 'Internet-Facing', 'Revenue', 'Compliance', 'Data Sensitivity'], rows: report.assetCriticality.map((a) => [a.asset, a.businessCriticality, a.operationalCriticality, a.customerFacing ? 'Yes' : 'No', a.internetFacing ? 'Yes' : 'No', a.revenueImpact, a.complianceScope.join('; '), a.dataSensitivity]) }, 'Asset Criticality');
  addTableSheet(workbook, { title: 'Migration Confidence', columns: ['Confidence Factor', 'Coverage %'], rows: [['OVERALL', report.migrationConfidence.overallPct], ...report.migrationConfidence.factors.map((f) => [f.label, f.coveragePct])] }, 'Migration Confidence');
  addTableSheet(workbook, { title: 'Evidence Confidence', columns: ['Source', 'Coverage %', 'Completeness %', 'Freshness', 'Confidence %', 'Note'], rows: report.evidenceConfidence.map((e) => [e.source, e.coveragePct, e.completenessPct, e.freshness, e.confidencePct, e.note]) }, 'Evidence Confidence');
  addTableSheet(workbook, { title: 'Executive Decisions', columns: ['Decision Required', 'Type', 'Rationale', 'Owner'], rows: report.executiveDecisions.map((d) => [d.decision, d.type, d.rationale, d.owner]) }, 'Executive Decisions');
  addTableSheet(workbook, { title: 'Migration Simulation', columns: ['Scenario', 'Readiness From', 'Readiness To', 'Risk From', 'Risk To', 'Cost', 'Timeline (wks)', 'Confidence %'], rows: report.waveSimulation.map((w) => [w.label, w.readinessFrom, w.readinessTo, w.riskFrom, w.riskTo, usd(w.costUsd), w.timelineWeeks, w.confidencePct]) }, 'Migration Simulation');
  addTableSheet(workbook, { title: 'Advisor Validation', columns: ['Attribute', 'Value'], rows: [
    ['Primary Exposure Domain', report.advisorValidation.primaryExposureDomain],
    ['Expected Risk Reduction', `${report.advisorValidation.expectedRiskReductionPct}%`],
    ['Confidence', `${report.advisorValidation.confidencePct}%`],
    ['Why This Recommendation', report.advisorValidation.why],
    ['Top Contributing Findings', report.advisorValidation.topContributingFindings.join('; ') || 'Evidence Not Available'],
    ['Top Contributing Assets', report.advisorValidation.topContributingAssets.join('; ') || 'Evidence Not Available'],
  ] }, 'Advisor Validation');
  addTableSheet(workbook, { title: 'Business Impact Intelligence', columns: ['Dimension', 'Level', 'Reason', 'Evidence'], rows: report.impactReasons.map((r) => [r.dimension, r.level, r.reason, r.evidence.join('; ')]) }, 'Impact Intelligence');
  addTableSheet(workbook, { title: 'Asset-Level Readiness', columns: ['Asset', 'Readiness', 'Risk', 'Posture', 'Internet-Facing', 'Primary Driver', 'Owner'], rows: report.assetReadiness.map((a) => [a.asset, a.readiness, a.risk, a.posture, a.internetFacing ? 'Yes' : 'No', a.primaryDriver, a.owner]) }, 'Asset Readiness');
  addTableSheet(workbook, { title: 'Executive Risk Acceptance', columns: ['Risk', 'Decision', 'Owner', 'Rationale', 'Residual Risk', 'Review Date'], rows: report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.residualRisk, r.reviewDate]) }, 'Risk Acceptance');
  addTableSheet(workbook, { title: 'Decision Traceability', columns: ['Stage', 'Detail'], rows: report.decisionChain.steps.map((s) => [s.stage, s.detail]) }, 'Decision Chain');
  addTableSheet(workbook, { title: 'Remediation Playbook', columns: ['Finding', 'Current State', 'Target State', 'Prerequisites', 'Dependencies', 'Execution Steps', 'Validation Steps', 'Rollback Steps', 'Success Criteria'], rows: report.playbookDetail.map((p) => [
    p.finding, p.currentState, p.targetState, p.prerequisites.join('; '), p.dependencies.join('; '),
    p.executionSteps.map((s, i) => `${i + 1}. ${s}`).join('  '), p.validationSteps.join('; '), p.rollbackSteps.join('; '), p.successCriteria.join('; '),
  ]) }, 'Remediation Playbook');
  addTableSheet(workbook, { title: 'Governance Gates', columns: ['Approval Gate', 'Owner', 'Criteria'], rows: report.governanceGates.map((g) => [g.gate, g.owner, g.criteria]) }, 'Governance Gates');
  addTableSheet(workbook, { title: 'Report Explainability', columns: ['Metric', 'What', 'How', 'Evidence', 'Why It Matters', 'Action'], rows: report.explainability.map((e) => [e.metric, e.what, e.how, e.evidence, e.why, e.action]) }, 'Explainability');

  // Improvements_02 sheets
  addTableSheet(workbook, { title: 'Top Business Risks', columns: ['#', 'Business Risk', 'Level', 'Evidence Driver'], rows: report.executiveBlock.topBusinessRisks.map((r, i) => [i + 1, r.risk, r.level, r.driver]) }, 'Business Risks');
  addTableSheet(workbook, { title: 'Readiness Methodology', columns: ['Factor', 'Weight %', 'Score', 'Contribution', 'Measured', 'Basis'], rows: [...report.readinessMethodology.factors.map((f) => [f.factor, f.measured ? f.weightPct : 'Excluded', f.score, f.measured ? f.contribution : '-', f.measured ? 'Yes' : 'No', f.basis]), ['OVERALL (Σ Contribution)', 100, report.readinessMethodology.overall, report.readinessMethodology.overall, '', '±1 rounding']] }, 'Readiness Methodology');
  addTableSheet(workbook, { title: 'Quantum Readiness Index', columns: ['Strategic Pillar', 'Score', 'Weight %', 'Contribution', 'Measured', 'Primary Driver'], rows: report.readinessIndex.pillars.map((p) => [p.pillar, p.score, p.measured ? p.weightPct : '-', p.measured ? p.contribution : '-', p.measured ? 'Yes' : 'No', p.driver]) }, 'Readiness Index');
  addTableSheet(workbook, { title: 'Executive ROI', columns: ['Value Metric', 'Expected Outcome', 'Basis / Formula'], rows: report.roiAnalysis.lines.map((l) => [l.metric, l.value, l.basis]) }, 'ROI');
  addTableSheet(workbook, { title: 'Industry Benchmarking', columns: ['Cohort', 'Readiness', 'Delta vs You', 'Source'], rows: report.benchmarking.rows.map((b) => [b.cohort, b.readiness, b.delta, b.source]) }, 'Benchmarking');
  addTableSheet(workbook, { title: 'Resource Loading', columns: ['Team', 'Waves', 'Hours', 'Engineers', 'Window (wks)', 'Allocation %', 'Basis'], rows: report.resourceLoading.map((r) => [r.team, r.waves, r.hours, r.engineers, r.windowWeeks, r.allocationPct, r.basis]) }, 'Resource Loading');
  addTableSheet(workbook, { title: 'Asset Intelligence', columns: ['Asset', 'Type', 'Environment', 'Owner Dept.', 'Certificates', 'TLS Version', 'Algorithms', 'Key Sizes', 'Crypto Libraries', 'Dependencies', 'PQC Ready %', 'Complexity', 'Est. Hours'], rows: report.assetIntelligence.map((a) => [a.asset, a.assetType, a.environment, a.ownerDepartment, a.certificates, a.tlsVersion, a.algorithms.join('; '), a.keySizes.join('; '), a.cryptoLibraries, a.dependencies.join('; '), a.pqcReadinessPct, a.migrationComplexity, a.estimatedHours]) }, 'Asset Intelligence');
  addTableSheet(workbook, { title: 'Crypto-Policy Profiles', columns: ['Profile', 'Active', 'Key Establishment', 'Digital Signature', 'Certificate Chain', 'Symmetric', 'Hash', 'Guidance'], rows: report.cryptoPolicy.profiles.map((p) => [p.profile, p.profile === report.cryptoPolicy.activeProfile ? 'ACTIVE' : '', p.keyEstablishment, p.digitalSignature, p.certificateChain, p.symmetric, p.hash, p.guidance]) }, 'Crypto Policy');
  addTableSheet(workbook, { title: 'Terminology & Definitions', columns: ['Term', 'Definition'], rows: report.definitions.map((d) => [d.term, d.definition]) }, 'Definitions');
  addTableSheet(workbook, { title: `Report Validation — ${report.reportValidation.overall}`, columns: ['Validation Check', 'Result', 'Detail'], rows: [...report.reportValidation.checks.map((c) => [c.check, c.status.toUpperCase(), c.detail]), ['OVERALL', report.reportValidation.overall, report.reportValidation.note]] }, 'Report Validation');

  // Inventory sheets
  addTableSheet(workbook, report.assets, 'Assets');
  addTableSheet(workbook, report.cbom, 'CBOM');
  addTableSheet(workbook, report.pqcReadiness.table, 'PQC Readiness');
  const compliance = workbook.addWorksheet('Compliance');
  styleHeader(compliance.addRow(['Framework', 'Control', 'Status', 'Current %', 'Target %', 'Gap (pts)', 'Progress %', 'Detail']));
  report.compliance.forEach((row) => compliance.addRow([row.framework, row.control, row.status, row.currentPct, row.targetPct, row.gapPct, row.progressPct, row.detail]));
  compliance.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: 8 } };
  [16, 36, 14, 10, 10, 10, 11, 50].forEach((width, index) => (compliance.getColumn(index + 1).width = width));
  const roadmap = workbook.addWorksheet('Roadmap');
  styleHeader(roadmap.addRow(['Phase', 'Start', 'Finish', 'Effort (weeks)', 'Milestone', 'Approval Gate', 'Critical Path', 'Slack (weeks)']));
  report.roadmap.forEach((phase) => roadmap.addRow([phase.phase, phase.startDate, phase.endDate, phase.effortWeeks, phase.milestone, phase.gate, phase.criticalPath ? 'Yes' : 'No', phase.slackWeeks]));
  [22, 12, 12, 14, 30, 24, 12, 12].forEach((width, index) => (roadmap.getColumn(index + 1).width = width));

  const buffer = await workbook.xlsx.writeBuffer();
  return new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
}
