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
  addTableSheet(workbook, { title: 'Readiness Domains', columns: ['Domain', 'Score', 'Risk Level', 'Owner', 'Recommended Action'], rows: report.readinessDomains.map((d) => [d.domain, d.score, d.riskLevel, d.owner, d.actions]) }, 'Readiness Domains');
  addTableSheet(workbook, { title: 'Migration Waves', columns: ['Wave', 'Focus', 'Priority', 'Owner', 'Duration (wks)', 'Cost', 'Risk Reduction', 'Status', 'Assets'], rows: report.migrationWaves.map((w) => [w.wave, w.name, w.priority, w.owner, w.durationWeeks, usd(w.costUsd), `${w.riskReductionPct}%`, w.status, w.assets.join('; ')]) }, 'Migration Waves');
  addTableSheet(workbook, { title: 'Risk Categories', columns: ['Category', 'Current', 'Target', 'Reduction Potential'], rows: report.riskCategories.map((r) => [r.category, r.currentScore, r.targetScore, `${r.reductionPotentialPct}%`]) }, 'Risk Analysis');
  addTableSheet(workbook, { title: 'Remediation Program', columns: ['Priority', 'Action', 'Owner', 'Affected Assets', 'Cost', 'Effort', 'Risk Reduction', 'Target Date', 'Status'], rows: report.remediationProgram.map((r) => [r.priority, r.action, r.owner, r.affectedAssets.join('; '), usd(r.costUsd), r.effort, `${r.riskReductionPct}%`, r.targetDate, r.status]) }, 'Remediation Program');
  addTableSheet(workbook, { title: 'Cost Forecast', columns: ['Category', 'Estimated Cost'], rows: [...report.costForecast.lines.map((l) => [l.category, usd(l.costUsd)]), ['TOTAL', usd(report.costForecast.totalUsd)], ['Projected Risk-Reduction Value', usd(report.costForecast.projectedRiskReductionValueUsd)]] }, 'Cost Forecast');
  addTableSheet(workbook, { title: 'Governance', columns: ['Role', 'Owner', 'Responsibility'], rows: report.governance.map((g) => [g.role, g.owner, g.responsibility]) }, 'Governance');

  // Inventory sheets
  addTableSheet(workbook, report.assets, 'Assets');
  addTableSheet(workbook, report.cbom, 'CBOM');
  addTableSheet(workbook, report.pqcReadiness.table, 'PQC Readiness');
  const compliance = workbook.addWorksheet('Compliance');
  styleHeader(compliance.addRow(['Framework', 'Control', 'Status', 'Detail']));
  report.compliance.forEach((row) => compliance.addRow([row.framework, row.control, row.status, row.detail]));
  compliance.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: 4 } };
  [16, 36, 14, 50].forEach((width, index) => (compliance.getColumn(index + 1).width = width));
  const roadmap = workbook.addWorksheet('Roadmap');
  styleHeader(roadmap.addRow(['Phase', 'Description', 'Status', 'Effort (weeks)']));
  report.roadmap.forEach((phase) => roadmap.addRow([phase.phase, phase.description, phase.status, phase.effortWeeks]));
  [18, 50, 14, 16].forEach((width, index) => (roadmap.getColumn(index + 1).width = width));

  const buffer = await workbook.xlsx.writeBuffer();
  return new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
}
