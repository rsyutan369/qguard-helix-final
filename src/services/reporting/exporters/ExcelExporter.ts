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

  // Findings sheet with severity colouring
  const findings = workbook.addWorksheet('Findings');
  const fHeader = findings.addRow(['ID', 'Title', 'Severity', 'Source', 'Affected Assets', 'Evidence', 'Recommendation', 'Remediation Plan']);
  styleHeader(fHeader);
  if (report.findings.length) {
    report.findings.forEach((finding) => {
      const row = findings.addRow([
        finding.id,
        finding.title,
        finding.severity.toUpperCase(),
        finding.source,
        finding.affectedAssets.join('; ') || 'Evidence Not Available',
        finding.evidence,
        finding.recommendation,
        finding.remediationPlan,
      ]);
      const sevCell = row.getCell(3);
      sevCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: SEV_FILL[finding.severity] || 'FF64748B' } };
      sevCell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    });
    findings.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: 8 } };
  } else {
    findings.addRow(['Evidence Not Available']);
  }
  [10, 30, 12, 18, 22, 40, 40, 40].forEach((width, index) => (findings.getColumn(index + 1).width = width));

  // Inventory & governance sheets
  addTableSheet(workbook, report.assets, 'Assets');
  addTableSheet(workbook, report.cbom, 'CBOM');
  addTableSheet(workbook, report.pqcReadiness.table, 'PQC Readiness');
  addTableSheet(workbook, report.remediation, 'Remediation');
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
