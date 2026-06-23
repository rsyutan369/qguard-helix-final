import Papa from 'papaparse';
import type { EnterpriseAssessmentReport } from '../schemas/ReportSchema';

/**
 * CSV export of raw findings + remediation evidence. Findings are the primary
 * machine-consumable artefact for SOC / GRC ingestion.
 */
export function exportCsv(report: EnterpriseAssessmentReport): Blob {
  const findingRows = report.findings.map((finding) => ({
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    source: finding.source,
    affected_assets: finding.affectedAssets.join('; '),
    evidence: finding.evidence,
    recommendation: finding.recommendation,
    remediation_plan: finding.remediationPlan,
    detected_at: finding.detectedAt || '',
  }));

  const csv = findingRows.length
    ? Papa.unparse(findingRows)
    : Papa.unparse([{ id: 'Evidence Not Available', title: '', severity: '', source: '', affected_assets: '', evidence: '', recommendation: '', remediation_plan: '', detected_at: '' }]);

  const header = `# ${report.meta.title} — ${report.branding.companyName}\n# Generated ${report.meta.generatedAt} | Version ${report.meta.version} | ${report.branding.classification}\n`;
  return new Blob([header, csv], { type: 'text/csv;charset=utf-8' });
}
