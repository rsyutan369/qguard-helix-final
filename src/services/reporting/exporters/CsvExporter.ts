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
    asset: finding.affectedAssets.join('; '),
    current_state: finding.currentState,
    recommended_state: finding.recommendedState,
    business_impact: finding.businessImpact,
    technical_impact: finding.technicalImpact,
    migration_complexity: finding.migrationComplexity,
    dependencies: finding.dependencies.join('; '),
    owner: finding.owner,
    target_date: finding.targetDate,
    estimated_effort: finding.estimatedEffort,
    estimated_cost_usd: finding.estimatedCostUsd,
    risk_reduction_pct: finding.riskReductionPct,
    validation: finding.validation,
    source: finding.source,
    detected_at: finding.detectedAt || '',
  }));

  const csv = findingRows.length
    ? Papa.unparse(findingRows)
    : Papa.unparse([{ id: 'Evidence Not Available' }]);

  const header = `# ${report.meta.title} — ${report.branding.companyName}\n# Generated ${report.meta.generatedAt} | Version ${report.meta.version} | ${report.branding.classification}\n`;
  return new Blob([header, csv], { type: 'text/csv;charset=utf-8' });
}
