import Papa from 'papaparse';
import { CSV_FORMULA_PREFIX, csvCell } from '@/lib/csv';
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
    ? Papa.unparse(findingRows, { escapeFormulae: CSV_FORMULA_PREFIX })
    : Papa.unparse([{ id: 'Evidence Not Available' }]);

  const header = [
    `# ${report.meta.title} — ${report.branding.companyName}`,
    `# Generated ${report.meta.generatedAt} | Version ${report.meta.version} | ${report.branding.classification}`,
    '',
  ].map(csvCell).join('\n');

  // Shared Responsibility Assessment™ — ownership-classified matrix (aligned with
  // the Migration Intelligence Engine) appended as a second CSV block for GRC ingestion.
  const sr = report.sharedResponsibility;
  let srBlock = '';
  if (sr.hasData) {
    // One row per cryptographic exposure, owner and asset. `occurrences` carries
    // the raw scanner instance count and `detection_labels` the merged detection
    // channels, so a GRC pipeline ingesting this block can reconstruct the raw
    // evidence without re-importing duplicate rows.
    const ownershipRows = sr.matrix.map((m) => ({
      finding: m.finding,
      asset: m.asset,
      owner: m.owner,
      ownership_domain: m.domain,
      recommended_action: m.action,
      occurrences: m.occurrences,
      detection_labels: m.detectionLabels.join(' | '),
      priority: m.priority,
      status: m.status,
    }));
    srBlock =
      `\n\n# Shared Responsibility Assessment — Ownership Matrix (consolidated)\n` +
      `# Customer readiness ${sr.readiness.customer}/100 | Provider ${sr.readiness.provider}/100 | Ecosystem ${sr.readiness.ecosystem}/100 | Overall ${sr.readiness.overall}/100\n` +
      `# Customer-controlled ${sr.customerControlled} | Provider-controlled ${sr.providerControlled} | Ecosystem-dependent ${sr.ecosystemDependent} | Actionable now ${sr.actionableNow} | Blockers ${sr.migrationBlockers}\n` +
      `# ${sr.matrix.length} consolidated ownership row(s) representing ${sr.matrixInstances} raw scanner instance(s)\n` +
      (ownershipRows.length ? Papa.unparse(ownershipRows, { escapeFormulae: CSV_FORMULA_PREFIX }) : '');
  }

  return new Blob([header, csv, srBlock], { type: 'text/csv;charset=utf-8' });
}
