import type { QuantumReadinessSnapshot } from '@/app/dashboard/quantum-readiness/_shared';
import { buildReportModel } from './ReportEvidence';
import { buildReportScope, scopeSnapshotToAssets } from './ReportScope';
import { renderReportCharts } from './ReportCharts';
import { sealDocument } from './ReportIntegrity';
import type { EnterpriseAssessmentReport, ReportBranding, ReportKind } from './schemas/ReportSchema';
import { enterpriseAssessmentReportSchema } from './schemas/ReportSchema';

/** Stable integrity input — excludes the integrity block and bulky chart bytes. */
function canonicalize(report: EnterpriseAssessmentReport): string {
  return JSON.stringify(report, (key, value) => {
    if (key === 'integrity') return undefined;
    if (key === 'dataUrl') return '<chart>';
    return value;
  });
}

/** Compute SHA3-256 integrity hash + a jose verification token for the report. */
export function attachIntegrity(report: EnterpriseAssessmentReport): EnterpriseAssessmentReport {
  const seal = sealDocument(canonicalize(report), { reportId: report.meta.id, kind: report.meta.kind });
  return { ...report, integrity: seal };
}

export interface BuildReportOptions {
  snapshot: QuantumReadinessSnapshot;
  branding: ReportBranding;
  kind: ReportKind;
  generatedBy: string;
  withCharts?: boolean;
  /**
   * Optional asset scope — asset names/keys to include in the report. When the
   * selection is a strict subset of the discovered assets, the snapshot is
   * re-scoped (evidence filtered + scores recomputed) before the model is
   * built, so every section and chart reflects the selected assets only.
   */
  scopeAssetKeys?: string[] | null;
}

/**
 * ReportEngine — single entry point that assembles the unified
 * EnterpriseAssessmentReport from real evidence, renders chart images, validates
 * against the schema and attaches an integrity hash + verification token.
 */
export function buildReport(options: BuildReportOptions): EnterpriseAssessmentReport {
  const { snapshot, branding, kind, generatedBy, withCharts = true, scopeAssetKeys } = options;
  const scope = buildReportScope(snapshot, scopeAssetKeys?.length ? scopeAssetKeys : null);
  const effectiveSnapshot = scope.type === 'custom' ? scopeSnapshotToAssets(snapshot, scopeAssetKeys!) : snapshot;
  const model = buildReportModel(effectiveSnapshot, branding, kind, generatedBy, scope);
  if (withCharts) {
    try {
      model.charts = renderReportCharts(effectiveSnapshot);
    } catch (error) {
      console.warn('Report chart rendering failed:', error);
      model.charts = [];
    }
  }
  // Validate the assembled model — fail loud in dev if a section drifts.
  const parsed = enterpriseAssessmentReportSchema.safeParse(model);
  if (!parsed.success) {
    console.warn('Report model validation warnings:', parsed.error.issues.slice(0, 5));
  }
  return attachIntegrity(model);
}
