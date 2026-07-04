import { sha3_256 } from '@noble/hashes/sha3.js';
import { UnsecuredJWT } from 'jose';
import type { QuantumReadinessSnapshot } from '@/app/dashboard/quantum-readiness/_shared';
import { buildReportModel } from './ReportEvidence';
import { buildReportScope, scopeSnapshotToAssets } from './ReportScope';
import { renderReportCharts } from './ReportCharts';
import type { EnterpriseAssessmentReport, ReportBranding, ReportKind } from './schemas/ReportSchema';
import { enterpriseAssessmentReportSchema } from './schemas/ReportSchema';

function hex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

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
  const digest = hex(sha3_256(new TextEncoder().encode(canonicalize(report))));
  const signedAt = new Date().toISOString();
  const verificationToken = new UnsecuredJWT({ hash: digest, reportId: report.meta.id, kind: report.meta.kind })
    .setIssuedAt()
    .setSubject(report.meta.id)
    .setIssuer('qguard-helix-reporting')
    .encode();
  return { ...report, integrity: { algorithm: 'SHA3-256', hash: digest, signedAt, verificationToken } };
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
