import { z } from 'zod';

/**
 * QGuard Helix Enterprise Reporting Engine™ — unified report model.
 *
 * `EnterpriseAssessmentReport` is the single source of truth every exporter
 * (PDF / DOCX / XLSX / CSV / JSON / HTML / PPTX) consumes. It is assembled
 * exclusively from real assessment evidence/telemetry — see ReportEvidence.ts.
 * Missing evidence is represented explicitly (`Evidence Not Available`); findings
 * are never fabricated.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const REPORT_KINDS = ['executive', 'technical', 'compliance', 'migration'] as const;
export type ReportKind = (typeof REPORT_KINDS)[number];

export const REPORT_FORMATS = ['pdf', 'docx', 'xlsx', 'csv', 'json', 'html', 'pptx'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export const EVIDENCE_UNAVAILABLE = 'Evidence Not Available';

export const findingSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: z.enum(SEVERITIES),
  evidence: z.string(),
  affectedAssets: z.array(z.string()),
  recommendation: z.string(),
  remediationPlan: z.string(),
  source: z.string().default('QGuard Helix'),
  detectedAt: z.string().nullable().optional(),
});
export type ReportFinding = z.infer<typeof findingSchema>;

export const kpiSchema = z.object({
  label: z.string(),
  value: z.union([z.string(), z.number()]),
  unit: z.string().optional(),
  level: z.string().optional(),
  tone: z.enum(['critical', 'high', 'medium', 'low', 'good', 'neutral']).default('neutral'),
});
export type ReportKpi = z.infer<typeof kpiSchema>;

export const tableSchema = z.object({
  title: z.string(),
  columns: z.array(z.string()),
  rows: z.array(z.array(z.union([z.string(), z.number()]))),
});
export type ReportTable = z.infer<typeof tableSchema>;

export const complianceMappingSchema = z.object({
  framework: z.string(),
  control: z.string(),
  status: z.enum(['aligned', 'partial', 'gap', 'not-assessed']),
  detail: z.string(),
});
export type ComplianceMapping = z.infer<typeof complianceMappingSchema>;

export const roadmapPhaseSchema = z.object({
  phase: z.string(),
  description: z.string(),
  status: z.string(),
  effortWeeks: z.number(),
});
export type RoadmapPhase = z.infer<typeof roadmapPhaseSchema>;

export const brandingSchema = z.object({
  companyName: z.string().default('QGuard Helix'),
  companyLogo: z.string().nullable().default(null), // data URL or storage URL
  businessUnit: z.string().default(''),
  reportOwner: z.string().default(''),
  reviewer: z.string().default(''),
  classification: z.string().default('CONFIDENTIAL'),
  reportVersion: z.string().default('1.0'),
  customNotes: z.string().default(''),
});
export type ReportBranding = z.infer<typeof brandingSchema>;

export const chartImageSchema = z.object({
  key: z.string(),
  title: z.string(),
  dataUrl: z.string(), // PNG data URL for embedding
});
export type ReportChartImage = z.infer<typeof chartImageSchema>;

export const reportMetaSchema = z.object({
  id: z.string(),
  kind: z.enum(REPORT_KINDS),
  title: z.string(),
  generatedAt: z.string(),
  generatedBy: z.string(),
  version: z.string(),
  tenantScoped: z.boolean().default(true),
  sourceGeneratedAt: z.string().nullable(),
});
export type ReportMeta = z.infer<typeof reportMetaSchema>;

export const integritySchema = z.object({
  algorithm: z.string(), // SHA3-256
  hash: z.string(),
  signedAt: z.string(),
  verificationToken: z.string().optional(),
});
export type ReportIntegrity = z.infer<typeof integritySchema>;

export const enterpriseAssessmentReportSchema = z.object({
  meta: reportMetaSchema,
  branding: brandingSchema,
  executiveSummary: z.string(),
  kpis: z.array(kpiSchema),
  findings: z.array(findingSchema),
  assets: tableSchema,
  certificates: tableSchema,
  keys: tableSchema,
  tlsEndpoints: tableSchema,
  cbom: tableSchema,
  hndl: z.object({ summary: z.string(), table: tableSchema }),
  trustRelationships: tableSchema,
  pqcReadiness: z.object({ summary: z.string(), table: tableSchema }),
  compliance: z.array(complianceMappingSchema),
  roadmap: z.array(roadmapPhaseSchema),
  remediation: tableSchema,
  evidence: z.object({ sources: z.array(z.string()), notes: z.string() }),
  charts: z.array(chartImageSchema),
  integrity: integritySchema.optional(),
});
export type EnterpriseAssessmentReport = z.infer<typeof enterpriseAssessmentReportSchema>;

export function severityRank(severity: Severity): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity] ?? 0;
}

export function normalizeSeverity(value: string): Severity {
  const v = (value || '').toLowerCase();
  if (v.includes('critical')) return 'critical';
  if (v.includes('high')) return 'high';
  if (v.includes('medium') || v.includes('moderate')) return 'medium';
  if (v.includes('low')) return 'low';
  return 'info';
}
