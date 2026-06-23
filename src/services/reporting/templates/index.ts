import type { ReportFormat, ReportKind } from '../schemas/ReportSchema';

/**
 * Report templates (Phase 4). Each maps an audience to the sections emphasised
 * and the export formats best suited to it. The unified model carries every
 * section; the template drives titling, emphasis and recommended formats.
 */
export interface ReportTemplate {
  kind: ReportKind;
  name: string;
  audience: string;
  description: string;
  sections: string[];
  formats: ReportFormat[];
}

export const REPORT_TEMPLATES: ReportTemplate[] = [
  {
    kind: 'executive',
    name: 'Executive Report™',
    audience: 'CEO · Board · CISO',
    description: 'KPI cards, risk scores, findings summary, roadmap and an executive narrative.',
    sections: ['KPI Cards', 'Risk Scores', 'Findings Summary', 'Roadmap', 'Executive Narrative'],
    formats: ['pdf', 'pptx', 'docx', 'html', 'json'],
  },
  {
    kind: 'technical',
    name: 'Technical Assessment™',
    audience: 'Security Engineers',
    description: 'Asset inventory, TLS analysis, certificates, CBOM and vulnerabilities.',
    sections: ['Asset Inventory', 'TLS Analysis', 'Certificates', 'CBOM', 'Vulnerabilities'],
    formats: ['pdf', 'xlsx', 'docx', 'csv', 'json'],
  },
  {
    kind: 'compliance',
    name: 'Compliance Report™',
    audience: 'Auditors · Regulators',
    description: 'NIST, FIPS 203/204/205, ISO 27001, PCI DSS and SOC 2 control mappings.',
    sections: ['NIST', 'FIPS 203/204/205', 'ISO 27001', 'PCI DSS', 'SOC 2', 'Mappings'],
    formats: ['pdf', 'docx', 'xlsx', 'json'],
  },
  {
    kind: 'migration',
    name: 'PQC Migration Report™',
    audience: 'Migration Teams',
    description: 'Readiness, risk, timeline, cost forecast and migration waves.',
    sections: ['Readiness', 'Risk', 'Timeline', 'Cost Forecast', 'Migration Waves'],
    formats: ['pdf', 'xlsx', 'pptx', 'docx', 'json'],
  },
];
