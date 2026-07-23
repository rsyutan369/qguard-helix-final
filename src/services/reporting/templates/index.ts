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
    description: 'KPI cards, risk scores, findings summary, roadmap, shared responsibility ownership, executive narrative and a signed certification summary.',
    sections: ['KPI Cards', 'Risk Scores', 'Findings Summary', 'Roadmap', 'Shared Responsibility', 'Executive Narrative', 'Certification Summary'],
    formats: ['pdf', 'pptx', 'docx', 'html', 'json'],
  },
  {
    kind: 'technical',
    name: 'Technical Assessment™',
    audience: 'Security Engineers',
    description: 'Asset inventory, TLS analysis, certificates, CBOM, vulnerabilities and shared responsibility ownership (edge vs origin, provider attribution).',
    sections: ['Asset Inventory', 'TLS Analysis', 'Certificates', 'CBOM', 'Vulnerabilities', 'Shared Responsibility'],
    formats: ['pdf', 'xlsx', 'docx', 'csv', 'json'],
  },
  {
    kind: 'compliance',
    name: 'Compliance Report™',
    audience: 'Auditors · Regulators',
    description: 'NIST, FIPS 203/204/205, ISO 27001, PCI DSS, SOC 2 control mappings and shared responsibility ownership attribution.',
    sections: ['NIST', 'FIPS 203/204/205', 'ISO 27001', 'PCI DSS', 'SOC 2', 'Mappings', 'Shared Responsibility'],
    formats: ['pdf', 'docx', 'xlsx', 'json'],
  },
  {
    kind: 'migration',
    name: 'PQC Migration Report™',
    audience: 'Migration Teams',
    description: 'Readiness, risk, timeline, cost forecast, migration waves and the shared responsibility dependency-ordered roadmap.',
    sections: ['Readiness', 'Risk', 'Timeline', 'Cost Forecast', 'Migration Waves', 'Shared Responsibility'],
    formats: ['pdf', 'xlsx', 'pptx', 'docx', 'json'],
  },
];
