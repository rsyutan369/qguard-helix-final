import type { DocumentFact, DocumentSection } from './ReportDocument'
import type { EvidenceAssessmentReport, ReportFormat, ReportTable } from './schemas/ReportSchema'
import { exportDocument, type DocumentExportInput, type DocumentExportResult } from './exporters/DocumentExporters'
import { utc } from './exporters/document/shared'
import { REPORT_TEMPLATES } from './templates'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#D97706',
  low: '#2478FF',
  info: '#64748B',
}

function severityChart(table: ReportTable, rowCount: number) {
  if (!rowCount) return null
  const counts = new Map<string, number>()
  for (const row of table.rows) {
    const severity = String(row[2])
    counts.set(severity, (counts.get(severity) ?? 0) + 1)
  }
  return {
    type: 'bars' as const,
    title: 'Findings by severity',
    caption: 'Counts are grouped from the finding rows included in this snapshot.',
    items: Array.from(counts, ([severity, value]) => ({
      label: severity,
      color: SEVERITY_COLORS[severity],
      value,
    })).sort((a, b) => Object.keys(SEVERITY_COLORS).indexOf(a.label) - Object.keys(SEVERITY_COLORS).indexOf(b.label)),
  }
}

/** Present captured evidence without recalculating its scores or querying current data. */
export function buildReadinessDocument(report: EvidenceAssessmentReport): DocumentExportInput {
  const { meta, branding, provenance } = report
  const template = REPORT_TEMPLATES.find(({ kind }) => kind === meta.kind)!
  const status = provenance.validationStatus === 'validated' ? 'Validated' : 'Incomplete'
  const facts: DocumentFact[] = [
    { label: 'Report branding', value: branding.companyName },
    { label: 'Report ID', value: provenance.reportId },
    { label: 'Snapshot timestamp', value: utc(provenance.snapshotAt) },
    { label: 'Generated at', value: utc(meta.generatedAt) },
    { label: 'Organization ID', value: provenance.organizationId ?? 'Unavailable' },
    { label: 'Snapshot validation', value: status },
  ]
  const sourceTable: ReportTable = {
    title: 'Snapshot sources and completeness',
    columns: ['Source', 'Status', 'Detail'],
    rows: provenance.dataCompleteness.map(({ source, status, detail }) => [source, status, detail]),
  }
  const versions: ReportTable = {
    title: 'Evidence references',
    columns: ['Source', 'Version or identifier'],
    rows: [
      ['Asset inventory version', provenance.assetInventoryVersion ?? 'Unavailable'],
      ['CBOM version', provenance.cbomVersion ?? 'Unavailable'],
      ['Assessment ID', provenance.assessmentId ?? 'Unavailable'],
    ],
  }
  const findings: ReportTable = {
    title: 'Recorded findings',
    columns: ['Finding ID', 'Title', 'Severity', 'Affected assets', 'Source', 'Detected at', 'Evidence', 'Recommendation'],
    rows: report.findings.map((finding) => [
      finding.id, finding.title, finding.severity, finding.affectedAssets.join(', '),
      finding.source, utc(finding.detectedAt), finding.evidence, finding.recommendation,
    ]),
  }
  const tables = [...report.tables, findings, versions, sourceTable]
  const sections: DocumentSection[] = report.tables.map((table, index) => ({
    id: `evidence-${index + 1}`,
    title: table.title,
    blocks: [{ type: 'table', table, wide: table.columns.length > 5 }],
  }))
  const chart = severityChart(findings, report.findings.length)
  sections.push({
    id: 'findings',
    title: findings.title,
    blocks: [
      ...(chart ? [chart] : []),
      { type: 'table', table: findings, emphasis: [{ column: 2, kind: 'severity' }], wide: true },
    ],
  }, {
    id: 'snapshot-provenance',
    title: 'Data Provenance',
    blocks: [
      { type: 'table', table: versions, widths: [30, 70] },
      { type: 'table', table: sourceTable, widths: [24, 14, 62] },
    ],
  })
  const integrity = report.integrity?.algorithm === 'SHA3-256' ? {
    algorithm: 'SHA3-256' as const,
    hash: report.integrity.hash,
    signedAt: report.integrity.signedAt,
    // Readiness JSON may contain a legacy unsigned token. Export its digest only.
    verificationToken: '',
  } : undefined

  return {
    meta: {
      reportId: provenance.reportId,
      filenameSlug: `readiness-${meta.kind}-${provenance.reportId.slice(0, 8)}`,
      generatedAt: meta.generatedAt,
      version: meta.version,
      generatedBy: meta.generatedBy,
      dataAsOf: meta.sourceGeneratedAt,
    },
    tables,
    reconciliation: [],
    integrity,
    document: {
      branding,
      template: { key: meta.kind, name: template.name, audience: template.audience },
      cover: {
        eyebrow: 'QGuard Helix · Quantum Readiness',
        title: meta.title,
        subtitle: 'Captured assessment evidence',
        scopeLine: report.scope.note,
        facts,
      },
      summary: {
        headline: report.executiveSummary,
        paragraphs: [report.scope.methodology].filter(Boolean),
        highlights: report.kpis.map(({ label, value, unit, level, tone }) => ({
          label, value: `${value}${unit ?? ''}`, detail: level, tone,
        })),
      },
      sections,
      decisions: [],
      validation: {
        status: provenance.validationStatus === 'validated' ? 'pass' : 'warn',
        checks: [],
      },
      provenance: [],
    },
  }
}

export async function exportReadinessReport(report: EvidenceAssessmentReport, format: ReportFormat): Promise<DocumentExportResult> {
  const model = buildReadinessDocument(report)
  if (format !== 'json') return exportDocument(model, format)

  const { workspaceOwnerId: _owner, ...provenance } = report.provenance
  return {
    blob: new Blob([JSON.stringify({ ...report, provenance }, null, 2)], { type: 'application/json;charset=utf-8' }),
    filename: `qguard-${model.meta.filenameSlug}-${report.meta.generatedAt.slice(0, 10)}.json`,
    mime: 'application/json',
    format,
  }
}
