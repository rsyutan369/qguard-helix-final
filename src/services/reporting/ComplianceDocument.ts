import { CONTROL_STATUS_LABEL } from '@/lib/governance/types'
import type { AssetComplianceScope } from '@/lib/governance/asset-scope'
import { ASSET_REPORT_TEMPLATES, utcStamp, type AssetReportTemplate } from './AssetReport'
import { validationScore, type DocumentSection } from './ReportDocument'
import { brandingSchema, type ReportTable } from './schemas/ReportSchema'
import type { DocumentExportInput } from './exporters/DocumentExporters'

export function buildAssetComplianceDocument(
  scope: AssetComplianceScope,
  template: AssetReportTemplate,
  generatedAt = new Date().toISOString(),
): DocumentExportInput {
  if (!scope.assets.length) throw new Error('Select at least one registered asset.')
  const ids = new Set(scope.assets.map((asset) => asset.id))
  const attributed = [...scope.evidence, ...scope.findings, ...scope.auditEvents, ...scope.remediation,
    ...scope.violations, ...scope.controls.flatMap((row) => row.failingSubjects)]
  if (ids.size !== scope.assets.length || attributed.some((row) => !row.assetId || !ids.has(row.assetId))) {
    throw new Error('This report includes evidence outside the selected asset scope.')
  }

  const spec = ASSET_REPORT_TEMPLATES.find((item) => item.key === template)!
  const score = (value: number | null) => value === null ? 'Not assessed' : `${value}%`
  const gaps = scope.controls.filter((row) => row.status === 'non-compliant' || row.status === 'partial')
  const span = scope.earliestEvidenceAt && scope.latestEvidenceAt
    ? `${utcStamp(scope.earliestEvidenceAt)} to ${utcStamp(scope.latestEvidenceAt)}` : 'No dated evidence available'
  const assetTable: ReportTable = {
    title: 'Selected assets',
    columns: ['Asset', 'ID', 'Owner', 'Environment', 'Lifecycle', 'Compliance', 'Risk level', 'Risk score', 'Posture', 'Last evidence'],
    rows: scope.assets.map((row) => [row.name, row.id, row.owner, row.environment, row.lifecycle, score(row.score), row.riskLevel ?? 'Unrecorded', row.riskScore ?? 'Not assessed', row.posture ?? 'Not assessed', utcStamp(row.lastEvidenceAt)]),
  }
  const controls: ReportTable = {
    title: 'Asset control assessments',
    columns: ['Control', 'Status', 'Score', 'Evaluated', 'Passed', 'Assessment basis', 'Last validation'],
    rows: scope.controls.map((row) => [`${row.code} · ${row.title}`, CONTROL_STATUS_LABEL[row.status], score(row.score),
      row.population, row.satisfied, row.basis, utcStamp(row.lastValidatedAt)]),
  }
  const regulatory: ReportTable = {
    title: 'Regulatory mappings',
    columns: ['Framework', 'Requirement', 'Status', 'Controls measured', 'Evidence records'],
    rows: scope.requirements.map((row) => [row.frameworkLabel, `${row.code} · ${row.title}`, CONTROL_STATUS_LABEL[row.status],
      `${row.controlsMeasured} of ${row.controlIds.length}`, row.evidenceCount]),
  }
  const gapTable: ReportTable = {
    title: 'Control gaps',
    columns: ['Control', 'Status', 'Severity', 'Failing subjects', 'Remediation module'],
    rows: gaps.map((row) => [`${row.code} · ${row.title}`, CONTROL_STATUS_LABEL[row.status], row.severity ?? 'Unrated', row.failing, row.remediationRoute]),
  }
  const findings: ReportTable = {
    title: 'Attributed risk findings',
    columns: ['Asset ID', 'Finding', 'Severity', 'Recorded status', 'Observed', 'Source record'],
    rows: scope.findings.map((row) => [row.assetId!, row.title, row.severity ?? 'Unrated', row.statusLabel ?? 'Unrecorded',
      utcStamp(row.occurredAt || row.recordedAt), `${row.source.table}/${row.source.recordId}`]),
  }
  const violations: ReportTable = {
    title: 'Policy violations',
    columns: ['Asset ID', 'Policy', 'Subject', 'Severity', 'Observed', 'Expected', 'Source record'],
    rows: scope.violations.map((row) => [row.assetId!, row.policyId, row.subject, row.severity, row.observed,
      row.expected, `${row.source.table}/${row.source.recordId}`]),
  }
  const remediation: ReportTable = {
    title: 'Recorded remediation jobs',
    columns: ['Asset ID', 'Job ID', 'Job', 'Status', 'Updated'],
    rows: scope.remediation.map((row) => [row.assetId, row.id, row.title, row.status ?? 'Unrecorded', utcStamp(row.updatedAt)]),
  }
  const evidence: ReportTable = {
    title: 'Supporting evidence',
    columns: ['Asset ID', 'Evidence', 'Outcome', 'Integrity', 'Observed', 'Source record'],
    rows: scope.evidence.map((row) => [row.assetId!, row.title, row.outcome, row.integrity.state,
      utcStamp(row.occurredAt || row.recordedAt), `${row.source.table}/${row.source.recordId}`]),
  }
  const audit: ReportTable = {
    title: 'Supporting audit events',
    columns: ['Asset ID', 'Action', 'Outcome', 'Timestamp', 'Source record'],
    rows: scope.auditEvents.map((row) => [row.assetId!, row.action, row.outcome, utcStamp(row.at), `${row.source.table}/${row.source.recordId}`]),
  }
  const tables = template === 'remediation' ? [assetTable, gapTable, findings, violations, remediation, controls, regulatory, evidence, audit]
    : template === 'technical' ? [assetTable, controls, evidence, audit, regulatory, findings, violations, gapTable, remediation]
    : [assetTable, controls, regulatory, gapTable, findings, violations, remediation, evidence, audit]
  const sections: DocumentSection[] = tables.map((table, index) => ({
    id: `scope-${index}`, title: table.title,
    blocks: table.rows.length ? [{
      type: 'table', table, wide: table.columns.length >= 7,
      widths: table === controls ? [23, 11, 9, 8, 7, 28, 14] : undefined,
      emphasis: table === findings ? [{ column: 2, kind: 'severity' }]
        : table === gapTable ? [{ column: 2, kind: 'severity' }] : undefined,
    }] : [{ type: 'paragraph', text: 'No records available for this selection.' }],
  }))
  const branding = brandingSchema.parse({})
  const title = 'Asset Compliance Assessment'
  const assessed = `${scope.measured} of ${scope.controls.length}`
  return {
    meta: { generatedAt, version: branding.reportVersion, filenameSlug: 'qguard-asset-compliance', dataAsOf: scope.latestEvidenceAt ?? undefined },
    tables,
    reconciliation: [
      { metric: 'Selected assets', dashboard: String(scope.assets.length), exported: String(assetTable.rows.length), matches: scope.assets.length === assetTable.rows.length },
      { metric: 'Attributed evidence', dashboard: String(scope.evidence.length), exported: String(evidence.rows.length), matches: scope.evidence.length === evidence.rows.length },
    ],
    document: {
      branding,
      template: { key: spec.key, name: spec.name, audience: spec.audience },
      cover: {
        eyebrow: 'QGuard Helix · Governance',
        title,
        subtitle: 'Evidence and control results for selected registered assets',
        scopeLine: `${scope.assets.length} registered asset(s)`,
        facts: [
          { label: 'Generated', value: utcStamp(generatedAt) },
          { label: 'Assessment captured', value: utcStamp(scope.generatedAt) },
          { label: 'Evidence period', value: span },
        ],
      },
      summary: {
        headline: `Measured-control compliance · ${score(scope.score)}`,
        paragraphs: ['Controls are evaluated against evidence attributable to the selected assets. Regulatory mappings describe platform control coverage and require independent review for certification.'],
        highlights: [
          { label: 'Measured controls', value: assessed },
          { label: 'Control gaps', value: String(gaps.length) },
          { label: 'Supporting evidence', value: String(scope.evidence.length) },
        ],
      },
      sections,
      decisions: [],
      validation: validationScore([
        { check: 'Asset scope', status: 'pass', detail: 'All attributed records belong to the exact registered selection.' },
        { check: 'Assessment coverage', status: scope.measured < scope.controls.length ? 'warn' : 'pass', detail: `${assessed} controls measured.` },
        { check: 'Source availability', status: scope.unavailableSources.length || scope.truncated ? 'warn' : 'pass',
          detail: [scope.unavailableSources.length ? `Unavailable sources: ${scope.unavailableSources.join(', ')}.` : '',
            scope.truncated ? 'The governance evidence window is limited.' : ''].filter(Boolean).join(' ') || 'Sources answered within their read limits.' },
      ]),
      provenance: [
        'Source: the tenant-scoped Governance assessment returned for the exact asset selection.',
        'Unassessed controls are excluded from the weighted score and retained in the coverage denominator.',
        'Remediation status is copied from recorded jobs. A recorded job alone establishes no verification of remediation.',
      ],
    },
  }
}
