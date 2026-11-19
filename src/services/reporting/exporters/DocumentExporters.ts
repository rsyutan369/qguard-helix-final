/**
 * Enterprise document export dispatcher.
 *
 * Renders an `InventoryReport` that carries a premium `document` into any of
 * seven formats. Each heavy renderer is imported lazily, so choosing PDF never
 * loads exceljs or pptxgenjs, and one failing library cannot block the others.
 */
import { VALIDATION_LABEL, DOCUMENT_MIME, documentFilename, type DocumentExportInput, type DocumentFormat } from './document/shared'
import { csvCell } from '@/lib/csv'

export type { DocumentExportInput, DocumentFormat } from './document/shared'
export const DOCUMENT_FORMATS: DocumentFormat[] = ['pdf', 'docx', 'xlsx', 'pptx', 'html', 'csv', 'json']

export interface DocumentExportResult {
  blob: Blob
  filename: string
  mime: string
  format: DocumentFormat
}

/**
 * CSV: the raw registers, one block per table, preceded by a provenance block.
 * UTF-8 with a BOM so Excel opens em dashes and non-Latin asset names intact.
 */
function renderCsv(report: DocumentExportInput): Blob {
  const d = report.document!
  const lines: string[] = []
  const section = (title: string, columns: string[], rows: Array<Array<string | number>>) => {
    lines.push(['# Section', title].map(csvCell).join(','))
    lines.push(columns.map(csvCell).join(','))
    for (const row of rows) lines.push(row.map(csvCell).join(','))
    lines.push('')
  }
  section('Report details', ['Field', 'Value'], [
    ['Title', d.cover.title],
    ['Organization', d.branding.companyName],
    ['Scope', d.cover.scopeLine],
    ['Generated at', report.meta.generatedAt],
    ['Validation', VALIDATION_LABEL[d.validation.status]],
    ...d.cover.facts.map(({ label, value }) => [label, value]),
    ...(report.integrity ? [['Integrity digest', `${report.integrity.algorithm} ${report.integrity.hash}`]] : []),
  ])
  section('Executive summary', ['Summary'], [[d.summary.headline], ...d.summary.paragraphs.map((paragraph) => [paragraph])])
  section('Key figures', ['Measure', 'Value', 'Context'], d.summary.highlights.map(({ label, value, detail }) => [label, value, detail || '']))
  for (const table of report.tables) section(table.title, table.columns, table.rows)
  if (d.decisions.length) section('Executive decisions', ['Priority', 'Decision', 'Rationale', 'Evidence', 'Owner'], d.decisions.map((decision) => [decision.priority, decision.decision, decision.rationale, decision.evidence, decision.owner]))
  section('Validation', ['Check', 'Result', 'Detail'], d.validation.checks.map((check) => [check.check, VALIDATION_LABEL[check.status], check.detail]))
  if (report.reconciliation.length) section('Reconciliation', ['Metric', 'Dashboard', 'Exported', 'Result'], report.reconciliation.map((row) => [row.metric, row.dashboard, row.exported, row.matches ? 'MATCH' : 'REVIEW']))
  if (d.provenance.length) section('Evidence & provenance', ['Source'], d.provenance.map((source) => [source]))
  return new Blob([`﻿${lines.join('\r\n')}`], { type: `${DOCUMENT_MIME.csv};charset=utf-8` })
}

function renderJson(report: DocumentExportInput): Blob {
  return new Blob([JSON.stringify(report, null, 2)], { type: `${DOCUMENT_MIME.json};charset=utf-8` })
}

export async function exportDocument(report: DocumentExportInput, format: DocumentFormat): Promise<DocumentExportResult> {
  if (!report.document) throw new Error('This report has no enterprise document to render.')
  let blob: Blob
  switch (format) {
    case 'pdf':
      blob = await (await import('./document/pdf')).renderDocumentPdf(report)
      break
    case 'docx':
      blob = await (await import('./document/docx')).renderDocumentDocx(report)
      break
    case 'xlsx':
      blob = await (await import('./document/xlsx')).renderDocumentXlsx(report)
      break
    case 'pptx':
      blob = await (await import('./document/pptx')).renderDocumentPptx(report)
      break
    case 'html':
      blob = (await import('./document/html')).renderDocumentHtml(report)
      break
    case 'csv':
      blob = renderCsv(report)
      break
    case 'json':
    default:
      blob = renderJson(report)
      break
  }
  return { blob, filename: documentFilename(report, format), mime: DOCUMENT_MIME[format], format }
}

/** Open the HTML rendering in a new tab for review before exporting. */
export async function previewDocument(report: DocumentExportInput): Promise<void> {
  const opened = window.open('', '_blank')
  if (!opened) throw new Error('The preview window was blocked — allow pop-ups for this site, or export HTML instead.')
  opened.opener = null
  try {
    const { blob } = await exportDocument(report, 'html')
    const url = URL.createObjectURL(blob)
    opened.location.replace(url)
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
  } catch (error) {
    opened.close()
    throw error
  }
}

export function downloadDocument(result: DocumentExportResult): void {
  const url = URL.createObjectURL(result.blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = result.filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 2000)
}
