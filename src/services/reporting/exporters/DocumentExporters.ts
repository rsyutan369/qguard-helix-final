/**
 * Enterprise document export dispatcher.
 *
 * Renders an `InventoryReport` that carries a premium `document` into any of
 * seven formats. Each heavy renderer is imported lazily, so choosing PDF never
 * loads exceljs or pptxgenjs, and one failing library cannot block the others.
 */
import type { InventoryReport } from '../InventoryReport'
import { VALIDATION_LABEL, DOCUMENT_MIME, documentFilename, type DocumentFormat } from './document/shared'

export type { DocumentFormat } from './document/shared'
export const DOCUMENT_FORMATS: DocumentFormat[] = ['pdf', 'docx', 'xlsx', 'pptx', 'html', 'csv', 'json']

export interface DocumentExportResult {
  blob: Blob
  filename: string
  mime: string
  format: DocumentFormat
}

function csvCell(value: unknown): string {
  const s = String(value ?? '')
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/**
 * CSV: the raw registers, one block per table, preceded by a provenance block.
 * UTF-8 with a BOM so Excel opens em dashes and non-Latin asset names intact.
 */
function renderCsv(report: InventoryReport): Blob {
  const d = report.document!
  const lines: string[] = [
    `# ${d.cover.title} — ${d.branding.companyName}`,
    `# Scope: ${d.cover.scopeLine}`,
    `# Report ID: ${report.meta.reportId || '—'} · Generated ${report.meta.generatedAt} · Evidence as of ${report.meta.dataAsOf || '—'}`,
    `# Validation: ${VALIDATION_LABEL[d.validation.status]} (quality ${d.validation.score}/100)`,
    `# Integrity: ${report.integrity ? `${report.integrity.algorithm} ${report.integrity.hash}` : 'not sealed'}`,
    '',
  ]
  for (const table of report.tables) {
    lines.push(`# ${table.title} (${table.rows.length} rows)`)
    lines.push(table.columns.map(csvCell).join(','))
    for (const row of table.rows) lines.push(row.map(csvCell).join(','))
    lines.push('')
  }
  return new Blob([`﻿${lines.join('\r\n')}`], { type: `${DOCUMENT_MIME.csv};charset=utf-8` })
}

function renderJson(report: InventoryReport): Blob {
  return new Blob([JSON.stringify(report, null, 2)], { type: `${DOCUMENT_MIME.json};charset=utf-8` })
}

export async function exportDocument(report: InventoryReport, format: DocumentFormat): Promise<DocumentExportResult> {
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
export async function previewDocument(report: InventoryReport): Promise<void> {
  const blob = (await import('./document/html')).renderDocumentHtml(report)
  const url = URL.createObjectURL(blob)
  const opened = window.open(url, '_blank', 'noopener,noreferrer')
  // Keep the object URL alive long enough for the new tab to load it.
  window.setTimeout(() => URL.revokeObjectURL(url), opened ? 60_000 : 0)
  if (!opened) throw new Error('The preview window was blocked — allow pop-ups for this site, or export HTML instead.')
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
