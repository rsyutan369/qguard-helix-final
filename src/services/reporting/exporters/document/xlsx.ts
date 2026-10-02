/**
 * Enterprise Excel renderer for `ReportDocument` (exceljs).
 *
 * Sheet 1 "Report" is the document: cover facts, executive summary, KPIs,
 * decisions, validation, reconciliation and the integrity seal. Every register
 * table then gets its own sheet — header in row 1 so filters and pivots work,
 * frozen, auto-filtered, status/severity cells tinted, long text wrapped. The
 * workbook is the COMPLETE register: nothing is capped here.
 */
import type { InventoryReport } from '../../InventoryReport'
import type { ReportTable } from '../../schemas/ReportSchema'
import { cellTone, type TableEmphasis } from '../../ReportDocument'
import { BRAND, INK, MUTED, VALIDATION_LABEL, noHash, tint, toneHex, utc, verificationUrl } from './shared'

type Worksheet = import('exceljs').Worksheet

const argb = (hex: string) => `FF${noHash(hex)}`

/** Columns whose words carry a state, tinted in every register sheet. */
const EMPHASIS_BY_HEADER: Record<string, TableEmphasis['kind']> = {
  'PQC Status': 'status',
  'Posture': 'status',
  'Freshness': 'status',
  'Result': 'status',
  'Severity': 'severity',
  'Worst Severity': 'severity',
  'Priority': 'priority',
  'Risk Band': 'band',
  'Flagged': 'status',
}

const LONG_TEXT = new Set(['Recommended Action', 'Evidence', 'Recommendation', 'Rationale', 'Decision', 'Detail', 'Observation', 'Assets', 'Component', 'Target'])

function writeRegister(sheet: Worksheet, table: ReportTable) {
  const header = sheet.addRow(table.columns)
  header.font = { bold: true, color: { argb: 'FFFFFFFF' } }
  header.alignment = { vertical: 'middle', wrapText: true }
  header.height = 30
  header.eachCell((cell) => {
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: argb(INK) } }
  })
  for (const row of table.rows) sheet.addRow(row.map((cell) => (typeof cell === 'number' ? cell : String(cell ?? ''))))
  sheet.views = [{ state: 'frozen', ySplit: 1 }]
  if (table.rows.length) sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: table.columns.length } }

  table.columns.forEach((column, index) => {
    const col = sheet.getColumn(index + 1)
    const longText = LONG_TEXT.has(String(column))
    let max = String(column).length + 2
    col.eachCell({ includeEmpty: false }, (cell) => {
      max = Math.max(max, Math.min(80, String(cell.value ?? '').length + 2))
    })
    col.width = longText ? Math.min(60, Math.max(24, max)) : Math.min(34, Math.max(10, max))
    if (longText) col.alignment = { wrapText: true, vertical: 'top' }
    const kind = EMPHASIS_BY_HEADER[String(column)]
    if (!kind) return
    col.eachCell({ includeEmpty: false }, (cell, rowNumber) => {
      if (rowNumber === 1) return
      const value = String(cell.value ?? '')
      if (!value.trim() || value === '—') return
      const hex = toneHex(cellTone(kind, value))
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: argb(tint(hex, 0.82)) } }
      cell.font = { bold: true, color: { argb: argb(INK) } }
      cell.border = { left: { style: 'thick', color: { argb: argb(hex) } } }
    })
  })
}

function sheetName(title: string, used: Set<string>): string {
  let base = title.replace(/[\\/*?:[\]]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 28) || 'Sheet'
  let name = base
  let n = 2
  while (used.has(name.toLowerCase())) {
    name = `${base.slice(0, 26)} ${n}`
    n += 1
  }
  used.add(name.toLowerCase())
  return name
}

export async function renderDocumentXlsx(report: InventoryReport): Promise<Blob> {
  const ExcelJS = (await import('exceljs')).default
  const d = report.document!
  const wb = new ExcelJS.Workbook()
  wb.creator = d.branding.companyName
  wb.company = d.branding.companyName
  wb.title = d.cover.title
  wb.subject = `${d.cover.eyebrow} · ${d.cover.scopeLine}`
  wb.keywords = [report.meta.reportId, report.integrity?.hash].filter(Boolean).join(' ')
  wb.created = new Date(report.meta.generatedAt)

  const used = new Set<string>()
  const ws = wb.addWorksheet(sheetName('Report', used), { views: [{ showGridLines: false }] })
  ws.getColumn(1).width = 34
  ws.getColumn(2).width = 22
  ws.getColumn(3).width = 22
  ws.getColumn(4).width = 64

  const title = ws.addRow([d.cover.title])
  title.font = { bold: true, size: 20, color: { argb: argb(INK) } }
  ws.addRow([`${d.cover.eyebrow} · ${d.cover.subtitle}`]).font = { color: { argb: argb(MUTED) }, size: 12 }
  ws.addRow([d.cover.scopeLine]).font = { color: { argb: argb(INK) }, size: 11 }
  const cls = ws.addRow([d.branding.classification || 'CONFIDENTIAL'])
  cls.getCell(1).font = { bold: true, color: { argb: 'FFFFFFFF' } }
  cls.getCell(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: argb(INK) } }
  ws.addRow([])

  const section = (label: string) => {
    ws.addRow([])
    const row = ws.addRow([label])
    row.font = { bold: true, size: 13, color: { argb: argb(INK) } }
    row.getCell(1).border = { bottom: { style: 'medium', color: { argb: argb(BRAND) } } }
  }
  const pairs = (items: Array<[string, string]>) => {
    for (const [label, value] of items) {
      const row = ws.addRow([label, value])
      row.getCell(1).font = { bold: true, color: { argb: argb(MUTED) } }
      ws.mergeCells(row.number, 2, row.number, 4)
      row.getCell(2).alignment = { wrapText: true, vertical: 'top' }
    }
  }
  const grid = (columns: string[], rows: Array<Array<string | number>>, emphasis?: { column: number; kind: TableEmphasis['kind'] }) => {
    const header = ws.addRow(columns)
    header.eachCell((cell) => {
      cell.font = { bold: true, color: { argb: 'FFFFFFFF' } }
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: argb(INK) } }
    })
    for (const values of rows) {
      const row = ws.addRow(values)
      row.alignment = { wrapText: true, vertical: 'top' }
      if (emphasis) {
        const cell = row.getCell(emphasis.column + 1)
        const hex = toneHex(cellTone(emphasis.kind, values[emphasis.column]))
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: argb(tint(hex, 0.82)) } }
        cell.font = { bold: true }
      }
    }
  }

  section('Report details')
  pairs(d.cover.facts.map((f) => [f.label, f.value]))

  section('Executive summary')
  const headline = ws.addRow([d.summary.headline])
  headline.font = { bold: true, size: 12, color: { argb: argb(INK) } }
  ws.mergeCells(headline.number, 1, headline.number, 4)
  headline.alignment = { wrapText: true, vertical: 'top' }
  headline.height = 36
  for (const paragraph of d.summary.paragraphs) {
    const row = ws.addRow([paragraph])
    ws.mergeCells(row.number, 1, row.number, 4)
    row.alignment = { wrapText: true, vertical: 'top' }
    row.height = Math.min(120, 16 * Math.ceil(paragraph.length / 120) + 6)
  }

  section('Key figures')
  grid(['Measure', 'Value', 'Context'], d.summary.highlights.map((k) => [k.label, k.value, k.detail || '']))

  if (d.decisions.length) {
    section('Executive decision register')
    grid(['Priority', 'Decision', 'Owner', 'Rationale & evidence'], d.decisions.map((x) => [x.priority, x.decision, x.owner, `${x.rationale} Evidence: ${x.evidence}`]), { column: 0, kind: 'priority' })
  }

  section(`Validation — ${VALIDATION_LABEL[d.validation.status]} · quality ${d.validation.score}/100`)
  grid(['Check', 'Result', '', 'Detail'], d.validation.checks.map((c) => [c.check, VALIDATION_LABEL[c.status], '', c.detail]), { column: 1, kind: 'status' })

  section('Reconciliation — dashboard vs exported')
  grid(['Metric', 'Dashboard', 'Exported', 'Result'], report.reconciliation.map((r) => [r.metric, r.dashboard, r.exported, r.matches ? 'MATCH' : 'REVIEW']), { column: 3, kind: 'status' })

  section('Integrity seal')
  const url = verificationUrl(report)
  pairs([
    ['Algorithm', report.integrity?.algorithm || 'Not sealed'],
    ['Digest', report.integrity?.hash || '—'],
    ['Signed at', report.integrity ? utc(report.integrity.signedAt) : '—'],
    ['Verification', url || 'Unavailable'],
  ])

  section('Evidence & provenance')
  for (const line of d.provenance) {
    const row = ws.addRow([line])
    ws.mergeCells(row.number, 1, row.number, 4)
    row.alignment = { wrapText: true, vertical: 'top' }
    row.height = 32
  }

  // The registers — complete, one sheet each.
  for (const table of report.tables) {
    const sheet = wb.addWorksheet(sheetName(table.title, used))
    writeRegister(sheet, table)
  }

  const buffer = await wb.xlsx.writeBuffer()
  return new Blob([buffer as unknown as BlobPart], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
}
