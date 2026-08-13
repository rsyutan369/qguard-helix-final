/**
 * Inventory export renderers — PDF, Excel, Word, HTML.
 *
 * One document model (`InventoryReport`) rendered four ways, using the same
 * libraries and visual language as the assessment exporters (pdf-lib, exceljs,
 * docx) so an inventory register and an assessment report look like they came
 * from the same product.
 *
 * Every renderer prints the KPI band, the Reconciliation table and the
 * provenance/notes block. The reconciliation block is not decoration: it is how
 * a reader verifies the export matches the dashboard it was launched from
 * without having to trust the exporter.
 *
 * Heavy libraries are imported lazily by `exportInventory` so choosing PDF never
 * loads exceljs, and one failing library can never block the other formats.
 */
import type { InventoryReport } from '../InventoryReport'
import type { ReportTable } from '../schemas/ReportSchema'
import { sanitizeForWinAnsi } from './pdf-text'

export type InventoryFormat = 'pdf' | 'xlsx' | 'docx' | 'html' | 'csv' | 'json'

const MIME: Record<InventoryFormat, string> = {
  pdf: 'application/pdf',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  html: 'text/html',
  csv: 'text/csv',
  json: 'application/json',
}

export interface InventoryExportResult {
  blob: Blob
  filename: string
  mime: string
  format: InventoryFormat
}

/* ------------------------------------------------------------------ */
/* PDF (pdf-lib)                                                       */
/* ------------------------------------------------------------------ */

/** Every string drawn into a standard-font PDF must pass through this. */
const san = sanitizeForWinAnsi

async function renderPdf(report: InventoryReport): Promise<Blob> {
  const { PDFDocument, StandardFonts, rgb } = await import('pdf-lib')
  const doc = await PDFDocument.create()
  doc.setTitle(`${report.meta.title} — ${report.meta.companyName}`)
  doc.setProducer('QGuard Helix')
  doc.setCreationDate(new Date(report.meta.generatedAt))

  const font = await doc.embedFont(StandardFonts.Helvetica)
  const bold = await doc.embedFont(StandardFonts.HelveticaBold)
  const mono = await doc.embedFont(StandardFonts.Courier)

  // Landscape: inventory tables are wide, and wrapping a register makes it
  // unreadable.
  const SIZE: [number, number] = [842, 595]
  const MARGIN = 32
  const INK = rgb(0.09, 0.11, 0.16)
  const MUTED = rgb(0.42, 0.46, 0.53)
  const ACCENT = rgb(0.05, 0.65, 0.79)
  const LINE = rgb(0.85, 0.88, 0.92)
  const BAND = rgb(0.96, 0.97, 0.99)

  let page = doc.addPage(SIZE)
  let y = SIZE[1] - MARGIN
  let pageNumber = 1

  const footer = (p: typeof page, n: number) => {
    p.drawText(san(`${report.meta.classification}  ·  ${report.meta.companyName}  ·  Generated ${new Date(report.meta.generatedAt).toISOString().slice(0, 16).replace('T', ' ')} UTC`), {
      x: MARGIN, y: 18, size: 7, font, color: MUTED,
    })
    p.drawText(`Page ${n}`, { x: SIZE[0] - MARGIN - 40, y: 18, size: 7, font, color: MUTED })
  }

  const newPage = () => {
    footer(page, pageNumber)
    page = doc.addPage(SIZE)
    pageNumber += 1
    y = SIZE[1] - MARGIN
  }
  const ensure = (needed: number) => { if (y - needed < 40) newPage() }

  // ---- Cover band -------------------------------------------------
  page.drawRectangle({ x: 0, y: SIZE[1] - 92, width: SIZE[0], height: 92, color: rgb(0.03, 0.06, 0.11) })
  page.drawText(san(report.meta.title), { x: MARGIN, y: SIZE[1] - 44, size: 20, font: bold, color: rgb(1, 1, 1) })
  page.drawText(san(report.meta.subtitle), { x: MARGIN, y: SIZE[1] - 62, size: 9, font, color: rgb(0.62, 0.7, 0.8) })
  page.drawText(san(`${report.meta.companyName}   ·   ${report.meta.classification}`), {
    x: MARGIN, y: SIZE[1] - 80, size: 8, font, color: ACCENT,
  })
  y = SIZE[1] - 112

  // ---- KPI band ---------------------------------------------------
  const kpiWidth = (SIZE[0] - MARGIN * 2) / Math.max(1, report.kpis.length)
  for (let i = 0; i < report.kpis.length; i += 1) {
    const kpi = report.kpis[i]
    const x = MARGIN + i * kpiWidth
    page.drawRectangle({ x, y: y - 46, width: kpiWidth - 6, height: 46, color: BAND })
    page.drawText(san(kpi.label.toUpperCase()), { x: x + 8, y: y - 15, size: 6.5, font: bold, color: MUTED })
    page.drawText(san(kpi.value), { x: x + 8, y: y - 33, size: 15, font: bold, color: INK })
    if (kpi.detail) page.drawText(san(kpi.detail).slice(0, 34), { x: x + 8, y: y - 42, size: 6, font, color: MUTED })
  }
  y -= 62

  page.drawText(san(report.meta.scopeNote), { x: MARGIN, y, size: 8, font, color: INK })
  y -= 12
  page.drawText(san(report.meta.provenance), { x: MARGIN, y, size: 6.5, font, color: MUTED })
  y -= 18

  // ---- Tables -----------------------------------------------------
  const drawTable = (table: ReportTable) => {
    ensure(60)
    page.drawText(san(table.title.toUpperCase()), { x: MARGIN, y, size: 9, font: bold, color: ACCENT })
    y -= 14

    const usable = SIZE[0] - MARGIN * 2
    // Column widths proportional to header length + sampled content, so a
    // register with a long "Component" column does not squash everything else.
    const weights = table.columns.map((column, index) => {
      const sample = table.rows.slice(0, 40).reduce((max, row) => Math.max(max, san(row[index]).length), 0)
      return Math.max(6, Math.min(40, Math.max(String(column).length, sample)))
    })
    const totalWeight = weights.reduce((sum, w) => sum + w, 0) || 1
    const widths = weights.map((w) => (w / totalWeight) * usable)

    const header = () => {
      page.drawRectangle({ x: MARGIN, y: y - 12, width: usable, height: 14, color: rgb(0.91, 0.94, 0.97) })
      let x = MARGIN + 3
      table.columns.forEach((column, index) => {
        page.drawText(truncate(san(column), widths[index], 6.5, bold), { x, y: y - 9, size: 6.5, font: bold, color: INK })
        x += widths[index]
      })
      y -= 16
    }
    header()

    table.rows.forEach((row, rowIndex) => {
      if (y < 44) { newPage(); page.drawText(san(`${table.title.toUpperCase()} (continued)`), { x: MARGIN, y, size: 9, font: bold, color: ACCENT }); y -= 14; header() }
      if (rowIndex % 2 === 1) page.drawRectangle({ x: MARGIN, y: y - 9, width: usable, height: 11, color: rgb(0.98, 0.985, 0.99) })
      let x = MARGIN + 3
      row.forEach((cell, index) => {
        page.drawText(truncate(san(cell), widths[index], 6, font), { x, y: y - 7, size: 6, font, color: INK })
        x += widths[index]
      })
      y -= 11
    })
    page.drawLine({ start: { x: MARGIN, y: y + 2 }, end: { x: MARGIN + usable, y: y + 2 }, thickness: 0.4, color: LINE })
    y -= 14
  }

  for (const table of report.tables) drawTable(table)

  // ---- Reconciliation + notes -------------------------------------
  drawTable({
    title: 'Reconciliation — dashboard vs exported',
    columns: ['Metric', 'Dashboard', 'Exported', 'Result'],
    rows: report.reconciliation.map((row) => [row.metric, row.dashboard, row.exported, row.matches ? 'MATCH' : 'REVIEW']),
  })

  ensure(50)
  page.drawText('NOTES', { x: MARGIN, y, size: 8, font: bold, color: MUTED })
  y -= 11
  for (const note of report.notes) {
    for (const line of wrap(san(note), 150)) {
      ensure(12)
      page.drawText(line, { x: MARGIN, y, size: 6.5, font, color: MUTED })
      y -= 9
    }
    y -= 2
  }

  ensure(16)
  page.drawText(san(`Document id: ${report.meta.kind}-${new Date(report.meta.generatedAt).getTime()}`), { x: MARGIN, y, size: 6, font: mono, color: MUTED })

  footer(page, pageNumber)
  const bytes = await doc.save()
  return new Blob([bytes as unknown as BlobPart], { type: MIME.pdf })
}

function truncate(value: string, width: number, size: number, font: { widthOfTextAtSize(text: string, size: number): number }): string {
  const limit = Math.max(0, width - 6)
  if (font.widthOfTextAtSize(value, size) <= limit) return value
  // ASCII "..." rather than "…": the ellipsis is appended AFTER sanitisation,
  // so a non-Latin-1 glyph introduced here would bypass the guard entirely.
  let cut = value
  while (cut.length > 1 && font.widthOfTextAtSize(`${cut}...`, size) > limit) cut = cut.slice(0, -1)
  return `${cut}...`
}

function wrap(value: string, columns: number): string[] {
  const words = value.split(/\s+/)
  const lines: string[] = []
  let line = ''
  for (const word of words) {
    if ((line + ' ' + word).trim().length > columns) { lines.push(line.trim()); line = word } else line += ` ${word}`
  }
  if (line.trim()) lines.push(line.trim())
  return lines
}

/* ------------------------------------------------------------------ */
/* Excel (exceljs)                                                     */
/* ------------------------------------------------------------------ */

async function renderXlsx(report: InventoryReport): Promise<Blob> {
  const ExcelJS = (await import('exceljs')).default
  const workbook = new ExcelJS.Workbook()
  workbook.creator = report.meta.companyName
  workbook.created = new Date(report.meta.generatedAt)

  const summary = workbook.addWorksheet('Summary')
  summary.addRow([report.meta.title]).font = { bold: true, size: 16 }
  summary.addRow([report.meta.subtitle]).font = { italic: true }
  summary.addRow([`${report.meta.companyName} · ${report.meta.classification} · Generated ${new Date(report.meta.generatedAt).toLocaleString()}`])
  summary.addRow([report.meta.scopeNote])
  summary.addRow([report.meta.provenance])
  summary.addRow([])
  const kpiHeader = summary.addRow(['KPI', 'Value', 'Detail'])
  kpiHeader.font = { bold: true }
  kpiHeader.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0E7490' } }
  kpiHeader.font = { bold: true, color: { argb: 'FFFFFFFF' } }
  for (const kpi of report.kpis) summary.addRow([kpi.label, kpi.value, kpi.detail ?? ''])
  summary.addRow([])
  const reconHeader = summary.addRow(['Reconciliation', 'Dashboard', 'Exported', 'Result'])
  reconHeader.font = { bold: true, color: { argb: 'FFFFFFFF' } }
  reconHeader.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0E7490' } }
  for (const row of report.reconciliation) {
    const added = summary.addRow([row.metric, row.dashboard, row.exported, row.matches ? 'MATCH' : 'REVIEW'])
    added.getCell(4).font = { bold: true, color: { argb: row.matches ? 'FF047857' : 'FFB91C1C' } }
  }
  summary.addRow([])
  for (const note of report.notes) summary.addRow([note])
  summary.columns.forEach((column) => { column.width = 42 })
  summary.getColumn(1).width = 46

  for (const table of report.tables) {
    // Excel sheet names cap at 31 chars and reject several characters.
    const name = table.title.replace(/[\\/*?:[\]]/g, ' ').slice(0, 31)
    const sheet = workbook.addWorksheet(name)
    const header = sheet.addRow(table.columns)
    header.font = { bold: true, color: { argb: 'FFFFFFFF' } }
    header.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0F172A' } }
    header.alignment = { vertical: 'middle' }
    table.rows.forEach((row) => sheet.addRow(row))
    sheet.views = [{ state: 'frozen', ySplit: 1 }]
    if (table.rows.length) sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: table.columns.length } }
    sheet.columns.forEach((column) => {
      let max = 12
      column.eachCell?.({ includeEmpty: true }, (cell) => { max = Math.max(max, String(cell.value ?? '').length + 2) })
      column.width = Math.min(58, max)
    })
  }

  const buffer = await workbook.xlsx.writeBuffer()
  return new Blob([buffer as unknown as BlobPart], { type: MIME.xlsx })
}

/* ------------------------------------------------------------------ */
/* Word (docx)                                                         */
/* ------------------------------------------------------------------ */

async function renderDocx(report: InventoryReport): Promise<Blob> {
  const docx = await import('docx')
  const { AlignmentType, Document, HeadingLevel, Packer, Paragraph, Table, TableCell, TableRow, TextRun, WidthType } = docx

  const cell = (value: string, opts: { bold?: boolean; header?: boolean } = {}) =>
    new TableCell({
      shading: opts.header ? { fill: '0F172A' } : undefined,
      children: [
        new Paragraph({
          children: [new TextRun({ text: value, bold: opts.bold || opts.header, size: 15, color: opts.header ? 'FFFFFF' : '111827' })],
        }),
      ],
    })

  const renderTable = (table: ReportTable) => [
    new Paragraph({ text: table.title, heading: HeadingLevel.HEADING_2, spacing: { before: 260, after: 100 } }),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        new TableRow({ tableHeader: true, children: table.columns.map((column) => cell(String(column), { header: true })) }),
        // Word documents become unusable past a few thousand rows; the register
        // is capped here and the omission is STATED, never silent.
        ...table.rows.slice(0, 800).map((row) => new TableRow({ children: row.map((value) => cell(String(value ?? ''))) })),
      ],
    }),
    ...(table.rows.length > 800
      ? [new Paragraph({ children: [new TextRun({ text: `Showing the first 800 of ${table.rows.length} rows — export to Excel for the complete register.`, italics: true, size: 14, color: '6B7280' })] })]
      : []),
  ]

  const doc = new Document({
    creator: report.meta.companyName,
    title: report.meta.title,
    sections: [
      {
        properties: { page: { size: { orientation: docx.PageOrientation.LANDSCAPE } } },
        children: [
          new Paragraph({ text: report.meta.title, heading: HeadingLevel.TITLE }),
          new Paragraph({ children: [new TextRun({ text: report.meta.subtitle, italics: true, color: '4B5563' })] }),
          new Paragraph({
            children: [new TextRun({ text: `${report.meta.companyName} · ${report.meta.classification} · Generated ${new Date(report.meta.generatedAt).toLocaleString()}`, size: 16, color: '6B7280' })],
            alignment: AlignmentType.LEFT,
            spacing: { after: 160 },
          }),
          new Paragraph({ children: [new TextRun({ text: report.meta.scopeNote, size: 17 })] }),
          new Paragraph({ children: [new TextRun({ text: report.meta.provenance, size: 14, color: '6B7280' })], spacing: { after: 200 } }),

          new Paragraph({ text: 'Summary', heading: HeadingLevel.HEADING_2 }),
          new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            rows: [
              new TableRow({ tableHeader: true, children: ['KPI', 'Value', 'Detail'].map((c) => cell(c, { header: true })) }),
              ...report.kpis.map((kpi) => new TableRow({ children: [cell(kpi.label), cell(kpi.value, { bold: true }), cell(kpi.detail ?? '')] })),
            ],
          }),

          ...report.tables.flatMap(renderTable),

          ...renderTable({
            title: 'Reconciliation — dashboard vs exported',
            columns: ['Metric', 'Dashboard', 'Exported', 'Result'],
            rows: report.reconciliation.map((row) => [row.metric, row.dashboard, row.exported, row.matches ? 'MATCH' : 'REVIEW']),
          }),

          new Paragraph({ text: 'Notes', heading: HeadingLevel.HEADING_2, spacing: { before: 240 } }),
          ...report.notes.map((note) => new Paragraph({ children: [new TextRun({ text: note, size: 15, color: '4B5563' })], spacing: { after: 60 } })),
        ],
      },
    ],
  })

  const blob = await Packer.toBlob(doc)
  return blob
}

/* ------------------------------------------------------------------ */
/* HTML                                                                */
/* ------------------------------------------------------------------ */

/** Escape every evidence-derived string: asset names come from scanned input. */
function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function renderHtml(report: InventoryReport): Blob {
  const table = (t: ReportTable) => `
  <section class="tbl">
    <h2>${esc(t.title)}</h2>
    <div class="scroll">
      <table>
        <thead><tr>${t.columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead>
        <tbody>${t.rows.map((r) => `<tr>${r.map((v) => `<td>${esc(v)}</td>`).join('')}</tr>`).join('')}</tbody>
      </table>
    </div>
    <p class="count">${t.rows.length} row${t.rows.length === 1 ? '' : 's'}</p>
  </section>`

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(report.meta.title)} — ${esc(report.meta.companyName)}</title>
<style>
:root{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--accent:#0e7490;--band:#f8fafc;--ok:#047857;--warn:#b91c1c}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);background:#fff}
header{background:#050a14;color:#fff;padding:28px 32px}
header h1{margin:0;font-size:24px;letter-spacing:-.02em}
header p{margin:6px 0 0;color:#9fb3c8;font-size:13px}
header .meta{margin-top:10px;color:#22d3ee;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
main{padding:24px 32px 56px;max-width:1600px;margin:0 auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:20px}
.kpi{border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:var(--band)}
.kpi .l{font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.kpi .v{font-size:24px;font-weight:800;margin-top:4px}
.kpi .d{font-size:11px;color:var(--muted)}
.scope{font-size:13px;margin:0 0 4px}
.prov{font-size:11px;color:var(--muted);margin:0 0 22px}
h2{font-size:12px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--accent);margin:26px 0 8px}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:12px}
th{background:#0f172a;color:#fff;text-align:left;padding:8px 10px;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;position:sticky;top:0}
td{padding:6px 10px;border-top:1px solid var(--line);vertical-align:top}
tbody tr:nth-child(even){background:#fbfdfe}
.count{font-size:11px;color:var(--muted);margin:6px 0 0}
.match{color:var(--ok);font-weight:800}.review{color:var(--warn);font-weight:800}
.notes{margin-top:28px;border-top:1px solid var(--line);padding-top:14px}
.notes li{font-size:11.5px;color:var(--muted);margin-bottom:6px}
@media print{header{background:#050a14 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}.scroll{overflow:visible;border:0}th{position:static}}
</style></head>
<body>
<header>
  <h1>${esc(report.meta.title)}</h1>
  <p>${esc(report.meta.subtitle)}</p>
  <div class="meta">${esc(report.meta.companyName)} · ${esc(report.meta.classification)} · ${esc(new Date(report.meta.generatedAt).toLocaleString())}</div>
</header>
<main>
  <div class="kpis">
    ${report.kpis.map((k) => `<div class="kpi"><div class="l">${esc(k.label)}</div><div class="v">${esc(k.value)}</div>${k.detail ? `<div class="d">${esc(k.detail)}</div>` : ''}</div>`).join('')}
  </div>
  <p class="scope">${esc(report.meta.scopeNote)}</p>
  <p class="prov">${esc(report.meta.provenance)}</p>
  ${report.tables.map(table).join('')}
  <section class="tbl">
    <h2>Reconciliation — dashboard vs exported</h2>
    <div class="scroll"><table>
      <thead><tr><th>Metric</th><th>Dashboard</th><th>Exported</th><th>Result</th></tr></thead>
      <tbody>${report.reconciliation.map((r) => `<tr><td>${esc(r.metric)}</td><td>${esc(r.dashboard)}</td><td>${esc(r.exported)}</td><td class="${r.matches ? 'match' : 'review'}">${r.matches ? 'MATCH' : 'REVIEW'}</td></tr>`).join('')}</tbody>
    </table></div>
  </section>
  <div class="notes"><ul>${report.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul></div>
</main>
</body></html>`
  return new Blob([html], { type: `${MIME.html};charset=utf-8` })
}

/* ------------------------------------------------------------------ */
/* CSV / JSON — kept so the existing affordances are not lost          */
/* ------------------------------------------------------------------ */

function csvCell(value: unknown): string {
  const s = String(value ?? '')
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

function renderCsv(report: InventoryReport): Blob {
  const lines: string[] = []
  for (const table of report.tables) {
    lines.push(`# ${table.title}`)
    lines.push(table.columns.map(csvCell).join(','))
    for (const row of table.rows) lines.push(row.map(csvCell).join(','))
    lines.push('')
  }
  return new Blob([lines.join('\n')], { type: `${MIME.csv};charset=utf-8` })
}

function renderJson(report: InventoryReport): Blob {
  return new Blob([JSON.stringify(report, null, 2)], { type: `${MIME.json};charset=utf-8` })
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                            */
/* ------------------------------------------------------------------ */

export async function exportInventory(report: InventoryReport, format: InventoryFormat): Promise<InventoryExportResult> {
  let blob: Blob
  switch (format) {
    case 'pdf': blob = await renderPdf(report); break
    case 'xlsx': blob = await renderXlsx(report); break
    case 'docx': blob = await renderDocx(report); break
    case 'html': blob = renderHtml(report); break
    case 'csv': blob = renderCsv(report); break
    case 'json':
    default: blob = renderJson(report); break
  }
  const stamp = new Date(report.meta.generatedAt).toISOString().slice(0, 10)
  const slug = report.meta.filenameSlug
    || (report.meta.kind === 'assets' ? 'asset-inventory' : report.meta.kind === 'migration' ? 'live-migration-report' : 'cbom')
  const filename = `qguard-${slug}-${stamp}.${format}`
  return { blob, filename, mime: MIME[format], format }
}

export function downloadInventory(result: InventoryExportResult): void {
  const url = URL.createObjectURL(result.blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = result.filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}
