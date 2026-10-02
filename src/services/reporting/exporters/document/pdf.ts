/**
 * Enterprise PDF renderer for `ReportDocument` (pdf-lib — identical in dev,
 * production and Node).
 *
 * Everything is vector: charts are drawn as shapes from the block's values, the
 * verification QR is drawn module by module, and no table is silently cut —
 * rows paginate with a repeated header, wide registers move to landscape pages,
 * and the one guard against a runaway cell (a single cell taller than a page)
 * says where the full text lives instead of hiding it.
 *
 * pdf-lib's standard fonts encode CP1252 only; EVERY string goes through
 * `sanitizeForWinAnsi` (see exporters/pdf-text.ts for the crash it prevents).
 */
import { PDFDocument, StandardFonts, degrees, rgb, type PDFFont, type PDFPage } from 'pdf-lib'
import type { InventoryReport } from '../../InventoryReport'
import type { ReportTable } from '../../schemas/ReportSchema'
import type { AssetDossier, BarItem, DocumentBlock, DocumentFact, DocumentKpi, StackSegment, TableEmphasis } from '../../ReportDocument'
import { cellTone } from '../../ReportDocument'
import { qrMatrix } from '../../ReportQr'
import { sanitizeForWinAnsi } from '../pdf-text'
import {
  BAND,
  BRAND,
  HEADER_BG,
  INK,
  INK_SOFT,
  LINE,
  MUTED,
  VALIDATION_LABEL,
  contentsEntries,
  countLabel,
  dataUrlToBytes,
  fitBox,
  hexToRgb01,
  imageKind,
  imageSize,
  percentOf,
  tint,
  toneHex,
  utc,
  verificationUrl,
} from './shared'

const PORTRAIT: [number, number] = [595.28, 841.89]
const LANDSCAPE: [number, number] = [841.89, 595.28]
const MARGIN = 44
const TOP_RESERVE = 60
const BOTTOM_RESERVE = 56
/** A single cell taller than this many lines is capped, with a pointer to the full text. */
const MAX_CELL_LINES = 16

/**
 * The shared WinAnsi sanitiser turns "·" into "-", which reads as a minus sign
 * inside figures ("13 critical - 16 high"). This writer uses a spaced bar for
 * the separator first; everything else goes through the one shared sanitiser.
 */
const san = (value: unknown) => sanitizeForWinAnsi(String(value ?? '').replace(/ · /g, '  |  '))
const color = (hex: string) => {
  const [r, g, b] = hexToRgb01(hex)
  return rgb(r, g, b)
}
const WHITE = rgb(1, 1, 1)

class PdfWriter {
  readonly doc: PDFDocument
  readonly font: PDFFont
  readonly bold: PDFFont
  readonly mono: PDFFont
  page!: PDFPage
  size: [number, number] = PORTRAIT
  y = 0
  readonly toc: Array<{ id: string; title: string; pageIndex: number }> = []
  cappedCells = 0

  constructor(doc: PDFDocument, font: PDFFont, bold: PDFFont, mono: PDFFont) {
    this.doc = doc
    this.font = font
    this.bold = bold
    this.mono = mono
  }

  get width() {
    return this.size[0] - MARGIN * 2
  }
  get top() {
    return this.size[1] - TOP_RESERVE
  }
  get isLandscape() {
    return this.size[0] > this.size[1]
  }

  addPage(size: [number, number] = this.size) {
    this.size = size
    this.page = this.doc.addPage(size)
    this.y = this.top
  }

  ensure(height: number) {
    if (this.y - height < BOTTOM_RESERVE) this.addPage()
  }

  orientation(target: 'portrait' | 'landscape') {
    const want = target === 'landscape' ? LANDSCAPE : PORTRAIT
    if (this.size !== want) this.addPage(want)
  }

  /** Wrap to a width, breaking over-long tokens (hashes, suite names) by character. */
  wrap(text: unknown, size: number, font: PDFFont, maxWidth: number): string[] {
    const clean = san(String(text ?? '')).replace(/\s+/g, ' ').trim()
    if (!clean) return ['']
    const lines: string[] = []
    let current = ''
    const pieces = (word: string): string[] => {
      if (font.widthOfTextAtSize(word, size) <= maxWidth) return [word]
      const out: string[] = []
      let chunk = ''
      for (const ch of word) {
        if (chunk && font.widthOfTextAtSize(chunk + ch, size) > maxWidth) {
          out.push(chunk)
          chunk = ch
        } else chunk += ch
      }
      if (chunk) out.push(chunk)
      return out
    }
    for (const word of clean.split(' ')) {
      for (const piece of pieces(word)) {
        const candidate = current ? `${current} ${piece}` : piece
        if (current && font.widthOfTextAtSize(candidate, size) > maxWidth) {
          lines.push(current)
          current = piece
        } else current = candidate
      }
    }
    if (current) lines.push(current)
    return lines
  }

  draw(text: string, x: number, y: number, size: number, font: PDFFont = this.font, hex = INK_SOFT) {
    this.page.drawText(san(text), { x, y, size, font, color: color(hex) })
  }

  sectionHeading(id: string, title: string) {
    this.ensure(64)
    this.toc.push({ id, title, pageIndex: this.doc.getPageCount() - 1 })
    this.y -= 8
    this.draw(title, MARGIN, this.y - 16, 17, this.bold, INK)
    this.y -= 26
    this.page.drawRectangle({ x: MARGIN, y: this.y, width: 36, height: 2.4, color: color(BRAND) })
    this.page.drawLine({ start: { x: MARGIN + 38, y: this.y + 1.2 }, end: { x: MARGIN + this.width, y: this.y + 1.2 }, thickness: 0.5, color: color(LINE) })
    this.y -= 14
  }

  subHeading(title: string) {
    this.ensure(34)
    this.y -= 4
    this.draw(title, MARGIN, this.y - 10, 10.5, this.bold, INK)
    this.y -= 18
  }

  paragraph(text: string, opts: { size?: number; hex?: string; font?: PDFFont; indent?: number } = {}) {
    const size = opts.size ?? 9.5
    const font = opts.font ?? this.font
    const indent = opts.indent ?? 0
    for (const line of this.wrap(text, size, font, this.width - indent)) {
      this.ensure(size + 4)
      this.draw(line, MARGIN + indent, this.y - size, size, font, opts.hex ?? INK_SOFT)
      this.y -= size + 3.4
    }
    this.y -= 5
  }

  kpis(items: DocumentKpi[]) {
    const perRow = this.isLandscape ? 4 : 3
    const gap = 8
    const cellW = (this.width - gap * (perRow - 1)) / perRow
    const cellH = 56
    for (let i = 0; i < items.length; i += perRow) {
      this.ensure(cellH + gap)
      items.slice(i, i + perRow).forEach((kpi, index) => {
        const x = MARGIN + index * (cellW + gap)
        const top = this.y
        this.page.drawRectangle({ x, y: top - cellH, width: cellW, height: cellH, color: WHITE, borderColor: color(LINE), borderWidth: 0.8 })
        this.page.drawRectangle({ x, y: top - 3, width: cellW, height: 3, color: color(toneHex(kpi.tone)) })
        this.draw(this.wrap(kpi.label.toUpperCase(), 6.8, this.bold, cellW - 16)[0], x + 8, top - 15, 6.8, this.bold, MUTED)
        let valueSize = 16
        while (valueSize > 9 && this.bold.widthOfTextAtSize(san(kpi.value), valueSize) > cellW - 16) valueSize -= 1
        this.draw(kpi.value, x + 8, top - 35, valueSize, this.bold, INK)
        if (kpi.detail) this.draw(this.wrap(kpi.detail, 7.4, this.font, cellW - 16)[0], x + 8, top - 48, 7.4, this.font, MUTED)
      })
      this.y -= cellH + gap
    }
    this.y -= 4
  }

  bars(block: { title: string; caption?: string; items: BarItem[]; unit?: string }) {
    // Keep the heading with its chart: a small chart moves whole to the next page.
    this.ensure(Math.min(34 + block.items.length * 17 + (block.caption ? 22 : 6), this.top - BOTTOM_RESERVE))
    this.subHeading(block.title)
    const max = Math.max(1, ...block.items.map((item) => item.value))
    const labelW = 128
    const valueW = 90
    const trackW = this.width - labelW - valueW
    const barH = 9
    const rowH = 17
    for (const item of block.items) {
      this.ensure(rowH)
      const baseY = this.y - 13
      this.draw(this.wrap(item.label, 8.5, this.font, labelW - 8)[0], MARGIN, baseY + 1, 8.5, this.font, INK)
      this.page.drawRectangle({ x: MARGIN + labelW, y: baseY, width: trackW, height: barH, color: color('#EEF2F7') })
      const fill = (trackW * item.value) / max
      if (item.value > 0) {
        const radius = barH / 2
        const body = Math.max(0, fill - radius)
        this.page.drawRectangle({ x: MARGIN + labelW, y: baseY, width: body, height: barH, color: color(item.color) })
        this.page.drawEllipse({ x: MARGIN + labelW + body, y: baseY + radius, xScale: Math.min(radius, fill), yScale: radius, color: color(item.color) })
      }
      const valueText = `${countLabel(item.value, block.unit)}${item.detail ? ` · ${item.detail}` : ''}`
      this.draw(valueText, MARGIN + labelW + trackW + 8, baseY + 1, 8.2, this.bold, INK)
      this.y -= rowH
    }
    if (block.caption) this.paragraph(block.caption, { size: 7.6, hex: MUTED })
    else this.y -= 6
  }

  stacked(block: { title: string; caption?: string; segments: StackSegment[]; total: number; unit?: string }) {
    this.ensure(34 + 16 + 44 + (block.caption ? 22 : 0))
    this.subHeading(block.title)
    const total = block.total || block.segments.reduce((sum, s) => sum + s.value, 0)
    const barH = 16
    this.ensure(barH + 44)
    const y0 = this.y - barH
    const visible = block.segments.filter((segment) => segment.value > 0)
    if (!total || !visible.length) {
      this.page.drawRectangle({ x: MARGIN, y: y0, width: this.width, height: barH, color: color('#EEF2F7') })
      this.draw('No components measured', MARGIN + 8, y0 + 5, 8, this.font, MUTED)
    } else {
      const gap = 2
      const available = this.width - gap * (visible.length - 1)
      let x = MARGIN
      for (const segment of visible) {
        const w = (available * segment.value) / total
        this.page.drawRectangle({ x, y: y0, width: w, height: barH, color: color(segment.color) })
        const label = `${segment.value.toLocaleString('en-US')}`
        if (this.bold.widthOfTextAtSize(label, 8) + 8 < w) this.draw(label, x + 5, y0 + 5, 8, this.bold, '#FFFFFF')
        x += w + gap
      }
    }
    this.y = y0 - 10
    // Legend: swatch + label + count + share, all in ink.
    let lx = MARGIN
    for (const segment of block.segments) {
      const text = `${segment.label}  ${segment.value.toLocaleString('en-US')} (${percentOf(segment.value, total)})`
      const w = this.font.widthOfTextAtSize(san(text), 8) + 22
      if (lx + w > MARGIN + this.width) {
        lx = MARGIN
        this.y -= 13
      }
      this.page.drawRectangle({ x: lx, y: this.y - 7, width: 8, height: 8, color: color(segment.color) })
      this.draw(text, lx + 12, this.y - 6.5, 8, this.font, INK)
      lx += w
    }
    this.y -= 16
    if (block.caption) this.paragraph(block.caption, { size: 7.6, hex: MUTED })
  }

  private columnWidths(table: ReportTable, widths: number[] | undefined, size: number): number[] {
    const count = table.columns.length
    if (widths && widths.length === count) {
      const sum = widths.reduce((a, b) => a + b, 0) || 1
      return widths.map((w) => (w / sum) * this.width)
    }
    // Auto layout: proportional to content, but never narrower than the column's
    // longest single word (header or sampled cell) — otherwise a short column
    // like "Severity" wraps one character per line and a page holds four rows.
    const pad = 3.6 * 2 + 8
    const longestWord = (value: unknown, font: PDFFont) =>
      san(String(value ?? '')).split(/\s+/).reduce((max, word) => Math.max(max, font.widthOfTextAtSize(word, size)), 0)
    const minimums = table.columns.map((column, index) => {
      const cellMax = table.rows.slice(0, 60).reduce((max, row) => Math.max(max, longestWord(row[index], this.font)), 0)
      return Math.min(96, Math.max(longestWord(column, this.bold), cellMax) + pad)
    })
    const weights = table.columns.map((column, index) => {
      const sample = table.rows.slice(0, 60).reduce((max, row) => Math.max(max, san(String(row[index] ?? '')).length), 0)
      return Math.max(5, Math.min(38, Math.max(String(column).length * 0.9, sample)))
    })
    const minTotal = minimums.reduce((a, b) => a + b, 0)
    if (minTotal >= this.width) return minimums.map((m) => (m / minTotal) * this.width)
    const spare = this.width - minTotal
    const weightTotal = weights.reduce((a, b) => a + b, 0) || 1
    return minimums.map((m, i) => m + (weights[i] / weightTotal) * spare)
  }

  table(table: ReportTable, opts: { widths?: number[]; emphasis?: TableEmphasis[]; note?: string; compact?: boolean; showTitle?: boolean } = {}) {
    const count = table.columns.length
    const size = opts.compact ? 6.4 : count > 8 ? 6.8 : count > 6 ? 7.4 : 8
    const lineH = size + 2.2
    const pad = 3.6
    const widths = this.columnWidths(table, opts.widths, size)
    const emphasis = new Map((opts.emphasis || []).map((e) => [e.column, e.kind]))
    if (opts.showTitle !== false) {
      this.ensure(34 + lineH * 4 + pad * 4)
      this.subHeading(table.title)
    }

    const header = () => {
      const lines = table.columns.map((column, i) => this.wrap(String(column), size, this.bold, widths[i] - pad * 2))
      const h = Math.max(...lines.map((l) => l.length)) * lineH + pad * 2
      if (this.y - h - lineH * 2 < BOTTOM_RESERVE) this.addPage()
      this.page.drawRectangle({ x: MARGIN, y: this.y - h, width: this.width, height: h, color: color(HEADER_BG) })
      let x = MARGIN
      lines.forEach((cellLines, i) => {
        cellLines.forEach((line, li) => this.page.drawText(line, { x: x + pad, y: this.y - pad - size + 1 - li * lineH, size, font: this.bold, color: WHITE }))
        x += widths[i]
      })
      this.y -= h
    }
    header()

    if (!table.rows.length) {
      this.ensure(lineH + pad * 2)
      this.draw('No rows.', MARGIN + pad, this.y - pad - size, size, this.font, MUTED)
      this.y -= lineH + pad * 2
    }

    table.rows.forEach((row, rowIndex) => {
      const cells = row.map((cell, i) => {
        const kind = emphasis.get(i)
        const value = String(cell ?? '')
        const marked = Boolean(kind && value.trim() && value !== '—')
        let lines = this.wrap(value, size, marked ? this.bold : this.font, widths[i] - pad * 2 - (marked ? 8 : 0))
        if (lines.length > MAX_CELL_LINES) {
          lines = lines.slice(0, MAX_CELL_LINES)
          lines[MAX_CELL_LINES - 1] = `${lines[MAX_CELL_LINES - 1]} ... [full text in the Excel / JSON export]`
          this.cappedCells += 1
        }
        return { lines, kind: marked ? kind : undefined, value }
      })
      const h = Math.max(1, ...cells.map((cell) => cell.lines.length)) * lineH + pad * 2
      if (this.y - h < BOTTOM_RESERVE) {
        this.addPage()
        header()
      }
      if (rowIndex % 2 === 1) this.page.drawRectangle({ x: MARGIN, y: this.y - h, width: this.width, height: h, color: color('#F8FAFC') })
      let x = MARGIN
      cells.forEach((cell, i) => {
        let tx = x + pad
        if (cell.kind) {
          const tone = cellTone(cell.kind, cell.value)
          this.page.drawCircle({ x: tx + 2.6, y: this.y - pad - size / 2 + 0.6, size: 2.6, color: color(toneHex(tone)) })
          tx += 8
        }
        cell.lines.forEach((line, li) => {
          this.page.drawText(line, { x: tx, y: this.y - pad - size + 1 - li * lineH, size, font: cell.kind ? this.bold : this.font, color: color(INK_SOFT) })
        })
        x += widths[i]
      })
      this.y -= h
      this.page.drawLine({ start: { x: MARGIN, y: this.y }, end: { x: MARGIN + this.width, y: this.y }, thickness: 0.4, color: color(LINE) })
    })
    this.y -= 8
    if (opts.note) this.paragraph(opts.note, { size: 7.6, hex: MUTED })
  }

  callout(tone: string, title: string, text: string) {
    const lines = this.wrap(text, 8.8, this.font, this.width - 26)
    const h = 22 + lines.length * 11.4 + 6
    this.ensure(h + 6)
    const top = this.y
    this.page.drawRectangle({ x: MARGIN, y: top - h, width: this.width, height: h, color: color(tint(tone, 0.9)) })
    this.page.drawRectangle({ x: MARGIN, y: top - h, width: 3, height: h, color: color(tone) })
    this.draw(this.wrap(title, 9.6, this.bold, this.width - 26)[0], MARGIN + 13, top - 15, 9.6, this.bold, INK)
    lines.forEach((line, i) => this.draw(line, MARGIN + 13, top - 29 - i * 11.4, 8.8, this.font, INK_SOFT))
    this.y -= h + 10
  }

  bullets(items: string[]) {
    for (const item of items) {
      const lines = this.wrap(item, 9, this.font, this.width - 14)
      lines.forEach((line, i) => {
        this.ensure(13)
        if (i === 0) this.page.drawCircle({ x: MARGIN + 3, y: this.y - 6, size: 1.7, color: color(BRAND) })
        this.draw(line, MARGIN + 12, this.y - 9, 9, this.font, INK_SOFT)
        this.y -= 12.4
      })
      this.y -= 2
    }
    this.y -= 4
  }

  facts(items: DocumentFact[], columns = 2) {
    const gap = 14
    const colW = (this.width - gap * (columns - 1)) / columns
    for (let i = 0; i < items.length; i += columns) {
      const row = items.slice(i, i + columns)
      const heights = row.map((fact) => this.wrap(fact.value, 8.8, this.font, colW).length * 11 + 14)
      const h = Math.max(...heights)
      this.ensure(h + 4)
      row.forEach((fact, index) => {
        const x = MARGIN + index * (colW + gap)
        this.draw(fact.label.toUpperCase(), x, this.y - 7, 6.6, this.bold, MUTED)
        this.wrap(fact.value, 8.8, this.font, colW).forEach((line, li) => this.draw(line, x, this.y - 18 - li * 11, 8.8, this.font, INK))
      })
      this.y -= h + 4
    }
    this.y -= 4
  }

  badges(items: Array<{ label: string; tone: string }>) {
    let x = MARGIN
    this.ensure(18)
    for (const badge of items) {
      const text = san(badge.label)
      const w = this.bold.widthOfTextAtSize(text, 7.4) + 20
      if (x + w > MARGIN + this.width) {
        x = MARGIN
        this.y -= 17
        this.ensure(18)
      }
      this.page.drawRectangle({ x, y: this.y - 13, width: w, height: 14, color: color(tint(badge.tone, 0.88)), borderColor: color(tint(badge.tone, 0.55)), borderWidth: 0.6 })
      this.page.drawCircle({ x: x + 7, y: this.y - 6, size: 2.4, color: color(badge.tone) })
      this.draw(text, x + 13, this.y - 9, 7.4, this.bold, INK)
      x += w + 6
    }
    this.y -= 22
  }

  dossier(d: AssetDossier) {
    this.ensure(140)
    const top = this.y
    this.page.drawRectangle({ x: MARGIN, y: top - 34, width: this.width, height: 34, color: color(BAND) })
    this.page.drawRectangle({ x: MARGIN, y: top - 34, width: 3, height: 34, color: color(BRAND) })
    this.draw(this.wrap(d.title, 12.5, this.bold, this.width - 20)[0], MARGIN + 12, top - 15, 12.5, this.bold, INK)
    this.draw(this.wrap(d.subtitle, 7.8, this.font, this.width - 20)[0], MARGIN + 12, top - 27, 7.8, this.font, MUTED)
    this.y -= 42
    this.badges(d.badges.map((b) => ({ label: b.label, tone: toneHex(b.tone) })))
    this.facts(d.facts)
    this.paragraph(d.summary, { size: 9, hex: INK })
    for (const t of d.tables) this.table(t.table, { widths: t.widths, emphasis: t.emphasis, note: t.note, compact: true })
    this.y -= 10
  }

  qr(matrix: boolean[][], sizePt: number, x: number, top: number) {
    const quiet = 4
    const total = matrix.length + quiet * 2
    const module = sizePt / total
    this.page.drawRectangle({ x, y: top - sizePt, width: sizePt, height: sizePt, color: WHITE, borderColor: color(LINE), borderWidth: 0.75 })
    matrix.forEach((row, r) =>
      row.forEach((dark, c) => {
        if (dark) this.page.drawRectangle({ x: x + (c + quiet) * module, y: top - (r + quiet + 1) * module, width: module, height: module, color: color(INK) })
      }),
    )
  }

  block(block: DocumentBlock) {
    switch (block.type) {
      case 'paragraph':
        this.paragraph(block.text, block.tone === 'muted' ? { size: 8.6, hex: MUTED } : block.tone === 'lead' ? { size: 11, font: this.bold, hex: INK } : {})
        break
      case 'kpis':
        this.kpis(block.items)
        break
      case 'bars':
        this.bars(block)
        break
      case 'stacked':
        this.stacked(block)
        break
      case 'table':
        this.table(block.table, { widths: block.widths, emphasis: block.emphasis, note: block.note, compact: block.wide })
        break
      case 'callout':
        this.callout(toneHex(block.tone), block.title, block.text)
        break
      case 'bullets':
        this.bullets(block.items)
        break
      case 'facts':
        this.facts(block.items)
        break
      case 'dossier':
        this.dossier(block.dossier)
        break
    }
  }
}

export async function renderDocumentPdf(report: InventoryReport): Promise<Blob> {
  const document = report.document!
  const { branding } = document
  const pdf = await PDFDocument.create()
  pdf.setTitle(san(`${document.cover.title} — ${branding.companyName}`))
  pdf.setAuthor(san(branding.companyName))
  pdf.setSubject(san(`${document.cover.eyebrow} · ${document.cover.scopeLine}`))
  pdf.setKeywords([report.meta.reportId || '', 'QGuard Helix', 'CBOM', 'post-quantum', report.integrity?.hash || ''].filter(Boolean))
  pdf.setProducer('QGuard Helix Enterprise Reporting')
  pdf.setCreationDate(new Date(report.meta.generatedAt))

  const font = await pdf.embedFont(StandardFonts.Helvetica)
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold)
  const mono = await pdf.embedFont(StandardFonts.Courier)
  const w = new PdfWriter(pdf, font, bold, mono)

  /* ---------------- Cover ---------------- */
  w.addPage(PORTRAIT)
  const [pw, ph] = PORTRAIT
  w.page.drawRectangle({ x: 0, y: 0, width: 8, height: ph, color: color(BRAND) })
  let cy = ph - 96
  const kind = imageKind(branding.companyLogo)
  if (kind && branding.companyLogo) {
    try {
      const bytes = dataUrlToBytes(branding.companyLogo)
      const image = kind === 'png' ? await pdf.embedPng(bytes) : await pdf.embedJpg(bytes)
      const box = fitBox(imageSize(bytes, kind) || { width: image.width, height: image.height }, 170, 56)
      w.page.drawImage(image, { x: MARGIN, y: cy - box.height + 40, width: box.width, height: box.height })
    } catch {
      /* logo not embeddable — the cover still carries text branding */
    }
  }
  cy -= 44
  const classification = san(branding.classification || 'CONFIDENTIAL')
  w.page.drawRectangle({ x: MARGIN, y: cy - 5, width: bold.widthOfTextAtSize(classification, 8.5) + 18, height: 19, color: color(INK) })
  w.draw(classification, MARGIN + 9, cy + 0.5, 8.5, bold, '#FFFFFF')
  cy -= 58
  w.draw(document.cover.eyebrow.toUpperCase(), MARGIN, cy, 9.5, bold, BRAND)
  cy -= 36
  for (const line of w.wrap(document.cover.title, 30, bold, pw - MARGIN * 2)) {
    w.draw(line, MARGIN, cy, 30, bold, INK)
    cy -= 36
  }
  cy -= 2
  w.draw(document.cover.subtitle, MARGIN, cy, 14, font, MUTED)
  cy -= 24
  for (const line of w.wrap(document.cover.scopeLine, 11, font, pw - MARGIN * 2)) {
    w.draw(line, MARGIN, cy, 11, font, INK_SOFT)
    cy -= 15
  }
  cy -= 16
  w.page.drawLine({ start: { x: MARGIN, y: cy }, end: { x: pw - MARGIN, y: cy }, thickness: 0.6, color: color(LINE) })
  cy -= 24
  const factColW = (pw - MARGIN * 2 - 20) / 2
  document.cover.facts.forEach((fact, index) => {
    const col = index % 2
    const x = MARGIN + col * (factColW + 20)
    if (col === 0 && index > 0) cy -= 36
    w.draw(fact.label.toUpperCase(), x, cy, 6.8, bold, MUTED)
    w.draw(w.wrap(fact.value, 9.5, font, factColW)[0], x, cy - 13, 9.5, font, INK)
  })
  // Quality + seal summary, bottom of the cover.
  const v = document.validation
  const qualityText = san(`Report quality ${VALIDATION_LABEL[v.status]} · ${v.score}/100`)
  const qualityTone = v.status === 'pass' ? '#16A34A' : v.status === 'warn' ? '#D97706' : '#DC2626'
  w.page.drawRectangle({ x: MARGIN, y: 128, width: bold.widthOfTextAtSize(qualityText, 8.5) + 22, height: 20, color: color(tint(qualityTone, 0.85)), borderColor: color(qualityTone), borderWidth: 0.7 })
  w.page.drawCircle({ x: MARGIN + 8, y: 138, size: 2.8, color: color(qualityTone) })
  w.draw(qualityText, MARGIN + 15, 134.5, 8.5, bold, INK)
  if (report.integrity) {
    w.draw(`Sealed with ${report.integrity.algorithm} · ${report.integrity.hash.slice(0, 24)}... · verify on the closing page`, MARGIN, 108, 7.8, font, MUTED)
  }
  w.page.drawLine({ start: { x: MARGIN, y: 92 }, end: { x: pw - MARGIN, y: 92 }, thickness: 2, color: color(BRAND) })
  w.draw(`${branding.companyName} · ${document.template.audience}`, MARGIN, 76, 8, font, MUTED)

  /* ---------------- Executive summary ---------------- */
  w.addPage(PORTRAIT)
  w.sectionHeading('executive-summary', 'Executive Summary')
  w.paragraph(document.summary.headline, { size: 12, font: bold, hex: INK })
  w.kpis(document.summary.highlights)
  for (const paragraph of document.summary.paragraphs) w.paragraph(paragraph)

  /* ---------------- Sections ---------------- */
  for (const section of document.sections) {
    const wide = section.blocks.some((b) => b.type === 'table' && b.wide)
    if (wide) w.orientation('landscape')
    else if (w.isLandscape) w.orientation('portrait')
    else if (section.pageBreak) w.addPage(PORTRAIT)
    w.sectionHeading(section.id, section.title)
    if (section.intro) w.paragraph(section.intro, { size: 9, hex: MUTED })
    for (const block of section.blocks) w.block(block)
  }
  if (w.isLandscape) w.orientation('portrait')

  /* ---------------- Decisions ---------------- */
  if (document.decisions.length) {
    w.addPage(PORTRAIT)
    w.sectionHeading('decisions', 'Executive Decision Register')
    w.paragraph('Decisions the evidence in this report requires. Each names its rationale, the evidence behind it and the accountable owner recorded on the assets.', { size: 9, hex: MUTED })
    w.table(
      {
        title: 'Decisions required',
        columns: ['Priority', 'Decision', 'Rationale', 'Evidence', 'Owner'],
        rows: document.decisions.map((d) => [d.priority, d.decision, d.rationale, d.evidence, d.owner]),
      },
      { widths: [8, 26, 28, 24, 14], emphasis: [{ column: 0, kind: 'priority' }] },
    )
  }

  /* ---------------- Validation, reconciliation & integrity ---------------- */
  w.addPage(PORTRAIT)
  w.sectionHeading('validation', 'Validation, Reconciliation & Integrity')
  w.badges([{ label: `Report quality ${VALIDATION_LABEL[v.status]} · ${v.score}/100`, tone: qualityTone }])
  w.table(
    { title: 'Pre-export validation', columns: ['Check', 'Result', 'Detail'], rows: v.checks.map((c) => [c.check, VALIDATION_LABEL[c.status], c.detail]) },
    { widths: [30, 10, 60], emphasis: [{ column: 1, kind: 'status' }] },
  )
  w.table(
    {
      title: 'Reconciliation — dashboard vs exported',
      columns: ['Metric', 'Dashboard', 'Exported', 'Result'],
      rows: report.reconciliation.map((r) => [r.metric, r.dashboard, r.exported, r.matches ? 'MATCH' : 'REVIEW']),
    },
    { widths: [58, 14, 14, 14], emphasis: [{ column: 3, kind: 'status' }] },
  )
  w.subHeading('Evidence & provenance')
  w.bullets(document.provenance)
  if (w.cappedCells > 0) {
    w.callout('#D97706', 'Long cells shortened in this PDF', `${w.cappedCells} table cell(s) exceeded ${MAX_CELL_LINES} lines and were shortened here. The Excel and JSON exports carry every cell in full.`)
  }

  w.subHeading('Integrity seal')
  if (report.integrity) {
    const url = verificationUrl(report)
    w.ensure(150)
    const top = w.y
    if (url) w.qr(qrMatrix(url), 118, MARGIN + w.width - 118, top)
    const textW = w.width - (url ? 134 : 0)
    const lines: Array<[string, string, PDFFont]> = [
      ['Algorithm', report.integrity.algorithm, font],
      ['Digest', report.integrity.hash, mono],
      ['Signed at', utc(report.integrity.signedAt), font],
      ['Report ID', report.meta.reportId || '—', font],
      ['Verify at', url ? `${url.split('?')[0]}?token=...` : 'Verification URL unavailable', font],
    ]
    let ly = top
    for (const [label, value, face] of lines) {
      w.draw(label.toUpperCase(), MARGIN, ly - 8, 6.6, bold, MUTED)
      const valueLines = w.wrap(value, face === mono ? 7.6 : 8.8, face, textW)
      valueLines.forEach((line, i) => w.draw(line, MARGIN, ly - 19 - i * 10.5, face === mono ? 7.6 : 8.8, face, INK))
      ly -= 16 + valueLines.length * 10.5
    }
    w.y = Math.min(ly, top - 128) - 6
    w.paragraph('Scan the code or open the verification page: the SHA3-256 digest it decodes must equal the digest printed above. Any alteration of this document changes the digest.', { size: 8, hex: MUTED })
  } else {
    w.paragraph('This document was not sealed at generation time.', { size: 8.6, hex: MUTED })
  }
  w.paragraph(
    `Prepared by ${report.meta.generatedBy || 'QGuard Helix'}${branding.reportOwner ? ` for ${branding.reportOwner}` : ''}${branding.reviewer ? `; reviewer ${branding.reviewer}` : ''}. Generated ${utc(report.meta.generatedAt)} from evidence current to ${utc(report.meta.dataAsOf || null)}.`,
    { size: 8.6, hex: INK_SOFT },
  )

  /* ---------------- Contents (inserted after the cover) ---------------- */
  const toc = pdf.insertPage(1, PORTRAIT)
  toc.drawText('Contents', { x: MARGIN, y: PORTRAIT[1] - TOP_RESERVE - 20, size: 20, font: bold, color: color(INK) })
  toc.drawRectangle({ x: MARGIN, y: PORTRAIT[1] - TOP_RESERVE - 32, width: 36, height: 2.4, color: color(BRAND) })
  let ty = PORTRAIT[1] - TOP_RESERVE - 64
  const order = contentsEntries(document)
  order.forEach((entry, index) => {
    const found = w.toc.find((t) => t.id === entry.id)
    if (!found) return
    const pageNumber = found.pageIndex + 2 // +1 for the inserted contents page, +1 for 1-based numbering
    const label = san(`${index + 1}.  ${entry.title}`)
    toc.drawText(label, { x: MARGIN, y: ty, size: 11, font, color: color(INK) })
    const numberText = String(pageNumber)
    const numberW = font.widthOfTextAtSize(numberText, 11)
    const dotsStart = MARGIN + font.widthOfTextAtSize(label, 11) + 8
    const dotsEnd = PORTRAIT[0] - MARGIN - numberW - 8
    for (let x = dotsStart; x < dotsEnd; x += 5) toc.drawCircle({ x, y: ty + 3, size: 0.5, color: color('#94A3B8') })
    toc.drawText(numberText, { x: PORTRAIT[0] - MARGIN - numberW, y: ty, size: 11, font: bold, color: color(INK) })
    ty -= 24
  })
  toc.drawText(san(`${document.template.name} · ${document.template.audience}`), { x: MARGIN, y: ty - 16, size: 8.5, font, color: color(MUTED) })

  /* ---------------- Running header, footer, watermark ---------------- */
  const pages = pdf.getPages()
  pages.forEach((page, index) => {
    if (index === 0) return
    const { width, height } = page.getSize()
    page.drawText(classification, { x: width / 2 - 150, y: height / 2 - 60, size: 64, font: bold, color: color(INK), opacity: 0.035, rotate: degrees(-32) })
    page.drawText(san(branding.companyName), { x: MARGIN, y: height - 30, size: 8, font, color: color(MUTED) })
    page.drawText(classification, { x: width - MARGIN - font.widthOfTextAtSize(classification, 8), y: height - 30, size: 8, font, color: color(MUTED) })
    page.drawLine({ start: { x: MARGIN, y: height - 38 }, end: { x: width - MARGIN, y: height - 38 }, thickness: 0.4, color: color(LINE) })
    page.drawLine({ start: { x: MARGIN, y: 40 }, end: { x: width - MARGIN, y: 40 }, thickness: 0.4, color: color(LINE) })
    page.drawText(san(`${document.cover.title} · v${report.meta.version || '1.0'} · ${report.meta.reportId || ''}`), { x: MARGIN, y: 27, size: 7.6, font, color: color(MUTED) })
    const label = `Page ${index + 1} of ${pages.length}`
    page.drawText(label, { x: width - MARGIN - font.widthOfTextAtSize(label, 7.6), y: 27, size: 7.6, font, color: color(MUTED) })
  })

  const bytes = await pdf.save()
  return new Blob([bytes as unknown as BlobPart], { type: 'application/pdf' })
}
