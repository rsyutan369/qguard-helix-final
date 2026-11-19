/**
 * Enterprise PowerPoint renderer for `ReportDocument` (pptxgenjs).
 *
 * Long tables continue on new slides with repeated column headers.
 * Charts use native editable shapes and the same values as the registers.
 */
import pptxgen from 'pptxgenjs'
import type { DocumentExportInput } from './shared'
import { validationLabel } from './shared'
import type { ReportTable } from '../../schemas/ReportSchema'
import type { BarItem, DocumentBlock, DocumentKpi, StackSegment, TableEmphasis } from '../../ReportDocument'
import { cellTone } from '../../ReportDocument'
import { qrPngDataUrl } from '../../ReportQr'
import { BRAND, INK, INK_SOFT, LINE, MUTED, VALIDATION_LABEL, contentsEntries, countLabel, imageKind, noHash, percentOf, tint, toneHex, utc, verificationUrl } from './shared'

// pptxgenjs is CJS: the default import is the constructor under Vite but a
// { default } wrapper under Node ESM. Normalise, as PptExporter.ts does.
const PptxGenJS = (pptxgen as unknown as { default?: typeof pptxgen }).default ?? pptxgen

type Slide = pptxgen.Slide
type TableRows = pptxgen.TableRow[]

const W = 13.333
const H = 7.5
const X0 = 0.55
const CONTENT_W = W - X0 * 2
const BARS_PER_SLIDE = 11

function tableRows(t: ReportTable, emphasis: TableEmphasis[] = []): TableRows {
  const kinds = new Map(emphasis.map((e) => [e.column, e.kind]))
  const header: pptxgen.TableRow = t.columns.map((column) => ({
    text: String(column),
    options: { bold: true, color: 'FFFFFF', fill: { color: noHash(INK) }, fontSize: 9 },
  }))
  const body: TableRows = t.rows.map((row, rowIndex) =>
    row.map((cell, i) => {
      const value = String(cell ?? '')
      const kind = kinds.get(i)
      if (kind && value.trim() && value !== '—') {
        const hex = toneHex(cellTone(kind, value))
        return { text: value, options: { bold: true, color: noHash(INK), fill: { color: noHash(tint(hex, 0.82)) }, fontSize: 9 } }
      }
      return { text: value, options: { color: noHash(INK_SOFT), fontSize: 9, fill: rowIndex % 2 ? { color: 'F8FAFC' } : undefined } }
    }),
  )
  return [header, ...body]
}

export async function renderDocumentPptx(report: DocumentExportInput): Promise<Blob> {
  const d = report.document!
  const { branding } = d
  const pptx = new PptxGenJS()
  pptx.layout = 'LAYOUT_WIDE'
  pptx.author = branding.companyName
  pptx.company = branding.companyName
  pptx.title = d.cover.title
  pptx.subject = `${d.cover.eyebrow} · ${d.cover.scopeLine}`
  let slideNo = 0

  const chrome = (slide: Slide) => {
    slideNo += 1
    slide.background = { color: 'FFFFFF' }
    slide.addShape(pptx.ShapeType.rect, { x: 0, y: 0, w: 0.12, h: H, fill: { color: noHash(BRAND) }, line: { color: noHash(BRAND) } })
    slide.addText(`${branding.companyName} · ${branding.classification || 'CONFIDENTIAL'} · ${report.meta.reportId || ''}`, { x: X0, y: H - 0.42, w: 9, h: 0.3, fontSize: 9, color: noHash(MUTED) })
    slide.addText(String(slideNo), { x: W - 1.2, y: H - 0.42, w: 0.7, h: 0.3, fontSize: 9, color: noHash(MUTED), align: 'right' })
  }
  const titled = (title: string, subtitle?: string): Slide => {
    const slide = pptx.addSlide()
    chrome(slide)
    slide.addText(title, { x: X0, y: 0.32, w: CONTENT_W, h: 0.6, fontSize: 24, bold: true, color: noHash(INK) })
    slide.addShape(pptx.ShapeType.rect, { x: X0, y: 0.92, w: 0.55, h: 0.05, fill: { color: noHash(BRAND) }, line: { color: noHash(BRAND) } })
    if (subtitle) slide.addText(subtitle, { x: X0, y: 1.0, w: CONTENT_W, h: 0.4, fontSize: 12, color: noHash(MUTED) })
    return slide
  }

  const kpiTiles = (slide: Slide, items: DocumentKpi[], y: number) => {
    const perRow = 3
    const gap = 0.2
    const tileW = (CONTENT_W - gap * (perRow - 1)) / perRow
    items.forEach((kpi, index) => {
      const x = X0 + (index % perRow) * (tileW + gap)
      const ty = y + Math.floor(index / perRow) * 1.25
      slide.addShape(pptx.ShapeType.rect, { x, y: ty, w: tileW, h: 1.1, fill: { color: 'FFFFFF' }, line: { color: noHash(LINE), width: 1 } })
      slide.addShape(pptx.ShapeType.rect, { x, y: ty, w: tileW, h: 0.06, fill: { color: noHash(toneHex(kpi.tone)) }, line: { color: noHash(toneHex(kpi.tone)) } })
      slide.addText(kpi.label.toUpperCase(), { x: x + 0.15, y: ty + 0.12, w: tileW - 0.3, h: 0.28, fontSize: 9, bold: true, color: noHash(MUTED) })
      slide.addText(kpi.value, { x: x + 0.15, y: ty + 0.36, w: tileW - 0.3, h: 0.45, fontSize: 24, bold: true, color: noHash(INK), fit: 'shrink' })
      if (kpi.detail) slide.addText(kpi.detail, { x: x + 0.15, y: ty + 0.78, w: tileW - 0.3, h: 0.26, fontSize: 9.5, color: noHash(MUTED) })
    })
  }

  const barChart = (slide: Slide, block: { title: string; items: BarItem[]; unit?: string }, x: number, y: number, w: number, max: number) => {
    slide.addText(block.title, { x, y, w, h: 0.32, fontSize: 12, bold: true, color: noHash(INK) })
    const labelW = 1.9
    const trackW = w - labelW - 1.3
    block.items.forEach((item, index) => {
      const ry = y + 0.45 + index * 0.4
      slide.addText(item.label, { x, y: ry, w: labelW, h: 0.3, fontSize: 10, color: noHash(INK) })
      slide.addShape(pptx.ShapeType.rect, { x: x + labelW, y: ry + 0.08, w: trackW, h: 0.16, fill: { color: 'EEF2F7' }, line: { color: 'EEF2F7' } })
      const fill = (trackW * item.value) / max
      if (item.value > 0) slide.addShape(pptx.ShapeType.roundRect, { x: x + labelW, y: ry + 0.08, w: Math.max(0.05, fill), h: 0.16, rectRadius: 0.05, fill: { color: noHash(item.color) }, line: { color: noHash(item.color) } })
      slide.addText(countLabel(item.value, block.unit), { x: x + labelW + trackW + 0.08, y: ry, w: 1.3, h: 0.3, fontSize: 10, bold: true, color: noHash(INK) })
    })
    return y + 0.45 + block.items.length * 0.4
  }

  const stackedChart = (slide: Slide, block: { title: string; segments: StackSegment[]; total: number }, x: number, y: number, w: number) => {
    slide.addText(block.title, { x, y, w, h: 0.32, fontSize: 12, bold: true, color: noHash(INK) })
    const total = block.total || block.segments.reduce((s, v) => s + v.value, 0)
    const visible = block.segments.filter((s) => s.value > 0)
    let cx = x
    const gap = 0.03
    const available = w - gap * Math.max(0, visible.length - 1)
    for (const segment of visible) {
      const sw = total ? (available * segment.value) / total : 0
      slide.addShape(pptx.ShapeType.rect, { x: cx, y: y + 0.42, w: sw, h: 0.32, fill: { color: noHash(segment.color) }, line: { color: noHash(segment.color) } })
      cx += sw + gap
    }
    const legend = block.segments.map((s) => `■ ${s.label} ${s.value.toLocaleString('en-US')} (${percentOf(s.value, total)})`).join('     ')
    slide.addText(legend, { x, y: y + 0.82, w, h: 0.32, fontSize: 10, color: noHash(INK) })
    return y + 1.2
  }

  /* ---- Cover ---- */
  const cover = pptx.addSlide()
  chrome(cover)
  const logoKind = imageKind(branding.companyLogo)
  if (logoKind && branding.companyLogo) {
    try {
      cover.addImage({ data: branding.companyLogo, x: X0, y: 0.5, w: 2.4, h: 0.9, sizing: { type: 'contain', w: 2.4, h: 0.9 } })
    } catch {
      /* logo not embeddable */
    }
  }
  cover.addText(branding.classification || 'CONFIDENTIAL', { x: X0, y: 1.6, w: 2.6, h: 0.36, fontSize: 11, bold: true, color: 'FFFFFF', fill: { color: noHash(INK) }, align: 'center' })
  cover.addText(d.cover.eyebrow.toUpperCase(), { x: X0, y: 2.25, w: CONTENT_W, h: 0.4, fontSize: 13, bold: true, color: noHash(BRAND), charSpacing: 2 })
  cover.addText(d.cover.title, { x: X0, y: 2.65, w: CONTENT_W, h: 1.1, fontSize: 40, bold: true, color: noHash(INK), fit: 'shrink' })
  cover.addText(d.cover.subtitle, { x: X0, y: 3.75, w: CONTENT_W, h: 0.5, fontSize: 20, color: noHash(MUTED) })
  cover.addText(d.cover.scopeLine, { x: X0, y: 4.3, w: CONTENT_W, h: 0.4, fontSize: 14, color: noHash(INK_SOFT) })
  const facts = d.cover.facts.map((f) => `${f.label}: ${f.value}`)
  cover.addText(facts.slice(0, 4).join('\n'), { x: X0, y: 4.95, w: 6, h: 1.4, fontSize: 11, color: noHash(INK_SOFT), valign: 'top' })
  cover.addText(facts.slice(4).join('\n'), { x: X0 + 6.2, y: 4.95, w: 6, h: 1.4, fontSize: 11, color: noHash(INK_SOFT), valign: 'top' })

  /* ---- Contents ---- */
  const contents = titled('Contents')
  contents.addText(contentsEntries(d).map((e, i) => `${i + 1}.  ${e.title}`).join('\n'), { x: X0, y: 1.3, w: CONTENT_W, h: 5, fontSize: 16, color: noHash(INK), valign: 'top', paraSpaceAfter: 8 })

  /* ---- Executive summary ---- */
  const summary = titled('Executive Summary', d.template.audience)
  summary.addText(d.summary.headline, { x: X0, y: 1.4, w: CONTENT_W, h: 0.8, fontSize: 16, bold: true, color: noHash(INK), fit: 'shrink' })
  kpiTiles(summary, d.summary.highlights, 2.35)
  const narrative = titled('Executive Summary — Narrative')
  narrative.addText(d.summary.paragraphs.map((p) => ({ text: p, options: { bullet: true, paraSpaceAfter: 8 } })), { x: X0, y: 1.2, w: CONTENT_W, h: 5.6, fontSize: 13, color: noHash(INK_SOFT), valign: 'top', fit: 'shrink' })

  /* ---- Sections ---- */
  const renderTableSlides = (title: string, t: ReportTable, emphasis?: TableEmphasis[], note?: string) => {
    const subtitle = `${t.title} · ${t.rows.length.toLocaleString('en-US')} row${t.rows.length === 1 ? '' : 's'}`
    if (!t.columns.length || !t.rows.length) {
      titled(title, subtitle).addText(note || 'No records in this snapshot.', { x: X0, y: 1.45, w: CONTENT_W, h: 1, fontSize: 12, valign: 'top' })
      return
    }
    const width = Math.max(8, Math.floor((CONTENT_W * 11) / t.columns.length))
    const wrap = (value: string | number) => String(value ?? '').split('\n')
      .flatMap((line) => line.match(new RegExp(`.{1,${width}}`, 'gu')) || [''])
    const maxLines = 22
    let page: ReportTable['rows'] = []
    let used = 0
    let pageNumber = 0
    const flush = () => {
      if (!page.length) return
      const slide = titled(pageNumber++ ? `${title} (continued)` : title, subtitle)
      slide.addTable(tableRows({ ...t, rows: page }, emphasis), {
        x: X0, y: 1.45, w: CONTENT_W, fontSize: 9, border: { type: 'solid', color: noHash(LINE), pt: 0.75 },
        valign: 'top', margin: 3, autoPage: false,
      })
      page = []
      used = 0
    }
    for (const row of t.rows) {
      const cells = row.map(wrap)
      const lines = Math.max(1, ...cells.map((cell) => cell.length))
      for (let offset = 0; offset < lines; offset += maxLines - 2) {
        const size = Math.min(maxLines - 2, lines - offset) + 1
        if (used + size > maxLines) flush()
        page.push(cells.map((cell, column) => lines === 1 ? row[column] : cell.slice(offset, offset + maxLines - 2).join('\n')))
        used += size
      }
    }
    flush()
    if (note) {
      const noteSlide = titled(title, 'Register notes')
      noteSlide.addText(note, { x: X0, y: 1.5, w: CONTENT_W, h: 4.8, fontSize: 14, color: noHash(INK_SOFT), valign: 'top', fit: 'shrink' })
    }
  }

  for (const section of d.sections) {
    for (const block of section.blocks) {
      if (block.type === 'table') renderTableSlides(section.title, block.table, block.emphasis, block.note)
      else if (block.type === 'bars') {
        const max = block.items.reduce((largest, item) => Math.max(largest, item.value), 1)
        for (let start = 0; start < block.items.length; start += BARS_PER_SLIDE) {
          const slide = titled(section.title, block.caption)
          const chart = { ...block, items: block.items.slice(start, start + BARS_PER_SLIDE) }
          barChart(slide, chart, X0, 1.5, CONTENT_W, max)
        }
      } else if (block.type === 'stacked') {
        stackedChart(titled(section.title, block.caption), block, X0, 1.5, CONTENT_W)
      } else if (block.type === 'facts') {
        renderTableSlides(section.title, { title: 'Details', columns: ['Field', 'Value'], rows: block.items.map(({ label, value }) => [label, value]) })
      } else if (block.type === 'kpis') {
        for (let start = 0; start < block.items.length; start += 12) {
          kpiTiles(titled(section.title), block.items.slice(start, start + 12), 1.5)
        }
      } else if (block.type === 'bullets' || block.type === 'paragraph') {
        renderTableSlides(section.title, { title: 'Notes', columns: ['Detail'], rows: (block.type === 'bullets' ? block.items : [block.text]).map((line) => [line]) })
      }
      else if (block.type === 'callout') {
        const slide = titled(section.title)
        slide.addText([{ text: `${block.title}\n`, options: { bold: true, fontSize: 16, color: noHash(INK) } }, { text: block.text, options: { fontSize: 13, color: noHash(INK_SOFT) } }], { x: X0, y: 1.5, w: CONTENT_W, h: 2, fill: { color: noHash(tint(toneHex(block.tone), 0.9)) }, valign: 'top', margin: 12 })
      } else if (block.type === 'dossier') {
        const dossier = block.dossier
        const slide = titled(dossier.title, dossier.subtitle)
        slide.addText(dossier.badges.map((b) => `● ${b.label}`).join('    '), { x: X0, y: 1.42, w: CONTENT_W, h: 0.32, fontSize: 11, bold: true, color: noHash(INK) })
        slide.addText(dossier.summary, { x: X0, y: 1.78, w: CONTENT_W, h: 0.4, fontSize: 12, color: noHash(INK_SOFT), fit: 'shrink' })
        renderTableSlides(dossier.title, { title: 'Asset details', columns: ['Field', 'Value'], rows: dossier.facts.map(({ label, value }) => [label, value]) })
        for (const detail of dossier.tables) renderTableSlides(dossier.title, detail.table, detail.emphasis, detail.note)
      }
    }
  }

  /* ---- Decisions ---- */
  if (d.decisions.length) {
    renderTableSlides(
      'Executive Decision Register',
      { title: 'Decisions required', columns: ['Priority', 'Decision', 'Rationale', 'Evidence', 'Owner'], rows: d.decisions.map((x) => [x.priority, x.decision, x.rationale, x.evidence, x.owner]) },
      [{ column: 0, kind: 'priority' }],
    )
  }

  /* ---- Validation & integrity ---- */
  const v = d.validation
  const closing = titled('Validation, Reconciliation & Integrity', validationLabel(v))
  if (report.integrity) {
    const url = verificationUrl(report)
    if (url) {
      try {
        const qr = await qrPngDataUrl(url, 240)
        closing.addImage({ data: qr, x: 8.5, y: 2.1, w: 1.9, h: 1.9 })
      } catch {
        /* QR unavailable — the digest below still verifies */
      }
    }
    closing.addText(`${report.integrity.algorithm} digest\n${report.integrity.hash}\nRecorded ${utc(report.integrity.signedAt)}`, { x: X0, y: 1.55, w: 7.8, h: 1.2, fontSize: 11, color: noHash(INK_SOFT), fontFace: 'Consolas', valign: 'top' })
    if (url) closing.addText('Digest reference', { x: 8.5, y: 5.4, w: 4.3, h: 0.3, fontSize: 10, color: noHash(BRAND), hyperlink: { url } })
  }
  if (v.checks.length) renderTableSlides('Validation checks', { title: 'Validation', columns: ['Check', 'Result', 'Detail'], rows: v.checks.map((c) => [c.check, VALIDATION_LABEL[c.status], c.detail]) }, [{ column: 1, kind: 'status' }])
  if (report.reconciliation.length) renderTableSlides('Reconciliation', { title: 'Dashboard vs exported', columns: ['Metric', 'Dashboard', 'Exported', 'Result'], rows: report.reconciliation.map((r) => [r.metric, r.dashboard, r.exported, r.matches ? 'MATCH' : 'REVIEW']) }, [{ column: 3, kind: 'status' }])
  if (d.provenance.length) renderTableSlides('Evidence & provenance', { title: 'Sources', columns: ['Source'], rows: d.provenance.map((line) => [line]) })

  const blob = (await pptx.write({ outputType: 'blob' })) as Blob
  return blob
}
