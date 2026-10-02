/**
 * Enterprise PowerPoint renderer for `ReportDocument` (pptxgenjs).
 *
 * A deck is a summary format, so it paginates rather than shrinks: long tables
 * continue on "(continued)" slides, and per-asset slides are capped with the
 * remainder STATED on the slide (the Excel export carries everything). Charts
 * are native shapes drawn from the block values, so they are vector, editable
 * and exactly equal to the numbers printed beside them.
 */
import pptxgen from 'pptxgenjs'
import type { InventoryReport } from '../../InventoryReport'
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
const ROWS_PER_TABLE_SLIDE = 11
const MAX_ASSET_SLIDES = 30

function tableRows(t: ReportTable, emphasis: TableEmphasis[] = [], start = 0, count = t.rows.length): TableRows {
  const kinds = new Map(emphasis.map((e) => [e.column, e.kind]))
  const header: pptxgen.TableRow = t.columns.map((column) => ({
    text: String(column),
    options: { bold: true, color: 'FFFFFF', fill: { color: noHash(INK) }, fontSize: 9 },
  }))
  const body: TableRows = t.rows.slice(start, start + count).map((row, rowIndex) =>
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

export async function renderDocumentPptx(report: InventoryReport): Promise<Blob> {
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

  const barChart = (slide: Slide, block: { title: string; items: BarItem[]; unit?: string }, x: number, y: number, w: number) => {
    slide.addText(block.title, { x, y, w, h: 0.32, fontSize: 12, bold: true, color: noHash(INK) })
    const max = Math.max(1, ...block.items.map((i) => i.value))
    const labelW = 1.9
    const trackW = w - labelW - 1.3
    block.items.forEach((item, index) => {
      const ry = y + 0.45 + index * 0.4
      slide.addText(item.label, { x, y: ry, w: labelW, h: 0.3, fontSize: 10, color: noHash(INK) })
      slide.addShape(pptx.ShapeType.rect, { x: x + labelW, y: ry + 0.08, w: trackW, h: 0.16, fill: { color: 'EEF2F7' }, line: { color: 'EEF2F7' } })
      const fill = (trackW * item.value) / max
      if (item.value > 0) slide.addShape(pptx.ShapeType.roundRect, { x: x + labelW, y: ry + 0.08, w: Math.max(0.05, fill), h: 0.16, rectRadius: 0.05, fill: { color: noHash(item.color) }, line: { color: noHash(item.color) } })
      slide.addText(countLabel(item.value, block.unit), { x: x + labelW + Math.max(0, fill) + 0.08, y: ry, w: 1.3, h: 0.3, fontSize: 10, bold: true, color: noHash(INK) })
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
    const pages = Math.max(1, Math.ceil(t.rows.length / ROWS_PER_TABLE_SLIDE))
    for (let page = 0; page < pages; page += 1) {
      const slide = titled(page ? `${title} (continued)` : title, `${t.title} — ${t.rows.length.toLocaleString('en-US')} row${t.rows.length === 1 ? '' : 's'}${pages > 1 ? ` · page ${page + 1} of ${pages}` : ''}`)
      slide.addTable(tableRows(t, emphasis, page * ROWS_PER_TABLE_SLIDE, ROWS_PER_TABLE_SLIDE), {
        x: X0, y: 1.45, w: CONTENT_W, fontSize: 9, border: { type: 'solid', color: noHash(LINE), pt: 0.75 }, valign: 'middle', autoPage: false,
      })
      if (note && page === pages - 1) slide.addText(note, { x: X0, y: H - 0.85, w: CONTENT_W, h: 0.35, fontSize: 9, color: noHash(MUTED) })
    }
  }

  let assetSlides = 0
  let assetSlidesSkipped = 0
  for (const section of d.sections) {
    const charts = section.blocks.filter((b): b is Extract<DocumentBlock, { type: 'bars' | 'stacked' }> => b.type === 'bars' || b.type === 'stacked')
    if (charts.length) {
      const slide = titled(section.title, section.intro)
      let leftY = 1.5
      let rightY = 1.5
      charts.forEach((chart, index) => {
        const left = index % 2 === 0
        const x = left ? X0 : X0 + CONTENT_W / 2 + 0.2
        const w = CONTENT_W / 2 - 0.2
        const y = left ? leftY : rightY
        const next = chart.type === 'stacked' ? stackedChart(slide, chart, x, y, w) : barChart(slide, chart, x, y, w)
        if (left) leftY = next + 0.25
        else rightY = next + 0.25
      })
    }
    for (const block of section.blocks) {
      if (block.type === 'table') renderTableSlides(section.title, block.table, block.emphasis, block.note)
      else if (block.type === 'callout') {
        const slide = titled(section.title)
        slide.addText([{ text: `${block.title}\n`, options: { bold: true, fontSize: 16, color: noHash(INK) } }, { text: block.text, options: { fontSize: 13, color: noHash(INK_SOFT) } }], { x: X0, y: 1.5, w: CONTENT_W, h: 2, fill: { color: noHash(tint(toneHex(block.tone), 0.9)) }, valign: 'top', margin: 12 })
      } else if (block.type === 'dossier') {
        if (assetSlides >= MAX_ASSET_SLIDES) {
          assetSlidesSkipped += 1
          continue
        }
        assetSlides += 1
        const dossier = block.dossier
        const slide = titled(dossier.title, dossier.subtitle)
        slide.addText(dossier.badges.map((b) => `● ${b.label}`).join('    '), { x: X0, y: 1.42, w: CONTENT_W, h: 0.32, fontSize: 11, bold: true, color: noHash(INK) })
        slide.addText(dossier.summary, { x: X0, y: 1.78, w: CONTENT_W, h: 0.4, fontSize: 12, color: noHash(INK_SOFT), fit: 'shrink' })
        const main = dossier.tables[0]
        if (main) {
          const shown = Math.min(main.table.rows.length, 10)
          slide.addTable(tableRows(main.table, main.emphasis, 0, shown), { x: X0, y: 2.3, w: CONTENT_W, fontSize: 9, border: { type: 'solid', color: noHash(LINE), pt: 0.75 }, valign: 'middle', autoPage: false })
          if (main.table.rows.length > shown) slide.addText(`+${main.table.rows.length - shown} more row(s) for this asset in the PDF, Word and Excel exports.`, { x: X0, y: H - 0.85, w: CONTENT_W, h: 0.3, fontSize: 9, color: noHash(MUTED) })
        }
      }
    }
  }
  if (assetSlidesSkipped > 0) {
    const slide = titled('Additional Assets')
    slide.addText(`${assetSlidesSkipped} further asset dossier(s) are not rendered as slides — a deck is a summary format. Every asset is in the PDF, Word and Excel exports of this report.`, { x: X0, y: 1.5, w: CONTENT_W, h: 1.2, fontSize: 14, color: noHash(INK_SOFT) })
  }

  /* ---- Decisions ---- */
  if (d.decisions.length) {
    renderTableSlides(
      'Executive Decision Register',
      { title: 'Decisions required', columns: ['Priority', 'Decision', 'Rationale', 'Owner'], rows: d.decisions.map((x) => [x.priority, x.decision, x.rationale, x.owner]) },
      [{ column: 0, kind: 'priority' }],
    )
  }

  /* ---- Validation & integrity ---- */
  const v = d.validation
  const closing = titled('Validation, Reconciliation & Integrity', `Report quality ${VALIDATION_LABEL[v.status]} · ${v.score}/100`)
  closing.addTable(
    tableRows({ title: 'Validation', columns: ['Check', 'Result'], rows: v.checks.map((c) => [c.check, VALIDATION_LABEL[c.status]]) }, [{ column: 1, kind: 'status' }]),
    { x: X0, y: 1.45, w: 7.6, colW: [6.2, 1.4], fontSize: 9, border: { type: 'solid', color: noHash(LINE), pt: 0.75 }, valign: 'middle', autoPage: false },
  )
  const matches = report.reconciliation.filter((r) => r.matches).length
  closing.addText(`Reconciliation: ${matches} of ${report.reconciliation.length} dashboard-vs-export checks MATCH.`, { x: 8.5, y: 1.45, w: 4.3, h: 0.5, fontSize: 11, bold: true, color: noHash(INK) })
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
    closing.addText(`${report.integrity.algorithm}\n${report.integrity.hash}\nSigned ${utc(report.integrity.signedAt)}`, { x: 8.5, y: 4.15, w: 4.3, h: 1.2, fontSize: 9, color: noHash(INK_SOFT), fontFace: 'Consolas', valign: 'top' })
    if (url) closing.addText('Verify', { x: 8.5, y: 5.4, w: 4.3, h: 0.3, fontSize: 10, color: noHash(BRAND), hyperlink: { url } })
  }

  const blob = (await pptx.write({ outputType: 'blob' })) as Blob
  return blob
}
