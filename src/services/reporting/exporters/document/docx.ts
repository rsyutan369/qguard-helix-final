/**
 * Enterprise Word renderer for `ReportDocument` (docx).
 *
 * Narrative in portrait sections, wide registers in their own landscape
 * sections, a Contents list whose entries are live links to bookmarked headings,
 * and a running header/footer with "Page X of Y". Charts are native Word
 * content (glyph bars and a shaded part-to-whole table) so they stay editable
 * and print crisply; every value also appears as text beside its mark.
 */
import {
  AlignmentType,
  Bookmark,
  BorderStyle,
  Document,
  ExternalHyperlink,
  Footer,
  Header,
  HeadingLevel,
  HeightRule,
  ImageRun,
  InternalHyperlink,
  Packer,
  PageBreak,
  PageNumber,
  PageOrientation,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
  type ISectionOptions,
} from 'docx'
import type { DocumentExportInput } from './shared'
import { validationLabel } from './shared'
import type { ReportTable } from '../../schemas/ReportSchema'
import type { AssetDossier, BarItem, DocumentBlock, DocumentKpi, StackSegment, TableEmphasis } from '../../ReportDocument'
import { cellTone } from '../../ReportDocument'
import { qrPngDataUrl } from '../../ReportQr'
import {
  BRAND,
  INK,
  INK_SOFT,
  LINE,
  MUTED,
  VALIDATION_LABEL,
  contentsEntries,
  countLabel,
  dataUrlToBytes,
  fitBox,
  imageKind,
  imageSize,
  noHash,
  percentOf,
  tint,
  toneHex,
  utc,
  verificationUrl,
} from './shared'

type Child = Paragraph | Table

const run = (text: string, opts: { bold?: boolean; color?: string; size?: number; italics?: boolean; font?: string } = {}) =>
  new TextRun({ text, bold: opts.bold, italics: opts.italics, color: noHash(opts.color || INK_SOFT), size: opts.size ?? 20, font: opts.font })

const para = (text: string, opts: { color?: string; size?: number; bold?: boolean; after?: number } = {}) =>
  new Paragraph({ spacing: { after: opts.after ?? 120 }, children: [run(text, { color: opts.color, size: opts.size ?? 20, bold: opts.bold })] })

function heading(id: string, text: string): Paragraph {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 120, after: 160 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: noHash(BRAND), space: 4 } },
    children: [new Bookmark({ id, children: [new TextRun({ text, bold: true, color: noHash(INK), size: 34 })] })],
  })
}

const subHeading = (text: string) =>
  new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 220, after: 100 }, children: [new TextRun({ text, bold: true, color: noHash(INK), size: 22 })] })

const THIN = { style: BorderStyle.SINGLE, size: 1, color: noHash(LINE) } as const
const NONE = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' } as const

function kpiTable(items: DocumentKpi[]): Table {
  const perRow = 3
  const rows: TableRow[] = []
  for (let i = 0; i < items.length; i += perRow) {
    const slice = items.slice(i, i + perRow)
    while (slice.length < perRow) slice.push({ label: '', value: '' })
    rows.push(new TableRow({
      children: slice.map((kpi) => new TableCell({
        width: { size: 33, type: WidthType.PERCENTAGE },
        borders: { top: { style: BorderStyle.SINGLE, size: 18, color: noHash(toneHex(kpi.tone)) }, bottom: THIN, left: THIN, right: THIN },
        margins: { top: 100, bottom: 100, left: 140, right: 140 },
        children: kpi.label
          ? [
              new Paragraph({ children: [run(kpi.label.toUpperCase(), { bold: true, color: MUTED, size: 15 })] }),
              new Paragraph({ children: [run(kpi.value, { bold: true, color: INK, size: 34 })] }),
              ...(kpi.detail ? [new Paragraph({ children: [run(kpi.detail, { color: MUTED, size: 16 })] })] : []),
            ]
          : [new Paragraph('')],
      })),
    }))
  }
  return new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows })
}

/** Horizontal bars as glyph runs: the mark in the series colour, the value in ink. */
function barsBlock(block: { title: string; caption?: string; items: BarItem[]; unit?: string }): Child[] {
  const max = Math.max(1, ...block.items.map((i) => i.value))
  const SLOTS = 28
  const rows = block.items.map((item) => {
    const filled = item.value > 0 ? Math.max(1, Math.round((SLOTS * item.value) / max)) : 0
    return new TableRow({
      children: [
        new TableCell({ width: { size: 26, type: WidthType.PERCENTAGE }, borders: { top: NONE, bottom: NONE, left: NONE, right: NONE }, children: [new Paragraph({ children: [run(item.label, { color: INK, size: 19 })] })] }),
        new TableCell({
          width: { size: 54, type: WidthType.PERCENTAGE },
          borders: { top: NONE, bottom: NONE, left: NONE, right: NONE },
          children: [new Paragraph({ children: [run('█'.repeat(filled), { color: item.color, size: 19, font: 'Consolas' }), run('░'.repeat(SLOTS - filled), { color: '#E2E8F0', size: 19, font: 'Consolas' })] })],
        }),
        new TableCell({
          width: { size: 20, type: WidthType.PERCENTAGE },
          borders: { top: NONE, bottom: NONE, left: NONE, right: NONE },
          children: [new Paragraph({ children: [run(countLabel(item.value, block.unit), { bold: true, color: INK, size: 19 })] })],
        }),
      ],
    })
  })
  return [
    subHeading(block.title),
    new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows }),
    ...(block.caption ? [para(block.caption, { color: MUTED, size: 16 })] : []),
  ]
}

function stackedBlock(block: { title: string; caption?: string; segments: StackSegment[]; total: number }): Child[] {
  const total = block.total || block.segments.reduce((s, x) => s + x.value, 0)
  const visible = block.segments.filter((s) => s.value > 0)
  const bar = total && visible.length
    ? new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [new TableRow({
          height: { value: 320, rule: HeightRule.EXACT },
          children: visible.map((segment) => new TableCell({
            width: { size: Math.max(1, Math.round((segment.value / total) * 100)), type: WidthType.PERCENTAGE },
            shading: { type: ShadingType.CLEAR, fill: noHash(segment.color), color: 'auto' },
            borders: { top: NONE, bottom: NONE, left: { style: BorderStyle.SINGLE, size: 8, color: 'FFFFFF' }, right: { style: BorderStyle.SINGLE, size: 8, color: 'FFFFFF' } },
            children: [new Paragraph('')],
          })),
        })],
      })
    : para('No components measured.', { color: MUTED })
  const legend = new Paragraph({
    spacing: { before: 100, after: 60 },
    children: block.segments.flatMap((s, i) => [
      run(`${i ? '     ' : ''}■ `, { color: s.color, size: 20 }),
      run(`${s.label} `, { color: INK, size: 18 }),
      run(`${s.value.toLocaleString('en-US')} `, { color: INK, size: 18, bold: true }),
      run(`(${percentOf(s.value, total)})`, { color: MUTED, size: 18 }),
    ]),
  })
  return [subHeading(block.title), bar, legend, ...(block.caption ? [para(block.caption, { color: MUTED, size: 16 })] : [])]
}

function wordTable(t: ReportTable, opts: { emphasis?: TableEmphasis[]; widths?: number[]; compact?: boolean; showTitle?: boolean; note?: string } = {}): Child[] {
  const kinds = new Map((opts.emphasis || []).map((e) => [e.column, e.kind]))
  const size = opts.compact ? 14 : t.columns.length > 7 ? 15 : 17
  const widths = opts.widths && opts.widths.length === t.columns.length ? opts.widths : null
  const header = new TableRow({
    tableHeader: true,
    children: t.columns.map((column, i) => new TableCell({
      width: widths ? { size: widths[i], type: WidthType.PERCENTAGE } : undefined,
      shading: { type: ShadingType.CLEAR, fill: noHash(INK), color: 'auto' },
      margins: { top: 50, bottom: 50, left: 70, right: 70 },
      children: [new Paragraph({ children: [run(String(column), { bold: true, color: '#FFFFFF', size })] })],
    })),
  })
  const body = t.rows.length
    ? t.rows.map((row, rowIndex) => new TableRow({
        cantSplit: false,
        children: row.map((cell, i) => {
          const value = String(cell ?? '')
          const kind = kinds.get(i)
          const marked = Boolean(kind && value.trim() && value !== '—')
          return new TableCell({
            width: widths ? { size: widths[i], type: WidthType.PERCENTAGE } : undefined,
            shading: rowIndex % 2 === 1 ? { type: ShadingType.CLEAR, fill: 'F8FAFC', color: 'auto' } : undefined,
            margins: { top: 40, bottom: 40, left: 70, right: 70 },
            children: [new Paragraph({
              alignment: typeof cell === 'number' ? AlignmentType.RIGHT : AlignmentType.LEFT,
              children: marked
                ? [run('● ', { color: toneHex(cellTone(kind!, value)), size }), run(value, { bold: true, color: INK, size })]
                : [run(value, { color: INK_SOFT, size })],
            })],
          })
        }),
      }))
    : [new TableRow({ children: [new TableCell({ columnSpan: t.columns.length, children: [para('No rows.', { color: MUTED })] })] })]
  return [
    ...(opts.showTitle === false ? [] : [subHeading(`${t.title} (${t.rows.length.toLocaleString('en-US')} row${t.rows.length === 1 ? '' : 's'})`)]),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      borders: { top: THIN, bottom: THIN, left: THIN, right: THIN, insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: 'EDF2F7' }, insideVertical: { style: BorderStyle.SINGLE, size: 1, color: 'EDF2F7' } },
      rows: [header, ...body],
    }),
    ...(opts.note ? [para(opts.note, { color: MUTED, size: 16 })] : [new Paragraph({ spacing: { after: 80 }, children: [] })]),
  ]
}

function calloutBlock(tone: string, title: string, text: string): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [new TableRow({
      children: [new TableCell({
        shading: { type: ShadingType.CLEAR, fill: noHash(tint(tone, 0.9)), color: 'auto' },
        borders: { top: NONE, bottom: NONE, right: NONE, left: { style: BorderStyle.SINGLE, size: 24, color: noHash(tone) } },
        margins: { top: 100, bottom: 100, left: 180, right: 140 },
        children: [new Paragraph({ children: [run(title, { bold: true, color: INK, size: 20 })] }), new Paragraph({ children: [run(text, { color: INK_SOFT, size: 19 })] })],
      })],
    })],
  })
}

function factsTable(items: Array<{ label: string; value: string }>): Table {
  const rows: TableRow[] = []
  for (let i = 0; i < items.length; i += 2) {
    const pair = items.slice(i, i + 2)
    rows.push(new TableRow({
      children: pair.flatMap((fact) => [
        new TableCell({ width: { size: 18, type: WidthType.PERCENTAGE }, borders: { top: NONE, bottom: THIN, left: NONE, right: NONE }, children: [new Paragraph({ children: [run(fact.label.toUpperCase(), { bold: true, color: MUTED, size: 14 })] })] }),
        new TableCell({ width: { size: 32, type: WidthType.PERCENTAGE }, borders: { top: NONE, bottom: THIN, left: NONE, right: NONE }, children: [new Paragraph({ children: [run(fact.value, { color: INK, size: 18 })] })] }),
      ]).concat(pair.length === 1 ? [new TableCell({ columnSpan: 2, borders: { top: NONE, bottom: THIN, left: NONE, right: NONE }, children: [new Paragraph('')] })] : []),
    }))
  }
  return new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows })
}

function dossierBlock(d: AssetDossier): Child[] {
  return [
    new Paragraph({
      spacing: { before: 280, after: 40 },
      border: { left: { style: BorderStyle.SINGLE, size: 24, color: noHash(BRAND), space: 8 } },
      children: [run(d.title, { bold: true, color: INK, size: 26 })],
    }),
    new Paragraph({ spacing: { after: 80 }, children: [run(d.subtitle, { color: MUTED, size: 17 })] }),
    new Paragraph({ spacing: { after: 100 }, children: d.badges.flatMap((b, i) => [run(`${i ? '    ' : ''}● `, { color: toneHex(b.tone), size: 18 }), run(b.label, { bold: true, color: INK, size: 17 })]) }),
    factsTable(d.facts),
    para(d.summary, { color: INK, bold: true, size: 19 }),
    ...d.tables.flatMap((t) => wordTable(t.table, { emphasis: t.emphasis, widths: t.widths, compact: true, note: t.note })),
  ]
}

function blockChildren(block: DocumentBlock): Child[] {
  switch (block.type) {
    case 'paragraph':
      return [para(block.text, block.tone === 'muted' ? { color: MUTED, size: 18 } : block.tone === 'lead' ? { color: INK, size: 24, bold: true } : {})]
    case 'kpis':
      return [kpiTable(block.items), para('')]
    case 'bars':
      return barsBlock(block)
    case 'stacked':
      return stackedBlock(block)
    case 'table':
      return wordTable(block.table, { emphasis: block.emphasis, widths: block.wide ? undefined : block.widths, compact: block.wide, note: block.note })
    case 'callout':
      return [calloutBlock(toneHex(block.tone), block.title, block.text), para('')]
    case 'bullets':
      return block.items.map((item) => new Paragraph({ bullet: { level: 0 }, spacing: { after: 60 }, children: [run(item, { size: 19 })] }))
    case 'facts':
      return [factsTable(block.items), para('')]
    case 'dossier':
      return dossierBlock(block.dossier)
  }
}

export async function renderDocumentDocx(report: DocumentExportInput): Promise<Blob> {
  const d = report.document!
  const { branding } = d
  const v = d.validation
  const qualityHex = v.status === 'pass' ? '#16A34A' : v.status === 'warn' ? '#D97706' : '#DC2626'

  const headers = {
    default: new Header({
      children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [run(`${branding.companyName} · ${branding.classification || 'CONFIDENTIAL'}`, { color: MUTED, size: 16 })] })],
    }),
  }
  const footers = {
    default: new Footer({
      children: [new Paragraph({
        alignment: AlignmentType.RIGHT,
        children: [
          run(`${d.cover.title} · v${report.meta.version || '1.0'} · ${report.meta.reportId || ''} · Page `, { color: MUTED, size: 16 }),
          new TextRun({ children: [PageNumber.CURRENT], color: noHash(MUTED), size: 16 }),
          run(' of ', { color: MUTED, size: 16 }),
          new TextRun({ children: [PageNumber.TOTAL_PAGES], color: noHash(MUTED), size: 16 }),
        ],
      })],
    }),
  }

  /* ---- Cover ---- */
  const cover: Child[] = []
  const kind = imageKind(branding.companyLogo)
  if (kind && branding.companyLogo) {
    try {
      const bytes = dataUrlToBytes(branding.companyLogo)
      cover.push(new Paragraph({ spacing: { after: 240 }, children: [new ImageRun({ type: kind, data: bytes, transformation: fitBox(imageSize(bytes, kind), 180, 64) })] }))
    } catch {
      /* logo not embeddable */
    }
  }
  cover.push(
    new Paragraph({ spacing: { before: 600, after: 200 }, children: [new TextRun({ text: ` ${branding.classification || 'CONFIDENTIAL'} `, bold: true, color: 'FFFFFF', size: 17, shading: { type: ShadingType.CLEAR, fill: noHash(INK), color: 'auto' } })] }),
    new Paragraph({ spacing: { before: 400, after: 80 }, children: [run(d.cover.eyebrow.toUpperCase(), { bold: true, color: BRAND, size: 20 })] }),
    new Paragraph({ spacing: { after: 120 }, children: [run(d.cover.title, { bold: true, color: INK, size: 60 })] }),
    new Paragraph({ spacing: { after: 80 }, children: [run(d.cover.subtitle, { color: MUTED, size: 30 })] }),
    new Paragraph({ spacing: { after: 360 }, children: [run(d.cover.scopeLine, { color: INK_SOFT, size: 22 })] }),
    factsTable(d.cover.facts),
    new Paragraph({ spacing: { before: 360 }, children: [run('● ', { color: qualityHex, size: 20 }), run(validationLabel(v), { bold: true, color: INK, size: 19 })] }),
    ...(report.integrity ? [new Paragraph({ children: [run(`${report.integrity.algorithm} digest · ${report.integrity.hash.slice(0, 24)}… · full digest on the closing page`, { color: MUTED, size: 16 })] })] : []),
  )

  /* ---- Contents + summary + narrative sections ---- */
  const entries = contentsEntries(d)
  const intro: Child[] = [
    new Paragraph({ spacing: { after: 240 }, children: [run('Contents', { bold: true, color: INK, size: 40 })] }),
    ...entries.map((entry, index) => new Paragraph({
      spacing: { after: 100 },
      children: [new InternalHyperlink({ anchor: entry.id, children: [new TextRun({ text: `${index + 1}.  ${entry.title}`, color: noHash(BRAND), size: 22, underline: {} })] })],
    })),
    new Paragraph({ children: [new PageBreak()] }),
    heading('executive-summary', 'Executive Summary'),
    para(d.summary.headline, { color: INK, size: 25, bold: true }),
    kpiTable(d.summary.highlights),
    para(''),
    ...d.summary.paragraphs.map((p) => para(p)),
  ]

  /* Group sections into portrait / landscape runs so wide registers get a
     landscape page without turning the narrative sideways. */
  type Run = { orientation: 'portrait' | 'landscape'; children: Child[] }
  const runs: Run[] = [{ orientation: 'portrait', children: intro }]
  for (const section of d.sections) {
    const wide = section.blocks.some((b) => b.type === 'table' && b.wide)
    const orientation = wide ? 'landscape' : 'portrait'
    const content: Child[] = [heading(section.id, section.title), ...(section.intro ? [para(section.intro, { color: MUTED, size: 18 })] : []), ...section.blocks.flatMap(blockChildren)]
    const last = runs[runs.length - 1]
    if (last.orientation === orientation) {
      if (section.pageBreak) last.children.push(new Paragraph({ children: [new PageBreak()] }))
      last.children.push(...content)
    } else runs.push({ orientation, children: content })
  }

  const closing: Child[] = []
  if (d.decisions.length) {
    closing.push(
      heading('decisions', 'Executive Decision Register'),
      para('Decisions the evidence in this report requires, each with its rationale, evidence and accountable owner.', { color: MUTED, size: 18 }),
      ...wordTable(
        { title: 'Decisions required', columns: ['Priority', 'Decision', 'Rationale', 'Evidence', 'Owner'], rows: d.decisions.map((x) => [x.priority, x.decision, x.rationale, x.evidence, x.owner]) },
        { emphasis: [{ column: 0, kind: 'priority' }], widths: [9, 26, 27, 24, 14] },
      ),
      new Paragraph({ children: [new PageBreak()] }),
    )
  }
  closing.push(
    heading('validation', 'Validation, Reconciliation & Integrity'),
    new Paragraph({ spacing: { after: 120 }, children: [run('● ', { color: qualityHex, size: 22 }), run(validationLabel(v), { bold: true, color: INK, size: 22 })] }),
    ...(v.checks.length ? wordTable({ title: 'Pre-export validation', columns: ['Check', 'Result', 'Detail'], rows: v.checks.map((c) => [c.check, VALIDATION_LABEL[c.status], c.detail]) }, { emphasis: [{ column: 1, kind: 'status' }], widths: [30, 12, 58] }) : []),
    ...(report.reconciliation.length ? wordTable(
      { title: 'Reconciliation — dashboard vs exported', columns: ['Metric', 'Dashboard', 'Exported', 'Result'], rows: report.reconciliation.map((r) => [r.metric, r.dashboard, r.exported, r.matches ? 'MATCH' : 'REVIEW']) },
      { emphasis: [{ column: 3, kind: 'status' }], widths: [58, 14, 14, 14] },
    ) : []),
    ...(d.provenance.length ? [subHeading('Evidence & provenance')] : []),
    ...d.provenance.map((p) => new Paragraph({ bullet: { level: 0 }, spacing: { after: 60 }, children: [run(p, { size: 19 })] })),
  )
  if (report.integrity) {
    closing.push(subHeading('Integrity digest'), factsTable([
      { label: 'Algorithm', value: report.integrity.algorithm },
      { label: 'Recorded at', value: utc(report.integrity.signedAt) },
      { label: 'Report ID', value: report.meta.reportId || '—' },
      { label: 'Digest', value: report.integrity.hash },
    ]))
    const url = verificationUrl(report)
    if (url) {
      try {
        const qr = await qrPngDataUrl(url, 240)
        closing.push(new Paragraph({ spacing: { before: 160, after: 60 }, children: [new ImageRun({ type: 'png', data: dataUrlToBytes(qr), transformation: { width: 120, height: 120 } })] }))
      } catch {
        /* QR unavailable — the URL below still verifies */
      }
      closing.push(new Paragraph({ spacing: { after: 80 }, children: [new ExternalHyperlink({ link: url, children: [new TextRun({ text: url.split('?')[0], color: noHash(BRAND), underline: {}, size: 18 })] })] }))
    }
    closing.push(para('The digest identifies the captured report model. Compare it with the report record held by your organization.', { color: MUTED, size: 17 }))
  }
  closing.push(para(`Prepared by ${report.meta.generatedBy || 'QGuard Helix'}${branding.reportOwner ? ` for ${branding.reportOwner}` : ''}${branding.reviewer ? `; reviewer ${branding.reviewer}` : ''}. Generated ${utc(report.meta.generatedAt)}. Latest evidence timestamp: ${utc(report.meta.dataAsOf)}.`, { color: INK_SOFT, size: 18 }))
  runs.push({ orientation: 'portrait', children: closing })

  const sections: ISectionOptions[] = [
    { properties: { page: { size: { orientation: PageOrientation.PORTRAIT } } }, children: cover },
    ...runs.map((r) => ({
      properties: { page: { size: { orientation: r.orientation === 'landscape' ? PageOrientation.LANDSCAPE : PageOrientation.PORTRAIT } } },
      headers,
      footers,
      children: r.children,
    })),
  ]

  const doc = new Document({
    creator: branding.companyName,
    title: `${d.cover.title} — ${branding.companyName}`,
    description: `${d.cover.eyebrow} · ${d.cover.scopeLine}`,
    keywords: [report.meta.reportId || '', report.integrity?.hash || ''].filter(Boolean).join(' '),
    styles: { default: { document: { run: { font: 'Calibri' } } } },
    sections,
  })
  return Packer.toBlob(doc)
}
