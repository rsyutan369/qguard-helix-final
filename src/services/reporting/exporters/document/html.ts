/**
 * Enterprise HTML renderer for `ReportDocument` — one self-contained file with
 * no external requests: inline CSS, inline SVG charts, inline SVG QR code.
 *
 * Every evidence-derived string is HTML-escaped (asset names and evidence come
 * from scanned input). Charts are drawn from the block values and each carries
 * an accessible label plus the same numbers in text, so no value is colour-only
 * or tooltip-only.
 */
import type { DocumentExportInput } from './shared'
import { validationLabel } from './shared'
import type { ReportTable } from '../../schemas/ReportSchema'
import type { AssetDossier, BarItem, DocumentBlock, DocumentKpi, StackSegment, TableEmphasis } from '../../ReportDocument'
import { cellTone } from '../../ReportDocument'
import { qrSvg } from '../../ReportQr'
import { BRAND, VALIDATION_LABEL, contentsEntries, countLabel, percentOf, tint, toneHex, utc, verificationUrl } from './shared'

function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** Only data:image/png|jpeg URLs are rendered — never a remote or script URL. */
function safeImage(dataUrl: string | null | undefined): string | null {
  return dataUrl && /^data:image\/(png|jpe?g|webp|gif);base64,[a-z0-9+/=\s]+$/i.test(dataUrl) ? dataUrl : null
}

function pill(label: string, hex: string): string {
  return `<span class="pill" style="--tone:${hex};--wash:${tint(hex, 0.88)}"><i></i>${esc(label)}</span>`
}

function kpis(items: DocumentKpi[]): string {
  return `<div class="kpis">${items
    .map((k) => `<div class="kpi" style="--tone:${toneHex(k.tone)}"><div class="kpi-l">${esc(k.label)}</div><div class="kpi-v">${esc(k.value)}</div>${k.detail ? `<div class="kpi-d">${esc(k.detail)}</div>` : ''}</div>`)
    .join('')}</div>`
}

function bars(block: { title: string; caption?: string; items: BarItem[]; unit?: string }): string {
  const max = Math.max(1, ...block.items.map((i) => i.value))
  const rowH = 30
  const labelW = 190
  const plotW = 520
  const height = block.items.length * rowH + 8
  const summary = block.items.map((i) => `${i.label}: ${i.value}`).join(', ')
  const rows = block.items
    .map((item, index) => {
      const y = index * rowH + 8
      const w = Math.max(0, (plotW * item.value) / max)
      const valueText = `${countLabel(item.value, block.unit)}${item.detail ? ` · ${item.detail}` : ''}`
      const bar = item.value > 0
        ? `<path d="M${labelW},${y} h${Math.max(0, w - 4)} a4,4 0 0 1 4,4 v${12 - 8} a4,4 0 0 1 -4,4 h-${Math.max(0, w - 4)} z" fill="${item.color}"><title>${esc(`${item.label}: ${valueText}`)}</title></path>`
        : ''
      return `<g><text x="0" y="${y + 10}" class="svg-label">${esc(item.label)}</text><rect x="${labelW}" y="${y}" width="${plotW}" height="12" rx="2" class="svg-track"/>${bar}<text x="${labelW + Math.max(w, 0) + 8}" y="${y + 10}" class="svg-value">${esc(valueText)}</text></g>`
    })
    .join('')
  return `<figure class="chart"><figcaption class="chart-t">${esc(block.title)}</figcaption><svg viewBox="0 0 ${labelW + plotW + 200} ${height}" role="img" aria-label="${esc(`${block.title}. ${summary}`)}" preserveAspectRatio="xMinYMin meet">${rows}</svg>${block.caption ? `<p class="caption">${esc(block.caption)}</p>` : ''}</figure>`
}

function stacked(block: { title: string; caption?: string; segments: StackSegment[]; total: number; unit?: string }): string {
  const total = block.total || block.segments.reduce((s, x) => s + x.value, 0)
  const visible = block.segments.filter((s) => s.value > 0)
  const W = 900
  const H = 22
  const gap = 2
  const available = W - gap * Math.max(0, visible.length - 1)
  let x = 0
  const rects = total
    ? visible
        .map((segment) => {
          const w = (available * segment.value) / total
          const out = `<rect x="${x}" y="0" width="${w}" height="${H}" fill="${segment.color}"><title>${esc(`${segment.label}: ${segment.value} (${percentOf(segment.value, total)})`)}</title></rect>`
          x += w + gap
          return out
        })
        .join('')
    : `<rect x="0" y="0" width="${W}" height="${H}" class="svg-track"/>`
  const legend = block.segments
    .map((s) => `<li><span class="sw" style="background:${s.color}"></span>${esc(s.label)} <b>${s.value.toLocaleString('en-US')}</b> <em>${percentOf(s.value, total)}</em></li>`)
    .join('')
  const summary = block.segments.map((s) => `${s.label} ${s.value}`).join(', ')
  return `<figure class="chart"><figcaption class="chart-t">${esc(block.title)}</figcaption><svg viewBox="0 0 ${W} ${H}" class="stack" role="img" aria-label="${esc(`${block.title}. ${summary} of ${total}`)}" preserveAspectRatio="none">${rects}</svg><ul class="legend">${legend}</ul>${block.caption ? `<p class="caption">${esc(block.caption)}</p>` : ''}</figure>`
}

function table(t: ReportTable, emphasis: TableEmphasis[] = [], note?: string, wide = false): string {
  const kinds = new Map(emphasis.map((e) => [e.column, e.kind]))
  const body = t.rows.length
    ? t.rows
        .map((row) => `<tr>${row.map((cell, i) => {
          const kind = kinds.get(i)
          const value = String(cell ?? '')
          if (kind && value.trim() && value !== '—') return `<td>${pill(value, toneHex(cellTone(kind, value)))}</td>`
          return `<td${typeof cell === 'number' ? ' class="num"' : ''}>${esc(value)}</td>`
        }).join('')}</tr>`)
        .join('')
    : `<tr><td colspan="${t.columns.length}" class="empty">No rows.</td></tr>`
  return `<div class="tbl${wide ? ' wide' : ''}"><div class="tbl-t">${esc(t.title)} <span>${t.rows.length.toLocaleString('en-US')} row${t.rows.length === 1 ? '' : 's'}</span></div><div class="scroll"><table><thead><tr>${t.columns.map((c) => `<th scope="col">${esc(c)}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table></div>${note ? `<p class="caption">${esc(note)}</p>` : ''}</div>`
}

function dossier(d: AssetDossier): string {
  return `<article class="dossier" id="asset-${esc(d.id)}"><header><h3>${esc(d.title)}</h3><p>${esc(d.subtitle)}</p><div class="badges">${d.badges.map((b) => pill(b.label, toneHex(b.tone))).join('')}</div></header><dl class="facts">${d.facts.map((f) => `<div><dt>${esc(f.label)}</dt><dd>${esc(f.value)}</dd></div>`).join('')}</dl><p class="dossier-s">${esc(d.summary)}</p>${d.tables.map((t) => table(t.table, t.emphasis, t.note)).join('')}</article>`
}

function block(b: DocumentBlock): string {
  switch (b.type) {
    case 'paragraph':
      return `<p class="${b.tone === 'muted' ? 'muted' : b.tone === 'lead' ? 'lead' : ''}">${esc(b.text)}</p>`
    case 'kpis':
      return kpis(b.items)
    case 'bars':
      return bars(b)
    case 'stacked':
      return stacked(b)
    case 'table':
      return table(b.table, b.emphasis, b.note, b.wide)
    case 'callout':
      return `<aside class="callout" style="--tone:${toneHex(b.tone)};--wash:${tint(toneHex(b.tone), 0.92)}"><b>${esc(b.title)}</b><p>${esc(b.text)}</p></aside>`
    case 'bullets':
      return `<ul class="bullets">${b.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>`
    case 'facts':
      return `<dl class="facts">${b.items.map((f) => `<div><dt>${esc(f.label)}</dt><dd>${esc(f.value)}</dd></div>`).join('')}</dl>`
    case 'dossier':
      return dossier(b.dossier)
  }
}

export function renderDocumentHtml(report: DocumentExportInput): Blob {
  const d = report.document!
  const { branding } = d
  const logo = safeImage(branding.companyLogo)
  const v = d.validation
  const qualityHex = v.status === 'pass' ? '#16A34A' : v.status === 'warn' ? '#D97706' : '#DC2626'
  const url = verificationUrl(report)
  const entries = contentsEntries(d)

  const sections = d.sections
    .map((s) => `<section id="${esc(s.id)}" class="${s.pageBreak ? 'break' : ''}"><h2>${esc(s.title)}</h2>${s.intro ? `<p class="muted">${esc(s.intro)}</p>` : ''}${s.blocks.map(block).join('')}</section>`)
    .join('')

  const decisions = d.decisions.length
    ? `<section id="decisions" class="break"><h2>Executive Decision Register</h2><p class="muted">Decisions the evidence in this report requires, each with its rationale, evidence and accountable owner.</p>${table(
        { title: 'Decisions required', columns: ['Priority', 'Decision', 'Rationale', 'Evidence', 'Owner'], rows: d.decisions.map((x) => [x.priority, x.decision, x.rationale, x.evidence, x.owner]) },
        [{ column: 0, kind: 'priority' }],
      )}</section>`
    : ''

  const integrity = report.integrity
    ? `<div class="seal">${url ? `<div class="qr">${qrSvg(url, 148)}</div>` : ''}<dl class="facts one"><div><dt>Algorithm</dt><dd>${esc(report.integrity.algorithm)}</dd></div><div><dt>Digest</dt><dd class="mono">${esc(report.integrity.hash)}</dd></div><div><dt>Recorded at</dt><dd>${esc(utc(report.integrity.signedAt))}</dd></div><div><dt>Report ID</dt><dd>${esc(report.meta.reportId || '—')}</dd></div>${url ? `<div><dt>Digest reference</dt><dd><a href="${esc(url)}" rel="noopener noreferrer">${esc(url.split('?')[0])}</a></dd></div>` : ''}</dl></div><p class="muted">The digest identifies the captured report model. Compare it with the report record held by your organization.</p>`
    : ''

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(d.cover.title)} — ${esc(branding.companyName)}</title>
<meta name="generator" content="QGuard Helix Enterprise Reporting">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<style>
:root{--ink:#0F172A;--soft:#334155;--muted:#64748B;--line:#E2E8F0;--band:#F8FAFC;--brand:${BRAND}}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:#F1F5F9;color:var(--ink);font:14px/1.55 Inter,"Segoe UI",system-ui,-apple-system,Arial,sans-serif}
.cover{background:#fff;border-left:10px solid var(--brand);min-height:min(92vh,760px);padding:56px clamp(20px,6vw,88px);display:flex;flex-direction:column;justify-content:center;gap:10px;border-bottom:3px solid var(--brand)}
.cover .logo{max-height:64px;max-width:260px;width:auto;height:auto;object-fit:contain;align-self:flex-start;margin-bottom:18px}
.cls{align-self:flex-start;background:var(--ink);color:#fff;font-size:11px;font-weight:800;letter-spacing:.14em;padding:4px 10px;border-radius:4px}
.eyebrow{color:var(--brand);font-weight:800;font-size:12px;letter-spacing:.16em;text-transform:uppercase;margin-top:28px}
.cover h1{font-size:clamp(28px,4.4vw,44px);line-height:1.1;margin:4px 0 6px;letter-spacing:-.02em}
.cover .sub{color:var(--muted);font-size:18px}
.cover .scope{color:var(--soft);font-size:15px}
.cover .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px 28px;margin-top:26px;padding-top:22px;border-top:1px solid var(--line)}
.cover .meta dt{font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.cover .meta dd{margin:2px 0 0;font-size:14px;word-break:break-word}
.cover .quality{margin-top:24px}
.shell{display:grid;grid-template-columns:minmax(0,1fr);max-width:1180px;margin:0 auto;padding:0 16px}
@media(min-width:1100px){.shell{grid-template-columns:230px minmax(0,1fr);gap:28px}}
nav.toc{display:none}
@media(min-width:1100px){nav.toc{display:block;position:sticky;top:18px;align-self:start;margin-top:28px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px}}
nav.toc b{display:block;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:8px}
nav.toc ol{margin:0;padding-left:18px}nav.toc li{margin:5px 0;font-size:13px}nav.toc a{color:var(--soft);text-decoration:none}nav.toc a:hover{color:var(--brand)}
main{min-width:0}
section{background:#fff;border:1px solid var(--line);border-radius:12px;padding:26px clamp(16px,3vw,34px);margin:28px 0}
h2{font-size:22px;margin:0 0 14px;letter-spacing:-.01em;padding-bottom:10px;border-bottom:1px solid var(--line);position:relative}
h2::after{content:"";position:absolute;left:0;bottom:-1px;width:44px;height:3px;background:var(--brand)}
h3{font-size:16px;margin:0}
p{margin:10px 0;color:var(--soft)}
p.lead{font-size:17px;font-weight:700;color:var(--ink)}
.muted{color:var(--muted);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}
.kpi{border:1px solid var(--line);border-top:3px solid var(--tone);border-radius:8px;padding:12px 14px;background:#fff}
.kpi-l{font-size:10.5px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.kpi-v{font-size:26px;font-weight:800;margin-top:2px}
.kpi-d{font-size:12px;color:var(--muted)}
.chart{margin:18px 0;padding:14px 16px;border:1px solid var(--line);border-radius:10px;background:var(--band)}
.chart-t{font-size:13px;font-weight:800;color:var(--ink);margin-bottom:10px}
.chart svg{width:100%;height:auto;display:block}
.chart svg.stack{height:22px;border-radius:6px;overflow:hidden}
.svg-label{font-size:13px;fill:var(--ink)}.svg-value{font-size:12.5px;font-weight:700;fill:var(--ink)}.svg-track{fill:#E8EDF4}
.legend{list-style:none;display:flex;flex-wrap:wrap;gap:8px 22px;margin:10px 0 0;padding:0;font-size:13px;color:var(--ink)}
.legend .sw{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.legend em{color:var(--muted);font-style:normal}
.caption{font-size:12px;color:var(--muted);margin:8px 0 0}
.tbl{margin:18px 0}.tbl-t{font-size:13px;font-weight:800;margin-bottom:8px}.tbl-t span{font-weight:600;color:var(--muted);font-size:12px;margin-left:6px}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:#fff}
table{border-collapse:collapse;width:100%;font-size:12.5px}
.wide table{font-size:12px}
th{background:var(--ink);color:#fff;text-align:left;padding:8px 10px;font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;position:sticky;top:0;white-space:nowrap}
td{padding:7px 10px;border-top:1px solid var(--line);vertical-align:top;color:var(--soft)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
tbody tr:nth-child(even){background:#FBFCFE}
td.empty{text-align:center;color:var(--muted)}
.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid color-mix(in srgb,var(--tone) 45%,transparent);background:var(--wash);color:var(--ink);font-weight:700;font-size:11.5px;border-radius:999px;padding:2px 9px;white-space:nowrap}
.pill i{width:7px;height:7px;border-radius:50%;background:var(--tone);display:inline-block}
.callout{border-left:4px solid var(--tone);background:var(--wash);border-radius:0 8px 8px 0;padding:12px 16px;margin:14px 0}
.callout p{margin:4px 0 0}
.bullets li{margin:6px 0;color:var(--soft)}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px 24px;margin:14px 0}
.facts.one{grid-template-columns:minmax(0,1fr)}
.facts dt{font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.facts dd{margin:2px 0 0;color:var(--ink);word-break:break-word}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}
.dossier{border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:22px 0;background:#fff}
.dossier header{border-left:4px solid var(--brand);padding-left:12px}
.dossier header p{margin:2px 0 8px;color:var(--muted);font-size:13px}
.badges{display:flex;flex-wrap:wrap;gap:8px}
.dossier-s{font-weight:600;color:var(--ink)}
.seal{display:flex;flex-wrap:wrap;gap:22px;align-items:flex-start}
.seal .qr{border:1px solid var(--line);border-radius:10px;padding:8px;background:#fff}
.seal .facts{flex:1;min-width:260px}
footer.doc{max-width:1180px;margin:0 auto 40px;padding:0 16px;color:var(--muted);font-size:12px;display:flex;flex-wrap:wrap;justify-content:space-between;gap:8px}
a{color:var(--brand)}
@media print{
  body{background:#fff}
  nav.toc{display:none}
  .shell{display:block;max-width:none;padding:0}
  section{border:0;border-radius:0;margin:0;padding:18px 0;page-break-inside:auto}
  section.break,#executive-summary{page-break-before:always}
  .cover{min-height:auto;page-break-after:always;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .scroll{overflow:visible;border:0}th{position:static}
  .kpi,.chart,.dossier,.callout,.pill,th,.legend .sw{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .dossier{page-break-inside:avoid}
}
</style></head>
<body>
<header class="cover">
  ${logo ? `<img class="logo" src="${logo}" alt="${esc(branding.companyName)} logo">` : ''}
  <span class="cls">${esc(branding.classification || 'CONFIDENTIAL')}</span>
  <div class="eyebrow">${esc(d.cover.eyebrow)}</div>
  <h1>${esc(d.cover.title)}</h1>
  <div class="sub">${esc(d.cover.subtitle)}</div>
  <div class="scope">${esc(d.cover.scopeLine)}</div>
  <dl class="meta">${d.cover.facts.map((f) => `<div><dt>${esc(f.label)}</dt><dd>${esc(f.value)}</dd></div>`).join('')}</dl>
  <div class="quality">${pill(validationLabel(v), qualityHex)}${report.integrity ? ` <span class="muted">${esc(report.integrity.algorithm)} digest · ${esc(report.integrity.hash.slice(0, 24))}…</span>` : ''}</div>
</header>
<div class="shell">
<nav class="toc" aria-label="Contents"><b>Contents</b><ol>${entries.map((e) => `<li><a href="#${esc(e.id)}">${esc(e.title)}</a></li>`).join('')}</ol></nav>
<main>
<section id="executive-summary"><h2>Executive Summary</h2><p class="lead">${esc(d.summary.headline)}</p>${kpis(d.summary.highlights)}${d.summary.paragraphs.map((p) => `<p>${esc(p)}</p>`).join('')}</section>
${sections}
${decisions}
<section id="validation" class="break"><h2>Validation, Reconciliation &amp; Integrity</h2>
<p>${pill(validationLabel(v), qualityHex)}</p>
${v.checks.length ? table({ title: 'Pre-export validation', columns: ['Check', 'Result', 'Detail'], rows: v.checks.map((c) => [c.check, VALIDATION_LABEL[c.status], c.detail]) }, [{ column: 1, kind: 'status' }]) : ''}
${report.reconciliation.length ? table({ title: 'Reconciliation — dashboard vs exported', columns: ['Metric', 'Dashboard', 'Exported', 'Result'], rows: report.reconciliation.map((r) => [r.metric, r.dashboard, r.exported, r.matches ? 'MATCH' : 'REVIEW']) }, [{ column: 3, kind: 'status' }]) : ''}
${d.provenance.length ? `<h3 style="margin-top:22px">Evidence &amp; provenance</h3><ul class="bullets">${d.provenance.map((p) => `<li>${esc(p)}</li>`).join('')}</ul>` : ''}
${integrity ? `<h3 style="margin-top:22px">Integrity digest</h3>${integrity}` : ''}
<p class="muted">Prepared by ${esc(report.meta.generatedBy || 'QGuard Helix')}${branding.reportOwner ? ` for ${esc(branding.reportOwner)}` : ''}${branding.reviewer ? `; reviewer ${esc(branding.reviewer)}` : ''}. Generated ${esc(utc(report.meta.generatedAt))}. Latest evidence timestamp: ${esc(utc(report.meta.dataAsOf))}.</p>
</section>
</main>
</div>
<footer class="doc"><span>${esc(branding.companyName)} · ${esc(branding.classification || 'CONFIDENTIAL')}</span><span>${esc(d.cover.title)} · v${esc(report.meta.version || '1.0')} · ${esc(report.meta.reportId || '')}</span></footer>
</body></html>`
  return new Blob([html], { type: 'text/html;charset=utf-8' })
}
