import { PDFDocument, PDFFont, PDFPage, StandardFonts, degrees, rgb, type RGB } from 'pdf-lib';
import type { EnterpriseAssessmentReport, ReportTable } from '../schemas/ReportSchema';
import { qrMatrix, reportVerificationUrl } from '../ReportQr';
import { sanitizeForWinAnsi } from './pdf-text';
import { playbookRows } from '../ReportPlaybook';

/**
 * Enterprise PDF exporter built on pdf-lib (pure JS — identical in dev and
 * production). Produces a branded cover page, running header/footer with page
 * numbers, a classification watermark, KPI grid, embedded chart images, findings
 * and governance tables. All content derives from the unified report model.
 */

const A4: [number, number] = [595.28, 841.89];
const MARGIN = 44;
const INK = rgb(0.06, 0.09, 0.16);
const MUTED = rgb(0.39, 0.45, 0.55);
const LINE = rgb(0.886, 0.91, 0.941);
const BRAND = rgb(0.142, 0.47, 1);
const WHITE = rgb(1, 1, 1);
const HEADER_BG = rgb(0.06, 0.09, 0.16);
const SEV: Record<string, RGB> = {
  critical: rgb(0.86, 0.15, 0.15),
  high: rgb(0.92, 0.35, 0.05),
  medium: rgb(0.85, 0.47, 0.02),
  low: rgb(0.09, 0.64, 0.29),
  info: rgb(0.15, 0.4, 1),
};
// Improvements_06 — risk-zone (heat map), ownership-domain and timeline-status palettes.
const TRACK = rgb(0.886, 0.91, 0.941);
const ZONE: Record<string, RGB> = {
  critical: rgb(0.725, 0.11, 0.11),
  high: rgb(0.918, 0.345, 0.047),
  medium: rgb(0.851, 0.467, 0.024),
  low: rgb(0.396, 0.639, 0.051),
  minimal: rgb(0.086, 0.639, 0.29),
};
const DOMAIN_RGB: Record<string, RGB> = {
  customer: rgb(0.033, 0.569, 0.698),
  provider: rgb(0.149, 0.388, 0.922),
  ecosystem: rgb(0.486, 0.227, 0.929),
};
const STATUS_RGB: Record<string, RGB> = {
  ready: rgb(0.086, 0.639, 0.29),
  'in-progress': rgb(0.149, 0.388, 0.922),
  waiting: rgb(0.851, 0.467, 0.024),
  'not-applicable': rgb(0.58, 0.639, 0.722),
};

/** Shared WinAnsi sanitiser — see exporters/pdf-text.ts for why. */
const san = sanitizeForWinAnsi;

function dataUrlToBytes(dataUrl: string): Uint8Array {
  const base64 = dataUrl.split(',')[1] || '';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

class PdfLayout {
  doc: PDFDocument;
  font: PDFFont;
  bold: PDFFont;
  page!: PDFPage;
  y = 0;
  readonly contentW = A4[0] - MARGIN * 2;
  readonly top = A4[1] - 64;
  readonly bottom = 56;

  constructor(doc: PDFDocument, font: PDFFont, bold: PDFFont) {
    this.doc = doc;
    this.font = font;
    this.bold = bold;
    this.newPage();
  }

  newPage() {
    this.page = this.doc.addPage(A4);
    this.y = this.top;
  }

  ensure(height: number) {
    if (this.y - height < this.bottom) this.newPage();
  }

  wrap(text: string, size: number, font: PDFFont, maxWidth: number): string[] {
    const words = san(text).replace(/\s+/g, ' ').trim().split(' ');
    const lines: string[] = [];
    let current = '';
    for (const word of words) {
      const candidate = current ? `${current} ${word}` : word;
      if (font.widthOfTextAtSize(candidate, size) > maxWidth && current) {
        lines.push(current);
        current = word;
      } else {
        current = candidate;
      }
    }
    if (current) lines.push(current);
    return lines.length ? lines : [''];
  }

  heading(text: string) {
    this.ensure(34);
    this.y -= 22;
    this.page.drawText(san(text), { x: MARGIN, y: this.y, size: 13, font: this.bold, color: INK });
    this.y -= 6;
    this.page.drawLine({ start: { x: MARGIN, y: this.y }, end: { x: MARGIN + this.contentW, y: this.y }, thickness: 0.7, color: LINE });
    this.y -= 8;
  }

  paragraph(text: string, size = 9.5, color = rgb(0.2, 0.25, 0.33)) {
    const lines = this.wrap(text, size, this.font, this.contentW);
    for (const line of lines) {
      this.ensure(size + 4);
      this.page.drawText(line, { x: MARGIN, y: this.y, size, font: this.font, color });
      this.y -= size + 3;
    }
    this.y -= 4;
  }

  kpiGrid(kpis: EnterpriseAssessmentReport['kpis']) {
    const perRow = 4;
    const gap = 8;
    const cellW = (this.contentW - gap * (perRow - 1)) / perRow;
    const cellH = 52;
    for (let i = 0; i < kpis.length; i += perRow) {
      this.ensure(cellH + 8);
      const rowKpis = kpis.slice(i, i + perRow);
      rowKpis.forEach((kpi, index) => {
        const x = MARGIN + index * (cellW + gap);
        const top = this.y;
        this.page.drawRectangle({ x, y: top - cellH, width: cellW, height: cellH, borderColor: LINE, borderWidth: 1, color: WHITE });
        this.page.drawText(san(`${kpi.value}${kpi.unit || ''}`), { x: x + 8, y: top - 24, size: 17, font: this.bold, color: INK });
        this.page.drawText(this.wrap(kpi.label, 7.5, this.font, cellW - 16)[0], { x: x + 8, y: top - 36, size: 7.5, font: this.font, color: MUTED });
        if (kpi.level) this.page.drawText(this.wrap(kpi.level, 8, this.font, cellW - 16)[0], { x: x + 8, y: top - 46, size: 8, font: this.font, color: BRAND });
      });
      this.y -= cellH + 8;
    }
  }

  async image(dataUrl: string, maxW: number, maxH: number, caption?: string) {
    try {
      const png = await this.doc.embedPng(dataUrlToBytes(dataUrl));
      const scale = Math.min(maxW / png.width, maxH / png.height);
      const w = png.width * scale;
      const h = png.height * scale;
      this.ensure(h + (caption ? 16 : 6));
      this.page.drawImage(png, { x: MARGIN, y: this.y - h, width: w, height: h });
      this.y -= h + 2;
      if (caption) {
        this.page.drawText(san(caption), { x: MARGIN, y: this.y - 9, size: 8, font: this.font, color: MUTED });
        this.y -= 14;
      }
      this.y -= 6;
    } catch {
      this.paragraph(`${caption || 'Chart'}: Evidence Not Available`, 9, MUTED);
    }
  }

  table(table: ReportTable, widthsPct?: number[]) {
    const cols = table.columns.length;
    const widths = (widthsPct || table.columns.map(() => 100 / cols)).map((pct) => (pct / 100) * this.contentW);
    const pad = 4;
    const fontSize = 8.5;

    const drawRow = (cells: Array<string | number>, isHeader: boolean) => {
      const cellLines = cells.map((cell, index) => this.wrap(String(cell), fontSize, isHeader ? this.bold : this.font, widths[index] - pad * 2));
      const rowH = Math.max(...cellLines.map((lines) => lines.length)) * (fontSize + 2) + pad * 2;
      this.ensure(rowH);
      let x = MARGIN;
      if (isHeader) this.page.drawRectangle({ x: MARGIN, y: this.y - rowH, width: this.contentW, height: rowH, color: HEADER_BG });
      cells.forEach((_, index) => {
        let ly = this.y - pad - fontSize;
        for (const line of cellLines[index]) {
          this.page.drawText(line, { x: x + pad, y: ly, size: fontSize, font: isHeader ? this.bold : this.font, color: isHeader ? WHITE : rgb(0.2, 0.25, 0.33) });
          ly -= fontSize + 2;
        }
        x += widths[index];
      });
      this.y -= rowH;
      this.page.drawLine({ start: { x: MARGIN, y: this.y }, end: { x: MARGIN + this.contentW, y: this.y }, thickness: 0.5, color: LINE });
    };

    drawRow(table.columns, true);
    for (const row of table.rows.slice(0, 24)) drawRow(row, false);
    this.y -= 8;
  }

  /** Crisp vector QR — dark modules drawn as filled squares (I4#9). */
  qr(matrix: boolean[][], sizePt: number) {
    const quiet = 4;
    const total = matrix.length + quiet * 2;
    const module = sizePt / total;
    this.ensure(sizePt + 10);
    const top = this.y;
    this.page.drawRectangle({ x: MARGIN, y: top - sizePt, width: sizePt, height: sizePt, color: WHITE, borderColor: LINE, borderWidth: 0.75 });
    matrix.forEach((row, r) =>
      row.forEach((dark, c) => {
        if (!dark) return;
        this.page.drawRectangle({ x: MARGIN + (c + quiet) * module, y: top - (r + quiet + 1) * module, width: module, height: module, color: INK });
      }),
    );
    this.y -= sizePt + 10;
  }

  /** Labelled proportional horizontal bar (Improvements_06 §1/§4). */
  hbar(label: string, pct: number, color: RGB, valueText: string) {
    const rowH = 17;
    this.ensure(rowH + 2);
    const labelW = 122;
    const valueW = 150;
    const trackX = MARGIN + labelW;
    const trackW = Math.max(40, this.contentW - labelW - valueW - 8);
    const yTop = this.y;
    this.page.drawText(this.wrap(label, 8.5, this.bold, labelW - 4)[0], { x: MARGIN, y: yTop - 12, size: 8.5, font: this.bold, color: INK });
    this.page.drawRectangle({ x: trackX, y: yTop - 15, width: trackW, height: 10, color: TRACK });
    const p = Math.max(0, Math.min(100, pct));
    if (p > 0) this.page.drawRectangle({ x: trackX, y: yTop - 15, width: (trackW * p) / 100, height: 10, color });
    this.page.drawText(this.wrap(valueText, 8, this.font, valueW - 4)[0], { x: trackX + trackW + 6, y: yTop - 12, size: 8, font: this.font, color: rgb(0.2, 0.25, 0.33) });
    this.y -= rowH;
  }

  /** 5×5 Executive Heat Map grid (Improvements_06 §2). */
  heatMap(heat: EnterpriseAssessmentReport['executiveHeatMap']) {
    const labelW = 58;
    const cols = heat.likelihoodLabels.length || 5;
    const cellW = (this.contentW - labelW) / cols;
    const cellH = 30;
    // Column header (likelihood).
    this.ensure(cellH * (heat.impactLabels.length + 1) + 20);
    let hx = MARGIN + labelW;
    for (const l of heat.likelihoodLabels) {
      this.page.drawText(this.wrap(l, 6.5, this.font, cellW - 2)[0], { x: hx + 2, y: this.y - 8, size: 6.5, font: this.font, color: MUTED });
      hx += cellW;
    }
    this.y -= 12;
    // Rows (impact, Critical→Minimal).
    for (const imp of heat.impactLabels) {
      const row = heat.cells.filter((c) => c.impact === imp).sort((a, b) => a.likelihoodRank - b.likelihoodRank);
      const top = this.y;
      this.page.drawText(imp, { x: MARGIN, y: top - cellH / 2 - 3, size: 7, font: this.bold, color: rgb(0.2, 0.25, 0.33) });
      let cx = MARGIN + labelW;
      for (const cell of row) {
        const zone = ZONE[cell.level] || rgb(0.58, 0.639, 0.722);
        const faded = cell.count === 0;
        this.page.drawRectangle({ x: cx + 1, y: top - cellH, width: cellW - 2, height: cellH - 2, color: zone, opacity: faded ? 0.25 : 1 });
        if (cell.count > 0) this.page.drawText(String(cell.count), { x: cx + cellW / 2 - 3, y: top - cellH / 2 - 3, size: 11, font: this.bold, color: WHITE });
        cx += cellW;
      }
      this.y -= cellH;
    }
    this.y -= 8;
  }

  findings(report: EnterpriseAssessmentReport) {
    if (!report.findings.length) {
      this.paragraph('Evidence Not Available — no findings recorded.', 9.5, MUTED);
      return;
    }
    for (const finding of report.findings.slice(0, 12)) {
      const lines = [
        ...this.wrap(`Asset: ${finding.affectedAssets.join(', ') || 'Evidence Not Available'}   |   Owner: ${finding.owner}   |   Target: ${finding.targetDate}`, 8.5, this.font, this.contentW - 16),
        ...this.wrap(`Current: ${finding.currentState}  ->  Recommended: ${finding.recommendedState}`, 8.5, this.font, this.contentW - 16),
        ...this.wrap(`Business Impact: ${finding.businessImpact}`, 8.5, this.font, this.contentW - 16),
        ...this.wrap(`Complexity: ${finding.migrationComplexity}  |  Effort: ${finding.estimatedEffort}  |  Cost: $${(finding.estimatedCostUsd || 0).toLocaleString()}  |  Risk Reduction: ${finding.riskReductionPct}%`, 8.5, this.font, this.contentW - 16),
        ...this.wrap(`Dependencies: ${finding.dependencies.join(', ') || '-'}   |   Validation: ${finding.validation}`, 8.5, this.font, this.contentW - 16),
      ];
      const boxH = 24 + lines.length * 11;
      this.ensure(boxH + 6);
      const top = this.y;
      this.page.drawRectangle({ x: MARGIN, y: top - boxH, width: this.contentW, height: boxH, borderColor: LINE, borderWidth: 1, color: WHITE });
      const sevColor = SEV[finding.severity] || MUTED;
      this.page.drawRectangle({ x: MARGIN + 8, y: top - 18, width: 46, height: 12, color: sevColor });
      this.page.drawText(finding.severity.toUpperCase(), { x: MARGIN + 11, y: top - 16, size: 7, font: this.bold, color: WHITE });
      this.page.drawText(this.wrap(finding.title, 10, this.bold, this.contentW - 70)[0], { x: MARGIN + 62, y: top - 16, size: 10, font: this.bold, color: INK });
      let ly = top - 30;
      for (const line of lines) {
        this.page.drawText(line, { x: MARGIN + 10, y: ly, size: 8.5, font: this.font, color: rgb(0.2, 0.25, 0.33) });
        ly -= 11;
      }
      this.y -= boxH + 6;
    }
  }
}

export async function exportPdf(report: EnterpriseAssessmentReport): Promise<Blob> {
  const doc = await PDFDocument.create();
  doc.setTitle(report.meta.title);
  doc.setAuthor(report.branding.companyName);
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const { branding, meta } = report;

  // ---- Cover page ----
  const cover = doc.addPage(A4);
  let cy = A4[1] - 150;
  if (branding.companyLogo) {
    try {
      const logo = await doc.embedPng(dataUrlToBytes(branding.companyLogo));
      const scale = Math.min(150 / logo.width, 56 / logo.height);
      cover.drawImage(logo, { x: MARGIN, y: cy, width: logo.width * scale, height: logo.height * scale });
      cy -= 40;
    } catch {
      /* logo not embeddable */
    }
  }
  cover.drawRectangle({ x: MARGIN, y: cy - 4, width: bold.widthOfTextAtSize(san(branding.classification), 9) + 16, height: 18, color: INK });
  cover.drawText(san(branding.classification), { x: MARGIN + 8, y: cy, size: 9, font: bold, color: WHITE });
  cy -= 60;
  for (const line of (function wrapTitle() {
    const words = san(meta.title).split(' ');
    const lines: string[] = [];
    let current = '';
    for (const word of words) {
      const candidate = current ? `${current} ${word}` : word;
      if (bold.widthOfTextAtSize(candidate, 28) > A4[0] - MARGIN * 2 && current) { lines.push(current); current = word; } else current = candidate;
    }
    if (current) lines.push(current);
    return lines;
  })()) {
    cover.drawText(line, { x: MARGIN, y: cy, size: 28, font: bold, color: INK });
    cy -= 34;
  }
  cy -= 6;
  cover.drawText(san(`${branding.companyName}${branding.businessUnit ? ` - ${branding.businessUnit}` : ''}`), { x: MARGIN, y: cy, size: 14, font, color: MUTED });
  cy -= 40;
  const metaLines = [
    `Report ID: ${meta.id}`,
    `Version: ${meta.version}   |   Generated: ${new Date(meta.generatedAt).toLocaleString()}`,
    `Generated By: ${meta.generatedBy}`,
    `Report Owner: ${branding.reportOwner || 'Evidence Not Available'}   |   Reviewer: ${branding.reviewer || 'Evidence Not Available'}`,
    `Assessment Scope: ${report.scope.type === 'custom' ? `${report.scope.selectedAssetCount} of ${report.scope.totalAssetCount} assets (custom selection)` : `Full assessment (${report.scope.totalAssetCount} asset${report.scope.totalAssetCount === 1 ? '' : 's'})`}`,
  ];
  for (const line of metaLines) {
    cover.drawText(san(line), { x: MARGIN, y: cy, size: 9.5, font, color: rgb(0.2, 0.25, 0.33) });
    cy -= 16;
  }
  cover.drawLine({ start: { x: MARGIN, y: 90 }, end: { x: A4[0] - MARGIN, y: 90 }, thickness: 2, color: BRAND });

  // ---- Body (board-level migration program structure) ----
  const ex = report.executiveBlock;
  const usd = (n: number) => (n ? `$${Math.round(n).toLocaleString()}` : 'Evidence Not Available');
  // ASCII progress bar (I3#6) — CP1252-safe (pdf-lib StandardFonts can't render
  // Unicode block glyphs, so we use [####----] rather than █░).
  const bar = (pct: number) => {
    const p = Math.max(0, Math.min(100, Math.round(pct)));
    const filled = Math.round(p / 10);
    return `[${'#'.repeat(filled)}${'-'.repeat(10 - filled)}] ${p}%`;
  };
  const layout = new PdfLayout(doc, font, bold);

  // ---- Board Snapshot — 60-second executive view (Improvements_06 §6) ----
  if (report.boardSnapshot.hasData) {
    const b = report.boardSnapshot;
    layout.heading('Board Snapshot — 60-Second Executive View');
    layout.paragraph(b.headline, 10, INK);
    layout.table({ title: 'Board Metrics', columns: ['Metric', 'Value', 'Context'], rows: b.metrics.map((m) => [m.label, m.value, m.context]) }, [26, 24, 50]);
    if (b.topDecisions.length) {
      layout.paragraph('Top Decisions for the Board:', 9.5, INK);
      b.topDecisions.forEach((d, i) => layout.paragraph(`${i + 1}. ${d}`, 9, MUTED));
    }
    const dist = b.responsibilitySplit;
    const distTotal = Math.max(1, dist.customer + dist.provider + dist.ecosystem);
    layout.paragraph('Customer vs Provider Responsibility:', 9.5, INK);
    layout.hbar('Customer', (dist.customer / distTotal) * 100, DOMAIN_RGB.customer, `${dist.customer} (${Math.round((dist.customer / distTotal) * 100)}%)`);
    layout.hbar('Provider', (dist.provider / distTotal) * 100, DOMAIN_RGB.provider, `${dist.provider} (${Math.round((dist.provider / distTotal) * 100)}%)`);
    layout.hbar('Ecosystem', (dist.ecosystem / distTotal) * 100, DOMAIN_RGB.ecosystem, `${dist.ecosystem} (${Math.round((dist.ecosystem / distTotal) * 100)}%)`);
    if (b.responsibilityNote) layout.paragraph(b.responsibilityNote, 8.5, MUTED);
    if (b.assetBasis) layout.paragraph(b.assetBasis, 8.5, MUTED);
    layout.paragraph(`Executive Recommendation: ${b.recommendation}`, 9.5, INK);
  }

  layout.heading('Executive Summary');
  layout.paragraph(report.executiveSummary);
  if (branding.customNotes) layout.paragraph(`Notes: ${branding.customNotes}`, 9, MUTED);
  // Improvement is stated in POINTS for every row (reductions also annotate the
  // relative %) — mixing "+65" points with "-75%" percent in one column read as
  // a miscalculation to reviewers.
  const hndlDropPct = Math.round(((ex.currentHndl - ex.targetHndl) / Math.max(1, ex.currentHndl)) * 100);
  layout.table({ title: 'Current vs Target', columns: ['Metric', 'Current', 'Target', 'Improvement'], rows: [
    ['Quantum Readiness', `${ex.currentReadiness}/100`, `${ex.targetReadiness}/100`, ex.targetReadiness > ex.currentReadiness ? `+${ex.targetReadiness - ex.currentReadiness} pts` : '—'],
    ['Quantum Risk', `${ex.currentRisk}/100`, `${ex.targetRisk}/100`, ex.currentRisk > ex.targetRisk ? `-${ex.currentRisk - ex.targetRisk} pts (-${ex.expectedRiskReductionPct}%)` : '—'],
    ['HNDL Exposure', `${ex.currentHndl}/100`, `${ex.targetHndl}/100`, ex.currentHndl > ex.targetHndl ? `-${ex.currentHndl - ex.targetHndl} pts (-${hndlDropPct}%)` : '—'],
    ['Migration Timeline', '—', `${ex.estimatedDurationWeeks || 'TBD'} weeks`, ''],
    ['Migration Budget', '—', usd(ex.estimatedCostUsd), ''],
    ['Quantum Exposure Window', '—', ex.quantumExposureWindow, ''],
  ] }, [34, 22, 22, 22]);
  layout.heading('Top Risks & Recommended Actions');
  layout.table({ title: 'Top 5', columns: ['# ', 'Top Risk', 'Recommended Action'], rows: Array.from({ length: Math.max(ex.topRisks.length, ex.topActions.length) }).map((_, i) => [i + 1, ex.topRisks[i] || '—', ex.topActions[i] || '—']) }, [6, 47, 47]);
  layout.heading('Top Business Risks');
  layout.table({ title: 'Business Risks', columns: ['#', 'Business Risk', 'Level', 'Evidence Driver'], rows: ex.topBusinessRisks.length ? ex.topBusinessRisks.map((r, i) => [i + 1, r.risk, r.level, r.driver]) : [['-', 'Evidence Not Available', '-', '-']] }, [5, 28, 10, 57]);
  layout.paragraph(`Executive Recommendation: ${ex.executiveRecommendation}`, 9.5, INK);

  layout.heading('Assessment Scope');
  layout.paragraph(report.scope.note);
  if (report.scope.type === 'custom') {
    layout.paragraph(report.scope.methodology, 9, MUTED);
    layout.table({ title: 'Assets In Scope', columns: ['Asset', 'Type', 'Environment', 'Risk', 'Posture'], rows: report.scope.assets.map((a) => [a.name, a.assetType, a.environment, `${a.riskScore}/100`, a.posture]) }, [36, 18, 16, 12, 18]);
  }

  layout.heading('Executive Dashboard');
  layout.kpiGrid(report.kpis);

  layout.heading('Business Impact Analysis');
  layout.table({ title: 'Business Impact', columns: ['Dimension', 'Value'], rows: [
    ['Customer-Facing Systems', report.businessImpact.customerFacingSystems],
    ['Mission-Critical Systems', report.businessImpact.missionCriticalSystems],
    ['Third-Party Dependencies', report.businessImpact.thirdPartyDependencies],
    ['Revenue Impact', report.businessImpact.revenueImpact],
    ['Compliance Impact', report.businessImpact.complianceImpact],
    ['Financial Impact', report.businessImpact.financialImpact],
    ['HNDL Exposure', report.businessImpact.hndlExposure],
    ['Quantum Exposure Window', report.businessImpact.quantumExposureWindow],
  ] }, [50, 50]);
  layout.table({ title: 'Business Impact Intelligence', columns: ['Dimension', 'Level', 'Why', 'Evidence'], rows: report.impactReasons.map((r) => [r.dimension, r.level, r.reason, r.evidence.join('; ')]) }, [18, 10, 36, 36]);

  layout.heading('Executive Decision Center');
  layout.table({ title: 'Decisions', columns: ['Decision Required', 'Type', 'Owner'], rows: report.executiveDecisions.map((d) => [d.decision, d.type, d.owner]) }, [54, 26, 20]);
  layout.paragraph('Executive Decision Package — the one-look decision summary; every line is sourced from the validated report sections referenced in its detail.', 9, MUTED);
  layout.table({ title: 'Decision Package', columns: ['Decision Item', 'Value', 'Detail / Source'], rows: report.decisionPackage.length ? report.decisionPackage.map((d) => [d.item, d.value, d.detail]) : [['Evidence Not Available', '-', '-']] }, [18, 22, 60]);

  layout.heading('Quantum Readiness Breakdown');
  layout.paragraph('Targets are calculated per domain (baseline + internet-facing exposure), not static — rationale below.', 9, MUTED);
  layout.table({ title: 'Domains', columns: ['Domain', 'Cur', 'Tgt', 'Risk', 'Owner', 'Target Rationale'], rows: report.readinessDomains.map((d) => [d.domain, `${d.score}`, `${d.targetScore}`, d.riskLevel, d.owner, d.targetRationale]) }, [14, 6, 6, 9, 15, 50]);

  layout.heading('Quantum Readiness Index');
  layout.paragraph(report.readinessIndex.note, 9, MUTED);
  layout.table({ title: 'Readiness Index', columns: ['Strategic Pillar', 'Score', 'Weight', 'Contribution', 'Primary Driver'], rows: report.readinessIndex.pillars.length ? report.readinessIndex.pillars.map((p) => [p.pillar, typeof p.score === 'number' ? `${p.score}` : p.score, p.measured ? `${p.weightPct}%` : '-', p.measured ? p.contribution.toFixed(1) : '-', p.driver]) : [['Evidence Not Available', '-', '-', '-', '-']] }, [20, 10, 9, 12, 49]);
  layout.paragraph(`Overall Quantum Readiness Index: ${report.readinessIndex.overall}/100.`, 9.5, INK);

  layout.heading('Readiness Scoring Methodology');
  layout.paragraph(`Formula: ${report.readinessMethodology.formula}`, 9, INK);
  layout.paragraph(report.readinessMethodology.explanation, 9, MUTED);
  layout.table({ title: 'Readiness Methodology', columns: ['Factor', 'Weight', 'Score', 'Contribution', 'Measurement Basis'], rows: report.readinessMethodology.factors.map((f) => [f.factor, f.measured ? `${f.weightPct}%` : 'Excluded', typeof f.score === 'number' ? `${f.score}` : f.score, f.measured ? f.contribution.toFixed(1) : '-', f.basis]) }, [22, 10, 10, 12, 46]);
  layout.paragraph(`Overall = ${report.readinessMethodology.factors.filter((f) => f.measured).map((f) => f.contribution.toFixed(1)).join(' + ')} = ${report.readinessMethodology.overall}/100 (±1 rounding).`, 9, INK);

  layout.heading('Industry Benchmarking');
  layout.paragraph(report.benchmarking.percentileNarrative, 9, MUTED);
  layout.table({ title: 'Benchmarking', columns: ['Cohort', 'Readiness', 'Delta vs You', 'Source'], rows: report.benchmarking.rows.length ? report.benchmarking.rows.map((b) => [b.cohort, `${b.readiness}/100`, b.delta === 0 ? '-' : `${b.delta > 0 ? '+' : ''}${b.delta}`, b.source]) : [['Evidence Not Available', '-', '-', '-']] }, [32, 14, 14, 40]);
  if (report.benchmarking.note) layout.paragraph(report.benchmarking.note, 8.5, MUTED);

  layout.heading('AI Migration Advisor');
  layout.paragraph(`Recommendation: ${report.migrationAdvisor.recommendation}`, 11, INK);
  layout.paragraph(report.migrationAdvisor.reason);
  layout.table({ title: 'Advisor', columns: ['Risk Reduction', 'Est. Cost', 'Timeline', 'Complexity', 'Confidence'], rows: [[`${report.migrationAdvisor.riskReductionPct}%`, usd(report.migrationAdvisor.costUsd), `${report.migrationAdvisor.timelineWeeks}w`, report.migrationAdvisor.complexity, `${report.migrationAdvisor.confidencePct}%`]] }, [20, 22, 16, 20, 22]);
  layout.paragraph(`Why this recommendation: ${report.advisorValidation.why}`, 9, MUTED);
  layout.table({ title: 'Validation', columns: ['Validation Factor', 'Evidence'], rows: [
    ['Primary Exposure Domain', report.advisorValidation.primaryExposureDomain],
    ['Top Contributing Findings', report.advisorValidation.topContributingFindings.join('; ') || 'Evidence Not Available'],
    ['Top Contributing Assets', report.advisorValidation.topContributingAssets.join('; ') || 'Evidence Not Available'],
  ] }, [28, 72]);

  layout.heading('Confidence Overview');
  layout.paragraph(report.confidenceSummary.note, 9, MUTED);
  layout.table({ title: 'Confidence', columns: ['Confidence Measure', 'Value', 'What it means'], rows: [
    ['Assessment Evidence Confidence', `${report.confidenceSummary.assessmentConfidencePct}%`, 'Completeness of the evidence behind the assessment'],
    ['Migration Plan Confidence', `${report.confidenceSummary.migrationPlanConfidencePct}%`, 'Likelihood the recommended plan achieves target'],
    ['Migration Forecast Confidence', `${report.confidenceSummary.migrationForecastConfidencePct}%`, 'Confidence in the entire-programme simulation outcome'],
    ['Wave Confidence (range)', report.confidenceSummary.waveConfidenceRange, 'Per-wave execution confidence (declines across waves)'],
    ['Evidence Confidence', `${report.confidenceSummary.evidenceConfidencePct}%`, 'Mean quality across evidence sources'],
  ] }, [26, 14, 60]);
  layout.paragraph(`Assessment Confidence (evidence coverage): ${report.confidenceSummary.assessmentConfidencePct}%`, 9.5, INK);
  layout.table({ title: 'Coverage', columns: ['Coverage Factor', 'Coverage'], rows: report.migrationConfidence.factors.map((f) => [f.label, `${f.coveragePct}%`]) }, [70, 30]);

  layout.heading('Migration Readiness Assessment');
  layout.table({ title: 'Readiness', columns: ['Category', 'Score', 'Recommendation'], rows: report.migrationReadiness.map((m) => [m.category, `${m.score}/100`, m.recommendation]) }, [26, 12, 62]);

  layout.heading('Migration Wave Planning');
  layout.table({ title: 'Waves', columns: ['Wave', 'Focus', 'Pri', 'Owner', 'Dur', 'Cost', 'Risk-', 'Status'], rows: report.migrationWaves.map((w) => [`W${w.wave}`, w.name, w.priority, w.owner, `${w.durationWeeks}w`, usd(w.costUsd), `${w.riskReductionPct}%`, w.status]) }, [7, 22, 11, 20, 8, 14, 8, 10]);

  if (report.sharedResponsibility.hasData) {
    const sr = report.sharedResponsibility;
    layout.heading('Shared Responsibility Assessment');
    layout.paragraph(sr.summary, 9, MUTED);
    // §1 — ownership summary bars
    const srTotal = Math.max(1, sr.customerControlled + sr.providerControlled + sr.ecosystemDependent);
    layout.paragraph('Shared Responsibility Summary:', 9.5, INK);
    layout.hbar('Customer', (sr.customerControlled / srTotal) * 100, DOMAIN_RGB.customer, `${sr.customerControlled} (${Math.round((sr.customerControlled / srTotal) * 100)}%)`);
    layout.hbar('Provider', (sr.providerControlled / srTotal) * 100, DOMAIN_RGB.provider, `${sr.providerControlled} (${Math.round((sr.providerControlled / srTotal) * 100)}%)`);
    layout.hbar('Ecosystem', (sr.ecosystemDependent / srTotal) * 100, DOMAIN_RGB.ecosystem, `${sr.ecosystemDependent} (${Math.round((sr.ecosystemDependent / srTotal) * 100)}%)`);
    // §4 — per-domain readiness timeline
    if (sr.timeline.length) {
      layout.paragraph('Shared Responsibility Timeline (Ready / Waiting):', 9.5, INK);
      sr.timeline.forEach((t) => layout.hbar(t.domain, t.readiness, STATUS_RGB[t.status] || STATUS_RGB['not-applicable'], `${t.label} - ${t.readiness}/100`));
    }
    layout.table({ title: 'Ownership Readiness', columns: ['Ownership Domain', 'Readiness', 'Findings'], rows: [
      ['Overall', `${sr.readiness.overall}/100`, `${sr.customerControlled + sr.providerControlled + sr.ecosystemDependent}`],
      ['Customer-Controlled', `${sr.readiness.customer}/100`, `${sr.customerControlled}`],
      ['Provider-Controlled', `${sr.readiness.provider}/100`, `${sr.providerControlled}`],
      ['Ecosystem-Dependent', `${sr.readiness.ecosystem}/100`, `${sr.ecosystemDependent}`],
    ] }, [50, 25, 25]);
    if (sr.reconciliationNote) layout.paragraph(`Finding-count reconciliation: ${sr.reconciliationNote}`, 8.5, MUTED);
    layout.paragraph(
      `Ownership matrix: ${sr.matrix.length} consolidated row(s) covering ${sr.matrixInstances} raw scanner instance(s). One row per exposure, owner and asset - repeated detections of the same exposure are merged and counted.`,
      8.5,
      MUTED,
    );
    layout.table({ title: 'Shared Responsibility Matrix', columns: ['Finding', 'Asset', 'Owner', 'Action', 'Inst', 'Pri', 'Status'], rows: sr.matrix.slice(0, 24).map((m) => [m.finding, m.asset, m.owner, m.action, `${m.occurrences}`, m.priority, m.status]) }, [20, 16, 13, 24, 6, 8, 13]);
    layout.table({ title: 'Dependency-Ordered Roadmap (7 Waves)', columns: ['Wave', 'Focus', 'Ownership', 'Findings', 'Status', 'Timeline'], rows: sr.waves.map((w) => [`W${w.wave}`, w.name, w.domain, `${w.findingCount}`, w.status, w.timeline]) }, [8, 26, 20, 12, 14, 20]);
    if (sr.providers.length) {
      layout.table({ title: 'Provider & Ecosystem Readiness', columns: ['Provider / Technology', 'Ownership', 'Findings', 'PQ Roadmap', 'Cust. Influence'], rows: sr.providers.map((p) => [p.name, p.domain, `${p.count}`, p.pqRoadmap, p.customerInfluence]) }, [28, 20, 14, 20, 18]);
    }
    if (sr.nextActions.length) sr.nextActions.forEach((a) => layout.paragraph(`• ${a}`, 9, MUTED));
  }

  layout.heading('Migration Dependency Analysis');
  layout.paragraph(report.dependencyAnalysis.summary, 9, MUTED);
  layout.table({ title: 'Dependencies', columns: ['Dependency Chain', 'Blast Radius', 'Complexity'], rows: report.dependencyAnalysis.chains.map((c) => [c.path, c.blastRadius, c.complexity]) }, [64, 18, 18]);

  layout.heading('Quantum Risk Analysis');
  layout.table({ title: 'Risk Categories', columns: ['Category', 'Current', 'Target', 'Reduction Potential'], rows: report.riskCategories.map((r) => [r.category, `${r.currentScore}`, `${r.targetScore}`, `${r.reductionPotentialPct}%`]) }, [40, 18, 18, 24]);

  if (report.executiveHeatMap.hasData) {
    layout.heading('Executive Risk Heat Map');
    layout.paragraph(report.executiveHeatMap.methodology, 8.5, MUTED);
    layout.heatMap(report.executiveHeatMap);
    layout.paragraph(`Rows = Business Impact (Critical -> Minimal); Columns = Quantum Exploitation Likelihood (Rare -> Almost Certain). Cell number = consolidated finding groups in that zone; ${report.executiveHeatMap.totalPlotted} plotted.`, 8.5, MUTED);
  }

  layout.heading('Risk Scoring Methodology');
  layout.paragraph(`Formula: ${report.riskMethodology.formula}`, 9, INK);
  layout.paragraph(report.riskMethodology.explanation, 9, MUTED);
  layout.table({ title: 'Risk Methodology', columns: ['Risk Domain', 'Domain Risk', 'Weight', 'Contribution', 'Share'], rows: report.riskMethodology.weights.map((w) => [w.domain, `${w.score}`, `${w.weightPct}%`, w.contribution.toFixed(1), `${w.contributionPct}%`]) }, [34, 16, 14, 18, 18]);
  layout.paragraph(`Overall = Σ Contribution = ${report.riskMethodology.weights.map((w) => w.contribution.toFixed(1)).join(' + ')} = ${report.riskMethodology.overall}/100.`, 9, INK);

  layout.heading('HNDL Exposure Analysis');
  layout.paragraph(report.hndl.summary);
  layout.table({ title: 'HNDL', columns: ['Data Category', 'Retention', 'Current', 'Risk', 'Recommended'], rows: report.hndl.categories.map((h) => [h.category, h.retention, h.currentProtection, h.hndlRisk, h.recommendedProtection]) }, [22, 18, 22, 10, 28]);

  layout.heading('Visual Analysis');
  for (const chart of report.charts) await layout.image(chart.dataUrl, layout.contentW * 0.62, 200, chart.title);

  layout.heading('Consolidated Findings (Root-Cause)');
  layout.table({ title: 'Finding Groups', columns: ['Finding', 'Occ.', 'Assets', 'Impact', 'Evidence'], rows: report.findingGroups.map((g) => [g.title, g.occurrences, g.affectedAssets, g.impact.toUpperCase(), g.evidence.join(', ') || '-']) }, [26, 8, 10, 12, 44]);

  layout.heading('Asset Criticality Analysis');
  layout.table({ title: 'Asset Criticality', columns: ['Asset', 'Business', 'Cust.', 'Internet', 'Revenue', 'Compliance', 'Data'], rows: report.assetCriticality.length ? report.assetCriticality.map((a) => [a.asset, a.businessCriticality, a.customerFacing ? 'Y' : 'N', a.internetFacing ? 'Y' : 'N', a.revenueImpact, a.complianceScope.join(', '), a.dataSensitivity]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-']] }, [24, 12, 8, 10, 12, 22, 12]);

  layout.heading('Asset Intelligence Profile');
  layout.paragraph('Per-asset crypto posture, ownership and platform metadata. Fields not observed by the current pipeline (OS/platform/hosting/cloud/cert expiry) are Evidence Not Available — deploy an agent/cloud connector to populate them.', 9, MUTED);
  layout.table({ title: 'Asset Intelligence', columns: ['Asset', 'Owner', 'Crit', 'Hosting', 'TLS', 'Primary Alg', 'Key', 'PQC', 'Cplx', 'Hrs'], rows: report.assetIntelligence.length ? report.assetIntelligence.map((a) => [a.asset, a.businessOwner, a.businessCriticality, a.hosting, a.tlsVersion, a.primaryAlgorithm, a.keyLength, `${a.pqcReadinessPct}%`, a.migrationComplexity, a.estimatedHours]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-', '-', '-', '-']] }, [16, 11, 7, 12, 10, 16, 9, 5, 8, 6]);

  // Raw per-instance findings belong in the Technical Assessment only. Board /
  // compliance / migration reports show the consolidated (root-cause) view above
  // so the same cipher/algorithm is not listed dozens of times.
  if (report.meta.kind === 'technical') {
    layout.heading('Technical Appendix — Raw Findings & Evidence');
    layout.findings(report);
  }

  layout.heading('Cryptographic & Asset Inventory');
  layout.table(report.assets, [26, 14, 16, 20, 12, 12]);
  layout.table(report.cbom, [60, 40]);
  layout.table(report.pqcReadiness.table, [60, 40]);

  layout.heading('Compliance Mapping');
  layout.paragraph('Dynamic gap tracking with a visual progress bar: Current to Target per framework.', 9, MUTED);
  layout.table({ title: 'Compliance', columns: ['Framework', 'Control', 'Cur', 'Tgt', 'Progress'], rows: report.compliance.map((c) => [c.framework, c.control, `${c.currentPct}%`, `${c.targetPct}%`, bar(c.progressPct)]) }, [15, 30, 8, 8, 39]);

  layout.heading('Crypto-Policy Profiles (Target Algorithm Selection)');
  layout.paragraph(report.cryptoPolicy.note, 9, MUTED);
  layout.table({ title: 'Crypto Policy', columns: ['Profile', 'Key Establishment', 'Digital Signature', 'Symmetric / Hash', 'Guidance'], rows: report.cryptoPolicy.profiles.map((p) => [p.profile === report.cryptoPolicy.activeProfile ? `${p.profile} (ACTIVE)` : p.profile, p.keyEstablishment, p.digitalSignature, `${p.symmetric} / ${p.hash}`, p.guidance]) }, [16, 20, 22, 16, 26]);

  if (report.remediationCampaigns.campaigns.length) {
    layout.heading('Remediation Campaigns');
    layout.paragraph(report.remediationCampaigns.note, 8.5, MUTED);
    layout.table({ title: 'Campaigns', columns: ['Pri', 'Campaign', 'Target', 'Find.', 'Occ.', 'Assets', 'Recommended Action'], rows: report.remediationCampaigns.campaigns.map((c) => [c.priority, c.campaign, c.target, `${c.findingCount}`, `${c.occurrences}`, `${c.affectedAssets}`, c.action]) }, [6, 20, 20, 7, 7, 8, 32]);
  }

  layout.heading('Remediation Program');
  layout.table({ title: 'Remediation', columns: ['Pri', 'Action', 'Owner', 'Cost', 'Risk-', 'Target'], rows: report.remediationProgram.map((r) => [r.priority, r.action, r.owner, usd(r.costUsd), `${r.riskReductionPct}%`, r.targetDate]) }, [6, 40, 18, 14, 8, 14]);

  if (report.businessPriorityMatrix.hasData) {
    layout.heading('Business Priority Matrix');
    layout.paragraph(report.businessPriorityMatrix.note, 8.5, MUTED);
    for (const q of report.businessPriorityMatrix.quadrants) {
      layout.paragraph(`${q.title} (${q.subtitle}) — ${q.guidance}`, 9.5, INK);
      if (q.items.length) q.items.slice(0, 6).forEach((it) => layout.paragraph(`- ${it.name}: ${it.rationale}`, 8.5, MUTED));
      else layout.paragraph('- No items in this quadrant.', 8.5, MUTED);
    }
  }

  layout.heading('Migration Roadmap & Program Plan');
  layout.paragraph(`Sequential dates, milestones, approval gates and critical-path/slack. Elapsed window: the "migration programme" duration counts the migration waves only; with the discovery and validation phases below, the end-to-end elapsed window is ${report.roadmap.reduce((sum, p) => sum + (Number(p.effortWeeks) || 0), 0)} weeks.`, 9, MUTED);
  layout.table({ title: 'Roadmap', columns: ['Phase', 'Start', 'Finish', 'Wks', 'Milestone / Gate', 'Crit', 'Slack'], rows: report.roadmap.map((p) => [p.phase, p.startDate, p.endDate, p.effortWeeks, `${p.milestone} | ${p.gate}`, p.criticalPath ? 'Y' : 'N', `${p.slackWeeks}w`]) }, [20, 12, 12, 6, 38, 6, 6]);

  layout.heading('Migration Resource Loading');
  layout.paragraph('Per-team planning: assumed availability (capacity), derived allocation demand, engineers and dependencies. A team whose allocation approaches its availability is over-subscribed.', 9, MUTED);
  layout.table({ title: 'Resource Loading', columns: ['Team', 'Waves', 'Hrs', 'Eng.', 'Window', 'Avail', 'Alloc', 'Dependencies'], rows: report.resourceLoading.length ? report.resourceLoading.map((r) => [r.team, r.waves, r.hours, r.engineers, `${r.windowWeeks}w`, `${r.availabilityPct}%`, `${r.allocationPct}%`, r.dependencies.join(', ')]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-', '-']] }, [14, 20, 7, 6, 8, 8, 8, 29]);

  layout.heading('Enterprise Remediation Playbook');
  // Controls identical across every playbook are stated once, then each playbook
  // lists only what differs for that finding.
  if (report.playbookStandardControls.rows.length) {
    layout.paragraph(`Standard Change Controls - applies to all ${report.playbookStandardControls.applies} playbooks`, 10, INK);
    layout.paragraph(report.playbookStandardControls.note, 8.5, MUTED);
    layout.table({ title: 'Standard Change Controls', columns: ['Control', 'Detail'], rows: report.playbookStandardControls.rows.map((r) => [r.step, r.detail]) }, [18, 82]);
  }
  for (const p of report.playbookDetail) {
    layout.paragraph(p.finding, 10, INK);
    layout.table({ title: 'Playbook', columns: ['Step', 'Detail'], rows: playbookRows(p, report.playbookStandardControls.sharedKeys) }, [18, 82]);
  }

  layout.heading('Cost Forecast Intelligence');
  layout.paragraph(`Blended rate $${report.costBreakdown.blendedRateUsd}/hr - total ${report.costBreakdown.totalHours.toLocaleString()} hours.`, 9, MUTED);
  layout.paragraph(report.costBreakdown.effortNote, 9, MUTED);
  layout.table({ title: 'Cost Breakdown', columns: ['Category', 'Hours', '~Wks', '~FTE', 'Eng.', 'Rate', 'Cost', 'Formula'], rows: [...report.costBreakdown.lines.map((l) => [l.category, l.hours, l.engineerWeeks, l.fte, l.engineers, usd(l.rateUsd), usd(l.costUsd), l.formula]), ['TOTAL', report.costBreakdown.totalHours, report.costBreakdown.totalEngineerWeeks, report.costBreakdown.totalFte, '', '', usd(report.costForecast.totalUsd), '']] }, [20, 8, 7, 7, 6, 10, 13, 29]);

  layout.heading('Executive ROI & Value Intelligence');
  layout.paragraph(report.roiAnalysis.paybackNarrative, 9.5, INK);
  layout.table({ title: 'ROI', columns: ['Value Metric', 'Expected Outcome', 'Basis / Formula'], rows: report.roiAnalysis.lines.length ? report.roiAnalysis.lines.map((l) => [l.metric, l.value, l.basis]) : [['Evidence Not Available', '-', '-']] }, [20, 32, 48]);
  layout.paragraph(`ROI assumption (configurable): ${report.roiAnalysis.assumptionBasis}`, 8.5, MUTED);

  layout.heading('Operational Benefits (Beyond ROI)');
  layout.paragraph('Non-financial business value executives value alongside pure financial return.', 9, MUTED);
  layout.table({ title: 'Operational Benefits', columns: ['Operational Benefit', 'Impact', 'Evidence'], rows: report.operationalBenefits.length ? report.operationalBenefits.map((b) => [b.benefit, b.impact, b.evidence]) : [['Evidence Not Available', '-', '-']] }, [26, 34, 40]);

  layout.heading('Executive Maturity Model');
  layout.paragraph(`${report.maturityModel.scale} ${report.maturityModel.note}`, 9, MUTED);
  layout.table({ title: 'Maturity Model', columns: ['Domain', 'Current', 'Target', 'Gap', 'Timeline', 'Invest', 'Owner', 'Dependencies'], rows: report.maturityModel.domains.length ? report.maturityModel.domains.map((d) => [d.domain, d.currentLabel, d.targetLabel, `${d.gap}`, d.timeline, d.investment, d.owner, d.dependencies]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-', '-']] }, [15, 13, 13, 5, 10, 9, 15, 20]);

  layout.heading('Migration Simulation (What-If)');
  layout.table({ title: 'Simulation', columns: ['Scenario', 'Readiness', 'Risk', 'Cost', 'Timeline', 'Confidence'], rows: report.waveSimulation.map((w) => [w.label, `${w.readinessFrom}->${w.readinessTo}`, `${w.riskFrom}->${w.riskTo}`, usd(w.costUsd), `${w.timelineWeeks}w`, `${w.confidencePct}%`]) }, [34, 16, 14, 14, 10, 12]);

  layout.heading('Readiness Progression');
  layout.paragraph('The simulation restated as an executive progression: current readiness, projected readiness after each completed wave, and the programme target. Values reconcile with the simulation above by construction.', 9, MUTED);
  layout.table({ title: 'Readiness Progression', columns: ['Stage', 'Readiness', 'Risk', 'Detail'], rows: report.readinessProgression.length ? report.readinessProgression.map((st) => [st.stage, `${st.readiness}/100`, `${st.risk}/100`, st.detail]) : [['Evidence Not Available', '-', '-', '-']] }, [32, 11, 10, 47]);

  layout.heading('Risk Reduction Forecast');
  layout.table({ title: 'Forecast', columns: ['Metric', 'Value'], rows: [
    ['Current Risk', `${report.riskForecast.currentRisk}/100`], ['Target Risk', `${report.riskForecast.targetRisk}/100`], ['Risk Reduction', `${report.riskForecast.reductionPct}%`],
    ['12-Month (Expected)', `${report.riskForecast.month12}/100`], ['24-Month (Expected)', `${report.riskForecast.month24}/100`], ['36-Month (Expected)', `${report.riskForecast.month36}/100`],
  ] }, [50, 50]);
  if (report.riskForecast.scenarios.length) {
    layout.table({ title: 'Scenario Bands', columns: ['Scenario', '12-Mo', '24-Mo', '36-Mo', 'Planning Assumption'], rows: report.riskForecast.scenarios.map((sc) => [sc.scenario, `${sc.month12}`, `${sc.month24}`, `${sc.month36}`, sc.assumption]) }, [16, 10, 10, 10, 54]);
  }

  layout.heading('Asset-Level Readiness & Intelligence');
  layout.paragraph('Which assets drive the overall readiness score, with the business context and per-asset crypto posture teams need to assign work immediately. Unobserved fields are Evidence Not Available - never fabricated.', 9, MUTED);
  layout.table({ title: 'Asset Readiness', columns: ['Asset', 'Ready', 'Risk', 'Crit', 'Environment', 'Business Unit', 'Owner', 'Net', 'Primary Driver'], rows: report.assetReadiness.length ? report.assetReadiness.map((a) => [a.asset, `${a.readiness}`, `${a.risk}`, a.criticality, a.environment, a.businessUnit, a.owner, a.internetFacing ? 'Y' : 'N', a.primaryDriver]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-', '-', '-']] }, [16, 6, 6, 7, 10, 12, 12, 5, 26]);
  layout.table({ title: 'Asset Crypto Profile', columns: ['Asset', 'TLS Version', 'Cert Expiry', 'Primary Algorithm', 'Key Size', 'PQC Status', 'HNDL Exposure'], rows: report.assetReadiness.length ? report.assetReadiness.map((a) => [a.asset, a.tlsVersion, a.certExpiry, a.primaryAlgorithm, a.keySize, a.pqcStatus, a.hndlExposure]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-']] }, [16, 15, 11, 20, 11, 13, 14]);

  layout.heading('Executive Risk Acceptance');
  layout.paragraph('Formal disposition of residual risk (mitigate / accept / transfer / defer) for governance and audit. Approvals are generated as Pending Executive Sign-off (never fabricated) and are executed against the report digital signature.', 9, MUTED);
  if (report.riskApprovalPolicy.uniform) {
    // Status, date and signature method are identical on every disposition —
    // stated once as policy instead of repeated as four identical cells per row.
    layout.paragraph(`Risk Owner Approval: ${report.riskApprovalPolicy.note}`, 9, MUTED);
    layout.table({ title: 'Risk Acceptance', columns: ['Risk', 'Decision', 'Owner', 'Rationale', 'Residual', 'Review', 'Approver'], rows: report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.residualRisk, r.reviewDate, r.approver]) }, [20, 10, 13, 25, 13, 8, 11]);
  } else {
    layout.table({ title: 'Risk Acceptance', columns: ['Risk', 'Decision', 'Owner', 'Rationale', 'Residual', 'Review'], rows: report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.residualRisk, r.reviewDate]) }, [22, 12, 14, 30, 14, 8]);
    layout.table({ title: 'Risk Owner Approval', columns: ['Risk', 'Approver', 'Approval Status', 'Approval Date', 'Signature Method'], rows: report.riskAcceptance.map((r) => [r.risk, r.approver, r.approvalStatus, r.approvalDate, r.approvalMethod]) }, [26, 12, 16, 12, 34]);
  }

  layout.heading('Decision Traceability');
  layout.paragraph(report.decisionChain.headline, 9, INK);
  layout.table({ title: 'Decision Chain', columns: ['Stage', 'Detail'], rows: report.decisionChain.steps.map((st) => [st.stage, st.detail]) }, [20, 80]);

  layout.heading('Program Governance');
  layout.table({ title: 'Governance', columns: ['Role', 'Owner', 'Responsibility'], rows: report.governance.map((g) => [g.role, g.owner, g.responsibility]) }, [22, 24, 54]);
  layout.table({ title: 'Approval Gates', columns: ['Gate', 'Owner', 'Success Criteria'], rows: report.governanceGates.map((g) => [g.gate, g.owner, g.criteria]) }, [24, 18, 58]);

  if (report.evidenceQuality.rows.length) {
    layout.heading('Evidence Quality Score');
    layout.paragraph(report.evidenceQuality.note, 8.5, MUTED);
    layout.table({ title: 'Evidence Quality', columns: ['Evidence Source', 'Grade', 'Confidence', 'Status', 'Note'], rows: report.evidenceQuality.rows.map((r) => [r.source, r.grade, `${r.confidencePct}%`, r.status, r.note]) }, [22, 8, 12, 12, 46]);
    layout.paragraph(`Overall Evidence Grade: ${report.evidenceQuality.overallGrade} (${report.evidenceQuality.gradedSources} contributing source(s), ${report.evidenceQuality.missingSources} missing).`, 9, INK);
  }

  layout.heading('Evidence Confidence Dashboard');
  layout.table({ title: 'Evidence Confidence', columns: ['Source', 'Coverage', 'Completeness', 'Freshness', 'Confidence', 'Note'], rows: report.evidenceConfidence.map((e) => [e.source, `${e.coveragePct}%`, `${e.completenessPct}%`, e.freshness, `${e.confidencePct}%`, e.note || '-']) }, [22, 14, 16, 16, 14, 18]);

  layout.heading('Report Explainability');
  for (const x of report.explainability) {
    layout.table({ title: x.metric, columns: [x.metric, ''], rows: [
      ['What was calculated?', x.what],
      ['How was it calculated?', x.how],
      ['Which evidence was used?', x.evidence],
      ['Why does it matter?', x.why],
      ['What action should be taken?', x.action],
    ] }, [26, 74]);
  }

  layout.heading('Terminology & Definitions');
  layout.table({ title: 'Definitions', columns: ['Term', 'Definition'], rows: report.definitions.length ? report.definitions.map((d) => [d.term, d.definition]) : [['Evidence Not Available', '-']] }, [24, 76]);

  layout.heading(`Report Validation — ${report.reportValidation.overall}`);
  layout.table({ title: 'Validation', columns: ['Validation Check', 'Result', 'Detail'], rows: report.reportValidation.checks.length ? report.reportValidation.checks.map((c) => [c.check, c.status === 'pass' ? 'PASS' : 'FAIL', c.detail]) : [['Evidence Not Available', '-', '-']] }, [24, 10, 66]);
  layout.paragraph(report.reportValidation.note, 8.5, MUTED);

  layout.heading('Evidence Sources');
  layout.paragraph(`Evidence contributed by: ${report.evidence.sources.length ? report.evidence.sources.map((s) => `[x] ${s}`).join('   ') : 'Evidence Not Available'}`, 9, INK);
  if (report.evidence.unavailableSources.length) {
    layout.paragraph(`Not available (no telemetry - contributed no evidence): ${report.evidence.unavailableSources.map((s) => `- ${s}`).join('   ')}`, 9, MUTED);
  }
  layout.paragraph(report.evidence.notes, 9, MUTED);
  if (report.integrity) layout.paragraph(`Integrity (${report.integrity.algorithm}): ${report.integrity.hash}`, 8, MUTED);

  // ---- Executive Certification Summary (I4#9) — dedicated closing page ----
  const cert = report.certification;
  layout.newPage();
  layout.heading('Executive Certification Summary');
  layout.ensure(26);
  const statusColor = cert.certified ? rgb(0.09, 0.64, 0.29) : rgb(0.2, 0.25, 0.33);
  const statusText = san(cert.certificationStatus);
  layout.page.drawRectangle({ x: MARGIN, y: layout.y - 18, width: bold.widthOfTextAtSize(statusText, 11) + 20, height: 22, color: statusColor });
  layout.page.drawText(statusText, { x: MARGIN + 10, y: layout.y - 11, size: 11, font: bold, color: WHITE });
  layout.y -= 32;
  layout.table({ title: 'Certification Snapshot', columns: ['Measure', 'Value'], rows: [
    ['Overall Quantum Readiness', `${cert.overallReadiness}/100 (${cert.readinessLevel || '-'})`],
    ['Assessment Evidence Confidence', `${cert.assessmentConfidencePct}%`],
    ['Migration Forecast Confidence', `${cert.migrationForecastConfidencePct}%`],
    ['Projected Residual Risk', `${cert.residualRisk}/100 (${cert.residualRiskLevel || '-'})`],
    ['Migration Status', cert.migrationStatus],
    ['Assessment Scope', cert.scopeStatement],
  ] }, [34, 66]);
  if (cert.milestones.length) {
    layout.table({ title: 'Migration Milestones', columns: ['Milestone', 'Window', 'Approval Gate'], rows: cert.milestones.map((ms) => [ms.milestone, ms.window, ms.gate || '-']) }, [40, 22, 38]);
  }
  if (cert.criteria.length) {
    layout.table({ title: 'Certification Criteria', columns: ['Certification Criterion', 'Required', 'Measured', 'Met'], rows: cert.criteria.map((c) => [c.criterion, c.required, c.actual, c.met ? 'YES' : 'NO']) }, [40, 18, 28, 14]);
  }
  layout.paragraph(cert.attestation, 9, rgb(0.2, 0.25, 0.33));
  layout.paragraph(`Digitally signed by: ${cert.signedBy || 'Evidence Not Available'} (${cert.signedRole || '-'})${report.integrity ? `   |   Signed at: ${new Date(report.integrity.signedAt).toLocaleString()}` : ''}`, 9.5, INK);
  if (report.integrity) {
    layout.paragraph(`Report integrity (${report.integrity.algorithm}): ${report.integrity.hash}`, 8.5, MUTED);
    const verifyUrl = reportVerificationUrl(report);
    if (verifyUrl) {
      layout.qr(qrMatrix(verifyUrl), 118);
      layout.paragraph(cert.verificationHint, 8.5, MUTED);
      layout.paragraph(`Verification URL: ${verifyUrl.split('?')[0]}?token=...`, 8, MUTED);
    }
  } else {
    layout.paragraph('The integrity hash, digital signature and verification QR code are attached when the report is signed at generation time.', 8.5, MUTED);
  }

  // ---- Header / footer / watermark on every page (skip watermark on cover) ----
  const pages = doc.getPages();
  pages.forEach((page, index) => {
    const { width, height } = page.getSize();
    if (index > 0) {
      page.drawText(san(branding.classification), { x: 90, y: 360, size: 70, font: bold, color: INK, opacity: 0.04, rotate: degrees(-35) });
      page.drawText(san(branding.companyName), { x: MARGIN, y: height - 28, size: 8, font, color: MUTED });
      page.drawText(san(branding.classification), { x: width - MARGIN - font.widthOfTextAtSize(san(branding.classification), 8), y: height - 28, size: 8, font, color: MUTED });
    }
    page.drawLine({ start: { x: MARGIN, y: 42 }, end: { x: width - MARGIN, y: 42 }, thickness: 0.5, color: LINE });
    page.drawText(san(`${meta.title} - v${meta.version}`), { x: MARGIN, y: 30, size: 8, font, color: MUTED });
    const pageLabel = `Page ${index + 1} of ${pages.length}`;
    page.drawText(pageLabel, { x: width - MARGIN - font.widthOfTextAtSize(pageLabel, 8), y: 30, size: 8, font, color: MUTED });
  });

  const bytes = await doc.save();
  return new Blob([bytes as BlobPart], { type: 'application/pdf' });
}
