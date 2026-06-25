import { PDFDocument, PDFFont, PDFPage, StandardFonts, degrees, rgb, type RGB } from 'pdf-lib';
import type { EnterpriseAssessmentReport, ReportTable } from '../schemas/ReportSchema';

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

/**
 * pdf-lib StandardFonts use WinAnsi (CP1252) and cannot encode arbitrary
 * Unicode. Map common glyphs to ASCII and drop anything outside Latin-1 so
 * evidence-derived text never breaks PDF generation.
 */
function san(value: unknown): string {
  return String(value ?? '')
    .replace(/[→⇒]/g, '->')
    .replace(/[←⇐]/g, '<-')
    .replace(/[↔⇔]/g, '<->')
    .replace(/™/g, '(TM)')
    .replace(/®/g, '(R)')
    .replace(/©/g, '(C)')
    .replace(/[•·]/g, '-')
    .replace(/[–—]/g, '-')
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/…/g, '...')
    .replace(/≥/g, '>=')
    .replace(/≤/g, '<=')
    // eslint-disable-next-line no-control-regex
    .replace(/[^\x00-\xFF]/g, '');
}

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
  ];
  for (const line of metaLines) {
    cover.drawText(san(line), { x: MARGIN, y: cy, size: 9.5, font, color: rgb(0.2, 0.25, 0.33) });
    cy -= 16;
  }
  cover.drawLine({ start: { x: MARGIN, y: 90 }, end: { x: A4[0] - MARGIN, y: 90 }, thickness: 2, color: BRAND });

  // ---- Body (board-level migration program structure) ----
  const ex = report.executiveBlock;
  const usd = (n: number) => (n ? `$${Math.round(n).toLocaleString()}` : 'Evidence Not Available');
  const layout = new PdfLayout(doc, font, bold);

  layout.heading('Executive Summary');
  layout.paragraph(report.executiveSummary);
  if (branding.customNotes) layout.paragraph(`Notes: ${branding.customNotes}`, 9, MUTED);
  layout.table({ title: 'Current vs Target', columns: ['Metric', 'Current', 'Target', 'Improvement'], rows: [
    ['Quantum Readiness', `${ex.currentReadiness}/100`, `${ex.targetReadiness}/100`, `+${Math.max(0, ex.targetReadiness - ex.currentReadiness)}`],
    ['Quantum Risk', `${ex.currentRisk}/100`, `${ex.targetRisk}/100`, `-${ex.expectedRiskReductionPct}%`],
    ['HNDL Exposure', `${ex.currentHndl}/100`, `${ex.targetHndl}/100`, `-${Math.max(0, ex.currentHndl - ex.targetHndl)}`],
    ['Migration Timeline', '—', `${ex.estimatedDurationWeeks || 'TBD'} weeks`, ''],
    ['Migration Budget', '—', usd(ex.estimatedCostUsd), ''],
    ['Quantum Exposure Window', '—', ex.quantumExposureWindow, ''],
  ] }, [34, 22, 22, 22]);
  layout.heading('Top Risks & Recommended Actions');
  layout.table({ title: 'Top 5', columns: ['# ', 'Top Risk', 'Recommended Action'], rows: Array.from({ length: Math.max(ex.topRisks.length, ex.topActions.length) }).map((_, i) => [i + 1, ex.topRisks[i] || '—', ex.topActions[i] || '—']) }, [6, 47, 47]);
  layout.paragraph(`Executive Recommendation: ${ex.executiveRecommendation}`, 9.5, INK);

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
  layout.table({ title: 'Business Impact Intelligence', columns: ['Dimension', 'Level', 'Why (evidence-based)'], rows: report.impactReasons.map((r) => [r.dimension, r.level, r.reason]) }, [22, 12, 66]);

  layout.heading('Executive Decision Center');
  layout.table({ title: 'Decisions', columns: ['Decision Required', 'Type', 'Owner'], rows: report.executiveDecisions.map((d) => [d.decision, d.type, d.owner]) }, [54, 26, 20]);

  layout.heading('Quantum Readiness Breakdown');
  layout.table({ title: 'Domains', columns: ['Domain', 'Score', 'Risk', 'Owner', 'Recommended Action'], rows: report.readinessDomains.map((d) => [d.domain, `${d.score}`, d.riskLevel, d.owner, d.actions]) }, [16, 8, 10, 18, 48]);

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

  layout.heading('Migration Confidence');
  layout.paragraph(`Overall Migration Confidence: ${report.migrationConfidence.overallPct}%`, 10, INK);
  layout.table({ title: 'Confidence', columns: ['Confidence Factor', 'Coverage'], rows: report.migrationConfidence.factors.map((f) => [f.label, `${f.coveragePct}%`]) }, [70, 30]);

  layout.heading('Migration Readiness Assessment');
  layout.table({ title: 'Readiness', columns: ['Category', 'Score', 'Recommendation'], rows: report.migrationReadiness.map((m) => [m.category, `${m.score}/100`, m.recommendation]) }, [26, 12, 62]);

  layout.heading('Migration Wave Planning');
  layout.table({ title: 'Waves', columns: ['Wave', 'Focus', 'Pri', 'Owner', 'Dur', 'Cost', 'Risk-', 'Status'], rows: report.migrationWaves.map((w) => [`W${w.wave}`, w.name, w.priority, w.owner, `${w.durationWeeks}w`, usd(w.costUsd), `${w.riskReductionPct}%`, w.status]) }, [7, 22, 11, 20, 8, 14, 8, 10]);

  layout.heading('Migration Dependency Analysis');
  layout.paragraph(report.dependencyAnalysis.summary, 9, MUTED);
  layout.table({ title: 'Dependencies', columns: ['Dependency Chain', 'Blast Radius', 'Complexity'], rows: report.dependencyAnalysis.chains.map((c) => [c.path, c.blastRadius, c.complexity]) }, [64, 18, 18]);

  layout.heading('Quantum Risk Analysis');
  layout.table({ title: 'Risk Categories', columns: ['Category', 'Current', 'Target', 'Reduction Potential'], rows: report.riskCategories.map((r) => [r.category, `${r.currentScore}`, `${r.targetScore}`, `${r.reductionPotentialPct}%`]) }, [40, 18, 18, 24]);

  layout.heading('Risk Scoring Methodology');
  layout.paragraph(`Formula: ${report.riskMethodology.formula}`, 9, INK);
  layout.paragraph(report.riskMethodology.explanation, 9, MUTED);
  layout.table({ title: 'Risk Methodology', columns: ['Risk Domain', 'Weight', 'Score', 'Weighted Contribution'], rows: report.riskMethodology.weights.map((w) => [w.domain, `${w.weightPct}%`, `${w.score}`, `${w.contributionPct}%`]) }, [40, 16, 16, 28]);

  layout.heading('HNDL Exposure Analysis');
  layout.paragraph(report.hndl.summary);
  layout.table({ title: 'HNDL', columns: ['Data Category', 'Retention', 'Current', 'Risk', 'Recommended'], rows: report.hndl.categories.map((h) => [h.category, h.retention, h.currentProtection, h.hndlRisk, h.recommendedProtection]) }, [22, 18, 22, 10, 28]);

  layout.heading('Visual Analysis');
  for (const chart of report.charts) await layout.image(chart.dataUrl, layout.contentW * 0.62, 200, chart.title);

  layout.heading('Consolidated Findings (Root-Cause)');
  layout.table({ title: 'Finding Groups', columns: ['Finding', 'Occ.', 'Assets', 'Impact', 'Evidence'], rows: report.findingGroups.map((g) => [g.title, g.occurrences, g.affectedAssets, g.impact.toUpperCase(), g.evidence.join(', ') || '-']) }, [26, 8, 10, 12, 44]);

  layout.heading('Asset Criticality Analysis');
  layout.table({ title: 'Asset Criticality', columns: ['Asset', 'Business', 'Cust.', 'Internet', 'Revenue', 'Compliance', 'Data'], rows: report.assetCriticality.length ? report.assetCriticality.map((a) => [a.asset, a.businessCriticality, a.customerFacing ? 'Y' : 'N', a.internetFacing ? 'Y' : 'N', a.revenueImpact, a.complianceScope.join(', '), a.dataSensitivity]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-']] }, [24, 12, 8, 10, 12, 22, 12]);

  layout.heading('Findings & Evidence');
  layout.findings(report);

  layout.heading('Cryptographic & Asset Inventory');
  layout.table(report.assets, [26, 14, 16, 20, 12, 12]);
  layout.table(report.cbom, [60, 40]);
  layout.table(report.pqcReadiness.table, [60, 40]);

  layout.heading('Compliance Mapping');
  layout.table({ title: 'Compliance', columns: ['Framework', 'Control', 'Status', 'Current -> Target / Gap'], rows: report.compliance.map((c) => [c.framework, c.control, c.status, c.detail]) }, [16, 28, 12, 44]);

  layout.heading('Remediation Program');
  layout.table({ title: 'Remediation', columns: ['Pri', 'Action', 'Owner', 'Cost', 'Risk-', 'Target'], rows: report.remediationProgram.map((r) => [r.priority, r.action, r.owner, usd(r.costUsd), `${r.riskReductionPct}%`, r.targetDate]) }, [6, 40, 18, 14, 8, 14]);

  layout.heading('Migration Roadmap');
  layout.table({ title: 'Roadmap', columns: ['Phase', 'Description', 'Status', 'Weeks'], rows: report.roadmap.map((p) => [p.phase, p.description, p.status, p.effortWeeks]) }, [26, 48, 14, 12]);

  layout.heading('Enterprise Remediation Playbook');
  for (const p of report.playbookDetail) {
    layout.paragraph(p.finding, 10, INK);
    layout.table({ title: 'Playbook', columns: ['Step', 'Detail'], rows: [
      ['Current State', p.currentState],
      ['Target State', p.targetState],
      ['Pre-Requisites', p.prerequisites.join('; ')],
      ['Execution', p.executionSteps.map((st, i) => `${i + 1}. ${st}`).join('  ')],
      ['Validation', p.validationSteps.join('; ')],
      ['Rollback', p.rollbackSteps.join('; ')],
      ['Success Criteria', p.successCriteria.join('; ')],
    ] }, [18, 82]);
  }

  layout.heading('Cost Forecast Intelligence');
  layout.paragraph(`Blended rate $${report.costBreakdown.blendedRateUsd}/hr - total ${report.costBreakdown.totalHours.toLocaleString()} hours.`, 9, MUTED);
  layout.table({ title: 'Cost Breakdown', columns: ['Category', 'Hours', 'Eng.', 'Rate', 'Cost', 'Formula'], rows: [...report.costBreakdown.lines.map((l) => [l.category, l.hours, l.engineers, usd(l.rateUsd), usd(l.costUsd), l.formula]), ['TOTAL', report.costBreakdown.totalHours, '', '', usd(report.costForecast.totalUsd), '']] }, [22, 10, 8, 12, 16, 32]);

  layout.heading('Migration Simulation (What-If)');
  layout.table({ title: 'Simulation', columns: ['Scenario', 'Readiness', 'Risk', 'Cost', 'Timeline', 'Confidence'], rows: report.waveSimulation.map((w) => [w.label, `${w.readinessFrom}->${w.readinessTo}`, `${w.riskFrom}->${w.riskTo}`, usd(w.costUsd), `${w.timelineWeeks}w`, `${w.confidencePct}%`]) }, [34, 16, 14, 14, 10, 12]);

  layout.heading('Risk Reduction Forecast');
  layout.table({ title: 'Forecast', columns: ['Metric', 'Value'], rows: [
    ['Current Risk', `${report.riskForecast.currentRisk}/100`], ['Target Risk', `${report.riskForecast.targetRisk}/100`], ['Risk Reduction', `${report.riskForecast.reductionPct}%`],
    ['12-Month', `${report.riskForecast.month12}/100`], ['24-Month', `${report.riskForecast.month24}/100`], ['36-Month', `${report.riskForecast.month36}/100`],
  ] }, [50, 50]);

  layout.heading('Program Governance');
  layout.table({ title: 'Governance', columns: ['Role', 'Owner', 'Responsibility'], rows: report.governance.map((g) => [g.role, g.owner, g.responsibility]) }, [22, 24, 54]);
  layout.table({ title: 'Approval Gates', columns: ['Gate', 'Owner', 'Success Criteria'], rows: report.governanceGates.map((g) => [g.gate, g.owner, g.criteria]) }, [24, 18, 58]);

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

  layout.heading('Evidence Sources');
  layout.paragraph(report.evidence.sources.join(' - '), 9, MUTED);
  layout.paragraph(report.evidence.notes, 9, MUTED);
  if (report.integrity) layout.paragraph(`Integrity (${report.integrity.algorithm}): ${report.integrity.hash}`, 8, MUTED);

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
