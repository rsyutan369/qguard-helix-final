import pptxgen from 'pptxgenjs';
import type { EnterpriseAssessmentReport } from '../schemas/ReportSchema';
import { qrPngDataUrl, reportVerificationUrl } from '../ReportQr';

// pptxgenjs ships CJS; depending on the runtime (Vite/browser vs Node ESM) the
// default import resolves either to the constructor or to a { default } wrapper.
// Normalise so `new PptxGenJS()` works in every runtime (browser export + any
// server-side / tooling invocation).
const PptxGenJS = ((pptxgen as unknown as { default?: typeof pptxgen }).default ?? pptxgen);

const INK = '0F172A';
const BRAND = '2478FF';
const MUTED = '64748B';
const SEV_COLOR: Record<string, string> = { critical: 'DC2626', high: 'EA580C', medium: 'D97706', low: '16A34A', info: '2563FF' };

/**
 * Board-ready PPTX deck: cover, KPI summary, visual analysis slides (one per
 * chart), top findings and migration roadmap. Built from the unified model.
 */
export async function exportPptx(report: EnterpriseAssessmentReport): Promise<Blob> {
  const pptx = new PptxGenJS();
  pptx.author = report.branding.companyName;
  pptx.company = report.branding.companyName;
  pptx.title = report.meta.title;
  pptx.layout = 'LAYOUT_WIDE';

  const footer = (slide: pptxgen.Slide) => {
    slide.addText(`${report.branding.companyName} · ${report.branding.classification} · v${report.meta.version}`, { x: 0.4, y: 7.0, w: 12.5, h: 0.3, fontSize: 9, color: MUTED, align: 'left' });
  };

  // Cover
  const cover = pptx.addSlide();
  cover.background = { color: 'F8FAFC' };
  if (report.branding.companyLogo) {
    try {
      cover.addImage({ data: report.branding.companyLogo, x: 0.6, y: 0.5, w: 2.4, h: 0.9, sizing: { type: 'contain', w: 2.4, h: 0.9 } });
    } catch {
      /* logo not embeddable */
    }
  }
  cover.addText(report.branding.classification, { x: 0.6, y: 1.6, w: 3, h: 0.4, fontSize: 11, color: 'FFFFFF', fill: { color: INK }, align: 'center' });
  cover.addText(report.meta.title, { x: 0.6, y: 2.4, w: 12, h: 1.2, fontSize: 40, bold: true, color: INK });
  cover.addText(`${report.branding.companyName}${report.branding.businessUnit ? ` — ${report.branding.businessUnit}` : ''}`, { x: 0.6, y: 3.6, w: 12, h: 0.6, fontSize: 20, color: MUTED });
  cover.addText(`Version ${report.meta.version}  ·  Generated ${new Date(report.meta.generatedAt).toLocaleString()}  ·  ${report.meta.generatedBy}`, { x: 0.6, y: 4.4, w: 12, h: 0.4, fontSize: 12, color: MUTED });
  cover.addText(`Assessment Scope: ${report.scope.type === 'custom' ? `${report.scope.selectedAssetCount} of ${report.scope.totalAssetCount} assets (custom selection)` : `Full assessment (${report.scope.totalAssetCount} asset${report.scope.totalAssetCount === 1 ? '' : 's'})`}`, { x: 0.6, y: 4.9, w: 12, h: 0.4, fontSize: 12, color: MUTED });
  footer(cover);

  // Board Snapshot — 60-second executive view (Improvements_06 §6)
  if (report.boardSnapshot.hasData) {
    const b = report.boardSnapshot;
    const bslide = pptx.addSlide();
    bslide.background = { color: 'F8FAFC' };
    bslide.addText('Board Snapshot — 60-Second Executive View', { x: 0.5, y: 0.3, w: 9.5, h: 0.6, fontSize: 24, bold: true, color: INK });
    bslide.addText(b.certificationStatus, { x: 9.9, y: 0.35, w: 3.4, h: 0.5, fontSize: 12, bold: true, color: 'FFFFFF', fill: { color: b.certified ? '16A34A' : '334155' }, align: 'center' });
    bslide.addText(b.headline, { x: 0.5, y: 0.95, w: 12.3, h: 0.6, fontSize: 13, color: '334155' });
    b.metrics.slice(0, 6).forEach((m, i) => {
      const col = i % 3;
      const row = Math.floor(i / 3);
      const x = 0.5 + col * 4.15;
      const y = 1.7 + row * 1.5;
      bslide.addShape(pptx.ShapeType.roundRect, { x, y, w: 3.95, h: 1.35, fill: { color: 'FFFFFF' }, line: { color: 'E2E8F0', width: 1 }, rectRadius: 0.06 });
      bslide.addText(m.value, { x: x + 0.15, y: y + 0.12, w: 3.7, h: 0.5, fontSize: 20, bold: true, color: INK });
      bslide.addText(m.label, { x: x + 0.15, y: y + 0.62, w: 3.7, h: 0.3, fontSize: 10, color: MUTED });
      bslide.addText(m.context, { x: x + 0.15, y: y + 0.92, w: 3.7, h: 0.35, fontSize: 9.5, color: BRAND });
    });
    bslide.addText([
      { text: 'Top Decisions for the Board\n', options: { bold: true, color: INK, fontSize: 12 } },
      ...(b.topDecisions.length ? b.topDecisions.map((d, i) => ({ text: `${i + 1}. ${d}\n`, options: { color: '334155', fontSize: 11 } })) : [{ text: 'Evidence Not Available', options: { color: MUTED, fontSize: 11 } }]),
    ], { x: 0.5, y: 4.85, w: 7.6, h: 1.9, valign: 'top' });
    bslide.addText([
      { text: 'Executive Recommendation\n', options: { bold: true, color: INK, fontSize: 12 } },
      { text: b.recommendation, options: { color: '334155', fontSize: 11 } },
    ], { x: 8.3, y: 4.85, w: 4.6, h: 1.9, valign: 'top' });
    footer(bslide);
  }

  // KPI summary
  const kpiSlide = pptx.addSlide();
  kpiSlide.addText('Key Performance Indicators', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  report.kpis.slice(0, 8).forEach((kpi, index) => {
    const col = index % 4;
    const row = Math.floor(index / 4);
    const x = 0.5 + col * 3.1;
    const y = 1.3 + row * 2.4;
    kpiSlide.addShape(pptx.ShapeType.roundRect, { x, y, w: 2.9, h: 2.1, fill: { color: 'FFFFFF' }, line: { color: 'E2E8F0', width: 1 }, rectRadius: 0.08 });
    kpiSlide.addText(`${kpi.value}${kpi.unit || ''}`, { x, y: y + 0.3, w: 2.9, h: 0.9, fontSize: 32, bold: true, color: INK, align: 'center' });
    kpiSlide.addText(kpi.label, { x, y: y + 1.2, w: 2.9, h: 0.5, fontSize: 11, color: MUTED, align: 'center' });
    if (kpi.level) kpiSlide.addText(kpi.level, { x, y: y + 1.6, w: 2.9, h: 0.4, fontSize: 11, color: BRAND, align: 'center' });
  });
  footer(kpiSlide);

  // Executive summary
  const summary = pptx.addSlide();
  summary.addText('Executive Summary', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  summary.addText(report.executiveSummary, { x: 0.5, y: 1.1, w: 12.3, h: 5, fontSize: 15, color: '334155', align: 'left', valign: 'top' });
  footer(summary);

  const usd = (n: number) => (n ? `$${Math.round(n).toLocaleString()}` : 'N/A');
  const headerRow = (cols: string[]): pptxgen.TableRow => cols.map((c) => ({ text: c, options: { bold: true, color: 'FFFFFF', fill: { color: INK } } }));
  const tableSlide = (title: string, head: string[], body: Array<Array<string | number>>, colW: number[]) => {
    const slide = pptx.addSlide();
    slide.addText(title, { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
    const rows: pptxgen.TableRow[] = [headerRow(head), ...body.map((r) => r.map((c) => ({ text: String(c), options: { color: '334155' } })))];
    slide.addTable(rows, { x: 0.5, y: 1.1, w: 12.3, colW, fontSize: 10, border: { type: 'solid', color: 'E2E8F0', pt: 1 }, valign: 'middle' });
    footer(slide);
    return slide;
  };

  // Executive current -> target
  const ex = report.executiveBlock;
  // Improvement is stated in POINTS for every row (reductions also annotate the
  // relative %) — one column must never mix points and percent units.
  const hndlDropPct = Math.round(((ex.currentHndl - ex.targetHndl) / Math.max(1, ex.currentHndl)) * 100);
  tableSlide('Executive Summary — Current vs Target', ['Metric', 'Current', 'Target', 'Improvement'], [
    ['Quantum Readiness', `${ex.currentReadiness}/100`, `${ex.targetReadiness}/100`, ex.targetReadiness > ex.currentReadiness ? `+${ex.targetReadiness - ex.currentReadiness} pts` : '—'],
    ['Quantum Risk', `${ex.currentRisk}/100`, `${ex.targetRisk}/100`, ex.currentRisk > ex.targetRisk ? `-${ex.currentRisk - ex.targetRisk} pts (-${ex.expectedRiskReductionPct}%)` : '—'],
    ['HNDL Exposure', `${ex.currentHndl}/100`, `${ex.targetHndl}/100`, ex.currentHndl > ex.targetHndl ? `-${ex.currentHndl - ex.targetHndl} pts (-${hndlDropPct}%)` : '—'],
    ['Timeline', '-', `${ex.estimatedDurationWeeks || 'TBD'} weeks`, ''],
    ['Budget', '-', usd(ex.estimatedCostUsd), ''],
  ], [3.6, 2.9, 2.9, 2.9]);

  // Assessment scope — which assets this report covers (custom selections list
  // the assets; the note slide always states the scope explicitly).
  if (report.scope.type === 'custom') {
    const scopeRows: Array<Array<string | number>> = report.scope.assets.slice(0, 14).map((a) => [a.name, a.assetType, a.environment, `${a.riskScore}/100`, a.posture]);
    if (report.scope.assets.length > 14) scopeRows.push([`… and ${report.scope.assets.length - 14} more selected asset(s)`, '', '', '', '']);
    const scopeSlide = tableSlide(`Assessment Scope — ${report.scope.selectedAssetCount} of ${report.scope.totalAssetCount} Assets`, ['Asset', 'Type', 'Environment', 'Risk', 'Posture'], scopeRows, [4.6, 2.2, 2.2, 1.5, 1.8]);
    scopeSlide.addText(report.scope.note, { x: 0.5, y: 6.4, w: 12.3, h: 0.5, fontSize: 10, color: MUTED });
  }

  // Top Business Risks (I2#8) — board-language risk register
  tableSlide('Top Business Risks', ['#', 'Business Risk', 'Level', 'Evidence Driver'], ex.topBusinessRisks.length ? ex.topBusinessRisks.map((r, i) => [i + 1, r.risk, r.level, r.driver]) : [['-', 'Evidence Not Available', '-', '-']], [0.6, 3.4, 1.3, 7]);

  // Quantum Readiness Index™ (I2#11) — strategic pillars behind the score
  tableSlide(`Quantum Readiness Index™ — Overall ${report.readinessIndex.overall}/100`, ['Strategic Pillar', 'Score', 'Weight', 'Contribution', 'Primary Driver'], report.readinessIndex.pillars.map((p) => [p.pillar, typeof p.score === 'number' ? `${p.score}/100` : p.score, p.measured ? `${p.weightPct}%` : '-', p.measured ? p.contribution.toFixed(1) : '-', p.driver]), [2.6, 1.4, 1.2, 1.5, 5.6]);

  // Readiness Scoring Methodology™ (I2#3) — auditable contribution table
  tableSlide('Readiness Scoring Methodology™', ['Factor', 'Weight', 'Score', 'Contribution', 'Basis'], [...report.readinessMethodology.factors.map((f) => [f.factor, f.measured ? `${f.weightPct}%` : 'Excluded', typeof f.score === 'number' ? `${f.score}/100` : f.score, f.measured ? f.contribution.toFixed(1) : '-', f.basis]), ['OVERALL (Σ)', '100%', `${report.readinessMethodology.overall}/100`, report.readinessMethodology.overall.toFixed(1), '±1 rounding']], [3, 1.3, 1.4, 1.5, 5.1]);

  // Industry Benchmarking™ (I2#9)
  tableSlide('Industry Benchmarking™', ['Cohort', 'Readiness', 'Delta vs You', 'Source'], report.benchmarking.rows.length ? report.benchmarking.rows.map((b) => [b.cohort, `${b.readiness}/100`, b.delta === 0 ? '-' : `${b.delta > 0 ? '+' : ''}${b.delta}`, b.source]) : [['Evidence Not Available', '-', '-', '-']], [4, 1.8, 1.8, 4.7]);

  // AI Migration Advisor
  const adv = pptx.addSlide();
  adv.addText('AI Migration Advisor™', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  adv.addText(report.migrationAdvisor.recommendation, { x: 0.5, y: 1.0, w: 12.3, h: 0.6, fontSize: 20, bold: true, color: BRAND });
  adv.addText(report.migrationAdvisor.reason, { x: 0.5, y: 1.7, w: 12.3, h: 1, fontSize: 14, color: '334155' });
  [['Risk Reduction', `${report.migrationAdvisor.riskReductionPct}%`], ['Est. Cost', usd(report.migrationAdvisor.costUsd)], ['Timeline', `${report.migrationAdvisor.timelineWeeks}w`], ['Confidence', `${report.migrationAdvisor.confidencePct}%`]].forEach(([k, v], i) => {
    const x = 0.5 + i * 3.1;
    adv.addShape(pptx.ShapeType.roundRect, { x, y: 3.0, w: 2.9, h: 1.6, fill: { color: 'FFFFFF' }, line: { color: 'E2E8F0', width: 1 }, rectRadius: 0.08 });
    adv.addText(String(v), { x, y: 3.2, w: 2.9, h: 0.8, fontSize: 26, bold: true, color: INK, align: 'center' });
    adv.addText(String(k), { x, y: 4.0, w: 2.9, h: 0.4, fontSize: 11, color: MUTED, align: 'center' });
  });
  footer(adv);

  // Business impact + Migration waves + Cost forecast
  tableSlide('Business Impact Analysis', ['Dimension', 'Value'], [
    ['Customer-Facing Systems', report.businessImpact.customerFacingSystems], ['Mission-Critical Systems', report.businessImpact.missionCriticalSystems],
    ['Revenue Impact', report.businessImpact.revenueImpact], ['Compliance Impact', report.businessImpact.complianceImpact],
    ['HNDL Exposure', report.businessImpact.hndlExposure], ['Quantum Exposure Window', report.businessImpact.quantumExposureWindow],
  ], [6.1, 6.2]);
  tableSlide('Migration Wave Planning', ['Wave', 'Focus', 'Priority', 'Owner', 'Duration', 'Cost', 'Risk-', 'Status'], report.migrationWaves.map((w) => [`W${w.wave}`, w.name, w.priority, w.owner, `${w.durationWeeks}w`, usd(w.costUsd), `${w.riskReductionPct}%`, w.status]), [1, 2.6, 1.4, 2.3, 1.2, 1.6, 1, 1.2]);

  // Shared Responsibility Assessment™ — ownership-classified migration intelligence.
  if (report.sharedResponsibility.hasData) {
    const sr = report.sharedResponsibility;
    const srDistTotal = Math.max(1, sr.customerControlled + sr.providerControlled + sr.ecosystemDependent);
    const srPct = (n: number) => `${n} (${Math.round((n / srDistTotal) * 100)}%)`;
    tableSlide('Shared Responsibility — Ownership Readiness', ['Ownership Domain', 'Readiness', 'Findings'], [
      ['Overall', `${sr.readiness.overall}/100`, `${sr.customerControlled + sr.providerControlled + sr.ecosystemDependent}`],
      ['Customer-Controlled', `${sr.readiness.customer}/100`, `${sr.customerControlled}`],
      ['Provider-Controlled', `${sr.readiness.provider}/100`, `${sr.providerControlled}`],
      ['Ecosystem-Dependent', `${sr.readiness.ecosystem}/100`, `${sr.ecosystemDependent}`],
    ], [4, 2.5, 2.5]);
    // §1 summary + §4 timeline
    const srSummarySlide = tableSlide('Shared Responsibility Summary & Timeline', ['Ownership Domain', 'Findings (share)', 'Timeline Status', 'Readiness'],
      sr.timeline.map((t) => {
        const count = t.domain.startsWith('Customer') ? sr.customerControlled : t.domain.startsWith('Provider') ? sr.providerControlled : sr.ecosystemDependent;
        return [t.domain, srPct(count), t.label, `${t.readiness}/100`];
      }), [3.4, 2.6, 3.5, 2.8]);
    if (sr.reconciliationNote) srSummarySlide.addText(`Finding-count reconciliation: ${sr.reconciliationNote}`, { x: 0.5, y: 6.1, w: 12.3, h: 0.8, fontSize: 9.5, color: MUTED, valign: 'top' });
    const srMatrixSlide = tableSlide('Shared Responsibility Matrix', ['Finding', 'Asset', 'Owner', 'Action', 'Inst', 'Pri', 'Status'], sr.matrix.slice(0, 12).map((m) => [m.finding, m.asset, m.owner, m.action, `${m.occurrences}`, m.priority, m.status]), [2.4, 1.9, 1.6, 2.8, 0.7, 1, 1.4]);
    srMatrixSlide.addText(`One row per cryptographic exposure, owner and asset — ${sr.matrix.length} consolidated row(s) covering ${sr.matrixInstances} raw scanner instance(s).`, { x: 0.5, y: 6.1, w: 12.3, h: 0.5, fontSize: 9.5, color: MUTED, valign: 'top' });
    tableSlide('Dependency-Ordered Roadmap (7 Waves)', ['Wave', 'Focus', 'Ownership', 'Findings', 'Status', 'Timeline'], sr.waves.map((w) => [`W${w.wave}`, w.name, w.domain, `${w.findingCount}`, w.status, w.timeline]), [0.9, 2.6, 1.8, 1.2, 1.4, 2]);
  }
  tableSlide('Cost Forecast', ['Category', 'Estimated Cost'], [...report.costForecast.lines.map((l) => [l.category, usd(l.costUsd)]), ['TOTAL', usd(report.costForecast.totalUsd)]], [8, 4.3]);

  // Confidence Overview™ (I3#1 / I4#1) — five distinct confidence measures
  tableSlide('Confidence Overview™', ['Confidence Measure', 'Value', 'What it means'], [
    ['Assessment Evidence Confidence', `${report.confidenceSummary.assessmentConfidencePct}%`, 'Completeness of evidence behind the assessment'],
    ['Migration Plan Confidence', `${report.confidenceSummary.migrationPlanConfidencePct}%`, 'Likelihood the plan achieves its target'],
    ['Migration Forecast Confidence', `${report.confidenceSummary.migrationForecastConfidencePct}%`, 'Confidence in the entire-programme simulation outcome'],
    ['Wave Confidence (range)', report.confidenceSummary.waveConfidenceRange, 'Per-wave execution confidence (declines across waves)'],
    ['Evidence Confidence', `${report.confidenceSummary.evidenceConfidencePct}%`, 'Mean quality across evidence sources'],
  ], [3.2, 1.8, 7.3]);

  // Executive ROI & Value Intelligence™ (I2#4 / I3#2 configurable assumption)
  tableSlide('Executive ROI & Value Intelligence™', ['Value Metric', 'Expected Outcome', 'Basis / Formula'], report.roiAnalysis.lines.length ? report.roiAnalysis.lines.map((l) => [l.metric, l.value, l.basis]) : [['Evidence Not Available', '-', '-']], [2.8, 3.6, 5.9]);

  // Operational Benefits (I3#8) — non-financial value beyond ROI
  tableSlide('Operational Benefits (Beyond ROI)', ['Operational Benefit', 'Impact', 'Evidence'], report.operationalBenefits.length ? report.operationalBenefits.map((b) => [b.benefit, b.impact, b.evidence]) : [['Evidence Not Available', '-', '-']], [3.2, 4.1, 5]);

  // Executive Maturity Model™ (I3#9) — CMMI-style current→target per domain
  tableSlide('Executive Maturity Model™', ['Domain', 'Current', 'Target', 'Gap', 'Timeline', 'Invest', 'Owner'], report.maturityModel.domains.length ? report.maturityModel.domains.map((d) => [d.domain, d.currentLabel, d.targetLabel, `${d.gap}`, d.timeline, d.investment, d.owner]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-']], [2.4, 1.9, 1.9, 0.7, 1.5, 1.4, 2.5]);

  // Migration Resource Loading™ (I2#5 / I3#5 capacity + dependencies)
  tableSlide('Migration Resource Loading™', ['Team', 'Waves', 'Hrs', 'Eng.', 'Window', 'Avail', 'Alloc', 'Dependencies'], report.resourceLoading.length ? report.resourceLoading.map((r) => [r.team, r.waves, r.hours, r.engineers, `${r.windowWeeks}w`, `${r.availabilityPct}%`, `${r.allocationPct}%`, r.dependencies.join(', ')]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-', '-']], [1.9, 2.9, 0.9, 0.8, 1.1, 1, 1, 2.7]);

  // Report Intelligence (Reports_Enhancements_3) board slides
  tableSlide('Risk Scoring Methodology™', ['Risk Domain', 'Domain Risk', 'Weight', 'Contribution', 'Share'], [...report.riskMethodology.weights.map((w) => [w.domain, `${w.score}/100`, `${w.weightPct}%`, w.contribution.toFixed(1), `${w.contributionPct}%`]), ['OVERALL = Σ Contribution', `${report.riskMethodology.overall}/100`, '100%', report.riskMethodology.overall.toFixed(1), '100%']], [4.3, 2.3, 2, 2.2, 1.5]);

  // Executive Risk Heat Map (Improvements_06 §2) — 5×5 colored grid
  if (report.executiveHeatMap.hasData) {
    const h = report.executiveHeatMap;
    const hs = pptx.addSlide();
    hs.addText('Executive Risk Heat Map', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
    const ZONE: Record<string, string> = { critical: 'B91C1C', high: 'EA580C', medium: 'D97706', low: '65A30D', minimal: '16A34A' };
    const gridX = 2.6;
    const gridY = 1.6;
    const cellW = 1.95;
    const cellH = 0.92;
    hs.addText('Business Impact ↓', { x: 0.4, y: gridY + 2, w: 2, h: 0.4, fontSize: 10, bold: true, color: MUTED });
    h.likelihoodLabels.forEach((l, ci) => hs.addText(l, { x: gridX + ci * cellW, y: gridY - 0.45, w: cellW, h: 0.4, fontSize: 9, color: MUTED, align: 'center' }));
    h.impactLabels.forEach((imp, ri) => {
      hs.addText(imp, { x: 0.5, y: gridY + ri * cellH, w: 2, h: cellH, fontSize: 10, bold: true, color: '334155', align: 'right', valign: 'middle' });
      const row = h.cells.filter((c) => c.impact === imp).sort((a, b) => a.likelihoodRank - b.likelihoodRank);
      row.forEach((c, ci) => {
        const x = gridX + ci * cellW;
        const y = gridY + ri * cellH;
        hs.addShape(pptx.ShapeType.rect, { x, y, w: cellW - 0.08, h: cellH - 0.08, fill: { color: c.count ? (ZONE[c.level] || '94A3B8') : 'F1F5F9' }, line: { color: 'FFFFFF', width: 1 } });
        if (c.count) hs.addText(String(c.count), { x, y, w: cellW - 0.08, h: cellH - 0.08, fontSize: 16, bold: true, color: 'FFFFFF', align: 'center', valign: 'middle' });
      });
    });
    hs.addText('Quantum Exploitation Likelihood →', { x: gridX, y: gridY + 5 * cellH + 0.1, w: 9, h: 0.4, fontSize: 10, bold: true, color: MUTED });
    hs.addText(h.methodology, { x: 0.5, y: 6.4, w: 12.3, h: 0.5, fontSize: 8.5, color: MUTED });
    footer(hs);
  }

  // Business Priority Matrix (Improvements_06 §3) — 2×2 quadrants
  if (report.businessPriorityMatrix.hasData) {
    const pm = report.businessPriorityMatrix;
    const ps = pptx.addSlide();
    ps.addText('Business Priority Matrix', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
    ps.addText(pm.note, { x: 0.5, y: 0.95, w: 12.3, h: 0.5, fontSize: 11, color: MUTED });
    const QCOL: Record<string, string> = { 'quick-wins': '16A34A', strategic: '2563EB', 'fill-ins': 'D97706', 'long-term': '94A3B8' };
    pm.quadrants.forEach((q, i) => {
      const col = i % 2;
      const row = Math.floor(i / 2);
      const x = 0.5 + col * 6.25;
      const y = 1.6 + row * 2.6;
      ps.addShape(pptx.ShapeType.roundRect, { x, y, w: 6, h: 2.4, fill: { color: 'FFFFFF' }, line: { color: QCOL[q.key] || 'E2E8F0', width: 1.5 }, rectRadius: 0.06 });
      ps.addText([{ text: `${q.title}   `, options: { bold: true, fontSize: 14, color: INK } }, { text: q.subtitle, options: { fontSize: 10, color: QCOL[q.key] || MUTED } }], { x: x + 0.2, y: y + 0.15, w: 5.6, h: 0.4 });
      ps.addText(q.items.length ? q.items.slice(0, 5).map((it) => ({ text: `• ${it.name} (${it.riskReductionPct}% risk↓)\n`, options: { fontSize: 10, color: '334155' } })) : [{ text: 'No items in this quadrant.', options: { fontSize: 10, color: MUTED } }], { x: x + 0.2, y: y + 0.65, w: 5.6, h: 1.65, valign: 'top' });
    });
    footer(ps);
  }

  // Remediation Campaigns (Improvements_06 minor §3)
  if (report.remediationCampaigns.campaigns.length) {
    tableSlide('Remediation Campaigns™', ['Pri', 'Campaign', 'Target', 'Findings', 'Occ.', 'Assets', 'Recommended Action'], report.remediationCampaigns.campaigns.map((c) => [c.priority, c.campaign, c.target, c.findingCount, c.occurrences, c.affectedAssets, c.action]), [0.8, 2.4, 2.4, 1, 0.8, 0.9, 4]);
  }
  const costSlide = tableSlide('Cost Forecast Intelligence™', ['Category', 'Hours', '≈ Wks', '≈ FTE', 'Eng.', 'Cost', 'Formula'], report.costBreakdown.lines.map((l) => [l.category, l.hours, l.engineerWeeks, l.fte, l.engineers, usd(l.costUsd), l.formula]), [2.5, 1, 1, 1, 0.8, 1.6, 4.4]);
  costSlide.addText(report.costBreakdown.effortNote, { x: 0.5, y: 6.5, w: 12.3, h: 0.6, fontSize: 10, color: MUTED });
  tableSlide('Executive Decision Center™', ['Decision Required', 'Type', 'Owner'], report.executiveDecisions.map((d) => [d.decision, d.type, d.owner]), [6.6, 3.2, 2.5]);
  tableSlide('Executive Decision Package™', ['Decision Item', 'Value', 'Detail / Source'], report.decisionPackage.length ? report.decisionPackage.map((d) => [d.item, d.value, d.detail]) : [['Evidence Not Available', '-', '-']], [2.2, 3, 7.1]);
  tableSlide('Migration Simulation (What-If)™', ['Scenario', 'Readiness', 'Risk', 'Cost', 'Timeline', 'Confidence'], report.waveSimulation.map((w) => [w.label, `${w.readinessFrom}→${w.readinessTo}`, `${w.riskFrom}→${w.riskTo}`, usd(w.costUsd), `${w.timelineWeeks}w`, `${w.confidencePct}%`]), [3.7, 2, 1.8, 2, 1.4, 1.4]);

  // Readiness Progression (I4#2) — executive wording for the simulation
  tableSlide('Readiness Progression', ['Stage', 'Readiness', 'Risk', 'Detail'], report.readinessProgression.length ? report.readinessProgression.map((st) => [st.stage, `${st.readiness}/100`, `${st.risk}/100`, st.detail]) : [['Evidence Not Available', '-', '-', '-']], [4.2, 1.4, 1.3, 5.4]);
  if (report.evidenceQuality.rows.length) {
    const eq = tableSlide('Evidence Quality Score™', ['Evidence Source', 'Grade', 'Confidence', 'Status', 'Note'], report.evidenceQuality.rows.map((r) => [r.source, r.grade, `${r.confidencePct}%`, r.status, r.note]), [3, 1.2, 1.6, 1.6, 5]);
    eq.addText(`Overall Evidence Grade: ${report.evidenceQuality.overallGrade} · ${report.evidenceQuality.gradedSources} contributing, ${report.evidenceQuality.missingSources} missing.`, { x: 0.5, y: 6.4, w: 12.3, h: 0.4, fontSize: 10, color: INK });
  }
  tableSlide('Evidence Confidence Dashboard™', ['Source', 'Coverage', 'Completeness', 'Freshness', 'Confidence'], report.evidenceConfidence.map((e) => [e.source, `${e.coveragePct}%`, `${e.completenessPct}%`, e.freshness, `${e.confidencePct}%`]), [3.5, 2.2, 2.5, 2.3, 1.8]);

  // AI Recommendation Validation™ — narrative + evidence
  const val = report.advisorValidation;
  const valSlide = pptx.addSlide();
  valSlide.addText('AI Recommendation Validation™', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  valSlide.addText(`Primary Exposure Domain: ${val.primaryExposureDomain}`, { x: 0.5, y: 1.0, w: 12.3, h: 0.5, fontSize: 16, bold: true, color: BRAND });
  valSlide.addText(val.why, { x: 0.5, y: 1.6, w: 12.3, h: 1.6, fontSize: 13, color: '334155', valign: 'top' });
  valSlide.addText('Top Contributing Findings', { x: 0.5, y: 3.3, w: 6, h: 0.4, fontSize: 13, bold: true, color: INK });
  valSlide.addText((val.topContributingFindings.length ? val.topContributingFindings : ['Evidence Not Available']).map((f) => `• ${f}`).join('\n'), { x: 0.5, y: 3.7, w: 6, h: 2.4, fontSize: 11, color: '334155', valign: 'top' });
  valSlide.addText('Top Contributing Assets', { x: 6.8, y: 3.3, w: 6, h: 0.4, fontSize: 13, bold: true, color: INK });
  valSlide.addText((val.topContributingAssets.length ? val.topContributingAssets : ['Evidence Not Available']).map((a) => `• ${a}`).join('\n'), { x: 6.8, y: 3.7, w: 6, h: 2.0, fontSize: 11, color: '334155', valign: 'top' });
  [['Expected Risk Reduction', `${val.expectedRiskReductionPct}%`], ['Confidence', `${val.confidencePct}%`]].forEach(([k, v], i) => {
    const x = 6.8 + i * 3.1;
    valSlide.addShape(pptx.ShapeType.roundRect, { x, y: 5.8, w: 2.9, h: 1.0, fill: { color: 'FFFFFF' }, line: { color: 'E2E8F0', width: 1 }, rectRadius: 0.08 });
    valSlide.addText(String(v), { x, y: 5.85, w: 2.9, h: 0.6, fontSize: 22, bold: true, color: INK, align: 'center' });
    valSlide.addText(String(k), { x, y: 6.45, w: 2.9, h: 0.3, fontSize: 10, color: MUTED, align: 'center' });
  });
  footer(valSlide);

  // Asset Criticality™
  tableSlide('Asset Criticality Analysis™', ['Asset', 'Business', 'Operational', 'Customer', 'Internet', 'Revenue', 'Data Sensitivity'], report.assetCriticality.map((a) => [a.asset, a.businessCriticality, a.operationalCriticality, a.customerFacing ? 'Yes' : 'No', a.internetFacing ? 'Yes' : 'No', a.revenueImpact, a.dataSensitivity]), [3.4, 1.6, 1.7, 1.4, 1.4, 1.4, 1.8]);

  // Business Impact Intelligence™ (evidence-cited)
  tableSlide('Business Impact Intelligence™', ['Dimension', 'Level', 'Why', 'Evidence'], report.impactReasons.map((r) => [r.dimension, r.level, r.reason, r.evidence.join('; ')]), [2.4, 1.2, 4.4, 4.3]);

  // Asset-Level Readiness (which assets drive the overall score) + I4#3/#7 enrichment
  tableSlide('Asset-Level Readiness™', ['Asset', 'Readiness', 'Risk', 'Criticality', 'Environment', 'Owner', 'Net', 'Primary Driver'], report.assetReadiness.map((a) => [a.asset, `${a.readiness}/100`, `${a.risk}/100`, a.criticality, a.environment, a.owner, a.internetFacing ? 'Yes' : 'No', a.primaryDriver]), [2.4, 1.2, 1, 1.1, 1.3, 1.7, 0.7, 2.9]);
  tableSlide('Asset Crypto Profile™', ['Asset', 'TLS Version', 'Cert Expiry', 'Primary Algorithm', 'Key Size', 'PQC Status', 'HNDL Exposure'], report.assetReadiness.map((a) => [a.asset, a.tlsVersion, a.certExpiry, a.primaryAlgorithm, a.keySize, a.pqcStatus, a.hndlExposure]), [2.3, 1.9, 1.3, 2.4, 1.3, 1.6, 1.5]);

  // Executive Risk Acceptance (residual-risk disposition) + I4#5 approvals
  if (report.riskApprovalPolicy.uniform) {
    // One approval state for every disposition — stated once instead of a
    // second slide of identical rows.
    const acceptanceSlide = tableSlide('Executive Risk Acceptance™', ['Risk', 'Decision', 'Owner', 'Rationale', 'Review', 'Approver'], report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.reviewDate, r.approver]), [2.8, 1.3, 1.7, 3.9, 1.3, 1.5]);
    acceptanceSlide.addText(`Risk Owner Approval: ${report.riskApprovalPolicy.note}`, { x: 0.5, y: 6.1, w: 12.3, h: 0.6, fontSize: 9.5, color: MUTED, valign: 'top' });
  } else {
    tableSlide('Executive Risk Acceptance™', ['Risk', 'Decision', 'Owner', 'Rationale', 'Review'], report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.reviewDate]), [3.0, 1.4, 1.8, 4.6, 1.5]);
    tableSlide('Risk Owner Approval™', ['Risk', 'Approver', 'Approval Status', 'Approval Date', 'Signature Method'], report.riskAcceptance.map((r) => [r.risk, r.approver, r.approvalStatus, r.approvalDate, r.approvalMethod]), [3.2, 1.6, 2, 1.5, 4]);
  }

  // Decision Traceability (Evidence → … → Approval)
  tableSlide('Decision Traceability™', ['Stage', 'Detail'], report.decisionChain.steps.map((s) => [s.stage, s.detail]), [2.4, 10]);

  // Finding Deduplication™
  tableSlide('Consolidated Findings (Root Cause)™', ['Finding', 'Occurrences', 'Affected Assets', 'Impact'], report.findingGroups.map((g) => [g.title, g.occurrences, g.affectedAssets, g.impact.toUpperCase()]), [6.4, 2, 2.4, 1.5]);

  // Assessment Confidence™ (evidence coverage)
  tableSlide(`Assessment Confidence™ — ${report.confidenceSummary.assessmentConfidencePct}% (evidence coverage)`, ['Coverage Factor', 'Coverage'], report.migrationConfidence.factors.map((f) => [f.label, `${f.coveragePct}%`]), [8, 4.3]);

  // Asset Intelligence Profile™ (I3#4 richer per-asset metadata)
  tableSlide('Asset Intelligence Profile™', ['Asset', 'Owner', 'Crit', 'Hosting', 'TLS', 'Primary Algorithm', 'Key', 'PQC'], report.assetIntelligence.length ? report.assetIntelligence.map((a) => [a.asset, a.businessOwner, a.businessCriticality, a.hosting, a.tlsVersion, a.primaryAlgorithm, a.keyLength, `${a.pqcReadinessPct}%`]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-', '-']], [2.6, 1.6, 1, 1.6, 1.4, 2.4, 1.1, 0.7]);

  // Risk Trend Scenarios™ (I3#7 best/expected/worst)
  tableSlide('Risk Trend — Scenario Bands™', ['Scenario', '12-Month', '24-Month', '36-Month', 'Planning Assumption'], report.riskForecast.scenarios.length ? report.riskForecast.scenarios.map((sc) => [sc.scenario, `${sc.month12}/100`, `${sc.month24}/100`, `${sc.month36}/100`, sc.assumption]) : [['Evidence Not Available', '-', '-', '-', '-']], [2, 1.6, 1.6, 1.6, 5.5]);

  // Governance Gates™
  tableSlide('Program Governance — Approval Gates™', ['Approval Gate', 'Owner', 'Criteria'], report.governanceGates.map((g) => [g.gate, g.owner, g.criteria]), [3.2, 2.4, 6.7]);

  // Report Explainability™
  tableSlide('Report Explainability™', ['Metric', 'What', 'How', 'Why It Matters', 'Action'], report.explainability.map((e) => [e.metric, e.what, e.how, e.why, e.action]), [2.2, 2.5, 2.6, 2.5, 2.5]);

  // Crypto-Policy Profiles (I2#12) — policy-driven target algorithm selection
  tableSlide(`Crypto-Policy Profiles — Active: ${report.cryptoPolicy.activeProfile}`, ['Profile', 'Key Establishment', 'Digital Signature', 'Symmetric / Hash', 'Guidance'], report.cryptoPolicy.profiles.map((p) => [p.profile === report.cryptoPolicy.activeProfile ? `${p.profile} (ACTIVE)` : p.profile, p.keyEstablishment, p.digitalSignature, `${p.symmetric} / ${p.hash}`, p.guidance]), [2.2, 2.6, 2.9, 1.9, 2.7]);

  // Report Validation badge (I2#10) — computed, never asserted
  const validationSlide = pptx.addSlide();
  validationSlide.addText('Report Validation', { x: 0.5, y: 0.3, w: 9, h: 0.6, fontSize: 24, bold: true, color: INK });
  validationSlide.addText(`Overall: ${report.reportValidation.overall}`, { x: 9.8, y: 0.35, w: 3, h: 0.5, fontSize: 16, bold: true, color: 'FFFFFF', fill: { color: report.reportValidation.overall === 'PASS' ? '16A34A' : 'DC2626' }, align: 'center' });
  const validationRows: pptxgen.TableRow[] = [
    headerRow(['Validation Check', 'Result', 'Detail']),
    ...report.reportValidation.checks.map((c) => [
      { text: c.check, options: { color: '334155' } },
      { text: c.status === 'pass' ? '✓ PASS' : '✗ FAIL', options: { bold: true, color: c.status === 'pass' ? '16A34A' : 'DC2626' } },
      { text: c.detail, options: { color: '334155' } },
    ]),
  ];
  validationSlide.addTable(validationRows, { x: 0.5, y: 1.1, w: 12.3, colW: [3, 1.3, 8], fontSize: 10, border: { type: 'solid', color: 'E2E8F0', pt: 1 }, valign: 'middle' });
  footer(validationSlide);

  // Enterprise Remediation Playbook™ — the change controls every playbook shares
  // get one slide up front, then one detailed slide per finding family.
  if (report.playbookStandardControls.rows.length) {
    const controlsSlide = tableSlide(
      `Standard Change Controls — All ${report.playbookStandardControls.applies} Playbooks`,
      ['Control', 'Detail'],
      report.playbookStandardControls.rows.map((r) => [r.step, r.detail]),
      [3.2, 9.1],
    );
    controlsSlide.addText(report.playbookStandardControls.note, { x: 0.5, y: 6.1, w: 12.3, h: 0.6, fontSize: 9.5, color: MUTED, valign: 'top' });
  }
  for (const p of report.playbookDetail) {
    const slide = pptx.addSlide();
    slide.addText('Enterprise Remediation Playbook™', { x: 0.5, y: 0.3, w: 12, h: 0.5, fontSize: 22, bold: true, color: INK });
    slide.addText(p.finding, { x: 0.5, y: 0.85, w: 12.3, h: 0.5, fontSize: 14, bold: true, color: BRAND });
    slide.addText([
      { text: 'Current State: ', options: { bold: true, color: INK } }, { text: `${p.currentState}\n`, options: { color: '334155' } },
      { text: 'Target State: ', options: { bold: true, color: INK } }, { text: `${p.targetState}\n`, options: { color: '16A34A' } },
      { text: 'Downtime: ', options: { bold: true, color: INK } }, { text: `${p.estimatedDowntime} · `, options: { color: '334155' } },
      { text: 'Window: ', options: { bold: true, color: INK } }, { text: `${p.maintenanceWindow} · `, options: { color: '334155' } },
      { text: 'Rollback: ', options: { bold: true, color: INK } }, { text: `${p.rollbackDuration} · `, options: { color: '334155' } },
      { text: 'Validation: ', options: { bold: true, color: INK } }, { text: `${p.validationOwner} · `, options: { color: '334155' } },
      { text: 'Automation: ', options: { bold: true, color: INK } }, { text: `${p.automationStatus} · `, options: { color: '334155' } },
      { text: 'SLA: ', options: { bold: true, color: INK } }, { text: p.slaImpact, options: { color: '334155' } },
    ], { x: 0.5, y: 1.4, w: 12.3, h: 1.05, fontSize: 10.5, valign: 'top' });
    const block = (title: string, items: string[], x: number, y: number, w: number, h: number) => {
      slide.addText(title, { x, y, w, h: 0.35, fontSize: 12, bold: true, color: INK });
      slide.addText((items.length ? items : ['Evidence Not Available']).map((s, i) => `${i + 1}. ${s}`).join('\n'), { x, y: y + 0.35, w, h, fontSize: 10, color: '334155', valign: 'top' });
    };
    block('Execution Steps', p.executionSteps, 0.5, 2.5, 6.0, 2.0);
    block('Validation Steps', p.validationSteps, 6.8, 2.5, 6.0, 2.0);
    block('Rollback Steps', p.rollbackSteps, 0.5, 4.9, 6.0, 1.6);
    block('Success Criteria', p.successCriteria, 6.8, 4.9, 6.0, 1.6);
    footer(slide);
  }

  // Visual analysis — one slide per chart
  for (const chart of report.charts) {
    const slide = pptx.addSlide();
    slide.addText(chart.title, { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 22, bold: true, color: INK });
    try {
      slide.addImage({ data: chart.dataUrl, x: 2.4, y: 1.1, w: 8.5, h: 5.2, sizing: { type: 'contain', w: 8.5, h: 5.2 } });
    } catch {
      slide.addText('Evidence Not Available', { x: 0.5, y: 3, w: 12, h: 1, fontSize: 18, color: MUTED, align: 'center' });
    }
    footer(slide);
  }

  // Raw per-instance top findings — Technical Assessment deck only. Board /
  // compliance / migration decks already carry the consolidated (root-cause)
  // findings slide, so the raw list would only duplicate it.
  if (report.meta.kind === 'technical') {
    const findingsSlide = pptx.addSlide();
    findingsSlide.addText('Technical Appendix — Raw Findings', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
    const rows: pptxgen.TableRow[] = [
      [
        { text: 'Severity', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
        { text: 'Finding', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
        { text: 'Recommendation', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      ],
      ...(report.findings.length
        ? report.findings.slice(0, 8).map((finding) => [
            { text: finding.severity.toUpperCase(), options: { color: 'FFFFFF', fill: { color: SEV_COLOR[finding.severity] || MUTED }, bold: true } },
            { text: finding.title, options: { color: '334155' } },
            { text: finding.recommendation, options: { color: '334155' } },
          ])
        : [[{ text: 'Evidence Not Available', options: { colspan: 3, color: MUTED } }]]),
    ];
    findingsSlide.addTable(rows, { x: 0.5, y: 1.1, w: 12.3, colW: [1.6, 5, 5.7], fontSize: 11, border: { type: 'solid', color: 'E2E8F0', pt: 1 }, valign: 'middle' });
    footer(findingsSlide);
  }

  // Roadmap & Program Plan (dates, milestones, approval gates, critical path)
  const roadmapSlide = pptx.addSlide();
  roadmapSlide.addText('PQC Migration Roadmap & Program Plan', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  const roadmapRows: pptxgen.TableRow[] = [
    [
      { text: 'Phase', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Start', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Finish', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Wks', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Milestone / Approval Gate', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Crit', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
    ],
    ...report.roadmap.map((phase) => [
      { text: phase.phase, options: { bold: true, color: INK } },
      { text: phase.startDate, options: { color: '334155', align: 'center' as const } },
      { text: phase.endDate, options: { color: '334155', align: 'center' as const } },
      { text: String(phase.effortWeeks), options: { color: '334155', align: 'center' as const } },
      { text: `${phase.milestone} — ${phase.gate}`, options: { color: '334155' } },
      { text: phase.criticalPath ? 'Yes' : 'No', options: { color: phase.criticalPath ? 'B91C1C' : MUTED, align: 'center' as const } },
    ]),
  ];
  roadmapSlide.addTable(roadmapRows, { x: 0.5, y: 1.1, w: 12.3, colW: [2.6, 1.3, 1.3, 0.7, 5.4, 1], fontSize: 10, border: { type: 'solid', color: 'E2E8F0', pt: 1 }, valign: 'middle' });
  footer(roadmapSlide);

  // Executive Certification Summary (I4#9) — closing slide with QR + signature
  const cert = report.certification;
  // I5#4 — dated migration milestone schedule ahead of the certification slide.
  if (cert.milestones.length) {
    tableSlide('Migration Milestones', ['Milestone', 'Window', 'Approval Gate'], cert.milestones.map((ms) => [ms.milestone, ms.window, ms.gate || '-']), [5, 2.6, 4.7]);
  }
  const certSlide = pptx.addSlide();
  certSlide.background = { color: 'F8FAFC' };
  certSlide.addText('Executive Certification Summary', { x: 0.5, y: 0.3, w: 8.6, h: 0.6, fontSize: 24, bold: true, color: INK });
  certSlide.addText(cert.certificationStatus, { x: 9.2, y: 0.35, w: 3.6, h: 0.5, fontSize: 13, bold: true, color: 'FFFFFF', fill: { color: cert.certified ? '16A34A' : '334155' }, align: 'center' });
  const certStats: Array<[string, string]> = [
    ['Quantum Readiness', `${cert.overallReadiness}/100`],
    ['Assessment Confidence', `${cert.assessmentConfidencePct}%`],
    ['Forecast Confidence', `${cert.migrationForecastConfidencePct}%`],
    ['Residual Risk', `${cert.residualRisk}/100`],
  ];
  certStats.forEach(([k, v], i) => {
    const x = 0.5 + i * 3.1;
    certSlide.addShape(pptx.ShapeType.roundRect, { x, y: 1.1, w: 2.9, h: 1.3, fill: { color: 'FFFFFF' }, line: { color: 'E2E8F0', width: 1 }, rectRadius: 0.08 });
    certSlide.addText(v, { x, y: 1.25, w: 2.9, h: 0.7, fontSize: 24, bold: true, color: INK, align: 'center' });
    certSlide.addText(k, { x, y: 1.95, w: 2.9, h: 0.35, fontSize: 10, color: MUTED, align: 'center' });
  });
  const certRows: pptxgen.TableRow[] = [
    headerRow(['Certification Criterion', 'Required', 'Measured', 'Met']),
    ...(cert.criteria.length
      ? cert.criteria.map((c) => [
          { text: c.criterion, options: { color: '334155' } },
          { text: c.required, options: { color: '334155' } },
          { text: c.actual, options: { color: '334155' } },
          { text: c.met ? '✓ Yes' : '✗ No', options: { bold: true, color: c.met ? '16A34A' : 'DC2626' } },
        ])
      : [[{ text: 'Evidence Not Available', options: { colspan: 4, color: MUTED } }]]),
  ];
  certSlide.addTable(certRows, { x: 0.5, y: 2.7, w: 8.4, colW: [3.4, 1.5, 2.3, 1.2], fontSize: 10, border: { type: 'solid', color: 'E2E8F0', pt: 1 }, valign: 'middle' });
  const verifyUrl = reportVerificationUrl(report);
  if (verifyUrl) {
    try {
      const qrPng = await qrPngDataUrl(verifyUrl, 300);
      certSlide.addImage({ data: qrPng, x: 9.4, y: 2.7, w: 1.9, h: 1.9 });
      certSlide.addText('Scan to verify — the decoded SHA3-256 hash must match the printed integrity hash.', { x: 9.2, y: 4.7, w: 3.4, h: 0.8, fontSize: 9, color: MUTED });
    } catch {
      /* QR not embeddable in this runtime */
    }
  }
  certSlide.addText(
    `Digitally signed by: ${cert.signedBy || 'Evidence Not Available'} (${cert.signedRole || '-'})${report.integrity ? `  ·  Signed at: ${new Date(report.integrity.signedAt).toLocaleString()}` : ''}${report.integrity ? `\nReport integrity (${report.integrity.algorithm}): ${report.integrity.hash}` : '\nIntegrity hash and verification QR are attached when the report is signed at generation time.'}\nMigration Status: ${cert.migrationStatus}  ·  Scope: ${cert.scopeStatement}`,
    { x: 0.5, y: 5.6, w: 12.3, h: 1.2, fontSize: 9.5, color: '334155', valign: 'top' },
  );
  footer(certSlide);

  const blob = (await pptx.write({ outputType: 'blob' })) as Blob;
  return blob;
}
