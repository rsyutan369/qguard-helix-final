import pptxgen from 'pptxgenjs';
import type { EnterpriseAssessmentReport } from '../schemas/ReportSchema';

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
  footer(cover);

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
  tableSlide('Executive Summary — Current vs Target', ['Metric', 'Current', 'Target', 'Improvement'], [
    ['Quantum Readiness', `${ex.currentReadiness}/100`, `${ex.targetReadiness}/100`, `+${Math.max(0, ex.targetReadiness - ex.currentReadiness)}`],
    ['Quantum Risk', `${ex.currentRisk}/100`, `${ex.targetRisk}/100`, `-${ex.expectedRiskReductionPct}%`],
    ['HNDL Exposure', `${ex.currentHndl}/100`, `${ex.targetHndl}/100`, `-${Math.max(0, ex.currentHndl - ex.targetHndl)}`],
    ['Timeline', '-', `${ex.estimatedDurationWeeks || 'TBD'} weeks`, ''],
    ['Budget', '-', usd(ex.estimatedCostUsd), ''],
  ], [3.6, 2.9, 2.9, 2.9]);

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
  tableSlide('Cost Forecast', ['Category', 'Estimated Cost'], [...report.costForecast.lines.map((l) => [l.category, usd(l.costUsd)]), ['TOTAL', usd(report.costForecast.totalUsd)]], [8, 4.3]);

  // Confidence Overview™ (I3#1) — four distinct confidence measures
  tableSlide('Confidence Overview™', ['Confidence Measure', 'Value', 'What it means'], [
    ['Assessment Confidence', `${report.confidenceSummary.assessmentConfidencePct}%`, 'Completeness of evidence behind the assessment'],
    ['Migration Plan Confidence', `${report.confidenceSummary.migrationPlanConfidencePct}%`, 'Likelihood the plan achieves its target'],
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
  tableSlide('Cost Forecast Intelligence™', ['Category', 'Hours', 'Eng.', 'Cost', 'Formula'], report.costBreakdown.lines.map((l) => [l.category, l.hours, l.engineers, usd(l.costUsd), l.formula]), [2.6, 1.2, 1, 1.8, 5.7]);
  tableSlide('Executive Decision Center™', ['Decision Required', 'Type', 'Owner'], report.executiveDecisions.map((d) => [d.decision, d.type, d.owner]), [6.6, 3.2, 2.5]);
  tableSlide('Migration Simulation (What-If)™', ['Scenario', 'Readiness', 'Risk', 'Cost', 'Timeline', 'Confidence'], report.waveSimulation.map((w) => [w.label, `${w.readinessFrom}→${w.readinessTo}`, `${w.riskFrom}→${w.riskTo}`, usd(w.costUsd), `${w.timelineWeeks}w`, `${w.confidencePct}%`]), [3.7, 2, 1.8, 2, 1.4, 1.4]);
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

  // Asset-Level Readiness (which assets drive the overall score)
  tableSlide('Asset-Level Readiness™', ['Asset', 'Readiness', 'Risk', 'Posture', 'Net', 'Primary Driver'], report.assetReadiness.map((a) => [a.asset, `${a.readiness}/100`, `${a.risk}/100`, a.posture, a.internetFacing ? 'Yes' : 'No', a.primaryDriver]), [3.0, 1.6, 1.4, 2.2, 0.9, 3.2]);

  // Executive Risk Acceptance (residual-risk disposition)
  tableSlide('Executive Risk Acceptance™', ['Risk', 'Decision', 'Owner', 'Rationale', 'Review'], report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.reviewDate]), [3.0, 1.4, 1.8, 4.6, 1.5]);

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

  // Enterprise Remediation Playbook™ — one detailed slide per finding family
  for (const p of report.playbookDetail) {
    const slide = pptx.addSlide();
    slide.addText('Enterprise Remediation Playbook™', { x: 0.5, y: 0.3, w: 12, h: 0.5, fontSize: 22, bold: true, color: INK });
    slide.addText(p.finding, { x: 0.5, y: 0.85, w: 12.3, h: 0.5, fontSize: 14, bold: true, color: BRAND });
    slide.addText([
      { text: 'Current State: ', options: { bold: true, color: INK } }, { text: `${p.currentState}\n`, options: { color: '334155' } },
      { text: 'Target State: ', options: { bold: true, color: INK } }, { text: p.targetState, options: { color: '16A34A' } },
    ], { x: 0.5, y: 1.4, w: 12.3, h: 0.9, fontSize: 12, valign: 'top' });
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

  const blob = (await pptx.write({ outputType: 'blob' })) as Blob;
  return blob;
}
