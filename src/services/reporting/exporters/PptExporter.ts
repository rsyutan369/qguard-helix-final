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

  // Report Intelligence (Reports_Enhancements_3) board slides
  tableSlide('Risk Scoring Methodology™', ['Risk Domain', 'Weight', 'Score', 'Weighted Contribution'], report.riskMethodology.weights.map((w) => [w.domain, `${w.weightPct}%`, `${w.score}/100`, `${w.contributionPct}%`]), [4.8, 2.5, 2.5, 2.5]);
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

  // Business Impact Intelligence™
  tableSlide('Business Impact Intelligence™', ['Dimension', 'Level', 'Reason'], report.impactReasons.map((r) => [r.dimension, r.level, r.reason]), [2.8, 1.5, 8]);

  // Finding Deduplication™
  tableSlide('Consolidated Findings (Root Cause)™', ['Finding', 'Occurrences', 'Affected Assets', 'Impact'], report.findingGroups.map((g) => [g.title, g.occurrences, g.affectedAssets, g.impact.toUpperCase()]), [6.4, 2, 2.4, 1.5]);

  // Migration Confidence™
  tableSlide(`Migration Confidence™ — Overall ${report.migrationConfidence.overallPct}%`, ['Confidence Factor', 'Coverage'], report.migrationConfidence.factors.map((f) => [f.label, `${f.coveragePct}%`]), [8, 4.3]);

  // Governance Gates™
  tableSlide('Program Governance — Approval Gates™', ['Approval Gate', 'Owner', 'Criteria'], report.governanceGates.map((g) => [g.gate, g.owner, g.criteria]), [3.2, 2.4, 6.7]);

  // Report Explainability™
  tableSlide('Report Explainability™', ['Metric', 'What', 'How', 'Why It Matters', 'Action'], report.explainability.map((e) => [e.metric, e.what, e.how, e.why, e.action]), [2.2, 2.5, 2.6, 2.5, 2.5]);

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

  // Top findings
  const findingsSlide = pptx.addSlide();
  findingsSlide.addText('Top Findings', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
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

  // Roadmap
  const roadmapSlide = pptx.addSlide();
  roadmapSlide.addText('PQC Migration Roadmap', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  const roadmapRows: pptxgen.TableRow[] = [
    [
      { text: 'Phase', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Description', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Status', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Weeks', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
    ],
    ...report.roadmap.map((phase) => [
      { text: phase.phase, options: { bold: true, color: INK } },
      { text: phase.description, options: { color: '334155' } },
      { text: phase.status, options: { color: BRAND } },
      { text: String(phase.effortWeeks), options: { color: '334155', align: 'center' as const } },
    ]),
  ];
  roadmapSlide.addTable(roadmapRows, { x: 0.5, y: 1.1, w: 12.3, colW: [2, 7, 2, 1.3], fontSize: 11, border: { type: 'solid', color: 'E2E8F0', pt: 1 }, valign: 'middle' });
  footer(roadmapSlide);

  const blob = (await pptx.write({ outputType: 'blob' })) as Blob;
  return blob;
}
