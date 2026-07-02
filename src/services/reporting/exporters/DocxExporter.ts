import {
  AlignmentType,
  Document,
  Footer,
  Header,
  HeadingLevel,
  ImageRun,
  Packer,
  PageNumber,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
  BorderStyle,
} from 'docx';
import type { EnterpriseAssessmentReport, ReportTable } from '../schemas/ReportSchema';

function dataUrlToBytes(dataUrl: string): Uint8Array {
  const base64 = dataUrl.split(',')[1] || '';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Read intrinsic PNG dimensions from the IHDR chunk (big-endian). */
function pngSize(bytes: Uint8Array): { width: number; height: number } | null {
  if (bytes.length < 24 || bytes[0] !== 0x89 || bytes[1] !== 0x50) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { width: view.getUint32(16), height: view.getUint32(20) };
}

/** Fit a logo into a box preserving aspect ratio. */
function logoFit(bytes: Uint8Array, maxW = 170, maxH = 64): { width: number; height: number } {
  const size = pngSize(bytes);
  if (!size || !size.width || !size.height) return { width: maxW, height: maxH };
  const scale = Math.min(maxW / size.width, maxH / size.height);
  return { width: Math.round(size.width * scale), height: Math.round(size.height * scale) };
}

const INK = '0F172A';
const MUTED = '64748B';

function heading(text: string): Paragraph {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 120 }, children: [new TextRun({ text, color: INK, bold: true })] });
}

function para(text: string, color = '334155'): Paragraph {
  return new Paragraph({ spacing: { after: 120 }, children: [new TextRun({ text, color, size: 21 })] });
}

function docTable(table: ReportTable): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: {
      top: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
      bottom: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
      left: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
      right: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
      insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: 'EDF2F7' },
      insideVertical: { style: BorderStyle.SINGLE, size: 1, color: 'EDF2F7' },
    },
    rows: [
      new TableRow({
        tableHeader: true,
        children: table.columns.map((column) => new TableCell({ shading: { fill: '0F172A' }, children: [new Paragraph({ children: [new TextRun({ text: String(column), bold: true, color: 'FFFFFF', size: 18 })] })] })),
      }),
      ...table.rows.map((row) => new TableRow({ children: row.map((cell) => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: String(cell), size: 18, color: '334155' })] })] })) })),
    ],
  });
}

function chartParagraphs(report: EnterpriseAssessmentReport): Paragraph[] {
  const out: Paragraph[] = [];
  for (const chart of report.charts) {
    try {
      out.push(new Paragraph({ spacing: { before: 160, after: 40 }, children: [new ImageRun({ type: 'png', data: dataUrlToBytes(chart.dataUrl), transformation: { width: 460, height: 260 } })] }));
      out.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 }, children: [new TextRun({ text: chart.title, color: MUTED, size: 18, italics: true })] }));
    } catch {
      out.push(para(`${chart.title}: Evidence Not Available`, MUTED));
    }
  }
  return out;
}

/**
 * Programmatic DOCX export with branded cover, running header/footer + page
 * numbers, KPI/finding/compliance/roadmap tables and embedded chart images.
 */
export async function exportDocx(report: EnterpriseAssessmentReport): Promise<Blob> {
  const { branding, meta } = report;

  const coverChildren: Paragraph[] = [];
  if (branding.companyLogo) {
    try {
      const logoBytes = dataUrlToBytes(branding.companyLogo);
      coverChildren.push(new Paragraph({ spacing: { after: 240 }, children: [new ImageRun({ type: 'png', data: logoBytes, transformation: logoFit(logoBytes, 170, 64) })] }));
    } catch {
      /* logo not embeddable */
    }
  }
  coverChildren.push(
    new Paragraph({ spacing: { after: 80 }, children: [new TextRun({ text: branding.classification, bold: true, color: 'FFFFFF', size: 16, highlight: 'black' })] }),
    new Paragraph({ spacing: { before: 200, after: 60 }, children: [new TextRun({ text: meta.title, bold: true, size: 52, color: INK })] }),
    new Paragraph({ spacing: { after: 240 }, children: [new TextRun({ text: `${branding.companyName}${branding.businessUnit ? ` — ${branding.businessUnit}` : ''}`, size: 26, color: MUTED })] }),
    para(`Report ID: ${meta.id}`, MUTED),
    para(`Version: ${meta.version}  |  Generated: ${new Date(meta.generatedAt).toLocaleString()}  |  By: ${meta.generatedBy}`, MUTED),
    para(`Report Owner: ${branding.reportOwner || 'Evidence Not Available'}  |  Reviewer: ${branding.reviewer || 'Evidence Not Available'}`, MUTED),
  );

  const kpiTable: ReportTable = { title: 'KPIs', columns: ['KPI', 'Value', 'Level'], rows: report.kpis.map((kpi) => [kpi.label, `${kpi.value}${kpi.unit || ''}`, kpi.level || '—']) };
  const findingsTable: ReportTable = {
    title: 'Findings',
    columns: ['ID', 'Severity', 'Asset', 'Current -> Recommended', 'Owner', 'Target', 'Cost', 'Risk-'],
    rows: report.findings.length
      ? report.findings.map((f) => [f.id, f.severity.toUpperCase(), f.affectedAssets.join(', ') || '-', `${f.currentState} -> ${f.recommendedState}`, f.owner, f.targetDate, f.estimatedCostUsd ? `$${f.estimatedCostUsd.toLocaleString()}` : '-', `${f.riskReductionPct}%`])
      : [['-', '-', 'Evidence Not Available', '-', '-', '-', '-', '-']],
  };
  const complianceTable: ReportTable = { title: 'Compliance', columns: ['Framework', 'Control', 'Status', 'Current', 'Target', 'Gap', 'Progress'], rows: report.compliance.map((c) => [c.framework, c.control, c.status, `${c.currentPct}%`, `${c.targetPct}%`, `${c.gapPct} pts`, `${c.progressPct}% complete`]) };
  const roadmapTable: ReportTable = { title: 'Roadmap & Program Plan', columns: ['Phase', 'Start', 'Finish', 'Wks', 'Milestone', 'Approval Gate', 'Critical', 'Slack'], rows: report.roadmap.map((p) => [p.phase, p.startDate, p.endDate, p.effortWeeks, p.milestone || '-', p.gate || '-', p.criticalPath ? 'Yes' : 'No', `${p.slackWeeks}w`]) };
  const ex = report.executiveBlock;
  const usd = (n: number) => (n ? `$${Math.round(n).toLocaleString()}` : 'Evidence Not Available');
  const stateTable: ReportTable = { title: 'Current vs Target', columns: ['Metric', 'Current', 'Target', 'Improvement'], rows: [
    ['Quantum Readiness', `${ex.currentReadiness}/100`, `${ex.targetReadiness}/100`, `+${Math.max(0, ex.targetReadiness - ex.currentReadiness)}`],
    ['Quantum Risk', `${ex.currentRisk}/100`, `${ex.targetRisk}/100`, `-${ex.expectedRiskReductionPct}%`],
    ['HNDL Exposure', `${ex.currentHndl}/100`, `${ex.targetHndl}/100`, `-${Math.max(0, ex.currentHndl - ex.targetHndl)}`],
    ['Migration Timeline', '-', `${ex.estimatedDurationWeeks || 'TBD'} weeks`, ''],
    ['Migration Budget', '-', usd(ex.estimatedCostUsd), ''],
  ] };
  const businessTable: ReportTable = { title: 'Business Impact', columns: ['Dimension', 'Value'], rows: [
    ['Customer-Facing Systems', report.businessImpact.customerFacingSystems], ['Mission-Critical Systems', report.businessImpact.missionCriticalSystems],
    ['Third-Party Dependencies', report.businessImpact.thirdPartyDependencies], ['Revenue Impact', report.businessImpact.revenueImpact],
    ['Compliance Impact', report.businessImpact.complianceImpact], ['Financial Impact', report.businessImpact.financialImpact],
    ['HNDL Exposure', report.businessImpact.hndlExposure], ['Quantum Exposure Window', report.businessImpact.quantumExposureWindow],
  ] };
  const domainsTable: ReportTable = { title: 'Readiness Domains', columns: ['Domain', 'Current', 'Target', 'Risk', 'Owner', 'Target Rationale'], rows: report.readinessDomains.map((d) => [d.domain, `${d.score}/100`, `${d.targetScore}/100`, d.riskLevel, d.owner, d.targetRationale]) };
  const advisorTable: ReportTable = { title: 'AI Migration Advisor', columns: ['Risk Reduction', 'Est. Cost', 'Timeline', 'Complexity', 'Confidence'], rows: [[`${report.migrationAdvisor.riskReductionPct}%`, usd(report.migrationAdvisor.costUsd), `${report.migrationAdvisor.timelineWeeks}w`, report.migrationAdvisor.complexity, `${report.migrationAdvisor.confidencePct}%`]] };
  const readinessTable: ReportTable = { title: 'Migration Readiness', columns: ['Category', 'Score', 'Recommendation'], rows: report.migrationReadiness.map((m) => [m.category, `${m.score}/100`, m.recommendation]) };
  const wavesTable: ReportTable = { title: 'Migration Waves', columns: ['Wave', 'Focus', 'Priority', 'Owner', 'Duration', 'Cost', 'Risk Reduction', 'Status'], rows: report.migrationWaves.map((w) => [`Wave ${w.wave}`, w.name, w.priority, w.owner, `${w.durationWeeks}w`, usd(w.costUsd), `${w.riskReductionPct}%`, w.status]) };
  const depTable: ReportTable = { title: 'Dependencies', columns: ['Dependency Chain', 'Blast Radius', 'Complexity'], rows: report.dependencyAnalysis.chains.map((c) => [c.path, c.blastRadius, c.complexity]) };
  const riskCatTable: ReportTable = { title: 'Risk Categories', columns: ['Category', 'Current', 'Target', 'Reduction Potential'], rows: report.riskCategories.map((r) => [r.category, `${r.currentScore}/100`, `${r.targetScore}/100`, `${r.reductionPotentialPct}%`]) };
  const hndlCatTable: ReportTable = { title: 'HNDL Categories', columns: ['Data Category', 'Retention', 'Current Protection', 'Risk', 'Recommended'], rows: report.hndl.categories.map((h) => [h.category, h.retention, h.currentProtection, h.hndlRisk, h.recommendedProtection]) };
  const remediationTable: ReportTable = { title: 'Remediation Program', columns: ['Pri', 'Action', 'Owner', 'Cost', 'Risk Reduction', 'Target Date', 'Status'], rows: report.remediationProgram.map((r) => [r.priority, r.action, r.owner, usd(r.costUsd), `${r.riskReductionPct}%`, r.targetDate, r.status]) };
  const costTable: ReportTable = { title: 'Cost Forecast', columns: ['Category', 'Estimated Cost'], rows: [...report.costForecast.lines.map((l) => [l.category, usd(l.costUsd)]), ['TOTAL', usd(report.costForecast.totalUsd)], ['Projected Risk-Reduction Value', usd(report.costForecast.projectedRiskReductionValueUsd)]] };
  const forecastTable: ReportTable = { title: 'Risk Forecast', columns: ['Metric', 'Value'], rows: [
    ['Current Risk', `${report.riskForecast.currentRisk}/100`], ['Target Risk', `${report.riskForecast.targetRisk}/100`], ['Risk Reduction', `${report.riskForecast.reductionPct}%`],
    ['12-Month', `${report.riskForecast.month12}/100`], ['24-Month', `${report.riskForecast.month24}/100`], ['36-Month', `${report.riskForecast.month36}/100`],
  ] };
  const governanceTable: ReportTable = { title: 'Governance', columns: ['Role', 'Owner', 'Responsibility'], rows: report.governance.map((g) => [g.role, g.owner, g.responsibility]) };
  const topTable: ReportTable = { title: 'Top 5', columns: ['#', 'Top Risk', 'Recommended Action'], rows: Array.from({ length: Math.max(ex.topRisks.length, ex.topActions.length, 1) }).map((_, i) => [i + 1, ex.topRisks[i] || '-', ex.topActions[i] || '-']) };

  // Report Intelligence (Reports_Enhancements_3) tables
  const methodologyTable: ReportTable = { title: 'Risk Methodology', columns: ['Risk Domain', 'Domain Risk', 'Weight', 'Contribution (Risk×Weight)', 'Share'], rows: [...report.riskMethodology.weights.map((w) => [w.domain, `${w.score}/100`, `${w.weightPct}%`, w.contribution.toFixed(1), `${w.contributionPct}%`]), ['OVERALL (Σ Contribution)', `${report.riskMethodology.overall}/100`, '100%', report.riskMethodology.overall.toFixed(1), '100%']] };
  const validationTable: ReportTable = { title: 'Recommendation Validation', columns: ['Validation Factor', 'Evidence'], rows: [
    ['Primary Exposure Domain', report.advisorValidation.primaryExposureDomain],
    ['Expected Risk Reduction', `${report.advisorValidation.expectedRiskReductionPct}%`],
    ['Confidence', `${report.advisorValidation.confidencePct}%`],
    ['Top Contributing Findings', report.advisorValidation.topContributingFindings.join('; ') || 'Evidence Not Available'],
    ['Top Contributing Assets', report.advisorValidation.topContributingAssets.join('; ') || 'Evidence Not Available'],
  ] };
  const confidenceTable: ReportTable = { title: 'Migration Confidence', columns: ['Confidence Factor', 'Coverage'], rows: report.migrationConfidence.factors.map((f) => [f.label, `${f.coveragePct}%`]) };
  const costBreakdownTable: ReportTable = { title: 'Cost Breakdown', columns: ['Category', 'Hours', 'Engineers', 'Rate', 'Cost', 'Formula'], rows: [...report.costBreakdown.lines.map((l) => [l.category, l.hours, l.engineers, usd(l.rateUsd), usd(l.costUsd), l.formula]), ['TOTAL', report.costBreakdown.totalHours, '', '', usd(report.costForecast.totalUsd), '']] };
  const criticalityTable: ReportTable = { title: 'Asset Criticality', columns: ['Asset', 'Business', 'Operational', 'Customer-Facing', 'Internet-Facing', 'Revenue', 'Compliance', 'Data'], rows: report.assetCriticality.length ? report.assetCriticality.map((a) => [a.asset, a.businessCriticality, a.operationalCriticality, a.customerFacing ? 'Yes' : 'No', a.internetFacing ? 'Yes' : 'No', a.revenueImpact, a.complianceScope.join(', '), a.dataSensitivity]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-', '-']] };
  const impactReasonTable: ReportTable = { title: 'Business Impact Intelligence', columns: ['Dimension', 'Level', 'Why', 'Evidence'], rows: report.impactReasons.map((r) => [r.dimension, r.level, r.reason, r.evidence.join('; ')]) };
  const assetReadinessTable: ReportTable = { title: 'Asset-Level Readiness', columns: ['Asset', 'Readiness', 'Risk', 'Posture', 'Internet-Facing', 'Primary Driver', 'Owner'], rows: report.assetReadiness.length ? report.assetReadiness.map((a) => [a.asset, `${a.readiness}/100`, `${a.risk}/100`, a.posture, a.internetFacing ? 'Yes' : 'No', a.primaryDriver, a.owner]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-']] };
  const riskAcceptanceTable: ReportTable = { title: 'Executive Risk Acceptance', columns: ['Risk', 'Decision', 'Owner', 'Rationale', 'Residual Risk', 'Review Date'], rows: report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.residualRisk, r.reviewDate]) };
  const decisionChainTable: ReportTable = { title: 'Decision Traceability', columns: ['Stage', 'Detail'], rows: report.decisionChain.steps.map((st) => [st.stage, st.detail]) };
  const findingGroupTable: ReportTable = { title: 'Consolidated Findings', columns: ['Finding', 'Occurrences', 'Affected Assets', 'Impact', 'Evidence'], rows: report.findingGroups.map((g) => [g.title, g.occurrences, g.affectedAssets, g.impact.toUpperCase(), g.evidence.join(', ') || '-']) };
  const decisionTable: ReportTable = { title: 'Executive Decisions', columns: ['Decision Required', 'Type', 'Rationale', 'Owner'], rows: report.executiveDecisions.map((d) => [d.decision, d.type, d.rationale, d.owner]) };
  const simulationTable: ReportTable = { title: 'Migration Simulation', columns: ['Scenario', 'Readiness', 'Risk', 'Cost', 'Timeline', 'Confidence'], rows: report.waveSimulation.map((w) => [w.label, `${w.readinessFrom} -> ${w.readinessTo}`, `${w.riskFrom} -> ${w.riskTo}`, usd(w.costUsd), `${w.timelineWeeks}w`, `${w.confidencePct}%`]) };
  const gateTable: ReportTable = { title: 'Approval Gates', columns: ['Gate', 'Owner', 'Success Criteria'], rows: report.governanceGates.map((g) => [g.gate, g.owner, g.criteria]) };
  const evidenceConfTable: ReportTable = { title: 'Evidence Confidence', columns: ['Source', 'Coverage', 'Completeness', 'Freshness', 'Confidence', 'Note'], rows: report.evidenceConfidence.map((e) => [e.source, `${e.coveragePct}%`, `${e.completenessPct}%`, e.freshness, `${e.confidencePct}%`, e.note || '-']) };

  // Improvements_02 tables
  const topBusinessRisksTable: ReportTable = { title: 'Top Business Risks', columns: ['#', 'Business Risk', 'Level', 'Evidence Driver'], rows: report.executiveBlock.topBusinessRisks.length ? report.executiveBlock.topBusinessRisks.map((r, i) => [i + 1, r.risk, r.level, r.driver]) : [['-', 'Evidence Not Available', '-', '-']] };
  const readinessIndexTable: ReportTable = { title: 'Quantum Readiness Index', columns: ['Strategic Pillar', 'Score', 'Weight', 'Contribution', 'Primary Driver'], rows: report.readinessIndex.pillars.length ? report.readinessIndex.pillars.map((p) => [p.pillar, typeof p.score === 'number' ? `${p.score}/100` : p.score, p.measured ? `${p.weightPct}%` : '-', p.measured ? p.contribution.toFixed(1) : '-', p.driver]) : [['Evidence Not Available', '-', '-', '-', '-']] };
  const readinessMethodologyTable: ReportTable = { title: 'Readiness Methodology', columns: ['Factor', 'Weight', 'Score', 'Contribution', 'Measurement Basis'], rows: [...report.readinessMethodology.factors.map((f) => [f.factor, f.measured ? `${f.weightPct}%` : 'Excluded', typeof f.score === 'number' ? `${f.score}/100` : f.score, f.measured ? f.contribution.toFixed(1) : '-', f.basis]), ['OVERALL (Σ Contribution)', '100%', `${report.readinessMethodology.overall}/100`, report.readinessMethodology.overall.toFixed(1), '±1 rounding']] };
  const benchmarkingTable: ReportTable = { title: 'Industry Benchmarking', columns: ['Cohort', 'Readiness', 'Delta vs You', 'Source'], rows: report.benchmarking.rows.length ? report.benchmarking.rows.map((b) => [b.cohort, `${b.readiness}/100`, b.delta === 0 ? '-' : `${b.delta > 0 ? '+' : ''}${b.delta}`, b.source]) : [['Evidence Not Available', '-', '-', '-']] };
  const roiTable: ReportTable = { title: 'Executive ROI', columns: ['Value Metric', 'Expected Outcome', 'Basis / Formula'], rows: report.roiAnalysis.lines.length ? report.roiAnalysis.lines.map((l) => [l.metric, l.value, l.basis]) : [['Evidence Not Available', '-', '-']] };
  const resourceLoadingTable: ReportTable = { title: 'Resource Loading', columns: ['Team', 'Waves', 'Hours', 'Engineers', 'Window', 'Allocation', 'Basis'], rows: report.resourceLoading.length ? report.resourceLoading.map((r) => [r.team, r.waves, r.hours, r.engineers, `${r.windowWeeks}w`, `${r.allocationPct}%`, r.basis]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-']] };
  const assetIntelTable: ReportTable = { title: 'Asset Intelligence', columns: ['Asset', 'Owner Dept.', 'Certificates', 'TLS Version', 'Algorithms', 'Key Sizes', 'Dependencies', 'PQC Ready', 'Complexity', 'Est. Hours'], rows: report.assetIntelligence.length ? report.assetIntelligence.map((a) => [a.asset, a.ownerDepartment, a.certificates, a.tlsVersion, a.algorithms.join(', '), a.keySizes.join(', '), a.dependencies.join(', '), `${a.pqcReadinessPct}%`, a.migrationComplexity, a.estimatedHours]) : [['Evidence Not Available', '-', '-', '-', '-', '-', '-', '-', '-', '-']] };
  const cryptoPolicyTable: ReportTable = { title: 'Crypto-Policy Profiles', columns: ['Profile', 'Key Establishment', 'Digital Signature', 'Certificate Chain', 'Symmetric / Hash', 'Guidance'], rows: report.cryptoPolicy.profiles.map((p) => [p.profile === report.cryptoPolicy.activeProfile ? `${p.profile} (ACTIVE)` : p.profile, p.keyEstablishment, p.digitalSignature, p.certificateChain, `${p.symmetric} / ${p.hash}`, p.guidance]) };
  const definitionsTable: ReportTable = { title: 'Terminology & Definitions', columns: ['Term', 'Definition'], rows: report.definitions.length ? report.definitions.map((d) => [d.term, d.definition]) : [['Evidence Not Available', '-']] };
  const reportValidationTable: ReportTable = { title: 'Report Validation', columns: ['Validation Check', 'Result', 'Detail'], rows: report.reportValidation.checks.length ? report.reportValidation.checks.map((c) => [c.check, c.status === 'pass' ? 'PASS' : 'FAIL', c.detail]) : [['Evidence Not Available', '-', '-']] };
  const playbookChildren = report.playbookDetail.flatMap((p) => [
    para(p.finding, INK),
    docTable({ title: 'Playbook', columns: ['Step', 'Detail'], rows: [
      ['Current State', p.currentState], ['Target State', p.targetState], ['Pre-Requisites', p.prerequisites.join('; ')], ['Dependencies', p.dependencies.join('; ')],
      ['Execution', p.executionSteps.map((st, i) => `${i + 1}. ${st}`).join('  ')], ['Validation', p.validationSteps.join('; ')], ['Rollback', p.rollbackSteps.join('; ')], ['Success Criteria', p.successCriteria.join('; ')],
    ] }),
  ]);
  const explainChildren = report.explainability.flatMap((x) => [
    para(x.metric, INK),
    docTable({ title: x.metric, columns: ['Question', 'Answer'], rows: [['What was calculated?', x.what], ['How was it calculated?', x.how], ['Which evidence was used?', x.evidence], ['Why does it matter?', x.why], ['What action should be taken?', x.action]] }),
  ]);

  const doc = new Document({
    creator: branding.companyName,
    title: meta.title,
    sections: [
      {
        properties: {},
        headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: `${branding.companyName} · ${branding.classification}`, color: MUTED, size: 16 })] })] }) },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [new TextRun({ text: `${meta.title} · v${meta.version} · Page `, color: MUTED, size: 16 }), new TextRun({ children: [PageNumber.CURRENT], color: MUTED, size: 16 }), new TextRun({ text: ' of ', color: MUTED, size: 16 }), new TextRun({ children: [PageNumber.TOTAL_PAGES], color: MUTED, size: 16 })],
              }),
            ],
          }),
        },
        children: [
          ...coverChildren,
          heading('Executive Summary'),
          para(report.executiveSummary),
          ...(branding.customNotes ? [para(`Notes: ${branding.customNotes}`, MUTED)] : []),
          docTable(stateTable),
          para(`Executive Recommendation: ${ex.executiveRecommendation}`, INK),
          heading('Top Risks & Recommended Actions'),
          docTable(topTable),
          heading('Top Business Risks'),
          docTable(topBusinessRisksTable),
          heading('Executive Dashboard'),
          docTable(kpiTable),
          heading('Business Impact Analysis'),
          docTable(businessTable),
          heading('Business Impact Intelligence'),
          docTable(impactReasonTable),
          heading('Executive Decision Center'),
          docTable(decisionTable),
          heading('Quantum Readiness Breakdown'),
          docTable(domainsTable),
          heading('Quantum Readiness Index'),
          para(report.readinessIndex.note, MUTED),
          docTable(readinessIndexTable),
          heading('Readiness Scoring Methodology'),
          para(`Formula: ${report.readinessMethodology.formula}`, INK),
          para(report.readinessMethodology.explanation, MUTED),
          docTable(readinessMethodologyTable),
          heading('Industry Benchmarking'),
          para(report.benchmarking.percentileNarrative, MUTED),
          docTable(benchmarkingTable),
          ...(report.benchmarking.note ? [para(report.benchmarking.note, MUTED)] : []),
          heading('AI Migration Advisor'),
          para(`Recommendation: ${report.migrationAdvisor.recommendation}`, INK),
          para(report.migrationAdvisor.reason),
          docTable(advisorTable),
          para(`Why this recommendation: ${report.advisorValidation.why}`, MUTED),
          docTable(validationTable),
          heading('Migration Confidence'),
          para(`Overall Migration Confidence: ${report.migrationConfidence.overallPct}%`, INK),
          docTable(confidenceTable),
          heading('Migration Readiness Assessment'),
          docTable(readinessTable),
          heading('Migration Wave Planning'),
          docTable(wavesTable),
          heading('Migration Dependency Analysis'),
          para(report.dependencyAnalysis.summary, MUTED),
          docTable(depTable),
          heading('Quantum Risk Analysis'),
          docTable(riskCatTable),
          heading('Risk Scoring Methodology'),
          para(`Formula: ${report.riskMethodology.formula}`, INK),
          para(report.riskMethodology.explanation, MUTED),
          docTable(methodologyTable),
          heading('HNDL Exposure Analysis'),
          para(report.hndl.summary),
          docTable(hndlCatTable),
          heading('Visual Analysis'),
          ...chartParagraphs(report),
          heading('Consolidated Findings (Root-Cause)'),
          docTable(findingGroupTable),
          heading('Asset Criticality Analysis'),
          docTable(criticalityTable),
          heading('Asset Intelligence Profile'),
          para('Per-asset cryptographic posture — algorithms, key sizes, TLS profile, dependencies, complexity and effort. Unobserved fields are Evidence Not Available.', MUTED),
          docTable(assetIntelTable),
          // Raw per-instance findings: Technical Assessment only (executive /
          // compliance / migration use the consolidated view above).
          ...(report.meta.kind === 'technical' ? [heading('Technical Appendix — Raw Findings & Evidence'), docTable(findingsTable)] : []),
          heading('Cryptographic & Asset Inventory'),
          docTable(report.assets),
          docTable(report.cbom),
          docTable(report.pqcReadiness.table),
          heading('Compliance Mapping'),
          para('Dynamic gap tracking: Current, Target, Gap and Progress per framework.', MUTED),
          docTable(complianceTable),
          heading('Crypto-Policy Profiles (Target Algorithm Selection)'),
          para(report.cryptoPolicy.note, MUTED),
          docTable(cryptoPolicyTable),
          heading('Remediation Program'),
          docTable(remediationTable),
          heading('Enterprise Remediation Playbook'),
          ...playbookChildren,
          heading('Migration Roadmap & Program Plan'),
          docTable(roadmapTable),
          heading('Migration Resource Loading'),
          para('Team allocation across the programme window — hours, engineers and percentage loading per team.', MUTED),
          docTable(resourceLoadingTable),
          heading('Cost Forecast Intelligence'),
          para(`Blended rate $${report.costBreakdown.blendedRateUsd}/hr — total ${report.costBreakdown.totalHours.toLocaleString()} hours.`, MUTED),
          docTable(costBreakdownTable),
          heading('Executive ROI & Value Intelligence'),
          para(report.roiAnalysis.paybackNarrative, INK),
          docTable(roiTable),
          heading('Migration Simulation (What-If)'),
          docTable(simulationTable),
          heading('Risk Reduction Forecast'),
          docTable(forecastTable),
          heading('Asset-Level Readiness'),
          docTable(assetReadinessTable),
          heading('Executive Risk Acceptance'),
          docTable(riskAcceptanceTable),
          heading('Decision Traceability'),
          para(report.decisionChain.headline, INK),
          docTable(decisionChainTable),
          heading('Program Governance'),
          docTable(governanceTable),
          docTable(gateTable),
          heading('Evidence Confidence Dashboard'),
          docTable(evidenceConfTable),
          heading('Report Explainability'),
          ...explainChildren,
          heading('Terminology & Definitions'),
          docTable(definitionsTable),
          heading(`Report Validation — ${report.reportValidation.overall}`),
          docTable(reportValidationTable),
          para(report.reportValidation.note, MUTED),
          heading('Evidence Sources'),
          para(report.evidence.sources.join(' - '), MUTED),
          para(report.evidence.notes, MUTED),
          ...(report.integrity ? [para(`Integrity (${report.integrity.algorithm}): ${report.integrity.hash}`, MUTED)] : []),
        ],
      },
    ],
  });

  return Packer.toBlob(doc);
}
