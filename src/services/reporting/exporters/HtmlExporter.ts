import type { EnterpriseAssessmentReport, ReportTable } from '../schemas/ReportSchema';

/** HTML-escape all dynamic, evidence-derived strings to prevent injection. */
function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const SEV_COLOR: Record<string, string> = { critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#16A34A', info: '#2563EB' };
const usd = (n: number) => (n ? `$${Math.round(n).toLocaleString()}` : 'Evidence Not Available');

/** Inline HTML progress bar (I3#6) — filled proportional to pct, 0-100. */
function progressBar(pct: number): string {
  const p = Math.max(0, Math.min(100, Math.round(pct)));
  const color = p >= 75 ? '#16A34A' : p >= 40 ? '#D97706' : '#DC2626';
  return `<div style="display:flex;align-items:center;gap:8px"><div style="flex:1;min-width:80px;height:8px;background:#E2E8F0;border-radius:4px;overflow:hidden"><div style="width:${p}%;height:100%;background:${color}"></div></div><span style="font-size:11px;color:#475569">${p}%</span></div>`;
}

function tableHtml(table: ReportTable): string {
  return `<h3>${esc(table.title)}</h3><table><thead><tr>${table.columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${table.rows
    .map((row) => `<tr>${row.map((cell) => `<td>${esc(cell)}</td>`).join('')}</tr>`)
    .join('')}</tbody></table>`;
}

function gridTable(columns: string[], rows: Array<Array<string | number>>): string {
  return `<table><thead><tr>${columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${rows
    .map((row) => `<tr>${row.map((cell) => `<td>${esc(cell)}</td>`).join('')}</tr>`)
    .join('')}</tbody></table>`;
}

/** Board-level Enterprise Quantum Readiness & Migration Program Report (HTML). */
export function exportHtml(report: EnterpriseAssessmentReport): Blob {
  const { branding, meta, executiveBlock: ex, scope } = report;
  const logo = branding.companyLogo ? `<img class="logo" src="${esc(branding.companyLogo)}" alt="logo" />` : '';

  const kpis = report.kpis
    .map((kpi) => `<div class="kpi"><div class="kpi-v">${esc(kpi.value)}${esc(kpi.unit || '')}</div><div class="kpi-l">${esc(kpi.label)}</div>${kpi.level ? `<div class="kpi-x">${esc(kpi.level)}</div>` : ''}</div>`)
    .join('');

  const stateCard = (label: string, current: string | number, target: string | number, unit = '') =>
    `<div class="state"><div class="state-l">${esc(label)}</div><div class="state-row"><span class="cur">${esc(current)}${esc(unit)}</span><span class="arrow">&rarr;</span><span class="tgt">${esc(target)}${esc(unit)}</span></div></div>`;

  const findings = report.findings.length
    ? report.findings
        .map(
          (f) => `<div class="finding"><div class="f-head"><span class="sev" style="background:${SEV_COLOR[f.severity]}">${esc(f.severity)}</span><strong>${esc(f.id)} — ${esc(f.title)}</strong><span class="cplx">${esc(f.migrationComplexity)}</span></div>
      <div class="f-grid">
        <div><b>Affected Asset:</b> ${esc(f.affectedAssets.join(', ') || 'Evidence Not Available')}</div>
        <div><b>Current State:</b> ${esc(f.currentState)}</div>
        <div><b>Recommended State:</b> ${esc(f.recommendedState)}</div>
        <div><b>Business Impact:</b> ${esc(f.businessImpact)}</div>
        <div><b>Technical Impact:</b> ${esc(f.technicalImpact)}</div>
        <div><b>Dependencies:</b> ${esc(f.dependencies.join(', ') || '—')}</div>
        <div><b>Owner:</b> ${esc(f.owner)}</div>
        <div><b>Target Date:</b> ${esc(f.targetDate)}</div>
        <div><b>Estimated Effort:</b> ${esc(f.estimatedEffort)}</div>
        <div><b>Estimated Cost:</b> ${esc(usd(f.estimatedCostUsd))}</div>
        <div><b>Risk Reduction:</b> ${esc(f.riskReductionPct)}%</div>
        <div><b>Validation:</b> ${esc(f.validation)}</div>
      </div></div>`,
        )
        .join('')
    : '<p class="muted">Evidence Not Available — no findings recorded.</p>';

  const charts = report.charts.map((c) => `<figure><img src="${esc(c.dataUrl)}" alt="${esc(c.title)}" /><figcaption>${esc(c.title)}</figcaption></figure>`).join('');

  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>${esc(meta.title)}</title>
<style>
  :root { --ink:#0F172A; --muted:#64748B; --line:#E2E8F0; --brand:#2478FF; --bg:#F8FAFC; }
  * { box-sizing: border-box; }
  body { font-family: Inter, 'Segoe UI', Arial, sans-serif; color: var(--ink); margin: 0; line-height:1.5; }
  .page { max-width: 940px; margin: 0 auto; padding: 40px 48px; }
  .cover { min-height: 72vh; display:flex; flex-direction:column; align-items:flex-start; justify-content:center; border-bottom: 3px solid var(--brand); }
  .logo { align-self:flex-start; display:block; width:auto; height:auto; max-height:72px; max-width:280px; object-fit:contain; margin-bottom:24px; }
  .classification { display:inline-block; align-self:flex-start; background:#0F172A; color:#fff; font-size:11px; letter-spacing:.12em; padding:4px 10px; border-radius:4px; margin-bottom:18px; }
  h1 { font-size: 34px; margin: 0 0 8px; }
  h2 { font-size: 19px; margin: 38px 0 12px; border-bottom: 2px solid var(--line); padding-bottom: 6px; color:#0F172A; }
  h3 { font-size: 14px; margin: 20px 0 8px; color: #334155; }
  .sub { color: var(--muted); font-size: 14px; }
  .meta-grid { display:grid; grid-template-columns: repeat(2, 1fr); gap: 8px 24px; margin-top: 24px; font-size: 13px; color:#334155; }
  .kpis { display:grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 14px 0; }
  .kpi { border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
  .kpi-v { font-size: 24px; font-weight: 700; } .kpi-l { font-size: 10.5px; text-transform: uppercase; letter-spacing:.05em; color: var(--muted); } .kpi-x { font-size: 11px; color: var(--brand); margin-top:2px; }
  .states { display:grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin:14px 0; }
  .state { border:1px solid var(--line); border-radius:8px; padding:14px; background:var(--bg); }
  .state-l { font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin-bottom:8px; }
  .state-row { display:flex; align-items:center; gap:10px; } .cur { font-size:22px; font-weight:700; color:#DC2626; } .tgt { font-size:22px; font-weight:700; color:#16A34A; } .arrow { color:var(--muted); font-size:18px; }
  .callout { border-left:4px solid var(--brand); background:#EFF6FF; padding:12px 16px; border-radius:0 8px 8px 0; margin:12px 0; font-size:13.5px; }
  .advisor { border:1px solid var(--brand); border-radius:10px; padding:18px; background:linear-gradient(135deg,#EFF6FF,#fff); }
  .advisor .rec { font-size:18px; font-weight:700; color:var(--brand); }
  .advisor .mx { display:grid; grid-template-columns: repeat(4,1fr); gap:10px; margin-top:12px; }
  .advisor .mx div { background:#fff; border:1px solid var(--line); border-radius:6px; padding:8px; }
  .advisor .mx .n { font-size:18px; font-weight:700; } .advisor .mx .k { font-size:10px; text-transform:uppercase; color:var(--muted); }
  table { width:100%; border-collapse: collapse; margin: 8px 0 18px; font-size: 12.5px; }
  th, td { border-bottom:1px solid var(--line); padding: 7px 8px; text-align:left; vertical-align: top; }
  th { background:#F1F5F9; font-size: 10.5px; text-transform: uppercase; letter-spacing:.04em; color:#475569; }
  .two { display:grid; grid-template-columns: 1fr 1fr; gap: 8px 24px; }
  .finding { border:1px solid var(--line); border-radius:8px; padding:12px 14px; margin-bottom:10px; }
  .f-head { display:flex; align-items:center; gap:10px; margin-bottom:8px; } .cplx { margin-left:auto; font-size:10px; background:#F1F5F9; color:#475569; padding:2px 8px; border-radius:10px; }
  .sev { color:#fff; font-size:10px; text-transform:uppercase; padding:2px 8px; border-radius:4px; letter-spacing:.05em; }
  .f-grid { font-size: 12px; color:#334155; display:grid; grid-template-columns: 1fr 1fr; gap:3px 18px; }
  figure { margin: 0 0 18px; border:1px solid var(--line); border-radius:8px; padding:12px; } figure img { max-width: 100%; } figcaption { font-size: 12px; color: var(--muted); margin-top: 6px; text-align:center; }
  .charts { display:grid; grid-template-columns: repeat(2, 1fr); gap:16px; }
  .muted { color: var(--muted); }
  .pill { display:inline-block; font-size:10px; padding:2px 8px; border-radius:10px; font-weight:700; }
  .foot { margin-top: 40px; border-top:1px solid var(--line); padding-top: 12px; font-size: 11px; color: var(--muted); display:flex; justify-content:space-between; }
</style></head><body>
<div class="page">
  <section class="cover">
    ${logo}
    <span class="classification">${esc(branding.classification)}</span>
    <h1>${esc(meta.title)}</h1>
    <div class="sub">${esc(branding.companyName)}${branding.businessUnit ? ` — ${esc(branding.businessUnit)}` : ''}</div>
    <div class="meta-grid">
      <div><b>Report ID:</b> ${esc(meta.id)}</div><div><b>Version:</b> ${esc(meta.version)}</div>
      <div><b>Generated:</b> ${esc(new Date(meta.generatedAt).toLocaleString())}</div><div><b>Generated By:</b> ${esc(meta.generatedBy)}</div>
      <div><b>Report Owner:</b> ${esc(branding.reportOwner || 'Evidence Not Available')}</div><div><b>Reviewer:</b> ${esc(branding.reviewer || 'Evidence Not Available')}</div>
      <div><b>Assessment Scope:</b> ${scope.type === 'custom' ? `${esc(scope.selectedAssetCount)} of ${esc(scope.totalAssetCount)} assets (custom selection)` : `Full assessment (${esc(scope.totalAssetCount || 'all')} asset${scope.totalAssetCount === 1 ? '' : 's'})`}</div>
    </div>
  </section>

  <h2>Executive Summary</h2>
  <p>${esc(report.executiveSummary)}</p>
  ${branding.customNotes ? `<p class="muted"><b>Notes:</b> ${esc(branding.customNotes)}</p>` : ''}
  <div class="states">
    ${stateCard('Quantum Readiness', ex.currentReadiness, ex.targetReadiness, '/100')}
    ${stateCard('Quantum Risk', ex.currentRisk, ex.targetRisk, '/100')}
    ${stateCard('HNDL Exposure', ex.currentHndl, ex.targetHndl, '/100')}
  </div>
  <div class="two">
    <div><h3>Top Risks</h3><ol>${ex.topRisks.map((r) => `<li>${esc(r)}</li>`).join('') || '<li class="muted">Evidence Not Available</li>'}</ol></div>
    <div><h3>Top Recommended Actions</h3><ol>${ex.topActions.map((a) => `<li>${esc(a)}</li>`).join('') || '<li class="muted">Evidence Not Available</li>'}</ol></div>
  </div>
  <h3>Top Business Risks</h3>
  ${gridTable(['#', 'Business Risk', 'Level', 'Evidence Driver'], ex.topBusinessRisks.length ? ex.topBusinessRisks.map((r, i) => [i + 1, r.risk, r.level, r.driver]) : [['—', 'Evidence Not Available', '—', '—']])}
  <div class="callout"><b>Executive Recommendation:</b> ${esc(ex.executiveRecommendation)}<br/><b>Estimated Programme:</b> ${esc(ex.estimatedDurationWeeks || 'TBD')} weeks · ${esc(usd(ex.estimatedCostUsd))} · Expected risk reduction ${esc(ex.expectedRiskReductionPct)}% · Quantum exposure window ${esc(ex.quantumExposureWindow)}.</div>

  <h2>Assessment Scope</h2>
  <p>${esc(scope.note)}</p>
  ${scope.type === 'custom' ? `<p class="muted">${esc(scope.methodology)}</p>
  ${gridTable(['Asset', 'Type', 'Environment', 'Risk Score', 'Posture'], scope.assets.map((a) => [a.name, a.assetType, a.environment, `${a.riskScore}/100`, a.posture]))}` : ''}

  <h2>Executive Dashboard</h2>
  <div class="kpis">${kpis}</div>

  <h2>Business Impact Analysis</h2>
  ${gridTable(['Dimension', 'Value'], [
    ['Customer-Facing Systems', report.businessImpact.customerFacingSystems],
    ['Mission-Critical Systems', report.businessImpact.missionCriticalSystems],
    ['Third-Party Dependencies', report.businessImpact.thirdPartyDependencies],
    ['Revenue Impact', report.businessImpact.revenueImpact],
    ['Operational Impact', report.businessImpact.operationalImpact],
    ['Compliance Impact', report.businessImpact.complianceImpact],
    ['Reputational Impact', report.businessImpact.reputationalImpact],
    ['Financial Impact', report.businessImpact.financialImpact],
    ['HNDL Exposure', report.businessImpact.hndlExposure],
    ['Estimated Quantum Exposure Window', report.businessImpact.quantumExposureWindow],
  ])}

  <h2>Business Impact Intelligence&trade;</h2>
  ${gridTable(['Dimension', 'Level', 'Why', 'Evidence'], report.impactReasons.map((r) => [r.dimension, r.level, r.reason, r.evidence.join('; ') || 'Evidence Not Available']))}

  <h2>Executive Decision Center&trade;</h2>
  <p class="muted">Decisions requiring executive approval, with rationale and accountable owner.</p>
  ${gridTable(['Decision Required', 'Type', 'Rationale', 'Owner'], report.executiveDecisions.map((d) => [d.decision, d.type, d.rationale, d.owner]))}

  <h2>Quantum Readiness Breakdown</h2>
  <p class="muted">Targets are calculated per domain (baseline + internet-facing exposure), not static — the rationale explains each.</p>
  ${gridTable(['Domain', 'Current', 'Target', 'Risk Level', 'Owner', 'Target Rationale'], report.readinessDomains.map((d) => [d.domain, `${d.score}/100`, `${d.targetScore}/100`, d.riskLevel, d.owner, d.targetRationale]))}

  <h2>Quantum Readiness Index&trade;</h2>
  <p class="muted">${esc(report.readinessIndex.note)}</p>
  ${gridTable(['Strategic Pillar', 'Score', 'Weight', 'Contribution', 'Primary Driver'], report.readinessIndex.pillars.length ? report.readinessIndex.pillars.map((p) => [p.pillar, typeof p.score === 'number' ? `${p.score}/100` : p.score, p.measured ? `${p.weightPct}%` : '—', p.measured ? p.contribution.toFixed(1) : '—', p.driver]) : [['Evidence Not Available', '—', '—', '—', '—']])}
  <p><b>Overall Quantum Readiness Index:</b> ${esc(report.readinessIndex.overall)}/100</p>

  <h2>Readiness Scoring Methodology&trade;</h2>
  <p><b>Formula:</b> <code>${esc(report.readinessMethodology.formula)}</code></p>
  <p class="muted">${esc(report.readinessMethodology.explanation)}</p>
  ${gridTable(['Factor', 'Weight', 'Score', 'Contribution (Score×Weight)', 'Measurement Basis'], report.readinessMethodology.factors.map((f) => [f.factor, f.measured ? `${f.weightPct}%` : 'Excluded', typeof f.score === 'number' ? `${f.score}/100` : f.score, f.measured ? f.contribution.toFixed(1) : '—', f.basis]))}
  <p><b>Overall Quantum Readiness = Σ Contribution =</b> ${report.readinessMethodology.factors.filter((f) => f.measured).map((f) => f.contribution.toFixed(1)).join(' + ')} ≈ <b>${esc(report.readinessMethodology.overall)}/100</b></p>

  <h2>Industry Benchmarking&trade;</h2>
  <p class="muted">${esc(report.benchmarking.percentileNarrative)}</p>
  ${gridTable(['Cohort', 'Readiness', 'Delta vs You', 'Source'], report.benchmarking.rows.length ? report.benchmarking.rows.map((b) => [b.cohort, `${b.readiness}/100`, b.delta === 0 ? '—' : `${b.delta > 0 ? '+' : ''}${b.delta}`, b.source]) : [['Evidence Not Available', '—', '—', '—']])}
  ${report.benchmarking.note ? `<p class="muted">${esc(report.benchmarking.note)}</p>` : ''}

  <h2>AI Migration Advisor&trade;</h2>
  <div class="advisor">
    <div class="rec">${esc(report.migrationAdvisor.recommendation)}</div>
    <p class="muted">${esc(report.migrationAdvisor.reason)}</p>
    <div class="mx">
      <div><div class="n">${esc(report.migrationAdvisor.riskReductionPct)}%</div><div class="k">Risk Reduction</div></div>
      <div><div class="n">${esc(usd(report.migrationAdvisor.costUsd))}</div><div class="k">Est. Cost</div></div>
      <div><div class="n">${esc(report.migrationAdvisor.timelineWeeks)}w</div><div class="k">Timeline</div></div>
      <div><div class="n">${esc(report.migrationAdvisor.confidencePct)}%</div><div class="k">Confidence</div></div>
    </div>
    <p class="muted" style="margin-top:10px"><b>Affected Assets:</b> ${esc(report.migrationAdvisor.affectedAssets.join(', ') || 'Evidence Not Available')} · <b>Complexity:</b> ${esc(report.migrationAdvisor.complexity)} · <b>Success Probability:</b> ${esc(report.migrationAdvisor.successProbabilityPct)}%</p>
  </div>

  <h3>Why This Recommendation? (Validation)</h3>
  <p class="muted">${esc(report.advisorValidation.why)}</p>
  ${gridTable(['Validation Factor', 'Evidence'], [
    ['Primary Exposure Domain', report.advisorValidation.primaryExposureDomain],
    ['Expected Risk Reduction', `${report.advisorValidation.expectedRiskReductionPct}%`],
    ['Confidence', `${report.advisorValidation.confidencePct}%`],
    ['Top Contributing Findings', report.advisorValidation.topContributingFindings.join('; ') || 'Evidence Not Available'],
    ['Top Contributing Assets', report.advisorValidation.topContributingAssets.join('; ') || 'Evidence Not Available'],
  ])}

  <h2>Confidence Overview&trade;</h2>
  <p class="muted">${esc(report.confidenceSummary.note)}</p>
  ${gridTable(['Confidence Measure', 'Value', 'What it means'], [
    ['Assessment Confidence', `${report.confidenceSummary.assessmentConfidencePct}%`, 'Completeness of the evidence behind this assessment'],
    ['Migration Plan Confidence', `${report.confidenceSummary.migrationPlanConfidencePct}%`, 'Likelihood the recommended plan achieves its target'],
    ['Wave Confidence (range)', report.confidenceSummary.waveConfidenceRange, 'Per-wave execution confidence (declines across waves)'],
    ['Evidence Confidence', `${report.confidenceSummary.evidenceConfidencePct}%`, 'Mean quality across evidence sources'],
  ])}

  <h2>Assessment Confidence&trade; (Evidence Coverage)</h2>
  <p><b>Overall Assessment Confidence:</b> ${esc(report.confidenceSummary.assessmentConfidencePct)}% — how complete the evidence behind the assessment is.</p>
  ${gridTable(['Coverage Factor', 'Coverage'], report.migrationConfidence.factors.map((f) => [f.label, `${f.coveragePct}%`]))}

  <h2>Migration Readiness Assessment</h2>
  ${gridTable(['Category', 'Score', 'Recommendation'], report.migrationReadiness.map((m) => [m.category, `${m.score}/100`, m.recommendation]))}

  <h2>Migration Wave Planning</h2>
  ${gridTable(['Wave', 'Focus', 'Priority', 'Assets', 'Owner', 'Duration', 'Cost', 'Risk Reduction', 'Status'], report.migrationWaves.map((w) => [
    `Wave ${w.wave}`, w.name, w.priority, w.assets.join(', '), w.owner, `${w.durationWeeks}w`, usd(w.costUsd), `${w.riskReductionPct}%`, w.status,
  ]))}

  <h2>Migration Dependency Analysis</h2>
  <p class="muted">${esc(report.dependencyAnalysis.summary)}</p>
  ${gridTable(['Dependency Chain', 'Blast Radius', 'Complexity'], report.dependencyAnalysis.chains.map((c) => [c.path, c.blastRadius, c.complexity]))}
  <p class="muted"><b>Potential Failure Points:</b> ${esc(report.dependencyAnalysis.failurePoints.join(', '))}</p>

  <h2>Quantum Risk Analysis</h2>
  ${gridTable(['Risk Category', 'Current', 'Target', 'Reduction Potential'], report.riskCategories.map((r) => [r.category, `${r.currentScore}/100`, `${r.targetScore}/100`, `${r.reductionPotentialPct}%`]))}

  <h2>Risk Scoring Methodology&trade;</h2>
  <p><b>Formula:</b> <code>${esc(report.riskMethodology.formula)}</code></p>
  <p class="muted">${esc(report.riskMethodology.explanation)}</p>
  ${gridTable(['Risk Domain', 'Domain Risk', 'Weight', 'Contribution (Risk×Weight)', 'Share'], report.riskMethodology.weights.map((w) => [w.domain, `${w.score}/100`, `${w.weightPct}%`, w.contribution.toFixed(1), `${w.contributionPct}%`]))}
  <p><b>Overall Quantum Risk = Σ Contribution =</b> ${report.riskMethodology.weights.map((w) => w.contribution.toFixed(1)).join(' + ')} = <b>${esc(report.riskMethodology.overall)}/100</b></p>
  <p><b>Top Driver:</b> ${esc(report.riskMethodology.topDriver)}</p>

  <h2>HNDL Exposure Analysis</h2>
  <p>${esc(report.hndl.summary)}</p>
  ${gridTable(['Data Category', 'Retention', 'Current Protection', 'HNDL Risk', 'Recommended Protection'], report.hndl.categories.map((h) => [h.category, h.retention, h.currentProtection, h.hndlRisk, h.recommendedProtection]))}

  <h2>Visual Analysis</h2>
  <div class="charts">${charts || '<p class="muted">Charts unavailable.</p>'}</div>

  <h2>Consolidated Findings (Root-Cause)&trade;</h2>
  <p class="muted">Findings de-duplicated by root cause; raw cipher/algorithm instances are retained as evidence.</p>
  ${gridTable(['Finding', 'Occurrences', 'Affected Assets', 'Impact', 'Evidence'], report.findingGroups.map((g) => [g.title, g.occurrences, g.affectedAssets, g.impact.toUpperCase(), g.evidence.join(', ') || 'Evidence Not Available']))}

  <h2>Asset Criticality Analysis&trade;</h2>
  ${gridTable(['Asset', 'Business', 'Operational', 'Customer-Facing', 'Internet-Facing', 'Revenue Impact', 'Compliance Scope', 'Data Sensitivity'], report.assetCriticality.length ? report.assetCriticality.map((a) => [a.asset, a.businessCriticality, a.operationalCriticality, a.customerFacing ? 'Yes' : 'No', a.internetFacing ? 'Yes' : 'No', a.revenueImpact, a.complianceScope.join(', '), a.dataSensitivity]) : [['Evidence Not Available', '—', '—', '—', '—', '—', '—', '—']])}

  <h2>Asset Intelligence Profile&trade;</h2>
  <p class="muted">Per-asset cryptographic posture, ownership and platform metadata to help technical teams prioritise remediation. Fields the evidence pipeline has not yet observed (OS, platform, hosting, cloud provider, certificate expiry) are shown as Evidence Not Available — never fabricated; deploy an agent/cloud connector to populate them.</p>
  ${gridTable(['Asset', 'Type / Env', 'Business Owner', 'Business Unit', 'Criticality', 'OS / Platform', 'Hosting / Cloud', 'TLS Version', 'Primary Algorithm', 'Key Length', 'Cert Expiry', 'Dependencies', 'PQC Ready', 'Complexity', 'Est. Hours'], report.assetIntelligence.length ? report.assetIntelligence.map((a) => [a.asset, `${a.assetType} / ${a.environment}`, a.businessOwner, a.businessUnit, a.businessCriticality, `${a.os} / ${a.platform}`, `${a.hosting} / ${a.cloudProvider}`, a.tlsVersion, a.primaryAlgorithm, a.keyLength, a.certExpiry, a.dependencies.join(', '), `${a.pqcReadinessPct}%`, a.migrationComplexity, a.estimatedHours]) : [['Evidence Not Available', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—']])}

  ${meta.kind === 'technical' ? `<h2>Technical Appendix &mdash; Raw Findings &amp; Evidence</h2>
  ${findings}` : ''}

  <h2>Cryptographic & Asset Inventory</h2>
  ${tableHtml(report.assets)}
  ${tableHtml(report.cbom)}
  ${tableHtml(report.pqcReadiness.table)}

  <h2>Compliance Mapping</h2>
  <p class="muted">Dynamic gap tracking with a visual progress indicator: Current → Target per framework — not a static status word.</p>
  <table><thead><tr>${['Framework', 'Control', 'Status', 'Current', 'Target', 'Gap', 'Progress'].map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${report.compliance
    .map((c) => `<tr><td>${esc(c.framework)}</td><td>${esc(c.control)}</td><td>${esc(c.status)}</td><td>${esc(c.currentPct)}%</td><td>${esc(c.targetPct)}%</td><td>${esc(c.gapPct)} pts</td><td>${progressBar(c.progressPct)}</td></tr>`)
    .join('')}</tbody></table>

  <h2>Crypto-Policy Profiles (Target Algorithm Selection)</h2>
  <p class="muted">${esc(report.cryptoPolicy.note)}</p>
  ${gridTable(['Profile', 'Key Establishment', 'Digital Signature', 'Certificate Chain', 'Symmetric', 'Hash', 'Guidance'], report.cryptoPolicy.profiles.map((p) => [p.profile === report.cryptoPolicy.activeProfile ? `${p.profile} (ACTIVE)` : p.profile, p.keyEstablishment, p.digitalSignature, p.certificateChain, p.symmetric, p.hash, p.guidance]))}

  <h2>Remediation Program&trade;</h2>
  ${gridTable(['Priority', 'Action', 'Owner', 'Affected Assets', 'Cost', 'Effort', 'Risk Reduction', 'Target Date', 'Status'], report.remediationProgram.map((r) => [
    r.priority, r.action, r.owner, r.affectedAssets.join(', '), usd(r.costUsd), r.effort, `${r.riskReductionPct}%`, r.targetDate, r.status,
  ]))}

  <h2>Migration Roadmap &amp; Program Plan</h2>
  <p class="muted">Sequential dates, milestones, approval gates and critical-path/slack — a true program-management plan.</p>
  ${gridTable(['Phase', 'Start', 'Finish', 'Effort (wks)', 'Milestone', 'Approval Gate', 'Critical Path', 'Slack'], report.roadmap.map((p) => [p.phase, p.startDate, p.endDate, p.effortWeeks, p.milestone || '—', p.gate || '—', p.criticalPath ? 'Yes' : 'No', `${p.slackWeeks}w`]))}

  <h2>Migration Resource Loading&trade;</h2>
  <p class="muted">Per-team resource planning: assumed availability (capacity), derived allocation demand, engineer count and cross-team dependencies. Availability values are standard enterprise planning assumptions; allocation is derived from the wave hours — a team whose allocation approaches or exceeds its availability is over-subscribed.</p>
  ${gridTable(['Team', 'Waves', 'Hours', 'Engineers', 'Window', 'Availability', 'Allocation', 'Dependencies'], report.resourceLoading.length ? report.resourceLoading.map((r) => [r.team, r.waves, r.hours, r.engineers, `${r.windowWeeks}w`, `${r.availabilityPct}%`, `${r.allocationPct}%`, r.dependencies.join(', ')]) : [['Evidence Not Available', '—', '—', '—', '—', '—', '—', '—']])}

  <h2>Enterprise Remediation Playbook&trade;</h2>
  ${report.playbookDetail.length ? report.playbookDetail.map((p) => `<h3>${esc(p.finding)}</h3>${gridTable(['Step', 'Detail'], [
    ['Current State', p.currentState],
    ['Target State', p.targetState],
    ['Pre-Requisites', p.prerequisites.join('; ')],
    ['Dependencies', p.dependencies.join('; ')],
    ['Execution Steps', p.executionSteps.map((st, i) => `${i + 1}. ${st}`).join('  ')],
    ['Validation Steps', p.validationSteps.join('; ')],
    ['Rollback Steps', p.rollbackSteps.join('; ')],
    ['Success Criteria', p.successCriteria.join('; ')],
  ])}`).join('') : '<p class="muted">Evidence Not Available — run a discovery scan to generate the remediation playbook.</p>'}

  <h2>Cost Forecast Intelligence&trade;</h2>
  <p class="muted">Every cost line is derived from labour hours × blended engineer rate ($${esc(report.costBreakdown.blendedRateUsd)}/hr). Total ${esc(report.costBreakdown.totalHours.toLocaleString())} hours.</p>
  ${gridTable(['Category', 'Hours', 'Engineers', 'Rate', 'Cost', 'Formula'], report.costBreakdown.lines.map((l) => [l.category, l.hours, l.engineers, usd(l.rateUsd), usd(l.costUsd), l.formula]))}
  <p><b>Total Migration Cost:</b> ${esc(usd(report.costForecast.totalUsd))} · <b>Projected Risk-Reduction Value:</b> ${esc(usd(report.costForecast.projectedRiskReductionValueUsd))}</p>

  <h2>Executive ROI &amp; Value Intelligence&trade;</h2>
  <div class="callout"><b>ROI Summary:</b> ${esc(report.roiAnalysis.paybackNarrative)}</div>
  ${gridTable(['Value Metric', 'Expected Outcome', 'Basis / Formula'], report.roiAnalysis.lines.length ? report.roiAnalysis.lines.map((l) => [l.metric, l.value, l.basis]) : [['Evidence Not Available', '—', '—']])}
  <p class="muted"><b>ROI assumption (configurable):</b> ${esc(report.roiAnalysis.assumptionBasis)}</p>

  <h2>Operational Benefits (Beyond ROI)</h2>
  <p class="muted">Non-financial business value executives value alongside pure financial return.</p>
  ${gridTable(['Operational Benefit', 'Impact', 'Evidence'], report.operationalBenefits.length ? report.operationalBenefits.map((b) => [b.benefit, b.impact, b.evidence]) : [['Evidence Not Available', '—', '—']])}

  <h2>Executive Maturity Model&trade;</h2>
  <p class="muted">${esc(report.maturityModel.scale)} ${esc(report.maturityModel.note)}</p>
  ${gridTable(['Domain', 'Current', 'Target', 'Gap', 'Timeline', 'Investment', 'Owner', 'Dependencies'], report.maturityModel.domains.length ? report.maturityModel.domains.map((d) => [d.domain, d.currentLabel, d.targetLabel, `${d.gap} level(s)`, d.timeline, d.investment, d.owner, d.dependencies]) : [['Evidence Not Available', '—', '—', '—', '—', '—', '—', '—']])}

  <h2>Migration Simulation (What-If)&trade;</h2>
  ${gridTable(['Scenario', 'Readiness', 'Risk', 'Cost', 'Timeline', 'Confidence'], report.waveSimulation.map((w) => [
    w.label, `${w.readinessFrom} → ${w.readinessTo}`, `${w.riskFrom} → ${w.riskTo}`, usd(w.costUsd), `${w.timelineWeeks}w`, `${w.confidencePct}%`,
  ]))}

  <h2>Risk Reduction Forecast</h2>
  ${gridTable(['Metric', 'Value'], [
    ['Current Risk', `${report.riskForecast.currentRisk}/100`],
    ['Target Risk (after migration waves)', `${report.riskForecast.targetRisk}/100`],
    ['Risk Reduction', `${report.riskForecast.reductionPct}%`],
    ['Residual Risk (after optimization)', `${report.riskForecast.residualRisk}/100`],
    ['12-Month Projection (Expected)', `${report.riskForecast.month12}/100`],
    ['24-Month Projection (Expected)', `${report.riskForecast.month24}/100`],
    ['36-Month Projection (Expected)', `${report.riskForecast.month36}/100`],
  ])}
  ${report.riskForecast.scenarios.length ? `<h3>Scenario Bands (Best / Expected / Worst Case)</h3>
  ${gridTable(['Scenario', '12-Month', '24-Month', '36-Month', 'Planning Assumption'], report.riskForecast.scenarios.map((sc) => [sc.scenario, `${sc.month12}/100`, `${sc.month24}/100`, `${sc.month36}/100`, sc.assumption]))}` : ''}

  <h2>Asset-Level Readiness</h2>
  <p class="muted">Which assets drive the overall readiness score, with their primary risk driver.</p>
  ${gridTable(['Asset', 'Readiness', 'Risk', 'Posture', 'Internet-Facing', 'Primary Driver', 'Owner'], report.assetReadiness.length ? report.assetReadiness.map((a) => [a.asset, `${a.readiness}/100`, `${a.risk}/100`, a.posture, a.internetFacing ? 'Yes' : 'No', a.primaryDriver, a.owner]) : [['Evidence Not Available', '—', '—', '—', '—', '—', '—']])}

  <h2>Executive Risk Acceptance</h2>
  <p class="muted">Formal disposition of residual risk — mitigate, accept, transfer or defer — for governance and audit.</p>
  ${gridTable(['Risk', 'Decision', 'Owner', 'Rationale', 'Residual Risk', 'Review Date'], report.riskAcceptance.length ? report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.residualRisk, r.reviewDate]) : [['Evidence Not Available', '—', '—', '—', '—', '—']])}

  <h2>Decision Traceability</h2>
  <p class="muted">${esc(report.decisionChain.headline)}</p>
  ${gridTable(['Stage', 'Detail'], report.decisionChain.steps.map((st) => [st.stage, st.detail]))}

  <h2>Program Governance</h2>
  ${gridTable(['Role', 'Owner', 'Responsibility'], report.governance.map((g) => [g.role, g.owner, g.responsibility]))}
  <h3>Approval Gates</h3>
  ${gridTable(['Gate', 'Owner', 'Success Criteria'], report.governanceGates.map((g) => [g.gate, g.owner, g.criteria]))}

  <h2>Evidence Confidence Dashboard&trade;</h2>
  ${gridTable(['Evidence Source', 'Coverage', 'Completeness', 'Freshness', 'Confidence', 'Note'], report.evidenceConfidence.map((e) => [e.source, `${e.coveragePct}%`, `${e.completenessPct}%`, e.freshness, `${e.confidencePct}%`, e.note || '—']))}

  <h2>Report Explainability&trade;</h2>
  <p class="muted">Every headline metric — what was calculated, how, from which evidence, why it matters, and the action to take.</p>
  ${report.explainability.map((x) => `<h3>${esc(x.metric)}</h3>${gridTable(['Question', 'Answer'], [
    ['What was calculated?', x.what],
    ['How was it calculated?', x.how],
    ['Which evidence was used?', x.evidence],
    ['Why does it matter?', x.why],
    ['What action should be taken?', x.action],
  ])}`).join('')}

  <h2>Terminology &amp; Definitions</h2>
  ${gridTable(['Term', 'Definition'], report.definitions.length ? report.definitions.map((d) => [d.term, d.definition]) : [['Evidence Not Available', '—']])}

  <h2>Report Validation</h2>
  <p><span class="pill" style="background:${report.reportValidation.overall === 'PASS' ? '#16A34A' : '#DC2626'};color:#fff">Overall Validation: ${esc(report.reportValidation.overall)}</span></p>
  ${gridTable(['Validation Check', 'Result', 'Detail'], report.reportValidation.checks.length ? report.reportValidation.checks.map((c) => [c.check, c.status === 'pass' ? '✓ PASS' : '✗ FAIL', c.detail]) : [['Evidence Not Available', '—', '—']])}
  <p class="muted">${esc(report.reportValidation.note)}</p>

  <h2>Evidence Sources</h2>
  <p class="muted">${esc(report.evidence.sources.join(' · '))}</p>
  <p class="muted">${esc(report.evidence.notes)}</p>
  ${report.integrity ? `<p class="muted"><b>Integrity (${esc(report.integrity.algorithm)}):</b> ${esc(report.integrity.hash)}</p>` : ''}

  <div class="foot"><span>${esc(branding.companyName)} · ${esc(meta.title)}</span><span>${esc(branding.classification)} · v${esc(meta.version)}</span></div>
</div>
</body></html>`;

  return new Blob([html], { type: 'text/html;charset=utf-8' });
}
