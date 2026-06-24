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
  const { branding, meta, executiveBlock: ex } = report;
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
  <div class="callout"><b>Executive Recommendation:</b> ${esc(ex.executiveRecommendation)}<br/><b>Estimated Programme:</b> ${esc(ex.estimatedDurationWeeks || 'TBD')} weeks · ${esc(usd(ex.estimatedCostUsd))} · Expected risk reduction ${esc(ex.expectedRiskReductionPct)}% · Quantum exposure window ${esc(ex.quantumExposureWindow)}.</div>

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

  <h2>Quantum Readiness Breakdown</h2>
  ${gridTable(['Domain', 'Score', 'Risk Level', 'Owner', 'Recommended Action'], report.readinessDomains.map((d) => [d.domain, `${d.score}/100`, d.riskLevel, d.owner, d.actions]))}

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

  <h2>HNDL Exposure Analysis</h2>
  <p>${esc(report.hndl.summary)}</p>
  ${gridTable(['Data Category', 'Retention', 'Current Protection', 'HNDL Risk', 'Recommended Protection'], report.hndl.categories.map((h) => [h.category, h.retention, h.currentProtection, h.hndlRisk, h.recommendedProtection]))}

  <h2>Visual Analysis</h2>
  <div class="charts">${charts || '<p class="muted">Charts unavailable.</p>'}</div>

  <h2>Findings &amp; Evidence</h2>
  ${findings}

  <h2>Cryptographic & Asset Inventory</h2>
  ${tableHtml(report.assets)}
  ${tableHtml(report.cbom)}
  ${tableHtml(report.pqcReadiness.table)}

  <h2>Compliance Mapping</h2>
  ${gridTable(['Framework', 'Control', 'Status', 'Current → Target / Gap'], report.compliance.map((c) => [c.framework, c.control, c.status, c.detail]))}

  <h2>Remediation Program&trade;</h2>
  ${gridTable(['Priority', 'Action', 'Owner', 'Affected Assets', 'Cost', 'Effort', 'Risk Reduction', 'Target Date', 'Status'], report.remediationProgram.map((r) => [
    r.priority, r.action, r.owner, r.affectedAssets.join(', '), usd(r.costUsd), r.effort, `${r.riskReductionPct}%`, r.targetDate, r.status,
  ]))}

  <h2>Migration Roadmap</h2>
  ${gridTable(['Phase', 'Description', 'Status', 'Effort (wks)'], report.roadmap.map((p) => [p.phase, p.description, p.status, p.effortWeeks]))}

  <h2>Migration Playbook&trade;</h2>
  ${report.playbook.map((stage) => `<h3>${esc(stage.wave)}</h3>${gridTable(['Step', 'Detail'], [
    ['Prerequisites', stage.prerequisites], ['Preparation', stage.preparation], ['Execution', stage.execution], ['Rollback', stage.rollback], ['Validation', stage.validation], ['Success Criteria', stage.successCriteria],
  ])}`).join('')}

  <h2>Cost Forecast</h2>
  ${gridTable(['Category', 'Estimated Cost'], report.costForecast.lines.map((l) => [l.category, usd(l.costUsd)]))}
  <p><b>Total Migration Cost:</b> ${esc(usd(report.costForecast.totalUsd))} · <b>Projected Risk-Reduction Value:</b> ${esc(usd(report.costForecast.projectedRiskReductionValueUsd))}</p>

  <h2>Risk Reduction Forecast</h2>
  ${gridTable(['Metric', 'Value'], [
    ['Current Risk', `${report.riskForecast.currentRisk}/100`],
    ['Target Risk', `${report.riskForecast.targetRisk}/100`],
    ['Risk Reduction', `${report.riskForecast.reductionPct}%`],
    ['Projected Residual Risk', `${report.riskForecast.residualRisk}/100`],
    ['12-Month Projection', `${report.riskForecast.month12}/100`],
    ['24-Month Projection', `${report.riskForecast.month24}/100`],
    ['36-Month Projection', `${report.riskForecast.month36}/100`],
  ])}

  <h2>Governance &amp; Ownership</h2>
  ${gridTable(['Role', 'Owner', 'Responsibility'], report.governance.map((g) => [g.role, g.owner, g.responsibility]))}

  <h2>Evidence Sources</h2>
  <p class="muted">${esc(report.evidence.sources.join(' · '))}</p>
  <p class="muted">${esc(report.evidence.notes)}</p>
  ${report.integrity ? `<p class="muted"><b>Integrity (${esc(report.integrity.algorithm)}):</b> ${esc(report.integrity.hash)}</p>` : ''}

  <div class="foot"><span>${esc(branding.companyName)} · ${esc(meta.title)}</span><span>${esc(branding.classification)} · v${esc(meta.version)}</span></div>
</div>
</body></html>`;

  return new Blob([html], { type: 'text/html;charset=utf-8' });
}
