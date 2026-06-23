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

function tableHtml(table: ReportTable): string {
  return `<h3>${esc(table.title)}</h3><table><thead><tr>${table.columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${table.rows
    .map((row) => `<tr>${row.map((cell) => `<td>${esc(cell)}</td>`).join('')}</tr>`)
    .join('')}</tbody></table>`;
}

/**
 * Branded, self-contained HTML report. Embeds chart PNGs inline and is suitable
 * for browser preview or print-to-PDF. Enterprise styling, cover, header/footer.
 */
export function exportHtml(report: EnterpriseAssessmentReport): Blob {
  const { branding, meta } = report;
  const logo = branding.companyLogo ? `<img class="logo" src="${esc(branding.companyLogo)}" alt="logo" />` : '';

  const kpis = report.kpis
    .map(
      (kpi) => `<div class="kpi"><div class="kpi-v">${esc(kpi.value)}${esc(kpi.unit || '')}</div><div class="kpi-l">${esc(kpi.label)}</div>${kpi.level ? `<div class="kpi-x">${esc(kpi.level)}</div>` : ''}</div>`,
    )
    .join('');

  const findings = report.findings.length
    ? report.findings
        .map(
          (finding) => `<div class="finding"><div class="f-head"><span class="sev" style="background:${SEV_COLOR[finding.severity]}">${esc(finding.severity)}</span><strong>${esc(finding.title)}</strong></div><div class="f-body"><div><b>Evidence:</b> ${esc(finding.evidence)}</div><div><b>Affected:</b> ${esc(finding.affectedAssets.join(', ') || 'Evidence Not Available')}</div><div><b>Recommendation:</b> ${esc(finding.recommendation)}</div><div><b>Remediation:</b> ${esc(finding.remediationPlan)}</div></div></div>`,
        )
        .join('')
    : '<p class="muted">Evidence Not Available — no findings recorded.</p>';

  const charts = report.charts.map((chart) => `<figure><img src="${esc(chart.dataUrl)}" alt="${esc(chart.title)}" /><figcaption>${esc(chart.title)}</figcaption></figure>`).join('');

  const compliance = `<h3>Compliance Mapping</h3><table><thead><tr><th>Framework</th><th>Control</th><th>Status</th><th>Detail</th></tr></thead><tbody>${report.compliance
    .map((row) => `<tr><td>${esc(row.framework)}</td><td>${esc(row.control)}</td><td>${esc(row.status)}</td><td>${esc(row.detail)}</td></tr>`)
    .join('')}</tbody></table>`;

  const roadmap = `<h3>PQC Migration Roadmap</h3><table><thead><tr><th>Phase</th><th>Description</th><th>Status</th><th>Effort (wks)</th></tr></thead><tbody>${report.roadmap
    .map((phase) => `<tr><td>${esc(phase.phase)}</td><td>${esc(phase.description)}</td><td>${esc(phase.status)}</td><td>${esc(phase.effortWeeks)}</td></tr>`)
    .join('')}</tbody></table>`;

  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>${esc(meta.title)}</title>
<style>
  :root { --ink:#0F172A; --muted:#64748B; --line:#E2E8F0; --brand:#2478FF; }
  * { box-sizing: border-box; }
  body { font-family: Inter, 'Segoe UI', Arial, sans-serif; color: var(--ink); margin: 0; }
  .page { max-width: 920px; margin: 0 auto; padding: 40px 48px; }
  .cover { min-height: 70vh; display:flex; flex-direction:column; justify-content:center; border-bottom: 3px solid var(--brand); }
  .logo { max-height: 64px; margin-bottom: 24px; }
  .classification { display:inline-block; align-self:flex-start; background:#0F172A; color:#fff; font-size:11px; letter-spacing:.12em; padding:4px 10px; border-radius:4px; margin-bottom:18px; }
  h1 { font-size: 34px; margin: 0 0 8px; }
  h2 { font-size: 20px; margin: 36px 0 12px; border-bottom: 1px solid var(--line); padding-bottom: 6px; }
  h3 { font-size: 15px; margin: 22px 0 8px; color: #334155; }
  .sub { color: var(--muted); font-size: 14px; }
  .meta-grid { display:grid; grid-template-columns: repeat(2, 1fr); gap: 8px 24px; margin-top: 24px; font-size: 13px; color:#334155; }
  .kpis { display:grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }
  .kpi { border:1px solid var(--line); border-radius:8px; padding:14px; }
  .kpi-v { font-size: 26px; font-weight: 700; }
  .kpi-l { font-size: 11px; text-transform: uppercase; letter-spacing:.05em; color: var(--muted); }
  .kpi-x { font-size: 11px; color: var(--brand); margin-top:2px; }
  table { width:100%; border-collapse: collapse; margin: 8px 0 18px; font-size: 12.5px; }
  th, td { border-bottom:1px solid var(--line); padding: 7px 8px; text-align:left; vertical-align: top; }
  th { background:#F8FAFC; font-size: 11px; text-transform: uppercase; letter-spacing:.04em; color:#475569; }
  .finding { border:1px solid var(--line); border-radius:8px; padding:12px 14px; margin-bottom:10px; }
  .f-head { display:flex; align-items:center; gap:10px; margin-bottom:6px; }
  .sev { color:#fff; font-size:10px; text-transform:uppercase; padding:2px 8px; border-radius:4px; letter-spacing:.05em; }
  .f-body { font-size: 12.5px; color:#334155; display:grid; gap:3px; }
  figure { margin: 0 0 18px; border:1px solid var(--line); border-radius:8px; padding:12px; }
  figure img { max-width: 100%; }
  figcaption { font-size: 12px; color: var(--muted); margin-top: 6px; text-align:center; }
  .charts { display:grid; grid-template-columns: repeat(2, 1fr); gap:16px; }
  .muted { color: var(--muted); }
  .foot { margin-top: 40px; border-top:1px solid var(--line); padding-top: 12px; font-size: 11px; color: var(--muted); display:flex; justify-content:space-between; }
</style></head><body>
<div class="page">
  <section class="cover">
    ${logo}
    <span class="classification">${esc(branding.classification)}</span>
    <h1>${esc(meta.title)}</h1>
    <div class="sub">${esc(branding.companyName)}${branding.businessUnit ? ` — ${esc(branding.businessUnit)}` : ''}</div>
    <div class="meta-grid">
      <div><b>Report ID:</b> ${esc(meta.id)}</div>
      <div><b>Version:</b> ${esc(meta.version)}</div>
      <div><b>Generated:</b> ${esc(new Date(meta.generatedAt).toLocaleString())}</div>
      <div><b>Generated By:</b> ${esc(meta.generatedBy)}</div>
      <div><b>Report Owner:</b> ${esc(branding.reportOwner || 'Evidence Not Available')}</div>
      <div><b>Reviewer:</b> ${esc(branding.reviewer || 'Evidence Not Available')}</div>
    </div>
  </section>

  <h2>Executive Summary</h2>
  <p>${esc(report.executiveSummary)}</p>
  ${branding.customNotes ? `<p class="muted"><b>Notes:</b> ${esc(branding.customNotes)}</p>` : ''}

  <h2>Key Performance Indicators</h2>
  <div class="kpis">${kpis}</div>

  <h2>Visual Analysis</h2>
  <div class="charts">${charts || '<p class="muted">Charts unavailable.</p>'}</div>

  <h2>Findings</h2>
  ${findings}

  <h2>PQC Readiness</h2>
  <p>${esc(report.pqcReadiness.summary)}</p>
  ${tableHtml(report.pqcReadiness.table)}

  <h2>HNDL Exposure</h2>
  <p>${esc(report.hndl.summary)}</p>
  ${tableHtml(report.hndl.table)}

  <h2>Asset & CBOM Inventory</h2>
  ${tableHtml(report.assets)}
  ${tableHtml(report.cbom)}

  <h2>Compliance</h2>
  ${compliance}

  <h2>Remediation Plan</h2>
  ${tableHtml(report.remediation)}

  <h2>Migration Roadmap</h2>
  ${roadmap}

  <h2>Evidence Sources</h2>
  <p class="muted">${esc(report.evidence.sources.join(' · '))}</p>
  <p class="muted">${esc(report.evidence.notes)}</p>
  ${report.integrity ? `<p class="muted"><b>Integrity (${esc(report.integrity.algorithm)}):</b> ${esc(report.integrity.hash)}</p>` : ''}

  <div class="foot"><span>${esc(branding.companyName)} · ${esc(meta.title)}</span><span>${esc(branding.classification)} · v${esc(meta.version)}</span></div>
</div>
</body></html>`;

  return new Blob([html], { type: 'text/html;charset=utf-8' });
}
