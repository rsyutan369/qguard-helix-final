import type { EnterpriseAssessmentReport, ReportTable } from '../schemas/ReportSchema';
import { qrSvg, reportVerificationUrl } from '../ReportQr';
import { playbookRows } from '../ReportPlaybook';

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

// Improvements_06 palettes — risk-zone (heat map), evidence grade, ownership domain.
const ZONE_COLOR: Record<string, string> = { critical: '#B91C1C', high: '#EA580C', medium: '#D97706', low: '#65A30D', minimal: '#16A34A' };
const GRADE_COLOR: Record<string, string> = { A: '#16A34A', B: '#65A30D', C: '#D97706', D: '#EA580C', E: '#DC2626', Missing: '#94A3B8' };
const DOMAIN_COLOR: Record<string, string> = { customer: '#0891B2', provider: '#2563EB', ecosystem: '#7C3AED' };
const STATUS_COLOR: Record<string, string> = { ready: '#16A34A', 'in-progress': '#2563EB', waiting: '#D97706', 'not-applicable': '#94A3B8' };

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
  const { branding, meta, executiveBlock: ex, scope, certification: cert } = report;
  const logo = branding.companyLogo ? `<img class="logo" src="${esc(branding.companyLogo)}" alt="logo" />` : '';
  const verifyUrl = reportVerificationUrl(report);

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
  .ladder { margin: 14px 0; }
  .rung { display:flex; align-items:center; gap:14px; border:1px solid var(--line); border-radius:8px; padding:12px 16px; background:#fff; }
  .rung-cur { border-left:4px solid #DC2626; } .rung-tgt { border-left:4px solid #16A34A; background:#F0FDF4; }
  .rung-score { font-size:26px; font-weight:800; color:#0F172A; min-width:86px; } .rung-score span { font-size:12px; color:var(--muted); font-weight:600; }
  .rung-stage { font-size:13px; font-weight:700; color:#0F172A; } .rung-detail { font-size:11.5px; color:var(--muted); margin-top:2px; }
  .rung-body { flex:1; } .rung-risk { font-size:11px; font-weight:700; color:#475569; white-space:nowrap; }
  .ladder-arrow { text-align:center; color:var(--muted); font-size:16px; padding:2px 0; }
  .cert { border:2px solid var(--brand); border-radius:12px; padding:22px; background:linear-gradient(160deg,#F8FAFC,#fff); page-break-inside:avoid; }
  .cert-status { display:inline-block; font-size:13px; font-weight:800; letter-spacing:.04em; padding:6px 14px; border-radius:6px; color:#fff; }
  .cert-grid { display:grid; grid-template-columns: repeat(4, 1fr); gap:12px; margin:16px 0; }
  .cert-stat { border:1px solid var(--line); border-radius:8px; padding:10px 12px; background:#fff; }
  .cert-stat .n { font-size:20px; font-weight:800; color:#0F172A; } .cert-stat .k { font-size:9.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin-top:2px; }
  .cert-sign { display:flex; gap:20px; align-items:flex-start; margin-top:16px; flex-wrap:wrap; }
  .cert-sign .qr { flex-shrink:0; border:1px solid var(--line); border-radius:8px; padding:8px; background:#fff; }
  .cert-sign .sig { flex:1; min-width:280px; font-size:12px; color:#334155; }
  .cert-sign .sig .hash { font-family: ui-monospace, Consolas, monospace; font-size:10.5px; word-break:break-all; background:#F1F5F9; border-radius:6px; padding:8px 10px; margin-top:6px; }
  .foot { margin-top: 40px; border-top:1px solid var(--line); padding-top: 12px; font-size: 11px; color: var(--muted); display:flex; justify-content:space-between; }
  /* Improvements_06 — board-level visual intelligence */
  .board { border:2px solid var(--brand); border-radius:12px; padding:22px 24px; background:linear-gradient(160deg,#EFF6FF,#fff); margin:18px 0 8px; page-break-inside:avoid; }
  .board-head { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
  .board-badge { font-size:11px; font-weight:800; letter-spacing:.1em; text-transform:uppercase; color:var(--brand); }
  .board-cert { font-size:11px; font-weight:800; padding:4px 12px; border-radius:6px; color:#fff; }
  .board-headline { font-size:15px; font-weight:600; color:#0F172A; margin:10px 0 16px; }
  .board-metrics { display:grid; grid-template-columns: repeat(3, 1fr); gap:12px; }
  .bm { border:1px solid var(--line); border-radius:8px; padding:12px 14px; background:#fff; }
  .bm-v { font-size:20px; font-weight:800; color:#0F172A; } .bm-l { font-size:10px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin-top:3px; } .bm-x { font-size:11px; color:var(--brand); margin-top:2px; }
  .board-two { display:grid; grid-template-columns: 1fr 1fr; gap:18px 28px; margin-top:16px; }
  .board-two h4 { font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:#334155; margin:0 0 8px; }
  .board-asset { margin-top:14px; font-size:11.5px; }
  .resp-bar { display:flex; height:14px; border-radius:7px; overflow:hidden; background:#E2E8F0; }
  .resp-legend { display:flex; flex-wrap:wrap; gap:14px; margin-top:8px; font-size:11px; font-weight:700; }
  .sr-bars { margin:10px 0 6px; }
  .srb-row { display:grid; grid-template-columns: 120px 1fr 90px; align-items:center; gap:10px; margin-bottom:8px; font-size:12px; }
  .srb-track { height:16px; border-radius:8px; background:#E2E8F0; overflow:hidden; }
  .srb-fill { height:100%; border-radius:8px; }
  .srb-count { text-align:right; font-variant-numeric:tabular-nums; color:#334155; font-weight:700; }
  .sr-timeline { margin:8px 0; }
  .srt-row { display:grid; grid-template-columns: 150px 1fr 150px; align-items:center; gap:12px; margin-bottom:8px; }
  .srt-dom { font-size:12px; font-weight:700; color:#0F172A; }
  .srt-track { height:16px; border-radius:8px; background:#E2E8F0; overflow:hidden; }
  .srt-fill { height:100%; border-radius:8px; }
  .srt-status { font-size:11px; font-weight:700; text-align:right; }
  .heat { border-collapse:separate; border-spacing:3px; width:100%; margin:8px 0 6px; }
  .heat td, .heat th { text-align:center; font-size:11px; padding:0; }
  .heat .axis { color:var(--muted); font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.03em; background:none; border:none; }
  .heat .rowlbl { color:#334155; font-weight:700; font-size:10.5px; text-align:right; padding-right:8px; white-space:nowrap; }
  .heat .cell { color:#fff; font-weight:800; border-radius:6px; height:42px; width:60px; vertical-align:middle; }
  .heat .cell small { display:block; font-size:8.5px; font-weight:600; opacity:.85; }
  .pmatrix { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:8px 0; }
  .quad { border:1px solid var(--line); border-radius:10px; padding:12px 14px; background:#fff; }
  .quad-title { font-size:13px; font-weight:800; color:#0F172A; }
  .quad-sub { font-size:10px; text-transform:uppercase; letter-spacing:.04em; color:var(--brand); margin:2px 0 6px; }
  .quad-guide { font-size:11px; color:var(--muted); margin-bottom:8px; }
  .quad ul { margin:0; padding-left:16px; } .quad li { font-size:11.5px; margin-bottom:4px; color:#334155; }
  .grade { display:inline-block; min-width:22px; text-align:center; font-weight:800; font-size:12px; padding:1px 7px; border-radius:5px; color:#fff; }
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

  ${report.boardSnapshot.hasData ? (() => {
    const b = report.boardSnapshot;
    const total = Math.max(1, b.responsibilitySplit.customer + b.responsibilitySplit.provider + b.responsibilitySplit.ecosystem);
    return `
  <section class="board">
    <div class="board-head">
      <span class="board-badge">Board Snapshot — 60-Second Executive View</span>
      <span class="board-cert" style="background:${b.certified ? '#16A34A' : '#334155'}">${esc(b.certificationStatus)}</span>
    </div>
    <p class="board-headline">${esc(b.headline)}</p>
    <div class="board-metrics">
      ${b.metrics.map((m) => `<div class="bm"><div class="bm-v">${esc(m.value)}</div><div class="bm-l">${esc(m.label)}</div><div class="bm-x">${esc(m.context)}</div></div>`).join('')}
    </div>
    <div class="board-two">
      <div><h4>Top Decisions for the Board</h4><ol>${b.topDecisions.map((d) => `<li>${esc(d)}</li>`).join('') || '<li class="muted">Evidence Not Available</li>'}</ol></div>
      <div><h4>Customer vs Provider Responsibility</h4>
        <div class="resp-bar">
          <div style="width:${(b.responsibilitySplit.customer / total) * 100}%;background:${DOMAIN_COLOR.customer}"></div>
          <div style="width:${(b.responsibilitySplit.provider / total) * 100}%;background:${DOMAIN_COLOR.provider}"></div>
          <div style="width:${(b.responsibilitySplit.ecosystem / total) * 100}%;background:${DOMAIN_COLOR.ecosystem}"></div>
        </div>
        <div class="resp-legend">
          <span style="color:${DOMAIN_COLOR.customer}">Customer ${esc(b.responsibilitySplit.customer)}</span>
          <span style="color:${DOMAIN_COLOR.provider}">Provider ${esc(b.responsibilitySplit.provider)}</span>
          <span style="color:${DOMAIN_COLOR.ecosystem}">Ecosystem ${esc(b.responsibilitySplit.ecosystem)}</span>
        </div>
        <p class="muted" style="margin-top:8px;font-size:11px">${esc(b.responsibilityNote)}</p>
      </div>
    </div>
    ${b.assetBasis ? `<p class="muted board-asset">${esc(b.assetBasis)}</p>` : ''}
    <div class="callout"><b>Executive Recommendation:</b> ${esc(b.recommendation)}</div>
  </section>` ;
  })() : ''}

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
  <h3>Executive Decision Package</h3>
  <p class="muted">The one-look decision summary — budget, resources, risk dispositions, timeline, ROI and business impact. Every line is sourced from the validated report sections referenced in its detail.</p>
  ${gridTable(['Decision Item', 'Value', 'Detail / Source'], report.decisionPackage.length ? report.decisionPackage.map((d) => [d.item, d.value, d.detail]) : [['Evidence Not Available', '—', '—']])}

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
    ['Assessment Evidence Confidence', `${report.confidenceSummary.assessmentConfidencePct}%`, 'Completeness of the evidence behind this assessment'],
    ['Migration Plan Confidence', `${report.confidenceSummary.migrationPlanConfidencePct}%`, 'Likelihood the recommended plan achieves its target'],
    ['Migration Forecast Confidence', `${report.confidenceSummary.migrationForecastConfidencePct}%`, 'Confidence in the entire-programme simulation outcome'],
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

  ${report.sharedResponsibility.hasData ? `
  <h2>Shared Responsibility Assessment&trade;</h2>
  <p>${esc(report.sharedResponsibility.summary)}</p>
  ${(() => {
    const sr = report.sharedResponsibility;
    const totalFindings = Math.max(1, sr.customerControlled + sr.providerControlled + sr.ecosystemDependent);
    const bar = (label: string, count: number, domain: string) =>
      `<div class="srb-row"><span style="color:${DOMAIN_COLOR[domain]};font-weight:700">${esc(label)}</span><div class="srb-track"><div class="srb-fill" style="width:${(count / totalFindings) * 100}%;background:${DOMAIN_COLOR[domain]}"></div></div><span class="srb-count">${esc(count)} (${Math.round((count / totalFindings) * 100)}%)</span></div>`;
    return `
  <h3>Shared Responsibility Summary</h3>
  <div class="sr-bars">
    ${bar('Customer', sr.customerControlled, 'customer')}
    ${bar('Provider', sr.providerControlled, 'provider')}
    ${bar('Ecosystem', sr.ecosystemDependent, 'ecosystem')}
  </div>
  <h3>Shared Responsibility Timeline</h3>
  <div class="sr-timeline">
    ${sr.timeline.map((t) => `<div class="srt-row"><span class="srt-dom">${esc(t.domain)}</span><div class="srt-track"><div class="srt-fill" style="width:${Math.max(3, Math.min(100, t.readiness))}%;background:${STATUS_COLOR[t.status] || '#94A3B8'}"></div></div><span class="srt-status" style="color:${STATUS_COLOR[t.status] || '#94A3B8'}">${esc(t.label)} · ${esc(t.readiness)}/100</span></div>`).join('')}
  </div>
  <p class="muted">${esc(sr.timeline.map((t) => t.note).filter(Boolean).join(' ')) }</p>`;
  })()}
  ${gridTable(['Ownership Domain', 'Readiness', 'Findings'], [
    ['Overall', `${report.sharedResponsibility.readiness.overall}/100`, String(report.sharedResponsibility.customerControlled + report.sharedResponsibility.providerControlled + report.sharedResponsibility.ecosystemDependent)],
    ['Customer-Controlled', `${report.sharedResponsibility.readiness.customer}/100`, String(report.sharedResponsibility.customerControlled)],
    ['Provider-Controlled', `${report.sharedResponsibility.readiness.provider}/100`, String(report.sharedResponsibility.providerControlled)],
    ['Ecosystem-Dependent', `${report.sharedResponsibility.readiness.ecosystem}/100`, String(report.sharedResponsibility.ecosystemDependent)],
  ])}
  <p class="muted"><b>${report.sharedResponsibility.actionableNow}</b> customer-actionable now &middot; <b>${report.sharedResponsibility.waitingDependencies}</b> waiting on a provider/ecosystem dependency &middot; <b>${report.sharedResponsibility.migrationBlockers}</b> migration blocker(s).</p>
  ${report.sharedResponsibility.reconciliationNote ? `<p class="muted"><b>Finding-count reconciliation:</b> ${esc(report.sharedResponsibility.reconciliationNote)}</p>` : ''}
  <h3>Shared Responsibility Matrix (Ownership)</h3>
  <p class="muted">One row per cryptographic exposure, owner and asset. The scanner reports one finding per detected instance and observes the same
  asset through several detection channels; identical detections are consolidated and the Instances column preserves the raw evidence count
  (${esc(report.sharedResponsibility.matrix.length)} ownership row(s) covering ${esc(report.sharedResponsibility.matrixInstances)} scanner instance(s)).</p>
  ${gridTable(['Finding', 'Asset', 'Owner', 'Recommended Action', 'Instances', 'Priority', 'Status'], report.sharedResponsibility.matrix.map((m) => [m.finding, m.asset, m.owner, m.action, m.occurrences, m.priority, m.status]))}
  ${report.sharedResponsibility.blockers.length ? `<h3>Migration Blockers</h3>${gridTable(['Finding', 'Owner', 'Dependency'], report.sharedResponsibility.blockers.map((b) => [b.title, b.owner, b.dependency]))}` : ''}
  <h3>Dependency-Ordered Roadmap &mdash; 7 Waves</h3>
  ${gridTable(['Wave', 'Focus', 'Ownership', 'Findings', 'Status', 'Timeline'], report.sharedResponsibility.waves.map((w) => [`Wave ${w.wave}`, w.name, w.domain, String(w.findingCount), w.status, w.timeline]))}
  ${report.sharedResponsibility.providers.length ? `<h3>Provider &amp; Ecosystem Readiness</h3>${gridTable(['Provider / Technology', 'Ownership', 'Findings', 'PQ Roadmap', 'Customer Influence'], report.sharedResponsibility.providers.map((p) => [p.name, p.domain, String(p.count), p.pqRoadmap, p.customerInfluence]))}` : ''}
  ${report.sharedResponsibility.nextActions.length ? `<h3>Next Actions</h3><ul>${report.sharedResponsibility.nextActions.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}
  <p class="muted">${esc(report.sharedResponsibility.note)}</p>
  ` : ''}

  <h2>Migration Dependency Analysis</h2>
  <p class="muted">${esc(report.dependencyAnalysis.summary)}</p>
  ${gridTable(['Dependency Chain', 'Blast Radius', 'Complexity'], report.dependencyAnalysis.chains.map((c) => [c.path, c.blastRadius, c.complexity]))}
  <p class="muted"><b>Potential Failure Points:</b> ${esc(report.dependencyAnalysis.failurePoints.join(', ') || 'None — no asset is at risk 70 or above')}</p>

  <h2>Quantum Risk Analysis</h2>
  <p class="muted">Per-domain current and target risk. Domain values are the calibrated risk-domain model (see Risk Scoring Methodology), and the targets use the same reduction engine as the executive summary — the weighted blend of the targets below reproduces the programme target risk of ${esc(report.executiveBlock.targetRisk)}/100 (verified in Report Validation).</p>
  ${gridTable(['Risk Category', 'Current', 'Target', 'Reduction Potential'], report.riskCategories.map((r) => [r.category, `${r.currentScore}/100`, `${r.targetScore}/100`, `${r.reductionPotentialPct}%`]))}

  ${report.executiveHeatMap.hasData ? (() => {
    const h = report.executiveHeatMap;
    return `
  <h2>Executive Risk Heat Map&trade;</h2>
  <p class="muted">${esc(h.methodology)}</p>
  <table class="heat">
    <tr><td class="axis" style="text-align:right">Impact &darr; / Likelihood &rarr;</td>${h.likelihoodLabels.map((l) => `<th class="axis">${esc(l)}</th>`).join('')}</tr>
    ${h.impactLabels.map((imp) => {
      const row = h.cells.filter((c) => c.impact === imp).sort((a, b) => a.likelihoodRank - b.likelihoodRank);
      return `<tr><td class="rowlbl">${esc(imp)}</td>${row.map((c) => `<td class="cell" style="background:${ZONE_COLOR[c.level] || '#94A3B8'};opacity:${c.count ? 1 : 0.28}" title="${esc(c.items.join(', '))}">${c.count || ''}${c.count ? `<small>${esc(c.level)}</small>` : ''}</td>`).join('')}</tr>`;
    }).join('')}
  </table>
  <p class="muted">Rows = Business Impact (Critical &rarr; Minimal) &middot; Columns = Quantum Exploitation Likelihood (Rare &rarr; Almost Certain). Cell number = consolidated finding groups in that zone; ${esc(h.totalPlotted)} plotted.</p>` ;
  })() : ''}

  <h2>Risk Scoring Methodology&trade;</h2>
  <p><b>Formula:</b> <code>${esc(report.riskMethodology.formula)}</code></p>
  <p class="muted">${esc(report.riskMethodology.explanation)}</p>
  ${gridTable(['Risk Domain', 'Domain Risk', 'Weight', 'Contribution (Risk×Weight)', 'Share'], report.riskMethodology.weights.map((w) => [w.domain, `${w.score}/100`, `${w.weightPct}%`, w.contribution.toFixed(1), `${w.contributionPct}%`]))}
  <p><b>Overall Quantum Risk = Σ Contribution =</b> ${report.riskMethodology.weights.map((w) => w.contribution.toFixed(1)).join(' + ')} = <b>${esc(report.riskMethodology.overall)}/100</b></p>
  <p><b>Top Driver:</b> ${esc(report.riskMethodology.topDriver)}</p>

  <h2>HNDL Exposure Analysis</h2>
  <p>${esc(report.hndl.summary)}</p>
  ${gridTable(['Data Category', 'Retention', 'Current Protection', 'HNDL Exposure', 'Recommended Protection'], report.hndl.categories.map((h) => [h.category, h.retention, h.currentProtection, h.hndlRisk, h.recommendedProtection]))}

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

  ${report.remediationCampaigns.campaigns.length ? `
  <h2>Remediation Campaigns&trade;</h2>
  <p class="muted">${esc(report.remediationCampaigns.note)}</p>
  ${gridTable(['Priority', 'Campaign', 'Target', 'Findings', 'Occurrences', 'Assets', 'Recommended Action'], report.remediationCampaigns.campaigns.map((c) => [c.priority, c.campaign, c.target, c.findingCount, c.occurrences, c.affectedAssets, c.action]))}` : ''}

  <h2>Remediation Program&trade;</h2>
  ${gridTable(['Priority', 'Action', 'Owner', 'Affected Assets', 'Cost', 'Effort', 'Risk Reduction', 'Target Date', 'Status'], report.remediationProgram.map((r) => [
    r.priority, r.action, r.owner, r.affectedAssets.join(', '), usd(r.costUsd), r.effort, `${r.riskReductionPct}%`, r.targetDate, r.status,
  ]))}

  ${report.businessPriorityMatrix.hasData ? `
  <h2>Business Priority Matrix&trade;</h2>
  <p class="muted">${esc(report.businessPriorityMatrix.note)}</p>
  <div class="pmatrix">
    ${report.businessPriorityMatrix.quadrants.map((q) => `<div class="quad"><div class="quad-title">${esc(q.title)}</div><div class="quad-sub">${esc(q.subtitle)}</div><div class="quad-guide">${esc(q.guidance)}</div><ul>${q.items.slice(0, 6).map((it) => `<li><b>${esc(it.name)}</b> — ${esc(it.rationale)}</li>`).join('') || '<li class="muted">No items in this quadrant.</li>'}</ul></div>`).join('')}
  </div>` : ''}

  <h2>Migration Roadmap &amp; Program Plan</h2>
  <p class="muted">Sequential dates, milestones, approval gates and critical-path/slack — a true program-management plan. Elapsed window: the "migration programme" duration cited in the executive summary counts the migration waves only; the schedule below adds the discovery and validation phases, so the end-to-end elapsed window is ${esc(report.roadmap.reduce((sum, p) => sum + (Number(p.effortWeeks) || 0), 0))} weeks.</p>
  ${gridTable(['Phase', 'Start', 'Finish', 'Effort (wks)', 'Milestone', 'Approval Gate', 'Critical Path', 'Slack'], report.roadmap.map((p) => [p.phase, p.startDate, p.endDate, p.effortWeeks, p.milestone || '—', p.gate || '—', p.criticalPath ? 'Yes' : 'No', `${p.slackWeeks}w`]))}

  <h2>Migration Resource Loading&trade;</h2>
  <p class="muted">Per-team resource planning: assumed availability (capacity), derived allocation demand, engineer count and cross-team dependencies. Availability values are standard enterprise planning assumptions; allocation is derived from the wave hours — a team whose allocation approaches or exceeds its availability is over-subscribed.</p>
  ${gridTable(['Team', 'Waves', 'Hours', 'Engineers', 'Window', 'Availability', 'Allocation', 'Dependencies'], report.resourceLoading.length ? report.resourceLoading.map((r) => [r.team, r.waves, r.hours, r.engineers, `${r.windowWeeks}w`, `${r.availabilityPct}%`, `${r.allocationPct}%`, r.dependencies.join(', ')]) : [['Evidence Not Available', '—', '—', '—', '—', '—', '—', '—']])}

  <h2>Enterprise Remediation Playbook&trade;</h2>
  ${report.playbookStandardControls.rows.length ? `<h3>Standard Change Controls — Applies To All ${esc(report.playbookStandardControls.applies)} Playbooks</h3>
  <p class="muted">${esc(report.playbookStandardControls.note)}</p>
  ${gridTable(['Control', 'Detail'], report.playbookStandardControls.rows.map((r) => [r.step, r.detail]))}` : ''}
  ${report.playbookDetail.length ? report.playbookDetail.map((p) => `<h3>${esc(p.finding)}</h3>${gridTable(['Step', 'Detail'], playbookRows(p, report.playbookStandardControls.sharedKeys))}`).join('') : '<p class="muted">Evidence Not Available — run a discovery scan to generate the remediation playbook.</p>'}

  <h2>Cost Forecast Intelligence&trade;</h2>
  <p class="muted">Every cost line is derived from labour hours × blended engineer rate ($${esc(report.costBreakdown.blendedRateUsd)}/hr). Total ${esc(report.costBreakdown.totalHours.toLocaleString())} hours.</p>
  <p class="muted">${esc(report.costBreakdown.effortNote)}</p>
  ${gridTable(['Category', 'Hours', '≈ Engineer-Weeks', '≈ FTE', 'Engineers', 'Rate', 'Cost', 'Formula'], report.costBreakdown.lines.map((l) => [l.category, l.hours, l.engineerWeeks, l.fte, l.engineers, usd(l.rateUsd), usd(l.costUsd), l.formula]))}
  <p><b>Total Migration Cost:</b> ${esc(usd(report.costForecast.totalUsd))} · <b>Total Effort:</b> ${esc(report.costBreakdown.totalHours.toLocaleString())} hrs ≈ ${esc(report.costBreakdown.totalEngineerWeeks)} engineer-weeks ≈ ${esc(report.costBreakdown.totalFte)} FTE · <b>Projected Risk-Reduction Value:</b> ${esc(usd(report.costForecast.projectedRiskReductionValueUsd))}</p>

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

  <h2>Readiness Progression</h2>
  <p class="muted">The migration simulation restated as an executive progression: current readiness, the projected readiness after each completed wave, and the programme target. Values reconcile with the simulation above by construction.</p>
  ${report.readinessProgression.length ? `<div class="ladder">${report.readinessProgression.map((step, i) => `
    <div class="rung${i === 0 ? ' rung-cur' : ''}${i === report.readinessProgression.length - 1 ? ' rung-tgt' : ''}">
      <div class="rung-score">${esc(step.readiness)}<span>/100</span></div>
      <div class="rung-body"><div class="rung-stage">${esc(step.stage)}</div><div class="rung-detail">${esc(step.detail)}</div></div>
      <div class="rung-risk">Risk ${esc(step.risk)}/100</div>
    </div>`).join('<div class="ladder-arrow">&darr;</div>')}</div>` : '<p class="muted">Evidence Not Available — run a discovery scan to project the readiness progression.</p>'}

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
  ${report.riskForecast.scenarios.length ? `<h3>Scenario Bands — Anchored to the Programme Schedule</h3>
  <p class="muted">Projections follow the printed roadmap: risk reaches the migration target when the waves complete and the residual level after validation &amp; optimization — not an arbitrary multi-year glide. The no-programme baseline shows the cost of inaction.</p>
  ${gridTable(['Scenario', '12-Month', '24-Month', '36-Month', 'Planning Assumption'], report.riskForecast.scenarios.map((sc) => [sc.scenario, `${sc.month12}/100`, `${sc.month24}/100`, `${sc.month36}/100`, sc.assumption]))}` : ''}

  <h2>Asset-Level Readiness &amp; Intelligence</h2>
  <p class="muted">Which assets drive the overall readiness score, enriched with the business context (owner, unit, environment, criticality, platform) and per-asset crypto posture (TLS, certificate expiry, primary algorithm, key size, PQC status, HNDL exposure) teams need to assign work immediately. Unobserved fields are Evidence Not Available — never fabricated.</p>
  ${gridTable(['Asset', 'Readiness', 'Risk', 'Owner', 'Business Unit', 'Environment', 'Criticality', 'Platform / Cloud', 'TLS Version', 'Cert Expiry', 'Primary Algorithm', 'Key Size', 'PQC Status', 'HNDL Exposure', 'Internet-Facing', 'Primary Driver'], report.assetReadiness.length ? report.assetReadiness.map((a) => [a.asset, `${a.readiness}/100`, `${a.risk}/100`, a.owner, a.businessUnit, a.environment, a.criticality, `${a.platform} / ${a.cloudProvider}`, a.tlsVersion, a.certExpiry, a.primaryAlgorithm, a.keySize, a.pqcStatus, a.hndlExposure, a.internetFacing ? 'Yes' : 'No', a.primaryDriver]) : [['Evidence Not Available', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—', '—']])}

  <h2>Executive Risk Acceptance</h2>
  <p class="muted">Formal disposition of residual risk — mitigate, accept, transfer or defer — for governance and audit. Approvals are generated as Pending Executive Sign-off (never fabricated) and are executed against the report's digital signature (SHA3-256 integrity hash + verification token).</p>
  ${report.riskApprovalPolicy.uniform ? `<div class="callout"><b>Risk Owner Approval:</b> ${esc(report.riskApprovalPolicy.note)}</div>` : ''}
  ${report.riskApprovalPolicy.uniform
    ? gridTable(['Risk', 'Decision', 'Owner', 'Rationale', 'Residual Risk', 'Review Date', 'Approver'], report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.residualRisk, r.reviewDate, r.approver]))
    : gridTable(['Risk', 'Decision', 'Owner', 'Rationale', 'Residual Risk', 'Review Date', 'Approver', 'Approval Status', 'Approval Date', 'Signature Method'], report.riskAcceptance.length ? report.riskAcceptance.map((r) => [r.risk, r.decision, r.owner, r.rationale, r.residualRisk, r.reviewDate, r.approver, r.approvalStatus, r.approvalDate, r.approvalMethod]) : [['Evidence Not Available', '—', '—', '—', '—', '—', '—', '—', '—', '—']])}

  <h2>Decision Traceability</h2>
  <p class="muted">${esc(report.decisionChain.headline)}</p>
  ${gridTable(['Stage', 'Detail'], report.decisionChain.steps.map((st) => [st.stage, st.detail]))}

  <h2>Program Governance</h2>
  ${gridTable(['Role', 'Owner', 'Responsibility'], report.governance.map((g) => [g.role, g.owner, g.responsibility]))}
  <h3>Approval Gates</h3>
  ${gridTable(['Gate', 'Owner', 'Success Criteria'], report.governanceGates.map((g) => [g.gate, g.owner, g.criteria]))}

  ${report.evidenceQuality.rows.length ? `
  <h2>Evidence Quality Score&trade;</h2>
  <p class="muted">${esc(report.evidenceQuality.note)}</p>
  <table><thead><tr>${['Evidence Source', 'Grade', 'Confidence', 'Status', 'Note'].map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${report.evidenceQuality.rows
    .map((r) => `<tr><td>${esc(r.source)}</td><td><span class="grade" style="background:${GRADE_COLOR[r.grade] || '#94A3B8'}">${esc(r.grade)}</span></td><td>${esc(r.confidencePct)}%</td><td>${esc(r.status)}</td><td>${esc(r.note)}</td></tr>`)
    .join('')}</tbody></table>
  <p><b>Overall Evidence Grade:</b> <span class="grade" style="background:${GRADE_COLOR[report.evidenceQuality.overallGrade] || '#94A3B8'}">${esc(report.evidenceQuality.overallGrade)}</span> &middot; ${esc(report.evidenceQuality.gradedSources)} contributing source(s), ${esc(report.evidenceQuality.missingSources)} missing.</p>` : ''}

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
  <p><b>Evidence contributed by:</b> ${report.evidence.sources.length ? report.evidence.sources.map((s) => `<span style="color:#16A34A">✓</span> ${esc(s)}`).join(' &nbsp;·&nbsp; ') : '<span class="muted">Evidence Not Available</span>'}</p>
  ${report.evidence.unavailableSources.length ? `<p class="muted"><b>Not available (no telemetry — contributed no evidence):</b> ${report.evidence.unavailableSources.map((s) => `• ${esc(s)}`).join(' &nbsp; ')}</p>` : ''}
  <p class="muted">${esc(report.evidence.notes)}</p>
  ${report.integrity ? `<p class="muted"><b>Integrity (${esc(report.integrity.algorithm)}):</b> ${esc(report.integrity.hash)}</p>` : ''}

  <h2>Executive Certification Summary</h2>
  <div class="cert">
    <span class="cert-status" style="background:${cert.certified ? '#16A34A' : '#334155'}">${esc(cert.certificationStatus)}</span>
    <div class="cert-grid">
      <div class="cert-stat"><div class="n">${esc(cert.overallReadiness)}/100</div><div class="k">Quantum Readiness (${esc(cert.readinessLevel || '—')})</div></div>
      <div class="cert-stat"><div class="n">${esc(cert.assessmentConfidencePct)}%</div><div class="k">Assessment Evidence Confidence</div></div>
      <div class="cert-stat"><div class="n">${esc(cert.migrationForecastConfidencePct)}%</div><div class="k">Migration Forecast Confidence</div></div>
      <div class="cert-stat"><div class="n">${esc(cert.residualRisk)}/100</div><div class="k">Projected Residual Risk (${esc(cert.residualRiskLevel || '—')})</div></div>
    </div>
    <p style="font-size:12.5px;color:#334155;margin:6px 0"><b>Migration Status:</b> ${esc(cert.migrationStatus)}</p>
    <p style="font-size:12.5px;color:#334155;margin:6px 0"><b>Assessment Scope:</b> ${esc(cert.scopeStatement)}</p>
    ${cert.milestones.length ? `<h3>Migration Milestones</h3>${gridTable(['Milestone', 'Window', 'Approval Gate'], cert.milestones.map((ms) => [ms.milestone, ms.window, ms.gate || '—']))}` : ''}
    ${cert.criteria.length ? gridTable(['Certification Criterion', 'Required', 'Measured', 'Met'], cert.criteria.map((c) => [c.criterion, c.required, c.actual, c.met ? '✓ Yes' : '✗ No'])) : ''}
    <p style="font-size:12px;color:#475569">${esc(cert.attestation)}</p>
    <div class="cert-sign">
      ${verifyUrl ? `<div class="qr">${qrSvg(verifyUrl, 128)}</div>` : ''}
      <div class="sig">
        <div><b>Digitally signed by:</b> ${esc(cert.signedBy || 'Evidence Not Available')} (${esc(cert.signedRole || '—')})${report.integrity ? ` · <b>Signed at:</b> ${esc(new Date(report.integrity.signedAt).toLocaleString())}` : ''}</div>
        ${report.integrity ? `<div class="hash"><b>Report integrity (${esc(report.integrity.algorithm)}):</b> ${esc(report.integrity.hash)}</div>` : '<div style="margin-top:6px;color:#64748B">Integrity hash is attached when the report is signed at generation time.</div>'}
        ${verifyUrl ? `<div style="margin-top:8px;color:#64748B">${esc(cert.verificationHint)}<br/>Verification URL: <a href="${esc(verifyUrl)}">${esc(verifyUrl.split('?')[0])}?token=…</a></div>` : ''}
      </div>
    </div>
  </div>

  <div class="foot"><span>${esc(branding.companyName)} · ${esc(meta.title)}</span><span>${esc(branding.classification)} · v${esc(meta.version)}</span></div>
</div>
</body></html>`;

  return new Blob([html], { type: 'text/html;charset=utf-8' });
}
