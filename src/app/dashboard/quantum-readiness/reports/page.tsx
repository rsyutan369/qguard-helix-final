'use client';

import { useCallback, useState } from 'react';
import { motion } from 'framer-motion';
import {
  BadgeCheck,
  Boxes,
  FileBarChart,
  FileCheck2,
  FileJson,
  FileSpreadsheet,
  FileText,
  Landmark,
  Presentation,
  RefreshCw,
  Route as RouteIcon,
} from 'lucide-react';
import {
  Badge,
  EmptyState,
  HeaderButton,
  Panel,
  PrimaryButton,
  QuantumReadinessShell,
  SectionTitle,
  currencyFmt,
  integerFmt,
  longDate,
  percentLabel,
  useQuantumReadiness,
  type QuantumReadinessSnapshot,
  BLUE,
  GREEN,
  ORANGE,
  VIOLET,
  AMBER,
  CYAN,
} from '../_shared';

type ReportType = 'executive' | 'technical' | 'board' | 'roadmap' | 'compliance' | 'evidence';

interface ReportTemplate {
  id: ReportType;
  name: string;
  description: string;
  icon: typeof FileText;
  color: string;
  formats: Array<'pdf' | 'pptx' | 'csv' | 'json'>;
}

const TEMPLATES: ReportTemplate[] = [
  { id: 'executive', name: 'Executive Report', description: 'Board-ready posture, business risk & investment summary.', icon: FileText, color: BLUE, formats: ['pdf', 'json'] },
  { id: 'technical', name: 'Technical Report', description: 'Full risk analysis, findings & remediation detail.', icon: FileBarChart, color: CYAN, formats: ['pdf', 'csv', 'json'] },
  { id: 'board', name: 'Board Presentation', description: 'Slide-ready strategic risk narrative.', icon: Presentation, color: VIOLET, formats: ['pptx', 'pdf'] },
  { id: 'roadmap', name: 'Migration Roadmap', description: 'Wave plan, sequencing, effort & cost estimates.', icon: RouteIcon, color: ORANGE, formats: ['pdf', 'csv', 'json'] },
  { id: 'compliance', name: 'Compliance Report', description: 'NIST FIPS 203/204/205 & regulatory alignment.', icon: Landmark, color: GREEN, formats: ['pdf', 'json'] },
  { id: 'evidence', name: 'Evidence Package', description: 'Raw assessment evidence for audit & attestation.', icon: Boxes, color: AMBER, formats: ['csv', 'json'] },
];

interface ReportRecord {
  id: string;
  type: ReportType;
  name: string;
  createdAt: string;
  status: 'draft' | 'approved';
  readiness: number;
  risk: number;
}

function buildReportPayload(type: ReportType, snapshot: QuantumReadinessSnapshot) {
  const base = {
    report: type,
    generatedAt: new Date().toISOString(),
    quantumReadinessScore: snapshot.scores.quantumReadiness,
    quantumRiskScore: snapshot.scores.quantumRisk,
    hndlRiskScore: snapshot.scores.hndlRisk,
    pqcAdoption: snapshot.scores.pqcAdoption,
  };
  switch (type) {
    case 'technical':
      return { ...base, riskDistribution: snapshot.riskDistribution, riskFactors: snapshot.riskFactors, findings: snapshot.criticalFindings, topRiskAssets: snapshot.topRiskAssets };
    case 'roadmap':
      return { ...base, estimates: snapshot.estimates, recommendedActions: snapshot.recommendedActions, topRiskAssets: snapshot.topRiskAssets };
    case 'compliance':
      return { ...base, standards: ['NIST FIPS 203 (ML-KEM)', 'NIST FIPS 204 (ML-DSA)', 'NIST FIPS 205 (SLH-DSA)', 'CNSA 2.0'], inventory: snapshot.inventory };
    case 'evidence':
      return { ...base, inventory: snapshot.inventory, telemetry: snapshot.telemetry, findings: snapshot.criticalFindings, exposureGraph: snapshot.exposureGraph };
    case 'board':
    case 'executive':
    default:
      return { ...base, inventory: snapshot.inventory, estimates: snapshot.estimates, recommendedActions: snapshot.recommendedActions.slice(0, 5) };
  }
}

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function toCsv(payload: Record<string, unknown>): string {
  const rows: string[] = ['key,value'];
  const walk = (obj: unknown, prefix = '') => {
    if (Array.isArray(obj)) {
      obj.forEach((item, i) => walk(item, `${prefix}[${i}]`));
    } else if (obj && typeof obj === 'object') {
      for (const [k, v] of Object.entries(obj as Record<string, unknown>)) walk(v, prefix ? `${prefix}.${k}` : k);
    } else {
      rows.push(`"${prefix}","${String(obj).replace(/"/g, '""')}"`);
    }
  };
  walk(payload);
  return rows.join('\n');
}

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function openPrintable(type: ReportType, name: string, snapshot: QuantumReadinessSnapshot) {
  const s = snapshot.scores;
  const win = window.open('', '_blank');
  if (!win) return;
  const safeName = escapeHtml(name);
  win.document.write(`<!doctype html><html><head><title>${safeName}</title>
    <style>
      body{font-family:Inter,Arial,sans-serif;color:#0f172a;max-width:820px;margin:40px auto;padding:0 24px}
      h1{font-size:24px;margin-bottom:4px}.sub{color:#64748b;margin-bottom:24px}
      .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:20px 0}
      .card{border:1px solid #e2e8f0;border-radius:8px;padding:14px}.card .n{font-size:28px;font-weight:700}
      .card .l{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#64748b}
      table{width:100%;border-collapse:collapse;margin-top:12px}td,th{border-bottom:1px solid #e2e8f0;padding:8px;text-align:left;font-size:13px}
      .foot{margin-top:32px;color:#94a3b8;font-size:11px}
    </style></head><body>
    <h1>${safeName}</h1>
    <div class="sub">QGuard Helix — Quantum Readiness Assessment Engine™ · Generated ${escapeHtml(new Date().toLocaleString())}</div>
    <div class="grid">
      <div class="card"><div class="n">${s.quantumReadiness}/100</div><div class="l">Quantum Readiness</div></div>
      <div class="card"><div class="n">${s.quantumRisk}/100</div><div class="l">Quantum Risk</div></div>
      <div class="card"><div class="n">${s.hndlRisk}/100</div><div class="l">HNDL Risk</div></div>
      <div class="card"><div class="n">${snapshot.inventory.assetsAssessed}</div><div class="l">Assets Assessed</div></div>
      <div class="card"><div class="n">${snapshot.inventory.quantumVulnerableAssets}</div><div class="l">Vulnerable Assets</div></div>
      <div class="card"><div class="n">${s.pqcAdoption}%</div><div class="l">PQC Adoption</div></div>
    </div>
    <h3>Recommended Actions</h3>
    <table><tr><th>Action</th><th>Severity</th></tr>
    ${snapshot.recommendedActions.map((a) => `<tr><td>${escapeHtml(a.title)}</td><td>${escapeHtml(a.severity)}</td></tr>`).join('') || '<tr><td colspan="2">No actions</td></tr>'}
    </table>
    <div class="foot">Evidence-grounded report. Estimated migration: ${snapshot.estimates.migrationTimelineWeeks || '—'} weeks · ${snapshot.estimates.migrationCostUsd ? currencyFmt(snapshot.estimates.migrationCostUsd) : '—'}.</div>
    </body></html>`);
  win.document.close();
  win.focus();
  win.print();
}

export default function ReportCenterPage() {
  const { snapshot, state, sseConnected, refresh } = useQuantumReadiness();
  const [history, setHistory] = useState<ReportRecord[]>([]);
  const [generating, setGenerating] = useState<ReportType | null>(null);

  const generate = useCallback(
    (template: ReportTemplate) => {
      if (!snapshot.hasData) return;
      setGenerating(template.id);
      window.setTimeout(() => {
        const record: ReportRecord = {
          id: `rpt-${template.id}-${Date.now()}`,
          type: template.id,
          name: template.name,
          createdAt: new Date().toISOString(),
          status: 'draft',
          readiness: snapshot.scores.quantumReadiness,
          risk: snapshot.scores.quantumRisk,
        };
        setHistory((prev) => [record, ...prev].slice(0, 15));
        setGenerating(null);
      }, 500);
    },
    [snapshot],
  );

  const approve = useCallback((id: string) => {
    setHistory((prev) => prev.map((r) => (r.id === id ? { ...r, status: 'approved' as const } : r)));
  }, []);

  const exportReport = useCallback(
    (record: ReportRecord, format: 'pdf' | 'pptx' | 'csv' | 'json') => {
      const payload = buildReportPayload(record.type, snapshot);
      const stamp = new Date().toISOString().slice(0, 10);
      const fname = `${record.type}-report-${stamp}`;
      if (format === 'json') download(`${fname}.json`, JSON.stringify(payload, null, 2), 'application/json');
      else if (format === 'csv') download(`${fname}.csv`, toCsv(payload as Record<string, unknown>), 'text/csv');
      else openPrintable(record.type, record.name, snapshot);
    },
    [snapshot],
  );

  const formatIcon = { pdf: FileText, pptx: Presentation, csv: FileSpreadsheet, json: FileJson } as const;

  return (
    <QuantumReadinessShell
      title="Report Center"
      subtitle="Generate customer-facing reports and exportable deliverables — executive, technical, board, migration roadmap, compliance and audit-grade evidence packages."
      badge={<Badge color={GREEN}>{integerFmt(history.length)} generated</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
          Refresh Data
        </HeaderButton>
      }
    >
      {/* Snapshot banner */}
      <Panel className="p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="inline-flex items-center gap-2 text-[11px] font-black uppercase tracking-wide text-white/45">
            <BadgeCheck className="h-4 w-4 text-emerald-400" /> Reports reflect live assessment data
          </span>
          <div className="flex flex-wrap gap-2 text-[11px]">
            <span className="rounded-md border border-white/8 bg-black/20 px-2.5 py-1">Readiness <strong className="font-mono text-white/80">{integerFmt(snapshot.scores.quantumReadiness)}</strong></span>
            <span className="rounded-md border border-white/8 bg-black/20 px-2.5 py-1">Risk <strong className="font-mono text-white/80">{integerFmt(snapshot.scores.quantumRisk)}</strong></span>
            <span className="rounded-md border border-white/8 bg-black/20 px-2.5 py-1">PQC <strong className="font-mono text-white/80">{percentLabel(snapshot.scores.pqcAdoption)}</strong></span>
            <span className="rounded-md border border-white/8 bg-black/20 px-2.5 py-1">Assets <strong className="font-mono text-white/80">{integerFmt(snapshot.inventory.assetsAssessed)}</strong></span>
          </div>
        </div>
      </Panel>

      {/* Template grid */}
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {TEMPLATES.map((template) => {
          const Icon = template.icon;
          return (
            <div key={template.id}>
            <Panel className="p-5">
              <div className="flex items-start justify-between">
                <span className="grid h-11 w-11 place-items-center rounded-md border" style={{ borderColor: `${template.color}40`, color: template.color, backgroundColor: `${template.color}12` }}>
                  <Icon className="h-5 w-5" />
                </span>
                <div className="flex gap-1">
                  {template.formats.map((fmt) => (
                    <span key={fmt} className="rounded border border-white/10 bg-black/20 px-1.5 py-0.5 text-[9px] font-black uppercase text-white/45">
                      {fmt}
                    </span>
                  ))}
                </div>
              </div>
              <div className="mt-3 text-sm font-bold text-white">{template.name}</div>
              <p className="mt-1 text-[11px] leading-snug text-white/50">{template.description}</p>
              <div className="mt-4">
                <PrimaryButton icon={FileCheck2} onClick={() => generate(template)} disabled={!snapshot.hasData || generating === template.id}>
                  {generating === template.id ? 'Generating…' : 'Generate'}
                </PrimaryButton>
              </div>
            </Panel>
            </div>
          );
        })}
      </motion.section>

      {/* History + approval */}
      <Panel className="p-5">
        <SectionTitle suffix={<span className="text-[11px] text-white/40">Approval workflow & downloads</span>}>Report History</SectionTitle>
        {history.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-[680px] w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                  <th className="pb-3 font-black">Report</th>
                  <th className="pb-3 font-black">Generated</th>
                  <th className="pb-3 font-black">Scores</th>
                  <th className="pb-3 font-black">Status</th>
                  <th className="pb-3 font-black">Export</th>
                  <th className="pb-3 font-black">Approval</th>
                </tr>
              </thead>
              <tbody>
                {history.map((record) => {
                  const template = TEMPLATES.find((t) => t.id === record.type)!;
                  return (
                    <tr key={record.id} className="border-b border-white/5 text-white/70">
                      <td className="py-3 font-medium text-white/82">{record.name}</td>
                      <td className="py-3 text-white/50">{longDate(record.createdAt)}</td>
                      <td className="py-3 font-mono text-white/60">R{record.readiness} · Q{record.risk}</td>
                      <td className="py-3">
                        <Badge color={record.status === 'approved' ? GREEN : AMBER}>{record.status}</Badge>
                      </td>
                      <td className="py-3">
                        <div className="flex gap-1">
                          {template.formats.map((fmt) => {
                            const Icon = formatIcon[fmt];
                            return (
                              <button
                                key={fmt}
                                type="button"
                                onClick={() => exportReport(record, fmt)}
                                title={`Export ${fmt.toUpperCase()}`}
                                className="grid h-7 w-7 place-items-center rounded border border-white/10 bg-black/20 text-white/55 transition hover:border-blue-400/40 hover:text-blue-200"
                              >
                                <Icon className="h-3.5 w-3.5" />
                              </button>
                            );
                          })}
                        </div>
                      </td>
                      <td className="py-3">
                        {record.status === 'approved' ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-300">
                            <BadgeCheck className="h-3.5 w-3.5" /> Approved
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => approve(record.id)}
                            className="rounded border border-emerald-400/30 bg-emerald-400/10 px-2.5 py-1 text-[11px] font-bold text-emerald-200 transition hover:bg-emerald-400/20"
                          >
                            Approve
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState label="No reports generated yet." hint="Generate a report from a template above to start the approval workflow." />
        )}
      </Panel>
    </QuantumReadinessShell>
  );
}
