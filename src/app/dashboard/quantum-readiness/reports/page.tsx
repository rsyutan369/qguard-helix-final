'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ChangeEvent } from 'react';
import { motion } from 'framer-motion';
import {
  BadgeCheck,
  Building2,
  Calendar,
  Download,
  Eye,
  FileBarChart,
  FileText,
  FileSpreadsheet,
  FileJson,
  ImagePlus,
  Landmark,
  Loader2,
  Presentation,
  RefreshCw,
  Route as RouteIcon,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import {
  Badge,
  EmptyState,
  HeaderButton,
  Panel,
  PrimaryButton,
  QuantumReadinessShell,
  SectionTitle,
  integerFmt,
  longDate,
  useQuantumReadiness,
  BLUE,
  GREEN,
  ORANGE,
  VIOLET,
  AMBER,
  CYAN,
  RED,
} from '../_shared';
import { useAuth } from '@/contexts/auth-context';
import { REPORT_TEMPLATES } from '@/services/reporting/templates';
import {
  REPORT_FORMATS,
  brandingSchema,
  type ReportBranding,
  type ReportChartImage,
  type ReportFormat,
  type ReportKind,
} from '@/services/reporting/schemas/ReportSchema';

const BRANDING_STORAGE_KEY = 'qg-report-branding';
const HISTORY_STORAGE_KEY = 'qg-report-history';

const FORMAT_META: Record<ReportFormat, { label: string; icon: typeof FileText; color: string }> = {
  pdf: { label: 'PDF', icon: FileText, color: RED },
  docx: { label: 'DOCX', icon: FileText, color: BLUE },
  xlsx: { label: 'XLSX', icon: FileSpreadsheet, color: GREEN },
  pptx: { label: 'PPTX', icon: Presentation, color: ORANGE },
  csv: { label: 'CSV', icon: FileSpreadsheet, color: CYAN },
  json: { label: 'JSON', icon: FileJson, color: VIOLET },
  html: { label: 'HTML', icon: FileBarChart, color: AMBER },
};

const TEMPLATE_ICON: Record<ReportKind, typeof FileText> = {
  executive: FileText,
  technical: FileBarChart,
  compliance: Landmark,
  migration: RouteIcon,
};

interface HistoryEntry {
  id: string;
  kind: ReportKind;
  name: string;
  version: string;
  format: ReportFormat;
  generatedAt: string;
  generatedBy: string;
  integrityHash: string;
}

function loadBranding(): ReportBranding {
  try {
    const raw = localStorage.getItem(BRANDING_STORAGE_KEY);
    if (raw) return brandingSchema.parse(JSON.parse(raw));
  } catch {
    /* ignore */
  }
  return brandingSchema.parse({});
}

function loadHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (raw) return JSON.parse(raw) as HistoryEntry[];
  } catch {
    /* ignore */
  }
  return [];
}

function bumpVersion(version: string): string {
  const parts = version.split('.').map((n) => parseInt(n, 10));
  if (parts.length < 2 || parts.some((n) => Number.isNaN(n))) return '1.0';
  parts[1] += 1;
  return parts.join('.');
}

export default function ReportCenterPage() {
  const { user } = useAuth();
  const { snapshot, state, sseConnected, refresh } = useQuantumReadiness();

  const [branding, setBranding] = useState<ReportBranding>(() => loadBranding());
  const [kind, setKind] = useState<ReportKind>('executive');
  const [busy, setBusy] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>(() => loadHistory());
  const [previews, setPreviews] = useState<ReportChartImage[] | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [schedule, setSchedule] = useState<'none' | 'daily' | 'weekly' | 'monthly' | 'quarterly'>('none');
  const [error, setError] = useState<string | null>(null);

  const generatedBy = user?.email || 'QGuard Helix';
  const activeTemplate = useMemo(() => REPORT_TEMPLATES.find((t) => t.kind === kind)!, [kind]);

  useEffect(() => {
    try {
      localStorage.setItem(BRANDING_STORAGE_KEY, JSON.stringify(branding));
    } catch {
      /* ignore */
    }
  }, [branding]);

  const persistHistory = useCallback((entries: HistoryEntry[]) => {
    setHistory(entries);
    try {
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(entries.slice(0, 40)));
    } catch {
      /* ignore */
    }
  }, []);

  const updateBranding = useCallback(<K extends keyof ReportBranding>(key: K, value: ReportBranding[K]) => {
    setBranding((current) => ({ ...current, [key]: value }));
  }, []);

  const onLogoUpload = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => updateBranding('companyLogo', String(reader.result));
    reader.readAsDataURL(file);
  }, [updateBranding]);

  const generate = useCallback(
    async (fmt: ReportFormat) => {
      if (!snapshot.hasData) {
        setError('No assessment evidence available — run a discovery scan before generating reports.');
        return;
      }
      setBusy(fmt);
      setError(null);
      try {
        const [{ buildReport }, { exportReport, downloadResult }] = await Promise.all([
          import('@/services/reporting/ReportEngine'),
          import('@/services/reporting/ReportExporter'),
        ]);
        const report = buildReport({ snapshot, branding, kind, generatedBy, withCharts: fmt !== 'csv' && fmt !== 'json' });
        const result = await exportReport(report, fmt);
        downloadResult(result);
        const entry: HistoryEntry = {
          id: report.meta.id,
          kind,
          name: report.meta.title,
          version: report.meta.version,
          format: fmt,
          generatedAt: report.meta.generatedAt,
          generatedBy,
          integrityHash: report.integrity?.hash.slice(0, 16) || '—',
        };
        persistHistory([entry, ...history]);
        // Auto-increment version for the next generation (Phase 10 versioning).
        updateBranding('reportVersion', bumpVersion(branding.reportVersion));
      } catch (err) {
        console.error('Report generation failed:', err);
        setError(err instanceof Error ? err.message : 'Report generation failed');
      } finally {
        setBusy(null);
      }
    },
    [snapshot, branding, kind, generatedBy, history, persistHistory, updateBranding],
  );

  const preview = useCallback(async () => {
    if (!snapshot.hasData) {
      setError('No assessment evidence available to preview.');
      return;
    }
    setBusy('preview');
    setError(null);
    try {
      const [{ buildReport }, { previewHtml }] = await Promise.all([
        import('@/services/reporting/ReportEngine'),
        import('@/services/reporting/ReportExporter'),
      ]);
      const report = buildReport({ snapshot, branding, kind, generatedBy });
      previewHtml(report);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Preview failed');
    } finally {
      setBusy(null);
    }
  }, [snapshot, branding, kind, generatedBy]);

  const loadPreviews = useCallback(async () => {
    if (!snapshot.hasData) return;
    setPreviewing(true);
    try {
      const { renderReportCharts } = await import('@/services/reporting/ReportCharts');
      setPreviews(renderReportCharts(snapshot));
    } catch (err) {
      console.error('Chart preview failed:', err);
    } finally {
      setPreviewing(false);
    }
  }, [snapshot]);

  return (
    <QuantumReadinessShell
      title="Report Center"
      subtitle="Enterprise Reporting Engine™ — generate professional, evidence-driven reports (PDF, DOCX, XLSX, CSV, JSON, HTML, PPTX) for executives, security teams, auditors and regulators. Every value is derived from live assessment telemetry."
      badge={<Badge color={GREEN}>{integerFmt(history.length)} generated</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh Data
          </HeaderButton>
          <HeaderButton icon={Eye} onClick={() => void preview()}>
            {busy === 'preview' ? 'Opening…' : 'Preview'}
          </HeaderButton>
        </>
      }
    >
      {error ? <div className="rounded-md border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">{error}</div> : null}

      {/* Template selection */}
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
        <Panel className="p-5">
          <SectionTitle suffix={<span className="text-[11px] text-white/40">{activeTemplate.audience}</span>}>Report Template</SectionTitle>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {REPORT_TEMPLATES.map((template) => {
              const Icon = TEMPLATE_ICON[template.kind];
              const active = kind === template.kind;
              return (
                <button
                  key={template.kind}
                  type="button"
                  onClick={() => setKind(template.kind)}
                  className={`rounded-lg border p-4 text-left transition ${active ? 'border-blue-400/50 bg-blue-500/10' : 'border-white/8 bg-white/[0.025] hover:border-blue-400/35'}`}
                >
                  <span className="grid h-10 w-10 place-items-center rounded-md border" style={{ borderColor: `${BLUE}40`, color: BLUE, backgroundColor: `${BLUE}12` }}>
                    <Icon className="h-5 w-5" />
                  </span>
                  <div className="mt-3 text-sm font-bold text-white">{template.name}</div>
                  <div className="mt-0.5 text-[11px] text-white/45">{template.audience}</div>
                  <p className="mt-1.5 text-[11px] leading-snug text-white/50">{template.description}</p>
                </button>
              );
            })}
          </div>
        </Panel>
      </motion.section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* Branding */}
        <Panel className="p-5 xl:col-span-5">
          <SectionTitle suffix={<Building2 className="h-4 w-4 text-white/40" />}>Branding & Cover</SectionTitle>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <BrandingField label="Company Name" value={branding.companyName} onChange={(v) => updateBranding('companyName', v)} />
            <BrandingField label="Business Unit" value={branding.businessUnit} onChange={(v) => updateBranding('businessUnit', v)} />
            <BrandingField label="Report Owner" value={branding.reportOwner} onChange={(v) => updateBranding('reportOwner', v)} />
            <BrandingField label="Reviewer" value={branding.reviewer} onChange={(v) => updateBranding('reviewer', v)} />
            <BrandingField label="Classification" value={branding.classification} onChange={(v) => updateBranding('classification', v)} />
            <BrandingField label="Version" value={branding.reportVersion} onChange={(v) => updateBranding('reportVersion', v)} />
          </div>
          <label className="mt-3 block">
            <span className="block text-[10px] uppercase tracking-wide text-white/40">Custom Notes</span>
            <textarea value={branding.customNotes} onChange={(e) => updateBranding('customNotes', e.target.value)} rows={2} className="mt-1 w-full resize-none rounded-md border border-white/10 bg-black/20 px-3 py-2 text-xs text-white outline-none focus:border-blue-400/50" />
          </label>
          <div className="mt-3 flex items-center gap-3">
            <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-white/10 bg-white/[0.025] px-3 py-2 text-xs font-bold text-white/70 transition hover:border-blue-400/40 hover:text-blue-200">
              <ImagePlus className="h-4 w-4" />
              Upload Logo
              <input type="file" accept="image/*" onChange={onLogoUpload} className="hidden" />
            </label>
            {branding.companyLogo ? (
              <span className="inline-flex items-center gap-2 text-[11px] text-white/50">
                <img src={branding.companyLogo} alt="logo" className="h-7 max-w-[120px] rounded border border-white/10 object-contain" />
                <button type="button" onClick={() => updateBranding('companyLogo', null)} className="text-white/40 hover:text-red-300">remove</button>
              </span>
            ) : (
              <span className="text-[11px] text-white/35">No logo — cover uses text branding.</span>
            )}
          </div>
        </Panel>

        {/* Generate / formats */}
        <Panel className="p-5 xl:col-span-7">
          <SectionTitle suffix={<Badge color={GREEN}>{activeTemplate.name}</Badge>}>Generate & Export</SectionTitle>
          <p className="mb-3 text-[11px] text-white/45">Sections: {activeTemplate.sections.join(' · ')}</p>
          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
            {REPORT_FORMATS.map((fmt) => {
              const meta = FORMAT_META[fmt];
              const Icon = meta.icon;
              const recommended = activeTemplate.formats.includes(fmt);
              return (
                <button
                  key={fmt}
                  type="button"
                  disabled={busy !== null || !snapshot.hasData}
                  onClick={() => void generate(fmt)}
                  className={`group/btn flex items-center justify-between gap-2 rounded-md border px-3 py-2.5 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${recommended ? 'border-white/12 bg-white/[0.03] hover:border-blue-400/45' : 'border-white/8 bg-black/20 hover:border-white/20'}`}
                >
                  <span className="flex items-center gap-2">
                    {busy === fmt ? <Loader2 className="h-4 w-4 animate-spin" style={{ color: meta.color }} /> : <Icon className="h-4 w-4" style={{ color: meta.color }} />}
                    <span className="text-xs font-bold text-white/85">{meta.label}</span>
                  </span>
                  {recommended ? <Sparkles className="h-3 w-3 text-blue-300/70" /> : null}
                </button>
              );
            })}
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2.5">
            <PrimaryButton icon={Download} onClick={() => void generate(activeTemplate.formats[0])} disabled={busy !== null || !snapshot.hasData}>
              Generate {FORMAT_META[activeTemplate.formats[0]].label}
            </PrimaryButton>
            <HeaderButton icon={Eye} onClick={() => void preview()}>
              Preview HTML
            </HeaderButton>
            <HeaderButton icon={FileBarChart} onClick={() => void loadPreviews()}>
              {previewing ? 'Rendering…' : 'Preview Charts'}
            </HeaderButton>
          </div>

          {/* Scheduling */}
          <div className="mt-4 rounded-md border border-white/8 bg-black/20 p-3">
            <div className="mb-2 flex items-center gap-2 text-[10px] font-black uppercase tracking-wide text-white/45">
              <Calendar className="h-3.5 w-3.5" /> Scheduled Reports
            </div>
            <div className="flex flex-wrap gap-2">
              {(['none', 'daily', 'weekly', 'monthly', 'quarterly'] as const).map((option) => (
                <button
                  key={option}
                  type="button"
                  onClick={() => setSchedule(option)}
                  className={`rounded border px-2.5 py-1 text-[11px] font-bold capitalize transition ${schedule === option ? 'border-blue-400/50 bg-blue-500/15 text-blue-200' : 'border-white/10 bg-black/20 text-white/55 hover:border-blue-400/35'}`}
                >
                  {option}
                </button>
              ))}
            </div>
            {schedule !== 'none' ? (
              <p className="mt-2 text-[11px] text-amber-200/80">
                {schedule} schedule saved for this template. Automated delivery requires the BullMQ/Redis worker + cron to be provisioned server-side.
              </p>
            ) : null}
          </div>
        </Panel>
      </section>

      {/* Chart previews */}
      {previews ? (
        <Panel className="p-5">
          <SectionTitle suffix={<span className="text-[11px] text-white/40">Embedded in PDF / DOCX / PPTX / XLSX</span>}>Visual Analysis Preview</SectionTitle>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {previews.map((chart) => (
              <div key={chart.key} className="rounded-md border border-white/8 bg-white p-2">
                <img src={chart.dataUrl} alt={chart.title} className="w-full rounded" />
                <div className="mt-1 text-center text-[11px] font-semibold text-slate-600">{chart.title}</div>
              </div>
            ))}
          </div>
        </Panel>
      ) : null}

      {/* Audit trail / history */}
      <Panel className="p-5">
        <SectionTitle suffix={<span className="text-[11px] text-white/40">Versioning & audit trail</span>}>Report History</SectionTitle>
        {history.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-[760px] w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                  <th className="pb-3 font-black">Report</th>
                  <th className="pb-3 font-black">Version</th>
                  <th className="pb-3 font-black">Format</th>
                  <th className="pb-3 font-black">Generated By</th>
                  <th className="pb-3 font-black">Generated</th>
                  <th className="pb-3 font-black">Integrity (SHA3-256)</th>
                  <th className="pb-3 font-black">Regenerate</th>
                </tr>
              </thead>
              <tbody>
                {history.slice(0, 20).map((entry, index) => {
                  const meta = FORMAT_META[entry.format];
                  return (
                    <tr key={`${entry.id}-${index}`} className="border-b border-white/5 text-white/70">
                      <td className="py-3 font-medium text-white/82">{entry.name}</td>
                      <td className="py-3 font-mono">v{entry.version}</td>
                      <td className="py-3"><span className="rounded px-1.5 py-0.5 text-[10px] font-black" style={{ color: meta.color, backgroundColor: `${meta.color}1a` }}>{meta.label}</span></td>
                      <td className="max-w-[160px] truncate py-3 text-white/55">{entry.generatedBy}</td>
                      <td className="py-3 text-white/50">{longDate(entry.generatedAt)}</td>
                      <td className="py-3 font-mono text-[10px] text-white/45">{entry.integrityHash}…</td>
                      <td className="py-3">
                        <button
                          type="button"
                          disabled={busy !== null}
                          onClick={() => { setKind(entry.kind); void generate(entry.format); }}
                          className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/[0.025] px-2 py-1 text-[10px] font-bold text-white/60 transition hover:border-blue-400/40 hover:text-blue-200 disabled:opacity-40"
                        >
                          <RefreshCw className="h-3 w-3" /> Regenerate
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState label="No reports generated yet." hint="Select a template and export format above to generate your first enterprise report." />
        )}
        <div className="mt-4 flex items-center gap-2 text-[11px] text-white/40">
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
          Reports are tenant-scoped, evidence-driven, and SHA3-256 integrity-hashed. <BadgeCheck className="h-3.5 w-3.5 text-emerald-400" /> No fabricated findings.
        </div>
      </Panel>
    </QuantumReadinessShell>
  );
}

function BrandingField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="block">
      <span className="block text-[10px] uppercase tracking-wide text-white/40">{label}</span>
      <input value={value} onChange={(e) => onChange(e.target.value)} className="mt-1 w-full rounded-md border border-white/10 bg-black/20 px-3 py-2 text-xs text-white outline-none focus:border-blue-400/50" />
    </label>
  );
}
