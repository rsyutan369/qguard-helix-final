'use client';

/**
 * Exposure Report Studio — the enterprise report builder for the Local and Dev
 * scanner modes.
 *
 * Modelled on the Assets page's Report Studio (templates, branding, seven
 * formats, preview, history, SHA3-256 integrity) and built from the assessment
 * the panel is rendering: the figures are the panel's figures, and the
 * pre-export validation shown here is the validation printed inside the
 * document.
 *
 * Loaded lazily by the panels, so the builder, the integrity code and the five
 * heavy renderers never weigh on the scanner's first paint.
 */

import React from 'react';
import {
  AlertTriangle,
  Building2,
  Check,
  CheckCircle2,
  ChevronDown,
  Eye,
  FileBarChart,
  FileCode2,
  FileJson,
  FileSpreadsheet,
  FileText,
  History,
  ImagePlus,
  Layers,
  Loader2,
  Presentation,
  RefreshCw,
  ScrollText,
  ShieldCheck,
  Wrench,
  X,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { SCAN_MODE_LABEL, type ExposureAssessment } from '@/lib/scanner/exposure/types';
import { coverageGapPhrase, reconcileExposure } from '@/lib/scanner/exposure/exposure-truth';
import {
  EXPOSURE_REPORT_DEPTHS,
  EXPOSURE_REPORT_TEMPLATES,
  buildExposureReport,
  describeTarget,
  type ExposureReportDepth,
  type ExposureReportRecord,
  type ExposureReportTemplate,
} from '@/services/reporting/ExposureReport';
import { brandingSchema, type ReportBranding } from '@/services/reporting/schemas/ReportSchema';
import type { DocumentFormat } from '@/services/reporting/exporters/DocumentExporters';

/** Shared with every other report surface, so branding is configured once. */
const BRANDING_STORAGE_KEY = 'qg-report-branding';
const HISTORY_STORAGE_KEY = 'qg-exposure-report-history';

/**
 * One entry per REPORT (id + seal), listing every format exported from it — a
 * PDF and a spreadsheet of the same report share one id and one digest.
 */
interface HistoryEntry {
  id: string;
  name: string;
  template: ExposureReportTemplate;
  depth: ExposureReportDepth;
  scanId: string;
  scopeLabel: string;
  formats: DocumentFormat[];
  generatedAt: string;
  hash: string;
  quality: string;
}

const FORMATS: Array<{ format: DocumentFormat; label: string; detail: string; icon: LucideIcon; tone: string }> = [
  { format: 'pdf', label: 'PDF', detail: 'Board-ready, print & sign', icon: FileText, tone: 'text-rose-400' },
  { format: 'docx', label: 'Word', detail: 'Editable document', icon: FileText, tone: 'text-sky-400' },
  { format: 'xlsx', label: 'Excel', detail: 'Complete registers, filterable', icon: FileSpreadsheet, tone: 'text-emerald-400' },
  { format: 'pptx', label: 'PowerPoint', detail: 'Executive deck', icon: Presentation, tone: 'text-orange-400' },
  { format: 'html', label: 'HTML', detail: 'Self-contained, shareable', icon: FileCode2, tone: 'text-amber-400' },
  { format: 'csv', label: 'CSV', detail: 'Raw registers for analysis', icon: FileSpreadsheet, tone: 'text-cyan-400' },
  { format: 'json', label: 'JSON', detail: 'Full sealed model', icon: FileJson, tone: 'text-violet-400' },
];

/** Where each template reads best. Shown as a hint, never a restriction. */
const RECOMMENDED: Record<ExposureReportTemplate, DocumentFormat[]> = {
  executive: ['pdf', 'pptx'],
  technical: ['xlsx', 'pdf'],
  remediation: ['xlsx', 'pdf'],
  compliance: ['pdf', 'xlsx'],
};

const TEMPLATE_ICON: Record<ExposureReportTemplate, LucideIcon> = {
  executive: FileBarChart,
  technical: FileSpreadsheet,
  remediation: Wrench,
  compliance: ScrollText,
};

function loadBranding(): ReportBranding {
  try {
    const raw = window.localStorage.getItem(BRANDING_STORAGE_KEY);
    if (raw) return brandingSchema.parse(JSON.parse(raw));
  } catch {
    /* unreadable or blocked storage — defaults below */
  }
  return brandingSchema.parse({});
}

function loadHistory(): HistoryEntry[] {
  try {
    const raw = window.localStorage.getItem(HISTORY_STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry) => entry && typeof entry.id === 'string').map((entry) => ({ ...entry, formats: Array.isArray(entry.formats) ? entry.formats : [] }));
  } catch {
    return [];
  }
}

function saveJson(key: string, value: unknown) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage full or blocked — the export itself is unaffected */
  }
}

const nf = (value: number) => value.toLocaleString('en-US');

export interface ExposureReportStudioProps {
  open: boolean;
  onClose: () => void;
  /** The assessment being reported on — live, or rebuilt from a record. */
  assessment: ExposureAssessment;
  /** Printed on the cover as the author of the document. */
  generatedBy: string;
  /** Set when the source is a stored record, so its edges are declared. */
  record?: ExposureReportRecord | null;
}

export default function ExposureReportStudio({ open, onClose, assessment, generatedBy, record }: ExposureReportStudioProps) {
  const [template, setTemplate] = React.useState<ExposureReportTemplate>('executive');
  const [depth, setDepth] = React.useState<ExposureReportDepth>('standard');
  const [branding, setBranding] = React.useState<ReportBranding>(() => loadBranding());
  const [brandingOpen, setBrandingOpen] = React.useState(false);
  const [busy, setBusy] = React.useState<DocumentFormat | 'preview' | null>(null);
  const [done, setDone] = React.useState<DocumentFormat | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [history, setHistory] = React.useState<HistoryEntry[]>(() => loadHistory());
  const [showPassed, setShowPassed] = React.useState(false);
  const panelRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    panelRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  const updateBranding = React.useCallback(<K extends keyof ReportBranding>(key: K, value: ReportBranding[K]) => {
    setBranding((current) => {
      const next = { ...current, [key]: value };
      saveJson(BRANDING_STORAGE_KEY, next);
      return next;
    });
  }, []);

  const truth = React.useMemo(() => reconcileExposure(assessment), [assessment]);
  const target = React.useMemo(() => describeTarget(assessment.task.target), [assessment.task.target]);

  /* The pre-export model: the SAME builder the export runs, so the validation
     shown here is the validation printed in the document, and every format
     exported from one configuration shares one report id and one digest. */
  const preview = React.useMemo(
    () => (open ? buildExposureReport({ assessment, template, depth, branding, generatedBy, record: record ?? null }) : null),
    [open, assessment, template, depth, branding, generatedBy, record],
  );

  const validation = preview?.document?.validation;
  const reconciliation = preview?.reconciliation ?? [];
  const reconMatches = reconciliation.filter((row) => row.matches).length;
  const sectionTitles = preview?.document?.sections.map((section) => section.title) ?? [];

  const run = React.useCallback(
    async (format: DocumentFormat, regenerate?: { template: ExposureReportTemplate; depth: ExposureReportDepth }) => {
      setBusy(format);
      setError(null);
      try {
        const report =
          !regenerate && preview
            ? preview
            : buildExposureReport({
                assessment,
                template: regenerate?.template ?? template,
                depth: regenerate?.depth ?? depth,
                branding,
                generatedBy,
                record: record ?? null,
              });
        const { exportDocument, downloadDocument } = await import('@/services/reporting/exporters/DocumentExporters');
        const result = await exportDocument(report, format);
        downloadDocument(result);
        const id = report.meta.reportId || String(Date.now());
        setHistory((current) => {
          const existing = current.find((entry) => entry.id === id);
          const entry: HistoryEntry = existing
            ? { ...existing, formats: existing.formats.includes(format) ? existing.formats : [...existing.formats, format] }
            : {
                id,
                name: report.meta.title,
                template: regenerate?.template ?? template,
                depth: regenerate?.depth ?? depth,
                scanId: assessment.task.scanId,
                scopeLabel: `${target.label} · ${nf(assessment.findings.length)} findings · ${nf(assessment.cbom.length)} components`,
                formats: [format],
                generatedAt: report.meta.generatedAt,
                hash: report.integrity?.hash || '',
                quality: report.document ? `${report.document.validation.status.toUpperCase()} ${report.document.validation.score}` : '—',
              };
          const next = [entry, ...current.filter((item) => item.id !== id)].slice(0, 20);
          saveJson(HISTORY_STORAGE_KEY, next);
          return next;
        });
        setDone(format);
        window.setTimeout(() => setDone(null), 2400);
      } catch (cause) {
        console.error('Exposure report export failed:', cause);
        setError(cause instanceof Error ? cause.message : 'Export failed');
      } finally {
        setBusy(null);
      }
    },
    [preview, assessment, template, depth, branding, generatedBy, record, target.label],
  );

  const previewHtml = React.useCallback(async () => {
    // Open the tab inside the click so pop-up blockers allow it, then fill it.
    const tab = window.open('', '_blank');
    setBusy('preview');
    setError(null);
    try {
      const report = preview ?? buildExposureReport({ assessment, template, depth, branding, generatedBy, record: record ?? null });
      const { renderDocumentHtml } = await import('@/services/reporting/exporters/document/html');
      const url = URL.createObjectURL(renderDocumentHtml(report));
      if (tab) tab.location.href = url;
      else window.open(url, '_blank', 'noopener');
      window.setTimeout(() => URL.revokeObjectURL(url), 120_000);
    } catch (cause) {
      tab?.close();
      setError(cause instanceof Error ? cause.message : 'Preview failed');
    } finally {
      setBusy(null);
    }
  }, [preview, assessment, template, depth, branding, generatedBy, record]);

  const onLogo = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (!/^image\/(png|jpeg)$/.test(file.type)) {
      setError('Upload the logo as PNG or JPEG — those embed in every format (PDF, Word, PowerPoint, HTML).');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => updateBranding('companyLogo', String(reader.result));
    reader.readAsDataURL(file);
  };

  if (!open) return null;

  const failing = validation?.checks.filter((check) => check.status !== 'pass') ?? [];
  const passing = validation?.checks.filter((check) => check.status === 'pass') ?? [];
  const modeLabel = SCAN_MODE_LABEL[assessment.task.mode];

  return (
    <div className="fixed inset-0 z-[70] flex justify-end" role="dialog" aria-modal="true" aria-labelledby="exposure-report-studio-title">
      <button type="button" aria-label="Close Report Studio" className="absolute inset-0 bg-black/60 backdrop-blur-[2px]" onClick={onClose} />
      <div
        ref={panelRef}
        tabIndex={-1}
        className="relative flex h-full w-full max-w-[660px] flex-col overflow-hidden border-l border-white/[0.08] bg-[#080d1a] text-slate-200 shadow-2xl outline-none"
      >
        <header className="flex items-start justify-between gap-3 border-b border-white/[0.07] px-5 py-4">
          <div className="min-w-0">
            <h2 id="exposure-report-studio-title" className="text-[17px] font-black tracking-tight text-white">
              Report Studio
            </h2>
            <p className="mt-0.5 text-[12px] leading-relaxed text-slate-400">
              Enterprise reports built from exactly what this assessment measured — validated before export and sealed with SHA3-256.
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-md p-1.5 text-slate-400 transition-colors hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </header>

        <div className="flex-1 space-y-6 overflow-y-auto px-5 py-5">
          {/* ── the assessment being reported on ───────────────────────── */}
          <section>
            <h3 className="mb-2 font-mono text-[9.5px] font-black uppercase tracking-[0.18em] text-slate-500">Source assessment</h3>
            <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/[0.04] px-4 py-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="truncate text-[13.5px] font-black text-white" title={target.label}>
                  {target.label}
                </p>
                <span className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-cyan-300">
                  {modeLabel} mode · {assessment.task.status === 'partial' ? 'partial coverage' : assessment.task.status}
                </span>
              </div>
              <p className="mt-0.5 text-[11px] text-slate-500">{target.kind}</p>
              <dl className="mt-2.5 grid grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-4">
                {[
                  { label: 'Findings', value: nf(assessment.findings.length) },
                  { label: 'Exposures', value: nf(assessment.exposures.length) },
                  { label: 'Components', value: nf(assessment.cbom.length) },
                  { label: 'Vulnerable', value: nf(truth.components.vulnerable), accent: 'text-rose-300' },
                  { label: 'Readiness', value: truth.readiness === null ? 'Not measured' : `${truth.readiness}%` },
                  { label: 'Security risk', value: assessment.task.scores.securityRisk === null ? '—' : `${assessment.task.scores.securityRisk}/100` },
                  { label: 'Coverage', value: assessment.task.scores.coverage === null ? '—' : `${assessment.task.scores.coverage}%` },
                  { label: 'Critical', value: nf(truth.severity.critical), accent: truth.severity.critical ? 'text-rose-300' : undefined },
                ].map((item) => (
                  <div key={item.label}>
                    <dt className="font-mono text-[8.5px] font-bold uppercase tracking-[0.14em] text-slate-500">{item.label}</dt>
                    <dd className={cn('font-mono text-[13px] font-black', item.accent ?? 'text-slate-200')}>{item.value}</dd>
                  </div>
                ))}
              </dl>
              {record && (
                <p className="mt-2.5 border-t border-white/[0.06] pt-2 text-[11px] leading-relaxed text-violet-200/80">
                  Built from a stored record (version {record.recordVersion}). Fields the record did not retain are named in the document rather than rendered as
                  empty results.
                </p>
              )}
              {truth.partial && (
                <p className="mt-2.5 flex items-start gap-1.5 border-t border-amber-400/20 pt-2 text-[11px] leading-relaxed text-amber-100/85">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>
                    {/* One shared phrase, so this banner cannot name a
                        different cause from the one printed on the KPI card
                        inside the document it is about. */}
                    This scan is partial — {coverageGapPhrase(truth)}. Every report says so on its cover and in its validation section.
                  </span>
                </p>
              )}
            </div>
          </section>

          {/* ── 1 · template ───────────────────────────────────────────── */}
          <section>
            <h3 className="mb-2 font-mono text-[9.5px] font-black uppercase tracking-[0.18em] text-slate-500">1 · Report</h3>
            <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
              {EXPOSURE_REPORT_TEMPLATES.map((candidate) => {
                const Icon = TEMPLATE_ICON[candidate.key];
                const active = candidate.key === template;
                return (
                  <button
                    key={candidate.key}
                    type="button"
                    onClick={() => setTemplate(candidate.key)}
                    aria-pressed={active}
                    className={cn(
                      'flex gap-3 rounded-xl border p-3 text-left transition-colors',
                      active ? 'border-cyan-400/50 bg-cyan-400/[0.07]' : 'border-white/[0.07] bg-white/[0.02] hover:border-cyan-400/30',
                    )}
                  >
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-cyan-400/25 bg-cyan-400/[0.08] text-cyan-300">
                      <Icon className="h-4 w-4" aria-hidden />
                    </span>
                    <span className="min-w-0">
                      <span className="block text-[12.5px] font-black text-white">{candidate.name}</span>
                      <span className="block font-mono text-[9px] font-bold uppercase tracking-[0.14em] text-slate-500">{candidate.audience}</span>
                      <span className="mt-1 block text-[11px] leading-snug text-slate-400">{candidate.description}</span>
                    </span>
                  </button>
                );
              })}
            </div>
            {sectionTitles.length > 0 && (
              <p className="mt-2 text-[10.5px] leading-relaxed text-slate-500">
                Sections in this report: Executive Summary · {sectionTitles.join(' · ')} · Executive Decision Register · Validation, Reconciliation &amp;
                Integrity
              </p>
            )}
          </section>

          {/* ── 2 · presented depth ────────────────────────────────────── */}
          <section>
            <h3 className="mb-2 font-mono text-[9.5px] font-black uppercase tracking-[0.18em] text-slate-500">2 · Presented depth</h3>
            <div className="grid grid-cols-[minmax(0,1fr)] gap-2 sm:grid-cols-3">
              {EXPOSURE_REPORT_DEPTHS.map((candidate) => {
                const active = candidate.key === depth;
                const rows = Number.isFinite(candidate.rows) ? candidate.rows : assessment.findings.length;
                return (
                  <button
                    key={candidate.key}
                    type="button"
                    onClick={() => setDepth(candidate.key)}
                    aria-pressed={active}
                    className={cn(
                      'rounded-xl border p-3 text-left transition-colors',
                      active ? 'border-violet-400/50 bg-violet-400/[0.08]' : 'border-white/[0.07] bg-white/[0.02] hover:border-violet-400/30',
                    )}
                  >
                    <span className="flex items-center justify-between gap-2">
                      <span className="text-[12px] font-black text-white">{candidate.label}</span>
                      <Layers className="h-3.5 w-3.5 shrink-0 text-slate-500" aria-hidden />
                    </span>
                    <span className="mt-1 block text-[10.5px] leading-snug text-slate-400">{candidate.detail}</span>
                    <span className="mt-1 block font-mono text-[9px] uppercase tracking-[0.12em] text-slate-500">
                      {nf(Math.min(rows, assessment.findings.length))} of {nf(assessment.findings.length)} findings shown
                    </span>
                  </button>
                );
              })}
            </div>
            <p className="mt-2 text-[10.5px] leading-relaxed text-slate-500">
              Depth changes only the PDF, Word, HTML and PowerPoint narrative. The Excel, CSV and JSON exports always carry every row, and any table shortened for
              a narrative format states the omission on its own face.
            </p>
          </section>

          {/* ── 3 · branding ───────────────────────────────────────────── */}
          <section>
            <button type="button" onClick={() => setBrandingOpen((value) => !value)} aria-expanded={brandingOpen} className="flex w-full items-center justify-between gap-2 text-left">
              <h3 className="font-mono text-[9.5px] font-black uppercase tracking-[0.18em] text-slate-500">3 · Branding &amp; cover</h3>
              <span className="inline-flex items-center gap-1.5 text-[11px] font-bold text-slate-400">
                <Building2 className="h-3.5 w-3.5" aria-hidden />
                {branding.companyName} · {branding.classification} · v{branding.reportVersion}
                <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', brandingOpen && 'rotate-180')} aria-hidden />
              </span>
            </button>
            {brandingOpen && (
              <div className="mt-3 grid grid-cols-[minmax(0,1fr)] gap-2 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 sm:grid-cols-2">
                {(
                  [
                    ['companyName', 'Company name'],
                    ['businessUnit', 'Business unit'],
                    ['reportOwner', 'Report owner'],
                    ['reviewer', 'Reviewer'],
                    ['classification', 'Classification'],
                    ['reportVersion', 'Version'],
                  ] as const
                ).map(([key, label]) => (
                  <label key={key} className="block">
                    <span className="block font-mono text-[9px] font-black uppercase tracking-[0.14em] text-slate-500">{label}</span>
                    <input
                      value={branding[key]}
                      onChange={(event) => updateBranding(key, event.target.value)}
                      className="mt-1 w-full rounded-lg border border-white/[0.08] bg-white/[0.03] px-2.5 py-1.5 text-[12px] text-slate-200 outline-none transition-colors focus:border-cyan-400/50"
                    />
                  </label>
                ))}
                <label className="block sm:col-span-2">
                  <span className="block font-mono text-[9px] font-black uppercase tracking-[0.14em] text-slate-500">Notes printed with the provenance</span>
                  <textarea
                    value={branding.customNotes}
                    onChange={(event) => updateBranding('customNotes', event.target.value)}
                    rows={2}
                    className="mt-1 w-full resize-none rounded-lg border border-white/[0.08] bg-white/[0.03] px-2.5 py-1.5 text-[12px] text-slate-200 outline-none transition-colors focus:border-cyan-400/50"
                  />
                </label>
                <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
                  <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11px] font-bold text-slate-300 transition-colors hover:border-cyan-400/40">
                    <ImagePlus className="h-4 w-4" aria-hidden /> Upload logo (PNG/JPEG)
                    <input type="file" accept="image/png,image/jpeg" onChange={onLogo} className="hidden" />
                  </label>
                  {branding.companyLogo ? (
                    <span className="inline-flex items-center gap-2 text-[11px] text-slate-500">
                      <img src={branding.companyLogo} alt="Report logo" className="h-7 max-w-[120px] rounded border border-white/[0.08] object-contain" />
                      <button type="button" onClick={() => updateBranding('companyLogo', null)} className="transition-colors hover:text-rose-300">
                        remove
                      </button>
                    </span>
                  ) : (
                    <span className="text-[10.5px] text-slate-500">No logo — the cover uses text branding.</span>
                  )}
                </div>
                <p className="text-[10px] text-slate-500 sm:col-span-2">
                  Shared with the Quantum Readiness Report Center and the Assets register, so every report the platform emits carries the same branding.
                </p>
              </div>
            )}
          </section>

          {/* ── 4 · pre-export validation ──────────────────────────────── */}
          <section>
            <h3 className="mb-2 font-mono text-[9.5px] font-black uppercase tracking-[0.18em] text-slate-500">4 · Pre-export validation</h3>
            {validation ? (
              <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span
                    className={cn(
                      'inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 font-mono text-[10.5px] font-black uppercase tracking-[0.12em]',
                      validation.status === 'pass'
                        ? 'border-emerald-400/35 bg-emerald-400/[0.08] text-emerald-300'
                        : validation.status === 'warn'
                          ? 'border-amber-400/40 bg-amber-400/[0.08] text-amber-200'
                          : 'border-rose-400/40 bg-rose-400/[0.08] text-rose-300',
                    )}
                  >
                    {validation.status === 'pass' ? <CheckCircle2 className="h-3.5 w-3.5" /> : validation.status === 'warn' ? <AlertTriangle className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}
                    Quality {validation.status} · {validation.score}/100
                  </span>
                  <span className="font-mono text-[10.5px] font-bold text-slate-400">
                    Reconciliation {reconMatches}/{reconciliation.length} match
                  </span>
                </div>
                {failing.length > 0 && (
                  <ul className="mt-2.5 space-y-1.5">
                    {failing.map((check) => (
                      <li key={check.check} className="flex gap-2 text-[11px] leading-snug">
                        {check.status === 'fail' ? (
                          <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-400" aria-label="Failed" />
                        ) : (
                          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" aria-label="Warning" />
                        )}
                        <span>
                          <span className="font-black text-slate-200">{check.check}.</span> <span className="text-slate-400">{check.detail}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
                <button
                  type="button"
                  onClick={() => setShowPassed((value) => !value)}
                  className="mt-2.5 font-mono text-[10px] font-black uppercase tracking-[0.14em] text-cyan-300 transition-colors hover:text-cyan-200"
                >
                  {showPassed ? 'Hide' : 'Show'} {passing.length} passed check{passing.length === 1 ? '' : 's'}
                </button>
                {showPassed && (
                  <ul className="mt-1.5 space-y-1">
                    {passing.map((check) => (
                      <li key={check.check} className="flex gap-2 text-[10.5px] leading-snug text-slate-400">
                        <Check className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" aria-hidden />
                        <span>
                          <span className="font-bold text-slate-300">{check.check}</span> — {check.detail}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="mt-2.5 text-[10px] leading-relaxed text-slate-500">
                  Warnings do not block export; they are printed inside the report&apos;s own Validation section so the reader sees them too.
                </p>
              </div>
            ) : (
              <p className="rounded-xl border border-dashed border-white/[0.1] p-3 text-[11px] text-slate-500">Building the report model…</p>
            )}
          </section>

          {/* ── 5 · generate ───────────────────────────────────────────── */}
          <section>
            <div className="mb-2 flex items-center justify-between gap-2">
              <h3 className="font-mono text-[9.5px] font-black uppercase tracking-[0.18em] text-slate-500">5 · Generate</h3>
              <button
                type="button"
                onClick={() => void previewHtml()}
                disabled={busy !== null}
                className="inline-flex items-center gap-1.5 font-mono text-[10px] font-black uppercase tracking-[0.14em] text-cyan-300 transition-colors hover:text-cyan-200 disabled:opacity-40"
              >
                {busy === 'preview' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Eye className="h-3.5 w-3.5" />} Preview
              </button>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {FORMATS.map((item) => {
                const Icon = item.icon;
                const recommended = RECOMMENDED[template].includes(item.format);
                return (
                  <button
                    key={item.format}
                    type="button"
                    disabled={busy !== null}
                    onClick={() => void run(item.format)}
                    className={cn(
                      'relative rounded-xl border p-2.5 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-45',
                      recommended ? 'border-cyan-400/40 bg-cyan-400/[0.05]' : 'border-white/[0.07] bg-white/[0.02]',
                      'hover:border-cyan-400/60',
                    )}
                  >
                    <span className="flex items-center gap-1.5">
                      {busy === item.format ? (
                        <Loader2 className={cn('h-4 w-4 animate-spin', item.tone)} />
                      ) : done === item.format ? (
                        <Check className="h-4 w-4 text-emerald-400" />
                      ) : (
                        <Icon className={cn('h-4 w-4', item.tone)} aria-hidden />
                      )}
                      <span className="text-[12px] font-black text-white">{item.label}</span>
                    </span>
                    <span className="mt-0.5 block text-[9.5px] leading-tight text-slate-500">{item.detail}</span>
                    {recommended && (
                      <span className="absolute right-1.5 top-1.5 font-mono text-[7.5px] font-black uppercase tracking-[0.1em] text-cyan-300">Rec.</span>
                    )}
                  </button>
                );
              })}
            </div>
            {error && (
              <p role="alert" className="mt-2 rounded-lg border border-rose-400/30 bg-rose-500/[0.08] px-3 py-2 text-[11px] text-rose-100/90">
                {error}
              </p>
            )}
          </section>

          {/* ── history ────────────────────────────────────────────────── */}
          <section>
            <h3 className="mb-2 flex items-center gap-1.5 font-mono text-[9.5px] font-black uppercase tracking-[0.18em] text-slate-500">
              <History className="h-3.5 w-3.5" aria-hidden /> Recent reports
            </h3>
            {history.length > 0 ? (
              <ul className="divide-y divide-white/[0.06] rounded-xl border border-white/[0.07] bg-white/[0.02]">
                {history.slice(0, 8).map((entry) => {
                  const sameScan = entry.scanId === assessment.task.scanId;
                  return (
                    <li key={entry.id} className="flex items-center justify-between gap-2 px-3 py-2">
                      <div className="min-w-0">
                        <div className="truncate text-[11.5px] font-black text-slate-200">
                          {entry.name}
                          {entry.formats.map((format) => (
                            <span key={format} className="ml-1 rounded bg-white/[0.06] px-1 font-mono text-[9px] uppercase text-slate-400">
                              {format}
                            </span>
                          ))}
                        </div>
                        <div className="truncate text-[10px] text-slate-500">
                          {new Date(entry.generatedAt).toLocaleString()} · {entry.scopeLabel} · {entry.depth} · {entry.quality} ·{' '}
                          <span className="font-mono">{entry.hash.slice(0, 12)}…</span>
                        </div>
                      </div>
                      <button
                        type="button"
                        disabled={busy !== null || !sameScan}
                        onClick={() => {
                          setTemplate(entry.template);
                          setDepth(entry.depth);
                          void run(entry.formats[0] || 'pdf', { template: entry.template, depth: entry.depth });
                        }}
                        title={sameScan ? 'Rebuild from this assessment with the same template and depth' : `That report described scan ${entry.scanId}, which is not the assessment on screen.`}
                        className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-white/[0.08] px-2 py-1 font-mono text-[9px] font-black uppercase tracking-[0.1em] text-slate-400 transition-colors hover:border-cyan-400/40 hover:text-cyan-300 disabled:opacity-35"
                      >
                        <RefreshCw className="h-3 w-3" aria-hidden /> Rebuild
                      </button>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="text-[11px] text-slate-500">No report has been generated from this page yet.</p>
            )}
            {history.length > 8 && (
              <p className="mt-1.5 text-[10px] text-slate-500">Showing the 8 most recent of {history.length} reports kept in this browser.</p>
            )}
          </section>
        </div>

        <footer className="flex items-start gap-2 border-t border-white/[0.07] px-5 py-3 text-[10.5px] leading-relaxed text-slate-500">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
          <span>
            {assessment.task.localOnly
              ? 'Generated in your browser from the local assessment — nothing is uploaded, and no file content or secret value reaches the document.'
              : 'Generated in your browser from this assessment — the document is rendered here, not on a server.'}{' '}
            Each report is sealed with SHA3-256 and verifiable at /verify-report.
          </span>
        </footer>
      </div>
    </div>
  );
}
