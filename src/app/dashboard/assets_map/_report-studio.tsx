'use client';

/**
 * Report Studio — the Assets page's enterprise report builder.
 *
 * Modelled on the Quantum Readiness Report Center (templates, branding, seven
 * formats, preview, history, SHA3-256 integrity), but built from the asset
 * register the page is rendering: the scope is the rows the user is looking at,
 * the numbers are the register's numbers, and the pre-export validation shown
 * here is the same validation printed inside the document.
 *
 * Loaded lazily by the page, so the report builder, the integrity code and the
 * exporters never weigh on the page's first paint.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react';
import {
  AlertTriangle,
  Building2,
  Check,
  CheckCircle2,
  ChevronDown,
  Download,
  Eye,
  FileBarChart,
  FileCode2,
  FileJson,
  FileSpreadsheet,
  FileText,
  History,
  ImagePlus,
  Loader2,
  Presentation,
  ShieldCheck,
  Wrench,
  X,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import { summarizeRows, type AssetRegister, type AssetRegisterRow, type RegisterFilter } from '@/lib/assets/asset-register';
import { ASSET_REPORT_TEMPLATES, type AssetReportTemplate } from '@/services/reporting/AssetReport';
import type { InventoryReport } from '@/services/reporting/InventoryReport';
import { brandingSchema, type ReportBranding } from '@/services/reporting/schemas/ReportSchema';
import type { DocumentFormat } from '@/services/reporting/exporters/DocumentExporters';
import { nf } from './_register-ui';

const BRANDING_STORAGE_KEY = 'qg-asset-report-branding';

export type StudioScopeType = 'selection' | 'filtered' | 'all' | 'single';

/**
 * One entry per REPORT (id + seal), listing every format exported from it —
 * a PDF and a spreadsheet of the same report share one id and one digest.
 */
interface HistoryEntry {
  id: string;
  name: string;
  assetCount: number;
  generatedAt: string;
  hash: string;
  quality: string;
}

const FORMATS: Array<{ format: DocumentFormat; label: string; detail: string; icon: LucideIcon; tone: string }> = [
  { format: 'pdf', label: 'PDF', detail: 'Board-ready, print & sign', icon: FileText, tone: 'text-red-500' },
  { format: 'docx', label: 'Word', detail: 'Editable document', icon: FileText, tone: 'text-blue-500' },
  { format: 'xlsx', label: 'Excel', detail: 'Complete registers, filterable', icon: FileSpreadsheet, tone: 'text-emerald-500' },
  { format: 'pptx', label: 'PowerPoint', detail: 'Executive deck', icon: Presentation, tone: 'text-orange-500' },
  { format: 'html', label: 'HTML', detail: 'Self-contained, shareable', icon: FileCode2, tone: 'text-amber-500' },
  { format: 'csv', label: 'CSV', detail: 'Raw registers for analysis', icon: FileSpreadsheet, tone: 'text-cyan-500' },
  { format: 'json', label: 'JSON', detail: 'Full sealed model', icon: FileJson, tone: 'text-violet-500' },
];

const RECOMMENDED: Record<AssetReportTemplate, DocumentFormat[]> = {
  executive: ['pdf', 'pptx'],
  technical: ['xlsx', 'pdf'],
  remediation: ['xlsx', 'pdf'],
};

const TEMPLATE_ICON: Record<AssetReportTemplate, LucideIcon> = {
  executive: FileBarChart,
  technical: FileSpreadsheet,
  remediation: Wrench,
};

function loadBranding(key: string): ReportBranding {
  try {
    const raw = window.localStorage.getItem(key);
    if (raw) return brandingSchema.parse(JSON.parse(raw));
  } catch {
    /* unreadable or blocked storage — defaults below */
  }
  return brandingSchema.parse({});
}

function saveJson(key: string, value: unknown) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage full or blocked — the export itself is unaffected */
  }
}

export interface ReportStudioProps {
  open: boolean;
  onClose: () => void;
  register: AssetRegister;
  selection: AssetRegisterRow[];
  filtered: AssetRegisterRow[];
  singleId: string | null;
  initialScope: StudioScopeType;
  filterDescription: string;
  filters: RegisterFilter;
  ownerId: string;
  token: string;
}

export default function ReportStudio({ open, onClose, register, selection, filtered, singleId, initialScope, filterDescription, filters, ownerId, token }: ReportStudioProps) {
  const brandingKey = `${BRANDING_STORAGE_KEY}:${ownerId}`;
  const [scopeType, setScopeType] = useState<StudioScopeType>(initialScope);
  const [template, setTemplate] = useState<AssetReportTemplate>('executive');
  const [branding, setBranding] = useState<ReportBranding>(() => loadBranding(brandingKey));
  const [brandingOpen, setBrandingOpen] = useState(false);
  const [busy, setBusy] = useState<DocumentFormat | 'preview' | 'capture' | null>(null);
  const [done, setDone] = useState<DocumentFormat | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [captured, setCaptured] = useState<{ configuration: string; report: InventoryReport; assetCount: number } | null>(null);
  const [showPassed, setShowPassed] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const operationRef = useRef<AbortController | null>(null);
  useEffect(() => () => operationRef.current?.abort(), [ownerId]);

  useEffect(() => setScopeType(initialScope), [initialScope, open]);

  useEffect(() => {
    if (!open) return;
    panelRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    void fetch('/api/v1/reports/asset-snapshots', {
      headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', signal: controller.signal,
    }).then(async (response) => {
      if (!response.ok) throw new Error('Saved asset report history is unavailable.');
      const payload = await response.json();
      if (!controller.signal.aborted) setHistory(payload.data);
    }).catch((cause) => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'History unavailable.');
    });
    return () => controller.abort();
  }, [open, token]);

  const updateBranding = useCallback(<K extends keyof ReportBranding>(key: K, value: ReportBranding[K]) => {
    setBranding((current) => {
      const next = { ...current, [key]: value };
      saveJson(brandingKey, next);
      return next;
    });
  }, [brandingKey]);

  const scopeOptions = useMemo(() => {
    const options: Array<{ type: StudioScopeType; label: string; detail: string; rows: AssetRegisterRow[]; description: string }> = [];
    const single = register.rows.find((row) => row.id === singleId);
    if (singleId) options.push({ type: 'single', label: single?.name ?? 'Original asset', detail: 'This asset only', rows: single ? [single] : [], description: single ? `the asset ${single.name}` : 'the original asset' });
    options.push({ type: 'selection', label: 'Selected assets', detail: selection.length ? `${nf(selection.length)} selected in the table` : 'Select rows in the table', rows: selection, description: `${nf(selection.length)} selected asset${selection.length === 1 ? '' : 's'}` });
    options.push({ type: 'filtered', label: 'Current view', detail: filterDescription || 'All assets — no filter applied', rows: filtered, description: filterDescription ? `the filtered view (${filterDescription})` : 'the current view' });
    options.push({ type: 'all', label: 'Entire estate', detail: `Every asset the scanner reports`, rows: register.rows, description: 'the full estate' });
    return options;
  }, [singleId, selection, filtered, register.rows, filterDescription]);

  const activeScope = scopeOptions.find((option) => option.type === scopeType) ?? scopeOptions[scopeOptions.length - 1];
  const scopeRows = activeScope.rows;

  const scopedIds = activeScope.type === 'selection' || activeScope.type === 'single'
    ? scopeRows.map((row) => row.id).sort()
    : [];
  const configuration = JSON.stringify([scopeType, template, branding, scopedIds, scopeType === 'filtered' ? filters : null]);
  const preview = captured?.configuration === configuration ? captured.report : null;

  const scopeTotals = useMemo(() => summarizeRows(scopeRows), [scopeRows]);
  const validation = preview?.document?.validation;
  const reconciliation = preview?.reconciliation || [];
  const reconMatches = reconciliation.filter((row) => row.matches).length;

  const capture = async (nextTemplate = template, nextScope = scopeType) => {
    if (operationRef.current) return;
    const controller = new AbortController();
    operationRef.current = controller;
    setBusy('capture');
    setError(null);
    try {
      const response = await fetch('/api/v1/reports/asset-snapshots', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          template: nextTemplate, scope: nextScope, branding,
          assetIds: nextScope === 'selection' || nextScope === 'single' ? scopedIds : [],
          filters: nextScope === 'filtered' ? filters : {},
        }),
        cache: 'no-store',
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(90_000)]),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error?.message || 'Unable to save the latest asset snapshot.');
      const report = payload.data as InventoryReport;
      if (report.meta.snapshot?.workspaceOwnerId !== ownerId) throw new Error('Invalid asset snapshot owner.');
      if (controller.signal.aborted) return;
      setScopeType(nextScope);
      setTemplate(nextTemplate);
      setHistory((current) => [payload.meta, ...current.filter((entry) => entry.id !== payload.meta.id)].slice(0, 20));
      setCaptured({
        configuration: JSON.stringify([nextScope, nextTemplate, branding, nextScope === 'all' ? [] : scopedIds, nextScope === 'filtered' ? filters : null]),
        report,
        assetCount: payload.meta.assetCount,
      });
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Snapshot capture failed');
    } finally {
      if (operationRef.current === controller) operationRef.current = null;
      if (!controller.signal.aborted) setBusy(null);
    }
  };

  const run = useCallback(
    async (format: DocumentFormat) => {
      if (!preview || !captured || operationRef.current) return;
      const controller = new AbortController();
      operationRef.current = controller;
      setBusy(format);
      setError(null);
      try {
        // The validated, sealed report shown above IS the report exported, so
        // every format exported from one configuration shares one report id
        // and one SHA3-256 digest. Capture a new snapshot to refresh its evidence.
        const report = preview;
        const { exportDocument, downloadDocument } = await import('@/services/reporting/exporters/DocumentExporters');
        const result = await exportDocument(report, format);
        if (controller.signal.aborted) return;
        downloadDocument(result);
        setDone(format);
        window.setTimeout(() => setDone(null), 2400);
      } catch (cause) {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Export failed');
      } finally {
        if (operationRef.current === controller) operationRef.current = null;
        if (!controller.signal.aborted) setBusy(null);
      }
    },
    [preview, captured],
  );

  const previewHtml = useCallback(async () => {
    if (!preview || operationRef.current) return;
    // Open the tab inside the click so pop-up blockers allow it, then fill it.
    const tab = window.open('', '_blank');
    if (!tab) {
      setError('Allow pop-ups to preview the report, or export HTML.');
      return;
    }
    tab.opener = null;
    const controller = new AbortController();
    operationRef.current = controller;
    setBusy('preview');
    setError(null);
    try {
      const { renderDocumentHtml } = await import('@/services/reporting/exporters/document/html');
      if (controller.signal.aborted) {
        tab.close();
        return;
      }
      const url = URL.createObjectURL(renderDocumentHtml(preview));
      tab.location.href = url;
      window.setTimeout(() => URL.revokeObjectURL(url), 120_000);
    } catch (cause) {
      tab.close();
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Preview failed');
    } finally {
      if (operationRef.current === controller) operationRef.current = null;
      if (!controller.signal.aborted) setBusy(null);
    }
  }, [preview]);

  const downloadSaved = async (entry: HistoryEntry) => {
    if (operationRef.current) return;
    const controller = new AbortController();
    operationRef.current = controller;
    const format = 'pdf';
    setBusy(format);
    setError(null);
    try {
      const response = await fetch(`/api/v1/reports/asset-snapshots/${encodeURIComponent(entry.id)}`, {
        headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', signal: controller.signal,
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error?.message || 'Saved report is unavailable.');
      const report = payload.data as InventoryReport;
      if (report.meta.snapshot?.workspaceOwnerId !== ownerId) throw new Error('Invalid asset snapshot owner.');
      const { exportDocument, downloadDocument } = await import('@/services/reporting/exporters/DocumentExporters');
      const result = await exportDocument(report, format);
      if (!controller.signal.aborted) downloadDocument(result);
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Saved report download failed.');
    } finally {
      if (operationRef.current === controller) operationRef.current = null;
      if (!controller.signal.aborted) setBusy(null);
    }
  };

  const onLogo = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (!/^image\/(png|jpeg)$/.test(file.type) || file.size > 384 * 1024) {
      setError('Upload the logo as PNG or JPEG, up to 384 KiB.');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => updateBranding('companyLogo', String(reader.result));
    reader.readAsDataURL(file);
  };

  if (!open) return null;

  const failing = validation?.checks.filter((c) => c.status !== 'pass') || [];
  const passing = validation?.checks.filter((c) => c.status === 'pass') || [];
  const spec = ASSET_REPORT_TEMPLATES.find((t) => t.key === template)!;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-labelledby="report-studio-title">
      <button type="button" aria-label="Close Report Studio" className="absolute inset-0 bg-black/55 backdrop-blur-[2px]" onClick={onClose} />
      <div ref={panelRef} tabIndex={-1} className="relative flex h-full w-full max-w-[600px] flex-col overflow-hidden border-l border-[var(--qg-card-border)] bg-[var(--qg-dashboard-bg)] text-[var(--qg-dashboard-text)] shadow-2xl outline-none">
        <header className="flex items-start justify-between gap-3 border-b border-[var(--qg-card-border)] px-5 py-4">
          <div>
            <h2 id="report-studio-title" className="text-lg font-black tracking-tight">Report Studio</h2>
            <p className="mt-0.5 text-[12px] text-[var(--qg-text-muted)]">Enterprise reports built from exactly what this register shows — scoped, validated and sealed with SHA3-256.</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-md p-1.5 text-[var(--qg-text-muted)] hover:text-[var(--qg-dashboard-text)]" aria-label="Close"><X className="h-5 w-5" /></button>
        </header>

        <div className="flex-1 space-y-6 overflow-y-auto px-5 py-5">
          {/* 1 — Scope */}
          <section>
            <h3 className="mb-2 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">1 · Scope</h3>
            <div className="grid grid-cols-[minmax(0,1fr)] gap-2 sm:grid-cols-2">
              {scopeOptions.map((option) => {
                const active = option.type === activeScope.type;
                const disabled = option.rows.length === 0;
                return (
                  <button
                    key={option.type}
                    type="button"
                    disabled={disabled}
                    onClick={() => setScopeType(option.type)}
                    aria-pressed={active}
                    className={`rounded-lg border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-45 ${active ? 'border-[var(--qg-amber)]/70 bg-[var(--qg-amber)]/10' : 'border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] hover:border-[var(--qg-amber)]/40'}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-[12px] font-black">{option.label}</span>
                      <span className="rounded bg-[var(--qg-muted-panel)] px-1.5 text-[10px] font-black tabular-nums">{nf(option.rows.length)}</span>
                    </div>
                    <div className="mt-1 line-clamp-2 text-[10.5px] text-[var(--qg-text-muted)]">{option.detail}</div>
                  </button>
                );
              })}
            </div>
            {scopeRows.length ? (
              <div className="mt-2 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-[11px] text-[var(--qg-dashboard-text-soft)]">
                <span className="font-black text-[var(--qg-dashboard-text)]">{nf(scopeTotals.assets)} asset{scopeTotals.assets === 1 ? '' : 's'}</span>
                {' · '}{nf(scopeTotals.components.total)} components · <span className="font-bold text-red-600 dark:text-red-300">{nf(scopeTotals.components.vulnerable)} quantum-vulnerable</span>
                {' · '}{nf(scopeTotals.vulnerableSeverity.critical)} critical · {nf(scopeTotals.components.pqcReady)} PQC-ready
                <div className="mt-1 truncate text-[10px] text-[var(--qg-text-muted)]" title={scopeRows.map((r) => r.name).join(', ')}>
                  {scopeRows.slice(0, 6).map((r) => r.name).join(', ')}{scopeRows.length > 6 ? ` +${nf(scopeRows.length - 6)} more` : ''}
                </div>
              </div>
            ) : null}
          </section>

          {/* 2 — Template */}
          <section>
            <h3 className="mb-2 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">2 · Template</h3>
            <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
              {ASSET_REPORT_TEMPLATES.map((t) => {
                const Icon = TEMPLATE_ICON[t.key];
                const active = t.key === template;
                return (
                  <button key={t.key} type="button" onClick={() => setTemplate(t.key)} aria-pressed={active} className={`flex gap-3 rounded-lg border p-3 text-left transition ${active ? 'border-[var(--qg-amber)]/70 bg-[var(--qg-amber)]/10' : 'border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] hover:border-[var(--qg-amber)]/40'}`}>
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]"><Icon className="h-4.5 w-4.5" aria-hidden /></span>
                    <span className="min-w-0">
                      <span className="block text-[12.5px] font-black">{t.name}</span>
                      <span className="block text-[10px] font-bold uppercase tracking-wider text-[var(--qg-text-muted)]">{t.audience}</span>
                      <span className="mt-1 block text-[11px] leading-snug text-[var(--qg-dashboard-text-soft)]">{t.description}</span>
                    </span>
                  </button>
                );
              })}
            </div>
            <p className="mt-2 text-[10.5px] text-[var(--qg-text-muted)]">Sections: {spec.sections.join(' · ')}</p>
          </section>

          {/* 3 — Branding */}
          <section>
            <button type="button" onClick={() => setBrandingOpen((value) => !value)} aria-expanded={brandingOpen} className="flex w-full items-center justify-between gap-2 text-left">
              <h3 className="text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">3 · Branding &amp; cover</h3>
              <span className="inline-flex items-center gap-1 text-[11px] font-bold text-[var(--qg-dashboard-text-soft)]">
                <Building2 className="h-3.5 w-3.5" aria-hidden />{branding.companyName} · {branding.classification} · v{branding.reportVersion}
                <ChevronDown className={`h-3.5 w-3.5 transition-transform ${brandingOpen ? 'rotate-180' : ''}`} aria-hidden />
              </span>
            </button>
            {brandingOpen ? (
              <div className="mt-3 grid grid-cols-[minmax(0,1fr)] gap-2 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] p-3 sm:grid-cols-2">
                {([
                  ['companyName', 'Company name'],
                  ['businessUnit', 'Business unit'],
                  ['reportOwner', 'Report owner'],
                  ['reviewer', 'Reviewer'],
                  ['classification', 'Classification'],
                  ['reportVersion', 'Version'],
                ] as const).map(([key, label]) => (
                  <label key={key} className="block">
                    <span className="block text-[9.5px] font-black uppercase tracking-wider text-[var(--qg-text-muted)]">{label}</span>
                    <input value={branding[key]} onChange={(event) => updateBranding(key, event.target.value)} className="mt-1 w-full rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-2.5 py-1.5 text-[12px] outline-none focus:border-[var(--qg-amber)]/60" />
                  </label>
                ))}
                <label className="block sm:col-span-2">
                  <span className="block text-[9.5px] font-black uppercase tracking-wider text-[var(--qg-text-muted)]">Notes printed with the provenance</span>
                  <textarea value={branding.customNotes} onChange={(event) => updateBranding('customNotes', event.target.value)} rows={2} className="mt-1 w-full resize-none rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-2.5 py-1.5 text-[12px] outline-none focus:border-[var(--qg-amber)]/60" />
                </label>
                <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
                  <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--qg-card-border)] px-3 py-1.5 text-[11px] font-bold text-[var(--qg-dashboard-text-soft)] hover:border-[var(--qg-amber)]/45">
                    <ImagePlus className="h-4 w-4" aria-hidden /> Upload logo (PNG/JPEG)
                    <input type="file" accept="image/png,image/jpeg" onChange={onLogo} className="hidden" />
                  </label>
                  {branding.companyLogo ? (
                    <span className="inline-flex items-center gap-2 text-[11px] text-[var(--qg-text-muted)]">
                      <img src={branding.companyLogo} alt="Report logo" className="h-7 max-w-[120px] rounded border border-[var(--qg-card-border)] object-contain" />
                      <button type="button" onClick={() => updateBranding('companyLogo', null)} className="hover:text-red-500">remove</button>
                    </span>
                  ) : <span className="text-[10.5px] text-[var(--qg-text-muted)]">No logo — the cover uses text branding.</span>}
                </div>
                <p className="text-[10px] text-[var(--qg-text-muted)] sm:col-span-2">Shared with the Quantum Readiness Report Center, so every report carries the same branding.</p>
              </div>
            ) : null}
          </section>

          {/* 4 — Pre-export validation */}
          <section>
            <h3 className="mb-2 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">4 · Pre-export validation</h3>
            {validation ? (
              <div className="rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-black uppercase tracking-wider ${validation.status === 'pass' ? 'border-emerald-500/35 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200' : validation.status === 'warn' ? 'border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200' : 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-200'}`}>
                    {validation.status === 'pass' ? <CheckCircle2 className="h-3.5 w-3.5" /> : validation.status === 'warn' ? <AlertTriangle className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}
                    Quality {validation.status} · {validation.score}/100
                  </span>
                  <span className="text-[11px] font-bold text-[var(--qg-dashboard-text-soft)]">Reconciliation {reconMatches}/{reconciliation.length} match</span>
                </div>
                {failing.length ? (
                  <ul className="mt-2 space-y-1.5">
                    {failing.map((check) => (
                      <li key={check.check} className="flex gap-2 text-[11px] leading-snug">
                        {check.status === 'fail' ? <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-500" aria-label="Failed" /> : <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" aria-label="Warning" />}
                        <span><span className="font-black">{check.check}.</span> <span className="text-[var(--qg-dashboard-text-soft)]">{check.detail}</span></span>
                      </li>
                    ))}
                  </ul>
                ) : null}
                <button type="button" onClick={() => setShowPassed((value) => !value)} className="mt-2 text-[10.5px] font-black uppercase tracking-wider text-[var(--qg-amber)]">
                  {showPassed ? 'Hide' : 'Show'} {passing.length} passed check{passing.length === 1 ? '' : 's'}
                </button>
                {showPassed ? (
                  <ul className="mt-1.5 space-y-1">
                    {passing.map((check) => (
                      <li key={check.check} className="flex gap-2 text-[10.5px] text-[var(--qg-dashboard-text-soft)]"><Check className="mt-0.5 h-3 w-3 shrink-0 text-emerald-500" aria-hidden />{check.check} — {check.detail}</li>
                    ))}
                  </ul>
                ) : null}
                <p className="mt-2 text-[10px] text-[var(--qg-text-muted)]">Warnings do not block export; they are printed in the report's Validation section so a reader sees them too.</p>
              </div>
            ) : (
              <p className="rounded-lg border border-dashed border-[var(--qg-card-border)] p-3 text-[11px] text-[var(--qg-text-muted)]">Choose a scope that contains at least one asset.</p>
            )}
          </section>

          {/* 5 — Export */}
          <section>
            <div className="mb-2 flex items-center justify-between gap-2">
              <h3 className="text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">Capture and export</h3>
              <button type="button" onClick={() => void capture()} disabled={!scopeRows.length || busy !== null} className="inline-flex items-center gap-1.5 rounded border border-[var(--qg-amber)]/45 px-3 py-2 text-[11px] font-black text-[var(--qg-amber)] disabled:opacity-40">
                {busy === 'capture' ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> : null}
                {preview ? 'Capture new snapshot' : 'Capture snapshot'}
              </button>
              <button type="button" onClick={() => void previewHtml()} disabled={!preview || busy !== null} className="inline-flex items-center gap-1.5 text-[11px] font-black uppercase tracking-wider text-[var(--qg-amber)] disabled:opacity-40">
                {busy === 'preview' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Eye className="h-3.5 w-3.5" />} Preview
              </button>
            </div>
            {preview ? <p className="mb-2 break-words text-[11px] text-[var(--qg-text-muted)]">Saved {new Date(preview.meta.generatedAt).toLocaleString()} · {preview.meta.reportId}</p> : null}
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {FORMATS.map((spec) => {
                const Icon = spec.icon;
                const recommended = RECOMMENDED[template].includes(spec.format);
                return (
                  <button
                    key={spec.format}
                    type="button"
                    disabled={!preview || busy !== null}
                    onClick={() => void run(spec.format)}
                    className={`relative rounded-lg border p-2.5 text-left transition disabled:cursor-not-allowed disabled:opacity-45 ${recommended ? 'border-[var(--qg-amber)]/45 bg-[var(--qg-amber)]/5' : 'border-[var(--qg-card-border)] bg-[var(--qg-card-bg)]'} hover:border-[var(--qg-amber)]/70`}
                  >
                    <span className="flex items-center gap-1.5">
                      {busy === spec.format ? <Loader2 className={`h-4 w-4 animate-spin ${spec.tone}`} /> : done === spec.format ? <Check className="h-4 w-4 text-emerald-500" /> : <Icon className={`h-4 w-4 ${spec.tone}`} aria-hidden />}
                      <span className="text-[12px] font-black">{spec.label}</span>
                    </span>
                    <span className="mt-0.5 block text-[9.5px] leading-tight text-[var(--qg-text-muted)]">{spec.detail}</span>
                    {recommended ? <span className="absolute right-1.5 top-1.5 text-[8px] font-black uppercase tracking-wider text-[var(--qg-amber)]">Rec.</span> : null}
                  </button>
                );
              })}
            </div>
            {error ? <p role="alert" className="mt-2 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-700 dark:text-red-200">{error}</p> : null}
          </section>

          {/* History */}
          <section>
            <h3 className="mb-2 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]"><History className="h-3.5 w-3.5" aria-hidden />Recent reports</h3>
            {history.length ? (
              <ul className="divide-y divide-[var(--qg-card-border)] rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)]">
                {history.slice(0, 8).map((entry) => (
                  <li key={entry.id} className="flex items-center justify-between gap-2 px-3 py-2">
                    <div className="min-w-0">
                      <div className="truncate text-[11.5px] font-black">{entry.name} </div>
                      <div className="truncate text-[10px] text-[var(--qg-text-muted)]">{new Date(entry.generatedAt).toLocaleString()} · {nf(entry.assetCount)} assets · {entry.quality} · <span className="font-mono">{entry.hash.slice(0, 12)}…</span></div>
                    </div>
                    <button
                      type="button"
                      disabled={busy !== null}
                      onClick={() => void downloadSaved(entry)}
                      title="Download the saved snapshot"
                      className="inline-flex shrink-0 items-center gap-1 rounded border border-[var(--qg-card-border)] px-2 py-1 text-[9.5px] font-black uppercase text-[var(--qg-dashboard-text-soft)] hover:border-[var(--qg-amber)]/45 disabled:opacity-40"
                    >
                      <Download className="h-3 w-3" aria-hidden /> Saved report
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-[11px] text-[var(--qg-text-muted)]">No reports generated from this page yet.</p>
            )}
            {history.length > 8 ? <p className="mt-1.5 text-[10px] text-[var(--qg-text-muted)]">Showing the 8 most recent of {history.length} saved reports.</p> : null}
          </section>
        </div>

        <footer className="flex items-center gap-2 border-t border-[var(--qg-card-border)] px-5 py-3 text-[10.5px] text-[var(--qg-text-muted)]">
          <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-500" aria-hidden />
          Generated in your browser from the live asset register — nothing is uploaded. Each document is sealed with SHA3-256 and verifiable at /verify-report.
        </footer>
      </div>
    </div>
  );
}
