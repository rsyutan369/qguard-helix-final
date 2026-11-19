'use client';

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ChangeEvent } from 'react';
import {
  Archive, CheckCircle2, ChevronLeft, ChevronRight, Download, Eye, FileBarChart, FileJson,
  FileSpreadsheet, FileText, ImagePlus, Landmark, Loader2, Presentation, RefreshCw,
  Route as RouteIcon, Search, X,
} from 'lucide-react';
import {
  Badge, EmptyState, HeaderButton, Panel, PrimaryButton, QuantumReadinessShell, SectionTitle,
  TruncationNote, useQuantumReadiness, AMBER, BLUE, GREEN,
} from '../_shared';
import { useAuth } from '@/contexts/auth-context';
import { useReportAuditTrail } from '@/hooks/use-report-audit-trail';
import { REPORT_TEMPLATES } from '@/services/reporting/templates';
import {
  REPORT_FORMATS,
  brandingSchema,
  evidenceAssessmentReportSchema,
  reportProvenanceSchema,
  type EvidenceAssessmentReport,
  type ReportBranding,
  type ReportFormat,
  type ReportKind,
} from '@/services/reporting/schemas/ReportSchema';

const FORMAT_ICONS: Record<ReportFormat, typeof FileText> = {
  pdf: FileText,
  docx: FileText,
  xlsx: FileSpreadsheet,
  pptx: Presentation,
  csv: FileSpreadsheet,
  json: FileJson,
  html: FileBarChart,
};

const TEMPLATE_META: Record<ReportKind, { icon: typeof FileText; name: string; description: string }> = {
  executive: { icon: FileText, name: 'Executive briefing', description: 'Readiness, exposure and priority findings for leadership.' },
  technical: { icon: FileBarChart, name: 'Technical assessment', description: 'Registered assets, CBOM and finding-level evidence.' },
  compliance: { icon: Landmark, name: 'Compliance evidence', description: 'Source coverage and recorded evidence for control review.' },
  migration: { icon: RouteIcon, name: 'PQC migration', description: 'Recorded migration activity and readiness evidence.' },
};

const ASSETS_PER_PAGE = 8;
const MAX_LOGO_BYTES = 384 * 1024;
const PAGE_BUTTON = 'inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-white/12 px-3 py-2 text-sm font-medium text-white/80 transition enabled:hover:border-blue-400/55 enabled:hover:bg-blue-500/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-300 disabled:cursor-not-allowed disabled:opacity-40';
const FIELD = 'mt-1 w-full rounded-md border border-white/12 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-blue-400/70';

interface RegisteredAsset {
  key: string;
  name: string;
  assetType: string;
  environment: string;
}

type Provenance = EvidenceAssessmentReport['provenance'];
type CapturedReport = Pick<EvidenceAssessmentReport, 'meta' | 'provenance' | 'scope' | 'kpis' | 'executiveSummary' | 'integrity'>;
type Capture = { report: CapturedReport; preview: boolean };

function brandingKey(ownerId: string) {
  return 'qg-report-branding:' + ownerId;
}

function savedBranding(ownerId: string): ReportBranding {
  try {
    const value = localStorage.getItem(brandingKey(ownerId));
    if (value) {
      const branding = brandingSchema.parse(JSON.parse(value));
      if (branding.companyLogo && !/^data:image\/(png|jpeg);base64,[a-z0-9+/=]+$/i.test(branding.companyLogo)) {
        branding.companyLogo = null;
      }
      return branding;
    }
  } catch {
    /* A disabled browser store or obsolete setting uses the defaults. */
  }
  return brandingSchema.parse({});
}

function isReportFormat(value: unknown): value is ReportFormat {
  return REPORT_FORMATS.some((format) => format === value);
}

function isRegisteredAsset(value: unknown): value is RegisteredAsset {
  if (!value || typeof value !== 'object') return false;
  const asset = value as Partial<RegisteredAsset>;
  return typeof asset.key === 'string' && Boolean(asset.key) && typeof asset.name === 'string'
    && typeof asset.assetType === 'string' && typeof asset.environment === 'string';
}

function utc(value: string | null | undefined) {
  const timestamp = value ? Date.parse(value) : NaN;
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC') : 'Unavailable';
}

async function requestData<T>(path: string, token: string, signal: AbortSignal, body?: object): Promise<T> {
  const response = await fetch('/api/v1/reports' + path, {
    method: body ? 'POST' : 'GET',
    cache: 'no-store',
    signal,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(typeof payload?.error?.message === 'string' ? payload.error.message : `Report service returned HTTP ${response.status}.`);
  }
  if (payload?.data == null) throw new Error('The report service returned no evidence.');
  return payload.data as T;
}

export default function ReportCenterPage() {
  const { user, session, loading } = useAuth();
  if (!user || user.id !== session?.user.id || !session.access_token) {
    return (
      <div className="p-6 text-sm text-white/75" role="status">
        {loading ? 'Loading your report workspace…' : 'Sign in to view your report workspace.'}
      </div>
    );
  }
  return <ReportWorkspace key={user.id} ownerId={user.id} token={session.access_token} />;
}

function ReportWorkspace({ ownerId, token }: { ownerId: string; token: string }) {
  const { snapshot, state, error: loadError, sseConnected, lastVerifiedAt, refresh } = useQuantumReadiness();
  const { entries, loaded, error: historyError, reload: reloadHistory } = useReportAuditTrail('report');
  const [branding, setBranding] = useState(() => savedBranding(ownerId));
  const [kind, setKind] = useState<ReportKind>('executive');
  const [format, setFormat] = useState<ReportFormat>('pdf');
  const [assets, setAssets] = useState<RegisteredAsset[]>([]);
  const [assetsStatus, setAssetsStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const [assetRefresh, setAssetRefresh] = useState(0);
  const [selection, setSelection] = useState<Set<string> | null>(null);
  const [query, setQuery] = useState('');
  const [assetPage, setAssetPage] = useState(1);
  const [busy, setBusy] = useState<'preview' | 'generate' | 'download' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [capture, setCapture] = useState<Capture | null>(null);
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const operation = useRef<AbortController | null>(null);
  const previewHeading = useRef<HTMLHeadingElement | null>(null);
  const previewButton = useRef<HTMLButtonElement | null>(null);

  const activeTemplate = REPORT_TEMPLATES.find((template) => template.kind === kind)!;
  const filteredAssets = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return needle ? assets.filter((asset) => `${asset.name} ${asset.assetType} ${asset.environment}`.toLowerCase().includes(needle)) : assets;
  }, [assets, query]);
  const pageCount = Math.max(1, Math.ceil(filteredAssets.length / ASSETS_PER_PAGE));
  const page = Math.min(assetPage, pageCount);
  const visibleAssets = filteredAssets.slice((page - 1) * ASSETS_PER_PAGE, page * ASSETS_PER_PAGE);
  const assetKeys = useMemo(() => new Set(assets.map((asset) => asset.key)), [assets]);
  const selectionCount = selection?.size ?? (assetsStatus === 'ready' ? assets.length : null);
  const selectionMissing = assetsStatus === 'ready' && selection !== null && Array.from(selection).some((key) => !assetKeys.has(key));
  const canCapture = busy === null && !selectionMissing && (selection === null || (assetsStatus === 'ready' && selection.size > 0));

  useLayoutEffect(() => () => operation.current?.abort(), []);

  useEffect(() => {
    try {
      localStorage.setItem(brandingKey(ownerId), JSON.stringify(branding));
    } catch {
      /* The current cover remains available when browser storage is disabled. */
    }
  }, [branding, ownerId]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timeout = setTimeout(() => controller.abort(), 30_000);
    setAssetsStatus('loading');
    void requestData<unknown>('/assets', token, controller.signal)
      .then((data) => {
        if (!active) return;
        if (!Array.isArray(data) || !data.every(isRegisteredAsset)) throw new Error('Invalid registered inventory');
        setAssets(Array.from(new Map(data.map((asset) => [asset.key, asset])).values()));
        setAssetsStatus('ready');
      })
      .catch(() => {
        if (active) setAssetsStatus('error');
      })
      .finally(() => clearTimeout(timeout));

    return () => {
      active = false;
      clearTimeout(timeout);
      controller.abort();
    };
  }, [token, snapshot, assetRefresh]);

  useEffect(() => {
    if (previewHtml) previewHeading.current?.focus();
  }, [previewHtml]);

  function setCover<K extends keyof ReportBranding>(field: K, value: ReportBranding[K]) {
    setBranding((previous) => ({ ...previous, [field]: value }));
  }

  function uploadLogo(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    if (!['image/png', 'image/jpeg'].includes(file.type) || file.size > MAX_LOGO_BYTES) {
      setError('Choose a PNG or JPEG logo up to 384 KiB.');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        setCover('companyLogo', reader.result);
        setError(null);
      }
    };
    reader.onerror = () => setError('The logo file could not be read.');
    reader.readAsDataURL(file);
  }

  function toggleAsset(assetKey: string) {
    setSelection((previous) => {
      const next = new Set(previous ?? assets.map((asset) => asset.key));
      if (next.has(assetKey)) next.delete(assetKey);
      else next.add(assetKey);
      return next;
    });
  }

  async function runReport(action: 'preview' | 'generate' | 'download', saved?: { id: string; format: ReportFormat }) {
    if (operation.current || (action !== 'download' && !canCapture)) return;
    const controller = new AbortController();
    operation.current = controller;
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 90_000);
    let savedOnServer = false;

    setBusy(action);
    setError(null);
    setNotice(null);

    try {
      const payload = saved
        ? await requestData<unknown>('/' + encodeURIComponent(saved.id), token, controller.signal)
        : await requestData<unknown>('/generate', token, controller.signal, {
            kind,
            format: action === 'preview' ? 'html' : format,
            branding,
            scopeAssets: selection === null ? null : Array.from(selection),
            preview: action === 'preview',
          });
      clearTimeout(timeout);
      if (controller.signal.aborted) return;
      savedOnServer = action === 'generate';
      if (savedOnServer) void reloadHistory();
      const parsed = evidenceAssessmentReportSchema.safeParse(payload);
      if (!parsed.success) throw new Error('The report service returned an invalid snapshot.');
      const report = payload as EvidenceAssessmentReport;
      if (report.provenance.workspaceOwnerId !== ownerId || report.meta.id !== report.provenance.reportId || (saved && saved.id !== report.meta.id)) {
        throw new Error('The report snapshot identity could not be confirmed.');
      }
      const { exportReadinessReport } = await import('@/services/reporting/ReadinessDocument');
      const result = await exportReadinessReport(report, action === 'preview' ? 'html' : saved?.format ?? format);
      if (controller.signal.aborted) return;

      if (action === 'preview') {
        const html = await result.blob.text();
        if (controller.signal.aborted) return;
        setPreviewHtml(html);
      } else {
        const { downloadResult } = await import('@/services/reporting/ReportExporter');
        if (controller.signal.aborted) return;
        downloadResult(result);
        setPreviewHtml(null);
        setNotice(saved ? 'Saved snapshot download started.' : 'Snapshot saved and download started.');
      }
      setCapture({
        preview: action === 'preview',
        report: {
          meta: report.meta,
          provenance: report.provenance,
          scope: report.scope,
          kpis: report.kpis,
          executiveSummary: report.executiveSummary,
          integrity: report.integrity,
        },
      });
    } catch (err) {
      if (timedOut) {
        setError(action === 'generate' ? 'The request timed out. Refresh Report History to see whether the snapshot was saved.' : 'The report service timed out. Try again.');
      } else if (!controller.signal.aborted) {
        const message = err instanceof Error ? err.message : 'Unexpected report error.';
        setError(savedOnServer ? `Snapshot saved. Export could not complete: ${message} Retry from Report History.` : message);
      }
    } finally {
      clearTimeout(timeout);
      if (operation.current === controller) {
        operation.current = null;
        setBusy(null);
      }
    }
  }

  return (
    <QuantumReadinessShell
      title="Quantum Readiness Reports"
      subtitle="Capture workspace evidence for executive, technical, compliance and migration reviews. Each saved report preserves the data used at generation time."
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      error={loadError}
      lastVerifiedAt={lastVerifiedAt}
      actions={
        <HeaderButton icon={RefreshCw} onClick={() => {
          setAssetRefresh((version) => version + 1);
          void refresh({ force: true });
          void reloadHistory();
        }}>
          Refresh workspace
        </HeaderButton>
      }
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(21rem,0.63fr)]">
        <Panel className="p-5 sm:p-6">
          <SectionTitle>Report template</SectionTitle>
          <div className="grid gap-3 sm:grid-cols-2">
            {REPORT_TEMPLATES.map((template) => {
              const { icon: Icon, name, description } = TEMPLATE_META[template.kind];
              const active = kind === template.kind;
              return (
                <button key={template.kind} type="button" aria-pressed={active}
                  onClick={() => setKind(template.kind)}
                  className={`group flex min-h-28 items-start gap-3 rounded-lg border p-4 text-left transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-300 ${active ? 'border-blue-400/65 bg-blue-500/12' : 'border-white/12 bg-white/[0.025] hover:border-blue-400/45'}`}>
                  <span className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-md border border-blue-400/30 bg-blue-500/10 text-blue-300"><Icon className="h-[18px] w-[18px]" aria-hidden="true" /></span>
                  <span>
                    <span className="block text-sm font-semibold text-white">{name}</span>
                    <span className="mt-1 block text-sm leading-5 text-white/65">{description}</span>
                  </span>
                </button>
              );
            })}
          </div>

          <details className="mt-6 rounded-lg border border-white/12 bg-white/[0.018]">
            <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-white/85">Cover and branding</summary>
            <div className="border-t border-white/10 px-4 pb-4 pt-3">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {([
                  ['companyName', 'Company name'], ['businessUnit', 'Business unit'],
                  ['reportOwner', 'Report owner'], ['reviewer', 'Reviewer'],
                  ['classification', 'Classification'], ['reportVersion', 'Version'],
                ] as const).map(([field, label]) => (
                  <label key={field} className="text-sm text-white/72">
                    {label}
                    <input value={branding[field]} onChange={(event) => setCover(field, event.target.value)} className={FIELD} />
                  </label>
                ))}
              </div>
              <label className="mt-3 block text-sm text-white/72">
                Cover notes
                <textarea value={branding.customNotes} onChange={(event) => setCover('customNotes', event.target.value)} rows={2} className={FIELD} />
              </label>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <label className={`relative cursor-pointer focus-within:outline focus-within:outline-2 focus-within:outline-blue-300 ${PAGE_BUTTON}`}>
                  <ImagePlus className="h-4 w-4" aria-hidden="true" /> Upload logo
                  <input type="file" accept="image/png,image/jpeg" onChange={uploadLogo} className="sr-only" />
                </label>
                {branding.companyLogo ? (
                  <>
                    <img src={branding.companyLogo} alt="Report cover logo" className="h-8 max-w-32 object-contain" />
                    <button type="button" onClick={() => setCover('companyLogo', null)} className={PAGE_BUTTON}>Remove logo</button>
                  </>
                ) : <span className="text-xs text-white/60">PNG or JPEG, up to 384 KiB.</span>}
              </div>
            </div>
          </details>
        </Panel>

        <Panel className="p-5 sm:p-6">
          <SectionTitle suffix={<Badge color={BLUE}>On demand</Badge>}>Generate and export</SectionTitle>
          <p className="mb-4 text-sm leading-6 text-white/68">The server reads the source records when you generate a report. Downloading a saved report uses its original snapshot.</p>
          <fieldset>
            <legend className="mb-2 text-sm font-semibold text-white/85">Export format</legend>
            <div className="grid grid-cols-3 gap-2 sm:grid-cols-4">
              {REPORT_FORMATS.map((item) => {
                const Icon = FORMAT_ICONS[item];
                return (
                  <button key={item} type="button" aria-pressed={format === item} onClick={() => setFormat(item)}
                    className={`${PAGE_BUTTON} ${format === item ? 'border-blue-400/70 bg-blue-500/15 text-blue-100' : 'bg-white/[0.02]'}`}
                    title={activeTemplate.formats.includes(item) ? 'Recommended for this template' : undefined}>
                    <Icon className="h-4 w-4 shrink-0" aria-hidden="true" /> {item.toUpperCase()}
                  </button>
                );
              })}
            </div>
          </fieldset>
          <div className="mt-5 flex flex-wrap gap-2">
            <PrimaryButton icon={busy === 'generate' ? Loader2 : Download} disabled={!canCapture} onClick={() => void runReport('generate')}>
              {busy === 'generate' ? 'Capturing snapshot…' : `Generate ${format.toUpperCase()}`}
            </PrimaryButton>
            <button ref={previewButton} type="button" className={PAGE_BUTTON} disabled={!canCapture} onClick={() => void runReport('preview')}>
              <Eye className="h-4 w-4" aria-hidden="true" /> {busy === 'preview' ? 'Capturing preview…' : 'Preview report'}
            </button>
          </div>
          <p className="mt-3 text-sm text-white/65">
            {selection === null ? 'Scope: all registered assets' : `Scope: ${selectionCount} selected asset${selectionCount === 1 ? '' : 's'}`}
          </p>
          {busy ? <p role="status" className="mt-2 text-sm text-blue-200">{busy === 'download' ? 'Opening saved snapshot…' : 'Reading and validating report evidence…'}</p> : null}
          {notice ? <p role="status" className="mt-3 flex items-center gap-2 text-sm text-emerald-300"><CheckCircle2 className="h-4 w-4" aria-hidden="true" />{notice}</p> : null}
          {error ? <p role="alert" className="mt-3 rounded-md border border-red-400/35 bg-red-400/10 p-3 text-sm text-red-100">{error}</p> : null}
        </Panel>
      </div>

      {capture ? <SnapshotDetails report={capture.report} preview={capture.preview} /> : null}
      {previewHtml ? (
        <Panel className="p-4 sm:p-5">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 ref={previewHeading} tabIndex={-1} className="text-base font-semibold text-white">Report preview</h2>
            <button type="button" onClick={() => { setPreviewHtml(null); previewButton.current?.focus(); }} className={PAGE_BUTTON}><X className="h-4 w-4" aria-hidden="true" /> Close preview</button>
          </div>
          <iframe sandbox="" referrerPolicy="no-referrer" title="Quantum readiness report preview" srcDoc={previewHtml} className="h-[min(78vh,62rem)] w-full rounded-md border border-white/12 bg-white" />
        </Panel>
      ) : null}

      <Panel className="p-5 sm:p-6">
        <SectionTitle suffix={selectionCount === null ? null : <Badge color={BLUE}>{selectionCount} {selection === null ? 'registered' : 'selected'}</Badge>}>Registered asset scope</SectionTitle>
        <p className="mb-4 text-sm text-white/68">Choose the registered assets to cover. For a custom scope, workspace-wide metrics require evidence attributable to that selection.</p>
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <button type="button" className={PAGE_BUTTON} aria-pressed={selection === null} disabled={selection === null} onClick={() => setSelection(null)}>Include all registered assets</button>
          <button type="button" className={PAGE_BUTTON} disabled={selection?.size === 0 || (selection === null && assets.length === 0)} onClick={() => setSelection(new Set())}>Clear selection</button>
          <label className="relative ml-auto w-full sm:w-64">
            <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-white/55" aria-hidden="true" />
            <input type="search" aria-label="Search registered assets" placeholder="Search registered assets" value={query}
              onChange={(event) => { setQuery(event.target.value); setAssetPage(1); }} className={`${FIELD} mt-0 pl-9`} />
          </label>
        </div>
        {selectionMissing ? <p className="mb-3 text-sm text-amber-200" role="alert">Some selected assets are no longer registered. Clear the selection or include all registered assets to proceed.</p> : null}
        {selection?.size === 0 ? <p className="mb-3 text-sm text-amber-200">Select at least one registered asset to use a custom scope.</p> : null}
        {assetsStatus === 'error' ? (
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-sm text-amber-200" role="status">The registered asset list is unavailable.</p>
            <button type="button" className={PAGE_BUTTON} onClick={() => setAssetRefresh((version) => version + 1)}>Retry asset list</button>
          </div>
        ) : assetsStatus === 'loading' && assets.length === 0 ? (
          <p className="text-sm text-white/65" role="status">Loading registered assets…</p>
        ) : visibleAssets.length ? (
          <>
            <div className="grid gap-2 sm:grid-cols-2">
              {visibleAssets.map((asset) => (
                <label key={asset.key} className="flex min-h-12 cursor-pointer items-center gap-3 rounded-md border border-white/10 px-3 py-2 hover:bg-blue-500/10">
                  <input type="checkbox" checked={selection?.has(asset.key) ?? true} onChange={() => toggleAsset(asset.key)} className="size-4 shrink-0 accent-blue-500" />
                  <span className="min-w-0">
                    <span className="block break-words text-sm font-semibold text-white/90">{asset.name}</span>
                    <span className="text-xs capitalize text-white/62">{[asset.assetType, asset.environment].filter(Boolean).join(' · ')}</span>
                  </span>
                </label>
              ))}
            </div>
            {pageCount > 1 ? (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button type="button" aria-label="Previous asset page" className={PAGE_BUTTON} disabled={page === 1} onClick={() => setAssetPage(page - 1)}><ChevronLeft className="h-4 w-4" /></button>
                <span className="px-2 text-sm text-white/65">Page {page} of {pageCount}</span>
                <button type="button" aria-label="Next asset page" className={PAGE_BUTTON} disabled={page === pageCount} onClick={() => setAssetPage(page + 1)}><ChevronRight className="h-4 w-4" /></button>
              </div>
            ) : null}
          </>
        ) : <EmptyState label={assets.length ? 'No assets match your search.' : 'No registered assets in this workspace.'} />}
      </Panel>

      <Panel className="p-5 sm:p-6">
        <SectionTitle suffix={<Archive className="h-4 w-4 text-white/60" aria-hidden="true" />}>Report history</SectionTitle>
        {historyError ? <p role="alert" className="mb-3 text-sm text-amber-200">{historyError}</p> : null}
        {entries.length ? (
          <>
            <div className="overflow-x-auto rounded-md border border-white/10">
              <table className="w-full min-w-[720px] text-left text-sm">
                <thead className="bg-white/[0.035] text-xs text-white/68">
                  <tr>
                    {['Report', 'Scope', 'Captured (UTC)', 'Validation', 'Download'].map((label) => <th key={label} scope="col" className="px-3 py-2.5 font-semibold">{label}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {entries.slice(0, 20).map((entry) => {
                    const candidate = reportProvenanceSchema.safeParse((entry as typeof entry & { provenance?: unknown }).provenance);
                    const provenance = candidate.success && candidate.data.workspaceOwnerId === ownerId && candidate.data.reportId === entry.reportId ? candidate.data : null;
                    const entryFormat = isReportFormat(entry.format) ? entry.format : null;
                    const saved = provenance && entry.reportId && entryFormat ? { id: entry.reportId, format: entryFormat } : null;
                    return (
                      <tr key={entry.id} className="border-t border-white/10 text-white/78">
                        <td className="px-3 py-3">
                          <span className="block font-semibold">{entry.title || 'Readiness report'}</span>
                          <span className="text-xs text-white/55">{[entry.version && `Version ${entry.version}`, entryFormat?.toUpperCase()].filter(Boolean).join(' · ')}</span>
                        </td>
                        <td className="px-3 py-3">{entry.scope || 'Unavailable'}</td>
                        <td className="whitespace-nowrap px-3 py-3 tabular-nums">{utc(provenance?.snapshotAt ?? entry.generatedAt ?? entry.createdAt)}</td>
                        <td className="px-3 py-3">
                          {provenance ? <ValidationBadge status={provenance.validationStatus} /> : <span className="text-white/60">Legacy audit entry</span>}
                        </td>
                        <td className="px-3 py-3">
                          {saved ? <button className={PAGE_BUTTON} type="button" disabled={busy !== null} onClick={() => void runReport('download', saved)} aria-label={`Download saved ${saved.format.toUpperCase()} ${entry.title || 'report'}`}>
                            <Download className="h-4 w-4" aria-hidden="true" /> {saved.format.toUpperCase()}
                          </button> : <span className="text-xs text-white/55">Snapshot unavailable</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <TruncationNote shown={Math.min(20, entries.length)} total={entries.length} noun="history entries" rank="most recent" />
          </>
        ) : (
          <EmptyState label={historyError ? 'Report history is unavailable.' : loaded ? 'No saved reports yet.' : 'Loading report history…'}
            hint={loaded && !historyError ? 'Generate a report to save its evidence snapshot here.' : undefined} />
        )}
      </Panel>
    </QuantumReadinessShell>
  );
}

function ValidationBadge({ status }: { status: Provenance['validationStatus'] }) {
  return <Badge color={status === 'validated' ? GREEN : AMBER}>{status === 'validated' ? 'Validated' : 'Incomplete'}</Badge>;
}

function SnapshotDetails({ report, preview }: { report: CapturedReport; preview: boolean }) {
  const { provenance, scope } = report;
  const details = [
    ['Report ID', provenance.reportId],
    ['Organization ID', provenance.organizationId ?? 'Unavailable'],
    ['Snapshot captured', utc(provenance.snapshotAt)],
    ['Asset inventory version', provenance.assetInventoryVersion ?? 'Unavailable'],
    ['CBOM version', provenance.cbomVersion ?? 'Unavailable'],
    ['Assessment ID', provenance.assessmentId ?? 'Unavailable'],
    ...(report.integrity?.hash ? [[
      'Snapshot integrity hash (' + report.integrity.algorithm + ')', report.integrity.hash,
    ]] : []),
  ];

  return (
    <Panel className="p-5 sm:p-6">
      <SectionTitle suffix={<ValidationBadge status={provenance.validationStatus} />}>{preview ? 'Preview snapshot provenance' : 'Saved snapshot provenance'}</SectionTitle>
      <h2 className="text-lg font-semibold text-white">{report.meta.title}</h2>
      <p className="mt-1 text-sm text-white/68">{report.executiveSummary}</p>
      <p className="mt-2 text-sm text-white/68">Registered asset scope: {scope.selectedAssetCount} of {scope.totalAssetCount}</p>
      {report.kpis.length ? (
        <dl className="my-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {report.kpis.map((metric) => (
            <div key={metric.label} className="rounded-md border border-white/10 bg-white/[0.025] p-3">
              <dt className="text-sm text-white/65">{metric.label}</dt>
              <dd className="mt-1 text-xl font-semibold tabular-nums text-white">{metric.value}{metric.unit ? ` ${metric.unit}` : ''}</dd>
            </div>
          ))}
        </dl>
      ) : null}
      <dl className="mt-4 grid gap-3 rounded-md border border-white/10 p-4 sm:grid-cols-2 lg:grid-cols-3">
        {details.map(([label, value]) => (
          <div key={label} className="min-w-0">
            <dt className="text-xs font-semibold text-white/64">{label}</dt>
            <dd className="mt-1 break-all font-mono text-xs text-white/87">{value}</dd>
          </div>
        ))}
      </dl>
      <h3 className="mb-2 mt-5 text-sm font-semibold text-white">Data completeness</h3>
      {provenance.dataCompleteness.length > 0 ? <ul className="divide-y divide-white/10 rounded-md border border-white/10 px-3">
        {provenance.dataCompleteness.map((source) => (
          <li key={source.source} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2 text-sm">
            <span className="font-semibold text-white/85">{source.source}</span>
            <span className={source.status === 'available' ? 'text-emerald-300' : 'text-amber-200'}>
              {{ available: 'Available', missing: 'Unavailable', partial: 'Partial' }[source.status]}
            </span>
            <span className="text-white/65">{source.detail}</span>
          </li>
        ))}
      </ul> : <p className="text-sm text-white/65">Source coverage is unavailable.</p>}
    </Panel>
  );
}
