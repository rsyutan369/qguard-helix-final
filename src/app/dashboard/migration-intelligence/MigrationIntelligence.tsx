'use client';

import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Scale, Shield, Cloud, Globe, UserCog, RefreshCw, Radio, AlertTriangle, CheckCircle2,
  Clock, Layers, Network, ChevronRight, ChevronLeft, ChevronsLeft, ChevronsRight,
  Building2, X, ArrowRight, Gauge, Filter, Search, Boxes,
  Workflow, ShieldCheck, Info, Server, Wifi, Route, type LucideIcon,
} from 'lucide-react';
import { useMigrationIntelligence } from '@/hooks/use-migration-intelligence';
import { useAuth } from '@/contexts/auth-context';
import { MigrationAssetScope } from './MigrationAssetScope';
import './migration-intelligence.css';
import { migrationDependencyLabel } from '@/lib/shared-responsibility';
import type {
  OwnershipFinding, ResponsibilityDomain, FindingPriority, MigrationDependencyStatus,
  SharedResponsibilityMatrixRow,
} from '@/lib/shared-responsibility';
import {
  Panel, SectionTitle, EmptyState, HeaderButton, Badge, Ring, ScoreGauge, MetricCard,
  integerFmt, readinessTone,
  RED, ORANGE, AMBER, GREEN, EMERALD, BLUE, CYAN, VIOLET, SLATE,
} from '@/app/dashboard/quantum-readiness/_shared';

/* ------------------------------------------------------------------ */
/* Domain + priority presentation                                     */
/* ------------------------------------------------------------------ */
const DOMAIN_META: Record<ResponsibilityDomain, { label: string; short: string; color: string; icon: LucideIcon; blurb: string }> = {
  customer: { label: 'Customer Responsibility', short: 'Customer', color: CYAN, icon: UserCog, blurb: 'Findings routed to customer review or remediation.' },
  provider: { label: 'Provider-Controlled', short: 'Provider', color: BLUE, icon: Cloud, blurb: 'Managed by a cloud / edge / SaaS provider.' },
  ecosystem: { label: 'Ecosystem-Dependent', short: 'Ecosystem', color: VIOLET, icon: Globe, blurb: 'Depends on browsers, OS, hardware or standards.' },
};

const PRIORITY_COLOR: Record<FindingPriority, string> = {
  critical: RED, high: ORANGE, medium: AMBER, low: BLUE, informational: SLATE,
};

function depColor(status: MigrationDependencyStatus): string {
  if (status === 'ready') return EMERALD;
  if (status === 'blocked') return RED;
  return AMBER;
}

function severityBucketColor(kind: 'critical' | 'high' | 'medium' | 'low'): string {
  return kind === 'critical' ? RED : kind === 'high' ? ORANGE : kind === 'medium' ? AMBER : BLUE;
}

/** Findings shown per page in the Shared Responsibility Matrix. */
const MATRIX_PAGE_SIZE = 10;

/**
 * Compact page window with first/last anchors and ellipsis gaps — e.g.
 * `[1, 'gap', 4, 5, 6, 'gap', 15]`. Keeps the control to a fixed width no
 * matter how many findings exist.
 */
function pageWindow(current: number, total: number): Array<number | 'gap'> {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages: Array<number | 'gap'> = [1];
  const left = Math.max(2, current - 1);
  const right = Math.min(total - 1, current + 1);
  if (left > 2) pages.push('gap');
  for (let p = left; p <= right; p += 1) pages.push(p);
  if (right < total - 1) pages.push('gap');
  pages.push(total);
  return pages;
}

/* ------------------------------------------------------------------ */
/* Matrix scope filters — company + asset                             */
/* ------------------------------------------------------------------ */

/** One selectable value with the live row/instance counts behind it. */
interface Facet {
  value: string
  label: string
  rows: number
  instances: number
  attributed?: boolean
}

/**
 * Build the company and asset option lists from the rows actually rendered.
 *
 * Derived from `data.matrix` rather than fetched separately, so an option can
 * never exist for something the table cannot show, and every count beside an
 * option is the count the table will produce when it is selected. A second
 * source here is how a filter starts promising rows it cannot deliver.
 */
function buildFacets(rows: SharedResponsibilityMatrixRow[]): { companies: Facet[]; assets: Facet[] } {
  const companies = new Map<string, Facet>();
  const assets = new Map<string, Facet>();

  for (const row of rows) {
    const instances = Math.max(1, row.occurrences ?? 1);

    const companyKey = row.providerAttributed ? (row.providerId || row.providerName) : '__unattributed__';
    const company = companies.get(companyKey) || {
      value: companyKey,
      label: row.providerAttributed ? row.providerName : 'Unattributed',
      rows: 0,
      instances: 0,
      attributed: row.providerAttributed,
    };
    company.rows += 1;
    company.instances += instances;
    companies.set(companyKey, company);

    const assetKey = row.assetKey || row.asset;
    const asset = assets.get(assetKey) || { value: assetKey, label: row.asset, rows: 0, instances: 0 };
    asset.rows += 1;
    asset.instances += instances;
    assets.set(assetKey, asset);
  }

  // Attributed companies first, then by volume — the unattributed bucket sinks
  // to the bottom because it is a gap to close, not a vendor to work with.
  const byVolume = (a: Facet, b: Facet) => b.rows - a.rows || a.label.localeCompare(b.label);
  return {
    companies: [...companies.values()].sort(
      (a, b) => Number(b.attributed) - Number(a.attributed) || byVolume(a, b),
    ),
    assets: [...assets.values()].sort(byVolume),
  };
}

/** Severity split for an arbitrary row set — used for the filtered subtotal. */
/**
 * Severity tally in INSTANCES, the unit "Severity by Responsibility" and every
 * other page count in. A matrix row can fold several instances of one finding,
 * so tallying rows printed "C8" here under a panel reading "C9" for the same
 * estate.
 */
function severityOf(rows: SharedResponsibilityMatrixRow[]) {
  const bucket = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const row of rows) {
    const weight = Math.max(1, row.occurrences ?? 1);
    if (row.severity === 'critical') bucket.critical += weight;
    else if (row.severity === 'high') bucket.high += weight;
    else if (row.severity === 'medium') bucket.medium += weight;
    else if (row.severity === 'low') bucket.low += weight;
  }
  return bucket;
}

/**
 * A searchable single-select. Native `<select>` cannot show per-option counts
 * or search, and an estate with hundreds of assets is unusable without both.
 */
function FacetSelect({
  icon: Icon, placeholder, facets, value, onChange, emptyLabel,
}: {
  icon: LucideIcon;
  placeholder: string;
  facets: Facet[];
  value: string | null;
  onChange: (next: string | null) => void;
  emptyLabel: string;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');

  const selected = facets.find((f) => f.value === value) || null;
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q ? facets.filter((f) => f.label.toLowerCase().includes(q)) : facets;
    return list.slice(0, 60);
  }, [facets, query]);

  // Close on Escape so the control never traps keyboard users.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  if (facets.length === 0) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md border border-white/8 bg-white/[0.02] px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wide text-white/30">
        <Icon className="h-3.5 w-3.5" /> {emptyLabel}
      </span>
    );
  }

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => { setOpen((o) => !o); setQuery(''); }}
        aria-haspopup="listbox"
        aria-expanded={open}
        className={`inline-flex max-w-[220px] items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wide transition ${
          selected
            ? 'border-cyan-400/45 bg-cyan-500/12 text-cyan-200'
            : 'border-white/10 bg-white/[0.03] text-white/50 hover:border-white/25 hover:text-white/75'
        }`}
      >
        <Icon className="h-3.5 w-3.5 shrink-0" />
        <span className="truncate">{selected ? selected.label : placeholder}</span>
        {selected ? (
          <span
            role="button"
            tabIndex={0}
            aria-label={`Clear ${placeholder}`}
            onClick={(e) => { e.stopPropagation(); onChange(null); }}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.stopPropagation(); onChange(null); } }}
            className="ml-0.5 rounded p-0.5 text-cyan-200/70 hover:bg-cyan-400/20 hover:text-white"
          >
            <X className="h-3 w-3" />
          </span>
        ) : null}
      </button>

      {open ? (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} aria-hidden="true" />
          <div className="absolute right-0 z-50 mt-1.5 w-[290px] overflow-hidden rounded-lg border border-white/12 bg-[#0b1220] shadow-2xl">
            <div className="flex items-center gap-2 border-b border-white/8 px-2.5 py-2">
              <Search className="h-3.5 w-3.5 shrink-0 text-white/30" />
              <input
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={`Search ${placeholder.toLowerCase()}…`}
                className="w-full bg-transparent text-[11px] text-white/85 outline-none placeholder:text-white/25"
              />
            </div>
            <div className="max-h-[260px] overflow-y-auto py-1" role="listbox">
              {shown.length === 0 ? (
                <div className="px-3 py-3 text-[11px] text-white/35">No match.</div>
              ) : (
                shown.map((f) => (
                  <button
                    key={f.value}
                    type="button"
                    role="option"
                    aria-selected={f.value === value}
                    onClick={() => { onChange(f.value === value ? null : f.value); setOpen(false); }}
                    className={`flex w-full items-center justify-between gap-3 px-3 py-1.5 text-left text-[11px] transition ${
                      f.value === value ? 'bg-cyan-500/12 text-cyan-200' : 'text-white/70 hover:bg-white/[0.05] hover:text-white'
                    }`}
                  >
                    <span className="truncate" title={f.label}>
                      {f.label}
                      {f.attributed === false ? (
                        <span className="ml-1.5 text-[9px] uppercase tracking-wide text-white/30">no evidence</span>
                      ) : null}
                    </span>
                    <span className="shrink-0 font-mono text-[10px] text-white/40">
                      {integerFmt(f.rows)}
                      {f.instances !== f.rows ? ` · ${integerFmt(f.instances)}i` : ''}
                    </span>
                  </button>
                ))
              )}
            </div>
            {facets.length > shown.length ? (
              <div className="border-t border-white/8 px-3 py-1.5 text-[10px] text-white/30">
                Showing {shown.length} of {integerFmt(facets.length)} — refine your search.
              </div>
            ) : null}
          </div>
        </>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Small charts                                                       */
/* ------------------------------------------------------------------ */
function Donut({ segments, size = 150 }: { segments: Array<{ label: string; value: number; color: string }>; size?: number }) {
  const total = segments.reduce((a, s) => a + s.value, 0);
  const stroke = 20;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="rgba(255,255,255,0.06)" strokeWidth={stroke} fill="none" />
        {total > 0 &&
          segments.map((s) => {
            const frac = s.value / total;
            const dash = frac * c;
            const el = (
              <circle
                key={s.label}
                cx={size / 2}
                cy={size / 2}
                r={r}
                stroke={s.color}
                strokeWidth={stroke}
                fill="none"
                strokeDasharray={`${dash} ${c - dash}`}
                strokeDashoffset={-offset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
                style={{ transition: 'stroke-dasharray 0.7s ease' }}
              />
            );
            offset += dash;
            return el;
          })}
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="text-2xl font-semibold text-white">{integerFmt(total)}</div>
          <div className="text-[9px] font-black uppercase tracking-wide text-white/45">Findings</div>
        </div>
      </div>
    </div>
  );
}

function StackedSeverityBar({ bucket }: { bucket: { critical: number; high: number; medium: number; low: number } }) {
  const total = bucket.critical + bucket.high + bucket.medium + bucket.low;
  const parts: Array<{ kind: 'critical' | 'high' | 'medium' | 'low'; value: number }> = [
    { kind: 'critical', value: bucket.critical },
    { kind: 'high', value: bucket.high },
    { kind: 'medium', value: bucket.medium },
    { kind: 'low', value: bucket.low },
  ];
  return (
    <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-white/5">
      {total === 0 ? null : parts.map((p) => (
        <div key={p.kind} style={{ width: `${(p.value / total) * 100}%`, backgroundColor: severityBucketColor(p.kind) }} />
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */
export default function MigrationIntelligence() {
  const [params, setParams] = useSearchParams();
  const { user } = useAuth();
  const assetId = params.get('asset') || null;
  const selectAsset = (id: string | null) => {
    setParams((current) => {
      const next = new URLSearchParams(current);
      if (id) next.set('asset', id); else next.delete('asset');
      return next;
    });
  };
  return <MigrationIntelligenceView key={JSON.stringify([user?.id, assetId])} assetId={assetId} onSelectAsset={selectAsset} />;
}

function MigrationIntelligenceView({ assetId, onSelectAsset }: { assetId: string | null; onSelectAsset: (id: string | null) => void }) {
  const navigate = useNavigate();
  const { session, user } = useAuth();
  const accessToken = session?.user.id === user?.id ? session?.access_token : undefined;
  const { data, state, error, sseConnected, transport, lastVerifiedAt, refresh } = useMigrationIntelligence(assetId);
  const [domainFilter, setDomainFilter] = useState<'all' | ResponsibilityDomain>('all');
  const [companyFilter, setCompanyFilter] = useState<string | null>(null);
  const [assetFilter, setAssetFilter] = useState<string | null>(null);
  const [selected, setSelected] = useState<OwnershipFinding | null>(null);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [drawerError, setDrawerError] = useState<string | null>(null);
  const [matrixPage, setMatrixPage] = useState(1);
  const findingRequest = useRef<AbortController | null>(null);
  useEffect(() => () => findingRequest.current?.abort(), []);
  const hasModel = Boolean(data.generatedAt);

  const readiness = data.readiness;
  const w = data.widgets;

  /*
   * Facets come from the SAME rows the table renders, so every option count is
   * exactly what selecting it will produce. They are recomputed on each live
   * update, which is also how a stale selection is detected below.
   */
  const facets = useMemo(() => buildFacets(data.matrix), [data.matrix]);

  const filteredMatrix = useMemo(() => {
    let rows = data.matrix;
    if (domainFilter !== 'all') rows = rows.filter((r) => r.domain === domainFilter);
    if (companyFilter) {
      rows = rows.filter((r) =>
        companyFilter === '__unattributed__'
          ? !r.providerAttributed
          : r.providerAttributed && (r.providerId || r.providerName) === companyFilter,
      );
    }
    if (assetFilter) rows = rows.filter((r) => (r.assetKey || r.asset) === assetFilter);
    return rows;
  }, [data.matrix, domainFilter, companyFilter, assetFilter]);

  /*
   * A live refresh can retire the asset or company a filter points at (the
   * scan that produced it was deleted, or the finding was remediated). Holding
   * the selection would show an empty table under a filter chip naming
   * something that no longer exists, which reads as data loss. Drop the stale
   * selection instead so the view always describes the current estate.
   */
  useEffect(() => {
    if (companyFilter && !facets.companies.some((f) => f.value === companyFilter)) setCompanyFilter(null);
    if (assetFilter && !facets.assets.some((f) => f.value === assetFilter)) setAssetFilter(null);
  }, [facets, companyFilter, assetFilter]);

  const scopeActive = domainFilter !== 'all' || companyFilter !== null || assetFilter !== null;
  const scopedSeverity = useMemo(() => severityOf(filteredMatrix), [filteredMatrix]);
  const scopedInstances = useMemo(
    () => filteredMatrix.reduce((sum, r) => sum + Math.max(1, r.occurrences ?? 1), 0),
    [filteredMatrix],
  );
  const scopedAssets = useMemo(
    () => new Set(filteredMatrix.map((r) => r.assetKey || r.asset)).size,
    [filteredMatrix],
  );
  const scopedFreshest = useMemo(() => {
    let newest = 0;
    for (const row of filteredMatrix) {
      const ms = row.observedAt ? Date.parse(row.observedAt) : 0;
      if (Number.isFinite(ms) && ms > newest) newest = ms;
    }
    return newest > 0 ? new Date(newest) : null;
  }, [filteredMatrix]);

  // Pagination — 10 findings per page. Clamp on render so a shrinking dataset
  // (filter change / live refresh) can never strand the view on an empty page.
  const matrixTotal = filteredMatrix.length;
  const matrixTotalPages = Math.max(1, Math.ceil(matrixTotal / MATRIX_PAGE_SIZE));
  const matrixCurrentPage = Math.min(matrixPage, matrixTotalPages);
  const matrixStart = (matrixCurrentPage - 1) * MATRIX_PAGE_SIZE;
  const pagedMatrix = filteredMatrix.slice(matrixStart, matrixStart + MATRIX_PAGE_SIZE);

  // Reset to the first page whenever ANY scope filter changes.
  useEffect(() => {
    setMatrixPage(1);
  }, [domainFilter, companyFilter, assetFilter]);

  /*
   * Open the drawer for a matrix row.
   *
   * The matrix carries up to 250 consolidated rows while the payload ships a
   * bounded findings list, so a row can legitimately reference a finding that
   * is not in the local array — clicking it used to do NOTHING, with no
   * feedback at all. Fall back to the tenant-scoped `/finding/:id` endpoint,
   * which reads the same cached intelligence window, and surface a real error
   * if it cannot be resolved rather than failing silently.
   */
  const openFinding = useCallback(async (findingId: string) => {
    findingRequest.current?.abort();
    setDrawerLoading(false);
    const local = data.findings.find((f) => f.id === findingId);
    if (local) { setSelected(local); setDrawerError(null); return; }
    const controller = new AbortController();
    findingRequest.current = controller;
    setDrawerLoading(true);
    setDrawerError(null);
    try {
      if (!accessToken) throw new Error('Your session expired — sign in again to open this finding.');
      const query = assetId ? `?asset=${encodeURIComponent(assetId)}` : '';
      const response = await fetch(`/api/v1/migration-intelligence/finding/${encodeURIComponent(findingId)}${query}`, {
        headers: { Authorization: `Bearer ${accessToken}` },
        cache: 'no-store',
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(12_000)]),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `Unable to load finding (HTTP ${response.status})`);
      if (payload?.finding?.id !== findingId || (assetId && payload.finding.assetId !== assetId)) throw new Error('This finding is no longer in the current intelligence window.');
      if (!controller.signal.aborted) setSelected(payload.finding as OwnershipFinding);
    } catch (err) {
      if (!controller.signal.aborted) setDrawerError(err instanceof Error ? err.message : 'Unable to open this finding.');
    } finally {
      if (!controller.signal.aborted) setDrawerLoading(false);
    }
  }, [accessToken, assetId, data.findings]);

  return (
    <div className="mi-view mx-auto max-w-[1440px] px-4 py-6 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="grid h-12 w-12 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300">
            <Scale className="h-6 w-6" />
          </span>
          <div>
            <h1 className="text-xl font-black tracking-tight text-[var(--qg-text-primary)] sm:text-2xl">
              Shared Responsibility Migration Intelligence™
            </h1>
            <p className="mt-0.5 max-w-2xl text-xs text-[var(--qg-text-secondary)]">
              Review cryptographic findings, who can act on them, and which dependencies affect migration.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* States what the connection is actually doing. "Reconnecting" used
              to show for every non-live state, including a healthy REST poll. */}
          <span
            role="status"
            data-connected={sseConnected}
            title={lastVerifiedAt ? `Server last confirmed this model at ${new Date(lastVerifiedAt).toLocaleTimeString()}` : 'Waiting for the first server answer'}
            className={`mi-transport inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wide ${
              sseConnected
                ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300'
                : transport === 'polling'
                  ? 'border-amber-400/40 bg-amber-500/10 text-amber-300'
                  : 'border-white/10 bg-black/20 text-white/45'
            }`}
          >
            <Radio className="h-3 w-3" />
            {sseConnected ? 'Live feed' : transport === 'polling' ? 'Polling' : transport === 'offline' ? 'Offline' : 'Connecting'}
            {lastVerifiedAt ? <span className="font-mono normal-case tracking-normal opacity-70">· checked {new Date(lastVerifiedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span> : null}
          </span>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh({ force: true })}>Refresh</HeaderButton>
          <HeaderButton icon={Route} onClick={() => navigate('/dashboard/migration-planner')}>Planner</HeaderButton>
        </div>
      </div>

      <MigrationAssetScope assetId={assetId} asset={data.assetScope} onSelect={onSelectAsset} />

      {data.coverage && (data.coverage.source !== 'scanner' || !data.coverage.providerConnectorsAvailable || (data.coverage.scannerFindings ?? 0) > data.totals.findings) && (
        <div role="status" className="mb-4 space-y-1 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-[var(--qg-text-primary)]">
          <p className="font-semibold">Limited evidence coverage</p>
          {data.coverage.source === 'partial-scanner' && <p>The scanner reported a partial inventory or evidence read.</p>}
          {data.coverage.source === 'readiness-fallback' && <p>Showing priority findings from the Quantum Readiness assessment fallback.</p>}
          {(data.coverage.scannerFindings ?? 0) > data.totals.findings && <p>{integerFmt(data.totals.findings)} of {integerFmt(data.coverage.scannerFindings!)} scanner observations were classified in this view.</p>}
          {!data.coverage.providerConnectorsAvailable && <p>Connected-provider corroboration is temporarily unavailable.</p>}
        </div>
      )}

      {/* A failed update must not look like a current one: the last good model
          stays on screen and says that it may be out of date. */}
      {error && hasModel ? (
        <div role="alert" className="mb-4 flex flex-wrap items-center gap-3 rounded-md border border-amber-400/30 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-200">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>Live updates interrupted: {error}. Showing the last model received — figures may be out of date.</span>
          <button type="button" onClick={() => void refresh({ force: true })} className="ml-auto font-bold underline">Retry</button>
        </div>
      ) : null}

      {state === 'loading' && !hasModel ? (
        <Panel className="p-5"><p role="status" className="flex items-center gap-2 text-sm text-white/70"><RefreshCw className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading migration intelligence…</p></Panel>
      ) : error && !hasModel ? (
        <Panel className="p-5">
          <div className="flex flex-wrap items-center gap-3 text-sm text-red-300" role="alert">
            <AlertTriangle className="h-4 w-4" /> <span>Migration intelligence could not be loaded: {error}</span>
            <button type="button" onClick={() => void refresh({ force: true })} className="ml-auto text-xs font-bold underline">Retry</button>
          </div>
        </Panel>
      ) : !data.hasData ? (
        <Panel className="p-8">
          <EmptyState
            label={assetId ? 'No findings linked to this asset in the current scanner evidence.' : 'No cryptographic findings in the current scanner evidence.'}
            hint={assetId ? 'The asset record, scan evidence, and job status are available above when recorded.' : 'Run a PQC scan or connect an evidence source to populate the assessment.'}
          />
        </Panel>
      ) : (
        <div className="space-y-6">
          {/* Tri-part readiness */}
          <Panel className="p-5">
            <SectionTitle suffix={<span className="text-[10px] font-bold uppercase tracking-wide text-white/40">Where progress can actually be made</span>}>
              Quantum Readiness — Shared Responsibility Breakdown
            </SectionTitle>
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
              <ScoreGauge label={data.coverage?.readiness === 'assessment' ? 'Estate Readiness' : 'Estimated Readiness'} score={readiness.overall.score} level={readiness.overall.level} color={readinessTone(readiness.overall.score)} />
              <ScoreGauge label="Customer Readiness" score={readiness.customer.score} level={readiness.customer.level} color={CYAN} notApplicable={readiness.customer.total === 0 ? 'No findings are owned by your teams.' : undefined} />
              <ScoreGauge label="Provider Readiness" score={readiness.provider.score} level={readiness.provider.level} color={BLUE} notApplicable={readiness.provider.total === 0 ? 'No finding is attributed to a cloud or SaaS provider.' : undefined} />
              <ScoreGauge label="Ecosystem Readiness" score={readiness.ecosystem.score} level={readiness.ecosystem.level} color={VIOLET} notApplicable={readiness.ecosystem.total === 0 ? 'No finding depends on browsers, CAs or standards bodies.' : undefined} />
            </div>
            <p className="mt-4 text-[11px] leading-relaxed text-white/45">
              {data.coverage?.readiness === 'assessment' ? 'Estate readiness comes from the Quantum Readiness assessment. ' : 'Overall readiness is estimated from the findings in this scope. '}
              Domain scores are planning estimates based on classified evidence and provider roadmap references.
            </p>
          </Panel>

          {/* Widget grid */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
            <MetricCard label="Customer Findings" value={integerFmt(w.customerFindings)} detail="Customer responsibility" color={CYAN} icon={UserCog} />
            <MetricCard label="Provider Findings" value={integerFmt(w.providerFindings)} detail="Provider-managed" color={BLUE} icon={Cloud} />
            <MetricCard label="Vendor / SaaS" value={integerFmt(w.vendorFindings)} detail="Partner dependencies" color={VIOLET} icon={Building2} />
            <MetricCard label="Cloud Dependencies" value={integerFmt(w.cloudDependencies)} detail="Edge / LB / managed" color={BLUE} icon={Server} />
            <MetricCard label="Browser Dependencies" value={integerFmt(w.browserDependencies)} detail="Await browser support" color={VIOLET} icon={Globe} />
            <MetricCard label="Actionable Now" value={integerFmt(w.actionableFindings)} detail="Customer-actionable" color={EMERALD} icon={CheckCircle2} ring={readiness.overall.total ? Math.round((w.actionableFindings / Math.max(1, readiness.overall.total)) * 100) : 0} />
            <MetricCard label="Migration Blockers" value={integerFmt(w.migrationBlockers)} detail="Critical/high gated on a dependency" color={RED} icon={AlertTriangle} />
            <MetricCard label="Waiting Dependencies" value={integerFmt(w.waitingDependencies)} detail="Provider / ecosystem" color={AMBER} icon={Clock} />
            {readiness.provider.total > 0
              ? <MetricCard label="Provider Readiness" value={integerFmt(w.providerReadiness)} suffix="/100" detail="PQ roadmap posture" color={BLUE} icon={Gauge} ring={w.providerReadiness} />
              : <MetricCard label="Provider Readiness" value="N/A" detail="No provider-attributed findings" color={SLATE} icon={Gauge} />}
            <MetricCard label="No Action Indicated" value={integerFmt(data.totals.resolved)} detail="Scanner observations" color={SLATE} icon={Workflow} />
          </div>

          {/* Ownership distribution + severity per responsibility */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Panel className="p-5">
              <SectionTitle>Ownership Distribution</SectionTitle>
              <div className="flex items-center gap-6">
                <Donut
                  segments={[
                    { label: 'Customer', value: data.domainDistribution.customer, color: CYAN },
                    { label: 'Provider', value: data.domainDistribution.provider, color: BLUE },
                    { label: 'Ecosystem', value: data.domainDistribution.ecosystem, color: VIOLET },
                  ]}
                />
                <div className="flex-1 space-y-3">
                  {(['customer', 'provider', 'ecosystem'] as ResponsibilityDomain[]).map((d) => {
                    const meta = DOMAIN_META[d];
                    const count = data.domainDistribution[d];
                    const Icon = meta.icon;
                    return (
                      <div key={d} className="flex items-start gap-2.5">
                        <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md" style={{ backgroundColor: `${meta.color}18`, color: meta.color }}>
                          <Icon className="h-4 w-4" />
                        </span>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-bold text-white">{integerFmt(count)}</span>
                            <span className="text-[11px] font-bold" style={{ color: meta.color }}>{meta.label}</span>
                          </div>
                          <div className="truncate text-[11px] text-white/45">{meta.blurb}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </Panel>

            <Panel className="p-5">
              <SectionTitle suffix={<LegendSeverity />}>Severity by Responsibility</SectionTitle>
              <div className="space-y-4">
                {(['customer', 'provider', 'ecosystem'] as ResponsibilityDomain[]).map((d) => {
                  const meta = DOMAIN_META[d];
                  const bucket = data.severityByDomain[d];
                  const total = bucket.critical + bucket.high + bucket.medium + bucket.low;
                  return (
                    <div key={d}>
                      <div className="mb-1.5 flex items-center justify-between text-[11px]">
                        <span className="font-bold" style={{ color: meta.color }}>{meta.label}</span>
                        <span className="font-mono text-white/50">
                          {integerFmt(total)} · C{bucket.critical} H{bucket.high} M{bucket.medium} L{bucket.low}
                        </span>
                      </div>
                      <StackedSeverityBar bucket={bucket} />
                    </div>
                  );
                })}
              </div>
            </Panel>
          </div>

          {/* Edge vs Origin intelligence */}
          <Panel className="p-5">
            <SectionTitle suffix={<Badge color={data.edgeOrigin.edgeManaged > 0 ? BLUE : SLATE}>{integerFmt(data.edgeOrigin.edgeManaged)} edge signals</Badge>}>
              TLS Termination Evidence
            </SectionTitle>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-blue-400/20 bg-blue-500/[0.06] p-4">
                <div className="flex items-center gap-2 text-[11px] font-black uppercase tracking-wide text-blue-300">
                  <Wifi className="h-4 w-4" /> Provider edge indicated
                </div>
                <p className="mt-2 text-xs leading-relaxed text-white/60">
                  {integerFmt(data.edgeOrigin.edgeManaged)} recorded findings indicate a provider edge. {integerFmt(data.edgeOrigin.providerFrontedAssets)} distinct inventory assets are linked by ID.
                </p>
              </div>
              <div className="rounded-lg border border-cyan-400/20 bg-cyan-500/[0.06] p-4">
                <div className="flex items-center gap-2 text-[11px] font-black uppercase tracking-wide text-cyan-300">
                  <Server className="h-4 w-4" /> Origin verification
                </div>
                <p className="mt-2 text-xs leading-relaxed text-white/60">
                  Verify the origin with its asset owner and capture origin TLS evidence before assigning a migration action.
                </p>
              </div>
            </div>
            {data.edgeOrigin.summary ? <p className="mt-3 text-[11px] text-white/45">{data.edgeOrigin.summary}</p> : null}
          </Panel>

          {/* Shared Responsibility Matrix */}
          <Panel className="p-5">
            <SectionTitle
              suffix={
                <div className="flex flex-wrap items-center justify-end gap-1.5">
                  <div className="flex items-center gap-1.5">
                    {(['all', 'customer', 'provider', 'ecosystem'] as const).map((f) => (
                      <button
                        key={f}
                        type="button"
                        onClick={() => setDomainFilter(f)}
                        className={`rounded px-2 py-1 text-[10px] font-black uppercase tracking-wide transition ${
                          domainFilter === f ? 'bg-white/15 text-white' : 'bg-white/[0.03] text-white/45 hover:text-white/70'
                        }`}
                      >
                        {f === 'all' ? 'All' : DOMAIN_META[f].short}
                      </button>
                    ))}
                  </div>
                  <span className="mx-0.5 hidden h-5 w-px bg-white/10 sm:block" aria-hidden="true" />
                  <FacetSelect
                    icon={Building2}
                    placeholder="Company"
                    facets={facets.companies}
                    value={companyFilter}
                    onChange={setCompanyFilter}
                    emptyLabel="No companies"
                  />
                  <FacetSelect
                    icon={Boxes}
                    placeholder="Asset"
                    facets={facets.assets}
                    value={assetFilter}
                    onChange={setAssetFilter}
                    emptyLabel="No assets"
                  />
                  {scopeActive ? (
                    <button
                      type="button"
                      onClick={() => { setDomainFilter('all'); setCompanyFilter(null); setAssetFilter(null); }}
                      className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1.5 text-[10px] font-black uppercase tracking-wide text-white/50 transition hover:border-white/25 hover:text-white/80"
                    >
                      Reset
                    </button>
                  ) : null}
                </div>
              }
            >
              Shared Responsibility Matrix
            </SectionTitle>

            {/*
              Scope bar. When a filter narrows the table, the subtotals BELOW
              describe the selection and nothing else — stated explicitly,
              because the panels above this one remain estate-wide and a reader
              must never have to guess which scope a number belongs to.
            */}
            <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2 text-[11px]">
              <span className="inline-flex items-center gap-1.5 font-bold text-white/70">
                <Filter className="h-3.5 w-3.5 text-cyan-300" />
                {scopeActive ? 'Filtered scope' : assetId ? 'Selected asset' : 'Estate evidence window'}
              </span>
              <span className="text-white/45">
                <span className="font-mono text-white/80">{integerFmt(filteredMatrix.length)}</span>
                {scopeActive ? <span className="text-white/30"> of {integerFmt(data.matrix.length)}</span> : null} rows
              </span>
              <span className="text-white/45">
                <span className="font-mono text-white/80">{integerFmt(scopedInstances)}</span> instances
              </span>
              <span className="text-white/45">
                <span className="font-mono text-white/80">{integerFmt(scopedAssets)}</span> {scopedAssets === 1 ? 'asset label' : 'asset labels'}
              </span>
              <span className="inline-flex items-center gap-2 text-white/45">
                <LegendSeverity />
                <span className="font-mono text-white/70">
                  C{scopedSeverity.critical} H{scopedSeverity.high} M{scopedSeverity.medium} L{scopedSeverity.low}
                </span>
              </span>
              {scopedFreshest ? (
                <span className="text-white/35">
                  newest evidence {scopedFreshest.toLocaleString()}
                </span>
              ) : (
                <span className="text-white/30">no observation timestamp recorded</span>
              )}
            </div>

            {(data.matrixTotal ?? 0) > data.matrix.length && <p className="mb-3 text-xs text-white/55">The table includes the {integerFmt(data.matrix.length)} highest-priority of {integerFmt(data.matrixTotal!)} consolidated rows in this scope.</p>}

            {drawerError ? (
              <div className="mb-3 flex items-center gap-2 rounded-lg border border-red-400/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-200">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> {drawerError}
              </div>
            ) : null}

            {filteredMatrix.length === 0 ? (
              <EmptyState
                label={scopeActive ? 'No findings match this scope.' : 'No findings in this ownership domain.'}
                hint={scopeActive ? 'Clear a matrix filter to show more rows in the current scope.' : undefined}
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[860px] text-left text-xs">
                  <thead>
                    <tr className="border-b border-white/10 text-[10px] font-black uppercase tracking-wide text-white/40">
                      <th className="py-2 pr-3">Finding</th>
                      <th className="py-2 pr-3">Asset</th>
                      <th className="py-2 pr-3">Company</th>
                      <th className="py-2 pr-3">Owner</th>
                      <th className="py-2 pr-3">Action</th>
                      <th className="py-2 pr-3 text-right">Inst.</th>
                      <th className="py-2 pr-3">Priority</th>
                      <th className="py-2 pr-3">Status</th>
                      <th className="py-2" />
                    </tr>
                  </thead>
                  <tbody>
                    {pagedMatrix.map((row) => {
                      const meta = DOMAIN_META[row.domain];
                      const occurrences = Math.max(1, row.occurrences ?? 1);
                      return (
                        <tr
                          key={row.findingId}
                          className="border-b border-white/5 transition hover:bg-white/[0.03]"
                        >
                          <td className="max-w-[220px] py-2.5 pr-3">
                            <div className="flex items-center gap-2">
                              <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: meta.color }} />
                              <button type="button" className="min-h-8 truncate rounded text-left font-semibold text-white/85 underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-cyan-400" title={row.finding} onClick={() => void openFinding(row.sourceFindingId ?? row.findingId)}>{row.finding}</button>
                            </div>
                          </td>
                          <td className="max-w-[180px] py-2.5 pr-3">
                            <span className="block truncate text-white/60" title={(row.detectionLabels ?? [row.asset]).join(' · ')}>{row.asset}</span>
                          </td>
                          <td className="max-w-[150px] py-2.5 pr-3">
                            {row.providerAttributed ? (
                              <span className="block truncate text-white/70" title={row.providerName}>{row.providerName}</span>
                            ) : (
                              /* Unattributed is a real state, not a blank cell — no evidence
                                 matched a vendor, and guessing one would misdirect the work. */
                              <span className="text-[10px] font-bold uppercase tracking-wide text-white/30" title="No evidence attributed this finding to a provider">
                                Unattributed
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 pr-3"><span className="font-semibold" style={{ color: meta.color }}>{row.owner}</span></td>
                          <td className="max-w-[240px] py-2.5 pr-3"><span className="line-clamp-2 text-white/60">{row.action}</span></td>
                          <td className="py-2.5 pr-3 text-right font-mono text-white/55">{occurrences}</td>
                          <td className="py-2.5 pr-3"><Badge color={PRIORITY_COLOR[row.priority]}>{row.priority}</Badge></td>
                          <td className="py-2.5 pr-3"><span className="text-white/65">{row.status}</span></td>
                          <td className="py-2.5 text-white/30"><ChevronRight className="h-4 w-4" /></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <MatrixPagination
                  total={matrixTotal}
                  currentPage={matrixCurrentPage}
                  totalPages={matrixTotalPages}
                  rangeStart={matrixStart}
                  shown={pagedMatrix.length}
                  onPage={(p) => setMatrixPage(Math.min(Math.max(1, p), matrixTotalPages))}
                />
              </div>
            )}
          </Panel>

          {/* Blockers + 7-wave roadmap */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Panel className="p-5">
              <SectionTitle suffix={<Badge color={w.migrationBlockers ? RED : SLATE}>{integerFmt(w.migrationBlockers)}</Badge>}>Migration Blockers</SectionTitle>
              {data.blockers.length === 0 ? (
                <EmptyState label="No high-impact blockers." hint="High/critical findings gated on an upstream dependency appear here." />
              ) : (
                <div className="space-y-2.5">
                  {data.blockers.length > 8 ? (
                    <div className="rounded-md border border-white/8 bg-white/[0.02] px-2.5 py-1.5 text-[10px] text-white/40">
                      Showing the 8 highest-impact of {integerFmt(w.migrationBlockers)} blockers.
                    </div>
                  ) : null}
                  {data.blockers.slice(0, 8).map((b) => (
                    <button
                      key={b.id}
                      type="button"
                      onClick={() => setSelected(b)}
                      className="flex w-full items-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-3 text-left transition hover:border-white/20"
                    >
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md" style={{ backgroundColor: `${depColor(b.migrationDependencyStatus)}18`, color: depColor(b.migrationDependencyStatus) }}>
                        <AlertTriangle className="h-4 w-4" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-xs font-semibold text-white/85">{b.title}</div>
                        <div className="truncate text-[11px] text-white/45">{b.ownerType} · {migrationDependencyLabel(b.migrationDependencyStatus)}</div>
                      </div>
                      <Badge color={depColor(b.migrationDependencyStatus)}>{migrationDependencyLabel(b.migrationDependencyStatus)}</Badge>
                    </button>
                  ))}
                </div>
              )}
            </Panel>

            <Panel className="p-5">
              <SectionTitle suffix={<span className="text-[10px] font-bold uppercase tracking-wide text-white/40">Planning estimates</span>}>Migration Roadmap — 7 Waves</SectionTitle>
              <div className="space-y-2">
                {data.waves.map((wave) => {
                  const meta = wave.domain === 'mixed' ? { color: SLATE } : DOMAIN_META[wave.domain];
                  // A wave with nothing classified into it has no work to finish:
                  // "Complete" would claim a migration that never had to happen.
                  const empty = wave.findingCount === 0;
                  const statusColor = empty ? SLATE : wave.status === 'ready' ? EMERALD : wave.status === 'complete' ? GREEN : wave.status === 'blocked' ? RED : AMBER;
                  return (
                    <div key={wave.wave} className="flex items-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-2.5">
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md text-xs font-black" style={{ backgroundColor: `${meta.color}18`, color: meta.color }}>
                        {wave.wave}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-xs font-bold text-white/85">{wave.name}</span>
                          <span className="text-[10px] font-mono text-white/40">{integerFmt(wave.findingCount)}</span>
                        </div>
                        <div className="truncate text-[10px] text-white/40">{wave.description}</div>
                      </div>
                      <div className="text-right">
                        <Badge color={statusColor}>{empty ? 'No findings' : wave.status}</Badge>
                        <div className="mt-0.5 text-[9px] text-white/35">{empty ? 'Nothing to migrate' : wave.estimatedTimeline}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Panel>
          </div>

          {/* Provider readiness breakdown */}
          <Panel className="p-5">
            <SectionTitle suffix={<span className="text-[10px] font-bold uppercase tracking-wide text-white/40">Evidence-attributed</span>}>Provider &amp; Ecosystem Readiness</SectionTitle>
            {data.providerBreakdown.length === 0 ? (
              <EmptyState label="No providers attributed yet." hint="Connect a provider account or capture TLS/header evidence to attribute findings." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-xs">
                  <thead>
                    <tr className="border-b border-white/10 text-[10px] font-black uppercase tracking-wide text-white/40">
                      <th className="py-2 pr-3">Provider / Technology</th>
                      <th className="py-2 pr-3">Domain</th>
                      <th className="py-2 pr-3">Findings</th>
                      <th className="py-2 pr-3">PQ Roadmap</th>
                      <th className="py-2 pr-3">Customer Influence</th>
                      <th className="py-2">Attribution Conf.</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.providerBreakdown.slice(0, 20).map((p) => {
                      const meta = DOMAIN_META[p.domain];
                      const roadmapColor = p.pqRoadmapStatus === 'shipping' ? EMERALD : p.pqRoadmapStatus === 'in_progress' ? BLUE : p.pqRoadmapStatus === 'announced' ? AMBER : SLATE;
                      return (
                        <tr key={p.providerId} className="border-b border-white/5">
                          <td className="py-2.5 pr-3 font-semibold text-white/85">{p.name}</td>
                          <td className="py-2.5 pr-3"><span className="font-semibold" style={{ color: meta.color }}>{meta.short}</span></td>
                          <td className="py-2.5 pr-3 font-mono text-white/70">{integerFmt(p.count)}</td>
                          <td className="py-2.5 pr-3"><Badge color={roadmapColor}>{p.pqRoadmapStatus.replace('_', ' ')}</Badge></td>
                          <td className="py-2.5 pr-3 capitalize text-white/60">{p.customerInfluence}</td>
                          <td className="py-2.5 text-white/60">{integerFmt(p.avgConfidence)}%</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {data.providerBreakdown.length > 20 ? (
                  <div className="mt-2 text-[10px] text-white/40">
                    Showing the 20 highest-volume of {integerFmt(data.providerBreakdown.length)} attributed providers.
                  </div>
                ) : null}
              </div>
            )}
            <div className="mt-4 flex flex-wrap items-center gap-4 border-t border-white/8 pt-3 text-[11px] text-white/45">
              <span className="inline-flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5 text-emerald-400" /> {integerFmt(data.attribution.attributed)} attributed</span>
              <span className="inline-flex items-center gap-1.5"><Info className="h-3.5 w-3.5 text-white/40" /> {integerFmt(data.attribution.unattributed)} unattributed (honest — evidence-driven only)</span>
              <span className="inline-flex items-center gap-1.5"><Gauge className="h-3.5 w-3.5 text-cyan-400" /> {integerFmt(data.attribution.avgConfidence)}% avg confidence</span>
            </div>
          </Panel>
        </div>
      )}

      {drawerLoading ? (
        <div className="mi-drawer-loading fixed inset-0 z-50 grid place-items-center">
          <div className="mi-drawer-loading-status" role="status">
            <RefreshCw className="h-4 w-4 motion-safe:animate-spin" aria-hidden="true" /> Loading finding…
          </div>
        </div>
      ) : null}
      {selected ? <FindingDrawer finding={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}

function LegendSeverity() {
  return (
    <div className="flex items-center gap-2 text-[9px] font-bold uppercase tracking-wide text-white/40">
      {(['critical', 'high', 'medium', 'low'] as const).map((k) => (
        <span key={k} className="inline-flex items-center gap-1">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: severityBucketColor(k) }} /> {k[0]}
        </span>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Premium matrix paginator — 10 findings / page                       */
/* ------------------------------------------------------------------ */
const PAGE_NAV_BASE =
  'grid h-8 w-8 place-items-center rounded-md border border-white/10 bg-white/[0.03] text-white/55 transition hover:border-cyan-400/40 hover:bg-cyan-500/10 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-30 disabled:hover:border-white/10 disabled:hover:bg-white/[0.03] disabled:hover:text-white/55';

function PageNav({ label, disabled, onClick, icon: Icon }: { label: string; disabled: boolean; onClick: () => void; icon: LucideIcon }) {
  return (
    <button type="button" aria-label={label} title={label} disabled={disabled} onClick={onClick} className={PAGE_NAV_BASE}>
      <Icon className="h-4 w-4" />
    </button>
  );
}

function MatrixPagination({
  total,
  currentPage,
  totalPages,
  rangeStart,
  shown,
  onPage,
}: {
  total: number;
  currentPage: number;
  totalPages: number;
  rangeStart: number;
  shown: number;
  onPage: (page: number) => void;
}) {
  const firstRow = total === 0 ? 0 : rangeStart + 1;
  const lastRow = rangeStart + shown;
  return (
    <div className="mt-4 flex flex-col gap-3 border-t border-white/8 pt-3 sm:flex-row sm:items-center sm:justify-between">
      <p className="text-[11px] text-white/45">
        Showing <span className="font-mono font-semibold text-white/75">{integerFmt(firstRow)}</span>–
        <span className="font-mono font-semibold text-white/75">{integerFmt(lastRow)}</span> of{' '}
        <span className="font-mono font-semibold text-white/75">{integerFmt(total)}</span> findings
        <span className="ml-1 text-white/30">· {MATRIX_PAGE_SIZE} per page</span>
      </p>

      {totalPages > 1 ? (
        <nav aria-label="Findings pagination" className="flex items-center gap-1.5">
          <PageNav label="First page" icon={ChevronsLeft} disabled={currentPage <= 1} onClick={() => onPage(1)} />
          <PageNav label="Previous page" icon={ChevronLeft} disabled={currentPage <= 1} onClick={() => onPage(currentPage - 1)} />

          <div className="flex items-center gap-1">
            {pageWindow(currentPage, totalPages).map((entry, i) =>
              entry === 'gap' ? (
                <span key={`gap-${i}`} className="px-1 text-[11px] font-bold text-white/25" aria-hidden="true">
                  …
                </span>
              ) : (
                <button
                  key={entry}
                  type="button"
                  aria-label={`Page ${entry}`}
                  aria-current={entry === currentPage ? 'page' : undefined}
                  onClick={() => onPage(entry)}
                  className={
                    entry === currentPage
                      ? 'h-8 min-w-[2rem] rounded-md border border-cyan-400/50 bg-cyan-500/15 px-2 text-[11px] font-black text-cyan-200 shadow-[0_0_16px_rgba(34,211,238,0.18)]'
                      : 'h-8 min-w-[2rem] rounded-md border border-white/10 bg-white/[0.03] px-2 text-[11px] font-bold text-white/55 transition hover:border-cyan-400/40 hover:bg-cyan-500/10 hover:text-cyan-200'
                  }
                >
                  {entry}
                </button>
              ),
            )}
          </div>

          <PageNav label="Next page" icon={ChevronRight} disabled={currentPage >= totalPages} onClick={() => onPage(currentPage + 1)} />
          <PageNav label="Last page" icon={ChevronsRight} disabled={currentPage >= totalPages} onClick={() => onPage(totalPages)} />
        </nav>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Finding drill-down drawer — ownership, dependency chain, edge/origin */
/* ------------------------------------------------------------------ */
type DrawerTone = 'muted' | 'accent' | 'customer' | 'ecosystem' | 'positive' | 'warning' | 'danger';

const DRAWER_DOMAIN_TONE: Record<ResponsibilityDomain, DrawerTone> = {
  customer: 'customer', provider: 'accent', ecosystem: 'ecosystem',
};

const DRAWER_PRIORITY_TONE: Record<FindingPriority, DrawerTone> = {
  critical: 'danger', high: 'warning', medium: 'warning', low: 'accent', informational: 'muted',
};

function FindingDrawer({ finding, onClose }: { finding: OwnershipFinding; onClose: () => void }) {
  const meta = DOMAIN_META[finding.domain];
  const Icon = meta.icon;
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  const observedAt = finding.observedAt && Number.isFinite(Date.parse(finding.observedAt))
    ? new Date(finding.observedAt).toLocaleString()
    : null;
  const actionTone = finding.customerActionable === 'yes' ? 'positive'
    : finding.customerActionable === 'partial' ? 'warning' : 'muted';

  return (
    <dialog ref={dialog} aria-labelledby={titleId} onCancel={(event) => { event.preventDefault(); onClose(); }}
      className="mi-drawer">
      <header className="mi-drawer-header" data-tone={DRAWER_DOMAIN_TONE[finding.domain]}>
        <span className="mi-drawer-icon"><Icon size={21} aria-hidden="true" /></span>
        <div className="mi-drawer-heading">
          <p>{meta.label}</p>
          <h2 id={titleId}>{finding.title}</h2>
        </div>
        <button type="button" autoFocus onClick={onClose} aria-label="Close finding details" className="mi-drawer-close">
          <X size={20} aria-hidden="true" />
        </button>
      </header>

      <div className="mi-drawer-body">
        <p className="mi-drawer-description">{finding.description}</p>

        <dl className="mi-drawer-grid">
          <DrawerField label="Asset" value={finding.asset || 'Unknown asset'} />
          <DrawerField label="Company" value={finding.attribution.attributed ? finding.attribution.providerName : 'Unattributed'}
            tone={finding.attribution.attributed ? undefined : 'muted'} />
          <DrawerField label="Algorithm" value={finding.algorithm || 'Not recorded'} tone={finding.algorithm ? undefined : 'muted'} />
          <DrawerField label="Evidence observed" value={observedAt ?? 'No timestamp recorded'} tone={observedAt ? undefined : 'muted'} />
          <DrawerField label="Owner" value={finding.ownerType} />
          <DrawerField label="Remediation contact" value={finding.responsibleParty} />
          <DrawerField label="Customer actionability" value={finding.actionability.label} tone={actionTone} />
          <DrawerField label="Priority" value={finding.priority} tone={DRAWER_PRIORITY_TONE[finding.priority]} />
          <DrawerField label="Business impact" value={finding.businessImpact.level} />
          <DrawerField label="Migration complexity" value={finding.migrationComplexity} />
          <DrawerField label="Estimated effort" value={finding.estimatedEffort} />
          <DrawerField label="Estimated timeline" value={finding.estimatedTimeline} />
        </dl>

        <section className="mi-drawer-card mi-drawer-action" data-tone="accent">
          <h3 className="mi-drawer-section-title"><ArrowRight size={17} aria-hidden="true" /> Recommended action</h3>
          <p>{finding.recommendedAction}</p>
        </section>

        {finding.dependencyChain.nodes.length > 0 && (
          <section className="mi-drawer-section">
            <h3 className="mi-drawer-section-title"><Network size={17} aria-hidden="true" /> Migration planning dependencies</h3>
            <div className="mi-drawer-card">
              <p>{finding.dependencyChain.summary}</p>
              <ol className="mi-drawer-dependencies">
                {finding.dependencyChain.nodes.map((node, index) => (
                  <li key={node.id}>
                    {index > 0 && <ChevronRight size={14} aria-hidden="true" />}
                    <span className="mi-drawer-pill" title={node.note}
                      data-tone={node.blocking ? 'danger' : node.status === 'complete' ? 'positive' : 'muted'}>
                      {node.label}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          </section>
        )}

        {finding.edgeOrigin && (
          <section className="mi-drawer-section">
            <h3 className="mi-drawer-section-title"><Layers size={17} aria-hidden="true" /> TLS layers</h3>
            {finding.edgeOrigin.layers.map((layer) => (
              <div key={layer.layer} className="mi-drawer-card">
                <div className="mi-drawer-layer">
                  <strong>{layer.layer} · {layer.owner}</strong>
                  <span className="mi-drawer-pill" data-tone={DRAWER_DOMAIN_TONE[layer.domain]}>
                    {layer.customerControl === 'yes' ? 'Customer' : 'Provider'}
                  </span>
                </div>
                <p>{layer.recommendation}</p>
              </div>
            ))}
          </section>
        )}

        <section className="mi-drawer-section">
          <h3 className="mi-drawer-section-title"><Shield size={17} aria-hidden="true" /> Evidence &amp; confidence</h3>
          <div className="mi-drawer-card mi-drawer-grid mi-drawer-confidence">
            <ConfidenceBar label="Overall" value={finding.confidence.overall} />
            <ConfidenceBar label="Ownership" value={finding.confidence.ownership} />
            <ConfidenceBar label="Actionability" value={finding.confidence.actionability} />
            <ConfidenceBar label="Provider attribution" value={finding.confidence.providerAttribution} />
          </div>
          <dl className="mi-drawer-card mi-drawer-evidence">
            <div><dt>Detection</dt><dd>{finding.evidence.detectionMethod}</dd></div>
            <div><dt>Source</dt><dd>{finding.evidence.evidenceSource}</dd></div>
            <div><dt>Attribution</dt><dd>{finding.evidence.providerAttributionReason}</dd></div>
          </dl>
          {finding.references.length > 0 && (
            <ul className="mi-drawer-references">
              {finding.references.map((reference) => (
                <li key={reference.url}>
                  <a href={reference.url} target="_blank" rel="noreferrer">{reference.label}</a>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </dialog>
  );
}

function DrawerField({ label, value, tone }: { label: string; value: string; tone?: DrawerTone }) {
  return (
    <div className="mi-drawer-card mi-drawer-field">
      <dt>{label}</dt>
      <dd data-tone={tone}>{value}</dd>
    </div>
  );
}

function ConfidenceBar({ label, value }: { label: string; value: number }) {
  const tone = value >= 80 ? 'positive' : value >= 60 ? 'accent' : value >= 40 ? 'warning' : 'muted';
  return (
    <div className="mi-drawer-meter">
      <div><span>{label}</span><span>{integerFmt(value)}%</span></div>
      <span className="mi-drawer-meter-track" aria-hidden="true">
        <span data-tone={tone} style={{ width: Math.min(100, Math.max(0, value)) + '%' }} />
      </span>
    </div>
  );
}
