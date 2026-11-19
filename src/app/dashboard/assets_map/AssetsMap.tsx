/**
 * /dashboard/assets — Asset Inventory & CBOM.
 *
 * ONE derivation feeds everything on this page and every report it exports:
 * `buildAssetRegister` (src/lib/assets/asset-register.ts) turns the live
 * scanner-intelligence stream into register rows and totals, and the panels,
 * the table, the selection bar and the Report Studio all render those rows.
 * Nothing on this page recomputes a count on its own (qguard-data-integrity,
 * rule 1).
 *
 * What changed from the previous page, and why (audit 2026-09-25):
 *  - per-asset "components" included scanner FINDINGS stored in crypto_inventory
 *    (a single asset read "20 vulnerable of 25" under a headline of 8 of 12);
 *  - "Scanned < 1h ago" was the snapshot's compute time, not the scan time —
 *    an eight-day-old inventory never showed as stale;
 *  - "Risk Score" was max(latest scan, estate mean) and "Q-Score" merely
 *    100 − risk, beside a different QR risk — now each score says its source;
 *  - "PQC ready / monitored" was granted without validating a single component;
 *  - a slow first load rendered "No assets" and zero KPIs;
 *  - the export's KPIs were estate-wide even for a two-asset selection.
 */
import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { SCAN_SOURCE_LABELS, type ScanSourceKind } from '@/lib/assets/scan-provenance';
import { AlertTriangle, Archive, ExternalLink, FileText, Loader2, Radio, RefreshCw, ScanLine, Shield } from 'lucide-react';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';
import { useQuantumReadiness } from '@/app/dashboard/quantum-readiness/_shared';
import { useMigrationWorkflow } from '@/hooks/use-migration-workflow';
import { useAuth } from '@/contexts/auth-context';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import {
  PQC_STATUS_META,
  REGISTER_BANDS,
  buildAssetRegister,
  filterRows,
  sortRows,
  summarizeRows,
  type AssetRegisterRow,
  type FreshnessState,
  type PqcStatus,
  type RegisterBandKey,
  type RegisterFilter,
  type RegisterQrInput,
  type RegisterSort,
} from '@/lib/assets/asset-register';
import { DiscoveryHeader, DiscoveryPage, StaleAssessmentBanner, panelClass } from '../_components/discovery/shell';
import { AssetTable } from './_asset-table';
import { LiveAssetFindings } from './_live-findings';
import { AssetLifecycleDialog, type LifecycleSelection } from './_lifecycle-dialog';
import { Pagination, PostureOverview, RegisterKpis, RegisterToolbar, SelectionBar, TransportStatus, nf, useNow } from './_register-ui';
import type { StudioScopeType } from './_report-studio';

const ReportStudio = lazy(() => import('./_report-studio'));

const PAGE_SIZE = 25;

export default function AssetsMap() {
  const [searchParams, setSearchParams] = useSearchParams();
  const sourceAgentId = searchParams.get('agentId');
  const sourceKindParam = searchParams.get('source');
  const sourceKind = sourceKindParam && Object.hasOwn(SCAN_SOURCE_LABELS, sourceKindParam) ? sourceKindParam as ScanSourceKind : null;
  const { user, session } = useAuth();
  const { data, error, refresh, changeAssetLifecycle, loading, connected, source, resolved, transport, lastVerifiedAt } = useScannerIntelligence();
  const qr = useQuantumReadiness();
  const { workflow } = useMigrationWorkflow();
  // Minute clock for freshness ("scanned 8d ago"): cheap, and a register row's
  // age cannot drift more than a minute behind the truth.
  const now = useNow(60_000);

  const qrInput: RegisterQrInput = useMemo(() => {
    const has = Boolean(qr.snapshot.hasData);
    return {
      resolved: qr.state === 'success',
      hasData: has,
      readiness: has ? qr.snapshot.scores.quantumReadiness : null,
      readinessLevel: has ? qr.snapshot.scores.quantumReadinessLevel : null,
      risk: has ? qr.snapshot.scores.quantumRisk : null,
      components: has ? qr.snapshot.inventory.cryptoComponents : null,
      vulnerableComponents: has ? qr.snapshot.inventory.vulnerableComponents : null,
    };
  }, [qr.state, qr.snapshot]);

  const register = useMemo(
    () => buildAssetRegister({ snapshot: data, qr: qrInput, workflowStates: workflow?.assetStates ?? null, now }),
    [data, qrInput, workflow, now],
  );

  /* ---------------- filters, sort, paging ---------------- */
  const [query, setQuery] = useState('');
  const [findingsRefresh, setFindingsRefresh] = useState(0);
  const [statusFilter, setStatusFilter] = useState<PqcStatus | null>(null);
  const [bandFilter, setBandFilter] = useState<RegisterBandKey | null>(null);
  const [freshnessFilter, setFreshnessFilter] = useState<FreshnessState | null>(null);
  const [sort, setSort] = useState<RegisterSort>('risk');
  const [page, setPage] = useState(1);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [lifecycleSelection, setLifecycleSelection] = useState<LifecycleSelection | null>(null);
  const [lifecycleMessage, setLifecycleMessage] = useState('');
  const archived = data.assets.archived ?? [];
  const [studio, setStudio] = useState<{ open: boolean; scope: StudioScopeType; singleId: string | null }>({ open: false, scope: 'all', singleId: null });

  const filters = useMemo<RegisterFilter>(() => ({
    agentId: sourceAgentId,
    sourceKind,
    query,
    statuses: statusFilter ? [statusFilter] : null,
    bands: bandFilter ? [bandFilter] : null,
    freshness: freshnessFilter ? [freshnessFilter] : null,
  }), [query, statusFilter, bandFilter, freshnessFilter, sourceAgentId, sourceKind]);
  const filtered = useMemo(
    () => sortRows(filterRows(register.rows, filters), sort),
    [register.rows, filters, sort],
  );

  useEffect(() => setPage(1), [query, statusFilter, bandFilter, freshnessFilter, sort, sourceAgentId, sourceKind]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  useEffect(() => setPage((current) => Math.min(current, pageCount)), [pageCount]);
  const pageRows = useMemo(() => filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [filtered, page]);

  // A selection may only hold assets that still exist (a scan can delete one).
  useEffect(() => {
    setSelectedIds((current) => {
      if (current.size === 0) return current;
      const live = new Set(register.rows.map((row) => row.id));
      const next = new Set([...current].filter((id) => live.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [register.rows]);

  const selectedRows = useMemo(() => register.rows.filter((row) => selectedIds.has(row.id)), [register.rows, selectedIds]);
  const selectionTotals = useMemo(() => summarizeRows(selectedRows), [selectedRows]);
  const allShownSelected = filtered.length > 0 && filtered.every((row) => selectedIds.has(row.id));

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  const toggleSelectShown = () => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (allShownSelected) filtered.forEach((row) => next.delete(row.id));
      else filtered.forEach((row) => next.add(row.id));
      return next;
    });
  };

  const filterDescription = [
    query && `search "${query}"`,
    statusFilter && `status ${PQC_STATUS_META[statusFilter].short}`,
    bandFilter && `risk band ${REGISTER_BANDS.find((b) => b.key === bandFilter)?.label}`,
    freshnessFilter && `freshness ${freshnessFilter}`,
  ].filter(Boolean).join(' · ');

  const openStudio = (scope: StudioScopeType, single: AssetRegisterRow | null = null) => setStudio({ open: true, scope, singleId: single?.id ?? null });
  const openStudioDefault = () => openStudio(selectedRows.length ? 'selection' : filterDescription ? 'filtered' : 'all');

  /* ---------------- states ---------------- */
  const hasSnapshot = source !== 'none';
  // Zero assets only means "empty" once the SERVER has said so; a cached view
  // with nothing in it is still "confirming", never a zero-filled dashboard.
  const confirming = !hasSnapshot || (register.rows.length === 0 && !resolved);
  const showEmpty = !confirming && register.rows.length === 0;

  return (
    <DiscoveryPage>
      <WorkflowRail activeStage="discovery" tone="adaptive" />
      <DiscoveryHeader
        title="Asset Inventory & CBOM"
        subtitle="Every asset the authorized scanner has measured, its cryptographic bill of materials and its post-quantum status — computed live from scan evidence."
        connected={connected}
        measuredAt={register.measuredAt}
        status={<TransportStatus transport={transport} source={source} lastVerifiedAt={lastVerifiedAt} />}
        actions={
          <>
            <button
              type="button"
              onClick={openStudioDefault}
              disabled={!register.rows.length}
              className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-amber)]/40 bg-[var(--qg-amber)] px-4 py-2 text-xs font-black text-[var(--qg-on-accent)] shadow-[0_0_18px_color-mix(in_srgb,var(--qg-amber)_28%,transparent)] transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <FileText className="h-4 w-4" aria-hidden /> Report Studio
            </button>
            <Link to="/dashboard/scanner" className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-4 py-2 text-xs font-bold text-[var(--qg-dashboard-text-soft)] no-underline transition hover:border-[var(--qg-amber)]/45">
              <ScanLine className="h-4 w-4" aria-hidden /> Run scan
            </Link>
            <button type="button" onClick={() => { void refresh(); setFindingsRefresh((value) => value + 1); }} className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-4 py-2 text-xs font-bold text-[var(--qg-dashboard-text-soft)] transition hover:border-[var(--qg-amber)]/45">
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} aria-hidden /> Refresh
            </button>
          </>
        }
      />

      {/* Cross-engine agreement and live-scan state, stated rather than implied. */}
      {hasSnapshot && register.rows.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2 text-[10px] font-black uppercase tracking-widest">
          <span
            title={register.qr.detail}
            className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${
              register.qr.state === 'match'
                ? 'border-[var(--qg-cyan)]/25 bg-[var(--qg-cyan)]/10 text-[var(--qg-cyan)]'
                : register.qr.state === 'diverged'
                  ? 'border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]'
                  : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'
            }`}
          >
            <Shield className="h-3 w-3" aria-hidden /> {register.qr.label}
          </span>
          {register.totals.scanning > 0 ? (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-700 dark:text-emerald-300">
              <Radio className="h-3 w-3 animate-pulse" aria-hidden /> Scanning {nf(register.totals.scanning)} asset{register.totals.scanning === 1 ? '' : 's'} now
            </span>
          ) : null}
          {register.unattributed.components > 0 ? (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-2 py-0.5 text-[var(--qg-text-muted)]" title="Counted by the CBOM but not attached to any asset record.">
              +{nf(register.unattributed.components)} unattributed CBOM component{register.unattributed.components === 1 ? '' : 's'}
            </span>
          ) : null}
        </div>
      ) : null}

      <StaleAssessmentBanner measuredAt={register.measuredAt} />
      {lifecycleMessage && <p className={`${panelClass} px-4 py-3 text-sm text-[var(--qg-dashboard-text)]`} role="status">{lifecycleMessage}</p>}
      {archived.length > 0 && (
        <details className={`${panelClass} p-4`}>
          <summary className="cursor-pointer text-sm font-bold text-[var(--qg-dashboard-text)]">
            <Archive className="mr-2 inline size-4" aria-hidden /> Archived assets ({nf(archived.length)})
          </summary>
          <ul className="mt-2 max-h-72 divide-y divide-[var(--qg-card-border)] overflow-auto">
            {archived.map((asset) => (
              <li key={asset.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
                <span className="break-all">{asset.name}</span>
                <div className="flex flex-wrap gap-2">
                  <button type="button" aria-label={`Restore ${asset.name}`} onClick={() => setLifecycleSelection({ action: 'restore', assets: [asset] })}
                    className="rounded-md border border-[var(--qg-card-border)] px-3 py-2 text-xs font-bold hover:border-[var(--qg-amber)]">Restore</button>
                  <button type="button" aria-label={`Remove ${asset.name}`} onClick={() => setLifecycleSelection({ action: 'remove', assets: [asset] })}
                    className="rounded-md border border-red-500/30 px-3 py-2 text-xs font-bold text-red-700 hover:bg-red-500/10 dark:text-red-300">Remove</button>
                </div>
              </li>
            ))}
          </ul>
        </details>
      )}
      <LiveAssetFindings refreshVersion={findingsRefresh} />

      {error && hasSnapshot ? (
        <div role="alert" className="flex flex-wrap items-center gap-3 rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-700 dark:text-red-200">
          <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden />
          <span>Live updates interrupted: {error}. Showing {source === 'cache' ? 'cached' : 'the last received'} inventory — figures may be out of date.</span>
          <button type="button" onClick={() => void refresh()} className="ml-auto text-xs font-black uppercase tracking-wider underline">Retry</button>
        </div>
      ) : null}

      {confirming ? (
        error ? (
          <div className={`${panelClass} p-10 text-center`} role="alert">
            <AlertTriangle className="mx-auto h-8 w-8 text-red-500" aria-hidden />
            <p className="mt-3 text-sm font-black">The asset inventory could not be loaded.</p>
            <p className="mt-1 text-xs text-[var(--qg-text-muted)]">{error}</p>
            <button type="button" onClick={() => void refresh()} className="mt-4 rounded-md border border-[var(--qg-amber)]/40 px-4 py-2 text-xs font-black uppercase text-[var(--qg-amber)]">Retry</button>
          </div>
        ) : (
          <div className={`${panelClass} flex items-center justify-center gap-3 p-12 text-sm font-bold text-[var(--qg-text-muted)]`} role="status">
            <Loader2 className="h-5 w-5 animate-spin text-[var(--qg-amber)]" aria-hidden />
            Loading the asset inventory from scan evidence… figures appear when the server answers, never as placeholder zeros.
          </div>
        )
      ) : showEmpty ? (
        <div className={`${panelClass} p-12 text-center`}>
          <ScanLine className="mx-auto h-9 w-9 text-[var(--qg-amber)]" aria-hidden />
          <p className="mt-3 text-base font-black">No authorized assets have been scanned yet</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-[var(--qg-text-muted)]">
            The register fills itself from scan evidence: run an authorized scan of a domain, endpoint or repository, and every asset it measures appears here with its cryptographic components, post-quantum status and remediation guidance.
          </p>
          <Link to="/dashboard/scanner" className="mt-5 inline-flex items-center gap-2 rounded-md border border-[var(--qg-amber)]/40 bg-[var(--qg-amber)]/10 px-4 py-2 text-xs font-black uppercase tracking-wider text-[var(--qg-amber)] no-underline">
            <ExternalLink className="h-4 w-4" aria-hidden /> Start an authorized scan
          </Link>
        </div>
      ) : (
        <>
          <RegisterKpis register={register} />
          <PostureOverview
            register={register}
            statusFilter={statusFilter}
            onStatus={setStatusFilter}
            freshnessFilter={freshnessFilter}
            onFreshness={setFreshnessFilter}
          />

          <section className={`${panelClass} space-y-4 p-4`} aria-label="Asset register">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-[11px] font-black uppercase tracking-[0.18em] text-[var(--qg-dashboard-text-soft)]">Asset register</h2>
              <span className="text-[10px] text-[var(--qg-text-muted)]">Components are cryptography only · configuration findings are listed per asset, never counted as components</span>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-xs">
              <label className="flex items-center gap-2 font-bold text-[var(--qg-dashboard-text-soft)]">Discovery source
                <select value={sourceKind || ''} onChange={(event) => setSearchParams((current) => { const next = new URLSearchParams(current); if (event.target.value) next.set('source', event.target.value); else next.delete('source'); return next; })} className="rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card)] px-3 py-2 text-[var(--qg-dashboard-text)]">
                  <option value="">All sources</option>
                  {Object.entries(SCAN_SOURCE_LABELS).map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}
                </select>
              </label>
              {sourceAgentId ? <span className="flex items-center gap-2 text-[var(--qg-text-muted)]">Showing assets attributed to this agent across its recorded scans.<button type="button" className="font-bold text-[var(--qg-amber)] underline" onClick={() => setSearchParams((current) => { const next = new URLSearchParams(current); next.delete('agentId'); return next; })}>Show all agents</button></span> : null}
            </div>
            <RegisterToolbar
              query={query}
              onQuery={setQuery}
              band={bandFilter}
              onBand={setBandFilter}
              bandCounts={register.totals.bands}
              sort={sort}
              onSort={setSort}
              shown={filtered.length}
              total={register.rows.length}
              onSelectAll={toggleSelectShown}
              allSelected={allShownSelected}
              selectedCount={selectedIds.size}
              onClearSelection={() => setSelectedIds(new Set())}
            />
            {statusFilter || freshnessFilter ? (
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--qg-dashboard-text-soft)]">
                <span className="font-bold">Filtered:</span>
                {statusFilter ? <button type="button" onClick={() => setStatusFilter(null)} className="rounded-full border border-[var(--qg-amber)]/40 px-2 py-0.5 font-black text-[var(--qg-amber)]">{PQC_STATUS_META[statusFilter].short} ×</button> : null}
                {freshnessFilter ? <button type="button" onClick={() => setFreshnessFilter(null)} className="rounded-full border border-[var(--qg-amber)]/40 px-2 py-0.5 font-black text-[var(--qg-amber)]">{freshnessFilter} ×</button> : null}
              </div>
            ) : null}
            {filtered.length === 0 ? (
              <div className="rounded-lg border border-dashed border-[var(--qg-card-border)] p-10 text-center text-sm text-[var(--qg-text-muted)]">
                No assets match the current search or filters.
                <button type="button" onClick={() => { setQuery(''); setStatusFilter(null); setBandFilter(null); setFreshnessFilter(null); }} className="ml-2 font-black text-[var(--qg-amber)]">Clear filters</button>
              </div>
            ) : (
              <AssetTable
                rows={pageRows}
                now={now}
                expandedId={expandedId}
                onToggleExpand={(id) => setExpandedId((current) => (current === id ? null : id))}
                selectedIds={selectedIds}
                onToggleSelect={toggleSelect}
                onReportAsset={(row) => openStudio('single', row)}
              />
            )}
            <Pagination
              page={page}
              pageCount={pageCount}
              onPage={setPage}
              from={filtered.length ? (page - 1) * PAGE_SIZE + 1 : 0}
              to={Math.min(page * PAGE_SIZE, filtered.length)}
              total={filtered.length}
            />
          </section>
        </>
      )}

      <SelectionBar
        count={selectedRows.length}
        vulnerable={selectionTotals.components.vulnerable}
        critical={selectionTotals.vulnerableSeverity.critical}
        onReport={() => openStudio('selection')}
        onClear={() => setSelectedIds(new Set())}
        onArchive={() => setLifecycleSelection({ action: 'archive', assets: selectedRows })}
        onRemove={() => setLifecycleSelection({ action: 'remove', assets: selectedRows })}
      />

      {lifecycleSelection && <AssetLifecycleDialog selection={lifecycleSelection} onClose={() => setLifecycleSelection(null)}
        onConfirm={async () => {
          const { action, assets } = lifecycleSelection;
          const { updatedIds, skipped } = await changeAssetLifecycle(action, assets.map((asset) => asset.id));
          if (!updatedIds.length) throw new Error('None of the selected assets could be updated. Refresh the register and try again.');
          const updated = new Set(updatedIds);
          setSelectedIds((current) => new Set([...current].filter((id) => !updated.has(id))));
          setExpandedId((current) => current && updated.has(current) ? null : current);
          const outcome = action === 'archive' ? 'archived' : action === 'restore' ? 'restored' : 'removed';
          setLifecycleMessage(`${nf(updated.size)} asset${updated.size === 1 ? '' : 's'} ${outcome}.${skipped ? ` ${nf(skipped)} could not be updated.` : ''}`);
          setFindingsRefresh((current) => current + 1);
          setLifecycleSelection(null);
        }}
      />}

      {studio.open && session && user ? (
        <Suspense fallback={<div className="fixed inset-0 z-50 grid place-items-center bg-black/40"><Loader2 className="h-6 w-6 animate-spin text-[var(--qg-amber)]" aria-label="Opening Report Studio" /></div>}>
          <ReportStudio
            key={user.id}
            open={studio.open}
            onClose={() => setStudio((current) => ({ ...current, open: false }))}
            register={register}
            selection={selectedRows}
            filtered={filtered}
            singleId={studio.singleId}
            initialScope={studio.scope}
            filterDescription={filterDescription}
            filters={filters}
            ownerId={user.id}
            token={session.access_token}
          />
        </Suspense>
      ) : null}
    </DiscoveryPage>
  );
}
