'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { AlertTriangle, Download, Filter, Microscope, RefreshCw, WifiOff } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/auth-context';
import { askSophia } from '@/lib/sophia-bridge';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { Panel } from '../_components/executive/primitives';
import { useRuntimeCryptoIntel } from '@/hooks/use-runtime-crypto-intel';
import type { RuntimeEvent, RuntimeIssue } from '@/lib/runtime-crypto/runtime-intelligence';
import {
  AttentionRequired, CoverageStrip, HndlRiskPanel, LiveCryptoActivity, MigrationVerificationPanel,
  NoTelemetryState, PqcAdoptionPanel, QuantumRiskPanel, RisksWorkspace, RuntimeConfigurationPanel,
  RuntimeFilterBar, RuntimeKpiStrip, RuntimeSecurityStatusCard, ScoreExplainer, SophiaInsightPanel,
  WindowEmptyNotice,
} from './_runtime-sections';
import { RuntimeDetailDrawer, type DrawerSelection } from './_runtime-drawer';
import {
  EMPTY_FILTERS, activeFilterCount, downloadTextFile, eventsToCsv, filterEvents, filterIssues,
  filtersFromSearchParams, filtersToSearchParams, relativeTime, sophiaContextFor, type RuntimeFilters,
} from './_runtime-lib';

/**
 * Runtime Cryptographic Intelligence.
 *
 * A decision dashboard, not a monitoring console. The reading order is the
 * operator's own question sequence:
 *
 *     SEE      → what cryptography is running
 *     UNDERSTAND → is it quantum-safe, and why does that matter
 *     ACT      → what should be fixed first
 *     VERIFY   → did the migration actually change runtime behaviour
 *
 * Three tabs, five KPIs, one score. Algorithms, certificates, libraries,
 * protocols, policies, baselines and CBOM each belong to their own QGuard Helix
 * module; this page summarises and links to them rather than duplicating them.
 *
 * Every number is served by /api/v1/runtime-crypto-intel, which derives it from
 * the tenant's own runtime evidence and reads estate-wide posture from the
 * shared Quantum Readiness snapshot. Nothing here is placeholder data.
 */

type TabKey = 'overview' | 'activity' | 'risks';

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'activity', label: 'Activity' },
  { key: 'risks', label: 'Risks' },
];

export default function RuntimeCryptoIntel() {
  const { session } = useAuth();
  const token = session?.access_token;

  const location = useLocation();
  const navigate = useNavigate();

  const [filters, setFilters] = useState<RuntimeFilters>(() => filtersFromSearchParams(location.search));
  const [tab, setTab] = useState<TabKey>('overview');
  const [showFilters, setShowFilters] = useState(false);
  const [selection, setSelection] = useState<DrawerSelection | null>(null);
  const [explainerOpen, setExplainerOpen] = useState(false);
  const [queueState, setQueueState] = useState<'idle' | 'busy' | 'done' | 'error'>('idle');

  const { data, state, error, live, lastGoodAt, refresh, reconnect } = useRuntimeCryptoIntel(filters.window);

  /* ---- URL query-state: filters survive reload and sharing --------- */
  const filterQuery = useMemo(() => filtersToSearchParams(filters), [filters]);
  useEffect(() => {
    if (filterQuery === location.search) return;
    navigate({ pathname: location.pathname, search: filterQuery }, { replace: true });
  }, [filterQuery, location.pathname, location.search, navigate]);

  const patchFilters = useCallback((patch: Partial<RuntimeFilters>) => setFilters((current) => ({ ...current, ...patch })), []);
  const clearFilters = useCallback(() => setFilters((current) => ({ ...EMPTY_FILTERS, window: current.window })), []);

  /* ---- Derived views ----------------------------------------------- */
  const events = useMemo(() => (data ? filterEvents(data.events, filters) : []), [data, filters]);
  const issues = useMemo(() => (data ? filterIssues(data.issues, filters) : []), [data, filters]);
  const attention = useMemo(() => issues.slice(0, 5), [issues]);

  /* ---- Sophia ------------------------------------------------------- */
  const ask = useCallback((question: string) => askSophia(question, sophiaContextFor(data)), [data]);

  /* ---- Queue an asset into the Migration Planner --------------------- */
  const queueAsset = useCallback(
    async (assetId: string) => {
      if (!token) return;
      setQueueState('busy');
      try {
        const response = await fetch('/api/v1/migration-planner/queue', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ assetId }),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        setQueueState('done');
      } catch (err) {
        console.error('Failed to queue asset for migration:', err);
        setQueueState('error');
      }
    },
    [token],
  );

  const openEvent = useCallback((event: RuntimeEvent) => {
    setQueueState('idle');
    setSelection({ kind: 'event', event });
  }, []);

  const openIssue = useCallback((issue: RuntimeIssue) => {
    setQueueState('idle');
    setSelection({ kind: 'issue', issue });
  }, []);

  const exportActivity = useCallback(() => {
    if (!data) return;
    downloadTextFile(
      `qguard-runtime-activity-${new Date().toISOString().slice(0, 10)}.csv`,
      eventsToCsv(events, filters, data.window.label),
    );
  }, [data, events, filters]);

  /* ================================================================ */
  /* Render                                                            */
  /* ================================================================ */

  const showSkeleton = state === 'loading' && !data;
  const showHardError = state === 'error' && !data;
  const noTelemetry = Boolean(data && data.telemetry.mode === 'none');
  const connectionLost = Boolean(data && !live && state !== 'loading');
  const filterCount = activeFilterCount(filters);

  return (
    <div className="runtime-shell min-h-screen space-y-4 p-3 lg:p-5">
      <style>{`
        .runtime-shell { background: var(--qg-dashboard-bg, #0a1020); }
        .qg-theme-light .runtime-shell [class*="bg-black/"] { background-color: rgba(255,255,255,0.55) !important; }
        .qg-theme-light .runtime-shell [class*="bg-[#0b1424]"] { background-color: rgba(255,255,255,0.92) !important; }
        .qg-theme-light .runtime-shell [class*="border-white/"] { border-color: rgba(9,13,22,0.10) !important; }
        .qg-theme-light .runtime-shell .text-white { color: var(--qg-dashboard-text) !important; }
        .qg-theme-light .runtime-shell [class*="text-white/"] { color: var(--qg-dashboard-text-soft) !important; }
        .qg-theme-light .runtime-shell .text-cyan-200,
        .qg-theme-light .runtime-shell .text-cyan-300 { color: #0e7490 !important; }
        .qg-theme-light .runtime-shell .text-emerald-200,
        .qg-theme-light .runtime-shell .text-emerald-300 { color: #047857 !important; }
        .qg-theme-light .runtime-shell .text-amber-200,
        .qg-theme-light .runtime-shell .text-amber-300 { color: #b45309 !important; }
        .qg-theme-light .runtime-shell .text-violet-200,
        .qg-theme-light .runtime-shell .text-violet-300 { color: #7c3aed !important; }
        .qg-theme-light .runtime-shell input::placeholder { color: rgba(9,13,22,0.35) !important; }
        @media (prefers-reduced-motion: reduce) {
          .runtime-shell *, .runtime-shell *::before, .runtime-shell *::after {
            animation-duration: 0.001ms !important;
            transition-duration: 0.001ms !important;
          }
        }
      `}</style>

      <WorkflowRail activeStage="monitoring" />

      {/* ---- Header (§1) ------------------------------------------------ */}
      <header className="flex flex-col gap-3 border-b border-white/10 pb-3.5 xl:flex-row xl:items-end xl:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.2)]">
            <Microscope className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h1 className="text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
              Runtime <span className="text-cyan-300">Cryptographic Intelligence</span>
            </h1>
            <p className="mt-1.5 max-w-3xl text-[12px] font-medium leading-relaxed text-white/45">
              Monitor cryptographic activity in real time, identify quantum risks, and verify your PQC migration.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex flex-col items-end">
            <span
              className={cn(
                'inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[9px] font-black uppercase tracking-widest',
                live
                  ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300'
                  : 'border-amber-400/40 bg-amber-500/10 text-amber-300',
              )}
              role="status"
            >
              <span className={cn('h-1.5 w-1.5 rounded-full', live ? 'animate-pulse bg-emerald-400' : 'bg-amber-300')} aria-hidden="true" />
              {state === 'loading' && !data ? 'Connecting' : live ? 'Live' : 'Connection lost'}
            </span>
            <span className="mt-1 font-mono text-[9.5px] text-white/30">
              Last updated: {relativeTime(data?.generatedAt ?? lastGoodAt)}
            </span>
          </div>

          <button
            type="button"
            onClick={() => setShowFilters((open) => !open)}
            aria-expanded={showFilters}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-[9px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
              filterCount > 0 ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200' : 'border-white/12 bg-white/[0.04] text-white/60 hover:bg-white/[0.08]',
            )}
          >
            <Filter className="h-3.5 w-3.5" aria-hidden="true" /> Filters{filterCount > 0 ? ` (${filterCount})` : ''}
          </button>

          <button
            type="button"
            onClick={exportActivity}
            disabled={!data || events.length === 0}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" /> Export
          </button>

          <button
            type="button"
            onClick={() => void refresh(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', state === 'loading' && 'animate-spin')} aria-hidden="true" /> Refresh
          </button>
        </div>
      </header>

      {/* ---- Connection lost (§20) — never present stale data as live --- */}
      {connectionLost && data ? (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3">
          <WifiOff className="h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <div className="text-[11.5px] font-black text-amber-200">Connection lost — this is the last successful sync, not live data</div>
            <div className="truncate text-[10px] text-white/45">
              Last update {relativeTime(lastGoodAt)}{error ? ` · ${error}` : ''}
            </div>
          </div>
          <button
            type="button"
            onClick={reconnect}
            className="rounded border border-amber-400/40 bg-amber-500/10 px-3 py-1.5 text-[9px] font-black uppercase tracking-wider text-amber-200 transition hover:bg-amber-500/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300/70"
          >
            Reconnect
          </button>
        </div>
      ) : null}

      {/* ---- Hard error -------------------------------------------------- */}
      {showHardError ? (
        <Panel className="p-8 text-center">
          <AlertTriangle className="mx-auto h-8 w-8 text-red-400" aria-hidden="true" />
          <h2 className="mt-3 text-[16px] font-black text-white">Runtime Telemetry Unavailable</h2>
          <p className="mx-auto mt-1.5 max-w-lg text-[11.5px] leading-relaxed text-white/45">
            The telemetry connection has been interrupted. No values are shown rather than presenting zeros as fact.
          </p>
          {error ? <p className="mx-auto mt-2 max-w-lg rounded-lg border border-white/10 bg-black/25 p-2.5 font-mono text-[10px] text-red-300">{error}</p> : null}
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            <button
              type="button"
              onClick={reconnect}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200"
            >
              <RefreshCw className="h-3 w-3" aria-hidden="true" /> Reconnect
            </button>
            <a href="/dashboard/quantum-readiness" className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 no-underline">
              View Quantum Readiness
            </a>
          </div>
        </Panel>
      ) : null}

      {/* ---- Loading skeleton -------------------------------------------- */}
      {showSkeleton ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-3 xl:grid-cols-5">
            {Array.from({ length: 5 }).map((_, index) => <div key={index} className="h-[118px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />)}
          </div>
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
            <div className="h-[280px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />
            <div className="h-[280px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />
          </div>
          <div className="h-[340px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />
        </div>
      ) : null}

      {/* ---- No runtime telemetry (§27) ---------------------------------- */}
      {noTelemetry && data ? <NoTelemetryState discovery={data.discovery} telemetry={data.telemetry} /> : null}

      {/* ---- Main ---------------------------------------------------------- */}
      {data && !noTelemetry ? (
        <>
          {/* Tabs (§18) */}
          <div role="tablist" aria-label="Runtime intelligence views" className="flex flex-wrap gap-1.5 border-b border-white/10 pb-1">
            {TABS.map((entry) => (
              <button
                key={entry.key}
                type="button"
                role="tab"
                id={`runtime-tab-${entry.key}`}
                aria-selected={tab === entry.key}
                aria-controls={`runtime-panel-${entry.key}`}
                onClick={() => setTab(entry.key)}
                className={cn(
                  'rounded-t-lg border-b-2 px-4 py-2 text-[10.5px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
                  tab === entry.key ? 'border-cyan-400 text-cyan-200' : 'border-transparent text-white/40 hover:text-white/70',
                )}
              >
                {entry.label}
                {entry.key === 'risks' && data.kpis.activeIssues > 0 ? (
                  <span className="ml-1.5 rounded-full bg-red-500/20 px-1.5 py-0.5 font-mono text-[9px] text-red-300">{data.kpis.activeIssues}</span>
                ) : null}
              </button>
            ))}
          </div>

          {showFilters ? (
            <RuntimeFilterBar
              filters={filters}
              environments={data.filters.environments}
              onChange={patchFilters}
              onClear={clearFilters}
              resultCount={tab === 'risks' ? issues.length : events.length}
              resultLabel={tab === 'risks' ? 'findings' : 'observations'}
            />
          ) : null}

          {data.telemetry.windowEmpty ? (
            <WindowEmptyNotice telemetry={data.telemetry} onWiden={() => patchFilters({ window: '30d' })} />
          ) : null}

          {/* ---- Overview ------------------------------------------------ */}
          {tab === 'overview' ? (
            <div id="runtime-panel-overview" role="tabpanel" aria-labelledby="runtime-tab-overview" className="space-y-4">
              <RuntimeKpiStrip kpis={data.kpis} windowLabel={data.window.label} />

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
                <RuntimeSecurityStatusCard status={data.securityStatus} onExplain={() => setExplainerOpen(true)} />
                <QuantumRiskPanel card={data.quantumRisk} />
              </div>

              <LiveCryptoActivity
                events={events}
                total={data.eventTotal}
                onSelect={openEvent}
                live={live}
                windowLabel={data.window.label}
                compact
              />

              <AttentionRequired
                issues={attention}
                totalIssues={issues.length}
                onSelect={openIssue}
                onSeeAll={() => setTab('risks')}
              />

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.35fr)]">
                <PqcAdoptionPanel adoption={data.pqcAdoption} />
                <RuntimeConfigurationPanel configurations={data.configurations} />
              </div>

              <MigrationVerificationPanel rows={data.migrationVerification} />

              <div className="grid gap-4 xl:grid-cols-2">
                <HndlRiskPanel card={data.hndl} />
                <SophiaInsightPanel insight={data.sophia} onAsk={ask} />
              </div>

              <CoverageStrip telemetry={data.telemetry} />
            </div>
          ) : null}

          {/* ---- Activity ------------------------------------------------ */}
          {tab === 'activity' ? (
            <div id="runtime-panel-activity" role="tabpanel" aria-labelledby="runtime-tab-activity" className="space-y-4">
              <RuntimeKpiStrip kpis={data.kpis} windowLabel={data.window.label} />
              <LiveCryptoActivity
                events={events}
                total={data.eventTotal}
                onSelect={openEvent}
                live={live}
                windowLabel={data.window.label}
              />
              <CoverageStrip telemetry={data.telemetry} />
            </div>
          ) : null}

          {/* ---- Risks --------------------------------------------------- */}
          {tab === 'risks' ? (
            <div id="runtime-panel-risks" role="tabpanel" aria-labelledby="runtime-tab-risks" className="space-y-4">
              <RisksWorkspace issues={issues} onSelect={openIssue} />
              <div className="grid gap-4 xl:grid-cols-2">
                <HndlRiskPanel card={data.hndl} />
                <SophiaInsightPanel insight={data.sophia} onAsk={ask} />
              </div>
            </div>
          ) : null}

          <p className="px-1 pb-2 text-[10px] leading-relaxed text-white/25">{data.evidence.note}</p>
        </>
      ) : null}

      <ScoreExplainer status={data?.securityStatus ?? { score: null, state: 'unknown', stateLabel: 'NO DATA', headline: '', mix: [], basis: '', penaltyApplied: 0 }} open={explainerOpen} onClose={() => setExplainerOpen(false)} />

      <RuntimeDetailDrawer
        selection={selection}
        onClose={() => setSelection(null)}
        onAsk={ask}
        onQueue={queueAsset}
        queueState={queueState}
      />
    </div>
  );
}
