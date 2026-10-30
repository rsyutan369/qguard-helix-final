'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  AlertTriangle, Beaker, Command as CommandIcon, Download, Maximize2, Minimize2,
  RefreshCw, ScanLine, Shuffle, Sparkles, History,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/auth-context';
import { useCryptoAgility } from '@/hooks/use-crypto-agility';
import { askSophia } from '@/lib/sophia-bridge';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { Panel } from '../_components/executive/primitives';
import type {
  AgilityAssetRow, AgilityBlocker, AgilityDomain, AgilityKpi, AgilityState,
  CouplingFinding, CouplingNode, ReplaceabilityRow, RuntimeCryptoEvent,
} from '@/lib/crypto-agility/agility-intelligence';
import {
  AgilityAssetWorkspace, AgilityBlockers, AgilityDistribution, AgilityDriftPanel,
  AgilityFilterBar, AgilityHero, AgilityKpiStrip, AgilityLifecycle, AgilityPosture,
  AssessmentHistory, CouplingAnalysis, GraphSection, PolicyPanel, ReplaceabilityMatrix,
  ResponsibilityMatrix, RuntimeAgility, SophiaRecommendations,
} from './_agility-sections';
import { DependencyGraph } from './_agility-graph';
import { AlgorithmTransitions, ChangeTrackingPanel } from './_agility-transitions';
import { ConnectionLostBanner, LiveStatus, ModuleBrief, SourceHealth } from '../_components/intel/kit';
import { AgilityDrawer, ChangeTestPanel, CommandPalette, ScoreExplainer, type AgilitySelection, type Command } from './_agility-drawer';
import {
  EMPTY_FILTERS, activeFilterCount, assetsToCsv, downloadTextFile, filterAssets,
  filterResponsibility, filtersFromSearchParams, filtersToSearchParams, relativeTime,
  replaceabilityToCsv, responsibilityToCsv, sophiaContextFor, sortAssets,
  type AgilityFilters, type AssetSortKey,
} from './_agility-lib';

/**
 * Crypto Agility Command Center™.
 *
 * "Mission control for cryptographic change" — the decision and control layer
 * connecting Discovery/CBOM, Quantum Readiness, the Migration Planner, the
 * Sandbox digital twin, Live Migration and Runtime Telemetry.
 *
 * Reading order (matches the operator's real question sequence):
 *   our agility → what blocks us → what can change → what will break →
 *   what to fix → who owns it → can we simulate it → can we migrate it →
 *   is the environment still agile
 *
 * Every number is served by /api/v1/crypto-agility, which derives it from the
 * tenant's own evidence. Nothing on this page is computed from placeholder data.
 */

export default function CryptoAgility() {
  const { session } = useAuth();
  const token = session?.access_token;
  const { data, state, error, live, transport, lastVerifiedAt, lastGoodAt, refreshing, refresh, reconnect } = useCryptoAgility();

  const location = useLocation();
  const navigate = useNavigate();

  const [filters, setFilters] = useState<AgilityFilters>(() => filtersFromSearchParams(location.search));
  const [sort, setSort] = useState<AssetSortKey>('agility');
  const [direction, setDirection] = useState<'asc' | 'desc'>('asc');
  const [selection, setSelection] = useState<AgilitySelection | null>(null);
  const [explainerOpen, setExplainerOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [changeTestAsset, setChangeTestAsset] = useState<string | null>(null);
  const [changeTestOpen, setChangeTestOpen] = useState(false);
  const [riskPathsOnly, setRiskPathsOnly] = useState(false);
  const [graphNodeId, setGraphNodeId] = useState<string | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  /* ---- URL query-state (§25): filters survive reload and sharing ---- */
  const filterQuery = useMemo(() => filtersToSearchParams(filters), [filters]);
  useEffect(() => {
    if (filterQuery === location.search) return;
    navigate({ pathname: location.pathname, search: filterQuery }, { replace: true });
  }, [filterQuery, location.pathname, location.search, navigate]);

  const patchFilters = useCallback((patch: Partial<AgilityFilters>) => setFilters((current) => ({ ...current, ...patch })), []);
  const clearFilters = useCallback(() => setFilters(EMPTY_FILTERS), []);

  const onSort = useCallback((key: AssetSortKey) => {
    setSort((currentKey) => {
      if (currentKey === key) {
        setDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
        return currentKey;
      }
      setDirection(key === 'name' ? 'asc' : 'desc');
      return key;
    });
  }, []);

  /* ---- Derived views ------------------------------------------------ */
  const assetRows = useMemo(() => (data ? sortAssets(filterAssets(data.assets, filters), sort, direction) : []), [data, filters, sort, direction]);
  const responsibilityRows = useMemo(() => (data ? filterResponsibility(data.responsibility, filters) : []), [data, filters]);
  const couplingRows = useMemo(() => {
    if (!data) return [];
    if (filters.state === 'all' && filters.environment === 'all' && filters.owner === 'all' && !filters.search.trim()) return data.coupling;
    const allowed = new Set(assetRows.map((r) => r.id));
    return data.coupling.filter((finding) => allowed.has(finding.assetId));
  }, [data, filters, assetRows]);

  /* ---- Sophia ------------------------------------------------------- */
  const ask = useCallback((question: string) => askSophia(question, sophiaContextFor(data)), [data]);

  /* ---- Actions ------------------------------------------------------ */
  const openChangeTest = useCallback((assetId: string | null) => {
    setChangeTestAsset(assetId);
    setChangeTestOpen(true);
    setSelection(null);
  }, []);

  const exportSnapshot = useCallback(() => {
    if (!data) return;
    downloadTextFile(`qguard-crypto-agility-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(data, null, 2), 'application/json;charset=utf-8');
  }, [data]);

  const toggleFullscreen = useCallback(() => {
    const element = rootRef.current;
    if (!element) return;
    if (!document.fullscreenElement) element.requestFullscreen?.().catch(() => {});
    else document.exitFullscreen?.().catch(() => {});
  }, []);

  useEffect(() => {
    const handler = () => setIsFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const scrollTo = useCallback((id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, []);

  const commands: Command[] = useMemo(() => {
    const sections: Array<[string, string]> = [
      ['agility-posture', 'Jump: Crypto Agility Posture'],
      ['agility-distribution', 'Jump: Agility State Distribution'],
      ['coupling-graph', 'Jump: Dependency & Coupling Graph'],
      ['coupling-analysis', 'Jump: Crypto Coupling Analysis'],
      ['replaceability', 'Jump: Replaceability Matrix'],
      ['agility-assets', 'Jump: Asset Agility & Readiness'],
      ['agility-blockers', 'Jump: Agility Blockers'],
      ['responsibility', 'Jump: Responsibility Matrix'],
      ['lifecycle', 'Jump: Crypto Agility Lifecycle'],
      ['runtime', 'Jump: Runtime Crypto Agility'],
      ['agility-drift', 'Jump: Crypto Agility Drift'],
      ['agility-policy', 'Jump: Policy & Governance'],
      ['history', 'Jump: Assessment History'],
      ['sophia', 'Jump: Sophia Recommendations'],
    ];
    const modules: Array<[string, string]> = [
      ['/dashboard/scanner', 'Open: PQC Scanner'],
      ['/dashboard/cbom', 'Open: CBOM'],
      ['/dashboard/migration-planner', 'Open: Migration Planner'],
      ['/dashboard/migration-sandbox', 'Open: Migration Sandbox'],
      ['/dashboard/live-migration', 'Open: Live Migration Ops'],
      ['/dashboard/quantum-remediation', 'Open: Remediation Engine'],
      ['/dashboard/runtime-crypto-intel', 'Open: Runtime Crypto Intelligence'],
    ];
    return [
      { id: 'run-assessment', label: 'Run Assessment (recompute now)', hint: 'action', run: () => void refresh(true) },
      { id: 'change-test', label: 'Test a cryptographic change', hint: 'action', run: () => openChangeTest(null) },
      { id: 'explain', label: 'How is the agility score calculated?', hint: 'help', run: () => setExplainerOpen(true) },
      { id: 'export', label: 'Export agility snapshot (JSON)', hint: 'export', run: exportSnapshot },
      { id: 'clear', label: 'Clear all filters', hint: 'filter', run: clearFilters },
      { id: 'fullscreen', label: 'Toggle full screen', hint: 'view', run: toggleFullscreen },
      ...sections.map(([id, label]) => ({ id, label, hint: 'section', run: () => scrollTo(id) })),
      ...modules.map(([href, label]) => ({ id: href, label, hint: 'module', run: () => navigate(href) })),
    ];
  }, [refresh, openChangeTest, exportSnapshot, clearFilters, toggleFullscreen, scrollTo, navigate]);

  const graphNode = useMemo(() => data?.graph.nodes.find((n) => n.id === graphNodeId) ?? null, [data, graphNodeId]);

  /* ================================================================ */
  /* Render                                                            */
  /* ================================================================ */

  const showSkeleton = state === 'loading' && !data;
  const showHardError = state === 'error' && !data;
  const showEmpty = Boolean(data && !data.hasData);

  return (
    <div ref={rootRef} className="agility-shell min-h-screen space-y-4 p-3 lg:p-5">
      <style>{`
        .agility-shell { background: var(--qg-dashboard-bg, #0a1020); }
        .qg-theme-light .agility-shell [class*="bg-black/"] { background-color: rgba(255,255,255,0.55) !important; }
        .qg-theme-light .agility-shell [class*="bg-[#080e1b]"],
        .qg-theme-light .agility-shell [class*="bg-[#060c17]"] { background-color: rgba(255,255,255,0.9) !important; }
        .qg-theme-light .agility-shell [class*="border-white/"] { border-color: rgba(9,13,22,0.10) !important; }
        .qg-theme-light .agility-shell .text-white { color: var(--qg-dashboard-text) !important; }
        .qg-theme-light .agility-shell [class*="text-white/"] { color: var(--qg-dashboard-text-soft) !important; }
        .qg-theme-light .agility-shell .text-cyan-200,
        .qg-theme-light .agility-shell .text-cyan-300 { color: #0e7490 !important; }
        .qg-theme-light .agility-shell .text-emerald-300 { color: #047857 !important; }
        .qg-theme-light .agility-shell .text-amber-300 { color: #b45309 !important; }
        .qg-theme-light .agility-shell .text-red-300 { color: #dc2626 !important; }
        .qg-theme-light .agility-shell .text-violet-300 { color: #7c3aed !important; }
        .qg-theme-light .agility-shell input::placeholder { color: rgba(9,13,22,0.35) !important; }
        @media (prefers-reduced-motion: reduce) {
          .agility-shell *, .agility-shell *::before, .agility-shell *::after {
            animation-duration: 0.001ms !important;
            transition-duration: 0.001ms !important;
          }
        }
      `}</style>

      <WorkflowRail activeStage="remediation" />

      {/* ---- Header ---------------------------------------------------- */}
      <header className="flex flex-col gap-3 border-b border-white/10 pb-3.5 xl:flex-row xl:items-end xl:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.2)]">
            <Shuffle className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h1 className="text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
              Crypto <span className="text-cyan-300">Agility Command Center</span>
            </h1>
            <p className="mt-1.5 max-w-3xl text-[12px] font-medium leading-relaxed text-white/45">
              Measure how quickly and safely your organization can change cryptography without disrupting applications, infrastructure, identity, trust, or business operations.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <LiveStatus transport={transport} lastVerifiedAt={lastVerifiedAt} generatedAt={data?.generatedAt ?? null} />
          <HeaderButton onClick={() => setPaletteOpen(true)} icon={CommandIcon} title="Command palette (Ctrl/Cmd+K)">⌘K</HeaderButton>
          <HeaderButton onClick={() => scrollTo('history')} icon={History} title="View assessment history">History</HeaderButton>
          <HeaderButton onClick={exportSnapshot} icon={Download} title="Export the full agility snapshot as JSON">Export</HeaderButton>
          <HeaderButton onClick={toggleFullscreen} icon={isFullscreen ? Minimize2 : Maximize2} title="Full screen">{isFullscreen ? 'Exit' : 'Full'}</HeaderButton>
          <button
            type="button"
            onClick={() => ask('Why is our crypto agility score what it is, and what should we fix first?')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/45 bg-violet-500/12 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/22"
          >
            <Sparkles className="h-3.5 w-3.5" /> Ask Sophia
          </button>
          <button
            type="button"
            onClick={() => void refresh(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} aria-hidden="true" /> Run Assessment
          </button>
        </div>
      </header>

      {/* ---- Connection banner (data still shown) ----------------------- */}
      {data && (transport !== 'stream' || error) && (
        <ConnectionLostBanner lastGoodAt={lastGoodAt} error={error} onReconnect={reconnect} transport={transport} lastVerifiedAt={lastVerifiedAt} />
      )}

      {/* ---- Hard error -------------------------------------------------- */}
      {showHardError && (
        <Panel className="p-8 text-center">
          <AlertTriangle className="mx-auto h-8 w-8 text-red-400" />
          <h2 className="mt-3 text-[16px] font-black text-white">Crypto Agility Data Unavailable</h2>
          <p className="mx-auto mt-1.5 max-w-lg text-[11.5px] leading-relaxed text-white/45">
            QGuard Helix could not retrieve the latest agility assessment. No values are shown rather than presenting zeros as fact.
          </p>
          <p className="mx-auto mt-2 max-w-lg rounded-lg border border-white/10 bg-black/25 p-2.5 font-mono text-[10px] text-red-300">{error}</p>
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            <button type="button" onClick={() => void refresh(true)} className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200">
              <RefreshCw className="h-3 w-3" /> Retry
            </button>
            <a href="/dashboard/quantum-readiness" className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 no-underline">
              View Quantum Readiness
            </a>
          </div>
        </Panel>
      )}

      {/* ---- Loading skeleton (no layout jump) --------------------------- */}
      {showSkeleton && (
        <div className="space-y-4">
          <div className="h-[188px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />
          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7">
            {Array.from({ length: 14 }).map((_, index) => <div key={index} className="h-[76px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />)}
          </div>
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]">
            <div className="h-[430px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />
            <div className="h-[430px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />
          </div>
        </div>
      )}

      {/* ---- Empty state ------------------------------------------------- */}
      {showEmpty && data && (
        <Panel className="p-8 text-center">
          <ScanLine className="mx-auto h-9 w-9 text-cyan-300/70" />
          <h2 className="mt-3 text-[18px] font-black text-white">No Crypto Agility Assessment</h2>
          <p className="mx-auto mt-2 max-w-2xl text-[12px] leading-relaxed text-white/50">
            QGuard Helix has not evaluated cryptographic replaceability for this environment yet.
          </p>
          <div className="mx-auto mt-4 max-w-2xl rounded-xl border border-white/10 bg-black/25 p-4 text-left">
            <div className="text-[9px] font-black uppercase tracking-widest text-cyan-300/70">What the assessment will do</div>
            <ul className="mt-2 space-y-1.5 text-[11px] leading-relaxed text-white/50">
              <li>· Inventory every cryptographic component and the asset it belongs to.</li>
              <li>· Detect coupling — hard-coded algorithms, embedded certificates, static trust anchors, legacy providers and vendor-locked cryptography.</li>
              <li>· Classify each implementation as Agile, Conditionally Agile, Rigid, Blocked or Unknown.</li>
              <li>· Map every algorithm to its NIST replacement and score how hard the swap is.</li>
              <li>· Score 11 agility domains, publish the blockers, and name the owner of each.</li>
            </ul>
          </div>
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            <a href="/dashboard/scanner" className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2.5 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline">
              <ScanLine className="h-3.5 w-3.5" /> Run Crypto Agility Assessment
            </a>
            <a href="/dashboard/assets" className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/5 px-4 py-2.5 text-[10px] font-black uppercase tracking-wider text-white/60 no-underline">
              Connect Asset Inventory
            </a>
          </div>
          <p className="mt-3 text-[10px] text-white/30">{data.evidence.note}</p>
        </Panel>
      )}

      {/* ---- Main content ------------------------------------------------ */}
      {data && data.hasData && (
        <>
          <ModuleBrief
            what={<>How quickly each cryptographic dependency can be swapped: per-asset replaceability, eleven scored domains, every algorithm's status and its approved target, and what blocks the change.</>}
            why={<>Quantum migration is a sequence of algorithm swaps. An estate whose cryptography is hard-coded, vendor-locked or anchored to static roots cannot move when a standard or a deadline changes — knowing which part is rigid decides the order of work.</>}
            next={{ label: data.nextStep.label, href: data.nextStep.route, detail: data.nextStep.detail, tone: data.nextStep.tone }}
            scope={<>{data.score.assetsEvaluated} of {data.assets.length} discovered asset(s) carry cryptographic evidence; {data.score.couplingAssessed} have source, library or runtime visibility so their coupling could be assessed.</>}
          />

          <AgilityHero
            intel={data}
            onExplain={() => setExplainerOpen(true)}
            onFilterState={(agilityState: AgilityState) => {
              patchFilters({ state: filters.state === agilityState ? 'all' : agilityState });
              scrollTo('agility-assets');
            }}
          />

          <AgilityKpiStrip kpis={data.kpis} onDrill={(kpi: AgilityKpi) => {
            if (kpi.filter?.kind === 'state') patchFilters({ state: kpi.filter.value });
            if (kpi.filter?.kind === 'readiness') patchFilters({ readiness: kpi.filter.value });
            if (kpi.route.startsWith('#')) scrollTo(kpi.route.slice(1));
            else if (kpi.route.startsWith('/')) navigate(kpi.route);
            setSelection({ kind: 'kpi', kpi });
          }} />

          <AgilityLifecycle stages={data.lifecycle} />

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
            <AgilityPosture domains={data.domains} onSelect={(domain: AgilityDomain) => setSelection({ kind: 'domain', domain })} />
            <div className="space-y-4">
              <AgilityDistribution
                buckets={data.distribution}
                active={filters.state}
                onSelect={(agilityState: AgilityState) => {
                  patchFilters({ state: filters.state === agilityState ? 'all' : agilityState });
                  scrollTo('agility-assets');
                }}
              />
              <AgilityDriftPanel drift={data.drift} />
            </div>
          </div>

          <GraphSection note={data.graph.note}>
            <DependencyGraph
              graph={data.graph}
              selectedId={graphNodeId}
              riskOnly={riskPathsOnly}
              onToggleRiskOnly={() => setRiskPathsOnly((value) => !value)}
              onSelect={(node: CouplingNode | null) => {
                setGraphNodeId(node?.id ?? null);
                setSelection(node ? { kind: 'node', node } : null);
              }}
            />
          </GraphSection>

          {/* Global filter bar governs every table below it */}
          <AgilityFilterBar
            filters={filters}
            options={data.filters}
            activeCount={activeFilterCount(filters)}
            onChange={patchFilters}
            onClear={clearFilters}
          />

          <CouplingAnalysis findings={couplingRows} onSelect={(finding: CouplingFinding) => setSelection({ kind: 'coupling', finding })} />

          <AlgorithmTransitions
            lanes={data.transitions}
            statuses={data.algorithmStatus}
            excludedFindingTitles={data.excludedFindingTitles}
          />

          <ReplaceabilityMatrix
            rows={data.replaceability}
            onSelect={(row: ReplaceabilityRow) => setSelection({ kind: 'replaceability', row })}
            onExport={() => downloadTextFile(`qguard-replaceability-${new Date().toISOString().slice(0, 10)}.csv`, replaceabilityToCsv(data), 'text/csv;charset=utf-8')}
          />

          <AgilityAssetWorkspace
            rows={assetRows}
            total={data.assets.length}
            filters={filters}
            sort={sort}
            direction={direction}
            onSort={onSort}
            onSelect={(row: AgilityAssetRow) => setSelection({ kind: 'asset', asset: row })}
            onExport={() => downloadTextFile(`qguard-agility-assets-${new Date().toISOString().slice(0, 10)}.csv`, assetsToCsv(assetRows), 'text/csv;charset=utf-8')}
            onClearFilters={clearFilters}
          />

          <AgilityBlockers blockers={data.blockers} onSelect={(blocker: AgilityBlocker) => setSelection({ kind: 'blocker', blocker })} />

          <ResponsibilityMatrix
            rows={responsibilityRows}
            controlDomain={filters.controlDomain}
            onFilterDomain={(domain) => patchFilters({ controlDomain: domain })}
            onExport={() => downloadTextFile(`qguard-responsibility-${new Date().toISOString().slice(0, 10)}.csv`, responsibilityToCsv(responsibilityRows), 'text/csv;charset=utf-8')}
          />

          {/* Change test entry point — the sandbox hand-off */}
          <Panel className="flex flex-wrap items-center justify-between gap-3 p-4">
            <div className="flex items-center gap-3">
              <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-500/10 text-cyan-300">
                <Beaker className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <div className="text-[12px] font-black text-white">Test a cryptographic change before you make it</div>
                <div className="text-[10.5px] text-white/45">
                  Project the blast radius from your own evidence, then hand the change to the Migration Sandbox digital twin — this page never simulates locally.
                </div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => openChangeTest(null)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2.5 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25"
            >
              <Beaker className="h-3.5 w-3.5" /> Test Crypto Change
            </button>
          </Panel>

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <RuntimeAgility events={data.runtimeEvents} live={live} onInvestigate={(event: RuntimeCryptoEvent) => setSelection({ kind: 'event', event })} />
            <PolicyPanel policy={data.policy} />
          </div>

          <ChangeTrackingPanel tracking={data.changeTracking} />

          <AssessmentHistory history={data.history} />

          <SophiaRecommendations
            recommendations={data.recommendations}
            onAsk={ask}
            onAct={(rec) => navigate(rec.route)}
          />

          <SourceHealth
            sources={data.sources.map((s) => ({ label: s.label, state: s.state, detail: s.detail }))}
            note={<>A source marked “could not be read” withholds every figure computed from it; a capped source read only its most recent rows.</>}
          />

          <footer className="flex flex-col gap-1.5 border-t border-white/8 pt-3 text-[10px] font-mono uppercase tracking-wider text-white/25 md:flex-row md:items-center md:justify-between">
            <span>Evidence coverage {data.evidenceCoverage}% · {data.confidence} confidence · {data.evidence.sources.length} source(s)</span>
            <span>Last assessment {relativeTime(data.lastAssessmentAt)} · snapshot {relativeTime(data.generatedAt)}</span>
          </footer>
        </>
      )}

      {/* ---- Overlays ---------------------------------------------------- */}
      <AgilityDrawer selection={selection} onClose={() => setSelection(null)} onAsk={ask} onSimulate={openChangeTest} />
      {data && <ScoreExplainer intel={data} open={explainerOpen} onClose={() => setExplainerOpen(false)} />}
      <ChangeTestPanel
        open={changeTestOpen}
        assetId={changeTestAsset}
        assets={data?.assets ?? []}
        token={token}
        onClose={() => setChangeTestOpen(false)}
        onAsk={ask}
      />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
    </div>
  );
}

function HeaderButton({
  onClick, icon: Icon, title, children,
}: {
  onClick: () => void;
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-label={title}
      className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:border-cyan-400/40 hover:text-cyan-300"
    >
      <Icon className="h-3.5 w-3.5" />
      {children}
    </button>
  );
}
