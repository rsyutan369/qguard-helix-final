'use client';

import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType, type ReactNode } from 'react';
import {
  Rocket, RefreshCw, Command as CommandIcon, Maximize2, Minimize2, Play, Download,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/auth-context';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';
import { useMigrationWorkflow } from '@/hooks/use-migration-workflow';
import { useMigrationOrchestrator } from '@/hooks/use-migration-orchestrator';
import {
  buildExecutiveBanner, buildKpis, buildWaves, activeWave, buildPhaseGates, buildTimelineCards,
  buildDigitalTwin, buildLiveJobs, buildHealth, buildRiskBurndown, buildAssetRows,
  buildDependencyGraph, buildActivityFeed, buildAuditTrail, hasAnyEvidence, relativeTime,
  downloadTextFile, type OpsInputs,
} from './_ops-lib';
import {
  ExecutiveBanner, KpiHeader, WaveOverview, PhaseGates, TimelineSection, DigitalTwinPanel,
  LiveTelemetry, AiRecommendationsPanel, HealthDashboard, RiskBurndownPanel, AssetTable,
  DependencyGraphPanel, ActivityFeed, AuditTrailPanel, ComplianceStrip, type OpsRecommendation,
} from './_ops-sections';
import { DetailsDrawer, CommandPalette, type DrawerSelection, type Command } from './_ops-drawer';

/* -- AI recommendations: reuse the same real endpoint as Executive -- */

function recRoute(r: { action?: string; category?: string; assetId?: string | null }): string {
  const a = String(r.action || '').toLowerCase();
  const c = String(r.category || '').toLowerCase();
  if (a.includes('scan') || c.includes('discover')) return '/dashboard/scanner';
  if (a.includes('migrat') || c.includes('migration')) return '/dashboard/live-migration';
  if (a.includes('cert') || c.includes('certificate')) return '/dashboard/certificate-telemetry';
  if (a.includes('tls') || a.includes('protocol') || c.includes('protocol')) return '/dashboard/encryption-monitoring';
  if (r.assetId) return `/dashboard/assets?asset=${encodeURIComponent(r.assetId)}`;
  return '/dashboard/migration-planner';
}

function useAiRecommendations() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [recs, setRecs] = useState<OpsRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    if (!token) { setLoading(false); return; }
    let active = true;
    (async () => {
      try {
        const res = await fetch('/api/v1/dashboard/recommendations', { headers: { Authorization: `Bearer ${token}` } });
        const json = await res.json().catch(() => ({}));
        const list = (json?.data?.recommendations || []) as Array<Record<string, any>>;
        if (active) {
          setRecs(list.map((r) => ({
            id: String(r.id), priority: Number(r.priority ?? 3), category: String(r.category || 'migration'),
            title: String(r.title || 'Recommendation'), description: String(r.description || ''),
            action: String(r.action || ''), estimatedEffort: String(r.estimatedEffort || '—'),
            assetId: r.assetId ?? null, route: recRoute(r),
          })));
        }
      } catch { /* auxiliary — stays empty on error */ } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; };
  }, [token]);
  return { recs, loading };
}

/* ------------------------------------------------------------------ */

export default function MigrationTimeline() {
  const { data: scanner, loading, error, connected, refresh } = useScannerIntelligence();
  const { workflow, refresh: refreshWorkflow } = useMigrationWorkflow();
  const { data: orch, sseConnected, refresh: refreshOrchestrator } = useMigrationOrchestrator(true);
  const { recs, loading: recsLoading } = useAiRecommendations();

  const [selection, setSelection] = useState<DrawerSelection | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [isFullscreen, setIsFullscreen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  const input: OpsInputs = useMemo(() => ({ scanner, workflow, orch }), [scanner, workflow, orch]);

  const banner = useMemo(() => buildExecutiveBanner(input), [input]);
  const kpis = useMemo(() => buildKpis(input), [input]);
  const waves = useMemo(() => buildWaves(scanner), [scanner]);
  const activeWaveObj = useMemo(() => activeWave(waves), [waves]);
  const gates = useMemo(() => buildPhaseGates(input), [input]);
  const timelineCards = useMemo(() => buildTimelineCards(input), [input]);
  const twin = useMemo(() => buildDigitalTwin(input), [input]);
  const liveJobs = useMemo(() => buildLiveJobs(input), [input]);
  const health = useMemo(() => buildHealth(input), [input]);
  const riskBurndown = useMemo(() => buildRiskBurndown(input), [input]);
  const assetRows = useMemo(() => buildAssetRows(input), [input]);
  const depGraph = useMemo(() => buildDependencyGraph(scanner), [scanner]);
  const activity = useMemo(() => buildActivityFeed(input), [input]);
  const audit = useMemo(() => buildAuditTrail(input), [input]);

  const live = connected || sseConnected;
  const hasEvidence = hasAnyEvidence(input);

  /* -- selection handlers -- */
  const selectTimeline = useCallback((id: string) => {
    const card = timelineCards.find((c) => c.id === id);
    if (card) setSelection({ kind: 'timeline', card });
  }, [timelineCards]);
  const selectAsset = useCallback((id: string) => {
    const row = assetRows.find((r) => r.id === id);
    if (row) setSelection({ kind: 'asset', row });
  }, [assetRows]);
  const selectJob = useCallback((id: string) => {
    const job = liveJobs.find((j) => j.id === id);
    if (job) setSelection({ kind: 'job', job });
  }, [liveJobs]);
  const selectNode = useCallback((id: string) => {
    const node = depGraph.nodes.find((n) => n.id === id);
    if (node) setSelection({ kind: 'node', node });
  }, [depGraph.nodes]);
  const explainRec = useCallback((rec: OpsRecommendation) => setSelection({ kind: 'rec', rec }), []);
  const dismissRec = useCallback((id: string) => setDismissed((s) => new Set(s).add(id)), []);

  const refreshAll = useCallback(() => { refresh(); refreshWorkflow(); refreshOrchestrator(); }, [refresh, refreshWorkflow, refreshOrchestrator]);

  const exportSnapshot = useCallback(() => {
    const payload = { generatedAt: new Date().toISOString(), banner, kpis, waves, gates, timelineCards, twin, health, riskBurndown, assets: assetRows.length };
    downloadTextFile(`qguard-migration-ops-${Date.now()}.json`, JSON.stringify(payload, null, 2), 'application/json;charset=utf-8');
  }, [banner, kpis, waves, gates, timelineCards, twin, health, riskBurndown, assetRows]);

  /* -- fullscreen -- */
  const toggleFullscreen = useCallback(() => {
    const el = rootRef.current;
    if (!el) return;
    if (!document.fullscreenElement) el.requestFullscreen?.().catch(() => {});
    else document.exitFullscreen?.().catch(() => {});
  }, []);
  useEffect(() => {
    const handler = () => setIsFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  /* -- Cmd/Ctrl+K palette -- */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPaletteOpen((o) => !o); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const scrollTo = useCallback((id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, []);

  const commands: Command[] = useMemo(() => {
    const jumps: Array<[string, string]> = [
      ['sec-waves', 'Jump: Migration Waves'], ['sec-gates', 'Jump: NIST Phase Gates'],
      ['sec-timeline', 'Jump: Migration Timeline'], ['sec-twin', 'Jump: Digital Twin'],
      ['sec-telemetry', 'Jump: Live Telemetry'], ['sec-ai', 'Jump: AI Recommendations'],
      ['sec-health', 'Jump: Migration Health'], ['sec-risk', 'Jump: Risk Burn-down'],
      ['sec-assets', 'Jump: Asset Table'], ['sec-deps', 'Jump: Dependency Graph'],
      ['sec-activity', 'Jump: Activity Feed'], ['sec-audit', 'Jump: Audit Trail'],
    ];
    const navs: Array<[string, string]> = [
      ['/dashboard/live-migration', 'Open: Live Migration Ops'],
      ['/dashboard/migration-planner', 'Open: Migration Planner'],
      ['/dashboard/migration-sandbox', 'Open: Migration Sandbox (Digital Twin)'],
      ['/dashboard/quantum-readiness', 'Open: Quantum Readiness'],
      ['/dashboard/compliance_dashboard', 'Open: Compliance'],
    ];
    return [
      { id: 'refresh', label: 'Refresh all evidence', hint: 'sync', run: refreshAll },
      { id: 'export', label: 'Export operations snapshot', hint: 'JSON', run: exportSnapshot },
      { id: 'fullscreen', label: 'Toggle full-screen command center', hint: 'view', run: toggleFullscreen },
      ...jumps.map(([id, label]) => ({ id, label, hint: 'section', run: () => scrollTo(id) })),
      ...navs.map(([href, label]) => ({ id: href, label, hint: 'module', run: () => { window.location.href = href; } })),
    ];
  }, [refreshAll, exportSnapshot, toggleFullscreen, scrollTo]);

  return (
    <div ref={rootRef} className="mig-ops-shell min-h-screen space-y-5 p-4 lg:p-6">
      {/* Theme-aware surface: dark navy in dark mode, near-white in light mode.
          Remaps the hard-coded dark utility surfaces/text used across the center
          so light mode is not a black canvas (mirrors the platform hndl-shell pattern). */}
      <style>{`
        .mig-ops-shell { background: var(--qg-dashboard-bg, #0a1020); }
        .qg-theme-light .mig-ops-shell [class*="bg-black/"] { background-color: rgba(255,255,255,0.55) !important; }
        .qg-theme-light .mig-ops-shell [class*="bg-[#0b1120]"],
        .qg-theme-light .mig-ops-shell [class*="bg-[#070b18]"],
        .qg-theme-light .mig-ops-shell [class*="bg-[#0a0f1e]"],
        .qg-theme-light .mig-ops-shell [class*="bg-[#070b16]"] { background-color: rgba(255,255,255,0.86) !important; }
        .qg-theme-light .mig-ops-shell [class*="border-white/"] { border-color: rgba(9,13,22,0.10) !important; }
        .qg-theme-light .mig-ops-shell .text-white { color: var(--qg-dashboard-text) !important; }
        .qg-theme-light .mig-ops-shell [class*="text-white/"] { color: var(--qg-dashboard-text-soft) !important; }
        .qg-theme-light .mig-ops-shell .text-cyan-200,
        .qg-theme-light .mig-ops-shell .text-cyan-300,
        .qg-theme-light .mig-ops-shell .text-cyan-400 { color: #0e7490 !important; }
        .qg-theme-light .mig-ops-shell .text-emerald-300,
        .qg-theme-light .mig-ops-shell .text-emerald-400 { color: #047857 !important; }
        .qg-theme-light .mig-ops-shell .text-amber-300,
        .qg-theme-light .mig-ops-shell .text-amber-400 { color: #b45309 !important; }
        .qg-theme-light .mig-ops-shell .text-red-300,
        .qg-theme-light .mig-ops-shell .text-red-400 { color: #dc2626 !important; }
        .qg-theme-light .mig-ops-shell .text-blue-300 { color: #1d4ed8 !important; }
        .qg-theme-light .mig-ops-shell .text-violet-300 { color: #7c3aed !important; }
        .qg-theme-light .mig-ops-shell input::placeholder { color: rgba(9,13,22,0.35) !important; }
      `}</style>
      {/* Header */}
      <header className="flex flex-col gap-4 border-b border-white/10 pb-4 xl:flex-row xl:items-end xl:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.2)]">
            <Rocket className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
              Migration <span className="text-cyan-300">Operations Center</span>
            </h1>
            <p className="mt-1.5 text-[12px] font-medium text-white/45">
              Enterprise PQC Migration Command Center · NIST SP 1800-38 · CNSA 2.0 · Evidence-Driven
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[10px] uppercase tracking-widest text-white/30">Synced {relativeTime(scanner.generatedAt)}</span>
          <span className={cn('flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[9px] font-black uppercase tracking-widest', live ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300' : 'border-amber-400/40 bg-amber-500/10 text-amber-300')}>
            <span className={cn('h-1.5 w-1.5 rounded-full', live ? 'animate-pulse bg-emerald-400' : 'bg-amber-300')} />
            {loading ? 'Syncing' : live ? 'Live' : 'Snapshot'}
          </span>
          <HeaderButton onClick={() => setPaletteOpen(true)} icon={CommandIcon} title="Command palette (Ctrl/Cmd+K)">⌘K</HeaderButton>
          <HeaderButton onClick={refreshAll} icon={RefreshCw} title="Refresh">Refresh</HeaderButton>
          <HeaderButton onClick={exportSnapshot} icon={Download} title="Export snapshot">Export</HeaderButton>
          <HeaderButton onClick={toggleFullscreen} icon={isFullscreen ? Minimize2 : Maximize2} title="Full screen">{isFullscreen ? 'Exit' : 'Full'}</HeaderButton>
          <a href="/dashboard/live-migration" className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25">
            <Play className="h-3.5 w-3.5" /> Start Migration
          </a>
        </div>
      </header>

      {error && <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm font-semibold text-red-300">{error}</div>}

      {loading && !hasEvidence ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {Array.from({ length: 15 }).map((_, i) => <div key={i} className="h-28 animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />)}
        </div>
      ) : (
        <>
          <div id="sec-banner"><ExecutiveBanner metrics={banner} /></div>
          <div id="sec-kpis"><KpiHeader kpis={kpis} /></div>
          <ComplianceStrip />
          <div id="sec-waves"><WaveOverview waves={waves} activeId={activeWaveObj?.id ?? null} /></div>
          <div id="sec-gates"><PhaseGates gates={gates} /></div>
          <div id="sec-timeline"><TimelineSection cards={timelineCards} onSelect={selectTimeline} /></div>
          <div id="sec-twin"><DigitalTwinPanel twin={twin} /></div>
          <div id="sec-telemetry"><LiveTelemetry jobs={liveJobs} live={sseConnected} onSelect={selectJob} /></div>
          <div id="sec-ai"><AiRecommendationsPanel recs={recs} loading={recsLoading} dismissed={dismissed} onDismiss={dismissRec} onExplain={explainRec} /></div>
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
            <div id="sec-health"><HealthDashboard metrics={health} score={scanner.summary.qScore} /></div>
            <div id="sec-risk"><RiskBurndownPanel data={riskBurndown} /></div>
          </div>
          <div id="sec-assets"><AssetTable rows={assetRows} onSelect={selectAsset} /></div>
          <div id="sec-deps"><DependencyGraphPanel graph={depGraph} onSelectNode={selectNode} /></div>
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
            <div id="sec-activity"><ActivityFeed events={activity} /></div>
            <div id="sec-audit"><AuditTrailPanel rows={audit} /></div>
          </div>
        </>
      )}

      <DetailsDrawer selection={selection} onClose={() => setSelection(null)} />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
    </div>
  );
}

function HeaderButton({ onClick, icon: Icon, title, children }: { onClick: () => void; icon: ComponentType<{ className?: string }>; title: string; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} title={title} className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:border-cyan-400/40 hover:text-cyan-300">
      <Icon className="h-3.5 w-3.5" />{children}
    </button>
  );
}
