'use client';

import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType, type ReactNode } from 'react';
import { Workflow, RefreshCw, Command as CommandIcon, Maximize2, Minimize2, Play, Download } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/auth-context';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';
import { useMigrationWorkflow } from '@/hooks/use-migration-workflow';
import { useMigrationOrchestrator } from '@/hooks/use-migration-orchestrator';
import {
  buildWorkflows, buildAutomationKpis, buildCommandCenter, buildPipeline, buildDag, buildCab,
  buildKanban, buildMarketplace, buildScheduler, buildPolicies, buildAnalytics, buildComplianceMap,
  buildEventStream, buildDigitalTwin, buildAuditTrail, hasAnyEvidence, relativeTime, downloadTextFile,
  type OpsInputs, type KanbanColumnId,
} from './_orch-lib';
import {
  ExecAutomationSummary, CommandCenterRibbon, PipelinePanel, WorkflowConsole, CabApprovalCenter,
  WorkflowQueue, ExecutionDag, OrchestratorTelemetry, AutomationAnalytics, KanbanBoard,
  EventStreamPanel, MarketplacePanel, SchedulerPanel, PoliciesPanel, ComplianceMapPanel,
  DigitalTwinPanel, AuditTrailPanel, AiRecommendationsPanel, type OpsRecommendation,
} from './_orch-sections';
import { WorkflowDrawer, CommandPalette, type OrchSelection, type Command } from './_orch-drawer';

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
        if (active) setRecs(list.map((r) => ({
          id: String(r.id), priority: Number(r.priority ?? 3), category: String(r.category || 'automation'),
          title: String(r.title || 'Recommendation'), description: String(r.description || ''),
          action: String(r.action || ''), estimatedEffort: String(r.estimatedEffort || '—'),
          assetId: r.assetId ?? null, route: recRoute(r),
        })));
      } catch { /* auxiliary */ } finally { if (active) setLoading(false); }
    })();
    return () => { active = false; };
  }, [token]);
  return { recs, loading };
}

export default function PqcOrchestration() {
  const { data: scanner, loading, error, connected, refresh } = useScannerIntelligence();
  const { workflow, refresh: refreshWorkflow } = useMigrationWorkflow();
  const { data: orch, sseConnected, refresh: refreshOrchestrator } = useMigrationOrchestrator(true);
  const { recs, loading: recsLoading } = useAiRecommendations();

  const [selection, setSelection] = useState<OrchSelection | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [kanbanMoves, setKanbanMoves] = useState<Map<string, KanbanColumnId>>(new Map());
  const [policyOff, setPolicyOff] = useState<Set<string>>(new Set());
  const [isFullscreen, setIsFullscreen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  const input: OpsInputs = useMemo(() => ({ scanner, workflow, orch }), [scanner, workflow, orch]);

  const baseWorkflows = useMemo(() => buildWorkflows(input), [input]);
  const workflows = useMemo(
    () => (kanbanMoves.size === 0 ? baseWorkflows : baseWorkflows.map((w) => (kanbanMoves.has(w.id) ? { ...w, kanban: kanbanMoves.get(w.id)! } : w))),
    [baseWorkflows, kanbanMoves],
  );

  const kpis = useMemo(() => buildAutomationKpis(input, workflows), [input, workflows]);
  const command = useMemo(() => buildCommandCenter(input, workflows), [input, workflows]);
  const pipeline = useMemo(() => buildPipeline(input), [input]);
  const dag = useMemo(() => buildDag(input, pipeline), [input, pipeline]);
  const twin = useMemo(() => buildDigitalTwin(input), [input]);
  const cab = useMemo(() => buildCab(input, workflows), [input, workflows]);
  const kanban = useMemo(() => buildKanban(workflows), [workflows]);
  const marketplace = useMemo(() => buildMarketplace(input), [input]);
  const scheduler = useMemo(() => buildScheduler(input), [input]);
  const policies = useMemo(() => buildPolicies(input).map((p) => (policyOff.has(p.id) ? { ...p, enabled: false } : p)), [input, policyOff]);
  const analytics = useMemo(() => buildAnalytics(input), [input]);
  const events = useMemo(() => buildEventStream(input), [input]);
  const audit = useMemo(() => buildAuditTrail(input), [input]);
  const compliance = useMemo(() => buildComplianceMap(input), [input]);
  const runningWorkflow = useMemo(() => workflows.find((w) => w.kanban === 'running') ?? workflows[0] ?? null, [workflows]);

  const live = connected || sseConnected;
  const hasEvidence = hasAnyEvidence(input);

  const selectWorkflow = useCallback((id: string) => { const w = workflows.find((x) => x.id === id); if (w) setSelection({ kind: 'workflow', workflow: w }); }, [workflows]);
  const selectTemplate = useCallback((id: string) => { const t = marketplace.find((x) => x.id === id); if (t) setSelection({ kind: 'template', template: t }); }, [marketplace]);
  const selectNode = useCallback((id: string) => { const n = dag.nodes.find((x) => x.id === id); if (n) setSelection({ kind: 'node', node: n }); }, [dag.nodes]);
  const explainRec = useCallback((rec: OpsRecommendation) => setSelection({ kind: 'rec', rec }), []);
  const dismissRec = useCallback((id: string) => setDismissed((s) => new Set(s).add(id)), []);
  const moveKanban = useCallback((id: string, col: KanbanColumnId) => setKanbanMoves((m) => new Map(m).set(id, col)), []);
  const togglePolicy = useCallback((id: string) => setPolicyOff((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; }), []);

  const refreshAll = useCallback(() => { refresh(); refreshWorkflow(); refreshOrchestrator(); }, [refresh, refreshWorkflow, refreshOrchestrator]);
  const exportSnapshot = useCallback(() => {
    const payload = { generatedAt: new Date().toISOString(), kpis, command, pipeline, workflows, kanban: kanban.map((c) => ({ id: c.id, count: c.workflows.length })), analytics };
    downloadTextFile(`qguard-pqc-orchestration-${Date.now()}.json`, JSON.stringify(payload, null, 2), 'application/json;charset=utf-8');
  }, [kpis, command, pipeline, workflows, kanban, analytics]);

  const toggleFullscreen = useCallback(() => {
    const el = rootRef.current; if (!el) return;
    if (!document.fullscreenElement) el.requestFullscreen?.().catch(() => {});
    else document.exitFullscreen?.().catch(() => {});
  }, []);
  useEffect(() => {
    const handler = () => setIsFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPaletteOpen((o) => !o); } };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const drill = useCallback((route: string) => {
    if (route.startsWith('#')) document.getElementById(route.slice(1))?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    else window.location.href = route;
  }, []);

  const commands: Command[] = useMemo(() => {
    const jumps: Array<[string, string]> = [
      ['sec-pipeline', 'Jump: Orchestration Pipeline'], ['sec-console', 'Jump: Command Console'],
      ['sec-twin', 'Jump: Digital Twin'], ['sec-cab', 'Jump: CAB Approval'], ['sec-queue', 'Jump: Workflow Queue'],
      ['sec-dag', 'Jump: Execution DAG'], ['sec-telemetry', 'Jump: Live Telemetry'], ['sec-analytics', 'Jump: Analytics'],
      ['sec-kanban', 'Jump: Task Board'], ['sec-events', 'Jump: Event Stream'], ['sec-marketplace', 'Jump: Marketplace'],
      ['sec-scheduler', 'Jump: Scheduler'], ['sec-policies', 'Jump: Policies'], ['sec-ai', 'Jump: AI Recommendations'],
    ];
    const navs: Array<[string, string]> = [
      ['/dashboard/live-migration', 'Open: Live Migration Ops'], ['/dashboard/migration-timeline', 'Open: Migration Timeline'],
      ['/dashboard/migration-sandbox', 'Open: Migration Sandbox'], ['/dashboard/migration-planner', 'Open: Migration Planner'],
    ];
    return [
      { id: 'refresh', label: 'Refresh all evidence', hint: 'sync', run: refreshAll },
      { id: 'export', label: 'Export orchestration snapshot', hint: 'JSON', run: exportSnapshot },
      { id: 'fullscreen', label: 'Toggle full-screen', hint: 'view', run: toggleFullscreen },
      ...jumps.map(([id, label]) => ({ id, label, hint: 'section', run: () => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }) })),
      ...navs.map(([href, label]) => ({ id: href, label, hint: 'module', run: () => { window.location.href = href; } })),
    ];
  }, [refreshAll, exportSnapshot, toggleFullscreen]);

  return (
    <div ref={rootRef} className="orch-shell min-h-screen space-y-5 p-4 lg:p-6">
      <style>{`
        .orch-shell { background: var(--qg-dashboard-bg, #0a1020); }
        .qg-theme-light .orch-shell [class*="bg-black/"] { background-color: rgba(255,255,255,0.55) !important; }
        .qg-theme-light .orch-shell [class*="bg-[#0b1120]"],
        .qg-theme-light .orch-shell [class*="bg-[#070b18]"],
        .qg-theme-light .orch-shell [class*="bg-[#0a0f1e]"] { background-color: rgba(255,255,255,0.86) !important; }
        .qg-theme-light .orch-shell [class*="border-white/"] { border-color: rgba(9,13,22,0.10) !important; }
        .qg-theme-light .orch-shell .text-white { color: var(--qg-dashboard-text) !important; }
        .qg-theme-light .orch-shell [class*="text-white/"] { color: var(--qg-dashboard-text-soft) !important; }
        .qg-theme-light .orch-shell .text-cyan-200,
        .qg-theme-light .orch-shell .text-cyan-300,
        .qg-theme-light .orch-shell .text-cyan-400 { color: #0e7490 !important; }
        .qg-theme-light .orch-shell .text-emerald-300,
        .qg-theme-light .orch-shell .text-emerald-400 { color: #047857 !important; }
        .qg-theme-light .orch-shell .text-amber-300,
        .qg-theme-light .orch-shell .text-amber-400 { color: #b45309 !important; }
        .qg-theme-light .orch-shell .text-red-300,
        .qg-theme-light .orch-shell .text-red-400 { color: #dc2626 !important; }
        .qg-theme-light .orch-shell .text-blue-300 { color: #1d4ed8 !important; }
        .qg-theme-light .orch-shell .text-violet-300 { color: #7c3aed !important; }
        .qg-theme-light .orch-shell input::placeholder { color: rgba(9,13,22,0.35) !important; }
      `}</style>

      <header className="flex flex-col gap-4 border-b border-white/10 pb-4 xl:flex-row xl:items-end xl:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.2)]">
            <Workflow className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
              PQC <span className="text-cyan-300">Automation Command Center</span>
            </h1>
            <p className="mt-1.5 text-[12px] font-medium text-white/45">Enterprise PQC Orchestration · Plan → Approve → Execute → Validate → Audit · Evidence-Driven</p>
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
            <Play className="h-3.5 w-3.5" /> Run Automation
          </a>
        </div>
      </header>

      {error && <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm font-semibold text-red-300">{error}</div>}

      {loading && !hasEvidence ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
          {Array.from({ length: 14 }).map((_, i) => <div key={i} className="h-24 animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />)}
        </div>
      ) : (
        <>
          <div id="sec-summary"><ExecAutomationSummary kpis={kpis} onDrill={drill} /></div>
          <CommandCenterRibbon fields={command} />
          <div id="sec-pipeline"><PipelinePanel stages={pipeline} /></div>
          <div id="sec-console"><WorkflowConsole workflow={runningWorkflow} orch={orch} /></div>
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
            <div id="sec-twin"><DigitalTwinPanel twin={twin} /></div>
            <div id="sec-cab"><CabApprovalCenter cab={cab} /></div>
          </div>
          <div id="sec-queue"><WorkflowQueue workflows={workflows} onSelect={selectWorkflow} /></div>
          <div id="sec-dag"><ExecutionDag nodes={dag.nodes} edges={dag.edges} onSelectNode={selectNode} /></div>
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
            <div id="sec-telemetry"><OrchestratorTelemetry orch={orch} live={sseConnected} /></div>
            <div id="sec-analytics"><AutomationAnalytics series={analytics} /></div>
          </div>
          <div id="sec-kanban"><KanbanBoard columns={kanban} onMove={moveKanban} onSelect={selectWorkflow} /></div>
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
            <div id="sec-events"><EventStreamPanel events={events} /></div>
            <div id="sec-scheduler"><SchedulerPanel entries={scheduler} /></div>
          </div>
          <div id="sec-marketplace"><MarketplacePanel templates={marketplace} onSelect={selectTemplate} /></div>
          <div id="sec-policies"><PoliciesPanel policies={policies} onToggle={togglePolicy} /></div>
          <ComplianceMapPanel rows={compliance} />
          <AuditTrailPanel rows={audit} />
          <div id="sec-ai"><AiRecommendationsPanel recs={recs} loading={recsLoading} dismissed={dismissed} onDismiss={dismissRec} onExplain={explainRec} /></div>
        </>
      )}

      <WorkflowDrawer selection={selection} onClose={() => setSelection(null)} />
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
