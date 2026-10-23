'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Building2,
  Download,
  Filter,
  Link2,
  Radar,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { NodePosture } from '@/types/exposure-graph';
import { computeBlastRadius, computeMigrationImpact } from '@/lib/exposure-graph-intel';
import { useExposureGraph } from '@/hooks/use-exposure-graph';
import {
  Badge,
  EMPTY_SNAPSHOT,
  EmptyState,
  HeaderButton,
  MetricCard,
  Panel,
  QuantumReadinessShell,
  integerFmt,
  BLUE,
  CYAN,
  EMERALD,
  ORANGE,
  RED,
  VIOLET,
} from '../_shared';
import { POSTURE_COLOR, POSTURE_LABEL } from './_common';
import { GraphCanvas, GROUP_MODES, type GroupMode } from './_graph';
import { EdgeRail, NodeRail, RailSummary } from './_panels';
import { AdvisorSection, MigrationOrderSection, RiskPrioritizationSection, ThirdPartySection } from './_intelligence';

type PostureFilter = 'all' | NodePosture;

type Selection = { kind: 'node'; id: string } | { kind: 'edge'; id: string } | null;

export default function ExposureGraphPage() {
  const { data, state, error, sseConnected, lastVerifiedAt, refresh, downloadJson } = useExposureGraph();
  const [postureFilter, setPostureFilter] = useState<PostureFilter>('all');
  const [tierFilter, setTierFilter] = useState<string>('all');
  const [showExternal, setShowExternal] = useState(true);
  const [groupBy, setGroupBy] = useState<GroupMode>('posture');
  const [searchTerm, setSearchTerm] = useState('');
  const [searchOpen, setSearchOpen] = useState(false);
  const [selection, setSelection] = useState<Selection>(null);
  const [focus, setFocus] = useState<{ id: string; n: number } | null>(null);
  const [fullscreen, setFullscreen] = useState(false);

  const { nodes, edges } = data.graph;
  const { summary } = data;

  /* ---- Filtering (search highlights, filters hide) ----------------- */
  const visibleNodes = useMemo(
    () =>
      nodes.filter((n) => {
        if (postureFilter !== 'all' && n.posture !== postureFilter) return false;
        if (!showExternal && n.kind === 'external') return false;
        if (tierFilter !== 'all' && n.tierLabel !== tierFilter) return false;
        return true;
      }),
    [nodes, postureFilter, showExternal, tierFilter],
  );
  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);
  const visibleEdges = useMemo(() => edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target)), [edges, visibleIds]);

  const tierOptions = useMemo(() => {
    const labels = new Map<number, string>();
    for (const n of nodes) labels.set(n.migrationTier, n.tierLabel);
    return [...labels.entries()].sort((a, b) => a[0] - b[0]).map(([, label]) => label);
  }, [nodes]);

  /* ---- Search ------------------------------------------------------- */
  const searchMatches = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) return null;
    return visibleNodes.filter((n) => `${n.label} ${n.type} ${n.category} ${n.environment} ${n.vendor || ''}`.toLowerCase().includes(term));
  }, [visibleNodes, searchTerm]);
  const highlightIds = useMemo(() => (searchMatches ? new Set(searchMatches.map((n) => n.id)) : null), [searchMatches]);

  /* ---- Selection + analytics (always on the FULL graph) ------------- */
  const selectedNode = useMemo(
    () => (selection?.kind === 'node' ? nodes.find((n) => n.id === selection.id) || null : null),
    [selection, nodes],
  );
  const selectedEdge = useMemo(
    () => (selection?.kind === 'edge' ? edges.find((e) => e.id === selection.id) || null : null),
    [selection, edges],
  );
  const blast = useMemo(() => (selectedNode ? computeBlastRadius(nodes, edges, selectedNode.id) : null), [selectedNode, nodes, edges]);
  const impact = useMemo(
    () => (selectedNode ? computeMigrationImpact(nodes, edges, selectedNode.id, blast || undefined) : null),
    [selectedNode, nodes, edges, blast],
  );

  const selectNode = useCallback((id: string | null) => {
    setSelection(id ? { kind: 'node', id } : null);
  }, []);
  const selectEdge = useCallback((id: string | null) => {
    setSelection(id ? { kind: 'edge', id } : null);
  }, []);
  /** Select from tables/search — also centers the graph on the node. */
  const selectAndFocus = useCallback((id: string) => {
    setSelection({ kind: 'node', id });
    setFocus((prev) => ({ id, n: (prev?.n || 0) + 1 }));
  }, []);

  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setFullscreen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [fullscreen]);

  /* ---- Shell-compatible snapshot shim -------------------------------- */
  const shellSnapshot = useMemo(
    () => ({ ...EMPTY_SNAPSHOT, hasData: data.hasData, generatedAt: data.generatedAt, lastAssessmentAt: data.lastAssessmentAt }),
    [data.hasData, data.generatedAt, data.lastAssessmentAt],
  );

  const postureChips: Array<{ key: PostureFilter; label: string; color: string; count: number }> = useMemo(() => {
    const count = (p: NodePosture) => nodes.filter((n) => n.posture === p).length;
    return [
      { key: 'all', label: `All (${nodes.length})`, color: BLUE, count: nodes.length },
      { key: 'vulnerable', label: `Vulnerable (${count('vulnerable')})`, color: POSTURE_COLOR.vulnerable, count: count('vulnerable') },
      { key: 'hybrid', label: `Hybrid (${count('hybrid')})`, color: POSTURE_COLOR.hybrid, count: count('hybrid') },
      { key: 'migrating', label: `In Progress (${count('migrating')})`, color: POSTURE_COLOR.migrating, count: count('migrating') },
      { key: 'pqc', label: `PQC-Ready (${count('pqc')})`, color: POSTURE_COLOR.pqc, count: count('pqc') },
      { key: 'unknown', label: `Unknown (${count('unknown')})`, color: POSTURE_COLOR.unknown, count: count('unknown') },
    ];
  }, [nodes]);

  const rail = selectedNode ? (
    <NodeRail node={selectedNode} nodes={nodes} blast={blast} impact={impact} onSelectNode={selectAndFocus} onClose={() => setSelection(null)} />
  ) : selectedEdge ? (
    <EdgeRail edge={selectedEdge} nodes={nodes} onSelectNode={selectAndFocus} onClose={() => setSelection(null)} />
  ) : (
    <RailSummary data={data} onSelectNode={selectAndFocus} />
  );

  const canvas = (
    <GraphCanvas
      nodes={visibleNodes}
      edges={visibleEdges}
      groupBy={groupBy}
      selectedNodeId={selectedNode?.id || null}
      selectedEdgeId={selectedEdge?.id || null}
      blast={blast}
      highlightIds={highlightIds}
      focus={focus}
      fullscreen={fullscreen}
      onSelectNode={selectNode}
      onSelectEdge={selectEdge}
      onToggleFullscreen={() => setFullscreen((f) => !f)}
    />
  );

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <Filter className="h-4 w-4 text-white/40" />
        {postureChips.map((chip) => (
          <button
            key={chip.key}
            type="button"
            onClick={() => setPostureFilter(chip.key)}
            className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[10.5px] font-bold transition ${
              postureFilter === chip.key ? 'border-blue-400/50 bg-blue-500/15 text-blue-100' : 'border-white/10 bg-black/20 text-white/60 hover:border-blue-400/35'
            }`}
          >
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: chip.color }} />
            {chip.label}
          </button>
        ))}
      </div>

      <div className="ml-auto flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-1.5 text-[10.5px] font-bold text-white/55">
          Group by
          <select
            value={groupBy}
            onChange={(event) => setGroupBy(event.target.value as GroupMode)}
            className="rounded-md border border-white/10 bg-[#07101D] px-2 py-1.5 text-[10.5px] font-bold text-white/80 outline-none transition focus:border-blue-400/50"
          >
            {GROUP_MODES.map((mode) => (
              <option key={mode.key} value={mode.key}>{mode.label}</option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-[10.5px] font-bold text-white/55">
          Layer
          <select
            value={tierFilter}
            onChange={(event) => setTierFilter(event.target.value)}
            className="max-w-[190px] rounded-md border border-white/10 bg-[#07101D] px-2 py-1.5 text-[10.5px] font-bold text-white/80 outline-none transition focus:border-blue-400/50"
          >
            <option value="all">All layers</option>
            {tierOptions.map((label) => (
              <option key={label} value={label}>{label}</option>
            ))}
          </select>
        </label>
        <button
          type="button"
          onClick={() => setShowExternal((v) => !v)}
          className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[10.5px] font-bold transition ${
            showExternal ? 'border-violet-400/40 bg-violet-500/10 text-violet-200' : 'border-white/10 bg-black/20 text-white/45 hover:border-violet-400/35'
          }`}
        >
          <Building2 className="h-3.5 w-3.5" /> Third-Party
        </button>

        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/35" />
          <input
            value={searchTerm}
            onChange={(event) => { setSearchTerm(event.target.value); setSearchOpen(true); }}
            onFocus={() => setSearchOpen(true)}
            onBlur={() => setTimeout(() => setSearchOpen(false), 150)}
            placeholder="Search assets, vendors, types…"
            className="w-56 rounded-md border border-white/10 bg-[#07101D] py-1.5 pl-8 pr-2.5 text-[11px] text-white/85 outline-none transition placeholder:text-white/30 focus:border-blue-400/50"
          />
          {searchOpen && searchMatches && searchMatches.length ? (
            <div className="absolute right-0 top-full z-30 mt-1 w-72 overflow-hidden rounded-md border border-blue-400/25 bg-[#0A1728]/97 shadow-[0_16px_44px_rgba(0,0,0,0.6)] backdrop-blur">
              {searchMatches.slice(0, 6).map((node) => (
                <button
                  key={node.id}
                  type="button"
                  onMouseDown={() => { selectAndFocus(node.id); setSearchOpen(false); }}
                  className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-[11px] transition hover:bg-blue-500/10"
                >
                  <span className="inline-flex min-w-0 items-center gap-1.5 text-white/80">
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: POSTURE_COLOR[node.posture] }} />
                    <span className="truncate">{node.label}</span>
                  </span>
                  <span className="shrink-0 text-[9.5px] uppercase tracking-wide text-white/35">{POSTURE_LABEL[node.posture]}</span>
                </button>
              ))}
              {searchMatches.length > 6 ? (
                <div className="border-t border-white/8 px-3 py-1.5 text-[10px] text-white/35">
                  {searchMatches.length - 6} more match{searchMatches.length - 6 === 1 ? '' : 'es'} highlighted in the graph — refine your search to list them.
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );

  return (
    <QuantumReadinessShell
      title="Quantum Exposure Graph™"
      subtitle="Enterprise Cryptographic Dependency Graph, Trust Relationship Map and Migration Impact Analysis Engine. Explore how assets, certificates, identities and third-party services interconnect — then simulate PQC migration safely."
      badge={<Badge color={CYAN}>{integerFmt(nodes.length)} nodes · {integerFmt(edges.length)} trust links</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={shellSnapshot}
      error={error}
      lastVerifiedAt={lastVerifiedAt}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>
          <HeaderButton icon={Download} onClick={() => downloadJson('quantum-exposure-graph', data)}>Export Intelligence</HeaderButton>
        </>
      }
    >
      {/* Enterprise KPI band */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        <MetricCard label="Total Assets" value={integerFmt(summary.totalAssets)} detail={`${integerFmt(summary.internetFacingAssets)} internet-facing`} color={BLUE} icon={Server} />
        <MetricCard
          label="Quantum Vulnerable"
          value={integerFmt(summary.quantumVulnerable)}
          detail={summary.totalAssets ? `${Math.round((summary.quantumVulnerable / Math.max(1, summary.totalAssets)) * 100)}% of estate` : 'No assets yet'}
          color={RED}
          icon={ShieldAlert}
          ring={summary.totalAssets ? Math.round((summary.quantumVulnerable / Math.max(1, summary.totalAssets)) * 100) : 0}
        />
        <MetricCard
          label="PQC Ready"
          value={integerFmt(summary.pqcReadyAssets)}
          detail={`${integerFmt(summary.hybridAssets)} hybrid · ${integerFmt(summary.migrationInProgress)} in progress`}
          color={EMERALD}
          icon={ShieldCheck}
          ring={summary.totalAssets ? Math.round((summary.pqcReadyAssets / Math.max(1, summary.totalAssets)) * 100) : 0}
        />
        <MetricCard label="Third-Party Dependencies" value={integerFmt(summary.thirdPartyDependencies)} detail={`${integerFmt(summary.certificateChains)} external certificate chain(s)`} color={VIOLET} icon={Building2} />
        <MetricCard label="Critical Trust Links" value={integerFmt(summary.criticalTrustRelationships)} detail={`of ${integerFmt(summary.trustRelationships)} trust relationships`} color={ORANGE} icon={Link2} />
        <MetricCard label="Migration Readiness" value={`${integerFmt(summary.migrationReadinessScore)}`} suffix="/100" detail={`Quantum readiness ${integerFmt(summary.quantumReadinessScore)}/100`} color={CYAN} icon={Radar} ring={summary.migrationReadinessScore} />
      </section>

      {/* Secondary metric strip */}
      <Panel className="px-4 py-3">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[11px]">
          {(
            [
              { label: 'High-Risk Assets', value: summary.highRiskAssets, color: RED },
              { label: 'Legacy Crypto Assets', value: summary.legacyCryptoAssets, color: ORANGE },
              { label: 'Unknown Posture', value: summary.unknownPosture, color: POSTURE_COLOR.unknown },
              { label: 'PKI Objects', value: summary.pkiObjects, color: VIOLET },
              { label: 'Certificate Chains', value: summary.certificateChains, color: VIOLET },
              { label: 'Max Blast Radius', value: summary.maxBlastRadius, color: CYAN },
              { label: 'Quantum Risk', value: summary.quantumRiskScore, color: summary.quantumRiskScore >= 60 ? RED : ORANGE, suffix: '/100' },
            ] as Array<{ label: string; value: number; color: string; suffix?: string }>
          ).map((stat) => (
            <span key={stat.label} className="inline-flex items-baseline gap-1.5">
              <span className="font-mono text-sm font-semibold" style={{ color: stat.color }}>
                {integerFmt(stat.value)}
                {stat.suffix || ''}
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wide text-white/40">{stat.label}</span>
            </span>
          ))}
        </div>
      </Panel>

      {/* Graph workspace */}
      <Panel className="p-4">{toolbar}</Panel>

      {!fullscreen ? (
        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-2 xl:col-span-8">
            {visibleNodes.length ? (
              canvas
            ) : (
              <div className="grid h-[560px] place-items-center">
                <EmptyState
                  label={data.hasData ? 'No assets match the current filters.' : 'No assets in the exposure graph yet.'}
                  hint={data.hasData ? 'Adjust the posture, layer or third-party filters.' : 'Run a PQC discovery scan or register assets and relationships to build the dependency graph.'}
                />
              </div>
            )}
          </Panel>
          <Panel className="max-h-[672px] overflow-y-auto p-5 xl:col-span-4">{rail}</Panel>
        </section>
      ) : null}

      {/* Fullscreen overlay */}
      {fullscreen ? (
        <div className="fixed inset-0 z-[70] flex flex-col gap-3 bg-[#030711] p-4">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <h2 className="text-sm font-bold text-white">Quantum Exposure Graph™ — Full Screen</h2>
              <Badge color={CYAN}>{integerFmt(visibleNodes.length)} nodes · {integerFmt(visibleEdges.length)} links</Badge>
            </div>
            <span className="text-[10px] text-white/35">Press Esc to exit</span>
          </div>
          <Panel className="p-4">{toolbar}</Panel>
          <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-12">
            <Panel className="min-h-0 p-2 xl:col-span-9">{canvas}</Panel>
            <Panel className="min-h-0 overflow-y-auto p-5 xl:col-span-3">{rail}</Panel>
          </div>
        </div>
      ) : null}

      {/* Migration Dependency Intelligence™ */}
      <MigrationOrderSection data={data} onSelectNode={selectAndFocus} />

      {/* AI Migration Advisor™ */}
      <AdvisorSection data={data} />

      {/* Third-party + prioritisation */}
      <ThirdPartySection data={data} onSelectNode={selectAndFocus} />
      <RiskPrioritizationSection data={data} onSelectNode={selectAndFocus} />

      {/* Evidence provenance */}
      {data.evidence.note ? (
        <Panel className="px-4 py-3">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[10.5px] text-white/40">
            <span className="font-black uppercase tracking-wide text-white/50">Evidence:</span>
            {data.evidence.sources.map((source) => (
              <span key={source} className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5">{source}</span>
            ))}
            <span className="basis-full text-white/35">{data.evidence.note}</span>
          </div>
        </Panel>
      ) : null}
    </QuantumReadinessShell>
  );
}
