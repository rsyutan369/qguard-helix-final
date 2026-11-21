'use client';

import { useCallback, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Building2, Download, Link2, Network, Radar, RefreshCw, Server, ShieldAlert, ShieldCheck } from 'lucide-react';
import { DefaultEdgeDetail, DetailSection, VendorTrustWorkflowCanvas } from '@/components/trust-workflow/VendorTrustWorkflowCanvas';
import { buildExposureWorkflowGraph, EXPOSURE_STATUS } from '@/lib/exposure-graph-workflow';
import { computeBlastRadius, computeMigrationImpact } from '@/lib/exposure-graph-intel';
import { useExposureGraph } from '@/hooks/use-exposure-graph';
import { Select, SectionCard } from '../../_components/external-trust/_shared';
import { Badge, EMPTY_SNAPSHOT, HeaderButton, MetricCard, Panel, QuantumReadinessShell, integerFmt, BLUE, CYAN, EMERALD, ORANGE, RED, VIOLET } from '../_shared';
import { POSTURE_COLOR } from './_common';
import { ExposureNodeDetail } from './_panels';
import { AdvisorSection, MigrationOrderSection, RiskPrioritizationSection, ThirdPartySection } from './_intelligence';

const ALL_FILTERS = { posture: 'all', type: 'all', criticality: 'all', layer: 'all' };

export default function ExposureGraphPage() {
  const { data, state, error, sseConnected, transport, lastVerifiedAt, refresh, downloadJson } = useExposureGraph();
  const [params] = useSearchParams();
  const [filters, setFilters] = useState(ALL_FILTERS);
  const requestedAsset = params.get('asset');
  const [focusOverride, setFocusOverride] = useState<string | null | undefined>();
  const focusId = focusOverride === undefined ? requestedAsset : focusOverride;
  const [selectedId, setSelectedId] = useState<string | null | undefined>();
  const activeId = selectedId === undefined ? requestedAsset : selectedId;
  const { nodes, edges } = data.graph;
  const { summary } = data;
  const nodeById = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const edgeById = useMemo(() => new Map(edges.map((edge) => [edge.id, edge])), [edges]);
  const evidencedEdges = useMemo(() => edges.filter((edge) => edge.provenance === 'explicit' || edge.provenance === 'observed'), [edges]);
  const visibleNodes = useMemo(() => nodes.filter((node) =>
    (filters.posture === 'all' || node.posture === filters.posture || node.cryptoPosture === filters.posture) &&
    (filters.type === 'all' || node.kind === filters.type) &&
    (filters.criticality === 'all' || node.businessCriticality === filters.criticality) &&
    (filters.layer === 'all' || node.tierLabel === filters.layer)), [nodes, filters]);
  const tiers = useMemo(() => [...new Set([...nodes].sort((a, b) => a.migrationTier - b.migrationTier).map((node) => node.tierLabel))], [nodes]);
  const blast = useMemo(() => activeId && visibleNodes.some((node) => node.id === activeId)
    ? computeBlastRadius(nodes, evidencedEdges, activeId) : null, [activeId, evidencedEdges, nodes, visibleNodes]);
  const graph = useMemo(() => buildExposureWorkflowGraph(visibleNodes, edges, blast, data.evidence.limitations ?? []), [visibleNodes, edges, blast, data.evidence.limitations]);
  const shellSnapshot = useMemo(() => ({ ...EMPTY_SNAPSHOT, hasData: data.hasData, generatedAt: data.generatedAt, lastAssessmentAt: data.lastAssessmentAt }), [data.hasData, data.generatedAt, data.lastAssessmentAt]);

  const selectAndFocus = useCallback((id: string) => {
    if (!nodeById.has(id)) return;
    setFilters(ALL_FILTERS);
    setSelectedId(id);
    setFocusOverride(id);
    document.getElementById('exposure-dependency-graph')?.scrollIntoView({ block: 'start' });
  }, [nodeById]);

  const updateFilter = (key: keyof typeof filters, value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
    setFocusOverride(null);
  };
  const graphSection = (
    <SectionCard id="exposure-dependency-graph" title="Dependency Graph" icon={Network}
      right={<span className="text-[11px] text-white/55">{integerFmt(graph.nodes.length)} nodes · {integerFmt(graph.edges.filter((edge) => edge.provenance !== 'inferred').length)} stored or observed · {integerFmt(graph.edges.filter((edge) => edge.provenance === 'inferred').length)} inferred</span>}>
      <div className="mb-3 flex flex-wrap items-center gap-2" role="group" aria-label="Dependency filters">
        <Select label="Node type" value={filters.type} onChange={(value) => updateFilter('type', value)} options={[[ 'all', 'All node types' ], ['asset', 'Workspace assets'], ['external', 'External dependencies']]} />
        <Select label="Criticality" value={filters.criticality} onChange={(value) => updateFilter('criticality', value)} options={[[ 'all', 'All criticality' ], ...['Critical', 'High', 'Medium', 'Low', 'Unknown'].map((value) => [value, value] as [string, string])]} />
        <Select label="Posture and migration" value={filters.posture} onChange={(value) => updateFilter('posture', value)} options={[[ 'all', 'All statuses' ], ...Object.entries(EXPOSURE_STATUS).map(([key, value]) => [key, value.label] as [string, string])]} />
        <Select label="Migration layer" value={filters.layer} onChange={(value) => updateFilter('layer', value)} options={[[ 'all', 'All layers' ], ...tiers.map((tier) => [tier, tier] as [string, string])]} />
        {Object.values(filters).some((value) => value !== 'all') && <button type="button" className="rounded-md border border-white/15 px-3 py-1.5 text-xs font-semibold" onClick={() => setFilters(ALL_FILTERS)}>Clear filters</button>}
      </div>
      <VendorTrustWorkflowCanvas graph={graph} ariaLabel="Quantum exposure dependency map" status="ready"
        searchPlaceholder="Find asset, owner, algorithm…" focusNodeId={focusId} enableTrace autoCollapseAbove={14} height={680} exportName="qguard-exposure-dependencies"
        onSelectNode={(node) => { setSelectedId(node?.kind === 'group' ? null : node?.id ?? null); setFocusOverride(null); }}
        empty={{ title: nodes.length ? 'No dependencies match these filters' : 'No exposure dependencies recorded', detail: nodes.length ? 'Clear the filters to see the mapped workspace.' : 'Record exposure evidence through discovery or register asset relationships.', cta: nodes.length ? undefined : { label: 'Open PQC Scanner', href: '/dashboard/scanner' } }}
        renderNodeDetail={(node, context) => {
          const source = nodeById.get(node.id);
          if (!source) return <p className="qg-wf__text">Expand the group to inspect its assets individually.</p>;
          const radius = blast?.nodeId === node.id ? blast : computeBlastRadius(nodes, evidencedEdges, node.id);
          const hasImpactEvidence = source.riskMeasured || source.algorithms.length > 0 || radius.totalAffected > 0;
          return <ExposureNodeDetail key={source.id} node={source} nodes={nodes} blast={radius}
            impact={hasImpactEvidence ? computeMigrationImpact(nodes, evidencedEdges, source.id, radius) : null} onSelectNode={(id) => {
              if (visibleNodes.some((item) => item.id === id)) context.select(id);
              else selectAndFocus(id);
            }} />;
        }}
        renderEdgeDetail={(edge, context) => <>
          <DefaultEdgeDetail edge={edge} nodeById={context.nodeById} />
          <DetailSection title="Observed algorithm"><p className="qg-wf__text">{edgeById.get(edge.id)?.algorithm || 'No algorithm recorded for this link.'}</p></DetailSection>
        </>}
      />
      <p className="mt-2 text-xs text-white/55">Select a node to inspect its evidence or trace its dependencies. Inferred links show their basis in the link inspector.</p>
    </SectionCard>
  );

  return (
    <QuantumReadinessShell
      title="Quantum Exposure Graph™"
      subtitle="Trace recorded dependencies, inspect findings by asset, and evaluate migration impact."
      badge={lastVerifiedAt ? <Badge color={CYAN}>{integerFmt(nodes.length)} nodes · {integerFmt(edges.length)} map links</Badge> : undefined}
      sseConnected={sseConnected}
      transport={transport}
      state={state === 'error' && lastVerifiedAt ? 'success' : state}
      snapshot={shellSnapshot}
      error={error}
      lastVerifiedAt={lastVerifiedAt}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>
          {lastVerifiedAt && <HeaderButton icon={Download} onClick={() => downloadJson('quantum-exposure-graph', data)}>Export Intelligence</HeaderButton>}
        </>
      }
    >
      {state === 'error' && lastVerifiedAt && <Panel className="p-3"><p role="status">Live refresh failed. Showing the last confirmed workspace snapshot.</p></Panel>}
      {/* Enterprise KPI band */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        <MetricCard label="Loaded Assets" value={integerFmt(summary.totalAssets)} detail={`${integerFmt(summary.internetFacingAssets)} recorded as internet-facing`} color={BLUE} icon={Server} />
        <MetricCard
          label="Vulnerable Crypto"
          value={integerFmt(summary.quantumVulnerable)}
          detail={summary.totalAssets ? `${Math.round((summary.quantumVulnerable / summary.totalAssets) * 100)}% of loaded assets` : 'No assets yet'}
          color={RED}
          icon={ShieldAlert}
          ring={summary.totalAssets ? Math.round((summary.quantumVulnerable / Math.max(1, summary.totalAssets)) * 100) : 0}
        />
        <MetricCard
          label="PQC Observed"
          value={integerFmt(summary.pqcReadyAssets)}
          detail={`${integerFmt(summary.hybridAssets)} hybrid · ${integerFmt(summary.migrationInProgress)} in progress`}
          color={EMERALD}
          icon={ShieldCheck}
          ring={summary.totalAssets ? Math.round((summary.pqcReadyAssets / Math.max(1, summary.totalAssets)) * 100) : 0}
        />
        <MetricCard label="Third-Party Dependencies" value={integerFmt(summary.thirdPartyDependencies)} detail={`${integerFmt(summary.certificateChains)} mapped issuer link(s)`} color={VIOLET} icon={Building2} />
        <MetricCard label="Critical Trust Links" value={integerFmt(summary.criticalTrustRelationships)} detail={`of ${integerFmt(summary.trustRelationships)} trust relationships`} color={ORANGE} icon={Link2} />
        <MetricCard label="Quantum Readiness" value={summary.assessmentMeasured ? integerFmt(summary.quantumReadinessScore) : '—'} suffix={summary.assessmentMeasured ? '/100' : undefined} detail="Quantum Readiness Assessment" color={CYAN} icon={Radar} ring={summary.assessmentMeasured ? summary.quantumReadinessScore : undefined} />
      </section>

      {/* Secondary metric strip */}
      <Panel className="px-4 py-3">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[11px]">
          {(
            [
              { label: 'High-Priority Mapped Assets', value: summary.highRiskAssets, color: RED },
              { label: 'Legacy Crypto Assets', value: summary.legacyCryptoAssets, color: ORANGE },
              { label: 'Unknown Posture', value: summary.unknownPosture, color: POSTURE_COLOR.unknown },
              { label: 'Certificate Records', value: summary.pkiObjects, color: VIOLET },
              { label: 'Mapped Issuer Links', value: summary.certificateChains, color: VIOLET },
              { label: 'Max Mapped Blast Radius', value: summary.maxBlastRadius, color: CYAN },
              { label: 'Quantum Risk', value: summary.assessmentMeasured ? summary.quantumRiskScore : null, color: summary.quantumRiskScore >= 60 ? RED : ORANGE, suffix: '/100' },
            ] as Array<{ label: string; value: number | null; color: string; suffix?: string }>
          ).map((stat) => (
            <span key={stat.label} className="inline-flex items-baseline gap-1.5">
              <span className="font-mono text-sm font-semibold" style={{ color: stat.color }}>
                {stat.value === null ? '—' : integerFmt(stat.value)}
                {stat.value !== null && stat.suffix}
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wide text-white/40">{stat.label}</span>
            </span>
          ))}
        </div>
      </Panel>

      {graphSection}

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
