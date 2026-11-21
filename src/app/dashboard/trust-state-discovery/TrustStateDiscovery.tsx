'use client';

/**
 * Cryptographic Trust Discovery & Relationship Intelligence Center —
 * `/dashboard/trust-state-discovery`.
 *
 * Answers "what is out there, and how is it related": every discovered trust
 * subject (root and intermediate CAs, certificates, TLS endpoints, services,
 * applications, APIs, identity systems, key managers, Kubernetes workloads,
 * containers, load balancers, gateways and cloud resources), the relationships
 * between them, and the end-to-end chains those relationships form.
 *
 * The subjects are projections of the same Trust Fabric model the other three
 * pages read, so a certificate counted here is the one Certificate Telemetry
 * shows and an asset counted here is the one Assets & CBOM shows.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Activity, Boxes, Filter, GitBranch, Network, Share2, Workflow } from 'lucide-react';
import {
  BarRow,
  ConnectionLost,
  Donut,
  Drawer,
  ErrorState,
  FilterSelect,
  FreshnessBar,
  NoDataState,
  Pager,
  PanelEmpty,
  Pill,
  ProvenanceFooter,
  SHELL_CSS,
  SearchInput,
  SectionLabel,
  TONE,
  TableShell,
  Td,
  Th,
  fmtNumber,
  fmtPercent,
  relativeTime,
} from '../_components/observability/primitives';
import {
  Basis,
  EventStream,
  KpiSkeleton,
  LiveDot,
  NodeKindBadge,
  ProviderChip,
  ReconciliationPanel,
  StaleBanner,
  TRUST_SHELL_CLASS,
  TRUST_SHELL_CSS,
  TRUST_STATE_TONE,
  TrustKpiTile,
  TrustModuleNav,
  TrustPanel,
  TrustSkeleton,
  TrustStateBadge,
} from '../_components/trust/primitives';
import DiscoveryTrustGraph from '../_components/trust/TrustGraph';
import {
  EMPTY_FILTERS,
  useTrustFabricDetail,
  useTrustFilters,
  useTrustPagedResource,
  useTrustStateDiscovery,
  type NodeDetail,
} from '@/hooks/use-trust-fabric';
import { TRUST_NODE_LABEL, TRUST_STATE_LABEL, type TrustNode, type TrustRelationship } from '@/lib/trust-fabric/types';
import { useAuth } from '@/contexts/auth-context';
import { cn } from '@/lib/utils';

const PAGE_SIZE = 25;

export default function TrustStateDiscovery() {
  const { user, session } = useAuth();
  const account = user && session?.user.id === user.id ? user.id : 'signed-out';
  return <TrustStateDiscoveryView key={account} />;
}

function TrustStateDiscoveryView() {
  const { data, state, error, live, lastSyncedAt, revision, refresh, reconnect } = useTrustStateDiscovery();
  const { loadNode, loading: detailLoading, detailError } = useTrustFabricDetail('discovery');
  const [searchParams] = useSearchParams();
  const { filters, setFilter, setFilters, activeCount } = useTrustFilters({
    state: searchParams.get('state') ?? 'all',
    kind: searchParams.get('kind') ?? 'all',
    sort: 'state',
  });
  const [offset, setOffset] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [detail, setDetail] = useState<NodeDetail | null>(null);
  const [drawerNodeId, setDrawerNodeId] = useState<string | null>(null);
  const [detailRetry, setDetailRetry] = useState(0);

  const scope = useMemo(
    () => ({
      search: filters.search,
      kind: filters.kind,
      state: filters.state,
      environment: filters.environment,
      provider: filters.provider,
      account: filters.account,
      region: filters.region,
      risk: filters.risk,
      posture: filters.posture,
      owner: filters.owner,
      measured: filters.attribution === 'attributed' ? 'true' : filters.attribution === 'unattributed' ? 'false' : 'all',
      range: filters.range,
      sort: filters.sort,
    }),
    [filters],
  );

  const table = useTrustPagedResource<TrustNode>('discovery', '/nodes', 'nodes', { ...scope, limit: PAGE_SIZE, offset }, revision);
  const scopedGraph = activeCount > 0 || filters.sort !== 'state';
  const graph = useTrustPagedResource<TrustNode>('discovery', '/nodes', 'nodes',
    { ...scope, limit: 80, includeRelationships: '1' }, revision, scopedGraph && Boolean(data));
  const graphNodes = scopedGraph ? graph.rows : data?.nodes ?? [];
  const graphRelationships = scopedGraph ? (graph.extra.relationships as TrustRelationship[] | undefined) ?? [] : data?.relationships ?? [];
  const graphTotal = scopedGraph ? graph.total : data?.totals.nodes ?? 0;
  const graphLinkTotal = scopedGraph ? (graph.extra.matchingRelationships as number | undefined) ?? 0 : data?.matchingRelationships ?? 0;

  useEffect(() => {
    setOffset(0);
  }, [filters]);

  const openNode = useCallback((id: string) => setDrawerNodeId(id), []);
  useEffect(() => {
    if (!drawerNodeId || !revision) return;
    let active = true;
    void loadNode(drawerNodeId).then((record) => { if (active) setDetail(record); });
    return () => { active = false; };
  }, [drawerNodeId, revision, loadNode, detailRetry]);
  const visibleDetail = detail?.node.id === drawerNodeId ? detail : null;

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await refresh(true);
    setRefreshing(false);
  }, [refresh]);

  const stateRows = useMemo(
    () =>
      (data?.stateDistribution ?? []).map((row) => ({
        label: row.label,
        value: row.count,
        hex: TONE[TRUST_STATE_TONE[row.state]].hex,
      })),
    [data],
  );

  if (state === 'loading' && !data) {
    return (
      <div className={TRUST_SHELL_CLASS}>
        <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>
        <KpiSkeleton count={6} />
        <TrustSkeleton rows={2} height={260} />
      </div>
    );
  }

  if (state === 'error' && !data) {
    return (
      <div className={TRUST_SHELL_CLASS}>
        <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>
        <ErrorState message={error || 'Unable to load trust-state discovery.'} onRetry={() => void refresh(true)} />
      </div>
    );
  }

  if (!data) return null;

  const incompleteChains = data.incompleteChains;
  const unmeasuredNodes = data.totals.nodes - data.totals.measuredNodes;
  const partialEvidence = data.reads.some((read) => read.state === 'unavailable' || read.state === 'truncated');

  return (
    <div className={TRUST_SHELL_CLASS}>
      <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>

      <header className="flex flex-col gap-3 border-b border-white/10 pb-3.5 xl:flex-row xl:items-end xl:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.2)]">
            <Network className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h1 className="flex items-center gap-2 text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
              Trust-State <span className="text-cyan-300">Discovery</span>
              <LiveDot live={live} />
            </h1>
            <p className="mt-1.5 max-w-3xl text-[12px] font-medium leading-relaxed text-white/45">
              What was discovered, what state it is in, and how it is related — who trusts whom, which certificate protects which service,
              and what breaks when a trust link fails.
            </p>
          </div>
        </div>
        <FreshnessBar
          live={live}
          state={state}
          generatedAt={data.generatedAt}
          latestEvidenceAt={data.latestEvidenceAt}
          telemetry={data.telemetry}
          onRefresh={() => void onRefresh()}
          refreshing={refreshing}
        />
      </header>

      <TrustModuleNav />

      {!live ? <ConnectionLost onReconnect={reconnect} lastSyncedAt={lastSyncedAt} /> : null}
      {data.stale && data.staleSinceHours !== null ? <StaleBanner hours={data.staleSinceHours} onRefresh={() => void onRefresh()} /> : null}

      {data.totals.nodes === 0 && !partialEvidence ? (
        <NoDataState
          title="Nothing discovered yet"
          body="No telemetry or discovered assets are currently available for this scope. Trust subjects are discovered by agent collectors, cloud connectors and authorized scans — connect one and the relationship graph below will build itself from the results."
          telemetry={data.telemetry}
        />
      ) : null}

      {/* ============ KPIs ============ */}
      <section aria-label="Discovery KPIs" className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        <TrustKpiTile
          index={0}
          label="Trust subjects"
          value={data.totals.nodes}
          detail={`${fmtNumber(data.totals.measuredNodes)} measured`}
          tone="neutral"
          hint="Every discovered CA, certificate, endpoint, service, asset and cloud resource."
        />
        <TrustKpiTile
          index={1}
          label="Relationships"
          value={data.totals.relationships}
          detail="Issued, protects, depends-on, deployed-on"
          tone="neutral"
          hint="Edges derived from certificate chains, deployment bindings and the tenant asset_relationships table."
        />
        <TrustKpiTile
          index={2}
          label="Chain paths"
          value={data.totals.chainPaths}
          detail={`${fmtNumber(incompleteChains)} incomplete`}
          tone={incompleteChains > 0 ? 'warning' : 'good'}
          hint="End-to-end paths assembled from root through to the serving asset."
        />
        <TrustKpiTile
          index={3}
          label="Unmeasured"
          value={unmeasuredNodes}
          detail="No measurement recorded"
          tone={unmeasuredNodes > 0 ? 'warning' : 'good'}
          onClick={() => setFilter('attribution', 'unattributed')}
          hint="Subjects present in inventory or referenced by an issuer string, with no collected evidence of their own."
        />
        <TrustKpiTile
          index={4}
          label="Certificates"
          value={data.totals.certificates}
          detail="Same records Certificate Telemetry reads"
          tone="neutral"
          href="/dashboard/certificate-telemetry"
          hint="Deduplicated certificate inventory shared across the whole platform."
        />
        <TrustKpiTile
          index={5}
          label="Open findings"
          value={data.totals.findings}
          detail="Cryptographic weaknesses on these subjects"
          tone={data.totals.findings > 0 ? 'warning' : 'good'}
          href="/dashboard/quantum-readiness/risk-analysis"
          hint="Scanner-reported and engine-derived findings, merged rather than summed."
        />
      </section>

      {/* ============ graph ============ */}
      <TrustPanel index={0}>
        <SectionLabel
          icon={Share2}
          hint="Select a subject or relationship to inspect its evidence. Paths describe the links visible in this graph. The filters also apply to the subject inventory."
        >
          Trust relationship graph
        </SectionLabel>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <SearchInput
            value={filters.search}
            onChange={(value) => setFilter('search', value)}
            placeholder="Search subject, host, owner or region"
          />
          <FilterSelect
            label="Type"
            value={filters.kind}
            onChange={(value) => setFilter('kind', value)}
            options={[{ value: 'all', label: 'All' }, ...data.kindDistribution.map((row) => ({ value: row.kind, label: `${TRUST_NODE_LABEL[row.kind]} (${row.count})` }))]}
          />
          <FilterSelect
            label="State"
            value={filters.state}
            onChange={(value) => setFilter('state', value)}
            options={[{ value: 'all', label: 'All' }, ...data.stateDistribution.map((row) => ({ value: row.state, label: `${TRUST_STATE_LABEL[row.state]} (${row.count})` }))]}
          />
          <FilterSelect
            label="Environment"
            value={filters.environment}
            onChange={(value) => setFilter('environment', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.environments.map((env) => ({ value: env.toLowerCase(), label: env }))]}
          />
          <FilterSelect
            label="Cloud"
            value={filters.provider}
            onChange={(value) => setFilter('provider', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.providers.map((provider) => ({ value: provider.id, label: provider.label }))]}
          />
          <FilterSelect
            label="Region"
            value={filters.region}
            onChange={(value) => setFilter('region', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.regions.map((region) => ({ value: region.toLowerCase(), label: region }))]}
          />
          <FilterSelect
            label="Risk"
            value={filters.risk}
            onChange={(value) => setFilter('risk', value)}
            options={[
              { value: 'all', label: 'All' },
              { value: 'critical', label: 'Critical' },
              { value: 'high', label: 'High' },
              { value: 'medium', label: 'Medium' },
              { value: 'low', label: 'Low' },
            ]}
          />
          <FilterSelect
            label="Evidence"
            value={filters.attribution}
            onChange={(value) => setFilter('attribution', value)}
            options={[
              { value: 'all', label: 'All' },
              { value: 'attributed', label: 'Measured' },
              { value: 'unattributed', label: 'Unmeasured' },
            ]}
          />
          <FilterSelect
            label="Sort"
            value={filters.sort}
            onChange={(value) => setFilter('sort', value)}
            options={[
              { value: 'state', label: 'Worst state first' },
              { value: 'risk', label: 'Highest risk' },
              { value: 'blast', label: 'Largest blast radius' },
              { value: 'expiry', label: 'Soonest expiry' },
              { value: 'name', label: 'Name' },
            ]}
          />
          {activeCount > 0 ? (
            <button
              type="button"
              onClick={() => setFilters({ ...EMPTY_FILTERS, sort: 'state' })}
              className="rounded-md border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/20"
            >
              Clear {activeCount} filter{activeCount === 1 ? '' : 's'}
            </button>
          ) : null}
        </div>

        <DiscoveryTrustGraph
          nodes={graphNodes}
          relationships={graphRelationships}
          matchingNodes={graphTotal}
          matchingRelationships={graphLinkTotal}
          filtered={activeCount > 0}
          partialEvidence={partialEvidence}
          loading={scopedGraph && graph.loading}
          error={scopedGraph ? graph.error : null}
          onRetry={graph.retry}
          onInspect={openNode}
        />
      </TrustPanel>

      {/* ============ distributions ============ */}
      <div className="grid gap-3 xl:grid-cols-3">
        <TrustPanel index={1}>
          <SectionLabel icon={Boxes} hint="Trust-state classification across every discovered subject.">
            Trust-state classification
          </SectionLabel>
          {stateRows.length === 0 ? (
            <PanelEmpty>Nothing discovered to classify.</PanelEmpty>
          ) : (
            <>
              <Donut rows={stateRows} centerLabel="Subjects" centerValue={fmtNumber(data.totals.nodes)} />
              <ul className="mt-2 space-y-0.5">
                {data.stateDistribution.slice(0, 6).map((row) => (
                  <li key={row.state}>
                    <button
                      type="button"
                      onClick={() => setFilter('state', row.state)}
                      className="flex w-full items-center justify-between gap-2 rounded px-1 py-0.5 text-left transition hover:bg-white/[0.05]"
                    >
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span
                          className="h-1.5 w-1.5 shrink-0 rounded-full"
                          style={{ backgroundColor: TONE[TRUST_STATE_TONE[row.state]].hex }}
                          aria-hidden="true"
                        />
                        <span className="truncate text-[10.5px] font-semibold text-white/65">{TRUST_STATE_LABEL[row.state]}</span>
                      </span>
                      <span className="shrink-0 font-mono text-[10px] text-white/40">
                        {fmtNumber(row.count)} · {fmtPercent(row.percent)}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </TrustPanel>

        <TrustPanel index={2}>
          <SectionLabel icon={GitBranch} hint="What discovery actually found, by subject type. 'Measured' is the share carrying real evidence rather than inventory alone.">
            Discovered subject types
          </SectionLabel>
          {data.kindDistribution.length === 0 ? (
            <PanelEmpty>No subject types to report.</PanelEmpty>
          ) : (
            <div className="space-y-1.5">
              {data.kindDistribution.slice(0, 10).map((row) => (
                <BarRow
                  key={row.kind}
                  label={TRUST_NODE_LABEL[row.kind]}
                  count={row.count}
                  percent={Math.round((row.count / Math.max(1, data.totals.nodes)) * 100)}
                  tone="neutral"
                  suffix={
                    <span className="font-mono text-[9px] text-white/35" title={`${row.measured} of ${row.count} carry their own evidence`}>
                      {row.measured}/{row.count} measured
                    </span>
                  }
                  onClick={() => setFilter('kind', row.kind)}
                />
              ))}
            </div>
          )}
        </TrustPanel>

        <TrustPanel index={3}>
          <SectionLabel icon={Workflow} hint="End-to-end chains, worst first. Blast radius is a real reachability count over the discovered edge set.">
            Trust chains
          </SectionLabel>
          {data.chainPaths.length === 0 ? (
            <PanelEmpty>No certificate could be assembled into a chain — no issuer relationships have been discovered.</PanelEmpty>
          ) : (
            <ul className="space-y-1.5">
              {data.chainPaths.slice(0, 8).map((path) => (
                <li key={path.id} className="rounded-lg border border-white/8 bg-black/20 p-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <TrustStateBadge state={path.state} reason={path.weakestReason} size="sm" />
                    <span className="font-mono text-[9.5px] text-white/40">
                      {path.nodeIds.length} links · {fmtNumber(path.blastRadius)} dependents
                    </span>
                  </div>
                  <p className="mt-1 line-clamp-2 text-[10.5px] leading-snug text-white/50">{path.weakestReason}</p>
                  {!path.complete ? (
                    <p className="mt-1 text-[9.5px] leading-snug text-amber-300/70">Incomplete: {path.incompleteReason}</p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
          <Basis>
            {fmtNumber(data.chainPaths.filter((path) => !path.complete).length)} of {fmtNumber(data.chainPaths.length)} displayed chains are incomplete. An incomplete chain is reported
            with the missing tier named, never scored as if it had passed.
          </Basis>
        </TrustPanel>
      </div>

      {/* ============ subject inventory ============ */}
      <TrustPanel index={4}>
        <SectionLabel
          icon={Filter}
          hint="Shares the filters and Trust Fabric source used by the relationship graph."
          meta={`${fmtNumber(table.total)} matching`}
        >
          Discovered trust subjects
        </SectionLabel>

        {table.error ? (
          <ErrorState message={table.error} onRetry={table.retry} />
        ) : table.loading && table.rows.length === 0 ? (
          <TrustSkeleton rows={6} height={44} />
        ) : table.rows.length === 0 ? (
          <PanelEmpty>No trust subject matches the current filters.</PanelEmpty>
        ) : (
          <>
            <TableShell minWidth={1080}>
              <thead>
                <tr>
                  <Th>Subject</Th>
                  <Th>Type</Th>
                  <Th>State</Th>
                  <Th>Owner</Th>
                  <Th>Environment</Th>
                  <Th>Cloud / region</Th>
                  <Th align="right">Depends on</Th>
                  <Th align="right">Dependents</Th>
                  <Th align="right">Risk</Th>
                  <Th>Last seen</Th>
                </tr>
              </thead>
              <tbody>
                {table.rows.map((node) => (
                  <tr
                    key={node.id}
                    onClick={() => void openNode(node.id)}
                    className="cursor-pointer border-b border-white/5 last:border-0 transition hover:bg-white/[0.04]"
                  >
                    <Td>
                      {/* A real button so the drawer opens from the keyboard too; the row click stays as a mouse shortcut. */}
                      <button
                        type="button"
                        onClick={(event) => {
                          event.stopPropagation();
                          void openNode(node.id);
                        }}
                        className="block max-w-[230px] truncate text-left text-[11.5px] font-bold text-white/85 hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
                      >
                        {node.label}
                      </button>
                      <span className="block max-w-[230px] truncate text-[9.5px] text-white/35">{node.subtitle}</span>
                    </Td>
                    <Td>
                      <NodeKindBadge kind={node.kind} />
                    </Td>
                    <Td>
                      <TrustStateBadge state={node.state} reason={node.stateReason} size="sm" />
                    </Td>
                    <Td>
                      <span className={cn('text-[10.5px]', node.owner ? 'text-white/60' : 'text-amber-300/60')}>
                        {node.owner || 'Unassigned'}
                      </span>
                    </Td>
                    <Td>
                      <span className="text-[10.5px] text-white/50">{node.environment || '—'}</span>
                    </Td>
                    <Td>
                      {node.provider !== 'unattributed' ? (
                        <div className="flex items-center gap-1.5">
                          <ProviderChip provider={node.provider as never} label={node.providerLabel} />
                          {node.region ? <span className="font-mono text-[9.5px] text-white/40">{node.region}</span> : null}
                        </div>
                      ) : (
                        <span className="text-[10px] text-white/30">{node.region || 'Not attributed'}</span>
                      )}
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10.5px] text-white/50">{fmtNumber(node.dependencyCount)}</span>
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10.5px] text-white/60">{fmtNumber(node.dependentCount)}</span>
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10.5px] text-white/60">{node.measured ? fmtNumber(node.riskScore) : 'n/m'}</span>
                    </Td>
                    <Td>
                      <span className="font-mono text-[9.5px] text-white/35">{relativeTime(node.lastObservedAt)}</span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
            <Pager offset={offset} limit={PAGE_SIZE} total={table.total} onChange={setOffset} />
          </>
        )}
      </TrustPanel>

      {/* ============ events + reconciliation ============ */}
      <div className="grid gap-3 xl:grid-cols-2">
        <TrustPanel index={5}>
          <SectionLabel icon={Activity} hint="Discovery and trust-state change events from your own records.">
            Trust-state changes
          </SectionLabel>
          <EventStream events={data.events} limit={10} />
        </TrustPanel>

        <TrustPanel index={6}>
          <SectionLabel icon={Boxes} hint="Where the discovered inventory is incomplete or inconsistent, and which table the discrepancy lives in.">
            Discovery data quality
          </SectionLabel>
          <ReconciliationPanel report={data.reconciliation} />
        </TrustPanel>
      </div>

      <ProvenanceFooter telemetry={data.telemetry} reads={data.reads} />

      <Drawer
        open={drawerNodeId !== null}
        onClose={() => {
          setDrawerNodeId(null);
          setDetail(null);
        }}
        title={visibleDetail?.node.label || 'Trust subject'}
        subtitle={visibleDetail?.node.subtitle}
      >
        {detailLoading && !visibleDetail ? (
          <TrustSkeleton rows={5} height={52} />
        ) : detailError ? (
          <ErrorState message={detailError} onRetry={() => setDetailRetry((count) => count + 1)} />
        ) : !visibleDetail ? (
          <TrustSkeleton rows={5} height={52} />
        ) : (
          <NodeDrawerBody detail={visibleDetail} />
        )}
      </Drawer>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Drawer body                                                         */
/* ------------------------------------------------------------------ */

function NodeDrawerBody({ detail }: { detail: NodeDetail }) {
  const { node, edges, neighbours, chain, certificates, certificateTrust, findings, events } = detail;

  return (
    <div className="space-y-4">
      <section>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <TrustStateBadge state={node.state} size="sm" />
          <NodeKindBadge kind={node.kind} />
          {node.provider !== 'unattributed' ? <ProviderChip provider={node.provider as never} label={node.providerLabel} /> : null}
          {!node.measured ? <Pill tone="warning">{node.kind === 'intermediate-ca' ? 'Issuer inferred' : 'Unmeasured'}</Pill> : null}
        </div>
        <p className="rounded-lg border border-white/10 bg-black/25 p-2.5 text-[11px] leading-relaxed text-white/65">{node.stateReason}</p>
        <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1.5 text-[10.5px]">
          <Field label="Owner" value={node.owner || 'Unassigned'} />
          <Field label="Environment" value={node.environment || 'Not recorded'} />
          <Field label="Region" value={node.region || 'Not recorded'} />
          <Field label="Account" value={node.account || 'Not recorded'} />
          <Field label="Risk score" value={node.measured ? String(node.riskScore) : 'Not measured'} />
          <Field label="Posture" value={node.posture} />
          <Field label="Depends on" value={String(node.dependencyCount)} />
          <Field label="Dependents" value={String(node.dependentCount)} />
          <Field label="Last observed" value={relativeTime(node.lastObservedAt)} />
          <Field
            label="Soonest expiry"
            value={node.daysToExpiry === null ? 'No certificate governs this subject' : `${node.daysToExpiry} days`}
          />
        </dl>
        <Link
          to={node.href}
          className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 no-underline transition hover:bg-cyan-500/20"
        >
          Open in owning module
        </Link>
      </section>

      {chain ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Chain position</h3>
          <div className="rounded-lg border border-white/8 bg-black/20 p-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <TrustStateBadge state={chain.state} size="sm" />
              <span className="font-mono text-[9.5px] text-white/40">
                {chain.nodeIds.length} links · {fmtNumber(chain.blastRadius)} dependents
              </span>
            </div>
            <p className="mt-1 text-[10.5px] leading-snug text-white/50">{chain.weakestReason}</p>
            {!chain.complete ? <p className="mt-1 text-[9.5px] text-amber-300/70">Incomplete: {chain.incompleteReason}</p> : null}
          </div>
        </section>
      ) : null}

      <section>
        <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">
          Relationships {edges.length > 0 ? `(${edges.length})` : ''}
        </h3>
        {edges.length === 0 ? (
          <PanelEmpty>No relationship has been discovered for this subject.</PanelEmpty>
        ) : (
          <ul className="space-y-1">
            {edges.slice(0, 12).map((edge) => {
              const other = neighbours.find((candidate) => candidate.id === (edge.from === node.id ? edge.to : edge.from));
              const outbound = edge.from === node.id;
              return (
                <li key={edge.id} className="rounded-lg border border-white/8 bg-black/20 p-2">
                  <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                    <span className="font-black uppercase tracking-wider text-white/35">{outbound ? 'to' : 'from'}</span>
                    <span className="min-w-0 truncate font-semibold text-white/75">{other?.label ?? 'Unknown subject'}</span>
                    <span className="rounded bg-white/8 px-1.5 py-0.5 font-mono text-[9px] text-white/50">{edge.label}</span>
                    {!edge.measured ? <span className="text-[9px] text-amber-300/70">inferred</span> : null}
                  </div>
                  <p className="mt-0.5 text-[9.5px] leading-snug text-white/40">{edge.reason}</p>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {certificates.length > 0 ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Certificates ({certificates.length})</h3>
          <ul className="space-y-1">
            {certificates.slice(0, 8).map((certificate) => {
              const trust = certificateTrust.find((record) => record.certificateId === certificate.id);
              return (
                <li key={certificate.id}>
                  <Link
                    to={`/dashboard/certificate-telemetry?certificate=${encodeURIComponent(certificate.id)}`}
                    className="block rounded-lg border border-white/8 bg-black/20 p-2 no-underline transition hover:border-cyan-400/30"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="min-w-0 truncate text-[10.5px] font-semibold text-white/75">
                        {certificate.name || certificate.subject}
                      </span>
                      {trust ? <TrustStateBadge state={trust.state} size="sm" /> : null}
                    </div>
                    <span className="mt-0.5 block font-mono text-[9.5px] text-white/40">
                      {certificate.algorithmLabel} ·{' '}
                      {certificate.daysToExpiry === null ? 'no expiry recorded' : `${certificate.daysToExpiry}d remaining`}
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      {findings.length > 0 ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Findings ({findings.length})</h3>
          <ul className="space-y-1">
            {findings.slice(0, 8).map((finding) => (
              <li key={finding.id} className="rounded-lg border border-white/8 bg-black/20 p-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[10.5px] font-bold text-white/80">{finding.title}</span>
                  <span className="font-mono text-[9px] uppercase text-white/35">{finding.severity}</span>
                </div>
                <p className="mt-0.5 text-[9.5px] leading-snug text-white/45">{finding.impact}</p>
                <p className="mt-0.5 text-[9.5px] leading-snug text-cyan-200/60">
                  <span className="font-black uppercase">Fix:</span> {finding.remediation} <span className="text-white/30">({finding.standard})</span>
                </p>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {events.length > 0 ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Recent events</h3>
          <EventStream events={events} limit={6} />
        </section>
      ) : null}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[9px] font-black uppercase tracking-wider text-white/30">{label}</dt>
      <dd className="mt-0.5 truncate text-white/70" title={value}>
        {value}
      </dd>
    </div>
  );
}
