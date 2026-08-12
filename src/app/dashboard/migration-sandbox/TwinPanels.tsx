/**
 * Migration Sandbox — Digital Twin panels.
 *
 * DigitalTwinTab      — metadata-only twin summary, isolation attestation,
 *                       component groups, twin node inventory, PQC stack.
 * DependencyGraphTab  — per-asset dependsOn/usedBy, certificates, blast
 *                       radius, "what systems will be affected" impact view.
 * TopologyTab         — environment zones with green/yellow/orange/red heat.
 *
 * Detail data comes from GET /api/v1/sandbox/twin (bounded), refreshed with
 * the snapshot generation; summary-level data arrives via the SSE snapshot.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Boxes,
  CheckCircle2,
  Cpu,
  GitBranch,
  Globe2,
  Key,
  Layers,
  Lock,
  Map as MapIcon,
  Network,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { cn } from '@/lib/utils'
import {
  ActionBtn,
  BLUE,
  CYAN,
  EmptyBlock,
  GOLD,
  GREEN,
  MetricTile,
  ORANGE,
  Panel,
  Pill,
  ProgressBar,
  PURPLE,
  RED,
  SectionHead,
  fmt,
  heatColor,
  pct,
  relTime,
  riskBadge,
  type DigitalTwinPayload,
  type FailurePredictionPayload,
  type GraphEdge,
  type GraphNode,
  type HeatStatus,
  type PqcStackItem,
  type SimulationTypeDef,
  type TopologyPayload,
  type TwinNode,
} from './_shared'

type TwinDetail = {
  generatedAt: string
  twin: DigitalTwinPayload & { nodes: TwinNode[] }
  graph: { nodes: GraphNode[]; edges: GraphEdge[]; stats: { totalNodes: number; observedEdges: number; inferredEdges: number; connectedNodes: number; maxBlastRadius: number } }
  topology: TopologyPayload
  failurePrediction: FailurePredictionPayload
}

export function useTwinDetail(enabled: boolean) {
  const { session } = useAuth()
  const token = session?.access_token
  const [detail, setDetail] = useState<TwinDetail | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const loadedRef = useRef(false)

  const load = useCallback(async () => {
    if (!token) return
    setLoading(true)
    try {
      const r = await fetch('/api/v1/sandbox/twin', { headers: { Authorization: `Bearer ${token}` } })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(j?.error?.message || `HTTP ${r.status}`)
      if (j?.data) {
        setDetail(j.data)
        setError(null)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load digital twin')
    } finally {
      setLoading(false)
    }
  }, [token])

  // Lazy: build the twin the first time a twin-powered tab opens.
  useEffect(() => {
    if (!enabled || loadedRef.current || !token) return
    loadedRef.current = true
    void load()
  }, [enabled, token, load])

  return { detail, loading, error, reload: load }
}

/* ═══════════════════════════════════════════════════════════════════════════
   DIGITAL TWIN TAB
   ═══════════════════════════════════════════════════════════════════════════ */

export function DigitalTwinTab({ detail, loading, error, reload, pqcStack, simulationTypes }: {
  detail: TwinDetail | null
  loading: boolean
  error: string | null
  reload: () => void
  pqcStack: PqcStackItem[]
  simulationTypes: SimulationTypeDef[]
}) {
  const [nodeSearch, setNodeSearch] = useState('')
  const twin = detail?.twin

  const filteredNodes = useMemo(() => {
    const nodes = twin?.nodes || []
    if (!nodeSearch.trim()) return nodes
    const q = nodeSearch.trim().toLowerCase()
    return nodes.filter((n) =>
      n.name.toLowerCase().includes(q)
      || n.componentLabel.toLowerCase().includes(q)
      || n.environment.toLowerCase().includes(q)
      || n.algorithms.some((a) => a.toLowerCase().includes(q))
    )
  }, [twin?.nodes, nodeSearch])

  if (loading && !detail) {
    return (
      <Panel className="p-10">
        <div className="flex items-center justify-center gap-3">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-gold/20 border-t-gold" />
          <span className="text-xs font-bold text-white/45">Generating digital twin from tenant evidence…</span>
        </div>
      </Panel>
    )
  }
  if (error && !detail) return <Panel className="p-8"><EmptyBlock label={`Digital twin unavailable: ${error}`} /></Panel>
  if (!twin) return <Panel className="p-8"><EmptyBlock label="Digital twin not yet generated. Run discovery scans to populate asset evidence." /></Panel>

  return (
    <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-8">
        <MetricTile label="Twin Nodes" value={fmt(twin.summary.totalNodes)} detail={`${fmt(twin.summary.nodesWithEvidence)} with evidence`} icon={Boxes} color={GOLD} />
        <MetricTile label="Coverage" value={pct(twin.summary.coveragePct)} detail="Evidence coverage" icon={Shield} color={twin.summary.coveragePct >= 70 ? GREEN : GOLD} />
        <MetricTile label="Fidelity" value={pct(twin.summary.fidelityPct)} detail="Behavioral fidelity" icon={Cpu} color={twin.summary.fidelityPct >= 70 ? GREEN : BLUE} />
        <MetricTile label="Crypto Records" value={fmt(twin.summary.inventoryRecordsCloned)} detail="Inventory cloned" icon={Key} color={PURPLE} />
        <MetricTile label="Certificates" value={fmt(twin.summary.certificatesCloned)} detail="Metadata cloned" icon={Lock} color={CYAN} />
        <MetricTile label="Trust Links" value={fmt(twin.summary.trustRelationships)} detail="Relationships" icon={GitBranch} color={BLUE} />
        <MetricTile label="Runtime Signals" value={fmt(twin.summary.runtimeSignalsSampled)} detail="Telemetry sampled" icon={Zap} color={ORANGE} />
        <MetricTile label="Environments" value={fmt(twin.summary.environments.length)} detail={twin.summary.environments.slice(0, 2).join(', ') || '--'} icon={Globe2} color={GREEN} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.35fr_1fr]">
        <Panel className="p-5">
          <SectionHead icon={Boxes} suffix={<ActionBtn icon={RefreshCw} label={loading ? 'Rebuilding' : 'Rebuild Twin'} onClick={reload} disabled={loading} small />}>
            Twin Component Groups
          </SectionHead>
          {twin.componentGroups.length === 0 ? (
            <EmptyBlock label="No components classified yet — the twin builds itself from discovered assets." />
          ) : (
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {twin.componentGroups.map((group) => (
                <div key={group.id} className="rounded-xl border border-white/8 bg-white/[0.02] p-3.5">
                  <div className="text-xs font-bold text-white/85">{group.label}</div>
                  <div className="mt-2 flex items-end justify-between">
                    <span className="font-mono text-2xl font-black text-white">{fmt(group.assets)}</span>
                    <div className="flex flex-col items-end gap-1">
                      {group.critical > 0 && <Pill className="border-red-500/25 bg-red-500/10 text-red-300">{fmt(group.critical)} critical</Pill>}
                      {group.vulnerable > 0 && <Pill className="border-amber-500/25 bg-amber-500/10 text-amber-300">{fmt(group.vulnerable)} vulnerable</Pill>}
                      {group.critical === 0 && group.vulnerable === 0 && <Pill className="border-emerald-500/25 bg-emerald-500/10 text-emerald-300">clean</Pill>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel className="p-5">
          <SectionHead icon={ShieldCheck}>Production Isolation Attestation</SectionHead>
          <div className="mb-3 flex flex-wrap gap-2">
            <Pill className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300">scope: {twin.isolation.scope}</Pill>
            <Pill className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300">production writes: {twin.isolation.productionWrites}</Pill>
          </div>
          <div className="space-y-2">
            {twin.isolation.guarantees.map((guarantee) => (
              <div key={guarantee} className="flex items-start gap-2 rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px] leading-relaxed text-white/55">
                <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                {guarantee}
              </div>
            ))}
          </div>
          <div className="mt-3">
            <div className="mb-1.5 text-[9px] font-bold uppercase tracking-wider text-white/30">Never cloned into the twin</div>
            <div className="flex flex-wrap gap-1.5">
              {twin.isolation.excludedDatasets.map((dataset) => (
                <span key={dataset}>
                  <Pill className="border-red-500/20 bg-red-500/[0.06] text-red-300/80">{dataset}</Pill>
                </span>
              ))}
            </div>
          </div>
        </Panel>
      </div>

      <Panel className="p-5">
        <SectionHead icon={Layers} suffix={
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/25" />
              <input
                value={nodeSearch}
                onChange={(e) => setNodeSearch(e.target.value)}
                placeholder="Search twin nodes…"
                className="w-52 rounded-lg border border-white/10 bg-white/[0.03] py-1.5 pl-8 pr-3 text-xs text-white outline-none placeholder:text-white/25 focus:border-gold/40"
              />
            </div>
            <span className="font-mono text-[10px] text-white/25">{fmt(filteredNodes.length)} nodes</span>
          </div>
        }>Twin Node Inventory</SectionHead>
        {filteredNodes.length === 0 ? (
          <EmptyBlock label={twin.nodes.length === 0 ? 'No assets discovered yet.' : 'No twin nodes match this search.'} />
        ) : (
          <div className="max-h-[460px] space-y-1.5 overflow-y-auto pr-1 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-white/10">
            {filteredNodes.slice(0, 120).map((node) => (
              <div key={node.id} className="grid gap-2 rounded-lg border border-white/6 bg-white/[0.015] px-3.5 py-2.5 lg:grid-cols-[1.4fr_1fr_auto] lg:items-center">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-xs font-bold text-white/85">{node.name}</span>
                    <Pill className="border-white/10 bg-white/5 text-white/40">{node.componentLabel}</Pill>
                    {node.criticalExposures > 0 && <Pill className="border-red-500/25 bg-red-500/10 text-red-300">{node.criticalExposures} critical</Pill>}
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {node.algorithms.slice(0, 4).map((algo) => <span key={algo}><Pill className="border-purple-500/20 bg-purple-500/[0.07] font-mono text-purple-300/85">{algo}</Pill></span>)}
                    {node.algorithms.length === 0 && <span className="text-[10px] text-white/25">no crypto evidence yet</span>}
                  </div>
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-semibold text-white/40">
                  <span>{node.environment}</span>
                  <span>{fmt(node.inventoryItems)} inventory</span>
                  <span>{fmt(node.certificates)} cert(s)</span>
                  <span>{fmt(node.runtimeSignals)} runtime</span>
                </div>
                <Pill className={riskBadge(node.criticalExposures > 0 ? 'critical' : node.vulnerableItems > 0 ? 'high' : 'low')}>
                  {node.criticalExposures > 0 ? 'critical' : node.vulnerableItems > 0 ? `${node.vulnerableItems} vulnerable` : 'clean'}
                </Pill>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel className="p-5">
          <SectionHead icon={Key}>Twin PQC Algorithm Stack</SectionHead>
          <p className="mb-3 text-xs text-white/40">NIST-approved post-quantum standards available inside the simulation twin.</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {pqcStack.map((item) => (
              <div key={item.name} className="rounded-lg border border-white/8 bg-white/[0.02] p-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-xs font-bold text-white/85">{item.name}</div>
                    <div className="mt-0.5 text-[10px] text-white/35">{item.standard}</div>
                  </div>
                  <Pill className={item.status === 'active' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-sky-500/25 bg-sky-500/10 text-sky-300'}>{item.status}</Pill>
                </div>
                <div className="mt-2 flex items-center justify-between text-[10px]">
                  <span className="text-white/35">Observed usage</span>
                  <span className="font-mono font-bold text-white/65">{fmt(item.usage)}</span>
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel className="p-5">
          <SectionHead icon={Zap}>Simulation Scenario Coverage</SectionHead>
          <p className="mb-3 text-xs text-white/40">Enterprise scenario types executable against this twin (launch from the Simulation Builder).</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {simulationTypes.map((type) => (
              <div key={type.id} className="flex items-center gap-2 rounded-lg border border-white/5 bg-white/[0.015] px-3 py-2">
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
                <div className="min-w-0">
                  <div className="truncate text-[11px] font-bold text-white/70">{type.label}</div>
                  <div className="truncate text-[9px] text-white/30">{type.recommendedFor}</div>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   DEPENDENCY GRAPH TAB
   ═══════════════════════════════════════════════════════════════════════════ */

export function DependencyGraphTab({ detail, loading, error, reload }: {
  detail: TwinDetail | null
  loading: boolean
  error: string | null
  reload: () => void
}) {
  const graph = detail?.graph
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  const nodes = graph?.nodes || []
  const filtered = useMemo(() => {
    if (!search.trim()) return nodes
    const q = search.trim().toLowerCase()
    return nodes.filter((n) => n.name.toLowerCase().includes(q) || n.type.toLowerCase().includes(q) || n.environment.toLowerCase().includes(q))
  }, [nodes, search])
  const selected = useMemo(() => nodes.find((n) => n.id === selectedId) || filtered[0] || null, [nodes, filtered, selectedId])

  if (loading && !detail) {
    return (
      <Panel className="p-10">
        <div className="flex items-center justify-center gap-3">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-gold/20 border-t-gold" />
          <span className="text-xs font-bold text-white/45">Resolving dependency graph…</span>
        </div>
      </Panel>
    )
  }
  if (error && !detail) return <Panel className="p-8"><EmptyBlock label={`Dependency graph unavailable: ${error}`} /></Panel>
  if (!graph || nodes.length === 0) return <Panel className="p-8"><EmptyBlock label="No assets discovered yet — the dependency graph builds itself from asset relationships and certificate trust evidence." /></Panel>

  return (
    <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <MetricTile label="Graph Nodes" value={fmt(graph.stats.totalNodes)} detail="Twin assets" icon={Network} color={GOLD} />
        <MetricTile label="Observed Edges" value={fmt(graph.stats.observedEdges)} detail="asset_relationships" icon={GitBranch} color={GREEN} />
        <MetricTile label="Inferred Edges" value={fmt(graph.stats.inferredEdges)} detail="Shared-issuer trust" icon={GitBranch} color={CYAN} />
        <MetricTile label="Connected" value={fmt(graph.stats.connectedNodes)} detail="Nodes with edges" icon={Boxes} color={BLUE} />
        <MetricTile label="Max Blast Radius" value={fmt(graph.stats.maxBlastRadius)} detail="Downstream consumers" icon={ShieldAlert} color={graph.stats.maxBlastRadius >= 3 ? RED : GREEN} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
        <Panel className="p-4">
          <SectionHead icon={Search} suffix={<span className="font-mono text-[10px] text-white/25">{fmt(filtered.length)}</span>}>Assets by Impact</SectionHead>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search assets…"
            className="mb-3 w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-white outline-none placeholder:text-white/25 focus:border-gold/40"
          />
          <div className="max-h-[560px] space-y-1.5 overflow-y-auto pr-1 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-white/10">
            {filtered.map((node) => (
              <button
                key={node.id}
                type="button"
                onClick={() => setSelectedId(node.id)}
                className={cn('w-full rounded-lg border px-3 py-2.5 text-left transition',
                  selected?.id === node.id ? 'border-gold/40 bg-gold/[0.06]' : 'border-white/6 bg-white/[0.015] hover:border-gold/20')}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-xs font-bold text-white/85">{node.name}</span>
                  <span className="font-mono text-[10px] font-black" style={{ color: node.impactScore >= 60 ? RED : node.impactScore >= 30 ? ORANGE : GREEN }}>{node.impactScore}</span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-x-2 text-[10px] text-white/35">
                  <span>{node.type}</span>
                  <span>·</span>
                  <span>{node.environment}</span>
                  <span>·</span>
                  <span>blast {node.blastRadius}</span>
                </div>
              </button>
            ))}
          </div>
        </Panel>

        {selected ? (
          <div className="space-y-4">
            <Panel className="p-5">
              <SectionHead icon={ShieldAlert} suffix={<ActionBtn icon={RefreshCw} label={loading ? 'Refreshing' : 'Refresh'} onClick={reload} disabled={loading} small />}>
                Impact Analysis — {selected.name}
              </SectionHead>
              <div className="rounded-xl border border-gold/20 bg-gold/[0.04] p-4">
                <div className="text-xs font-black uppercase tracking-wider text-gold">What systems will be affected if this migration proceeds?</div>
                <p className="mt-2 text-xs leading-relaxed text-white/60">
                  {selected.blastRadius === 0
                    ? 'No downstream consumers observed — migrating this asset carries isolated, per-asset risk only.'
                    : `${fmt(selected.blastRadius)} downstream system(s) depend on this asset (directly or transitively). A failed migration here cascades to every consumer below — sequence this asset early and validate consumers in the twin after cutover.`}
                </p>
                {selected.impactedAssets.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {selected.impactedAssets.map((ref) => (
                      <span key={ref.id}>
                        <Pill className="border-orange-500/25 bg-orange-500/10 text-orange-300">{ref.name}</Pill>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {[
                  ['Impact Score', `${selected.impactScore}`, selected.impactScore >= 60 ? RED : selected.impactScore >= 30 ? ORANGE : GREEN],
                  ['Blast Radius', fmt(selected.blastRadius), selected.blastRadius >= 3 ? RED : GREEN],
                  ['Critical Exposures', fmt(selected.criticalExposures), selected.criticalExposures > 0 ? RED : GREEN],
                  ['Vulnerable Items', fmt(selected.vulnerableItems), selected.vulnerableItems > 0 ? ORANGE : GREEN],
                ].map(([label, value, color]) => (
                  <div key={label as string} className="rounded-lg border border-white/8 bg-white/[0.02] p-3 text-center">
                    <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">{label}</div>
                    <div className="mt-1 font-mono text-xl font-black" style={{ color: color as string }}>{value}</div>
                  </div>
                ))}
              </div>
            </Panel>

            <div className="grid gap-4 lg:grid-cols-3">
              <Panel className="p-4">
                <SectionHead icon={GitBranch}>Depends On ({selected.dependsOn.length})</SectionHead>
                {selected.dependsOn.length === 0 ? (
                  <EmptyBlock label="No upstream dependencies observed." />
                ) : (
                  <div className="space-y-1.5">
                    {selected.dependsOn.map((ref) => (
                      <button key={ref.id} type="button" onClick={() => setSelectedId(ref.id)} className="flex w-full items-center gap-2 rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2 text-left text-[11px] font-semibold text-white/60 transition hover:border-gold/25 hover:text-gold">
                        <GitBranch className="h-3 w-3 shrink-0 text-sky-400" />
                        <span className="truncate">{ref.name}</span>
                      </button>
                    ))}
                  </div>
                )}
              </Panel>
              <Panel className="p-4">
                <SectionHead icon={Network}>Used By ({selected.usedBy.length})</SectionHead>
                {selected.usedBy.length === 0 ? (
                  <EmptyBlock label="No downstream consumers observed." />
                ) : (
                  <div className="space-y-1.5">
                    {selected.usedBy.map((ref) => (
                      <button key={ref.id} type="button" onClick={() => setSelectedId(ref.id)} className="flex w-full items-center gap-2 rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2 text-left text-[11px] font-semibold text-white/60 transition hover:border-gold/25 hover:text-gold">
                        <Network className="h-3 w-3 shrink-0 text-orange-400" />
                        <span className="truncate">{ref.name}</span>
                      </button>
                    ))}
                  </div>
                )}
              </Panel>
              <Panel className="p-4">
                <SectionHead icon={Lock}>Certificates ({selected.certificates.length})</SectionHead>
                {selected.certificates.length === 0 ? (
                  <EmptyBlock label="No certificates attached to this asset." />
                ) : (
                  <div className="space-y-1.5">
                    {selected.certificates.map((cert) => (
                      <div key={cert.id} className="rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2">
                        <div className="truncate text-[11px] font-bold text-white/70">{cert.name}</div>
                        <div className="mt-0.5 flex items-center justify-between">
                          <span className="font-mono text-[10px] text-white/35">{cert.algorithm || 'unknown'}</span>
                          <Pill className={cert.quantumSafe ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300' : 'border-red-500/25 bg-red-500/10 text-red-300'}>
                            {cert.quantumSafe ? 'PQC-safe' : 'quantum-vulnerable'}
                          </Pill>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </div>
          </div>
        ) : (
          <Panel className="p-8"><EmptyBlock label="Select an asset to inspect its dependency chain and migration impact." /></Panel>
        )}
      </div>
    </>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   TOPOLOGY / RISK HEAT MAP TAB
   ═══════════════════════════════════════════════════════════════════════════ */

const HEAT_ORDER: HeatStatus[] = ['blocked', 'high_risk', 'attention', 'ready']

export function TopologyTab({ detail, loading, error, reload }: {
  detail: TwinDetail | null
  loading: boolean
  error: string | null
  reload: () => void
}) {
  const topology = detail?.topology

  if (loading && !detail) {
    return (
      <Panel className="p-10">
        <div className="flex items-center justify-center gap-3">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-gold/20 border-t-gold" />
          <span className="text-xs font-bold text-white/45">Building topology heat map…</span>
        </div>
      </Panel>
    )
  }
  if (error && !detail) return <Panel className="p-8"><EmptyBlock label={`Topology unavailable: ${error}`} /></Panel>
  if (!topology || topology.zones.length === 0) return <Panel className="p-8"><EmptyBlock label="No environments discovered yet — the topology heat map renders your real asset zones once discovery runs." /></Panel>

  const total = HEAT_ORDER.reduce((sum, key) => sum + topology.totals[key], 0)

  return (
    <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {HEAT_ORDER.map((status) => {
          const h = heatColor(status)
          return (
            <div key={status}>
              <MetricTile
                label={h.label}
                value={fmt(topology.totals[status])}
                detail={total > 0 ? `${Math.round((topology.totals[status] / total) * 100)}% of assets` : '--'}
                icon={status === 'ready' ? ShieldCheck : status === 'attention' ? Shield : ShieldAlert}
                color={h.color}
              />
            </div>
          )
        })}
      </div>

      <Panel className="p-5">
        <SectionHead icon={MapIcon} suffix={
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-3">
              {HEAT_ORDER.map((status) => {
                const h = heatColor(status)
                return (
                  <span key={status} className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-wider text-white/40">
                    <span className="h-2 w-2 rounded-full" style={{ background: h.color, boxShadow: `0 0 8px ${h.color}88` }} />
                    {h.label}
                  </span>
                )
              })}
            </div>
            <ActionBtn icon={RefreshCw} label={loading ? 'Refreshing' : 'Refresh'} onClick={reload} disabled={loading} small />
          </div>
        }>Environment Topology — Migration Risk Heat Map</SectionHead>

        <div className="space-y-4">
          {topology.zones.map((zone) => {
            const zoneTotal = HEAT_ORDER.reduce((sum, key) => sum + zone.counts[key], 0)
            return (
              <div key={zone.environment} className="rounded-xl border border-white/8 bg-white/[0.015] p-4">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Globe2 className="h-4 w-4 text-gold" />
                    <span className="text-sm font-black capitalize text-white">{zone.environment}</span>
                    <Pill className="border-white/10 bg-white/5 text-white/40">{fmt(zoneTotal)} assets</Pill>
                  </div>
                  <div className="flex items-center gap-2">
                    {HEAT_ORDER.filter((status) => zone.counts[status] > 0).map((status) => {
                      const h = heatColor(status)
                      return <span key={status}><Pill className={h.badge}>{fmt(zone.counts[status])} {h.label.toLowerCase()}</Pill></span>
                    })}
                  </div>
                </div>

                <div className="mb-3 flex h-2 w-full overflow-hidden rounded-full bg-white/5">
                  {HEAT_ORDER.map((status) => {
                    const share = zoneTotal > 0 ? (zone.counts[status] / zoneTotal) * 100 : 0
                    if (share === 0) return null
                    return <div key={status} style={{ width: `${share}%`, background: heatColor(status).color }} />
                  })}
                </div>

                <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                  {zone.assets.map((asset) => {
                    const h = heatColor(asset.status)
                    return (
                      <div key={asset.id} className="flex items-center gap-2 rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2">
                        <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: h.color, boxShadow: `0 0 8px ${h.color}88` }} />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-[11px] font-bold text-white/75">{asset.name}</div>
                          <div className="truncate text-[9px] text-white/30">{asset.component} · business criticality: {asset.criticality}</div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
        <p className="mt-4 text-[10px] leading-relaxed text-white/30">
          Heat status derives from real evidence: red = critical exposures block migration, orange = concentrated vulnerable inventory or expiring certificates, yellow = open vulnerabilities or missing evidence, green = validated / no open crypto risk. Generated {relTime(detail?.generatedAt || null)}.
        </p>
      </Panel>
    </>
  )
}
