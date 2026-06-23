'use client';

import { useMemo, useState } from 'react';
import {
  Crosshair,
  Download,
  Filter,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Workflow,
  X,
} from 'lucide-react';
import {
  Badge,
  EmptyState,
  HeaderButton,
  Panel,
  QuantumReadinessShell,
  SectionTitle,
  integerFmt,
  riskTone,
  useQuantumReadiness,
  BLUE,
  CYAN,
  EMERALD,
  ORANGE,
  RED,
  AMBER,
} from '../_shared';

type GraphNode = ReturnType<typeof useQuantumReadiness>['snapshot']['exposureGraph']['nodes'][number];

const POSTURE_COLOR: Record<string, string> = {
  pqc: EMERALD,
  hybrid: AMBER,
  vulnerable: RED,
};

const POSTURE_LABEL: Record<string, string> = {
  pqc: 'PQC-Ready',
  hybrid: 'Hybrid / In-Progress',
  vulnerable: 'Quantum-Vulnerable',
};

type PostureFilter = 'all' | 'pqc' | 'hybrid' | 'vulnerable';

export default function ExposureGraphPage() {
  const { snapshot, state, sseConnected, refresh, downloadJson } = useQuantumReadiness();
  const [filter, setFilter] = useState<PostureFilter>('all');
  const [selected, setSelected] = useState<string | null>(null);

  const { nodes, edges } = snapshot.exposureGraph;

  const filteredNodes = useMemo(() => (filter === 'all' ? nodes : nodes.filter((n) => n.posture === filter)), [nodes, filter]);

  // Deterministic radial layout grouped by posture.
  const layout = useMemo(() => {
    const W = 920;
    const H = 540;
    const cx = W / 2;
    const cy = H / 2;
    const groups: Record<string, GraphNode[]> = { vulnerable: [], hybrid: [], pqc: [], unknown: [] };
    for (const n of filteredNodes) (groups[n.posture] || groups.unknown).push(n);
    const ring: Record<string, number> = { vulnerable: 110, hybrid: 200, pqc: 250, unknown: 250 };
    const positions = new Map<string, { x: number; y: number }>();
    (Object.keys(groups) as string[]).forEach((key) => {
      const list = groups[key];
      const radius = ring[key] ?? 230;
      list.forEach((node, index) => {
        const angle = (index / Math.max(1, list.length)) * Math.PI * 2 + (key === 'hybrid' ? 0.5 : key === 'pqc' ? 1.1 : 0);
        positions.set(node.id, { x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius });
      });
    });
    return { W, H, positions };
  }, [filteredNodes]);

  const visibleIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);
  const visibleEdges = useMemo(() => edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target)), [edges, visibleIds]);

  // Blast radius — direct neighbours of selected node.
  const blastRadius = useMemo(() => {
    if (!selected) return new Set<string>();
    const set = new Set<string>([selected]);
    for (const e of edges) {
      if (e.source === selected) set.add(e.target);
      if (e.target === selected) set.add(e.source);
    }
    return set;
  }, [selected, edges]);

  const selectedNode = useMemo(() => nodes.find((n) => n.id === selected) || null, [nodes, selected]);

  const counts = useMemo(() => {
    let pqc = 0;
    let hybrid = 0;
    let vulnerable = 0;
    for (const n of nodes) {
      if (n.posture === 'pqc') pqc += 1;
      else if (n.posture === 'hybrid') hybrid += 1;
      else if (n.posture === 'vulnerable') vulnerable += 1;
    }
    return { pqc, hybrid, vulnerable, total: nodes.length };
  }, [nodes]);

  return (
    <QuantumReadinessShell
      title="Quantum Exposure Graph™"
      subtitle="Visualize dependency relationships between assets, cryptographic posture and trust chains. Select a node to inspect its blast radius and quantum exposure."
      badge={<Badge color={CYAN}>{integerFmt(counts.total)} nodes · {integerFmt(edges.length)} edges</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh
          </HeaderButton>
          <HeaderButton icon={Download} onClick={() => downloadJson('quantum-exposure-graph', snapshot.exposureGraph)}>
            Export Graph
          </HeaderButton>
        </>
      }
    >
      {/* Legend / filters */}
      <Panel className="p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Filter className="h-4 w-4 text-white/40" />
            {([
              { key: 'all', label: `All (${counts.total})`, color: BLUE },
              { key: 'vulnerable', label: `Vulnerable (${counts.vulnerable})`, color: RED },
              { key: 'hybrid', label: `Hybrid (${counts.hybrid})`, color: AMBER },
              { key: 'pqc', label: `PQC-Ready (${counts.pqc})`, color: EMERALD },
            ] as Array<{ key: PostureFilter; label: string; color: string }>).map((chip) => (
              <button
                key={chip.key}
                type="button"
                onClick={() => setFilter(chip.key)}
                className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[11px] font-bold transition ${
                  filter === chip.key ? 'border-blue-400/50 bg-blue-500/15 text-blue-100' : 'border-white/10 bg-black/20 text-white/60 hover:border-blue-400/35'
                }`}
              >
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: chip.color }} />
                {chip.label}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-4 text-[11px] text-white/45">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: RED }} /> Quantum-Vulnerable
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: AMBER }} /> Hybrid
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: EMERALD }} /> PQC-Ready
            </span>
          </div>
        </div>
      </Panel>

      {/* Graph + details */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-3 xl:col-span-8">
          {filteredNodes.length ? (
            <svg viewBox={`0 0 ${layout.W} ${layout.H}`} className="h-[540px] w-full" role="img" aria-label="Quantum exposure dependency graph">
              {/* edges */}
              {visibleEdges.map((edge, index) => {
                const a = layout.positions.get(edge.source);
                const b = layout.positions.get(edge.target);
                if (!a || !b) return null;
                const active = selected ? edge.source === selected || edge.target === selected : false;
                return (
                  <line
                    key={`${edge.source}-${edge.target}-${index}`}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke={active ? CYAN : 'rgba(255,255,255,0.10)'}
                    strokeWidth={active ? 1.8 : 1}
                  />
                );
              })}
              {/* nodes */}
              {filteredNodes.map((node) => {
                const pos = layout.positions.get(node.id);
                if (!pos) return null;
                const color = POSTURE_COLOR[node.posture] || BLUE;
                const dimmed = selected && !blastRadius.has(node.id);
                const isSelected = selected === node.id;
                const r = 6 + Math.min(10, node.riskScore / 12);
                return (
                  <g key={node.id} className="cursor-pointer" opacity={dimmed ? 0.25 : 1} onClick={() => setSelected(isSelected ? null : node.id)}>
                    {isSelected ? <circle cx={pos.x} cy={pos.y} r={r + 6} fill="none" stroke={color} strokeWidth="1.5" opacity="0.5" /> : null}
                    <circle cx={pos.x} cy={pos.y} r={r} fill={`${color}28`} stroke={color} strokeWidth="1.8" />
                    {node.internetFacing ? <circle cx={pos.x + r * 0.7} cy={pos.y - r * 0.7} r="2.5" fill={ORANGE} /> : null}
                    {(isSelected || node.riskScore >= 70) && (
                      <text x={pos.x} y={pos.y + r + 11} textAnchor="middle" fill="rgba(255,255,255,0.7)" fontSize="9">
                        {node.label.length > 16 ? `${node.label.slice(0, 16)}…` : node.label}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
          ) : (
            <EmptyState label="No assets in the exposure graph." hint="Discover assets and dependencies to populate the graph." />
          )}
        </Panel>

        <Panel className="p-5 xl:col-span-4">
          {selectedNode ? (
            <div>
              <div className="mb-4 flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Network className="h-4 w-4 text-cyan-300" />
                  <h2 className="text-xs font-black uppercase tracking-[0.10em] text-white">Node Details</h2>
                </div>
                <button type="button" onClick={() => setSelected(null)} className="rounded p-1 text-white/40 transition hover:text-white">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="space-y-3">
                <div>
                  <div className="text-sm font-bold text-white">{selectedNode.label}</div>
                  <div className="text-[11px] text-white/45">{selectedNode.type} · {selectedNode.environment}</div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge color={POSTURE_COLOR[selectedNode.posture] || BLUE}>{POSTURE_LABEL[selectedNode.posture] || 'Unknown'}</Badge>
                  {selectedNode.internetFacing ? <Badge color={ORANGE}>Internet-Facing</Badge> : null}
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <DetailStat label="Risk Score" value={integerFmt(selectedNode.riskScore)} color={riskTone(selectedNode.riskScore)} />
                  <DetailStat label="Blast Radius" value={integerFmt(Math.max(0, blastRadius.size - 1))} color={CYAN} />
                </div>
                <div className="rounded-md border border-white/8 bg-black/20 p-3">
                  <div className="mb-2 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-white/45">
                    <Crosshair className="h-3.5 w-3.5" /> Connected Assets
                  </div>
                  {blastRadius.size > 1 ? (
                    <div className="space-y-1.5">
                      {[...blastRadius]
                        .filter((id) => id !== selectedNode.id)
                        .slice(0, 8)
                        .map((id) => {
                          const node = nodes.find((n) => n.id === id);
                          if (!node) return null;
                          const color = POSTURE_COLOR[node.posture] || BLUE;
                          return (
                            <button key={id} type="button" onClick={() => setSelected(id)} className="flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-left text-[11px] transition hover:bg-white/5">
                              <span className="inline-flex items-center gap-1.5 truncate text-white/70">
                                <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
                                {node.label}
                              </span>
                              <span className="font-mono text-white/45">{integerFmt(node.riskScore)}</span>
                            </button>
                          );
                        })}
                    </div>
                  ) : (
                    <div className="text-[11px] text-white/35">No direct dependencies recorded.</div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div>
              <SectionTitle>Exposure Summary</SectionTitle>
              <div className="space-y-2.5">
                {[
                  { label: 'Quantum-Vulnerable', value: counts.vulnerable, color: RED, icon: ShieldAlert },
                  { label: 'Hybrid / In-Progress', value: counts.hybrid, color: AMBER, icon: Workflow },
                  { label: 'PQC-Ready', value: counts.pqc, color: EMERALD, icon: ShieldCheck },
                ].map((row) => {
                  const Icon = row.icon;
                  const pct = counts.total ? Math.round((row.value / counts.total) * 100) : 0;
                  return (
                    <div key={row.label} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                      <div className="flex items-center justify-between">
                        <span className="inline-flex items-center gap-2 text-xs font-bold text-white/75">
                          <Icon className="h-4 w-4" style={{ color: row.color }} />
                          {row.label}
                        </span>
                        <span className="font-mono text-sm" style={{ color: row.color }}>
                          {integerFmt(row.value)}
                        </span>
                      </div>
                      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/5">
                        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: row.color }} />
                      </div>
                    </div>
                  );
                })}
              </div>
              <p className="mt-4 text-[11px] leading-relaxed text-white/45">
                Select any node in the graph to inspect its cryptographic posture, risk score and blast radius. Orange dots mark
                internet-facing assets.
              </p>
            </div>
          )}
        </Panel>
      </section>
    </QuantumReadinessShell>
  );
}

function DetailStat({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="rounded-md border border-white/8 bg-black/20 p-2.5">
      <div className="text-lg font-semibold" style={{ color }}>
        {value}
      </div>
      <div className="text-[10px] font-bold uppercase tracking-wide text-white/45">{label}</div>
    </div>
  );
}
