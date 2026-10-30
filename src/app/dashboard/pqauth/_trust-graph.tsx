'use client';

import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Crosshair, Info, KeyRound, ListTree, Minus, Network, Plus, RotateCcw, Server, ShieldCheck, Fingerprint } from 'lucide-react';
import { cn } from '@/lib/utils';
import { SLATE, fullTimestamp, relativeTime } from '../_components/intel/kit';
import type { PQAuthEdgeConfidence, PQAuthGraphEdge, PQAuthGraphNode, PQAuthGraphNodeKind, PQAuthSnapshot } from '@/types/pqauth-dashboard';
import {
  Badge, CLASS_META, CONFIDENCE_META, Card, ClassBadge, EvidenceUrl, Field, Notice, Pager, Reveal, RouteLink, SearchBox, td, th, usePaged,
  ink,
} from './_ui';

const KIND_ORDER: PQAuthGraphNodeKind[] = ['certificate', 'asset', 'provider', 'key'];
const KIND_LABEL: Record<PQAuthGraphNodeKind, string> = { certificate: 'Trust material', asset: 'Assets', provider: 'Identity providers', key: 'Signing keys' };
const KIND_GLYPH: Record<PQAuthGraphNodeKind, string> = { certificate: '▣', asset: '◼', provider: '◆', key: '⚿' };
const KIND_ICON = { certificate: ShieldCheck, asset: Server, provider: Fingerprint, key: KeyRound } as const;

const COL_W = 300;
const NODE_W = 230;
const NODE_H = 54;
const ROW_H = 70;
const HEADER = 44;
const PAD = 24;

type Positioned = PQAuthGraphNode & { x: number; y: number };

/**
 * Deterministic layered layout: trust material · assets · providers · keys.
 * Rows are ordered by the provider each node connects to, which keeps edges
 * mostly horizontal. Positions are layout only — they carry no meaning.
 */
function layout(nodes: PQAuthGraphNode[], edges: PQAuthGraphEdge[]) {
  const columns = KIND_ORDER.filter((kind) => nodes.some((n) => n.kind === kind));
  const providers = nodes.filter((n) => n.kind === 'provider').sort((a, b) => a.label.localeCompare(b.label));
  const providerIndex = new Map(providers.map((p, i) => [p.id, i]));
  const neighbours = new Map<string, string[]>();
  for (const e of edges) {
    neighbours.set(e.from, [...(neighbours.get(e.from) ?? []), e.to]);
    neighbours.set(e.to, [...(neighbours.get(e.to) ?? []), e.from]);
  }
  const rank = (node: PQAuthGraphNode, depth = 0): number => {
    if (node.kind === 'provider') return providerIndex.get(node.id) ?? 0;
    if (depth > 2) return 999;
    const ranks = (neighbours.get(node.id) ?? []).map((id) => nodes.find((n) => n.id === id)).filter(Boolean).map((n) => rank(n as PQAuthGraphNode, depth + 1));
    return ranks.length ? Math.min(...ranks) : 999;
  };
  const positioned: Positioned[] = [];
  let maxRows = 0;
  columns.forEach((kind, col) => {
    const members = nodes.filter((n) => n.kind === kind).sort((a, b) => rank(a) - rank(b) || a.label.localeCompare(b.label));
    maxRows = Math.max(maxRows, members.length);
    members.forEach((node, row) => positioned.push({ ...node, x: PAD + col * COL_W, y: HEADER + row * ROW_H }));
  });
  return {
    columns,
    positioned,
    width: PAD * 2 + Math.max(1, columns.length) * COL_W - (COL_W - NODE_W),
    height: HEADER + Math.max(1, maxRows) * ROW_H + PAD,
  };
}

export function TrustGraphView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const { graph } = snapshot.identity;
  const [params] = useSearchParams();
  const [selected, setSelected] = useState<string | null>(params.get('focus'));
  const [hovered, setHovered] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [confidences, setConfidences] = useState<Set<PQAuthEdgeConfidence>>(new Set(['observed', 'declared', 'inferred', 'unresolved']));
  const [kinds, setKinds] = useState<Set<PQAuthGraphNodeKind>>(new Set(KIND_ORDER));
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const frame = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const focus = params.get('focus');
    if (focus) setSelected(focus);
  }, [params]);

  const visibleNodes = useMemo(() => graph.nodes.filter((n) => kinds.has(n.kind)), [graph.nodes, kinds]);
  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);
  const visibleEdges = useMemo(() => graph.edges.filter((e) => confidences.has(e.confidence) && visibleIds.has(e.from) && visibleIds.has(e.to)), [graph.edges, confidences, visibleIds]);
  const { positioned, columns, width, height } = useMemo(() => layout(visibleNodes, visibleEdges), [visibleNodes, visibleEdges]);
  const byId = useMemo(() => new Map(positioned.map((n) => [n.id, n])), [positioned]);

  const focusId = hovered ?? selected;
  const neighbourhood = useMemo(() => {
    if (!focusId) return null;
    const ids = new Set([focusId]);
    for (const e of visibleEdges) {
      if (e.from === focusId) ids.add(e.to);
      if (e.to === focusId) ids.add(e.from);
    }
    return ids;
  }, [focusId, visibleEdges]);
  const q = query.trim().toLowerCase();
  const matches = (n: PQAuthGraphNode) => !q || `${n.label} ${n.sublabel}`.toLowerCase().includes(q);

  // Ctrl/⌘ + wheel zooms; a plain wheel keeps scrolling the page.
  useEffect(() => {
    const el = frame.current;
    if (!el) return;
    const onWheel = (event: WheelEvent) => {
      if (!event.ctrlKey && !event.metaKey) return;
      event.preventDefault();
      setView((v) => ({ ...v, k: Math.min(2.5, Math.max(0.4, v.k * (event.deltaY < 0 ? 1.1 : 0.9))) }));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, []);

  const onPointerDown = (event: ReactPointerEvent<SVGSVGElement>) => {
    if ((event.target as Element).closest('[data-node]')) return;
    drag.current = { x: event.clientX, y: event.clientY, vx: view.x, vy: view.y };
    (event.currentTarget as Element).setPointerCapture?.(event.pointerId);
  };
  const onPointerMove = (event: ReactPointerEvent<SVGSVGElement>) => {
    if (!drag.current) return;
    const d = drag.current;
    setView((v) => ({ ...v, x: d.vx + (event.clientX - d.x) / v.k, y: d.vy + (event.clientY - d.y) / v.k }));
  };
  const endDrag = () => { drag.current = null; };

  const toggleIn = <T,>(set: Set<T>, value: T, update: (s: Set<T>) => void) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    update(next);
  };

  if (!graph.nodes.length) {
    return (
      <Card title="Identity trust graph" icon={Network}>
        <Notice tone="info" icon={Info} title="No trust relationships have been observed">
          The graph is drawn only from recorded evidence: identity metadata read from your hosts, the signing keys those providers publish, the assets that declare
          trust in them, and their certificates. Nothing is drawn until discovery records it.
        </Notice>
        <div className="mt-3"><RouteLink to="/dashboard/pqauth/discovery">Run identity discovery</RouteLink></div>
      </Card>
    );
  }

  const selectedNode = selected ? graph.nodes.find((n) => n.id === selected) ?? null : null;
  const selectedEdges = selectedNode ? graph.edges.filter((e) => e.from === selectedNode.id || e.to === selectedNode.id) : [];
  const nodeLabel = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;

  return (
    <div className="space-y-4">
      <Reveal className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_380px]">
        <Card
          title="Identity trust graph"
          icon={Network}
          meta={`${visibleNodes.length} nodes · ${visibleEdges.length} edges`}
          action={(
            <div className="flex items-center gap-1" role="group" aria-label="Zoom">
              <button type="button" aria-label="Zoom out" onClick={() => setView((v) => ({ ...v, k: Math.max(0.4, v.k * 0.85) }))} className="grid h-7 w-7 place-items-center rounded-md border border-white/12 bg-white/[0.04] text-white/60 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"><Minus className="h-3.5 w-3.5" aria-hidden="true" /></button>
              <span className="w-11 text-center font-mono text-[10px] text-white/45">{Math.round(view.k * 100)}%</span>
              <button type="button" aria-label="Zoom in" onClick={() => setView((v) => ({ ...v, k: Math.min(2.5, v.k * 1.15) }))} className="grid h-7 w-7 place-items-center rounded-md border border-white/12 bg-white/[0.04] text-white/60 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"><Plus className="h-3.5 w-3.5" aria-hidden="true" /></button>
              <button type="button" aria-label="Reset view" onClick={() => setView({ k: 1, x: 0, y: 0 })} className="grid h-7 w-7 place-items-center rounded-md border border-white/12 bg-white/[0.04] text-white/60 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"><RotateCcw className="h-3.5 w-3.5" aria-hidden="true" /></button>
            </div>
          )}
        >
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <SearchBox value={query} onChange={setQuery} placeholder="Find a host, issuer, kid or algorithm…" label="Search the graph" />
            <div role="group" aria-label="Edge confidence" className="flex flex-wrap gap-1.5">
              {(Object.keys(CONFIDENCE_META) as PQAuthEdgeConfidence[]).map((c) => {
                const meta = CONFIDENCE_META[c];
                const on = confidences.has(c);
                const count = graph.edges.filter((e) => e.confidence === c).length;
                return (
                  <button key={c} type="button" aria-pressed={on} title={meta.hint} onClick={() => toggleIn(confidences, c, setConfidences)}
                    className={cn('rounded-full border px-2.5 py-1 text-[9.5px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70', on ? '' : 'opacity-40')}
                    style={{ borderColor: `${meta.hex}55`, color: ink(meta.hex), backgroundColor: on ? `${meta.hex}14` : 'transparent' }}>
                    {meta.glyph} {meta.label} <span className="font-mono">{count}</span>
                  </button>
                );
              })}
            </div>
          </div>
          <div role="group" aria-label="Node types" className="mb-3 flex flex-wrap gap-1.5">
            {KIND_ORDER.filter((k) => graph.nodes.some((n) => n.kind === k)).map((k) => (
              <button key={k} type="button" aria-pressed={kinds.has(k)} onClick={() => toggleIn(kinds, k, setKinds)}
                className={cn('rounded-full border border-white/12 px-2.5 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/60 transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70', kinds.has(k) ? 'bg-white/[0.06]' : 'opacity-40')}>
                {KIND_GLYPH[k]} {KIND_LABEL[k]} <span className="font-mono text-white/50">{graph.nodes.filter((n) => n.kind === k).length}</span>
              </button>
            ))}
          </div>

          {/* SVG fills are not reached by the shell's Tailwind light-theme overrides; CSS beats the presentation attribute. */}
          <style>{`.qg-theme-light .pqauth-node { fill: rgba(255,255,255,0.97); }`}</style>
          <div ref={frame} className="relative overflow-hidden rounded-xl border border-white/10 bg-black/25" style={{ height: Math.min(640, Math.max(320, height * 0.9)) }}>
            <svg
              role="img"
              aria-label={`Identity trust graph with ${visibleNodes.length} nodes and ${visibleEdges.length} relationships. Use the node list below the graph for keyboard navigation.`}
              className="h-full w-full cursor-grab touch-none select-none active:cursor-grabbing"
              viewBox={`0 0 ${width} ${height}`}
              preserveAspectRatio="xMidYMin meet"
              onPointerDown={onPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={endDrag}
              onPointerLeave={endDrag}
              onClick={(event) => { if (!(event.target as Element).closest('[data-node]')) setSelected(null); }}
            >
              <defs>
                {(Object.keys(CONFIDENCE_META) as PQAuthEdgeConfidence[]).map((c) => (
                  <marker key={c} id={`pqauth-arrow-${c}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                    <path d="M0,0 L10,5 L0,10 z" fill={CONFIDENCE_META[c].hex} />
                  </marker>
                ))}
              </defs>
              <g transform={`scale(${view.k}) translate(${view.x} ${view.y})`}>
                {columns.map((kind, col) => (
                  <text key={kind} x={PAD + col * COL_W} y={22} fill="currentColor" className="text-white/50" fontSize="10" fontWeight={900} letterSpacing="2">
                    {KIND_LABEL[kind].toUpperCase()}
                  </text>
                ))}
                {visibleEdges.map((edge) => {
                  const a = byId.get(edge.from);
                  const b = byId.get(edge.to);
                  if (!a || !b) return null;
                  const meta = CONFIDENCE_META[edge.confidence];
                  const lit = !neighbourhood || (neighbourhood.has(edge.from) && neighbourhood.has(edge.to) && (edge.from === focusId || edge.to === focusId));
                  const forward = a.x <= b.x;
                  const sx = forward ? a.x + NODE_W : a.x;
                  const tx = forward ? b.x : b.x + NODE_W;
                  const sy = a.y + NODE_H / 2;
                  const ty = b.y + NODE_H / 2;
                  const sameColumn = a.x === b.x;
                  const d = sameColumn
                    ? `M${a.x + NODE_W},${sy} C${a.x + NODE_W + 60},${sy} ${b.x + NODE_W + 60},${ty} ${b.x + NODE_W},${ty}`
                    : `M${sx},${sy} C${(sx + tx) / 2},${sy} ${(sx + tx) / 2},${ty} ${tx},${ty}`;
                  return (
                    <g key={edge.id} style={{ opacity: lit ? 1 : 0.12, transition: 'opacity 200ms ease' }}>
                      <path d={d} fill="none" stroke={meta.hex} strokeWidth={lit && neighbourhood ? 2.2 : 1.4} strokeDasharray={meta.dash || undefined} markerEnd={`url(#pqauth-arrow-${edge.confidence})`}>
                        <title>{`${nodeLabel(edge.from)} → ${nodeLabel(edge.to)}: ${edge.label} (${meta.label}). ${edge.evidence}`}</title>
                      </path>
                      {lit && neighbourhood ? (
                        <text x={(sx + tx) / 2 + (sameColumn ? 70 : 0)} y={(sy + ty) / 2 - 5} textAnchor="middle" fontSize="9.5" style={{ fill: ink(meta.hex) }} fontWeight={700}>{edge.label}</text>
                      ) : null}
                    </g>
                  );
                })}
                {positioned.map((node) => {
                  const meta = CLASS_META[node.status];
                  const isSelected = node.id === selected;
                  const dim = (neighbourhood && !neighbourhood.has(node.id)) || !matches(node);
                  const stroke = node.kind === 'asset' ? SLATE : meta.hex;
                  return (
                    <g
                      key={node.id}
                      data-node
                      transform={`translate(${node.x} ${node.y})`}
                      style={{ opacity: dim ? 0.22 : 1, transition: 'opacity 200ms ease', cursor: 'pointer' }}
                      onMouseEnter={() => setHovered(node.id)}
                      onMouseLeave={() => setHovered(null)}
                      onClick={() => setSelected((c) => (c === node.id ? null : node.id))}
                    >
                      <rect width={NODE_W} height={NODE_H} rx={11} fill="rgba(11,20,36,0.92)" className="pqauth-node" stroke={stroke} strokeOpacity={isSelected ? 1 : 0.55} strokeWidth={isSelected ? 2.4 : 1.2} />
                      <rect width={4} height={NODE_H - 16} x={0} y={8} rx={2} fill={stroke} />
                      <text x={14} y={21} fontSize="12" fontWeight={800} fill="currentColor" className="text-white">{KIND_GLYPH[node.kind]} {node.label.length > 26 ? `${node.label.slice(0, 25)}…` : node.label}</text>
                      <text x={14} y={38} fontSize="9.5" fill="currentColor" className="text-white/45">{node.sublabel.length > 40 ? `${node.sublabel.slice(0, 39)}…` : node.sublabel}</text>
                      {node.kind !== 'asset' ? <text x={NODE_W - 10} y={21} textAnchor="end" fontSize="11" style={{ fill: ink(meta.hex) }}>{meta.glyph}</text> : null}
                      <title>{`${node.label} — ${node.sublabel}${node.kind !== 'asset' ? ` · ${meta.label}` : ''}`}</title>
                    </g>
                  );
                })}
              </g>
            </svg>
            <span className="pointer-events-none absolute bottom-2 left-3 text-[9.5px] text-white/50">Drag to pan · Ctrl/⌘ + scroll to zoom · click a node for evidence</span>
          </div>

          {/* Legend */}
          <div className="mt-3 grid gap-3 rounded-xl border border-white/10 bg-white/[0.02] p-3 md:grid-cols-2">
            <div>
              <div className="mb-1.5 text-[8.5px] font-black uppercase tracking-[0.18em] text-white/50">Relationship evidence</div>
              <ul className="space-y-1">
                {(Object.keys(CONFIDENCE_META) as PQAuthEdgeConfidence[]).map((c) => (
                  <li key={c} className="flex items-center gap-2 text-[10.5px] text-white/55">
                    <svg width="34" height="8" aria-hidden="true"><line x1="0" y1="4" x2="34" y2="4" stroke={CONFIDENCE_META[c].hex} strokeWidth="2" strokeDasharray={CONFIDENCE_META[c].dash || undefined} /></svg>
                    <span className="font-bold" style={{ color: ink(CONFIDENCE_META[c].hex) }}>{CONFIDENCE_META[c].label}</span> — {CONFIDENCE_META[c].hint}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="mb-1.5 text-[8.5px] font-black uppercase tracking-[0.18em] text-white/50">Node posture</div>
              <div className="flex flex-wrap gap-1.5">{(['safe', 'hybrid', 'vulnerable', 'unknown'] as const).map((c) => <ClassBadge key={c} value={c} />)}</div>
              <p className="mt-2 text-[10px] leading-relaxed text-white/50">
                Edges show what is published or recorded. They do not assert that a live authentication or token validation succeeded — failed trust validations
                are not captured by discovery, so no edge is ever marked “failed”.
              </p>
            </div>
          </div>
        </Card>

        <Card title={selectedNode ? 'Selected node' : 'Node evidence'} icon={Crosshair}>
          {selectedNode ? (
            <NodeDetail node={selectedNode} edges={selectedEdges} nodeLabel={nodeLabel} onSelect={setSelected} />
          ) : (
            <p className="text-[11px] leading-relaxed text-white/45">
              Select a node to see its source record, the evidence behind each relationship, and links to the asset or provider it represents.
            </p>
          )}
          <NodeList nodes={visibleNodes} selected={selected} onSelect={setSelected} />
        </Card>
      </Reveal>

      <Reveal delay={0.06}>
        <EdgeLedger edges={graph.edges} nodeLabel={nodeLabel} onSelect={setSelected} />
      </Reveal>
    </div>
  );
}

function NodeDetail({ node, edges, nodeLabel, onSelect }: { node: PQAuthGraphNode; edges: PQAuthGraphEdge[]; nodeLabel: (id: string) => string; onSelect: (id: string) => void }) {
  const Icon = KIND_ICON[node.kind];
  return (
    <div className="space-y-3">
      <div className="flex items-start gap-3">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-white/12 bg-white/[0.04] text-cyan-300"><Icon className="h-4 w-4" aria-hidden="true" /></span>
        <div className="min-w-0">
          <div className="break-words text-[13px] font-black text-white">{node.label}</div>
          <div className="break-words text-[10.5px] text-white/45">{node.sublabel}</div>
        </div>
      </div>
      <dl>
        <Field label="Type">{KIND_LABEL[node.kind]}</Field>
        {node.kind !== 'asset' ? <Field label="Posture"><ClassBadge value={node.status} /></Field> : null}
        <Field label="Source record">{node.sourceTable} · <span className="font-mono text-white/45">{node.refId.slice(0, 8)}</span></Field>
        <Field label="Evidence URL"><EvidenceUrl url={node.sourceUrl} /></Field>
        <Field label="Last observed"><span title={fullTimestamp(node.lastSeenAt)}>{node.lastSeenAt ? relativeTime(node.lastSeenAt) : 'Not recorded'}</span></Field>
      </dl>
      <div className="flex flex-wrap gap-1.5">
        {node.assetId ? <RouteLink to="/dashboard/assets" tone="ghost">Asset inventory</RouteLink> : null}
        {node.kind === 'provider' || node.kind === 'key' ? <RouteLink to="/dashboard/pqauth/token-intelligence" tone="ghost">Token intelligence</RouteLink> : null}
        {node.kind === 'certificate' ? <RouteLink to="/dashboard/certificates" tone="ghost">Certificates</RouteLink> : null}
      </div>
      <div>
        <div className="mb-1.5 text-[8.5px] font-black uppercase tracking-[0.18em] text-white/50">Relationships ({edges.length})</div>
        <ul className="space-y-1.5">
          {edges.map((e) => {
            const other = e.from === node.id ? e.to : e.from;
            const meta = CONFIDENCE_META[e.confidence];
            return (
              <li key={e.id} className="rounded-lg border border-white/10 bg-white/[0.02] p-2.5">
                <div className="flex items-center justify-between gap-2">
                  <button type="button" onClick={() => onSelect(other)} className="min-w-0 truncate text-left text-[11px] font-bold text-white hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                    {e.from === node.id ? '→' : '←'} {e.label} · {nodeLabel(other)}
                  </button>
                  <Badge meta={meta} />
                </div>
                <p className="mt-1 text-[10px] leading-relaxed text-white/45">{e.evidence}</p>
                {e.sourceUrl ? <div className="mt-1"><EvidenceUrl url={e.sourceUrl} /></div> : null}
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}

/** Keyboard-operable alternative to the SVG: every node is a button. */
function NodeList({ nodes, selected, onSelect }: { nodes: PQAuthGraphNode[]; selected: string | null; onSelect: (id: string) => void }) {
  return (
    <details className="mt-4 rounded-xl border border-white/10 bg-white/[0.02]">
      <summary className="cursor-pointer px-3 py-2 text-[9.5px] font-black uppercase tracking-wider text-white/55 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
        <ListTree className="mr-1.5 inline h-3.5 w-3.5" aria-hidden="true" />Node list ({nodes.length})
      </summary>
      <ul className="max-h-[260px] space-y-1 overflow-y-auto px-2 pb-2">
        {nodes.map((n) => (
          <li key={n.id}>
            <button type="button" aria-pressed={selected === n.id} onClick={() => onSelect(n.id)} className={cn('flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-[11px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70', selected === n.id ? 'bg-cyan-500/15 text-cyan-200' : 'text-white/65 hover:bg-white/[0.05]')}>
              <span className="truncate">{KIND_GLYPH[n.kind]} {n.label}</span>
              {n.kind !== 'asset' ? <span aria-label={CLASS_META[n.status].label} style={{ color: ink(CLASS_META[n.status].hex) }}>{CLASS_META[n.status].glyph}</span> : null}
            </button>
          </li>
        ))}
      </ul>
    </details>
  );
}

function EdgeLedger({ edges, nodeLabel, onSelect }: { edges: PQAuthGraphEdge[]; nodeLabel: (id: string) => string; onSelect: (id: string) => void }) {
  const [query, setQuery] = useState('');
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return edges.filter((e) => !q || `${nodeLabel(e.from)} ${nodeLabel(e.to)} ${e.label} ${e.confidence} ${e.evidence}`.toLowerCase().includes(q));
  }, [edges, query, nodeLabel]);
  const paged = usePaged(filtered, 10);
  return (
    <Card title="Relationship evidence ledger" icon={Info} meta={`${edges.length} relationship(s)`}>
      <div className="mb-3"><SearchBox value={query} onChange={setQuery} placeholder="Filter relationships…" label="Filter relationships" /></div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px]">
          <thead><tr className="border-b border-white/10"><th className={th()}>From</th><th className={th()}>Relationship</th><th className={th()}>To</th><th className={th()}>Evidence</th><th className={th()}>Source</th></tr></thead>
          <tbody>
            {paged.slice.map((e) => (
              <tr key={e.id} className="border-b border-white/[0.05] last:border-0">
                <td className={td()}><button type="button" onClick={() => onSelect(e.from)} className="text-left font-semibold text-white hover:text-cyan-200">{nodeLabel(e.from)}</button></td>
                <td className={td()}><div>{e.label}</div><Badge meta={CONFIDENCE_META[e.confidence]} /></td>
                <td className={td()}><button type="button" onClick={() => onSelect(e.to)} className="text-left font-semibold text-white hover:text-cyan-200">{nodeLabel(e.to)}</button></td>
                <td className={td('max-w-[320px] text-white/55')}>{e.evidence}</td>
                <td className={td('text-white/45')}><div className="font-mono text-[10px]">{e.sourceTable}</div>{e.sourceUrl ? <EvidenceUrl url={e.sourceUrl} /> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!paged.total ? <p className="py-4 text-center text-[11px] text-white/50">No relationship matches the filter.</p> : null}
      <Pager page={paged.page} pages={paged.pages} total={paged.total} setPage={paged.setPage} />
      <p className="mt-2 text-[10px] text-white/50">
        Node positions are layout only. Every edge above names its source table — <Link to="/dashboard/pqauth/discovery" className="text-cyan-300">re-run discovery</Link> to refresh observed and declared relationships.
      </p>
    </Card>
  );
}
