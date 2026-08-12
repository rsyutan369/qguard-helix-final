'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Crosshair, Filter, Maximize2, Minus, Plus, Share2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { CouplingGraph, CouplingLayer, CouplingNode, AgilityState } from '@/lib/crypto-agility/agility-intelligence';
import { COUPLING_LAYER_LABEL, COUPLING_LAYER_ORDER } from '@/lib/crypto-agility/agility-intelligence';
import { AGILITY_STATE_LABEL, STATE_GLYPH, STATE_HEX } from './_agility-lib';

/**
 * Crypto Dependency & Coupling Graph.
 *
 * Renders the layered projection the server builds from the tenant's existing
 * CBOM, certificate inventory, trust fabric and provider attribution:
 *
 *   Application → Crypto Library → Algorithm → Certificate → PKI/CA
 *              → Trust Anchor → Identity Provider → Vendor
 *
 * Interaction: zoom, pan, layer filter, node selection, dependency + risk
 * highlighting. Only the server-selected bounded node set is rendered, so a
 * large estate never ships every node to the browser (§32).
 */

const COL_WIDTH = 210;
const ROW_HEIGHT = 46;
const NODE_WIDTH = 172;
const NODE_HEIGHT = 32;
const PADDING = 28;

interface Positioned extends CouplingNode {
  x: number;
  y: number;
}

export function DependencyGraph({
  graph,
  selectedId,
  onSelect,
  riskOnly,
  onToggleRiskOnly,
}: {
  graph: CouplingGraph;
  selectedId: string | null;
  onSelect: (node: CouplingNode | null) => void;
  riskOnly: boolean;
  onToggleRiskOnly: () => void;
}) {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [hiddenLayers, setHiddenLayers] = useState<Set<CouplingLayer>>(new Set());
  const [hovered, setHovered] = useState<string | null>(null);
  const dragRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const visibleNodes = useMemo(() => {
    let nodes = graph.nodes.filter((n) => !hiddenLayers.has(n.layer));
    if (riskOnly) {
      const risky = new Set(nodes.filter((n) => n.agilityState === 'blocked' || n.agilityState === 'rigid' || n.risk >= 60).map((n) => n.id));
      // Keep the neighbours of risky nodes so a highlighted path stays readable.
      for (const edge of graph.edges) {
        if (risky.has(edge.source)) risky.add(edge.target);
        if (risky.has(edge.target)) risky.add(edge.source);
      }
      nodes = nodes.filter((n) => risky.has(n.id));
    }
    return nodes;
  }, [graph.nodes, graph.edges, hiddenLayers, riskOnly]);

  const layout = useMemo(() => {
    const byLayer = new Map<CouplingLayer, CouplingNode[]>();
    for (const node of visibleNodes) {
      const list = byLayer.get(node.layer) || [];
      list.push(node);
      byLayer.set(node.layer, list);
    }
    const activeLayers = COUPLING_LAYER_ORDER.filter((layer) => (byLayer.get(layer) || []).length > 0);
    const positioned: Positioned[] = [];
    let maxRows = 0;
    activeLayers.forEach((layer, columnIndex) => {
      const nodes = (byLayer.get(layer) || []).slice().sort((a, b) => b.risk - a.risk || a.label.localeCompare(b.label));
      maxRows = Math.max(maxRows, nodes.length);
      nodes.forEach((node, rowIndex) => {
        positioned.push({
          ...node,
          x: PADDING + columnIndex * COL_WIDTH,
          y: PADDING + 30 + rowIndex * ROW_HEIGHT,
        });
      });
    });
    return {
      nodes: positioned,
      activeLayers,
      width: PADDING * 2 + Math.max(1, activeLayers.length) * COL_WIDTH,
      height: PADDING * 2 + 40 + Math.max(1, maxRows) * ROW_HEIGHT,
    };
  }, [visibleNodes]);

  const nodeById = useMemo(() => new Map(layout.nodes.map((n) => [n.id, n])), [layout.nodes]);

  const edges = useMemo(
    () => graph.edges.filter((edge) => nodeById.has(edge.source) && nodeById.has(edge.target)),
    [graph.edges, nodeById],
  );

  /** Ids on a path touching the focused node — used for dependency highlighting. */
  const highlighted = useMemo(() => {
    const focus = hovered || selectedId;
    if (!focus) return null;
    const ids = new Set<string>([focus]);
    for (const edge of edges) {
      if (edge.source === focus) ids.add(edge.target);
      if (edge.target === focus) ids.add(edge.source);
    }
    return ids;
  }, [hovered, selectedId, edges]);

  const onWheel = useCallback((event: React.WheelEvent) => {
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault();
    setZoom((z) => Math.max(0.4, Math.min(2.5, z - event.deltaY * 0.0015)));
  }, []);

  const onPointerDown = (event: React.PointerEvent) => {
    if ((event.target as Element).closest('[data-graph-node]')) return;
    dragRef.current = { x: event.clientX, y: event.clientY, panX: pan.x, panY: pan.y };
    (event.currentTarget as Element).setPointerCapture(event.pointerId);
  };
  const onPointerMove = (event: React.PointerEvent) => {
    const drag = dragRef.current;
    if (!drag) return;
    setPan({ x: drag.panX + (event.clientX - drag.x), y: drag.panY + (event.clientY - drag.y) });
  };
  const onPointerUp = (event: React.PointerEvent) => {
    dragRef.current = null;
    (event.currentTarget as Element).releasePointerCapture?.(event.pointerId);
  };

  const reset = useCallback(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, []);

  // Keyboard access to the graph: arrow keys pan, +/- zoom, 0 resets (§37).
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onKey = (event: KeyboardEvent) => {
      if (document.activeElement !== el) return;
      const step = 40;
      if (event.key === 'ArrowLeft') setPan((p) => ({ ...p, x: p.x + step }));
      else if (event.key === 'ArrowRight') setPan((p) => ({ ...p, x: p.x - step }));
      else if (event.key === 'ArrowUp') setPan((p) => ({ ...p, y: p.y + step }));
      else if (event.key === 'ArrowDown') setPan((p) => ({ ...p, y: p.y - step }));
      else if (event.key === '+' || event.key === '=') setZoom((z) => Math.min(2.5, z + 0.15));
      else if (event.key === '-') setZoom((z) => Math.max(0.4, z - 0.15));
      else if (event.key === '0') reset();
      else return;
      event.preventDefault();
    };
    el.addEventListener('keydown', onKey);
    return () => el.removeEventListener('keydown', onKey);
  }, [reset]);

  const toggleLayer = (layer: CouplingLayer) => {
    setHiddenLayers((current) => {
      const next = new Set(current);
      if (next.has(layer)) next.delete(layer);
      else next.add(layer);
      return next;
    });
  };

  if (!graph.nodes.length) {
    return (
      <div className="flex min-h-[220px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/12 bg-white/[0.02] p-6 text-center">
        <Share2 className="h-6 w-6 text-white/25" />
        <p className="text-[12px] font-bold text-white/55">No cryptographic dependency graph yet</p>
        <p className="max-w-md text-[11px] text-white/35">
          The graph is projected from your CBOM, certificate inventory and trust fabric. Run a discovery scan to populate it.
        </p>
        <a href="/dashboard/scanner" className="mt-1 rounded border border-cyan-400/40 bg-cyan-500/10 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline">
          Run Discovery Scan
        </a>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1 rounded-lg border border-white/10 bg-black/25 p-1">
          <IconBtn label="Zoom out" onClick={() => setZoom((z) => Math.max(0.4, z - 0.15))}><Minus className="h-3 w-3" /></IconBtn>
          <span className="min-w-[42px] text-center font-mono text-[9px] text-white/45">{Math.round(zoom * 100)}%</span>
          <IconBtn label="Zoom in" onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))}><Plus className="h-3 w-3" /></IconBtn>
          <IconBtn label="Reset view" onClick={reset}><Crosshair className="h-3 w-3" /></IconBtn>
        </div>

        <button
          type="button"
          onClick={onToggleRiskOnly}
          aria-pressed={riskOnly}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider transition',
            riskOnly ? 'border-red-400/50 bg-red-500/15 text-red-200' : 'border-white/10 bg-white/5 text-white/55 hover:text-cyan-300',
          )}
        >
          <Filter className="h-3 w-3" /> Risk paths only
        </button>

        <div className="flex flex-wrap items-center gap-1">
          {COUPLING_LAYER_ORDER.filter((layer) => graph.nodes.some((n) => n.layer === layer)).map((layer) => {
            const off = hiddenLayers.has(layer);
            return (
              <button
                key={layer}
                type="button"
                onClick={() => toggleLayer(layer)}
                aria-pressed={!off}
                className={cn(
                  'rounded border px-2 py-1 text-[8.5px] font-black uppercase tracking-wider transition',
                  off ? 'border-white/8 bg-transparent text-white/25 line-through' : 'border-cyan-400/25 bg-cyan-500/10 text-cyan-200',
                )}
              >
                {COUPLING_LAYER_LABEL[layer]}
              </button>
            );
          })}
        </div>

        <span className="ml-auto font-mono text-[9px] uppercase tracking-widest text-white/25">
          {layout.nodes.length} nodes · {edges.length} edges · ctrl+scroll to zoom
        </span>
      </div>

      {/* Canvas */}
      <div className="relative overflow-hidden rounded-lg border border-white/10 bg-[#060c17]">
        <svg
          ref={svgRef}
          tabIndex={0}
          role="application"
          aria-label={`Crypto dependency and coupling graph: ${layout.nodes.length} nodes across ${layout.activeLayers.length} layers. Arrow keys pan, plus and minus zoom, zero resets.`}
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          className="h-[420px] w-full cursor-grab touch-none outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60 active:cursor-grabbing"
          onWheel={onWheel}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerLeave={onPointerUp}
        >
          <defs>
            <marker id="ag-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M0,0 L8,4 L0,8 z" fill="rgba(148,163,184,0.55)" />
            </marker>
          </defs>

          <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
            {/* Layer headers */}
            {layout.activeLayers.map((layer, index) => (
              <text
                key={layer}
                x={PADDING + index * COL_WIDTH}
                y={PADDING}
                className="fill-cyan-300/60 font-mono"
                style={{ fontSize: 9, letterSpacing: '0.12em', textTransform: 'uppercase' }}
              >
                {COUPLING_LAYER_LABEL[layer]}
              </text>
            ))}

            {/* Edges */}
            {edges.map((edge) => {
              const source = nodeById.get(edge.source)!;
              const target = nodeById.get(edge.target)!;
              const x1 = source.x + NODE_WIDTH;
              const y1 = source.y + NODE_HEIGHT / 2;
              const x2 = target.x;
              const y2 = target.y + NODE_HEIGHT / 2;
              const mid = (x1 + x2) / 2;
              const dim = highlighted ? !(highlighted.has(edge.source) && highlighted.has(edge.target)) : false;
              return (
                <path
                  key={`${edge.source}->${edge.target}`}
                  d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                  fill="none"
                  stroke={STATE_HEX[edge.agilityState]}
                  strokeOpacity={dim ? 0.08 : 0.42}
                  strokeWidth={Math.min(3, 1 + edge.weight * 0.4)}
                  markerEnd="url(#ag-arrow)"
                />
              );
            })}

            {/* Nodes */}
            {layout.nodes.map((node) => {
              const dim = highlighted ? !highlighted.has(node.id) : false;
              const selected = selectedId === node.id;
              const color = STATE_HEX[node.agilityState];
              return (
                <g
                  key={node.id}
                  data-graph-node
                  transform={`translate(${node.x} ${node.y})`}
                  opacity={dim ? 0.25 : 1}
                  className="cursor-pointer"
                  onMouseEnter={() => setHovered(node.id)}
                  onMouseLeave={() => setHovered(null)}
                  onClick={() => onSelect(selected ? null : node)}
                  role="button"
                  tabIndex={0}
                  aria-label={`${node.label}, ${COUPLING_LAYER_LABEL[node.layer]}, ${AGILITY_STATE_LABEL[node.agilityState]}, risk ${node.risk}`}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onSelect(selected ? null : node);
                    }
                  }}
                >
                  <rect
                    width={NODE_WIDTH}
                    height={NODE_HEIGHT}
                    rx={6}
                    fill={selected ? 'rgba(34,211,238,0.16)' : 'rgba(255,255,255,0.035)'}
                    stroke={selected ? '#22d3ee' : color}
                    strokeOpacity={selected ? 1 : 0.5}
                    strokeWidth={selected ? 1.8 : 1}
                  />
                  <rect width={3} height={NODE_HEIGHT} rx={2} fill={color} />
                  <text x={12} y={13} className="fill-white font-sans" style={{ fontSize: 10, fontWeight: 700 }}>
                    {node.label.length > 22 ? `${node.label.slice(0, 21)}…` : node.label}
                  </text>
                  <text x={12} y={25} style={{ fontSize: 8, fill: color, fontWeight: 700 }}>
                    {STATE_GLYPH[node.agilityState]} {AGILITY_STATE_LABEL[node.agilityState]}
                  </text>
                  {node.assetCount > 1 && (
                    <text x={NODE_WIDTH - 8} y={25} textAnchor="end" style={{ fontSize: 8, fill: 'rgba(255,255,255,0.4)' }}>
                      ×{node.assetCount}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>

        <div className="pointer-events-none absolute bottom-2 left-3 flex flex-wrap items-center gap-3">
          {(['agile', 'conditional', 'rigid', 'blocked', 'unknown'] as AgilityState[]).map((state) => (
            <span key={state} className="inline-flex items-center gap-1 text-[8.5px] font-bold uppercase tracking-wider text-white/40">
              <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: STATE_HEX[state] }} />
              {STATE_GLYPH[state]} {AGILITY_STATE_LABEL[state]}
            </span>
          ))}
        </div>
        <span className="pointer-events-none absolute bottom-2 right-3 inline-flex items-center gap-1 text-[8.5px] uppercase tracking-wider text-white/25">
          <Maximize2 className="h-2.5 w-2.5" /> drag to pan
        </span>
      </div>

      <p className="text-[10px] leading-relaxed text-white/35">{graph.note}</p>
    </div>
  );
}

function IconBtn({ children, onClick, label }: { children: React.ReactNode; onClick: () => void; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className="grid h-6 w-6 place-items-center rounded text-white/50 transition hover:bg-white/10 hover:text-cyan-300"
    >
      {children}
    </button>
  );
}

export default DependencyGraph;
