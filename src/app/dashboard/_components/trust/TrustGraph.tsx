'use client';

/**
 * Interactive trust relationship graph (brief section 4).
 *
 * Renders the discovered hierarchy as a tiered SVG:
 *
 *     Root CA -> Intermediate CA -> Certificate -> TLS Endpoint
 *             -> Service -> Application -> Cloud Resource
 *
 * Deliberately NOT a force-directed blob. Trust is a hierarchy, and an operator
 * asking "which CA signs for this endpoint" needs to read the answer top to
 * bottom, not untangle it. Tiers come from `TRUST_NODE_TIER`, so the layout is
 * the model's own vocabulary rather than a second opinion about it.
 *
 * Honesty rules carried through from the engine:
 *   - an inferred node (issuer name only, certificate never collected) is drawn
 *     dashed and dimmed, and says so on hover;
 *   - an inferred edge is drawn dashed with no flow animation, so the moving
 *     dashes only ever indicate a MEASURED relationship;
 *   - selecting a node dims everything not reachable from it, which is the
 *     blast-radius answer rendered rather than described.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Maximize2, Minimize2, RotateCcw, ZoomIn, ZoomOut } from 'lucide-react';
import { cn } from '@/lib/utils';
import { TONE } from '../observability/primitives';
import { TRUST_NODE_LABEL, TRUST_NODE_TIER, TRUST_STATE_LABEL } from '@/lib/trust-fabric/types';
import type { TrustNode, TrustRelationship, TrustState } from '@/lib/trust-fabric/types';
import { TRUST_STATE_TONE } from './primitives';

const TIER_LABEL: Record<number, string> = {
  0: 'Root authorities (certificate collected)',
  1: 'Issuing / intermediate authorities',
  2: 'Certificates',
  3: 'Transport endpoints',
  4: 'Services & platform',
  5: 'Applications & assets',
  6: 'Cloud resources',
};

const NODE_W = 148;
const NODE_H = 44;
const GAP_X = 26;
const GAP_Y = 78;
const PADDING = 28;

interface Placed {
  node: TrustNode;
  x: number;
  y: number;
  tier: number;
}

function stateHex(state: TrustState): string {
  return TONE[TRUST_STATE_TONE[state]].hex;
}

export function TrustGraph({
  nodes,
  relationships,
  selectedId,
  onSelect,
  maxNodes = 140,
}: {
  nodes: TrustNode[];
  relationships: TrustRelationship[];
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  maxNodes?: number;
}) {
  const [zoom, setZoom] = useState(1);
  const [expanded, setExpanded] = useState(false);
  const [hovered, setHovered] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  /* ---- bounded node set ------------------------------------------ */
  // A 5,000-node estate cannot be drawn legibly and must not be shipped to the
  // browser to try. Worst-state-first ordering from the engine means the cap
  // keeps the nodes an operator actually needs to see.
  const visible = useMemo(() => nodes.slice(0, maxNodes), [nodes, maxNodes]);
  const visibleIds = useMemo(() => new Set(visible.map((node) => node.id)), [visible]);
  const edges = useMemo(
    () => relationships.filter((edge) => visibleIds.has(edge.from) && visibleIds.has(edge.to)),
    [relationships, visibleIds],
  );

  /* ---- layout ---------------------------------------------------- */
  const { placed, width, height, tiers } = useMemo(() => {
    const buckets = new Map<number, TrustNode[]>();
    for (const node of visible) {
      const tier = TRUST_NODE_TIER[node.kind] ?? 5;
      const list = buckets.get(tier);
      if (list) list.push(node);
      else buckets.set(tier, [node]);
    }

    const orderedTiers = [...buckets.keys()].sort((a, b) => a - b);
    const widest = Math.max(1, ...orderedTiers.map((tier) => (buckets.get(tier) as TrustNode[]).length));
    const canvasWidth = PADDING * 2 + widest * (NODE_W + GAP_X) - GAP_X;

    const result: Placed[] = [];
    orderedTiers.forEach((tier, rowIndex) => {
      const row = buckets.get(tier) as TrustNode[];
      const rowWidth = row.length * (NODE_W + GAP_X) - GAP_X;
      const startX = (canvasWidth - rowWidth) / 2;
      row.forEach((node, columnIndex) => {
        result.push({
          node,
          tier,
          x: startX + columnIndex * (NODE_W + GAP_X),
          y: PADDING + rowIndex * (NODE_H + GAP_Y),
        });
      });
    });

    return {
      placed: result,
      width: canvasWidth,
      height: PADDING * 2 + orderedTiers.length * (NODE_H + GAP_Y) - GAP_Y,
      tiers: orderedTiers,
    };
  }, [visible]);

  const positionById = useMemo(() => new Map(placed.map((item) => [item.node.id, item])), [placed]);

  /* ---- focus set: what the selection actually reaches ------------- */
  const focusIds = useMemo(() => {
    if (!selectedId) return null;
    const reachable = new Set<string>([selectedId]);
    const adjacency = new Map<string, string[]>();
    for (const edge of edges) {
      const out = adjacency.get(edge.from);
      if (out) out.push(edge.to);
      else adjacency.set(edge.from, [edge.to]);
      const back = adjacency.get(edge.to);
      if (back) back.push(edge.from);
      else adjacency.set(edge.to, [edge.from]);
    }
    const stack = [selectedId];
    let guard = 0;
    while (stack.length && guard < 600) {
      const current = stack.pop() as string;
      for (const next of adjacency.get(current) || []) {
        if (reachable.has(next)) continue;
        reachable.add(next);
        stack.push(next);
        guard += 1;
      }
    }
    return reachable;
  }, [selectedId, edges]);

  /* ---- keyboard: escape clears the selection --------------------- */
  useEffect(() => {
    if (!selectedId) return undefined;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onSelect(null);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [selectedId, onSelect]);

  const resetView = useCallback(() => {
    setZoom(1);
    onSelect(null);
    scrollRef.current?.scrollTo({ left: 0, top: 0, behavior: 'smooth' });
  }, [onSelect]);

  if (!visible.length) {
    return (
      <div className="flex min-h-[220px] items-center justify-center rounded-lg border border-dashed border-white/12 bg-white/[0.02] px-6 text-center text-[11.5px] font-medium leading-relaxed text-white/40">
        No trust subjects have been discovered yet. Run a scan or connect a collector to populate the trust graph.
      </div>
    );
  }

  return (
    <div className={cn('relative', expanded && 'fixed inset-3 z-[70] rounded-xl border border-white/12 bg-[#0b1424] p-3 shadow-2xl')}>
      {/* ---- controls ---- */}
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2 text-[9.5px] font-semibold text-white/40">
          <span>
            Showing {visible.length} of {nodes.length} subjects
          </span>
          {nodes.length > visible.length ? (
            <span className="rounded border border-amber-500/25 bg-amber-500/10 px-1.5 py-0.5 text-amber-200/80">
              Worst-state first — filter to narrow
            </span>
          ) : null}
          {selectedId ? (
            <button
              type="button"
              onClick={() => onSelect(null)}
              className="rounded border border-cyan-400/40 bg-cyan-500/10 px-1.5 py-0.5 text-cyan-200 transition hover:bg-cyan-500/20"
            >
              Clear focus
            </button>
          ) : null}
        </div>
        <div className="flex items-center gap-1">
          {[
            { icon: ZoomOut, label: 'Zoom out', action: () => setZoom((value) => Math.max(0.5, value - 0.15)) },
            { icon: ZoomIn, label: 'Zoom in', action: () => setZoom((value) => Math.min(1.8, value + 0.15)) },
            { icon: RotateCcw, label: 'Reset view', action: resetView },
            { icon: expanded ? Minimize2 : Maximize2, label: expanded ? 'Exit full screen' : 'Full screen', action: () => setExpanded((value) => !value) },
          ].map(({ icon: Icon, label, action }) => (
            <button
              key={label}
              type="button"
              onClick={action}
              aria-label={label}
              title={label}
              className="rounded-md border border-white/12 bg-white/[0.04] p-1.5 text-white/55 transition hover:bg-white/[0.09] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
            >
              <Icon className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          ))}
        </div>
      </div>

      {/* ---- canvas ---- */}
      <div
        ref={scrollRef}
        className={cn('overflow-auto rounded-lg border border-white/8 bg-black/25', expanded ? 'h-[calc(100%-3rem)]' : 'max-h-[520px]')}
      >
        <svg
          width={width * zoom}
          height={height * zoom}
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label="Cryptographic trust relationship graph"
          style={{ minWidth: '100%' }}
        >
          <defs>
            <marker id="tf-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 8 4 L 0 8 z" fill="rgba(255,255,255,0.35)" />
            </marker>
          </defs>

          {/* tier guides */}
          {tiers.map((tier, index) => (
            <g key={tier}>
              <line
                x1={0}
                x2={width}
                y1={PADDING + index * (NODE_H + GAP_Y) - 16}
                y2={PADDING + index * (NODE_H + GAP_Y) - 16}
                stroke="rgba(255,255,255,0.05)"
                strokeWidth={1}
              />
              <text
                x={6}
                y={PADDING + index * (NODE_H + GAP_Y) - 21}
                className="fill-white/25"
                style={{ fontSize: 8.5, fontWeight: 800, letterSpacing: '0.08em', textTransform: 'uppercase' }}
              >
                {TIER_LABEL[tier] ?? `Tier ${tier}`}
              </text>
            </g>
          ))}

          {/* edges */}
          {edges.map((edge) => {
            const from = positionById.get(edge.from);
            const to = positionById.get(edge.to);
            if (!from || !to) return null;
            const x1 = from.x + NODE_W / 2;
            const y1 = from.y + NODE_H;
            const x2 = to.x + NODE_W / 2;
            const y2 = to.y;
            const midY = (y1 + y2) / 2;
            const dimmed = focusIds ? !(focusIds.has(edge.from) && focusIds.has(edge.to)) : false;
            const highlighted = hovered ? edge.from === hovered || edge.to === hovered : false;
            const hex = stateHex(edge.state);

            return (
              <path
                key={edge.id}
                d={`M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`}
                fill="none"
                stroke={hex}
                strokeWidth={highlighted ? 2 : 1.2}
                strokeOpacity={dimmed ? 0.07 : highlighted ? 0.9 : 0.34}
                strokeDasharray={edge.measured ? undefined : '4 4'}
                className={edge.measured && !dimmed ? 'tf-edge-flow' : undefined}
                markerEnd="url(#tf-arrow)"
              >
                <title>{`${edge.label} — ${edge.reason}${edge.measured ? '' : ' (inferred, not measured)'}`}</title>
              </path>
            );
          })}

          {/* nodes */}
          {placed.map(({ node, x, y }) => {
            const dimmed = focusIds ? !focusIds.has(node.id) : false;
            const selected = node.id === selectedId;
            const hex = stateHex(node.state);
            return (
              <g
                key={node.id}
                transform={`translate(${x}, ${y})`}
                opacity={dimmed ? 0.18 : 1}
                onMouseEnter={() => setHovered(node.id)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => onSelect(selected ? null : node.id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    onSelect(selected ? null : node.id);
                  }
                }}
                tabIndex={0}
                role="button"
                aria-label={`${TRUST_NODE_LABEL[node.kind]}: ${node.label}, ${TRUST_STATE_LABEL[node.state]}`}
                style={{ cursor: 'pointer' }}
                className="focus-visible:outline-none"
              >
                <rect
                  width={NODE_W}
                  height={NODE_H}
                  rx={8}
                  fill={selected ? `${hex}26` : 'rgba(6,12,24,0.92)'}
                  stroke={hex}
                  strokeWidth={selected ? 2 : 1}
                  strokeOpacity={node.measured ? 0.85 : 0.4}
                  strokeDasharray={node.measured ? undefined : '5 4'}
                />
                <circle cx={11} cy={NODE_H / 2} r={3.5} fill={hex} />
                <text x={22} y={17} className="fill-white" style={{ fontSize: 10, fontWeight: 800 }}>
                  {node.label.length > 17 ? `${node.label.slice(0, 16)}…` : node.label}
                </text>
                <text x={22} y={30} className="fill-white/45" style={{ fontSize: 8 }}>
                  {TRUST_NODE_LABEL[node.kind]}
                </text>
                <text x={22} y={40} className="fill-white/30" style={{ fontSize: 7.5 }}>
                  {node.dependentCount > 0 ? `${node.dependentCount} dependent${node.dependentCount === 1 ? '' : 's'}` : 'no dependents mapped'}
                </text>
                <title>
                  {`${node.label}\n${TRUST_NODE_LABEL[node.kind]} — ${TRUST_STATE_LABEL[node.state]}\n${node.stateReason}${
                    node.measured ? '' : '\nInferred from an issuer name; the certificate itself was not collected.'
                  }`}
                </title>
              </g>
            );
          })}
        </svg>
      </div>

      {/* ---- legend ---- */}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[9px] font-semibold text-white/35">
        {(['trusted', 'healthy', 'degraded', 'at-risk', 'quantum-vulnerable', 'critical', 'expired', 'unknown'] as TrustState[]).map(
          (state) => (
            <span key={state} className="inline-flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: stateHex(state) }} aria-hidden="true" />
              {TRUST_STATE_LABEL[state]}
            </span>
          ),
        )}
        <span className="inline-flex items-center gap-1">
          <svg width="18" height="6" aria-hidden="true">
            <line x1="0" y1="3" x2="18" y2="3" stroke="rgba(255,255,255,0.5)" strokeWidth="1.4" strokeDasharray="4 4" />
          </svg>
          Inferred, not measured
        </span>
      </div>
    </div>
  );
}

export default TrustGraph;
