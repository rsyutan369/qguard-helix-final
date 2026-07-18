'use client';

import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { PointerEvent as ReactPointerEvent, WheelEvent as ReactWheelEvent } from 'react';
import { Maximize2, Minimize2, Minus, Plus, Scan } from 'lucide-react';
import type { BlastRadiusResult, ExposureGraphEdge, ExposureGraphNode } from '@/types/exposure-graph';
import { TRUST_CHAIN_CLASSES } from '@/lib/exposure-graph-intel';
import { CYAN, ORANGE, RED, SLATE } from '../_shared';
import { POSTURE_COLOR, POSTURE_LABEL, TRUST_CLASS_COLOR } from './_common';

export type GroupMode = 'posture' | 'tier' | 'environment' | 'category' | 'region';

export const GROUP_MODES: Array<{ key: GroupMode; label: string }> = [
  { key: 'posture', label: 'Quantum Readiness' },
  { key: 'tier', label: 'Migration Layer' },
  { key: 'environment', label: 'Environment' },
  { key: 'category', label: 'Asset Type' },
  { key: 'region', label: 'Region' },
];

const W = 1200;
const H = 680;

/* ------------------------------------------------------------------ */
/* Deterministic layouts                                               */
/* ------------------------------------------------------------------ */

interface LayoutGroup {
  key: string;
  label: string;
  cx: number;
  cy: number;
  r: number;
  count: number;
}

interface Layout {
  positions: Map<string, { x: number; y: number }>;
  groups: LayoutGroup[];
  mode: 'radial' | 'columns';
}

function groupKeyFor(node: ExposureGraphNode, groupBy: GroupMode): { key: string; label: string; order: number } {
  switch (groupBy) {
    case 'posture':
      return { key: node.posture, label: POSTURE_LABEL[node.posture], order: ['vulnerable', 'migrating', 'hybrid', 'unknown', 'pqc'].indexOf(node.posture) };
    case 'tier':
      return { key: `t${node.migrationTier}`, label: `Wave order ${node.migrationTier} · ${node.tierLabel}`, order: node.migrationTier };
    case 'environment':
      return { key: node.environment || 'unknown', label: node.environment || 'unknown', order: 0 };
    case 'category':
      return { key: node.category, label: node.tierLabel, order: node.migrationTier };
    case 'region':
      return { key: node.region || '—', label: node.region === '—' ? 'No region' : node.region, order: 0 };
  }
}

/** Pack members of one group into concentric rings around (0,0). */
function packRing(count: number): Array<{ x: number; y: number }> {
  const spacing = 30;
  const out: Array<{ x: number; y: number }> = [];
  if (count <= 0) return out;
  out.push({ x: 0, y: 0 });
  let placed = 1;
  let ring = 1;
  while (placed < count) {
    const radius = ring * spacing;
    const capacity = Math.max(1, Math.floor((2 * Math.PI * radius) / spacing));
    const take = Math.min(capacity, count - placed);
    for (let i = 0; i < take; i++) {
      const angle = (i / take) * Math.PI * 2 + ring * 0.7;
      out.push({ x: Math.cos(angle) * radius, y: Math.sin(angle) * radius });
    }
    placed += take;
    ring += 1;
  }
  return out;
}

function radiusForCount(count: number): number {
  if (count <= 1) return 34;
  const spacing = 30;
  let placed = 1;
  let ring = 1;
  while (placed < count) {
    const capacity = Math.max(1, Math.floor((2 * Math.PI * ring * spacing) / spacing));
    placed += capacity;
    ring += 1;
  }
  return ring * spacing + 16;
}

function computeLayout(nodes: ExposureGraphNode[], groupBy: GroupMode): Layout {
  const positions = new Map<string, { x: number; y: number }>();
  const groupsMap = new Map<string, { label: string; order: number; members: ExposureGraphNode[] }>();
  for (const node of nodes) {
    const g = groupKeyFor(node, groupBy);
    const entry = groupsMap.get(g.key) || { label: g.label, order: g.order, members: [] };
    entry.members.push(node);
    groupsMap.set(g.key, entry);
  }
  const groups: LayoutGroup[] = [];

  if (groupBy === 'tier') {
    const ordered = [...groupsMap.entries()].sort((a, b) => a[1].order - b[1].order);
    const margin = 90;
    const colWidth = (W - margin * 2) / Math.max(1, ordered.length);
    ordered.forEach(([key, group], index) => {
      const cx = margin + colWidth * (index + 0.5);
      const members = [...group.members].sort((a, b) => b.dependents - a.dependents || b.riskScore - a.riskScore);
      members.forEach((node, i) => {
        const y = 90 + ((i + 0.5) / members.length) * (H - 150);
        const x = cx + (i % 2 === 0 ? -1 : 1) * Math.min(colWidth * 0.18, 26);
        positions.set(node.id, { x, y });
      });
      groups.push({ key, label: group.label, cx, cy: 46, r: colWidth / 2 - 8, count: members.length });
    });
    return { positions, groups, mode: 'columns' };
  }

  const ordered = [...groupsMap.entries()].sort((a, b) => b[1].members.length - a[1].members.length || a[1].order - b[1].order);
  const cx0 = W / 2;
  const cy0 = H / 2;
  if (ordered.length === 1) {
    const [key, group] = ordered[0];
    const pack = packRing(group.members.length);
    group.members.forEach((node, i) => positions.set(node.id, { x: cx0 + pack[i].x, y: cy0 + pack[i].y }));
    groups.push({ key, label: group.label, cx: cx0, cy: cy0, r: radiusForCount(group.members.length), count: group.members.length });
    return { positions, groups, mode: 'radial' };
  }

  ordered.forEach(([key, group], index) => {
    let gx = cx0;
    let gy = cy0;
    if (index > 0) {
      const angle = ((index - 1) / (ordered.length - 1)) * Math.PI * 2 - Math.PI / 2;
      const orbit = Math.min(W, H) * 0.36 + (index % 2) * 24;
      gx = cx0 + Math.cos(angle) * orbit * 1.28;
      gy = cy0 + Math.sin(angle) * orbit * 0.86;
    }
    const pack = packRing(group.members.length);
    const members = [...group.members].sort((a, b) => b.riskScore - a.riskScore);
    members.forEach((node, i) => positions.set(node.id, { x: gx + pack[i].x * 0.92, y: gy + pack[i].y * 0.82 }));
    groups.push({ key, label: group.label, cx: gx, cy: gy, r: radiusForCount(group.members.length) * 0.95, count: group.members.length });
  });
  return { positions, groups, mode: 'radial' };
}

/* ------------------------------------------------------------------ */
/* Canvas                                                              */
/* ------------------------------------------------------------------ */

export interface GraphCanvasProps {
  nodes: ExposureGraphNode[];
  edges: ExposureGraphEdge[];
  groupBy: GroupMode;
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  blast: BlastRadiusResult | null;
  highlightIds: Set<string> | null;
  focus: { id: string; n: number } | null;
  fullscreen: boolean;
  onSelectNode: (id: string | null) => void;
  onSelectEdge: (id: string | null) => void;
  onToggleFullscreen: () => void;
}

interface HoverState {
  node: ExposureGraphNode;
  x: number;
  y: number;
}

export function GraphCanvas({
  nodes,
  edges,
  groupBy,
  selectedNodeId,
  selectedEdgeId,
  blast,
  highlightIds,
  focus,
  fullscreen,
  onSelectNode,
  onSelectEdge,
  onToggleFullscreen,
}: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [hover, setHover] = useState<HoverState | null>(null);
  const dragRef = useRef<{ startX: number; startY: number; viewX: number; viewY: number; moved: boolean } | null>(null);

  const layout = useMemo(() => computeLayout(nodes, groupBy), [nodes, groupBy]);

  const resetView = useCallback(() => setView({ x: 0, y: 0, k: 1 }), []);
  const zoomBy = useCallback((factor: number) => {
    setView((v) => {
      const k = Math.max(0.35, Math.min(4, v.k * factor));
      // Zoom around the logical center so buttons feel stable.
      const cx = W / 2;
      const cy = H / 2;
      const scale = k / v.k;
      return { k, x: cx - (cx - v.x) * scale, y: cy - (cy - v.y) * scale };
    });
  }, []);

  // Center the requested node (search / cross-panel focus).
  useEffect(() => {
    if (!focus) return;
    const pos = layout.positions.get(focus.id);
    if (!pos) return;
    setView((v) => {
      const k = Math.max(v.k, 1.15);
      return { k, x: W / 2 - pos.x * k, y: H / 2 - pos.y * k };
    });
  }, [focus, layout]);

  const toLogical = useCallback((clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    return { x: ((clientX - rect.left) / rect.width) * W, y: ((clientY - rect.top) / rect.height) * H };
  }, []);

  const onWheel = useCallback(
    (event: ReactWheelEvent<SVGSVGElement>) => {
      event.preventDefault();
      const point = toLogical(event.clientX, event.clientY);
      setView((v) => {
        const k = Math.max(0.35, Math.min(4, v.k * Math.exp(-event.deltaY * 0.0012)));
        const scale = k / v.k;
        return { k, x: point.x - (point.x - v.x) * scale, y: point.y - (point.y - v.y) * scale };
      });
    },
    [toLogical],
  );

  const onPointerDown = useCallback((event: ReactPointerEvent<SVGSVGElement>) => {
    dragRef.current = { startX: event.clientX, startY: event.clientY, viewX: view.x, viewY: view.y, moved: false };
    ;(event.target as Element).setPointerCapture?.(event.pointerId);
  }, [view.x, view.y]);

  const onPointerMove = useCallback(
    (event: ReactPointerEvent<SVGSVGElement>) => {
      const drag = dragRef.current;
      if (!drag) return;
      const svg = svgRef.current;
      if (!svg) return;
      const rect = svg.getBoundingClientRect();
      const dx = ((event.clientX - drag.startX) / rect.width) * W;
      const dy = ((event.clientY - drag.startY) / rect.height) * H;
      if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
      if (drag.moved) setView((v) => ({ ...v, x: drag.viewX + dx, y: drag.viewY + dy }));
    },
    [],
  );

  const onPointerUp = useCallback(() => {
    const drag = dragRef.current;
    dragRef.current = null;
    if (drag && !drag.moved) {
      onSelectNode(null);
      onSelectEdge(null);
    }
  }, [onSelectNode, onSelectEdge]);

  const handleHover = useCallback((node: ExposureGraphNode | null, event?: ReactPointerEvent) => {
    if (!node || !event || !containerRef.current) {
      setHover(null);
      return;
    }
    const rect = containerRef.current.getBoundingClientRect();
    setHover({ node, x: event.clientX - rect.left, y: event.clientY - rect.top });
  }, []);

  return (
    <div ref={containerRef} className={`relative overflow-hidden rounded-lg ${fullscreen ? 'h-full' : 'h-[560px] xl:h-[640px]'}`}>
      <style>{`
        @keyframes qegFlow { to { stroke-dashoffset: -26; } }
        @keyframes qegSpin { to { transform: rotate(360deg); } }
        .qeg-flow { stroke-dasharray: 7 6; animation: qegFlow 1.1s linear infinite; }
        .qeg-migrating { transform-box: fill-box; transform-origin: center; animation: qegSpin 6s linear infinite; }
        .qeg-node { transition: transform 650ms cubic-bezier(0.4, 0, 0.2, 1), opacity 350ms ease; }
        .qeg-fade { animation: qegFade 400ms ease; }
        @keyframes qegFade { from { opacity: 0; } }
      `}</style>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        className="h-full w-full cursor-grab touch-none select-none active:cursor-grabbing"
        role="img"
        aria-label="Enterprise cryptographic dependency graph"
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
      >
        <defs>
          <radialGradient id="qeg-bg" cx="50%" cy="42%" r="75%">
            <stop offset="0%" stopColor="rgba(36,120,255,0.06)" />
            <stop offset="100%" stopColor="rgba(3,7,17,0)" />
          </radialGradient>
          <marker id="qeg-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0.6 L7.4,4 L0,7.4 Z" fill="rgba(255,255,255,0.22)" />
          </marker>
          <marker id="qeg-arrow-active" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0.6 L7.4,4 L0,7.4 Z" fill={CYAN} />
          </marker>
        </defs>
        <rect x="0" y="0" width={W} height={H} fill="url(#qeg-bg)" />

        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          <GraphContent
            nodes={nodes}
            edges={edges}
            layout={layout}
            selectedNodeId={selectedNodeId}
            selectedEdgeId={selectedEdgeId}
            blast={blast}
            highlightIds={highlightIds}
            zoom={view.k}
            onSelectNode={onSelectNode}
            onSelectEdge={onSelectEdge}
            onHover={handleHover}
          />
        </g>
      </svg>

      {/* Zoom / fullscreen controls */}
      <div className="absolute right-3 top-3 flex flex-col gap-1.5">
        {[
          { icon: Plus, action: () => zoomBy(1.35), label: 'Zoom in' },
          { icon: Minus, action: () => zoomBy(1 / 1.35), label: 'Zoom out' },
          { icon: Scan, action: resetView, label: 'Fit graph' },
          { icon: fullscreen ? Minimize2 : Maximize2, action: onToggleFullscreen, label: fullscreen ? 'Exit full screen' : 'Full screen' },
        ].map((button) => {
          const Icon = button.icon;
          return (
            <button
              key={button.label}
              type="button"
              title={button.label}
              aria-label={button.label}
              onClick={button.action}
              className="grid h-8 w-8 place-items-center rounded-md border border-white/10 bg-[#07101D]/85 text-white/60 backdrop-blur transition hover:border-blue-400/45 hover:text-blue-200"
            >
              <Icon className="h-4 w-4" />
            </button>
          );
        })}
      </div>

      {/* Posture legend */}
      <div className="pointer-events-none absolute bottom-3 left-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-md border border-white/8 bg-[#07101D]/80 px-3 py-2 text-[10px] text-white/55 backdrop-blur">
        {(Object.keys(POSTURE_COLOR) as Array<keyof typeof POSTURE_COLOR>).map((posture) => (
          <span key={posture} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: POSTURE_COLOR[posture] }} />
            {POSTURE_LABEL[posture]}
          </span>
        ))}
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: ORANGE }} /> Internet-Facing
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full border border-dashed" style={{ borderColor: SLATE }} /> Third-Party / External
        </span>
      </div>

      {/* Hover tooltip */}
      {hover ? (
        <div
          className="pointer-events-none absolute z-20 w-56 rounded-md border border-blue-400/25 bg-[#0A1728]/95 p-3 shadow-[0_12px_36px_rgba(0,0,0,0.55)] backdrop-blur"
          style={{ left: Math.min(hover.x + 14, (containerRef.current?.clientWidth || 400) - 240), top: Math.max(8, hover.y - 10) }}
        >
          <div className="truncate text-xs font-bold text-white">{hover.node.label}</div>
          <div className="mt-0.5 text-[10px] text-white/45">{hover.node.tierLabel}</div>
          <div className="mt-2 flex items-center justify-between text-[10px]">
            <span className="font-bold" style={{ color: POSTURE_COLOR[hover.node.posture] }}>
              {POSTURE_LABEL[hover.node.posture]}
            </span>
            <span className="font-mono text-white/55">Risk {hover.node.riskScore}</span>
          </div>
          <div className="mt-1 flex items-center justify-between text-[10px] text-white/45">
            <span>Blast radius {hover.node.blastRadius}</span>
            <span>{hover.node.dependents + hover.node.dependencies} link(s)</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Memoized content (pan/zoom re-renders only the wrapper transform)   */
/* ------------------------------------------------------------------ */

const GraphContent = memo(function GraphContent({
  nodes,
  edges,
  layout,
  selectedNodeId,
  selectedEdgeId,
  blast,
  highlightIds,
  zoom,
  onSelectNode,
  onSelectEdge,
  onHover,
}: {
  nodes: ExposureGraphNode[];
  edges: ExposureGraphEdge[];
  layout: Layout;
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  blast: BlastRadiusResult | null;
  highlightIds: Set<string> | null;
  zoom: number;
  onSelectNode: (id: string | null) => void;
  onSelectEdge: (id: string | null) => void;
  onHover: (node: ExposureGraphNode | null, event?: ReactPointerEvent) => void;
}) {
  const showAllLabels = nodes.length <= 42 || zoom >= 1.5;

  const nodeOpacity = (node: ExposureGraphNode): number => {
    if (highlightIds) return highlightIds.has(node.id) ? 1 : 0.18;
    if (blast && selectedNodeId) {
      const depth = blast.depths[node.id];
      if (depth === undefined) return 0.12;
      return depth <= 1 ? 1 : 0.8;
    }
    return 1;
  };

  return (
    <>
      {/* Group hulls / column headers */}
      {layout.groups.map((group) =>
        layout.mode === 'columns' ? (
          <g key={group.key} className="qeg-fade">
            <text x={group.cx} y={group.cy} textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="10.5" fontWeight="800" letterSpacing="0.08em">
              {group.label.length > 34 ? `${group.label.slice(0, 34)}…` : group.label.toUpperCase()}
            </text>
            <text x={group.cx} y={group.cy + 14} textAnchor="middle" fill="rgba(255,255,255,0.28)" fontSize="9">
              {group.count} asset(s)
            </text>
            <line x1={group.cx - group.r} x2={group.cx + group.r} y1={group.cy + 22} y2={group.cy + 22} stroke="rgba(255,255,255,0.07)" />
          </g>
        ) : (
          <g key={group.key} className="qeg-fade">
            <circle cx={group.cx} cy={group.cy} r={group.r} fill="rgba(36,120,255,0.03)" stroke="rgba(255,255,255,0.055)" strokeDasharray="3 5" />
            <text x={group.cx} y={group.cy - group.r - 9} textAnchor="middle" fill="rgba(255,255,255,0.42)" fontSize="10" fontWeight="800" letterSpacing="0.08em">
              {group.label.length > 30 ? `${group.label.slice(0, 30)}…` : group.label.toUpperCase()} · {group.count}
            </text>
          </g>
        ),
      )}

      {/* Edges */}
      {edges.map((edge) => {
        const a = layout.positions.get(edge.source);
        const b = layout.positions.get(edge.target);
        if (!a || !b) return null;
        const active = selectedNodeId ? edge.source === selectedNodeId || edge.target === selectedNodeId : false;
        const isSelected = selectedEdgeId === edge.id;
        const inBlastPath = blast && !active ? blast.depths[edge.source] !== undefined && blast.depths[edge.target] !== undefined : false;
        const midX = (a.x + b.x) / 2;
        const midY = (a.y + b.y) / 2;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const len = Math.max(1, Math.hypot(dx, dy));
        const curve = Math.min(26, len * 0.12);
        const cxp = midX - (dy / len) * curve;
        const cyp = midY + (dx / len) * curve;
        const path = `M ${a.x} ${a.y} Q ${cxp} ${cyp} ${b.x} ${b.y}`;

        let stroke = 'rgba(255,255,255,0.08)';
        let width = 1;
        let opacity = highlightIds ? 0.12 : blast && selectedNodeId && !active && !inBlastPath ? 0.05 : 1;
        if (edge.posture === 'vulnerable') { stroke = `${RED}55`; width = 1.2; }
        else if (edge.critical) { stroke = `${ORANGE}50`; width = 1.1; }
        else if (TRUST_CHAIN_CLASSES.has(edge.trustClass)) { stroke = `${TRUST_CLASS_COLOR[edge.trustClass]}40`; width = 1.1; }
        if (inBlastPath) { stroke = `${CYAN}45`; width = 1.3; opacity = 1; }
        if (active || isSelected) { stroke = CYAN; width = 1.9; opacity = 1; }

        const directed = edge.trustClass === 'certificate-chain' || edge.trustClass === 'dependency' || edge.trustClass === 'api' || edge.trustClass === 'cloud';
        return (
          <g key={edge.id} opacity={opacity}>
            <path
              d={path}
              fill="none"
              stroke={stroke}
              strokeWidth={width}
              className={active || isSelected ? 'qeg-flow' : undefined}
              markerEnd={directed ? (active || isSelected ? 'url(#qeg-arrow-active)' : 'url(#qeg-arrow)') : undefined}
            />
            <path
              d={path}
              fill="none"
              stroke="transparent"
              strokeWidth={9}
              className="cursor-pointer"
              onClick={(event) => {
                event.stopPropagation();
                onSelectEdge(edge.id);
              }}
              onPointerDown={(event) => event.stopPropagation()}
            />
          </g>
        );
      })}

      {/* Nodes */}
      {nodes.map((node) => {
        const pos = layout.positions.get(node.id);
        if (!pos) return null;
        const color = POSTURE_COLOR[node.posture];
        const isSelected = selectedNodeId === node.id;
        const opacity = isSelected ? 1 : nodeOpacity(node);
        const r = 7 + Math.min(9, node.riskScore / 14) + (isSelected ? 2 : 0);
        const anchor = node.category === 'certificate-authority' || node.category === 'pki';
        const custody = node.category === 'kms' || node.category === 'hsm';
        const showLabel = isSelected || showAllLabels || node.riskScore >= 70 || Boolean(highlightIds?.has(node.id));
        return (
          <g
            key={node.id}
            className="qeg-node cursor-pointer"
            style={{ transform: `translate(${pos.x}px, ${pos.y}px)` }}
            opacity={opacity}
            onClick={(event) => {
              event.stopPropagation();
              onSelectNode(isSelected ? null : node.id);
            }}
            onPointerDown={(event) => event.stopPropagation()}
            onPointerMove={(event) => onHover(node, event)}
            onPointerLeave={() => onHover(null)}
          >
            {/* Blast pulse on the selected node */}
            {isSelected ? (
              <>
                <circle r={r + 4} fill="none" stroke={color} strokeWidth="1.4" opacity="0.55" />
                <circle r={r + 4} fill="none" stroke={CYAN} strokeWidth="1.2" opacity="0.7">
                  <animate attributeName="r" values={`${r + 4};${r + 26}`} dur="1.8s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.7;0" dur="1.8s" repeatCount="indefinite" />
                </circle>
                <circle r={r + 4} fill="none" stroke={CYAN} strokeWidth="1" opacity="0.5">
                  <animate attributeName="r" values={`${r + 4};${r + 26}`} dur="1.8s" begin="0.6s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.5;0" dur="1.8s" begin="0.6s" repeatCount="indefinite" />
                </circle>
              </>
            ) : null}
            {/* Direct blast neighbours get a steady cyan ring */}
            {!isSelected && blast && blast.depths[node.id] === 1 ? (
              <circle r={r + 3.5} fill="none" stroke={CYAN} strokeWidth="1.1" opacity="0.6" />
            ) : null}
            {/* Migration-in-progress rotating dashes */}
            {node.posture === 'migrating' ? (
              <circle className="qeg-migrating" r={r + 3} fill="none" stroke={color} strokeWidth="1.2" strokeDasharray="4 5" opacity="0.8" />
            ) : null}
            {/* Search highlight */}
            {highlightIds?.has(node.id) ? <circle r={r + 5} fill="none" stroke="#FBBF24" strokeWidth="1.4" opacity="0.8" /> : null}

            {anchor ? (
              <rect x={-r} y={-r} width={r * 2} height={r * 2} transform="rotate(45)" rx={2.5} fill={`${color}26`} stroke={color} strokeWidth="1.8" strokeDasharray={node.kind === 'external' ? '3 3' : undefined} />
            ) : custody ? (
              <rect x={-r} y={-r} width={r * 2} height={r * 2} rx={4} fill={`${color}26`} stroke={color} strokeWidth="1.8" strokeDasharray={node.kind === 'external' ? '3 3' : undefined} />
            ) : (
              <circle r={r} fill={`${color}26`} stroke={color} strokeWidth="1.8" strokeDasharray={node.kind === 'external' ? '3 3' : undefined} />
            )}
            {node.internetFacing ? <circle cx={r * 0.75} cy={-r * 0.75} r="2.6" fill={ORANGE} stroke="#030711" strokeWidth="0.8" /> : null}
            {showLabel ? (
              <text y={r + 12} textAnchor="middle" fill="rgba(255,255,255,0.72)" fontSize="9.5" fontWeight="600">
                {node.label.length > 20 ? `${node.label.slice(0, 20)}…` : node.label}
              </text>
            ) : null}
          </g>
        );
      })}
    </>
  );
});
