'use client';

/**
 * Quantum Exposure Graph™ canvas — a Neo4j-style force-directed property graph.
 *
 * ENGINEERING NOTES
 * -----------------
 * • LAYOUT is `d3-force` (link + many-body charge + collision + per-group
 *   anchoring). Collision radii include label clearance, so nodes never sit on
 *   top of each other however dense a group becomes.
 * • RENDERING is React-owned SVG, but simulation ticks write positions straight
 *   to the DOM through a registry of elements. Every React render reads the
 *   same mutable datums, so a re-render can never paint a stale position, and a
 *   600-edge graph settles without re-rendering 2,000 elements per frame.
 * • DATUMS PERSIST across data refreshes, filter changes and regrouping (keyed
 *   by node id), so a live SSE update nudges the graph instead of re-shuffling it.
 * • FLOWING LIGHT is budgeted (FLOW_BUDGET) and prioritised: the selected /
 *   hovered trust paths first, then quantum-vulnerable, critical and trust-chain
 *   links. It is pure CSS (stroke-dashoffset on a normalised pathLength) and is
 *   switched off under prefers-reduced-motion.
 */

import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { PointerEvent as ReactPointerEvent, RefObject } from 'react';
import {
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type Simulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force';
import { useReducedMotion } from 'motion/react';
import { Maximize2, Minimize2, Minus, Plus, RotateCcw, Scan } from 'lucide-react';
import type { BlastRadiusResult, ExposureGraphEdge, ExposureGraphNode, NodePosture } from '@/types/exposure-graph';
import { TRUST_CHAIN_CLASSES } from '@/lib/exposure-graph-intel';
import { CYAN, ORANGE, RED, SLATE } from '../_shared';
import { CATEGORY_ICON, POSTURE_COLOR, POSTURE_LABEL, TRUST_CLASS_COLOR, TRUST_CLASS_LABEL } from './_common';

export type GroupMode = 'posture' | 'tier' | 'environment' | 'category' | 'region';

export const GROUP_MODES: Array<{ key: GroupMode; label: string }> = [
  { key: 'posture', label: 'Quantum Readiness' },
  { key: 'tier', label: 'Migration Layer' },
  { key: 'environment', label: 'Environment' },
  { key: 'category', label: 'Asset Type' },
  { key: 'region', label: 'Region' },
];

/** Logical viewport (viewBox). The force layout is fitted into it. */
const W = 1200;
const H = 680;
const MIN_ZOOM = 0.2;
const MAX_ZOOM = 4;
/** Max edges carrying animated light at once — keeps 600-edge graphs smooth. */
const FLOW_BUDGET = 160;
/** Clearance added to every node's collision radius so labels do not collide. */
const LABEL_CLEARANCE = 14;
const NEUTRAL_LIGHT = '#7DD3FC';
const POSTURES = Object.keys(POSTURE_COLOR) as NodePosture[];

/* ------------------------------------------------------------------ */
/* Graph model                                                         */
/* ------------------------------------------------------------------ */

interface SimNode extends SimulationNodeDatum {
  id: string;
  r: number;
  group: string;
  /** True once the datum has been through a layout pass (has a real position). */
  placed: boolean;
}

interface SimLink extends SimulationLinkDatum<SimNode> {
  id: string;
}

interface EdgeMeta {
  source: string;
  target: string;
  /** Signed curvature — fans parallel relationships apart like Neo4j Browser. */
  bend: number;
}

interface GroupInfo {
  key: string;
  label: string;
  color: string | null;
  ax: number;
  ay: number;
  count: number;
}

interface GraphModel {
  nodes: SimNode[];
  byId: Map<string, SimNode>;
  links: SimLink[];
  edgeMeta: Map<string, EdgeMeta>;
  groups: GroupInfo[];
  members: Map<string, SimNode[]>;
  neighbours: Map<string, Set<string>>;
  columns: boolean;
  /** Node + edge identity; an unchanged key means a refresh needs no re-layout. */
  structureKey: string;
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

/** Visual radius: risk drives size, connectivity adds weight (hubs read as hubs). */
function nodeRadius(node: ExposureGraphNode): number {
  const links = node.dependents + node.dependencies;
  return 10 + Math.min(8, node.riskScore / 13) + Math.min(6, Math.sqrt(links) * 1.4);
}

/** Deterministic [0,1) from a string — seeds positions without Math.random. */
function hashUnit(value: string): number {
  let h = 2166136261;
  for (let i = 0; i < value.length; i++) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 10000) / 10000;
}

const px = (d: SimNode): number => d.x ?? 0;
const py = (d: SimNode): number => d.y ?? 0;
const r1 = (v: number): number => Math.round(v * 10) / 10;

function buildModel(nodes: ExposureGraphNode[], edges: ExposureGraphEdge[], groupBy: GroupMode, store: Map<string, SimNode>): GraphModel {
  const columns = groupBy === 'tier';

  const raw = new Map<string, { label: string; order: number; count: number }>();
  const keyById = new Map<string, string>();
  for (const node of nodes) {
    const g = groupKeyFor(node, groupBy);
    keyById.set(node.id, g.key);
    const entry = raw.get(g.key) || { label: g.label, order: g.order, count: 0 };
    entry.count += 1;
    raw.set(g.key, entry);
  }
  const ordered = [...raw.entries()].sort(
    columns ? (a, b) => a[1].order - b[1].order : (a, b) => b[1].count - a[1].count || a[1].order - b[1].order,
  );

  // Group anchors: columns for migration waves, otherwise the largest group at
  // the centre with the rest orbiting it. Orbit scales with estate size.
  const scale = Math.sqrt(Math.max(1, nodes.length));
  const groups: GroupInfo[] = ordered.map(([key, g], i) => {
    let ax = W / 2;
    let ay = H / 2;
    if (columns) {
      ax = W / 2 + (i - (ordered.length - 1) / 2) * (150 + scale * 9);
    } else if (i > 0) {
      const angle = ((i - 1) / (ordered.length - 1)) * Math.PI * 2 - Math.PI / 2;
      const orbit = 170 + scale * 16;
      ax = W / 2 + Math.cos(angle) * orbit * 1.3;
      ay = H / 2 + Math.sin(angle) * orbit;
    }
    return { key, label: g.label, color: groupBy === 'posture' ? POSTURE_COLOR[key as NodePosture] : null, ax, ay, count: g.count };
  });
  const groupByKey = new Map(groups.map((g) => [g.key, g]));

  const byId = new Map<string, SimNode>();
  const simNodes: SimNode[] = [];
  for (const node of nodes) {
    const group = keyById.get(node.id) || '';
    let datum = store.get(node.id);
    if (!datum) {
      datum = { id: node.id, r: 0, group, placed: false };
      store.set(node.id, datum);
    }
    datum.r = nodeRadius(node);
    datum.group = group;
    simNodes.push(datum);
    byId.set(node.id, datum);
  }

  const neighbours = new Map<string, Set<string>>();
  const addNeighbour = (from: string, to: string) => {
    const set = neighbours.get(from) || new Set<string>();
    set.add(to);
    neighbours.set(from, set);
  };
  const links: SimLink[] = [];
  const edgeMeta = new Map<string, EdgeMeta>();
  const pairs = new Map<string, string[]>();
  for (const edge of edges) {
    if (!byId.has(edge.source) || !byId.has(edge.target) || edge.source === edge.target) continue;
    links.push({ id: edge.id, source: edge.source, target: edge.target });
    addNeighbour(edge.source, edge.target);
    addNeighbour(edge.target, edge.source);
    const pair = edge.source < edge.target ? `${edge.source}|${edge.target}` : `${edge.target}|${edge.source}`;
    const list = pairs.get(pair) || [];
    list.push(edge.id);
    pairs.set(pair, list);
    edgeMeta.set(edge.id, { source: edge.source, target: edge.target, bend: 0 });
  }
  for (const ids of pairs.values()) {
    ids.forEach((id, index) => {
      const meta = edgeMeta.get(id);
      if (!meta) return;
      const canonical = ids.length === 1 ? 0.06 : (index - (ids.length - 1) / 2) * 0.24;
      // A reversed edge's normal flips, so flip the bend to keep the fan apart.
      meta.bend = meta.source < meta.target ? canonical : -canonical;
    });
  }

  // Seed unplaced datums next to an already-placed neighbour, else near their
  // group anchor — deterministic, so the same estate always opens the same way.
  for (const datum of simNodes) {
    if (datum.placed) continue;
    const anchorNeighbour = [...(neighbours.get(datum.id) || [])].map((id) => byId.get(id)).find((n) => n?.placed);
    const group = groupByKey.get(datum.group);
    const angle = hashUnit(datum.id) * Math.PI * 2;
    const spread = hashUnit(`${datum.id}#`);
    const baseX = anchorNeighbour ? px(anchorNeighbour) : group?.ax ?? W / 2;
    const baseY = anchorNeighbour ? py(anchorNeighbour) : group?.ay ?? H / 2;
    const dist = anchorNeighbour ? 30 + spread * 30 : 20 + spread * (40 + Math.sqrt(group?.count || 1) * 12);
    datum.x = baseX + Math.cos(angle) * dist;
    datum.y = baseY + Math.sin(angle) * dist;
    datum.vx = 0;
    datum.vy = 0;
  }

  const members = new Map<string, SimNode[]>();
  for (const datum of simNodes) {
    const list = members.get(datum.group) || [];
    list.push(datum);
    members.set(datum.group, list);
  }

  const structureKey = `${groupBy}::${simNodes.map((n) => n.id).join(',')}::${links.map((l) => l.id).join(',')}`;
  return { nodes: simNodes, byId, links, edgeMeta, groups, members, neighbours, columns, structureKey };
}

/* ------------------------------------------------------------------ */
/* Geometry (shared by React render and the tick writer)               */
/* ------------------------------------------------------------------ */

interface EdgeGeometry {
  d: string;
  len: number;
  labelTransform: string;
}

function edgeGeometry(a: SimNode, b: SimNode, bend: number): EdgeGeometry {
  const ax = px(a);
  const ay = py(a);
  const bx = px(b);
  const by = py(b);
  const dx = bx - ax;
  const dy = by - ay;
  const len = Math.max(1, Math.hypot(dx, dy));
  const offset = len * bend;
  const cx = (ax + bx) / 2 - (dy / len) * offset;
  const cy = (ay + by) / 2 + (dx / len) * offset;
  // Trim both ends to the node boundary so arrowheads land on the rim.
  const ux = cx - ax;
  const uy = cy - ay;
  const ul = Math.max(1, Math.hypot(ux, uy));
  const vx = cx - bx;
  const vy = cy - by;
  const vl = Math.max(1, Math.hypot(vx, vy));
  const sx = ax + (ux / ul) * (a.r + 1);
  const sy = ay + (uy / ul) * (a.r + 1);
  const ex = bx + (vx / vl) * (b.r + 3);
  const ey = by + (vy / vl) * (b.r + 3);
  const mx = 0.25 * sx + 0.5 * cx + 0.25 * ex;
  const my = 0.25 * sy + 0.5 * cy + 0.25 * ey;
  let angle = (Math.atan2(ey - sy, ex - sx) * 180) / Math.PI;
  if (angle > 90) angle -= 180;
  else if (angle < -90) angle += 180;
  return {
    d: `M${r1(sx)} ${r1(sy)} Q${r1(cx)} ${r1(cy)} ${r1(ex)} ${r1(ey)}`,
    len,
    labelTransform: `translate(${r1(mx)},${r1(my)}) rotate(${r1(angle)})`,
  };
}

interface HullGeometry {
  cx: number;
  cy: number;
  r: number;
  lx: number;
  ly: number;
}

function hullGeometry(members: SimNode[], columns: boolean): HullGeometry {
  let sx = 0;
  let sy = 0;
  let minY = Infinity;
  for (const m of members) {
    sx += px(m);
    sy += py(m);
    minY = Math.min(minY, py(m) - m.r);
  }
  const cx = sx / members.length;
  const cy = sy / members.length;
  let r = 0;
  for (const m of members) r = Math.max(r, Math.hypot(px(m) - cx, py(m) - cy) + m.r);
  r += 22;
  return columns ? { cx, cy, r, lx: cx, ly: minY - 30 } : { cx, cy, r, lx: cx, ly: cy - r - 10 };
}

/* ------------------------------------------------------------------ */
/* DOM registry (tick writer targets)                                  */
/* ------------------------------------------------------------------ */

interface EdgeEls {
  paths: SVGPathElement[];
  label: SVGTextElement | null;
}

interface HullEls {
  ring: SVGCircleElement | null;
  label: SVGTextElement | null;
  sub: SVGTextElement | null;
}

interface Registry {
  nodes: Map<string, SVGGElement>;
  edges: Map<string, EdgeEls>;
  hulls: Map<string, HullEls>;
}

const emptyRegistry = (): Registry => ({ nodes: new Map(), edges: new Map(), hulls: new Map() });

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

interface ViewState {
  x: number;
  y: number;
  k: number;
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
  const reduceMotion = useReducedMotion() ?? false;

  const [view, setView] = useState<ViewState>({ x: 0, y: 0, k: 1 });
  const [smoothView, setSmoothView] = useState(false);
  const [hover, setHover] = useState<HoverState | null>(null);
  const [settling, setSettling] = useState(false);

  const viewRef = useRef(view);
  viewRef.current = view;
  const selectedRef = useRef(selectedNodeId);
  selectedRef.current = selectedNodeId;

  const panRef = useRef<{ startX: number; startY: number; viewX: number; viewY: number; moved: boolean } | null>(null);
  const nodeDragRef = useRef<{ id: string; startX: number; startY: number; moved: boolean } | null>(null);
  const storeRef = useRef(new Map<string, SimNode>());
  const registryRef = useRef<Registry>(emptyRegistry());
  const simRef = useRef<Simulation<SimNode, SimLink> | null>(null);
  const modelRef = useRef<GraphModel | null>(null);
  const prevRef = useRef<{ structureKey: string; groupBy: GroupMode } | null>(null);
  const fitPendingRef = useRef(false);
  /** The analyst moved the camera since the last automatic fit. */
  const userViewRef = useRef(false);

  const model = useMemo(() => buildModel(nodes, edges, groupBy, storeRef.current), [nodes, edges, groupBy]);

  /** Tick writer — moves nodes, edges, labels and hulls without a React render. */
  const applyPositions = useCallback(() => {
    const m = modelRef.current;
    if (!m) return;
    const reg = registryRef.current;
    reg.nodes.forEach((el, id) => {
      const d = m.byId.get(id);
      if (d) el.setAttribute('transform', `translate(${r1(px(d))},${r1(py(d))})`);
    });
    reg.edges.forEach((els, id) => {
      const meta = m.edgeMeta.get(id);
      const a = meta && m.byId.get(meta.source);
      const b = meta && m.byId.get(meta.target);
      if (!meta || !a || !b) return;
      const geo = edgeGeometry(a, b, meta.bend);
      for (const path of els.paths) path.setAttribute('d', geo.d);
      els.label?.setAttribute('transform', geo.labelTransform);
    });
    reg.hulls.forEach((els, key) => {
      const members = m.members.get(key);
      if (!members?.length) return;
      const hull = hullGeometry(members, m.columns);
      if (els.ring) {
        els.ring.setAttribute('cx', String(r1(hull.cx)));
        els.ring.setAttribute('cy', String(r1(hull.cy)));
        els.ring.setAttribute('r', String(r1(hull.r)));
      }
      els.label?.setAttribute('x', String(r1(hull.lx)));
      els.label?.setAttribute('y', String(r1(hull.ly)));
      els.sub?.setAttribute('x', String(r1(hull.lx)));
      els.sub?.setAttribute('y', String(r1(hull.ly + 13)));
    });
  }, []);

  const fitView = useCallback((smooth: boolean) => {
    const m = modelRef.current;
    if (!m?.nodes.length) return;
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    for (const n of m.nodes) {
      minX = Math.min(minX, px(n) - n.r);
      maxX = Math.max(maxX, px(n) + n.r);
      minY = Math.min(minY, py(n) - n.r - (m.columns ? 40 : 0));
      maxY = Math.max(maxY, py(n) + n.r + 16);
    }
    const pad = 56;
    const k = Math.max(MIN_ZOOM, Math.min(1.8, W / (maxX - minX + pad * 2), H / (maxY - minY + pad * 2)));
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    userViewRef.current = false;
    setSmoothView(smooth);
    setView({ k, x: W / 2 - cx * k, y: H / 2 - cy * k });
  }, []);

  /* ---- Simulation lifecycle ------------------------------------------ */
  useLayoutEffect(() => {
    modelRef.current = model;
    const prev = prevRef.current;
    const fresh = !model.nodes.some((n) => n.placed);
    const regroup = Boolean(prev && prev.groupBy !== groupBy);
    const changed = !prev || prev.structureKey !== model.structureKey;
    prevRef.current = { structureKey: model.structureKey, groupBy };

    const anchors = new Map(model.groups.map((g) => [g.key, g]));
    const sim = forceSimulation<SimNode>(model.nodes)
      .velocityDecay(0.38)
      .alphaMin(0.004)
      .force(
        'link',
        forceLink<SimNode, SimLink>(model.links)
          .id((d) => d.id)
          .distance((l) => 46 + (l.source as SimNode).r + (l.target as SimNode).r),
      )
      .force('charge', forceManyBody<SimNode>().strength((d) => -180 - d.r * 9).distanceMax(520).theta(0.9))
      .force('collide', forceCollide<SimNode>((d) => d.r + LABEL_CLEARANCE).strength(0.95).iterations(2))
      .force('gx', forceX<SimNode>((d) => anchors.get(d.group)?.ax ?? W / 2).strength(model.columns ? 0.45 : 0.07))
      .force('gy', forceY<SimNode>((d) => anchors.get(d.group)?.ay ?? H / 2).strength(model.columns ? 0.035 : 0.07))
      .stop();
    simRef.current = sim;

    let ended = false;
    const onEnd = () => {
      ended = true;
      setSettling(false);
      if (fitPendingRef.current) {
        fitPendingRef.current = false;
        fitView(!reduceMotion);
      }
    };
    sim.on('tick', applyPositions).on('end', onEnd);

    if (!changed && !fresh) {
      // Same estate, new numbers (live refresh): repaint, no re-layout.
      ended = true;
      applyPositions();
    } else {
      fitPendingRef.current = fresh || regroup || !userViewRef.current;
      sim.alpha(fresh ? 1 : regroup ? 0.9 : 0.35);
      if (reduceMotion) {
        sim.tick(300);
        for (const n of model.nodes) n.placed = true;
        applyPositions();
        onEnd();
      } else {
        // Pre-warm a fresh layout so the first paint is already readable, then
        // let the remainder settle live.
        if (fresh) sim.tick(200);
        for (const n of model.nodes) n.placed = true;
        applyPositions();
        if (fresh) fitView(false);
        setSettling(true);
        sim.restart();
      }
    }

    return () => {
      sim.on('tick', null).on('end', null);
      sim.stop();
      // Interrupted mid-settle (StrictMode remount / rapid filter change):
      // let the next run treat the structure as changed and finish the job.
      if (!ended) prevRef.current = prev;
    };
  }, [model, groupBy, reduceMotion, applyPositions, fitView]);

  /* ---- Camera --------------------------------------------------------- */
  const zoomBy = useCallback((factor: number) => {
    userViewRef.current = true;
    setSmoothView(true);
    setView((v) => {
      const k = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, v.k * factor));
      const scale = k / v.k;
      return { k, x: W / 2 - (W / 2 - v.x) * scale, y: H / 2 - (H / 2 - v.y) * scale };
    });
  }, []);

  const relayout = useCallback(() => {
    const m = modelRef.current;
    const sim = simRef.current;
    if (!m || !sim) return;
    for (const n of m.nodes) {
      n.fx = null;
      n.fy = null;
    }
    sim.alpha(1);
    if (reduceMotion) {
      sim.tick(300);
      applyPositions();
      fitView(false);
      return;
    }
    fitPendingRef.current = true;
    setSettling(true);
    sim.restart();
  }, [reduceMotion, applyPositions, fitView]);

  // Center the requested node (search / cross-panel focus).
  useEffect(() => {
    if (!focus) return;
    const d = modelRef.current?.byId.get(focus.id);
    if (!d) return;
    fitPendingRef.current = false;
    userViewRef.current = true;
    const k = Math.max(viewRef.current.k, 1.25);
    setSmoothView(true);
    setView({ k, x: W / 2 - px(d) * k, y: H / 2 - py(d) * k });
  }, [focus]);

  const toLogical = useCallback((clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    // The viewBox uses the default xMidYMid meet — account for letterboxing.
    const s = Math.min(rect.width / W, rect.height / H) || 1;
    const ox = (rect.width - W * s) / 2;
    const oy = (rect.height - H * s) / 2;
    return { x: (clientX - rect.left - ox) / s, y: (clientY - rect.top - oy) / s };
  }, []);

  // Native, non-passive wheel listener so the page does not scroll while zooming.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const point = toLogical(event.clientX, event.clientY);
      userViewRef.current = true;
      setSmoothView(false);
      setView((v) => {
        const k = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, v.k * Math.exp(-event.deltaY * 0.0012)));
        const scale = k / v.k;
        return { k, x: point.x - (point.x - v.x) * scale, y: point.y - (point.y - v.y) * scale };
      });
    };
    svg.addEventListener('wheel', onWheel, { passive: false });
    return () => svg.removeEventListener('wheel', onWheel);
  }, [toLogical]);

  /* ---- Pointer: pan the canvas, drag nodes ---------------------------- */
  const onPointerDown = useCallback((event: ReactPointerEvent<SVGSVGElement>) => {
    if (event.button !== 0) return;
    const v = viewRef.current;
    panRef.current = { startX: event.clientX, startY: event.clientY, viewX: v.x, viewY: v.y, moved: false };
    svgRef.current?.setPointerCapture?.(event.pointerId);
  }, []);

  const onNodePointerDown = useCallback((id: string, event: ReactPointerEvent<SVGGElement>) => {
    event.stopPropagation();
    if (event.button !== 0) return;
    nodeDragRef.current = { id, startX: event.clientX, startY: event.clientY, moved: false };
    svgRef.current?.setPointerCapture?.(event.pointerId);
  }, []);

  const onPointerMove = useCallback(
    (event: ReactPointerEvent<SVGSVGElement>) => {
      const nodeDrag = nodeDragRef.current;
      if (nodeDrag) {
        if (!nodeDrag.moved) {
          if (Math.abs(event.clientX - nodeDrag.startX) + Math.abs(event.clientY - nodeDrag.startY) < 4) return;
          nodeDrag.moved = true;
          setHover(null);
          setSettling(true);
          simRef.current?.alphaTarget(0.25).restart();
        }
        const d = modelRef.current?.byId.get(nodeDrag.id);
        if (!d) return;
        const p = toLogical(event.clientX, event.clientY);
        const v = viewRef.current;
        d.fx = (p.x - v.x) / v.k;
        d.fy = (p.y - v.y) / v.k;
        return;
      }
      const pan = panRef.current;
      if (!pan) return;
      const a = toLogical(pan.startX, pan.startY);
      const b = toLogical(event.clientX, event.clientY);
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) pan.moved = true;
      if (pan.moved) {
        userViewRef.current = true;
        setSmoothView(false);
        setView((v) => ({ ...v, x: pan.viewX + dx, y: pan.viewY + dy }));
      }
    },
    [toLogical],
  );

  const onPointerUp = useCallback(() => {
    const nodeDrag = nodeDragRef.current;
    if (nodeDrag) {
      nodeDragRef.current = null;
      if (!nodeDrag.moved) {
        onSelectNode(selectedRef.current === nodeDrag.id ? null : nodeDrag.id);
        return;
      }
      const d = modelRef.current?.byId.get(nodeDrag.id);
      if (d) {
        d.fx = null;
        d.fy = null;
      }
      simRef.current?.alphaTarget(0);
      return;
    }
    const pan = panRef.current;
    panRef.current = null;
    if (pan && !pan.moved) {
      onSelectNode(null);
      onSelectEdge(null);
    }
  }, [onSelectNode, onSelectEdge]);

  const handleHover = useCallback((node: ExposureGraphNode | null, event?: ReactPointerEvent) => {
    if (!node || !event || !containerRef.current || nodeDragRef.current || panRef.current) {
      setHover(null);
      return;
    }
    const rect = containerRef.current.getBoundingClientRect();
    setHover({ node, x: event.clientX - rect.left, y: event.clientY - rect.top });
  }, []);

  const hoverId = hover?.node.id ?? null;
  const allLabels = nodes.length <= 60 || view.k >= 1.3;
  const edgeLabels = edges.length <= 200 && view.k >= 1.8;

  return (
    <div ref={containerRef} className={`relative overflow-hidden rounded-lg bg-[#030711] ${fullscreen ? 'h-full' : 'h-[560px] xl:h-[640px]'}`}>
      <style>{`
        @keyframes qegComet { from { stroke-dashoffset: 100; } to { stroke-dashoffset: 0; } }
        @keyframes qegCometHead { from { stroke-dashoffset: 82; } to { stroke-dashoffset: -18; } }
        @keyframes qegSpin { to { transform: rotate(360deg); } }
        @keyframes qegBreathe { 0%, 100% { opacity: 0.35; } 50% { opacity: 0.95; } }
        @keyframes qegFade { from { opacity: 0; } }
        .qeg-comet { fill: none; stroke-linecap: round; pointer-events: none; animation-timing-function: linear; animation-iteration-count: infinite; }
        .qeg-comet-trail { stroke-dasharray: 22 78; animation-name: qegComet; }
        .qeg-comet-head { stroke-dasharray: 4 96; animation-name: qegCometHead; }
        .qeg-migrating { transform-box: fill-box; transform-origin: center; animation: qegSpin 6s linear infinite; }
        .qeg-breathe { animation: qegBreathe 2.6s ease-in-out infinite; }
        .qeg-fade { animation: qegFade 400ms ease; }
        /* SVG label palette — a dark halo on the navy canvas, a light halo and
           warm ink on the light theme's parchment canvas (CSS beats attributes). */
        .qeg-text { stroke: #030711; paint-order: stroke; stroke-linejoin: round; }
        .qeg-node-label { fill: rgba(255, 255, 255, 0.78); }
        .qeg-node-label--strong { fill: #FFFFFF; }
        .qeg-group-label--neutral { fill: rgba(255, 255, 255, 0.55); }
        .qeg-group-sub { fill: rgba(255, 255, 255, 0.32); }
        .qg-theme-light .qeg-text { stroke: rgba(243, 237, 225, 0.92); }
        .qg-theme-light .qeg-node-label { fill: #5E4E41; }
        .qg-theme-light .qeg-node-label--strong { fill: #3A2D23; }
        .qg-theme-light .qeg-group-label--neutral { fill: #6E5D4E; }
        .qg-theme-light .qeg-group-sub { fill: rgba(94, 78, 65, 0.6); }
        @media (prefers-reduced-motion: reduce) {
          .qeg-comet { display: none; }
          .qeg-migrating, .qeg-breathe { animation: none; }
        }
      `}</style>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        className="h-full w-full cursor-grab touch-none select-none active:cursor-grabbing"
        role="img"
        aria-label="Enterprise cryptographic dependency graph"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      >
        <defs>
          <radialGradient id="qeg-bg" cx="50%" cy="45%" r="75%">
            <stop offset="0%" stopColor="rgba(36,120,255,0.10)" />
            <stop offset="55%" stopColor="rgba(34,211,238,0.025)" />
            <stop offset="100%" stopColor="rgba(3,7,17,0)" />
          </radialGradient>
          <pattern id="qeg-dots" width="24" height="24" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="0.9" fill="rgba(148,163,184,0.13)" />
          </pattern>
          {POSTURES.map((posture) => (
            <radialGradient key={`fill-${posture}`} id={`qeg-fill-${posture}`} cx="34%" cy="28%" r="78%">
              <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.42" />
              <stop offset="32%" stopColor={POSTURE_COLOR[posture]} stopOpacity="0.96" />
              <stop offset="100%" stopColor={POSTURE_COLOR[posture]} stopOpacity="0.62" />
            </radialGradient>
          ))}
          {POSTURES.map((posture) => (
            <radialGradient key={`halo-${posture}`} id={`qeg-halo-${posture}`}>
              <stop offset="45%" stopColor={POSTURE_COLOR[posture]} stopOpacity="0.5" />
              <stop offset="100%" stopColor={POSTURE_COLOR[posture]} stopOpacity="0" />
            </radialGradient>
          ))}
          {[
            { id: 'qeg-arrow', fill: 'rgba(148,163,184,0.55)' },
            { id: 'qeg-arrow-active', fill: CYAN },
            { id: 'qeg-arrow-vulnerable', fill: RED },
          ].map((marker) => (
            <marker
              key={marker.id}
              id={marker.id}
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="8"
              markerHeight="8"
              markerUnits="userSpaceOnUse"
              orient="auto-start-reverse"
            >
              <path d="M0,1 L10,5 L0,9 Z" fill={marker.fill} />
            </marker>
          ))}
        </defs>
        <rect x="0" y="0" width={W} height={H} fill="url(#qeg-dots)" />
        <rect x="0" y="0" width={W} height={H} fill="url(#qeg-bg)" />

        <g
          style={{
            transform: `translate(${view.x}px, ${view.y}px) scale(${view.k})`,
            transformOrigin: '0 0',
            transition: smoothView && !reduceMotion ? 'transform 650ms cubic-bezier(0.22, 1, 0.36, 1)' : 'none',
          }}
        >
          <GraphContent
            model={model}
            nodes={nodes}
            edges={edges}
            selectedNodeId={selectedNodeId}
            selectedEdgeId={selectedEdgeId}
            blast={blast}
            highlightIds={highlightIds}
            hoverId={hoverId}
            allLabels={allLabels}
            edgeLabels={edgeLabels}
            registryRef={registryRef}
            onNodePointerDown={onNodePointerDown}
            onSelectEdge={onSelectEdge}
            onHover={handleHover}
          />
        </g>
      </svg>

      {/* Layout status */}
      <div className="pointer-events-none absolute left-3 top-3 flex items-center gap-2 rounded-md border border-white/10 bg-[#07101D]/85 px-2.5 py-1.5 text-[10px] font-bold text-white/60 backdrop-blur">
        <span className={`h-1.5 w-1.5 rounded-full ${settling ? 'animate-pulse bg-cyan-300' : 'bg-emerald-400'}`} />
        {settling ? 'Force layout settling…' : 'Force layout stable'}
        <span className="hidden font-medium text-white/35 sm:inline">· Drag nodes · Scroll to zoom · Click to inspect</span>
      </div>

      {/* Camera / layout controls */}
      <div className="absolute right-3 top-3 flex flex-col gap-1.5">
        {[
          { icon: Plus, action: () => zoomBy(1.35), label: 'Zoom in' },
          { icon: Minus, action: () => zoomBy(1 / 1.35), label: 'Zoom out' },
          { icon: Scan, action: () => fitView(true), label: 'Fit graph' },
          { icon: RotateCcw, action: relayout, label: 'Re-run layout' },
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
              className="grid h-8 w-8 place-items-center rounded-md border border-white/10 bg-[#07101D]/85 text-white/60 backdrop-blur transition hover:border-cyan-400/45 hover:text-cyan-200"
            >
              <Icon className="h-4 w-4" />
            </button>
          );
        })}
      </div>

      {/* Legend */}
      <div className="pointer-events-none absolute bottom-3 left-3 right-14 flex flex-col gap-1.5 rounded-md border border-white/8 bg-[#07101D]/85 px-3 py-2 text-[10px] text-white/55 backdrop-blur sm:right-auto">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
          {POSTURES.map((posture) => (
            <span key={posture} className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: POSTURE_COLOR[posture], boxShadow: `0 0 6px ${POSTURE_COLOR[posture]}` }} />
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
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-white/45">
          {[
            { color: RED, label: 'Quantum-vulnerable link' },
            { color: ORANGE, label: 'Critical trust link' },
            { color: CYAN, label: 'Selected trust path' },
          ].map((item) => (
            <span key={item.label} className="inline-flex items-center gap-1.5">
              <span className="h-[2px] w-5 rounded-full" style={{ background: `linear-gradient(90deg, transparent, ${item.color}, #fff)` }} />
              {item.label}
            </span>
          ))}
          <span className="text-white/30">Light flows source → target</span>
        </div>
      </div>

      {/* Hover tooltip */}
      {hover ? (
        <div
          className="pointer-events-none absolute z-20 w-60 rounded-md border border-cyan-400/25 bg-[#0A1728]/95 p-3 shadow-[0_12px_36px_rgba(0,0,0,0.55)] backdrop-blur"
          style={{ left: Math.min(hover.x + 14, (containerRef.current?.clientWidth || 400) - 252), top: Math.max(8, hover.y - 10) }}
        >
          <div className="truncate text-xs font-bold text-white">{hover.node.label}</div>
          <div className="mt-0.5 truncate text-[10px] text-white/45">
            {hover.node.tierLabel}
            {hover.node.environment ? ` · ${hover.node.environment}` : ''}
          </div>
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
/* Memoized content — positions come from the live datums              */
/* ------------------------------------------------------------------ */

interface GraphContentProps {
  model: GraphModel;
  nodes: ExposureGraphNode[];
  edges: ExposureGraphEdge[];
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  blast: BlastRadiusResult | null;
  highlightIds: Set<string> | null;
  hoverId: string | null;
  allLabels: boolean;
  edgeLabels: boolean;
  registryRef: RefObject<Registry>;
  onNodePointerDown: (id: string, event: ReactPointerEvent<SVGGElement>) => void;
  onSelectEdge: (id: string | null) => void;
  onHover: (node: ExposureGraphNode | null, event?: ReactPointerEvent) => void;
}

const GraphContent = memo(function GraphContent({
  model,
  nodes,
  edges,
  selectedNodeId,
  selectedEdgeId,
  blast,
  highlightIds,
  hoverId,
  allLabels,
  edgeLabels,
  registryRef,
  onNodePointerDown,
  onSelectEdge,
  onHover,
}: GraphContentProps) {
  const rootRef = useRef<SVGGElement>(null);

  // Rebuild the tick writer's element registry after every render.
  useLayoutEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const next = emptyRegistry();
    root.querySelectorAll<SVGGElement>('[data-nid]').forEach((el) => {
      if (el.dataset.nid) next.nodes.set(el.dataset.nid, el);
    });
    const edgeEntry = (id: string): EdgeEls => {
      let entry = next.edges.get(id);
      if (!entry) {
        entry = { paths: [], label: null };
        next.edges.set(id, entry);
      }
      return entry;
    };
    root.querySelectorAll<SVGPathElement>('path[data-eid]').forEach((el) => {
      if (el.dataset.eid) edgeEntry(el.dataset.eid).paths.push(el);
    });
    root.querySelectorAll<SVGTextElement>('text[data-elabel]').forEach((el) => {
      if (el.dataset.elabel) edgeEntry(el.dataset.elabel).label = el;
    });
    root.querySelectorAll<SVGElement>('[data-hull]').forEach((el) => {
      const key = el.dataset.hull;
      if (!key) return;
      const entry = next.hulls.get(key) || { ring: null, label: null, sub: null };
      if (el.dataset.part === 'ring') entry.ring = el as SVGCircleElement;
      else if (el.dataset.part === 'label') entry.label = el as SVGTextElement;
      else if (el.dataset.part === 'sub') entry.sub = el as SVGTextElement;
      next.hulls.set(key, entry);
    });
    registryRef.current = next;
  });

  // Hover lights up a neighbourhood only when nothing else owns the focus.
  const hoverActive = hoverId && !selectedNodeId && !highlightIds ? hoverId : null;
  const hoverNeighbours = hoverActive ? model.neighbours.get(hoverActive) : undefined;

  /** Which edges carry flowing light, and in what colour (budgeted, prioritised). */
  const flows = useMemo(() => {
    const ranked: Array<{ id: string; score: number; color: string }> = [];
    for (const edge of edges) {
      const touchesSelected = selectedNodeId ? edge.source === selectedNodeId || edge.target === selectedNodeId : false;
      const touchesHover = hoverActive ? edge.source === hoverActive || edge.target === hoverActive : false;
      const inBlast = blast && selectedNodeId ? blast.depths[edge.source] !== undefined && blast.depths[edge.target] !== undefined : false;
      if (touchesSelected || touchesHover || selectedEdgeId === edge.id) ranked.push({ id: edge.id, score: 100, color: CYAN });
      else if (inBlast) ranked.push({ id: edge.id, score: 60, color: CYAN });
      else if (selectedNodeId || highlightIds) continue;
      else if (edge.posture === 'vulnerable') ranked.push({ id: edge.id, score: 40, color: RED });
      else if (edge.critical) ranked.push({ id: edge.id, score: 30, color: ORANGE });
      else if (TRUST_CHAIN_CLASSES.has(edge.trustClass)) ranked.push({ id: edge.id, score: 20, color: TRUST_CLASS_COLOR[edge.trustClass] });
      else ranked.push({ id: edge.id, score: 5, color: NEUTRAL_LIGHT });
    }
    ranked.sort((a, b) => b.score - a.score);
    return new Map(ranked.slice(0, FLOW_BUDGET).map((f) => [f.id, f.color]));
  }, [edges, selectedNodeId, selectedEdgeId, blast, highlightIds, hoverActive]);

  const nodeOpacity = (node: ExposureGraphNode): number => {
    if (highlightIds) return highlightIds.has(node.id) ? 1 : 0.18;
    if (blast && selectedNodeId) {
      const depth = blast.depths[node.id];
      if (depth === undefined) return 0.12;
      return depth <= 1 ? 1 : 0.8;
    }
    if (hoverActive) return node.id === hoverActive || hoverNeighbours?.has(node.id) ? 1 : 0.3;
    return 1;
  };

  return (
    <g ref={rootRef}>
      {/* Group hulls / column headers */}
      {model.groups.map((group) => {
        const members = model.members.get(group.key);
        if (!members?.length) return null;
        const hull = hullGeometry(members, model.columns);
        const tone = group.color || '#94A3B8';
        const label = group.label.length > 32 ? `${group.label.slice(0, 32)}…` : group.label;
        return (
          <g key={group.key} className="qeg-fade" pointerEvents="none">
            {!model.columns ? (
              <circle
                data-hull={group.key}
                data-part="ring"
                cx={r1(hull.cx)}
                cy={r1(hull.cy)}
                r={r1(hull.r)}
                fill={`${tone}0A`}
                stroke={tone}
                strokeOpacity={0.22}
                strokeDasharray="2 6"
              />
            ) : null}
            <text
              data-hull={group.key}
              data-part="label"
              x={r1(hull.lx)}
              y={r1(hull.ly)}
              textAnchor="middle"
              className={group.color ? 'qeg-text' : 'qeg-text qeg-group-label--neutral'}
              fill={group.color || undefined}
              fillOpacity={0.8}
              fontSize="10.5"
              fontWeight="800"
              letterSpacing="0.1em"
              strokeWidth="3"
            >
              {label.toUpperCase()}
              {model.columns ? '' : ` · ${group.count}`}
            </text>
            {model.columns ? (
              <text data-hull={group.key} data-part="sub" x={r1(hull.lx)} y={r1(hull.ly + 13)} textAnchor="middle" className="qeg-group-sub" fontSize="9">
                {group.count} asset(s)
              </text>
            ) : null}
          </g>
        );
      })}

      {/* Relationships */}
      {edges.map((edge) => {
        const meta = model.edgeMeta.get(edge.id);
        const a = model.byId.get(edge.source);
        const b = model.byId.get(edge.target);
        if (!meta || !a || !b) return null;
        const geo = edgeGeometry(a, b, meta.bend);
        const active = selectedNodeId ? edge.source === selectedNodeId || edge.target === selectedNodeId : false;
        const hovered = hoverActive ? edge.source === hoverActive || edge.target === hoverActive : false;
        const isSelected = selectedEdgeId === edge.id;
        const inBlastPath = blast && !active ? blast.depths[edge.source] !== undefined && blast.depths[edge.target] !== undefined : false;

        let stroke = 'rgba(148,163,184,0.2)';
        let width = 1;
        let marker = 'url(#qeg-arrow)';
        let opacity = highlightIds ? 0.12 : blast && selectedNodeId && !active && !inBlastPath ? 0.05 : hoverActive && !hovered ? 0.25 : 1;
        if (edge.posture === 'vulnerable') { stroke = `${RED}66`; width = 1.25; marker = 'url(#qeg-arrow-vulnerable)'; }
        else if (edge.critical) { stroke = `${ORANGE}5E`; width = 1.15; }
        else if (TRUST_CHAIN_CLASSES.has(edge.trustClass)) { stroke = `${TRUST_CLASS_COLOR[edge.trustClass]}55`; width = 1.15; }
        if (inBlastPath) { stroke = `${CYAN}55`; width = 1.35; opacity = 1; }
        if (active || hovered || isSelected) { stroke = `${CYAN}B3`; width = 1.8; opacity = 1; marker = 'url(#qeg-arrow-active)'; }

        const directed = edge.trustClass === 'certificate-chain' || edge.trustClass === 'dependency' || edge.trustClass === 'api' || edge.trustClass === 'cloud';
        const flow = flows.get(edge.id);
        const duration = Math.round(Math.max(1.3, Math.min(4.2, geo.len / 120)) * 10) / 10;
        const delay = Math.round(hashUnit(edge.id) * duration * 100) / 100;
        const cometTiming = { animationDuration: `${duration}s`, animationDelay: `-${delay}s` };
        const showLabel = isSelected || hovered || (active && edges.length <= 400) || edgeLabels;
        const labelText = `${TRUST_CLASS_LABEL[edge.trustClass]}${edge.algorithm ? ` · ${edge.algorithm}` : ''}`;

        return (
          <g key={edge.id} opacity={opacity}>
            <path data-eid={edge.id} d={geo.d} fill="none" stroke={stroke} strokeWidth={width} markerEnd={directed ? marker : undefined} />
            {flow ? (
              <>
                <path data-eid={edge.id} d={geo.d} pathLength={100} className="qeg-comet qeg-comet-trail" stroke={flow} strokeWidth={5.5} strokeOpacity={0.16} style={cometTiming} />
                <path data-eid={edge.id} d={geo.d} pathLength={100} className="qeg-comet qeg-comet-trail" stroke={flow} strokeWidth={1.7} strokeOpacity={0.75} style={cometTiming} />
                <path data-eid={edge.id} d={geo.d} pathLength={100} className="qeg-comet qeg-comet-head" stroke="#F8FAFC" strokeWidth={2.4} strokeOpacity={0.95} style={cometTiming} />
              </>
            ) : null}
            {showLabel ? (
              <text
                data-elabel={edge.id}
                transform={geo.labelTransform}
                dy={-4}
                textAnchor="middle"
                fill={active || hovered || isSelected ? CYAN : TRUST_CLASS_COLOR[edge.trustClass]}
                fontSize="8"
                fontWeight="700"
                letterSpacing="0.06em"
                className="qeg-text"
                strokeWidth="2.6"
                pointerEvents="none"
              >
                {labelText.toUpperCase()}
              </text>
            ) : null}
            <path
              data-eid={edge.id}
              d={geo.d}
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
        const datum = model.byId.get(node.id);
        if (!datum) return null;
        const color = POSTURE_COLOR[node.posture];
        const isSelected = selectedNodeId === node.id;
        const isHovered = hoverId === node.id;
        const emphasised = isSelected || isHovered;
        const opacity = isSelected ? 1 : nodeOpacity(node);
        const r = datum.r + (isSelected ? 2 : 0);
        const anchor = node.category === 'certificate-authority' || node.category === 'pki';
        const custody = node.category === 'kms' || node.category === 'hsm';
        const showLabel = emphasised || allLabels || node.riskScore >= 70 || Boolean(highlightIds?.has(node.id));
        const Icon = CATEGORY_ICON[node.category] || CATEGORY_ICON.service;
        const iconSize = Math.round(r * 1.05);
        const breathe = node.posture === 'vulnerable' && node.riskScore >= 80;
        const shapeProps = {
          fill: `url(#qeg-fill-${node.posture})`,
          stroke: emphasised ? '#FFFFFF' : color,
          strokeOpacity: emphasised ? 0.9 : 1,
          strokeWidth: 1.8,
          strokeDasharray: node.kind === 'external' ? '3 3' : undefined,
        };
        return (
          <g
            key={node.id}
            data-nid={node.id}
            transform={`translate(${r1(px(datum))},${r1(py(datum))})`}
            className="cursor-pointer"
            opacity={opacity}
            onPointerDown={(event) => onNodePointerDown(node.id, event)}
            onPointerMove={(event) => onHover(node, event)}
            onPointerLeave={() => onHover(null)}
          >
            {/* Glow halo — breathes on the highest-risk vulnerable assets */}
            <circle
              r={r + 9}
              fill={`url(#qeg-halo-${node.posture})`}
              opacity={emphasised ? 0.9 : 0.35}
              className={breathe && !isSelected ? 'qeg-breathe' : undefined}
              pointerEvents="none"
            />
            {/* Blast pulse on the selected node */}
            {isSelected ? (
              <>
                <circle r={r + 4} fill="none" stroke={color} strokeWidth="1.4" opacity="0.55" />
                <circle r={r + 4} fill="none" stroke={CYAN} strokeWidth="1.2" opacity="0.7">
                  <animate attributeName="r" values={`${r + 4};${r + 28}`} dur="1.8s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.7;0" dur="1.8s" repeatCount="indefinite" />
                </circle>
                <circle r={r + 4} fill="none" stroke={CYAN} strokeWidth="1" opacity="0.5">
                  <animate attributeName="r" values={`${r + 4};${r + 28}`} dur="1.8s" begin="0.6s" repeatCount="indefinite" />
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
              <rect x={-r * 0.82} y={-r * 0.82} width={r * 1.64} height={r * 1.64} transform="rotate(45)" rx={3} {...shapeProps} />
            ) : custody ? (
              <rect x={-r * 0.9} y={-r * 0.9} width={r * 1.8} height={r * 1.8} rx={r * 0.32} {...shapeProps} />
            ) : (
              <>
                <circle r={r} {...shapeProps} />
                {/* Inner rim for depth */}
                <circle r={Math.max(2, r - 2.5)} fill="none" stroke="rgba(3,7,17,0.35)" strokeWidth="1" pointerEvents="none" />
              </>
            )}
            <Icon
              x={-iconSize / 2}
              y={-iconSize / 2}
              size={iconSize}
              color="#FFFFFF"
              strokeWidth={2.2}
              opacity={0.92}
              aria-hidden="true"
              pointerEvents="none"
            />
            {node.internetFacing ? <circle cx={r * 0.74} cy={-r * 0.74} r="3" fill={ORANGE} stroke="#030711" strokeWidth="1" /> : null}
            {showLabel ? (
              <text
                y={r + 13}
                textAnchor="middle"
                className={emphasised ? 'qeg-text qeg-node-label qeg-node-label--strong' : 'qeg-text qeg-node-label'}
                fontSize="9.5"
                fontWeight="600"
                strokeWidth="3"
                pointerEvents="none"
              >
                {node.label.length > 22 ? `${node.label.slice(0, 21)}…` : node.label}
              </text>
            ) : null}
          </g>
        );
      })}
    </g>
  );
});
