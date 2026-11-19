'use client';

/**
 * QGuard Helix Exposure Workflow Graph™ — the process/exposure relationship canvas.
 *
 * Renders {@link buildWorkflowGraph} as a live force-directed map: the scan, the
 * lifecycle phases it ran, the engine processes each phase spawned, the
 * engine→engine dependency chain, and the findings, files, algorithms, CBOM
 * components, packages, secrets, correlated exposures and remediations they
 * reach. Eight lenses project the SAME graph, so a node's severity, size and
 * verdict cannot disagree between tabs.
 *
 * ENGINEERING NOTES
 * -----------------
 * • LAYOUT is `d3-force`; RENDERING is React Flow. The simulation owns
 *   positions and React Flow owns the viewport, node chrome and interaction.
 *   Dragging a node writes `fx/fy` back into the simulation and re-heats it, so
 *   the neighbourhood reacts the way a physical graph should.
 * • FOCUS STATE IS AN EXTERNAL STORE, read per node through
 *   `useSyncExternalStore` with a primitive snapshot. Hovering a node in a
 *   400-node graph therefore re-renders the handful of nodes whose visual state
 *   actually changed, not the whole canvas.
 * • HONESTY RULES CARRY THROUGH THE PICTURE. Nodes with no finding behind them
 *   are painted "None" slate, never a passing green. Inferred nodes and edges
 *   are dashed and can be switched off, so an operator can see only what was
 *   literally read. The reconciliation footer states projected-vs-total, and
 *   any capped population is disclosed rather than silently dropped.
 */

import React from 'react';
import {
  Background,
  BackgroundVariant,
  MiniMap,
  Panel as FlowPanel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  useStore,
  useViewport,
  ViewportPortal,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
  type ReactFlowInstance,
} from '@xyflow/react';
import '@xyflow/react/dist/base.css';
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
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import {
  Activity,
  AlertTriangle,
  Atom,
  BadgeCheck,
  Boxes,
  Check,
  Crosshair,
  ChevronRight,
  Cpu,
  Filter,
  Fingerprint,
  FileCode2,
  Layers,
  Maximize2,
  Minimize2,
  Minus,
  Package,
  Palette,
  Pause,
  Play,
  Plus,
  Radar,
  RotateCcw,
  Scan,
  ScanSearch,
  Search,
  Server,
  ShieldAlert,
  Waypoints,
  Wrench,
  X,
  type LucideIcon,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { ACCENT, Panel, SectionLabel } from '@/components/quantum-scan/ui';
import type { CorrelatedExposure, ExposureAssessment, ExposureFinding, FindingSeverity } from '@/lib/scanner/exposure/types';
import { descriptorsForMode } from '@/lib/scanner/exposure/registry';
import {
  buildWorkflowGraph,
  degreeMap,
  EDGE_KIND_LABEL,
  GROUPING_LABEL,
  neighboursOf,
  NODE_KIND_LABEL,
  NODE_KIND_SINGULAR,
  projectLens,
  WORKFLOW_LENSES,
  type WorkflowEdge,
  type WorkflowGraph,
  type WorkflowGrouping,
  type WorkflowLensDefinition,
  type WorkflowLens,
  type WorkflowNode,
  type WorkflowNodeKind,
} from '@/lib/scanner/exposure/workflow-graph';
import { QUANTUM_COLOR, QUANTUM_LABEL, SEVERITY_COLOR, FindingDetail } from './shared';

/* ────────────────────────────────────────────────────────────────── palette ── */

/** "None" is slate — an unmeasured node is never painted as a pass (§43). */
const NONE_COLOR = '#64748b';

/** Rendered while a projection is still loading. Never a fabricated stand-in. */
const EMPTY_GRAPH: WorkflowGraph = {
  nodes: [],
  edges: [],
  clusters: [],
  counts: {
    scan: 0, phase: 0, engine: 0, layer: 0, asset: 0, certificate: 0,
    finding: 0, algorithm: 0, component: 0, dependency: 0, secret: 0,
    file: 0, exposure: 0, remediation: 0,
  },
  reconciliation: {
    findingsInAssessment: 0, findingsProjected: 0,
    componentsInAssessment: 0, componentsProjected: 0,
    exposuresInAssessment: 0, exposuresProjected: 0,
  },
  truncation: { truncated: false, dropped: [] },
};

const KIND_COLOR: Record<WorkflowNodeKind, string> = {
  scan: ACCENT.cyan,
  phase: ACCENT.blue,
  engine: '#818cf8',
  layer: '#5eead4',
  asset: '#38bdf8',
  certificate: '#a3e635',
  finding: ACCENT.rose,
  algorithm: ACCENT.violet,
  component: ACCENT.emerald,
  dependency: '#facc15',
  secret: '#f472b6',
  file: '#94a3b8',
  exposure: '#fb923c',
  remediation: '#2dd4bf',
};

const DETECTION_COLOR: Record<string, string> = {
  observed: ACCENT.emerald,
  inferred: ACCENT.violet,
  potential: ACCENT.amber,
  unknown: NONE_COLOR,
};

const DETECTION_LABEL: Record<string, string> = {
  observed: 'Observed',
  inferred: 'Inferred',
  potential: 'Potential',
  unknown: 'Unknown',
};

const KIND_ICON: Record<WorkflowNodeKind, LucideIcon> = {
  scan: ScanSearch,
  phase: Waypoints,
  engine: Cpu,
  layer: Layers,
  asset: Server,
  certificate: BadgeCheck,
  finding: ShieldAlert,
  algorithm: Atom,
  component: Boxes,
  dependency: Package,
  secret: Fingerprint,
  file: FileCode2,
  exposure: Radar,
  remediation: Wrench,
};

type ColourMode = 'risk' | 'type' | 'evidence';

const SEVERITY_BANDS: Array<{ id: FindingSeverity | 'none'; label: string; color: string }> = [
  { id: 'critical', label: 'Critical', color: SEVERITY_COLOR.critical },
  { id: 'high', label: 'High', color: SEVERITY_COLOR.high },
  { id: 'medium', label: 'Medium', color: SEVERITY_COLOR.medium },
  { id: 'low', label: 'Low', color: SEVERITY_COLOR.low },
  { id: 'info', label: 'Info', color: SEVERITY_COLOR.info },
  { id: 'none', label: 'None', color: NONE_COLOR },
];

function colourOf(node: WorkflowNode, mode: ColourMode): string {
  if (mode === 'type') return KIND_COLOR[node.kind];
  if (mode === 'evidence') return DETECTION_COLOR[node.detection] ?? NONE_COLOR;
  return node.severity ? SEVERITY_COLOR[node.severity] : NONE_COLOR;
}

/* ────────────────────────────────────────────────────────── the focus store ── */

type FocusState = 'idle' | 'focus' | 'neighbour' | 'dim' | 'selected';

/**
 * A minimal external store for hover/selection.
 *
 * Node chrome reads it with `useSyncExternalStore` and a PRIMITIVE snapshot, so
 * React bails out of re-rendering every node whose state string is unchanged.
 * With a few hundred bodies on screen that is the difference between a smooth
 * hover and a visibly janky one.
 */
class FocusStore {
  private listeners = new Set<() => void>();
  private hovered: string | null = null;
  private selected: string | null = null;
  private related: Set<string> = new Set();
  private edgesRef: readonly WorkflowEdge[] = [];

  setEdges(edges: readonly WorkflowEdge[]) {
    this.edgesRef = edges;
    this.recompute();
  }

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private emit() {
    for (const listener of this.listeners) listener();
  }

  private recompute() {
    const anchor = this.hovered ?? this.selected;
    this.related = anchor ? neighboursOf(this.edgesRef, anchor) : new Set();
  }

  hover(id: string | null) {
    if (this.hovered === id) return;
    this.hovered = id;
    this.recompute();
    this.emit();
  }

  select(id: string | null) {
    if (this.selected === id) return;
    this.selected = id;
    this.recompute();
    this.emit();
  }

  nodeState = (id: string): FocusState => {
    const anchor = this.hovered ?? this.selected;
    if (!anchor) return 'idle';
    if (id === this.selected) return 'selected';
    if (id === anchor) return 'focus';
    return this.related.has(id) ? 'neighbour' : 'dim';
  };

  edgeState = (source: string, target: string): FocusState => {
    const anchor = this.hovered ?? this.selected;
    if (!anchor) return 'idle';
    return source === anchor || target === anchor ? 'focus' : 'dim';
  };
}

const FocusContext = React.createContext<FocusStore | null>(null);

/** Stable no-op subscription, so a missing store cannot cause a resubscribe
 *  on every render. */
const NO_SUBSCRIPTION = () => () => {};

function useFocusState(id: string): FocusState {
  const store = React.useContext(FocusContext);
  return React.useSyncExternalStore(
    store ? store.subscribe : NO_SUBSCRIPTION,
    () => (store ? store.nodeState(id) : 'idle'),
    () => 'idle' as FocusState,
  );
}

function useEdgeFocusState(source: string, target: string): FocusState {
  const store = React.useContext(FocusContext);
  return React.useSyncExternalStore(
    store ? store.subscribe : NO_SUBSCRIPTION,
    () => (store ? store.edgeState(source, target) : 'idle'),
    () => 'idle' as FocusState,
  );
}

/* ───────────────────────────────────────────────────────────── node chrome ── */

interface EntityNodeData extends Record<string, unknown> {
  model: WorkflowNode;
  radius: number;
  color: string;
  pinned: boolean;
}

type EntityNode = Node<EntityNodeData, 'entity'>;

function EntityNodeView({ id, data }: NodeProps<EntityNode>) {
  const { model, radius, color, pinned } = data;
  const state = useFocusState(id);
  const Icon = KIND_ICON[model.kind];
  const size = radius * 2;
  const dim = state === 'dim';
  const lit = state === 'focus' || state === 'selected';
  const iconSize = Math.max(11, Math.min(20, Math.round(radius * 0.78)));

  return (
    <div
      className="relative grid place-items-center"
      style={{
        width: size,
        height: size,
        opacity: dim ? 0.16 : 1,
        transition: 'opacity 160ms ease',
      }}
    >
      {/* halo — only for the focused / selected body, so the canvas stays calm */}
      {lit && (
        <span
          aria-hidden
          className="pointer-events-none absolute inset-0 rounded-full"
          style={{ boxShadow: `0 0 0 4px ${color}22, 0 0 26px ${color}55` }}
        />
      )}
      <span
        className="grid h-full w-full place-items-center rounded-full border"
        style={{
          borderColor: lit ? color : `${color}88`,
          borderWidth: state === 'selected' ? 2 : 1.5,
          backgroundColor: `${color}${lit ? '33' : '1c'}`,
          color,
          transition: 'background-color 160ms ease, border-color 160ms ease',
        }}
      >
        <Icon style={{ width: iconSize, height: iconSize }} strokeWidth={1.9} aria-hidden />
      </span>

      {pinned && (
        <span
          aria-hidden
          className="pointer-events-none absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full border border-[#04060e]"
          style={{ backgroundColor: ACCENT.cyan }}
          title="Pinned"
        />
      )}

      {/* label sits below the body, exactly as an entity map reads */}
      <span
        className="pointer-events-none absolute left-1/2 top-full mt-1 max-w-[104px] -translate-x-1/2 truncate text-center font-mono text-[9px] leading-tight"
        style={{ color: lit ? '#e2e8f0' : '#94a3b8' }}
      >
        {model.label}
      </span>
    </div>
  );
}

/* ──────────────────────────────────────────────────────────── cluster box ─── */

/**
 * A compound box is DRAWN, not modelled.
 *
 * These were React Flow nodes at first, and their size is derived from where
 * their members settle — so every simulation tick resized a DOM element that
 * React Flow was observing, and the observer's response resized it again:
 * "ResizeObserver loop completed with undelivered notifications", and a canvas
 * that could pin a core. Rendering them through `ViewportPortal` puts them
 * inside the same pan/zoom transform with no measurement, no observer and no
 * hit-testing — which is all a background region ever needed.
 */
interface ClusterBox {
  id: string;
  label: string;
  color: string;
  x: number;
  y: number;
  width: number;
  height: number;
}

function ClusterLayer({ boxes }: { boxes: ClusterBox[] }) {
  return (
    <ViewportPortal>
      {boxes.map((box) => (
        <div
          key={box.id}
          className="pointer-events-none absolute rounded-2xl border"
          style={{
            transform: `translate(${box.x}px, ${box.y}px)`,
            width: box.width,
            height: box.height,
            borderColor: `${box.color}30`,
            backgroundColor: `${box.color}0a`,
            zIndex: 0,
          }}
        >
          <span
            className="absolute left-3 top-2 font-mono text-[9px] font-black uppercase tracking-[0.2em]"
            style={{ color: `${box.color}cc` }}
          >
            {box.label}
          </span>
        </div>
      ))}
    </ViewportPortal>
  );
}

/* ──────────────────────────────────────────────────────────── floating edge ── */

interface FlowEdgeData extends Record<string, unknown> {
  color: string;
  dashed: boolean;
  sourceRadius: number;
  targetRadius: number;
}

/**
 * Centre-to-centre edge, clipped at each body's radius.
 *
 * Both handles sit at the exact centre of a node, so `sourceX/Y` and
 * `targetX/Y` are the two centres; the path is then shortened by each radius so
 * the line meets the circle rather than crossing it, and bowed slightly so
 * reciprocal edges do not overlap into a single stroke.
 */
function FloatingEdgeView({ id, source, target, sourceX, sourceY, targetX, targetY, data }: EdgeProps) {
  const state = useEdgeFocusState(source, target);
  const payload = (data ?? {}) as FlowEdgeData;
  const dx = targetX - sourceX;
  const dy = targetY - sourceY;
  const distance = Math.hypot(dx, dy) || 1;
  const ux = dx / distance;
  const uy = dy / distance;
  const x1 = sourceX + ux * (payload.sourceRadius ?? 12);
  const y1 = sourceY + uy * (payload.sourceRadius ?? 12);
  const x2 = targetX - ux * ((payload.targetRadius ?? 12) + 1.5);
  const y2 = targetY - uy * ((payload.targetRadius ?? 12) + 1.5);
  /* Gentle perpendicular bow, proportional to length and capped. */
  const bow = Math.min(distance * 0.11, 26);
  const cx = (x1 + x2) / 2 - uy * bow;
  const cy = (y1 + y2) / 2 + ux * bow;

  const dim = state === 'dim';
  const lit = state === 'focus';

  return (
    <path
      id={id}
      d={`M ${x1},${y1} Q ${cx},${cy} ${x2},${y2}`}
      fill="none"
      stroke={payload.color ?? NONE_COLOR}
      strokeWidth={lit ? 1.8 : 1.15}
      strokeDasharray={payload.dashed ? '2.5 3.5' : undefined}
      strokeLinecap="round"
      /* Stroke width is a SCREEN measurement, not a graph one. Without this the
         browser scales the stroke with the viewport transform, so the moment a
         large graph is fitted to the panel every edge thins to a fraction of a
         pixel and the canvas reads as unconnected dots. */
      vectorEffect="non-scaling-stroke"
      style={{
        opacity: dim ? 0.06 : lit ? 0.95 : 0.5,
        transition: 'opacity 160ms ease, stroke-width 160ms ease',
      }}
    />
  );
}

const NODE_TYPES = { entity: EntityNodeView };
const EDGE_TYPES = { floating: FloatingEdgeView };

/* ─────────────────────────────────────────────────────────────── geometry ─── */

/**
 * The layout canvas grows with the population.
 *
 * A fixed extent is what turns a 100-node graph into a knot: the same box that
 * gives 30 bodies room to breathe forces 300 on top of each other, and the
 * labels — which are wider than the bodies — mash into an unreadable band. Area
 * therefore scales with node count so density stays roughly constant no matter
 * how large the assessment is.
 */
/** Anchor key for bodies that belong to no compound box under the current
 *  grouping — the scan root, chiefly. */
const UNGROUPED_ANCHOR = '__ungrouped__';

function extentFor(nodeCount: number): { width: number; height: number } {
  const side = Math.max(860, Math.min(3400, Math.round(Math.sqrt(Math.max(nodeCount, 1)) * 142)));
  return { width: Math.round(side * 1.4), height: side };
}

/** Deterministic radius: base by kind, grown by attached work and connectivity. */
function radiusFor(node: WorkflowNode, degree: number): number {
  const base =
    node.kind === 'scan' ? 24 : node.kind === 'phase' ? 19 : node.kind === 'layer' || node.kind === 'engine' ? 16 : 13;
  const mass = Math.sqrt(node.weight * 1.6 + degree * 0.9);
  return Math.round(Math.min(38, base + mass * 2.4));
}

/** Phyllotaxis seed — deterministic, so a re-mount reproduces the same opening. */
function seedPosition(index: number, extent: { width: number; height: number }): { x: number; y: number } {
  const angle = index * 2.399963229728653;
  const radius = 20 * Math.sqrt(index);
  return { x: extent.width / 2 + radius * Math.cos(angle), y: extent.height / 2 + radius * Math.sin(angle) };
}

interface SimBody extends SimulationNodeDatum {
  id: string;
  radius: number;
  groupId?: string;
  anchorX: number;
  anchorY: number;
}

type SimLink = SimulationLinkDatum<SimBody> & { kind: string };

/* ──────────────────────────────────────────────────────────── the canvas ──── */

interface CanvasProps {
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  clusters: Array<{ id: string; label: string; severity: FindingSeverity | null }>;
  grouping: WorkflowGrouping;
  colourMode: ColourMode;
  physics: { repulsion: number; linkLength: number; gravity: number };
  frozen: boolean;
  layoutKey: string;
  store: FocusStore;
  onSelect: (node: WorkflowNode | null) => void;
  onReady: (instance: ReactFlowInstance) => void;
  /** Bumped by the toolbar. Counters rather than window events, so two maps
   *  on one page never act on each other's clicks. */
  fitRequest: number;
  relayoutRequest: number;
  expanded: boolean;
  onFit: () => void;
  onToggleExpanded: () => void;
}

const MIN_ZOOM = 0.12;
const MAX_ZOOM = 2.6;

/**
 * Floating zoom bar.
 *
 * The canvas pans on scroll (a page-length dashboard cannot hijack the wheel
 * for zoom), which left pinch / ctrl+wheel as the only way to zoom — invisible
 * to most users. These are the explicit controls: +/−, the live zoom level
 * (click to return to 100%), Fit, and full screen.
 */
function ZoomControls({
  expanded,
  onFit,
  onToggleExpanded,
  onUserView,
}: {
  expanded: boolean;
  onFit: () => void;
  onToggleExpanded: () => void;
  onUserView: () => void;
}) {
  const { zoomIn, zoomOut, zoomTo } = useReactFlow();
  const { zoom } = useViewport();
  const reduceMotion = useReducedMotion();
  const duration = reduceMotion ? 0 : 220;
  const percent = Math.round(zoom * 100);
  const button =
    'grid h-8 w-full place-items-center text-slate-300 transition-colors hover:bg-white/[0.06] hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-400/60 disabled:cursor-not-allowed disabled:opacity-35 disabled:hover:bg-transparent';

  return (
    <FlowPanel position="bottom-left" className="qg-workflow-zoom">
      <div
        role="toolbar"
        aria-label="Map zoom and view"
        aria-orientation="vertical"
        className="flex w-9 flex-col overflow-hidden rounded-xl border border-white/[0.1] bg-[#050a15]/90 shadow-[0_14px_36px_rgba(0,0,0,0.38)] backdrop-blur-md"
      >
        <button
          type="button"
          aria-label="Zoom in"
          title="Zoom in (+)"
          disabled={zoom >= MAX_ZOOM - 0.005}
          onClick={() => {
            onUserView();
            void zoomIn({ duration });
          }}
          className={button}
        >
          <Plus aria-hidden className="h-4 w-4" />
        </button>
        <button
          type="button"
          aria-label={`Zoom level ${percent}%. Reset to 100%`}
          title="Reset to 100%"
          onClick={() => {
            onUserView();
            void zoomTo(1, { duration });
          }}
          className="h-7 w-full border-y border-white/[0.08] font-mono text-[9.5px] font-bold tabular-nums text-slate-400 transition-colors hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-400/60"
        >
          {percent}%
        </button>
        <button
          type="button"
          aria-label="Zoom out"
          title="Zoom out (−)"
          disabled={zoom <= MIN_ZOOM + 0.005}
          onClick={() => {
            onUserView();
            void zoomOut({ duration });
          }}
          className={button}
        >
          <Minus aria-hidden className="h-4 w-4" />
        </button>
        <span aria-hidden className="h-px bg-white/[0.08]" />
        <button
          type="button"
          aria-label="Fit the whole map"
          title={expanded ? 'Fit the whole map (0)' : 'Fit the whole map on a full-screen canvas'}
          onClick={onFit}
          className={button}
        >
          <Scan aria-hidden className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          aria-label={expanded ? 'Exit full screen' : 'Full screen'}
          aria-pressed={expanded}
          title={expanded ? 'Exit full screen (Esc)' : 'Full screen'}
          onClick={onToggleExpanded}
          className={button}
        >
          {expanded ? <Minimize2 aria-hidden className="h-3.5 w-3.5" /> : <Maximize2 aria-hidden className="h-3.5 w-3.5" />}
        </button>
      </div>
    </FlowPanel>
  );
}

function WorkflowCanvas({
  nodes: modelNodes,
  edges: modelEdges,
  clusters,
  grouping,
  colourMode,
  physics,
  frozen,
  layoutKey,
  store,
  onSelect,
  onReady,
  fitRequest,
  relayoutRequest,
  expanded,
  onFit,
  onToggleExpanded,
}: CanvasProps) {
  const reduceMotion = useReducedMotion();
  const flow = useReactFlow();
  const [flowNodes, setFlowNodes] = React.useState<Node[]>([]);
  const [clusterBoxes, setClusterBoxes] = React.useState<ClusterBox[]>([]);
  const [flowEdges, setFlowEdges] = React.useState<Edge[]>([]);
  const [pinned, setPinned] = React.useState<ReadonlySet<string>>(new Set());

  const simulationRef = React.useRef<Simulation<SimBody, SimLink> | null>(null);
  const bodiesRef = React.useRef<Map<string, SimBody>>(new Map());
  const frameRef = React.useRef<number | null>(null);
  const draggingRef = React.useRef(false);
  const pinnedRef = React.useRef<Set<string>>(new Set());
  const boxTickRef = React.useRef(0);

  /**
   * Fitting is tied to CONVERGENCE, not to a timer.
   *
   * A fit fired on a fixed delay frames whatever the simulation happened to
   * have reached at that instant — and since the bodies are still spreading, the
   * graph then grows straight back out of the viewport. The opening fit is
   * therefore instant (so nothing starts off-screen) and the real one waits for
   * the layout to settle.
   */
  const fittedRef = React.useRef(false);

  /** The lens/filter/physics identity the current simulation was built for.
   *  A rebuild that keeps it is a DATA refresh (a realtime update), which must
   *  settle in place and leave the operator's zoom alone — not re-warm the
   *  whole layout and snap the view back as a fresh lens does. */
  const builtLayoutRef = React.useRef<string | null>(null);

  const degrees = React.useMemo(() => degreeMap(modelEdges), [modelEdges]);
  const extent = React.useMemo(() => extentFor(modelNodes.length), [modelNodes.length]);

  /**
   * Cluster anchors, packed rather than gridded.
   *
   * Populations are wildly uneven — Analysis routinely holds 90% of the bodies
   * while Scoring holds one — so an even grid gives the big cluster a cell it
   * cannot fit in and its compound box swallows its neighbours'. Each cluster
   * is instead treated as a circle whose radius comes from its member count and
   * packed by a short, seeded force pass, which guarantees the regions do not
   * overlap and keeps the result deterministic.
   */
  const anchors = React.useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    if (grouping === 'none' || clusters.length === 0) return map;

    /* A region's radius is the area its members will actually occupy once the
       node-level collide force has packed them — summed footprints, converted
       back to a radius, plus slack for the repulsion that spreads them further.
       Sizing a region by member COUNT alone under-sizes the big clusters, and
       their compound box then grows past its neighbours and swallows them. */
    /* Bodies that belong to no compound box under this grouping — the scan root
       always, plus whole entity types under some lens/grouping pairs — are
       packed as their OWN region. Anchoring them to a fixed offset instead put
       them wherever that offset happened to land, which was usually inside
       somebody else's box, reading as membership of a group they are not in. */
    const footprint = new Map<string, number>();
    const population = new Map<string, number>();
    for (const node of modelNodes) {
      const groupId = node.groups[grouping] ?? UNGROUPED_ANCHOR;
      const bodyRadius = radiusFor(node, degrees.get(node.id) ?? 0) + 21;
      footprint.set(groupId, (footprint.get(groupId) ?? 0) + Math.PI * bodyRadius * bodyRadius);
      population.set(groupId, (population.get(groupId) ?? 0) + 1);
    }

    interface Region extends SimulationNodeDatum {
      id: string;
      radius: number;
    }
    const regionIds = [
      ...clusters.map((cluster) => cluster.id),
      ...(population.has(UNGROUPED_ANCHOR) ? [UNGROUPED_ANCHOR] : []),
    ];
    const regions: Region[] = regionIds.map((regionId, index) => {
      const seed = seedPosition(index, extent);
      return {
        id: regionId,
        /* The floor matters as much as the footprint: a two-body cluster packs
           into almost no area, but repulsion still throws its members a long
           way apart, so a region sized purely by footprint is overrun by its
           own contents and its box swallows the neighbour. */
        radius: Math.max(
          110,
          Math.sqrt(population.get(regionId) ?? 1) * 46,
          Math.sqrt((footprint.get(regionId) ?? 0) / Math.PI) * 1.45,
        ),
        x: seed.x,
        y: seed.y,
      };
    });

    forceSimulation(regions)
      .force('collide', forceCollide<Region>((region) => region.radius + 96).strength(1))
      .force('x', forceX<Region>(extent.width / 2).strength(0.05))
      .force('y', forceY<Region>(extent.height / 2).strength(0.07))
      .stop()
      .tick(400);

    for (const region of regions) map.set(region.id, { x: region.x ?? 0, y: region.y ?? 0 });
    return map;
  }, [clusters, grouping, modelNodes, extent, degrees]);

  const clusterColour = React.useCallback(
    (severity: FindingSeverity | null) => (severity ? SEVERITY_COLOR[severity] : NONE_COLOR),
    [],
  );

  /* ── write simulation positions into React Flow ───────────────────────── */

  /** Bounding box per cluster, derived from where the members actually settled
   *  so a box always contains its members rather than approximating them. */
  const computeBoxes = React.useCallback((): ClusterBox[] => {
    if (grouping === 'none') return [];
    const bodies = bodiesRef.current;
    const boxes: ClusterBox[] = [];
    for (const cluster of clusters) {
      let minX = Infinity;
      let minY = Infinity;
      let maxX = -Infinity;
      let maxY = -Infinity;
      let members = 0;
      for (const model of modelNodes) {
        if (model.groups[grouping] !== cluster.id) continue;
        const body = bodies.get(model.id);
        if (!body || body.x === undefined || body.y === undefined) continue;
        members += 1;
        minX = Math.min(minX, body.x - body.radius);
        minY = Math.min(minY, body.y - body.radius);
        maxX = Math.max(maxX, body.x + body.radius);
        maxY = Math.max(maxY, body.y + body.radius);
      }
      if (members === 0 || !Number.isFinite(minX)) continue;
      const padX = 26;
      const padTop = 28;
      const padBottom = 32; /* room for the labels that hang below each body */
      boxes.push({
        id: cluster.id,
        label: cluster.label,
        color: clusterColour(cluster.severity),
        x: minX - padX,
        y: minY - padTop,
        width: maxX - minX + padX * 2,
        height: maxY - minY + padTop + padBottom,
      });
    }
    return boxes;
  }, [clusters, grouping, modelNodes, clusterColour]);

  const paint = React.useCallback(() => {
    const bodies = bodiesRef.current;

    const entityNodes: Node[] = modelNodes.map((model) => {
      const body = bodies.get(model.id);
      const radius = body?.radius ?? radiusFor(model, degrees.get(model.id) ?? 0);
      const x = body?.x ?? extent.width / 2;
      const y = body?.y ?? extent.height / 2;
      return {
        id: model.id,
        type: 'entity',
        position: { x: x - radius, y: y - radius },
        /* Dimensions are DECLARED, not measured. React Flow renders an
           unmeasured node with `visibility: hidden` until its ResizeObserver
           fires, so a canvas that hands over known sizes skips the measurement
           pass entirely: no first-paint flicker, an immediately correct
           minimap, and one less observer per body on a 400-node graph. */
        width: radius * 2,
        height: radius * 2,
        /* `measured` is the field React Flow actually reads. `width`/`height`
           alone leave `measured` undefined, which keeps `nodesInitialized`
           false forever — so `fitView` has no bounds to fit and silently does
           nothing, and the graph opens off-screen at scale 1. */
        measured: { width: radius * 2, height: radius * 2 },
        /* Handles are DECLARED too, and this one is load-bearing rather than an
           optimisation. React Flow re-derives `handleBounds` from the user node
           on every update; a node object with no `measured` field returns
           `undefined`, which WIPES the bounds the ResizeObserver measured. This
           canvas hands over a fresh node object every animation frame, so the
           bounds were cleared each tick and never re-measured (the element's
           size never changes, so the observer never fires again) — leaving
           `getEdgePosition` with nothing to work from and an empty edge layer.
           Declaring the two centre handles removes the DOM round-trip
           altogether: the coordinates are exact, deterministic, and immune to
           how often the node array is replaced. */
        handles: [
          { id: null, type: 'target', position: Position.Top, x: radius, y: radius, width: 1, height: 1 },
          { id: null, type: 'source', position: Position.Bottom, x: radius, y: radius, width: 1, height: 1 },
        ],
        data: {
          model,
          radius,
          color: colourOf(model, colourMode),
          pinned: pinnedRef.current.has(model.id),
        } satisfies EntityNodeData,
        zIndex: 2,
        draggable: true,
        selectable: true,
        connectable: false,
        deletable: false,
      };
    });

    setFlowNodes(entityNodes);

    /* Boxes are recomputed on a slower cadence than the bodies. They only frame
       a region, so a few frames of lag is invisible — while recomputing six
       absolutely-positioned overlays 60 times a second is not free. */
    boxTickRef.current += 1;
    if (boxTickRef.current % 5 !== 0) return;
    setClusterBoxes(computeBoxes());
  }, [modelNodes, colourMode, degrees, extent, computeBoxes]);

  /* The loop reads these through refs so a recolour mid-settle paints with the
     CURRENT colours instead of the ones captured when the loop started. */
  const paintRef = React.useRef(paint);
  paintRef.current = paint;
  const computeBoxesRef = React.useRef(computeBoxes);
  computeBoxesRef.current = computeBoxes;

  /**
   * The one animation loop: tick, paint, stop once settled, then fit if no
   * fit has happened yet. The simulation is ticked ONLY here — d3's own timer
   * is never started (no `.restart()`), because running both doubled the tick
   * rate and kept a hidden timer alive after the canvas stopped.
   *
   * Physics is paced by WALL-CLOCK time, not by frames. One tick per frame
   * tied settling to paint cost: a frame repaints every body and edge through
   * React Flow, and on a busy dashboard frames ran at ~4/s — the ~180 ticks to
   * converge took 45 s+, which read as a map that never stops moving and a
   * Re-layout that does nothing. A tick is cheap; the paint is not. So a frame
   * runs the ticks its elapsed time is owed (one at 60 Hz, so motion looks the
   * same) and paints once.
   */
  const startLoop = React.useCallback(() => {
    if (frameRef.current !== null) return;
    let last = performance.now();
    const step = (now: number) => {
      const active = simulationRef.current;
      if (!active) {
        frameRef.current = null;
        return;
      }
      const owed = Math.min(12, Math.max(1, Math.round((now - last) / (1000 / 60))));
      last = now;
      for (let tick = 0; tick < owed && (active.alpha() > 0.006 || draggingRef.current); tick += 1) active.tick();
      paintRef.current();
      if (active.alpha() > 0.006 || draggingRef.current) {
        frameRef.current = requestAnimationFrame(step);
        return;
      }
      frameRef.current = null;
      setClusterBoxes(computeBoxesRef.current());
      if (!fittedRef.current) {
        fittedRef.current = true;
        void flow.fitView({ padding: 0.18, duration: 420 });
      }
    };
    frameRef.current = requestAnimationFrame(step);
  }, [flow]);

  /* ── (re)build the simulation whenever the projection changes ─────────── */

  React.useEffect(() => {
    const layoutIdentity = `${layoutKey}|${physics.repulsion}|${physics.linkLength}|${physics.gravity}|${frozen}`;
    const refresh = builtLayoutRef.current === layoutIdentity && bodiesRef.current.size > 0;
    builtLayoutRef.current = layoutIdentity;
    if (!refresh) fittedRef.current = false;
    const previous = bodiesRef.current;
    const bodies = new Map<string, SimBody>();

    modelNodes.forEach((model, index) => {
      const carried = previous.get(model.id);
      const anchor = anchors.get(model.groups[grouping] ?? UNGROUPED_ANCHOR)
        ?? anchors.get(UNGROUPED_ANCHOR)
        ?? { x: extent.width / 2, y: extent.height / 2 };
      const seed = seedPosition(index, extent);
      bodies.set(model.id, {
        id: model.id,
        radius: radiusFor(model, degrees.get(model.id) ?? 0),
        groupId: model.groups[grouping],
        anchorX: anchor.x,
        anchorY: anchor.y,
        /* Carry a body's position across a filter change so the canvas
           re-settles rather than teleporting everything. */
        x: carried?.x ?? seed.x,
        y: carried?.y ?? seed.y,
        vx: 0,
        vy: 0,
        fx: pinnedRef.current.has(model.id) ? carried?.fx : undefined,
        fy: pinnedRef.current.has(model.id) ? carried?.fy : undefined,
      });
    });
    bodiesRef.current = bodies;

    const links: SimLink[] = modelEdges
      .filter((edge) => bodies.has(edge.source) && bodies.has(edge.target))
      .map((edge) => ({ source: edge.source, target: edge.target, kind: edge.kind }));

    simulationRef.current?.stop();
    const simulation = forceSimulation<SimBody, SimLink>([...bodies.values()])
      .alphaDecay(0.028)
      .velocityDecay(0.36)
      .stop();
    simulationRef.current = simulation as Simulation<SimBody, SimLink>;

    simulation.force(
      'link',
      forceLink<SimBody, SimLink>(links)
        .id((body) => body.id)
        /* Structural edges are held shorter than associative ones, so the
           process spine reads as a spine rather than a cloud. */
        .distance((link) =>
          (link.kind === 'spawns' || link.kind === 'orchestrates' ? 0.72 : link.kind === 'requires' ? 0.9 : 1.15) *
          physics.linkLength,
        )
        .strength((link) => (link.kind === 'spawns' || link.kind === 'orchestrates' ? 0.5 : 0.2)),
    );
    simulation.force('charge', forceManyBody<SimBody>().strength(-physics.repulsion).distanceMax(720));
    /* +19 rather than +2: the visual footprint of a body is the circle PLUS the
       label hanging under it, and packing to the circle alone is what makes the
       labels overlap into an unreadable band. */
    simulation.force(
      'collide',
      forceCollide<SimBody>((body) => body.radius + 19).strength(0.95),
    );
    simulation.force('x', forceX<SimBody>((body) => body.anchorX).strength(grouping === 'none' ? 0.035 : physics.gravity));
    simulation.force('y', forceY<SimBody>((body) => body.anchorY).strength(grouping === 'none' ? 0.05 : physics.gravity));

    if (reduceMotion || frozen) {
      /* No animation: converge synchronously and paint the settled result. */
      simulation.tick(320);
      paint();
      setClusterBoxes(computeBoxes());
      if (!refresh) {
        fittedRef.current = true;
        window.setTimeout(() => void flow.fitView({ padding: 0.18, duration: 0 }), 0);
      }
      return () => {
        simulation.stop();
      };
    }

    if (refresh) {
      /* Bodies carried their positions; a gentle reheat lets new entities
         find their place without re-spreading everything that is settled. */
      simulation.alpha(0.3);
    } else {
      /* Warm start so the opening frame is already legible rather than a knot. */
      simulation.tick(60);
      simulation.alpha(0.9);
      paint();
      window.setTimeout(() => void flow.fitView({ padding: 0.2, duration: 0 }), 0);
    }
    startLoop();

    return () => {
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
      frameRef.current = null;
      simulation.stop();
    };
  }, [modelNodes, modelEdges, anchors, grouping, degrees, physics, frozen, reduceMotion, paint, flow, layoutKey, extent, computeBoxes, startLoop]);

  /* Repaint (without re-simulating) when only the colouring changed. */
  React.useEffect(() => {
    paint();
  }, [colourMode, pinned, paint]);

  /* ── edges ────────────────────────────────────────────────────────────── */

  React.useEffect(() => {
    const bodies = bodiesRef.current;
    setFlowEdges(
      modelEdges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: 'floating',
        data: {
          color: edge.severity ? SEVERITY_COLOR[edge.severity] : '#5a7093',
          dashed: edge.detection !== 'observed',
          sourceRadius: bodies.get(edge.source)?.radius ?? 12,
          targetRadius: bodies.get(edge.target)?.radius ?? 12,
        } satisfies FlowEdgeData,
        selectable: false,
        focusable: false,
        deletable: false,
      })),
    );
    store.setEdges(modelEdges);
  }, [modelEdges, store]);

  /* ── interaction ──────────────────────────────────────────────────────── */

  /** Keep the layout live while a body is dragged; `handleDragStop` drops the
   *  target back to 0 so it settles. */
  const reheat = React.useCallback(() => {
    const simulation = simulationRef.current;
    if (!simulation || reduceMotion) return;
    simulation.alphaTarget(0.28);
    startLoop();
  }, [reduceMotion, startLoop]);

  const handleDragStart = React.useCallback(() => {
    draggingRef.current = true;
    /* Arranging the map is taking control of the view: no automatic fit may
       reframe it afterwards. */
    fittedRef.current = true;
    reheat();
  }, [reheat]);

  const handleDrag = React.useCallback((_: unknown, node: Node) => {
    const body = bodiesRef.current.get(node.id);
    if (!body) return;
    body.fx = node.position.x + body.radius;
    body.fy = node.position.y + body.radius;
  }, []);

  const handleDragStop = React.useCallback(
    (_: unknown, node: Node) => {
      draggingRef.current = false;
      const body = bodiesRef.current.get(node.id);
      if (body) {
        /* A dragged body stays where it was put — an operator arranging the map
           does not want it snapping back. "Re-layout" releases every pin. */
        body.fx = node.position.x + body.radius;
        body.fy = node.position.y + body.radius;
        pinnedRef.current.add(node.id);
        setPinned(new Set(pinnedRef.current));
      }
      simulationRef.current?.alphaTarget(0);
    },
    [],
  );

  /**
   * Re-layout: a genuinely FRESH layout, then a fit once it settles.
   *
   * The previous handler reheated through `reheat()`, whose drag-time
   * `alphaTarget(0.28)` was never released — alpha could not decay below 0.28,
   * the 0.006 convergence test never passed, and the map jiggled forever without
   * the settle-and-fit ever running. It also restarted from the current
   * (tangled) positions, so the result was the same tangle shaken. Bodies now
   * return to their deterministic seeds, every pin is released, and the
   * simulation decays to rest exactly as on first open.
   */
  const handledRelayoutRef = React.useRef(relayoutRequest);
  React.useEffect(() => {
    if (relayoutRequest === handledRelayoutRef.current) return;
    handledRelayoutRef.current = relayoutRequest;
    const simulation = simulationRef.current;
    if (!simulation) return;

    pinnedRef.current.clear();
    setPinned(new Set());
    let index = 0;
    for (const body of bodiesRef.current.values()) {
      const seed = seedPosition(index, extent);
      index += 1;
      body.x = seed.x;
      body.y = seed.y;
      body.vx = 0;
      body.vy = 0;
      body.fx = undefined;
      body.fy = undefined;
    }
    simulation.alphaTarget(0);
    fittedRef.current = false;

    if (reduceMotion || frozen) {
      simulation.alpha(1);
      simulation.tick(320);
      paint();
      setClusterBoxes(computeBoxes());
      fittedRef.current = true;
      void flow.fitView({ padding: 0.18, duration: reduceMotion ? 0 : 420 });
      return;
    }
    simulation.alpha(1);
    simulation.tick(60);
    simulation.alpha(0.9);
    paint();
    void flow.fitView({ padding: 0.2, duration: 260 });
    startLoop();
  }, [relayoutRequest, extent, reduceMotion, frozen, paint, computeBoxes, flow, startLoop]);

  /**
   * Fit, on request. The request usually arrives together with the switch to
   * full screen, so the pane is still its old size on this frame: fit now,
   * and again whenever React Flow reports a new pane size in the next moment.
   */
  const fitUntilRef = React.useRef(0);
  const fitNow = React.useCallback(() => {
    void flow.fitView({ padding: 0.12, duration: reduceMotion ? 0 : 450 });
  }, [flow, reduceMotion]);
  const handledFitRef = React.useRef(fitRequest);
  React.useEffect(() => {
    if (fitRequest === handledFitRef.current) return;
    handledFitRef.current = fitRequest;
    fitUntilRef.current = performance.now() + 1600;
    const frame = requestAnimationFrame(fitNow);
    return () => cancelAnimationFrame(frame);
  }, [fitRequest, fitNow]);
  const paneWidth = useStore((state) => state.width);
  const paneHeight = useStore((state) => state.height);
  React.useEffect(() => {
    if (performance.now() < fitUntilRef.current) fitNow();
  }, [paneWidth, paneHeight, fitNow]);

  const markUserView = React.useCallback(() => {
    fittedRef.current = true;
  }, []);

  React.useEffect(() => {
    onReady(flow as ReactFlowInstance);
  }, [flow, onReady]);

  const nodeById = React.useMemo(() => new Map(modelNodes.map((node) => [node.id, node])), [modelNodes]);

  /**
   * How far the canvas may be panned.
   *
   * Without this React Flow pans without limit, so one drag downward carries
   * the whole graph out of the frame and leaves an empty canvas with no way
   * back except Fit — which reads as the map breaking rather than as the map
   * having been moved. The bound is the layout's own extent plus a margin
   * comfortably larger than any viewport, so there is always somewhere to pan
   * to and never anywhere to lose the graph in.
   *
   * Derived from the SEEDED extent, not from live body positions: the force
   * simulation moves every tick, and a bound that moved with it would make the
   * drag feel like it was fighting back.
   */
  const translateExtent = React.useMemo<[[number, number], [number, number]]>(() => {
    const extent = extentFor(modelNodes.length);
    const marginX = Math.max(720, extent.width * 0.55);
    const marginY = Math.max(720, extent.height * 0.55);
    return [
      [-marginX, -marginY],
      [extent.width + marginX, extent.height + marginY],
    ];
  }, [modelNodes.length]);

  return (
    <ReactFlow
      nodes={flowNodes}
      edges={flowEdges}
      nodeTypes={NODE_TYPES}
      edgeTypes={EDGE_TYPES}
      onNodeDragStart={handleDragStart}
      onNodeDrag={handleDrag}
      onNodeDragStop={handleDragStop}
      onNodeMouseEnter={(_, node) => store.hover(node.id)}
      onNodeMouseLeave={() => store.hover(null)}
      onNodeClick={(_, node) => {
        const model = nodeById.get(node.id);
        store.select(model ? node.id : null);
        onSelect(model ?? null);
      }}
      onPaneClick={() => {
        store.select(null);
        onSelect(null);
      }}
      /* `event` is null for programmatic moves (fitView, the zoom buttons) and
         set for a real pan / pinch / ctrl+wheel — the operator taking control. */
      onMoveStart={(event) => {
        if (event) markUserView();
      }}
      minZoom={MIN_ZOOM}
      maxZoom={MAX_ZOOM}
      translateExtent={translateExtent}
      proOptions={{ hideAttribution: true }}
      nodesConnectable={false}
      elementsSelectable
      panOnScroll
      selectionOnDrag={false}
      zoomOnDoubleClick={false}
      className="qg-workflow-flow"
    >
      <ClusterLayer boxes={clusterBoxes} />
      <ZoomControls expanded={expanded} onFit={onFit} onToggleExpanded={onToggleExpanded} onUserView={markUserView} />
      <Background variant={BackgroundVariant.Dots} gap={26} size={1} color="rgba(148,163,184,0.16)" />
      <MiniMap
        pannable
        zoomable
        position="bottom-right"
        nodeStrokeWidth={0}
        maskColor="rgba(4,6,14,0.72)"
        nodeColor={(node) => (node.data as EntityNodeData | undefined)?.color ?? NONE_COLOR}
        style={{
          backgroundColor: 'rgba(5,10,21,0.92)',
          border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 10,
          height: 96,
          width: 150,
        }}
      />
    </ReactFlow>
  );
}

/* ──────────────────────────────────────────────────────────────── sidebar ─── */

function SidebarHeading({ icon: Icon, children, action }: { icon: LucideIcon; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="mb-2.5 flex items-center justify-between gap-2">
      <span className="flex items-center gap-1.5 font-mono text-[9px] font-bold uppercase tracking-[0.2em] text-slate-500">
        <Icon aria-hidden className="h-3 w-3" />
        {children}
      </span>
      {action}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────── focus panel ─ */

/**
 * Scope the whole graph to one or more entities.
 *
 * An estate graph is a hub-and-spoke, and two assets with fifty findings each
 * produce a picture in which NEITHER asset's story can be read — the request
 * this panel answers. Selecting an asset keeps that asset and everything
 * attached to it (see `focusScope`) and drops the rest.
 *
 * It is a VIEW, not a recount. The reconciliation footer keeps describing the
 * whole estate and states that a focus is active, so a focused graph can never
 * be mistaken for the tenant's full exposure.
 */
function FocusPanel({
  candidates,
  focusIds,
  onToggle,
  onClear,
  kindLabel,
}: {
  candidates: WorkflowNode[];
  focusIds: ReadonlySet<string>;
  onToggle: (id: string) => void;
  onClear: () => void;
  /** Plural label for the focus kind, e.g. "assets". */
  kindLabel: string;
}) {
  /* "assets" -> "asset". The kind labels are all regular plurals, and this
     keeps the one-entity sentence readable without a second prop to keep in
     step with the first. */
  const singular = kindLabel.endsWith('s') ? kindLabel.slice(0, -1) : kindLabel;
  const [needle, setNeedle] = React.useState('');
  const filtered = React.useMemo(() => {
    const text = needle.trim().toLowerCase();
    if (!text) return candidates;
    return candidates.filter(
      (node) => `${node.label} ${node.sublabel ?? ''}`.toLowerCase().includes(text),
    );
  }, [candidates, needle]);

  const active = focusIds.size > 0;

  return (
    <div className="px-4 py-3.5">
      <SidebarHeading
        icon={Crosshair}
        action={
          active ? (
            <button
              type="button"
              onClick={onClear}
              className="font-mono text-[9px] font-bold uppercase tracking-[0.14em] text-cyan-300 transition-colors hover:text-cyan-200"
            >
              Show all
            </button>
          ) : undefined
        }
      >
        Focus · {kindLabel}
      </SidebarHeading>

      {/* Only worth a search box once the list is long enough to scroll. */}
      {candidates.length > 6 && (
        <div className="relative mb-2">
          <Search aria-hidden className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-slate-600" />
          <input
            value={needle}
            onChange={(event) => setNeedle(event.target.value)}
            placeholder={`Filter ${kindLabel}…`}
            aria-label={`Filter ${kindLabel}`}
            className="w-full rounded-lg border border-white/[0.08] bg-white/[0.03] py-1.5 pl-7 pr-2 text-[11px] text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-400/40"
          />
        </div>
      )}

      <div className="max-h-56 space-y-1 overflow-y-auto pr-0.5 custom-scrollbar">
        {filtered.length === 0 ? (
          <p className="px-1 py-2 text-[11px] text-slate-500">No {kindLabel} match that name.</p>
        ) : (
          filtered.map((node) => {
            const selected = focusIds.has(node.id);
            /* Severity `null` is slate, never a pass colour (§43): an asset
               nobody measured must not read green in the picker either. */
            const tone = node.severity ? SEVERITY_COLOR[node.severity] : NONE_COLOR;
            return (
              <button
                key={node.id}
                type="button"
                onClick={() => onToggle(node.id)}
                aria-pressed={selected}
                title={node.sublabel ?? node.label}
                className={cn(
                  'flex w-full items-start gap-2 rounded-lg border px-2 py-1.5 text-left transition-colors',
                  selected
                    ? 'border-cyan-400/45 bg-cyan-400/[0.09]'
                    : 'border-white/[0.06] bg-white/[0.02] hover:border-white/[0.14]',
                )}
              >
                <span
                  aria-hidden
                  className="mt-[5px] h-2 w-2 shrink-0 rounded-full"
                  style={{ backgroundColor: tone, boxShadow: `0 0 6px ${tone}66` }}
                />
                <span className="min-w-0 flex-1">
                  <span className={cn('block truncate text-[11.5px] font-bold', selected ? 'text-cyan-100' : 'text-slate-300')}>
                    {node.label}
                  </span>
                  <span className="mt-0.5 block truncate font-mono text-[9.5px] text-slate-500">
                    {node.findingIds.length} finding{node.findingIds.length === 1 ? '' : 's'}
                    {node.sublabel ? ` · ${node.sublabel}` : ''}
                  </span>
                </span>
                {selected && <Check aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-cyan-300" />}
              </button>
            );
          })
        )}
      </div>

      <p className="mt-2 font-mono text-[9.5px] leading-relaxed text-slate-500">
        {active
          ? `Showing ${focusIds.size} of ${candidates.length} ${kindLabel} and everything attached to ${focusIds.size === 1 ? 'it' : 'them'}.`
          : candidates.length === 1
            /* One entity is not a choice. Say so rather than offering a control
               that cannot change anything — and rather than hiding the panel,
               which just makes an operator hunt for a filter that is not there. */
            ? `One ${singular} in this estate — nothing to filter between yet. The whole graph is already its own.`
            : `Showing all ${candidates.length} ${kindLabel}. Select one to isolate its exposure.`}
      </p>
    </div>
  );
}

function EntityChip({
  label,
  count,
  color,
  icon: Icon,
  active,
  onClick,
}: {
  label: string;
  count: number;
  color: string;
  icon: LucideIcon;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border py-1 pl-1.5 pr-2 text-[10.5px] font-semibold transition-colors',
        active ? 'border-current' : 'border-white/[0.07] text-slate-600 hover:text-slate-400',
      )}
      style={active ? { color, backgroundColor: `${color}12` } : undefined}
      title={`${label} — ${count} node${count === 1 ? '' : 's'}`}
    >
      <span
        className="grid h-4 w-4 shrink-0 place-items-center rounded-full"
        style={{ backgroundColor: active ? `${color}26` : 'rgba(148,163,184,0.1)' }}
      >
        <Icon aria-hidden className="h-2.5 w-2.5" />
      </span>
      <span className="truncate">{label}</span>
      <span className="font-mono text-[9.5px] text-slate-500">{count}</span>
    </button>
  );
}

function Slider({
  label,
  value,
  min,
  max,
  step,
  display,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  display: string;
  onChange: (next: number) => void;
}) {
  return (
    <label className="block">
      <span className="mb-1 flex items-center justify-between text-[11px] text-slate-400">
        {label}
        <span className="font-mono text-[10px] text-slate-500">{display}</span>
      </span>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(event) => onChange(Number(event.target.value))}
        className="qg-workflow-range h-1 w-full cursor-pointer appearance-none rounded-full bg-white/[0.09]"
        aria-label={label}
      />
    </label>
  );
}

/* ────────────────────────────────────────────────────────────── inspector ─── */

function Inspector({
  node,
  findingCorpus,
  nodes,
  edges,
  onClose,
  onOpenFinding,
  onSelectNode,
}: {
  node: WorkflowNode | null;
  /** Findings the inspector can expand. Empty for projections that have none. */
  findingCorpus: ExposureFinding[];
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  onClose: () => void;
  onOpenFinding: (finding: ExposureFinding) => void;
  onSelectNode: (node: WorkflowNode) => void;
}) {
  const findings = React.useMemo(() => {
    if (!node) return [];
    const byId = new Map(findingCorpus.map((finding) => [finding.id, finding]));
    return node.findingIds.map((id) => byId.get(id)).filter((finding): finding is ExposureFinding => Boolean(finding));
  }, [node, findingCorpus]);

  /* The typed relationships this entity participates in. This is the question a
     relationship map exists to answer — "what is this connected to, and how" —
     and answering it in words as well as in strokes means it survives a
     screenshot, a screen reader and a colour-blind reader. */
  const relationships = React.useMemo(() => {
    if (!node) return [];
    const byId = new Map(nodes.map((entry) => [entry.id, entry]));
    return edges
      .filter((edge) => edge.source === node.id || edge.target === node.id)
      .map((edge) => {
        const outgoing = edge.source === node.id;
        const other = byId.get(outgoing ? edge.target : edge.source);
        if (!other) return null;
        /* Fifty findings can share one title — "RSA for key management" is the
           same defect in fifty files — so the row carries where it was seen.
           Without it the list reads as fifty duplicates of one relationship. */
        const where = other.facts.find((fact) => fact.label === 'Evidence' || fact.label === 'Path')?.value;
        return { id: edge.id, outgoing, label: EDGE_KIND_LABEL[edge.kind], where, other };
      })
      .filter(
        (
          entry,
        ): entry is { id: string; outgoing: boolean; label: string; where: string | undefined; other: WorkflowNode } =>
          Boolean(entry),
      );
  }, [node, nodes, edges]);

  return (
    <AnimatePresence>
      {node && (
        <motion.aside
          key={node.id}
          initial={{ opacity: 0, x: 22 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: 22 }}
          transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
          className="absolute inset-y-3 right-3 z-20 flex w-[19rem] max-w-[calc(100%-1.5rem)] flex-col overflow-hidden rounded-xl border border-white/[0.09] bg-[#060b16]/95 shadow-[0_30px_80px_-40px_rgba(0,0,0,0.95)] backdrop-blur-xl"
          aria-label={`${NODE_KIND_SINGULAR[node.kind]} inspector`}
        >
          <div className="flex items-start gap-2.5 border-b border-white/[0.07] px-3.5 py-3">
            <span
              className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg"
              style={{
                backgroundColor: `${KIND_COLOR[node.kind]}18`,
                color: KIND_COLOR[node.kind],
              }}
            >
              {React.createElement(KIND_ICON[node.kind], { className: 'h-3.5 w-3.5', 'aria-hidden': true })}
            </span>
            <div className="min-w-0 flex-1">
              <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-slate-500">
                {NODE_KIND_SINGULAR[node.kind]}
              </p>
              <p className="mt-0.5 break-words text-[13px] font-bold leading-snug text-white">{node.label}</p>
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close inspector"
              className="rounded-md p-1 text-slate-500 transition-colors hover:bg-white/[0.06] hover:text-slate-200"
            >
              <X aria-hidden className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="min-h-0 flex-1 space-y-3 overflow-y-auto px-3.5 py-3">
            <div className="flex flex-wrap gap-1.5">
              <span
                className="rounded px-1.5 py-0.5 font-mono text-[9px] font-black uppercase tracking-[0.12em]"
                style={{
                  backgroundColor: `${node.severity ? SEVERITY_COLOR[node.severity] : NONE_COLOR}1f`,
                  color: node.severity ? SEVERITY_COLOR[node.severity] : NONE_COLOR,
                }}
              >
                {node.severity ?? 'no finding'}
              </span>
              <span
                className="rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-[0.12em]"
                style={{
                  borderColor: `${DETECTION_COLOR[node.detection]}44`,
                  color: DETECTION_COLOR[node.detection],
                }}
              >
                {DETECTION_LABEL[node.detection] ?? node.detection}
              </span>
              {node.quantumStatus && node.quantumStatus !== 'not-applicable' && (
                <span
                  className="rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-[0.12em]"
                  style={{
                    backgroundColor: `${QUANTUM_COLOR[node.quantumStatus]}18`,
                    color: QUANTUM_COLOR[node.quantumStatus],
                  }}
                >
                  {QUANTUM_LABEL[node.quantumStatus]}
                </span>
              )}
            </div>

            {node.sublabel && <p className="text-[11.5px] leading-relaxed text-slate-400">{node.sublabel}</p>}

            <dl className="space-y-1.5 rounded-lg border border-white/[0.06] bg-white/[0.015] px-3 py-2.5">
              {node.facts.map((fact) => (
                <div key={fact.label} className="grid grid-cols-[7rem_minmax(0,1fr)] gap-2">
                  <dt className="font-mono text-[9.5px] uppercase tracking-wider text-slate-600">{fact.label}</dt>
                  <dd className="break-words text-[11px] text-slate-300">{fact.value}</dd>
                </div>
              ))}
            </dl>

            {relationships.length > 0 && (
              <div>
                <p className="mb-1.5 font-mono text-[9px] uppercase tracking-[0.18em] text-slate-500">
                  Relationships ({relationships.length})
                </p>
                <ul className="space-y-1">
                  {relationships.slice(0, 18).map((entry) => (
                    <li key={entry.id}>
                      <button
                        type="button"
                        onClick={() => onSelectNode(entry.other)}
                        className="flex w-full items-center gap-2 rounded-lg border border-white/[0.06] px-2.5 py-1.5 text-left transition-colors hover:border-cyan-400/25 hover:bg-white/[0.03]"
                      >
                        <span
                          aria-hidden
                          className="shrink-0 font-mono text-[10px]"
                          style={{ color: KIND_COLOR[entry.other.kind] }}
                        >
                          {entry.outgoing ? '→' : '←'}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-[11px] text-slate-300">{entry.other.label}</span>
                          <span className="block truncate font-mono text-[9.5px] text-slate-600">
                            {entry.where
                              ? entry.where
                              : entry.outgoing
                                ? entry.label
                                : `${NODE_KIND_SINGULAR[entry.other.kind].toLowerCase()} ${entry.label}`}
                          </span>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
                {relationships.length > 18 && (
                  <p className="mt-1.5 font-mono text-[10px] text-slate-500">
                    Showing 18 of {relationships.length}. Hover the node on the canvas to see the rest highlighted.
                  </p>
                )}
              </div>
            )}

            {findings.length > 0 && (
              <div>
                <p className="mb-1.5 font-mono text-[9px] uppercase tracking-[0.18em] text-slate-500">
                  Attached findings ({findings.length})
                </p>
                <ul className="space-y-1">
                  {findings.slice(0, 24).map((finding) => (
                    <li key={finding.id}>
                      <button
                        type="button"
                        onClick={() => onOpenFinding(finding)}
                        className="flex w-full items-center gap-2 rounded-lg border border-white/[0.06] px-2.5 py-1.5 text-left transition-colors hover:border-cyan-400/25 hover:bg-white/[0.03]"
                      >
                        <span
                          aria-hidden
                          className="h-1.5 w-1.5 shrink-0 rounded-full"
                          style={{ backgroundColor: SEVERITY_COLOR[finding.severity] }}
                        />
                        <span className="min-w-0 flex-1 truncate text-[11px] text-slate-300">{finding.title}</span>
                        <ChevronRight aria-hidden className="h-3 w-3 shrink-0 text-slate-600" />
                      </button>
                    </li>
                  ))}
                </ul>
                {findings.length > 24 && (
                  <p className="mt-1.5 font-mono text-[10px] text-slate-500">
                    Showing 24 of {findings.length}. Open the Findings table for the full list.
                  </p>
                )}
              </div>
            )}
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  );
}

/* ─────────────────────────────────────────────────────────────── the panel ── */

export interface ExposureWorkflowGraphProps {
  /**
   * Assessment-backed source (the Local and Dev scanner panels): the graph is
   * projected here, from one run.
   */
  assessment?: ExposureAssessment;
  /** Engine descriptors supply the dependency edges. Defaults to the task mode. */
  mode?: 'local' | 'dev' | 'web';
  /**
   * PRE-BUILT source (the estate view on /dashboard).
   *
   * A tenant estate has no single run, no phase tree and no engine registry, so
   * it cannot be expressed as an `ExposureAssessment` without inventing
   * processes that never executed. It is projected by its own builder instead
   * and handed here already built — the renderer is identical either way, which
   * is the point: one interaction model, two honest projections.
   */
  graph?: WorkflowGraph;
  /** Findings the inspector can expand. Defaults to `assessment.findings`. */
  findings?: ExposureFinding[];
  /** Correlated exposures the finding sheet cross-references. */
  exposures?: CorrelatedExposure[];
  /** Lens set. Defaults to the assessment lenses; the estate supplies its own. */
  lenses?: WorkflowLensDefinition[];
  /** Sentence under the reconciliation footer, naming this projection's source. */
  provenance?: string;
  /**
   * Entity kind the operator may FOCUS the whole graph on — 'asset' for the
   * estate view. When set and the graph holds more than one of that kind, a
   * focus picker is offered and selecting an entity scopes the canvas to it and
   * everything attached to it. Omitted, the graph behaves exactly as before.
   */
  focusKind?: WorkflowNodeKind;
  /**
   * Grouping modes offered in the sidebar. Defaults to the assessment set
   * (phase / layer …). A projection with no phases or layers — the estate —
   * passes the groupings it actually populates, so no button draws nothing.
   */
  groupings?: WorkflowGrouping[];
  /** Replaces the scanner's evidence banner ("nothing was executed…") for other projections. */
  evidenceNote?: React.ReactNode;
  /** Replaces the inferred-toggle help text. */
  inferredHint?: string;
  /** Replaces the default reconciliation sentence in the footer. */
  reconciliationNote?: React.ReactNode;
}

const DEFAULT_GROUPINGS: WorkflowGrouping[] = ['none', 'phase', 'layer', 'severity', 'kind'];

export function ExposureWorkflowGraph({
  assessment,
  mode,
  graph: providedGraph,
  findings: providedFindings,
  exposures: providedExposures,
  lenses: providedLenses,
  provenance,
  focusKind,
  groupings = DEFAULT_GROUPINGS,
  evidenceNote,
  inferredHint,
  reconciliationNote,
}: ExposureWorkflowGraphProps) {
  const resolvedMode = mode ?? assessment?.task.mode ?? 'local';

  const graph = React.useMemo(
    () =>
      providedGraph ??
      (assessment
        ? buildWorkflowGraph(assessment, { descriptors: descriptorsForMode(resolvedMode) })
        : EMPTY_GRAPH),
    [providedGraph, assessment, resolvedMode],
  );

  const findingCorpus = React.useMemo(
    () => providedFindings ?? assessment?.findings ?? [],
    [providedFindings, assessment],
  );
  const exposureCorpus = React.useMemo(
    () => providedExposures ?? assessment?.exposures ?? [],
    [providedExposures, assessment],
  );
  const lensSet = providedLenses ?? WORKFLOW_LENSES;

  const [lensId, setLensId] = React.useState<WorkflowLens>('flow');
  const lens = React.useMemo(
    () => lensSet.find((entry) => entry.id === lensId) ?? lensSet[0],
    [lensSet, lensId],
  );

  const [hiddenKinds, setHiddenKinds] = React.useState<ReadonlySet<WorkflowNodeKind>>(new Set());
  const [hiddenSeverities, setHiddenSeverities] = React.useState<ReadonlySet<FindingSeverity | 'none'>>(new Set());
  const [showInferred, setShowInferred] = React.useState(true);
  const [colourMode, setColourMode] = React.useState<ColourMode>('risk');
  const [grouping, setGrouping] = React.useState<WorkflowGrouping>(lens.groupBy);
  const [query, setQuery] = React.useState('');
  const [frozen, setFrozen] = React.useState(false);
  const [expanded, setExpanded] = React.useState(false);
  const [selected, setSelected] = React.useState<WorkflowNode | null>(null);
  const [focusIds, setFocusIds] = React.useState<ReadonlySet<string>>(new Set());

  /* Past ~40 entities the layout needs materially more room than a sparse lens
     — the canvas grows with it rather than making every lens pay for the
     densest one. */
  const denseGraph = graph.nodes.length > 40;
  const [openFinding, setOpenFinding] = React.useState<ExposureFinding | null>(null);
  const [repulsion, setRepulsion] = React.useState(100);
  const [linkLength, setLinkLength] = React.useState(100);
  const [gravity, setGravity] = React.useState(100);

  const flowRef = React.useRef<ReactFlowInstance | null>(null);
  const store = React.useMemo(() => new FocusStore(), []);

  /* ── full screen ──────────────────────────────────────────────────────
     `expanded` pins the stage over the viewport (fixed, opaque). The browser
     Fullscreen API is layered on top when available so the map also gets the
     whole monitor; if it is refused (iframe, iOS) the pinned stage alone still
     fills the window. The stage wraps the finding sheet too: an element in
     browser full screen hides everything outside it. */
  const stageRef = React.useRef<HTMLDivElement | null>(null);
  const openFindingRef = React.useRef(openFinding);
  openFindingRef.current = openFinding;
  const [fitRequest, setFitRequest] = React.useState(0);
  const [relayoutRequest, setRelayoutRequest] = React.useState(0);

  const enterFullScreen = React.useCallback(() => {
    setExpanded(true);
    const stage = stageRef.current;
    if (stage && document.fullscreenEnabled && !document.fullscreenElement) {
      stage.requestFullscreen({ navigationUI: 'hide' }).catch(() => undefined);
    }
    /* Move focus into the dialog so keyboard and screen-reader users land in it. */
    requestAnimationFrame(() => stageRef.current?.focus({ preventScroll: true }));
  }, []);

  const exitFullScreen = React.useCallback(() => {
    setExpanded(false);
    if (document.fullscreenElement && document.fullscreenElement === stageRef.current) {
      document.exitFullscreen().catch(() => undefined);
    }
    setFitRequest((count) => count + 1);
  }, []);

  const toggleFullScreen = React.useCallback(() => {
    if (expanded) exitFullScreen();
    else {
      enterFullScreen();
      setFitRequest((count) => count + 1);
    }
  }, [expanded, enterFullScreen, exitFullScreen]);

  /** Fit = give the map the whole screen, then frame all of it. */
  const fitMap = React.useCallback(() => {
    if (!expanded) enterFullScreen();
    setFitRequest((count) => count + 1);
  }, [expanded, enterFullScreen]);

  /* The dashboard content lives in a `z-10` stacking context below the
     sidebar (`z-50`); without browser full screen the pinned stage would sit
     under the sidebar. Lift the content layer and stop the page scrolling
     behind the stage while it is open. */
  React.useEffect(() => {
    if (!expanded) return;
    const root = document.documentElement;
    root.classList.add('qg-workflow-fullscreen');
    return () => root.classList.remove('qg-workflow-fullscreen');
  }, [expanded]);

  /* Esc in browser full screen is consumed by the browser, which only fires
     `fullscreenchange` — follow it so the pinned stage does not linger. */
  React.useEffect(() => {
    const onChange = () => {
      if (!document.fullscreenElement && expanded) {
        setExpanded(false);
        setFitRequest((count) => count + 1);
      }
    };
    document.addEventListener('fullscreenchange', onChange);
    return () => document.removeEventListener('fullscreenchange', onChange);
  }, [expanded]);

  /* Keyboard while in full screen: Esc exits (when the browser did not take
     it), + / − zoom, 0 fits. Ignored while typing in the filter. */
  React.useEffect(() => {
    if (!expanded) return;
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)) return;
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      const flow = flowRef.current;
      if (event.key === 'Escape') {
        if (openFindingRef.current) return; /* the finding sheet closes first */
        exitFullScreen();
      } else if (event.key === '+' || event.key === '=') {
        void flow?.zoomIn({ duration: 220 });
      } else if (event.key === '-' || event.key === '_') {
        void flow?.zoomOut({ duration: 220 });
      } else if (event.key === '0') {
        setFitRequest((count) => count + 1);
      } else return;
      event.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [expanded, exitFullScreen]);

  /* A lens carries its own natural grouping; changing tab adopts it. */
  React.useEffect(() => {
    setGrouping(groupings.includes(lens.groupBy) ? lens.groupBy : 'none');
    setSelected(null);
    store.select(null);
  }, [lens, store, groupings]);

  const projection = React.useMemo(
    () =>
      projectLens(graph, {
        lens,
        hiddenKinds,
        showInferred,
        grouping,
        query,
        hiddenSeverities,
        focusIds,
        focusKind,
      }),
    [graph, lens, hiddenKinds, showInferred, grouping, query, hiddenSeverities, focusIds, focusKind],
  );

  /* The entities the focus picker offers, worst first so the asset that needs
     attention is the one at the top of the list. */
  const focusCandidates = React.useMemo(() => {
    if (!focusKind) return [];
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return graph.nodes
      .filter((node) => node.kind === focusKind)
      .sort(
        (a, b) =>
          (a.severity ? rank[a.severity] : 9) - (b.severity ? rank[b.severity] : 9) ||
          b.findingIds.length - a.findingIds.length ||
          a.label.localeCompare(b.label),
      );
  }, [graph.nodes, focusKind]);

  /* A focus is only meaningful while its subject still exists. A refreshed
     estate that no longer contains the focused asset must not leave the canvas
     empty with no explanation. */
  React.useEffect(() => {
    setFocusIds((current) => {
      if (current.size === 0) return current;
      const live = new Set(focusCandidates.map((node) => node.id));
      const next = new Set([...current].filter((id) => live.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [focusCandidates]);

  const toggleFocus = React.useCallback((id: string) => {
    setFocusIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setSelected(null);
  }, []);

  /* Per-lens node totals for the tab strip — counted on the unfiltered graph so
     a tab badge always states what that lens contains, not what is left after
     the current filters. */
  const lensCounts = React.useMemo(() => {
    const map = new Map<WorkflowLens, number>();
    for (const entry of lensSet) {
      map.set(entry.id, entry.kinds.reduce((total, kind) => total + graph.counts[kind], 0));
    }
    return map;
  }, [graph.counts]);

  const availableKinds = React.useMemo(
    () => lens.kinds.filter((kind) => graph.counts[kind] > 0),
    [lens, graph.counts],
  );

  const toggleKind = (kind: WorkflowNodeKind) => {
    setHiddenKinds((current) => {
      const next = new Set(current);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });
  };

  const toggleSeverity = (band: FindingSeverity | 'none') => {
    setHiddenSeverities((current) => {
      const next = new Set(current);
      if (next.has(band)) next.delete(band);
      else next.add(band);
      return next;
    });
  };

  const resetPhysics = () => {
    setRepulsion(100);
    setLinkLength(100);
    setGravity(100);
  };

  const physics = React.useMemo(
    () => ({
      repulsion: 120 + (repulsion / 100) * 620,
      linkLength: 40 + (linkLength / 100) * 110,
      gravity: 0.03 + (gravity / 100) * 0.19,
    }),
    [repulsion, linkLength, gravity],
  );

  const layoutKey = `${lensId}|${grouping}|${showInferred}|${[...hiddenKinds].sort().join(',')}|${[...hiddenSeverities].sort().join(',')}|${query.trim()}`;

  const legend =
    colourMode === 'risk'
      ? SEVERITY_BANDS.map((band) => ({ id: band.id as string, label: band.label, color: band.color, toggle: () => toggleSeverity(band.id), active: !hiddenSeverities.has(band.id) }))
      : colourMode === 'type'
        ? availableKinds.map((kind) => ({ id: kind, label: NODE_KIND_LABEL[kind], color: KIND_COLOR[kind], toggle: () => toggleKind(kind), active: !hiddenKinds.has(kind) }))
        : (['observed', 'inferred', 'potential', 'unknown'] as const).map((entry) => ({
            id: entry,
            label: DETECTION_LABEL[entry],
            color: DETECTION_COLOR[entry],
            toggle: undefined,
            active: true,
          }));

  const empty = projection.nodes.length === 0;

  return (
    <div
      ref={stageRef}
      className={cn(
        'qg-workflow-stage',
        expanded && 'fixed inset-0 z-[60] flex flex-col bg-[var(--qg-dashboard-bg)] p-2 sm:p-3',
      )}
      role={expanded ? 'dialog' : undefined}
      aria-modal={expanded ? true : undefined}
      aria-label={expanded ? 'Exposure workflow, full screen' : undefined}
      tabIndex={expanded ? -1 : undefined}
    >
      <Panel className={cn('overflow-hidden', expanded && 'flex min-h-0 flex-1 flex-col')}>
        {/* ── header ─────────────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
          <div className="flex items-center gap-3">
            <SectionLabel>Exposure Workflow</SectionLabel>
            <span className="hidden font-mono text-[10px] text-slate-500 sm:inline">
              process &amp; relationship map
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-slate-500">
              {graph.nodes.length.toLocaleString()} entities · {graph.edges.length.toLocaleString()} relationships
            </span>
            <button
              type="button"
              onClick={toggleFullScreen}
              aria-pressed={expanded}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-2 py-1 font-mono text-[10px] font-semibold text-slate-400 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
            >
              {expanded ? <Minimize2 aria-hidden className="h-3 w-3" /> : <Maximize2 aria-hidden className="h-3 w-3" />}
              {expanded ? 'Exit full screen' : 'Full screen'}
              {expanded && (
                <kbd className="rounded border border-white/[0.1] px-1 font-mono text-[9px] text-slate-500">Esc</kbd>
              )}
            </button>
          </div>
        </div>

        {/* ── lens tabs ──────────────────────────────────────────────────── */}
        <div
          role="tablist"
          aria-label="Workflow graph lens"
          className="flex gap-1 overflow-x-auto border-b border-white/[0.06] bg-white/[0.012] px-3"
        >
          {lensSet.map((entry) => {
            const active = entry.id === lensId;
            return (
              <button
                key={entry.id}
                role="tab"
                aria-selected={active}
                type="button"
                onClick={() => setLensId(entry.id)}
                className={cn(
                  'relative flex shrink-0 items-center gap-1.5 whitespace-nowrap px-3 py-2.5 text-[12px] font-bold transition-colors',
                  active ? 'text-white' : 'text-slate-500 hover:text-slate-300',
                )}
              >
                {entry.label}
                <span
                  className={cn(
                    'rounded px-1 py-px font-mono text-[9.5px] font-bold',
                    active ? 'bg-cyan-400/15 text-cyan-300' : 'bg-white/[0.05] text-slate-500',
                  )}
                >
                  {lensCounts.get(entry.id) ?? 0}
                </span>
                {active && (
                  <motion.span
                    layoutId="workflow-lens-underline"
                    className="absolute inset-x-2 bottom-0 h-[2px] rounded-full bg-cyan-400"
                    transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                  />
                )}
              </button>
            );
          })}
        </div>

        {/* ── provenance banner (§63) ────────────────────────────────────── */}
        <div className="flex items-start gap-2.5 border-b border-white/[0.06] bg-amber-400/[0.045] px-5 py-2.5">
          <AlertTriangle aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" />
          <p className="text-[11.5px] leading-relaxed text-amber-100/80">
            {evidenceNote ?? (
              <>
                Algorithm, CBOM, exposure and remediation nodes are conclusions <strong className="font-bold">inferred</strong>{' '}
                from static evidence — nothing was executed. Process, finding, file and secret nodes were{' '}
                <strong className="font-bold">observed</strong> in the corpus itself. Inferred relationships are drawn dashed
                and can be switched off.
              </>
            )}
          </p>
        </div>

        {/* ── body ───────────────────────────────────────────────────────── */}
        <div
          className={cn(
            'grid grid-cols-[minmax(0,1fr)] lg:grid-cols-[15.5rem_minmax(0,1fr)]',
            expanded && 'min-h-0 flex-1 grid-rows-[minmax(0,1fr)]',
          )}
        >
          {/* ── sidebar ──────────────────────────────────────────────────── */}
          {/* In full screen the controls scroll on their own so the canvas keeps
              the full height; below lg they give the canvas the whole screen. */}
          <div
            className={cn(
              'min-w-0 divide-y divide-white/[0.06] border-b border-white/[0.06] lg:border-b-0 lg:border-r',
              expanded && 'overflow-y-auto max-lg:hidden',
            )}
          >
            {/* Scoping comes FIRST: on an estate with more than one asset it is
                the control that makes the rest of the graph readable. Offered
                only when there is something to choose between. */}
            {focusKind && focusCandidates.length > 0 && (
              <FocusPanel
                candidates={focusCandidates}
                focusIds={focusIds}
                onToggle={toggleFocus}
                onClear={() => {
                  setFocusIds(new Set());
                  setSelected(null);
                }}
                kindLabel={NODE_KIND_LABEL[focusKind].toLowerCase()}
              />
            )}
            <div className="px-4 py-3.5">
              <SidebarHeading icon={Filter}>Entity types</SidebarHeading>
              <div className="flex flex-wrap gap-1.5">
                {availableKinds.map((kind) => (
                  <EntityChip
                    key={kind}
                    label={NODE_KIND_LABEL[kind]}
                    count={graph.counts[kind]}
                    color={KIND_COLOR[kind]}
                    icon={KIND_ICON[kind]}
                    active={!hiddenKinds.has(kind)}
                    onClick={() => toggleKind(kind)}
                  />
                ))}
              </div>
              <label className="mt-3 flex cursor-pointer items-start gap-2">
                <input
                  type="checkbox"
                  checked={showInferred}
                  onChange={(event) => setShowInferred(event.target.checked)}
                  className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-cyan-400"
                />
                <span className="min-w-0">
                  <span className="block text-[11.5px] font-semibold text-slate-300">Show inferred relationships</span>
                  <span className="mt-0.5 block text-[10.5px] leading-relaxed text-slate-500">
                    {inferredHint ?? 'Nothing was executed. Turn it off to see only what is literally present in the files.'}
                  </span>
                </span>
              </label>
            </div>

            <div className="px-4 py-3.5">
              <SidebarHeading icon={Palette}>Colour by</SidebarHeading>
              <div className="mb-2.5 grid grid-cols-3 gap-0.5 rounded-lg border border-white/[0.07] bg-[#050a15] p-0.5">
                {(['risk', 'type', 'evidence'] as ColourMode[]).map((entry) => (
                  <button
                    key={entry}
                    type="button"
                    onClick={() => setColourMode(entry)}
                    aria-pressed={colourMode === entry}
                    className={cn(
                      'rounded-md py-1 text-[11px] font-bold capitalize transition-colors',
                      colourMode === entry ? 'bg-white/[0.08] text-white' : 'text-slate-500 hover:text-slate-300',
                    )}
                  >
                    {entry}
                  </button>
                ))}
              </div>
              <ul className="grid grid-cols-2 gap-x-2 gap-y-1">
                {legend.map((entry) => (
                  <li key={entry.id}>
                    <button
                      type="button"
                      disabled={!entry.toggle}
                      onClick={entry.toggle}
                      className={cn(
                        'flex w-full items-center gap-1.5 rounded py-0.5 text-left text-[11px] transition-opacity',
                        entry.toggle ? 'cursor-pointer hover:opacity-100' : 'cursor-default',
                        entry.active ? 'text-slate-300 opacity-100' : 'text-slate-600 opacity-45',
                      )}
                    >
                      <span
                        aria-hidden
                        className="h-2 w-2 shrink-0 rounded-full"
                        style={{ backgroundColor: entry.color }}
                      />
                      <span className="truncate">{entry.label}</span>
                    </button>
                  </li>
                ))}
              </ul>
              {colourMode === 'risk' && (
                <p className="mt-2 text-[10px] leading-relaxed text-slate-600">
                  “None” means no finding is attached to that entity — not that it passed.
                </p>
              )}
            </div>

            <div className="px-4 py-3.5">
              <SidebarHeading icon={Layers}>Group by</SidebarHeading>
              <div className="flex flex-wrap gap-1">
                {groupings.map((entry) => (
                  <button
                    key={entry}
                    type="button"
                    onClick={() => setGrouping(entry)}
                    aria-pressed={grouping === entry}
                    className={cn(
                      'rounded-md border px-2 py-1 text-[10.5px] font-semibold transition-colors',
                      grouping === entry
                        ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-300'
                        : 'border-white/[0.07] text-slate-500 hover:text-slate-300',
                    )}
                  >
                    {GROUPING_LABEL[entry]}
                  </button>
                ))}
              </div>
            </div>

            <div className="px-4 py-3.5">
              <SidebarHeading
                icon={Activity}
                action={
                  <button
                    type="button"
                    onClick={resetPhysics}
                    className="inline-flex items-center gap-1 font-mono text-[9.5px] font-bold uppercase tracking-wider text-slate-500 transition-colors hover:text-cyan-300"
                  >
                    <RotateCcw aria-hidden className="h-2.5 w-2.5" />
                    Reset
                  </button>
                }
              >
                Physics
              </SidebarHeading>
              <div className="space-y-2.5">
                <Slider
                  label="Repulsion"
                  value={repulsion}
                  min={20}
                  max={200}
                  step={5}
                  display={`${repulsion}%`}
                  onChange={setRepulsion}
                />
                <Slider
                  label="Link length"
                  value={linkLength}
                  min={20}
                  max={200}
                  step={5}
                  display={`${linkLength}%`}
                  onChange={setLinkLength}
                />
                <Slider
                  label="Cluster gravity"
                  value={gravity}
                  min={0}
                  max={200}
                  step={5}
                  display={`${gravity}%`}
                  onChange={setGravity}
                />
              </div>
              <button
                type="button"
                onClick={() => setFrozen((current) => !current)}
                className={cn(
                  'mt-3 inline-flex w-full items-center justify-center gap-1.5 rounded-lg border px-2 py-1.5 text-[11px] font-semibold transition-colors',
                  frozen
                    ? 'border-amber-400/35 bg-amber-400/10 text-amber-300'
                    : 'border-white/[0.08] text-slate-400 hover:border-cyan-400/30 hover:text-cyan-300',
                )}
              >
                {frozen ? <Play aria-hidden className="h-3 w-3" /> : <Pause aria-hidden className="h-3 w-3" />}
                {frozen ? 'Resume simulation' : 'Freeze simulation'}
              </button>
            </div>
          </div>

          {/* ── canvas ───────────────────────────────────────────────────── */}
          <div className={cn('relative min-w-0', expanded && 'flex min-h-0 flex-col')}>
            {/* toolbar */}
            <div className="flex flex-wrap items-center gap-2 border-b border-white/[0.06] px-3 py-2">
              <span className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] bg-[#050a15] px-2 py-1 font-mono text-[10.5px] text-slate-400">
                <Waypoints aria-hidden className="h-3 w-3 text-cyan-400/70" />
                {projection.nodes.length} nodes · {projection.edges.length} edges
              </span>
              <button
                type="button"
                onClick={fitMap}
                title={expanded ? 'Frame the whole map' : 'Open the map full screen and frame all of it'}
                className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-2 py-1 text-[11px] font-semibold text-slate-400 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
              >
                <Scan aria-hidden className="h-3 w-3" />
                Fit
              </button>
              <button
                type="button"
                onClick={() => setRelayoutRequest((count) => count + 1)}
                title="Release pinned nodes and compute a fresh layout"
                className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-2 py-1 text-[11px] font-semibold text-slate-400 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
              >
                <RotateCcw aria-hidden className="h-3 w-3" />
                Re-layout
              </button>
              <div className="ml-auto flex min-w-[10rem] flex-1 items-center gap-1.5 rounded-lg border border-white/[0.08] bg-[#050a15] px-2 py-1 sm:max-w-[15rem]">
                <Search aria-hidden className="h-3 w-3 shrink-0 text-slate-600" />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Filter entities"
                  aria-label="Filter graph entities"
                  className="min-w-0 flex-1 bg-transparent text-[11px] text-slate-200 outline-none placeholder:text-slate-600"
                />
                {query && (
                  <button
                    type="button"
                    onClick={() => setQuery('')}
                    aria-label="Clear filter"
                    className="text-slate-600 hover:text-slate-300"
                  >
                    <X aria-hidden className="h-3 w-3" />
                  </button>
                )}
              </div>
            </div>

            <p className="border-b border-white/[0.06] px-3 py-1.5 text-[11px] leading-relaxed text-slate-500">
              {lens.description}
            </p>

            {/*
              * Canvas height.
              *
              * A flat 560px was a keyhole: the force layout for ~90 entities
              * spreads over roughly 1,900 x 1,370 units, so most of the graph
              * sat outside the frame and every pan pushed more of it out. The
              * height now scales with the VIEWPORT (a 1440p screen gets a much
              * larger canvas than a laptop) and with the SIZE OF THE GRAPH, so
              * a two-node lens does not reserve a screen of emptiness while a
              * dense one gets room to breathe. Full screen hands the canvas
              * every pixel the stage has left.
              */}
            <div
              className={cn('relative w-full', expanded && 'min-h-0 flex-1')}
              style={
                expanded
                  ? undefined
                  : { height: `clamp(${denseGraph ? 660 : 540}px, ${denseGraph ? 78 : 64}vh, ${denseGraph ? 1000 : 760}px)` }
              }
            >
              {empty ? (
                <div className="grid h-full place-items-center px-6 text-center">
                  <div>
                    <Waypoints aria-hidden className="mx-auto h-8 w-8 text-slate-700" />
                    <p className="mt-2 text-[13px] font-bold text-slate-300">Nothing to plot under these filters</p>
                    <p className="mt-1 text-[11.5px] text-slate-500">
                      {graph.counts[lens.kinds[0]] === 0
                        ? 'This lens has no entities in the current assessment.'
                        : 'Re-enable an entity type, a risk band, or clear the search to bring the map back.'}
                    </p>
                  </div>
                </div>
              ) : (
                <FocusContext.Provider value={store}>
                  <ReactFlowProvider>
                    <WorkflowCanvas
                      nodes={projection.nodes}
                      edges={projection.edges}
                      clusters={projection.clusters}
                      grouping={grouping}
                      colourMode={colourMode}
                      physics={physics}
                      frozen={frozen}
                      layoutKey={layoutKey}
                      store={store}
                      onSelect={setSelected}
                      onReady={(instance) => {
                        flowRef.current = instance;
                      }}
                      fitRequest={fitRequest}
                      relayoutRequest={relayoutRequest}
                      expanded={expanded}
                      onFit={fitMap}
                      onToggleExpanded={toggleFullScreen}
                    />
                  </ReactFlowProvider>
                </FocusContext.Provider>
              )}

              <Inspector
                node={selected}
                findingCorpus={findingCorpus}
                nodes={projection.nodes}
                edges={projection.edges}
                onClose={() => {
                  setSelected(null);
                  store.select(null);
                }}
                onOpenFinding={setOpenFinding}
                onSelectNode={(next) => {
                  setSelected(next);
                  store.select(next.id);
                }}
              />
            </div>
          </div>
        </div>

        {/* ── reconciliation + truncation disclosure ─────────────────────── */}
        <div className="space-y-1 border-t border-white/[0.06] px-5 py-2.5">
          <p className="font-mono text-[10.5px] leading-relaxed text-slate-500">
            {reconciliationNote ?? (
              <>
                Plotted {graph.reconciliation.findingsProjected.toLocaleString()} of{' '}
                {graph.reconciliation.findingsInAssessment.toLocaleString()} findings,{' '}
                {graph.reconciliation.componentsProjected.toLocaleString()} of{' '}
                {graph.reconciliation.componentsInAssessment.toLocaleString()} CBOM components and{' '}
                {graph.reconciliation.exposuresProjected.toLocaleString()} of{' '}
                {graph.reconciliation.exposuresInAssessment.toLocaleString()} correlated exposures.
              </>
            )}{' '}
            {provenance ??
              'Every node is a projection of a row in the panels above — the map adds nothing to the assessment.'}
          </p>
          {/* A focused canvas shows PART of the estate while the totals above
              describe all of it. Saying so is what stops a filtered view being
              read as the tenant's whole exposure. */}
          {focusIds.size > 0 && focusKind && (
            <p className="font-mono text-[10.5px] leading-relaxed text-cyan-200/70">
              Focused on {focusIds.size} of {focusCandidates.length}{' '}
              {NODE_KIND_LABEL[focusKind].toLowerCase()} — the canvas shows that subset and everything attached to it.
              The totals above still describe the whole estate.
            </p>
          )}
          {graph.truncation.truncated && (
            <p className="font-mono text-[10.5px] leading-relaxed text-amber-200/70">
              Bounded for legibility:{' '}
              {graph.truncation.dropped
                .map((entry) => `${entry.dropped.toLocaleString()} of ${entry.total.toLocaleString()} ${NODE_KIND_LABEL[entry.kind].toLowerCase()}`)
                .join(', ')}{' '}
              not drawn. The highest-severity members were kept; the scores and totals elsewhere are computed over all of
              them.
            </p>
          )}
        </div>
      </Panel>

      {/* Reuses the platform's real evidence sheet — the graph never renders a
          second, divergent version of a finding. */}
      <FindingDetail finding={openFinding} onClose={() => setOpenFinding(null)} exposures={exposureCorpus} />

      {/* Canvas-scoped styling. React Flow's base stylesheet ships no theme, so
          the few chrome surfaces it does draw are painted here. */}
      <style>{`
        .qg-workflow-flow { background: transparent; }
        .qg-workflow-flow .react-flow__node { cursor: pointer; }
        .qg-workflow-flow .react-flow__node.nopan { cursor: pointer; }
        .qg-workflow-flow .react-flow__minimap { margin: 10px; }
        .qg-workflow-range::-webkit-slider-thumb {
          appearance: none;
          width: 12px; height: 12px;
          border-radius: 9999px;
          background: ${ACCENT.cyan};
          border: 2px solid #04060e;
          box-shadow: 0 0 0 1px ${ACCENT.cyan}66;
          cursor: pointer;
        }
        .qg-workflow-range::-moz-range-thumb {
          width: 12px; height: 12px;
          border-radius: 9999px;
          background: ${ACCENT.cyan};
          border: 2px solid #04060e;
          cursor: pointer;
        }
        .qg-workflow-flow .react-flow__panel.qg-workflow-zoom { margin: 12px; }
        /* Browser full screen paints the element on a black backdrop by
           default; the stage brings its own theme ground instead. */
        .qg-workflow-stage:fullscreen { background: var(--qg-dashboard-bg); }
        .qg-workflow-stage::backdrop { background: var(--qg-dashboard-bg); }
        html.qg-workflow-fullscreen .dashboard-theme-scope { z-index: 70; }
        html.qg-workflow-fullscreen .qg-dashboard-main { overflow: hidden; }
        .qg-workflow-stage:focus { outline: none; }
        /* The minimap's colours are props drawn for the dark ground; on
           parchment it read as a black hole in the corner. */
        .qg-theme-light .qg-workflow-flow .react-flow__minimap {
          background-color: var(--qg-dashboard-surface-strong) !important;
          border-color: var(--qg-dashboard-border) !important;
          box-shadow: var(--qg-panel-shadow);
        }
        .qg-theme-light .qg-workflow-flow .react-flow__minimap-mask { fill: rgba(11, 29, 58, 0.12); }
      `}</style>
    </div>
  );
}
