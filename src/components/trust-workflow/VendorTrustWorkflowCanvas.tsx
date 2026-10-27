'use client'

/**
 * VendorTrustWorkflowCanvas — the shared node/edge canvas behind Vendor PQC
 * Readiness, Trust Chain Analyzer and the Hybrid Crypto Lab.
 *
 * ENGINEERING NOTES
 * • The canvas renders a `WorkflowGraph` (see graph-model.ts). It owns only
 *   presentation state — selection, grouping, isolation, path tracing, manual
 *   node positions — and never writes to the records the graph came from.
 * • LAYOUT is the deterministic layered pass in graph-model; RENDERING is React
 *   Flow. Node sizes and handles are DECLARED (so the first paint has exact
 *   bounds and `fitView` works immediately) AND rendered as real <Handle>s.
 *   Both are load-bearing: node objects here are memoised, so React Flow's
 *   ResizeObserver pass re-measures handles from the DOM and keeps the result
 *   — with no <Handle> elements that result is empty and every edge fails
 *   with error 008, leaving a blank edge layer.
 * • Selection arrives through `onNodesChange` select events, so a node chosen
 *   with the keyboard (Tab + Enter) behaves exactly like a clicked one.
 * • Motion is limited to the traced path / selected edge and is switched off
 *   under `prefers-reduced-motion`.
 */

import { memo, useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react'
import {
  Background, BackgroundVariant, BaseEdge, EdgeLabelRenderer, Handle, MarkerType, MiniMap, Position,
  ReactFlow, ReactFlowProvider, getBezierPath, getNodesBounds, getViewportForBounds,
  useReactFlow, type Edge, type EdgeChange, type EdgeProps, type Node, type NodeChange, type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/base.css'
import './workflow-canvas.css'
import { toPng } from 'html-to-image'
import {
  Activity, Anchor, AppWindow, ArrowLeftToLine, ArrowRightToLine, BadgeCheck, Binary, Boxes, Briefcase,
  Building2, ChevronsDownUp, ChevronsUpDown, CircleDot, Download, FileBadge, Fingerprint, Focus, Globe,
  Handshake, Info, KeyRound, KeySquare, Landmark, Laptop, Layers, Link, Link2, Lock, LockKeyhole,
  Maximize2, Network, PenTool, RotateCcw, Route, Search, Server, ShieldCheck, Tag, Waypoints, X,
  ZoomIn, ZoomOut, type LucideIcon,
} from 'lucide-react'
import {
  PROVENANCE_LABEL, STATUS_META, buildAdjacency, collapseGroups, layoutLayered, shortestPath, traverse,
  type EdgeProvenance, type TracedPath, type WorkflowEdge, type WorkflowGraph, type WorkflowIcon,
  type WorkflowNode, type WorkflowShape, type WorkflowStatus,
} from './graph-model'

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

const ICONS: Record<WorkflowIcon, LucideIcon> = {
  organization: Building2, vendor: Building2, application: AppWindow, service: Boxes,
  infrastructure: Server, identity: Fingerprint, business: Briefcase, surface: Globe,
  algorithm: Binary, certificate: FileBadge, 'root-ca': Landmark, 'intermediate-ca': ShieldCheck,
  anchor: Anchor, client: Laptop, handshake: Handshake, 'key-exchange': KeyRound, kem: LockKeyhole,
  signature: PenTool, secret: KeySquare, kdf: Waypoints, session: Link2, cipher: Lock,
  telemetry: Activity, group: Layers, chain: Link,
}

const SIZE: Record<WorkflowShape, { w: number; h: number }> = {
  card: { w: 240, h: 128 },
  document: { w: 240, h: 128 },
  shield: { w: 240, h: 116 },
  step: { w: 224, h: 120 },
  pill: { w: 210, h: 62 },
  stack: { w: 240, h: 108 },
}

const SLOT = { w: 240, h: 128 }
const LAYOUT = { nodeWidth: SLOT.w, nodeHeight: SLOT.h, columnGap: 104, rowGap: 26 }
const SHAPE_LABEL: Record<WorkflowShape, string> = {
  card: 'System / vendor', document: 'Certificate', shield: 'Authority / anchor',
  step: 'Protocol step', pill: 'Algorithm / surface', stack: 'Collapsed group',
}

type Scope = 'direct' | 'upstream' | 'downstream' | 'both'

interface NodeFlags {
  selected: boolean
  dimmed: boolean
  related: boolean
  match: boolean
  path: boolean
  traceStart: boolean
  badges: boolean
}

interface EdgeFlags {
  dimmed: boolean
  related: boolean
  selected: boolean
  flowing: boolean
  label: boolean
}

type FlowNode = Node<{ node: WorkflowNode; flags: NodeFlags }, 'workflow'>
/** Lane headers are inert nodes so `fitView` and the PNG export include them. */
type LaneNode = Node<{ label: string }, 'lane'>
type CanvasNode = FlowNode | LaneNode
const LANE_HEIGHT = 28
type FlowEdge = Edge<{ edge: WorkflowEdge; flags: EdgeFlags }, 'workflow'>

export interface PathExplanationView {
  verdict: 'trusted' | 'untrusted' | 'unknown'
  summary: string
  reasons: Array<{ status: WorkflowStatus; text: string }>
}

export interface DetailContext {
  nodeById: Map<string, WorkflowNode>
  incoming: Array<{ edge: WorkflowEdge; node: WorkflowNode }>
  outgoing: Array<{ edge: WorkflowEdge; node: WorkflowNode }>
  upstreamCount: number
  downstreamCount: number
  select: (nodeId: string) => void
}

export interface VendorTrustWorkflowCanvasProps {
  graph: WorkflowGraph
  ariaLabel: string
  status: 'loading' | 'ready' | 'error'
  error?: string | null
  onRetry?: () => void
  empty: { title: string; detail: string; cta?: { label: string; href: string } }
  /** Page-specific filters or mode switches rendered inside the toolbar. */
  toolbarExtras?: ReactNode
  /** Externally requested focus (URL parameter, register row). */
  focusNodeId?: string | null
  onSelectNode?: (node: WorkflowNode | null) => void
  renderNodeDetail?: (node: WorkflowNode, context: DetailContext) => ReactNode
  renderEdgeDetail?: (edge: WorkflowEdge, context: DetailContext) => ReactNode
  enableTrace?: boolean
  explainPath?: (path: TracedPath, nodeById: Map<string, WorkflowNode>) => PathExplanationView
  /** Groups with more members than this start collapsed. */
  autoCollapseAbove?: number
  height?: number
  exportName: string
}

/* ------------------------------------------------------------------ */
/* Node + edge renderers                                               */
/* ------------------------------------------------------------------ */

function StatusGlyph({ status }: { status: WorkflowStatus }) {
  return <span className="qg-wf-glyph" aria-hidden="true">{STATUS_META[status].glyph}</span>
}

const flagsEqual = <T extends object>(a: T, b: T) =>
  (Object.keys(a) as Array<keyof T>).every((key) => a[key] === b[key])

const WorkflowNodeView = memo(function WorkflowNodeView({ data }: NodeProps<FlowNode>) {
  const { node, flags } = data
  const Icon = ICONS[node.icon] ?? Layers
  const className = [
    'qg-wf-node', `qg-wf-node--${node.shape}`,
    node.inferred && 'is-inferred', flags.selected && 'is-selected', flags.dimmed && 'is-dimmed',
    flags.related && 'is-related', flags.match && 'is-match', flags.path && 'is-path',
    flags.traceStart && 'is-trace-start',
  ].filter(Boolean).join(' ')
  const style = { '--qg-wf-status': STATUS_META[node.status].color } as CSSProperties
  const pill = node.shape === 'pill'

  return (
    <div className={className} style={style} title={`${node.kindLabel}: ${node.label} — ${node.statusLabel}`}>
      <Handle type="target" position={Position.Left} isConnectable={false} className="qg-wf-handle" />
      <Handle type="source" position={Position.Right} isConnectable={false} className="qg-wf-handle" />
      <div className="qg-wf-node__head">
        <span className="qg-wf-node__icon" aria-hidden="true">
          {node.monogram && !pill ? <span className="qg-wf-node__monogram">{node.monogram}</span> : <Icon />}
        </span>
        <div style={{ minWidth: 0, flex: 1 }}>
          {!pill && <div className="qg-wf-node__kind">{node.kindLabel}{node.inferred ? ' · inferred' : ''}</div>}
          <div className="qg-wf-node__label">{node.label}</div>
          {pill && (
            <div className="qg-wf-node__status"><StatusGlyph status={node.status} /><span>{node.statusLabel}</span></div>
          )}
        </div>
      </div>
      {!pill && node.sublabel && <div className="qg-wf-node__sub">{node.sublabel}</div>}
      {!pill && (
        <div className="qg-wf-node__status"><StatusGlyph status={node.status} /><span>{node.statusLabel}</span></div>
      )}
      {!pill && flags.badges && node.badges && node.badges.length > 0 && (
        <div className="qg-wf-node__badges">
          {node.badges.slice(0, 2).map((badge) => (
            <span key={badge.label} className="qg-wf-badge" style={{ '--qg-wf-status': STATUS_META[badge.status].color } as CSSProperties}>
              {STATUS_META[badge.status].glyph} {badge.label}
            </span>
          ))}
        </div>
      )}
      {!pill && node.meta && node.meta.length > 0 && <div className="qg-wf-node__meta">{node.meta.join(' · ')}</div>}
    </div>
  )
}, (previous, next) => previous.data.node === next.data.node && flagsEqual(previous.data.flags, next.data.flags))

const WorkflowEdgeView = memo(function WorkflowEdgeView(props: EdgeProps<FlowEdge>) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, data } = props
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, curvature: 0.32 })
  if (!data) return null
  const { edge, flags } = data
  const className = [
    'qg-wf-edge', `qg-wf-edge--${edge.provenance}`,
    flags.dimmed && 'is-dimmed', flags.related && 'is-related', flags.selected && 'is-selected', flags.flowing && 'is-flowing',
  ].filter(Boolean).join(' ')
  const stroke = edge.status && edge.status !== 'unknown' && edge.status !== 'verified' ? STATUS_META[edge.status].color : undefined
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} className={className} interactionWidth={18} style={stroke ? { stroke } : undefined} />
      {flags.label && (
        <EdgeLabelRenderer>
          <div
            className={`qg-wf-edge-label nodrag nopan${edge.provenance === 'inferred' ? ' is-inferred' : ''}`}
            style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`, opacity: flags.dimmed ? 0.3 : 1 }}
          >
            {edge.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}, (previous, next) =>
  previous.data?.edge === next.data?.edge
  && Boolean(previous.data && next.data && flagsEqual(previous.data.flags, next.data.flags))
  && previous.sourceX === next.sourceX && previous.sourceY === next.sourceY
  && previous.targetX === next.targetX && previous.targetY === next.targetY)

function LaneView({ data }: NodeProps<LaneNode>) {
  return <div className="qg-wf__lane" aria-hidden="true">{data.label}</div>
}

const NODE_TYPES = { workflow: WorkflowNodeView, lane: LaneView }
const EDGE_TYPES = { workflow: WorkflowEdgeView }

/* ------------------------------------------------------------------ */
/* Small UI parts                                                      */
/* ------------------------------------------------------------------ */

export function StatusPill({ status, label }: { status: WorkflowStatus; label: string }) {
  return (
    <span className="qg-wf__pill" style={{ '--qg-wf-status': STATUS_META[status].color } as CSSProperties}>
      <StatusGlyph status={status} /> {label}
    </span>
  )
}

function ToolButton({ label, icon: Icon, onClick, pressed, disabled, text }: {
  label: string; icon: LucideIcon; onClick: () => void; pressed?: boolean; disabled?: boolean; text?: string
}) {
  return (
    <button type="button" className="qg-wf__btn" onClick={onClick} aria-label={label} title={label}
      aria-pressed={pressed === undefined ? undefined : pressed} disabled={disabled}>
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {text && <span className="hidden sm:inline">{text}</span>}
    </button>
  )
}

function EdgeSample({ provenance }: { provenance: EdgeProvenance }) {
  const dash = provenance === 'inferred' ? '7 5' : provenance === 'observed' ? '2 4' : undefined
  return (
    <svg className="edge-sample" viewBox="0 0 34 8" aria-hidden="true">
      <line x1="1" y1="4" x2="27" y2="4" stroke="currentColor" strokeWidth="1.6" strokeDasharray={dash} strokeLinecap="round" />
      <path d="M27 1 L33 4 L27 7 Z" fill="currentColor" />
    </svg>
  )
}

function downloadBlob(filename: string, content: Blob | string, type = 'application/json') {
  const url = typeof content === 'string' ? `data:${type};charset=utf-8,${encodeURIComponent(content)}` : URL.createObjectURL(content)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  if (typeof content !== 'string') URL.revokeObjectURL(url)
}

/* ------------------------------------------------------------------ */
/* Canvas                                                              */
/* ------------------------------------------------------------------ */

export function VendorTrustWorkflowCanvas(props: VendorTrustWorkflowCanvasProps) {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} />
    </ReactFlowProvider>
  )
}

function usePrefersReducedMotion(): boolean {
  const [reduce, setReduce] = useState(false)
  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)')
    const update = () => setReduce(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])
  return reduce
}

function CanvasInner({
  graph, ariaLabel, status, error, onRetry, empty, toolbarExtras, focusNodeId, onSelectNode,
  renderNodeDetail, renderEdgeDetail, enableTrace = false, explainPath, autoCollapseAbove = 3,
  height = 640, exportName,
}: VendorTrustWorkflowCanvasProps) {
  const flow = useReactFlow<CanvasNode, FlowEdge>()
  const reduceMotion = usePrefersReducedMotion()
  const wrapperRef = useRef<HTMLDivElement>(null)

  const [groupOverrides, setGroupOverrides] = useState<Record<string, boolean>>({})
  const [showLabels, setShowLabels] = useState(false)
  const [showBadges, setShowBadges] = useState(true)
  const [showInferred, setShowInferred] = useState(true)
  const [legendOpen, setLegendOpen] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)
  const [selection, setSelection] = useState<{ kind: 'node' | 'edge'; id: string } | null>(null)
  const [scope, setScope] = useState<Scope>('direct')
  const [isolate, setIsolate] = useState(false)
  const [trace, setTrace] = useState<{ active: boolean; from: string | null; to: string | null }>({ active: false, from: null, to: null })
  const [find, setFind] = useState('')
  const [matchIndex, setMatchIndex] = useState(0)
  const [manual, setManual] = useState<Record<string, { x: number; y: number }>>({})
  const pendingCenter = useRef<string | null>(null)
  // A canvas opened ON an entity (cross-page link) centres on it instead of
  // fitting — React Flow's initial fit would otherwise land after our centre.
  const mountedWithFocus = useRef(Boolean(focusNodeId))

  /* ---- Projection pipeline: inferred filter → group collapse → isolation → layout ---- */
  const memberCount = useMemo(() => {
    const counts = new Map<string, number>()
    for (const node of graph.nodes) if (node.groupId) counts.set(node.groupId, (counts.get(node.groupId) ?? 0) + 1)
    return counts
  }, [graph.nodes])

  const collapsedSet = useMemo(() => new Set(graph.groups
    .filter((group) => groupOverrides[group.id] ?? (memberCount.get(group.id) ?? 0) > autoCollapseAbove)
    .map((group) => group.id)), [graph.groups, groupOverrides, memberCount, autoCollapseAbove])

  const visible = useMemo(() => {
    const filtered = showInferred ? graph : { ...graph, edges: graph.edges.filter((edge) => edge.provenance !== 'inferred') }
    return collapseGroups(filtered, collapsedSet)
  }, [graph, showInferred, collapsedSet])

  const nodeById = useMemo(() => new Map(visible.nodes.map((node) => [node.id, node])), [visible.nodes])
  const edgeById = useMemo(() => new Map(visible.edges.map((edge) => [edge.id, edge])), [visible.edges])
  const adjacency = useMemo(() => buildAdjacency(visible.edges), [visible.edges])

  const selectedNode = selection?.kind === 'node' ? nodeById.get(selection.id) ?? null : null
  const selectedEdge = selection?.kind === 'edge' ? edgeById.get(selection.id) ?? null : null

  const shown = useMemo(() => {
    if (!isolate || !selectedNode) return visible
    const keep = traverse(adjacency, selectedNode.id, 'both').nodeIds
    return { ...visible, nodes: visible.nodes.filter((node) => keep.has(node.id)), edges: visible.edges.filter((edge) => keep.has(edge.source) && keep.has(edge.target)) }
  }, [isolate, selectedNode, visible, adjacency])

  const layout = useMemo(() => layoutLayered(shown.nodes, shown.edges, LAYOUT), [shown])

  /* ---- Focus sets ---- */
  const tracedPath = useMemo(
    () => (trace.from && trace.to ? shortestPath(visible.edges, trace.from, trace.to) : null),
    [trace.from, trace.to, visible.edges],
  )

  const focus = useMemo<{ nodes: Set<string>; edges: Set<string> } | null>(() => {
    if (tracedPath) return { nodes: new Set(tracedPath.nodeIds), edges: new Set(tracedPath.edges.map((edge) => edge.id)) }
    if (selectedNode) {
      if (scope === 'direct') {
        const incident = [...(adjacency.in.get(selectedNode.id) ?? []), ...(adjacency.out.get(selectedNode.id) ?? [])]
        return {
          nodes: new Set([selectedNode.id, ...incident.map((edge) => (edge.source === selectedNode.id ? edge.target : edge.source))]),
          edges: new Set(incident.map((edge) => edge.id)),
        }
      }
      const result = traverse(adjacency, selectedNode.id, scope)
      return { nodes: result.nodeIds, edges: result.edgeIds }
    }
    if (selectedEdge) return { nodes: new Set([selectedEdge.source, selectedEdge.target]), edges: new Set([selectedEdge.id]) }
    return null
  }, [tracedPath, selectedNode, selectedEdge, scope, adjacency])

  const term = find.trim().toLowerCase()
  const matches = useMemo(
    () => (term.length >= 2 ? shown.nodes.filter((node) => node.searchText.includes(term) || node.label.toLowerCase().includes(term)).map((node) => node.id) : []),
    [term, shown.nodes],
  )
  const matchSet = useMemo(() => new Set(matches), [matches])

  /* ---- React Flow projection ---- */
  const positionOf = useCallback((node: WorkflowNode) => {
    const size = SIZE[node.shape]
    if (manual[node.id]) return manual[node.id]
    const slot = layout.positions.get(node.id) ?? { x: 0, y: 0 }
    return { x: slot.x + (SLOT.w - size.w) / 2, y: slot.y + (SLOT.h - size.h) / 2 }
  }, [manual, layout])

  const flowNodes = useMemo<FlowNode[]>(() => shown.nodes.map((node) => {
    const size = SIZE[node.shape]
    const selected = selection?.kind === 'node' && selection.id === node.id
    const flags: NodeFlags = {
      selected,
      dimmed: focus ? !focus.nodes.has(node.id) : term.length >= 2 ? !matchSet.has(node.id) : false,
      related: Boolean(focus?.nodes.has(node.id)) && !selected,
      match: matchSet.has(node.id),
      path: Boolean(tracedPath?.nodeIds.includes(node.id)),
      traceStart: trace.active && trace.from === node.id,
      badges: showBadges,
    }
    return {
      id: node.id,
      type: 'workflow',
      position: positionOf(node),
      width: size.w,
      height: size.h,
      measured: { width: size.w, height: size.h },
      handles: [
        { id: null, type: 'target', position: Position.Left, x: 0, y: size.h / 2 - 0.5, width: 1, height: 1 },
        { id: null, type: 'source', position: Position.Right, x: size.w - 1, y: size.h / 2 - 0.5, width: 1, height: 1 },
      ],
      selected,
      ariaLabel: `${node.kindLabel} ${node.label}. ${node.statusLabel}.`,
      data: { node, flags },
    }
  }), [shown.nodes, selection, focus, term, matchSet, tracedPath, trace.active, trace.from, showBadges, positionOf])

  const laneNodes = useMemo<LaneNode[]>(() => {
    const lanes = graph.lanes ?? []
    if (!lanes.length || !shown.nodes.length) return []
    let top = Infinity
    for (const node of shown.nodes) top = Math.min(top, positionOf(node).y)
    return [...layout.columns.entries()].filter(([layer]) => lanes[layer]).map(([layer, x]) => ({
      id: `lane:${layer}`,
      type: 'lane',
      position: { x, y: top - LANE_HEIGHT - 22 },
      width: SLOT.w,
      height: LANE_HEIGHT,
      measured: { width: SLOT.w, height: LANE_HEIGHT },
      selectable: false,
      draggable: false,
      focusable: false,
      connectable: false,
      zIndex: -1,
      data: { label: lanes[layer] },
    }))
  }, [graph.lanes, shown.nodes, layout, positionOf])

  const canvasNodes = useMemo<CanvasNode[]>(() => [...laneNodes, ...flowNodes], [laneNodes, flowNodes])

  const flowEdges = useMemo<FlowEdge[]>(() => shown.edges.map((edge) => {
    const selected = selection?.kind === 'edge' && selection.id === edge.id
    const onPath = Boolean(tracedPath?.edges.some((candidate) => candidate.id === edge.id))
    const related = Boolean(focus?.edges.has(edge.id))
    const flags: EdgeFlags = {
      dimmed: focus ? !related : term.length >= 2,
      related,
      selected,
      flowing: !reduceMotion && (onPath || selected),
      label: showLabels || selected || onPath || (related && Boolean(selectedNode)),
    }
    const color = edge.status && edge.status !== 'unknown' && edge.status !== 'verified' ? STATUS_META[edge.status].color : 'var(--qg-wf-muted)'
    return {
      id: edge.id, source: edge.source, target: edge.target, type: 'workflow', selected,
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color },
      ariaLabel: `${nodeById.get(edge.source)?.label ?? edge.source} ${edge.label} ${nodeById.get(edge.target)?.label ?? edge.target}`,
      data: { edge, flags },
    }
  }), [shown.edges, selection, tracedPath, focus, term, reduceMotion, showLabels, selectedNode, nodeById])

  /* ---- Activation (click or keyboard) ---- */
  const activateNode = useCallback((id: string) => {
    const node = nodeById.get(id)
    if (!node) return
    if (node.kind === 'group' && node.groupId) {
      setGroupOverrides((current) => ({ ...current, [node.groupId!]: false }))
      setSelection(null)
      return
    }
    if (trace.active) {
      setTrace((current) => {
        if (!current.from || current.to) return { active: true, from: id, to: null }
        if (current.from === id) return current
        return { ...current, to: id }
      })
    }
    setSelection({ kind: 'node', id })
    onSelectNode?.(node)
  }, [nodeById, trace.active, onSelectNode])

  const clearSelection = useCallback(() => {
    setSelection(null)
    setIsolate(false)
    onSelectNode?.(null)
  }, [onSelectNode])

  const onNodesChange = useCallback((changes: NodeChange<CanvasNode>[]) => {
    const moved: Record<string, { x: number; y: number }> = {}
    let activated: string | null = null
    let deselectedCurrent = false
    for (const change of changes) {
      if (change.type === 'position' && change.position) moved[change.id] = change.position
      if (change.type === 'select' && change.selected) activated = change.id
      if (change.type === 'select' && !change.selected && selection?.kind === 'node' && change.id === selection.id) deselectedCurrent = true
    }
    if (Object.keys(moved).length) setManual((current) => ({ ...current, ...moved }))
    if (activated) activateNode(activated)
    // React Flow handles Escape on a focused node itself and only reports the
    // deselect; honour it so the keyboard can close the panel.
    else if (deselectedCurrent) clearSelection()
  }, [activateNode, clearSelection, selection])

  const onEdgesChange = useCallback((changes: EdgeChange<FlowEdge>[]) => {
    const picked = changes.find((change) => change.type === 'select' && change.selected)
    if (picked && 'id' in picked) setSelection({ kind: 'edge', id: picked.id })
  }, [])

  /* ---- Viewport ---- */
  const centerOn = useCallback((id: string, zoom?: number) => {
    const node = flow.getNode(id)
    if (!node || node.type !== 'workflow') return false
    const size = SIZE[(node as FlowNode).data.node.shape]
    const level = zoom ?? Math.max(flow.getZoom(), 0.85)
    // Land the node in the area the detail panel leaves visible: left of the
    // side panel on wide screens, above the bottom sheet on phones.
    const width = wrapperRef.current?.clientWidth ?? 1200
    const height = wrapperRef.current?.clientHeight ?? 640
    const phone = width < 768
    const dx = phone ? 0 : 185 / level
    const dy = phone ? (height * 0.28) / level : 0
    void flow.setCenter(node.position.x + size.w / 2 + dx, node.position.y + size.h / 2 + dy, {
      zoom: level,
      duration: reduceMotion ? 0 : 420,
    })
    return true
  }, [flow, reduceMotion])

  /* The initial fit is React Flow's own `fitView` prop, which waits for the
     pane to be measured; viewport calls made before `onInit` fit a 0×0 pane. */
  const initialized = useRef(false)
  const handleInit = useCallback(() => {
    initialized.current = true
    const pending = pendingCenter.current
    if (pending) {
      window.setTimeout(() => { if (centerOn(pending, 0.95)) pendingCenter.current = null }, 80)
    }
  }, [centerOn])

  const signature = useMemo(() => shown.nodes.map((node) => node.id).join('|'), [shown.nodes])
  useEffect(() => {
    if (!shown.nodes.length || !initialized.current) return
    const handle = window.setTimeout(() => {
      if (pendingCenter.current && centerOn(pendingCenter.current, 0.95)) {
        pendingCenter.current = null
        return
      }
      void flow.fitView({ padding: 0.14, duration: reduceMotion ? 0 : 320, maxZoom: 1.05 })
    }, 30)
    return () => window.clearTimeout(handle)
    // Refit only when the SET of drawn nodes changes — a live refresh that
    // changes no structure must not yank the user's viewport.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signature])

  /* External focus (URL parameter / register row). */
  useEffect(() => {
    if (!focusNodeId) return
    const raw = graph.nodes.find((node) => node.id === focusNodeId)
    if (!raw) return
    if (raw.groupId && collapsedSet.has(raw.groupId)) {
      setGroupOverrides((current) => ({ ...current, [raw.groupId!]: false }))
    }
    if (isolate && selection?.id !== focusNodeId) setIsolate(false)
    setSelection({ kind: 'node', id: focusNodeId })
    if (!initialized.current || !centerOn(focusNodeId, 0.95)) pendingCenter.current = focusNodeId
    // Only the requested id matters; graph refreshes must not re-trigger focus.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusNodeId, graph.nodes.length > 0])

  const stepMatch = useCallback((delta: number) => {
    if (!matches.length) return
    const next = (matchIndex + delta + matches.length) % matches.length
    setMatchIndex(next)
    centerOn(matches[next], 1)
  }, [matches, matchIndex, centerOn])

  useEffect(() => { setMatchIndex(0) }, [term])

  /* ---- Keyboard: Escape leaves trace / clears selection ---- */
  useEffect(() => {
    const element = wrapperRef.current
    if (!element) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      if (trace.active) setTrace({ active: false, from: null, to: null })
      else clearSelection()
    }
    element.addEventListener('keydown', onKey)
    return () => element.removeEventListener('keydown', onKey)
  }, [trace.active, clearSelection])

  /* ---- Export ---- */
  const exportJson = useCallback(() => {
    const payload = {
      exportedAt: new Date().toISOString(),
      view: ariaLabel,
      note: 'Presentation export of the visible graph. Edge provenance states whether each relationship is stored, observed, inferred or protocol structure.',
      notices: graph.notices,
      nodes: shown.nodes.map(({ searchText: _omit, ...node }) => node),
      edges: shown.edges,
    }
    downloadBlob(`${exportName}-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(payload, null, 2))
    setExportOpen(false)
  }, [ariaLabel, graph.notices, shown, exportName])

  const exportPng = useCallback(async () => {
    const viewport = wrapperRef.current?.querySelector<HTMLElement>('.react-flow__viewport')
    if (!viewport) return
    const width = 1800
    const imageHeight = 1100
    const bounds = getNodesBounds(flow.getNodes())
    const transform = getViewportForBounds(bounds, width, imageHeight, 0.1, 2, 0.08)
    const background = getComputedStyle(wrapperRef.current!).getPropertyValue('--qg-wf-surface').trim() || '#ffffff'
    try {
      const dataUrl = await toPng(viewport, {
        backgroundColor: background,
        width,
        height: imageHeight,
        style: { width: `${width}px`, height: `${imageHeight}px`, transform: `translate(${transform.x}px, ${transform.y}px) scale(${transform.zoom})` },
      })
      const anchor = document.createElement('a')
      anchor.href = dataUrl
      anchor.download = `${exportName}-${new Date().toISOString().slice(0, 10)}.png`
      anchor.click()
    } catch (err) {
      console.error('[workflow-canvas] PNG export failed', err)
    }
    setExportOpen(false)
  }, [flow, exportName])

  /* ---- Detail context ---- */
  const detailContext = useMemo<DetailContext | null>(() => {
    const anchorId = selectedNode?.id
    if (!anchorId && !selectedEdge) return null
    const incoming = anchorId ? (adjacency.in.get(anchorId) ?? []).map((edge) => ({ edge, node: nodeById.get(edge.source)! })).filter((entry) => entry.node) : []
    const outgoing = anchorId ? (adjacency.out.get(anchorId) ?? []).map((edge) => ({ edge, node: nodeById.get(edge.target)! })).filter((entry) => entry.node) : []
    return {
      nodeById,
      incoming,
      outgoing,
      upstreamCount: anchorId ? traverse(adjacency, anchorId, 'upstream').nodeIds.size - 1 : 0,
      downstreamCount: anchorId ? traverse(adjacency, anchorId, 'downstream').nodeIds.size - 1 : 0,
      select: (nodeId: string) => {
        setSelection({ kind: 'node', id: nodeId })
        onSelectNode?.(nodeById.get(nodeId) ?? null)
        centerOn(nodeId)
      },
    }
  }, [selectedNode, selectedEdge, adjacency, nodeById, onSelectNode, centerOn])

  const explanation = useMemo(
    () => (tracedPath && explainPath ? explainPath(tracedPath, nodeById) : null),
    [tracedPath, explainPath, nodeById],
  )

  const hasGroups = graph.groups.length > 0
  const allCollapsed = hasGroups && graph.groups.every((group) => collapsedSet.has(group.id))
  const showEmpty = status !== 'loading' && status !== 'error' && graph.nodes.length === 0
  const showLoading = status === 'loading' && graph.nodes.length === 0
  const showError = status === 'error' && graph.nodes.length === 0

  return (
    <div ref={wrapperRef} className="qg-wf" style={{ height: `min(${height}px, 82vh)` }} role="region" aria-label={ariaLabel}>
      {/* Toolbar */}
      <div className="qg-wf__toolbar" role="toolbar" aria-label={`${ariaLabel} controls`}>
        <label className="qg-wf__find">
          <span className="sr-only">Find in map</span>
          <Search aria-hidden="true" />
          <input
            value={find}
            onChange={(event) => setFind(event.target.value)}
            onKeyDown={(event) => { if (event.key === 'Enter') { event.preventDefault(); stepMatch(event.shiftKey ? -1 : 1) } }}
            placeholder="Find vendor, certificate, algorithm…"
          />
          {term.length >= 2 && <span className="qg-wf__find-count" aria-live="polite">{matches.length ? `${matchIndex + 1}/${matches.length}` : '0'}</span>}
        </label>
        {toolbarExtras}
        <span className="qg-wf__spacer" />
        <div className="qg-wf__toolbar-group">
          <ToolButton label="Zoom out" icon={ZoomOut} onClick={() => void flow.zoomOut({ duration: 160 })} />
          <ToolButton label="Zoom in" icon={ZoomIn} onClick={() => void flow.zoomIn({ duration: 160 })} />
          <ToolButton label="Fit to view" icon={Maximize2} onClick={() => void flow.fitView({ padding: 0.14, duration: reduceMotion ? 0 : 320 })} />
          <ToolButton label="Reset layout" icon={RotateCcw} onClick={() => { setManual({}); setIsolate(false); void flow.fitView({ padding: 0.14, duration: 0 }) }} />
        </div>
        <div className="qg-wf__toolbar-group">
          <ToolButton label="Edge labels" icon={Tag} text="Labels" pressed={showLabels} onClick={() => setShowLabels((value) => !value)} />
          <ToolButton label="Evidence badges" icon={BadgeCheck} text="Evidence" pressed={showBadges} onClick={() => setShowBadges((value) => !value)} />
          <ToolButton label="Show inferred relationships" icon={Waypoints} text="Inferred" pressed={showInferred} onClick={() => setShowInferred((value) => !value)} />
          {hasGroups && (
            <ToolButton
              label={allCollapsed ? 'Expand all groups' : 'Collapse all groups'}
              icon={allCollapsed ? ChevronsUpDown : ChevronsDownUp}
              onClick={() => setGroupOverrides(Object.fromEntries(graph.groups.map((group) => [group.id, !allCollapsed])))}
            />
          )}
          {enableTrace && (
            <ToolButton label="Trace trust path" icon={Route} text="Trace" pressed={trace.active}
              onClick={() => setTrace((current) => (current.active ? { active: false, from: null, to: null } : { active: true, from: selectedNode?.id ?? null, to: null }))} />
          )}
        </div>
        <div className="qg-wf__toolbar-group" style={{ position: 'relative' }}>
          <ToolButton label="Legend" icon={Info} pressed={legendOpen} onClick={() => setLegendOpen((value) => !value)} />
          <ToolButton label="Export graph" icon={Download} pressed={exportOpen} disabled={!shown.nodes.length} onClick={() => setExportOpen((value) => !value)} />
          {exportOpen && (
            <div className="qg-wf__panel" style={{ top: 'calc(100% + 6px)', right: 0, padding: 6, gap: 4, minWidth: 170, zIndex: 20 }}>
              <button type="button" className="qg-wf__link" onClick={exportJson}>Graph data (JSON)</button>
              <button type="button" className="qg-wf__link" onClick={() => void exportPng()}>Image (PNG)</button>
            </div>
          )}
        </div>
        <span className="font-mono text-[9.5px]" style={{ color: 'var(--qg-wf-muted)' }} aria-live="polite">
          {shown.nodes.length} nodes · {shown.edges.length} links
        </span>
      </div>

      {graph.notices.length > 0 && (
        <div className="qg-wf__notices" role="status">
          {graph.notices.map((notice) => <span key={notice}>⚠ {notice}</span>)}
        </div>
      )}

      <div className="qg-wf__stage">
        <ReactFlow<CanvasNode, FlowEdge>
          nodes={canvasNodes}
          edges={flowEdges}
          fitView={!mountedWithFocus.current}
          fitViewOptions={{ padding: 0.12, maxZoom: 1.05 }}
          onInit={handleInit}
          nodeTypes={NODE_TYPES}
          edgeTypes={EDGE_TYPES}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onPaneClick={clearSelection}
          nodesConnectable={false}
          elementsSelectable
          minZoom={0.15}
          maxZoom={2.2}
          panOnScroll
          zoomOnDoubleClick={false}
          selectionOnDrag={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--qg-wf-edge)" />
          {shown.nodes.length > 10 && (
            <MiniMap
              pannable
              zoomable
              position="bottom-right"
              nodeStrokeWidth={0}
              nodeBorderRadius={4}
              maskColor="color-mix(in srgb, var(--qg-wf-canvas) 70%, transparent)"
              nodeColor={(node) => (node.type === 'workflow' ? STATUS_META[(node.data as { node: WorkflowNode }).node.status].color : 'transparent')}
              style={{ width: 150, height: 96, right: selection && !trace.active ? 390 : 10 }}
              ariaLabel="Map overview"
            />
          )}
        </ReactFlow>

        {/* States */}
        {showLoading && (
          <div className="qg-wf__overlay" aria-busy="true">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 160px)', gap: 18 }} aria-hidden="true">
              {Array.from({ length: 8 }).map((_, index) => <div key={index} className="qg-wf__skeleton" style={{ height: 72 }} />)}
            </div>
            <span className="sr-only">Building the relationship map…</span>
          </div>
        )}
        {showError && (
          <div className="qg-wf__overlay" role="alert">
            <div className="qg-wf__overlay-card">
              <div className="qg-wf__section-title" style={{ color: 'var(--qg-danger-text, #dc2626)' }}>Map unavailable</div>
              <p className="qg-wf__text">The relationship data could not be loaded, so nothing is drawn rather than an empty map being shown as fact.</p>
              {error && <p className="qg-wf__text-muted" style={{ marginTop: 6, fontFamily: 'ui-monospace, monospace' }}>{error}</p>}
              {onRetry && <button type="button" className="qg-wf__btn qg-wf__btn--primary" style={{ marginTop: 12 }} onClick={onRetry}>Retry</button>}
            </div>
          </div>
        )}
        {showEmpty && (
          <div className="qg-wf__overlay">
            <div className="qg-wf__overlay-card">
              <Network className="mx-auto h-7 w-7" style={{ color: 'var(--qg-wf-muted)' }} aria-hidden="true" />
              <p className="qg-wf__text" style={{ marginTop: 8, fontWeight: 800, color: 'var(--qg-wf-text)' }}>{empty.title}</p>
              <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>{empty.detail}</p>
              {empty.cta && <a className="qg-wf__link qg-wf__link--primary" style={{ marginTop: 12 }} href={empty.cta.href}>{empty.cta.label}</a>}
            </div>
          </div>
        )}

        {/* Trace panel */}
        {trace.active && (
          <section className="qg-wf__panel qg-wf__trace" aria-label="Trace trust path" aria-live="polite">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
              <div className="qg-wf__section-title" style={{ margin: 0 }}>Trace path</div>
              <button type="button" className="qg-wf__btn" aria-label="Exit trace" onClick={() => setTrace({ active: false, from: null, to: null })}><X className="h-3.5 w-3.5" /></button>
            </div>
            {!trace.from && <p className="qg-wf__text">Select the <b>first</b> node — for example a root CA or a vendor.</p>}
            {trace.from && !trace.to && (
              <p className="qg-wf__text">From <b>{nodeById.get(trace.from)?.label ?? '—'}</b>. Now select the node to trace to.</p>
            )}
            {trace.from && trace.to && !tracedPath && (
              <p className="qg-wf__text">No known relationship connects <b>{nodeById.get(trace.from)?.label}</b> and <b>{nodeById.get(trace.to)?.label}</b>. They sit in disconnected components of the graph.</p>
            )}
            {tracedPath && (
              <>
                {explanation && (
                  <div>
                    <StatusPill
                      status={explanation.verdict === 'trusted' ? 'verified' : explanation.verdict === 'untrusted' ? 'critical' : 'unknown'}
                      label={explanation.verdict === 'trusted' ? 'Trusted' : explanation.verdict === 'untrusted' ? 'Untrusted' : 'Unknown'}
                    />
                    <p className="qg-wf__text" style={{ marginTop: 6 }}>{explanation.summary}</p>
                    <ul className="qg-wf__list" style={{ marginTop: 6 }}>
                      {explanation.reasons.map((reason, index) => (
                        <li key={index} className="qg-wf__legend-row" style={{ alignItems: 'flex-start', '--qg-wf-status': STATUS_META[reason.status].color } as CSSProperties}>
                          <StatusGlyph status={reason.status} /><span>{reason.text}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div>
                  <div className="qg-wf__section-title">Hops ({tracedPath.edges.length}){tracedPath.directed ? '' : ' · undirected'}</div>
                  <ol className="qg-wf__list">
                    {tracedPath.nodeIds.map((id, index) => {
                      const node = nodeById.get(id)
                      const edge = tracedPath.edges[index]
                      return (
                        <li key={id}>
                          <button type="button" className="qg-wf__row" onClick={() => centerOn(id)}>
                            <span className="qg-wf-glyph" style={{ '--qg-wf-status': STATUS_META[node?.status ?? 'unknown'].color } as CSSProperties}>{STATUS_META[node?.status ?? 'unknown'].glyph}</span>
                            <span className="qg-wf__row-main"><span className="qg-wf__row-kicker">{node?.kindLabel}</span><span style={{ display: 'block', fontWeight: 700 }}>{node?.label ?? id}</span></span>
                          </button>
                          {edge && <div className="qg-wf__text-muted" style={{ padding: '2px 0 2px 14px' }}>↓ {edge.label} · {PROVENANCE_LABEL[edge.provenance]}</div>}
                        </li>
                      )
                    })}
                  </ol>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button type="button" className="qg-wf__link" onClick={() => setTrace((current) => ({ active: true, from: current.to, to: current.from }))}>Reverse</button>
                  <button type="button" className="qg-wf__link" onClick={() => setTrace({ active: true, from: null, to: null })}>New trace</button>
                </div>
              </>
            )}
          </section>
        )}

        {/* Legend */}
        {legendOpen && (
          <section className="qg-wf__panel qg-wf__legend" aria-label="Legend">
            <div className="qg-wf__section-title" style={{ margin: 0 }}>Status</div>
            {(Object.keys(STATUS_META) as WorkflowStatus[]).map((key) => (
              <div key={key} className="qg-wf__legend-row" style={{ '--qg-wf-status': STATUS_META[key].color } as CSSProperties}>
                <StatusGlyph status={key} /><span>{graph.legend[key] ?? STATUS_META[key].label}</span>
              </div>
            ))}
            <div className="qg-wf__section-title" style={{ margin: '4px 0 0' }}>Relationships</div>
            {(Object.keys(PROVENANCE_LABEL) as EdgeProvenance[]).map((key) => (
              <div key={key} className="qg-wf__legend-row" style={{ color: 'var(--qg-wf-muted)' }}>
                <EdgeSample provenance={key} /><span style={{ color: 'var(--qg-wf-text-soft)' }}>{PROVENANCE_LABEL[key]}</span>
              </div>
            ))}
            <div className="qg-wf__section-title" style={{ margin: '4px 0 0' }}>Shapes</div>
            <p className="qg-wf__text-muted">
              {(Object.keys(SHAPE_LABEL) as WorkflowShape[]).map((shape) => `${shape === 'pill' ? 'Rounded pill' : shape === 'shield' ? 'Heavy rounded base' : shape === 'document' ? 'Folded corner' : shape === 'stack' ? 'Stacked, dashed' : 'Card'} — ${SHAPE_LABEL[shape]}`).join(' · ')}
            </p>
          </section>
        )}

        {/* Detail side panel */}
        {/* Trace mode keeps the map clear for picking; the trace panel explains the path. */}
        {!trace.active && (selectedNode || selectedEdge) && detailContext && (
          <aside className="qg-wf__panel qg-wf__detail" aria-label="Selection details">
            <div className="qg-wf__detail-head">
              <div style={{ minWidth: 0 }}>
                <div className="qg-wf__row-kicker">{selectedNode ? selectedNode.kindLabel : 'Relationship'}</div>
                <h3 style={{ margin: '2px 0 6px', fontSize: 14, fontWeight: 900, overflowWrap: 'anywhere' }}>
                  {selectedNode ? selectedNode.label : selectedEdge!.label}
                </h3>
                {selectedNode
                  ? <StatusPill status={selectedNode.status} label={selectedNode.statusLabel} />
                  : <span className="qg-wf__text-muted">{PROVENANCE_LABEL[selectedEdge!.provenance]}</span>}
              </div>
              <button type="button" className="qg-wf__btn" aria-label="Close details" onClick={clearSelection}><X className="h-4 w-4" /></button>
            </div>

            {selectedNode && (
              <div className="qg-wf__detail-actions" role="group" aria-label="Highlight relationships">
                {([
                  ['direct', 'Direct', CircleDot], ['upstream', 'Upstream', ArrowLeftToLine],
                  ['downstream', 'Downstream', ArrowRightToLine], ['both', 'Transitive', Network],
                ] as Array<[Scope, string, LucideIcon]>).map(([value, label, Icon]) => (
                  <button key={value} type="button" className="qg-wf__btn" aria-pressed={scope === value} onClick={() => setScope(value)}>
                    <Icon className="h-3 w-3" aria-hidden="true" />{label}
                  </button>
                ))}
                <button type="button" className="qg-wf__btn" aria-pressed={isolate} onClick={() => setIsolate((value) => !value)}>
                  <Focus className="h-3 w-3" aria-hidden="true" />Isolate
                </button>
                {enableTrace && (
                  <button type="button" className="qg-wf__btn" onClick={() => setTrace({ active: true, from: selectedNode.id, to: null })}>
                    <Route className="h-3 w-3" aria-hidden="true" />Trace from here
                  </button>
                )}
              </div>
            )}

            <div className="qg-wf__detail-body">
              {selectedNode && renderNodeDetail?.(selectedNode, detailContext)}
              {selectedEdge && (renderEdgeDetail?.(selectedEdge, detailContext) ?? <DefaultEdgeDetail edge={selectedEdge} nodeById={nodeById} />)}
              {selectedNode && (
                <RelationshipList context={detailContext} />
              )}
            </div>
          </aside>
        )}
      </div>
    </div>
  )
}

export function DefaultEdgeDetail({ edge, nodeById }: { edge: WorkflowEdge; nodeById: Map<string, WorkflowNode> }) {
  const source = nodeById.get(edge.source)
  const target = nodeById.get(edge.target)
  return (
    <>
      <div>
        <div className="qg-wf__section-title">Direction</div>
        <p className="qg-wf__text"><b>{source?.label ?? edge.source}</b> → {edge.label.toLowerCase()} → <b>{target?.label ?? edge.target}</b></p>
      </div>
      <dl className="qg-wf__kv">
        <div><dt>Relationship</dt><dd>{edge.label}</dd></div>
        <div><dt>Provenance</dt><dd>{PROVENANCE_LABEL[edge.provenance]}</dd></div>
        {edge.status && <div><dt>Status</dt><dd>{STATUS_META[edge.status].label}</dd></div>}
      </dl>
      <div>
        <div className="qg-wf__section-title">Evidence basis</div>
        <p className="qg-wf__text">{edge.basis}</p>
        {edge.provenance === 'inferred' && (
          <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>This relationship is inferred, not read from a stored record. Treat it as a lead to confirm.</p>
        )}
      </div>
    </>
  )
}

export function RelationshipList({ context }: { context: DetailContext }) {
  const rows = [
    ...context.incoming.map((entry) => ({ ...entry, direction: 'in' as const })),
    ...context.outgoing.map((entry) => ({ ...entry, direction: 'out' as const })),
  ]
  return (
    <div>
      <div className="qg-wf__section-title">
        Relationships · {context.upstreamCount} upstream · {context.downstreamCount} downstream
      </div>
      {rows.length === 0 ? (
        <p className="qg-wf__text-muted">No relationships recorded for this node in the current view.</p>
      ) : (
        <div className="qg-wf__list">
          {rows.map(({ edge, node, direction }) => (
            <button key={`${direction}-${edge.id}`} type="button" className="qg-wf__row" onClick={() => context.select(node.id)}>
              <span className="qg-wf-glyph" style={{ '--qg-wf-status': STATUS_META[node.status].color } as CSSProperties}>{STATUS_META[node.status].glyph}</span>
              <span className="qg-wf__row-main">
                <span className="qg-wf__row-kicker">{direction === 'in' ? '← ' : '→ '}{edge.label}{edge.provenance === 'inferred' && !/inferred/i.test(edge.label) ? ' (inferred)' : ''}</span>
                <span style={{ display: 'block', fontWeight: 700 }}>{node.label}</span>
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

/** Key/value grid for side-panel facts. */
export function DetailFacts({ items }: { items: Array<[string, ReactNode, boolean?]> }) {
  return (
    <dl className="qg-wf__kv">
      {items.map(([label, value, mono]) => (
        <div key={label}><dt>{label}</dt><dd className={mono ? 'is-mono' : undefined}>{value}</dd></div>
      ))}
    </dl>
  )
}

export function DetailSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <div className="qg-wf__section-title">{title}</div>
      {children}
    </section>
  )
}

export function DetailLink({ href, children, primary, onClick }: { href?: string; children: ReactNode; primary?: boolean; onClick?: () => void }) {
  const className = `qg-wf__link${primary ? ' qg-wf__link--primary' : ''}`
  return href
    ? <a className={className} href={href}>{children}</a>
    : <button type="button" className={className} onClick={onClick}>{children}</button>
}

export default VendorTrustWorkflowCanvas
