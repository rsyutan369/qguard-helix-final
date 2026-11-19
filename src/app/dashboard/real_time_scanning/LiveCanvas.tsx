'use client'

import { memo, useCallback, useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from 'react'
import {
  Background, BackgroundVariant, BaseEdge, Controls, EdgeLabelRenderer, Handle, MarkerType, MiniMap, Position, ReactFlow,
  getBezierPath, type Edge, type EdgeProps, type Node, type NodeChange, type NodeProps, type ReactFlowInstance,
} from '@xyflow/react'
import '@xyflow/react/dist/base.css'
import {
  AlertTriangle, AppWindow, Building2, Cpu, FileBadge, Globe, Landmark, Network, Radar, Server, ShieldCheck,
  type LucideIcon,
} from 'lucide-react'
import { relationshipVerification, type LiveGraphState } from '@/lib/live-scan/graph-reducer'
import { useTheme } from '@/contexts/theme-context'
import { LANES, NODE_LANE, type LaneId, type LiveEdge, type LiveNode, type NodeKind, type NodeStatus } from '@/lib/live-scan/types'
import { EXPOSURE_LABEL, FINDING_TYPE_LABEL, SEVERITY_LABEL, SEVERITY_RANK } from '@/lib/live-scan/policy'
import type { LiveFinding } from '@/lib/live-scan/types'

/* ------------------------------------------------------------------ */
/* Vocabulary                                                          */
/* ------------------------------------------------------------------ */

export const STATUS_WORD: Record<NodeStatus, string> = {
  validated: '✓ Validated',
  observed: '● Observed',
  active: '◌ Scanning',
  exposure: '▲ Exposure',
  critical: '■ Critical',
  failed: '✕ Failed',
  unknown: '? Unknown',
}

export const STATUS_TONE: Record<NodeStatus, string> = {
  validated: 'var(--rt-green)', observed: 'var(--rt-primary)', active: 'var(--rt-cyan)', exposure: 'var(--rt-orange)',
  critical: 'var(--rt-red)', failed: 'var(--rt-red)', unknown: 'var(--rt-gray)',
}

export const KIND_LABEL: Record<NodeKind, string> = {
  scanner: 'Scanner', asset: 'Asset', address: 'IP address', endpoint: 'TLS endpoint', ca: 'Certificate authority',
  'trust-store': 'Trust anchor store', certificate: 'Certificate', algorithm: 'Algorithm', application: 'Relying application',
  vendor: 'Vendor', finding: 'Finding',
}

export const KIND_ICON: Record<NodeKind, LucideIcon> = {
  scanner: Radar, asset: Globe, address: Network, endpoint: Server, ca: Landmark, 'trust-store': ShieldCheck,
  certificate: FileBadge, algorithm: Cpu, application: AppWindow, vendor: Building2, finding: AlertTriangle,
}

/* ------------------------------------------------------------------ */
/* Incremental lane layout                                             */
/* ------------------------------------------------------------------ */

const LANE_X = 330
const SLOT_H = 160
const TOP = 96
const FINDINGS_ROWS = 14
export const MIN_CANVAS_ZOOM = 0.02
const LANE_INDEX: Record<LaneId, number> = Object.fromEntries(LANES.map((lane, index) => [lane.id, index])) as Record<LaneId, number>

interface LayoutMemory {
  positions: Map<string, { x: number; y: number }>
  occupied: Map<LaneId, Set<number>>
  measurements: Map<string, NonNullable<Node['measured']>>
}

function slotFor(y: number) { return Math.max(0, Math.round((y - TOP) / SLOT_H)) }

/**
 * Place nodes that have no position yet, in arrival order, next to the
 * already-placed node they are connected to. Existing positions never move
 * (user drags included), so the canvas never jumps while a scan streams.
 */
function placeNew(graph: LiveGraphState, memory: LayoutMemory, visible: Set<string> | null = null): void {
  // Hidden nodes take no slot until they are shown, so filters leave no gaps.
  const pending = Object.values(graph.nodes).filter((node) => !memory.positions.has(node.id) && (!visible || visible.has(node.id))).sort((a, b) => a.firstSeq - b.firstSeq)
  if (!pending.length) return
  const edges = Object.values(graph.edges)
  for (const node of pending) {
    const lane = NODE_LANE[node.kind]
    let preferred = 0
    const anchors: number[] = []
    for (const edge of edges) {
      const other = edge.source === node.id ? edge.target : edge.target === node.id ? edge.source : null
      if (!other || other === 'scanner:helix') continue
      const position = memory.positions.get(other)
      if (position) anchors.push(position.y)
    }
    if (anchors.length) preferred = lane === 'findings' ? 0 : slotFor(Math.min(...anchors))
    const taken = memory.occupied.get(lane) ?? new Set<number>()
    let slot = preferred
    while (taken.has(slot)) slot += 1
    taken.add(slot)
    memory.occupied.set(lane, taken)
    // The findings lane is rightmost, so it can wrap into extra columns
    // instead of growing into a single column taller than the rest of the map.
    if (lane === 'findings') {
      const column = Math.floor(slot / FINDINGS_ROWS)
      memory.positions.set(node.id, { x: LANE_INDEX[lane] * LANE_X + column * 268, y: TOP + (slot % FINDINGS_ROWS) * SLOT_H })
    } else {
      memory.positions.set(node.id, { x: LANE_INDEX[lane] * LANE_X, y: TOP + slot * SLOT_H })
    }
  }
}

/** Full re-layout grouped by first target — the "Auto layout" control. */
export function relayout(graph: LiveGraphState, memory: LayoutMemory, visible: Set<string> | null = null): void {
  memory.positions.clear()
  memory.occupied.clear()
  const targets = graph.meta?.targets ?? []
  const order = (node: LiveNode) => {
    const index = targets.indexOf(node.targets[0] ?? '')
    return (index < 0 ? 999 : index) * 1e6 + node.firstSeq
  }
  const sorted = { ...graph, nodes: Object.fromEntries(Object.values(graph.nodes).sort((a, b) => order(a) - order(b)).map((node, index) => [node.id, { ...node, firstSeq: index }])) }
  placeNew(sorted, memory, visible)
}

export function newLayoutMemory(): LayoutMemory {
  return { positions: new Map(), occupied: new Map(), measurements: new Map() }
}

/* ------------------------------------------------------------------ */
/* Node card                                                           */
/* ------------------------------------------------------------------ */

type CardData = {
  node: LiveNode
  dim: boolean
  selected: boolean
  isNew: boolean
  flash: boolean
  progress: { done: number; total: number; stage: string; running: boolean } | null
  findingCount: number
  primaryFinding: LiveFinding | undefined
  onSelect: (id: string) => void
}

function short(value: unknown, max = 28): string | null {
  if (value === null || value === undefined || value === '') return null
  const text = String(value)
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

function factsFor(node: LiveNode): string[] {
  const d = node.data
  const facts: Array<string | null> = []
  switch (node.kind) {
    case 'asset':
      facts.push(short(d.assetType), Array.isArray(d.addresses) ? `${d.addresses.length} address(es)` : null,
        d.scanStatus ? `Scan: ${d.scanStatus}` : null, d.owner ? `Owner: ${short(d.owner, 18)}` : 'Owner unknown',
        d.riskScore != null ? `Risk ${d.riskScore}/100` : null)
      break
    case 'endpoint':
      facts.push(short(d.tlsVersion), d.chainTrusted === true ? 'Chain trusted' : d.chainTrusted === false ? 'Chain failed' : 'Chain not validated',
        short(d.quantumVerdict, 24), d.handshakeMs != null ? `${d.handshakeMs} ms` : null)
      break
    case 'certificate':
      facts.push(short(d.publicKeyAlgorithm), short(d.signatureAlgorithm, 22),
        typeof d.daysRemaining === 'number' ? (d.daysRemaining < 0 ? 'Expired' : `${d.daysRemaining} d left`) : null,
        d.hostnameMatches === false ? 'Hostname mismatch' : null)
      break
    case 'ca':
      facts.push(short(d.caType), short(d.publicKeyAlgorithm), short(d.validationStatus, 24))
      break
    case 'algorithm':
      facts.push(short(d.classification), short(d.parameters, 26), short(d.policyResult, 30))
      break
    case 'application':
      facts.push(d.statusCode != null ? `HTTP ${d.statusCode}` : null, short(d.server, 20), d.owner ? `Owner: ${short(d.owner, 16)}` : 'Owner unknown')
      break
    case 'vendor':
      facts.push(short(d.vendorRole, 30), short(d.basis, 30))
      break
    case 'finding':
      facts.push(d.severity ? SEVERITY_LABEL[d.severity as keyof typeof SEVERITY_LABEL] : null,
        d.exposure ? EXPOSURE_LABEL[d.exposure as keyof typeof EXPOSURE_LABEL] : null, `${node.targets.length} target(s)`)
      break
    case 'address':
      facts.push(short(d.family), d.resolvedFrom ? `from ${short(d.resolvedFrom, 20)}` : null)
      break
    case 'trust-store':
      facts.push(short(d.store, 34))
      break
    default:
      break
  }
  return facts.filter((fact): fact is string => Boolean(fact)).slice(0, 4)
}

const LiveNodeCard = memo(function LiveNodeCard({ data }: NodeProps<Node<CardData>>) {
  const { node, dim, selected, isNew, flash, progress, findingCount, primaryFinding, onSelect } = data
  const Icon = KIND_ICON[node.kind]
  const classes = ['rt-node', `st-${node.status}`, `k-${node.kind}`]
  if (dim) classes.push('is-dim')
  if (selected) classes.push('is-selected')
  if (isNew) classes.push('is-new')
  if (flash) classes.push('is-flash')
  return (
    <div
      className={classes.join(' ')}
      role="button"
      tabIndex={0}
      aria-label={`${KIND_LABEL[node.kind]} ${node.label}, ${STATUS_WORD[node.status]}`}
      onKeyDown={(event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return
        event.preventDefault()
        event.stopPropagation()
        onSelect(node.id)
      }}
    >
      <Handle type="target" position={Position.Left} />
      <Handle type="source" position={Position.Right} />
      {isNew && <span className="rt-new-badge">New</span>}
      <div className="rt-node-body">
        <div className="rt-node-top">
          <span className={`rt-node-icon${node.kind === 'scanner' && progress?.running ? ' rt-scanner-radar' : ''}`}><Icon size={15} /></span>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div className="rt-node-kind">{KIND_LABEL[node.kind]}</div>
            <div className="rt-node-label" title={node.label}>{node.label}</div>
            {node.sublabel && <div className="rt-node-sub" title={node.sublabel}>{node.sublabel}</div>}
          </div>
        </div>
        {node.kind === 'scanner' && progress ? (
          <>
            <div className="rt-node-sub" style={{ marginTop: 8 }}>{progress.stage}</div>
            <div className={`rt-progress${progress.running && progress.done === 0 ? ' is-indeterminate' : ''}`}>
              <i style={{ width: `${progress.total ? Math.round((progress.done / progress.total) * 100) : 0}%` }} />
            </div>
            <div className="rt-node-facts"><span className="rt-fact">{progress.done}/{progress.total} targets processed</span></div>
          </>
        ) : (
          <div className="rt-node-facts">
            <span className="rt-status">{STATUS_WORD[node.status]}</span>
            {primaryFinding && <span className="rt-fact rt-finding-count" title={primaryFinding.title}>
              {FINDING_TYPE_LABEL[primaryFinding.type]}{findingCount > 1 ? ` +${findingCount - 1}` : ''}
            </span>}
            {factsFor(node).map((fact) => <span key={fact} className="rt-fact" title={fact}>{fact}</span>)}
          </div>
        )}
      </div>
    </div>
  )
})

const LaneHeader = memo(function LaneHeader({ data }: NodeProps<Node<{ index: number; title: string; hint: string; count: number }>>) {
  return (
    <div className="rt-lane-head">
      <b><span className="rt-lane-num">{data.index + 1}</span>{data.title} <span className="rt-mono" style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--rt-ink-muted)' }}>{data.count}</span></b>
      <span>{data.hint}</span>
    </div>
  )
})

const LaneBand = memo(function LaneBand({ data }: NodeProps<Node<{ height: number }>>) {
  return <div className="rt-lane-band" style={{ width: 276, height: data.height }} />
})

/* ------------------------------------------------------------------ */
/* Lightning edge                                                      */
/* ------------------------------------------------------------------ */

type EdgeData = { edge: LiveEdge; fresh: boolean; flowing: boolean; dim: boolean; emphasis: boolean }

export function edgeColor(edge: LiveEdge): string {
  const verification = relationshipVerification(edge)
  if (verification === 'failed' || edge.risk === 'critical') return 'var(--rt-red)'
  if (edge.risk === 'exposure') return 'var(--rt-orange)'
  if (verification === 'validated') return 'var(--rt-green)'
  if (verification === 'inferred') return 'var(--rt-gray)'
  if (verification === 'inventory') return 'var(--rt-violet)'
  return 'var(--rt-primary)'
}

const LightningEdge = memo(function LightningEdge(props: EdgeProps<Edge<EdgeData>>) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, markerEnd } = props
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, curvature: 0.32 })
  if (!data) return null
  const color = edgeColor(data.edge)
  const verification = relationshipVerification(data.edge)
  const animate = verification !== 'inferred' && (data.fresh || data.flowing || data.emphasis)
  return (
    <g className={data.dim ? 'rt-edge-dim' : undefined}>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        className={`rt-edge-base v-${verification}`}
        style={{ stroke: color, strokeOpacity: verification === 'inferred' ? 0.55 : 0.75, strokeWidth: data.emphasis ? 2.4 : 1.6 }}
      />
      {animate && !data.dim && (
        <path d={path} className={`rt-edge-flow${data.fresh || data.emphasis ? '' : ' is-slow'}`} style={{ stroke: color, color }} />
      )}
      {animate && (data.fresh || data.emphasis) && !data.dim && (
        <circle r={3.4} className="rt-edge-spark" style={{ fill: color, color }}>
          <animateMotion dur={data.fresh ? '1.1s' : '1.8s'} repeatCount="indefinite" path={path} />
        </circle>
      )}
      {data.emphasis && (
        <EdgeLabelRenderer>
          <div className="rt-edge-label" style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}>
            {data.edge.type.replace(/_/g, ' ')}{verification === 'inferred' ? ' · inferred' : ''}
          </div>
        </EdgeLabelRenderer>
      )}
    </g>
  )
})

const nodeTypes = { live: LiveNodeCard, lane: LaneHeader, band: LaneBand }
const edgeTypes = { lightning: LightningEdge }

/* ------------------------------------------------------------------ */
/* Canvas                                                              */
/* ------------------------------------------------------------------ */

export interface LiveCanvasProps {
  graph: LiveGraphState
  visible: Set<string> | null
  highlight: Set<string> | null
  selectedId: string | null
  selectedEdgeId: string | null
  flashId: string | null
  newSinceSeq: number
  memory: LayoutMemory
  layoutVersion: number
  activeTargets: string[]
  running: boolean
  onInit: (instance: ReactFlowInstance) => void
  onSelectNode: (id: string | null) => void
  onSelectEdge: (id: string) => void
  onExpand: (id: string) => void
  onContext: (id: string, x: number, y: number) => void
  onHover: (id: string | null, x: number, y: number) => void
  /** The user panned or zoomed — follow-live mode yields to them. */
  onUserMove: () => void
}

export const LiveCanvas = memo(function LiveCanvas(props: LiveCanvasProps) {
  const {
    graph, visible, highlight, selectedId, selectedEdgeId, flashId, newSinceSeq, memory, layoutVersion, activeTargets, running,
    onInit, onSelectNode, onSelectEdge, onExpand, onContext, onHover, onUserMove,
  } = props
  const [nodeRevision, setNodeRevision] = useState(0)
  // SVG fills do not resolve CSS variables, so the minimap reads the theme class directly.
  const { theme, isLight: lightTheme } = useTheme()
  // Minimap and dot grid divide by the pane size; while the pane is 0×0 (hidden
  // tab, collapsed layout) they would emit NaN geometry, so they wait for a size.
  const paneRef = useRef<HTMLDivElement | null>(null)
  const [hasSize, setHasSize] = useState(false)
  useEffect(() => {
    const el = paneRef.current
    if (!el || typeof ResizeObserver === "undefined") { setHasSize(true); return }
    const observer = new ResizeObserver(([entry]) => setHasSize(entry.contentRect.width > 0 && entry.contentRect.height > 0))
    observer.observe(el)
    return () => observer.disconnect()
  }, [])
  const seenAt = useRef<Map<string, number> | null>(null)
  const [now, setNow] = useState(() => Date.now())

  // Edges present at first paint (a reopened scan) are not "fresh"; only
  // relationships verified while the page watches get the lightning burst.
  if (seenAt.current === null) {
    seenAt.current = new Map(Object.keys(graph.edges).map((id) => [id, 0]))
  }
  for (const id of seenAt.current.keys()) if (!graph.edges[id]) seenAt.current.delete(id)
  for (const id of Object.keys(graph.edges)) if (!seenAt.current.has(id)) seenAt.current.set(id, Date.now())

  const hasFresh = [...seenAt.current.values()].some((at) => at && now - at < 6500)
  useEffect(() => {
    if (!hasFresh && !running) return
    const timer = setInterval(() => setNow(Date.now()), 900)
    return () => clearInterval(timer)
  }, [hasFresh, running])

  const activeNodes = useMemo(() => {
    const set = new Set<string>()
    for (const node of Object.values(graph.nodes)) {
      if ((node.kind === 'asset' || node.kind === 'endpoint') && node.targets.some((target) => activeTargets.includes(target))) set.add(node.id)
    }
    return set
  }, [graph.nodes, activeTargets])

  const nodes = useMemo<Node[]>(() => {
    placeNew(graph, memory, visible)
    const out: Node[] = []
    const laneCounts = new Map<LaneId, number>()
    const findingsByNode = new Map<string, LiveFinding[]>()
    const findingsByTarget = new Map<string, LiveFinding[]>()
    const openFindings = Object.values(graph.findings).filter((finding) => finding.status === 'open' && finding.severity !== 'info')
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
    for (const finding of openFindings) {
      for (const id of finding.affectedNodeIds) {
        const related = findingsByNode.get(id) ?? []
        related.push(finding)
        findingsByNode.set(id, related)
      }
      for (const target of finding.affectedTargets) {
        const related = findingsByTarget.get(target) ?? []
        related.push(finding)
        findingsByTarget.set(target, related)
      }
    }
    let maxY = TOP + SLOT_H
    for (const node of Object.values(graph.nodes)) {
      if (visible && !visible.has(node.id)) continue
      laneCounts.set(NODE_LANE[node.kind], (laneCounts.get(NODE_LANE[node.kind]) ?? 0) + 1)
      const position = memory.positions.get(node.id) ?? { x: 0, y: TOP }
      maxY = Math.max(maxY, position.y + SLOT_H)
      const related = node.kind === 'asset'
        ? [...new Set(node.targets.flatMap((target) => findingsByTarget.get(target) ?? []))]
          .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
        : findingsByNode.get(node.id) ?? []
      out.push({
        id: node.id,
        type: 'live',
        position,
        measured: memory.measurements.get(node.id),
        selected: node.id === selectedId,
        focusable: false,
        data: {
          node,
          dim: Boolean(highlight && !highlight.has(node.id)),
          selected: node.id === selectedId,
          isNew: node.firstSeq > newSinceSeq,
          flash: node.id === flashId,
          findingCount: related.length,
          primaryFinding: related[0],
          progress: node.kind === 'scanner' && graph.meta
            ? { done: graph.meta.completedTargets.length + graph.meta.failedTargets.length, total: graph.meta.targets.length, stage: graph.meta.stage, running }
            : null,
          onSelect: onSelectNode,
        } satisfies CardData,
        draggable: true,
        selectable: true,
        zIndex: 2,
      })
    }
    LANES.forEach((lane, index) => {
      const headerId = `lane:${lane.id}`
      const bandId = `band:${lane.id}`
      out.push({ id: headerId, type: 'lane', position: { x: index * LANE_X - 6, y: 0 }, measured: memory.measurements.get(headerId), data: { index, title: lane.title, hint: lane.hint, count: laneCounts.get(lane.id) ?? 0 }, draggable: false, selectable: false, focusable: false, zIndex: 1 })
      out.push({ id: bandId, type: 'band', position: { x: index * LANE_X - 14, y: TOP - 18 }, measured: memory.measurements.get(bandId), data: { height: maxY - TOP + 24 }, draggable: false, selectable: false, focusable: false, zIndex: 0 })
    })
    return out
    // Node changes and explicit relayout both update the layout memory.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, visible, highlight, selectedId, flashId, newSinceSeq, running, memory, nodeRevision, layoutVersion, onSelectNode])

  const edges = useMemo<Edge[]>(() => {
    const out: Edge[] = []
    for (const edge of Object.values(graph.edges)) {
      if (visible && (!visible.has(edge.source) || !visible.has(edge.target))) continue
      if (!graph.nodes[edge.source] || !graph.nodes[edge.target]) continue
      const at = seenAt.current!.get(edge.id) ?? 0
      const emphasis = edge.id === selectedEdgeId || (selectedId !== null && (edge.source === selectedId || edge.target === selectedId))
      out.push({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: 'lightning',
        data: {
          edge,
          fresh: Boolean(at) && now - at < 6500,
          flowing: running && (activeNodes.has(edge.source) || activeNodes.has(edge.target)),
          dim: Boolean(highlight && !(highlight.has(edge.source) && highlight.has(edge.target))),
          emphasis,
        } satisfies EdgeData,
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor(edge), width: 14, height: 14 },
        zIndex: emphasis ? 3 : 1,
      })
    }
    return out
  }, [graph.edges, graph.nodes, visible, highlight, selectedEdgeId, selectedId, now, running, activeNodes])

  const onNodesChange = useCallback((changes: NodeChange[]) => {
    let changed = false
    for (const change of changes) {
      if (change.type === 'dimensions' && change.dimensions?.width && change.dimensions.height) {
        const previous = memory.measurements.get(change.id)
        if (previous?.width === change.dimensions.width && previous.height === change.dimensions.height) continue
        memory.measurements.set(change.id, change.dimensions)
        changed = true
      } else if (change.type === 'position' && change.position && memory.positions.has(change.id)) {
        memory.positions.set(change.id, change.position)
        changed = true
      }
    }
    if (changed) setNodeRevision((revision) => revision + 1)
  }, [memory])

  const onNodeMouseEnter = useCallback((event: ReactMouseEvent, node: Node) => {
    if (node.type === 'live') onHover(node.id, event.clientX, event.clientY)
  }, [onHover])
  const onNodeMouseLeave = useCallback((_: ReactMouseEvent, node: Node) => {
    if (node.type === 'live') onHover(null, 0, 0)
  }, [onHover])

  return (
    <div ref={paneRef} style={{ width: "100%", height: "100%" }}>
    <ReactFlow
      nodes={nodes}
      colorMode={theme}
      edges={edges}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      onInit={onInit}
      onNodesChange={onNodesChange}
      onNodeMouseEnter={onNodeMouseEnter}
      onNodeMouseLeave={onNodeMouseLeave}
      onNodeClick={(_, node) => { if (node.type === 'live') onSelectNode(node.id) }}
      onNodeDoubleClick={(_, node) => { if (node.type === 'live') onExpand(node.id) }}
      onNodeContextMenu={(event: ReactMouseEvent, node) => { if (node.type === 'live') { event.preventDefault(); onContext(node.id, event.clientX, event.clientY) } }}
      onEdgeClick={(_, edge) => onSelectEdge(edge.id)}
      onPaneClick={() => onSelectNode(null)}
      onNodeDragStart={onUserMove}
      onMoveStart={(event) => { if (event) onUserMove() }}
      minZoom={MIN_CANVAS_ZOOM}
      maxZoom={1.8}
      nodesConnectable={false}
      deleteKeyCode={null}
      elementsSelectable
      proOptions={{ hideAttribution: true }}
    >
      {hasSize && <Background variant={BackgroundVariant.Dots} gap={22} size={1.3} color="var(--rt-grid)" />}
      {/* The canvas toolbar provides Fit with bounds for newly arrived cards. */}
      <Controls showInteractive={false} showFitView={false} position="bottom-left" onZoomIn={onUserMove} onZoomOut={onUserMove} />
      {hasSize && Object.keys(graph.nodes).length > 0 && <MiniMap
        style={{ width: 150, height: 96 }}
        pannable
        zoomable
        position="bottom-right"
        nodeStrokeWidth={2}
        nodeColor={(node) => {
          const live = (node.data as CardData | undefined)?.node
          if (!live) return 'transparent'
          return ({ validated: '#16A34A', observed: '#2563EB', active: '#38d6f5', exposure: '#EA7600', critical: '#DC2626', failed: '#DC2626', unknown: '#64748B' } as Record<NodeStatus, string>)[live.status]
        }}
        maskColor={lightTheme ? "rgba(15,35,69,0.08)" : "rgba(5,10,22,0.55)"}
        bgColor={lightTheme ? "#ffffff" : "#0a1226"}
      />}
    </ReactFlow>
    </div>
  )
})

