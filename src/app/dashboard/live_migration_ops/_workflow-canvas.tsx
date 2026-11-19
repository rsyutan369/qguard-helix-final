/**
 * Four-agent workflow canvas — Collector → Scanner → Patcher → Migration Operator.
 *
 * Renders `AgentWorkflowModel` (src/lib/migration/agent-workflow.ts) and owns
 * only presentation state. The four stage cards form the top row; every agent
 * the tenant has deployed for a stage hangs beneath it as a branch of a
 * process tree, carrying its OWN state (`fleet.agents[]` — derived per agent
 * from its frames, heartbeats and claimed jobs, never copied from the stage).
 *
 * Motion rules:
 *   • an edge's flowing dash means the model recorded the downstream stage (or,
 *     on a branch, that agent) as running — the CSS keys off `data-state`;
 *   • a handoff packet travels an edge ONLY when that edge's recorded
 *     `lastHandoffAt` changes between snapshots (never on first paint, so a
 *     page load does not replay history as if it were happening now);
 *   • everything is skipped under `prefers-reduced-motion`.
 * Wide screens get the React Flow canvas (pan / zoom / fit / full screen /
 * keyboard focus); narrow screens get the same cards stacked, which is also
 * the accessible fallback announced through the live region.
 */
import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import gsap from 'gsap'
import {
  BaseEdge,
  EdgeLabelRenderer,
  Handle,
  Position,
  ReactFlow,
  ReactFlowProvider,
  getBezierPath,
  getSmoothStepPath,
  useReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeChange,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/base.css'
import './live-workflow.css'
import { ArrowRightLeft, CheckCircle2, Crosshair, ExternalLink, Maximize2, Minimize2, Minus, Plus, Radar, Scan, ShieldAlert, XCircle } from 'lucide-react'
import type { ReportedAgentDiscovery } from '@/lib/migration/agent-discovery'
import { DiscoveryCard, DiscoveryInspector, type CanvasDiscovery } from './_workflow-discovery'
import type {
  AgentWorkflowModel,
  AgentWorkflowStatus,
  WorkflowAgentId,
  WorkflowAgentInstance,
  WorkflowAgentNode,
  WorkflowEdge,
  WorkflowEvent,
} from '@/lib/migration/agent-workflow'
import {
  AGENT_VISUAL,
  AgentCard,
  AgentInspector,
  AgentInstanceCard,
  STATUS_META,
  TONE,
  agentPresence,
  mix,
  prefersReducedMotion,
  timeAgo,
  type AgentLiveActivity,
} from './_workflow-ui'

const NODE_W = 292
const NODE_H = 318
const GAP = 168
const WORLD_W = 4 * NODE_W + 3 * GAP

/* Tree geometry: children are inset under their stage; the trunk drops from
   the stage card's bottom-left and branches right into each child. */
const TRUNK_X = 18
const CHILD_INSET = 36
const CHILD_W = NODE_W - CHILD_INSET
const CHILD_H = 148
const CHILD_GAP = 14
const CHILD_TOP = NODE_H + 46
const OVERFLOW_H = 40
const DISCOVERY_H = 82
const DISCOVERIES_PER_STAGE = 8
/** Agents drawn per stage. Beyond this, the most urgent are kept and the rest summarised. */
const MAX_ROWS = 6
const INLINE_MIN_H = 392
const INLINE_MAX_H = 860
/* Fit padding in screen px: the bottom keeps the view toolbar (bottom-right)
   clear of the tree; in full screen the top keeps the title clear. */
const FIT_PAD = { x: 28, top: 28, topExpanded: 48, bottom: 56 }
const fitPadding = (expanded: boolean) => ({
  left: `${FIT_PAD.x}px`,
  right: `${FIT_PAD.x}px`,
  top: `${expanded ? FIT_PAD.topExpanded : FIT_PAD.top}px`,
  bottom: `${FIT_PAD.bottom}px`,
}) as const

/** Which agents earn a visible slot when a stage has more than MAX_ROWS. */
const URGENCY: Record<AgentWorkflowStatus, number> = {
  failed: 0, blocked: 1, retrying: 2, running: 3, awaiting_approval: 4, queued: 5,
  paused: 6, waiting: 7, rolled_back: 8, completed: 8, idle: 9, cancelled: 10,
}

const byName = (a: WorkflowAgentInstance, b: WorkflowAgentInstance) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id)

/**
 * The agents drawn under a stage, in stable name order so cards do not jump
 * between snapshots. Over MAX_ROWS, the most urgent MAX_ROWS - 1 are kept and
 * the overflow row summarises the rest.
 */
function visibleAgents(agents: WorkflowAgentInstance[]): { shown: WorkflowAgentInstance[]; hidden: WorkflowAgentInstance[] } {
  if (agents.length <= MAX_ROWS) return { shown: [...agents].sort(byName), hidden: [] }
  const ranked = [...agents].sort((a, b) => URGENCY[a.state] - URGENCY[b.state] || Number(b.online) - Number(a.online) || byName(a, b))
  return { shown: ranked.slice(0, MAX_ROWS - 1).sort(byName), hidden: ranked.slice(MAX_ROWS - 1) }
}

/** Branch styling uses the handoff edges' vocabulary, keyed off the agent's own state. */
function branchState(state: AgentWorkflowStatus, online: boolean) {
  if (state === 'running' || state === 'retrying') return 'active'
  if (state === 'failed') return 'failed'
  if (state === 'blocked') return 'blocked'
  if (state === 'completed' || state === 'rolled_back') return 'completed'
  return online ? 'waiting' : 'idle'
}

interface AgentNodeData extends Record<string, unknown> {
  node: WorkflowAgentNode
  now: number
  selected: boolean
  highlighted: boolean
  onSelect: (id: WorkflowAgentId) => void
  onOutput: (id: WorkflowAgentId) => void
  /** Deployed / online tally shown on the trunk; null when no agent is deployed. */
  fleet: { deployed: number; online: number } | null
}

interface InstanceNodeData extends Record<string, unknown> {
  instance: WorkflowAgentInstance
  live: AgentLiveActivity | undefined
  now: number
  selected: boolean
  onSelectInstance: (instance: WorkflowAgentInstance) => void
}

interface OverflowNodeData extends Record<string, unknown> {
  role: WorkflowAgentId
  hidden: number
  hiddenOnline: number
}

interface FlowEdgeData extends Record<string, unknown> {
  edge: WorkflowEdge
  color: string
  now: number
  /** Increments each time a NEW recorded handoff arrives on this edge. */
  handoffSeq: number
  /**
   * Which handoff each edge has already animated. Owned by the canvas, not the
   * edge: React Flow remounts an edge when its nodes re-measure, and a
   * per-edge ref would take the new handoff as its baseline and never play it.
   */
  played: Record<string, number>
}

interface BranchEdgeData extends Record<string, unknown> {
  discovery?: boolean
  state: string
  color: string
}

type AgentFlowNode = Node<AgentNodeData, 'agent'>
type InstanceFlowNode = Node<InstanceNodeData, 'instance'>
type OverflowFlowNode = Node<OverflowNodeData, 'overflow'>
type DiscoveryFlowNode = Node<{
  item: CanvasDiscovery
  selected: boolean
  onSelect: (id: string) => void
}, 'discovery'>
type CanvasNode = AgentFlowNode | InstanceFlowNode | OverflowFlowNode | DiscoveryFlowNode
type AgentFlowEdge = Edge<FlowEdgeData, 'handoff'>
type BranchFlowEdge = Edge<BranchEdgeData, 'branch'>
type CanvasEdge = AgentFlowEdge | BranchFlowEdge

const AgentNode = memo(function AgentNode({ data }: NodeProps<AgentFlowNode>) {
  const visual = AGENT_VISUAL[data.node.id]
  return (
    <div className="relative" style={{ width: NODE_W, height: NODE_H }}>
      <Handle id="prev" type="target" position={Position.Left} isConnectable={false} className="qg-lw-handle" />
      <AgentCard
        node={data.node}
        now={data.now}
        selected={data.selected}
        highlighted={data.highlighted}
        onSelect={() => data.onSelect(data.node.id)}
        onOutput={() => data.onOutput(data.node.id)}
      />
      <Handle id="next" type="source" position={Position.Right} isConnectable={false} className="qg-lw-handle" />
      {data.fleet && (
        <>
          <Handle id="fleet" type="source" position={Position.Bottom} isConnectable={false} className="qg-lw-handle" style={{ left: TRUNK_X }} />
          {/* Trunk root: the joint the deployed agents branch from. */}
          <span className="qg-lw-trunk-root" style={{ left: TRUNK_X, background: visual.color, boxShadow: `0 0 10px ${visual.glow}` }} aria-hidden="true" />
          <div
            className="pointer-events-none absolute flex items-center gap-1.5 whitespace-nowrap rounded-full border bg-[var(--lw-screen)] px-2 py-0.5 text-[10px] font-bold text-[color:var(--lw-ink-soft)]"
            style={{ left: TRUNK_X + 14, top: NODE_H + 12, borderColor: mix(visual.color, 30) }}
          >
            <span style={{ color: visual.color }}>{data.fleet.deployed} deployed</span>
            <span className="text-[color:var(--lw-ink-muted)]">·</span>
            <span style={{ color: data.fleet.online ? TONE.green : 'var(--lw-slate)' }}>{data.fleet.online} online</span>
          </div>
        </>
      )}
    </div>
  )
})

const InstanceNode = memo(function InstanceNode({ data }: NodeProps<InstanceFlowNode>) {
  return (
    <div style={{ width: CHILD_W, height: CHILD_H }}>
      <Handle id="in" type="target" position={Position.Left} isConnectable={false} className="qg-lw-handle" />
      <AgentInstanceCard
        instance={data.instance}
        live={data.live}
        now={data.now}
        selected={data.selected}
        onSelect={() => data.onSelectInstance(data.instance)}
      />
    </div>
  )
})

const OverflowNode = memo(function OverflowNode({ data }: NodeProps<OverflowFlowNode>) {
  const visual = AGENT_VISUAL[data.role]
  return (
    <div style={{ width: CHILD_W, height: OVERFLOW_H }}>
      <Handle id="in" type="target" position={Position.Left} isConnectable={false} className="qg-lw-handle" />
      <a
        href="/downloads"
        className="nodrag flex h-full items-center gap-2 rounded-xl border border-dashed bg-[var(--lw-card)] px-3 text-[11px] font-bold text-[color:var(--lw-ink-soft)] transition hover:text-[color:var(--lw-ink)]"
        style={{ borderColor: mix(visual.color, 35) }}
        title="Every deployed agent is listed in the Agent Center"
      >
        <span style={{ color: visual.color }}>+{data.hidden} more</span>
        <span className="font-semibold text-[color:var(--lw-ink-muted)]">{data.hiddenOnline} online</span>
        <span className="ml-auto inline-flex items-center gap-1 text-[color:var(--lw-ink-muted)]">Agent Center <ExternalLink className="h-3 w-3" aria-hidden="true" /></span>
      </a>
    </div>
  )
})

const DiscoveryNode = memo(function DiscoveryNode({ data }: NodeProps<DiscoveryFlowNode>) {
  return (
    <div className="h-full">
      <Handle id="in" type="target" position={Position.Left} isConnectable={false} className="qg-lw-handle" />
      <DiscoveryCard item={data.item} selected={data.selected} onSelect={data.onSelect} />
    </div>
  )
})

const EDGE_ICON = { completed: CheckCircle2, failed: XCircle, blocked: ShieldAlert } as const

const HandoffEdge = memo(function HandoffEdge(props: EdgeProps<AgentFlowEdge>) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data } = props
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, curvature: 0.25 })
  const pathRef = useRef<SVGPathElement>(null)
  const packetRef = useRef<SVGCircleElement>(null)
  const glowRef = useRef<SVGPathElement>(null)
  const lastState = useRef(data?.edge.state)
  const state = data?.edge.state ?? 'idle'
  const color = data?.color ?? TONE.cyan

  // Packet: one traversal per recorded handoff. Not killed on effect cleanup —
  // StrictMode's mount/unmount/mount would cancel it — the tween stops itself
  // if its elements leave the DOM.
  useEffect(() => {
    const seq = data?.handoffSeq ?? 0
    const played = data?.played
    if (!played || (played[id] ?? 0) >= seq) return
    played[id] = seq
    const line = pathRef.current
    const packet = packetRef.current
    if (!line || !packet || prefersReducedMotion()) return
    const length = line.getTotalLength()
    const progress = { t: 0 }
    const tween = gsap.to(progress, {
      t: 1,
      duration: 1.4,
      ease: 'power1.inOut',
      onStart: () => { gsap.set(packet, { opacity: 1 }) },
      onUpdate: () => {
        if (!line.isConnected || !packet.isConnected) {
          tween.kill()
          return
        }
        const point = line.getPointAtLength(progress.t * length)
        packet.setAttribute('cx', String(point.x))
        packet.setAttribute('cy', String(point.y))
      },
      onComplete: () => { gsap.to(packet, { opacity: 0, duration: 0.3 }) },
    })
  }, [data?.handoffSeq, data?.played, id])

  // Brief success pulse when an edge becomes completed.
  useEffect(() => {
    if (lastState.current === state) return
    lastState.current = state
    if (state !== 'completed' || !glowRef.current || prefersReducedMotion()) return
    const tween = gsap.fromTo(glowRef.current, { opacity: 0.85 }, { opacity: 0.18, duration: 1.2, ease: 'power2.out' })
    return () => { tween.kill() }
  }, [state])

  const Icon = state in EDGE_ICON ? EDGE_ICON[state as keyof typeof EDGE_ICON] : ArrowRightLeft
  const tone = state === 'failed' ? TONE.red : state === 'blocked' ? TONE.amber : state === 'completed' || state === 'active' ? color : 'var(--lw-slate)'

  return (
    <>
      <path ref={glowRef} d={path} className="qg-lw-edge qg-lw-edge--glow" data-state={state} style={{ ['--edge-color' as string]: color, stroke: tone }} />
      {/* BaseEdge supplies the hit area only; the visible line is ours so it can carry data-state. */}
      <BaseEdge id={id} path={path} interactionWidth={16} style={{ stroke: 'transparent' }} />
      <path ref={pathRef} d={path} className="qg-lw-edge qg-lw-edge--line" data-state={state} style={{ ['--edge-color' as string]: color }} />
      <circle ref={packetRef} r="5" className="qg-lw-packet" style={{ fill: color, filter: `drop-shadow(0 0 8px ${color})` }} />
      <EdgeLabelRenderer>
        <div
          className="nodrag nopan pointer-events-auto absolute"
          style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
          title={`${data?.edge.handoffDetail ?? ''}${data?.edge.lastHandoffAt ? ` · ${new Date(data.edge.lastHandoffAt).toLocaleString()}` : ''}`}
        >
          <div
            className="flex items-center gap-1.5 rounded-full border bg-[var(--lw-screen)] px-2.5 py-1 text-[10px] font-bold text-[color:var(--lw-ink)] shadow-lg"
            style={{ borderColor: `${mix(tone, 40)}`, boxShadow: state === 'active' || state === 'completed' ? `0 0 16px ${mix(tone, 27)}` : undefined }}
          >
            <Icon className="h-3 w-3" style={{ color: tone }} aria-hidden="true" />
            <span>{data?.edge.label}</span>
            {data?.edge.lastHandoffAt && <span className="font-mono font-normal text-[color:var(--lw-ink-muted)]">{timeAgo(data.edge.lastHandoffAt, data.now)}</span>}
          </div>
        </div>
      </EdgeLabelRenderer>
    </>
  )
})

/**
 * Stage → deployed agent. Every branch of a stage shares the trunk, so the
 * trunk is drawn in one neutral role tone (overlaps are invisible) and only
 * the branch's own horizontal stub carries that agent's state.
 */
const BranchEdge = memo(function BranchEdge(props: EdgeProps<BranchFlowEdge>) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data } = props
  const [trunk] = getSmoothStepPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition, borderRadius: 10, offset: 0 })
  const color = data?.color ?? TONE.cyan
  const state = data?.state ?? 'idle'
  const stub = `M ${sourceX + 10} ${targetY} L ${targetX} ${targetY}`
  return (
    <>
      <path d={trunk} className="qg-lw-trunk" style={{ stroke: mix(color, 38) }} />
      <BaseEdge id={id} path={stub} interactionWidth={12} style={{ stroke: 'transparent' }} />
      <path d={stub} className="qg-lw-edge qg-lw-edge--glow" data-state={state} style={{ ['--edge-color' as string]: color }} />
      <path d={stub} className="qg-lw-edge qg-lw-edge--branch" data-state={state} style={{ ['--edge-color' as string]: color }} />
      {data?.discovery && <path d={trunk} pathLength={1} className="qg-lw-discovery-pulse" style={{ stroke: color }} />}
      <circle cx={targetX} cy={targetY} r="3.5" className="qg-lw-branch-joint" data-state={state} style={{ ['--edge-color' as string]: color }} />
    </>
  )
})

const NODE_TYPES = { agent: AgentNode, instance: InstanceNode, overflow: OverflowNode, discovery: DiscoveryNode }
const EDGE_TYPES = { handoff: HandoffEdge, branch: BranchEdge }

export interface WorkflowCanvasProps {
  model: AgentWorkflowModel
  now: number
  selectedAgent: WorkflowAgentId
  highlightedAgent: WorkflowAgentId | null
  onSelect: (id: WorkflowAgentId) => void
  onOutput: (id: WorkflowAgentId) => void
  /** Agent-bus frames newer than the snapshot, per agent id (SSE `agent-event`). */
  liveByAgent?: Record<string, AgentLiveActivity>
  /** Snapshot events plus live frames — the inspector lists the selected agent's own. */
  events?: WorkflowEvent[]
  discoveries?: ReportedAgentDiscovery[]
  discoveriesConnected?: boolean
  discoveriesPlanScoped?: boolean
}

interface InnerProps extends WorkflowCanvasProps {
  selectedInstance: WorkflowAgentInstance | null
  onSelectInstance: (instance: WorkflowAgentInstance | null) => void
  discoveriesByStage: Map<WorkflowAgentId, CanvasDiscovery[]>
  selectedDiscovery: CanvasDiscovery | null
  onSelectDiscovery: (id: string | null) => void
}

function CanvasInner({
  model, now, selectedAgent, highlightedAgent, onSelect, onOutput, liveByAgent, events, selectedInstance,
  onSelectInstance, discoveriesByStage, selectedDiscovery, onSelectDiscovery, discoveriesConnected, discoveriesPlanScoped,
}: InnerProps) {
  const flow = useReactFlow<CanvasNode, CanvasEdge>()
  const handoffSeqs = useRef<Record<string, { at: string | null; seq: number }>>({})
  const played = useRef<Record<string, number>>({})

  /* ── tree layout ───────────────────────────────────────────────────── */
  const tree = useMemo(() => model.nodes.map((node) => ({ node, ...visibleAgents(node.fleet.agents) })), [model.nodes])
  const treeHeight = useMemo(() => {
    let height = NODE_H
    for (const branch of tree) {
      if (!branch.shown.length) continue
      const rows = branch.shown.length * (CHILD_H + CHILD_GAP) - CHILD_GAP + (branch.hidden.length ? CHILD_GAP + OVERFLOW_H : 0)
      height = Math.max(height, CHILD_TOP + rows)
    }
    return height
  }, [tree])
  // Changes only when an agent is enrolled / revoked or the overflow changes —
  // the cue to re-frame. A state change inside the same shape never re-frames.
  const layoutKey = tree.map((branch) => `${branch.shown.map((agent) => agent.id).join(',')}+${branch.hidden.length}`).join('|')

  /* ── full screen ──────────────────────────────────────────────────────
     `expanded` pins the stage over the viewport (fixed, opaque). The browser
     Fullscreen API is layered on top when available so the canvas also gets
     the whole monitor; if it is refused (iframe, iOS) the pinned stage alone
     still fills the window. Either way the graph is re-framed once the stage
     has actually changed size. */
  const stageRef = useRef<HTMLDivElement>(null)
  const [expanded, setExpanded] = useState(false)
  const [stageWidth, setStageWidth] = useState(0)
  const [followLive, setFollowLive] = useState(false)

  const enterFullScreen = useCallback(() => {
    setExpanded(true)
    const stage = stageRef.current
    if (stage && document.fullscreenEnabled && !document.fullscreenElement) {
      stage.requestFullscreen({ navigationUI: 'hide' }).catch(() => undefined)
    }
    requestAnimationFrame(() => stageRef.current?.focus({ preventScroll: true }))
  }, [])

  const exitFullScreen = useCallback((): Promise<unknown> => {
    setExpanded(false)
    if (document.fullscreenElement && document.fullscreenElement === stageRef.current) {
      return document.exitFullscreen().catch(() => undefined)
    }
    return Promise.resolve()
  }, [])

  const toggleFullScreen = useCallback(() => {
    if (expanded) void exitFullScreen()
    else enterFullScreen()
  }, [enterFullScreen, exitFullScreen, expanded])

  const expandedRef = useRef(expanded)
  expandedRef.current = expanded
  const fit = useCallback((duration = 250) => {
    requestAnimationFrame(() => { void flow.fitView({ padding: fitPadding(expandedRef.current), duration }) })
  }, [flow])

  // Re-frame whenever the stage actually changes size (full screen, window
  // resize, the tree growing). Deferred a frame so React Flow has recorded its
  // new dimensions before fitView reads them.
  useEffect(() => {
    const stage = stageRef.current
    if (!stage || typeof ResizeObserver === 'undefined') return
    let last = { w: 0, h: 0 }
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      if (Math.abs(width - last.w) < 1 && Math.abs(height - last.h) < 1) return
      last = { w: width, h: height }
      setStageWidth(width)
      fit()
    })
    observer.observe(stage)
    return () => observer.disconnect()
  }, [fit])

  // An agent enrolled or revoked changes the tree's shape — re-frame even if
  // the stage size stays the same (e.g. in full screen).
  const firstLayout = useRef(true)
  useEffect(() => {
    if (firstLayout.current) {
      firstLayout.current = false
      return
    }
    fit()
  }, [fit, layoutKey])

  // Esc in browser full screen is consumed by the browser, which only fires
  // `fullscreenchange` — follow it so the pinned stage does not linger.
  useEffect(() => {
    const onChange = () => {
      if (!document.fullscreenElement && expanded) setExpanded(false)
    }
    document.addEventListener('fullscreenchange', onChange)
    return () => document.removeEventListener('fullscreenchange', onChange)
  }, [expanded])

  // While pinned: Esc closes an open agent inspector first, then exits (when
  // the browser did not take it); the dashboard content layer is lifted above
  // the sidebar and the page stops scrolling.
  useEffect(() => {
    if (!expanded) return
    const root = document.documentElement
    root.classList.add('qg-lw-fullscreen')
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      event.preventDefault()
      if (selectedDiscovery) onSelectDiscovery(null)
      else if (selectedInstance) onSelectInstance(null)
      else void exitFullScreen()
    }
    document.addEventListener('keydown', onKey)
    return () => {
      root.classList.remove('qg-lw-fullscreen')
      document.removeEventListener('keydown', onKey)
    }
  }, [exitFullScreen, expanded, selectedDiscovery, onSelectDiscovery, selectedInstance, onSelectInstance])

  // Leaving the page while in full screen must not strand the browser there.
  useEffect(() => () => {
    if (document.fullscreenElement && document.fullscreenElement === stageRef.current) {
      document.exitFullscreen().catch(() => undefined)
    }
  }, [])

  // "Output" scrolls to the insights panel below the canvas, which is hidden
  // while the canvas fills the screen — leave full screen first.
  const showOutput = useCallback((id: WorkflowAgentId) => {
    if (!expanded) {
      onOutput(id)
      return
    }
    void exitFullScreen().then(() => requestAnimationFrame(() => onOutput(id)))
  }, [exitFullScreen, expanded, onOutput])

  const selectInstance = useCallback((instance: WorkflowAgentInstance) => {
    onSelectDiscovery(null)
    onSelectInstance(instance)
    onSelect(instance.role)
  }, [onSelect, onSelectDiscovery, onSelectInstance])

  const inspectDiscovery = useCallback((id: string) => {
    onSelectInstance(null)
    onSelectDiscovery(id)
  }, [onSelectDiscovery, onSelectInstance])

  const discoveryNodes = useMemo<DiscoveryFlowNode[]>(() => tree.flatMap(({ node, shown, hidden }, index) => {
    const x = index * (NODE_W + GAP) + CHILD_INSET
    const top = CHILD_TOP + shown.length * (CHILD_H + CHILD_GAP) + (hidden.length ? OVERFLOW_H + CHILD_GAP : 0)
    return (discoveriesByStage.get(node.id) || []).map((item, row) => ({
      id: `discovery:${item.id}`,
      type: 'discovery' as const,
      position: { x, y: top + row * (DISCOVERY_H + CHILD_GAP) },
      width: CHILD_W,
      height: DISCOVERY_H,
      draggable: false,
      selectable: false,
      focusable: false,
      data: { item, selected: item.id === selectedDiscovery?.id, onSelect: inspectDiscovery },
    }))
  }), [discoveriesByStage, inspectDiscovery, selectedDiscovery?.id, tree])
  const latestDiscovery = useMemo(() => discoveryNodes.reduce<DiscoveryFlowNode | null>((latest, node) =>
    !latest || node.data.item.order > latest.data.item.order ? node : latest, null), [discoveryNodes])
  const latestId = latestDiscovery?.id
  const focusLatest = useCallback(() => {
    if (!latestId) return
    const node = flow.getNode(latestId)
    if (!node) return
    void flow.setCenter(node.position.x + CHILD_W / 2, node.position.y + DISCOVERY_H / 2, {
      zoom: Math.max(0.8, flow.getZoom()),
      duration: prefersReducedMotion() ? 0 : 220,
    })
  }, [flow, latestId])
  useEffect(() => {
    if (!followLive || !latestId || selectedDiscovery || selectedInstance) return
    const frame = requestAnimationFrame(focusLatest)
    return () => cancelAnimationFrame(frame)
  }, [focusLatest, followLive, latestId, selectedDiscovery, selectedInstance])

  /* ── graph ─────────────────────────────────────────────────────────── */

  // Count NEW recorded handoffs per edge. The first observation only seeds the
  // baseline, so loading the page never fires a packet for an old handoff.
  const seqFor = useCallback((edge: WorkflowEdge) => {
    const record = handoffSeqs.current[edge.id]
    if (!record) {
      handoffSeqs.current[edge.id] = { at: edge.lastHandoffAt, seq: 0 }
      return 0
    }
    if (edge.lastHandoffAt && edge.lastHandoffAt !== record.at && (!record.at || Date.parse(edge.lastHandoffAt) > Date.parse(record.at))) {
      record.at = edge.lastHandoffAt
      record.seq += 1
    }
    return record.seq
  }, [])

  const nodes = useMemo<CanvasNode[]>(() => {
    const out: CanvasNode[] = []
    tree.forEach(({ node, shown, hidden }, index) => {
      const x = index * (NODE_W + GAP)
      const deployed = node.fleet.agents
      out.push({
        id: node.id,
        type: 'agent',
        position: { x, y: 0 },
        width: NODE_W,
        height: NODE_H,
        draggable: false,
        selectable: true,
        focusable: true,
        ariaLabel: `${node.label}: ${STATUS_META[node.status].label}. ${node.currentTask}`,
        data: {
          node,
          now,
          selected: node.id === selectedAgent,
          highlighted: node.id === highlightedAgent,
          onSelect,
          onOutput: showOutput,
          fleet: deployed.length
            ? { deployed: deployed.length, online: deployed.filter((agent) => agentPresence(agent, liveByAgent?.[agent.id], now).online).length }
            : null,
        },
      })
      shown.forEach((instance, row) => {
        out.push({
          id: `agent:${instance.id}`,
          type: 'instance',
          position: { x: x + CHILD_INSET, y: CHILD_TOP + row * (CHILD_H + CHILD_GAP) },
          width: CHILD_W,
          height: CHILD_H,
          draggable: false,
          selectable: false,
          focusable: true,
          ariaLabel: `${node.label} agent ${instance.name}: ${STATUS_META[instance.state].label}. ${instance.currentTask}`,
          data: { instance, live: liveByAgent?.[instance.id], now, selected: instance.id === selectedInstance?.id, onSelectInstance: selectInstance },
        })
      })
      if (hidden.length) {
        out.push({
          id: `overflow:${node.id}`,
          type: 'overflow',
          position: { x: x + CHILD_INSET, y: CHILD_TOP + shown.length * (CHILD_H + CHILD_GAP) },
          width: CHILD_W,
          height: OVERFLOW_H,
          draggable: false,
          selectable: false,
          focusable: false,
          data: { role: node.id, hidden: hidden.length, hiddenOnline: hidden.filter((agent) => agentPresence(agent, liveByAgent?.[agent.id], now).online).length },
        })
      }
    })
    return [...out, ...discoveryNodes]
  }, [discoveryNodes, highlightedAgent, liveByAgent, now, onSelect, selectInstance, selectedAgent, selectedInstance, showOutput, tree])

  const edges = useMemo<CanvasEdge[]>(() => {
    const out: CanvasEdge[] = model.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      sourceHandle: 'next',
      target: edge.target,
      targetHandle: 'prev',
      type: 'handoff',
      selectable: false,
      focusable: false,
      data: { edge, color: AGENT_VISUAL[edge.source].color, now, handoffSeq: seqFor(edge), played: played.current },
    }))
    for (const { node, shown, hidden } of tree) {
      const color = AGENT_VISUAL[node.id].color
      for (const item of discoveriesByStage.get(node.id) || []) {
        out.push({
          id: `branch:discovery:${item.id}`,
          source: node.id,
          sourceHandle: 'fleet',
          target: `discovery:${item.id}`,
          targetHandle: 'in',
          type: 'branch',
          selectable: false,
          focusable: false,
          data: { state: 'completed', color, discovery: true },
        })
      }
      for (const instance of shown) {
        const { online } = agentPresence(instance, liveByAgent?.[instance.id], now)
        out.push({
          id: `branch:${instance.id}`,
          source: node.id,
          sourceHandle: 'fleet',
          target: `agent:${instance.id}`,
          targetHandle: 'in',
          type: 'branch',
          selectable: false,
          focusable: false,
          data: { state: branchState(instance.state, online), color },
        })
      }
      if (hidden.length) {
        out.push({
          id: `branch:overflow:${node.id}`,
          source: node.id,
          sourceHandle: 'fleet',
          target: `overflow:${node.id}`,
          targetHandle: 'in',
          type: 'branch',
          selectable: false,
          focusable: false,
          data: { state: 'idle', color },
        })
      }
    }
    return out
  }, [discoveriesByStage, liveByAgent, model.edges, now, seqFor, tree])

  const onNodesChange = useCallback((changes: NodeChange<CanvasNode>[]) => {
    for (const change of changes) {
      if (change.type === 'select' && change.selected && !change.id.includes(':')) onSelect(change.id as WorkflowAgentId)
    }
  }, [onSelect])

  // Inline height follows the tree's aspect at the measured width, so a fleet
  // under the stages is framed at a readable zoom rather than shrunk to fit.
  const inlineHeight = stageWidth
    ? Math.round(Math.min(INLINE_MAX_H, Math.max(INLINE_MIN_H, ((stageWidth - 2 * FIT_PAD.x) * treeHeight) / WORLD_W + FIT_PAD.top + FIT_PAD.bottom)))
    : INLINE_MIN_H

  return (
    <div
      ref={stageRef}
      tabIndex={-1}
      data-expanded={expanded ? 'true' : undefined}
      role={expanded ? 'dialog' : undefined}
      aria-modal={expanded || undefined}
      aria-label={expanded ? 'Agent workflow canvas, full screen' : undefined}
      className="qg-lw-canvas relative overflow-hidden border outline-none"
      style={expanded ? undefined : { height: inlineHeight }}
    >
      {expanded && (
        <div className="pointer-events-none absolute left-4 top-3 z-10 flex items-center gap-3">
          <span className="text-[11px] font-bold uppercase tracking-[0.18em] text-[color:var(--lw-ink-muted)]">Collector → Scanner → Patcher → Migration Operator</span>
          <span className="text-[10px] text-[color:var(--lw-ink-muted)]">Esc to exit full screen</span>
        </div>
      )}
      <ReactFlow<CanvasNode, CanvasEdge>
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        edgeTypes={EDGE_TYPES}
        onNodesChange={onNodesChange}
        onNodeClick={(_, node) => { if (node.type === 'agent') onSelect(node.id as WorkflowAgentId) }}
        onPaneClick={() => { onSelectInstance(null); onSelectDiscovery(null) }}
        onMoveStart={(event) => { if (event) setFollowLive(false) }}
        fitView
        fitViewOptions={{ padding: fitPadding(expanded) }}
        minZoom={0.12}
        maxZoom={1.6}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        nodesFocusable
        panOnScroll={false}
        // Wheel zoom only when there is no page behind the canvas to scroll.
        zoomOnScroll={expanded}
        zoomOnPinch
        preventScrolling={false}
        proOptions={{ hideAttribution: true }}
      />
      {selectedDiscovery && (
        <DiscoveryInspector
          item={selectedDiscovery}
          onClose={() => onSelectDiscovery(null)}
          className="absolute bottom-14 right-3 top-3 z-20 w-[340px] max-w-[calc(100%-1.5rem)]"
        />
      )}
      {selectedInstance && (
        <AgentInspector
          instance={selectedInstance}
          live={liveByAgent?.[selectedInstance.id]}
          events={events ?? model.events}
          now={now}
          onClose={() => onSelectInstance(null)}
          onOpenStage={() => {
            onSelectInstance(null)
            showOutput(selectedInstance.role)
          }}
          className="absolute bottom-14 right-3 top-3 z-20 w-[340px] max-w-[calc(100%-1.5rem)]"
        />
      )}
      <div className="qg-lw-discovery-dock absolute bottom-3 left-3 z-10 flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[11px]">
        <Radar size={15} className="shrink-0 text-[color:var(--lw-sky)]" aria-hidden="true" />
        <div className="min-w-0">
          <div className="font-bold">{discoveriesPlanScoped ? 'Workspace discoveries · available in fleet view' : discoveriesConnected ? 'Live agent discoveries' : 'Agent discovery stream disconnected'}</div>
          <div className="truncate text-[color:var(--lw-ink-soft)]" aria-live="polite">
            {latestDiscovery
              ? `${latestDiscovery.data.item.label} · ${latestDiscovery.data.item.agentName}`
              : !discoveriesPlanScoped && discoveriesConnected ? 'Waiting for evidence from agents' : null}
          </div>
        </div>
        {latestDiscovery && (
          <button type="button" onClick={focusLatest} className="qg-lw-discovery-control shrink-0 rounded-md px-1.5 py-1 font-bold" title="Center the latest discovery">
            Latest
          </button>
        )}
      </div>
      <div className="qg-lw-view-controls absolute bottom-3 right-3 z-10 flex overflow-hidden rounded-lg border bg-[var(--lw-screen)] backdrop-blur" role="toolbar" aria-label="Canvas view controls">
        {[
          { label: 'Zoom in', icon: Plus, run: () => flow.zoomIn({ duration: 200 }) },
          { label: 'Zoom out', icon: Minus, run: () => flow.zoomOut({ duration: 200 }) },
          { label: 'Fit to screen', icon: Scan, run: () => { setFollowLive(false); fit(prefersReducedMotion() ? 0 : 250) } },
          { label: 'Follow live discoveries', icon: Crosshair, run: () => setFollowLive((value) => !value), pressed: followLive },
          { label: expanded ? 'Exit full screen' : 'Full screen', icon: expanded ? Minimize2 : Maximize2, run: toggleFullScreen, pressed: expanded },
        ].map((control) => (
          <button
            key={control.label}
            type="button"
            onClick={control.run}
            title={control.label}
            aria-label={control.label}
            aria-pressed={'pressed' in control ? control.pressed : undefined}
            className="grid h-8 w-8 place-items-center transition-colors"
          >
            <control.icon className="h-3.5 w-3.5" />
          </button>
        ))}
      </div>
    </div>
  )
}

export default function WorkflowCanvas(props: WorkflowCanvasProps) {
  const { model, now, selectedAgent, highlightedAgent, onSelect, onOutput, liveByAgent, events, discoveries } = props
  const [announcement, setAnnouncement] = useState('')
  const [selectedInstanceId, setSelectedInstanceId] = useState<string | null>(null)
  const [selectedDiscoveryId, setSelectedDiscoveryId] = useState<string | null>(null)
  const previous = useRef<Record<string, string>>({})

  const discoveriesByStage = useMemo(() => {
    const agents = new Map(model.nodes.flatMap((node) => node.fleet.agents.map((agent) => [agent.id, agent] as const)))
    const grouped = new Map<WorkflowAgentId, CanvasDiscovery[]>()
    discoveries?.forEach((item, order) => {
      const agent = agents.get(item.agentId)
      if (!agent) return
      const stage = grouped.get(agent.role) || []
      stage.push({ ...item, agentName: agent.name, order })
      grouped.set(agent.role, stage)
    })
    for (const [role, items] of grouped) {
      const recent = items.slice(-DISCOVERIES_PER_STAGE)
      const inspected = items.find((item) => item.id === selectedDiscoveryId)
      grouped.set(role, inspected && !recent.includes(inspected) ? [inspected, ...recent.slice(1)] : recent)
    }
    return grouped
  }, [discoveries, model.nodes, selectedDiscoveryId])
  const selectedDiscovery = Array.from(discoveriesByStage.values()).flat().find((item) => item.id === selectedDiscoveryId) || null

  // Resolve against the CURRENT snapshot, so the inspector shows live values
  // and closes by itself if the agent is revoked.
  const selectedInstance = useMemo(() => {
    if (!selectedInstanceId) return null
    for (const node of model.nodes) {
      const match = node.fleet.agents.find((agent) => agent.id === selectedInstanceId)
      if (match) return match
    }
    return null
  }, [model.nodes, selectedInstanceId])

  const onSelectInstance = useCallback((instance: WorkflowAgentInstance | null) => setSelectedInstanceId(instance?.id ?? null), [])

  // Screen-reader announcement of confirmed status changes — stages and agents.
  useEffect(() => {
    const changes: string[] = []
    for (const node of model.nodes) {
      const before = previous.current[node.id]
      if (before && before !== node.status) changes.push(`${node.label} is now ${STATUS_META[node.status].label}.`)
      previous.current[node.id] = node.status
      for (const agent of node.fleet.agents) {
        const key = `agent:${agent.id}`
        const was = previous.current[key]
        if (was && was !== agent.state) changes.push(`${node.label} agent ${agent.name} is now ${STATUS_META[agent.state].label}.`)
        previous.current[key] = agent.state
      }
    }
    if (changes.length) setAnnouncement(changes.join(' '))
  }, [model.nodes])

  return (
    <div>
      <div className="qg-lw-canvas-host hidden lg:block">
        <ReactFlowProvider>
          <CanvasInner
            {...props}
            selectedInstance={selectedInstance}
            onSelectInstance={onSelectInstance}
            discoveriesByStage={discoveriesByStage}
            selectedDiscovery={selectedDiscovery}
            onSelectDiscovery={setSelectedDiscoveryId}
          />
        </ReactFlowProvider>
      </div>
      {/* Narrow screens: the same cards, stacked in workflow order, each stage's agents beneath it. */}
      <div className="grid gap-3 sm:grid-cols-2 lg:hidden">
        {model.nodes.map((node) => (
          <div key={node.id} className="grid content-start gap-2">
            <div className="h-[318px]">
              <AgentCard
                node={node}
                now={now}
                selected={node.id === selectedAgent}
                highlighted={node.id === highlightedAgent}
                onSelect={() => onSelect(node.id)}
                onOutput={() => onOutput(node.id)}
              />
            </div>
            {node.fleet.agents.length > 0 && (
              <ul className="ml-4 grid gap-2 border-l pl-3" style={{ borderColor: mix(AGENT_VISUAL[node.id].color, 35) }} aria-label={`${node.label} agents`}>
                {[...node.fleet.agents].sort(byName).map((agent) => (
                  <li key={agent.id} className="h-[148px]">
                    <AgentInstanceCard
                      instance={agent}
                      live={liveByAgent?.[agent.id]}
                      now={now}
                      selected={agent.id === selectedInstanceId}
                      onSelect={() => {
                        setSelectedDiscoveryId(null)
                        setSelectedInstanceId(agent.id === selectedInstanceId ? null : agent.id)
                        onSelect(node.id)
                      }}
                    />
                  </li>
                ))}
              </ul>
            )}
            {discoveriesByStage.has(node.id) && (
              <ul className="ml-4 grid gap-2 border-l pl-3" style={{ borderColor: mix(AGENT_VISUAL[node.id].color, 35) }} aria-label={`${node.label} recent discoveries`}>
                {discoveriesByStage.get(node.id)?.map((item) => (
                  <li key={item.id} className="h-[82px]">
                    <DiscoveryCard item={item} selected={item.id === selectedDiscoveryId} onSelect={(id) => {
                      setSelectedInstanceId(null)
                      setSelectedDiscoveryId(id)
                    }} />
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
        {selectedDiscovery && (
          <DiscoveryInspector item={selectedDiscovery} onClose={() => setSelectedDiscoveryId(null)} className="max-h-[560px] sm:col-span-2" />
        )}
        {selectedInstance && (
          <AgentInspector
            instance={selectedInstance}
            live={liveByAgent?.[selectedInstance.id]}
            events={events ?? model.events}
            now={now}
            onClose={() => setSelectedInstanceId(null)}
            onOpenStage={() => {
              setSelectedInstanceId(null)
              onOutput(selectedInstance.role)
            }}
            className="max-h-[560px] sm:col-span-2"
          />
        )}
      </div>
      <ol className="qg-lw-sr" aria-label="Workflow stages">
        {model.nodes.map((node) => (
          <li key={node.id}>
            {`${node.label}: ${STATUS_META[node.status].label}. ${node.currentTask}. ${node.reason}`}
            {node.fleet.agents.length > 0 && (
              <ul aria-label={`${node.label} agents`}>
                {node.fleet.agents.map((agent) => (
                  <li key={agent.id}>{`${agent.name}: ${STATUS_META[agent.state].label}, ${agent.online ? 'online' : 'offline'}. ${agent.currentTask}. ${agent.reason}`}</li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ol>
      <div className="qg-lw-sr" role="status" aria-live="polite">{announcement}</div>
    </div>
  )
}
