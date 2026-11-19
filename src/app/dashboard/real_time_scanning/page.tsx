'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { getNodesBounds, getViewportForBounds, type ReactFlowInstance } from '@xyflow/react'
import { toPng } from 'html-to-image'
import {
  Activity, AlertTriangle, ChevronRight, Crosshair, FileJson, FileSpreadsheet, History, Image as ImageIcon,
  Frame, LayoutGrid, Maximize, Minimize, Pause, Play, Radar, RefreshCw, RotateCw, Search, Square, X, ZoomIn, ZoomOut,
} from 'lucide-react'
import { useLiveScan, type StartScanInput } from '@/hooks/use-live-scan'
import { GROUP_PREFIX, buildGraph, clusterFindings, hasMeasuredSurface, neighbours, relationshipVerification, summarize, trace, type LiveGraphState } from '@/lib/live-scan/graph-reducer'
import { EXPOSURE_LABEL, POLICY_VERSION, SEVERITY_LABEL, SEVERITY_RANK } from '@/lib/live-scan/policy'
import type { LiveScanStatus, NodeKind, Severity } from '@/lib/live-scan/types'
import { KIND_LABEL, LiveCanvas, MIN_CANVAS_ZOOM, STATUS_WORD, newLayoutMemory, relayout } from './LiveCanvas'
import { Inspector } from './Inspector'
import { ScanHistory } from './ScanHistory'
import './live-scan.css'

/**
 * Real Time Scanning — Discovery › PQC Scanner › Real Time Scanning.
 *
 * QGuard Helix Scanning Workflow: the live canvas is drawn ONLY from the run's
 * persisted event log, which the backend appends as the existing scanner
 * engines report. There is no demo or simulated mode on this page: with no
 * run, it shows an empty canvas and the way to start one.
 */

type Category = 'all' | 'quantum' | 'certificates' | 'cas' | 'algorithms' | 'relying' | 'vendors' | 'findings' | 'new' | 'migration' | 'unknown'
type EvidenceFilter = 'all' | 'verified' | 'inferred'

const CATEGORIES: Array<[Category, string]> = [
  ['all', 'All assets'], ['quantum', 'Quantum vulnerable'], ['certificates', 'Certificates'], ['cas', 'CAs & trust anchors'],
  ['algorithms', 'Algorithms'], ['relying', 'Relying apps'], ['vendors', 'Vendors'], ['findings', 'Findings'],
  ['migration', 'Requires migration'], ['unknown', 'Unknown / incomplete'], ['new', 'Newly discovered'],
]

const CATEGORY_KINDS: Partial<Record<Category, NodeKind[]>> = {
  certificates: ['certificate'], cas: ['ca', 'trust-store'], algorithms: ['algorithm'], relying: ['application'], vendors: ['vendor'], findings: ['finding'],
}

const STATUS_LABEL: Record<LiveScanStatus, string> = {
  idle: 'Idle', starting: 'Starting', running: 'Running', paused: 'Paused', cancelling: 'Cancelling', completed: 'Completed', partial: 'Partial assessment', failed: 'Failed', cancelled: 'Cancelled',
}

function duration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—'
  const s = Math.floor(ms / 1000)
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return h ? `${h}h ${m}m` : `${m}m ${String(s % 60).padStart(2, '0')}s`
}

function Stat({ label, value, title }: { label: string; value: string | number; title?: string }) {
  return (
    <div className="rt-stat" title={title}>
      <div className="rt-stat-label">{label}</div>
      <div key={String(value)} className="rt-stat-value is-bump">{value}</div>
    </div>
  )
}

function Metric({ label, value, tone, hint }: { label: string; value: number | string; tone?: string; hint?: string }) {
  return (
    <div className={`rt-metric${tone ? ` tone-${tone}` : ''}`} title={hint}>
      <b key={String(value)} className="rt-stat-value is-bump" style={{ fontSize: 18 }}>{value}</b>
      <span>{label}</span>
      {hint && <small>{hint}</small>}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Scan configuration dialog                                           */
/* ------------------------------------------------------------------ */

function ConfigDialog({ open, onClose, onStart, token, limits, initialTargets }: {
  open: boolean
  onClose: () => void
  onStart: (input: StartScanInput) => Promise<void>
  token: string | null
  limits: ReturnType<typeof useLiveScan>['limits']
  initialTargets: string[]
}) {
  const [name, setName] = useState('')
  const [targets, setTargets] = useState(initialTargets.join('\n'))
  const [concurrency, setConcurrency] = useState(limits?.concurrency.default ?? 2)
  const [timeout, setTimeoutSec] = useState(limits?.targetTimeoutSec.default ?? 45)
  const [expiring, setExpiring] = useState(limits?.expiringWithinDays.default ?? 30)
  const [authorized, setAuthorized] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [inventory, setInventory] = useState<string[] | null>(null)
  const [inventoryState, setInventoryState] = useState<'idle' | 'loading' | 'error'>('idle')

  useEffect(() => { if (open) { setTargets(initialTargets.join('\n')); setError(null) } }, [open, initialTargets])

  const loadInventory = useCallback(async () => {
    if (!token) return
    setInventoryState('loading')
    try {
      const response = await fetch('/api/v1/scanner/assets', { headers: { Authorization: `Bearer ${token}` } })
      if (!response.ok) throw new Error()
      const body = await response.json()
      const rows = (body?.data?.assets ?? body?.data ?? []) as Array<Record<string, unknown>>
      const names = [...new Set(rows.map((row) => String(row.domain || row.url || row.name || '')).filter((item) => item && !item.includes('github.com')))]
      setInventory(names.slice(0, 200))
      setInventoryState('idle')
    } catch {
      setInventoryState('error')
    }
  }, [token])

  if (!open) return null
  const list = targets.split(/[\n,;\s]+/).map((item) => item.trim()).filter(Boolean)
  const max = limits?.maxTargets ?? 25

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      await onStart({ name, targets: list, concurrency, targetTimeoutSec: timeout, expiringWithinDays: expiring })
      onClose()
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="rt-scrim" onClick={onClose} aria-hidden="true" />
      <div className="rt-scan-config" role="dialog" aria-label="Configure live scan">
        <div style={{ padding: '16px 18px', borderBottom: '1px solid var(--rt-line)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Radar size={18} style={{ color: 'var(--rt-primary)' }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 900, fontSize: 15 }}>Start Live Scan</div>
            <div className="rt-muted" style={{ fontSize: 11.5 }}>Runs the QGuard web, TLS, PKI and PQC engines against authorized public endpoints.</div>
          </div>
          <button type="button" className="rt-btn is-icon" onClick={onClose} aria-label="Close"><X size={15} /></button>
        </div>
        <div style={{ padding: 18, display: 'grid', gap: 12 }}>
          <label className="rt-field">Scan name
            <input className="rt-input" value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Customer portal TLS posture" maxLength={80} />
          </label>
          <label className="rt-field">Authorized targets — domains, hostnames, IPs or https:// URLs (max {max})
            <textarea className="rt-input" rows={5} value={targets} onChange={(event) => setTargets(event.target.value)} placeholder={'example.com\napi.example.com:8443'} />
            <span className="rt-muted" style={{ fontWeight: 600 }}>{list.length} target(s). Private, loopback and internal names are refused — they need a deployed internal agent.</span>
          </label>
          <div>
            <button type="button" className="rt-btn" onClick={loadInventory} disabled={!token || inventoryState === 'loading'}>
              <RefreshCw size={13} /> {inventoryState === 'loading' ? 'Loading inventory…' : 'Refresh inventory'}
            </button>
            {inventoryState === 'error' && <span className="rt-muted" style={{ marginLeft: 8, fontSize: 11 }}>Inventory could not be loaded.</span>}
            {inventory && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 8, maxHeight: 120, overflowY: 'auto' }}>
                {inventory.length === 0 && <span className="rt-muted" style={{ fontSize: 11 }}>No scanned assets in your inventory yet.</span>}
                {inventory.map((item) => {
                  const on = list.includes(item)
                  return (
                    <button key={item} type="button" className={`rt-chip${on ? ' is-on' : ''}`} onClick={() => setTargets(on ? list.filter((value) => value !== item).join('\n') : [...list, item].join('\n'))}>
                      {item}
                    </button>
                  )
                })}
              </div>
            )}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 10 }}>
            <label className="rt-field">Parallel targets
              <input className="rt-input" type="number" min={limits?.concurrency.min ?? 1} max={limits?.concurrency.max ?? 4} value={concurrency} onChange={(event) => setConcurrency(Number(event.target.value))} />
            </label>
            <label className="rt-field">Per-target budget (s)
              <input className="rt-input" type="number" min={limits?.targetTimeoutSec.min ?? 20} max={limits?.targetTimeoutSec.max ?? 90} value={timeout} onChange={(event) => setTimeoutSec(Number(event.target.value))} />
            </label>
            <label className="rt-field">Expiring within (days)
              <input className="rt-input" type="number" min={1} max={120} value={expiring} onChange={(event) => setExpiring(Number(event.target.value))} />
            </label>
          </div>
          <div className="rt-block" style={{ fontSize: 11.5, margin: 0 }}>
            <dl className="rt-kv">
              <dt>TLS ports</dt><dd>443, or the port written in the target (e.g. host:8443)</dd>
              <dt>Trust-store policy</dt><dd>Platform default (Node.js / OpenSSL bundled roots)</dd>
              <dt>Quantum-risk policy</dt><dd>qguard-live-quantum-policy v{POLICY_VERSION} + engine detection rules</dd>
              <dt>Passive discovery</dt><dd>Not included — only listed targets are contacted</dd>
              <dt>Internal agents</dt><dd>Not used by live scans; deploy a collector for private assets</dd>
            </dl>
          </div>
          <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12, color: 'var(--rt-ink-soft)' }}>
            <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} style={{ marginTop: 2 }} />
            I confirm every target belongs to my organization or I am explicitly authorized to perform defensive cryptographic scanning against it.
          </label>
          {error && <div className="rt-banner is-error">{error}</div>}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button type="button" className="rt-btn" onClick={onClose}>Cancel</button>
            <button type="button" className="rt-btn is-primary" disabled={!authorized || !list.length || list.length > max || busy} onClick={submit}>
              <Play size={13} /> {busy ? 'Starting…' : 'Start Live Scan'}
            </button>
          </div>
        </div>
      </div>
    </>
  )
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

const NO_ACTIVE_TARGETS: string[] = []

export default function RealTimeScanningPage() {
  const [params, setParams] = useSearchParams()
  const live = useLiveScan(params.get('run'))
  const { graph, events, health, runId } = live

  const [configOpen, setConfigOpen] = useState(false)
  const [configTargets, setConfigTargets] = useState<string[]>([])
  const [historyOpen, setHistoryOpen] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [pendingCenter, setPendingCenter] = useState<string | null>(null)
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null)
  const [drawer, setDrawer] = useState(false)
  const [inspectorWidth, setInspectorWidth] = useState(560)
  const [inspectorExpanded, setInspectorExpanded] = useState(false)
  const [highlight, setHighlight] = useState<Set<string> | null>(null)
  const [highlightLabel, setHighlightLabel] = useState<string | null>(null)
  const [flashId, setFlashId] = useState<string | null>(null)
  const [category, setCategory] = useState<Category>('all')
  const [severity, setSeverity] = useState<Severity | 'all'>('all')
  const [evidenceFilter, setEvidenceFilter] = useState<EvidenceFilter>('all')
  const [query, setQuery] = useState('')
  const [withContext, setWithContext] = useState(true)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [timelineSeq, setTimelineSeq] = useState<number | null>(null)
  const [playing, setPlaying] = useState(false)
  const [playbackSpeed, setPlaybackSpeed] = useState(1)
  const [feedMode, setFeedMode] = useState<'live' | 'findings' | 'severity'>('live')
  const [menu, setMenu] = useState<{ id: string; x: number; y: number } | null>(null)
  const [tip, setTip] = useState<{ id: string; x: number; y: number } | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [now, setNow] = useState(() => Date.now())
  const [layoutVersion, setLayoutVersion] = useState(0)
  const [follow, setFollow] = useState(true)
  const [fullscreen, setFullscreen] = useState(false)
  const [showAddresses, setShowAddresses] = useState(false)
  const [baselineSeq, setBaselineSeq] = useState(0)
  const [newSince, setNewSince] = useState(0)

  const flowRef = useRef<ReactFlowInstance | null>(null)
  const stageRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLDivElement | null>(null)
  const fullscreenButton = useRef<HTMLButtonElement | null>(null)
  const memoryRef = useRef(newLayoutMemory())
  const samples = useRef<Array<{ at: number; seq: number }>>([])

  // Keep ?run= in sync so a refresh reopens the same run instead of starting one.
  useEffect(() => {
    const current = params.get('run')
    if (runId && current !== runId) setParams({ run: runId }, { replace: true })
  }, [runId, params, setParams])

  // New run → fresh layout and baseline; replayed history is not "new".
  useEffect(() => {
    memoryRef.current = newLayoutMemory()
    setSelectedId(null); setSelectedEdgeId(null); setHighlight(null); setTimelineSeq(null); setExpanded(new Set()); setExpandedGroups(new Set()); setFollow(true)
    setTip(null); setMenu(null); setDrawer(false); setPendingCenter(null)
    setPlaying(false)
    samples.current = []
  }, [runId])
  useEffect(() => {
    if (!live.loading) { setBaselineSeq(graph.lastSeq); setNewSince(graph.lastSeq) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live.loading, runId])

  const liveMeta = graph.meta
  const running = liveMeta ? ['starting', 'running', 'paused', 'cancelling'].includes(liveMeta.status) : false
  const genuinelyRunning = liveMeta?.status === 'running' && (health === 'live' || health === 'connecting' || health === 'reconnecting')

  useEffect(() => {
    if (!running) return
    const timer = setInterval(() => {
      setNow(Date.now())
      samples.current.push({ at: Date.now(), seq: graph.lastSeq })
      samples.current = samples.current.filter((sample) => Date.now() - sample.at < 30_000)
      const old = samples.current.find((sample) => Date.now() - sample.at >= 20_000)
      if (old) setNewSince((value) => Math.max(value, old.seq, baselineSeq))
    }, 1000)
    return () => clearInterval(timer)
  }, [running, graph.lastSeq, baselineSeq])

  /* ------------------------------ displayed graph ------------------------------ */

  const displayGraph: LiveGraphState = useMemo(
    () => (timelineSeq === null ? graph : buildGraph(events, timelineSeq)),
    [graph, events, timelineSeq],
  )
  const recordedMeta = displayGraph.meta
  const legacyPartial = recordedMeta?.status === 'failed' && recordedMeta.stage === 'Every target failed' &&
    hasMeasuredSurface(displayGraph)
  const meta = legacyPartial && recordedMeta
    ? { ...recordedMeta, status: 'partial' as const, stage: 'Partial assessment · evidence retained' }
    : recordedMeta
  const activeTargets = meta?.activeTargets ?? NO_ACTIVE_TARGETS
  const replayEvent = timelineSeq === null ? null : events.find((event) => event.seq === timelineSeq)
  const replayNext = useMemo(() => {
    if (timelineSeq === null) return null
    return events.find((event) => event.seq > timelineSeq && event.type !== 'evidence.recorded') ?? null
  }, [events, timelineSeq])

  useEffect(() => {
    if (!playing || timelineSeq === null || !replayNext) return
    // Preserve recorded order and relative pauses with a cap for long probes.
    const recordedGap = replayEvent ? Date.parse(replayNext.at) - Date.parse(replayEvent.at) : 0
    const delay = Math.max(100, Math.min(2500, recordedGap || 0)) / playbackSpeed
    const timer = window.setTimeout(() => {
      setTimelineSeq(replayNext.seq)
    }, delay)
    return () => window.clearTimeout(timer)
  }, [playing, timelineSeq, replayEvent, replayNext, playbackSpeed])

  useEffect(() => {
    if (playing && !replayNext) setPlaying(false)
  }, [playing, replayNext])
  const summary = useMemo(() => summarize(displayGraph), [displayGraph])
  // Presentation only: large same-type finding sets collapse into one group node.
  const canvasGraph = useMemo(() => clusterFindings(displayGraph, expandedGroups), [displayGraph, expandedGroups])
  const groupOf = useCallback((findingId: string) => {
    for (const node of Object.values(canvasGraph.nodes)) {
      if (node.id.startsWith(GROUP_PREFIX) && (node.data.memberIds as string[]).includes(findingId)) return node.id
    }
    return null
  }, [canvasGraph])

  const visible = useMemo<Set<string> | null>(() => {
    const q = query.trim().toLowerCase()
    if (category === 'all' && severity === 'all' && evidenceFilter === 'all' && !q && showAddresses) return null
    const nodes = Object.values(canvasGraph.nodes)
    const findings = Object.values(displayGraph.findings)
    const edges = Object.values(canvasGraph.edges)
    const migration = new Set(edges.filter((edge) => edge.type === 'REQUIRES_MIGRATION').flatMap((edge) => [edge.source, edge.target]))
    const severityNodes = severity === 'all' ? null : new Set(findings.filter((finding) => finding.severity === severity).flatMap((finding) => finding.affectedNodeIds))
    const evidenceNodes = evidenceFilter === 'all' ? null : new Set(edges
      .filter((edge) => {
        const verification = relationshipVerification(edge)
        return evidenceFilter === 'inferred' ? verification === 'inferred' : verification === 'validated' || verification === 'observed'
      })
      .flatMap((edge) => [edge.source, edge.target]))
    const matched = new Set<string>()
    const unfiltered = category === 'all' && severity === 'all' && evidenceFilter === 'all' && !q
    for (const node of nodes) {
      if (node.kind === 'address' && !showAddresses) continue
      if (CATEGORY_KINDS[category] && !CATEGORY_KINDS[category]!.includes(node.kind)) continue
      if (category === 'quantum' && !(node.status === 'exposure' || node.status === 'critical')) continue
      if (category === 'migration' && !migration.has(node.id)) continue
      if (category === 'unknown' && !(node.status === 'unknown' || node.status === 'failed')) continue
      if (category === 'new' && !(node.firstSeq > baselineSeq)) continue
      if (severityNodes && (node.kind === 'finding' ? node.data.severity !== severity : !severityNodes.has(node.id))) continue
      if (evidenceNodes && !evidenceNodes.has(node.id)) continue
      if (q && !`${node.label} ${node.sublabel ?? ''} ${node.targets.join(' ')} ${node.id}`.toLowerCase().includes(q)) continue
      matched.add(node.id)
    }
    const out = new Set(matched)
    if (withContext && !unfiltered) for (const id of matched) for (const other of neighbours(canvasGraph, id)) out.add(other)
    for (const id of expanded) for (const other of neighbours(canvasGraph, id)) out.add(other)
    out.add('scanner:helix')
    if (!showAddresses) for (const id of [...out]) if (canvasGraph.nodes[id]?.kind === 'address') out.delete(id)
    return out
  }, [canvasGraph, displayGraph, category, severity, evidenceFilter, query, withContext, expanded, baselineSeq, showAddresses])

  /* ------------------------------ canvas navigation ------------------------------ */

  const centerOn = useCallback((id: string) => {
    const group = canvasGraph.nodes[id] ? null : groupOf(id)
    if (group) {
      setExpandedGroups((current) => new Set(current).add(group))
      setPendingCenter(id)
      return
    }
    setFollow(false)
    const position = memoryRef.current.positions.get(id)
    if (position && flowRef.current) flowRef.current.setCenter(position.x + 124, position.y + 50, { zoom: Math.max(flowRef.current.getZoom(), 0.85), duration: 600 })
    setFlashId(id)
    setTimeout(() => setFlashId((current) => (current === id ? null : current)), 2600)
  }, [canvasGraph, groupOf])
  useEffect(() => {
    if (!pendingCenter || !canvasGraph.nodes[pendingCenter]) return
    setPendingCenter(null)
    centerOn(pendingCenter)
  }, [pendingCenter, canvasGraph.nodes, centerOn])

  const selectNode = useCallback((id: string | null, openDrawer = true) => {
    if (id && id.startsWith(GROUP_PREFIX)) {
      setExpandedGroups((current) => new Set(current).add(id))
      setNotice(null)
      return
    }
    setSelectedEdgeId(null)
    setSelectedId(id)
    setMenu(null)
    setTip(null)
    if (!id) { setDrawer(false); return }
    // Inspection keeps the rest of the graph visible. Focus and trace controls
    // can still narrow attention to a relationship path.
    if (openDrawer) setDrawer(true)
  }, [])

  const selectEdge = useCallback((id: string) => {
    setSelectedId(null)
    setSelectedEdgeId(id)
    setTip(null)
    setDrawer(true)
  }, [])

  const linkedFinding = params.get('finding')
  const matchingRun = runId === params.get('run')
  useEffect(() => {
    if (!linkedFinding || !matchingRun || !displayGraph.findings[linkedFinding]) return
    selectNode(linkedFinding)
    setParams((current) => {
      const next = new URLSearchParams(current)
      next.delete('finding')
      return next
    }, { replace: true })
  }, [linkedFinding, matchingRun, displayGraph.findings, selectNode, setParams])

  const fitCanvas = useCallback((onlyIds?: ReadonlySet<string>) => {
    const flow = flowRef.current
    const pane = canvasRef.current?.querySelector('.react-flow')
    if (!flow?.viewportInitialized || !pane || document.visibilityState === 'hidden') return
    const { clientWidth: width, clientHeight: height } = pane
    if (width < 50 || height < 50) return

    const cards = flow.getNodes().filter((node) => node.type === 'live' && (!onlyIds || onlyIds.has(node.id)))
    if (!cards.length && onlyIds) return
    let left = Infinity
    let top = onlyIds ? Infinity : 0
    let right = -Infinity
    let bottom = -Infinity
    for (const { position, measured } of cards) {
      left = Math.min(left, position.x)
      top = Math.min(top, position.y)
      // Allow for a card that has just arrived and is waiting for measurement.
      right = Math.max(right, position.x + (measured?.width ?? 248))
      bottom = Math.max(bottom, position.y + (measured?.height ?? 160))
    }
    const viewport = cards.length
      ? getViewportForBounds({ x: left, y: top, width: right - left, height: bottom - top }, width, height, MIN_CANVAS_ZOOM, onlyIds ? 1.1 : 1, 0.16)
      : { x: 24, y: 16, zoom: 0.85 }
    const current = flow.getViewport()
    if (Math.abs(current.x - viewport.x) < 0.5 && Math.abs(current.y - viewport.y) < 0.5 && Math.abs(current.zoom - viewport.zoom) < 0.001) return
    void flow.setViewport(viewport)
  }, [])

  const fitToScreen = useCallback(() => {
    setTip(null)
    if (!fullscreen) stageRef.current?.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'instant' })
    fitCanvas()
  }, [fitCanvas, fullscreen])

  const focusMode = useCallback((id: string, mode: 'focus' | 'upstream' | 'downstream') => {
    const set = mode === 'focus' ? neighbours(canvasGraph, id) : trace(canvasGraph, id, mode)
    setHighlight(set)
    setHighlightLabel(`${mode === 'focus' ? 'Focus' : mode === 'upstream' ? 'Upstream trace' : 'Downstream trace'}: ${displayGraph.nodes[id]?.label ?? id}`)
    setSelectedId(id)
    setDrawer(false)
    setMenu(null)
    setTip(null)
    fitCanvas(set)
  }, [displayGraph, canvasGraph, fitCanvas])

  const trackPointer = useCallback((id: string | null, x: number, y: number) => {
    setTip(id ? { id, x, y } : null)
  }, [])
  const takeViewport = useCallback(() => { setFollow(false); setTip(null) }, [])
  const onFlowInit = useCallback((instance: ReactFlowInstance) => {
    flowRef.current = instance
    fitCanvas()
  }, [fitCanvas])
  const openContext = useCallback((id: string, x: number, y: number) => setMenu({ id, x, y }), [])
  const expandNode = useCallback((id: string) => {
    setExpanded((current) => new Set(current).add(id))
    focusMode(id, 'focus')
  }, [focusMode])
  const tipNode = tip && (!visible || visible.has(tip.id)) ? canvasGraph.nodes[tip.id] : null
  const inspecting = Boolean(tipNode || drawer || menu || highlight)
  const visibleNodeIds = useMemo(() => Object.keys(canvasGraph.nodes).filter((id) => !visible || visible.has(id)).join('\n'), [canvasGraph.nodes, visible])

  // One automatic camera update. Hovering or opening details suspends it.
  // Scan completion and tab switches use the same rules as incoming findings.
  useEffect(() => {
    if (!follow || inspecting || !visibleNodeIds) return
    const timer = requestAnimationFrame(() => fitCanvas())
    const onVisible = () => fitCanvas()
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      cancelAnimationFrame(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [follow, inspecting, visibleNodeIds, layoutVersion, running, fitCanvas])

  const toggleFullscreen = useCallback(async () => {
    const stage = stageRef.current
    if (!stage) return
    setTip(null)
    setMenu(null)
    if (document.fullscreenElement === stage) {
      await document.exitFullscreen()
    } else if (fullscreen) {
      setFullscreen(false)
    } else {
      try {
        await stage.requestFullscreen()
      } catch {
        // Embedded browsers can deny native fullscreen.
        setFullscreen(true)
      }
    }
  }, [fullscreen])

  useEffect(() => {
    const stage = stageRef.current
    const onChange = () => {
      setFullscreen(document.fullscreenElement === stage)
      setTip(null)
      setMenu(null)
    }
    document.addEventListener('fullscreenchange', onChange)
    return () => document.removeEventListener('fullscreenchange', onChange)
  }, [])

  const wasFullscreen = useRef(false)
  useEffect(() => {
    if (!fullscreen && !wasFullscreen.current) return
    wasFullscreen.current = fullscreen
    const frame = requestAnimationFrame(() => {
      fitCanvas()
      fullscreenButton.current?.focus({ preventScroll: true })
    })
    return () => cancelAnimationFrame(frame)
  }, [fullscreen, fitCanvas])

  useEffect(() => {
    const onEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented) return
      if (configOpen) setConfigOpen(false)
      else if (historyOpen) return // The modal handles Escape and restores focus.
      else if (menu) setMenu(null)
      else if (drawer) setDrawer(false)
      else if (fullscreen && document.fullscreenElement !== stageRef.current) setFullscreen(false)
    }
    document.addEventListener('keydown', onEscape)
    return () => document.removeEventListener('keydown', onEscape)
  }, [configOpen, drawer, fullscreen, historyOpen, menu])

  const latestFinding = useMemo(() => Object.values(displayGraph.nodes).filter((node) => node.kind === 'finding').sort((a, b) => b.firstSeq - a.firstSeq)[0] ?? null, [displayGraph.nodes])

  const exportPng = useCallback(async () => {
    const viewport = canvasRef.current?.querySelector<HTMLElement>('.react-flow__viewport')
    if (!viewport || !flowRef.current) return
    const width = 2200
    const height = 1300
    const bounds = getNodesBounds(flowRef.current.getNodes())
    const transform = getViewportForBounds(bounds, width, height, 0.1, 2, 0.06)
    const background = getComputedStyle(canvasRef.current!).getPropertyValue('--rt-canvas').trim() || '#050a16'
    try {
      const dataUrl = await toPng(viewport, { backgroundColor: background, width, height, style: { width: `${width}px`, height: `${height}px`, transform: `translate(${transform.x}px, ${transform.y}px) scale(${transform.zoom})` } })
      const anchor = document.createElement('a')
      anchor.href = dataUrl
      anchor.download = `live-scan-graph-${(runId ?? 'scan').slice(0, 8)}.png`
      anchor.click()
    } catch {
      setNotice('PNG export failed in this browser — use JSON export instead.')
    }
  }, [runId])

  const rescan = useCallback(async (target: string) => {
    try {
      const mode = await live.rescan(target)
      if (mode === 'queued') setNotice(`Rescan of ${target} queued in this run.`)
      else { setConfigTargets([target]); setConfigOpen(true) }
    } catch (err) {
      setNotice((err as Error).message)
    }
    setMenu(null)
  }, [live])

  /* ------------------------------ activity feed ------------------------------ */

  const feed = useMemo(() => {
    const items = events.filter((event) => event.activity && (timelineSeq === null || event.seq <= timelineSeq))
    if (feedMode === 'findings') return items.filter((event) => event.type.startsWith('finding.')).reverse().slice(0, 300)
    if (feedMode === 'severity') {
      const rank = (sev?: string) => (sev && sev in SEVERITY_RANK ? SEVERITY_RANK[sev as Severity] : sev === 'validated' ? -1 : -2)
      return items.filter((event) => event.activity?.severity).sort((a, b) => rank(b.activity!.severity) - rank(a.activity!.severity) || b.seq - a.seq).slice(0, 300)
    }
    return items.slice().reverse().slice(0, 300)
  }, [events, feedMode, timelineSeq])

  const findingsList = useMemo(() => Object.values(displayGraph.findings)
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.affectedTargets.length - a.affectedTargets.length), [displayGraph.findings])

  const elapsed = meta?.startedAt ? (meta.endedAt ? new Date(meta.endedAt).getTime() : now) - new Date(meta.startedAt).getTime() : NaN
  const liveClass = genuinelyRunning ? 'is-running' : meta?.status === 'paused' || meta?.status === 'partial' ? 'is-paused' : meta?.status === 'completed' ? 'is-done' : meta?.status === 'failed' ? 'is-failed' : ''
  const liveText = timelineSeq !== null ? 'Scan recording' : genuinelyRunning ? 'Live scan running' : meta ? STATUS_LABEL[meta.status] : 'Idle'
  const healthText: Record<typeof health, string> = {
    idle: 'Not connected', connecting: 'Connecting…', live: 'Streaming', reconnecting: 'Reconnecting…', ended: meta && !running ? 'Replayed from record' : 'Stream closed', error: 'Error',
  }
  const canControl = Boolean(meta && running && timelineSeq === null)
  const filtersActive = category !== 'all' || severity !== 'all' || evidenceFilter !== 'all' || query.trim() !== ''

  return (
    <div className="qg-rt" style={{ minHeight: '100%' }}>
      <div className="rt-shell">
        {/* ------------------------------ header ------------------------------ */}
        <header className="rt-panel rt-header">
          <div style={{ minWidth: 0 }}>
            <nav aria-label="Breadcrumb" className="rt-crumb">
              <span>Discovery</span><ChevronRight size={12} />
              <Link to="/dashboard/scanner">PQC Scanner</Link><ChevronRight size={12} />
              <span aria-current="page" style={{ color: 'var(--rt-primary)' }}>Real Time Scanning</span>
            </nav>
            <h1 className="rt-title">QGuard Helix Scanning Workflow</h1>
            <p className="rt-subtitle">Live discovery, cryptographic dependency mapping, and quantum vulnerability analysis across your digital ecosystem.</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span className={`rt-live ${liveClass}`} aria-live="polite"><span className="rt-dot" />{liveText}</span>
            <button type="button" className="rt-btn is-primary" onClick={() => { setConfigTargets([]); setConfigOpen(true) }}>
              <Play size={14} /> Start Live Scan
            </button>
          </div>
        </header>

        {meta && (
          <section className="rt-panel rt-statusbar" aria-label="Scan status">
            <Stat label="Scan" value={meta.name} title={meta.id} />
            <Stat label="Status" value={STATUS_LABEL[meta.status]} />
            <Stat label="Stage" value={meta.stage || '—'} title={meta.stage} />
            <Stat label="Elapsed" value={duration(elapsed)} />
            <Stat label="Started" value={meta.startedAt ? new Date(meta.startedAt).toLocaleTimeString() : '—'} />
            <Stat label="Assets discovered" value={summary.assetsDiscovered} />
            <Stat label="Quantum-vulnerable" value={summary.quantumExposedAssets} title="Assets with an open quantum-migration finding" />
            <Stat label="Targets" value={`${summary.targetsDone}/${summary.targetsTotal}`} />
            <Stat label="Stream" value={healthText[health]} title={live.lastHeartbeat ? `Last heartbeat ${new Date(live.lastHeartbeat).toLocaleTimeString()}` : undefined} />
          </section>
        )}

        {live.error && <div className="rt-banner is-error" role="alert">{live.error} <button type="button" className="rt-chip" onClick={() => live.setError(null)}>Dismiss</button></div>}
        {meta?.errorSummary && !running && <div className="rt-banner">Run notes: {meta.errorSummary}</div>}
        {notice && <div className="rt-banner">{notice} <button type="button" className="rt-chip" onClick={() => setNotice(null)}>Dismiss</button></div>}

        {/* ------------------------------ toolbar ------------------------------ */}
        <section className="rt-panel rt-toolbar" aria-label="Scan controls">
          <button type="button" className="rt-btn" disabled={!canControl || meta?.status === 'paused' || meta?.status === 'cancelling'} onClick={() => void live.control('pause')} title="Stops new targets from starting; in-flight targets finish"><Pause size={13} /> Pause</button>
          <button type="button" className="rt-btn" disabled={!canControl || meta?.status !== 'paused'} onClick={() => void live.control('resume')}><Play size={13} /> Resume</button>
          <button type="button" className="rt-btn is-danger" disabled={!canControl || meta?.status === 'cancelling'} onClick={() => void live.control('cancel')}><Square size={13} /> Cancel</button>
          <button type="button" className="rt-btn" disabled={!selectedId || !displayGraph.nodes[selectedId]?.targets[0] || !['asset', 'endpoint'].includes(displayGraph.nodes[selectedId]?.kind ?? '')}
            onClick={() => selectedId && void rescan(displayGraph.nodes[selectedId].targets[0])}><RotateCw size={13} /> Rescan selected</button>
          <span className="rt-sep" />
          <button type="button" className="rt-btn" onClick={() => { relayout(canvasGraph, memoryRef.current, visible); setLayoutVersion((v) => v + 1); requestAnimationFrame(fitToScreen) }}><LayoutGrid size={13} /> Auto layout</button>
          <button type="button" className="rt-btn" disabled={!latestFinding} onClick={() => latestFinding && (centerOn(latestFinding.id), selectNode(latestFinding.id, false))}><Crosshair size={13} /> Latest finding</button>
          <span className="rt-sep" />
          <button type="button" className="rt-btn" disabled={!runId} onClick={() => void live.download('json')}><FileJson size={13} /> Graph JSON</button>
          <button type="button" className="rt-btn" disabled={!runId} onClick={() => void exportPng()}><ImageIcon size={13} /> PNG</button>
          <button type="button" className="rt-btn" disabled={!runId} onClick={() => void live.download('csv')}><FileSpreadsheet size={13} /> Findings CSV</button>
          <button type="button" className="rt-btn" onClick={() => { void live.refreshRuns(); setHistoryOpen(true) }}><History size={13} /> Scan history</button>
        </section>

        {/* ------------------------------ filters ------------------------------ */}
        <section className="rt-panel rt-toolbar" aria-label="Filters">
          <div style={{ position: 'relative', flex: '1 1 220px', maxWidth: 320 }}>
            <Search size={13} style={{ position: 'absolute', left: 9, top: 9, color: 'var(--rt-ink-muted)' }} />
            <input className="rt-input" style={{ width: '100%', paddingLeft: 28 }} placeholder="Search hosts, certificates, algorithms…" value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search the graph" />
          </div>
          {CATEGORIES.map(([key, label]) => (
            <button key={key} type="button" className={`rt-chip${category === key ? ' is-on' : ''}`} aria-pressed={category === key} onClick={() => setCategory(key)}>{label}</button>
          ))}
          <select className="rt-input" value={severity} onChange={(event) => setSeverity(event.target.value as Severity | 'all')} aria-label="Criticality">
            <option value="all">All criticality</option>
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((value) => <option key={value} value={value}>{SEVERITY_LABEL[value]}</option>)}
          </select>
          <select className="rt-input" value={evidenceFilter} onChange={(event) => setEvidenceFilter(event.target.value as EvidenceFilter)} aria-label="Relationship evidence">
            <option value="all">All relationships</option>
            <option value="verified">Verified / observed only</option>
            <option value="inferred">Inferred only</option>
          </select>
          <button type="button" className={`rt-chip${withContext ? ' is-on' : ''}`} onClick={() => setWithContext((value) => !value)} aria-pressed={withContext}>Show neighbours</button>
          <button type="button" className={`rt-chip${showAddresses ? ' is-on' : ''}`} onClick={() => setShowAddresses((value) => !value)} aria-pressed={showAddresses}>Show IP addresses</button>
          {expandedGroups.size > 0 && <button type="button" className="rt-chip" onClick={() => setExpandedGroups(new Set())}>Collapse finding groups</button>}
          {(filtersActive || highlight || expanded.size > 0) && (
            <button type="button" className="rt-chip" onClick={() => { setCategory('all'); setSeverity('all'); setEvidenceFilter('all'); setQuery(''); setHighlight(null); setHighlightLabel(null); setExpanded(new Set()) }}>
              <X size={11} /> Clear
            </button>
          )}
        </section>

        {/* ------------------------------ main ------------------------------ */}
        <div className="rt-main">
          <div className="rt-canvas-column">
            <div className={`rt-canvas-stage${fullscreen ? ' is-fullscreen' : ''}`} ref={stageRef}>
              <div className="rt-stage-toolbar" role="group" aria-label="Canvas controls">
                <button type="button" className="rt-btn" onClick={fitToScreen}><Frame size={14} /> Fit to screen</button>
                <button type="button" className="rt-btn is-icon" aria-label="Zoom in" onClick={() => { takeViewport(); void flowRef.current?.zoomIn() }}><ZoomIn size={14} /></button>
                <button type="button" className="rt-btn is-icon" aria-label="Zoom out" onClick={() => { takeViewport(); void flowRef.current?.zoomOut() }}><ZoomOut size={14} /></button>
                <button type="button" className={`rt-btn${follow ? ' is-on' : ''}`} aria-pressed={follow} title="Keep the whole graph in view as nodes arrive" onClick={() => setFollow((value) => !value)}><Radar size={13} /> Follow live</button>
                <button type="button" className="rt-btn rt-fullscreen-button" ref={fullscreenButton} onClick={() => void toggleFullscreen()}>
                  {fullscreen ? <Minimize size={14} /> : <Maximize size={14} />}
                  {fullscreen ? 'Exit full screen' : 'Full screen'}
                </button>
              </div>
              <div className="rt-stage-content">
                <div className="rt-canvas-wrap" ref={canvasRef}>
                  <LiveCanvas
                    graph={canvasGraph}
                    visible={visible}
                    highlight={highlight}
                    selectedId={selectedId}
                    selectedEdgeId={selectedEdgeId}
                    flashId={flashId}
                    newSinceSeq={timelineSeq === null ? Math.max(newSince, baselineSeq) : Math.max(0, timelineSeq - 1)}
                    memory={memoryRef.current}
                    layoutVersion={layoutVersion}
                    activeTargets={activeTargets}
                    running={genuinelyRunning && timelineSeq === null || playing && meta?.status === 'running'}
                    onInit={onFlowInit}
                    onSelectNode={selectNode}
                    onSelectEdge={selectEdge}
                    onExpand={expandNode}
                    onContext={openContext}
                    onHover={trackPointer}
                    onUserMove={takeViewport}
                  />
                  {highlight && (
                    <div style={{ position: 'absolute', top: 10, left: '50%', transform: 'translateX(-50%)', zIndex: 6 }}>
                      <span className="rt-chip is-on" style={{ background: 'var(--rt-panel-solid)' }}>
                        {highlightLabel} <button type="button" onClick={() => { setHighlight(null); setHighlightLabel(null) }} aria-label="Clear focus" style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer' }}><X size={11} /></button>
                      </span>
                    </div>
                  )}
                  {!liveMeta && !live.loading && timelineSeq === null && (
                    <div className="rt-canvas-overlay">
                      <div className="rt-panel">
                        <Radar size={30} style={{ color: 'var(--rt-primary)' }} />
                        <h2 style={{ fontSize: 17, fontWeight: 900, margin: '10px 0 6px' }}>No live scan selected</h2>
                        <p className="rt-soft" style={{ fontSize: 12.5, lineHeight: 1.6, margin: 0 }}>
                          Start a scan against domains or endpoints you are authorized to assess. Assets, certificates, CAs, algorithms and findings
                          appear here one by one as the QGuard engines verify them — nothing is drawn until it is observed.
                        </p>
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 14, flexWrap: 'wrap' }}>
                          <button type="button" className="rt-btn is-primary" onClick={() => { setConfigTargets([]); setConfigOpen(true) }}><Play size={13} /> Start Live Scan</button>
                          <button type="button" className="rt-btn" onClick={() => { void live.refreshRuns(); setHistoryOpen(true) }}><History size={13} /> Open a previous scan</button>
                        </div>
                      </div>
                    </div>
                  )}
                  {live.loading && (
                    <div className="rt-canvas-overlay"><div className="rt-panel"><RefreshCw size={22} style={{ color: 'var(--rt-primary)' }} /><p className="rt-soft" style={{ fontSize: 12.5 }}>Loading scan record…</p></div></div>
                  )}
                </div>
                {tip && tipNode && !menu && !drawer && (
                  <div className="rt-tooltip" style={{ left: Math.max(8, Math.min(tip.x + 14, window.innerWidth - 308)), top: Math.min(tip.y + 14, window.innerHeight - 90) }}>
                    <div style={{ fontWeight: 800, color: 'var(--rt-ink)' }}>{tipNode.label}</div>
                    <div>{KIND_LABEL[tipNode.kind]} · {STATUS_WORD[tipNode.status]}</div>
                    {tipNode.targets.length > 0 && <div className="rt-muted">Targets: {tipNode.targets.slice(0, 3).join(', ')}{tipNode.targets.length > 3 ? '…' : ''}</div>}
                  </div>
                )}

                {menu && displayGraph.nodes[menu.id] && (
                  <>
                    <div style={{ position: 'fixed', inset: 0, zIndex: 79 }} onClick={() => setMenu(null)} onContextMenu={(event) => { event.preventDefault(); setMenu(null) }} />
                    <div className="rt-menu" style={{ left: Math.min(menu.x, window.innerWidth - 230), top: Math.min(menu.y, window.innerHeight - 280) }} role="menu">
                      <button type="button" role="menuitem" onClick={() => selectNode(menu.id)}>Inspect</button>
                      <button type="button" role="menuitem" onClick={() => focusMode(menu.id, 'focus')}>Focus (dim unrelated)</button>
                      <button type="button" role="menuitem" onClick={() => focusMode(menu.id, 'upstream')}>Trace upstream</button>
                      <button type="button" role="menuitem" onClick={() => focusMode(menu.id, 'downstream')}>Trace downstream</button>
                      <button type="button" role="menuitem" onClick={() => { setExpanded(new Set([menu.id])); setQuery(''); setCategory('all'); setHighlight(neighbours(displayGraph, menu.id)); setHighlightLabel(`Related to ${displayGraph.nodes[menu.id].label}`); setMenu(null) }}>Filter to related</button>
                      <button type="button" role="menuitem" onClick={() => { void navigator.clipboard?.writeText(menu.id); setMenu(null) }}>Copy identifier</button>
                      {['asset', 'endpoint'].includes(displayGraph.nodes[menu.id].kind) && displayGraph.nodes[menu.id].targets[0] && (
                        <button type="button" role="menuitem" onClick={() => void rescan(displayGraph.nodes[menu.id].targets[0])}>Rescan</button>
                      )}
                    </div>
                  </>
                )}

                {drawer && (selectedId || selectedEdgeId) && (
                  <Inspector
                    key={selectedId ?? selectedEdgeId}
                    graph={displayGraph}
                    events={events}
                    nodeId={selectedId}
                    edgeId={selectedEdgeId}
                    onClose={() => setDrawer(false)}
                    onSelectNode={(id) => { centerOn(id); selectNode(id) }}
                    onSelectEdge={selectEdge}
                    onFocus={(id) => focusMode(id, 'focus')}
                    onRescan={(target) => void rescan(target)}
                    canRescan={timelineSeq === null}
                    replaying={timelineSeq !== null}
                    width={inspectorWidth}
                    expanded={inspectorExpanded}
                    onResize={(width) => setInspectorWidth(Math.min(1600, Math.max(320, width)))}
                    onToggleExpanded={() => setInspectorExpanded((value) => !value)}
                  />
                )}

                <ConfigDialog open={configOpen} onClose={() => setConfigOpen(false)} token={live.token} limits={live.limits} initialTargets={configTargets}
                  onStart={async (input) => { await live.start(input); setNotice(null) }} />

                {historyOpen && <ScanHistory runs={live.runs} statusLabels={STATUS_LABEL}
                  onOpen={(id) => { live.openRun(id); setHistoryOpen(false) }}
                  onClose={() => setHistoryOpen(false)}
                />}
              </div>
              {events.length > 0 && (
                <div className="rt-panel rt-timeline">
                  <button type="button" className="rt-btn" onClick={() => { setTimelineSeq(0); setPlaying(true) }}>
                    <History size={14} /> Replay scan
                  </button>
                  {timelineSeq !== null && <button type="button" className="rt-btn" disabled={!playing && !replayNext} onClick={() => setPlaying((value) => !value)}>
                    {playing ? <Pause size={13} /> : <Play size={13} />}{playing ? 'Pause replay' : 'Resume replay'}
                  </button>}
                  <label className="rt-muted">Speed <select aria-label="Replay speed" className="rt-btn" value={playbackSpeed} onChange={(event) => setPlaybackSpeed(Number(event.target.value))}>
                    {[0.5, 1, 2, 4].map((speed) => <option key={speed} value={speed}>{speed}×</option>)}
                  </select></label>
                  <input type="range" min={0} max={graph.lastSeq} value={timelineSeq ?? graph.lastSeq} aria-label="Scan timeline"
                    onChange={(event) => { setPlaying(false); setTimelineSeq(Number(event.target.value)) }} />
                  <span className="rt-mono rt-muted" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                    {timelineSeq === null ? `Live · event #${graph.lastSeq}` : replayEvent ? `Event #${timelineSeq} · ${new Date(replayEvent.at).toLocaleTimeString()}` : 'Start of recording'}
                  </span>
                  {timelineSeq !== null && <button type="button" className="rt-chip is-on" onClick={() => { setPlaying(false); setTimelineSeq(null) }}>Back to live</button>}
                </div>
              )}
            </div>
            <p className="rt-muted" style={{ fontSize: 10.5, margin: '0 4px', lineHeight: 1.5 }}>
              Solid green = cryptographically validated · solid blue = directly observed · orange = migration exposure · red = critical / failed verification ·
              dashed gray = inferred (not proof). Click a node or wire for its evidence; double-click to expand; right-click for actions; drag to rearrange (relationships never change).
            </p>
          </div>

          {/* ------------------------------ sidebar ------------------------------ */}
          <aside className="rt-side">
            <section className="rt-panel" aria-label="Live scan summary">
              <div className="rt-side-head"><span className="rt-side-title"><Activity size={13} /> Live scan summary</span>
                <span className="rt-mono rt-muted" style={{ fontSize: 10.5 }}>{summary.progressPercent === null ? '—' : `${summary.progressPercent}%`}</span></div>
              <div style={{ padding: '8px 10px 0' }}>
                <div className={`rt-progress${running && summary.targetsDone === 0 ? ' is-indeterminate' : ''}`}><i style={{ width: `${summary.progressPercent ?? 0}%` }} /></div>
              </div>
              <div className="rt-summary">
                <Metric label="Assets discovered" value={summary.assetsDiscovered} />
                <Metric label="TLS endpoints" value={summary.endpointsInspected} hint={summary.endpointsFailed ? `${summary.endpointsFailed} unreachable` : undefined} />
                <Metric label="Certificates" value={summary.certificatesAnalyzed} />
                <Metric label="Chains validated" value={summary.chainsValidated} tone="validated" hint={summary.chainsFailed ? `${summary.chainsFailed} failed` : undefined} />
                <Metric label="Algorithms" value={summary.algorithmsObserved} />
                <Metric label="Quantum-exposed" value={summary.quantumExposedAssets} tone="high" />
                <Metric label="Critical findings" value={summary.findingsBySeverity.critical} tone="critical" />
                <Metric label="High findings" value={summary.findingsBySeverity.high} tone="high" />
                <Metric label="Unknown / incomplete" value={summary.unknownAssessments} tone="info" hint="Never counted as safe" />
                <Metric label="Open findings" value={summary.findingsTotal} />
              </div>
            </section>

            <section className="rt-panel" aria-label="Live activity">
              <div className="rt-side-head">
                <span className="rt-side-title"><span className="rt-live is-running" style={{ padding: 0, border: 'none', background: 'none' }}>{genuinelyRunning && <span className="rt-dot" />}</span> Live activity</span>
                <div style={{ display: 'flex', gap: 4 }}>
                  {(['live', 'findings', 'severity'] as const).map((mode) => (
                    <button key={mode} type="button" className={`rt-chip${feedMode === mode ? ' is-on' : ''}`} onClick={() => setFeedMode(mode)}>{mode === 'live' ? 'Chronological' : mode === 'findings' ? 'Findings' : 'By severity'}</button>
                  ))}
                </div>
              </div>
              <div className="rt-feed" aria-live="polite">
                {feed.length === 0 && <p className="rt-muted" style={{ fontSize: 11.5, padding: 10 }}>{meta ? 'Waiting for the first scanner observation…' : 'Activity from the scanner engines appears here as it happens.'}</p>}
                {feed.map((event) => {
                  const activity = event.activity!
                  const sev = activity.severity
                  return (
                    <button key={event.seq} type="button" className={`rt-feed-item${sev ? ` tone-${sev}` : ''}`} disabled={!activity.entityId || !displayGraph.nodes[activity.entityId]}
                      onClick={() => { if (activity.entityId) { centerOn(activity.entityId); selectNode(activity.entityId, false) } }}>
                      <span className="rt-feed-dot" />
                      <span style={{ minWidth: 0 }}>
                        <span style={{ display: 'flex', gap: 6, alignItems: 'baseline' }}>
                          <span className="rt-feed-title">{activity.title}</span>
                          <span className="rt-feed-time" style={{ marginLeft: 'auto' }}>{new Date(event.at).toLocaleTimeString()}</span>
                        </span>
                        <span className="rt-feed-detail">{activity.detail}</span>
                        <span className="rt-feed-time">{event.type}{sev ? ` · ${sev === 'validated' ? 'validated' : SEVERITY_LABEL[sev]}` : ''}</span>
                      </span>
                    </button>
                  )
                })}
              </div>
            </section>

            <section className="rt-panel" aria-label="Quantum findings">
              <div className="rt-side-head"><span className="rt-side-title"><AlertTriangle size={13} /> Quantum findings</span><span className="rt-mono rt-muted" style={{ fontSize: 10.5 }}>{findingsList.length}</span></div>
              <div className="rt-feed" style={{ maxHeight: 300 }}>
                {findingsList.length === 0 && <p className="rt-muted" style={{ fontSize: 11.5, padding: 10 }}>No findings yet. A finding only appears with an evidence record behind it.</p>}
                {findingsList.map((finding) => (
                  <button key={finding.id} type="button" className={`rt-feed-item tone-${finding.severity}`} onClick={() => { centerOn(finding.id); selectNode(finding.id) }}>
                    <span className="rt-feed-dot" />
                    <span style={{ minWidth: 0 }}>
                      <span className="rt-feed-title">{finding.title}</span>
                      <span className="rt-feed-detail">{SEVERITY_LABEL[finding.severity]} · {EXPOSURE_LABEL[finding.exposure]} · {finding.affectedTargets.length} target(s)</span>
                    </span>
                  </button>
                ))}
              </div>
            </section>
          </aside>
        </div>
      </div>


    </div>
  )
}
