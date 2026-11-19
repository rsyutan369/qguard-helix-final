/**
 * Live Migration command-center panels. Every panel takes the derived
 * `AgentWorkflowModel` (or a slice of it), never raw snapshot rows, so the
 * timeline, metrics, insights, logs, guardrails and checklist cannot disagree.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { csvCell } from '@/lib/csv'
import gsap from 'gsap'
import { Link } from 'react-router-dom'
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  Bell,
  BellOff,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDashed,
  Clock3,
  Copy,
  Cpu,
  Download,
  Gauge,
  History,
  ListChecks,
  MemoryStick,
  MinusCircle,
  Pause,
  Play,
  Radar,
  Search,
  ShieldAlert,
  ShieldCheck,
  Square,
  Terminal,
  Timer,
  X,
  XCircle,
  Zap,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  AGENT_META,
  WORKFLOW_AGENT_IDS,
  type AgentWorkflowModel,
  type ChecklistItem,
  type EventSeverity,
  type WorkflowAgentId,
  type WorkflowAgentNode,
  type WorkflowEvent,
  type WorkflowRisk,
} from '@/lib/migration/agent-workflow'
import {
  AGENT_VISUAL,
  PANEL,
  ProgressBar,
  ProgressRing,
  SEVERITY_TONE,
  STATUS_META,
  SUBPANEL,
  SectionTitle,
  Sparkline,
  StatusPill,
  TONE,
  bytes,
  clock,
  formatDuration,
  mix,
  prefersReducedMotion,
  timeAgo,
} from './_workflow-ui'

export type ConnectionState = 'live' | 'reconnecting' | 'stale' | 'historical'

export const CONNECTION_META: Record<ConnectionState, { label: string; color: string; detail: string }> = {
  live: { label: 'Live', color: TONE.green, detail: 'Stream connected — updates arrive as agents report.' },
  reconnecting: { label: 'Reconnecting', color: TONE.amber, detail: 'Stream dropped. Showing the last confirmed snapshot while reconnecting.' },
  stale: { label: 'Stale', color: TONE.red, detail: 'No confirmed update for over 2 minutes. Data on screen may be out of date.' },
  historical: { label: 'Historical', color: TONE.violet, detail: 'Viewing a finished run. Nothing in this view is executing.' },
}

function Chip({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <div title={title} className="flex min-w-0 items-center gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-2.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
      {children}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* A. Global execution header                                          */
/* ------------------------------------------------------------------ */

export function WorkflowHeader({
  model,
  connection,
  ageLabel,
  now,
  runs,
  planId,
  onSelectRun,
  controls,
  moreActions,
}: {
  model: AgentWorkflowModel
  connection: ConnectionState
  ageLabel: string
  now: number
  runs: Array<{ id: string; status: string; updatedAt: string | null }>
  planId: string | null
  onSelectRun: (id: string | null) => void
  controls: {
    canPause: boolean
    canResume: boolean
    canCancel: boolean
    pending: string
    onPause: () => void
    onResume: () => void
    onCancel: () => void
    pauseReason: string
  }
  moreActions: Array<{ label: string; icon: typeof Download; onClick: () => void; disabled?: boolean; tone?: string }>
}) {
  const conn = CONNECTION_META[connection]
  const elapsed = model.startedAt ? now - Date.parse(model.startedAt) : null
  const stage = model.currentStage ? AGENT_META[model.currentStage].label : '—'
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!menuOpen) return
    const close = (event: MouseEvent) => { if (!menuRef.current?.contains(event.target as globalThis.Node)) setMenuOpen(false) }
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape') setMenuOpen(false) }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', escape)
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('keydown', escape) }
  }, [menuOpen])

  return (
    <header className={cn(PANEL, 'overflow-visible p-4 sm:p-5', menuOpen && 'z-30')}>
      <div className="pointer-events-none absolute inset-0 overflow-hidden rounded-2xl">
        <div className="absolute -left-20 -top-24 h-56 w-[520px] rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="absolute -right-10 -top-20 h-48 w-[360px] rounded-full bg-violet-500/10 blur-3xl" />
      </div>
      <div className="relative grid gap-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1 basis-[420px]">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-[color:var(--lw-cyan)]/80">Qguard Helix</span>
              <span className="h-3 w-px bg-white/20" />
              <h1 className="text-2xl font-black tracking-tight text-white sm:text-[28px]">PQC Migration Workflow</h1>
              <span
                className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-black uppercase tracking-wider"
                style={{ color: conn.color, borderColor: `${mix(conn.color, 40)}`, background: `${mix(conn.color, 8)}` }}
                title={`${conn.detail} Last confirmed update ${ageLabel}.`}
              >
                <span className={cn('h-2 w-2 rounded-full', connection === 'live' && 'animate-pulse')} style={{ background: conn.color, boxShadow: `0 0 10px ${conn.color}` }} />
                {conn.label}
                <span className="font-mono text-[10px] font-semibold normal-case tracking-normal opacity-70">{ageLabel}</span>
              </span>
            </div>
            <p className="mt-1.5 text-sm text-white/55">
              Real-time execution of the post-quantum migration workflow — <span className="text-white/75">{model.statusReason}</span>
            </p>
          </div>

          <div role="group" aria-label="Workflow actions" className="flex max-w-full flex-wrap items-center gap-2">
            {controls.canResume && (
              <button
                type="button"
                onClick={controls.onResume}
                disabled={controls.pending === 'bulk:resume'}
                className="inline-flex h-11 items-center gap-2 rounded-xl border border-[color:var(--lw-green)]/50 bg-[color:var(--lw-green)]/12 px-4 text-sm font-bold text-[color:var(--lw-green)] transition hover:bg-[color:var(--lw-green)]/20 disabled:opacity-50"
              >
                <Play className="h-4 w-4" /> Resume Workflow
              </button>
            )}
            <button
              type="button"
              onClick={controls.onPause}
              disabled={!controls.canPause || controls.pending === 'bulk:pause'}
              title={controls.canPause ? 'Pause every running and queued migration job in this scope.' : controls.pauseReason}
              className="inline-flex h-11 items-center gap-2 rounded-xl border border-[color:var(--lw-red)]/55 bg-[color:var(--lw-red)]/12 px-4 text-sm font-bold text-[color:var(--lw-red)] shadow-[0_0_24px_rgba(248,113,113,0.15)] transition hover:bg-[color:var(--lw-red)]/20 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Pause className="h-4 w-4" /> Pause Workflow
            </button>
            <button
              type="button"
              onClick={controls.onCancel}
              disabled={!controls.canCancel}
              title={controls.canCancel ? 'Withdraw every unfinished job in this scope (kept on record).' : 'Nothing in this scope can be cancelled.'}
              className="inline-flex h-11 items-center gap-2 rounded-xl border border-white/15 bg-white/[0.04] px-3 text-sm font-bold text-white/70 transition hover:border-white/35 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Square className="h-3.5 w-3.5" /> Cancel
            </button>
            <label className="sr-only" htmlFor="lw-run-selector">Workflow run</label>
            <div className="relative">
              <History className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/45" aria-hidden="true" />
              <select
                id="lw-run-selector"
                value={planId || ''}
                onChange={(event) => onSelectRun(event.target.value || null)}
                className="h-11 max-w-[220px] appearance-none rounded-xl border border-white/12 bg-[var(--lw-field)] pl-9 pr-8 text-sm font-semibold text-white/80 outline-none transition hover:border-white/30 focus:border-[color:var(--lw-cyan)]/60"
              >
                <option value="">All runs (tenant)</option>
                {runs.map((run) => (
                  <option key={run.id} value={run.id}>
                    {run.id.length > 18 ? `${run.id.slice(0, 18)}…` : run.id} · {run.status || 'plan'}
                  </option>
                ))}
              </select>
              <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-white/45" aria-hidden="true" />
            </div>
            <div className="relative" ref={menuRef}>
              <button
                type="button"
                aria-haspopup="menu"
                aria-expanded={menuOpen}
                onClick={() => setMenuOpen((value) => !value)}
                className="inline-flex h-11 items-center gap-2 rounded-xl border border-white/12 bg-white/[0.04] px-3.5 text-sm font-semibold text-white/80 transition hover:border-white/30 hover:text-white"
              >
                More Actions <ChevronDown className="h-4 w-4" />
              </button>
              {menuOpen && (
                <div role="menu" className="absolute left-0 top-12 z-40 w-56 max-w-[calc(100vw-2rem)] overflow-hidden rounded-xl border border-white/12 bg-[var(--lw-panel-solid)] p-1 shadow-2xl backdrop-blur-xl sm:left-auto sm:right-0">
                  {moreActions.map((action) => (
                    <button
                      key={action.label}
                      role="menuitem"
                      type="button"
                      disabled={action.disabled}
                      onClick={() => { setMenuOpen(false); action.onClick() }}
                      className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-[13px] text-white/80 transition hover:bg-white/[0.07] hover:text-white disabled:opacity-40"
                    >
                      <action.icon className="h-4 w-4" style={{ color: action.tone || TONE.cyan }} />
                      {action.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-stretch gap-2">
          <Chip title={`${model.activeAgents} of 4 stages executing. ${model.onlineAgents} of ${model.enrolledAgents} enrolled agents sent a heartbeat in the last 10 minutes.`}>
            <Radar className="h-5 w-5 shrink-0 text-[color:var(--lw-cyan)]" aria-hidden="true" />
            <div>
              <div className="font-mono text-lg font-black leading-none text-white">{model.onlineAgents}/{model.enrolledAgents}</div>
              <div className="mt-0.5 text-[10px] text-white/50">Agents online · {model.activeAgents}/4 active</div>
            </div>
          </Chip>
          <Chip title={model.progressBasis}>
            <ProgressRing value={model.overallProgress} color={TONE.cyan} status={model.status} size={40} />
            <div>
              <div className="font-mono text-lg font-black leading-none text-white">{model.overallProgress === null ? '—' : `${model.overallProgress}%`}</div>
              <div className="mt-0.5 text-[10px] text-white/50">Overall progress</div>
            </div>
          </Chip>
          <Chip title={model.startedAt ? `Earliest recorded start of the active stages: ${new Date(model.startedAt).toLocaleString()}` : 'No stage is executing.'}>
            <Timer className="h-5 w-5 shrink-0 text-[color:var(--lw-cyan)]" aria-hidden="true" />
            <div>
              <div className="font-mono text-lg font-black leading-none text-white">{elapsed === null ? '—' : formatDuration(elapsed)}</div>
              <div className="mt-0.5 text-[10px] text-white/50">Elapsed · stage {stage}</div>
            </div>
          </Chip>
          <Chip title="Warnings and errors recorded in the last 24 hours.">
            <AlertTriangle className={cn('h-5 w-5 shrink-0', model.errors ? 'text-[color:var(--lw-red)]' : model.warnings ? 'text-[color:var(--lw-amber)]' : 'text-white/35')} aria-hidden="true" />
            <div>
              <div className="font-mono text-lg font-black leading-none text-white">{model.errors}<span className="text-white/40"> / </span>{model.warnings}</div>
              <div className="mt-0.5 text-[10px] text-white/50">Errors / warnings (24h)</div>
            </div>
          </Chip>
        </div>
      </div>
    </header>
  )
}

/* ------------------------------------------------------------------ */
/* Live notifications (upper-right stack)                              */
/* ------------------------------------------------------------------ */

export interface WorkflowNotification {
  id: string
  title: string
  message: string
  severity: EventSeverity
  at: string
  agent: WorkflowAgentId | null
  live: boolean
  action: { label: string; href: string }
}

export function NotificationStack({
  items,
  now,
  minSeverity,
  onMinSeverity,
  onDismiss,
  onNavigate,
}: {
  items: WorkflowNotification[]
  now: number
  minSeverity: 'warning' | 'error'
  onMinSeverity: (value: 'warning' | 'error') => void
  onDismiss: (id: string) => void
  onNavigate: (href: string, agent: WorkflowAgentId | null) => void
}) {
  const list = useRef<HTMLDivElement>(null)
  const seen = useRef(new Set<string>())
  useEffect(() => {
    if (!list.current) return
    const fresh = items.filter((item) => !seen.current.has(item.id))
    const firstPaint = seen.current.size === 0
    for (const item of items) seen.current.add(item.id)
    if (firstPaint || !fresh.length || prefersReducedMotion()) return
    const targets = fresh.map((item) => list.current!.querySelector(`[data-note="${CSS.escape(item.id)}"]`)).filter(Boolean)
    const tween = gsap.from(targets, { x: 40, opacity: 0, duration: 0.5, stagger: 0.08, ease: 'power3.out' })
    return () => { tween.kill() }
  }, [items])

  return (
    <aside className={cn(PANEL, 'flex h-full flex-col p-4')} aria-label="Live workflow notifications">
      <SectionTitle
        icon={Bell}
        title="Live Notifications"
        right={
          <button
            type="button"
            onClick={() => onMinSeverity(minSeverity === 'warning' ? 'error' : 'warning')}
            className="inline-flex items-center gap-1.5 rounded-md border border-white/10 px-2 py-1 text-[10px] font-bold text-white/60 transition hover:text-white"
            title="Notification preference — stored in this browser"
          >
            {minSeverity === 'warning' ? <Bell className="h-3 w-3" /> : <BellOff className="h-3 w-3" />}
            {minSeverity === 'warning' ? 'Warnings +' : 'Errors only'}
          </button>
        }
      />
      <div ref={list} className="mt-3 flex-1 space-y-2 overflow-y-auto pr-1" style={{ maxHeight: 392 }} aria-live="polite">
        {items.length === 0 ? (
          <div className={cn(SUBPANEL, 'grid h-full min-h-40 place-items-center p-4 text-center')}>
            <div>
              <ShieldCheck className="mx-auto mb-2 h-7 w-7 text-[color:var(--lw-green)]/70" />
              <div className="text-sm font-semibold text-white/80">No active alerts</div>
              <div className="mt-1 text-[11px] text-white/45">Alerts appear here only from recorded agent and job events.</div>
            </div>
          </div>
        ) : (
          items.map((item) => {
            const tone = SEVERITY_TONE[item.severity]
            const visual = item.agent ? AGENT_VISUAL[item.agent] : null
            const Icon = item.severity === 'critical' || item.severity === 'error' ? AlertOctagon : item.severity === 'success' ? CheckCircle2 : AlertTriangle
            return (
              <div
                key={item.id}
                data-note={item.id}
                className="group relative overflow-hidden rounded-xl border bg-[var(--lw-raised)] p-3"
                style={{ borderColor: `${mix(tone, 33)}`, boxShadow: `0 0 22px ${mix(tone, 12)}` }}
              >
                <div className="flex items-start gap-3">
                  <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border" style={{ borderColor: `${mix(tone, 40)}`, background: `${mix(tone, 8)}` }}>
                    <Icon className="h-4 w-4" style={{ color: tone }} aria-hidden="true" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-[13px] font-bold text-white">{item.title}</span>
                      <span className="ml-auto shrink-0 font-mono text-[10px] text-white/40">{timeAgo(item.at, now)}</span>
                    </div>
                    <p className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-white/60">{item.message}</p>
                    <div className="mt-2 flex items-center gap-2">
                      <button type="button" onClick={() => onNavigate(item.action.href, item.agent)} className="text-[11px] font-bold transition hover:brightness-125" style={{ color: tone }}>
                        {item.action.label} →
                      </button>
                      {visual && item.agent && (
                        <span className="rounded px-1.5 py-0.5 text-[9px] font-bold" style={{ color: visual.color, background: visual.soft }}>{AGENT_META[item.agent].label}</span>
                      )}
                      {item.live && <span className="rounded bg-[color:var(--lw-cyan)]/10 px-1.5 py-0.5 text-[9px] font-bold text-[color:var(--lw-cyan)]">LIVE</span>}
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  aria-label={`Dismiss ${item.title}`}
                  onClick={() => onDismiss(item.id)}
                  className="absolute right-1.5 top-1.5 rounded p-1 text-white/30 opacity-0 transition hover:text-white focus:opacity-100 group-hover:opacity-100"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            )
          })
        )}
      </div>
    </aside>
  )
}

/* ------------------------------------------------------------------ */
/* C. Execution timeline                                               */
/* ------------------------------------------------------------------ */

const SEVERITY_LABEL: Record<EventSeverity, string> = { info: 'Info', success: 'Success', warning: 'Warning', error: 'Error', critical: 'Critical' }

function AgentGlyph({ agent }: { agent: WorkflowAgentId }) {
  const visual = AGENT_VISUAL[agent]
  const Icon = visual.icon
  return (
    <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${mix(visual.color, 33)}`, background: visual.soft }}>
      <Icon className="h-3.5 w-3.5" style={{ color: visual.color }} aria-hidden="true" />
    </span>
  )
}

function eventBadge(event: WorkflowEvent) {
  if (event.status) return { label: STATUS_META[event.status].label, color: STATUS_META[event.status].color }
  return { label: SEVERITY_LABEL[event.severity], color: SEVERITY_TONE[event.severity] }
}

export function ExecutionTimeline({
  events,
  truncated,
  now,
  onOpenJob,
}: {
  events: WorkflowEvent[]
  truncated: boolean
  now: number
  onOpenJob: (jobId: string) => void
}) {
  const [agent, setAgent] = useState<'all' | WorkflowAgentId>('all')
  const [severity, setSeverity] = useState<'all' | EventSeverity>('all')
  const [source, setSource] = useState<'all' | WorkflowEvent['source']>('all')
  const [live, setLive] = useState(true)
  const [frozen, setFrozen] = useState<WorkflowEvent[] | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [limit, setLimit] = useState(40)
  const body = useRef<HTMLOListElement>(null)
  const seen = useRef(new Set<string>())

  const base = live ? events : frozen || events
  const filtered = useMemo(() => base.filter((event) =>
    (agent === 'all' || event.agent === agent)
    && (severity === 'all' || event.severity === severity)
    && (source === 'all' || event.source === source)), [agent, base, severity, source])
  const shown = filtered.slice(0, limit)

  // Timeline additions slide in — only events this tab has not rendered before.
  useEffect(() => {
    if (!body.current) return
    const firstPaint = seen.current.size === 0
    const fresh = shown.filter((event) => !seen.current.has(event.id))
    for (const event of shown) seen.current.add(event.id)
    if (firstPaint || !fresh.length || prefersReducedMotion()) return
    const targets = fresh.slice(0, 12).map((event) => body.current!.querySelector(`[data-evt="${CSS.escape(event.id)}"]`)).filter(Boolean)
    const tween = gsap.from(targets, { opacity: 0, x: -16, duration: 0.45, stagger: 0.05, ease: 'power2.out' })
    return () => { tween.kill() }
  }, [shown])

  const select = 'h-8 rounded-lg border border-white/12 bg-[var(--lw-field)] px-2 text-[11px] font-semibold text-white/75 outline-none focus:border-[color:var(--lw-cyan)]/60'

  return (
    <section className={cn(PANEL, 'flex min-h-[420px] flex-col p-4')} aria-labelledby="lw-timeline-title">
      <div className="flex flex-wrap items-center gap-2">
        <Activity className="h-4 w-4 text-[color:var(--lw-cyan)]" aria-hidden="true" />
        <h2 id="lw-timeline-title" className="text-sm font-bold text-white">Execution Timeline</h2>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <select aria-label="Filter by agent" value={agent} onChange={(event) => setAgent(event.target.value as typeof agent)} className={select}>
            <option value="all">All Agents</option>
            {WORKFLOW_AGENT_IDS.map((id) => <option key={id} value={id}>{AGENT_META[id].label}</option>)}
          </select>
          <select aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value as typeof severity)} className={select}>
            <option value="all">All severities</option>
            {(['critical', 'error', 'warning', 'success', 'info'] as EventSeverity[]).map((value) => <option key={value} value={value}>{SEVERITY_LABEL[value]}</option>)}
          </select>
          <select aria-label="Filter by event type" value={source} onChange={(event) => setSource(event.target.value as typeof source)} className={select}>
            <option value="all">All types</option>
            <option value="scan-frame">Scan frames</option>
            <option value="job-event">Job events</option>
            <option value="validation">Validation</option>
            <option value="heartbeat">Agent status</option>
            <option value="telemetry">Telemetry</option>
          </select>
          <button
            type="button"
            role="switch"
            aria-checked={live}
            onClick={() => { setFrozen(live ? events : null); setLive(!live) }}
            className="inline-flex items-center gap-2 text-[11px] font-semibold text-white/65"
          >
            Live Events
            <span className={cn('relative h-5 w-9 rounded-full transition', live ? 'bg-[var(--lw-green)]' : 'bg-white/15')}>
              <span className={cn('absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-all', live ? 'left-[18px]' : 'left-0.5')} />
            </span>
          </button>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className={cn(SUBPANEL, 'mt-3 grid flex-1 place-items-center p-6 text-center')}>
          <div>
            <CircleDashed className="mx-auto mb-2 h-7 w-7 text-white/30" />
            <div className="text-sm font-semibold text-white/75">{events.length ? 'No events match these filters' : 'No execution events recorded yet'}</div>
            <div className="mt-1 max-w-sm text-[11px] text-white/45">
              {events.length ? 'Clear a filter to see more.' : 'Events appear as agents post scan frames and migration jobs record execution, validation and rollback.'}
            </div>
          </div>
        </div>
      ) : (
        <ol ref={body} className="relative mt-3 flex-1 space-y-0.5 overflow-y-auto pr-1" style={{ maxHeight: 380 }}>
          <span className="absolute bottom-2 left-[7px] top-2 w-px bg-gradient-to-b from-cyan-400/50 via-white/10 to-transparent" aria-hidden="true" />
          {shown.map((event) => {
            const badge = eventBadge(event)
            const open = expanded === event.id
            return (
              <li key={event.id} data-evt={event.id} className="relative pl-6">
                <span className="absolute left-[3px] top-[13px] h-2.5 w-2.5 rounded-full border-2 border-[color:var(--lw-panel-solid)]" style={{ background: SEVERITY_TONE[event.severity], boxShadow: `0 0 8px ${SEVERITY_TONE[event.severity]}` }} aria-hidden="true" />
                <button
                  type="button"
                  onClick={() => setExpanded(open ? null : event.id)}
                  aria-expanded={open}
                  className="grid w-full grid-cols-[62px_minmax(0,auto)_minmax(0,1fr)_auto] items-center gap-2.5 rounded-lg px-2 py-1.5 text-left transition hover:bg-white/[0.04] sm:grid-cols-[62px_150px_minmax(0,1fr)_auto]"
                >
                  <span className="font-mono text-[11px] text-white/50" title={new Date(event.at).toLocaleString()}>{clock(event.at)}</span>
                  <span className="flex min-w-0 items-center gap-2">
                    <AgentGlyph agent={event.agent} />
                    <span className="hidden truncate text-[12px] font-semibold text-white/85 sm:inline">{AGENT_META[event.agent].label}</span>
                  </span>
                  <span className="truncate text-[12px] text-white/70" title={event.message}>{event.message}</span>
                  <span className="shrink-0 rounded-md border px-2 py-0.5 text-[10px] font-bold" style={{ color: badge.color, borderColor: `${mix(badge.color, 33)}`, background: `${mix(badge.color, 7)}` }}>
                    {badge.label}
                  </span>
                </button>
                {open && (
                  <div className={cn(SUBPANEL, 'mb-2 ml-2 mt-1 space-y-2 p-3 text-[11px]')}>
                    <div className="grid gap-x-4 gap-y-1 text-white/55 sm:grid-cols-2">
                      <span>Type <span className="font-mono text-white/80">{event.type}</span></span>
                      <span>Source <span className="text-white/80">{event.source}</span></span>
                      <span>Correlation <span className="font-mono text-white/80">{event.correlationId.slice(0, 28)}</span></span>
                      <span>Recorded <span className="text-white/80">{new Date(event.at).toLocaleString()} · {timeAgo(event.at, now)}</span></span>
                      {event.asset && <span className="sm:col-span-2">Target <span className="text-white/80">{event.asset}</span></span>}
                      {event.progress !== null && <span>Reported progress <span className="font-mono text-white/80">{event.progress}%</span></span>}
                    </div>
                    {Object.keys(event.detail).length > 0 && (
                      <pre className="qg-force-dark max-h-40 overflow-auto rounded-lg bg-[var(--lw-screen)] p-2 font-mono text-[10px] leading-relaxed text-cyan-100/80">{JSON.stringify(event.detail, null, 2)}</pre>
                    )}
                    {event.jobId && (
                      <button type="button" onClick={() => onOpenJob(event.jobId!)} className="font-bold text-[color:var(--lw-cyan)] hover:text-[color:var(--lw-cyan)]">Open job evidence →</button>
                    )}
                  </div>
                )}
              </li>
            )
          })}
        </ol>
      )}
      <div className="mt-2 flex items-center justify-between text-[10px] text-white/40">
        <span>
          {shown.length} of {filtered.length} shown{truncated ? ' · newest 400 retained' : ''}{!live ? ' · paused' : ''}
        </span>
        {filtered.length > shown.length && (
          <button type="button" onClick={() => setLimit((value) => value + 40)} className="font-bold text-[color:var(--lw-cyan)] hover:text-[color:var(--lw-cyan)]">Load more</button>
        )}
      </div>
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* E. Agent metrics + F. Vulnerability summary                         */
/* ------------------------------------------------------------------ */

function MetricTile({ icon: Icon, label, value, unit, series, color, note }: { icon: typeof Cpu; label: string; value: string; unit?: string; series: number[]; color: string; note: string }) {
  return (
    <div className={cn(SUBPANEL, 'flex min-h-[112px] flex-col p-3')} title={note}>
      <div className="flex items-center gap-2 text-[11px] text-white/55">
        <Icon className="h-4 w-4" style={{ color }} aria-hidden="true" />
        {label}
      </div>
      <div className="mt-1 font-mono text-xl font-black text-white">
        {value}
        {unit && value !== '—' && <span className="ml-0.5 text-xs font-semibold text-white/45">{unit}</span>}
      </div>
      <div className="mt-auto">
        {series.length > 1 ? <Sparkline values={series} color={color} /> : <div className="text-[10px] leading-tight text-white/35">{note}</div>}
      </div>
    </div>
  )
}

export function AgentMetricsPanel({
  node,
  model,
  latency,
}: {
  node: WorkflowAgentNode
  model: AgentWorkflowModel
  latency: { latest: number | null; series: number[] }
}) {
  const visual = AGENT_VISUAL[node.id]
  const m = node.metrics
  const perMinute = useMemo(() => {
    // Events per minute for the selected stage, last 30 minutes — from recorded events.
    const buckets = new Array(30).fill(0)
    const end = Date.parse(model.generatedAt)
    for (const event of model.events) {
      if (event.agent !== node.id) continue
      const age = Math.floor((end - Date.parse(event.at)) / 60000)
      if (age >= 0 && age < 30) buckets[29 - age] += 1
    }
    return buckets
  }, [model.events, model.generatedAt, node.id])
  const hasEvents = perMinute.some((value) => value > 0)
  const recentRate = hasEvents ? Math.round((perMinute.slice(-15).reduce((a, b) => a + b, 0) / 15) * 10) / 10 : null

  return (
    <section className={cn(PANEL, 'p-4')} aria-labelledby="lw-metrics-title">
      <div className="flex flex-wrap items-center gap-2">
        <Gauge className="h-4 w-4 text-[color:var(--lw-cyan)]" aria-hidden="true" />
        <h2 id="lw-metrics-title" className="text-sm font-bold text-white">Agent Metrics</h2>
        <span className="ml-auto rounded-md px-2 py-0.5 text-[10px] font-bold" style={{ color: visual.color, background: visual.soft }}>{node.label} · {m.reporting} reporting</span>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <MetricTile
          icon={Cpu}
          label="CPU load"
          value={m.cpuLoadPct === null ? '—' : String(m.cpuLoadPct)}
          unit="%"
          series={m.series.cpu}
          color={TONE.sky}
          note={m.reporting ? 'Host 1-min load ÷ cores, agent-reported. Windows hosts do not report load.' : `No ${node.label} agent is reporting host telemetry.`}
        />
        <MetricTile
          icon={MemoryStick}
          label="Memory used"
          value={m.memoryUsedPct === null ? '—' : String(m.memoryUsedPct)}
          unit="%"
          series={m.series.memory}
          color={TONE.violet}
          note={m.reporting ? `Host memory, agent-reported. Agent process RSS ${bytes(m.agentRssBytes)}.` : `No ${node.label} agent is reporting host telemetry.`}
        />
        <MetricTile
          icon={Zap}
          label="Events / min"
          value={recentRate === null ? '—' : String(recentRate)}
          series={hasEvents ? perMinute : []}
          color={TONE.green}
          note={hasEvents ? 'Recorded events for this stage, last 15 minutes.' : 'No events recorded for this stage in the last 30 minutes.'}
        />
        <MetricTile
          icon={Activity}
          label="API latency"
          value={latency.latest === null ? '—' : String(latency.latest)}
          unit="ms"
          series={latency.series}
          color={TONE.amber}
          note="Round-trip of the live snapshot request, measured by this browser."
        />
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px] sm:grid-cols-4">
        {[
          ['Completed', node.jobs ? String(node.jobs.completed) : node.units ? String(node.units.done) : '—'],
          ['Failed', node.jobs ? String(node.jobs.failed) : String(node.errors)],
          ['Scans run', m.scanCount === null ? '—' : String(m.scanCount)],
          ['Queue depth', m.queueDepth === null ? '—' : String(m.queueDepth)],
        ].map(([label, value]) => (
          <div key={label} className="flex items-center justify-between gap-2 border-b border-white/[0.06] pb-1">
            <dt className="text-white/45">{label}</dt>
            <dd className="font-mono font-bold text-white/85">{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

const SEVERITY_ROWS = [
  { key: 'critical', label: 'Critical', color: TONE.rose },
  { key: 'high', label: 'High', color: 'var(--lw-orange)' },
  { key: 'medium', label: 'Medium', color: TONE.amber },
  { key: 'low', label: 'Low', color: TONE.green },
] as const

export function VulnerabilitySummaryPanel({ model, degraded }: { model: AgentWorkflowModel; degraded: boolean }) {
  const v = model.vulnerabilities
  const radius = 42
  const circumference = 2 * Math.PI * radius
  let offset = 0
  const arcs = SEVERITY_ROWS.map((row) => {
    const value = v[row.key]
    const length = v.total ? (value / v.total) * circumference : 0
    const arc = { ...row, value, length, offset }
    offset += length
    return arc
  })
  const readiness = v.readiness
  const safePct = readiness.inventory ? Math.round(((readiness.quantumSafe ?? 0) / readiness.inventory) * 100) : null

  return (
    <section className={cn(PANEL, 'p-4')} aria-labelledby="lw-vuln-title">
      <div className="flex flex-wrap items-center gap-2">
        <ShieldAlert className="h-4 w-4 text-[color:var(--lw-red)]" aria-hidden="true" />
        <h2 id="lw-vuln-title" className="text-sm font-bold text-white">Vulnerability Summary</h2>
        <span className="text-[10px] font-semibold text-white/40">(evidence)</span>
        <Link to="/dashboard/crypto-exposure" className="ml-auto text-[11px] font-bold text-[color:var(--lw-cyan)] hover:text-[color:var(--lw-cyan)]">Drill down →</Link>
      </div>
      {v.total === 0 ? (
        <div className={cn(SUBPANEL, 'mt-3 p-4 text-center text-[12px] text-white/55')}>
          {degraded ? 'Exposure records could not be read — status unknown, not clean.' : 'No cryptographic exposures recorded. Run an authorised scan to assess the estate.'}
        </div>
      ) : (
        <div className="mt-3 grid grid-cols-[112px_minmax(0,1fr)] items-center gap-4">
          <div className="relative h-28 w-28">
            <svg viewBox="0 0 100 100" className="-rotate-90" aria-hidden="true">
              <circle cx="50" cy="50" r={radius} strokeWidth="9" fill="none" style={{ stroke: 'var(--lw-track)' }} />
              {arcs.map((arc) => arc.length > 0 && (
                <circle key={arc.key} cx="50" cy="50" r={radius} strokeWidth="9" fill="none" strokeDasharray={`${arc.length} ${circumference - arc.length}`} strokeDashoffset={-arc.offset} style={{ stroke: arc.color, filter: `drop-shadow(0 0 4px ${mix(arc.color, 53)})` }} />
              ))}
            </svg>
            <div className="absolute inset-0 grid place-items-center text-center">
              <div>
                <div className="font-mono text-xl font-black text-white">{v.total.toLocaleString('en-US')}</div>
                <div className="text-[9px] leading-tight text-white/45">exposures</div>
              </div>
            </div>
          </div>
          <ul className="space-y-1.5">
            {SEVERITY_ROWS.map((row) => (
              <li key={row.key}>
                <Link to={`/dashboard/crypto-exposure?severity=${row.key}`} className="flex items-center gap-2 rounded-md px-1.5 py-1 text-[12px] transition hover:bg-white/[0.05]">
                  <span className="h-2.5 w-2.5 rounded-sm" style={{ background: row.color }} aria-hidden="true" />
                  <span className="text-white/70">{row.label}</span>
                  <span className="ml-auto font-mono font-bold text-white">{v[row.key].toLocaleString('en-US')}</span>
                  <ChevronRight className="h-3 w-3 text-white/30" aria-hidden="true" />
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
      {v.categories.length > 0 && (
        <div className="mt-3 space-y-1.5">
          {v.categories.slice(0, 4).map((category) => (
            <div key={category.key} className="grid grid-cols-[110px_minmax(0,1fr)_auto] items-center gap-2 text-[11px]">
              <span className="truncate text-white/60">{category.label}</span>
              <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.07]">
                <div className="h-full rounded-full bg-gradient-to-r from-[color:var(--lw-red)] to-[color:var(--lw-amber)]" style={{ width: `${Math.max(4, (category.count / Math.max(1, v.categories[0].count)) * 100)}%` }} />
              </div>
              <span className="font-mono text-white/70">{category.count}</span>
            </div>
          ))}
        </div>
      )}
      <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] sm:grid-cols-4">
        <div className={cn(SUBPANEL, 'p-2')}><div className="text-white/45">Affected assets</div><div className="font-mono text-sm font-bold text-white">{v.affectedAssets === null ? 'Unknown' : v.affectedAssets}{v.sampled ? '+' : ''}</div></div>
        <div className={cn(SUBPANEL, 'p-2')} title={readiness.inventory === null ? 'Inventory could not be read.' : `${readiness.quantumSafe ?? 0} quantum-safe of ${readiness.inventory} inventory items`}>
          <div className="text-white/45">PQC-safe inventory</div><div className="font-mono text-sm font-bold text-[color:var(--lw-green)]">{safePct === null ? '—' : `${safePct}%`}</div>
        </div>
        <div className={cn(SUBPANEL, 'p-2')} title="Approved remediation jobs ready for a Patcher"><div className="text-white/45">Remediation-ready</div><div className="font-mono text-sm font-bold text-[color:var(--lw-amber)]">{v.remediationEligible}</div></div>
        <div className={cn(SUBPANEL, 'p-2')} title="Approved, undispatched-blocker-free cutovers"><div className="text-white/45">Cutover-ready</div><div className="font-mono text-sm font-bold text-[color:var(--lw-violet)]">{v.migrationReady}</div></div>
      </div>
      {v.sampled && <p className="mt-2 text-[10px] text-white/40">Categories and affected assets computed from the first {v.sampleSize.toLocaleString('en-US')} of {v.total.toLocaleString('en-US')} exposure records.</p>}
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* D. Selected agent insights                                          */
/* ------------------------------------------------------------------ */

export function AgentInsightsPanel({
  node,
  model,
  now,
  onNavigate,
  onSelect,
}: {
  node: WorkflowAgentNode
  model: AgentWorkflowModel
  now: number
  onNavigate: (href: string) => void
  onSelect: (id: WorkflowAgentId) => void
}) {
  const visual = AGENT_VISUAL[node.id]
  const Icon = visual.icon
  const upstream = node.dependsOn ? model.nodes.find((item) => item.id === node.dependsOn) : null
  const events = model.events.filter((event) => event.agent === node.id).slice(0, 4)
  const output = node.latestEvent ? { type: node.latestEvent.type, at: node.latestEvent.at, message: node.latestEvent.message, ...node.latestEvent.detail } : null
  const [copied, setCopied] = useState(false)
  const panel = useRef<HTMLElement>(null)
  useEffect(() => {
    if (!panel.current || prefersReducedMotion()) return
    const tween = gsap.fromTo(panel.current.querySelectorAll('[data-reveal]'), { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.35, stagger: 0.04, ease: 'power2.out' })
    return () => { tween.kill() }
  }, [node.id])
  const duration = node.startedAt ? (node.completedAt ? Date.parse(node.completedAt) : now) - Date.parse(node.startedAt) : null

  return (
    <section ref={panel} className={cn(PANEL, 'flex flex-col p-4')} aria-labelledby="lw-insights-title" style={{ borderColor: `${mix(visual.color, 25)}` }}>
      <div className="flex items-center gap-2">
        <Radar className="h-4 w-4 text-[color:var(--lw-cyan)]" aria-hidden="true" />
        <h2 id="lw-insights-title" className="text-sm font-bold text-white">Current Agent Insights</h2>
        <div className="ml-auto flex gap-1" role="tablist" aria-label="Choose agent">
          {WORKFLOW_AGENT_IDS.map((id) => {
            const AgentIcon = AGENT_VISUAL[id].icon
            return (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={id === node.id}
                aria-label={AGENT_META[id].label}
                onClick={() => onSelect(id)}
                className="grid h-7 w-7 place-items-center rounded-md border transition"
                style={{ borderColor: id === node.id ? AGENT_VISUAL[id].color : 'rgba(255,255,255,0.1)', background: id === node.id ? AGENT_VISUAL[id].soft : 'transparent' }}
              >
                <AgentIcon className="h-3.5 w-3.5" style={{ color: AGENT_VISUAL[id].color }} />
              </button>
            )
          })}
        </div>
      </div>

      <div data-reveal className={cn(SUBPANEL, 'mt-3 flex items-center gap-3 p-3')}>
        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border" style={{ borderColor: `${mix(visual.color, 40)}`, background: visual.soft }}>
          <Icon className="h-5 w-5" style={{ color: visual.color }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[15px] font-bold text-white">{node.label} Agent</div>
          <div className="truncate text-[11px] text-white/50">{node.purpose}</div>
        </div>
        <StatusPill status={node.status} size="md" />
      </div>

      <div data-reveal className="mt-3">
        <div className="text-[12px] font-bold text-white/85">Current Task</div>
        <div className={cn(SUBPANEL, 'mt-1.5 p-3')}>
          <div className="text-[13px] font-semibold text-white">{node.currentTask}</div>
          <p className="mt-1 text-[11px] leading-relaxed text-white/55">{node.reason}</p>
          <div className="mt-2.5 flex items-center gap-3">
            <div className="flex-1"><ProgressBar value={node.status === 'completed' ? 100 : node.progress} color={visual.color} active={node.status === 'running' || node.status === 'retrying'} /></div>
            <span className="font-mono text-[12px] font-bold" style={{ color: visual.color }}>{node.status === 'completed' ? '100%' : node.progress === null ? 'n/m' : `${node.progress}%`}</span>
          </div>
          <div className="mt-1.5 flex flex-wrap justify-between gap-2 text-[10px] text-white/45">
            <span>{node.units ? `${node.units.done} of ${node.units.total} ${node.units.label}` : node.progress === null ? 'Progress not measurable for this stage right now' : 'Agent-reported stage progress'}</span>
            <span>{node.startedAt ? `Started ${clock(node.startedAt)} · ${formatDuration(duration)}` : 'Not started'}</span>
          </div>
        </div>
      </div>

      <div data-reveal className="mt-3 grid grid-cols-2 gap-2 text-[11px]">
        {node.findings.map((finding) => (
          <div key={finding.label} className={cn(SUBPANEL, 'flex items-center justify-between gap-2 px-2.5 py-1.5')}>
            <span className="truncate text-white/55">{finding.label}</span>
            <span className="font-mono font-bold" style={{ color: SEVERITY_TONE[finding.tone] }}>{finding.value}</span>
          </div>
        ))}
      </div>

      <div data-reveal className="mt-3 space-y-1.5 text-[11px]">
        <div className="flex items-center justify-between gap-2">
          <span className="text-white/50">Dependency</span>
          {upstream ? (
            <button type="button" onClick={() => onSelect(upstream.id)} className="inline-flex items-center gap-1.5 font-semibold text-white/80 hover:text-white">
              {upstream.label} · <span style={{ color: STATUS_META[upstream.status].color }}>{STATUS_META[upstream.status].label}</span>
            </button>
          ) : <span className="text-white/70">None — first stage</span>}
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="text-white/50">Fleet</span>
          <span className="text-white/80">{node.fleet.online}/{node.fleet.enrolled} online{node.fleet.authorised !== null ? ` · ${node.fleet.authorised} authorised to write` : ' · read-only role'}</span>
        </div>
        {node.fleet.agents.slice(0, 3).map((agent) => (
          <div key={agent.id} className="flex items-center gap-2 pl-2 text-white/60">
            <span className={cn('h-1.5 w-1.5 rounded-full', agent.online ? 'bg-[var(--lw-green)]' : 'bg-white/25')} aria-hidden="true" />
            <span className="truncate">{agent.name}</span>
            <span className="ml-auto shrink-0 font-mono text-[10px] text-white/40">{agent.version ? `v${agent.version} · ` : ''}{agent.online ? 'online' : `seen ${timeAgo(agent.lastSeenAt, now)}`}</span>
          </div>
        ))}
      </div>

      <div data-reveal className="mt-3 flex flex-wrap gap-1.5">
        {node.outputs.map((item) => (
          <button key={item.label} type="button" onClick={() => onNavigate(item.href)} className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-[10px] text-white/60 transition hover:border-white/25 hover:text-white">
            {item.label} <span className="font-mono font-bold text-white">{item.value}</span>
          </button>
        ))}
      </div>

      {events.length > 0 && (
        <div data-reveal className="mt-3 space-y-1">
          <div className="text-[12px] font-bold text-white/85">Latest events</div>
          {events.map((event) => (
            <div key={event.id} className="flex items-center gap-2 text-[11px]">
              <span className="font-mono text-white/40">{clock(event.at)}</span>
              <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEVERITY_TONE[event.severity] }} aria-hidden="true" />
              <span className="truncate text-white/70">{event.message}</span>
            </div>
          ))}
        </div>
      )}

      <div data-reveal className="mt-3">
        <div className="flex items-center gap-2">
          <span className="text-[12px] font-bold text-white/85">Live Output</span>
          <span className="text-[10px] text-white/40">latest recorded event · redacted</span>
          {output && (
            <button
              type="button"
              onClick={() => { void navigator.clipboard?.writeText(JSON.stringify(output, null, 2)).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }) }}
              className="ml-auto inline-flex items-center gap-1 rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-white/55 hover:text-white"
              aria-label="Copy live output"
            >
              <Copy className="h-3 w-3" /> {copied ? 'Copied' : 'Copy'}
            </button>
          )}
        </div>
        <pre className="qg-force-dark qg-lw-terminal mt-1.5 max-h-36 overflow-auto rounded-lg border border-white/[0.07] bg-[var(--lw-screen)] p-2.5 font-mono text-[10.5px] leading-relaxed text-cyan-100/85">
          {output ? JSON.stringify(output, null, 2) : '// No event recorded for this stage yet.'}
        </pre>
      </div>

      <div data-reveal className="mt-3 rounded-xl border p-3 text-[11px]" style={{ borderColor: `${mix(visual.color, 25)}`, background: visual.soft }}>
        <div className="font-bold" style={{ color: visual.color }}>Next eligible step</div>
        <p className="mt-0.5 leading-relaxed text-white/75">{node.nextAction}</p>
        <button type="button" onClick={() => onNavigate(node.nextHref)} className="mt-1.5 font-bold text-white hover:underline">Go →</button>
      </div>
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* Phase 7. Execution logs                                             */
/* ------------------------------------------------------------------ */

const LEVEL: Record<EventSeverity, { tag: string; color: string }> = {
  info: { tag: 'INFO', color: '#7dd3fc' },
  success: { tag: 'OK', color: TONE.green },
  warning: { tag: 'WARN', color: TONE.amber },
  error: { tag: 'ERROR', color: TONE.red },
  critical: { tag: 'CRIT', color: TONE.rose },
}

export function ExecutionLogs({
  events,
  streamLabel,
  streamColor,
  onServerExport,
  exportPending,
}: {
  events: WorkflowEvent[]
  streamLabel: string
  streamColor: string
  onServerExport: (format: 'csv' | 'json') => void
  exportPending: boolean
}) {
  const [agent, setAgent] = useState<'all' | WorkflowAgentId>('all')
  const [level, setLevel] = useState<'all' | 'warning' | 'error'>('all')
  const [query, setQuery] = useState('')
  const [follow, setFollow] = useState(true)
  const box = useRef<HTMLDivElement>(null)

  const lines = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return [...events]
      .filter((event) =>
        (agent === 'all' || event.agent === agent)
        && (level === 'all' || (level === 'warning' ? ['warning', 'error', 'critical'].includes(event.severity) : ['error', 'critical'].includes(event.severity)))
        && (!needle || `${event.message} ${event.type} ${event.asset || ''} ${event.correlationId}`.toLowerCase().includes(needle)))
      .slice(0, 300)
      .reverse()
  }, [agent, events, level, query])

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight
  }, [follow, lines])

  const exportVisible = () => {
    const header = 'timestamp,agent,level,type,message,target,correlation_id'
    const rows = lines.map((event) => [event.at, AGENT_META[event.agent].label, LEVEL[event.severity].tag, event.type, event.message, event.asset || '', event.correlationId].map(csvCell).join(','))
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `qguard-agent-execution-log-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  const select = 'h-8 rounded-lg border border-white/12 bg-[var(--lw-field)] px-2 text-[11px] font-semibold text-white/75 outline-none focus:border-[color:var(--lw-cyan)]/60'

  return (
    <section className={cn(PANEL, 'flex min-h-[340px] flex-col p-4')} aria-labelledby="lw-logs-title">
      <div className="flex flex-wrap items-center gap-2">
        <Terminal className="h-4 w-4 text-[color:var(--lw-cyan)]" aria-hidden="true" />
        <h2 id="lw-logs-title" className="text-sm font-bold text-white">Agent Execution Logs</h2>
        <span className="inline-flex items-center gap-1.5 text-[10px] font-bold" style={{ color: streamColor }}>
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: streamColor }} /> {streamLabel}
        </span>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <select aria-label="Log agent filter" value={agent} onChange={(event) => setAgent(event.target.value as typeof agent)} className={select}>
            <option value="all">All agents</option>
            {WORKFLOW_AGENT_IDS.map((id) => <option key={id} value={id}>{AGENT_META[id].label}</option>)}
          </select>
          <select aria-label="Log level filter" value={level} onChange={(event) => setLevel(event.target.value as typeof level)} className={select}>
            <option value="all">All levels</option>
            <option value="warning">Warnings +</option>
            <option value="error">Errors only</option>
          </select>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/35" aria-hidden="true" />
            <input
              type="search"
              aria-label="Search logs"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search logs…"
              className="h-8 w-40 rounded-lg border border-white/12 bg-[var(--lw-field)] pl-7 pr-2 text-[11px] text-white/80 outline-none placeholder:text-white/30 focus:border-[color:var(--lw-cyan)]/60"
            />
          </div>
          <button type="button" onClick={exportVisible} disabled={!lines.length} title="Export the filtered lines (CSV)" className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-white/12 px-2 text-[11px] font-semibold text-white/70 transition hover:text-white disabled:opacity-40">
            <Download className="h-3.5 w-3.5" /> Lines
          </button>
          <button type="button" onClick={() => onServerExport('json')} disabled={exportPending} title="Full server-side export of the live migration record (JSON)" className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-[color:var(--lw-cyan)]/30 bg-[color:var(--lw-cyan)]/10 px-2 text-[11px] font-semibold text-[color:var(--lw-cyan)] transition hover:bg-[color:var(--lw-cyan)]/20 disabled:opacity-40">
            <Download className="h-3.5 w-3.5" /> Full export
          </button>
        </div>
      </div>
      <div
        ref={box}
        onScroll={(event) => {
          const el = event.currentTarget
          setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24)
        }}
        className="qg-force-dark qg-lw-terminal mt-3 flex-1 overflow-y-auto rounded-xl border border-white/[0.07] bg-[var(--lw-screen)] p-3 font-mono text-[11.5px] leading-relaxed"
        style={{ maxHeight: 300 }}
        role="log"
        aria-live="off"
      >
        {lines.length === 0 ? (
          <div className="grid h-40 place-items-center text-center text-white/35">
            <div>
              <Terminal className="mx-auto mb-2 h-6 w-6" />
              {events.length ? 'No log lines match.' : 'No agent execution recorded yet. Lines appear as agents report.'}
            </div>
          </div>
        ) : (
          lines.map((event) => (
            <div key={event.id} className="flex gap-2 whitespace-pre-wrap break-words">
              <span className="shrink-0 text-white/35">{clock(event.at)}</span>
              <span className="w-[54px] shrink-0 font-bold" style={{ color: LEVEL[event.severity].color }}>[{LEVEL[event.severity].tag}]</span>
              <span className="shrink-0" style={{ color: AGENT_VISUAL[event.agent].color }}>{AGENT_META[event.agent].label.split(' ')[0]}</span>
              <span className="min-w-0 text-white/75">{event.message}{event.asset ? <span className="text-white/35"> · {event.asset}</span> : null}</span>
            </div>
          ))
        )}
      </div>
      <div className="mt-2 text-[10px] text-white/35">
        {lines.length} line(s) · newest 300 rendered · credentials, keys and tokens redacted server-side
        {!follow && <button type="button" onClick={() => setFollow(true)} className="ml-2 font-bold text-[color:var(--lw-cyan)]">Jump to latest</button>}
      </div>
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* Phase 6B. PQC Risks & Guardrails                                    */
/* ------------------------------------------------------------------ */

export function RisksPanel({
  risks,
  onHover,
  onNavigate,
}: {
  risks: WorkflowRisk[]
  onHover: (agent: WorkflowAgentId | null) => void
  onNavigate: (href: string, agent: WorkflowAgentId) => void
}) {
  return (
    <section className={cn(PANEL, 'flex min-h-[340px] flex-col p-4')} aria-labelledby="lw-risks-title" style={{ borderColor: risks.some((risk) => risk.severity === 'critical') ? 'rgba(244,63,94,0.35)' : undefined }}>
      <div className="flex items-center gap-2">
        <AlertOctagon className="h-4 w-4 text-[color:var(--lw-rose)]" aria-hidden="true" />
        <h2 id="lw-risks-title" className="text-sm font-bold text-white">PQC Risks &amp; Guardrails</h2>
        <span className="ml-auto text-[10px] text-white/40">{risks.length} active</span>
      </div>
      <ul className="mt-3 flex-1 space-y-2 overflow-y-auto pr-1" style={{ maxHeight: 310 }}>
        {risks.length === 0 ? (
          <li className={cn(SUBPANEL, 'grid h-40 place-items-center p-4 text-center')}>
            <div>
              <ShieldCheck className="mx-auto mb-2 h-7 w-7 text-[color:var(--lw-green)]/70" />
              <div className="text-sm font-semibold text-white/80">No guardrail violations recorded</div>
              <div className="mt-1 text-[11px] text-white/45">Every risk shown here is derived from a recorded block, finding or failed check.</div>
            </div>
          </li>
        ) : risks.map((risk) => {
          const tone = SEVERITY_TONE[risk.severity]
          const visual = AGENT_VISUAL[risk.agent]
          return (
            <li
              key={risk.id}
              onMouseEnter={() => onHover(risk.agent)}
              onMouseLeave={() => onHover(null)}
              onFocus={() => onHover(risk.agent)}
              onBlur={() => onHover(null)}
              className="relative overflow-hidden rounded-xl border bg-gradient-to-r p-3 transition hover:brightness-110"
              style={{ borderColor: `${mix(tone, 33)}`, backgroundImage: `linear-gradient(90deg, ${mix(tone, 10)}, transparent 60%)` }}
            >
              <span className="absolute inset-y-0 left-0 w-1" style={{ background: tone, boxShadow: `0 0 12px ${tone}` }} aria-hidden="true" />
              <div className="flex items-start gap-3 pl-1">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" style={{ color: tone }} aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[13px] font-bold text-white">{risk.title}</span>
                    <span className="rounded px-1.5 py-0.5 text-[9px] font-black uppercase" style={{ color: tone, background: `${mix(tone, 12)}` }}>{risk.severity}</span>
                  </div>
                  <p className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-white/60">{risk.detail}</p>
                  <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[10px]">
                    <span className="rounded px-1.5 py-0.5 font-bold" style={{ color: visual.color, background: visual.soft }}>{AGENT_META[risk.agent].label}</span>
                    <span className="text-white/35">evidence: {risk.evidence}</span>
                    {risk.affected.length > 0 && <span className="truncate text-white/45">· {risk.affected.join(', ')}</span>}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate(risk.action.href, risk.agent)}
                  className="shrink-0 rounded-lg border px-2.5 py-1 text-[11px] font-bold transition hover:brightness-125"
                  style={{ color: tone, borderColor: `${mix(tone, 40)}`, background: `${mix(tone, 8)}` }}
                >
                  {risk.action.label}
                </button>
              </div>
            </li>
          )
        })}
      </ul>
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* Phase 6C. Safe migration checklist                                  */
/* ------------------------------------------------------------------ */

const CHECK_META = {
  verified: { icon: CheckCircle2, color: TONE.green, label: 'Verified' },
  pending: { icon: Clock3, color: 'var(--lw-slate)', label: 'Pending' },
  failed: { icon: XCircle, color: TONE.red, label: 'Failed' },
  not_applicable: { icon: MinusCircle, color: 'var(--lw-slate)', label: 'Not applicable' },
} as const

export function SafetyChecklistPanel({
  items,
  jobs,
  selectedJobId,
  onSelectJob,
}: {
  items: ChecklistItem[]
  jobs: Array<{ id: string; asset: string; status: string }>
  selectedJobId: string
  onSelectJob: (id: string) => void
}) {
  const list = useRef<HTMLUListElement>(null)
  const previous = useRef<Record<string, string>>({})
  const jobKey = useRef(selectedJobId)
  // A checkmark pops ONLY when that safeguard transitions to verified for the
  // same job — not when the operator opens the panel or switches jobs.
  useEffect(() => {
    const switched = jobKey.current !== selectedJobId
    jobKey.current = selectedJobId
    const flips = items.filter((item) => !switched && previous.current[item.id] && previous.current[item.id] !== 'verified' && item.state === 'verified')
    previous.current = Object.fromEntries(items.map((item) => [item.id, item.state]))
    if (!flips.length || !list.current || prefersReducedMotion()) return
    const targets = flips.map((item) => list.current!.querySelector(`[data-check="${item.id}"] svg`)).filter(Boolean)
    const tween = gsap.fromTo(targets, { scale: 0.2, rotate: -40 }, { scale: 1, rotate: 0, duration: 0.6, ease: 'back.out(3)' })
    return () => { tween.kill() }
  }, [items, selectedJobId])

  const verified = items.filter((item) => item.state === 'verified').length
  const applicable = items.filter((item) => item.state !== 'not_applicable').length
  const failed = items.filter((item) => item.state === 'failed').length

  return (
    <section className={cn(PANEL, 'flex min-h-[340px] flex-col p-4')} aria-labelledby="lw-check-title">
      <div className="flex flex-wrap items-center gap-2">
        <ListChecks className="h-4 w-4 text-[color:var(--lw-green)]" aria-hidden="true" />
        <h2 id="lw-check-title" className="text-sm font-bold text-white">PQC Migration Safety Checklist</h2>
        {items.length > 0 && (
          <span className="ml-auto font-mono text-[11px] font-bold" style={{ color: failed ? TONE.red : verified === applicable ? TONE.green : TONE.amber }}>
            {verified}/{applicable} verified{failed ? ` · ${failed} failed` : ''}
          </span>
        )}
      </div>
      {jobs.length > 0 && (
        <select
          aria-label="Job for the safety checklist"
          value={selectedJobId}
          onChange={(event) => onSelectJob(event.target.value)}
          className="mt-2 h-8 w-full rounded-lg border border-white/12 bg-[var(--lw-field)] px-2 text-[11px] font-semibold text-white/80 outline-none focus:border-[color:var(--lw-cyan)]/60"
        >
          {jobs.map((job) => <option key={job.id} value={job.id}>{job.asset} · {job.status}</option>)}
        </select>
      )}
      {items.length === 0 ? (
        <div className={cn(SUBPANEL, 'mt-3 grid flex-1 place-items-center p-4 text-center text-[12px] text-white/55')}>
          Select a migration job to see which safeguards are verified by recorded evidence.
        </div>
      ) : (
        <ul ref={list} className="mt-2 flex-1 space-y-1 overflow-y-auto pr-1" style={{ maxHeight: 290 }}>
          {items.map((item) => {
            const meta = CHECK_META[item.state]
            const Icon = meta.icon
            return (
              <li key={item.id} data-check={item.id} className="flex items-start gap-2.5 rounded-lg px-2 py-1.5 transition hover:bg-white/[0.035]" title={item.detail}>
                <Icon className="mt-0.5 h-4 w-4 shrink-0" style={{ color: meta.color, filter: item.state === 'verified' ? `drop-shadow(0 0 5px ${meta.color})` : undefined }} aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className={cn('text-[12px] font-semibold', item.state === 'not_applicable' ? 'text-white/45' : 'text-white/85')}>{item.label}</span>
                    <span className="ml-auto shrink-0 text-[9px] font-bold uppercase" style={{ color: meta.color }}>{meta.label}</span>
                  </div>
                  <p className="truncate text-[10.5px] text-white/45">{item.detail}</p>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
