/**
 * Shared presentation kit for the four-agent workflow surfaces.
 *
 * Status is never colour-only: every badge pairs a glyph and a word. Progress
 * renders the model's measured value, or an indeterminate sweep with the
 * reason when the model says it cannot be measured — never an invented %.
 */
import { useEffect, useRef, type ReactNode } from 'react'
import gsap from 'gsap'
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  CircleDashed,
  Clock3,
  Cpu,
  Database,
  ExternalLink,
  Hourglass,
  KeyRound,
  Lock,
  MemoryStick,
  PauseCircle,
  Play,
  Radio,
  RefreshCcw,
  Search,
  Server,
  ShieldAlert,
  ShieldQuestion,
  Workflow,
  Wrench,
  X,
  XCircle,
  type LucideIcon,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { HEARTBEAT_ONLINE_WINDOW_MS } from '@/lib/agent-installer/agent-release'
import type { AgentWorkflowStatus, EventSeverity, WorkflowAgentId, WorkflowAgentInstance, WorkflowAgentNode, WorkflowEvent } from '@/lib/migration/agent-workflow'

/*
 * Colours are theme tokens (live-workflow.css): `var(--lw-*)` resolves to the
 * neon value on dark grounds and to the dark end of the hue on parchment, and
 * back to neon inside a `qg-force-dark` screen. Translucent variants go
 * through `mix()` because a hex+alpha suffix cannot be appended to a var().
 */
export function mix(color: string, percent: number) {
  return `color-mix(in srgb, ${color} ${percent}%, transparent)`
}

const tone = (name: string) => `var(--lw-${name})`

export const AGENT_VISUAL: Record<WorkflowAgentId, { color: string; soft: string; icon: LucideIcon; glow: string }> = {
  collector: { color: tone('green'), soft: mix(tone('green'), 12), icon: Database, glow: mix(tone('green'), 35) },
  scanner: { color: tone('sky'), soft: mix(tone('sky'), 12), icon: Search, glow: mix(tone('sky'), 35) },
  patcher: { color: tone('amber'), soft: mix(tone('amber'), 12), icon: Wrench, glow: mix(tone('amber'), 32) },
  operator: { color: tone('violet'), soft: mix(tone('violet'), 13), icon: Workflow, glow: mix(tone('violet'), 35) },
}

export const STATUS_META: Record<AgentWorkflowStatus, { label: string; icon: LucideIcon; color: string }> = {
  idle: { label: 'Idle', icon: CircleDashed, color: tone('slate') },
  queued: { label: 'Queued', icon: Hourglass, color: tone('slate-soft') },
  waiting: { label: 'Waiting', icon: Clock3, color: tone('amber') },
  running: { label: 'Running', icon: Play, color: tone('cyan') },
  blocked: { label: 'Blocked', icon: ShieldAlert, color: tone('orange') },
  awaiting_approval: { label: 'Awaiting approval', icon: Lock, color: tone('amber') },
  paused: { label: 'Paused', icon: PauseCircle, color: tone('slate-soft') },
  retrying: { label: 'Rolling back', icon: RefreshCcw, color: tone('amber') },
  completed: { label: 'Completed', icon: CheckCircle2, color: tone('green') },
  failed: { label: 'Failed', icon: XCircle, color: tone('red') },
  cancelled: { label: 'Cancelled', icon: Ban, color: tone('slate') },
}

export const SEVERITY_TONE: Record<string, string> = {
  critical: tone('rose'),
  error: tone('red'),
  high: tone('orange'),
  warning: tone('amber'),
  medium: tone('amber'),
  low: tone('green'),
  success: tone('green'),
  good: tone('green'),
  info: tone('slate'),
  neutral: tone('slate-soft'),
}

export const TONE = {
  cyan: tone('cyan'),
  sky: tone('sky'),
  green: tone('green'),
  amber: tone('amber'),
  red: tone('red'),
  rose: tone('rose'),
  violet: tone('violet'),
}

export const PANEL =
  'relative rounded-2xl border border-white/10 bg-[var(--lw-panel)] backdrop-blur-xl text-white shadow-[0_18px_60px_rgba(0,0,0,0.18),inset_0_1px_0_rgba(255,255,255,0.04)]'
export const SUBPANEL = 'rounded-xl border border-white/[0.08] bg-white/[0.025]'
/** Native form fields — themed surface, so text and options stay legible. */
export const FIELD = 'border border-white/12 bg-[var(--lw-field)] text-white/75 outline-none focus:border-[color:var(--lw-cyan)]'

export function prefersReducedMotion() {
  return typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
}

export function formatDuration(msValue: number | null) {
  if (msValue === null || !Number.isFinite(msValue) || msValue < 0) return '—'
  const total = Math.floor(msValue / 1000)
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (h > 48) return `${Math.floor(h / 24)}d ${h % 24}h`
  if (h) return `${h}h ${String(m).padStart(2, '0')}m`
  if (m) return `${m}m ${String(s).padStart(2, '0')}s`
  return `${s}s`
}

export function timeAgo(iso: string | null | undefined, now: number) {
  const at = iso ? Date.parse(iso) : NaN
  if (!Number.isFinite(at)) return '—'
  const seconds = Math.max(0, Math.round((now - at) / 1000))
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`
  return `${Math.round(seconds / 86400)}d ago`
}

export function clock(iso: string | null | undefined) {
  const at = iso ? new Date(iso) : null
  if (!at || Number.isNaN(at.getTime())) return '--:--:--'
  return at.toLocaleTimeString('en-US', { hour12: false })
}

export function bytes(value: number | null) {
  if (value === null) return '—'
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(1)} GB`
  if (value >= 1024 ** 2) return `${Math.round(value / 1024 ** 2)} MB`
  return `${Math.round(value / 1024)} KB`
}

export function StatusPill({ status, size = 'sm' }: { status: AgentWorkflowStatus; size?: 'sm' | 'md' }) {
  const meta = STATUS_META[status]
  const Icon = meta.icon
  const ref = useRef<HTMLSpanElement>(null)
  const previous = useRef(status)
  // A confirmed status change gets a brief emphasis; nothing animates on a timer.
  useEffect(() => {
    if (previous.current === status) return
    previous.current = status
    if (!ref.current || prefersReducedMotion()) return
    const tween = gsap.fromTo(ref.current, { scale: 1.12, boxShadow: `0 0 22px ${meta.color}` }, { scale: 1, boxShadow: '0 0 0px transparent', duration: 0.6, ease: 'power2.out' })
    return () => { tween.kill() }
  }, [meta.color, status])
  return (
    <span
      ref={ref}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border font-bold',
        size === 'md' ? 'px-3 py-1 text-xs' : 'px-2.5 py-0.5 text-[10px]',
      )}
      style={{ color: meta.color, borderColor: `${mix(meta.color, 33)}`, background: `${mix(meta.color, 8)}` }}
    >
      <Icon className={cn(size === 'md' ? 'h-3.5 w-3.5' : 'h-3 w-3', (status === 'running' || status === 'retrying') && 'qg-lw-spin')} aria-hidden="true" />
      {meta.label}
    </span>
  )
}

/** Determinate bar when `value` is measured; an explained sweep when it is not. */
export function ProgressBar({ value, color, active }: { value: number | null; color: string; active: boolean }) {
  const fill = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!fill.current || value === null) return
    if (prefersReducedMotion()) {
      fill.current.style.width = `${value}%`
      return
    }
    const tween = gsap.to(fill.current, { width: `${value}%`, duration: 0.8, ease: 'power2.out' })
    return () => { tween.kill() }
  }, [value])
  if (value === null) {
    return (
      <div
        className={cn('h-1.5 rounded-full bg-[var(--lw-track)]', active && 'qg-lw-indeterminate')}
        style={{ ['--bar-color' as string]: color }}
        role="progressbar"
        aria-valuetext={active ? 'In progress — not measurable' : 'Not started'}
      />
    )
  }
  return (
    <div className="h-1.5 overflow-hidden rounded-full bg-[var(--lw-track)]" role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
      <div ref={fill} className="h-full rounded-full" style={{ width: 0, background: `linear-gradient(90deg, ${mix(color, 67)}, ${color})`, boxShadow: `0 0 10px ${mix(color, 53)}` }} />
    </div>
  )
}

/** Circular progress. `value === null` renders the status glyph instead of a number. */
export function ProgressRing({ value, color, status, size = 58 }: { value: number | null; color: string; status: AgentWorkflowStatus; size?: number }) {
  const radius = (size - 8) / 2
  const circumference = 2 * Math.PI * radius
  const arc = useRef<SVGCircleElement>(null)
  useEffect(() => {
    if (!arc.current) return
    const offset = circumference * (1 - (value ?? 0) / 100)
    if (prefersReducedMotion()) {
      arc.current.style.strokeDashoffset = String(offset)
      return
    }
    const tween = gsap.to(arc.current, { strokeDashoffset: offset, duration: 0.9, ease: 'power2.out' })
    return () => { tween.kill() }
  }, [circumference, value])
  const meta = STATUS_META[status]
  const Icon = meta.icon
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90" aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={radius} strokeWidth="4" fill="none" style={{ stroke: 'var(--lw-track)' }} />
        <circle
          ref={arc}
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth="4"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference}
          style={{ stroke: color, filter: `drop-shadow(0 0 6px ${mix(color, 67)})` }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        {value !== null ? (
          <span className="font-mono text-[13px] font-black text-white">{value}%</span>
        ) : (
          <Icon className={cn('h-5 w-5', (status === 'running' || status === 'retrying') && 'qg-lw-spin')} style={{ color: meta.color }} aria-hidden="true" />
        )}
      </div>
    </div>
  )
}

export function Sparkline({ values, color, height = 34 }: { values: number[]; color: string; height?: number }) {
  if (values.length < 2) return <div style={{ height }} aria-hidden="true" />
  const max = Math.max(1, ...values)
  const min = Math.min(...values)
  const span = Math.max(1, max - min)
  const points = values.map((value, index) => `${(index / (values.length - 1)) * 100},${height - 3 - ((value - min) / span) * (height - 8)}`).join(' ')
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" className="w-full" style={{ height }} aria-hidden="true">
      <polyline points={`0,${height} ${points} 100,${height}`} stroke="none" style={{ fill: mix(color, 13) }} />
      <polyline points={points} fill="none" strokeWidth="1.6" style={{ stroke: color }} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
    </svg>
  )
}

export function SectionTitle({ icon: Icon, title, right, color = TONE.cyan }: { icon: LucideIcon; title: string; right?: ReactNode; color?: string }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Icon className="h-4 w-4 shrink-0" style={{ color }} aria-hidden="true" />
      <h2 className="text-sm font-bold tracking-tight text-white">{title}</h2>
      {right ? <div className="ml-auto flex flex-wrap items-center gap-2">{right}</div> : null}
    </div>
  )
}

/**
 * The agent card. Rendered inside a React Flow node on wide screens and as a
 * stacked card on phones/tablets — one component, so both views agree.
 */
export function AgentCard({
  node,
  now,
  selected,
  highlighted,
  onSelect,
  onOutput,
}: {
  node: WorkflowAgentNode
  now: number
  selected: boolean
  highlighted: boolean
  onSelect: () => void
  onOutput?: () => void
}) {
  const visual = AGENT_VISUAL[node.id]
  const Icon = visual.icon
  const card = useRef<HTMLDivElement>(null)
  const lastStatus = useRef(node.status)
  const active = node.status === 'running' || node.status === 'retrying'

  // Activation / completion / failure emphasis — fired by a status change in
  // the snapshot, never by a timer.
  useEffect(() => {
    if (lastStatus.current === node.status) return
    lastStatus.current = node.status
    if (!card.current || prefersReducedMotion()) return
    const tone = STATUS_META[node.status].color
    const tl = gsap.timeline()
    tl.fromTo(card.current, { boxShadow: `0 0 0 1px ${tone}, 0 0 60px ${mix(tone, 53)}` }, { boxShadow: `0 0 0 1px ${mix(visual.color, 33)}, 0 0 34px ${visual.glow}`, duration: 1.1, ease: 'power2.out' })
    if (node.status === 'failed') tl.fromTo(card.current, { x: -4 }, { x: 0, duration: 0.4, ease: 'elastic.out(1, 0.3)' }, 0)
    else tl.fromTo(card.current, { scale: 1.025 }, { scale: 1, duration: 0.6, ease: 'power2.out' }, 0)
    return () => { tl.kill() }
  }, [node.status, visual.color, visual.glow])

  const duration = node.startedAt
    ? (node.completedAt ? Date.parse(node.completedAt) : now) - Date.parse(node.startedAt)
    : null
  const dependency = node.dependsOn ? `Depends on ${node.dependsOn === 'operator' ? 'Migration Operator' : node.dependsOn[0].toUpperCase() + node.dependsOn.slice(1)}` : 'First stage — no upstream dependency'
  const bullets: Array<{ ok: boolean | null; text: string }> = [
    node.units ? { ok: node.units.done >= node.units.total, text: `${node.units.done.toLocaleString('en-US')} / ${node.units.total.toLocaleString('en-US')} ${node.units.label}` } : { ok: null, text: node.reason },
    { ok: node.fleet.online > 0 ? true : node.fleet.enrolled > 0 ? false : null, text: `${node.fleet.online}/${node.fleet.enrolled} agents online${node.fleet.authorised !== null ? ` · ${node.fleet.authorised} authorised` : ''}` },
    { ok: node.readOnly ? true : null, text: node.readOnly ? 'Read-only — never writes to hosts' : 'Writes only after approval + snapshot' },
    node.latestEvent ? { ok: node.latestEvent.severity === 'error' || node.latestEvent.severity === 'critical' ? false : node.latestEvent.severity === 'success' ? true : null, text: node.latestEvent.message } : { ok: null, text: dependency },
  ]

  return (
    <div
      ref={card}
      onClick={onSelect}
      className={cn(
        'qg-force-dark group relative flex h-full w-full flex-col overflow-hidden rounded-2xl border bg-[var(--lw-card)] p-4 text-left text-white backdrop-blur-xl transition-[border-color,opacity] duration-300',
        node.status === 'idle' && !selected && 'opacity-80',
      )}
      style={{
        borderColor: selected || highlighted ? visual.color : `${mix(visual.color, 33)}`,
        boxShadow: selected || highlighted
          ? `0 0 0 1px ${visual.color}, 0 0 46px ${visual.glow}`
          : active ? `0 0 0 1px ${mix(visual.color, 33)}, 0 0 34px ${visual.glow}` : `0 0 0 1px ${mix(visual.color, 13)}, 0 12px 40px rgba(0,0,0,0.45)`,
      }}
    >
      <div className="pointer-events-none absolute inset-x-0 top-0 h-24" style={{ background: `radial-gradient(240px 90px at 20% 0%, ${visual.soft}, transparent 70%)` }} />
      <div className="relative flex items-start gap-3">
        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border" style={{ borderColor: `${mix(visual.color, 40)}`, background: visual.soft, boxShadow: `0 0 18px ${visual.glow}` }}>
          <Icon className="h-5 w-5" style={{ color: visual.color }} aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="truncate text-[15px] font-bold leading-tight">{node.label}</h3>
            {(node.errors > 0 || node.warnings > 0) && (
              <span
                className="ml-auto inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-bold"
                style={{ color: node.errors ? TONE.red : TONE.amber, background: mix(node.errors ? TONE.red : TONE.amber, 12) }}
                title={`${node.errors} error(s), ${node.warnings} warning(s) in recent events`}
              >
                <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                {node.errors || node.warnings}
              </span>
            )}
          </div>
          <p className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-white/55">{node.purpose}</p>
        </div>
      </div>

      <div className="relative mt-3 flex items-center gap-3">
        <ProgressRing value={node.status === 'completed' ? 100 : node.progress} color={visual.color} status={node.status} />
        <div className="min-w-0 flex-1 space-y-2">
          <StatusPill status={node.status} />
          <div className="truncate text-[11px] font-semibold text-white/80" title={node.currentTask}>{node.currentTask}</div>
          <ProgressBar value={node.status === 'completed' ? 100 : node.progress} color={visual.color} active={active} />
        </div>
      </div>

      <ul className="relative mt-3 space-y-1.5 text-[11px]">
        {bullets.map((bullet, index) => (
          <li key={index} className="flex min-w-0 items-start gap-2">
            {bullet.ok === true ? (
              <CheckCircle2 className="mt-px h-3.5 w-3.5 shrink-0 text-[color:var(--lw-green)]" aria-hidden="true" />
            ) : bullet.ok === false ? (
              <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0 text-[color:var(--lw-amber)]" aria-hidden="true" />
            ) : (
              <ShieldQuestion className="mt-px h-3.5 w-3.5 shrink-0 text-white/35" aria-hidden="true" />
            )}
            <span className="line-clamp-1 text-white/70" title={bullet.text}>{bullet.text}</span>
          </li>
        ))}
      </ul>

      <div className="relative mt-auto flex items-center gap-2 border-t border-white/[0.07] pt-3 text-[11px] text-white/50">
        <Clock3 className="h-3.5 w-3.5" aria-hidden="true" />
        <span className="font-mono">{node.startedAt ? formatDuration(duration) : node.updatedAt ? timeAgo(node.updatedAt, now) : 'Not started'}</span>
        <div className="ml-auto flex items-center gap-1.5">
          {onOutput && node.outputs.length > 0 && (
            <button
              type="button"
              onClick={(event) => { event.stopPropagation(); onOutput() }}
              className="nodrag rounded-md border border-white/10 px-2 py-1 text-[10px] font-bold text-white/60 transition hover:border-white/30 hover:text-white"
            >
              Output
            </button>
          )}
          <button
            type="button"
            onClick={(event) => { event.stopPropagation(); onSelect() }}
            className="nodrag rounded-md border px-2 py-1 text-[10px] font-bold transition hover:brightness-125"
            style={{ color: visual.color, borderColor: `${mix(visual.color, 33)}`, background: visual.soft }}
          >
            View Details →
          </button>
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Deployed agents — the children of each stage in the workflow tree   */
/* ------------------------------------------------------------------ */

/**
 * What the SSE agent bus reported for one agent AFTER the snapshot was built.
 * It only advances presence and the activity line; the agent's state stays
 * the snapshot's, which follows within seconds.
 */
export interface AgentLiveActivity {
  /** Newest frame proving the agent is alive (heartbeat, scan frame, error). */
  seenAt: string | null
  /** Newest non-heartbeat frame. */
  message: string | null
  messageAt: string | null
  progress: number | null
  severity: EventSeverity | null
  /** The agent was revoked after the snapshot. */
  disconnected: boolean
}

/** Presence after applying live frames: a fresh frame proves online; a revoke ends it. */
export function agentPresence(instance: WorkflowAgentInstance, live: AgentLiveActivity | undefined, now: number) {
  if (live?.disconnected) return { online: false, lastSeenAt: instance.lastSeenAt }
  const liveSeen = live?.seenAt && Date.parse(live.seenAt) > (Date.parse(instance.lastSeenAt || '') || 0) ? live.seenAt : null
  const lastSeenAt = liveSeen || instance.lastSeenAt
  const online = instance.online || Boolean(liveSeen && now - Date.parse(liveSeen) <= HEARTBEAT_ONLINE_WINDOW_MS)
  return { online, lastSeenAt }
}

function percent(value: number | null) {
  return value === null ? '—' : `${value}%`
}

function MetricChip({ icon: Icon, label, value, title, tone: chipTone }: { icon: LucideIcon; label: string; value: string; title?: string; tone?: string }) {
  return (
    <span className="inline-flex min-w-0 items-center gap-1 rounded-md border border-white/[0.07] bg-white/[0.03] px-1.5 py-0.5" title={title ? `${label}: ${value} — ${title}` : `${label}: ${value}`}>
      <Icon className="h-3 w-3 shrink-0 text-white/40" aria-hidden="true" />
      <span className="sr-only">{label}</span>
      <span className="whitespace-nowrap font-mono font-bold" style={{ color: chipTone || 'rgba(255,255,255,0.85)' }}>{value}</span>
    </span>
  )
}

/** The role-specific third chip: evidence for read-only roles, claimed jobs for write roles. */
function workChip(instance: WorkflowAgentInstance) {
  if (instance.jobs) {
    const { claimed, failed, running, completed } = instance.jobs
    return {
      icon: Workflow,
      label: 'Jobs',
      value: failed ? `${claimed} · ${failed}✗` : String(claimed),
      tone: failed ? TONE.red : undefined,
      title: `${claimed} claimed · ${running} running · ${completed} completed · ${failed} failed`,
    }
  }
  const evidence = instance.lastRun?.evidence ?? null
  return {
    icon: Database,
    label: 'Evidence',
    value: evidence === null ? '—' : evidence.toLocaleString('en-US'),
    tone: undefined,
    title: instance.lastRun ? "Evidence items in this agent's latest scan run" : 'No scan run recorded in the last 24 hours',
  }
}

/** Compact card for one deployed agent. Same tokens and vocabulary as `AgentCard`. */
export function AgentInstanceCard({
  instance,
  live,
  now,
  selected,
  onSelect,
}: {
  instance: WorkflowAgentInstance
  live?: AgentLiveActivity
  now: number
  selected: boolean
  onSelect: () => void
}) {
  const visual = AGENT_VISUAL[instance.role]
  const card = useRef<HTMLButtonElement>(null)
  const lastState = useRef(instance.state)
  const { online, lastSeenAt } = agentPresence(instance, live, now)
  const active = instance.state === 'running' || instance.state === 'retrying'
  const liveMessage = live?.message && live.messageAt ? live : null
  const task = liveMessage?.message || instance.currentTask
  const progress = instance.state === 'completed' ? 100 : liveMessage?.progress ?? instance.progress
  const isWindows = (instance.platform || '').toLowerCase() === 'win32'
  const work = workChip(instance)

  // A confirmed state change gets the same brief emphasis as the stage card.
  useEffect(() => {
    if (lastState.current === instance.state) return
    lastState.current = instance.state
    if (!card.current || prefersReducedMotion()) return
    const stateTone = STATUS_META[instance.state].color
    const tween = gsap.fromTo(
      card.current,
      { boxShadow: `0 0 0 1px ${stateTone}, 0 0 40px ${mix(stateTone, 45)}` },
      { boxShadow: `0 0 0 1px ${mix(visual.color, 20)}, 0 10px 30px rgba(0,0,0,0.4)`, duration: 1, ease: 'power2.out' },
    )
    return () => { tween.kill() }
  }, [instance.state, visual.color])

  return (
    <button
      ref={card}
      type="button"
      onClick={(event) => { event.stopPropagation(); onSelect() }}
      aria-pressed={selected}
      aria-label={`${instance.name}: ${STATUS_META[instance.state].label}, ${online ? 'online' : 'offline'}. ${instance.currentTask}`}
      className={cn(
        'qg-force-dark nodrag relative flex h-full w-full flex-col overflow-hidden rounded-xl border bg-[var(--lw-card)] py-2.5 pl-3.5 pr-3 text-left text-white backdrop-blur-xl transition-[border-color,opacity] duration-300',
        !online && !selected && 'opacity-75',
      )}
      style={{
        borderColor: selected ? visual.color : mix(visual.color, 24),
        boxShadow: selected
          ? `0 0 0 1px ${visual.color}, 0 0 32px ${visual.glow}`
          : active ? `0 0 0 1px ${mix(visual.color, 28)}, 0 0 24px ${visual.glow}` : `0 0 0 1px ${mix(visual.color, 10)}, 0 10px 30px rgba(0,0,0,0.4)`,
      }}
    >
      <span className="absolute inset-y-2 left-0 w-[3px] rounded-r-full" style={{ background: visual.color, boxShadow: `0 0 10px ${visual.glow}` }} aria-hidden="true" />
      <div className="flex min-w-0 items-center gap-2">
        <Server className="h-3.5 w-3.5 shrink-0" style={{ color: visual.color }} aria-hidden="true" />
        <span className="min-w-0 flex-1 truncate text-[12px] font-bold" title={instance.name}>{instance.name}</span>
        <span
          className="inline-flex shrink-0 items-center gap-1 text-[10px] font-semibold"
          style={{ color: online ? TONE.green : 'var(--lw-slate)' }}
          title={lastSeenAt ? `Last check-in ${new Date(lastSeenAt).toLocaleString()}` : 'Never checked in'}
        >
          <span className="relative flex h-1.5 w-1.5">
            {online && !prefersReducedMotion() && <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60" style={{ background: TONE.green }} />}
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full" style={{ background: online ? TONE.green : 'var(--lw-slate)' }} />
          </span>
          {online ? 'Online' : lastSeenAt ? `Offline · ${timeAgo(lastSeenAt, now).replace(' ago', '')}` : 'Never seen'}
        </span>
      </div>
      <div className="mt-0.5 flex min-w-0 items-center gap-1.5 pl-[22px] text-[10px] text-white/45">
        <span className="truncate font-mono">{[instance.hostname, instance.version ? `v${instance.version}` : null, instance.platform].filter(Boolean).join(' · ') || 'No host details reported'}</span>
        {instance.authorised !== null && (
          <span
            className="ml-auto inline-flex shrink-0 items-center gap-0.5 font-semibold"
            style={{ color: instance.authorised ? TONE.green : TONE.amber }}
            title={instance.authorised ? 'Authorised to write for this stage' : 'No write authority — never claims a job'}
          >
            <KeyRound className="h-2.5 w-2.5" aria-hidden="true" />
            {instance.authorised ? 'Authorised' : 'No authority'}
          </span>
        )}
      </div>

      <div className="mt-2 flex min-w-0 items-center gap-2">
        <StatusPill status={instance.state} />
        {liveMessage && (
          <span
            className="inline-flex shrink-0 items-center gap-1 text-[9px] font-black uppercase tracking-wider"
            style={{ color: TONE.cyan }}
            title={`Live frame ${timeAgo(liveMessage.messageAt, now)} — state confirms on the next snapshot`}
          >
            <Radio className="h-3 w-3" aria-hidden="true" />
            Live
          </span>
        )}
        <span className="min-w-0 flex-1 truncate text-[11px] font-semibold text-white/75" title={task}>{task}</span>
      </div>
      <div className="mt-2">
        <ProgressBar value={progress} color={visual.color} active={active} />
      </div>

      <div className="mt-auto flex min-w-0 items-center gap-1 pt-2 text-[10px]">
        <MetricChip icon={MemoryStick} label="Mem" value={percent(instance.metrics.memoryUsedPct)} title="Host memory used, as the agent last reported it" />
        <MetricChip
          icon={Cpu}
          label="CPU"
          value={isWindows && instance.metrics.cpuLoadPct === null ? 'n/a' : percent(instance.metrics.cpuLoadPct)}
          title={isWindows ? 'Windows reports no load average — CPU load is not measured' : '1-minute load ÷ cores, as the agent last reported it'}
        />
        <MetricChip icon={work.icon} label={work.label} value={work.value} title={work.title} tone={work.tone} />
        {(instance.errors > 0 || instance.warnings > 0) && (
          <span
            className="ml-auto inline-flex shrink-0 items-center gap-0.5 rounded-md px-1 py-0.5 font-bold"
            style={{ color: instance.errors ? TONE.red : TONE.amber, background: mix(instance.errors ? TONE.red : TONE.amber, 12) }}
            title={`${instance.errors} error(s), ${instance.warnings} warning(s) in recent events from this agent`}
          >
            <AlertTriangle className="h-2.5 w-2.5" aria-hidden="true" />
            {instance.errors || instance.warnings}
          </span>
        )}
      </div>
    </button>
  )
}

function InspectorRow({ label, value, title }: { label: string; value: ReactNode; title?: string }) {
  return (
    <div className="flex min-w-0 items-baseline justify-between gap-3 py-1 text-[11px]" title={title}>
      <span className="shrink-0 text-white/45">{label}</span>
      <span className="min-w-0 truncate text-right font-mono text-white/85">{value}</span>
    </div>
  )
}

function InspectorHeading({ children }: { children: ReactNode }) {
  return <div className="mb-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-white/45">{children}</div>
}

/**
 * Full detail for one deployed agent: identity, state and why, host health
 * with its own trend, role-specific work, and its own recent events.
 */
export function AgentInspector({
  instance,
  live,
  events,
  now,
  onClose,
  onOpenStage,
  className,
}: {
  instance: WorkflowAgentInstance
  live?: AgentLiveActivity
  events: WorkflowEvent[]
  now: number
  onClose: () => void
  onOpenStage: () => void
  className?: string
}) {
  const visual = AGENT_VISUAL[instance.role]
  const { online, lastSeenAt } = agentPresence(instance, live, now)
  const own = events.filter((event) => event.agentId === instance.id).slice(0, 6)
  const isWindows = (instance.platform || '').toLowerCase() === 'win32'
  const elapsed = instance.startedAt ? (instance.completedAt ? Date.parse(instance.completedAt) : now) - Date.parse(instance.startedAt) : null
  const metrics = instance.metrics
  const liveMessage = live?.message && live.messageAt ? live : null
  const panel = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!panel.current || prefersReducedMotion()) return
    const tween = gsap.fromTo(panel.current, { x: 16, opacity: 0 }, { x: 0, opacity: 1, duration: 0.28, ease: 'power2.out' })
    return () => { tween.kill() }
  }, [instance.id])

  return (
    <div
      ref={panel}
      role="dialog"
      aria-label={`Agent ${instance.name}`}
      onKeyDown={(event) => {
        if (event.key !== 'Escape') return
        // Close the inspector without also leaving canvas full screen.
        event.stopPropagation()
        event.nativeEvent.stopImmediatePropagation()
        onClose()
      }}
      className={cn('qg-force-dark nodrag nopan nowheel flex flex-col overflow-hidden rounded-2xl border bg-[var(--lw-screen)] text-white shadow-2xl backdrop-blur-xl', className)}
      style={{ borderColor: mix(visual.color, 35), boxShadow: `0 0 0 1px ${mix(visual.color, 15)}, 0 24px 60px rgba(0,0,0,0.55)` }}
    >
      <div className="flex items-start gap-2.5 border-b border-white/[0.07] p-3" style={{ background: `radial-gradient(260px 80px at 10% 0%, ${visual.soft}, transparent 70%)` }}>
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border" style={{ borderColor: mix(visual.color, 40), background: visual.soft }}>
          <Server className="h-4 w-4" style={{ color: visual.color }} aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[13px] font-bold" title={instance.name}>{instance.name}</div>
          <div className="truncate text-[10px] font-bold uppercase tracking-[0.14em]" style={{ color: visual.color }}>
            {instance.role === 'operator' ? 'Migration Operator' : instance.role[0].toUpperCase() + instance.role.slice(1)} agent
          </div>
        </div>
        <button type="button" onClick={onClose} aria-label="Close agent details" className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-white/50 transition hover:bg-white/10 hover:text-white">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <StatusPill status={instance.state} />
            <span className="text-[10px] font-semibold" style={{ color: online ? TONE.green : 'var(--lw-slate)' }}>{online ? '● Online' : '○ Offline'}</span>
          </div>
          <div className="text-[12px] font-semibold text-white/85">{liveMessage?.message || instance.currentTask}</div>
          <p className="text-[11px] leading-snug text-white/55">{instance.reason}</p>
          <ProgressBar
            value={instance.state === 'completed' ? 100 : liveMessage?.progress ?? instance.progress}
            color={visual.color}
            active={instance.state === 'running' || instance.state === 'retrying'}
          />
        </div>

        <div className={cn(SUBPANEL, 'px-2.5 py-1')}>
          <InspectorRow label="Hostname" value={instance.hostname || '—'} />
          <InspectorRow label="Version" value={instance.version ? `v${instance.version}` : '—'} />
          <InspectorRow label="Platform" value={instance.platform || 'Not reported'} />
          <InspectorRow label="Last check-in" value={lastSeenAt ? timeAgo(lastSeenAt, now) : 'Never'} title={lastSeenAt ? new Date(lastSeenAt).toLocaleString() : undefined} />
          <InspectorRow
            label={instance.state === 'running' || instance.state === 'retrying' ? 'Running for' : 'Run duration'}
            value={instance.startedAt ? formatDuration(elapsed) : '—'}
          />
          {instance.authorised !== null && (
            <InspectorRow label="Write authority" value={<span style={{ color: instance.authorised ? TONE.green : TONE.amber }}>{instance.authorised ? 'Authorised' : 'Not authorised'}</span>} />
          )}
        </div>

        <div className={cn(SUBPANEL, 'p-2.5')}>
          <InspectorHeading>Host health</InspectorHeading>
          {metrics.reporting === 0 ? (
            <p className="text-[11px] text-white/50">This agent has not reported host telemetry yet.</p>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <InspectorRow label="Memory" value={percent(metrics.memoryUsedPct)} />
                  {metrics.series.memory.length > 1 && <Sparkline values={metrics.series.memory} color={visual.color} height={26} />}
                </div>
                <div>
                  <InspectorRow
                    label="CPU load"
                    value={isWindows && metrics.cpuLoadPct === null ? 'n/a' : percent(metrics.cpuLoadPct)}
                    title={isWindows ? 'Windows reports no load average' : undefined}
                  />
                  {metrics.series.cpu.length > 1 && <Sparkline values={metrics.series.cpu} color={TONE.cyan} height={26} />}
                </div>
              </div>
              <InspectorRow label="Agent RSS" value={bytes(metrics.agentRssBytes)} />
              <InspectorRow label="Scans · errors" value={`${metrics.scanCount ?? '—'} · ${metrics.errorCount ?? '—'}`} />
              <InspectorRow label="Queue depth" value={metrics.queueDepth ?? '—'} />
              <InspectorRow label="Last scan took" value={formatDuration(metrics.lastScanDurationMs)} />
            </>
          )}
        </div>

        {instance.lastRun && (
          <div className={cn(SUBPANEL, 'px-2.5 py-1.5')}>
            <InspectorHeading>Latest scan run</InspectorHeading>
            <InspectorRow label="Evidence" value={instance.lastRun.evidence?.toLocaleString('en-US') ?? '—'} />
            <InspectorRow label="Accepted" value={instance.lastRun.accepted?.toLocaleString('en-US') ?? '—'} />
            <InspectorRow label="Rejected by policy" value={instance.lastRun.rejected?.toLocaleString('en-US') ?? '—'} />
          </div>
        )}
        {instance.jobs && (
          <div className={cn(SUBPANEL, 'px-2.5 py-1.5')}>
            <InspectorHeading>Claimed jobs</InspectorHeading>
            <InspectorRow label="Claimed" value={instance.jobs.claimed} />
            <InspectorRow label="Running · paused" value={`${instance.jobs.running} · ${instance.jobs.paused}`} />
            <InspectorRow label="Completed" value={instance.jobs.completed} />
            <InspectorRow label="Failed" value={<span style={{ color: instance.jobs.failed ? TONE.red : undefined }}>{instance.jobs.failed}</span>} />
            <InspectorRow label="Rolled back" value={instance.jobs.rollback} />
          </div>
        )}

        <div>
          <InspectorHeading>Recent events from this agent</InspectorHeading>
          {own.length === 0 ? (
            <p className="text-[11px] text-white/50">No events from this agent in the current window.</p>
          ) : (
            <ul className="space-y-1.5">
              {own.map((event) => (
                <li key={event.id} className="flex min-w-0 items-start gap-2 text-[11px]">
                  <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEVERITY_TONE[event.severity] || TONE.cyan }} aria-hidden="true" />
                  <span className="line-clamp-2 min-w-0 flex-1 text-white/75" title={event.message}>{event.message}</span>
                  <span className="shrink-0 font-mono text-[10px] text-white/40">{timeAgo(event.at, now)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 border-t border-white/[0.07] p-3">
        <button
          type="button"
          onClick={onOpenStage}
          className="rounded-md border px-2.5 py-1.5 text-[10px] font-bold transition hover:brightness-125"
          style={{ color: visual.color, borderColor: mix(visual.color, 33), background: visual.soft }}
        >
          Stage details
        </button>
        <a href="/downloads" className="ml-auto inline-flex items-center gap-1 rounded-md border border-white/10 px-2.5 py-1.5 text-[10px] font-bold text-white/65 transition hover:border-white/30 hover:text-white">
          Agent Center <ExternalLink className="h-3 w-3" aria-hidden="true" />
        </a>
      </div>
    </div>
  )
}
