/**
 * Migration Timeline — pure derivation (no React, no I/O).
 *
 * Turns the orchestration snapshot into a time axis of REAL migration work:
 * one lane per recorded plan (plus one for per-finding remediation that has no
 * plan), one bar per job from when it started (or, if it never ran, from when
 * it was recorded) to when it finished (or now, while it is still open).
 *
 * What it deliberately does not do, because the previous page did:
 *  • invent dates — "waves" 21 days apart from the first scan, timeline cards
 *    offset 7/14/21… days, a "Projected Completion" from ~3 days/component.
 *    Only recorded timestamps are placed: job created/started/completed/
 *    verified, plan approval and the plan's recorded scheduled start.
 *  • call anything overdue without a recorded date. Nothing records a target
 *    completion date, so the only overdue state is "recorded scheduled start
 *    has passed and nothing started" (computed once, in the model).
 *  • fill gaps with CBOM rows dressed up as jobs. No job → no bar.
 *
 * tools/orchestrator-check.ts drives this module with fixtures.
 */
import {
  jobDisplayStatus,
  type JobDisplayStatus,
  type OrchestrationJob,
  type OrchestrationPlan,
  type OrchestrationSnapshot,
  type PlanScheduleState,
} from '@/lib/migration/orchestration-model'

export type TimeWindow = 'all' | '90d' | '30d' | '7d'

export const WINDOW_LABEL: Record<TimeWindow, string> = { all: 'All recorded', '90d': '90 days', '30d': '30 days', '7d': '7 days' }

const WINDOW_DAYS: Record<Exclude<TimeWindow, 'all'>, number> = { '90d': 90, '30d': 30, '7d': 7 }
const DAY = 86_400_000

export interface TimelineFilters {
  window: TimeWindow
  status: JobDisplayStatus | 'all'
  search: string
  /** `?planId=` from the Migration Planner's orchestration link. */
  planId: string | null
}

export const DEFAULT_TIMELINE_FILTERS: TimelineFilters = { window: 'all', status: 'all', search: '', planId: null }

export interface TimelineBar {
  jobId: string
  name: string
  assetName: string
  display: JobDisplayStatus
  startAt: number
  endAt: number
  /** `started`: the bar is execution time. `created`: it never ran — the bar is waiting time. */
  startKind: 'started' | 'created'
  endKind: 'completed' | 'now' | 'last-update'
  /** The visible window cut the start off. */
  clipped: boolean
  startPct: number
  endPct: number
  phaseIndex: number | null
  phaseName: string | null
  verifiedAt: number | null
  verifiedPct: number | null
}

export type MarkerKind = 'recorded' | 'approved' | 'scheduled' | 'first-start' | 'last-completion'

export interface TimelineMarker {
  kind: MarkerKind
  at: number
  pct: number
  label: string
}

export interface TimelineLane {
  id: string
  kind: 'plan' | 'planless'
  title: string
  plan: OrchestrationPlan | null
  schedule: PlanScheduleState | null
  markers: TimelineMarker[]
  bars: TimelineBar[]
  /** Listed jobs of this lane hidden by the status/search filter or the window. */
  hidden: number
}

export interface TimelineModel {
  /** Null when nothing recorded can be placed on the axis. */
  domain: { start: number; end: number } | null
  ticks: Array<{ at: number; pct: number; label: string }>
  nowPct: number | null
  lanes: TimelineLane[]
  /** Bars placed after filtering. */
  shown: number
  /** Jobs in the snapshot list (capped at 200, most urgent first). */
  listed: number
  /** Exact operational job count. */
  total: number
  truncated: boolean
  /** Listed jobs ending before the visible window. */
  outsideWindow: number
  /** Plans with a recorded scheduled start, of all plans. */
  scheduleRecorded: number
  planCount: number
  overduePlans: number
}

function ms(value: string | null | undefined): number | null {
  if (!value) return null
  const t = Date.parse(value)
  return Number.isFinite(t) ? t : null
}

const OPEN: ReadonlySet<JobDisplayStatus> = new Set([
  'awaiting-approval', 'not-released', 'blocked', 'ready', 'running', 'executor-silent', 'validating', 'paused',
])

/** Where a job's bar starts and ends — recorded timestamps only. */
export function barSpan(job: OrchestrationJob, now: number): Pick<TimelineBar, 'startAt' | 'endAt' | 'startKind' | 'endKind'> | null {
  const display = jobDisplayStatus(job)
  const started = ms(job.startedAt)
  const created = ms(job.createdAt)
  const startAt = started ?? created
  if (startAt === null) return null
  const completed = ms(job.completedAt)
  const updated = ms(job.updatedAt)
  let endAt: number
  let endKind: TimelineBar['endKind']
  if (OPEN.has(display)) {
    endAt = now
    endKind = 'now'
  } else if (completed !== null && job.phase === 'completed') {
    endAt = completed
    endKind = 'completed'
  } else {
    endAt = updated ?? completed ?? startAt
    endKind = 'last-update'
  }
  return { startAt, endAt: Math.max(endAt, startAt), startKind: started !== null ? 'started' : 'created', endKind }
}

function matches(job: OrchestrationJob, filters: TimelineFilters): boolean {
  if (filters.status !== 'all' && jobDisplayStatus(job) !== filters.status) return false
  const q = filters.search.trim().toLowerCase()
  if (q && !`${job.name} ${job.assetName} ${job.targetAlgorithm || ''} ${job.fromAlgorithm || ''}`.toLowerCase().includes(q)) return false
  return true
}

function tickStep(span: number): number {
  if (span <= 2 * DAY) return DAY / 4
  if (span <= 16 * DAY) return DAY
  if (span <= 120 * DAY) return 7 * DAY
  if (span <= 400 * DAY) return 30 * DAY
  return 90 * DAY
}

function tickLabel(at: number, step: number): string {
  const date = new Date(at)
  if (step < DAY) return date.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false })
  if (step >= 30 * DAY) return date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' })
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

/** Build the time view. `now` is injectable so fixtures are deterministic. */
export function buildTimeline(snapshot: OrchestrationSnapshot, filters: TimelineFilters, now: number = Date.now()): TimelineModel {
  const windowStart = filters.window === 'all' ? null : now - WINDOW_DAYS[filters.window] * DAY
  const planById = new Map(snapshot.plans.map((plan) => [plan.id, plan]))

  // Group listed jobs by plan, keeping the snapshot's plan order.
  const laneJobs = new Map<string, OrchestrationJob[]>()
  for (const job of snapshot.jobs) {
    const key = job.planId || '__planless__'
    if (filters.planId && job.planId !== filters.planId) continue
    const list = laneJobs.get(key) || []
    list.push(job)
    laneJobs.set(key, list)
  }
  const laneOrder = [
    ...snapshot.plans.map((plan) => plan.id).filter((id) => laneJobs.has(id)),
    ...[...laneJobs.keys()].filter((id) => id !== '__planless__' && !planById.has(id)),
    ...(laneJobs.has('__planless__') ? ['__planless__'] : []),
  ]

  // First pass: spans (absolute times) and markers.
  type Draft = { lane: TimelineLane; spans: Array<{ job: OrchestrationJob; span: NonNullable<ReturnType<typeof barSpan>> }> }
  const drafts: Draft[] = []
  let outsideWindow = 0
  const instants: number[] = []
  for (const id of laneOrder) {
    const jobs = laneJobs.get(id) || []
    const plan = id === '__planless__' ? null : planById.get(id) || null
    const lane: TimelineLane = {
      id,
      kind: id === '__planless__' ? 'planless' : 'plan',
      title: id === '__planless__'
        ? 'Remediation without a plan'
        : plan?.name || `Plan ${id.slice(0, 8)}`,
      plan,
      schedule: plan?.schedule ?? (plan ? 'not-recorded' : null),
      markers: [],
      bars: [],
      hidden: 0,
    }
    const spans: Draft['spans'] = []
    for (const job of jobs) {
      if (!matches(job, filters)) { lane.hidden += 1; continue }
      const span = barSpan(job, now)
      if (!span) { lane.hidden += 1; continue }
      if (windowStart !== null && span.endAt < windowStart) { lane.hidden += 1; outsideWindow += 1; continue }
      spans.push({ job, span })
      instants.push(windowStart !== null ? Math.max(span.startAt, windowStart) : span.startAt, span.endAt)
    }
    if (plan) {
      const add = (kind: MarkerKind, value: string | null | undefined, label: string) => {
        const at = ms(value)
        if (at === null) return
        if (windowStart !== null && at < windowStart) return
        lane.markers.push({ kind, at, pct: 0, label })
        instants.push(at)
      }
      add('recorded', plan.createdAt ?? null, 'Plan recorded')
      add('approved', plan.approvedAt ?? null, plan.approvedBy ? `Approved by ${plan.approvedBy}` : 'Approved')
      add('scheduled', plan.scheduledAt ?? null, plan.schedule === 'overdue' ? 'Scheduled start — passed, nothing started' : 'Scheduled start (recorded)')
      add('first-start', plan.firstStartedAt, 'First job started')
      add('last-completion', plan.lastCompletedAt ?? null, 'Latest completion')
    }
    drafts.push({ lane, spans })
  }

  // Domain: everything placed, plus "now".
  let domain: TimelineModel['domain'] = null
  if (instants.length) {
    let start = windowStart ?? Math.min(...instants)
    let end = Math.max(now, ...instants)
    if (end - start < DAY) { start -= DAY / 2; end += DAY / 2 }
    const pad = (end - start) * 0.03
    domain = { start: windowStart ?? start - pad, end: end + pad }
  }
  const pctOf = (at: number) => (domain ? Math.max(0, Math.min(100, ((at - domain.start) / (domain.end - domain.start)) * 100)) : 0)

  let shown = 0
  const lanes = drafts.map(({ lane, spans }) => {
    lane.bars = spans
      .map(({ job, span }) => {
        const clipped = windowStart !== null && span.startAt < windowStart
        const verifiedAt = job.verified ? ms(job.verifiedAt) : null
        return {
          jobId: job.id,
          name: job.name,
          assetName: job.assetName,
          display: jobDisplayStatus(job),
          ...span,
          clipped,
          startPct: pctOf(span.startAt),
          endPct: pctOf(span.endAt),
          phaseIndex: job.sequence?.phaseIndex ?? null,
          phaseName: job.sequence?.phaseName ?? null,
          verifiedAt,
          verifiedPct: verifiedAt !== null ? pctOf(verifiedAt) : null,
        }
      })
      .sort((a, b) => (a.phaseIndex ?? 99) - (b.phaseIndex ?? 99) || a.startAt - b.startAt)
    lane.markers = lane.markers.map((marker) => ({ ...marker, pct: pctOf(marker.at) })).sort((a, b) => a.at - b.at)
    shown += lane.bars.length
    return lane
  })

  const ticks: TimelineModel['ticks'] = []
  if (domain) {
    const step = tickStep(domain.end - domain.start)
    const first = Math.ceil(domain.start / step) * step
    for (let at = first; at <= domain.end && ticks.length < 14; at += step) ticks.push({ at, pct: pctOf(at), label: tickLabel(at, step) })
  }

  return {
    domain,
    ticks,
    nowPct: domain ? pctOf(now) : null,
    lanes,
    shown,
    listed: snapshot.jobs.length,
    total: snapshot.metrics.total,
    truncated: snapshot.jobsTruncated || snapshot.jobsListed < snapshot.metrics.total,
    outsideWindow,
    scheduleRecorded: snapshot.plans.filter((plan) => Boolean(plan.scheduledAt)).length,
    planCount: snapshot.plans.length,
    overduePlans: snapshot.metrics.overduePlans ?? snapshot.plans.filter((plan) => plan.schedule === 'overdue').length,
  }
}

/* ------------------------------------------------------------------ */
/* Chronology — recorded milestones, newest first                      */
/* ------------------------------------------------------------------ */

export type ChronologyKind = 'recorded' | 'approved' | 'scheduled' | 'started' | 'completed' | 'verified' | 'failed' | 'event'

export interface ChronologyEntry {
  id: string
  at: number
  kind: ChronologyKind
  title: string
  detail: string
  jobId: string | null
  tone: 'good' | 'warning' | 'critical' | 'info' | 'neutral'
}

export interface ChronologyDay {
  day: string
  entries: ChronologyEntry[]
}

const CHRONOLOGY_CAP = 160

/**
 * The activity record: every timestamp the platform actually wrote for the
 * listed jobs and their plans, plus the migration event log. This is what the
 * page shows instead of a plan when no schedule was recorded.
 */
export function buildChronology(snapshot: OrchestrationSnapshot, filters: Pick<TimelineFilters, 'planId' | 'search'>, now: number = Date.now()): { days: ChronologyDay[]; total: number; capped: boolean } {
  const entries: ChronologyEntry[] = []
  const q = filters.search.trim().toLowerCase()
  const jobs = snapshot.jobs.filter((job) => (!filters.planId || job.planId === filters.planId)
    && (!q || `${job.name} ${job.assetName}`.toLowerCase().includes(q)))
  const jobIds = new Set(jobs.map((job) => job.id))

  for (const job of jobs) {
    const push = (kind: ChronologyKind, at: string | null | undefined, title: string, detail: string, tone: ChronologyEntry['tone']) => {
      const t = ms(at)
      if (t !== null) entries.push({ id: `${job.id}:${kind}`, at: t, kind, title, detail, jobId: job.id, tone })
    }
    push('recorded', job.createdAt, `Job recorded — ${job.name}`, `${job.assetName} · ${job.sourceLabel}`, 'neutral')
    push('started', job.startedAt, `Execution started — ${job.name}`, job.executor.assignedAgent ? `Claimed by agent ${job.executor.assignedAgent}` : 'Claimed by an agent', 'info')
    if (job.phase === 'completed') {
      push('completed', job.completedAt, `Executor reported completion — ${job.name}`,
        job.verified ? 'Validation passed (recorded separately).' : job.verification === 'failed' ? 'Recorded validation FAILED.' : 'No passing validation recorded — not verified.',
        job.verified ? 'neutral' : job.verification === 'failed' ? 'critical' : 'warning')
    }
    if (job.verified) push('verified', job.verifiedAt, `Validation passed — ${job.name}`, `${job.validationRecords} validation record${job.validationRecords === 1 ? '' : 's'}`, 'good')
    if (job.phase === 'failed') push('failed', job.updatedAt, `Failed — ${job.name}`, job.failureReason || 'No failure reason was recorded by the executor.', 'critical')
  }
  for (const plan of snapshot.plans) {
    if (filters.planId && plan.id !== filters.planId) continue
    const name = plan.name || `Plan ${plan.id.slice(0, 8)}`
    const approvedAt = ms(plan.approvedAt ?? null)
    if (approvedAt !== null) entries.push({ id: `${plan.id}:approved`, at: approvedAt, kind: 'approved', title: `Plan approved — ${name}`, detail: plan.approvedBy ? `Decision recorded by ${plan.approvedBy}` : 'Approval decision recorded', jobId: null, tone: 'info' })
    const scheduledAt = ms(plan.scheduledAt ?? null)
    if (scheduledAt !== null) {
      entries.push({
        id: `${plan.id}:scheduled`, at: scheduledAt, kind: 'scheduled',
        title: `${scheduledAt > now ? 'Scheduled start (upcoming)' : 'Scheduled start'} — ${name}`,
        detail: plan.schedule === 'overdue' ? 'The recorded start has passed and no job has started.' : 'Recorded on the plan in the Migration Planner.',
        jobId: null, tone: plan.schedule === 'overdue' ? 'warning' : 'info',
      })
    }
  }
  for (const event of snapshot.events) {
    if (filters.planId && event.planId !== filters.planId && (!event.jobId || !jobIds.has(event.jobId))) continue
    if (q && (!event.jobId || !jobIds.has(event.jobId)) && !`${event.type} ${event.message}`.toLowerCase().includes(q)) continue
    const t = ms(event.at)
    if (t === null) continue
    const severity = event.severity.toLowerCase()
    entries.push({
      id: `event:${event.id}`, at: t, kind: 'event',
      title: event.message || event.type,
      detail: `${event.jobName ? `${event.jobName} · ` : ''}event ${event.type}`,
      jobId: event.jobId,
      tone: /error|critical|fail/.test(severity) ? 'critical' : /warn/.test(severity) ? 'warning' : 'neutral',
    })
  }

  entries.sort((a, b) => b.at - a.at)
  const total = entries.length
  const kept = entries.slice(0, CHRONOLOGY_CAP)
  const byDay = new Map<string, ChronologyEntry[]>()
  for (const entry of kept) {
    const day = new Date(entry.at).toISOString().slice(0, 10)
    const list = byDay.get(day) || []
    list.push(entry)
    byDay.set(day, list)
  }
  return { days: [...byDay.entries()].map(([day, list]) => ({ day, entries: list })), total, capped: total > kept.length }
}
