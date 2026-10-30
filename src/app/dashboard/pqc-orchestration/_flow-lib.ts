/**
 * PQC Orchestration — pure derivation of the lifecycle flow
 * DISCOVER → ASSESS → PLAN → APPROVE → EXECUTE → VALIDATE → MONITOR.
 *
 * Two populations, never blended: DISCOVER and ASSESS count ASSETS from the
 * scanner snapshot; PLAN counts the assets that migration jobs reference;
 * APPROVE … MONITOR count JOBS from the orchestration model, partitioned by
 * `jobFlowStage` so the five job stages sum to the operational total. Every
 * stage carries its unit and its source so the reader never compares a job
 * count with an asset count by accident.
 *
 * What it replaced: a 13-stage "Global Orchestration Pipeline" whose stages
 * were marked complete from scanner percentages, a DAG of fixed nodes, a CAB
 * record with a generated RFC number, a 16-template "marketplace", invented
 * policies and a scheduler with a fabricated change freeze. None of it read a
 * migration job. Shared by both pages: `exactCounts`.
 */
import {
  FLOW_JOB_STAGES,
  JOB_DISPLAY_STATUSES,
  jobDisplayStatus,
  jobFlowStage,
  summarizeNextActions,
  type FlowJobStage,
  type JobDisplayStatus,
  type NextActionSummary,
  type OrchestrationJob,
  type OrchestrationSnapshot,
} from '@/lib/migration/orchestration-model'

/* ------------------------------------------------------------------ */
/* Exact counts                                                        */
/* ------------------------------------------------------------------ */

export interface ExactCounts {
  display: Record<JobDisplayStatus, number> | null
  flow: Record<FlowJobStage, number> | null
  nextActions: NextActionSummary[] | null
  /** `server`: counted over every job; `listed`: the list is complete, so it is the same population. */
  basis: 'server' | 'listed' | null
  reason: string | null
}

function tally<K extends string>(jobs: OrchestrationJob[], key: (job: OrchestrationJob) => K, keys: readonly K[]): Record<K, number> {
  const out = Object.fromEntries(keys.map((k) => [k, 0])) as Record<K, number>
  for (const job of jobs) out[key(job)] += 1
  return out
}

/**
 * Per-status and per-stage counts over the WHOLE operational population.
 * The server publishes them; when an older payload lacks them, they are
 * recomputed from the job list only if that list is the whole population —
 * otherwise null with a reason, never a count of the first 200 dressed up as
 * the total.
 */
export function exactCounts(snapshot: OrchestrationSnapshot): ExactCounts {
  const m = snapshot.metrics
  if (m.display && m.flow && snapshot.nextActions) {
    return { display: m.display, flow: m.flow, nextActions: snapshot.nextActions, basis: 'server', reason: null }
  }
  const complete = !snapshot.jobsTruncated && snapshot.jobs.length === m.total
  if (complete) {
    return {
      display: tally(snapshot.jobs, jobDisplayStatus, JOB_DISPLAY_STATUSES),
      flow: tally(snapshot.jobs, jobFlowStage, FLOW_JOB_STAGES),
      nextActions: summarizeNextActions(snapshot.jobs),
      basis: 'listed',
      reason: null,
    }
  }
  return {
    display: null,
    flow: null,
    nextActions: null,
    basis: null,
    reason: 'The server did not publish per-status counts and the job list is capped, so counting it would undercount.',
  }
}

/* ------------------------------------------------------------------ */
/* Lifecycle flow                                                      */
/* ------------------------------------------------------------------ */

export type FlowStageId = 'discover' | 'assess' | 'plan' | 'approve' | 'execute' | 'validate' | 'monitor'

export type FlowTone = 'good' | 'active' | 'attention' | 'idle' | 'unknown'

export interface FlowStage {
  id: FlowStageId
  label: string
  /** The question the stage answers, in plain language. */
  question: string
  source: 'Scanner' | 'Orchestration'
  unit: string
  value: number | null
  /** Why `value` is null. */
  reason: string | null
  tone: FlowTone
  breakdown: Array<{ label: string; value: number | null; tone?: FlowTone }>
  /** Job-table filter the stage applies; null for estate stages. */
  filter: FlowJobStage | 'planned' | null
  href: string
  hrefLabel: string
  explanation: string
}

/** The scanner estate as the page reads it from `useScannerIntelligence`. */
export interface EstateInput {
  /** The scanner server answered (a cache does not count). */
  resolved: boolean
  error: string | null
  totalAssets: number
  vulnerableAssets: number
  totalComponents: number
  vulnerableComponents: number
  pqcReadyComponents: number
  completedScans: number
}

export function buildFlowStages(snapshot: OrchestrationSnapshot, estate: EstateInput): FlowStage[] {
  const m = snapshot.metrics
  const counts = exactCounts(snapshot)
  const d = counts.display
  const f = counts.flow
  const estateReason = estate.error
    ? 'The scanner snapshot could not be read.'
    : estate.resolved ? null : 'Waiting for the scanner snapshot.'
  const estateValue = (value: number) => (estateReason ? null : value)
  const jobsReason = counts.reason
  const dv = (key: JobDisplayStatus) => (d ? d[key] : null)

  const discover = estateValue(estate.totalAssets)
  const vulnerable = estateValue(estate.vulnerableAssets)
  const planned = m.assets.total

  const stage = (s: FlowStage) => s
  return [
    stage({
      id: 'discover', label: 'Discover', question: 'What do we have?', source: 'Scanner', unit: 'assets discovered',
      value: discover, reason: estateReason,
      tone: discover === null ? 'unknown' : discover > 0 ? 'good' : 'idle',
      breakdown: [
        { label: 'Completed scans', value: estateValue(estate.completedScans) },
        { label: 'Cryptographic components', value: estateValue(estate.totalComponents) },
      ],
      filter: null, href: '/dashboard/scanner', hrefLabel: 'Scanner',
      explanation: 'Assets the scanner has inventoried for this tenant. Discovery is owned by the Scanner and its agents; this page only reads the result.',
    }),
    stage({
      id: 'assess', label: 'Assess', question: 'What is quantum-vulnerable?', source: 'Scanner', unit: 'assets with vulnerable crypto',
      value: vulnerable, reason: estateReason,
      tone: vulnerable === null ? 'unknown' : vulnerable > 0 ? 'attention' : discover ? 'good' : 'idle',
      breakdown: [
        { label: 'Vulnerable components', value: estateValue(estate.vulnerableComponents), tone: 'attention' },
        { label: 'PQC-ready components', value: estateValue(estate.pqcReadyComponents), tone: 'good' },
      ],
      filter: null, href: '/dashboard/quantum-readiness', hrefLabel: 'Quantum Readiness',
      explanation: 'Assets whose inventoried cryptography is quantum-vulnerable (RSA, ECDSA, ECDH, classical DH…). These are candidates for a migration plan.',
    }),
    stage({
      id: 'plan', label: 'Plan', question: 'What have we decided to change?', source: 'Orchestration', unit: 'assets in migration jobs',
      value: planned, reason: null,
      tone: planned > 0 ? 'active' : vulnerable ? 'attention' : 'idle',
      breakdown: [
        { label: 'Plans recorded', value: snapshot.plans.length },
        { label: 'Jobs from plans', value: m.planless === undefined ? null : m.total - m.planless },
        { label: 'Remediation without a plan', value: m.planless ?? null },
      ],
      filter: 'planned', href: '/dashboard/migration-planner', hrefLabel: 'Migration Planner',
      explanation: 'Distinct assets referenced by recorded migration jobs. Plans are created in the Migration Planner; per-finding remediation (Harvest Now) creates jobs without a plan.',
    }),
    stage({
      id: 'approve', label: 'Approve', question: 'Who authorised it?', source: 'Orchestration', unit: 'jobs awaiting a decision',
      value: f ? f.approve : null, reason: jobsReason,
      tone: !f ? 'unknown' : f.approve > 0 ? 'attention' : m.total > 0 ? 'good' : 'idle',
      breakdown: [
        { label: 'Awaiting approval', value: dv('awaiting-approval'), tone: 'attention' },
        { label: 'Rejected', value: dv('rejected'), tone: 'attention' },
      ],
      filter: 'approve', href: '/dashboard/migration-planner', hrefLabel: 'Migration Planner',
      explanation: 'No agent takes work until a named person records an approval. A plan status of "approved" is not an approval — only an attributed decision is.',
    }),
    stage({
      id: 'execute', label: 'Execute', question: 'Is it being changed?', source: 'Orchestration', unit: 'jobs in execution',
      value: f ? f.execute : null, reason: jobsReason,
      tone: !f ? 'unknown'
        : (dv('failed') || 0) + (dv('executor-silent') || 0) > 0 ? 'attention'
          : f.execute > 0 ? 'active' : m.total > 0 ? 'good' : 'idle',
      breakdown: [
        { label: 'Ready · queued', value: dv('ready') },
        { label: 'Held · not released', value: dv('not-released') },
        { label: 'Blocked', value: dv('blocked'), tone: 'attention' },
        { label: 'Running', value: dv('running'), tone: 'active' },
        { label: 'Executor silent', value: dv('executor-silent'), tone: 'attention' },
        { label: 'Paused', value: dv('paused') },
        { label: 'Failed', value: dv('failed'), tone: 'attention' },
        { label: 'Rollback', value: dv('rollback') },
      ],
      filter: 'execute', href: '/dashboard/live-migration', hrefLabel: 'Live Migration',
      explanation: 'Approved work moving through dispatch and an agent. Four gates decide it: approval, dispatch (the agent poll\'s refusal record), executor (a capable agent online) and execution.',
    }),
    stage({
      id: 'validate', label: 'Validate', question: 'Did the change work?', source: 'Orchestration', unit: 'jobs not yet verified',
      value: f ? f.validate : null, reason: jobsReason,
      tone: !f ? 'unknown'
        : (dv('validation-failed') || 0) > 0 || (dv('completed-unverified') || 0) > 0 ? 'attention'
          : f.validate > 0 ? 'active' : 'idle',
      breakdown: [
        { label: 'Validating', value: dv('validating'), tone: 'active' },
        { label: 'Completed · unverified', value: dv('completed-unverified'), tone: 'attention' },
        { label: 'Validation failed', value: dv('validation-failed'), tone: 'attention' },
      ],
      filter: 'validate', href: '/dashboard/live-migration', hrefLabel: 'Live Migration',
      explanation: 'An executor saying "completed" is not proof. Only a recorded passing validation moves a job on; until then it stays here, amber.',
    }),
    stage({
      id: 'monitor', label: 'Monitor', question: 'Is it staying fixed?', source: 'Orchestration', unit: 'verified jobs',
      value: f ? f.monitor : null, reason: jobsReason,
      tone: !f ? 'unknown' : f.monitor > 0 ? 'good' : 'idle',
      breakdown: [
        { label: 'Verified assets', value: m.assets.verified, tone: 'good' },
      ],
      filter: 'monitor', href: '/dashboard/drift', hrefLabel: 'Drift Detection',
      explanation: 'Changes with a passing validation record. Continuous monitoring is done by subsequent scans and Drift Detection, not by this page; a verified asset has every job closed and at least one verified.',
    }),
  ]
}

/** Jobs a flow-stage filter selects from the listed jobs. */
export function jobsForStage(jobs: OrchestrationJob[], filter: FlowStage['filter']): OrchestrationJob[] {
  if (!filter) return jobs
  if (filter === 'planned') return jobs.filter((job) => Boolean(job.planId))
  return jobs.filter((job) => jobFlowStage(job) === filter)
}

/* ------------------------------------------------------------------ */
/* Path role check summary                                             */
/* ------------------------------------------------------------------ */

export interface PathPair {
  from: string
  to: string
  check: OrchestrationJob['pathCheck']
  note: string
  jobs: number
  openJobs: number
  jobIds: string[]
}

/** Distinct (source → target) migration paths among the listed jobs, mismatches first. */
export function pathPairs(jobs: OrchestrationJob[]): PathPair[] {
  const map = new Map<string, PathPair>()
  for (const job of jobs) {
    const from = job.fromAlgorithm || 'Not recorded'
    const to = job.targetAlgorithm || 'Not recorded'
    const key = `${from}→${to}→${job.pathCheck}`
    const entry = map.get(key) || { from, to, check: job.pathCheck, note: job.pathNote, jobs: 0, openJobs: 0, jobIds: [] }
    entry.jobs += 1
    if (!['completed', 'cancelled', 'failed'].includes(job.phase)) entry.openJobs += 1
    if (entry.jobIds.length < 50) entry.jobIds.push(job.id)
    map.set(key, entry)
  }
  const order = { 'role-mismatch': 0, unverifiable: 1, consistent: 2 } as const
  return [...map.values()].sort((a, b) => order[a.check] - order[b.check] || b.jobs - a.jobs)
}
