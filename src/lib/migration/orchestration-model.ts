/**
 * PQC orchestration model — where every REAL migration job stands, derived
 * once, read by the Migration Timeline, PQC Orchestration and the check tool.
 *
 * Isomorphic and free of I/O. The api-server router loads the rows; this module
 * turns them into the one vocabulary both pages render.
 *
 * What it replaced, and why each rule below exists:
 *
 *  • The previous orchestrator snapshot WROTE on every GET and every SSE tick:
 *    a job claimed more than 300 s earlier had `assignedAgentId` deleted and was
 *    re-queued, and every failed job was re-queued with a back-off. Agents keep
 *    their first `claimedAt`, so any real migration longer than five minutes was
 *    torn out from under its executor — whose completion event the agent API
 *    then refused (`REMEDIATION_JOB_NOT_CLAIMED`) while a second agent could
 *    claim the same change. Opening a dashboard decided operational outcomes.
 *    This model is read-only. A silent executor is SURFACED (`executorSilent`)
 *    and a failed job is marked retry-eligible; the operator acts through Live
 *    Migration, whose actions re-check approval and take the snapshot.
 *  • Its select asked for `migration_jobs.criticality`, a column that does not
 *    exist (42703). PostgREST rejects the whole select on one unknown column, so
 *    the snapshot always read ZERO jobs and both pages always reported an empty
 *    orchestration — whatever the tenant was running.
 *  • "Validation passed" was `/pass|success|valid|ok|complete/`, which matches
 *    "invalid" and "validation_failed". The exact-token `isPassingValidation`
 *    rule is used instead, per job, not per log row.
 *  • Progress and validation percentages published 0 for an empty estate, and
 *    "worker utilisation" divided by a hard-coded capacity of 64 that nothing
 *    enforces. Unmeasured values are null; invented capacity is gone.
 *  • A completed job is not a migrated asset. Completion and verification are
 *    reported separately, and an asset counts as verified only when a passing
 *    validation is recorded and none of its jobs is still open or failed.
 *  • Sandbox simulations are excluded from operational figures (and counted),
 *    using the shared `isSimulationJob` predicate the agent claim path enforces.
 */
import { HEARTBEAT_ONLINE_WINDOW_MS } from '@/lib/agent-installer/agent-release'
import { isFailingValidation, isPassingValidation, isSimulationJob, jobPlanId, type ApprovalState } from './job-safety'
import {
  AGENT_ROLES_FOR_EXECUTION,
  describeOperationalWorkflow,
  type ExecutionClass,
  type OperationalAgent,
  type OperationalGate,
  type OperationalStage,
} from './operational-workflow'

type Loose = Record<string, unknown>

/* ------------------------------------------------------------------ */
/* Vocabulary                                                          */
/* ------------------------------------------------------------------ */

/**
 * Where a job stands. Disjoint: every operational job is in exactly one phase,
 * so the phase counts partition the total.
 */
export type OrchestrationPhase =
  | 'awaiting-approval' // no recorded approval — no agent will take it
  | 'rejected'          // approval refused
  | 'blocked'           // approved, but dispatch is refused or no capable/online executor
  | 'ready'             // approved, waiting for a capable online agent to claim it
  | 'executing'         // claimed and running on an agent
  | 'validating'        // executor reports post-change validation in progress
  | 'paused'
  | 'completed'         // executor reported completion (see `verification`)
  | 'failed'
  | 'rollback'          // rollback requested or completed
  | 'cancelled'

export const ORCHESTRATION_PHASES: readonly OrchestrationPhase[] = [
  'awaiting-approval', 'rejected', 'blocked', 'ready', 'executing', 'validating',
  'paused', 'completed', 'failed', 'rollback', 'cancelled',
]

export const PHASE_LABEL: Record<OrchestrationPhase, string> = {
  'awaiting-approval': 'Awaiting approval',
  rejected: 'Rejected',
  blocked: 'Blocked',
  ready: 'Ready to dispatch',
  executing: 'Executing',
  validating: 'Validating',
  paused: 'Paused',
  completed: 'Completed',
  failed: 'Failed',
  rollback: 'Rollback',
  cancelled: 'Cancelled',
}

/** Verification of a job's change, from `migration_validation_logs` (+ the job's own record). */
export type VerificationState = 'passed' | 'failed' | 'pending' | 'missing' | 'unavailable'

export const VERIFICATION_LABEL: Record<VerificationState, string> = {
  passed: 'Verified',
  failed: 'Validation failed',
  pending: 'Not yet validated',
  missing: 'No validation recorded',
  unavailable: 'Validation evidence unavailable',
}

/**
 * Does the target algorithm play the same cryptographic ROLE as what it replaces?
 * ML-KEM (FIPS 203) establishes keys; ML-DSA (FIPS 204) and SLH-DSA (FIPS 205)
 * sign. A key-encapsulation target for a signature source is a defect.
 */
export type PathCheck = 'consistent' | 'role-mismatch' | 'unverifiable'

export interface OrchestrationJob {
  id: string
  name: string
  assetId: string | null
  assetName: string
  jobType: string
  executionClass: ExecutionClass
  planId: string | null
  sourceLabel: string
  rawStatus: string
  phase: OrchestrationPhase
  /** Executor-reported progress 0–100; null before anything ran. */
  progress: number | null
  fromAlgorithm: string | null
  targetAlgorithm: string | null
  pathCheck: PathCheck
  pathNote: string
  approval: {
    state: ApprovalState
    approved: boolean
    readable: boolean
    approvedBy: string | null
    approvedAt: string | null
  }
  /** From `describeOperationalWorkflow` — the same verdict Live Migration and the sandbox render. */
  stage: OperationalStage
  headline: string
  nextAction: string
  gates: OperationalGate[]
  executor: {
    assignedAgent: string | null
    assignedAgentId: string | null
    /** Heartbeat of the assigned agent; null when unknown (no assignment or fleet unreadable). */
    online: boolean | null
    lastSeenAt: string | null
  }
  /** Executing/validating, but the assigned agent has not checked in within the heartbeat window. */
  executorSilent: boolean
  verification: VerificationState
  verifiedAt: string | null
  validationRecords: number
  /** Completed AND a passing validation is recorded. */
  verified: boolean
  /** Failed work an operator may retry through Live Migration (which re-checks approval). */
  retry: 'eligible' | 'needs-approval' | null
  failureReason: string | null
  createdAt: string | null
  startedAt: string | null
  completedAt: string | null
  updatedAt: string | null
  /** Most recent recorded event for this job. */
  lastEvent: { type: string; message: string; severity: string; at: string } | null
  links: { liveMigration: string; planner: string | null; asset: string | null }
  /**
   * Phase ordering the Migration Planner recorded on the job
   * (`metadata.execution`), or null when none was recorded. Optional: payloads
   * built before this field existed do not carry it.
   */
  sequence?: JobSequence | null
  /**
   * Whether the job is in a status the agent poll reads at all. An approved job
   * left at `pending` (a later plan phase, a saved or scheduled plan) is never
   * claimed, so it is not "ready". Null for jobs past dispatch.
   */
  release?: { released: boolean; reason: string } | null
}

/** Recorded plan-phase position of a job (Migration Planner `metadata.execution`). */
export interface JobSequence {
  phaseIndex: number | null
  phaseName: string | null
  totalPhases: number | null
  sequenceOrder: number | null
  /** The plan recorded that this phase starts only after the prior phase is approved. */
  gateRequired: boolean
  /** Recorded `execution.sequenceState` (waiting_for_prior_phase, waiting_for_agent …). */
  sequenceState: string | null
  /** Open job whose recorded sequence state says it waits for the prior phase. */
  waitingForPriorPhase: boolean
}

/** One recorded phase of a plan, aggregated over ALL of the plan's jobs. */
export interface OrchestrationPlanPhase {
  index: number
  name: string | null
  jobs: number
  completed: number
  verified: number
  failed: number
  /** Jobs not yet finished (awaiting approval … rollback). */
  open: number
  /** Jobs whose recorded sequence state waits on the prior phase. */
  waitingForPrior: number
  gateRequired: boolean
}

/**
 * Where a plan's RECORDED schedule stands. Only `migration_plans.scheduled_at`
 * (the planner's `scheduleAt`) is a recorded date; nothing records a target
 * completion date, so nothing here invents one.
 */
export type PlanScheduleState = 'not-recorded' | 'upcoming' | 'started' | 'overdue'

export interface OrchestrationPlan {
  id: string
  name: string | null
  approval: ApprovalState
  approvedBy: string | null
  readable: boolean
  jobs: number
  phases: Partial<Record<OrchestrationPhase, number>>
  completed: number
  verified: number
  failed: number
  /** Completed share of the plan's non-cancelled jobs; null when it has none. */
  completionPct: number | null
  verifiedPct: number | null
  firstStartedAt: string | null
  lastActivityAt: string | null
  /* Additive, optional (older payloads omit them) — recorded plan dates. */
  /** `migration_plans.status` as recorded (not an approval — see `approval`). */
  planStatus?: string | null
  createdAt?: string | null
  /** The attributed approval decision time (falls back to `approved_at`, stamped only on approval). */
  approvedAt?: string | null
  /** `migration_plans.scheduled_at` — the only recorded schedule date. */
  scheduledAt?: string | null
  schedule?: PlanScheduleState
  /** Earliest job record time in the plan. */
  firstCreatedAt?: string | null
  lastCompletedAt?: string | null
  openJobs?: number
  /** Recorded phases, ascending; empty when no job recorded a phase. */
  phaseOrder?: OrchestrationPlanPhase[]
}

export interface OrchestrationEvent {
  id: string
  jobId: string | null
  planId?: string | null
  jobName: string | null
  type: string
  severity: string
  message: string
  at: string
}

export type SourceState = 'ok' | 'unavailable' | 'truncated'

export interface OrchestrationMetrics {
  /** Operational (non-simulation) jobs read. */
  total: number
  simulationsExcluded: number
  phases: Record<OrchestrationPhase, number>
  completed: number
  verified: number
  /** Completed with no passing validation yet (pending or missing). */
  completedUnverified: number
  /** Completed, but the recorded validation FAILED — needs an operator. */
  completedValidationFailed: number
  completedValidationUnavailable?: number
  /** completed / (total − cancelled); null when nothing is in scope. */
  completionPct: number | null
  verifiedPct: number | null
  assets: {
    total: number
    verified: number
    inFlight: number
    needsAttention: number
  }
  executors: {
    fleetReadable: boolean
    enrolled: number | null
    migrationCapable: number | null
    remediationCapable: number | null
    online: number | null
  }
  staleExecutions: number
  retryEligible: number
  awaitingApproval: number
  blocked: number
  /** Mean executor-reported duration of completed jobs; null with no timed completion. */
  avgDurationSeconds: number | null
  completedLast24h: number
  connectors: { healthy: number; total: number }
  /* Additive, optional — exact counts over EVERY operational job (the job list is capped). */
  display?: Record<JobDisplayStatus, number>
  flow?: Record<FlowJobStage, number>
  pathChecks?: Record<PathCheck, number>
  /** Open jobs (not completed/cancelled) whose path check is a role mismatch. */
  openRoleMismatches?: number
  /** Approved, but at a status the agent poll does not read. */
  notReleased?: number
  /** Jobs that declare no migration plan (per-finding remediation). */
  planless?: number
  /** Plans whose recorded scheduled start passed with nothing started. */
  overduePlans?: number
}

export interface OrchestrationSnapshot {
  generatedAt: string
  hasData: boolean
  metrics: OrchestrationMetrics
  /** Most urgent first, capped at `jobsListed`; `metrics.total` is exact. */
  jobs: OrchestrationJob[]
  jobsListed: number
  jobsTruncated: boolean
  plans: OrchestrationPlan[]
  /** Daily completions over the last 14 days (UTC), oldest first. */
  throughput: Array<{ date: string; completed: number; verified: number; failed: number }>
  events: OrchestrationEvent[]
  agents: Array<{ id: string; name: string; role: string | null; online: boolean; lastSeenAt: string | null; assignedJobs: number }>
  /** `schedules` is optional: the plan-date read was added after the original contract. */
  sources: Record<'jobs' | 'plans' | 'agents' | 'validations' | 'events' | 'connectors' | 'assets', SourceState> & { schedules?: SourceState }
  scopeNote: string
  /** Ranked next actions over every operational job (additive, optional). */
  nextActions?: NextActionSummary[]
}

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

export interface OrchestrationInputs {
  jobs: Loose[]
  /** Server-side `jobExecutionClass(job)` — the classifier the agent claim path uses. */
  executionClassOf: (job: Loose) => ExecutionClass
  /** Plans the jobs declare, projected to what `planApproval` reads. */
  plans: Map<string, { status?: unknown; metadata?: unknown; name?: unknown }>
  /** Plan ids that were actually queried (a planned job whose plan was never read is "unreadable", not "not approved"). */
  plansQueried: Set<string>
  /** Enrolled agents, or null when the fleet could not be read (never rendered as "none"). */
  agents: OperationalAgent[] | null
  validations: Loose[]
  events: Loose[]
  connectors: Loose[]
  assetNames: Map<string, string>
  sources: OrchestrationSnapshot['sources']
  jobsTruncated: boolean
  now?: number
  /**
   * Recorded plan dates (`migration_plans` created_at / approved_at /
   * scheduled_at / status), keyed by plan id. Optional and additive; absent →
   * the dates are reported as not recorded, never invented.
   */
  planRecords?: Map<string, { status?: unknown; created_at?: unknown; approved_at?: unknown; scheduled_at?: unknown }>
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

const LIST_CAP = 200
const EVENT_CAP = 50
const THROUGHPUT_DAYS = 14

function rec(value: unknown): Loose {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Loose) : {}
}

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value == null ? '' : String(value).trim()
}

function ms(value: unknown): number {
  const t = Date.parse(str(value))
  return Number.isFinite(t) ? t : 0
}

function iso(value: unknown): string | null {
  return ms(value) ? new Date(ms(value)).toISOString() : null
}

function pct(part: number, whole: number): number | null {
  return whole > 0 ? Math.round((part / whole) * 100) : null
}

/**
 * Raw `migration_jobs.status` → the orchestration status vocabulary. Unknown
 * tokens fall to `queued` (the schema default is `pending`), matching how Live
 * Migration and the sandbox read the same column.
 */
export function orchestrationStatus(raw: unknown): 'queued' | 'running' | 'validating' | 'paused' | 'completed' | 'failed' | 'rollback_requested' | 'rolled_back' | 'stopped' {
  const v = str(raw).toLowerCase().replace(/\s+/g, '_')
  if (['completed', 'complete', 'done', 'success', 'succeeded'].includes(v)) return 'completed'
  if (['failed', 'error', 'errored', 'rollback_failed', 'validation_failed', 'dead_letter'].includes(v)) return 'failed'
  if (['validating', 'verifying', 'validation'].includes(v)) return 'validating'
  if (['running', 'in_progress', 'executing', 'migrating', 'claimed', 'leased'].includes(v)) return 'running'
  if (['rollback_requested', 'rollback', 'rolling_back'].includes(v)) return 'rollback_requested'
  if (['rolled_back', 'rollback_complete', 'restored'].includes(v)) return 'rolled_back'
  if (['stopped', 'stop', 'cancelled', 'canceled', 'aborted'].includes(v)) return 'stopped'
  if (v === 'paused') return 'paused'
  return 'queued'
}

const KEM_TARGET = /ML-?KEM|KYBER|FIPS\s*203/i
const SIGNATURE_TARGET = /ML-?DSA|SLH-?DSA|DILITHIUM|SPHINCS|FALCON|FN-?DSA|FIPS\s*20[45]/i
const SIGNATURE_SOURCE = /ECDSA|ED25519|ED448|EDDSA|\bDSA\b|RSA-?PSS|PKCS#?1.?SIG|SIGNATURE|SIGNING|CERT(IFICATE)?|X\.?509|CODE.?SIGN|JWT|JWS|SAML/i
const KEX_SOURCE = /ECDHE?|X25519|X448|\bDHE?\b|DIFFIE|KEY.?EXCHANGE|KEX|KEY.?AGREEMENT|KEY.?ESTABLISH|TLS_RSA_WITH|RSA.?KEY.?TRANSPORT|KEM\b/i

/**
 * Role check for a planned migration path. Only answers when BOTH sides carry a
 * role-identifying token; RSA alone is used for signatures and key transport
 * alike, so a bare "RSA-2048" with no job context is `unverifiable`, never a
 * guessed pass.
 */
export function migrationPathCheck(from: string | null, target: string | null, jobType = ''): { check: PathCheck; note: string } {
  const to = str(target)
  if (!to) return { check: 'unverifiable', note: 'No target algorithm recorded on the job.' }
  const targetRole = KEM_TARGET.test(to) && SIGNATURE_TARGET.test(to)
    ? 'both'
    : KEM_TARGET.test(to) ? 'kem' : SIGNATURE_TARGET.test(to) ? 'signature' : null
  if (!targetRole) return { check: 'unverifiable', note: `Target "${to}" is not a NIST PQC primitive this check recognises.` }
  const context = `${str(from)} ${jobType}`
  const sourceIsSig = SIGNATURE_SOURCE.test(context) || /cert[_-]?transition|signature|signing/i.test(jobType)
  const sourceIsKex = KEX_SOURCE.test(context) || /protocol[_-]?upgrade|tls|key[_-]?exchange/i.test(jobType)
  if (!sourceIsSig && !sourceIsKex) return { check: 'unverifiable', note: 'The source algorithm does not identify its role (key establishment or signature).' }
  if (targetRole === 'both' || (sourceIsSig && sourceIsKex)) return { check: 'consistent', note: 'Target covers the roles the source plays.' }
  if (sourceIsSig && targetRole === 'kem') {
    return { check: 'role-mismatch', note: `${to} is a key-encapsulation mechanism (FIPS 203); a signature source needs ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).` }
  }
  if (sourceIsKex && targetRole === 'signature') {
    return { check: 'role-mismatch', note: `${to} is a signature scheme; key establishment needs ML-KEM (FIPS 203), typically hybrid X25519 + ML-KEM-768.` }
  }
  return { check: 'consistent', note: targetRole === 'kem' ? 'Key establishment → ML-KEM (FIPS 203).' : 'Signature → ML-DSA / SLH-DSA (FIPS 204/205).' }
}

function sourceAlgorithmOf(meta: Loose): string | null {
  for (const key of ['sourceAlgorithm', 'source_algorithm', 'fromAlgorithm', 'from_algorithm', 'currentAlgorithm', 'algorithm']) {
    const value = str(meta[key])
    if (value) return value
  }
  return null
}

/**
 * Statuses the agent job poll reads (`GET /agent/remediation/jobs` in
 * api-server/agent-scanner.ts: `.in('status', [...])`). Anything else — the
 * schema default `pending` above all — is never claimed, whatever its approval.
 * tools/orchestrator-check.ts fails if this list drifts from the poll.
 */
export const AGENT_CLAIMABLE_STATUSES: readonly string[] = ['queued', 'awaiting_agent', 'running', 'in_progress', 'executing']

/** Phases of work that is not finished. */
const OPEN_PHASES: readonly OrchestrationPhase[] = ['awaiting-approval', 'blocked', 'ready', 'executing', 'validating', 'paused', 'rollback']

function positiveInt(value: unknown): number | null {
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? Math.round(n) : null
}

function sequenceOf(execution: Loose, phase: OrchestrationPhase): JobSequence | null {
  const phaseIndex = positiveInt(execution.phaseIndex)
  const phaseName = str(execution.phaseName) || null
  if (phaseIndex === null && !phaseName) return null
  const sequenceState = str(execution.sequenceState) || null
  const waiting = sequenceState === 'waiting_for_prior_phase'
    && ['awaiting-approval', 'blocked', 'ready', 'paused'].includes(phase)
  return {
    phaseIndex,
    phaseName,
    totalPhases: positiveInt(execution.totalPhases),
    sequenceOrder: positiveInt(execution.sequenceOrder),
    gateRequired: execution.gateRequired === true,
    sequenceState,
    waitingForPriorPhase: waiting,
  }
}

const PHASE_URGENCY: Record<OrchestrationPhase, number> = {
  failed: 0,
  blocked: 2,
  rejected: 3,
  validating: 4,
  executing: 4,
  'awaiting-approval': 5,
  ready: 6,
  paused: 7,
  rollback: 8,
  completed: 9,
  cancelled: 11,
}

function urgency(job: OrchestrationJob): number {
  if (job.executorSilent) return 1
  if (job.phase === 'completed' && job.verification === 'failed') return 1
  if (job.phase === 'completed' && job.verified) return 10
  return PHASE_URGENCY[job.phase]
}

type JobValidationIndex = Map<string, { latest: Loose; count: number }>

export function indexJobValidations(rows: Loose[]): JobValidationIndex {
  const index: JobValidationIndex = new Map()
  for (const row of rows) {
    const jobId = str(row.migration_id || row.migration_job_id || row.job_id)
    if (!jobId) continue
    const entry = index.get(jobId)
    const replace = !entry || ms(row.created_at) > ms(entry.latest.created_at) ||
      (ms(row.created_at) === ms(entry.latest.created_at) && str(row.id) > str(entry.latest.id))
    index.set(jobId, { latest: replace ? row : entry!.latest, count: (entry?.count ?? 0) + 1 })
  }
  return index
}

export function readJobVerification(job: Loose, index: JobValidationIndex, source: SourceState, completed: boolean) {
  const records = index.get(str(job.id))
  const metadata = rec(rec(job.metadata).lastValidation ?? job.last_validation)
  const latest = records?.latest
  const status = str(latest?.status) || str(metadata.status) ||
    (metadata.passed === true ? 'passed' : metadata.passed === false ? 'failed' : '')
  let state: VerificationState = completed && !status ? 'missing' : 'pending'
  if (source === 'unavailable' || (source === 'truncated' && !latest)) state = 'unavailable'
  else if (isPassingValidation(status)) state = 'passed'
  else if (isFailingValidation(status)) state = 'failed'
  const at = state === 'passed' ? iso(latest?.created_at) || iso(metadata.at || metadata.validatedAt) : null
  return { state, at, count: records?.count ?? 0 }
}

/* ------------------------------------------------------------------ */
/* Builder                                                             */
/* ------------------------------------------------------------------ */

export function buildOrchestrationSnapshot(input: OrchestrationInputs): OrchestrationSnapshot {
  const now = input.now ?? Date.now()
  const operationalRows = input.jobs.filter((row) => !isSimulationJob(row))
  const simulationsExcluded = input.jobs.length - operationalRows.length

  const validationsByJob = indexJobValidations(input.validations)

  const operationalIds = new Set(operationalRows.map((row) => str(row.id)))
  const eventsSorted = input.events
    .filter((row) => !isSimulationJob({ job_type: row.event_type, metadata: row.metadata }))
    .filter((row) => !str(row.migration_id) || operationalIds.has(str(row.migration_id)))
    .sort((a, b) => ms(b.created_at) - ms(a.created_at))
  const lastEventByJob = new Map<string, Loose>()
  for (const row of eventsSorted) {
    const jobId = str(row.migration_id)
    if (jobId && !lastEventByJob.has(jobId)) lastEventByJob.set(jobId, row)
  }

  const agentById = new Map((input.agents || []).map((agent) => [agent.id, agent]))
  const isOnline = (agent: OperationalAgent | undefined) => {
    const seen = agent?.lastSeenAt ? Date.parse(agent.lastSeenAt) : 0
    return Boolean(seen) && now - seen <= HEARTBEAT_ONLINE_WINDOW_MS && !agent?.revoked
  }

  const jobs: OrchestrationJob[] = operationalRows.map((row) => {
    const meta = rec(row.metadata)
    const id = str(row.id)
    const status = orchestrationStatus(row.status)
    const planId = jobPlanId(row) || null
    const executionClass = input.executionClassOf(row)
    const describeStatus = status === 'validating' ? 'running' : status
    const plan = planId ? input.plans.get(planId) || null : null
    const operational = describeOperationalWorkflow({
      job: row,
      status: describeStatus,
      progress: Number(row.progress) || 0,
      plan,
      planReadable: !planId || input.plansQueried.has(planId),
      executionClass,
      agents: input.agents,
      now,
    })

    let phase: OrchestrationPhase
    switch (status) {
      case 'completed': phase = 'completed'; break
      case 'failed': phase = 'failed'; break
      case 'rollback_requested':
      case 'rolled_back': phase = 'rollback'; break
      case 'stopped': phase = 'cancelled'; break
      case 'paused': phase = 'paused'; break
      case 'validating': phase = 'validating'; break
      case 'running': phase = 'executing'; break
      default:
        phase = operational.stage === 'rejected'
          ? 'rejected'
          : operational.stage === 'awaiting-approval' || operational.stage === 'approval-unreadable'
            ? 'awaiting-approval'
            : operational.stage === 'awaiting-claim'
              ? 'ready'
              : 'blocked'
    }

    // Release: an approved queued-family job is dispatchable only at a status
    // the agent poll reads. `pending` (later plan phases, saved/scheduled
    // plans) is never claimed — it is held, not "ready".
    const rawToken = str(row.status).toLowerCase().replace(/\s+/g, '_')
    const sequence = sequenceOf(rec(meta.execution), phase)
    const release = status === 'queued'
      ? AGENT_CLAIMABLE_STATUSES.includes(rawToken)
        ? { released: true, reason: 'Queued for the agent poll.' }
        : {
            released: false,
            reason: sequence?.waitingForPriorPhase
              ? `Phase ${sequence.phaseIndex ?? '?'}${sequence.totalPhases ? ` of ${sequence.totalPhases}` : ''} waits for the prior phase to be approved.`
              : `Status "${str(row.status) || 'pending'}" is not polled by agents — execution has not been started for it.`,
          }
      : null
    const heldNotReleased = phase === 'ready' && release?.released === false
    if (heldNotReleased) phase = 'blocked'

    const { state: verification, at: verifiedAt, count: validationRecords } =
      readJobVerification(row, validationsByJob, input.sources.validations, phase === 'completed')
    const verified = phase === 'completed' && verification === 'passed'

    const assignedAgentId = str(meta.assignedAgentId || meta.assigned_agent_id) || null
    const assignedAgent = agentById.get(assignedAgentId || '')
    const executorOnline = assignedAgentId && input.agents ? isOnline(assignedAgent) : null
    const executorSilent = (phase === 'executing' || phase === 'validating') && executorOnline === false

    const from = sourceAlgorithmOf(meta)
    const target = str(row.target_algorithm) || str(meta.targetAlgorithm || meta.target_algorithm) || null
    const path = migrationPathCheck(from, target, str(row.job_type))

    const event = lastEventByJob.get(id)
    const assetId = str(row.asset_id) || null
    // The agent event endpoint records a failure in `lastExecutorEvent` /
    // `executorState`, not `failureReason`; read those too, or every
    // agent-reported failure reaches the page without its reason.
    const executorEvent = rec(meta.lastExecutorEvent)
    const executorState = rec(meta.executorState)
    const executorFailure = str(executorEvent.status).toLowerCase() === 'failed'
      ? str(executorEvent.message)
      : str(executorState.status).toLowerCase() === 'failed' ? str(executorState.currentStep) : ''
    const failureReason = phase === 'failed' ? str(meta.failureReason || meta.error || meta.lastError) || executorFailure || null : null

    let headline = executorSilent
      ? `Executor ${operational.executor.assignedAgent || assignedAgentId} has not checked in for over ${Math.round(HEARTBEAT_ONLINE_WINDOW_MS / 60000)} minutes.`
      : phase === 'failed' && !str(meta.failureReason || meta.error) && executorFailure
        ? `Failed: ${executorFailure}`
        : operational.headline
    let nextAction = executorSilent
      ? 'Check the agent host. The job is NOT re-queued automatically — a second executor must never take a change that may still be running. Retry or roll back from Live Migration once the executor state is known.'
      : phase === 'completed' && verification !== 'passed'
        ? verification === 'failed'
          ? 'The executor reported completion but the recorded validation failed. Review the evidence and roll back or remediate from Live Migration.'
          : 'Completed but not verified. Record post-change validation evidence before treating this asset as migrated.'
        : operational.nextAction
    let gates = operational.gates
    if (heldNotReleased && release) {
      headline = sequence?.waitingForPriorPhase
        ? `Approved — held: ${release.reason}`
        : `Approved — not released for dispatch. ${release.reason}`
      nextAction = sequence?.waitingForPriorPhase
        ? 'Approve the next phase in Live Migration Operations once the prior phase has completed and been verified. Agents only poll released (queued) jobs.'
        : 'Start execution for this plan in Live Migration Operations, which re-checks approval and takes the pre-change snapshot before queueing the job for an agent.'
      gates = gates.map((gate) => (gate.id === 'dispatch' && gate.state !== 'fail'
        ? { ...gate, state: 'pending' as const, detail: `Not released — ${release.reason}` }
        : gate))
    }
    const progressRaw = Number(row.progress)
    const progress = phase === 'completed'
      ? 100
      : Number.isFinite(progressRaw) && progressRaw > 0 ? Math.max(0, Math.min(100, Math.round(progressRaw))) : null

    return {
      id,
      name: str(row.name) || `Migration ${id.slice(0, 8)}`,
      assetId,
      assetName: (assetId && input.assetNames.get(assetId)) || str(meta.assetName || meta.asset_name || meta.target || meta.host) || 'Unlinked asset',
      jobType: str(row.job_type) || 'migration',
      executionClass,
      planId,
      sourceLabel: operational.sourceLabel,
      rawStatus: str(row.status),
      phase,
      progress,
      fromAlgorithm: from,
      targetAlgorithm: target,
      pathCheck: path.check,
      pathNote: path.note,
      approval: {
        state: operational.approval.state,
        approved: operational.approval.approved,
        readable: operational.approvalReadable,
        approvedBy: operational.approval.approvedBy || null,
        approvedAt: operational.approval.approvedAt || null,
      },
      stage: operational.stage,
      headline,
      nextAction,
      gates,
      executor: {
        assignedAgent: operational.executor.assignedAgent,
        assignedAgentId,
        online: executorOnline,
        lastSeenAt: assignedAgent?.lastSeenAt || null,
      },
      executorSilent,
      verification,
      verifiedAt,
      validationRecords,
      verified,
      retry: phase === 'failed' ? (operational.approval.approved ? 'eligible' : 'needs-approval') : null,
      failureReason,
      createdAt: iso(row.created_at),
      startedAt: iso(row.started_at),
      completedAt: iso(row.completed_at),
      updatedAt: iso(row.updated_at) || iso(row.created_at),
      lastEvent: event
        ? { type: str(event.event_type), message: str(event.message), severity: str(event.severity) || 'info', at: iso(event.created_at) || '' }
        : null,
      links: {
        liveMigration: operational.links.liveMigration,
        planner: operational.links.planner,
        asset: assetId ? `/dashboard/assets?asset=${encodeURIComponent(assetId)}` : null,
      },
      sequence,
      release,
    }
  })

  /* -- metrics: every figure is a projection of `jobs` ----------------- */
  const phases = Object.fromEntries(ORCHESTRATION_PHASES.map((p) => [p, 0])) as Record<OrchestrationPhase, number>
  for (const job of jobs) phases[job.phase] += 1

  const completedJobs = jobs.filter((job) => job.phase === 'completed')
  const verified = completedJobs.filter((job) => job.verified).length
  const completedValidationFailed = completedJobs.filter((job) => job.verification === 'failed').length
  const completedValidationUnavailable = completedJobs.filter((job) => job.verification === 'unavailable').length
  const inScope = jobs.length - phases.cancelled

  const byAsset = new Map<string, OrchestrationJob[]>()
  for (const job of jobs) {
    if (!job.assetId) continue
    const list = byAsset.get(job.assetId) || []
    list.push(job)
    byAsset.set(job.assetId, list)
  }
  const OPEN: OrchestrationPhase[] = ['awaiting-approval', 'blocked', 'ready', 'executing', 'validating', 'paused', 'rollback']
  let assetsVerified = 0
  let assetsInFlight = 0
  let assetsAttention = 0
  for (const list of byAsset.values()) {
    const required = list.filter((job) => job.phase !== 'cancelled')
    if (required.length && required.every((job) => job.verified)) assetsVerified += 1
    if (list.some((job) => job.phase === 'executing' || job.phase === 'validating')) assetsInFlight += 1
    if (list.some((job) => job.phase === 'failed' || job.phase === 'blocked' || job.executorSilent || (job.phase === 'completed' && !job.verified))) assetsAttention += 1
  }

  const durations = completedJobs
    .map((job) => (job.startedAt && job.completedAt ? (Date.parse(job.completedAt) - Date.parse(job.startedAt)) / 1000 : 0))
    .filter((seconds) => seconds > 0)

  const fleet = input.agents
  const nonRevoked = fleet ? fleet.filter((agent) => !agent.revoked) : null
  // Same role table and write-authority rule `describeOperationalWorkflow` applies per job.
  const capable = (cls: ExecutionClass) => (nonRevoked
    ? nonRevoked.filter((agent) => (AGENT_ROLES_FOR_EXECUTION[cls] as readonly string[]).includes(str(agent.role))
        && (!agent.writeAuthority || agent.writeAuthority[cls] === true)).length
    : null)

  const metrics: OrchestrationMetrics = {
    total: jobs.length,
    simulationsExcluded,
    phases,
    completed: completedJobs.length,
    verified,
    completedUnverified: completedJobs.length - verified - completedValidationFailed - completedValidationUnavailable,
    completedValidationFailed,
    completedValidationUnavailable,
    completionPct: pct(completedJobs.length, inScope),
    verifiedPct: pct(verified, inScope),
    assets: { total: byAsset.size, verified: assetsVerified, inFlight: assetsInFlight, needsAttention: assetsAttention },
    executors: {
      fleetReadable: Boolean(fleet),
      enrolled: nonRevoked ? nonRevoked.length : null,
      migrationCapable: capable('migration'),
      remediationCapable: capable('remediation'),
      online: nonRevoked ? nonRevoked.filter((agent) => isOnline(agent)).length : null,
    },
    staleExecutions: jobs.filter((job) => job.executorSilent).length,
    retryEligible: jobs.filter((job) => job.retry === 'eligible').length,
    awaitingApproval: phases['awaiting-approval'],
    blocked: phases.blocked,
    avgDurationSeconds: durations.length ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length) : null,
    completedLast24h: completedJobs.filter((job) => job.completedAt && now - Date.parse(job.completedAt) <= 86_400_000).length,
    connectors: {
      healthy: input.connectors.filter((row) => ['active', 'connected', 'healthy'].includes(str(row.status).toLowerCase())).length,
      total: input.connectors.length,
    },
    display: countBy(jobs, jobDisplayStatus, JOB_DISPLAY_STATUSES),
    flow: countBy(jobs, jobFlowStage, FLOW_JOB_STAGES),
    pathChecks: countBy(jobs, (job) => job.pathCheck, ['consistent', 'role-mismatch', 'unverifiable'] as const),
    openRoleMismatches: jobs.filter((job) => job.pathCheck === 'role-mismatch' && OPEN_PHASES.includes(job.phase)).length,
    notReleased: jobs.filter((job) => jobDisplayStatus(job) === 'not-released').length,
    planless: jobs.filter((job) => !job.planId).length,
  }

  /* -- plans ------------------------------------------------------------ */
  const planGroups = new Map<string, OrchestrationJob[]>()
  for (const job of jobs) {
    if (!job.planId) continue
    const list = planGroups.get(job.planId) || []
    list.push(job)
    planGroups.set(job.planId, list)
  }
  const plans: OrchestrationPlan[] = [...planGroups.entries()].map(([id, list]) => {
    const planPhases: Partial<Record<OrchestrationPhase, number>> = {}
    for (const job of list) planPhases[job.phase] = (planPhases[job.phase] || 0) + 1
    const planScope = list.length - (planPhases.cancelled || 0)
    const completed = planPhases.completed || 0
    const planVerified = list.filter((job) => job.verified).length
    const starts = list.map((job) => (job.startedAt ? Date.parse(job.startedAt) : 0)).filter(Boolean)
    const activity = list.map((job) => (job.updatedAt ? Date.parse(job.updatedAt) : 0)).filter(Boolean)
    const head = list[0]
    const planRow = input.plans.get(id)
    const record = input.planRecords?.get(id)
    const created = list.map((job) => (job.createdAt ? Date.parse(job.createdAt) : 0)).filter(Boolean)
    const completions = list.map((job) => (job.completedAt ? Date.parse(job.completedAt) : 0)).filter(Boolean)
    const scheduledAt = iso(record?.scheduled_at)
    const openJobs = list.filter((job) => OPEN_PHASES.includes(job.phase)).length
    const startedAny = starts.length > 0 || completed > 0
    const schedule: PlanScheduleState = !scheduledAt
      ? 'not-recorded'
      : startedAny
        ? 'started'
        : Date.parse(scheduledAt) > now
          ? 'upcoming'
          : openJobs > 0 ? 'overdue' : 'not-recorded'
    return {
      id,
      name: str(planRow?.name) || null,
      approval: head.approval.state,
      approvedBy: head.approval.approvedBy,
      readable: head.approval.readable,
      jobs: list.length,
      phases: planPhases,
      completed,
      verified: planVerified,
      failed: planPhases.failed || 0,
      completionPct: pct(completed, planScope),
      verifiedPct: pct(planVerified, planScope),
      firstStartedAt: starts.length ? new Date(Math.min(...starts)).toISOString() : null,
      lastActivityAt: activity.length ? new Date(Math.max(...activity)).toISOString() : null,
      planStatus: str(record?.status ?? planRow?.status) || null,
      createdAt: iso(record?.created_at),
      // The attributed decision time; `approved_at` is only stamped when an approval exists.
      approvedAt: head.approval.state === 'approved' ? iso(head.approval.approvedAt) || iso(record?.approved_at) : null,
      scheduledAt,
      schedule,
      firstCreatedAt: created.length ? new Date(Math.min(...created)).toISOString() : null,
      lastCompletedAt: completions.length ? new Date(Math.max(...completions)).toISOString() : null,
      openJobs,
      phaseOrder: planPhaseOrder(list),
    }
  }).sort((a, b) => (Date.parse(b.lastActivityAt || '') || 0) - (Date.parse(a.lastActivityAt || '') || 0))

  /* -- throughput: daily completions, UTC -------------------------------- */
  const dayKey = (t: number) => new Date(t).toISOString().slice(0, 10)
  const days: OrchestrationSnapshot['throughput'] = []
  for (let i = THROUGHPUT_DAYS - 1; i >= 0; i -= 1) days.push({ date: dayKey(now - i * 86_400_000), completed: 0, verified: 0, failed: 0 })
  const dayIndex = new Map(days.map((d, index) => [d.date, index]))
  for (const job of jobs) {
    if (job.phase === 'completed' && job.completedAt) {
      const index = dayIndex.get(dayKey(Date.parse(job.completedAt)))
      if (index !== undefined) {
        days[index].completed += 1
        if (job.verified) days[index].verified += 1
      }
    }
    if (job.phase === 'failed' && job.updatedAt) {
      const index = dayIndex.get(dayKey(Date.parse(job.updatedAt)))
      if (index !== undefined) days[index].failed += 1
    }
  }

  const jobNames = new Map(jobs.map((job) => [job.id, job.name]))
  const jobPlans = new Map(jobs.map((job) => [job.id, job.planId]))
  const events: OrchestrationEvent[] = eventsSorted.slice(0, EVENT_CAP).map((row) => ({
    id: str(row.id),
    jobId: str(row.migration_id) || null,
    planId: jobPlanId(row) || jobPlans.get(str(row.migration_id)) || null,
    jobName: jobNames.get(str(row.migration_id)) || null,
    type: str(row.event_type) || 'event',
    severity: str(row.severity) || 'info',
    message: str(row.message),
    at: iso(row.created_at) || '',
  }))

  const assignedCounts = new Map<string, number>()
  for (const job of jobs) {
    if (job.executor.assignedAgentId && (job.phase === 'executing' || job.phase === 'validating')) {
      assignedCounts.set(job.executor.assignedAgentId, (assignedCounts.get(job.executor.assignedAgentId) || 0) + 1)
    }
  }
  const agents = (nonRevoked || []).slice(0, 60).map((agent) => ({
    id: agent.id,
    name: str(agent.name) || agent.id,
    role: agent.role || null,
    online: isOnline(agent),
    lastSeenAt: agent.lastSeenAt || null,
    assignedJobs: assignedCounts.get(agent.id) || 0,
  }))

  const ranked = [...jobs].sort((a, b) => urgency(a) - urgency(b) || (Date.parse(b.updatedAt || '') || 0) - (Date.parse(a.updatedAt || '') || 0))
  metrics.overduePlans = plans.filter((plan) => plan.schedule === 'overdue').length

  return {
    generatedAt: new Date(now).toISOString(),
    hasData: jobs.length > 0,
    metrics,
    jobs: ranked.slice(0, LIST_CAP),
    jobsListed: Math.min(LIST_CAP, ranked.length),
    jobsTruncated: input.jobsTruncated,
    plans,
    throughput: days,
    events,
    agents,
    sources: input.sources,
    scopeNote: simulationsExcluded > 0
      ? `Operational migration jobs only — ${simulationsExcluded} sandbox simulation(s) are excluded; they never reach an agent.`
      : 'Operational migration jobs recorded for this tenant.',
    nextActions: summarizeNextActions(jobs),
  }
}

/* ------------------------------------------------------------------ */
/* Additive: shared vocabularies both pages render                     */
/* ------------------------------------------------------------------ */

function countBy<T, K extends string>(items: T[], key: (item: T) => K, keys: readonly K[]): Record<K, number> {
  const out = Object.fromEntries(keys.map((k) => [k, 0])) as Record<K, number>
  for (const item of items) out[key(item)] += 1
  return out
}

function planPhaseOrder(list: OrchestrationJob[]): OrchestrationPlanPhase[] {
  const byIndex = new Map<number, OrchestrationPlanPhase>()
  for (const job of list) {
    const index = job.sequence?.phaseIndex
    if (!index) continue
    const entry = byIndex.get(index) || {
      index, name: job.sequence?.phaseName ?? null, jobs: 0, completed: 0, verified: 0, failed: 0, open: 0, waitingForPrior: 0, gateRequired: false,
    }
    entry.jobs += 1
    if (job.phase === 'completed') entry.completed += 1
    if (job.verified) entry.verified += 1
    if (job.phase === 'failed') entry.failed += 1
    if (OPEN_PHASES.includes(job.phase)) entry.open += 1
    if (job.sequence?.waitingForPriorPhase) entry.waitingForPrior += 1
    if (job.sequence?.gateRequired) entry.gateRequired = true
    if (!entry.name && job.sequence?.phaseName) entry.name = job.sequence.phaseName
    byIndex.set(index, entry)
  }
  return [...byIndex.values()].sort((a, b) => a.index - b.index)
}

/**
 * The one status vocabulary both pages print for a job. Disjoint: every job
 * has exactly one, so the counts partition the total. "Completed" is split by
 * verification, so a change with no passing validation never reads as success.
 */
export type JobDisplayStatus =
  | 'awaiting-approval' | 'rejected' | 'not-released' | 'blocked' | 'ready'
  | 'running' | 'executor-silent' | 'validating' | 'paused' | 'failed'
  | 'completed-unverified' | 'validation-failed' | 'verified' | 'rollback' | 'cancelled'

export const JOB_DISPLAY_STATUSES: readonly JobDisplayStatus[] = [
  'awaiting-approval', 'rejected', 'not-released', 'blocked', 'ready', 'running', 'executor-silent', 'validating',
  'paused', 'failed', 'completed-unverified', 'validation-failed', 'verified', 'rollback', 'cancelled',
]

export const DISPLAY_STATUS_LABEL: Record<JobDisplayStatus, string> = {
  'awaiting-approval': 'Awaiting approval',
  rejected: 'Rejected',
  'not-released': 'Approved · not released',
  blocked: 'Blocked',
  ready: 'Ready · queued',
  running: 'Running',
  'executor-silent': 'Executor silent',
  validating: 'Validating',
  paused: 'Paused',
  failed: 'Failed',
  'completed-unverified': 'Completed · unverified',
  'validation-failed': 'Completed · validation failed',
  verified: 'Verified',
  rollback: 'Rollback',
  cancelled: 'Cancelled',
}

export function jobDisplayStatus(job: Pick<OrchestrationJob, 'phase' | 'verification' | 'verified' | 'executorSilent' | 'stage'> & { release?: OrchestrationJob['release'] }): JobDisplayStatus {
  switch (job.phase) {
    case 'awaiting-approval': return 'awaiting-approval'
    case 'rejected': return 'rejected'
    case 'blocked': return job.release?.released === false && job.stage === 'awaiting-claim' ? 'not-released' : 'blocked'
    case 'ready': return 'ready'
    case 'executing': return job.executorSilent ? 'executor-silent' : 'running'
    case 'validating': return job.executorSilent ? 'executor-silent' : 'validating'
    case 'paused': return 'paused'
    case 'failed': return 'failed'
    case 'completed': return job.verified ? 'verified' : job.verification === 'failed' ? 'validation-failed' : 'completed-unverified'
    case 'rollback': return 'rollback'
    case 'cancelled': return 'cancelled'
  }
}

/**
 * Where a job sits on the PLAN → APPROVE → EXECUTE → VALIDATE → MONITOR flow.
 * Disjoint (cancelled work is `closed`), so stage counts partition the total.
 * MONITOR holds only completed work with a passing validation record.
 */
export type FlowJobStage = 'approve' | 'execute' | 'validate' | 'monitor' | 'closed'
export const FLOW_JOB_STAGES: readonly FlowJobStage[] = ['approve', 'execute', 'validate', 'monitor', 'closed']

export const FLOW_STAGE_OF_DISPLAY: Record<JobDisplayStatus, FlowJobStage> = {
  'awaiting-approval': 'approve',
  rejected: 'approve',
  'not-released': 'execute',
  blocked: 'execute',
  ready: 'execute',
  running: 'execute',
  // A silent executor is an execution problem, whether it was running or validating.
  'executor-silent': 'execute',
  paused: 'execute',
  failed: 'execute',
  rollback: 'execute',
  validating: 'validate',
  'completed-unverified': 'validate',
  'validation-failed': 'validate',
  verified: 'monitor',
  cancelled: 'closed',
}

/** Derived from the display status, so each stage's status breakdown sums to the stage. */
export function jobFlowStage(job: Parameters<typeof jobDisplayStatus>[0]): FlowJobStage {
  return FLOW_STAGE_OF_DISPLAY[jobDisplayStatus(job)]
}

/**
 * What must happen next, per job — first matching rule wins, so every
 * non-cancelled job belongs to exactly one action and the action counts sum to
 * `total − cancelled`. Order is urgency: a silent executor or a failed
 * validation outranks anything waiting.
 */
export type NextActionKey =
  | 'check-silent-executor' | 'review-validation-failure' | 'review-failure' | 'fix-path-role'
  | 'revise-rejected' | 'approval-unreadable' | 'approve' | 'enroll-executor' | 'clear-dispatch-block'
  | 'release-phase' | 'record-validation' | 'resume-paused' | 'follow-rollback' | 'await-claim'
  | 'follow-execution' | 'confirm-by-rescan'

export interface NextActionSummary {
  key: NextActionKey
  rank: number
  tone: 'critical' | 'warning' | 'action' | 'calm'
  title: string
  detail: string
  count: number
  href: string
  hrefLabel: string
}

const LIVE_MIGRATION = '/dashboard/live-migration'
const PLANNER = '/dashboard/migration-planner'
const AGENT_CENTER = '/downloads'
const SCANNER = '/dashboard/scanner'

const NEXT_ACTION_META: Record<NextActionKey, Omit<NextActionSummary, 'key' | 'count' | 'rank' | 'title'> & { title: (n: number) => string }> = {
  'check-silent-executor': { tone: 'critical', title: (n) => `Check ${n} silent executor${n === 1 ? '' : 's'}`, detail: 'A job is running on an agent that has stopped checking in. Nothing re-queues it automatically — confirm the host state before any retry or rollback.', href: AGENT_CENTER, hrefLabel: 'Agent Center' },
  'review-validation-failure': { tone: 'critical', title: (n) => `Review ${n} change${n === 1 ? '' : 's'} whose validation failed`, detail: 'The executor reported completion but the recorded validation failed. Roll back or remediate before the asset is treated as migrated.', href: LIVE_MIGRATION, hrefLabel: 'Live Migration' },
  'review-failure': { tone: 'critical', title: (n) => `Review ${n} failed job${n === 1 ? '' : 's'}`, detail: 'Read the executor\'s failure reason. A retry from Live Migration is re-checked against the same approval before any agent takes it.', href: LIVE_MIGRATION, hrefLabel: 'Live Migration' },
  'fix-path-role': { tone: 'warning', title: (n) => `Correct ${n} migration path${n === 1 ? '' : 's'} with a role mismatch`, detail: 'The target algorithm does not play the role of what it replaces: ML-KEM (FIPS 203) establishes keys; signatures need ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).', href: PLANNER, hrefLabel: 'Migration Planner' },
  'revise-rejected': { tone: 'warning', title: (n) => `${n} job${n === 1 ? ' was' : 's were'} rejected`, detail: 'A rejected plan is never dispatched. Revise the plan and resubmit it if the change is still needed.', href: PLANNER, hrefLabel: 'Migration Planner' },
  'approval-unreadable': { tone: 'warning', title: (n) => `Approval unreadable for ${n} job${n === 1 ? '' : 's'}`, detail: 'The plan holding the approval could not be read, so approval is unknown — not denied. It refreshes with the next snapshot.', href: PLANNER, hrefLabel: 'Migration Planner' },
  approve: { tone: 'action', title: (n) => `Approve ${n} job${n === 1 ? '' : 's'}`, detail: 'No agent takes work until a named person records an approval — on the plan for planned migrations, on the job for per-finding remediation.', href: PLANNER, hrefLabel: 'Migration Planner' },
  'enroll-executor': { tone: 'action', title: (n) => `${n} approved job${n === 1 ? ' has' : 's have'} no executor`, detail: 'No capable agent is enrolled, authorised and online to claim this work. Install or reconnect a Migration Operator (cutovers) or Patcher (remediation).', href: AGENT_CENTER, hrefLabel: 'Agent Center' },
  'clear-dispatch-block': { tone: 'action', title: (n) => `Clear the dispatch refusal on ${n} job${n === 1 ? '' : 's'}`, detail: 'The agent poll recorded why it refused this work (role, snapshot or approval). The refusal names what unblocks it.', href: LIVE_MIGRATION, hrefLabel: 'Live Migration' },
  'release-phase': { tone: 'action', title: (n) => `Release ${n} held job${n === 1 ? '' : 's'}`, detail: 'Approved work at a status agents do not poll — a later plan phase waiting for its gate, or a plan whose execution was never started.', href: LIVE_MIGRATION, hrefLabel: 'Live Migration' },
  'record-validation': { tone: 'warning', title: (n) => `Verify ${n} completed change${n === 1 ? '' : 's'}`, detail: 'Completed is not migrated: no passing validation is recorded yet. Record post-change validation evidence, then rescan.', href: LIVE_MIGRATION, hrefLabel: 'Live Migration' },
  'resume-paused': { tone: 'action', title: (n) => `${n} paused job${n === 1 ? '' : 's'}`, detail: 'Paused by an operator or by the executor needing a manual change. Resume from Live Migration, which re-checks approval.', href: LIVE_MIGRATION, hrefLabel: 'Live Migration' },
  'follow-rollback': { tone: 'warning', title: (n) => `Follow ${n} rollback${n === 1 ? '' : 's'}`, detail: 'A rollback was requested or completed. Its disposition is tracked where it was dispatched.', href: LIVE_MIGRATION, hrefLabel: 'Live Migration' },
  'await-claim': { tone: 'calm', title: (n) => `${n} job${n === 1 ? '' : 's'} ready for an agent`, detail: 'Approved, released and a capable agent is online. The next agent poll claims it after re-checking approval, role and the pre-change snapshot.', href: LIVE_MIGRATION, hrefLabel: 'Live Migration' },
  'follow-execution': { tone: 'calm', title: (n) => `${n} job${n === 1 ? '' : 's'} executing`, detail: 'Running on an agent that is checking in. Progress, telemetry and validation stream into Live Migration.', href: LIVE_MIGRATION, hrefLabel: 'Live Migration' },
  'confirm-by-rescan': { tone: 'calm', title: (n) => `${n} verified change${n === 1 ? '' : 's'}`, detail: 'Validation passed. A fresh scan confirms the new cryptography from the outside and keeps it under drift monitoring.', href: SCANNER, hrefLabel: 'Scanner' },
}

const NEXT_ACTION_ORDER: NextActionKey[] = [
  'check-silent-executor', 'review-validation-failure', 'review-failure', 'fix-path-role', 'revise-rejected',
  'approval-unreadable', 'approve', 'enroll-executor', 'clear-dispatch-block', 'release-phase', 'record-validation',
  'resume-paused', 'follow-rollback', 'await-claim', 'follow-execution', 'confirm-by-rescan',
]

export function nextActionKey(job: OrchestrationJob): NextActionKey | null {
  const display = jobDisplayStatus(job)
  if (display === 'cancelled') return null
  if (display === 'executor-silent') return 'check-silent-executor'
  if (display === 'validation-failed') return 'review-validation-failure'
  if (display === 'failed') return 'review-failure'
  if (job.pathCheck === 'role-mismatch' && OPEN_PHASES.includes(job.phase)) return 'fix-path-role'
  if (display === 'rejected') return 'revise-rejected'
  if (display === 'awaiting-approval') return job.stage === 'approval-unreadable' ? 'approval-unreadable' : 'approve'
  if (display === 'not-released') return 'release-phase'
  if (display === 'blocked') return job.stage === 'no-capable-agent' || job.stage === 'no-online-agent' ? 'enroll-executor' : 'clear-dispatch-block'
  if (display === 'completed-unverified') return 'record-validation'
  if (display === 'paused') return 'resume-paused'
  if (display === 'rollback') return 'follow-rollback'
  if (display === 'ready') return 'await-claim'
  if (display === 'running' || display === 'validating') return 'follow-execution'
  return 'confirm-by-rescan'
}

/** Ranked next actions over the given jobs (pass EVERY operational job for exact counts). */
export function summarizeNextActions(jobs: OrchestrationJob[]): NextActionSummary[] {
  const counts = new Map<NextActionKey, number>()
  for (const job of jobs) {
    const key = nextActionKey(job)
    if (key) counts.set(key, (counts.get(key) || 0) + 1)
  }
  return NEXT_ACTION_ORDER
    .filter((key) => (counts.get(key) || 0) > 0)
    .map((key, index) => {
      const meta = NEXT_ACTION_META[key]
      const count = counts.get(key) || 0
      return { key, rank: index + 1, tone: meta.tone, title: meta.title(count), detail: meta.detail, count, href: meta.href, hrefLabel: meta.hrefLabel }
    })
}
