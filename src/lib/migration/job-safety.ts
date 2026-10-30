/**
 * Job safety predicates — the single definition of "may an agent act on this?"
 *
 * Every path that can put work in front of an agent reads these: the dispatch
 * routes (`api-server/migration.ts`), the agent job poll and event endpoint
 * (`api-server/agent-scanner.ts`), the sandbox engine (`api-server/sandbox.ts`)
 * and the Live Migration snapshot. Isomorphic, no I/O, so the browser can render
 * the same verdict the server enforces.
 *
 * Two questions live here because they were each answered in several places,
 * differently:
 *
 *  1. IS THIS A SIMULATION?  `sandbox.ts` and `migration.ts` each had a copy of
 *     the predicate and they had already drifted — only the sandbox copy honoured
 *     `metadata.dryRun`. The agent claim path had NO copy at all, so a queued
 *     `[DRY RUN]` job whose target algorithm matched the PQC regex could be
 *     claimed by a real Patcher and executed against a real host.
 *
 *  2. WHO APPROVED THIS?  The dispatch gate used to ask the negative question
 *     ("is the plan rejected?"), which let every other state through — including
 *     the planner's own defaults and every Harvest Now remediation job, which
 *     has no plan at all. Approval is now a positive, attributed record, kept on
 *     the unit that was approved: the plan for planned migrations, the job itself
 *     for unplanned remediation.
 */

export type ApprovalState = 'approved' | 'rejected' | 'pending' | 'not-requested'

export interface ApprovalVerdict {
  /** True only when a named person recorded an approve decision. */
  approved: boolean
  state: ApprovalState
  /** Where the decision lives. `null` for work that needs no approval (simulations). */
  source: 'plan' | 'job' | null
  /** False for simulations, which never reach an agent. */
  required: boolean
  approvedBy: string
  approvedAt: string
  reason: string
  via: string
}

export interface ApprovalRecord {
  decision: 'approve' | 'reject'
  decidedBy: string
  decidedAt: string
  reason: string
  /** Which control recorded it — planner-start, planner-approval, live-migration… */
  via: string
}

type Loose = Record<string, unknown>

function rec(value: unknown): Loose {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Loose) : {}
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : value == null ? '' : String(value)
}

/** Tolerant boolean: rows written by different code paths store flags as bool, string or number. */
function flag(value: unknown): boolean {
  return value === true || value === 1 || /^(1|true|yes)$/i.test(text(value).trim())
}

/* ------------------------------------------------------------------ */
/* 1. Simulation                                                       */
/* ------------------------------------------------------------------ */

/**
 * Is this job a sandbox simulation or dry run?
 *
 * The UNION of the markers every writer uses, so no path can classify a
 * simulation as real work. A simulation is executed by the sandbox engine
 * against a digital twin and must never be claimed by an agent — no approval,
 * role or snapshot changes that.
 */
export function isSimulationJob(job: { job_type?: unknown; name?: unknown; metadata?: unknown } | null | undefined): boolean {
  if (!job) return false
  const metadata = rec(job.metadata)
  const executionMode = text(metadata.executionMode || metadata.runMode || metadata.mode).toLowerCase()
  const jobType = text(job.job_type).toLowerCase()
  return (
    flag(metadata.sandboxMode) ||
    flag(metadata.dryRun) ||
    ['sandbox_simulation', 'dry_run', 'simulation'].includes(executionMode) ||
    /sandbox|simulation|dry_run|dry-run/.test(jobType) ||
    /^\[dry run\]|^sandbox:/i.test(text(job.name))
  )
}

/**
 * PostgREST projection of exactly the metadata keys `isSimulationJob` reads.
 * Readers that do not need the whole JSONB blob select these instead, and pass
 * the row to `isSimulationRow`.
 */
export const SIMULATION_MARKER_SELECT =
  'sandbox_mode:metadata->>sandboxMode, dry_run:metadata->>dryRun, execution_mode:metadata->>executionMode, run_mode:metadata->>runMode, mode_hint:metadata->>mode'

/** `isSimulationJob` over a row carrying either `metadata` or the projected `SIMULATION_MARKER_SELECT` columns. */
export function isSimulationRow(row: Record<string, unknown> | null | undefined): boolean {
  if (!row) return false
  const metadata = rec(row.metadata)
  return isSimulationJob({
    job_type: row.job_type,
    name: row.name,
    metadata: {
      ...metadata,
      sandboxMode: metadata.sandboxMode ?? row.sandbox_mode,
      dryRun: metadata.dryRun ?? row.dry_run,
      executionMode: metadata.executionMode ?? row.execution_mode,
      runMode: metadata.runMode ?? row.run_mode,
      mode: metadata.mode ?? row.mode_hint,
    },
  })
}

/* ------------------------------------------------------------------ */
/* 2. Approval                                                         */
/* ------------------------------------------------------------------ */

/** The owning plan id a job declares, or ''. */
export function jobPlanId(job: { metadata?: unknown } | null | undefined): string {
  const metadata = rec(job?.metadata)
  return text(metadata.planId || metadata.plan_id).trim()
}

function decisionFrom(metadata: Loose) {
  const approval = rec(metadata.approval)
  return {
    decision: text(approval.decision).toLowerCase(),
    decidedBy: text(approval.decidedBy),
    decidedAt: text(approval.decidedAt),
    reason: text(approval.reason),
    via: text(approval.via),
  }
}

function verdict(state: ApprovalState, source: 'plan' | 'job', d: ReturnType<typeof decisionFrom>): ApprovalVerdict {
  const approved = state === 'approved'
  return {
    approved,
    state,
    source,
    required: true,
    approvedBy: approved ? d.decidedBy : '',
    approvedAt: approved ? d.decidedAt : '',
    reason: d.reason,
    via: d.via,
  }
}

/**
 * Was this PLAN explicitly approved?
 *
 * Accepts both shapes a plan travels in: the raw `migration_plans` row keeps the
 * decision under `metadata`, while `loadMigrationPlan()` maps that column to
 * `migrationMetadata`. A predicate that read only one of them answered "not
 * approved" for every plan on the other path.
 *
 * A bare `status: 'approved'` is NOT approval. Exporting a plan to PDF and
 * pushing it to the sandbox both used to write that status on plans nobody had
 * approved.
 */
export function planApproval(plan: { status?: unknown; metadata?: unknown; migrationMetadata?: unknown } | null | undefined): ApprovalVerdict {
  const metadata = { ...rec(plan?.migrationMetadata), ...rec(plan?.metadata) }
  const d = decisionFrom(metadata)
  const status = text(plan?.status).toLowerCase()
  if (status === 'rejected' || d.decision === 'reject' || d.decision === 'rejected') return verdict('rejected', 'plan', d)
  if (d.decision === 'approve' || d.decision === 'approved') return verdict('approved', 'plan', d)
  return verdict(status === 'pending_approval' ? 'pending' : 'not-requested', 'plan', d)
}

/**
 * Is this JOB approved for agent execution?
 *
 *  • simulation            → never agent work; `required: false`
 *  • declares a plan       → the plan's decision (the plan is the unit of approval;
 *                            a job-level record cannot override a rejected plan)
 *  • declares no plan      → the job's own `metadata.approval` (Harvest Now
 *                            remediation, which is created per finding)
 *
 * `plan` may be omitted when the job declares none; for a planned job a missing
 * plan is NOT approved — an approval that cannot be read cannot be relied on.
 */
export function jobApproval(
  job: { job_type?: unknown; name?: unknown; metadata?: unknown } | null | undefined,
  plan?: { status?: unknown; metadata?: unknown; migrationMetadata?: unknown } | null,
): ApprovalVerdict {
  if (isSimulationJob(job)) {
    return { approved: false, state: 'not-requested', source: null, required: false, approvedBy: '', approvedAt: '', reason: '', via: '' }
  }
  if (jobPlanId(job)) {
    if (!plan) return verdict('not-requested', 'plan', decisionFrom({}))
    return planApproval(plan)
  }
  const d = decisionFrom(rec(job?.metadata))
  if (d.decision === 'reject' || d.decision === 'rejected') return verdict('rejected', 'job', d)
  if (d.decision === 'approve' || d.decision === 'approved') return verdict('approved', 'job', d)
  return verdict('not-requested', 'job', d)
}

/** The attributed record an explicit approve decision writes. */
export function approvalRecord(decidedBy: string, decidedAt: string, via: string, reason = ''): ApprovalRecord {
  return {
    decision: 'approve',
    decidedBy: decidedBy || 'owner',
    decidedAt,
    reason: reason || 'Approved for agent execution.',
    via,
  }
}

/* ------------------------------------------------------------------ */
/* 3. Verification                                                     */
/* ------------------------------------------------------------------ */

/**
 * Did a validation actually PASS?
 *
 * Exact tokens only. The counters used `/pass|success|valid/`, and `/valid/`
 * also matches "invalid", "validation_failed" and "unvalidated" — so a failed
 * validation was counted as Verified, and `validationSeverity` rendered
 * "invalid" in the success colour. Lives here (isomorphic) so Live Migration,
 * the orchestration model and the UI read one rule.
 */
export function isPassingValidation(status: unknown): boolean {
  const value = String(status || '').toLowerCase().trim()
  if (!value || /fail|invalid|error|pending|unvalid|unverif|\bnot\b|blocked/.test(value)) return false
  return ['passed', 'pass', 'success', 'successful', 'validated', 'valid', 'verified'].includes(value)
}

/** Did a validation record an explicit FAILURE (as opposed to "not yet passed")? */
export function isFailingValidation(status: unknown): boolean {
  const value = String(status || '').toLowerCase().trim()
  return /fail|invalid|error|rejected/.test(value)
}

/** Operator-facing refusal naming the action that unblocks the work. */
export function approvalRefusal(v: ApprovalVerdict): string {
  if (v.state === 'rejected') {
    return v.source === 'plan'
      ? 'This migration plan was rejected. Agent execution cannot be dispatched against a rejected plan.'
      : 'This remediation job was rejected. It will not be dispatched to an agent.'
  }
  if (v.source === 'plan') {
    return v.state === 'pending'
      ? 'This migration plan is awaiting approval. Record an approval decision in the Migration Planner before any agent may change an asset.'
      : 'This migration plan has not been approved. Submit it for approval in the Migration Planner and record an approval decision before any agent may change an asset.'
  }
  return 'This remediation job has not been approved. Approve it in Live Migration Operations before any agent may change an asset.'
}
