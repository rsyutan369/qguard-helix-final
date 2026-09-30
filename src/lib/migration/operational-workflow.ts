/**
 * Operational migration workflow — where a REAL (non-simulation) migration job
 * stands, and what has to happen before anything touches the asset.
 *
 * The Migration Sandbox lists operational jobs (Migration Planner cutovers,
 * Harvest Now remediation) beside its simulations, but it never executes them:
 * an agent does, after approval, through Live Migration. The sandbox used to
 * describe every queued job with its own engine's copy — "Awaiting sandbox
 * executor capacity." — which for a planner cutover is false. Nothing in the
 * sandbox will ever pick that job up. Whether it moves depends on three facts
 * this module reads:
 *
 *   1. the approval recorded on its plan (or, for planless remediation, on the
 *      job) — `jobApproval`, the same verdict the agent poll enforces;
 *   2. any refusal the agent poll recorded on the job (`metadata.dispatchBlock`);
 *   3. whether an agent holding a role that may execute it is enrolled and
 *      checking in.
 *
 * Isomorphic and free of I/O: the sandbox snapshot builds it from rows it
 * already loads, the UI renders it as-is, and tools/sandbox-details-check.ts
 * drives it with fixtures.
 */
import { HEARTBEAT_ONLINE_WINDOW_MS, agentRole } from '@/lib/agent-installer/agent-release'
import { TIER_LABEL, plansIncludingAgentRole, type AgentRoleId } from '@/lib/subscription-access'
import { approvalRefusal, jobApproval, jobPlanId, type ApprovalVerdict } from './job-safety'

/** Which write role a job needs — `jobExecutionClass` in api-server/agent-scanner.ts decides it. */
export type ExecutionClass = 'migration' | 'remediation'

/**
 * Enrolled roles that may execute each class of work. This mirrors the role
 * test at the top of `agentMayWrite` (api-server/agent-entitlement.ts): a
 * Live Migration cutover needs a Migration Operator, remediation a Patcher or
 * an Operator. tools/sandbox-details-check.ts reads that function's source and
 * fails if the two drift.
 */
export const AGENT_ROLES_FOR_EXECUTION: Record<ExecutionClass, readonly AgentRoleId[]> = {
  migration: ['operator'],
  remediation: ['patcher', 'operator'],
}

export interface DispatchBlock {
  kind: string
  requires: string
  reason: string
  at: string
}

export type OperationalStage =
  | 'rejected'
  | 'approval-unreadable'
  | 'awaiting-approval'
  | 'dispatch-blocked'
  | 'no-capable-agent'
  | 'no-online-agent'
  | 'awaiting-claim'
  | 'executing'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'rollback'

export type GateState = 'pass' | 'pending' | 'fail' | 'unknown'

export interface OperationalGate {
  id: 'approval' | 'dispatch' | 'executor' | 'execution'
  label: string
  state: GateState
  detail: string
}

export interface OperationalAgent {
  id: string
  name?: string | null
  /** Server-resolved role from `scanner_agents.metadata.role`. */
  role?: string | null
  lastSeenAt?: string | null
  revoked?: boolean
  /**
   * The agent's recorded write authority (`resolveWriteAuthority`). A write
   * role is a ceiling, not a grant: a Patcher nobody authorised never claims
   * a job, so counting it as "capable" would promise a claim that cannot come.
   * Absent = not read (older callers); only then is the role alone trusted.
   */
  writeAuthority?: { remediation: boolean; migration: boolean } | null
}

export interface OperationalWorkflowInput {
  job: { id?: unknown; name?: unknown; job_type?: unknown; metadata?: unknown }
  /**
   * Status in the sandbox vocabulary: queued | running | paused | completed |
   * failed | stopped | rollback_requested | rolled_back.
   */
  status: string
  progress?: number
  /** The plan the job declares, carrying what `planApproval` reads (status + metadata.approval). */
  plan: { status?: unknown; metadata?: unknown } | null
  /** False when the plan could not be read: a planned job's approval is then unknown, not "no". */
  planReadable: boolean
  executionClass: ExecutionClass
  /** Enrolled agents for the tenant, or null when the fleet could not be read. */
  agents: OperationalAgent[] | null
  now?: number
}

export interface OperationalWorkflowDetail {
  sourceLabel: string
  planId: string | null
  phaseName: string | null
  phaseIndex: number | null
  totalPhases: number | null
  strategy: string | null
  priority: string | null
  approval: ApprovalVerdict
  /** False when the approval record could not be read (never rendered as "not approved"). */
  approvalReadable: boolean
  executionClass: ExecutionClass
  executor: {
    roleLabel: string
    /** Plans that include the role, e.g. ["Pro", "Elite"]. */
    plans: string[]
    fleetReadable: boolean
    /** Non-revoked agents of any role. Null when the fleet could not be read. */
    enrolled: number | null
    /** Non-revoked agents whose role may execute this job. */
    capable: number | null
    /** Capable agents that checked in within the heartbeat window. */
    capableOnline: number | null
    /** The agent recorded on the job, if one claimed it. */
    assignedAgent: string | null
  }
  dispatch: {
    status: string | null
    sequenceState: string | null
    block: DispatchBlock | null
  }
  controls: Array<{ key: string; label: string; enabled: boolean }>
  stage: OperationalStage
  /** One line for the queue row: where the job stands. */
  headline: string
  /** What unblocks it, addressed to the operator. */
  nextAction: string
  gates: OperationalGate[]
  links: { liveMigration: string; planner: string | null; agentCenter: string }
}

type Loose = Record<string, unknown>

function rec(value: unknown): Loose {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Loose) : {}
}

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function positiveInt(value: unknown): number | null {
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? Math.round(n) : null
}

function humanize(value: string): string {
  return value.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim().replace(/^\w/, (c) => c.toUpperCase())
}

const CONTROL_LABELS: Record<string, string> = {
  rollback: 'Rollback',
  hybridMode: 'Hybrid mode',
  validation: 'Validation',
  compatibility: 'Compatibility checks',
  complianceValidation: 'Compliance validation',
  continuousMonitoring: 'Continuous monitoring',
}

function controlLabel(key: string): string {
  return CONTROL_LABELS[key] || humanize(key.replace(/([a-z])([A-Z])/g, '$1 $2'))
}

/**
 * The refusal the agent poll recorded on a job, while it still applies.
 *
 * Shared with Live Migration (api-server/migration.ts) so both pages show the
 * same block for the same row. A finished job's old refusal is history, not a
 * reason it is waiting.
 */
export function dispatchBlockFor(metadata: unknown, status: string): DispatchBlock | null {
  const block = rec(rec(metadata).dispatchBlock)
  if (!block.reason || ['completed', 'cancelled', 'stopped', 'rolled_back'].includes(status)) return null
  return {
    kind: String(block.kind || 'unknown'),
    requires: String(block.requires || ''),
    reason: String(block.reason),
    at: String(block.at || ''),
  }
}

function sourceLabelFor(metadata: Loose, planId: string): string {
  const source = str(metadata.source).toLowerCase()
  const workflow = str(metadata.workflow).toLowerCase()
  if (source === 'migration-planner') return 'Migration Planner'
  if (source === 'harvest-now' || workflow.includes('hndl')) return 'Harvest Now remediation'
  if (source === 'live-migration') return 'Live Migration'
  return planId ? 'Migration plan' : 'Operational workflow'
}

function plural(n: number, noun: string) {
  return `${n} ${noun}${n === 1 ? '' : 's'}`
}

/** Describe an operational (agent-executed) migration job. */
export function describeOperationalWorkflow(input: OperationalWorkflowInput): OperationalWorkflowDetail {
  const metadata = rec(input.job.metadata)
  const execution = rec(metadata.execution)
  const configuration = rec(metadata.configuration)
  const status = input.status
  const now = input.now ?? Date.now()
  const planId = jobPlanId(input.job)

  const approval = jobApproval(input.job, input.plan)
  const approvalReadable = !(planId && !input.planReadable)

  const roleIds = AGENT_ROLES_FOR_EXECUTION[input.executionClass]
  const primaryRole = roleIds[0]
  const roleLabel = agentRole(primaryRole).label
  const plans = plansIncludingAgentRole(primaryRole).map((plan) => TIER_LABEL[plan])

  const liveAgents = input.agents ? input.agents.filter((agent) => !agent.revoked) : null
  const roleAgents = liveAgents ? liveAgents.filter((agent) => roleIds.includes(String(agent.role || '') as AgentRoleId)) : null
  const capableAgents = roleAgents
    ? roleAgents.filter((agent) => !agent.writeAuthority || agent.writeAuthority[input.executionClass] === true)
    : null
  const capableOnline = capableAgents
    ? capableAgents.filter((agent) => {
        const seen = agent.lastSeenAt ? Date.parse(agent.lastSeenAt) : 0
        return Boolean(seen) && now - seen <= HEARTBEAT_ONLINE_WINDOW_MS
      }).length
    : null

  const assignedId = str(metadata.assignedAgentId) || str(metadata.assigned_agent_id)
  const assignedAgent = str(metadata.assignedAgentName)
    || str(metadata.assigned_agent_name)
    || (assignedId ? str(input.agents?.find((agent) => agent.id === assignedId)?.name) || assignedId : '')
    || null

  const block = dispatchBlockFor(metadata, status)
  const dispatchStatus = str(execution.agentDispatchStatus) || null
  const sequenceState = str(execution.sequenceState) || null

  const controlSource = rec(metadata.controls && typeof metadata.controls === 'object' ? metadata.controls : configuration.controls)
  const controls = Object.entries(controlSource)
    .filter(([, value]) => typeof value === 'boolean')
    .map(([key, value]) => ({ key, label: controlLabel(key), enabled: value === true }))

  const failure = str(metadata.failureReason) || str(metadata.error)

  let stage: OperationalStage
  let headline: string
  let nextAction: string

  if (status === 'completed') {
    stage = 'completed'
    headline = 'Completed by the executing agent.'
    nextAction = 'Validation evidence for this change is recorded in Live Migration Operations.'
  } else if (status === 'failed') {
    stage = 'failed'
    headline = str(metadata.rollbackDisposition) === 'failed'
      ? 'Rollback failed — the restore could not be verified on the asset.'
      : failure ? `Failed: ${failure}` : 'Failed — the executor reported a failure.'
    nextAction = 'Review the failure in Live Migration Operations. A retry is re-checked against the same approval before any agent takes it.'
  } else if (status === 'rollback_requested' || status === 'rolled_back') {
    stage = 'rollback'
    // Only Migration Snapshot Management dispatches a rollback, and it records
    // a disposition. A request without one was written somewhere that
    // dispatches nothing, so saying "awaiting an executor" would be false.
    const disposition = str(metadata.rollbackDisposition)
    headline = status === 'rolled_back'
      ? 'Rolled back to the recorded pre-change state.'
      : disposition === 'dispatched'
        ? 'Rollback dispatched to the executor holding the pre-change backup — awaiting its confirmation.'
        : disposition
          ? 'Rollback requested — no executor holding the pre-change backup is connected.'
          : 'Rollback requested, but nothing has been dispatched to an executor.'
    nextAction = disposition || status === 'rolled_back'
      ? 'Rollback progress for operational migrations is tracked in Live Migration Operations.'
      : 'Roll this job back from its pre-change snapshot in Live Migration Operations, which dispatches the restore to the agent holding the backup and reports what actually happened.'
  } else if (status === 'stopped') {
    stage = 'cancelled'
    headline = 'Cancelled — withdrawn from the execution queue.'
    nextAction = 'Nothing will execute. Start a new migration from the Migration Planner if the change is still needed.'
  } else if (status === 'paused') {
    stage = 'paused'
    headline = 'Paused by an operator.'
    nextAction = 'Resume it from Live Migration Operations, which re-checks approval before any agent takes it.'
  } else if (status === 'running') {
    stage = 'executing'
    headline = assignedAgent ? `Executing on agent ${assignedAgent}.` : 'Executing — an agent has claimed this job.'
    nextAction = 'Follow live progress, telemetry and validation in Live Migration Operations.'
  } else if (approval.state === 'rejected') {
    stage = 'rejected'
    headline = 'Rejected — this job will not be dispatched to an agent.'
    nextAction = approvalRefusal(approval)
  } else if (!approvalReadable) {
    stage = 'approval-unreadable'
    headline = 'Approval record could not be read.'
    nextAction = 'The migration plan holding this job\'s approval could not be read, so its approval is unknown — not denied. It will refresh with the next snapshot.'
  } else if (!approval.approved) {
    stage = 'awaiting-approval'
    headline = 'Awaiting approval — no agent will take this job until it is approved.'
    nextAction = approvalRefusal(approval)
  } else if (block) {
    stage = 'dispatch-blocked'
    headline = `Approved — not dispatched: ${block.reason}`
    nextAction = block.requires ? `${block.reason} Requires: ${block.requires}.` : block.reason
  } else if (capableAgents && capableAgents.length === 0 && roleAgents && roleAgents.length > 0) {
    stage = 'no-capable-agent'
    headline = `Approved — ${plural(roleAgents.length, `${roleLabel} agent`)} enrolled, none authorised to change hosts.`
    nextAction = `Grant ${input.executionClass} authority to one of them in the Agent Center (agent → Capabilities → Write authority). A write role without that authorisation stays read-only and never claims this job.`
  } else if (capableAgents && capableAgents.length === 0) {
    stage = 'no-capable-agent'
    headline = `Approved — no ${roleLabel} agent is enrolled to execute it.`
    nextAction = `Install a ${roleLabel} agent (included in ${plans.join(' and ')}) from the Agent Center. Until one is enrolled and online, nothing can claim this approved job.`
  } else if (capableAgents && capableOnline === 0) {
    stage = 'no-online-agent'
    headline = `Approved — ${plural(capableAgents.length, `${roleLabel} agent`)} enrolled, none online.`
    nextAction = `Start or reconnect a ${roleLabel} agent. None has checked in within the last ${Math.round(HEARTBEAT_ONLINE_WINDOW_MS / 60000)} minutes, so nothing is polling for this job.`
  } else {
    stage = 'awaiting-claim'
    headline = `Approved — waiting for a ${roleLabel} agent to claim it.`
    nextAction = capableOnline !== null
      ? `${plural(capableOnline, `${roleLabel} agent`)} online. The next agent poll claims it after re-checking approval, role and the pre-change snapshot.`
      : 'The agent fleet could not be read. The next agent poll claims this job after re-checking approval, role and the pre-change snapshot.'
  }

  const approvalGate: OperationalGate = !approvalReadable
    ? { id: 'approval', label: 'Approval', state: 'unknown', detail: 'Plan approval could not be read.' }
    : approval.state === 'rejected'
      ? { id: 'approval', label: 'Approval', state: 'fail', detail: approval.source === 'plan' ? 'Migration plan rejected.' : 'Job rejected.' }
      : approval.approved
        ? { id: 'approval', label: 'Approval', state: 'pass', detail: `${approval.approvedBy || 'Operator'}${approval.via ? ` · ${humanize(approval.via)}` : ''}` }
        : { id: 'approval', label: 'Approval', state: 'pending', detail: approval.state === 'pending' ? 'Decision pending.' : 'Not yet requested.' }

  const claimed = status === 'running' || status === 'completed' || status === 'failed' || Boolean(assignedAgent)
  const dispatchGate: OperationalGate = block
    ? { id: 'dispatch', label: 'Dispatch', state: 'fail', detail: block.reason }
    : claimed
      ? { id: 'dispatch', label: 'Dispatch', state: 'pass', detail: assignedAgent ? `Claimed by ${assignedAgent}.` : 'Claimed by an agent.' }
      : { id: 'dispatch', label: 'Dispatch', state: 'pending', detail: dispatchStatus ? `${humanize(dispatchStatus)} — no refusal recorded.` : 'Not yet claimed — no refusal recorded.' }

  const executorGate: OperationalGate = claimed && assignedAgent
    ? { id: 'executor', label: 'Executor', state: 'pass', detail: `Agent ${assignedAgent}.` }
    : !capableAgents
      ? { id: 'executor', label: 'Executor', state: 'unknown', detail: 'Agent fleet could not be read.' }
      : capableAgents.length === 0
        ? { id: 'executor', label: 'Executor', state: 'fail', detail: `No ${roleLabel} agent enrolled.` }
        : capableOnline === 0
          ? { id: 'executor', label: 'Executor', state: 'fail', detail: `${plural(capableAgents.length, `${roleLabel} agent`)} enrolled, none online.` }
          : { id: 'executor', label: 'Executor', state: 'pass', detail: `${plural(capableOnline || 0, `${roleLabel} agent`)} online.` }

  const progress = Math.max(0, Math.min(100, Math.round(Number(input.progress) || 0)))
  const executionGate: OperationalGate = status === 'completed'
    ? { id: 'execution', label: 'Execution', state: 'pass', detail: 'Completed.' }
    : status === 'failed'
      ? { id: 'execution', label: 'Execution', state: 'fail', detail: failure || 'Executor reported a failure.' }
      : status === 'running'
        ? { id: 'execution', label: 'Execution', state: 'pending', detail: `In progress · ${progress}%.` }
        : status === 'stopped'
          ? { id: 'execution', label: 'Execution', state: 'unknown', detail: 'Cancelled before completion.' }
          : status === 'rollback_requested' || status === 'rolled_back'
            ? { id: 'execution', label: 'Execution', state: 'unknown', detail: humanize(status) + '.' }
            : { id: 'execution', label: 'Execution', state: 'pending', detail: status === 'paused' ? 'Paused.' : 'Not started.' }

  const encodedPlan = planId ? encodeURIComponent(planId) : ''
  return {
    sourceLabel: sourceLabelFor(metadata, planId),
    planId: planId || null,
    phaseName: str(execution.phaseName) || null,
    phaseIndex: positiveInt(execution.phaseIndex),
    totalPhases: positiveInt(execution.totalPhases),
    strategy: str(execution.strategy) || str(configuration.deploymentStrategy) || null,
    priority: str(metadata.priority) || null,
    approval,
    approvalReadable,
    executionClass: input.executionClass,
    executor: {
      roleLabel,
      plans,
      fleetReadable: Boolean(input.agents),
      enrolled: liveAgents ? liveAgents.length : null,
      capable: capableAgents ? capableAgents.length : null,
      capableOnline,
      assignedAgent,
    },
    dispatch: { status: dispatchStatus, sequenceState, block },
    controls,
    stage,
    headline,
    nextAction,
    gates: [approvalGate, dispatchGate, executorGate, executionGate],
    links: {
      liveMigration: encodedPlan ? `/dashboard/live-migration?planId=${encodedPlan}` : '/dashboard/live-migration',
      planner: planId ? '/dashboard/migration-planner' : null,
      agentCenter: '/downloads',
    },
  }
}
