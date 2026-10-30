/**
 * Four-agent PQC migration workflow — Collector → Scanner → Patcher →
 * Migration Operator — derived ONLY from recorded execution evidence.
 *
 * Live Migration renders this as its workflow canvas, timeline, metrics,
 * guardrails and safety checklist. Every panel reads this one model, so two
 * panels cannot disagree about what an agent is doing.
 *
 * Where each stage's truth comes from:
 *
 *   Collector / Scanner  the latest scan run of enrolled agents holding that
 *                        role: the ordered `scan_progress` frames the agent
 *                        itself posts (`/agent/scan-progress`), plus its
 *                        heartbeat status. Progress is the agent-reported stage
 *                        percentage — never a timer.
 *   Patcher              non-simulation migration jobs whose execution class is
 *                        `remediation` (`jobExecutionClass`, the same rule the
 *                        agent poll enforces).
 *   Migration Operator   non-simulation jobs whose execution class is
 *                        `migration` (Live Migration cutovers).
 *
 * Sandbox simulations are never attributed to an agent: they run in the
 * sandbox engine against a digital twin, so counting them would show agent
 * activity that never happened.
 *
 * Isomorphic and free of I/O: `api-server/migration.ts` builds it from rows the
 * live snapshot already loads, the dashboard renders it as-is, and
 * tools/live-agent-workflow-check.ts drives it with fixtures.
 */
import { HEARTBEAT_ONLINE_WINDOW_MS } from '@/lib/agent-installer/agent-release'
import { MANDATORY_PQC_TARGET_ALGORITHMS } from '@/lib/crypto/mandatory-pqc-stack'
import { isPassingValidation, type ApprovalVerdict } from './job-safety'

export const WORKFLOW_AGENT_IDS = ['collector', 'scanner', 'patcher', 'operator'] as const
export type WorkflowAgentId = (typeof WORKFLOW_AGENT_IDS)[number]

export type AgentWorkflowStatus =
  | 'idle'
  | 'queued'
  | 'waiting'
  | 'running'
  | 'blocked'
  | 'awaiting_approval'
  | 'paused'
  | 'retrying'
  | 'completed'
  | 'failed'
  | 'cancelled'

export type EdgeState = 'idle' | 'waiting' | 'active' | 'completed' | 'blocked' | 'failed'
export type EventSeverity = 'info' | 'success' | 'warning' | 'error' | 'critical'

/** Stage weights for overall progress — each stage is a quarter of the workflow. */
export const STAGE_WEIGHTS: Record<WorkflowAgentId, number> = { collector: 0.25, scanner: 0.25, patcher: 0.25, operator: 0.25 }

export const AGENT_META: Record<WorkflowAgentId, { label: string; purpose: string; readOnly: boolean; dependsOn: WorkflowAgentId | null }> = {
  collector: {
    label: 'Collector',
    purpose: 'Cryptographic inventory and CBOM evidence collection',
    readOnly: true,
    dependsOn: null,
  },
  scanner: {
    label: 'Scanner',
    purpose: 'Quantum-vulnerability assessment (FIPS 203 / 204 / 205)',
    readOnly: true,
    dependsOn: 'collector',
  },
  patcher: {
    label: 'Patcher',
    purpose: 'Approved PQC configuration remediation on allow-listed paths',
    readOnly: false,
    dependsOn: 'scanner',
  },
  operator: {
    label: 'Migration Operator',
    purpose: 'Authorised live PQC migration cutovers',
    readOnly: false,
    dependsOn: 'patcher',
  },
}

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

export interface WorkflowAgentRow {
  id: string
  name: string | null
  hostname: string | null
  status: string | null
  version: string | null
  lastSeenAt: string | null
  revoked: boolean
  role: string | null
  writeAuthority: { remediation: boolean; migration: boolean } | null
  /** `scanner_agents.metadata.lastTelemetry` — the agent's own host-health report. */
  telemetry: Record<string, unknown> | null
}

export interface WorkflowHeartbeatRow {
  id: string
  agentId: string
  status: string
  telemetry: Record<string, unknown>
  observedAt: string
}

/** The subset of a live migration job this model reads. */
export interface WorkflowJob {
  id: string
  asset: string
  assetId: string | null
  assetType: string
  environment: string
  owner: string
  criticality: string
  fromAlgo: string
  toAlgo: string
  migrationType: string
  status: string
  progress: number
  startedAt: string | null
  completedAt: string | null
  createdAt: string
  updatedAt: string
  executionBacked: boolean
  isSandbox?: boolean
  agentId: string | null
  agentName: string | null
  currentStep: string
  validationStatus: string
  validationCount: number
  telemetryCount: number
  dispatchBlock: { kind: string; requires: string; reason: string; at: string } | null
  approval: ApprovalVerdict
  executionClass?: 'migration' | 'remediation'
  logs: Array<{ id: string; eventType: string; message: string; severity: string; createdAt: string; metadata: Record<string, unknown> }>
  metadata: Record<string, unknown>
}

export interface WorkflowEvidenceInput {
  totalAssets: number
  inventoryItems: number | null
  certificates: number | null
  keys: number | null
  quantumSafeItems: number | null
  vulnerableItems: number | null
  findings: number
  /** Exposure severity counts across the tenant (exact counts). */
  exposures: { critical: number; high: number; medium: number; low: number }
  /** Exposure rows read for the category breakdown (bounded). */
  exposureSample: Array<{ assetId: string | null; exposureType: string; severity: string }>
  exposureTotal: number
  lastScanAt: string | null
}

export interface AgentWorkflowInput {
  now?: number
  agents: WorkflowAgentRow[] | null
  heartbeats: WorkflowHeartbeatRow[]
  jobs: WorkflowJob[]
  evidence: WorkflowEvidenceInput
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

export interface WorkflowEvent {
  id: string
  at: string
  agent: WorkflowAgentId
  type: string
  severity: EventSeverity
  message: string
  /** Status the event reports, in the workflow vocabulary, when it reports one. */
  status: AgentWorkflowStatus | null
  jobId: string | null
  /** The agent that reported the frame or claimed the job; null when no agent did. */
  agentId: string | null
  asset: string | null
  /** Job id for job events, `agentId:runStart` for scan frames. */
  correlationId: string
  source: 'scan-frame' | 'heartbeat' | 'job-event' | 'telemetry' | 'validation'
  progress: number | null
  detail: Record<string, unknown>
}

export interface AgentHostMetrics {
  /** Agents whose heartbeat telemetry contributed. */
  reporting: number
  /** Mean host memory used %, as each agent reported it. */
  memoryUsedPct: number | null
  /** Mean 1-minute load ÷ cores (%). Null on Windows, which has no load average. */
  cpuLoadPct: number | null
  /** Summed agent process RSS. */
  agentRssBytes: number | null
  scanCount: number | null
  errorCount: number | null
  queueDepth: number | null
  lastScanDurationMs: number | null
  series: { memory: number[]; cpu: number[] }
}

/**
 * One deployed agent under its stage. Its state is derived from ITS OWN scan
 * frames, heartbeats and claimed jobs — never copied from the stage roll-up,
 * so one busy host does not make an idle sibling look busy.
 */
export interface WorkflowAgentInstance {
  id: string
  name: string
  hostname: string | null
  version: string | null
  lastSeenAt: string | null
  /** Heartbeat within HEARTBEAT_ONLINE_WINDOW_MS (the Agent Center's window). */
  online: boolean
  /** `scanner_agents.status` as stored. */
  status: string | null
  role: WorkflowAgentId
  /** Host OS as the agent reported it (`lastTelemetry.host.platform`). */
  platform: string | null
  state: AgentWorkflowStatus
  reason: string
  currentTask: string
  stage: string | null
  /** Measured progress of this agent's own run / job; null when unmeasured. */
  progress: number | null
  startedAt: string | null
  completedAt: string | null
  /** Latest event this agent produced. */
  updatedAt: string | null
  /** Write roles: authorised for this stage's execution class. Null for read-only roles. */
  authorised: boolean | null
  /** Collector / Scanner: the agent's latest scan run. */
  lastRun: { evidence: number | null; accepted: number | null; rejected: number | null } | null
  /** Patcher / Operator: jobs this agent claimed. */
  jobs: { claimed: number; running: number; completed: number; failed: number; paused: number; rollback: number } | null
  warnings: number
  errors: number
  latestEvent: { at: string; message: string; severity: EventSeverity } | null
  metrics: AgentHostMetrics
}

export interface WorkflowAgentNode {
  id: WorkflowAgentId
  label: string
  purpose: string
  readOnly: boolean
  dependsOn: WorkflowAgentId | null
  status: AgentWorkflowStatus
  /** Why the status is what it is — always present for non-running, non-completed states. */
  reason: string
  currentTask: string
  stage: string | null
  /** Measured progress. Null when it cannot be measured (render indeterminate). */
  progress: number | null
  units: { done: number; total: number; label: string } | null
  startedAt: string | null
  updatedAt: string | null
  completedAt: string | null
  fleet: {
    enrolled: number
    online: number
    /** Write-capable agents authorised for this stage (Patcher / Operator). */
    authorised: number | null
    /** Every enrolled, non-revoked agent of this role — the children of the stage in the workflow tree. */
    agents: WorkflowAgentInstance[]
  }
  jobs: { total: number; running: number; queued: number; awaitingApproval: number; blocked: number; completed: number; failed: number; paused: number; rollback: number; cancelled: number } | null
  latestEvent: WorkflowEvent | null
  warnings: number
  errors: number
  outputs: Array<{ label: string; value: string; href: string }>
  findings: Array<{ label: string; value: string; tone: 'critical' | 'high' | 'medium' | 'low' | 'neutral' | 'good' }>
  nextAction: string
  nextHref: string
  metrics: AgentHostMetrics
}

export interface WorkflowEdge {
  id: string
  source: WorkflowAgentId
  target: WorkflowAgentId
  label: string
  state: EdgeState
  /** Timestamp of the last real handoff on this edge (null = none recorded). */
  lastHandoffAt: string | null
  handoffDetail: string
}

export interface VulnerabilitySummary {
  critical: number
  high: number
  medium: number
  low: number
  total: number
  affectedAssets: number | null
  /** True when the breakdown was computed from a bounded sample. */
  sampled: boolean
  sampleSize: number
  categories: Array<{ key: string; label: string; count: number }>
  readiness: { quantumSafe: number | null; vulnerable: number | null; inventory: number | null }
  remediationEligible: number
  migrationReady: number
}

export interface AgentWorkflowModel {
  generatedAt: string
  status: AgentWorkflowStatus
  statusReason: string
  currentStage: WorkflowAgentId | null
  activeAgents: number
  onlineAgents: number
  enrolledAgents: number
  /** Stage-weighted progress (STAGE_WEIGHTS). Null when no stage has measurable work. */
  overallProgress: number | null
  progressBasis: string
  startedAt: string | null
  warnings: number
  errors: number
  simulationsExcluded: number
  nodes: WorkflowAgentNode[]
  edges: WorkflowEdge[]
  events: WorkflowEvent[]
  eventsTruncated: boolean
  vulnerabilities: VulnerabilitySummary
  throughput: { eventsPerMinute: number | null; windowMinutes: number }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

type Loose = Record<string, unknown>

function rec(value: unknown): Loose {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Loose) : {}
}

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function num(value: unknown): number | null {
  const n = typeof value === 'number' ? value : typeof value === 'string' && value.trim() ? Number(value) : NaN
  return Number.isFinite(n) ? n : null
}

function ms(value: string | null | undefined): number {
  const parsed = value ? Date.parse(value) : NaN
  return Number.isFinite(parsed) ? parsed : 0
}

function plural(n: number, noun: string) {
  return `${n} ${noun}${n === 1 ? '' : 's'}`
}

function humanize(value: string): string {
  return value.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim().replace(/^\w/, (c) => c.toUpperCase())
}

const SECRET_KEY = /(token|secret|password|passwd|credential|private.?key|api.?key|authorization|cookie|session.?id|bearer)/i
const SECRET_VALUE = /(-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})/

/**
 * Remove credentials, private keys and tokens from event detail before it is
 * shown or exported. Depth- and size-bounded so one huge payload cannot bloat
 * the snapshot.
 */
export function redactDetail(value: unknown, depth = 0): unknown {
  if (depth > 4) return '[truncated]'
  if (typeof value === 'string') {
    if (SECRET_VALUE.test(value)) return '[redacted]'
    return value.length > 400 ? `${value.slice(0, 400)}…` : value
  }
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => redactDetail(item, depth + 1))
  if (value && typeof value === 'object') {
    const out: Loose = {}
    for (const [key, item] of Object.entries(value as Loose).slice(0, 40)) {
      out[key] = SECRET_KEY.test(key) && !/count|rotation|size|status|type/i.test(key) ? '[redacted]' : redactDetail(item, depth + 1)
    }
    return out
  }
  return value
}

function agentOnline(agent: WorkflowAgentRow, now: number) {
  if (agent.revoked) return false
  const seen = ms(agent.lastSeenAt)
  return Boolean(seen) && now - seen <= HEARTBEAT_ONLINE_WINDOW_MS
}

function normalizeSeverity(value: string): EventSeverity {
  const s = value.toLowerCase()
  if (s === 'critical') return 'critical'
  if (/error|fail/.test(s)) return 'error'
  if (/warn/.test(s)) return 'warning'
  if (/success|pass|complete/.test(s)) return 'success'
  return 'info'
}

/** Scan-frame stage → readable label. Unknown stages are humanised, never dropped. */
export const SCAN_STAGE_LABEL: Record<string, string> = {
  connecting: 'Connecting to control plane',
  system_inventory: 'Collecting system inventory',
  discovering_cryptography: 'Discovering cryptography',
  inspecting_certificates: 'Inspecting certificates and TLS',
  analyzing_tls: 'Analysing key exchange',
  building_cbom: 'Building CBOM from evidence',
  calculating_exposure: 'Calculating quantum exposure',
  publishing_findings: 'Publishing findings',
  scan_complete: 'Scan complete',
  scan_failed: 'Scan failed',
}

function stageLabel(stage: string) {
  return SCAN_STAGE_LABEL[stage] || humanize(stage)
}

const PQC_TARGETS = new Set(MANDATORY_PQC_TARGET_ALGORITHMS.map((algo) => String(algo).toLowerCase()))

/** True when the target algorithm is on the mandatory PQC stack (or a hybrid of it). */
export function isApprovedPqcTarget(algorithm: string): boolean {
  const value = algorithm.toLowerCase().trim()
  if (!value) return false
  if (PQC_TARGETS.has(value)) return true
  return /ml-kem|ml-dsa|slh-dsa|aes-256-gcm|sha3-(256|384|512)/.test(value)
}

/* ------------------------------------------------------------------ */
/* Scan-run derivation (Collector / Scanner)                           */
/* ------------------------------------------------------------------ */

interface ScanRun {
  agentId: string
  startedAt: string
  updatedAt: string
  stage: string
  progress: number | null
  message: string
  terminal: 'complete' | 'failed' | null
  evidence: number | null
  accepted: number | null
  rejected: number | null
  frames: WorkflowHeartbeatRow[]
}

/** The latest scan run per agent, rebuilt from its ordered scan frames. */
function scanLifecycleFrame(beat: WorkflowHeartbeatRow): WorkflowHeartbeatRow | null {
  if (beat.status === 'scan_progress') return beat
  const phase = str(beat.telemetry.phase)
  const commandTerminal = /^command:(scan|rescan_validation):(completed|failed)$/.test(beat.status)
  if (!['starting', 'completed', 'failed'].includes(phase) && !commandTerminal) return null
  const failed = phase === 'failed' || (commandTerminal && beat.status.endsWith(':failed'))
  const starting = phase === 'starting'
  const result = commandTerminal ? rec(beat.telemetry.result) : beat.telemetry
  return {
    ...beat,
    status: 'scan_progress',
    telemetry: {
      ...beat.telemetry,
      ...result,
      stage: starting ? 'connecting' : failed ? 'scan_failed' : 'scan_complete',
      progress: starting || failed ? null : 100,
      message: starting ? 'Agent started a scan' : failed ? str(beat.telemetry.error) || 'Scan failed' : result.degraded === true ? 'Scan complete with publishing errors' : 'Scan complete',
      accepted: result.acceptedByControlPlane ?? result.acceptedCount ?? result.accepted,
      reportedVia: commandTerminal ? 'command-receipt' : 'heartbeat-phase',
    },
  }
}

function latestRuns(frames: WorkflowHeartbeatRow[]): Map<string, ScanRun> {
  const byAgent = new Map<string, WorkflowHeartbeatRow[]>()
  for (const frame of frames) {
    if (!byAgent.has(frame.agentId)) byAgent.set(frame.agentId, [])
    byAgent.get(frame.agentId)!.push(frame)
  }
  const runs = new Map<string, ScanRun>()
  for (const [agentId, rows] of byAgent) {
    const ordered = [...rows].sort((a, b) => ms(a.observedAt) - ms(b.observedAt))
    // A run starts at its `connecting` frame. Without one in the window, the
    // whole window is treated as the run's tail — still real frames.
    let startIndex = 0
    for (let i = ordered.length - 1; i >= 0; i -= 1) {
      if (str(ordered[i].telemetry.stage) === 'connecting') {
        startIndex = i
        break
      }
    }
    const run = ordered.slice(startIndex)
    const last = run[run.length - 1]
    const stage = str(last.telemetry.stage)
    const evidence = num(last.telemetry.evidenceCount) ?? num(last.telemetry.evidenceSoFar)
    runs.set(agentId, {
      agentId,
      startedAt: run[0].observedAt,
      updatedAt: last.observedAt,
      stage,
      progress: num(last.telemetry.progress),
      message: str(last.telemetry.message) || stageLabel(stage),
      terminal: stage === 'scan_complete' ? 'complete' : stage === 'scan_failed' ? 'failed' : null,
      evidence,
      accepted: num(last.telemetry.accepted),
      rejected: num(last.telemetry.rejectedByPolicy),
      frames: run,
    })
  }
  return runs
}

function hostMetrics(agents: WorkflowAgentRow[], heartbeats: WorkflowHeartbeatRow[]): AgentHostMetrics {
  const memory: number[] = []
  const cpu: number[] = []
  let rss = 0
  let rssSeen = false
  let scanCount: number | null = null
  let errorCount: number | null = null
  let queueDepth: number | null = null
  let lastScanDurationMs: number | null = null
  let reporting = 0

  const cpuPct = (telemetry: Loose): number | null => {
    const host = rec(telemetry.host)
    const platform = str(host.platform).toLowerCase()
    const load = num(host.loadAverage1m)
    const cores = num(host.cpuCount)
    // Windows reports a zero load average; that is "unmeasured", not "idle".
    if (platform === 'win32' || load === null || !cores) return null
    return Math.max(0, Math.min(100, Math.round((load / cores) * 100)))
  }

  for (const agent of agents) {
    const telemetry = rec(agent.telemetry)
    if (!Object.keys(telemetry).length) continue
    reporting += 1
    const mem = num(rec(telemetry.memory).usedPercent)
    if (mem !== null) memory.push(mem)
    const load = cpuPct(telemetry)
    if (load !== null) cpu.push(load)
    const agentRss = num(rec(telemetry.memory).agentRssBytes)
    if (agentRss !== null) {
      rss += agentRss
      rssSeen = true
    }
    const counters = rec(telemetry.counters)
    const add = (current: number | null, value: unknown) => {
      const n = num(value)
      return n === null ? current : (current ?? 0) + n
    }
    scanCount = add(scanCount, counters.scanCount)
    errorCount = add(errorCount, counters.errorCount)
    queueDepth = add(queueDepth, counters.queueDepth)
    const duration = num(counters.lastScanDurationMs)
    if (duration !== null) lastScanDurationMs = Math.max(lastScanDurationMs ?? 0, duration)
  }

  // Series: routine heartbeats carrying host telemetry, oldest → newest.
  const series = { memory: [] as number[], cpu: [] as number[] }
  const ordered = [...heartbeats].sort((a, b) => ms(a.observedAt) - ms(b.observedAt)).slice(-40)
  for (const beat of ordered) {
    const mem = num(rec(beat.telemetry.memory).usedPercent)
    if (mem !== null) series.memory.push(mem)
    const load = cpuPct(beat.telemetry)
    if (load !== null) series.cpu.push(load)
  }

  const mean = (values: number[]) => (values.length ? Math.round(values.reduce((a, b) => a + b, 0) / values.length) : null)
  return {
    reporting,
    memoryUsedPct: mean(memory),
    cpuLoadPct: mean(cpu),
    agentRssBytes: rssSeen ? rss : null,
    scanCount,
    errorCount,
    queueDepth,
    lastScanDurationMs,
    series,
  }
}

/* ------------------------------------------------------------------ */
/* Event collection                                                    */
/* ------------------------------------------------------------------ */

const ROUTINE_HEARTBEAT = new Set(['active', 'online', 'scanning'])
const EVENT_LIMIT = 400

function heartbeatEvent(beat: WorkflowHeartbeatRow, agent: WorkflowAgentId): WorkflowEvent | null {
  const telemetry = beat.telemetry
  if (beat.status === 'scan_progress') {
    const stage = str(telemetry.stage)
    const progress = num(telemetry.progress)
    const failed = stage === 'scan_failed'
    const complete = stage === 'scan_complete'
    const rejected = num(telemetry.rejectedByPolicy) || 0
    return {
      id: beat.id,
      at: beat.observedAt,
      agent,
      type: complete ? 'scan.completed' : failed ? 'scan.failed' : stage === 'connecting' ? 'scan.started' : 'scan.progress',
      severity: failed ? 'error' : complete ? (rejected > 0 ? 'warning' : 'success') : 'info',
      message: str(telemetry.message) || stageLabel(stage),
      status: failed ? 'failed' : complete ? 'completed' : 'running',
      jobId: null,
      agentId: beat.agentId,
      asset: str(telemetry.target) || str(telemetry.path) || null,
      correlationId: `${beat.agentId}:${stage}`,
      source: 'scan-frame',
      progress,
      detail: redactDetail(telemetry) as Loose,
    }
  }
  if (beat.status === 'telemetry') {
    const type = str(telemetry.eventType) || str(telemetry.event_type) || str(telemetry.type) || 'agent.telemetry'
    const message = str(telemetry.message) || humanize(type)
    return {
      id: beat.id,
      at: beat.observedAt,
      agent,
      type,
      severity: /fail|error/.test(`${type} ${message}`.toLowerCase()) ? 'warning' : 'info',
      message,
      status: null,
      jobId: null,
      agentId: beat.agentId,
      asset: str(rec(telemetry.metadata).target) || null,
      correlationId: beat.agentId,
      source: 'telemetry',
      progress: null,
      detail: redactDetail(telemetry) as Loose,
    }
  }
  if (ROUTINE_HEARTBEAT.has(beat.status) && str(telemetry.phase) !== 'completed') return null
  const error = str(telemetry.error)
  const phase = str(telemetry.phase)
  const status = beat.status
  return {
    id: beat.id,
    at: beat.observedAt,
    agent,
    type: `agent.${status}`,
    severity: status === 'error' ? 'error' : status === 'degraded' ? 'warning' : status === 'disabled' ? 'warning' : 'success',
    message: status === 'error'
      ? `Agent reported an error${error ? `: ${error}` : '.'}`
      : status === 'degraded'
        ? 'Scan finished with publish errors — some evidence did not reach the control plane.'
        : status === 'disabled'
          ? `Agent disabled${str(telemetry.reason) ? ` (${humanize(str(telemetry.reason))})` : ''}.`
          : phase === 'completed'
            ? `Collection cycle completed · ${num(telemetry.evidenceCount) ?? 0} evidence item(s).`
            : humanize(status),
    status: status === 'error' ? 'failed' : status === 'disabled' ? 'paused' : null,
    jobId: null,
    agentId: beat.agentId,
    asset: null,
    correlationId: beat.agentId,
    source: 'heartbeat',
    progress: null,
    detail: redactDetail(telemetry) as Loose,
  }
}

function jobStatusToWorkflow(status: string): AgentWorkflowStatus {
  switch (status) {
    case 'running': return 'running'
    case 'completed': return 'completed'
    case 'failed': return 'failed'
    case 'paused': return 'paused'
    case 'cancelled': return 'cancelled'
    case 'rolling_back': return 'retrying'
    case 'rolled_back': return 'completed'
    default: return 'queued'
  }
}

function jobEvents(job: WorkflowJob, agent: WorkflowAgentId): WorkflowEvent[] {
  return job.logs.map((log) => {
    const type = log.eventType || 'migration-event'
    const text = `${type} ${log.message}`.toLowerCase()
    return {
      id: `${job.id}:${log.id}`,
      at: log.createdAt,
      agent,
      type,
      severity: normalizeSeverity(log.severity || (/fail|error/.test(text) ? 'error' : 'info')),
      message: log.message || humanize(type),
      status: /rollback/.test(text) ? 'retrying' : /claimed|started/.test(text) ? 'running' : /complete|validated|pass/.test(text) ? 'completed' : /fail/.test(text) ? 'failed' : null,
      jobId: job.id,
      agentId: job.agentId,
      asset: job.asset,
      correlationId: job.id,
      source: /validation/.test(type) ? 'validation' : 'job-event',
      progress: null,
      detail: redactDetail({ ...log.metadata, jobStatus: job.status, toAlgo: job.toAlgo }) as Loose,
    }
  })
}

/* ------------------------------------------------------------------ */
/* Builder                                                             */
/* ------------------------------------------------------------------ */

function emptyMetrics(): AgentHostMetrics {
  return { reporting: 0, memoryUsedPct: null, cpuLoadPct: null, agentRssBytes: null, scanCount: null, errorCount: null, queueDepth: null, lastScanDurationMs: null, series: { memory: [], cpu: [] } }
}

/* ------------------------------------------------------------------ */
/* Per-agent instances (the workflow tree's children)                  */
/* ------------------------------------------------------------------ */

/** Points per host-metric sparkline on an agent instance — bounds the snapshot. */
const INSTANCE_SERIES_POINTS = 24

const pendingApproval = (job: WorkflowJob) => job.approval.required && !job.approval.approved && ['queued', 'paused'].includes(job.status)

function isDisabled(agent: WorkflowAgentRow, latestBeat: WorkflowHeartbeatRow | null) {
  return latestBeat?.status === 'disabled' || String(agent.status).toLowerCase() === 'disabled'
}

/** Identity, host metrics and event tallies shared by every role. */
function instanceBase(agent: WorkflowAgentRow, role: WorkflowAgentId, routineBeats: WorkflowHeartbeatRow[], events: WorkflowEvent[], now: number) {
  const metrics = hostMetrics([agent], routineBeats.filter((beat) => beat.agentId === agent.id))
  metrics.series = { memory: metrics.series.memory.slice(-INSTANCE_SERIES_POINTS), cpu: metrics.series.cpu.slice(-INSTANCE_SERIES_POINTS) }
  const own = events.filter((event) => event.agentId === agent.id)
  const latest = own[0] || null
  return {
    id: agent.id,
    name: agent.name || agent.hostname || agent.id,
    hostname: agent.hostname,
    version: agent.version,
    lastSeenAt: agent.lastSeenAt,
    online: agentOnline(agent, now),
    status: agent.status,
    role,
    platform: str(rec(rec(agent.telemetry).host).platform) || null,
    updatedAt: latest?.at || null,
    warnings: own.filter((event) => event.severity === 'warning').length,
    errors: own.filter((event) => event.severity === 'error' || event.severity === 'critical').length,
    latestEvent: latest ? { at: latest.at, message: latest.message, severity: latest.severity } : null,
    metrics,
  }
}

function offlineReason(agent: WorkflowAgentRow) {
  return agent.lastSeenAt
    ? `No check-in within ${Math.round(HEARTBEAT_ONLINE_WINDOW_MS / 60000)} minutes.`
    : 'Enrolled, but has never checked in.'
}

/** Collector / Scanner agent: state from its own latest scan run and heartbeat. */
function scanInstance(
  agent: WorkflowAgentRow,
  role: 'collector' | 'scanner',
  run: ScanRun | undefined,
  latestBeat: WorkflowHeartbeatRow | null,
  routineBeats: WorkflowHeartbeatRow[],
  events: WorkflowEvent[],
  now: number,
): WorkflowAgentInstance {
  const base = instanceBase(agent, role, routineBeats, events, now)
  const fresh = Boolean(run && !run.terminal && now - ms(run.updatedAt) <= HEARTBEAT_ONLINE_WINDOW_MS)
  let state: AgentWorkflowStatus
  let reason: string
  let currentTask: string
  let progress: number | null = null
  let completedAt: string | null = null

  if (isDisabled(agent, latestBeat)) {
    state = 'paused'
    currentTask = 'Disabled'
    reason = 'Disabled by policy or an operator.'
  } else if (run && fresh) {
    state = 'running'
    currentTask = run.message
    progress = run.progress
    reason = `Reporting scan frames — last at "${stageLabel(run.stage)}".`
  } else if (run?.terminal === 'failed') {
    state = 'failed'
    currentTask = run.message
    reason = 'The latest scan run reported a failure.'
  } else if (latestBeat?.status === 'error') {
    state = 'failed'
    const error = str(latestBeat.telemetry.error)
    currentTask = 'Agent error'
    reason = error ? `Agent reported: ${error}` : 'The agent reported an error on its last heartbeat.'
  } else if (run && !run.terminal) {
    state = 'blocked'
    currentTask = run.message
    reason = `Run stopped reporting at "${stageLabel(run.stage)}" — no frame for over ${Math.round(HEARTBEAT_ONLINE_WINDOW_MS / 60000)} minutes.`
  } else if (run?.terminal === 'complete') {
    state = 'completed'
    currentTask = run.message
    progress = 100
    completedAt = run.updatedAt
    reason = base.online ? 'Latest run complete. The next run starts on the agent schedule.' : 'Latest run complete. The agent is offline now.'
  } else if (!base.online) {
    state = 'waiting'
    currentTask = 'Offline'
    reason = offlineReason(agent)
  } else {
    state = 'waiting'
    currentTask = 'Awaiting first scan'
    reason = 'Online — no scan frame recorded in the last 24 hours.'
  }

  return {
    ...base,
    state,
    reason,
    currentTask,
    stage: run?.stage || null,
    progress,
    startedAt: run?.startedAt || null,
    completedAt,
    authorised: null,
    lastRun: run ? { evidence: run.evidence, accepted: run.accepted, rejected: run.rejected } : null,
    jobs: null,
  }
}

/** Patcher / Operator agent: state from the jobs it claimed and its write authority. */
function jobInstance(
  agent: WorkflowAgentRow,
  role: 'patcher' | 'operator',
  executionClass: 'remediation' | 'migration',
  stageJobs: WorkflowJob[],
  latestBeat: WorkflowHeartbeatRow | null,
  routineBeats: WorkflowHeartbeatRow[],
  events: WorkflowEvent[],
  now: number,
): WorkflowAgentInstance {
  const base = instanceBase(agent, role, routineBeats, events, now)
  const authorised = !agent.writeAuthority || agent.writeAuthority[executionClass] === true
  const own = stageJobs.filter((job) => job.agentId === agent.id)
  const byRecency = [...own].sort((a, b) => ms(b.updatedAt) - ms(a.updatedAt))
  const tally = {
    claimed: own.length,
    running: own.filter((job) => job.status === 'running').length,
    completed: own.filter((job) => job.status === 'completed').length,
    failed: own.filter((job) => job.status === 'failed').length,
    paused: own.filter((job) => job.status === 'paused' && !pendingApproval(job)).length,
    rollback: own.filter((job) => job.status === 'rolling_back' || job.status === 'rolled_back').length,
  }
  // Approved, undispatched work any authorised agent of this role may claim.
  const claimable = stageJobs.filter((job) => job.status === 'queued' && !job.agentId && !job.dispatchBlock && !pendingApproval(job)).length
  const rollingBack = byRecency.find((job) => job.status === 'rolling_back')
  const running = byRecency.filter((job) => job.status === 'running')
  const latestTerminal = byRecency.find((job) => ['completed', 'failed', 'rolled_back', 'cancelled'].includes(job.status))
  const noun = role === 'patcher' ? 'remediation' : 'cutover'

  let state: AgentWorkflowStatus
  let reason: string
  let currentTask: string
  let progress: number | null = null
  let stage: string | null = null
  let startedAt: string | null = null
  let completedAt: string | null = null

  if (isDisabled(agent, latestBeat)) {
    state = 'paused'
    currentTask = 'Disabled'
    reason = 'Disabled by policy or an operator — claims no work.'
  } else if (rollingBack) {
    state = 'retrying'
    currentTask = `Rolling back ${rollingBack.asset}`
    reason = 'Rollback dispatched to this agent, which holds the pre-change backup.'
    startedAt = rollingBack.startedAt
  } else if (running.length) {
    const lead = running[0]
    state = 'running'
    stage = lead.currentStep || null
    currentTask = `${lead.currentStep || 'Executing'} · ${lead.asset}${running.length > 1 ? ` (+${running.length - 1} more)` : ''}`
    // The job's own reported progress, and only when an agent is executing it.
    progress = lead.executionBacked && Number.isFinite(lead.progress) ? Math.max(0, Math.min(100, Math.round(lead.progress))) : null
    startedAt = lead.startedAt
    reason = `Executing ${plural(running.length, `claimed ${noun} job`)}.`
  } else if (tally.paused > 0) {
    state = 'paused'
    currentTask = `${plural(tally.paused, 'job')} paused`
    reason = 'Paused by an operator. Resume re-checks approval before this agent continues.'
  } else if (latestTerminal?.status === 'failed') {
    state = 'failed'
    currentTask = `Failed · ${latestTerminal.asset}`
    reason = str(latestTerminal.metadata.failureReason) || str(latestTerminal.metadata.error) || 'This agent reported a failure on its latest job.'
  } else if (!authorised) {
    state = claimable > 0 ? 'blocked' : 'idle'
    currentTask = 'No write authority'
    reason = `Not authorised for ${executionClass} — this agent never claims a job.`
  } else if (!base.online) {
    state = 'waiting'
    currentTask = 'Offline'
    reason = `${offlineReason(agent)}${claimable ? ` ${plural(claimable, 'approved job')} waiting for an online agent.` : ''}`
  } else if (claimable > 0) {
    state = 'queued'
    currentTask = `${plural(claimable, 'approved job')} awaiting claim`
    reason = 'Online and authorised. The next poll claims after re-checking approval, scope and the pre-change snapshot.'
  } else if (tally.completed > 0) {
    state = 'completed'
    currentTask = `${plural(tally.completed, 'job')} completed`
    completedAt = byRecency.find((job) => job.status === 'completed')?.completedAt || null
    reason = 'Every job this agent claimed reached a recorded terminal state.'
  } else {
    state = 'idle'
    currentTask = 'No job claimed'
    reason = 'Online and authorised — no approved work in scope.'
  }

  return {
    ...base,
    state,
    reason,
    currentTask,
    stage,
    progress,
    startedAt,
    completedAt,
    authorised,
    lastRun: null,
    jobs: tally,
  }
}

function scanStageNode(
  id: 'collector' | 'scanner',
  roleAgents: WorkflowAgentRow[],
  runs: Map<string, ScanRun>,
  beatsByAgent: Map<string, WorkflowHeartbeatRow[]>,
  routineBeats: WorkflowHeartbeatRow[],
  events: WorkflowEvent[],
  evidence: WorkflowEvidenceInput,
  now: number,
): WorkflowAgentNode {
  const meta = AGENT_META[id]
  const live = roleAgents.filter((agent) => !agent.revoked)
  const online = live.filter((agent) => agentOnline(agent, now))
  const roleRuns = live.map((agent) => runs.get(agent.id)).filter((run): run is ScanRun => Boolean(run))
  const latestBeat = (agentId: string) => (beatsByAgent.get(agentId) || [])[0] || null

  let status: AgentWorkflowStatus
  let reason = ''
  let currentTask = ''
  let stage: string | null = null
  let progress: number | null = null
  let units: WorkflowAgentNode['units'] = null
  let startedAt: string | null = null
  let completedAt: string | null = null

  const running = roleRuns.filter((run) => !run.terminal && now - ms(run.updatedAt) <= HEARTBEAT_ONLINE_WINDOW_MS)
  const stalled = roleRuns.filter((run) => !run.terminal && now - ms(run.updatedAt) > HEARTBEAT_ONLINE_WINDOW_MS)
  const failed = roleRuns.filter((run) => run.terminal === 'failed')
  const complete = roleRuns.filter((run) => run.terminal === 'complete')
  const erroring = live.filter((agent) => {
    const beat = latestBeat(agent.id)
    return beat?.status === 'error'
  })
  const disabled = live.length > 0 && live.every((agent) => latestBeat(agent.id)?.status === 'disabled' || String(agent.status).toLowerCase() === 'disabled')

  if (!live.length) {
    status = 'idle'
    reason = `No ${meta.label} agent is enrolled for this tenant.`
    currentTask = 'Not enrolled'
  } else if (disabled) {
    status = 'paused'
    reason = `Every ${meta.label} agent is disabled by policy or an operator.`
    currentTask = 'Disabled'
  } else if (running.length) {
    status = 'running'
    const lead = [...running].sort((a, b) => ms(b.updatedAt) - ms(a.updatedAt))[0]
    stage = lead.stage
    currentTask = lead.message
    const measured = running.map((run) => run.progress).filter((value): value is number => value !== null)
    progress = measured.length ? Math.round(measured.reduce((a, b) => a + b, 0) / measured.length) : null
    startedAt = [...running].sort((a, b) => ms(a.startedAt) - ms(b.startedAt))[0].startedAt
    units = { done: complete.length, total: live.length, label: `${meta.label} runs complete` }
    reason = `${plural(running.length, 'agent')} reporting scan frames.`
  } else if (failed.length && failed.some((run) => !complete.some((done) => done.agentId === run.agentId && ms(done.updatedAt) > ms(run.updatedAt)))) {
    status = 'failed'
    const lead = failed[0]
    stage = lead.stage
    currentTask = lead.message
    startedAt = lead.startedAt
    reason = `${plural(failed.length, 'agent')} reported a failed scan run.`
  } else if (erroring.length) {
    status = 'failed'
    const error = str(latestBeat(erroring[0].id)?.telemetry.error)
    currentTask = 'Agent error'
    reason = error ? `Agent reported: ${error}` : 'The agent reported an error on its last heartbeat.'
  } else if (stalled.length) {
    status = 'blocked'
    const lead = stalled[0]
    stage = lead.stage
    currentTask = lead.message
    startedAt = lead.startedAt
    reason = `Run stopped reporting at "${stageLabel(lead.stage)}" — no frame for over ${Math.round(HEARTBEAT_ONLINE_WINDOW_MS / 60000)} minutes.`
  } else if (complete.length) {
    status = 'completed'
    const lead = [...complete].sort((a, b) => ms(b.updatedAt) - ms(a.updatedAt))[0]
    stage = lead.stage
    progress = 100
    currentTask = lead.message
    startedAt = lead.startedAt
    completedAt = lead.updatedAt
    units = { done: complete.length, total: live.length, label: `${meta.label} runs complete` }
    reason = online.length ? 'Latest run complete. The next run starts on the agent schedule.' : 'Latest run complete. No agent of this role is online now.'
  } else if (!online.length) {
    status = 'waiting'
    currentTask = 'Agent offline'
    reason = `${plural(live.length, `${meta.label} agent`)} enrolled, none checked in within ${Math.round(HEARTBEAT_ONLINE_WINDOW_MS / 60000)} minutes.`
  } else {
    status = 'waiting'
    currentTask = 'Awaiting first scan'
    reason = 'Enrolled and online — no scan frame recorded in the last 24 hours.'
  }

  if (id === 'scanner' && status === 'completed' && evidence.findings > 0) currentTask = `${evidence.findings.toLocaleString('en-US')} findings classified`

  const roleIds = new Set(live.map((agent) => agent.id))
  const own = events.filter((event) => event.agent === id)
  const latestEvent = own[0] || null
  const totalEvidence = complete.reduce((sum, run) => sum + (run.evidence || 0), 0)

  const outputs: WorkflowAgentNode['outputs'] = id === 'collector'
    ? [
        { label: 'Inventory items', value: evidence.inventoryItems === null ? 'Unknown' : evidence.inventoryItems.toLocaleString('en-US'), href: '/dashboard/cbom-explorer' },
        { label: 'Certificates', value: evidence.certificates === null ? 'Unknown' : evidence.certificates.toLocaleString('en-US'), href: '/dashboard/cbom-explorer' },
        { label: 'Assets', value: evidence.totalAssets.toLocaleString('en-US'), href: '/dashboard/assets' },
      ]
    : [
        { label: 'Findings', value: evidence.findings.toLocaleString('en-US'), href: '/dashboard/crypto-exposure' },
        { label: 'Critical exposures', value: evidence.exposures.critical.toLocaleString('en-US'), href: '/dashboard/crypto-exposure' },
        { label: 'Last scan', value: evidence.lastScanAt ? new Date(evidence.lastScanAt).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : 'None recorded', href: '/dashboard/scanner' },
      ]

  const findings: WorkflowAgentNode['findings'] = id === 'collector'
    ? [
        { label: 'Evidence in latest runs', value: totalEvidence.toLocaleString('en-US'), tone: 'neutral' },
        { label: 'Keys', value: evidence.keys === null ? 'Unknown' : evidence.keys.toLocaleString('en-US'), tone: 'neutral' },
        { label: 'Rejected by policy', value: String(complete.reduce((sum, run) => sum + (run.rejected || 0), 0)), tone: complete.some((run) => (run.rejected || 0) > 0) ? 'medium' : 'good' },
      ]
    : [
        { label: 'Critical', value: String(evidence.exposures.critical), tone: 'critical' },
        { label: 'High', value: String(evidence.exposures.high), tone: 'high' },
        { label: 'Medium', value: String(evidence.exposures.medium), tone: 'medium' },
        { label: 'Low', value: String(evidence.exposures.low), tone: 'low' },
      ]

  const nextAction = status === 'idle'
    ? `Install a ${meta.label} agent from the Agent Center and authorise its targets and paths.`
    : status === 'waiting' && !online.length
      ? `Start or reconnect a ${meta.label} agent — nothing is collecting evidence while none is online.`
      : status === 'failed'
        ? 'Inspect the failed run in the execution log, fix the target/path, then trigger a rescan from the Agent Center.'
        : status === 'blocked'
          ? 'The run stopped reporting. Check the agent host and its connectivity to the control plane.'
          : status === 'running'
            ? 'Follow the live frames below. Downstream stages wait for this run to publish.'
            : id === 'collector'
              ? 'Evidence is published. The Scanner classifies it against FIPS 203 / 204 / 205.'
              : 'Review findings and approve remediation for the affected assets.'

  return {
    id,
    label: meta.label,
    purpose: meta.purpose,
    readOnly: meta.readOnly,
    dependsOn: meta.dependsOn,
    status,
    reason,
    currentTask,
    stage,
    progress,
    units,
    startedAt,
    updatedAt: latestEvent?.at || null,
    completedAt,
    fleet: {
      enrolled: live.length,
      online: online.length,
      authorised: null,
      agents: live.map((agent) => scanInstance(agent, id, runs.get(agent.id), latestBeat(agent.id), routineBeats, events, now)),
    },
    jobs: null,
    latestEvent,
    warnings: own.filter((event) => event.severity === 'warning').length,
    errors: own.filter((event) => event.severity === 'error' || event.severity === 'critical').length,
    outputs,
    findings,
    nextAction,
    nextHref: status === 'idle' || status === 'waiting' ? '/downloads' : id === 'collector' ? '/dashboard/cbom-explorer' : '/dashboard/crypto-exposure',
    metrics: live.length ? hostMetrics(live, routineBeats.filter((beat) => roleIds.has(beat.agentId))) : emptyMetrics(),
  }
}

function jobStageNode(
  id: 'patcher' | 'operator',
  roleAgents: WorkflowAgentRow[],
  jobs: WorkflowJob[],
  beatsByAgent: Map<string, WorkflowHeartbeatRow[]>,
  routineBeats: WorkflowHeartbeatRow[],
  events: WorkflowEvent[],
  now: number,
): WorkflowAgentNode {
  const meta = AGENT_META[id]
  const executionClass = id === 'patcher' ? 'remediation' : 'migration'
  const live = roleAgents.filter((agent) => !agent.revoked)
  const authorised = live.filter((agent) => !agent.writeAuthority || agent.writeAuthority[executionClass] === true)
  const authorisedOnline = authorised.filter((agent) => agentOnline(agent, now))
  const online = live.filter((agent) => agentOnline(agent, now))

  const count = (predicate: (job: WorkflowJob) => boolean) => jobs.filter(predicate).length
  const tally = {
    total: jobs.length,
    running: count((job) => job.status === 'running'),
    queued: count((job) => job.status === 'queued' && !pendingApproval(job) && !job.dispatchBlock),
    awaitingApproval: count(pendingApproval),
    blocked: count((job) => Boolean(job.dispatchBlock) && job.status === 'queued'),
    completed: count((job) => job.status === 'completed'),
    failed: count((job) => job.status === 'failed'),
    paused: count((job) => job.status === 'paused' && !pendingApproval(job)),
    rollback: count((job) => job.status === 'rolling_back' || job.status === 'rolled_back'),
    cancelled: count((job) => job.status === 'cancelled'),
  }
  const countable = tally.total - tally.cancelled
  const runningJobs = jobs.filter((job) => job.status === 'running').sort((a, b) => ms(b.updatedAt) - ms(a.updatedAt))
  const lead = runningJobs[0]

  let status: AgentWorkflowStatus
  let reason: string
  let currentTask: string
  if (!jobs.length) {
    status = 'idle'
    currentTask = id === 'patcher' ? 'No remediation jobs' : 'No cutover jobs'
    reason = id === 'patcher'
      ? 'No approved remediation has been created for this scope yet.'
      : 'No Live Migration cutover has been planned for this scope yet.'
  } else if (jobs.some((job) => job.status === 'rolling_back')) {
    status = 'retrying'
    const job = jobs.find((item) => item.status === 'rolling_back')!
    currentTask = `Rolling back ${job.asset}`
    reason = 'A rollback was dispatched to the executor holding the pre-change backup and is awaiting confirmation.'
  } else if (lead) {
    status = 'running'
    currentTask = `${lead.currentStep || 'Executing'} · ${lead.asset}`
    reason = `${plural(tally.running, 'job')} executing on ${lead.agentName || 'a claimed agent'}.`
  } else if (!authorised.length && (tally.queued + tally.blocked) > 0) {
    status = 'blocked'
    currentTask = `No authorised ${meta.label}`
    reason = live.length
      ? `${plural(live.length, `${meta.label} agent`)} enrolled, none authorised for ${executionClass}. A write role without that authorisation never claims a job.`
      : `Approved work exists but no ${meta.label} agent is enrolled to execute it.`
  } else if (tally.blocked > 0) {
    status = 'blocked'
    const job = jobs.find((item) => item.dispatchBlock && item.status === 'queued')!
    currentTask = `Not dispatched · ${job.asset}`
    reason = job.dispatchBlock!.reason
  } else if (tally.awaitingApproval > 0 && tally.queued === 0) {
    status = 'awaiting_approval'
    currentTask = `${plural(tally.awaitingApproval, 'job')} awaiting approval`
    reason = 'No agent changes an asset until a named person approves the job or its plan.'
  } else if (tally.queued > 0 && !authorisedOnline.length) {
    status = 'waiting'
    currentTask = `${plural(tally.queued, 'approved job')} queued`
    reason = `${plural(authorised.length, `authorised ${meta.label} agent`)}, none online — nothing is polling for this work.`
  } else if (tally.queued > 0) {
    status = 'queued'
    currentTask = `${plural(tally.queued, 'approved job')} awaiting claim`
    reason = `${plural(authorisedOnline.length, `${meta.label} agent`)} online. The next poll claims after re-checking approval, scope and the pre-change snapshot.`
  } else if (tally.paused > 0) {
    status = 'paused'
    currentTask = `${plural(tally.paused, 'job')} paused`
    reason = 'Paused by an operator. Resume re-checks approval before any agent takes it.'
  } else if (tally.failed > 0) {
    status = 'failed'
    const job = jobs.find((item) => item.status === 'failed')!
    currentTask = `Failed · ${job.asset}`
    reason = str(job.metadata.failureReason) || str(job.metadata.error) || 'The executor reported a failure.'
  } else if (tally.completed > 0 && tally.completed + tally.rollback >= countable) {
    status = 'completed'
    currentTask = `${plural(tally.completed, 'job')} completed`
    reason = 'Every job in scope reached a terminal, recorded state.'
  } else {
    status = 'cancelled'
    currentTask = 'Cancelled'
    reason = 'Every job in scope was withdrawn by an operator.'
  }

  const validated = jobs.filter((job) => job.status === 'completed' && isPassingValidation(job.validationStatus)).length
  const starts = jobs.map((job) => job.startedAt).filter((value): value is string => Boolean(value)).sort((a, b) => ms(a) - ms(b))
  const completions = jobs.map((job) => job.completedAt).filter((value): value is string => Boolean(value)).sort((a, b) => ms(b) - ms(a))
  const own = events.filter((event) => event.agent === id)
  const roleIds = new Set(live.map((agent) => agent.id))
  const snapshots = jobs.filter((job) => str(job.metadata.preChangeSnapshotId) || str(rec(job.metadata.execution).preChangeSnapshotId)).length

  const nextAction = status === 'idle'
    ? id === 'patcher' ? 'Create remediation from Harvest Now or the Migration Planner, then approve it.' : 'Plan a cutover in the Migration Planner and send it to Live Migration.'
    : status === 'blocked'
      ? live.length ? `Grant ${executionClass} authority to a ${meta.label} agent (Agent Center → Capabilities → Write authority).` : `Install a ${meta.label} agent from the Agent Center.`
      : status === 'awaiting_approval'
        ? 'Review and approve the pending jobs below — approval is recorded with your identity.'
        : status === 'waiting'
          ? `Start or reconnect an authorised ${meta.label} agent.`
          : status === 'failed'
            ? 'Inspect the failure, then Retry (re-checked against the same approval) or Roll back from its snapshot.'
            : status === 'paused'
              ? 'Resume the paused jobs when ready.'
              : status === 'running' || status === 'queued' || status === 'retrying'
                ? 'Monitor execution and validation in the job detail below.'
                : 'Review validation evidence; completed changes are recorded in the Audit Vault.'

  return {
    id,
    label: meta.label,
    purpose: meta.purpose,
    readOnly: meta.readOnly,
    dependsOn: meta.dependsOn,
    status,
    reason,
    currentTask,
    stage: lead?.currentStep || null,
    // Measured in jobs: terminal-and-recorded over countable. A single running
    // job's own reported progress is shown on that job, not blended in here.
    progress: countable > 0 ? Math.round(((tally.completed + tally.rollback) / countable) * 100) : null,
    units: countable > 0 ? { done: tally.completed + tally.rollback, total: countable, label: 'jobs finished' } : null,
    startedAt: starts[0] || null,
    updatedAt: own[0]?.at || jobs.map((job) => job.updatedAt).sort((a, b) => ms(b) - ms(a))[0] || null,
    completedAt: status === 'completed' ? completions[0] || null : null,
    fleet: {
      enrolled: live.length,
      online: online.length,
      authorised: authorised.length,
      agents: live.map((agent) => jobInstance(agent, id, executionClass, jobs, (beatsByAgent.get(agent.id) || [])[0] || null, routineBeats, events, now)),
    },
    jobs: tally,
    latestEvent: own[0] || null,
    warnings: own.filter((event) => event.severity === 'warning').length,
    errors: own.filter((event) => event.severity === 'error' || event.severity === 'critical').length,
    outputs: [
      { label: 'Validated changes', value: String(validated), href: '/dashboard/audit-vault' },
      { label: 'Pre-change snapshots', value: String(snapshots), href: '#snapshots' },
      { label: id === 'patcher' ? 'Remediation records' : 'Cutover records', value: String(tally.total), href: '/dashboard/migration-timeline' },
    ],
    findings: [
      { label: 'Awaiting approval', value: String(tally.awaitingApproval), tone: tally.awaitingApproval ? 'medium' : 'neutral' },
      { label: 'Not dispatched', value: String(tally.blocked), tone: tally.blocked ? 'high' : 'neutral' },
      { label: 'Failed', value: String(tally.failed), tone: tally.failed ? 'critical' : 'good' },
      { label: 'Rolled back', value: String(tally.rollback), tone: 'neutral' },
    ],
    nextAction,
    nextHref: status === 'blocked' || status === 'waiting' || (status === 'idle' && !live.length) ? '/downloads' : status === 'idle' ? '/dashboard/migration-planner' : '#jobs',
    metrics: live.length ? hostMetrics(live, routineBeats.filter((beat) => roleIds.has(beat.agentId))) : emptyMetrics(),
  }
}

const DONE: AgentWorkflowStatus[] = ['completed']
const ACTIVE: AgentWorkflowStatus[] = ['running', 'retrying']

function edgeBetween(source: WorkflowAgentNode, target: WorkflowAgentNode, label: string, lastHandoffAt: string | null, handoffDetail: string): WorkflowEdge {
  let state: EdgeState
  if (target.status === 'failed') state = 'failed'
  else if (target.status === 'blocked') state = 'blocked'
  else if (ACTIVE.includes(target.status)) state = 'active'
  else if (DONE.includes(source.status) && lastHandoffAt) state = 'completed'
  else if (source.status === 'idle' && target.status === 'idle') state = 'idle'
  else state = 'waiting'
  return { id: `${source.id}->${target.id}`, source: source.id, target: target.id, label, state, lastHandoffAt, handoffDetail }
}

const EXPOSURE_LABEL: Record<string, string> = {
  rsa: 'RSA', ecc: 'ECC / ECDSA', dh: 'Diffie-Hellman', weak_tls: 'Weak TLS', sha1: 'SHA-1', md5: 'MD5',
  deprecated_lib: 'Deprecated library', exposed_cert: 'Exposed certificate', insecure_key_mgmt: 'Key management',
}

export function buildAgentWorkflow(input: AgentWorkflowInput): AgentWorkflowModel {
  const now = input.now ?? Date.now()
  const agents = input.agents || []
  const roleOf = new Map<string, WorkflowAgentId>()
  for (const agent of agents) {
    const role = String(agent.role || '').toLowerCase()
    roleOf.set(agent.id, (WORKFLOW_AGENT_IDS as readonly string[]).includes(role) ? (role as WorkflowAgentId) : 'collector')
  }
  const byRole = (role: WorkflowAgentId) => agents.filter((agent) => roleOf.get(agent.id) === role)

  const beats = [...input.heartbeats].sort((a, b) => ms(b.observedAt) - ms(a.observedAt))
  const beatsByAgent = new Map<string, WorkflowHeartbeatRow[]>()
  for (const beat of beats) {
    if (!beatsByAgent.has(beat.agentId)) beatsByAgent.set(beat.agentId, [])
    beatsByAgent.get(beat.agentId)!.push(beat)
  }
  // Heartbeat phases and acknowledged command outcomes are terminal evidence too.
  // A lost final progress POST must not leave a completed run stuck at 85%.
  const frames = beats.map(scanLifecycleFrame).filter((beat): beat is WorkflowHeartbeatRow => beat !== null)
  const routineBeats = beats.filter((beat) => Object.keys(rec(beat.telemetry.memory)).length > 0)
  const runs = latestRuns(frames)

  const realJobs = input.jobs.filter((job) => !job.isSandbox)
  const simulationsExcluded = input.jobs.length - realJobs.length
  const classOf = (job: WorkflowJob): 'migration' | 'remediation' =>
    job.executionClass || (str(job.metadata.executionClass) === 'remediation' ? 'remediation' : str(job.metadata.executionClass) === 'migration' ? 'migration' : 'migration')
  const remediationJobs = realJobs.filter((job) => classOf(job) === 'remediation')
  const migrationJobs = realJobs.filter((job) => classOf(job) === 'migration')

  // Events: agent frames/heartbeats attributed by the reporting agent's role,
  // job events by the job's execution class. Newest first, bounded.
  const events: WorkflowEvent[] = []
  for (const beat of beats) {
    const role = roleOf.get(beat.agentId)
    if (!role) continue
    const event = heartbeatEvent(scanLifecycleFrame(beat) || beat, role)
    if (event) events.push(event)
  }
  for (const job of remediationJobs) events.push(...jobEvents(job, 'patcher'))
  for (const job of migrationJobs) events.push(...jobEvents(job, 'operator'))
  events.sort((a, b) => ms(b.at) - ms(a.at))
  const eventsTruncated = events.length > EVENT_LIMIT
  const boundedEvents = events.slice(0, EVENT_LIMIT)

  const collector = scanStageNode('collector', byRole('collector'), runs, beatsByAgent, routineBeats, boundedEvents, input.evidence, now)
  const scanner = scanStageNode('scanner', byRole('scanner'), runs, beatsByAgent, routineBeats, boundedEvents, input.evidence, now)
  const patcher = jobStageNode('patcher', byRole('patcher'), remediationJobs, beatsByAgent, routineBeats, boundedEvents, now)
  const operator = jobStageNode('operator', byRole('operator'), migrationJobs, beatsByAgent, routineBeats, boundedEvents, now)
  const nodes = [collector, scanner, patcher, operator]

  // Handoffs come from recorded transitions, never from the UI clock.
  const collectorRuns = byRole('collector').map((agent) => runs.get(agent.id)).filter((run): run is ScanRun => Boolean(run && run.terminal === 'complete'))
  const lastCollectorPublish = collectorRuns.sort((a, b) => ms(b.updatedAt) - ms(a.updatedAt))[0] || null
  const lastRemediationCreated = [...remediationJobs].sort((a, b) => ms(b.createdAt) - ms(a.createdAt))[0] || null
  const lastValidatedRemediation = remediationJobs
    .filter((job) => job.status === 'completed' && isPassingValidation(job.validationStatus))
    .sort((a, b) => ms(b.completedAt || b.updatedAt) - ms(a.completedAt || a.updatedAt))[0] || null

  const edges: WorkflowEdge[] = [
    edgeBetween(collector, scanner, 'Evidence published', lastCollectorPublish?.updatedAt || null,
      lastCollectorPublish ? `${lastCollectorPublish.accepted ?? lastCollectorPublish.evidence ?? 0} evidence item(s) accepted by the control plane.` : 'No completed collection run in the last 24 hours.'),
    edgeBetween(scanner, patcher, 'Remediation created', lastRemediationCreated?.createdAt || null,
      lastRemediationCreated ? `Remediation job for ${lastRemediationCreated.asset} created from findings.` : 'No remediation job has been created from findings.'),
    edgeBetween(patcher, operator, 'Validated fixes', lastValidatedRemediation ? lastValidatedRemediation.completedAt || lastValidatedRemediation.updatedAt : null,
      lastValidatedRemediation ? `${lastValidatedRemediation.asset} remediated and validation passed.` : 'No remediation has passed validation yet.'),
  ]

  // Overall: stage weights over measured stage completion. A stage with no
  // measurable work contributes nothing and is named in the basis.
  let weighted = 0
  let measuredWeight = 0
  for (const node of nodes) {
    const fraction = node.status === 'completed' ? 1 : node.progress !== null ? node.progress / 100 : null
    if (fraction === null) continue
    weighted += fraction * STAGE_WEIGHTS[node.id]
    measuredWeight += STAGE_WEIGHTS[node.id]
  }
  const unmeasured = nodes.filter((node) => node.status !== 'completed' && node.progress === null).map((node) => node.label)
  const overallProgress = measuredWeight > 0 ? Math.round(weighted * 100) : null

  const order: WorkflowAgentId[] = ['collector', 'scanner', 'patcher', 'operator']
  const activeNode = nodes.find((node) => ACTIVE.includes(node.status))
  const currentStage = activeNode?.id
    ?? nodes.find((node) => ['blocked', 'awaiting_approval', 'failed', 'waiting', 'queued', 'paused'].includes(node.status))?.id
    ?? (nodes.every((node) => node.status === 'idle') ? null : order.find((id) => nodes.find((node) => node.id === id)!.status !== 'completed') ?? null)

  let status: AgentWorkflowStatus
  let statusReason: string
  if (nodes.some((node) => node.status === 'failed')) {
    status = 'failed'
    const node = nodes.find((item) => item.status === 'failed')!
    statusReason = `${node.label}: ${node.reason}`
  } else if (activeNode) {
    status = activeNode.status
    statusReason = `${activeNode.label}: ${activeNode.currentTask}`
  } else if (nodes.some((node) => node.status === 'blocked')) {
    status = 'blocked'
    const node = nodes.find((item) => item.status === 'blocked')!
    statusReason = `${node.label}: ${node.reason}`
  } else if (nodes.some((node) => node.status === 'awaiting_approval')) {
    status = 'awaiting_approval'
    statusReason = 'Changes are waiting for a named approver.'
  } else if (nodes.some((node) => node.status === 'queued')) {
    status = 'queued'
    statusReason = 'Approved work is waiting for an agent claim.'
  } else if (nodes.some((node) => node.status === 'paused')) {
    status = 'paused'
    statusReason = 'Paused by an operator.'
  } else if (nodes.every((node) => node.status === 'idle')) {
    status = 'idle'
    statusReason = 'No agent is enrolled and no migration work exists yet.'
  } else if (nodes.every((node) => ['completed', 'idle', 'cancelled'].includes(node.status)) && nodes.some((node) => node.status === 'completed')) {
    status = 'completed'
    statusReason = 'Every stage with work reached a recorded terminal state.'
  } else {
    status = 'waiting'
    const node = nodes.find((item) => item.status === 'waiting')
    statusReason = node ? `${node.label}: ${node.reason}` : 'Waiting on upstream stages.'
  }

  const startCandidates = nodes.filter((node) => !['idle', 'completed', 'cancelled'].includes(node.status)).map((node) => node.startedAt).filter((value): value is string => Boolean(value))
  const startedAt = startCandidates.sort((a, b) => ms(a) - ms(b))[0] || null

  const dayAgo = now - 24 * 60 * 60 * 1000
  const recent = boundedEvents.filter((event) => ms(event.at) >= dayAgo)
  const windowMinutes = 15
  const windowEvents = boundedEvents.filter((event) => ms(event.at) >= now - windowMinutes * 60 * 1000).length

  const exposures = input.evidence.exposures
  const sample = input.evidence.exposureSample
  const categoryCounts = new Map<string, number>()
  for (const row of sample) {
    const key = row.exposureType || 'other'
    categoryCounts.set(key, (categoryCounts.get(key) || 0) + 1)
  }
  const affected = new Set(sample.map((row) => row.assetId).filter(Boolean))
  const sampled = input.evidence.exposureTotal > sample.length

  return {
    generatedAt: new Date(now).toISOString(),
    status,
    statusReason,
    currentStage,
    activeAgents: nodes.filter((node) => ACTIVE.includes(node.status)).length,
    onlineAgents: agents.filter((agent) => agentOnline(agent, now)).length,
    enrolledAgents: agents.filter((agent) => !agent.revoked).length,
    overallProgress,
    progressBasis: overallProgress === null
      ? 'No stage has measurable work yet.'
      : `Stage-weighted (4 × 25%) over measured stages${unmeasured.length ? `; not measurable: ${unmeasured.join(', ')}` : ''}.`,
    startedAt,
    warnings: recent.filter((event) => event.severity === 'warning').length,
    errors: recent.filter((event) => event.severity === 'error' || event.severity === 'critical').length,
    simulationsExcluded,
    nodes,
    edges,
    events: boundedEvents,
    eventsTruncated,
    vulnerabilities: {
      critical: exposures.critical,
      high: exposures.high,
      medium: exposures.medium,
      low: exposures.low,
      total: exposures.critical + exposures.high + exposures.medium + exposures.low,
      affectedAssets: sample.length ? affected.size : input.evidence.exposureTotal === 0 ? 0 : null,
      sampled,
      sampleSize: sample.length,
      categories: Array.from(categoryCounts.entries())
        .map(([key, count]) => ({ key, label: EXPOSURE_LABEL[key] || humanize(key), count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8),
      readiness: { quantumSafe: input.evidence.quantumSafeItems, vulnerable: input.evidence.vulnerableItems, inventory: input.evidence.inventoryItems },
      remediationEligible: remediationJobs.filter((job) => job.approval.approved && ['queued', 'paused'].includes(job.status)).length,
      migrationReady: migrationJobs.filter((job) => job.approval.approved && !job.dispatchBlock && ['queued', 'paused'].includes(job.status)).length,
    },
    throughput: { eventsPerMinute: boundedEvents.length ? Math.round((windowEvents / windowMinutes) * 10) / 10 : null, windowMinutes },
  }
}

/* ------------------------------------------------------------------ */
/* Guardrails — risks linked to the agent and step they affect         */
/* ------------------------------------------------------------------ */

export interface WorkflowRisk {
  id: string
  title: string
  detail: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  agent: WorkflowAgentId
  evidence: string
  affected: string[]
  action: { label: string; href: string }
}

export function deriveRisks(model: AgentWorkflowModel, jobs: WorkflowJob[]): WorkflowRisk[] {
  const risks: WorkflowRisk[] = []
  const real = jobs.filter((job) => !job.isSandbox)
  const node = (id: WorkflowAgentId) => model.nodes.find((item) => item.id === id)!
  const v = model.vulnerabilities

  if (v.critical + v.high > 0) {
    risks.push({
      id: 'legacy-algorithms',
      title: 'Quantum-vulnerable algorithms in use',
      detail: `${v.critical} critical and ${v.high} high exposures (RSA / ECC / DH and weak TLS) recorded by scans.`,
      severity: v.critical > 0 ? 'critical' : 'high',
      agent: 'scanner',
      evidence: 'crypto_exposures',
      affected: v.categories.slice(0, 3).map((category) => category.label),
      action: { label: 'Investigate', href: '/dashboard/crypto-exposure' },
    })
  }
  const outOfScope = real.filter((job) => job.dispatchBlock?.kind === 'out-of-scope')
  if (outOfScope.length) {
    risks.push({
      id: 'unauthorised-path',
      title: 'Change targets an unauthorised path',
      detail: outOfScope[0].dispatchBlock!.reason,
      severity: 'high',
      agent: 'patcher',
      evidence: 'migration_jobs.metadata.dispatchBlock',
      affected: outOfScope.map((job) => job.asset).slice(0, 4),
      action: { label: 'Review scope', href: '/downloads' },
    })
  }
  const noSnapshot = real.filter((job) => job.dispatchBlock?.kind === 'no-snapshot')
  if (noSnapshot.length) {
    risks.push({
      id: 'no-snapshot',
      title: 'No recovery snapshot — execution withheld',
      detail: noSnapshot[0].dispatchBlock!.reason,
      severity: 'high',
      agent: 'patcher',
      evidence: 'snapshot-gate-blocked events',
      affected: noSnapshot.map((job) => job.asset).slice(0, 4),
      action: { label: 'Open snapshots', href: '#snapshots' },
    })
  }
  const unapproved = real.filter((job) => job.approval.required && !job.approval.approved && ['queued', 'paused'].includes(job.status))
  if (unapproved.length) {
    risks.push({
      id: 'missing-authorisation',
      title: 'Changes missing authorisation',
      detail: `${plural(unapproved.length, 'job')} cannot execute until a named person approves it or its plan.`,
      severity: 'medium',
      agent: unapproved.some((job) => (job.executionClass || 'migration') === 'migration') ? 'operator' : 'patcher',
      evidence: 'approval verdict (job / plan metadata)',
      affected: unapproved.map((job) => job.asset).slice(0, 4),
      action: { label: 'Review', href: '#jobs' },
    })
  }
  const failedValidation = real.filter((job) => /fail|invalid|error/.test(job.validationStatus.toLowerCase()))
  if (failedValidation.length) {
    risks.push({
      id: 'validation-failed',
      title: 'Post-change validation failed',
      detail: `${plural(failedValidation.length, 'job')} recorded a failing validation. Rollback is required unless re-validated.`,
      severity: 'critical',
      agent: failedValidation.some((job) => (job.executionClass || 'migration') === 'migration') ? 'operator' : 'patcher',
      evidence: 'migration_validation_logs',
      affected: failedValidation.map((job) => job.asset).slice(0, 4),
      action: { label: 'Verify', href: '#jobs' },
    })
  }
  const unsupportedTarget = real.filter((job) => job.toAlgo && !isApprovedPqcTarget(job.toAlgo) && job.status !== 'cancelled')
  if (unsupportedTarget.length) {
    risks.push({
      id: 'unsupported-target',
      title: 'Target outside the mandatory PQC stack',
      detail: `${plural(unsupportedTarget.length, 'job')} target an algorithm that is not ML-KEM / ML-DSA / SLH-DSA / AES-256-GCM / SHA3.`,
      severity: 'medium',
      agent: 'operator',
      evidence: 'job target algorithm vs mandatory PQC stack',
      affected: unsupportedTarget.map((job) => `${job.asset} → ${job.toAlgo}`).slice(0, 4),
      action: { label: 'Re-plan', href: '/dashboard/migration-planner' },
    })
  }
  for (const id of ['collector', 'scanner'] as const) {
    const n = node(id)
    if (n.status === 'idle') {
      risks.push({
        id: `no-${id}`,
        title: id === 'collector' ? 'Incomplete asset inventory' : 'No vulnerability assessment agent',
        detail: n.reason,
        severity: id === 'collector' ? 'medium' : 'low',
        agent: id,
        evidence: 'scanner_agents (role)',
        affected: [],
        action: { label: 'Install agent', href: '/downloads' },
      })
    } else if (n.status === 'blocked' || (n.status === 'waiting' && n.fleet.online === 0)) {
      risks.push({
        id: `stale-${id}`,
        title: `${n.label} coverage gap`,
        detail: n.reason,
        severity: 'medium',
        agent: id,
        evidence: 'agent heartbeats',
        affected: n.fleet.agents.filter((agent) => !agent.online).map((agent) => agent.name).slice(0, 4),
        action: { label: 'Check agent', href: '/downloads' },
      })
    }
  }
  const unmet = model.edges.filter((edge) => edge.state === 'blocked')
  for (const edge of unmet) {
    const target = node(edge.target)
    if (risks.some((risk) => risk.agent === target.id && /dispatch|authoris|snapshot|path/i.test(risk.title))) continue
    risks.push({
      id: `dependency-${edge.id}`,
      title: `Unmet dependency: ${target.label}`,
      detail: target.reason,
      severity: 'high',
      agent: target.id,
      evidence: 'workflow stage state',
      affected: [],
      action: { label: 'Resolve', href: target.nextHref },
    })
  }
  const rank = { critical: 0, high: 1, medium: 2, low: 3 }
  return risks.sort((a, b) => rank[a.severity] - rank[b.severity])
}

/* ------------------------------------------------------------------ */
/* Safe migration checklist — per job, from recorded evidence only     */
/* ------------------------------------------------------------------ */

export type ChecklistState = 'verified' | 'pending' | 'failed' | 'not_applicable'

export interface ChecklistItem {
  id: string
  label: string
  state: ChecklistState
  detail: string
}

export function safetyChecklist(job: WorkflowJob | null, model: AgentWorkflowModel): ChecklistItem[] {
  if (!job) return []
  const metadata = job.metadata || {}
  const execution = rec(metadata.execution)
  const isMigration = (job.executionClass || 'migration') === 'migration'
  const validation = job.validationStatus.toLowerCase()
  const validated = isPassingValidation(job.validationStatus)
  const validationFailed = /fail|invalid|error/.test(validation)
  const snapshotId = str(metadata.preChangeSnapshotId) || str(execution.preChangeSnapshotId)
  const deps = Array.isArray(metadata.dependencies) ? metadata.dependencies : Array.isArray(rec(metadata.migrationContext).dependencies) ? rec(metadata.migrationContext).dependencies as unknown[] : null
  const packageVerification = rec(metadata.packageVerification || metadata.sourceVerification)
  const auditTrail = job.logs.length

  if (job.isSandbox) {
    return [{ id: 'sandbox', label: 'Sandbox simulation', state: 'not_applicable', detail: 'Executed against a digital twin by the sandbox engine. No asset is changed, so no safeguard applies.' }]
  }

  const items: ChecklistItem[] = [
    {
      id: 'target',
      label: 'Verify target asset and authorisation',
      state: job.assetId && job.approval.approved ? 'verified' : job.approval.state === 'rejected' ? 'failed' : 'pending',
      detail: job.assetId
        ? job.approval.approved ? `Asset on record; approved by ${job.approval.approvedBy || 'an operator'}.` : 'Asset on record; approval not yet recorded.'
        : 'The job does not reference an inventoried asset.',
    },
    {
      id: 'inventory',
      label: 'Validate cryptographic inventory',
      state: job.fromAlgo && !/unknown/i.test(job.fromAlgo) ? 'verified' : 'pending',
      detail: job.fromAlgo && !/unknown/i.test(job.fromAlgo) ? `Current algorithm ${job.fromAlgo} recorded from inventory.` : 'The source algorithm is not confirmed by inventory evidence.',
    },
    {
      id: 'evidence',
      label: 'Review vulnerability evidence',
      state: model.vulnerabilities.total > 0 || job.fromAlgo ? 'verified' : 'pending',
      detail: model.vulnerabilities.total > 0 ? `${model.vulnerabilities.total} exposures on record for the tenant.` : 'No exposure rows recorded yet.',
    },
    {
      id: 'approval',
      label: 'Confirm configuration change approval',
      state: !job.approval.required ? 'not_applicable' : job.approval.approved ? 'verified' : job.approval.state === 'rejected' ? 'failed' : 'pending',
      detail: job.approval.approved
        ? `Approved${job.approval.approvedAt ? ` ${job.approval.approvedAt.slice(0, 10)}` : ''} via ${job.approval.source === 'plan' ? 'migration plan' : 'job approval'}.`
        : job.approval.state === 'rejected' ? 'Rejected — will not be dispatched.' : 'Awaiting a named approver.',
    },
    {
      id: 'sources',
      label: 'Verify trusted package and configuration sources',
      state: Object.keys(packageVerification).length
        ? packageVerification.verified === true ? 'verified' : 'failed'
        : job.dispatchBlock?.kind === 'out-of-scope' ? 'failed' : job.executionBacked ? 'verified' : 'pending',
      detail: Object.keys(packageVerification).length
        ? packageVerification.verified === true ? 'Source verification recorded on the job.' : 'Source verification recorded as failed.'
        : job.dispatchBlock?.kind === 'out-of-scope'
          ? job.dispatchBlock.reason
          : job.executionBacked ? 'Executed on an allow-listed path accepted by the agent policy.' : 'Checked by the agent against its allow-list at claim time.',
    },
    {
      id: 'snapshot',
      label: 'Create a recovery snapshot',
      state: snapshotId ? 'verified' : job.dispatchBlock?.kind === 'no-snapshot' ? 'failed' : 'pending',
      detail: snapshotId ? `Pre-change snapshot ${snapshotId.slice(0, 12)}… recorded at claim.` : job.dispatchBlock?.kind === 'no-snapshot' ? job.dispatchBlock.reason : 'Taken by the agent before it changes anything.',
    },
    {
      id: 'pqc-settings',
      label: 'Validate proposed PQC settings',
      state: job.toAlgo ? (isApprovedPqcTarget(job.toAlgo) ? 'verified' : 'failed') : 'pending',
      detail: job.toAlgo ? (isApprovedPqcTarget(job.toAlgo) ? `${job.toAlgo} is on the mandatory PQC stack.` : `${job.toAlgo} is not on the mandatory PQC stack.`) : 'No target algorithm recorded.',
    },
    {
      id: 'dependencies',
      label: 'Confirm dependency readiness',
      state: deps === null ? (job.dispatchBlock ? 'failed' : 'pending') : deps.length === 0 ? 'verified' : job.status === 'completed' ? 'verified' : 'pending',
      detail: deps === null ? (job.dispatchBlock ? job.dispatchBlock.reason : 'No dependency analysis attached to this job.') : deps.length === 0 ? 'No upstream dependencies recorded.' : `${deps.length} dependencies recorded by the planner.`,
    },
    {
      id: 'health',
      label: 'Verify post-remediation service health',
      state: validated ? 'verified' : validationFailed ? 'failed' : 'pending',
      detail: validated ? `Validation ${job.validationStatus} (${job.validationCount} record${job.validationCount === 1 ? '' : 's'}).` : validationFailed ? `Validation ${job.validationStatus}.` : 'No passing validation recorded yet.',
    },
    {
      id: 'cutover-auth',
      label: 'Confirm cutover authorisation',
      state: !isMigration ? 'not_applicable' : job.approval.approved ? 'verified' : job.approval.state === 'rejected' ? 'failed' : 'pending',
      detail: !isMigration ? 'Remediation job — no live cutover is performed.' : job.approval.approved ? 'Cutover approved; executable only by a Migration Operator.' : 'Cutover not yet authorised.',
    },
    {
      id: 'completion',
      label: 'Validate migration completion',
      state: job.status === 'completed' && validated ? 'verified' : job.status === 'failed' ? 'failed' : 'pending',
      detail: job.status === 'completed' ? (validated ? 'Completed with passing validation.' : 'Completed, but no passing validation recorded.') : job.status === 'failed' ? 'Execution failed.' : `Status: ${job.status}.`,
    },
    {
      id: 'audit',
      label: 'Record final evidence and audit trail',
      state: job.status === 'completed' && auditTrail > 0 ? 'verified' : 'pending',
      detail: auditTrail > 0 ? `${auditTrail} execution record(s) persisted for this job.` : 'No execution records persisted yet.',
    },
  ]
  return items
}

export { jobStatusToWorkflow }
