import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  BadgeCheck,
  CheckCircle2,
  Ban,
  Clock3,
  Diamond,
  Download,
  FileText,
  Filter,
  Layers3,
  ListChecks,
  Maximize2,
  MoreVertical,
  Pause,
  Play,
  Radio,
  Rocket,
  RefreshCcw,
  RotateCcw,
  Server,
  ShieldCheck,
  Terminal,
  Trash2,
  XCircle,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import CryptoUpgradePanel, { targetStandard, type CryptoTransition } from './_crypto-upgrade'
import { SnapshotManager } from './_snapshots'
import { ReportExportMenu } from '../_components/InventoryExportMenu'
import { buildMigrationReport } from '@/services/reporting/MigrationReport'
import { Archive, FileJson, History as HistoryIcon } from 'lucide-react'
import type { ApprovalVerdict } from '@/lib/migration/job-safety'
import {
  AGENT_META,
  SCAN_STAGE_LABEL,
  deriveRisks,
  safetyChecklist,
  type AgentWorkflowModel,
  type EventSeverity,
  type WorkflowAgentId,
  type WorkflowEvent,
} from '@/lib/migration/agent-workflow'
import WorkflowCanvas from './_workflow-canvas'
import ScanRunPanel from './_scan-run-panel'
import {
  AgentInsightsPanel,
  AgentMetricsPanel,
  CONNECTION_META,
  ExecutionLogs,
  ExecutionTimeline,
  NotificationStack,
  RisksPanel,
  SafetyChecklistPanel,
  VulnerabilitySummaryPanel,
  WorkflowHeader,
  type ConnectionState,
  type WorkflowNotification,
} from './_workflow-panels'
import { PANEL, type AgentLiveActivity } from './_workflow-ui'

type LiveMigrationStatus =
  | 'running'
  | 'completed'
  | 'failed'
  | 'queued'
  | 'paused'
  | 'cancelled'
  /** Rollback dispatched to an executor; the asset has NOT changed back yet. */
  | 'rolling_back'
  /** An executor confirmed the previous configuration is back on the asset. */
  | 'rolled_back'

type LiveMigrationEvent = {
  id: string
  migrationId: string
  eventType: string
  message: string
  severity: string
  createdAt: string
  metadata: Record<string, unknown>
}

type LiveMigrationJob = {
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
  /** Raw job_type; the operation class is decided from this server-side. */
  jobType: string
  /** Which agent role may execute it (server: `jobExecutionClass`). */
  executionClass?: 'migration' | 'remediation'
  status: LiveMigrationStatus
  rawStatus: string
  progress: number
  eta: string
  startedAt: string | null
  completedAt: string | null
  createdAt: string
  updatedAt: string
  executionStatus: string
  executionBacked: boolean
  /** Why nothing is executing this job, when something is blocking it. */
  dispatchBlock: { kind: string; requires: string; reason: string; at: string } | null
  /** Same verdict the agent poll enforces — who approved this, or why nobody has. */
  approval: ApprovalVerdict
  isSandbox?: boolean
  runMode?: string
  agentId: string | null
  agentName: string | null
  agentStatus: string
  currentStep: string
  telemetryCount: number
  validationCount: number
  validationStatus: string
  logs: LiveMigrationEvent[]
  logCount: number
  metadata: Record<string, unknown>
}

type TimelinePoint = {
  key: string
  label: string
  running: number
  completed: number
  failed: number
}

/**
 * Per-asset context handed over by the Migration Planner's asset workspace.
 * Present when the page was opened via "Send to Live Migration" — it carries the
 * exact plan, recommendations, dependencies, rollback configuration, approvals
 * and readiness the operator reviewed in the planner.
 */
type PlannerHandoff = {
  stampedAt?: string
  stampedBy?: string
  assets?: Array<{
    assetId: string
    name: string
    type?: string
    environment?: string
    owner?: string
    priority?: string
    riskScore?: number
    readinessScore?: number
    estimatedDowntime?: string
    successProbabilityPct?: number
    rollbackStrategy?: { strategy?: string; recoveryObjective?: string }
    recommendations?: Array<{ title: string }>
    requiredApprovals?: Array<{ role: string; required: boolean }>
    dependencies?: unknown[]
  }>
}

type LiveMigrationSnapshot = {
  generatedAt: string
  planId: string | null
  plannerHandoff?: PlannerHandoff | null
  summary: {
    total: number
    running: number
    completed: number
    failed: number
    queued: number
    paused: number
    cancelled: number
    rollingBack: number
    rolledBack: number
    awaitingApproval: number
    completionRate: number
    waitingForAgent: number
    agentBacked: number
    verified: number
    agentsOnline: number
    agentsEnrolled: number
    agentsStale: number
    totalAssets: number
    findings: number
    criticalExposures: number
    highExposures: number
    lastScanAt: string | null
    complianceMode: string
    standardLabel: string
  }
  jobs: LiveMigrationJob[]
  timeline: TimelinePoint[]
  telemetry: {
    tlsHandshakeEvents: number
    certificateReplacements: number
    keyRotations: number
    pqcValidationEvents: number
    compatibilityChecks: number
    systemHealth: string
    activityFeed: {
      migrationLogs: number
      validationLogs: number
      errorLogs: number
      auditLogs: number
      complianceLogs: number
    }
  }
  /** Four-agent workflow derived server-side (src/lib/migration/agent-workflow.ts). */
  agentWorkflow?: AgentWorkflowModel
  /** Optional enrichment reads that failed — shown as Unknown, never as zero. */
  workflowDegraded?: { heartbeats: boolean; exposures: boolean; inventory: boolean }
  /** Execution runs (migration plans) for the run selector. */
  runs?: Array<{ id: string; status: string; createdAt: string | null; updatedAt: string | null }>
}

/** A frame pushed on the live stream by the agent event bus (server-sequenced id). */
type AgentStreamFrame = { id: number; name: string; agentId: string | null; at: string; payload: Record<string, unknown> }

const TERMINAL_JOB = new Set(['completed', 'failed', 'cancelled', 'rolled_back'])
/** Agent-bus frames that only an agent checking in can produce — each proves it is alive. */
const LIVENESS_FRAMES = new Set(['agent.heartbeat', 'agent.connected', 'agent.scan_progress', 'agent.scan_completed', 'agent.error'])
/** Frames that describe what the agent is doing right now. */
const ACTIVITY_FRAMES = new Set(['agent.scan_progress', 'agent.scan_completed', 'agent.error'])

function storedJson<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as T) : fallback
  } catch {
    return fallback
  }
}

function storeJson(key: string, value: unknown) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // Preferences are a convenience; private mode simply forgets them.
  }
}

const NOTIFICATION_TITLE: Array<[RegExp, string]> = [
  [/^scan\.failed$/, 'Scan failed'],
  [/^agent\.error$/, 'Agent error'],
  [/^agent\.degraded$/, 'Evidence publish errors'],
  [/^agent\.disabled$/, 'Agent disabled'],
  [/snapshot-gate/, 'Recovery snapshot missing'],
  [/rollback/, 'Rollback update'],
  [/validation/, 'Validation failed'],
  [/^scan\.completed$/, 'Observations outside authorised scope'],
  [/dispatch|block/, 'Dispatch blocked'],
]

function notificationTitle(event: WorkflowEvent) {
  const match = NOTIFICATION_TITLE.find(([pattern]) => pattern.test(event.type))
  return match ? match[1] : event.type.replace(/[._-]+/g, ' ').replace(/^\w/, (c) => c.toUpperCase())
}

const EMPTY_SNAPSHOT: LiveMigrationSnapshot = {
  generatedAt: new Date(0).toISOString(),
  planId: null,
  summary: {
    total: 0,
    running: 0,
    completed: 0,
    failed: 0,
    queued: 0,
    paused: 0,
    cancelled: 0,
    rollingBack: 0,
    rolledBack: 0,
    awaitingApproval: 0,
    completionRate: 0,
    waitingForAgent: 0,
    agentBacked: 0,
    verified: 0,
    agentsOnline: 0,
    agentsEnrolled: 0,
    agentsStale: 0,
    totalAssets: 0,
    findings: 0,
    criticalExposures: 0,
    highExposures: 0,
    lastScanAt: null,
    complianceMode: 'NIST Compliant',
    standardLabel: 'NIST SP 800-208 | NIST SP 800-57 Rev. 5',
  },
  jobs: [],
  timeline: [],
  telemetry: {
    tlsHandshakeEvents: 0,
    certificateReplacements: 0,
    keyRotations: 0,
    pqcValidationEvents: 0,
    compatibilityChecks: 0,
    systemHealth: 'No active migrations',
    activityFeed: {
      migrationLogs: 0,
      validationLogs: 0,
      errorLogs: 0,
      auditLogs: 0,
      complianceLogs: 0,
    },
  },
}

// Premium glassmorphism — aligned with the Agent Collector Console, Quantum
// Certification and Quantum Readiness surfaces (cyan-forward, soft, spacious).
const GLASS =
  'rounded-2xl border border-white/10 bg-white/[0.035] backdrop-blur-xl text-white shadow-[0_18px_60px_rgba(0,0,0,0.35)]'
const INNER =
  'rounded-xl border border-white/10 bg-white/[0.02] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]'
// Theme tokens (live-workflow.css): neon on dark, the hue's dark end on parchment.
const GOLD = 'var(--lw-cyan)'
const GREEN = 'var(--lw-green)'
const RED = 'var(--lw-red)'

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(value || 0)
}

function safeDate(value: string | null | undefined) {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

function formatTime(value: string | null | undefined) {
  const date = safeDate(value)
  if (!date) return 'Pending'
  return date.toLocaleTimeString('en-US', { hour12: false })
}

function formatShortDate(value: string | null | undefined) {
  const date = safeDate(value)
  if (!date) return 'No scan yet'
  return date.toLocaleDateString('en-US', { month: 'short', day: '2-digit' })
}

function uiRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function uiText(value: unknown) {
  if (typeof value === 'string' && value.trim()) return value.trim()
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  return ''
}

function firstUiText(...values: unknown[]) {
  for (const value of values) {
    const text = uiText(value)
    if (text) return text
  }
  return ''
}

function selectedJobConfigPath(job: LiveMigrationJob | undefined) {
  if (!job) return ''
  const metadata = uiRecord(job.metadata)
  const execution = uiRecord(metadata.execution)
  const remediation = uiRecord(metadata.remediation)
  const target = uiRecord(metadata.target)
  return firstUiText(
    metadata.filePath,
    metadata.path,
    metadata.configPath,
    metadata.configurationPath,
    metadata.localConfigPath,
    metadata.targetPath,
    execution.filePath,
    execution.path,
    execution.targetPath,
    remediation.filePath,
    target.filePath,
  )
}

function selectedJobConnector(job: LiveMigrationJob | undefined) {
  if (!job) return ''
  const metadata = uiRecord(job.metadata)
  const execution = uiRecord(metadata.execution)
  const connector = uiRecord(metadata.connector)
  return firstUiText(
    metadata.connectorId,
    metadata.connector_id,
    metadata.connectorName,
    metadata.provider,
    execution.connectorId,
    execution.provider,
    connector.id,
    connector.name,
    connector.provider,
  )
}

function selectedJobNeedsConnector(job: LiveMigrationJob | undefined) {
  if (!job) return false
  const metadata = uiRecord(job.metadata)
  const execution = uiRecord(metadata.execution)
  const text = [
    job.asset,
    job.assetType,
    job.migrationType,
    job.currentStep,
    metadata.assetClass,
    metadata.provider,
    metadata.connectorId,
    metadata.connector_id,
    execution.provider,
  ].map((item) => String(item || '').toLowerCase()).join(' ')
  return /cloud|aws|azure|gcp|kubernetes|k8s|cluster|ingress|load balancer|alb|elb|cdn|cloudfront|cloudflare|akamai|kms|key vault|iam|identity|okta|entra|auth0|oauth|oidc|saml|certificate|cert|issuer|pki/.test(text)
}

function statusConfig(status: LiveMigrationStatus) {
  switch (status) {
    case 'running':
      return { icon: RefreshCcw, color: 'text-[#22d3ee]', ring: 'border-[#22d3ee]', bar: 'from-[#22d3ee] to-[#fff3c1]', label: 'RUNNING' }
    case 'completed':
      return { icon: CheckCircle2, color: 'text-[#34d399]', ring: 'border-[#34d399]', bar: 'from-[#34d399] to-[#8dffab]', label: 'COMPLETED' }
    case 'failed':
      return { icon: XCircle, color: 'text-[#f87171]', ring: 'border-[#f87171]', bar: 'from-[#f87171] to-[#ff7a6f]', label: 'FAILED' }
    case 'paused':
      return { icon: Pause, color: 'text-[#22d3ee]', ring: 'border-[#22d3ee]', bar: 'from-[#22d3ee] to-[#ffb84d]', label: 'PAUSED' }
    case 'cancelled':
      return { icon: Ban, color: 'text-white/45', ring: 'border-white/30', bar: 'from-white/35 to-white/15', label: 'CANCELLED' }
    case 'rolling_back':
      return { icon: RotateCcw, color: 'text-[#fbbf24]', ring: 'border-[#fbbf24]', bar: 'from-[#fbbf24] to-[#ffd98a]', label: 'ROLLING BACK' }
    case 'rolled_back':
      return { icon: RotateCcw, color: 'text-[#a78bfa]', ring: 'border-[#a78bfa]', bar: 'from-[#a78bfa] to-[#d3c4ff]', label: 'ROLLED BACK' }
    case 'queued':
    default:
      return { icon: Clock3, color: 'text-white/45', ring: 'border-white/35', bar: 'from-white/50 to-white/25', label: 'QUEUED' }
  }
}

function Sparkline({ values, color = GOLD }: { values: number[]; color?: string }) {
  const max = Math.max(1, ...values)
  const points = values.length
    ? values.map((value, index) => {
        const x = values.length === 1 ? 96 : (index / (values.length - 1)) * 96
        const y = 38 - (value / max) * 32
        return `${x},${y}`
      }).join(' ')
    : '0,38 96,38'

  return (
    <svg viewBox="0 0 100 44" className="h-11 w-24 shrink-0 overflow-visible" aria-hidden="true">
      <polyline points={points} fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ stroke: color }} />
      <polyline points={`0,42 ${points} 100,42`} stroke="none" style={{ fill: `color-mix(in srgb, ${color} 9%, transparent)` }} />
    </svg>
  )
}

function PhaseRail({ job }: { job: LiveMigrationJob }) {
  const phases = [
    ['Key Generation', 15],
    ['Hybrid Handshake', 35],
    ['Certificate Deploy', 55],
    ['Validation', 72],
    ['Cutover', 88],
    ['Verify & Monitor', 100],
  ] as const

  const completedIndex = job.status === 'completed'
    ? phases.length
    : job.status === 'failed'
      ? Math.max(0, phases.findIndex(([, threshold]) => job.progress < threshold))
      : phases.filter(([, threshold]) => job.progress >= threshold).length
  const currentIndex = Math.min(completedIndex, phases.length - 1)

  return (
    <div className="relative z-10 px-2 py-4">
      <div className="absolute left-[8%] right-[8%] top-[34px] h-px bg-white/30" />
      <div className="grid grid-cols-6 gap-2">
        {phases.map(([label], index) => {
          const complete = index < completedIndex || job.status === 'completed'
          const current = index === currentIndex && job.status === 'running'
          const failed = index === currentIndex && job.status === 'failed'
          return (
            <div key={label} className="relative flex flex-col items-center gap-2 text-center">
              <div
                className={cn(
                  'z-10 grid h-7 w-7 place-items-center rounded-full border bg-[#0b1120] shadow-[0_0_16px_rgba(0,0,0,0.65)]',
                  complete && 'border-[#34d399] text-[#34d399]',
                  current && 'border-[#22d3ee] text-[#22d3ee] shadow-[0_0_18px_rgba(212,175,55,0.45)]',
                  failed && 'border-[#f87171] text-[#f87171]',
                  !complete && !current && !failed && 'border-white/30 text-white/30',
                )}
              >
                <BadgeCheck className="h-3.5 w-3.5" />
              </div>
              <div className="min-h-10">
                <div className="text-[9px] font-bold leading-tight text-white/70">{label}</div>
                <div
                  className={cn(
                    'mt-1 text-[8px] font-black uppercase tracking-wider',
                    complete && 'text-[#34d399]',
                    current && 'text-[#22d3ee]',
                    failed && 'text-[#f87171]',
                    !complete && !current && !failed && 'text-white/32',
                  )}
                >
                  {failed ? 'Failed' : complete ? 'Completed' : current ? 'In Progress' : 'Pending'}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function SeverityDots({ criticality }: { criticality: string }) {
  const value = criticality.toLowerCase()
  const count = value === 'critical' ? 4 : value === 'high' ? 3 : value === 'medium' ? 2 : 1
  return (
    <div className="flex items-center gap-1">
      {Array.from({ length: 4 }, (_, index) => (
        <span
          key={index}
          className={cn('h-2.5 w-2.5 rounded-full', index < count ? 'bg-[#f87171] shadow-[0_0_9px_rgba(255,59,48,0.45)]' : 'bg-white/12')}
        />
      ))}
      <span className="ml-1 text-[9px] capitalize text-white/35">{criticality || 'medium'}</span>
    </div>
  )
}

export default function LiveMigrationOperations() {
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const planId = searchParams.get('planId')
  const requestedAgentId = searchParams.get('agentId')
  const requestedCommandId = searchParams.get('commandId')
  const { session, user } = useAuth()
  const token = session?.access_token
  const [snapshot, setSnapshot] = useState<LiveMigrationSnapshot>(EMPTY_SNAPSHOT)
  const [selectedJobId, setSelectedJobId] = useState<string>('')
  const [filter, setFilter] = useState<'all' | LiveMigrationStatus>('all')
  const [loading, setLoading] = useState(true)
  const [streamConnected, setStreamConnected] = useState(false)
  const [realtimeStatus, setRealtimeStatus] = useState('CLOSED')
  const [actionPending, setActionPending] = useState('')
  const [notice, setNotice] = useState('')
  // Queue curation: operators can withdraw (cancel) or delete (remove) jobs they
  // queued by mistake. Removal is destructive, so it always goes through an
  // explicit confirmation that names exactly what will be deleted.
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [confirm, setConfirm] = useState<null | { mode: 'cancel' | 'remove' | 'rollback' | 'approve'; ids: string[]; includeCompleted: boolean }>(null)
  const [now, setNow] = useState(new Date())
  const [snapshotsOpen, setSnapshotsOpen] = useState(false)
  const [snapshotFocusAsset, setSnapshotFocusAsset] = useState<string | null>(null)
  // Workflow command center (presentation state only — truth is the snapshot).
  const [selectedAgent, setSelectedAgent] = useState<WorkflowAgentId>('collector')
  const agentChosenRef = useRef(false)
  const [highlightedAgent, setHighlightedAgent] = useState<WorkflowAgentId | null>(null)
  const [latency, setLatency] = useState<{ latest: number | null; series: number[] }>({ latest: null, series: [] })
  const [liveFrames, setLiveFrames] = useState<AgentStreamFrame[]>([])
  const [dismissed, setDismissed] = useState<string[]>(() => storedJson('qg.liveMigration.dismissed', [] as string[]))
  const [minSeverity, setMinSeverity] = useState<'warning' | 'error'>(() => storedJson('qg.liveMigration.minSeverity', 'warning' as 'warning' | 'error'))
  const insightsRef = useRef<HTMLDivElement>(null)
  const jobsRef = useRef<HTMLElement>(null)

  const authHeaders = useMemo(() => ({
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }), [token])
  const planQuery = planId ? `planId=${encodeURIComponent(planId)}` : ''
  const lastGeneratedAtRef = useRef(0)

  // Snapshots arrive from three async sources (REST, SSE, action responses);
  // never let an older snapshot overwrite a newer one, and never replace live
  // data with a missing payload.
  const applySnapshot = useCallback((next?: LiveMigrationSnapshot | null) => {
    if (!next) return
    const generatedMs = Date.parse(String(next.generatedAt || '')) || Date.now()
    if (generatedMs < lastGeneratedAtRef.current) return
    lastGeneratedAtRef.current = generatedMs
    setSnapshot(next)
  }, [])

  const fetchSnapshot = useCallback(async () => {
    if (!token) return
    try {
      const started = performance.now()
      const res = await fetch(`/api/v1/migration/live${planQuery ? `?${planQuery}` : ''}`, { headers: authHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      // Control-plane latency as this browser measured it — a real round trip.
      const elapsed = Math.round(performance.now() - started)
      setLatency((current) => ({ latest: elapsed, series: [...current.series, elapsed].slice(-30) }))
      // A 200 with a missing/truncated body must not wipe the dashboard to the
      // empty state — keep last-known-good data and surface the error instead.
      if (!json?.data) throw new Error('Snapshot response was empty or malformed')
      applySnapshot(json.data)
    } catch (error) {
      console.error('Live migration sync failed:', error)
      setNotice('Live migration data is temporarily unavailable.')
    } finally {
      setLoading(false)
    }
  }, [applySnapshot, authHeaders, planQuery, token])

  useEffect(() => {
    fetchSnapshot()
  }, [fetchSnapshot])

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (!token) return
    const streamParams = new URLSearchParams({ token })
    if (planId) streamParams.set('planId', planId)
    const source = new EventSource(`/api/v1/migration/live/stream?${streamParams.toString()}`)
    source.onopen = () => setStreamConnected(true)
    source.onerror = () => setStreamConnected(false)
    source.addEventListener('connected', () => setStreamConnected(true))
    source.addEventListener('migration-update', (event) => {
      try {
        applySnapshot(JSON.parse(event.data))
        setLoading(false)
      } catch (error) {
        console.error('Invalid live migration stream payload:', error)
      }
    })
    // Agent bus frames: server-sequenced, so a reconnect (EventSource resends
    // Last-Event-ID) replays what was missed; duplicates are dropped by id.
    source.addEventListener('agent-event', (event) => {
      try {
        const frame = JSON.parse((event as MessageEvent).data) as AgentStreamFrame
        if (!frame || typeof frame.id !== 'number') return
        setLiveFrames((current) => (current.some((item) => item.id === frame.id) ? current : [frame, ...current].slice(0, 100)))
      } catch (error) {
        console.error('Invalid agent stream frame:', error)
      }
    })
    return () => {
      source.close()
      setStreamConnected(false)
    }
  }, [applySnapshot, planId, token])

  useEffect(() => {
    if (!user?.id) return
    // Debounced: while a migration runs, migration_jobs updates land every
    // couple of seconds; refetching on every event creates a request storm
    // (each snapshot build advances the sandbox engine, which writes again).
    let refetchTimer: ReturnType<typeof setTimeout> | null = null
    const scheduleRefetch = () => {
      if (refetchTimer) return
      refetchTimer = setTimeout(() => {
        refetchTimer = null
        void fetchSnapshot()
      }, 1200)
    }
    const channel = supabase
      .channel(`live-migration-ops-${user.id}`)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'migration_jobs', filter: `user_id=eq.${user.id}` }, scheduleRefetch)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'migration_plans', filter: `user_id=eq.${user.id}` }, scheduleRefetch)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'migration_events', filter: `user_id=eq.${user.id}` }, scheduleRefetch)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'migration_execution', filter: `user_id=eq.${user.id}` }, scheduleRefetch)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'migration_telemetry', filter: `user_id=eq.${user.id}` }, scheduleRefetch)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'migration_validation_logs', filter: `user_id=eq.${user.id}` }, scheduleRefetch)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'execution_queues', filter: `user_id=eq.${user.id}` }, scheduleRefetch)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'pqc_scan_results', filter: `user_id=eq.${user.id}` }, scheduleRefetch)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'crypto_exposures', filter: `user_id=eq.${user.id}` }, scheduleRefetch)
      .subscribe((status) => setRealtimeStatus(status))

    return () => {
      if (refetchTimer) clearTimeout(refetchTimer)
      supabase.removeChannel(channel)
    }
  }, [fetchSnapshot, user?.id])

  useEffect(() => {
    if (!snapshot.jobs.length) {
      setSelectedJobId('')
      return
    }
    if (!snapshot.jobs.some((job) => job.id === selectedJobId)) {
      setSelectedJobId(snapshot.jobs[0].id)
    }
  }, [selectedJobId, snapshot.jobs])

  const selectedJob = snapshot.jobs.find((job) => job.id === selectedJobId) || snapshot.jobs[0]
  const selectedJobConfig = uiRecord(selectedJob?.metadata?.configuration)
  const selectedJobExecution = uiRecord(selectedJob?.metadata?.execution)
  const selectedJobControls = uiRecord(selectedJob?.metadata?.controls || selectedJobConfig.controls)
  const selectedJobEnabledControls = Object.entries(selectedJobControls).filter(([, enabled]) => enabled !== false).length
  const selectedConfigPath = selectedJobConfigPath(selectedJob)
  const selectedConnector = selectedJobConnector(selectedJob)
  const selectedNeedsConnector = selectedJobNeedsConnector(selectedJob)
  const filteredJobs = filter === 'all' ? snapshot.jobs : snapshot.jobs.filter((job) => job.status === filter)

  const selectedSet = useMemo(() => new Set(selectedIds), [selectedIds])
  const allFilteredSelected = filteredJobs.length > 0 && filteredJobs.every((job) => selectedSet.has(job.id))
  // A live update (SSE / realtime) can remove jobs another session deleted —
  // drop them from the selection so bulk actions never target stale ids.
  useEffect(() => {
    setSelectedIds((current) => {
      if (!current.length) return current
      const live = new Set(snapshot.jobs.map((job) => job.id))
      const next = current.filter((id) => live.has(id))
      return next.length === current.length ? current : next
    })
  }, [snapshot.jobs])

  const toggleJobSelection = useCallback((jobId: string) => {
    setSelectedIds((current) => (current.includes(jobId) ? current.filter((id) => id !== jobId) : [...current, jobId]))
  }, [])
  const toggleAllFiltered = useCallback(() => {
    setSelectedIds((current) => {
      const ids = filteredJobs.map((job) => job.id)
      const everySelected = ids.length > 0 && ids.every((id) => current.includes(id))
      if (everySelected) return current.filter((id) => !ids.includes(id))
      return [...new Set([...current, ...ids])]
    })
  }, [filteredJobs])

  /**
   * How old the data on screen is.
   *
   * Recomputed from `now` (which ticks every second) rather than from a render,
   * so a page left open with a dead stream visibly ages instead of freezing at
   * whatever it last said.
   */
  const snapshotAgeSeconds = useMemo(() => {
    const generated = Date.parse(String(snapshot.generatedAt || ''))
    if (!Number.isFinite(generated) || generated <= 0) return Number.POSITIVE_INFINITY
    return Math.max(0, Math.round((now.getTime() - generated) / 1000))
  }, [snapshot.generatedAt, now])

  const snapshotAgeLabel = useMemo(() => {
    if (!Number.isFinite(snapshotAgeSeconds)) return 'never'
    if (snapshotAgeSeconds < 5) return 'just now'
    if (snapshotAgeSeconds < 90) return `${snapshotAgeSeconds}s ago`
    const minutes = Math.round(snapshotAgeSeconds / 60)
    return minutes < 90 ? `${minutes}m ago` : `${Math.round(minutes / 60)}h ago`
  }, [snapshotAgeSeconds])

  const statSparklines = useMemo(() => ({
    running: snapshot.timeline.map((point) => point.running),
    completed: snapshot.timeline.map((point) => point.completed),
    failed: snapshot.timeline.map((point) => point.failed),
    total: snapshot.timeline.map((point) => point.running + point.completed + point.failed),
  }), [snapshot.timeline])

  const runJobAction = useCallback(async (jobId: string, action: 'pause' | 'resume' | 'retry' | 'rollback' | 'cancel' | 'approve') => {
    if (!token) return
    setActionPending(`${jobId}:${action}`)
    setNotice('')
    try {
      const res = await fetch(`/api/v1/migration/jobs/${jobId}/action`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ action }),
      })
      const json = await res.json()
      if (!res.ok) throw new Error(json?.error?.message || `HTTP ${res.status}`)
      applySnapshot(json.data?.snapshot)
      /* A rollback resolves to one of four dispositions and the server states
         which. Echoing "action recorded" would hide the difference between a
         rollback that was executed and one that nothing could act on. */
      const rollback = json.data?.rollback as { disposition?: string; message?: string } | undefined
      setNotice(rollback?.message || `Migration action recorded: ${action}.`)
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Migration action failed.')
    } finally {
      setActionPending('')
    }
  }, [applySnapshot, authHeaders, token])

  const runBulkAction = useCallback(async (action: 'pause' | 'resume' | 'retry' | 'cancel', jobIds?: string[]) => {
    if (!token) return
    setActionPending(`bulk:${action}`)
    setNotice('')
    try {
      const res = await fetch('/api/v1/migration/jobs/actions', {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ action, ...(planId ? { planId } : {}), ...(jobIds?.length ? { jobIds } : {}) }),
      })
      const json = await res.json()
      if (!res.ok) throw new Error(json?.error?.message || `HTTP ${res.status}`)
      applySnapshot(json.data?.snapshot)
      /* Say what did NOT happen as well as what did: "Resume All" that moved 3
         of 10 jobs must name why the other 7 stayed put. */
      const blocked = (json.data?.blocked || []) as Array<{ name: string; reason: string }>
      setNotice(
        blocked.length
          ? `${numberFmt(json.data?.affected || 0)} migration job(s) updated. ${numberFmt(blocked.length)} not updated — ${blocked[0].reason}`
          : `${numberFmt(json.data?.affected || 0)} migration job(s) updated.`,
      )
      if (jobIds?.length) setSelectedIds([])
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Bulk migration action failed.')
    } finally {
      setActionPending('')
    }
  }, [applySnapshot, authHeaders, planId, token])

  /**
   * Deletes migration jobs outright. The server refuses to remove a running job
   * and (unless explicitly included) a completed one, and reports what it
   * skipped — so the notice reflects what actually happened, not what was asked.
   */
  const removeJobs = useCallback(async (jobIds: string[], includeCompleted: boolean) => {
    if (!token || !jobIds.length) return
    setActionPending(`remove:${jobIds.length}`)
    setNotice('')
    try {
      const res = await fetch('/api/v1/migration/jobs/remove', {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ jobIds, includeCompleted, ...(planId ? { planId } : {}) }),
      })
      const json = await res.json()
      if (!res.ok) throw new Error(json?.error?.message || `HTTP ${res.status}`)
      applySnapshot(json.data?.snapshot)
      const removed = Number(json.data?.removed || 0)
      const blocked = (json.data?.blocked || []) as Array<{ name: string; reason: string }>
      setSelectedIds((current) => current.filter((id) => !(json.data?.removedIds || []).includes(id)))
      setSelectedJobId((current) => ((json.data?.removedIds || []).includes(current) ? '' : current))
      setNotice(
        blocked.length
          ? `${numberFmt(removed)} job(s) removed. ${blocked.length} kept: ${blocked[0].reason}`
          : `${numberFmt(removed)} migration job(s) removed from the queue.`,
      )
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Migration job removal failed.')
    } finally {
      setActionPending('')
      setConfirm(null)
    }
  }, [applySnapshot, authHeaders, planId, token])

  const downloadExport = useCallback(async (format: 'csv' | 'json') => {
    if (!token) return
    setActionPending(`export:${format}`)
    try {
      const params = new URLSearchParams({ format })
      if (planId) params.set('planId', planId)
      const res = await fetch(`/api/v1/migration/live/export?${params.toString()}`, { headers: authHeaders })
      if (!res.ok) throw new Error(`Export failed with HTTP ${res.status}`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `qguard-live-migration-${new Date().toISOString().slice(0, 10)}.${format}`
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      setNotice(`Migration ${format.toUpperCase()} export generated from live data.`)
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Migration export failed.')
    } finally {
      setActionPending('')
    }
  }, [authHeaders, planId, token])

  const metricCards = [
    {
      key: 'running',
      label: 'Running',
      value: snapshot.summary.running,
      detail: `${numberFmt(snapshot.summary.agentBacked)} agent-backed`,
      color: GOLD,
      icon: RefreshCcw,
      iconClass: 'animate-spin',
      spark: statSparklines.running,
    },
    {
      key: 'completed',
      label: 'Completed',
      value: snapshot.summary.completed,
      detail: `${snapshot.summary.total ? Math.round((snapshot.summary.completed / snapshot.summary.total) * 100) : 0}% of total`,
      color: GREEN,
      icon: CheckCircle2,
      iconClass: '',
      spark: statSparklines.completed,
    },
    {
      key: 'failed',
      label: 'Failed',
      value: snapshot.summary.failed,
      detail: `${snapshot.summary.total ? Math.round((snapshot.summary.failed / snapshot.summary.total) * 100) : 0}% of total`,
      color: RED,
      icon: XCircle,
      iconClass: '',
      spark: statSparklines.failed,
    },
    {
      key: 'total',
      label: 'Total',
      value: snapshot.summary.total,
      detail: `${numberFmt(snapshot.summary.waitingForAgent)} waiting for agent`,
      color: GOLD,
      icon: Layers3,
      iconClass: '',
      spark: statSparklines.total,
    },
  ] as const

  // Before → After: algorithm transitions recorded on real (non-sandbox) jobs.
  const transitions = useMemo<CryptoTransition[]>(() => {
    const pairs = new Map<string, CryptoTransition>()
    for (const job of snapshot.jobs) {
      if (job.isSandbox) continue
      const from = (job.fromAlgo || '').trim()
      const to = (job.toAlgo || '').trim()
      if (!from || !to) continue
      const key = `${from}->${to}`
      const pair = pairs.get(key) || { from, to, standard: targetStandard(to), jobs: 0, completed: 0 }
      pair.jobs += 1
      if (job.status === 'completed') pair.completed += 1
      pairs.set(key, pair)
    }
    return Array.from(pairs.values()).sort((a, b) => b.jobs - a.jobs).slice(0, 6)
  }, [snapshot.jobs])

  /* ---------------- Four-agent workflow command center ---------------- */

  const model = snapshot.agentWorkflow ?? null

  // Open on the stage that is actually doing something, until the operator picks one.
  useEffect(() => {
    if (!agentChosenRef.current && model?.currentStage) setSelectedAgent(model.currentStage)
  }, [model?.currentStage])

  const selectAgent = useCallback((id: WorkflowAgentId) => {
    agentChosenRef.current = true
    setSelectedAgent(id)
  }, [])

  useEffect(() => {
    if (!requestedAgentId || !requestedCommandId) return
    document.getElementById('agent-workflow')?.scrollIntoView({ block: 'start', behavior: 'auto' })
  }, [requestedAgentId, requestedCommandId])

  const selectedNode = model ? model.nodes.find((node) => node.id === selectedAgent) || model.nodes[0] : null

  // Frames pushed after the snapshot was built are not in it yet; older ones
  // are already persisted in `model.events`, so they are dropped, not doubled.
  const liveEvents = useMemo<WorkflowEvent[]>(() => {
    if (!model) return []
    const roleOf = new Map<string, WorkflowAgentId>()
    for (const node of model.nodes) for (const agent of node.fleet.agents) roleOf.set(agent.id, node.id)
    const cutoff = Date.parse(model.generatedAt)
    return liveFrames
      .filter((frame) => Date.parse(frame.at) > cutoff && frame.name !== 'agent.heartbeat' && frame.agentId && roleOf.has(frame.agentId))
      .map((frame) => {
        const stage = typeof frame.payload.stage === 'string' ? frame.payload.stage : ''
        const message = typeof frame.payload.message === 'string' && frame.payload.message
          ? frame.payload.message
          : stage ? SCAN_STAGE_LABEL[stage] || stage : frame.name.replace('agent.', '').replace(/_/g, ' ')
        const severity: EventSeverity = /error|failed/.test(frame.name) || stage === 'scan_failed' ? 'error' : /completed/.test(frame.name) ? 'success' : 'info'
        return {
          id: `live-${frame.id}`,
          at: frame.at,
          agent: roleOf.get(frame.agentId!)!,
          type: frame.name,
          severity,
          message,
          status: severity === 'error' ? 'failed' : /completed/.test(frame.name) ? 'completed' : /started|progress/.test(frame.name) ? 'running' : null,
          jobId: null,
          agentId: frame.agentId!,
          asset: typeof frame.payload.target === 'string' ? frame.payload.target : null,
          correlationId: `${frame.agentId}:${frame.id}`,
          source: 'heartbeat',
          progress: typeof frame.payload.progress === 'number' ? frame.payload.progress : null,
          detail: frame.payload,
        } satisfies WorkflowEvent
      })
  }, [liveFrames, model])

  const allEvents = useMemo(() => [...liveEvents, ...(model?.events || [])], [liveEvents, model])

  // Per-agent view of the bus frames that arrived after the snapshot: they
  // advance each deployed agent's presence and activity line on the workflow
  // tree immediately; the agent's state follows with the next snapshot.
  const liveByAgent = useMemo<Record<string, AgentLiveActivity>>(() => {
    const out: Record<string, AgentLiveActivity> = {}
    if (!model) return out
    const cutoff = Date.parse(model.generatedAt)
    for (const frame of liveFrames) { // newest first
      if (!frame.agentId || !(Date.parse(frame.at) > cutoff)) continue
      const entry = (out[frame.agentId] ??= { seenAt: null, message: null, messageAt: null, progress: null, severity: null, disconnected: false })
      if (frame.name === 'agent.disconnected') {
        entry.disconnected = true
        continue
      }
      if (LIVENESS_FRAMES.has(frame.name) && !entry.seenAt) entry.seenAt = frame.at
      if (!ACTIVITY_FRAMES.has(frame.name) || entry.messageAt) continue
      const stage = typeof frame.payload.stage === 'string' ? frame.payload.stage : ''
      const error = typeof frame.payload.error === 'string' ? frame.payload.error : ''
      entry.messageAt = frame.at
      entry.message = frame.name === 'agent.error'
        ? error ? `Agent reported: ${error}` : 'Agent reported an error'
        : typeof frame.payload.message === 'string' && frame.payload.message ? frame.payload.message : SCAN_STAGE_LABEL[stage] || stage || 'Scan frame received'
      entry.progress = typeof frame.payload.progress === 'number' && Number.isFinite(frame.payload.progress) ? Math.max(0, Math.min(100, Math.round(frame.payload.progress))) : null
      entry.severity = frame.name === 'agent.error' || stage === 'scan_failed' ? 'error' : frame.name === 'agent.scan_completed' ? 'success' : 'info'
    }
    return out
  }, [liveFrames, model])

  const historical = Boolean(planId) && snapshot.jobs.length > 0 && snapshot.jobs.every((job) => TERMINAL_JOB.has(job.status))
  const connection: ConnectionState = historical
    ? 'historical'
    : streamConnected ? 'live' : snapshotAgeSeconds > 120 ? 'stale' : 'reconnecting'

  const risks = useMemo(() => (model ? deriveRisks(model, snapshot.jobs) : []), [model, snapshot.jobs])
  const checklist = useMemo(() => (model && selectedJob ? safetyChecklist(selectedJob, model) : []), [model, selectedJob])

  const notifications = useMemo<WorkflowNotification[]>(() => {
    if (!model) return []
    const dayAgo = Date.parse(model.generatedAt) - 24 * 60 * 60 * 1000
    const severe = (severity: EventSeverity) => (minSeverity === 'error' ? ['error', 'critical'] : ['warning', 'error', 'critical']).includes(severity)
    const fromEvents: WorkflowNotification[] = allEvents
      .filter((event) => severe(event.severity) && Date.parse(event.at) >= dayAgo)
      .map((event) => ({
        id: event.id,
        title: notificationTitle(event),
        message: event.asset ? `${event.message} · ${event.asset}` : event.message,
        severity: event.severity,
        at: event.at,
        agent: event.agent,
        live: event.id.startsWith('live-'),
        action: { label: event.jobId ? 'Review' : 'Investigate', href: event.jobId ? `#job:${event.jobId}` : `#agent:${event.agent}` },
      }))
    const approvals: WorkflowNotification[] = minSeverity === 'warning'
      ? snapshot.jobs
          .filter((job) => !job.isSandbox && job.approval.required && !job.approval.approved && job.approval.state !== 'rejected' && ['queued', 'paused'].includes(job.status))
          .slice(0, 3)
          .map((job) => ({
            id: `approval-${job.id}`,
            title: 'Migration approval required',
            message: `${job.asset}: ${job.fromAlgo} → ${job.toAlgo}. No agent will change this asset until it is approved.`,
            severity: 'warning' as EventSeverity,
            at: job.updatedAt,
            agent: (job.executionClass === 'remediation' ? 'patcher' : 'operator') as WorkflowAgentId,
            live: false,
            action: { label: 'Review', href: `#job:${job.id}` },
          }))
      : []
    const hidden = new Set(dismissed)
    return [...approvals, ...fromEvents]
      .filter((item) => !hidden.has(item.id))
      .sort((a, b) => Date.parse(b.at) - Date.parse(a.at))
      .slice(0, 6)
  }, [allEvents, dismissed, minSeverity, model, snapshot.jobs])

  const dismissNotification = useCallback((id: string) => {
    setDismissed((current) => {
      const next = [id, ...current].slice(0, 300)
      storeJson('qg.liveMigration.dismissed', next)
      return next
    })
  }, [])

  const changeMinSeverity = useCallback((value: 'warning' | 'error') => {
    setMinSeverity(value)
    storeJson('qg.liveMigration.minSeverity', value)
  }, [])

  const scrollTo = (element: HTMLElement | null) => element?.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' })

  const handleNavigate = useCallback((href: string, agent?: WorkflowAgentId | null) => {
    if (href === '#jobs') return scrollTo(jobsRef.current)
    if (href === '#snapshots') {
      setSnapshotFocusAsset(selectedJob?.asset || null)
      setSnapshotsOpen(true)
      return
    }
    if (href.startsWith('#job:')) {
      setSelectedJobId(href.slice(5))
      return scrollTo(jobsRef.current)
    }
    if (href.startsWith('#agent:')) {
      selectAgent(href.slice(7) as WorkflowAgentId)
      return scrollTo(insightsRef.current)
    }
    if (agent && href === '#') selectAgent(agent)
    if (href.startsWith('/')) navigate(href)
  }, [navigate, selectAgent, selectedJob?.asset])

  const showAgentOutput = useCallback((id: WorkflowAgentId) => {
    selectAgent(id)
    scrollTo(insightsRef.current)
  }, [selectAgent])

  const unfinishedJobIds = snapshot.jobs.filter((job) => !TERMINAL_JOB.has(job.status) && job.status !== 'rolling_back').map((job) => job.id)
  const workflowControls = {
    canPause: snapshot.summary.running + snapshot.summary.queued > 0,
    canResume: snapshot.summary.paused > 0,
    canCancel: unfinishedJobIds.length > 0,
    pending: actionPending,
    pauseReason: 'Nothing is running or queued in this scope. Collector and Scanner schedules are controlled per agent in the Agent Center.',
    onPause: () => void runBulkAction('pause'),
    onResume: () => void runBulkAction('resume'),
    onCancel: () => setConfirm({ mode: 'cancel', ids: unfinishedJobIds, includeCompleted: false }),
  }

  const moreActions = [
    { label: 'Export logs (CSV)', icon: ArrowDownToLine, onClick: () => void downloadExport('csv'), disabled: actionPending.startsWith('export:') },
    { label: 'Export record (JSON)', icon: FileJson, onClick: () => void downloadExport('json'), disabled: actionPending.startsWith('export:') },
    { label: 'Snapshots', icon: Archive, onClick: () => { setSnapshotFocusAsset(null); setSnapshotsOpen(true) } },
    { label: 'Rollback selected job', icon: RotateCcw, tone: 'var(--lw-amber)', onClick: () => { setSnapshotFocusAsset(selectedJob?.asset || null); setSnapshotsOpen(true) }, disabled: !selectedJob },
    { label: 'Retry failed jobs', icon: RefreshCcw, onClick: () => void runBulkAction('retry'), disabled: snapshot.summary.failed === 0 },
    { label: 'Audit trail', icon: ShieldCheck, onClick: () => navigate('/dashboard/audit-vault') },
    { label: 'Agent Center', icon: Server, onClick: () => navigate('/downloads') },
  ]

  return (
    <div id="agent-workflow" className="qg-lw grid min-h-[calc(100vh-64px)] scroll-mt-20 grid-cols-[minmax(0,1fr)] gap-3 overflow-x-hidden p-3 text-white sm:p-4 lg:scroll-mt-5 lg:p-5">
      {requestedAgentId && requestedCommandId ? <ScanRunPanel key={`${requestedAgentId}:${requestedCommandId}`} agentId={requestedAgentId} commandId={requestedCommandId} onRole={selectAgent} /> : null}
      {model ? (
        <>
          <WorkflowHeader
            model={model}
            connection={connection}
            ageLabel={snapshotAgeLabel}
            now={now.getTime()}
            runs={snapshot.runs || []}
            planId={planId}
            onSelectRun={(id) => setSearchParams(id ? { planId: id } : {})}
            controls={workflowControls}
            moreActions={moreActions}
          />

          {snapshot.workflowDegraded && (snapshot.workflowDegraded.heartbeats || snapshot.workflowDegraded.exposures || snapshot.workflowDegraded.inventory) && (
            <div className="flex items-center gap-2 rounded-xl border border-[#fbbf24]/30 bg-[#fbbf24]/[0.07] px-4 py-2 text-[12px] text-white/75" role="status">
              <AlertTriangle className="h-4 w-4 shrink-0 text-[#fbbf24]" />
              Some evidence could not be read this cycle
              ({[snapshot.workflowDegraded.heartbeats && 'agent heartbeats', snapshot.workflowDegraded.exposures && 'exposures', snapshot.workflowDegraded.inventory && 'inventory'].filter(Boolean).join(', ')}).
              Affected values show as Unknown — not zero — until the next snapshot.
            </div>
          )}

          <section className="grid grid-cols-[minmax(0,1fr)] gap-3 2xl:grid-cols-[minmax(0,1fr)_340px]" aria-label="Agent workflow">
            <div className={cn(PANEL, 'p-3 sm:p-4')}>
              <div className="mb-3 flex flex-wrap items-center gap-2 px-1">
                <span className="text-[11px] font-bold uppercase tracking-[0.18em] text-white/45">Collector → Scanner → Patcher → Migration Operator</span>
                <span className="ml-auto text-[10px] text-white/40">
                  {model.simulationsExcluded > 0 ? `${model.simulationsExcluded} sandbox simulation(s) excluded — they never run on an agent · ` : ''}
                  {CONNECTION_META[connection].detail}
                </span>
              </div>
              <p className="mb-3 px-1 text-xs text-white/50">Live fleet · latest collection cycle per agent. Scheduled cycles continue according to each agent’s policy.{requestedCommandId ? ' Your requested scan outcome stays in the receipt above.' : ''}</p>
              <WorkflowCanvas
                model={model}
                now={now.getTime()}
                selectedAgent={selectedNode?.id || 'collector'}
                highlightedAgent={highlightedAgent}
                onSelect={selectAgent}
                onOutput={showAgentOutput}
                liveByAgent={liveByAgent}
                events={allEvents}
              />
            </div>
            <NotificationStack
              items={notifications}
              now={now.getTime()}
              minSeverity={minSeverity}
              onMinSeverity={changeMinSeverity}
              onDismiss={dismissNotification}
              onNavigate={(href, agent) => handleNavigate(href, agent)}
            />
          </section>

          <section className="grid grid-cols-[minmax(0,1fr)] gap-3 xl:grid-cols-2 2xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)_minmax(0,1fr)]">
            <ExecutionTimeline events={allEvents} truncated={model.eventsTruncated} now={now.getTime()} onOpenJob={(id) => handleNavigate(`#job:${id}`)} />
            <div className="grid content-start gap-3">
              {selectedNode && <AgentMetricsPanel node={selectedNode} model={model} latency={latency} />}
              <VulnerabilitySummaryPanel model={model} degraded={Boolean(snapshot.workflowDegraded?.exposures)} />
            </div>
            <div ref={insightsRef} className="xl:col-span-2 2xl:col-span-1">
              {selectedNode && (
                <AgentInsightsPanel node={selectedNode} model={model} now={now.getTime()} onNavigate={(href) => handleNavigate(href)} onSelect={selectAgent} />
              )}
            </div>
          </section>

          <section className="grid grid-cols-[minmax(0,1fr)] gap-3 xl:grid-cols-2 2xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)_minmax(0,1fr)]">
            <div className="xl:col-span-2 2xl:col-span-1">
              <ExecutionLogs
                events={allEvents}
                streamLabel={CONNECTION_META[connection].label}
                streamColor={CONNECTION_META[connection].color}
                onServerExport={(format) => void downloadExport(format)}
                exportPending={actionPending.startsWith('export:')}
              />
            </div>
            <RisksPanel risks={risks} onHover={setHighlightedAgent} onNavigate={(href, agent) => handleNavigate(href, agent)} />
            <SafetyChecklistPanel
              items={checklist}
              jobs={snapshot.jobs.map((job) => ({ id: job.id, asset: job.asset, status: job.status }))}
              selectedJobId={selectedJob?.id || ''}
              onSelectJob={setSelectedJobId}
            />
          </section>
        </>
      ) : (
        <section className={cn(PANEL, 'grid min-h-[320px] place-items-center p-8 text-center')} aria-busy={loading}>
          <div>
            <HistoryIcon className={cn('mx-auto mb-3 h-9 w-9 text-cyan-300/70', loading && 'animate-pulse')} />
            <h1 className="text-xl font-black text-white">PQC Migration Workflow</h1>
            <p className="mt-1 max-w-md text-sm text-white/55">
              {loading
                ? 'Loading the agent workflow from recorded execution evidence…'
                : 'The workflow could not be loaded. The job board below keeps its last confirmed data; the view retries automatically.'}
            </p>
          </div>
        </section>
      )}

      <div className="mt-2 flex items-center gap-3 px-1">
        <Diamond className="h-4 w-4 text-cyan-300" />
        <h2 className="text-sm font-bold uppercase tracking-[0.18em] text-white/70">Migration Jobs &amp; Cutover Control</h2>
        <span className="h-px flex-1 bg-gradient-to-r from-white/15 to-transparent" />
      </div>

      <header className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_300px] xl:items-center">
        <div className={cn(GLASS, 'px-4 py-3')}>
          <div className="relative z-10">
            <div className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.16em] text-white">
              <ShieldCheck className="h-4 w-4 text-[#22d3ee]" />
              {snapshot.summary.complianceMode}
            </div>
            <div className="mt-1 truncate text-[10px] text-white/45">{snapshot.summary.standardLabel}</div>
            <div className="mt-1 truncate text-[10px] text-white/45">
              {numberFmt(snapshot.summary.agentBacked)} agent-backed / {numberFmt(snapshot.summary.waitingForAgent)} waiting
            </div>
            {planId && <div className="mt-1 truncate font-mono text-[10px] text-[#22d3ee]/70">Plan {planId}</div>}
          </div>
        </div>

        <div className="flex items-center justify-end gap-3">
          {/* The live/stale indicator lives in the workflow header above, bound
              to the same stream state, so it is not repeated here. */}
          <div className="text-right font-mono">
            <div className="flex items-center justify-end gap-2 text-xs font-black text-white">
              <Clock3 className="h-4 w-4 text-[#22d3ee]" />
              {now.toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })} UTC
            </div>
            <div className="text-[10px] text-white/45">{now.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })}</div>
          </div>
          <div className={cn(INNER, 'flex items-center gap-2 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee]')}>
            <Zap className="h-3.5 w-3.5" />
            {numberFmt(snapshot.summary.agentBacked)} Agent Backed
          </div>
        </div>
      </header>

      {/*
       * Migration Planner handoff. Rendered when this page was opened via
       * "Send to Live Migration" — the asset(s), their reviewed plan, rollback
       * configuration and approvals arrive with the plan, so the operator can
       * execute without re-selecting anything.
       */}
      {snapshot.plannerHandoff?.assets?.length ? (
        <section className={cn(GLASS, 'p-4')}>
          <div className="relative z-10">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.16em] text-[#22d3ee]">
                <Rocket className="h-4 w-4" />
                Received from Migration Planner
                <span className="font-mono text-[10px] normal-case tracking-normal text-white/40">
                  {snapshot.plannerHandoff.assets.length} asset(s)
                  {snapshot.plannerHandoff.stampedAt ? ` · ${new Date(snapshot.plannerHandoff.stampedAt).toLocaleString()}` : ''}
                </span>
              </div>
              <Link to="/dashboard/migration-planner" className="text-[10px] font-black uppercase tracking-wider text-white/50 transition hover:text-[#22d3ee]">
                Back to planner
              </Link>
            </div>
            <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              {snapshot.plannerHandoff.assets.slice(0, 6).map((asset) => (
                <div key={asset.assetId} className={cn(INNER, 'p-3')}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-xs font-bold text-white">{asset.name}</span>
                    <span className="shrink-0 rounded bg-white/8 px-1.5 py-0.5 text-[9px] font-black uppercase text-white/65">{asset.priority || '—'}</span>
                  </div>
                  <div className="mt-0.5 truncate text-[10px] text-white/45">
                    {asset.type || 'asset'}{asset.environment ? ` · ${asset.environment}` : ''}{asset.owner ? ` · ${asset.owner}` : ''}
                  </div>
                  <div className="mt-1.5 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[10px] text-white/45">
                    <span>Readiness <span className="font-mono text-white/75">{Math.round(asset.readinessScore ?? 0)}</span></span>
                    <span>Risk <span className="font-mono text-white/75">{Math.round(asset.riskScore ?? 0)}</span></span>
                    <span>Success <span className="font-mono text-[#34d399]">{Math.round(asset.successProbabilityPct ?? 0)}%</span></span>
                    <span>Deps <span className="font-mono text-white/75">{asset.dependencies?.length ?? 0}</span></span>
                    <span className="col-span-2 truncate">Downtime <span className="text-white/70">{asset.estimatedDowntime || '—'}</span></span>
                    <span className="col-span-2 truncate">Rollback <span className="text-white/70">{asset.rollbackStrategy?.strategy || '—'}</span></span>
                    <span className="col-span-2 truncate">
                      Approvals <span className="text-white/70">{(asset.requiredApprovals || []).filter((approval) => approval.required).map((approval) => approval.role).join(', ') || '—'}</span>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      ) : null}

      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {metricCards.map((metric) => {
          const Icon = metric.icon
          return (
            <motion.div
              key={metric.key}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              className={cn(GLASS, 'min-h-[104px] p-4')}
            >
              <div className="relative z-10 flex items-center gap-4">
                <div className={cn('grid h-12 w-12 place-items-center rounded-full border-2 bg-black/25', metric.key === 'total' ? 'border-[#22d3ee]' : '')} style={{ borderColor: metric.color }}>
                  <Icon className={cn('h-7 w-7', metric.iconClass)} style={{ color: metric.color }} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-[10px] font-black uppercase tracking-wider" style={{ color: metric.color }}>{metric.label}</div>
                  <div className="mt-1 flex items-end gap-2">
                    <span className="font-mono text-3xl font-black leading-none text-white">{numberFmt(metric.value)}</span>
                    <span className="pb-1 text-xs font-bold text-white/55">Jobs</span>
                  </div>
                  <div className="mt-1 text-[11px] text-white/45">{metric.detail}</div>
                </div>
                <Sparkline values={metric.spark} color={metric.color} />
              </div>
            </motion.div>
          )
        })}
      </section>

      <section className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(360px,0.82fr)]">
        <div className={cn(GLASS, 'flex min-h-[236px] flex-col p-4')}>
          <div className="relative z-10 mb-3 flex items-center justify-between gap-3">
            <h3 className="text-[11px] font-black uppercase tracking-[0.18em] text-[#22d3ee]">Real-Time Telemetry</h3>
            {/* Tone follows the server's health verdict; "Degraded" means failed jobs exist. */}
            <span
              className={cn(
                'rounded-full border px-3 py-1 text-[9px] font-black uppercase tracking-wider',
                snapshot.telemetry.systemHealth === 'Degraded'
                  ? 'border-[#f87171]/25 bg-[#f87171]/10 text-[#f87171]'
                  : snapshot.telemetry.systemHealth === 'Awaiting Agent'
                    ? 'border-[#fbbf24]/25 bg-[#fbbf24]/10 text-[#fbbf24]'
                    : snapshot.telemetry.systemHealth === 'No active migrations'
                      ? 'border-white/15 bg-white/[0.04] text-white/50'
                      : 'border-[#34d399]/25 bg-[#34d399]/10 text-[#34d399]',
              )}
            >
              {snapshot.telemetry.systemHealth}
            </span>
          </div>
          <div className="relative z-10 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
            {[
              /* Operations that happened: completed with a passing validation,
                 one per job, classified by recorded job type. */
              ['TLS Upgrades Validated', snapshot.telemetry.tlsHandshakeEvents],
              ['Certificates Replaced', snapshot.telemetry.certificateReplacements],
              ['Keys Rotated', snapshot.telemetry.keyRotations],
              ['Validations Recorded', snapshot.telemetry.pqcValidationEvents],
              ['Compatibility Checks', snapshot.telemetry.compatibilityChecks],
            ].map(([label, value]) => (
              <div key={String(label)} className={cn(INNER, 'min-h-[76px] px-3 py-2.5')}>
                <div className="font-mono text-2xl font-black text-white">{numberFmt(Number(value))}</div>
                <div className="mt-1 text-[8px] font-black uppercase tracking-wider text-white/35">{label}</div>
              </div>
            ))}
          </div>
          <div className="relative z-10 mt-auto flex justify-end pt-12">
            <Link
              to="/dashboard/agents"
              className="inline-flex h-9 items-center gap-2 rounded-md border border-[#22d3ee]/45 bg-[#22d3ee]/10 px-3 text-[10px] font-black uppercase tracking-[0.12em] text-[#22d3ee] transition hover:border-[#22d3ee]/75 hover:bg-[#22d3ee]/15 hover:text-[#ffe7a3]"
            >
              <Server className="h-3.5 w-3.5" />
              <span>Next Step: setup an Agent</span>
            </Link>
          </div>
        </div>

        <div className={cn(GLASS, 'p-4')}>
          <h3 className="relative z-10 mb-3 text-[11px] font-black uppercase tracking-[0.18em] text-[#22d3ee]">Activity Feed</h3>
          <div className="relative z-10 grid grid-cols-2 gap-2">
            {[
              ['Migration Logs', snapshot.telemetry.activityFeed.migrationLogs],
              ['Validation Logs', snapshot.telemetry.activityFeed.validationLogs],
              ['Error Logs', snapshot.telemetry.activityFeed.errorLogs],
              ['Audit Logs', snapshot.telemetry.activityFeed.auditLogs],
              ['Compliance Logs', snapshot.telemetry.activityFeed.complianceLogs],
            ].map(([label, value]) => (
              <div key={String(label)} className={cn(INNER, 'px-3 py-2')}>
                <div className="text-[8px] font-black uppercase tracking-wider text-white/35">{label}</div>
                <div className="mt-1 font-mono text-lg font-black text-white">{numberFmt(Number(value))}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <CryptoUpgradePanel transitions={transitions} loading={loading} />

      <section ref={jobsRef} id="jobs" className="grid scroll-mt-4 grid-cols-[minmax(0,1fr)] gap-3 xl:grid-cols-[440px_minmax(0,1fr)]">
        <div className={cn(GLASS, 'overflow-hidden')}>
          <div className="relative z-10 border-b border-[#22d3ee]/10 px-4 py-3">
            <div className="flex items-center justify-between">
              <h2 className="text-[11px] font-black uppercase tracking-[0.18em] text-[#22d3ee]">Migration Jobs</h2>
              <span className="text-[10px] text-white/35">Last scan {formatShortDate(snapshot.summary.lastScanAt)}</span>
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {[
                ['all', 'All', snapshot.summary.total],
                ['running', 'Running', snapshot.summary.running],
                ['completed', 'Completed', snapshot.summary.completed],
                ['failed', 'Failed', snapshot.summary.failed],
                ['queued', 'Queued', snapshot.summary.queued],
                ['paused', 'Paused', snapshot.summary.paused],
                ['rolling_back', 'Rolling Back', snapshot.summary.rollingBack],
                ['rolled_back', 'Rolled Back', snapshot.summary.rolledBack],
                ['cancelled', 'Cancelled', snapshot.summary.cancelled],
              ].map(([key, label, count]) => (
                <button
                  key={String(key)}
                  type="button"
                  onClick={() => setFilter(key as 'all' | LiveMigrationStatus)}
                  className={cn(
                    'rounded-full border px-2.5 py-1 text-[10px] font-bold transition',
                    filter === key
                      ? 'border-[#22d3ee]/55 bg-[#22d3ee]/12 text-[#22d3ee]'
                      : 'border-white/10 bg-white/[0.025] text-white/45 hover:border-[#22d3ee]/30 hover:text-white/70',
                  )}
                >
                  {label} <span className="ml-1 text-[#22d3ee]">{count}</span>
                </button>
              ))}
            </div>
          </div>

          {/*
            Queue curation toolbar. Cancel withdraws a job but keeps it on the
            record; Remove deletes it. Both are confirmed before running, and the
            server independently enforces what may be cancelled or removed.
          */}
          <div className="relative z-10 flex flex-wrap items-center gap-2 border-b border-[#22d3ee]/10 px-3 py-2">
            <label className="inline-flex cursor-pointer items-center gap-2 text-[10px] font-black uppercase tracking-wider text-white/50 transition hover:text-white/80">
              <input
                type="checkbox"
                checked={allFilteredSelected}
                onChange={toggleAllFiltered}
                disabled={filteredJobs.length === 0}
                aria-label="Select all listed migration jobs"
                className="h-3.5 w-3.5 cursor-pointer accent-[#22d3ee]"
              />
              {allFilteredSelected ? 'Clear' : 'Select all'}
            </label>
            <span className="text-[10px] font-bold text-white/35">
              {selectedIds.length ? `${numberFmt(selectedIds.length)} selected` : `${numberFmt(filteredJobs.length)} listed`}
            </span>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={!selectedIds.length || actionPending.startsWith('bulk:') || actionPending.startsWith('remove:')}
                onClick={() => setConfirm({ mode: 'cancel', ids: selectedIds, includeCompleted: false })}
                className="inline-flex items-center gap-1.5 rounded-md border border-white/12 bg-white/[0.03] px-2.5 py-1.5 text-[10px] font-black uppercase tracking-wider text-white/60 transition hover:border-[#22d3ee]/45 hover:text-[#22d3ee] disabled:cursor-not-allowed disabled:opacity-35"
              >
                <Ban className="h-3 w-3" />
                Cancel
              </button>
              <button
                type="button"
                disabled={!selectedIds.length || actionPending.startsWith('remove:')}
                onClick={() => setConfirm({ mode: 'remove', ids: selectedIds, includeCompleted: false })}
                className="inline-flex items-center gap-1.5 rounded-md border border-[#f87171]/35 bg-[#f87171]/10 px-2.5 py-1.5 text-[10px] font-black uppercase tracking-wider text-[#f87171] transition hover:border-[#f87171]/70 hover:bg-[#f87171]/18 disabled:cursor-not-allowed disabled:opacity-35"
              >
                <Trash2 className="h-3 w-3" />
                Remove
              </button>
            </div>
          </div>

          <div className="relative z-10 max-h-[438px] space-y-2 overflow-y-auto p-3">
            {loading && (
              <div className="grid h-48 place-items-center text-[11px] font-black uppercase tracking-[0.22em] text-white/35">
                Syncing migration telemetry
              </div>
            )}
            {!loading && filteredJobs.length === 0 && (
              <div className={cn(INNER, 'grid min-h-48 place-items-center px-6 text-center')}>
                <div>
                  <Server className="mx-auto mb-3 h-8 w-8 text-[#22d3ee]/65" />
                  <div className="text-sm font-bold text-white">No migration jobs found</div>
                  <div className="mt-1 text-xs text-white/45">Run an authenticated migration plan to populate this live operations view.</div>
                </div>
              </div>
            )}
            {filteredJobs.map((job, index) => {
              const config = statusConfig(job.status)
              const StatusIcon = config.icon
              const selected = selectedJob?.id === job.id
              const ticked = selectedSet.has(job.id)
              return (
                // A row is a container, not a <button>: the checkbox and the
                // per-row remove control are themselves interactive, and nesting
                // buttons inside a button is invalid.
                <motion.div
                  key={job.id}
                  role="button"
                  tabIndex={0}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.025 }}
                  onClick={() => setSelectedJobId(job.id)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault()
                      setSelectedJobId(job.id)
                    }
                  }}
                  className={cn(
                    'group relative w-full cursor-pointer overflow-hidden rounded-lg border p-3 text-left transition focus:outline-none focus-visible:ring-2 focus-visible:ring-[#22d3ee]/60',
                    selected
                      ? 'border-[#22d3ee]/70 bg-[#22d3ee]/10 shadow-[0_0_28px_rgba(212,175,55,0.24)]'
                      : ticked
                        ? 'border-[#22d3ee]/40 bg-[#22d3ee]/[0.06]'
                        : 'border-white/10 bg-white/[0.035] hover:border-[#22d3ee]/35 hover:bg-[#22d3ee]/6',
                  )}
                >
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={ticked}
                      onClick={(event) => event.stopPropagation()}
                      onChange={() => toggleJobSelection(job.id)}
                      aria-label={`Select migration job for ${job.asset}`}
                      className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[#22d3ee]"
                    />
                    <div className={cn('grid h-8 w-8 shrink-0 place-items-center rounded-full border-2 bg-black/25', config.ring)}>
                      <StatusIcon className={cn('h-5 w-5', config.color, job.status === 'running' && 'animate-spin')} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-3">
                        <span className="truncate text-sm font-black text-white">{job.asset}</span>
                        <span className={cn('text-[10px] font-black uppercase', config.color)}>{config.label}</span>
                      </div>
                      <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5 text-[10px] text-white/42">
                        <span className="truncate">{job.fromAlgo}</span>
                        <ArrowRight className="h-3 w-3 shrink-0 text-[#22d3ee]/55" />
                        <span className="truncate text-[#22d3ee]/80">{job.toAlgo}</span>
                        <span className={cn('rounded border px-1.5 py-0.5 text-[8px] font-black uppercase',
                          job.isSandbox ? 'border-[#a78bfa]/30 text-[#a78bfa]' : job.executionBacked ? 'border-[#34d399]/30 text-[#34d399]' : 'border-[#22d3ee]/24 text-[#22d3ee]/70')}>
                          {job.isSandbox ? (job.runMode === 'dry_run' ? 'Dry Run' : 'Sandbox') : job.executionBacked ? 'Agent' : 'Waiting'}
                        </span>
                      </div>
                      <div className="mt-2 grid grid-cols-[1fr_auto] items-center gap-3">
                        <div className="h-1.5 overflow-hidden rounded-full bg-white/10">
                          <div className={cn('h-full rounded-full bg-gradient-to-r', config.bar)} style={{ width: `${job.progress}%` }} />
                        </div>
                        <span className="text-[10px] text-white/45">{job.status === 'completed' ? formatShortDate(job.completedAt) : job.eta}</span>
                      </div>
                    </div>
                    {/* Per-row removal for the common case: one job queued by mistake. */}
                    <button
                      type="button"
                      aria-label={`Remove migration job for ${job.asset}`}
                      title={job.status === 'running' ? 'Pause or cancel a running job before removing it' : 'Remove from the migration queue'}
                      disabled={job.status === 'running' || actionPending.startsWith('remove:')}
                      onClick={(event) => {
                        event.stopPropagation()
                        setConfirm({ mode: 'remove', ids: [job.id], includeCompleted: job.status === 'completed' })
                      }}
                      className="shrink-0 self-start rounded-md border border-white/10 p-1.5 text-white/35 opacity-0 transition hover:border-[#f87171]/60 hover:text-[#f87171] focus:opacity-100 focus-visible:ring-2 focus-visible:ring-[#f87171]/50 disabled:cursor-not-allowed disabled:opacity-0 group-hover:opacity-100"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </motion.div>
              )
            })}
          </div>
          <div className="relative z-10 border-t border-[#22d3ee]/10 p-3 text-center">
            <a href="/dashboard/migration-timeline" className="inline-flex items-center gap-2 rounded-md border border-[#22d3ee]/15 bg-[#22d3ee]/5 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/50">
              <ListChecks className="h-3.5 w-3.5" />
              View All Jobs
            </a>
          </div>
        </div>

        <div className="space-y-3">
          <div className={cn(GLASS, 'p-4')}>
            {selectedJob ? (
              <>
                <div className="relative z-10 flex flex-col gap-3 border-b border-[#22d3ee]/10 pb-3 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0">
                    <h2 className="truncate text-xl font-black text-white">{selectedJob.asset}</h2>
                    <div className="mt-1 flex min-w-0 items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-[#22d3ee]">
                      <span className="truncate">{selectedJob.fromAlgo}</span>
                      <ArrowRight className="h-3 w-3 shrink-0" />
                      <span className="truncate">{selectedJob.toAlgo}</span>
                    </div>
                  </div>
                  {/*
                    A queued job that no agent may claim is not a slow queue —
                    it is a role boundary or a missing snapshot, and the operator
                    can only act on it if they are told which.
                  */}
                  {/*
                    Approval, stated from the same verdict the agent poll
                    enforces. An unapproved job is not "queued and slow" — no
                    agent will take it until a named person approves it.
                  */}
                  {selectedJob.approval.required && !selectedJob.approval.approved && ['queued', 'paused', 'failed'].includes(selectedJob.status) && (
                    <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[#fbbf24]/35 bg-[#fbbf24]/[0.08] px-3 py-2 text-[11px] leading-relaxed text-white/80">
                      <div className="min-w-0 flex-1">
                        <span className="font-black uppercase tracking-wider text-[#fbbf24]">
                          {selectedJob.approval.state === 'rejected' ? 'Rejected' : 'Awaiting approval'}
                        </span>
                        <span className="ml-2">
                          {selectedJob.approval.source === 'plan'
                            ? 'Approval for this job is recorded on its migration plan. No agent will change this asset until the plan is approved.'
                            : 'No agent will change this asset until this remediation job is approved.'}
                        </span>
                      </div>
                      {selectedJob.approval.source === 'job' && selectedJob.approval.state !== 'rejected' ? (
                        <button
                          type="button"
                          disabled={actionPending === `${selectedJob.id}:approve`}
                          onClick={() => setConfirm({ mode: 'approve', ids: [selectedJob.id], includeCompleted: false })}
                          className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-[#34d399]/45 bg-[#34d399]/12 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-[#34d399] transition hover:bg-[#34d399]/20 disabled:opacity-50"
                        >
                          <BadgeCheck className="h-3.5 w-3.5" />
                          Approve &amp; queue
                        </button>
                      ) : selectedJob.approval.source === 'plan' ? (
                        <a
                          href="/dashboard/migration-planner"
                          className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-[#22d3ee]/35 bg-[#22d3ee]/10 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:bg-[#22d3ee]/18"
                        >
                          Review plan approval
                        </a>
                      ) : null}
                    </div>
                  )}
                  {selectedJob.approval.required && selectedJob.approval.approved && (
                    <div className="flex items-center gap-1.5 text-[10px] text-white/50">
                      <BadgeCheck className="h-3.5 w-3.5 text-[#34d399]" />
                      Approved by <span className="font-bold text-white/75">{selectedJob.approval.approvedBy || 'unknown'}</span>
                      {selectedJob.approval.approvedAt ? <span>· {formatShortDate(selectedJob.approval.approvedAt)}</span> : null}
                      <span className="text-white/35">· {selectedJob.approval.source === 'plan' ? 'via migration plan' : 'job-level approval'}</span>
                    </div>
                  )}
                  {!selectedJob.approval.required && (
                    <div className="text-[10px] text-white/45">
                      Sandbox simulation — executed by the sandbox engine against a digital twin. Never dispatched to an agent.
                    </div>
                  )}
                  {/*
                    A queued job that no agent may claim is not a slow queue — it
                    is a role boundary, a missing approval or a missing snapshot,
                    and the operator can only act on it if told which.
                  */}
                  {selectedJob.dispatchBlock && (
                    <div className="rounded-lg border border-[#fbbf24]/30 bg-[#fbbf24]/[0.07] px-3 py-2 text-[11px] leading-relaxed text-white/75">
                      <span className="font-black uppercase tracking-wider text-[#fbbf24]">
                        {selectedJob.dispatchBlock.kind === 'agent-role'
                          ? 'Not dispatched — agent type'
                          : selectedJob.dispatchBlock.kind === 'not-approved'
                            ? 'Not dispatched — approval'
                            : selectedJob.dispatchBlock.kind === 'out-of-scope'
                              ? 'Not dispatched — outside agent scope'
                            : selectedJob.dispatchBlock.kind === 'no-snapshot'
                              ? 'Not dispatched — no snapshot'
                              : 'Not dispatched'}
                      </span>
                      <span className="ml-2">{selectedJob.dispatchBlock.reason}</span>
                    </div>
                  )}
                  <div className="flex flex-wrap gap-2">
                    {selectedJob.status === 'running' && (
                      <button
                        type="button"
                        disabled={actionPending === `${selectedJob.id}:pause`}
                        onClick={() => runJobAction(selectedJob.id, 'pause')}
                        className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/45 bg-[#22d3ee]/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:bg-[#22d3ee]/18 disabled:opacity-50"
                      >
                        <Pause className="h-3.5 w-3.5" />
                        Pause
                      </button>
                    )}
                    {(selectedJob.status === 'paused' || selectedJob.status === 'queued') && (!selectedJob.approval.required || selectedJob.approval.approved) && (
                      <button
                        type="button"
                        disabled={actionPending === `${selectedJob.id}:resume`}
                        onClick={() => runJobAction(selectedJob.id, 'resume')}
                        className="inline-flex items-center gap-2 rounded-lg border border-[#34d399]/35 bg-[#34d399]/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#34d399] transition hover:bg-[#34d399]/18 disabled:opacity-50"
                      >
                        <Play className="h-3.5 w-3.5" />
                        Resume
                      </button>
                    )}
                    {selectedJob.status === 'failed' && (!selectedJob.approval.required || selectedJob.approval.approved) && (
                      <button
                        type="button"
                        disabled={actionPending === `${selectedJob.id}:retry`}
                        onClick={() => runJobAction(selectedJob.id, 'retry')}
                        className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/45 bg-[#22d3ee]/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:bg-[#22d3ee]/18 disabled:opacity-50"
                      >
                        <RefreshCcw className="h-3.5 w-3.5" />
                        Retry
                      </button>
                    )}
                    {/*
                       Rollback goes through Migration Snapshot Management: it
                       resolves the executor that holds the recorded undo
                       information and reports what actually happened. Offered on
                       jobs that have executed something — a queued job has
                       nothing to undo.
                    */}
                    {(selectedJob.status === 'completed' || selectedJob.status === 'failed' || selectedJob.status === 'paused') && (
                      <button
                        type="button"
                        disabled={actionPending === `${selectedJob.id}:rollback`}
                        title="Restore this asset from its pre-change snapshot"
                        onClick={() => setConfirm({ mode: 'rollback', ids: [selectedJob.id], includeCompleted: false })}
                        className="inline-flex items-center gap-2 rounded-lg border border-[#fbbf24]/45 bg-[#fbbf24]/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#fbbf24] transition hover:bg-[#fbbf24]/18 disabled:opacity-50"
                      >
                        <RotateCcw className="h-3.5 w-3.5" />
                        Rollback
                      </button>
                    )}
                    {/* Cancel withdraws this job from execution but keeps it on
                        the record; Remove deletes it from the queue entirely. */}
                    {selectedJob.status !== 'completed' && selectedJob.status !== 'cancelled' && (
                      <button
                        type="button"
                        disabled={actionPending === `${selectedJob.id}:cancel`}
                        onClick={() => setConfirm({ mode: 'cancel', ids: [selectedJob.id], includeCompleted: false })}
                        className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-white/[0.04] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/60 transition hover:border-white/35 hover:text-white disabled:opacity-50"
                      >
                        <Ban className="h-3.5 w-3.5" />
                        Cancel
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={selectedJob.status === 'running' || actionPending.startsWith('remove:')}
                      title={selectedJob.status === 'running' ? 'Pause or cancel a running job before removing it' : 'Remove from the migration queue'}
                      onClick={() => setConfirm({ mode: 'remove', ids: [selectedJob.id], includeCompleted: selectedJob.status === 'completed' })}
                      className="inline-flex items-center gap-2 rounded-lg border border-[#f87171]/40 bg-[#f87171]/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#f87171] transition hover:border-[#f87171]/70 hover:bg-[#f87171]/18 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      Remove
                    </button>
                    <button
                      type="button"
                      className="rounded-lg border border-white/10 bg-white/[0.04] p-2 text-white/45 transition hover:border-[#22d3ee]/30 hover:text-[#22d3ee]"
                      title="Migration options"
                    >
                      <MoreVertical className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                <div className="relative z-10 mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
                  {[
                    { label: 'Progress', value: `${selectedJob.progress}%`, color: '#22d3ee', icon: RefreshCcw },
                    { label: 'Execution', value: selectedJob.executionBacked ? selectedJob.executionStatus : 'Waiting', color: selectedJob.executionBacked ? '#34d399' : '#22d3ee', icon: Radio },
                    { label: 'Agent', value: selectedJob.agentName || 'Unassigned', color: '#ffffff', icon: Server },
                    { label: 'Telemetry', value: numberFmt(selectedJob.telemetryCount), color: '#22d3ee', icon: Activity },
                    { label: 'Validation', value: selectedJob.validationStatus, color: /pass|success|valid/.test(selectedJob.validationStatus) ? '#34d399' : '#ffffff', icon: ShieldCheck },
                  ].map((tile) => {
                    const Icon = tile.icon
                    return (
                      <div key={tile.label} className={cn(INNER, 'min-h-[68px] px-3 py-2.5')}>
                        <div className="flex items-center gap-2">
                          <Icon className="h-4 w-4" style={{ color: tile.color }} />
                          <div className="truncate text-lg font-black leading-none" style={{ color: tile.color }}>{tile.value}</div>
                        </div>
                        <div className="mt-1 text-[8px] font-black uppercase tracking-wider text-white/35">{tile.label}</div>
                      </div>
                    )
                  })}
                </div>

                <PhaseRail job={selectedJob} />

                <div className="relative z-10 grid gap-2 md:grid-cols-5">
                  {[
                    ['Target Algorithm', selectedJob.toAlgo],
                    ['Migration Type', selectedJob.migrationType],
                    ['Strategy', String(selectedJobConfig.deploymentStrategy || selectedJobExecution.strategy || 'Staged Rollout')],
                    ['Phase', `${Number(selectedJobExecution.phaseIndex || 1)}/${Number(selectedJobExecution.totalPhases || 1)}`],
                    ['Controls', `${selectedJobEnabledControls || 0} enabled`],
                    ['Agent Status', selectedJob.agentStatus || 'unassigned'],
                    ['Current Step', selectedJob.currentStep],
                    ['Validation Logs', numberFmt(selectedJob.validationCount)],
                    ['Started', formatTime(selectedJob.startedAt)],
                    ['Asset Type', selectedJob.assetType],
                    ['Owner', selectedJob.owner],
                  ].map(([label, value]) => (
                    <div key={label} className={cn(INNER, 'px-3 py-2.5')}>
                      <div className="text-[8px] font-black uppercase tracking-wider text-[#22d3ee]/75">{label}</div>
                      <div className="mt-1 truncate text-xs font-bold text-white">{value}</div>
                    </div>
                  ))}
                  <div className={cn(INNER, 'px-3 py-2.5')}>
                    <div className="text-[8px] font-black uppercase tracking-wider text-[#22d3ee]/75">Criticality</div>
                    <div className="mt-2"><SeverityDots criticality={selectedJob.criticality} /></div>
                  </div>
                </div>

                <div className="relative z-10 mt-3 grid gap-2 lg:grid-cols-2">
                  <div className={cn(INNER, 'p-3')}>
                    <div className="flex flex-wrap items-center gap-2">
                      <FileText className="h-4 w-4 text-[#22d3ee]" />
                      <div className="text-[10px] font-black uppercase tracking-[0.16em] text-white">Local Config Ownership</div>
                      <span className={cn(
                        'ml-auto rounded-full border px-2 py-1 text-[8px] font-black uppercase tracking-wider',
                        selectedConfigPath ? 'border-[#34d399]/35 bg-[#34d399]/10 text-[#34d399]' : 'border-[#22d3ee]/35 bg-[#22d3ee]/10 text-[#22d3ee]',
                      )}>
                        {selectedConfigPath ? 'Path Attached' : 'Path Needed'}
                      </span>
                    </div>
                    <p className="mt-2 text-[11px] font-semibold leading-relaxed text-white/58">
                      The agent owns the path only when it runs on the asset or has a mounted config path, that path is listed in the agent policy allowedPaths, and the migration job carries the same filePath/configPath.
                    </p>
                    <div className="mt-3 space-y-2 text-[10px] font-bold text-white/55">
                      <div className="flex gap-2">
                        <span className="w-16 shrink-0 uppercase tracking-wider text-[#22d3ee]/75">Path</span>
                        <span className="min-w-0 truncate text-white/75">{selectedConfigPath || 'Attach filePath/configPath through the agent or operator patch action.'}</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="w-16 shrink-0 uppercase tracking-wider text-[#22d3ee]/75">Next</span>
                        <span className="text-white/75">Enroll the collector on the host, add allowedPaths, then enable remediation/config patching after approval.</span>
                      </div>
                    </div>
                    <Link to="/dashboard/agents" className="mt-3 inline-flex items-center gap-2 rounded-md border border-[#22d3ee]/25 bg-[#22d3ee]/8 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/55">
                      <Server className="h-3.5 w-3.5" />
                      Open Agent Setup
                    </Link>
                  </div>

                  <div className={cn(INNER, 'p-3')}>
                    <div className="flex flex-wrap items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-[#22d3ee]" />
                      <div className="text-[10px] font-black uppercase tracking-[0.16em] text-white">Connector / Operator Credentials</div>
                      <span className={cn(
                        'ml-auto rounded-full border px-2 py-1 text-[8px] font-black uppercase tracking-wider',
                        selectedNeedsConnector ? 'border-[#22d3ee]/35 bg-[#22d3ee]/10 text-[#22d3ee]' : 'border-white/15 bg-white/[0.04] text-white/45',
                      )}>
                        {selectedNeedsConnector ? (selectedConnector ? 'Connector Attached' : 'Connector Required') : 'If Required'}
                      </span>
                    </div>
                    <p className="mt-2 text-[11px] font-semibold leading-relaxed text-white/58">
                      This migration card does not collect provider secrets. Cloud, Kubernetes, identity, KMS, CDN, load balancer, and certificate automation changes must be connected through a tenant-scoped connector or approved operator patch action.
                    </p>
                    <div className="mt-3 space-y-2 text-[10px] font-bold text-white/55">
                      <div className="flex gap-2">
                        <span className="w-20 shrink-0 uppercase tracking-wider text-[#22d3ee]/75">Connector</span>
                        <span className="min-w-0 truncate text-white/75">{selectedConnector || 'Register provider, scopes, allowed targets, and approval owner.'}</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="w-20 shrink-0 uppercase tracking-wider text-[#22d3ee]/75">Next</span>
                        <span className="text-white/75">Create the operator patch action, approve it, apply with the owning platform, then resume validation here.</span>
                      </div>
                    </div>
                    <Link to="/dashboard/agents" className="mt-3 inline-flex items-center gap-2 rounded-md border border-[#22d3ee]/25 bg-[#22d3ee]/8 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/55">
                      <ListChecks className="h-3.5 w-3.5" />
                      Open Connector Patchers
                    </Link>
                  </div>
                </div>
              </>
            ) : (
              <div className="relative z-10 grid min-h-[260px] place-items-center text-center">
                <div>
                  <Radio className="mx-auto mb-3 h-10 w-10 text-[#22d3ee]/65" />
                  <div className="text-lg font-black text-white">No live migration selected</div>
                  <div className="mt-1 text-sm text-white/45">Authenticated migration jobs will appear here as soon as they are created.</div>
                </div>
              </div>
            )}
          </div>

          <div className={cn(GLASS, 'overflow-hidden')}>
            <div className="relative z-10 flex flex-wrap items-center gap-3 border-b border-[#22d3ee]/10 px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                <Terminal className="h-4 w-4 text-[#22d3ee]" />
                <h3 className="truncate text-[11px] font-black uppercase tracking-[0.18em] text-[#22d3ee]">
                  Migration Log {selectedJob ? `- ${selectedJob.asset}` : ''}
                </h3>
              </div>
              <div className="ml-auto flex items-center gap-3">
                {/* Bound to the stream, like the header indicator — a dropped
                    stream must not keep a green "Live" dot on the log. */}
                <span className="flex items-center gap-2 text-[10px] text-white/65">
                  <span className={cn('h-2 w-2 rounded-full', streamConnected ? 'bg-[#34d399]' : snapshotAgeSeconds > 120 ? 'bg-[#f87171]' : 'bg-[#fbbf24]')} />
                  {streamConnected ? 'Live' : snapshotAgeSeconds > 120 ? 'Stale' : 'Reconnecting'}
                </span>
                <button type="button" title="Filter logs" className="text-white/35 transition hover:text-[#22d3ee]"><Filter className="h-4 w-4" /></button>
                <button type="button" title="Export logs" onClick={() => downloadExport('csv')} className="text-white/35 transition hover:text-[#22d3ee]"><Download className="h-4 w-4" /></button>
                <button type="button" title="Expand log panel" className="text-white/35 transition hover:text-[#22d3ee]"><Maximize2 className="h-4 w-4" /></button>
              </div>
            </div>

            <div className="relative z-10 min-h-[188px] max-h-[240px] overflow-y-auto bg-black/20 p-4 font-mono text-xs">
              {selectedJob?.logs?.length ? (
                <div className="space-y-1.5">
                  {selectedJob.logs.map((log) => {
                    const severity = log.severity?.toLowerCase()
                    return (
                      <div
                        key={log.id}
                        className={cn(
                          'leading-relaxed',
                          (severity === 'error' || severity === 'critical') && 'font-bold text-[#f87171]',
                          severity === 'warning' && 'font-bold text-[#22d3ee]',
                          (severity === 'success' || log.message.toUpperCase().includes('PASS')) && 'font-bold text-[#34d399]',
                          !['error', 'critical', 'warning', 'success'].includes(severity) && !log.message.toUpperCase().includes('PASS') && 'text-white/55',
                        )}
                      >
                        <span className="text-white/38">[{formatTime(log.createdAt)}]</span> {log.message}
                      </div>
                    )
                  })}
                  {selectedJob.status === 'running' && <div className="animate-pulse text-[#22d3ee]">█</div>}
                </div>
              ) : (
                <div className="grid h-[150px] place-items-center text-center text-white/36">
                  <div>
                    <Terminal className="mx-auto mb-2 h-7 w-7 text-[#22d3ee]/55" />
                    <div className="font-bold">No migration events recorded for this job.</div>
                    <div className="mt-1 text-[11px]">Awaiting authenticated agent telemetry.</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Snapshot Management — pre-migration backups + safe rollback */}
      <SnapshotManager
        enabled={Boolean(token)}
        open={snapshotsOpen}
        onOpenChange={(v) => { setSnapshotsOpen(v); if (!v) setSnapshotFocusAsset(null) }}
        focusAssetName={snapshotFocusAsset}
      />

      <section className="sticky bottom-0 z-20 -mx-3 border-t border-[#22d3ee]/10 bg-[#0b1120]/88 px-3 py-3 backdrop-blur-xl sm:-mx-4 sm:px-4 lg:-mx-5 lg:px-5">
        <div className="flex flex-wrap items-center gap-2">
          <a href="/dashboard/migration-planner" className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/30 bg-[#22d3ee]/8 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/65 hover:bg-[#22d3ee]/14">
            <Play className="h-3.5 w-3.5" />
            Start New Migration
          </a>
          <button type="button" disabled={actionPending === 'bulk:retry'} onClick={() => runBulkAction('retry')} className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/55 disabled:opacity-50">
            <RefreshCcw className="h-3.5 w-3.5" />
            Retry Failed
          </button>
          <button type="button" disabled={actionPending === 'bulk:pause'} onClick={() => runBulkAction('pause')} className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/55 disabled:opacity-50">
            <Pause className="h-3.5 w-3.5" />
            Pause All
          </button>
          <button type="button" disabled={actionPending === 'bulk:resume'} onClick={() => runBulkAction('resume')} className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/55 disabled:opacity-50">
            <Play className="h-3.5 w-3.5" />
            Resume All
          </button>
          <button type="button" onClick={() => { setSnapshotFocusAsset(selectedJob?.asset || null); setSnapshotsOpen(true) }} className="inline-flex items-center gap-2 rounded-lg border border-[#f87171]/25 bg-[#f87171]/8 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#ff6b61] transition hover:border-[#f87171]/55">
            <RotateCcw className="h-3.5 w-3.5" />
            Rollback
          </button>
          <button type="button" onClick={() => { setSnapshotFocusAsset(null); setSnapshotsOpen(true) }} className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/25 bg-[#22d3ee]/8 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/55">
            <Archive className="h-3.5 w-3.5" />
            Snapshots
          </button>
          <button type="button" disabled={actionPending === 'export:csv'} onClick={() => downloadExport('csv')} className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/55 disabled:opacity-50">
            <ArrowDownToLine className="h-3.5 w-3.5" />
            Export Logs
          </button>
          {/*
            Enterprise report — PDF / Excel / Word / HTML / CSV / JSON from the
            SHARED exporters that already back the Assets register and the CBOM
            Explorer. Built from `filteredJobs`, i.e. exactly the rows on screen,
            so the document cannot disagree with the view it was launched from.
          */}
          <ReportExportMenu
            label="Generate Report"
            align="left"
            disabled={loading}
            title="Export live migration report"
            note="Plan state and execution evidence are reported separately, so a job marked complete without a collector is never presented as an applied change."
            className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/55 disabled:opacity-50"
            buildReport={() =>
              buildMigrationReport({
                generatedAt: new Date().toISOString(),
                planId,
                summary: snapshot.summary,
                jobs: filteredJobs,
                totalJobsBeforeFilter: snapshot.jobs.length,
                filtered: filter !== 'all',
                filterDescription: filter !== 'all' ? `status = ${filter}` : undefined,
                timeline: snapshot.timeline,
                telemetry: snapshot.telemetry,
              })
            }
          />
          <a href="/dashboard/audit-vault" className="inline-flex items-center gap-2 rounded-lg border border-[#22d3ee]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#22d3ee] transition hover:border-[#22d3ee]/55">
            <ShieldCheck className="h-3.5 w-3.5" />
            Audit Trail
          </a>
          <div className="ml-auto flex min-w-[220px] flex-wrap justify-end gap-3 text-[10px] text-white/38">
            <span className="flex items-center gap-1.5"><Activity className="h-3.5 w-3.5 text-[#22d3ee]" />SSE {streamConnected ? 'connected' : 'reconnecting'}</span>
            <span className="flex items-center gap-1.5"><Radio className="h-3.5 w-3.5 text-[#22d3ee]" />Realtime {realtimeStatus}</span>
            {/* Online is heartbeat-measured; an enrolled agent that stopped
                checking in is shown as stale rather than counted as online. */}
            <span
              className="flex items-center gap-1.5"
              title={`${snapshot.summary.agentsOnline} of ${snapshot.summary.agentsEnrolled} enrolled agent(s) sent a heartbeat in the last 10 minutes.`}
            >
              <Server className="h-3.5 w-3.5 text-[#22d3ee]" />
              Agents {numberFmt(snapshot.summary.agentsOnline)}/{numberFmt(snapshot.summary.agentsEnrolled)} online
              {snapshot.summary.agentsStale > 0 && (
                <span className="text-[#fbbf24]"> · {numberFmt(snapshot.summary.agentsStale)} stale</span>
              )}
            </span>
            {snapshot.summary.awaitingApproval > 0 && (
              <span
                className="flex items-center gap-1.5 text-[#fbbf24]"
                title="Jobs that exist and have not run, which no agent will take until a named person approves them."
              >
                <BadgeCheck className="h-3.5 w-3.5" />
                Awaiting approval {numberFmt(snapshot.summary.awaitingApproval)}
              </span>
            )}
            <span className="flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5 text-[#22d3ee]" />Verified {numberFmt(snapshot.summary.verified)}</span>
            <span className="flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5 text-[#22d3ee]" />Findings {numberFmt(snapshot.summary.findings)}</span>
          </div>
        </div>
        {notice && <div className="mt-2 text-[11px] font-bold text-white/55">{notice}</div>}
      </section>

      {/*
        Destructive-action confirmation. It names the exact jobs affected and
        states plainly what cancel vs remove does, so an operator can never
        delete queued migration work by a single mis-click.
      */}
      {confirm && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          aria-label={confirm.mode === 'remove' ? 'Confirm job removal' : confirm.mode === 'rollback' ? 'Confirm rollback' : confirm.mode === 'approve' ? 'Confirm approval' : 'Confirm job cancellation'}
          onClick={() => setConfirm(null)}
        >
          <div className={cn(GLASS, 'w-full max-w-lg p-5')} onClick={(event) => event.stopPropagation()}>
            <div className="relative z-10">
              <div className="flex items-center gap-3">
                <div className={cn('grid h-10 w-10 shrink-0 place-items-center rounded-full border-2 bg-black/30',
                  confirm.mode === 'remove' ? 'border-[#f87171]' : confirm.mode === 'rollback' ? 'border-[#fbbf24]' : confirm.mode === 'approve' ? 'border-[#34d399]' : 'border-white/35')}>
                  {confirm.mode === 'remove'
                    ? <Trash2 className="h-5 w-5 text-[#f87171]" />
                    : confirm.mode === 'rollback'
                      ? <RotateCcw className="h-5 w-5 text-[#fbbf24]" />
                      : confirm.mode === 'approve'
                        ? <BadgeCheck className="h-5 w-5 text-[#34d399]" />
                        : <Ban className="h-5 w-5 text-white/70" />}
                </div>
                <div>
                  <h2 className="text-sm font-black uppercase tracking-[0.14em] text-white">
                    {confirm.mode === 'remove'
                      ? 'Remove from migration queue'
                      : confirm.mode === 'rollback'
                        ? 'Roll back cryptographic change'
                        : confirm.mode === 'approve'
                          ? 'Approve change for agent execution'
                          : 'Cancel migration job'}
                  </h2>
                  <p className="mt-0.5 text-[11px] text-white/50">
                    {confirm.mode === 'remove'
                      ? 'Deletes the job and its dispatch records. The removal itself is written to the audit trail.'
                      : confirm.mode === 'rollback'
                        ? 'Restores the asset from its pre-change snapshot. The executor that applied the change verifies the backup digest before writing it back; the job is only marked rolled back once that is confirmed.'
                        : confirm.mode === 'approve'
                          ? 'Authorises a Patcher agent to change this asset. Your identity and the time are recorded on the job as the approval, and written to the audit trail.'
                          : 'Withdraws the job from execution. The job stays on the record and can be reviewed later.'}
                  </p>
                </div>
              </div>

              <div className="mt-4 max-h-44 space-y-1.5 overflow-y-auto rounded-lg border border-white/10 bg-black/25 p-3">
                {snapshot.jobs.filter((job) => confirm.ids.includes(job.id)).map((job) => (
                  <div key={job.id} className="flex items-center justify-between gap-3 text-[11px]">
                    <span className="truncate font-bold text-white/85">{job.asset}</span>
                    <span className={cn('shrink-0 text-[9px] font-black uppercase', statusConfig(job.status).color)}>
                      {statusConfig(job.status).label}
                    </span>
                  </div>
                ))}
              </div>

              {confirm.mode === 'remove' && snapshot.jobs.some((job) => confirm.ids.includes(job.id) && job.status === 'completed') && (
                <label className="mt-3 flex cursor-pointer items-start gap-2 rounded-lg border border-[#f87171]/30 bg-[#f87171]/[0.07] p-3 text-[11px] text-white/70">
                  <input
                    type="checkbox"
                    checked={confirm.includeCompleted}
                    onChange={(event) => setConfirm({ ...confirm, includeCompleted: event.target.checked })}
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 cursor-pointer accent-[#f87171]"
                  />
                  <span>
                    Also remove <span className="font-bold text-[#f87171]">completed</span> migrations. These record cryptographic
                    changes that actually happened and are normally retained as compliance evidence.
                  </span>
                </label>
              )}
              {confirm.mode === 'remove' && snapshot.jobs.some((job) => confirm.ids.includes(job.id) && job.status === 'running') && (
                <p className="mt-3 rounded-lg border border-[#22d3ee]/25 bg-[#22d3ee]/[0.07] p-3 text-[11px] text-white/70">
                  Running jobs in this selection will be kept — pause or cancel them first.
                </p>
              )}
              {confirm.mode === 'approve' && (
                <div className="mt-3 space-y-1.5 rounded-lg border border-[#34d399]/25 bg-[#34d399]/[0.06] p-3 text-[11px] leading-relaxed text-white/70">
                  <div className="font-bold text-[#34d399]">What happens after you approve</div>
                  <div>1. The job is queued. Only a Patcher agent whose policy covers this asset may claim it.</div>
                  <div>2. Before anything changes, a verified pre-change snapshot is taken. If it cannot be taken, the job is withheld.</div>
                  <div>3. The agent backs up the configuration, applies the change, and re-scans to validate it.</div>
                  <div>4. If validation fails, the agent restores the backup automatically. You can also roll back from Snapshots.</div>
                </div>
              )}
              {confirm.mode === 'rollback' && (
                <p className="mt-3 rounded-lg border border-[#fbbf24]/25 bg-[#fbbf24]/[0.07] p-3 text-[11px] leading-relaxed text-white/70">
                  If no executor can reach the recorded backup — the agent that applied the change is offline, revoked or read-only,
                  or the asset was never modified — the request is recorded and <span className="font-bold text-[#fbbf24]">nothing on the
                  asset changes</span>. The result message says which happened.
                </p>
              )}

              <div className="mt-4 flex flex-wrap justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setConfirm(null)}
                  className="rounded-lg border border-white/12 bg-white/[0.04] px-4 py-2 text-[10px] font-black uppercase tracking-wider text-white/60 transition hover:border-white/30 hover:text-white"
                >
                  {confirm.mode === 'rollback' ? 'Keep current state' : confirm.mode === 'approve' ? 'Not yet' : 'Keep jobs'}
                </button>
                <button
                  type="button"
                  disabled={actionPending.startsWith('remove:') || actionPending.startsWith('bulk:')}
                  onClick={() => {
                    if (confirm.mode === 'remove') void removeJobs(confirm.ids, confirm.includeCompleted)
                    else if (confirm.mode === 'rollback') { void runJobAction(confirm.ids[0], 'rollback'); setConfirm(null) }
                    else if (confirm.mode === 'approve') { void runJobAction(confirm.ids[0], 'approve'); setConfirm(null) }
                    else { void runBulkAction('cancel', confirm.ids); setConfirm(null) }
                  }}
                  className={cn(
                    'inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-[10px] font-black uppercase tracking-wider transition disabled:opacity-50',
                    confirm.mode === 'remove'
                      ? 'border-[#f87171]/55 bg-[#f87171]/15 text-[#f87171] hover:bg-[#f87171]/25'
                      : confirm.mode === 'rollback'
                        ? 'border-[#fbbf24]/55 bg-[#fbbf24]/15 text-[#fbbf24] hover:bg-[#fbbf24]/25'
                        : confirm.mode === 'approve'
                          ? 'border-[#34d399]/55 bg-[#34d399]/15 text-[#34d399] hover:bg-[#34d399]/25'
                          : 'border-white/25 bg-white/[0.06] text-white hover:bg-white/[0.12]',
                  )}
                >
                  {confirm.mode === 'remove' ? <Trash2 className="h-3.5 w-3.5" /> : confirm.mode === 'rollback' ? <RotateCcw className="h-3.5 w-3.5" /> : confirm.mode === 'approve' ? <BadgeCheck className="h-3.5 w-3.5" /> : <Ban className="h-3.5 w-3.5" />}
                  {confirm.mode === 'remove'
                    ? `Remove ${numberFmt(confirm.ids.length)} job${confirm.ids.length === 1 ? '' : 's'}`
                    : confirm.mode === 'rollback'
                      ? 'Roll back this change'
                      : confirm.mode === 'approve'
                        ? 'Approve & queue'
                        : `Cancel ${numberFmt(confirm.ids.length)} job${confirm.ids.length === 1 ? '' : 's'}`}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
