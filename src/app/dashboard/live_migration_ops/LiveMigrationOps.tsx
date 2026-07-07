import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  BadgeCheck,
  CheckCircle2,
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
  RefreshCcw,
  RotateCcw,
  Server,
  ShieldCheck,
  Terminal,
  XCircle,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'
import { Link, useSearchParams } from 'react-router-dom'

type LiveMigrationStatus = 'running' | 'completed' | 'failed' | 'queued' | 'paused'

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

type LiveMigrationSnapshot = {
  generatedAt: string
  planId: string | null
  summary: {
    total: number
    running: number
    completed: number
    failed: number
    queued: number
    paused: number
    completionRate: number
    waitingForAgent: number
    agentBacked: number
    verified: number
    agentsOnline: number
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
  health: Array<{ key: string; label: string; count: number; percent: number; color: string }>
  algorithmSummary: Array<{ label: string; count: number; percent: number; color: string }>
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
    completionRate: 0,
    waitingForAgent: 0,
    agentBacked: 0,
    verified: 0,
    agentsOnline: 0,
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
  health: [
    { key: 'onTrack', label: 'On Track', count: 0, percent: 0, color: '#30d158' },
    { key: 'atRisk', label: 'At Risk', count: 0, percent: 0, color: '#f6d365' },
    { key: 'delayed', label: 'Delayed', count: 0, percent: 0, color: '#f59e0b' },
    { key: 'failed', label: 'Failed', count: 0, percent: 0, color: '#ff3b30' },
  ],
  algorithmSummary: [],
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

const GLASS =
  'glass-panel rounded-xl border border-[#d4af37]/20 bg-[#05070d]/70 text-white shadow-[0_18px_60px_rgba(0,0,0,0.38)]'
const INNER =
  'rounded-lg border border-[#d4af37]/10 bg-black/20 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]'
const GOLD = '#d4af37'
const GREEN = '#30d158'
const RED = '#ff3b30'
const CYAN = '#00d9ff'

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
      return { icon: RefreshCcw, color: 'text-[#d4af37]', ring: 'border-[#d4af37]', bar: 'from-[#d4af37] to-[#fff3c1]', label: 'RUNNING' }
    case 'completed':
      return { icon: CheckCircle2, color: 'text-[#30d158]', ring: 'border-[#30d158]', bar: 'from-[#30d158] to-[#8dffab]', label: 'COMPLETED' }
    case 'failed':
      return { icon: XCircle, color: 'text-[#ff3b30]', ring: 'border-[#ff3b30]', bar: 'from-[#ff3b30] to-[#ff7a6f]', label: 'FAILED' }
    case 'paused':
      return { icon: Pause, color: 'text-[#d4af37]', ring: 'border-[#d4af37]', bar: 'from-[#d4af37] to-[#ffb84d]', label: 'PAUSED' }
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
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <polyline points={`0,42 ${points} 100,42`} fill={`${color}18`} stroke="none" />
    </svg>
  )
}

function LineChart({ data }: { data: TimelinePoint[] }) {
  const points = data.length ? data : EMPTY_SNAPSHOT.timeline
  const max = Math.max(3, ...points.flatMap((point) => [point.running, point.completed, point.failed]))
  const width = 520
  const height = 170
  const left = 32
  const right = 14
  const top = 14
  const bottom = 28

  const makePoints = (key: keyof Pick<TimelinePoint, 'running' | 'completed' | 'failed'>) => {
    if (!points.length) return ''
    return points.map((point, index) => {
      const x = left + (index / Math.max(points.length - 1, 1)) * (width - left - right)
      const y = top + (1 - point[key] / max) * (height - top - bottom)
      return `${x},${y}`
    }).join(' ')
  }

  return (
    <div className="relative h-[178px]">
      <svg viewBox={`0 0 ${width} ${height}`} className="h-full w-full" role="img" aria-label="Migration jobs over time chart">
        {[0, 1, 2, 3].map((line) => {
          const y = top + (line / 3) * (height - top - bottom)
          return (
            <g key={line}>
              <line x1={left} x2={width - right} y1={y} y2={y} stroke="rgba(255,255,255,0.07)" />
              <text x="4" y={y + 4} fill="rgba(255,255,255,0.55)" fontSize="11">{Math.round(max - (line / 3) * max)}</text>
            </g>
          )
        })}
        {points.map((point, index) => {
          const x = left + (index / Math.max(points.length - 1, 1)) * (width - left - right)
          return <text key={point.key} x={x - 16} y={height - 6} fill="rgba(255,255,255,0.54)" fontSize="11">{point.label}</text>
        })}
        <polyline points={makePoints('running')} fill="none" stroke={GOLD} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points={makePoints('completed')} fill="none" stroke={GREEN} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points={makePoints('failed')} fill="none" stroke={RED} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        {(['running', 'completed', 'failed'] as const).map((key) =>
          points.map((point, index) => {
            const color = key === 'running' ? GOLD : key === 'completed' ? GREEN : RED
            const x = left + (index / Math.max(points.length - 1, 1)) * (width - left - right)
            const y = top + (1 - point[key] / max) * (height - top - bottom)
            return <circle key={`${key}-${point.key}`} cx={x} cy={y} r="3" fill={color} />
          }),
        )}
      </svg>
    </div>
  )
}

function Donut({
  segments,
  center,
  label,
  size = 116,
}: {
  segments: Array<{ color: string; percent: number }>
  center: string
  label: string
  size?: number
}) {
  let offset = 0
  const visible = segments.filter((segment) => segment.percent > 0)

  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 120 120" className="absolute inset-0 h-full w-full -rotate-90">
        <circle cx="60" cy="60" r="42" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="14" />
        {visible.map((segment, index) => {
          const currentOffset = offset
          offset += segment.percent
          return (
            <circle
              key={`${segment.color}-${index}`}
              cx="60"
              cy="60"
              r="42"
              fill="none"
              pathLength="100"
              stroke={segment.color}
              strokeWidth="14"
              strokeDasharray={`${segment.percent} ${100 - segment.percent}`}
              strokeDashoffset={-currentOffset}
              strokeLinecap="butt"
            />
          )
        })}
      </svg>
      <div className="relative text-center">
        <div className="text-3xl font-black text-white">{center}</div>
        <div className="text-[10px] uppercase tracking-wider text-white/45">{label}</div>
      </div>
    </div>
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
                  'z-10 grid h-7 w-7 place-items-center rounded-full border bg-[#05070d] shadow-[0_0_16px_rgba(0,0,0,0.65)]',
                  complete && 'border-[#30d158] text-[#30d158]',
                  current && 'border-[#d4af37] text-[#d4af37] shadow-[0_0_18px_rgba(212,175,55,0.45)]',
                  failed && 'border-[#ff3b30] text-[#ff3b30]',
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
                    complete && 'text-[#30d158]',
                    current && 'text-[#d4af37]',
                    failed && 'text-[#ff3b30]',
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
          className={cn('h-2.5 w-2.5 rounded-full', index < count ? 'bg-[#ff3b30] shadow-[0_0_9px_rgba(255,59,48,0.45)]' : 'bg-white/12')}
        />
      ))}
      <span className="ml-1 text-[9px] capitalize text-white/35">{criticality || 'medium'}</span>
    </div>
  )
}

export default function LiveMigrationOperations() {
  const [searchParams] = useSearchParams()
  const planId = searchParams.get('planId')
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
  const [now, setNow] = useState(new Date())

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
      const res = await fetch(`/api/v1/migration/live${planQuery ? `?${planQuery}` : ''}`, { headers: authHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
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

  const statSparklines = useMemo(() => ({
    running: snapshot.timeline.map((point) => point.running),
    completed: snapshot.timeline.map((point) => point.completed),
    failed: snapshot.timeline.map((point) => point.failed),
    total: snapshot.timeline.map((point) => point.running + point.completed + point.failed),
  }), [snapshot.timeline])

  const runJobAction = useCallback(async (jobId: string, action: 'pause' | 'resume' | 'retry' | 'rollback') => {
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
      setNotice(`Migration action recorded: ${action}.`)
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Migration action failed.')
    } finally {
      setActionPending('')
    }
  }, [applySnapshot, authHeaders, token])

  const runBulkAction = useCallback(async (action: 'pause' | 'resume' | 'retry') => {
    if (!token) return
    setActionPending(`bulk:${action}`)
    setNotice('')
    try {
      const res = await fetch('/api/v1/migration/jobs/actions', {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ action, ...(planId ? { planId } : {}) }),
      })
      const json = await res.json()
      if (!res.ok) throw new Error(json?.error?.message || `HTTP ${res.status}`)
      applySnapshot(json.data?.snapshot)
      setNotice(`${numberFmt(json.data?.affected || 0)} migration job(s) updated.`)
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Bulk migration action failed.')
    } finally {
      setActionPending('')
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

  return (
    <div className="min-h-[calc(100vh-64px)] space-y-3 p-3 text-white sm:p-4 lg:p-5">
      <header className="grid gap-3 xl:grid-cols-[1fr_300px_240px] xl:items-center">
        <div className="flex min-w-0 items-start gap-3">
          <div className="mt-1 grid h-9 w-9 shrink-0 place-items-center text-[#d4af37]">
            <Diamond className="h-7 w-7" />
          </div>
          <div className="min-w-0">
            <h1 className="truncate font-mono text-2xl font-black uppercase leading-none tracking-[0.08em] text-white sm:text-3xl">
              Live Migration <span className="text-[#d4af37]">Operations</span>
            </h1>
            <p className="mt-2 text-sm font-medium text-white/55">
              Real-time PQC migration job monitoring, logs, and rollback management.
            </p>
          </div>
        </div>

        <div className={cn(GLASS, 'px-4 py-3')}>
          <div className="relative z-10">
            <div className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.16em] text-white">
              <ShieldCheck className="h-4 w-4 text-[#d4af37]" />
              {snapshot.summary.complianceMode}
            </div>
            <div className="mt-1 truncate text-[10px] text-white/45">{snapshot.summary.standardLabel}</div>
            <div className="mt-1 truncate text-[10px] text-white/45">
              {numberFmt(snapshot.summary.agentBacked)} agent-backed / {numberFmt(snapshot.summary.waitingForAgent)} waiting
            </div>
            {planId && <div className="mt-1 truncate font-mono text-[10px] text-[#d4af37]/70">Plan {planId}</div>}
          </div>
        </div>

        <div className="flex items-center justify-end gap-3">
          <div className={cn(INNER, 'flex items-center gap-2 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-[#30d158]')}>
            <span className={cn('h-2 w-2 rounded-full bg-[#30d158]', streamConnected && 'animate-pulse shadow-[0_0_10px_rgba(48,209,88,0.85)]')} />
            {streamConnected ? 'Live' : 'Syncing'}
          </div>
          <div className="text-right font-mono">
            <div className="flex items-center justify-end gap-2 text-xs font-black text-white">
              <Clock3 className="h-4 w-4 text-[#d4af37]" />
              {now.toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })} UTC
            </div>
            <div className="text-[10px] text-white/45">{now.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })}</div>
          </div>
          <div className={cn(INNER, 'flex items-center gap-2 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37]')}>
            <Zap className="h-3.5 w-3.5" />
            {numberFmt(snapshot.summary.agentBacked)} Agent Backed
          </div>
        </div>
      </header>

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
                <div className={cn('grid h-12 w-12 place-items-center rounded-full border-2 bg-black/25', metric.key === 'total' ? 'border-[#d4af37]' : '')} style={{ borderColor: metric.color }}>
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
            <h3 className="text-[11px] font-black uppercase tracking-[0.18em] text-[#d4af37]">Real-Time Telemetry</h3>
            <span className="rounded-full border border-[#30d158]/25 bg-[#30d158]/10 px-3 py-1 text-[9px] font-black uppercase tracking-wider text-[#30d158]">{snapshot.telemetry.systemHealth}</span>
          </div>
          <div className="relative z-10 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
            {[
              ['TLS Handshakes', snapshot.telemetry.tlsHandshakeEvents],
              ['Certificate Replacements', snapshot.telemetry.certificateReplacements],
              ['Key Rotations', snapshot.telemetry.keyRotations],
              ['PQC Validations', snapshot.telemetry.pqcValidationEvents],
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
              to="/dashboard/scanner?tab=agents"
              className="inline-flex h-9 items-center gap-2 rounded-md border border-[#d4af37]/45 bg-[#d4af37]/10 px-3 text-[10px] font-black uppercase tracking-[0.12em] text-[#d4af37] transition hover:border-[#d4af37]/75 hover:bg-[#d4af37]/15 hover:text-[#ffe7a3]"
            >
              <Server className="h-3.5 w-3.5" />
              <span>Next Step: setup an Agent</span>
            </Link>
          </div>
        </div>

        <div className={cn(GLASS, 'p-4')}>
          <h3 className="relative z-10 mb-3 text-[11px] font-black uppercase tracking-[0.18em] text-[#d4af37]">Activity Feed</h3>
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

      <section className="grid gap-3 xl:grid-cols-[440px_minmax(0,1fr)]">
        <div className={cn(GLASS, 'overflow-hidden')}>
          <div className="relative z-10 border-b border-[#d4af37]/10 px-4 py-3">
            <div className="flex items-center justify-between">
              <h2 className="text-[11px] font-black uppercase tracking-[0.18em] text-[#d4af37]">Migration Jobs</h2>
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
              ].map(([key, label, count]) => (
                <button
                  key={String(key)}
                  type="button"
                  onClick={() => setFilter(key as 'all' | LiveMigrationStatus)}
                  className={cn(
                    'rounded-full border px-2.5 py-1 text-[10px] font-bold transition',
                    filter === key
                      ? 'border-[#d4af37]/55 bg-[#d4af37]/12 text-[#d4af37]'
                      : 'border-white/10 bg-white/[0.025] text-white/45 hover:border-[#d4af37]/30 hover:text-white/70',
                  )}
                >
                  {label} <span className="ml-1 text-[#d4af37]">{count}</span>
                </button>
              ))}
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
                  <Server className="mx-auto mb-3 h-8 w-8 text-[#d4af37]/65" />
                  <div className="text-sm font-bold text-white">No migration jobs found</div>
                  <div className="mt-1 text-xs text-white/45">Run an authenticated migration plan to populate this live operations view.</div>
                </div>
              </div>
            )}
            {filteredJobs.map((job, index) => {
              const config = statusConfig(job.status)
              const StatusIcon = config.icon
              const selected = selectedJob?.id === job.id
              return (
                <motion.button
                  key={job.id}
                  type="button"
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.025 }}
                  onClick={() => setSelectedJobId(job.id)}
                  className={cn(
                    'relative w-full overflow-hidden rounded-lg border p-3 text-left transition',
                    selected
                      ? 'border-[#d4af37]/70 bg-[#d4af37]/10 shadow-[0_0_28px_rgba(212,175,55,0.24)]'
                      : 'border-white/10 bg-white/[0.035] hover:border-[#d4af37]/35 hover:bg-[#d4af37]/6',
                  )}
                >
                  <div className="flex items-center gap-3">
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
                        <ArrowRight className="h-3 w-3 shrink-0 text-[#d4af37]/55" />
                        <span className="truncate text-[#d4af37]/80">{job.toAlgo}</span>
                        <span className={cn('rounded border px-1.5 py-0.5 text-[8px] font-black uppercase',
                          job.isSandbox ? 'border-[#a78bfa]/30 text-[#a78bfa]' : job.executionBacked ? 'border-[#30d158]/30 text-[#30d158]' : 'border-[#d4af37]/24 text-[#d4af37]/70')}>
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
                  </div>
                </motion.button>
              )
            })}
          </div>
          <div className="relative z-10 border-t border-[#d4af37]/10 p-3 text-center">
            <a href="/dashboard/migration-timeline" className="inline-flex items-center gap-2 rounded-md border border-[#d4af37]/15 bg-[#d4af37]/5 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:border-[#d4af37]/50">
              <ListChecks className="h-3.5 w-3.5" />
              View All Jobs
            </a>
          </div>
        </div>

        <div className="space-y-3">
          <div className={cn(GLASS, 'p-4')}>
            {selectedJob ? (
              <>
                <div className="relative z-10 flex flex-col gap-3 border-b border-[#d4af37]/10 pb-3 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0">
                    <h2 className="truncate text-xl font-black text-white">{selectedJob.asset}</h2>
                    <div className="mt-1 flex min-w-0 items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-[#d4af37]">
                      <span className="truncate">{selectedJob.fromAlgo}</span>
                      <ArrowRight className="h-3 w-3 shrink-0" />
                      <span className="truncate">{selectedJob.toAlgo}</span>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {selectedJob.status === 'running' && (
                      <button
                        type="button"
                        disabled={actionPending === `${selectedJob.id}:pause`}
                        onClick={() => runJobAction(selectedJob.id, 'pause')}
                        className="inline-flex items-center gap-2 rounded-lg border border-[#d4af37]/45 bg-[#d4af37]/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:bg-[#d4af37]/18 disabled:opacity-50"
                      >
                        <Pause className="h-3.5 w-3.5" />
                        Pause
                      </button>
                    )}
                    {(selectedJob.status === 'paused' || selectedJob.status === 'queued') && (
                      <button
                        type="button"
                        disabled={actionPending === `${selectedJob.id}:resume`}
                        onClick={() => runJobAction(selectedJob.id, 'resume')}
                        className="inline-flex items-center gap-2 rounded-lg border border-[#30d158]/35 bg-[#30d158]/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#30d158] transition hover:bg-[#30d158]/18 disabled:opacity-50"
                      >
                        <Play className="h-3.5 w-3.5" />
                        Resume
                      </button>
                    )}
                    {selectedJob.status === 'failed' && (
                      <button
                        type="button"
                        disabled={actionPending === `${selectedJob.id}:retry`}
                        onClick={() => runJobAction(selectedJob.id, 'retry')}
                        className="inline-flex items-center gap-2 rounded-lg border border-[#d4af37]/45 bg-[#d4af37]/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:bg-[#d4af37]/18 disabled:opacity-50"
                      >
                        <RefreshCcw className="h-3.5 w-3.5" />
                        Retry
                      </button>
                    )}
                    <button
                      type="button"
                      className="rounded-lg border border-white/10 bg-white/[0.04] p-2 text-white/45 transition hover:border-[#d4af37]/30 hover:text-[#d4af37]"
                      title="Migration options"
                    >
                      <MoreVertical className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                <div className="relative z-10 mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
                  {[
                    { label: 'Progress', value: `${selectedJob.progress}%`, color: '#d4af37', icon: RefreshCcw },
                    { label: 'Execution', value: selectedJob.executionBacked ? selectedJob.executionStatus : 'Waiting', color: selectedJob.executionBacked ? '#30d158' : '#d4af37', icon: Radio },
                    { label: 'Agent', value: selectedJob.agentName || 'Unassigned', color: '#ffffff', icon: Server },
                    { label: 'Telemetry', value: numberFmt(selectedJob.telemetryCount), color: '#00d9ff', icon: Activity },
                    { label: 'Validation', value: selectedJob.validationStatus, color: /pass|success|valid/.test(selectedJob.validationStatus) ? '#30d158' : '#ffffff', icon: ShieldCheck },
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
                      <div className="text-[8px] font-black uppercase tracking-wider text-[#d4af37]/75">{label}</div>
                      <div className="mt-1 truncate text-xs font-bold text-white">{value}</div>
                    </div>
                  ))}
                  <div className={cn(INNER, 'px-3 py-2.5')}>
                    <div className="text-[8px] font-black uppercase tracking-wider text-[#d4af37]/75">Criticality</div>
                    <div className="mt-2"><SeverityDots criticality={selectedJob.criticality} /></div>
                  </div>
                </div>

                <div className="relative z-10 mt-3 grid gap-2 lg:grid-cols-2">
                  <div className={cn(INNER, 'p-3')}>
                    <div className="flex flex-wrap items-center gap-2">
                      <FileText className="h-4 w-4 text-[#00d9ff]" />
                      <div className="text-[10px] font-black uppercase tracking-[0.16em] text-white">Local Config Ownership</div>
                      <span className={cn(
                        'ml-auto rounded-full border px-2 py-1 text-[8px] font-black uppercase tracking-wider',
                        selectedConfigPath ? 'border-[#30d158]/35 bg-[#30d158]/10 text-[#30d158]' : 'border-[#d4af37]/35 bg-[#d4af37]/10 text-[#d4af37]',
                      )}>
                        {selectedConfigPath ? 'Path Attached' : 'Path Needed'}
                      </span>
                    </div>
                    <p className="mt-2 text-[11px] font-semibold leading-relaxed text-white/58">
                      The agent owns the path only when it runs on the asset or has a mounted config path, that path is listed in the agent policy allowedPaths, and the migration job carries the same filePath/configPath.
                    </p>
                    <div className="mt-3 space-y-2 text-[10px] font-bold text-white/55">
                      <div className="flex gap-2">
                        <span className="w-16 shrink-0 uppercase tracking-wider text-[#d4af37]/75">Path</span>
                        <span className="min-w-0 truncate text-white/75">{selectedConfigPath || 'Attach filePath/configPath through the agent or operator patch action.'}</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="w-16 shrink-0 uppercase tracking-wider text-[#d4af37]/75">Next</span>
                        <span className="text-white/75">Enroll the collector on the host, add allowedPaths, then enable remediation/config patching after approval.</span>
                      </div>
                    </div>
                    <Link to="/dashboard/scanner?tab=agents" className="mt-3 inline-flex items-center gap-2 rounded-md border border-[#00d9ff]/25 bg-[#00d9ff]/8 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-[#00d9ff] transition hover:border-[#00d9ff]/55">
                      <Server className="h-3.5 w-3.5" />
                      Open Agent Setup
                    </Link>
                  </div>

                  <div className={cn(INNER, 'p-3')}>
                    <div className="flex flex-wrap items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-[#d4af37]" />
                      <div className="text-[10px] font-black uppercase tracking-[0.16em] text-white">Connector / Operator Credentials</div>
                      <span className={cn(
                        'ml-auto rounded-full border px-2 py-1 text-[8px] font-black uppercase tracking-wider',
                        selectedNeedsConnector ? 'border-[#d4af37]/35 bg-[#d4af37]/10 text-[#d4af37]' : 'border-white/15 bg-white/[0.04] text-white/45',
                      )}>
                        {selectedNeedsConnector ? (selectedConnector ? 'Connector Attached' : 'Connector Required') : 'If Required'}
                      </span>
                    </div>
                    <p className="mt-2 text-[11px] font-semibold leading-relaxed text-white/58">
                      This migration card does not collect provider secrets. Cloud, Kubernetes, identity, KMS, CDN, load balancer, and certificate automation changes must be connected through a tenant-scoped connector or approved operator patch action.
                    </p>
                    <div className="mt-3 space-y-2 text-[10px] font-bold text-white/55">
                      <div className="flex gap-2">
                        <span className="w-20 shrink-0 uppercase tracking-wider text-[#d4af37]/75">Connector</span>
                        <span className="min-w-0 truncate text-white/75">{selectedConnector || 'Register provider, scopes, allowed targets, and approval owner.'}</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="w-20 shrink-0 uppercase tracking-wider text-[#d4af37]/75">Next</span>
                        <span className="text-white/75">Create the operator patch action, approve it, apply with the owning platform, then resume validation here.</span>
                      </div>
                    </div>
                    <Link to="/dashboard/scanner?tab=agents" className="mt-3 inline-flex items-center gap-2 rounded-md border border-[#d4af37]/25 bg-[#d4af37]/8 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-[#d4af37] transition hover:border-[#d4af37]/55">
                      <ListChecks className="h-3.5 w-3.5" />
                      Open Connector Patchers
                    </Link>
                  </div>
                </div>
              </>
            ) : (
              <div className="relative z-10 grid min-h-[260px] place-items-center text-center">
                <div>
                  <Radio className="mx-auto mb-3 h-10 w-10 text-[#d4af37]/65" />
                  <div className="text-lg font-black text-white">No live migration selected</div>
                  <div className="mt-1 text-sm text-white/45">Authenticated migration jobs will appear here as soon as they are created.</div>
                </div>
              </div>
            )}
          </div>

          <div className={cn(GLASS, 'overflow-hidden')}>
            <div className="relative z-10 flex flex-wrap items-center gap-3 border-b border-[#d4af37]/10 px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                <Terminal className="h-4 w-4 text-[#d4af37]" />
                <h3 className="truncate text-[11px] font-black uppercase tracking-[0.18em] text-[#d4af37]">
                  Migration Log {selectedJob ? `- ${selectedJob.asset}` : ''}
                </h3>
              </div>
              <div className="ml-auto flex items-center gap-3">
                <span className="flex items-center gap-2 text-[10px] text-white/65"><span className="h-2 w-2 rounded-full bg-[#30d158]" />Live</span>
                <button type="button" title="Filter logs" className="text-white/35 transition hover:text-[#d4af37]"><Filter className="h-4 w-4" /></button>
                <button type="button" title="Export logs" onClick={() => downloadExport('csv')} className="text-white/35 transition hover:text-[#d4af37]"><Download className="h-4 w-4" /></button>
                <button type="button" title="Expand log panel" className="text-white/35 transition hover:text-[#d4af37]"><Maximize2 className="h-4 w-4" /></button>
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
                          (severity === 'error' || severity === 'critical') && 'font-bold text-[#ff3b30]',
                          severity === 'warning' && 'font-bold text-[#d4af37]',
                          (severity === 'success' || log.message.toUpperCase().includes('PASS')) && 'font-bold text-[#30d158]',
                          !['error', 'critical', 'warning', 'success'].includes(severity) && !log.message.toUpperCase().includes('PASS') && 'text-white/55',
                        )}
                      >
                        <span className="text-white/38">[{formatTime(log.createdAt)}]</span> {log.message}
                      </div>
                    )
                  })}
                  {selectedJob.status === 'running' && <div className="animate-pulse text-[#d4af37]">█</div>}
                </div>
              ) : (
                <div className="grid h-[150px] place-items-center text-center text-white/36">
                  <div>
                    <Terminal className="mx-auto mb-2 h-7 w-7 text-[#d4af37]/55" />
                    <div className="font-bold">No migration events recorded for this job.</div>
                    <div className="mt-1 text-[11px]">Awaiting authenticated agent telemetry.</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-3 xl:grid-cols-[minmax(0,1.15fr)_284px_minmax(360px,1fr)]">
        <div className={cn(GLASS, 'p-4')}>
          <div className="relative z-10 mb-2 flex items-center justify-between">
            <h3 className="text-[11px] font-black uppercase tracking-[0.18em] text-[#d4af37]">Migration Jobs Over Time</h3>
            <div className="flex gap-4 text-[10px] text-white/55">
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-[#d4af37]" />Running</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-[#30d158]" />Completed</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-[#ff3b30]" />Failed</span>
            </div>
          </div>
          <div className="relative z-10">
            <LineChart data={snapshot.timeline} />
          </div>
        </div>

        <div className={cn(GLASS, 'p-4')}>
          <h3 className="relative z-10 mb-3 text-[11px] font-black uppercase tracking-[0.18em] text-[#d4af37]">Migration Health</h3>
          <div className="relative z-10 grid grid-cols-[112px_minmax(0,1fr)] items-center gap-3">
            <Donut
              segments={snapshot.health.map((item) => ({ color: item.color, percent: item.percent }))}
              center={String(Math.round(snapshot.health.find((item) => item.key === 'onTrack')?.percent || 0))}
              label="Good"
              size={112}
            />
            <div className="space-y-2">
              {snapshot.health.map((item) => (
                <div key={item.key} className="flex items-center justify-between gap-3 text-xs">
                  <span className="flex min-w-0 items-center gap-2 text-white/70">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ background: item.color }} />
                    <span className="truncate">{item.label}</span>
                  </span>
                  <span className="font-mono font-bold text-white">{numberFmt(item.count)} ({item.percent}%)</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className={cn(GLASS, 'p-4')}>
          <h3 className="relative z-10 mb-3 text-[11px] font-black uppercase tracking-[0.18em] text-[#d4af37]">Algorithm Transition Summary</h3>
          <div className="relative z-10 grid gap-4 md:grid-cols-[132px_minmax(0,1fr)] md:items-center">
            <Donut
              segments={snapshot.algorithmSummary.map((item) => ({ color: item.color, percent: item.percent }))}
              center={String(snapshot.summary.total)}
              label="Total Jobs"
              size={132}
            />
            <div className="space-y-2">
              {snapshot.algorithmSummary.length ? snapshot.algorithmSummary.map((item) => (
                <div key={item.label} className={cn(INNER, 'flex items-center justify-between gap-3 px-3 py-2 text-xs')}>
                  <span className="flex min-w-0 items-center gap-2 text-white/74">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ background: item.color }} />
                    <span className="truncate">{item.label}</span>
                  </span>
                  <span className="font-mono font-bold text-white">{numberFmt(item.count)} ({item.percent}%)</span>
                </div>
              )) : (
                <div className={cn(INNER, 'px-3 py-6 text-center text-xs text-white/42')}>No algorithm transitions recorded yet.</div>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="sticky bottom-0 z-20 -mx-3 border-t border-[#d4af37]/10 bg-[#05070d]/88 px-3 py-3 backdrop-blur-xl sm:-mx-4 sm:px-4 lg:-mx-5 lg:px-5">
        <div className="flex flex-wrap items-center gap-2">
          <a href="/dashboard/migration-planner" className="inline-flex items-center gap-2 rounded-lg border border-[#d4af37]/30 bg-[#d4af37]/8 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:border-[#d4af37]/65 hover:bg-[#d4af37]/14">
            <Play className="h-3.5 w-3.5" />
            Start New Migration
          </a>
          <button type="button" disabled={actionPending === 'bulk:retry'} onClick={() => runBulkAction('retry')} className="inline-flex items-center gap-2 rounded-lg border border-[#d4af37]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:border-[#d4af37]/55 disabled:opacity-50">
            <RefreshCcw className="h-3.5 w-3.5" />
            Retry Failed
          </button>
          <button type="button" disabled={actionPending === 'bulk:pause'} onClick={() => runBulkAction('pause')} className="inline-flex items-center gap-2 rounded-lg border border-[#d4af37]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:border-[#d4af37]/55 disabled:opacity-50">
            <Pause className="h-3.5 w-3.5" />
            Pause All
          </button>
          <button type="button" disabled={actionPending === 'bulk:resume'} onClick={() => runBulkAction('resume')} className="inline-flex items-center gap-2 rounded-lg border border-[#d4af37]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:border-[#d4af37]/55 disabled:opacity-50">
            <Play className="h-3.5 w-3.5" />
            Resume All
          </button>
          <button type="button" disabled={!selectedJob || actionPending === `${selectedJob?.id}:rollback`} onClick={() => selectedJob && runJobAction(selectedJob.id, 'rollback')} className="inline-flex items-center gap-2 rounded-lg border border-[#ff3b30]/25 bg-[#ff3b30]/8 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#ff6b61] transition hover:border-[#ff3b30]/55 disabled:opacity-50">
            <RotateCcw className="h-3.5 w-3.5" />
            Rollback
          </button>
          <button type="button" disabled={actionPending === 'export:csv'} onClick={() => downloadExport('csv')} className="inline-flex items-center gap-2 rounded-lg border border-[#d4af37]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:border-[#d4af37]/55 disabled:opacity-50">
            <ArrowDownToLine className="h-3.5 w-3.5" />
            Export Logs
          </button>
          <button type="button" disabled={actionPending === 'export:json'} onClick={() => downloadExport('json')} className="inline-flex items-center gap-2 rounded-lg border border-[#d4af37]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:border-[#d4af37]/55 disabled:opacity-50">
            <FileText className="h-3.5 w-3.5" />
            Generate Report
          </button>
          <a href="/dashboard/audit-vault" className="inline-flex items-center gap-2 rounded-lg border border-[#d4af37]/20 bg-white/[0.035] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[#d4af37] transition hover:border-[#d4af37]/55">
            <ShieldCheck className="h-3.5 w-3.5" />
            Audit Trail
          </a>
          <div className="ml-auto flex min-w-[220px] flex-wrap justify-end gap-3 text-[10px] text-white/38">
            <span className="flex items-center gap-1.5"><Activity className="h-3.5 w-3.5 text-[#d4af37]" />SSE {streamConnected ? 'connected' : 'reconnecting'}</span>
            <span className="flex items-center gap-1.5"><Radio className="h-3.5 w-3.5 text-[#d4af37]" />Realtime {realtimeStatus}</span>
            <span className="flex items-center gap-1.5"><Server className="h-3.5 w-3.5 text-[#d4af37]" />Agents {numberFmt(snapshot.summary.agentsOnline)}</span>
            <span className="flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5 text-[#d4af37]" />Verified {numberFmt(snapshot.summary.verified)}</span>
            <span className="flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5 text-[#d4af37]" />Findings {numberFmt(snapshot.summary.findings)}</span>
          </div>
        </div>
        {notice && <div className="mt-2 text-[11px] font-bold text-white/55">{notice}</div>}
      </section>
    </div>
  )
}
