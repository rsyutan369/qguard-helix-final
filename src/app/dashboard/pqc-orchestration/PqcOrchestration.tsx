import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Download,
  ExternalLink,
  Filter,
  Layers3,
  ListChecks,
  MoreHorizontal,
  Pause,
  Play,
  Plus,
  Radio,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  SquareStack,
  Terminal,
  Workflow,
  X,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'
import { useNavigate, useSearchParams } from 'react-router-dom'

type WorkflowStatus = 'completed' | 'running' | 'failed' | 'pending' | 'paused'
type StageState = 'completed' | 'active' | 'pending' | 'failed'

type OrchestrationMetrics = {
  activeWorkflows: number
  runningJobs: number
  failedTasks: number
  pqcReadiness: number
  totalAssets: number
  completedWorkflows: number
  pendingWorkflows: number
  activeScans: number
  hndlPending?: number
}

type WorkflowItem = {
  id: string
  name: string
  subtitle: string
  assetName: string
  environment: string
  assetType: string
  status: WorkflowStatus
  rawStatus: string
  priority: string
  eta: string
  progress: number
  targetAlgorithm: string
  currentStep: string
  startedAt: string | null
  completedAt: string | null
  updatedAt: string | null
  source?: string
  sourceFindingId?: string
  materialized?: boolean
}

type LiveExecution = {
  workflowId: string
  name: string
  currentStep: string
  algorithmTransition: string
  progress: number
  startedAt: string | null
  eta: string
  status: WorkflowStatus
  stages: Array<{
    key: string
    label: string
    threshold: number
    state: StageState
    timestamp: string | null
  }>
} | null

type TelemetryLog = {
  id: string
  timestamp: string
  message: string
  severity: string
}

type ReadinessBreakdown = {
  pqcEnabled: number
  hybridMode: number
  legacy: number
  notAssessed: number
  totalAssets: number
  score: number
}

type ComplianceItem = {
  label: string
  status: string
}

type TaskItem = {
  id: string
  title: string
  priority: string
  progress: number
  eta: string
  status: string
}

type HndlRemediationSummary = {
  activeFindings: number
  pendingFindings: number
  linkedJobs: number
  lastDetectedAt: string | null
}

type MigrationPlan = {
  id: string
  status: string
  selectedAssets: Array<{
    id: string
    assetId: string | null
    name: string
    type: string
    environment: string
    owner: string
    currentAlgorithm: string
    targetSolution: string
    risk: number
    priority: string
    status: string
    progress: number
  }>
  configuration: {
    currentAlgorithms?: string[]
    targetAlgorithms?: string[]
    deploymentStrategy?: string
    controls?: Record<string, boolean>
    tags?: string[]
  }
  riskData: Record<string, unknown>
  migrationMetadata: Record<string, unknown>
  jobs: Array<{ id: string; status: string; progress: number; target_algorithm?: string }>
  orchestrationUrl: string
  liveMigrationUrl: string
}

type OrchestrationSnapshot = {
  generatedAt: string
  metrics: OrchestrationMetrics
  workflowQueue: WorkflowItem[]
  liveExecution: LiveExecution
  telemetryLogs: TelemetryLog[]
  readiness: ReadinessBreakdown
  compliance: ComplianceItem[]
  taskQueue: TaskItem[]
  hndlRemediation: HndlRemediationSummary
}

type LoadState = 'loading' | 'success' | 'error'

const EMPTY_SNAPSHOT: OrchestrationSnapshot = {
  generatedAt: new Date(0).toISOString(),
  metrics: {
    activeWorkflows: 0,
    runningJobs: 0,
    failedTasks: 0,
    pqcReadiness: 0,
    totalAssets: 0,
    completedWorkflows: 0,
    pendingWorkflows: 0,
    activeScans: 0,
    hndlPending: 0,
  },
  workflowQueue: [],
  liveExecution: null,
  telemetryLogs: [],
  readiness: {
    pqcEnabled: 0,
    hybridMode: 0,
    legacy: 0,
    notAssessed: 0,
    totalAssets: 0,
    score: 0,
  },
  compliance: [],
  taskQueue: [],
  hndlRemediation: {
    activeFindings: 0,
    pendingFindings: 0,
    linkedJobs: 0,
    lastDetectedAt: null,
  },
}

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:bg-[#FFD36B]/25 text-white'

const GOLD = '#FFD36B'
const GREEN = '#22c55e'
const RED = '#ef4444'
const BLUE = '#38bdf8'
const SLATE = '#94a3b8'
const WORKFLOW_PAGE_SIZE = 5

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(value || 0)
}

function clamp(value: number) {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, Math.round(value)))
}

function relativeTime(value: string | null) {
  if (!value) return 'No telemetry'
  const ms = Date.now() - new Date(value).getTime()
  if (!Number.isFinite(ms) || ms < 0) return new Date(value).toLocaleString()
  const minutes = Math.floor(ms / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

function timeOnly(value: string | null) {
  if (!value) return '--:--'
  return new Date(value).toLocaleTimeString('en-US', { hour12: false })
}

function statusLabel(status: string) {
  const value = status.toLowerCase()
  if (value === 'running') return 'In Progress'
  if (value === 'completed') return 'Completed'
  if (value === 'failed') return 'Failed'
  if (value === 'paused') return 'Paused'
  return 'Pending'
}

function statusClass(status: string) {
  const value = status.toLowerCase()
  if (value.includes('completed') || value.includes('compliant') || value.includes('running')) return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
  if (value.includes('failed') || value.includes('non') || value.includes('critical')) return 'border-red-500/30 bg-red-500/10 text-red-300'
  if (value.includes('progress') || value.includes('approval') || value.includes('risk')) return 'border-gold/30 bg-gold/10 text-gold'
  return 'border-white/15 bg-white/5 text-white/55'
}

function priorityClass(priority: string) {
  const value = priority.toLowerCase()
  if (value.includes('critical')) return 'text-red-400'
  if (value.includes('high')) return 'text-red-300'
  if (value.includes('medium')) return 'text-gold'
  return 'text-emerald-300'
}

function usePqcOrchestrationSnapshot(planId?: string | null) {
  const { session, user } = useAuth()
  const token = session?.access_token
  const [snapshot, setSnapshot] = useState<OrchestrationSnapshot>(EMPTY_SNAPSHOT)
  const [plan, setPlan] = useState<MigrationPlan | null>(null)
  const [planLoading, setPlanLoading] = useState(false)
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)

  const fetchSnapshot = useCallback(async () => {
    if (!token) return
    setState((current) => current === 'success' ? current : 'loading')
    try {
      const response = await fetch('/api/v1/dashboard/pqc-orchestration', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`)
      setSnapshot(payload.data || EMPTY_SNAPSHOT)
      setState('success')
      setError(null)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to load PQC orchestration telemetry'
      console.error('PQC orchestration telemetry failed:', err)
      setError(message)
      setState('error')
    }
  }, [token])

  const queueHndlRemediation = useCallback(async (findingId?: string) => {
    if (!token) throw new Error('Authentication required')
    const response = await fetch('/api/v1/dashboard/pqc-orchestration/hndl-remediation', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(findingId ? { findingId } : {}),
    })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`)
    await fetchSnapshot()
    return payload?.data || { created: 0 }
  }, [token, fetchSnapshot])

  const fetchPlan = useCallback(async () => {
    if (!token || !planId) {
      setPlan(null)
      setPlanLoading(false)
      return
    }
    setPlanLoading(true)
    try {
      const response = await fetch(`/api/v1/migration/plans/${encodeURIComponent(planId)}`, {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`)
      setPlan(payload.data || null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load approved migration plan')
      setPlan(null)
    } finally {
      setPlanLoading(false)
    }
  }, [planId, token])

  const runPlanAction = useCallback(async (action: 'start_execution' | 'pause' | 'resume' | 'rollback' | 'approve_next_phase') => {
    if (!token || !planId) throw new Error('Migration plan is required')
    const response = await fetch(`/api/v1/migration/plans/${encodeURIComponent(planId)}/action`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ action }),
    })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`)
    if (payload.data?.plan) setPlan(payload.data.plan)
    await fetchSnapshot()
    return payload.data
  }, [fetchSnapshot, planId, token])

  useEffect(() => {
    if (!token || !user) return
    fetchSnapshot()
    void fetchPlan()
  }, [token, user, fetchSnapshot, fetchPlan])

  useEffect(() => {
    if (!user) return
    const tables = [
      'assets',
      'crypto_inventory',
      'crypto_exposures',
      'migration_jobs',
      'migration_plans',
      'migration_events',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'security_events',
      'compliance_evidence',
    ]

    const channels = tables.map((table) => supabase
      .channel(`pqc-orchestration-${table}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` },
        () => {
          void fetchSnapshot()
          if (table === 'migration_plans') void fetchPlan()
        }
      )
      .subscribe())

    return () => {
      for (const channel of channels) {
        supabase.removeChannel(channel)
      }
    }
  }, [user, fetchSnapshot, fetchPlan])

  useEffect(() => {
    if (!token) return
    let retryTimer: ReturnType<typeof setTimeout> | undefined

    const connect = () => {
      const eventSource = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`)
      eventSourceRef.current = eventSource
      eventSource.onopen = () => setSseConnected(true)
      eventSource.onerror = () => {
        setSseConnected(false)
        eventSource.close()
        retryTimer = setTimeout(connect, 10000)
      }
      eventSource.addEventListener('metrics-update', fetchSnapshot)
      eventSource.addEventListener('scan-complete', fetchSnapshot)
    }

    connect()
    return () => {
      if (retryTimer) clearTimeout(retryTimer)
      eventSourceRef.current?.close()
      eventSourceRef.current = null
      setSseConnected(false)
    }
  }, [token, fetchSnapshot])

  return { snapshot, state, error, sseConnected, refresh: fetchSnapshot, queueHndlRemediation, plan, planLoading, refreshPlan: fetchPlan, runPlanAction }
}

function GlassPanel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={cn(GLASS_PANEL_CLASSES, className)}>
      <div className="relative z-10 h-full">{children}</div>
    </section>
  )
}

function HeaderButton({ icon: Icon, children, href, onClick, primary }: { icon: LucideIcon; children: string; href?: string; onClick?: () => void; primary?: boolean }) {
  const classes = cn(
    'inline-flex h-9 items-center justify-center gap-2 rounded-md border px-4 text-[10px] font-black uppercase tracking-[0.14em] transition',
    primary
      ? 'border-gold/70 bg-gold text-black shadow-[0_0_24px_rgba(255,211,107,0.45)] hover:bg-[#FFE8A8]'
      : 'border-gold/20 bg-black/20 text-white/70 hover:border-gold/60 hover:bg-gold/10 hover:text-gold'
  )

  if (href) {
    return (
      <a className={classes} href={href}>
        <Icon className="h-3.5 w-3.5" />
        {children}
      </a>
    )
  }

  return (
    <button className={classes} type="button" onClick={onClick}>
      <Icon className="h-3.5 w-3.5" />
      {children}
    </button>
  )
}

function WorkflowActionLink({ href, label, detail, children }: { href: string; label: string; detail: string; children: ReactNode }) {
  const [open, setOpen] = useState(false)

  return (
    <a
      href={href}
      aria-label={`${label}. ${detail}`}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      className="relative flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-black/20 text-white/55 transition hover:border-gold/40 hover:text-gold focus-visible:border-gold focus-visible:outline-none"
    >
      <span className="sr-only">{label}</span>
      {children}
      {open && (
        <span className="pointer-events-none absolute right-0 top-9 z-30 w-72 rounded-md border border-gold/25 bg-[#080c19] p-3 text-left shadow-[0_18px_45px_rgba(0,0,0,0.45)]">
          <span className="block text-[9px] font-black uppercase tracking-[0.18em] text-gold">{label}</span>
          <span className="mt-1 block whitespace-normal text-[11px] font-semibold leading-relaxed text-white/72">{detail}</span>
        </span>
      )}
    </a>
  )
}

function SectionTitle({ icon: Icon, children, suffix }: { icon: LucideIcon; children: ReactNode; suffix?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-4">
      <h2 className="flex min-w-0 items-center gap-2 text-[11px] font-black uppercase tracking-[0.22em] text-gold">
        <Icon className="h-4 w-4 shrink-0" />
        <span className="truncate">{children}</span>
      </h2>
      {suffix}
    </div>
  )
}

function MetricCard({ label, value, detail, icon: Icon, tone }: { label: string; value: string; detail: string; icon: LucideIcon; tone: 'gold' | 'green' | 'red' }) {
  const toneClasses = {
    gold: 'border-gold/40 bg-gold/10 text-gold',
    green: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
    red: 'border-red-500/40 bg-red-500/10 text-red-300',
  }

  return (
    <GlassPanel className="p-4">
      <div className="flex items-center gap-4">
        <div className={cn('flex h-12 w-12 shrink-0 items-center justify-center rounded-full border', toneClasses[tone])}>
          <Icon className="h-6 w-6" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[9px] font-black uppercase tracking-[0.22em] text-white/45">{label}</div>
          <div className="mt-2 text-3xl font-black leading-none text-white">{value}</div>
          <div className={cn('mt-2 text-[9px] font-bold', tone === 'red' ? 'text-red-300' : tone === 'green' ? 'text-emerald-300' : 'text-gold')}>
            {detail}
          </div>
        </div>
      </div>
    </GlassPanel>
  )
}

function ProgressBar({ value, color = GOLD }: { value: number; color?: string }) {
  return (
    <div className="h-2 overflow-hidden rounded-full bg-white/10">
      <div className="h-full rounded-full shadow-[0_0_12px_rgba(255,211,107,0.55)]" style={{ width: `${clamp(value)}%`, backgroundColor: color }} />
    </div>
  )
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex min-h-[180px] items-center justify-center rounded-lg border border-dashed border-white/10 bg-white/[0.02] text-center">
      <div>
        <Radio className="mx-auto mb-3 h-6 w-6 text-white/25" />
        <p className="text-xs font-bold text-white/45">{label}</p>
      </div>
    </div>
  )
}

function ReadinessDonut({ data }: { data: ReadinessBreakdown }) {
  const total = Math.max(1, data.pqcEnabled + data.hybridMode + data.legacy + data.notAssessed)
  const pqcDeg = (data.pqcEnabled / total) * 360
  const hybridDeg = pqcDeg + (data.hybridMode / total) * 360
  const legacyDeg = hybridDeg + (data.legacy / total) * 360
  const background = `conic-gradient(${GREEN} 0deg ${pqcDeg}deg, ${GOLD} ${pqcDeg}deg ${hybridDeg}deg, ${RED} ${hybridDeg}deg ${legacyDeg}deg, ${SLATE} ${legacyDeg}deg 360deg)`

  return (
    <div className="relative flex h-32 w-32 shrink-0 items-center justify-center rounded-full" style={{ background }}>
      <div className="absolute inset-3 rounded-full bg-[#0b1020]" />
      <div className="relative text-center">
        <div className="text-3xl font-black text-white">{data.score}%</div>
        <div className="text-[10px] font-bold text-emerald-300">{data.score >= 70 ? 'Good' : data.score ? 'At Risk' : 'No Data'}</div>
      </div>
    </div>
  )
}

function exportJson(name: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `${name}-${new Date().toISOString().slice(0, 10)}.json`
  anchor.click()
  URL.revokeObjectURL(url)
}

export default function PqcOrchestration() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const planId = searchParams.get('planId')
  const { snapshot, state, error, sseConnected, refresh, queueHndlRemediation, plan, planLoading, runPlanAction } = usePqcOrchestrationSnapshot(planId)
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('all')
  const [type, setType] = useState('all')
  const [environment, setEnvironment] = useState('all')
  const [actionPending, setActionPending] = useState('')
  const [planActionPending, setPlanActionPending] = useState('')
  const [notice, setNotice] = useState('')
  const [workflowPage, setWorkflowPage] = useState(1)
  const [showAllWorkflows, setShowAllWorkflows] = useState(false)

  const metrics = snapshot.metrics
  const hndlSummary = snapshot.hndlRemediation || EMPTY_SNAPSHOT.hndlRemediation
  const generatedAt = snapshot.generatedAt ? new Date(snapshot.generatedAt) : new Date()
  const types = useMemo(() => Array.from(new Set(snapshot.workflowQueue.map((workflow) => workflow.assetType).filter(Boolean))).sort(), [snapshot.workflowQueue])
  const environments = useMemo(() => Array.from(new Set(snapshot.workflowQueue.map((workflow) => workflow.environment).filter(Boolean))).sort(), [snapshot.workflowQueue])
  const visibleWorkflows = useMemo(() => snapshot.workflowQueue.filter((workflow) => {
    const haystack = `${workflow.name} ${workflow.subtitle} ${workflow.assetName} ${workflow.targetAlgorithm}`.toLowerCase()
    return (!search || haystack.includes(search.toLowerCase()))
      && (status === 'all' || workflow.status === status)
      && (type === 'all' || workflow.assetType === type)
      && (environment === 'all' || workflow.environment === environment)
  }), [snapshot.workflowQueue, search, status, type, environment])
  const workflowPageCount = Math.max(1, Math.ceil(visibleWorkflows.length / WORKFLOW_PAGE_SIZE))
  const safeWorkflowPage = Math.min(workflowPage, workflowPageCount)
  const workflowStartIndex = showAllWorkflows ? 0 : (safeWorkflowPage - 1) * WORKFLOW_PAGE_SIZE
  const workflowEndIndex = showAllWorkflows ? visibleWorkflows.length : Math.min(workflowStartIndex + WORKFLOW_PAGE_SIZE, visibleWorkflows.length)
  const pagedWorkflows = showAllWorkflows ? visibleWorkflows : visibleWorkflows.slice(workflowStartIndex, workflowEndIndex)
  const workflowPageNumbers = useMemo(() => {
    const totalButtons = Math.min(5, workflowPageCount)
    const firstPage = Math.max(1, Math.min(safeWorkflowPage - 2, workflowPageCount - totalButtons + 1))
    return Array.from({ length: totalButtons }, (_, index) => firstPage + index)
  }, [safeWorkflowPage, workflowPageCount])

  useEffect(() => {
    setWorkflowPage(1)
  }, [search, status, type, environment, showAllWorkflows])

  useEffect(() => {
    if (workflowPage > workflowPageCount) setWorkflowPage(workflowPageCount)
  }, [workflowPage, workflowPageCount])

  const metricCards = [
    { label: 'Active Workflows', value: numberFmt(metrics.activeWorkflows), detail: metrics.hndlPending ? `${numberFmt(metrics.pendingWorkflows)} pending | ${numberFmt(metrics.hndlPending)} HNDL` : `${numberFmt(metrics.pendingWorkflows)} pending`, icon: Layers3, tone: 'gold' as const },
    { label: 'Running Jobs', value: numberFmt(metrics.runningJobs), detail: `${numberFmt(metrics.activeScans)} active scans`, icon: Play, tone: 'green' as const },
    { label: 'Failed Tasks', value: numberFmt(metrics.failedTasks), detail: 'requires attention', icon: X, tone: 'red' as const },
    { label: 'PQC Readiness', value: `${metrics.pqcReadiness}%`, detail: `${numberFmt(metrics.totalAssets)} assets tracked`, icon: ShieldCheck, tone: 'green' as const },
  ]

  const queueHndl = useCallback(async (findingId?: string) => {
    const key = findingId ? `hndl:${findingId}` : 'hndl:all'
    setActionPending(key)
    setNotice('')
    try {
      const result = await queueHndlRemediation(findingId)
      const created = Number(result?.created || 0)
      setNotice(created > 0
        ? `${numberFmt(created)} HNDL remediation workflow${created === 1 ? '' : 's'} queued into migration jobs.`
        : 'No unqueued HNDL remediation findings remain.')
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'Unable to queue HNDL remediation workflows.')
    } finally {
      setActionPending('')
    }
  }, [queueHndlRemediation])

  const applyPlanAction = useCallback(async (action: 'start_execution' | 'pause' | 'resume' | 'rollback' | 'approve_next_phase') => {
    setPlanActionPending(action)
    setNotice('')
    try {
      const result = await runPlanAction(action)
      setNotice(`${action.replace(/_/g, ' ')} applied to ${numberFmt(result?.affected || 0)} linked migration job(s).`)
      if (action === 'start_execution') {
        navigate(result?.liveMigrationUrl || `/dashboard/live-migration${planId ? `?planId=${encodeURIComponent(planId)}` : ''}`)
      }
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'Unable to apply orchestration action.')
    } finally {
      setPlanActionPending('')
    }
  }, [navigate, planId, runPlanAction])

  return (
    <main className="min-h-screen space-y-4 p-3 text-white lg:p-5">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <h1 className="text-3xl font-black uppercase leading-none tracking-[0.02em] text-white md:text-4xl">
            PQC <span className="font-mono text-gold">Orchestration</span>
          </h1>
          <p className="mt-2 max-w-2xl text-sm font-medium text-white/55">
            Centralized orchestration for post-quantum cryptographic operations.
          </p>
          {error && <p className="mt-2 text-xs font-semibold text-red-300">Telemetry warning: {error}</p>}
        </div>

        <div className="flex flex-wrap items-center justify-start gap-3 xl:justify-end">
          <button
            type="button"
            onClick={refresh}
            className="inline-flex h-9 items-center gap-2 rounded-md border border-gold/20 bg-black/20 px-4 text-[10px] font-black uppercase tracking-[0.14em] text-white/70 transition hover:border-gold/60 hover:bg-gold/10 hover:text-gold"
          >
            <span className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_12px_rgba(34,197,94,0.9)]' : 'bg-slate-500')} />
            {sseConnected ? 'Live Telemetry' : state === 'loading' ? 'Syncing' : 'Refresh'}
          </button>
          <HeaderButton icon={Download} onClick={() => exportJson('pqc-orchestration-report', snapshot)}>Export Report</HeaderButton>
          {hndlSummary.pendingFindings > 0 && (
            <button
              type="button"
              disabled={actionPending === 'hndl:all'}
              onClick={() => queueHndl()}
              className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-red-400/50 bg-red-500/15 px-4 text-[10px] font-black uppercase tracking-[0.14em] text-red-100 transition hover:border-gold/70 hover:bg-gold/10 hover:text-gold disabled:cursor-wait disabled:opacity-60"
            >
              <AlertTriangle className="h-3.5 w-3.5" />
              {actionPending === 'hndl:all' ? 'Queuing HNDL' : `Queue HNDL (${numberFmt(hndlSummary.pendingFindings)})`}
            </button>
          )}
          <HeaderButton icon={Plus} href="/dashboard/migration-planner" primary>New Orchestration</HeaderButton>
          <HeaderButton icon={Play} onClick={() => planId ? void applyPlanAction('start_execution') : navigate('/dashboard/live-migration')}>Start Execution</HeaderButton>
          <HeaderButton icon={Pause} onClick={() => planId ? void applyPlanAction('pause') : navigate('/dashboard/live-migration')}>Pause</HeaderButton>
          <HeaderButton icon={ShieldCheck} onClick={() => planId ? void applyPlanAction('approve_next_phase') : undefined}>Approve Phase</HeaderButton>
          <HeaderButton icon={X} onClick={() => planId ? void applyPlanAction('rollback') : undefined}>Rollback</HeaderButton>
          <div className="hidden items-center gap-2 pl-1 xl:flex">
            <Clock3 className="h-5 w-5 text-gold" />
            <div className="font-mono text-[10px] font-bold uppercase text-white/60">
              <div>{generatedAt.toLocaleTimeString('en-US', { hour12: false })} UTC</div>
              <div className="text-white/35">{generatedAt.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })}</div>
            </div>
          </div>
          <button className="hidden h-9 w-9 items-center justify-center rounded-full border border-gold/20 text-gold xl:inline-flex" type="button" onClick={refresh} aria-label="Refresh orchestration telemetry">
            <Sparkles className="h-4 w-4" />
          </button>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {metricCards.map((metric) => (
          <div key={metric.label}>
            <MetricCard
              label={metric.label}
              value={metric.value}
              detail={metric.detail}
              icon={metric.icon}
              tone={metric.tone}
            />
          </div>
        ))}
      </div>

      {(planId || planLoading || plan) && (
        <GlassPanel className="p-4">
          <div className="relative z-10 grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,0.9fr)]">
            <div>
              <SectionTitle
                icon={ListChecks}
                suffix={<a href={plan?.liveMigrationUrl || `/dashboard/live-migration${planId ? `?planId=${encodeURIComponent(planId)}` : ''}`} className="rounded border border-gold/25 px-3 py-1.5 text-[10px] font-black uppercase tracking-widest text-gold hover:bg-gold/10">Live Migration</a>}
              >
                Approved Migration Plan
              </SectionTitle>
              {planLoading ? (
                <div className="text-xs font-bold text-white/45">Loading approved plan...</div>
              ) : plan ? (
                <div className="grid gap-3 md:grid-cols-5">
                  {[
                    ['Plan ID', plan.id],
                    ['Status', plan.status],
                    ['Assets', numberFmt(plan.selectedAssets.length)],
                    ['Strategy', plan.configuration.deploymentStrategy || 'Unspecified'],
                    ['Targets', (plan.configuration.targetAlgorithms || []).join(', ') || 'Unspecified'],
                    ['Controls', `${Object.values(plan.configuration.controls || {}).filter((enabled) => enabled !== false).length} enabled`],
                    ['Tags', (plan.configuration.tags || []).join(', ') || 'All assets'],
                    ['Complexity', `${Number(plan.riskData.migrationComplexityScore || 0)}/100`],
                  ].map(([label, value]) => (
                    <div key={label} className="rounded-md border border-white/8 bg-black/24 p-3">
                      <div className="text-[8px] font-black uppercase tracking-widest text-white/35">{label}</div>
                      <div className="mt-1 truncate text-xs font-black text-white/80">{value}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs font-bold text-red-300">Plan {planId} could not be loaded for this authenticated user.</div>
              )}
            </div>
            <div className="grid grid-cols-2 gap-2 md:grid-cols-5 xl:grid-cols-2">
              {[
                { action: 'start_execution', label: 'Start Execution', icon: Play },
                { action: 'pause', label: 'Pause', icon: Pause },
                { action: 'resume', label: 'Resume', icon: Radio },
                { action: 'approve_next_phase', label: 'Approve Next Phase', icon: ShieldCheck },
                { action: 'rollback', label: 'Rollback', icon: X },
              ].map(({ action, label, icon: Icon }) => (
                <button
                  key={action}
                  type="button"
                  disabled={!planId || Boolean(planActionPending)}
                  onClick={() => void applyPlanAction(action as 'start_execution' | 'pause' | 'resume' | 'rollback' | 'approve_next_phase')}
                  className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-gold/25 bg-gold/8 px-3 py-2 text-[9px] font-black uppercase tracking-widest text-gold transition hover:border-gold/60 hover:bg-gold/14 disabled:cursor-wait disabled:opacity-45"
                >
                  <Icon className="h-3.5 w-3.5" />
                  {planActionPending === action ? 'Applying' : label}
                </button>
              ))}
            </div>
          </div>
        </GlassPanel>
      )}

      {(hndlSummary.pendingFindings > 0 || notice) && (
        <GlassPanel className="border-red-500/30 bg-red-950/20 p-4">
          <div className="relative z-10 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-start gap-3">
              <div className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-red-400/50 bg-red-500/15 text-red-300">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div>
                <p className="text-xs font-black uppercase tracking-[0.18em] text-red-300">Harvest Now Remediation Queue</p>
                <p className="mt-1 text-sm font-semibold text-white/68">
                  {hndlSummary.pendingFindings > 0
                    ? `${numberFmt(hndlSummary.pendingFindings)} active HNDL finding${hndlSummary.pendingFindings === 1 ? '' : 's'} are staged as remediation workflows from live scanner telemetry.`
                    : 'Harvest Now findings have been linked to migration jobs.'}
                </p>
                {notice && <p className="mt-2 text-xs font-bold text-gold">{notice}</p>}
              </div>
            </div>
            {hndlSummary.pendingFindings > 0 && (
              <button
                type="button"
                disabled={actionPending === 'hndl:all'}
                onClick={() => queueHndl()}
                className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-gold/40 bg-gold/10 px-4 text-[10px] font-black uppercase tracking-[0.14em] text-gold transition hover:border-gold/70 hover:bg-gold/20 disabled:cursor-wait disabled:opacity-60"
              >
                <Play className="h-3.5 w-3.5" />
                {actionPending === 'hndl:all' ? 'Creating Jobs' : 'Create Linked Jobs'}
              </button>
            )}
          </div>
        </GlassPanel>
      )}

      <div className="space-y-4">
        <GlassPanel className="p-4">
          <SectionTitle
            icon={Radio}
            suffix={<a href="/dashboard/live-migration" className="rounded border border-gold/25 px-3 py-1.5 text-[10px] font-black uppercase tracking-widest text-gold hover:bg-gold/10">View Details</a>}
          >
            Live Execution <span className="ml-2 text-[10px] text-white/35">Workflow ID: {snapshot.liveExecution?.workflowId?.slice(0, 12) || 'none'}</span>
          </SectionTitle>
          {snapshot.liveExecution ? (
            <div>
              <div className="flex flex-col gap-4 border-b border-white/5 pb-4 md:flex-row md:items-start md:justify-between">
                <div>
                  <h3 className="text-lg font-black text-white">{snapshot.liveExecution.name}</h3>
                  <div className="mt-4 grid gap-4 text-xs md:grid-cols-4">
                    <div>
                      <div className="text-[9px] uppercase tracking-widest text-white/35">Current Step</div>
                      <div className="mt-1 font-bold text-white/80">{snapshot.liveExecution.currentStep}</div>
                    </div>
                    <div>
                      <div className="text-[9px] uppercase tracking-widest text-white/35">Algorithm Transition</div>
                      <div className="mt-1 font-bold text-white/80">{snapshot.liveExecution.algorithmTransition}</div>
                    </div>
                    <div>
                      <div className="text-[9px] uppercase tracking-widest text-white/35">Progress</div>
                      <div className="mt-1 flex items-center gap-2">
                        <div className="w-24"><ProgressBar value={snapshot.liveExecution.progress} /></div>
                        <span className="font-mono text-white/65">{snapshot.liveExecution.progress}%</span>
                      </div>
                    </div>
                    <div>
                      <div className="text-[9px] uppercase tracking-widest text-white/35">ETA</div>
                      <div className="mt-1 font-bold text-white/80">{snapshot.liveExecution.eta}</div>
                    </div>
                  </div>
                </div>
                <span className={cn('rounded border px-3 py-1 text-[10px] font-black uppercase tracking-wider', statusClass(statusLabel(snapshot.liveExecution.status)))}>{statusLabel(snapshot.liveExecution.status)}</span>
              </div>
              <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-5">
                {snapshot.liveExecution.stages.map((stage, index) => (
                  <div key={stage.key} className="relative text-center">
                    {index < snapshot.liveExecution!.stages.length - 1 && <div className="absolute left-1/2 top-4 hidden h-px w-full bg-gold/20 md:block" />}
                    <div className={cn(
                      'relative mx-auto flex h-8 w-8 items-center justify-center rounded-full border',
                      stage.state === 'completed' && 'border-emerald-500 bg-emerald-500/10 text-emerald-300',
                      stage.state === 'active' && 'border-gold bg-gold/10 text-gold',
                      stage.state === 'failed' && 'border-red-500 bg-red-500/10 text-red-300',
                      stage.state === 'pending' && 'border-white/15 bg-black/30 text-white/35'
                    )}>
                      {stage.state === 'completed' ? <CheckCircle2 className="h-4 w-4" /> : stage.state === 'failed' ? <X className="h-4 w-4" /> : <ListChecks className="h-4 w-4" />}
                    </div>
                    <div className="mt-2 text-[10px] font-black text-white/70">{stage.label}</div>
                    <div className={cn('mt-1 text-[9px] font-bold', stage.state === 'completed' ? 'text-emerald-300' : stage.state === 'active' ? 'text-gold' : stage.state === 'failed' ? 'text-red-300' : 'text-white/35')}>
                      {stage.state === 'completed' ? 'Completed' : stage.state === 'active' ? 'In Progress' : stage.state === 'failed' ? 'Failed' : 'Pending'}
                    </div>
                    <div className="mt-0.5 text-[9px] font-mono text-white/25">{timeOnly(stage.timestamp)}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState label="No active or scheduled orchestration workflow yet." />
          )}
        </GlassPanel>

        <GlassPanel className="p-4">
          <SectionTitle icon={Workflow}>Workflow Queue</SectionTitle>
          <div className="mb-3 grid gap-2 md:grid-cols-[1fr_110px_110px_140px_36px]">
            <label className="relative block">
              <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/35" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                className="h-9 w-full rounded-md border border-white/10 bg-black/25 pl-9 pr-3 text-xs text-white outline-none placeholder:text-white/35 focus:border-gold/50"
                placeholder="Search workflows..."
              />
            </label>
            <select value={status} onChange={(event) => setStatus(event.target.value)} className="h-9 rounded-md border border-white/10 bg-black/25 px-3 text-xs text-white outline-none focus:border-gold/50">
              <option value="all">All Status</option>
              <option value="running">Running</option>
              <option value="pending">Pending</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="paused">Paused</option>
            </select>
            <select value={type} onChange={(event) => setType(event.target.value)} className="h-9 rounded-md border border-white/10 bg-black/25 px-3 text-xs text-white outline-none focus:border-gold/50">
              <option value="all">All Types</option>
              {types.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
            <select value={environment} onChange={(event) => setEnvironment(event.target.value)} className="h-9 rounded-md border border-white/10 bg-black/25 px-3 text-xs text-white outline-none focus:border-gold/50">
              <option value="all">All Environments</option>
              {environments.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
            <button className="flex h-9 items-center justify-center rounded-md border border-gold/20 bg-black/25 text-gold" type="button" aria-label="Filter workflow queue">
              <Filter className="h-4 w-4" />
            </button>
          </div>

          {visibleWorkflows.length === 0 ? (
            <EmptyState label="No workflows match the current telemetry filters." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-gold/15">
                    {['Workflow Name', 'Environment', 'Progress', 'Status', 'Priority', 'ETA', 'Actions'].map((header) => (
                      <th key={header} className="px-3 py-3 text-[9px] font-black uppercase tracking-[0.18em] text-gold/80">{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {pagedWorkflows.map((workflow) => {
                    const liveMigrationHref = `/dashboard/live-migration${planId ? `?planId=${encodeURIComponent(planId)}` : ''}`
                    const primaryActionLabel = workflow.status === 'running' ? 'Pause workflow' : 'Open execution'
                    const primaryActionDetail = workflow.status === 'running'
                      ? `Opens Live Migration for ${workflow.name}, where operators can pause, roll back, inspect telemetry, and review execution logs.`
                      : `Opens Live Migration for ${workflow.name}, where operators can start/resume execution, inspect progress, and validate telemetry.`
                    return (
                    <tr key={workflow.id} className="transition hover:bg-gold/[0.04]">
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-3">
                          <div className="flex h-7 w-7 items-center justify-center rounded-md border border-gold/30 bg-gold/10 text-gold">
                            <Workflow className="h-3.5 w-3.5" />
                          </div>
                          <div>
                            <div className="text-xs font-black text-white/90">{workflow.name}</div>
                            <div className="mt-0.5 text-[9px] text-white/35">{workflow.subtitle}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-[9px] font-black uppercase text-emerald-300">{workflow.environment}</span>
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-24"><ProgressBar value={workflow.progress} /></div>
                          <span className="font-mono text-xs text-white/55">{workflow.progress}%</span>
                        </div>
                      </td>
                      <td className="px-3 py-3"><span className={cn('rounded border px-2 py-1 text-[9px] font-black uppercase tracking-wider', statusClass(statusLabel(workflow.status)))}>{statusLabel(workflow.status)}</span></td>
                      <td className={cn('px-3 py-3 text-xs font-black', priorityClass(workflow.priority))}>{workflow.priority}</td>
                      <td className="px-3 py-3 font-mono text-xs text-white/55">{workflow.eta}</td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-2">
                          {workflow.source === 'harvest-now' && workflow.materialized === false ? (
                            <button
                              type="button"
                              disabled={!workflow.sourceFindingId || actionPending === `hndl:${workflow.sourceFindingId}`}
                              onClick={() => workflow.sourceFindingId && queueHndl(workflow.sourceFindingId)}
                              className="inline-flex h-7 items-center justify-center rounded border border-red-400/40 bg-red-500/10 px-2 text-[9px] font-black uppercase tracking-wider text-red-200 transition hover:border-gold/50 hover:bg-gold/10 hover:text-gold disabled:cursor-wait disabled:opacity-60"
                              aria-label={`Queue remediation job for ${workflow.name}. Creates a linked migration job from the active HNDL finding.`}
                            >
                              {actionPending === `hndl:${workflow.sourceFindingId}` ? 'Queuing' : 'Queue'}
                            </button>
                          ) : (
                            <>
                              <WorkflowActionLink href={liveMigrationHref} label={primaryActionLabel} detail={primaryActionDetail}>
                                {workflow.status === 'running' ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
                              </WorkflowActionLink>
                              <WorkflowActionLink
                                href={liveMigrationHref}
                                label="Workflow details"
                                detail={`Opens Live Migration details for ${workflow.name}: execution state, agent telemetry, migration events, validation evidence, rollback controls, and exports.`}
                              >
                                <MoreHorizontal className="h-3.5 w-3.5" />
                              </WorkflowActionLink>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
          <div className="mt-3 flex flex-col gap-3 border-t border-gold/10 pt-3 text-xs text-white/45 md:flex-row md:items-center md:justify-between">
            <span>
              {visibleWorkflows.length === 0
                ? 'Showing 0 results'
                : showAllWorkflows
                  ? `Showing all ${numberFmt(visibleWorkflows.length)} results`
                  : `Showing ${numberFmt(workflowStartIndex + 1)} to ${numberFmt(workflowEndIndex)} of ${numberFmt(visibleWorkflows.length)} results`}
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={showAllWorkflows || safeWorkflowPage <= 1}
                onClick={() => setWorkflowPage((page) => Math.max(1, page - 1))}
                className="h-9 rounded-md border border-white/10 bg-black/20 px-3 text-[10px] font-bold text-white/45 transition hover:border-gold/40 hover:text-gold disabled:cursor-not-allowed disabled:opacity-35"
              >
                Prev
              </button>
              {!showAllWorkflows && workflowPageNumbers.map((page) => (
                <button
                  key={page}
                  type="button"
                  onClick={() => setWorkflowPage(page)}
                  className={cn(
                    'h-9 min-w-9 rounded-md border px-3 text-[11px] font-bold transition',
                    page === safeWorkflowPage
                      ? 'border-gold bg-gold/10 text-gold shadow-[0_0_18px_rgba(255,211,107,0.18)]'
                      : 'border-white/10 bg-black/20 text-white/45 hover:border-gold/40 hover:text-gold',
                  )}
                >
                  {page}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setShowAllWorkflows((value) => !value)}
                className={cn(
                  'h-9 rounded-md border px-3 text-[10px] font-black uppercase tracking-wider transition',
                  showAllWorkflows
                    ? 'border-gold bg-gold/10 text-gold'
                    : 'border-white/10 bg-black/20 text-white/45 hover:border-gold/40 hover:text-gold',
                )}
              >
                {showAllWorkflows ? 'Show 5' : 'Show All'}
              </button>
              <button
                type="button"
                disabled={showAllWorkflows || safeWorkflowPage >= workflowPageCount}
                onClick={() => setWorkflowPage((page) => Math.min(workflowPageCount, page + 1))}
                className="h-9 rounded-md border border-white/10 bg-black/20 px-3 text-[10px] font-bold text-white/45 transition hover:border-gold/40 hover:text-gold disabled:cursor-not-allowed disabled:opacity-35"
              >
                Next
              </button>
            </div>
          </div>
        </GlassPanel>

        <GlassPanel className="p-4">
          <SectionTitle
            icon={Terminal}
            suffix={<button type="button" onClick={() => exportJson('pqc-orchestration-logs', snapshot.telemetryLogs)} className="rounded border border-gold/25 px-3 py-1.5 text-[10px] font-black uppercase tracking-widest text-gold hover:bg-gold/10">Download Logs</button>}
          >
            Live Telemetry
          </SectionTitle>
          {snapshot.telemetryLogs.length === 0 ? (
            <EmptyState label="No orchestration logs have been emitted for this user yet." />
          ) : (
            <div className="max-h-[188px] space-y-2 overflow-y-auto rounded-md border border-white/5 bg-black/25 p-3 font-mono text-[11px]">
              {snapshot.telemetryLogs.map((log) => (
                <div key={log.id} className="grid grid-cols-[82px_1fr_32px] gap-2 text-white/55">
                  <span>[{timeOnly(log.timestamp)}]</span>
                  <span className="truncate">{log.message}</span>
                  <span className={cn('text-right font-black', log.severity === 'success' ? 'text-emerald-300' : log.severity === 'critical' || log.severity === 'error' ? 'text-red-300' : 'text-gold')}>{log.severity === 'success' ? 'OK' : log.severity.toUpperCase().slice(0, 4)}</span>
                </div>
              ))}
            </div>
          )}
        </GlassPanel>
      </div>

      <GlassPanel className="p-4">
        <SectionTitle icon={SlidersHorizontal} suffix={<a href="/dashboard/live-migration" className="rounded border border-gold/25 px-3 py-1.5 text-[10px] font-black uppercase tracking-widest text-gold hover:bg-gold/10">View All Tasks</a>}>
          Task Queue
        </SectionTitle>
        {snapshot.taskQueue.length === 0 ? (
          <EmptyState label="No pending orchestration tasks. Findings and migration jobs will appear here." />
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {snapshot.taskQueue.map((task) => (
              <a key={task.id} href="/dashboard/live-migration" className="grid grid-cols-[1fr_86px_62px] items-center gap-4 rounded-md border border-white/5 bg-white/[0.02] p-3 transition hover:border-gold/35 hover:bg-gold/[0.05]">
                <div className="min-w-0">
                  <div className="truncate text-xs font-black text-white/80">{task.title}</div>
                  <div className={cn('mt-0.5 text-[10px] font-bold', priorityClass(task.priority))}>{task.priority}</div>
                </div>
                <div>
                  {task.progress > 0 ? <ProgressBar value={task.progress} /> : <span className="text-xs text-white/45">{task.status}</span>}
                </div>
                <div className="text-right">
                  <div className="text-[9px] uppercase text-white/30">ETA</div>
                  <div className="font-mono text-[10px] text-white/55">{task.eta}</div>
                </div>
              </a>
            ))}
          </div>
        )}
      </GlassPanel>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <GlassPanel className="p-4">
          <SectionTitle icon={ShieldCheck}>PQC Readiness Overview</SectionTitle>
          <div className="flex flex-col gap-6 md:flex-row md:items-center">
            <ReadinessDonut data={snapshot.readiness} />
            <div className="flex-1 space-y-3">
              {[
                ['PQC Enabled', snapshot.readiness.pqcEnabled, GREEN],
                ['Hybrid Mode', snapshot.readiness.hybridMode, GOLD],
                ['Legacy', snapshot.readiness.legacy, RED],
                ['Not Assessed', snapshot.readiness.notAssessed, SLATE],
              ].map(([label, count, color]) => {
                const percent = snapshot.readiness.totalAssets ? (Number(count) / Math.max(1, snapshot.readiness.totalAssets)) * 100 : 0
                return (
                  <div key={String(label)} className="grid grid-cols-[1fr_92px] items-center gap-3 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: String(color) }} />
                      <span className="text-white/65">{label}</span>
                    </div>
                    <span className="text-right font-mono text-white/65">{numberFmt(Number(count))} ({clamp(percent)}%)</span>
                  </div>
                )
              })}
            </div>
          </div>
          <div className="mt-5 border-t border-white/5 pt-4 text-xs text-white/55">Total Assets: {numberFmt(snapshot.readiness.totalAssets)}</div>
        </GlassPanel>

        <GlassPanel className="p-4">
          <SectionTitle icon={CheckCircle2}>Compliance Status</SectionTitle>
          {snapshot.compliance.length === 0 ? (
            <EmptyState label="No compliance evidence or telemetry-derived status is available yet." />
          ) : (
            <div className="space-y-3">
              {snapshot.compliance.map((item) => (
                <div key={item.label} className="flex items-center justify-between gap-4 border-b border-white/5 pb-2 last:border-b-0">
                  <div className="flex items-center gap-3">
                    <span className={cn('flex h-5 w-5 items-center justify-center rounded-full border', statusClass(item.status))}>
                      {item.status.toLowerCase().includes('non') || item.status.toLowerCase().includes('risk') ? <X className="h-3 w-3" /> : <CheckCircle2 className="h-3 w-3" />}
                    </span>
                    <span className="text-xs font-bold text-white/70">{item.label}</span>
                  </div>
                  <span className={cn('text-xs font-black', item.status.toLowerCase().includes('non') ? 'text-red-300' : item.status.toLowerCase().includes('risk') ? 'text-gold' : item.status.toLowerCase().includes('not') ? 'text-white/35' : 'text-emerald-300')}>{item.status}</span>
                </div>
              ))}
            </div>
          )}
          <a href="/dashboard/compliance" className="mt-4 inline-flex items-center gap-2 text-xs font-black text-gold hover:text-[#FFE8A8]">
            View Compliance Report <ArrowRight className="h-4 w-4" />
          </a>
        </GlassPanel>
      </div>

      <footer className="flex flex-col gap-2 border-t border-white/5 pt-3 text-[10px] font-mono uppercase tracking-wider text-white/30 md:flex-row md:items-center md:justify-between">
        <span>Snapshot: {generatedAt.toLocaleString()}</span>
        <span>Realtime: {sseConnected ? 'SSE connected' : 'waiting'} / Workflows: {numberFmt(snapshot.workflowQueue.length)}</span>
        <a href="/dashboard/migration_timeline" className="inline-flex items-center gap-2 text-gold hover:text-[#FFE8A8]">Open Migration Timeline <ExternalLink className="h-3.5 w-3.5" /></a>
      </footer>
    </main>
  )
}
