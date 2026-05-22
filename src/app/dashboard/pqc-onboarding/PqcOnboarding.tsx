import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  ArrowRight,
  Bell,
  Check,
  CheckCircle2,
  Circle,
  CircleHelp,
  ClipboardCheck,
  Database,
  Download,
  Eye,
  FileArchive,
  FileText,
  Headphones,
  MonitorCheck,
  RefreshCw,
  Rocket,
  ScanSearch,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  UsersRound,
  XCircle,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'

type LoadState = 'loading' | 'success' | 'error'
type StepStatus = 'completed' | 'current' | 'pending'
type TaskStatus = 'completed' | 'in_progress' | 'pending' | 'overdue'

type OnboardingStep = {
  id: number
  title: string
  href: string
  status: StepStatus
  progress: number
}

type StepOverview = {
  bullets: string[]
  tasksCompleted: number
  inProgress: number
  pending: number
  overdue: number
  totalTasks: number
}

type StepTask = {
  label: string
  detail: string
  href: string
  status: TaskStatus
  labelStatus: string
  tone: 'green' | 'blue' | 'amber' | 'red'
  count: number
  source: string
}

type ResourceItem = {
  title: string
  type: string
  href: string
}

type ActivityItem = {
  id: string
  type: string
  title: string
  actor: string
  timestamp: string | null
  severity: string
}

type ClientOverview = {
  name: string
  industry: string
  onboardingStartDate: string | null
  targetGoLive: string | null
  projectManager: string
  status: string
  avatarUrl: string | null
  email: string | null
}

type OnboardingMetrics = {
  assets: number
  assessedAssets: number
  findings: number
  criticalExposures: number
  highExposures: number
  riskScore: number
  readinessScore: number
  migrationJobs: number
  completedMigrations: number
  runningMigrations: number
  failedMigrations: number
  runtimeEvents: number
  runtimeEvents24h: number
  activeScans: number
  scannerAgents: number
  openAlerts: number
  generatedKeys: number
  certificates: number
  vulnerableCryptoItems: number
  coverageScore: number
}

type Benefit = {
  label: string
  value: string
  detail: string
  status: TaskStatus
}

type OnboardingSnapshot = {
  generatedAt: string | null
  currentStep: number
  currentStepTitle: string
  currentStepStatus: string
  nextStep: { title: string; href: string } | null
  overallProgress: number
  stepProgress: number
  steps: OnboardingStep[]
  stepOverview: StepOverview
  tasks: StepTask[]
  resources: ResourceItem[]
  activity: ActivityItem[]
  client: ClientOverview
  metrics: OnboardingMetrics
  benefits: Benefit[]
  sync: {
    userId: string
    sourceTables: Record<string, number>
  }
}

const EMPTY_SNAPSHOT: OnboardingSnapshot = {
  generatedAt: null,
  currentStep: 1,
  currentStepTitle: 'Awareness & Preparation',
  currentStepStatus: 'Preparing',
  nextStep: null,
  overallProgress: 0,
  stepProgress: 0,
  steps: [],
  stepOverview: { bullets: [], tasksCompleted: 0, inProgress: 0, pending: 0, overdue: 0, totalTasks: 0 },
  tasks: [],
  resources: [],
  activity: [],
  client: {
    name: 'Not configured',
    industry: 'Not configured',
    onboardingStartDate: null,
    targetGoLive: null,
    projectManager: 'Not assigned',
    status: 'Preparing',
    avatarUrl: null,
    email: null,
  },
  metrics: {
    assets: 0,
    assessedAssets: 0,
    findings: 0,
    criticalExposures: 0,
    highExposures: 0,
    riskScore: 0,
    readinessScore: 0,
    migrationJobs: 0,
    completedMigrations: 0,
    runningMigrations: 0,
    failedMigrations: 0,
    runtimeEvents: 0,
    runtimeEvents24h: 0,
    activeScans: 0,
    scannerAgents: 0,
    openAlerts: 0,
    generatedKeys: 0,
    certificates: 0,
    vulnerableCryptoItems: 0,
    coverageScore: 0,
  },
  benefits: [],
  sync: { userId: '', sourceTables: {} },
}

const STEP_VISUALS: Array<{ icon: LucideIcon; color: string; short: string }> = [
  { icon: UsersRound, color: '#d9ff00', short: 'Awareness' },
  { icon: ScanSearch, color: '#00d9ff', short: 'Discovery' },
  { icon: Shield, color: '#4f83ff', short: 'Risk' },
  { icon: Rocket, color: '#d763ff', short: 'Migration' },
  { icon: ShieldCheck, color: '#ff466c', short: 'Testing' },
  { icon: MonitorCheck, color: '#ffb000', short: 'Validation' },
]

const GLASS =
  'group relative overflow-hidden rounded-lg border border-[#FFD36B]/15 bg-[#07101d]/72 shadow-[inset_0_1px_0_rgba(255,255,255,0.07),0_12px_44px_rgba(0,0,0,0.38)] backdrop-blur-xl transition duration-300 hover:-translate-y-0.5 hover:border-[#FFD36B]/55 hover:bg-[#0b1628]/82 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.14),0_0_36px_rgba(255,211,107,0.24),0_18px_52px_rgba(0,0,0,0.5)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFE7A0]/55 before:to-transparent'

function clamp(value: number) {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, Math.round(value)))
}

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(value || 0)
}

function formatDate(value: string | null) {
  if (!value) return 'Not scheduled'
  return new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

function relativeTime(value: string | null) {
  if (!value) return 'No timestamp'
  const ms = Date.now() - new Date(value).getTime()
  if (!Number.isFinite(ms) || ms < 0) return new Date(value).toLocaleString()
  const minutes = Math.floor(ms / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes} mins ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} hours ago`
  return `${Math.floor(hours / 24)} days ago`
}

function statusTone(status: TaskStatus | StepStatus | string) {
  if (status === 'completed' || status === 'Monitoring') return 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10'
  if (status === 'current' || status === 'in_progress' || status === 'In Progress') return 'text-sky-300 border-sky-400/30 bg-sky-400/10'
  if (status === 'overdue' || status === 'Action Required') return 'text-red-300 border-red-500/30 bg-red-500/10'
  return 'text-amber-300 border-amber-400/30 bg-amber-400/10'
}

function severityTone(severity: string) {
  const value = severity.toLowerCase()
  if (value.includes('critical') || value.includes('high')) return '#ff466c'
  if (value.includes('medium') || value.includes('warning')) return '#ffb000'
  if (value.includes('success') || value.includes('low')) return '#19d66b'
  return '#1e9bff'
}

function downloadRoadmap(snapshot: OnboardingSnapshot) {
  const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `pqc-onboarding-roadmap-${new Date().toISOString().slice(0, 10)}.json`
  anchor.click()
  URL.revokeObjectURL(url)
}

function usePqcOnboardingSnapshot() {
  const { session, user } = useAuth()
  const token = session?.access_token
  const [snapshot, setSnapshot] = useState<OnboardingSnapshot | null>(null)
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState('')
  const [live, setLive] = useState(false)
  const streamsRef = useRef<EventSource[]>([])

  const fetchSnapshot = useCallback(async () => {
    if (!token) return
    try {
      setState((current) => (current === 'success' ? current : 'loading'))
      const response = await fetch('/api/v1/dashboard/pqc-onboarding', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`)
      setSnapshot(payload.data || EMPTY_SNAPSHOT)
      setState('success')
      setError('')
    } catch (err) {
      setState('error')
      setError(err instanceof Error ? err.message : 'Unable to load onboarding telemetry')
    }
  }, [token])

  useEffect(() => {
    if (!token || !user) return
    fetchSnapshot()
  }, [token, user, fetchSnapshot])

  useEffect(() => {
    if (!user) return
    const tables = [
      'profiles',
      'assets',
      'crypto_inventory',
      'crypto_exposures',
      'migration_jobs',
      'migration_events',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'security_events',
      'compliance_evidence',
      'runtime_crypto_events',
      'scanner_agents',
      'scanner_alerts',
      'generated_keys',
      'certificates',
    ]

    const channels = tables.map((table) => {
      const filter = table === 'profiles' ? `id=eq.${user.id}` : `user_id=eq.${user.id}`
      return supabase
        .channel(`pqc-onboarding-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter }, fetchSnapshot)
        .subscribe()
    })

    return () => {
      for (const channel of channels) supabase.removeChannel(channel)
    }
  }, [user, fetchSnapshot])

  useEffect(() => {
    if (!token) return
    const onboarding = new EventSource(`/api/v1/dashboard/pqc-onboarding/stream?token=${encodeURIComponent(token)}`)
    const metrics = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`)
    streamsRef.current = [onboarding, metrics]

    onboarding.onopen = () => setLive(true)
    onboarding.onerror = () => setLive(false)
    onboarding.addEventListener('pqc-onboarding-update', (event) => {
      try {
        setSnapshot(JSON.parse((event as MessageEvent).data))
        setState('success')
        setError('')
      } catch {
        fetchSnapshot()
      }
    })

    metrics.addEventListener('metrics-update', fetchSnapshot)
    metrics.addEventListener('runtime-crypto-update', fetchSnapshot)
    metrics.addEventListener('scan-complete', fetchSnapshot)
    metrics.onerror = () => setLive(false)

    return () => {
      streamsRef.current.forEach((stream) => stream.close())
      streamsRef.current = []
      setLive(false)
    }
  }, [token, fetchSnapshot])

  return { snapshot, state, error, live, refresh: fetchSnapshot }
}

function GlassPanel({ children, className }: { children: ReactNode; className?: string; key?: string | number }) {
  return (
    <section className={cn(GLASS, className)}>
      <div className="relative z-10 h-full">{children}</div>
    </section>
  )
}

function IconButton({ icon: Icon, label, alert }: { icon: LucideIcon; label: string; alert?: number }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className="relative flex h-10 w-10 items-center justify-center rounded-lg border border-white/10 bg-black/25 text-white/70 transition hover:border-gold/50 hover:bg-gold/10 hover:text-gold"
    >
      <Icon className="h-4 w-4" />
      {alert ? (
        <span className="absolute -right-1 -top-1 rounded-full bg-red-500 px-1.5 py-0.5 text-[8px] font-black text-white">{alert}</span>
      ) : null}
    </button>
  )
}

function ProfileChip({ client }: { client: ClientOverview }) {
  const initials = client.projectManager
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('') || 'U'

  return (
    <div className="flex items-center gap-3 rounded-lg border border-white/8 bg-black/20 px-3 py-2">
      <div className="relative h-9 w-9 overflow-hidden rounded-full border border-gold/25 bg-gold/10">
        {client.avatarUrl ? <img src={client.avatarUrl} alt="" className="h-full w-full object-cover" /> : (
          <div className="grid h-full w-full place-items-center text-xs font-black text-gold">{initials}</div>
        )}
        <span className="absolute bottom-0 right-0 h-2.5 w-2.5 rounded-full border border-[#07101d] bg-emerald-400" />
      </div>
      <div className="min-w-0">
        <div className="truncate text-xs font-black text-white">{client.projectManager}</div>
        <div className="truncate text-[10px] font-semibold text-white/45">{client.email || 'Tenant operator'}</div>
      </div>
    </div>
  )
}

function ProcessRail({ steps }: { steps: OnboardingStep[] }) {
  return (
    <GlassPanel className="p-3">
      <div className="grid min-w-[960px] grid-cols-6 gap-0 overflow-hidden rounded-lg lg:min-w-0">
        {steps.map((step, index) => {
          const visual = STEP_VISUALS[index] || STEP_VISUALS[0]
          const Icon = visual.icon
          const active = step.status === 'current'
          const complete = step.status === 'completed'
          const style = {
            '--step-color': visual.color,
            clipPath: 'polygon(8% 0, 92% 0, 100% 50%, 92% 100%, 8% 100%, 0 50%)',
          } as CSSProperties

          return (
            <Link
              key={step.id}
              to={step.href}
              style={style}
              className={cn(
                'group/step relative -ml-1 flex min-h-[154px] flex-col items-center justify-between border border-[color:var(--step-color)]/35 bg-black/20 px-4 py-5 text-center no-underline transition hover:z-10 hover:bg-[color:var(--step-color)]/[0.08] hover:shadow-[0_0_34px_var(--step-color)]',
                index === 0 && 'ml-0',
                active && 'bg-[color:var(--step-color)]/[0.10] shadow-[0_0_30px_var(--step-color)]',
                complete && 'bg-emerald-500/[0.04]',
              )}
            >
              <div className="pointer-events-none absolute inset-x-6 top-0 h-px bg-[color:var(--step-color)] shadow-[0_0_20px_var(--step-color)]" />
              <div>
                <Icon className="mx-auto h-9 w-9 text-[color:var(--step-color)] drop-shadow-[0_0_16px_var(--step-color)]" />
                <div className="mt-2 font-mono text-sm font-black text-[color:var(--step-color)]">{step.id}</div>
              </div>
              <div>
                <div className="text-[10px] font-black uppercase leading-snug tracking-[0.1em] text-white">{visual.short}</div>
                <div className="mt-1 text-[10px] font-black uppercase leading-snug tracking-[0.08em] text-white/90">{step.title.replace(`${visual.short} & `, '')}</div>
              </div>
              <div className="flex h-7 w-7 items-center justify-center rounded-full border border-[color:var(--step-color)] bg-[#07101d] text-[color:var(--step-color)] shadow-[0_0_18px_var(--step-color)]">
                {complete ? <Check className="h-4 w-4" /> : active ? <Circle className="h-3 w-3 fill-current" /> : <Circle className="h-4 w-4" />}
              </div>
            </Link>
          )
        })}
      </div>
    </GlassPanel>
  )
}

function MiniMetric({ label, value, detail }: { label: string; value: string; detail: string; key?: string | number }) {
  return (
    <div className="rounded-md border border-white/10 bg-black/20 px-3 py-2">
      <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/32">{label}</div>
      <div className="mt-1 text-lg font-black text-white">{value}</div>
      <div className="mt-0.5 truncate text-[10px] font-semibold text-white/42">{detail}</div>
    </div>
  )
}

function ProgressDonut({ value }: { value: number }) {
  const safe = clamp(value)
  return (
    <div className="relative grid h-32 w-32 shrink-0 place-items-center rounded-full" style={{ background: `conic-gradient(#b43cff ${safe * 3.6}deg, rgba(255,255,255,0.1) 0deg)` }}>
      <div className="absolute inset-3 rounded-full bg-[#07101d] shadow-[inset_0_0_28px_rgba(180,60,255,0.35)]" />
      <div className="relative text-center">
        <div className="text-3xl font-black text-white">{safe}%</div>
      </div>
    </div>
  )
}

function CurrentStepPanel({ snapshot, live, onRefresh }: { snapshot: OnboardingSnapshot; live: boolean; onRefresh: () => void }) {
  const visual = STEP_VISUALS[snapshot.currentStep - 1] || STEP_VISUALS[0]
  const Icon = visual.icon
  const metrics = snapshot.metrics
  const miniMetrics = [
    { label: 'Assets', value: numberFmt(metrics.assets), detail: `${numberFmt(metrics.assessedAssets)} assessed` },
    { label: 'Findings', value: numberFmt(metrics.findings), detail: `${numberFmt(metrics.criticalExposures)} critical` },
    { label: 'Migrations', value: numberFmt(metrics.migrationJobs), detail: `${numberFmt(metrics.completedMigrations)} complete` },
    { label: 'Runtime', value: numberFmt(metrics.runtimeEvents24h), detail: 'events in 24h' },
  ]

  return (
    <GlassPanel className="p-4">
      <div className="grid gap-5 xl:grid-cols-[1.02fr_1.05fr_0.92fr]">
        <div className="min-w-0 border-white/10 xl:border-r xl:pr-5">
          <div className="flex items-start gap-4">
            <div
              className="grid h-20 w-20 shrink-0 place-items-center rounded-lg border bg-black/25 shadow-[0_0_26px_var(--step-color)]"
              style={{ '--step-color': visual.color, borderColor: `${visual.color}55` } as CSSProperties}
            >
              <Icon className="h-11 w-11 text-[color:var(--step-color)]" />
            </div>
            <div className="min-w-0">
              <div className="text-[10px] font-black uppercase tracking-[0.18em] text-[#d763ff]">Step {snapshot.currentStep} of 6</div>
              <h2 className="mt-1 text-2xl font-black leading-tight text-white">{snapshot.currentStepTitle}</h2>
              <p className="mt-2 text-xs leading-5 text-white/58">
                Live onboarding state derived from tenant assets, scans, detections, migration jobs, and runtime telemetry.
              </p>
              <span className={cn('mt-3 inline-flex rounded border px-3 py-1 text-[10px] font-black uppercase tracking-[0.14em]', statusTone(snapshot.currentStepStatus))}>
                {snapshot.currentStepStatus}
              </span>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-2">
            {miniMetrics.map((metric) => <MiniMetric key={metric.label} {...metric} />)}
          </div>
          {snapshot.nextStep ? (
            <Link to={snapshot.nextStep.href} className="mt-4 flex items-center justify-between rounded-md border border-white/10 bg-black/20 px-3 py-3 text-xs text-white/70 no-underline hover:border-gold/40 hover:text-gold">
              <span><span className="block text-[9px] uppercase tracking-[0.16em] text-white/30">Next Step</span>{snapshot.nextStep.title}</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
          ) : null}
        </div>

        <div className="border-white/10 xl:border-r xl:px-4">
          <div className="mb-4 text-[11px] font-black uppercase tracking-[0.2em] text-white">Step Overview</div>
          <div className="space-y-3">
            {snapshot.stepOverview.bullets.slice(0, 5).map((bullet, index) => (
              <div key={bullet} className="grid grid-cols-[18px_1fr] gap-3 text-xs leading-5 text-white/72">
                <CheckCircle2 className={cn('mt-0.5 h-4 w-4', index < snapshot.stepOverview.tasksCompleted ? 'text-emerald-300' : 'text-white/45')} />
                <span>{bullet}</span>
              </div>
            ))}
          </div>
        </div>

        <div>
          <div className="mb-4 flex items-center justify-between gap-3">
            <div className="text-[11px] font-black uppercase tracking-[0.2em] text-white">Step Progress</div>
            <button type="button" onClick={onRefresh} className="rounded border border-white/10 bg-black/25 p-2 text-white/55 hover:border-gold/40 hover:text-gold" aria-label="Refresh onboarding telemetry">
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="flex flex-col gap-4 md:flex-row md:items-center xl:flex-col xl:items-start 2xl:flex-row 2xl:items-center">
            <ProgressDonut value={snapshot.stepProgress} />
            <div className="w-full flex-1 space-y-3">
              {[
                ['Tasks Completed', snapshot.stepOverview.tasksCompleted, 'bg-emerald-400'],
                ['In Progress', snapshot.stepOverview.inProgress, 'bg-blue-400'],
                ['Pending', snapshot.stepOverview.pending, 'bg-amber-400'],
                ['Overdue', snapshot.stepOverview.overdue, 'bg-red-400'],
              ].map(([label, count, dot]) => (
                <div key={String(label)} className="flex items-center justify-between gap-4 border-b border-white/7 pb-2 text-xs last:border-b-0">
                  <span className="flex items-center gap-2 text-white/60"><span className={cn('h-2 w-2 rounded-full', dot)} />{label}</span>
                  <span className="font-black text-white">{count} / {snapshot.stepOverview.totalTasks}</span>
                </div>
              ))}
              <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.12em] text-white/35">
                <span className={cn('h-2 w-2 rounded-full', live ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.9)]' : 'bg-slate-500')} />
                {live ? 'Realtime sync active' : 'Realtime reconnecting'}
              </div>
            </div>
          </div>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <Link to="/dashboard/pqc-orchestration" className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-blue-400/30 bg-blue-500/5 text-xs font-black text-blue-300 no-underline hover:bg-blue-500/10">
              <Eye className="h-4 w-4" /> View Step Details
            </Link>
            <Link to={snapshot.nextStep?.href || '/dashboard/audit-vault'} className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-[#d763ff]/60 bg-[#8b2aff]/30 text-xs font-black text-white no-underline shadow-[0_0_24px_rgba(183,75,255,0.35)] hover:bg-[#9d3dff]/45">
              Continue Step <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </div>
    </GlassPanel>
  )
}

function TaskIcon({ status }: { status: TaskStatus }) {
  if (status === 'completed') return <CheckCircle2 className="h-4 w-4 text-emerald-300" />
  if (status === 'overdue') return <XCircle className="h-4 w-4 text-red-300" />
  if (status === 'in_progress') return <Circle className="h-4 w-4 text-sky-300" />
  return <Circle className="h-4 w-4 text-amber-300" />
}

function TaskPanel({ tasks }: { tasks: StepTask[] }) {
  return (
    <GlassPanel className="p-4">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-[12px] font-black uppercase tracking-[0.16em] text-white">Step Tasks</h3>
        <ClipboardCheck className="h-4 w-4 text-gold" />
      </div>
      <div className="space-y-2">
        {tasks.map((task) => (
          <Link key={task.label} to={task.href} className="grid grid-cols-[22px_1fr_auto] items-center gap-3 rounded-md border border-white/7 bg-black/18 px-3 py-2.5 text-xs text-white/72 no-underline transition hover:border-gold/35 hover:bg-gold/[0.04]">
            <TaskIcon status={task.status} />
            <span className="min-w-0">
              <span className="block truncate font-semibold">{task.label}</span>
              <span className="block truncate text-[9px] text-white/30">{task.source} | {numberFmt(task.count)}</span>
            </span>
            <span className={cn('rounded border px-2 py-1 text-[9px] font-black', statusTone(task.status))}>{task.labelStatus}</span>
          </Link>
        ))}
      </div>
      <Link to="/dashboard/migration-planner" className="mt-4 inline-flex h-9 w-full items-center justify-center gap-2 rounded-md border border-blue-400/30 bg-blue-500/5 text-xs font-black text-blue-300 no-underline hover:bg-blue-500/10">
        View All Tasks <ArrowRight className="h-4 w-4" />
      </Link>
    </GlassPanel>
  )
}

function ResourcesPanel({ resources }: { resources: ResourceItem[] }) {
  return (
    <GlassPanel className="p-4">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-[12px] font-black uppercase tracking-[0.16em] text-white">Step Resources</h3>
        <FileArchive className="h-4 w-4 text-gold" />
      </div>
      <div className="space-y-2">
        {resources.map((resource, index) => (
          <Link key={resource.title} to={resource.href} className="grid grid-cols-[34px_1fr] gap-3 rounded-md border border-white/7 bg-black/18 p-3 text-white no-underline transition hover:border-gold/35 hover:bg-gold/[0.04]">
            <div className={cn('grid h-9 w-9 place-items-center rounded-md border', index === 2 ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300' : 'border-red-500/25 bg-red-500/10 text-red-300')}>
              <FileText className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <div className="truncate text-xs font-black text-white/82">{resource.title}</div>
              <div className="mt-1 truncate text-[10px] font-semibold text-white/38">{resource.type}</div>
            </div>
          </Link>
        ))}
      </div>
      <Link to="/dashboard/audit-vault" className="mt-4 inline-flex h-9 w-full items-center justify-center gap-2 rounded-md border border-blue-400/30 bg-blue-500/5 text-xs font-black text-blue-300 no-underline hover:bg-blue-500/10">
        View All Resources <ArrowRight className="h-4 w-4" />
      </Link>
    </GlassPanel>
  )
}

function ActivityPanel({ activity }: { activity: ActivityItem[] }) {
  return (
    <GlassPanel className="p-4">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-[12px] font-black uppercase tracking-[0.16em] text-white">Activity Feed</h3>
        <Link to="/dashboard/runtime-telemetry" className="text-[10px] font-black text-blue-300 no-underline hover:text-gold">View All Activity</Link>
      </div>
      {activity.length === 0 ? (
        <div className="grid min-h-[250px] place-items-center rounded-md border border-dashed border-white/10 bg-black/15 text-center text-xs text-white/45">
          No tenant activity has been recorded yet.
        </div>
      ) : (
        <div className="relative space-y-0 pl-2">
          <div className="absolute bottom-4 left-[17px] top-2 w-px bg-white/10" />
          {activity.slice(0, 7).map((item) => (
            <div key={item.id} className="relative grid grid-cols-[34px_1fr_auto] gap-3 py-2.5">
              <div className="relative z-10 grid h-7 w-7 place-items-center rounded-full border bg-[#07101d]" style={{ borderColor: `${severityTone(item.severity)}55`, color: severityTone(item.severity), boxShadow: `0 0 16px ${severityTone(item.severity)}55` }}>
                <Activity className="h-3.5 w-3.5" />
              </div>
              <div className="min-w-0">
                <div className="truncate text-xs font-black text-white/84">{item.title}</div>
                <div className="mt-1 truncate text-[10px] font-semibold text-white/38">by {item.actor}</div>
              </div>
              <div className="whitespace-nowrap pt-4 text-right text-[10px] text-white/45">{relativeTime(item.timestamp)}</div>
            </div>
          ))}
        </div>
      )}
    </GlassPanel>
  )
}

function ClientPanel({ client, metrics }: { client: ClientOverview; metrics: OnboardingMetrics }) {
  const rows = [
    ['Client Name', client.name],
    ['Industry', client.industry],
    ['Onboarding Start Date', formatDate(client.onboardingStartDate)],
    ['Target Go-Live', formatDate(client.targetGoLive)],
    ['Project Manager', client.projectManager],
  ]

  return (
    <GlassPanel className="p-4">
      <h3 className="mb-4 text-[12px] font-black uppercase tracking-[0.16em] text-white">Client Overview</h3>
      <div className="space-y-3">
        {rows.map(([label, value]) => (
          <div key={label} className="grid grid-cols-[1fr_1.15fr] gap-3 text-xs">
            <span className="text-white/40">{label}</span>
            <span className="truncate text-right font-bold text-white/72">{value}</span>
          </div>
        ))}
        <div className="grid grid-cols-[1fr_auto] items-center gap-3 text-xs">
          <span className="text-white/40">Status</span>
          <span className={cn('rounded border px-2 py-1 text-[10px] font-black', statusTone(client.status))}>{client.status}</span>
        </div>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-2">
        <MiniMetric label="Coverage" value={`${metrics.coverageScore}%`} detail="assessed assets" />
        <MiniMetric label="Risk" value={`${metrics.riskScore}%`} detail="posture score" />
      </div>
      <Link to="/dashboard/settings" className="mt-4 inline-flex h-10 w-full items-center justify-center rounded-md border border-blue-400/35 bg-blue-500/5 text-xs font-black text-blue-300 no-underline hover:bg-blue-500/10">
        View Client Details
      </Link>
    </GlassPanel>
  )
}

function BenefitsPanel({ benefits }: { benefits: Benefit[] }) {
  return (
    <GlassPanel className="p-4">
      <h3 className="mb-4 text-[12px] font-black uppercase tracking-[0.16em] text-white">Key Benefits</h3>
      <div className="space-y-3">
        {benefits.map((benefit) => (
          <div key={benefit.label} className="grid grid-cols-[28px_1fr_auto] items-center gap-3">
            <div className={cn('grid h-7 w-7 place-items-center rounded-md border', statusTone(benefit.status))}>
              <ShieldCheck className="h-3.5 w-3.5" />
            </div>
            <div className="min-w-0">
              <div className="truncate text-xs font-bold text-white/72">{benefit.label}</div>
              <div className="truncate text-[9px] text-white/32">{benefit.detail}</div>
            </div>
            <div className="text-xs font-black text-gold">{benefit.value}</div>
          </div>
        ))}
      </div>
    </GlassPanel>
  )
}

function HelpPanel() {
  return (
    <GlassPanel className="p-4">
      <h3 className="mb-3 text-[12px] font-black uppercase tracking-[0.16em] text-white">Need Help?</h3>
      <p className="text-xs leading-5 text-white/56">Our experts are here to help you at every step of your journey.</p>
      <Link to="/dashboard/settings" className="mt-5 inline-flex h-10 w-full items-center justify-center gap-2 rounded-md border border-blue-400/35 bg-blue-500/5 text-xs font-black text-blue-300 no-underline hover:bg-blue-500/10">
        <Headphones className="h-4 w-4" />
        Contact Support
      </Link>
    </GlassPanel>
  )
}

function KpiBar({ metrics }: { metrics: OnboardingMetrics }) {
  const items = [
    { label: 'Assets', value: numberFmt(metrics.assets), detail: `${numberFmt(metrics.assessedAssets)} assessed`, icon: Database },
    { label: 'Findings', value: numberFmt(metrics.findings), detail: `${numberFmt(metrics.openAlerts)} open alerts`, icon: ShieldAlert },
    { label: 'Readiness', value: `${metrics.readinessScore}%`, detail: `${numberFmt(metrics.vulnerableCryptoItems)} vulnerable crypto`, icon: Target },
    { label: 'Telemetry', value: numberFmt(metrics.runtimeEvents), detail: `${numberFmt(metrics.runtimeEvents24h)} last 24h`, icon: Activity },
  ]

  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
      {items.map((item) => {
        const Icon = item.icon
        return (
          <GlassPanel key={item.label} className="p-3">
            <div className="flex items-center gap-3">
              <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-gold/25 bg-gold/10 text-gold">
                <Icon className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/35">{item.label}</div>
                <div className="mt-1 text-2xl font-black text-white">{item.value}</div>
                <div className="truncate text-[10px] font-semibold text-white/42">{item.detail}</div>
              </div>
            </div>
          </GlassPanel>
        )
      })}
    </div>
  )
}

export default function PqcOnboarding() {
  const { snapshot, state, error, live, refresh } = usePqcOnboardingSnapshot()
  const data = snapshot || EMPTY_SNAPSHOT
  const steps = data.steps.length ? data.steps : Array.from({ length: 6 }, (_, index) => ({
    id: index + 1,
    title: ['Awareness & Preparation', 'Discovery & Inventory', 'Risk Assessment & Planning', 'Migration Execution', 'Migration Testing', 'Validation & Monitoring'][index],
    href: '/dashboard/pqc-onboarding',
    status: index === 0 ? 'current' as const : 'pending' as const,
    progress: index === 0 ? 0 : 0,
  }))

  const sourceCount = useMemo(() => Object.values(data.sync.sourceTables || {}).reduce((sum: number, value: unknown) => sum + Number(value || 0), 0), [data.sync.sourceTables])

  return (
    <main className="min-h-screen bg-[#02060d] p-3 text-white lg:p-5">
      <div className="pointer-events-none fixed inset-0 opacity-70" aria-hidden="true">
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,211,107,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(0,217,255,0.025)_1px,transparent_1px)] bg-[size:48px_48px]" />
        <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(255,211,107,0.08),transparent_32%,rgba(0,140,255,0.05)_100%)]" />
      </div>

      <div className="relative z-10 mx-auto max-w-[1680px] space-y-4">
        <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <h1 className="text-3xl font-black leading-tight tracking-tight text-white md:text-4xl">Onboarding & Migration Process</h1>
            <p className="mt-2 max-w-2xl text-sm font-medium text-white/55">
              Your quantum-safe journey starts here. Follow the workflow to onboard and secure your environment.
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2 text-[10px] font-black uppercase tracking-[0.14em] text-white/35">
              <span className={cn('h-2 w-2 rounded-full', live ? 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.9)]' : 'bg-slate-500')} />
              {state === 'loading' && !snapshot ? 'Syncing tenant telemetry' : `Live sources ${numberFmt(sourceCount)}`}
              {error ? <span className="text-red-300">Telemetry warning: {error}</span> : null}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <IconButton icon={Search} label="Search onboarding telemetry" />
            <IconButton icon={Bell} label="Alerts" alert={data.metrics.openAlerts || undefined} />
            <IconButton icon={CircleHelp} label="Help" />
            <IconButton icon={Settings} label="Settings" />
            <ProfileChip client={data.client} />
            <button
              type="button"
              onClick={() => downloadRoadmap(data)}
              className="inline-flex h-10 items-center gap-2 rounded-lg border border-blue-400/35 bg-blue-500/5 px-4 text-xs font-black text-blue-300 transition hover:bg-blue-500/10"
            >
              <Download className="h-4 w-4" />
              Download Roadmap
            </button>
          </div>
        </header>

        {state === 'loading' && !snapshot ? (
          <GlassPanel className="grid min-h-[420px] place-items-center p-8 text-center">
            <div>
              <RefreshCw className="mx-auto h-8 w-8 animate-spin text-gold" />
              <div className="mt-4 text-sm font-black uppercase tracking-[0.18em] text-white">Syncing live onboarding telemetry</div>
              <div className="mt-2 text-xs text-white/45">Backend API, database queries, realtime channels, and SSE streams are connecting.</div>
            </div>
          </GlassPanel>
        ) : (
          <>
            <div className="overflow-x-auto pb-1">
              <ProcessRail steps={steps} />
            </div>

            <div className="grid gap-4 xl:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]">
              <ClientPanel client={data.client} metrics={data.metrics} />
              <BenefitsPanel benefits={data.benefits} />
            </div>

            <CurrentStepPanel snapshot={data} live={live} onRefresh={refresh} />

            <div className="grid gap-4 xl:grid-cols-2">
              <TaskPanel tasks={data.tasks} />
              <ResourcesPanel resources={data.resources} />
            </div>

            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px] 2xl:grid-cols-[minmax(0,1fr)_400px]">
              <ActivityPanel activity={data.activity} />
              <HelpPanel />
            </div>
          </>
        )}
      </div>
    </main>
  )
}
