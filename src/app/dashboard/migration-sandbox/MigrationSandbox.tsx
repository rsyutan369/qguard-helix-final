import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  AlertTriangle,
  Box,
  CheckCircle2,
  ClipboardList,
  Clock3,
  Copy,
  Database,
  DollarSign,
  Download,
  Eye,
  FileText,
  Globe2,
  KeyRound,
  MoreHorizontal,
  Package,
  Play,
  Plus,
  Radio,
  Server,
  Shield,
  ShieldCheck,
  TestTube2,
  Upload,
  UserRound,
  X,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'

type LoadState = 'loading' | 'success' | 'error'

type SandboxMetrics = {
  sandboxEnvironments: number
  activeEnvironments: number
  activeTests: number
  testsPassed: number
  testsFailed: number
  successRate: number
  failureRate: number
  readinessScore: number
  costEstimate: number
}

type SandboxEnvironment = {
  id: string
  environment: string
  displayName: string
  type: string
  region: string
  status: string
  tests: number
  progress: number
  lastActivityAt: string | null
  assetId: string | null
  from: string
  to: string
  transitionType: string
  success: boolean
  failed: boolean
}

type SandboxTopology = {
  users: number
  loadGenerators: number
  appServers: number
  apiGateways: number
  databases: number
  keyVaults: number
  externalServices: number
  kemServices: number
  signServices: number
  telemetryEvents: number
}

type ExecutionSummary = {
  passed: number
  failed: number
  running: number
  pending: number
  total: number
}

type TransitionRow = {
  id: string
  from: string
  to: string
  type: string
  tests: number
  successRate: number
}

type ActivityRow = {
  id: string
  timestamp: string | null
  environment: string
  event: string
  details: string
  status: string
  user: string
}

type ValidationRow = {
  label: string
  status: string
}

type SandboxSnapshot = {
  generatedAt: string | null
  metrics: SandboxMetrics
  environments: SandboxEnvironment[]
  topology: SandboxTopology
  executionSummary: ExecutionSummary
  transitions: TransitionRow[]
  activity: ActivityRow[]
  validation: ValidationRow[]
}

const EMPTY_SNAPSHOT: SandboxSnapshot = {
  generatedAt: null,
  metrics: {
    sandboxEnvironments: 0,
    activeEnvironments: 0,
    activeTests: 0,
    testsPassed: 0,
    testsFailed: 0,
    successRate: 0,
    failureRate: 0,
    readinessScore: 0,
    costEstimate: 0,
  },
  environments: [],
  topology: {
    users: 0,
    loadGenerators: 0,
    appServers: 0,
    apiGateways: 0,
    databases: 0,
    keyVaults: 0,
    externalServices: 0,
    kemServices: 0,
    signServices: 0,
    telemetryEvents: 0,
  },
  executionSummary: { passed: 0, failed: 0, running: 0, pending: 0, total: 0 },
  transitions: [],
  activity: [],
  validation: [],
}

const GOLD = '#FBBF24'
const GREEN = '#22C55E'
const RED = '#EF4444'
const BLUE = '#38BDF8'
const PURPLE = '#C084FC'

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-gold/18 bg-[#07101D]/70 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(251,191,36,0.035),0_0_34px_rgba(0,0,0,0.32)] transition-all duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/78 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-24px_60px_rgba(251,191,36,0.12),0_14px_42px_rgba(0,0,0,0.45),0_0_54px_rgba(251,191,36,0.32)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/70 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-52 after:w-52 after:rounded-full after:bg-gold/10 after:blur-3xl after:transition-all group-hover:after:bg-gold/20'

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(value || 0)))
}

function moneyFmt(value: number) {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(Math.max(0, Math.round(value || 0)))
}

function relativeTime(value: string | null) {
  if (!value) return '--'
  const ms = new Date(value).getTime()
  if (!Number.isFinite(ms)) return '--'
  const diff = Date.now() - ms
  const mins = Math.max(0, Math.round(diff / 60000))
  if (mins < 1) return 'now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return new Date(value).toLocaleDateString('en-US', { month: 'short', day: '2-digit' })
}

function timeOnly(value: string | null) {
  if (!value) return '--'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '--'
  return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function statusClass(value: string) {
  const lower = value.toLowerCase()
  if (lower.includes('completed') || lower.includes('passed') || lower.includes('success')) return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
  if (lower.includes('running')) return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
  if (lower.includes('failed')) return 'border-red-500/35 bg-red-500/10 text-red-300'
  if (lower.includes('warning')) return 'border-gold/35 bg-gold/10 text-gold'
  return 'border-sky-500/30 bg-sky-500/10 text-sky-300'
}

function progressColor(value: number, status = '') {
  if (status.toLowerCase().includes('failed')) return RED
  if (value >= 80) return GREEN
  if (value <= 30) return RED
  return GOLD
}

function regionBadge(region: string) {
  const lower = region.toLowerCase()
  if (lower.includes('eu')) return 'EU'
  if (lower.includes('ap')) return 'AP'
  if (lower.includes('us')) return 'US'
  return region.slice(0, 2).toUpperCase() || '--'
}

function useMigrationSandboxSnapshot() {
  const { session, user } = useAuth()
  const token = session?.access_token
  const [snapshot, setSnapshot] = useState<SandboxSnapshot>(EMPTY_SNAPSHOT)
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)

  const fetchSnapshot = useCallback(async () => {
    if (!token) return
    setState((current) => current === 'success' ? current : 'loading')
    try {
      const response = await fetch('/api/v1/dashboard/migration-sandbox', {
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
      const message = err instanceof Error ? err.message : 'Unable to load migration sandbox telemetry'
      console.error('Migration sandbox telemetry failed:', err)
      setError(message)
      setState('error')
    }
  }, [token])

  useEffect(() => {
    if (!token || !user) return
    fetchSnapshot()
  }, [token, user, fetchSnapshot])

  useEffect(() => {
    if (!user) return
    const tables = [
      'assets',
      'asset_relationships',
      'crypto_inventory',
      'crypto_exposures',
      'migration_jobs',
      'migration_events',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'security_events',
    ]

    const channels = tables.map((table) => supabase
      .channel(`migration-sandbox-${table}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` },
        () => fetchSnapshot()
      )
      .subscribe())

    return () => {
      for (const channel of channels) {
        supabase.removeChannel(channel)
      }
    }
  }, [user, fetchSnapshot])

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

  return { snapshot, state, error, sseConnected, refresh: fetchSnapshot }
}

function GlassPanel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={cn(GLASS_PANEL_CLASSES, className)}>
      <div className="relative z-10 h-full">{children}</div>
    </section>
  )
}

function SectionTitle({ icon: Icon, children, suffix }: { icon: LucideIcon; children: ReactNode; suffix?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h2 className="flex items-center gap-2 text-sm font-black text-white">
        <Icon className="h-4 w-4 text-gold" />
        {children}
      </h2>
      {suffix}
    </div>
  )
}

function HeaderButton({ icon: Icon, children, href, onClick, primary }: { icon: LucideIcon; children: ReactNode; href?: string; onClick?: () => void; primary?: boolean }) {
  const className = cn(
    'inline-flex h-10 items-center justify-center gap-2 rounded-md border px-4 text-xs font-black transition',
    primary
      ? 'border-gold bg-gold text-black shadow-[0_0_22px_rgba(251,191,36,0.35)] hover:bg-[#FFE08A]'
      : 'border-gold/20 bg-black/20 text-white/80 hover:border-gold/60 hover:bg-gold/10 hover:text-gold'
  )

  if (href) {
    return (
      <a href={href} className={className}>
        <Icon className="h-4 w-4" />
        {children}
      </a>
    )
  }

  return (
    <button type="button" onClick={onClick} className={className}>
      <Icon className="h-4 w-4" />
      {children}
    </button>
  )
}

function MetricCard({ label, value, detail, icon: Icon, tone }: { label: string; value: string; detail: string; icon: LucideIcon; tone: 'gold' | 'green' | 'red' | 'purple' }) {
  const color = tone === 'green' ? GREEN : tone === 'red' ? RED : tone === 'purple' ? PURPLE : GOLD
  return (
    <GlassPanel className="p-5">
      <div className="flex items-center gap-4">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border bg-black/25" style={{ borderColor: `${color}66`, color, boxShadow: `0 0 28px ${color}24` }}>
          <Icon className="h-7 w-7" />
        </div>
        <div className="min-w-0">
          <div className="text-[9px] font-black uppercase tracking-[0.18em] text-white/45">{label}</div>
          <div className="mt-2 font-mono text-3xl font-black leading-none text-white">{value}</div>
          <div className={cn('mt-2 text-[10px] font-bold', tone === 'green' ? 'text-emerald-300' : tone === 'red' ? 'text-red-300' : tone === 'purple' ? 'text-purple-300' : 'text-gold')}>{detail}</div>
        </div>
      </div>
    </GlassPanel>
  )
}

function ProgressBar({ value, color = GOLD }: { value: number; color?: string }) {
  return (
    <div className="h-2 overflow-hidden rounded-full bg-white/7">
      <div className="h-full rounded-full transition-all" style={{ width: `${Math.max(0, Math.min(100, value))}%`, background: `linear-gradient(90deg, ${color}bb, ${color})`, boxShadow: `0 0 14px ${color}66` }} />
    </div>
  )
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="rounded-md border border-white/5 bg-white/[0.025] p-5 text-center text-xs font-semibold text-white/40">
      {label}
    </div>
  )
}

function ExecutionDonut({ summary }: { summary: ExecutionSummary }) {
  const total = Math.max(1, summary.total)
  const passed = (summary.passed / total) * 100
  const failed = (summary.failed / total) * 100
  const running = (summary.running / total) * 100
  const gradient = `conic-gradient(${GREEN} 0 ${passed}%, ${RED} ${passed}% ${passed + failed}%, ${GOLD} ${passed + failed}% ${passed + failed + running}%, #94A3B8 ${passed + failed + running}% 100%)`
  return (
    <div className="relative flex h-32 w-32 items-center justify-center rounded-full" style={{ background: gradient }}>
      <div className="absolute inset-4 rounded-full bg-[#07101D] shadow-[inset_0_0_24px_rgba(0,0,0,0.55)]" />
      <div className="relative text-center">
        <div className="font-mono text-3xl font-black text-white">{numberFmt(summary.total)}</div>
        <div className="text-[10px] text-white/45">Total Tests</div>
      </div>
    </div>
  )
}

function Topology({ topology, environmentName }: { topology: SandboxTopology; environmentName: string }) {
  const centerStats = [
    { label: 'App Servers', value: topology.appServers, icon: Server },
    { label: 'API Gateway', value: topology.apiGateways, icon: Globe2 },
    { label: 'Database', value: topology.databases, icon: Database },
    { label: 'Key Vault', value: topology.keyVaults, icon: Shield },
  ]

  return (
    <div className="rounded-lg border border-white/5 bg-black/10 p-3">
      <div className="grid gap-3 lg:grid-cols-[minmax(120px,0.7fr)_minmax(0,1.7fr)_minmax(130px,0.75fr)]">
        <div className="rounded-lg border border-white/10 bg-white/[0.025] p-4">
          <div className="mb-4 text-center text-xs font-black text-white/80">Users</div>
          <div className="space-y-4 text-xs text-white/60">
            <div className="flex items-center gap-2"><UserRound className="h-4 w-4" /> {numberFmt(topology.users)} owners</div>
            <div className="flex items-center gap-2"><TestTube2 className="h-4 w-4" /> {numberFmt(topology.loadGenerators)} load runs</div>
          </div>
        </div>

        <div className="space-y-3">
          <div className="rounded-lg border border-gold/30 bg-gold/[0.035] p-4 text-center">
            <div className="text-sm font-black text-white">Sandbox Environment</div>
            <div className="mt-1 text-xs font-mono text-white/55">{environmentName || 'No active sandbox'}</div>
            <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {centerStats.map((item) => {
                const Icon = item.icon
                return (
                  <div key={item.label} className="border-r border-white/10 text-center last:border-r-0">
                    <Icon className="mx-auto h-5 w-5 text-white/70" />
                    <div className="mt-2 text-[10px] text-white/50">{item.label}</div>
                    <div className="mt-1 font-mono text-sm font-black text-white">{numberFmt(item.value)}</div>
                  </div>
                )
              })}
            </div>
          </div>

          <div className="rounded-lg border border-sky-400/35 bg-sky-500/[0.04] p-4 text-center">
            <div className="text-xs font-black text-white">Crypto Services</div>
            <div className="mt-4 grid grid-cols-2 divide-x divide-white/10">
              <div>
                <KeyRound className="mx-auto h-5 w-5 text-white/70" />
                <div className="mt-2 text-[10px] text-white/55">KEM Services</div>
                <div className="font-mono text-sm font-black text-sky-300">{numberFmt(topology.kemServices)}</div>
              </div>
              <div>
                <ShieldCheck className="mx-auto h-5 w-5 text-white/70" />
                <div className="mt-2 text-[10px] text-white/55">Sign Services</div>
                <div className="font-mono text-sm font-black text-sky-300">{numberFmt(topology.signServices)}</div>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-3">
          <div className="rounded-lg border border-white/10 bg-white/[0.025] p-4">
            <div className="mb-4 text-center text-xs font-black text-white/80">External Services</div>
            <div className="space-y-3 text-xs text-white/60">
              <div className="flex items-center justify-between"><span>CA / PKI</span><span className="font-mono text-white">{numberFmt(topology.externalServices)}</span></div>
              <div className="flex items-center justify-between"><span>DNS</span><span className="font-mono text-white">{numberFmt(topology.apiGateways)}</span></div>
              <div className="flex items-center justify-between"><span>Monitoring</span><span className="font-mono text-white">{numberFmt(topology.telemetryEvents)}</span></div>
            </div>
          </div>
          <div className="rounded-lg border border-purple-400/35 bg-purple-500/[0.07] p-4 text-center">
            <Package className="mx-auto h-5 w-5 text-purple-300" />
            <div className="mt-2 text-xs font-black text-white">Telemetry Collector</div>
            <div className="mt-1 font-mono text-sm text-purple-300">{numberFmt(topology.telemetryEvents)}</div>
          </div>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-5 text-[10px] font-bold text-white/45">
        <span className="inline-flex items-center gap-2"><span className="h-px w-8 bg-sky-400" /> Data Flow</span>
        <span className="inline-flex items-center gap-2"><span className="h-px w-8 bg-gold" /> Crypto Operations</span>
        <span className="inline-flex items-center gap-2"><span className="h-px w-8 bg-purple-400" /> Monitoring</span>
      </div>
    </div>
  )
}

function exportJson(name: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `${name}-${new Date().toISOString().slice(0, 10)}.json`
  anchor.click()
  URL.revokeObjectURL(url)
}

export default function MigrationSandbox() {
  const { snapshot, state, error, sseConnected, refresh } = useMigrationSandboxSnapshot()
  const metrics = snapshot.metrics
  const generatedAt = useMemo(() => snapshot.generatedAt ? new Date(snapshot.generatedAt) : new Date(), [snapshot.generatedAt])
  const primaryEnvironment = snapshot.environments[0]?.environment || ''

  const metricCards = [
    { label: 'Sandbox Environments', value: numberFmt(metrics.sandboxEnvironments), detail: `${numberFmt(metrics.activeEnvironments)} Active`, icon: Box, tone: 'gold' as const },
    { label: 'Active Tests', value: numberFmt(metrics.activeTests), detail: `${numberFmt(snapshot.executionSummary.running)} running now`, icon: Play, tone: 'green' as const },
    { label: 'Tests Passed', value: numberFmt(metrics.testsPassed), detail: `${metrics.successRate}% Success Rate`, icon: CheckCircle2, tone: 'green' as const },
    { label: 'Tests Failed', value: numberFmt(metrics.testsFailed), detail: `${metrics.failureRate}% Failure Rate`, icon: X, tone: 'red' as const },
    { label: 'Readiness Score', value: `${metrics.readinessScore}%`, detail: metrics.readinessScore >= 75 ? 'Good' : metrics.readinessScore ? 'Needs Review' : 'Not Assessed', icon: Shield, tone: 'gold' as const },
    { label: 'Cost Estimate', value: moneyFmt(metrics.costEstimate), detail: 'This Month', icon: DollarSign, tone: 'purple' as const },
  ]

  const quickActions = [
    { label: 'Create Sandbox', detail: 'Provision isolated environment', href: '/dashboard/migration_planner', icon: Plus },
    { label: 'Import Configuration', detail: 'Upload sandbox configuration', href: '/dashboard/scanner', icon: Upload },
    { label: 'Clone Environment', detail: 'Clone existing sandbox', href: '/dashboard/assets_map', icon: Copy },
    { label: 'Run Predefined Test', detail: 'Execute standard test suite', href: '/dashboard/live-migration', icon: Play },
    { label: 'Validate Algorithms', detail: 'Check algorithm compatibility', href: '/dashboard/crypto-agility', icon: ShieldCheck },
    { label: 'Generate Report', detail: 'Export sandbox report', onClick: () => exportJson('migration-sandbox-report', snapshot), icon: FileText },
  ]

  return (
    <main className="min-h-screen space-y-4 bg-[#02070E] p-3 text-white md:p-4">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-white md:text-4xl">Migration Sandbox</h1>
          <p className="mt-2 text-sm font-medium text-white/55">Safely test post-quantum migration plans in isolated environments before production rollout.</p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={refresh}
            className="inline-flex h-10 items-center gap-2 rounded-md border border-gold/20 bg-black/20 px-4 text-xs font-black text-white/80 transition hover:border-gold/60 hover:bg-gold/10 hover:text-gold"
          >
            <span className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_12px_rgba(34,197,94,0.9)]' : 'bg-slate-500')} />
            {sseConnected ? 'Live Telemetry' : state === 'loading' ? 'Syncing' : 'Refresh'}
          </button>
          <HeaderButton icon={Download} onClick={() => exportJson('migration-sandbox-report', snapshot)}>Export Report</HeaderButton>
          <HeaderButton icon={Plus} href="/dashboard/migration_planner" primary>New Sandbox</HeaderButton>
          <div className="hidden items-center gap-2 pl-1 xl:flex">
            <Clock3 className="h-5 w-5 text-gold" />
            <div className="font-mono text-[10px] font-bold uppercase text-white/60">
              <div>{generatedAt.toLocaleTimeString('en-US', { hour12: false })} UTC</div>
              <div className="text-white/35">{generatedAt.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })}</div>
            </div>
          </div>
          <div className="flex h-10 w-10 items-center justify-center rounded-full border border-white/10 bg-white/[0.03] text-white/55">
            <UserRound className="h-5 w-5" />
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-6">
        {metricCards.map((metric) => (
          <div key={metric.label}>
            <MetricCard {...metric} />
          </div>
        ))}
      </div>

      <div className="space-y-4">
        <GlassPanel className="p-5">
          <SectionTitle icon={Box} suffix={<a href="/dashboard/assets_map" className="rounded border border-gold/30 px-3 py-2 text-[10px] font-black text-gold hover:bg-gold/10">View All Environments</a>}>
            Sandbox Environments
          </SectionTitle>
          {snapshot.environments.length === 0 ? (
            <EmptyState label="No migration jobs or discovered assets are available for sandbox simulation yet." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[780px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-white/8">
                    {['Environment', 'Type', 'Region', 'Status', 'Tests', 'Progress', 'Last Activity', 'Actions'].map((header) => (
                      <th key={header} className="px-3 py-3 text-[9px] font-black uppercase tracking-wider text-white/45">{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {snapshot.environments.map((env) => (
                    <tr key={env.id} className="transition hover:bg-gold/[0.04]">
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-md border border-gold/30 bg-gold/10 text-gold">
                            <Box className="h-4 w-4" />
                          </div>
                          <div>
                            <div className="text-sm font-black text-white/90">{env.environment}</div>
                            <div className="mt-1 text-[10px] text-white/40">{env.displayName}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-3 py-3 text-xs font-bold text-white/60">{env.type}</td>
                      <td className="px-3 py-3">
                        <span className="inline-flex items-center gap-2 text-xs font-mono text-white/65">
                          <span className="rounded bg-sky-500/15 px-1.5 py-0.5 text-[9px] text-sky-300">{regionBadge(env.region)}</span>
                          {env.region}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        <span className={cn('rounded border px-2 py-1 text-[9px] font-black tracking-wider', statusClass(env.status))}>{env.status}</span>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-white/70">{numberFmt(env.tests)}</td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-20"><ProgressBar value={env.progress} color={progressColor(env.progress, env.status)} /></div>
                          <span className="font-mono text-[10px] text-white/50">{env.progress}%</span>
                        </div>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-white/45">{relativeTime(env.lastActivityAt)}</td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-2">
                          <a href="/dashboard/migration_terminal" className="flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-black/20 text-gold hover:border-gold/40" aria-label={`View ${env.environment}`}>
                            <Eye className="h-3.5 w-3.5" />
                          </a>
                          <button type="button" className="flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-black/20 text-gold hover:border-gold/40" aria-label={`Actions for ${env.environment}`}>
                            <MoreHorizontal className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="mt-4 border-t border-white/5 pt-3 text-xs text-white/45">Showing {numberFmt(snapshot.environments.length)} sandbox environments</div>
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={Package} suffix={<a href="/dashboard/assets_map" className="rounded border border-gold/30 px-3 py-2 text-[10px] font-black text-gold hover:bg-gold/10">View Topology</a>}>
            Sandbox Topology
          </SectionTitle>
          <Topology topology={snapshot.topology} environmentName={primaryEnvironment} />
        </GlassPanel>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(260px,0.65fr)_minmax(0,0.95fr)_minmax(380px,1.1fr)]">
        <GlassPanel className="p-5">
          <SectionTitle icon={ClipboardList}>Test Execution Summary</SectionTitle>
          <div className="grid gap-5 sm:grid-cols-[140px_minmax(0,1fr)] xl:grid-cols-1 2xl:grid-cols-[140px_minmax(0,1fr)]">
            <div className="flex justify-center"><ExecutionDonut summary={snapshot.executionSummary} /></div>
            <div className="space-y-3 self-center">
              {[
                ['Passed', snapshot.executionSummary.passed, GREEN],
                ['Failed', snapshot.executionSummary.failed, RED],
                ['Running', snapshot.executionSummary.running, GOLD],
                ['Pending', snapshot.executionSummary.pending, '#94A3B8'],
              ].map(([label, count, color]) => (
                <div key={String(label)} className="flex items-center gap-3 text-xs">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: String(color) }} />
                  <span className="flex-1 text-white/60">{label}</span>
                  <span className="font-mono font-bold text-white">{numberFmt(Number(count))}</span>
                </div>
              ))}
            </div>
          </div>
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={TestTube2}>Algorithm Transitions Tested</SectionTitle>
          {snapshot.transitions.length === 0 ? (
            <EmptyState label="No completed migration tests are available yet." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[520px] text-left">
                <thead>
                  <tr className="border-b border-white/8">
                    {['From', 'To', 'Type', 'Tests', 'Success Rate'].map((header) => (
                      <th key={header} className="px-3 py-3 text-[9px] font-black uppercase tracking-wider text-gold">{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {snapshot.transitions.map((transition) => (
                    <tr key={transition.id} className="text-xs">
                      <td className="px-3 py-3 font-mono text-white/55">{transition.from}</td>
                      <td className="px-3 py-3 font-mono text-white/80">{transition.to}</td>
                      <td className="px-3 py-3 text-white/55">{transition.type}</td>
                      <td className="px-3 py-3 font-mono text-white/70">{numberFmt(transition.tests)}</td>
                      <td className={cn('px-3 py-3 font-mono font-black', transition.successRate >= 80 ? 'text-emerald-300' : transition.successRate ? 'text-gold' : 'text-white/40')}>{transition.successRate}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={Plus}>Quick Actions</SectionTitle>
          <div className="grid gap-3 sm:grid-cols-2">
            {quickActions.map((action) => {
              const Icon = action.icon
              const content = (
                <>
                  <Icon className="h-5 w-5 text-gold" />
                  <div>
                    <div className="text-xs font-black text-white/90">{action.label}</div>
                    <div className="mt-1 text-[11px] leading-snug text-white/45">{action.detail}</div>
                  </div>
                </>
              )
              return action.href ? (
                <a key={action.label} href={action.href} className="flex items-center gap-3 rounded-md border border-white/10 bg-white/[0.025] p-4 transition hover:border-gold/40 hover:bg-gold/[0.06]">
                  {content}
                </a>
              ) : (
                <button key={action.label} type="button" onClick={action.onClick} className="flex items-center gap-3 rounded-md border border-white/10 bg-white/[0.025] p-4 text-left transition hover:border-gold/40 hover:bg-gold/[0.06]">
                  {content}
                </button>
              )
            })}
          </div>
        </GlassPanel>
      </div>

      <div className="space-y-4">
        <GlassPanel className="p-5">
          <SectionTitle icon={Radio} suffix={<a href="/dashboard/audit-vault" className="text-[10px] font-black text-gold hover:text-[#FFE8A8]">View All Activity</a>}>
            Recent Activity
          </SectionTitle>
          {snapshot.activity.length === 0 ? (
            <EmptyState label="No sandbox, migration, scan, or security activity has been recorded yet." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-left">
                <thead>
                  <tr className="border-b border-white/8">
                    {['Time', 'Environment', 'Event', 'Details', 'Status', 'User'].map((header) => (
                      <th key={header} className="px-3 py-2 text-[9px] font-black text-white/45">{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {snapshot.activity.map((row) => (
                    <tr key={row.id} className="text-xs">
                      <td className="px-3 py-2 font-mono text-white/70">{timeOnly(row.timestamp)}</td>
                      <td className="px-3 py-2 text-white/60">{row.environment}</td>
                      <td className="px-3 py-2 text-white/70">{row.event}</td>
                      <td className="px-3 py-2 text-white/50">{row.details}</td>
                      <td className={cn('px-3 py-2 font-black', row.status === 'Failed' ? 'text-red-300' : row.status === 'Warning' ? 'text-gold' : 'text-emerald-300')}>{row.status}</td>
                      <td className="px-3 py-2 text-white/55">{row.user}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={ShieldCheck}>Security Validation</SectionTitle>
          <div className="space-y-4">
            {snapshot.validation.map((item) => (
              <div key={item.label} className="flex items-center justify-between gap-4 text-sm">
                <div className="flex items-center gap-3 text-white/70">
                  {item.status === 'Failed' ? <X className="h-4 w-4 text-red-300" /> : item.status === 'Warning' ? <AlertTriangle className="h-4 w-4 text-gold" /> : <CheckCircle2 className="h-4 w-4 text-emerald-300" />}
                  <span>{item.label}</span>
                </div>
                <span className={cn('font-black', item.status === 'Failed' ? 'text-red-300' : item.status === 'Warning' ? 'text-gold' : item.status === 'Pending' ? 'text-sky-300' : 'text-emerald-300')}>{item.status}</span>
              </div>
            ))}
          </div>
        </GlassPanel>
      </div>

      <footer className="flex flex-col gap-2 border-t border-white/5 pt-3 text-[10px] font-mono uppercase tracking-wider text-white/30 md:flex-row md:items-center md:justify-between">
        <span>{error ? `Telemetry warning: ${error}` : 'Sandbox telemetry synchronized'}</span>
        <span>Live stream: {sseConnected ? 'connected' : 'standby'} / Snapshot: {snapshot.generatedAt ? relativeTime(snapshot.generatedAt) : 'pending'}</span>
        {state === 'loading' && <span>Loading migration sandbox telemetry...</span>}
      </footer>
    </main>
  )
}
