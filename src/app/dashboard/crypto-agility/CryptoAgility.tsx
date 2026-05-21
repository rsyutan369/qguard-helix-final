import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  AlertTriangle,
  ArrowRight,
  Box,
  CheckCircle2,
  Clock3,
  Download,
  FileText,
  GitCompare,
  Layers,
  ListChecks,
  PackageCheck,
  Play,
  Radio,
  RefreshCw,
  Route,
  Shield,
  ShieldCheck,
  Shuffle,
  Sparkles,
  TimerReset,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'

type AgilityStatus = 'Ready' | 'Staged' | 'Blocked' | 'Not Scanned'

type AgilityMetrics = {
  agilityScore: number
  policyPacks: number
  blockedSwitches: number
  autoRotations: number
  readinessGates: { passed: number; total: number }
  totalDomains: number
  ready: number
  staged: number
  blocked: number
  notScanned: number
}

type SwitchReadiness = {
  id: string
  assetId: string | null
  domain: string
  assetType: string
  environment: string
  owner: string
  from: string
  to: string
  readiness: number
  blockers: string
  status: AgilityStatus
  lastScanAt: string | null
}

type LifecycleStep = {
  key: string
  label: string
  value: number
}

type TrendPoint = {
  label: string
  successful: number
  staged: number
  blocked: number
}

type Blocker = {
  label: string
  count: number
}

type QueueItem = {
  id: string
  title: string
  priority: string
  status: string
  eta: string
  assetId: string | null
}

type PolicyPack = {
  id: string
  name: string
  algorithms: string
  description: string
  status: string
  version: string
  standard: string
  domains: number
  assets: number
  successRate: number
}

type CryptoAgilitySnapshot = {
  generatedAt: string
  metrics: AgilityMetrics
  switchReadiness: SwitchReadiness[]
  lifecycle: LifecycleStep[]
  overview: {
    domainStatus: {
      ready: number
      staged: number
      blocked: number
      notScanned: number
      total: number
    }
    switchTrend: TrendPoint[]
    topBlockers: Blocker[]
  }
  automationQueue: QueueItem[]
  policyPacks: PolicyPack[]
  latest: {
    lastScanAt: string | null
    latestEvent: {
      id: string
      event_type: string
      severity: string
      message: string
      created_at: string
    } | null
    activeScans: number
  }
}

type LoadState = 'loading' | 'success' | 'error'

const EMPTY_SNAPSHOT: CryptoAgilitySnapshot = {
  generatedAt: new Date(0).toISOString(),
  metrics: {
    agilityScore: 0,
    policyPacks: 0,
    blockedSwitches: 0,
    autoRotations: 0,
    readinessGates: { passed: 0, total: 5 },
    totalDomains: 0,
    ready: 0,
    staged: 0,
    blocked: 0,
    notScanned: 0,
  },
  switchReadiness: [],
  lifecycle: [
    { key: 'discover', label: 'Discover', value: 0 },
    { key: 'classify', label: 'Classify', value: 0 },
    { key: 'abstract', label: 'Abstract', value: 0 },
    { key: 'switch', label: 'Switch', value: 0 },
    { key: 'validate', label: 'Validate', value: 0 },
  ],
  overview: {
    domainStatus: { ready: 0, staged: 0, blocked: 0, notScanned: 0, total: 0 },
    switchTrend: [],
    topBlockers: [],
  },
  automationQueue: [],
  policyPacks: [],
  latest: {
    lastScanAt: null,
    latestEvent: null,
    activeScans: 0,
  },
}

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:bg-[#FFD36B]/25 text-white'

const GOLD = '#FFD36B'
const GREEN = '#22c55e'
const RED = '#ef4444'
const ORANGE = '#f97316'
const BLUE = '#22d3ee'

const lifecycleIcons: Record<string, LucideIcon> = {
  discover: Layers,
  classify: ListChecks,
  abstract: Shuffle,
  switch: GitCompare,
  validate: ShieldCheck,
}

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(value || 0)
}

function clamp(value: number) {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, Math.round(value)))
}

function relativeTime(value: string | null) {
  if (!value) return 'No scan yet'
  const ms = Date.now() - new Date(value).getTime()
  if (!Number.isFinite(ms) || ms < 0) return new Date(value).toLocaleString()
  const minutes = Math.floor(ms / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

function statusClass(status: string) {
  const value = status.toLowerCase()
  if (value.includes('ready') || value.includes('active') || value.includes('running')) return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
  if (value.includes('blocked') || value.includes('review') || value.includes('failed')) return 'border-red-500/30 bg-red-500/10 text-red-300'
  if (value.includes('not')) return 'border-slate-500/30 bg-slate-500/10 text-slate-300'
  return 'border-gold/30 bg-gold/10 text-gold'
}

function priorityClass(priority: string) {
  if (priority.toLowerCase().includes('high')) return 'text-red-300'
  if (priority.toLowerCase().includes('medium')) return 'text-gold'
  return 'text-white/45'
}

function useCryptoAgilitySnapshot() {
  const { session, user } = useAuth()
  const token = session?.access_token
  const [snapshot, setSnapshot] = useState<CryptoAgilitySnapshot>(EMPTY_SNAPSHOT)
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)

  const fetchSnapshot = useCallback(async () => {
    if (!token) return
    setState((current) => current === 'success' ? current : 'loading')
    try {
      const response = await fetch('/api/v1/dashboard/crypto-agility', {
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
      const message = err instanceof Error ? err.message : 'Unable to load crypto agility telemetry'
      console.error('Crypto agility telemetry failed:', err)
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
      'crypto_inventory',
      'crypto_exposures',
      'migration_jobs',
      'migration_events',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'security_events',
    ]

    const channels = tables.map((table) => supabase
      .channel(`crypto-agility-${table}`)
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

function HeaderButton({ icon: Icon, children, href, onClick, primary }: { icon: LucideIcon; children: string; href?: string; onClick?: () => void; primary?: boolean }) {
  const classes = cn(
    'inline-flex h-9 items-center justify-center gap-2 rounded-md border px-4 text-[10px] font-black uppercase tracking-[0.16em] transition',
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

function SectionTitle({ icon: Icon, children, suffix }: { icon: LucideIcon; children: ReactNode; suffix?: ReactNode }) {
  return (
    <div className="mb-5 flex items-center justify-between gap-4">
      <h2 className="flex min-w-0 items-center gap-2 text-[11px] font-black uppercase tracking-[0.24em] text-white/60">
        <Icon className="h-4 w-4 shrink-0 text-gold" />
        <span className="truncate">{children}</span>
      </h2>
      {suffix}
    </div>
  )
}

function MetricCard({ label, value, detail, icon: Icon, tone }: { label: string; value: string; detail: string; icon: LucideIcon; tone: 'gold' | 'green' | 'red' | 'orange' | 'blue' }) {
  const toneClasses = {
    gold: 'border-gold/40 bg-gold/10 text-gold',
    green: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
    red: 'border-red-500/40 bg-red-500/10 text-red-300',
    orange: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
    blue: 'border-cyan-400/40 bg-cyan-400/10 text-cyan-300',
  }

  return (
    <GlassPanel className="p-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className={cn('flex h-12 w-12 shrink-0 items-center justify-center rounded-full border', toneClasses[tone])}>
            <Icon className="h-6 w-6" />
          </div>
          <div>
            <div className="text-[9px] font-black uppercase tracking-[0.2em] text-white/45">{label}</div>
            <div className="mt-2 text-3xl font-black leading-none text-white">{value}</div>
            <div className="mt-2 text-[9px] font-black uppercase tracking-[0.18em] text-white/35">{detail}</div>
          </div>
        </div>
        <div className={cn('hidden h-12 w-12 items-center justify-center rounded-full border xl:flex', toneClasses[tone])}>
          <Icon className="h-6 w-6" />
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

function MiniTrendChart({ data }: { data: TrendPoint[] }) {
  const series = useMemo(() => {
    const successful = data.map((point) => point.successful)
    const staged = data.map((point) => point.staged)
    const blocked = data.map((point) => point.blocked)
    const max = Math.max(1, ...successful, ...staged, ...blocked)
    const toPoints = (values: number[]) => values.map((value, index) => {
      const x = values.length === 1 ? 0 : (index / Math.max(1, values.length - 1)) * 220
      const y = 72 - (value / max) * 60
      return `${x},${y}`
    }).join(' ')
    return {
      successful: toPoints(successful),
      staged: toPoints(staged),
      blocked: toPoints(blocked),
    }
  }, [data])

  if (!data.length) return <EmptyState label="No switch trend events yet." />

  return (
    <div>
      <svg className="h-28 w-full overflow-visible" viewBox="0 0 220 82" aria-hidden="true">
        {[16, 32, 48, 64].map((line) => (
          <line key={line} x1="0" x2="220" y1={line} y2={line} stroke="rgba(255,255,255,0.08)" />
        ))}
        <polyline points={series.successful} fill="none" stroke={GREEN} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points={series.staged} fill="none" stroke={GOLD} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points={series.blocked} fill="none" stroke={RED} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div className="mt-2 grid grid-cols-6 gap-2 text-[9px] font-mono text-white/35">
        {data.map((point) => <span key={point.label}>{point.label}</span>)}
      </div>
    </div>
  )
}

function Donut({ ready, staged, blocked, notScanned, total }: { ready: number; staged: number; blocked: number; notScanned: number; total: number }) {
  const safeTotal = Math.max(1, total)
  const readyDeg = (ready / safeTotal) * 360
  const stagedDeg = readyDeg + (staged / safeTotal) * 360
  const blockedDeg = stagedDeg + (blocked / safeTotal) * 360
  const background = `conic-gradient(${GREEN} 0deg ${readyDeg}deg, ${GOLD} ${readyDeg}deg ${stagedDeg}deg, ${RED} ${stagedDeg}deg ${blockedDeg}deg, #64748b ${blockedDeg}deg 360deg)`

  return (
    <div className="relative flex h-28 w-28 shrink-0 items-center justify-center rounded-full" style={{ background }}>
      <div className="absolute inset-3 rounded-full bg-[#0b1020]" />
      <div className="relative text-center">
        <div className="text-3xl font-black text-white">{numberFmt(total)}</div>
        <div className="text-[9px] font-bold uppercase tracking-widest text-white/45">Domains</div>
      </div>
    </div>
  )
}

function exportSnapshot(snapshot: CryptoAgilitySnapshot) {
  const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `crypto-agility-${new Date().toISOString().slice(0, 10)}.json`
  anchor.click()
  URL.revokeObjectURL(url)
}

export default function CryptoAgility() {
  const { snapshot, state, error, sseConnected, refresh } = useCryptoAgilitySnapshot()
  const metrics = snapshot.metrics
  const generatedAt = snapshot.generatedAt ? new Date(snapshot.generatedAt) : new Date()

  const metricCards = [
    { label: 'Agility Score', value: `${metrics.agilityScore}%`, detail: 'cryptographic snap readiness', icon: Sparkles, tone: 'gold' as const },
    { label: 'Policy Packs', value: numberFmt(metrics.policyPacks), detail: 'approved algorithm bundles', icon: PackageCheck, tone: 'green' as const },
    { label: 'Blocked Switches', value: numberFmt(metrics.blockedSwitches), detail: 'dependency or owner gaps', icon: AlertTriangle, tone: 'red' as const },
    { label: 'Auto Rotations', value: numberFmt(metrics.autoRotations), detail: 'last 30 days', icon: RefreshCw, tone: 'orange' as const },
    { label: 'Readiness Gates', value: `${metrics.readinessGates.passed}/${metrics.readinessGates.total}`, detail: 'passed', icon: ShieldCheck, tone: 'green' as const },
  ]

  return (
    <main className="min-h-screen space-y-4 p-3 text-white lg:p-5">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <h1 className="text-3xl font-black uppercase leading-none tracking-[0.02em] text-white md:text-4xl">
            Crypto <span className="font-mono text-gold">Agility</span>
          </h1>
          <p className="mt-2 max-w-2xl text-sm font-medium text-white/55">
            Automate cryptographic transitions through policy packs, abstraction layers, readiness gates, and rollback-safe algorithm switches.
          </p>
          {error && <p className="mt-2 text-xs font-semibold text-red-300">Telemetry warning: {error}</p>}
        </div>

        <div className="flex flex-wrap items-center justify-start gap-3 xl:justify-end">
          <button
            type="button"
            onClick={refresh}
            className="inline-flex h-9 items-center gap-2 rounded-md border border-gold/20 bg-black/20 px-4 text-[10px] font-black uppercase tracking-[0.16em] text-white/70 transition hover:border-gold/60 hover:bg-gold/10 hover:text-gold"
          >
            <span className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_12px_rgba(34,197,94,0.9)]' : 'bg-slate-500')} />
            {sseConnected ? 'Live Telemetry' : state === 'loading' ? 'Syncing' : 'Refresh'}
          </button>
          <HeaderButton icon={Download} onClick={() => exportSnapshot(snapshot)}>Export Report</HeaderButton>
          <HeaderButton icon={Shield} href="/dashboard/audit-vault">Audit Logs</HeaderButton>
          <HeaderButton icon={Zap} href="/dashboard/migration_planner" primary>Generate Switch Plan</HeaderButton>
          <div className="hidden items-center gap-2 pl-1 xl:flex">
            <Clock3 className="h-5 w-5 text-gold" />
            <div className="font-mono text-[10px] font-bold uppercase text-white/60">
              <div>{generatedAt.toLocaleTimeString('en-US', { hour12: false })} UTC</div>
              <div className="text-white/35">{generatedAt.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })}</div>
            </div>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
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

      <div className="space-y-4">
        <GlassPanel className="p-5">
          <SectionTitle icon={GitCompare}>Algorithm Switch Readiness</SectionTitle>
          {snapshot.switchReadiness.length === 0 ? (
            <EmptyState label="No cryptographic domains discovered yet. Run a scan to populate switch readiness." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[880px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-gold/15">
                    {['Domain', 'From', 'To', 'Readiness', 'Blockers', 'Status', 'Last Scan'].map((header) => (
                      <th key={header} className="px-3 py-3 text-[9px] font-black uppercase tracking-[0.2em] text-gold/80">{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {snapshot.switchReadiness.map((row) => (
                    <tr key={row.id} className="transition hover:bg-gold/[0.04]">
                      <td className="px-3 py-3">
                        <div className="text-sm font-black text-white/90">{row.domain}</div>
                        <div className="mt-1 text-[9px] font-bold uppercase tracking-wider text-white/30">{row.assetType} / {row.environment}</div>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-white/50">{row.from}</td>
                      <td className="px-3 py-3 font-mono text-xs font-bold text-gold">{row.to}</td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-24">
                            <ProgressBar value={row.readiness} />
                          </div>
                          <span className="font-mono text-xs font-bold text-white/70">{row.readiness}%</span>
                        </div>
                      </td>
                      <td className="px-3 py-3 text-xs font-semibold text-white/50">{row.blockers}</td>
                      <td className="px-3 py-3">
                        <span className={cn('rounded border px-2 py-1 text-[9px] font-black uppercase tracking-wider', statusClass(row.status))}>{row.status}</span>
                      </td>
                      <td className="px-3 py-3 text-xs font-mono text-white/40">{relativeTime(row.lastScanAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-white/5 pt-3">
            <div className="flex flex-wrap items-center gap-4 text-[10px] font-bold text-white/45">
              <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-emerald-500" /> Ready</span>
              <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-gold" /> Staged</span>
              <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-red-500" /> Blocked</span>
              <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-slate-500" /> Not Scanned</span>
            </div>
            <a href="/dashboard/assets_map" className="inline-flex items-center gap-2 rounded border border-gold/30 px-3 py-2 text-[10px] font-black uppercase tracking-widest text-gold hover:bg-gold/10">
              View All Domains <ArrowRight className="h-3.5 w-3.5" />
            </a>
          </div>
        </GlassPanel>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(320px,0.9fr)_minmax(0,1.1fr)]">
          <GlassPanel className="p-5">
            <SectionTitle icon={Route}>Agility Lifecycle</SectionTitle>
            <div className="space-y-4">
              {snapshot.lifecycle.map((step) => {
                const Icon = lifecycleIcons[step.key] || Route
                return (
                  <div key={step.key}>
                    <div className="mb-2 flex items-center justify-between">
                      <span className="flex items-center gap-2 text-xs font-black text-white/70">
                        <Icon className="h-4 w-4 text-gold" />
                        {step.label}
                      </span>
                      <span className="font-mono text-xs font-bold text-white/55">{step.value}%</span>
                    </div>
                    <ProgressBar value={step.value} />
                  </div>
                )
              })}
            </div>
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle icon={TimerReset} suffix={<span className="rounded border border-gold/30 bg-gold/10 px-2 py-0.5 text-[9px] font-black text-gold">{snapshot.automationQueue.length}</span>}>
              Automation Queue
            </SectionTitle>
            {snapshot.automationQueue.length === 0 ? (
              <EmptyState label="No active switch tasks. New scan findings and migrations will appear here." />
            ) : (
              <div className="space-y-2">
                {snapshot.automationQueue.map((task) => (
                  <a
                    href="/dashboard/live-migration"
                    key={task.id}
                    className="flex items-center gap-3 rounded-md border border-white/5 bg-white/[0.025] p-3 transition hover:border-gold/40 hover:bg-gold/[0.06]"
                  >
                    <div className={cn('flex h-7 w-7 shrink-0 items-center justify-center rounded-md border', statusClass(task.status))}>
                      {task.status.toLowerCase().includes('blocked') ? <AlertTriangle className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-xs font-black text-white/80">{task.title}</div>
                      <div className={cn('mt-1 text-[9px] font-bold uppercase tracking-wider', priorityClass(task.priority))}>{task.priority}</div>
                    </div>
                    <span className={cn('rounded border px-2 py-1 text-[8px] font-black uppercase tracking-wider', statusClass(task.status))}>{task.status}</span>
                    <span className="w-16 text-right text-[10px] font-mono text-white/40">{task.eta}</span>
                    <Play className="h-4 w-4 text-gold" />
                  </a>
                ))}
              </div>
            )}
            <div className="mt-4 flex justify-end border-t border-white/5 pt-3">
              <a href="/dashboard/live-migration" className="inline-flex items-center gap-2 rounded border border-gold/30 px-3 py-2 text-[10px] font-black uppercase tracking-widest text-gold hover:bg-gold/10">
                View All Tasks <ArrowRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </GlassPanel>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1.4fr)_minmax(300px,0.8fr)]">
        <GlassPanel className="p-5">
          <SectionTitle icon={Shuffle}>Crypto Agility Overview</SectionTitle>
          <div className="grid gap-5 lg:grid-cols-[150px_minmax(0,1fr)]">
            <div className="flex justify-center">
              <Donut
                ready={metrics.ready}
                staged={metrics.staged}
                blocked={metrics.blocked}
                notScanned={metrics.notScanned}
                total={metrics.totalDomains}
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-3">
                {[
                  ['Ready', metrics.ready, GREEN],
                  ['Staged', metrics.staged, GOLD],
                  ['Blocked', metrics.blocked, RED],
                  ['Not Scanned', metrics.notScanned, '#64748b'],
                ].map(([label, count, color]) => (
                  <div key={String(label)} className="flex items-center gap-3 text-xs">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: String(color) }} />
                    <span className="flex-1 text-white/60">{label}</span>
                    <span className="font-mono font-bold text-white">{numberFmt(Number(count))}</span>
                  </div>
                ))}
              </div>
              <div>
                <div className="mb-2 text-[9px] font-black uppercase tracking-[0.2em] text-gold">Top Blocker Categories</div>
                {snapshot.overview.topBlockers.length === 0 ? (
                  <div className="rounded-md border border-white/5 bg-white/[0.02] p-3 text-xs text-white/35">No active blockers.</div>
                ) : (
                  <div className="space-y-2">
                    {snapshot.overview.topBlockers.map((blocker) => (
                      <div key={blocker.label} className="grid grid-cols-[1fr_44px] items-center gap-3 text-[10px]">
                        <div>
                          <div className="mb-1 flex justify-between text-white/60">
                            <span>{blocker.label}</span>
                            <span>{blocker.count}</span>
                          </div>
                          <ProgressBar value={(blocker.count / Math.max(1, snapshot.overview.topBlockers[0]?.count || 1)) * 100} color={blocker.label.toLowerCase().includes('failed') ? RED : GOLD} />
                        </div>
                        <span className="font-mono text-white/45">{numberFmt(blocker.count)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={GitCompare}>Switch Trend <span className="text-white/35">(Last 30 Days)</span></SectionTitle>
          <MiniTrendChart data={snapshot.overview.switchTrend} />
          <div className="mt-4 flex items-center gap-5 text-[10px] font-bold text-white/45">
            <span className="inline-flex items-center gap-2"><span className="h-1.5 w-5 rounded-full bg-emerald-500" /> Successful</span>
            <span className="inline-flex items-center gap-2"><span className="h-1.5 w-5 rounded-full bg-gold" /> Staged</span>
            <span className="inline-flex items-center gap-2"><span className="h-1.5 w-5 rounded-full bg-red-500" /> Blocked</span>
          </div>
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={Box}>Quick Actions</SectionTitle>
          <div className="space-y-2">
            {[
              { label: 'Scan Cryptographic Inventory', href: '/dashboard/scanner', icon: Layers },
              { label: 'Analyze Switch Readiness', href: '/dashboard/crypto-exposure', icon: GitCompare },
              { label: 'Simulate Algorithm Migration', href: '/dashboard/migration-sandbox', icon: Sparkles },
              { label: 'View Abstraction Layers', href: '/dashboard/runtime-crypto-intel', icon: Shuffle },
              { label: 'Manage Policy Packs', href: '/dashboard/crypto-policies', icon: PackageCheck },
              { label: 'Configure Rollback Strategy', href: '/dashboard/live-migration', icon: RefreshCw },
            ].map((action) => {
              const Icon = action.icon
              return (
                <a key={action.href} href={action.href} className="flex items-center gap-3 rounded-md border border-white/5 bg-white/[0.025] px-3 py-3 text-xs font-bold text-white/65 transition hover:border-gold/40 hover:bg-gold/[0.06] hover:text-gold">
                  <Icon className="h-4 w-4 text-gold" />
                  <span className="truncate">{action.label}</span>
                </a>
              )
            })}
          </div>
        </GlassPanel>
      </div>

      <GlassPanel className="p-5">
        <SectionTitle icon={PackageCheck}>Policy Packs Library</SectionTitle>
        {snapshot.policyPacks.length === 0 ? (
          <EmptyState label="No policy packs can be derived yet. Run a cryptographic inventory scan to build policy bundles." />
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            {snapshot.policyPacks.map((pack) => (
              <article key={pack.id} className="rounded-lg border border-white/10 bg-white/[0.025] p-4 transition hover:border-gold/40 hover:bg-gold/[0.05]">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-black text-white/90">{pack.name}</h3>
                    <p className="mt-1 font-mono text-xs font-bold text-gold">{pack.algorithms}</p>
                  </div>
                  <span className={cn('rounded border px-2 py-1 text-[8px] font-black uppercase tracking-wider', statusClass(pack.status))}>{pack.status}</span>
                </div>
                <p className="mt-3 min-h-[42px] text-xs leading-relaxed text-white/45">{pack.description}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <span className="rounded border border-white/10 bg-black/20 px-2 py-1 text-[8px] font-bold uppercase text-white/45">{pack.version}</span>
                  <span className="rounded border border-white/10 bg-black/20 px-2 py-1 text-[8px] font-bold uppercase text-white/45">{pack.standard}</span>
                </div>
                <div className="mt-4 grid grid-cols-3 gap-3 border-t border-white/5 pt-3 text-center">
                  <div>
                    <div className="text-[9px] uppercase text-white/35">Domains</div>
                    <div className="mt-1 font-mono text-sm font-black text-white">{numberFmt(pack.domains)}</div>
                  </div>
                  <div>
                    <div className="text-[9px] uppercase text-white/35">Assets</div>
                    <div className="mt-1 font-mono text-sm font-black text-white">{numberFmt(pack.assets)}</div>
                  </div>
                  <div>
                    <div className="text-[9px] uppercase text-white/35">Rate</div>
                    <div className="mt-1 font-mono text-sm font-black text-white">{pack.successRate}%</div>
                  </div>
                </div>
                <a href="/dashboard/crypto-policies" className="mt-4 flex h-8 items-center justify-center rounded border border-gold/25 text-[10px] font-black uppercase tracking-widest text-gold hover:bg-gold/10">
                  View Details
                </a>
              </article>
            ))}
          </div>
        )}
      </GlassPanel>

      <footer className="flex flex-col gap-2 border-t border-white/5 pt-3 text-[10px] font-mono uppercase tracking-wider text-white/30 md:flex-row md:items-center md:justify-between">
        <span>Last scan: {relativeTime(snapshot.latest.lastScanAt)}</span>
        <span>Active scans: {numberFmt(snapshot.latest.activeScans)} / Latest event: {snapshot.latest.latestEvent?.event_type?.replace(/_/g, ' ') || 'none'}</span>
        {state === 'loading' && <span>Loading live crypto-agility telemetry...</span>}
      </footer>
    </main>
  )
}
