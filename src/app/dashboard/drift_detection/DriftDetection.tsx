import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  AlertTriangle,
  Bell,
  CalendarDays,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Download,
  Eye,
  FileText,
  Filter,
  MoreVertical,
  Play,
  Plus,
  Radio,
  RefreshCw,
  Settings,
  ShieldAlert,
  XCircle,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'

type LoadState = 'loading' | 'success' | 'error'
type DriftSeverity = 'critical' | 'high' | 'medium' | 'low'
type DriftStatus = 'Unresolved' | 'Resolved' | 'Auto-Remediated'

type DriftEventRow = {
  id: string
  severity: DriftSeverity
  event: string
  resource: string
  resourceRegion: string
  type: string
  detectedAt: string | null
  status: DriftStatus
  expected: string
  actual: string
}

type DriftMetricSet = {
  unresolvedDrifts: number
  criticalDrifts: number
  autoRemediated: number
  totalEvents24h: number
  unresolvedDelta: number
  criticalDelta: number
  autoRemediatedDelta: number
  totalEventsDelta: number
  environmentRiskScore: number
  environmentRiskDelta: number
}

type DistributionRow = {
  severity: DriftSeverity
  count: number
  percent: number
}

type TrendPoint = {
  label: string
  critical: number
  high: number
  medium: number
  low: number
}

type CategoryRow = {
  label: string
  count: number
}

type ActivityRow = {
  id: string
  title: string
  resource: string
  timestamp: string | null
  severity: DriftSeverity
  status: DriftStatus
}

type DriftSnapshot = {
  generatedAt: string | null
  metrics: DriftMetricSet
  events: DriftEventRow[]
  driftDistribution: DistributionRow[]
  trend: TrendPoint[]
  categories: CategoryRow[]
  recentActivity: ActivityRow[]
}

const EMPTY_SNAPSHOT: DriftSnapshot = {
  generatedAt: null,
  metrics: {
    unresolvedDrifts: 0,
    criticalDrifts: 0,
    autoRemediated: 0,
    totalEvents24h: 0,
    unresolvedDelta: 0,
    criticalDelta: 0,
    autoRemediatedDelta: 0,
    totalEventsDelta: 0,
    environmentRiskScore: 0,
    environmentRiskDelta: 0,
  },
  events: [],
  driftDistribution: [
    { severity: 'critical', count: 0, percent: 0 },
    { severity: 'high', count: 0, percent: 0 },
    { severity: 'medium', count: 0, percent: 0 },
    { severity: 'low', count: 0, percent: 0 },
  ],
  trend: [],
  categories: [],
  recentActivity: [],
}

const GOLD = '#FBBF24'
const RED = '#EF4444'
const ORANGE = '#F97316'
const GREEN = '#22C55E'
const CYAN = '#22D3EE'

const SEVERITY_COLORS: Record<DriftSeverity, string> = {
  critical: RED,
  high: ORANGE,
  medium: GOLD,
  low: GREEN,
}

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-gold/18 bg-[#07101D]/72 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(251,191,36,0.035),0_0_34px_rgba(0,0,0,0.32)] transition-all duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/80 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-24px_60px_rgba(251,191,36,0.12),0_14px_42px_rgba(0,0,0,0.45),0_0_54px_rgba(251,191,36,0.32)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/70 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-52 after:w-52 after:rounded-full after:bg-gold/10 after:blur-3xl after:transition-all group-hover:after:bg-gold/20'

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(value || 0)))
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

function dateOnly(value: string | null) {
  if (!value) return '--'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '--'
  return date.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })
}

function formatDelta(value: number) {
  if (value > 0) return `+${numberFmt(value)} from yesterday`
  if (value < 0) return `${numberFmt(value)} from yesterday`
  return 'no change from yesterday'
}

function severityClass(severity: DriftSeverity) {
  if (severity === 'critical') return 'border-red-500/35 bg-red-500/10 text-red-300'
  if (severity === 'high') return 'border-orange-500/35 bg-orange-500/10 text-orange-300'
  if (severity === 'medium') return 'border-gold/35 bg-gold/10 text-gold'
  return 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300'
}

function statusClass(status: DriftStatus) {
  if (status === 'Unresolved') return 'text-red-300'
  if (status === 'Auto-Remediated') return 'text-cyan-300'
  return 'text-emerald-300'
}

function statusIcon(status: DriftStatus, severity: DriftSeverity) {
  if (status === 'Auto-Remediated') return RefreshCw
  if (status === 'Resolved') return CheckCircle2
  return severity === 'critical' ? AlertTriangle : ShieldAlert
}

function useDriftSnapshot() {
  const { session, user } = useAuth()
  const token = session?.access_token
  const [snapshot, setSnapshot] = useState<DriftSnapshot>(EMPTY_SNAPSHOT)
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)

  const fetchSnapshot = useCallback(async () => {
    if (!token) return
    setState((current) => current === 'success' ? current : 'loading')
    try {
      const response = await fetch('/api/v1/dashboard/drift', {
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
      const message = err instanceof Error ? err.message : 'Unable to load drift telemetry'
      console.error('Drift telemetry failed:', err)
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
      'pqc_scan_sessions',
      'pqc_scan_results',
      'security_events',
      'migration_events',
      'compliance_evidence',
      'vulnerabilities',
      'certificates',
    ]

    const channels = tables.map((table) => supabase
      .channel(`drift-detection-${table}`)
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
      <h2 className="flex items-center gap-2 font-mono text-xs font-black uppercase tracking-[0.2em] text-white/75">
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

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const width = 92
  const height = 34
  const max = Math.max(1, ...values)
  const points = values.length
    ? values.map((value, index) => {
      const x = values.length === 1 ? width : (index / (values.length - 1)) * width
      const y = height - (value / max) * (height - 6) - 3
      return `${x},${y}`
    }).join(' ')
    : `0,${height - 3} ${width},${height - 3}`

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-9 w-24 overflow-visible">
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function MetricCard({ label, value, detail, icon: Icon, tone, sparkValues }: { label: string; value: string; detail: string; icon: LucideIcon; tone: DriftSeverity | 'cyan' | 'gold'; sparkValues: number[] }) {
  const color = tone === 'critical' ? RED : tone === 'high' ? ORANGE : tone === 'medium' || tone === 'gold' ? GOLD : tone === 'cyan' ? CYAN : GREEN
  return (
    <GlassPanel className="p-5">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full border bg-black/25" style={{ borderColor: `${color}66`, color, boxShadow: `0 0 28px ${color}24` }}>
            <Icon className="h-6 w-6" />
          </div>
          <div>
            <div className="font-mono text-[9px] font-black uppercase tracking-[0.18em] text-white/45">{label}</div>
            <div className="mt-2 font-mono text-3xl font-black leading-none text-white">{value}</div>
            <div className={cn('mt-2 text-[10px] font-bold', detail.startsWith('+') ? 'text-emerald-300' : detail.startsWith('-') ? 'text-red-300' : 'text-white/45')}>{detail}</div>
          </div>
        </div>
        <div className="hidden self-end md:block">
          <Sparkline values={sparkValues} color={color} />
        </div>
      </div>
    </GlassPanel>
  )
}

function DriftDonut({ distribution }: { distribution: DistributionRow[] }) {
  const total = Math.max(1, distribution.reduce((sum, row) => sum + row.count, 0))
  let cursor = 0
  const segments = distribution.map((row) => {
    const start = cursor
    const size = (row.count / total) * 100
    cursor += size
    return `${SEVERITY_COLORS[row.severity]} ${start}% ${cursor}%`
  })
  const gradient = `conic-gradient(${segments.join(', ') || '#334155 0 100%'})`

  return (
    <div className="grid gap-5 sm:grid-cols-[150px_minmax(0,1fr)]">
      <div className="flex justify-center">
        <div className="relative flex h-32 w-32 items-center justify-center rounded-full" style={{ background: gradient }}>
          <div className="absolute inset-5 rounded-full bg-[#07101D] shadow-[inset_0_0_24px_rgba(0,0,0,0.55)]" />
          <div className="relative text-center">
            <div className="font-mono text-3xl font-black text-white">{numberFmt(distribution.reduce((sum, row) => sum + row.count, 0))}</div>
            <div className="text-[10px] text-white/45">Total</div>
          </div>
        </div>
      </div>
      <div className="space-y-3 self-center">
        {distribution.map((row) => (
          <div key={row.severity} className="flex items-center gap-3 text-sm">
            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[row.severity] }} />
            <span className="flex-1 capitalize text-white/65">{row.severity}</span>
            <span className="font-mono font-bold text-white">{numberFmt(row.count)} ({row.percent}%)</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function TrendChart({ data }: { data: TrendPoint[] }) {
  const width = 420
  const height = 190
  const pad = 28
  const series = [
    { key: 'critical' as const, color: RED, label: 'Critical' },
    { key: 'high' as const, color: ORANGE, label: 'High' },
    { key: 'medium' as const, color: GOLD, label: 'Medium' },
    { key: 'low' as const, color: GREEN, label: 'Low' },
  ]
  const max = Math.max(1, ...data.flatMap((point) => series.map((item) => Number(point[item.key] || 0))))

  const pathFor = (key: keyof TrendPoint) => data.map((point, index) => {
    const x = pad + (index / Math.max(1, data.length - 1)) * (width - pad * 2)
    const y = height - pad - (Number(point[key] || 0) / max) * (height - pad * 2)
    return `${index === 0 ? 'M' : 'L'} ${x} ${y}`
  }).join(' ')

  return (
    <div>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-48 w-full">
        {[0, 1, 2, 3].map((line) => (
          <line key={line} x1={pad} x2={width - pad} y1={pad + line * ((height - pad * 2) / 3)} y2={pad + line * ((height - pad * 2) / 3)} stroke="rgba(255,255,255,0.07)" />
        ))}
        {data.map((point, index) => {
          const x = pad + (index / Math.max(1, data.length - 1)) * (width - pad * 2)
          return (
            <g key={point.label}>
              <line x1={x} x2={x} y1={pad} y2={height - pad} stroke="rgba(255,255,255,0.05)" />
              <text x={x} y={height - 6} textAnchor="middle" className="fill-white/45 text-[10px]">{point.label}</text>
            </g>
          )
        })}
        {series.map((item) => (
          <path key={item.key} d={pathFor(item.key)} fill="none" stroke={item.color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        ))}
      </svg>
      <div className="flex flex-wrap items-center gap-5 text-[10px] font-bold text-white/45">
        {series.map((item) => (
          <span key={item.key} className="inline-flex items-center gap-2"><span className="h-1.5 w-5 rounded-full" style={{ backgroundColor: item.color }} /> {item.label}</span>
        ))}
      </div>
    </div>
  )
}

function RiskGauge({ value, delta }: { value: number; delta: number }) {
  const angle = -120 + (Math.max(0, Math.min(100, value)) / 100) * 240
  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative h-36 w-44">
        <div className="absolute inset-x-3 bottom-0 h-32 rounded-t-full" style={{ background: `conic-gradient(from 240deg, ${GREEN} 0 33%, ${GOLD} 33% 66%, ${RED} 66% 100%)`, clipPath: 'polygon(0 0, 100% 0, 100% 70%, 0 70%)' }} />
        <div className="absolute inset-x-7 bottom-0 h-24 rounded-t-full bg-[#07101D]" />
        <div className="absolute left-1/2 top-20 h-1 w-16 origin-left rounded-full bg-white shadow-[0_0_10px_rgba(255,255,255,0.8)]" style={{ transform: `rotate(${angle}deg)` }} />
        <div className="absolute inset-x-0 bottom-4 text-center">
          <div className="font-mono text-4xl font-black text-white">{numberFmt(value)}<span className="text-sm text-white/40">/100</span></div>
          <div className={cn('mt-1 text-xs font-black', value >= 70 ? 'text-orange-300' : value >= 40 ? 'text-gold' : 'text-emerald-300')}>
            {value >= 70 ? 'High Risk' : value >= 40 ? 'Moderate Risk' : value ? 'Low Risk' : 'No Active Risk'}
          </div>
        </div>
      </div>
      <div className={cn('mt-2 text-xs font-semibold', delta > 0 ? 'text-emerald-300' : delta < 0 ? 'text-red-300' : 'text-white/40')}>{formatDelta(delta)}</div>
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

function exportJson(name: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `${name}-${new Date().toISOString().slice(0, 10)}.json`
  anchor.click()
  URL.revokeObjectURL(url)
}

export default function DriftDetection() {
  const { snapshot, state, error, sseConnected, refresh } = useDriftSnapshot()
  const [tab, setTab] = useState<'all' | 'unresolved' | 'resolved'>('all')
  const [severityFilter, setSeverityFilter] = useState<'all' | DriftSeverity>('all')
  const [environmentFilter, setEnvironmentFilter] = useState('all')

  const metrics = snapshot.metrics
  const generatedAt = useMemo(() => snapshot.generatedAt ? new Date(snapshot.generatedAt) : new Date(), [snapshot.generatedAt])
  const environments = useMemo(() => Array.from(new Set(snapshot.events.map((event) => event.resourceRegion).filter(Boolean))).sort(), [snapshot.events])

  const filteredEvents = useMemo(() => snapshot.events.filter((event) => {
    if (tab === 'unresolved' && event.status !== 'Unresolved') return false
    if (tab === 'resolved' && event.status === 'Unresolved') return false
    if (severityFilter !== 'all' && event.severity !== severityFilter) return false
    if (environmentFilter !== 'all' && event.resourceRegion !== environmentFilter) return false
    return true
  }), [environmentFilter, severityFilter, snapshot.events, tab])

  const sparkValues = useMemo(() => snapshot.trend.map((point) => point.critical + point.high + point.medium + point.low), [snapshot.trend])

  const cards = [
    { label: 'Unresolved Drifts', value: numberFmt(metrics.unresolvedDrifts), detail: formatDelta(metrics.unresolvedDelta), icon: AlertTriangle, tone: 'critical' as const, sparkValues },
    { label: 'Critical Drifts', value: numberFmt(metrics.criticalDrifts), detail: formatDelta(metrics.criticalDelta), icon: XCircle, tone: 'critical' as const, sparkValues: snapshot.trend.map((point) => point.critical) },
    { label: 'Auto-Remediated', value: numberFmt(metrics.autoRemediated), detail: formatDelta(metrics.autoRemediatedDelta), icon: RefreshCw, tone: 'cyan' as const, sparkValues: sparkValues.map((value) => Math.max(0, value - metrics.criticalDrifts)) },
    { label: 'Total Events (24h)', value: numberFmt(metrics.totalEvents24h), detail: formatDelta(metrics.totalEventsDelta), icon: Eye, tone: 'gold' as const, sparkValues },
  ]

  const tabs = [
    { key: 'all' as const, label: 'All Events', count: snapshot.events.length },
    { key: 'unresolved' as const, label: 'Unresolved', count: snapshot.events.filter((event) => event.status === 'Unresolved').length },
    { key: 'resolved' as const, label: 'Resolved', count: snapshot.events.filter((event) => event.status !== 'Unresolved').length },
  ]

  return (
    <main className="min-h-screen space-y-4 bg-[#02070E] p-3 text-white md:p-4">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <h1 className="font-mono text-3xl font-black uppercase tracking-tight text-white md:text-4xl">Drift <span className="text-gold">Detection</span></h1>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-white/58">Continuous monitoring for cryptographic configuration drift, algorithm downgrades, and policy violations.</p>
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
          <HeaderButton icon={Download} onClick={() => exportJson('drift-detection-report', snapshot)}>Export Report</HeaderButton>
          <HeaderButton icon={Plus} href="/dashboard/scanner" primary>New Scan</HeaderButton>
          <button type="button" className="relative flex h-10 w-10 items-center justify-center rounded-md border border-gold/15 bg-black/20 text-gold hover:border-gold/50">
            <Bell className="h-4 w-4" />
            {metrics.criticalDrifts > 0 && <span className="absolute -right-1 -top-1 rounded-full bg-gold px-1.5 text-[9px] font-black text-black">{numberFmt(metrics.criticalDrifts)}</span>}
          </button>
          <div className="hidden items-center gap-2 border-l border-white/8 pl-5 xl:flex">
            <div className="font-mono text-[10px] font-bold uppercase text-white/60">
              <div>{generatedAt.toLocaleTimeString('en-US', { hour12: false })} UTC</div>
              <div className="text-white/35">{generatedAt.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })}</div>
            </div>
          </div>
          <a href="/dashboard/crypto-policies" className="flex h-10 w-10 items-center justify-center rounded-md border border-gold/20 bg-black/20 text-gold transition hover:border-gold/60 hover:bg-gold/10" aria-label="Open drift policy settings">
            <Settings className="h-4 w-4" />
          </a>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {cards.map((card) => (
          <div key={card.label}>
            <MetricCard {...card} />
          </div>
        ))}
      </div>

      <GlassPanel className="p-4">
        <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_210px_210px_210px_140px]">
          <div className="flex flex-wrap gap-2">
            {tabs.map((item) => (
              <button
                type="button"
                key={item.key}
                onClick={() => setTab(item.key)}
                className={cn(
                  'rounded-md border px-4 py-2 text-xs font-black transition',
                  tab === item.key ? 'border-gold/55 bg-gold/10 text-gold shadow-[0_0_18px_rgba(251,191,36,0.18)]' : 'border-white/10 bg-black/15 text-white/45 hover:border-gold/30 hover:text-white/70'
                )}
              >
                {item.label} ({numberFmt(item.count)})
              </button>
            ))}
          </div>

          <div className="inline-flex items-center justify-between rounded-md border border-white/10 bg-black/20 px-3 py-2 text-xs text-white/70">
            <span>Last 24 hours</span>
            <CalendarDays className="h-4 w-4 text-gold" />
          </div>
          <select value={environmentFilter} onChange={(event) => setEnvironmentFilter(event.target.value)} className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-xs text-white/70 outline-none focus:border-gold/40">
            <option value="all">All Environments</option>
            {environments.map((environment) => <option key={environment} value={environment}>{environment}</option>)}
          </select>
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as 'all' | DriftSeverity)} className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-xs text-white/70 outline-none focus:border-gold/40">
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button type="button" className="inline-flex items-center justify-center gap-2 rounded-md border border-gold/25 bg-black/20 px-3 py-2 text-xs font-black text-gold hover:bg-gold/10">
            <Filter className="h-4 w-4" />
            Filters
          </button>
        </div>
      </GlassPanel>

      <div className="space-y-4">
        <GlassPanel className="p-5">
          <SectionTitle icon={Radio}>Drift Events</SectionTitle>
          {filteredEvents.length === 0 ? (
            <EmptyState label="No drift events match the current filters." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[980px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-white/8 bg-white/[0.025]">
                    {['Severity', 'Event', 'Resource', 'Type', 'Detected At', 'Status', 'Actions'].map((header) => (
                      <th key={header} className="px-3 py-3 font-mono text-[9px] font-black uppercase tracking-wider text-white/45">{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filteredEvents.slice(0, 8).map((event) => (
                    <tr key={event.id} className="transition hover:bg-gold/[0.04]">
                      <td className="px-3 py-3">
                        <span className={cn('inline-flex items-center gap-2 rounded border px-2 py-1 font-mono text-[9px] font-black uppercase tracking-wider', severityClass(event.severity))}>
                          <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[event.severity] }} />
                          {event.severity}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        <div className="text-sm font-black text-white/88">{event.event}</div>
                        <div className="mt-1 text-[10px] text-white/45">Expected: {event.expected}</div>
                      </td>
                      <td className="px-3 py-3">
                        <div className="text-xs font-black text-white/80">{event.resource}</div>
                        <div className="mt-1 text-[10px] text-white/45">{event.resourceRegion}</div>
                      </td>
                      <td className="px-3 py-3">
                        <span className="rounded border border-gold/20 bg-gold/10 px-2 py-1 font-mono text-[9px] font-black uppercase tracking-wider text-gold">{event.type}</span>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-white/60">
                        <div>{timeOnly(event.detectedAt)}</div>
                        <div className="mt-1 text-white/35">{dateOnly(event.detectedAt)}</div>
                      </td>
                      <td className={cn('px-3 py-3 text-xs font-black', statusClass(event.status))}>{event.status}</td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-2">
                          <a href="/dashboard/runtime-telemetry" className="flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-black/20 text-gold hover:border-gold/40" aria-label={`Inspect ${event.event}`}>
                            <Play className="h-3.5 w-3.5" />
                          </a>
                          <button type="button" className="flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-black/20 text-gold hover:border-gold/40" aria-label={`Actions for ${event.event}`}>
                            <MoreVertical className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="mt-4 flex items-center justify-between border-t border-white/5 pt-3 text-xs text-white/45">
            <span>Showing {numberFmt(Math.min(8, filteredEvents.length))} of {numberFmt(filteredEvents.length)} events</span>
            <div className="flex items-center gap-2">
              <button type="button" className="flex h-7 w-7 items-center justify-center rounded border border-white/10 text-white/35"><ChevronLeft className="h-4 w-4" /></button>
              <span className="rounded border border-gold/40 px-2 py-1 font-mono text-gold">1</span>
              <button type="button" className="flex h-7 w-7 items-center justify-center rounded border border-white/10 text-white/35"><ChevronRight className="h-4 w-4" /></button>
            </div>
          </div>
        </GlassPanel>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(320px,0.8fr)_minmax(320px,0.85fr)_minmax(360px,1fr)]">
          <GlassPanel className="p-5">
            <SectionTitle icon={Eye}>Drift Distribution</SectionTitle>
            <DriftDonut distribution={snapshot.driftDistribution} />
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle icon={Radio} suffix={<a href="/dashboard/audit-vault" className="rounded border border-gold/30 px-3 py-1.5 text-[10px] font-black text-gold hover:bg-gold/10">View All</a>}>
              Recent Activity
            </SectionTitle>
            {snapshot.recentActivity.length === 0 ? (
              <EmptyState label="No recent drift activity yet." />
            ) : (
              <div className="space-y-3">
                {snapshot.recentActivity.map((activity) => {
                  const Icon = statusIcon(activity.status, activity.severity)
                  return (
                    <div key={activity.id} className="grid grid-cols-[24px_minmax(0,1fr)_64px] gap-3 border-b border-white/5 pb-3 last:border-b-0 last:pb-0">
                      <Icon className={cn('mt-1 h-4 w-4', activity.status === 'Resolved' ? 'text-emerald-300' : activity.status === 'Auto-Remediated' ? 'text-cyan-300' : activity.severity === 'critical' ? 'text-red-300' : 'text-orange-300')} />
                      <div className="min-w-0">
                        <div className="truncate text-xs font-bold text-white/80">{activity.title}</div>
                        <div className="mt-1 truncate text-[10px] text-white/40">{activity.resource}</div>
                      </div>
                      <div className="font-mono text-[10px] text-white/55">{timeOnly(activity.timestamp)}</div>
                    </div>
                  )
                })}
              </div>
            )}
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle icon={Settings}>Quick Actions</SectionTitle>
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                { label: 'Run Drift Scan', detail: 'Scan environments', href: '/dashboard/scanner', icon: Radio },
                { label: 'View Policies', detail: 'Manage drift policies', href: '/dashboard/crypto-policies', icon: FileText },
                { label: 'Auto-Remediation', detail: 'Configure actions', href: '/dashboard/pqc-orchestration', icon: RefreshCw },
                { label: 'Generate Report', detail: 'Export drift report', onClick: () => exportJson('drift-detection-report', snapshot), icon: FileText },
              ].map((action) => {
                const Icon = action.icon
                const content = (
                  <>
                    <Icon className="h-5 w-5 text-gold" />
                    <div>
                      <div className="text-xs font-black text-white/90">{action.label}</div>
                      <div className="mt-1 text-[10px] text-white/45">{action.detail}</div>
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
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,0.65fr)_minmax(260px,0.55fr)]">
        <GlassPanel className="p-5">
          <SectionTitle icon={Radio}>Drift Trends <span className="text-white/35">(7 Days)</span></SectionTitle>
          <TrendChart data={snapshot.trend} />
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={Filter}>Top Drift Categories</SectionTitle>
          {snapshot.categories.length === 0 ? (
            <EmptyState label="No drift categories detected." />
          ) : (
            <div className="space-y-4">
              {snapshot.categories.map((category, index) => {
                const color = [RED, ORANGE, GOLD, CYAN, '#A855F7'][index] || GOLD
                const max = Math.max(1, snapshot.categories[0]?.count || 1)
                return (
                  <div key={category.label} className="grid grid-cols-[minmax(0,1fr)_36px] items-center gap-3 text-xs">
                    <div>
                      <div className="mb-2 flex justify-between text-white/65">
                        <span>{category.label}</span>
                      </div>
                      <div className="h-2 overflow-hidden rounded-full bg-white/7">
                        <div className="h-full rounded-full" style={{ width: `${(category.count / max) * 100}%`, backgroundColor: color, boxShadow: `0 0 12px ${color}66` }} />
                      </div>
                    </div>
                    <span className="font-mono font-black text-white">{numberFmt(category.count)}</span>
                  </div>
                )
              })}
            </div>
          )}
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={ShieldAlert}>Environment Risk Score</SectionTitle>
          <RiskGauge value={metrics.environmentRiskScore} delta={metrics.environmentRiskDelta} />
        </GlassPanel>
      </div>

      <footer className="flex flex-col gap-2 border-t border-white/5 pt-3 text-[10px] font-mono uppercase tracking-wider text-white/30 md:flex-row md:items-center md:justify-between">
        <span>{error ? `Telemetry warning: ${error}` : 'Drift telemetry synchronized'}</span>
        <span>Live stream: {sseConnected ? 'connected' : 'standby'} / Snapshot: {snapshot.generatedAt ? relativeTime(snapshot.generatedAt) : 'pending'}</span>
        {state === 'loading' && <span>Loading drift telemetry...</span>}
      </footer>
    </main>
  )
}
