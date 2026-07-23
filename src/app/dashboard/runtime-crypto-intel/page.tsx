import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  AlertTriangle,
  Bell,
  CalendarDays,
  ChevronRight,
  Cpu,
  Database,
  Download,
  Eye,
  Filter,
  KeyRound,
  Lock,
  Maximize2,
  Menu,
  Network,
  Radio,
  RefreshCw,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'

type LoadState = 'loading' | 'success' | 'error'
type Severity = 'critical' | 'high' | 'medium' | 'low' | string

type RuntimeMetrics = {
  cryptoOpsPerSec: number
  cryptoOpsDelta: number
  encryptionOpsPerSec: number
  encryptionDelta: number
  decryptionOpsPerSec: number
  decryptionDelta: number
  keyUsageEventsPerSec: number
  keyUsageDelta: number
  pqcHandshakesPerSec: number
  pqcHandshakeDelta: number
  quantumExposureScore: number
}

type TrendPoint = {
  label: string
  encryption: number
  decryption: number
  keyUsage: number
  other: number
}

type HealthRow = {
  label: string
  count: number
  percent: number
}

type CryptoHealth = {
  score: number
  total: number
  strong: number
  warning: number
  weak: number
  critical: number
  rows: HealthRow[]
}

type CountRow = {
  label: string
  count: number
  percent?: number
}

type AlgorithmRow = {
  algorithm: string
  usage: number
  percent: number
  trend: number[]
}

type AlertRow = {
  id: string
  title: string
  resource: string
  severity: Severity
  timestamp: string | null
}

type VerificationRow = {
  label: string
  status: string
  count: number
  detail: string
}

type MigrationValidation = {
  progress: number
  migratedAssets: number
  inProgress: number
  pending: number
  failedBlocked: number
}

type KeyLifecycle = {
  generated7d: number
  generatedDelta: number
  rotated7d: number
  expiring30d: number
  compromisedKeys: number
  entropyQuality: number
}

type QuantumTelemetryRow = {
  label: string
  value: string
  percent: number
}

type RuntimeCoverage = {
  source: string
  totalRuntimeEvents: number
  runtimeEvents24h: number
  coveredAssets: number
  activeAgents: number
  staleAgents: number
  totalAgents: number
  sourceCoverage: CountRow[]
}

type EnterpriseSignals = {
  shadowCrypto: number
  downgradeAttempts: number
  hndlExposure: number
  weakCertificates: number
  vendorPackageCrypto: number
}

type EventPipeline = {
  status: string
  latestRuntimeEventAt: string | null
  openScannerAlerts: number
  table: string
}

type TopRisk = {
  id: string
  label: string
  category: string
  severity: Severity
  riskScore: number
  observedAt: string | null
}

type HandshakeRow = {
  id: string
  time: string | null
  source: string
  destination: string
  tlsVersion: string
  cipherSuite: string
  keyExchange: string
  pqc: boolean
  status: string
}

type GraphNode = {
  id: string
  label: string
  type: string
  criticality: string
}

type GraphEdge = {
  id: string
  source: string
  target: string
  label: string
}

type RuntimeSnapshot = {
  generatedAt: string | null
  latestScanAt: string | null
  filters: {
    environments: string[]
  }
  metrics: RuntimeMetrics
  operationsTrend: TrendPoint[]
  cryptoHealth: CryptoHealth
  threatHunting: CountRow[]
  operationsByType: CountRow[]
  algorithmUsage: AlgorithmRow[]
  protocolUsage: CountRow[]
  liveAlerts: AlertRow[]
  pqcVerification: VerificationRow[]
  migrationValidation: MigrationValidation
  keyLifecycle: KeyLifecycle
  quantumTelemetry: QuantumTelemetryRow[]
  tlsHandshakes: HandshakeRow[]
  dependencyGraph: {
    nodes: GraphNode[]
    edges: GraphEdge[]
  }
  runtimeCoverage: RuntimeCoverage
  enterpriseSignals: EnterpriseSignals
  eventPipeline: EventPipeline
  topRisks: TopRisk[]
}

const EMPTY_SNAPSHOT: RuntimeSnapshot = {
  generatedAt: null,
  latestScanAt: null,
  filters: { environments: [] },
  metrics: {
    cryptoOpsPerSec: 0,
    cryptoOpsDelta: 0,
    encryptionOpsPerSec: 0,
    encryptionDelta: 0,
    decryptionOpsPerSec: 0,
    decryptionDelta: 0,
    keyUsageEventsPerSec: 0,
    keyUsageDelta: 0,
    pqcHandshakesPerSec: 0,
    pqcHandshakeDelta: 0,
    quantumExposureScore: 0,
  },
  operationsTrend: [],
  cryptoHealth: {
    score: 0,
    total: 0,
    strong: 0,
    warning: 0,
    weak: 0,
    critical: 0,
    rows: [
      { label: 'Strong', count: 0, percent: 0 },
      { label: 'Warning', count: 0, percent: 0 },
      { label: 'Weak', count: 0, percent: 0 },
      { label: 'Critical', count: 0, percent: 0 },
    ],
  },
  threatHunting: [],
  operationsByType: [],
  algorithmUsage: [],
  protocolUsage: [],
  liveAlerts: [],
  pqcVerification: [],
  migrationValidation: { progress: 0, migratedAssets: 0, inProgress: 0, pending: 0, failedBlocked: 0 },
  keyLifecycle: { generated7d: 0, generatedDelta: 0, rotated7d: 0, expiring30d: 0, compromisedKeys: 0, entropyQuality: 0 },
  quantumTelemetry: [],
  tlsHandshakes: [],
  dependencyGraph: { nodes: [], edges: [] },
  runtimeCoverage: {
    source: 'fallback_telemetry',
    totalRuntimeEvents: 0,
    runtimeEvents24h: 0,
    coveredAssets: 0,
    activeAgents: 0,
    staleAgents: 0,
    totalAgents: 0,
    sourceCoverage: [],
  },
  enterpriseSignals: {
    shadowCrypto: 0,
    downgradeAttempts: 0,
    hndlExposure: 0,
    weakCertificates: 0,
    vendorPackageCrypto: 0,
  },
  eventPipeline: {
    status: 'no_agents',
    latestRuntimeEventAt: null,
    openScannerAlerts: 0,
    table: 'runtime_crypto_events',
  },
  topRisks: [],
}

const GOLD = '#FBBF24'
const GREEN = '#22C55E'
const RED = '#EF4444'
const ORANGE = '#F97316'
const BLUE = '#3B82F6'
const CYAN = '#06B6D4'
const PURPLE = '#A855F7'
const SLATE = '#94A3B8'

const DONUT_COLORS = [BLUE, GOLD, PURPLE, CYAN, GREEN, SLATE]
const HEALTH_COLORS: Record<string, string> = {
  Strong: GREEN,
  Warning: GOLD,
  Weak: ORANGE,
  Critical: RED,
}

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-gold/18 bg-[#07101D]/72 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(251,191,36,0.035),0_0_34px_rgba(0,0,0,0.32)] transition-all duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/80 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-24px_60px_rgba(251,191,36,0.12),0_14px_42px_rgba(0,0,0,0.45),0_0_54px_rgba(251,191,36,0.32)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/70 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-52 after:w-52 after:rounded-full after:bg-gold/10 after:blur-3xl after:transition-all group-hover:after:bg-gold/20'

function numberFmt(value: number) {
  const safe = Number.isFinite(value) ? Math.max(0, value) : 0
  return new Intl.NumberFormat('en-US', {
    maximumFractionDigits: safe > 99 ? 0 : safe >= 10 ? 1 : 2,
  }).format(safe)
}

function integerFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(value || 0)))
}

function formatDelta(value: number) {
  if (value > 0) return `+ ${integerFmt(value)}% vs last 7 days`
  if (value < 0) return `${integerFmt(value)}% vs last 7 days`
  return '0% vs last 7 days'
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

function shortDateRange() {
  const end = new Date()
  const start = new Date(end)
  start.setDate(end.getDate() - 7)
  const format = (date: Date) => date.toLocaleDateString('en-US', { month: 'short', day: '2-digit' })
  return `${format(start)} - ${format(end)}, ${end.getFullYear()}`
}

function severityColor(severity: Severity) {
  const value = String(severity || '').toLowerCase()
  if (value === 'critical') return RED
  if (value === 'high') return ORANGE
  if (value === 'medium' || value === 'warning') return GOLD
  return GREEN
}

function severityBadge(severity: Severity) {
  const value = String(severity || '').toLowerCase()
  if (value === 'critical') return 'border-red-500/35 bg-red-500/10 text-red-300'
  if (value === 'high') return 'border-orange-500/35 bg-orange-500/10 text-orange-300'
  if (value === 'medium' || value === 'warning') return 'border-gold/35 bg-gold/10 text-gold'
  return 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300'
}

function statusClass(value: string) {
  const lower = String(value || '').toLowerCase()
  if (lower.includes('active') || lower.includes('valid') || lower.includes('success') || lower.includes('strong') || lower.includes('clear')) return 'text-emerald-300'
  if (lower.includes('detected') || lower.includes('weak') || lower.includes('blocked') || lower.includes('compromised')) return 'text-red-300'
  if (lower.includes('pending') || lower.includes('warning') || lower.includes('moderate')) return 'text-gold'
  return 'text-white/55'
}

function useRuntimeCryptoSnapshot() {
  const { session, user } = useAuth()
  const token = session?.access_token
  const [snapshot, setSnapshot] = useState<RuntimeSnapshot>(EMPTY_SNAPSHOT)
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const streamsRef = useRef<EventSource[]>([])
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const closeStreams = useCallback(() => {
    for (const stream of streamsRef.current) stream.close()
    streamsRef.current = []
    setSseConnected(false)
  }, [])

  const fetchSnapshot = useCallback(async () => {
    if (!token) return
    setState((current) => current === 'success' ? current : 'loading')
    try {
      const response = await fetch('/api/v1/dashboard/runtime-crypto-intel', {
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
      const message = err instanceof Error ? err.message : 'Unable to load runtime cryptographic telemetry'
      console.error('Runtime crypto intelligence telemetry failed:', err)
      setError(message)
      setState('error')
    }
  }, [token])

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null
      void fetchSnapshot()
    }, 250)
  }, [fetchSnapshot])

  useEffect(() => () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
  }, [])

  useEffect(() => {
    if (!token || !user) {
      setSnapshot(EMPTY_SNAPSHOT)
      setState('success')
      setError(null)
      return
    }
    fetchSnapshot()
  }, [token, user, fetchSnapshot])

  useEffect(() => {
    if (!user) return
    const tables = [
      'assets',
      'asset_relationships',
      'crypto_inventory',
      'crypto_exposures',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'security_events',
      'migration_jobs',
      'migration_events',
      'compliance_evidence',
      'certificates',
      'qrng_events',
      'vault_audit_logs',
      'generated_keys',
      'runtime_crypto_events',
      'scanner_agents',
      'scanner_alerts',
      'scanner_evidence',
      'agent_heartbeats',
      'connector_accounts',
    ]

    const channels = tables.map((table) => supabase
      .channel(`runtime-crypto-intel-${table}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` },
        queueRefresh
      )
      .subscribe())

    return () => {
      for (const channel of channels) {
        supabase.removeChannel(channel)
      }
    }
  }, [user, queueRefresh])

  useEffect(() => {
    if (!token) {
      closeStreams()
      return
    }
    let retryTimer: ReturnType<typeof setTimeout> | undefined

    const connect = () => {
      closeStreams()
      const runtimeStream = new EventSource(`/api/v1/dashboard/runtime-crypto-intel/stream?token=${encodeURIComponent(token)}`)
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`)
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`)
      streamsRef.current = [runtimeStream, metricsStream, scannerStream]

      const markOpen = () => setSseConnected(true)
      const scheduleReconnect = () => {
        setSseConnected(false)
        closeStreams()
        if (retryTimer) clearTimeout(retryTimer)
        retryTimer = setTimeout(connect, 10000)
      }
      const refreshFromStream = () => queueRefresh()

      runtimeStream.onopen = markOpen
      metricsStream.onopen = markOpen
      scannerStream.onopen = markOpen
      runtimeStream.onerror = scheduleReconnect
      metricsStream.onerror = scheduleReconnect
      scannerStream.onerror = scheduleReconnect
      runtimeStream.addEventListener('runtime-crypto-intel-connected', refreshFromStream)
      runtimeStream.addEventListener('runtime-crypto-intel-update', refreshFromStream)
      runtimeStream.addEventListener('runtime-crypto-intel-error', refreshFromStream)
      metricsStream.addEventListener('metrics-update', refreshFromStream)
      metricsStream.addEventListener('runtime-crypto-update', refreshFromStream)
      metricsStream.addEventListener('scan-complete', refreshFromStream)
      scannerStream.addEventListener('scanner-intelligence', refreshFromStream)
      scannerStream.addEventListener('scanner-error', refreshFromStream)
    }

    connect()
    return () => {
      if (retryTimer) clearTimeout(retryTimer)
      closeStreams()
    }
  }, [token, queueRefresh, closeStreams])

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
      <h2 className="font-mono text-xs font-black uppercase tracking-[0.17em] text-white">
        <Icon className="mr-2 inline h-4 w-4 text-gold" />
        {children}
      </h2>
      {suffix}
    </div>
  )
}

function HeaderButton({ icon: Icon, children, onClick, primary }: { icon: LucideIcon; children: ReactNode; onClick?: () => void; primary?: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'inline-flex h-10 items-center gap-2 rounded-md border px-4 text-xs font-black transition',
        primary
          ? 'border-gold/70 bg-gold text-black shadow-[0_0_22px_rgba(251,191,36,0.28)] hover:bg-[#FFD766]'
          : 'border-white/10 bg-black/20 text-white/75 hover:border-gold/50 hover:bg-gold/10 hover:text-gold'
      )}
    >
      <Icon className="h-4 w-4" />
      {children}
    </button>
  )
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex min-h-[120px] items-center justify-center rounded-md border border-dashed border-white/10 bg-white/[0.02] px-4 text-center text-xs font-medium text-white/35">
      {label}
    </div>
  )
}

function Sparkline({ values, color = GOLD, className }: { values: number[]; color?: string; className?: string }) {
  const width = 130
  const height = 44
  const max = Math.max(1, ...values)
  const min = Math.min(0, ...values)
  const range = Math.max(1, max - min)
  const points = values.length
    ? values.map((value, index) => {
      const x = values.length === 1 ? width : (index / (values.length - 1)) * width
      const y = height - ((value - min) / range) * (height - 8) - 4
      return `${x},${y}`
    }).join(' ')
    : `0,${height} ${width},${height}`

  return (
    <svg className={cn('h-11 w-32', className)} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function MetricCard({
  label,
  value,
  unit,
  delta,
  icon: Icon,
  color,
  spark,
  danger,
}: {
  label: string
  value: string
  unit?: string
  delta: string
  icon: LucideIcon
  color: string
  spark: number[]
  danger?: boolean
}) {
  return (
    <GlassPanel className={cn('min-h-[88px] p-4', danger && 'border-red-500/30 bg-red-950/20 hover:border-red-400/70 hover:shadow-[0_0_54px_rgba(239,68,68,0.28)]')}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 font-mono text-[10px] font-black uppercase tracking-wider" style={{ color }}>
            <Icon className="h-3.5 w-3.5" />
            {label}
          </div>
          <div className="mt-3 font-mono text-2xl font-black text-white md:text-3xl">
            {value}
            {unit && <span className="ml-1 text-sm text-white/55">{unit}</span>}
          </div>
          <div className={cn('mt-2 text-[11px] font-bold', danger ? 'text-red-300' : 'text-emerald-300')}>
            {delta}
          </div>
        </div>
        <Sparkline values={spark} color={color} className="mt-4 hidden opacity-90 sm:block" />
      </div>
    </GlassPanel>
  )
}

function ProgressBar({ value, color = GOLD }: { value: number; color?: string }) {
  const safe = Math.max(0, Math.min(100, Math.round(value || 0)))
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-white/8">
      <div className="h-full rounded-full transition-all" style={{ width: `${safe}%`, backgroundColor: color, boxShadow: `0 0 14px ${color}66` }} />
    </div>
  )
}

function DonutChart({
  rows,
  total,
  center,
  sub,
  colors = DONUT_COLORS,
  size = 144,
}: {
  rows: CountRow[]
  total: number
  center: string
  sub: string
  colors?: string[]
  size?: number
}) {
  let cursor = 0
  const segments = rows
    .filter((row) => row.count > 0)
    .map((row, index) => {
      const percent = total > 0 ? (row.count / total) * 100 : 0
      const start = cursor
      cursor += percent * 3.6
      return `${colors[index % colors.length]} ${start}deg ${cursor}deg`
    })
  const background = segments.length ? `conic-gradient(${segments.join(', ')}, rgba(148,163,184,0.18) ${cursor}deg 360deg)` : 'rgba(148,163,184,0.12)'

  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <div className="absolute inset-0 rounded-full" style={{ background }} />
      <div className="absolute inset-[18px] rounded-full bg-[#06101D] shadow-[inset_0_0_18px_rgba(0,0,0,0.7)]" />
      <div className="relative text-center">
        <div className="font-mono text-2xl font-black text-white">{center}</div>
        <div className="text-[10px] font-bold uppercase text-white/50">{sub}</div>
      </div>
    </div>
  )
}

function LineChart({ points }: { points: TrendPoint[] }) {
  const width = 900
  const height = 230
  const padX = 34
  const padTop = 18
  const padBottom = 34
  const chartHeight = height - padTop - padBottom
  const keys: Array<{ key: keyof TrendPoint; color: string; label: string }> = [
    { key: 'encryption', color: BLUE, label: 'Encryption' },
    { key: 'decryption', color: GOLD, label: 'Decryption' },
    { key: 'keyUsage', color: PURPLE, label: 'Key Usage' },
    { key: 'other', color: SLATE, label: 'Other' },
  ]
  const max = Math.max(1, ...points.flatMap((point) => keys.map((series) => Number(point[series.key]) || 0)))
  const xFor = (index: number) => points.length <= 1 ? padX : padX + (index / (points.length - 1)) * (width - padX * 2)
  const yFor = (value: number) => padTop + chartHeight - (value / max) * chartHeight
  const pathFor = (key: keyof TrendPoint) => points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${xFor(index)} ${yFor(Number(point[key]) || 0)}`).join(' ')

  return (
    <div className="h-full min-h-[230px]">
      {points.length === 0 ? (
        <EmptyState label="No live crypto operations have been observed in the selected window yet." />
      ) : (
        <svg className="h-full w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
          {[0, 0.25, 0.5, 0.75, 1].map((tick) => (
            <line key={tick} x1={padX} x2={width - padX} y1={padTop + chartHeight * tick} y2={padTop + chartHeight * tick} stroke="rgba(148,163,184,0.12)" />
          ))}
          {points.map((point, index) => index % 4 === 0 || index === points.length - 1 ? (
            <text key={point.label + index} x={xFor(index)} y={height - 9} textAnchor="middle" fill="rgba(255,255,255,0.48)" fontSize="11">{point.label}</text>
          ) : null)}
          {keys.map((series) => (
            <path key={String(series.key)} d={pathFor(series.key)} fill="none" stroke={series.color} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
          ))}
        </svg>
      )}
    </div>
  )
}

function OperationDonut({ title, rows, icon: Icon }: { title: string; rows: CountRow[]; icon: LucideIcon }) {
  const total = rows.reduce((sum, row) => sum + row.count, 0)
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={Icon}>{title}</SectionTitle>
      {total === 0 ? (
        <EmptyState label="No operation telemetry is available yet." />
      ) : (
        <div className="grid gap-4 sm:grid-cols-[150px_minmax(0,1fr)] xl:grid-cols-1 2xl:grid-cols-[150px_minmax(0,1fr)]">
          <div className="flex justify-center">
            <DonutChart rows={rows} total={total} center={integerFmt(total)} sub="Total" />
          </div>
          <div className="space-y-2 self-center">
            {rows.map((row, index) => (
              <div key={row.label} className="flex items-center gap-3 text-xs">
                <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: DONUT_COLORS[index % DONUT_COLORS.length] }} />
                <span className="flex-1 text-white/60">{row.label}</span>
                <span className="font-mono text-white/80">{integerFmt(row.count)}</span>
                <span className="w-12 text-right font-mono text-white/40">({row.percent || 0}%)</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </GlassPanel>
  )
}

function CryptoHealthPanel({ health }: { health: CryptoHealth }) {
  const total = Math.max(0, health.total)
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={ShieldCheck}>Cryptographic Health</SectionTitle>
      {total === 0 ? (
        <EmptyState label="No cryptographic inventory, certificates, or exposure records are available yet." />
      ) : (
        <div className="grid gap-4 sm:grid-cols-[150px_minmax(0,1fr)] xl:grid-cols-1 2xl:grid-cols-[150px_minmax(0,1fr)]">
          <div className="flex justify-center">
            <DonutChart
              rows={health.rows}
              total={total}
              center={`${health.score}%`}
              sub="Healthy"
              colors={health.rows.map((row) => HEALTH_COLORS[row.label] || SLATE)}
            />
          </div>
          <div className="space-y-3 self-center">
            {health.rows.map((row) => (
              <div key={row.label} className="flex items-center gap-3 text-xs">
                <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: HEALTH_COLORS[row.label] || SLATE }} />
                <span className="flex-1 text-white/60">{row.label}</span>
                <span className="font-mono text-white">{integerFmt(row.count)}</span>
                <span className="w-12 text-right font-mono text-white/40">({row.percent}%)</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </GlassPanel>
  )
}

function ThreatPanel({ rows }: { rows: CountRow[] }) {
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={ShieldAlert} suffix={<a href="/dashboard/vulnerabilities" className="text-[10px] font-black text-sky-300 hover:text-sky-200">View All Threats <ChevronRight className="inline h-3 w-3" /></a>}>
        Threat Hunting
      </SectionTitle>
      <div className="mb-3 text-xs font-bold text-white/45">AI Risk Score: {integerFmt(rows.reduce((sum, row) => sum + row.count, 0))}</div>
      <div className="space-y-2">
        {rows.length === 0 ? (
          <EmptyState label="No threat categories have matching telemetry yet." />
        ) : rows.map((row, index) => (
          <div key={row.label} className="flex items-center gap-3 rounded-md border border-white/5 bg-white/[0.02] px-3 py-2 text-xs">
            <span className="flex h-5 w-5 items-center justify-center rounded-full bg-orange-500/12 text-orange-300">
              <AlertTriangle className="h-3 w-3" />
            </span>
            <span className="flex-1 text-white/70">{row.label}</span>
            <span className={cn('font-mono font-black', index === 0 ? 'text-red-300' : 'text-gold')}>{integerFmt(row.count)}</span>
          </div>
        ))}
      </div>
    </GlassPanel>
  )
}

function AlgorithmUsage({ rows }: { rows: AlgorithmRow[] }) {
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={Cpu} suffix={<a href="/dashboard/cbom" className="text-[10px] font-black text-sky-300 hover:text-sky-200">View All Algorithms <ChevronRight className="inline h-3 w-3" /></a>}>
        Algorithm Usage <span className="text-white/35">(Top 10)</span>
      </SectionTitle>
      {rows.length === 0 ? (
        <EmptyState label="No algorithm usage has been discovered yet." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[460px] text-left">
            <thead>
              <tr className="border-b border-white/8">
                {['Algorithm', 'Usage', 'Trend'].map((header) => (
                  <th key={header} className="px-2 py-2 font-mono text-[9px] font-black uppercase tracking-wider text-white/45">{header}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {rows.map((row) => (
                <tr key={row.algorithm} className="text-xs">
                  <td className={cn('px-2 py-2 font-mono font-bold', /ml-kem|dilithium|ml-dsa/i.test(row.algorithm) ? 'text-emerald-300' : 'text-white/70')}>{row.algorithm}</td>
                  <td className="px-2 py-2 font-mono text-white/65">{integerFmt(row.usage)} <span className="text-white/35">({row.percent}%)</span></td>
                  <td className="px-2 py-2">
                    <Sparkline values={row.trend} color={/ml-kem|dilithium|ml-dsa/i.test(row.algorithm) ? GREEN : CYAN} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </GlassPanel>
  )
}

function LiveAlerts({ rows }: { rows: AlertRow[] }) {
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={AlertTriangle} suffix={<a href="/dashboard/drift" className="text-[10px] font-black text-sky-300 hover:text-sky-200">View All Alerts <ChevronRight className="inline h-3 w-3" /></a>}>
        Live Alerts
      </SectionTitle>
      <div className="space-y-2">
        {rows.length === 0 ? (
          <EmptyState label="No live alerts have been emitted from scans or runtime telemetry yet." />
        ) : rows.map((row) => (
          <div key={row.id} className="flex items-center gap-3 rounded-md border border-white/5 bg-white/[0.02] px-3 py-2 text-xs">
            <AlertTriangle className="h-4 w-4 shrink-0" style={{ color: severityColor(row.severity) }} />
            <div className="min-w-0 flex-1">
              <div className="truncate font-bold text-white/80">{row.title}</div>
              <div className="truncate text-[10px] text-white/40">{row.resource}</div>
            </div>
            <div className="text-right">
              <div className="font-mono text-[10px] text-white/45">{timeOnly(row.timestamp)}</div>
              <span className={cn('mt-1 inline-flex rounded border px-1.5 py-0.5 font-mono text-[9px] font-black uppercase', severityBadge(row.severity))}>{row.severity}</span>
            </div>
          </div>
        ))}
      </div>
    </GlassPanel>
  )
}

function PqcVerification({ rows }: { rows: VerificationRow[] }) {
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={Lock}>PQC Verification</SectionTitle>
      <div className="space-y-2">
        {rows.length === 0 ? (
          <EmptyState label="No PQC verification signals have been recorded yet." />
        ) : rows.map((row) => (
          <div key={row.label} className="grid grid-cols-[20px_minmax(0,1fr)_auto_auto] items-center gap-3 border-b border-white/5 py-2 text-xs last:border-b-0">
            <Shield className="h-4 w-4 text-white/45" />
            <span className="truncate text-white/70">{row.label}</span>
            <span className={cn('font-mono font-black', statusClass(row.status))}>{row.status}</span>
            <span className="font-mono text-white/55">{integerFmt(row.count)} {row.detail}</span>
          </div>
        ))}
      </div>
    </GlassPanel>
  )
}

function MigrationValidationPanel({ validation }: { validation: MigrationValidation }) {
  const rows = [
    { label: 'Migrated Assets', value: validation.migratedAssets, color: GREEN },
    { label: 'In Progress', value: validation.inProgress, color: BLUE },
    { label: 'Pending', value: validation.pending, color: GOLD },
    { label: 'Failed / Blocked', value: validation.failedBlocked, color: RED },
  ]
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={RefreshCw} suffix={<a href="/dashboard/migration-timeline" className="text-[10px] font-black text-sky-300 hover:text-sky-200">View Migration Timeline <ChevronRight className="inline h-3 w-3" /></a>}>
        Migration Validation
      </SectionTitle>
      <div className="grid gap-4 sm:grid-cols-[130px_minmax(0,1fr)]">
        <div className="flex justify-center">
          <DonutChart rows={rows.map((row) => ({ label: row.label, count: row.value }))} total={Math.max(1, rows.reduce((sum, row) => sum + row.value, 0))} center={`${validation.progress}%`} sub="Progress" colors={rows.map((row) => row.color)} size={126} />
        </div>
        <div className="space-y-3 self-center">
          {rows.map((row) => (
            <div key={row.label} className="flex items-center gap-3 text-xs">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: row.color }} />
              <span className="flex-1 text-white/60">{row.label}</span>
              <span className="font-mono font-black" style={{ color: row.color }}>{integerFmt(row.value)}</span>
            </div>
          ))}
        </div>
      </div>
    </GlassPanel>
  )
}

function KeyLifecyclePanel({ lifecycle }: { lifecycle: KeyLifecycle }) {
  const rows = [
    { label: 'Keys Generated (7D)', value: lifecycle.generated7d, delta: lifecycle.generatedDelta, color: GREEN },
    { label: 'Keys Rotated (7D)', value: lifecycle.rotated7d, delta: 0, color: BLUE },
    { label: 'Keys Expiring (30D)', value: lifecycle.expiring30d, delta: 0, color: RED },
    { label: 'Compromised Keys', value: lifecycle.compromisedKeys, delta: 0, color: CYAN },
  ]
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={KeyRound} suffix={<a href="/dashboard/qkms/inventory" className="text-[10px] font-black text-sky-300 hover:text-sky-200">View Key Intelligence <ChevronRight className="inline h-3 w-3" /></a>}>
        Key Lifecycle Intelligence
      </SectionTitle>
      <div className="space-y-3">
        {rows.map((row) => (
          <div key={row.label} className="grid grid-cols-[minmax(0,1fr)_auto_70px] items-center gap-3 text-xs">
            <span className="truncate text-white/65">{row.label}</span>
            <span className="font-mono font-black text-white">{integerFmt(row.value)}</span>
            <span className={cn('text-right font-mono text-[10px]', row.delta >= 0 ? 'text-emerald-300' : 'text-red-300')}>{row.delta ? `${row.delta > 0 ? '+' : ''}${row.delta}%` : '--'}</span>
          </div>
        ))}
        <div className="border-t border-white/5 pt-3">
          <div className="mb-2 flex items-center justify-between text-xs">
            <span className="text-white/60">Avg Entropy Quality</span>
            <span className="font-mono font-black text-white">{numberFmt(lifecycle.entropyQuality)}%</span>
          </div>
          <ProgressBar value={lifecycle.entropyQuality} color={lifecycle.entropyQuality >= 90 ? GREEN : lifecycle.entropyQuality >= 60 ? GOLD : RED} />
        </div>
      </div>
    </GlassPanel>
  )
}

function QuantumTelemetry({ rows }: { rows: QuantumTelemetryRow[] }) {
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={Radio} suffix={<a href="/dashboard/quantum-risk-scoring" className="text-[10px] font-black text-sky-300 hover:text-sky-200">View All <ChevronRight className="inline h-3 w-3" /></a>}>
        Quantum Telemetry
      </SectionTitle>
      <div className="space-y-3">
        {rows.length === 0 ? (
          <EmptyState label="No quantum telemetry has been calculated yet." />
        ) : rows.map((row) => {
          const tone = row.percent >= 70 ? RED : row.percent >= 40 ? GOLD : BLUE
          return (
            <div key={row.label} className="grid grid-cols-[18px_minmax(0,1fr)_auto] items-center gap-3 text-xs">
              <Radio className="h-3.5 w-3.5" style={{ color: tone }} />
              <span className="truncate text-white/60">{row.label}</span>
              <span className="rounded border px-2 py-0.5 font-mono text-[10px] font-black" style={{ borderColor: `${tone}55`, color: tone, backgroundColor: `${tone}18` }}>{row.value}</span>
              <div className="col-span-3">
                <ProgressBar value={row.percent} color={tone} />
              </div>
            </div>
          )
        })}
      </div>
    </GlassPanel>
  )
}

function RuntimeCoveragePanel({ coverage }: { coverage: RuntimeCoverage }) {
  const agentHealth = coverage.totalAgents ? Math.round((coverage.activeAgents / coverage.totalAgents) * 100) : 0
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={Radio}>Runtime Coverage</SectionTitle>
      <div className="grid grid-cols-3 gap-2 text-center">
        {[
          ['24H Events', coverage.runtimeEvents24h],
          ['Assets', coverage.coveredAssets],
          ['Total Events', coverage.totalRuntimeEvents],
        ].map(([label, value]) => (
          <div key={String(label)} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
            <div className="font-mono text-xl font-black text-white">{integerFmt(Number(value))}</div>
            <div className="mt-1 text-[9px] font-black uppercase tracking-wider text-white/40">{label}</div>
          </div>
        ))}
      </div>
      <div className="mt-4">
        <div className="mb-2 flex items-center justify-between text-xs">
          <span className="text-white/60">Agent Coverage</span>
          <span className="font-mono font-black text-white">{coverage.activeAgents}/{coverage.totalAgents}</span>
        </div>
        <ProgressBar value={agentHealth} color={agentHealth >= 80 ? GREEN : agentHealth >= 40 ? GOLD : RED} />
      </div>
      <div className="mt-4 space-y-2">
        {coverage.sourceCoverage.length === 0 ? (
          <div className="rounded border border-dashed border-white/10 px-3 py-2 text-center text-[10px] text-white/35">Waiting for runtime event sources.</div>
        ) : coverage.sourceCoverage.map((row) => (
          <div key={row.label} className="grid grid-cols-[minmax(0,1fr)_56px] items-center gap-3 text-xs">
            <span className="truncate text-white/60">{row.label}</span>
            <span className="text-right font-mono text-white/70">{integerFmt(row.count)}</span>
            <div className="col-span-2"><ProgressBar value={row.percent || 0} color={CYAN} /></div>
          </div>
        ))}
      </div>
    </GlassPanel>
  )
}

function EnterpriseSignalsPanel({ signals, risks }: { signals: EnterpriseSignals; risks: TopRisk[] }) {
  const rows = [
    { label: 'Shadow Crypto', value: signals.shadowCrypto, color: PURPLE },
    { label: 'Downgrades', value: signals.downgradeAttempts, color: RED },
    { label: 'HNDL Exposure', value: signals.hndlExposure, color: ORANGE },
    { label: 'Weak Certificates', value: signals.weakCertificates, color: GOLD },
    { label: 'Vendor Crypto', value: signals.vendorPackageCrypto, color: CYAN },
  ]
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={ShieldAlert}>Runtime Risk Signals</SectionTitle>
      <div className="grid grid-cols-2 gap-2">
        {rows.map((row) => (
          <div key={row.label} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
            <div className="font-mono text-xl font-black" style={{ color: row.color }}>{integerFmt(row.value)}</div>
            <div className="mt-1 text-[9px] font-black uppercase tracking-wider text-white/42">{row.label}</div>
          </div>
        ))}
      </div>
      <div className="mt-3 space-y-2">
        {risks.length === 0 ? (
          <div className="rounded border border-dashed border-white/10 px-3 py-2 text-center text-[10px] text-white/35">No runtime risk events have been observed.</div>
        ) : risks.slice(0, 3).map((risk) => (
          <div key={risk.id} className="flex items-center gap-3 rounded border border-white/5 bg-black/15 px-3 py-2 text-xs">
            <span className={cn('h-2.5 w-2.5 rounded-full', risk.severity === 'critical' ? 'bg-red-400' : risk.severity === 'high' ? 'bg-orange-400' : 'bg-gold')} />
            <div className="min-w-0 flex-1">
              <div className="truncate font-bold text-white/75">{risk.label}</div>
              <div className="text-[10px] text-white/40">{risk.category}</div>
            </div>
            <span className="font-mono font-black text-white">{risk.riskScore}</span>
          </div>
        ))}
      </div>
    </GlassPanel>
  )
}

function AgentHealthPanel({ coverage }: { coverage: RuntimeCoverage }) {
  const hasAgents = coverage.totalAgents > 0
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={ShieldCheck}>Agent Health</SectionTitle>
      <div className="grid grid-cols-3 gap-2 text-center">
        {[
          ['Active', coverage.activeAgents, GREEN],
          ['Stale', coverage.staleAgents, GOLD],
          ['Total', coverage.totalAgents, BLUE],
        ].map(([label, value, color]) => (
          <div key={String(label)} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
            <div className="font-mono text-xl font-black" style={{ color: String(color) }}>{integerFmt(Number(value))}</div>
            <div className="mt-1 text-[9px] font-black uppercase tracking-wider text-white/42">{label}</div>
          </div>
        ))}
      </div>
      <div className="mt-4 rounded-md border border-white/8 bg-black/15 p-3 text-xs text-white/55">
        {hasAgents
          ? coverage.staleAgents > 0
            ? 'Some collectors are stale. Runtime intelligence remains active for healthy agents.'
            : 'All registered collectors are reporting within the runtime window.'
          : 'No runtime collectors are enrolled for this tenant yet.'}
      </div>
    </GlassPanel>
  )
}

function PipelineStatusPanel({ pipeline, source }: { pipeline: EventPipeline; source: string }) {
  const active = pipeline.status === 'active'
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={Database}>Event Pipeline Status</SectionTitle>
      <div className="flex items-center justify-between rounded-md border border-white/8 bg-white/[0.025] p-3">
        <div>
          <div className={cn('font-mono text-sm font-black uppercase', active ? 'text-emerald-300' : 'text-gold')}>{pipeline.status.replace(/_/g, ' ')}</div>
          <div className="mt-1 text-[10px] text-white/40">{pipeline.table}</div>
        </div>
        <span className={cn('h-3 w-3 rounded-full', active ? 'bg-emerald-400 shadow-[0_0_16px_rgba(34,197,94,0.9)]' : 'bg-gold shadow-[0_0_16px_rgba(251,191,36,0.7)]')} />
      </div>
      <div className="mt-4 space-y-3 text-xs">
        <div className="flex justify-between gap-3">
          <span className="text-white/55">Latest Event</span>
          <span className="font-mono text-white/75">{timeOnly(pipeline.latestRuntimeEventAt)}</span>
        </div>
        <div className="flex justify-between gap-3">
          <span className="text-white/55">Open Scanner Alerts</span>
          <span className="font-mono text-white/75">{integerFmt(pipeline.openScannerAlerts)}</span>
        </div>
        <div className="flex justify-between gap-3">
          <span className="text-white/55">Telemetry Source</span>
          <span className="font-mono text-white/75">{source.replace(/_/g, ' ')}</span>
        </div>
      </div>
    </GlassPanel>
  )
}

function HandshakeTable({ rows }: { rows: HandshakeRow[] }) {
  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={Activity} suffix={<a href="/dashboard/tls-telemetry" className="text-[10px] font-black text-sky-300 hover:text-sky-200">View All Handshakes <ChevronRight className="inline h-3 w-3" /></a>}>
        Live TLS Handshake Analysis
      </SectionTitle>
      {rows.length === 0 ? (
        <EmptyState label="No TLS handshake telemetry has been captured yet." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[880px] text-left">
            <thead>
              <tr className="border-b border-white/8">
                {['Time', 'Source', 'Destination', 'TLS Version', 'Cipher Suite', 'Key Exchange', 'PQC', 'Status'].map((header) => (
                  <th key={header} className="px-3 py-2 font-mono text-[9px] font-black uppercase tracking-wider text-white/45">{header}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {rows.map((row) => (
                <tr key={row.id} className="text-xs transition hover:bg-gold/[0.035]">
                  <td className="px-3 py-2 font-mono text-white/55">{timeOnly(row.time)}</td>
                  <td className="px-3 py-2 text-white/70">{row.source}</td>
                  <td className="px-3 py-2 text-white/55">{row.destination}</td>
                  <td className="px-3 py-2 font-mono text-white/65">{row.tlsVersion}</td>
                  <td className="px-3 py-2 font-mono text-white/55">{row.cipherSuite}</td>
                  <td className="px-3 py-2 font-mono text-white/65">{row.keyExchange}</td>
                  <td className={cn('px-3 py-2 font-mono font-black', row.pqc ? 'text-emerald-300' : 'text-red-300')}>{row.pqc ? 'Yes' : 'No'}</td>
                  <td className={cn('px-3 py-2 font-mono font-black', row.status.toLowerCase().includes('success') ? 'text-emerald-300' : 'text-gold')}>{row.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </GlassPanel>
  )
}

function DependencyGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const positioned = useMemo(() => {
    if (nodes.length === 0) return []
    const centerIndex = Math.min(1, nodes.length - 1)
    return nodes.map((node, index) => {
      if (index === centerIndex) return { ...node, x: 50, y: 48 }
      const angle = ((index / Math.max(1, nodes.length - 1)) * Math.PI * 2) - Math.PI / 2
      return {
        ...node,
        x: 50 + Math.cos(angle) * 32,
        y: 48 + Math.sin(angle) * 30,
      }
    })
  }, [nodes])
  const nodeById = new Map<string, (typeof positioned)[number]>(positioned.map((node) => [node.id, node] as const))

  return (
    <GlassPanel className="p-4">
      <SectionTitle icon={Network} suffix={<a href="/dashboard/quantum-readiness/exposure-graph" className="text-[10px] font-black text-sky-300 hover:text-sky-200">View Full Graph <ChevronRight className="inline h-3 w-3" /></a>}>
        Crypto Dependency Map
      </SectionTitle>
      {nodes.length === 0 ? (
        <EmptyState label="No asset relationships are available to render a crypto dependency map yet." />
      ) : (
        <div className="relative h-[250px] rounded-lg border border-white/8 bg-[#050B14]/70">
          <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
            {edges.map((edge) => {
              const source = nodeById.get(edge.source)
              const target = nodeById.get(edge.target)
              if (!source || !target) return null
              return (
                <line key={edge.id} x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke="rgba(59,130,246,0.7)" strokeWidth="0.5" />
              )
            })}
          </svg>
          {positioned.map((node, index) => (
            <div
              key={node.id}
              className={cn(
                'absolute -translate-x-1/2 -translate-y-1/2 rounded-md border px-3 py-2 text-center font-mono text-[10px] font-bold shadow-[0_0_18px_rgba(59,130,246,0.24)]',
                index === 1 ? 'border-blue-400/70 bg-blue-500/25 text-white' : 'border-white/15 bg-white/[0.04] text-white/70'
              )}
              style={{ left: `${node.x}%`, top: `${node.y}%` }}
            >
              {node.label}
              <div className="mt-1 text-[8px] uppercase text-white/35">{node.type}</div>
            </div>
          ))}
          {edges.length === 0 && (
            <div className="absolute bottom-3 left-3 right-3 rounded border border-dashed border-white/10 px-3 py-2 text-center text-[10px] text-white/35">
              Assets found, but no relationship edges are recorded yet.
            </div>
          )}
        </div>
      )}
    </GlassPanel>
  )
}

function exportJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `${filename}-${new Date().toISOString().slice(0, 10)}.json`
  anchor.click()
  URL.revokeObjectURL(url)
}

export default function RuntimeCryptoIntelPage() {
  const { snapshot, state, error, sseConnected, refresh } = useRuntimeCryptoSnapshot()
  const metrics = snapshot.metrics
  const trend = snapshot.operationsTrend
  const totalTrend = trend.map((point) => point.encryption + point.decryption + point.keyUsage + point.other)

  const metricCards: Array<{ label: string; value: string; unit?: string; delta: string; icon: LucideIcon; color: string; spark: number[]; danger?: boolean }> = [
    { label: 'Crypto Operations / Sec', value: numberFmt(metrics.cryptoOpsPerSec), unit: '/s', delta: formatDelta(metrics.cryptoOpsDelta), icon: Activity, color: CYAN, spark: totalTrend },
    { label: 'Encryption Ops / Sec', value: numberFmt(metrics.encryptionOpsPerSec), unit: '/s', delta: formatDelta(metrics.encryptionDelta), icon: Lock, color: BLUE, spark: trend.map((point) => point.encryption) },
    { label: 'Decryption Ops / Sec', value: numberFmt(metrics.decryptionOpsPerSec), unit: '/s', delta: formatDelta(metrics.decryptionDelta), icon: Database, color: PURPLE, spark: trend.map((point) => point.decryption) },
    { label: 'Key Usage Events / Sec', value: numberFmt(metrics.keyUsageEventsPerSec), unit: '/s', delta: formatDelta(metrics.keyUsageDelta), icon: KeyRound, color: PURPLE, spark: trend.map((point) => point.keyUsage) },
    { label: 'PQC Handshakes / Sec', value: numberFmt(metrics.pqcHandshakesPerSec), unit: '/s', delta: formatDelta(metrics.pqcHandshakeDelta), icon: ShieldCheck, color: GREEN, spark: trend.map((point) => point.keyUsage) },
    { label: 'Quantum Exposure Score', value: integerFmt(metrics.quantumExposureScore), unit: '/100', delta: metrics.quantumExposureScore >= 70 ? 'High risk' : metrics.quantumExposureScore >= 40 ? 'Moderate risk' : 'Low risk', icon: ShieldAlert, color: RED, spark: totalTrend, danger: metrics.quantumExposureScore >= 70 },
  ]

  return (
    <main className="min-h-screen space-y-3 bg-[#02070E] p-3 text-white md:p-4">
      <header className="flex flex-col gap-4 border-b border-white/6 pb-3 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex items-start gap-4">
          <button type="button" className="mt-1 flex h-9 w-9 items-center justify-center rounded-md border border-white/10 bg-black/20 text-white/65 hover:border-gold/50 hover:text-gold" aria-label="Open dashboard navigation">
            <Menu className="h-5 w-5" />
          </button>
          <div>
            <h1 className="font-mono text-2xl font-black uppercase tracking-tight text-white md:text-3xl">
              Runtime Cryptographic Intelligence
            </h1>
            <p className="mt-1 text-sm font-medium text-white/55">
              Deep cryptographic observability with real-time quantum telemetry and AI-driven threat detection
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <select className="h-10 min-w-[160px] rounded-md border border-white/10 bg-black/20 px-3 text-xs font-bold text-white/70 outline-none focus:border-gold/50">
            <option>All Environments</option>
            {snapshot.filters.environments.map((environment) => (
              <option key={environment}>{environment}</option>
            ))}
          </select>
          <button type="button" className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 bg-black/20 px-4 text-xs font-bold text-white/70 hover:border-gold/50 hover:text-gold">
            <CalendarDays className="h-4 w-4" />
            {shortDateRange()}
          </button>
          <button
            type="button"
            onClick={refresh}
            className="inline-flex h-10 items-center gap-2 rounded-md border border-emerald-500/25 bg-emerald-500/8 px-3 text-xs font-black text-emerald-300 hover:border-emerald-400/70"
          >
            <span className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_12px_rgba(34,197,94,0.9)]' : 'bg-slate-500')} />
            {sseConnected ? 'LIVE' : state === 'loading' ? 'SYNC' : 'REFRESH'}
          </button>
          <button type="button" className="relative flex h-10 w-10 items-center justify-center rounded-md border border-white/10 bg-black/20 text-white/65 hover:border-gold/50 hover:text-gold" aria-label="Notifications">
            <Bell className="h-4 w-4" />
            {snapshot.liveAlerts.length > 0 && <span className="absolute -right-1 -top-1 rounded-full bg-red-500 px-1.5 py-0.5 font-mono text-[9px] font-black text-white">{snapshot.liveAlerts.length}</span>}
          </button>
          <button type="button" className="flex h-10 w-10 items-center justify-center rounded-md border border-white/10 bg-black/20 text-white/65 hover:border-gold/50 hover:text-gold" aria-label="Settings">
            <Settings className="h-4 w-4" />
          </button>
          <div className="flex h-10 w-10 items-center justify-center rounded-full border border-white/10 bg-white/[0.03] text-white/55">
            <UserRound className="h-5 w-5" />
          </div>
        </div>
      </header>

      {error && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          Telemetry warning: {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-6">
        {metricCards.map((metric) => (
          <Fragment key={metric.label}>
            <MetricCard
              label={metric.label}
              value={metric.value}
              unit={metric.unit}
              delta={metric.delta}
              icon={metric.icon}
              color={metric.color}
              spark={metric.spark}
              danger={metric.danger}
            />
          </Fragment>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1.72fr)_minmax(300px,0.8fr)_minmax(300px,0.8fr)]">
        <GlassPanel className="min-h-[300px] p-4">
          <SectionTitle
            icon={Activity}
            suffix={(
              <div className="flex items-center gap-3">
                <select className="h-8 rounded-md border border-white/10 bg-black/20 px-3 text-[10px] font-bold text-white/70">
                  <option>Last 24 Hours</option>
                </select>
                <button type="button" className="flex h-8 w-8 items-center justify-center rounded border border-white/10 bg-black/20 text-white/60 hover:border-gold/40 hover:text-gold" aria-label="Expand operations chart">
                  <Maximize2 className="h-3.5 w-3.5" />
                </button>
              </div>
            )}
          >
            Live Crypto Operations Over Time
          </SectionTitle>
          <div className="mb-2 flex flex-wrap gap-4 pl-2 text-[10px] font-bold text-white/50">
            {[
              ['Encryption', BLUE],
              ['Decryption', GOLD],
              ['Key Usage', PURPLE],
              ['Other', SLATE],
            ].map(([label, color]) => (
              <span key={label} className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: color }} />
                {label}
              </span>
            ))}
          </div>
          <LineChart points={snapshot.operationsTrend} />
        </GlassPanel>

        <CryptoHealthPanel health={snapshot.cryptoHealth} />
        <ThreatPanel rows={snapshot.threatHunting} />
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-4">
        <RuntimeCoveragePanel coverage={snapshot.runtimeCoverage} />
        <EnterpriseSignalsPanel signals={snapshot.enterpriseSignals} risks={snapshot.topRisks} />
        <AgentHealthPanel coverage={snapshot.runtimeCoverage} />
        <PipelineStatusPanel pipeline={snapshot.eventPipeline} source={snapshot.runtimeCoverage.source} />
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(280px,0.9fr)_minmax(360px,0.95fr)_minmax(280px,0.85fr)_minmax(300px,0.85fr)]">
        <OperationDonut title="Crypto Operations By Type" rows={snapshot.operationsByType} icon={Zap} />
        <AlgorithmUsage rows={snapshot.algorithmUsage} />
        <OperationDonut title="Protocol Usage" rows={snapshot.protocolUsage} icon={Network} />
        <LiveAlerts rows={snapshot.liveAlerts} />
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-4">
        <PqcVerification rows={snapshot.pqcVerification} />
        <MigrationValidationPanel validation={snapshot.migrationValidation} />
        <KeyLifecyclePanel lifecycle={snapshot.keyLifecycle} />
        <QuantumTelemetry rows={snapshot.quantumTelemetry} />
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1.18fr)_minmax(430px,0.82fr)]">
        <HandshakeTable rows={snapshot.tlsHandshakes} />
        <DependencyGraph nodes={snapshot.dependencyGraph.nodes} edges={snapshot.dependencyGraph.edges} />
      </div>

      <footer className="flex flex-wrap items-center justify-between gap-3 pb-1 text-[10px] font-bold uppercase tracking-wider text-white/35">
        <span>Last API snapshot: {timeOnly(snapshot.generatedAt)} UTC / {dateOnly(snapshot.generatedAt)}</span>
        <div className="flex items-center gap-2">
          <HeaderButton icon={Download} onClick={() => exportJson('runtime-crypto-intel', snapshot)}>Export Snapshot</HeaderButton>
          <HeaderButton icon={Filter}>Telemetry Filters</HeaderButton>
          <HeaderButton icon={Eye} primary>Audit View</HeaderButton>
        </div>
      </footer>
    </main>
  )
}
