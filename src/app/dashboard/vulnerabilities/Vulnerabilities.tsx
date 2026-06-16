import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  BarChart3,
  CalendarDays,
  ChevronLeft,
  ChevronRight,
  Download,
  Eye,
  FileText,
  Filter,
  MoreVertical,
  Plus,
  RefreshCw,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Target,
  XCircle,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'

type LoadState = 'loading' | 'success' | 'error'
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

type VulnerabilityEvidence = {
  id: string
  label: string
  description?: string
  algorithm?: string
  source?: string
  severity?: Severity
  detectedAt?: string | null
}

type VulnerabilityRow = {
  id: string
  sourceId?: string
  assetId?: string | null
  source?: string
  sourceIds?: string[]
  scanTarget?: string | null
  canonicalFingerprint?: string
  rootCause?: string
  title: string
  description: string
  asset: string
  assetType: string
  environment: string
  severity: Severity
  exposureLevel: string
  type: string
  detectedAt: string | null
  status: string
  algorithm: string
  remediation: string
  remediationHref?: string
  inspectHref?: string
  evidence?: VulnerabilityEvidence[]
  evidenceCount?: number
}

type VulnerabilityMetrics = {
  criticalExposure: number
  criticalExposureDelta: number
  legacyAlgorithms: number
  legacyAlgorithmsDelta: number
  remediated: number
  remediatedDelta: number
  totalVulnerabilities: number
  current7d: number
}

type BreakdownRow = {
  severity?: Severity
  label?: string
  count: number
  percent: number
}

type TrendPoint = {
  label: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

type TopAsset = {
  asset: string
  severity: Severity
  count: number
}

type ScanStatus = {
  latestScanAt: string | null
  nextScanAt: string | null
  activeScans: number
  latestStatus: string
  telemetryEvents: number
}

type VulnerabilitySnapshot = {
  generatedAt: string | null
  metrics: VulnerabilityMetrics
  filters: {
    environments: string[]
    assetTypes: string[]
    vulnerabilityTypes: string[]
  }
  vulnerabilities: VulnerabilityRow[]
  severityBreakdown: BreakdownRow[]
  assetTypeBreakdown: BreakdownRow[]
  trend: TrendPoint[]
  topAssets: TopAsset[]
  scanStatus: ScanStatus
}

type ScanActionState = {
  status: 'idle' | 'running' | 'success' | 'error'
  progress: number
  message: string
}

const PAGE_SIZE = 5

const EMPTY_SNAPSHOT: VulnerabilitySnapshot = {
  generatedAt: null,
  metrics: {
    criticalExposure: 0,
    criticalExposureDelta: 0,
    legacyAlgorithms: 0,
    legacyAlgorithmsDelta: 0,
    remediated: 0,
    remediatedDelta: 0,
    totalVulnerabilities: 0,
    current7d: 0,
  },
  filters: { environments: [], assetTypes: [], vulnerabilityTypes: [] },
  vulnerabilities: [],
  severityBreakdown: [
    { severity: 'critical', count: 0, percent: 0 },
    { severity: 'high', count: 0, percent: 0 },
    { severity: 'medium', count: 0, percent: 0 },
    { severity: 'low', count: 0, percent: 0 },
    { severity: 'info', count: 0, percent: 0 },
  ],
  assetTypeBreakdown: [],
  trend: [],
  topAssets: [],
  scanStatus: {
    latestScanAt: null,
    nextScanAt: null,
    activeScans: 0,
    latestStatus: 'not_started',
    telemetryEvents: 0,
  },
}

const IDLE_SCAN_ACTION: ScanActionState = {
  status: 'idle',
  progress: 0,
  message: '',
}

const RED = '#EF4444'
const ORANGE = '#F97316'
const GOLD = '#FBBF24'
const GREEN = '#22C55E'
const BLUE = '#3B82F6'
const CYAN = '#06B6D4'
const PURPLE = '#A855F7'

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: RED,
  high: ORANGE,
  medium: GOLD,
  low: GREEN,
  info: BLUE,
}

const ASSET_COLORS = [BLUE, CYAN, PURPLE, ORANGE, '#64748B', GREEN]

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-gold/18 bg-[#07101D]/72 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(251,191,36,0.035),0_0_34px_rgba(0,0,0,0.32)] transition-all duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/80 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-24px_60px_rgba(251,191,36,0.12),0_14px_42px_rgba(0,0,0,0.45),0_0_54px_rgba(251,191,36,0.32)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/70 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-52 after:w-52 after:rounded-full after:bg-gold/10 after:blur-3xl after:transition-all group-hover:after:bg-gold/20'

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(value || 0)))
}

function formatDelta(value: number) {
  if (value > 0) return `+ ${numberFmt(value)} vs last 7 days`
  if (value < 0) return `${numberFmt(value)} vs last 7 days`
  return '0 vs last 7 days'
}

function relativeTime(value: string | null) {
  if (!value) return 'Not scheduled'
  const ms = new Date(value).getTime()
  if (!Number.isFinite(ms)) return 'Not scheduled'
  return new Date(value).toLocaleString('en-US', { month: 'short', day: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function dateTime(value: string | null) {
  if (!value) return { date: '--', time: '--' }
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return { date: '--', time: '--' }
  return {
    date: date.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }),
    time: date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
  }
}

function severityClass(severity: Severity) {
  if (severity === 'critical') return 'border-red-500/35 bg-red-500/10 text-red-300'
  if (severity === 'high') return 'border-orange-500/35 bg-orange-500/10 text-orange-300'
  if (severity === 'medium') return 'border-gold/35 bg-gold/10 text-gold'
  if (severity === 'low') return 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300'
  return 'border-sky-500/35 bg-sky-500/10 text-sky-300'
}

function severityRank(severity: string) {
  if (severity === 'critical') return 5
  if (severity === 'high') return 4
  if (severity === 'medium') return 3
  if (severity === 'low') return 2
  return 1
}

function remediationRouteFor(row: VulnerabilityRow) {
  const text = [
    row.title,
    row.description,
    row.algorithm,
    row.type,
    row.source,
    row.remediation,
  ].map((value) => String(value || '').toLowerCase()).join(' ')

  if (/hndl|harvest|runtime|shadow|downgrade/.test(text)) return '/dashboard/live-migration'
  if (/certificate|cert|pki|x509|pinning|issuer|subject/.test(text)) return '/dashboard/certificate-telemetry'
  if (/tls|ssl|cipher|protocol|handshake/.test(text)) return '/dashboard/tls-orchestrator'
  if (/library|dependency|component|package|cve|repo|github|source/.test(text)) return '/dashboard/migration-planner'
  if (/random|rng|entropy/.test(text)) return '/dashboard/qrng'
  if (/api|gateway/.test(text)) return '/dashboard/api-encryption'
  if (/cloud|kms|bucket|storage/.test(text)) return '/dashboard/cloud'
  return '/dashboard/pqc-orchestration'
}

function remediationHref(row: VulnerabilityRow) {
  if (row.remediationHref) return row.remediationHref
  const params = new URLSearchParams({
    source: 'vulnerabilities',
    action: 'remediate',
    findingId: row.sourceId || row.id,
    asset: row.asset,
    severity: row.severity,
  })
  if (row.assetId) params.set('assetId', row.assetId)
  if (row.algorithm) params.set('algorithm', row.algorithm)
  if (row.type) params.set('type', row.type)
  if (row.source) params.set('findingSource', row.source)
  return `${remediationRouteFor(row)}?${params.toString()}`
}

function evidenceHref(row: VulnerabilityRow) {
  const params = new URLSearchParams({
    source: 'vulnerabilities',
    findingId: row.sourceId || row.id,
    asset: row.asset,
  })
  if (row.assetId) params.set('assetId', row.assetId)
  if (row.algorithm) params.set('algorithm', row.algorithm)
  return `/dashboard/cbom?${params.toString()}`
}

function scanTargetForRow(row: VulnerabilityRow) {
  const candidates = [row.scanTarget, row.asset]
  for (const value of candidates) {
    const target = String(value || '').trim()
    if (!target || /^unassigned asset$/i.test(target)) continue
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) return target
    if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/i.test(target)) return target
    if (/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\/.*)?$/i.test(target)) return target
  }
  return null
}

function useVulnerabilitySnapshot() {
  const { session, user } = useAuth()
  const token = session?.access_token
  const [snapshot, setSnapshot] = useState<VulnerabilitySnapshot>(EMPTY_SNAPSHOT)
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const [scanAction, setScanAction] = useState<ScanActionState>(IDLE_SCAN_ACTION)
  const streamsRef = useRef<EventSource[]>([])
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const scanAbortRef = useRef<AbortController | null>(null)

  const closeStreams = useCallback(() => {
    for (const stream of streamsRef.current) stream.close()
    streamsRef.current = []
    setSseConnected(false)
  }, [])

  const fetchSnapshot = useCallback(async () => {
    if (!token) return
    setState((current) => current === 'success' ? current : 'loading')
    try {
      const response = await fetch('/api/v1/dashboard/vulnerabilities', {
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
      const message = err instanceof Error ? err.message : 'Unable to load vulnerability telemetry'
      console.error('Vulnerability telemetry failed:', err)
      setError(message)
      setState('error')
    }
  }, [token])

  const runNewScan = useCallback(async (targets: string[]) => {
    if (!token) {
      setScanAction({
        status: 'error',
        progress: 0,
        message: 'Sign in again to run a scan.',
      })
      return
    }

    const uniqueTargets = Array.from(new Set(targets.map((target) => target.trim()).filter(Boolean))).slice(0, 25)
    if (uniqueTargets.length === 0) {
      setScanAction({
        status: 'error',
        progress: 0,
        message: 'No scannable asset target found on this vulnerability page.',
      })
      return
    }

    scanAbortRef.current?.abort()
    const controller = new AbortController()
    scanAbortRef.current = controller
    setScanAction({
      status: 'running',
      progress: 0,
      message: `Starting scan for ${uniqueTargets.length} asset${uniqueTargets.length === 1 ? '' : 's'}...`,
    })

    try {
      const params = new URLSearchParams({
        authorized: 'true',
        targets: uniqueTargets.join(','),
      })
      const response = await fetch(`/api/v1/scanner/stream?${params.toString()}`, {
        signal: controller.signal,
        headers: { Authorization: `Bearer ${token}` },
      })

      if (!response.ok) {
        const errorBody = await response.text().catch(() => '')
        let message = `Scanner returned HTTP ${response.status}`
        try {
          const parsed = JSON.parse(errorBody)
          message = parsed?.error?.message || parsed?.message || message
        } catch {
          if (errorBody.trim()) message = errorBody.trim()
        }
        throw new Error(message)
      }

      if (!response.body) throw new Error('Scanner stream did not return a response body.')

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      const processFrame = (frame: string) => {
        const dataLine = frame.split('\n').find((line) => line.startsWith('data:'))
        if (!dataLine) return
        try {
          const event = JSON.parse(dataLine.slice(5).trim())
          const progress = typeof event.progress === 'number' ? Math.max(0, Math.min(100, Math.round(event.progress))) : undefined
          const message = String(event.message || event.type || 'Scanner telemetry received')
          if (event.type === 'scan-complete' || event.status === 'completed') {
            setScanAction({ status: 'success', progress: 100, message })
          } else if (event.type === 'scan-failed' || event.status === 'failed') {
            setScanAction({ status: 'error', progress: progress ?? 100, message })
          } else {
            setScanAction((current) => ({
              status: 'running',
              progress: progress ?? current.progress,
              message,
            }))
          }
        } catch {
          // Ignore malformed SSE frames; the next persisted snapshot is authoritative.
        }
      }

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const frames = buffer.split('\n\n')
        buffer = frames.pop() || ''
        frames.forEach(processFrame)
      }
      if (buffer.trim()) processFrame(buffer)

      setScanAction((current) => current.status === 'error'
        ? current
        : { status: 'success', progress: 100, message: 'Scan completed and telemetry is refreshing.' })
      await fetchSnapshot()
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      const message = err instanceof Error ? err.message : 'Unable to start scanner stream.'
      setScanAction({ status: 'error', progress: 0, message })
    } finally {
      if (scanAbortRef.current === controller) scanAbortRef.current = null
    }
  }, [fetchSnapshot, token])

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null
      void fetchSnapshot()
    }, 250)
  }, [fetchSnapshot])

  useEffect(() => () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
    scanAbortRef.current?.abort()
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
      'vulnerabilities',
      'certificates',
      'migration_jobs',
      'migration_events',
      'compliance_evidence',
      'security_events',
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
      .channel(`vulnerabilities-${table}`)
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
      const vulnerabilitiesStream = new EventSource(`/api/v1/dashboard/vulnerabilities/stream?token=${encodeURIComponent(token)}`)
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`)
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`)
      streamsRef.current = [vulnerabilitiesStream, metricsStream, scannerStream]

      const markOpen = () => setSseConnected(true)
      const scheduleReconnect = () => {
        setSseConnected(false)
        closeStreams()
        if (retryTimer) clearTimeout(retryTimer)
        retryTimer = setTimeout(connect, 10000)
      }
      const refreshFromStream = () => queueRefresh()

      vulnerabilitiesStream.onopen = markOpen
      metricsStream.onopen = markOpen
      scannerStream.onopen = markOpen
      vulnerabilitiesStream.onerror = scheduleReconnect
      metricsStream.onerror = scheduleReconnect
      scannerStream.onerror = scheduleReconnect
      vulnerabilitiesStream.addEventListener('vulnerabilities-connected', refreshFromStream)
      vulnerabilitiesStream.addEventListener('vulnerabilities-update', refreshFromStream)
      vulnerabilitiesStream.addEventListener('vulnerabilities-error', refreshFromStream)
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

  return { snapshot, state, error, sseConnected, refresh: fetchSnapshot, runNewScan, scanAction }
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

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const width = 150
  const height = 48
  const max = Math.max(1, ...values)
  const points = values.length
    ? values.map((value, index) => {
      const x = values.length === 1 ? width : (index / (values.length - 1)) * width
      const y = height - (value / max) * (height - 8) - 4
      return `${x},${y}`
    }).join(' ')
    : `0,${height - 4} ${width},${height - 4}`

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-12 w-40 overflow-visible">
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function MetricCard({ label, value, detail, tone, values }: { label: string; value: string; detail: string; tone: 'red' | 'gold' | 'green'; values: number[] }) {
  const color = tone === 'red' ? RED : tone === 'green' ? GREEN : GOLD
  const panelClass = tone === 'red'
    ? 'border-red-500/25 bg-red-950/15 hover:border-red-400/55'
    : tone === 'green'
      ? 'border-emerald-500/25 bg-emerald-950/15 hover:border-emerald-400/55'
      : 'border-gold/25 bg-gold/[0.055] hover:border-gold/65'

  return (
    <GlassPanel className={cn('p-5', panelClass)}>
      <div className="flex items-end justify-between gap-4">
        <div>
          <div className="font-mono text-[10px] font-black uppercase tracking-[0.18em]" style={{ color }}>{label}</div>
          <div className="mt-2 font-mono text-4xl font-black leading-none" style={{ color }}>{value}</div>
        </div>
        <Sparkline values={values} color={color} />
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-white/6 pt-3 text-xs">
        <span className="text-white/60">{label === 'Critical Exposure' ? 'Assets at severe risk' : label === 'Legacy Algorithms' ? 'Detected in use' : 'Vulnerabilities fixed'}</span>
        <span className={detail.startsWith('+') ? 'text-emerald-300' : detail.startsWith('-') ? 'text-red-300' : 'text-white/45'}>{detail}</span>
      </div>
    </GlassPanel>
  )
}

function Donut({ total, rows, colors }: { total: number; rows: BreakdownRow[]; colors: string[] }) {
  let cursor = 0
  const safeTotal = Math.max(1, total)
  const segments = rows.map((row, index) => {
    const size = (row.count / safeTotal) * 100
    const start = cursor
    cursor += size
    return `${colors[index] || GOLD} ${start}% ${cursor}%`
  })
  const gradient = `conic-gradient(${segments.join(', ') || '#334155 0 100%'})`

  return (
    <div className="grid gap-5 md:grid-cols-[160px_minmax(0,1fr)]">
      <div className="flex justify-center">
        <div className="relative flex h-36 w-36 items-center justify-center rounded-full" style={{ background: gradient }}>
          <div className="absolute inset-6 rounded-full bg-[#07101D] shadow-[inset_0_0_24px_rgba(0,0,0,0.55)]" />
          <div className="relative text-center">
            <div className="font-mono text-3xl font-black text-white">{numberFmt(total)}</div>
            <div className="text-[10px] text-white/45">Total</div>
          </div>
        </div>
      </div>
      <div className="space-y-3 self-center">
        {rows.map((row, index) => (
          <div key={row.label || row.severity || index} className="flex items-center gap-3 text-sm">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: colors[index] || GOLD }} />
            <span className="flex-1 capitalize text-white/65">{row.label || row.severity}</span>
            <span className="font-mono font-bold text-white">{numberFmt(row.count)} ({row.percent}%)</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function TrendChart({ data }: { data: TrendPoint[] }) {
  const width = 520
  const height = 200
  const pad = 30
  const series = [
    { key: 'critical' as const, label: 'Critical', color: RED },
    { key: 'high' as const, label: 'High', color: ORANGE },
    { key: 'medium' as const, label: 'Medium', color: GOLD },
    { key: 'low' as const, label: 'Low', color: GREEN },
    { key: 'info' as const, label: 'Info', color: BLUE },
  ]
  const max = Math.max(1, ...data.flatMap((point) => series.map((item) => Number(point[item.key] || 0))))
  const pathFor = (key: keyof TrendPoint) => data.map((point, index) => {
    const x = pad + (index / Math.max(1, data.length - 1)) * (width - pad * 2)
    const y = height - pad - (Number(point[key] || 0) / max) * (height - pad * 2)
    return `${index === 0 ? 'M' : 'L'} ${x} ${y}`
  }).join(' ')

  return (
    <div>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-56 w-full">
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
          <span key={item.key} className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} /> {item.label}</span>
        ))}
      </div>
    </div>
  )
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="rounded-md border border-white/5 bg-white/[0.025] p-8 text-center text-xs font-semibold text-white/40">
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

function ActionButton({ href, label, icon: Icon }: { href: string; label: string; icon: LucideIcon }) {
  return (
    <a
      href={href}
      title={label}
      aria-label={label}
      className="group/action relative flex h-8 w-8 items-center justify-center rounded border border-white/10 bg-black/20 text-white/55 transition hover:border-gold/40 hover:text-gold"
    >
      <Icon className="h-4 w-4" />
      <span className="pointer-events-none absolute bottom-full left-1/2 z-30 mb-2 hidden -translate-x-1/2 whitespace-nowrap rounded border border-gold/25 bg-[#07101D] px-2 py-1 text-[10px] font-black uppercase tracking-[0.08em] text-gold shadow-xl group-hover/action:block">
        {label}
      </span>
    </a>
  )
}

export default function Vulnerabilities() {
  const { snapshot, state, error, sseConnected, refresh, runNewScan, scanAction } = useVulnerabilitySnapshot()
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all')
  const [assetTypeFilter, setAssetTypeFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')
  const [environmentFilter, setEnvironmentFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)

  const metrics = snapshot.metrics
  const filteredRows = useMemo(() => snapshot.vulnerabilities.filter((row) => {
    if (severityFilter !== 'all' && row.severity !== severityFilter) return false
    if (assetTypeFilter !== 'all' && row.assetType !== assetTypeFilter) return false
    if (typeFilter !== 'all' && row.type !== typeFilter) return false
    if (environmentFilter !== 'all' && row.environment !== environmentFilter) return false
    const evidenceText = (row.evidence || []).map((item) => `${item.label} ${item.description || ''} ${item.algorithm || ''} ${item.source || ''}`).join(' ')
    const haystack = `${row.title} ${row.description} ${row.asset} ${row.type} ${row.algorithm} ${row.source || ''} ${evidenceText}`.toLowerCase()
    return haystack.includes(query.toLowerCase())
  }), [assetTypeFilter, environmentFilter, query, severityFilter, snapshot.vulnerabilities, typeFilter])

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE))
  const safePage = Math.min(page, totalPages)
  const pageStart = filteredRows.length ? (safePage - 1) * PAGE_SIZE : 0
  const pageEnd = Math.min(pageStart + PAGE_SIZE, filteredRows.length)
  const pagedRows = useMemo(() => filteredRows.slice(pageStart, pageEnd), [filteredRows, pageEnd, pageStart])
  const visiblePages = useMemo(() => {
    return Array.from({ length: totalPages }, (_, index) => index + 1).filter((pageNumber) => (
      totalPages <= 7 ||
      pageNumber === 1 ||
      pageNumber === totalPages ||
      Math.abs(pageNumber - safePage) <= 1
    ))
  }, [safePage, totalPages])
  const scanTargets = useMemo(() => {
    const targets = snapshot.vulnerabilities
      .map(scanTargetForRow)
      .filter((target): target is string => Boolean(target))
    return Array.from(new Set(targets)).slice(0, 25)
  }, [snapshot.vulnerabilities])

  const metricTrend = useMemo(() => snapshot.trend.map((point) => point.critical + point.high + point.medium + point.low + point.info), [snapshot.trend])
  const criticalTrend = useMemo(() => snapshot.trend.map((point) => point.critical), [snapshot.trend])
  const legacyTrend = useMemo(() => snapshot.trend.map((point) => point.high + point.medium), [snapshot.trend])
  const generatedAt = snapshot.generatedAt ? new Date(snapshot.generatedAt) : new Date()

  const scanPct = scanAction.status === 'running'
    ? Math.max(5, scanAction.progress)
    : snapshot.scanStatus.latestStatus === 'completed' ? 100 : snapshot.scanStatus.activeScans ? 66 : snapshot.vulnerabilities.length ? 100 : 0
  const scanButtonLabel = scanAction.status === 'running' ? `Scanning ${scanAction.progress}%` : 'Run New Scan'

  useEffect(() => {
    setPage(1)
  }, [assetTypeFilter, environmentFilter, query, severityFilter, typeFilter])

  useEffect(() => {
    if (page > totalPages) setPage(totalPages)
  }, [page, totalPages])

  return (
    <main className="min-h-screen space-y-4 bg-[#02070E] p-3 text-white md:p-4">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <h1 className="font-mono text-3xl font-black uppercase tracking-tight text-white md:text-4xl">Quantum <span className="text-red-400">Vulnerabilities</span></h1>
          <p className="mt-2 max-w-4xl text-base text-white/58">Identified cryptographic weaknesses vulnerable to Harvest Now, Decrypt Later (HNDL) attacks.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <select value={environmentFilter} onChange={(event) => setEnvironmentFilter(event.target.value)} className="h-10 rounded-md border border-white/10 bg-black/20 px-4 text-sm text-white/70 outline-none focus:border-gold/40">
            <option value="all">All Environments</option>
            {snapshot.filters.environments.map((environment) => <option key={environment} value={environment}>{environment}</option>)}
          </select>
          <div className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 bg-black/20 px-4 text-sm text-white/70">
            <span>Last 7 Days</span>
            <CalendarDays className="h-4 w-4 text-gold" />
          </div>
          <button type="button" onClick={refresh} className="flex h-10 w-14 items-center justify-center rounded-md border border-white/10 bg-black/20 text-white/70 hover:border-gold/40 hover:text-gold">
            <RefreshCw className={cn('h-4 w-4', state === 'loading' && 'animate-spin')} />
          </button>
          <a href="/dashboard/scanner" className="inline-flex h-10 items-center gap-2 rounded-md border border-red-500 bg-red-500 px-4 text-sm font-black text-white shadow-[0_0_22px_rgba(239,68,68,0.35)] hover:bg-red-400">
            <Plus className="h-4 w-4" />
            New Scan
          </a>
        </div>
      </header>

      <div className="space-y-4">
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <MetricCard label="Critical Exposure" value={numberFmt(metrics.criticalExposure)} detail={formatDelta(metrics.criticalExposureDelta)} tone="red" values={criticalTrend} />
            <MetricCard label="Legacy Algorithms" value={numberFmt(metrics.legacyAlgorithms)} detail={formatDelta(metrics.legacyAlgorithmsDelta)} tone="gold" values={legacyTrend} />
            <MetricCard label="Remediated" value={numberFmt(metrics.remediated)} detail={formatDelta(metrics.remediatedDelta)} tone="green" values={metricTrend} />
          </div>

          <GlassPanel className="p-4">
            <div className="grid gap-3 xl:grid-cols-[160px_170px_190px_minmax(220px,1fr)_90px]">
              <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as 'all' | Severity)} className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white/70 outline-none focus:border-gold/40">
                <option value="all">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <select value={assetTypeFilter} onChange={(event) => setAssetTypeFilter(event.target.value)} className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white/70 outline-none focus:border-gold/40">
                <option value="all">All Asset Types</option>
                {snapshot.filters.assetTypes.map((assetType) => <option key={assetType} value={assetType}>{assetType}</option>)}
              </select>
              <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-white/70 outline-none focus:border-gold/40">
                <option value="all">All Vulnerability Types</option>
                {snapshot.filters.vulnerabilityTypes.map((type) => <option key={type} value={type}>{type}</option>)}
              </select>
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/40" />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search vulnerabilities, assets..." className="h-10 w-full rounded-md border border-white/10 bg-black/20 pl-10 pr-3 text-sm text-white outline-none placeholder:text-white/35 focus:border-gold/40" />
              </div>
              <button type="button" className="inline-flex items-center justify-center gap-2 rounded-md border border-white/10 bg-black/20 px-3 py-2 text-xs font-black text-white/70 hover:border-gold/40 hover:text-gold">
                <Filter className="h-4 w-4" />
                Filters
              </button>
            </div>
          </GlassPanel>

          <GlassPanel className="p-0">
            {filteredRows.length === 0 ? (
              <div className="p-6">
                <EmptyState label="No vulnerabilities match the current filters." />
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[980px] border-collapse text-left">
                  <thead>
                    <tr className="border-b border-white/8 bg-white/[0.025]">
                      {['Vulnerability', 'Asset', 'Exposure Level', 'First Detected', 'Status', 'Actions'].map((header) => (
                        <th key={header} className="px-4 py-4 font-mono text-[10px] font-black uppercase tracking-[0.18em] text-white/42">{header}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/6">
                    {pagedRows.map((row) => {
                      const detected = dateTime(row.detectedAt)
                      const rowRemediationHref = remediationHref(row)
                      const rowInspectHref = row.inspectHref || `/dashboard/crypto-exposure?${new URLSearchParams({ source: 'vulnerabilities', findingId: row.sourceId || row.id }).toString()}`
                      return (
                        <tr key={row.id} className="transition hover:bg-gold/[0.04]">
                          <td className="px-4 py-4">
                            <div className="flex items-start gap-3">
                              <div className={cn('mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border', severityClass(row.severity))}>
                                <XCircle className="h-4 w-4" />
                              </div>
                              <div>
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="font-mono text-sm font-black uppercase text-white/92">{row.title}</span>
                                  <span className={cn('rounded px-2 py-0.5 font-mono text-[9px] font-black uppercase', severityClass(row.severity))}>{row.severity}</span>
                                </div>
                                <div className="mt-1 max-w-xl text-xs leading-relaxed text-white/50">{row.description}</div>
                                {row.evidenceCount ? (
                                  <div className="mt-2 flex max-w-xl flex-wrap items-center gap-1.5">
                                    <span className="rounded border border-white/10 bg-white/[0.035] px-2 py-0.5 font-mono text-[9px] font-black uppercase tracking-[0.08em] text-white/38">
                                      Evidence
                                    </span>
                                    {(row.evidence || []).slice(0, 4).map((item) => (
                                      <span
                                        key={item.id || item.label}
                                        title={item.description || item.label}
                                        className="max-w-[220px] truncate rounded border border-red-500/18 bg-red-500/[0.06] px-2 py-0.5 font-mono text-[10px] text-red-200/85"
                                      >
                                        {item.label}
                                      </span>
                                    ))}
                                    {(row.evidenceCount || 0) > 4 ? (
                                      <span className="rounded border border-white/10 bg-white/[0.03] px-2 py-0.5 font-mono text-[10px] text-white/42">
                                        +{numberFmt((row.evidenceCount || 0) - 4)} more
                                      </span>
                                    ) : null}
                                  </div>
                                ) : null}
                              </div>
                            </div>
                          </td>
                          <td className="px-4 py-4">
                            <div className="text-sm text-white/80">{row.asset}</div>
                            <span className="mt-1 inline-flex rounded border border-white/10 bg-white/[0.03] px-2 py-0.5 text-[10px] text-white/45">{row.assetType}</span>
                          </td>
                          <td className={cn('px-4 py-4 font-mono text-xs font-black uppercase', row.exposureLevel.toLowerCase().includes('moderate') ? 'text-gold' : row.exposureLevel.toLowerCase().includes('high') ? 'text-red-300' : 'text-white/55')}>{row.exposureLevel}</td>
                          <td className="px-4 py-4 font-mono text-xs text-white/58">
                            <div>{detected.date}</div>
                            <div className="mt-1">{detected.time}</div>
                          </td>
                          <td className="px-4 py-4">
                            {row.status === 'Remediated' ? (
                              <span
                                title="Finding fixed"
                                className="inline-flex rounded border border-emerald-500/35 bg-emerald-500/10 px-4 py-2 font-mono text-[10px] font-black uppercase text-emerald-300"
                              >
                                Fixed
                              </span>
                            ) : (
                              <a
                                href={rowRemediationHref}
                                title={`Remediate ${row.title}`}
                                aria-label={`Remediate ${row.title}`}
                                className="inline-flex rounded border border-red-500/40 bg-red-500/10 px-4 py-2 font-mono text-[10px] font-black uppercase text-red-300 transition hover:border-gold/60 hover:bg-gold/10 hover:text-gold"
                              >
                                Remediate
                              </a>
                            )}
                            <span className="sr-only">
                              {row.status === 'Remediated' ? 'Fixed' : 'Remediate'}
                            </span>
                          </td>
                          <td className="px-4 py-4">
                            <div className="flex items-center gap-2">
                              <ActionButton href={rowInspectHref} label="View Exposure" icon={Eye} />
                              <ActionButton href={rowRemediationHref} label="Plan Remediation" icon={BarChart3} />
                              <ActionButton href={evidenceHref(row)} label="Open Evidence" icon={MoreVertical} />
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <div className="flex items-center justify-between border-t border-white/6 px-4 py-3 text-sm text-white/45">
              <span>Showing {filteredRows.length ? numberFmt(pageStart + 1) : '0'} to {numberFmt(pageEnd)} of {numberFmt(filteredRows.length)} results</span>
              <div className="flex items-center gap-2" aria-label="Vulnerability results pages">
                <button
                  type="button"
                  aria-label="Previous page"
                  disabled={safePage <= 1}
                  onClick={() => setPage((current) => Math.max(1, current - 1))}
                  className="flex h-8 w-8 items-center justify-center rounded border border-white/10 text-white/35 transition hover:border-gold/40 hover:text-gold disabled:cursor-not-allowed disabled:opacity-35"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                {visiblePages.map((pageNumber, index) => {
                  const previousPage = visiblePages[index - 1]
                  const hasGap = previousPage && pageNumber - previousPage > 1
                  return (
                    <span key={pageNumber} className="inline-flex items-center gap-2">
                      {hasGap ? <span className="text-white/35">...</span> : null}
                      <button
                        type="button"
                        aria-label={`Page ${pageNumber}`}
                        aria-current={safePage === pageNumber ? 'page' : undefined}
                        onClick={() => setPage(pageNumber)}
                        className={cn(
                          'h-8 min-w-8 rounded border px-2 text-sm transition hover:border-gold/40 hover:text-gold',
                          safePage === pageNumber ? 'border-red-500 text-red-300' : 'border-white/10 text-white/35'
                        )}
                      >
                        {pageNumber}
                      </button>
                    </span>
                  )
                })}
                <button
                  type="button"
                  aria-label="Next page"
                  disabled={safePage >= totalPages}
                  onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                  className="flex h-8 w-8 items-center justify-center rounded border border-white/10 text-white/35 transition hover:border-gold/40 hover:text-gold disabled:cursor-not-allowed disabled:opacity-35"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          </GlassPanel>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(260px,0.72fr)_minmax(340px,1fr)_minmax(280px,0.78fr)]">
          <GlassPanel className="p-4">
            <SectionTitle icon={Activity}>Scan Status</SectionTitle>
            <div className="grid gap-4 sm:grid-cols-[90px_minmax(0,1fr)]">
              <div className="relative flex h-24 w-24 items-center justify-center rounded-full bg-[conic-gradient(#3B82F6_var(--scan),rgba(255,255,255,0.08)_0)]" style={{ '--scan': `${scanPct}%` } as CSSProperties}>
                <div className="absolute inset-3 rounded-full bg-[#07101D]" />
                <Activity className="relative h-6 w-6 text-blue-400" />
              </div>
              <div className="space-y-2 text-xs text-white/55">
                <div><span className="text-white/35">Last Scan</span><br />{relativeTime(snapshot.scanStatus.latestScanAt)}</div>
                <div><span className="text-white/35">Next Scan</span><br />{relativeTime(snapshot.scanStatus.nextScanAt)}</div>
                <button
                  type="button"
                  onClick={() => void runNewScan(scanTargets)}
                  disabled={scanAction.status === 'running'}
                  title={scanTargets.length ? `Run scan for ${scanTargets.length} current asset target${scanTargets.length === 1 ? '' : 's'}` : 'No scannable target found on this page'}
                  className="mt-2 h-9 w-full rounded border border-blue-500/50 bg-blue-500/5 text-xs font-black text-blue-300 transition hover:bg-blue-500/10 disabled:cursor-wait disabled:opacity-60"
                >
                  {scanButtonLabel}
                </button>
                {scanAction.message ? (
                  <div className={cn(
                    'rounded border px-2 py-1 text-[10px] leading-relaxed',
                    scanAction.status === 'error'
                      ? 'border-red-500/35 bg-red-500/10 text-red-200'
                      : scanAction.status === 'success'
                        ? 'border-emerald-500/35 bg-emerald-500/10 text-emerald-200'
                        : 'border-blue-500/25 bg-blue-500/10 text-blue-100'
                  )}>
                    {scanAction.message}
                  </div>
                ) : null}
              </div>
            </div>
          </GlassPanel>

          <GlassPanel className="p-4">
            <SectionTitle icon={Settings}>Quick Actions</SectionTitle>
            <div className="grid gap-2 sm:grid-cols-2">
              {[
                { label: 'Run Quantum Scan', detail: 'Start a new vulnerability scan', href: '/dashboard/scanner', icon: Target },
                { label: 'Add Asset', detail: 'Add new asset for scanning', href: '/dashboard/assets_map', icon: Plus },
                { label: 'View Reports', detail: 'View scan and compliance reports', href: '/dashboard/audit-vault', icon: FileText },
                { label: 'Manage Policies', detail: 'Configure detection policies', href: '/dashboard/crypto-policies', icon: Settings },
              ].map((action) => {
                const Icon = action.icon
                return (
                  <a key={action.label} href={action.href} className="flex items-center gap-3 rounded-md border border-white/10 bg-white/[0.025] p-3 transition hover:border-gold/40 hover:bg-gold/[0.06]">
                    <Icon className="h-4 w-4 text-white/65" />
                    <div>
                      <div className="text-xs font-black text-white/85">{action.label}</div>
                      <div className="mt-1 text-[10px] text-white/40">{action.detail}</div>
                    </div>
                  </a>
                )
              })}
            </div>
          </GlassPanel>

          <GlassPanel className="p-4">
            <SectionTitle icon={ShieldAlert}>Top Vulnerable Assets</SectionTitle>
            {snapshot.topAssets.length === 0 ? (
              <EmptyState label="No vulnerable assets detected." />
            ) : (
              <div className="space-y-3">
                {snapshot.topAssets.map((asset) => (
                  <div key={asset.asset} className="flex items-center gap-3 text-xs">
                    <ShieldAlert className="h-4 w-4 text-white/45" />
                    <span className="min-w-0 flex-1 truncate text-white/75">{asset.asset}</span>
                    <span className={cn('rounded border px-2 py-1 text-[9px] font-black capitalize', severityClass(asset.severity))}>{asset.severity}</span>
                  </div>
                ))}
              </div>
            )}
            <a href="/dashboard/assets_map" className="mt-4 flex h-9 items-center justify-center rounded border border-blue-500/45 text-xs font-black text-blue-300 hover:bg-blue-500/10">View All Assets</a>
          </GlassPanel>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,0.78fr)_minmax(0,0.95fr)_minmax(0,0.82fr)]">
        <GlassPanel className="p-5">
          <SectionTitle icon={ShieldAlert}>Vulnerabilities By Severity</SectionTitle>
          <Donut total={metrics.totalVulnerabilities} rows={snapshot.severityBreakdown} colors={[RED, ORANGE, GOLD, GREEN, BLUE]} />
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={BarChart3}>Trend Over Time</SectionTitle>
          <TrendChart data={snapshot.trend} />
        </GlassPanel>

        <GlassPanel className="p-5">
          <SectionTitle icon={Activity}>Vulnerabilities By Asset Type</SectionTitle>
          <Donut total={metrics.totalVulnerabilities} rows={snapshot.assetTypeBreakdown} colors={ASSET_COLORS} />
        </GlassPanel>
      </div>

      <footer className="flex flex-col gap-2 border-t border-white/5 pt-3 text-[10px] font-mono uppercase tracking-wider text-white/30 md:flex-row md:items-center md:justify-between">
        <span>{error ? `Telemetry warning: ${error}` : 'Vulnerability telemetry synchronized'}</span>
        <span>Live stream: {sseConnected ? 'connected' : 'standby'} / Snapshot: {snapshot.generatedAt ? relativeTime(snapshot.generatedAt) : 'pending'} / Generated: {generatedAt.toLocaleTimeString('en-US', { hour12: false })}</span>
        <button type="button" onClick={() => exportJson('vulnerability-report', snapshot)} className="inline-flex items-center gap-2 text-gold hover:text-[#FFE8A8]"><Download className="h-3.5 w-3.5" /> Export Snapshot</button>
      </footer>
    </main>
  )
}
