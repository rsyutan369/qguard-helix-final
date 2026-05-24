import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  BarChart3,
  BookOpen,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Copy,
  Download,
  Eye,
  FileText,
  FlaskConical,
  Globe2,
  History,
  Key,
  Layers,
  Lightbulb,
  Lock,
  Maximize2,
  Minimize2,
  MoreHorizontal,
  Pause,
  Play,
  Plus,
  Radio,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Square,
  Target,
  Terminal,
  TestTube2,
  TrendingDown,
  TrendingUp,
  Upload,
  X,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'

/* ═══════════════════════════════════════════════════════════════════════════
   TYPES
   ═══════════════════════════════════════════════════════════════════════════ */

type SimulationStatus = 'running' | 'completed' | 'failed' | 'queued' | 'paused'

type SimEvent = {
  id: string
  type: string
  message: string
  severity: string
  timestamp: string
}

type Simulation = {
  id: string
  name: string
  assetId: string | null
  assetName: string
  assetType: string
  environment: string
  owner: string
  criticality: string
  fromAlgo: string
  toAlgo: string
  migrationType: string
  status: SimulationStatus
  progress: number
  riskLevel: string
  phase: string
  startedAt: string | null
  completedAt: string | null
  updatedAt: string
  createdAt: string
  eventCount: number
  recentEvents: SimEvent[]
  metadata: Record<string, unknown>
}

type RiskFactor = {
  label: string
  count: number
  severity: string
  impact: string
}

type Recommendation = {
  id: string
  priority: number
  type: string
  title: string
  description: string
  algorithm: string
  asset: string
  effort: string
  timeEstimate: string
  compliance: string[]
}

type ComplianceItem = {
  framework: string
  control: string
  status: string
  score: number
}

type WorkflowPhase = {
  id: string
  label: string
  description: string
  complete: boolean
  active: boolean
  progress: number
}

type PqcStackItem = {
  name: string
  standard: string
  status: string
  usage: number
}

type LogEntry = {
  id: string
  jobId: string
  type: string
  message: string
  severity: string
  timestamp: string
}

type SandboxSummary = {
  totalSimulations: number
  running: number
  completed: number
  failed: number
  queued: number
  paused: number
  totalAssets: number
  vulnerableAssets: number
  criticalExposures: number
  highExposures: number
  openVulnerabilities: number
  pqcReadiness: number
  riskScore: number
  complianceScore: number
  expiringCerts: number
  lastScanAt: string | null
  completionRate: number
}

type SandboxSnapshot = {
  generatedAt: string
  summary: SandboxSummary
  simulations: Simulation[]
  riskFactors: RiskFactor[]
  recommendations: Recommendation[]
  complianceItems: ComplianceItem[]
  complianceScore: number
  workflowPhases: WorkflowPhase[]
  pqcStack: PqcStackItem[]
  recentLogs: LogEntry[]
}

type ActiveTab = 'overview' | 'simulations' | 'risk' | 'rollback' | 'compliance' | 'logs' | 'recommendations' | 'pqc-stack'

const EMPTY: SandboxSnapshot = {
  generatedAt: new Date().toISOString(),
  summary: { totalSimulations: 0, running: 0, completed: 0, failed: 0, queued: 0, paused: 0, totalAssets: 0, vulnerableAssets: 0, criticalExposures: 0, highExposures: 0, openVulnerabilities: 0, pqcReadiness: 0, riskScore: 100, complianceScore: 0, expiringCerts: 0, lastScanAt: null, completionRate: 0 },
  simulations: [],
  riskFactors: [],
  recommendations: [],
  complianceItems: [],
  complianceScore: 0,
  workflowPhases: [],
  pqcStack: [],
  recentLogs: [],
}

/* ═══════════════════════════════════════════════════════════════════════════
   STYLE TOKENS
   ═══════════════════════════════════════════════════════════════════════════ */

const GOLD = '#FBBF24'
const GREEN = '#22C55E'
const RED = '#EF4444'
const BLUE = '#38BDF8'
const PURPLE = '#A78BFA'
const CYAN = '#22D3EE'
const ORANGE = '#F97316'

const GLASS =
  'group relative overflow-hidden rounded-xl border border-gold/15 bg-[#060F1C]/80 backdrop-blur-2xl shadow-[inset_0_1px_0_rgba(255,255,255,0.06),0_0_30px_rgba(0,0,0,0.3)] transition-all duration-500 hover:border-gold/40 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.12),0_8px_32px_rgba(0,0,0,0.4),0_0_48px_rgba(251,191,36,0.08)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/50 before:to-transparent'

/* ═══════════════════════════════════════════════════════════════════════════
   UTILS
   ═══════════════════════════════════════════════════════════════════════════ */

function fmt(v: number) { return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(v || 0))) }
function pct(v: number) { return `${Math.max(0, Math.min(100, Math.round(v || 0)))}%` }

function relTime(v: string | null) {
  if (!v) return '--'
  const ms = Date.now() - new Date(v).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '--'
  const m = Math.round(ms / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

function timeStr(v: string | null) {
  if (!v) return '--'
  const d = new Date(v)
  return Number.isFinite(d.getTime()) ? d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '--'
}

function statusColor(s: string) {
  if (s === 'running') return { bg: 'bg-emerald-500/12', border: 'border-emerald-500/30', text: 'text-emerald-300', dot: 'bg-emerald-400' }
  if (s === 'completed') return { bg: 'bg-emerald-500/12', border: 'border-emerald-500/30', text: 'text-emerald-300', dot: 'bg-emerald-400' }
  if (s === 'failed') return { bg: 'bg-red-500/12', border: 'border-red-500/30', text: 'text-red-300', dot: 'bg-red-400' }
  if (s === 'paused') return { bg: 'bg-amber-500/12', border: 'border-amber-500/30', text: 'text-amber-300', dot: 'bg-amber-400' }
  return { bg: 'bg-sky-500/10', border: 'border-sky-500/25', text: 'text-sky-300', dot: 'bg-sky-400' }
}

function riskBadge(level: string) {
  if (level === 'critical') return 'bg-red-500/15 border-red-500/30 text-red-300'
  if (level === 'high') return 'bg-orange-500/15 border-orange-500/30 text-orange-300'
  if (level === 'medium') return 'bg-amber-500/15 border-amber-500/30 text-amber-300'
  return 'bg-emerald-500/12 border-emerald-500/30 text-emerald-300'
}

function complianceColor(status: string) {
  if (status === 'compliant') return 'text-emerald-300'
  if (status === 'partial') return 'text-amber-300'
  if (status === 'pending') return 'text-sky-300'
  return 'text-red-300'
}

function severityIcon(s: string) {
  if (s === 'critical' || s === 'error') return <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
  if (s === 'warning' || s === 'high') return <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
  if (s === 'info') return <CheckCircle2 className="h-3.5 w-3.5 text-sky-400" />
  return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
}

function progressBarColor(v: number, status: string) {
  if (status === 'failed') return RED
  if (status === 'completed') return GREEN
  if (v >= 70) return GREEN
  if (v >= 40) return GOLD
  return ORANGE
}

/* ═══════════════════════════════════════════════════════════════════════════
   DATA HOOK — Connects to /api/v1/sandbox + SSE + Supabase Realtime
   ═══════════════════════════════════════════════════════════════════════════ */

function useSandbox() {
  const { session, user } = useAuth()
  const token = session?.access_token
  const [data, setData] = useState<SandboxSnapshot>(EMPTY)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [sseActive, setSseActive] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  const fetchSnapshot = useCallback(async () => {
    if (!token) return
    try {
      const r = await fetch('/api/v1/sandbox/snapshot', { headers: { Authorization: `Bearer ${token}` } })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(j?.error?.message || `HTTP ${r.status}`)
      setData(j.data || EMPTY)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed')
    } finally {
      setLoading(false)
    }
  }, [token])

  // Initial fetch
  useEffect(() => { if (token && user) fetchSnapshot() }, [token, user, fetchSnapshot])

  // SSE connection
  useEffect(() => {
    if (!token) return
    let retry: ReturnType<typeof setTimeout> | undefined
    const connect = () => {
      const es = new EventSource(`/api/v1/sandbox/stream?token=${encodeURIComponent(token)}`)
      esRef.current = es
      es.onopen = () => setSseActive(true)
      es.onerror = () => { setSseActive(false); es.close(); retry = setTimeout(connect, 12000) }
      es.addEventListener('sandbox-update', (e) => {
        try {
          const d = JSON.parse(e.data)
          if (d) setData(d)
        } catch { /* skip */ }
      })
    }
    connect()
    return () => { if (retry) clearTimeout(retry); esRef.current?.close(); esRef.current = null; setSseActive(false) }
  }, [token])

  // Supabase realtime
  useEffect(() => {
    if (!user) return
    const tables = ['migration_jobs', 'migration_events', 'assets', 'crypto_exposures', 'crypto_inventory', 'certificates', 'pqc_scan_sessions']
    const channels = tables.map((t) =>
      supabase.channel(`sandbox-${t}`).on('postgres_changes', { event: '*', schema: 'public', table: t, filter: `user_id=eq.${user.id}` }, () => fetchSnapshot()).subscribe()
    )
    return () => { channels.forEach((c) => supabase.removeChannel(c)) }
  }, [user, fetchSnapshot])

  // Actions
  const doAction = useCallback(async (jobId: string, action: string) => {
    if (!token) return
    await fetch(`/api/v1/sandbox/jobs/${jobId}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ action }),
    })
    fetchSnapshot()
  }, [token, fetchSnapshot])

  const doBulkAction = useCallback(async (action: string) => {
    if (!token) return
    await fetch('/api/v1/sandbox/bulk-action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ action }),
    })
    fetchSnapshot()
  }, [token, fetchSnapshot])

  const startSimulation = useCallback(async (params: { fromAlgo: string; toAlgo?: string; migrationType?: string; dryRun?: boolean; assetId?: string }) => {
    if (!token) return null
    const r = await fetch('/api/v1/sandbox/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(params),
    })
    const j = await r.json().catch(() => ({}))
    fetchSnapshot()
    return j?.data || null
  }, [token, fetchSnapshot])

  const exportReport = useCallback(async (format: 'json' | 'csv' = 'json') => {
    if (!token) return
    const r = await fetch(`/api/v1/sandbox/export?format=${format}`, { headers: { Authorization: `Bearer ${token}` } })
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `qguard-sandbox-${new Date().toISOString().slice(0, 10)}.${format}`
    a.click()
    URL.revokeObjectURL(url)
  }, [token])

  return { data, loading, error, sseActive, refresh: fetchSnapshot, doAction, doBulkAction, startSimulation, exportReport }
}

/* ═══════════════════════════════════════════════════════════════════════════
   SUB-COMPONENTS
   ═══════════════════════════════════════════════════════════════════════════ */

function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cn(GLASS, className)}><div className="relative z-10 h-full">{children}</div></section>
}

function SectionHead({ icon: Icon, children, suffix }: { icon: LucideIcon; children: ReactNode; suffix?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h2 className="flex items-center gap-2.5 text-sm font-extrabold text-white/90">
        <Icon className="h-4.5 w-4.5 text-gold" />
        {children}
      </h2>
      {suffix}
    </div>
  )
}

function Pill({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-bold tracking-wide', className)}>{children}</span>
}

function ProgressBar({ value, color = GOLD, height = 'h-1.5' }: { value: number; color?: string; height?: string }) {
  const w = Math.max(0, Math.min(100, value))
  return (
    <div className={cn('overflow-hidden rounded-full bg-white/8', height)}>
      <div className="h-full rounded-full transition-all duration-700 ease-out" style={{ width: `${w}%`, background: `linear-gradient(90deg, ${color}aa, ${color})`, boxShadow: `0 0 12px ${color}55` }} />
    </div>
  )
}

function EmptyBlock({ label }: { label: string }) {
  return <div className="rounded-lg border border-white/5 bg-white/[0.02] p-8 text-center text-xs font-semibold text-white/35">{label}</div>
}

function ActionBtn({ icon: Icon, label, onClick, variant = 'default', small, disabled }: { icon: LucideIcon; label: string; onClick?: () => void; variant?: 'default' | 'gold' | 'danger' | 'success'; small?: boolean; disabled?: boolean }) {
  const styles = {
    default: 'border-white/12 bg-white/[0.03] text-white/70 hover:border-gold/40 hover:bg-gold/8 hover:text-gold',
    gold: 'border-gold/40 bg-gold/10 text-gold hover:bg-gold/20',
    danger: 'border-red-500/30 bg-red-500/8 text-red-300 hover:bg-red-500/15',
    success: 'border-emerald-500/30 bg-emerald-500/8 text-emerald-300 hover:bg-emerald-500/15',
  }
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn('inline-flex items-center gap-1.5 rounded-lg border font-bold transition-all', styles[variant], small ? 'px-2.5 py-1.5 text-[10px]' : 'px-3.5 py-2 text-xs', disabled && 'pointer-events-none opacity-40')}
    >
      <Icon className={small ? 'h-3 w-3' : 'h-3.5 w-3.5'} />
      {label}
    </button>
  )
}

function MetricTile({ label, value, detail, icon: Icon, color, trend }: { label: string; value: string; detail?: string; icon: LucideIcon; color: string; trend?: number }) {
  return (
    <Panel className="p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-[9px] font-bold uppercase tracking-[0.2em] text-white/40">{label}</div>
          <div className="mt-2 font-mono text-2xl font-black leading-none text-white">{value}</div>
          {detail && <div className="mt-1.5 text-[10px] font-semibold" style={{ color }}>{detail}</div>}
        </div>
        <div className="flex flex-col items-center gap-1.5">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border bg-black/30" style={{ borderColor: `${color}44`, color, boxShadow: `0 0 20px ${color}18` }}>
            <Icon className="h-5 w-5" />
          </div>
          {trend !== undefined && trend !== 0 && (
            <div className={cn('flex items-center gap-0.5 text-[9px] font-bold', trend > 0 ? 'text-emerald-400' : 'text-red-400')}>
              {trend > 0 ? <ArrowUpRight className="h-2.5 w-2.5" /> : <ArrowDownRight className="h-2.5 w-2.5" />}
              {Math.abs(trend)}%
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}

function ScoreGauge({ value, size = 120, label }: { value: number; size?: number; label: string }) {
  const r = (size - 16) / 2
  const circ = 2 * Math.PI * r
  const offset = circ - (Math.max(0, Math.min(100, value)) / 100) * circ
  const color = value >= 80 ? GREEN : value >= 60 ? GOLD : value >= 40 ? ORANGE : RED
  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="rgba(255,255,255,0.06)" strokeWidth={8} fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={8} fill="none" strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" className="transition-all duration-1000 ease-out" style={{ filter: `drop-shadow(0 0 8px ${color}66)` }} />
      </svg>
      <div className="absolute flex flex-col items-center justify-center" style={{ width: size, height: size }}>
        <span className="font-mono text-2xl font-black text-white">{Math.round(value)}</span>
        <span className="text-[9px] font-bold uppercase tracking-wider text-white/40">/ 100</span>
      </div>
      <span className="text-[10px] font-bold text-white/50">{label}</span>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   NEW SIMULATION MODAL
   ═══════════════════════════════════════════════════════════════════════════ */

function NewSimulationModal({ open, onClose, onStart }: { open: boolean; onClose: () => void; onStart: (p: any) => void }) {
  const [fromAlgo, setFromAlgo] = useState('RSA-2048')
  const [toAlgo, setToAlgo] = useState('ML-KEM-768')
  const [migType, setMigType] = useState('key_exchange')
  const [dryRun, setDryRun] = useState(true)

  if (!open) return null

  const presets = [
    { label: 'RSA → ML-KEM', from: 'RSA-2048', to: 'ML-KEM-768', type: 'key_exchange' },
    { label: 'ECDSA → ML-DSA', from: 'ECDSA P-256', to: 'ML-DSA-65', type: 'digital_signature' },
    { label: 'TLS Certificate', from: 'RSA-2048 (TLS)', to: 'ML-DSA-65 (Hybrid)', type: 'tls_certificate' },
    { label: 'VPN Tunnel', from: 'IKEv2 + ECDH', to: 'ML-KEM Hybrid KEX', type: 'vpn_tunnel' },
    { label: 'API Encryption', from: 'AES-128-CBC', to: 'AES-256-GCM', type: 'api_encryption' },
    { label: 'Database Re-key', from: 'AES-128', to: 'AES-256-GCM', type: 'database_rekey' },
    { label: 'HSM Migration', from: 'RSA-3072', to: 'ML-KEM-1024', type: 'hsm_migration' },
    { label: 'Key Rotation', from: 'ECDSA P-384', to: 'ML-DSA-87', type: 'key_rotation' },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-2xl border border-gold/25 bg-[#0A1525]/95 p-6 shadow-2xl backdrop-blur-xl" onClick={(e) => e.stopPropagation()}>
        <div className="mb-5 flex items-center justify-between">
          <h3 className="flex items-center gap-2 text-lg font-black text-white"><FlaskConical className="h-5 w-5 text-gold" /> New Migration Simulation</h3>
          <button type="button" onClick={onClose} className="rounded-lg p-1.5 text-white/40 hover:bg-white/10 hover:text-white"><X className="h-4 w-4" /></button>
        </div>

        <div className="mb-5">
          <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-white/40">Quick Presets</div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {presets.map((p) => (
              <button key={p.label} type="button" onClick={() => { setFromAlgo(p.from); setToAlgo(p.to); setMigType(p.type) }}
                className={cn('rounded-lg border px-3 py-2.5 text-left text-[11px] font-bold transition-all',
                  fromAlgo === p.from && toAlgo === p.to ? 'border-gold/50 bg-gold/12 text-gold' : 'border-white/10 bg-white/[0.02] text-white/60 hover:border-gold/30 hover:text-white'
                )}>
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div className="mb-5 grid gap-4 sm:grid-cols-2">
          <div>
            <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-white/40">Source Algorithm</label>
            <input value={fromAlgo} onChange={(e) => setFromAlgo(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2.5 font-mono text-sm text-white outline-none focus:border-gold/50" />
          </div>
          <div>
            <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-white/40">Target Algorithm (PQC)</label>
            <input value={toAlgo} onChange={(e) => setToAlgo(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2.5 font-mono text-sm text-white outline-none focus:border-gold/50" />
          </div>
        </div>

        <div className="mb-5 flex items-center gap-4">
          <label className="flex cursor-pointer items-center gap-2 text-xs text-white/60">
            <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-white/5 accent-gold" />
            <span className="font-bold">Dry Run Mode</span>
            <span className="text-[10px] text-white/35">(Simulate without commit)</span>
          </label>
        </div>

        <div className="flex items-center justify-end gap-3">
          <button type="button" onClick={onClose} className="rounded-lg border border-white/10 px-4 py-2 text-xs font-bold text-white/50 hover:bg-white/5">Cancel</button>
          <button type="button" onClick={() => { onStart({ fromAlgo, toAlgo, migrationType: migType, dryRun }); onClose() }}
            className="rounded-lg border border-gold bg-gold px-5 py-2 text-xs font-black text-black shadow-[0_0_20px_rgba(251,191,36,0.3)] transition hover:bg-[#FFE08A]">
            <Play className="mr-1.5 inline h-3.5 w-3.5" />
            Start Simulation
          </button>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   SIMULATION ROW (Expandable)
   ═══════════════════════════════════════════════════════════════════════════ */

function SimulationRow({ sim, onAction }: { sim: Simulation; onAction: (id: string, action: string) => void }) {
  const [expanded, setExpanded] = useState(false)
  const sc = statusColor(sim.status)

  return (
    <div className="rounded-lg border border-white/6 bg-white/[0.015] transition hover:border-gold/15 hover:bg-gold/[0.02]">
      <div className="flex items-center gap-3 px-4 py-3 cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <button type="button" className="text-white/30 hover:text-white">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>

        <div className={cn('h-2 w-2 rounded-full', sc.dot, sim.status === 'running' && 'animate-pulse')} />

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-bold text-white/90">{sim.name}</span>
            <Pill className={riskBadge(sim.riskLevel)}>{sim.riskLevel}</Pill>
          </div>
          <div className="mt-0.5 text-[10px] text-white/40">
            <span className="font-mono">{sim.fromAlgo}</span>
            <span className="mx-1.5 text-gold">→</span>
            <span className="font-mono text-emerald-300">{sim.toAlgo}</span>
            <span className="mx-2 text-white/20">|</span>
            <span>{sim.environment}</span>
            <span className="mx-2 text-white/20">|</span>
            <span>{sim.owner}</span>
          </div>
        </div>

        <div className="hidden items-center gap-2 sm:flex">
          <Pill className={cn(sc.bg, sc.border, sc.text, 'uppercase tracking-wider')}>{sim.status}</Pill>
        </div>

        <div className="flex w-28 items-center gap-2">
          <div className="flex-1"><ProgressBar value={sim.progress} color={progressBarColor(sim.progress, sim.status)} /></div>
          <span className="font-mono text-[10px] font-bold text-white/50">{sim.progress}%</span>
        </div>

        <div className="hidden text-[10px] font-mono text-white/35 lg:block">{relTime(sim.updatedAt)}</div>
      </div>

      {expanded && (
        <div className="border-t border-white/5 px-4 py-3">
          <div className="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
            <div><div className="text-[9px] font-bold uppercase text-white/30">Asset</div><div className="mt-0.5 text-xs text-white/70">{sim.assetName}</div></div>
            <div><div className="text-[9px] font-bold uppercase text-white/30">Type</div><div className="mt-0.5 text-xs text-white/70">{sim.assetType}</div></div>
            <div><div className="text-[9px] font-bold uppercase text-white/30">Phase</div><div className="mt-0.5 text-xs font-bold capitalize text-gold">{sim.phase}</div></div>
            <div><div className="text-[9px] font-bold uppercase text-white/30">Criticality</div><div className="mt-0.5 text-xs font-bold capitalize text-white/70">{sim.criticality}</div></div>
            <div><div className="text-[9px] font-bold uppercase text-white/30">Started</div><div className="mt-0.5 font-mono text-[11px] text-white/50">{sim.startedAt ? timeStr(sim.startedAt) : '--'}</div></div>
            <div><div className="text-[9px] font-bold uppercase text-white/30">Events</div><div className="mt-0.5 font-mono text-xs text-white/70">{fmt(sim.eventCount)}</div></div>
          </div>

          {sim.recentEvents.length > 0 && (
            <div className="mb-3 space-y-1">
              <div className="text-[9px] font-bold uppercase text-white/30">Recent Events</div>
              {sim.recentEvents.map((ev) => (
                <div key={ev.id} className="flex items-center gap-2 rounded bg-white/[0.02] px-2 py-1.5 text-[11px]">
                  {severityIcon(ev.severity)}
                  <span className="flex-1 text-white/60 truncate">{ev.message}</span>
                  <span className="font-mono text-[9px] text-white/25">{timeStr(ev.timestamp)}</span>
                </div>
              ))}
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            {sim.status === 'running' && <ActionBtn icon={Pause} label="Pause" onClick={() => onAction(sim.id, 'pause')} small />}
            {sim.status === 'paused' && <ActionBtn icon={Play} label="Resume" onClick={() => onAction(sim.id, 'resume')} variant="success" small />}
            {sim.status === 'failed' && <ActionBtn icon={RefreshCw} label="Retry" onClick={() => onAction(sim.id, 'retry')} variant="gold" small />}
            {sim.status === 'running' && <ActionBtn icon={Square} label="Stop" onClick={() => onAction(sim.id, 'stop')} variant="danger" small />}
            {(sim.status === 'running' || sim.status === 'completed') && <ActionBtn icon={RotateCcw} label="Rollback" onClick={() => onAction(sim.id, 'rollback')} variant="danger" small />}
            <ActionBtn icon={Save} label="Snapshot" onClick={() => onAction(sim.id, 'snapshot')} small />
            <ActionBtn icon={Eye} label="Details" onClick={() => window.location.href = `/dashboard/live-ops`} small />
          </div>
        </div>
      )}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   WORKFLOW TIMELINE
   ═══════════════════════════════════════════════════════════════════════════ */

function WorkflowTimeline({ phases }: { phases: WorkflowPhase[] }) {
  if (phases.length === 0) return <EmptyBlock label="No workflow phases available. Start a simulation to begin." />
  return (
    <div className="space-y-1">
      {phases.map((p, i) => (
        <div key={p.id} className={cn('flex items-start gap-3 rounded-lg border px-4 py-3 transition',
          p.complete ? 'border-emerald-500/20 bg-emerald-500/[0.03]'
          : p.active ? 'border-gold/25 bg-gold/[0.04]'
          : 'border-white/5 bg-white/[0.015]')}>
          <div className="relative flex flex-col items-center">
            <div className={cn('flex h-7 w-7 items-center justify-center rounded-full border text-xs font-black',
              p.complete ? 'border-emerald-500/50 bg-emerald-500/20 text-emerald-300'
              : p.active ? 'border-gold/50 bg-gold/15 text-gold'
              : 'border-white/15 bg-white/5 text-white/30')}>
              {p.complete ? <CheckCircle2 className="h-4 w-4" /> : <span>{i + 1}</span>}
            </div>
            {i < phases.length - 1 && <div className={cn('mt-1 h-4 w-px', p.complete ? 'bg-emerald-500/30' : 'bg-white/8')} />}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className={cn('text-sm font-bold', p.complete ? 'text-emerald-300' : p.active ? 'text-gold' : 'text-white/50')}>{p.label}</span>
              {p.active && !p.complete && <span className="flex items-center gap-1 text-[9px] font-bold text-gold"><Activity className="h-3 w-3 animate-pulse" />Active</span>}
            </div>
            <div className="mt-0.5 text-[11px] text-white/35">{p.description}</div>
            {(p.active || p.complete) && (
              <div className="mt-2 flex items-center gap-2">
                <div className="w-24"><ProgressBar value={p.progress} color={p.complete ? GREEN : GOLD} /></div>
                <span className="font-mono text-[10px] text-white/40">{p.progress}%</span>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN EXPORT
   ═══════════════════════════════════════════════════════════════════════════ */

export default function MigrationSandbox() {
  const { data, loading, error, sseActive, refresh, doAction, doBulkAction, startSimulation, exportReport } = useSandbox()
  const [tab, setTab] = useState<ActiveTab>('overview')
  const [showNewSim, setShowNewSim] = useState(false)
  const [logFilter, setLogFilter] = useState('')

  const s = data.summary
  const generated = useMemo(() => new Date(data.generatedAt), [data.generatedAt])

  const tabs: { key: ActiveTab; label: string; icon: LucideIcon }[] = [
    { key: 'overview', label: 'Overview', icon: Layers },
    { key: 'simulations', label: `Simulations (${s.totalSimulations})`, icon: FlaskConical },
    { key: 'risk', label: 'Risk Analysis', icon: ShieldAlert },
    { key: 'rollback', label: 'Rollback Center', icon: RotateCcw },
    { key: 'compliance', label: 'Compliance', icon: ShieldCheck },
    { key: 'recommendations', label: 'AI Insights', icon: Bot },
    { key: 'logs', label: 'Execution Logs', icon: Terminal },
    { key: 'pqc-stack', label: 'PQC Stack', icon: Key },
  ]

  const filteredLogs = useMemo(() => {
    if (!logFilter) return data.recentLogs
    const q = logFilter.toLowerCase()
    return data.recentLogs.filter((l) => l.message.toLowerCase().includes(q) || l.type.toLowerCase().includes(q) || l.severity.toLowerCase().includes(q))
  }, [data.recentLogs, logFilter])

  /* ─── Loading State ──────────────────────────────────────────────────── */
  if (loading && s.totalSimulations === 0) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#02070E] p-4">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-2 border-gold/20 border-t-gold" />
          <span className="text-sm font-bold text-white/50">Initializing Migration Sandbox…</span>
        </div>
      </main>
    )
  }

  return (
    <main className="min-h-screen bg-[#02070E] text-white">
      <NewSimulationModal open={showNewSim} onClose={() => setShowNewSim(false)} onStart={startSimulation} />

      {/* ─── Header ──────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-30 border-b border-white/5 bg-[#02070E]/90 backdrop-blur-xl">
        <div className="flex flex-col gap-3 p-3 lg:flex-row lg:items-center lg:justify-between lg:p-4">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-gold/30 bg-gold/10 shadow-[0_0_24px_rgba(251,191,36,0.15)]">
                <FlaskConical className="h-5 w-5 text-gold" />
              </div>
              <div>
                <h1 className="text-xl font-black tracking-tight text-white lg:text-2xl">Migration Sandbox</h1>
                <p className="text-[11px] font-medium text-white/40">Post-Quantum Cryptographic Migration Operations Center</p>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={refresh}
              className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-[11px] font-bold text-white/60 transition hover:border-gold/30 hover:text-gold">
              <span className={cn('h-2 w-2 rounded-full', sseActive ? 'bg-emerald-400 shadow-[0_0_10px_rgba(34,197,94,0.8)] animate-pulse' : 'bg-slate-500')} />
              {sseActive ? 'Live' : 'Offline'}
            </button>
            <ActionBtn icon={Download} label="Export" onClick={() => exportReport('json')} />
            <ActionBtn icon={Upload} label="CSV" onClick={() => exportReport('csv')} />
            <ActionBtn icon={Plus} label="New Simulation" onClick={() => setShowNewSim(true)} variant="gold" />

            <div className="hidden items-center gap-2 pl-2 xl:flex">
              <Clock3 className="h-4 w-4 text-gold/60" />
              <div className="font-mono text-[10px] text-white/35">
                <div>{generated.toLocaleTimeString('en-US', { hour12: false })}</div>
                <div>{generated.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })}</div>
              </div>
            </div>
          </div>
        </div>

        {/* ─── Tab Navigation ─────────────────────────────────────────────── */}
        <div className="flex gap-1 overflow-x-auto px-3 pb-1 lg:px-4">
          {tabs.map((t) => {
            const Icon = t.icon
            return (
              <button key={t.key} type="button" onClick={() => setTab(t.key)}
                className={cn('flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-2 text-[11px] font-bold transition',
                  tab === t.key ? 'bg-gold/12 text-gold border border-gold/25' : 'text-white/40 hover:bg-white/5 hover:text-white/70 border border-transparent')}>
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </button>
            )
          })}
        </div>
      </header>

      <div className="space-y-4 p-3 lg:p-4">

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: OVERVIEW
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'overview' && (
          <>
            {/* ─── Hero Metrics ────────────────────────────────────────────── */}
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-8">
              <MetricTile label="Simulations" value={fmt(s.totalSimulations)} detail={`${s.running} running`} icon={FlaskConical} color={GOLD} />
              <MetricTile label="Running" value={fmt(s.running)} detail="Active now" icon={Activity} color={GREEN} />
              <MetricTile label="Completed" value={fmt(s.completed)} detail={`${s.completionRate}% rate`} icon={CheckCircle2} color={GREEN} />
              <MetricTile label="Failed" value={fmt(s.failed)} icon={X} color={RED} detail={s.failed > 0 ? 'Needs attention' : 'None'} />
              <MetricTile label="PQC Readiness" value={pct(s.pqcReadiness)} icon={Shield} color={s.pqcReadiness >= 70 ? GREEN : GOLD} detail={s.pqcReadiness >= 80 ? 'Strong' : 'In Progress'} />
              <MetricTile label="Risk Score" value={`${s.riskScore}`} icon={Target} color={s.riskScore >= 70 ? GREEN : s.riskScore >= 40 ? GOLD : RED} detail={s.riskScore >= 70 ? 'Healthy' : 'At Risk'} />
              <MetricTile label="Compliance" value={pct(data.complianceScore)} icon={ShieldCheck} color={data.complianceScore >= 70 ? GREEN : GOLD} detail={data.complianceScore >= 80 ? 'Compliant' : 'Review Needed'} />
              <MetricTile label="Total Assets" value={fmt(s.totalAssets)} detail={`${s.vulnerableAssets} vulnerable`} icon={Server} color={BLUE} />
            </div>

            {/* ─── Workflow + Score Gauges ──────────────────────────────────── */}
            <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
              <Panel className="p-5">
                <SectionHead icon={Layers}>Migration Workflow Pipeline</SectionHead>
                <WorkflowTimeline phases={data.workflowPhases} />
              </Panel>

              <Panel className="p-5">
                <SectionHead icon={BarChart3}>Readiness Scores</SectionHead>
                <div className="grid grid-cols-3 gap-2">
                  <div className="relative flex justify-center py-2">
                    <ScoreGauge value={s.pqcReadiness} size={100} label="PQC Ready" />
                  </div>
                  <div className="relative flex justify-center py-2">
                    <ScoreGauge value={s.riskScore} size={100} label="Risk Score" />
                  </div>
                  <div className="relative flex justify-center py-2">
                    <ScoreGauge value={data.complianceScore} size={100} label="Compliance" />
                  </div>
                </div>

                <div className="mt-4 space-y-2">
                  <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">Quick Risk Summary</div>
                  {[
                    { label: 'Critical Exposures', value: s.criticalExposures, color: RED },
                    { label: 'High Exposures', value: s.highExposures, color: ORANGE },
                    { label: 'Expiring Certificates', value: s.expiringCerts, color: GOLD },
                    { label: 'Open Vulnerabilities', value: s.openVulnerabilities, color: ORANGE },
                  ].map((r) => (
                    <div key={r.label} className="flex items-center justify-between text-xs">
                      <span className="text-white/50">{r.label}</span>
                      <span className="font-mono font-bold" style={{ color: r.value > 0 ? r.color : GREEN }}>{fmt(r.value)}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>

            {/* ─── Active Sims Quick View + Recommendations ────────────────── */}
            <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
              <Panel className="p-5">
                <SectionHead icon={FlaskConical} suffix={
                  <div className="flex gap-2">
                    {s.running > 0 && <ActionBtn icon={Pause} label="Pause All" onClick={() => doBulkAction('pause')} variant="default" small />}
                    {s.paused > 0 && <ActionBtn icon={Play} label="Resume All" onClick={() => doBulkAction('resume')} variant="success" small />}
                  </div>
                }>Active Simulations</SectionHead>
                {data.simulations.length === 0 ? (
                  <EmptyBlock label="No simulations yet. Click 'New Simulation' to start your first PQC migration test." />
                ) : (
                  <div className="space-y-2">
                    {data.simulations.slice(0, 5).map((sim) => (
                      <SimulationRow key={sim.id} sim={sim} onAction={doAction} />
                    ))}
                    {data.simulations.length > 5 && (
                      <button type="button" onClick={() => setTab('simulations')} className="w-full rounded-lg border border-white/8 py-2 text-center text-[11px] font-bold text-gold hover:bg-gold/5">
                        View all {data.simulations.length} simulations →
                      </button>
                    )}
                  </div>
                )}
              </Panel>

              <Panel className="p-5">
                <SectionHead icon={Bot}>AI Migration Insights</SectionHead>
                {data.recommendations.length === 0 ? (
                  <EmptyBlock label="No recommendations available. Run scans and simulations to generate AI-powered insights." />
                ) : (
                  <div className="space-y-3">
                    {data.recommendations.slice(0, 4).map((rec) => (
                      <div key={rec.id} className="rounded-lg border border-white/6 bg-white/[0.015] p-3">
                        <div className="flex items-start gap-2">
                          <div className={cn('mt-0.5 flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-black',
                            rec.priority === 1 ? 'bg-red-500/20 text-red-300' : rec.priority === 2 ? 'bg-amber-500/20 text-amber-300' : 'bg-sky-500/20 text-sky-300')}>
                            {rec.priority}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="text-xs font-bold text-white/85">{rec.title}</div>
                            <div className="mt-1 text-[11px] leading-relaxed text-white/40">{rec.description}</div>
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              <Pill className="border-purple-500/25 bg-purple-500/10 text-purple-300">{rec.algorithm}</Pill>
                              <Pill className="border-sky-500/25 bg-sky-500/10 text-sky-300">{rec.effort} effort</Pill>
                              <Pill className="border-white/10 bg-white/5 text-white/40">{rec.timeEstimate}</Pill>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                    {data.recommendations.length > 4 && (
                      <button type="button" onClick={() => setTab('recommendations')} className="w-full rounded-lg border border-white/5 py-2 text-[11px] font-bold text-gold hover:bg-gold/5">
                        View all recommendations →
                      </button>
                    )}
                  </div>
                )}
              </Panel>
            </div>

            {/* ─── Recent Logs ─────────────────────────────────────────────── */}
            <Panel className="p-5">
              <SectionHead icon={Terminal} suffix={<button type="button" onClick={() => setTab('logs')} className="text-[10px] font-bold text-gold hover:text-amber-300">View All Logs</button>}>
                Real-Time Execution Logs
              </SectionHead>
              {data.recentLogs.length === 0 ? (
                <EmptyBlock label="No execution logs yet. Logs will appear here when simulations are running." />
              ) : (
                <div className="space-y-1 max-h-[240px] overflow-y-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-white/10">
                  {data.recentLogs.slice(0, 15).map((log) => (
                    <div key={log.id} className="flex items-center gap-2.5 rounded px-2.5 py-1.5 text-[11px] hover:bg-white/[0.03]">
                      {severityIcon(log.severity)}
                      <span className="font-mono text-[9px] text-white/25 w-16 shrink-0">{timeStr(log.timestamp)}</span>
                      <Pill className={cn('shrink-0',
                        log.severity === 'critical' || log.severity === 'error' ? 'border-red-500/25 bg-red-500/10 text-red-300' :
                        log.severity === 'warning' ? 'border-amber-500/25 bg-amber-500/10 text-amber-300' :
                        'border-white/10 bg-white/5 text-white/40'
                      )}>{log.type}</Pill>
                      <span className="flex-1 truncate text-white/55">{log.message}</span>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          </>
        )}

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: SIMULATIONS
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'simulations' && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <h2 className="text-lg font-black text-white">All Simulations</h2>
                <Pill className="border-gold/25 bg-gold/10 text-gold">{fmt(s.totalSimulations)} total</Pill>
              </div>
              <div className="flex items-center gap-2">
                {s.running > 0 && <ActionBtn icon={Pause} label="Pause All" onClick={() => doBulkAction('pause')} small />}
                {s.paused > 0 && <ActionBtn icon={Play} label="Resume All" onClick={() => doBulkAction('resume')} variant="success" small />}
                {s.failed > 0 && <ActionBtn icon={RefreshCw} label="Retry Failed" onClick={() => doBulkAction('retry')} variant="gold" small />}
                <ActionBtn icon={Plus} label="New Simulation" onClick={() => setShowNewSim(true)} variant="gold" />
              </div>
            </div>

            {data.simulations.length === 0 ? (
              <Panel className="p-8">
                <EmptyBlock label="No migration simulations found. Start a new simulation to safely test PQC migration workflows." />
              </Panel>
            ) : (
              <Panel className="p-5">
                <div className="space-y-2">
                  {data.simulations.map((sim) => (
                    <SimulationRow key={sim.id} sim={sim} onAction={doAction} />
                  ))}
                </div>
              </Panel>
            )}
          </>
        )}

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: RISK ANALYSIS
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'risk' && (
          <>
            <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
              <Panel className="p-5">
                <SectionHead icon={Target}>Risk Overview</SectionHead>
                <div className="relative flex justify-center py-4">
                  <ScoreGauge value={s.riskScore} size={160} label="Migration Risk Score" />
                </div>
                <div className="mt-4 rounded-lg border border-white/8 bg-white/[0.02] p-3 text-center">
                  <span className={cn('text-sm font-black',
                    s.riskScore >= 80 ? 'text-emerald-300' : s.riskScore >= 50 ? 'text-amber-300' : 'text-red-300')}>
                    {s.riskScore >= 80 ? 'Low Risk — Ready for Production' : s.riskScore >= 50 ? 'Moderate Risk — Continue Mitigation' : 'High Risk — Critical Action Needed'}
                  </span>
                </div>
              </Panel>

              <Panel className="p-5">
                <SectionHead icon={BarChart3}>Risk Factors & Impact Analysis</SectionHead>
                {data.riskFactors.length === 0 ? (
                  <EmptyBlock label="No risk factors detected. Run discovery scans to identify quantum-vulnerable assets." />
                ) : (
                  <div className="space-y-3">
                    {data.riskFactors.map((rf) => (
                      <div key={rf.label} className="flex items-center gap-3 rounded-lg border border-white/6 bg-white/[0.015] p-3">
                        <div className={cn('flex h-8 w-8 items-center justify-center rounded-lg border',
                          rf.severity === 'critical' ? 'border-red-500/30 bg-red-500/10' : rf.severity === 'high' ? 'border-orange-500/30 bg-orange-500/10' : 'border-amber-500/30 bg-amber-500/10')}>
                          <AlertTriangle className={cn('h-4 w-4', rf.severity === 'critical' ? 'text-red-400' : rf.severity === 'high' ? 'text-orange-400' : 'text-amber-400')} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-bold text-white/80">{rf.label}</div>
                          <div className="mt-0.5 flex items-center gap-2">
                            <Pill className={riskBadge(rf.severity)}>{rf.severity}</Pill>
                            <span className="text-[10px] text-white/35">Impact: {rf.impact}</span>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="font-mono text-2xl font-black" style={{ color: rf.severity === 'critical' ? RED : rf.severity === 'high' ? ORANGE : GOLD }}>{fmt(rf.count)}</div>
                          <div className="text-[9px] font-bold text-white/30">DETECTED</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <div className="mt-5 grid gap-3 sm:grid-cols-3">
                  <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3 text-center">
                    <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">Downtime Probability</div>
                    <div className="mt-1 font-mono text-xl font-black" style={{ color: s.failed > 2 ? RED : s.failed > 0 ? GOLD : GREEN }}>
                      {s.failed > 2 ? 'High' : s.failed > 0 ? 'Medium' : 'Low'}
                    </div>
                  </div>
                  <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3 text-center">
                    <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">Crypto Agility</div>
                    <div className="mt-1 font-mono text-xl font-black" style={{ color: s.pqcReadiness >= 70 ? GREEN : GOLD }}>
                      {pct(s.pqcReadiness)}
                    </div>
                  </div>
                  <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3 text-center">
                    <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">HNDL Exposure</div>
                    <div className="mt-1 font-mono text-xl font-black" style={{ color: s.criticalExposures > 0 ? RED : GREEN }}>
                      {s.criticalExposures > 0 ? 'Active' : 'Mitigated'}
                    </div>
                  </div>
                </div>
              </Panel>
            </div>
          </>
        )}

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: ROLLBACK CENTER
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'rollback' && (
          <>
            <Panel className="p-5">
              <SectionHead icon={RotateCcw}>Rollback & Recovery Control Center</SectionHead>
              <p className="mb-4 text-xs text-white/40">Safely revert cryptographic migrations, restore snapshots, and execute emergency recovery procedures.</p>

              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {[
                  { label: 'Restore Previous Keys', icon: Key, desc: 'Revert to classical key pairs', action: 'rollback' },
                  { label: 'Revert Certificates', icon: Lock, desc: 'Restore original certificate chain', action: 'rollback' },
                  { label: 'Restore TLS Config', icon: Globe2, desc: 'Reset TLS to pre-migration state', action: 'rollback' },
                  { label: 'Emergency Recovery', icon: ShieldAlert, desc: 'Full environment restore', action: 'rollback' },
                ].map((item) => {
                  const Icon = item.icon
                  return (
                    <button key={item.label} type="button" onClick={() => doBulkAction(item.action)}
                      className="flex flex-col items-center gap-3 rounded-xl border border-red-500/15 bg-red-500/[0.03] p-5 text-center transition hover:border-red-500/30 hover:bg-red-500/[0.06]">
                      <div className="flex h-12 w-12 items-center justify-center rounded-full border border-red-500/25 bg-red-500/10">
                        <Icon className="h-6 w-6 text-red-300" />
                      </div>
                      <div className="text-sm font-bold text-white/80">{item.label}</div>
                      <div className="text-[11px] text-white/35">{item.desc}</div>
                    </button>
                  )
                })}
              </div>
            </Panel>

            <Panel className="p-5">
              <SectionHead icon={History}>Rollback-Eligible Simulations</SectionHead>
              {data.simulations.filter((s) => s.status === 'completed' || s.status === 'running' || s.status === 'paused').length === 0 ? (
                <EmptyBlock label="No simulations are currently eligible for rollback." />
              ) : (
                <div className="space-y-2">
                  {data.simulations.filter((s) => ['completed', 'running', 'paused'].includes(s.status)).map((sim) => (
                    <div key={sim.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/6 bg-white/[0.015] px-4 py-3">
                      <div className="min-w-0">
                        <div className="text-sm font-bold text-white/80 truncate">{sim.name}</div>
                        <div className="text-[11px] text-white/35">{sim.fromAlgo} → {sim.toAlgo} · {sim.environment}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Pill className={cn(statusColor(sim.status).bg, statusColor(sim.status).border, statusColor(sim.status).text)}>{sim.status}</Pill>
                        <ActionBtn icon={RotateCcw} label="Rollback" onClick={() => doAction(sim.id, 'rollback')} variant="danger" small />
                        <ActionBtn icon={Save} label="Snapshot" onClick={() => doAction(sim.id, 'snapshot')} small />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          </>
        )}

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: COMPLIANCE
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'compliance' && (
          <>
            <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
              <Panel className="p-5">
                <SectionHead icon={ShieldCheck}>Compliance Score</SectionHead>
                <div className="relative flex justify-center py-4">
                  <ScoreGauge value={data.complianceScore} size={160} label="Overall Compliance" />
                </div>
              </Panel>

              <Panel className="p-5">
                <SectionHead icon={BookOpen}>Governance Validation</SectionHead>
                <div className="space-y-2">
                  {data.complianceItems.map((ci) => (
                    <div key={ci.framework + ci.control} className="flex items-center justify-between gap-3 rounded-lg border border-white/6 bg-white/[0.015] px-4 py-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-bold text-white/80">{ci.framework}</span>
                          <Pill className={cn(
                            ci.status === 'compliant' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' :
                            ci.status === 'partial' ? 'border-amber-500/30 bg-amber-500/10 text-amber-300' :
                            ci.status === 'pending' ? 'border-sky-500/25 bg-sky-500/10 text-sky-300' :
                            'border-red-500/30 bg-red-500/10 text-red-300'
                          )}>{ci.status}</Pill>
                        </div>
                        <div className="mt-0.5 text-[11px] text-white/35">{ci.control}</div>
                      </div>
                      <div className="text-right">
                        <div className="font-mono text-lg font-black" style={{ color: ci.score >= 80 ? GREEN : ci.score >= 50 ? GOLD : RED }}>{ci.score}</div>
                        <div className="text-[9px] font-bold text-white/25">SCORE</div>
                      </div>
                      <div className="w-20">
                        <ProgressBar value={ci.score} color={ci.score >= 80 ? GREEN : ci.score >= 50 ? GOLD : RED} />
                      </div>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>

            <Panel className="p-5">
              <SectionHead icon={FileText}>Available Reports</SectionHead>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {[
                  { label: 'Audit Report', desc: 'Full migration audit trail', format: 'json' as const },
                  { label: 'Risk Assessment', desc: 'Quantum vulnerability report', format: 'json' as const },
                  { label: 'Executive Summary', desc: 'Leadership readiness brief', format: 'json' as const },
                  { label: 'Compliance Evidence', desc: 'Evidence package export', format: 'csv' as const },
                ].map((report) => (
                  <button key={report.label} type="button" onClick={() => exportReport(report.format)}
                    className="flex items-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-4 text-left transition hover:border-gold/25 hover:bg-gold/[0.03]">
                    <FileText className="h-8 w-8 text-gold/60 shrink-0" />
                    <div>
                      <div className="text-sm font-bold text-white/80">{report.label}</div>
                      <div className="text-[11px] text-white/35">{report.desc}</div>
                    </div>
                  </button>
                ))}
              </div>
            </Panel>
          </>
        )}

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: AI RECOMMENDATIONS
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'recommendations' && (
          <Panel className="p-5">
            <SectionHead icon={Bot}>AI-Assisted Migration Recommendations</SectionHead>
            <p className="mb-4 text-xs text-white/40">Intelligent recommendations based on your asset inventory, scan findings, migration history, and compliance posture.</p>
            {data.recommendations.length === 0 ? (
              <EmptyBlock label="No recommendations available. Run scans and simulations to generate AI-powered migration insights." />
            ) : (
              <div className="space-y-3">
                {data.recommendations.map((rec) => (
                  <div key={rec.id} className={cn('rounded-xl border p-4',
                    rec.priority === 1 ? 'border-red-500/20 bg-red-500/[0.025]' :
                    rec.priority === 2 ? 'border-amber-500/20 bg-amber-500/[0.025]' :
                    'border-white/8 bg-white/[0.015]')}>
                    <div className="flex items-start gap-3">
                      <div className={cn('flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border text-sm font-black',
                        rec.priority === 1 ? 'border-red-500/40 bg-red-500/15 text-red-300' :
                        rec.priority === 2 ? 'border-amber-500/40 bg-amber-500/15 text-amber-300' :
                        'border-sky-500/40 bg-sky-500/15 text-sky-300')}>
                        P{rec.priority}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-bold text-white/90">{rec.title}</div>
                        <div className="mt-1.5 text-xs leading-relaxed text-white/45">{rec.description}</div>
                        <div className="mt-3 flex flex-wrap gap-2">
                          <Pill className="border-purple-500/25 bg-purple-500/10 text-purple-300"><Key className="mr-1 h-3 w-3 inline" />{rec.algorithm}</Pill>
                          <Pill className="border-sky-500/25 bg-sky-500/10 text-sky-300">{rec.effort} effort</Pill>
                          <Pill className="border-emerald-500/25 bg-emerald-500/10 text-emerald-300"><Clock3 className="mr-1 h-3 w-3 inline" />{rec.timeEstimate}</Pill>
                          {rec.compliance.map((c) => (
                            <Pill key={c} className="border-white/10 bg-white/5 text-white/40">{c}</Pill>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        )}

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: EXECUTION LOGS
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'logs' && (
          <Panel className="p-5">
            <SectionHead icon={Terminal} suffix={
              <div className="flex items-center gap-2">
                <input
                  value={logFilter}
                  onChange={(e) => setLogFilter(e.target.value)}
                  placeholder="Filter logs…"
                  className="w-48 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-white outline-none placeholder:text-white/25 focus:border-gold/40"
                />
                <span className="font-mono text-[10px] text-white/25">{filteredLogs.length} entries</span>
              </div>
            }>Real-Time Execution Logs</SectionHead>

            {filteredLogs.length === 0 ? (
              <EmptyBlock label="No execution logs available. Logs populate in real-time as simulations execute." />
            ) : (
              <div className="space-y-0.5 max-h-[600px] overflow-y-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-white/10">
                {filteredLogs.map((log) => (
                  <div key={log.id} className="flex items-center gap-2.5 rounded px-3 py-2 text-[11px] hover:bg-white/[0.03] transition">
                    {severityIcon(log.severity)}
                    <span className="font-mono text-[9px] text-white/20 w-16 shrink-0">{timeStr(log.timestamp)}</span>
                    <Pill className={cn('shrink-0 min-w-[70px] text-center',
                      log.severity === 'critical' || log.severity === 'error' ? 'border-red-500/25 bg-red-500/10 text-red-300' :
                      log.severity === 'warning' || log.severity === 'high' ? 'border-amber-500/25 bg-amber-500/10 text-amber-300' :
                      'border-white/10 bg-white/5 text-white/40'
                    )}>{log.severity}</Pill>
                    <Pill className="shrink-0 border-white/8 bg-white/[0.03] text-white/30">{log.type}</Pill>
                    <span className="flex-1 text-white/55 truncate">{log.message}</span>
                    <span className="hidden font-mono text-[9px] text-white/15 lg:block">{log.jobId?.slice(0, 8)}</span>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        )}

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: PQC STACK
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'pqc-stack' && (
          <>
            <Panel className="p-5">
              <SectionHead icon={Key}>Recommended PQC Algorithm Stack</SectionHead>
              <p className="mb-4 text-xs text-white/40">Production-grade NIST-approved post-quantum cryptographic standards supported in this sandbox environment.</p>

              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {data.pqcStack.map((item) => (
                  <div key={item.name} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="text-sm font-bold text-white/90">{item.name}</div>
                        <div className="mt-0.5 text-[11px] text-white/35">{item.standard}</div>
                      </div>
                      <Pill className={cn(
                        item.status === 'active' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' :
                        'border-sky-500/25 bg-sky-500/10 text-sky-300'
                      )}>{item.status}</Pill>
                    </div>
                    <div className="mt-3 flex items-center justify-between text-xs">
                      <span className="text-white/40">Active Deployments</span>
                      <span className="font-mono font-bold text-white/70">{fmt(item.usage)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel className="p-5">
              <SectionHead icon={Zap}>Supported Migration Types</SectionHead>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {[
                  'RSA → ML-KEM migration',
                  'ECC → ML-DSA transition',
                  'Hybrid cryptography deployment',
                  'TLS certificate replacement',
                  'VPN tunnel migration',
                  'API encryption migration',
                  'Secure messaging validation',
                  'Database encryption re-keying',
                  'Key rotation simulation',
                  'HSM migration validation',
                  'Certificate chain replacement',
                  'Crypto agility workflows',
                ].map((item) => (
                  <div key={item} className="flex items-center gap-2 rounded-lg border border-white/5 bg-white/[0.015] px-3 py-2.5">
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                    <span className="text-xs font-semibold text-white/60">{item}</span>
                  </div>
                ))}
              </div>
            </Panel>
          </>
        )}
      </div>

      {/* ─── Footer ────────────────────────────────────────────────────── */}
      <footer className="border-t border-white/5 px-4 py-3">
        <div className="flex flex-col gap-2 text-[10px] font-mono uppercase tracking-wider text-white/25 md:flex-row md:items-center md:justify-between">
          <span>{error ? `⚠ ${error}` : 'Sandbox telemetry synchronized'}</span>
          <span>
            SSE: {sseActive ? <span className="text-emerald-400">connected</span> : <span className="text-red-400">standby</span>}
            {' · '}
            Snapshot: {relTime(data.generatedAt)}
            {' · '}
            NIST SP 800-208 | FIPS 203/204/205
          </span>
        </div>
      </footer>
    </main>
  )
}
