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
  Trash2,
  Upload,
  X,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'
import { clearMigrationHandoff, readMigrationHandoff, type MigrationHandoff } from '@/app/dashboard/quantum-readiness/_advisor'

/* ═══════════════════════════════════════════════════════════════════════════
   TYPES
   ═══════════════════════════════════════════════════════════════════════════ */

type SimulationStatus = 'running' | 'completed' | 'failed' | 'queued' | 'paused' | 'rollback_requested' | 'rolled_back' | 'stopped'

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
  runMode: string
  runModeLabel: string
  isSandbox: boolean
  isActualMigration: boolean
  executionScope: string
  engineStatus: string
  queuedReason: string | null
  eta: string
  status: SimulationStatus
  progress: number
  riskLevel: string
  phase: string
  phaseId: string
  phaseDetail: string
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
  count?: number
  running?: number
  queued?: number
  blocked?: number
  source?: string
  updatedAt?: string | null
}

type PqcStackItem = {
  name: string
  standard: string
  status: string
  usage: number
}

type SimulationHistoryRow = {
  id: string
  name: string
  sourceAlgorithm: string
  targetAlgorithm: string
  assetName: string
  assetType: string
  assets: number
  riskScore: number
  complianceScore: number
  status: SimulationStatus
  durationMs: number
  duration: string
  createdAt: string
  startedAt: string | null
  completedAt: string | null
  updatedAt: string
  riskLevel: string
  runMode: string
  runModeLabel: string
  owner: string
  environment: string
  snapshots: number
  eventCount: number
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
  totalWorkflows: number
  actualMigrations: number
  remediationWorkflows: number
  runningWorkflows: number
  completedWorkflows: number
  failedWorkflows: number
  queuedWorkflows: number
  pausedWorkflows: number
  blockedWorkflows: number
  averageWorkflowProgress: number
  backgroundEngine: string
  lastMigrationEventAt: string | null
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
  workflowCompletionRate: number
}

type SandboxSnapshot = {
  generatedAt: string
  summary: SandboxSummary
  simulations: Simulation[]
  history: SimulationHistoryRow[]
  workflows: Simulation[]
  riskFactors: RiskFactor[]
  recommendations: Recommendation[]
  complianceItems: ComplianceItem[]
  complianceScore: number
  workflowPhases: WorkflowPhase[]
  pqcStack: PqcStackItem[]
  recentLogs: LogEntry[]
}

type OperatorNotice = {
  kind: 'success' | 'error' | 'info'
  message: string
}

type ActiveTab = 'overview' | 'simulations' | 'history' | 'risk' | 'rollback' | 'compliance' | 'logs' | 'recommendations' | 'pqc-stack'
type SandboxActionHandler = (id: string, action: string, options?: Record<string, unknown>) => void | Promise<void>
type TerminalLineLevel = 'command' | 'telemetry' | 'event' | 'nist' | 'success' | 'warning' | 'error'
type TerminalLine = {
  id: string
  timestamp: string
  level: TerminalLineLevel
  prompt: string
  command: string
  detail?: string
}

const EMPTY: SandboxSnapshot = {
  generatedAt: new Date().toISOString(),
  summary: { totalSimulations: 0, running: 0, completed: 0, failed: 0, queued: 0, paused: 0, totalWorkflows: 0, actualMigrations: 0, remediationWorkflows: 0, runningWorkflows: 0, completedWorkflows: 0, failedWorkflows: 0, queuedWorkflows: 0, pausedWorkflows: 0, blockedWorkflows: 0, averageWorkflowProgress: 0, backgroundEngine: 'idle', lastMigrationEventAt: null, totalAssets: 0, vulnerableAssets: 0, criticalExposures: 0, highExposures: 0, openVulnerabilities: 0, pqcReadiness: 0, riskScore: 100, complianceScore: 0, expiringCerts: 0, lastScanAt: null, completionRate: 0, workflowCompletionRate: 0 },
  simulations: [],
  history: [],
  workflows: [],
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
  'migration-sandbox-panel group relative overflow-hidden rounded-xl border border-gold/15 bg-[#060F1C]/80 backdrop-blur-2xl shadow-[inset_0_1px_0_rgba(255,255,255,0.06),0_0_30px_rgba(0,0,0,0.3)] transition-all duration-500 hover:border-gold/40 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.12),0_8px_32px_rgba(0,0,0,0.4),0_0_48px_rgba(251,191,36,0.08)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/50 before:to-transparent'

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
  if (s === 'rollback_requested') return { bg: 'bg-orange-500/12', border: 'border-orange-500/30', text: 'text-orange-300', dot: 'bg-orange-400' }
  if (s === 'rolled_back') return { bg: 'bg-purple-500/12', border: 'border-purple-500/30', text: 'text-purple-300', dot: 'bg-purple-400' }
  if (s === 'stopped') return { bg: 'bg-slate-500/12', border: 'border-slate-500/30', text: 'text-slate-300', dot: 'bg-slate-400' }
  if (s === 'paused') return { bg: 'bg-amber-500/12', border: 'border-amber-500/30', text: 'text-amber-300', dot: 'bg-amber-400' }
  return { bg: 'bg-sky-500/10', border: 'border-sky-500/25', text: 'text-sky-300', dot: 'bg-sky-400' }
}

function modeBadge(mode: string) {
  if (mode === 'dry_run') return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
  if (mode === 'simulation') return 'border-purple-500/30 bg-purple-500/10 text-purple-300'
  if (mode === 'remediation') return 'border-red-500/25 bg-red-500/10 text-red-300'
  if (mode === 'actual_migration') return 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300'
  return 'border-white/10 bg-white/5 text-white/45'
}

function modeLabel(sim: Simulation) {
  return sim.runModeLabel || sim.runMode?.replace(/_/g, ' ') || 'Workflow'
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

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function progressBarColor(v: number, status: string) {
  if (status === 'failed') return RED
  if (status === 'completed') return GREEN
  if (v >= 70) return GREEN
  if (v >= 40) return GOLD
  return ORANGE
}

function canDeleteSimulationStatus(status: string) {
  return ['completed', 'failed', 'stopped', 'rolled_back'].includes(status)
}

function historyDuration(start: string | null, end: string | null, fallback: string | null) {
  const started = start ? new Date(start).getTime() : 0
  const finished = end ? new Date(end).getTime() : fallback ? new Date(fallback).getTime() : 0
  if (!started || !finished || !Number.isFinite(started) || !Number.isFinite(finished) || finished < started) {
    return { durationMs: 0, duration: '--' }
  }
  const ms = finished - started
  const minutes = Math.floor(ms / 60000)
  const seconds = Math.max(0, Math.round((ms % 60000) / 1000))
  if (minutes >= 60) return { durationMs: ms, duration: `${Math.floor(minutes / 60)}h ${minutes % 60}m` }
  if (minutes > 0) return { durationMs: ms, duration: `${minutes}m ${seconds}s` }
  return { durationMs: ms, duration: `${seconds}s` }
}

function historyRiskScore(sim: Simulation) {
  const riskPenalty = sim.riskLevel === 'critical' ? 35 : sim.riskLevel === 'high' ? 25 : sim.riskLevel === 'medium' ? 12 : 4
  const statusPenalty = sim.status === 'failed' ? 25 : sim.status === 'rolled_back' ? 15 : 0
  return Math.max(0, Math.min(100, Math.round(100 - riskPenalty - statusPenalty + sim.progress * 0.35)))
}

function deriveHistory(simulations: Simulation[], complianceScore = 0): SimulationHistoryRow[] {
  return simulations.map((sim) => {
    const duration = historyDuration(sim.startedAt || sim.createdAt, sim.completedAt, sim.updatedAt)
    return {
      id: sim.id,
      name: sim.name,
      sourceAlgorithm: sim.fromAlgo,
      targetAlgorithm: sim.toAlgo,
      assetName: sim.assetName,
      assetType: sim.assetType,
      assets: sim.assetName && sim.assetName !== 'Unknown Asset' ? 1 : 0,
      riskScore: historyRiskScore(sim),
      complianceScore: Math.max(0, Math.min(100, Math.round((complianceScore + (sim.status === 'completed' ? 100 : sim.progress || 0)) / 2))),
      status: sim.status,
      durationMs: duration.durationMs,
      duration: duration.duration,
      createdAt: sim.createdAt,
      startedAt: sim.startedAt,
      completedAt: sim.completedAt,
      updatedAt: sim.updatedAt,
      riskLevel: sim.riskLevel,
      runMode: sim.runMode,
      runModeLabel: sim.runModeLabel,
      owner: sim.owner,
      environment: sim.environment,
      snapshots: Array.isArray(sim.metadata?.snapshots) ? sim.metadata.snapshots.length : 0,
      eventCount: sim.eventCount,
    }
  })
}

function downloadJson(filename: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function historyDateMatches(value: string, range: string) {
  if (range === 'all') return true
  const ms = new Date(value).getTime()
  if (!Number.isFinite(ms)) return false
  const days = range === '24h' ? 1 : range === '7d' ? 7 : range === '30d' ? 30 : 90
  return Date.now() - ms <= days * 24 * 60 * 60 * 1000
}

function quoteArg(value: unknown) {
  const text = String(value ?? '').trim() || 'unknown'
  return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

function nistStandardsForAlgorithm(algorithm: string) {
  const normalized = String(algorithm || '').toLowerCase()
  const standards: string[] = []
  if (/ml-kem|kyber|kem/.test(normalized)) standards.push('NIST FIPS 203 (ML-KEM)')
  if (/ml-dsa|dilithium/.test(normalized)) standards.push('NIST FIPS 204 (ML-DSA)')
  if (/slh-dsa|sphincs/.test(normalized)) standards.push('NIST FIPS 205 (SLH-DSA)')
  if (/aes-?256/.test(normalized)) standards.push('NIST FIPS 197 (AES-256)')
  if (/sha-?3|shake/.test(normalized)) standards.push('NIST FIPS 202 (SHA-3/SHAKE)')
  return standards.length ? standards.join(' + ') : 'NIST PQC target pending'
}

function sourceRiskStandard(sourceAlgorithm: string) {
  const normalized = String(sourceAlgorithm || '').toLowerCase()
  if (/rsa|ecdsa|ecdh|diffie|dh|ed25519|x25519/.test(normalized)) {
    return 'quantum-vulnerable public-key source; transition tracked against NIST PQC migration guidance'
  }
  if (/aes|sha-?3|shake/.test(normalized)) return 'symmetric/hash primitive reviewed for quantum security posture'
  return 'source inventory normalized from tenant crypto evidence'
}

function phaseCommandForSimulation(sim: Simulation, planId: string) {
  const phase = String(sim.phaseId || sim.phase || '').toLowerCase()
  if (sim.status === 'queued') {
    return `qguard-sandbox queue inspect --plan ${quoteArg(planId)} --job ${quoteArg(sim.id)} --engine ${quoteArg(sim.engineStatus)}`
  }
  if (sim.status === 'failed') {
    return `qguard-sandbox triage --job ${quoteArg(sim.id)} --status "failed" --evidence "migration_events"`
  }
  if (sim.status === 'rollback_requested' || sim.status === 'rolled_back' || phase.includes('rollback')) {
    return `qguard-sandbox rollback verify --plan ${quoteArg(planId)} --job ${quoteArg(sim.id)} --checkpoint "latest"`
  }
  if (phase.includes('preparation')) {
    return `qguard-sandbox snapshot create --job ${quoteArg(sim.id)} --asset ${quoteArg(sim.assetName)} --rollback-checkpoint`
  }
  if (phase.includes('assessment')) {
    return `qguard-pqc assess --job ${quoteArg(sim.id)} --source ${quoteArg(sim.fromAlgo)} --target ${quoteArg(sim.toAlgo)} --nist "FIPS-203,FIPS-204,FIPS-205"`
  }
  if (phase.includes('verification')) {
    return `qguard-pqc verify --job ${quoteArg(sim.id)} --handshake --certificate-chain --target ${quoteArg(sim.toAlgo)}`
  }
  if (phase.includes('finalization') || sim.status === 'completed') {
    return `qguard-evidence collect --plan ${quoteArg(planId)} --job ${quoteArg(sim.id)} --format "nist-pqc-readiness"`
  }
  return `qguard-pqc simulate --job ${quoteArg(sim.id)} --mode "sandbox" --source ${quoteArg(sim.fromAlgo)} --target ${quoteArg(sim.toAlgo)}`
}

function terminalLevelClass(level: TerminalLineLevel) {
  if (level === 'command') return 'text-sky-200'
  if (level === 'telemetry') return 'text-cyan-200'
  if (level === 'event') return 'text-white/70'
  if (level === 'nist') return 'text-gold'
  if (level === 'success') return 'text-emerald-300'
  if (level === 'warning') return 'text-amber-300'
  if (level === 'error') return 'text-red-300'
  return 'text-white/70'
}

function buildHandoffTerminalLines(planId: string, simulations: Simulation[], recentLogs: LogEntry[], generatedAt: string, sseActive: boolean): TerminalLine[] {
  const lines: TerminalLine[] = [{
    id: `stream-${planId}-${generatedAt}`,
    timestamp: generatedAt,
    level: sseActive ? 'success' : 'warning',
    prompt: '$',
    command: `qguard-sandbox watch --plan ${quoteArg(planId)} --source "migration-planner" --stream ${quoteArg(sseActive ? 'sse-live' : 'reconnecting')}`,
    detail: `${fmt(simulations.length)} linked simulation(s) in authenticated tenant scope`,
  }]

  if (simulations.length === 0) {
    lines.push({
      id: `waiting-${planId}-${generatedAt}`,
      timestamp: generatedAt,
      level: 'warning',
      prompt: '>',
      command: 'awaiting planner handoff jobs from migration_jobs',
      detail: 'No sandbox simulation rows are linked to this plan yet.',
    })
    return lines
  }

  simulations.forEach((sim) => {
    const standards = nistStandardsForAlgorithm(sim.toAlgo)
    const snapshots = Array.isArray(sim.metadata?.snapshots) ? sim.metadata.snapshots as Array<Record<string, unknown>> : []
    const jobLogs = recentLogs
      .filter((log) => log.jobId === sim.id)
      .slice(-4)

    lines.push(
      {
        id: `standard-${sim.id}-${sim.toAlgo}-${sim.updatedAt}`,
        timestamp: sim.updatedAt || generatedAt,
        level: 'nist',
        prompt: 'nist',
        command: `qguard-pqc standards validate --job ${quoteArg(sim.id)} --target ${quoteArg(sim.toAlgo)} --standard ${quoteArg(standards)}`,
        detail: `source=${sim.fromAlgo || 'unknown'}; ${sourceRiskStandard(sim.fromAlgo)}`,
      },
      {
        id: `phase-${sim.id}-${sim.phaseId}-${sim.progress}-${sim.updatedAt}`,
        timestamp: sim.updatedAt || generatedAt,
        level: sim.status === 'failed' ? 'error' : sim.status === 'completed' ? 'success' : 'command',
        prompt: '$',
        command: phaseCommandForSimulation(sim, planId),
        detail: `phase=${sim.phase || sim.phaseId || 'queued'}; ${sim.phaseDetail || sim.queuedReason || sim.eta || 'live sandbox state'}`,
      },
      {
        id: `telemetry-${sim.id}-${sim.status}-${sim.progress}-${sim.updatedAt}`,
        timestamp: sim.updatedAt || generatedAt,
        level: 'telemetry',
        prompt: 'tel',
        command: `telemetry status=${sim.status} progress=${pct(sim.progress)} engine=${quoteArg(sim.engineStatus)} risk=${sim.riskLevel || 'unknown'}`,
        detail: `asset=${sim.assetName || sim.name}; env=${sim.environment}; owner=${sim.owner}; eta=${sim.eta}; events=${fmt(sim.eventCount || 0)}`,
      },
    )

    if (snapshots.length > 0) {
      const latest = snapshots[snapshots.length - 1]
      lines.push({
        id: `snapshot-${sim.id}-${String(latest?.id || snapshots.length)}-${sim.updatedAt}`,
        timestamp: String(latest?.capturedAt || latest?.createdAt || sim.updatedAt || generatedAt),
        level: 'event',
        prompt: 'snap',
        command: `rollback checkpoint ${quoteArg(latest?.id || `snapshot-${snapshots.length}`)} captured`,
        detail: `snapshot_count=${fmt(snapshots.length)}; rollback evidence retained in simulation metadata`,
      })
    }

    sim.recentEvents.slice(-4).forEach((event) => {
      const severity = String(event.severity || '').toLowerCase()
      lines.push({
        id: `event-${sim.id}-${event.id}`,
        timestamp: event.timestamp || sim.updatedAt || generatedAt,
        level: severity === 'error' || severity === 'critical' ? 'error' : severity === 'warning' ? 'warning' : 'event',
        prompt: 'evt',
        command: `${event.type || 'migration_event'}: ${event.message || 'migration event received'}`,
        detail: `job=${sim.id}; severity=${event.severity || 'info'}`,
      })
    })

    jobLogs.forEach((log) => {
      const severity = String(log.severity || '').toLowerCase()
      lines.push({
        id: `log-${sim.id}-${log.id}`,
        timestamp: log.timestamp || sim.updatedAt || generatedAt,
        level: severity === 'error' || severity === 'critical' ? 'error' : severity === 'warning' ? 'warning' : 'event',
        prompt: 'log',
        command: `${log.type || 'sandbox_log'}: ${log.message || 'telemetry event received'}`,
        detail: `source=recentLogs; severity=${log.severity || 'info'}`,
      })
    })
  })

  return Array.from(new Map(lines.map((line) => [line.id, line])).values())
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    .slice(-120)
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
  const [notice, setNotice] = useState<OperatorNotice | null>(null)
  const [pendingAction, setPendingAction] = useState<string | null>(null)
  const [sseActive, setSseActive] = useState(false)
  const esRef = useRef<EventSource | null>(null)
  const lastGeneratedAtRef = useRef(0)

  const applySnapshot = useCallback((snapshot?: SandboxSnapshot | null) => {
    if (snapshot) {
      // Snapshots arrive from three async sources (REST, SSE, action
      // responses); never let an older snapshot overwrite a newer one.
      const generatedMs = Date.parse(String(snapshot.generatedAt || '')) || Date.now()
      if (generatedMs < lastGeneratedAtRef.current) return
      lastGeneratedAtRef.current = generatedMs
      const simulations = Array.isArray(snapshot.simulations) ? snapshot.simulations : []
      setData({
        ...snapshot,
        simulations,
        history: Array.isArray(snapshot.history) ? snapshot.history : deriveHistory(simulations, snapshot.complianceScore || snapshot.summary?.complianceScore || 0),
        workflows: Array.isArray(snapshot.workflows) ? snapshot.workflows : simulations,
      })
    }
  }, [])

  const showNotice = useCallback((kind: OperatorNotice['kind'], message: string) => {
    setNotice({ kind, message })
  }, [])

  const fetchSnapshot = useCallback(async () => {
    if (!token) {
      setLoading(false)
      return
    }
    try {
      const r = await fetch('/api/v1/sandbox/snapshot', { headers: { Authorization: `Bearer ${token}` } })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(j?.error?.message || `HTTP ${r.status}`)
      // A 200 with a missing/truncated body must not wipe the dashboard to the
      // empty state — keep last-known-good data and surface the error instead.
      if (!j?.data) throw new Error('Snapshot response was empty or malformed')
      applySnapshot(j.data)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed')
    } finally {
      setLoading(false)
    }
  }, [token, applySnapshot])

  useEffect(() => {
    if (!notice) return
    const timer = setTimeout(() => setNotice(null), 5500)
    return () => clearTimeout(timer)
  }, [notice])

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
          applySnapshot(d)
        } catch { /* skip */ }
      })
    }
    connect()
    return () => { if (retry) clearTimeout(retry); esRef.current?.close(); esRef.current = null; setSseActive(false) }
  }, [token, applySnapshot])

  // Supabase realtime. Refetches are debounced: while a simulation runs, the
  // engine updates migration_jobs every couple of seconds, and refetching on
  // every event turns each write into another snapshot build (which itself
  // advances the engine and writes again) — a self-sustaining request storm.
  useEffect(() => {
    if (!user) return
    let refetchTimer: ReturnType<typeof setTimeout> | null = null
    const scheduleRefetch = () => {
      if (refetchTimer) return
      refetchTimer = setTimeout(() => {
        refetchTimer = null
        void fetchSnapshot()
      }, 1200)
    }
    const tables = [
      'migration_jobs',
      'migration_events',
      'assets',
      'crypto_exposures',
      'crypto_inventory',
      'certificates',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'vulnerabilities',
      'scanner_alerts',
      'runtime_crypto_events',
      'security_events',
      'audit_logs',
    ]
    const channels = tables.map((t) =>
      supabase.channel(`sandbox-${t}`).on('postgres_changes', { event: '*', schema: 'public', table: t, filter: `user_id=eq.${user.id}` }, scheduleRefetch).subscribe()
    )
    return () => {
      if (refetchTimer) clearTimeout(refetchTimer)
      channels.forEach((c) => supabase.removeChannel(c))
    }
  }, [user, fetchSnapshot])

  // Actions
  const doAction = useCallback(async (jobId: string, action: string, options: Record<string, unknown> = {}) => {
    if (!token) return
    const key = `${jobId}:${action}`
    setPendingAction(key)
    try {
      const response = await fetch(`/api/v1/sandbox/jobs/${jobId}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action, ...options }),
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(payload?.error?.message || `Failed to ${action} simulation`)
      applySnapshot(payload?.data?.snapshot)
      showNotice('success', `${action.replace(/_/g, ' ')} completed and synchronized.`)
      await fetchSnapshot()
    } catch (err) {
      const message = err instanceof Error ? err.message : `Unable to ${action} simulation`
      setError(message)
      showNotice('error', message)
    } finally {
      setPendingAction(null)
    }
  }, [token, fetchSnapshot, applySnapshot, showNotice])

  const doBulkAction = useCallback(async (action: string, scope: 'sandbox' | 'all' = 'sandbox') => {
    if (!token) return
    const key = scope === 'all' ? `bulk:all:${action}` : `bulk:${action}`
    setPendingAction(key)
    try {
      const response = await fetch('/api/v1/sandbox/bulk-action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action, scope }),
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(payload?.error?.message || `Failed to ${action} simulations`)
      applySnapshot(payload?.data?.snapshot)
      const affected = Number(payload?.data?.affected || 0)
      const target = scope === 'all' ? 'workflow' : 'simulation'
      showNotice(affected > 0 ? 'success' : 'info', affected > 0 ? `${action.replace(/_/g, ' ')} applied to ${affected} ${target}(s).` : `No ${target}s were eligible for ${action}.`)
      await fetchSnapshot()
    } catch (err) {
      const message = err instanceof Error ? err.message : `Unable to ${action} simulations`
      setError(message)
      showNotice('error', message)
    } finally {
      setPendingAction(null)
    }
  }, [token, fetchSnapshot, applySnapshot, showNotice])

  const startSimulation = useCallback(async (params: { fromAlgo?: string; toAlgo?: string; migrationType?: string; dryRun?: boolean; assetId?: string; assetIds?: string[] }) => {
    if (!token) return null
    setPendingAction('simulate')
    try {
      const r = await fetch('/api/v1/sandbox/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(params),
      })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(j?.error?.message || 'Failed to start simulation')
      applySnapshot(j?.data?.snapshot)
      const count = Number(j?.data?.count || 1)
      showNotice('success', count > 1
        ? `${count} sandbox simulations started against your scanned assets.`
        : 'New sandbox simulation started and synchronized.')
      await fetchSnapshot()
      return j?.data || null
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to start simulation'
      setError(message)
      showNotice('error', message)
      return null
    } finally {
      setPendingAction(null)
    }
  }, [token, fetchSnapshot, applySnapshot, showNotice])

  const exportReport = useCallback(async (format: 'json' | 'csv' = 'json') => {
    if (!token) return
    setPendingAction(`export:${format}`)
    try {
      const r = await fetch(`/api/v1/sandbox/export?format=${format}`, { headers: { Authorization: `Bearer ${token}` } })
      if (!r.ok) {
        const payload = await r.json().catch(() => ({}))
        throw new Error(payload?.error?.message || `Export failed (${r.status})`)
      }
      const blob = await r.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `qguard-sandbox-${new Date().toISOString().slice(0, 10)}.${format}`
      a.click()
      URL.revokeObjectURL(url)
      showNotice('success', `${format.toUpperCase()} sandbox export generated.`)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to export sandbox report'
      setError(message)
      showNotice('error', message)
    } finally {
      setPendingAction(null)
    }
  }, [token, showNotice])

  const exportSimulation = useCallback(async (simulationId: string, format: 'json' | 'csv' = 'json') => {
    if (!token) return
    const key = `${simulationId}:export:${format}`
    setPendingAction(key)
    try {
      const r = await fetch(`/api/v1/sandbox/export?format=${format}&simulationId=${encodeURIComponent(simulationId)}`, { headers: { Authorization: `Bearer ${token}` } })
      if (!r.ok) {
        const payload = await r.json().catch(() => ({}))
        throw new Error(payload?.error?.message || `Simulation export failed (${r.status})`)
      }
      const blob = await r.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `qguard-simulation-${simulationId.slice(0, 8)}-${new Date().toISOString().slice(0, 10)}.${format}`
      a.click()
      URL.revokeObjectURL(url)
      showNotice('success', `${format.toUpperCase()} simulation report generated.`)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to export simulation report'
      setError(message)
      showNotice('error', message)
    } finally {
      setPendingAction(null)
    }
  }, [token, showNotice])

  return { data, loading, error, notice, pendingAction, sseActive, refresh: fetchSnapshot, doAction, doBulkAction, startSimulation, exportReport, exportSimulation }
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

function HandoffTerminalConsole({
  planId,
  simulations,
  recentLogs,
  generatedAt,
  sseActive,
}: {
  planId: string
  simulations: Simulation[]
  recentLogs: LogEntry[]
  generatedAt: string
  sseActive: boolean
}) {
  const terminalRef = useRef<HTMLDivElement | null>(null)
  const lines = useMemo(
    () => buildHandoffTerminalLines(planId, simulations, recentLogs, generatedAt, sseActive),
    [generatedAt, planId, recentLogs, simulations, sseActive],
  )
  const activeCount = simulations.filter((sim) => ['running', 'queued', 'paused'].includes(sim.status)).length
  const targetStandards = Array.from(new Set(
    simulations
      .map((sim) => nistStandardsForAlgorithm(sim.toAlgo))
      .filter((standard) => standard !== 'NIST PQC target pending'),
  ))

  useEffect(() => {
    const el = terminalRef.current
    if (!el) return
    el.scrollTop = el.scrollHeight
  }, [lines])

  return (
    <div className="migration-handoff-terminal mt-4 overflow-hidden rounded-xl border border-white/8 bg-[#02070E]/80 shadow-[inset_0_1px_0_rgba(255,255,255,0.05),0_18px_48px_rgba(0,0,0,0.24)]">
      <div className="flex flex-col gap-3 border-b border-white/8 bg-black/20 px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-gold/25 bg-gold/10 text-gold">
            <Terminal className="h-4.5 w-4.5" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-black text-white">Real-Time Migration Terminal</h3>
              <span className={cn('h-2 w-2 rounded-full', sseActive ? 'bg-emerald-400 shadow-[0_0_10px_rgba(34,197,94,0.8)] animate-pulse' : 'bg-amber-400')} />
            </div>
            <p className="mt-0.5 truncate text-[10px] font-semibold text-white/40">
              Live commands are reconstructed from tenant sandbox jobs, migration events, and SSE telemetry.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Pill className="border-cyan-500/25 bg-cyan-500/10 text-cyan-300">{fmt(lines.length)} entries</Pill>
          <Pill className={cn(sseActive ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300' : 'border-amber-500/25 bg-amber-500/10 text-amber-300')}>
            {sseActive ? 'streaming' : 'reconnecting'}
          </Pill>
          <Pill className="border-gold/25 bg-gold/10 text-gold">
            {targetStandards.length ? targetStandards.slice(0, 2).join(' + ') : 'NIST PQC'}
          </Pill>
          <Pill className="border-white/10 bg-white/[0.03] text-white/45">{fmt(activeCount)} active</Pill>
        </div>
      </div>

      <div
        ref={terminalRef}
        role="log"
        aria-live="polite"
        aria-label="Real-time migration planner handoff terminal"
        className="max-h-[320px] overflow-y-auto px-4 py-3 font-mono text-[11px] leading-relaxed"
      >
        {lines.map((line) => (
          <div key={line.id} className="grid gap-2 border-b border-white/[0.04] py-2 last:border-b-0 sm:grid-cols-[70px_46px_minmax(0,1fr)]">
            <span className="text-white/30">{timeStr(line.timestamp)}</span>
            <span className={cn('uppercase tracking-[0.18em]', terminalLevelClass(line.level))}>{line.prompt}</span>
            <div className="min-w-0">
              <div className={cn('break-words font-semibold', terminalLevelClass(line.level))}>{line.command}</div>
              {line.detail && <div className="mt-0.5 break-words text-white/35">{line.detail}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
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

type SimulationAsset = {
  id: string
  name: string
  type: string
  environment: string
  owner: string
  criticality: string
  sourceAlgorithm: string
  targetAlgorithm: string
  riskLevel: string
  inventoryItems: number
  vulnerableItems: number
  exposures: number
  criticalExposures: number
  algorithms: string[]
  activeSimulations: number
  hasEvidence: boolean
  lastSeen: string | null
}

function NewSimulationModal({ open, onClose, onStart }: { open: boolean; onClose: () => void; onStart: (p: any) => void }) {
  const { session } = useAuth()
  const token = session?.access_token
  const [mode, setMode] = useState<'assets' | 'custom'>('assets')
  const [assets, setAssets] = useState<SimulationAsset[]>([])
  const [assetsLoading, setAssetsLoading] = useState(false)
  const [assetsError, setAssetsError] = useState<string | null>(null)
  const [selectedAssets, setSelectedAssets] = useState<Set<string>>(new Set())
  const [assetSearch, setAssetSearch] = useState('')
  const [fromAlgo, setFromAlgo] = useState('RSA-2048')
  const [toAlgo, setToAlgo] = useState('ML-KEM-768')
  const [migType, setMigType] = useState('key_exchange')
  const [dryRun, setDryRun] = useState(true)

  // Load the tenant's real scanned assets (with crypto evidence) each time
  // the modal opens, so simulations always target current inventory.
  useEffect(() => {
    if (!open || !token) return
    let cancelled = false
    setSelectedAssets(new Set())
    setAssetSearch('')
    setAssetsLoading(true)
    setAssetsError(null)
    fetch('/api/v1/sandbox/assets', { headers: { Authorization: `Bearer ${token}` } })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}))
        if (!r.ok) throw new Error(j?.error?.message || `HTTP ${r.status}`)
        return j?.data
      })
      .then((d) => {
        if (cancelled) return
        const rows: SimulationAsset[] = Array.isArray(d?.assets) ? d.assets : []
        setAssets(rows)
        setMode(rows.length > 0 ? 'assets' : 'custom')
      })
      .catch((err) => {
        if (cancelled) return
        setAssetsError(err instanceof Error ? err.message : 'Failed to load scanned assets')
        setMode('custom')
      })
      .finally(() => { if (!cancelled) setAssetsLoading(false) })
    return () => { cancelled = true }
  }, [open, token])

  const filteredAssets = useMemo(() => {
    if (!assetSearch.trim()) return assets
    const q = assetSearch.trim().toLowerCase()
    return assets.filter((a) =>
      a.name.toLowerCase().includes(q)
      || a.type.toLowerCase().includes(q)
      || a.environment.toLowerCase().includes(q)
      || a.sourceAlgorithm.toLowerCase().includes(q)
      || a.algorithms.some((algo) => algo.toLowerCase().includes(q))
    )
  }, [assets, assetSearch])

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

  const vulnerableAssetIds = assets.filter((a) => a.vulnerableItems > 0 || a.criticalExposures > 0).map((a) => a.id)
  const toggleAsset = (id: string) => {
    setSelectedAssets((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else if (next.size < 25) next.add(id)
      return next
    })
  }

  const startDisabled = mode === 'assets' ? selectedAssets.size === 0 : !fromAlgo.trim()
  const handleStart = () => {
    if (mode === 'assets') {
      onStart({ assetIds: Array.from(selectedAssets), dryRun, migrationType: 'asset_migration' })
    } else {
      onStart({ fromAlgo, toAlgo, migrationType: migType, dryRun })
    }
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onClick={onClose}>
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-gold/25 bg-[#0A1525]/95 p-6 shadow-2xl backdrop-blur-xl" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <h3 className="flex items-center gap-2 text-lg font-black text-white"><FlaskConical className="h-5 w-5 text-gold" /> New Migration Simulation</h3>
          <button type="button" onClick={onClose} className="rounded-lg p-1.5 text-white/40 hover:bg-white/10 hover:text-white"><X className="h-4 w-4" /></button>
        </div>

        <div className="mb-4 flex gap-2">
          {[
            { key: 'assets' as const, label: `Scanned Assets (${assets.length})`, icon: Server },
            { key: 'custom' as const, label: 'Custom Algorithms', icon: Key },
          ].map((m) => {
            const Icon = m.icon
            return (
              <button key={m.key} type="button" onClick={() => setMode(m.key)}
                className={cn('flex items-center gap-1.5 rounded-lg border px-3 py-2 text-[11px] font-bold transition',
                  mode === m.key ? 'border-gold/50 bg-gold/12 text-gold' : 'border-white/10 bg-white/[0.02] text-white/50 hover:border-gold/25 hover:text-white')}>
                <Icon className="h-3.5 w-3.5" />
                {m.label}
              </button>
            )
          })}
        </div>

        {mode === 'assets' && (
          <>
            <p className="mb-3 text-[11px] leading-relaxed text-white/40">
              Select assets from your scanned inventory. Each simulation loads the asset's real cryptographic
              evidence (inventory + exposures) and validates the recommended PQC migration against it in the sandbox.
            </p>

            {assetsLoading ? (
              <div className="flex items-center justify-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] py-10">
                <div className="h-5 w-5 animate-spin rounded-full border-2 border-gold/20 border-t-gold" />
                <span className="text-xs font-bold text-white/45">Loading scanned assets…</span>
              </div>
            ) : assetsError ? (
              <EmptyBlock label={`Could not load scanned assets: ${assetsError}`} />
            ) : assets.length === 0 ? (
              <EmptyBlock label="No scanned assets found. Run a discovery scan in the PQC Scanner first, then simulate migrations against the discovered assets." />
            ) : (
              <>
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <input
                    value={assetSearch}
                    onChange={(e) => setAssetSearch(e.target.value)}
                    placeholder="Search assets, algorithms, environments…"
                    className="min-w-0 flex-1 rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs text-white outline-none placeholder:text-white/25 focus:border-gold/40"
                  />
                  <button type="button" onClick={() => setSelectedAssets(new Set(vulnerableAssetIds.slice(0, 25)))}
                    className="rounded-lg border border-red-500/25 bg-red-500/8 px-2.5 py-2 text-[10px] font-bold text-red-300 transition hover:bg-red-500/15">
                    Select Vulnerable ({vulnerableAssetIds.length})
                  </button>
                  <button type="button" onClick={() => setSelectedAssets(new Set())}
                    className="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-2 text-[10px] font-bold text-white/50 transition hover:bg-white/8">
                    Clear
                  </button>
                </div>

                <div className="mb-4 max-h-[300px] space-y-1.5 overflow-y-auto pr-1">
                  {filteredAssets.length === 0 ? (
                    <EmptyBlock label="No assets match this search." />
                  ) : filteredAssets.map((asset) => {
                    const checked = selectedAssets.has(asset.id)
                    return (
                      <label key={asset.id} className={cn('flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2.5 transition',
                        checked ? 'border-gold/40 bg-gold/[0.06]' : 'border-white/8 bg-white/[0.015] hover:border-gold/20')}>
                        <input type="checkbox" checked={checked} onChange={() => toggleAsset(asset.id)} className="h-4 w-4 shrink-0 rounded border-white/20 bg-white/5 accent-gold" />
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="truncate text-xs font-bold text-white/85">{asset.name}</span>
                            <Pill className={riskBadge(asset.riskLevel)}>{asset.riskLevel}</Pill>
                            {asset.activeSimulations > 0 && <Pill className="border-sky-500/25 bg-sky-500/10 text-sky-300">{asset.activeSimulations} active</Pill>}
                          </div>
                          <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[10px] text-white/40">
                            <span className="font-mono">{asset.sourceAlgorithm}</span>
                            <span className="text-gold">→</span>
                            <span className="font-mono text-emerald-300">{asset.targetAlgorithm}</span>
                            <span className="text-white/20">|</span>
                            <span>{asset.type} · {asset.environment}</span>
                          </div>
                          <div className="mt-0.5 text-[9px] font-semibold text-white/30">
                            {asset.hasEvidence
                              ? `${fmt(asset.vulnerableItems)} vulnerable item(s) · ${fmt(asset.exposures)} exposure(s) · ${fmt(asset.inventoryItems)} inventory record(s)`
                              : 'No crypto evidence yet — simulation will validate the recommended baseline migration'}
                          </div>
                        </div>
                      </label>
                    )
                  })}
                </div>
              </>
            )}
          </>
        )}

        {mode === 'custom' && (
          <>
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
          </>
        )}

        <div className="mb-5 flex items-center gap-4">
          <label className="flex cursor-pointer items-center gap-2 text-xs text-white/60">
            <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-white/5 accent-gold" />
            <span className="font-bold">Dry Run Mode</span>
            <span className="text-[10px] text-white/35">(Simulate without commit)</span>
          </label>
        </div>

        <div className="flex items-center justify-end gap-3">
          <button type="button" onClick={onClose} className="rounded-lg border border-white/10 px-4 py-2 text-xs font-bold text-white/50 hover:bg-white/5">Cancel</button>
          <button type="button" onClick={handleStart} disabled={startDisabled}
            className={cn('rounded-lg border border-gold bg-gold px-5 py-2 text-xs font-black text-black shadow-[0_0_20px_rgba(251,191,36,0.3)] transition hover:bg-[#FFE08A]', startDisabled && 'pointer-events-none opacity-40')}>
            <Play className="mr-1.5 inline h-3.5 w-3.5" />
            {mode === 'assets' ? `Simulate ${selectedAssets.size} Asset${selectedAssets.size === 1 ? '' : 's'}` : 'Start Simulation'}
          </button>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   SIMULATION ROW (Expandable)
   ═══════════════════════════════════════════════════════════════════════════ */

function SimulationDetailsModal({
  simulation,
  onClose,
  onAction,
  pendingAction,
}: {
  simulation: Simulation | null
  onClose: () => void
  onAction: SandboxActionHandler
  pendingAction: string | null
}) {
  if (!simulation) return null
  const sc = statusColor(simulation.status)
  const snapshots = Array.isArray(simulation.metadata?.snapshots) ? simulation.metadata.snapshots as Array<Record<string, unknown>> : []
  const busy = (action: string) => pendingAction === `${simulation.id}:${action}`
  const deleteAllowed = simulation.isSandbox && canDeleteSimulationStatus(simulation.status)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onClick={onClose}>
      <div className="max-h-[88vh] w-full max-w-4xl overflow-hidden rounded-2xl border border-gold/25 bg-[#0A1525]/95 shadow-2xl backdrop-blur-xl" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-4 border-b border-white/10 p-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="truncate text-lg font-black text-white">{simulation.name}</h3>
              <Pill className={cn(sc.bg, sc.border, sc.text)}>{simulation.status.replace(/_/g, ' ')}</Pill>
              <Pill className={modeBadge(simulation.runMode)}>{modeLabel(simulation)}</Pill>
              <Pill className={riskBadge(simulation.riskLevel)}>{simulation.riskLevel}</Pill>
            </div>
            <p className="mt-1 text-xs text-white/45">{simulation.assetName} | {simulation.environment} | {simulation.owner}</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-lg p-1.5 text-white/40 hover:bg-white/10 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-[calc(88vh-82px)] overflow-y-auto p-5">
          <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              ['Source', simulation.fromAlgo],
              ['Target', simulation.toAlgo],
              ['Phase', simulation.phase],
              ['ETA', simulation.eta || '--'],
              ['Mode', modeLabel(simulation)],
              ['Engine', simulation.engineStatus || '--'],
              ['Progress', `${simulation.progress}%`],
              ['Asset Type', simulation.assetType],
              ['Criticality', simulation.criticality],
              ['Started', simulation.startedAt ? timeStr(simulation.startedAt) : '--'],
              ['Updated', relTime(simulation.updatedAt)],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-white/8 bg-white/[0.025] p-3">
                <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">{label}</div>
                <div className="mt-1 truncate text-xs font-bold text-white/75">{value}</div>
              </div>
            ))}
          </div>

          <div className="mb-5">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-black uppercase tracking-wider text-white/55">Execution Progress</span>
              <span className="font-mono text-xs font-bold text-white/55">{simulation.progress}%</span>
            </div>
            <ProgressBar value={simulation.progress} color={progressBarColor(simulation.progress, simulation.status)} height="h-2.5" />
            <div className="mt-2 rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px] text-white/45">
              {simulation.phaseDetail || simulation.queuedReason || 'Workflow metadata is synchronized from migration telemetry.'}
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
              <div className="mb-3 text-xs font-black uppercase tracking-wider text-white/55">Recent Events</div>
              {simulation.recentEvents.length === 0 ? (
                <EmptyBlock label="No event entries are attached to this simulation yet." />
              ) : (
                <div className="space-y-2">
                  {simulation.recentEvents.map((event) => (
                    <div key={event.id} className="grid grid-cols-[18px_1fr_auto] items-center gap-2 rounded-lg bg-white/[0.025] px-3 py-2 text-[11px]">
                      {severityIcon(event.severity)}
                      <span className="truncate text-white/60">{event.message}</span>
                      <span className="font-mono text-white/25">{timeStr(event.timestamp)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
              <div className="mb-3 text-xs font-black uppercase tracking-wider text-white/55">Recovery Snapshots</div>
              {snapshots.length === 0 ? (
                <EmptyBlock label="No recovery snapshots captured yet." />
              ) : (
                <div className="space-y-2">
                  {snapshots.slice().reverse().slice(0, 6).map((snap, index) => {
                    const simulationState = objectRecord(snap.simulationState)
                    const riskState = objectRecord(snap.riskState)
                    const complianceState = objectRecord(snap.complianceState)
                    const snapshotId = String(snap.id || `snapshot-${index + 1}`)
                    return (
                    <div key={snapshotId} className="rounded-lg border border-white/6 bg-white/[0.025] px-3 py-2 text-[11px]">
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-mono font-bold text-gold">{snapshotId}</span>
                        <span className="text-white/35">{relTime(String(snap.at || ''))}</span>
                      </div>
                      <div className="mt-1 grid gap-1 text-white/45 sm:grid-cols-2">
                        <span>Snapshot: {String(snap.status || simulationState.status || '--')} | {String(snap.progress ?? simulationState.progress ?? '--')}%</span>
                        <span>Current: {simulation.status} | {simulation.progress}%</span>
                        <span>Risk score: {String(riskState.riskScore ?? '--')}</span>
                        <span>Compliance: {String(complianceState.score ?? '--')}</span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <ActionBtn
                          icon={Upload}
                          label={busy('restore_snapshot') ? 'Restoring' : 'Restore'}
                          onClick={() => onAction(simulation.id, 'restore_snapshot', { snapshotId })}
                          disabled={busy('restore_snapshot')}
                          small
                        />
                        <ActionBtn
                          icon={Download}
                          label="Export"
                          onClick={() => downloadJson(`qguard-snapshot-${snapshotId}.json`, { simulationId: simulation.id, simulationName: simulation.name, snapshot: snap })}
                          small
                        />
                      </div>
                    </div>
                  )})}
                </div>
              )}
            </div>
          </div>

          <div className="mt-5 flex flex-wrap justify-end gap-2">
            {simulation.isSandbox && simulation.status === 'running' && <ActionBtn icon={Pause} label={busy('pause') ? 'Pausing' : 'Pause'} onClick={() => onAction(simulation.id, 'pause')} disabled={busy('pause')} />}
            {simulation.isSandbox && simulation.status === 'paused' && <ActionBtn icon={Play} label={busy('resume') ? 'Resuming' : 'Resume'} onClick={() => onAction(simulation.id, 'resume')} disabled={busy('resume')} variant="success" />}
            {simulation.isSandbox && simulation.status === 'failed' && <ActionBtn icon={RefreshCw} label={busy('retry') ? 'Retrying' : 'Retry'} onClick={() => onAction(simulation.id, 'retry')} disabled={busy('retry')} variant="gold" />}
            {simulation.isSandbox && simulation.status === 'running' && <ActionBtn icon={Square} label={busy('stop') ? 'Stopping' : 'Stop'} onClick={() => onAction(simulation.id, 'stop')} disabled={busy('stop')} variant="danger" />}
            {['running', 'paused', 'completed'].includes(simulation.status) && <ActionBtn icon={RotateCcw} label={busy('rollback') ? 'Rolling Back' : 'Rollback'} onClick={() => onAction(simulation.id, 'rollback')} disabled={busy('rollback')} variant="danger" />}
            <ActionBtn icon={Save} label={busy('snapshot') ? 'Capturing' : 'Snapshot'} onClick={() => onAction(simulation.id, 'snapshot')} disabled={busy('snapshot')} />
            {snapshots.length > 0 && <ActionBtn icon={Upload} label={busy('restore_snapshot') ? 'Restoring' : 'Restore Snapshot'} onClick={() => onAction(simulation.id, 'restore_snapshot', { snapshotId: String(snapshots[snapshots.length - 1]?.id || '') })} disabled={busy('restore_snapshot')} />}
            {deleteAllowed && <ActionBtn icon={Trash2} label={busy('delete') ? 'Deleting' : 'Delete Simulation'} onClick={() => { if (window.confirm('Delete this completed simulation and purge its execution artifacts? Audit and security records will remain.')) onAction(simulation.id, 'delete') }} disabled={busy('delete')} variant="danger" />}
          </div>
        </div>
      </div>
    </div>
  )
}

function SimulationRow({
  sim,
  onAction,
  onDetails,
  pendingAction,
}: {
  sim: Simulation
  onAction: SandboxActionHandler
  onDetails: (sim: Simulation) => void
  pendingAction: string | null
}) {
  const [expanded, setExpanded] = useState(false)
  const sc = statusColor(sim.status)
  const busy = (action: string) => pendingAction === `${sim.id}:${action}`
  const deleteAllowed = sim.isSandbox && canDeleteSimulationStatus(sim.status)
  const snapshots = Array.isArray(sim.metadata?.snapshots) ? sim.metadata.snapshots as Array<Record<string, unknown>> : []

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
            <Pill className={modeBadge(sim.runMode)}>{modeLabel(sim)}</Pill>
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
            {sim.eta && <><span className="mx-2 text-white/20">|</span><span>{sim.eta}</span></>}
          </div>
        </div>

        <div className="hidden items-center gap-2 sm:flex">
          <Pill className={cn(sc.bg, sc.border, sc.text, 'uppercase tracking-wider')}>{sim.status.replace(/_/g, ' ')}</Pill>
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

          {(sim.phaseDetail || sim.queuedReason) && (
            <div className="mb-3 rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px] text-white/45">
              {sim.phaseDetail || sim.queuedReason}
            </div>
          )}

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
            {sim.isSandbox && sim.status === 'running' && <ActionBtn icon={Pause} label={busy('pause') ? 'Pausing' : 'Pause'} onClick={() => onAction(sim.id, 'pause')} disabled={busy('pause')} small />}
            {sim.isSandbox && sim.status === 'paused' && <ActionBtn icon={Play} label={busy('resume') ? 'Resuming' : 'Resume'} onClick={() => onAction(sim.id, 'resume')} disabled={busy('resume')} variant="success" small />}
            {sim.isSandbox && sim.status === 'failed' && <ActionBtn icon={RefreshCw} label={busy('retry') ? 'Retrying' : 'Retry'} onClick={() => onAction(sim.id, 'retry')} disabled={busy('retry')} variant="gold" small />}
            {sim.isSandbox && sim.status === 'running' && <ActionBtn icon={Square} label={busy('stop') ? 'Stopping' : 'Stop'} onClick={() => onAction(sim.id, 'stop')} disabled={busy('stop')} variant="danger" small />}
            {['running', 'paused', 'completed'].includes(sim.status) && <ActionBtn icon={RotateCcw} label={busy('rollback') ? 'Rolling Back' : 'Rollback'} onClick={() => onAction(sim.id, 'rollback')} disabled={busy('rollback')} variant="danger" small />}
            <ActionBtn icon={Save} label={busy('snapshot') ? 'Capturing' : 'Snapshot'} onClick={() => onAction(sim.id, 'snapshot')} disabled={busy('snapshot')} small />
            {snapshots.length > 0 && <ActionBtn icon={Upload} label={busy('restore_snapshot') ? 'Restoring' : 'Restore'} onClick={() => onAction(sim.id, 'restore_snapshot', { snapshotId: String(snapshots[snapshots.length - 1]?.id || '') })} disabled={busy('restore_snapshot')} small />}
            <ActionBtn icon={Eye} label="Details" onClick={() => onDetails(sim)} small />
            {deleteAllowed && <ActionBtn icon={Trash2} label={busy('delete') ? 'Deleting' : 'Delete'} onClick={() => { if (window.confirm('Delete this completed simulation and purge its execution artifacts? Audit and security records will remain.')) onAction(sim.id, 'delete') }} disabled={busy('delete')} variant="danger" small />}
          </div>
        </div>
      )}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   WORKFLOW TIMELINE
   ═══════════════════════════════════════════════════════════════════════════ */

function WorkflowQueueRow({
  workflow,
  onAction,
  onDetails,
  pendingAction,
}: {
  workflow: Simulation
  onAction: SandboxActionHandler
  onDetails: (sim: Simulation) => void
  pendingAction: string | null
}) {
  const sc = statusColor(workflow.status)
  const busy = (action: string) => pendingAction === `${workflow.id}:${action}`
  const rollbackEligible = ['running', 'paused', 'completed'].includes(workflow.status)

  return (
    <div className="grid gap-3 rounded-lg border border-white/6 bg-white/[0.015] px-4 py-3 transition hover:border-gold/15 hover:bg-gold/[0.02] lg:grid-cols-[1fr_150px_120px_130px_auto] lg:items-center">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate text-sm font-bold text-white/85">{workflow.name}</span>
          <Pill className={modeBadge(workflow.runMode)}>{modeLabel(workflow)}</Pill>
        </div>
        <div className="mt-1 truncate text-[11px] text-white/40">{workflow.phaseDetail || workflow.queuedReason || workflow.engineStatus}</div>
      </div>
      <div className="flex items-center gap-2">
        <Pill className={cn(sc.bg, sc.border, sc.text)}>{workflow.status.replace(/_/g, ' ')}</Pill>
      </div>
      <div>
        <div className="mb-1 flex items-center justify-between text-[10px] font-mono text-white/40">
          <span>{workflow.phase}</span>
          <span>{workflow.progress}%</span>
        </div>
        <ProgressBar value={workflow.progress} color={progressBarColor(workflow.progress, workflow.status)} />
      </div>
      <div className="text-[10px] font-mono text-white/35">
        <div>{workflow.eta || '--'}</div>
        <div>Updated {relTime(workflow.updatedAt)}</div>
      </div>
      <div className="flex flex-wrap gap-2 lg:justify-end">
        {rollbackEligible && <ActionBtn icon={RotateCcw} label={busy('rollback') ? 'Rolling Back' : 'Rollback'} onClick={() => onAction(workflow.id, 'rollback')} disabled={busy('rollback')} variant="danger" small />}
        <ActionBtn icon={Save} label={busy('snapshot') ? 'Capturing' : 'Snapshot'} onClick={() => onAction(workflow.id, 'snapshot')} disabled={busy('snapshot')} small />
        <ActionBtn icon={Eye} label="Details" onClick={() => onDetails(workflow)} small />
      </div>
    </div>
  )
}

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
            <div className="mt-1 flex flex-wrap gap-2 text-[9px] font-bold uppercase tracking-wider text-white/25">
              {p.count !== undefined && <span>{fmt(p.count)} signals</span>}
              {p.running !== undefined && p.running > 0 && <span className="text-emerald-300">{fmt(p.running)} running</span>}
              {p.queued !== undefined && p.queued > 0 && <span className="text-sky-300">{fmt(p.queued)} queued</span>}
              {p.blocked !== undefined && p.blocked > 0 && <span className="text-red-300">{fmt(p.blocked)} blocked</span>}
              {p.source && <span>{p.source}</span>}
              {p.updatedAt && <span>updated {relTime(p.updatedAt)}</span>}
            </div>
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
  const { data, loading, error, notice, pendingAction, sseActive, refresh, doAction, doBulkAction, startSimulation, exportReport, exportSimulation } = useSandbox()
  const plannerHandoffPlanId = useMemo(() => {
    if (typeof window === 'undefined') return ''
    return new URLSearchParams(window.location.search).get('planId') || ''
  }, [])
  const [tab, setTab] = useState<ActiveTab>(() => plannerHandoffPlanId ? 'simulations' : 'overview')
  // Roadmap handed off from the AI Migration Advisor™ (localStorage payload).
  const [advisorHandoff, setAdvisorHandoff] = useState<MigrationHandoff | null>(() => readMigrationHandoff())
  const [showNewSim, setShowNewSim] = useState(false)
  const [selectedSimulation, setSelectedSimulation] = useState<Simulation | null>(null)
  const [logFilter, setLogFilter] = useState('')
  const [historyStatus, setHistoryStatus] = useState('all')
  const [historyAlgorithm, setHistoryAlgorithm] = useState('all')
  const [historyDateRange, setHistoryDateRange] = useState('all')
  const [historyAssetType, setHistoryAssetType] = useState('all')
  const [historyRisk, setHistoryRisk] = useState('all')

  const s = data.summary
  const generated = useMemo(() => new Date(data.generatedAt), [data.generatedAt])
  const plannerHandoffSimulations = useMemo(() => {
    if (!plannerHandoffPlanId) return []
    return data.simulations.filter((sim) => {
      const metadata = objectRecord(sim.metadata)
      const plan = objectRecord(metadata.plan)
      return [metadata.planId, metadata.sandboxPlanId, plan.id]
        .some((value) => String(value || '') === plannerHandoffPlanId)
    })
  }, [data.simulations, plannerHandoffPlanId])
  const plannerHandoffStats = useMemo(() => ({
    total: plannerHandoffSimulations.length,
    queued: plannerHandoffSimulations.filter((sim) => sim.status === 'queued').length,
    running: plannerHandoffSimulations.filter((sim) => sim.status === 'running').length,
    completed: plannerHandoffSimulations.filter((sim) => sim.status === 'completed').length,
    failed: plannerHandoffSimulations.filter((sim) => sim.status === 'failed').length,
    averageProgress: plannerHandoffSimulations.length
      ? Math.round(plannerHandoffSimulations.reduce((sum, sim) => sum + Number(sim.progress || 0), 0) / plannerHandoffSimulations.length)
      : 0,
  }), [plannerHandoffSimulations])
  const visibleSimulations = plannerHandoffPlanId ? plannerHandoffSimulations : data.simulations
  const operationalWorkflows = useMemo(() => data.workflows.filter((workflow) => !workflow.isSandbox), [data.workflows])
  const rollbackEligibleWorkflows = useMemo(
    () => data.workflows.filter((workflow) => ['completed', 'running', 'paused'].includes(workflow.status)),
    [data.workflows]
  )

  const tabs: { key: ActiveTab; label: string; icon: LucideIcon }[] = [
    { key: 'overview', label: 'Overview', icon: Layers },
    { key: 'simulations', label: `Simulations (${s.totalSimulations})`, icon: FlaskConical },
    { key: 'history', label: `History (${data.history.length})`, icon: History },
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

  const historyAlgorithms = useMemo(() => {
    const values = new Set<string>()
    data.history.forEach((row) => {
      if (row.sourceAlgorithm) values.add(row.sourceAlgorithm)
      if (row.targetAlgorithm) values.add(row.targetAlgorithm)
    })
    return Array.from(values).sort()
  }, [data.history])

  const historyAssetTypes = useMemo(() => Array.from(new Set(data.history.map((row) => row.assetType || 'service'))).sort(), [data.history])
  const historyRisks = useMemo(() => {
    const order = ['critical', 'high', 'medium', 'low']
    const values = Array.from(new Set(data.history.map((row) => String(row.riskLevel || 'low')))) as string[]
    return values.sort((a, b) => order.indexOf(a) - order.indexOf(b))
  }, [data.history])

  const filteredHistory = useMemo(() => {
    return data.history.filter((row) => {
      const statusOk = historyStatus === 'all' || row.status === historyStatus
      const algorithmOk = historyAlgorithm === 'all' || row.sourceAlgorithm === historyAlgorithm || row.targetAlgorithm === historyAlgorithm
      const dateOk = historyDateMatches(row.completedAt || row.updatedAt || row.createdAt, historyDateRange)
      const assetTypeOk = historyAssetType === 'all' || row.assetType === historyAssetType
      const riskOk = historyRisk === 'all' || row.riskLevel === historyRisk
      return statusOk && algorithmOk && dateOk && assetTypeOk && riskOk
    })
  }, [data.history, historyStatus, historyAlgorithm, historyDateRange, historyAssetType, historyRisk])

  useEffect(() => {
    if (!selectedSimulation) return
    const refreshed = data.simulations.find((sim) => sim.id === selectedSimulation.id)
    if (refreshed) setSelectedSimulation(refreshed)
    else setSelectedSimulation(null)
  }, [data.simulations, selectedSimulation])

  /* ─── Loading State ──────────────────────────────────────────────────── */
  if (loading && s.totalSimulations === 0) {
    return (
      <main className="migration-sandbox-shell flex min-h-screen items-center justify-center bg-[var(--qg-dashboard-bg)] p-4 text-[var(--qg-dashboard-text)]">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-2 border-gold/20 border-t-gold" />
          <span className="text-sm font-bold text-white/50">Initializing Migration Sandbox…</span>
        </div>
      </main>
    )
  }

  return (
    <main className="migration-sandbox-shell min-h-screen bg-[var(--qg-dashboard-bg)] text-[var(--qg-dashboard-text)]">
      <style>{`
        .migration-sandbox-shell {
          background:
            radial-gradient(circle at 18% 8%, rgba(0, 197, 235, 0.13), transparent 30%),
            radial-gradient(circle at 82% 10%, rgba(251, 191, 36, 0.08), transparent 28%),
            linear-gradient(180deg, #02070E 0%, #06101d 52%, #02070E 100%);
        }
        .qg-theme-light .migration-sandbox-shell {
          background:
            radial-gradient(circle at 18% 8%, rgba(0, 197, 235, 0.17), transparent 32%),
            radial-gradient(circle at 82% 14%, rgba(124, 58, 237, 0.08), transparent 30%),
            linear-gradient(180deg, var(--qg-dashboard-bg) 0%, var(--qg-dashboard-bg-soft) 100%);
          color: var(--qg-dashboard-text);
        }
        .qg-theme-light .migration-sandbox-panel {
          background:
            linear-gradient(135deg, rgba(255,255,255,0.92), rgba(236,249,255,0.82)) !important;
          border-color: var(--qg-card-border) !important;
          color: var(--qg-dashboard-text) !important;
          box-shadow: var(--qg-panel-shadow) !important;
        }
        .qg-theme-light .migration-sandbox-panel:hover {
          border-color: var(--qg-border-bright) !important;
          box-shadow: var(--qg-hover-shadow) !important;
        }
        .qg-theme-light .migration-sandbox-panel::before {
          background: linear-gradient(90deg, transparent, rgba(0,197,235,0.48), transparent) !important;
        }
        .qg-theme-light .migration-sandbox-shell header {
          background:
            linear-gradient(135deg, rgba(255,255,255,0.92), rgba(236,249,255,0.82)) !important;
          border-color: var(--qg-card-border) !important;
          color: var(--qg-dashboard-text) !important;
          box-shadow: var(--qg-panel-shadow);
        }
        .qg-theme-light .migration-sandbox-shell [class*="bg-[#02070E]"],
        .qg-theme-light .migration-sandbox-shell [class*="bg-[#060F1C]"],
        .qg-theme-light .migration-sandbox-shell [class*="bg-[#0A1525]"],
        .qg-theme-light .migration-sandbox-shell [class*="bg-black/"] {
          background-color: rgba(255,255,255,0.84) !important;
        }
        .qg-theme-light .migration-sandbox-shell [class*="bg-white/"],
        .qg-theme-light .migration-sandbox-shell [class*="bg-white\\["] {
          background-color: rgba(236,249,255,0.76) !important;
        }
        .qg-theme-light .migration-handoff-terminal {
          background: rgba(255,255,255,0.9) !important;
          border-color: var(--qg-card-border) !important;
          color: var(--qg-dashboard-text) !important;
          box-shadow: var(--qg-panel-shadow) !important;
        }
        .qg-theme-light .migration-handoff-terminal > div:first-child {
          background: rgba(236,249,255,0.74) !important;
          border-color: var(--qg-card-border) !important;
        }
        .qg-theme-light .migration-handoff-terminal [role="log"] {
          color: var(--qg-dashboard-text) !important;
        }
        .qg-theme-light .migration-sandbox-shell [class*="border-white"],
        .qg-theme-light .migration-sandbox-shell [class*="border-gold"] {
          border-color: var(--qg-card-border) !important;
        }
        .qg-theme-light .migration-sandbox-shell [class*="text-white/"] {
          color: var(--qg-dashboard-text-soft) !important;
        }
        .qg-theme-light .migration-sandbox-shell .text-white,
        .qg-theme-light .migration-sandbox-shell h1[class*="text-white"],
        .qg-theme-light .migration-sandbox-shell h2[class*="text-white"],
        .qg-theme-light .migration-sandbox-shell h3[class*="text-white"],
        .qg-theme-light .migration-sandbox-shell p[class*="text-white"],
        .qg-theme-light .migration-sandbox-shell span[class*="text-white"],
        .qg-theme-light .migration-sandbox-shell [class*="font-black"][class*="text-white"],
        .qg-theme-light .migration-sandbox-shell [class*="font-bold"][class*="text-white"] {
          color: var(--qg-dashboard-text) !important;
        }
        .qg-theme-light .migration-sandbox-shell input,
        .qg-theme-light .migration-sandbox-shell select,
        .qg-theme-light .migration-sandbox-shell textarea {
          background: var(--qg-input-bg) !important;
          border-color: var(--qg-input-border) !important;
          color: var(--qg-input-text) !important;
        }
        .qg-theme-light .migration-sandbox-shell input::placeholder,
        .qg-theme-light .migration-sandbox-shell textarea::placeholder {
          color: var(--qg-dashboard-text-muted) !important;
        }
        .qg-theme-light .migration-sandbox-shell .text-red-300,
        .qg-theme-light .migration-sandbox-shell .text-red-400 {
          color: #dc2626 !important;
        }
        .qg-theme-light .migration-sandbox-shell .text-orange-300,
        .qg-theme-light .migration-sandbox-shell .text-orange-400 {
          color: #ea580c !important;
        }
        .qg-theme-light .migration-sandbox-shell .text-emerald-300,
        .qg-theme-light .migration-sandbox-shell .text-emerald-400 {
          color: #047857 !important;
        }
        .qg-theme-light .migration-sandbox-shell .text-sky-300,
        .qg-theme-light .migration-sandbox-shell .text-sky-400 {
          color: #0284c7 !important;
        }
        .qg-theme-light .migration-sandbox-shell .text-purple-300 {
          color: #7c3aed !important;
        }
        .qg-theme-light .migration-sandbox-shell .text-gold,
        .qg-theme-light .migration-sandbox-shell .hover\\:text-gold:hover {
          color: var(--qg-amber) !important;
        }
        .qg-theme-light .migration-sandbox-shell .bg-gold,
        .qg-theme-light .migration-sandbox-shell [class*="bg-gold"] {
          background-color: color-mix(in srgb, var(--qg-amber) 16%, transparent) !important;
        }
        .qg-theme-light .migration-sandbox-shell .text-black {
          color: var(--qg-dashboard-text) !important;
        }
        .qg-theme-light .migration-sandbox-shell svg text {
          fill: var(--qg-dashboard-text-soft) !important;
        }
      `}</style>
      <NewSimulationModal open={showNewSim} onClose={() => setShowNewSim(false)} onStart={startSimulation} />
      <SimulationDetailsModal simulation={selectedSimulation} onClose={() => setSelectedSimulation(null)} onAction={doAction} pendingAction={pendingAction} />
      {notice && (
        <div className={cn(
          'fixed right-4 top-4 z-[60] max-w-sm rounded-xl border px-4 py-3 text-sm font-bold shadow-2xl backdrop-blur-xl',
          notice.kind === 'success' ? 'border-emerald-400/35 bg-emerald-500/15 text-emerald-200' :
          notice.kind === 'error' ? 'border-red-400/35 bg-red-500/15 text-red-200' :
          'border-sky-400/35 bg-sky-500/15 text-sky-100'
        )}>
          {notice.message}
        </div>
      )}

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
            <ActionBtn icon={Download} label={pendingAction === 'export:json' ? 'Exporting' : 'Export'} onClick={() => exportReport('json')} disabled={pendingAction === 'export:json'} />
            <ActionBtn icon={Upload} label={pendingAction === 'export:csv' ? 'Exporting' : 'CSV'} onClick={() => exportReport('csv')} disabled={pendingAction === 'export:csv'} />
            <ActionBtn icon={Plus} label={pendingAction === 'simulate' ? 'Starting' : 'New Simulation'} onClick={() => setShowNewSim(true)} disabled={pendingAction === 'simulate'} variant="gold" />

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
        {advisorHandoff && (
          <Panel className="border-violet-400/25 bg-violet-500/[0.03] p-5">
            <SectionHead
              icon={Bot}
              suffix={
                <div className="flex flex-wrap items-center gap-2">
                  <Pill className="border-violet-400/25 bg-violet-500/10 text-violet-300">confidence {advisorHandoff.confidencePct}%</Pill>
                  <ActionBtn icon={CheckCircle2} label="Acknowledge" onClick={() => { clearMigrationHandoff(); setAdvisorHandoff(null) }} small />
                </div>
              }
            >
              AI Migration Advisor™ Roadmap Handoff
            </SectionHead>
            <p className="text-xs leading-relaxed text-white/65">
              <span className="font-bold text-violet-200">{advisorHandoff.recommendation}</span>
              {' — '}
              {advisorHandoff.waves.length} wave(s) · {advisorHandoff.assetPrioritization.length} prioritized asset(s) · {advisorHandoff.rollbackStrategy.length} rollback runbook(s)
              {advisorHandoff.estimates.migrationTimelineWeeks ? ` · ${advisorHandoff.estimates.migrationTimelineWeeks}w programme` : ''}
            </p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {advisorHandoff.waves.map((wave) => (
                <span key={wave.wave}>
                  <Pill className="border-white/10 bg-black/20 text-white/55">
                    W{wave.wave} {wave.name} · {wave.durationWeeks}w · −{wave.riskReductionPct}%
                  </Pill>
                </span>
              ))}
            </div>
            <p className="mt-2 text-[10px] leading-snug text-white/35">
              Use the roadmap's waves to scope simulations below — target algorithms resolve through the {advisorHandoff.cryptoPolicyProfile?.profile || 'active'} crypto-policy profile. Acknowledging clears the handoff.
            </p>
          </Panel>
        )}
        {plannerHandoffPlanId && (
          <Panel className="border-gold/30 bg-gold/[0.025] p-5">
            <SectionHead icon={FlaskConical} suffix={
              <div className="flex flex-wrap items-center gap-2">
                <Pill className={cn(sseActive ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-amber-500/30 bg-amber-500/10 text-amber-300')}>
                  {sseActive ? 'SSE live' : 'SSE reconnecting'}
                </Pill>
                <ActionBtn icon={RefreshCw} label="Refresh" onClick={refresh} small />
                <ActionBtn icon={Terminal} label="Logs" onClick={() => setTab('logs')} small />
              </div>
            }>
              Migration Planner Handoff
            </SectionHead>

            <div className="grid gap-3 lg:grid-cols-[1.1fr_1.9fr]">
              <div className="rounded-xl border border-white/8 bg-black/20 p-4">
                <div className="text-[9px] font-bold uppercase tracking-[0.22em] text-white/35">Plan ID</div>
                <div className="mt-1 truncate font-mono text-sm font-black text-gold">{plannerHandoffPlanId}</div>
                <div className="mt-4 grid grid-cols-2 gap-2">
                  {[
                    { label: 'Assets', value: plannerHandoffStats.total, tone: 'text-white' },
                    { label: 'Queued', value: plannerHandoffStats.queued, tone: 'text-sky-300' },
                    { label: 'Running', value: plannerHandoffStats.running, tone: 'text-emerald-300' },
                    { label: 'Complete', value: plannerHandoffStats.completed, tone: 'text-gold' },
                  ].map((item) => (
                    <div key={item.label} className="rounded-lg border border-white/6 bg-white/[0.025] px-3 py-2">
                      <div className="text-[8px] font-bold uppercase tracking-wider text-white/30">{item.label}</div>
                      <div className={cn('mt-1 font-mono text-xl font-black', item.tone)}>{fmt(item.value)}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-4">
                  <div className="mb-1 flex items-center justify-between text-[10px] font-bold uppercase tracking-wider text-white/35">
                    <span>Simulation Progress</span>
                    <span className="font-mono text-gold">{plannerHandoffStats.averageProgress}%</span>
                  </div>
                  <ProgressBar value={plannerHandoffStats.averageProgress} color={plannerHandoffStats.failed > 0 ? RED : plannerHandoffStats.completed === plannerHandoffStats.total && plannerHandoffStats.total > 0 ? GREEN : GOLD} />
                </div>
              </div>

              <div className="space-y-2">
                {plannerHandoffSimulations.length === 0 ? (
                  <EmptyBlock label="Waiting for sandbox simulation jobs from this migration plan handoff." />
                ) : (
                  plannerHandoffSimulations.slice(0, 5).map((sim) => {
                    const colors = statusColor(sim.status)
                    return (
                      <div key={sim.id} className="rounded-xl border border-white/8 bg-white/[0.025] px-4 py-3">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="truncate text-sm font-black text-white">{sim.assetName || sim.name}</div>
                            <div className="mt-1 text-[11px] font-semibold text-white/45">{sim.fromAlgo} -&gt; {sim.toAlgo} · {sim.environment}</div>
                          </div>
                          <Pill className={cn(colors.bg, colors.border, colors.text)}>{sim.status.replace(/_/g, ' ')}</Pill>
                        </div>
                        <div className="mt-3 flex items-center gap-3">
                          <div className="min-w-0 flex-1"><ProgressBar value={sim.progress} color={progressBarColor(sim.progress, sim.status)} /></div>
                          <span className="w-10 text-right font-mono text-[11px] font-black text-white/55">{sim.progress}%</span>
                          <ActionBtn icon={Eye} label="Details" onClick={() => setSelectedSimulation(sim)} small />
                        </div>
                      </div>
                    )
                  })
                )}
                {plannerHandoffSimulations.length > 5 && (
                  <button type="button" onClick={() => setTab('simulations')} className="w-full rounded-lg border border-gold/20 bg-gold/[0.04] py-2 text-center text-[11px] font-bold text-gold hover:bg-gold/[0.08]">
                    View all {plannerHandoffSimulations.length} handoff simulations
                  </button>
                )}
              </div>
            </div>

            <HandoffTerminalConsole
              planId={plannerHandoffPlanId}
              simulations={plannerHandoffSimulations}
              recentLogs={data.recentLogs}
              generatedAt={data.generatedAt}
              sseActive={sseActive}
            />
          </Panel>
        )}

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: OVERVIEW
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'overview' && (
          <>
            {/* ─── Hero Metrics ────────────────────────────────────────────── */}
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-8">
              <MetricTile label="Sandbox Runs" value={fmt(s.totalSimulations)} detail={`${s.running} running / ${s.queued} queued`} icon={FlaskConical} color={GOLD} />
              <MetricTile label="Migration Queue" value={fmt(s.totalWorkflows)} detail={`${s.queuedWorkflows} queued`} icon={Layers} color={BLUE} />
              <MetricTile label="Live Workflows" value={fmt(s.runningWorkflows)} detail={s.backgroundEngine === 'active' ? 'Engine active' : 'Engine idle'} icon={Activity} color={GREEN} />
              <MetricTile label="Completed" value={fmt(s.completedWorkflows)} detail={`${s.workflowCompletionRate}% rate`} icon={CheckCircle2} color={GREEN} />
              <MetricTile label="Blocked" value={fmt(s.blockedWorkflows + s.failedWorkflows)} icon={X} color={RED} detail={s.failedWorkflows > 0 ? 'Needs attention' : 'Queue review'} />
              <MetricTile label="PQC Readiness" value={pct(s.pqcReadiness)} icon={Shield} color={s.pqcReadiness >= 70 ? GREEN : GOLD} detail={s.pqcReadiness >= 80 ? 'Strong' : 'In Progress'} />
              <MetricTile label="Risk Score" value={`${s.riskScore}`} icon={Target} color={s.riskScore >= 70 ? GREEN : s.riskScore >= 40 ? GOLD : RED} detail={s.riskScore >= 70 ? 'Healthy' : 'At Risk'} />
              <MetricTile label="Compliance" value={pct(data.complianceScore)} icon={ShieldCheck} color={data.complianceScore >= 70 ? GREEN : GOLD} detail={data.complianceScore >= 80 ? 'Compliant' : 'Review Needed'} />
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
                    {s.running > 0 && <ActionBtn icon={Pause} label={pendingAction === 'bulk:pause' ? 'Pausing' : 'Pause All'} onClick={() => doBulkAction('pause')} disabled={pendingAction === 'bulk:pause'} variant="default" small />}
                    {s.paused > 0 && <ActionBtn icon={Play} label={pendingAction === 'bulk:resume' ? 'Resuming' : 'Resume All'} onClick={() => doBulkAction('resume')} disabled={pendingAction === 'bulk:resume'} variant="success" small />}
                  </div>
                }>Active Sandbox Simulations</SectionHead>
                {data.simulations.length === 0 ? (
                  <EmptyBlock label={operationalWorkflows.length > 0 ? `${fmt(operationalWorkflows.length)} operational migration workflow(s) are queued outside sandbox simulation.` : "No simulations yet. Click 'New Simulation' to start your first PQC migration test."} />
                ) : (
                  <div className="space-y-2">
                    {data.simulations.slice(0, 5).map((sim) => (
                      <div key={sim.id}>
                        <SimulationRow sim={sim} onAction={doAction} onDetails={setSelectedSimulation} pendingAction={pendingAction} />
                      </div>
                    ))}
                    {data.simulations.length > 5 && (
                      <button type="button" onClick={() => setTab('simulations')} className="w-full rounded-lg border border-white/8 py-2 text-center text-[11px] font-bold text-gold hover:bg-gold/5">
                        View all {data.simulations.length} sandbox runs →
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
            {operationalWorkflows.length > 0 && (
              <Panel className="p-5">
                <SectionHead icon={Layers} suffix={
                  <div className="flex flex-wrap gap-2">
                    <Pill className="border-sky-500/25 bg-sky-500/10 text-sky-300">{fmt(s.queuedWorkflows)} queued</Pill>
                    <Pill className="border-red-500/25 bg-red-500/10 text-red-300">{fmt(s.blockedWorkflows)} stale</Pill>
                  </div>
                }>Operational Migration Queue</SectionHead>
                <div className="space-y-2">
                  {operationalWorkflows.slice(0, 6).map((workflow) => (
                    <div key={workflow.id}>
                      <WorkflowQueueRow workflow={workflow} onAction={doAction} onDetails={setSelectedSimulation} pendingAction={pendingAction} />
                    </div>
                  ))}
                  {operationalWorkflows.length > 6 && (
                    <button type="button" onClick={() => setTab('rollback')} className="w-full rounded-lg border border-white/8 py-2 text-center text-[11px] font-bold text-gold hover:bg-gold/5">
                      Review all {operationalWorkflows.length} operational workflows →
                    </button>
                  )}
                </div>
              </Panel>
            )}

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
                <h2 className="text-lg font-black text-white">{plannerHandoffPlanId ? 'Migration Plan Simulations' : 'Sandbox Simulations'}</h2>
                <Pill className="border-gold/25 bg-gold/10 text-gold">{fmt(visibleSimulations.length)} total</Pill>
                {plannerHandoffPlanId && <Pill className="border-sky-500/25 bg-sky-500/10 text-sky-300">Plan handoff</Pill>}
              </div>
              <div className="flex items-center gap-2">
                {s.running > 0 && <ActionBtn icon={Pause} label={pendingAction === 'bulk:pause' ? 'Pausing' : 'Pause All'} onClick={() => doBulkAction('pause')} disabled={pendingAction === 'bulk:pause'} small />}
                {s.paused > 0 && <ActionBtn icon={Play} label={pendingAction === 'bulk:resume' ? 'Resuming' : 'Resume All'} onClick={() => doBulkAction('resume')} disabled={pendingAction === 'bulk:resume'} variant="success" small />}
                {s.failed > 0 && <ActionBtn icon={RefreshCw} label={pendingAction === 'bulk:retry' ? 'Retrying' : 'Retry Failed'} onClick={() => doBulkAction('retry')} disabled={pendingAction === 'bulk:retry'} variant="gold" small />}
                <ActionBtn icon={Save} label={pendingAction === 'bulk:snapshot' ? 'Capturing' : 'Snapshot All'} onClick={() => doBulkAction('snapshot')} disabled={pendingAction === 'bulk:snapshot'} small />
                <ActionBtn icon={Plus} label={pendingAction === 'simulate' ? 'Starting' : 'New Simulation'} onClick={() => setShowNewSim(true)} disabled={pendingAction === 'simulate'} variant="gold" />
              </div>
            </div>

            {visibleSimulations.length === 0 ? (
              <Panel className="p-8">
                <EmptyBlock label={plannerHandoffPlanId ? "No simulations are linked to this migration plan yet. The sandbox stream will update this view when jobs are queued." : "No migration simulations found. Start a new simulation to safely test PQC migration workflows."} />
              </Panel>
            ) : (
              <Panel className="p-5">
                <div className="space-y-2">
                  {visibleSimulations.map((sim) => (
                    <div key={sim.id}>
                      <SimulationRow sim={sim} onAction={doAction} onDetails={setSelectedSimulation} pendingAction={pendingAction} />
                    </div>
                  ))}
                </div>
              </Panel>
            )}
          </>
        )}

        {/* ═══════════════════════════════════════════════════════════════════
           TAB: RISK ANALYSIS
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'history' && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <h2 className="text-lg font-black text-white">Simulation History</h2>
                <Pill className="border-gold/25 bg-gold/10 text-gold">{fmt(filteredHistory.length)} shown</Pill>
                <Pill className="border-white/10 bg-white/5 text-white/45">{fmt(data.history.length)} total</Pill>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <ActionBtn icon={Download} label={pendingAction === 'export:json' ? 'Exporting' : 'Export All'} onClick={() => exportReport('json')} disabled={pendingAction === 'export:json'} small />
                <ActionBtn icon={RefreshCw} label="Refresh" onClick={refresh} small />
              </div>
            </div>

            <Panel className="p-4">
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
                <label className="space-y-1">
                  <span className="text-[9px] font-bold uppercase tracking-wider text-white/30">Status</span>
                  <select value={historyStatus} onChange={(e) => setHistoryStatus(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs font-bold text-white outline-none focus:border-gold/40">
                    <option value="all">All statuses</option>
                    {['queued', 'running', 'paused', 'completed', 'failed', 'stopped', 'rolled_back'].map((status) => <option key={status} value={status}>{status.replace(/_/g, ' ')}</option>)}
                  </select>
                </label>
                <label className="space-y-1">
                  <span className="text-[9px] font-bold uppercase tracking-wider text-white/30">Algorithm</span>
                  <select value={historyAlgorithm} onChange={(e) => setHistoryAlgorithm(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs font-bold text-white outline-none focus:border-gold/40">
                    <option value="all">All algorithms</option>
                    {historyAlgorithms.map((algorithm) => <option key={algorithm} value={algorithm}>{algorithm}</option>)}
                  </select>
                </label>
                <label className="space-y-1">
                  <span className="text-[9px] font-bold uppercase tracking-wider text-white/30">Date Range</span>
                  <select value={historyDateRange} onChange={(e) => setHistoryDateRange(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs font-bold text-white outline-none focus:border-gold/40">
                    <option value="all">All dates</option>
                    <option value="24h">Last 24 hours</option>
                    <option value="7d">Last 7 days</option>
                    <option value="30d">Last 30 days</option>
                    <option value="90d">Last 90 days</option>
                  </select>
                </label>
                <label className="space-y-1">
                  <span className="text-[9px] font-bold uppercase tracking-wider text-white/30">Asset Type</span>
                  <select value={historyAssetType} onChange={(e) => setHistoryAssetType(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs font-bold text-white outline-none focus:border-gold/40">
                    <option value="all">All asset types</option>
                    {historyAssetTypes.map((assetType) => <option key={assetType} value={assetType}>{assetType}</option>)}
                  </select>
                </label>
                <label className="space-y-1">
                  <span className="text-[9px] font-bold uppercase tracking-wider text-white/30">Risk Level</span>
                  <select value={historyRisk} onChange={(e) => setHistoryRisk(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs font-bold text-white outline-none focus:border-gold/40">
                    <option value="all">All risk levels</option>
                    {historyRisks.map((risk) => <option key={risk} value={risk}>{risk}</option>)}
                  </select>
                </label>
              </div>
            </Panel>

            <Panel className="p-5">
              {filteredHistory.length === 0 ? (
                <EmptyBlock label="No simulation history matches the selected filters." />
              ) : (
                <div className="space-y-3">
                  {filteredHistory.map((row) => {
                    const sim = data.simulations.find((item) => item.id === row.id)
                    const colors = statusColor(row.status)
                    const canDelete = canDeleteSimulationStatus(row.status)
                    return (
                      <div key={row.id} className="rounded-xl border border-white/8 bg-white/[0.018] p-4">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <h3 className="truncate text-sm font-black text-white">{row.name}</h3>
                              <Pill className={cn(colors.bg, colors.border, colors.text)}>{row.status.replace(/_/g, ' ')}</Pill>
                              <Pill className={riskBadge(row.riskLevel)}>{row.riskLevel}</Pill>
                            </div>
                            <div className="mt-1 text-[11px] font-semibold text-white/40">
                              <span className="font-mono">{row.sourceAlgorithm}</span>
                              <span className="mx-1.5 text-gold">-&gt;</span>
                              <span className="font-mono text-emerald-300">{row.targetAlgorithm}</span>
                              <span className="mx-2 text-white/20">|</span>
                              <span>{row.assetName || 'Unknown Asset'}</span>
                            </div>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <ActionBtn icon={Eye} label="View Details" onClick={() => sim && setSelectedSimulation(sim)} disabled={!sim} small />
                            <ActionBtn icon={RefreshCw} label={pendingAction === 'simulate' ? 'Queued' : 'Re-Run'} onClick={() => startSimulation({ fromAlgo: row.sourceAlgorithm, toAlgo: row.targetAlgorithm, migrationType: 'history_rerun', dryRun: row.runMode === 'dry_run' })} disabled={pendingAction === 'simulate'} variant="gold" small />
                            <ActionBtn icon={Download} label={pendingAction === `${row.id}:export:json` ? 'Exporting' : 'Export Report'} onClick={() => exportSimulation(row.id, 'json')} disabled={pendingAction === `${row.id}:export:json`} small />
                            <ActionBtn icon={Upload} label={pendingAction === `${row.id}:restore_snapshot` ? 'Restoring' : 'Restore Snapshot'} onClick={() => doAction(row.id, 'restore_snapshot')} disabled={row.snapshots < 1 || pendingAction === `${row.id}:restore_snapshot`} small />
                            {canDelete && <ActionBtn icon={Trash2} label={pendingAction === `${row.id}:delete` ? 'Deleting' : 'Delete'} onClick={() => { if (window.confirm('Delete this completed simulation and purge its execution artifacts? Audit and security records will remain.')) doAction(row.id, 'delete') }} disabled={pendingAction === `${row.id}:delete`} variant="danger" small />}
                          </div>
                        </div>

                        <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-6">
                          {[
                            ['Assets', fmt(row.assets || 0)],
                            ['Asset Type', row.assetType || 'service'],
                            ['Risk Score', `${row.riskScore}`],
                            ['Compliance', `${row.complianceScore}%`],
                            ['Duration', row.duration || '--'],
                            ['Events', fmt(row.eventCount || 0)],
                          ].map(([label, value]) => (
                            <div key={label} className="rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2">
                              <div className="text-[8px] font-bold uppercase tracking-wider text-white/25">{label}</div>
                              <div className="mt-1 truncate font-mono text-xs font-black text-white/70">{value}</div>
                            </div>
                          ))}
                        </div>

                        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-semibold text-white/35">
                          <span>Created {timeStr(row.createdAt)} ({relTime(row.createdAt)})</span>
                          <span>Started {row.startedAt ? timeStr(row.startedAt) : '--'}</span>
                          <span>Completed {row.completedAt ? timeStr(row.completedAt) : '--'}</span>
                          <span>Snapshots {fmt(row.snapshots || 0)}</span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </Panel>
          </>
        )}

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

              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                {[
                  { label: 'Restore Previous Keys', icon: Key, desc: 'Revert to classical key pairs', action: 'rollback' },
                  { label: 'Revert Certificates', icon: Lock, desc: 'Restore original certificate chain', action: 'rollback' },
                  { label: 'Restore TLS Config', icon: Globe2, desc: 'Reset TLS to pre-migration state', action: 'rollback' },
                  { label: 'Emergency Recovery', icon: ShieldAlert, desc: 'Full environment restore', action: 'rollback' },
                  { label: 'Create Snapshot', icon: Save, desc: 'Capture all eligible recovery points', action: 'snapshot' },
                ].map((item) => {
                  const Icon = item.icon
                  const isSnapshot = item.action === 'snapshot'
                  const confirmBulk = () => {
                    if (isSnapshot || window.confirm(`${item.label}: request rollback for ALL eligible workflows?\n\nSandbox simulations roll back immediately. Operational migrations are marked rollback-requested and wait for an approved executor.`)) {
                      doBulkAction(item.action, 'all')
                    }
                  }
                  return (
                    <button key={item.label} type="button" onClick={confirmBulk} disabled={pendingAction === `bulk:all:${item.action}`}
                      className={cn('flex flex-col items-center gap-3 rounded-xl border p-5 text-center transition disabled:pointer-events-none disabled:opacity-45',
                        isSnapshot ? 'border-gold/20 bg-gold/[0.04] hover:border-gold/35 hover:bg-gold/[0.07]' : 'border-red-500/15 bg-red-500/[0.03] hover:border-red-500/30 hover:bg-red-500/[0.06]')}>
                      <div className={cn('flex h-12 w-12 items-center justify-center rounded-full border', isSnapshot ? 'border-gold/30 bg-gold/10' : 'border-red-500/25 bg-red-500/10')}>
                        <Icon className={cn('h-6 w-6', isSnapshot ? 'text-gold' : 'text-red-300')} />
                      </div>
                      <div className="text-sm font-bold text-white/80">{pendingAction === `bulk:all:${item.action}` ? 'Processing...' : item.label}</div>
                      <div className="text-[11px] text-white/35">{item.desc}</div>
                    </button>
                  )
                })}
              </div>
            </Panel>

            <Panel className="p-5">
              <SectionHead icon={History}>Rollback-Eligible Workflows</SectionHead>
              {rollbackEligibleWorkflows.length === 0 ? (
                <EmptyBlock label="No workflows are currently eligible for rollback." />
              ) : (
                <div className="space-y-2">
                  {rollbackEligibleWorkflows.map((sim) => (
                    <div key={sim.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/6 bg-white/[0.015] px-4 py-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <div className="truncate text-sm font-bold text-white/80">{sim.name}</div>
                          <Pill className={modeBadge(sim.runMode)}>{modeLabel(sim)}</Pill>
                        </div>
                        <div className="text-[11px] text-white/35">{sim.fromAlgo} → {sim.toAlgo} · {sim.environment}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Pill className={cn(statusColor(sim.status).bg, statusColor(sim.status).border, statusColor(sim.status).text)}>{sim.status}</Pill>
                        <ActionBtn icon={RotateCcw} label={pendingAction === `${sim.id}:rollback` ? 'Rolling Back' : 'Rollback'} onClick={() => doAction(sim.id, 'rollback')} disabled={pendingAction === `${sim.id}:rollback`} variant="danger" small />
                        <ActionBtn icon={Save} label={pendingAction === `${sim.id}:snapshot` ? 'Capturing' : 'Snapshot'} onClick={() => doAction(sim.id, 'snapshot')} disabled={pendingAction === `${sim.id}:snapshot`} small />
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
                            <span key={c}>
                              <Pill className="border-white/10 bg-white/5 text-white/40">{c}</Pill>
                            </span>
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
