/**
 * Enterprise Migration Sandbox & Digital Twin — real-time post-quantum
 * migration simulation platform.
 *
 * 15 enterprise tabs: Overview · Digital Twin · Simulation Builder ·
 * Migration Pipeline · Dependency Graph · Topology · Telemetry · Performance ·
 * Validation · Rollback · Compliance · AI Insights · Execution Logs ·
 * Reports · History.
 *
 * Data: /api/v1/sandbox (snapshot + SSE + Supabase realtime). Simulations
 * execute exclusively against the metadata-only digital twin — production is
 * never modified. The Production Approval Gate records governed decisions.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  AlertTriangle,
  BarChart3,
  BookOpen,
  Bot,
  Boxes,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Cpu,
  Download,
  Eye,
  FileText,
  FlaskConical,
  Gauge,
  GitBranch,
  Globe2,
  History,
  Key,
  Layers,
  Lock,
  Map as MapIcon,
  Network,
  Pause,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Square,
  Target,
  Terminal,
  ThumbsDown,
  ThumbsUp,
  Trash2,
  Upload,
  X,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { cn } from '@/lib/utils'
import { clearMigrationHandoff, readMigrationHandoff, type MigrationHandoff } from '@/app/dashboard/quantum-readiness/_advisor'
import {
  ActionBtn,
  BLUE,
  CYAN,
  EmptyBlock,
  GOLD,
  GREEN,
  MetricTile,
  ORANGE,
  Panel,
  Pill,
  ProgressBar,
  PURPLE,
  RED,
  ScoreGauge,
  SectionHead,
  canDeleteSimulationStatus,
  downloadJson,
  fmt,
  heatColor,
  historyDateMatches,
  modeBadge,
  objectRecord,
  pct,
  progressBarColor,
  relTime,
  riskBadge,
  severityIcon,
  simModeLabel,
  statusColor,
  timeStr,
  type ApprovalGatePayload,
  type LogEntry,
  type OperatorNotice,
  type PipelineStage,
  type SandboxActionHandler,
  type SandboxSnapshot,
  type Simulation,
  type SimulationHistoryRow,
  type SophiaPayload,
  type TimelineEntry,
  type WorkflowPhase,
} from './_shared'
import { DependencyGraphTab, DigitalTwinTab, TopologyTab, useTwinDetail } from './TwinPanels'
import { PerformanceTab, ReportsTab, SimulationBuilderTab, TelemetryTab, ValidationTab } from './OpsPanels'

/* ═══════════════════════════════════════════════════════════════════════════
   TYPES + EMPTY STATE
   ═══════════════════════════════════════════════════════════════════════════ */

type ActiveTab =
  | 'overview' | 'twin' | 'builder' | 'pipeline' | 'dependencies' | 'topology'
  | 'telemetry' | 'performance' | 'validation' | 'rollback' | 'compliance'
  | 'ai' | 'logs' | 'reports' | 'history'

type TerminalLineLevel = 'command' | 'telemetry' | 'event' | 'nist' | 'success' | 'warning' | 'error'
type TerminalLine = {
  id: string
  timestamp: string
  level: TerminalLineLevel
  prompt: string
  command: string
  detail?: string
}

type ApprovalHandler = (jobId: string, decision: 'approve' | 'reject' | 'request_review', note?: string) => void | Promise<void>

// Fallback pipeline definition until the first snapshot arrives.
const DEFAULT_PIPELINE: PipelineStage[] = [
  { id: 'discovery', label: 'Discovery', detail: '', at: 0 },
  { id: 'crypto_inventory', label: 'Crypto Inventory', detail: '', at: 5 },
  { id: 'dependency_mapping', label: 'Dependency Mapping', detail: '', at: 11 },
  { id: 'business_impact', label: 'Business Impact Analysis', detail: '', at: 17 },
  { id: 'migration_planning', label: 'Migration Planning', detail: '', at: 23 },
  { id: 'digital_twin', label: 'Digital Twin Generation', detail: '', at: 29 },
  { id: 'pqc_simulation', label: 'PQC Migration Simulation', detail: '', at: 36 },
  { id: 'compatibility_validation', label: 'Compatibility Validation', detail: '', at: 50 },
  { id: 'performance_benchmark', label: 'Performance Benchmark', detail: '', at: 60 },
  { id: 'security_validation', label: 'Security Validation', detail: '', at: 69 },
  { id: 'rollback_validation', label: 'Rollback Validation', detail: '', at: 78 },
  { id: 'compliance_validation', label: 'Compliance Validation', detail: '', at: 86 },
  { id: 'ai_risk_analysis', label: 'AI Risk Analysis', detail: '', at: 93 },
  { id: 'executive_approval', label: 'Executive Approval', detail: '', at: 100, gate: true },
  { id: 'production_ready', label: 'Production Ready', detail: '', at: 100, gate: true },
]

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
   LOCAL UTILS (history derivation + planner-handoff terminal)
   ═══════════════════════════════════════════════════════════════════════════ */

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
      snapshots: Array.isArray(sim.metadata?.snapshots) ? (sim.metadata.snapshots as unknown[]).length : 0,
      eventCount: sim.eventCount,
    }
  })
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
  if (phase.includes('preparation') || phase.includes('discovery') || phase.includes('inventory')) {
    return `qguard-sandbox snapshot create --job ${quoteArg(sim.id)} --asset ${quoteArg(sim.assetName)} --rollback-checkpoint`
  }
  if (phase.includes('assessment') || phase.includes('impact') || phase.includes('planning')) {
    return `qguard-pqc assess --job ${quoteArg(sim.id)} --source ${quoteArg(sim.fromAlgo)} --target ${quoteArg(sim.toAlgo)} --nist "FIPS-203,FIPS-204,FIPS-205"`
  }
  if (phase.includes('verification') || phase.includes('validation') || phase.includes('benchmark')) {
    return `qguard-pqc verify --job ${quoteArg(sim.id)} --handshake --certificate-chain --target ${quoteArg(sim.toAlgo)}`
  }
  if (phase.includes('finalization') || phase.includes('ai_risk') || sim.status === 'completed') {
    return `qguard-evidence collect --plan ${quoteArg(planId)} --job ${quoteArg(sim.id)} --format "nist-pqc-readiness"`
  }
  return `qguard-pqc simulate --job ${quoteArg(sim.id)} --mode "digital-twin" --source ${quoteArg(sim.fromAlgo)} --target ${quoteArg(sim.toAlgo)}`
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
    const jobLogs = recentLogs.filter((log) => log.jobId === sim.id).slice(-4)

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
   DATA HOOK — /api/v1/sandbox + SSE + Supabase Realtime
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

  const startSimulation = useCallback(async (params: Record<string, unknown>) => {
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

  // Production Approval Gate decision — records the governed decision with
  // audit evidence server-side. Never mutates production systems.
  const approveSimulation = useCallback(async (jobId: string, decision: 'approve' | 'reject' | 'request_review', note?: string) => {
    if (!token) return
    const key = `${jobId}:approval:${decision}`
    setPendingAction(key)
    try {
      const response = await fetch(`/api/v1/sandbox/jobs/${jobId}/approval`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ decision, note }),
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(payload?.error?.message || 'Failed to record approval decision')
      applySnapshot(payload?.data?.snapshot)
      showNotice(decision === 'reject' ? 'info' : 'success',
        decision === 'approve' ? 'Simulation approved for production planning — decision recorded with audit evidence.'
        : decision === 'reject' ? 'Simulation rejected — decision recorded with audit evidence.'
        : 'Review requested — decision recorded with audit evidence.')
      await fetchSnapshot()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to record approval decision'
      setError(message)
      showNotice('error', message)
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

  return { data, loading, error, notice, pendingAction, sseActive, refresh: fetchSnapshot, doAction, doBulkAction, startSimulation, approveSimulation, exportReport, exportSimulation, notify: showNotice }
}

/* ═══════════════════════════════════════════════════════════════════════════
   HANDOFF TERMINAL CONSOLE
   ═══════════════════════════════════════════════════════════════════════════ */

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

/* ═══════════════════════════════════════════════════════════════════════════
   ENTERPRISE PIPELINE STAGE RAIL (per-simulation)
   ═══════════════════════════════════════════════════════════════════════════ */

function StageRail({ sim, pipeline }: { sim: Simulation; pipeline: PipelineStage[] }) {
  const meta = objectRecord(sim.metadata)
  const isEnterprise = Number(meta.pipelineVersion) >= 2 || typeof meta.simulationType === 'string'
  const stages = isEnterprise
    ? pipeline.filter((stage) => !stage.gate)
    : [
        { id: 'preparation', label: 'Preparation', at: 0 },
        { id: 'assessment', label: 'Risk Assessment', at: 22 },
        { id: 'execution', label: 'Sandbox Execution', at: 48 },
        { id: 'verification', label: 'Verification', at: 74 },
        { id: 'finalization', label: 'Finalization', at: 94 },
      ] as PipelineStage[]
  const stageHistory = Array.isArray(meta.stageHistory) ? meta.stageHistory as Array<Record<string, unknown>> : []
  const enteredAt = new Map(stageHistory.map((entry) => [String(entry.id || ''), String(entry.enteredAt || '')]))
  const terminal = ['failed', 'stopped', 'rolled_back', 'rollback_requested'].includes(sim.status)

  return (
    <div className="overflow-x-auto pb-1">
      <div className="flex min-w-max items-start gap-0">
        {stages.map((stage, index) => {
          const done = sim.status === 'completed' || (sim.progress > stage.at && sim.phaseId !== stage.id)
          const current = !terminal && sim.status !== 'completed' && sim.phaseId === stage.id
          const at = enteredAt.get(stage.id)
          return (
            <div key={stage.id} className="flex items-start">
              <div className="flex w-[92px] flex-col items-center text-center">
                <div className={cn('flex h-7 w-7 items-center justify-center rounded-full border text-[10px] font-black transition',
                  done ? 'border-emerald-500/50 bg-emerald-500/20 text-emerald-300'
                  : current ? 'border-gold/60 bg-gold/15 text-gold shadow-[0_0_12px_rgba(251,191,36,0.4)]'
                  : terminal ? 'border-red-500/25 bg-red-500/[0.06] text-red-300/60'
                  : 'border-white/12 bg-white/[0.03] text-white/30')}>
                  {done ? <CheckCircle2 className="h-3.5 w-3.5" /> : index + 1}
                </div>
                <div className={cn('mt-1.5 text-[8px] font-bold uppercase leading-tight tracking-wide',
                  done ? 'text-emerald-300/80' : current ? 'text-gold' : 'text-white/30')}>
                  {stage.label}
                </div>
                {at && <div className="mt-0.5 font-mono text-[7px] text-white/25">{timeStr(at)}</div>}
                {current && <div className="mt-0.5 font-mono text-[8px] font-black text-gold">{sim.progress}%</div>}
              </div>
              {index < stages.length - 1 && (
                <div className={cn('mt-3.5 h-px w-4', done ? 'bg-emerald-500/40' : 'bg-white/10')} />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   PRODUCTION APPROVAL GATE BANNER
   ═══════════════════════════════════════════════════════════════════════════ */

function ApprovalGateBanner({ gate, pendingAction, onDecision, onExport, exportPending }: {
  gate: ApprovalGatePayload
  pendingAction: string | null
  onDecision: ApprovalHandler
  onExport: () => void
  exportPending: boolean
}) {
  const statusStyles = gate.simulationStatus === 'PASS'
    ? { border: 'border-emerald-500/30', bg: 'bg-emerald-500/[0.04]', text: 'text-emerald-300', icon: ShieldCheck }
    : gate.simulationStatus === 'FAILED'
      ? { border: 'border-red-500/30', bg: 'bg-red-500/[0.04]', text: 'text-red-300', icon: ShieldAlert }
      : { border: 'border-sky-500/25', bg: 'bg-sky-500/[0.03]', text: 'text-sky-300', icon: ShieldQuestion }
  const StatusIcon = statusStyles.icon
  const undecided = gate.eligibleSimulations.filter((sim) => !sim.approval)
  const primary = undecided[0] || null

  return (
    <Panel className={cn('p-5', statusStyles.border, statusStyles.bg)}>
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="flex min-w-0 items-start gap-4">
          <div className={cn('flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border', statusStyles.border, statusStyles.bg)}>
            <StatusIcon className={cn('h-7 w-7', statusStyles.text)} />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-black uppercase tracking-wider text-white/85">Production Approval Gate</h2>
              <Pill className={cn('text-[11px]', statusStyles.border, statusStyles.bg, statusStyles.text)}>
                Simulation {gate.simulationStatus}
              </Pill>
              {gate.productionReady && <Pill className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300">PRODUCTION READY</Pill>}
            </div>
            <p className="mt-1.5 max-w-2xl text-xs leading-relaxed text-white/55">{gate.aiRecommendation}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {gate.gates.map((g) => (
                <span key={g.id}>
                  <Pill className={cn(
                    g.status === 'pass' ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300'
                    : g.status === 'warn' ? 'border-amber-500/25 bg-amber-500/10 text-amber-300'
                    : 'border-red-500/25 bg-red-500/10 text-red-300'
                  )}>
                    {g.label}: {g.value}
                  </Pill>
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="flex shrink-0 flex-col items-stretch gap-2">
          <div className="flex flex-wrap gap-2">
            <ActionBtn
              icon={ThumbsUp}
              label={primary && pendingAction === `${primary.id}:approval:approve` ? 'Approving…' : 'Approve for Production'}
              variant="success"
              disabled={!primary || gate.simulationStatus !== 'PASS' || pendingAction !== null}
              onClick={() => {
                if (!primary) return
                if (window.confirm(`Approve "${primary.name}" for production planning?\n\nThis records a governed decision with audit evidence. No production system is modified — execution happens through the operational migration workflow.`)) {
                  void onDecision(primary.id, 'approve')
                }
              }}
            />
            <ActionBtn
              icon={ThumbsDown}
              label={primary && pendingAction === `${primary.id}:approval:reject` ? 'Rejecting…' : 'Reject'}
              variant="danger"
              disabled={!primary || pendingAction !== null}
              onClick={() => {
                if (!primary) return
                if (window.confirm(`Reject "${primary.name}"?\n\nThe rejection is recorded with audit evidence and the simulation stays available for re-runs.`)) {
                  void onDecision(primary.id, 'reject')
                }
              }}
            />
            <ActionBtn
              icon={Eye}
              label={primary && pendingAction === `${primary.id}:approval:request_review` ? 'Requesting…' : 'Request Review'}
              disabled={!primary || pendingAction !== null}
              onClick={() => primary && void onDecision(primary.id, 'request_review')}
            />
            <ActionBtn icon={Download} label={exportPending ? 'Exporting…' : 'Export Report'} onClick={onExport} disabled={exportPending} variant="gold" />
          </div>
          <div className="text-right text-[9px] font-semibold text-white/30">
            {primary ? `Next decision: ${primary.name}` : gate.counts.completed > 0 ? 'All completed simulations have decisions recorded.' : 'Complete a simulation to unlock approval decisions.'}
          </div>
        </div>
      </div>

      {gate.decisions.length > 0 && (
        <div className="mt-4 border-t border-white/8 pt-3">
          <div className="mb-2 text-[9px] font-bold uppercase tracking-wider text-white/30">Decision Log ({gate.counts.approved} approved · {gate.counts.rejected} rejected · {gate.counts.reviewRequested} review)</div>
          <div className="flex flex-wrap gap-2">
            {gate.decisions.slice(0, 6).map((decision) => (
              <div key={`${decision.jobId}-${decision.decidedAt}`} className="rounded-lg border border-white/8 bg-black/20 px-3 py-1.5 text-[10px] font-semibold text-white/50">
                <span className={cn('font-black uppercase', decision.decision === 'approve' ? 'text-emerald-300' : decision.decision === 'reject' ? 'text-red-300' : 'text-sky-300')}>{decision.decision.replace(/_/g, ' ')}</span>
                <span className="mx-1.5 text-white/20">·</span>
                <span className="truncate">{decision.jobName}</span>
                <span className="mx-1.5 text-white/20">·</span>
                <span>{decision.decidedBy || 'operator'}</span>
                <span className="mx-1.5 text-white/20">·</span>
                <span>{relTime(decision.decidedAt)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      <p className="mt-3 text-[9px] leading-relaxed text-white/25">{gate.guarantee}</p>
    </Panel>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   LIVE MIGRATION TIMELINE PANEL
   ═══════════════════════════════════════════════════════════════════════════ */

function TimelinePanel({ timeline, limit = 14 }: { timeline: TimelineEntry[]; limit?: number }) {
  if (timeline.length === 0) return <EmptyBlock label="No migration events yet — the live timeline populates as simulations execute." />
  return (
    <div className="space-y-0">
      {timeline.slice(0, limit).map((entry, index) => (
        <div key={entry.id} className="grid grid-cols-[64px_20px_1fr] gap-2">
          <div className="pt-0.5 text-right font-mono text-[10px] font-bold text-white/40">{timeStr(entry.at)}</div>
          <div className="flex flex-col items-center">
            <span className={cn('mt-1 h-2.5 w-2.5 rounded-full border-2',
              entry.severity === 'error' || entry.severity === 'critical' ? 'border-red-400 bg-red-500/30'
              : entry.severity === 'warning' ? 'border-amber-400 bg-amber-500/30'
              : entry.severity === 'success' ? 'border-emerald-400 bg-emerald-500/30'
              : 'border-sky-400 bg-sky-500/30')} />
            {index < Math.min(timeline.length, limit) - 1 && <span className="w-px flex-1 bg-white/8" />}
          </div>
          <div className="pb-3">
            <div className="text-[11px] font-semibold leading-relaxed text-white/65">{entry.label}</div>
            <div className="mt-0.5 flex flex-wrap gap-x-2 text-[9px] font-bold uppercase tracking-wider text-white/25">
              <span>{entry.type}</span>
              {entry.jobName && <span className="text-gold/60">{entry.jobName}</span>}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   SOPHIA AI PANEL (AI Insights tab)
   ═══════════════════════════════════════════════════════════════════════════ */

function SophiaPanel({ sophia, pendingAction }: { sophia: SophiaPayload; pendingAction: string | null }) {
  void pendingAction
  const verdictStyle = sophia.verdict === 'ready'
    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
    : sophia.verdict === 'at_risk'
      ? 'border-red-500/30 bg-red-500/10 text-red-300'
      : sophia.verdict === 'progressing'
        ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
        : 'border-sky-500/25 bg-sky-500/10 text-sky-300'
  return (
    <>
      <Panel className="border-violet-400/20 bg-violet-500/[0.02] p-5">
        <SectionHead icon={Bot} suffix={<Pill className={verdictStyle}>{sophia.verdict.replace(/_/g, ' ').toUpperCase()}</Pill>}>
          Sophia AI Migration Advisor — Executive Analysis
        </SectionHead>
        <p className="text-xs leading-relaxed text-white/65">{sophia.executiveSummary}</p>

        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
          {[
            { label: 'Migration Confidence', value: sophia.migrationConfidencePct, color: sophia.migrationConfidencePct >= 70 ? GREEN : sophia.migrationConfidencePct >= 45 ? GOLD : RED },
            { label: 'Compatibility Score', value: sophia.compatibilityScorePct, color: sophia.compatibilityScorePct >= 70 ? GREEN : GOLD },
            { label: 'Risk Score', value: sophia.riskScorePct, color: sophia.riskScorePct >= 70 ? GREEN : sophia.riskScorePct >= 40 ? GOLD : RED },
            { label: 'Rollback Confidence', value: sophia.rollbackConfidencePct, color: sophia.rollbackConfidencePct >= 70 ? GREEN : GOLD },
            { label: 'AI Confidence', value: sophia.aiConfidencePct, color: sophia.aiConfidencePct >= 70 ? GREEN : BLUE },
          ].map((score) => (
            <div key={score.label} className="rounded-xl border border-white/8 bg-white/[0.02] p-3">
              <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">{score.label}</div>
              <div className="mt-1 font-mono text-2xl font-black" style={{ color: score.color }}>{score.value}%</div>
              <div className="mt-1.5"><ProgressBar value={score.value} color={score.color} /></div>
            </div>
          ))}
        </div>

        {sophia.narrative.length > 0 && (
          <div className="mt-4 space-y-1.5">
            {sophia.narrative.map((line) => (
              <div key={line} className="flex items-start gap-2 rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px] leading-relaxed text-white/55">
                <Bot className="mt-0.5 h-3.5 w-3.5 shrink-0 text-violet-300" />
                {line}
              </div>
            ))}
          </div>
        )}

        <div className="mt-3 flex flex-wrap gap-2 text-[9px] font-bold uppercase tracking-wider text-white/25">
          <span>Evidence basis:</span>
          <span>{fmt(sophia.evidenceBasis.assets)} assets</span>
          <span>· {fmt(sophia.evidenceBasis.inventoryRecords)} inventory</span>
          <span>· {fmt(sophia.evidenceBasis.certificates)} certificates</span>
          <span>· {fmt(sophia.evidenceBasis.relationships)} relationships</span>
          <span>· {fmt(sophia.evidenceBasis.runtimeEvents)} runtime events</span>
          <span>· {fmt(sophia.evidenceBasis.simulations)} simulations</span>
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel className="p-5">
          <SectionHead icon={GitBranch}>Recommended Migration Sequence</SectionHead>
          {sophia.recommendedSequence.length === 0 ? (
            <EmptyBlock label="Sequence recommendations appear once assets are discovered and classified." />
          ) : (
            <div className="space-y-2">
              {sophia.recommendedSequence.map((step) => (
                <div key={step.component} className="flex items-start gap-3 rounded-lg border border-white/6 bg-white/[0.015] p-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-gold/40 bg-gold/10 text-xs font-black text-gold">{step.order}</div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-bold text-white/85">{step.label}</span>
                      <Pill className="border-white/10 bg-white/5 text-white/40">{fmt(step.assets)} asset(s)</Pill>
                      {step.vulnerableAssets > 0 && <Pill className="border-amber-500/25 bg-amber-500/10 text-amber-300">{fmt(step.vulnerableAssets)} vulnerable</Pill>}
                    </div>
                    <p className="mt-1 text-[11px] leading-relaxed text-white/45">{step.rationale}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel className="p-5">
          <SectionHead icon={ShieldAlert} suffix={<Pill className="border-red-500/25 bg-red-500/10 text-red-300">{fmt(sophia.detectedBlockers.length)} blockers</Pill>}>
            Detected Blockers & Root Causes
          </SectionHead>
          {sophia.detectedBlockers.length === 0 ? (
            <EmptyBlock label="No critical blockers detected in current evidence." />
          ) : (
            <div className="space-y-2">
              {sophia.detectedBlockers.map((blocker) => (
                <div key={blocker.id} className="rounded-lg border border-red-500/15 bg-red-500/[0.03] p-3">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-xs font-bold text-white/85">{blocker.label}</span>
                    <span className="font-mono text-sm font-black text-red-300">{blocker.probabilityPct}%</span>
                  </div>
                  <p className="mt-1 text-[11px] text-white/45">{blocker.recommendation}</p>
                </div>
              ))}
            </div>
          )}
          {sophia.rootCauses.length > 0 && (
            <div className="mt-4">
              <div className="mb-1.5 text-[9px] font-bold uppercase tracking-wider text-white/30">Root Cause Analysis</div>
              <div className="space-y-1.5">
                {sophia.rootCauses.map((cause) => (
                  <div key={cause} className="flex items-start gap-2 rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px] leading-relaxed text-white/55">
                    <Target className="mt-0.5 h-3.5 w-3.5 shrink-0 text-gold" />
                    {cause}
                  </div>
                ))}
              </div>
            </div>
          )}
        </Panel>
      </div>

      {sophia.priorityActions.length > 0 && (
        <Panel className="p-5">
          <SectionHead icon={Zap}>Priority Actions</SectionHead>
          <div className="grid gap-2 md:grid-cols-2">
            {sophia.priorityActions.map((action, index) => (
              <div key={action} className="flex items-start gap-3 rounded-lg border border-white/6 bg-white/[0.015] p-3">
                <div className={cn('flex h-6 w-6 shrink-0 items-center justify-center rounded-lg border text-[10px] font-black',
                  index === 0 ? 'border-red-500/40 bg-red-500/15 text-red-300' : index === 1 ? 'border-amber-500/40 bg-amber-500/15 text-amber-300' : 'border-sky-500/40 bg-sky-500/15 text-sky-300')}>
                  {index + 1}
                </div>
                <p className="text-[11px] leading-relaxed text-white/60">{action}</p>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   SIMULATION DETAILS MODAL
   ═══════════════════════════════════════════════════════════════════════════ */

function SimulationDetailsModal({
  simulation,
  onClose,
  onAction,
  onApproval,
  pendingAction,
  pipeline,
}: {
  simulation: Simulation | null
  onClose: () => void
  onAction: SandboxActionHandler
  onApproval: ApprovalHandler
  pendingAction: string | null
  pipeline: PipelineStage[]
}) {
  if (!simulation) return null
  const sc = statusColor(simulation.status)
  const snapshots = Array.isArray(simulation.metadata?.snapshots) ? simulation.metadata.snapshots as Array<Record<string, unknown>> : []
  const busy = (action: string) => pendingAction === `${simulation.id}:${action}`
  const deleteAllowed = simulation.isSandbox && canDeleteSimulationStatus(simulation.status)
  const approval = objectRecord(simulation.metadata?.approval)
  const approvalDecision = String(approval.decision || '')
  const canDecide = simulation.isSandbox && simulation.status === 'completed'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onClick={onClose}>
      <div className="max-h-[88vh] w-full max-w-4xl overflow-hidden rounded-2xl border border-gold/25 bg-[#0A1525]/95 shadow-2xl backdrop-blur-xl" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-4 border-b border-white/10 p-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="truncate text-lg font-black text-white">{simulation.name}</h3>
              <Pill className={cn(sc.bg, sc.border, sc.text)}>{simulation.status.replace(/_/g, ' ')}</Pill>
              <Pill className={modeBadge(simulation.runMode)}>{simModeLabel(simulation)}</Pill>
              <Pill className={riskBadge(simulation.riskLevel)}>{simulation.riskLevel}</Pill>
              {approvalDecision && (
                <Pill className={approvalDecision === 'approve' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : approvalDecision === 'reject' ? 'border-red-500/30 bg-red-500/10 text-red-300' : 'border-sky-500/25 bg-sky-500/10 text-sky-300'}>
                  {approvalDecision === 'approve' ? 'approved' : approvalDecision === 'reject' ? 'rejected' : 'review requested'}
                </Pill>
              )}
            </div>
            <p className="mt-1 text-xs text-white/45">{simulation.assetName} | {simulation.environment} | {simulation.owner}</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-lg p-1.5 text-white/40 hover:bg-white/10 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-[calc(88vh-82px)] overflow-y-auto p-5">
          <div className="mb-5 rounded-xl border border-white/8 bg-white/[0.02] p-4">
            <div className="mb-3 text-xs font-black uppercase tracking-wider text-white/55">Enterprise Migration Pipeline</div>
            <StageRail sim={simulation} pipeline={pipeline} />
          </div>

          <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              ['Source', simulation.fromAlgo],
              ['Target', simulation.toAlgo],
              ['Phase', simulation.phase],
              ['ETA', simulation.eta || '--'],
              ['Mode', simModeLabel(simulation)],
              ['Engine', simulation.engineStatus || '--'],
              ['Progress', `${simulation.progress}%`],
              ['Asset Type', simulation.assetType],
              ['Scenario', String(objectRecord(simulation.metadata).simulationTypeLabel || simulation.migrationType || '--')],
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

          {canDecide && (
            <div className="mb-5 rounded-xl border border-gold/20 bg-gold/[0.03] p-4">
              <div className="mb-2 text-xs font-black uppercase tracking-wider text-gold">Production Approval Gate</div>
              <p className="mb-3 text-[11px] leading-relaxed text-white/45">
                Record a governed decision for this completed simulation. Approval never modifies production — it produces
                audit evidence consumed by the operational migration workflow.
              </p>
              <div className="flex flex-wrap gap-2">
                <ActionBtn icon={ThumbsUp} label={busy('approval:approve') ? 'Approving…' : 'Approve for Production'} variant="success"
                  onClick={() => { if (window.confirm(`Approve "${simulation.name}" for production planning?`)) void onApproval(simulation.id, 'approve') }}
                  disabled={pendingAction !== null} />
                <ActionBtn icon={ThumbsDown} label={busy('approval:reject') ? 'Rejecting…' : 'Reject'} variant="danger"
                  onClick={() => { if (window.confirm(`Reject "${simulation.name}"?`)) void onApproval(simulation.id, 'reject') }}
                  disabled={pendingAction !== null} />
                <ActionBtn icon={Eye} label={busy('approval:request_review') ? 'Requesting…' : 'Request Review'}
                  onClick={() => void onApproval(simulation.id, 'request_review')}
                  disabled={pendingAction !== null} />
              </div>
              {approvalDecision && (
                <div className="mt-2 text-[10px] font-semibold text-white/40">
                  Last decision: <span className="font-black text-white/70">{approvalDecision.replace(/_/g, ' ')}</span> by {String(approval.decidedBy || 'operator')} · {relTime(String(approval.decidedAt || '') || null)}
                </div>
              )}
            </div>
          )}

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

/* ═══════════════════════════════════════════════════════════════════════════
   SIMULATION ROW (Expandable) + WORKFLOW ROWS
   ═══════════════════════════════════════════════════════════════════════════ */

function SimulationRow({
  sim,
  onAction,
  onDetails,
  pendingAction,
  pipeline,
}: {
  sim: Simulation
  onAction: SandboxActionHandler
  onDetails: (sim: Simulation) => void
  pendingAction: string | null
  pipeline: PipelineStage[]
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
            <Pill className={modeBadge(sim.runMode)}>{simModeLabel(sim)}</Pill>
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
          <div className="mb-3 rounded-lg border border-white/6 bg-black/20 px-3 py-2.5">
            <StageRail sim={sim} pipeline={pipeline} />
          </div>

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
          <Pill className={modeBadge(workflow.runMode)}>{simModeLabel(workflow)}</Pill>
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
  const { data, loading, error, notice, pendingAction, sseActive, refresh, doAction, doBulkAction, startSimulation, approveSimulation, exportReport, exportSimulation, notify } = useSandbox()
  const plannerHandoffPlanId = useMemo(() => {
    if (typeof window === 'undefined') return ''
    return new URLSearchParams(window.location.search).get('planId') || ''
  }, [])
  const [tab, setTab] = useState<ActiveTab>(() => plannerHandoffPlanId ? 'pipeline' : 'overview')
  // Roadmap handed off from the AI Migration Advisor™ (localStorage payload).
  const [advisorHandoff, setAdvisorHandoff] = useState<MigrationHandoff | null>(() => readMigrationHandoff())
  const [selectedSimulation, setSelectedSimulation] = useState<Simulation | null>(null)
  const [logFilter, setLogFilter] = useState('')
  const [historyStatus, setHistoryStatus] = useState('all')
  const [historyAlgorithm, setHistoryAlgorithm] = useState('all')
  const [historyDateRange, setHistoryDateRange] = useState('all')
  const [historyAssetType, setHistoryAssetType] = useState('all')
  const [historyRisk, setHistoryRisk] = useState('all')

  // Twin detail loads lazily the first time a twin-powered tab opens.
  const twinTabsActive = tab === 'twin' || tab === 'dependencies' || tab === 'topology'
  const { detail: twinDetail, loading: twinLoading, error: twinError, reload: twinReload } = useTwinDetail(twinTabsActive)

  const s = data.summary
  const pipeline = data.pipeline && data.pipeline.length > 0 ? data.pipeline : DEFAULT_PIPELINE
  const simulationTypes = data.simulationTypes || []
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
    { key: 'twin', label: 'Digital Twin', icon: Boxes },
    { key: 'builder', label: 'Simulation Builder', icon: Plus },
    { key: 'pipeline', label: `Migration Pipeline (${s.totalSimulations})`, icon: FlaskConical },
    { key: 'dependencies', label: 'Dependency Graph', icon: Network },
    { key: 'topology', label: 'Topology', icon: MapIcon },
    { key: 'telemetry', label: 'Telemetry', icon: Activity },
    { key: 'performance', label: 'Performance', icon: Gauge },
    { key: 'validation', label: 'Validation', icon: ShieldAlert },
    { key: 'rollback', label: 'Rollback', icon: RotateCcw },
    { key: 'compliance', label: 'Compliance', icon: ShieldCheck },
    { key: 'ai', label: 'AI Insights', icon: Bot },
    { key: 'logs', label: 'Execution Logs', icon: Terminal },
    { key: 'reports', label: 'Reports', icon: FileText },
    { key: 'history', label: `History (${data.history.length})`, icon: History },
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

  const handleBuilderStart = useCallback(async (params: Record<string, unknown>) => {
    const result = await startSimulation(params)
    if (result) setTab('pipeline')
    return result
  }, [startSimulation])

  const benchmarkHandshake = data.performanceBenchmark?.available
    ? data.performanceBenchmark.metrics.find((m) => m.id === 'tls_handshake')
    : undefined
  const benchmarkDuration = data.performanceBenchmark?.available
    ? data.performanceBenchmark.metrics.find((m) => m.id === 'migration_duration')
    : undefined

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
      <SimulationDetailsModal simulation={selectedSimulation} onClose={() => setSelectedSimulation(null)} onAction={doAction} onApproval={approveSimulation} pendingAction={pendingAction} pipeline={pipeline} />
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
                <p className="text-[11px] font-medium text-white/40">Enterprise Digital Twin · Post-Quantum Migration Simulation Platform</p>
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
            <ActionBtn icon={FileText} label="Reports" onClick={() => setTab('reports')} />
            <ActionBtn icon={Plus} label="New Simulation" onClick={() => setTab('builder')} variant="gold" />

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
              Use the roadmap's waves to scope simulations in the Simulation Builder — target algorithms resolve through the {advisorHandoff.cryptoPolicyProfile?.profile || 'active'} crypto-policy profile. Acknowledging clears the handoff.
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
                  <button type="button" onClick={() => setTab('pipeline')} className="w-full rounded-lg border border-gold/20 bg-gold/[0.04] py-2 text-center text-[11px] font-bold text-gold hover:bg-gold/[0.08]">
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
           TAB: OVERVIEW — Executive Dashboard + Approval Gate
           ═══════════════════════════════════════════════════════════════════ */}
        {tab === 'overview' && (
          <>
            {data.approvalGate && (
              <ApprovalGateBanner
                gate={data.approvalGate}
                pendingAction={pendingAction}
                onDecision={approveSimulation}
                onExport={() => setTab('reports')}
                exportPending={false}
              />
            )}

            {/* ─── Executive Command Metrics ────────────────────────────────── */}
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
              <MetricTile label="Migration Confidence" value={pct(data.sophia?.migrationConfidencePct ?? 0)} detail={data.sophia?.verdict === 'ready' ? 'Evidence-backed' : data.sophia?.verdict === 'at_risk' ? 'Blockers present' : 'Building evidence'} icon={Target} color={(data.sophia?.migrationConfidencePct ?? 0) >= 70 ? GREEN : (data.sophia?.migrationConfidencePct ?? 0) >= 45 ? GOLD : RED} />
              <MetricTile label="Production Readiness" value={data.approvalGate?.simulationStatus ?? 'PENDING'} detail={data.approvalGate?.productionReady ? 'Approved + gates pass' : `${data.approvalGate?.counts.approved ?? 0} approval(s)`} icon={ShieldCheck} color={data.approvalGate?.simulationStatus === 'PASS' ? GREEN : data.approvalGate?.simulationStatus === 'FAILED' ? RED : BLUE} />
              <MetricTile label="Compatibility Score" value={pct(data.sophia?.compatibilityScorePct ?? 0)} detail="Protocol + library fit" icon={Cpu} color={(data.sophia?.compatibilityScorePct ?? 0) >= 70 ? GREEN : GOLD} />
              <MetricTile label="Rollback Confidence" value={pct(data.rollbackAnalysis?.successProbabilityPct ?? 0)} detail={`RTO ${data.rollbackAnalysis?.rtoMinutes ?? 0}m · RPO ${data.rollbackAnalysis?.rpoMinutes ?? 0}m`} icon={RotateCcw} color={(data.rollbackAnalysis?.successProbabilityPct ?? 0) >= 70 ? GREEN : GOLD} />
              <MetricTile label="AI Confidence" value={pct(data.sophia?.aiConfidencePct ?? 0)} detail="Evidence depth" icon={Bot} color={(data.sophia?.aiConfidencePct ?? 0) >= 70 ? GREEN : PURPLE} />
              <MetricTile label="Performance Impact" value={benchmarkHandshake ? `${benchmarkHandshake.deltaPct > 0 ? '+' : ''}${benchmarkHandshake.deltaPct}%` : '--'} detail="TLS handshake (modeled)" icon={Gauge} color={benchmarkHandshake?.improved ? GREEN : GOLD} />
              <MetricTile label="Downtime Prediction" value={`${data.rollbackAnalysis?.downtimePredictionMin ?? 0}m`} detail={`${data.failurePrediction?.overallFailureProbabilityPct ?? 0}% failure probability`} icon={Clock3} color={(data.rollbackAnalysis?.downtimePredictionMin ?? 0) > 20 ? RED : (data.rollbackAnalysis?.downtimePredictionMin ?? 0) > 5 ? GOLD : GREEN} />
              <MetricTile label="Migration Duration" value={benchmarkDuration ? `${Math.round(benchmarkDuration.after)}m` : '--'} detail="Per asset (modeled)" icon={Zap} color={CYAN} />
              <MetricTile label="Affected Assets" value={fmt(s.vulnerableAssets)} detail={`${fmt(s.totalAssets)} total in twin`} icon={Boxes} color={s.vulnerableAssets > 0 ? ORANGE : GREEN} />
              <MetricTile label="Critical Risks" value={fmt(s.criticalExposures)} detail={s.criticalExposures > 0 ? 'Blocking approval' : 'None open'} icon={ShieldAlert} color={s.criticalExposures > 0 ? RED : GREEN} />
            </div>

            {/* ─── Heat strip + ops row ─────────────────────────────────────── */}
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-8">
              {data.topology && (['ready', 'attention', 'high_risk', 'blocked'] as const).map((status) => {
                const h = heatColor(status)
                return <div key={status}><MetricTile label={h.label} value={fmt(data.topology!.totals[status])} detail="Topology heat" icon={status === 'ready' ? ShieldCheck : status === 'blocked' ? Lock : Shield} color={h.color} /></div>
              })}
              <MetricTile label="Sandbox Runs" value={fmt(s.totalSimulations)} detail={`${s.running} running / ${s.queued} queued`} icon={FlaskConical} color={GOLD} />
              <MetricTile label="Live Workflows" value={fmt(s.runningWorkflows)} detail={s.backgroundEngine === 'active' ? 'Engine active' : 'Engine idle'} icon={Activity} color={GREEN} />
              <MetricTile label="PQC Readiness" value={pct(s.pqcReadiness)} icon={Shield} color={s.pqcReadiness >= 70 ? GREEN : GOLD} detail={s.pqcReadiness >= 80 ? 'Strong' : 'In Progress'} />
              <MetricTile label="Compliance" value={pct(data.complianceScore)} icon={ShieldCheck} color={data.complianceScore >= 70 ? GREEN : GOLD} detail={data.complianceScore >= 80 ? 'Compliant' : 'Review Needed'} />
            </div>

            {/* ─── Workflow + Score Gauges ──────────────────────────────────── */}
            <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
              <Panel className="p-5">
                <SectionHead icon={Layers}>Migration Workflow Pipeline</SectionHead>
                <WorkflowTimeline phases={data.workflowPhases} />
              </Panel>

              <div className="space-y-4">
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

                <Panel className="p-5">
                  <SectionHead icon={Clock3} suffix={<button type="button" onClick={() => setTab('pipeline')} className="text-[10px] font-bold text-gold hover:text-amber-300">Full Timeline</button>}>
                    Live Migration Timeline
                  </SectionHead>
                  <TimelinePanel timeline={data.timeline || []} limit={6} />
                </Panel>
              </div>
            </div>

            {/* ─── Active Sims Quick View + Sophia summary ─────────────────── */}
            <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
              <Panel className="p-5">
                <SectionHead icon={FlaskConical} suffix={
                  <div className="flex gap-2">
                    {s.running > 0 && <ActionBtn icon={Pause} label={pendingAction === 'bulk:pause' ? 'Pausing' : 'Pause All'} onClick={() => doBulkAction('pause')} disabled={pendingAction === 'bulk:pause'} variant="default" small />}
                    {s.paused > 0 && <ActionBtn icon={Play} label={pendingAction === 'bulk:resume' ? 'Resuming' : 'Resume All'} onClick={() => doBulkAction('resume')} disabled={pendingAction === 'bulk:resume'} variant="success" small />}
                  </div>
                }>Active Sandbox Simulations</SectionHead>
                {data.simulations.length === 0 ? (
                  <EmptyBlock label={operationalWorkflows.length > 0 ? `${fmt(operationalWorkflows.length)} operational migration workflow(s) are queued outside sandbox simulation.` : "No simulations yet. Open the Simulation Builder to launch your first PQC migration rehearsal."} />
                ) : (
                  <div className="space-y-2">
                    {data.simulations.slice(0, 5).map((sim) => (
                      <div key={sim.id}>
                        <SimulationRow sim={sim} onAction={doAction} onDetails={setSelectedSimulation} pendingAction={pendingAction} pipeline={pipeline} />
                      </div>
                    ))}
                    {data.simulations.length > 5 && (
                      <button type="button" onClick={() => setTab('pipeline')} className="w-full rounded-lg border border-white/8 py-2 text-center text-[11px] font-bold text-gold hover:bg-gold/5">
                        View all {data.simulations.length} sandbox runs →
                      </button>
                    )}
                  </div>
                )}
              </Panel>

              <Panel className="p-5">
                <SectionHead icon={Bot} suffix={<button type="button" onClick={() => setTab('ai')} className="text-[10px] font-bold text-gold hover:text-amber-300">Full Analysis</button>}>
                  Sophia AI Migration Insights
                </SectionHead>
                {data.sophia ? (
                  <>
                    <p className="mb-3 text-[11px] leading-relaxed text-white/55">{data.sophia.executiveSummary}</p>
                    {data.sophia.priorityActions.length > 0 && (
                      <div className="space-y-2">
                        {data.sophia.priorityActions.slice(0, 4).map((action, index) => (
                          <div key={action} className="flex items-start gap-2 rounded-lg border border-white/6 bg-white/[0.015] p-2.5">
                            <div className={cn('mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-black',
                              index === 0 ? 'bg-red-500/20 text-red-300' : index === 1 ? 'bg-amber-500/20 text-amber-300' : 'bg-sky-500/20 text-sky-300')}>
                              {index + 1}
                            </div>
                            <span className="text-[11px] leading-relaxed text-white/55">{action}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                ) : (
                  <EmptyBlock label="Sophia analysis arrives with the next snapshot." />
                )}
              </Panel>
            </div>

            {/* ─── Operational queue + logs preview ────────────────────────── */}
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

        {/* ═══ TAB: DIGITAL TWIN ═══ */}
        {tab === 'twin' && (
          <DigitalTwinTab detail={twinDetail} loading={twinLoading} error={twinError} reload={twinReload} pqcStack={data.pqcStack} simulationTypes={simulationTypes} />
        )}

        {/* ═══ TAB: SIMULATION BUILDER ═══ */}
        {tab === 'builder' && (
          <SimulationBuilderTab simulationTypes={simulationTypes.length > 0 ? simulationTypes : []} pipeline={pipeline} pendingAction={pendingAction} onStart={handleBuilderStart} />
        )}

        {/* ═══ TAB: MIGRATION PIPELINE ═══ */}
        {tab === 'pipeline' && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <h2 className="text-lg font-black text-white">{plannerHandoffPlanId ? 'Migration Plan Simulations' : 'Migration Pipeline'}</h2>
                <Pill className="border-gold/25 bg-gold/10 text-gold">{fmt(visibleSimulations.length)} total</Pill>
                {plannerHandoffPlanId && <Pill className="border-sky-500/25 bg-sky-500/10 text-sky-300">Plan handoff</Pill>}
              </div>
              <div className="flex items-center gap-2">
                {s.running > 0 && <ActionBtn icon={Pause} label={pendingAction === 'bulk:pause' ? 'Pausing' : 'Pause All'} onClick={() => doBulkAction('pause')} disabled={pendingAction === 'bulk:pause'} small />}
                {s.paused > 0 && <ActionBtn icon={Play} label={pendingAction === 'bulk:resume' ? 'Resuming' : 'Resume All'} onClick={() => doBulkAction('resume')} disabled={pendingAction === 'bulk:resume'} variant="success" small />}
                {s.failed > 0 && <ActionBtn icon={RefreshCw} label={pendingAction === 'bulk:retry' ? 'Retrying' : 'Retry Failed'} onClick={() => doBulkAction('retry')} disabled={pendingAction === 'bulk:retry'} variant="gold" small />}
                <ActionBtn icon={Save} label={pendingAction === 'bulk:snapshot' ? 'Capturing' : 'Snapshot All'} onClick={() => doBulkAction('snapshot')} disabled={pendingAction === 'bulk:snapshot'} small />
                <ActionBtn icon={Plus} label="New Simulation" onClick={() => setTab('builder')} variant="gold" />
              </div>
            </div>

            <Panel className="p-5">
              <SectionHead icon={GitBranch}>Enterprise Pipeline Stages</SectionHead>
              <div className="flex flex-wrap gap-1.5">
                {pipeline.map((stage, index) => (
                  <span key={stage.id}>
                    <Pill className={cn(stage.gate ? 'border-purple-500/25 bg-purple-500/10 text-purple-300' : 'border-white/10 bg-white/[0.03] text-white/50')}>
                      {index + 1}. {stage.label}
                    </Pill>
                  </span>
                ))}
              </div>
              <p className="mt-2 text-[10px] leading-relaxed text-white/30">
                Every simulation executes stages 1–13 automatically inside the digital twin. Executive Approval and Production
                Ready are human gates resolved through the Production Approval Gate — the engine never auto-approves production.
              </p>
            </Panel>

            {visibleSimulations.length === 0 ? (
              <Panel className="p-8">
                <EmptyBlock label={plannerHandoffPlanId ? "No simulations are linked to this migration plan yet. The sandbox stream will update this view when jobs are queued." : "No migration simulations found. Open the Simulation Builder to safely rehearse PQC migration workflows."} />
              </Panel>
            ) : (
              <Panel className="p-5">
                <div className="space-y-2">
                  {visibleSimulations.map((sim) => (
                    <div key={sim.id}>
                      <SimulationRow sim={sim} onAction={doAction} onDetails={setSelectedSimulation} pendingAction={pendingAction} pipeline={pipeline} />
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            <Panel className="p-5">
              <SectionHead icon={Clock3}>Live Migration Timeline</SectionHead>
              <TimelinePanel timeline={data.timeline || []} limit={20} />
            </Panel>
          </>
        )}

        {/* ═══ TAB: DEPENDENCY GRAPH ═══ */}
        {tab === 'dependencies' && (
          <DependencyGraphTab detail={twinDetail} loading={twinLoading} error={twinError} reload={twinReload} />
        )}

        {/* ═══ TAB: TOPOLOGY ═══ */}
        {tab === 'topology' && (
          <TopologyTab detail={twinDetail} loading={twinLoading} error={twinError} reload={twinReload} />
        )}

        {/* ═══ TAB: TELEMETRY ═══ */}
        {tab === 'telemetry' && (
          <TelemetryTab frame={data.telemetryFrame} sseActive={sseActive} />
        )}

        {/* ═══ TAB: PERFORMANCE ═══ */}
        {tab === 'performance' && (
          <PerformanceTab benchmark={data.performanceBenchmark} />
        )}

        {/* ═══ TAB: VALIDATION ═══ */}
        {tab === 'validation' && (
          <ValidationTab summary={s} riskFactors={data.riskFactors} failurePrediction={data.failurePrediction} sophia={data.sophia} />
        )}

        {/* ═══ TAB: ROLLBACK ═══ */}
        {tab === 'rollback' && (
          <>
            {data.rollbackAnalysis && (
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-6">
                <MetricTile label="Rollback Success" value={pct(data.rollbackAnalysis.successProbabilityPct)} detail={`${data.rollbackAnalysis.simulationsWithSnapshots}/${data.rollbackAnalysis.totalSandboxSimulations} sims with snapshots`} icon={RotateCcw} color={data.rollbackAnalysis.successProbabilityPct >= 70 ? GREEN : GOLD} />
                <MetricTile label="RTO" value={`${data.rollbackAnalysis.rtoMinutes}m`} detail="Recovery Time Objective" icon={Clock3} color={data.rollbackAnalysis.rtoMinutes <= 15 ? GREEN : GOLD} />
                <MetricTile label="RPO" value={`${data.rollbackAnalysis.rpoMinutes}m`} detail="Recovery Point Objective" icon={Save} color={data.rollbackAnalysis.rpoMinutes <= 5 ? GREEN : GOLD} />
                <MetricTile label="Downtime Prediction" value={`${data.rollbackAnalysis.downtimePredictionMin}m`} detail="If rollback triggers" icon={AlertTriangle} color={data.rollbackAnalysis.downtimePredictionMin > 20 ? RED : data.rollbackAnalysis.downtimePredictionMin > 5 ? GOLD : GREEN} />
                <MetricTile label="Snapshot Coverage" value={pct(data.rollbackAnalysis.snapshotCoveragePct)} detail="Simulations protected" icon={Shield} color={data.rollbackAnalysis.snapshotCoveragePct >= 50 ? GREEN : ORANGE} />
                <MetricTile label="Auto-Rollback" value={data.rollbackAnalysis.automaticRollbackReady ? 'READY' : 'NOT READY'} detail={data.rollbackAnalysis.automaticRollbackReady ? 'Coverage + clean history' : 'Raise snapshot coverage'} icon={Zap} color={data.rollbackAnalysis.automaticRollbackReady ? GREEN : ORANGE} />
              </div>
            )}

            {data.rollbackAnalysis && (
              <Panel className="p-5">
                <SectionHead icon={ShieldCheck}>Restoration Checklist</SectionHead>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {data.rollbackAnalysis.restorationChecklist.map((item) => (
                    <div key={item.id} className={cn('rounded-lg border p-3', item.covered ? 'border-emerald-500/20 bg-emerald-500/[0.03]' : 'border-amber-500/20 bg-amber-500/[0.03]')}>
                      <div className="flex items-center gap-2">
                        {item.covered ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" /> : <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />}
                        <span className="text-xs font-bold text-white/80">{item.label}</span>
                      </div>
                      <p className="mt-1.5 text-[10px] leading-relaxed text-white/40">{item.detail}</p>
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-[10px] leading-relaxed text-white/30">{data.rollbackAnalysis.note}</p>
              </Panel>
            )}

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
                          <Pill className={modeBadge(sim.runMode)}>{simModeLabel(sim)}</Pill>
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

        {/* ═══ TAB: COMPLIANCE ═══ */}
        {tab === 'compliance' && (
          <>
            <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
              <Panel className="p-5">
                <SectionHead icon={ShieldCheck}>Compliance Score</SectionHead>
                <div className="relative flex justify-center py-4">
                  <ScoreGauge value={data.complianceScore} size={160} label="Overall Compliance" />
                </div>
                <div className="mt-3 rounded-lg border border-white/8 bg-white/[0.02] p-3 text-center text-[11px] leading-relaxed text-white/45">
                  Validated continuously against NIST PQC, NSA CNSA 2.0, FIPS 140-3/203-205, ISO 27001, PCI DSS, SOC 2, HIPAA,
                  GDPR, and CISA quantum-readiness guidance — every status traces to live tenant evidence.
                </div>
              </Panel>

              <Panel className="p-5">
                <SectionHead icon={BookOpen} suffix={<Pill className="border-white/10 bg-white/5 text-white/40">{fmt(data.complianceItems.length)} frameworks</Pill>}>
                  Governance Validation
                </SectionHead>
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
              <SectionHead icon={FileText}>Compliance Evidence & Reports</SectionHead>
              <p className="mb-3 text-xs text-white/40">
                Generate audit-ready compliance evidence packages — including the framework validation table above, approval-gate
                decisions, and execution audit trails — from the Enterprise Report Center.
              </p>
              <ActionBtn icon={FileText} label="Open Report Center" onClick={() => setTab('reports')} variant="gold" />
            </Panel>
          </>
        )}

        {/* ═══ TAB: AI INSIGHTS ═══ */}
        {tab === 'ai' && (
          <>
            {data.sophia ? (
              <SophiaPanel sophia={data.sophia} pendingAction={pendingAction} />
            ) : (
              <Panel className="p-8"><EmptyBlock label="Sophia analysis arrives with the next snapshot." /></Panel>
            )}

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
          </>
        )}

        {/* ═══ TAB: EXECUTION LOGS ═══ */}
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

        {/* ═══ TAB: REPORTS ═══ */}
        {tab === 'reports' && (
          <ReportsTab snapshot={data} onNotice={notify} />
        )}

        {/* ═══ TAB: HISTORY ═══ */}
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
      </div>

      {/* ─── Footer ────────────────────────────────────────────────────── */}
      <footer className="border-t border-white/5 px-4 py-3">
        <div className="flex flex-col gap-2 text-[10px] font-mono uppercase tracking-wider text-white/25 md:flex-row md:items-center md:justify-between">
          <span>{error ? `⚠ ${error}` : 'Digital twin telemetry synchronized · Production isolated'}</span>
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
