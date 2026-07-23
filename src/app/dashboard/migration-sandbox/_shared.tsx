/**
 * Migration Sandbox — shared types, style tokens, utils, and UI atoms.
 * Used by MigrationSandbox.tsx (shell + core tabs), TwinPanels.tsx
 * (Digital Twin / Dependency Graph / Topology), and OpsPanels.tsx
 * (Simulation Builder / Telemetry / Performance / Validation / Reports).
 */
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { AlertTriangle, ArrowDownRight, ArrowUpRight, CheckCircle2 } from 'lucide-react'
import { cn } from '@/lib/utils'

/* ═══════════════════════════════════════════════════════════════════════════
   TYPES — core simulation model
   ═══════════════════════════════════════════════════════════════════════════ */

export type SimulationStatus = 'running' | 'completed' | 'failed' | 'queued' | 'paused' | 'rollback_requested' | 'rolled_back' | 'stopped'

export type SimEvent = {
  id: string
  type: string
  message: string
  severity: string
  timestamp: string
}

export type Simulation = {
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

export type RiskFactor = {
  label: string
  count: number
  severity: string
  impact: string
}

export type Recommendation = {
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

export type ComplianceItem = {
  framework: string
  control: string
  status: string
  score: number
}

export type WorkflowPhase = {
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

export type PqcStackItem = {
  name: string
  standard: string
  status: string
  usage: number
}

export type SimulationHistoryRow = {
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

export type LogEntry = {
  id: string
  jobId: string
  type: string
  message: string
  severity: string
  timestamp: string
}

export type SandboxSummary = {
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

/* ═══════════════════════════════════════════════════════════════════════════
   TYPES — Digital Twin & enterprise intelligence payload
   ═══════════════════════════════════════════════════════════════════════════ */

export type TwinSummary = {
  totalNodes: number
  nodesWithEvidence: number
  coveragePct: number
  fidelityPct: number
  inventoryRecordsCloned: number
  certificatesCloned: number
  trustRelationships: number
  runtimeSignalsSampled: number
  environments: string[]
}

export type TwinIsolation = {
  scope: string
  productionWrites: string
  guarantees: string[]
  excludedDatasets: string[]
}

export type TwinComponentGroup = { id: string; label: string; assets: number; vulnerable: number; critical: number }

export type TwinNode = {
  id: string
  name: string
  type: string
  component: string
  componentLabel: string
  environment: string
  region: string | null
  owner: string
  criticality: string
  algorithms: string[]
  protocols: string[]
  inventoryItems: number
  vulnerableItems: number
  exposures: number
  criticalExposures: number
  certificates: number
  quantumSafeCerts: number
  expiringCerts: number
  runtimeSignals: number
  hasEvidence: boolean
}

export type DigitalTwinPayload = {
  generatedAt: string
  summary: TwinSummary
  isolation: TwinIsolation
  componentGroups: TwinComponentGroup[]
}

export type GraphRef = { id: string; name: string }

export type GraphNode = {
  id: string
  name: string
  type: string
  environment: string
  criticality: string
  dependsOn: GraphRef[]
  usedBy: GraphRef[]
  certificates: Array<{ id: string; name: string; algorithm: string; quantumSafe: boolean }>
  blastRadius: number
  impactedAssets: GraphRef[]
  criticalExposures: number
  vulnerableItems: number
  impactScore: number
}

export type GraphEdge = { source: string; target: string; type: string; origin: 'observed' | 'inferred' }

export type DependencyGraphSummary = {
  stats: { totalNodes: number; observedEdges: number; inferredEdges: number; connectedNodes: number; maxBlastRadius: number }
  topNodes: GraphNode[]
}

export type HeatStatus = 'ready' | 'attention' | 'high_risk' | 'blocked'

export type TopologyPayload = {
  zones: Array<{ environment: string; assets: Array<{ id: string; name: string; type: string; component: string; criticality: string; status: HeatStatus }>; counts: Record<HeatStatus, number> }>
  totals: Record<HeatStatus, number>
}

export type FailurePrediction = {
  id: string
  category: string
  label: string
  probabilityPct: number
  severity: string
  affectedAssets: string[]
  evidence: string
  recommendation: string
}

export type FailurePredictionPayload = { predictions: FailurePrediction[]; overallFailureProbabilityPct: number }

export type BenchmarkMetric = {
  id: string
  label: string
  unit: string
  before: number
  after: number
  deltaPct: number
  improved: boolean
  betterWhenLower: boolean
  note: string
}

export type PerformanceBenchmarkPayload = {
  available: boolean
  methodology: string
  sampleSize: number
  algorithmMix: { rsaSharePct: number; eccSharePct: number; pqcSharePct: number; symmetricSharePct: number; weakSharePct?: number }
  metrics: BenchmarkMetric[]
}

export type BusinessImpactCategory = {
  id: string
  label: string
  assets: number
  criticalAssets: number
  vulnerableAssets: number
  criticalExposures: number
  downtimeRisk: string
  revenueSensitive: boolean
  businessCriticality: string
  predictedDowntimeMin: number
  guidance: string
}

export type BusinessImpactPayload = {
  categories: BusinessImpactCategory[]
  summary: {
    categoriesIdentified: number
    revenueSensitiveAtRisk: number
    predictedCumulativeDowntimeMin: number
    downtimeCostBand: string
    overallFailureProbabilityPct: number
    note: string
  }
}

export type RollbackChecklistItem = { id: string; label: string; covered: boolean; detail: string }

export type RollbackAnalysisPayload = {
  available: boolean
  successProbabilityPct: number
  snapshotCoveragePct: number
  simulationsWithSnapshots: number
  totalSandboxSimulations: number
  rtoMinutes: number
  rpoMinutes: number
  downtimePredictionMin: number
  automaticRollbackReady: boolean
  restorationChecklist: RollbackChecklistItem[]
  history: { rolledBackWorkflows: number; failedWorkflows: number }
  note: string
}

export type SophiaBlocker = { id: string; label: string; probabilityPct: number; severity: string; affectedAssets: string[]; recommendation: string }

export type SophiaSequenceStep = { order: number; component: string; label: string; assets: number; vulnerableAssets: number; rationale: string }

export type SophiaPayload = {
  verdict: 'no_data' | 'at_risk' | 'progressing' | 'ready'
  migrationConfidencePct: number
  compatibilityScorePct: number
  riskScorePct: number
  rollbackConfidencePct: number
  aiConfidencePct: number
  recommendedSequence: SophiaSequenceStep[]
  detectedBlockers: SophiaBlocker[]
  rootCauses: string[]
  businessImpactSummary: BusinessImpactPayload['summary']
  executiveSummary: string
  priorityActions: string[]
  narrative: string[]
  evidenceBasis: { assets: number; inventoryRecords: number; exposures: number; certificates: number; relationships: number; runtimeEvents: number; simulations: number }
}

export type ApprovalGateDecision = { jobId: string; jobName: string; decision: string; decidedBy: string | null; decidedAt: string | null; note: string | null }

export type ApprovalGatePayload = {
  simulationStatus: 'PASS' | 'FAILED' | 'PENDING'
  productionReady: boolean
  aiRecommendation: string
  gates: Array<{ id: string; label: string; value: string; status: 'pass' | 'warn' | 'fail' }>
  eligibleSimulations: Array<{ id: string; name: string; completedAt: string | null; approval: Record<string, unknown> | null }>
  decisions: ApprovalGateDecision[]
  counts: { completed: number; failed: number; running: number; approved: number; rejected: number; reviewRequested: number }
  guarantee: string
}

export type TimelineEntry = { id: string; at: string; jobId: string | null; jobName: string | null; type: string; severity: string; label: string }

export type TelemetrySeries = { id: string; label: string; unit: string; source: string; values: number[] }

export type TelemetryFramePayload = {
  generatedAt: string
  windowMinutes: number
  bucketMinutes: number
  series: TelemetrySeries[]
  totals: { cryptoOps: number; migrationEvents: number; errors: number; warnings: number }
  simulatedLoad: Array<{ jobId: string; jobName: string; progress: number; modeled: true; cpuPct: number; memoryMb: number; latencyMs: number; phase: string }>
  note: string
}

export type SimulationTypeDef = {
  id: string
  label: string
  description: string
  focus: string[]
  baseDurationMs: number
  perAssetMs: number
  recommendedFor: string
}

export type PipelineStage = { id: string; label: string; detail: string; at: number; gate?: boolean }

export type SandboxSnapshot = {
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
  // Digital Twin & enterprise intelligence (optional: older cached snapshots)
  digitalTwin?: DigitalTwinPayload
  dependencyGraph?: DependencyGraphSummary
  topology?: TopologyPayload
  failurePrediction?: FailurePredictionPayload
  performanceBenchmark?: PerformanceBenchmarkPayload
  rollbackAnalysis?: RollbackAnalysisPayload
  businessImpact?: BusinessImpactPayload
  sophia?: SophiaPayload
  approvalGate?: ApprovalGatePayload
  timeline?: TimelineEntry[]
  telemetryFrame?: TelemetryFramePayload
  simulationTypes?: SimulationTypeDef[]
  pipeline?: PipelineStage[]
}

export type OperatorNotice = {
  kind: 'success' | 'error' | 'info'
  message: string
}

export type SandboxActionHandler = (id: string, action: string, options?: Record<string, unknown>) => void | Promise<void>

export type SimulationAsset = {
  id: string
  name: string
  type: string
  environment: string
  region?: string | null
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

/* ═══════════════════════════════════════════════════════════════════════════
   STYLE TOKENS
   ═══════════════════════════════════════════════════════════════════════════ */

export const GOLD = '#FBBF24'
export const GREEN = '#22C55E'
export const RED = '#EF4444'
export const BLUE = '#38BDF8'
export const PURPLE = '#A78BFA'
export const CYAN = '#22D3EE'
export const ORANGE = '#F97316'

export const GLASS =
  'migration-sandbox-panel group relative overflow-hidden rounded-xl border border-gold/15 bg-[#060F1C]/80 backdrop-blur-2xl shadow-[inset_0_1px_0_rgba(255,255,255,0.06),0_0_30px_rgba(0,0,0,0.3)] transition-all duration-500 hover:border-gold/40 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.12),0_8px_32px_rgba(0,0,0,0.4),0_0_48px_rgba(251,191,36,0.08)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/50 before:to-transparent'

/* ═══════════════════════════════════════════════════════════════════════════
   UTILS
   ═══════════════════════════════════════════════════════════════════════════ */

export function fmt(v: number) { return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(v || 0))) }
export function pct(v: number) { return `${Math.max(0, Math.min(100, Math.round(v || 0)))}%` }

export function relTime(v: string | null) {
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

export function timeStr(v: string | null) {
  if (!v) return '--'
  const d = new Date(v)
  return Number.isFinite(d.getTime()) ? d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '--'
}

export function statusColor(s: string) {
  if (s === 'running') return { bg: 'bg-emerald-500/12', border: 'border-emerald-500/30', text: 'text-emerald-300', dot: 'bg-emerald-400' }
  if (s === 'completed') return { bg: 'bg-emerald-500/12', border: 'border-emerald-500/30', text: 'text-emerald-300', dot: 'bg-emerald-400' }
  if (s === 'failed') return { bg: 'bg-red-500/12', border: 'border-red-500/30', text: 'text-red-300', dot: 'bg-red-400' }
  if (s === 'rollback_requested') return { bg: 'bg-orange-500/12', border: 'border-orange-500/30', text: 'text-orange-300', dot: 'bg-orange-400' }
  if (s === 'rolled_back') return { bg: 'bg-purple-500/12', border: 'border-purple-500/30', text: 'text-purple-300', dot: 'bg-purple-400' }
  if (s === 'stopped') return { bg: 'bg-slate-500/12', border: 'border-slate-500/30', text: 'text-slate-300', dot: 'bg-slate-400' }
  if (s === 'paused') return { bg: 'bg-amber-500/12', border: 'border-amber-500/30', text: 'text-amber-300', dot: 'bg-amber-400' }
  return { bg: 'bg-sky-500/10', border: 'border-sky-500/25', text: 'text-sky-300', dot: 'bg-sky-400' }
}

export function modeBadge(mode: string) {
  if (mode === 'dry_run') return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
  if (mode === 'simulation') return 'border-purple-500/30 bg-purple-500/10 text-purple-300'
  if (mode === 'remediation') return 'border-red-500/25 bg-red-500/10 text-red-300'
  if (mode === 'actual_migration') return 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300'
  return 'border-white/10 bg-white/5 text-white/45'
}

export function simModeLabel(sim: Simulation) {
  return sim.runModeLabel || sim.runMode?.replace(/_/g, ' ') || 'Workflow'
}

export function riskBadge(level: string) {
  if (level === 'critical') return 'bg-red-500/15 border-red-500/30 text-red-300'
  if (level === 'high') return 'bg-orange-500/15 border-orange-500/30 text-orange-300'
  if (level === 'medium') return 'bg-amber-500/15 border-amber-500/30 text-amber-300'
  return 'bg-emerald-500/12 border-emerald-500/30 text-emerald-300'
}

export function complianceColor(status: string) {
  if (status === 'compliant') return 'text-emerald-300'
  if (status === 'partial') return 'text-amber-300'
  if (status === 'pending') return 'text-sky-300'
  return 'text-red-300'
}

export function severityIcon(s: string) {
  if (s === 'critical' || s === 'error') return <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
  if (s === 'warning' || s === 'high') return <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
  if (s === 'info') return <CheckCircle2 className="h-3.5 w-3.5 text-sky-400" />
  return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
}

export function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

export function progressBarColor(v: number, status: string) {
  if (status === 'failed') return RED
  if (status === 'completed') return GREEN
  if (v >= 70) return GREEN
  if (v >= 40) return GOLD
  return ORANGE
}

export function canDeleteSimulationStatus(status: string) {
  return ['completed', 'failed', 'stopped', 'rolled_back'].includes(status)
}

export function heatColor(status: HeatStatus) {
  if (status === 'blocked') return { color: RED, label: 'Migration Blocked', badge: 'border-red-500/30 bg-red-500/12 text-red-300' }
  if (status === 'high_risk') return { color: ORANGE, label: 'High Risk', badge: 'border-orange-500/30 bg-orange-500/12 text-orange-300' }
  if (status === 'attention') return { color: GOLD, label: 'Needs Attention', badge: 'border-amber-500/30 bg-amber-500/12 text-amber-300' }
  return { color: GREEN, label: 'Ready', badge: 'border-emerald-500/30 bg-emerald-500/12 text-emerald-300' }
}

export function downloadJson(filename: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function historyDateMatches(value: string, range: string) {
  if (range === 'all') return true
  const ms = new Date(value).getTime()
  if (!Number.isFinite(ms)) return false
  const days = range === '24h' ? 1 : range === '7d' ? 7 : range === '30d' ? 30 : 90
  return Date.now() - ms <= days * 24 * 60 * 60 * 1000
}

/* ═══════════════════════════════════════════════════════════════════════════
   UI ATOMS
   ═══════════════════════════════════════════════════════════════════════════ */

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cn(GLASS, className)}><div className="relative z-10 h-full">{children}</div></section>
}

export function SectionHead({ icon: Icon, children, suffix }: { icon: LucideIcon; children: ReactNode; suffix?: ReactNode }) {
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

export function Pill({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-bold tracking-wide', className)}>{children}</span>
}

export function ProgressBar({ value, color = GOLD, height = 'h-1.5' }: { value: number; color?: string; height?: string }) {
  const w = Math.max(0, Math.min(100, value))
  return (
    <div className={cn('overflow-hidden rounded-full bg-white/8', height)}>
      <div className="h-full rounded-full transition-all duration-700 ease-out" style={{ width: `${w}%`, background: `linear-gradient(90deg, ${color}aa, ${color})`, boxShadow: `0 0 12px ${color}55` }} />
    </div>
  )
}

export function EmptyBlock({ label }: { label: string }) {
  return <div className="rounded-lg border border-white/5 bg-white/[0.02] p-8 text-center text-xs font-semibold text-white/35">{label}</div>
}

export function ActionBtn({ icon: Icon, label, onClick, variant = 'default', small, disabled }: { icon: LucideIcon; label: string; onClick?: () => void; variant?: 'default' | 'gold' | 'danger' | 'success'; small?: boolean; disabled?: boolean }) {
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

export function MetricTile({ label, value, detail, icon: Icon, color, trend }: { label: string; value: string; detail?: string; icon: LucideIcon; color: string; trend?: number }) {
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

export function ScoreGauge({ value, size = 120, label }: { value: number; size?: number; label: string }) {
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

/** Minimal inline sparkline for real bucketed telemetry series. */
export function Sparkline({ values, color = CYAN, height = 42 }: { values: number[]; color?: string; height?: number }) {
  const width = 220
  const max = Math.max(1, ...values)
  const step = values.length > 1 ? width / (values.length - 1) : width
  const points = values.map((v, i) => `${Math.round(i * step)},${Math.round(height - (v / max) * (height - 4)) + 2}`).join(' ')
  return (
    <svg viewBox={`0 0 ${width} ${height + 4}`} className="w-full" style={{ height: height + 4 }} preserveAspectRatio="none">
      <polyline points={points} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" style={{ filter: `drop-shadow(0 0 4px ${color}66)` }} />
      <polyline points={`0,${height + 2} ${points} ${width},${height + 2}`} fill={`${color}14`} stroke="none" />
    </svg>
  )
}
