/**
 * Migration Sandbox — the per-job Details dialog and the pipeline stage rail.
 *
 * The dialog opens from sandbox simulations AND from the operational migration
 * queue, and the two are different kinds of work. A simulation is run by the
 * sandbox engine against the digital twin, so the dialog shows its stage rail
 * and engine controls. An operational job (a Migration Planner cutover, a
 * Harvest Now remediation) is executed by an agent after approval, through
 * Live Migration — so the dialog shows what decides whether it moves (approval,
 * dispatch, executor, execution) and hands off to the page that runs it. The
 * sandbox engine's controls are never offered on it: the API refuses them.
 */
import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  CheckCircle2,
  Clock3,
  Download,
  ExternalLink,
  Eye,
  HelpCircle,
  Pause,
  Play,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  Square,
  ThumbsDown,
  ThumbsUp,
  Trash2,
  Upload,
  X,
  XCircle,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  ActionBtn,
  EmptyBlock,
  Pill,
  ProgressBar,
  canDeleteSimulationStatus,
  downloadJson,
  modeBadge,
  objectRecord,
  progressBarColor,
  relTime,
  riskBadge,
  severityIcon,
  simModeLabel,
  statusColor,
  timeStr,
  type OperationalWorkflowDetail,
  type PipelineStage,
  type SandboxActionHandler,
  type Simulation,
} from './_shared'

export type ApprovalHandler = (jobId: string, decision: 'approve' | 'reject' | 'request_review', note?: string) => void | Promise<void>

/* ═══════════════════════════════════════════════════════════════════════════
   ENTERPRISE PIPELINE STAGE RAIL (per-simulation)
   ═══════════════════════════════════════════════════════════════════════════ */

export function StageRail({ sim, pipeline }: { sim: Simulation; pipeline: PipelineStage[] }) {
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
   OPERATIONAL WORKFLOW DETAIL (agent-executed jobs)
   ═══════════════════════════════════════════════════════════════════════════ */

function humanize(value: string | null | undefined) {
  if (!value) return '--'
  return value.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim().replace(/^\w/, (c) => c.toUpperCase())
}

function approvalPill(op: OperationalWorkflowDetail) {
  if (!op.approvalReadable) return { label: 'approval unknown', className: 'border-slate-500/30 bg-slate-500/10 text-slate-300' }
  if (op.approval.state === 'rejected') return { label: 'rejected', className: 'border-red-500/30 bg-red-500/10 text-red-300' }
  if (op.approval.approved) return { label: 'approved', className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' }
  return { label: 'awaiting approval', className: 'border-amber-500/30 bg-amber-500/10 text-amber-300' }
}

const GATE_STYLE = {
  pass: { icon: CheckCircle2, box: 'border-emerald-500/25 bg-emerald-500/[0.04]', text: 'text-emerald-300', word: 'Ready' },
  pending: { icon: Clock3, box: 'border-sky-500/25 bg-sky-500/[0.04]', text: 'text-sky-300', word: 'Pending' },
  fail: { icon: XCircle, box: 'border-red-500/25 bg-red-500/[0.04]', text: 'text-red-300', word: 'Blocked' },
  unknown: { icon: HelpCircle, box: 'border-white/10 bg-white/[0.02]', text: 'text-white/45', word: 'Unknown' },
} as const

/** Stages where no agent can make progress until the operator acts. */
const STALLED_STAGES = new Set(['rejected', 'awaiting-approval', 'dispatch-blocked', 'no-capable-agent', 'no-online-agent', 'failed'])

function OperationalOverview({ simulation, op }: { simulation: Simulation; op: OperationalWorkflowDetail }) {
  const stalled = STALLED_STAGES.has(op.stage)
  const needsAgent = op.stage === 'no-capable-agent' || op.stage === 'no-online-agent'
  const agentLine = op.executor.fleetReadable
    ? `${op.executor.capable ?? 0} capable · ${op.executor.capableOnline ?? 0} online (${op.executor.enrolled ?? 0} enrolled in total)`
    : 'Agent fleet could not be read'
  const facts: Array<[string, string, string?]> = [
    ['Source', op.sourceLabel],
    ['Migration plan', op.planId || 'None (job-level approval)', op.planId || undefined],
    ['Phase', op.phaseName ? `${op.phaseName}${op.phaseIndex && op.totalPhases ? ` (${op.phaseIndex}/${op.totalPhases})` : ''}` : '--'],
    ['Strategy', op.strategy || '--'],
    ['Current crypto', simulation.fromAlgo],
    ['Target', simulation.toAlgo],
    ['Job type', humanize(simulation.migrationType)],
    ['Priority', op.priority || '--'],
    ['Executor role', `${op.executor.roleLabel} agent`, `Included in ${op.executor.plans.join(' and ')}`],
    ['Agents', agentLine],
    ['Dispatch', humanize(op.dispatch.status)],
    ['Assigned agent', op.executor.assignedAgent || 'Not claimed yet'],
    ['Created', simulation.createdAt ? `${timeStr(simulation.createdAt)} (${relTime(simulation.createdAt)})` : '--'],
    ['Updated', relTime(simulation.updatedAt)],
    ['Criticality', simulation.criticality],
    ['Asset type', simulation.assetType],
  ]

  return (
    <>
      <div className={cn('mb-5 rounded-xl border p-4', stalled ? 'border-amber-500/30 bg-amber-500/[0.05]' : 'border-sky-500/25 bg-sky-500/[0.04]')}>
        <div className="flex flex-wrap items-center gap-2 text-[10px] font-black uppercase tracking-wider text-white/45">
          <Server className="h-3.5 w-3.5" />
          Operational migration · executed by an agent through Live Migration, never by the sandbox engine
        </div>
        <div className={cn('mt-2 text-sm font-black', stalled ? 'text-amber-200' : 'text-white/85')}>{op.headline}</div>
        <p className="mt-1 text-[11px] leading-relaxed text-white/55">{op.nextAction}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <Link
            to={op.links.liveMigration}
            className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/35 bg-sky-500/10 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-sky-300 transition hover:bg-sky-500/20"
          >
            <ExternalLink className="h-3 w-3" />
            Open in Live Migration
          </Link>
          {op.links.planner && (op.stage === 'awaiting-approval' || op.stage === 'rejected') && (
            <Link
              to={op.links.planner}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.03] px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-white/70 transition hover:border-gold/40 hover:text-gold"
            >
              Review plan approval
            </Link>
          )}
          {needsAgent && (
            <Link
              to={op.links.agentCenter}
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/35 bg-emerald-500/10 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-emerald-300 transition hover:bg-emerald-500/20"
            >
              <Server className="h-3 w-3" />
              Open Agent Center
            </Link>
          )}
        </div>
      </div>

      <div className="mb-5">
        <div className="mb-2 text-xs font-black uppercase tracking-wider text-white/55">Execution Readiness</div>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {op.gates.map((gate) => {
            const style = GATE_STYLE[gate.state]
            const Icon = style.icon
            return (
              <div key={gate.id} className={cn('rounded-lg border p-3', style.box)}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-black uppercase tracking-wider text-white/60">{gate.label}</span>
                  <span className={cn('inline-flex items-center gap-1 text-[10px] font-black uppercase', style.text)}>
                    <Icon className="h-3.5 w-3.5" />
                    {style.word}
                  </span>
                </div>
                <div className="mt-1.5 text-[11px] leading-relaxed text-white/55">{gate.detail}</div>
              </div>
            )
          })}
        </div>
        {op.approval.approved && op.approval.approvedAt && (
          <div className="mt-2 text-[10px] font-semibold text-white/40">
            Approved by <span className="font-black text-white/70">{op.approval.approvedBy || 'operator'}</span>
            {' · '}{timeStr(op.approval.approvedAt)} ({relTime(op.approval.approvedAt)})
            {' · '}{op.approval.source === 'plan' ? 'recorded on the migration plan' : 'job-level approval'}
          </div>
        )}
      </div>

      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {facts.map(([label, value, title]) => (
          <div key={label} className="rounded-lg border border-white/8 bg-white/[0.025] p-3" title={title}>
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
          Progress is reported by the executing agent. {simulation.status === 'queued' ? 'Nothing has executed yet.' : ''}
        </div>
      </div>

      {op.controls.length > 0 && (
        <div className="mb-5">
          <div className="mb-2 text-xs font-black uppercase tracking-wider text-white/55">Deployment Controls</div>
          <div className="flex flex-wrap gap-2">
            {op.controls.map((control) => (
              <span key={control.key}>
                <Pill className={control.enabled ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300' : 'border-white/10 bg-white/5 text-white/40'}>
                  {control.label}: {control.enabled ? 'on' : 'off'}
                </Pill>
              </span>
            ))}
          </div>
        </div>
      )}
    </>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   DETAILS DIALOG
   ═══════════════════════════════════════════════════════════════════════════ */

/** The tenant quantum risk a snapshot recorded — never a filler 0. */
function snapshotRiskLabel(riskState: Record<string, unknown>) {
  if (typeof riskState.quantumRiskScore === 'number') return `${riskState.quantumRiskScore}/100`
  // Captures taken before this field existed recorded a field the summary no
  // longer carried (read as 0), so they are shown as not recorded.
  return 'quantumRiskScore' in riskState ? 'Not assessed' : 'Not recorded'
}

export function SimulationDetailsModal({
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
  const open = Boolean(simulation)
  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!simulation) return null
  const sc = statusColor(simulation.status)
  const snapshots = Array.isArray(simulation.metadata?.snapshots) ? simulation.metadata.snapshots as Array<Record<string, unknown>> : []
  const busy = (action: string) => pendingAction === `${simulation.id}:${action}`
  const isSandbox = simulation.isSandbox
  const op = !isSandbox ? simulation.operational ?? null : null
  const deleteAllowed = isSandbox && canDeleteSimulationStatus(simulation.status)
  const approval = objectRecord(simulation.metadata?.approval)
  const approvalDecision = isSandbox ? String(approval.decision || '') : ''
  const canDecide = isSandbox && simulation.status === 'completed'
  const opApproval = op ? approvalPill(op) : null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="sandbox-details-title"
        className="max-h-[88vh] w-full max-w-4xl overflow-hidden rounded-2xl border border-gold/25 bg-[#0A1525]/95 shadow-2xl backdrop-blur-xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 border-b border-white/10 p-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 id="sandbox-details-title" className="truncate text-lg font-black text-white">{simulation.name}</h3>
              <Pill className={cn(sc.bg, sc.border, sc.text)}>{simulation.status.replace(/_/g, ' ')}</Pill>
              <Pill className={modeBadge(simulation.runMode)}>{simModeLabel(simulation)}</Pill>
              <Pill className={riskBadge(simulation.riskLevel)}>{simulation.riskLevel} risk</Pill>
              {opApproval && <Pill className={opApproval.className}>{opApproval.label}</Pill>}
              {approvalDecision && (
                <Pill className={approvalDecision === 'approve' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : approvalDecision === 'reject' ? 'border-red-500/30 bg-red-500/10 text-red-300' : 'border-sky-500/25 bg-sky-500/10 text-sky-300'}>
                  {approvalDecision === 'approve' ? 'approved' : approvalDecision === 'reject' ? 'rejected' : 'review requested'}
                </Pill>
              )}
            </div>
            <p className="mt-1 text-xs text-white/45">{simulation.assetName} | {simulation.environment} | {simulation.owner}</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close details" className="rounded-lg p-1.5 text-white/40 hover:bg-white/10 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-[calc(88vh-82px)] overflow-y-auto p-5">
          {isSandbox ? (
            <>
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
            </>
          ) : op ? (
            <OperationalOverview simulation={simulation} op={op} />
          ) : (
            <div className="mb-5 rounded-xl border border-white/8 bg-white/[0.02] p-4 text-[11px] text-white/50">
              {simulation.phaseDetail || simulation.queuedReason || 'Operational migration job.'} Approval, dispatch and agent details arrive with the next snapshot.
            </div>
          )}

          {canDecide && (
            <div className="mb-5 rounded-xl border border-gold/20 bg-gold/[0.03] p-4">
              <div className="mb-2 text-xs font-black uppercase tracking-wider text-gold">Analytical Review</div>
              <p className="mb-3 text-[11px] leading-relaxed text-white/45">
                Record your review of a modeled scenario. Use the lab for cryptographic checks and the planner for production change approval.
              </p>
              <div className="flex flex-wrap gap-2">
                <ActionBtn icon={ThumbsUp} label={busy('approval:approve') ? 'Recording…' : 'Accept analytical review'}
                  onClick={() => { if (window.confirm(`Accept the analytical review of "${simulation.name}"?`)) void onApproval(simulation.id, 'approve') }}
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
              <div className="mb-3 flex items-center justify-between gap-2">
                <span className="text-xs font-black uppercase tracking-wider text-white/55">Recent Events</span>
                {simulation.eventCount > simulation.recentEvents.length && (
                  <span className="text-[10px] text-white/35">Newest {simulation.recentEvents.length} of {simulation.eventCount}</span>
                )}
              </div>
              {simulation.recentEvents.length === 0 ? (
                <EmptyBlock label={isSandbox ? 'No event entries are attached to this simulation yet.' : 'No events recorded for this job yet — they appear once an agent claims it or an operator acts on it.'} />
              ) : (
                <div className="space-y-2">
                  {simulation.recentEvents.map((event) => (
                    <div key={event.id} className="grid grid-cols-[18px_1fr_auto] items-center gap-2 rounded-lg bg-white/[0.025] px-3 py-2 text-[11px]">
                      {severityIcon(event.severity)}
                      <span className="truncate text-white/60" title={event.message}>{event.message}</span>
                      <span className="font-mono text-white/25">{timeStr(event.timestamp)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
              <div className="mb-3 text-xs font-black uppercase tracking-wider text-white/55">{isSandbox ? 'Recovery Snapshots' : 'Record Snapshots'}</div>
              {!isSandbox && (
                <p className="mb-3 text-[10px] leading-relaxed text-white/40">
                  Captures of this job&apos;s record taken from the sandbox. They cannot restore an operational migration —
                  rollback runs from the job&apos;s pre-change snapshot in Live Migration, which dispatches it to the agent holding the backup.
                </p>
              )}
              {snapshots.length === 0 ? (
                <EmptyBlock label="No snapshots captured yet." />
              ) : (
                <div className="space-y-2">
                  {snapshots.length > 6 ? (
                    <div className="text-[10px] text-white/35">
                      Showing the 6 most recent of {snapshots.length} snapshots.
                    </div>
                  ) : null}
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
                        <span>Tenant quantum risk: {snapshotRiskLabel(riskState)}</span>
                        <span>Tenant control evidence: {complianceState.score == null ? "Not assessed" : `${String(complianceState.score)}%`}</span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {isSandbox && (
                          <ActionBtn
                            icon={Upload}
                            label={busy('restore_snapshot') ? 'Restoring' : 'Restore'}
                            onClick={() => onAction(simulation.id, 'restore_snapshot', { snapshotId })}
                            disabled={busy('restore_snapshot')}
                            small
                          />
                        )}
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
            {isSandbox && simulation.status === 'running' && <ActionBtn icon={Pause} label={busy('pause') ? 'Pausing' : 'Pause'} onClick={() => onAction(simulation.id, 'pause')} disabled={busy('pause')} />}
            {isSandbox && simulation.status === 'paused' && <ActionBtn icon={Play} label={busy('resume') ? 'Resuming' : 'Resume'} onClick={() => onAction(simulation.id, 'resume')} disabled={busy('resume')} variant="success" />}
            {isSandbox && simulation.status === 'failed' && <ActionBtn icon={RefreshCw} label={busy('retry') ? 'Retrying' : 'Retry'} onClick={() => onAction(simulation.id, 'retry')} disabled={busy('retry')} variant="gold" />}
            {isSandbox && simulation.status === 'running' && <ActionBtn icon={Square} label={busy('stop') ? 'Stopping' : 'Stop'} onClick={() => onAction(simulation.id, 'stop')} disabled={busy('stop')} variant="danger" />}
            {isSandbox && ['running', 'paused', 'completed'].includes(simulation.status) && <ActionBtn icon={RotateCcw} label={busy('rollback') ? 'Rolling Back' : 'Rollback'} onClick={() => onAction(simulation.id, 'rollback')} disabled={busy('rollback')} variant="danger" />}
            {isSandbox && <ActionBtn icon={Save} label={busy('snapshot') ? 'Capturing' : 'Model checkpoint'} onClick={() => onAction(simulation.id, 'snapshot')} disabled={busy('snapshot')} />}
            {isSandbox && snapshots.length > 0 && <ActionBtn icon={Upload} label={busy('restore_snapshot') ? 'Restoring' : 'Restore Snapshot'} onClick={() => onAction(simulation.id, 'restore_snapshot', { snapshotId: String(snapshots[snapshots.length - 1]?.id || '') })} disabled={busy('restore_snapshot')} />}
            {deleteAllowed && <ActionBtn icon={Trash2} label={busy('delete') ? 'Deleting' : 'Delete Simulation'} onClick={() => { if (window.confirm('Delete this completed simulation and purge its execution artifacts? Audit and security records will remain.')) onAction(simulation.id, 'delete') }} disabled={busy('delete')} variant="danger" />}
            {!isSandbox && op && (
              <Link
                to={op.links.liveMigration}
                className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/35 bg-sky-500/10 px-3.5 py-2 text-xs font-bold text-sky-300 transition hover:bg-sky-500/20"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Manage in Live Migration
              </Link>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
