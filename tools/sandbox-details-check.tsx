/**
 * Offline check for the Migration Sandbox Details dialog.
 *
 * Written for the bug where "Details" on an Operational Migration Queue row
 * showed nothing: the dialog resolved its record against `data.simulations`
 * (the sandbox subset) and closed itself on the next render for every
 * operational job. Fixing that exposed the rest — the dialog was built for
 * simulations only, described an approved planner cutover as "Awaiting sandbox
 * executor capacity.", offered a Restore that wrote `rolled_back` onto a real
 * migration, and listed the five OLDEST events as "Recent Events".
 *
 *   §1 selection resolves operational AND sandbox rows (negative control: the old lookup)
 *   §2 describeOperationalWorkflow — every stage from real-shaped fixtures, with
 *      "unreadable" kept apart from "no"
 *   §3 dispatchBlockFor is the one refusal rule (Live Migration uses it too)
 *   §4 the executor-role table cannot drift from agentMayWrite
 *   §5 sandbox.ts: engine-only actions refused on operational jobs, rows carry
 *      the operational detail, risk + events + snapshot risk derived correctly
 *   §6 the dialog RENDERS the right thing for each kind of job
 *
 * No server / Supabase required:  npx tsx tools/sandbox-details-check.tsx
 */
import { readFileSync } from 'node:fs'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import {
  AGENT_ROLES_FOR_EXECUTION,
  describeOperationalWorkflow,
  dispatchBlockFor,
  type OperationalAgent,
  type OperationalWorkflowInput,
} from '../src/lib/migration/operational-workflow'
import { approvalRefusal, jobApproval } from '../src/lib/migration/job-safety'
import { findJobRecord, type Simulation } from '../src/app/dashboard/migration-sandbox/_shared'
import { SimulationDetailsModal } from '../src/app/dashboard/migration-sandbox/SimulationDetails'

let failures = 0
let checks = 0
function assert(cond: boolean, label: string, detail = '') {
  checks++
  if (cond) console.log(`  OK   ${label}`)
  else {
    failures++
    console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ''}`)
  }
}
function section(title: string) {
  console.log(`\n${title}`)
}

const NOW = Date.parse('2026-09-21T06:00:00.000Z')
const PLAN_ID = 'planner-asset-1700000000000'

/** Shaped like a real Migration Planner job row (metadata trimmed to the keys read). */
function plannerJob(overrides: Record<string, unknown> = {}) {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    name: 'PQC Migration: expired.badssl.com',
    job_type: 'cert_transition',
    metadata: {
      planId: PLAN_ID,
      source: 'migration-planner',
      workflow: 'post-quantum-migration-plan',
      priority: 'High',
      planStatus: 'awaiting_agent',
      controls: { rollback: true, hybridMode: true, validation: true, compatibility: true, complianceValidation: true, continuousMonitoring: true },
      execution: {
        strategy: 'Staged Rollout',
        phaseName: 'Stage 1: Critical Services',
        phaseIndex: 1,
        totalPhases: 1,
        agentRequired: true,
        sequenceState: 'waiting_for_agent',
        agentDispatchStatus: 'queued_for_agent',
      },
      configuration: { deploymentStrategy: 'Staged Rollout' },
      ...overrides,
    },
  }
}

const approvedPlan = {
  status: 'awaiting_agent',
  metadata: { approval: { via: 'planner-start', decision: 'approve', decidedAt: '2026-09-21T05:24:34.896Z', decidedBy: 'operator@example.com', reason: 'Approved by the operator who started this migration.' } },
}

function describe(partial: Partial<OperationalWorkflowInput> & { job?: OperationalWorkflowInput['job'] }) {
  return describeOperationalWorkflow({
    job: plannerJob(),
    status: 'queued',
    progress: 0,
    plan: approvedPlan,
    planReadable: true,
    executionClass: 'migration',
    agents: [],
    now: NOW,
    ...partial,
  })
}

const onlineOperator: OperationalAgent = { id: 'a1', name: 'edge-operator-01', role: 'operator', lastSeenAt: new Date(NOW - 60_000).toISOString() }
const staleOperator: OperationalAgent = { id: 'a2', name: 'edge-operator-02', role: 'operator', lastSeenAt: new Date(NOW - 2 * 3600_000).toISOString() }
const onlinePatcher: OperationalAgent = { id: 'a3', name: 'patcher-01', role: 'patcher', lastSeenAt: new Date(NOW - 30_000).toISOString() }
const revokedOperator: OperationalAgent = { ...onlineOperator, id: 'a4', revoked: true }

/* ─────────────────────────────────────────────────────────────────────────── */
section('§1 Details selection resolves every list it can be opened from')

const simRow = { id: 'sim-1', isSandbox: true } as unknown as Simulation
const opRow = { id: 'op-1', isSandbox: false } as unknown as Simulation
const workflows = [simRow, opRow]
const simulations = [simRow]
assert(findJobRecord('op-1', workflows, simulations) === opRow, 'an operational job opened from the queue resolves (the reported bug)')
assert(findJobRecord('sim-1', workflows, simulations) === simRow, 'a sandbox simulation still resolves')
assert(findJobRecord('sim-1', [], simulations) === simRow, 'falls back to the simulations list when workflows lack the row')
assert(findJobRecord('gone', workflows, simulations) === null, 'a deleted job resolves to null, closing the dialog')
assert(findJobRecord(null, workflows, simulations) === null, 'no selection → no dialog')
// Negative control: the lookup the page used to run.
assert(simulations.find((sim) => sim.id === 'op-1') === undefined, 'NEGATIVE CONTROL: the old simulations-only lookup misses the operational job')
const pageSrc = readFileSync('src/app/dashboard/migration-sandbox/MigrationSandbox.tsx', 'utf8')
assert(/findJobRecord\(selectedJobId, data\.workflows, data\.simulations\)/.test(pageSrc), 'the page resolves the open dialog through findJobRecord over both lists')
assert(!/data\.simulations\.find\(\(sim\) => sim\.id === selectedSimulation\.id\)/.test(pageSrc), 'the self-closing simulations-only effect is gone')
assert((pageSrc.match(/onDetails=\{openDetails\}/g) || []).length === 3, 'all three row types open Details by job ID')

/* ─────────────────────────────────────────────────────────────────────────── */
section('§2 describeOperationalWorkflow — what decides whether the job moves')

{
  const d = describe({})
  assert(d.stage === 'no-capable-agent', 'approved + no agents enrolled → no-capable-agent', d.stage)
  assert(/no Migration Operator agent is enrolled/i.test(d.headline), 'headline names the missing role', d.headline)
  assert(/Pro and Elite/.test(d.nextAction) && /Agent Center/.test(d.nextAction), 'next action says where to get the agent and which plans include it', d.nextAction)
  assert(!/sandbox executor/i.test(d.headline + d.nextAction), 'never describes an operational job as waiting for the sandbox executor')
  const gate = Object.fromEntries(d.gates.map((g) => [g.id, g.state]))
  assert(gate.approval === 'pass' && gate.dispatch === 'pending' && gate.executor === 'fail' && gate.execution === 'pending',
    'gates: approval pass · dispatch pending · executor fail · execution pending', JSON.stringify(gate))
  assert(d.approval.approvedBy === 'operator@example.com' && d.approval.source === 'plan', 'approval is attributed and sourced to the plan')
  assert(d.sourceLabel === 'Migration Planner' && d.planId === PLAN_ID, 'source + plan identified')
  assert(d.phaseName === 'Stage 1: Critical Services' && d.phaseIndex === 1 && d.totalPhases === 1 && d.strategy === 'Staged Rollout', 'phase + strategy read from execution metadata')
  assert(d.links.liveMigration === `/dashboard/live-migration?planId=${encodeURIComponent(PLAN_ID)}`, 'Live Migration deep link carries the plan', d.links.liveMigration)
  assert(d.links.agentCenter === '/downloads', 'Agent Center link')
  assert(d.controls.length === 6 && d.controls.every((c) => c.enabled), 'six deployment controls, all enabled')
  assert(d.executor.enrolled === 0 && d.executor.capable === 0 && d.executor.capableOnline === 0, 'fleet counts are measured zeros')
}

{
  const d = describe({ agents: [onlineOperator] })
  assert(d.stage === 'awaiting-claim', 'an online Migration Operator → awaiting-claim', d.stage)
  assert(d.gates.find((g) => g.id === 'executor')?.state === 'pass', 'executor gate passes')
  assert(/1 Migration Operator agent online/.test(d.nextAction), 'next action counts online capable agents', d.nextAction)
}

{
  const d = describe({ agents: [staleOperator] })
  assert(d.stage === 'no-online-agent', 'an operator that stopped checking in → no-online-agent', d.stage)
  assert(d.executor.capable === 1 && d.executor.capableOnline === 0, 'capable 1, online 0')
}

{
  const d = describe({ agents: [onlinePatcher, revokedOperator] })
  assert(d.stage === 'no-capable-agent', 'NEGATIVE CONTROL: a Patcher cannot execute a migration cutover; a revoked Operator does not count', d.stage)
  assert(d.executor.enrolled === 1, 'the revoked agent is excluded from the enrolled count')
}

{
  const d = describe({ executionClass: 'remediation', agents: [onlinePatcher] })
  assert(d.stage === 'awaiting-claim', 'remediation work is claimable by an online Patcher', d.stage)
  assert(d.executor.roleLabel === 'Patcher', 'remediation names the Patcher role')
}

{
  const d = describe({ plan: null, planReadable: false })
  assert(d.stage === 'approval-unreadable', 'unreadable plan → approval-unreadable, NOT awaiting-approval', d.stage)
  assert(d.gates.find((g) => g.id === 'approval')?.state === 'unknown', 'approval gate is unknown, not pending')
  assert(d.approvalReadable === false, 'approvalReadable false')
}

{
  const plan = { status: 'awaiting_agent', metadata: { approval: null } }
  const d = describe({ plan })
  assert(d.stage === 'awaiting-approval', 'plan read, no approval record → awaiting-approval', d.stage)
  assert(d.nextAction === approvalRefusal(jobApproval(plannerJob(), plan)), 'next action is the shared refusal text the agent poll uses')
}

{
  const d = describe({ plan: { status: 'approved', metadata: {} } })
  assert(d.stage === 'awaiting-approval', 'NEGATIVE CONTROL: a bare status "approved" is not an approval', d.stage)
}

{
  const d = describe({ plan: { status: 'rejected', metadata: {} } })
  assert(d.stage === 'rejected' && d.gates[0].state === 'fail', 'rejected plan → rejected, approval gate fails')
}

{
  const job = plannerJob({ dispatchBlock: { kind: 'agent-role', reason: 'This is a Live Migration cutover and requires a Migration Operator agent.', requires: 'operator', at: '2026-09-21T05:40:00Z' } })
  const d = describe({ job, agents: [onlinePatcher] })
  assert(d.stage === 'dispatch-blocked', 'a refusal recorded by the agent poll → dispatch-blocked', d.stage)
  assert(d.gates.find((g) => g.id === 'dispatch')?.state === 'fail' && /Migration Operator/.test(d.headline), 'dispatch gate fails with the recorded reason')
}

{
  const d = describe({ agents: null })
  assert(d.stage === 'awaiting-claim' && /could not be read/.test(d.nextAction), 'unreadable fleet is stated as unreadable, never as "no agent"', d.nextAction)
  assert(d.gates.find((g) => g.id === 'executor')?.state === 'unknown', 'executor gate unknown')
  assert(d.executor.enrolled === null && d.executor.fleetReadable === false, 'fleet counts are null, not 0')
}

{
  const job = plannerJob({ assignedAgentId: 'a1' })
  const d = describe({ job, status: 'running', progress: 42, agents: [onlineOperator] })
  assert(d.stage === 'executing' && /edge-operator-01/.test(d.headline), 'running job names the agent resolved from the fleet', d.headline)
  assert(d.gates.find((g) => g.id === 'execution')?.detail === 'In progress · 42%.', 'execution gate reports progress')
}

{
  const job = { id: 'hn-1', name: 'HNDL remediation', job_type: 'hndl_remediation', metadata: { source: 'harvest-now', approval: { decision: 'approve', decidedBy: 'owner@example.com', decidedAt: '2026-09-20T00:00:00Z', via: 'live-migration' } } }
  const d = describe({ job, plan: null, planReadable: true, executionClass: 'remediation', agents: [onlinePatcher] })
  assert(d.approval.approved && d.approval.source === 'job', 'planless remediation resolves its own job-level approval')
  assert(d.sourceLabel === 'Harvest Now remediation' && d.links.liveMigration === '/dashboard/live-migration' && d.links.planner === null, 'planless job links to Live Migration without a plan filter')
}

for (const [status, stage] of [['completed', 'completed'], ['failed', 'failed'], ['paused', 'paused'], ['stopped', 'cancelled'], ['rollback_requested', 'rollback'], ['rolled_back', 'rollback']] as const) {
  assert(describe({ status }).stage === stage, `status ${status} → ${stage}`)
}

{
  // The sandbox's own Rollback writes `rollback_requested` and dispatches nothing;
  // only Migration Snapshot Management records a disposition.
  const undispatched = describe({ status: 'rollback_requested' })
  assert(/nothing has been dispatched/.test(undispatched.headline) && /pre-change snapshot in Live Migration/.test(undispatched.nextAction),
    'a rollback request nothing dispatched is not described as "awaiting an executor"', undispatched.headline)
  const dispatched = describe({ status: 'rollback_requested', job: plannerJob({ rollbackDisposition: 'dispatched' }) })
  assert(/dispatched to the executor/.test(dispatched.headline), 'a dispatched rollback says so', dispatched.headline)
  const rollbackFailed = describe({ status: 'failed', job: plannerJob({ rollbackDisposition: 'failed' }) })
  assert(/^Rollback failed/.test(rollbackFailed.headline), 'a failed rollback is named as one', rollbackFailed.headline)
}

/* ─────────────────────────────────────────────────────────────────────────── */
section('§3 dispatchBlockFor — one refusal rule for Live Migration and the sandbox')

const blockMeta = { dispatchBlock: { kind: 'no-snapshot', reason: 'No verified pre-change snapshot.', requires: 'snapshot', at: 'x' } }
assert(dispatchBlockFor(blockMeta, 'queued')?.kind === 'no-snapshot', 'an active block is returned')
for (const status of ['completed', 'cancelled', 'stopped', 'rolled_back']) {
  assert(dispatchBlockFor(blockMeta, status) === null, `a ${status} job's old refusal is history, not a reason`)
}
assert(dispatchBlockFor({ dispatchBlock: { kind: 'x' } }, 'queued') === null, 'a block without a reason is not shown')
const migrationSrc = readFileSync('src/api-server/migration.ts', 'utf8')
assert(/dispatchBlock: dispatchBlockFor\(metadata, status\)/.test(migrationSrc), 'Live Migration reads the shared rule')
assert(!/const block = asRecord\(metadata\.dispatchBlock\)/.test(migrationSrc), 'Live Migration keeps no private copy of it')

/* ─────────────────────────────────────────────────────────────────────────── */
section('§4 executor roles cannot drift from agentMayWrite')

const entitlementSrc = readFileSync('src/api-server/agent-entitlement.ts', 'utf8')
assert(/operation === 'migration' && role !== 'operator'/.test(entitlementSrc) && AGENT_ROLES_FOR_EXECUTION.migration.join() === 'operator',
  'migration work: Migration Operator only (matches agentMayWrite)')
assert(/operation === 'remediation' && role !== 'patcher' && role !== 'operator'/.test(entitlementSrc) && AGENT_ROLES_FOR_EXECUTION.remediation.join() === 'patcher,operator',
  'remediation work: Patcher or Operator (matches agentMayWrite)')

/* ─────────────────────────────────────────────────────────────────────────── */
section('§5 sandbox.ts contract')

const sandboxSrc = readFileSync('src/api-server/sandbox.ts', 'utf8')
assert(/const SANDBOX_ENGINE_ONLY_ACTIONS = \['pause', 'resume', 'retry', 'stop', 'restore_snapshot'\]/.test(sandboxSrc), 'engine-only actions are listed')
assert(/const refusal = sandboxEngineActionRefusal\(job, action\)\s*\n\s*if \(refusal\) \{\s*\n\s*return res\.status\(409\)/.test(sandboxSrc), 'the single-job action route refuses them on operational jobs (409)')
assert(/&& !sandboxEngineActionRefusal\(job, action\)\)/.test(sandboxSrc), 'the bulk route filters them out too')
const refusalIndex = sandboxSrc.indexOf('const refusal = sandboxEngineActionRefusal(job, action)')
const updateIndex = sandboxSrc.indexOf('const update = actionUpdate(job, action, now, {')
assert(refusalIndex > 0 && updateIndex > refusalIndex, 'the refusal runs before any write')
assert(/operational = isSandbox \? null : describeOperationalWorkflow\(/.test(sandboxSrc), 'every operational row carries the shared description')
assert(/queuedReason: status === 'queued'\s*\n\s*\? operational\?\.headline/.test(sandboxSrc), 'the queue reason of an operational row is its real state')
assert(/recentEvents: jobEvents\.slice\(0, 5\)/.test(sandboxSrc) && !/jobEvents\.slice\(-5\)/.test(sandboxSrc), '"Recent Events" are the newest five (events load newest-first)')
assert(/const riskLevel = assetMap\.has\(job\.asset_id\) \? evidenceRiskLevel\(invItems, expItems, fromAlgo\)/.test(sandboxSrc), 'row risk uses the Simulation Builder evidence rule')
assert(/riskLevel: evidenceRiskLevel\(invItems, expItems, sourceAlgorithm\)/.test(sandboxSrc), 'the Simulation Builder uses the same function (one rule)')
assert(!/riskScore: Number\(summary\.riskScore/.test(sandboxSrc), 'snapshots no longer read the removed summary.riskScore (recorded 0 = perfect)')
assert(/quantumRiskScore: typeof summary\.quantumRiskScore === 'number' \? summary\.quantumRiskScore : null/.test(sandboxSrc), 'snapshots record the canonical score or null')
const fleetSrc = readFileSync('src/api-server/operational-fleet.ts', 'utf8')
assert(/select\('id, status, approval:metadata->approval, plan_name:metadata->>name, plan_title:metadata->>planName'\)/.test(fleetSrc) && /loadPlanApprovalsShared\(client, userId, jobs, '\[sandbox\]'\)/.test(sandboxSrc),
  'plan approvals are projected (shared loader, also used by the orchestration snapshot), not the whole plan metadata blob')
assert(/\['failed', 'error', 'errored', 'rollback_failed', 'validation_failed'\]\.includes\(v\)\) return 'failed'/.test(sandboxSrc),
  'rollback_failed / validation_failed read as failed (as in Live Migration), not as queued')

/* ─────────────────────────────────────────────────────────────────────────── */
section('§6 the Details dialog renders the right thing for each kind of job')

function baseRow(overrides: Partial<Simulation>): Simulation {
  return {
    id: 'row',
    name: 'Row',
    assetId: 'asset-1',
    assetName: 'expired.badssl.com',
    assetType: 'web_application',
    environment: 'unknown',
    owner: 'Unassigned',
    criticality: 'high',
    fromAlgo: 'Classical crypto',
    toAlgo: 'X25519 + ML-KEM-768',
    migrationType: 'cert_transition',
    runMode: 'migration_workflow',
    runModeLabel: 'Migration Workflow',
    isSandbox: false,
    isActualMigration: true,
    executionScope: 'unknown',
    engineStatus: 'awaiting approved executor',
    queuedReason: null,
    eta: 'Awaiting executor',
    status: 'queued',
    progress: 0,
    riskLevel: 'critical',
    phase: 'Queued',
    phaseId: 'queued',
    phaseDetail: '',
    startedAt: null,
    completedAt: null,
    updatedAt: new Date(NOW - 5 * 60_000).toISOString(),
    createdAt: new Date(NOW - 30 * 60_000).toISOString(),
    eventCount: 0,
    recentEvents: [],
    metadata: {},
    ...overrides,
  }
}

function render(sim: Simulation) {
  return renderToStaticMarkup(
    <MemoryRouter>
      <SimulationDetailsModal simulation={sim} onClose={() => {}} onAction={() => {}} onApproval={() => {}} pendingAction={null} pipeline={[]} />
    </MemoryRouter>,
  )
}
const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;|&apos;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ')

{
  const operational = describe({})
  const legacySnapshot = { id: 'snap_legacy', at: new Date(NOW - 20 * 60_000).toISOString(), status: 'queued', progress: 0, riskState: { riskLevel: 'low', riskScore: 100 }, complianceState: { score: 43 } }
  const sim = baseRow({
    id: 'op-1',
    name: 'PQC Migration: expired.badssl.com',
    phaseDetail: operational.headline,
    queuedReason: operational.headline,
    operational,
    metadata: { snapshots: [legacySnapshot] },
  })
  const html = render(sim)
  const t = text(html)
  assert(html.length > 0 && /role="dialog"/.test(html), 'the dialog renders for an operational job (it used to unmount immediately)')
  assert(t.includes(operational.headline), 'shows where the job really stands')
  assert(/Execution Readiness/.test(t) && /Approval/.test(t) && /Executor/.test(t), 'shows the four readiness gates')
  assert(/operator@example\.com/.test(t), 'names who approved it')
  assert(/Open in Live Migration/.test(t) && html.includes(`href="/dashboard/live-migration?planId=${encodeURIComponent(PLAN_ID)}"`), 'hands off to Live Migration for this plan')
  assert(/Open Agent Center/.test(t) && html.includes('href="/downloads"'), 'offers the Agent Center when no capable agent exists')
  assert(/Stage 1: Critical Services \(1\/1\)/.test(t) && /Staged Rollout/.test(t), 'shows plan phase and strategy')
  assert(/critical risk/.test(t) && /approved/.test(t), 'header shows risk and approval')
  assert(!/sandbox executor capacity/i.test(t), 'NEGATIVE: no "Awaiting sandbox executor capacity"')
  assert(!/Enterprise Migration Pipeline/.test(t), 'NEGATIVE: no sandbox stage rail on an operational job')
  assert(!/Restore/.test(t), 'NEGATIVE: no Restore controls on an operational job (they wrote rolled_back with nothing run)')
  assert(!/Delete Simulation|>Pause<|>Resume<|>Retry<|>Stop</.test(html), 'NEGATIVE: no sandbox-engine controls')
  assert(/Record Snapshots/.test(t) && /Export/.test(t), 'snapshots stay exportable, labelled as records')
  assert(/Tenant quantum risk: Not recorded/.test(t) && !/Risk score: 100/.test(t), 'a legacy snapshot\'s unknown-provenance score is not shown as a measurement')
}

{
  const sim = baseRow({ id: 'op-2', operational: undefined, phaseDetail: 'Queued.' })
  const t = text(render(sim))
  assert(/arrive with the next snapshot/.test(t) && !/Restore/.test(t), 'an operational row from an older server still renders, without engine controls')
}

{
  const sim = baseRow({
    id: 'sim-1',
    name: '[DRY RUN] expired.badssl.com (TLSv1 → ML-KEM-768)',
    isSandbox: true,
    isActualMigration: false,
    runMode: 'dry_run',
    runModeLabel: 'Dry Run',
    status: 'completed',
    progress: 100,
    operational: null,
    eventCount: 12,
    recentEvents: [{ id: 'e1', type: 'sandbox-complete', message: 'Simulation completed', severity: 'info', timestamp: new Date(NOW).toISOString() }],
    metadata: { snapshots: [
      { id: 'snap_new', at: new Date(NOW).toISOString(), status: 'completed', progress: 100, riskState: { quantumRiskScore: 45 }, complianceState: { score: 39 } },
      { id: 'snap_unassessed', at: new Date(NOW).toISOString(), status: 'running', progress: 50, riskState: { quantumRiskScore: null }, complianceState: { score: 39 } },
    ] },
  })
  const t = text(render(sim))
  assert(/Enterprise Migration Pipeline/.test(t) && /Production Approval Gate/.test(t), 'a completed simulation keeps its stage rail and approval gate')
  assert(/Restore Snapshot/.test(t), 'a simulation keeps its snapshot restore')
  assert(!/Execution Readiness/.test(t), 'no operational panel on a simulation')
  assert(/Tenant quantum risk: 45\/100/.test(t) && /Tenant quantum risk: Not assessed/.test(t), 'snapshot risk: a measured score, or "Not assessed" — never 0')
  assert(/Newest 1 of 12/.test(t), 'states when only the newest events are shown')
}

console.log(`\n${checks - failures}/${checks} checks passed`)
if (failures > 0) process.exit(1)
