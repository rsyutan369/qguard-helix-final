/**
 * Offline verification for the Live Migration four-agent workflow model
 * (src/lib/migration/agent-workflow.ts).
 *
 * The properties that matter: every status, percentage, handoff and checkmark
 * on the canvas must come from a recorded fact. These fixtures pin the cases
 * that would otherwise drift into "looks active" — an enrolled agent with no
 * frames, a stalled run, a sandbox job, a write role without authority, an
 * unapproved cutover, a Windows host's zero load average, a token in a payload.
 *
 * Run:  npx tsx tools/live-agent-workflow-check.ts
 */
import {
  buildAgentWorkflow,
  deriveRisks,
  redactDetail,
  safetyChecklist,
  type AgentWorkflowInput,
  type WorkflowAgentRow,
  type WorkflowHeartbeatRow,
  type WorkflowJob,
} from '../src/lib/migration/agent-workflow'
import type { ApprovalVerdict } from '../src/lib/migration/job-safety'
import { trackRequestedScan, scanWorkflowPath } from '../src/lib/agent-installer/scan-tracking'
import type { AgentCommand } from '../src/lib/agent-installer/agent-release'
import { assetScanSources, scanSourceFor } from '../src/lib/assets/scan-provenance'
import { buildAssetRegister, filterRows } from '../src/lib/assets/asset-register'
import { classifyHostIdentity } from './qguard-agent/host-identity'
import { assetIsInternetFacing } from '../src/lib/governance/subjects'
import { AGENT_DISCOVERY_EVENT, projectAgentDiscovery } from '../src/lib/migration/agent-discovery'
import { busStats, eventsSince, publishAgentEvent, subscribe } from '../src/api-server/agent-event-bus'
import { scanEvidenceWithModules } from '../src/lib/scanner/scanner_2/modules'
import type { ScannerEvidenceRecord } from '../src/types/scanner.types'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const NOW = Date.parse('2026-10-28T12:00:00.000Z')
const iso = (minutesAgo: number) => new Date(NOW - minutesAgo * 60_000).toISOString()

const EVIDENCE: AgentWorkflowInput['evidence'] = {
  totalAssets: 12,
  inventoryItems: 40,
  certificates: 6,
  keys: 4,
  quantumSafeItems: 10,
  vulnerableItems: 30,
  findings: 18,
  exposures: { critical: 2, high: 3, medium: 4, low: 1 },
  exposureSample: [
    { assetId: 'a1', exposureType: 'rsa', severity: 'critical' },
    { assetId: 'a1', exposureType: 'rsa', severity: 'high' },
    { assetId: 'a2', exposureType: 'weak_tls', severity: 'medium' },
  ],
  exposureTotal: 10,
  lastScanAt: iso(30),
}

function agent(id: string, role: string, overrides: Partial<WorkflowAgentRow> = {}): WorkflowAgentRow {
  return {
    id, name: `${role}-${id}`, hostname: `host-${id}`, status: 'active', version: '1.5.5',
    lastSeenAt: iso(1), revoked: false, role,
    writeAuthority: role === 'patcher' ? { remediation: true, migration: false } : role === 'operator' ? { remediation: true, migration: true } : { remediation: false, migration: false },
    telemetry: null,
    ...overrides,
  }
}

let frameSeq = 0
function frame(agentId: string, minutesAgo: number, stage: string, progress: number, extra: Record<string, unknown> = {}): WorkflowHeartbeatRow {
  frameSeq += 1
  return { id: `f${frameSeq}`, agentId, status: 'scan_progress', telemetry: { stage, progress, message: stage, ...extra }, observedAt: iso(minutesAgo) }
}

const APPROVED: ApprovalVerdict = { approved: true, state: 'approved' as ApprovalVerdict['state'], source: 'job', required: true, approvedBy: 'ciso@example.com', approvedAt: iso(120), reason: '', via: 'console' }
const PENDING: ApprovalVerdict = { approved: false, state: 'pending' as ApprovalVerdict['state'], source: 'plan', required: true, approvedBy: '', approvedAt: '', reason: '', via: '' }

function job(id: string, overrides: Partial<WorkflowJob> = {}): WorkflowJob {
  return {
    id, asset: `asset-${id}`, assetId: `a-${id}`, assetType: 'Web Service', environment: 'production', owner: 'platform',
    criticality: 'high', fromAlgo: 'RSA-2048', toAlgo: 'ML-KEM-768', migrationType: 'TLS hybrid', status: 'queued', progress: 0,
    startedAt: null, completedAt: null, createdAt: iso(60), updatedAt: iso(5), executionBacked: false, isSandbox: false,
    agentId: null, agentName: null, currentStep: 'Waiting for agent claim', validationStatus: 'pending', validationCount: 0,
    telemetryCount: 0, dispatchBlock: null, approval: APPROVED, executionClass: 'migration', logs: [], metadata: {},
    ...overrides,
  }
}

const node = (model: ReturnType<typeof buildAgentWorkflow>, id: string) => model.nodes.find((item) => item.id === id)!

/* ------------------------------------------------------------------ */
console.log('\n[1] Nothing enrolled, nothing planned → idle everywhere, no invented progress')
{
  const model = buildAgentWorkflow({ now: NOW, agents: [], heartbeats: [], jobs: [], evidence: { ...EVIDENCE, findings: 0, exposures: { critical: 0, high: 0, medium: 0, low: 0 }, exposureSample: [], exposureTotal: 0 } })
  assert(model.nodes.every((item) => item.status === 'idle'), 'every stage is idle')
  assert(model.overallProgress === null, 'overall progress is null, not 0%')
  assert(model.status === 'idle', 'workflow status idle')
  assert(model.nodes.every((item) => item.reason.length > 0), 'every idle stage states its reason')
  assert(model.edges.every((edge) => edge.lastHandoffAt === null), 'no handoff without a recorded transition')
}

/* ------------------------------------------------------------------ */
console.log('\n[2] Collector progress comes from the agent\'s own scan frames')
{
  const heartbeats = [frame('c1', 6, 'connecting', 2), frame('c1', 4, 'system_inventory', 8), frame('c1', 1, 'inspecting_certificates', 45, { target: 'api.example.com' })]
  const model = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector')], heartbeats, jobs: [], evidence: EVIDENCE })
  const collector = node(model, 'collector')
  assert(collector.status === 'running', 'collector running', collector.status)
  assert(collector.progress === 45, 'progress is the reported 45%', String(collector.progress))
  assert(collector.startedAt === iso(6), 'start is the run\'s connecting frame')
  assert(model.currentStage === 'collector', 'current stage is collector')
  assert(model.edges[0].state === 'waiting', 'collector→scanner waits while collection runs', model.edges[0].state)
}

/* ------------------------------------------------------------------ */
console.log('\n[3] A run that stopped reporting is blocked, not "running"')
{
  const heartbeats = [frame('c1', 40, 'connecting', 2), frame('c1', 35, 'building_cbom', 75)]
  const model = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector', { lastSeenAt: iso(35) })], heartbeats, jobs: [], evidence: EVIDENCE })
  const collector = node(model, 'collector')
  assert(collector.status === 'blocked', 'stalled run is blocked', collector.status)
  assert(/stopped reporting/.test(collector.reason), 'reason names the stall')
}

/* ------------------------------------------------------------------ */
console.log('\n[4] Enrolled but silent ≠ running')
{
  const model = buildAgentWorkflow({ now: NOW, agents: [agent('s1', 'scanner')], heartbeats: [], jobs: [], evidence: EVIDENCE })
  const scanner = node(model, 'scanner')
  assert(scanner.status === 'waiting', 'waiting for first scan', scanner.status)
  assert(scanner.progress === null, 'no progress invented')
}

/* ------------------------------------------------------------------ */
console.log('\n[5] Completed collection records a real handoff; stage-weighted progress')
{
  const heartbeats = [
    frame('c1', 30, 'connecting', 2), frame('c1', 20, 'scan_complete', 100, { accepted: 33 }),
    frame('s1', 10, 'connecting', 2), frame('s1', 1, 'building_cbom', 50),
  ]
  const model = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector'), agent('s1', 'scanner')], heartbeats, jobs: [], evidence: EVIDENCE })
  assert(node(model, 'collector').status === 'completed', 'collector completed')
  assert(model.edges[0].lastHandoffAt === iso(20), 'handoff timestamp is the scan_complete frame')
  assert(model.edges[0].state === 'active', 'edge active while scanner runs', model.edges[0].state)
  assert(model.overallProgress === 38, 'overall = 25% + 50%×25% = 38%', String(model.overallProgress))
  assert(/not measurable: Patcher, Migration Operator/.test(model.progressBasis), 'basis names unmeasured stages', model.progressBasis)
}

/* ------------------------------------------------------------------ */
console.log('\n[6] Sandbox simulations never count as agent work')
{
  const model = buildAgentWorkflow({ now: NOW, agents: [], heartbeats: [], jobs: [job('sim', { isSandbox: true, status: 'running', progress: 60 })], evidence: EVIDENCE })
  assert(node(model, 'operator').status === 'idle', 'operator stays idle', node(model, 'operator').status)
  assert(model.simulationsExcluded === 1, 'simulation is counted as excluded')
}

/* ------------------------------------------------------------------ */
console.log('\n[7] Approval and authority gates')
{
  const pending = buildAgentWorkflow({ now: NOW, agents: [agent('o1', 'operator')], heartbeats: [], jobs: [job('j1', { approval: PENDING })], evidence: EVIDENCE })
  assert(node(pending, 'operator').status === 'awaiting_approval', 'unapproved cutover awaits approval', node(pending, 'operator').status)

  const noOperator = buildAgentWorkflow({ now: NOW, agents: [], heartbeats: [], jobs: [job('j1')], evidence: EVIDENCE })
  assert(node(noOperator, 'operator').status === 'blocked', 'approved cutover with no operator is blocked', node(noOperator, 'operator').status)

  const unauthorised = buildAgentWorkflow({
    now: NOW,
    agents: [agent('p1', 'patcher', { writeAuthority: { remediation: false, migration: false } })],
    heartbeats: [],
    jobs: [job('r1', { executionClass: 'remediation' })],
    evidence: EVIDENCE,
  })
  assert(node(unauthorised, 'patcher').status === 'blocked', 'patcher without write authority never claims', node(unauthorised, 'patcher').status)

  const ready = buildAgentWorkflow({ now: NOW, agents: [agent('o1', 'operator')], heartbeats: [], jobs: [job('j1')], evidence: EVIDENCE })
  assert(node(ready, 'operator').status === 'queued', 'approved + authorised online operator → queued', node(ready, 'operator').status)

  const offline = buildAgentWorkflow({ now: NOW, agents: [agent('o1', 'operator', { lastSeenAt: iso(60) })], heartbeats: [], jobs: [job('j1')], evidence: EVIDENCE })
  assert(node(offline, 'operator').status === 'waiting', 'authorised operator offline → waiting', node(offline, 'operator').status)

  /* A cutover that ran and was then reverted is neither "completed" (reads as
     migrated) nor "cancelled — withdrawn by an operator" (reads as never run). */
  const reverted = node(buildAgentWorkflow({ now: NOW, agents: [agent('o1', 'operator')], heartbeats: [], jobs: [job('j1', { status: 'rolled_back', agentId: 'o1' })], evidence: EVIDENCE }), 'operator')
  assert(reverted.status === 'rolled_back', 'all jobs rolled back → rolled_back, not cancelled', `${reverted.status}: ${reverted.reason}`)
  assert(!/withdrawn/.test(reverted.reason) && /not migrated/.test(reverted.reason), 'rolled-back stage says the asset is not migrated', reverted.reason)
  const mixed = node(buildAgentWorkflow({ now: NOW, agents: [agent('o1', 'operator')], heartbeats: [], jobs: [job('j1', { status: 'rolled_back', agentId: 'o1' }), job('j2', { status: 'completed', agentId: 'o1' })], evidence: EVIDENCE }), 'operator')
  assert(mixed.status === 'completed' && /rolled back/.test(mixed.currentTask), 'completed + rolled back → completed, naming the rollback', `${mixed.status}: ${mixed.currentTask}`)
}

/* ------------------------------------------------------------------ */
console.log('\n[8] Host metrics are agent-reported; Windows load is unmeasured')
{
  const telemetry = { host: { platform: 'win32', loadAverage1m: 0, cpuCount: 8 }, memory: { usedPercent: 61, agentRssBytes: 90_000_000 }, counters: { scanCount: 3, errorCount: 0, queueDepth: 0 } }
  const model = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector', { telemetry })], heartbeats: [], jobs: [], evidence: EVIDENCE })
  const metrics = node(model, 'collector').metrics
  assert(metrics.cpuLoadPct === null, 'win32 load average is null, not 0%')
  assert(metrics.memoryUsedPct === 61, 'memory is the reported value')
  assert(node(model, 'scanner').metrics.reporting === 0 && node(model, 'scanner').metrics.memoryUsedPct === null, 'no scanner telemetry → null metrics')
}

/* ------------------------------------------------------------------ */
console.log('\n[9] Safety checklist marks only recorded safeguards verified')
{
  const model = buildAgentWorkflow({ now: NOW, agents: [], heartbeats: [], jobs: [], evidence: EVIDENCE })
  const unapproved = safetyChecklist(job('j1', { approval: PENDING }), model)
  const state = (items: ReturnType<typeof safetyChecklist>, id: string) => items.find((item) => item.id === id)?.state
  assert(state(unapproved, 'approval') === 'pending', 'unapproved → approval pending')
  assert(state(unapproved, 'snapshot') === 'pending', 'no snapshot recorded → pending')
  assert(state(unapproved, 'completion') === 'pending', 'not completed → pending')
  assert(unapproved.length === 12, 'twelve safeguards')

  const done = safetyChecklist(job('j2', {
    status: 'completed', validationStatus: 'passed', validationCount: 2, executionBacked: true,
    metadata: { preChangeSnapshotId: 'snap-123456789abc', dependencies: [] },
    logs: [{ id: 'l1', eventType: 'migration-validation', message: 'passed', severity: 'success', createdAt: iso(2), metadata: {} }],
  }), model)
  assert(['snapshot', 'health', 'completion', 'audit', 'approval', 'cutover-auth'].every((id) => state(done, id) === 'verified'), 'completed + validated + snapshot → verified')

  const remediation = safetyChecklist(job('r1', { executionClass: 'remediation' }), model)
  assert(state(remediation, 'cutover-auth') === 'not_applicable', 'remediation has no cutover gate')

  const sandbox = safetyChecklist(job('s1', { isSandbox: true }), model)
  assert(sandbox.length === 1 && sandbox[0].state === 'not_applicable', 'sandbox → single N/A item')

  const legacyTarget = safetyChecklist(job('j3', { toAlgo: 'RSA-4096' }), model)
  assert(state(legacyTarget, 'pqc-settings') === 'failed', 'non-PQC target fails PQC settings check')
}

/* ------------------------------------------------------------------ */
console.log('\n[10] Guardrails derive from recorded blocks and findings only')
{
  const jobs = [job('j1', { dispatchBlock: { kind: 'out-of-scope', requires: 'allowedPaths', reason: 'Path /etc/nginx is outside the agent policy.', at: iso(3) } })]
  const model = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector'), agent('s1', 'scanner')], heartbeats: [], jobs, evidence: EVIDENCE })
  const risks = deriveRisks(model, jobs)
  assert(risks.some((risk) => risk.id === 'unauthorised-path' && risk.agent === 'patcher'), 'out-of-scope block → unauthorised path risk')
  assert(risks.some((risk) => risk.id === 'legacy-algorithms' && risk.severity === 'critical'), 'critical exposures → critical legacy-algorithm risk')
  assert(risks[0].severity === 'critical', 'sorted most severe first')

  const clean = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector'), agent('s1', 'scanner')], heartbeats: [], jobs: [], evidence: { ...EVIDENCE, exposures: { critical: 0, high: 0, medium: 0, low: 0 } } })
  assert(deriveRisks(clean, []).every((risk) => risk.id !== 'legacy-algorithms'), 'no exposures → no legacy-algorithm risk (negative control)')
}

/* ------------------------------------------------------------------ */
console.log('\n[11] Secrets are redacted from event detail')
{
  const out = redactDetail({ apiToken: 'abc', password: 'x', keyRotations: 4, note: '-----BEGIN RSA PRIVATE KEY----- MII...', nested: { authorization: 'Bearer y' } }) as Record<string, any>
  assert(out.apiToken === '[redacted]' && out.password === '[redacted]', 'credential keys redacted')
  assert(out.keyRotations === 4, 'counters named like keys are kept')
  assert(out.note === '[redacted]', 'PEM private key value redacted')
  assert(out.nested.authorization === '[redacted]', 'nested authorization redacted')
}

/* ------------------------------------------------------------------ */
console.log('\n[12] Events are attributed, ordered newest-first and bounded')
{
  const heartbeats = Array.from({ length: 450 }, (_, index) => frame('c1', 600 - index, 'discovering_cryptography', 50))
  const model = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector')], heartbeats, jobs: [job('j1', { logs: [{ id: 'l1', eventType: 'agent-job-claimed', message: 'claimed', severity: 'info', createdAt: iso(0.5), metadata: { token: 's3cret' } }] })], evidence: EVIDENCE })
  assert(model.events.length === 400 && model.eventsTruncated, 'bounded to 400 and flagged truncated')
  assert(model.events[0].agent === 'operator' && model.events[0].jobId === 'j1', 'newest event is the job claim, attributed to the operator')
  assert(model.events[0].detail.token === '[redacted]', 'job event metadata redacted')
  assert(model.events.every((event, index) => index === 0 || Date.parse(model.events[index - 1].at) >= Date.parse(event.at)), 'sorted newest first')
}

/* ------------------------------------------------------------------ */
console.log('\n[13] Workflow tree: each deployed agent carries its OWN state, not the stage roll-up')
{
  const heartbeats = [frame('c1', 6, 'connecting', 2), frame('c1', 1, 'inspecting_certificates', 45)]
  const model = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector'), agent('c2', 'collector')], heartbeats, jobs: [], evidence: EVIDENCE })
  const fleet = node(model, 'collector').fleet.agents
  const c1 = fleet.find((item) => item.id === 'c1')!
  const c2 = fleet.find((item) => item.id === 'c2')!
  assert(fleet.length === 2, 'both collectors are children of the Collector stage')
  assert(node(model, 'collector').status === 'running', 'stage roll-up is running')
  assert(c1.state === 'running' && c1.progress === 45, 'c1 running at its own reported 45%', `${c1.state} ${c1.progress}`)
  assert(c1.startedAt === iso(6) && c1.stage === 'inspecting_certificates', 'c1 start + stage come from its own frames')
  assert(c2.state === 'waiting' && c2.progress === null, 'negative control: idle sibling c2 is NOT shown as running', `${c2.state} ${c2.progress}`)
  assert(/no scan frame/i.test(c2.reason), 'c2 says why it is waiting')
  assert(c1.role === 'collector' && c1.authorised === null && c1.jobs === null, 'read-only role has no write authority or job tally')
}

/* ------------------------------------------------------------------ */
console.log('\n[14] Per-agent presence, stalls, errors, disablement and revocation')
{
  const heartbeats = [
    frame('done', 40, 'connecting', 2), frame('done', 38, 'scan_complete', 100, { evidenceCount: 120, accepted: 118, rejectedByPolicy: 2 }),
    frame('stall', 40, 'connecting', 2), frame('stall', 35, 'building_cbom', 75),
    { id: 'e1', agentId: 'err', status: 'error', telemetry: { error: 'permission denied: /etc/ssl' }, observedAt: iso(2) },
    { id: 'd1', agentId: 'off', status: 'disabled', telemetry: { reason: 'policy' }, observedAt: iso(2) },
  ]
  const model = buildAgentWorkflow({
    now: NOW,
    agents: [
      agent('done', 'scanner', { lastSeenAt: iso(30) }),
      agent('stall', 'scanner', { lastSeenAt: iso(35) }),
      agent('err', 'scanner'),
      agent('off', 'scanner'),
      agent('never', 'scanner', { lastSeenAt: null }),
      agent('gone', 'scanner', { revoked: true }),
    ],
    heartbeats,
    jobs: [],
    evidence: EVIDENCE,
  })
  const get = (id: string) => node(model, 'scanner').fleet.agents.find((item) => item.id === id)
  assert(get('done')?.state === 'completed' && get('done')?.online === false, 'completed run on an offline host: completed, shown offline')
  assert(get('done')?.lastRun?.evidence === 120 && get('done')?.lastRun?.rejected === 2, 'latest-run evidence/rejections are that agent\'s own')
  assert(get('stall')?.state === 'blocked' && /stopped reporting/.test(get('stall')!.reason), 'stalled run → blocked with reason')
  assert(get('err')?.state === 'failed' && /permission denied/.test(get('err')!.reason), 'error heartbeat → failed, quoting the agent')
  assert(get('off')?.state === 'paused' && get('off')?.currentTask === 'Disabled', 'disabled agent → paused')
  assert(get('never')?.state === 'waiting' && /never checked in/i.test(get('never')!.reason), 'never-seen agent says so')
  assert(!get('gone'), 'revoked agent is not drawn in the tree')
}

/* ------------------------------------------------------------------ */
console.log('\n[15] Write roles: claimed jobs, authority and claimable work per agent')
{
  const remediation = (id: string, overrides: Partial<WorkflowJob> = {}) => job(id, { executionClass: 'remediation', ...overrides })
  const jobs = [
    remediation('r1', { status: 'running', executionBacked: true, progress: 60, agentId: 'p1', agentName: 'patcher-p1', currentStep: 'Applying config', startedAt: iso(3) }),
    remediation('r2', { status: 'queued' }),
  ]
  const agents = [
    agent('p1', 'patcher'),
    agent('p2', 'patcher'),
    agent('p3', 'patcher', { writeAuthority: { remediation: false, migration: false } }),
    agent('p4', 'patcher', { lastSeenAt: iso(90) }),
  ]
  const model = buildAgentWorkflow({ now: NOW, agents, heartbeats: [], jobs, evidence: EVIDENCE })
  const get = (id: string) => node(model, 'patcher').fleet.agents.find((item) => item.id === id)!
  assert(get('p1').state === 'running' && get('p1').progress === 60, 'p1 running its claimed job at the job\'s reported 60%', `${get('p1').state} ${get('p1').progress}`)
  assert(get('p1').jobs?.claimed === 1 && get('p1').jobs?.running === 1, 'p1 job tally counts only jobs it claimed')
  assert(get('p2').state === 'queued' && get('p2').jobs?.claimed === 0, 'p2 (authorised, online) is queued for the claimable job, claimed none')
  assert(get('p3').state === 'blocked' && get('p3').authorised === false, 'p3 without authority is blocked while approved work waits')
  assert(get('p4').state === 'waiting' && /approved job/.test(get('p4').reason), 'offline authorised p4 waits, naming the queued work')

  const noWork = buildAgentWorkflow({ now: NOW, agents: [agents[2]], heartbeats: [], jobs: [], evidence: EVIDENCE })
  const p3 = node(noWork, 'patcher').fleet.agents[0]
  assert(p3.state === 'idle' && p3.currentTask === 'No write authority', 'negative control: no work → unauthorised agent is idle, not blocked')

  const unbacked = buildAgentWorkflow({ now: NOW, agents: [agents[0]], heartbeats: [], jobs: [remediation('r3', { status: 'running', executionBacked: false, progress: 80, agentId: 'p1' })], evidence: EVIDENCE })
  assert(node(unbacked, 'patcher').fleet.agents[0].progress === null, 'progress is null when no agent execution backs it (no invented %)')
}

/* ------------------------------------------------------------------ */
console.log('\n[16] Operator: latest outcome per agent wins')
{
  const failedThenDone = [
    job('m1', { status: 'failed', agentId: 'o1', updatedAt: iso(30), metadata: { failureReason: 'TLS handshake failed after cutover' } }),
    job('m2', { status: 'completed', agentId: 'o1', updatedAt: iso(5), completedAt: iso(5), validationStatus: 'passed' }),
  ]
  const recovered = node(buildAgentWorkflow({ now: NOW, agents: [agent('o1', 'operator')], heartbeats: [], jobs: failedThenDone, evidence: EVIDENCE }), 'operator').fleet.agents[0]
  assert(recovered.state === 'completed' && recovered.jobs?.failed === 1, 'a later completion supersedes an earlier failure (failure still counted)', recovered.state)
  const stillFailed = node(buildAgentWorkflow({ now: NOW, agents: [agent('o1', 'operator')], heartbeats: [], jobs: [failedThenDone[0]], evidence: EVIDENCE }), 'operator').fleet.agents[0]
  assert(stillFailed.state === 'failed' && /TLS handshake/.test(stillFailed.reason), 'latest failed job → failed, with the recorded reason')
}

/* ------------------------------------------------------------------ */
console.log('\n[17] Per-agent host metrics and events stay with their own agent')
{
  const routine = (agentId: string, minutesAgo: number, usedPercent: number): WorkflowHeartbeatRow => ({
    id: `r-${agentId}-${minutesAgo}`, agentId, status: 'active', observedAt: iso(minutesAgo),
    telemetry: { memory: { usedPercent }, host: { platform: 'linux', loadAverage1m: 1, cpuCount: 4 } },
  })
  const heartbeats = [
    ...Array.from({ length: 30 }, (_, index) => routine('a1', 60 - index, 40 + index)),
    routine('a2', 3, 91),
    frame('a1', 1, 'discovering_cryptography', 30),
    { id: 'err-a2', agentId: 'a2', status: 'error', telemetry: { error: 'disk full' }, observedAt: iso(1) },
  ]
  const model = buildAgentWorkflow({
    now: NOW,
    agents: [
      agent('a1', 'collector', { telemetry: { memory: { usedPercent: 69 }, host: { platform: 'linux', loadAverage1m: 1, cpuCount: 4 } } }),
      agent('a2', 'collector', { telemetry: { memory: { usedPercent: 91 }, host: { platform: 'win32', loadAverage1m: 0, cpuCount: 8 } } }),
    ],
    heartbeats,
    jobs: [],
    evidence: EVIDENCE,
  })
  const get = (id: string) => node(model, 'collector').fleet.agents.find((item) => item.id === id)!
  assert(get('a1').metrics.memoryUsedPct === 69 && get('a1').metrics.cpuLoadPct === 25, 'a1 metrics are its own last report (69% mem, 1/4 load)')
  assert(get('a2').metrics.cpuLoadPct === null && get('a2').platform === 'win32', 'Windows host: CPU load unmeasured, not 0%')
  assert(get('a1').metrics.series.memory.length === 24, 'per-agent series bounded to 24 points', String(get('a1').metrics.series.memory.length))
  assert(!get('a1').metrics.series.memory.includes(91), 'isolation: a2\'s samples never enter a1\'s series')
  assert(get('a2').errors === 1 && get('a1').errors === 0, 'error count is per agent')
  assert(model.events.filter((event) => event.source === 'scan-frame').every((event) => event.agentId === 'a1'), 'scan-frame events carry the reporting agent id')
  const jobModel = buildAgentWorkflow({ now: NOW, agents: [agent('o1', 'operator')], heartbeats: [], jobs: [job('jx', { agentId: 'o1', logs: [{ id: 'l1', eventType: 'agent-job-claimed', message: 'claimed', severity: 'info', createdAt: iso(1), metadata: {} }] })], evidence: EVIDENCE })
  assert(jobModel.events[0].agentId === 'o1', 'job events carry the claiming agent id')
  assert(node(jobModel, 'operator').fleet.agents[0].latestEvent?.message === 'claimed', 'agent\'s latest event is its own')
}

console.log('\n[18] Lost final progress frames settle from recorded heartbeat and command outcomes')
{
  const heartbeats = [frame('c1', 5, 'connecting', 2), frame('c1', 3, 'calculating_quantum_exposure', 85),
    { id: 'terminal-phase', agentId: 'c1', status: 'active', telemetry: { phase: 'completed', evidenceCount: 3, acceptedByControlPlane: 2 }, observedAt: iso(2) }]
  const model = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector')], heartbeats, jobs: [], evidence: EVIDENCE })
  assert(node(model, 'collector').status === 'completed', 'completed heartbeat closes a run stuck at 85%')
  assert(node(model, 'collector').progress === 100, 'terminal progress is recorded completion')
  const receipt = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector')], heartbeats: [...heartbeats.slice(0, 2), { id: 'ack', agentId: 'c1', status: 'command:scan:completed', telemetry: { result: { acceptedCount: 2 } }, observedAt: iso(2) }], jobs: [], evidence: EVIDENCE })
  assert(node(receipt, 'collector').status === 'completed', 'command acknowledgement also closes the run')
  const rerun = buildAgentWorkflow({ now: NOW, agents: [agent('c1', 'collector')], heartbeats: [...heartbeats, frame('c1', 1, 'connecting', 2)], jobs: [], evidence: EVIDENCE })
  assert(node(rerun, 'collector').status === 'running' && node(rerun, 'collector').startedAt === iso(1), 'a later scheduled cycle has its own start')
}

console.log('\n[19] Requested scan receipts never borrow another cycle’s progress')
{
  const command: AgentCommand = { id: 'cmd-1', type: 'scan', status: 'queued', queuedAt: iso(5), requestedBy: 'test-tenant' }
  const unrelated = [{ status: 'scan_progress', telemetry: { stage: 'building_cbom', progress: 75 }, observed_at: iso(4) }]
  assert(trackRequestedScan(command, unrelated, NOW).progress === null, 'queued request does not borrow an already-running scheduled scan')
  const frames = [{ status: 'command:scan:running', telemetry: { commandId: command.id }, observed_at: iso(3) }, { status: 'scan_progress', telemetry: { stage: 'building_cbom', progress: 75 }, observed_at: iso(2) }]
  assert(trackRequestedScan({ ...command, status: 'running' }, frames, NOW).progress === 75, 'legacy command running acknowledgement bounds its progress')
  const done = { ...command, status: 'completed' as const, startedAt: iso(3), completedAt: iso(1), result: { acceptedCount: 0, evidenceCount: 3, rejectedByPolicy: 3 } }
  const tracked = trackRequestedScan(done, [...frames, ...unrelated, { status: 'scan_progress', telemetry: { progress: 8 }, observed_at: iso(0) }], NOW)
  assert(tracked.state === 'completed' && tracked.progress === 100 && tracked.acceptedCount === 0, 'zero accepted remains zero and a new scheduled run cannot reset the receipt')
  assert(trackRequestedScan({ ...done, status: 'failed', error: 'Upload refused' }, [], NOW).state === 'failed', 'failed command remains failed')
  assert(trackRequestedScan({ ...command, status: 'running', startedAt: iso(20) }, [], NOW).state === 'stalled', 'silent command is interrupted, not perpetually running')
  const missingAck = trackRequestedScan({ ...command, status: 'running', startedAt: iso(3) }, [...frames, { status: 'active', telemetry: { phase: 'completed', evidenceCount: 4, acceptedByControlPlane: 4 }, observed_at: iso(1) }], NOW)
  assert(missingAck.state === 'completed' && missingAck.acceptedCount === 4, 'terminal heartbeat settles the receipt when the final command acknowledgement is lost')
  assert(scanWorkflowPath('c1', 'cmd-1').includes('agentId=c1&commandId=cmd-1') && scanWorkflowPath('c1', 'cmd-1').endsWith('#agent-workflow'), 'scan destination carries command identity and workflow anchor')
}

console.log('\n[20] Asset source attribution is evidence-based and filterable')
{
  const source = scanSourceFor({ assetType: 'server', sourceType: 'local-agent' }, { id: 'c1', hostname: 'TestVM', platform: 'win32' })
  assert(source.kind === 'windows-device', 'Windows is reported, but a VM-like hostname does not prove virtualization')
  const hardware = classifyHostIdentity('VMware, Inc.', 'VMware Virtual Platform')
  assert(scanSourceFor({ assetType: 'server' }, { id: 'c1', platform: 'win32', metadata: { lastTelemetry: { host: hardware } } }).kind === 'virtual-machine', 'VMware hardware evidence identifies a virtual machine')
  assert(classifyHostIdentity('Generic vendor', 'Unknown model').virtualization.detected === null, 'unrecognized hardware stays unknown, never asserted physical')
  assert(scanSourceFor({ assetType: 'endpoint', target: 'https://example.com' }, { id: 'c1', platform: 'win32', metadata: { lastTelemetry: { host: hardware } } }).kind === 'web-application', 'remote web endpoints do not inherit the collector’s VM classification')
  assert(scanSourceFor({ assetType: 'virtual-machine' }).kind === 'virtual-machine', 'explicit VM evidence is labeled VM')
  assert(scanSourceFor({ assetType: 'kubernetes-cluster' }).kind === 'kubernetes', 'Kubernetes source is identified')
  assert(scanSourceFor({ assetType: 'repository', target: 'https://github.com/acme/repo' }).kind === 'github-repository', 'GitHub label requires repository context')
  assert(scanSourceFor({ assetType: 'endpoint', target: 'https://github.com' }).kind === 'web-application', 'a web scan of github.com is not labeled a repository scan')
  assert(scanSourceFor({ assetType: 'kms-key', sourceType: 'connector' }, undefined, { id: 'aws-1', provider: 'aws' }).kind === 'cloud', 'cloud-provider connector evidence is labeled cloud')
  assert(scanSourceFor({ assetType: 'device', sourceType: 'connector' }, undefined, { id: 'messaging-1', provider: 'qguard-messaging' }).kind !== 'cloud', 'a non-cloud integration is never mislabeled cloud')
  const asset = { id: 'a1', name: 'TestVM', type: 'server', metadata: { scanSources: [source], last_scanned_at: iso(1) }, cryptoInventory: [] }
  assert(!assetIsInternetFacing({ ...asset, type: 'endpoint-security' }), 'local device evidence does not prove Internet exposure')
  assert(assetIsInternetFacing({ ...asset, metadata: { ...asset.metadata, public: true } }), 'explicit public-exposure evidence is preserved')
  assert(assetScanSources(asset)[0].agentId === 'c1', 'agent identity survives the asset provenance projection')
  const register = buildAssetRegister({ now: NOW, snapshot: { summary: {}, assets: { assets: [asset] } } })
  assert(register.rows[0].pqcStatus === 'not-measured', 'discovery without cryptographic observations never claims PQC readiness')
  assert(filterRows(register.rows, { agentId: 'c1' }).length === 1 && filterRows(register.rows, { agentId: 'other' }).length === 0, 'asset register filters the exact agent provenance')
  assert(filterRows(register.rows, { sourceKind: 'windows-device' }).length === 1 && filterRows(register.rows, { sourceKind: 'cloud' }).length === 0, 'source category filter is exact')
}

console.log('\n[21] Discovery cards project accepted evidence and stay in the reporting workspace')
{
  const evidence: ScannerEvidenceRecord = {
    id: 'e-1',
    agentId: 'scanner-1',
    sourceType: 'local-agent',
    evidenceType: 'tls-certificate',
    assetName: 'example.test',
    target: 'https://user:pass@example.test/private?token=hidden',
    observedAlgorithm: 'RSA-2048',
    certificateFingerprint: '11:22:33',
    observedAt: iso(1),
  }
  const [finding] = scanEvidenceWithModules([evidence], 'fixture')
  assert(finding?.target.id === evidence.id, 'classified finding joins the exact originating evidence record')
  const observed = projectAgentDiscovery(evidence, undefined, false, iso(-5))
  assert(observed.map((item) => item.kind).join(',') === 'endpoint,certificate,algorithm', 'one evidence record can produce three separate, traceable cards')
  assert(observed.every((item) => !item.severity && item.asset === 'example.test'), 'observation alone has no severity and the target omits credential and query data')
  const classified = projectAgentDiscovery(evidence, finding, true, iso(2))
  assert(classified.find((item) => item.kind === 'algorithm')?.recommendation === finding?.recommendation, 'algorithm uses the originating finding recommendation')
  assert(classified.find((item) => item.kind === 'certificate')?.severity === 'critical', 'certificate expiration is measured at the observation time')
  assert(!projectAgentDiscovery({ ...evidence, observedAt: undefined }, undefined, false, iso(2)).some((item) => item.severity), 'unknown observation time cannot establish expiration')
  const protocol = projectAgentDiscovery({ ...evidence, evidenceType: 'tls-protocol', observedAlgorithm: 'TLSv1.2' }, undefined, false, null)
  assert(protocol.length === 1 && protocol[0].kind === 'endpoint' && protocol[0].protocol === 'TLSv1.2', 'a negotiated protocol is endpoint evidence, not an algorithm')
  assert(projectAgentDiscovery({ ...evidence, id: undefined }, undefined, false, null).length === 0, 'records without an evidence reference do not render')
  const cursor = busStats().sequence
  let ownNotifications = 0
  let otherNotifications = 0
  const own = subscribe('workspace-a', () => { ownNotifications += 1 })
  const other = subscribe('workspace-b', () => { otherNotifications += 1 })
  publishAgentEvent('workspace-a', AGENT_DISCOVERY_EVENT, evidence.agentId!, { discoveries: classified })
  own()
  other()
  const [frame] = eventsSince('workspace-a', cursor)
  assert(ownNotifications === 1 && frame?.agentId === evidence.agentId, 'the reporting workspace receives its own agent frame')
  assert(otherNotifications === 0 && eventsSince('workspace-b', cursor).length === 0, 'other workspaces do not receive or replay the frame')
}

console.log(`\n${failures ? `✗ ${failures} check(s) failed` : '✓ all live agent workflow checks passed'}\n`)
process.exit(failures ? 1 : 0)
