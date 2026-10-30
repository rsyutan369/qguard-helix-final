// Orchestration fixture built from the shapes tools/orchestrator-check.ts
// asserts on: an approved plan, a completed-but-unverified cutover, a running
// job on a live operator, a queued job, a sandbox simulation (excluded) and a
// cancelled job — run through the REAL `buildOrchestrationSnapshot`.
import { buildOrchestrationSnapshot, type OrchestrationInputs } from '../../../src/lib/migration/orchestration-model'
import type { OperationalAgent } from '../../../src/lib/migration/operational-workflow'

export const NOW = Date.now()
const isoAgo = (minutes: number) => new Date(NOW - minutes * 60_000).toISOString()
const approved = { decision: 'approve', decidedBy: 'ciso@tenant.test', decidedAt: isoAgo(600), via: 'planner-approval' }

export function inputs(over: Partial<OrchestrationInputs> = {}): OrchestrationInputs {
  return {
    jobs: [],
    executionClassOf: (job) => (String((job.metadata as Record<string, unknown> | undefined)?.planId || '') ? 'migration' : 'remediation'),
    plans: new Map(),
    plansQueried: new Set(),
    agents: [],
    validations: [],
    events: [],
    connectors: [],
    assetNames: new Map(),
    sources: { jobs: 'ok', plans: 'ok', agents: 'ok', validations: 'ok', events: 'ok', connectors: 'ok', assets: 'ok' },
    jobsTruncated: false,
    now: NOW,
    ...over,
  }
}

const operator: OperationalAgent = {
  id: 'op-1', name: 'op-1', role: 'operator', lastSeenAt: isoAgo(1), revoked: false, writeAuthority: { remediation: true, migration: true },
}

export const populated = buildOrchestrationSnapshot(inputs({
  agents: [operator],
  plans: new Map([['plan-1', { status: 'awaiting_agent', metadata: { approval: approved } }]]),
  plansQueried: new Set(['plan-1']),
  assetNames: new Map([['a1', 'web-01'], ['a2', 'api-01'], ['a3', 'db-01']]),
  jobs: [
    { id: 'j-done', asset_id: 'a1', name: 'cutover web-01', job_type: 'protocol_upgrade', status: 'completed', target_algorithm: 'X25519 + ML-KEM-768', started_at: isoAgo(90), completed_at: isoAgo(30), updated_at: isoAgo(30), created_at: isoAgo(200), metadata: { planId: 'plan-1', sourceAlgorithm: 'ECDHE' } },
    { id: 'j-run', asset_id: 'a2', name: 'cutover api-01', job_type: 'protocol_upgrade', status: 'running', started_at: isoAgo(20), updated_at: isoAgo(5), created_at: isoAgo(200), metadata: { planId: 'plan-1', assignedAgentId: 'op-1', claimedAt: isoAgo(20) } },
    { id: 'j-q', asset_id: 'a3', name: 'cutover db-01', job_type: 'protocol_upgrade', status: 'queued', updated_at: isoAgo(2), created_at: isoAgo(200), metadata: { planId: 'plan-1' } },
    { id: 'sim', asset_id: 'a4', name: '[DRY RUN] web-01', job_type: 'pqc_migration', status: 'running', metadata: { dryRun: true } },
    { id: 'j-x', asset_id: 'a5', name: 'withdrawn', job_type: 'protocol_upgrade', status: 'cancelled', metadata: {} },
  ],
}))

export const empty = buildOrchestrationSnapshot(inputs())

export const unreadable = buildOrchestrationSnapshot(inputs({
  sources: { jobs: 'ok', plans: 'ok', agents: 'unavailable', validations: 'ok', events: 'ok', connectors: 'ok', assets: 'ok' },
  jobs: [
    { id: 'j-q2', asset_id: 'a3', name: 'cutover db-01', job_type: 'protocol_upgrade', status: 'queued', updated_at: isoAgo(2), created_at: isoAgo(200), metadata: { planId: 'plan-1' } },
  ],
  plans: new Map([['plan-1', { status: 'awaiting_agent', metadata: { approval: approved } }]]),
  plansQueried: new Set(['plan-1']),
}))
