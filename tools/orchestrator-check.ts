/**
 * Offline verification for the PQC orchestration model and its router.
 *
 *   npx tsx tools/orchestrator-check.ts
 *
 * No server, no Supabase. Each section names the defect it pins:
 *  [1] the router is READ-ONLY (the old GET/SSE tick re-queued running and
 *      failed jobs), header-auth only, and selects only real columns (the old
 *      select asked for migration_jobs.criticality → 42703 → zero jobs, always)
 *  [2] phases partition the operational total; simulations are excluded
 *  [3] a silent executor is SURFACED, never re-queued
 *  [4] failure is failure — retry eligibility, no fabricated back-off
 *  [5] verification uses exact tokens; completion ≠ verified ≠ migrated asset
 *  [6] approval / dispatch / executor stages come from the shared description
 *  [7] migration-path role check (ML-KEM is key establishment, never signature)
 *  [8] unmeasured figures are null, not 0; ordering; throughput
 */
import { readFileSync } from 'node:fs'
import { buildOrchestrationSnapshot, migrationPathCheck, orchestrationStatus, type OrchestrationInputs } from '../src/lib/migration/orchestration-model'
import { isPassingValidation } from '../src/lib/migration/job-safety'
import type { OperationalAgent } from '../src/lib/migration/operational-workflow'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}
const section = (title: string) => console.log(`\n${title}`)

const NOW = Date.parse('2026-10-27T12:00:00Z')
const MIN = 60_000
const isoAgo = (minutes: number) => new Date(NOW - minutes * MIN).toISOString()
const approved = { decision: 'approve', decidedBy: 'ciso@tenant.test', decidedAt: isoAgo(600), via: 'planner-approval' }

function inputs(over: Partial<OrchestrationInputs>): OrchestrationInputs {
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

const operator = (id: string, seenMinutesAgo: number): OperationalAgent => ({
  id, name: id, role: 'operator', lastSeenAt: isoAgo(seenMinutesAgo), revoked: false, writeAuthority: { remediation: true, migration: true },
})

/* ------------------------------------------------------------------ */
section('[1] Router contract — read-only, header auth, real columns')
const routerSrc = readFileSync('src/api-server/migration-orchestrator.ts', 'utf8')
const code = routerSrc.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
// Supabase writes: .update(…)/.insert(…)/.upsert(…) and the argument-less .delete()
// (Map#delete(key) on the cache takes an argument and is not a write).
assert(!/\.(update|insert|upsert)\(/.test(code) && !/\.delete\(\s*\)/.test(code), 'no Supabase .update/.insert/.upsert/.delete() anywhere in the router')
assert(!/applyReconciliation|planReconciliation/.test(code), 'the reconciliation loop is gone')
assert(!/req\.query\.token/.test(code), 'no ?token= fallback (it also bypassed the subscription gateway)')
assert(/streamLiveSnapshot\(req, res,/.test(code), 'stream uses the shared fingerprinted live-snapshot contract')
const schema = readFileSync('supabase/dashboard-schema.sql', 'utf8')
const jobTable = schema.slice(schema.indexOf('CREATE TABLE IF NOT EXISTS migration_jobs'), schema.indexOf(');', schema.indexOf('CREATE TABLE IF NOT EXISTS migration_jobs')))
const schemaColumns = new Set(Array.from(jobTable.matchAll(/^\s{4}([a-z_]+)\s/gm)).map((m) => m[1]))
const jobsAt = code.indexOf("'migration_jobs'")
const jobSelect = jobsAt >= 0 ? /\.select\('([^']+)'\)/.exec(code.slice(jobsAt))?.[1] ?? '' : ''
const unknownColumns = jobSelect.split(',').map((c) => c.trim()).filter((c) => c && !schemaColumns.has(c))
assert(jobSelect.length > 0 && unknownColumns.length === 0, 'every migration_jobs column selected exists in dashboard-schema.sql', unknownColumns.join(', ') || jobSelect)
assert(!schemaColumns.has('criticality'), 'negative control: the schema really has no criticality column (the old select failed on it)')

/* ------------------------------------------------------------------ */
section('[2] Partition + simulation exclusion')
const mixed = buildOrchestrationSnapshot(inputs({
  agents: [operator('op-1', 1)],
  plans: new Map([['plan-1', { status: 'awaiting_agent', metadata: { approval: approved } }]]),
  plansQueried: new Set(['plan-1']),
  jobs: [
    { id: 'j-done', asset_id: 'a1', name: 'cutover web-01', job_type: 'protocol_upgrade', status: 'completed', target_algorithm: 'X25519 + ML-KEM-768', started_at: isoAgo(90), completed_at: isoAgo(30), updated_at: isoAgo(30), metadata: { planId: 'plan-1', sourceAlgorithm: 'ECDHE' } },
    { id: 'j-run', asset_id: 'a2', name: 'cutover api-01', job_type: 'protocol_upgrade', status: 'running', updated_at: isoAgo(5), metadata: { planId: 'plan-1', assignedAgentId: 'op-1', claimedAt: isoAgo(120) } },
    { id: 'j-q', asset_id: 'a3', name: 'cutover db-01', job_type: 'protocol_upgrade', status: 'queued', updated_at: isoAgo(2), metadata: { planId: 'plan-1' } },
    { id: 'sim', asset_id: 'a4', name: '[DRY RUN] web-01', job_type: 'pqc_migration', status: 'running', metadata: { dryRun: true } },
    { id: 'j-x', asset_id: 'a5', name: 'withdrawn', job_type: 'protocol_upgrade', status: 'cancelled', metadata: {} },
  ],
}))
const phaseSum = Object.values(mixed.metrics.phases).reduce((a, b) => a + b, 0)
assert(mixed.metrics.total === 4 && phaseSum === mixed.metrics.total, 'phase counts partition the operational total', `${phaseSum}/${mixed.metrics.total}`)
assert(mixed.metrics.simulationsExcluded === 1 && !mixed.jobs.some((j) => j.id === 'sim'), 'the [DRY RUN] job is excluded and counted')
assert(/1 sandbox simulation/.test(mixed.scopeNote), 'the scope note states the exclusion')
assert(mixed.metrics.completionPct === 33, 'completion = completed / (total − cancelled) = 1/3', `${mixed.metrics.completionPct}`)
assert(mixed.jobs.find((j) => j.id === 'j-run')?.phase === 'executing', 'a job claimed 120 min ago by an ONLINE agent is still executing (old model reclaimed it at 5 min)')

/* ------------------------------------------------------------------ */
section('[3] Silent executor is surfaced, never re-queued')
const silentSnap = buildOrchestrationSnapshot(inputs({
  agents: [operator('op-dead', 45)],
  plans: new Map([['plan-1', { status: 'x', metadata: { approval: approved } }]]),
  plansQueried: new Set(['plan-1']),
  jobs: [{ id: 'j-silent', asset_id: 'a1', name: 'cutover', job_type: 'protocol_upgrade', status: 'running', updated_at: isoAgo(40), metadata: { planId: 'plan-1', assignedAgentId: 'op-dead', assignedAgentName: 'op-dead' } }],
}))
const silent = silentSnap.jobs[0]
assert(silent.phase === 'executing' && silent.executorSilent === true, 'running + executor unseen for 45 min → executing AND executorSilent')
assert(/NOT re-queued/.test(silent.nextAction), 'the next action says it is not re-queued automatically')
assert(silentSnap.metrics.staleExecutions === 1 && silentSnap.metrics.assets.needsAttention === 1, 'counted as a stale execution needing attention')
const fresh = buildOrchestrationSnapshot(inputs({
  agents: [operator('op-live', 2)],
  jobs: [{ id: 'j1', name: 'x', job_type: 'protocol_upgrade', status: 'running', metadata: { assignedAgentId: 'op-live' } }],
})).jobs[0]
assert(fresh.executorSilent === false && fresh.executor.online === true, 'negative control: an agent seen 2 min ago is not silent')
const unreadFleet = buildOrchestrationSnapshot(inputs({
  agents: null,
  jobs: [{ id: 'j1', name: 'x', job_type: 'protocol_upgrade', status: 'running', metadata: { assignedAgentId: 'op-x' } }],
}))
assert(unreadFleet.jobs[0].executor.online === null && !unreadFleet.jobs[0].executorSilent, 'unreadable fleet → executor state unknown, not "silent"')
assert(unreadFleet.metrics.executors.enrolled === null && unreadFleet.metrics.executors.fleetReadable === false, 'unreadable fleet publishes null, not 0 agents')

/* ------------------------------------------------------------------ */
section('[4] Failure is failure')
const failSnap = buildOrchestrationSnapshot(inputs({
  jobs: [
    { id: 'f-approved', name: 'hndl fix', job_type: 'hndl_remediation', status: 'failed', updated_at: isoAgo(10), metadata: { approval: approved, failureReason: 'post-patch validation failed' } },
    { id: 'f-unapproved', name: 'hndl fix 2', job_type: 'hndl_remediation', status: 'error', updated_at: isoAgo(11), metadata: {} },
  ],
}))
assert(failSnap.jobs.every((j) => j.phase === 'failed'), 'failed/error → failed (old model labelled them "retrying" and re-queued them)')
assert(failSnap.jobs.find((j) => j.id === 'f-approved')?.retry === 'eligible', 'approved failed work is retry-eligible (operator decision)')
assert(failSnap.jobs.find((j) => j.id === 'f-unapproved')?.retry === 'needs-approval', 'unapproved failed work needs approval before any retry')
assert(failSnap.jobs.find((j) => j.id === 'f-approved')?.failureReason === 'post-patch validation failed', 'the executor failure reason is carried to the UI')
assert(failSnap.metrics.retryEligible === 1, 'retry-eligible count')

/* ------------------------------------------------------------------ */
section('[5] Verification — exact tokens, completion ≠ verified')
assert(/pass|success|valid|ok|complete/i.test('invalid'), 'negative control: the OLD validation regex matches "invalid"')
assert(!isPassingValidation('invalid') && !isPassingValidation('validation_failed') && isPassingValidation('passed'), 'shared exact-token predicate')
const verSnap = buildOrchestrationSnapshot(inputs({
  jobs: [
    { id: 'v-pass', asset_id: 'a1', name: 'a', job_type: 'protocol_upgrade', status: 'completed', completed_at: isoAgo(60), metadata: {} },
    { id: 'v-none', asset_id: 'a2', name: 'b', job_type: 'protocol_upgrade', status: 'completed', completed_at: isoAgo(60), metadata: {} },
    { id: 'v-invalid', asset_id: 'a3', name: 'c', job_type: 'protocol_upgrade', status: 'completed', completed_at: isoAgo(60), metadata: {} },
    { id: 'v-meta', asset_id: 'a4', name: 'd', job_type: 'protocol_upgrade', status: 'completed', completed_at: isoAgo(60), metadata: { lastValidation: { passed: true } } },
    { id: 'v-open', asset_id: 'a1', name: 'e', job_type: 'cert_transition', status: 'failed', metadata: {} },
  ],
  validations: [
    { migration_id: 'v-pass', status: 'failed', created_at: isoAgo(50) },
    { migration_id: 'v-pass', status: 'passed', created_at: isoAgo(40) },
    { migration_id: 'v-invalid', status: 'invalid', created_at: isoAgo(40) },
  ],
}))
const byId = new Map(verSnap.jobs.map((j) => [j.id, j]))
assert(byId.get('v-pass')?.verified === true && byId.get('v-pass')?.verification === 'passed', 'latest record "passed" (after an earlier failure) → verified')
assert(byId.get('v-none')?.verification === 'missing' && !byId.get('v-none')?.verified, 'completed with no record → "missing", not verified')
assert(byId.get('v-invalid')?.verification === 'failed' && !byId.get('v-invalid')?.verified, '"invalid" → validation failed, never verified')
assert(byId.get('v-meta')?.verified === true, "the job's own lastValidation.passed record counts")
assert(verSnap.metrics.completed === 4 && verSnap.metrics.verified === 2, 'completed 4, verified 2', `${verSnap.metrics.completed}/${verSnap.metrics.verified}`)
assert(verSnap.metrics.completedUnverified === 1 && verSnap.metrics.completedValidationFailed === 1, 'unverified and validation-failed are reported separately')
assert(verSnap.metrics.assets.verified === 1, 'asset a1 has a verified job but ALSO a failed job → not a verified asset; only a4 qualifies', `${verSnap.metrics.assets.verified}`)

/* ------------------------------------------------------------------ */
section('[6] Approval / dispatch / executor stages')
const stageSnap = buildOrchestrationSnapshot(inputs({
  agents: [],
  plans: new Map([['p-ok', { status: 'awaiting_agent', metadata: { approval: approved } }], ['p-bare', { status: 'approved', metadata: {} }]]),
  plansQueried: new Set(['p-ok', 'p-bare']),
  jobs: [
    { id: 's-unread', name: 'a', job_type: 'protocol_upgrade', status: 'queued', metadata: { planId: 'p-never-read' } },
    { id: 's-bare', name: 'b', job_type: 'protocol_upgrade', status: 'queued', metadata: { planId: 'p-bare' } },
    { id: 's-noagent', name: 'c', job_type: 'protocol_upgrade', status: 'queued', metadata: { planId: 'p-ok' } },
  ],
}))
const st = new Map(stageSnap.jobs.map((j) => [j.id, j]))
assert(st.get('s-unread')?.phase === 'awaiting-approval' && st.get('s-unread')?.approval.readable === false, 'unread plan → awaiting approval, approval marked unreadable (not "denied")')
assert(st.get('s-bare')?.phase === 'awaiting-approval', 'a bare status "approved" is NOT approval')
assert(st.get('s-noagent')?.phase === 'blocked' && /no Migration Operator agent is enrolled/i.test(st.get('s-noagent')?.headline || ''), 'approved but no capable agent → blocked, says why')
const ready = buildOrchestrationSnapshot(inputs({
  agents: [operator('op-1', 1)],
  plans: new Map([['p-ok', { status: 'awaiting_agent', metadata: { approval: approved } }]]),
  plansQueried: new Set(['p-ok']),
  jobs: [{ id: 'r', name: 'r', job_type: 'protocol_upgrade', status: 'queued', metadata: { planId: 'p-ok' } }],
})).jobs[0]
assert(ready.phase === 'ready' && ready.gates.length === 4, 'approved + online operator → ready, with the four shared gates')

/* ------------------------------------------------------------------ */
section('[7] Migration-path role check')
assert(migrationPathCheck('RSA-2048', 'ML-KEM-768', 'cert_transition').check === 'role-mismatch', 'certificate (signature) → ML-KEM is a role mismatch')
assert(migrationPathCheck('ECDSA P-256', 'ML-DSA-65', '').check === 'consistent', 'ECDSA → ML-DSA-65 consistent')
assert(migrationPathCheck('ECDHE', 'X25519 + ML-KEM-768', '').check === 'consistent', 'ECDHE → hybrid ML-KEM consistent')
assert(migrationPathCheck('X25519', 'ML-DSA-65', '').check === 'role-mismatch', 'key exchange → ML-DSA is a role mismatch')
assert(migrationPathCheck('RSA-2048', 'ML-KEM-768', '').check === 'unverifiable', 'bare RSA with no context is unverifiable, not a guessed pass')
assert(migrationPathCheck('ECDHE', null, '').check === 'unverifiable', 'no target recorded → unverifiable')
assert(/FIPS 203/.test(migrationPathCheck('ECDSA', 'ML-KEM-1024', '').note), 'mismatch note names the standard')

/* ------------------------------------------------------------------ */
section('[8] Null-not-zero, ordering, throughput, status vocabulary')
const empty = buildOrchestrationSnapshot(inputs({ agents: null }))
assert(!empty.hasData && empty.metrics.completionPct === null && empty.metrics.verifiedPct === null, 'empty estate → completion/verified null, not 0%')
assert(empty.metrics.avgDurationSeconds === null, 'no timed completion → avg duration null')
const order = buildOrchestrationSnapshot(inputs({
  agents: [operator('op-dead', 60)],
  jobs: [
    { id: 'o-done', name: 'a', job_type: 'x', status: 'completed', completed_at: isoAgo(5), metadata: { lastValidation: { passed: true } } },
    { id: 'o-q', name: 'b', job_type: 'x', status: 'queued', metadata: {} },
    { id: 'o-silent', name: 'c', job_type: 'x', status: 'running', metadata: { assignedAgentId: 'op-dead' } },
    { id: 'o-fail', name: 'd', job_type: 'x', status: 'failed', metadata: {} },
  ],
})).jobs.map((j) => j.id)
assert(order[0] === 'o-fail' && order[1] === 'o-silent' && order[order.length - 1] === 'o-done', 'most urgent first: failed, silent executor … verified last', order.join(' → '))
const tp = mixed.throughput
assert(tp.length === 14 && tp.reduce((s, d) => s + d.completed, 0) === 1, '14 daily buckets, one completion counted')
assert(orchestrationStatus('validation_failed') === 'failed' && orchestrationStatus('pending') === 'queued' && orchestrationStatus('validating') === 'validating', 'status vocabulary')
const validatingJob = buildOrchestrationSnapshot(inputs({ jobs: [{ id: 'v', name: 'v', job_type: 'x', status: 'validating', metadata: {} }] })).jobs[0]
assert(validatingJob.phase === 'validating', 'validating is its own phase (not folded into queued)')

console.log(`\n${failures === 0 ? 'ALL ORCHESTRATION CHECKS PASSED' : `${failures} CHECK(S) FAILED`}\n`)
process.exitCode = failures === 0 ? 0 : 1
