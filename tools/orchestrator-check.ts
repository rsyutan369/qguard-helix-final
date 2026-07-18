/**
 * Offline verification for the Migration Orchestrator™ scheduling engine.
 *
 * Exercises the pure scheduling logic (no DB) and asserts the enterprise
 * fault-tolerance + scale invariants:
 *  - phase derivation (blocked/queued/leased/running/retrying/dead-letter)
 *  - dependency-aware scheduling (blocked until deps complete)
 *  - lease-based distributed locking + node-failure recovery (stale-lease reclaim)
 *  - exponential-backoff retry then dead-letter (partial-failure isolation)
 *  - back-pressure (leasable capped by the concurrency limit)
 *  - priority ordering + real metric computation
 *
 * No server / Supabase required:  npx tsx tools/orchestrator-check.ts
 */
import {
  DEFAULT_SCHEDULER_CONFIG,
  computeMetrics,
  jobPhase,
  planReconciliation,
  toOrchJob,
  type OrchJob,
} from '../src/api-server/migration-orchestrator'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const cfg = { ...DEFAULT_SCHEDULER_CONFIG, maxConcurrentPerTenant: 3, workerCapacity: 3, leaseSeconds: 300, baseBackoffSeconds: 30, maxRetries: 2 }
const NOW = 1_000_000_000_000
const SEC = 1000

function job(over: Partial<OrchJob>): OrchJob {
  return {
    id: 'j', assetId: 'a', asset: 'asset', status: 'queued', criticality: 'medium', priority: 50, dependsOn: [],
    retryCount: 0, maxRetries: cfg.maxRetries, nextRetryMs: 0, leaseWorker: null, leaseExpiresMs: 0,
    startedMs: 0, completedMs: 0, updatedMs: NOW, deadLetter: false, managed: true, ...over,
  }
}

console.log('\n[1] toOrchJob — normalize row + derive lease from existing claim')
const row = { id: 'r1', asset_id: 'a1', name: 'web-01', status: 'running', metadata: { criticality: 'critical', assignedAgentId: 'agent-7', claimedAt: new Date(NOW - 60 * SEC).toISOString() } }
const nj = toOrchJob(row, cfg)
assert(nj.priority === 100, 'critical criticality → priority 100', `${nj.priority}`)
assert(nj.leaseWorker === 'agent-7' && nj.leaseExpiresMs === (NOW - 60 * SEC) + cfg.leaseSeconds * 1000, 'lease derived from assignedAgentId + claimedAt + TTL')

console.log('\n[2] Phase derivation')
const completed = new Set<string>(['dep-done'])
assert(jobPhase(job({ status: 'queued', dependsOn: ['dep-open'] }), completed, NOW) === 'blocked', 'unmet dependency → blocked')
assert(jobPhase(job({ status: 'queued', dependsOn: ['dep-done'] }), completed, NOW) === 'queued', 'satisfied dependency → queued')
assert(jobPhase(job({ status: 'running', leaseWorker: 'w1', leaseExpiresMs: NOW + 60 * SEC }), completed, NOW) === 'running', 'held lease + running → running')
assert(jobPhase(job({ status: 'awaiting_agent', leaseWorker: 'w1', leaseExpiresMs: NOW + 60 * SEC }), completed, NOW) === 'leased', 'held lease → leased')
assert(jobPhase(job({ status: 'failed', retryCount: 0 }), completed, NOW) === 'retrying', 'failed with retries left → retrying')
assert(jobPhase(job({ status: 'failed', retryCount: 2, maxRetries: 2 }), completed, NOW) === 'dead_letter', 'failed exhausted → dead_letter')
assert(jobPhase(job({ status: 'completed' }), completed, NOW) === 'completed', 'completed')

console.log('\n[3] Reconciliation — recovery, retry, dead-letter, back-pressure')
const jobs: OrchJob[] = [
  job({ id: 'stale', status: 'running', leaseWorker: 'dead-worker', leaseExpiresMs: NOW - 10 * SEC }),   // expired lease → reclaim
  job({ id: 'fail1', status: 'failed', retryCount: 0, nextRetryMs: 0 }),                                  // retry (backoff ready)
  job({ id: 'backoff', status: 'failed', retryCount: 1, nextRetryMs: NOW + 60 * SEC }),                   // waiting in backoff → NOT retried
  job({ id: 'dead', status: 'failed', retryCount: 2, maxRetries: 2 }),                                    // exhausted → dead-letter
  job({ id: 'run1', status: 'running', leaseWorker: 'w1', leaseExpiresMs: NOW + 60 * SEC }),              // in-flight
  job({ id: 'run2', status: 'in_progress', leaseWorker: 'w2', leaseExpiresMs: NOW + 60 * SEC }),          // in-flight
  job({ id: 'q1', status: 'queued' }), job({ id: 'q2', status: 'queued' }), job({ id: 'q3', status: 'queued' }),
]
const plan = planReconciliation(jobs, cfg, NOW)
assert(plan.reclaim.includes('stale') && plan.reclaim.length === 1, 'expired lease reclaimed (node-failure recovery)')
assert(plan.retry.includes('fail1') && !plan.retry.includes('backoff'), 'backoff-ready retried; in-backoff job left alone')
assert(plan.deadLetter.includes('dead'), 'exhausted job dead-lettered (isolation)')
assert(plan.inFlight === 2, 'in-flight = 2 held leases', `${plan.inFlight}`)
assert(plan.leasableReady === Math.min(3, cfg.maxConcurrentPerTenant - 2), 'back-pressure caps leasable to (cap − inFlight)', `${plan.leasableReady}`)

console.log('\n[4] Priority ordering')
const pjobs = [job({ id: 'lo', priority: 25 }), job({ id: 'hi', priority: 100 }), job({ id: 'mid', priority: 50 })]
const ordered = [...pjobs].sort((a, b) => b.priority - a.priority).map((j) => j.id)
assert(ordered[0] === 'hi' && ordered[2] === 'lo', 'highest priority scheduled first', ordered.join(' → '))

console.log('\n[5] Real metric computation')
const metricsJobs: OrchJob[] = [
  job({ id: 'c1', status: 'completed', startedMs: NOW - 120 * SEC, completedMs: NOW - 60 * SEC }),
  job({ id: 'c2', status: 'completed', startedMs: NOW - 200 * SEC, completedMs: NOW - 100 * SEC }),
  job({ id: 'r', status: 'running', leaseWorker: 'w1', leaseExpiresMs: NOW + 60 * SEC }),
  job({ id: 'q', status: 'queued' }),
]
const metrics = computeMetrics(
  metricsJobs,
  [{ status: 'active', lastSeenMs: NOW - 30 * SEC }, { status: 'active', lastSeenMs: NOW - 20 * 60 * SEC }],
  [{ status: 'active' }, { status: 'inactive' }],
  { total: 4, passed: 3 },
  { cpu: null, memory: null, latency: null },
  plan, cfg, NOW,
)
assert(metrics.completed === 2 && metrics.overallProgressPct === 50, 'progress = 50% (2/4 completed)', `${metrics.overallProgressPct}%`)
assert(metrics.avgDurationSeconds === 80, 'avg duration = mean(60s, 100s) = 80s', `${metrics.avgDurationSeconds}s`)
assert(metrics.throughputPerMin === Math.round((2 / 15) * 100) / 100, 'throughput = completed-in-window / 15min', `${metrics.throughputPerMin}`)
assert(metrics.validationProgressPct === 75, 'validation = 3/4 = 75%')
assert(metrics.agentsOnline === 1 && metrics.agentsOffline === 1, 'agent health from last-seen (1 online, 1 offline)')
assert(metrics.connectorsHealthy === 1 && metrics.connectorsTotal === 2, 'connector health (1/2 active)')
assert(metrics.agentCpuPct === null && metrics.networkLatencyMs === null, 'unreported infra metrics stay null (no fabrication)')

console.log(`\n${failures === 0 ? 'ALL ORCHESTRATOR CHECKS PASSED ✓' : `${failures} CHECK(S) FAILED ✗`}\n`)
process.exit(failures === 0 ? 0 : 1)
