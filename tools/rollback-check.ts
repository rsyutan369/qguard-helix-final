/**
 * Offline verification for agent role enforcement + snapshot rollback.
 *
 * These are the two properties that decide whether the platform can change a
 * customer's asset and whether it can honestly claim to have changed it back.
 * Both used to be wrong in ways nothing caught:
 *
 *   • a Patcher agent claimed and executed Live Migration cutovers, because the
 *     job queue asked for the remediation capability and `agentMayWrite(...,
 *     'migration')` had no call site at all;
 *   • `restore` marked a snapshot `restored` and its job `rolled_back` the
 *     moment ANY active agent row existed, without dispatching anything — and
 *     `autoRollbackFailedJobs` did the same for every failed job, on a GET.
 *
 * Run:  npx tsx tools/rollback-check.ts
 */
import { readFileSync } from 'node:fs'
import { jobExecutionClass } from '../src/api-server/agent-scanner'
import { mapSnapshot, restorability, readExecution } from '../src/api-server/migration-snapshots'
import { AGENT_ROLLBACK_MIN_VERSION, agentVersionAtLeast } from '../src/lib/agent-installer/agent-release'
import { hashState, deriveCryptoState } from '../src/api-server/migration-snapshots'
import { approvalRefusal, isSimulationJob, jobApproval, planApproval } from '../src/lib/migration/job-safety'
import { buildLiveTelemetry, isPassingValidation } from '../src/api-server/migration'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

/* ------------------------------------------------------------------ */
console.log('\n[1] Agent type decides which jobs an agent may execute')

assert(
  jobExecutionClass({ id: '1', name: 'Rotate api.example.com certificate', job_type: 'certificate_replacement', metadata: {} }) === 'migration',
  'a certificate replacement is a Migration Operator job',
)
assert(
  jobExecutionClass({ id: '2', name: 'Cutover', job_type: 'pqc_migration', metadata: { planId: 'plan-77' } }) === 'migration',
  'a job owned by a migration plan is a Migration Operator job',
)
assert(
  jobExecutionClass({ id: '3', name: 'HNDL mitigation for /etc/nginx/nginx.conf', job_type: 'hndl_mitigation', metadata: { source: 'harvest-now' } }) === 'remediation',
  'HNDL mitigation is a Patcher job even though the text mentions migration concepts',
)
assert(
  jobExecutionClass({ id: '4', name: 'Enable TLS 1.3', job_type: 'config_patch', metadata: {} }) === 'remediation',
  'a plain config patch is a Patcher job',
)
assert(
  jobExecutionClass({ id: '5', name: 'x', job_type: '', metadata: { source: 'migration-planner' } }) === 'migration',
  'a job the Migration Planner queued is a Migration Operator job',
)

/* The enforcement itself is a backend call; assert the call SITES exist, because
   the defect was a correct helper with no caller. */
const scannerSrc = readFileSync('src/api-server/agent-scanner.ts', 'utf8')
assert(
  /agentMayWrite\(client, agent, 'migration'\)/.test(scannerSrc),
  "agentMayWrite(..., 'migration') is actually called (it had no call site)",
)
assert(
  /agentMayWrite\(client, agent, jobClass === 'migration' \? 'migration' : 'remediation'\)/.test(scannerSrc),
  'the remediation EVENT endpoint re-checks the write capability (a collector token could complete a migration)',
)

/* ------------------------------------------------------------------ */
console.log('\n[2] Snapshot-before-change is a gate, not a dashboard side effect')

const snapshotSrc = readFileSync('src/api-server/migration-snapshots.ts', 'utf8')
assert(!/autoRollbackFailedJobs/.test(snapshotSrc), 'the fabricated auto-rollback writer is gone')
assert(!/(async )?function ensurePreMigrationSnapshots/.test(snapshotSrc), 'snapshot creation is no longer a dashboard side effect')
assert(/export async function ensureSnapshotForJob/.test(snapshotSrc), 'a snapshot gate exists for the claim path')
assert(
  /await ensureSnapshotForJob\(client, agent\.user_id, job/.test(scannerSrc),
  'the agent claim path calls the snapshot gate before dispatching a job',
)
assert(
  /if \(!snapshot\.ok\) \{[\s\S]*?\r?\n {6}continue\r?\n {4}\}/.test(scannerSrc),
  'a job whose snapshot could not be created is NOT dispatched',
)

const dashboardBody = snapshotSrc.slice(
  snapshotSrc.indexOf('export async function buildSnapshotDashboard'),
  snapshotSrc.indexOf('/* Routes'),
)
assert(
  !/\.update\(|\.insert\(|createSnapshot\(/.test(dashboardBody),
  'buildSnapshotDashboard performs no writes (it ran on GET and on a 20s SSE tick)',
)

/* ------------------------------------------------------------------ */
console.log('\n[3] Restorability is derived from a real executor record')

const emptyState = deriveCryptoState([], [], [], {}, null)
const populatedState = deriveCryptoState(
  [{ name: 'Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA', algorithm: 'RSA-2048', item_type: 'TLS Cipher Suite', protocol: 'TLS 1.2' }],
  [], [], {}, 'asset-1',
)

assert(
  restorability('restorable', null, populatedState).executable === false,
  'a snapshot with captured state but NO executor record is not restorable',
)
assert(
  /nothing to undo/i.test(String(restorability('restorable', null, populatedState).reason)),
  'and the reason says there is nothing to undo',
)
assert(
  restorability('restorable', null, emptyState).executable === false &&
    /captured no cryptographic state/i.test(String(restorability('restorable', null, emptyState).reason)),
  'an empty snapshot is refused with its own reason',
)

const agentExec = readExecution({
  execution: { kind: 'agent-config', agentId: 'a1', agentName: 'web-01', targetPath: '/etc/nginx/nginx.conf', backupPath: '/etc/nginx/nginx.conf.qguard-backup-1', beforeHash: 'aa'.repeat(32), recordedAt: '2026-01-01T00:00:00Z' },
})
assert(agentExec?.kind === 'agent-config' && agentExec.backupPath === '/etc/nginx/nginx.conf.qguard-backup-1', 'an agent execution record round-trips')
assert(restorability('restorable', agentExec, populatedState).executable === true, 'a complete agent record makes the snapshot restorable')

const partialExec = readExecution({ execution: { kind: 'agent-config', agentId: 'a1', targetPath: '/etc/nginx/nginx.conf', recordedAt: 'x' } })
assert(
  restorability('restorable', partialExec, populatedState).executable === false,
  'an agent record missing the backup path / digest is NOT restorable',
)

const connectorExec = readExecution({ execution: { kind: 'cloud-connector', provider: 'aws', adapter: 'aws-elb', rollbackPlan: { restoreSslPolicy: 'ELBSecurityPolicy-2016-08' }, recordedAt: 'x' } })
assert(restorability('restorable', connectorExec, populatedState).executable === true, 'a connector record with a rollback plan is restorable')
assert(
  restorability('restorable', readExecution({ execution: { kind: 'cloud-connector', provider: 'aws', recordedAt: 'x' } }), populatedState).executable === false,
  'a connector record with NO rollback plan is not restorable',
)

assert(restorability('restoring', agentExec, populatedState).executable === false, 'a rollback already in flight blocks a second dispatch')
assert(restorability('expired', agentExec, populatedState).executable === false, 'an expired snapshot is not a restore source')
assert(restorability('deleted', agentExec, populatedState).executable === false, 'a deleted snapshot is not a restore source')

/* ------------------------------------------------------------------ */
console.log('\n[4] Integrity is measured on read, not asserted')

const good = hashState(populatedState)
const row = {
  id: 'r1', snapshot_id: 'MSNAP-2026-000001', asset_name: 'web-01', status: 'restorable',
  crypto_state: populatedState, integrity_hash: good.hash, integrity_verified: true,
  metadata: { execution: { kind: 'agent-config', agentId: 'a1', targetPath: '/p', backupPath: '/p.bak', beforeHash: 'bb'.repeat(32), recordedAt: 'x' } },
}
assert(mapSnapshot(row).integrityVerified === true, 'a snapshot whose state still hashes to its digest reads as verified')

/* The row still CLAIMS integrity_verified: true — the old code trusted exactly
   this column, which is written true at creation and never re-checked. */
const tampered = { ...row, crypto_state: { ...populatedState, algorithms: [...populatedState.algorithms, 'ML-KEM-768'] } }
assert(mapSnapshot(tampered).integrityVerified === false, 'a tampered state reads as UNVERIFIED despite integrity_verified=true on the row')
assert(mapSnapshot(tampered).restoreExecutable === false, 'and it cannot be restored')
assert(
  /integrity verification failed/i.test(String(mapSnapshot(tampered).restoreBlockedReason)),
  'and the blocked reason names the integrity failure',
)

/* ------------------------------------------------------------------ */
console.log('\n[5] Rollback is only dispatched to a runtime that can execute it')

assert(agentVersionAtLeast('1.5.3', AGENT_ROLLBACK_MIN_VERSION) === true, '1.5.3 can execute rollback')
assert(agentVersionAtLeast('1.6.0', AGENT_ROLLBACK_MIN_VERSION) === true, '1.6.0 can execute rollback')
assert(agentVersionAtLeast('1.5.2', AGENT_ROLLBACK_MIN_VERSION) === false, '1.5.2 cannot')
assert(agentVersionAtLeast('', AGENT_ROLLBACK_MIN_VERSION) === false, 'an unknown version cannot')
assert(agentVersionAtLeast(null, AGENT_ROLLBACK_MIN_VERSION) === false, 'a null version cannot')

/* ------------------------------------------------------------------ */
console.log('\n[6] The agent refuses a rollback it cannot prove')

const agentSrc = readFileSync('tools/qguard-agent/agent.ts', 'utf8')
assert(/case 'rollback':/.test(agentSrc), 'the runtime implements the rollback command')
assert(
  agentSrc.includes("!['patcher', 'operator'].includes(AGENT_ROLE) || !REMEDIATION_ENABLED || !CONFIG_PATCHES_ENABLED"),
  'a read-only agent refuses to write, whatever it is asked',
)
assert(
  /backupHash !== expectedBeforeHash/.test(agentSrc),
  'a backup that no longer matches its recorded digest is refused, not restored',
)
assert(/fileAllowedByPolicy\(targetPath, policy\)/.test(agentSrc), 'the target must still be inside the policy allowedPaths')
assert(/qguard-prerollback-/.test(agentSrc), 'the current file is copied aside first, so the rollback is itself reversible')
assert(
  /result\.verified \? 'completed' : 'failed'/.test(agentSrc),
  'an unverified write is acknowledged as FAILED, so the snapshot never flips to restored on an unproven change',
)

const bundle = readFileSync('tools/qguard-agent/dist/qguard-agent.cjs', 'utf8')
assert(/case "rollback"/.test(bundle), 'the PUBLISHED runtime bundle contains the handler (installers ship dist/, not agent.ts)')

/* ------------------------------------------------------------------ */
console.log('\n[7] Only a confirmed executor result may write "restored"')

const restoredWriters = snapshotSrc.split('\n').filter((line) => /status: (verified \? 'restored'|executor \? 'restored')/.test(line) || /'restored',$/.test(line.trim()))
assert(
  /settleAgentRollback/.test(snapshotSrc) && /status: verified \? 'restored' : 'restore_failed'/.test(snapshotSrc),
  'settleAgentRollback is the writer, and it keys on the executor-verified flag',
)
assert(
  !/status: executor \? 'restored'/.test(snapshotSrc),
  'the old "an executor EXISTS therefore it is restored" write is gone',
)
assert(
  /disposition === 'restored' \? 'rolled_back'/.test(snapshotSrc),
  'the migration job only reads rolled_back on a confirmed restore',
)
assert(restoredWriters.length <= 2, 'the number of places that can write "restored" is small enough to audit', `${restoredWriters.length}`)

/* ------------------------------------------------------------------ */
console.log('\n[8] One definition of "simulation", and it is the union')

assert(isSimulationJob({ name: 'x', job_type: 'pqc_migration', metadata: { dryRun: true } }), 'metadata.dryRun alone marks a simulation (migration.ts\'s copy missed this)')
assert(isSimulationJob({ name: 'x', job_type: 'pqc_migration', metadata: { dryRun: 'true' } }), 'string-typed flags are honoured')
assert(isSimulationJob({ name: 'x', job_type: 'pqc_migration', metadata: { sandboxMode: true } }), 'metadata.sandboxMode marks a simulation')
assert(isSimulationJob({ name: '[DRY RUN] web-01', job_type: 'pqc_migration', metadata: {} }), 'a [DRY RUN] name marks a simulation')
assert(isSimulationJob({ name: 'x', job_type: 'sandbox_asset_migration', metadata: {} }), 'a sandbox_ job type marks a simulation')
assert(!isSimulationJob({ name: 'PQC Migration: web-01', job_type: 'certificate_replacement', metadata: { planId: 'p' } }), 'a real cutover is not a simulation')

const sandboxSrc = readFileSync('src/api-server/sandbox.ts', 'utf8')
const migrationSrc = readFileSync('src/api-server/migration.ts', 'utf8')
assert(/return isSimulationJob\(job\)/.test(sandboxSrc), 'sandbox.ts delegates to the shared predicate (no private copy)')
assert(/return isSimulationJob\(\{/.test(migrationSrc), 'migration.ts delegates to the shared predicate (no private copy)')
assert(/\.filter\(\(job: any\) => !isSimulationJob\(job\)\)/.test(scannerSrc), 'the agent claim path excludes simulations (it had no check at all)')

/* ------------------------------------------------------------------ */
console.log('\n[9] Approval is positive, attributed, and lives on the approved unit')

const decided = { decision: 'approve', decidedBy: 'ciso@tenant.test', decidedAt: '2026-09-17T00:00:00Z', reason: 'window' }
assert(planApproval({ status: 'approved', metadata: {} }).approved === false, 'a bare status "approved" is NOT approval (export/sandbox used to write it)')
assert(planApproval({ status: 'awaiting_agent', metadata: {} }).approved === false, 'the planner default state is not approval')
assert(planApproval({ status: 'awaiting_agent', metadata: { approval: decided } }).approved === true, 'a recorded decision on the raw row is approval')
assert(planApproval({ status: 'awaiting_agent', migrationMetadata: { approval: decided } }).approved === true, 'a recorded decision on the MAPPED payload is approval (the shape the dispatch route passes)')
assert(planApproval({ status: 'rejected', metadata: { approval: decided } }).approved === false, 'a rejected plan is never approved, whatever the record says')
assert(planApproval({ status: 'awaiting_agent', metadata: { approval: decided } }).approvedBy === 'ciso@tenant.test', 'the verdict names the approver')

const plannedJob = { name: 'cutover', job_type: 'certificate_replacement', metadata: { planId: 'plan-1' } }
assert(jobApproval(plannedJob, null).approved === false, 'a planned job whose plan cannot be read is NOT approved')
assert(jobApproval(plannedJob, { status: 'x', metadata: { approval: decided } }).source === 'plan', 'a planned job resolves from its plan')
assert(
  jobApproval({ ...plannedJob, metadata: { planId: 'plan-1', approval: decided } }, { status: 'rejected', metadata: {} }).approved === false,
  'a job-level record cannot override a rejected plan',
)

const hndlJob = { name: 'HNDL', job_type: 'hndl_mitigation', metadata: { source: 'harvest-now' } }
assert(jobApproval(hndlJob, null).approved === false && jobApproval(hndlJob, null).source === 'job', 'an unplanned remediation job is unapproved until its own record says so')
assert(jobApproval({ ...hndlJob, metadata: { source: 'harvest-now', approval: decided } }, null).approved === true, 'and approved once it does')
assert(jobApproval({ name: '[DRY RUN] x', metadata: { approval: decided } }, null).required === false, 'a simulation needs no approval — it never reaches an agent')
assert(/Migration Planner/.test(approvalRefusal(jobApproval(plannedJob, null))), 'the refusal for planned work points to the planner')
assert(/Live Migration/.test(approvalRefusal(jobApproval(hndlJob, null))), 'the refusal for remediation points to Live Migration')

assert(/if \(assignedAgentId !== agent\.id\)/.test(scannerSrc), 'the event endpoint requires the claim (it accepted any unclaimed job)')
assert(!/if \(assignedAgentId && assignedAgentId !== agent\.id\) \{\s*jsonError\(res, 403, 'REMEDIATION_JOB_ASSIGNED'/.test(scannerSrc), 'the old "unassigned is fine" check is gone')
assert(/if \(action === 'export'\) return 'exported'/.test(migrationSrc), 'exporting a plan no longer marks it approved')

/* ------------------------------------------------------------------ */
console.log('\n[10] Live Migration counts operations that HAPPENED, once each')

assert(isPassingValidation('passed') && isPassingValidation('validated'), 'passing statuses pass')
assert(!isPassingValidation('invalid'), '"invalid" is NOT a pass (it matched /valid/)')
assert(!isPassingValidation('validation_failed'), '"validation_failed" is NOT a pass (it matched /valid/)')
assert(!isPassingValidation('unvalidated') && !isPassingValidation('pending') && !isPassingValidation(''), 'unvalidated / pending / empty are not passes')

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const job = (over: Record<string, unknown>) => ({
  isSandbox: false, status: 'completed', executionBacked: true, validationCount: 1,
  validationStatus: 'passed', validationEvidenceStatus: 'passed', jobType: 'key_rotation', logs: [], ...over,
}) as any
const claimRow = { event_type: 'agent-job-claimed', metric_type: 'key_rotation', message: 'QGuard agent claimed ML-KEM-768 key envelope migration' }

const claimOnly = buildLiveTelemetry([job({ status: 'running', validationStatus: 'pending' })], [claimRow, claimRow])
assert(claimOnly.keyRotations === 0, 'CLAIMING an ML-KEM job is not a key rotation (it matched /kem/)', `${claimOnly.keyRotations}`)
assert(claimOnly.certificateReplacements === 0 && claimOnly.tlsHandshakeEvents === 0, 'nor a certificate replacement or TLS upgrade')

const done = buildLiveTelemetry([job({})], [claimRow, claimRow, claimRow])
assert(done.keyRotations === 1, 'a completed + validated key rotation counts ONCE, however many rows mention it', `${done.keyRotations}`)

const failedValidation = buildLiveTelemetry([job({ validationStatus: 'validation_failed', validationEvidenceStatus: 'validation_failed' })], [])
assert(failedValidation.keyRotations === 0, 'a completion whose validation FAILED is not counted')
const unverified = buildLiveTelemetry([job({ validationCount: 0, validationEvidenceStatus: undefined })], [])
assert(unverified.keyRotations === 0 && unverified.pqcValidationEvents === 0, 'completion metadata alone cannot count as recorded validation')

const sim = buildLiveTelemetry([job({ isSandbox: true })], [])
assert(sim.keyRotations === 0, 'a sandbox simulation is never counted as a real operation')

const cert = buildLiveTelemetry([job({ jobType: 'cert_transition' })], [])
assert(cert.certificateReplacements === 1 && cert.keyRotations === 0, 'the planner\'s cert_transition is a certificate replacement, and only that')

const liveSrc = readFileSync('src/app/dashboard/live_migration_ops/LiveMigrationOps.tsx', 'utf8')
assert(!/: 100\}%`, hint: 'Completed vs failed'/.test(liveSrc), 'success rate no longer reads 100% with no outcomes')
assert(!/s\.verified \|\| s\.completed/.test(liveSrc), '"Assets Protected — Validated" no longer falls back to unvalidated completions')
assert(!/Math\.max\(0, s\.completed - s\.failed\)/.test(liveSrc), '"Critical Systems Protected" is no longer completed − failed')

/* ------------------------------------------------------------------ */
console.log(`\n${failures === 0 ? 'PASS' : `FAIL (${failures})`} — rollback & agent-role checks\n`)
process.exit(failures === 0 ? 0 : 1)
