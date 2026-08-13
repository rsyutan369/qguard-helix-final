/**
 * Live Migration report builder — offline invariant check.
 *
 * The report is a compliance artefact. Its job is to state what happened
 * WITHOUT overstating it, so these assertions guard the one distinction that
 * matters:
 *
 *   PLAN STATE      the workflow reached a step ("completed")
 *   EXECUTION       a collector agent or cloud connector actually changed the
 *                   asset
 *
 * A document that prints "12 completed" on a tenant with zero collectors is the
 * same defect the snapshot restore path carried: an audit record asserting a
 * change that never happened.
 *
 *   1. Plan state and execution evidence are ALWAYS separate columns.
 *   2. A completed job with no executor is reported as such, and the caveat is
 *      the FIRST note, not an appendix line.
 *   3. Sandbox / dry-run jobs never count as execution.
 *   4. Zero collectors ⇒ the report says no job could have been executed.
 *   5. The reconciliation table compares dashboard vs exported honestly and
 *      marks a mismatch rather than hiding it.
 *   6. A filtered export declares its own scope.
 *   7. Every format renders and carries the same document.
 *
 * Run: npx tsx tools/migration-report-check.ts
 */

import {
  buildMigrationReport,
  isExecutionBacked,
  isPlanComplete,
  type MigrationReportInput,
} from '../src/services/reporting/MigrationReport'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const NOW = '2026-08-13T12:00:00.000Z'

const summary: MigrationReportInput['summary'] = {
  total: 4, running: 1, completed: 2, failed: 0, queued: 1, paused: 0, cancelled: 0,
  completionRate: 50, waitingForAgent: 1, agentBacked: 1, verified: 1, agentsOnline: 1,
  totalAssets: 4, findings: 12, criticalExposures: 2, highExposures: 4,
  lastScanAt: '2026-08-12T09:00:00.000Z', complianceMode: 'NIST', standardLabel: 'FIPS 203/204',
}

const jobs: MigrationReportInput['jobs'] = [
  // Completed AND executed by an agent — the only honest "applied" case.
  {
    id: 'j1', asset: 'payments.example.com', assetType: 'api', environment: 'production', owner: 'Payments',
    criticality: 'critical', fromAlgo: 'RSA-2048', toAlgo: 'ML-DSA-65', migrationType: 'signature',
    status: 'completed', progress: 100, executionStatus: 'applied', executionBacked: true,
    agentId: 'ag-1', agentName: 'collector-01', agentStatus: 'active', currentStep: 'done',
    telemetryCount: 40, validationCount: 3, validationStatus: 'passed', logCount: 2,
    startedAt: '2026-08-13T10:00:00.000Z', completedAt: '2026-08-13T10:30:00.000Z', updatedAt: '2026-08-13T10:30:00.000Z',
    logs: [{ at: '2026-08-13T10:30:00.000Z', level: 'info', message: 'Cutover complete', source: 'agent' }],
  },
  // Completed in PLAN state only — no executor. Must be flagged.
  {
    id: 'j2', asset: 'legacy.example.com', assetType: 'server', environment: 'production', owner: 'Infra',
    criticality: 'high', fromAlgo: 'RSA-2048', toAlgo: 'ML-KEM-768', migrationType: 'transport',
    status: 'completed', progress: 100, executionStatus: 'plan-only', executionBacked: false,
    agentId: null, agentName: null, agentStatus: '', currentStep: 'done',
    telemetryCount: 0, validationCount: 0, validationStatus: 'not-validated', logCount: 0,
    startedAt: '2026-08-13T09:00:00.000Z', completedAt: '2026-08-13T09:20:00.000Z', updatedAt: '2026-08-13T09:20:00.000Z',
  },
  // Sandbox run at 100% — never execution evidence.
  {
    id: 'j3', asset: 'sandbox.example.com', assetType: 'api', environment: 'staging', owner: 'Platform',
    criticality: 'medium', fromAlgo: 'X25519', toAlgo: 'X25519MLKEM768', migrationType: 'transport',
    status: 'completed', progress: 100, executionStatus: 'simulated', executionBacked: true,
    isSandbox: true, runMode: 'sandbox', agentName: 'twin', agentStatus: 'sim',
    telemetryCount: 5, validationCount: 1, validationStatus: 'simulated', logCount: 0,
    updatedAt: '2026-08-13T08:00:00.000Z',
  },
  {
    id: 'j4', asset: 'batch.example.com', assetType: 'service', environment: 'staging', owner: 'Data',
    criticality: 'low', fromAlgo: 'SHA-1', toAlgo: 'SHA3-256', migrationType: 'hash',
    status: 'running', progress: 45, executionStatus: 'awaiting-agent', executionBacked: false,
    agentName: null, agentStatus: '', currentStep: 'waiting', telemetryCount: 0, validationCount: 0,
    validationStatus: 'pending', logCount: 0, updatedAt: '2026-08-13T11:00:00.000Z',
  },
]

const input: MigrationReportInput = {
  generatedAt: NOW,
  planId: 'PLAN-2026-004',
  summary,
  jobs,
  totalJobsBeforeFilter: 4,
  timeline: [{ label: '10:00', running: 1, completed: 1, failed: 0 }],
  telemetry: {
    tlsHandshakeEvents: 120, certificateReplacements: 1, keyRotations: 2, pqcValidationEvents: 3,
    compatibilityChecks: 4, systemHealth: 'healthy',
    activityFeed: { migrationLogs: 6, validationLogs: 3, errorLogs: 0, auditLogs: 4, complianceLogs: 1 },
  },
  snapshots: { total: 2, restorable: 2, restored: 0, expired: 0, integrityVerified: 2, autoRollbackEnabled: true, schemaReady: true },
}

const report = buildMigrationReport(input)

/* ------------------------------------------------------------------ */
console.log('\n1. Plan state and execution evidence are never conflated')
{
  const jobTable = report.tables.find((t) => /Plan State vs Execution/i.test(t.title))!
  assert(Boolean(jobTable), 'the jobs table separates the two in its title', jobTable?.title)
  assert(jobTable.columns.includes('Plan Status'), 'plan status has its own column')
  assert(jobTable.columns.includes('Executed On Asset'), 'execution has its own column')

  const legacyRow = jobTable.rows.find((r) => String(r[0]) === 'legacy.example.com')!
  assert(String(legacyRow[5]) === 'completed', 'plan status still reads completed', String(legacyRow[5]))
  assert(/No — plan state only/.test(String(legacyRow[7])), 'but execution says plan state only', String(legacyRow[7]))

  const payRow = jobTable.rows.find((r) => String(r[0]) === 'payments.example.com')!
  assert(String(payRow[7]) === 'Yes', 'an agent-backed job reports Yes', String(payRow[7]))
  assert(String(payRow[8]) === 'collector-01', 'and names the executor', String(payRow[8]))
}

console.log('\n2. The execution caveat leads, it does not hide')
{
  assert(/^EXECUTION CAVEAT/.test(report.notes[0]), 'the caveat is the FIRST note', report.notes[0].slice(0, 42))
  assert(/legacy\.example\.com/.test(report.notes[0]), 'and names the affected asset')
  assert(/not evidence that the asset/i.test(report.notes[0]), 'stating plainly what completed does not mean')

  const kpi = report.kpis.find((k) => k.label === 'Executed on Asset')!
  assert(kpi.value === '1', 'the KPI counts only executor-backed completions', kpi.value)
  const planKpi = report.kpis.find((k) => k.label === 'Completed (plan state)')!
  assert(planKpi.value === '2', 'while plan-state completion is reported separately', planKpi.value)
  assert(planKpi.value !== kpi.value, 'the two are visibly different numbers')
}

console.log('\n3. Sandbox runs are never execution evidence')
{
  const sandbox = jobs.find((j) => j.id === 'j3')!
  assert(sandbox.executionBacked === true, 'the fixture sandbox job claims executionBacked')
  assert(!isExecutionBacked(sandbox), 'but the builder rejects it as sandbox', String(isExecutionBacked(sandbox)))
  assert(isPlanComplete(sandbox), 'even though its plan state is complete')
  assert(/sandbox \/ dry-run mode/i.test(report.notes.join(' ')), 'and the report says so')
}

console.log('\n4. Zero collectors is stated outright')
{
  const blind = buildMigrationReport({
    ...input,
    summary: { ...summary, agentsOnline: 0, agentBacked: 0 },
    jobs: jobs.map((j) => ({ ...j, executionBacked: false })),
  })
  assert(
    blind.notes.some((n) => /No collector agent is reporting/i.test(n)),
    'the report states that no executor exists',
  )
  assert(
    blind.notes.some((n) => /no job in this report could have been executed/i.test(n)),
    'and that therefore nothing could have been applied',
  )
  const kpi = blind.kpis.find((k) => k.label === 'Executed on Asset')!
  assert(kpi.value === '0', 'the executed KPI is zero', kpi.value)
  const online = blind.kpis.find((k) => k.label === 'Collectors Online')!
  assert(/no executor available/i.test(online.detail ?? ''), 'and the collector KPI explains the consequence')
}

console.log('\n5. Reconciliation is honest about mismatches')
{
  assert(report.reconciliation.length >= 5, 'a reconciliation block is present', String(report.reconciliation.length))
  const jobsRow = report.reconciliation.find((r) => r.metric === 'Migration jobs')!
  assert(jobsRow.matches, 'job totals reconcile on this fixture', `${jobsRow.dashboard} vs ${jobsRow.exported}`)

  // Force a divergence: the dashboard claims more completions than the rows show.
  const skewed = buildMigrationReport({ ...input, summary: { ...summary, completed: 99 } })
  const row = skewed.reconciliation.find((r) => r.metric === 'Completed (plan state)')!
  assert(!row.matches, 'a mismatch is flagged, not hidden', `${row.dashboard} vs ${row.exported}`)
}

console.log('\n6. A filtered export declares its own scope')
{
  const filtered = buildMigrationReport({
    ...input,
    jobs: jobs.slice(0, 2),
    totalJobsBeforeFilter: 4,
    filtered: true,
    filterDescription: 'status = completed',
  })
  assert(/2 of 4/.test(filtered.meta.scopeNote), 'the scope note states the subset', filtered.meta.scopeNote)
  assert(filtered.notes.some((n) => /FILTERED view/i.test(n)), 'and a note repeats it')
  assert(filtered.notes.some((n) => /status = completed/.test(n)), 'naming the filter applied')
}

console.log('\n7. Document shape and provenance')
{
  assert(report.meta.kind === 'migration', 'kind is migration', report.meta.kind)
  assert(report.meta.filenameSlug === 'live-migration-report', 'filename slug is set', String(report.meta.filenameSlug))
  assert(Boolean(report.meta.provenance), 'provenance is printed in the document')
  assert(/migration_jobs/.test(report.meta.provenance), 'naming the real source tables')
  assert(report.tables.length >= 5, 'all sections are present', String(report.tables.length))
  assert(
    report.tables.every((t) => t.rows.every((r) => r.length === t.columns.length)),
    'every row matches its column count (exporters assume it)',
  )
  assert(
    report.tables.some((t) => /Executor Activity/i.test(t.title)),
    'collector / connector activity has its own table',
  )
  assert(
    report.tables.some((t) => /Rollback Readiness/i.test(t.title)),
    'rollback readiness is reported',
  )
  const rollback = report.tables.find((t) => /Rollback Readiness/i.test(t.title))!
  const executorRow = rollback.rows.find((r) => /Executor available/i.test(String(r[0])))!
  assert(Boolean(executorRow), 'including whether a rollback could actually be applied', String(executorRow?.[1]))
}

console.log(`\n${failures === 0 ? '✓ All migration report invariants hold.' : `✗ ${failures} invariant(s) FAILED.`}`)
process.exit(failures === 0 ? 0 : 1)
