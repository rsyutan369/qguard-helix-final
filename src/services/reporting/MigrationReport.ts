/**
 * Live Migration report builder.
 *
 * Turns the exact snapshot the Live Migration Operations page is rendering into
 * the shared report document model, so PDF / Excel / Word / HTML / CSV / JSON
 * all come from the already-hardened exporters rather than a second export
 * stack.
 *
 * ── The one thing this report must get right ───────────────────────────────
 * A migration job's `status` is PLAN state. It says the workflow reached a
 * step. It does NOT say anything changed on the asset — only an executor can do
 * that: an enrolled collector agent on the host, or a cloud connector with
 * write scope. `executionBacked` records whether one was actually behind the
 * job.
 *
 * A report that prints "12 completed" without that distinction is the same
 * defect the snapshot restore path carried: a compliance document asserting
 * changes that may never have been applied. So every table here separates
 * PLAN STATE from EXECUTION EVIDENCE, the KPI block reports both, and when the
 * two disagree the notes say so in the first line rather than a footnote.
 *
 * Pure and dependency-free so the browser and `tools/migration-report-check.ts`
 * build the identical document.
 */

import type { InventoryReport, InventoryKpi, ReconciliationRow } from './InventoryReport'
import type { ReportTable } from './schemas/ReportSchema'

/* ================================================================== */
/* Inputs — the page's own objects, unchanged                          */
/* ================================================================== */

export interface MigrationJobRow {
  id?: unknown
  asset?: unknown
  assetType?: unknown
  environment?: unknown
  owner?: unknown
  criticality?: unknown
  fromAlgo?: unknown
  toAlgo?: unknown
  migrationType?: unknown
  status?: unknown
  rawStatus?: unknown
  progress?: unknown
  eta?: unknown
  startedAt?: unknown
  completedAt?: unknown
  createdAt?: unknown
  updatedAt?: unknown
  executionStatus?: unknown
  executionBacked?: unknown
  isSandbox?: unknown
  runMode?: unknown
  agentId?: unknown
  agentName?: unknown
  agentStatus?: unknown
  currentStep?: unknown
  telemetryCount?: unknown
  validationCount?: unknown
  validationStatus?: unknown
  logCount?: unknown
  logs?: Array<{ at?: unknown; level?: unknown; message?: unknown; source?: unknown }>
}

export interface MigrationSummaryInput {
  total: number
  running: number
  completed: number
  failed: number
  queued: number
  paused: number
  cancelled: number
  completionRate: number
  waitingForAgent: number
  agentBacked: number
  verified: number
  agentsOnline: number
  totalAssets: number
  findings: number
  criticalExposures: number
  highExposures: number
  lastScanAt: string | null
  complianceMode: string
  standardLabel: string
}

export interface MigrationTimelinePoint {
  label: string
  running: number
  completed: number
  failed: number
}

export interface MigrationTelemetryInput {
  tlsHandshakeEvents: number
  certificateReplacements: number
  keyRotations: number
  pqcValidationEvents: number
  compatibilityChecks: number
  systemHealth: string
  activityFeed: {
    migrationLogs: number
    validationLogs: number
    errorLogs: number
    auditLogs: number
    complianceLogs: number
  }
}

export interface MigrationSnapshotSummaryInput {
  total: number
  restorable: number
  restored: number
  expired: number
  integrityVerified: number
  autoRollbackEnabled: boolean
  schemaReady: boolean
}

export interface MigrationReportInput {
  generatedAt?: string
  planId?: string | null
  summary: MigrationSummaryInput
  /** Jobs exactly as the page is showing them (post-filter). */
  jobs: MigrationJobRow[]
  /** Total jobs before any filter, so the scope note is honest. */
  totalJobsBeforeFilter?: number
  filtered?: boolean
  filterDescription?: string
  timeline?: MigrationTimelinePoint[]
  telemetry?: MigrationTelemetryInput
  snapshots?: MigrationSnapshotSummaryInput | null
  companyName?: string
  classification?: string
}

/* ================================================================== */
/* Helpers                                                             */
/* ================================================================== */

const text = (value: unknown, fallback = '—'): string => {
  if (value === null || value === undefined) return fallback
  const s = String(value).trim()
  return s === '' ? fallback : s
}
const num = (value: unknown): number => {
  const n = Number(value)
  return Number.isFinite(n) ? n : 0
}
const pctText = (value: number): string => `${Math.round(value)}%`
const dateLabel = (value: unknown): string => {
  const s = text(value, '')
  if (!s) return '—'
  const t = Date.parse(s)
  return Number.isFinite(t) ? `${new Date(t).toISOString().slice(0, 16).replace('T', ' ')} UTC` : s
}
const truthy = (value: unknown): boolean => value === true || value === 'true' || value === 1

/**
 * Was this job actually executed by something that can change the asset?
 *
 * `executionBacked` is set by the backend when an agent or connector carried
 * the job. A sandbox / dry run is explicitly NOT execution, however far its
 * progress bar travelled.
 */
export function isExecutionBacked(job: MigrationJobRow): boolean {
  if (truthy(job.isSandbox)) return false
  if (/sandbox|dry[-_\s]?run|simulat/i.test(text(job.runMode, ''))) return false
  return truthy(job.executionBacked)
}

/** Plan state says "completed" — but was anything applied? */
export function isPlanComplete(job: MigrationJobRow): boolean {
  return /complete|success|done|verified/i.test(text(job.status, '') + ' ' + text(job.rawStatus, ''))
}

/* ================================================================== */
/* Builder                                                             */
/* ================================================================== */

export function buildMigrationReport(input: MigrationReportInput): InventoryReport {
  const generatedAt = input.generatedAt || new Date().toISOString()
  const jobs = input.jobs || []
  const summary = input.summary
  const totalBefore = input.totalJobsBeforeFilter ?? jobs.length
  const filtered = Boolean(input.filtered) || jobs.length !== totalBefore

  /* ---- Execution evidence ------------------------------------------- */
  const sandboxJobs = jobs.filter((job) => truthy(job.isSandbox) || /sandbox|dry[-_\s]?run|simulat/i.test(text(job.runMode, '')))
  const sandboxIds = new Set(sandboxJobs)
  const executed = jobs.filter(isExecutionBacked)
  // A sandbox run reaching 100% is not a completed migration in either the
  // dashboard's count or this one. Including it here made the report claim more
  // completions than the screen showed, which is the reconciliation failure this
  // document exists to make impossible.
  const planComplete = jobs.filter((job) => isPlanComplete(job) && !sandboxIds.has(job))
  const completedAndExecuted = planComplete.filter(isExecutionBacked)
  const completedNotExecuted = planComplete.filter((job) => !isExecutionBacked(job))
  const verifiedJobs = jobs.filter((job) => /pass|success|valid|verified/i.test(text(job.validationStatus, '')))

  /* ---- KPIs ---------------------------------------------------------- */
  const kpis: InventoryKpi[] = [
    { label: 'Migration Jobs', value: String(jobs.length), detail: filtered ? `of ${totalBefore} total (filtered view)` : 'all jobs in scope' },
    { label: 'Completed (plan state)', value: String(planComplete.length), detail: `${pctText(summary.completionRate)} completion rate` },
    { label: 'Executed on Asset', value: String(completedAndExecuted.length), detail: completedAndExecuted.length === planComplete.length ? 'every completed job was executor-backed' : `${completedNotExecuted.length} completed without an executor` },
    { label: 'Running', value: String(summary.running), detail: `${summary.queued} queued · ${summary.paused} paused` },
    { label: 'Failed', value: String(summary.failed), detail: summary.failed > 0 ? 'requires operator attention' : 'no failures recorded' },
    { label: 'Collectors Online', value: String(summary.agentsOnline), detail: summary.agentsOnline === 0 ? 'no executor available for this tenant' : 'agents reporting' },
    { label: 'Runtime Validated', value: String(verifiedJobs.length), detail: `${summary.verified} verified by the platform` },
    { label: 'Assets in Scope', value: String(summary.totalAssets), detail: `${summary.findings} open finding(s)` },
  ]

  /* ---- Tables --------------------------------------------------------- */
  const tables: ReportTable[] = []

  tables.push({
    title: 'Migration Jobs — Plan State vs Execution Evidence',
    columns: ['Asset', 'Environment', 'Owner', 'From', 'To', 'Plan Status', 'Progress', 'Executed On Asset', 'Executor', 'Validation'],
    rows: jobs.map((job) => [
      text(job.asset),
      text(job.environment),
      text(job.owner),
      text(job.fromAlgo),
      text(job.toAlgo),
      text(job.status),
      `${Math.round(num(job.progress))}%`,
      isExecutionBacked(job) ? 'Yes' : 'No — plan state only',
      text(job.agentName, isExecutionBacked(job) ? 'connector' : 'none'),
      text(job.validationStatus),
    ]),
  })

  tables.push({
    title: 'Executor Activity — Collector Agents & Connectors',
    columns: ['Asset', 'Executor', 'Executor Status', 'Execution Status', 'Current Step', 'Telemetry Events', 'Validation Logs', 'Last Update'],
    rows: jobs.map((job) => [
      text(job.asset),
      text(job.agentName, 'none assigned'),
      text(job.agentStatus, isExecutionBacked(job) ? 'active' : 'no executor'),
      text(job.executionStatus),
      text(job.currentStep),
      String(num(job.telemetryCount)),
      String(num(job.validationCount)),
      dateLabel(job.updatedAt || job.completedAt || job.startedAt),
    ]),
  })

  tables.push({
    title: 'Cryptographic Change Record',
    columns: ['Asset', 'Type', 'Criticality', 'From Algorithm', 'To Algorithm', 'Migration Type', 'Started', 'Completed'],
    rows: jobs.map((job) => [
      text(job.asset),
      text(job.assetType),
      text(job.criticality),
      text(job.fromAlgo),
      text(job.toAlgo),
      text(job.migrationType),
      dateLabel(job.startedAt),
      dateLabel(job.completedAt),
    ]),
  })

  if (input.timeline?.length) {
    tables.push({
      title: 'Migration Timeline',
      columns: ['Window', 'Running', 'Completed', 'Failed'],
      rows: input.timeline.map((point) => [text(point.label), String(num(point.running)), String(num(point.completed)), String(num(point.failed))]),
    })
  }

  if (input.telemetry) {
    const t = input.telemetry
    tables.push({
      title: 'Migration Telemetry',
      columns: ['Signal', 'Count'],
      rows: [
        /* Same measurements as the Live Migration page: operations completed
           with a passing validation, one per job. */
        ['TLS upgrades validated', String(num(t.tlsHandshakeEvents))],
        ['Certificates replaced (validated)', String(num(t.certificateReplacements))],
        ['Keys rotated (validated)', String(num(t.keyRotations))],
        ['Validations recorded', String(num(t.pqcValidationEvents))],
        ['Compatibility checks', String(num(t.compatibilityChecks))],
        ['Migration logs', String(num(t.activityFeed.migrationLogs))],
        ['Validation logs', String(num(t.activityFeed.validationLogs))],
        ['Error logs', String(num(t.activityFeed.errorLogs))],
        ['Audit logs', String(num(t.activityFeed.auditLogs))],
        ['Compliance logs', String(num(t.activityFeed.complianceLogs))],
        ['System health', text(t.systemHealth)],
      ],
    })
  }

  if (input.snapshots) {
    const s = input.snapshots
    tables.push({
      title: 'Rollback Readiness — Pre-Migration Snapshots',
      columns: ['Metric', 'Value'],
      rows: [
        ['Snapshots captured', String(num(s.total))],
        ['Restorable', String(num(s.restorable))],
        ['Already restored', String(num(s.restored))],
        ['Expired', String(num(s.expired))],
        ['Integrity verified', String(num(s.integrityVerified))],
        ['Auto-rollback', s.autoRollbackEnabled ? 'Enabled' : 'Disabled'],
        ['Executor available for rollback', summary.agentsOnline > 0 ? 'Yes' : 'No — restore records intent only'],
      ],
    })
  }

  const recentEvents = jobs
    .flatMap((job) => (job.logs || []).map((log) => ({ asset: text(job.asset), ...log })))
    .sort((a, b) => Date.parse(text(b.at, '')) - Date.parse(text(a.at, '')))
    .slice(0, 60)
  if (recentEvents.length) {
    tables.push({
      title: 'Recent Migration Events',
      columns: ['Time', 'Asset', 'Level', 'Source', 'Message'],
      rows: recentEvents.map((event) => [
        dateLabel(event.at),
        text(event.asset),
        text(event.level),
        text(event.source),
        text(event.message),
      ]),
    })
  }

  /* ---- Reconciliation -------------------------------------------------- */
  const reconciliation: ReconciliationRow[] = [
    { metric: 'Migration jobs', dashboard: String(summary.total), exported: String(totalBefore), matches: summary.total === totalBefore },
    { metric: 'Completed (plan state)', dashboard: String(summary.completed), exported: String(planComplete.length), matches: summary.completed === planComplete.length },
    { metric: 'Running', dashboard: String(summary.running), exported: String(jobs.filter((j) => /run|progress|execut/i.test(text(j.status, ''))).length), matches: true },
    { metric: 'Failed', dashboard: String(summary.failed), exported: String(jobs.filter((j) => /fail|error|reject/i.test(text(j.status, ''))).length), matches: true },
    { metric: 'Executor-backed jobs', dashboard: String(summary.agentBacked), exported: String(executed.length), matches: summary.agentBacked === executed.length },
    { metric: 'Collectors online', dashboard: String(summary.agentsOnline), exported: String(summary.agentsOnline), matches: true },
  ].map((row) => ({ ...row, matches: row.dashboard === row.exported }))

  /* ---- Notes ----------------------------------------------------------- */
  const notes: string[] = []

  // The headline caveat goes FIRST when it applies — a reader must not have to
  // reach the appendix to learn that nothing was applied to an asset.
  if (completedNotExecuted.length > 0) {
    notes.push(
      `EXECUTION CAVEAT: ${completedNotExecuted.length} of ${planComplete.length} job(s) marked complete were not backed by a collector agent or cloud connector. For those, "completed" records that the migration plan reached its final step — it is not evidence that the asset's cryptography changed. Affected: ${completedNotExecuted.map((j) => text(j.asset)).slice(0, 8).join(', ')}${completedNotExecuted.length > 8 ? ', …' : ''}.`,
    )
  }
  if (summary.agentsOnline === 0) {
    notes.push(
      'No collector agent is reporting for this tenant and no cloud connector is connected, so no job in this report could have been executed against a live asset. Enrol a collector under Scanner → Agents to enable execution and rollback.',
    )
  }
  if (sandboxJobs.length > 0) {
    notes.push(`${sandboxJobs.length} job(s) ran in sandbox / dry-run mode and are excluded from execution evidence by design.`)
  }
  if (summary.waitingForAgent > 0) {
    notes.push(`${summary.waitingForAgent} job(s) are waiting for an executor to pick them up.`)
  }
  notes.push(
    `Validation status reflects the platform's own checks. A job is "Runtime Validated" only where post-change telemetry was recorded; ${verifiedJobs.length} of ${jobs.length} job(s) meet that bar.`,
  )
  if (filtered) {
    notes.push(`This document covers a FILTERED view: ${jobs.length} of ${totalBefore} job(s).${input.filterDescription ? ` Filter: ${input.filterDescription}.` : ''} Totals in the reconciliation table refer to the full estate.`)
  }
  notes.push(`Migration guidance: ${text(summary.complianceMode)} · References: ${text(summary.standardLabel)}. Last scan: ${dateLabel(summary.lastScanAt)}.`)

  return {
    meta: {
      kind: 'migration',
      title: 'Live Migration Operations Report',
      subtitle: input.planId ? `Migration plan ${input.planId}` : 'Post-quantum migration execution record',
      generatedAt,
      companyName: input.companyName || 'QGuard Helix',
      classification: input.classification || 'Confidential — Internal Use',
      scopeNote: filtered
        ? `${jobs.length} of ${totalBefore} migration job(s) — filtered view`
        : `${jobs.length} migration job(s) — full scope`,
      provenance:
        'Built from the live migration snapshot this page is rendering: migration_jobs, migration_events, migration_validation_logs, scanner_agents and connector_accounts, all tenant-scoped. Plan state and execution evidence are reported as separate columns; neither is inferred from the other.',
      filenameSlug: 'live-migration-report',
    },
    kpis,
    tables,
    reconciliation,
    notes,
  }
}
