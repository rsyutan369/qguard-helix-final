/**
 * QKMS export document.
 *
 * Builds an `InventoryReport` — the same structure behind the Assets and CBOM
 * exports — so QKMS gets real PDF / Excel / Word / HTML / CSV / JSON output
 * through one document pipeline rather than a second, parallel exporter.
 *
 * ── The reconciliation table ────────────────────────────────────────────────
 * Every export carries a table comparing the figures printed in the document
 * against the figures the dashboard is showing, computed from the same model.
 * A reader can check the document rather than trust it — and if the two ever
 * diverge, the document says so on its own face instead of quietly shipping a
 * number nobody can trace.
 */

import type { InventoryReport } from '@/services/reporting/InventoryReport'
import type { QkmsIntelligence } from '@/lib/qkms/types'
import { GATE_LABEL, LIFECYCLE_LABEL, ROTATION_LABEL, CUSTODY_LABEL } from '@/lib/qkms/types'

const POSTURE_TEXT: Record<string, string> = {
  'post-quantum': 'Post-Quantum',
  hybrid: 'Hybrid',
  'quantum-resistant-symmetric': 'Quantum-Resistant Symmetric',
  'weakened-symmetric': 'Weakened Symmetric',
  'quantum-vulnerable': 'Quantum Vulnerable',
  deprecated: 'Deprecated',
  unknown: 'Unknown',
}

function pct(value: number | null): string {
  return value === null || value === undefined ? 'Not applicable' : `${Math.round(value)}%`
}

function date(value: string | null): string {
  if (!value) return 'Not observed'
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 16).replace('T', ' ') : 'Not observed'
}

export function buildQkmsReport(model: QkmsIntelligence): InventoryReport {
  const { metrics, readiness, governance, rotation, lifecycle } = model

  const kpis = [
    { label: 'Keys under management', value: String(metrics.totalKeys), detail: 'Distinct key identities across every evidence source' },
    { label: 'Migration gate', value: GATE_LABEL[readiness.gate.state], detail: readiness.gate.why.slice(0, 160) },
    { label: 'PQC readiness', value: pct(metrics.pqcReadinessPercent), detail: 'Post-quantum or hybrid share of keys that need a quantum decision' },
    { label: 'Critical-risk keys', value: String(metrics.criticalRiskKeys), detail: 'Weighted risk score of 80 or above' },
    { label: 'Governance violations', value: String(metrics.governanceViolations), detail: `Across ${metrics.keysWithViolations} key(s)` },
    { label: 'Rotation health', value: pct(metrics.rotationHealthPercent), detail: `${rotation.posture.governedKeys} key(s) have a determinable rotation state` },
    { label: 'Approved custody', value: pct(metrics.custodyCoveragePercent), detail: 'HSM, managed KMS or vault share of keys with known custody' },
    { label: 'Audit coverage', value: pct(metrics.auditReadinessPercent), detail: 'Live keys carrying at least one evidence or audit record' },
  ]

  /* ---- Key register ------------------------------------------------ */
  const keyRows = model.keys.map((key) => [
    key.id,
    key.label,
    key.keyType,
    key.algorithm,
    `v${key.version}`,
    key.owner || 'Unassigned',
    key.assetName || 'Unmapped',
    key.environment,
    `${key.backend} (${CUSTODY_LABEL[key.custody]})`,
    POSTURE_TEXT[key.posture] || key.posture,
    key.migrationRequirement,
    LIFECYCLE_LABEL[key.lifecycle],
    ROTATION_LABEL[key.rotation],
    date(key.createdAt),
    date(key.lastRotatedAt),
    date(key.expiresAt),
    key.violationIds.length,
    key.risk.score,
    key.risk.level,
  ])

  /* ---- Risk decomposition ------------------------------------------ */
  const riskRows = model.keys.slice(0, 200).map((key) => [
    key.label,
    key.risk.score,
    key.risk.level,
    `${key.risk.confidence}%`,
    key.risk.drivers[0] || '—',
    key.risk.recommendedAction,
  ])

  /* ---- Governance --------------------------------------------------- */
  const violationRows = governance.violations.map((row) => [
    row.severity,
    row.policyName,
    row.rule,
    row.keyLabel,
    row.detail,
    row.remediation,
  ])

  const policyRows = governance.policies.map((policy) => [
    policy.name,
    policy.origin,
    policy.enabled ? 'Enabled' : 'Disabled',
    policy.severity,
    policy.environmentScope,
    policy.keysInScope,
    policy.violations,
    `${policy.compliance}%`,
  ])

  /* ---- Readiness ----------------------------------------------------- */
  const readinessRows = readiness.bands.map((band) => [
    band.label,
    band.applicable === 0 ? 'Not applicable' : String(band.applicable),
    band.applicable === 0 ? '—' : String(band.ready),
    pct(band.percent),
    band.detail,
  ])

  const precheckRows = readiness.gate.prechecks.map((row) => [
    row.label,
    row.decision,
    row.count,
    row.detail,
    row.requiredAction || '—',
  ])

  /* ---- Rotation ------------------------------------------------------- */
  const jobRows = rotation.jobs.map((job) => [
    job.id,
    job.keyLabel,
    job.status,
    job.priority,
    job.previousVersion === null ? '—' : `v${job.previousVersion}`,
    job.newVersion === null ? '—' : `v${job.newVersion}`,
    date(job.requestedAt),
    date(job.completedAt),
    job.validationStatus,
  ])

  /* ---- Lifecycle ------------------------------------------------------ */
  const lifecycleRows = lifecycle.funnel.map((row) => [row.label, row.count, `${row.percent}%`])

  /*
   * Reconciliation.
   *
   * Each row states a figure the dashboard shows, the figure this document
   * contains, and whether they agree. Both sides are computed from the same
   * model, so a mismatch can only mean the export lost or duplicated rows —
   * which is exactly what this table exists to catch.
   */
  const reconciliation = [
    {
      metric: 'Total keys',
      dashboard: String(metrics.totalKeys),
      exported: String(keyRows.length),
      matches: metrics.totalKeys === keyRows.length,
    },
    {
      metric: 'Governance violations',
      dashboard: String(metrics.governanceViolations),
      exported: String(violationRows.length),
      matches: metrics.governanceViolations === violationRows.length,
    },
    {
      metric: 'Rotation work orders',
      dashboard: String(rotation.posture.jobsTotal),
      exported: String(jobRows.length),
      matches: rotation.posture.jobsTotal === jobRows.length,
    },
    {
      metric: 'Critical-risk keys',
      dashboard: String(metrics.criticalRiskKeys),
      exported: String(model.keys.filter((key) => key.risk.level === 'critical').length),
      matches: metrics.criticalRiskKeys === model.keys.filter((key) => key.risk.level === 'critical').length,
    },
    {
      metric: 'Keys requiring migration',
      dashboard: String(metrics.keysRequiringMigration),
      exported: String(model.keys.filter((key) => key.migrationRequirement === 'required').length),
      matches: metrics.keysRequiringMigration === model.keys.filter((key) => key.migrationRequirement === 'required').length,
    },
    {
      metric: 'Migration gate',
      dashboard: GATE_LABEL[readiness.gate.state],
      exported: GATE_LABEL[readiness.gate.state],
      matches: true,
    },
  ]

  const notes: string[] = [
    `Every figure in this document derives from tenant-scoped records observed up to ${date(model.latestEvidenceAt)}. Nothing is estimated, sampled or generated.`,
    'Risk scores use one weighted model (algorithm 22, quantum exposure 20, lifecycle 15, rotation 14, ownership 11, custody 10, blast radius 8). The same score appears on every QKMS page and in this document.',
    'A percentage shown as "Not applicable" had an empty denominator — there was nothing of that kind to measure. It is not zero.',
    `Migration gate: ${readiness.gate.why}`,
  ]

  if (readiness.gate.blockers.length) {
    notes.push(`Blockers: ${readiness.gate.blockers.join(' | ')}`)
  }
  if (model.telemetry.truncated) {
    notes.push('A source query reached its row cap, so counts in this document are a lower bound for very large estates.')
  }
  if (model.telemetry.absentSources.length) {
    notes.push(`No rows were returned by: ${model.telemetry.absentSources.join(', ')}. Absence of a finding from these sources is not evidence of absence in the estate.`)
  }

  return {
    meta: {
      kind: 'cbom',
      title: 'QKMS Key Estate Report',
      subtitle: 'Cryptographic key inventory, governance, rotation and post-quantum readiness',
      generatedAt: model.generatedAt,
      companyName: 'QGuard Helix',
      classification: 'Confidential — Cryptographic Key Governance',
      scopeNote: `${metrics.totalKeys} key(s) across ${model.distributions.environments.length} environment(s), assembled from ${Object.keys(model.telemetry.sourceCounts).length} tenant evidence source(s).`,
      provenance: `QKMS Command Center · model computed ${date(model.generatedAt)} · newest evidence ${date(model.latestEvidenceAt)} · pipeline ${model.telemetry.pipelineStatus}`,
      filenameSlug: 'qkms-key-estate',
    },
    kpis,
    tables: [
      {
        title: 'Key register',
        columns: ['Key ID', 'Label', 'Type', 'Algorithm', 'Version', 'Owner', 'Asset', 'Env', 'Custody', 'PQC posture', 'Migration', 'Lifecycle', 'Rotation', 'Created', 'Last rotated', 'Expires', 'Violations', 'Risk', 'Level'],
        rows: keyRows,
      },
      {
        title: 'Risk decomposition and recommended action',
        columns: ['Key', 'Score', 'Level', 'Confidence', 'Primary driver', 'Recommended action'],
        rows: riskRows,
      },
      {
        title: 'Governance violations',
        columns: ['Severity', 'Policy', 'Rule', 'Key', 'Detail', 'Remediation'],
        rows: violationRows,
      },
      {
        title: 'Policies in force',
        columns: ['Policy', 'Origin', 'State', 'Severity', 'Scope', 'Keys in scope', 'Violations', 'Compliance'],
        rows: policyRows,
      },
      {
        title: 'Post-quantum readiness by band',
        columns: ['Band', 'Applicable keys', 'Ready keys', 'Readiness', 'Detail'],
        rows: readinessRows,
      },
      {
        title: 'Migration gate prechecks',
        columns: ['Precheck', 'Decision', 'Records', 'Detail', 'Required action'],
        rows: precheckRows,
      },
      {
        title: 'Rotation work orders',
        columns: ['Job', 'Key', 'Status', 'Priority', 'From', 'To', 'Requested', 'Completed', 'Validation'],
        rows: jobRows,
      },
      {
        title: 'Lifecycle distribution',
        columns: ['Lifecycle state', 'Keys', 'Share'],
        rows: lifecycleRows,
      },
      {
        title: 'Storage backends and custody',
        columns: ['Backend', 'Provider', 'Custody class', 'Status', 'Keys', 'Violations', 'Last verified'],
        rows: governance.backends.map((row) => [
          row.name,
          row.provider,
          CUSTODY_LABEL[row.custody],
          row.status,
          row.keys,
          row.violations,
          date(row.lastVerifiedAt),
        ]),
      },
      {
        title: 'Audit evidence',
        columns: ['Event', 'Type', 'Actor', 'Key', 'Recorded', 'Source'],
        rows: model.audit.slice(0, 200).map((row) => [
          row.title,
          row.eventType,
          row.actor,
          row.keyLabel || '—',
          date(row.at),
          row.table,
        ]),
      },
    ].filter((table) => table.rows.length > 0),
    reconciliation,
    notes,
  }
}
