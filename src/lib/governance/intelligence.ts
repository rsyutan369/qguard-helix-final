/**
 * Governance intelligence composer — the one model behind four dashboards.
 *
 * Compliance, Quantum Governance, Audit Vault and Regulatory Mapping are
 * projections of the object this module returns. That is the entire reason two
 * of them can never publish different numbers for the same fact: there is only
 * one computation, and each page selects from it.
 *
 * Canonical figures (assets, components, vulnerable components, certificates,
 * keys, readiness, risk) are MIRRORED from the Quantum Readiness snapshot, never
 * recomputed here. `reconciliation` publishes that mapping so the claim is
 * checkable rather than asserted.
 */

import {
  CONTROL_CATALOG,
  CONTROL_BY_ID,
  FRAMEWORK_CATALOG,
  REQUIREMENT_CATALOG,
  resolveFrameworkId,
} from './catalog'
import { buildAuditEvents, type AuditInputs } from './audit'
import { buildEvidence, freshnessOf, type EvidenceInputs } from './evidence'
import { evaluateControls, type CanonicalSnapshot, type ControlEvaluationInputs } from './controls'
import { evaluatePolicies, severityOrder, type PolicyEvaluationContext } from './policy'
import { buildSubjects, clampPercent, daysBetween, ms, newest, num, recordOf, str, type Row } from './subjects'
import {
  CONTROL_DOMAIN_LABEL,
  CONTROL_STATUS_LABEL,
  AUDIT_CATEGORY_LABEL,
  POLICY_CATEGORY_LABEL,
  type AssetComplianceRecord,
  type AuditEvent,
  type ControlDomain,
  type ControlRecord,
  type ControlStatus,
  type EvidenceRecord,
  type FrameworkRecord,
  type GapKind,
  type GovernanceFacets,
  type GovernanceGap,
  type GovernanceIntelligence,
  type GovernancePipelineStatus,
  type GovernanceScore,
  type GovernanceSeverity,
  type GovernanceTelemetry,
  type GovernanceTrendPoint,
  type PolicyRecord,
  type ReconciliationReport,
  type ReconciliationRow,
  type RequirementRecord,
} from './types'

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

/** A per-asset dossier from the shared Migration Planner portfolio. */
export interface PortfolioAsset {
  id: string
  name: string
  type: string
  environment: string
  owner: string
  businessCriticality: string
  internetFacing: boolean
  riskScore: number
  readinessScore: number
  posture: string
  postureLabel: string
  severityCounts: { critical: number; high: number; medium: number; low: number }
  lastEvidenceAt: string | null
}

export interface GovernanceInputs {
  now?: number
  snapshot: CanonicalSnapshot
  portfolioAssets: PortfolioAsset[]

  assets: Row[]
  cryptoInventory: Row[]
  certificates: Row[]
  generatedKeys: Row[]
  runtimeEvents: Row[]
  vaultFiles: Row[]
  scanSessions: Row[]
  scanResults: Row[]
  cryptoExposures: Row[]
  vulnerabilities: Row[]
  scannerAlerts: Row[]
  scannerEvidence: Row[]
  scannerAgents: Row[]
  connectorAccounts: Row[]
  agentHeartbeats: Row[]
  migrationJobs: Row[]
  migrationPlans: Row[]
  migrationEvents: Row[]
  complianceEvidence: Row[]
  auditLogs: Row[]
  vaultAuditLogs: Row[]
  securityEvents: Row[]
  userSecurityEvents: Row[]
  authEvents: Row[]

  /** Null when the store is unavailable (schema not applied). */
  policyOverrides: Row[] | null
  evidenceAnchors: Row[] | null
  controlAssessments: Row[] | null

  /** True when any source query hit its row cap. */
  truncated: boolean
  sourceCounts: Record<string, number>
  absentSources: string[]
}

/* ------------------------------------------------------------------ */
/* Scores                                                              */
/* ------------------------------------------------------------------ */

function toneFor(value: number | null, invert = false): GovernanceScore['tone'] {
  if (value === null) return 'neutral'
  const scaled = invert ? 100 - value : value
  if (scaled >= 85) return 'good'
  if (scaled >= 60) return 'warning'
  return 'critical'
}

function score(input: {
  id: string
  label: string
  value: number | null
  measured: boolean
  unit: GovernanceScore['unit']
  basis: string
  numerator: number
  denominator: number
  route: string | null
  hint: string
  invertTone?: boolean
}): GovernanceScore {
  return {
    id: input.id,
    label: input.label,
    value: input.measured ? input.value : null,
    measured: input.measured,
    unit: input.unit,
    basis: input.basis,
    numerator: input.numerator,
    denominator: input.denominator,
    tone: input.measured ? toneFor(input.value, input.invertTone) : 'neutral',
    route: input.route,
    hint: input.hint,
  }
}

/**
 * Weighted compliance over MEASURED, in-scope controls only.
 *
 * Unassessed controls are excluded from the numerator AND the denominator — a
 * tenant that has not connected a PKI source is not "failing PKI", it is not
 * measured there, and `controlCoverage` is the number that says so. Reporting
 * both is what makes the headline honest.
 */
function weightedCompliance(controls: ControlRecord[]): { value: number | null; measured: number; weight: number } {
  const scored = controls.filter((control) => control.measured && control.score !== null && control.status !== 'not-applicable')
  if (!scored.length) return { value: null, measured: 0, weight: 0 }
  const totalWeight = scored.reduce((sum, control) => sum + control.weight, 0)
  if (totalWeight <= 0) return { value: null, measured: scored.length, weight: 0 }
  const weighted = scored.reduce((sum, control) => sum + (control.score ?? 0) * control.weight, 0)
  return { value: clampPercent(weighted / totalWeight), measured: scored.length, weight: totalWeight }
}

/* ------------------------------------------------------------------ */
/* Requirement + framework rollup                                      */
/* ------------------------------------------------------------------ */

function rollupStatus(statuses: ControlStatus[]): ControlStatus {
  const inScope = statuses.filter((status) => status !== 'not-applicable')
  if (!inScope.length) return statuses.length ? 'not-applicable' : 'not-assessed'
  const measured = inScope.filter((status) => status !== 'not-assessed')
  if (!measured.length) return 'not-assessed'
  if (measured.every((status) => status === 'compliant')) return 'compliant'
  if (measured.every((status) => status === 'non-compliant')) return 'non-compliant'
  return 'partial'
}

function buildRequirements(controls: ControlRecord[], evidence: EvidenceRecord[]): RequirementRecord[] {
  const controlById = new Map(controls.map((control) => [control.id, control]))
  const evidenceByRequirement = new Map<string, number>()
  for (const record of evidence) {
    for (const requirementId of record.requirementIds) {
      evidenceByRequirement.set(requirementId, (evidenceByRequirement.get(requirementId) || 0) + 1)
    }
  }

  return REQUIREMENT_CATALOG.map((definition) => {
    const scoped = definition.controlIds.map((id) => controlById.get(id)).filter((control): control is ControlRecord => Boolean(control))
    const inScope = scoped.filter((control) => control.status !== 'not-applicable')
    const measured = inScope.filter((control) => control.measured && control.score !== null)
    const totalWeight = measured.reduce((sum, control) => sum + control.weight, 0)
    const value = totalWeight > 0 ? clampPercent(measured.reduce((sum, control) => sum + (control.score ?? 0) * control.weight, 0) / totalWeight) : null
    const status = rollupStatus(scoped.map((control) => control.status))
    const lastValidatedAt = newest(...scoped.map((control) => control.lastValidatedAt))

    return {
      id: definition.id,
      frameworkId: definition.frameworkId,
      code: definition.code,
      title: definition.title,
      summary: definition.summary,
      controlIds: definition.controlIds,
      status,
      score: value,
      measured: measured.length > 0,
      controlsTotal: scoped.length,
      controlsMeasured: measured.length,
      controlsCompliant: scoped.filter((control) => control.status === 'compliant').length,
      controlsFailing: scoped.filter((control) => control.status === 'non-compliant' || control.status === 'partial').length,
      evidenceCount: evidenceByRequirement.get(definition.id) || 0,
      lastValidatedAt,
      evidenceFreshness: freshnessOf(lastValidatedAt, Date.now()).state,
      unmeasuredControlIds: inScope.filter((control) => !control.measured).map((control) => control.id),
    }
  })
}

function buildFrameworks(
  requirements: RequirementRecord[],
  controls: ControlRecord[],
  evidence: EvidenceRecord[],
  complianceEvidence: Row[],
  now: number,
): FrameworkRecord[] {
  const controlById = new Map(controls.map((control) => [control.id, control]))
  const attestedByFramework = new Map<string, number>()
  for (const row of complianceEvidence) {
    const frameworkId = resolveFrameworkId(str(row.framework))
    if (!frameworkId) continue
    attestedByFramework.set(frameworkId, (attestedByFramework.get(frameworkId) || 0) + 1)
  }
  const evidenceByFramework = new Map<string, number>()
  for (const record of evidence) {
    for (const frameworkId of record.frameworkIds) {
      evidenceByFramework.set(frameworkId, (evidenceByFramework.get(frameworkId) || 0) + 1)
    }
  }

  return FRAMEWORK_CATALOG.map((definition) => {
    const scopedRequirements = requirements.filter((requirement) => requirement.frameworkId === definition.id)
    const controlIds = new Set<string>()
    for (const requirement of scopedRequirements) for (const id of requirement.controlIds) controlIds.add(id)
    const scopedControls = [...controlIds].map((id) => controlById.get(id)).filter((control): control is ControlRecord => Boolean(control))

    const measuredControls = scopedControls.filter((control) => control.measured && control.score !== null && control.status !== 'not-applicable')
    const totalWeight = measuredControls.reduce((sum, control) => sum + control.weight, 0)
    const value = totalWeight > 0 ? clampPercent(measuredControls.reduce((sum, control) => sum + (control.score ?? 0) * control.weight, 0) / totalWeight) : null

    const openFindings = scopedControls.reduce((sum, control) => sum + control.failing, 0)
    const criticalFindings = scopedControls.filter((control) => control.severity === 'critical').length
    const lastValidatedAt = newest(...scopedControls.map((control) => control.lastValidatedAt))

    return {
      id: definition.id,
      name: definition.name,
      shortName: definition.shortName,
      authority: definition.authority,
      version: definition.version,
      scope: definition.scope,
      reference: definition.reference,
      category: definition.category,
      status: rollupStatus(scopedControls.map((control) => control.status)),
      score: value,
      measured: measuredControls.length > 0,
      requirementsTotal: scopedRequirements.length,
      requirementsMeasured: scopedRequirements.filter((requirement) => requirement.measured).length,
      requirementsCompliant: scopedRequirements.filter((requirement) => requirement.status === 'compliant').length,
      requirementsPartial: scopedRequirements.filter((requirement) => requirement.status === 'partial').length,
      requirementsFailing: scopedRequirements.filter((requirement) => requirement.status === 'non-compliant').length,
      requirementsUnassessed: scopedRequirements.filter((requirement) => requirement.status === 'not-assessed').length,
      controlsTotal: scopedControls.length,
      controlsMeasured: measuredControls.length,
      coverage: scopedRequirements.length
        ? clampPercent((scopedRequirements.filter((requirement) => requirement.measured).length / scopedRequirements.length) * 100)
        : 0,
      evidenceCount: evidenceByFramework.get(definition.id) || 0,
      attestedEvidenceCount: attestedByFramework.get(definition.id) || 0,
      openFindings,
      criticalFindings,
      lastValidatedAt,
      evidenceFreshness: freshnessOf(lastValidatedAt, now).state,
    }
  })
}

/* ------------------------------------------------------------------ */
/* Gaps                                                                */
/* ------------------------------------------------------------------ */

function buildGaps(input: {
  controls: ControlRecord[]
  policies: PolicyRecord[]
  evidence: EvidenceRecord[]
  frameworks: FrameworkRecord[]
  assets: AssetComplianceRecord[]
  now: number
}): GovernanceGap[] {
  const gaps: GovernanceGap[] = []
  const push = (gap: GovernanceGap) => gaps.push(gap)

  /* Failing and weak controls — one gap per control, never aggregated away. */
  for (const control of input.controls) {
    if (control.status === 'non-compliant') {
      push({
        id: `gap:failing:${control.id}`,
        kind: 'failing-control',
        title: control.title,
        detail: control.basis,
        severity: control.severity || 'high',
        count: control.failing,
        domain: control.domain,
        controlIds: [control.id],
        frameworkIds: control.frameworkIds,
        requirementIds: control.requirementIds,
        assetIds: control.affectedAssetIds.slice(0, 50),
        route: control.remediationRoute,
        impact: `Closing this control moves ${control.failing} of ${control.population} in-scope subject(s) into compliance across ${control.frameworkIds.length} framework(s).`,
        detectedAt: control.lastValidatedAt,
      })
    } else if (control.status === 'partial' && (control.score ?? 100) < 70) {
      push({
        id: `gap:weak:${control.id}`,
        kind: 'weak-control',
        title: control.title,
        detail: control.basis,
        severity: control.severity || 'medium',
        count: control.failing,
        domain: control.domain,
        controlIds: [control.id],
        frameworkIds: control.frameworkIds,
        requirementIds: control.requirementIds,
        assetIds: control.affectedAssetIds.slice(0, 50),
        route: control.remediationRoute,
        impact: `${control.failing} of ${control.population} subject(s) still fail this control.`,
        detectedAt: control.lastValidatedAt,
      })
    } else if (!control.measured && control.status === 'not-assessed') {
      push({
        id: `gap:unmeasured:${control.id}`,
        kind: 'missing-evidence',
        title: `No evidence for ${control.title}`,
        detail: control.basis,
        severity: control.weight >= 4 ? 'high' : 'medium',
        count: 1,
        domain: control.domain,
        controlIds: [control.id],
        frameworkIds: control.frameworkIds,
        requirementIds: control.requirementIds,
        assetIds: [],
        route: control.remediationRoute,
        impact: `Connecting this evidence source lets ${control.requirementIds.length} requirement(s) across ${control.frameworkIds.length} framework(s) be assessed.`,
        detectedAt: null,
      })
    }
    if (control.exception?.expired) {
      push({
        id: `gap:exception:${control.id}`,
        kind: 'expired-exception',
        title: `Expired exception on ${control.title}`,
        detail: `Exception approved by ${control.exception.approvedBy} expired on ${control.exception.expiresAt?.slice(0, 10)} and has not been renewed.`,
        severity: 'high',
        count: 1,
        domain: control.domain,
        controlIds: [control.id],
        frameworkIds: control.frameworkIds,
        requirementIds: control.requirementIds,
        assetIds: [],
        route: '/dashboard/compliance',
        impact: 'The control is back in scope until the exception is renewed or the finding is remediated.',
        detectedAt: control.exception.expiresAt,
      })
    }
  }

  /* Policy violations, grouped per rule so the count is the rule's own. */
  for (const policy of input.policies) {
    if (!policy.violations) continue
    const controlIds = policy.controlIds
    const domain = (CONTROL_BY_ID.get(controlIds[0] || '')?.domain || 'governance') as ControlDomain
    push({
      id: `gap:policy:${policy.id}`,
      kind: 'policy-violation',
      title: policy.title,
      detail: `${policy.violations} violation(s) of a ${policy.enforcement} rule. ${policy.basis}`,
      severity: policy.criticalViolations > 0 ? 'critical' : policy.severity,
      count: policy.violations,
      domain,
      controlIds,
      frameworkIds: [...new Set(controlIds.flatMap((id) => input.controls.find((control) => control.id === id)?.frameworkIds || []))],
      requirementIds: [...new Set(controlIds.flatMap((id) => input.controls.find((control) => control.id === id)?.requirementIds || []))],
      assetIds: [...new Set(policy.violationSample.map((item) => item.assetId).filter((id): id is string => Boolean(id)))],
      route: policy.remediationRoute,
      impact: `Resolving these restores adherence on ${policy.evaluated} evaluated subject(s).`,
      detectedAt: policy.lastEvaluatedAt,
    })
  }

  /* Evidence lifecycle. */
  const stale = input.evidence.filter((record) => record.freshness === 'stale')
  if (stale.length) {
    push({
      id: 'gap:stale-evidence',
      kind: 'stale-evidence',
      title: 'Evidence has aged beyond the staleness threshold',
      detail: `${stale.length} evidence record(s) are older than 90 days and no longer describe the live estate.`,
      severity: 'medium',
      count: stale.length,
      domain: 'audit',
      controlIds: ['CTL-EVD-01'],
      frameworkIds: [],
      requirementIds: [],
      assetIds: [...new Set(stale.map((record) => record.assetId).filter((id): id is string => Boolean(id)))].slice(0, 50),
      route: '/dashboard/scanner',
      impact: 'Re-running discovery refreshes the evidence supporting every affected control.',
      detectedAt: newest(...stale.map((record) => record.occurredAt)),
    })
  }
  const expired = input.evidence.filter((record) => record.retention.state === 'expired')
  if (expired.length) {
    push({
      id: 'gap:expired-evidence',
      kind: 'expired-evidence',
      title: 'Evidence has passed its retention window',
      detail: `${expired.length} evidence record(s) are past the platform retention window for their class.`,
      severity: 'low',
      count: expired.length,
      domain: 'audit',
      controlIds: ['CTL-AUD-04'],
      frameworkIds: [],
      requirementIds: [],
      assetIds: [],
      route: '/dashboard/audit-vault',
      impact: 'Archive or renew these records to keep the retention control satisfied.',
      detectedAt: newest(...expired.map((record) => record.occurredAt)),
    })
  }

  /* Assets with no cryptographic evidence at all. */
  const unmapped = input.assets.filter((asset) => asset.status === 'not-assessed' && asset.evidenceCount === 0)
  if (unmapped.length) {
    push({
      id: 'gap:unmapped-assets',
      kind: 'unmapped-asset',
      title: 'Assets carry no cryptographic evidence',
      detail: `${unmapped.length} asset(s) have no component, certificate, finding or runtime observation bound to them.`,
      severity: 'medium',
      count: unmapped.length,
      domain: 'inventory',
      controlIds: ['CTL-INV-01'],
      frameworkIds: [],
      requirementIds: [],
      assetIds: unmapped.map((asset) => asset.assetId).slice(0, 50),
      route: '/dashboard/scanner',
      impact: 'Scanning these assets brings them into every inventory-scoped control.',
      detectedAt: null,
    })
  }

  const rank: Record<GapKind, number> = {
    'failing-control': 9,
    'policy-violation': 8,
    'pqc-gap': 8,
    'expired-exception': 7,
    'open-finding': 6,
    'weak-control': 5,
    'missing-control': 5,
    'missing-evidence': 4,
    'unmapped-asset': 3,
    'stale-evidence': 2,
    'expired-evidence': 1,
  }
  return gaps.sort(
    (a, b) => severityOrder(b.severity) - severityOrder(a.severity) || rank[b.kind] - rank[a.kind] || b.count - a.count,
  )
}

/* ------------------------------------------------------------------ */
/* Asset compliance                                                    */
/* ------------------------------------------------------------------ */

function buildAssetCompliance(input: {
  portfolioAssets: PortfolioAsset[]
  assets: Row[]
  controls: ControlRecord[]
  policies: PolicyRecord[]
  evidence: EvidenceRecord[]
  complianceEvidence: Row[]
  now: number
}): AssetComplianceRecord[] {
  const failingByAsset = new Map<string, Set<string>>()
  for (const control of input.controls) {
    for (const assetId of control.affectedAssetIds) {
      const set = failingByAsset.get(assetId) || new Set<string>()
      set.add(control.id)
      failingByAsset.set(assetId, set)
    }
  }
  const violationsByAsset = new Map<string, number>()
  for (const policy of input.policies) {
    for (const item of policy.violationSample) {
      if (!item.assetId) continue
      violationsByAsset.set(item.assetId, (violationsByAsset.get(item.assetId) || 0) + 1)
    }
  }
  const evidenceByAsset = new Map<string, EvidenceRecord[]>()
  for (const record of input.evidence) {
    if (!record.assetId) continue
    const list = evidenceByAsset.get(record.assetId) || []
    list.push(record)
    evidenceByAsset.set(record.assetId, list)
  }
  const attestedByAsset = new Map<string, Set<string>>()
  for (const row of input.complianceEvidence) {
    const assetId = str(row.asset_id)
    if (!assetId) continue
    const set = attestedByAsset.get(assetId) || new Set<string>()
    const framework = str(row.framework)
    if (framework) set.add(framework)
    attestedByAsset.set(assetId, set)
  }

  // The portfolio is the canonical per-asset dossier set (shared with the
  // Migration Planner). Assets present in the raw table but absent from the
  // portfolio still appear, so nothing is silently dropped from the estate.
  const byId = new Map<string, PortfolioAsset>(input.portfolioAssets.map((asset) => [asset.id, asset]))
  const rows: AssetComplianceRecord[] = []
  const seen = new Set<string>()

  const emit = (id: string, name: string, type: string, environment: string, owner: string, criticality: string, internetFacing: boolean, posture: string, postureLabel: string, riskScore: number, readinessScore: number, severityCounts: { critical: number; high: number } | null, lastEvidenceAt: string | null) => {
    if (seen.has(id)) return
    seen.add(id)
    const failingControls = failingByAsset.get(id)
    const assetEvidence = evidenceByAsset.get(id) || []
    const openFindings = assetEvidence.filter((record) => record.kind === 'finding' && record.outcome === 'contradicting').length
    const criticalFindings = severityCounts ? severityCounts.critical : assetEvidence.filter((record) => record.kind === 'finding' && record.severity === 'critical').length
    const freshness = freshnessOf(lastEvidenceAt, input.now)
    const status: ControlStatus = assetEvidence.length === 0
      ? 'not-assessed'
      : failingControls && failingControls.size > 0
        ? 'non-compliant'
        : 'compliant'

    rows.push({
      assetId: id,
      name,
      type,
      environment,
      owner: owner || 'Unassigned',
      criticality,
      internetFacing,
      posture,
      postureLabel,
      riskScore,
      readinessScore,
      controlsInScope: input.controls.filter((control) => control.domain !== 'governance' && control.domain !== 'audit').length,
      controlsFailing: failingControls?.size || 0,
      failingControlIds: [...(failingControls || [])],
      openFindings,
      criticalFindings,
      policyViolations: violationsByAsset.get(id) || 0,
      evidenceCount: assetEvidence.length,
      attestedFrameworks: [...(attestedByAsset.get(id) || [])],
      status,
      lastEvidenceAt,
      evidenceFreshness: freshness.state,
      href: `/dashboard/migration-planner?asset=${encodeURIComponent(id)}`,
    })
  }

  for (const asset of input.portfolioAssets) {
    emit(
      asset.id,
      asset.name,
      asset.type,
      asset.environment,
      asset.owner,
      asset.businessCriticality,
      asset.internetFacing,
      asset.posture,
      asset.postureLabel,
      asset.riskScore,
      asset.readinessScore,
      asset.severityCounts,
      asset.lastEvidenceAt,
    )
  }
  for (const row of input.assets) {
    const id = str(row.id)
    if (!id || byId.has(id)) continue
    if (str(row.status).toLowerCase() === 'archived') continue
    const metadata = recordOf(row.metadata)
    emit(
      id,
      str(row.name) || 'Asset',
      str(row.type) || 'asset',
      str(row.environment) || 'unknown',
      str(row.service_owner) || str(metadata.owner),
      str(row.criticality) || 'unknown',
      false,
      'unknown',
      'Not assessed',
      0,
      0,
      null,
      str(row.updated_at) || str(row.created_at) || null,
    )
  }

  return rows.sort(
    (a, b) => b.controlsFailing - a.controlsFailing || b.criticalFindings - a.criticalFindings || b.riskScore - a.riskScore,
  )
}

/* ------------------------------------------------------------------ */
/* Trend                                                               */
/* ------------------------------------------------------------------ */

/**
 * A 30-day activity trend built only from timestamps that actually exist.
 *
 * Days before the first observation are marked `observed: false` so the chart
 * can render them as "no data" instead of drawing a zero line that reads as a
 * measured absence.
 */
function buildTrend(evidence: EvidenceRecord[], auditEvents: AuditEvent[], policies: PolicyRecord[], now: number): GovernanceTrendPoint[] {
  const days = 30
  const start = new Date(now)
  start.setHours(0, 0, 0, 0)
  start.setDate(start.getDate() - (days - 1))
  const startMs = start.getTime()

  const earliest = Math.min(
    ...[
      ...evidence.map((record) => ms(record.occurredAt)).filter(Boolean),
      ...auditEvents.map((event) => ms(event.at)).filter(Boolean),
    ].concat([now]),
  )

  const violationsPerDay = policies.reduce((sum, policy) => sum + policy.violations, 0) > 0
  const points: GovernanceTrendPoint[] = []
  for (let index = 0; index < days; index += 1) {
    const dayStart = startMs + index * 86_400_000
    const dayEnd = dayStart + 86_400_000
    const inDay = (value: string | null) => {
      const at = ms(value)
      return at >= dayStart && at < dayEnd
    }
    const dayEvidence = evidence.filter((record) => inDay(record.occurredAt))
    const dayAudit = auditEvents.filter((event) => inDay(event.at))
    const findings = dayEvidence.filter((record) => record.kind === 'finding')
    points.push({
      label: new Date(dayStart).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      date: new Date(dayStart).toISOString().slice(0, 10),
      evidence: dayEvidence.length,
      auditEvents: dayAudit.length,
      findingsOpened: findings.filter((record) => record.outcome === 'contradicting').length,
      findingsResolved: findings.filter((record) => record.outcome === 'supporting').length,
      // Policy evaluation is point-in-time, not historical: attributing today's
      // violation count to a past day would be invented history. Only the most
      // recent day carries the measured figure.
      violations: violationsPerDay && index === days - 1 ? policies.reduce((sum, policy) => sum + policy.violations, 0) : 0,
      observed: dayEnd > earliest,
    })
  }
  return points
}

/* ------------------------------------------------------------------ */
/* Facets                                                             */
/* ------------------------------------------------------------------ */

function countFacet<T>(items: T[], key: (item: T) => string, label: (id: string) => string): Array<{ id: string; label: string; count: number }> {
  const counts = new Map<string, number>()
  for (const item of items) {
    const id = key(item)
    if (!id) continue
    counts.set(id, (counts.get(id) || 0) + 1)
  }
  return [...counts.entries()]
    .map(([id, count]) => ({ id, label: label(id), count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
}

function buildFacets(input: {
  controls: ControlRecord[]
  frameworks: FrameworkRecord[]
  assets: AssetComplianceRecord[]
  evidence: EvidenceRecord[]
  auditEvents: AuditEvent[]
  policies: PolicyRecord[]
}): GovernanceFacets {
  return {
    frameworks: input.frameworks
      .map((framework) => ({ id: framework.id, label: framework.shortName, count: framework.controlsTotal }))
      .sort((a, b) => a.label.localeCompare(b.label)),
    domains: countFacet(input.controls, (control) => control.domain, (id) => CONTROL_DOMAIN_LABEL[id as ControlDomain] || id),
    statuses: countFacet(input.controls, (control) => control.status, (id) => CONTROL_STATUS_LABEL[id as ControlStatus] || id),
    environments: countFacet(input.assets, (asset) => asset.environment, (id) => id),
    owners: countFacet(input.assets, (asset) => asset.owner, (id) => id),
    criticalities: countFacet(input.assets, (asset) => asset.criticality, (id) => id),
    severities: countFacet(
      input.controls.filter((control) => control.severity),
      (control) => control.severity || '',
      (id) => id.charAt(0).toUpperCase() + id.slice(1),
    ),
    auditCategories: countFacet(input.auditEvents, (event) => event.category, (id) => AUDIT_CATEGORY_LABEL[id as AuditEvent['category']] || id),
    evidenceKinds: countFacet(input.evidence, (record) => record.kind, (id) => id.charAt(0).toUpperCase() + id.slice(1)),
    policyCategories: countFacet(input.policies, (policy) => policy.category, (id) => POLICY_CATEGORY_LABEL[id as PolicyRecord['category']] || id),
  }
}

/* ------------------------------------------------------------------ */
/* Reconciliation (§16)                                                */
/* ------------------------------------------------------------------ */

function buildReconciliation(input: {
  snapshot: CanonicalSnapshot
  controls: ControlRecord[]
  evidence: EvidenceRecord[]
  auditEvents: AuditEvent[]
  assets: AssetComplianceRecord[]
  policies: PolicyRecord[]
  now: number
}): ReconciliationReport {
  const rows: ReconciliationRow[] = []
  const discrepancies: string[] = []

  const row = (metric: string, value: number | null, source: string, alsoShownOn: string[], scopeNote: string, agrees = true): ReconciliationRow => {
    if (!agrees) discrepancies.push(`${metric}: ${scopeNote}`)
    return { metric, value, source, alsoShownOn, scopeNote, agrees }
  }

  const assetsAssessed = input.snapshot.inventory.assetsAssessed
  rows.push(
    row('Assets assessed', assetsAssessed, 'Quantum Readiness snapshot · inventory.assetsAssessed', ['Assets & CBOM', 'Migration Planner', 'Executive Command Center'], 'Active tenant assets. Governance mirrors this figure rather than recounting.'),
  )
  rows.push(
    row('Cryptographic components', input.snapshot.inventory.cryptoComponents, 'Quantum Readiness snapshot · inventory.cryptoComponents', ['CBOM Explorer', 'Assets & CBOM', 'Quantum Readiness'], 'The canonical unit is the COMPONENT, not the finding.'),
  )
  rows.push(
    row('Quantum-vulnerable components', input.snapshot.inventory.vulnerableComponents, 'Quantum Readiness snapshot · inventory.vulnerableComponents', ['CBOM Explorer', 'Quantum Readiness', 'Harvest Now'], 'Components classified quantum-vulnerable. Drives CTL-PQC-01 and CTL-PQC-03.'),
  )
  rows.push(
    row('PQC-ready components', input.snapshot.inventory.pqcReadyComponents, 'Quantum Readiness snapshot · inventory.pqcReadyComponents', ['CBOM Explorer', 'Quantum Readiness'], 'Post-quantum plus hybrid components.'),
  )
  rows.push(
    row('Certificates analysed', input.snapshot.inventory.certificatesAnalyzed, 'Quantum Readiness snapshot · inventory.certificatesAnalyzed', ['PKI Visibility', 'Certificate Telemetry'], 'Certificate population for CTL-CRT-01..03.'),
  )
  rows.push(
    row('Managed keys', input.snapshot.inventory.keysDiscovered, 'Quantum Readiness snapshot · inventory.keysDiscovered', ['QKMS Inventory'], 'Key population for CTL-KEY-01..03.'),
  )
  rows.push(
    row('Critical findings', input.snapshot.riskDistribution.critical, 'Quantum Readiness snapshot · riskDistribution.critical', ['Quantum Risk Analysis', 'Quantum Readiness', 'Executive Command Center'], 'Per-instance severity distribution from the scanner intelligence bundle.'),
  )
  rows.push(
    row('High findings', input.snapshot.riskDistribution.high, 'Quantum Readiness snapshot · riskDistribution.high', ['Quantum Risk Analysis', 'Quantum Readiness'], 'Per-instance severity distribution from the scanner intelligence bundle.'),
  )
  rows.push(
    row('Quantum readiness', input.snapshot.scores.quantumReadiness, 'Quantum Readiness snapshot · scores.quantumReadiness', ['Quantum Readiness', 'Executive Command Center', 'Report Center'], 'Mirrored, not recomputed.'),
  )
  rows.push(
    row('Quantum risk', input.snapshot.scores.quantumRisk, 'Quantum Readiness snapshot · scores.quantumRisk', ['Quantum Readiness', 'Harvest Now'], 'Mirrored, and the value CTL-GOV-03 is tested against.'),
  )
  rows.push(
    row('PQC adoption', Math.round(input.snapshot.scores.pqcAdoption), 'Quantum Readiness snapshot · scores.pqcAdoption', ['Quantum Readiness', 'Migration Timeline'], 'CTL-PQC-03 publishes this value directly rather than deriving a rival one.'),
  )

  /* Governance-owned figures. */
  rows.push(
    row('Controls in catalog', input.controls.length, 'Governance control catalog', ['Compliance', 'Regulatory Mapping', 'Quantum Governance'], 'Same catalog on all four governance pages.'),
  )
  rows.push(
    row('Controls measured', input.controls.filter((control) => control.measured).length, 'Governance control evaluation', ['Compliance', 'Regulatory Mapping'], 'Controls with tenant evidence. The compliance score covers only these.'),
  )
  rows.push(
    row('Evidence records', input.evidence.length, 'Unified evidence model', ['Audit Vault', 'Compliance', 'Regulatory Mapping'], 'One producer; the vault and the control drill-downs cite the same records.'),
  )
  rows.push(
    row('Audit events', input.auditEvents.length, 'Audit trail normaliser', ['Audit Vault'], 'Normalised across every audit-relevant source table.'),
  )
  rows.push(
    row('Policy violations', input.policies.reduce((sum, policy) => sum + policy.violations, 0), 'Crypto policy engine', ['Quantum Governance', 'Compliance'], 'Control failures for policy-backed controls are the same violations, not a second count.'),
  )

  /* Consistency assertion the engine can actually check. */
  const assetRowCount = input.assets.length
  if (assetsAssessed > 0 && assetRowCount > 0 && Math.abs(assetRowCount - assetsAssessed) > 0) {
    rows.push(
      row(
        'Assets in governance table',
        assetRowCount,
        'Governance asset compliance projection',
        ['Compliance', 'Regulatory Mapping'],
        `Differs from the canonical ${assetsAssessed} because the governance table also lists assets present in the asset table but absent from the migration portfolio (no dossier yet).`,
        assetRowCount >= assetsAssessed,
      ),
    )
  } else {
    rows.push(row('Assets in governance table', assetRowCount, 'Governance asset compliance projection', ['Compliance', 'Regulatory Mapping'], 'Matches the canonical asset count.'))
  }

  return {
    generatedAt: new Date(input.now).toISOString(),
    rows,
    discrepancies,
    note: 'Every estate figure on these four pages is mirrored from the Quantum Readiness snapshot, which is itself computed once per tenant per 15-second window. Governance-owned figures are produced by the single engine behind all four pages. Where a number legitimately differs in scope, the difference is stated above rather than hidden.',
  }
}

/* ------------------------------------------------------------------ */
/* Telemetry                                                           */
/* ------------------------------------------------------------------ */

function buildTelemetry(input: GovernanceInputs, evidence: EvidenceRecord[], auditEvents: AuditEvent[], now: number): GovernanceTelemetry {
  const agentsOnline = input.scannerAgents.filter((agent) => {
    const lastSeen = ms(agent.last_seen_at || agent.updated_at)
    return (lastSeen > 0 && now - lastSeen <= 3_600_000) || /online|active|healthy|running/i.test(str(agent.status))
  }).length
  const connectorsActive = input.connectorAccounts.filter((connector) =>
    /connected|active|healthy|ok|synced/i.test(str(connector.status)),
  ).length
  const runningScans = input.scanSessions.filter((session) => /running|pending|queued|analyzing|scanning/i.test(str(session.status))).length

  const lastScanAt = newest(...input.scanSessions.map((session) => session.completed_at || session.updated_at || session.created_at))
  const lastEvidenceAt = newest(...evidence.map((record) => record.occurredAt))
  const lastAuditEventAt = newest(...auditEvents.map((event) => event.at))

  const hasInventory =
    input.snapshot.inventory.assetsAssessed > 0 || input.snapshot.inventory.cryptoComponents > 0 || input.cryptoInventory.length > 0
  const recentEvidence = lastEvidenceAt ? now - ms(lastEvidenceAt) <= 7 * 86_400_000 : false
  const pipelineStatus: GovernancePipelineStatus = recentEvidence
    ? 'live'
    : hasInventory
      ? 'inventory-only'
      : input.scannerAgents.length || input.connectorAccounts.length
        ? 'awaiting-evidence'
        : 'no-sources'

  return {
    pipelineStatus,
    agentsOnline,
    agentsTotal: input.scannerAgents.length,
    connectorsActive,
    connectorsTotal: input.connectorAccounts.length,
    runningScans,
    lastScanAt,
    lastRuntimeEventAt: input.snapshot.telemetry.latestRuntimeEventAt,
    lastAuditEventAt,
    lastEvidenceAt,
    sourceCounts: input.sourceCounts,
    truncated: input.truncated,
    absentSources: input.absentSources,
    anchoringAvailable: input.evidenceAnchors !== null,
    policyStoreAvailable: input.policyOverrides !== null,
  }
}

/* ------------------------------------------------------------------ */
/* Composer                                                            */
/* ------------------------------------------------------------------ */

export function buildGovernanceIntelligence(inputs: GovernanceInputs): GovernanceIntelligence {
  const now = inputs.now ?? Date.now()

  /* 1. Normalise the subject population once. */
  const subjects = buildSubjects({
    assets: inputs.assets,
    cryptoInventory: inputs.cryptoInventory,
    certificates: inputs.certificates,
    generatedKeys: inputs.generatedKeys,
    runtimeEvents: inputs.runtimeEvents,
    vaultFiles: inputs.vaultFiles,
  })

  /* 2. Evaluate cryptographic policy against it. */
  const policyContext: PolicyEvaluationContext = {
    subjects,
    now,
    quantumRisk: inputs.snapshot.hasData ? inputs.snapshot.scores.quantumRisk : null,
    hasEstateEvidence: inputs.snapshot.hasData,
  }
  const policies = evaluatePolicies(policyContext, inputs.policyOverrides)

  /* 3. Build the unified evidence model (integrity, retention, custody). */
  const anchorMap = inputs.evidenceAnchors
    ? new Map(
        inputs.evidenceAnchors.map((anchor) => [
          str(anchor.evidence_id),
          { digest: str(anchor.digest), anchoredAt: str(anchor.anchored_at) || str(anchor.created_at) || null },
        ]),
      )
    : null

  const evidenceInputs: EvidenceInputs = {
    now,
    assetById: subjects.assetById,
    complianceEvidence: inputs.complianceEvidence,
    scanSessions: inputs.scanSessions,
    scanResults: inputs.scanResults,
    cryptoExposures: inputs.cryptoExposures,
    vulnerabilities: inputs.vulnerabilities,
    scannerAlerts: inputs.scannerAlerts,
    scannerEvidence: inputs.scannerEvidence,
    cryptoInventory: inputs.cryptoInventory,
    certificates: inputs.certificates,
    generatedKeys: inputs.generatedKeys,
    runtimeEvents: inputs.runtimeEvents,
    migrationJobs: inputs.migrationJobs,
    vaultFiles: inputs.vaultFiles,
    vaultAuditLogs: inputs.vaultAuditLogs,
    auditLogs: inputs.auditLogs,
    anchors: anchorMap,
  }
  const evidence = buildEvidence(evidenceInputs)

  /* 4. Normalise the audit trail. */
  const auditInputs: AuditInputs = {
    now,
    assetById: subjects.assetById,
    auditLogs: inputs.auditLogs,
    vaultAuditLogs: inputs.vaultAuditLogs,
    securityEvents: inputs.securityEvents,
    userSecurityEvents: inputs.userSecurityEvents,
    authEvents: inputs.authEvents,
    migrationEvents: inputs.migrationEvents,
    scanSessions: inputs.scanSessions,
    complianceEvidence: inputs.complianceEvidence,
    scannerAlerts: inputs.scannerAlerts,
    generatedKeys: inputs.generatedKeys,
    certificates: inputs.certificates,
    assets: inputs.assets,
  }
  const auditEvents = buildAuditEvents(auditInputs)

  /* 5. Evaluate controls. */
  const controlInputs: ControlEvaluationInputs = {
    now,
    snapshot: inputs.snapshot,
    subjects,
    policies,
    evidence,
    assets: inputs.assets,
    scanSessions: inputs.scanSessions,
    scanResults: inputs.scanResults,
    vulnerabilities: inputs.vulnerabilities,
    scannerAlerts: inputs.scannerAlerts,
    cryptoExposures: inputs.cryptoExposures,
    scannerAgents: inputs.scannerAgents,
    connectorAccounts: inputs.connectorAccounts,
    agentHeartbeats: inputs.agentHeartbeats,
    migrationJobs: inputs.migrationJobs,
    migrationPlans: inputs.migrationPlans,
    auditLogs: inputs.auditLogs,
    vaultAuditLogs: inputs.vaultAuditLogs,
    securityEvents: inputs.securityEvents,
    authEvents: inputs.authEvents,
    complianceEvidence: inputs.complianceEvidence,
    assessments: inputs.controlAssessments,
    anchoringAvailable: inputs.evidenceAnchors !== null,
  }
  const controls = evaluateControls(controlInputs)

  /* 6. Roll up to requirements and frameworks. */
  const requirements = buildRequirements(controls, evidence)
  const frameworks = buildFrameworks(requirements, controls, evidence, inputs.complianceEvidence, now)

  /* 7. Asset projection, gaps, trend, facets. */
  const assets = buildAssetCompliance({
    portfolioAssets: inputs.portfolioAssets,
    assets: inputs.assets,
    controls,
    policies,
    evidence,
    complianceEvidence: inputs.complianceEvidence,
    now,
  })
  const gaps = buildGaps({ controls, policies, evidence, frameworks, assets, now })
  const trend = buildTrend(evidence, auditEvents, policies, now)
  const facets = buildFacets({ controls, frameworks, assets, evidence, auditEvents, policies })
  const telemetry = buildTelemetry(inputs, evidence, auditEvents, now)
  const reconciliation = buildReconciliation({ snapshot: inputs.snapshot, controls, evidence, auditEvents, assets, policies, now })

  /* 8. Scores. */
  const compliance = weightedCompliance(controls)
  const inScopeControls = controls.filter((control) => control.status !== 'not-applicable')
  const measuredControls = inScopeControls.filter((control) => control.measured)

  const datedEvidence = evidence.filter((record) => record.freshness !== 'unknown')
  const freshEvidence = datedEvidence.filter((record) => record.freshness === 'fresh')
  const controlsWithEvidence = inScopeControls.filter((control) => control.evidenceIds.length > 0)

  const measurablePolicies = policies.filter((policy) => policy.measured && policy.adherence !== null)
  const policyEvaluated = measurablePolicies.reduce((sum, policy) => sum + policy.evaluated, 0)
  const policyCompliant = measurablePolicies.reduce((sum, policy) => sum + policy.compliantSubjects, 0)

  const pqcControls = controls.filter((control) => control.domain === 'quantum' && control.measured && control.score !== null)
  const pqcWeight = pqcControls.reduce((sum, control) => sum + control.weight, 0)
  const pqcValue = pqcWeight > 0 ? clampPercent(pqcControls.reduce((sum, control) => sum + (control.score ?? 0) * control.weight, 0) / pqcWeight) : null

  const auditControls = controls.filter((control) => control.domain === 'audit' && control.measured && control.score !== null)
  const auditWeight = auditControls.reduce((sum, control) => sum + control.weight, 0)
  const auditValue = auditWeight > 0 ? clampPercent(auditControls.reduce((sum, control) => sum + (control.score ?? 0) * control.weight, 0) / auditWeight) : null

  const governanceControls = controls.filter((control) => control.domain === 'governance' && control.measured && control.score !== null)
  const governanceWeight = governanceControls.reduce((sum, control) => sum + control.weight, 0)
  const governanceValue = governanceWeight > 0
    ? clampPercent(governanceControls.reduce((sum, control) => sum + (control.score ?? 0) * control.weight, 0) / governanceWeight)
    : null

  const latestEvidenceAt = newest(
    ...evidence.slice(0, 200).map((record) => record.occurredAt),
    ...auditEvents.slice(0, 200).map((event) => event.at),
  )
  const staleSinceHours = latestEvidenceAt ? Math.floor((now - ms(latestEvidenceAt)) / 3_600_000) : null
  const hasData = evidence.length > 0 || auditEvents.length > 0 || inputs.snapshot.hasData

  const scores: GovernanceIntelligence['scores'] = {
    compliance: score({
      id: 'compliance',
      label: 'Compliance Score',
      value: compliance.value,
      measured: compliance.value !== null,
      unit: 'percent',
      basis: compliance.value === null
        ? 'No control has enough tenant evidence to be assessed yet.'
        : `Weighted across the ${compliance.measured} of ${inScopeControls.length} control(s) that have tenant evidence. Unassessed controls are excluded from both the numerator and the denominator.`,
      numerator: compliance.measured,
      denominator: inScopeControls.length,
      route: '/dashboard/compliance',
      hint: 'Weighted mean of measured control scores. Controls with no evidence do not count as failures — see Control Coverage.',
    }),
    controlCoverage: score({
      id: 'control-coverage',
      label: 'Control Coverage',
      value: inScopeControls.length ? clampPercent((measuredControls.length / inScopeControls.length) * 100) : null,
      measured: inScopeControls.length > 0,
      unit: 'percent',
      basis: `${measuredControls.length} of ${inScopeControls.length} in-scope control(s) have the evidence required to assess them.`,
      numerator: measuredControls.length,
      denominator: inScopeControls.length,
      route: '/dashboard/compliance',
      hint: 'How much of the control set the platform can actually assess with the evidence connected today.',
    }),
    evidenceCoverage: score({
      id: 'evidence-coverage',
      label: 'Evidence Coverage',
      value: inScopeControls.length ? clampPercent((controlsWithEvidence.length / inScopeControls.length) * 100) : null,
      measured: inScopeControls.length > 0,
      unit: 'percent',
      basis: `${controlsWithEvidence.length} of ${inScopeControls.length} in-scope control(s) cite at least one evidence record.`,
      numerator: controlsWithEvidence.length,
      denominator: inScopeControls.length,
      route: '/dashboard/audit-vault',
      hint: 'Controls that can point to a concrete, retained evidence record.',
    }),
    evidenceFreshness: score({
      id: 'evidence-freshness',
      label: 'Evidence Freshness',
      value: datedEvidence.length ? clampPercent((freshEvidence.length / datedEvidence.length) * 100) : null,
      measured: datedEvidence.length > 0,
      unit: 'percent',
      basis: datedEvidence.length
        ? `${freshEvidence.length} of ${datedEvidence.length} dated evidence record(s) are newer than 30 days.`
        : 'No dated evidence exists yet.',
      numerator: freshEvidence.length,
      denominator: datedEvidence.length,
      route: '/dashboard/audit-vault',
      hint: 'Share of evidence recorded in the last 30 days. Older evidence still counts, but describes an older estate.',
    }),
    policyAdherence: score({
      id: 'policy-adherence',
      label: 'Policy Adherence',
      value: policyEvaluated > 0 ? clampPercent((policyCompliant / policyEvaluated) * 100) : null,
      measured: policyEvaluated > 0,
      unit: 'percent',
      basis: policyEvaluated
        ? `${policyCompliant} of ${policyEvaluated} evaluated subject(s) satisfy every applicable cryptographic policy rule.`
        : 'No policy rule has subjects to evaluate yet.',
      numerator: policyCompliant,
      denominator: policyEvaluated,
      route: '/dashboard/quantum-governance',
      hint: 'Subject-level adherence across all enforced and monitored cryptographic policy rules.',
    }),
    pqcGovernance: score({
      id: 'pqc-governance',
      label: 'PQC Governance',
      value: pqcValue,
      measured: pqcValue !== null,
      unit: 'percent',
      basis: pqcValue === null
        ? 'No post-quantum control has enough evidence to be assessed yet.'
        : `Weighted across ${pqcControls.length} measured post-quantum control(s), including migration coverage, adoption and internet-facing exposure.`,
      numerator: pqcControls.length,
      denominator: controls.filter((control) => control.domain === 'quantum').length,
      route: '/dashboard/quantum-governance',
      hint: 'Governance readiness for the post-quantum transition, as distinct from technical readiness.',
    }),
    auditIntegrity: score({
      id: 'audit-integrity',
      label: 'Audit Integrity',
      value: auditValue,
      measured: auditValue !== null,
      unit: 'percent',
      basis: auditValue === null
        ? 'No audit or evidence control has enough evidence to be assessed yet.'
        : `Weighted across ${auditControls.length} measured audit control(s): logging, failure review, anchoring, retention and freshness.`,
      numerator: auditControls.length,
      denominator: controls.filter((control) => control.domain === 'audit').length,
      route: '/dashboard/audit-vault',
      hint: 'How defensible the audit trail and evidence store are, not how many events exist.',
    }),
    governance: score({
      id: 'governance',
      label: 'Governance Score',
      value: governanceValue,
      measured: governanceValue !== null,
      unit: 'percent',
      basis: governanceValue === null
        ? 'No governance control has enough evidence to be assessed yet.'
        : `Weighted across ${governanceControls.length} measured governance control(s): policy enforcement, exception governance and risk appetite.`,
      numerator: governanceControls.length,
      denominator: controls.filter((control) => control.domain === 'governance').length,
      route: '/dashboard/quantum-governance',
      hint: 'Whether cryptographic governance is defined, enforced and operating inside its stated risk appetite.',
    }),
    quantumReadiness: score({
      id: 'quantum-readiness',
      label: 'Quantum Readiness',
      value: inputs.snapshot.hasData ? Math.round(inputs.snapshot.scores.quantumReadiness) : null,
      measured: inputs.snapshot.hasData,
      unit: 'percent',
      basis: 'Mirrored from the Quantum Readiness assessment — the same value that page and the Report Center publish.',
      numerator: inputs.snapshot.inventory.pqcReadyComponents,
      denominator: inputs.snapshot.inventory.cryptoComponents,
      route: '/dashboard/quantum-readiness',
      hint: 'Canonical readiness score. Governance does not compute a rival value.',
    }),
    quantumRisk: score({
      id: 'quantum-risk',
      label: 'Quantum Risk',
      value: inputs.snapshot.hasData ? Math.round(inputs.snapshot.scores.quantumRisk) : null,
      measured: inputs.snapshot.hasData,
      unit: 'score',
      basis: 'Mirrored from the Quantum Readiness assessment. CTL-GOV-03 tests this value against the configured risk appetite.',
      numerator: inputs.snapshot.inventory.vulnerableComponents,
      denominator: inputs.snapshot.inventory.cryptoComponents,
      route: '/dashboard/quantum-readiness',
      hint: 'Lower is better. Compared against the quantum-risk threshold policy.',
      invertTone: true,
    }),
  }

  return {
    generatedAt: new Date(now).toISOString(),
    latestEvidenceAt,
    hasData,
    stale: staleSinceHours !== null && staleSinceHours > 24,
    staleSinceHours,
    scores,
    frameworks,
    requirements,
    controls,
    policies,
    evidence,
    auditEvents,
    gaps,
    assets,
    trend,
    facets,
    telemetry,
    reconciliation,
    totals: {
      frameworks: frameworks.length,
      requirements: requirements.length,
      controls: controls.length,
      controlsMeasured: measuredControls.length,
      controlsCompliant: controls.filter((control) => control.status === 'compliant').length,
      controlsPartial: controls.filter((control) => control.status === 'partial').length,
      controlsFailing: controls.filter((control) => control.status === 'non-compliant').length,
      controlsUnassessed: controls.filter((control) => control.status === 'not-assessed').length,
      controlsNotApplicable: controls.filter((control) => control.status === 'not-applicable').length,
      criticalGaps: gaps.filter((gap) => gap.severity === 'critical').length,
      gaps: gaps.length,
      policies: policies.length,
      policiesEnforced: policies.filter((policy) => policy.enforcement !== 'disabled').length,
      policyViolations: policies.reduce((sum, policy) => sum + policy.violations, 0),
      criticalPolicyViolations: policies.reduce((sum, policy) => sum + policy.criticalViolations, 0),
      evidence: evidence.length,
      evidenceStale: evidence.filter((record) => record.freshness === 'stale').length,
      evidenceExpired: evidence.filter((record) => record.retention.state === 'expired').length,
      evidenceAnchored: evidence.filter((record) => record.integrity.state === 'verified').length,
      evidenceMismatched: evidence.filter((record) => record.integrity.state === 'mismatch').length,
      auditEvents: auditEvents.length,
      auditFailures: auditEvents.filter((event) => event.outcome === 'failure' || event.outcome === 'denied').length,
      assets: assets.length,
      assetsCompliant: assets.filter((asset) => asset.status === 'compliant').length,
      assetsFailing: assets.filter((asset) => asset.status === 'non-compliant').length,
      assetsUnassessed: assets.filter((asset) => asset.status === 'not-assessed').length,
      openFindings: evidence.filter((record) => record.kind === 'finding' && record.outcome === 'contradicting').length,
      criticalFindings: inputs.snapshot.riskDistribution.critical,
      cryptoComponents: inputs.snapshot.inventory.cryptoComponents,
      vulnerableComponents: inputs.snapshot.inventory.vulnerableComponents,
      pqcReadyComponents: inputs.snapshot.inventory.pqcReadyComponents,
      certificates: inputs.snapshot.inventory.certificatesAnalyzed,
      keys: inputs.snapshot.inventory.keysDiscovered,
    },
  }
}

export { CONTROL_CATALOG, FRAMEWORK_CATALOG, REQUIREMENT_CATALOG }
export type { CanonicalSnapshot }
