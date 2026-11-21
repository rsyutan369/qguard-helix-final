import { CONTROL_BY_ID, FRAMEWORK_BY_ID } from './catalog'
import { evaluateControls, type ControlEvaluationInputs } from './controls'
import { buildRequirements, weightedCompliance } from './intelligence'
import { evaluatePolicies, policyViolations } from './policy'
import { newest, str, type Row, type SubjectSet } from './subjects'
import type { AuditEvent, ControlRecord, EvidenceRecord, GovernanceIntelligence, PolicyViolation, RequirementRecord } from './types'

/** These evaluators have a subject population that can be attributed to registered assets. */
const ASSET_EVALUATORS = new Set([
  'assetCryptoCoverage', 'cbomAlgorithmIdentification', 'assetOwnership',
  'forbiddenAlgorithms', 'keyStrength', 'approvedAlgorithms', 'tlsMinimumVersion', 'forwardSecrecy',
  'certificateInventory', 'certificateExpiry', 'certificateAlgorithm', 'cleartextOperations',
  'internetFacingPqc', 'findingSla', 'findingOwnership',
])


export function complianceAssetOption(row: Row) {
  return {
    id: str(row.id),
    name: str(row.name) || 'Unnamed asset',
    type: str(row.type) || 'asset',
    environment: str(row.environment) || 'Unrecorded',
    owner: str(row.service_owner) || 'Unassigned',
    lifecycle: str(row.status) || 'Unrecorded',
  }
}

export type ComplianceAssetOption = ReturnType<typeof complianceAssetOption>

export interface ComplianceAssetAssessment extends ComplianceAssetOption {
  score: number | null
  measured: number
  controls: number
  gaps: number
  posture: string | null
  riskScore: number | null
  riskLevel: string | null
  lastEvidenceAt: string | null
}

export interface AssetComplianceScope {
  generatedAt: string
  latestEvidenceAt: string | null
  earliestEvidenceAt: string | null
  assets: ComplianceAssetAssessment[]
  score: number | null
  measured: number
  controls: ControlRecord[]
  requirements: Array<RequirementRecord & { frameworkLabel: string }>
  violations: PolicyViolation[]
  evidence: EvidenceRecord[]
  findings: EvidenceRecord[]
  auditEvents: AuditEvent[]
  remediation: Array<{ id: string; assetId: string; title: string; status: string | null; updatedAt: string | null }>
  unavailableSources: string[]
  truncated: boolean
}

export function buildAssetComplianceScope(
  model: GovernanceIntelligence,
  inputs: ControlEvaluationInputs,
  registered: Row[],
  overrides: Row[] | null,
): AssetComplianceScope {
  const ids = new Set(registered.map((row) => str(row.id)))
  const evidence = model.evidence.filter((row) => row.assetId !== null && ids.has(row.assetId))
  const auditEvents = model.auditEvents.filter((row) => row.assetId !== null && ids.has(row.assetId))
  const estateAssets = new Map(model.assets.map((row) => [row.assetId, row]))

  function evaluate(assets: Row[], selected: Set<string>, records: EvidenceRecord[]) {
    const fromAssets = (rows: Row[]) => rows.filter((row) => selected.has(str(row.asset_id)))
    const fromSubjects = (rows: SubjectSet['all']) => rows.filter((row) => row.assetId !== null && selected.has(row.assetId))
    const subjects: SubjectSet = {
      all: fromSubjects(inputs.subjects.all),
      components: fromSubjects(inputs.subjects.components),
      certificates: fromSubjects(inputs.subjects.certificates),
      keys: fromSubjects(inputs.subjects.keys),
      transport: fromSubjects(inputs.subjects.transport),
      objects: fromSubjects(inputs.subjects.objects),
      assetById: new Map(assets.map((row) => [str(row.id), row])),
    }
    const policies = evaluatePolicies({ subjects, now: inputs.now, quantumRisk: null, hasEstateEvidence: false }, overrides)
    const controls = evaluateControls({
      ...inputs, assets, subjects, policies, evidence: records,
      scanResults: fromAssets(inputs.scanResults),
      vulnerabilities: fromAssets(inputs.vulnerabilities),
      cryptoExposures: fromAssets(inputs.cryptoExposures),
      complianceEvidence: fromAssets(inputs.complianceEvidence),
      scannerAlerts: [],
      // An organization-level exception has no verified asset attribution.
      assessments: null,
    }, ASSET_EVALUATORS).map((control) => {
      const missing = CONTROL_BY_ID.get(control.id)?.evidenceSources.filter((source) => model.telemetry.absentSources.includes(source)) ?? []
      if (!missing.length || control.failing > 0) return control
      return { ...control, status: 'not-assessed' as const, measured: false, score: null,
        basis: `Required sources unavailable: ${missing.join(', ')}. ${control.basis}` }
    })
    return { controls, violations: policies.flatMap(policyViolations).filter((row) => row.assetId !== null && selected.has(row.assetId)),
      scoring: weightedCompliance(controls) }
  }

  const combined = evaluate(registered, ids, evidence)
  const assets = registered.map((row) => {
    const asset = complianceAssetOption(row)
    const records = evidence.filter((record) => record.assetId === asset.id)
    const result = registered.length === 1 ? combined : evaluate([row], new Set([asset.id]), records)
    const posture = estateAssets.get(asset.id)
    return {
      ...asset, score: result.scoring.value, measured: result.scoring.measured, controls: result.controls.length,
      gaps: result.controls.filter((control) => control.status === 'non-compliant' || control.status === 'partial').length,
      posture: posture?.posture && posture.posture !== 'unknown' && posture.posture !== 'not-assessed' ? posture.postureLabel : null,
      riskScore: posture?.posture && posture.posture !== 'unknown' && posture.posture !== 'not-assessed' ? posture.riskScore : null,
      riskLevel: posture?.posture && posture.posture !== 'unknown' && posture.posture !== 'not-assessed' ? posture.riskLevel ?? null : null,
      lastEvidenceAt: newest(...records.map((record) => record.occurredAt || record.recordedAt)),
    }
  })
  const times = [...evidence.map((row) => row.occurredAt || row.recordedAt), ...auditEvents.map((row) => row.at)]
    .filter((time): time is string => typeof time === 'string' && Number.isFinite(Date.parse(time)))
    .sort((a, b) => Date.parse(a) - Date.parse(b))

  return {
    generatedAt: model.generatedAt,
    latestEvidenceAt: times.at(-1) ?? null,
    earliestEvidenceAt: times[0] ?? null,
    assets,
    score: combined.scoring.value,
    measured: combined.scoring.measured,
    controls: combined.controls,
    requirements: buildRequirements(combined.controls, evidence, inputs.now)
      .filter((row) => row.controlsTotal > 0 || row.evidenceCount > 0)
      .map((row) => ({
        ...row,
        status: row.status === 'compliant' && row.controlsMeasured < row.controlIds.length ? 'partial' : row.status,
        frameworkLabel: FRAMEWORK_BY_ID.get(row.frameworkId)?.name ?? row.frameworkId,
      })),
    violations: combined.violations,
    evidence,
    findings: evidence.filter((row) => row.kind === 'finding'),
    auditEvents,
    remediation: inputs.migrationJobs.filter((row) => ids.has(str(row.asset_id))).map((row) => ({
      id: str(row.id), assetId: str(row.asset_id), title: str(row.name) || str(row.job_type) || 'Migration job',
      status: str(row.status) || null, updatedAt: str(row.updated_at) || str(row.completed_at) || str(row.created_at) || null,
    })),
    unavailableSources: model.telemetry.absentSources,
    truncated: model.telemetry.truncated,
  }
}
