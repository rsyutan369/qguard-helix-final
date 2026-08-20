/**
 * Enterprise Governance, Compliance, Audit & Regulatory engine.
 *
 * One model behind four dashboards — see `intelligence.ts` for the composer and
 * `types.ts` for the vocabulary. Everything here is isomorphic and free of
 * server dependencies, so the same code runs in the API router and in the
 * offline reconciliation check (`tools/governance-check.ts`).
 */

export * from './types'
export {
  CONTROL_CATALOG,
  CONTROL_BY_ID,
  FRAMEWORK_CATALOG,
  FRAMEWORK_BY_ID,
  REQUIREMENT_CATALOG,
  REQUIREMENT_BY_ID,
  REQUIREMENTS_BY_CONTROL,
  FRAMEWORKS_BY_CONTROL,
  CATALOG_ORPHANS,
  resolveFrameworkId,
} from './catalog'
export {
  ALGORITHM_FAMILY_LABEL,
  algorithmFamily,
  assetIsInternetFacing,
  buildSubjects,
  clampPercent,
  daysBetween,
  isoOrNull,
  ms,
  newest,
  num,
  recordOf,
  str,
  type CryptoSubject,
  type Row,
  type SubjectSet,
} from './subjects'
export { ASSURANCE, assuranceFor, canonicalize, contentDigest, buildIntegrity } from './integrity'
export { POLICY_CATALOG, POLICY_BY_ID, allViolationsFor, evaluatePolicies, severityOrder, tlsVersionNumber, type PolicyEvaluationContext } from './policy'
export { AGING_DAYS, FRESH_DAYS, RETENTION_DAYS, buildEvidence, freshnessOf, type EvidenceInputs } from './evidence'
export { buildAuditEvents, type AuditInputs } from './audit'
export { evaluateControls, failingSubjectsFor, type CanonicalSnapshot, type ControlEvaluationInputs } from './controls'
export { buildGovernanceIntelligence, type GovernanceInputs, type PortfolioAsset } from './intelligence'
