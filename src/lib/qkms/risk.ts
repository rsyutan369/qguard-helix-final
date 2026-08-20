/**
 * THE key risk model — one weighted, explainable score.
 *
 * ── Why there is exactly one ────────────────────────────────────────────────
 * The predecessor ran two. The backend published
 *
 *     riskScore = clamp(100 - trustScore + (exportable ? 10 : 0) + (nearExpiry ? 8 : 0))
 *
 * which Overview and Inventory rendered, while the Lifecycle, Rotation and Risk
 * Analysis pages called a *different* seven-factor model in the browser
 * (`keyRiskFactors()`), on the same key, in the same session. A key could read
 * 62 on Inventory and 81 on Risk Analysis, and the Risk Analysis KPI strip
 * ("Critical-risk keys") could not be reconciled against the inventory table
 * next to it.
 *
 * This module is now the only place a key risk score is produced. The API ships
 * the score AND its decomposition; the UI renders, and never recomputes.
 *
 * ── What a score has to carry (brief section 16) ────────────────────────────
 * "Every risk score must be explainable. Do not simply display a number.
 *  Show: Risk Score → Contributing Factors → Evidence → Recommended Action."
 *
 * So every factor returns its own sub-score, its weight, its actual
 * contribution to the headline, a sentence explaining it, and whether the input
 * it needed was measured at all. `confidence` reports how much of the score
 * rests on measured inputs, so a 30/100 built entirely from absent evidence is
 * never mistaken for a clean key.
 */

import type {
  CustodyClass,
  GovernanceViolation,
  KeyClass,
  KeyPqcPosture,
  KeyRiskAssessment,
  LifecycleState,
  MigrationRequirement,
  QkmsEvidenceRef,
  RiskFactor,
  RiskLevel,
  RotationState,
} from './types'
import { RISK_WEIGHTS } from './types'
import { violationSeverityWeight } from './governance'

export interface RiskInput {
  algorithm: string
  family: string
  keyClass: KeyClass
  posture: KeyPqcPosture
  migrationRequirement: MigrationRequirement
  deprecated: boolean
  securityBits: number | null
  lifecycle: LifecycleState
  lifecycleReason: string
  rotation: RotationState
  rotationReason: string
  ageDays: number | null
  daysToExpiry: number | null
  owner: string | null
  environment: string
  custody: CustodyClass
  backend: string
  hsmBacked: boolean
  exportable: boolean | null
  runtimeUsage: number | null
  blastRadius: number
  certificateCount: number
  violations: GovernanceViolation[]
  evidence: QkmsEvidenceRef[]
}

const WEIGHT = Object.fromEntries(RISK_WEIGHTS.map((row) => [row.key, row])) as Record<
  RiskFactor['key'],
  { key: RiskFactor['key']; label: string; weight: number }
>

function clamp(value: number): number {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, Math.round(value)))
}

/* ------------------------------------------------------------------ */
/* Factors                                                             */
/* ------------------------------------------------------------------ */

function algorithmFactor(input: RiskInput): RiskFactor {
  const meta = WEIGHT.algorithm
  let score: number
  let reason: string
  let measured = true

  if (input.posture === 'unknown') {
    // Unknown is a real risk — an unclassifiable key cannot be governed — but
    // it is scored below a *known* weakness and flagged unmeasured so it
    // depresses confidence rather than masquerading as a finding.
    score = 45
    reason = 'The algorithm could not be resolved to a known primitive, so its strength cannot be asserted.'
    measured = false
  } else if (input.deprecated) {
    score = 100
    reason = `${input.family} is broken against classical attack and must not protect data.`
  } else if (input.posture === 'weakened-symmetric') {
    score = 40
    reason = `${input.family} is sound today but its effective strength${input.securityBits ? ` (~${Math.round(input.securityBits / 2)} bits under Grover)` : ''} is below the 256-bit target for long-lived data.`
  } else if (input.posture === 'quantum-vulnerable') {
    score = 55
    reason = `${input.family} is cryptographically sound today; the risk it carries is quantum, not classical.`
  } else if (input.posture === 'hybrid') {
    score = 12
    reason = `${input.family} pairs a classical and a post-quantum primitive, so neither half alone breaks the key.`
  } else {
    score = 6
    reason = `${input.family} is a current NIST-approved primitive with no known weakness.`
  }

  return { ...meta, score, contribution: (score * meta.weight) / 100, reason, measured }
}

function quantumFactor(input: RiskInput): RiskFactor {
  const meta = WEIGHT.quantum
  let score: number
  let reason: string
  let measured = true

  switch (input.posture) {
    case 'post-quantum':
      score = 4
      reason = 'Post-quantum key material. No harvest-now-decrypt-later exposure.'
      break
    case 'hybrid':
      score = 18
      reason = 'Hybrid key material. The post-quantum half protects the shared secret; the classical half still has to be retired eventually.'
      break
    case 'quantum-resistant-symmetric':
      score = 8
      reason = 'Symmetric material at adequate size. Grover halves its strength, which leaves it out of reach — this is not a migration candidate.'
      break
    case 'weakened-symmetric':
      score = 35
      reason = 'Symmetric material below the 256-bit target. Weakened by Grover, not broken by Shor.'
      break
    case 'quantum-vulnerable':
      score = input.keyClass === 'key-establishment' ? 95 : 85
      reason = input.keyClass === 'key-establishment'
        ? 'Quantum-vulnerable key establishment. Traffic captured today can be decrypted once a CRQC exists — the harvest-now-decrypt-later case.'
        : 'Quantum-vulnerable signature material. Forgery becomes possible once a CRQC exists.'
      break
    case 'deprecated':
      score = 100
      reason = 'Already broken; quantum exposure is moot until the algorithm is replaced.'
      break
    default:
      score = 50
      reason = 'Quantum exposure cannot be determined because the algorithm is unknown.'
      measured = false
  }

  return { ...meta, score, contribution: (score * meta.weight) / 100, reason, measured }
}

function lifecycleFactor(input: RiskInput): RiskFactor {
  const meta = WEIGHT.lifecycle
  let score: number
  let reason: string
  let measured = true

  if (input.lifecycle === 'decommissioned' || input.lifecycle === 'retired') {
    score = 2
    reason = 'The key is out of service, so its lifecycle carries no live risk.'
  } else if (input.lifecycle === 'revoked') {
    score = 10
    reason = 'The key is revoked. Residual risk is limited to anything still trusting it.'
  } else if (input.lifecycle === 'expired') {
    const overdue = input.daysToExpiry === null ? null : Math.abs(input.daysToExpiry)
    score = input.runtimeUsage && input.runtimeUsage > 0 ? 100 : 80
    reason = input.runtimeUsage && input.runtimeUsage > 0
      ? `Expired${overdue !== null ? ` ${overdue} day(s) ago` : ''} yet still carrying runtime traffic.`
      : `Expired${overdue !== null ? ` ${overdue} day(s) ago` : ''} and not yet retired.`
  } else if (input.daysToExpiry !== null && input.daysToExpiry <= 7) {
    score = 75
    reason = `Expires in ${input.daysToExpiry} day(s); replacement has to be in flight now.`
  } else if (input.daysToExpiry !== null && input.daysToExpiry <= 45) {
    score = 50
    reason = `Expires in ${input.daysToExpiry} day(s), inside the replacement window.`
  } else if (input.lifecycle === 'suspended') {
    score = 40
    reason = 'The key is suspended pending a governance decision.'
  } else if (input.lifecycle === 'discovered') {
    score = 55
    reason = 'Discovered by scan or telemetry with no lifecycle metadata — it is outside lifecycle governance entirely.'
    measured = false
  } else if (input.ageDays !== null && input.ageDays > 730) {
    score = 45
    reason = `The key is ${input.ageDays} days old, beyond the two-year long-lived threshold.`
  } else if (input.ageDays === null) {
    score = 35
    reason = 'No creation date was observed, so key age cannot be assessed.'
    measured = false
  } else {
    score = 10
    reason = `Lifecycle is current: ${input.ageDays} day(s) old${input.daysToExpiry !== null ? `, ${input.daysToExpiry} day(s) to expiry` : ', no expiry recorded'}.`
  }

  return { ...meta, score, contribution: (score * meta.weight) / 100, reason, measured }
}

function rotationFactor(input: RiskInput): RiskFactor {
  const meta = WEIGHT.rotation
  let score: number
  let measured = true

  switch (input.rotation) {
    case 'healthy': score = 8; break
    case 'not-applicable': score = 5; break
    case 'due': score = 45; break
    case 'in-progress': score = 30; break
    case 'never-rotated': score = 60; break
    case 'overdue': score = 88; break
    case 'failed': score = 92; break
    case 'blocked': score = 80; break
    default:
      score = 50
      measured = false
      break
  }

  return {
    ...meta,
    score,
    contribution: (score * meta.weight) / 100,
    reason: input.rotationReason,
    measured,
  }
}

function ownershipFactor(input: RiskInput): RiskFactor {
  const meta = WEIGHT.ownership
  const governance = input.violations.filter((row) =>
    row.rule === 'missing-owner' || row.rule === 'algorithm-not-allowed' || row.rule === 'blocked-algorithm' || row.rule === 'pqc-migration-required')
  const worst = governance.reduce((max, row) => Math.max(max, violationSeverityWeight(row.severity)), 0)

  let score: number
  let reason: string
  let measured = true

  if (!input.owner) {
    score = Math.max(85, worst)
    reason = 'No accountable owner is recorded. Rotation, approval and migration all require an owner, so every other control is blocked behind this one.'
  } else if (governance.length) {
    score = Math.max(40, worst)
    reason = `Owned by ${input.owner}, with ${governance.length} open governance violation(s) against policy.`
  } else if (input.violations.length) {
    score = 30
    reason = `Owned by ${input.owner}, with ${input.violations.length} open violation(s) in other control areas.`
  } else {
    score = 8
    reason = `Owned by ${input.owner} with no open governance violations.`
  }

  if (input.environment === 'unknown') {
    score = Math.max(score, 35)
    reason += ' The environment could not be determined, so scope-based policy cannot be applied.'
    measured = false
  }

  return { ...meta, score, contribution: (score * meta.weight) / 100, reason, measured }
}

function custodyFactor(input: RiskInput): RiskFactor {
  const meta = WEIGHT.custody
  const production = input.environment === 'production'
  let score: number
  let reason: string
  let measured = true

  switch (input.custody) {
    case 'hsm':
      score = 4
      reason = `Held in ${input.backend}: hardware custody, material non-exportable by construction.`
      break
    case 'cloud-kms':
      score = 12
      reason = `Held in ${input.backend}: managed key service with provider-enforced custody.`
      break
    case 'vault':
    case 'platform-vault':
      score = 20
      reason = `Held in ${input.backend}: managed secrets custody with access control and audit.`
      break
    case 'software-keystore':
      score = production ? 65 : 45
      reason = `Held in ${input.backend}: software custody${production ? ' for a production key, where an approved backend is required' : ''}.`
      break
    case 'unmanaged':
      score = production ? 95 : 75
      reason = `Held in ${input.backend}: unmanaged storage. Key material in a file, config or source location has no access control and no audit trail.`
      break
    default:
      score = 60
      reason = 'Custody could not be established from any source, so the key cannot be said to be protected at all.'
      measured = false
      break
  }

  if (input.exportable === true) {
    score = Math.max(score, production ? 98 : 80)
    reason += ' The key is additionally marked exportable, so the material can leave its backend.'
  }

  return { ...meta, score, contribution: (score * meta.weight) / 100, reason, measured }
}

function exposureFactor(input: RiskInput): RiskFactor {
  const meta = WEIGHT.exposure
  const production = input.environment === 'production'
  let measured = true

  if (input.runtimeUsage === null && input.blastRadius === 0 && input.certificateCount === 0) {
    return {
      ...meta,
      score: 30,
      contribution: (30 * meta.weight) / 100,
      reason: 'No runtime usage, certificate or dependency evidence was observed, so the blast radius of this key is unknown.',
      measured: false,
    }
  }

  // Blast radius scales with what actually breaks: dependent assets, certs, and
  // observed traffic. Production multiplies the consequence, not the likelihood.
  const dependency = Math.min(60, input.blastRadius * 8 + input.certificateCount * 10)
  const traffic = input.runtimeUsage === null
    ? 0
    : input.runtimeUsage > 1000 ? 30 : input.runtimeUsage > 100 ? 20 : input.runtimeUsage > 0 ? 10 : 0
  if (input.runtimeUsage === null) measured = false

  const score = clamp(dependency + traffic + (production ? 20 : 0))
  const parts: string[] = []
  if (input.blastRadius) parts.push(`${input.blastRadius} dependent asset(s)`)
  if (input.certificateCount) parts.push(`${input.certificateCount} certificate(s)`)
  if (input.runtimeUsage !== null) parts.push(`${input.runtimeUsage} observed runtime operation(s)`)
  if (production) parts.push('production environment')

  return {
    ...meta,
    score,
    contribution: (score * meta.weight) / 100,
    reason: parts.length ? `Blast radius: ${parts.join(', ')}.` : 'No dependencies were observed for this key.',
    measured,
  }
}

/* ------------------------------------------------------------------ */
/* Aggregation                                                         */
/* ------------------------------------------------------------------ */

export function riskLevelOf(score: number): RiskLevel {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 35) return 'medium'
  if (score >= 15) return 'low'
  return 'none'
}

/**
 * The recommended action.
 *
 * Ordered by what has to happen FIRST, not by which factor scored highest: a
 * key with no owner cannot be rotated or migrated, so ownership precedes both
 * even when the algorithm factor dominates the score.
 */
function recommendedActionFor(input: RiskInput, factors: RiskFactor[]): string {
  if (input.deprecated) {
    return `Replace ${input.family} immediately — it is broken against classical attack — and rotate every dependent certificate and service.`
  }
  if (input.lifecycle === 'expired' && (input.runtimeUsage ?? 0) > 0) {
    return 'Replace this expired key now: runtime telemetry shows services are still using it.'
  }
  if (input.exportable === true && input.environment === 'production') {
    return 'Disable export on this production key, or re-issue it as non-exportable inside its backend and retire the current material.'
  }
  if (!input.owner) {
    return 'Assign an accountable owner. Rotation, approval and PQC migration are all blocked until this key has one.'
  }
  if (input.custody === 'unmanaged') {
    return `Move this key out of ${input.backend} into an HSM, managed KMS or vault, then retire the unmanaged copy.`
  }
  if (input.rotation === 'failed') {
    return 'Investigate the failed rotation work order, roll back if the new version is not in service, and re-run the rotation.'
  }
  if (input.rotation === 'overdue') {
    return 'Raise and execute a rotation work order, then attach post-rotation validation evidence to close it.'
  }
  if (input.migrationRequirement === 'required') {
    return input.keyClass === 'signature' || input.keyClass === 'certificate'
      ? 'Plan an ML-DSA-65 signature migration (or Ed25519 + ML-DSA-65 hybrid) and re-issue dependent certificates.'
      : 'Plan an ML-KEM-768 key-establishment migration (or X25519 + ML-KEM-768 hybrid while classical interoperability is required).'
  }
  if (input.custody === 'unknown') {
    return 'Record where this key is stored so custody can be governed and evidenced.'
  }
  if (input.posture === 'unknown') {
    return 'Classify this key: its algorithm could not be resolved, so no posture, policy or migration decision can be applied to it.'
  }
  if (input.rotation === 'never-rotated' || input.rotation === 'due') {
    return 'Schedule the next rotation and record the interval so the key stays inside its rotation SLA.'
  }
  const worst = [...factors].sort((a, b) => b.contribution - a.contribution)[0]
  if (worst && worst.score >= 35) {
    return `Reduce ${worst.label.toLowerCase()}: ${worst.reason}`
  }
  return 'No remediation is outstanding. Maintain rotation and custody evidence so the posture stays provable.'
}

/**
 * Assess one key. The only producer of `riskScore` in the platform.
 */
export function assessKeyRisk(input: RiskInput): KeyRiskAssessment {
  const factors: RiskFactor[] = [
    algorithmFactor(input),
    quantumFactor(input),
    lifecycleFactor(input),
    rotationFactor(input),
    ownershipFactor(input),
    custodyFactor(input),
    exposureFactor(input),
  ]

  let score = clamp(factors.reduce((sum, factor) => sum + factor.contribution, 0))

  /*
   * Governance escalation (brief section 17).
   *
   * A critical violation on the Governance page must be visible in the key's
   * risk score, or the two pages tell different stories about the same key.
   * It raises a FLOOR rather than adding points, so the score stays bounded and
   * a single violation cannot double-count a factor that already caught it.
   */
  const worstViolation = input.violations.reduce((max, row) => Math.max(max, violationSeverityWeight(row.severity)), 0)
  if (worstViolation >= 100) score = Math.max(score, 80)
  else if (worstViolation >= 70) score = Math.max(score, 60)
  else if (worstViolation >= 40) score = Math.max(score, 35)

  const measuredWeight = factors.filter((factor) => factor.measured).reduce((sum, factor) => sum + factor.weight, 0)

  const drivers = [...factors]
    .filter((factor) => factor.score >= 35)
    .sort((a, b) => b.contribution - a.contribution)
    .slice(0, 4)
    .map((factor) => `${factor.label}: ${factor.reason}`)

  if (!drivers.length && input.violations.length) {
    drivers.push(`Governance: ${input.violations[0].detail}`)
  }

  return {
    score,
    level: riskLevelOf(score),
    factors: factors.map((factor) => ({ ...factor, contribution: Math.round(factor.contribution * 10) / 10 })),
    drivers: drivers.length ? drivers : ['No factor scored above the reporting threshold.'],
    recommendedAction: recommendedActionFor(input, factors),
    confidence: clamp(measuredWeight),
    evidence: [
      ...input.evidence.slice(0, 4),
      ...input.violations.slice(0, 3).flatMap((row) => row.evidence.slice(0, 1)),
    ].slice(0, 6),
  }
}
