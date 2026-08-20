/**
 * PQC key readiness and the migration gate.
 *
 * ── Two rules this module exists to enforce ─────────────────────────────────
 *
 * 1. "Do not label an asset PQC Ready merely because it has a PQC-compatible
 *    algorithm available. Readiness must be evidence-driven." (section 14)
 *
 *    So a band's numerator counts keys whose OBSERVED material is post-quantum
 *    or hybrid — never keys that could be migrated, and never keys whose
 *    algorithm is simply unknown.
 *
 * 2. Not-applicable is not zero. (sections 2, 26)
 *
 *    An estate with no signature keys has no ML-DSA readiness — it does not
 *    have 0% ML-DSA readiness. `applicable: 0` and `percent: null` render as
 *    "Not applicable", which is why every band carries its own denominator.
 *    The predecessor divided by `Math.max(1, …)`, turning every empty band into
 *    a hard 0% and dragging the headline down with phantom failures.
 *
 * The gate implements the six states of section 15, and each decision carries
 * why / evidence / blockers / required actions.
 */

import type {
  GatePrecheck,
  GovernanceViolation,
  KeyPqcPosture,
  ManagedKey,
  MigrationGate,
  MigrationGateState,
  MigrationRequirement,
  PqcReadiness,
  PrecheckDecision,
  QkmsEvidenceRef,
  ReadinessBand,
} from './types'

const EMPTY_POSTURE_COUNTS: Record<KeyPqcPosture, number> = {
  'post-quantum': 0,
  hybrid: 0,
  'quantum-resistant-symmetric': 0,
  'weakened-symmetric': 0,
  'quantum-vulnerable': 0,
  deprecated: 0,
  unknown: 0,
}

const EMPTY_REQUIREMENT_COUNTS: Record<MigrationRequirement, number> = {
  none: 0,
  monitor: 0,
  recommended: 0,
  required: 0,
  unknown: 0,
}

/** A key counts as ready when its OBSERVED material is PQC or hybrid. */
function isReady(key: ManagedKey): boolean {
  return key.posture === 'post-quantum' || key.posture === 'hybrid'
}

function band(
  key: string,
  label: string,
  applicable: ManagedKey[],
  readyPredicate: (key: ManagedKey) => boolean,
  applicableDetail: string,
  notApplicableDetail: string,
): ReadinessBand {
  if (!applicable.length) {
    return { key, label, applicable: 0, ready: 0, percent: null, detail: notApplicableDetail }
  }
  const ready = applicable.filter(readyPredicate).length
  return {
    key,
    label,
    applicable: applicable.length,
    ready,
    percent: Math.round((ready / applicable.length) * 100),
    detail: `${ready} of ${applicable.length} ${applicableDetail}`,
  }
}

export function buildReadinessBands(keys: ManagedKey[]): ReadinessBand[] {
  const kem = keys.filter((row) => row.keyClass === 'key-establishment')
  const sig = keys.filter((row) => row.keyClass === 'signature' || row.keyClass === 'certificate')
  const sym = keys.filter((row) => row.keyClass === 'symmetric-encryption')
  const kdf = keys.filter((row) => row.keyClass === 'hash-kdf')
  const certs = keys.filter((row) => row.keyClass === 'certificate' || row.certificateIds.length > 0)
  /*
   * `certificate` is an asymmetric key class too — it is a signature key that
   * happens to be carried by a certificate. Omitting it made an estate of three
   * certificate keys report "No asymmetric keys were discovered", contradicting
   * the signature band directly above it on the same page.
   */
  const hybridCandidates = keys.filter((row) =>
    row.keyClass === 'key-establishment' || row.keyClass === 'signature' || row.keyClass === 'certificate')

  return [
    band(
      'ml-kem', 'ML-KEM key establishment', kem, isReady,
      'key-establishment keys use ML-KEM or a hybrid composite.',
      'No key-establishment keys were discovered, so ML-KEM readiness does not apply to this estate yet.',
    ),
    band(
      'ml-dsa', 'ML-DSA / SLH-DSA signatures', sig, isReady,
      'signature and certificate keys use ML-DSA, SLH-DSA or a hybrid composite.',
      'No signature or certificate keys were discovered, so signature readiness does not apply to this estate yet.',
    ),
    band(
      'symmetric', 'AES-256-GCM symmetric', sym,
      (key) => key.posture === 'quantum-resistant-symmetric',
      'symmetric keys are at 256-bit strength, which Grover leaves out of reach.',
      'No symmetric encryption keys were discovered, so symmetric readiness does not apply to this estate yet.',
    ),
    band(
      'hash-kdf', 'SHA3 / HKDF-SHA3', kdf,
      (key) => key.posture === 'quantum-resistant-symmetric',
      'derivation and integrity keys use a quantum-resistant hash.',
      'No derivation or integrity keys were discovered, so hash/KDF readiness does not apply to this estate yet.',
    ),
    band(
      'hybrid', 'Hybrid composite adoption', hybridCandidates,
      (key) => key.posture === 'hybrid',
      'asymmetric keys run a classical + post-quantum composite, which is the interoperable migration step.',
      'No asymmetric keys were discovered, so hybrid adoption does not apply to this estate yet.',
    ),
    band(
      'certificate', 'Certificate key migration', certs, isReady,
      'certificate-bearing keys use post-quantum or hybrid signature material.',
      'No certificate-bearing keys were discovered, so certificate migration does not apply to this estate yet.',
    ),
  ]
}

/* ------------------------------------------------------------------ */
/* Prechecks                                                           */
/* ------------------------------------------------------------------ */

function precheck(
  id: string,
  label: string,
  failing: ManagedKey[],
  decisionWhenFailing: Exclude<PrecheckDecision, 'pass' | 'not-evaluated'>,
  detailWhenFailing: string,
  detailWhenPassing: string,
  requiredAction: string,
  evaluated = true,
): GatePrecheck {
  if (!evaluated) {
    return { id, label, decision: 'not-evaluated', count: 0, detail: detailWhenPassing, requiredAction, keyIds: [] }
  }
  if (!failing.length) {
    return { id, label, decision: 'pass', count: 0, detail: detailWhenPassing, requiredAction: '', keyIds: [] }
  }
  return {
    id,
    label,
    decision: decisionWhenFailing,
    count: failing.length,
    detail: detailWhenFailing.replace('{n}', String(failing.length)),
    requiredAction,
    keyIds: failing.map((key) => key.id).slice(0, 200),
  }
}

export function buildPrechecks(
  keys: ManagedKey[],
  violations: GovernanceViolation[],
  auditRecordCount: number,
): GatePrecheck[] {
  const live = keys.filter((key) => key.lifecycle !== 'revoked' && key.lifecycle !== 'decommissioned' && key.lifecycle !== 'retired')

  const deprecated = live.filter((key) => key.posture === 'deprecated')
  const unowned = live.filter((key) => !key.owner)
  const unmanaged = live.filter((key) => key.custody === 'unmanaged' || key.custody === 'unknown')
  const unclassified = live.filter((key) => key.posture === 'unknown')
  const expired = live.filter((key) => key.lifecycle === 'expired')
  const overdue = live.filter((key) => key.rotation === 'overdue' || key.rotation === 'failed')
  const noRotationEvidence = live.filter((key) => key.rotation === 'unknown' || key.rotation === 'never-rotated')
  const criticalViolationKeys = new Set(violations.filter((row) => row.severity === 'critical').map((row) => row.keyId))
  const criticalOffenders = live.filter((key) => criticalViolationKeys.has(key.id))
  const migrationRequired = live.filter((key) => key.migrationRequirement === 'required')
  const signingGaps = migrationRequired.filter((key) => key.keyClass === 'signature' || key.keyClass === 'certificate')
  const kemGaps = migrationRequired.filter((key) => key.keyClass === 'key-establishment')

  return [
    precheck(
      'no-broken-crypto', 'No broken cryptography in service', deprecated, 'block',
      '{n} key(s) use an algorithm that is broken against classical attack.',
      'No key in service uses a classically broken algorithm.',
      'Replace the broken algorithms before any post-quantum migration begins — migrating a broken key preserves the break.',
    ),
    precheck(
      'ownership', 'Every key has an accountable owner', unowned, 'block',
      '{n} key(s) have no accountable owner, so no migration can be approved for them.',
      'Every key in service has an accountable owner.',
      'Assign owners on the Inventory page; ownership gates approval for every subsequent step.',
    ),
    precheck(
      'critical-governance', 'No critical governance violations', criticalOffenders, 'block',
      '{n} key(s) carry a critical governance violation.',
      'No key carries a critical governance violation.',
      'Clear the critical violations on the Governance page before migrating.',
    ),
    precheck(
      'custody', 'Key custody is established and approved', unmanaged, 'warn',
      '{n} key(s) are in unmanaged or unestablished custody.',
      'Every key in service has established, approved custody.',
      'Move keys into an HSM, managed KMS or vault, or record where they are held.',
    ),
    precheck(
      'classification', 'Every key is classified', unclassified, 'warn',
      "{n} key(s) could not be classified, so their migration requirement is unknown.",
      'Every key in service resolves to a known primitive.',
      'Classify the unknown keys — an unclassified key cannot be migrated, only guessed at.',
    ),
    precheck(
      'expiry', 'No expired key still in service', expired, 'warn',
      '{n} key(s) have expired but have not been retired.',
      'No expired key remains in service.',
      'Retire or replace the expired keys and confirm nothing still references them.',
    ),
    precheck(
      'rotation', 'Rotation is current', overdue, 'warn',
      '{n} key(s) are overdue for rotation or have a failed rotation work order.',
      'No key is overdue for rotation.',
      'Work the rotation queue down before migrating; a migration on top of an overdue key compounds both.',
    ),
    precheck(
      'rotation-evidence', 'Rotation history is evidenced', noRotationEvidence, 'warn',
      '{n} key(s) have no rotation history at all, so rollback capability is unproven.',
      'Every key has rotation history or an explicit rotation policy.',
      'Establish a rotation interval so a migration can be rolled back if validation fails.',
    ),
    precheck(
      'signature-plan', 'Signature migration path defined', signingGaps, 'warn',
      '{n} signature or certificate key(s) still require an ML-DSA / SLH-DSA migration.',
      'No signature key is awaiting a post-quantum migration path.',
      'Plan the ML-DSA-65 (or Ed25519 + ML-DSA-65 hybrid) migration for the listed keys.',
    ),
    precheck(
      'kem-plan', 'Key-establishment migration path defined', kemGaps, 'warn',
      '{n} key-establishment key(s) still require an ML-KEM migration.',
      'No key-establishment key is awaiting a post-quantum migration path.',
      'Plan the ML-KEM-768 (or X25519 + ML-KEM-768 hybrid) migration for the listed keys.',
    ),
    {
      id: 'audit-evidence',
      label: 'Audit evidence is available',
      decision: auditRecordCount > 0 ? 'pass' : keys.length ? 'warn' : 'not-evaluated',
      count: auditRecordCount,
      detail: auditRecordCount > 0
        ? `${auditRecordCount} audit record(s) are available to evidence key operations.`
        : 'No audit evidence has been recorded for key operations yet.',
      requiredAction: auditRecordCount > 0 ? '' : 'Perform key operations through QKMS so the migration carries an auditable trail.',
      keyIds: [],
    },
  ]
}

/* ------------------------------------------------------------------ */
/* The gate                                                            */
/* ------------------------------------------------------------------ */

/**
 * Decide the gate.
 *
 * State order matters and is deliberate:
 *   BLOCKED             a hard precondition fails — nothing else can proceed.
 *   MIGRATION_IN_PROGRESS  work is actually under way, evidenced by open jobs.
 *   VALIDATION_REQUIRED migration completed but its evidence is incomplete.
 *   MIGRATED            everything that needed migrating is migrated and proven.
 *   NOT_READY           no blockers, but prerequisites are still missing.
 *   READY               every precheck passes and there is something to migrate.
 */
export function buildMigrationGate(
  keys: ManagedKey[],
  prechecks: GatePrecheck[],
  context: {
    openMigrationJobs: number
    completedMigrationJobs: number
    openRotationJobs: number
    unvalidatedRotationJobs: number
    auditRecordCount: number
    evidence: QkmsEvidenceRef[]
    nowIso: string
  },
): MigrationGate {
  const evaluated = prechecks.filter((row) => row.decision !== 'not-evaluated')
  const blocking = evaluated.filter((row) => row.decision === 'block')
  const warning = evaluated.filter((row) => row.decision === 'warn')
  const passing = evaluated.filter((row) => row.decision === 'pass')
  const score = evaluated.length ? Math.round((passing.length / evaluated.length) * 100) : null

  const live = keys.filter((key) => key.lifecycle !== 'revoked' && key.lifecycle !== 'decommissioned' && key.lifecycle !== 'retired')
  const needsMigration = live.filter((key) => key.migrationRequirement === 'required' || key.migrationRequirement === 'recommended')
  const migrated = live.filter((key) => key.posture === 'post-quantum' || key.posture === 'hybrid')

  const blockers = blocking.map((row) => `${row.label}: ${row.detail}`)
  const requiredActions = [...blocking, ...warning]
    .map((row) => row.requiredAction)
    .filter(Boolean)

  let state: MigrationGateState
  let why: string

  if (!keys.length) {
    state = 'NOT_READY'
    why = 'No cryptographic keys have been discovered for this tenant, so there is nothing to gate. Run a scan, deploy an agent collector or connect a cloud account to build the key inventory.'
  } else if (blocking.length) {
    state = 'BLOCKED'
    why = `${blocking.length} hard precondition(s) fail. ${blocking[0].detail} A post-quantum migration executed over these conditions would carry the defect forward into the migrated estate.`
  } else if (context.openMigrationJobs > 0 || context.openRotationJobs > 0) {
    state = 'MIGRATION_IN_PROGRESS'
    why = `${context.openMigrationJobs} migration job(s) and ${context.openRotationJobs} rotation work order(s) are open against this key estate. The gate stays open while that work completes.`
  } else if (needsMigration.length === 0 && migrated.length > 0) {
    if (context.auditRecordCount === 0 || context.unvalidatedRotationJobs > 0) {
      state = 'VALIDATION_REQUIRED'
      why = context.unvalidatedRotationJobs > 0
        ? `Every key that required migration is now post-quantum or hybrid, but ${context.unvalidatedRotationJobs} completed work order(s) have no post-rotation validation evidence attached. Migration is not proven until it is validated.`
        : 'Every key that required migration is now post-quantum or hybrid, but no audit evidence has been recorded. Migration is not proven until it is evidenced.'
    } else {
      state = 'MIGRATED'
      why = `All ${migrated.length} key(s) requiring a post-quantum decision now use post-quantum or hybrid material, every precheck passes, and ${context.auditRecordCount} audit record(s) evidence the change.`
    }
  } else if (warning.length) {
    state = 'NOT_READY'
    why = `No hard blocker remains, but ${warning.length} prerequisite(s) are still outstanding — starting here would migrate keys whose ownership, custody or rotation posture is not yet provable.`
  } else {
    state = 'READY'
    why = needsMigration.length
      ? `Every precheck passes. ${needsMigration.length} key(s) are ready to migrate to post-quantum or hybrid material.`
      : 'Every precheck passes and no key currently requires migration.'
  }

  return {
    state,
    why,
    blockers,
    requiredActions: [...new Set(requiredActions)].slice(0, 8),
    evidence: context.evidence.slice(0, 8),
    prechecks,
    score,
    evaluatedAt: context.nowIso,
  }
}

/* ------------------------------------------------------------------ */
/* Assembly                                                            */
/* ------------------------------------------------------------------ */

export function buildReadiness(
  keys: ManagedKey[],
  prechecks: GatePrecheck[],
  gate: MigrationGate,
): PqcReadiness {
  const postureCounts = { ...EMPTY_POSTURE_COUNTS }
  const requirementCounts = { ...EMPTY_REQUIREMENT_COUNTS }
  for (const key of keys) {
    postureCounts[key.posture] += 1
    requirementCounts[key.migrationRequirement] += 1
  }

  /*
   * The headline denominator is keys that NEED a post-quantum decision — the
   * ones already post-quantum or hybrid, plus the ones that must migrate.
   * Symmetric and hash keys are excluded on purpose: including them inflates
   * readiness with material that was never at quantum risk, which is the same
   * error as publishing AES-256 as a vulnerability, run in reverse.
   */
  const decisionScope = keys.filter((key) =>
    key.posture === 'post-quantum'
    || key.posture === 'hybrid'
    || key.posture === 'quantum-vulnerable'
    || (key.posture === 'deprecated' && (key.keyClass === 'signature' || key.keyClass === 'certificate' || key.keyClass === 'key-establishment')))

  const ready = decisionScope.filter(isReady).length

  return {
    overall: decisionScope.length ? Math.round((ready / decisionScope.length) * 100) : null,
    bands: buildReadinessBands(keys),
    postureCounts,
    requirementCounts,
    gate: { ...gate, prechecks },
  }
}
