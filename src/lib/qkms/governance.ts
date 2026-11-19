/**
 * Governance — custody classification, policy evaluation, entropy posture.
 *
 * ── Why policy evaluation had to be rebuilt ─────────────────────────────────
 * The predecessor computed the headline "Policy Violations" like this:
 *
 *     const policyViolations = keyTextRows.filter((row) =>
 *       /policy|violation|weak|expired|rotation|orphan|exposure|leak|high|critical|fail/i
 *         .test(JSON.stringify(row))).length
 *
 * — a regex over the serialised JSON of exposures, scanner alerts, security
 * events, vulnerabilities and scan results. Any row whose JSON contained the
 * word "high" was a policy violation. The number could not be drilled into, did
 * not correspond to any policy, and moved when unrelated scanner rows arrived.
 *
 * A governance violation is now what the name says: one KEY failing one RULE of
 * one POLICY, carrying the evidence that proves it. It is drillable end to end,
 * and Risk Analysis consumes the same records, which is what makes brief
 * section 17 hold — a custody violation on Governance necessarily raises the
 * custody factor of that key's risk score.
 */

import type {
  CustodyClass,
  EntropyPosture,
  EntropyStatus,
  GovernanceViolation,
  ManagedKey,
  PolicyRule,
  QkmsEvidenceRef,
  QkmsPolicy,
  Severity,
  StorageBackendPosture,
} from './types'
import { POLICY_RULE_LABEL } from './types'
import { dateMs, LONG_LIVED_DAYS, ONE_DAY_MS } from './lifecycle'

/* ------------------------------------------------------------------ */
/* Custody                                                             */
/* ------------------------------------------------------------------ */

/**
 * Classify the backend holding a key.
 *
 * Ordered most-specific first: "AWS CloudHSM" must resolve to `hsm`, not to
 * `cloud-kms` because it contains "AWS".
 */
const CUSTODY_PATTERNS: Array<[RegExp, CustodyClass, string]> = [
  [/cloudhsm|cloud hsm|yubihsm|luna|thales|entrust nshield|\bhsm\b|hardware security module/i, 'hsm', 'Hardware security module'],
  [/softhsm/i, 'software-keystore', 'SoftHSM (software-emulated HSM)'],
  [/azure key vault|key vault|aws kms|google cloud kms|cloud kms|\bkms\b/i, 'cloud-kms', 'Managed cloud key management service'],
  [/hashicorp|hashicorp vault|\bvault\b/i, 'vault', 'Secrets vault'],
  [/quantum vault|qguard vault|platform vault/i, 'platform-vault', 'QGuard platform vault'],
  [/keystore|keychain|jks|pkcs12|pem file|filesystem|local disk|config|environment variable|source code|\.env/i, 'unmanaged', 'Unmanaged file, config or source location'],
  [/application key store|application keystore|app store|local encrypted software vault|software/i, 'software-keystore', 'Application-managed software keystore'],
]

export interface CustodyVerdict {
  custody: CustodyClass
  backend: string
  protectionLevel: string
  hsmBacked: boolean
  /** true when custody could not be established from any source. */
  unknown: boolean
}

export function classifyCustody(declaredBackend: string, hints = ''): CustodyVerdict {
  const declared = String(declaredBackend || '').trim()
  const text = `${declared} ${hints}`.trim()

  if (!text) {
    return {
      custody: 'unknown',
      backend: 'Unknown',
      protectionLevel: 'Not established',
      hsmBacked: false,
      unknown: true,
    }
  }

  for (const [pattern, custody, protectionLevel] of CUSTODY_PATTERNS) {
    if (pattern.test(text)) {
      return {
        custody,
        backend: declared || protectionLevel,
        protectionLevel,
        hsmBacked: custody === 'hsm',
        unknown: false,
      }
    }
  }

  /*
   * An unrecognised string is NOT a backend name.
   *
   * Echoing `declared` back as the backend meant any text that reached this
   * field became a storage location in the custody chart. On a live estate that
   * filled "Keys by backend" with entries like "Detection Rule CERT-002" and
   * "TLS Handshake — https://www.cloudflare.com/" — finding titles rendered as
   * places where key material lives. A string is kept only when it actually
   * looks like a storage location; otherwise custody is honestly Unknown.
   */
  const looksLikeLocation = /^[a-z]+:\/\//i.test(declared)
    || /[/\\]/.test(declared)
    || /\.(pem|jks|p12|pfx|key|keystore)$/i.test(declared)
    || /^[\w .-]{1,60}$/.test(declared) && !/[:—]/.test(declared) && declared.split(/\s+/).length <= 5

  return {
    custody: 'unknown',
    backend: looksLikeLocation && declared ? declared : 'Unknown',
    protectionLevel: 'Not established',
    hsmBacked: false,
    unknown: true,
  }
}

/** Custody classes that satisfy an "approved backend" requirement. */
export const APPROVED_CUSTODY: CustodyClass[] = ['hsm', 'cloud-kms', 'vault', 'platform-vault']

export function isApprovedCustody(custody: CustodyClass): boolean {
  return APPROVED_CUSTODY.includes(custody)
}

/* ------------------------------------------------------------------ */
/* Baseline policies                                                   */
/* ------------------------------------------------------------------ */

/**
 * Policies QKMS ships with.
 *
 * They are marked `origin: 'baseline'` and are visibly distinguishable in the
 * UI from policies the tenant authored, so nobody mistakes a platform default
 * for their own governance decision. A tenant policy of the same name
 * supersedes the baseline.
 */
export function baselinePolicies(): QkmsPolicy[] {
  const shared = {
    origin: 'baseline' as const,
    enabled: true,
    keysInScope: 0,
    violations: 0,
    compliance: null as number | null,
    evaluation: 'no-keys-in-scope' as const,
    updatedAt: null,
  }

  return [
    {
      ...shared,
      id: 'baseline-no-broken-crypto',
      name: 'No broken cryptography in service',
      description: 'DES, 3DES, RC4, MD5, SHA-1 and RSA below 2048 bits must not protect any tenant data.',
      severity: 'critical',
      environmentScope: 'all',
      allowedAlgorithms: [],
      blockedAlgorithms: ['DES', '3DES', 'RC4', 'MD5', 'SHA-1', 'RSA-1024'],
      maxKeyAgeDays: null,
      rotationIntervalDays: null,
      requireOwner: false,
      requireHsm: false,
      allowExport: true,
      requirePqc: false,
      owner: 'QGuard baseline',
    },
    {
      ...shared,
      id: 'baseline-owner-accountability',
      name: 'Every key has an accountable owner',
      description: 'A key with no owner cannot be rotated, approved or migrated. Ownership is the precondition for every other control.',
      severity: 'high',
      environmentScope: 'all',
      allowedAlgorithms: [],
      blockedAlgorithms: [],
      maxKeyAgeDays: null,
      rotationIntervalDays: null,
      requireOwner: true,
      requireHsm: false,
      allowExport: true,
      requirePqc: false,
      owner: 'QGuard baseline',
    },
    {
      ...shared,
      id: 'baseline-production-custody',
      name: 'Production keys held in an approved backend',
      description: 'Production key material must reside in an HSM, a managed KMS or a vault — never in a file, a config or application memory alone.',
      severity: 'high',
      environmentScope: 'production',
      allowedAlgorithms: [],
      blockedAlgorithms: [],
      maxKeyAgeDays: null,
      rotationIntervalDays: null,
      requireOwner: false,
      requireHsm: false,
      allowExport: false,
      requirePqc: false,
      owner: 'QGuard baseline',
    },
    {
      ...shared,
      id: 'baseline-rotation-sla',
      name: 'Rotation within a 365-day interval',
      description: 'Key material in service must be rotated at least annually, and never left past its expiry.',
      severity: 'medium',
      environmentScope: 'all',
      allowedAlgorithms: [],
      blockedAlgorithms: [],
      maxKeyAgeDays: LONG_LIVED_DAYS,
      rotationIntervalDays: 365,
      requireOwner: false,
      requireHsm: false,
      allowExport: true,
      requirePqc: false,
      owner: 'QGuard baseline',
    },
    {
      ...shared,
      id: 'baseline-pqc-migration',
      name: 'Quantum-vulnerable key material carries a migration path',
      description: 'RSA, ECDSA, ECDH, Ed25519 and X25519 key material must be scheduled for ML-KEM / ML-DSA or a hybrid composite.',
      severity: 'high',
      environmentScope: 'all',
      allowedAlgorithms: [],
      blockedAlgorithms: [],
      maxKeyAgeDays: null,
      rotationIntervalDays: null,
      requireOwner: false,
      requireHsm: false,
      allowExport: true,
      requirePqc: true,
      owner: 'QGuard baseline',
    },
  ]
}

/* ------------------------------------------------------------------ */
/* Evaluation                                                          */
/* ------------------------------------------------------------------ */

/** Whether a policy's scope covers a key — the same rule evaluation uses. */
export function policyCoversKey(policy: Pick<QkmsPolicy, 'environmentScope'>, key: Pick<ManagedKey, 'environment'>): boolean {
  return inScope(policy as QkmsPolicy, key as ManagedKey)
}

export function needsPolicyEvidence(policy: QkmsPolicy, key: ManagedKey): boolean {
  return (policy.environmentScope !== 'all' && key.environment === 'unknown')
    || ((policy.allowedAlgorithms.length > 0 || policy.blockedAlgorithms.length > 0) && key.posture === 'unknown')
    || (!policy.allowExport && key.exportable === null)
    || (policy.requireHsm && key.hsmBacked) // only declared custody is available today
    || (policy.maxKeyAgeDays !== null && key.ageDays === null)
    || (policy.rotationIntervalDays !== null && key.rotation !== 'not-applicable' && !(key.lastRotatedAt || key.activatedAt || key.createdAt))
    || (policy.requirePqc && (key.posture === 'unknown' || key.postureEvidence === 'declared'))
}

function inScope(policy: QkmsPolicy, key: ManagedKey): boolean {
  const scope = String(policy.environmentScope || 'all').toLowerCase()
  if (!scope || scope === 'all') return true
  return String(key.environment || '').toLowerCase() === scope
}

function algorithmMatches(list: string[], key: ManagedKey): boolean {
  if (!list.length) return false
  const algorithm = key.algorithm.toUpperCase().replace(/[\s_]/g, '-')
  const family = key.family.toUpperCase().replace(/[\s_]/g, '-')
  return list.some((entry) => {
    const needle = String(entry || '').toUpperCase().replace(/[\s_]/g, '-')
    if (!needle) return false
    // Whole-token comparison: `DSA` in a blocklist must not match `ML-DSA-65`.
    // This is the same trap that made every PQC signature key "weak".
    const boundary = new RegExp(`^${needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(-|$)`)
    return algorithm === needle || family === needle || boundary.test(algorithm) || boundary.test(family)
  })
}

function violation(
  rule: PolicyRule,
  policy: QkmsPolicy,
  key: ManagedKey,
  severity: Severity,
  detail: string,
  remediation: string,
  evidence: QkmsEvidenceRef[],
  now: string,
): GovernanceViolation {
  return {
    id: `viol:${policy.id}:${rule}:${key.id}`,
    rule,
    policyId: policy.id,
    policyName: policy.name,
    keyId: key.id,
    keyLabel: key.label,
    severity,
    detail,
    remediation,
    detectedAt: now,
    evidence,
  }
}

/**
 * Evaluate every in-scope key against every enabled policy.
 *
 * Returns the violations plus policies annotated with their real scope and
 * compliance, so the Governance page can state "12 of 40 production keys
 * violate this policy" rather than an unanchored percentage.
 */
export function evaluateGovernance(
  keys: ManagedKey[],
  policies: QkmsPolicy[],
  nowIso: string,
): { violations: GovernanceViolation[]; policies: QkmsPolicy[] } {
  const violations: GovernanceViolation[] = []
  const annotated: QkmsPolicy[] = []

  for (const policy of policies) {
    if (!policy.enabled) {
      // A disabled policy evaluated nothing; reporting it 100% compliant read as
      // a clean bill of health for a control that was not running.
      annotated.push({ ...policy, keysInScope: 0, violations: 0, compliance: null, evaluation: 'disabled' })
      continue
    }

    const scoped = keys.filter((key) => inScope(policy, key)
      && !['revoked', 'decommissioned', 'retired'].includes(key.lifecycle))
    const offenders = new Set<string>()

    for (const key of scoped) {
      // Terminal keys are out of scope for operational rules: revoking a key is
      // the remediation, so continuing to bill it as a violation would keep the
      // count permanently inflated after the fix.
      const terminal = key.lifecycle === 'revoked' || key.lifecycle === 'decommissioned' || key.lifecycle === 'retired'
      const keyEvidence = key.evidence.slice(0, 3)

      if (policy.blockedAlgorithms.length && algorithmMatches(policy.blockedAlgorithms, key) && !terminal) {
        offenders.add(key.id)
        violations.push(violation(
          'blocked-algorithm', policy, key, policy.severity === 'info' ? 'high' : policy.severity,
          `${key.algorithm} is on this policy's blocked list.`,
          `Replace ${key.algorithm} with an approved algorithm and rotate every dependent asset.`,
          keyEvidence, nowIso,
        ))
      } else if (policy.allowedAlgorithms.length && !algorithmMatches(policy.allowedAlgorithms, key) && !terminal && key.posture !== 'unknown') {
        offenders.add(key.id)
        violations.push(violation(
          'algorithm-not-allowed', policy, key, 'medium',
          `${key.algorithm} is not on this policy's approved list.`,
          `Move this key to one of: ${policy.allowedAlgorithms.slice(0, 4).join(', ')}.`,
          keyEvidence, nowIso,
        ))
      }

      if (policy.requireOwner && !key.owner && !terminal) {
        offenders.add(key.id)
        violations.push(violation(
          'missing-owner', policy, key, 'high',
          'No accountable owner is recorded for this key.',
          'Assign an owning team so rotation and migration can be approved.',
          keyEvidence, nowIso,
        ))
      }

      if (policy.requireHsm && !key.hsmBacked && !terminal) {
        offenders.add(key.id)
        violations.push(violation(
          'hsm-required', policy, key, 'high',
          `Custody is ${key.backend}, but this policy requires HSM protection.`,
          'Move the key into an HSM, or re-issue it inside the HSM and retire the current material.',
          keyEvidence, nowIso,
        ))
      }

      if (policy.id === 'baseline-production-custody' && !isApprovedCustody(key.custody) && !terminal) {
        offenders.add(key.id)
        violations.push(violation(
          'unapproved-custody', policy, key,
          key.custody === 'unknown' ? 'medium' : 'high',
          key.custody === 'unknown'
            ? 'Custody for this key could not be established from any source.'
            : `The key is held in ${key.backend}, which is not an approved backend for production.`,
          key.custody === 'unknown'
            ? 'Record the storage backend for this key so custody can be governed.'
            : 'Re-issue the key inside an HSM, managed KMS or vault and retire the current copy.',
          keyEvidence, nowIso,
        ))
      }

      if (!policy.allowExport && key.exportable === true && !terminal) {
        offenders.add(key.id)
        violations.push(violation(
          'export-not-allowed', policy, key, 'critical',
          'The key is marked exportable where this policy prohibits export.',
          'Disable export on the key, or replace it with a non-exportable key in the same backend.',
          keyEvidence, nowIso,
        ))
      }

      if (policy.maxKeyAgeDays !== null && key.ageDays !== null && key.ageDays > policy.maxKeyAgeDays && !terminal) {
        offenders.add(key.id)
        violations.push(violation(
          'max-key-age-exceeded', policy, key, 'medium',
          `The key is ${key.ageDays} days old against a ${policy.maxKeyAgeDays}-day maximum.`,
          'Schedule replacement and retire the current version once the successor is validated.',
          keyEvidence, nowIso,
        ))
      }

      const anchor = dateMs(key.lastRotatedAt ?? key.activatedAt ?? key.createdAt)
      const policyOverdue = policy.rotationIntervalDays !== null && anchor !== null
        && Date.parse(nowIso) >= anchor + policy.rotationIntervalDays * ONE_DAY_MS
      if (policyOverdue && key.rotation !== 'not-applicable' && !terminal) {
        offenders.add(key.id)
        violations.push(violation(
          'rotation-interval-exceeded', policy, key,
          'high',
          `The recorded key exceeds this policy's ${policy.rotationIntervalDays}-day interval.`,
          'Raise a rotation work order, execute it and attach the post-rotation validation evidence.',
          keyEvidence, nowIso,
        ))
      }

      if (key.lifecycle === 'expired' && key.lastUsedAt && key.expiresAt && Date.parse(key.lastUsedAt) > Date.parse(key.expiresAt) && policy.id === 'baseline-rotation-sla') {
        offenders.add(key.id)
        violations.push(violation(
          'expired-key-in-use', policy, key, 'critical',
          'A recorded last-use timestamp falls after expiry.',
          'Replace the key immediately and confirm no service still references the expired material.',
          keyEvidence, nowIso,
        ))
      }

      if (policy.requirePqc && key.migrationRequirement === 'required' && !terminal) {
        offenders.add(key.id)
        violations.push(violation(
          'pqc-migration-required', policy, key,
          key.posture === 'deprecated' ? 'critical' : 'high',
          key.postureReason,
          key.keyClass === 'signature' || key.keyClass === 'certificate'
            ? 'Plan an ML-DSA-65 (or Ed25519 + ML-DSA-65 hybrid) signature migration and re-issue dependent certificates.'
            : 'Plan an ML-KEM-768 (or X25519 + ML-KEM-768 hybrid) key-establishment migration.',
          keyEvidence, nowIso,
        ))
      }
    }

    const violationsForPolicy = violations.filter((row) => row.policyId === policy.id).length
    annotated.push({
      ...policy,
      keysInScope: scoped.length,
      violations: violationsForPolicy,
      // No key in scope means nothing was evaluated — not 100% compliance.
      compliance: scoped.length && !scoped.some((key) => !offenders.has(key.id) && needsPolicyEvidence(policy, key))
        ? Math.round(((scoped.length - offenders.size) / scoped.length) * 100) : null,
      evaluation: scoped.length ? 'evaluated' : 'no-keys-in-scope',
    })
  }

  return { violations, policies: annotated }
}

export function violationSeverityWeight(severity: Severity): number {
  switch (severity) {
    case 'critical': return 100
    case 'high': return 70
    case 'medium': return 40
    case 'low': return 20
    default: return 10
  }
}

export function ruleLabel(rule: PolicyRule): string {
  return POLICY_RULE_LABEL[rule] || rule
}

/* ------------------------------------------------------------------ */
/* Storage backends                                                    */
/* ------------------------------------------------------------------ */

export function buildBackendPosture(
  keys: ManagedKey[],
  violations: GovernanceViolation[],
  declared: Array<{ id: string; name: string; provider: string; location: string; protectionLevel: string; hsmBacked: boolean; status: string; lastVerifiedAt: string | null }>,
): StorageBackendPosture[] {
  const byName = new Map<string, StorageBackendPosture>()
  const violationsByKey = new Map<string, number>()
  for (const row of violations) violationsByKey.set(row.keyId, (violationsByKey.get(row.keyId) || 0) + 1)

  // Tenant-declared backends first: a configured backend must appear even when
  // no key has been attributed to it yet, or the operator cannot tell whether
  // their integration is working.
  for (const row of declared) {
    const custody = classifyCustody(row.provider || row.name, row.protectionLevel).custody
    byName.set(row.name.toLowerCase(), {
      id: `backend:${row.id}`,
      name: row.name,
      provider: row.provider || row.name,
      custody,
      location: row.location || 'Tenant default',
      protectionLevel: row.protectionLevel || (row.hsmBacked ? 'Hardware security module' : 'Software custody'),
      hsmBacked: Boolean(row.hsmBacked),
      status: 'configured',
      keys: 0,
      violations: 0,
      lastVerifiedAt: row.lastVerifiedAt,
      evidence: [{
        source: 'qkms-registry',
        table: 'qkms_storage_backends',
        recordId: row.id,
        observedAt: row.lastVerifiedAt,
        detail: `Backend declared by the tenant with status "${row.status}".`,
      }],
    })
  }

  for (const key of keys) {
    const name = key.backend || 'Unknown'
    const slot = name.toLowerCase()
    const existing = byName.get(slot)
    if (existing) {
      existing.keys += 1
      existing.violations += violationsByKey.get(key.id) || 0
      continue
    }
    byName.set(slot, {
      id: `backend:observed:${slot.replace(/[^a-z0-9]+/g, '-')}`,
      name,
      provider: name,
      custody: key.custody,
      location: 'Observed from key evidence',
      protectionLevel: key.custody === 'unknown' ? 'Not established' : key.hsmBacked ? 'Hardware security module' : 'Software custody',
      hsmBacked: key.hsmBacked,
      // Observed, not configured: the tenant never declared this backend, QKMS
      // inferred it from where keys were found.
      status: key.custody === 'unknown' ? 'unverified' : 'observed',
      keys: 1,
      violations: violationsByKey.get(key.id) || 0,
      lastVerifiedAt: key.lastObservedAt,
      evidence: key.evidence.slice(0, 2),
    })
  }

  return [...byName.values()].sort((a, b) => b.keys - a.keys || a.name.localeCompare(b.name))
}

/* ------------------------------------------------------------------ */
/* Entropy / QRNG                                                      */
/* ------------------------------------------------------------------ */

const QRNG_PATTERN = /qrng|quantum random|id quantique|idq|quantum entropy/i
const HARDWARE_RNG = /hsm rng|hardware rng|trng|true random/i

/**
 * Entropy posture, with the four states the brief distinguishes.
 *
 * The rule that matters: `available` is never claimed from the platform's own
 * capability to generate keys. It requires a tenant row — a declared backend or
 * a connector — that advertises the source. Without one the answer is
 * `not-available`, because from the tenant's evidence it is not available.
 */
export function buildEntropyPosture(
  keys: ManagedKey[],
  qrngEvents: Array<{ id: string; algorithm?: unknown; created_at?: unknown }>,
  backends: StorageBackendPosture[],
  nowIso: string,
): EntropyPosture {
  const attributed = keys.filter((key) => Boolean(key.entropySource))
  const qrngKeys = attributed.filter((key) => QRNG_PATTERN.test(key.entropySource || ''))
  const hardwareKeys = attributed.filter((key) => HARDWARE_RNG.test(key.entropySource || '') || key.custody === 'hsm')

  const events = qrngEvents.length
  const latestAt = qrngEvents
    .map((row) => (row.created_at ? String(row.created_at) : null))
    .filter(Boolean)
    .sort()
    .reverse()[0] || null

  const declaredQrngBackend = backends.find((row) => row.status === 'configured' && QRNG_PATTERN.test(`${row.name} ${row.provider} ${row.protectionLevel}`))

  const evidence: QkmsEvidenceRef[] = []
  let status: EntropyStatus
  let source: string | null = null
  let detail: string

  if (events > 0 || qrngKeys.length > 0) {
    status = 'detected'
    source = qrngKeys[0]?.entropySource || 'QRNG service'
    detail = `Quantum entropy is in active use: ${events} entropy event(s) and ${qrngKeys.length} key(s) attributed to a QRNG source.`
    if (events > 0) {
      evidence.push({
        source: 'entropy-service',
        table: 'qrng_events',
        recordId: String(qrngEvents[0]?.id ?? 'qrng'),
        observedAt: latestAt,
        detail: `${events} QRNG entropy event(s) recorded for this tenant.`,
      })
    }
    for (const key of qrngKeys.slice(0, 3)) {
      evidence.push({
        source: 'qkms-registry',
        table: key.records[0]?.table || 'generated_keys',
        recordId: key.records[0]?.recordId || key.id,
        observedAt: key.lastObservedAt,
        detail: `Key "${key.label}" declares entropy source "${key.entropySource}".`,
      })
    }
  } else if (declaredQrngBackend) {
    status = 'configured'
    source = declaredQrngBackend.provider
    detail = `A QRNG-capable backend (${declaredQrngBackend.name}) is configured, but no entropy event has been observed from it yet.`
    evidence.push(...declaredQrngBackend.evidence)
  } else if (hardwareKeys.length > 0) {
    status = 'available'
    source = 'Hardware RNG'
    detail = `No quantum entropy source is configured. ${hardwareKeys.length} key(s) are held in hardware custody, so a hardware RNG is available to them; the remainder rely on the operating-system CSPRNG.`
    for (const key of hardwareKeys.slice(0, 3)) {
      evidence.push({
        source: 'qkms-registry',
        table: key.records[0]?.table || 'qkms_keys',
        recordId: key.records[0]?.recordId || key.id,
        observedAt: key.lastObservedAt,
        detail: `Key "${key.label}" is held in ${key.backend}, which provides a hardware RNG.`,
      })
    }
  } else {
    status = 'not-available'
    source = attributed.length ? attributed[0].entropySource : null
    detail = attributed.length
      ? 'No quantum or hardware entropy source was found. Keys rely on the operating-system CSPRNG, which is an approved source but carries no quantum-entropy claim.'
      : 'No entropy source could be attributed to any key. QKMS will not assert an entropy posture without evidence.'
  }

  const counts = new Map<string, number>()
  for (const key of attributed) counts.set(key.entropySource!, (counts.get(key.entropySource!) || 0) + 1)

  return {
    status,
    source,
    events,
    latestAt: latestAt || (status === 'detected' ? nowIso : null),
    detail,
    attributedKeys: attributed.length,
    distribution: [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([label, count]) => ({
        label,
        count,
        percent: attributed.length ? Math.round((count / attributed.length) * 100) : 0,
        keyIds: attributed.filter((key) => key.entropySource === label).map((key) => key.id).slice(0, 60),
      })),
    evidence: evidence.slice(0, 6),
  }
}
