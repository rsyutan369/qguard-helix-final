/**
 * Cryptographic policy engine.
 *
 * Declares the platform's baseline cryptographic rules and evaluates each one
 * against the tenant's real subject population (see `subjects.ts`). Every rule
 * is parameterised, so a tenant can raise a key-size floor or shorten a renewal
 * window without a code change; overrides arrive as rows from
 * `governance_policies` and are merged over the baseline here.
 *
 * MEASUREMENT HONESTY
 * -------------------
 * A rule that has nothing to evaluate reports `measured: false` with a null
 * adherence. It is never rendered as 100% ("nothing broken") — the absence of
 * subjects is the absence of evidence, not compliance.
 */

import {
  ASYMMETRIC_FAMILIES,
  ALGORITHM_FAMILY_LABEL,
  PQC_FAMILIES,
  clampPercent,
  daysBetween,
  ms,
  num,
  str,
  type AlgorithmFamily,
  type CryptoSubject,
  type Row,
  type SubjectSet,
} from './subjects'
import type {
  GovernanceSeverity,
  PolicyEnforcement,
  PolicyParameterDefinition,
  PolicyRecord,
  PolicyRuleDefinition,
  PolicyViolation,
} from './types'

/* ------------------------------------------------------------------ */
/* Baseline rule set                                                   */
/* ------------------------------------------------------------------ */

const FORBIDDEN_DEFAULT = ['MD5', 'SHA-1', 'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'ANON']
const APPROVED_DEFAULT = [
  'ML-KEM',
  'ML-DSA',
  'SLH-DSA',
  'Hybrid (X25519+ML-KEM)',
  'AES-256-GCM',
  'ChaCha20-Poly1305',
  'SHA3-256',
  'SHA3-512',
  'SHA-384',
  'ECDSA P-384',
  'X25519',
]

export const POLICY_CATALOG: PolicyRuleDefinition[] = [
  {
    id: 'POL-ALG-FORBIDDEN',
    title: 'Forbidden algorithms must not be deployed',
    category: 'forbidden-algorithms',
    rationale: 'Broken or disallowed primitives provide no meaningful security and are explicitly retired by transition guidance.',
    standard: 'NIST SP 800-131A Rev. 2 · CNSA 2.0',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'critical',
    parameters: [
      {
        key: 'families',
        label: 'Forbidden algorithm families',
        type: 'string-list',
        value: FORBIDDEN_DEFAULT,
        hint: 'Any subject whose algorithm resolves to one of these families is a violation.',
      },
    ],
    controlIds: ['CTL-ALG-01'],
    evaluator: 'forbiddenFamilies',
    remediationRoute: '/dashboard/crypto-agility',
  },
  {
    id: 'POL-ALG-APPROVED',
    title: 'Only approved algorithms may be used',
    category: 'approved-algorithms',
    rationale: 'Restricting deployment to a reviewed allowlist keeps the estate inside a known, governable cryptographic surface.',
    standard: 'ISO/IEC 27001 A.8.24 · CNSA 2.0',
    defaultEnforcement: 'monitored',
    defaultSeverity: 'medium',
    parameters: [
      {
        key: 'allowlist',
        label: 'Approved algorithms',
        type: 'string-list',
        value: APPROVED_DEFAULT,
        hint: 'Algorithms outside this list are reported for review.',
      },
      {
        key: 'allowClassicalTransitional',
        label: 'Permit classical algorithms during transition',
        type: 'boolean',
        value: true,
        hint: 'When enabled, RSA/ECC at or above the minimum key strength is treated as transitional rather than a violation.',
      },
    ],
    controlIds: ['CTL-ALG-03'],
    evaluator: 'approvedAllowlist',
    remediationRoute: '/dashboard/quantum-governance',
  },
  {
    id: 'POL-KEY-RSA',
    title: 'RSA and finite-field keys meet the minimum modulus size',
    category: 'key-strength',
    rationale: 'Modulus sizes below the floor no longer deliver the required classical security strength.',
    standard: 'NIST SP 800-131A Rev. 2',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'high',
    parameters: [
      { key: 'minBits', label: 'Minimum modulus', type: 'number', value: 3072, unit: 'bits', hint: 'CNSA 2.0 requires 3072-bit RSA where RSA is still permitted.' },
    ],
    controlIds: ['CTL-ALG-02'],
    evaluator: 'minimumRsaBits',
    remediationRoute: '/dashboard/crypto-agility',
  },
  {
    id: 'POL-KEY-EC',
    title: 'Elliptic-curve keys meet the minimum curve size',
    category: 'key-strength',
    rationale: 'Curves below the floor fall short of the required classical security strength.',
    standard: 'NIST SP 800-131A Rev. 2 · CNSA 2.0',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'high',
    parameters: [
      { key: 'minBits', label: 'Minimum curve size', type: 'number', value: 256, unit: 'bits', hint: 'CNSA 2.0 specifies P-384 where ECC is still permitted.' },
    ],
    controlIds: ['CTL-ALG-02'],
    evaluator: 'minimumEcBits',
    remediationRoute: '/dashboard/crypto-agility',
  },
  {
    id: 'POL-KEY-SYMMETRIC',
    title: 'Symmetric keys meet the minimum length',
    category: 'key-strength',
    rationale: 'Grover-style search halves effective symmetric strength, so 256-bit keys are the quantum-resistant baseline.',
    standard: 'CNSA 2.0 · NIST SP 800-57 Pt.1',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'medium',
    parameters: [
      { key: 'minBits', label: 'Minimum symmetric key length', type: 'number', value: 256, unit: 'bits', hint: 'AES-256 is the quantum-resistant symmetric baseline.' },
    ],
    controlIds: ['CTL-ALG-02'],
    evaluator: 'minimumSymmetricBits',
    remediationRoute: '/dashboard/encryption-monitoring',
  },
  {
    id: 'POL-TLS-MIN',
    title: 'Transport sessions negotiate at least the minimum TLS version',
    category: 'transport',
    rationale: 'Superseded protocol versions carry known weaknesses and are disallowed for protecting data in transit.',
    standard: 'PCI DSS 4.0.1 Req. 4 · NIST SP 800-52 Rev. 2',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'high',
    parameters: [
      { key: 'minVersion', label: 'Minimum TLS version', type: 'number', value: 1.2, hint: 'Measured endpoints negotiating below this version are violations.' },
      { key: 'preferVersion', label: 'Preferred TLS version', type: 'number', value: 1.3, hint: 'Endpoints below the preferred version are reported as advisory.' },
    ],
    controlIds: ['CTL-TLS-01'],
    evaluator: 'tlsMinimumVersion',
    remediationRoute: '/dashboard/tls-orchestrator',
  },
  {
    id: 'POL-TLS-FS',
    title: 'Key agreement provides forward secrecy',
    category: 'transport',
    rationale: 'Without ephemeral key agreement, recorded traffic can be decrypted later from a single long-term key — the core harvest-now-decrypt-later exposure.',
    standard: 'NIST SP 800-52 Rev. 2 · SOC 2 CC6.6',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'high',
    parameters: [
      { key: 'requireEphemeral', label: 'Require ephemeral key agreement', type: 'boolean', value: true, hint: 'ECDHE, DHE and PQC hybrid key agreement satisfy this rule.' },
    ],
    controlIds: ['CTL-TLS-02'],
    evaluator: 'forwardSecrecy',
    remediationRoute: '/dashboard/tls-telemetry',
  },
  {
    id: 'POL-PQC-EXPOSED',
    title: 'Internet-facing cryptography must be quantum-resistant',
    category: 'post-quantum',
    rationale: 'Externally reachable traffic can be captured today and decrypted once a cryptographically relevant quantum computer exists.',
    standard: 'NIST IR 8547 · CNSA 2.0',
    defaultEnforcement: 'monitored',
    defaultSeverity: 'critical',
    parameters: [
      { key: 'allowHybrid', label: 'Accept hybrid key establishment', type: 'boolean', value: true, hint: 'Hybrid classical+PQC key establishment satisfies the rule during transition.' },
    ],
    controlIds: ['CTL-PQC-04'],
    evaluator: 'internetFacingPqc',
    remediationRoute: '/dashboard/harvest-now',
  },
  {
    id: 'POL-PQC-SIGNATURE',
    title: 'Signature algorithms have a post-quantum transition path',
    category: 'post-quantum',
    rationale: 'Classical signatures must be scheduled for replacement with ML-DSA or SLH-DSA before the deprecation deadline.',
    standard: 'FIPS 204 / 205 · NIST IR 8547',
    defaultEnforcement: 'monitored',
    defaultSeverity: 'medium',
    parameters: [
      { key: 'deadlineYear', label: 'Classical deprecation year', type: 'number', value: 2030, hint: 'Planning year for the NIST public-key deprecation window. Earlier or different requirements may apply to the system.' },
    ],
    controlIds: ['CTL-PQC-03'],
    evaluator: 'signatureTransition',
    remediationRoute: '/dashboard/migration-planner',
  },
  {
    id: 'POL-CERT-RENEWAL',
    title: 'Certificates are renewed before expiry',
    category: 'certificate',
    rationale: 'An expired certificate breaks trust; renewal must start inside a defined window.',
    standard: 'NIST SP 800-53 SC-17',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'high',
    parameters: [
      { key: 'renewalWindowDays', label: 'Renewal window', type: 'number', value: 30, unit: 'days', hint: 'Certificates expiring inside this window are violations until renewed.' },
    ],
    controlIds: ['CTL-CRT-02'],
    evaluator: 'certificateRenewal',
    remediationRoute: '/dashboard/certificate-telemetry',
  },
  {
    id: 'POL-CERT-SIGALG',
    title: 'Certificate signature algorithms are approved',
    category: 'certificate',
    rationale: 'Certificates signed with deprecated hash or key families inherit those weaknesses across the whole chain.',
    standard: 'CNSA 2.0 · NIST SP 800-131A Rev. 2',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'high',
    parameters: [
      { key: 'forbidden', label: 'Forbidden signature families', type: 'string-list', value: ['MD5', 'SHA-1', 'DSA'], hint: 'Certificates signed with these families are violations.' },
    ],
    controlIds: ['CTL-CRT-03'],
    evaluator: 'certificateSignature',
    remediationRoute: '/dashboard/pki-visibility',
  },
  {
    id: 'POL-KEY-LIFECYCLE',
    title: 'Managed keys carry a defined cryptoperiod',
    category: 'key-lifecycle',
    rationale: 'A key with no expiry or rotation lineage cannot be retired on schedule.',
    standard: 'NIST SP 800-57 Pt.1 · PCI DSS 4.0.1 Req. 3.7.4',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'medium',
    parameters: [
      { key: 'maxAgeDays', label: 'Maximum key age', type: 'number', value: 365, unit: 'days', hint: 'Active keys older than this without rotation are violations.' },
      { key: 'requireExpiry', label: 'Require an expiry date', type: 'boolean', value: true, hint: 'Active keys with no expiry and no rotation lineage are violations.' },
    ],
    controlIds: ['CTL-KEY-02'],
    evaluator: 'keyCryptoperiod',
    remediationRoute: '/dashboard/qkms/lifecycle',
  },
  {
    id: 'POL-KEY-ENTROPY',
    title: 'Key material derives from a recorded entropy source',
    category: 'key-lifecycle',
    rationale: 'Randomness quality is a precondition for key strength and must be auditable.',
    standard: 'NIST SP 800-90A/B · SP 800-57 Pt.1',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'medium',
    parameters: [
      { key: 'minQuality', label: 'Minimum entropy quality score', type: 'number', value: 70, hint: 'Keys recording a quality score below this value are violations.' },
    ],
    controlIds: ['CTL-KEY-03'],
    evaluator: 'keyEntropy',
    remediationRoute: '/dashboard/qkms/governance',
  },
  {
    id: 'POL-DATA-REST',
    title: 'Stored objects reach an encrypted state',
    category: 'data-protection',
    rationale: 'Objects left in a pending state are stored without the protection the control claims.',
    standard: 'NIST SP 800-53 SC-28 · GDPR Art. 32(1)(a)',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'high',
    parameters: [
      { key: 'requireTerminalState', label: 'Require a completed encryption state', type: 'boolean', value: true, hint: 'Objects still pending encryption are violations.' },
    ],
    controlIds: ['CTL-DAT-01'],
    evaluator: 'dataAtRest',
    remediationRoute: '/dashboard/encryption-monitoring',
  },
  {
    id: 'POL-RUNTIME-CLEARTEXT',
    title: 'No cleartext or downgraded operations at runtime',
    category: 'data-protection',
    rationale: 'A downgrade or plaintext path defeats every control layered above it.',
    standard: 'NIST CSF 2.0 PR.DS-02',
    defaultEnforcement: 'enforced',
    defaultSeverity: 'critical',
    parameters: [
      { key: 'treatShadowCryptoAsViolation', label: 'Treat shadow cryptography as a violation', type: 'boolean', value: true, hint: 'Unmanaged cryptographic paths observed at runtime are reported as violations.' },
    ],
    controlIds: ['CTL-DAT-02'],
    evaluator: 'cleartextRuntime',
    remediationRoute: '/dashboard/runtime-crypto-intel',
  },
  {
    id: 'POL-AGILITY-CLASSIFICATION',
    title: 'Deployed cryptography is classifiable',
    category: 'crypto-agility',
    rationale: 'An algorithm that cannot be identified cannot be replaced on demand, which is the definition of an agility blocker.',
    standard: 'NIST IR 8547 · PCI DSS 4.0.1 Req. 12.3.3',
    defaultEnforcement: 'monitored',
    defaultSeverity: 'medium',
    parameters: [
      { key: 'maxUnknownPercent', label: 'Maximum unclassified share', type: 'number', value: 10, unit: '%', hint: 'Components whose algorithm cannot be classified count against this ceiling.' },
    ],
    controlIds: ['CTL-INV-02', 'CTL-PQC-05'],
    evaluator: 'classifiability',
    remediationRoute: '/dashboard/cbom-explorer',
  },
  {
    id: 'POL-RISK-THRESHOLD',
    title: 'Quantum risk stays inside the accepted appetite',
    category: 'quantum-risk',
    rationale: 'Governance sets a risk ceiling; exceeding it requires an accepted, time-bound exception.',
    standard: 'NIST CSF 2.0 GV.RM-01',
    defaultEnforcement: 'monitored',
    defaultSeverity: 'high',
    parameters: [
      { key: 'maxQuantumRisk', label: 'Maximum quantum risk score', type: 'number', value: 40, hint: 'Measured against the canonical tenant quantum risk score.' },
    ],
    controlIds: ['CTL-GOV-03'],
    evaluator: 'quantumRiskThreshold',
    remediationRoute: '/dashboard/quantum-readiness',
  },
]

export const POLICY_BY_ID = new Map(POLICY_CATALOG.map((policy) => [policy.id, policy]))

/* ------------------------------------------------------------------ */
/* Parameter merge                                                     */
/* ------------------------------------------------------------------ */

function mergeParameters(
  defaults: PolicyParameterDefinition[],
  overrides: Record<string, unknown>,
): PolicyParameterDefinition[] {
  return defaults.map((parameter) => {
    if (!(parameter.key in overrides)) return parameter
    const raw = overrides[parameter.key]
    if (parameter.type === 'number' && Number.isFinite(Number(raw))) {
      return { ...parameter, value: Number(raw) }
    }
    if (parameter.type === 'boolean' && typeof raw === 'boolean') {
      return { ...parameter, value: raw }
    }
    if (parameter.type === 'string-list' && Array.isArray(raw)) {
      return { ...parameter, value: raw.map((item) => str(item)).filter(Boolean) }
    }
    return parameter
  })
}

function paramNumber(parameters: PolicyParameterDefinition[], key: string, fallback: number): number {
  const found = parameters.find((parameter) => parameter.key === key)
  return typeof found?.value === 'number' ? found.value : fallback
}

function paramBoolean(parameters: PolicyParameterDefinition[], key: string, fallback: boolean): boolean {
  const found = parameters.find((parameter) => parameter.key === key)
  return typeof found?.value === 'boolean' ? found.value : fallback
}

function paramList(parameters: PolicyParameterDefinition[], key: string, fallback: string[]): string[] {
  const found = parameters.find((parameter) => parameter.key === key)
  return Array.isArray(found?.value) ? (found!.value as string[]) : fallback
}

/* ------------------------------------------------------------------ */
/* Evaluation primitives                                               */
/* ------------------------------------------------------------------ */

interface EvaluationOutcome {
  /** Subjects the rule could actually judge. */
  evaluated: number
  violations: PolicyViolation[]
  /** Sentence describing the population and the test applied. */
  basis: string
  /** When false, the rule had nothing to measure. */
  measured: boolean
}

function violation(input: {
  policyId: string
  subject: CryptoSubject
  severity: GovernanceSeverity
  observed: string
  expected: string
  detail: string
}): PolicyViolation {
  return {
    id: `${input.policyId}::${input.subject.id}`,
    policyId: input.policyId,
    subject: input.subject.label,
    subjectType: input.subject.kind,
    assetId: input.subject.assetId,
    assetName: input.subject.assetName,
    severity: input.severity,
    observed: input.observed,
    expected: input.expected,
    detail: input.detail,
    detectedAt: input.subject.observedAt,
    source: input.subject.source,
    href: input.subject.href,
  }
}

/** Parses a TLS version label ("TLSv1.2", "1.3", "TLS 1.0") to a number. */
export function tlsVersionNumber(raw: string): number | null {
  const text = String(raw || '').toUpperCase()
  if (/SSL\s*V?\s*2/.test(text)) return 0.2
  if (/SSL\s*V?\s*3/.test(text)) return 0.3
  const match = text.match(/(?:TLS\s*V?\s*)?(\d)\.(\d)/)
  if (!match) return null
  const value = Number(`${match[1]}.${match[2]}`)
  return Number.isFinite(value) ? value : null
}

const FORBIDDEN_FAMILY_MAP: Record<string, AlgorithmFamily[]> = {
  MD5: ['md5'],
  'SHA-1': ['sha1'],
  SHA1: ['sha1'],
  RC4: ['rc4'],
  DES: ['des'],
  '3DES': ['3des'],
  DSA: ['dsa'],
}

/** Tokens that mark a suite as offering no or negotiable protection. */
const NULL_SUITE_PATTERN = /\bNULL\b|\bANON\b|\bEXPORT\b|\bWITH_NULL\b|\baNULL\b|\beNULL\b/i

/* ------------------------------------------------------------------ */
/* Evaluators                                                          */
/* ------------------------------------------------------------------ */

export interface PolicyEvaluationContext {
  subjects: SubjectSet
  now: number
  /** Canonical tenant quantum risk score from the QR snapshot. */
  quantumRisk: number | null
  /** True when the QR snapshot reports any evidence at all. */
  hasEstateEvidence: boolean
}

type Evaluator = (
  parameters: PolicyParameterDefinition[],
  severity: GovernanceSeverity,
  context: PolicyEvaluationContext,
  policyId: string,
) => EvaluationOutcome

const EVALUATORS: Record<string, Evaluator> = {
  forbiddenFamilies(parameters, severity, context, policyId) {
    const configured = paramList(parameters, 'families', FORBIDDEN_DEFAULT)
    const families = new Set<AlgorithmFamily>()
    let checkNullSuites = false
    for (const entry of configured) {
      const key = entry.toUpperCase().trim()
      if (key === 'NULL' || key === 'EXPORT' || key === 'ANON') checkNullSuites = true
      for (const family of FORBIDDEN_FAMILY_MAP[key] || []) families.add(family)
    }
    // Only subjects whose algorithm was actually recorded can be judged.
    const population = context.subjects.all.filter((subject) => Boolean(subject.algorithm))
    const violations: PolicyViolation[] = []
    for (const subject of population) {
      const hitFamily = families.has(subject.family)
      const hitNull = checkNullSuites && NULL_SUITE_PATTERN.test(`${subject.algorithm} ${str(subject.meta.cipherSuite)}`)
      if (!hitFamily && !hitNull) continue
      violations.push(
        violation({
          policyId,
          subject,
          severity,
          observed: subject.algorithm || ALGORITHM_FAMILY_LABEL[subject.family],
          expected: `Not one of: ${configured.join(', ')}`,
          detail: hitNull
            ? 'Suite offers no confidentiality or authentication (NULL / anonymous / export grade).'
            : `${ALGORITHM_FAMILY_LABEL[subject.family]} is on the forbidden list.`,
        }),
      )
    }
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} cryptographic subject(s) with a recorded algorithm tested against ${configured.length} forbidden famil(ies).`,
    }
  },

  approvedAllowlist(parameters, severity, context, policyId) {
    const allowTransitional = paramBoolean(parameters, 'allowClassicalTransitional', true)
    const population = context.subjects.all.filter((subject) => Boolean(subject.algorithm) && subject.family !== 'unknown')
    const violations: PolicyViolation[] = []
    for (const subject of population) {
      const approved =
        PQC_FAMILIES.includes(subject.family) ||
        subject.family === 'hybrid' ||
        subject.family === 'aes' ||
        subject.family === 'chacha' ||
        subject.family === 'sha3' ||
        subject.family === 'sha2'
      if (approved) continue
      const transitional =
        allowTransitional && ASYMMETRIC_FAMILIES.includes(subject.family) && subject.family !== 'dsa'
      if (transitional) continue
      violations.push(
        violation({
          policyId,
          subject,
          severity,
          observed: subject.algorithm,
          expected: 'An algorithm on the approved allowlist',
          detail: allowTransitional
            ? `${ALGORITHM_FAMILY_LABEL[subject.family]} is neither approved nor accepted as a transitional classical algorithm.`
            : `${ALGORITHM_FAMILY_LABEL[subject.family]} is outside the approved allowlist.`,
        }),
      )
    }
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} classified subject(s) checked against the approved algorithm set${allowTransitional ? ' (classical algorithms accepted as transitional)' : ''}.`,
    }
  },

  minimumRsaBits(parameters, severity, context, policyId) {
    const minBits = paramNumber(parameters, 'minBits', 3072)
    const population = context.subjects.all.filter(
      (subject) => (subject.family === 'rsa' || subject.family === 'dh' || subject.family === 'dsa') && (subject.keySize ?? 0) > 0,
    )
    const violations = population
      .filter((subject) => (subject.keySize ?? 0) < minBits)
      .map((subject) =>
        violation({
          policyId,
          subject,
          severity,
          observed: `${subject.keySize} bits`,
          expected: `>= ${minBits} bits`,
          detail: `${ALGORITHM_FAMILY_LABEL[subject.family]} modulus below the configured minimum classical strength.`,
        }),
      )
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} RSA / finite-field subject(s) with a recorded key size tested against a ${minBits}-bit floor.`,
    }
  },

  minimumEcBits(parameters, severity, context, policyId) {
    const minBits = paramNumber(parameters, 'minBits', 256)
    const population = context.subjects.all.filter(
      (subject) => (subject.family === 'ecdsa' || subject.family === 'ecdh') && (subject.keySize ?? 0) > 0,
    )
    const violations = population
      .filter((subject) => (subject.keySize ?? 0) < minBits)
      .map((subject) =>
        violation({
          policyId,
          subject,
          severity,
          observed: `${subject.keySize} bits`,
          expected: `>= ${minBits} bits`,
          detail: 'Elliptic-curve key size below the configured minimum.',
        }),
      )
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} elliptic-curve subject(s) with a recorded curve size tested against a ${minBits}-bit floor.`,
    }
  },

  minimumSymmetricBits(parameters, severity, context, policyId) {
    const minBits = paramNumber(parameters, 'minBits', 256)
    const population = context.subjects.all.filter(
      (subject) => (subject.family === 'aes' || subject.family === 'chacha') && (subject.keySize ?? 0) > 0,
    )
    const violations = population
      .filter((subject) => (subject.keySize ?? 0) < minBits)
      .map((subject) =>
        violation({
          policyId,
          subject,
          severity,
          observed: `${subject.keySize} bits`,
          expected: `>= ${minBits} bits`,
          detail: 'Symmetric key length below the quantum-resistant baseline.',
        }),
      )
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} symmetric subject(s) with a recorded key length tested against a ${minBits}-bit floor.`,
    }
  },

  tlsMinimumVersion(parameters, severity, context, policyId) {
    const minVersion = paramNumber(parameters, 'minVersion', 1.2)
    const preferVersion = paramNumber(parameters, 'preferVersion', 1.3)
    // Population = endpoints whose negotiated version was actually MEASURED.
    const population = context.subjects.transport.filter((subject) => tlsVersionNumber(subject.tlsVersion) !== null)
    const violations: PolicyViolation[] = []
    for (const subject of population) {
      const version = tlsVersionNumber(subject.tlsVersion)!
      if (version >= preferVersion) continue
      const below = version < minVersion
      violations.push(
        violation({
          policyId,
          subject,
          severity: below ? severity : 'low',
          observed: subject.tlsVersion,
          expected: below ? `>= TLS ${minVersion}` : `TLS ${preferVersion} preferred`,
          detail: below
            ? 'Negotiated protocol version is below the enforced minimum.'
            : 'Negotiated version meets the minimum but is below the preferred version.',
        }),
      )
    }
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} endpoint observation(s) with a measured protocol version tested against TLS ${minVersion} (preferred TLS ${preferVersion}).`,
    }
  },

  forwardSecrecy(parameters, severity, context, policyId) {
    if (!paramBoolean(parameters, 'requireEphemeral', true)) {
      return { evaluated: 0, violations: [], measured: false, basis: 'Rule disabled by tenant policy.' }
    }
    // Only observations that recorded a key exchange can be judged.
    const population = context.subjects.transport.filter((subject) => Boolean(subject.keyExchange || subject.meta.cipherSuite))
    const violations: PolicyViolation[] = []
    for (const subject of population) {
      const text = `${subject.keyExchange} ${str(subject.meta.cipherSuite)}`.toUpperCase()
      const ephemeral =
        /\bECDHE\b|\bDHE\b|\bX25519\b|\bX448\b/.test(text) ||
        subject.family === 'hybrid' ||
        PQC_FAMILIES.includes(subject.family) ||
        // TLS 1.3 mandates ephemeral key agreement for every standard suite.
        (tlsVersionNumber(subject.tlsVersion) ?? 0) >= 1.3
      if (ephemeral) continue
      violations.push(
        violation({
          policyId,
          subject,
          severity,
          observed: subject.keyExchange || str(subject.meta.cipherSuite),
          expected: 'Ephemeral key agreement (ECDHE / DHE / PQC hybrid)',
          detail: 'Static key agreement lets recorded traffic be decrypted from one long-term key.',
        }),
      )
    }
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} endpoint observation(s) with a measured key exchange tested for forward secrecy.`,
    }
  },

  internetFacingPqc(parameters, severity, context, policyId) {
    const allowHybrid = paramBoolean(parameters, 'allowHybrid', true)
    const population = context.subjects.all.filter(
      (subject) => subject.internetFacing && (subject.kind === 'transport' || subject.kind === 'component' || subject.kind === 'certificate') && subject.posture !== 'unknown',
    )
    const violations = population
      .filter((subject) => {
        if (subject.posture === 'pqc') return false
        if (allowHybrid && subject.posture === 'hybrid') return false
        return subject.posture === 'vulnerable'
      })
      .map((subject) =>
        violation({
          policyId,
          subject,
          severity,
          observed: subject.algorithm || ALGORITHM_FAMILY_LABEL[subject.family],
          expected: allowHybrid ? 'Post-quantum or hybrid key establishment' : 'Post-quantum key establishment',
          detail: 'Internet-facing cryptography is exposed to harvest-now-decrypt-later collection.',
        }),
      )
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} classified internet-facing subject(s) tested for quantum-resistant key establishment.`,
    }
  },

  signatureTransition(parameters, severity, context, policyId) {
    const deadlineYear = paramNumber(parameters, 'deadlineYear', 2030)
    const population = context.subjects.all.filter(
      (subject) => subject.family === 'rsa' || subject.family === 'ecdsa' || subject.family === 'dsa' || subject.family === 'ml-dsa' || subject.family === 'slh-dsa',
    )
    const violations = population
      .filter((subject) => subject.family === 'rsa' || subject.family === 'ecdsa' || subject.family === 'dsa')
      .map((subject) =>
        violation({
          policyId,
          subject,
          severity,
          observed: subject.algorithm || ALGORITHM_FAMILY_LABEL[subject.family],
          expected: 'ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)',
          detail: `Classical signature algorithm requires a transition plan for the deprecation window after ${deadlineYear}.`,
        }),
      )
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} signature-capable subject(s) tested against the ${deadlineYear} classical deprecation timeline.`,
    }
  },

  certificateRenewal(parameters, severity, context, policyId) {
    const windowDays = paramNumber(parameters, 'renewalWindowDays', 30)
    const population = context.subjects.certificates.filter((subject) => Boolean(subject.meta.notAfter))
    const violations: PolicyViolation[] = []
    for (const subject of population) {
      const expiry = ms(subject.meta.notAfter)
      const days = daysBetween(context.now, expiry)
      if (days > windowDays) continue
      violations.push(
        violation({
          policyId,
          subject,
          severity: days < 0 ? 'critical' : severity,
          observed: days < 0 ? `Expired ${Math.abs(days)}d ago` : `Expires in ${days}d`,
          expected: `More than ${windowDays} days of validity remaining`,
          detail: days < 0 ? 'Certificate has already expired.' : 'Certificate is inside the renewal window.',
        }),
      )
    }
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} certificate(s) with a recorded expiry tested against a ${windowDays}-day renewal window.`,
    }
  },

  certificateSignature(parameters, severity, context, policyId) {
    const configured = paramList(parameters, 'forbidden', ['MD5', 'SHA-1', 'DSA'])
    const families = new Set<AlgorithmFamily>()
    for (const entry of configured) for (const family of FORBIDDEN_FAMILY_MAP[entry.toUpperCase().trim()] || []) families.add(family)
    const population = context.subjects.certificates.filter((subject) => Boolean(subject.algorithm))
    const violations = population
      .filter((subject) => families.has(subject.family))
      .map((subject) =>
        violation({
          policyId,
          subject,
          severity,
          observed: subject.algorithm,
          expected: `Not one of: ${configured.join(', ')}`,
          detail: 'Certificate signature algorithm is deprecated; the weakness propagates through the whole chain.',
        }),
      )
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} certificate(s) with a recorded signature algorithm tested against the forbidden set.`,
    }
  },

  keyCryptoperiod(parameters, severity, context, policyId) {
    const maxAgeDays = paramNumber(parameters, 'maxAgeDays', 365)
    const requireExpiry = paramBoolean(parameters, 'requireExpiry', true)
    const population = context.subjects.keys.filter((subject) => {
      const status = str(subject.meta.status).toLowerCase()
      return !subject.meta.revokedAt && !/revoked|destroyed|compromised/.test(status)
    })
    const violations: PolicyViolation[] = []
    for (const subject of population) {
      const expiresAt = subject.meta.expiresAt ? ms(subject.meta.expiresAt) : 0
      const createdAt = subject.meta.createdAt ? ms(subject.meta.createdAt) : 0
      const rotated = Boolean(str(subject.meta.rotatedFrom))
      if (expiresAt && expiresAt < context.now) {
        violations.push(
          violation({
            policyId,
            subject,
            severity: 'high',
            observed: `Expired ${Math.abs(daysBetween(context.now, expiresAt))}d ago, status "${str(subject.meta.status) || 'active'}"`,
            expected: 'Retired at end of cryptoperiod',
            detail: 'Key is past its recorded expiry but is not marked revoked or destroyed.',
          }),
        )
        continue
      }
      if (!expiresAt && requireExpiry && !rotated) {
        const ageDays = createdAt ? daysBetween(createdAt, context.now) : null
        if (ageDays === null || ageDays > maxAgeDays) {
          violations.push(
            violation({
              policyId,
              subject,
              severity,
              observed: ageDays === null ? 'No expiry, age unknown' : `No expiry, ${ageDays}d old`,
              expected: `An expiry date, or rotation within ${maxAgeDays} days`,
              detail: 'Key has no defined cryptoperiod and no rotation lineage.',
            }),
          )
        }
      }
    }
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} active key(s) tested for a defined cryptoperiod (max age ${maxAgeDays} days).`,
    }
  },

  keyEntropy(parameters, severity, context, policyId) {
    const minQuality = paramNumber(parameters, 'minQuality', 70)
    const population = context.subjects.keys
    const violations: PolicyViolation[] = []
    for (const subject of population) {
      const source = str(subject.meta.entropySource)
      const quality = typeof subject.meta.qualityScore === 'number' ? subject.meta.qualityScore : null
      if (!source) {
        violations.push(
          violation({
            policyId,
            subject,
            severity,
            observed: 'No entropy source recorded',
            expected: 'A recorded, approved entropy source',
            detail: 'Randomness provenance cannot be audited for this key.',
          }),
        )
        continue
      }
      if (quality !== null && quality < minQuality) {
        violations.push(
          violation({
            policyId,
            subject,
            severity,
            observed: `Entropy quality ${quality}`,
            expected: `>= ${minQuality}`,
            detail: `Entropy source "${source}" scored below the configured quality floor.`,
          }),
        )
      }
    }
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} managed key(s) tested for entropy provenance (quality floor ${minQuality}).`,
    }
  },

  dataAtRest(parameters, severity, context, policyId) {
    if (!paramBoolean(parameters, 'requireTerminalState', true)) {
      return { evaluated: 0, violations: [], measured: false, basis: 'Rule disabled by tenant policy.' }
    }
    const population = context.subjects.objects
    const violations = population
      .filter((subject) => !/encrypted|complete|processed|sealed|ready/i.test(str(subject.meta.encryptionStatus)))
      .map((subject) =>
        violation({
          policyId,
          subject,
          severity,
          observed: str(subject.meta.encryptionStatus) || 'No encryption status recorded',
          expected: 'A completed encrypted state',
          detail: 'Stored object has not reached a confirmed encrypted state.',
        }),
      )
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} stored object(s) tested for a completed encryption state.`,
    }
  },

  cleartextRuntime(parameters, severity, context, policyId) {
    const shadowCounts = paramBoolean(parameters, 'treatShadowCryptoAsViolation', true)
    const population = context.subjects.transport
    const violations: PolicyViolation[] = []
    for (const subject of population) {
      const plaintext = /plaintext|cleartext|unencrypted/i.test(
        `${str(subject.meta.operationType)} ${str(subject.meta.eventType)}`,
      )
      const downgrade = subject.meta.downgradeDetected === true
      const shadow = shadowCounts && subject.meta.shadowCrypto === true
      if (!plaintext && !downgrade && !shadow) continue
      violations.push(
        violation({
          policyId,
          subject,
          severity: plaintext || downgrade ? severity : 'medium',
          observed: plaintext ? 'Plaintext operation' : downgrade ? 'Protocol downgrade' : 'Unmanaged cryptographic path',
          expected: 'Encrypted, non-downgraded, managed cryptographic operation',
          detail: plaintext
            ? 'A cryptographic operation was observed running without protection.'
            : downgrade
              ? 'A negotiated downgrade was observed on this path.'
              : 'Cryptography outside the governed inventory was observed at runtime.',
        }),
      )
    }
    return {
      evaluated: population.length,
      violations,
      measured: population.length > 0,
      basis: `${population.length} runtime transport observation(s) tested for plaintext, downgrade and shadow cryptography.`,
    }
  },

  classifiability(parameters, severity, context, policyId) {
    const maxUnknown = paramNumber(parameters, 'maxUnknownPercent', 10)
    const population = context.subjects.components
    if (!population.length) {
      return { evaluated: 0, violations: [], measured: false, basis: 'No cryptographic components discovered yet.' }
    }
    const unclassified = population.filter((subject) => subject.family === 'unknown' || !subject.algorithm)
    const sharePercent = clampPercent((unclassified.length / population.length) * 100)
    const overBudget = sharePercent > maxUnknown
    const violations = overBudget
      ? unclassified.map((subject) =>
          violation({
            policyId,
            subject,
            severity,
            observed: subject.algorithm ? `Unrecognised algorithm "${subject.algorithm}"` : 'No algorithm recorded',
            expected: 'A classifiable algorithm identifier',
            detail: `Unclassified components are ${sharePercent}% of the inventory, above the ${maxUnknown}% ceiling — these cannot be swapped on demand.`,
          }),
        )
      : []
    return {
      evaluated: population.length,
      violations,
      measured: true,
      basis: `${unclassified.length} of ${population.length} component(s) unclassified (${sharePercent}%), ceiling ${maxUnknown}%.`,
    }
  },

  quantumRiskThreshold(parameters, severity, context, policyId) {
    const threshold = paramNumber(parameters, 'maxQuantumRisk', 40)
    if (context.quantumRisk === null || !context.hasEstateEvidence) {
      return {
        evaluated: 0,
        violations: [],
        measured: false,
        basis: 'Quantum risk is not measured until cryptographic evidence exists.',
      }
    }
    const breached = context.quantumRisk > threshold
    const violations: PolicyViolation[] = breached
      ? [
          {
            id: `${policyId}::tenant`,
            policyId,
            subject: 'Tenant quantum risk',
            subjectType: 'tenant',
            assetId: null,
            assetName: null,
            severity,
            observed: `Quantum risk ${context.quantumRisk}`,
            expected: `<= ${threshold}`,
            detail: 'Measured quantum risk exceeds the governance risk appetite; an approved exception is required.',
            detectedAt: new Date(context.now).toISOString(),
            source: { table: 'quantum_readiness_snapshot', recordId: 'quantumRisk' },
            href: '/dashboard/quantum-readiness',
          },
        ]
      : []
    return {
      evaluated: 1,
      violations,
      measured: true,
      basis: `Canonical quantum risk score ${context.quantumRisk} tested against a ceiling of ${threshold}.`,
    }
  },
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */

const VIOLATION_SAMPLE = 12

function normalizeEnforcement(value: unknown, fallback: PolicyEnforcement): PolicyEnforcement {
  const text = str(value).toLowerCase()
  if (text === 'enforced' || text === 'monitored' || text === 'disabled') return text
  return fallback
}

function normalizeSeverity(value: unknown, fallback: GovernanceSeverity): GovernanceSeverity {
  const text = str(value).toLowerCase()
  if (text === 'critical' || text === 'high' || text === 'medium' || text === 'low') return text
  return fallback
}

/**
 * Evaluates every policy rule against the tenant's real subject population.
 *
 * `overrides` are rows from `governance_policies` (null when the store is not
 * available). A disabled rule is still returned — with its population reported
 * and adherence null — so the UI can show what governance is NOT watching.
 */
export function evaluatePolicies(
  context: PolicyEvaluationContext,
  overrides: Row[] | null,
): PolicyRecord[] {
  const overrideById = new Map<string, Row>()
  for (const row of overrides || []) {
    const id = str(row.policy_id) || str(row.id)
    if (id) overrideById.set(id, row)
  }
  const evaluatedAt = new Date(context.now).toISOString()

  return POLICY_CATALOG.map((definition) => {
    const override = overrideById.get(definition.id)
    const overrideParameters =
      override && typeof override.parameters === 'object' && override.parameters !== null
        ? (override.parameters as Record<string, unknown>)
        : {}
    const parameters = mergeParameters(definition.parameters, overrideParameters)
    const enforcement = normalizeEnforcement(override?.enforcement, definition.defaultEnforcement)
    const severity = normalizeSeverity(override?.severity, definition.defaultSeverity)

    const evaluator = EVALUATORS[definition.evaluator]
    const outcome: EvaluationOutcome =
      enforcement === 'disabled'
        ? { evaluated: 0, violations: [], measured: false, basis: 'Rule is disabled — nothing is evaluated while it is off.' }
        : evaluator
          ? evaluator(parameters, severity, context, definition.id)
          : { evaluated: 0, violations: [], measured: false, basis: 'No evaluator is registered for this rule.' }

    const violations = outcome.violations
    const compliantSubjects = Math.max(0, outcome.evaluated - new Set(violations.map((row) => row.id.split('::')[1])).size)
    const adherence = outcome.measured && outcome.evaluated > 0 ? clampPercent((compliantSubjects / outcome.evaluated) * 100) : null

    return {
      id: definition.id,
      title: definition.title,
      category: definition.category,
      rationale: definition.rationale,
      standard: definition.standard,
      enforcement,
      severity,
      parameters,
      controlIds: definition.controlIds,
      remediationRoute: definition.remediationRoute,
      tenantConfigured: Boolean(override),
      updatedAt: override ? (str(override.updated_at) || null) : null,
      updatedBy: override ? (str(override.updated_by) || null) : null,
      measured: outcome.measured,
      evaluated: outcome.evaluated,
      compliantSubjects,
      violations: violations.length,
      criticalViolations: violations.filter((row) => row.severity === 'critical').length,
      adherence,
      basis: outcome.basis,
      violationSample: violations
        .slice()
        .sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity) || ms(b.detectedAt) - ms(a.detectedAt))
        .slice(0, VIOLATION_SAMPLE),
      lastEvaluatedAt: evaluatedAt,
    }
  })
}

export function severityOrder(severity: GovernanceSeverity): number {
  if (severity === 'critical') return 4
  if (severity === 'high') return 3
  if (severity === 'medium') return 2
  return 1
}

/**
 * The full violation set for a policy — used by the paged drill-down route so a
 * user can page through every violation, not only the sample carried in the
 * dashboard payload.
 */
export function allViolationsFor(
  policyId: string,
  context: PolicyEvaluationContext,
  overrides: Row[] | null,
): PolicyViolation[] {
  const definition = POLICY_BY_ID.get(policyId)
  if (!definition) return []
  const override = (overrides || []).find((row) => str(row.policy_id) === policyId || str(row.id) === policyId)
  const overrideParameters =
    override && typeof override.parameters === 'object' && override.parameters !== null
      ? (override.parameters as Record<string, unknown>)
      : {}
  const parameters = mergeParameters(definition.parameters, overrideParameters)
  const enforcement = normalizeEnforcement(override?.enforcement, definition.defaultEnforcement)
  if (enforcement === 'disabled') return []
  const severity = normalizeSeverity(override?.severity, definition.defaultSeverity)
  const evaluator = EVALUATORS[definition.evaluator]
  if (!evaluator) return []
  return evaluator(parameters, severity, context, policyId).violations
}

export { num, str }
