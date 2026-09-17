/**
 * The ONE risk verdict for a piece of agent-collected cryptographic evidence.
 *
 * Every runtime crypto event the agent publishes, and every remediation
 * validation gate it runs, is decided here. It replaces a set of substring
 * regexes that ran against the STRINGIFIED evidence record — a design that
 * produced six reproducible misclassifications, the worst of which made the
 * agent roll back its own successful PQC remediation:
 *
 *   1. `/…|dsa|…/` matched "ML-DSA-65" and "SLH-DSA-SHA2-128s", so the two
 *      NIST post-quantum signature standards (FIPS 204/205) were published as
 *      LEGACY, severity high.
 *   2. `/…|ssl|…/` matched "OpenSSL" and "oqs-openssl", so a library
 *      inventory row was published as a CRITICAL protocol downgrade.
 *   3. `/downgrade|fallback|…/` matched the POLICY FIELD `classicalFallback`,
 *      so carrying the platform's own PQC policy made a record critical.
 *   4. Because the regexes ran over `JSON.stringify(rawEvidence)`, any record
 *      embedding `MANDATORY_PQC_STACK` inherited (1)-(3). The agent embeds it
 *      in the success attestation it writes after a clean post-patch rescan,
 *      so a remediation that WORKED validated as failed -> rollbackRequired
 *      -> the correct configuration was restored to its vulnerable state.
 *   5. `keySize <= 1024 => critical` was written for an RSA modulus but ran
 *      against every key size, so every ECDSA P-256 (256) and Ed25519 (256)
 *      certificate was published critical.
 *   6. The post-quantum regex knew `sphincs` but not `slh-dsa`, so FIPS 205
 *      under its standardised name was not recognised as post-quantum at all.
 *
 * The rule this module enforces: classify the PRIMITIVE the evidence names,
 * using the ground-truth knowledge base, and decide protocol downgrade from
 * the protocol version actually observed. Never classify a record by the text
 * of the policy attached to it.
 */

import { findAlgorithm } from './knowledge-base/algorithms'
import type { QuantumStatus } from './knowledge-base/types'
import { analyzeCryptoObservation } from './suite-anatomy'

export type EvidenceSeverity = 'critical' | 'high' | 'moderate' | 'low' | 'safe'

/** The subset of an agent evidence record that carries cryptographic meaning. */
export interface AgentEvidenceInput {
  evidenceType: string
  /** The primitive the agent observed. THIS is what gets classified. */
  observedAlgorithm?: string | null
  protocol?: string | null
  host?: string | null
  target?: string | null
  keySize?: number | null
  packageName?: string | null
  rawEvidence?: Record<string, unknown> | null
}

export interface AgentEvidenceVerdict {
  isPqc: boolean
  isLegacy: boolean
  downgradeDetected: boolean
  shadowCrypto: boolean
  hndlRisk: boolean
  severity: EvidenceSeverity
  riskScore: number
  /** Canonical knowledge-base name, when the primitive was recognised. */
  algorithm: string | null
  quantumStatus: QuantumStatus
  /** One sentence, published next to the verdict. Never a bare label. */
  rationale: string
}

/** Discovery surfaces: they name where crypto is configured, not a live negotiation. */
const SHADOW_CRYPTO_TYPES = new Set([
  'package-manifest',
  'config-reference',
  'crypto-library',
  'jwt-algorithm',
])

/** Inventory rows name a PACKAGE ("OpenSSL 3.5"), never a primitive. */
const LIBRARY_TYPES = new Set(['crypto-library', 'package-manifest'])

/**
 * Protocol versions that are a genuine downgrade. Decided from the version
 * observed, not from the presence of the letters "ssl" somewhere in a blob:
 * "OpenSSL 3.5" is the library that implements TLS 1.3.
 *
 * Anchored at the start, so it reads a value that IS a protocol version. The
 * separator is deliberately loose because the producers disagree: the network
 * probe reports "TLS 1.0", the config detector reports "TLS-1.0", and an
 * OpenSSL-style string reports "TLSv1.0".
 */
const PROTOCOL_VERSION = /^(SSL|TLS|DTLS)[\s._-]*V?\s*(\d+(?:[._]\d+)?)/i

/** Asymmetric roles where a small key size is a finding. 256-bit EC is not. */
const RSA_LIKE = /^(RSA|DIFFIE-HELLMAN|DSA)$/i

function text(value: unknown) {
  return String(value ?? '').trim()
}

function isDowngradedProtocol(value: unknown) {
  const match = PROTOCOL_VERSION.exec(text(value))
  if (!match) return false
  const family = match[1].toUpperCase()
  const version = match[2].replace('_', '.')
  // SSL 2.0 and 3.0 are withdrawn outright; TLS 1.0 and 1.1 are deprecated by
  // RFC 8996. TLS 1.2 is not a downgrade, so it is not escalated here.
  if (family === 'SSL') return /^[23](\.0)?$/.test(version)
  return /^1(\.[01])?$/.test(version)
}

/**
 * A remediation attestation is the agent asserting its own post-patch rescan
 * found nothing. It is a validation RESULT, not an observation of a primitive,
 * and the mandatory PQC stack it carries is policy — classifying either as
 * cryptography is defect (4) above.
 */
function isAttestation(input: AgentEvidenceInput) {
  const raw = input.rawEvidence || {}
  return raw.remediationValidation === true
}

/**
 * Does the primitive carry the risk Shor's algorithm creates, in a role where
 * a network attacker could record the traffic now and decrypt it later?
 * Symmetric ciphers and hashes carry no key-agreement risk, so they never do.
 */
function bearsHndlRisk(quantumStatus: QuantumStatus, shorBroken: boolean) {
  return shorBroken && quantumStatus === 'QUANTUM_VULNERABLE'
}

function scoreFor(severity: EvidenceSeverity) {
  return severity === 'critical' ? 92 : severity === 'high' ? 74 : severity === 'moderate' ? 55 : severity === 'low' ? 28 : 5
}

function escalate(verdict: AgentEvidenceVerdict, severity: EvidenceSeverity, rationale: string): AgentEvidenceVerdict {
  return { ...verdict, downgradeDetected: true, severity, riskScore: scoreFor(severity), rationale }
}

function rationaleFor(args: {
  canonical: string
  observed: string
  quantumStatus: QuantumStatus
  classical: string
  downgradeDetected: boolean
  hndlRisk: boolean
  undersizedModulus: boolean
  keySize: number
}) {
  const parts: string[] = []
  if (args.downgradeDetected) parts.push('a downgraded transport protocol was observed')
  if (args.hndlRisk) parts.push('it is broken by Shor’s algorithm and was observed on a network target, so recorded traffic is decryptable once a CRQC exists')
  if (args.undersizedModulus) parts.push(`the ${args.keySize}-bit modulus is below the accepted floor`)
  if (args.quantumStatus === 'PQC_STANDARDIZED') parts.push('it is a NIST-standardised post-quantum algorithm')
  if (args.quantumStatus === 'HYBRID') parts.push('it pairs a classical primitive with a post-quantum one')
  if (args.classical === 'BROKEN') parts.push('practical classical attacks exist against it')
  else if (args.classical === 'LEGACY') parts.push('it is discouraged for new use')
  const because = parts.length ? ` — ${parts.join('; ')}.` : '.'
  const alias = args.observed.toLowerCase() === args.canonical.toLowerCase() ? '' : ` (observed as "${args.observed}")`
  return `${args.canonical}${alias}${because}`
}

export function classifyAgentEvidence(input: AgentEvidenceInput): AgentEvidenceVerdict {
  const evidenceType = text(input.evidenceType)
  const observed = text(input.observedAlgorithm)
  const shadowCrypto = SHADOW_CRYPTO_TYPES.has(evidenceType)
  const onNetworkTarget = Boolean(text(input.host) || text(input.target))

  const unclassified = (
    rationale: string,
    severity: EvidenceSeverity = shadowCrypto ? 'moderate' : 'low'
  ): AgentEvidenceVerdict => ({
    isPqc: false,
    isLegacy: false,
    downgradeDetected: false,
    shadowCrypto,
    hndlRisk: false,
    severity,
    riskScore: scoreFor(severity),
    algorithm: null,
    quantumStatus: 'UNKNOWN',
    rationale,
  })

  if (isAttestation(input)) {
    return {
      ...unclassified(
        'Post-remediation validation attestation: the rescan observed no vulnerable primitive at this location. Not itself an observed primitive.',
        'safe'
      ),
      quantumStatus: 'NOT_APPLICABLE',
    }
  }

  /*
   * A genuine protocol downgrade is decided by the version named. The observed
   * algorithm is checked whatever the evidence type carries it: a network probe
   * reports the negotiated version as a `tls-protocol` record, while a config
   * scan reports the SAME finding as a `config-reference` row, and a deprecated
   * protocol pinned in a config file is exactly as real a finding.
   */
  const downgradeDetected =
    isDowngradedProtocol(observed) ||
    isDowngradedProtocol(input.protocol) ||
    (input.rawEvidence || {}).downgradeDetected === true

  if (!observed) {
    const verdict = unclassified('No algorithm was observed for this record, so no cryptographic verdict is published.')
    return downgradeDetected
      ? escalate(verdict, 'critical', 'A downgraded transport protocol was observed at this location.')
      : verdict
  }

  // Library / package inventory names a package, not a primitive. "OpenSSL 3.5"
  // is not an algorithm and must never be scored as one.
  if (LIBRARY_TYPES.has(evidenceType) && text(input.packageName)) {
    return unclassified(
      `Inventory row for package ${text(input.packageName)}: it records where cryptography is available, not which primitive is in use.`,
      'moderate'
    )
  }

  /*
   * Composite names are decomposed by the canonical classifier, never looked up
   * by substring in the knowledge base. The knowledge base's alias scan matched
   * the PART it recognised: `rsa-sha2-512` (an RSA signature) as "SHA-2,
   * quantum resistant", and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` as "AES,
   * quantum resistant" — so the fallback below, which reads the key exchange,
   * was never reached, and an agent validating its own patch could pass a
   * classical TLS 1.2 suite. Single primitives ("RSA-3072", "RC4", "ML-DSA-65")
   * still use the knowledge base, which grades classical security.
   */
  const COMPOSITE = /_WITH_|^TLS_|-SHA2-|MLKEM|ML-KEM.*X25519|X25519.*ML-?KEM|SNTRUP|@OPENSSH|NISTP\d|DIFFIE-HELLMAN-GROUP|SECP\d+R1MLKEM|\+/i
  const known = COMPOSITE.test(observed) ? null : findAlgorithm(observed)

  if (known) {
    const shorBroken = known.shorBroken === true
    const classical = known.classicalSecurity
    const quantumStatus = known.quantumStatus
    const isPqc = quantumStatus === 'PQC_STANDARDIZED' || quantumStatus === 'HYBRID'
    const brokenClassically = classical === 'BROKEN' || classical === 'LEGACY'
    const isLegacy = shorBroken || brokenClassically
    const hndlRisk = bearsHndlRisk(quantumStatus, shorBroken) && onNetworkTarget

    // The small-key rule belongs to RSA-style moduli. A 256-bit EC key is the
    // recommended size, not a weakness.
    const keySize = Number(input.keySize)
    const undersizedModulus =
      Number.isFinite(keySize) && keySize > 0 && keySize <= 1024 && RSA_LIKE.test(known.canonicalName)

    const severity: EvidenceSeverity = downgradeDetected || hndlRisk || undersizedModulus
      ? 'critical'
      : isLegacy
        ? 'high'
        : isPqc || quantumStatus === 'QUANTUM_RESISTANT'
          ? 'safe'
          : shadowCrypto
            ? 'moderate'
            : 'low'

    return {
      isPqc,
      isLegacy,
      downgradeDetected,
      shadowCrypto,
      hndlRisk,
      severity,
      riskScore: scoreFor(severity),
      algorithm: known.canonicalName,
      quantumStatus,
      rationale: rationaleFor({
        canonical: known.canonicalName,
        observed,
        quantumStatus,
        classical,
        downgradeDetected,
        hndlRisk,
        undersizedModulus,
        keySize,
      }),
    }
  }

  // Composite strings the knowledge base does not alias one-to-one: cipher
  // suites (TLS_ECDHE_RSA_WITH_…) and hybrid group names (X25519MLKEM768).
  const anatomy = analyzeCryptoObservation({ algorithm: observed, protocol: input.protocol })
  if (anatomy.kind !== 'policy') {
    const isPqc = anatomy.quantumClass === 'safe' || anatomy.quantumClass === 'hybrid'
    const isLegacy = anatomy.quantumClass === 'vulnerable'
    const hndlRisk = isLegacy && onNetworkTarget && anatomy.kind !== 'symmetric' && anatomy.kind !== 'hash'
    const severity: EvidenceSeverity = downgradeDetected || hndlRisk
      ? 'critical'
      : isLegacy
        ? 'high'
        : isPqc
          ? 'safe'
          : shadowCrypto
            ? 'moderate'
            : 'low'
    return {
      isPqc,
      isLegacy,
      downgradeDetected,
      shadowCrypto,
      hndlRisk,
      severity,
      riskScore: scoreFor(severity),
      algorithm: anatomy.family,
      quantumStatus:
        anatomy.quantumClass === 'safe'
          ? 'QUANTUM_RESISTANT'
          : anatomy.quantumClass === 'hybrid'
            ? 'HYBRID'
            : anatomy.quantumClass === 'vulnerable'
              ? 'QUANTUM_VULNERABLE'
              : 'UNKNOWN',
      rationale: `${anatomy.family}: the quantum verdict follows the risk-bearing primitive in the observation, not the whole string.`,
    }
  }

  const verdict = unclassified(
    `"${observed}" was not recognised as a cryptographic primitive by the knowledge base, so no quantum verdict is published for it.`
  )
  return downgradeDetected
    ? escalate(verdict, 'critical', 'A downgraded transport protocol was observed at this location.')
    : verdict
}
