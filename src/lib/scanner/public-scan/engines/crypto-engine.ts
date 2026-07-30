/**
 * QGuard Helix — Cryptographic Intelligence + Post-Quantum Readiness Engine
 *
 * Builds the catalogue of algorithms actually observed at the edge, classifies
 * each one (Quantum Safe / Hybrid / Classical / Legacy / Deprecated), derives
 * post-quantum readiness from measured evidence, and runs the Quantum Risk
 * Engine that explains *why* a risk level was assigned.
 *
 * Only algorithms genuinely observed are reported. Nothing is added because it
 * is "probably there" — a public scan sees the handshake and the certificate,
 * and that is the extent of its authority.
 */

import type { CertificateIntelligence } from './certificate-engine'
import type { TlsIntelligence } from './tls-engine'
import { HYBRID_GROUP_KEM } from './tls-engine'
import { type Evidence, type EngineResult, clampScore, runEngine } from './contract'

export type AlgorithmClass = 'Quantum Safe' | 'Hybrid' | 'Classical' | 'Legacy' | 'Deprecated'
export type AlgorithmRole =
  | 'Key encapsulation'
  | 'Key agreement'
  | 'Digital signature'
  | 'Certificate public key'
  | 'Symmetric encryption'
  | 'Hash'
  | 'Transport protocol'

export type QuantumRiskLevel = 'Low' | 'Medium' | 'High' | 'Critical'

export interface ObservedAlgorithm {
  name: string
  role: AlgorithmRole
  classification: AlgorithmClass
  /** True when a CRQC recovers the secret (Shor), not merely weakens it. */
  quantumVulnerable: boolean
  /** Effective post-quantum security margin in bits, where meaningful. */
  postQuantumBits: number | null
  detail: string
  evidenceSource: string
}

export interface QuantumRiskFactor {
  factor: string
  observed: string
  impact: 'Low' | 'Medium' | 'High' | 'Critical'
  explanation: string
}

export interface CryptoIntelligenceData {
  algorithms: ObservedAlgorithm[]

  keyExchange: string
  keyExchangeClass: AlgorithmClass
  forwardSecrecy: 'Enabled' | 'Partial' | 'Not observed'

  hybridObserved: boolean
  pqSignatureObserved: boolean
  hybridGroups: string[]
  kemParameterSets: string[]

  postQuantumReadiness: number
  readinessReasons: string[]

  quantumRisk: QuantumRiskLevel
  quantumRiskScore: number
  riskFactors: QuantumRiskFactor[]

  migrationTargets: Array<{ name: string; standard: string; replaces: string; rationale: string }>
}

// ─── Pattern catalogues ───────────────────────────────────────────────────────

const PQ_GROUP_PATTERNS = [/x25519(?:mlkem|kyber)/i, /ml[-_]?kem/i, /kyber/i, /secp\d+r1mlkem/i, /frodo/i, /bike/i, /hqc/i]
const PQ_SIGNATURE_PATTERNS = [/ml[-_]?dsa/i, /dilithium/i, /slh[-_]?dsa/i, /sphincs/i, /falcon/i]

export const isPostQuantumGroup = (value: string | null | undefined): boolean =>
  Boolean(value) && PQ_GROUP_PATTERNS.some((pattern) => pattern.test(value as string))

export const isPostQuantumSignature = (value: string | null | undefined): boolean =>
  Boolean(value) && PQ_SIGNATURE_PATTERNS.some((pattern) => pattern.test(value as string))

/** Symmetric key length read from the negotiated suite name. */
export function symmetricStrength(cipherSuite: string | null | undefined): number | null {
  if (!cipherSuite) return null
  if (/_256_|AES256|CHACHA20/i.test(cipherSuite)) return 256
  if (/_128_|AES128/i.test(cipherSuite)) return 128
  return null
}

// ─── Algorithm catalogue ──────────────────────────────────────────────────────

function catalogueAlgorithms(tls: TlsIntelligence, cert: CertificateIntelligence): ObservedAlgorithm[] {
  const algorithms: ObservedAlgorithm[] = []

  // Symmetric AEAD. Grover halves the effective key length, so a 128-bit
  // cipher is reported at its true 64-bit post-quantum margin rather than
  // waved through as quantum-safe.
  const cipher = tls.negotiatedCipher ?? ''
  const bits = symmetricStrength(cipher)
  if (/AES_256_GCM|AES256-GCM/i.test(cipher)) {
    algorithms.push({
      name: 'AES-256-GCM',
      role: 'Symmetric encryption',
      classification: 'Quantum Safe',
      quantumVulnerable: false,
      postQuantumBits: 128,
      detail: 'Grover reduces 256-bit symmetric strength to a 128-bit margin — at the recommended level.',
      evidenceSource: 'negotiated cipher suite',
    })
  } else if (/AES_128_GCM|AES128-GCM/i.test(cipher)) {
    algorithms.push({
      name: 'AES-128-GCM',
      role: 'Symmetric encryption',
      classification: 'Classical',
      quantumVulnerable: true,
      postQuantumBits: 64,
      detail: 'Grover reduces 128-bit symmetric strength to a 64-bit margin — below the 128-bit target.',
      evidenceSource: 'negotiated cipher suite',
    })
  } else if (/CHACHA20/i.test(cipher)) {
    algorithms.push({
      name: 'ChaCha20-Poly1305',
      role: 'Symmetric encryption',
      classification: 'Quantum Safe',
      quantumVulnerable: false,
      postQuantumBits: 128,
      detail: 'Grover reduces 256-bit symmetric strength to a 128-bit margin — at the recommended level.',
      evidenceSource: 'negotiated cipher suite',
    })
  } else if (bits) {
    algorithms.push({
      name: `Symmetric ${bits}-bit`,
      role: 'Symmetric encryption',
      classification: bits >= 256 ? 'Quantum Safe' : 'Classical',
      quantumVulnerable: bits < 256,
      postQuantumBits: bits / 2,
      detail: `Grover halves symmetric strength to a ${bits / 2}-bit margin.`,
      evidenceSource: 'negotiated cipher suite',
    })
  }

  // Certificate public key.
  if (cert.publicKeyAlgorithm) {
    const algorithm = cert.publicKeyAlgorithm
    const pq = isPostQuantumSignature(algorithm)
    const isEd25519 = /ed25519/i.test(algorithm)
    const isRsa = /rsa/i.test(algorithm)
    const weakRsa = isRsa && cert.publicKeySize > 0 && cert.publicKeySize < 2048
    algorithms.push({
      name: algorithm,
      role: 'Certificate public key',
      classification: pq ? 'Quantum Safe' : weakRsa ? 'Deprecated' : 'Classical',
      quantumVulnerable: !pq,
      postQuantumBits: pq ? null : 0,
      detail: pq
        ? 'Post-quantum signature algorithm — resistant to Shor’s algorithm.'
        : weakRsa
          ? `${cert.publicKeySize}-bit RSA is below current classical guidance and fully broken by a CRQC.`
          : isEd25519 || /ec|ecdsa/i.test(algorithm)
            ? 'Elliptic-curve key — the private key is recoverable by Shor’s algorithm.'
            : 'Classical public key — recoverable by Shor’s algorithm.',
      evidenceSource: 'leaf certificate',
    })
  }

  // Signature hash from the certificate's signatureAlgorithm OID name.
  const hashMatch = cert.signatureAlgorithm?.match(/SHA-?(1|224|256|384|512)/i)
  if (hashMatch) {
    const hashBits = hashMatch[1]
    const legacy = hashBits === '1'
    algorithms.push({
      name: legacy ? 'SHA-1' : `SHA-${hashBits}`,
      role: 'Hash',
      classification: legacy ? 'Deprecated' : hashBits === '224' ? 'Legacy' : 'Quantum Safe',
      quantumVulnerable: legacy || hashBits === '224',
      postQuantumBits: legacy ? 0 : Math.floor(Number(hashBits) / 2),
      detail: legacy
        ? 'SHA-1 is collision-broken classically and must not be used for signatures.'
        : `Grover reduces the preimage margin to ${Math.floor(Number(hashBits) / 2)} bits.`,
      evidenceSource: 'certificate signature algorithm',
    })
  }

  // Key agreement — one entry per accepted named group.
  for (const group of tls.hybridGroups) {
    algorithms.push({
      name: HYBRID_GROUP_KEM[group] ?? 'ML-KEM',
      role: 'Key encapsulation',
      classification: 'Hybrid',
      quantumVulnerable: false,
      postQuantumBits: null,
      detail: `Hybrid ${group}: classical ECDHE combined with FIPS 203 ML-KEM. Resists harvest-now-decrypt-later.`,
      evidenceSource: 'named-group probe',
    })
  }
  for (const group of tls.classicalGroups) {
    algorithms.push({
      name: group,
      role: 'Key agreement',
      classification: 'Classical',
      quantumVulnerable: true,
      postQuantumBits: 0,
      detail: 'Classical elliptic-curve key agreement — the shared secret is recoverable by Shor’s algorithm.',
      evidenceSource: 'named-group probe',
    })
  }

  // Transport protocol versions actually accepted.
  for (const protocol of tls.supportedProtocols) {
    const legacy = protocol === 'TLSv1' || protocol === 'TLSv1.1'
    algorithms.push({
      name: protocol.replace('TLSv', 'TLS '),
      role: 'Transport protocol',
      classification: legacy ? 'Deprecated' : protocol === 'TLSv1.2' ? 'Legacy' : 'Classical',
      quantumVulnerable: false,
      postQuantumBits: null,
      detail: legacy
        ? 'Deprecated protocol version — enables downgrade attacks and fails modern audits.'
        : protocol === 'TLSv1.3'
          ? 'Current protocol version; the one hybrid PQ groups deploy on.'
          : 'Supported but superseded by TLS 1.3.',
      evidenceSource: 'per-version handshake probe',
    })
  }

  return algorithms
}

// ─── Post-quantum readiness ───────────────────────────────────────────────────

/**
 * Deliberately conservative: a target scores 0 unless a hybrid/PQ group or PQ
 * signature is actually observed. Crypto-agility signals earn a small
 * "ready to move" allowance — never a readiness claim.
 */
export function computeReadiness(
  tls: TlsIntelligence,
  cert: CertificateIntelligence,
  hstsSecure: boolean,
): { score: number; hybridObserved: boolean; pqSignatureObserved: boolean; reasons: string[] } {
  const reasons: string[] = []

  const hybridObserved =
    tls.hybridGroups.length > 0 ||
    isPostQuantumGroup(tls.handshake?.negotiatedCurve) ||
    isPostQuantumGroup(tls.handshake?.keyExchange) ||
    isPostQuantumGroup(tls.negotiatedCipher)

  const pqSignatureObserved =
    isPostQuantumSignature(cert.signatureAlgorithm) ||
    isPostQuantumSignature(cert.publicKeyAlgorithm) ||
    isPostQuantumSignature(tls.handshake?.signatureAlgorithm)

  let score = 0

  if (hybridObserved) {
    score += 55
    reasons.push(
      tls.hybridGroups.length
        ? `Hybrid post-quantum key agreement accepted: ${tls.hybridGroups.join(', ')}.`
        : 'Hybrid post-quantum key agreement negotiated in the TLS handshake.',
    )
  } else {
    reasons.push('No hybrid or post-quantum key agreement offered at the public edge.')
  }

  if (pqSignatureObserved) {
    score += 30
    reasons.push('Post-quantum signature algorithm present in the served certificate chain.')
  } else {
    reasons.push('Certificate chain is signed with classical algorithms only.')
  }

  if (tls.supportedProtocols.includes('TLSv1.3')) {
    score += 12
    reasons.push('TLS 1.3 is the protocol PQ hybrid groups deploy on — the prerequisite is met.')
  }
  if (cert.validityDays > 0 && cert.validityDays <= 100) {
    score += 8
    reasons.push('Short-lived automated certificates enable fast algorithm rollover.')
  }
  if (cert.signedCertificateTimestamps) {
    score += 3
    reasons.push('Certificate Transparency participation supports auditable re-issuance.')
  }
  if (hstsSecure) {
    score += 3
    reasons.push('Enforced HTTPS narrows the downgrade path during a hybrid rollout.')
  }

  return { score: clampScore(score), hybridObserved, pqSignatureObserved, reasons }
}

// ─── Quantum Risk Engine ──────────────────────────────────────────────────────

/**
 * Evaluates each observed primitive and explains the resulting risk level.
 * The verdict is the worst factor, not an average, because a single fully
 * recoverable key exchange is not offset by good hygiene elsewhere.
 */
export function computeQuantumRisk(
  tls: TlsIntelligence,
  cert: CertificateIntelligence,
  hybridObserved: boolean,
): { level: QuantumRiskLevel; score: number; factors: QuantumRiskFactor[] } {
  const factors: QuantumRiskFactor[] = []

  // Key exchange — the harvest-now-decrypt-later surface.
  if (hybridObserved) {
    factors.push({
      factor: 'Key exchange',
      observed: tls.hybridGroups.join(', ') || 'hybrid group',
      impact: 'Low',
      explanation:
        'Hybrid ML-KEM key agreement means session secrets are not recoverable by Shor’s algorithm. Traffic captured today stays protected.',
    })
  } else if (tls.classicalGroups.length || tls.forwardSecrecy) {
    factors.push({
      factor: 'Key exchange',
      observed: tls.classicalGroups.join(', ') || tls.handshake?.keyExchange || 'classical ECDHE',
      impact: 'Critical',
      explanation:
        'Classical elliptic-curve key agreement. A cryptographically relevant quantum computer recovers the shared secret, so recorded sessions become readable retroactively (harvest-now-decrypt-later).',
    })
  }

  // Static RSA key transport — worse than ECDHE, no forward secrecy at all.
  if (tls.staticRsaAccepted) {
    factors.push({
      factor: 'Static RSA key transport',
      observed: 'RSA key-exchange suites accepted',
      impact: 'Critical',
      explanation:
        'Static RSA provides no forward secrecy at all. One private-key compromise — classical or quantum — decrypts every recorded session.',
    })
  }

  // Certificate public key.
  if (cert.publicKeyAlgorithm) {
    const pq = isPostQuantumSignature(cert.publicKeyAlgorithm)
    const weakRsa = /rsa/i.test(cert.publicKeyAlgorithm) && cert.publicKeySize > 0 && cert.publicKeySize < 2048
    factors.push({
      factor: 'Certificate public key',
      observed: `${cert.publicKeyAlgorithm}${cert.publicKeySize ? ` (${cert.publicKeySize}-bit)` : ''}`,
      impact: pq ? 'Low' : weakRsa ? 'Critical' : 'High',
      explanation: pq
        ? 'Post-quantum signature algorithm; authentication survives a CRQC.'
        : weakRsa
          ? `${cert.publicKeySize}-bit RSA is already below classical guidance and is trivially broken by Shor’s algorithm.`
          : 'Classical public-key cryptography. Potentially vulnerable to Shor’s algorithm once a cryptographically relevant quantum computer exists. Impersonation requires an attacker active at that time, so exposure is lower than for key exchange.',
    })
  }

  // Signature hash.
  const hashMatch = cert.signatureAlgorithm?.match(/SHA-?(1|224|256|384|512)/i)
  if (hashMatch) {
    const legacy = hashMatch[1] === '1'
    factors.push({
      factor: 'Signature hash',
      observed: legacy ? 'SHA-1' : `SHA-${hashMatch[1]}`,
      impact: legacy ? 'Critical' : 'Low',
      explanation: legacy
        ? 'SHA-1 is collision-broken classically; no quantum computer is required to forge.'
        : `Grover halves preimage resistance to ${Math.floor(Number(hashMatch[1]) / 2)} bits, which remains adequate.`,
    })
  }

  // Symmetric encryption.
  const bits = symmetricStrength(tls.negotiatedCipher)
  if (bits) {
    factors.push({
      factor: 'Symmetric encryption',
      observed: tls.negotiatedCipher ?? `${bits}-bit`,
      impact: bits >= 256 ? 'Low' : 'Medium',
      explanation:
        bits >= 256
          ? 'Grover leaves a 128-bit margin — at the recommended post-quantum level.'
          : 'Grover leaves only a 64-bit margin, below the 128-bit post-quantum target.',
    })
  }

  // Protocol version.
  if (tls.legacyProtocols.length) {
    factors.push({
      factor: 'Protocol version',
      observed: tls.legacyProtocols.join(', '),
      impact: 'High',
      explanation:
        'Deprecated TLS versions remain negotiable, allowing downgrade to weaker key exchange and blocking hybrid PQ deployment.',
    })
  }

  const weights: Record<QuantumRiskFactor['impact'], number> = { Low: 0, Medium: 40, High: 70, Critical: 100 }
  const score = factors.length ? Math.max(...factors.map((factor) => weights[factor.impact])) : 0
  const level: QuantumRiskLevel = score >= 100 ? 'Critical' : score >= 70 ? 'High' : score >= 40 ? 'Medium' : 'Low'

  return { level, score, factors }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

export async function runCryptoEngine(
  tls: TlsIntelligence,
  cert: CertificateIntelligence,
  hstsSecure: boolean,
): Promise<EngineResult<CryptoIntelligenceData>> {
  return runEngine(
    'cryptographic-intelligence',
    {
      algorithms: [],
      keyExchange: 'unknown',
      keyExchangeClass: 'Classical' as AlgorithmClass,
      forwardSecrecy: 'Not observed' as const,
      hybridObserved: false,
      pqSignatureObserved: false,
      hybridGroups: [],
      kemParameterSets: [],
      postQuantumReadiness: 0,
      readinessReasons: [],
      quantumRisk: 'Critical' as QuantumRiskLevel,
      quantumRiskScore: 100,
      riskFactors: [],
      migrationTargets: [],
    },
    async () => {
      const evidence: Evidence[] = []
      const notes: string[] = []

      const algorithms = catalogueAlgorithms(tls, cert)
      const readiness = computeReadiness(tls, cert, hstsSecure)
      const risk = computeQuantumRisk(tls, cert, readiness.hybridObserved)

      const keyExchange = tls.primaryGroup
        ? tls.hybridGroups.length
          ? `Hybrid ECDHE + ML-KEM (${tls.primaryGroup})`
          : `ECDHE (${tls.primaryGroup})`
        : tls.handshake?.keyExchange && tls.handshake.keyExchange !== 'unknown'
          ? tls.handshake.keyExchange
          : tls.negotiatedProtocol === 'TLSv1.3'
            ? 'ECDHE (TLS 1.3 ephemeral)'
            : 'unknown'

      // Migration targets are listed only for primitives actually observed.
      const migrationTargets: CryptoIntelligenceData['migrationTargets'] = []
      if (!readiness.hybridObserved && tls.handshake) {
        migrationTargets.push({
          name: 'ML-KEM-768',
          standard: 'FIPS 203',
          replaces: tls.classicalGroups[0] || keyExchange.split(' (')[0] || 'classical key exchange',
          rationale: 'Deploy as the hybrid X25519MLKEM768 group; supported by current TLS stacks and CDNs today.',
        })
      }
      if (!readiness.pqSignatureObserved && cert.publicKeyAlgorithm) {
        const isEc = /ec|ecdsa|prime|p-2|p-3/i.test(cert.publicKeyAlgorithm)
        const level5 = (isEc && cert.publicKeySize >= 384) || (!isEc && cert.publicKeySize >= 7680)
        migrationTargets.push({
          name: level5 ? 'ML-DSA-87' : 'ML-DSA-65',
          standard: 'FIPS 204',
          replaces: `${cert.publicKeyAlgorithm} leaf signature`,
          rationale: `Parameter set matched to the classical security level the current ${cert.publicKeyAlgorithm} key targets.`,
        })
      }
      if (!migrationTargets.length) {
        migrationTargets.push({
          name: 'Sustain hybrid deployment',
          standard: 'NIST SP 1800-38C',
          replaces: 'no classical-only primitive observed at the edge',
          rationale: 'Maintain the hybrid group and extend the same posture to internal services.',
        })
      }

      const data: CryptoIntelligenceData = {
        algorithms,
        keyExchange,
        keyExchangeClass: readiness.hybridObserved ? 'Hybrid' : 'Classical',
        forwardSecrecy: tls.forwardSecrecy ? (tls.staticRsaAccepted ? 'Partial' : 'Enabled') : 'Not observed',
        hybridObserved: readiness.hybridObserved,
        pqSignatureObserved: readiness.pqSignatureObserved,
        hybridGroups: tls.hybridGroups,
        kemParameterSets: Array.from(
          new Set(tls.hybridGroups.map((group) => HYBRID_GROUP_KEM[group]).filter(Boolean)),
        ),
        postQuantumReadiness: readiness.score,
        readinessReasons: readiness.reasons,
        quantumRisk: risk.level,
        quantumRiskScore: risk.score,
        riskFactors: risk.factors,
        migrationTargets,
      }

      evidence.push({
        label: 'Observed algorithms',
        observedValue: algorithms.map((algorithm) => algorithm.name).join(', ') || 'none',
        detectionMethod: 'Derived',
        evidenceSource: 'TLS handshake + certificate + named-group probe',
        confidence: 100,
      })
      evidence.push({
        label: 'Quantum risk',
        observedValue: `${risk.level} (${risk.factors.length} factor${risk.factors.length === 1 ? '' : 's'})`,
        detectionMethod: 'Derived',
        evidenceSource: 'Quantum Risk Engine',
        confidence: 95,
      })
      if (readiness.hybridObserved) {
        notes.push(`Hybrid key encapsulation in use: ${data.kemParameterSets.join(', ') || 'ML-KEM'}.`)
      }

      return {
        data,
        ok: algorithms.length > 0,
        confidence: clampScore(algorithms.length ? 95 : 20),
        evidence,
        notes,
        error: null,
      }
    },
  )
}
