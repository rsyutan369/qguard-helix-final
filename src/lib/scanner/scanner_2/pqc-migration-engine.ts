/**
 * QGuard PQC Migration Recommendation Engine
 * Maps classical cryptographic algorithms to post-quantum replacements
 * and generates migration guidance for detected vulnerabilities.
 */

import type { ClassicalAlgorithm } from '@/types/quantum.types'

export interface PQCRecommendation {
  classicalAlgorithm: ClassicalAlgorithm
  recommendedPQC: string
  alternativePQC: string[]
  migrationType: string
  migrationComplexity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  migrationSteps: string[]
  nistStandard: string
  estimatedEffort: string
}

/**
 * Complete mapping of classical algorithms to PQC replacements
 */
const PQC_MIGRATION_MAP: Record<string, PQCRecommendation> = {
  'RSA-1024': {
    classicalAlgorithm: 'RSA-1024',
    recommendedPQC: 'ML-KEM-768 (FIPS 203)',
    alternativePQC: ['FrodoKEM', 'Classic McEliece', 'NTRU', 'HQC'],
    migrationType: 'Key Exchange / Encryption Replacement',
    migrationComplexity: 'CRITICAL',
    migrationSteps: [
      'Immediately revoke all RSA-1024 keys',
      'Deploy ML-KEM-768 key encapsulation',
      'Issue post-quantum certificates',
      'Update all dependent services',
      'Verify no RSA-1024 fallback paths remain',
    ],
    nistStandard: 'FIPS 203 (ML-KEM)',
    estimatedEffort: '1-2 weeks (urgent)',
  },
  'RSA-2048': {
    classicalAlgorithm: 'RSA-2048',
    recommendedPQC: 'ML-KEM-768 (FIPS 203)',
    alternativePQC: ['FrodoKEM', 'BIKE', 'HQC', 'Classic McEliece'],
    migrationType: 'TLS Key Exchange Replacement',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Deploy hybrid TLS (X25519 + ML-KEM-768)',
      'Issue post-quantum certificates from PQC-ready CA',
      'Rotate classical RSA certificates',
      'Disable RSA key exchange on servers',
      'Monitor for compatibility issues',
    ],
    nistStandard: 'FIPS 203 (ML-KEM)',
    estimatedEffort: '2-4 weeks',
  },
  'RSA-4096': {
    classicalAlgorithm: 'RSA-4096',
    recommendedPQC: 'ML-KEM-1024 (FIPS 203)',
    alternativePQC: ['FrodoKEM-1344', 'Classic McEliece'],
    migrationType: 'High-Security Key Exchange Replacement',
    migrationComplexity: 'MEDIUM',
    migrationSteps: [
      'Plan hybrid deployment with ML-KEM-1024',
      'Test PQC key exchange performance',
      'Deploy hybrid TLS configuration',
      'Phase out RSA-4096 over transition period',
    ],
    nistStandard: 'FIPS 203 (ML-KEM)',
    estimatedEffort: '3-6 weeks',
  },
  'ECC-P256': {
    classicalAlgorithm: 'ECC-P256',
    recommendedPQC: 'ML-KEM-768 (FIPS 203)',
    alternativePQC: ['BIKE', 'HQC', 'FrodoKEM'],
    migrationType: 'Elliptic Curve Key Exchange Replacement',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Deploy hybrid X25519 + ML-KEM-768 key exchange',
      'Update TLS configurations to prefer PQC suites',
      'Replace ECDH key agreement with ML-KEM',
      'Validate all endpoints support hybrid mode',
    ],
    nistStandard: 'FIPS 203 (ML-KEM)',
    estimatedEffort: '2-4 weeks',
  },
  'ECC-P384': {
    classicalAlgorithm: 'ECC-P384',
    recommendedPQC: 'ML-KEM-1024 (FIPS 203)',
    alternativePQC: ['FrodoKEM-1344', 'Classic McEliece'],
    migrationType: 'High-Assurance Key Exchange Replacement',
    migrationComplexity: 'MEDIUM',
    migrationSteps: [
      'Evaluate ML-KEM-1024 for security requirements',
      'Deploy hybrid key exchange',
      'Update certificate infrastructure',
      'Phase out ECC-P384 dependencies',
    ],
    nistStandard: 'FIPS 203 (ML-KEM)',
    estimatedEffort: '3-6 weeks',
  },
  'ECC-secp256k1': {
    classicalAlgorithm: 'ECC-secp256k1',
    recommendedPQC: 'ML-DSA-65 (FIPS 204)',
    alternativePQC: ['Falcon-512', 'SPHINCS+-SHA2-128f', 'XMSS'],
    migrationType: 'Blockchain Signature Migration',
    migrationComplexity: 'CRITICAL',
    migrationSteps: [
      'Monitor blockchain PQC standardization efforts',
      'Implement PQC signature verification alongside ECDSA',
      'Migrate wallet keys to quantum-resistant scheme',
      'Update smart contract signature verification',
      'Coordinate with chain governance for hard fork if needed',
    ],
    nistStandard: 'FIPS 204 (ML-DSA)',
    estimatedEffort: '6-12 months (ecosystem dependent)',
  },
  'ECDSA-P256': {
    classicalAlgorithm: 'ECDSA-P256',
    recommendedPQC: 'ML-DSA-44 (FIPS 204)',
    alternativePQC: ['Falcon-512', 'SPHINCS+-SHA2-128f'],
    migrationType: 'Digital Signature Replacement',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Generate ML-DSA-44 signing keys',
      'Deploy hybrid signatures (ECDSA + ML-DSA)',
      'Update signature verification in all consumers',
      'Rotate code signing certificates to PQC',
      'Disable ECDSA-only signature acceptance',
    ],
    nistStandard: 'FIPS 204 (ML-DSA)',
    estimatedEffort: '2-4 weeks',
  },
  'ECDSA-P384': {
    classicalAlgorithm: 'ECDSA-P384',
    recommendedPQC: 'ML-DSA-65 (FIPS 204)',
    alternativePQC: ['Falcon-1024', 'SPHINCS+-SHA2-192f'],
    migrationType: 'High-Assurance Signature Replacement',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Evaluate ML-DSA-65 for compliance requirements',
      'Deploy hybrid signature scheme',
      'Update PKI infrastructure',
      'Reissue government/enterprise certificates',
    ],
    nistStandard: 'FIPS 204 (ML-DSA)',
    estimatedEffort: '4-8 weeks',
  },
  'DH-1024': {
    classicalAlgorithm: 'DH-1024',
    recommendedPQC: 'ML-KEM-768 (FIPS 203)',
    alternativePQC: ['FrodoKEM', 'NTRU'],
    migrationType: 'Key Exchange Replacement (Urgent)',
    migrationComplexity: 'CRITICAL',
    migrationSteps: [
      'Immediately disable DH-1024 key exchange',
      'Deploy ML-KEM-768 or hybrid mode',
      'Update VPN and tunnel configurations',
      'Audit all services using DH parameters',
    ],
    nistStandard: 'FIPS 203 (ML-KEM)',
    estimatedEffort: '1-2 weeks (urgent)',
  },
  'DH-2048': {
    classicalAlgorithm: 'DH-2048',
    recommendedPQC: 'ML-KEM-768 (FIPS 203)',
    alternativePQC: ['FrodoKEM', 'BIKE', 'HQC'],
    migrationType: 'Key Exchange Replacement',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Deploy hybrid key exchange (DH + ML-KEM)',
      'Update VPN configurations to PQC',
      'Replace DH parameters in TLS configs',
      'Phase out classical DH over transition',
    ],
    nistStandard: 'FIPS 203 (ML-KEM)',
    estimatedEffort: '2-4 weeks',
  },
  'DSA-1024': {
    classicalAlgorithm: 'DSA-1024',
    recommendedPQC: 'ML-DSA-44 (FIPS 204)',
    alternativePQC: ['Falcon-512', 'SPHINCS+-SHA2-128f'],
    migrationType: 'Legacy Signature Replacement (Urgent)',
    migrationComplexity: 'CRITICAL',
    migrationSteps: [
      'Immediately stop using DSA-1024 for signing',
      'Generate ML-DSA-44 replacement keys',
      'Re-sign all artifacts with PQC signatures',
      'Remove DSA-1024 keys from authorized stores',
    ],
    nistStandard: 'FIPS 204 (ML-DSA)',
    estimatedEffort: '1-2 weeks (urgent)',
  },
  'DSA-2048': {
    classicalAlgorithm: 'DSA-2048',
    recommendedPQC: 'ML-DSA-44 (FIPS 204)',
    alternativePQC: ['Falcon-512', 'SPHINCS+-SHA2-128f'],
    migrationType: 'Signature Scheme Replacement',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Generate ML-DSA-44 signing keys',
      'Deploy hybrid signatures during transition',
      'Update key distribution infrastructure',
      'Phase out DSA-2048',
    ],
    nistStandard: 'FIPS 204 (ML-DSA)',
    estimatedEffort: '2-4 weeks',
  },
  'Ed25519': {
    classicalAlgorithm: 'Ed25519',
    recommendedPQC: 'ML-DSA-44 (FIPS 204)',
    alternativePQC: ['Falcon-512', 'SPHINCS+-SHA2-128f'],
    migrationType: 'SSH / Git Signature Migration',
    migrationComplexity: 'MEDIUM',
    migrationSteps: [
      'Monitor OpenSSH PQC key type support',
      'Generate ML-DSA-44 SSH keys when available',
      'Deploy hybrid SSH authentication',
      'Update authorized_keys infrastructure',
    ],
    nistStandard: 'FIPS 204 (ML-DSA)',
    estimatedEffort: '2-4 weeks (when tooling available)',
  },
  'X25519': {
    classicalAlgorithm: 'X25519',
    recommendedPQC: 'ML-KEM-768 (FIPS 203)',
    alternativePQC: ['BIKE', 'HQC', 'FrodoKEM'],
    migrationType: 'Key Exchange Hybrid Upgrade',
    migrationComplexity: 'MEDIUM',
    migrationSteps: [
      'Deploy hybrid X25519 + ML-KEM-768 key exchange',
      'Update TLS 1.3 to use hybrid groups',
      'Configure WireGuard/VPN for PQC key exchange',
      'Verify all endpoints support hybrid mode',
    ],
    nistStandard: 'FIPS 203 (ML-KEM)',
    estimatedEffort: '1-3 weeks',
  },
  'PGP-RSA': {
    classicalAlgorithm: 'PGP-RSA',
    recommendedPQC: 'ML-KEM-768 (FIPS 203) + ML-DSA-44 (FIPS 204)',
    alternativePQC: ['Falcon-512', 'SPHINCS+'],
    migrationType: 'PGP Key Migration',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Monitor OpenPGP PQC standardization',
      'Generate PQC-based PGP keys when supported',
      'Re-encrypt archived messages with PQC',
      'Update key servers and web of trust',
      'Revoke classical PGP keys',
    ],
    nistStandard: 'FIPS 203 + FIPS 204',
    estimatedEffort: '4-8 weeks (tooling dependent)',
  },
  'PGP-ECC': {
    classicalAlgorithm: 'PGP-ECC',
    recommendedPQC: 'ML-KEM-768 (FIPS 203) + ML-DSA-44 (FIPS 204)',
    alternativePQC: ['Falcon-512', 'SPHINCS+'],
    migrationType: 'PGP Key Migration',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Monitor OpenPGP PQC draft specifications',
      'Prepare PQC key generation workflow',
      'Plan re-encryption of sensitive archives',
      'Update key distribution channels',
    ],
    nistStandard: 'FIPS 203 + FIPS 204',
    estimatedEffort: '4-8 weeks',
  },
  'S/MIME-RSA': {
    classicalAlgorithm: 'S/MIME-RSA',
    recommendedPQC: 'ML-KEM-768 (FIPS 203)',
    alternativePQC: ['FrodoKEM', 'Classic McEliece'],
    migrationType: 'Enterprise Email Certificate Migration',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Request PQC S/MIME certificates from CA',
      'Deploy hybrid S/MIME during transition',
      'Update email client configurations',
      'Re-encrypt sensitive email archives',
      'Revoke classical S/MIME certificates',
    ],
    nistStandard: 'FIPS 203 (ML-KEM)',
    estimatedEffort: '4-8 weeks',
  },
  'SHA-1': {
    classicalAlgorithm: 'SHA-1',
    recommendedPQC: 'SHA-3-256 (Keccak)',
    alternativePQC: ['SHA-256', 'BLAKE3'],
    migrationType: 'Hash Function Upgrade',
    migrationComplexity: 'MEDIUM',
    migrationSteps: [
      'Replace SHA-1 with SHA-256 or SHA-3',
      'Update all integrity verification code',
      'Re-hash stored values',
      'Remove SHA-1 from allowed algorithms list',
    ],
    nistStandard: 'FIPS 180-4 / FIPS 202',
    estimatedEffort: '1-2 weeks',
  },
  'MD5': {
    classicalAlgorithm: 'MD5',
    recommendedPQC: 'SHA-3-256 (Keccak)',
    alternativePQC: ['SHA-256', 'BLAKE3'],
    migrationType: 'Hash Function Replacement (Urgent)',
    migrationComplexity: 'MEDIUM',
    migrationSteps: [
      'Immediately replace MD5 with SHA-256 or SHA-3',
      'Update all checksum verification',
      'Re-hash stored values',
      'Audit for MD5 usage in authentication',
    ],
    nistStandard: 'FIPS 180-4 / FIPS 202',
    estimatedEffort: '1 week',
  },
  'AES-128': {
    classicalAlgorithm: 'AES-128',
    recommendedPQC: 'AES-256',
    alternativePQC: ['AES-256-GCM', 'ChaCha20-Poly1305'],
    migrationType: 'Symmetric Key Size Upgrade',
    migrationComplexity: 'LOW',
    migrationSteps: [
      'Upgrade key generation to 256-bit',
      'Re-encrypt data with AES-256',
      'Update configuration to require AES-256 minimum',
    ],
    nistStandard: 'FIPS 197',
    estimatedEffort: '1 week',
  },
  'AES-256': {
    classicalAlgorithm: 'AES-256',
    recommendedPQC: 'AES-256 (quantum-resilient)',
    alternativePQC: [],
    migrationType: 'No Migration Needed',
    migrationComplexity: 'LOW',
    migrationSteps: [
      'No action required — AES-256 is quantum-resilient',
      'Ensure proper key management practices',
    ],
    nistStandard: 'FIPS 197',
    estimatedEffort: 'None',
  },
  '3DES': {
    classicalAlgorithm: '3DES',
    recommendedPQC: 'AES-256-GCM',
    alternativePQC: ['ChaCha20-Poly1305'],
    migrationType: 'Symmetric Cipher Replacement',
    migrationComplexity: 'MEDIUM',
    migrationSteps: [
      'Replace 3DES with AES-256-GCM',
      'Re-encrypt all 3DES-protected data',
      'Update hardware security modules if applicable',
      'Remove 3DES from cipher suite configurations',
    ],
    nistStandard: 'FIPS 197',
    estimatedEffort: '1-2 weeks',
  },
  'TLS-1.0': {
    classicalAlgorithm: 'TLS-1.0',
    recommendedPQC: 'TLS 1.3 with ML-KEM Hybrid',
    alternativePQC: ['TLS 1.3 with X25519Kyber768'],
    migrationType: 'Transport Protocol Upgrade (Urgent)',
    migrationComplexity: 'CRITICAL',
    migrationSteps: [
      'Immediately disable TLS 1.0',
      'Deploy TLS 1.3 with PQC key exchange',
      'Configure hybrid X25519 + ML-KEM-768',
      'Test all client compatibility',
      'Enable HSTS headers',
    ],
    nistStandard: 'RFC 8446 + FIPS 203',
    estimatedEffort: '1-2 weeks (urgent)',
  },
  'TLS-1.1': {
    classicalAlgorithm: 'TLS-1.1',
    recommendedPQC: 'TLS 1.3 with ML-KEM Hybrid',
    alternativePQC: ['TLS 1.3 with X25519Kyber768'],
    migrationType: 'Transport Protocol Upgrade',
    migrationComplexity: 'HIGH',
    migrationSteps: [
      'Disable TLS 1.1',
      'Deploy TLS 1.3 with PQC key exchange',
      'Configure hybrid key exchange groups',
      'Verify client compatibility',
    ],
    nistStandard: 'RFC 8446 + FIPS 203',
    estimatedEffort: '1-2 weeks',
  },
  'TLS-1.2': {
    classicalAlgorithm: 'TLS-1.2',
    recommendedPQC: 'TLS 1.3 with ML-KEM Hybrid',
    alternativePQC: ['TLS 1.2 with hybrid PQC extensions'],
    migrationType: 'Transport Protocol Enhancement',
    migrationComplexity: 'MEDIUM',
    migrationSteps: [
      'Upgrade to TLS 1.3 where possible',
      'Enable hybrid PQC key exchange groups',
      'Prefer PQC cipher suites in configuration',
      'Plan full TLS 1.2 deprecation timeline',
    ],
    nistStandard: 'RFC 8446 + FIPS 203',
    estimatedEffort: '2-4 weeks',
  },
}

/**
 * Get PQC migration recommendation for a classical algorithm
 */
export function getMigrationRecommendation(algorithm: string): PQCRecommendation | null {
  return PQC_MIGRATION_MAP[algorithm] || null
}

/**
 * Get all available PQC algorithms for reference
 */
export const PQC_ALGORITHMS = [
  { name: 'ML-KEM (CRYSTALS-Kyber)', type: 'Key Encapsulation', nist: 'FIPS 203', status: 'Standardized' },
  { name: 'ML-DSA (CRYSTALS-Dilithium)', type: 'Digital Signature', nist: 'FIPS 204', status: 'Standardized' },
  { name: 'Falcon', type: 'Digital Signature', nist: 'FIPS 206 (draft)', status: 'Standardized' },
  { name: 'SPHINCS+ (SLH-DSA)', type: 'Digital Signature', nist: 'FIPS 205', status: 'Standardized' },
  { name: 'Classic McEliece', type: 'Key Encapsulation', nist: 'Round 4', status: 'Under Evaluation' },
  { name: 'BIKE', type: 'Key Encapsulation', nist: 'Round 4', status: 'Under Evaluation' },
  { name: 'HQC', type: 'Key Encapsulation', nist: 'Round 4', status: 'Under Evaluation' },
  { name: 'NTRU', type: 'Key Encapsulation', nist: 'Legacy', status: 'Available' },
  { name: 'FrodoKEM', type: 'Key Encapsulation', nist: 'Alternative', status: 'Available' },
  { name: 'XMSS', type: 'Hash-Based Signature', nist: 'SP 800-208', status: 'Standardized (stateful)' },
  { name: 'LMS', type: 'Hash-Based Signature', nist: 'SP 800-208', status: 'Standardized (stateful)' },
]

export interface QuantumReadinessSummary {
  /** Share of OBSERVATIONS that need no migration, 0-100. */
  score: number
  /** Readiness band for `score`. Never a risk level — see the note below. */
  label: string
  color: string
  /** Observations needing migration, by cryptographic category. */
  assetsRequiringMigration: Record<string, number>
  /** Cryptographic observations scored. This is a FINDING count. */
  totalFindings: number
  /** Observations that need no migration. A FINDING count. */
  quantumSafeFindings: number
  /** Distinct scan targets the observations came from. An ASSET count. */
  totalAssets: number
  /** Distinct targets with no observation requiring migration. */
  quantumSafeAssets: number
  /** True when no observation was scored, so `score` asserts nothing. */
  notAssessed: boolean
}

/**
 * Quantum readiness over the cryptographic OBSERVATIONS in a scan.
 *
 * ── Two defects this signature exists to prevent ──────────────────────────
 *
 * 1. It returned `totalAssets: findings.length` and `quantumSafeAssets`, and
 *    the Quantum Posture card printed them verbatim as
 *    "3 of 16 inventoried asset(s) are already quantum-safe" — on a tenant with
 *    exactly ONE scanned asset. The numbers were finding counts wearing the
 *    word "asset". Both populations are now returned, each named for what it
 *    counts, and the distinct-target count is a real asset count.
 *
 * 2. Its bands ran "Quantum-Ready / Mostly Protected / At Risk / High Risk /
 *    Critical Risk" — three readiness labels and two RISK labels on one scale.
 *    A readiness of 19% rendered as "Critical Risk", which then sat two rows
 *    above Scanner_2's risk aggregate reading "moderate-risk": two contradictory
 *    risk verdicts from the same engine on the same evidence. The bands are now
 *    readiness labels throughout; risk is reported only by the risk engine.
 */
export function calculateQuantumReadiness(findings: {
  detectedAlgorithm: string
  threatLevel: string
  riskScore: number
  target?: { name?: string }
}[]): QuantumReadinessSummary {
  if (findings.length === 0) {
    /* Nothing was scored. This is NOT "fully quantum-ready" — it used to
       return 100, which turns an empty scan into a perfect posture. */
    return {
      score: 0,
      label: 'Not assessed',
      color: '#64748b',
      assetsRequiringMigration: {},
      totalFindings: 0,
      quantumSafeFindings: 0,
      totalAssets: 0,
      quantumSafeAssets: 0,
      notAssessed: true,
    }
  }

  const assetsRequiringMigration: Record<string, number> = {}
  const assetNeedsMigration = new Map<string, boolean>()
  let quantumSafeCount = 0

  for (const f of findings) {
    const asset = f.target?.name?.trim() || '(unattributed)'
    if (!assetNeedsMigration.has(asset)) assetNeedsMigration.set(asset, false)
    const rec = getMigrationRecommendation(f.detectedAlgorithm)
    if (rec && rec.migrationComplexity !== 'LOW') {
      const category = getCryptoCategory(f.detectedAlgorithm)
      assetsRequiringMigration[category] = (assetsRequiringMigration[category] || 0) + 1
      assetNeedsMigration.set(asset, true)
    } else {
      quantumSafeCount++
    }
  }

  const score = Math.round((quantumSafeCount / findings.length) * 100)

  let label: string
  let color: string
  if (score >= 80) { label = 'Quantum-Ready'; color = '#30d158' }
  else if (score >= 60) { label = 'Mostly Ready'; color = '#00d4ff' }
  else if (score >= 40) { label = 'Partially Ready'; color = '#ffcc00' }
  else if (score >= 20) { label = 'Early Stage'; color = '#ff6b35' }
  else { label = 'Not Started'; color = '#ff2d55' }

  return {
    score,
    label,
    color,
    assetsRequiringMigration,
    totalFindings: findings.length,
    quantumSafeFindings: quantumSafeCount,
    totalAssets: assetNeedsMigration.size,
    quantumSafeAssets: Array.from(assetNeedsMigration.values()).filter((needs) => !needs).length,
    notAssessed: false,
  }
}

function getCryptoCategory(algorithm: string): string {
  if (algorithm.startsWith('RSA') || algorithm.startsWith('DH')) return 'Key Exchange'
  if (algorithm.startsWith('ECC') || algorithm.startsWith('ECDSA') || algorithm.startsWith('DSA') || algorithm === 'Ed25519') return 'Digital Signatures'
  if (algorithm.startsWith('TLS')) return 'TLS Certificates'
  if (algorithm.startsWith('PGP') || algorithm.startsWith('S/MIME')) return 'Email Encryption'
  if (algorithm === 'X25519') return 'Key Agreement'
  if (algorithm.startsWith('AES') || algorithm === '3DES') return 'Symmetric Encryption'
  if (algorithm === 'SHA-1' || algorithm === 'MD5') return 'Hash Functions'
  return 'Other'
}
