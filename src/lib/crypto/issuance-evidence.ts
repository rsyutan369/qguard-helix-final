export const ISSUANCE_UNAVAILABLE = {
  code: 'CRYPTO_ISSUANCE_UNAVAILABLE',
  message: 'Key and certificate issuance require a configured provider that retains private keys and verifies issued material. Use your organization’s approved KMS or certificate authority.',
} as const

export function isIssuanceAction(action: string) {
  return ['key', 'generate-key', 'pki', 'generate-pki'].includes(action.trim().toLowerCase())
}

/**
 * The retired Express issuer recorded these markers for random bytes. PKI rows
 * from the same service carried metadata only, with no signed certificate.
 * Keep historical records available for review, but exclude them from key
 * and certificate evidence until actual material can be verified.
 */
export function isUnverifiedIssuanceRecord(row: { algorithm?: unknown; entropy_source?: unknown; quality_score?: unknown }) {
  const algorithm = String(row.algorithm ?? '').trim().toUpperCase()
  if (algorithm.startsWith('PKI-')) return true
  return ['ML-KEM', 'ML-DSA', 'SPHINCS+', 'HYBRID'].includes(algorithm)
    && String(row.entropy_source ?? '').trim().toUpperCase() === 'QRNG'
    && Number(row.quality_score) === 0.992
}
