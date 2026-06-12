import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'

export type VaultKemName = 'ML-KEM-768' | 'ML-KEM-1024'
export type VaultKexName = VaultKemName | `X25519+${VaultKemName}`

export const CURRENT_VAULT_KEM: VaultKemName = 'ML-KEM-1024'
export const CURRENT_VAULT_SECURITY_LEVEL = 'NIST-FIPS-203-Level-5'

export const ML_KEM_PUBLIC_KEY_BYTES: Record<VaultKemName, number> = {
  'ML-KEM-768': 1184,
  'ML-KEM-1024': 1568,
}

export const ML_KEM_SECRET_KEY_BYTES: Record<VaultKemName, number> = {
  'ML-KEM-768': 2400,
  'ML-KEM-1024': 3168,
}

export const ML_KEM_CIPHERTEXT_BYTES: Record<VaultKemName, number> = {
  'ML-KEM-768': 1088,
  'ML-KEM-1024': 1568,
}

type VaultKemPrimitive = typeof ml_kem768

export function isVaultKemName(value: unknown): value is VaultKemName {
  return value === 'ML-KEM-768' || value === 'ML-KEM-1024'
}

function preferredKemName(value: unknown): VaultKemName | null {
  if (typeof value !== 'string') return null
  if (value.includes('ML-KEM-1024')) return 'ML-KEM-1024'
  if (value.includes('ML-KEM-768')) return 'ML-KEM-768'
  return null
}

function resolveByLength(
  actualLength: number,
  lengths: Record<VaultKemName, number>,
  preferred?: unknown,
): VaultKemName {
  const preferredName = preferredKemName(preferred)
  if (preferredName && lengths[preferredName] === actualLength) return preferredName

  for (const name of Object.keys(lengths) as VaultKemName[]) {
    if (lengths[name] === actualLength) return name
  }

  throw new Error(`UNSUPPORTED_ML_KEM_KEY_LENGTH:${actualLength}`)
}

export function resolveKemNameFromPublicKey(publicKey: Uint8Array, preferred?: unknown): VaultKemName {
  return resolveByLength(publicKey.length, ML_KEM_PUBLIC_KEY_BYTES, preferred)
}

export function resolveKemNameFromSecretKey(secretKey: Uint8Array, preferred?: unknown): VaultKemName {
  return resolveByLength(secretKey.length, ML_KEM_SECRET_KEY_BYTES, preferred)
}

export function resolveKemNameFromCiphertext(ciphertext: Uint8Array, preferred?: unknown): VaultKemName {
  return resolveByLength(ciphertext.length, ML_KEM_CIPHERTEXT_BYTES, preferred)
}

export function kemForName(name: VaultKemName): VaultKemPrimitive {
  return name === 'ML-KEM-1024' ? ml_kem1024 : ml_kem768
}

export function kemForPublicKey(publicKey: Uint8Array, preferred?: unknown) {
  const name = resolveKemNameFromPublicKey(publicKey, preferred)
  return { name, kem: kemForName(name) }
}

export function kemForSecretKey(secretKey: Uint8Array, preferred?: unknown) {
  const name = resolveKemNameFromSecretKey(secretKey, preferred)
  return { name, kem: kemForName(name) }
}

export function kemForCiphertext(ciphertext: Uint8Array, preferred?: unknown) {
  const name = resolveKemNameFromCiphertext(ciphertext, preferred)
  return { name, kem: kemForName(name) }
}

export function kexName(kem: VaultKemName, hybrid: boolean): VaultKexName {
  return hybrid ? `X25519+${kem}` : kem
}

export function securityLevelForKem(kem: VaultKemName): string {
  return kem === 'ML-KEM-1024' ? CURRENT_VAULT_SECURITY_LEVEL : 'NIST-FIPS-203-Level-3'
}
