import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js'
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js'
import { gcm } from '@noble/ciphers/aes.js'
import { buildMerkleIntegrity, verifyMerkleIntegrity, type MerkleIntegrityMeta } from './merkle-tree'
import {
  CURRENT_VAULT_KEM,
  type VaultKemName,
  type VaultKexName,
  kemForName,
  kemForPublicKey,
  kemForSecretKey,
  kexName,
  securityLevelForKem,
} from './kem-profile'

/**
 * Zero-Knowledge Client Cryptography for the Quantum Vault.
 *
 * Browser runtime note:
 * - The active implementation uses audited noble primitives for local, zero-
 *   knowledge operation in Vite/browser builds.
 * - Algorithm names and envelope metadata are OQS/OpenSSL-provider compatible
 *   so a native liboqs / oqs-provider backend can replace the primitive adapter
 *   without changing stored vault metadata.
 */

export interface ZKMasterKeys {
  encPublicKey: Uint8Array
  encSecretKey: Uint8Array
  signPublicKey: Uint8Array
  signSecretKey: Uint8Array
  x25519Public?: Uint8Array
  x25519Secret?: Uint8Array
  ed25519Public?: Uint8Array
  ed25519Secret?: Uint8Array
}

export interface WrappedMasterKeys {
  wrapped_bundle: string
  enc_public_key: string
  sign_public_key: string
}

export interface VaultEnvelopeMeta {
  version: 2
  mode: 'hybrid' | 'ml-kem'
  kem: VaultKemName
  kex: VaultKexName
  securityLevel?: string
  signature: 'Ed25519+ML-DSA-65' | 'ML-DSA-65'
  symmetric: 'AES-256-GCM'
  kdf: 'HKDF-SHA3-256'
  hash: 'SHA3-256'
  encryptedHash: 'SHA3-512'
  merkle?: MerkleIntegrityMeta
  wrappedDataKey: string
  wrapNonce: string
  wrapSalt: string
  x25519EphemeralPublic?: string
  aadHash: string
}

export interface LocalEncryptionResult {
  encryptedData: Uint8Array
  kemCiphertext: string
  aesNonce: string
  aesAuthTag: string
  integrityHash: string
  encryptedIntegrityHash: string
  aadHash: string
  envelopeMeta: VaultEnvelopeMeta
  merkleIntegrity: MerkleIntegrityMeta
  originalSize: number
  algorithm: string
}

export interface HybridSignature {
  version: 1
  algorithm: 'Ed25519+ML-DSA-65' | 'ML-DSA-65'
  mldsa65: string
  ed25519?: string
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function fromHex(hex: string): Uint8Array {
  const matches = hex.match(/.{1,2}/g)
  if (!matches) return new Uint8Array(0)
  return new Uint8Array(matches.map((byte) => parseInt(byte, 16)))
}

function randomBytes(length: number): Uint8Array {
  return window.crypto.getRandomValues(new Uint8Array(length))
}

function encodeBase64Json(value: unknown): string {
  const json = JSON.stringify(value)
  const bytes = new TextEncoder().encode(json)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function decodeBase64Json<T>(value: string): T {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return JSON.parse(new TextDecoder().decode(bytes)) as T
}

function deriveWrappingKey({
  mlkemSecret,
  x25519Secret,
  salt,
  aadHash,
}: {
  mlkemSecret: Uint8Array
  x25519Secret?: Uint8Array
  salt: Uint8Array
  aadHash: Uint8Array
}): Uint8Array {
  const input = new Uint8Array(mlkemSecret.length + (x25519Secret?.length || 0))
  input.set(mlkemSecret, 0)
  if (x25519Secret) input.set(x25519Secret, mlkemSecret.length)
  return hkdf(
    sha3_256,
    input,
    salt,
    new TextEncoder().encode(`qguard-vault-data-key-wrap:${toHex(aadHash)}`),
    32,
  )
}

function extractGcmTag(ciphertextWithTag: Uint8Array): string {
  return ciphertextWithTag.length >= 16 ? toHex(ciphertextWithTag.slice(-16)) : ''
}

function normalizeEnvelopeMeta(meta?: VaultEnvelopeMeta | Record<string, unknown> | string | null): VaultEnvelopeMeta | null {
  if (!meta) return null
  if (typeof meta === 'string') {
    try {
      return JSON.parse(meta) as VaultEnvelopeMeta
    } catch {
      return null
    }
  }
  return meta as VaultEnvelopeMeta
}

/**
 * Argon2id KEK profile. Memory-hard key stretching resists GPU/ASIC and quantum
 * (Grover) brute-force of a *harvested* wrapped-key bundle far better than PBKDF2.
 * Tuned for an interactive browser unlock: ~19 MiB, 2 passes (OWASP-balanced).
 * Params are persisted in the bundle so they can be raised later without breaking
 * already-wrapped vaults.
 */
export const ARGON2_KEK_PROFILE = { t: 2, m: 19456, p: 1 } as const

async function deriveArgon2Material(
  passphrase: string,
  salt: Uint8Array,
  params: { t: number; m: number; p: number },
): Promise<Uint8Array> {
  return argon2idAsync(passphrase, salt, { t: params.t, m: params.m, p: params.p, dkLen: 32 })
}

/** True if a stored bundle predates the Argon2id KEK and should be re-wrapped on unlock. */
export function bundleNeedsKdfUpgrade(wrappedBundleB64: string): boolean {
  try {
    const bundle = JSON.parse(atob(wrappedBundleB64))
    return !String(bundle?.kdf ?? '').includes('Argon2id')
  } catch {
    return false
  }
}

async function derivePassphraseMaterial(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
  kdf?: string,
): Promise<Uint8Array> {
  if (kdf?.includes('SHA3-256')) {
    return pbkdf2Async(sha3_256, passphrase, salt, { c: iterations, dkLen: 32 })
  }

  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits']
  )

  const stretchedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    baseKey,
    256
  )

  return new Uint8Array(stretchedBits)
}

/**
 * Generates a new set of master keys for zero-knowledge vault access.
 */
export async function generateMasterKeys(): Promise<ZKMasterKeys> {
  const encKeys = kemForName(CURRENT_VAULT_KEM).keygen()
  const signKeys = ml_dsa65.keygen()
  const x25519Secret = x25519.utils.randomPrivateKey()
  const ed25519Secret = ed25519.utils.randomPrivateKey()

  return {
    encPublicKey: encKeys.publicKey,
    encSecretKey: encKeys.secretKey,
    signPublicKey: signKeys.publicKey,
    signSecretKey: signKeys.secretKey,
    x25519Public: x25519.getPublicKey(x25519Secret),
    x25519Secret,
    ed25519Public: ed25519.getPublicKey(ed25519Secret),
    ed25519Secret,
  }
}

/**
 * Wraps master keys with a passphrase for secure storage.
 */
export async function wrapMasterKeys(keys: ZKMasterKeys, passphrase: string): Promise<string> {
  const salt = randomBytes(32)
  const iv = randomBytes(12)
  const stretchedBits = await deriveArgon2Material(passphrase, salt, ARGON2_KEK_PROFILE)

  const wrappingMaterial = hkdf(
    sha3_256,
    stretchedBits,
    salt,
    new TextEncoder().encode('qguard-vault-master-key-wrap'),
    32,
  )
  stretchedBits.fill(0)

  const wrappingKey = await window.crypto.subtle.importKey(
    'raw',
    wrappingMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  )

  const payload = JSON.stringify({
    encSecretKey: toHex(keys.encSecretKey),
    signSecretKey: toHex(keys.signSecretKey),
    encPublicKey: toHex(keys.encPublicKey),
    signPublicKey: toHex(keys.signPublicKey),
    x25519Secret: keys.x25519Secret ? toHex(keys.x25519Secret) : undefined,
    x25519Public: keys.x25519Public ? toHex(keys.x25519Public) : undefined,
    ed25519Secret: keys.ed25519Secret ? toHex(keys.ed25519Secret) : undefined,
    ed25519Public: keys.ed25519Public ? toHex(keys.ed25519Public) : undefined,
  })

  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    new TextEncoder().encode(payload)
  )

  const bundle = {
    v: 3,
    kdf: 'Argon2id+HKDF-SHA3-256',
    argon2: { ...ARGON2_KEK_PROFILE },
    salt: toHex(salt),
    iv: toHex(iv),
    data: toHex(new Uint8Array(encrypted))
  }

  return btoa(JSON.stringify(bundle))
}

/**
 * Unwraps master keys using a passphrase.
 */
export async function unwrapMasterKeys(wrappedBundleB64: string, passphrase: string): Promise<ZKMasterKeys> {
  const bundle = JSON.parse(atob(wrappedBundleB64))
  const salt = fromHex(bundle.salt)
  const iv = fromHex(bundle.iv)
  const data = fromHex(bundle.data)
  const kdf: string = bundle.kdf || 'PBKDF2-SHA-256'

  // Dispatch on the stored KDF so existing bundles keep unwrapping after the
  // Argon2id upgrade: v3 uses Argon2id; v1/v2 fall back to PBKDF2.
  const stretchedBits = kdf.includes('Argon2id')
    ? await deriveArgon2Material(passphrase, salt, {
        t: bundle.argon2?.t ?? ARGON2_KEK_PROFILE.t,
        m: bundle.argon2?.m ?? ARGON2_KEK_PROFILE.m,
        p: bundle.argon2?.p ?? ARGON2_KEK_PROFILE.p,
      })
    : await derivePassphraseMaterial(passphrase, salt, bundle.iterations || 600000, kdf)

  const wrappingMaterial = bundle.v >= 2
    ? hkdf(
        sha3_256,
        stretchedBits,
        salt,
        new TextEncoder().encode('qguard-vault-master-key-wrap'),
        32,
      )
    : stretchedBits
  stretchedBits.fill(0)

  const wrappingKey = await window.crypto.subtle.importKey(
    'raw',
    wrappingMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  )
  
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    data
  )
  
  const payload = JSON.parse(new TextDecoder().decode(decrypted))
  
  return {
    encSecretKey: fromHex(payload.encSecretKey),
    signSecretKey: fromHex(payload.signSecretKey),
    encPublicKey: fromHex(payload.encPublicKey),
    signPublicKey: fromHex(payload.signPublicKey),
    x25519Secret: payload.x25519Secret ? fromHex(payload.x25519Secret) : undefined,
    x25519Public: payload.x25519Public ? fromHex(payload.x25519Public) : undefined,
    ed25519Secret: payload.ed25519Secret ? fromHex(payload.ed25519Secret) : undefined,
    ed25519Public: payload.ed25519Public ? fromHex(payload.ed25519Public) : undefined,
  }
}

/**
 * Local decryption for zero-knowledge files.
 */
export function decryptFileLocal(
  encryptedData: Uint8Array,
  kemCiphertextHex: string,
  aesNonceHex: string,
  secretKey: Uint8Array,
  expectedIntegrityHash?: string,
  envelopeMeta?: VaultEnvelopeMeta | Record<string, unknown> | string | null,
  x25519SecretKey?: Uint8Array,
): Uint8Array {
  const kemCiphertext = fromHex(kemCiphertextHex)
  const meta = normalizeEnvelopeMeta(envelopeMeta)
  const { kem } = kemForSecretKey(secretKey, meta?.kem || meta?.kex)
  const sharedSecret = kem.decapsulate(kemCiphertext, secretKey)
  const nonce = fromHex(aesNonceHex)
  let fileKey: Uint8Array

  if (meta?.wrappedDataKey && meta.wrapNonce && meta.wrapSalt) {
    let classicalSecret: Uint8Array | undefined
    if (meta.x25519EphemeralPublic && x25519SecretKey) {
      classicalSecret = x25519.getSharedSecret(x25519SecretKey, fromHex(meta.x25519EphemeralPublic))
    }
    const wrappingKey = deriveWrappingKey({
      mlkemSecret: sharedSecret,
      x25519Secret: classicalSecret,
      salt: fromHex(meta.wrapSalt),
      aadHash: fromHex(meta.aadHash || ''),
    })
    fileKey = gcm(wrappingKey, fromHex(meta.wrapNonce)).decrypt(fromHex(meta.wrappedDataKey))
    wrappingKey.fill(0)
    classicalSecret?.fill(0)
  } else {
    // Legacy vault files encrypted before the data-key-wrap envelope used the
    // first 32 bytes of the ML-KEM shared secret directly as the AES key.
    fileKey = sharedSecret.slice(0, 32)
  }
  
  const decrypted = gcm(fileKey, nonce).decrypt(encryptedData)
  fileKey.fill(0)
  sharedSecret.fill(0)
  
  if (expectedIntegrityHash) {
    const actualHash = toHex(sha3_256(decrypted))
    const legacyHash = toHex(sha256(decrypted))
    if (actualHash !== expectedIntegrityHash) {
      if (legacyHash === expectedIntegrityHash) return decrypted
      throw new Error('INTEGRITY_CHECK_FAILED')
    }
  }

  if (meta?.merkle && !verifyMerkleIntegrity(decrypted, meta.merkle)) {
    throw new Error('MERKLE_INTEGRITY_CHECK_FAILED')
  }
  
  return decrypted
}

/**
 * Local encryption for zero-knowledge files.
 */
export function encryptFileLocal(
  data: Uint8Array,
  recipientPublicKey: Uint8Array,
  recipientX25519Public?: Uint8Array,
): LocalEncryptionResult {
  const fileKey = randomBytes(32)
  const payloadNonce = randomBytes(12)
  const wrapNonce = randomBytes(12)
  const wrapSalt = randomBytes(32)
  const aad = new TextEncoder().encode(`qguard-vault-file:${data.length}:${Date.now()}`)
  const aadHash = sha3_256(aad)
  const merkleIntegrity = buildMerkleIntegrity(data)

  const encrypted = gcm(fileKey, payloadNonce).encrypt(data)
  const { name: kemName, kem } = kemForPublicKey(recipientPublicKey)
  const { sharedSecret, cipherText } = kem.encapsulate(recipientPublicKey)

  let ephemeralPublic: Uint8Array | undefined
  let classicalSecret: Uint8Array | undefined
  if (recipientX25519Public) {
    const ephemeralSecret = x25519.utils.randomPrivateKey()
    ephemeralPublic = x25519.getPublicKey(ephemeralSecret)
    classicalSecret = x25519.getSharedSecret(ephemeralSecret, recipientX25519Public)
    ephemeralSecret.fill(0)
  }

  const wrappingKey = deriveWrappingKey({
    mlkemSecret: sharedSecret,
    x25519Secret: classicalSecret,
    salt: wrapSalt,
    aadHash,
  })
  const wrappedDataKey = gcm(wrappingKey, wrapNonce).encrypt(fileKey)
  const encryptedIntegrityHash = sha3_512(encrypted)
  const integrityHash = sha3_256(data)

  fileKey.fill(0)
  wrappingKey.fill(0)
  sharedSecret.fill(0)
  classicalSecret?.fill(0)

  const mode = recipientX25519Public ? 'hybrid' : 'ml-kem'
  const envelopeMeta: VaultEnvelopeMeta = {
    version: 2,
    mode,
    kem: kemName,
    kex: kexName(kemName, !!recipientX25519Public),
    securityLevel: securityLevelForKem(kemName),
    signature: 'Ed25519+ML-DSA-65',
    symmetric: 'AES-256-GCM',
    kdf: 'HKDF-SHA3-256',
    hash: 'SHA3-256',
    encryptedHash: 'SHA3-512',
    merkle: merkleIntegrity,
    wrappedDataKey: toHex(wrappedDataKey),
    wrapNonce: toHex(wrapNonce),
    wrapSalt: toHex(wrapSalt),
    x25519EphemeralPublic: ephemeralPublic ? toHex(ephemeralPublic) : undefined,
    aadHash: toHex(aadHash),
  }
  
  return {
    encryptedData: encrypted,
    kemCiphertext: toHex(cipherText),
    aesNonce: toHex(payloadNonce),
    aesAuthTag: extractGcmTag(encrypted),
    integrityHash: toHex(integrityHash),
    encryptedIntegrityHash: toHex(encryptedIntegrityHash),
    aadHash: toHex(aadHash),
    envelopeMeta,
    merkleIntegrity,
    originalSize: data.length,
    algorithm: envelopeMeta.kex + '+AES-256-GCM',
  }
}

// ─── Encrypted file metadata (zero-knowledge filename / MIME protection) ──────
// Filenames and MIME types must never sit in cleartext columns. We derive a
// stable per-vault metadata key from the user's ML-KEM secret key (which never
// leaves the client) and seal the sensitive fields with AES-256-GCM. Only the
// ciphertext is stored; recovering it requires the passphrase-gated master key —
// the same trust tier as the file content itself. A random nonce per seal means
// identical filenames never produce identical ciphertext (no equality leakage).

export interface SealedFileMeta {
  v: 1
  alg: 'AES-256-GCM'
  kdf: 'HKDF-SHA3-256'
  nonce: string
  data: string
}

export interface FileMetaPlain {
  filename: string
  mime?: string
}

function deriveMetadataKey(encSecretKey: Uint8Array): Uint8Array {
  return hkdf(
    sha3_256,
    encSecretKey,
    new TextEncoder().encode('qguard-vault-metadata-salt'),
    new TextEncoder().encode('qguard-vault-metadata-key'),
    32,
  )
}

/** Seal a file's name + MIME into an AES-256-GCM blob bound to the vault keys. */
export function sealFileMeta(meta: FileMetaPlain, encSecretKey: Uint8Array): SealedFileMeta {
  const metaKey = deriveMetadataKey(encSecretKey)
  const nonce = randomBytes(12)
  const plaintext = new TextEncoder().encode(
    JSON.stringify({ filename: meta.filename, mime: meta.mime ?? '' }),
  )
  const ciphertext = gcm(metaKey, nonce).encrypt(plaintext)
  metaKey.fill(0)
  plaintext.fill(0)
  return { v: 1, alg: 'AES-256-GCM', kdf: 'HKDF-SHA3-256', nonce: toHex(nonce), data: toHex(ciphertext) }
}

/** Open a sealed metadata blob; returns null if absent, malformed, or wrong key. */
export function openFileMeta(
  sealed: SealedFileMeta | Record<string, unknown> | null | undefined,
  encSecretKey: Uint8Array,
): FileMetaPlain | null {
  if (!sealed || typeof sealed !== 'object') return null
  const s = sealed as Partial<SealedFileMeta>
  if (typeof s.nonce !== 'string' || typeof s.data !== 'string') return null
  const metaKey = deriveMetadataKey(encSecretKey)
  try {
    const plaintext = gcm(metaKey, fromHex(s.nonce)).decrypt(fromHex(s.data))
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as { filename?: string; mime?: string }
    if (typeof parsed.filename !== 'string') return null
    return { filename: parsed.filename, mime: parsed.mime || undefined }
  } catch {
    return null
  } finally {
    metaKey.fill(0)
  }
}

/**
 * Computes SHA3-256 hash in hex format.
 */
export function computeHash(data: Uint8Array): string {
  return toHex(sha3_256(data))
}

export function computeEncryptedHash(data: Uint8Array): string {
  return toHex(sha3_512(data))
}

/**
 * Signs data with ML-DSA-65 secret key.
 */
export function signData(data: Uint8Array, secretKey: Uint8Array, ed25519SecretKey?: Uint8Array): string {
  const signature = signHybridData(data, secretKey, ed25519SecretKey)
  return encodeBase64Json(signature)
}

export function signHybridData(data: Uint8Array, secretKey: Uint8Array, ed25519SecretKey?: Uint8Array): HybridSignature {
  const sig = ml_dsa65.sign(data, secretKey)
  return {
    version: 1,
    algorithm: ed25519SecretKey ? 'Ed25519+ML-DSA-65' : 'ML-DSA-65',
    mldsa65: toHex(sig),
    ed25519: ed25519SecretKey ? toHex(ed25519.sign(data, ed25519SecretKey)) : undefined,
  }
}

export function verifyHybridSignature(
  data: Uint8Array,
  signatureText: string,
  mldsaPublicKey: Uint8Array,
  ed25519PublicKey?: Uint8Array,
): boolean {
  try {
    let signature: HybridSignature
    if (signatureText.trim().startsWith('{')) {
      signature = JSON.parse(signatureText) as HybridSignature
    } else {
      signature = decodeBase64Json<HybridSignature>(signatureText)
    }

    const mldsaOk = ml_dsa65.verify(fromHex(signature.mldsa65), data, mldsaPublicKey)
    const edOk = signature.ed25519 && ed25519PublicKey
      ? ed25519.verify(fromHex(signature.ed25519), data, ed25519PublicKey)
      : true
    return !!mldsaOk && !!edOk
  } catch {
    try {
      // Legacy raw ML-DSA signature support.
      return !!ml_dsa65.verify(fromHex(signatureText), data, mldsaPublicKey)
    } catch {
      return false
    }
  }
}
