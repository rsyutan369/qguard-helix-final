import { gcm } from '@noble/ciphers/aes.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { argon2idAsync as deriveMemoryHardKdf } from '@noble/hashes/argon2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { importBundle } from './qgkey'
import {
  type VaultKemName,
  type VaultKexName,
  kemForPublicKey,
  kemForSecretKey,
  kexName,
  resolveKemNameFromPublicKey,
} from './kem-profile'

/**
 * Sharing Cryptography for the Quantum Vault.
 * Uses AES-256-GCM for file encryption.
 * New password-protected shares use a memory-hard password profile, with the
 * earlier PBKDF2-SHA3-256 profile retained only for legacy share compatibility.
 */

export type SharePasswordKdfAlgorithm = 'hardened-v2' | 'argon2id' | 'pbkdf2-sha3-256'

export interface PasswordKdfMetadata {
  // Serialized to JSON / stored as jsonb and passed through Record<string, unknown> share payloads.
  [key: string]: unknown
  algorithm: SharePasswordKdfAlgorithm
  params?: {
    memoryKiB?: number
    iterations?: number
    parallelism?: number
    version?: number
    dkLen?: number
    keyIterations?: number
    hashIterations?: number
  }
}

export interface RecipientWrappedShareKey {
  // Serialized to JSON / stored as jsonb and passed through Record<string, unknown> share payloads.
  [key: string]: unknown
  version: 1
  algorithm: `${VaultKemName}+X25519/AES-256-GCM` | `${VaultKemName}/AES-256-GCM`
  kem: VaultKemName
  kex: VaultKexName
  symmetric: 'AES-256-GCM'
  kdf: 'HKDF-SHA3-256'
  recipientFingerprint: string
  kemCiphertext: string
  x25519EphemeralPublic?: string
  wrapNonce: string
  wrapSalt: string
  wrappedShareKey: string
}

interface RecipientPublicKeys {
  mlkemPublic: Uint8Array
  x25519Public?: Uint8Array
  fingerprint: string
}

const textEncoder = new TextEncoder()
const ARGON2ID_PARAMS = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
  version: 19,
  dkLen: 32,
} as const

export const CURRENT_PASSWORD_KDF: PasswordKdfMetadata = {
  algorithm: 'hardened-v2',
  params: ARGON2ID_PARAMS,
}

const LEGACY_PASSWORD_KDF: PasswordKdfMetadata = {
  algorithm: 'pbkdf2-sha3-256',
  params: {
    keyIterations: 310000,
    hashIterations: 100000,
    dkLen: 32,
  },
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
  return globalThis.crypto.getRandomValues(new Uint8Array(length))
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const length = arrays.reduce((total, item) => total + item.length, 0)
  const out = new Uint8Array(length)
  let offset = 0
  for (const item of arrays) {
    out.set(item, offset)
    offset += item.length
  }
  return out
}

function fromBase64(value: string): Uint8Array {
  const normalized = value.trim().replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function decodeKeyMaterial(value: unknown): Uint8Array {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('RECIPIENT_PUBLIC_KEY_REQUIRED')
  }
  const normalized = value.trim().replace(/\s+/g, '')
  if (/^[0-9a-f]+$/i.test(normalized) && normalized.length % 2 === 0) {
    return fromHex(normalized)
  }
  return fromBase64(normalized)
}

function fromPayload(value: string): Uint8Array {
  const normalized = value.trim().replace(/\s+/g, '')
  if (normalized.startsWith('\\x')) return fromHex(normalized.slice(2))
  if (/^[0-9a-f]+$/i.test(normalized) && normalized.length % 2 === 0) return fromHex(normalized)
  return fromBase64(normalized)
}

function toBase64(bytes: Uint8Array): string {
  let s = ''
  for (const x of bytes) s += String.fromCharCode(x)
  return btoa(s)
}

function clampInteger(value: unknown, fallback: number, min: number, max: number): number {
  const n = Number(value)
  if (!Number.isFinite(n)) return fallback
  return Math.max(min, Math.min(max, Math.floor(n)))
}

function normalizePasswordKdf(passwordKdf?: PasswordKdfMetadata | null): PasswordKdfMetadata {
  if (!passwordKdf?.algorithm) return LEGACY_PASSWORD_KDF
  if (passwordKdf.algorithm === 'hardened-v2' || passwordKdf.algorithm === 'argon2id') {
    return {
      algorithm: 'hardened-v2',
      params: {
        memoryKiB: clampInteger(passwordKdf.params?.memoryKiB, ARGON2ID_PARAMS.memoryKiB, 8192, 131072),
        iterations: clampInteger(passwordKdf.params?.iterations, ARGON2ID_PARAMS.iterations, 1, 6),
        parallelism: clampInteger(passwordKdf.params?.parallelism, ARGON2ID_PARAMS.parallelism, 1, 4),
        version: clampInteger(passwordKdf.params?.version, ARGON2ID_PARAMS.version, 16, 19),
        dkLen: clampInteger(passwordKdf.params?.dkLen, ARGON2ID_PARAMS.dkLen, 32, 64),
      },
    }
  }
  return LEGACY_PASSWORD_KDF
}

async function deriveHardenedPasswordMaterial(
  password: string,
  salt: Uint8Array,
  purpose: 'file-key' | 'server-proof',
  passwordKdf?: PasswordKdfMetadata | null,
): Promise<Uint8Array> {
  const normalized = normalizePasswordKdf(passwordKdf)
  const params = normalized.params || ARGON2ID_PARAMS
  const passwordBytes = textEncoder.encode(password)

  try {
    return deriveMemoryHardKdf(passwordBytes, salt, {
      t: clampInteger(params.iterations, ARGON2ID_PARAMS.iterations, 1, 6),
      m: clampInteger(params.memoryKiB, ARGON2ID_PARAMS.memoryKiB, 8192, 131072),
      p: clampInteger(params.parallelism, ARGON2ID_PARAMS.parallelism, 1, 4),
      version: clampInteger(params.version, ARGON2ID_PARAMS.version, 16, 19),
      dkLen: clampInteger(params.dkLen, ARGON2ID_PARAMS.dkLen, 32, 64),
      personalization: textEncoder.encode(`qguard-share-${purpose}-v2`),
      asyncTick: 10,
      maxmem: 256 * 1024 * 1024,
    })
  } finally {
    passwordBytes.fill(0)
  }
}

async function deriveShareKey(
  password: string,
  salt: Uint8Array,
  passwordKdf?: PasswordKdfMetadata | null,
): Promise<Uint8Array> {
  const normalized = normalizePasswordKdf(passwordKdf)
  if (normalized.algorithm === 'hardened-v2') {
    return deriveHardenedPasswordMaterial(password, salt, 'file-key', normalized)
  }
  return pbkdf2Async(sha3_256, password, salt, {
    c: normalized.params?.keyIterations || 310000,
    dkLen: normalized.params?.dkLen || 32,
  })
}

async function derivePasswordHash(
  password: string,
  salt: Uint8Array,
  passwordKdf?: PasswordKdfMetadata | null,
): Promise<Uint8Array> {
  const normalized = normalizePasswordKdf(passwordKdf)
  if (normalized.algorithm === 'hardened-v2') {
    return deriveHardenedPasswordMaterial(password, salt, 'server-proof', normalized)
  }
  return pbkdf2Async(sha3_256, password, salt, {
    c: normalized.params?.hashIterations || 100000,
    dkLen: normalized.params?.dkLen || 32,
  })
}

function verifyIntegrity(data: Uint8Array, expectedHash?: string) {
  if (!expectedHash) return
  const actualHash = toHex(sha3_256(data))
  if (actualHash !== expectedHash) {
    throw new Error('INTEGRITY_CHECK_FAILED')
  }
}

function deriveRecipientWrapKey({
  mlkemSecret,
  x25519Secret,
  salt,
  recipientFingerprint,
}: {
  mlkemSecret: Uint8Array
  x25519Secret?: Uint8Array
  salt: Uint8Array
  recipientFingerprint: string
}): Uint8Array {
  const input = x25519Secret ? concatBytes(mlkemSecret, x25519Secret) : mlkemSecret
  return hkdf(
    sha3_256,
    input,
    salt,
    textEncoder.encode(`qguard-share-recipient-wrap:v1:${recipientFingerprint}`),
    32,
  )
}

export function parseRecipientPublicKeys(input: string): RecipientPublicKeys {
  const trimmed = input.trim()
  if (!trimmed) throw new Error('RECIPIENT_PUBLIC_KEY_REQUIRED')

  let mlkemPublic: Uint8Array
  let x25519Public: Uint8Array | undefined

  if (trimmed.startsWith('{')) {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>
    const publics = parsed.publics && typeof parsed.publics === 'object'
      ? parsed.publics as Record<string, unknown>
      : parsed

    mlkemPublic = decodeKeyMaterial(
      publics.mlkem ||
      publics.mlkemPublic ||
      publics.mlkem_public ||
      publics.encPublicKey ||
      publics.publicKey,
    )

    const x25519Candidate = publics.x25519 || publics.x25519Public || publics.x25519_public
    if (typeof x25519Candidate === 'string' && x25519Candidate.trim()) {
      x25519Public = decodeKeyMaterial(x25519Candidate)
      if (x25519Public.length !== 32) {
        throw new Error('RECIPIENT_X25519_PUBLIC_KEY_INVALID')
      }
    }
  } else {
    mlkemPublic = decodeKeyMaterial(trimmed)
  }

  try {
    resolveKemNameFromPublicKey(mlkemPublic)
  } catch {
    throw new Error('RECIPIENT_MLKEM_PUBLIC_KEY_INVALID')
  }

  const fingerprintMaterial = concatBytes(
    textEncoder.encode('qguard-recipient-public:v1'),
    mlkemPublic,
    x25519Public || new Uint8Array(0),
  )
  const fingerprint = toHex(sha3_256(fingerprintMaterial)).slice(0, 32)

  return { mlkemPublic, x25519Public, fingerprint }
}

/**
 * Encrypts data for a standard share link.
 * Generates a random 256-bit key.
 */
export async function encryptForSharing(fileData: Uint8Array) {
  const shareKey = randomBytes(32)
  const iv = randomBytes(12)

  const aes = gcm(shareKey, iv)
  const encrypted = aes.encrypt(fileData)

  return {
    encryptedPayload: toBase64(encrypted),
    iv: toHex(iv),
    integrityHash: toHex(sha3_256(fileData)),
    shareKey: toHex(shareKey)
  }
}

/**
 * Encrypts data for a password-protected share link.
 * Derives the key from the password using the current hardened profile.
 */
export async function encryptForSharingWithPassword(fileData: Uint8Array, password: string) {
  const salt = randomBytes(32)
  const passwordKdf = CURRENT_PASSWORD_KDF
  const shareKey = await deriveShareKey(password, salt, passwordKdf)

  // Also create a password proof for the server to verify before serving the blob.
  const passwordHashBytes = await derivePasswordHash(password, salt, passwordKdf)

  const iv = randomBytes(12)
  const aes = gcm(shareKey, iv)
  const encrypted = aes.encrypt(fileData)
  const passwordHash = toHex(passwordHashBytes)

  shareKey.fill(0)
  passwordHashBytes.fill(0)

  return {
    encryptedPayload: toBase64(encrypted),
    iv: toHex(iv),
    integrityHash: toHex(sha3_256(fileData)),
    passwordSalt: toHex(salt),
    passwordHash,
    passwordKdf,
  }
}

export async function encryptForRecipientSharing(fileData: Uint8Array, recipientPublicKeyInput: string) {
  const recipient = parseRecipientPublicKeys(recipientPublicKeyInput)
  const shareKey = randomBytes(32)
  const iv = randomBytes(12)
  const encrypted = gcm(shareKey, iv).encrypt(fileData)
  const { name: kemName, kem } = kemForPublicKey(recipient.mlkemPublic)
  const { sharedSecret, cipherText } = kem.encapsulate(recipient.mlkemPublic)
  const wrapNonce = randomBytes(12)
  const wrapSalt = randomBytes(32)

  let x25519EphemeralPublic: Uint8Array | undefined
  let x25519Shared: Uint8Array | undefined
  if (recipient.x25519Public) {
    const ephemeralSecret = x25519.utils.randomPrivateKey()
    x25519EphemeralPublic = x25519.getPublicKey(ephemeralSecret)
    x25519Shared = x25519.getSharedSecret(ephemeralSecret, recipient.x25519Public)
    ephemeralSecret.fill(0)
  }

  const wrappingKey = deriveRecipientWrapKey({
    mlkemSecret: sharedSecret,
    x25519Secret: x25519Shared,
    salt: wrapSalt,
    recipientFingerprint: recipient.fingerprint,
  })
  const wrappedShareKey = gcm(wrappingKey, wrapNonce).encrypt(shareKey)

  const recipientWrap: RecipientWrappedShareKey = {
    version: 1,
    algorithm: recipient.x25519Public ? `${kemName}+X25519/AES-256-GCM` : `${kemName}/AES-256-GCM`,
    kem: kemName,
    kex: kexName(kemName, !!recipient.x25519Public),
    symmetric: 'AES-256-GCM',
    kdf: 'HKDF-SHA3-256',
    recipientFingerprint: recipient.fingerprint,
    kemCiphertext: toHex(cipherText),
    x25519EphemeralPublic: x25519EphemeralPublic ? toHex(x25519EphemeralPublic) : undefined,
    wrapNonce: toHex(wrapNonce),
    wrapSalt: toHex(wrapSalt),
    wrappedShareKey: toHex(wrappedShareKey),
  }

  shareKey.fill(0)
  wrappingKey.fill(0)
  sharedSecret.fill(0)
  x25519Shared?.fill(0)

  return {
    encryptedPayload: toBase64(encrypted),
    iv: toHex(iv),
    integrityHash: toHex(sha3_256(fileData)),
    recipientWrap,
  }
}

export async function hashPassword(
  password: string,
  passwordSalt: string,
  passwordKdf?: PasswordKdfMetadata | null,
): Promise<string> {
  const salt = fromHex(passwordSalt)
  const passwordHash = await derivePasswordHash(password, salt, passwordKdf)
  try {
    return toHex(passwordHash)
  } finally {
    passwordHash.fill(0)
  }
}

export async function unwrapRecipientShareKey(
  recipientWrap: RecipientWrappedShareKey,
  privateKeyBundle: string,
  passphrase: string,
): Promise<string> {
  if (recipientWrap.version !== 1 || (recipientWrap.kem !== 'ML-KEM-768' && recipientWrap.kem !== 'ML-KEM-1024')) {
    throw new Error('RECIPIENT_WRAP_UNSUPPORTED')
  }

  const material = importBundle(privateKeyBundle, passphrase)
  const { kem } = kemForSecretKey(material.mlkemSecret, recipientWrap.kem)
  const kemShared = kem.decapsulate(fromHex(recipientWrap.kemCiphertext), material.mlkemSecret)
  let x25519Shared: Uint8Array | undefined

  if (recipientWrap.x25519EphemeralPublic) {
    if (!material.x25519Secret?.length) {
      throw new Error('RECIPIENT_X25519_SECRET_REQUIRED')
    }
    x25519Shared = x25519.getSharedSecret(
      material.x25519Secret,
      fromHex(recipientWrap.x25519EphemeralPublic),
    )
  }

  const wrappingKey = deriveRecipientWrapKey({
    mlkemSecret: kemShared,
    x25519Secret: x25519Shared,
    salt: fromHex(recipientWrap.wrapSalt),
    recipientFingerprint: recipientWrap.recipientFingerprint,
  })
  const shareKey = gcm(wrappingKey, fromHex(recipientWrap.wrapNonce)).decrypt(fromHex(recipientWrap.wrappedShareKey))

  try {
    return toHex(shareKey)
  } finally {
    shareKey.fill(0)
    wrappingKey.fill(0)
    kemShared.fill(0)
    x25519Shared?.fill(0)
    material.x25519Secret.fill(0)
    material.mlkemSecret.fill(0)
    material.ed25519Secret.fill(0)
    material.mldsaSecret.fill(0)
  }
}

export async function decryptSharedFile(
  encryptedPayload: string,
  iv: string,
  shareKey: string,
  integrityHash?: string,
): Promise<Uint8Array> {
  const key = fromHex(shareKey)
  try {
    const decrypted = gcm(key, fromHex(iv)).decrypt(fromPayload(encryptedPayload))
    verifyIntegrity(decrypted, integrityHash)
    return decrypted
  } finally {
    key.fill(0)
  }
}

export async function decryptSharedFileWithPassword(
  encryptedPayload: string,
  iv: string,
  shareKey: string | null | undefined,
  password: string,
  passwordSalt: string,
  integrityHash?: string,
  passwordKdf?: PasswordKdfMetadata | null,
): Promise<Uint8Array> {
  const localKey = await deriveShareKey(password, fromHex(passwordSalt), passwordKdf)
  const fragmentKey = shareKey ? fromHex(shareKey) : null

  try {
    if (fragmentKey?.length && toHex(fragmentKey) !== toHex(localKey)) {
      throw new Error('SHARE_KEY_PASSWORD_MISMATCH')
    }

    const decrypted = gcm(localKey, fromHex(iv)).decrypt(fromPayload(encryptedPayload))
    verifyIntegrity(decrypted, integrityHash)
    return decrypted
  } finally {
    fragmentKey?.fill(0)
    localKey.fill(0)
  }
}
