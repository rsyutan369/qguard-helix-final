/**
 * Vault KEK + metadata hardening tests (headless).
 *
 *   - Argon2id wrap → unwrap round-trips (new v3 bundle).
 *   - Legacy v2 (PBKDF2) bundles still unwrap (backward compatibility).
 *   - bundleNeedsKdfUpgrade flags legacy bundles for re-wrap.
 *   - Sealed filename/MIME round-trips and rejects the wrong key.
 *
 * Run: npx tsx tools/vault-crypto/kek-test.ts
 *
 * client-crypto.ts targets the browser (window.crypto). Node 20+ exposes the
 * same WebCrypto on globalThis.crypto, so we shim `window` before importing.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
;(globalThis as any).window = { crypto: globalThis.crypto }

import { hkdf } from '@noble/hashes/hkdf.js'
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js'
import { sha3_256 } from '@noble/hashes/sha3.js'
import {
  bundleNeedsKdfUpgrade,
  generateMasterKeys,
  openFileMeta,
  sealFileMeta,
  unwrapMasterKeys,
  wrapMasterKeys,
  type ZKMasterKeys,
} from '../../src/lib/vault/client-crypto.ts'

let passed = 0
let failed = 0
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) { passed++; console.log(`  ✓ ${name}`) }
  else { failed++; console.error(`  ✗ ${name} ${detail}`) }
}
function bytesEqual(a?: Uint8Array, b?: Uint8Array): boolean {
  if (!a || !b || a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
function keysEqual(a: ZKMasterKeys, b: ZKMasterKeys): boolean {
  return (
    bytesEqual(a.encSecretKey, b.encSecretKey) &&
    bytesEqual(a.signSecretKey, b.signSecretKey) &&
    bytesEqual(a.encPublicKey, b.encPublicKey) &&
    bytesEqual(a.x25519Secret, b.x25519Secret) &&
    bytesEqual(a.ed25519Secret, b.ed25519Secret)
  )
}
const toHex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('')
const enc = (s: string) => new TextEncoder().encode(s)

/** Reproduces the pre-Argon2id (v2) wrap so we can prove backward compatibility. */
async function makeLegacyV2Bundle(keys: ZKMasterKeys, passphrase: string): Promise<string> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const stretched = await pbkdf2Async(sha3_256, passphrase, salt, { c: 600000, dkLen: 32 })
  const wrapMat = hkdf(sha3_256, stretched, salt, enc('qguard-vault-master-key-wrap'), 32)
  const wk = await globalThis.crypto.subtle.importKey('raw', wrapMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
  const payload = JSON.stringify({
    encSecretKey: toHex(keys.encSecretKey), signSecretKey: toHex(keys.signSecretKey),
    encPublicKey: toHex(keys.encPublicKey), signPublicKey: toHex(keys.signPublicKey),
    x25519Secret: keys.x25519Secret ? toHex(keys.x25519Secret) : undefined,
    x25519Public: keys.x25519Public ? toHex(keys.x25519Public) : undefined,
    ed25519Secret: keys.ed25519Secret ? toHex(keys.ed25519Secret) : undefined,
    ed25519Public: keys.ed25519Public ? toHex(keys.ed25519Public) : undefined,
  })
  const encd = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wk, enc(payload))
  const bundle = {
    v: 2, kdf: 'PBKDF2-SHA3-256+HKDF-SHA3-256', iterations: 600000,
    salt: toHex(salt), iv: toHex(iv), data: toHex(new Uint8Array(encd)),
  }
  return btoa(JSON.stringify(bundle))
}

async function main(): Promise<void> {
  console.log('\nVault KEK + metadata hardening\n')
  const passphrase = 'correct horse battery staple 2026!'
  const keys = await generateMasterKeys()

  console.log('[Argon2id KEK]')
  const wrapped = await wrapMasterKeys(keys, passphrase)
  const bundle = JSON.parse(atob(wrapped))
  check('new bundle is v3 / Argon2id', bundle.v === 3 && String(bundle.kdf).includes('Argon2id'),
    `v=${bundle.v} kdf=${bundle.kdf}`)
  check('argon2 params persisted', !!bundle.argon2 && bundle.argon2.m > 0, JSON.stringify(bundle.argon2))
  const unwrapped = await unwrapMasterKeys(wrapped, passphrase)
  check('Argon2id wrap → unwrap recovers identical keys', keysEqual(keys, unwrapped))
  let wrongThrew = false
  try { await unwrapMasterKeys(wrapped, 'wrong passphrase') } catch { wrongThrew = true }
  check('wrong passphrase is rejected (GCM tag fails)', wrongThrew)
  check('new bundle does not need upgrade', bundleNeedsKdfUpgrade(wrapped) === false)

  console.log('\n[backward compatibility]')
  const legacy = await makeLegacyV2Bundle(keys, passphrase)
  check('legacy v2 (PBKDF2) bundle flagged for upgrade', bundleNeedsKdfUpgrade(legacy) === true)
  const legacyUnwrapped = await unwrapMasterKeys(legacy, passphrase)
  check('legacy v2 bundle still unwraps to identical keys', keysEqual(keys, legacyUnwrapped))

  console.log('\n[sealed filename / MIME]')
  const sealed = sealFileMeta({ filename: 'Q3-financials-confidential.xlsx', mime: 'application/vnd.ms-excel' }, keys.encSecretKey)
  check('sealed blob carries no plaintext name', !JSON.stringify(sealed).includes('financials'))
  const opened = openFileMeta(sealed, keys.encSecretKey)
  check('seal → open recovers filename + mime',
    opened?.filename === 'Q3-financials-confidential.xlsx' && opened?.mime === 'application/vnd.ms-excel')
  const otherKeys = await generateMasterKeys()
  check('wrong vault key cannot open sealed metadata', openFileMeta(sealed, otherKeys.encSecretKey) === null)
  const sealed2 = sealFileMeta({ filename: 'same.txt' }, keys.encSecretKey)
  const sealed3 = sealFileMeta({ filename: 'same.txt' }, keys.encSecretKey)
  check('identical names produce different ciphertext (nonce)', sealed2.data !== sealed3.data)

  console.log(`\nResult: ${passed} passed, ${failed} failed\n`)
  if (failed > 0) process.exit(1)
}

main().catch((err) => { console.error(err); process.exit(1) })
