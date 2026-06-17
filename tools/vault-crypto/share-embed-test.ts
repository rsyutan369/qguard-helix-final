/**
 * Share-token filename embedding tests (headless).
 *
 *   - Filename + MIME sealed in the token round-trip (fragment + password modes).
 *   - Legacy shares (no embedded meta) still decrypt; filename is absent.
 *   - A legacy raw payload that merely begins with the envelope magic is NOT
 *     mis-parsed (no data loss).
 *   - Tampering with the payload is rejected.
 *
 * Run: npx tsx tools/vault-crypto/share-embed-test.ts
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
;(globalThis as any).window = { crypto: globalThis.crypto }

import {
  decryptSharedFile,
  decryptSharedFileWithPassword,
  encryptForSharing,
  encryptForSharingWithPassword,
  hashPassword,
  unpackShareEnvelope,
} from '../../src/lib/vault/sharing-crypto.ts'

let passed = 0
let failed = 0
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) { passed++; console.log(`  ✓ ${name}`) }
  else { failed++; console.error(`  ✗ ${name} ${detail}`) }
}
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

async function main(): Promise<void> {
  console.log('\nShare-token filename embedding\n')
  const content = new TextEncoder().encode('Top-secret Q3 board deck — do not forward. '.repeat(200))
  const meta = { filename: 'Q3-board-deck-CONFIDENTIAL.pdf', mime: 'application/pdf' }

  console.log('[fragment-key share]')
  {
    const enc = await encryptForSharing(content, meta)
    // The server-stored ciphertext must not contain the cleartext name.
    check('ciphertext carries no cleartext filename', !atob(enc.encryptedPayload).includes('CONFIDENTIAL'))
    const out = await decryptSharedFile(enc.encryptedPayload, enc.iv, enc.shareKey!, enc.integrityHash)
    check('content round-trips byte-for-byte', bytesEqual(out.data, content))
    check('embedded filename recovered', out.filename === meta.filename)
    check('embedded MIME recovered', out.mimeType === meta.mime)
  }

  console.log('\n[legacy share — no embedded meta]')
  {
    const enc = await encryptForSharing(content) // no meta
    const out = await decryptSharedFile(enc.encryptedPayload, enc.iv, enc.shareKey!, enc.integrityHash)
    check('legacy content round-trips', bytesEqual(out.data, content))
    check('legacy filename is absent (server fallback used)', out.filename === undefined)
  }

  console.log('\n[false-positive safety]')
  {
    // A legacy raw file whose bytes begin with "QGSF1" + version 1 must not be
    // mis-read as an envelope.
    const evil = new Uint8Array(256)
    evil.set(new TextEncoder().encode('QGSF1'), 0)
    evil[5] = 1
    for (let i = 6; i < evil.length; i++) evil[i] = (i * 41) & 0xff
    const unpacked = unpackShareEnvelope(evil)
    check('magic-colliding raw payload returned unchanged', bytesEqual(unpacked.data, evil) && unpacked.filename === undefined)
  }

  console.log('\n[tamper rejection]')
  {
    const enc = await encryptForSharing(content, meta)
    const raw = atob(enc.encryptedPayload)
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0))
    bytes[bytes.length - 3] ^= 0xff
    const tampered = btoa(String.fromCharCode(...bytes))
    let threw = false
    try { await decryptSharedFile(tampered, enc.iv, enc.shareKey!, enc.integrityHash) } catch { threw = true }
    check('tampered payload is rejected', threw)
  }

  console.log('\n[password share] (Argon2id — may take a few seconds)')
  {
    const password = 'unrelated tide marble quiet lantern 7'
    const enc = await encryptForSharingWithPassword(content, password, meta)
    const proof = await hashPassword(password, enc.passwordSalt, enc.passwordKdf)
    check('password proof derived', proof.length === 64)
    const out = await decryptSharedFileWithPassword(
      enc.encryptedPayload, enc.iv, null, password, enc.passwordSalt, enc.integrityHash, enc.passwordKdf,
    )
    check('password-share content round-trips', bytesEqual(out.data, content))
    check('password-share embedded filename recovered', out.filename === meta.filename)
  }

  console.log(`\nResult: ${passed} passed, ${failed} failed\n`)
  if (failed > 0) process.exit(1)
}

main().catch((err) => { console.error(err); process.exit(1) })
