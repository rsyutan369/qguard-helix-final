/**
 * Scanner_2 algorithm normalisation — the one implementation, ISOMORPHIC.
 *
 * WHY THIS MODULE EXISTS
 * ----------------------
 * These functions turn a free-text algorithm string an observation carries
 * ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "sha256WithRSAEncryption",
 * "X25519MLKEM768") into the Scanner_2 `ClassicalAlgorithm` the risk model,
 * the HNDL analyser and the PQC recommendation engine all key on.
 *
 * Both sides of the platform need it:
 *
 *   • the api-server, which normalises a finding as it is recorded, and
 *   • the scanner dashboard, which joins a PQC recommendation back to the
 *     findings it covers and MUST use the same normaliser that produced the
 *     recommendation, or the join silently matches nothing.
 *
 * It used to live in `src/api-server/scanner.ts`, and the dashboard imported
 * it from there. That import pulled the entire Express router graph into the
 * browser bundle: Express reaches for Node built-ins, which Vite replaces with
 * empty stubs in the client, so `util.inherits` was undefined and the module
 * threw while evaluating. Because `App.tsx` imports every page eagerly, that
 * one throw killed the whole bundle before `createRoot().render()` ran — every
 * route on the site rendered an empty `#root`.
 *
 * So the rule this module encodes: shared scanner logic lives under
 * `src/lib/scanner/`, never in `src/api-server/`. Nothing here may import
 * Express, Supabase, `node:*`, or anything that transitively does — it has to
 * run unchanged in a browser tab and in the API server.
 */

import type { ClassicalAlgorithm } from '@/types/quantum.types'

/**
 * A public-key size the observation actually STATES — never one inferred from
 * an unrelated number in the same string.
 *
 * THE DEFECT THIS REPLACES
 * ------------------------
 * The size used to be read with
 *   `/(?:rsa|dh|aes|p-?|nistp|secp)?[-_ ]?(\d{3,4}|\d{2,3})/`
 * whose algorithm prefix is OPTIONAL, so it returned the first three-or-four
 * digit run anywhere in the string. The bulk cipher's key length and the
 * digest's output length were therefore read as the RSA modulus:
 *
 *   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  ->  128  -> "RSA-1024"
 *   TLS_RSA_WITH_AES_256_CBC_SHA           ->  256  -> "RSA-1024"
 *   sha256WithRSAEncryption                ->  256  -> "RSA-1024"
 *
 * RSA-1024 is the most alarming classical key size the model has, and it was
 * being published for endpoints that carry no 1024-bit key anywhere. On a
 * Google endpoint (ECDSA P-256 leaf, RSA-2048 issuer) six of the eight
 * harvest-now records claimed RSA-1024 with "data may already be harvested",
 * every one of them a fabrication — and those same records drove the Scanner_2
 * critical count, the risk aggregate, the readiness percentage and the modelled
 * break window on the Quantum Posture card.
 *
 * A digit run now only counts when it is written against the algorithm that
 * owns it. When no size is stated the caller falls back to the family's
 * conventional deployment size, which is a stated assumption rather than an
 * invented measurement.
 */
function statedKeySize(value: string, family: 'rsa' | 'dh' | 'dsa'): number | null {
  const token = family === 'rsa' ? 'rsa' : family === 'dh' ? '(?:dh|diffie[- ]?hellman)' : 'dsa'
  const patterns = [
    // rsa-2048 · rsa 2048 · rsa2048 · rsa_2048 · rsaEncryption 2048
    new RegExp(`${token}[a-z]*[-_ ]?\\(?(\\d{3,5})\\)?`, 'i'),
    // 2048-bit RSA · 2048 bit rsa · 2048-bit-rsa
    new RegExp(`(\\d{3,5})[-_ ]?bits?[-_ ]?${token}`, 'i'),
  ]
  for (const pattern of patterns) {
    const bits = Number(value.match(pattern)?.[1])
    // A plausible modulus only. 128/256 in a suite name is a cipher or a
    // digest, never a public key, and must not be read as one.
    if (Number.isFinite(bits) && bits >= 512) return bits
  }
  return null
}

/**
 * Classify a TLS cipher-suite name by the decision that carries the exposure.
 *
 * A suite name is four independent decisions wearing one string, and the
 * substring test that used to run over it answered with whichever one appeared
 * first: `TLS_ECDHE_RSA_WITH_...` contains "rsa", so a forward-secret ECDHE
 * suite was filed as an RSA key transport. The key exchange is what Shor
 * breaks retroactively, so it decides; the bulk cipher answers only for TLS 1.3
 * suites, whose key agreement is negotiated separately and recorded as its own
 * observation.
 */
function suiteAlgorithmForScanner2(value: string): ClassicalAlgorithm | null {
  if (!/^tls[_-]/i.test(value)) return null
  // TLS 1.3 suites name no key exchange — the negotiated group is a separate
  // observation, and reporting a second one here would double-count it.
  if (/^tls[_-](aes|chacha)/i.test(value)) {
    if (/aes[_-]?128/i.test(value)) return 'AES-128'
    return 'AES-256'
  }
  if (/^tls[_-]rsa[_-]with/i.test(value)) return 'RSA-2048' // static RSA key transport, size not stated
  if (/[_-]ecdhe[_-]/i.test(value)) return 'ECC-P256'
  if (/[_-]dhe[_-]/i.test(value)) return 'DH-2048'
  if (/[_-]ecdh[_-]/i.test(value)) return 'ECC-P256'
  if (/3des|des[_-]cbc3/i.test(value)) return '3DES'
  if (/aes[_-]?128/i.test(value)) return 'AES-128'
  if (/aes[_-]?256/i.test(value)) return 'AES-256'
  return null
}

/**
 * Post-quantum and hybrid primitives, which have NO classical representation.
 *
 * `X25519MLKEM768` contains the substring "x25519", so the classical ladder
 * below filed the measured hybrid group as bare X25519 — a Shor-breakable
 * key agreement. The consequence was visible on the Quantum Posture card: the
 * one observation proving the endpoint is protected was counted as an asset
 * *requiring migration*, pushing Scanner_2 readiness down. A hybrid group is
 * not a classical algorithm, so it leaves the classical model entirely; it is
 * already recorded as its own SAFE post-quantum observation.
 */
const POST_QUANTUM_PRIMITIVE = /ml[-_]?kem|ml[-_]?dsa|slh[-_]?dsa|kyber|dilithium|sphincs|falcon|bike|hqc|frodo|classic[-_ ]?mceliece/i

export function normalizeToScanner2Algorithm(value: string): ClassicalAlgorithm | null {
  const lower = value.toLowerCase()
  if (POST_QUANTUM_PRIMITIVE.test(value)) return null
  const suite = suiteAlgorithmForScanner2(value)
  if (suite) return suite
  if (lower.includes('rsa')) {
    const bits = statedKeySize(value, 'rsa')
    if (bits && bits <= 1024) return 'RSA-1024'
    if (bits && bits >= 4096) return 'RSA-4096'
    return 'RSA-2048'
  }
  if (lower.includes('ecdsa') || lower.includes('secp')) {
    if (lower.includes('384') || lower.includes('p384')) return 'ECDSA-P384'
    if (lower.includes('secp256k1')) return 'ECC-secp256k1'
    return 'ECDSA-P256'
  }
  if (lower.includes('ecdh') || lower.includes('p-256') || lower.includes('prime256') || lower.includes('nistp256')) return 'ECC-P256'
  if (lower.includes('p-384') || lower.includes('nistp384')) return 'ECC-P384'
  if (lower.includes('x25519') || lower.includes('curve25519')) return 'X25519'
  if (lower.includes('ed25519')) return 'Ed25519'
  if (lower.includes('diffie') || lower.includes('dhe') || lower.includes('dh-')) {
    const bits = statedKeySize(value, 'dh')
    if (bits && bits <= 1024) return 'DH-1024'
    return 'DH-2048'
  }
  if (lower.includes('tls') || lower.includes('tlsv')) {
    if (lower.includes('1.0')) return 'TLS-1.0'
    if (lower.includes('1.1')) return 'TLS-1.1'
    if (lower.includes('1.2')) return 'TLS-1.2'
    if (lower.includes('1.3')) return 'TLS-1.3'
  }
  if (lower.includes('sha-1') || lower.includes('sha1')) return 'SHA-1'
  if (lower.includes('sha-256') || lower.includes('sha256')) return 'SHA-256'
  if (lower.includes('md5')) return 'MD5'
  if (lower.includes('aes-128') || lower.includes('aes_128')) return 'AES-128'
  if (lower.includes('aes-256') || lower.includes('aes_256')) return 'AES-256'
  if (lower.includes('3des') || lower.includes('triple-des')) return '3DES'
  if (lower.includes('pgp') && lower.includes('rsa')) return 'PGP-RSA'
  if (lower.includes('pgp') && (lower.includes('ecc') || lower.includes('ec'))) return 'PGP-ECC'
  if (lower.includes('s/mime') && lower.includes('rsa')) return 'S/MIME-RSA'
  return null
}
