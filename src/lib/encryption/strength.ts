/**
 * Data-protection strength — the Grover model.
 *
 * This module exists to make one specific error impossible: describing a
 * symmetric or hash primitive in the language of Shor's algorithm.
 *
 *   RSA-2048  → Shor recovers the private key.        BROKEN by a CRQC.
 *   AES-256   → Grover halves the search space.       ~128-bit. SAFE.
 *   AES-128   → Grover halves the search space.       ~64-bit. WEAKENED.
 *   3DES/RC4  → broken by classical cryptanalysis.    BROKEN, quantum irrelevant.
 *
 * The platform has published the wrong verdict here before: the Harvest Now
 * exposure matrix filed `TLS_RSA_WITH_AES_256_GCM_SHA384` under "AES-256-GCM"
 * and rendered it Critical / quantum-vulnerable. AES-256-GCM is on the
 * platform's own approved list — the weakness in that suite is the RSA key
 * transport. `suite-anatomy.ts` fixed the decomposition; this module fixes the
 * VERDICT, so every consumer states the same security level with the same
 * arithmetic behind it.
 *
 * Grover's quadratic speedup is also widely held to be far less practical than
 * the raw figure suggests, because the search is inherently sequential and
 * cannot be parallelised the way classical brute force can. The rationale
 * strings say "weakened, not broken" for that reason, and never imply that a
 * quantum computer reads AES-128 traffic.
 *
 * Bar: CNSA 2.0 requires AES-256 and SHA-384 or SHA-512 for national security
 * systems, and is the standard this platform tracks for symmetric primitives.
 */

import type { ProtectionLayer, ProtectionStrength, StrengthProfile } from './types'

/**
 * NIST SP 800-57 Part 1 Rev. 5, Table 2 — comparable classical security
 * strength for RSA modulus sizes. Published values, not a curve fit.
 */
const RSA_COMPARABLE_STRENGTH: Record<number, number> = {
  1024: 80,
  2048: 112,
  3072: 128,
  4096: 152,
  8192: 200,
}

const CNSA2 = 'CNSA 2.0'
const SP800_131A = 'NIST SP 800-131A Rev. 2'
const FIPS140 = 'FIPS 140-3'

function profile(input: {
  classicalBits: number | null
  quantumBits: number | null
  strength: ProtectionStrength
  rationale: string
  standard: string
  target?: string | null
}): StrengthProfile {
  return { target: null, ...input }
}

/* ------------------------------------------------------------------ */
/* Symmetric ciphers                                                   */
/* ------------------------------------------------------------------ */

function symmetricStrength(label: string): StrengthProfile | null {
  const value = label.toUpperCase()

  if (/CHACHA20/.test(value)) {
    return profile({
      classicalBits: 256,
      quantumBits: 128,
      strength: 'quantum-safe',
      rationale: 'ChaCha20 uses a 256-bit key and has a large generic search margin. It is outside the CNSA 2.0 suite.',
      standard: 'RFC 8439',
    })
  }

  const aes = value.match(/AES[-_ ]?(128|192|256)/)
  if (aes) {
    const bits = Number(aes[1])
    if (bits === 256) {
      return profile({
        classicalBits: 256,
        quantumBits: 128,
        strength: 'quantum-safe',
        rationale: 'AES-256 keeps ~128 bits of security against Grover, which is the CNSA 2.0 bar. This primitive does not need to be migrated for quantum reasons.',
        standard: CNSA2,
      })
    }
    if (bits === 192) {
      return profile({
        classicalBits: 192,
        quantumBits: 96,
        strength: 'adequate',
        rationale: 'AES-192 is sound today and keeps ~96 bits against Grover, but CNSA 2.0 specifies AES-256 for long-term and national-security use.',
        standard: CNSA2,
        target: 'AES-256-GCM',
      })
    }
    return profile({
      classicalBits: 128,
      quantumBits: 64,
      strength: 'weakened',
      rationale: 'AES-128 is not broken — classically it is still sound — but Grover reduces it to ~64 bits of effective security, below the CNSA 2.0 bar for data with a long confidentiality lifetime.',
      standard: CNSA2,
      target: 'AES-256-GCM',
    })
  }

  if (/3DES|TRIPLE[-_ ]?DES|DESEDE/.test(value)) {
    return profile({
      classicalBits: 112,
      quantumBits: null,
      strength: 'broken',
      rationale: 'Triple-DES is disallowed by NIST SP 800-131A and vulnerable to Sweet32 birthday attacks on its 64-bit block. This is a classical break; quantum is irrelevant to the verdict.',
      standard: SP800_131A,
      target: 'AES-256-GCM',
    })
  }
  if (/\bRC4\b/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'broken',
      rationale: 'RC4 is prohibited (RFC 7465) — practical biases recover plaintext. A classical break, unrelated to quantum.',
      standard: SP800_131A,
      target: 'AES-256-GCM',
    })
  }
  if (/\bDES\b|\bRC2\b|\bBLOWFISH\b/.test(value)) {
    return profile({
      classicalBits: 56,
      quantumBits: null,
      strength: 'broken',
      rationale: `${value} is brute-forceable with classical hardware and disallowed for any new use.`,
      standard: SP800_131A,
      target: 'AES-256-GCM',
    })
  }

  return null
}

/**
 * Mode-of-operation caveats that survive a strong key.
 *
 * AES-256-CBC has a 256-bit key and is quantum-safe on that axis, but CBC
 * without an AEAD construction remains padding-oracle prone. The verdict must
 * therefore carry the mode as well as the key size, or a page would present a
 * CBC deployment as unreservedly safe.
 */
function modeCaveat(label: string, base: StrengthProfile): StrengthProfile {
  const value = label.toUpperCase()
  if (/GCM|POLY1305|CCM|OCB|SIV/.test(value)) return base
  if (/CBC/.test(value) && base.strength !== 'broken') {
    return {
      ...base,
      strength: base.strength === 'quantum-safe' ? 'adequate' : base.strength,
      rationale: `${base.rationale} The key size is not the concern here — CBC mode provides no integrity of its own and is padding-oracle prone; prefer an AEAD mode.`,
      target: base.target || 'AES-256-GCM',
    }
  }
  if (/\bECB\b/.test(value)) {
    return {
      ...base,
      strength: 'broken',
      rationale: 'ECB mode leaks plaintext structure regardless of key size and must not be used for data at rest or in transit.',
      standard: FIPS140,
      target: 'AES-256-GCM',
    }
  }
  return base
}

/* ------------------------------------------------------------------ */
/* Hashes and MACs                                                     */
/* ------------------------------------------------------------------ */

function hashStrength(label: string): StrengthProfile | null {
  const value = label.toUpperCase()

  if (/SHA3[-_ ]?(256|384|512)|SHAKE/.test(value)) {
    const bits = Number(value.match(/(256|384|512)/)?.[1] || 256)
    return profile({
      classicalBits: bits / 2,
      quantumBits: bits / 3,
      strength: 'quantum-safe',
      rationale: `SHA-3 (${bits}) is a Keccak sponge construction with no known practical weakness and adequate margin against quantum collision search.`,
      standard: 'FIPS 202',
    })
  }
  if (/SHA[-_ ]?(384|512)/.test(value)) {
    const bits = Number(value.match(/(384|512)/)?.[1] || 384)
    return profile({
      classicalBits: bits / 2,
      quantumBits: bits / 3,
      strength: 'quantum-safe',
      rationale: `SHA-${bits} meets the CNSA 2.0 hash requirement and retains a comfortable margin against quantum collision search.`,
      standard: CNSA2,
    })
  }
  if (/SHA[-_ ]?256|SHA2\b/.test(value)) {
    return profile({
      classicalBits: 128,
      quantumBits: 85,
      strength: 'adequate',
      rationale: 'SHA-256 is cryptographically sound and not broken. CNSA 2.0 nonetheless specifies SHA-384 or SHA-512 for national-security use and long-lived signatures.',
      standard: CNSA2,
      target: 'SHA-384',
    })
  }
  if (/SHA[-_ ]?224/.test(value)) {
    return profile({
      classicalBits: 112,
      quantumBits: 74,
      strength: 'adequate',
      rationale: 'SHA-224 is sound but offers the least margin of the SHA-2 family; prefer SHA-384 for new use.',
      standard: CNSA2,
      target: 'SHA-384',
    })
  }
  if (/SHA[-_ ]?1\b|\bSHA1\b/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'broken',
      rationale: 'SHA-1 is collision-broken in practice (SHAttered, 2017) and disallowed for digital signatures. A classical break — quantum does not change the verdict.',
      standard: SP800_131A,
      target: 'SHA-384',
    })
  }
  if (/\bMD5\b|\bMD4\b/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'broken',
      rationale: 'MD5 collisions are trivially computable and it must not be used for any security purpose.',
      standard: SP800_131A,
      target: 'SHA-384',
    })
  }
  return null
}

function macStrength(label: string): StrengthProfile | null {
  const value = label.toUpperCase()
  if (/POLY1305/.test(value)) {
    return profile({
      classicalBits: 128,
      quantumBits: 128,
      strength: 'quantum-safe',
      rationale: 'Poly1305 is a one-time authenticator with 128-bit forgery resistance; Grover does not meaningfully assist forgery.',
      standard: CNSA2,
    })
  }
  if (/HMAC/.test(value)) {
    const inner = hashStrength(value)
    if (inner && inner.strength === 'broken') {
      // HMAC-SHA1 is NOT broken the way a bare SHA-1 signature is: HMAC's
      // security rests on PRF properties, not collision resistance. Saying
      // otherwise would overstate the risk and misdirect remediation effort.
      return profile({
        classicalBits: 160,
        quantumBits: 80,
        strength: 'adequate',
        rationale: 'HMAC-SHA-1 is not broken by the SHA-1 collision attacks — HMAC relies on pseudorandomness, not collision resistance. It is nonetheless deprecated for new designs.',
        standard: SP800_131A,
        target: 'HMAC-SHA-384',
      })
    }
    if (inner) return { ...inner, rationale: `HMAC construction over ${value.replace(/HMAC[-_ ]?/, '')}. ${inner.rationale}` }
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'unknown',
      rationale: 'HMAC observed but the underlying hash was not recorded, so its strength cannot be stated.',
      standard: CNSA2,
    })
  }
  if (/\bCMAC\b|\bGMAC\b/.test(value)) {
    return profile({
      classicalBits: 128,
      quantumBits: 128,
      strength: 'quantum-safe',
      rationale: `${value} inherits the strength of its underlying block cipher and provides 128-bit forgery resistance.`,
      standard: CNSA2,
    })
  }
  return null
}

/* ------------------------------------------------------------------ */
/* Key derivation and password hashing                                 */
/* ------------------------------------------------------------------ */

function kdfStrength(label: string): StrengthProfile | null {
  const value = label.toUpperCase()
  if (/ARGON2/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'quantum-safe',
      rationale: 'Argon2 is the current password-hashing recommendation — memory-hard, which blunts both GPU and quantum-assisted search.',
      standard: 'OWASP / RFC 9106',
    })
  }
  if (/SCRYPT/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'quantum-safe',
      rationale: 'scrypt is memory-hard and remains an accepted password-hashing function.',
      standard: 'RFC 7914',
    })
  }
  if (/BCRYPT/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'adequate',
      rationale: 'bcrypt is still acceptable but is not memory-hard and caps input at 72 bytes; Argon2id is preferred for new systems.',
      standard: 'OWASP',
      target: 'Argon2id',
    })
  }
  if (/PBKDF2/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'adequate',
      rationale: 'PBKDF2 is FIPS-approved but not memory-hard, so it is comparatively cheap to attack on GPUs. Ensure a high iteration count, or move to Argon2id.',
      standard: 'NIST SP 800-132',
      target: 'Argon2id',
    })
  }
  if (/\bHKDF\b/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'quantum-safe',
      rationale: 'HKDF is the standard extract-and-expand KDF for high-entropy inputs and carries the strength of its underlying hash.',
      standard: 'RFC 5869',
    })
  }
  if (/\bMD5\b|\bSHA[-_ ]?1\b/.test(value) && /KDF|DERIV|PASSWORD/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'broken',
      rationale: 'Deriving keys or hashing passwords with a bare broken digest offers no work factor at all.',
      standard: 'NIST SP 800-132',
      target: 'Argon2id',
    })
  }
  return null
}

/* ------------------------------------------------------------------ */
/* Post-quantum key material                                           */
/* ------------------------------------------------------------------ */

function pqcStrength(label: string): StrengthProfile | null {
  const value = label.toUpperCase()
  if (/ML[-_ ]?KEM|KYBER/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'post-quantum',
      rationale: 'ML-KEM (FIPS 203) is the NIST-standardised key-encapsulation mechanism; its security rests on module lattice problems with no known quantum attack.',
      standard: 'FIPS 203',
    })
  }
  if (/ML[-_ ]?DSA|DILITHIUM/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'post-quantum',
      rationale: 'ML-DSA (FIPS 204) is the NIST-standardised lattice signature scheme.',
      standard: 'FIPS 204',
    })
  }
  if (/SLH[-_ ]?DSA|SPHINCS/.test(value)) {
    return profile({
      classicalBits: null,
      quantumBits: null,
      strength: 'post-quantum',
      rationale: 'SLH-DSA (FIPS 205) is the hash-based signature standard — conservative security resting only on hash assumptions.',
      standard: 'FIPS 205',
    })
  }
  return null
}

/**
 * Asymmetric primitives that protect DATA (key wrapping, envelope encryption).
 *
 * Here — and only here — Shor applies, so the verdict language changes.
 */
function asymmetricStrength(label: string): StrengthProfile | null {
  const value = label.toUpperCase()
  if (/\bRSA\b/.test(value)) {
    const bits = Number(value.match(/\b(1024|2048|3072|4096|8192)\b/)?.[1] || 0) || null
    return profile({
      // Published NIST SP 800-57 Part 1 Rev. 5 comparable-strength equivalences.
      // An earlier version computed this as `log2(bits) * 12`, which is not a
      // real relationship and printed "132-bit classical" for RSA-2048 — a
      // fabricated number where a standardised one already exists (112).
      classicalBits: bits ? RSA_COMPARABLE_STRENGTH[bits] ?? null : null,
      quantumBits: null,
      strength: 'quantum-vulnerable',
      rationale: `RSA${bits ? `-${bits}` : ''} key wrapping is sound against classical attack today, but is recovered outright by Shor's algorithm on a CRQC — a break rather than a halving. Any data it wraps is exposed to harvest-now-decrypt-later.`,
      standard: 'FIPS 203',
      target: 'ML-KEM-768 (or hybrid X25519 + ML-KEM-768)',
    })
  }
  if (/ECDH|ECDSA|X25519|ED25519|SECP|\bP-?(256|384|521)\b/.test(value)) {
    return profile({
      classicalBits: 128,
      quantumBits: null,
      strength: 'quantum-vulnerable',
      rationale: "Elliptic-curve key agreement and signatures are sound classically but are recovered outright by Shor's algorithm on a CRQC — a break, not a halving.",
      standard: 'FIPS 203 / FIPS 204',
      target: 'ML-KEM-768 / ML-DSA-65',
    })
  }
  return null
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */

export const UNKNOWN_STRENGTH: StrengthProfile = {
  classicalBits: null,
  quantumBits: null,
  strength: 'unknown',
  rationale: 'The primitive was recorded but its parameters were not, so no security level can be stated. This is not a pass — it is an unmeasured value.',
  standard: CNSA2,
  target: null,
}

/**
 * Resolve the strength of one named primitive.
 *
 * Order matters: post-quantum names are checked first so `ML-KEM` is never
 * caught by a generic pattern, and mode caveats are applied last so a strong
 * key in a weak mode is reported honestly.
 */
export function strengthOf(label: string, layer?: ProtectionLayer): StrengthProfile {
  const text = String(label ?? '').trim()
  if (!text) return UNKNOWN_STRENGTH

  const pq = pqcStrength(text)
  if (pq) return pq

  if (layer === 'kdf') {
    const kdf = kdfStrength(text)
    if (kdf) return kdf
  }

  const mac = macStrength(text)
  if (mac) return mac

  const symmetric = symmetricStrength(text)
  if (symmetric) return modeCaveat(text, symmetric)

  const hash = hashStrength(text)
  if (hash) return hash

  const kdf = kdfStrength(text)
  if (kdf) return kdf

  const asymmetric = asymmetricStrength(text)
  if (asymmetric) return asymmetric

  return UNKNOWN_STRENGTH
}

/** Algorithm-family comparison only. Modes, implementation and NSS scope need separate evidence. */
export function matchesCnsa2Primitive(label: string, layer: ProtectionLayer): boolean {
  const name = label.trim().toUpperCase()
  return (layer === 'symmetric' && /^AES[-_ ]?256(?:[-_ ][A-Z][A-Z0-9]*)?$/.test(name))
    || (layer === 'hash' && /^SHA[-_ ]?(?:384|512)$/.test(name))
}

/** Strength verdicts that require operator action. */
export function needsAction(profileValue: StrengthProfile): boolean {
  return (
    profileValue.strength === 'broken' ||
    profileValue.strength === 'weakened' ||
    profileValue.strength === 'quantum-vulnerable'
  )
}

export const STRENGTH_LABEL: Record<ProtectionStrength, string> = {
  'quantum-safe': 'Quantum Safe',
  'post-quantum': 'Post-Quantum',
  adequate: 'Adequate',
  weakened: 'Weakened by Grover',
  'quantum-vulnerable': 'Quantum Vulnerable',
  broken: 'Broken',
  unknown: 'Unknown',
}

/** Severity a finding about this primitive should carry. */
export function severityForStrength(profileValue: StrengthProfile): 'critical' | 'high' | 'medium' | 'low' {
  // Only a CLASSICAL break is critical — it is exploitable now. A
  // Shor-breakable primitive is high: urgent for long-lived data, but not an
  // attack anyone can mount today. This matches how the TLS pages rank the same
  // primitives, so the two consoles cannot disagree about RSA.
  if (profileValue.strength === 'broken') return 'critical'
  if (profileValue.strength === 'quantum-vulnerable') return 'high'
  if (profileValue.strength === 'weakened') return 'high'
  if (profileValue.strength === 'adequate') return 'medium'
  return 'low'
}
