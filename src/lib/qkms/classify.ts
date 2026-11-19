/**
 * Key classification — what a key IS, decided from the algorithm alone.
 *
 * ── Why this module exists ──────────────────────────────────────────────────
 * The previous QKMS classified keys by running regexes over a concatenation of
 * the key name, backend, purpose, environment AND `JSON.stringify(metadata)`:
 *
 *     const sourceText = `${name} ${algorithm} ${backend} ${purpose} …`
 *     const weak = isWeakAlgorithm(sourceText, keySize)
 *
 * with
 *
 *     /des|3des|rc4|md5|sha-?1|dsa|rsa[_ -]?1024|…/
 *
 * Two failures followed directly:
 *
 *   1. `dsa` is a substring of **ML-DSA** and **SLH-DSA**. Every post-quantum
 *      signature key in the estate was therefore published as a deprecated,
 *      weak algorithm — and, because `weak` also forces `rotationRequired`,
 *      each one was additionally counted as rotation-due and used to BLOCK the
 *      migration gate. The platform was telling tenants to migrate away from
 *      the very algorithms it tells them to migrate to.
 *
 *   2. Matching the metadata blob meant a key whose notes mentioned
 *      `aes-cbc`, or an asset called `RC4 Networks`, was deprecated by
 *      association.
 *
 * The fix is the same one the scanner already made: classify the PRIMITIVE, via
 * the shared decomposer in `lib/crypto/suite-anatomy`, and never the blob. One
 * reading of an algorithm string across the scanner, the transport pages, the
 * encryption pages and QKMS.
 */

import { analyzeCryptoObservation, type SuiteAnatomy } from '@/lib/crypto/suite-anatomy'
import type { KeyClass, KeyPqcPosture, MigrationRequirement } from './types'

export interface KeyClassification {
  /** Canonical grouping label — the primitive that carries the risk. */
  family: string
  keyClass: KeyClass
  posture: KeyPqcPosture
  migrationRequirement: MigrationRequirement
  /** Human-readable justification. Rendered wherever the posture is shown. */
  reason: string
  /** Broken today, independently of quantum. Drives `deprecated` counts. */
  deprecated: boolean
  /** Shor-breakable asymmetric material. Drives PQC migration counts. */
  quantumVulnerable: boolean
  /** Effective symmetric strength in bits, when the primitive defines one. */
  securityBits: number | null
  anatomy: SuiteAnatomy
}

const BROKEN_PRIMITIVE = /^(DES|3DES|RC4|MD5|SHA-1)$/
const BROKEN_RSA = /^RSA-1024$/

/**
 * Purpose text is used ONLY to disambiguate a key class the algorithm leaves
 * open (an AES key used for wrapping vs for bulk). It never decides posture.
 */
const PURPOSE_SIGNATURE = /\bsign|signature|signing|attest|certif|jwt|token issu|code.?sign\b/i
const PURPOSE_KEM = /\bkem|encapsulat|key exchange|key establish|key agreement|handshake|tls\b/i
const PURPOSE_WRAP = /\bwrap|unwrap|envelope|kek|master key|data key|tde|at.rest\b/i

function bitsForSymmetric(bulk: string | null, keySize: number | null): number | null {
  if (bulk) {
    if (/256/.test(bulk)) return 256
    if (/128/.test(bulk)) return 128
    if (/ChaCha20/.test(bulk)) return 256
    if (/^3DES$/.test(bulk)) return 112
    if (/^DES$/.test(bulk)) return 56
    if (/^RC4$/.test(bulk)) return 0
  }
  return keySize && keySize > 0 ? keySize : null
}

/**
 * RSA below 3072 bits is not "weak today" in the DES sense — it is inadequate
 * for new issuance and Shor-breakable regardless. Both facts are reported
 * separately rather than collapsed into one `weak` boolean, because they call
 * for different remediation.
 */
function rsaInadequate(family: string, keySize: number | null): boolean {
  /*
   * Gated on the family actually BEING RSA.
   *
   * Without the gate this ran on every algorithm and compared an elliptic-curve
   * key size against an RSA modulus threshold — so `ECDSA P-256` (256 bits, and
   * perfectly sound classically) was reported as DEPRECATED, i.e. "broken
   * against classical attack". On a live estate that single comparison marked
   * six certificate keys broken and BLOCKED the migration gate with a reason
   * that was not true. 256 bits of ECC ≈ 3072 bits of RSA; the two scales are
   * not comparable and must never be compared.
   */
  if (!/^RSA/i.test(family)) return false
  const declared = family.match(/^RSA-(\d+)$/)?.[1]
  const bits = declared ? Number(declared) : keySize
  return Boolean(bits && bits > 0 && bits < 2048)
}

/**
 * Discrete-log primitives named on their own.
 *
 * Returns `null` for anything it does not recognise, so the caller falls back
 * to an explicit "unknown posture" rather than to a guess.
 */
function classicalFallthrough(value: string): Pick<KeyClassification, 'family' | 'keyClass' | 'posture' | 'migrationRequirement' | 'reason' | 'quantumVulnerable'> | null {
  const upper = value.toUpperCase()
  /*
   * Anchored deliberately, not a word-boundary form: a boundary sits between
   * the hyphen and the D of `ML-DSA`, so `\bDSA\b` would match the very
   * algorithms this module exists to stop mis-classifying. Requiring the token
   * to start the string — or to follow a character that is neither a letter nor
   * a hyphen — matches `DSA` and `DSA-2048` while `ML-DSA-65` and `SLH-DSA`
   * cannot. (They never reach here anyway: the decomposer resolves them to
   * `signature`, and this helper only runs on strings it declined.)
   */
  const isSignature = /^DSA(-|$)/.test(upper) || /[^A-Z-]DSA(-|$)/.test(upper)
  const isKex = /^DH(-|$)/.test(upper) || /ELGAMAL/.test(upper) || /DIFFIE[- ]?HELLMAN/.test(upper)
  if (!isSignature && !isKex) return null
  return {
    family: value,
    keyClass: isKex ? 'key-establishment' : 'signature',
    posture: 'quantum-vulnerable',
    migrationRequirement: 'required',
    quantumVulnerable: true,
    reason: `${value} rests on a discrete-logarithm problem Shor's algorithm solves, so a cryptographically relevant quantum computer breaks it outright. Target ${isKex ? 'ML-KEM-768, or X25519 + ML-KEM-768 while classical interoperability is still required' : 'ML-DSA-65, or Ed25519 + ML-DSA-65 as a hybrid signature'}.`,
  }
}

/**
 * Classify one key.
 *
 * @param algorithm  The algorithm string exactly as observed. Nothing else.
 * @param keySize    Declared key size, when a source carried one.
 * @param purpose    Free text used only for key-class disambiguation.
 * @param itemType   Source hint, e.g. `certificate`, so a cert-borne key is
 *                   classed as certificate material rather than a bare signature.
 */
export function classifyKey(
  algorithm: string,
  keySize: number | null = null,
  purpose = '',
  itemType = '',
): KeyClassification {
  const value = String(algorithm || '').trim()
  const anatomy = analyzeCryptoObservation({ algorithm: value, itemType }, Boolean(value))

  const base = {
    anatomy,
    securityBits: null as number | null,
    deprecated: false,
    quantumVulnerable: false,
  }

  if (!value || anatomy.kind === 'policy') {
    /*
     * Classical primitives the shared decomposer leaves unresolved.
     *
     * `analyzeCryptoObservation` handles ECDSA, RSA, Ed25519, ECDHE and the PQC
     * families, but a bare `DSA`, `DH` or `ElGamal` falls through to `policy` —
     * so without this branch a DSA signing key would be published as "unknown
     * posture" rather than as Shor-breakable, and would silently escape the
     * migration gate.
     *
     * Matching `DSA` here is safe ONLY because it is gated on the decomposer
     * having already declined the string: `ML-DSA-65` and `SLH-DSA` resolve to
     * `signature`, never `policy`, so they can never reach this line. That
     * ordering is doing the work the predecessor's bare `/dsa/` could not.
     */
    const classical = classicalFallthrough(value)
    if (classical) return { ...base, ...classical }

    return {
      ...base,
      family: value || 'Unknown',
      keyClass: 'unknown',
      posture: 'unknown',
      migrationRequirement: 'unknown',
      reason: value
        ? `"${value}" does not name a cryptographic primitive, so no posture can be asserted for this key.`
        : 'No algorithm was observed for this key, so its quantum posture is unknown.',
    }
  }

  const family = anatomy.family
  const upperFamily = family.toUpperCase()
  const identifier = value.toUpperCase().replace(/ML-?(KEM|DSA)/g, 'ML-$1').replace(/SLH-?DSA/g, 'SLH-DSA')
  const kem = identifier.match(/(?:\b|X25519|SECP256R1|SECP384R1)ML-KEM-?(512|768|1024)\b/)?.[1]
  const dsa = identifier.match(/\bML-DSA-?(44|65|87)\b/)?.[1]
  const slh = identifier.match(/\bSLH-DSA-(SHA2|SHAKE)-(128|192|256)(S|F)\b/)?.[0]
  const signature = anatomy.kind === 'signature' || anatomy.kind === 'certificate'
  const isPqcName = /ML-KEM|ML-DSA|SLH-DSA|KYBER|DILITHIUM|SPHINCS|SNTRUP/.test(identifier)
  if (isPqcName && (/KYBER|DILITHIUM|SPHINCS|SNTRUP/.test(identifier) || !(signature ? dsa || slh : kem))) {
    return {
      ...base,
      family: value,
      keyClass: signature ? itemType === 'certificate' ? 'certificate' : 'signature' : 'key-establishment',
      posture: 'unknown',
      migrationRequirement: 'unknown',
      reason: 'The observation does not establish a finalized NIST PQC parameter set. Verify the exact algorithm, parameters and implementation with the provider.',
    }
  }

  /* ---- Post-quantum key establishment --------------------------- */
  if (anatomy.quantumClass === 'hybrid') {
    return {
      ...base,
      family,
      keyClass: signature ? itemType === 'certificate' ? 'certificate' : 'signature' : 'key-establishment',
      posture: 'hybrid',
      migrationRequirement: 'monitor',
      reason: `${family} reports a hybrid ${signature ? 'signature' : 'key establishment'} configuration. Verify the protocol profile, component parameters and combiner or verification rules before relying on it.`,
    }
  }

  if (kem) {
    return {
      ...base,
      family: `ML-KEM-${kem}`,
      keyClass: 'key-establishment',
      posture: 'post-quantum',
      migrationRequirement: 'none',
      reason: `ML-KEM-${kem} names a FIPS 203 parameter set for key encapsulation. This observation does not validate the implementation.`,
    }
  }

  /* ---- Post-quantum signatures ---------------------------------- */
  if (dsa) {
    return {
      ...base,
      family: 'ML-DSA',
      keyClass: itemType === 'certificate' ? 'certificate' : 'signature',
      posture: 'post-quantum',
      migrationRequirement: 'none',
      reason: `ML-DSA-${dsa} names a FIPS 204 digital signature parameter set. This observation does not validate the implementation.`,
    }
  }

  if (slh) {
    return {
      ...base,
      family: 'SLH-DSA',
      keyClass: itemType === 'certificate' ? 'certificate' : 'signature',
      posture: 'post-quantum',
      migrationRequirement: 'none',
      reason: `${slh.toLowerCase().replace(/^slh-dsa-(sha2|shake)/, (_, hash) => `SLH-DSA-${hash.toUpperCase()}`)} names a FIPS 205 stateless hash-based digital signature parameter set. This observation does not validate the implementation.`,
    }
  }

  /* ---- Broken-today primitives ---------------------------------- */
  const bulk = anatomy.bulk
  if ((bulk && BROKEN_PRIMITIVE.test(bulk)) || (anatomy.mac && BROKEN_PRIMITIVE.test(anatomy.mac) && anatomy.kind === 'hash')) {
    const broken = bulk && BROKEN_PRIMITIVE.test(bulk) ? bulk : anatomy.mac!
    return {
      ...base,
      family: broken,
      keyClass: anatomy.kind === 'hash' ? 'hash-kdf' : 'symmetric-encryption',
      posture: 'deprecated',
      migrationRequirement: 'required',
      deprecated: true,
      securityBits: bitsForSymmetric(bulk, keySize),
      reason: `${broken} is broken against classical attack and must not protect any data. Replace before considering quantum exposure.`,
    }
  }

  if (BROKEN_RSA.test(upperFamily) || rsaInadequate(family, keySize)) {
    return {
      ...base,
      family,
      keyClass: itemType === 'certificate' ? 'certificate' : 'signature',
      posture: 'deprecated',
      migrationRequirement: 'required',
      deprecated: true,
      quantumVulnerable: true,
      reason: `${family} is below the minimum modulus for issuance and is Shor-breakable. Replace immediately, and target ML-DSA or a hybrid signature.`,
    }
  }

  /* ---- Symmetric --------------------------------------------------- */
  if (anatomy.kind === 'symmetric' || (bulk && !anatomy.keyExchange && !anatomy.authentication)) {
    const bits = bitsForSymmetric(bulk, keySize)
    if (anatomy.quantumClass === 'safe') {
      return {
        ...base,
        family,
        keyClass: 'symmetric-encryption',
        posture: 'quantum-resistant-symmetric',
        migrationRequirement: 'none',
        securityBits: bits,
        reason: `${family} is a symmetric cipher. Grover's algorithm halves its effective strength${bits ? ` to ~${Math.round(bits / 2)} bits` : ''}, which remains beyond reach — no algorithm migration is required. Custody and rotation evidence still apply.`,
      }
    }
    return {
      ...base,
      family,
      keyClass: 'symmetric-encryption',
      posture: 'weakened-symmetric',
      migrationRequirement: 'recommended',
      securityBits: bits,
      reason: `${family} is symmetric and not broken, but Grover reduces it${bits ? ` to ~${Math.round(bits / 2)} bits` : ''}. Move to a 256-bit cipher for long-lived data.`,
    }
  }

  /* ---- Hash / KDF -------------------------------------------------- */
  if (anatomy.kind === 'hash') {
    const safe = anatomy.quantumClass === 'safe'
    return {
      ...base,
      family,
      keyClass: 'hash-kdf',
      posture: safe ? 'quantum-resistant-symmetric' : 'deprecated',
      migrationRequirement: safe ? 'none' : 'required',
      deprecated: !safe,
      reason: safe
        ? `${family} is a hash/KDF primitive with no quantum-vulnerable key agreement. No migration is required.`
        : `${family} is a broken hash and must not anchor integrity or signatures.`,
    }
  }

  /* ---- Classical asymmetric ---------------------------------------- */
  if (anatomy.quantumClass === 'vulnerable') {
    const isKex = anatomy.kind === 'key-exchange'
    const isSig = anatomy.kind === 'signature' || anatomy.kind === 'certificate'
    const inferredClass: KeyClass = isKex
      ? 'key-establishment'
      : isSig
        ? (itemType === 'certificate' ? 'certificate' : 'signature')
        : PURPOSE_SIGNATURE.test(purpose)
          ? 'signature'
          : PURPOSE_KEM.test(purpose)
            ? 'key-establishment'
            : 'unknown'

    const target = inferredClass === 'key-establishment'
      ? 'ML-KEM-768, or X25519 + ML-KEM-768 while classical interoperability is still required'
      : 'ML-DSA-65, or Ed25519 + ML-DSA-65 as a hybrid signature'

    return {
      ...base,
      family,
      keyClass: inferredClass,
      posture: 'quantum-vulnerable',
      migrationRequirement: 'required',
      quantumVulnerable: true,
      reason: `${family} rests on a problem Shor's algorithm solves, so a cryptographically relevant quantum computer breaks it outright. Target ${target}.`,
    }
  }

  /* ---- Cipher suites reaching here carry a classical key agreement -- */
  if (anatomy.kind === 'cipher-suite') {
    return {
      ...base,
      family,
      keyClass: 'key-establishment',
      posture: anatomy.quantumClass === 'safe' ? 'quantum-resistant-symmetric' : 'quantum-vulnerable',
      migrationRequirement: anatomy.quantumClass === 'safe' ? 'monitor' : 'required',
      quantumVulnerable: anatomy.quantumClass !== 'safe',
      reason: `Key material bound to ${family}. The suite's quantum posture is decided by its key agreement, not by its bulk cipher.`,
    }
  }

  return {
    ...base,
    family,
    keyClass: PURPOSE_WRAP.test(purpose) ? 'symmetric-encryption' : 'unknown',
    posture: 'unknown',
    migrationRequirement: 'unknown',
    reason: `${family} could not be resolved to a known primitive class, so no posture is asserted. Classify the key to bring it under governance.`,
  }
}

/* ------------------------------------------------------------------ */
/* Key-material recognition                                            */
/* ------------------------------------------------------------------ */

/**
 * Does this row describe KEY MATERIAL, as opposed to a protocol setting, a
 * finding title or a library name?
 *
 * The predecessor (`isKeyText`) matched `key|kms|hsm|vault|…|encrypt|decrypt`
 * against `JSON.stringify(row)`, so any row whose JSON contained the word
 * "key" — including `{"api_key_present": false}` and every finding titled
 * "Weak Key Exchange" — became a key. Requiring an actual primitive plus a
 * key-bearing signal is what keeps the inventory an inventory of keys.
 */
/**
 * Item types that denote KEY MATERIAL rather than an observation about it.
 *
 * `crypto_inventory` is this platform's CBOM: a register of cryptographic
 * COMPONENTS observed on an asset — protocol versions, cipher suites,
 * key-agreement algorithms, certificate facts, findings. Almost none of those
 * rows is a key.
 */
const KEY_MATERIAL_ITEM_TYPES = new Set([
  'key', 'keys', 'key-material', 'keypair', 'key-pair', 'private-key', 'private_key',
  'public-key', 'public_key', 'secret', 'secrets', 'symmetric-key', 'signing-key',
  'keystore', 'key-store', 'hsm-key', 'kms-key', 'vault-key',
])

/** Names that describe a finding or a configuration fact, never key material. */
const NOT_KEY_MATERIAL = /\b(library|package|dependency|cve-|advisory|banner|header|policy|violation|misconfiguration|information disclosure|detection rule|handshake|protocol|cipher suite|hsts|dnssec|caa|ocsp|revocation|stapling|hndl risk|risk:)\b/i

export interface KeyMaterialProbe {
  /** `crypto_inventory.item_type` / `scanner_evidence.evidence_type`. */
  itemType?: string
  /** Free text: the row's name or summary. */
  name?: string
  algorithm?: string
  /** A key fingerprint is decisive: only key material has one. */
  fingerprint?: string | null
}

/**
 * Does this row describe KEY MATERIAL, as opposed to an observation about
 * cryptography?
 *
 * ── Why this had to get much stricter ──────────────────────────────────────
 * The predecessor (`isKeyText`) matched `key|kms|hsm|vault|…|encrypt|decrypt`
 * against `JSON.stringify(row)`, so every row whose JSON contained the word
 * "key" became a key. On a live estate that turned a CBOM of 72 scan
 * observations into a key inventory containing entries called
 * "Detection Rule CERT-002", "Certificate Signature: ecdsa-with-SHA256" and
 * "TLS Handshake — https://www.cloudflare.com/", and produced five separate
 * "keys" for one certificate — each with its own owner gap, its own violations
 * and its own risk score.
 *
 * The rule now: a row is key material only when it is IDENTIFIED as such —
 * by a key-bearing item type, or by a fingerprint, which nothing but key
 * material carries. A name that merely mentions keys is not enough, because
 * finding titles mention keys constantly.
 */
export function namesKeyMaterial(probe: KeyMaterialProbe): boolean {
  const itemType = String(probe.itemType || '').trim().toLowerCase()
  const name = String(probe.name || '').trim()
  const algorithm = String(probe.algorithm || '').trim()

  // A fingerprint identifies key material regardless of how the row is labelled.
  if (probe.fingerprint && String(probe.fingerprint).trim().length >= 8) return true

  if (!KEY_MATERIAL_ITEM_TYPES.has(itemType)) return false
  if (NOT_KEY_MATERIAL.test(name) || NOT_KEY_MATERIAL.test(algorithm)) return false

  // Even a key-typed row must name a primitive; otherwise it carries a finding
  // title in its algorithm column and there is nothing to classify.
  return classifyKey(algorithm || name).anatomy.kind !== 'policy'
}

/* ------------------------------------------------------------------ */
/* Key type & custody inference                                        */
/* ------------------------------------------------------------------ */

/** Operational key type, for the inventory's "Type" column. */
export function inferKeyType(classification: KeyClassification, hints: string): string {
  const text = String(hints || '').toLowerCase()
  if (/\btde\b|database|transparent data/.test(text)) return 'Database encryption key'
  if (/tokeniz/.test(text)) return 'Tokenization key'
  if (/\bssh\b/.test(text)) return 'SSH key'
  if (/api[_ -]?key|client secret|webhook/.test(text)) return 'API secret'
  if (/root|master|kek|trust anchor/.test(text)) return 'Root / master key'
  if (/code.?sign/.test(text)) return 'Code-signing key'
  if (classification.keyClass === 'certificate' || /\btls\b|x509|certificate/.test(text)) return 'TLS / certificate key'
  if (classification.keyClass === 'signature') return 'Signing key'
  if (classification.keyClass === 'key-establishment') return 'Key-establishment key'
  if (classification.keyClass === 'symmetric-encryption') return 'Symmetric encryption key'
  if (classification.keyClass === 'hash-kdf') return 'Derivation / integrity key'
  return 'Cryptographic key'
}

/** Purpose sentence, used when no source declared one. */
export function inferPurpose(classification: KeyClassification): string {
  switch (classification.keyClass) {
    case 'key-establishment': return 'Key establishment / encapsulation'
    case 'signature': return 'Digital signatures'
    case 'certificate': return 'Certificate and TLS identity'
    case 'symmetric-encryption': return 'Data encryption'
    case 'hash-kdf': return 'Key derivation and integrity'
    default: return 'Unclassified key usage'
  }
}
