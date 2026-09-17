/**
 * Cipher-suite anatomy — what a cryptographic observation actually IS.
 *
 * Pure and dependency-free so the backend, the dashboards and the check tools
 * share one reading of an algorithm string.
 *
 * ── Why this module exists ──────────────────────────────────────────────────
 * A TLS cipher suite names four different primitives at once:
 *
 *     TLS_RSA_WITH_AES_256_GCM_SHA384
 *         └KEX┘      └──bulk──┘ └MAC┘
 *
 * Substring-matching that string picks whichever primitive the pattern happens
 * to hit first, and every consumer that did so published something false:
 *
 *   • The Harvest Now exposure matrix matched `/AES-?256/` and filed
 *     `TLS_RSA_WITH_AES_256_GCM_SHA384` under **AES-256-GCM**. One vulnerable
 *     member then marked the whole family vulnerable, so the page reported
 *     "AES-256-GCM — Critical, quantum-vulnerable". AES-256-GCM is on the
 *     platform's own approved list; the weakness is the RSA key transport, not
 *     the bulk cipher.
 *   • Forward secrecy was computed over anything whose text contained "tls",
 *     which on a live tenant matched 166 of 166 inventory rows — including 99
 *     `library` rows, `No OCSP Stapling`, `Information Disclosure` and
 *     `AES-256-GCM` itself. A quantum-safe symmetric cipher and a TLS 1.3 suite
 *     were both listed as "no forward secrecy".
 *   • `Zone Not DNSSEC-Signed` matched `/EC-/` (inside "DNSSEC-Signed") and was
 *     filed as an ECDSA algorithm.
 *
 * So: decompose first, classify the PART, never the whole string.
 *
 * Pairs with `namesCryptography()` in `scanner/finding-identity.ts`, which
 * separates measured cryptography from policy findings using the scanner's own
 * record-name prefix. Use both: that one says "is this cryptography at all",
 * this one says "what kind, and which primitive carries the risk".
 */

export type CryptoObservationKind =
  | 'cipher-suite'
  | 'key-exchange'
  | 'signature'
  | 'certificate'
  | 'symmetric'
  | 'hash'
  | 'protocol'
  | 'policy'

export type QuantumClass = 'safe' | 'hybrid' | 'vulnerable' | 'unknown'

export interface SuiteAnatomy {
  kind: CryptoObservationKind
  /** Key-agreement primitive, when the observation carries one. */
  keyExchange: string | null
  /** Authentication / signature primitive, when present. */
  authentication: string | null
  /** Bulk (symmetric) cipher, when present. */
  bulk: string | null
  /** MAC / hash, when present. */
  mac: string | null
  /**
   * true / false only when the observation actually determines it.
   * `null` = NOT APPLICABLE — a bulk cipher, a hash or a policy finding has no
   * key agreement, so it can be neither protected nor unprotected. Rendering
   * null as "unprotected" is what produced 117 unprotected "assets" on a
   * two-asset tenant.
   */
  forwardSecrecy: boolean | null
  /** Grouping label: the primitive that carries the quantum risk. */
  family: string
  /** Quantum posture of the RISK-BEARING primitive, not of the whole string. */
  quantumClass: QuantumClass
}

const upper = (value: unknown) => String(value ?? '').trim().toUpperCase()

/* ── Primitive vocabularies ─────────────────────────────────────────────── */

const EPHEMERAL_KEX = /^(ECDHE|DHE|EECDH|EDH)$/
const PQ_KEX = /ML-?KEM|KYBER/
/**
 * Hybrid key agreement: a classical and a post-quantum KEM combined, so the
 * session stays confidential while EITHER half holds.
 *
 * Covers the IANA TLS groups (X25519MLKEM768, SecP256r1MLKEM768,
 * SecP384r1MLKEM1024) and both OpenSSH methods (mlkem768x25519-sha256,
 * sntrup761x25519-sha512). Only the first two used to match: SecP384r1MLKEM1024
 * fell through to the pure-KEM branch and read as standalone ML-KEM, and
 * sntrup761x25519 — OpenSSH's default key exchange since 9.0 — matched nothing
 * and was published as an unclassified policy row.
 */
const HYBRID_KEX = /^X25519MLKEM768$|^SECP(256|384|521)R1MLKEM(512|768|1024)$|X25519.*ML-?KEM|ML-?KEM.*X25519|SNTRUP\d+X25519|X25519.*SNTRUP/

/** "P-384 + ML-KEM-1024 (hybrid)" — both halves named, from the name itself. */
function hybridKexFamily(value: string): string {
  const kem = value.match(/ML-?KEM-?(512|768|1024)/)?.[1]
  const sntrup = value.match(/SNTRUP(\d+)/)?.[1]
  const pq = sntrup ? `sntrup${sntrup}` : kem ? `ML-KEM-${kem}` : 'ML-KEM'
  const classical = /SECP384R1/.test(value) ? 'P-384' : /SECP256R1/.test(value) ? 'P-256' : /SECP521R1/.test(value) ? 'P-521' : 'X25519'
  return `${classical} + ${pq} (hybrid)`
}

/** Bulk ciphers, longest-first so AES_256_GCM wins over AES_256. */
const BULK_CIPHERS: Array<[RegExp, string]> = [
  [/CHACHA20[-_]?POLY1305/, 'ChaCha20-Poly1305'],
  [/AES[-_]?256[-_]?GCM/, 'AES-256-GCM'],
  [/AES[-_]?128[-_]?GCM/, 'AES-128-GCM'],
  [/AES[-_]?256[-_]?CBC/, 'AES-256-CBC'],
  [/AES[-_]?128[-_]?CBC/, 'AES-128-CBC'],
  [/AES[-_]?256/, 'AES-256'],
  [/AES[-_]?128/, 'AES-128'],
  [/3DES|TRIPLE[-_]?DES/, '3DES'],
  [/\bRC4\b/, 'RC4'],
  [/\bDES\b/, 'DES'],
]

const MACS: Array<[RegExp, string]> = [
  [/SHA3[-_]?512/, 'SHA3-512'],
  [/SHA3[-_]?256/, 'SHA3-256'],
  [/SHA[-_]?384/, 'SHA-384'],
  [/SHA[-_]?256/, 'SHA-256'],
  [/SHA[-_]?512/, 'SHA-512'],
  [/POLY1305/, 'Poly1305'],
  /* The trailing `(?![0-9])` is what lets `sha1WithRSAEncryption` keep its
     digest: `\b` never fires between "1" and "W", so the composite OID form
     used to lose the fact that it is signed with SHA-1. The longer SHA-2/SHA-3
     entries are matched first, so this cannot steal SHA-512 or SHA-384. */
  [/\bSHA1?\b|SHA[-_]?1(?![0-9])/, 'SHA-1'],
  [/\bMD5\b/, 'MD5'],
]

function matchFirst(text: string, table: Array<[RegExp, string]>): string | null {
  for (const [pattern, label] of table) if (pattern.test(text)) return label
  return null
}

/** Symmetric and hash primitives are quantum-resistant at adequate sizes. */
function symmetricClass(bulk: string | null): QuantumClass {
  if (!bulk) return 'unknown'
  if (/^(AES-256|AES-256-GCM|AES-256-CBC|ChaCha20-Poly1305)$/.test(bulk)) return 'safe'
  // AES-128 keeps ~64-bit security under Grover: weakened, not broken. Treated
  // as `unknown` rather than `vulnerable` so it is never shown beside RSA/ECC
  // as if a quantum computer breaks it outright.
  if (/^AES-128/.test(bulk)) return 'unknown'
  return 'vulnerable' // 3DES / DES / RC4
}

function kexClass(kex: string | null): QuantumClass {
  if (!kex) return 'unknown'
  const value = upper(kex)
  if (HYBRID_KEX.test(value) || (PQ_KEX.test(value) && /X25519|SECP|ECDH/.test(value))) return 'hybrid'
  if (PQ_KEX.test(value)) return 'safe'
  return 'vulnerable' // ECDHE, DHE, X25519 alone, static RSA/DH: all classical
}

/* ── Cipher-suite grammar ───────────────────────────────────────────────── */

/**
 * TLS 1.3 renamed its suites: `TLS_AES_256_GCM_SHA384` names only the AEAD and
 * hash because the key exchange is negotiated separately — and in TLS 1.3 it is
 * ALWAYS ephemeral. Such a suite therefore has forward secrecy by construction,
 * which the old string matching got backwards.
 */
const TLS13_SUITE = /^TLS_(AES|CHACHA20)/

function parseSuite(value: string): SuiteAnatomy | null {
  if (!value.startsWith('TLS_')) return null

  const bulk = matchFirst(value, BULK_CIPHERS)
  const mac = matchFirst(value, MACS)

  if (TLS13_SUITE.test(value) && !value.includes('_WITH_')) {
    return {
      kind: 'cipher-suite',
      keyExchange: 'Ephemeral (TLS 1.3 negotiated)',
      authentication: null,
      bulk,
      mac,
      forwardSecrecy: true,
      family: bulk ? `${bulk} (TLS 1.3)` : 'TLS 1.3 suite',
      quantumClass: symmetricClass(bulk),
    }
  }

  // TLS_<KEX>[_<AUTH>]_WITH_<BULK>_<MAC>
  const withIndex = value.indexOf('_WITH_')
  if (withIndex < 0) return null
  const head = value.slice(4, withIndex) // between TLS_ and _WITH_
  const parts = head.split('_').filter(Boolean)

  let keyExchange = parts[0] || null
  let authentication = parts.length > 1 ? parts.slice(1).join('_') : null

  // `TLS_RSA_WITH_...` is RSA KEY TRANSPORT: RSA is both the exchange and the
  // authentication, and there is no ephemeral secret at all.
  if (keyExchange === 'RSA' && !authentication) authentication = 'RSA'

  const ephemeral = keyExchange ? EPHEMERAL_KEX.test(keyExchange) : false
  const forwardSecrecy = ephemeral

  const family = ephemeral
    ? `${keyExchange}${authentication ? ` + ${authentication}` : ''}`
    : keyExchange === 'RSA'
      ? 'RSA key transport (static)'
      : keyExchange || 'Unknown key exchange'

  return {
    kind: 'cipher-suite',
    keyExchange,
    authentication,
    bulk,
    mac,
    forwardSecrecy,
    // The suite's quantum posture is decided by its KEY EXCHANGE and
    // authentication, never by its bulk cipher — that is the whole point.
    family,
    quantumClass: 'vulnerable',
  }
}

/* ── Public entry point ─────────────────────────────────────────────────── */

export interface ObservationInput {
  algorithm?: unknown
  /** Scanner record name, e.g. "Cipher Suite: TLS_…" — carries the class prefix. */
  name?: unknown
  itemType?: unknown
  protocol?: unknown
}

/**
 * Decompose one observation.
 *
 * `isCryptography` (from `namesCryptography`) must gate this: a record whose
 * name is "Certificate Revocation: No OCSP Stapling" holds a finding TITLE in
 * its algorithm column, not an algorithm, and is returned as `policy`.
 */
export function analyzeCryptoObservation(input: ObservationInput, isCryptography = true): SuiteAnatomy {
  const algorithm = String(input.algorithm ?? '').trim()
  const value = upper(algorithm)
  const itemType = String(input.itemType ?? '').trim().toLowerCase()

  const policy: SuiteAnatomy = {
    kind: 'policy',
    keyExchange: null,
    authentication: null,
    bulk: null,
    mac: null,
    forwardSecrecy: null,
    family: algorithm || 'Unclassified observation',
    quantumClass: 'unknown',
  }

  if (!value) return policy
  // A configuration/policy record never names a primitive; classifying it as
  // cryptography is how "Information Disclosure" became an algorithm.
  if (!isCryptography) return policy
  // Library inventory rows name a package, not a primitive.
  if (itemType === 'library') return { ...policy, kind: 'policy', family: algorithm }

  const suite = parseSuite(value)
  if (suite) return suite

  /* JOSE / JWS algorithm identifiers (RFC 7518) name a signature or MAC exactly.
     They were unrecognised — `RS256` read as an unclassified policy row — so a
     JWKS or OIDC configuration contributed nothing to identity posture.
     Exact whole-token match, so the tokens cannot hijack longer names. */
  const jose = value.match(/^(RS|PS|ES|HS)(256|384|512)(K?)$|^EDDSA$/)
  if (jose) {
    const [, family, bits, koblitz] = jose
    if (!family) {
      return { ...policy, kind: 'signature', authentication: algorithm, family: 'EdDSA', quantumClass: 'vulnerable' }
    }
    if (family === 'HS') {
      return { ...policy, kind: 'hash', mac: `SHA-${bits}`, family: `HMAC-SHA-${bits}`, quantumClass: 'safe' }
    }
    if (family === 'ES') {
      const curve = koblitz ? 'secp256k1' : bits === '384' ? 'P-384' : bits === '512' ? 'P-521' : 'P-256'
      return { ...policy, kind: 'signature', authentication: algorithm, mac: `SHA-${bits}`, family: `ECDSA ${curve}`, quantumClass: 'vulnerable' }
    }
    return { ...policy, kind: 'signature', authentication: algorithm, mac: `SHA-${bits}`, family: `RSA (${value})`, quantumClass: 'vulnerable' }
  }

  // Hybrid / post-quantum key agreement, named directly.
  if (HYBRID_KEX.test(value)) {
    return {
      kind: 'key-exchange',
      keyExchange: algorithm,
      authentication: null,
      bulk: null,
      mac: null,
      forwardSecrecy: true,
      family: hybridKexFamily(value),
      quantumClass: 'hybrid',
    }
  }
  if (PQ_KEX.test(value)) {
    return {
      kind: 'key-exchange',
      keyExchange: algorithm,
      authentication: null,
      bulk: null,
      mac: null,
      forwardSecrecy: true,
      family: /768/.test(value) ? 'ML-KEM-768' : 'ML-KEM',
      quantumClass: 'safe',
    }
  }
  if (/^(ECDHE|DHE)\b/.test(value) || /\bECDHE\b|\bDHE\b/.test(value)) {
    return {
      kind: 'key-exchange',
      keyExchange: algorithm,
      authentication: null,
      bulk: null,
      mac: null,
      forwardSecrecy: true,
      family: 'ECDHE (classical)',
      quantumClass: 'vulnerable',
    }
  }
  if (/^X25519$|CURVE25519/.test(value)) {
    return {
      kind: 'key-exchange',
      keyExchange: algorithm,
      authentication: null,
      bulk: null,
      mac: null,
      forwardSecrecy: true,
      family: 'X25519 (classical)',
      quantumClass: 'vulnerable',
    }
  }
  /* OpenSSH key exchange method names. Every SSH key exchange is ephemeral — a
     fresh secret per connection — so these carry forward secrecy. The generic
     branch below models STATIC TLS (EC)DH, and used to file
     `ecdh-sha2-nistp256` as "Static Diffie-Hellman" without it. */
  const sshEcdh = value.match(/^ECDH-SHA2-NISTP(256|384|521)$/)
  if (sshEcdh) {
    return {
      kind: 'key-exchange',
      keyExchange: algorithm,
      authentication: null,
      bulk: null,
      mac: 'SHA-2',
      forwardSecrecy: true,
      family: `ECDH P-${sshEcdh[1]} (classical)`,
      quantumClass: 'vulnerable',
    }
  }
  const sshDh = value.match(/^DIFFIE-HELLMAN-GROUP(\d+|-EXCHANGE)/)
  if (sshDh) {
    const group = sshDh[1]
    const size = group === '1' ? '1024-bit' : group === '14' ? '2048-bit' : group === '16' ? '4096-bit' : group === '18' ? '8192-bit' : null
    return {
      kind: 'key-exchange',
      keyExchange: algorithm,
      authentication: null,
      bulk: null,
      mac: matchFirst(value, MACS),
      forwardSecrecy: true,
      family: group === '-EXCHANGE' ? 'Diffie-Hellman group exchange (classical)' : `Diffie-Hellman group${group}${size ? ` (${size})` : ''} (classical)`,
      quantumClass: 'vulnerable',
    }
  }
  if (/^ECDH\b|^DH\b|DIFFIE/.test(value)) {
    return {
      kind: 'key-exchange',
      keyExchange: algorithm,
      authentication: null,
      bulk: null,
      mac: null,
      forwardSecrecy: false,
      family: 'Static Diffie-Hellman',
      quantumClass: 'vulnerable',
    }
  }

  // Signature / certificate primitives.
  /* Composite / hybrid signatures ("Ed25519 + ML-DSA-65", id-MLDSA65-RSA3072…)
     carry a classical AND a post-quantum signature. They matched the ML-DSA
     branch and read as pure post-quantum, overstating the migration. */
  if (/ML-?DSA|DILITHIUM|SLH-?DSA|SPHINCS/.test(value) && /ED25519|ED448|ECDSA|RSA|\bP-?(256|384|521)\b|SECP/.test(value)) {
    const level = value.match(/ML-?DSA-?(44|65|87)/)?.[1]
    const pq = /SLH-?DSA|SPHINCS/.test(value) ? 'SLH-DSA' : level ? `ML-DSA-${level}` : 'ML-DSA'
    const classical = /ED448/.test(value)
      ? 'Ed448'
      : /ED25519/.test(value)
        ? 'Ed25519'
        : /ECDSA|\bP-?(256|384|521)\b|SECP/.test(value)
          ? 'ECDSA'
          : 'RSA'
    return { ...policy, kind: 'signature', authentication: algorithm, family: `${classical} + ${pq} (hybrid)`, quantumClass: 'hybrid' }
  }
  if (/ML-?DSA|DILITHIUM/.test(value)) {
    return { ...policy, kind: 'signature', authentication: algorithm, family: 'ML-DSA', quantumClass: 'safe' }
  }
  if (/SLH-?DSA|SPHINCS/.test(value)) {
    return { ...policy, kind: 'signature', authentication: algorithm, family: 'SLH-DSA', quantumClass: 'safe' }
  }
  if (/ECDSA|SECP\d|\bP-?(256|384|521)\b/.test(value)) {
    const curve = /256K1/.test(value) ? 'secp256k1' : /384/.test(value) ? 'P-384' : /521/.test(value) ? 'P-521' : 'P-256'
    return {
      ...policy,
      kind: itemType === 'certificate' ? 'certificate' : 'signature',
      authentication: algorithm,
      mac: matchFirst(value, MACS),
      family: `ECDSA ${curve}`,
      quantumClass: 'vulnerable',
    }
  }
  if (/ED25519|ED448/.test(value)) {
    return { ...policy, kind: 'signature', authentication: algorithm, family: /ED448/.test(value) ? 'Ed448' : 'Ed25519', quantumClass: 'vulnerable' }
  }
  if (value === 'SSH-DSS') {
    return { ...policy, kind: 'signature', authentication: algorithm, family: 'DSA', quantumClass: 'vulnerable' }
  }
  /* Composite signature names carry BOTH primitives, and only one of them
     bears the quantum risk.
     ------------------------------------------------------------------------
     `sha256WithRSAEncryption` is the commonest certificate signature on the
     internet. `\bRSA\b` finds no word boundary before "Encryption", `WITHRSA`
     has none before "RSA" either, so this branch used to miss the string
     entirely — and the hash branch below then claimed it, publishing
     `kind: 'hash', quantumClass: 'safe'`. An RSA signature was reported as a
     quantum-SAFE hash by the decomposer that Harvest Now, Drift, Runtime
     Crypto, Telemetry Correlation, QKMS and the Trust Fabric all read, while
     the scanner's own panel — which classifies it separately — showed it as
     quantum-vulnerable on the same estate.

     The digest is kept in `mac`, because it is genuinely present; the quantum
     verdict comes from the signature primitive, which is the part Shor breaks.
     `ecdsa-with-SHA384` and `SHA256withECDSA` are already caught by the ECDSA
     branch above, which does the same thing. */
  if (/\bRSA\b|RSASSA|RSA-?PSS|RSA-?\d{3,4}|RSAENCRYPTION|WITH[-_]?RSA/.test(value)) {
    const bits = value.match(/\b(1024|2048|3072|4096)\b/)?.[1]
    return {
      ...policy,
      kind: itemType === 'certificate' ? 'certificate' : 'signature',
      authentication: algorithm,
      mac: matchFirst(value, MACS),
      family: bits ? `RSA-${bits}` : 'RSA',
      quantumClass: 'vulnerable',
    }
  }
  if (/WITH[-_]?(DSA|ED25519|ED448)\b|\bDSA[-_]?WITH\b/.test(value)) {
    return {
      ...policy,
      kind: itemType === 'certificate' ? 'certificate' : 'signature',
      authentication: algorithm,
      mac: matchFirst(value, MACS),
      family: /ED25519|ED448/.test(value) ? 'Ed25519' : 'DSA',
      quantumClass: 'vulnerable',
    }
  }

  // Bulk cipher named on its own.
  const bulk = matchFirst(value, BULK_CIPHERS)
  if (bulk) {
    return {
      kind: 'symmetric',
      keyExchange: null,
      authentication: null,
      bulk,
      mac: matchFirst(value, MACS),
      forwardSecrecy: null, // a bulk cipher has no key agreement
      family: bulk,
      quantumClass: symmetricClass(bulk),
    }
  }

  // Hash on its own.
  const mac = matchFirst(value, MACS)
  if (mac && /^(SHA|MD5|POLY)/.test(value)) {
    return {
      kind: 'hash',
      keyExchange: null,
      authentication: null,
      bulk: null,
      mac,
      forwardSecrecy: null,
      family: mac,
      quantumClass: /SHA-1|MD5/.test(mac) ? 'vulnerable' : 'safe',
    }
  }

  // Protocol version.
  /* `TLS-1.3` (the form the agent emits) as well as `TLSv1.3`: the hyphenated
     form used to miss this branch and read as a policy row. */
  if (/^(TLS|SSL|DTLS)[-_\s]?V?\d/.test(value)) {
    return {
      kind: 'protocol',
      keyExchange: null,
      authentication: null,
      bulk: null,
      mac: null,
      forwardSecrecy: null, // the protocol version alone does not decide it
      family: algorithm,
      quantumClass: 'unknown',
    }
  }

  return policy
}

/** Observations whose key agreement is actually determinable. */
export function determinesForwardSecrecy(anatomy: SuiteAnatomy): boolean {
  return anatomy.forwardSecrecy !== null
}
