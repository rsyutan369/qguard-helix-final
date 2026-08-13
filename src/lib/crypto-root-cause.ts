/**
 * Cryptographic root-cause classification — ONE implementation, many readers.
 *
 * A scanner emits one observation per cipher suite, certificate, protocol and
 * algorithm. The `vulnerabilities` table stores one row per *root cause* so an
 * operator sees "fix this one thing" rather than eight near-identical rows.
 * Mapping observation → root cause is therefore a routing rule, and per
 * `qguard-data-integrity` Rule 5 a routing rule must exist exactly once:
 * `scanner.ts` classifies on the write path and `dashboard.ts` re-classifies on
 * the read path, and two copies of a regex table WILL drift.
 *
 * ── Why this module exists ──────────────────────────────────────────────────
 * Both copies previously bucketed on `/…|dhe|ecdh|tls_rsa|key exchange/`. Every
 * one of those alternatives is a *substring* test, so `TLS_ECDHE_ECDSA_WITH_
 * AES_128_GCM_SHA256` matched `dhe` and `ecdh` and was filed under
 * `weak-key-exchange` — a bucket whose published description reads "No ephemeral
 * key exchange - past traffic can be decrypted if the private key is
 * compromised."
 *
 * ECDHE *is* ephemeral key exchange. It is the control that provides forward
 * secrecy, not the absence of one. The classifier was calling the fix a defect.
 *
 * Two distinct facts were being collapsed into one bucket:
 *
 *   static RSA key transport   → no forward secrecy AND quantum-vulnerable
 *   ECDHE / DHE                → forward secret today, quantum-vulnerable later
 *
 * They carry different severities, different urgency and different remediation,
 * so they are now different root causes. The ephemeral guard below is the load-
 * bearing line: a suite is only "weak key exchange" when a *positive* static /
 * anonymous / no-forward-secrecy marker is present.
 *
 * Pure and dependency-free (no Express, no Supabase) so the backend, the read
 * path and any check tool can share it rather than reimplement it.
 */

export interface CryptoRootCause {
  ruleId: string
  title: string
  type: string
  description: string
  remediation: string
}

export interface RootCauseInput {
  algorithm?: unknown
  category?: unknown
  title?: unknown
  description?: unknown
  recommendation?: unknown
  remediation?: unknown
  status?: unknown
  type?: unknown
  source?: unknown
}

const text = (value: unknown) => (value == null ? '' : String(value))

/** Join every field that can carry a signal into one lower-cased haystack. */
export function rootCauseHaystack(input: RootCauseInput): string {
  return [
    input.algorithm,
    input.category,
    input.title,
    input.description,
    input.recommendation,
    input.remediation,
    input.status,
    input.type,
    input.source,
  ]
    .map(text)
    .join(' ')
    .toLowerCase()
}

/* ── Key-exchange discrimination ─────────────────────────────────────────────
   Ordered so the *positive* evidence of a weak exchange is required before the
   weak bucket can be chosen. */

/** Ephemeral (forward-secret) key agreement, classical or hybrid. */
const EPHEMERAL_KEX =
  /ecdhe|\bdhe\b|_dhe_|dhe[-_]|x25519|x448|curve25519|ml-?kem|mlkem|kyber|ephemeral|forward secrecy is|pfs enabled/

/**
 * Static RSA key transport — the client encrypts the premaster secret to the
 * server's long-term RSA key. No forward secrecy at all.
 * `tls_rsa_with…` is the wire name; the prose forms cover analyst text.
 * Deliberately NOT a bare `rsa`: `TLS_ECDHE_RSA_WITH_…` is RSA *authentication*
 * over an ephemeral exchange, which is a different and much weaker finding.
 */
const STATIC_RSA_KEX = /tls_rsa_with|\btls[-_ ]rsa\b|static rsa|rsa key exchange|rsa key transport|key transport/

/** Static, anonymous or undersized finite-field Diffie-Hellman. */
const WEAK_DH =
  /static (?:dh|diffie)|anon(?:ymous)? (?:dh|diffie)|\bdh_anon\b|\badh\b|export[-_ ]?(?:grade|cipher|dh|rsa)|\bdh[-_]?(?:512|768|1024)\b|logjam|weak dh/

/** An explicit statement that forward secrecy is absent. */
const NO_FORWARD_SECRECY =
  /no forward secrecy|without forward secrecy|missing forward secrecy|lacks forward secrecy|no ephemeral key|non-?ephemeral|forward secrecy: (?:no|none|absent)/

/** Explicit analyst verdict. */
const EXPLICIT_WEAK_KEX = /weak key exchange|insecure key exchange/

/**
 * True when the text describes a key exchange with NO forward secrecy.
 *
 * The ephemeral guard: text that mentions ECDHE/DHE/X25519 and carries no
 * static/anonymous/no-FS marker is forward secret and must never land here.
 * Exported so tests and check tools can assert the discrimination directly.
 */
export function isWeakKeyExchange(haystack: string): boolean {
  const positive =
    STATIC_RSA_KEX.test(haystack) ||
    WEAK_DH.test(haystack) ||
    NO_FORWARD_SECRECY.test(haystack) ||
    EXPLICIT_WEAK_KEX.test(haystack)
  if (!positive) return false
  // A hybrid statement such as "ECDHE offered, static RSA also accepted" keeps
  // the weak verdict: the weakest accepted path is what an attacker selects.
  return true
}

/** Forward-secret but classical — safe today, harvest-now-decrypt-later later. */
export function isClassicalKeyExchange(haystack: string): boolean {
  if (isWeakKeyExchange(haystack)) return false
  if (!EPHEMERAL_KEX.test(haystack)) return false
  // Already hybrid/post-quantum: not a key-exchange root cause at all.
  if (/ml-?kem|mlkem|kyber|hybrid/.test(haystack)) return false
  return /ecdhe|\bdhe\b|_dhe_|dhe[-_]|x25519|x448|curve25519|\becdh\b/.test(haystack)
}

/* ── Remaining buckets ───────────────────────────────────────────────────────
   Each pattern is anchored so it cannot fire on an incidental substring. The
   previous bare alternatives are noted where they caused real misfiling. */

/** `(?<![a-z])ssl(?![a-z])` so "OpenSSL 3.5+" in a *recommendation* is not read
 *  as evidence that SSL is enabled on the asset. */
const LEGACY_PROTOCOL = /tls\s*1\.[01]\b|tls-?1\.[01]\b|sslv[23]|(?<![a-z])ssl(?![a-z])|legacy protocol/

const WEAK_HASH = /\bsha-?1\b|\bmd5\b|legacy mac|weak hash|sha1with|with[-_]?sha1/

/** `\b3?des\b` — a bare `des` matched "described"/"designed" in analyst prose. */
const WEAK_CIPHER = /\bcbc\b|_cbc_|\b3des\b|\bdes\b|\brc4\b|\bnull\b cipher|weak cipher|legacy cipher|non-?aead/

const CERTIFICATE = /\bcert(?:ificate|s)?\b|x\.?509|issuer|subject dn|\bpki\b|pinning|chain of trust/

const RANDOMNESS = /\brandom(?:ness)?\b|\brng\b|csprng|entropy|predictable seed/

const RUNTIME_EXPOSURE = /\bhndl\b|harvest[- ]now|shadow crypto|downgrade attack|runtime exposure/

/**
 * Classify one observation into its root cause, or return `null` when nothing
 * matches so the caller can apply its own fallback (the two call sites build
 * different fallbacks from fields only they have).
 */
export function classifyCryptoRootCause(input: RootCauseInput | string): CryptoRootCause | null {
  const haystack = typeof input === 'string' ? input.toLowerCase() : rootCauseHaystack(input)

  if (isWeakKeyExchange(haystack)) {
    return {
      ruleId: 'weak-key-exchange',
      title: 'Weak Key Exchange Algorithm',
      type: 'Key Exchange Risk',
      description:
        'No ephemeral key exchange - past traffic can be decrypted if the private key is compromised, and the exchange is quantum-vulnerable.',
      remediation:
        'Disable static RSA and anonymous/export Diffie-Hellman suites, require ECDHE or DHE, then migrate to an ML-KEM hybrid group.',
    }
  }

  if (isClassicalKeyExchange(haystack)) {
    return {
      ruleId: 'classical-key-exchange',
      title: 'Quantum-Vulnerable Key Exchange',
      type: 'Key Exchange Risk',
      description:
        'Ephemeral key exchange provides forward secrecy today, but the group is classical (ECDH/DH) and is breakable by a cryptographically relevant quantum computer, so recorded sessions remain exposed to harvest-now-decrypt-later.',
      remediation:
        'Enable a hybrid post-quantum key-exchange group (X25519MLKEM768, ML-KEM per FIPS 203) alongside the existing ephemeral group.',
    }
  }

  if (LEGACY_PROTOCOL.test(haystack)) {
    return {
      ruleId: 'legacy-tls-protocol',
      title: 'Legacy TLS Protocol',
      type: 'Protocol Risk',
      description: 'Legacy TLS or SSL protocol support was observed on this asset.',
      remediation: 'Disable SSL, TLS 1.0, and TLS 1.1; enforce TLS 1.2+ with TLS 1.3 preferred.',
    }
  }

  if (WEAK_HASH.test(haystack)) {
    return {
      ruleId: 'weak-hash-or-mac',
      title: 'Weak Hash Or MAC Algorithm',
      type: 'Hash Risk',
      description: 'A weak hash or MAC primitive was observed in cryptographic telemetry.',
      remediation: 'Retire SHA-1/MD5 MAC usage and enforce SHA-384, SHA-3, or approved AEAD suites.',
    }
  }

  if (WEAK_CIPHER.test(haystack)) {
    return {
      ruleId: 'weak-cipher-suite',
      title: 'Weak Cipher Suite',
      type: 'Cipher Suite Risk',
      description: 'A legacy or non-AEAD cipher suite was observed on this asset.',
      remediation: 'Disable CBC, RC4, DES, and 3DES suites; prefer AES-256-GCM or ChaCha20-Poly1305.',
    }
  }

  if (CERTIFICATE.test(haystack)) {
    return {
      ruleId: 'certificate-risk',
      title: 'Certificate Risk',
      type: 'Certificate Risk',
      description: 'Certificate telemetry indicates a weak, expiring, or non-PQC-ready trust object.',
      remediation: 'Rotate the certificate and plan ML-DSA or hybrid certificate adoption.',
    }
  }

  if (RANDOMNESS.test(haystack)) {
    return {
      ruleId: 'weak-randomness',
      title: 'Weak Random Number Generator',
      type: 'Entropy Risk',
      description: 'Weak or insufficient entropy was observed in cryptographic telemetry.',
      remediation: 'Move key generation and nonce generation to approved QRNG or CSPRNG sources.',
    }
  }

  if (RUNTIME_EXPOSURE.test(haystack)) {
    return {
      ruleId: 'runtime-crypto-exposure',
      title: 'Runtime Crypto Exposure',
      type: 'Runtime Exposure',
      description: 'Runtime telemetry indicates a harvest-now or downgrade-sensitive cryptographic exposure.',
      remediation: 'Open live migration controls and migrate the affected flow to a PQC or hybrid profile.',
    }
  }

  return null
}
