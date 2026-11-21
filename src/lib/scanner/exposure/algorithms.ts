/**
 * QGuard Helix Exposure Assessment Engine™ — algorithm normalisation and
 * ROLE-AWARE quantum classification.
 *
 * This module is the reason the engine does not repeat the two accuracy
 * failures the specification calls out by name:
 *
 *  §10 "Do not incorrectly classify algorithm aliases as separate cryptographic
 *       technologies."  →  Kyber and ML-KEM are ONE technology. So are
 *       Dilithium/ML-DSA and SPHINCS+/SLH-DSA. Counting them twice inflates
 *       both the CBOM headline and the vulnerable ratio.
 *
 *  §64 "Do not create simplistic `Algorithm = vulnerable` logic without
 *       considering usage."  →  The verdict is a function of (algorithm, role).
 *       AES-256 protecting data at rest is `resistant`. SHA-256 used for
 *       integrity is `resistant`. RSA-2048 signing a token is `vulnerable`.
 *       The same SHA-1 is `vulnerable` for a signature and merely `weak` (a
 *       classical, non-quantum problem) for a checksum.
 *
 *  §16 "Do not automatically claim an application is quantum-safe merely
 *       because AES-256 is present."  →  `resistant` is a per-component verdict
 *       and never propagates to the estate: the readiness figure is computed
 *       from the components whose ROLE is quantum-relevant.
 *
 * Isomorphic: no Node and no DOM imports.
 */

import type { CryptoRole, FindingSeverity, QuantumStatus } from './types';
import { hybridRoles } from '@/lib/crypto/hybrid-construction';

/**
 * Families whose primitives can be a half of a hybrid construction.
 *
 * These are the asymmetric ones — the key agreements and the signatures. A
 * hash or a symmetric cipher is never a participant, however close in the
 * source it happens to appear to a post-quantum name.
 */
const ASYMMETRIC_FAMILIES = new Set<AlgorithmFamily>(['rsa', 'ecc', 'dh', 'dsa']);

/* ────────────────────────────────────────────────────── canonical families ── */

export type AlgorithmFamily =
  | 'rsa'
  | 'ecc'
  | 'dh'
  | 'dsa'
  | 'ml-kem'
  | 'ml-dsa'
  | 'slh-dsa'
  | 'falcon'
  | 'pqc-other'
  | 'aes'
  | 'chacha'
  | 'legacy-symmetric'
  | 'sha2'
  | 'sha3'
  | 'legacy-hash'
  | 'mac'
  | 'kdf'
  | 'password-hash'
  | 'protocol'
  | 'random'
  | 'unknown';

export interface CanonicalAlgorithm {
  /** The name the platform publishes. Aliases collapse into this. */
  canonical: string;
  family: AlgorithmFamily;
  /** Standards body designation where one exists. */
  standard?: string;
  /** True when the primitive itself is broken by Shor's algorithm. */
  shorBroken: boolean;
  /** True when Grover halves the effective security (symmetric/hash). */
  groverAffected: boolean;
  /** Already broken classically, independent of quantum. */
  classicallyWeak: boolean;
  /** Aliases, lower-cased, matched on word boundaries. */
  aliases: string[];
}

/**
 * The catalogue. Order matters only for `describeAlgorithm`'s longest-match
 * scan; correctness does not depend on it.
 */
const CATALOGUE: CanonicalAlgorithm[] = [
  /* ── Asymmetric, Shor-broken ─────────────────────────────────────────── */
  {
    canonical: 'RSA',
    family: 'rsa',
    shorBroken: true,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['rsa', 'rsassa', 'rsa-pss', 'rsassa-pss', 'rsaes', 'pkcs1', 'rsa-oaep', 'rsa-sha256', 'rsa-sha1', 'sha256withrsa', 'sha1withrsa'],
  },
  {
    canonical: 'ECDSA',
    family: 'ecc',
    shorBroken: true,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['ecdsa', 'ecdsa-with-sha256', 'sha256withecdsa', 'secp256r1', 'secp384r1', 'secp521r1', 'prime256v1', 'p-256', 'p-384', 'p-521'],
  },
  {
    canonical: 'ECDH',
    family: 'ecc',
    shorBroken: true,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['ecdh', 'ecdhe', 'ecies'],
  },
  {
    canonical: 'X25519',
    family: 'ecc',
    shorBroken: true,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['x25519', 'curve25519', 'x448', 'curve448'],
  },
  {
    canonical: 'Ed25519',
    family: 'ecc',
    shorBroken: true,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['ed25519', 'eddsa', 'ed448'],
  },
  {
    canonical: 'Diffie-Hellman',
    family: 'dh',
    shorBroken: true,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['diffie-hellman', 'diffiehellman', 'dhe', 'ffdhe', 'modp'],
  },
  {
    canonical: 'DSA',
    family: 'dsa',
    shorBroken: true,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['dsa', 'dss'],
  },
  {
    canonical: 'ElGamal',
    family: 'dh',
    shorBroken: true,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['elgamal'],
  },
  {
    canonical: 'SM2',
    family: 'ecc',
    shorBroken: true,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['sm2'],
  },

  /* ── Post-quantum. Aliases collapse: Kyber IS ML-KEM. ────────────────── */
  {
    canonical: 'ML-KEM',
    family: 'ml-kem',
    standard: 'FIPS 203',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['ml-kem', 'mlkem', 'kyber', 'crystals-kyber', 'kyber512', 'kyber768', 'kyber1024', 'ml-kem-512', 'ml-kem-768', 'ml-kem-1024'],
  },
  {
    canonical: 'ML-DSA',
    family: 'ml-dsa',
    standard: 'FIPS 204',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['ml-dsa', 'mldsa', 'dilithium', 'crystals-dilithium', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'],
  },
  {
    canonical: 'SLH-DSA',
    family: 'slh-dsa',
    standard: 'FIPS 205',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['slh-dsa', 'slhdsa', 'sphincs', 'sphincs+', 'sphincsplus'],
  },
  {
    canonical: 'FN-DSA (Falcon)',
    family: 'falcon',
    standard: 'FIPS 206 (draft)',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['falcon', 'fn-dsa', 'falcon-512', 'falcon-1024'],
  },
  {
    canonical: 'Classic McEliece',
    family: 'pqc-other',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['mceliece', 'classic-mceliece'],
  },
  {
    canonical: 'BIKE',
    family: 'pqc-other',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['bike'],
  },
  {
    canonical: 'HQC',
    family: 'pqc-other',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['hqc'],
  },
  {
    canonical: 'XMSS',
    family: 'pqc-other',
    standard: 'RFC 8391',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['xmss', 'lms', 'hss'],
  },

  /* ── Symmetric ───────────────────────────────────────────────────────── */
  {
    canonical: 'AES',
    family: 'aes',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['aes', 'aes-128', 'aes-192', 'aes-256', 'aes-gcm', 'aes-cbc', 'aes-ctr', 'aes-ccm', 'aes-ecb', 'rijndael'],
  },
  {
    canonical: 'ChaCha20-Poly1305',
    family: 'chacha',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['chacha20', 'chacha20-poly1305', 'xchacha20', 'salsa20'],
  },
  {
    canonical: '3DES',
    family: 'legacy-symmetric',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: true,
    aliases: ['3des', 'triple-des', 'tripledes', 'des-ede3', 'des3'],
  },
  {
    canonical: 'DES',
    family: 'legacy-symmetric',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: true,
    aliases: ['des'],
  },
  {
    canonical: 'RC4',
    family: 'legacy-symmetric',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: true,
    aliases: ['rc4', 'arcfour'],
  },
  {
    canonical: 'Blowfish',
    family: 'legacy-symmetric',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: true,
    aliases: ['blowfish'],
  },
  {
    canonical: 'RC2',
    family: 'legacy-symmetric',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: true,
    aliases: ['rc2'],
  },
  {
    canonical: 'Camellia',
    family: 'aes',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['camellia'],
  },
  {
    canonical: 'SM4',
    family: 'aes',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['sm4'],
  },

  /* ── Hashes ──────────────────────────────────────────────────────────── */
  {
    canonical: 'SHA-2',
    family: 'sha2',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['sha-2', 'sha2', 'sha224', 'sha-224', 'sha256', 'sha-256', 'sha384', 'sha-384', 'sha512', 'sha-512'],
  },
  {
    canonical: 'SHA-3',
    family: 'sha3',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['sha-3', 'sha3', 'sha3-256', 'sha3-512', 'keccak', 'shake128', 'shake256'],
  },
  {
    canonical: 'BLAKE2',
    family: 'sha2',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['blake2', 'blake2b', 'blake2s', 'blake3'],
  },
  {
    canonical: 'SHA-1',
    family: 'legacy-hash',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: true,
    aliases: ['sha-1', 'sha1'],
  },
  {
    canonical: 'MD5',
    family: 'legacy-hash',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: true,
    aliases: ['md5'],
  },
  {
    canonical: 'MD4',
    family: 'legacy-hash',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: true,
    aliases: ['md4', 'md2'],
  },
  {
    canonical: 'RIPEMD',
    family: 'legacy-hash',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: true,
    aliases: ['ripemd', 'ripemd160'],
  },
  {
    canonical: 'SM3',
    family: 'sha2',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['sm3'],
  },

  /* ── MAC / KDF / password hashing ────────────────────────────────────── */
  {
    canonical: 'HMAC',
    family: 'mac',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['hmac'],
  },
  {
    canonical: 'Poly1305',
    family: 'mac',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['poly1305', 'cmac', 'gmac'],
  },
  {
    canonical: 'HKDF',
    family: 'kdf',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['hkdf'],
  },
  {
    canonical: 'PBKDF2',
    family: 'password-hash',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['pbkdf2'],
  },
  {
    canonical: 'Argon2',
    family: 'password-hash',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['argon2', 'argon2i', 'argon2d', 'argon2id'],
  },
  {
    canonical: 'scrypt',
    family: 'password-hash',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['scrypt'],
  },
  {
    canonical: 'bcrypt',
    family: 'password-hash',
    shorBroken: false,
    groverAffected: true,
    classicallyWeak: false,
    aliases: ['bcrypt'],
  },

  /* ── Protocols ───────────────────────────────────────────────────────── */
  {
    canonical: 'TLS',
    family: 'protocol',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['tls', 'tlsv1.2', 'tlsv1.3', 'tls-1.2', 'tls-1.3', 'mtls'],
  },
  {
    canonical: 'TLS 1.0',
    family: 'protocol',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: true,
    aliases: ['tlsv1', 'tlsv1.0', 'tls-1.0'],
  },
  {
    canonical: 'TLS 1.1',
    family: 'protocol',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: true,
    aliases: ['tlsv1.1', 'tls-1.1'],
  },
  {
    canonical: 'SSL (legacy)',
    family: 'protocol',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: true,
    aliases: ['sslv2', 'sslv3', 'ssl 3.0', 'ssl3'],
  },
  {
    canonical: 'SSH',
    family: 'protocol',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['ssh', 'sshv2'],
  },
  {
    canonical: 'JWT',
    family: 'protocol',
    shorBroken: false,
    groverAffected: false,
    classicallyWeak: false,
    aliases: ['jwt', 'jws', 'jwe', 'jose'],
  },
];

/** Pre-built alias → entry map for O(1) exact lookup. */
const ALIAS_INDEX = (() => {
  const map = new Map<string, CanonicalAlgorithm>();
  for (const entry of CATALOGUE) {
    map.set(entry.canonical.toLowerCase(), entry);
    for (const alias of entry.aliases) map.set(alias, entry);
  }
  return map;
})();

/** Aliases sorted longest-first, for substring scanning of free text. */
const ALIAS_SCAN = (() => {
  const pairs: Array<{ alias: string; entry: CanonicalAlgorithm }> = [];
  for (const entry of CATALOGUE) {
    for (const alias of entry.aliases) pairs.push({ alias, entry });
  }
  return pairs.sort((a, b) => b.alias.length - a.alias.length);
})();

/**
 * Resolve a raw algorithm string to its canonical entry.
 *
 * Exact alias match first (fast, unambiguous). Only then a bounded, word-aware
 * substring scan — and NEVER a bare `includes()`. A bare `includes('ssl')`
 * matches the string "OpenSSL" and publishes an SSL-3.0 finding for a library
 * name; a bare `includes('dh')` matches "ecdh" and splits one exposure in two.
 * The scan therefore requires a non-alphanumeric boundary on both sides.
 */
export function describeAlgorithm(raw: string | null | undefined): CanonicalAlgorithm | null {
  if (!raw) return null;
  const text = raw.trim().toLowerCase();
  if (!text) return null;

  const exact = ALIAS_INDEX.get(text);
  if (exact) return exact;

  // Strip common decorations: "RSA-2048", "AES_256_GCM", "sha256WithRSA".
  const stripped = text.replace(/[_\s]+/g, '-');
  const strippedExact = ALIAS_INDEX.get(stripped);
  if (strippedExact) return strippedExact;

  const base = stripped.replace(/-\d{2,5}$/, '');
  const baseExact = ALIAS_INDEX.get(base);
  if (baseExact) return baseExact;

  for (const { alias, entry } of ALIAS_SCAN) {
    const index = stripped.indexOf(alias);
    if (index === -1) continue;
    const before = index === 0 ? '' : stripped[index - 1];
    const after = stripped[index + alias.length] ?? '';
    const boundaryBefore = before === '' || !/[a-z0-9]/.test(before);
    // A trailing digit is part of the name ("aes256"), a trailing letter is not
    // ("openssl" must not match "ssl" — the 'l' is consumed, but "opens" is
    // not a boundary, which is exactly what this rejects).
    const boundaryAfter = after === '' || !/[a-z]/.test(after);
    if (boundaryBefore && boundaryAfter) return entry;
  }

  return null;
}

/** Canonical display name, or the trimmed input when unrecognised. */
export function canonicalAlgorithmName(raw: string | null | undefined): string {
  const entry = describeAlgorithm(raw);
  if (entry) return entry.canonical;
  return (raw ?? '').trim() || 'Unknown';
}

/** True when the two strings describe the same cryptographic technology. */
export function sameAlgorithm(a: string | null | undefined, b: string | null | undefined): boolean {
  const left = describeAlgorithm(a);
  const right = describeAlgorithm(b);
  if (left && right) return left.canonical === right.canonical;
  return (a ?? '').trim().toLowerCase() === (b ?? '').trim().toLowerCase();
}

/* ─────────────────────────────────────────────────────── key-size parsing ── */

/** Extract a key size when the raw string carries one ("RSA-2048", "AES_256"). */
export function parseKeySize(raw: string | null | undefined): number | null {
  if (!raw) return null;
  const match = raw.match(/(?:^|[^0-9])(\d{3,5})(?:$|[^0-9])/);
  if (!match) return null;
  const value = Number(match[1]);
  if (!Number.isFinite(value)) return null;
  // Plausible cryptographic key sizes only — 2024 is a year, not a key.
  const plausible = [128, 160, 192, 224, 256, 384, 512, 521, 768, 1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360];
  return plausible.includes(value) ? value : null;
}

/* ───────────────────────────────────────────────────────── role inference ── */

const ROLE_HINTS: Array<{ role: CryptoRole; patterns: RegExp[] }> = [
  { role: 'signature', patterns: [/\bsign(ing|ature)?\b/i, /createSign/i, /\bjws\b/i, /verify/i, /\bdsa\b/i] },
  { role: 'key-exchange', patterns: [/key[-_ ]?(exchange|agreement|encapsulat)/i, /\bkem\b/i, /\bdhe?\b/i, /\becdh/i] },
  { role: 'certificate', patterns: [/certificat/i, /\bx509\b/i, /\bpki\b/i, /\bcsr\b/i, /\bca\b/i] },
  { role: 'tls', patterns: [/\btls\b/i, /\bhttps\b/i, /\bssl\b/i, /cipher[-_ ]?suite/i, /\bingress\b/i] },
  { role: 'token-signing', patterns: [/\bjwt\b/i, /\btoken\b/i, /\bbearer\b/i, /\boauth\b/i] },
  { role: 'password-derivation', patterns: [/\bpassword\b/i, /\bbcrypt\b/i, /\bargon2\b/i, /\bscrypt\b/i, /\bpbkdf2\b/i] },
  { role: 'key-derivation', patterns: [/\bhkdf\b/i, /derive[-_ ]?key/i, /\bkdf\b/i] },
  { role: 'storage-encryption', patterns: [/at[-_ ]?rest/i, /\bdisk\b/i, /\bvolume\b/i, /\bbucket\b/i, /\bstorage\b/i] },
  { role: 'database-encryption', patterns: [/\bdatabase\b/i, /\brds\b/i, /\btde\b/i, /\bsql\b/i] },
  { role: 'code-signing', patterns: [/code[-_ ]?sign/i, /\bcosign\b/i, /\bnotary\b/i, /\bprovenance\b/i, /\bsigstore\b/i] },
  { role: 'key-management', patterns: [/\bkms\b/i, /key[-_ ]?vault/i, /\bhsm\b/i, /secret[-_ ]?manager/i] },
  { role: 'integrity', patterns: [/\bhmac\b/i, /\bchecksum\b/i, /\bintegrity\b/i, /\bmac\b/i] },
  { role: 'hashing', patterns: [/\bhash\b/i, /createHash/i, /\bdigest\b/i] },
  { role: 'encryption', patterns: [/\bencrypt/i, /\bcipher\b/i, /\baead\b/i] },
  { role: 'authentication', patterns: [/\bauth(entication)?\b/i, /\blogin\b/i, /\bmtls\b/i] },
  { role: 'random', patterns: [/\brandom\b/i, /\bprng\b/i, /\bentropy\b/i, /\bnonce\b/i, /\biv\b/i] },
];

/** Family-implied roles, used only when no textual hint is available. */
const FAMILY_DEFAULT_ROLE: Partial<Record<AlgorithmFamily, CryptoRole>> = {
  'ml-kem': 'key-exchange',
  'ml-dsa': 'signature',
  'slh-dsa': 'signature',
  falcon: 'signature',
  dsa: 'signature',
  dh: 'key-exchange',
  aes: 'encryption',
  chacha: 'encryption',
  'legacy-symmetric': 'encryption',
  sha2: 'hashing',
  sha3: 'hashing',
  'legacy-hash': 'hashing',
  mac: 'integrity',
  kdf: 'key-derivation',
  'password-hash': 'password-derivation',
  protocol: 'tls',
  random: 'random',
};

/**
 * Infer what the cryptography is being used FOR from the surrounding context.
 *
 * `context` should be the strongest available signal — the matched line, the
 * file path, the rule label — concatenated. When nothing indicates a role the
 * answer is the family default, and failing that `unknown`. It is never
 * guessed into `signature` just because a signature is the interesting case.
 */
export function inferRole(
  algorithm: string | null | undefined,
  context: string,
  explicit?: CryptoRole,
): CryptoRole {
  if (explicit && explicit !== 'unknown') return explicit;
  for (const hint of ROLE_HINTS) {
    if (hint.patterns.some((pattern) => pattern.test(context))) return hint.role;
  }
  const entry = describeAlgorithm(algorithm);
  if (entry) {
    if (entry.family === 'rsa' || entry.family === 'ecc') {
      // RSA and ECC are genuinely ambiguous without context: RSA does both
      // signatures and encryption, ECC does both signatures and key agreement.
      // Saying so is more useful than picking one.
      return 'unknown';
    }
    return FAMILY_DEFAULT_ROLE[entry.family] ?? 'unknown';
  }
  return 'unknown';
}

/* ────────────────────────────────────────────── role-aware classification ── */

/** Roles for which a Shor-broken primitive is an actual quantum exposure. */
const QUANTUM_RELEVANT_ROLES: readonly CryptoRole[] = [
  'key-exchange',
  'signature',
  'authentication',
  'certificate',
  'code-signing',
  'token-signing',
  'tls',
  'key-management',
  'unknown',
];

export interface QuantumVerdict {
  status: QuantumStatus;
  /** One sentence, published verbatim next to the verdict. */
  rationale: string;
  /** Recommended migration target, only when one genuinely applies. */
  migrationTarget?: string;
  /** True when this component should count toward the readiness ratio. */
  quantumRelevant: boolean;
}

/**
 * Classify one cryptographic observation.
 *
 * The verdict is `(algorithm, role, keySize, hybridEvidence)` — never the
 * algorithm alone. `hybridPartner` is set when the SAME observation carries
 * both a classical and a post-quantum primitive (X25519MLKEM768,
 * Ed25519+ML-DSA), which is `hybrid`, not `vulnerable`.
 */
export function classifyQuantum(input: {
  algorithm: string | null | undefined;
  role?: CryptoRole;
  keySize?: number | null;
  hybridPartner?: string | null;
}): QuantumVerdict {
  const entry = describeAlgorithm(input.algorithm);
  const role = input.role ?? 'unknown';
  const partner = describeAlgorithm(input.hybridPartner);

  if (!entry) {
    return {
      status: 'unknown',
      rationale: `"${(input.algorithm ?? '').trim() || 'unnamed'}" is not a cryptographic algorithm this engine recognises, so no quantum verdict is published for it.`,
      quantumRelevant: false,
    };
  }

  const pqcFamilies: AlgorithmFamily[] = ['ml-kem', 'ml-dsa', 'slh-dsa', 'falcon', 'pqc-other'];
  const selfIsPqc = pqcFamilies.includes(entry.family);

  /* Hybrid: a classical ASYMMETRIC primitive deployed alongside a PQC one.
     Both halves have to be asymmetric — the test used to be "one side is PQC
     and the other is not", which is true of every hash and every symmetric
     cipher, so MD5 named beside an ML-KEM was published as a hybrid
     construction. `hybridRoles` is the single rule, shared with the crypto
     knowledge base; see `src/lib/crypto/hybrid-construction.ts`. */
  const asParticipant = (candidate: CanonicalAlgorithm) => ({
    asymmetric: ASYMMETRIC_FAMILIES.has(candidate.family) || pqcFamilies.includes(candidate.family),
    shorBroken: candidate.shorBroken,
    entry: candidate,
  });

  const pair = partner ? hybridRoles(asParticipant(entry), asParticipant(partner)) : null;
  if (pair) {
    const classical = pair.classical.entry;
    const pqc = pair.pqc.entry;
    return {
      status: 'hybrid',
      rationale: `${classical.canonical} is combined with ${pqc.canonical}${pqc.standard ? ` (${pqc.standard})` : ''}, so the exchange stays secure if either component holds.`,
      quantumRelevant: true,
    };
  }

  if (selfIsPqc) {
    return {
      status: 'pqc',
      rationale: `${entry.canonical}${entry.standard ? ` is standardised as ${entry.standard} and` : ''} is not broken by Shor's algorithm.`,
      quantumRelevant: true,
    };
  }

  if (entry.shorBroken) {
    const relevant = QUANTUM_RELEVANT_ROLES.includes(role);
    if (!relevant) {
      return {
        status: 'vulnerable',
        rationale: `${entry.canonical} is broken by Shor's algorithm. In a ${humanRole(role)} role the migration is lower priority, but the primitive itself remains quantum-vulnerable.`,
        migrationTarget: migrationTargetFor(entry, role),
        quantumRelevant: true,
      };
    }
    return {
      status: 'vulnerable',
      rationale: `${entry.canonical}${input.keySize ? `-${input.keySize}` : ''} used for ${humanRole(role)} is broken by Shor's algorithm on a cryptographically relevant quantum computer.`,
      migrationTarget: migrationTargetFor(entry, role),
      quantumRelevant: true,
    };
  }

  // Symmetric and hash primitives. Grover halves the effective strength; that
  // is a key-size question, not a break — and it is emphatically NOT a licence
  // to call the estate quantum-safe (§16).
  if (entry.groverAffected) {
    if (entry.classicallyWeak) {
      return {
        status: 'vulnerable',
        rationale: `${entry.canonical} is already broken by classical cryptanalysis, independently of any quantum threat.`,
        migrationTarget: entry.family === 'legacy-hash' ? 'SHA-256 or SHA3-256' : 'AES-256-GCM',
        quantumRelevant: false,
      };
    }
    const strength = input.keySize ?? impliedStrength(entry);
    if (strength !== null && strength < 256 && (entry.family === 'aes' || entry.family === 'chacha')) {
      return {
        status: 'resistant',
        rationale: `${entry.canonical}-${strength} retains roughly ${Math.round(strength / 2)} bits against Grover's algorithm. It is not broken, but 256-bit keys are the recommended post-quantum margin.`,
        migrationTarget: 'AES-256-GCM',
        quantumRelevant: false,
      };
    }
    return {
      status: 'resistant',
      rationale: `${entry.canonical} is a symmetric/hash primitive. Grover's algorithm halves its effective strength, which adequate key and digest sizes already absorb — it is not a migration candidate.`,
      quantumRelevant: false,
    };
  }

  if (entry.family === 'protocol') {
    return {
      status: 'not-applicable',
      rationale: `${entry.canonical} is a protocol, not a primitive. Its quantum exposure is determined by the key-exchange and signature algorithms it negotiates.`,
      quantumRelevant: false,
    };
  }

  return {
    status: 'unknown',
    rationale: `No quantum verdict is published for ${entry.canonical} without evidence of how it is used.`,
    quantumRelevant: false,
  };
}

function impliedStrength(entry: CanonicalAlgorithm): number | null {
  if (entry.canonical === 'ChaCha20-Poly1305') return 256;
  if (entry.canonical === '3DES') return 112;
  if (entry.canonical === 'DES') return 56;
  return null;
}

function humanRole(role: CryptoRole): string {
  const labels: Record<CryptoRole, string> = {
    'key-exchange': 'key exchange',
    signature: 'digital signatures',
    encryption: 'encryption',
    authentication: 'authentication',
    integrity: 'message integrity',
    hashing: 'hashing',
    'password-derivation': 'password derivation',
    'key-derivation': 'key derivation',
    tls: 'TLS transport',
    certificate: 'certificates',
    'code-signing': 'code signing',
    'token-signing': 'token signing',
    'storage-encryption': 'storage encryption',
    'database-encryption': 'database encryption',
    'key-management': 'key management',
    random: 'random generation',
    unknown: 'an unidentified role',
  };
  return labels[role];
}

/**
 * Recommend a migration target — but only one that fits the ROLE (§23).
 *
 * "Do not blindly recommend ML-DSA for every use case." ML-DSA is a signature
 * scheme; recommending it for a key exchange is the exact error the spec calls
 * out, and it is why this function refuses to answer when the role is unknown.
 */
export function migrationTargetFor(entry: CanonicalAlgorithm, role: CryptoRole): string | undefined {
  switch (role) {
    case 'key-exchange':
      return 'ML-KEM (FIPS 203), deployed hybrid with X25519 during transition';
    case 'signature':
    case 'certificate':
    case 'code-signing':
    case 'token-signing':
      return 'ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) where a conservative hash-based signature is required';
    case 'tls':
      return 'TLS 1.3 with a hybrid X25519MLKEM768 key-agreement group';
    case 'authentication':
      return 'Hybrid Ed25519 + ML-DSA credentials';
    case 'key-management':
      return 'A KMS/HSM profile that can issue and store ML-KEM and ML-DSA key material';
    case 'encryption':
    case 'storage-encryption':
    case 'database-encryption':
      return entry.shorBroken ? 'AES-256-GCM with an ML-KEM-wrapped data key' : undefined;
    default:
      // Deliberately silent: recommending a specific PQC algorithm without
      // knowing the role is how a key-exchange gets told to adopt a signature
      // scheme.
      return undefined;
  }
}

/* ─────────────────────────────────────────────────────────────── severity ── */

/**
 * Severity from the cryptographic facts, not from the pattern's own label.
 *
 * Pattern catalogues tend to mark every RSA reference CRITICAL. That is right
 * for an RSA-1024 signing key and wrong for an RSA mention in a comment, which
 * is why `detection` participates: a `potential` match is capped.
 */
export function severityFor(input: {
  quantum: QuantumVerdict;
  classicallyWeak: boolean;
  role: CryptoRole;
  detection: 'observed' | 'inferred' | 'potential' | 'unknown';
  keySize?: number | null;
}): FindingSeverity {
  let base: FindingSeverity = 'info';

  if (input.classicallyWeak) base = 'high';
  if (input.quantum.status === 'vulnerable' && input.quantum.quantumRelevant) base = 'high';
  if (input.quantum.status === 'vulnerable' && !input.quantum.quantumRelevant) base = 'medium';
  if (input.quantum.status === 'hybrid' || input.quantum.status === 'pqc') base = 'info';
  if (input.quantum.status === 'resistant') base = 'info';

  // Internet-reachable roles carry the exposure, so they escalate.
  const exposedRoles: CryptoRole[] = ['tls', 'certificate', 'key-exchange', 'authentication', 'token-signing'];
  if (base === 'high' && exposedRoles.includes(input.role)) base = 'critical';

  // Undersized keys are a present-tense problem, not a future one.
  if (input.keySize && input.keySize <= 1024 && input.quantum.status === 'vulnerable') base = 'critical';

  if (input.detection === 'potential') return demote(demote(base));
  if (input.detection === 'inferred') return demote(base);
  return base;
}

function demote(severity: FindingSeverity): FindingSeverity {
  const ladder: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const index = ladder.indexOf(severity);
  return ladder[Math.min(ladder.length - 1, index + 1)];
}

/** Every canonical algorithm the engine knows, for capability disclosure. */
export function knownAlgorithms(): string[] {
  return CATALOGUE.map((entry) => entry.canonical);
}
