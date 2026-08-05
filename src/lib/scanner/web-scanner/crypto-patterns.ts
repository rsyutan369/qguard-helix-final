/**
 * QGuard Web Scanner — Cryptographic Pattern Detection
 *
 * 125 patterns spanning: asymmetric (RSA/ECC/DSA/DH/ElGamal/SM2), symmetric
 * (AES/ChaCha20/3DES/DES/RC4/RC2/Blowfish/IDEA/Twofish/Camellia/SEED/SM4/Salsa20),
 * hashes (MD2/MD4/MD5/SHA-1/SHA-2/SHA-3/BLAKE2/BLAKE3/RIPEMD/Whirlpool/SM3),
 * MAC (HMAC/CMAC/GMAC/Poly1305), KDF (PBKDF2/HKDF/Argon2/bcrypt/scrypt),
 * POST-QUANTUM (ML-KEM/ML-DSA/SLH-DSA/Falcon/BIKE/HQC/McEliece/liboqs/hybrid
 * groups — the only rules that can raise a SAFE asymmetric verdict), dependency
 * manifests across 7 package ecosystems, JWT, TLS/SSH config and key material.
 *
 * Two rule shapes are needed and both matter: algorithm NAMES (`RSA`) and
 * API-CALL IDIOMS (`createHash('md5')`). Real code overwhelmingly uses the
 * latter, and matching only the former is why a repository that plainly used
 * MD5 and RSA once reported zero findings.
 *
 * When this count changes, update EXPECTED_WEB_CRYPTO_PATTERNS in
 * runtime-health.ts or the health check reports 'degraded'.
 */

import type { CryptoPattern } from './types'

export const CRYPTO_PATTERNS: CryptoPattern[] = [
  // ── RSA Detection (Patterns 1-10) ─────────────────────────────────────────

  {
    id: 1,
    regex: /\bRSA\b/i,
    label: 'RSA Key Generation',
    category: 'RSA',
    algorithm: 'RSA',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'RSA algorithm reference detected — vulnerable to Shor\'s algorithm',
  },
  {
    id: 2,
    regex: /from\s+Crypto\.PublicKey\s+import\s+RSA/,
    label: 'Python RSA Library (PyCryptodome)',
    category: 'RSA',
    algorithm: 'RSA',
    threatLevel: 'CRITICAL',
    languages: ['python'],
    description: 'Python PyCryptodome RSA import — quantum-vulnerable key generation',
  },
  {
    id: 3,
    regex: /cryptography\.hazmat\.primitives\.asymmetric\.rsa/,
    label: 'Python Cryptography RSA',
    category: 'RSA',
    algorithm: 'RSA',
    threatLevel: 'CRITICAL',
    languages: ['python'],
    description: 'Python cryptography library RSA module — quantum-vulnerable',
  },
  {
    id: 4,
    regex: /createSign\(['"]RSA/,
    label: 'Node.js RSA Signatures',
    category: 'RSA',
    algorithm: 'RSA',
    threatLevel: 'CRITICAL',
    languages: ['javascript', 'typescript'],
    description: 'Node.js RSA signature creation — quantum-vulnerable signing',
  },
  {
    id: 5,
    regex: /RSA_generate_key/,
    label: 'OpenSSL RSA Key Generation',
    category: 'RSA',
    algorithm: 'RSA',
    threatLevel: 'CRITICAL',
    languages: ['c', 'cpp'],
    description: 'OpenSSL RSA key generation function — quantum-vulnerable',
  },
  {
    id: 6,
    regex: /KeyPairGenerator\.getInstance\(["']RSA["']\)/,
    label: 'Java RSA KeyPairGenerator',
    category: 'RSA',
    algorithm: 'RSA',
    threatLevel: 'CRITICAL',
    languages: ['java'],
    description: 'Java RSA key pair generation — quantum-vulnerable',
  },
  {
    id: 7,
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
    label: 'RSA Private Key Block',
    category: 'RSA',
    algorithm: 'RSA Private Key',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'RSA private key in PEM format detected — exposed key + quantum-vulnerable algorithm',
  },
  {
    id: 8,
    regex: /-----BEGIN PUBLIC KEY-----/,
    label: 'Public Key Block',
    category: 'RSA',
    algorithm: 'Public Key (likely RSA)',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'Public key in PEM format — may be RSA/ECC, requires inspection',
  },
  {
    id: 9,
    regex: /PKCS#?1\b/i,
    label: 'PKCS#1 RSA Standard',
    category: 'RSA',
    algorithm: 'RSA (PKCS#1)',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'PKCS#1 RSA padding scheme — quantum-vulnerable algorithm',
  },
  {
    id: 10,
    regex: /RSA-?OAEP/i,
    label: 'RSA-OAEP Encryption',
    category: 'RSA',
    algorithm: 'RSA-OAEP',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'RSA-OAEP encryption — quantum-vulnerable key encapsulation',
  },

  // ── Diffie-Hellman Detection (Patterns 11-13) ─────────────────────────────

  {
    id: 11,
    regex: /DiffieHellman/i,
    label: 'Diffie-Hellman Key Exchange',
    category: 'Key Exchange',
    algorithm: 'Diffie-Hellman',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'Diffie-Hellman key exchange — breakable by Shor\'s algorithm',
  },
  {
    id: 12,
    regex: /DHE_RSA/,
    label: 'DHE-RSA Cipher Usage',
    category: 'Key Exchange',
    algorithm: 'DHE-RSA',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'DHE-RSA cipher configuration — both DH and RSA are quantum-vulnerable',
  },
  {
    id: 13,
    regex: /DH_generate_parameters/,
    label: 'OpenSSL DH Parameter Generation',
    category: 'Key Exchange',
    algorithm: 'Diffie-Hellman',
    threatLevel: 'HIGH',
    languages: ['c', 'cpp'],
    description: 'OpenSSL Diffie-Hellman parameter generation — quantum-vulnerable',
  },

  // ── Elliptic Curve Detection (Patterns 14-20) ─────────────────────────────

  {
    id: 14,
    regex: /ECDSA/i,
    label: 'ECDSA Signature Algorithm',
    category: 'ECC',
    algorithm: 'ECDSA',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'ECDSA signature algorithm — breakable by Shor\'s algorithm on ECDLP',
  },
  {
    id: 15,
    regex: /EC_KEY_new/,
    label: 'OpenSSL EC Key Generation',
    category: 'ECC',
    algorithm: 'EC Key',
    threatLevel: 'HIGH',
    languages: ['c', 'cpp'],
    description: 'OpenSSL elliptic curve key creation — quantum-vulnerable',
  },
  {
    id: 16,
    regex: /KeyPairGenerator\.getInstance\(["']EC["']\)/,
    label: 'Java EC KeyPairGenerator',
    category: 'ECC',
    algorithm: 'EC Key',
    threatLevel: 'HIGH',
    languages: ['java'],
    description: 'Java elliptic curve key pair generation — quantum-vulnerable',
  },
  {
    id: 17,
    regex: /\becdsa\b/i,
    label: 'ECDSA Reference',
    category: 'ECC',
    algorithm: 'ECDSA',
    threatLevel: 'HIGH',
    languages: ['javascript', 'typescript', 'python'],
    description: 'ECDSA algorithm reference — quantum-vulnerable signatures',
  },
  {
    id: 18,
    regex: /secp256k1/i,
    label: 'secp256k1 Curve (Blockchain)',
    category: 'ECC',
    algorithm: 'secp256k1',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'secp256k1 curve (Bitcoin/Ethereum) — quantum-vulnerable wallet cryptography',
  },
  {
    id: 19,
    regex: /secp256r1|prime256v1/i,
    label: 'secp256r1 / P-256 Curve',
    category: 'ECC',
    algorithm: 'secp256r1 (P-256)',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'NIST P-256 curve — widely used but quantum-vulnerable via ECDLP',
  },
  {
    id: 20,
    regex: /secp384r1|secp521r1/i,
    label: 'secp384r1 / P-384 Curve',
    category: 'ECC',
    algorithm: 'secp384r1 (P-384)',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'NIST P-384 curve — quantum-vulnerable via ECDLP',
  },

  // ── Weak Hash Detection (Patterns 21-23) ──────────────────────────────────

  {
    id: 21,
    regex: /\bSHA1\b|sha-?1\b/i,
    label: 'SHA-1 Hash Usage',
    category: 'Hash',
    algorithm: 'SHA-1',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'SHA-1 hash — classically broken (collision attacks demonstrated)',
  },
  {
    id: 22,
    regex: /\bMD5\b/i,
    label: 'MD5 Hash Usage',
    category: 'Hash',
    algorithm: 'MD5',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'MD5 hash — classically broken, trivial collisions possible',
  },
  {
    id: 23,
    regex: /SHA-?1\s*with\s*(RSA|DSA|ECDSA)/i,
    label: 'SHA-1 with RSA Signature',
    category: 'Hash',
    algorithm: 'SHA1withRSA',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'SHA-1 + RSA signature — broken hash with quantum-vulnerable signing',
  },

  // ── JWT Detection (Patterns 24-25) ────────────────────────────────────────

  {
    id: 24,
    regex: /\bRS(256|384|512)\b|\bPS(256|384|512)\b/i,
    label: 'JWT RSA-SHA256 Signing',
    category: 'JWT',
    algorithm: 'RS256 (RSA-SHA256)',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'JWT RS256 signing algorithm — RSA-based, quantum-vulnerable',
  },
  {
    id: 25,
    regex: /\bES(256|384|512)\b|\bEdDSA\b/i,
    label: 'JWT ECDSA-SHA256 Signing',
    category: 'JWT',
    algorithm: 'ES256 (ECDSA-P256)',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'JWT ES256 signing algorithm — ECDSA-based, quantum-vulnerable',
  },

  // ── Key Management (Patterns 26-27) ───────────────────────────────────────

  {
    id: 26,
    regex: /-----BEGIN PRIVATE KEY-----/,
    label: 'Generic Private Key Block',
    category: 'Key Management',
    algorithm: 'Private Key (PKCS#8)',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'Private key in PEM format — exposed key material in source code',
  },
  {
    id: 27,
    regex: /-----BEGIN CERTIFICATE-----/,
    label: 'PEM Certificate',
    category: 'Certificate',
    algorithm: 'X.509 Certificate',
    threatLevel: 'MEDIUM',
    languages: ['all'],
    description: 'X.509 certificate in PEM format — inspect for algorithm type',
  },

  // ── OpenSSL & CLI (Pattern 28) ────────────────────────────────────────────

  {
    id: 28,
    regex: /openssl\s+genrsa/,
    label: 'OpenSSL RSA Key Generation (CLI)',
    category: 'RSA',
    algorithm: 'RSA (via OpenSSL)',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'OpenSSL genrsa command — generating quantum-vulnerable RSA keys',
  },

  // ── TLS Cipher Configuration (Patterns 29-30) ────────────────────────────

  {
    id: 29,
    regex: /TLS_ECDHE_(RSA|ECDSA)/i,
    label: 'TLS ECDHE-RSA Cipher Suite',
    category: 'TLS',
    algorithm: 'ECDHE-RSA',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'TLS cipher suite with ECDHE-RSA — both key exchange and cert are quantum-vulnerable',
  },
  {
    id: 30,
    regex: /TLS_RSA_WITH/i,
    label: 'TLS RSA Key Exchange Cipher',
    category: 'TLS',
    algorithm: 'RSA Key Exchange',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'TLS cipher with RSA key exchange — no forward secrecy + quantum-vulnerable',
  },

  // ── Crypto Library Imports (Patterns 31-34) ───────────────────────────────

  {
    id: 31,
    regex: /javax\.crypto/,
    label: 'Java Crypto Library',
    category: 'Library',
    algorithm: 'Java Crypto API',
    threatLevel: 'MEDIUM',
    languages: ['java'],
    description: 'Java cryptography API usage — inspect for quantum-vulnerable algorithms',
  },
  {
    id: 32,
    regex: /import\s+Crypto/,
    label: 'Python PyCrypto Import',
    category: 'Library',
    algorithm: 'PyCrypto/PyCryptodome',
    threatLevel: 'MEDIUM',
    languages: ['python'],
    description: 'Python crypto library import — inspect for quantum-vulnerable algorithm usage',
  },
  {
    id: 33,
    regex: /crypto\/rsa/i,
    label: 'Go crypto/rsa Package',
    category: 'RSA',
    algorithm: 'RSA (Go)',
    threatLevel: 'CRITICAL',
    languages: ['go'],
    description: 'Go crypto/rsa package — quantum-vulnerable RSA implementation',
  },
  {
    id: 34,
    regex: /crypto\/elliptic/i,
    label: 'Go crypto/elliptic Package',
    category: 'ECC',
    algorithm: 'ECC (Go)',
    threatLevel: 'HIGH',
    languages: ['go'],
    description: 'Go crypto/elliptic package — quantum-vulnerable ECC implementation',
  },

  // ── Blockchain / Wallet Keys (Pattern 35) ─────────────────────────────────

  {
    id: 35,
    regex: /0x[a-fA-F0-9]{64}/,
    label: 'Potential Wallet Private Key',
    category: 'Blockchain',
    algorithm: 'Hex Private Key (256-bit)',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'Potential 256-bit private key (blockchain wallet) — exposed key material',
  },

  // ── Rust Crypto Detection (Patterns 36-38) ────────────────────────────────

  {
    id: 36,
    regex: /use\s+rsa::|RsaPrivateKey::new|RsaPublicKey/,
    label: 'Rust RSA Crate Usage',
    category: 'RSA',
    algorithm: 'RSA (Rust)',
    threatLevel: 'CRITICAL',
    languages: ['rust'],
    description: 'Rust rsa crate usage — quantum-vulnerable RSA implementation',
  },
  {
    id: 37,
    regex: /use\s+p256::|use\s+p384::|use\s+k256::/,
    label: 'Rust ECC Crate Usage',
    category: 'ECC',
    algorithm: 'ECC (Rust)',
    threatLevel: 'HIGH',
    languages: ['rust'],
    description: 'Rust elliptic curve crate — quantum-vulnerable via ECDLP',
  },
  {
    id: 38,
    regex: /use\s+ed25519_dalek::|Ed25519/,
    label: 'Rust Ed25519 Usage',
    category: 'ECC',
    algorithm: 'Ed25519 (Rust)',
    threatLevel: 'HIGH',
    languages: ['rust'],
    description: 'Ed25519 signature scheme — quantum-vulnerable EdDSA on Curve25519',
  },

  // ── C# / .NET Crypto Detection (Patterns 39-42) ──────────────────────────

  {
    id: 39,
    regex: /RSACryptoServiceProvider|RSA\.Create/,
    label: '.NET RSA Provider',
    category: 'RSA',
    algorithm: 'RSA (.NET)',
    threatLevel: 'CRITICAL',
    languages: ['csharp'],
    description: '.NET RSA cryptographic provider — quantum-vulnerable',
  },
  {
    id: 40,
    regex: /ECDsa\.Create|ECDiffieHellman\.Create/,
    label: '.NET ECC Provider',
    category: 'ECC',
    algorithm: 'ECDSA/ECDH (.NET)',
    threatLevel: 'HIGH',
    languages: ['csharp'],
    description: '.NET elliptic curve provider — quantum-vulnerable via Shor\'s',
  },
  {
    id: 41,
    regex: /DSACryptoServiceProvider|DSA\.Create/,
    label: '.NET DSA Provider',
    category: 'DSA',
    algorithm: 'DSA (.NET)',
    threatLevel: 'HIGH',
    languages: ['csharp'],
    description: '.NET DSA cryptographic provider — quantum-vulnerable',
  },
  {
    id: 42,
    regex: /System\.Security\.Cryptography/,
    label: '.NET Crypto Namespace',
    category: 'Library',
    algorithm: '.NET Crypto API',
    threatLevel: 'MEDIUM',
    languages: ['csharp'],
    description: '.NET System.Security.Cryptography usage — inspect for quantum-vulnerable algorithms',
  },

  // ── Swift / iOS Crypto Detection (Patterns 43-45) ─────────────────────────

  {
    id: 43,
    regex: /SecKeyCreateRandomKey|kSecAttrKeyTypeRSA/,
    label: 'iOS/macOS RSA Key Generation',
    category: 'RSA',
    algorithm: 'RSA (Apple Security)',
    threatLevel: 'CRITICAL',
    languages: ['swift'],
    description: 'Apple Security framework RSA key generation — quantum-vulnerable',
  },
  {
    id: 44,
    regex: /kSecAttrKeyTypeECSECPrimeRandom|SecKeyCreateSignature/,
    label: 'iOS/macOS ECC Operations',
    category: 'ECC',
    algorithm: 'ECDSA (Apple Security)',
    threatLevel: 'HIGH',
    languages: ['swift'],
    description: 'Apple Security framework ECC operations — quantum-vulnerable',
  },
  {
    id: 45,
    regex: /CryptoKit\.P256|CryptoKit\.P384|CryptoKit\.P521|Curve25519/,
    label: 'Swift CryptoKit ECC',
    category: 'ECC',
    algorithm: 'CryptoKit ECC',
    threatLevel: 'HIGH',
    languages: ['swift'],
    description: 'Swift CryptoKit elliptic curve usage — quantum-vulnerable',
  },

  // ── Config File Detection (Patterns 46-50) ────────────────────────────────

  {
    id: 46,
    regex: /ssl_ciphers|ssl_protocols|SSLCipherSuite|SSLProtocol/,
    label: 'TLS Configuration Directive',
    category: 'TLS',
    algorithm: 'TLS Config',
    threatLevel: 'MEDIUM',
    languages: ['all'],
    description: 'Server TLS configuration — inspect for quantum-vulnerable cipher suites',
  },
  {
    id: 47,
    regex: /KexAlgorithms|Ciphers|MACs.*hmac/,
    label: 'SSH Crypto Configuration',
    category: 'SSH',
    algorithm: 'SSH Crypto Config',
    threatLevel: 'MEDIUM',
    languages: ['all'],
    description: 'SSH cryptographic configuration — inspect for quantum-vulnerable algorithms',
  },
  {
    id: 48,
    regex: /tls_ecdhe_rsa|tls_rsa_with|ssl_prefer_server_ciphers/i,
    label: 'Cipher Suite Configuration',
    category: 'TLS',
    algorithm: 'TLS Cipher Config',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'TLS cipher suite configuration — may include quantum-vulnerable suites',
  },
  {
    id: 49,
    regex: /gpg_key|pgp_|openpgp/i,
    label: 'PGP/GPG Key Reference',
    category: 'Key Management',
    algorithm: 'PGP/GPG',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'PGP/GPG key reference — typically uses quantum-vulnerable RSA or ECC',
  },
  {
    id: 50,
    regex: /bcrypt|scrypt|argon2|pbkdf2/i,
    label: 'Password Hashing Function',
    category: 'Hash',
    algorithm: 'Password Hash',
    threatLevel: 'LOW',
    languages: ['all'],
    description: 'Password hashing function — symmetric, quantum impact limited to Grover\'s (128-bit security)',
  },

  // ── Modern Go / Kotlin Detection (Patterns 51-54) ─────────────────────────

  {
    id: 51,
    regex: /crypto\/ed25519|crypto\/x509/,
    label: 'Go Crypto Package',
    category: 'ECC',
    algorithm: 'Ed25519/X509 (Go)',
    threatLevel: 'HIGH',
    languages: ['go'],
    description: 'Go crypto package with quantum-vulnerable signatures',
  },
  {
    id: 52,
    regex: /java\.security\.KeyPairGenerator|java\.security\.Signature/,
    label: 'Java Security API',
    category: 'Library',
    algorithm: 'Java Security API',
    threatLevel: 'MEDIUM',
    languages: ['java', 'kotlin'],
    description: 'Java Security API — inspect for quantum-vulnerable algorithm selection',
  },
  {
    id: 53,
    regex: /BouncyCastle|org\.bouncycastle/,
    label: 'BouncyCastle Crypto Library',
    category: 'Library',
    algorithm: 'BouncyCastle',
    threatLevel: 'MEDIUM',
    languages: ['java', 'kotlin', 'csharp'],
    description: 'BouncyCastle crypto library — may contain PQC or legacy algorithms',
  },
  {
    id: 54,
    regex: /nacl\.box|nacl\.sign|tweetnacl|libsodium|sodium/i,
    label: 'NaCl/Libsodium Usage',
    category: 'Library',
    algorithm: 'NaCl/Libsodium',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'NaCl/Libsodium library — uses Curve25519/Ed25519, quantum-vulnerable',
  },

  // ── Legacy / Weak Symmetric Ciphers (Patterns 55-61) ──────────────────────
  // Symmetric ciphers are only weakened (not broken) by Grover's algorithm, but
  // these are classically deprecated/broken and belong in the CBOM inventory.
  {
    id: 55,
    regex: /\b3DES\b|\bDES3\b|TripleDES|DESede|DES-EDE3|DES_EDE/i,
    label: '3DES / Triple DES',
    category: 'Symmetric',
    algorithm: '3DES',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: '3DES — 64-bit block (SWEET32), classically deprecated by NIST (disallowed after 2023)',
  },
  {
    id: 56,
    regex: /\bDES\b(?!ede|-EDE|_EDE)|DES\/CBC|DES-CBC(?!3)/,
    label: 'Single DES',
    category: 'Symmetric',
    algorithm: 'DES',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'Single DES (56-bit key) — exhaustively breakable, classically broken',
  },
  {
    id: 57,
    regex: /\bRC4\b|ARCFOUR|Rivest Cipher 4/i,
    label: 'RC4 Stream Cipher',
    category: 'Symmetric',
    algorithm: 'RC4',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'RC4 — biased keystream, classically broken and prohibited (RFC 7465)',
  },
  {
    id: 58,
    regex: /\bRC2\b/i,
    label: 'RC2 Block Cipher',
    category: 'Symmetric',
    algorithm: 'RC2',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'RC2 — legacy 64-bit block cipher, classically weak',
  },
  {
    id: 59,
    regex: /\bBlowfish\b/i,
    label: 'Blowfish Cipher',
    category: 'Symmetric',
    algorithm: 'Blowfish',
    threatLevel: 'MEDIUM',
    languages: ['all'],
    description: 'Blowfish — 64-bit block (SWEET32-exposed), legacy; migrate to AES-256-GCM',
  },
  {
    id: 60,
    regex: /\bIDEA\b(?!S|L)|IDEA-CBC/,
    label: 'IDEA Cipher',
    category: 'Symmetric',
    algorithm: 'IDEA',
    threatLevel: 'MEDIUM',
    languages: ['all'],
    description: 'IDEA — 64-bit block legacy cipher; migrate to AES-256-GCM',
  },
  {
    id: 61,
    regex: /\bTwofish\b|\bSalsa20\b|\bCamellia\b|\bSM4\b/i,
    label: 'Legacy/Regional Symmetric Cipher',
    category: 'Symmetric',
    algorithm: 'Twofish/Salsa20/Camellia/SEED/SM4',
    threatLevel: 'LOW',
    languages: ['all'],
    description: 'Symmetric cipher detected — inventory for CBOM; ensure 256-bit key strength for post-Grover margin',
  },

  // ── Broken / Legacy Hash Functions (Patterns 62-64) ───────────────────────
  {
    id: 62,
    regex: /\bMD2\b|\bMD4\b/i,
    label: 'MD2 / MD4 Hash',
    category: 'Hash',
    algorithm: 'MD2/MD4',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'MD2/MD4 — obsolete hash functions, classically broken (trivial collisions)',
  },
  {
    id: 63,
    regex: /\bRIPEMD(-?1[26]0)?\b/i,
    label: 'RIPEMD Hash',
    category: 'Hash',
    algorithm: 'RIPEMD',
    threatLevel: 'MEDIUM',
    languages: ['all'],
    description: 'RIPEMD hash family — legacy; prefer SHA-256/SHA-3 (SHA-1-era security for RIPEMD-160)',
  },
  {
    id: 64,
    regex: /\bWhirlpool\b/i,
    label: 'Whirlpool Hash',
    category: 'Hash',
    algorithm: 'Whirlpool',
    threatLevel: 'LOW',
    languages: ['all'],
    description: 'Whirlpool hash — uncommon; inventory for CBOM and confirm library support',
  },

  // ── DSA / ElGamal Asymmetric (Pattern 65) ─────────────────────────────────
  {
    id: 65,
    regex: /\bDSA\b|DSACryptoServiceProvider|ElGamal/i,
    label: 'DSA / ElGamal',
    category: 'Asymmetric',
    algorithm: 'DSA/ElGamal',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'DSA/ElGamal — discrete-log cryptography, breakable by Shor\'s algorithm',
  },

  /* ══════════════════════════════════════════════════════════════════════════
     API-CALL IDIOMS (66-99)

     The patterns above match algorithm NAMES. Real code rarely writes the name
     in isolation — it passes a lowercase string to a factory:
     `createHash('md5')`, `generateKeyPairSync('rsa')`, `hashlib.sha1()`.
     Those went undetected entirely, which is why scanning a repository that
     demonstrably used MD5 and RSA reported neither.
     ═════════════════════════════════════════════════════════════════════════ */

  // ── Node.js / JavaScript runtime crypto ───────────────────────────────────
  {
    id: 66,
    regex: /createHash\(\s*['"`](md5|md4|md2)['"`]/i,
    label: 'Node.js Broken Hash Construction',
    category: 'Hash',
    algorithm: 'MD5',
    threatLevel: 'CRITICAL',
    languages: ['javascript', 'typescript'],
    description: 'createHash("md5") — collision-broken hash in active use; replace with SHA-256 or SHA3-256',
  },
  {
    id: 67,
    regex: /createHash\(\s*['"`](sha1|sha-1)['"`]/i,
    label: 'Node.js SHA-1 Construction',
    category: 'Hash',
    algorithm: 'SHA-1',
    threatLevel: 'HIGH',
    languages: ['javascript', 'typescript'],
    description: 'createHash("sha1") — collision-broken since SHAttered; migrate to SHA-256/SHA3-256',
  },
  {
    id: 68,
    regex: /createHash\(\s*['"`](sha256|sha384|sha512|sha3-256|sha3-384|sha3-512)['"`]/i,
    label: 'Node.js Modern Hash Construction',
    category: 'Hash',
    algorithm: 'SHA-2/SHA-3',
    threatLevel: 'SAFE',
    languages: ['javascript', 'typescript'],
    description: 'SHA-2/SHA-3 family — quantum impact limited to Grover (halved margin); SHA-384+ recommended',
  },
  {
    id: 69,
    regex: /createCipheriv\(\s*['"`](des|des3|des-ede3|des-ede3-cbc|desx|rc2|rc4|bf|blowfish|cast5|idea)/i,
    label: 'Node.js Legacy Cipher Construction',
    category: 'Symmetric',
    algorithm: 'Legacy Symmetric Cipher',
    threatLevel: 'CRITICAL',
    languages: ['javascript', 'typescript'],
    description: 'Legacy/broken block or stream cipher passed to createCipheriv — classically insecure',
  },
  {
    id: 70,
    regex: /createCipheriv\(\s*['"`]aes-(128|192)-/i,
    label: 'Node.js AES-128/192',
    category: 'Symmetric',
    algorithm: 'AES-128/192',
    threatLevel: 'MEDIUM',
    languages: ['javascript', 'typescript'],
    description: 'AES-128/192 — Grover halves the effective margin; AES-256 is the PQC-recommended baseline',
  },
  {
    id: 71,
    regex: /createCipheriv\(\s*['"`]aes-256-(gcm|ccm|ocb)/i,
    label: 'Node.js AES-256 AEAD',
    category: 'Symmetric',
    algorithm: 'AES-256-GCM',
    threatLevel: 'SAFE',
    languages: ['javascript', 'typescript'],
    description: 'AES-256 AEAD — 128-bit post-quantum margin under Grover; meets the PQC symmetric baseline',
  },
  {
    id: 72,
    regex: /['"`]aes-\d{3}-ecb['"`]|['"`]AES\/ECB|Cipher\.getInstance\(\s*["'][^"']*ECB/i,
    label: 'ECB Mode Usage',
    category: 'Symmetric',
    algorithm: 'AES-ECB',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'ECB mode leaks plaintext structure — never semantically secure, regardless of key size',
  },
  {
    id: 73,
    regex: /generateKeyPair(Sync)?\(\s*['"`](rsa|rsa-pss)['"`]/i,
    label: 'Node.js RSA Key Generation',
    category: 'RSA',
    algorithm: 'RSA',
    threatLevel: 'CRITICAL',
    languages: ['javascript', 'typescript'],
    description: 'RSA keypair generation — recoverable by Shor; migrate to ML-KEM (FIPS 203) / ML-DSA (FIPS 204)',
  },
  {
    id: 74,
    regex: /generateKeyPair(Sync)?\(\s*['"`](ec|ed25519|ed448|x25519|x448|dsa|dh)['"`]/i,
    label: 'Node.js ECC/DH Key Generation',
    category: 'ECC',
    algorithm: 'ECC/DH',
    threatLevel: 'CRITICAL',
    languages: ['javascript', 'typescript'],
    description: 'Elliptic-curve or finite-field keypair generation — ECDLP/DLP recoverable by Shor',
  },
  {
    id: 75,
    regex: /createECDH\(|createDiffieHellman\(/i,
    label: 'Node.js Key Agreement',
    category: 'Key Exchange',
    algorithm: 'ECDH/DH',
    threatLevel: 'CRITICAL',
    languages: ['javascript', 'typescript'],
    description: 'Classical key agreement — harvest-now-decrypt-later exposure; deploy a hybrid PQC KEM',
  },
  {
    id: 76,
    regex: /Math\.random\(\)[^\n]{0,60}(key|token|secret|nonce|iv|salt|password)/i,
    label: 'Insecure Randomness for Key Material',
    category: 'Key Management',
    algorithm: 'Non-CSPRNG',
    threatLevel: 'CRITICAL',
    languages: ['javascript', 'typescript'],
    description: 'Math.random() is not cryptographically secure — use crypto.randomBytes / getRandomValues',
  },

  // ── Python ────────────────────────────────────────────────────────────────
  {
    id: 77,
    regex: /hashlib\.(md5|md4|sha1)\s*\(/i,
    label: 'Python Broken Hash',
    category: 'Hash',
    algorithm: 'MD5/SHA-1',
    threatLevel: 'CRITICAL',
    languages: ['python'],
    description: 'hashlib.md5/sha1 — collision-broken; migrate to hashlib.sha256 or sha3_256',
  },
  {
    id: 78,
    regex: /hashlib\.(sha256|sha384|sha512|sha3_256|sha3_384|sha3_512|blake2b)\s*\(/i,
    label: 'Python Modern Hash',
    category: 'Hash',
    algorithm: 'SHA-2/SHA-3',
    threatLevel: 'SAFE',
    languages: ['python'],
    description: 'SHA-2/SHA-3/BLAKE2 — Grover-resistant at 256-bit output; no migration required',
  },
  {
    id: 79,
    regex: /algorithms\.(TripleDES|Blowfish|ARC4|CAST5|IDEA|SEED)\b/,
    label: 'Python Legacy Cipher (pyca)',
    category: 'Symmetric',
    algorithm: 'Legacy Symmetric Cipher',
    threatLevel: 'CRITICAL',
    languages: ['python'],
    description: 'Deprecated cipher from cryptography.hazmat — classically weak, remove from the estate',
  },
  {
    id: 80,
    regex: /rsa\.generate_private_key|RSA\.generate\(/i,
    label: 'Python RSA Key Generation',
    category: 'RSA',
    algorithm: 'RSA',
    threatLevel: 'CRITICAL',
    languages: ['python'],
    description: 'RSA private key generation — recoverable by Shor; plan ML-KEM/ML-DSA migration',
  },
  {
    id: 81,
    regex: /ec\.(SECP256R1|SECP384R1|SECP521R1|SECP256K1)\(|ec\.generate_private_key/,
    label: 'Python ECC Key Generation',
    category: 'ECC',
    algorithm: 'ECDSA/ECDH',
    threatLevel: 'CRITICAL',
    languages: ['python'],
    description: 'NIST/Koblitz curve key generation — ECDLP recoverable by Shor',
  },
  {
    id: 82,
    regex: /Crypto\.Cipher\s+import\s+(DES|DES3|ARC4|Blowfish|XOR)/,
    label: 'Python PyCryptodome Legacy Cipher Import',
    category: 'Symmetric',
    algorithm: 'Legacy Symmetric Cipher',
    threatLevel: 'CRITICAL',
    languages: ['python'],
    description: 'Legacy cipher imported from PyCryptodome — classically broken primitive',
  },

  // ── Java / Kotlin / Scala ─────────────────────────────────────────────────
  {
    id: 83,
    regex: /MessageDigest\.getInstance\(\s*["'](MD5|MD2|SHA-?1)["']/i,
    label: 'Java Broken Digest',
    category: 'Hash',
    algorithm: 'MD5/SHA-1',
    threatLevel: 'CRITICAL',
    languages: ['java', 'kotlin', 'scala'],
    description: 'MessageDigest with a collision-broken algorithm — migrate to SHA-256/SHA3-256',
  },
  {
    id: 84,
    regex: /Cipher\.getInstance\(\s*["'](DES|DESede|RC2|RC4|Blowfish|ARCFOUR)/i,
    label: 'Java Legacy Cipher',
    category: 'Symmetric',
    algorithm: 'Legacy Symmetric Cipher',
    threatLevel: 'CRITICAL',
    languages: ['java', 'kotlin', 'scala'],
    description: 'Legacy JCE cipher — classically insecure; replace with AES-256-GCM',
  },
  {
    id: 85,
    regex: /KeyPairGenerator\.getInstance\(\s*["'](DSA|DiffieHellman|EdDSA|Ed25519|XDH)["']/i,
    label: 'Java Classical Keypair Generator',
    category: 'Asymmetric',
    algorithm: 'DSA/DH/EdDSA',
    threatLevel: 'CRITICAL',
    languages: ['java', 'kotlin', 'scala'],
    description: 'Discrete-log or curve keypair generation — recoverable by Shor',
  },
  {
    id: 86,
    regex: /Signature\.getInstance\(\s*["'][^"']*(withRSA|withECDSA|withDSA)/i,
    label: 'Java Classical Signature',
    category: 'Signature',
    algorithm: 'RSA/ECDSA/DSA Signature',
    threatLevel: 'CRITICAL',
    languages: ['java', 'kotlin', 'scala'],
    description: 'Classical signature scheme — migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)',
  },

  // ── Go ────────────────────────────────────────────────────────────────────
  {
    id: 87,
    regex: /crypto\/(md5|sha1|des|rc4)\b/i,
    label: 'Go Broken Crypto Package',
    category: 'Symmetric',
    algorithm: 'MD5/SHA-1/DES/RC4',
    threatLevel: 'CRITICAL',
    languages: ['go'],
    description: 'Go standard-library package for a classically broken primitive',
  },
  {
    id: 88,
    regex: /crypto\/(ecdsa|ed25519|dsa)\b|elliptic\.P(224|256|384|521)\(\)/i,
    label: 'Go Classical Asymmetric',
    category: 'ECC',
    algorithm: 'ECDSA/Ed25519/DSA',
    threatLevel: 'CRITICAL',
    languages: ['go'],
    description: 'Curve or discrete-log cryptography — ECDLP/DLP recoverable by Shor',
  },

  // ── .NET ──────────────────────────────────────────────────────────────────
  {
    id: 89,
    regex: /MD5\.Create\(\)|SHA1\.Create\(\)|MD5CryptoServiceProvider|SHA1Managed|SHA1CryptoServiceProvider/i,
    label: '.NET Broken Hash Provider',
    category: 'Hash',
    algorithm: 'MD5/SHA-1',
    threatLevel: 'CRITICAL',
    languages: ['csharp'],
    description: 'Collision-broken hash provider — migrate to SHA256/SHA3 managed providers',
  },
  {
    id: 90,
    regex: /TripleDESCryptoServiceProvider|DESCryptoServiceProvider|RC2CryptoServiceProvider|RijndaelManaged/i,
    label: '.NET Legacy Cipher Provider',
    category: 'Symmetric',
    algorithm: 'Legacy Symmetric Cipher',
    threatLevel: 'CRITICAL',
    languages: ['csharp'],
    description: 'Legacy symmetric provider — replace with AesGcm (AES-256-GCM)',
  },

  // ── Rust ──────────────────────────────────────────────────────────────────
  {
    id: 91,
    regex: /\b(md5|md-5|sha1)::(Md5|Sha1)\b|use\s+(md5|sha1)::/i,
    label: 'Rust Broken Hash Crate',
    category: 'Hash',
    algorithm: 'MD5/SHA-1',
    threatLevel: 'CRITICAL',
    languages: ['rust'],
    description: 'Collision-broken hash crate in use — migrate to sha2/sha3',
  },
  {
    id: 92,
    regex: /use\s+(x25519_dalek|k256|p521|secp256k1|ring::signature::(ECDSA|ED25519))/i,
    label: 'Rust Classical Asymmetric Crate',
    category: 'ECC',
    algorithm: 'ECC/EdDSA',
    threatLevel: 'CRITICAL',
    languages: ['rust'],
    description: 'Curve cryptography crate — ECDLP recoverable by Shor',
  },

  // ── PHP / Ruby / Perl ─────────────────────────────────────────────────────
  {
    id: 93,
    // `\bhash(` anchored: without the boundary this also matched Node's
    // `createHash('md5')`, filing a JavaScript call under the PHP rule.
    regex: /\b(md5|sha1)\s*\(\s*\$|\bhash\(\s*['"](md5|sha1)['"]|mcrypt_/i,
    label: 'PHP Broken Hash / mcrypt',
    category: 'Hash',
    algorithm: 'MD5/SHA-1',
    threatLevel: 'CRITICAL',
    languages: ['php'],
    description: 'Broken hash or the removed mcrypt extension — migrate to hash("sha256") / sodium',
  },
  {
    id: 94,
    regex: /Digest::(MD5|SHA1)\b|OpenSSL::Cipher\.new\(\s*['"](des|rc4|bf)/i,
    label: 'Ruby Broken Digest / Legacy Cipher',
    category: 'Hash',
    algorithm: 'MD5/SHA-1',
    threatLevel: 'CRITICAL',
    languages: ['ruby'],
    description: 'Collision-broken digest or legacy cipher — migrate to Digest::SHA256 / AES-256-GCM',
  },
  {
    id: 95,
    regex: /OpenSSL::PKey::(RSA|DSA|DH|EC)\b/,
    label: 'Ruby Classical Key Object',
    category: 'Asymmetric',
    algorithm: 'RSA/DSA/DH/EC',
    threatLevel: 'CRITICAL',
    languages: ['ruby'],
    description: 'Classical public-key object — recoverable by Shor; plan a PQC migration',
  },

  // ── Apple platforms ───────────────────────────────────────────────────────
  {
    id: 96,
    regex: /CC_MD5|CC_SHA1|kCCAlgorithm3DES|kCCAlgorithmDES|kCCAlgorithmRC4/,
    label: 'Apple CommonCrypto Legacy Primitive',
    category: 'Symmetric',
    algorithm: 'MD5/SHA-1/3DES/RC4',
    threatLevel: 'CRITICAL',
    languages: ['swift', 'objectivec'],
    description: 'CommonCrypto legacy primitive — migrate to CryptoKit SHA256 / AES.GCM',
  },

  // ── Symmetric baseline (named, not constructed) ───────────────────────────
  {
    id: 97,
    regex: /\bAES-?256\b|\bAES_256\b|AES\.GCM|AesGcm|aes256/i,
    label: 'AES-256',
    category: 'Symmetric',
    algorithm: 'AES-256',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'AES-256 — 128-bit security under Grover; the PQC-recommended symmetric baseline',
  },
  {
    id: 98,
    regex: /\bAES-?128\b|\bAES_128\b|aes128/i,
    label: 'AES-128',
    category: 'Symmetric',
    algorithm: 'AES-128',
    threatLevel: 'MEDIUM',
    languages: ['all'],
    description: 'AES-128 — Grover reduces the margin to 64 bits; step up to AES-256 for long-lived data',
  },
  {
    id: 99,
    regex: /ChaCha20|XChaCha20|Poly1305/i,
    label: 'ChaCha20-Poly1305',
    category: 'Symmetric',
    algorithm: 'ChaCha20-Poly1305',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'ChaCha20-Poly1305 AEAD — 256-bit key, Grover-resistant; no migration required',
  },

  /* ══════════════════════════════════════════════════════════════════════════
     POST-QUANTUM DETECTION (100-109)

     The catalogue previously had NO way to recognise post-quantum code, so a
     repository that had already migrated to ML-KEM scored identically to one
     that had done nothing. These are the only patterns that can raise a SAFE
     verdict for asymmetric cryptography.
     ═════════════════════════════════════════════════════════════════════════ */
  {
    id: 100,
    regex: /\bML-?KEM\b|\bKyber\b|kyber(512|768|1024)|FIPS\s*203/i,
    label: 'ML-KEM / Kyber (FIPS 203)',
    category: 'Post-Quantum',
    algorithm: 'ML-KEM',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'ML-KEM (FIPS 203) key encapsulation — quantum-safe key establishment',
  },
  {
    id: 101,
    regex: /\bML-?DSA\b|\bDilithium\b|dilithium(2|3|5)|FIPS\s*204/i,
    label: 'ML-DSA / Dilithium (FIPS 204)',
    category: 'Post-Quantum',
    algorithm: 'ML-DSA',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'ML-DSA (FIPS 204) lattice signature — quantum-safe digital signature',
  },
  {
    id: 102,
    regex: /\bSLH-?DSA\b|SPHINCS\+?|sphincsplus|FIPS\s*205/i,
    label: 'SLH-DSA / SPHINCS+ (FIPS 205)',
    category: 'Post-Quantum',
    algorithm: 'SLH-DSA',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'SLH-DSA (FIPS 205) hash-based signature — quantum-safe, conservative security assumption',
  },
  {
    id: 103,
    regex: /\bFalcon-?(512|1024)\b|\bBIKE\b|\bHQC\b|Classic\s*McEliece|\bFrodoKEM\b/i,
    label: 'Alternate PQC Algorithm',
    category: 'Post-Quantum',
    algorithm: 'Falcon/BIKE/HQC/McEliece',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'Alternate/round-4 PQC algorithm — quantum-safe; confirm it is an approved profile for your policy',
  },
  {
    id: 104,
    regex: /liboqs|oqs-provider|open-quantum-safe|pqcrypto|pqclean|\boqs::/i,
    label: 'Post-Quantum Library',
    category: 'Post-Quantum',
    algorithm: 'PQC Library',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'Post-quantum cryptography library in the dependency graph — quantum-safe primitives available',
  },
  {
    id: 105,
    regex: /X25519MLKEM768|X25519Kyber768|P256Kyber768|SecP256r1MLKEM768|hybrid.{0,12}(kem|kyber|mlkem)/i,
    label: 'Hybrid PQC Key Agreement',
    category: 'Post-Quantum',
    algorithm: 'Hybrid ML-KEM',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'Hybrid classical+PQC key agreement — the recommended migration posture for TLS',
  },

  /* ══════════════════════════════════════════════════════════════════════════
     DEPENDENCY & MANIFEST DETECTION (110-119)

     "Code & Dependencies" must see the dependency graph, not only call sites.
     These match manifest entries in package.json, requirements.txt, go.mod,
     Cargo.toml, pom.xml, Gemfile and composer.json.
     ═════════════════════════════════════════════════════════════════════════ */
  {
    id: 110,
    regex: /["']?(crypto-js|node-forge|jsrsasign|elliptic|sjcl|bcryptjs|jsonwebtoken|jose|node-rsa|ursa)["']?\s*[:=]\s*["'][\^~>=<\d]/i,
    label: 'JavaScript Crypto Dependency',
    category: 'Dependency',
    algorithm: 'Client/Server Crypto Library',
    threatLevel: 'HIGH',
    languages: ['javascript', 'typescript'],
    description: 'Crypto library declared in package.json — inventory its algorithms for the CBOM',
  },
  {
    id: 111,
    regex: /^\s*(pycryptodome|pycrypto|cryptography|paramiko|pyopenssl|ecdsa|rsa|pynacl)\s*[=><~!]/im,
    label: 'Python Crypto Dependency',
    category: 'Dependency',
    algorithm: 'Python Crypto Library',
    threatLevel: 'HIGH',
    languages: ['python'],
    description: 'Crypto library pinned in requirements.txt/Pipfile — inventory its algorithms for the CBOM',
  },
  {
    id: 112,
    regex: /golang\.org\/x\/crypto|github\.com\/(btcsuite|decred)\/[^\s]*secp256k1|github\.com\/cloudflare\/circl/i,
    label: 'Go Crypto Dependency',
    category: 'Dependency',
    algorithm: 'Go Crypto Module',
    threatLevel: 'HIGH',
    languages: ['go'],
    description: 'Crypto module in go.mod — inventory its algorithms for the CBOM',
  },
  {
    id: 113,
    regex: /^\s*(openssl|rustls|ring|rsa|ed25519-dalek|x25519-dalek|p256|k256|sha1|md-?5|aes-gcm|chacha20poly1305)\s*=/im,
    label: 'Rust Crypto Dependency',
    category: 'Dependency',
    algorithm: 'Rust Crypto Crate',
    threatLevel: 'HIGH',
    languages: ['rust'],
    description: 'Crypto crate in Cargo.toml — inventory its algorithms for the CBOM',
  },
  {
    id: 114,
    regex: /bcprov-jdk|bcpkix|<artifactId>\s*(bcprov|bcpkix|jose4j|nimbus-jose-jwt|java-jwt)/i,
    label: 'Java Crypto Dependency',
    category: 'Dependency',
    algorithm: 'Java Crypto Library',
    threatLevel: 'HIGH',
    languages: ['java', 'kotlin'],
    description: 'Crypto library in pom.xml/build.gradle — inventory its algorithms for the CBOM',
  },
  {
    id: 115,
    regex: /gem\s+["'](openssl|bcrypt|jwt|rbnacl)["']|["'](firebase\/php-jwt|paragonie\/sodium_compat|phpseclib\/phpseclib)["']/i,
    label: 'Ruby/PHP Crypto Dependency',
    category: 'Dependency',
    algorithm: 'Crypto Library',
    threatLevel: 'HIGH',
    languages: ['ruby', 'php'],
    description: 'Crypto library in Gemfile/composer.json — inventory its algorithms for the CBOM',
  },

  /* ══════════════════════════════════════════════════════════════════════════
     TRANSPORT & PROTOCOL CONFIGURATION (120-124)
     ═════════════════════════════════════════════════════════════════════════ */
  {
    id: 120,
    regex: /(SSLv2|SSLv3|TLSv1(\.0|\.1)?)\b(?!\.[23])/,
    label: 'Deprecated TLS/SSL Protocol',
    category: 'Protocol',
    algorithm: 'SSLv2/SSLv3/TLS 1.0/1.1',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'Deprecated transport protocol configured — classically broken, disable and require TLS 1.3',
  },
  {
    id: 121,
    regex: /ssh-rsa\b|ssh-dss\b|\bdiffie-hellman-group1-sha1\b|\bdiffie-hellman-group14-sha1\b/i,
    label: 'Weak SSH Algorithm',
    category: 'Protocol',
    algorithm: 'ssh-rsa/ssh-dss',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'Weak SSH host key or KEX algorithm — migrate to ed25519 now and a PQC KEX when available',
  },
  {
    id: 122,
    regex: /InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)/i,
    label: 'TLS Verification Disabled',
    category: 'Protocol',
    algorithm: 'TLS Trust Bypass',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'Certificate verification disabled — the transport provides no authenticated channel at all',
  },
  {
    id: 123,
    regex: /-----BEGIN (EC|DSA|OPENSSH|PGP) PRIVATE KEY-----/,
    label: 'Non-RSA Private Key Block',
    category: 'Key Management',
    algorithm: 'EC/DSA/OpenSSH/PGP Private Key',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'Private key material committed to the repository — rotate immediately and move to a KMS',
  },
  {
    id: 124,
    regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    label: 'Encrypted Private Key Block',
    category: 'Key Management',
    algorithm: 'Encrypted Private Key',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'Encrypted private key in the repository — confirm the passphrase is not also committed',
  },

  /* ══════════════════════════════════════════════════════════════════════════
     MESSAGE AUTHENTICATION, KEY DERIVATION & REMAINING HASH FAMILIES (125-133)

     Completes the primitive coverage: a CBOM that lists ciphers and signatures
     but omits the MAC and KDF in use is not a full cryptographic inventory.
     ═════════════════════════════════════════════════════════════════════════ */
  {
    id: 125,
    regex: /\bHMAC\b|createHmac\(|hmac\.new\(|HMACSHA(1|256|384|512)|Mac\.getInstance\(/i,
    label: 'HMAC',
    category: 'MAC',
    algorithm: 'HMAC',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'HMAC message authentication — symmetric, Grover-limited; safe when built on SHA-256 or better',
  },
  {
    id: 126,
    regex: /\bHMAC-?(MD5|SHA-?1)\b|createHmac\(\s*['"`](md5|sha1)['"`]/i,
    label: 'HMAC over a Broken Hash',
    category: 'MAC',
    algorithm: 'HMAC-MD5/SHA-1',
    threatLevel: 'HIGH',
    languages: ['all'],
    description: 'HMAC built on a collision-broken digest — migrate the underlying hash to SHA-256/SHA3-256',
  },
  {
    id: 127,
    regex: /\bCMAC\b|\bGMAC\b|\bAES-CMAC\b|CipherMac|Poly1305/i,
    label: 'Block-Cipher MAC',
    category: 'MAC',
    algorithm: 'CMAC/GMAC/Poly1305',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'Block-cipher or polynomial MAC — symmetric, quantum impact limited to Grover',
  },
  {
    id: 128,
    regex: /\bHKDF\b|hkdf_extract|HKDFExpand|Hkdf/i,
    label: 'HKDF Key Derivation',
    category: 'KDF',
    algorithm: 'HKDF',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'HKDF extract-and-expand — the recommended KDF for hybrid PQC key schedules',
  },
  {
    id: 129,
    regex: /\bPBKDF1\b|\bMD5Crypt\b|\bcrypt\(\s*\$|DES_crypt/i,
    label: 'Obsolete Password KDF',
    category: 'KDF',
    algorithm: 'PBKDF1/crypt',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'Obsolete password derivation — migrate to Argon2id, scrypt or PBKDF2-HMAC-SHA256 with a high work factor',
  },
  {
    id: 130,
    regex: /\bBLAKE3\b|blake3::|blake3\(/i,
    label: 'BLAKE3 Hash',
    category: 'Hash',
    algorithm: 'BLAKE3',
    threatLevel: 'SAFE',
    languages: ['all'],
    description: 'BLAKE3 — 256-bit output, Grover-resistant; no migration required',
  },
  {
    id: 131,
    regex: /\bSM3\b|sm3_|SM3Digest/i,
    label: 'SM3 Hash (GM/T)',
    category: 'Hash',
    algorithm: 'SM3',
    threatLevel: 'MEDIUM',
    languages: ['all'],
    description: 'SM3 Chinese national hash — 256-bit; inventory for regional compliance and Grover margin',
  },
  {
    id: 132,
    regex: /\bSM2\b|sm2_|SM2Engine/i,
    label: 'SM2 Elliptic Curve (GM/T)',
    category: 'ECC',
    algorithm: 'SM2',
    threatLevel: 'CRITICAL',
    languages: ['all'],
    description: 'SM2 Chinese national elliptic curve — ECDLP recoverable by Shor, same exposure as ECDSA',
  },
  {
    id: 133,
    regex: /<PackageReference\s+Include="(BouncyCastle|System\.Security\.Cryptography|Portable\.BouncyCastle|NSec|Sodium\.Core|jose-jwt|IdentityModel)/i,
    label: 'NuGet Crypto Dependency',
    category: 'Dependency',
    algorithm: '.NET Crypto Package',
    threatLevel: 'HIGH',
    languages: ['csharp'],
    description: 'Crypto package referenced in a .csproj/NuGet manifest — inventory its algorithms for the CBOM',
  },
]

/**
 * Scannable file extensions for repository analysis
 */
export const SCANNABLE_EXTENSIONS = new Set([
  '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.java', '.go', '.rs', '.c', '.cpp', '.h', '.hpp', '.cc',
  '.rb', '.php', '.cs', '.swift', '.kt', '.kts', '.scala',
  '.yaml', '.yml', '.json', '.toml', '.xml', '.properties',
  '.env', '.cfg', '.conf', '.ini', '.config',
  '.sh', '.bash', '.zsh', '.ps1',
  '.pem', '.key', '.crt', '.cer', '.p12', '.pfx',
  '.dockerfile', '.tf', '.hcl', '.bicep',
  '.gradle', '.sbt', '.cmake', '.makefile',
  '.nginx', '.apache', '.htaccess',
  // Dependency manifests and lockfiles. `.txt` (requirements.txt) and `.mod` /
  // `.sum` (Go modules) were missing, so the dependency graph of a Python or Go
  // repository was invisible to the "Code & Dependencies" surface.
  '.txt', '.mod', '.sum', '.lock', '.gemspec', '.cabal', '.nix',
  '.csproj', '.fsproj', '.vbproj', '.props', '.targets', '.nuspec',
  // Additional languages that ship cryptography.
  '.m', '.mm', '.dart', '.ex', '.exs', '.erl', '.clj', '.groovy',
  '.vb', '.fs', '.jl', '.lua', '.pl', '.pm', '.r', '.sql', '.tfvars',
  // Additional key/certificate material.
  '.pub', '.asc', '.gpg', '.der', '.p8', '.jks', '.keystore', '.csr',
])

/**
 * Files with no extension (or a name-only convention) that still carry the
 * dependency graph. Matched on basename, case-insensitively.
 *
 * Without this, `go.mod`, `Gemfile`, `Dockerfile` and `Pipfile` were filtered
 * out before any pattern ran.
 */
export const SCANNABLE_FILENAMES = new Set([
  'dockerfile', 'containerfile', 'makefile', 'gemfile', 'gemfile.lock',
  'pipfile', 'pipfile.lock', 'go.mod', 'go.sum', 'cargo.lock',
  'requirements.txt', 'requirements-dev.txt', 'pyproject.toml', 'setup.py',
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'composer.json', 'composer.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts',
  'packages.config', 'directory.packages.props', 'paket.dependencies',
  'sshd_config', 'ssh_config', 'nginx.conf', 'httpd.conf', 'openssl.cnf',
  'known_hosts', 'authorized_keys', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
])

/** True when a repository path should be read and pattern-matched. */
export function isScannablePath(path: string): boolean {
  const basename = path.split('/').pop()?.toLowerCase() ?? ''
  if (!basename) return false
  if (SCANNABLE_FILENAMES.has(basename)) return true
  // Dotfiles: `.env`, `.npmrc`, `.htaccess` have no "name" before the dot, so
  // the whole basename IS the extension. Treating them as extension-less
  // skipped `.env` — the single most likely place to find committed key
  // material — before any pattern could run.
  if (basename.startsWith('.') && SCANNABLE_EXTENSIONS.has(basename)) return true
  const dot = basename.lastIndexOf('.')
  if (dot <= 0) return false
  return SCANNABLE_EXTENSIONS.has(basename.slice(dot))
}

/**
 * File extensions to prioritize in scanning (most likely to contain crypto code)
 */
export const PRIORITY_EXTENSIONS = new Set([
  '.py', '.js', '.ts', '.java', '.go', '.rs', '.c', '.cpp', '.cs', '.swift', '.kt',
  '.pem', '.key', '.env', '.yaml', '.yml', '.conf', '.cfg',
])

/**
 * Apply all crypto patterns against a line of source code
 */
export function matchCryptoPatterns(
  line: string,
  filename: string
): { pattern: CryptoPattern; match: RegExpMatchArray }[] {
  const results: { pattern: CryptoPattern; match: RegExpMatchArray }[] = []

  for (const pattern of CRYPTO_PATTERNS) {
    const match = line.match(pattern.regex)
    if (match) {
      results.push({ pattern, match })
    }
  }

  return results
}
