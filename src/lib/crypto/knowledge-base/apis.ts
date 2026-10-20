/**
 * Cryptographic API semantics (§27, §28, §29) and library catalogue (§25).
 *
 * THIS IS THE MODULE THAT MAKES DETECTION SEMANTIC RATHER THAN LEXICAL.
 *
 * A lexical rule sees the string "RSA" and reports RSA. An API rule sees
 * `crypto.createSign('RSA-SHA256')` and reports: RSA, used for a DIGITAL
 * SIGNATURE, with SHA-256, through the Node.js crypto binding to OpenSSL — with
 * DIRECT evidence quality, because the call site proves the use.
 *
 * §29: "Map API → algorithm → role → evidence."
 *
 * That role is the field everything downstream depends on. §80 forbids
 * recommending one PQC algorithm for every use, and the only way to give a
 * role-appropriate recommendation is to have established the role. A pattern
 * catalogue cannot; a call-shape catalogue can.
 *
 * Every pattern here is anchored to a CALL or an ASSIGNMENT, never to a bare
 * identifier. That is deliberate: a bare name is what `crypto-patterns.ts`
 * already covers as a lexical layer, and mixing the two would destroy the
 * confidence distinction between them.
 */

import type { CryptoApiDefinition, CryptoRole, LibraryDefinition } from './types';

/* ═══════════════════════════════════════════════════════════ libraries ════ */

export const LIBRARIES: LibraryDefinition[] = [
  { libraryId: 'openssl', canonicalName: 'OpenSSL', aliases: ['openssl', 'libssl', 'libcrypto', 'evp'], ecosystems: ['c', 'cpp', 'system'], providesAlgorithms: ['rsa', 'ecdsa', 'ecdh', 'dh', 'aes', 'sha2', 'sha3', 'ed25519', 'x25519'], pqcCapable: false, note: 'OpenSSL 3.5 and later ship ML-KEM and ML-DSA; earlier versions require the oqs-provider.' },
  { libraryId: 'boringssl', canonicalName: 'BoringSSL', aliases: ['boringssl'], ecosystems: ['c', 'cpp'], providesAlgorithms: ['rsa', 'ecdsa', 'x25519', 'aes', 'chacha20-poly1305', 'ml-kem'], pqcCapable: true, note: 'BoringSSL ships X25519MLKEM768 hybrid key agreement, which is what Chrome negotiates.' },
  { libraryId: 'libressl', canonicalName: 'LibreSSL', aliases: ['libressl'], ecosystems: ['c', 'system'], providesAlgorithms: ['rsa', 'ecdsa', 'ecdh', 'aes', 'sha2'], pqcCapable: false },
  { libraryId: 'aws-lc', canonicalName: 'AWS-LC', aliases: ['aws-lc', 'awslc'], ecosystems: ['c', 'cpp'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'ml-kem'], pqcCapable: true },
  { libraryId: 'wolfssl', canonicalName: 'wolfSSL', aliases: ['wolfssl', 'wolfcrypt'], ecosystems: ['c', 'cpp'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'ml-kem', 'ml-dsa'], pqcCapable: true },
  { libraryId: 'mbedtls', canonicalName: 'mbedTLS', aliases: ['mbedtls', 'polarssl'], ecosystems: ['c', 'embedded'], providesAlgorithms: ['rsa', 'ecdsa', 'ecdh', 'aes', 'sha2'], pqcCapable: false },
  { libraryId: 'gnutls', canonicalName: 'GnuTLS', aliases: ['gnutls'], ecosystems: ['c', 'system'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'sha2'], pqcCapable: false },
  { libraryId: 'nss', canonicalName: 'NSS', aliases: ['nss', 'libnss3'], ecosystems: ['c', 'system'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'sha2'], pqcCapable: false },
  { libraryId: 'libsodium', canonicalName: 'libsodium', aliases: ['libsodium', 'sodium', 'nacl', 'tweetnacl'], ecosystems: ['c', 'npm', 'pypi', 'composer', 'cargo'], providesAlgorithms: ['x25519', 'ed25519', 'chacha20-poly1305', 'argon2'], pqcCapable: false },
  { libraryId: 'liboqs', canonicalName: 'liboqs (Open Quantum Safe)', aliases: ['liboqs', 'oqs', 'open-quantum-safe', 'oqs-provider', 'oqsprovider'], ecosystems: ['c', 'npm', 'pypi', 'go'], providesAlgorithms: ['ml-kem', 'ml-dsa', 'slh-dsa', 'fn-dsa'], pqcCapable: true },
  { libraryId: 'bouncycastle', canonicalName: 'Bouncy Castle', aliases: ['bouncycastle', 'bcprov', 'org.bouncycastle'], ecosystems: ['maven', 'gradle', 'nuget'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'ml-kem', 'ml-dsa', 'slh-dsa'], pqcCapable: true, note: 'Post-quantum support depends on the Bouncy Castle version; the PQC provider is a separate artefact.' },
  { libraryId: 'botan', canonicalName: 'Botan', aliases: ['botan'], ecosystems: ['cpp'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'ml-kem', 'ml-dsa'], pqcCapable: true },
  { libraryId: 'java-jca', canonicalName: 'Java JCA/JCE', aliases: ['javax.crypto', 'java.security', 'jca', 'jce', 'sunjce', 'sunec'], ecosystems: ['maven', 'gradle'], providesAlgorithms: ['rsa', 'ecdsa', 'dh', 'aes', 'sha2'], pqcCapable: false },
  { libraryId: 'dotnet-crypto', canonicalName: '.NET Cryptography', aliases: ['system.security.cryptography', 'dotnet-crypto'], ecosystems: ['nuget'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'sha2'], pqcCapable: false },
  { libraryId: 'windows-cng', canonicalName: 'Windows CNG', aliases: ['bcrypt.dll', 'ncrypt', 'cng'], ecosystems: ['windows'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'sha2'], pqcCapable: false },
  { libraryId: 'apple-security', canonicalName: 'Apple Security Framework', aliases: ['seckey', 'commoncrypto', 'cryptokit', 'security.framework'], ecosystems: ['swift', 'objc'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'sha2', 'x25519', 'ed25519'], pqcCapable: false },
  { libraryId: 'node-crypto', canonicalName: 'Node.js crypto', aliases: ['node:crypto', 'node-crypto'], ecosystems: ['npm'], providesAlgorithms: ['rsa', 'ecdsa', 'ecdh', 'dh', 'aes', 'sha2', 'ed25519', 'x25519', 'scrypt'], pqcCapable: false, note: 'Node crypto binds to the OpenSSL the runtime was built against, so its algorithm set follows that version.' },
  { libraryId: 'webcrypto', canonicalName: 'WebCrypto', aliases: ['subtlecrypto', 'crypto.subtle', 'webcrypto'], ecosystems: ['npm', 'browser'], providesAlgorithms: ['rsa', 'ecdsa', 'ecdh', 'aes', 'sha2', 'pbkdf2'], pqcCapable: false },
  { libraryId: 'py-cryptography', canonicalName: 'Python cryptography', aliases: ['cryptography.hazmat', 'python-cryptography'], ecosystems: ['pypi'], providesAlgorithms: ['rsa', 'ecdsa', 'ecdh', 'dh', 'aes', 'sha2', 'ed25519', 'x25519'], pqcCapable: false },
  { libraryId: 'pycryptodome', canonicalName: 'PyCryptodome', aliases: ['crypto.publickey', 'cryptodome', 'pycryptodome'], ecosystems: ['pypi'], providesAlgorithms: ['rsa', 'dsa', 'aes', 'sha2'], pqcCapable: false },
  { libraryId: 'go-crypto', canonicalName: 'Go crypto', aliases: ['crypto/rsa', 'crypto/ecdsa', 'crypto/ed25519', 'crypto/tls', 'crypto/aes'], ecosystems: ['go'], providesAlgorithms: ['rsa', 'ecdsa', 'ed25519', 'aes', 'sha2', 'x25519'], pqcCapable: false },
  { libraryId: 'circl', canonicalName: 'Cloudflare CIRCL', aliases: ['circl'], ecosystems: ['go'], providesAlgorithms: ['ml-kem', 'ml-dsa', 'x25519'], pqcCapable: true },
  { libraryId: 'rustcrypto', canonicalName: 'RustCrypto', aliases: ['rustcrypto', 'aes-gcm', 'sha2', 'ed25519-dalek', 'x25519-dalek', 'rsa'], ecosystems: ['cargo'], providesAlgorithms: ['rsa', 'ecdsa', 'ed25519', 'x25519', 'aes', 'sha2'], pqcCapable: false },
  { libraryId: 'ring', canonicalName: 'ring', aliases: ['ring'], ecosystems: ['cargo'], providesAlgorithms: ['ecdsa', 'ed25519', 'aes', 'hmac'], pqcCapable: false },
  { libraryId: 'rustls', canonicalName: 'rustls', aliases: ['rustls'], ecosystems: ['cargo'], providesAlgorithms: ['ecdh', 'ecdsa', 'aes', 'chacha20-poly1305'], pqcCapable: true, note: 'rustls supports X25519MLKEM768 from version 0.23.22.' },
  { libraryId: 'openssh', canonicalName: 'OpenSSH', aliases: ['openssh', 'ssh-keygen', 'sshd'], ecosystems: ['system'], providesAlgorithms: ['rsa', 'ecdsa', 'ed25519', 'dh'], pqcCapable: true, note: 'OpenSSH 9.0+ enables sntrup761x25519 hybrid key exchange by default.' },
  { libraryId: 'noble-pq', canonicalName: '@noble/post-quantum', aliases: ['@noble/post-quantum', 'noble-post-quantum'], ecosystems: ['npm'], providesAlgorithms: ['ml-kem', 'ml-dsa', 'slh-dsa'], pqcCapable: true },

  /* Application-level libraries an agent meets in a manifest. Added because the
     agent's package classifier previously invented an algorithm and a key size
     for each of these (`crypto-js` -> AES-128, `jsonwebtoken` -> RSA-2048).
     Reporting the LIBRARY is the honest reading: a manifest establishes that a
     capability is available, never that it is used. */
  { libraryId: 'crypto-js', canonicalName: 'CryptoJS', aliases: ['crypto-js', 'cryptojs'], ecosystems: ['npm'], providesAlgorithms: ['aes', 'tripledes', 'rc4', 'sha-256', 'sha-1', 'md5', 'hmac', 'pbkdf2'], pqcCapable: false, note: 'Ships several broken primitives (RC4, MD5, SHA-1) alongside sound ones; presence alone says nothing about which are called.' },
  { libraryId: 'node-forge', canonicalName: 'node-forge', aliases: ['node-forge', 'forge'], ecosystems: ['npm'], providesAlgorithms: ['rsa', 'aes', 'tripledes', 'sha-256', 'sha-1', 'md5', 'x509', 'pkcs12'], pqcCapable: false },
  { libraryId: 'node-rsa', canonicalName: 'node-rsa', aliases: ['node-rsa'], ecosystems: ['npm'], providesAlgorithms: ['rsa'], pqcCapable: false },
  { libraryId: 'jsonwebtoken', canonicalName: 'jsonwebtoken', aliases: ['jsonwebtoken'], ecosystems: ['npm'], providesAlgorithms: ['hmac', 'rsa', 'ecdsa', 'rsa-pss'], pqcCapable: false, note: 'The signing algorithm is chosen per call; the dependency does not determine it.' },
  { libraryId: 'jose', canonicalName: 'jose', aliases: ['jose', 'node-jose', 'jose4j', 'go-jose', 'python-jose'], ecosystems: ['npm', 'maven', 'go', 'pypi'], providesAlgorithms: ['hmac', 'rsa', 'rsa-pss', 'ecdsa', 'eddsa', 'aes', 'ecdh'], pqcCapable: false },
  { libraryId: 'pyjwt', canonicalName: 'PyJWT', aliases: ['pyjwt'], ecosystems: ['pypi'], providesAlgorithms: ['hmac', 'rsa', 'rsa-pss', 'ecdsa', 'eddsa'], pqcCapable: false },
  { libraryId: 'jjwt', canonicalName: 'JJWT', aliases: ['jjwt', 'jjwt-api', 'jjwt-impl'], ecosystems: ['maven'], providesAlgorithms: ['hmac', 'rsa', 'rsa-pss', 'ecdsa', 'eddsa'], pqcCapable: false },
  { libraryId: 'elliptic', canonicalName: 'elliptic', aliases: ['elliptic'], ecosystems: ['npm'], providesAlgorithms: ['ecdsa', 'ecdh', 'eddsa'], pqcCapable: false },
  { libraryId: 'secp256k1', canonicalName: 'secp256k1', aliases: ['secp256k1'], ecosystems: ['npm', 'crates.io'], providesAlgorithms: ['ecdsa'], pqcCapable: false },
  { libraryId: 'ssh2', canonicalName: 'ssh2', aliases: ['ssh2'], ecosystems: ['npm'], providesAlgorithms: ['ed25519', 'ecdsa', 'rsa', 'aes', 'diffie-hellman', 'ecdh'], pqcCapable: false, note: 'An SSH client library. Which host-key and KEX algorithms are negotiated is a runtime property, not a manifest one.' },
  { libraryId: 'paramiko', canonicalName: 'Paramiko', aliases: ['paramiko'], ecosystems: ['pypi'], providesAlgorithms: ['ed25519', 'ecdsa', 'rsa', 'aes', 'diffie-hellman'], pqcCapable: false },
  { libraryId: 'bcrypt-lib', canonicalName: 'bcrypt', aliases: ['bcryptjs', 'py-bcrypt', 'jbcrypt'], ecosystems: ['npm', 'pypi', 'maven'], providesAlgorithms: ['bcrypt'], pqcCapable: false, note: 'Password hashing. Blowfish-derived, not SHA-based — a distinction the agent previously got wrong.' },
  { libraryId: 'argon2-lib', canonicalName: 'Argon2', aliases: ['argon2', 'argon2-cffi', 'node-argon2'], ecosystems: ['npm', 'pypi'], providesAlgorithms: ['argon2'], pqcCapable: false },
  { libraryId: 'scrypt-lib', canonicalName: 'scrypt', aliases: ['scrypt', 'scrypt-js'], ecosystems: ['npm'], providesAlgorithms: ['scrypt'], pqcCapable: false },
  { libraryId: 'tink', canonicalName: 'Google Tink', aliases: ['tink', 'tink-java', 'tink-py', 'google-tink'], ecosystems: ['maven', 'pypi', 'npm', 'go'], providesAlgorithms: ['aes', 'ecdsa', 'ed25519', 'hmac', 'ecdh', 'rsa'], pqcCapable: false },
  { libraryId: 'cryptojs-net', canonicalName: 'System.Security.Cryptography', aliases: ['system.security.cryptography', 'microsoft.identitymodel.tokens'], ecosystems: ['nuget'], providesAlgorithms: ['rsa', 'ecdsa', 'aes', 'sha-256', 'hmac'], pqcCapable: false },
];

const LIBRARY_BY_ALIAS = (() => {
  const map = new Map<string, LibraryDefinition>();
  for (const library of LIBRARIES) {
    map.set(library.canonicalName.toLowerCase(), library);
    map.set(library.libraryId, library);
    for (const alias of library.aliases) map.set(alias.toLowerCase(), library);
  }
  return map;
})();

export function findLibrary(raw: string | null | undefined): LibraryDefinition | null {
  if (!raw) return null;
  const text = String(raw).trim().toLowerCase();
  return LIBRARY_BY_ALIAS.get(text) ?? null;
}

/** Libraries that ship post-quantum primitives, for the readiness narrative. */
export function pqcCapableLibraries(): LibraryDefinition[] {
  return LIBRARIES.filter((library) => library.pqcCapable);
}

/* ═══════════════════════════════════════════════════════════ API catalogue ═ */

/**
 * Call-shape rules. Each proves an algorithm AND a role.
 *
 * `algorithmFromGroup` is used where the call names the algorithm as an
 * argument — `createSign('RSA-SHA256')`, `getInstance("AES/GCM/NoPadding")` —
 * so one rule covers every algorithm that API can be asked for, and the
 * algorithm comes from what the code actually requested rather than from a
 * guess.
 */
export const CRYPTO_APIS: CryptoApiDefinition[] = [
  /* ══════════════════════════════════ Node.js ══════════════════════════ */
  {
    apiId: 'node-create-sign',
    pattern: /\bcreateSign\s*\(\s*['"`]([^'"`]+)['"`]/,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithmFromGroup: 1,
    role: 'digital-signature',
    evidenceQuality: 'DIRECT',
    note: 'crypto.createSign establishes a signing operation; the argument names the algorithm and digest.',
  },
  {
    apiId: 'node-create-verify',
    pattern: /\bcreateVerify\s*\(\s*['"`]([^'"`]+)['"`]/,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithmFromGroup: 1,
    role: 'digital-signature',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'node-create-hash',
    pattern: /\bcreateHash\s*\(\s*['"`]([a-z0-9-]+)['"`]/i,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithmFromGroup: 1,
    role: 'hashing',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'node-create-hmac',
    pattern: /\bcreateHmac\s*\(\s*['"`]([a-z0-9-]+)['"`]/i,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithm: 'HMAC',
    role: 'integrity',
    parameterFromGroup: 1,
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'node-create-cipheriv',
    pattern: /\bcreateCipheriv\s*\(\s*['"`]([a-z0-9-]+)['"`]/i,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithmFromGroup: 1,
    role: 'encryption',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'node-create-decipheriv',
    pattern: /\bcreateDecipheriv\s*\(\s*['"`]([a-z0-9-]+)['"`]/i,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithmFromGroup: 1,
    role: 'encryption',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'node-generate-keypair',
    pattern: /\bgenerateKeyPair(?:Sync)?\s*\(\s*['"`]([a-z0-9]+)['"`]/i,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithmFromGroup: 1,
    role: 'key-management',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'node-create-ecdh',
    pattern: /\bcreateECDH\s*\(\s*['"`]([a-z0-9]+)['"`]/i,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithm: 'ECDH',
    parameterFromGroup: 1,
    role: 'key-establishment',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'node-create-diffiehellman',
    pattern: /\bcreateDiffieHellman(?:Group)?\s*\(/,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithm: 'Diffie-Hellman',
    role: 'key-establishment',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'node-pbkdf2',
    pattern: /\bpbkdf2(?:Sync)?\s*\(/,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithm: 'PBKDF2',
    role: 'password-derivation',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'node-scrypt',
    pattern: /\bscrypt(?:Sync)?\s*\(/,
    language: ['javascript', 'typescript'],
    library: 'node-crypto',
    algorithm: 'scrypt',
    role: 'password-derivation',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'jwt-sign',
    pattern: /\bjwt\.sign\s*\([\s\S]{0,200}?algorithm\s*:\s*['"`]([A-Z0-9]+)['"`]/,
    language: ['javascript', 'typescript'],
    algorithmFromGroup: 1,
    role: 'token-signing',
    evidenceQuality: 'DIRECT',
    note: 'The JOSE `alg` decides the exposure: RS*/ES*/PS* are quantum-vulnerable, HS* are symmetric.',
  },

  /* ══════════════════════════════════ WebCrypto ════════════════════════ */
  {
    apiId: 'webcrypto-subtle',
    pattern: /crypto\.subtle\.(?:sign|verify|encrypt|decrypt|deriveKey|deriveBits|generateKey|importKey)\s*\(\s*(?:\{[\s\S]{0,120}?name\s*:\s*)?['"`]([A-Za-z0-9-]+)['"`]/,
    language: ['javascript', 'typescript'],
    library: 'webcrypto',
    algorithmFromGroup: 1,
    role: 'unknown',
    evidenceQuality: 'DIRECT',
    note: 'The SubtleCrypto operation name determines the role; the algorithm comes from the parameter object.',
  },

  /* ══════════════════════════════════ Python ═══════════════════════════ */
  {
    apiId: 'py-cryptography-rsa-generate',
    pattern: /rsa\.generate_private_key\s*\(/,
    language: ['python'],
    library: 'py-cryptography',
    algorithm: 'RSA',
    role: 'key-management',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'py-cryptography-ec-generate',
    pattern: /ec\.generate_private_key\s*\(\s*ec\.([A-Za-z0-9]+)/,
    language: ['python'],
    library: 'py-cryptography',
    algorithm: 'ECDSA',
    parameterFromGroup: 1,
    role: 'key-management',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'py-hazmat-sign',
    pattern: /\.sign\s*\([\s\S]{0,160}?(?:padding\.(PSS|PKCS1v15)|ec\.ECDSA)/,
    language: ['python'],
    library: 'py-cryptography',
    role: 'digital-signature',
    evidenceQuality: 'DIRECT',
    parameterFromGroup: 1,
  },
  {
    apiId: 'py-hashlib',
    pattern: /hashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_512|blake2b|blake2s)\s*\(/,
    language: ['python'],
    algorithmFromGroup: 1,
    role: 'hashing',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'py-hmac-new',
    pattern: /hmac\.new\s*\([\s\S]{0,120}?digestmod\s*=\s*(?:hashlib\.)?([a-z0-9_]+)/,
    language: ['python'],
    algorithm: 'HMAC',
    parameterFromGroup: 1,
    role: 'integrity',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'py-fernet',
    pattern: /\bFernet\s*\(/,
    language: ['python'],
    library: 'py-cryptography',
    algorithm: 'AES-128-CBC',
    role: 'authenticated-encryption',
    evidenceQuality: 'STRONG',
    note: 'Fernet is AES-128-CBC with HMAC-SHA256. The 128-bit key is the fact worth recording.',
  },
  {
    apiId: 'py-pyjwt-encode',
    pattern: /jwt\.encode\s*\([\s\S]{0,200}?algorithm\s*=\s*['"]([A-Z0-9]+)['"]/,
    language: ['python'],
    algorithmFromGroup: 1,
    role: 'token-signing',
    evidenceQuality: 'DIRECT',
  },

  /* ══════════════════════════════════ Java ═════════════════════════════ */
  {
    apiId: 'java-keypair-generator',
    pattern: /KeyPairGenerator\.getInstance\s*\(\s*"([A-Za-z0-9/]+)"/,
    language: ['java', 'kotlin'],
    library: 'java-jca',
    algorithmFromGroup: 1,
    role: 'key-management',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'java-signature',
    pattern: /Signature\.getInstance\s*\(\s*"([A-Za-z0-9/]+)"/,
    language: ['java', 'kotlin'],
    library: 'java-jca',
    algorithmFromGroup: 1,
    role: 'digital-signature',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'java-cipher',
    pattern: /Cipher\.getInstance\s*\(\s*"([A-Za-z0-9/]+)"/,
    language: ['java', 'kotlin'],
    library: 'java-jca',
    algorithmFromGroup: 1,
    role: 'encryption',
    evidenceQuality: 'DIRECT',
    note: 'The transformation string carries algorithm, mode and padding — "AES/ECB/PKCS5Padding" is a finding the algorithm name alone would miss.',
  },
  {
    apiId: 'java-message-digest',
    pattern: /MessageDigest\.getInstance\s*\(\s*"([A-Za-z0-9-]+)"/,
    language: ['java', 'kotlin'],
    library: 'java-jca',
    algorithmFromGroup: 1,
    role: 'hashing',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'java-key-agreement',
    pattern: /KeyAgreement\.getInstance\s*\(\s*"([A-Za-z0-9]+)"/,
    language: ['java', 'kotlin'],
    library: 'java-jca',
    algorithmFromGroup: 1,
    role: 'key-establishment',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'java-secret-key-factory',
    pattern: /SecretKeyFactory\.getInstance\s*\(\s*"(PBKDF2[A-Za-z0-9]*)"/,
    language: ['java', 'kotlin'],
    library: 'java-jca',
    algorithm: 'PBKDF2',
    role: 'password-derivation',
    evidenceQuality: 'DIRECT',
  },

  /* ══════════════════════════════════ .NET ═════════════════════════════ */
  {
    apiId: 'dotnet-rsa-create',
    pattern: /\bRSA\.Create\s*\(|new\s+RSACryptoServiceProvider\s*\(/,
    language: ['csharp'],
    library: 'dotnet-crypto',
    algorithm: 'RSA',
    role: 'key-management',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'dotnet-ecdsa-create',
    pattern: /\bECDsa\.Create\s*\(/,
    language: ['csharp'],
    library: 'dotnet-crypto',
    algorithm: 'ECDSA',
    role: 'digital-signature',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'dotnet-aes-create',
    pattern: /\bAes\.Create\s*\(|new\s+AesCryptoServiceProvider\s*\(|new\s+AesGcm\s*\(/,
    language: ['csharp'],
    library: 'dotnet-crypto',
    algorithm: 'AES',
    role: 'encryption',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'dotnet-legacy-hash',
    pattern: /\b(MD5|SHA1)\.Create\s*\(|new\s+(MD5|SHA1)CryptoServiceProvider\s*\(/,
    language: ['csharp'],
    library: 'dotnet-crypto',
    algorithmFromGroup: 1,
    role: 'hashing',
    evidenceQuality: 'DIRECT',
  },

  /* ══════════════════════════════════ Go ═══════════════════════════════ */
  {
    apiId: 'go-rsa-generate',
    pattern: /rsa\.GenerateKey\s*\(/,
    language: ['go'],
    library: 'go-crypto',
    algorithm: 'RSA',
    role: 'key-management',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'go-ecdsa-sign',
    pattern: /ecdsa\.(?:Sign|SignASN1|GenerateKey)\s*\(/,
    language: ['go'],
    library: 'go-crypto',
    algorithm: 'ECDSA',
    role: 'digital-signature',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'go-ed25519',
    pattern: /ed25519\.(?:Sign|GenerateKey|Verify)\s*\(/,
    language: ['go'],
    library: 'go-crypto',
    algorithm: 'Ed25519',
    role: 'digital-signature',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'go-aes-cipher',
    pattern: /aes\.NewCipher\s*\(/,
    language: ['go'],
    library: 'go-crypto',
    algorithm: 'AES',
    role: 'encryption',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'go-legacy-hash',
    pattern: /\b(md5|sha1)\.(?:New|Sum)\s*\(/,
    language: ['go'],
    algorithmFromGroup: 1,
    role: 'hashing',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'go-tls-min-version',
    pattern: /MinVersion\s*:\s*tls\.(VersionSSL30|VersionTLS10|VersionTLS11|VersionTLS12|VersionTLS13)/,
    language: ['go'],
    library: 'go-crypto',
    algorithm: 'TLS',
    parameterFromGroup: 1,
    role: 'transport-security',
    evidenceQuality: 'DIRECT',
  },

  /* ══════════════════════════════════ Rust ═════════════════════════════ */
  /* Rust type names are matched on a leading word boundary. Unanchored,
     `Keypair::generate(` matched `LocalKemKeypair::generate()` — an ML-KEM
     keypair — and every post-quantum key generation in a Rust codebase was
     published as an Ed25519 signature at API-layer (strong) confidence. */
  {
    apiId: 'rust-rsa-generate',
    pattern: /\bRsaPrivateKey::new\s*\(/,
    language: ['rust'],
    library: 'rustcrypto',
    algorithm: 'RSA',
    role: 'key-management',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'rust-ed25519',
    pattern: /\b(?:SigningKey|Keypair)::(?:generate|from_bytes)\s*\(|\bed25519_dalek::/,
    language: ['rust'],
    library: 'rustcrypto',
    algorithm: 'Ed25519',
    role: 'digital-signature',
    evidenceQuality: 'STRONG',
  },
  {
    apiId: 'rust-aes-gcm',
    pattern: /Aes256Gcm::new\s*\(|Aes128Gcm::new\s*\(/,
    language: ['rust'],
    library: 'rustcrypto',
    algorithm: 'AES',
    role: 'authenticated-encryption',
    evidenceQuality: 'DIRECT',
  },

  /* ══════════════════════════════════ PHP / Ruby ═══════════════════════ */
  {
    apiId: 'php-openssl-sign',
    pattern: /openssl_sign\s*\(|openssl_verify\s*\(/,
    language: ['php'],
    library: 'openssl',
    role: 'digital-signature',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'php-openssl-encrypt',
    pattern: /openssl_encrypt\s*\(\s*[^,]+,\s*['"]([A-Za-z0-9-]+)['"]/,
    language: ['php'],
    library: 'openssl',
    algorithmFromGroup: 1,
    role: 'encryption',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'ruby-openssl-digest',
    pattern: /OpenSSL::Digest(?:::|\.new\s*\(\s*['"])([A-Za-z0-9]+)/,
    language: ['ruby'],
    library: 'openssl',
    algorithmFromGroup: 1,
    role: 'hashing',
    evidenceQuality: 'DIRECT',
  },

  /* ══════════════════════════════════ C / C++ (OpenSSL EVP) ════════════ */
  {
    apiId: 'openssl-evp-digest-sign',
    pattern: /EVP_DigestSign(?:Init|Update|Final)?\s*\(/,
    language: ['c', 'cpp'],
    library: 'openssl',
    role: 'digital-signature',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'openssl-evp-encrypt',
    pattern: /EVP_EncryptInit(?:_ex2?)?\s*\([\s\S]{0,80}?EVP_(aes_\d+_[a-z]+|des_ede3|rc4|chacha20)/,
    language: ['c', 'cpp'],
    library: 'openssl',
    algorithmFromGroup: 1,
    role: 'encryption',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'openssl-rsa-generate',
    pattern: /RSA_generate_key(?:_ex)?\s*\(|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_RSA/,
    language: ['c', 'cpp'],
    library: 'openssl',
    algorithm: 'RSA',
    role: 'key-management',
    evidenceQuality: 'DIRECT',
  },
  {
    apiId: 'openssl-set-cipher-list',
    pattern: /SSL_CTX_set_cipher_list\s*\(\s*[^,]+,\s*"([^"]+)"/,
    language: ['c', 'cpp'],
    library: 'openssl',
    algorithm: 'TLS',
    parameterFromGroup: 1,
    role: 'transport-security',
    evidenceQuality: 'DIRECT',
    note: 'The cipher list string is the effective TLS policy for this context.',
  },
  {
    apiId: 'openssl-set-groups',
    pattern: /SSL_CTX_set1_(?:groups|curves)_list\s*\(\s*[^,]+,\s*"([^"]+)"/,
    language: ['c', 'cpp'],
    library: 'openssl',
    parameterFromGroup: 1,
    role: 'key-establishment',
    evidenceQuality: 'DIRECT',
    note: 'The configured group list is where hybrid post-quantum key agreement is enabled or absent.',
  },

  /* ══════════════════════════════════ Swift / Apple ════════════════════ */
  {
    apiId: 'apple-cryptokit',
    pattern: /\b(?:P256|P384|P521|Curve25519)\.(?:Signing|KeyAgreement)\./,
    language: ['swift'],
    library: 'apple-security',
    role: 'unknown',
    evidenceQuality: 'DIRECT',
    parameterFromGroup: 1,
    note: 'CryptoKit names the curve and the operation in the type path, so both the algorithm and the role are recoverable.',
  },
];

/* ═══════════════════════════════════════════════════════ weak randomness ══ */

/**
 * §17: "Do not report weak randomness as a cryptographic vulnerability unless
 *       its context supports that conclusion."
 *
 * `Math.random()` in a UI animation is not a finding. `Math.random()` feeding a
 * key, token, nonce or IV is a serious one. The rule therefore carries the
 * CONTEXT PATTERN that has to co-occur, and the detector only reports when both
 * are present within a small window.
 */
export interface WeakRandomRule {
  ruleId: string;
  pattern: RegExp;
  language: string[];
  /** What makes this use security-relevant. All must be searched nearby. */
  securityContext: RegExp;
  replacement: string;
  note: string;
}

export const WEAK_RANDOM_RULES: WeakRandomRule[] = [
  {
    ruleId: 'rand-js-math-random',
    pattern: /\bMath\.random\s*\(\s*\)/,
    language: ['javascript', 'typescript'],
    securityContext: /\b(key|secret|token|nonce|iv|salt|password|session|csrf|otp|seed|apikey)\b/i,
    replacement: 'crypto.randomBytes() in Node, or crypto.getRandomValues() in a browser',
    note: 'Math.random() is not a cryptographically secure PRNG; its output is predictable from a small number of observations.',
  },
  {
    ruleId: 'rand-python-random',
    pattern: /\brandom\.(?:random|randint|choice|randrange|getrandbits)\s*\(/,
    language: ['python'],
    securityContext: /\b(key|secret|token|nonce|iv|salt|password|session|csrf|otp|seed)\b/i,
    replacement: 'the `secrets` module',
    note: "Python's `random` module uses Mersenne Twister, which is fully predictable once enough output is observed.",
  },
  {
    ruleId: 'rand-java-util-random',
    pattern: /new\s+Random\s*\(|\bMath\.random\s*\(\s*\)/,
    language: ['java', 'kotlin'],
    securityContext: /\b(key|secret|token|nonce|iv|salt|password|session|csrf|otp|seed)\b/i,
    replacement: 'java.security.SecureRandom',
    note: 'java.util.Random is a linear congruential generator and is not suitable for security purposes.',
  },
  {
    ruleId: 'rand-go-math-rand',
    pattern: /math\/rand|rand\.(?:Intn|Int63|Float64)\s*\(/,
    language: ['go'],
    securityContext: /\b(key|secret|token|nonce|iv|salt|password|session|csrf|otp|seed)\b/i,
    replacement: 'crypto/rand',
    note: 'math/rand is deterministic and must not generate key material.',
  },
  {
    ruleId: 'rand-php-rand',
    pattern: /\b(?:rand|mt_rand|uniqid)\s*\(/,
    language: ['php'],
    securityContext: /\b(key|secret|token|nonce|iv|salt|password|session|csrf|otp|seed)\b/i,
    replacement: 'random_bytes() or random_int()',
    note: 'rand(), mt_rand() and uniqid() are not cryptographically secure.',
  },
  {
    ruleId: 'rand-c-rand',
    pattern: /\b(?:srand\s*\(\s*time\s*\(|rand\s*\(\s*\))/,
    language: ['c', 'cpp'],
    securityContext: /\b(key|secret|token|nonce|iv|salt|password|session|seed)\b/i,
    replacement: 'a CSPRNG such as getrandom(2) or RAND_bytes()',
    note: 'rand() seeded from time() is trivially reproducible by an attacker who knows the approximate start time.',
  },
];

/* ═══════════════════════════════════════════════════ KDF parameter rules ══ */

/**
 * §16: "Flag weak configurations based on validated rules."
 *
 * The thresholds are from OWASP's Password Storage Cheat Sheet and NIST
 * SP 800-63B. They are the platform's applied judgement of published guidance,
 * so the rules carry `QGUARD_RULE` alongside the SP 800-63B citation rather
 * than claiming NIST states a specific iteration count — it does not.
 */
export interface KdfParameterRule {
  ruleId: string;
  algorithm: string;
  /** Captures the parameter value in group 1. */
  pattern: RegExp;
  language: string[];
  parameter: 'iterations' | 'memory' | 'parallelism' | 'cost' | 'keyLength';
  /** Below this the configuration is flagged. */
  minimum: number;
  unit: string;
  guidance: string;
}

export const KDF_PARAMETER_RULES: KdfParameterRule[] = [
  {
    ruleId: 'kdf-pbkdf2-iterations',
    algorithm: 'PBKDF2',
    pattern: /pbkdf2[^\n;)]{0,120}?[,(]\s*(\d{3,9})\s*[,)]/i,
    language: ['javascript', 'typescript', 'python', 'java', 'csharp', 'go'],
    parameter: 'iterations',
    minimum: 600_000,
    unit: 'iterations',
    guidance: 'OWASP recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256. Lower counts are proportionally cheaper to attack on GPUs.',
  },
  {
    ruleId: 'kdf-bcrypt-cost',
    algorithm: 'bcrypt',
    pattern: /bcrypt[^\n;)]{0,80}?(?:rounds|cost|saltRounds)\s*[:=]\s*(\d{1,2})/i,
    language: ['javascript', 'typescript', 'python', 'php', 'ruby', 'go'],
    parameter: 'cost',
    minimum: 12,
    unit: 'cost factor',
    guidance: 'A bcrypt cost factor below 12 is considered too fast on current hardware.',
  },
  {
    ruleId: 'kdf-argon2-memory',
    algorithm: 'Argon2',
    pattern: /argon2[^\n;)]{0,160}?memoryCost\s*[:=]\s*(\d{3,9})/i,
    language: ['javascript', 'typescript', 'python', 'go', 'rust'],
    parameter: 'memory',
    minimum: 19_456,
    unit: 'KiB',
    guidance: 'OWASP recommends Argon2id with at least 19 MiB of memory, 2 iterations and 1 degree of parallelism.',
  },
  {
    ruleId: 'kdf-scrypt-cost',
    algorithm: 'scrypt',
    pattern: /scrypt[^\n;)]{0,120}?\bN\s*[:=]\s*(\d{3,9})/i,
    language: ['javascript', 'typescript', 'python', 'go'],
    parameter: 'cost',
    minimum: 65_536,
    unit: 'N',
    guidance: 'OWASP recommends scrypt with N ≥ 2^17 (131072), r = 8, p = 1; N ≥ 2^16 is the minimum.',
  },
];

/* ─────────────────────────────────────────────────────────────── helpers ─── */

/** Every API rule that applies to a language. */
export function apisForLanguage(language: string): CryptoApiDefinition[] {
  const key = language.toLowerCase();
  return CRYPTO_APIS.filter((api) => api.language.includes(key));
}

/**
 * Roles a SubtleCrypto / generic operation name implies.
 *
 * Used where the API rule matched an operation whose role depends on which
 * method was called rather than on the algorithm argument.
 */
export function roleForOperation(operation: string): CryptoRole {
  const name = operation.toLowerCase();
  if (/sign|verify/.test(name)) return 'digital-signature';
  if (/derivekey|derivebits/.test(name)) return 'key-derivation';
  if (/encrypt|decrypt/.test(name)) return 'encryption';
  if (/wrapkey|unwrapkey/.test(name)) return 'key-transport';
  if (/generatekey|importkey|exportkey/.test(name)) return 'key-management';
  if (/digest/.test(name)) return 'hashing';
  return 'unknown';
}
