/**
 * Canonical algorithm registry (§7, §8, §13, §14, §15, §16, §39).
 *
 * The single source of truth for what every cryptographic algorithm IS. Four
 * modules previously each held their own partial answer; they now delegate here.
 *
 * The field that does the most work is `migrationTargets`, which is keyed BY
 * ROLE. §80: "Do not blindly replace every algorithm with one PQC algorithm."
 * RSA used for key transport migrates to ML-KEM; RSA used for signatures
 * migrates to ML-DSA. One `migrationTarget: 'ML-DSA'` on the RSA record would
 * tell half the estate to adopt a signature scheme for its key exchange.
 *
 * `classicalSecurity` and `quantumStatus` are independent, per §9. Reading only
 * one of them is how "RSA-2048 is broken" gets published.
 */

import type { AlgorithmDefinition, CryptoRole } from './types';
import { standardsFor } from './standards';

/** Shorthand so the table stays readable. */
function algorithm(input: Omit<AlgorithmDefinition, 'standards'> & { standardIds?: string[] }): AlgorithmDefinition {
  const { standardIds, ...rest } = input;
  return { ...rest, standards: standardIds ? standardsFor(standardIds) : [] };
}

const RSA_MIGRATION: Partial<Record<CryptoRole, string>> = {
  'key-establishment': 'ML-KEM (FIPS 203), deployed hybrid with X25519 or ECDH during transition',
  'key-transport': 'ML-KEM (FIPS 203) key encapsulation — RSA key transport has no direct PQC equivalent and the construction changes',
  'digital-signature': 'ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) where a conservative hash-based scheme is required',
  'certificate-public-key': 'ML-DSA (FIPS 204) certificates once the issuing CA supports them',
  'certificate-signature': 'ML-DSA (FIPS 204) issuance chain',
  'code-signing': 'SLH-DSA (FIPS 205) — a stateless hash-based signature is the conservative choice for long-lived artefact signatures',
  'token-signing': 'ML-DSA (FIPS 204)',
  authentication: 'Hybrid classical + ML-DSA credentials',
  'key-management': 'A KMS/HSM profile able to issue and store ML-KEM and ML-DSA key material',
};

const ECC_SIGNATURE_MIGRATION: Partial<Record<CryptoRole, string>> = {
  'digital-signature': 'ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) for long-lived signatures',
  'certificate-public-key': 'ML-DSA (FIPS 204) certificates',
  'certificate-signature': 'ML-DSA (FIPS 204) issuance chain',
  'code-signing': 'SLH-DSA (FIPS 205)',
  'token-signing': 'ML-DSA (FIPS 204)',
  authentication: 'Hybrid Ed25519 + ML-DSA credentials',
};

const KEX_MIGRATION: Partial<Record<CryptoRole, string>> = {
  'key-establishment': 'ML-KEM (FIPS 203), deployed hybrid with the existing curve during transition',
  'transport-security': 'TLS 1.3 with a hybrid X25519MLKEM768 key-agreement group',
  'key-management': 'A KMS/HSM profile able to issue and store ML-KEM key material',
};

export const ALGORITHMS: AlgorithmDefinition[] = [
  /* ═══════════════════════════════════════════ public key — Shor-broken ══ */
  algorithm({
    algorithmId: 'rsa',
    canonicalName: 'RSA',
    aliases: ['rsa', 'rsaencryption', 'rsassa', 'rsaes', 'pkcs1', 'rsa-sha256', 'rsa-sha1', 'rsa-sha384', 'rsa-sha512',
      'sha256withrsa', 'sha1withrsa', 'sha384withrsa', 'sha512withrsa', 'rsassa-pkcs1-v1_5', 'rs256', 'rs384', 'rs512'],
    family: 'RSA',
    primitiveType: 'public-key-encryption',
    cryptographicRoles: ['digital-signature', 'key-transport', 'encryption', 'certificate-public-key', 'certificate-signature', 'code-signing', 'token-signing', 'authentication'],
    /* ACCEPTABLE, not BROKEN. §9 is explicit about this. */
    classicalSecurity: 'ACCEPTABLE',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    minimumKeySize: 2048,
    recommendedKeySize: 3072,
    weakKeySizes: [512, 768, 1024, 1536],
    supportedProtocols: ['TLS', 'SSH', 'S/MIME', 'JWS', 'X.509', 'IPsec'],
    knownLibraries: ['OpenSSL', 'BoringSSL', 'LibreSSL', 'Bouncy Castle', 'Windows CNG', 'Java JCA', 'Node crypto', 'Python cryptography'],
    knownIdentifiers: ['1.2.840.113549.1.1.1', '1.2.840.113549.1.1.11', '1.2.840.113549.1.1.10', 'ssh-rsa', 'RS256', 'PS256'],
    migrationTargets: RSA_MIGRATION,
    standardIds: ['SP-800-56B', 'FIPS-186-5', 'SP-800-131A', 'SP-800-57'],
    note: 'RSA at 2048 bits or more is classically acceptable and is NOT currently breakable. It is quantum-vulnerable, which makes it a migration candidate rather than an active compromise.',
  }),
  algorithm({
    algorithmId: 'rsa-pss',
    canonicalName: 'RSA-PSS',
    aliases: ['rsa-pss', 'rsassa-pss', 'pss', 'ps256', 'ps384', 'ps512'],
    family: 'RSA',
    primitiveType: 'digital-signature',
    cryptographicRoles: ['digital-signature', 'certificate-signature', 'token-signing'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    minimumKeySize: 2048,
    recommendedKeySize: 3072,
    knownIdentifiers: ['1.2.840.113549.1.1.10', 'PS256', 'PS384', 'PS512'],
    migrationTargets: RSA_MIGRATION,
    standardIds: ['FIPS-186-5'],
    note: 'RSA-PSS is the probabilistic signature scheme and is preferred over PKCS#1 v1.5 for new signatures. It remains quantum-vulnerable.',
  }),
  algorithm({
    algorithmId: 'rsa-pkcs1v15',
    canonicalName: 'RSA PKCS#1 v1.5',
    aliases: ['pkcs1v15', 'pkcs1-v1_5', 'rsa-pkcs1', 'rsaes-pkcs1-v1_5'],
    family: 'RSA',
    primitiveType: 'public-key-encryption',
    cryptographicRoles: ['key-transport', 'encryption', 'digital-signature'],
    classicalSecurity: 'LEGACY',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: true,
    disallowed: false,
    minimumKeySize: 2048,
    migrationTargets: RSA_MIGRATION,
    standardIds: ['SP-800-56B'],
    note: 'PKCS#1 v1.5 ENCRYPTION padding is vulnerable to Bleichenbacher-style oracle attacks and is deprecated in favour of RSA-OAEP. The signature variant is separately still permitted.',
  }),
  algorithm({
    algorithmId: 'rsa-oaep',
    canonicalName: 'RSA-OAEP',
    aliases: ['rsa-oaep', 'oaep', 'rsaes-oaep'],
    family: 'RSA',
    primitiveType: 'public-key-encryption',
    cryptographicRoles: ['key-transport', 'encryption'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    minimumKeySize: 2048,
    migrationTargets: RSA_MIGRATION,
    standardIds: ['SP-800-56B'],
  }),
  algorithm({
    algorithmId: 'ecdsa',
    canonicalName: 'ECDSA',
    aliases: ['ecdsa', 'ecdsa-with-sha256', 'ecdsa-with-sha384', 'ecdsa-with-sha512', 'sha256withecdsa', 'es256', 'es384', 'es512', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'],
    family: 'ECC',
    primitiveType: 'digital-signature',
    cryptographicRoles: ['digital-signature', 'certificate-public-key', 'certificate-signature', 'code-signing', 'token-signing', 'authentication'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    knownIdentifiers: ['1.2.840.10045.2.1', '1.2.840.10045.4.3.2', 'ES256', 'ecdsa-sha2-nistp256'],
    migrationTargets: ECC_SIGNATURE_MIGRATION,
    standardIds: ['FIPS-186-5', 'SP-800-57'],
    note: 'ECDSA security depends on the named curve. The curve, not the algorithm name, determines the classical strength.',
  }),
  algorithm({
    algorithmId: 'ecdh',
    canonicalName: 'ECDH',
    aliases: ['ecdh', 'ecdhe', 'eecdh', 'ecies'],
    family: 'ECC',
    primitiveType: 'key-establishment',
    cryptographicRoles: ['key-establishment', 'transport-security'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    supportedProtocols: ['TLS', 'SSH', 'IPsec'],
    migrationTargets: KEX_MIGRATION,
    standardIds: ['SP-800-56A'],
    note: 'ECDHE provides forward secrecy against a classical adversary. It does NOT protect against harvest-now-decrypt-later, because a future quantum computer recovers the session key from the recorded handshake.',
  }),
  algorithm({
    algorithmId: 'x25519',
    canonicalName: 'X25519',
    aliases: ['x25519', 'curve25519-sha256', 'x448'],
    family: 'ECC',
    primitiveType: 'key-establishment',
    cryptographicRoles: ['key-establishment', 'transport-security'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    knownIdentifiers: ['1.3.101.110', '1.3.101.111'],
    migrationTargets: KEX_MIGRATION,
    standardIds: ['SP-800-56A'],
    note: 'X25519 performs key agreement only and cannot sign.',
  }),
  algorithm({
    algorithmId: 'ed25519',
    canonicalName: 'Ed25519',
    aliases: ['ed25519', 'eddsa', 'ed448', 'ssh-ed25519', 'eddsa25519'],
    family: 'ECC',
    primitiveType: 'digital-signature',
    cryptographicRoles: ['digital-signature', 'certificate-public-key', 'authentication', 'code-signing'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    knownIdentifiers: ['1.3.101.112', '1.3.101.113', 'ssh-ed25519', 'EdDSA'],
    migrationTargets: ECC_SIGNATURE_MIGRATION,
    standardIds: ['FIPS-186-5'],
    note: 'Ed25519 signs only and cannot perform key agreement.',
  }),
  algorithm({
    algorithmId: 'dh',
    canonicalName: 'Diffie-Hellman',
    aliases: ['dh', 'dhe', 'diffie-hellman', 'diffiehellman', 'ffdhe', 'modp', 'edh'],
    family: 'DH',
    primitiveType: 'key-establishment',
    cryptographicRoles: ['key-establishment', 'transport-security'],
    classicalSecurity: 'ACCEPTABLE',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    minimumKeySize: 2048,
    recommendedKeySize: 3072,
    weakKeySizes: [512, 768, 1024, 1536],
    supportedProtocols: ['TLS', 'SSH', 'IPsec'],
    migrationTargets: KEX_MIGRATION,
    standardIds: ['SP-800-56A'],
    note: 'Finite-field Diffie-Hellman below 2048 bits is within reach of precomputation attacks (Logjam). Named FFDHE groups are preferred over custom parameters.',
  }),
  algorithm({
    algorithmId: 'dsa',
    canonicalName: 'DSA',
    aliases: ['dsa', 'dss', 'ssh-dss', 'sha1withdsa'],
    family: 'DSA',
    primitiveType: 'digital-signature',
    cryptographicRoles: ['digital-signature', 'certificate-public-key'],
    classicalSecurity: 'LEGACY',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: true,
    disallowed: true,
    knownIdentifiers: ['1.2.840.10040.4.1', 'ssh-dss'],
    migrationTargets: ECC_SIGNATURE_MIGRATION,
    standardIds: ['FIPS-186-5'],
    note: 'FIPS 186-5 withdrew DSA for signature GENERATION. It remains quantum-vulnerable in addition to being withdrawn.',
  }),
  algorithm({
    algorithmId: 'elgamal',
    canonicalName: 'ElGamal',
    aliases: ['elgamal'],
    family: 'DH',
    primitiveType: 'public-key-encryption',
    cryptographicRoles: ['encryption', 'key-transport'],
    classicalSecurity: 'LEGACY',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: true,
    disallowed: false,
    migrationTargets: KEX_MIGRATION,
  }),
  algorithm({
    algorithmId: 'sm2',
    canonicalName: 'SM2',
    aliases: ['sm2'],
    family: 'ECC',
    primitiveType: 'digital-signature',
    cryptographicRoles: ['digital-signature', 'key-establishment', 'encryption'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_VULNERABLE',
    shorBroken: true,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    migrationTargets: ECC_SIGNATURE_MIGRATION,
    note: 'SM2 is the Chinese national elliptic-curve standard. It is not FIPS-approved and is quantum-vulnerable.',
  }),

  /* ═════════════════════════════════════════════ post-quantum (§39) ══════ */
  algorithm({
    algorithmId: 'ml-kem',
    canonicalName: 'ML-KEM',
    aliases: ['ml-kem', 'mlkem', 'kyber', 'crystals-kyber', 'kyber512', 'kyber768', 'kyber1024',
      'ml-kem-512', 'ml-kem-768', 'ml-kem-1024', 'mlkem512', 'mlkem768', 'mlkem1024'],
    family: 'ML-KEM',
    primitiveType: 'key-establishment',
    cryptographicRoles: ['key-establishment', 'transport-security', 'key-management'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'PQC_STANDARDIZED',
    shorBroken: false,
    groverAffected: false,
    standardStatus: 'FIPS 203',
    deprecated: false,
    disallowed: false,
    knownLibraries: ['liboqs', 'BoringSSL', 'OpenSSL 3.5+', 'AWS-LC', 'Bouncy Castle', '@noble/post-quantum', 'CIRCL'],
    knownIdentifiers: ['2.16.840.1.101.3.4.4.1', '2.16.840.1.101.3.4.4.2', '2.16.840.1.101.3.4.4.3'],
    standardIds: ['FIPS-203', 'CNSA-2.0'],
    note: 'ML-KEM is a KEY ENCAPSULATION MECHANISM. It is not a signature scheme and must never be recommended for signing. Kyber is the pre-standardisation name for the same technology.',
  }),
  algorithm({
    algorithmId: 'ml-dsa',
    canonicalName: 'ML-DSA',
    aliases: ['ml-dsa', 'mldsa', 'dilithium', 'crystals-dilithium', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87', 'dilithium2', 'dilithium3', 'dilithium5'],
    family: 'ML-DSA',
    primitiveType: 'digital-signature',
    cryptographicRoles: ['digital-signature', 'certificate-public-key', 'certificate-signature', 'code-signing', 'token-signing', 'authentication'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'PQC_STANDARDIZED',
    shorBroken: false,
    groverAffected: false,
    standardStatus: 'FIPS 204',
    deprecated: false,
    disallowed: false,
    knownLibraries: ['liboqs', 'Bouncy Castle', '@noble/post-quantum', 'CIRCL'],
    knownIdentifiers: ['2.16.840.1.101.3.4.3.17', '2.16.840.1.101.3.4.3.18', '2.16.840.1.101.3.4.3.19'],
    standardIds: ['FIPS-204', 'CNSA-2.0'],
    note: 'ML-DSA is a SIGNATURE scheme. It cannot perform key establishment. Dilithium is the pre-standardisation name for the same technology.',
  }),
  algorithm({
    algorithmId: 'slh-dsa',
    canonicalName: 'SLH-DSA',
    aliases: ['slh-dsa', 'slhdsa', 'sphincs', 'sphincs+', 'sphincsplus', 'sphincs-plus'],
    family: 'SLH-DSA',
    primitiveType: 'digital-signature',
    cryptographicRoles: ['digital-signature', 'code-signing', 'certificate-signature'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'PQC_STANDARDIZED',
    shorBroken: false,
    groverAffected: false,
    standardStatus: 'FIPS 205',
    deprecated: false,
    disallowed: false,
    knownLibraries: ['liboqs', 'Bouncy Castle', '@noble/post-quantum'],
    standardIds: ['FIPS-205', 'CNSA-2.0'],
    note: 'SLH-DSA is stateless and hash-based, so its security rests only on the hash function. Signatures are large, which suits long-lived artefact and firmware signing more than TLS.',
  }),
  algorithm({
    algorithmId: 'fn-dsa',
    canonicalName: 'FN-DSA (Falcon)',
    aliases: ['falcon', 'fn-dsa', 'falcon-512', 'falcon-1024'],
    family: 'FN-DSA',
    primitiveType: 'digital-signature',
    cryptographicRoles: ['digital-signature'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'PQC_STANDARDIZED',
    shorBroken: false,
    groverAffected: false,
    standardStatus: 'FIPS 206 (draft)',
    deprecated: false,
    disallowed: false,
    note: 'Falcon was selected by NIST and is being standardised as FN-DSA. The standard is not yet final, so an implementation cannot be described as FIPS-validated for it.',
  }),
  algorithm({
    algorithmId: 'xmss',
    canonicalName: 'XMSS / LMS',
    aliases: ['xmss', 'xmssmt', 'lms', 'hss'],
    family: 'hash-signature',
    primitiveType: 'digital-signature',
    cryptographicRoles: ['digital-signature', 'code-signing'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'PQC_STANDARDIZED',
    shorBroken: false,
    groverAffected: false,
    standardStatus: 'NIST SP 800-208',
    deprecated: false,
    disallowed: false,
    note: 'XMSS and LMS are STATEFUL hash-based signatures. State reuse catastrophically breaks them, which restricts them to firmware and software signing with rigorous key-state management.',
  }),
  algorithm({
    algorithmId: 'sntrup761',
    canonicalName: 'Streamlined NTRU Prime',
    aliases: ['sntrup761', 'sntrup', 'ntruprime', 'streamlined-ntru-prime'],
    family: 'ntru',
    primitiveType: 'key-establishment',
    cryptographicRoles: ['key-establishment', 'transport-security'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    knownLibraries: ['OpenSSH', 'libntruprime'],
    knownIdentifiers: ['sntrup761x25519-sha512@openssh.com'],
    note: "Streamlined NTRU Prime is the post-quantum half of OpenSSH's default hybrid key exchange. It is NOT a NIST-standardised algorithm — it was not selected in the FIPS 203 process — so an implementation using it is post-quantum but not FIPS-aligned, and both facts matter for a governance report.",
  }),
  algorithm({
    algorithmId: 'weak-prng',
    canonicalName: 'Non-cryptographic PRNG',
    aliases: ['weak-prng', 'math.random', 'insecure-random', 'random'],
    family: 'RNG',
    primitiveType: 'rng',
    cryptographicRoles: ['random-generation'],
    /* BROKEN for a security purpose: the output is predictable. This is a
       classical property; a quantum computer is irrelevant to it. */
    classicalSecurity: 'BROKEN',
    quantumStatus: 'NOT_APPLICABLE',
    shorBroken: false,
    groverAffected: false,
    deprecated: true,
    disallowed: true,
    standardIds: ['SP-800-90A'],
    note: 'A non-cryptographic pseudo-random generator. Predictable from a small number of observations, so it must never produce key material, nonces, IVs, salts or tokens.',
  }),
  algorithm({
    algorithmId: 'classic-mceliece',
    canonicalName: 'Classic McEliece',
    aliases: ['mceliece', 'classic-mceliece', 'classicmceliece'],
    family: 'code-based',
    primitiveType: 'key-establishment',
    cryptographicRoles: ['key-establishment'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    note: 'Classic McEliece is a NIST round-4 candidate, not a finalised FIPS standard. Its public keys are very large.',
  }),

  /* ═══════════════════════════════════════════════════════ symmetric ════ */
  algorithm({
    algorithmId: 'aes',
    canonicalName: 'AES',
    aliases: ['aes', 'aes-128', 'aes-192', 'aes-256', 'aes128', 'aes192', 'aes256', 'rijndael',
      'aes-gcm', 'aes-cbc', 'aes-ctr', 'aes-ccm', 'aes-ecb', 'aes-128-gcm', 'aes-256-gcm', 'aes-128-cbc', 'aes-256-cbc',
      'a128gcm', 'a256gcm', 'a128cbc-hs256', 'a256cbc-hs512'],
    family: 'AES',
    primitiveType: 'block-cipher',
    cryptographicRoles: ['encryption', 'authenticated-encryption', 'storage-encryption', 'database-encryption', 'key-management'],
    classicalSecurity: 'STRONG',
    /* NOT vulnerable. §38 and §95: AES-256 must never be presented as
       equivalent to RSA in quantum exposure. */
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
    minimumKeySize: 128,
    recommendedKeySize: 256,
    supportedProtocols: ['TLS', 'SSH', 'IPsec', 'JWE'],
    standardIds: ['SP-800-57', 'CNSA-2.0'],
    note: 'Grover-style search halves the effective key strength: AES-256 retains roughly 128 bits and AES-128 roughly 64. AES-256 is the recommended choice for long-term confidentiality, but AES is not a post-quantum migration candidate in the sense RSA and ECC are.',
  }),
  algorithm({
    algorithmId: 'chacha20-poly1305',
    canonicalName: 'ChaCha20-Poly1305',
    aliases: ['chacha20', 'chacha20-poly1305', 'chacha', 'xchacha20', 'xchacha20-poly1305'],
    family: 'ChaCha',
    primitiveType: 'aead',
    cryptographicRoles: ['authenticated-encryption', 'encryption', 'storage-encryption'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
    minimumKeySize: 256,
    recommendedKeySize: 256,
    note: 'ChaCha20-Poly1305 is a 256-bit AEAD construction and retains roughly 128 bits against Grover-style search.',
  }),
  algorithm({
    algorithmId: 'salsa20',
    canonicalName: 'Salsa20',
    aliases: ['salsa20', 'xsalsa20'],
    family: 'ChaCha',
    primitiveType: 'stream-cipher',
    cryptographicRoles: ['encryption'],
    classicalSecurity: 'ACCEPTABLE',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
  }),
  algorithm({
    algorithmId: '3des',
    canonicalName: '3DES',
    aliases: ['3des', 'triple-des', 'tripledes', 'des-ede3', 'des3', 'des-ede3-cbc'],
    family: 'DES',
    primitiveType: 'block-cipher',
    cryptographicRoles: ['encryption'],
    classicalSecurity: 'BROKEN',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: true,
    disallowed: true,
    standardIds: ['SP-800-131A'],
    note: '3DES has a 64-bit block, which makes it vulnerable to Sweet32 birthday attacks on long-lived connections. NIST disallowed it after 2023. This is a CLASSICAL problem, not a quantum one.',
  }),
  algorithm({
    algorithmId: 'des',
    canonicalName: 'DES',
    aliases: ['des', 'des-cbc'],
    family: 'DES',
    primitiveType: 'block-cipher',
    cryptographicRoles: ['encryption'],
    classicalSecurity: 'BROKEN',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: true,
    disallowed: true,
    standardIds: ['SP-800-131A'],
    note: 'DES has a 56-bit key and is exhaustively searchable with commodity hardware.',
  }),
  algorithm({
    algorithmId: 'rc4',
    canonicalName: 'RC4',
    aliases: ['rc4', 'arcfour', 'arcfour128', 'arcfour256'],
    family: 'RC4',
    primitiveType: 'stream-cipher',
    cryptographicRoles: ['encryption'],
    classicalSecurity: 'BROKEN',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: true,
    disallowed: true,
    standardIds: ['RFC-7465'],
    note: 'RC4 keystream biases are practically exploitable. RFC 7465 prohibits it in TLS.',
  }),
  algorithm({
    algorithmId: 'blowfish',
    canonicalName: 'Blowfish',
    aliases: ['blowfish', 'bf-cbc'],
    family: 'Blowfish',
    primitiveType: 'block-cipher',
    cryptographicRoles: ['encryption'],
    classicalSecurity: 'BROKEN',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: true,
    disallowed: true,
    note: 'Blowfish has a 64-bit block and is subject to the same birthday-bound problem as 3DES.',
  }),
  algorithm({
    algorithmId: 'camellia',
    canonicalName: 'Camellia',
    aliases: ['camellia', 'camellia-128', 'camellia-256'],
    family: 'Camellia',
    primitiveType: 'block-cipher',
    cryptographicRoles: ['encryption'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
  }),
  algorithm({
    algorithmId: 'sm4',
    canonicalName: 'SM4',
    aliases: ['sm4'],
    family: 'SM4',
    primitiveType: 'block-cipher',
    cryptographicRoles: ['encryption'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
  }),

  /* ══════════════════════════════════════════════════════════ hashes ════ */
  algorithm({
    algorithmId: 'sha2',
    canonicalName: 'SHA-2',
    aliases: ['sha-2', 'sha2', 'sha224', 'sha-224', 'sha256', 'sha-256', 'sha384', 'sha-384',
      'sha512', 'sha-512', 'sha-512/224', 'sha-512/256', 'sha512-256'],
    family: 'SHA-2',
    primitiveType: 'hash',
    cryptographicRoles: ['hashing', 'integrity', 'digital-signature', 'certificate-signature'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
    standardIds: ['SP-800-57'],
    note: 'SHA-256 retains roughly 128 bits of collision resistance against a quantum adversary, which is adequate. SHA-2 is not a migration candidate.',
  }),
  algorithm({
    algorithmId: 'sha3',
    canonicalName: 'SHA-3',
    aliases: ['sha-3', 'sha3', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'keccak', 'shake128', 'shake256'],
    family: 'SHA-3',
    primitiveType: 'hash',
    cryptographicRoles: ['hashing', 'integrity', 'digital-signature'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
  }),
  algorithm({
    algorithmId: 'blake2',
    canonicalName: 'BLAKE2',
    aliases: ['blake2', 'blake2b', 'blake2s', 'blake3'],
    family: 'BLAKE',
    primitiveType: 'hash',
    cryptographicRoles: ['hashing', 'integrity'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
    note: 'BLAKE2 and BLAKE3 are cryptographically strong but are not NIST-approved, which matters only where FIPS validation is required.',
  }),
  algorithm({
    algorithmId: 'sha1',
    canonicalName: 'SHA-1',
    aliases: ['sha-1', 'sha1'],
    family: 'SHA-1',
    primitiveType: 'hash',
    cryptographicRoles: ['hashing', 'integrity', 'digital-signature', 'certificate-signature'],
    /* BROKEN classically; quantum-irrelevant. §14 requires the USE to decide
       how much that matters. */
    classicalSecurity: 'BROKEN',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: true,
    disallowed: true,
    standardIds: ['SP-800-131A-SHA1', 'CABF-BR'],
    note: 'SHA-1 collisions are practical (SHAttered, 2017). It must not sign certificates or tokens. Its use as a non-security identifier — a Git object id, a cache key — is not a security finding.',
  }),
  algorithm({
    algorithmId: 'md5',
    canonicalName: 'MD5',
    aliases: ['md5'],
    family: 'MD',
    primitiveType: 'hash',
    cryptographicRoles: ['hashing', 'integrity'],
    classicalSecurity: 'BROKEN',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: true,
    disallowed: true,
    standardIds: ['RFC-6151', 'SP-800-131A'],
    note: 'MD5 collisions are trivially generated. It is unsuitable for any security purpose, though a non-security checksum use is not itself a vulnerability.',
  }),
  algorithm({
    algorithmId: 'md4',
    canonicalName: 'MD4 / MD2',
    aliases: ['md4', 'md2'],
    family: 'MD',
    primitiveType: 'hash',
    cryptographicRoles: ['hashing'],
    classicalSecurity: 'BROKEN',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: true,
    disallowed: true,
  }),
  algorithm({
    algorithmId: 'ripemd',
    canonicalName: 'RIPEMD-160',
    aliases: ['ripemd', 'ripemd160', 'ripemd-160'],
    family: 'RIPEMD',
    primitiveType: 'hash',
    cryptographicRoles: ['hashing', 'integrity'],
    classicalSecurity: 'LEGACY',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: true,
    disallowed: false,
    note: 'RIPEMD-160 has a 160-bit output, so its collision resistance is below current guidance. It remains in use in Bitcoin address derivation.',
  }),
  algorithm({
    algorithmId: 'sm3',
    canonicalName: 'SM3',
    aliases: ['sm3'],
    family: 'SM3',
    primitiveType: 'hash',
    cryptographicRoles: ['hashing', 'integrity'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
  }),

  /* ════════════════════════════════════════════════════════ MAC / KDF ═══ */
  algorithm({
    algorithmId: 'hmac',
    canonicalName: 'HMAC',
    aliases: ['hmac', 'hmac-sha256', 'hmac-sha1', 'hs256', 'hs384', 'hs512'],
    family: 'HMAC',
    primitiveType: 'mac',
    cryptographicRoles: ['integrity', 'authentication', 'token-signing'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
    note: 'HMAC is a symmetric construction. HMAC-SHA1 remains secure as a MAC despite SHA-1 collisions, because HMAC does not depend on collision resistance.',
  }),
  algorithm({
    algorithmId: 'poly1305',
    canonicalName: 'Poly1305',
    aliases: ['poly1305', 'cmac', 'gmac'],
    family: 'MAC',
    primitiveType: 'mac',
    cryptographicRoles: ['integrity'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
  }),
  algorithm({
    algorithmId: 'hkdf',
    canonicalName: 'HKDF',
    aliases: ['hkdf', 'hkdf-sha256'],
    family: 'KDF',
    primitiveType: 'kdf',
    cryptographicRoles: ['key-derivation'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
  }),
  algorithm({
    algorithmId: 'pbkdf2',
    canonicalName: 'PBKDF2',
    aliases: ['pbkdf2', 'pbkdf2-sha256', 'pbkdf2-hmac-sha256'],
    family: 'KDF',
    primitiveType: 'password-hash',
    cryptographicRoles: ['password-derivation', 'key-derivation'],
    classicalSecurity: 'ACCEPTABLE',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
    standardIds: ['SP-800-63B'],
    note: 'PBKDF2 is acceptable only with a high iteration count. It offers no memory hardness, so it resists GPU cracking far less well than Argon2 or scrypt.',
  }),
  algorithm({
    algorithmId: 'bcrypt',
    canonicalName: 'bcrypt',
    aliases: ['bcrypt'],
    family: 'password-hash',
    primitiveType: 'password-hash',
    cryptographicRoles: ['password-derivation'],
    classicalSecurity: 'ACCEPTABLE',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
    note: 'bcrypt silently truncates input beyond 72 bytes, which matters when a pepper or a long passphrase is used.',
  }),
  algorithm({
    algorithmId: 'scrypt',
    canonicalName: 'scrypt',
    aliases: ['scrypt'],
    family: 'password-hash',
    primitiveType: 'password-hash',
    cryptographicRoles: ['password-derivation', 'key-derivation'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
  }),
  algorithm({
    algorithmId: 'argon2',
    canonicalName: 'Argon2',
    aliases: ['argon2', 'argon2i', 'argon2d', 'argon2id'],
    family: 'password-hash',
    primitiveType: 'password-hash',
    cryptographicRoles: ['password-derivation'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'QUANTUM_RESISTANT',
    shorBroken: false,
    groverAffected: true,
    deprecated: false,
    disallowed: false,
    note: 'Argon2id is the recommended variant, combining resistance to side-channel and GPU attacks.',
  }),

  /* ═══════════════════════════════════════════════════════ protocols ════ */
  algorithm({
    algorithmId: 'tls',
    canonicalName: 'TLS',
    aliases: ['tls', 'tlsv1.2', 'tlsv1.3', 'tls1.2', 'tls1.3', 'mtls'],
    family: 'protocol',
    primitiveType: 'protocol',
    cryptographicRoles: ['transport-security'],
    classicalSecurity: 'STRONG',
    /* A protocol has no quantum status of its own — the primitives it
       negotiates do. §19: identify WHICH component creates the exposure. */
    quantumStatus: 'NOT_APPLICABLE',
    shorBroken: false,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    standardIds: ['SP-800-52', 'RFC-9325'],
    note: 'TLS is a protocol, not a primitive. Its quantum exposure is determined by the key-agreement group and the certificate signature algorithm it negotiates.',
  }),
  algorithm({
    algorithmId: 'ssl-legacy',
    canonicalName: 'SSL (legacy)',
    aliases: ['sslv2', 'sslv3', 'ssl2', 'ssl3', 'ssl 3.0', 'ssl 2.0'],
    family: 'protocol',
    primitiveType: 'protocol',
    cryptographicRoles: ['transport-security'],
    classicalSecurity: 'BROKEN',
    quantumStatus: 'NOT_APPLICABLE',
    shorBroken: false,
    groverAffected: false,
    deprecated: true,
    disallowed: true,
    standardIds: ['RFC-8996', 'SP-800-52'],
    note: 'SSL 2.0 and 3.0 are broken (DROWN, POODLE) and must not be offered.',
  }),
  algorithm({
    algorithmId: 'tls10',
    canonicalName: 'TLS 1.0',
    aliases: ['tlsv1.0', 'tlsv1', 'tls1.0', 'tls 1.0'],
    family: 'protocol',
    primitiveType: 'protocol',
    cryptographicRoles: ['transport-security'],
    classicalSecurity: 'LEGACY',
    quantumStatus: 'NOT_APPLICABLE',
    shorBroken: false,
    groverAffected: false,
    deprecated: true,
    disallowed: true,
    standardIds: ['RFC-8996', 'SP-800-52'],
    note: 'RFC 8996 deprecates TLS 1.0 and 1.1. A TLS 1.0 endpoint also cannot negotiate a hybrid post-quantum group, so it has no path to post-quantum transport without a protocol upgrade.',
  }),
  algorithm({
    algorithmId: 'tls11',
    canonicalName: 'TLS 1.1',
    aliases: ['tlsv1.1', 'tls1.1', 'tls 1.1'],
    family: 'protocol',
    primitiveType: 'protocol',
    cryptographicRoles: ['transport-security'],
    classicalSecurity: 'LEGACY',
    quantumStatus: 'NOT_APPLICABLE',
    shorBroken: false,
    groverAffected: false,
    deprecated: true,
    disallowed: true,
    standardIds: ['RFC-8996', 'SP-800-52'],
  }),
  algorithm({
    algorithmId: 'ssh',
    canonicalName: 'SSH',
    aliases: ['ssh', 'sshv2', 'ssh-2'],
    family: 'protocol',
    primitiveType: 'protocol',
    cryptographicRoles: ['transport-security', 'authentication'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'NOT_APPLICABLE',
    shorBroken: false,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
  }),
  algorithm({
    algorithmId: 'jwt',
    canonicalName: 'JWT / JOSE',
    aliases: ['jwt', 'jws', 'jwe', 'jose'],
    family: 'protocol',
    primitiveType: 'protocol',
    cryptographicRoles: ['token-signing'],
    classicalSecurity: 'STRONG',
    quantumStatus: 'NOT_APPLICABLE',
    shorBroken: false,
    groverAffected: false,
    deprecated: false,
    disallowed: false,
    note: 'A JWT\'s exposure is determined by its `alg`: RS*/ES*/PS* are quantum-vulnerable, HS* are symmetric and are not.',
  }),
];

/* ─────────────────────────────────────────────────────────────── indexes ──── */

const BY_ID = new Map(ALGORITHMS.map((entry) => [entry.algorithmId, entry]));

const BY_ALIAS = (() => {
  const map = new Map<string, AlgorithmDefinition>();
  for (const entry of ALGORITHMS) {
    map.set(entry.canonicalName.toLowerCase(), entry);
    map.set(entry.algorithmId, entry);
    for (const alias of entry.aliases) map.set(alias, entry);
    for (const identifier of entry.knownIdentifiers ?? []) map.set(identifier.toLowerCase(), entry);
  }
  return map;
})();

/** Aliases longest-first, for the bounded free-text scan. */
const ALIAS_SCAN = (() => {
  const pairs: Array<{ alias: string; entry: AlgorithmDefinition }> = [];
  for (const entry of ALGORITHMS) {
    for (const alias of entry.aliases) pairs.push({ alias, entry });
  }
  return pairs.sort((a, b) => b.alias.length - a.alias.length);
})();

export function algorithmById(id: string): AlgorithmDefinition | null {
  return BY_ID.get(id) ?? null;
}

/**
 * Resolve a raw algorithm string.
 *
 * Exact alias match first. The free-text scan that follows requires a
 * non-alphanumeric boundary on both sides, which is what stops the three
 * collisions this codebase has actually shipped: `ssl` inside "OpenSSL",
 * `des` inside "described", and `dh` inside "ecdh".
 */
export function findAlgorithm(raw: string | null | undefined): AlgorithmDefinition | null {
  if (!raw) return null;
  const text = String(raw).trim().toLowerCase();
  if (!text) return null;

  const exact = BY_ALIAS.get(text);
  if (exact) return exact;

  const normalised = text.replace(/[_\s]+/g, '-');
  const byNormalised = BY_ALIAS.get(normalised);
  if (byNormalised) return byNormalised;

  // "RSA-2048" → "rsa"; "AES-256-GCM" is already an alias so it never reaches here.
  const withoutSize = normalised.replace(/-\d{2,5}(-|$)/g, '$1').replace(/-$/, '');
  const bySize = BY_ALIAS.get(withoutSize);
  if (bySize) return bySize;

  for (const { alias, entry } of ALIAS_SCAN) {
    const index = normalised.indexOf(alias);
    if (index === -1) continue;
    const before = index === 0 ? '' : normalised[index - 1];
    const after = normalised[index + alias.length] ?? '';
    const boundaryBefore = before === '' || !/[a-z0-9]/.test(before);
    // A trailing digit belongs to the name ("aes256"); a trailing letter does
    // not, which is what rejects "ssl" inside "openssl".
    const boundaryAfter = after === '' || !/[a-z]/.test(after);
    if (boundaryBefore && boundaryAfter) return entry;
  }

  return null;
}

export function canonicalName(raw: string | null | undefined): string {
  return findAlgorithm(raw)?.canonicalName ?? (String(raw ?? '').trim() || 'Unknown');
}

/** True when both strings name the same cryptographic technology. */
export function sameAlgorithm(a: string | null | undefined, b: string | null | undefined): boolean {
  const left = findAlgorithm(a);
  const right = findAlgorithm(b);
  if (left && right) return left.algorithmId === right.algorithmId;
  return String(a ?? '').trim().toLowerCase() === String(b ?? '').trim().toLowerCase();
}

/** Extract a plausible key size. Rejects years and other incidental numbers. */
const PLAUSIBLE_KEY_SIZES = new Set([
  128, 160, 192, 224, 256, 283, 384, 448, 512, 521, 768, 1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360,
]);

/**
 * The smallest size that is a KEY rather than a digest or a block, per family.
 *
 * A three-digit run near an RSA reference is almost always a hash length: the
 * modulus is four digits. Enforcing the floor is what stops `RSA-256` — which
 * is not a key size that exists — from being published.
 */
function plausibleForFamily(value: number, algorithm: AlgorithmDefinition | null | undefined): boolean {
  if (!PLAUSIBLE_KEY_SIZES.has(value)) return false;
  if (!algorithm) return true;
  const family = algorithm.family.toLowerCase();
  if (family === 'rsa' || family === 'dh' || family === 'dsa' || family === 'elgamal') return value >= 512;
  if (family === 'ecc' || family === 'ec') return value >= 160 && value <= 521;
  return true;
}

/**
 * A key size the observation actually STATES, for the algorithm that owns it.
 *
 * ── The defect this replaces ────────────────────────────────────────────────
 *
 * The size used to be the first plausible three-to-five digit run ANYWHERE in
 * the string, with no requirement that it belong to the algorithm being
 * classified. The digest length and the bulk cipher's key length were
 * therefore read as the public key size:
 *
 *   sha256WithRSAEncryption            ->  256   -> "RSA-256"
 *   TLS_ECDHE_RSA_WITH_AES_128_GCM     ->  128   -> "RSA-128"
 *
 * A live Dev scan of this repository published `RSA-256 for digital signature`
 * as a CRITICAL finding. RSA-256 is not a key size that exists; it is a
 * misread of a SHA-256 designation, and it appeared at the top of the panel.
 *
 * A digit run now counts only when it is written against the algorithm that
 * owns it, or against an explicit bit marker. When no size is stated the
 * answer is `null` — the caller records "key size not established", which is a
 * measurement gap rather than an invented measurement.
 */
export function parseKeySize(
  raw: string | null | undefined,
  ownedBy?: AlgorithmDefinition | null,
): number | null {
  if (!raw) return null;
  const value = String(raw).trim();

  /* A bare number is the size, with nothing else to misattribute it to. */
  if (/^\d{3,5}$/.test(value)) {
    const bare = Number(value);
    return plausibleForFamily(bare, ownedBy) ? bare : null;
  }

  /* "2048-bit", "2048 bits", "bits: 2048" — the marker names the quantity. */
  for (const pattern of [/(\d{3,5})[-_ ]?bits?\b/i, /\bbits?[-_ :]+(\d{3,5})/i]) {
    const match = value.match(pattern);
    if (match) {
      const stated = Number(match[1]);
      if (plausibleForFamily(stated, ownedBy)) return stated;
    }
  }

  /* Attached to the algorithm's own name: rsa-2048, rsa2048, RSA_2048,
     rsaEncryption 2048, ML-KEM-768. Without a name to anchor to there is no
     way to tell whose number it is, so nothing is returned. */
  if (!ownedBy) return null;

  const tokens = [ownedBy.canonicalName, ...ownedBy.aliases]
    .map((name) => name.toLowerCase().replace(/[^a-z0-9]+/g, '[-_ ]?'))
    .filter((name) => name.length > 0);

  for (const token of tokens) {
    const match = value.match(new RegExp(`${token}[a-z]*[-_ ]?\\(?(\\d{3,5})\\)?`, 'i'));
    if (!match) continue;
    const stated = Number(match[1]);
    if (plausibleForFamily(stated, ownedBy)) return stated;
  }

  return null;
}

export function knownAlgorithmNames(): string[] {
  return ALGORITHMS.map((entry) => entry.canonicalName);
}

/** Every algorithm broken by Shor's algorithm — the migration population. */
export function shorBrokenAlgorithms(): AlgorithmDefinition[] {
  return ALGORITHMS.filter((entry) => entry.shorBroken);
}

/** Every NIST-standardised post-quantum algorithm the base recognises. */
export function pqcAlgorithms(): AlgorithmDefinition[] {
  return ALGORITHMS.filter((entry) => entry.quantumStatus === 'PQC_STANDARDIZED');
}
