export const MANDATORY_PQC_STACK = {
  version: 'qguard-pqc-stack-v1',
  libraries: ['Open Quantum Safe liboqs', 'OQS-OpenSSL Hybrid Builds', 'OQS Provider', 'OpenSSL 3.x provider interface'],
  referenceUrls: [
    'https://openquantumsafe.org/liboqs/',
    'https://github.com/open-quantum-safe/liboqs',
    'https://github.com/open-quantum-safe/oqs-provider',
    'https://github.com/open-quantum-safe/openssl',
  ],
  integration: {
    nativeLibrary: 'Open Quantum Safe liboqs',
    primaryProvider: 'OQS Provider for OpenSSL 3.x',
    compatibilityBuild: 'OQS-OpenSSL hybrid builds',
    opensslProviderName: 'oqsprovider',
  },
  keyExchange: {
    primary: 'ML-KEM-768',
    hybrid: 'X25519 + ML-KEM-768',
  },
  tls: {
    minProtocol: 'TLSv1.3',
    keyExchange: 'X25519 + ML-KEM-768',
    preferredGroup: 'X25519MLKEM768',
    groups: ['X25519MLKEM768', 'X25519 + ML-KEM-768', 'ML-KEM-768'],
    cipherSuites: ['TLS_AES_256_GCM_SHA384'],
    hybridEnabled: true,
    classicalFallback: 'policy-controlled',
  },
  signatures: {
    primary: 'ML-DSA-65',
    hybrid: 'Ed25519 + ML-DSA-65',
  },
  /*
   * SSH names its primitives differently from TLS, and a patcher that writes
   * one syntax into the other produces a config the daemon refuses to load.
   * `X25519MLKEM768:X25519` is a TLS group list; sshd expects SSH kex names,
   * comma-separated. Writing the TLS form into `KexAlgorithms` stopped sshd
   * from starting, which then failed post-patch validation and rolled back.
   *
   * `mlkem768x25519-sha256` is OpenSSH 10's default hybrid kex;
   * `sntrup761x25519-sha512@openssh.com` is the OpenSSH 9.x hybrid, kept so
   * the value applies to hosts that have not moved to 10 yet;
   * `curve25519-sha256` remains last as the classical fallback.
   */
  ssh: {
    kexAlgorithms: 'mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256',
    /*
     * Stock OpenSSH has no post-quantum HOST KEY type: authentication stays
     * classical until one is standardised in the protocol. This is the
     * hardened classical set, and it is published as an accepted residual —
     * never as evidence that SSH authentication is quantum-safe.
     */
    hostKeyAlgorithms: 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256',
    pubkeyAcceptedAlgorithms: 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256',
    ciphers: 'aes256-gcm@openssh.com,aes256-ctr',
    hostKeyResidual:
      'SSH host-key authentication remains classical: the protocol has no standardised post-quantum host-key type. Session confidentiality is protected by the hybrid ML-KEM key exchange, so recorded traffic is not harvestable.',
  },
  encryption: {
    symmetric: 'AES-256-GCM',
    envelope: 'AES-256-GCM + ML-KEM-768 envelope',
  },
  kdf: {
    primary: 'HKDF-SHA3-256',
    compatibilityFallback: 'HKDF-SHA-256',
  },
  hashes: ['SHA3-256', 'SHA3-512'],
  // Reserved for assets that anchor long-term trust (Quantum Vault, QKMS root
  // keys, HSM-backed roots): stronger parameter sets from the approved stack.
  highSecurityProfile: {
    label: 'High Security Profile (Quantum Vault / QKMS / HSM roots)',
    keyExchange: 'ML-KEM-1024',
    signatures: ['ML-DSA-87', 'SLH-DSA'],
    appliesTo: ['quantum-vault', 'qkms-root', 'hsm-root', 'long-term-trust-anchor'],
  },
  validationSignals: [
    'liboqs-present',
    'oqs-provider-loaded',
    'openssl3-provider-active',
    'tls-hybrid-group-negotiated',
    'mldsa-signature-available',
    'aes256gcm-enforced',
    'hkdf-sha3-derived',
    'sha3-integrity-evidence',
  ],
} as const

export const MANDATORY_PQC_TARGET_ALGORITHMS = [
  MANDATORY_PQC_STACK.tls.keyExchange,
  MANDATORY_PQC_STACK.keyExchange.primary,
  MANDATORY_PQC_STACK.signatures.hybrid,
  MANDATORY_PQC_STACK.signatures.primary,
  MANDATORY_PQC_STACK.encryption.symmetric,
  MANDATORY_PQC_STACK.kdf.primary,
  ...MANDATORY_PQC_STACK.hashes,
  MANDATORY_PQC_STACK.highSecurityProfile.keyExchange,
  ...MANDATORY_PQC_STACK.highSecurityProfile.signatures,
] as const

export const MANDATORY_PQC_REQUIRED_CAPABILITIES = [
  'liboqs',
  'oqs-provider',
  'openssl3',
  'hybrid-tls',
  'ml-kem-768',
  'ml-dsa-65',
  'aes-256-gcm',
  'hkdf-sha3-256',
  'sha3',
] as const

export const MANDATORY_PQC_CONFIG_VALUES = {
  pqcEnabled: 'true',
  postQuantumEnabled: 'true',
  hybridKemEnabled: 'true',
  tlsMinProtocol: MANDATORY_PQC_STACK.tls.minProtocol,
  tlsGroups: 'X25519MLKEM768:X25519',
  tlsKemGroup: MANDATORY_PQC_STACK.tls.keyExchange,
  kemAlgorithm: MANDATORY_PQC_STACK.keyExchange.primary,
  signatureAlgorithm: MANDATORY_PQC_STACK.signatures.hybrid,
  pqcSignature: MANDATORY_PQC_STACK.signatures.primary,
  symmetricCipher: MANDATORY_PQC_STACK.encryption.symmetric,
  kdf: MANDATORY_PQC_STACK.kdf.primary,
  kdfCompatibilityFallback: MANDATORY_PQC_STACK.kdf.compatibilityFallback,
  hashAlgorithm: 'SHA3-256',
  integrityHash: 'SHA3-512',
  opensslProvider: 'oqsprovider',
  opensslConf: '/etc/ssl/oqs-openssl.cnf',
  oqsLibraries: MANDATORY_PQC_STACK.libraries.join(','),
  oqsProviderModule: 'oqsprovider',
  sshKexAlgorithms: MANDATORY_PQC_STACK.ssh.kexAlgorithms,
  sshHostKeyAlgorithms: MANDATORY_PQC_STACK.ssh.hostKeyAlgorithms,
  sshPubkeyAcceptedAlgorithms: MANDATORY_PQC_STACK.ssh.pubkeyAcceptedAlgorithms,
  sshCiphers: MANDATORY_PQC_STACK.ssh.ciphers,
} as const

/**
 * Is this configuration line already the value the mandatory stack prescribes?
 *
 * Post-patch validation needs the distinction between "the patch failed" and
 * "the approved end state legitimately still contains a classical primitive".
 * SSH is the case that forces it: stock OpenSSH has no post-quantum host-key
 * type, so `hostKeyAlgorithms` stays `ssh-ed25519,rsa-sha2-512,…` — the value
 * the Patcher itself writes. Scoring that as remaining risk made every SSH
 * remediation fail validation and roll back the configuration it had just
 * correctly applied, forever.
 *
 * The row is still PUBLISHED as the classical primitive it is, so Harvest Now,
 * the CBOM and the runtime dashboards keep seeing the residual honestly. Only
 * the rollback gate treats it as satisfied.
 */
export function matchesMandatoryConfigValue(line: unknown): { key: string; value: string; residualNote?: string } | null {
  const text = String(line ?? '').trim()
  if (!text) return null
  // Take everything after the first `=`, `:` or run of whitespace: that is the
  // configured VALUE. Comparing whole lines would never match, because the
  // directive names differ per file format.
  const separator = text.search(/[:=]|\s/)
  if (separator === -1) return null
  const value = text
    .slice(separator)
    .replace(/^[:=\s]+/, '')
    .replace(/[;,]\s*$/, '')
    .trim()
  if (!value) return null

  for (const [key, prescribed] of Object.entries(MANDATORY_PQC_CONFIG_VALUES)) {
    if (String(prescribed).toLowerCase() !== value.toLowerCase()) continue
    return key === 'sshHostKeyAlgorithms' || key === 'sshPubkeyAcceptedAlgorithms'
      ? { key, value, residualNote: MANDATORY_PQC_STACK.ssh.hostKeyResidual }
      : { key, value }
  }
  return null
}

function compact(value: unknown) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, '')
}

function lower(value: unknown) {
  return String(value || '').toLowerCase()
}

function isHighSecurityContext(normalized: string) {
  return /quantum.?vault|qkms.?root|hsm.?root|root.?of.?trust|trust.?anchor|high.?security|long.?term.?secret|cnsa/.test(normalized)
}

export function mandatoryPqcTargetForContext(sourceAlgorithm: unknown, context = '') {
  const text = `${sourceAlgorithm || ''} ${context || ''}`
  const normalized = lower(text)
  const sourceNormalized = lower(sourceAlgorithm).trim()
  const contextNormalized = lower(context)
  const compacted = compact(text)

  // High-security profile: explicit stronger parameter sets are approved and
  // must never be downgraded to the standard profile.
  if (/mlkem1024|kyber1024/.test(compacted)) return MANDATORY_PQC_STACK.highSecurityProfile.keyExchange
  if (/mldsa87|dilithium5/.test(compacted)) return 'ML-DSA-87'
  if (/slhdsa|sphincs/.test(compacted)) return 'SLH-DSA'
  if (isHighSecurityContext(normalized)) {
    if (/certificate|cert|pki|sign|signature|jwt|saml|identity|dsa|ed25519/.test(normalized)) return 'ML-DSA-87'
    return MANDATORY_PQC_STACK.highSecurityProfile.keyExchange
  }

  if (/x25519mlkem768|x25519kyber768|mlkem768x25519/.test(compacted)) return MANDATORY_PQC_STACK.tls.keyExchange
  if (/ed25519mldsa65|mldsa65ed25519/.test(compacted)) return MANDATORY_PQC_STACK.signatures.hybrid
  if (/^ml[-_ ]?kem[-_ ]?768$/.test(sourceNormalized) && !/tls|ssl|https|web|api|gateway|vpn|ssh|handshake|protocol/.test(contextNormalized)) {
    return MANDATORY_PQC_STACK.keyExchange.primary
  }
  if (/^ml[-_ ]?dsa[-_ ]?65$/.test(sourceNormalized) && !/certificate|cert|pki|sign|signature|jwt|saml|identity/.test(contextNormalized)) {
    return MANDATORY_PQC_STACK.signatures.primary
  }
  if (/aes256gcm/.test(compacted)) return MANDATORY_PQC_STACK.encryption.symmetric
  if (/hkdfsha3256/.test(compacted)) return MANDATORY_PQC_STACK.kdf.primary
  if (/sha3512/.test(compacted)) return 'SHA3-512'
  if (/sha3256/.test(compacted)) return 'SHA3-256'

  if (/certificate|cert|pki|sign|signature|ecdsa|dsa\b|jwt|saml|identity|mldsa|dilithium|ed25519/.test(normalized)) {
    return MANDATORY_PQC_STACK.signatures.hybrid
  }

  if (/database|storage|vault|secret|data at rest|encryption|encrypt|cipher|gcm|aes|key vault|kms/.test(normalized)) {
    return MANDATORY_PQC_STACK.encryption.envelope
  }

  if (/kdf|key derivation|derive/.test(normalized)) return MANDATORY_PQC_STACK.kdf.primary
  if (/hash|integrity|sha-?1|sha-?2|sha-?256|sha-?384|sha-?512|md5/.test(normalized)) return 'SHA3-256'

  if (/tls|ssl|https|web|api|gateway|vpn|ssh|handshake|protocol|key exchange|rsa|ecdh|diffie|dh\b|kem|kyber|ml-kem|mlkem/.test(normalized)) {
    return MANDATORY_PQC_STACK.tls.keyExchange
  }

  return MANDATORY_PQC_STACK.tls.keyExchange
}

export function mandatoryPqcStackMetadata(sourceAlgorithm?: unknown, context = '') {
  const targetAlgorithm = mandatoryPqcTargetForContext(sourceAlgorithm, context)
  return {
    version: MANDATORY_PQC_STACK.version,
    targetAlgorithm,
    requiredLibraries: MANDATORY_PQC_STACK.libraries,
    referenceUrls: MANDATORY_PQC_STACK.referenceUrls,
    integration: MANDATORY_PQC_STACK.integration,
    keyExchange: MANDATORY_PQC_STACK.keyExchange,
    tls: MANDATORY_PQC_STACK.tls,
    signatures: MANDATORY_PQC_STACK.signatures,
    encryption: MANDATORY_PQC_STACK.encryption,
    kdf: MANDATORY_PQC_STACK.kdf,
    hashes: MANDATORY_PQC_STACK.hashes,
    highSecurityProfile: MANDATORY_PQC_STACK.highSecurityProfile,
    requiredCapabilities: MANDATORY_PQC_REQUIRED_CAPABILITIES,
    validationSignals: MANDATORY_PQC_STACK.validationSignals,
  }
}
