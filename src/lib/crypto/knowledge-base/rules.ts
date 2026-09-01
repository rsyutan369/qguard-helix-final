/**
 * QGuard Helix Rule Engine (§44, §45, §75, §86).
 *
 * A rule is the reviewable unit of scanner behaviour. Each carries the eleven
 * fields §44 requires, and — critically — a VERSION, so a finding can be traced
 * to the exact rule that produced it (§86) and a change in results can be
 * attributed to a rule change rather than to the estate changing.
 *
 * `falsePositiveConditions` is not documentation. It is the list a reviewer
 * checks before acting on a finding, and several of the entries here exist
 * because this codebase has shipped that exact false positive before:
 *
 *   • `ssl` matching inside "OpenSSL"
 *   • `des` matching inside "described"
 *   • a bare `RSA` in a migration TODO comment reported as Critical
 *   • the classical half of X25519MLKEM768 reported as a standalone exposure
 *
 * §75: standards mappings are only present where the relationship is real. A
 * rule with no legitimate citation carries a `QGUARD_RULE` reference instead,
 * which the UI renders as this platform's judgement rather than an obligation.
 */

import type { CryptoRole, RequirementType, StandardReference } from './types';
import { qguardRule, standardsFor } from './standards';

export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RuleCategory =
  | 'crypto-usage'
  | 'weak-algorithm'
  | 'key-size'
  | 'tls-configuration'
  | 'certificate'
  | 'pki'
  | 'dependency'
  | 'library'
  | 'secret'
  | 'randomness'
  | 'kdf-parameters'
  | 'ssh'
  | 'pqc-adoption'
  | 'crypto-agility';

export interface ScannerRule {
  /** QGH-<DOMAIN>-<TOPIC>-<NNN>. Stable for the life of the rule. */
  ruleId: string;
  /** Semantic. Bump minor for a detection change, major for a meaning change. */
  ruleVersion: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: RuleSeverity;
  /**
   * The evidence this rule REQUIRES before it may fire at its stated severity.
   * A detector that cannot supply it must demote the finding.
   */
  evidenceRequirements: string[];
  /** How the rule detects. Drives the §47 layer attribution. */
  detectionLayers: Array<'lexical' | 'ast' | 'api' | 'configuration' | 'dependency' | 'data-flow' | 'runtime' | 'cross-scanner'>;
  /** Quantum classification the rule asserts, when it asserts one. */
  quantumClassification?: string;
  remediation: string;
  standards: StandardReference[];
  /** Conditions under which this rule is WRONG. Checked before acting. */
  falsePositiveConditions: string[];
  /** Cryptographic role the rule establishes, when it does. */
  establishesRole?: CryptoRole;
  references?: string[];
}

function rule(input: Omit<ScannerRule, 'standards'> & { standardIds?: string[]; qguardTopic?: string }): ScannerRule {
  const { standardIds, qguardTopic, ...rest } = input;
  const standards = standardIds?.length ? standardsFor(standardIds) : [];
  if (standards.length === 0 && qguardTopic) standards.push(qguardRule(qguardTopic));
  return { ...rest, standards };
}

/* ═══════════════════════════════════════════════════════════════ the rules ══ */

export const SCANNER_RULES: ScannerRule[] = [
  /* ── RSA (§9) ─────────────────────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-CRYPTO-RSA-001',
    ruleVersion: '3.0.0',
    name: 'RSA in a quantum-relevant role',
    description:
      'RSA used for signatures, key transport, certificates or authentication. RSA at 2048 bits or more is classically ACCEPTABLE and is not currently breakable; it is quantum-vulnerable, which makes it a migration candidate.',
    category: 'crypto-usage',
    severity: 'high',
    evidenceRequirements: [
      'An API call, configuration directive, parsed key or certificate that establishes RSA is used — not merely named.',
      'A cryptographic role, so the migration target can be role-appropriate.',
    ],
    detectionLayers: ['api', 'ast', 'configuration', 'lexical'],
    quantumClassification: 'QUANTUM_VULNERABLE',
    remediation:
      'Plan migration to ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures, deployed hybrid with the existing algorithm during transition.',
    standardIds: ['SP-800-56B', 'FIPS-186-5', 'FIPS-203', 'FIPS-204'],
    falsePositiveConditions: [
      'The match is a variable or type named RSA with no cryptographic call.',
      'The match is in a comment, README or migration TODO describing intent.',
      'The match is a test fixture or documented example key.',
      'The line disables RSA rather than using it (an allowlist exclusion).',
    ],
  }),
  rule({
    ruleId: 'QGH-CRYPTO-RSA-002',
    ruleVersion: '3.0.0',
    name: 'RSA key below the 2048-bit minimum',
    description:
      'An RSA key of 1024 bits or fewer. This is a CLASSICAL weakness — such keys are considered factorable with sustained effort — and is independent of any quantum consideration.',
    category: 'key-size',
    severity: 'critical',
    evidenceRequirements: ['A parsed key, certificate or configuration directive stating the modulus size.'],
    detectionLayers: ['configuration', 'api', 'ast'],
    quantumClassification: 'QUANTUM_VULNERABLE',
    remediation: 'Re-key to 3072-bit RSA as an interim minimum, and plan the post-quantum migration in the same change.',
    standardIds: ['SP-800-131A', 'CABF-BR', 'SP-800-57'],
    falsePositiveConditions: [
      'The number was parsed from a filename or version string rather than a key parameter.',
      'The key is a documented test vector.',
    ],
  }),
  rule({
    ruleId: 'QGH-CRYPTO-RSA-003',
    ruleVersion: '3.0.0',
    name: 'RSA PKCS#1 v1.5 encryption padding',
    description:
      'RSA encryption using PKCS#1 v1.5 padding, which is vulnerable to Bleichenbacher-style padding-oracle attacks. The SIGNATURE variant of PKCS#1 v1.5 is a separate construction and is still permitted.',
    category: 'weak-algorithm',
    severity: 'high',
    evidenceRequirements: ['A call or transformation string that names PKCS1 padding in an ENCRYPTION operation.'],
    detectionLayers: ['api', 'ast'],
    remediation: 'Use RSA-OAEP for encryption. For new designs prefer a KEM construction, which is also the shape ML-KEM takes.',
    standardIds: ['SP-800-56B'],
    falsePositiveConditions: [
      'The transformation is a SIGNATURE (`SHA256withRSA`), where PKCS#1 v1.5 remains approved.',
    ],
    establishesRole: 'key-transport',
  }),

  /* ── ECC (§10) ────────────────────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-CRYPTO-ECC-001',
    ruleVersion: '3.0.0',
    name: 'Elliptic-curve cryptography in a quantum-relevant role',
    description:
      'ECDSA, ECDH, Ed25519 or X25519 used for signatures, key agreement or authentication. All are broken by Shor\'s algorithm regardless of curve; the curve determines the CLASSICAL strength only.',
    category: 'crypto-usage',
    severity: 'high',
    evidenceRequirements: ['An API call, parsed key, negotiated group or configuration directive.', 'The named curve, where the artefact carries one.'],
    detectionLayers: ['api', 'ast', 'configuration', 'runtime'],
    quantumClassification: 'QUANTUM_VULNERABLE',
    remediation: 'For key agreement, adopt ML-KEM (FIPS 203) in a hybrid group. For signatures, adopt ML-DSA (FIPS 204).',
    standardIds: ['SP-800-56A', 'FIPS-186-5', 'FIPS-203', 'FIPS-204'],
    falsePositiveConditions: [
      'The curve is part of a hybrid construction with a post-quantum primitive, in which case the exposure is HYBRID and not vulnerable.',
      'The match is a curve name in documentation.',
    ],
  }),
  rule({
    ruleId: 'QGH-CRYPTO-ECC-002',
    ruleVersion: '3.0.0',
    name: 'Elliptic curve below the 128-bit classical floor',
    description: 'A named curve providing under 128 bits of classical security — P-192, P-224 or a small binary-field curve.',
    category: 'key-size',
    severity: 'high',
    evidenceRequirements: ['A named curve identifier from a parsed key, certificate or configuration.'],
    detectionLayers: ['configuration', 'api'],
    remediation: 'Move to P-256 or stronger; prefer P-384 where CNSA alignment is required.',
    standardIds: ['SP-800-57', 'FIPS-186-5'],
    falsePositiveConditions: ['The curve appears in a list of DISABLED curves rather than enabled ones.'],
  }),
  rule({
    ruleId: 'QGH-CRYPTO-ECC-003',
    ruleVersion: '1.0.0',
    name: 'Curve used in a role it cannot serve',
    description:
      'The surrounding context describes a role the named curve cannot perform — X25519 cannot sign, Ed25519 cannot perform key agreement. Either the context or the curve identification is wrong.',
    category: 'crypto-usage',
    severity: 'info',
    evidenceRequirements: ['A named curve AND a role established from another source that contradicts it.'],
    detectionLayers: ['cross-scanner'],
    remediation: 'Verify which key the surrounding code actually uses; the two Curve25519 variants are frequently conflated.',
    qguardTopic: 'curve role consistency',
    falsePositiveConditions: [
      'The file legitimately handles both X25519 and Ed25519 keys, and the context matched the other one.',
    ],
  }),

  /* ── Diffie-Hellman (§11) ─────────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-CRYPTO-DH-001',
    ruleVersion: '2.0.0',
    name: 'Finite-field Diffie-Hellman below 2048 bits',
    description:
      'A DH group smaller than 2048 bits. Small and widely-shared groups are within reach of precomputation attacks (Logjam), which is a classical weakness in addition to the quantum one.',
    category: 'key-size',
    severity: 'high',
    evidenceRequirements: ['A dhparam file reference, a configured group size, or a negotiated group observed in a handshake.'],
    detectionLayers: ['configuration', 'runtime'],
    quantumClassification: 'QUANTUM_VULNERABLE',
    remediation: 'Use a named FFDHE group of 3072 bits or more, or prefer ECDHE with a named curve.',
    standardIds: ['SP-800-56A', 'RFC-9325'],
    falsePositiveConditions: ['The size was parsed from a filename that does not reflect the actual parameter.'],
    establishesRole: 'key-establishment',
  }),

  /* ── TLS (§18-§21) ────────────────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-TLS-001',
    ruleVersion: '3.0.0',
    name: 'Deprecated TLS protocol version offered',
    description:
      'TLS 1.0 or 1.1 is offered. RFC 8996 deprecates both. Such an endpoint also cannot negotiate a hybrid post-quantum key-agreement group, so it has no path to post-quantum transport without a protocol upgrade.',
    category: 'tls-configuration',
    severity: 'high',
    evidenceRequirements: ['A protocol directive in configuration, or a completed handshake at that version.'],
    detectionLayers: ['configuration', 'runtime'],
    remediation: 'Restrict the protocol list to TLS 1.2 and TLS 1.3.',
    standardIds: ['RFC-8996', 'SP-800-52', 'RFC-9325'],
    falsePositiveConditions: [
      'The directive is commented out.',
      'The version appears in a DISABLE or MinVersion floor rather than an offer list.',
    ],
    establishesRole: 'transport-security',
  }),
  rule({
    ruleId: 'QGH-TLS-002',
    ruleVersion: '3.0.0',
    name: 'Broken or anonymous cipher suite permitted',
    description: 'The cipher list permits RC4, NULL encryption, anonymous key exchange, EXPORT grade or DES.',
    category: 'tls-configuration',
    severity: 'critical',
    evidenceRequirements: ['A cipher-list directive, or a suite negotiated in a real handshake.'],
    detectionLayers: ['configuration', 'runtime'],
    remediation: 'Restrict the cipher list to modern AEAD suites and remove eNULL, aNULL, EXPORT, RC4 and DES.',
    standardIds: ['RFC-7465', 'RFC-9325', 'SP-800-52'],
    falsePositiveConditions: ['The suite appears with a `!` exclusion prefix in an OpenSSL cipher string, which DISABLES it.'],
    establishesRole: 'transport-security',
  }),
  rule({
    ruleId: 'QGH-TLS-003',
    ruleVersion: '2.0.0',
    name: '3DES cipher suite permitted',
    description:
      "3DES has a 64-bit block, which makes long-lived connections vulnerable to Sweet32 birthday attacks. NIST disallowed it after 2023. This is a classical weakness, not a quantum one.",
    category: 'tls-configuration',
    severity: 'medium',
    evidenceRequirements: ['A cipher-list directive or a negotiated suite.'],
    detectionLayers: ['configuration', 'runtime'],
    remediation: 'Remove 3DES and DES-CBC3 suites.',
    standardIds: ['SP-800-131A', 'RFC-9325'],
    falsePositiveConditions: ['The suite is listed with an exclusion prefix.'],
  }),
  rule({
    ruleId: 'QGH-TLS-004',
    ruleVersion: '1.0.0',
    name: 'Hybrid post-quantum key agreement configured',
    description:
      'A hybrid post-quantum group such as X25519MLKEM768 is configured or was negotiated. This is completed migration work and is recorded as evidence of readiness, not as an exposure.',
    category: 'pqc-adoption',
    severity: 'info',
    evidenceRequirements: ['A named group in configuration, or a group negotiated in a real handshake.'],
    detectionLayers: ['configuration', 'runtime'],
    quantumClassification: 'HYBRID',
    remediation: 'Keep the classical half in place until the ecosystem completes its transition.',
    standardIds: ['FIPS-203'],
    falsePositiveConditions: ['The group is listed but the server did not actually negotiate it — configuration is intent, negotiation is fact.'],
    establishesRole: 'key-establishment',
  }),
  rule({
    ruleId: 'QGH-TLS-005',
    ruleVersion: '1.0.0',
    name: 'TLS 1.3 unavailable',
    description:
      'The endpoint or configuration does not offer TLS 1.3. TLS 1.3 is the prerequisite for hybrid post-quantum key agreement, so its absence is a migration blocker rather than a present-tense weakness.',
    category: 'crypto-agility',
    severity: 'low',
    evidenceRequirements: ['A protocol list that omits TLS 1.3, or a handshake that could not negotiate it.'],
    detectionLayers: ['configuration', 'runtime'],
    remediation: 'Enable TLS 1.3 so a hybrid group can be adopted without a further protocol change.',
    standardIds: ['SP-800-52'],
    falsePositiveConditions: ['The stack in use does not support TLS 1.3 at all, which is a platform constraint rather than a configuration error.'],
  }),

  /* ── Certificates (§22-§24) ───────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-CERT-001',
    ruleVersion: '3.0.0',
    name: 'Certificate signed with SHA-1',
    description:
      'The certificate signature algorithm uses SHA-1, whose collisions are practical. This is a CLASSICAL break of the signature, independent of quantum risk.',
    category: 'certificate',
    severity: 'critical',
    evidenceRequirements: ['A parsed certificate whose signatureAlgorithm field names SHA-1.'],
    detectionLayers: ['ast', 'runtime'],
    remediation: 'Re-issue with SHA-256 or stronger. Publicly-trusted CAs have been prohibited from issuing SHA-1 certificates since 2016.',
    standardIds: ['CABF-BR', 'SP-800-131A-SHA1'],
    falsePositiveConditions: [
      'The SHA-1 appears in the subject key identifier or thumbprint rather than the signature algorithm — those are identifiers, not signatures.',
    ],
    establishesRole: 'certificate-signature',
  }),
  rule({
    ruleId: 'QGH-CERT-002',
    ruleVersion: '3.0.0',
    name: 'Certificate public key is quantum-vulnerable',
    description:
      'The certificate\'s SubjectPublicKeyInfo names RSA, ECDSA, DSA or EdDSA. Recorded SEPARATELY from the signature algorithm, which is a different field and frequently a different algorithm.',
    category: 'certificate',
    severity: 'high',
    evidenceRequirements: ['A parsed SubjectPublicKeyInfo with its algorithm OID and key size or curve.'],
    detectionLayers: ['ast', 'runtime'],
    quantumClassification: 'QUANTUM_VULNERABLE',
    remediation: 'Re-issue with ML-DSA (FIPS 204) once the issuing CA supports it. Automated issuance makes this a configuration change rather than a project.',
    standardIds: ['FIPS-204', 'SP-800-57'],
    falsePositiveConditions: ['The certificate is a test or self-signed development artefact rather than a deployed one.'],
    establishesRole: 'certificate-public-key',
  }),
  rule({
    ruleId: 'QGH-CERT-003',
    ruleVersion: '2.0.0',
    name: 'Certificate validation disabled',
    description:
      'Certificate verification is explicitly turned off, which removes authentication from TLS and makes the channel interceptable by anyone on the network path.',
    category: 'certificate',
    severity: 'critical',
    evidenceRequirements: ['A configuration key or API flag set to a disabling value.'],
    detectionLayers: ['configuration', 'api'],
    remediation: 'Re-enable verification and install the correct trust anchor rather than bypassing the check.',
    standardIds: ['RFC-9325'],
    falsePositiveConditions: [
      'The flag is inside a test harness that deliberately targets a self-signed fixture.',
      'The line sets the flag to a SAFE value and the match read the key rather than the value.',
    ],
  }),
  rule({
    ruleId: 'QGH-CERT-004',
    ruleVersion: '1.0.0',
    name: 'Certificate expired or not yet valid',
    description: 'The certificate is outside its validity window.',
    category: 'certificate',
    severity: 'high',
    evidenceRequirements: ['Parsed notBefore and notAfter fields compared against the scan time.'],
    detectionLayers: ['ast', 'runtime'],
    remediation: 'Renew the certificate and review the renewal automation that allowed it to lapse.',
    standardIds: ['CABF-BR'],
    falsePositiveConditions: ['The scanning host clock is wrong.', 'The certificate is an archived artefact rather than a served one.'],
  }),

  /* ── Hashes (§14) ─────────────────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-HASH-001',
    ruleVersion: '3.0.0',
    name: 'Collision-broken hash in a security role',
    description:
      'MD5 or SHA-1 used where collision resistance is required — a signature, a certificate, an integrity check or a content address. Their use as a NON-SECURITY identifier is not a finding.',
    category: 'weak-algorithm',
    severity: 'high',
    evidenceRequirements: ['A hashing call or configuration directive.', 'Context establishing a security role.'],
    detectionLayers: ['api', 'ast', 'configuration'],
    remediation: 'Replace with SHA-256 or SHA3-256.',
    standardIds: ['SP-800-131A-SHA1', 'RFC-6151'],
    falsePositiveConditions: [
      'The hash is a cache key, an ETag, a Git object id or a non-security fingerprint.',
      'It is HMAC-SHA1, which does not depend on collision resistance and remains a secure MAC.',
    ],
  }),

  /* ── Randomness (§17) ─────────────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-RAND-001',
    ruleVersion: '2.0.0',
    name: 'Non-cryptographic PRNG in a security context',
    description:
      'A predictable random source is used near key, token, nonce, IV or salt generation. Reported ONLY when the security context co-occurs — a non-CSPRNG in a UI animation is not a finding.',
    category: 'randomness',
    severity: 'high',
    evidenceRequirements: ['A non-CSPRNG call.', 'A security-relevant identifier within the same statement or a few lines.'],
    detectionLayers: ['api', 'data-flow'],
    remediation: "Use the platform CSPRNG: crypto.randomBytes, crypto.getRandomValues, secrets, SecureRandom or crypto/rand.",
    standardIds: ['SP-800-90A'],
    falsePositiveConditions: [
      'The random value is used for jitter, sampling, animation, shuffling display order or test data.',
      'The identifier matched is a coincidence — a variable named `key` in a map iteration, for instance.',
    ],
  }),

  /* ── KDF parameters (§16) ─────────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-KDF-001',
    ruleVersion: '2.0.0',
    name: 'Password-hashing parameters below current guidance',
    description:
      'A password KDF configured with a work factor below the level currently recommended. The thresholds are this platform\'s applied reading of OWASP guidance; NIST SP 800-63B requires salting and a suitable KDF but does not state a specific iteration count.',
    category: 'kdf-parameters',
    severity: 'medium',
    evidenceRequirements: ['A KDF call with a literal parameter value.'],
    detectionLayers: ['api', 'ast'],
    remediation: 'Raise the work factor to at least the recommended floor and re-hash on next successful login.',
    standardIds: ['SP-800-63B'],
    falsePositiveConditions: [
      'The literal is a test fixture deliberately using a low cost for speed.',
      'The parameter is read from configuration at runtime and the literal is only a default.',
    ],
    establishesRole: 'password-derivation',
  }),

  /* ── SSH (§31) ────────────────────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-SSH-001',
    ruleVersion: '2.0.0',
    name: 'Weak SSH key exchange or cipher permitted',
    description: 'The SSH configuration permits a SHA-1-based key exchange, a 1024-bit DH group, or a legacy cipher such as 3DES-CBC or arcfour.',
    category: 'ssh',
    severity: 'high',
    evidenceRequirements: ['A KexAlgorithms, Ciphers or MACs directive in an sshd_config or ssh_config.'],
    detectionLayers: ['configuration'],
    remediation: 'Restrict KexAlgorithms to curve25519-sha256 and diffie-hellman-group16-sha512 or better; restrict Ciphers to ChaCha20-Poly1305 and the AES-GCM suites.',
    standardIds: ['SP-800-131A'],
    falsePositiveConditions: ['The directive is commented out.', 'The algorithm appears in a removal list prefixed with `-`.'],
    establishesRole: 'transport-security',
  }),
  rule({
    ruleId: 'QGH-SSH-002',
    ruleVersion: '1.0.0',
    name: 'SSH host or user key is quantum-vulnerable',
    description: 'An SSH key using RSA, DSA, ECDSA or Ed25519. All are broken by Shor\'s algorithm; DSA is additionally withdrawn.',
    category: 'crypto-usage',
    severity: 'medium',
    evidenceRequirements: ['A parsed OpenSSH public key blob with its type and, for RSA, its modulus size.'],
    detectionLayers: ['ast'],
    quantumClassification: 'QUANTUM_VULNERABLE',
    remediation: 'Track OpenSSH for post-quantum host and user key support. OpenSSH already offers hybrid KEY EXCHANGE (sntrup761x25519), which addresses the harvest-now risk to session traffic ahead of the key material itself.',
    standardIds: ['FIPS-204'],
    falsePositiveConditions: ['The key is a documented example in a README.'],
    establishesRole: 'authentication',
  }),

  /* ── Dependencies and libraries (§25, §26) ────────────────────────────── */
  rule({
    ruleId: 'QGH-DEP-001',
    ruleVersion: '2.0.0',
    name: 'Dependency provides quantum-vulnerable cryptography',
    description:
      'A declared dependency is known to provide RSA, ECC or DH. §26: this establishes AVAILABILITY, not use. The finding is reported as inferred unless a call site corroborates it.',
    category: 'dependency',
    severity: 'medium',
    evidenceRequirements: ['A manifest or lockfile declaration naming the package and version.'],
    detectionLayers: ['dependency'],
    quantumClassification: 'QUANTUM_VULNERABLE',
    remediation: 'Confirm which algorithms this application actually exercises before scheduling migration work for them.',
    standardIds: ['FIPS-203', 'FIPS-204'],
    falsePositiveConditions: [
      'The dependency is development-only and does not ship.',
      'The dependency is transitive and unreachable from application code.',
      'The library is present but the crypto capability is never imported.',
    ],
  }),
  rule({
    ruleId: 'QGH-LIB-001',
    ruleVersion: '1.0.0',
    name: 'Post-quantum capable library present',
    description:
      'A library that ships standardised post-quantum primitives is available. Recorded as crypto-agility evidence, not as an exposure.',
    category: 'pqc-adoption',
    severity: 'info',
    evidenceRequirements: ['A manifest declaration or an install step naming the library.'],
    detectionLayers: ['dependency'],
    quantumClassification: 'PQC_STANDARDIZED',
    remediation: 'Confirm the version actually exposes the standardised parameter sets rather than an earlier NIST round submission.',
    qguardTopic: 'post-quantum capability inventory',
    falsePositiveConditions: [
      'The library version predates standardisation, so the algorithm names match but the parameter sets differ from FIPS 203/204/205.',
    ],
  }),

  /* ── Crypto agility (§79) ─────────────────────────────────────────────── */
  rule({
    ruleId: 'QGH-AGILITY-001',
    ruleVersion: '1.0.0',
    name: 'Hard-coded algorithm selection',
    description:
      'An algorithm, key size or cipher suite is hard-coded at a call site rather than read from configuration. This is a crypto-agility blocker: every such site must be edited and redeployed to change algorithm.',
    category: 'crypto-agility',
    severity: 'low',
    evidenceRequirements: ['A call site with a literal algorithm argument.'],
    detectionLayers: ['api', 'ast'],
    remediation: 'Introduce a cryptographic policy layer so the algorithm is selected from configuration, which is what makes a future migration a config change rather than a code change.',
    qguardTopic: 'crypto agility — hard-coded algorithm selection',
    falsePositiveConditions: [
      'The literal is inside a policy module that IS the abstraction layer.',
      'The algorithm is fixed by an external protocol and cannot be negotiated.',
    ],
  }),
];

/* ─────────────────────────────────────────────────────────────── accessors ── */

const BY_ID = new Map(SCANNER_RULES.map((entry) => [entry.ruleId, entry]));

export function ruleById(ruleId: string): ScannerRule | null {
  return BY_ID.get(ruleId) ?? null;
}

export function rulesByCategory(category: RuleCategory): ScannerRule[] {
  return SCANNER_RULES.filter((entry) => entry.category === category);
}

/** The rule-set version, for the reproducibility stamp (§87). */
export const RULE_SET_VERSION = '3.0.0';

/**
 * A finding's rule provenance. Attached to every finding a rule produces so a
 * result can be traced back to the exact logic that generated it (§86).
 */
export interface RuleProvenance {
  ruleId: string;
  ruleVersion: string;
  ruleSetVersion: string;
  /** The requirement types cited, so the UI can label the obligation (§76). */
  requirementTypes: RequirementType[];
}

export function provenanceFor(ruleId: string): RuleProvenance | null {
  const entry = BY_ID.get(ruleId);
  if (!entry) return null;
  return {
    ruleId: entry.ruleId,
    ruleVersion: entry.ruleVersion,
    ruleSetVersion: RULE_SET_VERSION,
    requirementTypes: [...new Set(entry.standards.map((standard) => standard.requirementType))],
  };
}

/** Capability disclosure: every rule the scanner can fire. */
export function ruleCatalogue(): Array<{ ruleId: string; name: string; category: RuleCategory; severity: RuleSeverity; version: string }> {
  return SCANNER_RULES.map((entry) => ({
    ruleId: entry.ruleId,
    name: entry.name,
    category: entry.category,
    severity: entry.severity,
    version: entry.ruleVersion,
  }));
}
