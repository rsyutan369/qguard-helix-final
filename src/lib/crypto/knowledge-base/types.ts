/**
 * QGuard Helix Crypto Knowledge Base™ — the canonical model (§7, §36, §43, §45).
 *
 * §7: "Do not duplicate algorithm definitions across individual scanners.
 *      Create a canonical knowledge model."
 *
 * Before this module, algorithm facts lived in FOUR places — `suite-anatomy.ts`,
 * `exposure/algorithms.ts`, `crypto-patterns.ts` and `oid-database.ts` — each
 * with its own quantum vocabulary and its own idea of what "RSA" means. That is
 * how the same key ends up classified three different ways on three pages.
 * Everything downstream now reads from here.
 *
 * THE TWO DISTINCTIONS THIS MODEL EXISTS TO PRESERVE
 *
 *  §9  Classical security and quantum security are ORTHOGONAL. RSA-2048 is
 *      classically acceptable and quantum-vulnerable. SHA-1 is classically
 *      broken and quantum-irrelevant. Collapsing them into one "is it bad"
 *      field is the single most common error in a PQC scanner, and it is what
 *      produces "RSA-2048 is broken" — which is false and destroys trust.
 *
 *  §36 Seven quantum states, not two. `QUANTUM_VULNERABLE` is a migration
 *      classification, not a statement that something is currently breakable.
 *
 * Isomorphic: no Node, no DOM. Runs in the browser worker and on the server.
 */

/* ═══════════════════════════════════════════════════════ quantum model (§36) ═ */

/**
 * §36: "Do NOT use only VULNERABLE / SAFE."
 *
 * `QUANTUM_VULNERABLE` means: broken by a cryptographically relevant quantum
 * computer, therefore a migration candidate. It does NOT mean broken today.
 * §37 is explicit that "Quantum Vulnerable" must never be rendered as
 * "Currently Cryptographically Broken".
 */
export type QuantumStatus =
  | 'QUANTUM_VULNERABLE'
  | 'QUANTUM_RESISTANT'
  | 'PQC_STANDARDIZED'
  | 'HYBRID'
  | 'CLASSICAL_ONLY'
  | 'UNKNOWN'
  | 'NOT_APPLICABLE';

export const QUANTUM_STATUS_LABEL: Record<QuantumStatus, string> = {
  QUANTUM_VULNERABLE: 'Quantum Vulnerable',
  QUANTUM_RESISTANT: 'Quantum Resistant',
  PQC_STANDARDIZED: 'Post-Quantum (standardised)',
  HYBRID: 'Hybrid',
  CLASSICAL_ONLY: 'Classical Only',
  UNKNOWN: 'Unknown',
  NOT_APPLICABLE: 'Not Applicable',
};

/** One-line explanation shown wherever the status is. Never a bare label. */
export const QUANTUM_STATUS_MEANING: Record<QuantumStatus, string> = {
  QUANTUM_VULNERABLE:
    'Broken by a cryptographically relevant quantum computer, so it is a migration candidate. This is not a statement that the algorithm is breakable today.',
  QUANTUM_RESISTANT:
    'Not broken by any known quantum algorithm at adequate parameter sizes. Grover-style search halves the effective strength of symmetric primitives, which adequate key sizes already absorb.',
  PQC_STANDARDIZED: 'A NIST-standardised post-quantum algorithm.',
  HYBRID: 'A classical primitive deployed alongside a post-quantum one, so the construction holds if either half does.',
  CLASSICAL_ONLY: 'A classical primitive whose quantum relevance depends on a cryptographic role that has not been established.',
  UNKNOWN: 'Not enough evidence to publish a quantum verdict.',
  NOT_APPLICABLE: 'Not a cryptographic primitive, so no quantum verdict applies.',
};

/* ═══════════════════════════════════════════════════════ classical model (§9) ═ */

/**
 * Classical security, kept strictly separate from quantum security.
 *
 * §9: "Do not report RSA-2048 as merely 'weak' because it is not currently
 *      considered classically broken."
 */
export type ClassicalSecurity =
  | 'STRONG'          // meets or exceeds current guidance
  | 'ACCEPTABLE'      // adequate now, context-dependent (RSA-2048, AES-128)
  | 'LEGACY'          // discouraged, still in transition (SHA-1 outside signatures, 3DES)
  | 'BROKEN'          // practical attacks exist (MD5, RC4, DES, SHA-1 signatures)
  | 'UNKNOWN';

export const CLASSICAL_SECURITY_LABEL: Record<ClassicalSecurity, string> = {
  STRONG: 'Strong',
  ACCEPTABLE: 'Acceptable',
  LEGACY: 'Legacy',
  BROKEN: 'Broken',
  UNKNOWN: 'Unknown',
};

/* ══════════════════════════════════════════════════════════ primitive model ══ */

export type PrimitiveType =
  | 'public-key-encryption'
  | 'key-establishment'
  | 'digital-signature'
  | 'block-cipher'
  | 'stream-cipher'
  | 'aead'
  | 'hash'
  | 'mac'
  | 'kdf'
  | 'password-hash'
  | 'rng'
  | 'protocol'
  | 'certificate'
  | 'unknown';

/**
 * §12: "Do not confuse encryption with key establishment. They are separate
 *       cryptographic roles."
 */
export type CryptoRole =
  | 'key-establishment'
  | 'key-transport'
  | 'digital-signature'
  | 'encryption'
  | 'authenticated-encryption'
  | 'authentication'
  | 'integrity'
  | 'hashing'
  | 'password-derivation'
  | 'key-derivation'
  | 'transport-security'
  | 'certificate-public-key'
  | 'certificate-signature'
  | 'code-signing'
  | 'token-signing'
  | 'storage-encryption'
  | 'database-encryption'
  | 'key-management'
  | 'random-generation'
  | 'unknown';

export const ROLE_LABEL: Record<CryptoRole, string> = {
  'key-establishment': 'Key establishment',
  'key-transport': 'Key transport',
  'digital-signature': 'Digital signature',
  encryption: 'Encryption',
  'authenticated-encryption': 'Authenticated encryption',
  authentication: 'Authentication',
  integrity: 'Integrity',
  hashing: 'Hashing',
  'password-derivation': 'Password derivation',
  'key-derivation': 'Key derivation',
  'transport-security': 'Transport security',
  'certificate-public-key': 'Certificate public key',
  'certificate-signature': 'Certificate signature',
  'code-signing': 'Code signing',
  'token-signing': 'Token signing',
  'storage-encryption': 'Storage encryption',
  'database-encryption': 'Database encryption',
  'key-management': 'Key management',
  'random-generation': 'Random generation',
  unknown: 'Unidentified role',
};

/**
 * Roles for which a Shor-broken primitive is a real quantum exposure.
 *
 * §37 lists the quantum-vulnerable families; this list decides whether a given
 * USE of one counts toward the readiness ratio. An RSA key that only ever
 * verifies a local checksum is still RSA, but it is not the migration priority
 * that an Internet-facing TLS certificate is.
 */
export const QUANTUM_RELEVANT_ROLES: readonly CryptoRole[] = [
  'key-establishment',
  'key-transport',
  'digital-signature',
  'authentication',
  'certificate-public-key',
  'certificate-signature',
  'code-signing',
  'token-signing',
  'transport-security',
  'key-management',
  'unknown',
];

/* ═══════════════════════════════════════════════════════════ standards (§43) ═ */

export type StandardAuthority = 'NIST' | 'NSA' | 'CISA' | 'OMB' | 'IETF' | 'CNSS' | 'ISO' | 'CA/Browser Forum' | 'QGuard';

/**
 * §76: "Clearly distinguish MANDATORY / RECOMMENDED / DRAFT / INFORMATIONAL /
 *       VENDOR GUIDANCE / INTERNAL QGUARD RULE."
 *
 * This type is what stops a NIST recommendation being rendered as a federal
 * legal requirement — a specific misrepresentation §76 names.
 */
export type RequirementType =
  | 'REQUIRED'        // binding on a defined population (e.g. NSS under CNSA 2.0)
  | 'RECOMMENDED'     // authoritative guidance, not binding
  | 'DRAFT'           // published but not final
  | 'INFORMATIONAL'
  | 'INDUSTRY_PRACTICE'
  | 'QGUARD_RULE';    // this platform's own opinion, labelled as such

export type StandardStatus = 'FINAL' | 'DRAFT' | 'SUPERSEDED' | 'WITHDRAWN';

export interface StandardReference {
  standardId: string;
  authority: StandardAuthority;
  publication: string;
  version?: string;
  status: StandardStatus;
  requirementType: RequirementType;
  /** Who the requirement actually binds. Never "everyone" unless it is. */
  applicability: string;
  section?: string;
  sourceUrl?: string;
  effectiveDate?: string;
}

/* ═══════════════════════════════════════════════════════════ the algorithm ══ */

/** §7's canonical algorithm record. */
export interface AlgorithmDefinition {
  algorithmId: string;
  canonicalName: string;
  /** Lower-cased. Matched on boundaries, never as a bare substring. */
  aliases: string[];
  family: string;
  primitiveType: PrimitiveType;
  /** Roles this primitive can legitimately serve. */
  cryptographicRoles: CryptoRole[];
  /** Security against classical cryptanalysis, at the default parameters. */
  classicalSecurity: ClassicalSecurity;
  /** Quantum posture, before role is considered. */
  quantumStatus: QuantumStatus;
  /** True when Shor's algorithm breaks it outright. */
  shorBroken: boolean;
  /** True when Grover-style search halves the effective strength. */
  groverAffected: boolean;
  standardStatus?: string;
  /** Deprecated by an authority, with the reference in `standards`. */
  deprecated: boolean;
  /** Disallowed by an authority for new use. */
  disallowed: boolean;
  minimumKeySize?: number;
  recommendedKeySize?: number;
  /** Sizes that are recognised but below the recommended floor. */
  weakKeySizes?: number[];
  supportedProtocols?: string[];
  knownLibraries?: string[];
  /** OIDs, TLS codepoints, JOSE `alg` values, SSH names. */
  knownIdentifiers?: string[];
  /** Role-keyed migration guidance. §80 forbids one target for every role. */
  migrationTargets?: Partial<Record<CryptoRole, string>>;
  standards?: StandardReference[];
  /** One sentence, published verbatim next to a verdict. */
  note?: string;
}

/* ══════════════════════════════════════════════════════════════ curves (§8) ══ */

/**
 * §8: "Do not assume every ECC curve has the same security properties."
 */
export interface CurveDefinition {
  curveId: string;
  canonicalName: string;
  aliases: string[];
  /** Field size in bits. */
  bits: number;
  /** Classical security strength in bits (roughly bits/2 for ECC). */
  classicalStrength: number;
  classicalSecurity: ClassicalSecurity;
  family: 'nist-prime' | 'nist-binary' | 'koblitz' | 'edwards' | 'montgomery' | 'brainpool' | 'other';
  oid?: string;
  tlsGroupId?: number;
  roles: CryptoRole[];
  note?: string;
  /** Deliberately-chosen-verifiably-random provenance, where it matters. */
  rigid?: boolean;
}

/* ════════════════════════════════════════════════════════════ libraries (§25) ═ */

export interface LibraryDefinition {
  libraryId: string;
  canonicalName: string;
  aliases: string[];
  ecosystems: string[];
  /** Algorithms the library provides. Availability, NOT usage — see §26. */
  providesAlgorithms: string[];
  /** True when the library ships post-quantum primitives. */
  pqcCapable: boolean;
  note?: string;
}

/* ══════════════════════════════════════════════════════════════ APIs (§29) ══ */

/**
 * An API-call idiom that identifies an algorithm AND its role.
 *
 * §29: "Map API → algorithm → role → evidence."
 *
 * This is the difference between lexical detection and semantic detection:
 * `crypto.createSign('RSA-SHA256')` proves RSA is used FOR A SIGNATURE, which
 * a bare match on the string "RSA" never does.
 */
export interface CryptoApiDefinition {
  apiId: string;
  /** Anchored to a call shape, not a bare name. */
  pattern: RegExp;
  language: string[];
  library?: string;
  /** The algorithm the call establishes, when the call alone determines it. */
  algorithm?: string;
  /** Read the algorithm out of this capture group instead, when it is an argument. */
  algorithmFromGroup?: number;
  role: CryptoRole;
  /** Key size, curve or parameter, when the call carries it. */
  parameterFromGroup?: number;
  /** Evidence strength this API match justifies on its own. */
  evidenceQuality: 'DIRECT' | 'STRONG' | 'CIRCUMSTANTIAL';
  note?: string;
}

/* ═════════════════════════════════════════════════════════ classification ═══ */

/**
 * The output of classifying one observation. Every field is separately
 * justified, and every uncertainty is representable.
 */
export interface CryptoClassification {
  /** Resolved algorithm, or null when nothing was recognised. */
  algorithm: AlgorithmDefinition | null;
  /** The name as written in the artefact, preserved for evidence. */
  observedAs: string;
  canonicalName: string;
  role: CryptoRole;
  /** How the role was decided. */
  roleBasis: 'api-semantics' | 'protocol-position' | 'textual-context' | 'family-default' | 'declared' | 'undetermined';
  keySize: number | null;
  curve: CurveDefinition | null;
  parameterSet: string | null;
  cipherMode: string | null;
  padding: string | null;
  hash: string | null;
  library: LibraryDefinition | null;
  protocol: string | null;

  classicalSecurity: ClassicalSecurity;
  /** Why the classical verdict is what it is. */
  classicalRationale: string;

  quantumStatus: QuantumStatus;
  /** Why the quantum verdict is what it is. Rendered verbatim. */
  quantumRationale: string;
  /** True when this component belongs in the readiness denominator. */
  quantumRelevant: boolean;
  /** Effective post-quantum strength in bits, for symmetric primitives. */
  effectiveQuantumStrength: number | null;

  /** Role-appropriate target, or undefined when the role is unknown (§80). */
  migrationTarget?: string;
  migrationPriority: 'P1' | 'P2' | 'P3' | 'P4' | null;

  standards: StandardReference[];
  /** Everything the classifier could NOT establish, named. */
  undetermined: string[];
}

/* ═══════════════════════════════════════════════════════════ evidence (§49) ═ */

/**
 * §49's evidence taxonomy. This is the "how do we know" axis, and it is
 * SEPARATE from both severity and confidence (§45).
 */
export type EvidenceType =
  | 'DIRECT_OBSERVATION'
  | 'STATIC_ANALYSIS'
  | 'CONFIGURATION'
  | 'DEPENDENCY_METADATA'
  | 'NETWORK_OBSERVATION'
  | 'CERTIFICATE_OBSERVATION'
  | 'RUNTIME_TELEMETRY'
  | 'INFERENCE'
  | 'UNKNOWN';

export const EVIDENCE_TYPE_LABEL: Record<EvidenceType, string> = {
  DIRECT_OBSERVATION: 'Direct observation',
  STATIC_ANALYSIS: 'Static analysis',
  CONFIGURATION: 'Configuration',
  DEPENDENCY_METADATA: 'Dependency metadata',
  NETWORK_OBSERVATION: 'Network observation',
  CERTIFICATE_OBSERVATION: 'Certificate observation',
  RUNTIME_TELEMETRY: 'Runtime telemetry',
  INFERENCE: 'Inference',
  UNKNOWN: 'Unknown provenance',
};

/**
 * §45: "Evidence Quality" is its own axis.
 *
 * DIRECT         the artefact itself was read (a parsed certificate, a matched
 *                call site, a negotiated handshake).
 * STRONG         an authoritative statement about the artefact (a lockfile
 *                pinning a version, a config directive in force).
 * CIRCUMSTANTIAL a fact that makes the conclusion likely but does not establish
 *                it (a dependency that COULD provide the algorithm).
 * WEAK           a lexical match with no supporting context.
 */
export type EvidenceQuality = 'DIRECT' | 'STRONG' | 'CIRCUMSTANTIAL' | 'WEAK';

export const EVIDENCE_QUALITY_RANK: Record<EvidenceQuality, number> = {
  DIRECT: 4,
  STRONG: 3,
  CIRCUMSTANTIAL: 2,
  WEAK: 1,
};

/** §90: the four permitted determination states. */
export type DeterminationState = 'CONFIRMED' | 'POTENTIAL' | 'NOT_ASSESSED' | 'UNKNOWN';

/** §47's eight detection layers. Independent agreement raises confidence. */
export type DetectionLayer =
  | 'lexical'
  | 'ast'
  | 'api'
  | 'configuration'
  | 'dependency'
  | 'data-flow'
  | 'runtime'
  | 'cross-scanner';

export const DETECTION_LAYER_LABEL: Record<DetectionLayer, string> = {
  lexical: 'Lexical match',
  ast: 'Syntactic analysis',
  api: 'API semantics',
  configuration: 'Configuration directive',
  dependency: 'Dependency declaration',
  'data-flow': 'Data-flow correlation',
  runtime: 'Runtime observation',
  'cross-scanner': 'Cross-scanner correlation',
};

/** How much independent weight each layer carries toward confidence. */
export const DETECTION_LAYER_WEIGHT: Record<DetectionLayer, number> = {
  lexical: 1,
  ast: 3,
  api: 4,
  configuration: 4,
  dependency: 2,
  'data-flow': 4,
  runtime: 5,
  'cross-scanner': 3,
};
