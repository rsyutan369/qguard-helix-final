/**
 * The classification engine (§6, §9, §10, §14, §15, §36, §37, §38, §80).
 *
 * Turns one raw observation into a fully-qualified {@link CryptoClassification}
 * with every axis separately justified.
 *
 * §6: "Do NOT classify cryptography solely from a keyword."
 *
 * The single most important property of this module is that CLASSICAL and
 * QUANTUM verdicts are computed independently and can disagree in both
 * directions:
 *
 *   RSA-2048   classical ACCEPTABLE   quantum QUANTUM_VULNERABLE
 *   SHA-1      classical BROKEN       quantum QUANTUM_RESISTANT
 *   AES-256    classical STRONG       quantum QUANTUM_RESISTANT
 *   ML-KEM     classical STRONG       quantum PQC_STANDARDIZED
 *
 * A single "is it bad" field cannot express any of those four rows correctly,
 * and §95 forbids three of the four collapses by name.
 */

import type {
  AlgorithmDefinition,
  ClassicalSecurity,
  CryptoClassification,
  CryptoRole,
  CurveDefinition,
  QuantumStatus,
  StandardReference,
} from './types';
import { QUANTUM_RELEVANT_ROLES } from './types';
import { hybridRoles, type HybridParticipant } from '../hybrid-construction';
import { canonicalName, findAlgorithm, parseKeySize } from './algorithms';
import { curveSupportsRole, findCurve } from './curves';
import { findLibrary } from './apis';
import { qguardRule, standardsFor } from './standards';

/* ══════════════════════════════════════════════════════════════ role model ══ */

/** Contextual signals that establish a cryptographic role. */
const ROLE_SIGNALS: Array<{ role: CryptoRole; patterns: RegExp[] }> = [
  { role: 'certificate-signature', patterns: [/signature\s*algorithm/i, /cert.{0,12}sign/i, /signed\s+by/i] },
  { role: 'certificate-public-key', patterns: [/public\s*key\s*(algorithm)?/i, /subject\s*public\s*key/i, /\bspki\b/i] },
  { role: 'code-signing', patterns: [/code[-_\s]?sign/i, /\bcosign\b/i, /\bnotary\b/i, /\bsigstore\b/i, /authenticode/i, /jarsigner/i, /provenance/i] },
  { role: 'token-signing', patterns: [/\bjwt\b/i, /\bjws\b/i, /\bjose\b/i, /bearer\s*token/i, /id[_-]?token/i, /access[_-]?token/i] },
  { role: 'key-transport', patterns: [/key\s*transport/i, /wrap(ping)?\s*key/i, /encrypt.{0,12}key/i, /\bkek\b/i] },
  { role: 'key-establishment', patterns: [/key\s*(exchange|agreement|establishment|encapsulat)/i, /\bkem\b/i, /\bkex\b/i, /shared\s*secret/i, /\becdhe?\b/i, /\bdhe?\b/i] },
  { role: 'digital-signature', patterns: [/\bsign(ing|ature)?\b/i, /createsign/i, /\bverify\b/i, /signeddata/i] },
  { role: 'password-derivation', patterns: [/\bpassword\b/i, /\bpasswd\b/i, /credential\s*hash/i, /\bbcrypt\b/i, /\bargon2\b/i, /\bscrypt\b/i, /\bpbkdf2\b/i] },
  { role: 'key-derivation', patterns: [/\bhkdf\b/i, /derive[-_\s]?(key|bits)/i, /\bkdf\b/i] },
  { role: 'key-management', patterns: [/\bkms\b/i, /key\s*vault/i, /\bhsm\b/i, /secret[s]?\s*manager/i, /generatekey/i, /keypairgenerator/i] },
  { role: 'storage-encryption', patterns: [/at[-_\s]?rest/i, /\bdisk\b/i, /\bvolume\b/i, /\bbucket\b/i, /\bstorage\b/i, /\bs3\b/i] },
  { role: 'database-encryption', patterns: [/\bdatabase\b/i, /\brds\b/i, /\btde\b/i, /\bsql\b/i] },
  { role: 'transport-security', patterns: [/\btls\b/i, /\bhttps\b/i, /cipher[-_\s]?suite/i, /\bingress\b/i, /\bssl_/i, /\bmtls\b/i] },
  { role: 'authentication', patterns: [/\bauth(entication)?\b/i, /\blogin\b/i, /\bssh\b/i, /host\s*key/i] },
  { role: 'integrity', patterns: [/\bhmac\b/i, /\bchecksum\b/i, /\bintegrity\b/i, /\bmac\b/i, /message\s*auth/i] },
  { role: 'authenticated-encryption', patterns: [/\baead\b/i, /\bgcm\b/i, /\bpoly1305\b/i, /\bccm\b/i] },
  { role: 'hashing', patterns: [/\bhash\b/i, /createhash/i, /\bdigest\b/i, /messagedigest/i] },
  { role: 'encryption', patterns: [/\bencrypt/i, /\bcipher\b/i, /\bdecrypt/i] },
  { role: 'random-generation', patterns: [/\brandom\b/i, /\bprng\b/i, /\bentropy\b/i, /\bnonce\b/i, /\biv\b/i, /\bseed\b/i] },
];

/**
 * Infer the cryptographic role.
 *
 * `declared` wins outright: an API rule that matched `createSign` has PROVEN
 * the role, and no amount of surrounding prose should override it. Textual
 * context is consulted only when nothing stronger is available, and the family
 * default is the last resort.
 *
 * RSA and ECC deliberately fall through to `unknown` rather than a default:
 * RSA does both signatures and key transport, ECC does both signatures and key
 * agreement, and §80 forbids recommending a migration target without knowing
 * which. `unknown` is a truthful answer that suppresses the recommendation;
 * a guess is not.
 */
export function inferRole(input: {
  algorithm: AlgorithmDefinition | null;
  context: string;
  declared?: CryptoRole;
}): { role: CryptoRole; basis: CryptoClassification['roleBasis'] } {
  if (input.declared && input.declared !== 'unknown') {
    return { role: input.declared, basis: 'declared' };
  }

  for (const signal of ROLE_SIGNALS) {
    if (!signal.patterns.some((pattern) => pattern.test(input.context))) continue;
    // Only accept a contextual role the algorithm can actually serve.
    if (input.algorithm && input.algorithm.cryptographicRoles.length > 0) {
      if (!input.algorithm.cryptographicRoles.includes(signal.role)) continue;
    }
    return { role: signal.role, basis: 'textual-context' };
  }

  if (input.algorithm) {
    /* A single-role algorithm needs no context: ML-KEM is key establishment
       and nothing else, X25519 cannot sign. */
    if (input.algorithm.cryptographicRoles.length === 1) {
      return { role: input.algorithm.cryptographicRoles[0], basis: 'family-default' };
    }
    const family = input.algorithm.family;
    if (family === 'ML-KEM') return { role: 'key-establishment', basis: 'family-default' };
    if (family === 'ML-DSA' || family === 'SLH-DSA' || family === 'FN-DSA' || family === 'DSA') {
      return { role: 'digital-signature', basis: 'family-default' };
    }
    if (family === 'DH') return { role: 'key-establishment', basis: 'family-default' };
    if (input.algorithm.primitiveType === 'hash') return { role: 'hashing', basis: 'family-default' };
    if (input.algorithm.primitiveType === 'mac') return { role: 'integrity', basis: 'family-default' };
    if (input.algorithm.primitiveType === 'password-hash') return { role: 'password-derivation', basis: 'family-default' };
    if (input.algorithm.primitiveType === 'kdf') return { role: 'key-derivation', basis: 'family-default' };
    if (input.algorithm.primitiveType === 'block-cipher' || input.algorithm.primitiveType === 'stream-cipher' || input.algorithm.primitiveType === 'aead') {
      return { role: 'encryption', basis: 'family-default' };
    }
    if (input.algorithm.primitiveType === 'protocol') return { role: 'transport-security', basis: 'family-default' };
  }

  return { role: 'unknown', basis: 'undetermined' };
}

/* ══════════════════════════════════════════════════ classical verdict (§9) ══ */

/**
 * Classical security, independent of any quantum consideration.
 *
 * The key-size check is what turns "RSA" into "RSA-1024 is below the floor" or
 * "RSA-3072 meets current guidance" — a distinction §9 requires and a bare
 * algorithm lookup cannot make.
 */
export function classicalVerdict(input: {
  algorithm: AlgorithmDefinition | null;
  keySize: number | null;
  curve: CurveDefinition | null;
  cipherMode?: string | null;
  padding?: string | null;
}): { security: ClassicalSecurity; rationale: string } {
  const { algorithm, keySize, curve } = input;

  if (!algorithm) {
    return { security: 'UNKNOWN', rationale: 'The algorithm was not recognised, so no classical verdict is published.' };
  }

  /* The MODE can be the weakness even when the cipher is strong. AES-256 in ECB
     leaks plaintext structure block by block — the famous penguin image — so a
     verdict that reads only the algorithm name calls it STRONG and misses the
     actual defect. */
  if (input.cipherMode === 'ECB' && algorithm.primitiveType === 'block-cipher') {
    return {
      security: 'BROKEN',
      rationale: `${algorithm.canonicalName} in ECB mode encrypts each block independently, so identical plaintext blocks produce identical ciphertext and the structure of the data is preserved. The cipher is strong; the mode defeats it.`,
    };
  }

  /* Unauthenticated CBC is not broken, but it is a footgun: without a MAC it is
     malleable and vulnerable to padding-oracle attacks. */
  if (input.cipherMode === 'CBC' && algorithm.primitiveType === 'block-cipher') {
    return {
      security: 'LEGACY',
      rationale: `${algorithm.canonicalName}-CBC provides confidentiality but not integrity. Without a separate MAC it is malleable and exposed to padding-oracle attacks; an AEAD mode such as GCM is preferred for new use.`,
    };
  }

  // A named curve is more specific than the algorithm's default.
  if (curve) {
    return {
      security: curve.classicalSecurity,
      rationale:
        curve.note ??
        `${curve.canonicalName} provides approximately ${curve.classicalStrength} bits of classical security.`,
    };
  }

  if (keySize !== null && algorithm.weakKeySizes?.includes(keySize)) {
    return {
      security: keySize <= 1024 ? 'BROKEN' : 'LEGACY',
      rationale: `${algorithm.canonicalName}-${keySize} is below the ${algorithm.minimumKeySize ?? 2048}-bit minimum for this algorithm. ${
        keySize <= 1024
          ? 'Key sizes at or below 1024 bits are considered factorable with sustained effort and are disallowed for new use.'
          : 'This size is deprecated for new use.'
      }`,
    };
  }

  if (keySize !== null && algorithm.recommendedKeySize && keySize >= algorithm.recommendedKeySize) {
    return {
      security: 'STRONG',
      rationale: `${algorithm.canonicalName}-${keySize} meets or exceeds the ${algorithm.recommendedKeySize}-bit size recommended for this algorithm.`,
    };
  }

  if (keySize !== null && algorithm.minimumKeySize && keySize >= algorithm.minimumKeySize) {
    return {
      security: 'ACCEPTABLE',
      rationale: `${algorithm.canonicalName}-${keySize} meets the ${algorithm.minimumKeySize}-bit minimum but is below the ${algorithm.recommendedKeySize ?? algorithm.minimumKeySize}-bit size recommended for long-lived protection.`,
    };
  }

  return {
    security: algorithm.classicalSecurity,
    rationale: algorithm.note ?? `${algorithm.canonicalName} is classified ${algorithm.classicalSecurity.toLowerCase()} against classical cryptanalysis.`,
  };
}

/* ═══════════════════════════════════════════════════ quantum verdict (§36-39) ═ */

/** Effective post-quantum strength for a symmetric primitive (§38). */
function effectiveQuantumStrength(algorithm: AlgorithmDefinition, keySize: number | null): number | null {
  if (!algorithm.groverAffected) return null;
  const size = keySize ?? algorithm.recommendedKeySize ?? algorithm.minimumKeySize ?? null;
  if (size === null) return null;
  /* Grover gives a quadratic speed-up on unstructured search, so an n-bit
     symmetric key retains roughly n/2 bits. This is the standard modelling
     assumption and is stated as such rather than as a hard guarantee. */
  return Math.floor(size / 2);
}

export interface QuantumVerdict {
  status: QuantumStatus;
  rationale: string;
  quantumRelevant: boolean;
  effectiveStrength: number | null;
  migrationTarget?: string;
}

/**
 * Classify quantum posture from (algorithm, role, key size, hybrid partner).
 *
 * §37: use "Quantum Vulnerable", never "Currently Cryptographically Broken".
 * §38: symmetric primitives are modelled, not lumped in with RSA/ECC.
 * §95: AES-256 must never be presented as equivalent to RSA.
 */
export function quantumVerdict(input: {
  algorithm: AlgorithmDefinition | null;
  role: CryptoRole;
  keySize: number | null;
  curve?: CurveDefinition | null;
  /** Set when the SAME observation carries a partner primitive. */
  hybridPartner?: AlgorithmDefinition | null;
}): QuantumVerdict {
  const { algorithm, role, keySize, hybridPartner } = input;

  if (!algorithm) {
    return {
      status: 'UNKNOWN',
      rationale: 'The algorithm was not recognised, so no quantum verdict is published for it.',
      quantumRelevant: false,
      effectiveStrength: null,
    };
  }

  /* "Post-quantum" here means "an asymmetric primitive Shor does not break" —
     NOT "standardised by NIST". Those are different questions and conflating
     them mis-classified sntrup761x25519, OpenSSH's default hybrid exchange,
     because Streamlined NTRU Prime was not selected for FIPS 203. Whether the
     algorithm is standardised is reported separately, through `standardStatus`
     and the standards list, where a governance reader can act on it. */
  const asHybridParticipant = (candidate: AlgorithmDefinition): HybridParticipant => ({
    asymmetric:
      candidate.primitiveType === 'key-establishment' ||
      candidate.primitiveType === 'digital-signature' ||
      candidate.primitiveType === 'public-key-encryption',
    shorBroken: candidate.shorBroken,
  });

  /* ── hybrid: a classical ASYMMETRIC primitive deployed WITH a PQC one ───
     Both halves must be asymmetric. The rule used to be "one side is PQC and
     the other is not", which is true of every hash and every symmetric cipher,
     so MD5 beside an ML-KEM mention was published as completed migration work.
     `hybridRoles` is the one place that decision is made — see
     `src/lib/crypto/hybrid-construction.ts`. */
  const pair = hybridPartner
    ? hybridRoles(
        { ...asHybridParticipant(algorithm), entry: algorithm },
        { ...asHybridParticipant(hybridPartner), entry: hybridPartner },
      )
    : null;

  if (pair) {
    const classical = pair.classical.entry;
    const pqc = pair.pqc.entry;
    return {
      status: 'HYBRID',
      rationale: `${classical.canonicalName} is combined with ${pqc.canonicalName}${
        pqc.standardStatus ? ` (${pqc.standardStatus})` : ' (not a NIST-standardised algorithm)'
      }, so the construction remains secure if either component holds. This is completed migration work, not an exposure.`,
      quantumRelevant: true,
      effectiveStrength: null,
    };
  }

  if (algorithm.quantumStatus === 'PQC_STANDARDIZED') {
    return {
      status: 'PQC_STANDARDIZED',
      rationale: `${algorithm.canonicalName}${algorithm.standardStatus ? ` is standardised as ${algorithm.standardStatus} and` : ''} is not broken by Shor's algorithm.`,
      quantumRelevant: true,
      effectiveStrength: null,
    };
  }

  /* ── Shor-broken public-key primitives ────────────────────────────────── */
  if (algorithm.shorBroken) {
    const relevant = QUANTUM_RELEVANT_ROLES.includes(role);
    const target = migrationTargetFor(algorithm, role);
    const sizeLabel = keySize ? `-${keySize}` : input.curve ? ` on ${input.curve.canonicalName}` : '';

    return {
      status: 'QUANTUM_VULNERABLE',
      rationale: relevant
        ? `${algorithm.canonicalName}${sizeLabel} used for ${humanRole(role)} is broken by Shor's algorithm on a cryptographically relevant quantum computer. It is a migration candidate; it is not breakable today.`
        : `${algorithm.canonicalName}${sizeLabel} is broken by Shor's algorithm. In a ${humanRole(role)} role the migration is lower priority, but the primitive itself remains quantum-vulnerable.`,
      quantumRelevant: relevant,
      effectiveStrength: null,
      migrationTarget: target,
    };
  }

  /* ── symmetric and hash primitives (§38) ──────────────────────────────── */
  if (algorithm.groverAffected) {
    const strength = effectiveQuantumStrength(algorithm, keySize);

    if (algorithm.classicalSecurity === 'BROKEN') {
      return {
        status: 'QUANTUM_RESISTANT',
        rationale: `${algorithm.canonicalName} is already broken by CLASSICAL cryptanalysis, which is a present-tense problem independent of any quantum threat. Replacing it is urgent for classical reasons, not quantum ones.`,
        quantumRelevant: false,
        effectiveStrength: strength,
        migrationTarget: algorithm.primitiveType === 'hash' ? 'SHA-256 or SHA3-256' : 'AES-256-GCM',
      };
    }

    if (strength !== null && strength < 128) {
      return {
        status: 'QUANTUM_RESISTANT',
        rationale: `${algorithm.canonicalName}${keySize ? `-${keySize}` : ''} retains roughly ${strength} bits against Grover-style search. That is below the 128-bit post-quantum margin generally recommended for long-lived protection, but it is a key-size question — the primitive is not broken by a quantum computer the way RSA and ECC are.`,
        quantumRelevant: false,
        effectiveStrength: strength,
        migrationTarget: algorithm.family === 'AES' ? 'AES-256-GCM' : undefined,
      };
    }

    return {
      status: 'QUANTUM_RESISTANT',
      rationale: `${algorithm.canonicalName} is a symmetric or hash primitive. Grover-style search halves its effective strength${strength ? `, leaving roughly ${strength} bits` : ''}, which adequate sizes already absorb. It is not a post-quantum migration candidate.`,
      quantumRelevant: false,
      effectiveStrength: strength,
    };
  }

  if (algorithm.primitiveType === 'protocol') {
    return {
      status: 'NOT_APPLICABLE',
      rationale: `${algorithm.canonicalName} is a protocol, not a primitive. Its quantum exposure is determined by the key-agreement group and signature algorithm it negotiates.`,
      quantumRelevant: false,
      effectiveStrength: null,
    };
  }

  if (algorithm.quantumStatus === 'QUANTUM_RESISTANT') {
    return {
      status: 'QUANTUM_RESISTANT',
      rationale: algorithm.note ?? `${algorithm.canonicalName} is not broken by any known quantum algorithm.`,
      quantumRelevant: false,
      effectiveStrength: null,
    };
  }

  return {
    status: 'UNKNOWN',
    rationale: `No quantum verdict is published for ${algorithm.canonicalName} without evidence of how it is used.`,
    quantumRelevant: false,
    effectiveStrength: null,
  };
}

/**
 * Role-appropriate migration target (§80).
 *
 * Returns `undefined` when the role is unknown. That silence is deliberate:
 * recommending ML-DSA for something that turns out to be a key exchange is
 * worse than recommending nothing, because the customer acts on it.
 */
export function migrationTargetFor(algorithm: AlgorithmDefinition, role: CryptoRole): string | undefined {
  return algorithm.migrationTargets?.[role];
}

function humanRole(role: CryptoRole): string {
  const labels: Partial<Record<CryptoRole, string>> = {
    'key-establishment': 'key establishment',
    'key-transport': 'key transport',
    'digital-signature': 'digital signatures',
    'certificate-public-key': 'a certificate public key',
    'certificate-signature': 'a certificate signature',
    'code-signing': 'code signing',
    'token-signing': 'token signing',
    'transport-security': 'TLS transport',
    authentication: 'authentication',
    'key-management': 'key management',
    encryption: 'encryption',
    unknown: 'an unidentified role',
  };
  return labels[role] ?? role.replace(/-/g, ' ');
}

/* ══════════════════════════════════════════════════════ migration priority ══ */

/**
 * §77: quantum exposure is multi-factor, never `RSA = 100`.
 *
 * The factors available at CLASSIFICATION time are the algorithm, the role and
 * the key size. Asset criticality, data lifetime and blast radius are estate
 * facts the risk engine adds later; this function deliberately does not invent
 * them.
 */
export function migrationPriority(input: {
  quantum: QuantumVerdict;
  classical: ClassicalSecurity;
  role: CryptoRole;
}): 'P1' | 'P2' | 'P3' | 'P4' | null {
  if (input.quantum.status !== 'QUANTUM_VULNERABLE' && input.classical !== 'BROKEN') return null;

  // A classically broken primitive outranks any quantum consideration.
  if (input.classical === 'BROKEN') return 'P1';

  const internetFacing: CryptoRole[] = ['transport-security', 'certificate-public-key', 'certificate-signature', 'key-establishment'];
  const longLived: CryptoRole[] = ['code-signing', 'certificate-signature', 'token-signing'];

  if (internetFacing.includes(input.role)) return 'P1';
  if (longLived.includes(input.role)) return 'P2';
  if (input.quantum.quantumRelevant) return 'P3';
  return 'P4';
}

/* ══════════════════════════════════════════════════════ the public entry ════ */

export interface ClassifyInput {
  /** The algorithm string as written in the artefact. */
  algorithm: string | null | undefined;
  /** Everything the detector knows: matched line, file path, rule label. */
  context?: string;
  /** Set when an API rule or a parsed structure PROVED the role. */
  declaredRole?: CryptoRole;
  keySize?: number | null;
  curve?: string | null;
  parameterSet?: string | null;
  cipherMode?: string | null;
  padding?: string | null;
  hash?: string | null;
  library?: string | null;
  protocol?: string | null;
  /** The other half of a hybrid construction, when one was observed. */
  hybridPartner?: string | null;
}

/**
 * Classify one observation into the canonical model.
 *
 * Everything the classifier could NOT establish is listed in `undetermined`,
 * so a consumer can see the difference between "AES-256" and "AES, key size
 * unknown" — which §90 requires and which a nullable field alone does not
 * communicate.
 */
export function classify(input: ClassifyInput): CryptoClassification {
  const observedAs = String(input.algorithm ?? '').trim();
  const algorithm = findAlgorithm(observedAs);
  const context = input.context ?? '';
  const undetermined: string[] = [];

  /* ── curve ─────────────────────────────────────────────────────────────── */
  const curve = findCurve(input.curve) ?? findCurve(observedAs) ?? null;

  /* ── key size: explicit, then from the algorithm string, then the curve ── */
  let keySize = input.keySize ?? null;
  /* The algorithm is passed so the size has to be written against IT. Without
     it, `sha256WithRSAEncryption` published "RSA-256" — the digest length read
     as the modulus — as a critical finding. */
  if (keySize === null) keySize = parseKeySize(observedAs, algorithm);
  if (keySize === null && curve) keySize = curve.bits;
  if (keySize === null && algorithm && (algorithm.family === 'RSA' || algorithm.family === 'DH')) {
    undetermined.push('key size');
  }

  /* ── role ──────────────────────────────────────────────────────────────── */
  const roleResult = inferRole({
    algorithm,
    context: `${observedAs} ${context}`,
    declared: input.declaredRole,
  });
  if (roleResult.basis === 'undetermined') undetermined.push('cryptographic role');

  /* ── curve/role consistency ────────────────────────────────────────────── */
  if (curve && roleResult.basis !== 'undetermined' && !curveSupportsRole(curve, roleResult.role)) {
    /* X25519 cannot sign; Ed25519 cannot do key agreement. When the context
       claims otherwise, the CURVE is the harder fact — it is a mathematical
       property, not an inference — so the role is demoted rather than the
       curve being silently accepted in a role it cannot serve. */
    undetermined.push(
      `role consistency (${curve.canonicalName} cannot serve ${roleResult.role}; the surrounding context may describe a different key)`,
    );
  }

  const hybridPartner = input.hybridPartner ? findAlgorithm(input.hybridPartner) : null;

  /* ── the two independent verdicts ──────────────────────────────────────── */
  const cipherMode = input.cipherMode ?? extractMode(observedAs);
  const classical = classicalVerdict({ algorithm, keySize, curve, cipherMode, padding: input.padding });
  const quantum = quantumVerdict({ algorithm, role: roleResult.role, keySize, curve, hybridPartner });

  /* ── standards ─────────────────────────────────────────────────────────── */
  const standards: StandardReference[] = [...(algorithm?.standards ?? [])];
  if (algorithm?.disallowed && standards.length === 0) {
    standards.push(qguardRule(`${algorithm.canonicalName} disallowed for new use`));
  }

  if (!input.library && algorithm) undetermined.push('implementing library');
  if (algorithm?.primitiveType === 'block-cipher' && !input.cipherMode) undetermined.push('cipher mode');

  return {
    algorithm,
    observedAs: observedAs || 'unknown',
    canonicalName: canonicalName(observedAs),
    role: roleResult.role,
    roleBasis: roleResult.basis,
    keySize,
    curve,
    parameterSet: input.parameterSet ?? null,
    cipherMode,
    padding: input.padding ?? extractPadding(observedAs),
    hash: input.hash ?? extractHash(observedAs),
    library: findLibrary(input.library),
    protocol: input.protocol ?? null,

    classicalSecurity: classical.security,
    classicalRationale: classical.rationale,

    quantumStatus: quantum.status,
    quantumRationale: quantum.rationale,
    quantumRelevant: quantum.quantumRelevant,
    effectiveQuantumStrength: quantum.effectiveStrength,

    migrationTarget: quantum.migrationTarget,
    migrationPriority: migrationPriority({ quantum, classical: classical.security, role: roleResult.role }),

    standards,
    undetermined,
  };
}

/* ─────────────────────────────────────────────────────── string extractors ── */

/** Cipher mode from a transformation string like "AES/GCM/NoPadding". */
export function extractMode(raw: string): string | null {
  const match = raw.match(/\b(GCM|CBC|CTR|CCM|ECB|OFB|CFB|XTS|SIV|OCB)\b/i);
  return match ? match[1].toUpperCase() : null;
}

/** Padding from a transformation string. */
export function extractPadding(raw: string): string | null {
  const match = raw.match(/\b(NoPadding|PKCS[157]Padding|PKCS1|OAEP|PSS|ISO10126Padding|ZeroPadding)\b/i);
  if (!match) return null;
  const value = match[1];
  return /nopadding/i.test(value) ? 'None' : value.toUpperCase().startsWith('PKCS') ? value.replace(/padding/i, '') : value.toUpperCase();
}

/** Digest named alongside a signature algorithm. */
export function extractHash(raw: string): string | null {
  const match = raw.match(/\b(SHA3-?(?:224|256|384|512)|SHA-?(?:1|224|256|384|512)|MD5|BLAKE2[bs]?)\b/i);
  if (!match) return null;
  const value = match[1].toUpperCase().replace(/^SHA(\d)/, 'SHA-$1');
  return value.replace(/^SHA-3-?/, 'SHA3-');
}

/**
 * The primitives a hybrid name can be built from.
 *
 * `denotes` is what the marker STANDS FOR, in the order the partner name
 * should be resolved. Curve markers are the reason this is a list rather than
 * a string: `p256_mlkem768` names its classical half by the CURVE, and P-256
 * is a curve, not an algorithm — `findAlgorithm('P-256')` is null. The
 * algorithm it denotes is ECDH in a key-establishment hybrid and ECDSA in a
 * signature composite, so the PQC half decides which name is returned.
 */
interface HybridMarker {
  pattern: string;
  kind: 'classical' | 'pqc';
  denotes: string[];
}

const HYBRID_MARKERS: HybridMarker[] = [
  /* Longest first: `secp256r1` must win before `p-?256` can match inside it. */
  { pattern: 'secp256r1', kind: 'classical', denotes: ['ECDH', 'ECDSA'] },
  { pattern: 'secp384r1', kind: 'classical', denotes: ['ECDH', 'ECDSA'] },
  { pattern: 'secp521r1', kind: 'classical', denotes: ['ECDH', 'ECDSA'] },
  { pattern: 'x25519', kind: 'classical', denotes: ['X25519', 'ECDH'] },
  { pattern: 'x448', kind: 'classical', denotes: ['X448', 'ECDH'] },
  { pattern: 'ed25519', kind: 'classical', denotes: ['Ed25519'] },
  { pattern: 'ed448', kind: 'classical', denotes: ['Ed448'] },
  { pattern: 'ecdsa', kind: 'classical', denotes: ['ECDSA'] },
  { pattern: 'ecdh', kind: 'classical', denotes: ['ECDH'] },
  { pattern: 'p-?256', kind: 'classical', denotes: ['ECDH', 'ECDSA'] },
  { pattern: 'p-?384', kind: 'classical', denotes: ['ECDH', 'ECDSA'] },
  { pattern: 'p-?521', kind: 'classical', denotes: ['ECDH', 'ECDSA'] },
  { pattern: 'rsa', kind: 'classical', denotes: ['RSA'] },

  { pattern: 'ml-?kem', kind: 'pqc', denotes: ['ML-KEM'] },
  { pattern: 'kyber', kind: 'pqc', denotes: ['ML-KEM'] },
  { pattern: 'ml-?dsa', kind: 'pqc', denotes: ['ML-DSA'] },
  { pattern: 'dilithium', kind: 'pqc', denotes: ['ML-DSA'] },
  { pattern: 'slh-?dsa', kind: 'pqc', denotes: ['SLH-DSA'] },
  { pattern: 'sphincs', kind: 'pqc', denotes: ['SLH-DSA'] },
  { pattern: 'falcon', kind: 'pqc', denotes: ['Falcon'] },
  { pattern: 'sntrup761', kind: 'pqc', denotes: ['Streamlined NTRU Prime'] },
  { pattern: 'frodokem', kind: 'pqc', denotes: ['FrodoKEM'] },
  { pattern: 'mceliece', kind: 'pqc', denotes: ['Classic McEliece'] },
  { pattern: 'bike', kind: 'pqc', denotes: ['BIKE'] },
  { pattern: 'hqc', kind: 'pqc', denotes: ['HQC'] },
];

const HYBRID_MARKER_SCAN = new RegExp(HYBRID_MARKERS.map((entry) => `(${entry.pattern})`).join('|'), 'g');

/** Name-like runs: a hybrid is named as ONE of these, never across two. */
const NAME_TOKEN = /[a-z0-9_+.@-]+/g;

/**
 * What may sit BETWEEN two halves of a fused name: parameter digits and at
 * most one joining character. Nothing else — a letter between them means they
 * are two separate words that happen to share a token, which is how
 * `rsa_to_mlkem_migration` (a function name) used to read as a deployment.
 */
const HYBRID_JOIN = /^[0-9]*[-_+.]?[0-9]*$/;

interface MarkerHit {
  marker: HybridMarker;
  start: number;
  end: number;
}

function scanMarkers(token: string): MarkerHit[] {
  const hits: MarkerHit[] = [];
  HYBRID_MARKER_SCAN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = HYBRID_MARKER_SCAN.exec(token)) !== null) {
    const groupIndex = match.slice(1).findIndex((value) => value !== undefined);
    if (groupIndex < 0) continue;
    hits.push({ marker: HYBRID_MARKERS[groupIndex], start: match.index, end: match.index + match[0].length });
  }
  return hits;
}

/**
 * Detect the other half of a hybrid construction NAMED IN ONE IDENTIFIER.
 *
 * Reporting the classical half of `X25519MLKEM768` as a standalone vulnerable
 * exposure turns the customer's completed post-quantum WORK into a finding
 * against them — the single most misleading result a PQC scanner can produce.
 *
 * ── Why fusion, and not co-occurrence ───────────────────────────────────────
 *
 * This used to answer "is there a PQC token ANYWHERE in the text, and a
 * classical token ANYWHERE in the text", over a ±4-line window. Any file that
 * merely NAMES both — an algorithm catalogue, a config enum, a switch over
 * supported suites, a migration comment — made every primitive near it hybrid.
 * A Dev scan of this repository published 33 RSA components and 46 ECDSA
 * components as hybrid, i.e. as quantum-PROTECTED, because the surrounding
 * lines happened to mention ML-KEM. Understating RSA exposure is the precise
 * failure this platform exists to prevent.
 *
 * A hybrid deployment is named as ONE thing — `X25519MLKEM768`,
 * `x25519_kyber768`, `sntrup761x25519-sha512@openssh.com`, `Ed25519+ML-DSA`.
 * That fusion is the evidence; two names in the same neighbourhood are not.
 */
export function detectHybridPartner(text: string, algorithmName: string): string | null {
  const self = findAlgorithm(algorithmName);
  if (!self) return null;

  for (const [token] of text.toLowerCase().matchAll(NAME_TOKEN)) {
    const hits = scanMarkers(token);
    if (hits.length < 2) continue;

    /* Two halves are FUSED when only parameter digits and at most one joining
       character separate them. Adjacency is checked between consecutive
       markers, so a chain like `ecdsa_p256_mldsa44` holds together while
       `rsa_to_mlkem_migration` does not. */
    let pair: { classical: HybridMarker; pqc: HybridMarker } | null = null;
    for (let index = 0; index + 1 < hits.length && !pair; index += 1) {
      const left = hits[index];
      const right = hits[index + 1];
      if (left.marker.kind === right.marker.kind) continue;
      if (!HYBRID_JOIN.test(token.slice(left.end, right.start))) continue;
      pair = left.marker.kind === 'classical'
        ? { classical: left.marker, pqc: right.marker }
        : { classical: right.marker, pqc: left.marker };
    }
    if (!pair) continue;

    /* The observation being classified must itself be named in this token. A
       hybrid group named elsewhere in the window says nothing about it — that
       assumption is what published RSA as quantum-protected. */
    const selfIsNamed = hits.some((hit) => hit.marker.denotes.includes(self.canonicalName));
    if (!selfIsNamed) continue;

    const selfKind = pair.pqc.denotes.includes(self.canonicalName) ? 'pqc' : 'classical';
    const partner = selfKind === 'pqc' ? pair.classical : pair.pqc;

    /* Curve markers denote more than one algorithm; the half we are pairing
       with decides which. A hybrid KEM's classical half is a key agreement,
       a composite signature's is a signature. */
    const wantSignature = selfKind === 'pqc'
      ? self.primitiveType === 'digital-signature'
      : findAlgorithm(pair.pqc.denotes[0])?.primitiveType === 'digital-signature';

    const ordered = partner.denotes.length > 1 && wantSignature
      ? [...partner.denotes].sort((a, b) => (a === 'ECDSA' ? -1 : b === 'ECDSA' ? 1 : 0))
      : partner.denotes;

    for (const candidate of ordered) {
      if (candidate === self.canonicalName) continue;
      if (findAlgorithm(candidate)) return candidate;
    }
  }

  return null;
}
