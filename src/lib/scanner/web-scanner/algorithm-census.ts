/**
 * Algorithm census — ONE reading of "which algorithms did this scan observe,
 * and which of them are post-quantum".
 *
 * ── The defect this module exists to remove ─────────────────────────────────
 *
 * A single scan of one CDN endpoint published both of these, adjacent, on the
 * same page:
 *
 *   Score decomposition        Cryptographic Algorithms  25
 *                              "4 algorithms observed · 1 quantum-safe"
 *   Cryptographic Intelligence Observed Algorithms
 *                              RSA-2048  ×5
 *                              sha256WithRSAEncryption  ×2
 *                              AES-128-GCM  ×1
 *
 * Four observed above a list of three, and one of them called quantum-safe when
 * none of them is. Two separate censuses were running:
 *
 *   `cryptographicAlgorithms()` in published-scoring.ts — pushed the socket's
 *       TLS 1.3 placeholder, the negotiated curve, the signature algorithm,
 *       every cipher-suite bulk cipher AND every supported protocol version
 *       into one flat list, then defined "quantum-safe" as `!vulnerable`. It
 *       pushes bulk ciphers and protocol versions with `vulnerable: false`,
 *       so AES-128-GCM and TLSv1.3 were both counted as quantum-safe — and
 *       they carried the category score with them.
 *
 *   `buildObservedAlgorithms()` in the dashboard — a better list (it drops the
 *       TLS 1.3 placeholder and ranks by algorithm class) but its own list,
 *       with its own vulnerability rule and an 8-row display cap.
 *
 * ── The rule ────────────────────────────────────────────────────────────────
 *
 * "Quantum-safe" means an ASYMMETRIC primitive a cryptographically relevant
 * quantum computer does not break — ML-KEM, ML-DSA, SLH-DSA, or a hybrid
 * construction. It does not mean "Shor does not break it", because Shor does
 * not break AES, SHA-2 or a protocol version either, and counting those as
 * migration wins is how an estate with zero post-quantum deployment scored 25
 * on the category that is supposed to measure post-quantum deployment.
 *
 * So a census entry is one of:
 *
 *   post-quantum        ML-KEM / ML-DSA / SLH-DSA / hybrid. Migration done.
 *   quantum-vulnerable  RSA / ECDSA / ECDH / DH / Ed25519. Migration candidate.
 *   grover-affected     symmetric or hash. NOT a post-quantum migration
 *                       candidate, so it belongs in neither half of the ratio.
 *                       Reported separately, with the below-margin ones named.
 *   protocol            a TLS version. Carries no quantum verdict of its own —
 *                       its exposure is the group and signature it negotiates.
 *   unclassified        the string named no primitive this platform knows.
 *
 * The ratio is therefore over `postQuantum + quantumVulnerable` alone, and the
 * category is NOT MEASURED — null, weight redistributed — when that population
 * is empty, rather than scoring 0 or 100 off primitives it does not describe.
 *
 * Pure and dependency-free apart from the platform's own decomposer, so the
 * backend scorer, the dashboard panel and the check tools all read one census.
 */

import { analyzeCryptoObservation } from '../../crypto/suite-anatomy';

/* ─────────────────────────────────────────────────────────────────── model ── */

export type CensusClass =
  | 'post-quantum'
  | 'quantum-vulnerable'
  | 'grover-affected'
  | 'protocol'
  | 'unclassified';

export interface CensusEntry {
  /** The algorithm string exactly as it was observed. */
  name: string;
  /** Operator-facing role, e.g. `Certificate public key - recoverable by Shor`. */
  role: string;
  cls: CensusClass;
  /** True only for `quantum-vulnerable` — the icon and the ratio share one rule. */
  quantumVulnerable: boolean;
  /** A symmetric primitive below the 128-bit post-quantum margin (AES-128). */
  belowPqMargin: boolean;
  /** Broken by CLASSICAL cryptanalysis today: RC4, DES, 3DES, SHA-1, MD5. */
  classicallyBroken: boolean;
  /** A deprecated transport protocol. Context here; scored by `tls-configuration`. */
  legacyProtocol: boolean;
  /** How many times this exact string was observed across the results in view. */
  count: number;
  /** Display order by algorithm class, not by severity. */
  rank: number;
}

export interface AlgorithmCensus {
  /** Every distinct algorithm observed, ordered for display. */
  entries: CensusEntry[];
  /** `entries.length` — the number every panel must quote. */
  observed: number;
  postQuantum: number;
  quantumVulnerable: number;
  /** postQuantum + quantumVulnerable: the population the ratio is taken over. */
  migrationRelevant: number;
  groverAffected: number;
  protocols: number;
  /** Names of primitives broken classically today, worst-first. */
  classicallyBroken: string[];
  /** Names of symmetric primitives under the 128-bit post-quantum margin. */
  belowPqMargin: string[];
  /** Deprecated protocol versions observed. Reported, never scored here. */
  legacyProtocols: string[];
  /**
   * The published `cryptographic-algorithms` category score, or null when no
   * migration-relevant primitive was observed — unmeasured, never zero.
   */
  score: number | null;
  /** The one sentence the score row and the panel footnote both print. */
  summary: string;
}

/* ─────────────────────────────────────────────────────────────────── input ── */

/**
 * Declared structurally rather than by importing `TlsAnalysisResult`, because
 * the dashboard carries its own narrower TLS shape and both sides must be able
 * to call this. Casting at each call site would defeat having one census.
 */
export interface CensusTlsObservation {
  keyExchange?: string | null;
  negotiatedCurve?: string | null;
  signatureAlgorithm?: string | null;
  cipherSuites?: Array<{ encryption?: string | null; name?: string | null }> | null;
  supportedProtocols?: string[] | null;
}

export interface CensusCertificateObservation {
  publicKeyAlgorithm?: string | null;
  publicKeySize?: number | null;
  signatureAlgorithm?: string | null;
  chain?: Array<{ publicKeyAlgorithm?: string | null; signatureAlgorithm?: string | null }> | null;
}

/** `MeasuredKeyAgreement`-shaped, plus the prober's parameter sets. */
export interface CensusKeyAgreement {
  probed: boolean;
  kemApplied: boolean;
  hybrid: boolean;
  group: string | null;
  classicalComponent: string | null;
  postQuantumComponent: string | null;
  kemParameterSets?: readonly string[];
}

export interface CensusObservation {
  tls?: CensusTlsObservation | null;
  certificate?: CensusCertificateObservation | null;
  /** The named-group probe's verdict for THIS target, when it ran. */
  keyAgreement?: CensusKeyAgreement | null;
}

export interface AlgorithmCensusInput {
  /** One entry per scanned target. */
  observations: CensusObservation[];
  /** Repository / client-bundle pattern hits, for targets with no transport. */
  patterns?: Array<{ algorithm?: string | null }>;
  /**
   * Last-resort source for target types that produce no transport evidence at
   * all. Rule-shaped titles are dropped: "No PQC Cipher Suites" is a statement
   * about the estate, not an algorithm.
   */
  fallbackFindings?: Array<{ algorithm?: string | null; category?: string | null }>;
}

/* ──────────────────────────────────────────────────────────── ordering ────── */

/**
 * Display order by algorithm CLASS, not by severity. Ranking by vulnerability
 * pushed every symmetric and protocol entry past the display cap, so the panel
 * showed eight flavours of "recoverable by Shor" and none of the AES or hash
 * material that is also part of the observed posture.
 */
const RANK = {
  postQuantum: -1,
  certificateKey: 0,
  certificateSignature: 1,
  keyAgreement: 2,
  namedGroup: 3,
  handshakeSignature: 4,
  symmetric: 5,
  protocol: 6,
  chainKey: 7,
  fallback: 8,
} as const;

/** A protocol version the industry has deprecated — a CLASSICAL break. */
const LEGACY_PROTOCOL = /TLSv1(\.0)?$|TLSv1\.1|SSLv/i;

/** Symmetric primitives under the 128-bit post-quantum margin. */
const BELOW_PQ_MARGIN = /AES[-_]?128|\bAES128\b/i;

/* ────────────────────────────────────────────────────────── classification ── */

interface Classified {
  cls: CensusClass;
  belowPqMargin: boolean;
  /**
   * Broken by CLASSICAL cryptanalysis today — RC4, DES/3DES, MD5, SHA-1.
   *
   * Deliberately excludes deprecated protocol versions: they are scored by
   * `tls-configuration` at weight 18, and penalising them here as well charged
   * one observation to two categories.
   */
  classicallyBroken: boolean;
  /** Deprecated transport protocol. Reported as context; scored elsewhere. */
  legacyProtocol?: boolean;
  /** Role suffix that states the quantum reading in the operator's language. */
  shorSuffix: string;
}

/**
 * One algorithm string → its census class.
 *
 * Everything routes through the platform's shared decomposer, which classifies
 * the risk-bearing PART rather than the whole string — the rule that stops
 * `TLS_RSA_WITH_AES_256_GCM_SHA384` being filed under AES-256-GCM, and that
 * (since the composite-signature fix) stops `sha256WithRSAEncryption` being
 * filed as a quantum-safe hash.
 */
export function classifyForCensus(name: string): Classified {
  const anatomy = analyzeCryptoObservation({ algorithm: name });
  const asymmetric =
    anatomy.kind === 'key-exchange' ||
    anatomy.kind === 'signature' ||
    anatomy.kind === 'certificate' ||
    anatomy.kind === 'cipher-suite';

  if (anatomy.kind === 'protocol') {
    return {
      cls: 'protocol',
      belowPqMargin: false,
      /* A DEPRECATED PROTOCOL IS NOT A BROKEN ALGORITHM, AND IT IS NOT THIS
         CATEGORY'S TO PENALISE.
         `tls-configuration` scores the accepted protocol versions at weight 18
         and drops an endpoint to 45/100 the moment TLS 1.0 or 1.1 appears.
         Charging the same observation again here — 25 points per version — took
         a live endpoint whose asymmetric primitives were 50% post-quantum
         (ML-KEM-768 measured across 23 handshakes) and published
         "Cryptographic Algorithms 0/100" beside "Key Exchange 100/100".
         Ownership is unique: protocols stay in the census as context and are
         graded by the category that owns them. */
      classicallyBroken: false,
      legacyProtocol: LEGACY_PROTOCOL.test(name),
      shorSuffix: '',
    };
  }

  if (anatomy.kind === 'symmetric' || anatomy.kind === 'hash') {
    return {
      cls: 'grover-affected',
      belowPqMargin: BELOW_PQ_MARGIN.test(name),
      // 3DES / DES / RC4 / SHA-1 / MD5 — a present-tense problem, not a
      // quantum one, and it must not read as a post-quantum migration item.
      classicallyBroken: anatomy.quantumClass === 'vulnerable',
      shorSuffix: anatomy.kind === 'hash' ? 'Grover halves preimage resistance' : 'Grover halves the key',
    };
  }

  if (asymmetric && (anatomy.quantumClass === 'safe' || anatomy.quantumClass === 'hybrid')) {
    return {
      cls: 'post-quantum',
      belowPqMargin: false,
      classicallyBroken: false,
      shorSuffix: 'not recoverable by Shor',
    };
  }

  if (asymmetric && anatomy.quantumClass === 'vulnerable') {
    return {
      cls: 'quantum-vulnerable',
      belowPqMargin: false,
      classicallyBroken: false,
      shorSuffix: 'recoverable by Shor',
    };
  }

  /* A cipher-suite whose quantum class came from its bulk cipher (a TLS 1.3
     suite names no key exchange) is a symmetric reading, not an asymmetric
     one — counting it in the post-quantum ratio is the original defect. */
  if (anatomy.kind === 'cipher-suite') {
    return {
      cls: 'grover-affected',
      belowPqMargin: BELOW_PQ_MARGIN.test(name),
      classicallyBroken: false,
      shorSuffix: 'Grover halves the key',
    };
  }

  return { cls: 'unclassified', belowPqMargin: false, classicallyBroken: false, shorSuffix: '' };
}

/* ──────────────────────────────────────────────────────────────── builder ── */

const clean = (value: string | null | undefined): string => String(value ?? '').trim();

/** Rule-shaped titles are statements about the estate, not algorithms. */
function isRuleTitle(name: string): boolean {
  return /^(no|missing|weak|insecure|deprecated)\b/i.test(name) || name.includes(':');
}

/**
 * The identity two observations of the SAME algorithm share.
 *
 * The census used to key on the raw string, so one primitive could occupy two
 * rows and two slots in the post-quantum ratio. A live scan listed
 * `ML-KEM-768` and `ML-KEM-768 (FIPS 203)` as separate algorithms — the first
 * from the measured KEM parameter set, the second as the named post-quantum
 * half of the hybrid construction — and `X25519` / `X25519 (Curve25519 ECDHE)`
 * split the same way. Both the "N algorithms observed" headline and the
 * denominator of the post-quantum share were wrong by one per collision.
 *
 * The trailing parenthetical is a standard reference or an expansion of the
 * name, never a different algorithm, so it is dropped for identity purposes;
 * the longer, more informative string is kept for DISPLAY.
 */
export function censusIdentity(name: string): string {
  return name
    .replace(/\s*\([^()]*\)\s*$/, '')
    .trim()
    .toUpperCase();
}

export function buildAlgorithmCensus(input: AlgorithmCensusInput): AlgorithmCensus {
  const observed = new Map<string, CensusEntry>();

  const add = (rawName: string | null | undefined, roleNoun: string, rank: number) => {
    const name = clean(rawName);
    if (!name || name.toLowerCase() === 'unknown' || name === '-') return;
    /* Node's `getEphemeralKeyInfo()` is empty for TLS 1.3, so `keyExchange`
       degrades to the literal "ECDHE (TLS 1.3 key_share)" on EVERY modern
       endpoint. It names no group, so it is not an observation of one. */
    if (/key_share/i.test(name)) return;

    const identity = censusIdentity(name);
    if (!identity) return;
    const existing = observed.get(identity);
    if (existing) {
      existing.count += 1;
      existing.rank = Math.min(existing.rank, rank);
      /* Keep the more informative spelling — "ML-KEM-768 (FIPS 203)" tells the
         operator the standard; "ML-KEM-768" does not. The role follows the name
         that wins, so the two never describe different things. */
      if (name.length > existing.name.length) {
        existing.name = name;
        if (rank <= existing.rank) {
          const verdict = classifyForCensus(name);
          existing.role = verdict.shorSuffix ? `${roleNoun} - ${verdict.shorSuffix}` : roleNoun;
        }
      }
      return;
    }
    const verdict = classifyForCensus(name);
    observed.set(identity, {
      name,
      role: verdict.shorSuffix ? `${roleNoun} - ${verdict.shorSuffix}` : roleNoun,
      cls: verdict.cls,
      quantumVulnerable: verdict.cls === 'quantum-vulnerable',
      belowPqMargin: verdict.belowPqMargin,
      classicallyBroken: verdict.classicallyBroken,
      legacyProtocol: verdict.legacyProtocol === true,
      count: 1,
      rank,
    });
  };

  for (const observation of input.observations) {
    const { tls, certificate, keyAgreement } = observation;

    /* The measured post-quantum key encapsulation leads the list. The TLS
       analyzer cannot see it — TLS 1.3 negotiates the group in the key_share
       extension, which Node does not expose — so the named-group probe is the
       only source, and it is authoritative. */
    if (keyAgreement?.probed) {
      for (const parameterSet of keyAgreement.kemParameterSets ?? []) {
        add(parameterSet, 'Key encapsulation', RANK.postQuantum);
      }
      if (keyAgreement.kemApplied) {
        add(keyAgreement.group, 'Key agreement', RANK.keyAgreement);
        add(keyAgreement.postQuantumComponent, 'Key encapsulation', RANK.postQuantum);
        add(keyAgreement.classicalComponent, 'Key agreement (classical half)', RANK.keyAgreement);
      } else {
        add(keyAgreement.group, 'Key agreement', RANK.keyAgreement);
      }
    }

    if (certificate) {
      /* The algorithm string is entered VERBATIM. Decorating it with the key
         size here would make this panel disagree with the Certificate Key row
         on the Observed Attack Surface, which prints the same field unmodified
         — and the size is already reported beside it by the Quantum Risk
         Engine ("RSA-2048 (2048-bit)"). */
      add(certificate.publicKeyAlgorithm, 'Certificate public key', RANK.certificateKey);
      add(certificate.signatureAlgorithm, 'Certificate signature', RANK.certificateSignature);
      for (const entry of certificate.chain ?? []) {
        add(entry.publicKeyAlgorithm, 'Chain public key', RANK.chainKey);
      }
    }

    if (tls) {
      // Only when the named-group probe produced nothing to supersede it.
      if (!keyAgreement?.probed || !keyAgreement.group) {
        add(tls.keyExchange, 'Key agreement', RANK.keyAgreement);
      }
      add(tls.negotiatedCurve, 'Named group', RANK.namedGroup);
      add(tls.signatureAlgorithm, 'Handshake signature', RANK.handshakeSignature);
      for (const suite of tls.cipherSuites ?? []) add(suite.encryption, 'Symmetric encryption', RANK.symmetric);
      for (const protocol of tls.supportedProtocols ?? []) add(protocol, 'Transport protocol', RANK.protocol);
    }
  }

  for (const pattern of input.patterns ?? []) {
    const name = clean(pattern.algorithm);
    if (name && !isRuleTitle(name)) add(name, 'Source or dependency', RANK.fallback);
  }

  // Fallback for target types with no transport evidence at all.
  if (observed.size === 0) {
    for (const finding of input.fallbackFindings ?? []) {
      const name = clean(finding.algorithm);
      if (name && !isRuleTitle(name)) add(name, clean(finding.category) || 'Observed', RANK.fallback);
    }
  }

  const entries = Array.from(observed.values()).sort(
    (a, b) => a.rank - b.rank || b.count - a.count || a.name.localeCompare(b.name),
  );

  const postQuantum = entries.filter((entry) => entry.cls === 'post-quantum').length;
  const quantumVulnerable = entries.filter((entry) => entry.cls === 'quantum-vulnerable').length;
  const groverAffected = entries.filter((entry) => entry.cls === 'grover-affected').length;
  const protocols = entries.filter((entry) => entry.cls === 'protocol').length;
  const migrationRelevant = postQuantum + quantumVulnerable;
  const classicallyBroken = entries.filter((entry) => entry.classicallyBroken).map((entry) => entry.name);
  const belowPqMargin = entries.filter((entry) => entry.belowPqMargin).map((entry) => entry.name);
  const legacyProtocols = entries.filter((entry) => entry.legacyProtocol).map((entry) => entry.name);

  const score = scoreCensus({ postQuantum, migrationRelevant, classicallyBroken });

  return {
    entries,
    observed: entries.length,
    postQuantum,
    quantumVulnerable,
    migrationRelevant,
    groverAffected,
    protocols,
    classicallyBroken,
    belowPqMargin,
    legacyProtocols,
    score,
    summary: summarise({
      legacyProtocols,
      observed: entries.length,
      postQuantum,
      quantumVulnerable,
      migrationRelevant,
      groverAffected,
      protocols,
      classicallyBroken,
      belowPqMargin,
    }),
  };
}

/**
 * The published category score.
 *
 * The share of the migration-relevant primitives that are already post-quantum,
 * less a STATED penalty for anything broken by classical cryptanalysis today —
 * a category named "use of modern, secure and PQC algorithms" cannot report a
 * clean number over an estate still serving RC4 or SHA-1.
 *
 * The penalty covers ALGORITHMS only. Deprecated protocol VERSIONS used to be
 * counted here as well, at 25 points each, and `tls-configuration` already
 * scores them at weight 18 — so one observation was charged to two categories
 * and an endpoint measured at 3 of 6 asymmetric primitives post-quantum
 * published 0/100 next to "Key Exchange 100/100". Rule 4: an observation has
 * exactly one owner.
 */
function scoreCensus(input: {
  postQuantum: number;
  migrationRelevant: number;
  classicallyBroken: string[];
}): number | null {
  // Nothing asymmetric was observed: there is no post-quantum share to take.
  // Weight redistributes rather than a filler being invented.
  if (input.migrationRelevant === 0) return null;
  const share = (input.postQuantum / input.migrationRelevant) * 100;
  const penalty = Math.min(100, input.classicallyBroken.length * 25);
  return Math.max(0, Math.min(100, Math.round(share - penalty)));
}

function summarise(counts: {
  observed: number;
  postQuantum: number;
  quantumVulnerable: number;
  migrationRelevant: number;
  groverAffected: number;
  protocols: number;
  classicallyBroken: string[];
  belowPqMargin: string[];
  legacyProtocols: string[];
}): string {
  if (counts.observed === 0) return 'no algorithm was observed on this target';

  const parts: string[] = [`${counts.observed} algorithm${counts.observed === 1 ? '' : 's'} observed`];

  if (counts.migrationRelevant === 0) {
    parts.push('no asymmetric primitive observed, so no post-quantum share can be taken');
  } else {
    parts.push(
      `${counts.postQuantum} of ${counts.migrationRelevant} asymmetric primitive${
        counts.migrationRelevant === 1 ? '' : 's'
      } post-quantum`,
    );
  }

  const notApplicable = counts.groverAffected + counts.protocols;
  if (notApplicable > 0) {
    parts.push(
      `${notApplicable} symmetric/hash/protocol entr${notApplicable === 1 ? 'y' : 'ies'} are not migration candidates`,
    );
  }
  if (counts.classicallyBroken.length) parts.push(`broken today: ${counts.classicallyBroken.join(', ')}`);
  /* Named, but explicitly handed to the category that scores it, so a reader
     comparing this row with TLS Configuration is not left wondering which one
     the penalty landed in. */
  if (counts.legacyProtocols.length) {
    parts.push(`${counts.legacyProtocols.join(', ')} deprecated — scored under TLS Configuration, not here`);
  }
  if (counts.belowPqMargin.length) parts.push(`${counts.belowPqMargin.join(', ')} below the 128-bit PQ margin`);

  return parts.join(' · ');
}
