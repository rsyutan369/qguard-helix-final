/**
 * Quantum Simulation Range — the standards registry.
 *
 * WHY THIS EXISTS
 * ---------------
 * The old simulation page name-dropped "FIPS 203" inside log strings and put
 * invented numbers ("14.7 TB", "~4 Hours") on the screen next to them. A page
 * whose whole job is to teach quantum risk cannot itself be the least accurate
 * artefact in the room.
 *
 * Everything in this file is a PUBLISHED fact: a parameter set from a released
 * FIPS document, a code point from the IANA TLS registry, or a milestone date
 * from a named government publication. Each record carries its own citation so
 * the UI can print the source next to the number.
 *
 * Nothing here is derived, estimated or modelled. Derived values live in
 * `resource-estimator.ts`; measured values are produced at runtime by
 * `pqc-live.ts`. The UI badges the three apart.
 */

/** Where a displayed number came from. The UI must badge every number. */
export type Provenance =
  /** A standards document, registry, or published paper states this exactly. */
  | 'published'
  /** Output of a named model in `resource-estimator.ts`, with its citation. */
  | 'model'
  /** Computed live in this browser during this session. */
  | 'measured';

export interface Citation {
  /** Short label shown inline, e.g. "FIPS 203 §8". */
  label: string;
  /** Full document title. */
  title: string;
  /** Publication or last-update date, ISO. */
  published: string;
  /** Canonical URL. */
  url: string;
}

/* ═══════════════════════════════════════════════════════════════════════════
   1. NIST post-quantum standards
   ═══════════════════════════════════════════════════════════════════════════ */

export const CITATIONS = {
  fips203: {
    label: 'FIPS 203',
    title: 'Module-Lattice-Based Key-Encapsulation Mechanism Standard',
    published: '2024-08-13',
    url: 'https://doi.org/10.6028/NIST.FIPS.203',
  },
  fips204: {
    label: 'FIPS 204',
    title: 'Module-Lattice-Based Digital Signature Standard',
    published: '2024-08-13',
    url: 'https://doi.org/10.6028/NIST.FIPS.204',
  },
  fips205: {
    label: 'FIPS 205',
    title: 'Stateless Hash-Based Digital Signature Standard',
    published: '2024-08-13',
    url: 'https://doi.org/10.6028/NIST.FIPS.205',
  },
  hqc: {
    label: 'NIST PQC Round 4',
    title: 'NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption',
    published: '2025-03-11',
    url: 'https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption',
  },
  ir8547: {
    label: 'NIST IR 8547 ipd',
    title: 'Transition to Post-Quantum Cryptography Standards (initial public draft)',
    published: '2024-11-12',
    url: 'https://doi.org/10.6028/NIST.IR.8547.ipd',
  },
  sp800131a: {
    label: 'SP 800-131A Rev. 2',
    title: 'Transitioning the Use of Cryptographic Algorithms and Key Lengths',
    published: '2019-03-21',
    url: 'https://doi.org/10.6028/NIST.SP.800-131Ar2',
  },
  cnsa2: {
    label: 'CNSA 2.0 FAQ',
    title: 'Commercial National Security Algorithm Suite 2.0 FAQ (NSA), December 2024 Ver. 2.1',
    published: '2024-12-01',
    // The transition timeline lives in the FAQ, not in the September 2022 press
    // release — and the FAQ has been revised twice since (April 2024, December
    // 2024). Cite the current revision, since that is what the dates come from.
    url: 'https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF',
  },
  sp800208: {
    label: 'SP 800-208',
    title: 'Recommendation for Stateful Hash-Based Signature Schemes',
    published: '2020-10-29',
    url: 'https://doi.org/10.6028/NIST.SP.800-208',
  },
  fips206: {
    label: 'NIST PQC Project',
    title: 'Post-Quantum Cryptography Project — FN-DSA (draft FIPS 206) status',
    published: '2026-01-01',
    url: 'https://csrc.nist.gov/projects/post-quantum-cryptography',
  },
  nsm10: {
    label: 'NSM-10',
    title:
      'National Security Memorandum on Promoting United States Leadership in Quantum Computing While Mitigating Risks to Vulnerable Cryptographic Systems',
    published: '2022-05-04',
    url: 'https://bidenwhitehouse.archives.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/',
  },
  ommM2302: {
    label: 'OMB M-23-02',
    title: 'Migrating to Post-Quantum Cryptography',
    published: '2022-11-18',
    url: 'https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf',
  },
  gidneyEkera: {
    label: 'Gidney & Ekerå 2021',
    title: 'How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits',
    published: '2021-04-15',
    url: 'https://doi.org/10.22331/q-2021-04-15-433',
  },
  gidney2025: {
    label: 'Gidney 2025',
    title: 'How to factor 2048 bit RSA integers with less than a million noisy qubits',
    published: '2025-05-21',
    url: 'https://arxiv.org/abs/2505.15917',
  },
  roetteler: {
    label: 'Roetteler et al. 2017',
    title: 'Quantum resource estimates for computing elliptic curve discrete logarithms',
    published: '2017-06-20',
    url: 'https://arxiv.org/abs/1706.06752',
  },
  shor1997: {
    label: 'Shor 1997',
    title: 'Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer',
    published: '1997-10-01',
    url: 'https://doi.org/10.1137/S0097539795293172',
  },
  grover1996: {
    label: 'Grover 1996',
    title: 'A fast quantum mechanical algorithm for database search',
    published: '1996-07-01',
    url: 'https://arxiv.org/abs/quant-ph/9605043',
  },
  mosca: {
    label: 'Mosca 2015',
    title: 'Cybersecurity in an era with quantum computers: will we be ready?',
    published: '2015-05-01',
    url: 'https://eprint.iacr.org/2015/1075',
  },
  ianaGroups: {
    label: 'IANA TLS SupportedGroups',
    title: 'Transport Layer Security (TLS) Parameters — Supported Groups',
    published: '2025-01-01',
    url: 'https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8',
  },
  rfc8446: {
    label: 'RFC 8446',
    title: 'The Transport Layer Security (TLS) Protocol Version 1.3',
    published: '2018-08-01',
    url: 'https://www.rfc-editor.org/rfc/rfc8446',
  },
  hybridDraft: {
    label: 'draft-ietf-tls-ecdhe-mlkem',
    title: 'Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3',
    published: '2025-01-01',
    url: 'https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/',
  },
} as const satisfies Record<string, Citation>;

export type CitationKey = keyof typeof CITATIONS;

/**
 * NIST post-quantum security categories (Call for Proposals, §4.A.5).
 * A category is defined by the classical/quantum cost of attacking a named
 * symmetric primitive — it is NOT a bit count.
 */
export const NIST_SECURITY_CATEGORY: Record<number, { anchor: string; meaning: string }> = {
  1: { anchor: 'AES-128', meaning: 'At least as hard to break as an exhaustive key search on AES-128.' },
  2: { anchor: 'SHA-256 / SHA3-256', meaning: 'At least as hard as finding a collision in SHA-256.' },
  3: { anchor: 'AES-192', meaning: 'At least as hard as an exhaustive key search on AES-192.' },
  4: { anchor: 'SHA-384 / SHA3-384', meaning: 'At least as hard as finding a collision in SHA-384.' },
  5: { anchor: 'AES-256', meaning: 'At least as hard as an exhaustive key search on AES-256.' },
};

export type PqcFamily = 'ml-kem' | 'ml-dsa' | 'slh-dsa' | 'hqc' | 'fn-dsa' | 'lms-xmss';
export type PqcRole = 'kem' | 'signature';
export type StandardStatus = 'final' | 'draft' | 'selected-not-drafted';

export interface PqcParameterSet {
  /**
   * Name as it appears in the standard. ML-KEM and ML-DSA ids are exact; the
   * SLH-DSA ids are the short form shared by that set's two instantiations —
   * FIPS 205 names them SLH-DSA-SHA2-<n><s|f> and SLH-DSA-SHAKE-<n><s|f>, and
   * both have identical key and signature sizes, so one row covers the pair.
   */
  id: string;
  family: PqcFamily;
  role: PqcRole;
  /** NIST post-quantum security category 1..5. */
  category: number;
  /** Byte sizes, exactly as tabulated in the standard. `null` = not fixed / not applicable. */
  sizes: {
    /** Encapsulation key / verification (public) key. */
    publicKey: number;
    /** Decapsulation key / signing (private) key. */
    secretKey: number;
    /** KEM ciphertext. */
    ciphertext: number | null;
    /** Signature. */
    signature: number | null;
    /** Established shared secret. */
    sharedSecret: number | null;
  };
  /** The mathematical problem an attacker must solve. */
  hardness: string;
  citation: CitationKey;
  status: StandardStatus;
  /** One-line note the UI can print under the row. */
  note?: string;
}

/**
 * FIPS 203 — ML-KEM. Sizes are FIPS 203 Table 3.
 * Ring R_q = Z_q[X]/(X^256 + 1) with n = 256, q = 3329.
 */
export const ML_KEM_SETS: PqcParameterSet[] = [
  {
    id: 'ML-KEM-512',
    family: 'ml-kem',
    role: 'kem',
    category: 1,
    sizes: { publicKey: 800, secretKey: 1632, ciphertext: 768, signature: null, sharedSecret: 32 },
    hardness: 'Module Learning With Errors (MLWE), module rank k = 2',
    citation: 'fips203',
    status: 'final',
    note: 'Smallest set. Category 1 only — CNSA 2.0 does not accept it.',
  },
  {
    id: 'ML-KEM-768',
    family: 'ml-kem',
    role: 'kem',
    category: 3,
    sizes: { publicKey: 1184, secretKey: 2400, ciphertext: 1088, signature: null, sharedSecret: 32 },
    hardness: 'Module Learning With Errors (MLWE), module rank k = 3',
    citation: 'fips203',
    status: 'final',
    note: 'The set browsers deploy today, inside the X25519MLKEM768 hybrid group.',
  },
  {
    id: 'ML-KEM-1024',
    family: 'ml-kem',
    role: 'kem',
    category: 5,
    sizes: { publicKey: 1568, secretKey: 3168, ciphertext: 1568, signature: null, sharedSecret: 32 },
    hardness: 'Module Learning With Errors (MLWE), module rank k = 4',
    citation: 'fips203',
    status: 'final',
    note: 'Required by CNSA 2.0 for US national security systems.',
  },
];

/** FIPS 204 — ML-DSA. Sizes are FIPS 204 Table 2. q = 8380417, n = 256. */
export const ML_DSA_SETS: PqcParameterSet[] = [
  {
    id: 'ML-DSA-44',
    family: 'ml-dsa',
    role: 'signature',
    category: 2,
    sizes: { publicKey: 1312, secretKey: 2560, ciphertext: null, signature: 2420, sharedSecret: null },
    hardness: 'MLWE + SelfTargetMSIS, dimensions (k, l) = (4, 4)',
    citation: 'fips204',
    status: 'final',
  },
  {
    id: 'ML-DSA-65',
    family: 'ml-dsa',
    role: 'signature',
    category: 3,
    sizes: { publicKey: 1952, secretKey: 4032, ciphertext: null, signature: 3309, sharedSecret: null },
    hardness: 'MLWE + SelfTargetMSIS, dimensions (k, l) = (6, 5)',
    citation: 'fips204',
    status: 'final',
  },
  {
    id: 'ML-DSA-87',
    family: 'ml-dsa',
    role: 'signature',
    category: 5,
    sizes: { publicKey: 2592, secretKey: 4896, ciphertext: null, signature: 4627, sharedSecret: null },
    hardness: 'MLWE + SelfTargetMSIS, dimensions (k, l) = (8, 7)',
    citation: 'fips204',
    status: 'final',
    note: 'Required by CNSA 2.0 for US national security systems.',
  },
];

/**
 * FIPS 205 — SLH-DSA. Sizes are FIPS 205 Table 2 and are identical for the
 * SHA2 and SHAKE instantiations of each parameter set, so `SLH-DSA-128s` below
 * stands for both SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-128s. The live benchmark
 * in `pqc-live.ts` runs the SHA2 instantiation.
 * `s` = small signature / slow signing. `f` = fast signing / large signature.
 */
export const SLH_DSA_SETS: PqcParameterSet[] = [
  {
    id: 'SLH-DSA-128s',
    family: 'slh-dsa',
    role: 'signature',
    category: 1,
    sizes: { publicKey: 32, secretKey: 64, ciphertext: null, signature: 7856, sharedSecret: null },
    hardness: 'Hash-function security only — second-preimage and target-collision resistance of the tweakable hash',
    citation: 'fips205',
    status: 'final',
    note: 'FIPS 205 names this pair SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-128s; both have these exact sizes.',
  },
  {
    id: 'SLH-DSA-128f',
    family: 'slh-dsa',
    role: 'signature',
    category: 1,
    sizes: { publicKey: 32, secretKey: 64, ciphertext: null, signature: 17088, sharedSecret: null },
    hardness: 'Hash-function security only — second-preimage and target-collision resistance of the tweakable hash',
    citation: 'fips205',
    status: 'final',
  },
  {
    id: 'SLH-DSA-192s',
    family: 'slh-dsa',
    role: 'signature',
    category: 3,
    sizes: { publicKey: 48, secretKey: 96, ciphertext: null, signature: 16224, sharedSecret: null },
    hardness: 'Hash-function security only — second-preimage and target-collision resistance of the tweakable hash',
    citation: 'fips205',
    status: 'final',
  },
  {
    id: 'SLH-DSA-192f',
    family: 'slh-dsa',
    role: 'signature',
    category: 3,
    sizes: { publicKey: 48, secretKey: 96, ciphertext: null, signature: 35664, sharedSecret: null },
    hardness: 'Hash-function security only — second-preimage and target-collision resistance of the tweakable hash',
    citation: 'fips205',
    status: 'final',
  },
  {
    id: 'SLH-DSA-256s',
    family: 'slh-dsa',
    role: 'signature',
    category: 5,
    sizes: { publicKey: 64, secretKey: 128, ciphertext: null, signature: 29792, sharedSecret: null },
    hardness: 'Hash-function security only — second-preimage and target-collision resistance of the tweakable hash',
    citation: 'fips205',
    status: 'final',
  },
  {
    id: 'SLH-DSA-256f',
    family: 'slh-dsa',
    role: 'signature',
    category: 5,
    sizes: { publicKey: 64, secretKey: 128, ciphertext: null, signature: 49856, sharedSecret: null },
    hardness: 'Hash-function security only — second-preimage and target-collision resistance of the tweakable hash',
    citation: 'fips205',
    status: 'final',
    note: 'Largest signature in the suite. Chosen when the only assumption you will accept is a hash function.',
  },
];

export const PQC_SETS: PqcParameterSet[] = [...ML_KEM_SETS, ...ML_DSA_SETS, ...SLH_DSA_SETS];

/** Standards that are selected or drafted but not yet published as a FIPS. */
export interface PendingStandard {
  id: string;
  role: PqcRole;
  status: StandardStatus;
  summary: string;
  citation: CitationKey;
}

export const PENDING_STANDARDS: PendingStandard[] = [
  {
    id: 'HQC',
    role: 'kem',
    status: 'selected-not-drafted',
    summary:
      'Code-based backup KEM selected 11 Mar 2025. Chosen because its hardness rests on error-correcting codes rather than lattices, so a break of ML-KEM would not carry over. Draft standard expected 2026, final expected 2027.',
    citation: 'hqc',
  },
  {
    id: 'FN-DSA (FALCON)',
    role: 'signature',
    status: 'draft',
    summary:
      'NTRU-lattice signature scheme selected in 2022 for the smallest signatures of the finalists. NIST submitted draft FIPS 206 for approval in August 2025, but no draft has yet been published for public comment; its floating-point Gaussian sampler makes constant-time implementation the hard part.',
    citation: 'fips206',
  },
  {
    id: 'LMS / XMSS (SP 800-208)',
    role: 'signature',
    status: 'final',
    summary:
      'Stateful hash-based signatures, specified by SP 800-208 and already required by CNSA 2.0 for software and firmware signing. Stateful: reusing a one-time key destroys security, so they are only safe where signing state can be guaranteed.',
    citation: 'sp800208',
  },
];

/* ═══════════════════════════════════════════════════════════════════════════
   2. Transition milestones — the dates the countdown is built from
   ═══════════════════════════════════════════════════════════════════════════ */

export type MilestoneSeverity = 'info' | 'deadline' | 'hard-stop';

export interface TransitionMilestone {
  id: string;
  /** ISO date the milestone takes effect. */
  date: string;
  authority: 'NIST' | 'NSA' | 'White House' | 'OMB';
  title: string;
  detail: string;
  severity: MilestoneSeverity;
  citation: CitationKey;
}

/**
 * Real, published dates. The hero countdown ticks against these — it does not
 * count down to an invented "Q-Day", because nobody has published one.
 *
 * Milestones worded "AFTER <year>" use 1 January of the following year, because
 * the restriction bites once that year is over: IR 8547's "deprecated after
 * 2030" is 2031-01-01 and its "disallowed after 2035" is 2036-01-01.
 * Milestones worded "BY <year>" use 1 January of the year itself, which is the
 * conservative reading: CNSA 2.0's exclusive-use dates and NSM-10's 2035 target
 * are encoded that way. The timeline prints the stored year, so an "after"
 * milestone shows one year later than the figure quoted in its source text —
 * the detail line on each entry carries the source's own wording.
 */
export const TRANSITION_MILESTONES: TransitionMilestone[] = [
  {
    id: 'cnsa-sw-signing',
    date: '2025-01-01',
    authority: 'NSA',
    title: 'CNSA 2.0 — software and firmware signing support',
    detail:
      'National security systems must support and prefer CNSA 2.0 algorithms for signing software and firmware (LMS or XMSS, per SP 800-208). Exclusive use required by 2030.',
    severity: 'info',
    citation: 'cnsa2',
  },
  {
    id: 'cnsa-web-support',
    date: '2025-01-01',
    authority: 'NSA',
    title: 'CNSA 2.0 — browsers, servers and cloud services support',
    detail: 'Web browsers, servers and cloud services supporting NSS must support CNSA 2.0. Exclusive use required by 2033.',
    severity: 'info',
    citation: 'cnsa2',
  },
  {
    id: 'cnsa-network-support',
    date: '2026-01-01',
    authority: 'NSA',
    title: 'CNSA 2.0 — networking equipment support',
    detail: 'VPN concentrators, routers and other traditional networking equipment must support CNSA 2.0. Exclusive use required by 2030.',
    severity: 'info',
    citation: 'cnsa2',
  },
  {
    id: 'cnsa-os-support',
    date: '2027-01-01',
    authority: 'NSA',
    title: 'CNSA 2.0 — operating systems support',
    detail: 'Operating systems used in national security systems must support CNSA 2.0. Exclusive use required by 2033.',
    severity: 'info',
    citation: 'cnsa2',
  },
  {
    id: 'ir8547-deprecate',
    date: '2031-01-01',
    authority: 'NIST',
    title: '112-bit-strength RSA, ECDSA, ECDH and finite-field DH deprecated',
    detail:
      'NIST IR 8547 ipd deprecates public-key algorithms at the 112-bit classical security strength after 2030 — RSA-2048, finite-field DH/MQV-2048, and ECDH/ECDSA on 224-bit curves. Deprecated means: still permitted, but the user must accept the associated security risk (SP 800-131A definition). Algorithms at 128-bit strength and above (RSA-3072 and larger, P-256, P-384, X25519, Ed25519) get no deprecation step — they are disallowed outright after 2035.',
    severity: 'deadline',
    citation: 'ir8547',
  },
  {
    id: 'cnsa-network-exclusive',
    date: '2030-01-01',
    authority: 'NSA',
    title: 'CNSA 2.0 exclusive — networking equipment and signing',
    detail: 'Networking equipment and software/firmware signing for national security systems must use CNSA 2.0 algorithms exclusively.',
    severity: 'deadline',
    citation: 'cnsa2',
  },
  {
    id: 'cnsa-web-exclusive',
    date: '2033-01-01',
    authority: 'NSA',
    title: 'CNSA 2.0 exclusive — browsers, servers, cloud, operating systems',
    detail: 'Exclusive CNSA 2.0 use required across web infrastructure and operating systems supporting national security systems.',
    severity: 'deadline',
    citation: 'cnsa2',
  },
  {
    id: 'ir8547-disallow',
    date: '2036-01-01',
    authority: 'NIST',
    title: 'Quantum-vulnerable public-key cryptography disallowed',
    detail:
      'NIST IR 8547 ipd disallows RSA, ECDSA, EdDSA, DH and ECDH at every key size after 2035. Disallowed means the algorithm may no longer be used to apply cryptographic protection under NIST guidance. IR 8547 is still an initial public draft, so these dates are proposed rather than final.',
    severity: 'hard-stop',
    citation: 'ir8547',
  },
  {
    id: 'nsm10-2035',
    date: '2035-01-01',
    authority: 'White House',
    title: 'NSM-10 — federal quantum-risk mitigation target',
    detail: 'National Security Memorandum 10 sets 2035 as the target for mitigating quantum risk across federal systems to the maximum extent feasible.',
    severity: 'hard-stop',
    citation: 'nsm10',
  },
];

export interface MilestoneClock {
  milestone: TransitionMilestone;
  /** Milliseconds remaining. Negative once the date has passed. */
  remainingMs: number;
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
  elapsed: boolean;
}

/** Time remaining to a milestone, evaluated against a caller-supplied clock. */
export function milestoneClock(milestone: TransitionMilestone, now: number = Date.now()): MilestoneClock {
  const target = Date.parse(`${milestone.date}T00:00:00Z`);
  const remainingMs = target - now;
  const abs = Math.abs(remainingMs);
  return {
    milestone,
    remainingMs,
    days: Math.floor(abs / 86_400_000),
    hours: Math.floor((abs % 86_400_000) / 3_600_000),
    minutes: Math.floor((abs % 3_600_000) / 60_000),
    seconds: Math.floor((abs % 60_000) / 1000),
    elapsed: remainingMs <= 0,
  };
}

/** The next milestone that has not yet passed, or the final one if all have. */
export function nextMilestone(now: number = Date.now()): TransitionMilestone {
  const upcoming = [...TRANSITION_MILESTONES]
    .sort((a, b) => Date.parse(a.date) - Date.parse(b.date))
    .find((m) => Date.parse(`${m.date}T00:00:00Z`) > now);
  return upcoming ?? TRANSITION_MILESTONES[TRANSITION_MILESTONES.length - 1];
}

/* ═══════════════════════════════════════════════════════════════════════════
   3. IANA TLS named groups — the wire-level evidence of a hybrid handshake
   ═══════════════════════════════════════════════════════════════════════════ */

export type GroupKind = 'classical' | 'hybrid' | 'pure-pqc';

export interface NamedGroup {
  /** IANA code point. */
  id: number;
  name: string;
  kind: GroupKind;
  /** Client key_share length in bytes for this group. */
  clientShareBytes: number;
  /** Server key_share length in bytes for this group. */
  serverShareBytes: number;
  /** Classical security in bits against a conventional attacker. */
  classicalBits: number;
  /** True if a cryptographically relevant quantum computer breaks it. */
  quantumBroken: boolean;
  note: string;
}

/**
 * Only the groups that matter to this page. `clientShareBytes` for the hybrids
 * is the concatenation defined in draft-ietf-tls-ecdhe-mlkem: for
 * X25519MLKEM768 the ML-KEM part comes FIRST, for the SecP* hybrids the ECDH
 * part comes first. The lengths are the same either way.
 */
export const TLS_NAMED_GROUPS: NamedGroup[] = [
  {
    id: 0x0017,
    name: 'secp256r1',
    kind: 'classical',
    clientShareBytes: 65,
    serverShareBytes: 65,
    classicalBits: 128,
    quantumBroken: true,
    note: 'NIST P-256 ECDH. Shor solves the elliptic-curve discrete log; the recorded handshake is decryptable later.',
  },
  {
    id: 0x0018,
    name: 'secp384r1',
    kind: 'classical',
    clientShareBytes: 97,
    serverShareBytes: 97,
    classicalBits: 192,
    quantumBroken: true,
    note: 'A larger curve buys nothing against Shor — the cost grows only polynomially.',
  },
  {
    id: 0x001d,
    name: 'x25519',
    kind: 'classical',
    clientShareBytes: 32,
    serverShareBytes: 32,
    classicalBits: 128,
    quantumBroken: true,
    note: 'The most widely deployed classical group on the public web, and fully quantum-vulnerable.',
  },
  {
    id: 0x11eb,
    name: 'SecP256r1MLKEM768',
    kind: 'hybrid',
    clientShareBytes: 65 + 1184,
    serverShareBytes: 65 + 1088,
    classicalBits: 128,
    quantumBroken: false,
    note: 'ECDH share first, then the ML-KEM-768 encapsulation key. Safe if EITHER component holds.',
  },
  {
    id: 0x11ec,
    name: 'X25519MLKEM768',
    kind: 'hybrid',
    clientShareBytes: 1184 + 32,
    serverShareBytes: 1088 + 32,
    classicalBits: 128,
    quantumBroken: false,
    note: 'The group Chrome, Firefox and Cloudflare enabled by default. ML-KEM-768 key first, then X25519.',
  },
  {
    id: 0x11ed,
    name: 'SecP384r1MLKEM1024',
    kind: 'hybrid',
    clientShareBytes: 97 + 1568,
    serverShareBytes: 97 + 1568,
    classicalBits: 192,
    quantumBroken: false,
    note: 'CNSA 2.0-aligned hybrid for national security systems.',
  },
];

export function namedGroup(id: number): NamedGroup | undefined {
  return TLS_NAMED_GROUPS.find((g) => g.id === id);
}

/** TLS 1.3 cipher suites (RFC 8446 §B.4). Symmetric — none of these is broken by a quantum computer. */
export const TLS13_CIPHER_SUITES = [
  { id: 0x1301, name: 'TLS_AES_128_GCM_SHA256', aead: 'AES-128-GCM', keyBits: 128 },
  { id: 0x1302, name: 'TLS_AES_256_GCM_SHA384', aead: 'AES-256-GCM', keyBits: 256 },
  { id: 0x1303, name: 'TLS_CHACHA20_POLY1305_SHA256', aead: 'ChaCha20-Poly1305', keyBits: 256 },
] as const;

/* ═══════════════════════════════════════════════════════════════════════════
   4. Lookups
   ═══════════════════════════════════════════════════════════════════════════ */

export function pqcSet(id: string): PqcParameterSet | undefined {
  return PQC_SETS.find((s) => s.id === id);
}

export function pqcSetsForCategory(category: number): PqcParameterSet[] {
  return PQC_SETS.filter((s) => s.category === category);
}

/** Format a byte count the way the standards tables do. */
export function formatBytes(bytes: number | null): string {
  if (bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(2)} KiB`;
}
