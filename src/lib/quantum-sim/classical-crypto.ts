/**
 * Quantum Simulation Range — what a quantum computer actually does to each
 * classical primitive.
 *
 * WHY THIS EXISTS
 * ---------------
 * The single most common error in "quantum attack" material — including the
 * page this replaces — is treating "quantum" as a solvent that dissolves all
 * cryptography. It does not. There are exactly two relevant quantum algorithms
 * and they do very different things:
 *
 *   Shor   — turns factoring and discrete logarithm from sub-exponential into
 *            POLYNOMIAL time. This is a break. RSA, DH, ECDH, ECDSA, EdDSA all
 *            fail completely, at every key size.
 *
 *   Grover — turns an unstructured search of N items into √N. This is a
 *            quadratic speed-up, not a break. AES-256 retains ~128 bits of
 *            quantum security, which is not attackable. AES-128 drops to a
 *            nominal 2^64 — but see `GROVER_REALITY` below, because that number
 *            is misleading in a way that matters.
 *
 * Hashes and symmetric ciphers survive. Public-key cryptography does not. Every
 * verdict in this file is derived from that distinction, not asserted.
 */

import type { CitationKey } from './nist-standards';

export type QuantumAttack = 'shor' | 'grover' | 'none';
export type QuantumVerdict =
  /** Completely broken. The algorithm has no security left against a CRQC. */
  | 'broken'
  /** Security is reduced but the remaining margin is still infeasible. */
  | 'reduced'
  /** No known quantum speed-up beyond generic search; effectively unaffected. */
  | 'safe';

export type PrimitiveRole = 'key-exchange' | 'signature' | 'encryption' | 'hash' | 'mac' | 'kdf';

export interface ClassicalPrimitive {
  id: string;
  name: string;
  role: PrimitiveRole;
  /** Security in bits against the best known conventional attack. */
  classicalBits: number;
  /**
   * Security in bits against the best known quantum attack, ignoring hardware
   * limits. For Shor-broken primitives this is 0 by definition.
   */
  quantumBits: number;
  attack: QuantumAttack;
  verdict: QuantumVerdict;
  /** The mathematical object the attacker recovers. */
  target: string;
  /** How the quantum algorithm applies here, in one sentence. */
  mechanism: string;
  /** What replaces it, per NIST. Empty when nothing needs replacing. */
  replacement: string;
  /**
   * NIST IR 8547 ipd status: the year after which it is deprecated / disallowed.
   *
   * IR 8547 scopes these by SECURITY STRENGTH, not by algorithm family. Only the
   * 112-bit rows (RSA-2048, finite-field DH/MQV-2048, ECDH/ECMQV and ECDSA at
   * 112-bit strength) are "deprecated after 2030, disallowed after 2035".
   * Everything at 128-bit strength and above — RSA-3072 and larger, P-256,
   * P-384, X25519, Ed25519 — is "disallowed after 2035" with NO deprecation
   * step, so `deprecatedAfter` is null for those. See IR 8547 ipd Tables 2 & 4.
   */
  transition: { deprecatedAfter: number | null; disallowedAfter: number | null };
  citation: CitationKey;
}

/**
 * `quantumBits` for Grover targets is the idealised √N figure (keyBits / 2).
 * It is reported because it is what NIST's own category definitions use, but
 * `GROVER_REALITY` must be shown next to it — see below.
 */
export const CLASSICAL_PRIMITIVES: ClassicalPrimitive[] = [
  /* ── Shor: completely broken ─────────────────────────────────────────── */
  {
    id: 'rsa-2048',
    name: 'RSA-2048',
    role: 'key-exchange',
    classicalBits: 112,
    quantumBits: 0,
    attack: 'shor',
    verdict: 'broken',
    target: 'the private exponent d, via the prime factors p, q of the modulus N',
    mechanism:
      "Shor's order-finding recovers the multiplicative order r of a random a modulo N; gcd(a^(r/2) ± 1, N) then yields p and q, from which d follows by inverting e modulo φ(N).",
    replacement: 'ML-KEM-768 or ML-KEM-1024 (FIPS 203) for key establishment; ML-DSA (FIPS 204) for signatures',
    transition: { deprecatedAfter: 2030, disallowedAfter: 2035 },
    citation: 'shor1997',
  },
  {
    id: 'rsa-3072',
    name: 'RSA-3072',
    role: 'key-exchange',
    classicalBits: 128,
    quantumBits: 0,
    attack: 'shor',
    verdict: 'broken',
    target: 'the private exponent d',
    mechanism:
      "Identical to RSA-2048. Shor's cost grows as roughly n^3 in the modulus size, so a 50% larger modulus costs an attacker about 3.4x more — a rounding error against an exponential defence budget.",
    replacement: 'ML-KEM-1024 (FIPS 203)',
    transition: { deprecatedAfter: null, disallowedAfter: 2035 },
    citation: 'shor1997',
  },
  {
    id: 'rsa-4096',
    name: 'RSA-4096',
    role: 'key-exchange',
    classicalBits: 152,
    quantumBits: 0,
    attack: 'shor',
    verdict: 'broken',
    target: 'the private exponent d',
    mechanism:
      'Doubling the modulus from 2048 to 4096 bits multiplies the classical cost by roughly 2^40 but the quantum cost by only about 8. Key-size escalation is not a defence against Shor. Note that 152 bits is an interpolation, not a published figure: SP 800-57 tabulates 2048 (112 bits), 3072 (128) and 7680 (192) and does not list 4096.',
    replacement: 'ML-KEM-1024 (FIPS 203)',
    transition: { deprecatedAfter: null, disallowedAfter: 2035 },
    citation: 'shor1997',
  },
  {
    id: 'ecdh-p256',
    name: 'ECDH P-256 / X25519',
    role: 'key-exchange',
    classicalBits: 128,
    quantumBits: 0,
    attack: 'shor',
    verdict: 'broken',
    target: 'the private scalar k in Q = kG',
    mechanism:
      "Shor's discrete-logarithm variant recovers k directly. Elliptic curves are CHEAPER to break than RSA at equivalent classical strength: about 2,330 logical qubits for P-256 against roughly 6,190 for RSA-2048.",
    replacement: 'X25519MLKEM768 hybrid (IANA 0x11EC) now; ML-KEM-768 alone once hybrids are retired',
    transition: { deprecatedAfter: null, disallowedAfter: 2035 },
    citation: 'roetteler',
  },
  {
    id: 'ecdsa-p256',
    name: 'ECDSA P-256',
    role: 'signature',
    classicalBits: 128,
    quantumBits: 0,
    attack: 'shor',
    verdict: 'broken',
    target: 'the long-term signing key',
    mechanism:
      'Same discrete-log break as ECDH. A recovered signing key lets an attacker forge signatures indistinguishable from real ones — which means code-signing and certificate chains fail silently rather than loudly.',
    replacement: 'ML-DSA-65 / ML-DSA-87 (FIPS 204), or SLH-DSA (FIPS 205) where only hash assumptions are acceptable',
    transition: { deprecatedAfter: null, disallowedAfter: 2035 },
    citation: 'roetteler',
  },
  {
    id: 'ecdsa-p384',
    name: 'ECDSA P-384',
    role: 'signature',
    classicalBits: 192,
    quantumBits: 0,
    attack: 'shor',
    verdict: 'broken',
    target: 'the long-term signing key',
    mechanism: 'A 384-bit curve raises the quantum cost by roughly 3.6x over P-256. It does not change the outcome.',
    replacement: 'ML-DSA-87 (FIPS 204)',
    transition: { deprecatedAfter: null, disallowedAfter: 2035 },
    citation: 'roetteler',
  },
  {
    id: 'dh-2048',
    name: 'Finite-field DH 2048',
    role: 'key-exchange',
    classicalBits: 112,
    quantumBits: 0,
    attack: 'shor',
    verdict: 'broken',
    target: 'the discrete logarithm x in g^x mod p',
    mechanism: "Shor's discrete-logarithm algorithm applies to any finite cyclic group, including the multiplicative group modulo a prime.",
    replacement: 'ML-KEM (FIPS 203)',
    transition: { deprecatedAfter: 2030, disallowedAfter: 2035 },
    citation: 'shor1997',
  },

  /* ── Grover: reduced, not broken ─────────────────────────────────────── */
  {
    id: 'aes-128',
    name: 'AES-128',
    role: 'encryption',
    classicalBits: 128,
    quantumBits: 64,
    attack: 'grover',
    verdict: 'reduced',
    target: 'the symmetric key, by exhaustive search',
    mechanism:
      "Grover's search finds a 128-bit key in about 2^64 quantum evaluations of AES. That number is nominal: the search is inherently sequential, so it cannot be spread across machines the way a classical key search can.",
    replacement: 'None required by NIST — AES-128 remains approved. Use AES-256 where CNSA 2.0 applies or for long-lived data',
    transition: { deprecatedAfter: null, disallowedAfter: null },
    citation: 'grover1996',
  },
  {
    id: 'aes-256',
    name: 'AES-256',
    role: 'encryption',
    classicalBits: 256,
    quantumBits: 128,
    attack: 'grover',
    verdict: 'safe',
    target: 'the symmetric key, by exhaustive search',
    mechanism:
      'Grover reduces AES-256 to a nominal 2^128 quantum operations. That is not an attack anyone can mount — it is the same margin that makes AES-128 safe classically today.',
    replacement: 'None. AES-256 is the CNSA 2.0 symmetric algorithm.',
    transition: { deprecatedAfter: null, disallowedAfter: null },
    citation: 'grover1996',
  },
  {
    id: 'sha-256',
    name: 'SHA-256',
    role: 'hash',
    classicalBits: 128,
    quantumBits: 128,
    attack: 'none',
    verdict: 'safe',
    target: 'a collision',
    mechanism:
      'Collision search is already the birthday bound at 2^128 classically. The best quantum collision algorithms do not improve on this once the memory they need is priced in, so the practical security is unchanged.',
    replacement: 'SHA-384 or SHA-512 where CNSA 2.0 applies',
    transition: { deprecatedAfter: null, disallowedAfter: null },
    citation: 'grover1996',
  },
  {
    id: 'sha3-256',
    name: 'SHA3-256',
    role: 'hash',
    classicalBits: 128,
    quantumBits: 128,
    attack: 'none',
    verdict: 'safe',
    target: 'a collision',
    mechanism: 'Same position as SHA-256. SHA-3/SHAKE is also what FIPS 203 and FIPS 204 build their sampling and hashing on, as do the SHAKE parameter sets of FIPS 205.',
    replacement: 'None',
    transition: { deprecatedAfter: null, disallowedAfter: null },
    citation: 'grover1996',
  },
  {
    id: 'hmac-sha256',
    name: 'HMAC-SHA-256',
    role: 'mac',
    classicalBits: 256,
    quantumBits: 128,
    attack: 'grover',
    verdict: 'safe',
    target: 'the MAC key',
    mechanism: 'Key recovery is a Grover search over the key space. With a full-length key the remaining margin is 2^128.',
    replacement: 'None',
    transition: { deprecatedAfter: null, disallowedAfter: null },
    citation: 'grover1996',
  },
];

/**
 * The correction that stops the Grover number being misread.
 *
 * NIST's own analysis of the security categories makes the point that Grover
 * parallelises terribly: running it on m machines gives only a √m speed-up, so
 * a thousand quantum computers buy you a factor of ~32, not 1,000. Combined
 * with a MAXDEPTH bound on circuit depth, an attack on AES-128 that the naive
 * 2^64 figure suggests is feasible turns out not to be.
 */
export const GROVER_REALITY = {
  headline: 'Grover does not parallelise.',
  detail:
    'Splitting a Grover search across m quantum computers yields only a sqrt(m) speed-up, against the linear speed-up a classical key search enjoys. NIST therefore bounds attacks by a maximum circuit depth (MAXDEPTH) of 2^40 to 2^96 gates. Under that bound, even AES-128 is not practically searchable, and AES-256 is far outside reach.',
  practicalGuidance: 'NIST continues to approve AES-128/192/256 and SHA-2/SHA-3, so no algorithm replacement is needed. CNSA 2.0 systems, and data that must stay secret for decades, should use AES-256 and SHA-384/SHA-512.',
} as const;

export function primitive(id: string): ClassicalPrimitive | undefined {
  return CLASSICAL_PRIMITIVES.find((p) => p.id === id);
}

export function primitivesByVerdict(verdict: QuantumVerdict): ClassicalPrimitive[] {
  return CLASSICAL_PRIMITIVES.filter((p) => p.verdict === verdict);
}

/* ═══════════════════════════════════════════════════════════════════════════
   Complexity curves — the actual reason Shor matters
   ═══════════════════════════════════════════════════════════════════════════ */

/**
 * General Number Field Sieve: the best known classical factoring algorithm.
 *
 *   L_n[1/3, (64/9)^(1/3)] = exp( (64/9)^(1/3) * (ln n)^(1/3) * (ln ln n)^(2/3) )
 *
 * @param bits modulus size in bits
 * @returns log2 of the operation count — i.e. the effective security in bits
 */
export function gnfsCostBits(bits: number): number {
  const lnN = bits * Math.LN2;
  const c = Math.cbrt(64 / 9);
  const exponent = c * Math.cbrt(lnN) * Math.pow(Math.log(lnN), 2 / 3);
  return exponent / Math.LN2;
}

/**
 * Shor's factoring cost, expressed the same way so the two can be plotted on
 * one axis. The gate count is polynomial: the Gidney-Ekerå circuit is
 * 0.3 n^3 + 0.0005 n^3 lg n Toffoli gates.
 *
 * @param bits modulus size in bits
 * @returns log2 of the Toffoli count
 */
export function shorCostBits(bits: number): number {
  const toffoli = 0.3 * bits ** 3 + 0.0005 * bits ** 3 * Math.log2(bits);
  return Math.log2(toffoli);
}

/** Pollard's rho on an elliptic curve: sqrt of the group order. */
export function ecdlpClassicalCostBits(curveBits: number): number {
  return curveBits / 2;
}

/**
 * Shor on an elliptic curve, via the Roetteler et al. gate-count fit.
 * See `resource-estimator.ts` for the fitted constant and its calibration.
 */
export function ecdlpQuantumCostBits(curveBits: number): number {
  const toffoli = 940 * curveBits ** 3 * Math.log2(curveBits);
  return Math.log2(toffoli);
}

export interface ComplexityPoint {
  bits: number;
  classical: number;
  quantum: number;
}

/** Sample both curves across a key-size range, for the comparison chart. */
export function complexityCurve(
  kind: 'rsa' | 'ecc',
  from: number,
  to: number,
  steps = 24,
): ComplexityPoint[] {
  const points: ComplexityPoint[] = [];
  for (let i = 0; i <= steps; i += 1) {
    const bits = Math.round(from + ((to - from) * i) / steps);
    points.push({
      bits,
      classical: kind === 'rsa' ? gnfsCostBits(bits) : ecdlpClassicalCostBits(bits),
      quantum: kind === 'rsa' ? shorCostBits(bits) : ecdlpQuantumCostBits(bits),
    });
  }
  return points;
}
