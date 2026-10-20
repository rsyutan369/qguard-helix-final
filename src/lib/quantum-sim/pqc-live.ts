/**
 * Quantum Simulation Range — real post-quantum cryptography, executed here.
 *
 * WHY THIS EXISTS
 * ---------------
 * Everything else on this page is either a published fact or a model. This
 * module is the third provenance tier: MEASURED. It runs genuine FIPS 203/204/205
 * operations in the visitor's own browser, using the same open-source
 * `@noble/post-quantum` implementation the platform's Quantum Vault and
 * certification engine depend on, and reports the byte lengths and timings it
 * actually observed.
 *
 * That matters for two reasons:
 *
 *   1. The key sizes on the page stop being a table someone typed. If the
 *      encapsulation key the browser just produced is not 1,184 bytes, the page
 *      says so — `verifyAgainstStandard()` compares live output against the
 *      FIPS 203 Table 3 values in `nist-standards.ts`.
 *
 *   2. "Post-quantum cryptography is too slow" is the most common objection to
 *      migrating, and it is usually wrong by two orders of magnitude. A number
 *      measured on the reader's own laptop settles it better than any claim.
 *
 * All of these are synchronous and fast (single-digit milliseconds for ML-KEM
 * and ML-DSA). SLH-DSA signing is deliberately slow by design and is measured
 * with a smaller sample count.
 */

import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128f, slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { pqcSet, type PqcParameterSet } from './nist-standards';

/* ═══════════════════════════════════════════════════════════════════════════
   Algorithm registry
   ═══════════════════════════════════════════════════════════════════════════ */

type KemPrimitive = typeof ml_kem768;
type SignPrimitive = typeof ml_dsa65;

const KEMS: Record<string, KemPrimitive> = {
  'ML-KEM-512': ml_kem512,
  'ML-KEM-768': ml_kem768,
  'ML-KEM-1024': ml_kem1024,
};

const SIGNERS: Record<string, SignPrimitive> = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87,
  'SLH-DSA-128s': slh_dsa_sha2_128s as unknown as SignPrimitive,
  'SLH-DSA-128f': slh_dsa_sha2_128f as unknown as SignPrimitive,
};

export const LIVE_KEM_IDS = Object.keys(KEMS);
export const LIVE_SIGNER_IDS = Object.keys(SIGNERS);

function now(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

/* ═══════════════════════════════════════════════════════════════════════════
   Key encapsulation — the ML-KEM handshake, executed
   ═══════════════════════════════════════════════════════════════════════════ */

export interface KemExchange {
  algorithm: string;
  /** FIPS 203 Table 3 record this run should match. */
  standard: PqcParameterSet | undefined;
  encapsulationKey: Uint8Array;
  decapsulationKey: Uint8Array;
  ciphertext: Uint8Array;
  /** The secret the initiator derived. */
  sharedSecretInitiator: Uint8Array;
  /** The secret the responder derived, independently. */
  sharedSecretResponder: Uint8Array;
  /** True when both sides landed on the same 32 bytes, checked byte by byte. */
  agreed: boolean;
  timings: { keygenMs: number; encapsulateMs: number; decapsulateMs: number; totalMs: number };
  /** Live byte lengths compared against the published table. */
  sizeCheck: SizeCheck[];
}

export interface SizeCheck {
  field: string;
  observed: number;
  published: number | null;
  matches: boolean;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Perform a complete ML-KEM key encapsulation, both sides, right now.
 *
 * This is the exact operation that replaces the ECDHE key agreement a quantum
 * computer would break: the responder encapsulates a shared secret to the
 * initiator's public key, and both derive the same 32 bytes without either ever
 * transmitting them.
 */
export function runKemExchange(algorithm = 'ML-KEM-768'): KemExchange {
  const kem = KEMS[algorithm];
  if (!kem) throw new Error(`Unknown KEM: ${algorithm}`);
  const standard = pqcSet(algorithm);

  const t0 = now();
  const keys = kem.keygen();
  const t1 = now();
  const { cipherText, sharedSecret } = kem.encapsulate(keys.publicKey);
  const t2 = now();
  const recovered = kem.decapsulate(cipherText, keys.secretKey);
  const t3 = now();

  const sizeCheck: SizeCheck[] = [
    { field: 'Encapsulation key', observed: keys.publicKey.length, published: standard?.sizes.publicKey ?? null, matches: keys.publicKey.length === standard?.sizes.publicKey },
    { field: 'Decapsulation key', observed: keys.secretKey.length, published: standard?.sizes.secretKey ?? null, matches: keys.secretKey.length === standard?.sizes.secretKey },
    { field: 'Ciphertext', observed: cipherText.length, published: standard?.sizes.ciphertext ?? null, matches: cipherText.length === standard?.sizes.ciphertext },
    { field: 'Shared secret', observed: sharedSecret.length, published: standard?.sizes.sharedSecret ?? null, matches: sharedSecret.length === standard?.sizes.sharedSecret },
  ];

  return {
    algorithm,
    standard,
    encapsulationKey: keys.publicKey,
    decapsulationKey: keys.secretKey,
    ciphertext: cipherText,
    sharedSecretInitiator: sharedSecret,
    sharedSecretResponder: recovered,
    agreed: constantTimeEqual(sharedSecret, recovered),
    timings: { keygenMs: t1 - t0, encapsulateMs: t2 - t1, decapsulateMs: t3 - t2, totalMs: t3 - t0 },
    sizeCheck,
  };
}

/* ═══════════════════════════════════════════════════════════════════════════
   Signatures
   ═══════════════════════════════════════════════════════════════════════════ */

export interface SignatureRun {
  algorithm: string;
  standard: PqcParameterSet | undefined;
  publicKey: Uint8Array;
  signature: Uint8Array;
  message: string;
  valid: boolean;
  /** A single flipped bit in the message must invalidate the signature. */
  tamperDetected: boolean;
  timings: { keygenMs: number; signMs: number; verifyMs: number };
  sizeCheck: SizeCheck[];
}

/**
 * Sign and verify a message, then tamper with it and verify again. The tamper
 * check is the part worth watching: it demonstrates that a post-quantum
 * signature fails exactly the way a classical one does, so nothing about
 * downstream integrity logic has to change during a migration.
 */
export function runSignature(algorithm = 'ML-DSA-65', message = 'QGuard Helix — post-quantum signature demonstration'): SignatureRun {
  const signer = SIGNERS[algorithm];
  if (!signer) throw new Error(`Unknown signature algorithm: ${algorithm}`);
  const standard = pqcSet(algorithm.startsWith('SLH') ? algorithm : algorithm);
  const bytes = new TextEncoder().encode(message);

  const t0 = now();
  const keys = signer.keygen();
  const t1 = now();
  const signature = signer.sign(bytes, keys.secretKey);
  const t2 = now();
  const valid = signer.verify(signature, bytes, keys.publicKey);
  const t3 = now();

  const tampered = Uint8Array.from(bytes);
  tampered[0] ^= 0x01;
  const tamperDetected = !signer.verify(signature, tampered, keys.publicKey);

  const sizeCheck: SizeCheck[] = [
    { field: 'Verification key', observed: keys.publicKey.length, published: standard?.sizes.publicKey ?? null, matches: keys.publicKey.length === standard?.sizes.publicKey },
    { field: 'Signature', observed: signature.length, published: standard?.sizes.signature ?? null, matches: signature.length === standard?.sizes.signature },
  ];

  return {
    algorithm,
    standard,
    publicKey: keys.publicKey,
    signature,
    message,
    valid: Boolean(valid),
    tamperDetected,
    timings: { keygenMs: t1 - t0, signMs: t2 - t1, verifyMs: t3 - t2 },
    sizeCheck,
  };
}

/* ═══════════════════════════════════════════════════════════════════════════
   Benchmark
   ═══════════════════════════════════════════════════════════════════════════ */

export interface BenchmarkRow {
  algorithm: string;
  role: 'kem' | 'signature';
  category: number;
  /** Median milliseconds per operation across the sample. */
  keygenMs: number;
  /** encapsulate for KEMs, sign for signatures. */
  primaryMs: number;
  primaryLabel: string;
  /** decapsulate for KEMs, verify for signatures. */
  secondaryMs: number;
  secondaryLabel: string;
  /** Bytes on the wire per handshake or per signature. */
  wireBytes: number;
  samples: number;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/**
 * Measure the suite. Sample counts are per-algorithm because SLH-DSA signing is
 * three orders of magnitude slower than ML-DSA by design — running it 50 times
 * would block the main thread for seconds.
 */
export function benchmarkPqc(sampleBudgetMs = 400): BenchmarkRow[] {
  const rows: BenchmarkRow[] = [];

  for (const algorithm of LIVE_KEM_IDS) {
    const kem = KEMS[algorithm];
    const standard = pqcSet(algorithm);
    const keygen: number[] = [];
    const encap: number[] = [];
    const decap: number[] = [];
    const deadline = now() + sampleBudgetMs / 3;

    let samples = 0;
    while (now() < deadline && samples < 200) {
      let t = now();
      const keys = kem.keygen();
      keygen.push(now() - t);
      t = now();
      const { cipherText } = kem.encapsulate(keys.publicKey);
      encap.push(now() - t);
      t = now();
      kem.decapsulate(cipherText, keys.secretKey);
      decap.push(now() - t);
      samples += 1;
    }

    rows.push({
      algorithm,
      role: 'kem',
      category: standard?.category ?? 0,
      keygenMs: median(keygen),
      primaryMs: median(encap),
      primaryLabel: 'encapsulate',
      secondaryMs: median(decap),
      secondaryLabel: 'decapsulate',
      wireBytes: (standard?.sizes.publicKey ?? 0) + (standard?.sizes.ciphertext ?? 0),
      samples,
    });
  }

  const message = new TextEncoder().encode('QGuard Helix benchmark payload');
  for (const algorithm of LIVE_SIGNER_IDS) {
    const signer = SIGNERS[algorithm];
    const standard = pqcSet(algorithm);
    const slow = algorithm.startsWith('SLH');
    const keygen: number[] = [];
    const sign: number[] = [];
    const verify: number[] = [];
    const cap = slow ? 3 : 200;
    const deadline = now() + (slow ? sampleBudgetMs : sampleBudgetMs / 3);

    let samples = 0;
    while (now() < deadline && samples < cap) {
      let t = now();
      const keys = signer.keygen();
      keygen.push(now() - t);
      t = now();
      const signature = signer.sign(message, keys.secretKey);
      sign.push(now() - t);
      t = now();
      signer.verify(signature, message, keys.publicKey);
      verify.push(now() - t);
      samples += 1;
    }

    rows.push({
      algorithm,
      role: 'signature',
      category: standard?.category ?? 0,
      keygenMs: median(keygen),
      primaryMs: median(sign),
      primaryLabel: 'sign',
      secondaryMs: median(verify),
      secondaryLabel: 'verify',
      wireBytes: (standard?.sizes.publicKey ?? 0) + (standard?.sizes.signature ?? 0),
      samples,
    });
  }

  return rows;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Standards conformance
   ═══════════════════════════════════════════════════════════════════════════ */

export interface ConformanceResult {
  algorithm: string;
  checks: SizeCheck[];
  allMatch: boolean;
}

/**
 * Run one operation of every algorithm and compare the byte lengths the
 * implementation produced against the values tabulated in the FIPS documents.
 *
 * This is the page keeping itself honest: if the published table in
 * `nist-standards.ts` and the implementation ever disagree, the UI
 * shows a failed row rather than a confident number.
 */
export function verifyAgainstStandard(): ConformanceResult[] {
  const results: ConformanceResult[] = [];

  for (const algorithm of LIVE_KEM_IDS) {
    const run = runKemExchange(algorithm);
    results.push({ algorithm, checks: run.sizeCheck, allMatch: run.sizeCheck.every((c) => c.matches) && run.agreed });
  }
  for (const algorithm of LIVE_SIGNER_IDS) {
    const run = runSignature(algorithm, 'conformance');
    results.push({ algorithm, checks: run.sizeCheck, allMatch: run.sizeCheck.every((c) => c.matches) && run.valid && run.tamperDetected });
  }

  return results;
}

/**
 * Real ML-KEM key-share bytes for a TLS hybrid group, so the handshake hex dump
 * in `tls-evidence.ts` carries actual lattice material rather than noise.
 */
export function hybridKeyShare(groupName: string): Uint8Array {
  if (groupName === 'X25519MLKEM768') {
    const kem = ml_kem768.keygen();
    const share = new Uint8Array(1184 + 32);
    share.set(kem.publicKey, 0);
    share.set(randomClassicalPoint(32), 1184);
    return share;
  }
  if (groupName === 'SecP256r1MLKEM768') {
    const kem = ml_kem768.keygen();
    const share = new Uint8Array(65 + 1184);
    share.set(randomClassicalPoint(65), 0);
    share.set(kem.publicKey, 65);
    return share;
  }
  if (groupName === 'SecP384r1MLKEM1024') {
    const kem = ml_kem1024.keygen();
    const share = new Uint8Array(97 + 1568);
    share.set(randomClassicalPoint(97), 0);
    share.set(kem.publicKey, 97);
    return share;
  }
  return randomClassicalPoint(32);
}

/**
 * Filler for the classical half of a hybrid share. A real X25519 point would
 * need the curve library; the length and position are what the hex dump is
 * teaching, and the ML-KEM half — the half that matters here — is genuine.
 */
function randomClassicalPoint(length: number): Uint8Array {
  const out = new Uint8Array(length);
  const webcrypto = typeof globalThis !== 'undefined' ? (globalThis.crypto as Crypto | undefined) : undefined;
  if (webcrypto?.getRandomValues) webcrypto.getRandomValues(out);
  else for (let i = 0; i < length; i += 1) out[i] = Math.floor(Math.random() * 256);
  if (length === 65 || length === 97) out[0] = 0x04; // uncompressed point marker
  return out;
}
