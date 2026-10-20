/**
 * Quantum Simulation Range — a real quantum computer simulator, and Shor's
 * algorithm running on it.
 *
 * WHY THIS EXISTS
 * ---------------
 * The page this replaces animated a glowing sphere and printed
 * `r = 2650381045982183907817024831` as the "period" of an RSA-2048 key. That
 * number is not the period of anything; it was typed.
 *
 * This module does the actual thing. It allocates a complex state vector over
 * (t + n) qubits, applies real Hadamard gates, a real controlled modular
 * exponentiation, and a real inverse quantum Fourier transform, samples the
 * control register from the resulting Born-rule distribution, runs continued
 * fractions on the outcome, and factors the number with gcd. If it prints a
 * period, a quantum state produced it.
 *
 * WHAT THIS PROVES, AND WHAT IT DOES NOT
 * --------------------------------------
 * It proves the algorithm is real and that the interference pattern the user
 * sees is the genuine Born-rule distribution.
 *
 * It does NOT mean RSA-2048 can be factored here. Simulating m qubits costs
 * 2^m complex amplitudes. RSA-2048 needs about 6,144 logical qubits, so its
 * state vector holds 2^6144 ≈ 10^1850 numbers — the estimated atom count of the
 * observable universe (about 10^80) raised to the 23rd power. That impossibility is the
 * whole point: a classical machine cannot fake this, which is precisely why a
 * real quantum computer would change the situation. `simulationWall()` turns
 * that into a number the UI can show.
 *
 * CORRECTNESS
 * -----------
 * `tools/quantum-sim-check.ts` verifies the inverse QFT against its
 * mathematical definition by direct summation for small registers, and runs the
 * full algorithm across a matrix of (N, a) pairs, asserting the factors it
 * returns actually multiply back to N.
 *
 * Reference: Shor, SIAM J. Comput. 26(5), 1997.
 */

/* ═══════════════════════════════════════════════════════════════════════════
   Integer helpers. Every value stays below 2^26 so products fit in a double.
   ═══════════════════════════════════════════════════════════════════════════ */

export function gcd(a: number, b: number): number {
  let x = Math.abs(a);
  let y = Math.abs(b);
  while (y) {
    const t = y;
    y = x % y;
    x = t;
  }
  return x;
}

export function modPow(base: number, exponent: number, modulus: number): number {
  if (modulus === 1) return 0;
  let result = 1;
  let b = base % modulus;
  let e = exponent;
  while (e > 0) {
    if (e & 1) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1;
  }
  return result;
}

export function isPrime(n: number): boolean {
  if (n < 2) return false;
  if (n % 2 === 0) return n === 2;
  for (let d = 3; d * d <= n; d += 2) if (n % d === 0) return false;
  return true;
}

/** Classical order of a modulo n, used only to label the expected answer. */
export function classicalOrder(a: number, n: number): number | null {
  if (gcd(a, n) !== 1) return null;
  let value = a % n;
  for (let r = 1; r <= n; r += 1) {
    if (value === 1) return r;
    value = (value * a) % n;
  }
  return null;
}

/* ═══════════════════════════════════════════════════════════════════════════
   State vector
   ═══════════════════════════════════════════════════════════════════════════ */

const INV_SQRT2 = Math.SQRT1_2;

/**
 * A quantum register held as split real/imaginary Float64Arrays.
 *
 * Index layout: the WORK register occupies the low `workQubits` bits and the
 * CONTROL register the next `controlQubits` bits, so control bit j lives at
 * global bit position `workQubits + j` and each work register is a contiguous
 * run of 2^workQubits amplitudes. That layout is what makes the controlled
 * modular multiplication a block-local permutation rather than a scatter.
 */
export class StateVector {
  readonly workQubits: number;
  readonly controlQubits: number;
  readonly totalQubits: number;
  readonly size: number;
  readonly re: Float64Array;
  readonly im: Float64Array;
  /** Every gate applied, in order, for the circuit diagram. */
  readonly gateLog: string[] = [];

  constructor(controlQubits: number, workQubits: number) {
    this.controlQubits = controlQubits;
    this.workQubits = workQubits;
    this.totalQubits = controlQubits + workQubits;
    this.size = 2 ** this.totalQubits;
    this.re = new Float64Array(this.size);
    this.im = new Float64Array(this.size);
  }

  /** |0…0⟩|value⟩ */
  initialise(workValue: number): void {
    this.re.fill(0);
    this.im.fill(0);
    this.re[workValue] = 1;
    this.gateLog.push(`init |0…0⟩|${workValue}⟩`);
  }

  /** Hadamard on the qubit at global bit position `bit`. */
  hadamard(bit: number): void {
    const stride = 1 << bit;
    for (let i = 0; i < this.size; i += 1) {
      if ((i & stride) !== 0) continue;
      const j = i | stride;
      const ar = this.re[i];
      const ai = this.im[i];
      const br = this.re[j];
      const bi = this.im[j];
      this.re[i] = (ar + br) * INV_SQRT2;
      this.im[i] = (ai + bi) * INV_SQRT2;
      this.re[j] = (ar - br) * INV_SQRT2;
      this.im[j] = (ai - bi) * INV_SQRT2;
    }
  }

  /**
   * Controlled phase rotation: multiply by e^(i·angle) on states where both
   * `control` and `target` bits are set. Symmetric in its two qubits, as the
   * gate genuinely is.
   */
  controlledPhase(control: number, target: number, angle: number): void {
    const mask = (1 << control) | (1 << target);
    const c = Math.cos(angle);
    const s = Math.sin(angle);
    for (let i = 0; i < this.size; i += 1) {
      if ((i & mask) !== mask) continue;
      const r = this.re[i];
      const m = this.im[i];
      this.re[i] = r * c - m * s;
      this.im[i] = r * s + m * c;
    }
  }

  /** Exchange two qubits. */
  swap(a: number, b: number): void {
    if (a === b) return;
    const ma = 1 << a;
    const mb = 1 << b;
    for (let i = 0; i < this.size; i += 1) {
      const hasA = (i & ma) !== 0;
      const hasB = (i & mb) !== 0;
      if (hasA === hasB) continue;
      const j = (i ^ ma) ^ mb;
      if (j <= i) continue;
      const tr = this.re[i];
      const ti = this.im[i];
      this.re[i] = this.re[j];
      this.im[i] = this.im[j];
      this.re[j] = tr;
      this.im[j] = ti;
    }
  }

  /**
   * Controlled modular multiplication: |w⟩ → |w · multiplier mod N⟩ on every
   * branch where the control qubit is 1, and identity for w ≥ N.
   *
   * This is a permutation of basis states, which is what makes it reversible
   * and therefore implementable as a quantum gate at all. On real hardware it
   * is the expensive part — it is where essentially all of the Toffoli gates in
   * the resource estimate go.
   */
  controlledModularMultiply(controlBit: number, multiplier: number, modulus: number): void {
    const blockSize = 1 << this.workQubits;
    const controlMask = 1 << controlBit;
    const tmpRe = new Float64Array(blockSize);
    const tmpIm = new Float64Array(blockSize);

    for (let base = 0; base < this.size; base += blockSize) {
      if ((base & controlMask) === 0) continue;
      tmpRe.set(this.re.subarray(base, base + blockSize));
      tmpIm.set(this.im.subarray(base, base + blockSize));
      this.re.fill(0, base, base + blockSize);
      this.im.fill(0, base, base + blockSize);
      for (let w = 0; w < blockSize; w += 1) {
        const target = w < modulus ? (w * multiplier) % modulus : w;
        this.re[base + target] = tmpRe[w];
        this.im[base + target] = tmpIm[w];
      }
    }
  }

  /**
   * Inverse quantum Fourier transform over the control register.
   *
   * Circuit: bit-reversal swaps, then for each qubit j the accumulated negative
   * controlled rotations from every lower qubit, then a Hadamard. Verified
   * against the direct definition
   *   IQFT|x⟩ = 2^(-t/2) Σ_y exp(-2πi·x·y / 2^t) |y⟩
   * by `tools/quantum-sim-check.ts`.
   */
  inverseQft(): void {
    const t = this.controlQubits;
    const offset = this.workQubits;

    for (let i = 0; i < Math.floor(t / 2); i += 1) {
      this.swap(offset + i, offset + (t - 1 - i));
    }
    for (let j = 0; j < t; j += 1) {
      for (let k = 0; k < j; k += 1) {
        this.controlledPhase(offset + k, offset + j, -Math.PI / 2 ** (j - k));
      }
      this.hadamard(offset + j);
    }
    this.gateLog.push(`IQFT†(${t} qubits) — ${(t * (t + 1)) / 2} gates`);
  }

  /** Marginal probability of each control-register value, tracing out the work register. */
  controlDistribution(): Float64Array {
    const blockSize = 1 << this.workQubits;
    const out = new Float64Array(1 << this.controlQubits);
    for (let i = 0; i < this.size; i += 1) {
      out[i >>> this.workQubits] += this.re[i] * this.re[i] + this.im[i] * this.im[i];
    }
    // Guard against float drift so the sampler always terminates.
    let total = 0;
    for (let i = 0; i < out.length; i += 1) total += out[i];
    if (total > 0 && Math.abs(total - 1) > 1e-9) {
      for (let i = 0; i < out.length; i += 1) out[i] /= total;
    }
    void blockSize;
    return out;
  }

  /** Bytes of heap this register occupies. */
  get bytes(): number {
    return this.size * 16;
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   Deterministic sampling
   ═══════════════════════════════════════════════════════════════════════════ */

/** xorshift32 — a real PRNG, so a seeded run is reproducible for screenshots. */
function makeRandom(seed: number): () => number {
  let state = seed >>> 0 || 0x9e3779b9;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x1_0000_0000;
  };
}

function sampleFrom(distribution: Float64Array, random: () => number): number {
  const roll = random();
  let cumulative = 0;
  for (let i = 0; i < distribution.length; i += 1) {
    cumulative += distribution[i];
    if (roll <= cumulative) return i;
  }
  return distribution.length - 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Continued fractions — the classical post-processing
   ═══════════════════════════════════════════════════════════════════════════ */

export interface Convergent {
  /** Term of the continued fraction expansion. */
  term: number;
  numerator: number;
  denominator: number;
  /** The value of this convergent, for the "how close is it" column. */
  value: number;
}

/**
 * Expand `numerator / denominator` as a continued fraction and return every
 * convergent whose denominator stays below `limit`.
 *
 * The measured y is close to k·2^t/r for some integer k. The denominator of the
 * best rational approximation to y/2^t with denominator under N is therefore
 * the period r — that is the entire bridge from "a quantum measurement" to "a
 * factor of N".
 */
export function continuedFractionConvergents(numerator: number, denominator: number, limit: number): Convergent[] {
  const out: Convergent[] = [];
  let n = numerator;
  let d = denominator;
  let prevNum = 0;
  let prevDen = 1;
  let curNum = 1;
  let curDen = 0;

  for (let guard = 0; guard < 64 && d !== 0; guard += 1) {
    const term = Math.floor(n / d);
    const nextNum = term * curNum + prevNum;
    const nextDen = term * curDen + prevDen;
    prevNum = curNum;
    prevDen = curDen;
    curNum = nextNum;
    curDen = nextDen;
    if (curDen > limit) break;
    if (curDen > 0) {
      out.push({ term, numerator: curNum, denominator: curDen, value: curNum / curDen });
    }
    const remainder = n - term * d;
    n = d;
    d = remainder;
  }
  return out;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Shor's algorithm
   ═══════════════════════════════════════════════════════════════════════════ */

export interface ShorOptions {
  /** The composite to factor. Must be odd, composite, and not a prime power. */
  N: number;
  /** Base a with gcd(a, N) = 1. Omit to pick one deterministically from the seed. */
  a?: number;
  /**
   * Control-register width. Defaults to 2·⌈lg N⌉, the textbook choice that
   * guarantees the continued-fraction step succeeds. Lowering it is the most
   * instructive knob on the page: the peaks blur and the classical
   * post-processing starts to fail.
   */
  controlQubits?: number;
  /** PRNG seed for the measurement. */
  seed?: number;
  /** Hard ceiling on total qubits, to protect the tab. */
  maxQubits?: number;
}

export interface ShorPeak {
  /** Measured control-register value. */
  y: number;
  probability: number;
  /** y / 2^t — the phase estimate. */
  phase: number;
  /** Nearest k/r the peak corresponds to, when the true order is known. */
  nearestFraction: string;
}

export interface ShorResult {
  N: number;
  a: number;
  controlQubits: number;
  workQubits: number;
  totalQubits: number;
  stateVectorBytes: number;
  /** Gate counts actually executed, not estimated. */
  gates: { hadamard: number; controlledPhase: number; swap: number; modularMultiply: number; total: number };
  /** a^x mod N for x = 0 … min(2^t, 512) — the classical periodic function. */
  periodicFunction: number[];
  /** The true order of a mod N, computed classically for comparison. */
  trueOrder: number | null;
  /** Born-rule probability of every control-register outcome after the IQFT. */
  distribution: Float64Array;
  /** The tallest peaks in that distribution. */
  peaks: ShorPeak[];
  /** The single outcome this run measured. */
  measurement: number;
  measuredPhase: number;
  convergents: Convergent[];
  /** Period recovered from the measurement, or null if this shot failed. */
  recoveredPeriod: number | null;
  /** Non-trivial factors, or null. */
  factors: [number, number] | null;
  /** Why this shot failed, when it did. Shor's algorithm is probabilistic. */
  failureReason: string | null;
  success: boolean;
  /** Wall-clock milliseconds spent in the simulator. */
  elapsedMs: number;
  /** Human narration of each stage, for the stepper UI. */
  stages: ShorStage[];
}

export interface ShorStage {
  id: string;
  title: string;
  detail: string;
  /** What the register holds after this stage. */
  registerState: string;
}

export const SHOR_DEFAULT_MAX_QUBITS = 22;

/** Odd composites small enough to simulate, with their factorisations. */
export const SHOR_TARGETS: Array<{ N: number; factors: [number, number]; qubits: number; note: string }> = [
  { N: 15, factors: [3, 5], qubits: 12, note: 'The canonical demonstration. 8 control + 4 work qubits.' },
  { N: 21, factors: [3, 7], qubits: 15, note: 'Orders up to 6 (a = 2 has order 6). The first target where r is not a power of two, so the peaks are not exact and continued fractions must do real work.' },
  { N: 33, factors: [3, 11], qubits: 18, note: 'Six work qubits. State vector crosses 4 MB.' },
  { N: 35, factors: [5, 7], qubits: 18, note: 'Both factors above 3. Orders up to 12; 10 of the 34 nonzero residues share a factor with 35 and fall to the gcd check alone.' },
  { N: 39, factors: [3, 13], qubits: 18, note: '12 is the most common order here (8 of the 24 units mod 39), giving a twelve-tooth comb.' },
  { N: 51, factors: [3, 17], qubits: 18, note: 'Larger prime factor stresses the continued-fraction step.' },
  { N: 55, factors: [5, 11], qubits: 18, note: 'Order 20 for many bases — a dense comb.' },
  { N: 65, factors: [5, 13], qubits: 21, note: 'Seven work qubits. 33 MB of amplitudes.' },
  { N: 77, factors: [7, 11], qubits: 21, note: 'The largest target that stays comfortable in a browser tab.' },
  { N: 91, factors: [7, 13], qubits: 21, note: '12 is the most common order (32 of the 72 units mod 91), but a = 3 has order 6 (3^6 = 729 = 8·91 + 1). Runs in about a second.' },
];

function pickBase(N: number, random: () => number): number {
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const candidate = 2 + Math.floor(random() * (N - 3));
    if (gcd(candidate, N) === 1) return candidate;
  }
  for (let candidate = 2; candidate < N; candidate += 1) if (gcd(candidate, N) === 1) return candidate;
  return 2;
}

/**
 * Run one shot of Shor's algorithm on a genuine simulated quantum register.
 *
 * Shor's is probabilistic: a single shot fails whenever the measured peak
 * yields an odd period, or a period r with a^(r/2) ≡ -1 (mod N). Those failures
 * are reported honestly rather than retried silently, because seeing the
 * algorithm fail and then succeed on the next shot is the clearest possible
 * demonstration that it is real.
 */
export function runShor(options: ShorOptions): ShorResult {
  const started = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const { N } = options;
  const maxQubits = options.maxQubits ?? SHOR_DEFAULT_MAX_QUBITS;

  if (N < 3 || N % 2 === 0) throw new Error(`Shor needs an odd composite. ${N} is not one.`);
  if (isPrime(N)) throw new Error(`${N} is prime — there is nothing to factor.`);

  const workQubits = Math.ceil(Math.log2(N));
  const controlQubits = options.controlQubits ?? 2 * workQubits;
  const total = workQubits + controlQubits;
  if (total > maxQubits) {
    throw new Error(
      `${total} qubits would need ${((2 ** total * 16) / 1e6).toFixed(0)} MB of amplitudes. The ceiling is ${maxQubits} qubits.`,
    );
  }

  const random = makeRandom(options.seed ?? 0x5eed_1234);
  const a = options.a ?? pickBase(N, random);

  const stages: ShorStage[] = [];
  const gates = { hadamard: 0, controlledPhase: 0, swap: 0, modularMultiply: 0, total: 0 };

  // A base sharing a factor with N is a lucky classical hit — gcd already wins.
  const luckyFactor = gcd(a, N);
  if (luckyFactor !== 1) {
    const elapsed = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - started;
    return {
      N,
      a,
      controlQubits,
      workQubits,
      totalQubits: total,
      stateVectorBytes: 0,
      gates,
      periodicFunction: [],
      trueOrder: null,
      distribution: new Float64Array(0),
      peaks: [],
      measurement: -1,
      measuredPhase: 0,
      convergents: [],
      recoveredPeriod: null,
      factors: [luckyFactor, N / luckyFactor],
      failureReason: null,
      success: true,
      elapsedMs: elapsed,
      stages: [
        {
          id: 'lucky',
          title: 'Classical shortcut',
          detail: `gcd(${a}, ${N}) = ${luckyFactor} ≠ 1. The base shares a factor with N, so no quantum computer is needed for this one. Shor's algorithm starts with exactly this check.`,
          registerState: 'not allocated',
        },
      ],
    };
  }

  const state = new StateVector(controlQubits, workQubits);
  state.initialise(1);
  stages.push({
    id: 'init',
    title: 'Prepare the registers',
    detail: `${controlQubits} control qubits set to |0⟩ and ${workQubits} work qubits set to |1⟩. The state vector holds 2^${total} = ${state.size.toLocaleString()} complex amplitudes.`,
    registerState: `|0⟩^${controlQubits} ⊗ |1⟩`,
  });

  for (let j = 0; j < controlQubits; j += 1) {
    state.hadamard(workQubits + j);
    gates.hadamard += 1;
  }
  stages.push({
    id: 'superposition',
    title: 'Superpose every exponent at once',
    detail: `A Hadamard on each control qubit puts the register into an equal superposition of all ${(2 ** controlQubits).toLocaleString()} values of x simultaneously. This is the only step that is "quantum parallelism" — and on its own it is useless, because measuring now returns one random x.`,
    registerState: `2^(-t/2) Σ_x |x⟩|1⟩`,
  });

  for (let j = 0; j < controlQubits; j += 1) {
    const multiplier = modPow(a, 2 ** j, N);
    state.controlledModularMultiply(workQubits + j, multiplier, N);
    gates.modularMultiply += 1;
  }
  stages.push({
    id: 'modexp',
    title: 'Compute a^x mod N into the work register',
    detail: `${controlQubits} controlled modular multiplications by a^(2^j) mod N build the full exponentiation. The register now holds Σ_x |x⟩|${a}^x mod ${N}⟩ — the exponent and its residue are entangled. On real hardware this step is where almost every Toffoli gate in the resource estimate is spent.`,
    registerState: `2^(-t/2) Σ_x |x⟩|${a}^x mod ${N}⟩`,
  });

  const periodicFunction: number[] = [];
  const sampleWidth = Math.min(2 ** controlQubits, 512);
  for (let x = 0; x < sampleWidth; x += 1) periodicFunction.push(modPow(a, x, N));

  state.inverseQft();
  gates.hadamard += controlQubits;
  gates.controlledPhase += (controlQubits * (controlQubits - 1)) / 2;
  gates.swap += Math.floor(controlQubits / 2);
  stages.push({
    id: 'iqft',
    title: 'Interfere the exponents',
    detail:
      'The inverse quantum Fourier transform makes every measurement outcome y that is not close to a multiple of 2^t / r cancel destructively. What survives is a comb of sharp peaks at y ≈ k·2^t / r. The period was never measured — it was made to be the only thing left.',
    registerState: 'peaked at multiples of 2^t / r',
  });

  gates.total = gates.hadamard + gates.controlledPhase + gates.swap + gates.modularMultiply;

  const distribution = state.controlDistribution();
  const trueOrder = classicalOrder(a, N);

  const ranked = Array.from(distribution)
    .map((probability, y) => ({ y, probability }))
    .filter((p) => p.probability > 1e-6)
    .sort((x, y) => y.probability - x.probability)
    .slice(0, 12);

  const scale = 2 ** controlQubits;
  const peaks: ShorPeak[] = ranked.map((p) => {
    const phase = p.y / scale;
    let nearestFraction = '—';
    if (trueOrder) {
      const k = Math.round(phase * trueOrder);
      nearestFraction = `${k}/${trueOrder}`;
    }
    return { y: p.y, probability: p.probability, phase, nearestFraction };
  });

  const measurement = sampleFrom(distribution, random);
  const measuredPhase = measurement / scale;
  stages.push({
    id: 'measure',
    title: 'Measure',
    detail: `The control register collapses to y = ${measurement}, i.e. a phase estimate of ${measuredPhase.toFixed(6)}. This single number is everything the quantum computer produces; the rest is ordinary arithmetic.`,
    registerState: `|${measurement}⟩`,
  });

  const convergents = continuedFractionConvergents(measurement, scale, N);
  let recoveredPeriod: number | null = null;
  for (const convergent of convergents) {
    if (convergent.denominator > 1 && modPow(a, convergent.denominator, N) === 1) {
      recoveredPeriod = convergent.denominator;
      break;
    }
  }
  stages.push({
    id: 'continued-fractions',
    title: 'Recover the period classically',
    detail: recoveredPeriod
      ? `Expanding ${measurement}/${scale} as a continued fraction and testing each convergent gives r = ${recoveredPeriod}, confirmed by ${a}^${recoveredPeriod} mod ${N} = 1.`
      : `No convergent of ${measurement}/${scale} with denominator below ${N} satisfies ${a}^r ≡ 1 (mod ${N}). This shot found nothing — which happens, and is why Shor's algorithm is run repeatedly.`,
    registerState: recoveredPeriod ? `r = ${recoveredPeriod}` : 'r unresolved',
  });

  let factors: [number, number] | null = null;
  let failureReason: string | null = null;

  if (!recoveredPeriod) {
    failureReason = 'The measured peak did not resolve to a period. Re-run: a different measurement outcome will.';
  } else if (recoveredPeriod % 2 !== 0) {
    failureReason = `The period r = ${recoveredPeriod} is odd, so a^(r/2) is not an integer power and the factoring step does not apply. Odd periods and the a^(r/2) ≡ -1 case together sink at most half of all bases when N has two distinct odd prime factors — pick another a.`;
  } else {
    const half = modPow(a, recoveredPeriod / 2, N);
    if (half === N - 1) {
      failureReason = `a^(r/2) ≡ -1 (mod N), so gcd(a^(r/2) ± 1, N) returns only the trivial factors 1 and N. Pick another a.`;
    } else {
      const p = gcd(half - 1, N);
      const q = gcd(half + 1, N);
      const candidate = [p, q].find((v) => v > 1 && v < N);
      if (candidate) {
        factors = [candidate, N / candidate];
      } else {
        failureReason = 'gcd returned only trivial factors on this shot.';
      }
    }
  }

  stages.push({
    id: 'factor',
    title: 'Factor',
    detail: factors
      ? `a^(r/2) mod N = ${modPow(a, (recoveredPeriod as number) / 2, N)}. gcd(a^(r/2) − 1, N) and gcd(a^(r/2) + 1, N) give ${factors[0]} × ${factors[1]} = ${N}. Both factors recovered.`
      : (failureReason ?? 'No factors on this shot.'),
    registerState: factors ? `${factors[0]} × ${factors[1]}` : 'no factors',
  });

  const elapsed = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - started;

  return {
    N,
    a,
    controlQubits,
    workQubits,
    totalQubits: total,
    stateVectorBytes: state.bytes,
    gates,
    periodicFunction,
    trueOrder,
    distribution,
    peaks,
    measurement,
    measuredPhase,
    convergents,
    recoveredPeriod,
    factors,
    failureReason,
    success: factors !== null,
    elapsedMs: elapsed,
    stages,
  };
}

/**
 * Keep drawing shots until one succeeds or the budget runs out. Returns every
 * attempt, so the UI can show the failures too — a probabilistic algorithm that
 * only ever displays its successes looks like a magic trick.
 *
 * If the caller pinned a base, it is held across every shot: the user asked to
 * watch THAT base, and some bases (a ≡ -1 mod N, for instance) can never
 * succeed, which is worth seeing. With no base pinned, each shot draws a fresh
 * one, which is what the real algorithm does.
 */
export function runShorUntilSuccess(options: ShorOptions, maxShots = 8): ShorResult[] {
  const attempts: ShorResult[] = [];
  const baseSeed = options.seed ?? 0x5eed_1234;
  for (let shot = 0; shot < maxShots; shot += 1) {
    const result = runShor({ ...options, seed: baseSeed + shot * 0x9e37 });
    attempts.push(result);
    if (result.success) break;
  }
  return attempts;
}

/* ═══════════════════════════════════════════════════════════════════════════
   The wall
   ═══════════════════════════════════════════════════════════════════════════ */

export interface SimulationWall {
  keyBits: number;
  /** Logical qubits Shor needs for this key size (3n, per the Gidney & Ekerå circuit). */
  qubits: number;
  /** Complex amplitudes a classical simulation would have to store. */
  amplitudesLog10: number;
  /** Bytes, as a power of ten. */
  bytesLog10: number;
  /** Plain-language comparison, so the number means something. */
  comparison: string;
}

/** Atoms in the observable universe, order of magnitude. */
const ATOMS_LOG10 = 80;

/**
 * How much classical memory a full state-vector simulation of Shor at this key
 * size would need. This is the honest answer to "why don't you just factor
 * RSA-2048 in the browser".
 */
export function simulationWall(keyBits: number): SimulationWall {
  const qubits = 3 * keyBits;
  const amplitudesLog10 = qubits * Math.log10(2);
  const bytesLog10 = amplitudesLog10 + Math.log10(16);

  let comparison: string;
  if (bytesLog10 < 10) comparison = `${(10 ** bytesLog10 / 1e9).toFixed(2)} GB — a laptop could do this.`;
  else if (bytesLog10 < 18) comparison = `${(10 ** (bytesLog10 - 15)).toFixed(1)} petabytes — a national supercomputing facility.`;
  else if (bytesLog10 < ATOMS_LOG10)
    comparison = `10^${Math.round(bytesLog10)} bytes. There are about 10^${ATOMS_LOG10} atoms in the observable universe.`;
  else
    comparison = `10^${Math.round(bytesLog10)} bytes — that is the number of atoms in the observable universe raised to the power ${(bytesLog10 / ATOMS_LOG10).toFixed(1)}.`;

  return { keyBits, qubits, amplitudesLog10, bytesLog10, comparison };
}
