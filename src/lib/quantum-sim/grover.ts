/**
 * Quantum Simulation Range — Grover's algorithm, and why it is not a break.
 *
 * WHY THIS EXISTS
 * ---------------
 * "Quantum computers break encryption" is a sentence that is half true, and the
 * false half is Grover. Shor destroys public-key cryptography outright. Grover
 * gives a quadratic speed-up on unstructured search, which sounds devastating
 * and is not: it turns a 2^256 key search into 2^128, and 2^128 is the margin
 * that makes AES-128 safe today.
 *
 * The amplitude evolution here is exact, not simulated by state vector: for a
 * search space of size M with one marked item, the amplitude on the marked item
 * after j iterations is exactly sin((2j + 1)·θ) with θ = arcsin(1/√M). That
 * closed form is the actual quantum state, so the curve the UI draws is real.
 *
 * References: Grover 1996; NIST PQC Call for Proposals §4.A.5 (MAXDEPTH).
 */

export interface GroverEvolution {
  /** Search-space size, as a power of two. */
  keyBits: number;
  /** Optimal iteration count: ⌊(π/4)·√M⌋. */
  optimalIterations: number;
  /** Success probability at each iteration, from 0 to `samples`. */
  curve: Array<{ iteration: number; probability: number }>;
  /** Probability at the optimal iteration count. */
  peakProbability: number;
  /** Nominal quantum security in bits, i.e. lg(optimal iterations). */
  quantumBits: number;
}

/**
 * Exact amplitude amplification. `samples` bounds how many points the curve
 * carries, because plotting 2^63 iterations is not useful.
 */
export function groverEvolution(keyBits: number, samples = 220): GroverEvolution {
  const searchSpace = 2 ** Math.min(keyBits, 30); // curve is drawn for a plottable space
  const theta = Math.asin(1 / Math.sqrt(searchSpace));
  const optimalForCurve = Math.floor((Math.PI / 4) / theta);

  const curve: Array<{ iteration: number; probability: number }> = [];
  const step = Math.max(1, Math.floor((optimalForCurve * 1.6) / samples));
  for (let iteration = 0; iteration <= optimalForCurve * 1.6; iteration += step) {
    curve.push({ iteration, probability: Math.sin((2 * iteration + 1) * theta) ** 2 });
  }

  // The reported iteration count is for the REAL key size, not the plotted one.
  const trueIterations = (Math.PI / 4) * 2 ** (keyBits / 2);

  return {
    keyBits,
    optimalIterations: trueIterations,
    curve,
    peakProbability: Math.sin((2 * optimalForCurve + 1) * theta) ** 2,
    quantumBits: Math.log2(trueIterations),
  };
}

export interface GroverFeasibility {
  keyBits: number;
  /** Sequential quantum operations required. */
  operations: number;
  /** log2 of that. */
  operationsBits: number;
  /**
   * Years of wall-clock time at a given gate rate, assuming ONE machine.
   * Grover's iterations are strictly sequential, so this is the honest figure.
   */
  yearsAtRate: number;
  /**
   * Speed-up from running the search on `machines` quantum computers.
   * Grover parallelises as √m, not m — the whole reason the naive figure misleads.
   */
  parallelSpeedup: number;
  /**
   * Whether the required circuit depth exceeds each of NIST's three MAXDEPTH
   * bounds. Reported as all three because the answer genuinely differs: AES-128
   * blows past the conservative bound and sits right at the plausible one,
   * which is exactly why NIST rates it Category 1 rather than declaring it
   * broken or safe.
   */
  exceedsMaxDepth: { conservative: boolean; plausible: boolean; generous: boolean };
  verdict: 'infeasible' | 'theoretically-reachable' | 'reduced-margin';
  explanation: string;
}

/**
 * NIST bounds attacks by a maximum circuit depth, on the argument that no
 * attacker can run a single coherent computation forever. The Call for
 * Proposals gives 2^40 (about one year of serial gates), 2^64, and 2^96 as the
 * plausible range. 2^64 is used here as the middle case.
 */
export const NIST_MAXDEPTH = { conservative: 2 ** 40, plausible: 2 ** 64, generous: 2 ** 96 } as const;

/**
 * @param keyBits symmetric key length
 * @param gateRateHz quantum gate rate, in gates per second. 1e9 is optimistic
 *                   by several orders of magnitude for an error-corrected machine.
 * @param machines how many quantum computers the attacker runs in parallel
 */
export function groverFeasibility(keyBits: number, gateRateHz = 1e9, machines = 1): GroverFeasibility {
  const operations = (Math.PI / 4) * 2 ** (keyBits / 2);
  const parallelSpeedup = Math.sqrt(machines);
  const seconds = operations / gateRateHz / parallelSpeedup;
  const years = seconds / 31_557_600;
  const exceedsMaxDepth = {
    conservative: operations > NIST_MAXDEPTH.conservative,
    plausible: operations > NIST_MAXDEPTH.plausible,
    generous: operations > NIST_MAXDEPTH.generous,
  };

  let verdict: GroverFeasibility['verdict'];
  let explanation: string;
  if (years > 1e6) {
    verdict = 'infeasible';
    explanation = `${keyBits}-bit keys need about 2^${(keyBits / 2).toFixed(0)} sequential quantum operations. At ${gateRateHz.toExponential(0)} gates per second that is ${years.toExponential(1)} years on ${machines.toLocaleString()} machine${machines === 1 ? '' : 's'}. Grover parallelises only as the square root of the machine count, so buying a million quantum computers buys a factor of a thousand.`;
  } else if (years > 1) {
    verdict = 'reduced-margin';
    explanation = `Reachable in ${years.toExponential(1)} years under generous hardware assumptions. Move to a longer key; no algorithm change is required.`;
  } else {
    verdict = 'theoretically-reachable';
    explanation = `${years.toExponential(1)} years under these assumptions. This key length no longer carries a quantum margin — double it.`;
  }

  if (exceedsMaxDepth.generous) {
    explanation += ` The circuit depth exceeds even NIST's most generous MAXDEPTH bound of 2^96 gates, which rules the attack out on its own.`;
  } else if (exceedsMaxDepth.plausible) {
    explanation += ` The circuit depth also exceeds NIST's plausible MAXDEPTH bound of 2^64 gates.`;
  } else if (exceedsMaxDepth.conservative) {
    explanation += ` The circuit depth exceeds NIST's conservative MAXDEPTH bound of 2^40 gates but sits inside the plausible 2^64 bound — which is exactly why NIST places this key length at security Category 1 rather than calling it safe or broken.`;
  }

  return {
    keyBits,
    operations,
    operationsBits: Math.log2(operations),
    yearsAtRate: years,
    parallelSpeedup,
    exceedsMaxDepth,
    verdict,
    explanation,
  };
}
