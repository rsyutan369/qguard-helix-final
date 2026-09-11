/**
 * Quantum Simulation Range — cryptographically relevant quantum computer
 * (CRQC) resource estimator.
 *
 * WHY THIS EXISTS
 * ---------------
 * The page this replaces printed "~4 Hours" as the time to break RSA-2048 with
 * nothing behind it. That number is not knowable by assertion — it is the
 * output of a resource-estimation model, and the model's assumptions are the
 * interesting part.
 *
 * This module implements three PUBLISHED models and reproduces their published
 * anchor points. Every value it returns is labelled `model` provenance and
 * carries the citation of the model that produced it. The user can move the
 * assumptions (physical error rate, cycle time, code distance policy) and watch
 * the answer move, which is the actual lesson: "when is Q-Day" is a question
 * about engineering budgets, not about mathematics.
 *
 * MODELS
 * ------
 *   'gidney-ekera-2021'  RSA. 20M physical qubits, 8 hours, at p = 1e-3.
 *                        Quantum 5, 433 (2021), arXiv:1905.09749.
 *   'gidney-2025'        RSA, optimised. Under 1M physical qubits, ~5 days,
 *                        same physical error rate. arXiv:2505.15917.
 *   'roetteler-2017'     Elliptic curves. Exact tabulated logical qubit counts.
 *                        ASIACRYPT 2017, arXiv:1706.06752.
 *
 * SURFACE CODE
 * ------------
 * All three assume a surface code with:
 *   - threshold p_th = 1e-2
 *   - logical error per round p_L(d) ≈ 0.1 * (p / p_th) ^ ((d + 1) / 2)
 *   - 2d² physical qubits per logical qubit (d² data + d² - 1 measure)
 * plus an overhead factor covering magic-state factories and routing space.
 *
 * CALIBRATION
 * -----------
 * `FACTORY_OVERHEAD` and `TOFFOLI_CODE_CYCLES` are not free parameters chosen
 * to look good: they are fixed by requiring the model to reproduce its own
 * published anchor. `verifyAnchors()` asserts that, and `tools/quantum-sim-check.ts`
 * runs it. If someone edits a constant here, that check fails.
 */

import type { CitationKey } from './nist-standards';

export type EstimatorModel = 'gidney-ekera-2021' | 'gidney-2025' | 'roetteler-2017';

export interface HardwareAssumptions {
  /** Physical two-qubit gate error rate. 1e-3 is the published anchor. */
  physicalErrorRate: number;
  /** Surface-code cycle time in seconds. 1e-6 is the published anchor. */
  cycleTimeSeconds: number;
  /** Acceptable probability that the whole computation fails. */
  errorBudget: number;
}

export const ANCHOR_HARDWARE: HardwareAssumptions = {
  physicalErrorRate: 1e-3,
  cycleTimeSeconds: 1e-6,
  errorBudget: 0.3,
};

/** Surface-code threshold. Below this, adding distance helps; above it, it hurts. */
const SURFACE_CODE_THRESHOLD = 1e-2;

/**
 * Physical qubits consumed by magic-state factories and routing, as a multiple
 * of the data patch area.
 *
 * Fixed by the Gidney-Ekerå anchor: 6,189 logical qubits at d = 27 occupy
 * 6,189 * 2 * 27² = 9.02M physical qubits of data patch; the paper reports
 * approximately 20M total, so the rest of the machine is ~2.2x the data area.
 */
const FACTORY_OVERHEAD = 2.2;

/**
 * Code cycles consumed per Toffoli gate, in units of the code distance.
 *
 * Fixed by the same anchor: 2.7e9 Toffoli gates in 8 hours at a 1 µs cycle and
 * d = 27 gives 10.67 µs per Toffoli, i.e. 0.395 * d * t_cycle. Sub-unity
 * because many magic-state factories run in parallel and execution is
 * reaction-limited rather than distillation-limited.
 */
const TOFFOLI_CODE_CYCLES = 0.395;

/**
 * The 2025 circuit's improvement factor over the 2021 circuit, derived from the
 * two papers' own headline results rather than re-deriving the construction:
 * roughly 1/20th the physical qubits for roughly 15x the wall-clock time. The
 * arithmetic is dominated by approximate residue arithmetic and a smaller
 * window size, which trades space for depth.
 */
const GIDNEY_2025_SPACE_FACTOR = 0.048;
const GIDNEY_2025_TIME_FACTOR = 15.0;

/* ═══════════════════════════════════════════════════════════════════════════
   Logical-layer circuit costs
   ═══════════════════════════════════════════════════════════════════════════ */

export interface LogicalCost {
  /** Logical (error-corrected) qubits the algorithm needs. */
  qubits: number;
  /** Toffoli gates, the dominant non-Clifford cost. */
  toffoli: number;
  /** Human-readable formula, printed under the number. */
  formula: string;
}

/**
 * RSA, Gidney-Ekerå §Abstract:
 *   qubits  = 3n + 0.002 n lg n
 *   Toffoli = 0.3 n³ + 0.0005 n³ lg n
 *
 * At n = 2048 this gives 6,189 logical qubits and 2.7e9 Toffoli gates, which
 * are the paper's own stated figures.
 */
export function rsaLogicalCost(modulusBits: number): LogicalCost {
  const n = modulusBits;
  const lg = Math.log2(n);
  return {
    qubits: Math.round(3 * n + 0.002 * n * lg),
    toffoli: 0.3 * n ** 3 + 0.0005 * n ** 3 * lg,
    formula: '3n + 0.002·n·lg n qubits;  0.3n³ + 0.0005·n³·lg n Toffoli',
  };
}

/**
 * Elliptic curves, Roetteler et al. §5:
 *   qubits = 9n + 2⌈lg n⌉ + 10   — exact, reproduces every row of their Table 2
 *   Toffoli ≈ c·n³·lg n           — least-squares fit, c ≈ 940
 *
 * The fit reproduces the tabulated counts to within 5% across P-160 … P-521;
 * the exact tabulated values are used where a standard curve is requested.
 */
const ECC_TABULATED_TOFFOLI: Record<number, number> = {
  160: 2.97e10,
  192: 5.3e10,
  224: 8.43e10,
  256: 1.26e11,
  384: 4.52e11,
  521: 1.14e12,
};

export function eccLogicalCost(curveBits: number): LogicalCost {
  const n = curveBits;
  const qubits = 9 * n + 2 * Math.ceil(Math.log2(n)) + 10;
  const toffoli = ECC_TABULATED_TOFFOLI[n] ?? 940 * n ** 3 * Math.log2(n);
  return {
    qubits,
    toffoli,
    formula: '9n + 2⌈lg n⌉ + 10 qubits;  ≈940·n³·lg n Toffoli',
  };
}

/* ═══════════════════════════════════════════════════════════════════════════
   Physical layer
   ═══════════════════════════════════════════════════════════════════════════ */

/** Logical error rate per surface-code round at distance d. */
export function logicalErrorRate(distance: number, physicalErrorRate: number): number {
  return 0.1 * Math.pow(physicalErrorRate / SURFACE_CODE_THRESHOLD, (distance + 1) / 2);
}

/**
 * Smallest odd code distance that keeps total logical error under the budget.
 *
 * Total error ≈ qubits × rounds × p_L(d), and `rounds` depends on the runtime
 * which depends on d — so this iterates to a fixed point. Two passes are enough
 * because p_L falls off exponentially in d while rounds grows only linearly.
 */
export function chooseCodeDistance(cost: LogicalCost, hw: HardwareAssumptions): number {
  if (hw.physicalErrorRate >= SURFACE_CODE_THRESHOLD) return Number.POSITIVE_INFINITY;

  let rounds = cost.toffoli * TOFFOLI_CODE_CYCLES * 31; // seed with d ≈ 31
  for (let pass = 0; pass < 3; pass += 1) {
    let chosen = Number.POSITIVE_INFINITY;
    for (let d = 3; d <= 199; d += 2) {
      const total = cost.qubits * rounds * logicalErrorRate(d, hw.physicalErrorRate);
      if (total < hw.errorBudget) {
        chosen = d;
        break;
      }
    }
    if (!Number.isFinite(chosen)) return chosen;
    rounds = cost.toffoli * TOFFOLI_CODE_CYCLES * chosen;
    if (pass === 2) return chosen;
  }
  return Number.POSITIVE_INFINITY;
}

export interface ResourceEstimate {
  model: EstimatorModel;
  citation: CitationKey;
  target: string;
  logical: LogicalCost;
  /** Chosen surface-code distance. */
  codeDistance: number;
  /** Physical qubits, including magic-state factories and routing. */
  physicalQubits: number;
  /** Wall-clock seconds for one run of the algorithm. */
  runtimeSeconds: number;
  /** Surface-code rounds executed. */
  codeRounds: number;
  /** Logical error rate per round at the chosen distance. */
  logicalErrorPerRound: number;
  hardware: HardwareAssumptions;
  /** True when the assumptions make error correction impossible. */
  infeasible: boolean;
  /** Why, when infeasible. */
  infeasibleReason?: string;
}

function estimateFromLogical(
  model: EstimatorModel,
  citation: CitationKey,
  target: string,
  logical: LogicalCost,
  hw: HardwareAssumptions,
  spaceFactor = 1,
  timeFactor = 1,
): ResourceEstimate {
  const codeDistance = chooseCodeDistance(logical, hw);

  if (!Number.isFinite(codeDistance)) {
    return {
      model,
      citation,
      target,
      logical,
      codeDistance: Number.POSITIVE_INFINITY,
      physicalQubits: Number.POSITIVE_INFINITY,
      runtimeSeconds: Number.POSITIVE_INFINITY,
      codeRounds: Number.POSITIVE_INFINITY,
      logicalErrorPerRound: 1,
      hardware: hw,
      infeasible: true,
      infeasibleReason:
        hw.physicalErrorRate >= SURFACE_CODE_THRESHOLD
          ? `Physical error rate ${hw.physicalErrorRate.toExponential(1)} is at or above the surface-code threshold of 1e-2. Adding qubits makes the machine worse, not better — no code distance suffices.`
          : 'No code distance up to 199 meets the error budget for a circuit this deep.',
    };
  }

  const codeRounds = logical.toffoli * TOFFOLI_CODE_CYCLES * codeDistance;
  const runtimeSeconds = codeRounds * hw.cycleTimeSeconds * timeFactor;
  const physicalQubits = logical.qubits * 2 * codeDistance ** 2 * FACTORY_OVERHEAD * spaceFactor;

  return {
    model,
    citation,
    target,
    logical,
    codeDistance,
    physicalQubits,
    runtimeSeconds,
    codeRounds,
    logicalErrorPerRound: logicalErrorRate(codeDistance, hw.physicalErrorRate),
    hardware: hw,
    infeasible: false,
  };
}

/** Estimate the machine needed to factor an n-bit RSA modulus. */
export function estimateRsa(
  modulusBits: number,
  hw: HardwareAssumptions = ANCHOR_HARDWARE,
  model: Extract<EstimatorModel, 'gidney-ekera-2021' | 'gidney-2025'> = 'gidney-ekera-2021',
): ResourceEstimate {
  const logical = rsaLogicalCost(modulusBits);
  if (model === 'gidney-2025') {
    return estimateFromLogical(
      'gidney-2025',
      'gidney2025',
      `RSA-${modulusBits}`,
      logical,
      hw,
      GIDNEY_2025_SPACE_FACTOR,
      GIDNEY_2025_TIME_FACTOR,
    );
  }
  return estimateFromLogical('gidney-ekera-2021', 'gidneyEkera', `RSA-${modulusBits}`, logical, hw);
}

/** Estimate the machine needed to solve an n-bit elliptic-curve discrete log. */
export function estimateEcc(curveBits: number, hw: HardwareAssumptions = ANCHOR_HARDWARE): ResourceEstimate {
  return estimateFromLogical('roetteler-2017', 'roetteler', `ECC P-${curveBits}`, eccLogicalCost(curveBits), hw);
}

/* ═══════════════════════════════════════════════════════════════════════════
   Anchor verification — the model must reproduce its own paper
   ═══════════════════════════════════════════════════════════════════════════ */

export interface AnchorCheck {
  label: string;
  metric: string;
  published: number;
  computed: number;
  /** Fractional tolerance the check allows. */
  tolerance: number;
  pass: boolean;
}

/**
 * Reproduces the published headline results. Called by
 * `tools/quantum-sim-check.ts` and surfaced in the UI so a reader can see the
 * model being held to its source.
 */
export function verifyAnchors(): AnchorCheck[] {
  const checks: AnchorCheck[] = [];

  const rsa = rsaLogicalCost(2048);
  checks.push({
    label: 'Gidney & Ekerå 2021 — RSA-2048 logical qubits',
    metric: 'logical qubits',
    published: 6189,
    computed: rsa.qubits,
    tolerance: 0.01,
    pass: Math.abs(rsa.qubits - 6189) / 6189 < 0.01,
  });
  checks.push({
    label: 'Gidney & Ekerå 2021 — RSA-2048 Toffoli count',
    metric: 'Toffoli gates',
    published: 2.7e9,
    computed: rsa.toffoli,
    tolerance: 0.05,
    pass: Math.abs(rsa.toffoli - 2.7e9) / 2.7e9 < 0.05,
  });

  const rsaEstimate = estimateRsa(2048, ANCHOR_HARDWARE, 'gidney-ekera-2021');
  checks.push({
    label: 'Gidney & Ekerå 2021 — physical qubits at p = 1e-3',
    metric: 'physical qubits',
    published: 20e6,
    computed: rsaEstimate.physicalQubits,
    tolerance: 0.2,
    pass: Math.abs(rsaEstimate.physicalQubits - 20e6) / 20e6 < 0.2,
  });
  checks.push({
    label: 'Gidney & Ekerå 2021 — runtime at 1 µs cycle',
    metric: 'hours',
    published: 8,
    computed: rsaEstimate.runtimeSeconds / 3600,
    tolerance: 0.2,
    pass: Math.abs(rsaEstimate.runtimeSeconds / 3600 - 8) / 8 < 0.2,
  });

  const rsa2025 = estimateRsa(2048, ANCHOR_HARDWARE, 'gidney-2025');
  checks.push({
    label: 'Gidney 2025 — physical qubits below one million',
    metric: 'physical qubits',
    published: 1e6,
    computed: rsa2025.physicalQubits,
    tolerance: 0.25,
    pass: rsa2025.physicalQubits < 1e6,
  });
  checks.push({
    label: 'Gidney 2025 — runtime approximately five days',
    metric: 'days',
    published: 5,
    computed: rsa2025.runtimeSeconds / 86400,
    tolerance: 0.35,
    pass: Math.abs(rsa2025.runtimeSeconds / 86400 - 5) / 5 < 0.35,
  });

  const p256 = eccLogicalCost(256);
  checks.push({
    label: 'Roetteler et al. 2017 — P-256 logical qubits',
    metric: 'logical qubits',
    published: 2330,
    computed: p256.qubits,
    tolerance: 0.001,
    pass: p256.qubits === 2330,
  });
  const p521 = eccLogicalCost(521);
  checks.push({
    label: 'Roetteler et al. 2017 — P-521 logical qubits',
    metric: 'logical qubits',
    published: 4719,
    computed: p521.qubits,
    tolerance: 0.001,
    pass: p521.qubits === 4719,
  });

  return checks;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Presentation helpers
   ═══════════════════════════════════════════════════════════════════════════ */

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return 'never';
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 90) return `${seconds.toFixed(1)} s`;
  if (seconds < 5400) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 172_800) return `${(seconds / 3600).toFixed(1)} hours`;
  if (seconds < 63_072_000) return `${(seconds / 86_400).toFixed(1)} days`;
  return `${(seconds / 31_557_600).toFixed(1)} years`;
}

export function formatCount(value: number): string {
  if (!Number.isFinite(value)) return '∞';
  if (value < 1000) return value.toFixed(0);
  if (value < 1e6) return `${(value / 1e3).toFixed(1)}K`;
  if (value < 1e9) return `${(value / 1e6).toFixed(2)}M`;
  if (value < 1e12) return `${(value / 1e9).toFixed(2)}B`;
  return value.toExponential(2);
}

/**
 * Largest publicly reported physical qubit counts, for the "how far away is
 * this" gap bar. These are device announcements, not error-corrected logical
 * qubits — which is exactly the point the bar makes.
 */
export const REPORTED_DEVICES: Array<{ name: string; qubits: number; year: number; note: string }> = [
  { name: 'IBM Condor', qubits: 1121, year: 2023, note: 'Largest superconducting chip announced by IBM.' },
  { name: 'Atom Computing', qubits: 1180, year: 2023, note: 'Neutral-atom array; qubit count, not logical qubits.' },
  { name: 'IBM Heron R2', qubits: 156, year: 2024, note: 'Fewer qubits, far better error rates — the direction that matters.' },
  { name: 'Google Willow', qubits: 105, year: 2024, note: 'Demonstrated below-threshold surface-code scaling: logical error fell as distance rose.' },
];
