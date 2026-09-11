/**
 * Exposure truth — ONE reconciled count model for the Local and Dev panels.
 *
 * ── The defect this removes ─────────────────────────────────────────────────
 *
 * The same page could show, from one assessment:
 *
 *   Quantum Exposure      Vulnerable: 5          (counting CBOM COMPONENTS)
 *   Findings, filtered    12 vulnerable          (counting FINDINGS)
 *   Scanned Assets        3 vuln, 2 vuln, ...    (counting FINDINGS, per asset)
 *   Reconciliation        Quantum-vulnerable: 9  (FINDINGS above informational)
 *
 * Four numbers, all labelled with words that read as the same thing, and only
 * one of them saying which unit it counted. A reader who sees "Vulnerable 5",
 * clicks the vulnerable filter and gets 12 rows has been told the product is
 * inconsistent — when in truth all four numbers were correct and none of them
 * said what they were counting.
 *
 * ── Why the units genuinely differ ──────────────────────────────────────────
 *
 * They are different things, and both are needed:
 *
 *   COMPONENT   one cryptographic primitive in one place. The unit an estate is
 *               MIGRATED in — you replace a component. This is the canonical
 *               unit for readiness, because readiness is "what share of the
 *               cryptography I own is quantum-safe".
 *
 *   FINDING     one issue worth acting on. The unit work is TRIAGED in. Several
 *               findings can attach to one component (a weak key AND a weak
 *               signature on the same certificate), and one finding can span
 *               several components.
 *
 * So the fix is not to force them equal. It is to make every panel state its
 * unit, and to publish both counts from one place so they cannot drift.
 *
 * Pure and dependency-free: the panels, the persistence layer and the check
 * tools all read the same reconciliation.
 */

import type { ExposureAssessment, ExposureFinding, FindingSeverity, QuantumStatus } from './types';
/* `algorithms` imports only types, so this cannot close a cycle with `cbom`,
   which reads `postQuantumReadiness` back out of this module. */
import { describeAlgorithm } from './algorithms';

/* ─────────────────────────────────────────────────────────────── the shape ── */

export type CountUnit = 'component' | 'finding' | 'exposure';

export interface QuantumCounts {
  vulnerable: number;
  hybrid: number;
  pqc: number;
  resistant: number;
  unknown: number;
  notApplicable: number;
  /** Everything quantum-relevant, i.e. the denominator readiness is a share of. */
  quantumRelevant: number;
  /**
   * Of these, how many are broken by CLASSICAL cryptanalysis (MD5, SHA-1, RC4,
   * DES, 3DES, Blowfish, MD4, RIPEMD).
   *
   * They sit in `resistant`, and correctly so — `resistant` is a verdict about
   * Shor's algorithm alone. But "Resistant 230" rendered in cyan, with no
   * qualifier, tells a CISO that 230 components are healthy. Populated only for
   * component tallies, where the algorithm name is available; findings and
   * exposures carry 0.
   */
  classicallyWeak: number;
  total: number;
}

export interface ExposureTruth {
  /**
   * Counts in BOTH units, each explicitly named.
   *
   * Panels pick the unit that matches what they are for, and say which one.
   */
  components: QuantumCounts;
  findings: QuantumCounts;
  /**
   * The THIRD unit, and the one every risk score is computed in.
   *
   * Correlation merges findings that are one underlying issue, so a scan with
   * 15 findings can hold 13 exposures. `computeScores` weighs EXPOSURES, which
   * is why a panel showing finding severities beside a risk score appears to
   * contradict it. Published here so no panel has to guess, and so the two
   * populations can never be tallied independently and drift.
   */
  exposures: QuantumCounts;
  /** Exposure severities — the population the risk scores are weighted over. */
  exposureSeverity: Record<FindingSeverity, number>;

  /**
   * Post-quantum readiness.
   *
   * null = NOT MEASURABLE, because no quantum-relevant cryptography was
   * observed. 0% would say "nothing you own is quantum-safe", which is a
   * verdict; "not measured" is the truth when there was nothing to assess.
   * Always a share of COMPONENTS — the unit migration happens in.
   */
  readiness: number | null;
  readinessReason: string;
  /** The unit `readiness` is computed over. Stated so a panel can print it. */
  readinessUnit: CountUnit;

  /** Findings by severity — the triage view. */
  severity: Record<FindingSeverity, number>;
  /** Findings worth acting on: everything above informational. */
  actionable: number;

  /** Engines that did not complete, so a panel never renders a partial as whole. */
  incompleteEngines: Array<{ engineId: string; label: string; state: string; detail: string }>;
  /** Dimensions the scan could not read. */
  notAssessed: Array<{ dimension: string; reason: string }>;
  /** True when any dimension is missing — the scan is partial, not clean. */
  partial: boolean;

  /**
   * Stated when the two units differ enough that a reader would notice.
   *
   * Not a warning — both numbers are right. It is the sentence that stops the
   * difference reading as a bug.
   */
  unitNote: string | null;

  /**
   * One sentence naming the population the risk scores were computed over, and
   * how it relates to the finding counts a reader sees beside them. Always
   * present once there is anything to score — this is the sentence that stops
   * "1 critical" next to "99/100" reading as a defect.
   */
  scoreUnitNote: string | null;
}

/* ──────────────────────────────────────────────────────────────── counting ── */

const EMPTY_COUNTS: QuantumCounts = {
  vulnerable: 0, hybrid: 0, pqc: 0, resistant: 0, unknown: 0, notApplicable: 0,
  quantumRelevant: 0, classicallyWeak: 0, total: 0,
};

function tally(statuses: QuantumStatus[]): QuantumCounts {
  const counts: QuantumCounts = { ...EMPTY_COUNTS };
  for (const status of statuses) {
    counts.total += 1;
    switch (status) {
      case 'vulnerable': counts.vulnerable += 1; break;
      case 'hybrid': counts.hybrid += 1; break;
      case 'pqc': counts.pqc += 1; break;
      case 'resistant': counts.resistant += 1; break;
      case 'not-applicable': counts.notApplicable += 1; break;
      default: counts.unknown += 1; break;
    }
  }
  /* `unknown` is excluded from the denominator deliberately: a primitive whose
     quantum status could not be established is not evidence of readiness OR of
     exposure, and folding it into either direction is a fabricated verdict.

     `resistant` and `not-applicable` are excluded because symmetric material
     and hashes are not what a post-quantum migration replaces. The comment
     used to say exactly that while the code added `resistant` back in — and
     since the pipeline labels every symmetric cipher and hash `resistant`
     (never `not-applicable`), the intended exclusion never fired. An estate
     full of AES-256 and SHA-256 therefore reported high readiness while every
     one of its signatures was still RSA: the precise error §16 forbids. */
  counts.quantumRelevant = counts.vulnerable + counts.hybrid + counts.pqc;
  return counts;
}

/**
 * Post-quantum readiness — THE formula, for every panel and every export.
 *
 * A share of the quantum-relevant components: those a post-quantum migration
 * actually replaces (asymmetric key establishment, signatures, certificates).
 * Hybrid deployments count at 0.6 rather than 1.0 because a hybrid still
 * carries a classical half that has to be retired eventually — it is real,
 * substantial progress, but it is not a finished migration.
 *
 * `null` means NOT MEASURABLE, not zero: an estate with no asymmetric
 * cryptography in scope has nothing to be ready or unready about, and 0%
 * would be a verdict the evidence does not support.
 */
export function postQuantumReadiness(counts: {
  vulnerable: number;
  hybrid: number;
  pqc: number;
}): number | null {
  const relevant = counts.vulnerable + counts.hybrid + counts.pqc;
  if (relevant === 0) return null;
  return Math.round(((counts.pqc + counts.hybrid * 0.6) / relevant) * 100);
}

/* ────────────────────────────────────────────────────────── the reconciler ── */

export function reconcileExposure(assessment: ExposureAssessment): ExposureTruth {
  const components = tally(assessment.cbom.map((entry) => entry.quantumStatus));
  /* Only components carry an algorithm name, so this is the only tally that can
     answer "is the resistant bucket actually healthy?". */
  components.classicallyWeak = assessment.cbom.filter(
    (entry) => describeAlgorithm(entry.canonicalAlgorithm)?.classicallyWeak === true,
  ).length;
  const findings = tally(assessment.findings.map((entry) => entry.quantumStatus));
  const exposures = tally(assessment.exposures.map((entry) => entry.quantumStatus));

  /* Readiness is a share of COMPONENTS, always. Computing it over findings
     would make an estate look worse the more thoroughly it was scanned, since
     a single weak component can raise several findings.

     ONE formula, shared with `summariseCbom` — see `postQuantumReadiness`. The
     two used to disagree on the same scan (48% here, 31% on the CBOM panel)
     because this one counted `resistant` on both sides of the ratio. */
  const readiness = postQuantumReadiness(components);

  const readinessReason = readiness !== null
    ? `${components.pqc} of ${components.quantumRelevant} quantum-relevant components are post-quantum and ${components.hybrid} are hybrid (counted at 0.6, since a hybrid deployment still carries a classical half). Symmetric and hash primitives are excluded from both sides of the ratio: they are not what a post-quantum migration replaces.`
    : components.total > 0
      ? 'No post-quantum readiness percentage is published: cryptography was observed, but none of it is quantum-relevant (asymmetric key exchange, signatures or certificates). That is not the same as being quantum-safe.'
      : 'No post-quantum readiness percentage is published: no cryptographic component was observed in scope. That is not the same as being quantum-safe.';

  const severity: Record<FindingSeverity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const finding of assessment.findings) {
    severity[finding.severity] = (severity[finding.severity] ?? 0) + 1;
  }
  const actionable = assessment.findings.filter((finding) => finding.severity !== 'info').length;

  /* Tallied HERE rather than in risk.ts, so the panel that renders a score and
     the model that computes it are counting the same rows. */
  const exposureSeverity: Record<FindingSeverity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const exposure of assessment.exposures) {
    exposureSeverity[exposure.severity] = (exposureSeverity[exposure.severity] ?? 0) + 1;
  }

  const incompleteEngines = assessment.task.runs
    .filter((run) => run.state === 'failed' || run.state === 'cancelled')
    .map((run) => ({
      engineId: run.engineId,
      label: run.label,
      state: run.state,
      detail: run.detail ?? 'The engine did not complete, so this dimension is incomplete rather than clean.',
    }));

  /* Read, not re-deduplicated. `mergeCoverage` now keys the ledger on the
     dimension itself, so the list arriving here already holds one entry per
     gap. This used to run its own dedup pass, which fixed the completeness
     note and left the Assessment Coverage panel — reading the same ledger
     directly — still showing the duplicate. Two implementations of one rule
     drift; the rule belongs at the write path, once. */
  const notAssessed = assessment.task.coverage.notAssessed.map((entry) => ({
    dimension: entry.dimension,
    reason: entry.reason,
  }));

  /* Only stated when a reader would actually notice. Two numbers that differ by
     one do not need a paragraph explaining measurement units. */
  const unitNote =
    components.vulnerable !== findings.vulnerable && (components.vulnerable > 0 || findings.vulnerable > 0)
      /* Pluralised in the same case as the word. `COMPONENT` + `s` produced
         "COMPONENTs", which reads as a typo in a panel whose whole job is to
         look precise. */
      ? `Quantum Exposure counts ${components.vulnerable} vulnerable ${components.vulnerable === 1 ? 'COMPONENT' : 'COMPONENTS'} — one cryptographic primitive in one place, the unit a migration replaces. Findings counts ${findings.vulnerable} vulnerable ${findings.vulnerable === 1 ? 'FINDING' : 'FINDINGS'} — the unit work is triaged in. Several findings can attach to one component, so the two differ by design.`
      : null;

  /* Always stated once anything was scored. Unlike `unitNote`, this is not
     conditional on the numbers differing: a reader looking at a risk score is
     entitled to know what it was computed over even when the two populations
     happen to coincide. */
  const scoreUnitNote = assessment.exposures.length > 0
    ? `Risk scores are computed over CORRELATED EXPOSURES, not raw findings: ${assessment.findings.length} finding${assessment.findings.length === 1 ? '' : 's'} correlated into ${assessment.exposures.length} exposure${assessment.exposures.length === 1 ? '' : 's'} (${describeSeverity(exposureSeverity)}). Each is weighted by severity and discounted by detection confidence, so a small number of high-severity exposures can produce a high score.`
    : null;

  return {
    components,
    findings,
    exposures,
    exposureSeverity,
    scoreUnitNote,
    readiness,
    readinessReason,
    readinessUnit: 'component',
    severity,
    actionable,
    incompleteEngines,
    notAssessed,
    partial: incompleteEngines.length > 0 || notAssessed.length > 0,
    unitNote,
  };
}

/* ─────────────────────────────────────────────────────── display helpers ──── */

/** "1 critical, 8 high, 2 medium" — omitting the bands with no members. */
export function describeSeverity(counts: Record<FindingSeverity, number>): string {
  const parts = (['critical', 'high', 'medium', 'low', 'info'] as FindingSeverity[])
    .filter((severity) => counts[severity] > 0)
    .map((severity) => `${counts[severity]} ${severity}`);
  return parts.length ? parts.join(', ') : 'none';
}

/** "5 components" / "12 findings" / "13 exposures" — the unit, said out loud. */
export function withUnit(count: number, unit: CountUnit): string {
  return `${count} ${unit}${count === 1 ? '' : 's'}`;
}

/**
 * Whether a panel may present its numbers as a complete picture.
 *
 * False when any engine failed or any dimension went unread — the panel then
 * has to say so, because a total computed over a partial scan reads as a total
 * over the whole estate.
 */
export function isComplete(truth: ExposureTruth): boolean {
  return !truth.partial;
}

/** One sentence naming what is missing, for the panel header. */
export function completenessNote(truth: ExposureTruth): string | null {
  if (!truth.partial) return null;
  const parts: string[] = [];
  if (truth.incompleteEngines.length) {
    parts.push(
      `${truth.incompleteEngines.length} engine${truth.incompleteEngines.length === 1 ? '' : 's'} did not complete (${truth.incompleteEngines.map((entry) => entry.label).join(', ')})`,
    );
  }
  if (truth.notAssessed.length) {
    parts.push(
      `${truth.notAssessed.length} dimension${truth.notAssessed.length === 1 ? '' : 's'} could not be read (${truth.notAssessed.map((entry) => entry.dimension).join(', ')})`,
    );
  }
  return `These counts are from a PARTIAL scan: ${parts.join(', and ')}. Absent evidence is not clean evidence.`;
}

/** Findings matching a quantum status — the same predicate the filter uses. */
export function findingsWithStatus(
  assessment: ExposureAssessment,
  status: QuantumStatus,
): ExposureFinding[] {
  return assessment.findings.filter((finding) => finding.quantumStatus === status);
}
