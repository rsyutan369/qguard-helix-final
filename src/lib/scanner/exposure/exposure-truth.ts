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

/* ─────────────────────────────────────────────────────────────── the shape ── */

export type CountUnit = 'component' | 'finding';

export interface QuantumCounts {
  vulnerable: number;
  hybrid: number;
  pqc: number;
  resistant: number;
  unknown: number;
  notApplicable: number;
  /** Everything quantum-relevant, i.e. the denominator readiness is a share of. */
  quantumRelevant: number;
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
}

/* ──────────────────────────────────────────────────────────────── counting ── */

const EMPTY_COUNTS: QuantumCounts = {
  vulnerable: 0, hybrid: 0, pqc: 0, resistant: 0, unknown: 0, notApplicable: 0,
  quantumRelevant: 0, total: 0,
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
     `not-applicable` is excluded because symmetric material and hashes are not
     what a post-quantum migration replaces. */
  counts.quantumRelevant = counts.vulnerable + counts.hybrid + counts.pqc + counts.resistant;
  return counts;
}

/* ────────────────────────────────────────────────────────── the reconciler ── */

export function reconcileExposure(assessment: ExposureAssessment): ExposureTruth {
  const components = tally(assessment.cbom.map((entry) => entry.quantumStatus));
  const findings = tally(assessment.findings.map((entry) => entry.quantumStatus));

  /* Readiness is a share of COMPONENTS, always. Computing it over findings
     would make an estate look worse the more thoroughly it was scanned, since
     a single weak component can raise several findings. */
  const readiness = components.quantumRelevant > 0
    ? Math.round(((components.hybrid + components.pqc + components.resistant) / components.quantumRelevant) * 100)
    : null;

  const readinessReason = readiness !== null
    ? `${components.hybrid + components.pqc + components.resistant} of ${components.quantumRelevant} quantum-relevant components are hybrid or post-quantum.`
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

  const incompleteEngines = assessment.task.runs
    .filter((run) => run.state === 'failed' || run.state === 'cancelled')
    .map((run) => ({
      engineId: run.engineId,
      label: run.label,
      state: run.state,
      detail: run.detail ?? 'The engine did not complete, so this dimension is incomplete rather than clean.',
    }));

  /* De-duplicated BY DIMENSION, merging the reasons.
     The coverage ledger keys on `dimension|reason`, so two engines that could
     not read the same dimension for slightly different reasons both survive —
     and the panel then said "2 dimensions could not be read (Dependency
     vulnerability advisories, Dependency vulnerability advisories)". One
     dimension is one gap however many engines noticed it. */
  const notAssessedByDimension = new Map<string, string[]>();
  for (const entry of assessment.task.coverage.notAssessed) {
    const reasons = notAssessedByDimension.get(entry.dimension) ?? [];
    if (!reasons.includes(entry.reason)) reasons.push(entry.reason);
    notAssessedByDimension.set(entry.dimension, reasons);
  }
  const notAssessed = [...notAssessedByDimension.entries()].map(([dimension, reasons]) => ({
    dimension,
    reason: reasons.join(' '),
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

  return {
    components,
    findings,
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

/** "5 components" / "12 findings" — the unit, always said out loud. */
export function withUnit(count: number, unit: CountUnit): string {
  const noun = unit === 'component' ? 'component' : 'finding';
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
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
