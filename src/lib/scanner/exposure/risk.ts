/**
 * Quantum Risk Scoring (§40, §41, Spec-2 §40).
 *
 * §40: "Separate Security Risk, Quantum Risk, Migration Risk, Confidence and
 *       Coverage. Do not reduce all of these to one number."
 *
 * Five readings, five computations, each stating its own basis:
 *
 *   SECURITY RISK    present-tense exposure. Severity-weighted, confidence-
 *                    discounted, saturating. A committed private key and an
 *                    RSA signature are not the same problem and are not scored
 *                    on the same axis.
 *   QUANTUM RISK     future exposure. Computed ONLY from quantum-relevant
 *                    components, so an estate full of AES-256 cannot dilute it.
 *   MIGRATION RISK   how hard the fix is. Driven by blast radius (how many
 *                    layers the exposure spans) and by role complexity, not by
 *                    finding count.
 *   COVERAGE         what fraction of the declared scope was actually read.
 *   CONFIDENCE       weighted confidence of the findings the scores rest on.
 *
 * Every score returns `null` rather than 0 when there is nothing to measure.
 * Zero means "measured, and it is zero"; null means "not measured". Collapsing
 * the two is how an unscanned estate comes to look perfectly secure.
 */

import type {
  CorrelatedExposure,
  ExposureFinding,
  ExposureScores,
  FindingSeverity,
  ScanCoverage,
  EngineRun,
} from './types';
import { CONFIDENCE_WEIGHT, SEVERITY_ORDER, SEVERITY_WEIGHT, riskBand } from './types';

/* ────────────────────────────────────────────────────────── security risk ── */

/**
 * Band structure, taken from the SAME thresholds `riskBand()` publishes.
 *
 * The score is built out of the bands rather than mapped onto them afterwards,
 * so the number and the label it carries agree by construction. The previous
 * model computed the two independently, which is how a single critical finding
 * came to print "57 — moderate".
 */
const SECURITY_BAND_FLOOR: Record<FindingSeverity, number> = {
  critical: 80, high: 60, medium: 35, low: 15, info: 0,
};
const SECURITY_BAND_CEILING: Record<FindingSeverity, number> = {
  critical: 100, high: 80, medium: 60, low: 35, info: 15,
};
/** The floor of the band BELOW each one — where low confidence pulls back to. */
const SECURITY_BAND_PREVIOUS: Record<FindingSeverity, number> = {
  critical: 60, high: 35, medium: 15, low: 0, info: 0,
};

/**
 * Critical-equivalents at which a severity band is considered fully consumed.
 *
 * Tuned by sweeping 50-1000 against real estate shapes (tools/risk-curve-check.ts):
 * below ~200 the top of the scale pins again on large estates, above ~1000 small
 * estates stop separating. 500 is the knee.
 */
const VOLUME_REFERENCE = 500;

/**
 * Security risk — severity decides the band, volume ranks within it.
 *
 * WHY NOT A WEIGHTED SUM
 * ----------------------
 * The previous model accumulated `severity x confidence` and saturated it
 * through `100 * (1 - e^(-w/120))`. Because severity was ADDITIVE, volume could
 * impersonate severity: ten low-severity exposures and one committed private
 * key both scored exactly 57. It also under-claimed severity (one critical read
 * "moderate") while over-claiming volume (four highs with no critical present
 * read "critical", and anything past eight pinned at 98-100 with no headroom
 * left to rank estates apart).
 *
 * THE MODEL
 * ---------
 *   floor   the worst exposure's band floor, pulled back toward the band below
 *           it in proportion to that exposure's CONFIDENCE. A critical the
 *           scanner is unsure of must not assert a critical posture, and
 *           severity and confidence stay separate readings (S37) rather than
 *           being multiplied into one.
 *   volume  log-scaled critical-equivalents. Estates span orders of magnitude;
 *           a linear term runs away with repository size and an exponential one
 *           pins after a handful of findings.
 *   score   floor + (band ceiling - floor) * volume
 *
 * Volume can therefore rank an estate within its band but can never carry it
 * into a higher one. The band names the worst class of thing actually present,
 * which is the claim the evidence supports.
 */
function computeSecurityRisk(exposures: CorrelatedExposure[]): { score: number | null; basis: string } {
  if (exposures.length === 0) {
    return { score: null, basis: 'No exposures were recorded, so no security risk score is published.' };
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let equivalents = 0;
  let worst = exposures[0];

  for (const exposure of exposures) {
    counts[exposure.severity] += 1;
    /* A "critical-equivalent": one high-confidence critical is 1.0, a
       high-confidence low is 0.1, an informational exposure is 0. */
    equivalents += (SEVERITY_WEIGHT[exposure.severity] / 100) * CONFIDENCE_WEIGHT[exposure.confidence];
    if (SEVERITY_ORDER[exposure.severity] < SEVERITY_ORDER[worst.severity]) worst = exposure;
  }

  const bandFloor = SECURITY_BAND_FLOOR[worst.severity];
  const previousFloor = SECURITY_BAND_PREVIOUS[worst.severity];
  const floor = previousFloor + (bandFloor - previousFloor) * CONFIDENCE_WEIGHT[worst.confidence];
  const ceiling = SECURITY_BAND_CEILING[worst.severity];

  const volume = Math.min(1, Math.log10(1 + equivalents) / Math.log10(1 + VOLUME_REFERENCE));
  const score = Math.max(0, Math.min(100, Math.round(floor + (ceiling - floor) * volume)));

  const parts: string[] = [];
  if (counts.critical) parts.push(`${counts.critical} critical`);
  if (counts.high) parts.push(`${counts.high} high`);
  if (counts.medium) parts.push(`${counts.medium} medium`);
  if (counts.low) parts.push(`${counts.low} low`);

  const confidenceNote = worst.confidence === 'high'
    ? ''
    : ` at ${worst.confidence} confidence, which pulls the floor back from ${bandFloor}`;

  return {
    score,
    basis: `Security risk ${score}/100 from ${exposures.length} correlated exposure${exposures.length === 1 ? '' : 's'}${parts.length ? ` (${parts.join(', ')})` : ''}. The most severe is ${worst.severity}${confidenceNote}, setting the floor at ${Math.round(floor)}; the ${equivalents.toFixed(1)} critical-equivalents these exposures amount to then place it ${Math.round(volume * 100)}% of the way to ${ceiling}. Severity decides the band and volume ranks within it, so a large number of lower-severity exposures can never present as a critical one.`,
  };
}

/* ─────────────────────────────────────────────────────────── quantum risk ── */

function computeQuantumRisk(exposures: CorrelatedExposure[]): { score: number | null; basis: string } {
  const relevant = exposures.filter(
    (exposure) => exposure.quantumStatus === 'vulnerable' || exposure.quantumStatus === 'hybrid' || exposure.quantumStatus === 'pqc',
  );

  if (relevant.length === 0) {
    return {
      score: null,
      basis:
        'No quantum-relevant cryptography was observed in scope, so no quantum risk score is published. This is not the same as being quantum-safe — it means the scan found no asymmetric key exchange, signature or certificate to assess.',
    };
  }

  const vulnerable = relevant.filter((exposure) => exposure.quantumStatus === 'vulnerable');
  const hybrid = relevant.filter((exposure) => exposure.quantumStatus === 'hybrid');
  const pqc = relevant.filter((exposure) => exposure.quantumStatus === 'pqc');

  /* The proportion vulnerable is the base. Exposure to the Internet and
     long-lived assertions (certificates, code signing) escalate it, because
     those are the ones harvest-now-decrypt-later actually reaches. */
  const proportion = vulnerable.length / relevant.length;
  let score = proportion * 100;

  const exposedRoles = new Set(['tls', 'certificate', 'key-exchange', 'code-signing', 'token-signing']);
  const exposedVulnerable = vulnerable.filter((exposure) => exposure.role && exposedRoles.has(exposure.role));
  if (exposedVulnerable.length > 0) {
    score = Math.min(100, score + 10 + Math.min(15, exposedVulnerable.length * 3));
  }

  // Hybrid deployments are real mitigation and are credited as such.
  if (hybrid.length > 0) score = Math.max(0, score - Math.min(20, hybrid.length * 5));

  const rounded = Math.round(score);
  return {
    score: rounded,
    basis: `Quantum risk ${rounded}/100: ${vulnerable.length} of ${relevant.length} quantum-relevant exposure${relevant.length === 1 ? '' : 's'} are broken by Shor's algorithm${hybrid.length ? `, ${hybrid.length} are hybrid` : ''}${pqc.length ? `, ${pqc.length} are post-quantum` : ''}${exposedVulnerable.length ? `; ${exposedVulnerable.length} sit in an Internet-facing or long-lived-assertion role` : ''}. Symmetric and hash primitives are excluded from both sides of this ratio.`,
  };
}

/* ───────────────────────────────────────────────────────── migration risk ── */

function computeMigrationRisk(exposures: CorrelatedExposure[]): { score: number | null; basis: string } {
  const candidates = exposures.filter((exposure) => exposure.migration?.candidate);
  if (candidates.length === 0) {
    return { score: null, basis: 'No migration candidates were identified, so no migration risk score is published.' };
  }

  /* Migration risk is about DIFFICULTY, not quantity. The two drivers are how
     many layers an exposure spans (a key that appears in source, a container
     and an ingress must change in three places at once) and the intrinsic
     complexity of the role. */
  let total = 0;
  let deepest = 0;
  const complexityWeight = { low: 20, medium: 50, high: 85 } as const;

  for (const exposure of candidates) {
    const layers = exposure.layers.length;
    deepest = Math.max(deepest, layers);
    const complexity = complexityWeight[exposure.migration?.complexity ?? 'medium'];
    const spanPenalty = Math.min(30, (layers - 1) * 12);
    total += Math.min(100, complexity + spanPenalty);
  }

  const score = Math.round(total / candidates.length);
  return {
    score,
    basis: `Migration risk ${score}/100 across ${candidates.length} candidate${candidates.length === 1 ? '' : 's'}; the deepest spans ${deepest} layer${deepest === 1 ? '' : 's'}, which is the number of places that must change together.`,
  };
}

/* ─────────────────────────────────────────────────────────────── coverage ── */

function computeCoverage(coverage: ScanCoverage, runs: EngineRun[]): { score: number | null; basis: string } {
  /* Coverage is MEASURED / APPLICABLE, never measured / catalogue.
     `not-applicable` engines leave the denominator: a repository with no
     Dockerfile, no Kubernetes manifests, no IaC and no CI/CD definitions was
     scanned completely, and reporting it as 68% covered punishes it for
     lacking things it does not have. It also makes the figure meaningless —
     no repository of that shape could ever reach 100% however thoroughly it
     was read. */
  const applicable = runs.filter(
    (run) => run.state !== 'pending' && run.state !== 'skipped' && run.state !== 'not-applicable',
  );
  const inapplicable = runs.length - applicable.length;

  if (applicable.length === 0) {
    return {
      score: null,
      basis: inapplicable > 0
        ? `No coverage figure is published: all ${inapplicable} selected engine${inapplicable === 1 ? '' : 's'} reported that they do not apply to this target.`
        : 'No engine ran, so no coverage figure is published.',
    };
  }

  /* Two components, deliberately: what fraction of the ENGINES reported, and
     what fraction of the FILES were read. An engine that failed reduces
     coverage even if every file it would have read was analysed by another. */
  const reported = applicable.filter((run) => run.state === 'completed').length;
  const engineShare = reported / applicable.length;

  const discovered = coverage.filesDiscovered;
  const fileShare = discovered > 0 ? coverage.filesAnalyzed / discovered : 1;

  const score = Math.round(((engineShare * 0.6 + fileShare * 0.4) * 100));

  const limitations: string[] = [];
  if (coverage.exclusions.length) limitations.push(`${coverage.exclusions.length} exclusion rule${coverage.exclusions.length === 1 ? '' : 's'} in force`);
  if (coverage.filesUnsupported) limitations.push(`${coverage.filesUnsupported} binary or unsupported file${coverage.filesUnsupported === 1 ? '' : 's'}`);
  if (coverage.notAssessed.length) limitations.push(`${coverage.notAssessed.length} dimension${coverage.notAssessed.length === 1 ? '' : 's'} not assessed`);
  if (coverage.truncated) limitations.push('a bounded budget truncated the analysis');

  /* Stated, not hidden: a reader comparing "6 of 6 engines" against a catalogue
     of 13 needs to be told the other 7 were excluded because they do not
     apply, or the figure looks like it is quietly ignoring them. */
  const applicabilityNote = inapplicable > 0
    ? ` ${inapplicable} further engine${inapplicable === 1 ? '' : 's'} did not apply to this target and ${inapplicable === 1 ? 'is' : 'are'} excluded from the ratio.`
    : '';

  return {
    score: Math.max(0, Math.min(100, score)),
    basis: `Coverage ${score}%: ${reported} of ${applicable.length} applicable engines completed and ${coverage.filesAnalyzed} of ${discovered} discovered files were analysed${limitations.length ? `. Limitations: ${limitations.join('; ')}.` : '.'}${applicabilityNote}`,
  };
}

/* ───────────────────────────────────────────────────────────── confidence ── */

function computeConfidence(findings: ExposureFinding[]): { score: number | null; basis: string } {
  if (findings.length === 0) {
    return { score: null, basis: 'No findings were produced, so no confidence figure is published.' };
  }

  /* Weighted by severity: confidence in the critical findings matters far more
     than confidence in the informational ones. */
  let weighted = 0;
  let weight = 0;
  const observed = findings.filter((finding) => finding.detection === 'observed').length;

  for (const finding of findings) {
    const importance = Math.max(1, SEVERITY_WEIGHT[finding.severity]);
    weighted += CONFIDENCE_WEIGHT[finding.confidence] * importance;
    weight += importance;
  }

  const score = Math.round((weighted / weight) * 100);
  return {
    score,
    basis: `Confidence ${score}%: severity-weighted across ${findings.length} finding${findings.length === 1 ? '' : 's'}, of which ${observed} (${Math.round((observed / findings.length) * 100)}%) were directly observed rather than inferred.`,
  };
}

/* ───────────────────────────────────────────────────────────────── public ── */

export function computeScores(input: {
  findings: ExposureFinding[];
  exposures: CorrelatedExposure[];
  coverage: ScanCoverage;
  runs: EngineRun[];
}): ExposureScores {
  const security = computeSecurityRisk(input.exposures);
  const quantum = computeQuantumRisk(input.exposures);
  const migration = computeMigrationRisk(input.exposures);
  const coverage = computeCoverage(input.coverage, input.runs);
  const confidence = computeConfidence(input.findings);

  return {
    securityRisk: security.score,
    quantumRisk: quantum.score,
    migrationRisk: migration.score,
    coverage: coverage.score,
    confidence: confidence.score,
    securityBand: riskBand(security.score),
    quantumBand: riskBand(quantum.score),
    migrationBand: riskBand(migration.score),
    basis: [security.basis, quantum.basis, migration.basis, coverage.basis, confidence.basis],
  };
}

/** Prioritise migration work (Spec-2 §40). Never by algorithm name alone. */
export function prioritiseMigration(exposures: CorrelatedExposure[]): Array<{
  exposure: CorrelatedExposure;
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  score: number;
  drivers: string[];
}> {
  const internetFacingLayers = new Set(['edge', 'kubernetes', 'cloud', 'certificate']);
  const longLivedRoles = new Set(['certificate', 'code-signing', 'token-signing']);

  return exposures
    .filter((exposure) => exposure.migration?.candidate)
    .map((exposure) => {
      const drivers: string[] = [];
      let score = 0;

      if (exposure.severity === 'critical') { score += 35; drivers.push('critical severity'); }
      else if (exposure.severity === 'high') { score += 22; drivers.push('high severity'); }
      else if (exposure.severity === 'medium') { score += 10; }

      if (exposure.layers.some((layer) => internetFacingLayers.has(layer))) {
        score += 20;
        drivers.push('Internet-facing exposure');
      }
      if (exposure.role && longLivedRoles.has(exposure.role)) {
        score += 18;
        drivers.push('long-lived cryptographic assertion');
      }
      if (exposure.role === 'key-exchange') {
        score += 16;
        drivers.push('harvest-now-decrypt-later reach');
      }
      if (exposure.layers.length > 2) {
        score += 8;
        drivers.push(`blast radius across ${exposure.layers.length} layers`);
      }
      if (exposure.confidence === 'high') { score += 6; drivers.push('high detection confidence'); }
      else if (exposure.confidence === 'low' || exposure.confidence === 'unknown') { score -= 10; drivers.push('low detection confidence — verify before scheduling'); }

      const priority: 'P1' | 'P2' | 'P3' | 'P4' = score >= 60 ? 'P1' : score >= 40 ? 'P2' : score >= 20 ? 'P3' : 'P4';
      return { exposure, priority, score, drivers };
    })
    .sort((a, b) => b.score - a.score);
}
