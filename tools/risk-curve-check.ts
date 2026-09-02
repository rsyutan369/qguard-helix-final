/**
 * Security-risk curve — calibration check.
 *
 * WHY THIS EXISTS
 * ---------------
 * The previous model accumulated `severity x confidence` and saturated it
 * through `100 * (1 - e^(-w/120))`. Severity being ADDITIVE meant volume could
 * impersonate severity — ten low exposures and one committed private key both
 * scored exactly 57 — while the saturation pinned every estate past ~8 high
 * findings at 98-100, leaving no headroom to rank estates apart.
 *
 * The replacement builds the score OUT of the bands: the worst exposure sets a
 * floor (pulled back by its own confidence) and log-scaled volume ranks within
 * that band. These assertions pin the properties that motivated the change, so
 * a future tweak to the constants cannot quietly reintroduce either failure.
 *
 * It also prints the calibration table, which is the evidence the constants
 * were chosen from.
 *
 *   npx tsx tools/risk-curve-check.ts
 */

import { computeScores } from '../src/lib/scanner/exposure/risk';
import { riskBand, type CorrelatedExposure, type FindingConfidence, type FindingSeverity } from '../src/lib/scanner/exposure/types';

/* ──────────────────────────────────────────────────────────────── shapes ──── */

const ORDER: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

function exposuresFor(
  spec: Partial<Record<FindingSeverity, number>>,
  confidence: FindingConfidence = 'high',
): CorrelatedExposure[] {
  const out: CorrelatedExposure[] = [];
  for (const severity of ORDER) {
    for (let index = 0; index < (spec[severity] ?? 0); index += 1) {
      out.push({
        key: `${severity}-${index}`,
        title: `${severity} exposure ${index}`,
        description: 'calibration fixture',
        severity,
        confidence,
        quantumStatus: 'not-applicable',
        layers: ['source'],
        findingIds: [`${severity}-${index}`],
        evidence: [],
        engines: ['calibration'],
      } as CorrelatedExposure);
    }
  }
  return out;
}

/** The score alone — coverage/confidence/quantum are separate readings. */
function score(spec: Partial<Record<FindingSeverity, number>>, confidence: FindingConfidence = 'high'): number {
  const exposures = exposuresFor(spec, confidence);
  const result = computeScores({
    findings: [],
    exposures,
    coverage: {
      filesDiscovered: 0, filesAnalyzed: 0, filesSkipped: 0, filesUnsupported: 0,
      repositories: 0, dependencies: 0, cryptoComponents: 0, certificates: 0,
      secrets: 0, configFiles: 0, containers: 0, images: 0,
      kubernetesNamespaces: 0, kubernetesWorkloads: 0, iacFiles: 0,
      cicdWorkflows: 0, cloudResources: 0, branches: 0, commitsAnalyzed: 0,
      exclusions: [], notAssessed: [], truncated: false,
    } as never,
    runs: [],
  });
  return result.securityRisk ?? -1;
}

/* ────────────────────────────────────────────────────────── assertions ────── */

const results: Array<{ name: string; pass: boolean; detail: string }> = [];
function check(name: string, pass: boolean, detail: string) {
  results.push({ name, pass, detail });
}

/* 1 ── THE DEFECT THAT MOTIVATED THE CHANGE. Volume must never impersonate
       severity: no quantity of low-severity exposures may reach one critical. */
const oneCritical = score({ critical: 1 });
const manyLow = score({ low: 200 });
check(
  'no amount of low severity reaches one critical',
  manyLow < oneCritical,
  `200 low = ${manyLow}, 1 critical = ${oneCritical} (they were both 57 before)`,
);

/* 2 ── A single critical is a critical posture, not a moderate one. */
check(
  'one high-confidence critical lands in the critical band',
  riskBand(oneCritical) === 'critical',
  `${oneCritical} -> ${String(riskBand(oneCritical))} (was 57 -> moderate)`,
);

/* 3 ── Volume ranks WITHIN a band, never across one. An estate with no
       critical exposure must not report a critical posture. */
for (const count of [4, 8, 40, 200]) {
  const value = score({ high: count });
  check(
    `${count} high with no critical stays out of the critical band`,
    riskBand(value) === 'high',
    `${value} -> ${String(riskBand(value))}`,
  );
}

/* 4 ── Monotonic in volume: adding an exposure never lowers the score. */
let monotonic = true;
let previous = -1;
const ladder = [1, 2, 4, 8, 16, 32, 64, 128];
const ladderScores = ladder.map((count) => score({ high: count }));
for (const value of ladderScores) {
  if (value < previous) monotonic = false;
  previous = value;
}
check('monotonic in volume', monotonic, ladder.map((n, i) => `${n}h=${ladderScores[i]}`).join(' '));

/* 5 ── Monotonic in severity: a worse worst-exposure never scores lower. */
const bySeverity = ORDER.filter((s) => s !== 'info').map((severity) => score({ [severity]: 1 }));
const severityMonotonic = bySeverity.every((value, index) => index === 0 || value <= bySeverity[index - 1]);
check(
  'monotonic in severity',
  severityMonotonic,
  ORDER.filter((s) => s !== 'info').map((s, i) => `${s}=${bySeverity[i]}`).join(' '),
);

/* 6 ── Confidence pulls the floor back rather than being folded into severity:
       an unsure critical must not assert a critical posture. */
const unsureCritical = score({ critical: 1 }, 'low');
check(
  'a low-confidence critical does not assert a critical posture',
  unsureCritical < oneCritical && riskBand(unsureCritical) !== 'critical',
  `low confidence = ${unsureCritical} (${String(riskBand(unsureCritical))}), high confidence = ${oneCritical}`,
);

/* 7 ── Headroom: the realistic worst case must not pin at the ceiling, or the
       scale stops ranking estates again. */
const yourScan = score({ critical: 1, high: 8, medium: 2, low: 2 });
const tenTimesWorse = score({ critical: 10, high: 40 });
const enterprise = score({ critical: 100, high: 500 });
check(
  'a repo-scale estate leaves headroom above it',
  yourScan < tenTimesWorse && tenTimesWorse < enterprise,
  `repo=${yourScan} < 10x=${tenTimesWorse} < enterprise=${enterprise} (all three were 99-100 before)`,
);

/* 8 ── Bounded, and never null when there is something to score. */
const everything = [oneCritical, manyLow, yourScan, enterprise, unsureCritical];
check(
  'every score is inside 0-100',
  everything.every((value) => value >= 0 && value <= 100),
  everything.join(', '),
);

/* ─────────────────────────────────────────────────── calibration table ────── */

const TABLE: Array<[string, Partial<Record<FindingSeverity, number>>, FindingConfidence]> = [
  ['1 low', { low: 1 }, 'high'],
  ['10 low', { low: 10 }, 'high'],
  ['1 medium', { medium: 1 }, 'high'],
  ['1 high', { high: 1 }, 'high'],
  ['4 high', { high: 4 }, 'high'],
  ['8 high', { high: 8 }, 'high'],
  ['40 high', { high: 40 }, 'high'],
  ['200 high', { high: 200 }, 'high'],
  ['1 critical', { critical: 1 }, 'high'],
  ['1 critical (low conf.)', { critical: 1 }, 'low'],
  ['3 critical', { critical: 3 }, 'high'],
  ['1c 8h 2m 2l', { critical: 1, high: 8, medium: 2, low: 2 }, 'high'],
  ['10 critical + 40 high', { critical: 10, high: 40 }, 'high'],
  ['100 critical + 500 high', { critical: 100, high: 500 }, 'high'],
];

console.log(`\n${'ESTATE SHAPE'.padEnd(26)} SCORE  BAND`);
console.log('-'.repeat(48));
const values: number[] = [];
for (const [label, spec, confidence] of TABLE) {
  const value = score(spec, confidence);
  values.push(value);
  console.log(`${label.padEnd(26)} ${String(value).padStart(5)}  ${String(riskBand(value))}`);
}
console.log(`\nDistinct scores ${new Set(values).size}/${values.length}   range ${Math.min(...values)}-${Math.max(...values)}   pinned >=95: ${values.filter((v) => v >= 95).length}`);

let failures = 0;
console.log('');
for (const result of results) {
  if (!result.pass) failures += 1;
  console.log(`${result.pass ? 'PASS' : 'FAIL'}  ${result.name}\n      ${result.detail}`);
}
console.log(`\n${results.length - failures}/${results.length} checks passed.`);
process.exitCode = failures === 0 ? 0 : 1;
