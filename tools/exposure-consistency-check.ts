/**
 * Exposure assessment — cross-panel consistency check.
 *
 * WHY THIS EXISTS
 * ---------------
 * A Dev scan reported "1 CRITICAL" on the theatre donut and "Security risk
 * 99/100" beside it, and a coverage basis reading "126 of 341 files" under a
 * tile reading "477 / 479 FILES". Every one of those numbers was individually
 * correct. They disagreed because three different populations — components,
 * findings and correlated exposures — were being tallied independently by
 * different panels, and because summed per-engine unit counts were being
 * labelled as files.
 *
 * These assertions pin the reconciliation. They run the REAL orchestrator over
 * a fixture workspace, so the numbers come from the real engines, the real
 * correlator and the real scoring model — not from hand-written expectations.
 *
 *   npx tsx tools/exposure-consistency-check.ts
 */

import { runExposureScan } from '../src/lib/scanner/exposure/orchestrator';
import { emptyWorkspace, type WorkspaceFile } from '../src/lib/scanner/exposure/engine-contract';
import { reconcileExposure } from '../src/lib/scanner/exposure/exposure-truth';
import { resolveProfile } from '../src/lib/scanner/exposure/profiles';
import { classifyFile } from '../src/lib/scanner/exposure/content/file-discovery';
import { defaultExclusions, riskBand, SEVERITY_ORDER, type FindingSeverity } from '../src/lib/scanner/exposure/types';

/* ─────────────────────────────────────────────────────────────── fixture ──── */

function file(path: string, content: string): WorkspaceFile {
  const basename = path.split('/').pop() ?? path;
  const dot = basename.lastIndexOf('.');
  return {
    path,
    content,
    size: content.length,
    binary: false,
    ext: dot > 0 ? basename.slice(dot).toLowerCase() : '',
    basename: basename.toLowerCase(),
    /* The REAL classifier, not a hardcoded 'other'. Engines select files by
       classification, so a fixture that mislabels its own corpus silently
       exercises nothing and every assertion passes vacuously. */
    classification: classifyFile(path, content),
  };
}

/* A corpus shaped like the repository that produced the report: asymmetric
   crypto in source, credential material in an env file, crypto-relevant
   dependencies, a container definition and a Kubernetes manifest. */
const FIXTURE: WorkspaceFile[] = [
  file('src/tls/client.ts', [
    'import crypto from "crypto";',
    'const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });',
    'const sig = crypto.createSign("RSA-SHA256");',
  ].join('\n')),
  file('src/auth/jwt.ts', [
    'import jwt from "jsonwebtoken";',
    'export const token = jwt.sign(payload, key, { algorithm: "ES256" });',
  ].join('\n')),
  file('src/db/encrypt.ts', 'const c = crypto.createCipheriv("aes-256-gcm", key, iv);\nconst h = crypto.createHash("sha1");'),
  file('.env.local', 'GOOGLE_API_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuv\nNEXTAUTH_SECRET=6f1c0d9b8a7e5f4c3b2a1908d7e6f5c4'),
  file('package.json', JSON.stringify({
    name: 'fixture', version: '1.0.0',
    dependencies: { jsonwebtoken: '^9.0.0', 'node-forge': '^1.3.1', bcrypt: '^5.1.0' },
  })),
  file('Dockerfile', 'FROM node:20-alpine\nUSER root\nRUN npm ci --omit=dev'),
  file('k8s/ingress.yaml', 'apiVersion: networking.k8s.io/v1\nkind: Ingress\nspec:\n  tls:\n    - hosts: [api.example.com]'),
];

/* ─────────────────────────────────────────────────────────── assertions ───── */

const results: Array<{ name: string; pass: boolean; detail: string }> = [];

function check(name: string, pass: boolean, detail: string) {
  results.push({ name, pass, detail });
}

async function main() {
  const workspace = emptyWorkspace();
  workspace.files = FIXTURE;

  const { engines } = resolveProfile('dev', 'deep', []);
  const assessment = await runExposureScan({
    scanId: 'consistency-check',
    mode: 'dev',
    target: { kind: 'repository', url: 'https://github.com/fixture/repo', provider: 'github', owner: 'fixture', repo: 'repo', visibility: 'public' },
    profileId: 'deep',
    engineIds: engines,
    workspace,
    exclusions: defaultExclusions(),
    budgetMs: 120_000,
    concurrency: 2,
  });

  const truth = reconcileExposure(assessment);
  const { scores, coverage, runs } = assessment.task;

  /* 1 ── Per-severity counts must sum to the headline, in BOTH units. A panel
          that shows a breakdown whose parts do not reach its own total is the
          most common way a dashboard is caught being wrong. */
  const findingSum = (Object.keys(truth.severity) as FindingSeverity[])
    .reduce((total, severity) => total + truth.severity[severity], 0);
  check(
    'finding severities sum to the finding total',
    findingSum === assessment.findings.length,
    `${findingSum} vs ${assessment.findings.length}`,
  );

  const exposureSum = (Object.keys(truth.exposureSeverity) as FindingSeverity[])
    .reduce((total, severity) => total + truth.exposureSeverity[severity], 0);
  check(
    'exposure severities sum to the exposure total',
    exposureSum === assessment.exposures.length,
    `${exposureSum} vs ${assessment.exposures.length}`,
  );

  /* 2 ── Correlation may merge findings, never invent them. An exposure count
          above the finding count means the correlator produced rows from
          nothing. */
  check(
    'correlation never produces more exposures than findings',
    assessment.exposures.length <= assessment.findings.length,
    `${assessment.exposures.length} exposures from ${assessment.findings.length} findings`,
  );

  /* 3 ── Every exposure references findings that actually exist. */
  const findingIds = new Set(assessment.findings.map((finding) => finding.id));
  const orphaned = assessment.exposures.flatMap((exposure) =>
    exposure.findingIds.filter((id) => !findingIds.has(id)),
  );
  check(
    'every exposure references real findings',
    orphaned.length === 0,
    orphaned.length ? `${orphaned.length} dangling id(s): ${orphaned.slice(0, 3).join(', ')}` : 'none dangling',
  );

  /* 4 ── The score's own basis line must name the exposure counts the
          reconciler publishes. This is the sentence the user reads under the
          Risk Decomposition tiles, and it is where "1 critical / 99" is
          explained or not. */
  const securityBasis = scores.basis[0] ?? '';
  const basisNamesExposures = securityBasis.includes(`${assessment.exposures.length} correlated exposure`);
  check(
    'security basis names the exposure population it scored',
    basisNamesExposures,
    securityBasis.slice(0, 120),
  );

  const criticalExposures = truth.exposureSeverity.critical;
  check(
    'security basis severity counts match the reconciler',
    criticalExposures === 0 || securityBasis.includes(`${criticalExposures} critical`),
    `reconciler says ${criticalExposures} critical exposures`,
  );

  /* 4b ─ The score and the band it is published with must agree. They are now
          built from the same thresholds, so a disagreement means one of them
          was computed somewhere else. Calibration itself is pinned separately
          in tools/risk-curve-check.ts. */
  check(
    'the published band matches the published score',
    scores.securityRisk === null || scores.securityBand === riskBand(scores.securityRisk),
    `score=${String(scores.securityRisk)} band=${String(scores.securityBand)} expected=${String(riskBand(scores.securityRisk))}`,
  );

  check(
    'the security basis explains the floor the score was built from',
    scores.securityRisk === null || /setting the floor at \d+/.test(securityBasis),
    securityBasis.slice(-160),
  );

  /* 5 ── The reconciler must publish the sentence that explains the unit gap.
          Without it the theatre donut and the risk score look contradictory. */
  check(
    'score unit note is published whenever anything was scored',
    assessment.exposures.length === 0 || Boolean(truth.scoreUnitNote),
    truth.scoreUnitNote ? truth.scoreUnitNote.slice(0, 100) : 'absent',
  );

  /* 6 ── Coverage: analysed files can never exceed discovered files. The
          theatre used to sum per-engine unit counts and call them files, which
          produced 477 "of" 479 on a 341-file corpus. */
  check(
    'files analysed never exceeds files discovered',
    coverage.filesAnalyzed <= coverage.filesDiscovered,
    `${coverage.filesAnalyzed} analysed / ${coverage.filesDiscovered} discovered`,
  );

  const summedUnits = runs.reduce((total, run) => total + (run.units?.total ?? 0), 0);
  check(
    'summed engine passes are NOT the file count (they double-count by design)',
    coverage.filesDiscovered === 0 || summedUnits >= coverage.filesDiscovered,
    `${summedUnits} engine passes over ${coverage.filesDiscovered} discovered files — a tile showing passes must not say "files"`,
  );

  /* 7 ── Every engine reaches a terminal state, so no panel renders a partial
          run as a whole one. */
  const unterminated = runs.filter((run) => run.state === 'pending' || run.state === 'running');
  check(
    'every selected engine reached a terminal state',
    unterminated.length === 0,
    unterminated.length ? unterminated.map((run) => `${run.engineId}=${run.state}`).join(', ') : 'all terminal',
  );

  /* 8 ── Coverage's "completed" is stricter than "settled". Both are legitimate;
          a panel must not print one under the other's label. */
  const completed = runs.filter((run) => run.state === 'completed').length;
  const settled = runs.filter((run) => run.state !== 'pending' && run.state !== 'running').length;
  check(
    'completed is a subset of settled',
    completed <= settled,
    `${completed} completed, ${settled} settled, ${runs.length} selected`,
  );

  /* 9 ── Scores are null, never 0, when nothing was measured. Zero is a verdict;
          null is the absence of one. */
  const quantumRelevant = truth.components.quantumRelevant;
  check(
    'quantum risk is withheld rather than zeroed when nothing is quantum-relevant',
    quantumRelevant > 0 || scores.quantumRisk === null,
    `quantumRelevant=${quantumRelevant} quantumRisk=${String(scores.quantumRisk)}`,
  );
  check(
    'readiness is withheld rather than zeroed when nothing is quantum-relevant',
    quantumRelevant > 0 || truth.readiness === null,
    `readiness=${String(truth.readiness)}`,
  );

  /* 10 ─ The intelligence block the posture tiles read must agree with the
          reconciler, or the strip and the Quantum Exposure panel disagree. */
  check(
    'posture tiles and Quantum Exposure count the same components',
    assessment.intelligence.quantum.vulnerable === truth.components.vulnerable,
    `intelligence=${assessment.intelligence.quantum.vulnerable} reconciler=${truth.components.vulnerable}`,
  );
  check(
    'posture tiles and the findings table count the same severities',
    assessment.intelligence.severity.critical === truth.severity.critical
      && assessment.intelligence.severity.high === truth.severity.high,
    `intelligence c=${assessment.intelligence.severity.critical}/h=${assessment.intelligence.severity.high} reconciler c=${truth.severity.critical}/h=${truth.severity.high}`,
  );

  /* 11 ─ byEngine finding counts must sum to the finding total (Rule 4:
          ownership is total and unique). */
  const byEngineSum = assessment.intelligence.byEngine.reduce((total, entry) => total + entry.findings, 0);
  check(
    'per-engine finding counts sum to the finding total',
    byEngineSum === assessment.findings.length,
    `${byEngineSum} vs ${assessment.findings.length}`,
  );

  const byLayerSum = assessment.intelligence.byLayer.reduce((total, entry) => total + entry.findings, 0);
  check(
    'per-layer finding counts sum to the finding total',
    byLayerSum === assessment.findings.length,
    `${byLayerSum} vs ${assessment.findings.length}`,
  );

  /* 12 ─ The top severity a panel would headline must be the real maximum. */
  const realTop = assessment.exposures.reduce<FindingSeverity | null>(
    (top, exposure) => (!top || SEVERITY_ORDER[exposure.severity] < SEVERITY_ORDER[top] ? exposure.severity : top),
    null,
  );
  const tallyTop = (['critical', 'high', 'medium', 'low', 'info'] as FindingSeverity[])
    .find((severity) => truth.exposureSeverity[severity] > 0) ?? null;
  check(
    'headline severity derived from the tally matches the rows',
    realTop === tallyTop,
    `rows=${String(realTop)} tally=${String(tallyTop)}`,
  );

  /* ── report ─────────────────────────────────────────────────────────── */
  console.log(`\nFixture: ${assessment.findings.length} findings, ${assessment.exposures.length} exposures, ${assessment.cbom.length} components`);
  console.log(`Scores: security=${String(scores.securityRisk)} quantum=${String(scores.quantumRisk)} migration=${String(scores.migrationRisk)} coverage=${String(scores.coverage)} confidence=${String(scores.confidence)}\n`);

  let failures = 0;
  for (const result of results) {
    if (!result.pass) failures += 1;
    console.log(`${result.pass ? 'PASS' : 'FAIL'}  ${result.name}\n      ${result.detail}`);
  }
  console.log(`\n${results.length - failures}/${results.length} checks passed.`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((error) => {
  console.error('check failed to run:', (error as Error).message);
  console.error((error as Error).stack);
  process.exitCode = 2;
});
