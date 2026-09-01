/**
 * Exposure engine liveness — does every engine actually RUN and DETECT?
 *
 * The panel-consistency work proves the numbers agree with each other. This
 * proves there are numbers at all: an engine that silently matches nothing
 * produces a clean-looking report, and a clean report from an engine that never
 * looked is the worst output this platform can produce.
 *
 * Three questions, per engine:
 *
 *   1. Did it reach a TERMINAL state? (completed / failed / not-applicable /
 *      not-assessed / skipped / cancelled — never left running)
 *   2. Given material it SHOULD match, did it actually emit something?
 *   3. When it emits nothing, does it say WHY — or does it just return quietly?
 *
 * (2) is the one that catches the real failure. This project has already shipped
 * two engines whose rule families matched nothing at all: four Kubernetes rule
 * families broken by a `*`-vs-`**` glob difference, and a weak-DH rule broken by
 * a leading `\b` before a digit. Both looked like clean scans.
 *
 * Run: npx tsx tools/exposure-engine-liveness-check.ts
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { emptyWorkspace } from '../src/lib/scanner/exposure/engine-contract';
import { toWorkspaceFile } from '../src/lib/scanner/exposure/content/file-discovery';
import { runExposureScan } from '../src/lib/scanner/exposure/orchestrator';
import { enginesForMode } from '../src/lib/scanner/exposure/registry';
import { resolveProfile } from '../src/lib/scanner/exposure/profiles';
import { reconcileExposure, completenessNote } from '../src/lib/scanner/exposure/exposure-truth';
import type { ExposureAssessment } from '../src/lib/scanner/exposure/types';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(label: string, condition: boolean, detail?: string): void {
  if (condition) {
    passed += 1;
    return;
  }
  failed += 1;
  failures.push(`${label}${detail ? ` — ${detail}` : ''}`);
}

function section(title: string): void {
  console.log(`\n\x1b[36m── ${title} ${'─'.repeat(Math.max(0, 56 - title.length))}\x1b[0m`);
}

/* ══════════════════════════════════════════════════════════════ the corpus ═ */

/**
 * A tree with material for EVERY content engine.
 *
 * Every credential and key below is fake. The point is coverage, not realism:
 * each file exists so that exactly one engine has something it must find, and
 * an engine that stays silent on its own file is broken.
 */
const CORPUS: Array<{ path: string; content: string; engine: string; why: string }> = [
  {
    engine: 'source-crypto',
    why: 'a real crypto API call with an established role',
    path: 'src/sign.js',
    content: [
      "import crypto from 'node:crypto';",
      "export function sign(data, key) {",
      "  return crypto.createSign('RSA-SHA256').update(data).sign(key);",
      "}",
      "export function legacyDigest(input) {",
      "  return crypto.createHash('md5').update(input).digest('hex');",
      "}",
    ].join('\n'),
  },
  {
    engine: 'dependency-analysis',
    why: 'a manifest naming crypto libraries',
    path: 'package.json',
    content: JSON.stringify(
      { name: 'fixture', version: '1.0.0', dependencies: { 'node-forge': '^1.3.0', jsonwebtoken: '^9.0.0' } },
      null,
      2,
    ),
  },
  {
    engine: 'configuration-security',
    why: 'a TLS directive offering a deprecated protocol',
    path: 'nginx/legacy.conf',
    content: [
      'server {',
      '  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;',
      '  ssl_ciphers HIGH:!aNULL:RC4;',
      '}',
    ].join('\n'),
  },
  {
    engine: 'kubernetes-security',
    why: 'a workload with a privileged container and an inline secret',
    path: 'k8s/deploy.yaml',
    content: [
      'apiVersion: apps/v1',
      'kind: Deployment',
      'metadata:',
      '  name: api',
      'spec:',
      '  template:',
      '    spec:',
      '      containers:',
      '        - name: api',
      '          image: registry.example.com/api:latest',
      '          securityContext:',
      '            privileged: true',
      '            capabilities:',
      '              add:',
      '                - SYS_ADMIN',
      '          env:',
      '            - name: DB_PASSWORD',
      '              value: hunter2-not-a-real-password',
    ].join('\n'),
  },
  {
    engine: 'container-security',
    why: 'a Dockerfile running as root from a floating tag',
    path: 'Dockerfile',
    content: ['FROM node:latest', 'USER root', 'RUN curl -k https://example.com/install.sh | sh', 'CMD ["node", "index.js"]'].join('\n'),
  },
  {
    engine: 'iac-security',
    why: 'Terraform with an unencrypted bucket',
    path: 'infra/main.tf',
    content: [
      'resource "aws_s3_bucket" "data" {',
      '  bucket = "fixture-data"',
      '}',
      'resource "aws_db_instance" "db" {',
      '  storage_encrypted = false',
      '}',
    ].join('\n'),
  },
  {
    engine: 'cicd-security',
    why: 'a pipeline with an unpinned third-party action',
    path: '.github/workflows/ci.yml',
    content: [
      'name: ci',
      'on: [push]',
      'jobs:',
      '  build:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '      - uses: some-org/risky-action@master',
    ].join('\n'),
  },
  {
    engine: 'secret-discovery',
    why: 'a credential in a URL, where the identifier does not look secret-shaped',
    path: '.env.example',
    content: ['DATABASE_URL=postgres://app:s3cr3t-fixture@db.internal:5432/app', 'DEBUG=true'].join('\n'),
  },
];

/* ═══════════════════════════════════════════════════ 1. terminal states ════ */

async function runCorpus(): Promise<ExposureAssessment> {
  const workspace = emptyWorkspace();
  for (const entry of CORPUS) {
    workspace.files.push(toWorkspaceFile(entry.path, entry.content));
  }
  const { engines } = resolveProfile('local', 'deep');
  return runExposureScan({
    scanId: 'engine-liveness',
    mode: 'local',
    target: { kind: 'local', label: 'liveness-fixture', rootName: 'liveness-fixture', fileCount: workspace.files.length, viaAgent: false },
    profileId: 'deep',
    engineIds: engines,
    workspace,
    localOnly: true,
    budgetMs: 90_000,
    concurrency: 2,
  });
}

async function main(): Promise<void> {
  console.log('\x1b[1mQGuard Helix — exposure engine liveness\x1b[0m');
  console.log('Offline. Every credential and key in the fixture tree is fake.\n');

  const assessment = await runCorpus();
  const runs = assessment.task.runs;

  section('Every selected engine reached a terminal state');

  const TERMINAL = new Set(['completed', 'failed', 'not-applicable', 'not-assessed', 'skipped', 'cancelled']);
  const selected = enginesForMode('local');
  check(
    `the local profile selected engines (${runs.length} ran of ${selected.length} available)`,
    runs.length > 0,
    'no engine ran at all',
  );
  for (const run of runs) {
    check(
      `${run.label} reached a terminal state (${run.state})`,
      TERMINAL.has(run.state),
      `left in "${run.state}" — a non-terminal engine leaves the scan looking incomplete forever`,
    );
  }

  section('Engines that found nothing SAY WHY');

  for (const run of runs) {
    if (run.findingCount > 0) continue;
    if (run.state === 'completed') continue;
    check(
      `${run.label} (${run.state}) states a reason`,
      Boolean(run.detail && run.detail.trim().length > 0),
      'an engine that reports nothing and explains nothing is indistinguishable from one that is broken',
    );
  }

  section('Each engine DETECTED the material planted for it');

  /* The assertion that catches a silently-dead rule family. Each fixture file
     exists so exactly one engine must produce evidence from it. */
  const filesWithFindings = new Set<string>();
  for (const finding of assessment.findings) {
    for (const evidence of finding.evidence) {
      if (evidence.file) filesWithFindings.add(evidence.file);
    }
  }
  for (const component of assessment.cbom) {
    if (component.file) filesWithFindings.add(component.file);
  }

  for (const entry of CORPUS) {
    check(
      `${entry.engine.padEnd(22)} detected ${entry.path}`,
      filesWithFindings.has(entry.path),
      `nothing was reported from a file planted with ${entry.why} — the rule family may be matching nothing`,
    );
  }

  section('The scan is honest about what it could not do');

  const truth = reconcileExposure(assessment);
  check(
    'coverage records the files it analysed',
    assessment.task.coverage.filesAnalyzed > 0,
    `filesAnalyzed=${assessment.task.coverage.filesAnalyzed}`,
  );
  check(
    'every not-assessed dimension carries a reason',
    truth.notAssessed.every((entry) => entry.reason.trim().length > 0),
    truth.notAssessed.filter((entry) => !entry.reason.trim()).map((entry) => entry.dimension).join(', '),
  );
  check(
    'every incomplete engine carries a reason',
    truth.incompleteEngines.every((entry) => entry.detail.trim().length > 0),
  );
  if (truth.partial) {
    check('a partial scan says so', Boolean(completenessNote(truth)));
  }

  section('Counts reconcile across units');

  check(
    'component counts sum to the component total',
    truth.components.vulnerable + truth.components.hybrid + truth.components.pqc +
      truth.components.resistant + truth.components.unknown + truth.components.notApplicable ===
      truth.components.total,
    `parts do not sum to ${truth.components.total}`,
  );
  check(
    'finding counts sum to the finding total',
    truth.findings.vulnerable + truth.findings.hybrid + truth.findings.pqc +
      truth.findings.resistant + truth.findings.unknown + truth.findings.notApplicable ===
      truth.findings.total,
    `parts do not sum to ${truth.findings.total}`,
  );
  check(
    'the component total equals the CBOM length the panels render',
    truth.components.total === assessment.cbom.length,
    `${truth.components.total} vs ${assessment.cbom.length}`,
  );
  check(
    'the finding total equals the findings length the table renders',
    truth.findings.total === assessment.findings.length,
    `${truth.findings.total} vs ${assessment.findings.length}`,
  );
  check(
    'severity counts sum to the finding total',
    Object.values(truth.severity).reduce((sum, value) => sum + value, 0) === assessment.findings.length,
  );
  check(
    'readiness is null OR a share of quantum-relevant components',
    truth.readiness === null || (truth.readiness >= 0 && truth.readiness <= 100),
    String(truth.readiness),
  );
  check(
    'readiness null implies no quantum-relevant component',
    truth.readiness !== null || truth.components.quantumRelevant === 0,
    `readiness=null but ${truth.components.quantumRelevant} quantum-relevant components exist`,
  );
  check(
    'a unit note is emitted exactly when the two units differ',
    (truth.unitNote !== null) === (truth.components.vulnerable !== truth.findings.vulnerable &&
      (truth.components.vulnerable > 0 || truth.findings.vulnerable > 0)),
  );


  section('Panels read the reconciler, not their own arithmetic');

  /* The structural half. The count model above being self-consistent fixes
     nothing if a panel keeps computing its own — which is exactly how the Web
     tab came to publish three different answers for forward secrecy. */
  const shared = readFileSync(join(process.cwd(), 'src', 'components', 'exposure', 'shared.tsx'), 'utf8');
  const intelligence = readFileSync(join(process.cwd(), 'src', 'components', 'exposure', 'ScannerIntelligence.tsx'), 'utf8');

  check(
    'QuantumExposureSummary imports the reconciler',
    /reconcileExposure/.test(shared),
    'it read intelligence.quantum directly, with no unit stated',
  );
  check(
    'and no longer destructures the raw quantum counts',
    !/const \{ quantum, topAlgorithms \} = assessment\.intelligence/.test(shared),
  );
  check(
    'the component panel states its unit',
    /Counting cryptographic components/.test(shared),
    'an unlabelled "Vulnerable 5" invites comparison with a finding count',
  );
  check(
    'the findings table states its unit',
    /finding\$\{assessment\.findings\.length === 1 \? '' : 's'\}/.test(shared) ||
      /findings`/.test(shared),
    'a bare total is comparable with the component total by accident',
  );
  check(
    'the asset inventory names its quantum column by unit',
    /Quantum \(findings\)/.test(intelligence),
  );
  check(
    'a partial scan is disclosed on the summary panel',
    /completenessNote\(truth\)/.test(shared),
    'a total over a partial scan reads as a total over the estate',
  );
  check(
    'the unit difference is explained when it occurs',
    /truth\.unitNote/.test(shared),
  );

  section('The orchestrator source is text, not binary');

  /* A raw NUL byte used as a glob sentinel made git classify orchestrator.ts as
     BINARY — every change showed as "Binary files differ" with no reviewable
     diff, on the file that decides which engines run. */
  const orchestrator = readFileSync(join(process.cwd(), 'src', 'lib', 'scanner', 'exposure', 'orchestrator.ts'));
  check(
    'orchestrator.ts contains no NUL bytes',
    !orchestrator.includes(0x00),
    'git treats the file as binary and shows no diff for it',
  );

  /* ── report ─────────────────────────────────────────────────────────────── */

  console.log('\n\x1b[2m  Measured from this run:\x1b[0m');
  console.log(`    engines run        : ${runs.length}`);
  console.log(`    findings           : ${assessment.findings.length}`);
  console.log(`    CBOM components    : ${assessment.cbom.length}`);
  console.log(`    files analysed     : ${assessment.task.coverage.filesAnalyzed}`);
  console.log(`    readiness          : ${truth.readiness === null ? 'not measured' : `${truth.readiness}%`}`);
  console.log(`    partial            : ${truth.partial ? 'yes' : 'no'}`);

  console.log(`\n\x1b[1m${'═'.repeat(66)}\x1b[0m`);
  if (failed === 0) {
    console.log(`\x1b[32m✓ ${passed} checks passed\x1b[0m`);
    return;
  }
  console.log(`\x1b[31m✗ ${failed} of ${passed + failed} checks failed\x1b[0m\n`);
  for (const failure of failures) console.log(`  \x1b[31m•\x1b[0m ${failure}`);
  process.exitCode = 1;
}

main().catch((error) => {
  console.error('\x1b[31mThe liveness harness itself failed:\x1b[0m', error);
  process.exit(1);
});
