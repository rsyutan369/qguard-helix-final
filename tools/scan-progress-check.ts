/**
 * Dev scan progress — fidelity check.
 *
 * WHY THIS EXISTS
 * ---------------
 * A Dev repository scan reported 1% for almost its entire duration and then
 * jumped to 100%. Measured against a real public repository, the cause was not
 * a rendering bug: acquisition took 21.1s (98% of the scan) and emitted NO
 * `progress` field at all, while the engines took 0.4s and owned the whole
 * 0-100 sweep. The bar was faithfully describing 2% of the work.
 *
 * The fix splits the bar into two real bands — acquisition 0-80, engines 80-99
 * — so these assertions pin the properties that make the bar honest:
 * monotonic, in-band, no large silent jumps, and continuous across the handover
 * between the two phases.
 *
 * Runs the REAL orchestrator over a fixture corpus; no network required.
 *
 *   npx tsx tools/scan-progress-check.ts
 */

import { runExposureScan } from '../src/lib/scanner/exposure/orchestrator';
import { emptyWorkspace, type WorkspaceFile } from '../src/lib/scanner/exposure/engine-contract';
import { classifyFile } from '../src/lib/scanner/exposure/content/file-discovery';
import { resolveProfile } from '../src/lib/scanner/exposure/profiles';
import { defaultExclusions } from '../src/lib/scanner/exposure/types';
import { ACQUISITION_PROGRESS_SHARE, acquisitionProgress } from '../src/lib/scanner/exposure/dev/run-dev-scan';
import { reportStride } from '../src/lib/scanner/exposure/engine-contract';

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
    classification: classifyFile(path, content),
  };
}

const FIXTURE: WorkspaceFile[] = Array.from({ length: 40 }, (_, index) =>
  file(`src/module-${index}/crypto.ts`, [
    'import crypto from "crypto";',
    `const pair${index} = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });`,
    'const c = crypto.createCipheriv("aes-256-gcm", key, iv);',
  ].join('\n')),
).concat([
  file('package.json', '{"name":"fixture","dependencies":{"jsonwebtoken":"^9.0.0","node-forge":"^1.3.1"}}'),
  file('Dockerfile', 'FROM node:20-alpine\nUSER root'),
  file('k8s/ingress.yaml', 'apiVersion: networking.k8s.io/v1\nkind: Ingress'),
]);

const results: Array<{ name: string; pass: boolean; detail: string }> = [];
function check(name: string, pass: boolean, detail: string) {
  results.push({ name, pass, detail });
}

/** The client keeps a monotonic floor; this mirrors it so the assertions
 *  describe what an operator would actually see. */
function asRendered(values: number[]): number[] {
  const out: number[] = [];
  let floor = 0;
  for (const value of values) {
    if (value > floor) {
      floor = value;
      out.push(value);
    }
  }
  return out;
}

async function enginePhase(range?: { from: number; to: number }): Promise<number[]> {
  const workspace = emptyWorkspace();
  workspace.files = FIXTURE;
  const { engines } = resolveProfile('dev', 'standard', []);
  const seen: number[] = [];
  await runExposureScan({
    scanId: 'progress-check',
    mode: 'dev',
    target: { kind: 'repository', url: 'https://example.invalid/x/y', provider: 'github', owner: 'x', repo: 'y', visibility: 'public' },
    profileId: 'standard',
    engineIds: engines,
    workspace,
    exclusions: defaultExclusions(),
    budgetMs: 120_000,
    concurrency: 2,
    progressRange: range,
    onEvent: (event) => {
      if (typeof event.progress === 'number') seen.push(event.progress);
    },
  });
  return seen;
}

async function main() {
  /* ── 1. acquisition maps real read ratios onto its band ─────────────────
        Sampled at the cadence repo-collector actually reports at — every
        `ceil(total / 200)` files — so the sequence under test is the one an
        operator sees, not an arbitrarily sparse sample of it. */
  const TOTAL_FILES = 341; // the corpus size from the reported scan
  const stride = Math.max(1, Math.ceil(TOTAL_FILES / 200));
  const acquisition: number[] = [];
  for (let done = stride; done <= TOTAL_FILES; done += stride) {
    acquisition.push(acquisitionProgress(done, TOTAL_FILES));
  }
  acquisition.push(acquisitionProgress(TOTAL_FILES, TOTAL_FILES));
  check(
    'acquisition maps 0-100% of files onto 0-80% of the bar',
    acquisitionProgress(0, TOTAL_FILES) === 0
      && acquisition[acquisition.length - 1] === ACQUISITION_PROGRESS_SHARE,
    `0 files -> 0%, ${TOTAL_FILES} files -> ${acquisition[acquisition.length - 1]}%, in ${acquisition.length} updates`,
  );
  check(
    'acquisition progress is monotonic in files read',
    acquisition.every((value, index) => index === 0 || value >= acquisition[index - 1]),
    `${acquisition.length} samples, ${acquisition[0]}% -> ${acquisition[acquisition.length - 1]}%, never decreasing`,
  );
  check(
    'acquisition never reports progress it has not earned',
    acquisitionProgress(0, 0) === 0 && acquisitionProgress(5, 0) === 0,
    'an unknown total yields 0, not a fabricated fraction',
  );

  /* ── 2. THE REGRESSION. Acquisition must contribute to the bar at all.
          Before the fix its events carried no `progress` field, so the longest
          phase of the scan moved the bar by exactly nothing. */
  check(
    'acquisition contributes the majority of the bar',
    ACQUISITION_PROGRESS_SHARE >= 50,
    `acquisition owns 0-${ACQUISITION_PROGRESS_SHARE}%, measured at 98% of real scan time`,
  );

  /* ── 3. the engine phase stays inside the band it was given ───────────── */
  const banded = await enginePhase({ from: ACQUISITION_PROGRESS_SHARE, to: 99 });
  /* The terminal frame is 100 by definition — completion is not "99% of the
     band", it is done. Band membership is asserted over everything before it. */
  const bandedRunning = banded.filter((value) => value < 100);
  check(
    'engine progress stays inside its band until completion',
    bandedRunning.every((value) => value >= ACQUISITION_PROGRESS_SHARE && value <= 99)
      && banded[banded.length - 1] === 100,
    `running ${Math.min(...bandedRunning)}-${Math.max(...bandedRunning)} inside ${ACQUISITION_PROGRESS_SHARE}-99, terminal ${banded[banded.length - 1]}`,
  );
  check(
    'the handover is continuous — engines start where acquisition ended',
    Math.min(...bandedRunning) === ACQUISITION_PROGRESS_SHARE,
    `acquisition ends at ${ACQUISITION_PROGRESS_SHARE}, engines open at ${Math.min(...banded)}`,
  );

  /* ── 4. no silent leaps. A bar that teleports is not reporting work. ──── */
  const rendered = asRendered([...acquisition, ...banded]);
  let biggest = 0;
  for (let index = 1; index < rendered.length; index += 1) {
    biggest = Math.max(biggest, rendered[index] - rendered[index - 1]);
  }
  check(
    'the rendered bar never jumps more than 20 points',
    biggest <= 20,
    `largest single advance ${biggest}% across ${rendered.length} updates`,
  );
  check(
    'the rendered bar is strictly monotonic',
    rendered.every((value, index) => index === 0 || value > rendered[index - 1]),
    `${rendered.length} advances, ${rendered[0]}% -> ${rendered[rendered.length - 1]}%`,
  );

  /* ── 5. callers with no acquisition phase keep the whole range ────────── */
  const full = await enginePhase();
  const fullRunning = full.filter((value) => value < 100);
  check(
    'a target with no acquisition phase keeps the full range',
    Math.min(...fullRunning) < ACQUISITION_PROGRESS_SHARE && Math.max(...fullRunning) <= 99,
    `running ${Math.min(...fullRunning)}-${Math.max(...fullRunning)} — Local and connection-only Dev are unchanged`,
  );

  /* -- 6. LOCAL. Collection happens before the operator presses Start, so the
        bar covers the engine phase alone and must be smooth on its own.
        Engines used to hardcode a report stride - every 20 files here, every 50
        there - which fires ONCE on a small corpus, so the engine contributed a
        single step and then its whole weight at completion. */
  const strides = [10, 60, 341, 1500, 5000].map((total) => ({
    total,
    updates: Math.floor(total / reportStride(total)),
  }));
  check(
    'report cadence scales with the corpus instead of being hardcoded',
    strides.every((entry) => entry.updates >= 10 && entry.updates <= 60),
    strides.map((entry) => `${entry.total}f->${entry.updates} updates`).join('  '),
  );
  check(
    'a tiny corpus still reports more than once',
    reportStride(10) === 1 && reportStride(3) === 1,
    'the stride never exceeds the work, so a 3-file engine still ticks per file',
  );

  const localRendered = asRendered(await enginePhase());
  check(
    'the Local engine phase advances many times and reaches 100',
    localRendered.length >= 15 && localRendered[localRendered.length - 1] === 100,
    `${localRendered.length} advances, ends at ${localRendered[localRendered.length - 1]}%`,
  );

  /* An engine that stops early (a component budget, a byte cap) is credited its
     whole weight the moment it settles, so one large-weight engine can still
     land a double-digit step. That residue is TRUE - the engine really did
     finish - and is smoothed by interpolation in the theatre rather than by
     pretending the engine was further along than it was. */
  let localBiggest = 0;
  for (let index = 1; index < localRendered.length; index += 1) {
    localBiggest = Math.max(localBiggest, localRendered[index] - localRendered[index - 1]);
  }
  console.log(`
local engine phase: ${localRendered.length} advances, largest raw step ${localBiggest}% (interpolated in the UI)`);

  console.log(`\nacquisition band 0-${ACQUISITION_PROGRESS_SHARE}   engine band ${ACQUISITION_PROGRESS_SHARE}-99`);
  console.log(`rendered sequence: ${rendered.join(' → ')}\n`);

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
  process.exitCode = 2;
});
