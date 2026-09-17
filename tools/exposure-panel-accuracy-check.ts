/**
 * Panel accuracy check for the Local and Dev exposure surfaces.
 *
 * `tools/exposure-panel-audit.ts` already reconciles the counts the ORCHESTRATOR
 * publishes — findings against the ledger, the CBOM against the reconciler, the
 * workflow graph against both. It has never covered the derivations the PANELS
 * perform on top of those counts, and that is precisely where every panel defect
 * has lived: a derivation inside a `.tsx` component cannot be asserted without
 * re-implementing it, and a re-implementation is a second source of truth that
 * agrees on the day it is written and never again.
 *
 * `src/lib/scanner/exposure/panel-model.ts` exists so those derivations live
 * outside the components. This is the tool its header names: it runs the REAL
 * pipeline over a REAL corpus and asserts, over the same numbers the panels
 * render:
 *
 *   Scanned Assets       rows reconcile to the finding and component arrays,
 *                        and the header does not present them as the estate
 *   Correlated Exposures the merged/cross-layer/singleton split is exact, and
 *                        the hidden population is declared
 *   Evidence Matrix      corroborated + unbacked is the whole finding set
 *   Standards Cited      the column counts FINDINGS, and the uncited remainder
 *                        is declared
 *   Algorithms observed  the chip row's own denominators
 *   Coverage / status    a scan with an unread dimension is never published as
 *                        complete, and never scores 100% coverage
 *
 *   npx tsx tools/exposure-panel-accuracy-check.ts [directory] [mode] [profile]
 *
 * Defaults: the repo's own src/components, mode=local, profile=deep.
 */

import fs from 'node:fs';
import path from 'node:path';
import { runExposureScan } from '@/lib/scanner/exposure/orchestrator';
import { resolveProfile } from '@/lib/scanner/exposure/profiles';
import { reconcileExposure } from '@/lib/scanner/exposure/exposure-truth';
import {
  algorithmChipCoverage,
  deriveStandards,
  evidencePopulation,
  summariseAssets,
  summariseCorrelation,
  summariseStandards,
} from '@/lib/scanner/exposure/panel-model';
import type { WorkspaceFile } from '@/lib/scanner/exposure/engine-contract';
import { emptyWorkspace } from '@/lib/scanner/exposure/engine-contract';
import { toWorkspaceFile } from '@/lib/scanner/exposure/content/file-discovery';
import type { ExposureAssessment, ScanMode, ScanTarget } from '@/lib/scanner/exposure/types';

/* ─────────────────────────────────────────────────────────────── corpus ──── */

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.vite', 'out',
  'target', '.turbo', '.cache', 'gen', 'android', 'ios',
]);

const MAX_FILES = Number(process.env.AUDIT_MAX_FILES || 2500);
const MAX_BYTES = 512 * 1024;

function walk(root: string): WorkspaceFile[] {
  const files: WorkspaceFile[] = [];
  const stack: string[] = [root];
  while (stack.length > 0 && files.length < MAX_FILES) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) break;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      let stat: fs.Stats;
      try {
        stat = fs.statSync(full);
      } catch {
        continue;
      }
      if (stat.size > MAX_BYTES) continue;
      let content: string;
      try {
        content = fs.readFileSync(full, 'utf8');
      } catch {
        continue;
      }
      files.push(toWorkspaceFile(path.relative(root, full).split(path.sep).join('/'), content, stat.size));
    }
  }
  return files;
}

/* ────────────────────────────────────────────────────────────── reporting ── */

const BOLD = (text: string) => `[1m${text}[0m`;
const DIM = (text: string) => `[2m${text}[0m`;
const CYAN = (text: string) => `[36m${text}[0m`;
const GREEN = (text: string) => `[32m${text}[0m`;
const RED = (text: string) => `[31m${text}[0m`;

function panel(title: string) {
  console.log('');
  console.log(CYAN(`── ${title} ${'─'.repeat(Math.max(0, 62 - title.length))}`));
}

const problems: string[] = [];
function assert(ok: boolean, label: string, detail: string) {
  if (ok) {
    console.log(`  ${GREEN('ok  ')} ${label}`);
  } else {
    console.log(`  ${RED('FAIL')} ${label} ${DIM(`(${detail})`)}`);
    problems.push(`${label} — ${detail}`);
  }
}

function row(label: string, value: unknown) {
  console.log(`  ${label.padEnd(40)} ${String(value)}`);
}

/* ────────────────────────────────────────────────────────────────── main ── */

async function main() {
  const dir = path.resolve(process.argv[2] || path.join(import.meta.dirname, '..', 'src', 'components'));
  const mode = (process.argv[3] as ScanMode) || 'local';
  const profileId = process.argv[4] || 'deep';

  console.log(BOLD('\nExposure PANEL ACCURACY check — LIVE pipeline'));
  console.log(`  corpus  : ${dir}`);
  console.log(`  mode    : ${mode}`);
  console.log(`  profile : ${profileId}`);

  const files = walk(dir);
  const { engines } = resolveProfile(mode, profileId);
  console.log(`  files   : ${files.length}`);
  console.log(`  engines : ${engines.length}`);

  const workspace = emptyWorkspace();
  workspace.files = files;

  const target: ScanTarget =
    mode === 'local'
      ? { kind: 'local', label: path.basename(dir), rootName: path.basename(dir), fileCount: files.length, viaAgent: false }
      : {
          kind: 'repository',
          url: 'https://github.com/qguard/helix',
          provider: 'github',
          owner: 'qguard',
          repo: 'helix',
          branch: 'main',
          visibility: 'private',
        };

  const assessment: ExposureAssessment = await runExposureScan({
    scanId: 'panel-accuracy-' + Date.now().toString(36),
    mode,
    target,
    profileId,
    engineIds: engines,
    workspace,
    localOnly: mode === 'local',
    budgetMs: 600_000,
    engineBudgetMs: 180_000,
  });

  const truth = reconcileExposure(assessment);

  /* ═══════════════════════════════════════════════ 1. Scanned Assets ════ */
  panel('1. SCANNED ASSETS');
  const assets = summariseAssets(assessment);
  row('rows', assets.rows.length);
  row('carrying evidence', assets.scanned);
  row('with gaps', assets.gaps);
  row('files analysed', assets.filesAnalyzed);
  row('files with nothing observed', assets.clean);

  const rowFindings = assets.rows.reduce((total, entry) => total + entry.findings, 0);
  const rowComponents = assets.rows.reduce((total, entry) => total + entry.components, 0);
  const rowCritical = assets.rows.reduce((total, entry) => total + entry.critical, 0);
  const rowVulnerable = assets.rows.reduce((total, entry) => total + entry.quantumVulnerable, 0);

  /* Every finding lands on exactly one row. When rows were keyed on
     `layer|name`, one file became three assets and each held a fraction of its
     findings — the sums still reconciled, which is why the defect survived. The
     identity assertion below is the one that actually catches it. */
  assert(rowFindings === assessment.findings.length, 'asset rows account for every finding',
    `${rowFindings} over rows vs ${assessment.findings.length} in the assessment`);
  assert(rowComponents === assessment.cbom.length, 'asset rows account for every CBOM component',
    `${rowComponents} over rows vs ${assessment.cbom.length} in the CBOM`);
  assert(rowCritical === truth.severity.critical, 'asset critical column sums to the severity tally',
    `${rowCritical} vs ${truth.severity.critical}`);
  assert(rowVulnerable === truth.findings.vulnerable, 'asset quantum column counts FINDINGS, as its header says',
    `${rowVulnerable} vs ${truth.findings.vulnerable} vulnerable findings`);

  /* An asset is identified by WHAT IT IS, never by the layer that observed it.
     Two rows with the same name mean the derivation has started splitting one
     file across its detection layers again. */
  const names = assets.rows.map((entry) => entry.name);
  assert(new Set(names).size === names.length, 'no asset appears twice under different layers',
    `${names.length - new Set(names).size} duplicate name(s)`);

  /* The row count is not the size of the estate, and must never be published as
     if it were: rows exist only where something was observed. */
  assert(assets.scanned <= assets.filesAnalyzed || assets.filesAnalyzed === 0,
    'evidence-carrying rows never exceed the files analysed',
    `${assets.scanned} rows vs ${assets.filesAnalyzed} files`);

  /* Dimensions nothing reached, and engines that fell over, are rows in their
     own right (§64). An absent row reads as nothing to worry about. */
  const gapRows = assets.rows.filter((entry) => entry.state !== 'scanned').length;
  const expectedGaps = truth.notAssessed.length + truth.incompleteEngines.length;
  assert(gapRows === expectedGaps, 'every unread dimension and failed engine has a row',
    `${gapRows} gap rows vs ${expectedGaps} recorded gaps`);

  /* ═══════════════════════════════════════════ 2. Correlated Exposures ══ */
  panel('2. CORRELATED EXPOSURES');
  const correlation = summariseCorrelation(assessment.exposures);
  row('total exposures', correlation.total);
  row('merged (rendered)', correlation.merged.length);
  row('of those, across layers', correlation.crossLayer);
  row('singletons (not rendered)', correlation.singletons);

  assert(correlation.merged.length + correlation.singletons === correlation.total,
    'the rendered and hidden populations sum to every exposure',
    `${correlation.merged.length} + ${correlation.singletons} vs ${correlation.total}`);
  assert(correlation.total === assessment.exposures.length,
    'the panel total is the population every other panel counts',
    `${correlation.total} vs ${assessment.exposures.length}`);

  /* "merged several findings" is not "reached across layers". The header used
     to make the stronger claim for both, reporting 30 cross-layer exposures on
     a scan whose true number was zero. */
  const trueCrossLayer = assessment.exposures.filter((exposure) => exposure.layers.length > 1).length;
  assert(correlation.crossLayer === trueCrossLayer,
    'cross-layer count is exactly the exposures spanning more than one layer',
    `${correlation.crossLayer} vs ${trueCrossLayer}`);
  assert(correlation.crossLayer <= correlation.merged.length,
    'cross-layer exposures are a subset of the merged ones',
    `${correlation.crossLayer} > ${correlation.merged.length}`);
  assert(correlation.merged.every((exposure) => exposure.findingIds.length > 1 || exposure.layers.length > 1),
    'every rendered row is one correlation actually merged',
    'a single-finding single-layer exposure reached the merged set');

  /* ══════════════════════════════════════════════ 3. Evidence Matrix ════ */
  panel('3. EVIDENCE MATRIX');
  const evidence = evidencePopulation(assessment);
  row('corroborated (plottable)', evidence.corroborated);
  row('no detection layer at all', evidence.unbacked);
  row('total findings', evidence.total);

  assert(evidence.corroborated + evidence.unbacked === evidence.total,
    'corroborated and unbacked partition the whole finding set',
    `${evidence.corroborated} + ${evidence.unbacked} vs ${evidence.total}`);
  assert(evidence.total === assessment.findings.length,
    'the matrix speaks about this scan\'s findings, not a subset',
    `${evidence.total} vs ${assessment.findings.length}`);
  /* A finding with no detection layer CANNOT be corroborated. Describing its
     absence as a ranking decision tells the reader it merely scored lower. */
  const plottable = assessment.findings.filter((finding) =>
    finding.evidence.some((entry) => typeof entry.attributes?.detectionLayer === 'string'),
  ).length;
  assert(evidence.corroborated === plottable,
    'the corroborated population is exactly the findings carrying a detection layer',
    `${evidence.corroborated} vs ${plottable}`);

  /* ═══════════════════════════════════════════════ 4. Standards Cited ═══ */
  panel('4. STANDARDS CITED');
  const standards = summariseStandards(assessment);
  row('publications', standards.rows.length);
  row('findings citing at least one', standards.cited);
  row('findings citing none', standards.uncited);

  assert(standards.cited + standards.uncited === standards.total,
    'cited and uncited partition the whole finding set',
    `${standards.cited} + ${standards.uncited} vs ${standards.total}`);
  assert(standards.rows === deriveStandards(assessment) || standards.rows.length === deriveStandards(assessment).length,
    'the summary and the row derivation agree',
    'summariseStandards and deriveStandards disagree on the row count');

  /* The column is labelled "N findings". Counting REFERENCES instead makes it a
     citation tally the moment one finding cites two clauses of one publication,
     so no row may exceed the number of findings in the scan. */
  const overCounted = standards.rows.filter((entry) => entry.findings > standards.total);
  assert(overCounted.length === 0, 'no publication claims more findings than the scan produced',
    overCounted.map((entry) => `${entry.publication}: ${entry.findings}`).join('; '));
  assert(standards.rows.every((entry) => entry.findings <= standards.cited),
    'no publication claims more findings than cite any publication at all',
    `cited=${standards.cited}`);
  /* §76: a citation that does not say who it binds converts guidance into an
     obligation the reader may not have. */
  assert(standards.rows.every((entry) => entry.applicability.trim().length > 0),
    'every publication states who it binds',
    'a row carries no applicability');

  /* ══════════════════════════════════════════ 5. Algorithms observed ════ */
  panel('5. ALGORITHMS OBSERVED');
  const chips = algorithmChipCoverage(assessment);
  row('groups rendered', chips.shown);
  row('groups in the CBOM', chips.groups);
  row('components the chips account for', chips.components);
  row('components in the CBOM', chips.total);
  row('truncation note renders', chips.truncated);

  assert(chips.shown <= chips.groups, 'the chip row never renders more groups than exist',
    `${chips.shown} > ${chips.groups}`);
  assert(chips.components <= chips.total, 'the chips never account for more components than the CBOM holds',
    `${chips.components} > ${chips.total}`);
  assert(chips.total === assessment.cbom.length, 'the chip denominator is the CBOM the panel renders above it',
    `${chips.total} vs ${assessment.cbom.length}`);
  /* The note must appear exactly when the chips do not add up to the cells
     above them — that is the whole reason it exists. */
  assert(chips.truncated === (chips.groups > chips.shown),
    'the truncation note renders exactly when groups were dropped',
    `truncated=${chips.truncated}, groups=${chips.groups}, shown=${chips.shown}`);

  /* ═════════════════════════════════════════════ 6. Findings filters ════ */
  panel('6. FINDINGS FILTERS');

  /* §51's rule, and the one the Migration Intelligence audit named: a facet's
     count is exactly what selecting it returns, and every value present in the
     data has a facet. A status with no chip is a population no filter can
     reach and the reader has no way to know exists — 15 findings carried
     `not-applicable` while the row offered five chips, so selecting all of them
     returned 1101 of 1116 with nothing on the page explaining the remainder. */
  const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
  for (const severity of severities) {
    const actual = assessment.findings.filter((finding) => finding.severity === severity).length;
    assert(assessment.intelligence.severity[severity] === actual,
      `severity facet "${severity}" counts what selecting it returns`,
      `chip=${assessment.intelligence.severity[severity]} vs ${actual} rows`);
  }

  const quantumStatuses = ['vulnerable', 'hybrid', 'pqc', 'resistant', 'unknown', 'not-applicable'] as const;
  const facetTally: Record<string, number> = {
    vulnerable: truth.findings.vulnerable,
    hybrid: truth.findings.hybrid,
    pqc: truth.findings.pqc,
    resistant: truth.findings.resistant,
    unknown: truth.findings.unknown,
    'not-applicable': truth.findings.notApplicable,
  };
  for (const status of quantumStatuses) {
    const actual = assessment.findings.filter((finding) => finding.quantumStatus === status).length;
    assert(facetTally[status] === actual, `quantum facet "${status}" counts what selecting it returns`,
      `chip=${facetTally[status]} vs ${actual} rows`);
  }
  const facetTotal = quantumStatuses.reduce((total, status) => total + facetTally[status], 0);
  assert(facetTotal === assessment.findings.length,
    'the quantum facets between them reach every finding',
    `${facetTotal} reachable of ${assessment.findings.length}`);

  for (const entry of assessment.intelligence.byEngine) {
    const actual = assessment.findings.filter((finding) => finding.engineId === entry.engineId).length;
    assert(entry.findings === actual, `engine facet "${entry.engineId}" counts what selecting it returns`,
      `option=${entry.findings} vs ${actual} rows`);
  }

  /* ══════════════════════════════════ 7. Coverage and terminal status ══ */
  panel('7. COVERAGE AND TERMINAL STATUS');
  row('task.status', assessment.task.status);
  row('coverage score', assessment.task.scores.coverage);
  row('dimensions not assessed', truth.notAssessed.length);
  row('engines that did not complete', truth.incompleteEngines.length);
  row('reconciler says partial', truth.partial);
  console.log(`  ${DIM(assessment.task.scores.basis[3] ?? '')}`);

  /* §64, on the surface that states it most loudly. A scan with a hole in it is
     partial however cleanly its engines exited — the status bar used to render
     a green "Assessment complete" directly above an Assessment Coverage panel
     listing the dimensions nothing reached. */
  assert(!(truth.partial && assessment.task.status === 'completed'),
    'a scan with unread dimensions is never published as complete',
    `status=${assessment.task.status} with ${truth.notAssessed.length} unread dimension(s)`);
  assert(!truth.partial || Boolean(assessment.task.failureReason),
    'a partial scan always states what is missing',
    'task.failureReason is empty on a partial scan');

  /* Coverage is the headline number a reader trusts to mean "nothing is
     missing". It may not read 100% while the same assessment lists a dimension
     it never read. */
  assert(!(truth.notAssessed.length > 0 && assessment.task.scores.coverage === 100),
    'coverage never reads 100% while a dimension went unread',
    `coverage=${assessment.task.scores.coverage} with ${truth.notAssessed.length} unread dimension(s)`);
  assert(
    assessment.task.scores.coverage === null ||
      (assessment.task.scores.coverage >= 0 && assessment.task.scores.coverage <= 100),
    'coverage is a percentage or explicitly not published',
    String(assessment.task.scores.coverage),
  );

  /* ─────────────────────────────────────────────────────────── verdict ─── */
  console.log('');
  console.log(BOLD('═'.repeat(66)));
  if (problems.length === 0) {
    console.log(GREEN(`✓ every panel derivation is accurate (${mode} mode)`));
  } else {
    console.log(RED(`✗ ${problems.length} panel accuracy problem(s) (${mode} mode)`));
    for (const problem of problems) console.log(`   • ${problem}`);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
