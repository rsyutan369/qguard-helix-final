/**
 * LIVE panel audit for the Dev and Local exposure surfaces.
 *
 * `/dashboard/scanner?mode=dev` and `?mode=local` render ten panels off ONE
 * assessment. The offline check tools assert individual rules; this runs the
 * REAL pipeline over a REAL corpus and prints what every panel would render,
 * side by side, so cross-panel contradictions are visible without a browser.
 *
 * It is the Dev/Local counterpart of `tools/scanner-panel-audit.ts` (web mode),
 * and exists for the same reason: a contradiction between two panels is invisible
 * to any single unit test, because each panel is individually correct.
 *
 * The corpus is a real directory on disk, walked the way the Local FS collector
 * and the Dev repo collector both deliver it — so the engines, the correlator,
 * the CBOM builder, the risk model and the reconciler all see production input.
 *
 *   npx tsx tools/exposure-panel-audit.ts [directory] [mode] [profile]
 *
 * Defaults: the repo's own src/lib, mode=dev, profile=deep (every engine).
 */

import fs from 'node:fs';
import path from 'node:path';
import { runExposureScan } from '@/lib/scanner/exposure/orchestrator';
import { resolveProfile } from '@/lib/scanner/exposure/profiles';
import { descriptorsForMode } from '@/lib/scanner/exposure/registry';
import { reconcileExposure, withUnit, completenessNote } from '@/lib/scanner/exposure/exposure-truth';
import { summariseCbom } from '@/lib/scanner/exposure/cbom';
import { layerLabel } from '@/lib/scanner/exposure/correlate';
import { buildWorkflowGraph } from '@/lib/scanner/exposure/workflow-graph';
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
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;

      let stat: fs.Stats;
      try {
        stat = fs.statSync(full);
      } catch {
        continue;
      }

      const rel = path.relative(root, full).split(path.sep).join('/');

      let content: string | null = null;
      if (stat.size <= MAX_BYTES) {
        try {
          content = fs.readFileSync(full, 'utf8');
        } catch {
          content = null;
        }
      }

      /* `toWorkspaceFile` is the SAME constructor both production collectors
         use (fs-collector via readFileEntry, repo-collector directly). Building
         the corpus any other way would leave `classification` unset, and every
         content engine keys its applicability off classification — an audit
         corpus built by hand would report the whole engine fleet as
         "not applicable" and the defect would be the harness's, not the
         product's. */
      files.push(toWorkspaceFile(rel, content, stat.size));
    }
  }
  return files;
}

/* ──────────────────────────────────────────────────────────── formatting ── */

const BOLD = (s: string) => `\x1b[1m${s}\x1b[0m`;
const DIM = (s: string) => `\x1b[2m${s}\x1b[0m`;
const CYAN = (s: string) => `\x1b[36m${s}\x1b[0m`;
const RED = (s: string) => `\x1b[31m${s}\x1b[0m`;
const GREEN = (s: string) => `\x1b[32m${s}\x1b[0m`;
const YELLOW = (s: string) => `\x1b[33m${s}\x1b[0m`;

function panel(title: string) {
  console.log('');
  console.log(CYAN(`── ${title} ${'─'.repeat(Math.max(0, 66 - title.length))}`));
}

function row(label: string, value: unknown) {
  console.log(`  ${label.padEnd(42)} ${String(value)}`);
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

/* ────────────────────────────────────────────────────────────────── main ── */

async function main() {
  const dir = path.resolve(process.argv[2] || path.join(import.meta.dirname, '..', 'src', 'lib'));
  const mode = (process.argv[3] as ScanMode) || 'dev';
  const profileId = process.argv[4] || 'deep';

  console.log(BOLD('\nExposure panel audit — LIVE pipeline'));
  console.log(`  corpus  : ${dir}`);
  console.log(`  mode    : ${mode}`);
  console.log(`  profile : ${profileId}`);

  const files = walk(dir);
  console.log(`  files   : ${files.length}${files.length >= MAX_FILES ? ` (capped at ${MAX_FILES})` : ''}`);

  const { engines, dropped } = resolveProfile(mode, profileId);
  console.log(`  engines : ${engines.length} selected${dropped.length ? `, ${dropped.length} unavailable in this mode` : ''}`);

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

  const started = Date.now();
  const assessment: ExposureAssessment = await runExposureScan({
    scanId: 'audit-' + Date.now().toString(36),
    mode,
    target,
    profileId,
    engineIds: engines,
    workspace,
    localOnly: mode === 'local',
    budgetMs: 600_000,
    engineBudgetMs: 180_000,
  });
  console.log(`  elapsed : ${((Date.now() - started) / 1000).toFixed(1)}s`);

  const truth = reconcileExposure(assessment);
  const { task, findings, exposures, cbom, intelligence } = assessment;
  const cbomSummary = summariseCbom(cbom);

  /* ─────────────────────────────────────────── 1. Risk Decomposition ──── */
  panel('1. RISK DECOMPOSITION');
  for (const [key, value] of Object.entries(task.scores)) {
    row(key, typeof value === 'number' ? value : JSON.stringify(value));
  }
  row('scoreUnitNote', truth.scoreUnitNote ?? DIM('(none)'));

  /* ─────────────────────────────────────────── 2. Quantum Exposure ────── */
  panel('2. QUANTUM EXPOSURE');
  row('components  vulnerable', truth.components.vulnerable);
  row('components  hybrid', truth.components.hybrid);
  row('components  pqc', truth.components.pqc);
  row('components  resistant', truth.components.resistant);
  row('components  unknown', truth.components.unknown);
  row('components  not-applicable', truth.components.notApplicable);
  row('components  quantum-relevant', truth.components.quantumRelevant);
  row('components  total', truth.components.total);
  row('findings    vulnerable', truth.findings.vulnerable);
  row('exposures   vulnerable', truth.exposures.vulnerable);
  row('readiness', truth.readiness === null ? `null (${truth.readinessReason})` : `${truth.readiness}% of ${truth.readinessUnit}s`);
  row('intelligence.quantum.readiness', intelligence.quantum.readiness);
  row('unitNote', truth.unitNote ?? DIM('(none)'));

  /* ─────────────────────────────────────────── 3. Scanned Assets ──────── */
  panel('3. SCANNED ASSETS / COVERAGE INPUTS');
  const cov = task.coverage;
  for (const key of [
    'filesDiscovered', 'filesAnalyzed', 'filesSkipped', 'filesUnsupported',
    'dependencies', 'cryptoComponents', 'certificates', 'secrets', 'configFiles',
    'containers', 'iacFiles', 'cicdWorkflows', 'commitsAnalyzed',
  ] as const) {
    row(key, cov[key]);
  }
  row('truncated', cov.truncated + (cov.truncationNote ? ` — ${cov.truncationNote}` : ''));

  /* ─────────────────────────────────────────── 4. Platform Reconciliation */
  panel('4. PLATFORM RECONCILIATION');
  row('findings total', findings.length);
  row('task.findingCount', task.findingCount);
  row('exposures (correlated)', exposures.length);
  row('cbom components', cbom.length);
  row('cbom summary total', cbomSummary.total);
  row('cbom vulnerable', cbomSummary.vulnerable);
  row('cbom readiness', cbomSummary.readiness === null ? 'null (not measurable)' : `${cbomSummary.readiness}%`);

  /* ─────────────────────────────────────────── 5. Correlated Exposures ── */
  panel('5. CORRELATED EXPOSURES');
  /* `CorrelatedExposure.layers` is PLURAL — one exposure can span several
     layers, which is the whole point of correlation. Reading a singular
     `.layer` yields undefined for every row. */
  const byLayer = new Map<string, { findings: number; exposures: number }>();
  const unlabelledLayers = new Set<string>();
  for (const exposure of exposures) {
    for (const layer of exposure.layers) {
      const label = layerLabel(layer);
      if (typeof label !== 'string') unlabelledLayers.add(String(layer));
      const key = typeof label === 'string' ? label : `(unlabelled: ${String(layer)})`;
      const bucket = byLayer.get(key) ?? { findings: 0, exposures: 0 };
      bucket.exposures += 1;
      bucket.findings += exposure.findingIds?.length ?? 0;
      byLayer.set(key, bucket);
    }
    if (exposure.layers.length === 0) unlabelledLayers.add('(no layer)');
  }
  for (const [layer, bucket] of byLayer) row(layer, `${bucket.exposures} exposure(s) · ${bucket.findings} finding(s)`);
  row('exposure severity', JSON.stringify(truth.exposureSeverity));

  /* ─────────────────────────────────────────── 6. Findings ────────────── */
  panel('6. FINDINGS');
  row('severity tally', JSON.stringify(truth.severity));
  row('actionable (above info)', truth.actionable);
  const byEngine = new Map<string, number>();
  for (const finding of findings) byEngine.set(finding.engineId, (byEngine.get(finding.engineId) ?? 0) + 1);
  for (const [engineId, count] of [...byEngine].sort((a, b) => b[1] - a[1])) row(`  ${engineId}`, count);

  /* ─────────────────────────────────────────── 7. Exposure Workflow ───── */
  panel('7. EXPOSURE WORKFLOW');
  let graph: ReturnType<typeof buildWorkflowGraph> | null = null;
  try {
    graph = buildWorkflowGraph(assessment, { descriptors: descriptorsForMode(mode) });
    row('nodes', graph.nodes.length);
    row('edges', graph.edges.length);
    row('clusters', graph.clusters.length);
    row('counts by kind', JSON.stringify(graph.counts));
    row('truncated', graph.truncation.truncated);
    for (const entry of graph.truncation.dropped) row(`  dropped ${entry.kind}`, `${entry.dropped} of ${entry.total}`);
    const rec = graph.reconciliation;
    row('reconciliation findings', `${rec.findingsProjected} projected / ${rec.findingsInAssessment} in assessment`);
    row('reconciliation components', `${rec.componentsProjected} projected / ${rec.componentsInAssessment} in assessment`);
    row('reconciliation exposures', `${rec.exposuresProjected} projected / ${rec.exposuresInAssessment} in assessment`);
  } catch (error) {
    row('buildWorkflowGraph', RED(`threw: ${(error as Error).message}`));
    problems.push(`buildWorkflowGraph threw: ${(error as Error).message}`);
  }

  /* ─────────────────────────────────────────── 8. Recommended Actions ─── */
  panel('8. RECOMMENDED ACTIONS');
  if (intelligence.recommendations.length === 0) row('(none)', DIM('no recommendations produced'));
  for (const rec of intelligence.recommendations) {
    console.log(`  [${rec.severity}] ${rec.findingIds.length} finding(s) · effort ${rec.effort}`);
    console.log(`      ${DIM(rec.title.slice(0, 150))}`);
  }

  /* ─────────────────────────────────────────── 9. CBOM ────────────────── */
  panel('9. CRYPTOGRAPHIC BILL OF MATERIALS');
  for (const [key, value] of Object.entries(cbomSummary)) {
    row(key, typeof value === 'object' ? JSON.stringify(value) : String(value));
  }
  panel('9b. TOP ALGORITHMS (intelligence)');
  for (const algorithm of intelligence.topAlgorithms.slice(0, 15)) {
    const mix = algorithm.mix.map((slice) => `${slice.count} ${slice.status}`).join(' · ');
    const weak = algorithm.classicallyWeak > 0 ? RED(`  ⚠ ${algorithm.classicallyWeak} classically broken`) : '';
    row(algorithm.algorithm, `${algorithm.count} · ${algorithm.quantumStatus}  ${DIM(`[${mix}]`)}${weak}`);
  }

  /* ─────────────────────────────────────────── 10. Assessment Coverage ── */
  panel('10. ASSESSMENT COVERAGE');
  const runs = task.runs;
  const stateCounts = new Map<string, number>();
  for (const run of runs) stateCounts.set(run.state, (stateCounts.get(run.state) ?? 0) + 1);
  row('engine runs', runs.length);
  for (const [state, count] of stateCounts) row(`  ${state}`, count);
  for (const run of runs) {
    const detail = run.detail ? ` — ${run.detail}` : '';
    const marker = run.state === 'failed' ? RED('✗') : run.state === 'completed' ? GREEN('✓') : YELLOW('•');
    console.log(`    ${marker} ${run.engineId.padEnd(26)} ${run.state.padEnd(16)} ${run.findingCount} finding(s)${DIM(detail)}`);
  }
  row('notAssessed dimensions', cov.notAssessed.length);
  for (const entry of cov.notAssessed) console.log(`      ${DIM(`${entry.dimension}: ${entry.reason}`)}`);
  row('completenessNote', completenessNote(truth) ?? DIM('(none)'));
  row('partial', truth.partial);

  /* ───────────────────────────────────── CROSS-PANEL RECONCILIATION ───── */
  panel('CROSS-PANEL RECONCILIATION');

  assert(
    task.findingCount === findings.length,
    'task.findingCount equals the findings array',
    `${task.findingCount} vs ${findings.length}`,
  );

  const correlatedFindingIds = new Set<string>();
  for (const exposure of exposures) for (const id of exposure.findingIds ?? []) correlatedFindingIds.add(id);
  assert(
    correlatedFindingIds.size === findings.length,
    'every finding belongs to exactly one correlated exposure',
    `${correlatedFindingIds.size} correlated vs ${findings.length} findings`,
  );

  const severitySum = Object.values(truth.severity).reduce((sum, n) => sum + n, 0);
  assert(
    severitySum === findings.length,
    'severity tally sums to the finding total',
    `${severitySum} vs ${findings.length}`,
  );

  const engineSum = [...byEngine.values()].reduce((sum, n) => sum + n, 0);
  assert(
    engineSum === findings.length,
    'per-engine finding counts sum to the total',
    `${engineSum} vs ${findings.length}`,
  );

  const ledgerSum = runs.reduce((sum, run) => sum + run.findingCount, 0);
  assert(
    ledgerSum === findings.length,
    'engine ledger counts sum to the finding total',
    `${ledgerSum} vs ${findings.length}`,
  );

  assert(
    cbomSummary.total === cbom.length,
    'CBOM summary total equals the component array',
    `${cbomSummary.total} vs ${cbom.length}`,
  );

  assert(
    truth.components.total === cbom.length,
    'reconciler component tally equals the CBOM',
    `${truth.components.total} vs ${cbom.length}`,
  );

  /* The defect this catches: `byAlgorithm` published the status of whichever
     component was enumerated first, so "ML-KEM x90 hybrid" and "ML-DSA x112
     hybrid" rendered as chips directly beneath a cell reporting 23 hybrid
     components. Each panel was internally consistent; together they were a
     202-vs-23 contradiction. Reconciling the per-algorithm mix against the
     bucket totals is the only assertion that sees it. */
  const mixTotals = new Map<string, number>();
  for (const entry of cbomSummary.byAlgorithm) {
    for (const slice of entry.mix) mixTotals.set(slice.status, (mixTotals.get(slice.status) ?? 0) + slice.count);
  }
  for (const [status, bucket] of [
    ['vulnerable', cbomSummary.vulnerable],
    ['hybrid', cbomSummary.hybrid],
    ['pqc', cbomSummary.pqc],
    ['resistant', cbomSummary.resistant],
  ] as const) {
    assert(
      (mixTotals.get(status) ?? 0) === bucket,
      `per-algorithm mix reconciles to the ${status} bucket`,
      `mix=${mixTotals.get(status) ?? 0} bucket=${bucket}`,
    );
  }

  const mixGroupsSound = cbomSummary.byAlgorithm.every(
    (entry) =>
      entry.mix.reduce((sum, slice) => sum + slice.count, 0) === entry.count &&
      entry.mix.some((slice) => slice.status === entry.quantumStatus),
  );
  assert(
    mixGroupsSound,
    'every algorithm mix sums to its group and contains its published status',
    cbomSummary.byAlgorithm
      .filter((entry) => entry.mix.reduce((sum, slice) => sum + slice.count, 0) !== entry.count)
      .map((entry) => entry.algorithm)
      .join(', ') || 'published status absent from mix',
  );

  const algorithmSum = cbomSummary.byAlgorithm.reduce((sum, entry) => sum + entry.count, 0);
  assert(
    algorithmSum === cbom.length,
    'per-algorithm counts sum to the component total',
    `${algorithmSum} vs ${cbom.length}`,
  );

  /* "Resistant" is a verdict about Shor's algorithm alone. An estate whose
     resistant bucket is entirely MD5/SHA-1/RC4/DES must not be able to render
     that cell without the qualifier — so the count has to reach the panel. */
  const weakSum = cbomSummary.byAlgorithm.reduce((sum, entry) => sum + entry.classicallyWeak, 0);
  assert(
    weakSum === cbomSummary.classicallyWeak && cbomSummary.classicallyWeak === truth.components.classicallyWeak,
    'classically-weak count agrees across summary, algorithms and reconciler',
    `algorithms=${weakSum} summary=${cbomSummary.classicallyWeak} reconciler=${truth.components.classicallyWeak}`,
  );

  const quantumIntel = intelligence.quantum;
  assert(
    quantumIntel.vulnerable === truth.components.vulnerable,
    'intelligence.quantum.vulnerable is the COMPONENT count (one model)',
    `intelligence=${quantumIntel.vulnerable} truth.components=${truth.components.vulnerable} truth.findings=${truth.findings.vulnerable}`,
  );

  assert(
    quantumIntel.readiness === truth.readiness,
    'intelligence readiness equals the reconciler readiness',
    `${quantumIntel.readiness} vs ${truth.readiness}`,
  );

  const layerFindingSum = intelligence.byLayer.reduce((sum, entry) => sum + entry.findings, 0);
  assert(
    layerFindingSum === findings.length,
    'byLayer finding counts sum to the total',
    `${layerFindingSum} vs ${findings.length}`,
  );

  const intelEngineSum = intelligence.byEngine.reduce((sum, entry) => sum + entry.findings, 0);
  assert(
    intelEngineSum === findings.length,
    'byEngine finding counts sum to the total',
    `${intelEngineSum} vs ${findings.length}`,
  );

  const recIds = new Set(intelligence.recommendations.flatMap((rec) => rec.findingIds));
  const knownIds = new Set(findings.map((finding) => finding.id));
  const orphanRecs = [...recIds].filter((id) => !knownIds.has(id));
  assert(
    orphanRecs.length === 0,
    'every recommendation cites a finding that exists',
    `${orphanRecs.length} orphan id(s)`,
  );

  assert(
    runs.length === engines.length,
    'the ledger carries a run for every selected engine',
    `${runs.length} runs vs ${engines.length} engines`,
  );

  const unresolved = runs.filter((run) => run.state === 'running' || run.state === 'pending');
  assert(
    unresolved.length === 0,
    'no engine is left unresolved when the scan ends',
    unresolved.map((run) => `${run.engineId}=${run.state}`).join(', '),
  );

  const noDetail = runs.filter(
    (run) => (run.state === 'skipped' || run.state === 'not-applicable' || run.state === 'failed' || run.state === 'not-assessed') && !run.detail,
  );
  assert(
    noDetail.length === 0,
    'every non-measuring engine states a reason',
    noDetail.map((run) => run.engineId).join(', '),
  );

  assert(
    truth.readiness === null || (truth.readiness >= 0 && truth.readiness <= 100),
    'readiness is a percentage or explicitly not measurable',
    String(truth.readiness),
  );

  /* One gap, one row. The Assessment Coverage panel counts this list directly
     while the completeness note describes the same list, so a dimension
     appearing twice makes the two disagree in the same viewport — which is how
     "Not assessed (3)" came to sit beside "2 dimensions could not be read". */
  const dimensions = cov.notAssessed.map((entry) => entry.dimension);
  const duplicateDimensions = dimensions.filter((name, index) => dimensions.indexOf(name) !== index);
  assert(
    duplicateDimensions.length === 0,
    'each not-assessed dimension is listed exactly once',
    `duplicated: ${[...new Set(duplicateDimensions)].join(', ')}`,
  );

  assert(
    cov.notAssessed.length === truth.notAssessed.length,
    'the coverage panel and the completeness note count the same gaps',
    `panel=${cov.notAssessed.length} note=${truth.notAssessed.length}`,
  );

  assert(
    cov.notAssessed.every((entry) => entry.reason.trim().length > 0),
    'every not-assessed dimension states why it could not be read',
    cov.notAssessed.filter((entry) => !entry.reason.trim()).map((entry) => entry.dimension).join(', '),
  );

  if (truth.components.quantumRelevant === 0) {
    assert(
      truth.readiness === null,
      'no quantum-relevant component ⇒ readiness withheld, never 0 or 100',
      String(truth.readiness),
    );
  }

  if (graph) {
    const rec = graph.reconciliation;
    assert(
      rec.findingsInAssessment === findings.length,
      'workflow graph reads the same finding population',
      `${rec.findingsInAssessment} vs ${findings.length}`,
    );
    assert(
      graph.truncation.truncated || rec.findingsProjected === rec.findingsInAssessment,
      'workflow graph projects every finding, or declares truncation',
      `${rec.findingsProjected} of ${rec.findingsInAssessment}, truncated=${graph.truncation.truncated}`,
    );
    assert(
      graph.truncation.truncated || rec.componentsProjected === rec.componentsInAssessment,
      'workflow graph projects every component, or declares truncation',
      `${rec.componentsProjected} of ${rec.componentsInAssessment}, truncated=${graph.truncation.truncated}`,
    );
    assert(
      graph.truncation.truncated || rec.exposuresProjected === rec.exposuresInAssessment,
      'workflow graph projects every exposure, or declares truncation',
      `${rec.exposuresProjected} of ${rec.exposuresInAssessment}, truncated=${graph.truncation.truncated}`,
    );
    const nodeIds = new Set(graph.nodes.map((node) => node.id));
    const danglingEdges = graph.edges.filter((edge) => !nodeIds.has(edge.source) || !nodeIds.has(edge.target));
    assert(
      danglingEdges.length === 0,
      'no workflow edge points at a node the graph does not hold',
      `${danglingEdges.length} dangling edge(s)`,
    );
  }

  assert(
    unlabelledLayers.size === 0,
    'every correlated exposure carries a layer the UI can label',
    `unlabelled layer(s): ${[...unlabelledLayers].join(', ')}`,
  );

  const analyzed = cov.filesAnalyzed;
  assert(
    analyzed <= cov.filesDiscovered,
    'files analyzed never exceeds files discovered',
    `${analyzed} > ${cov.filesDiscovered}`,
  );

  /* ───────────────────────────────────────────────────────────── verdict ── */
  console.log('');
  console.log(BOLD('═'.repeat(70)));
  if (problems.length === 0) {
    console.log(GREEN(`✓ every cross-panel reconciliation holds (${mode} mode)`));
    process.exit(0);
  }
  console.log(RED(`✗ ${problems.length} cross-panel contradiction(s) in ${mode} mode:`));
  for (const problem of problems) console.log(`  · ${problem}`);
  process.exit(1);
}

main().catch((error) => {
  console.error('\naudit crashed:', error);
  process.exit(2);
});
