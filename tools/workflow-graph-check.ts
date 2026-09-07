/**
 * Exposure Workflow Graph — integrity check.
 *
 * WHY THIS EXISTS
 * ---------------
 * A relationship map is the easiest surface on the platform to fabricate on.
 * It renders shapes rather than numbers, so a node that exists for no reason,
 * an edge to something that was never observed, or a "clean green" body that
 * simply had nothing attached to it all read as insight instead of as the
 * defects they are. This module has no user-visible counter to disagree with,
 * which is exactly why it needs assertions of its own.
 *
 * The contract under test:
 *
 *   1. DERIVED ROWS ENRICH, THEY NEVER ADD — every finding, component and
 *      exposure node traces back to a row the assessment already holds, and
 *      the projected/total reconciliation the UI prints is true.
 *   2. NO ORPHAN EDGES — the canvas can never draw a line to a node that was
 *      capped away or filtered out.
 *   3. ABSENCE IS NOT SAFETY — a node with no finding behind it carries
 *      severity `null` ("None"), never `info` and never a passing band.
 *   4. DETECTION SURVIVES THE PROJECTION — conclusions are `inferred`,
 *      artefacts are `observed`, and switching inferred off leaves only what
 *      was literally read.
 *   5. THE PROCESS TREE IS REAL — engine→engine edges come from the registry's
 *      declared `dependsOn`, not from run order.
 *   6. DETERMINISM — the same assessment yields the same graph, so a selection
 *      survives a re-render and two runs can be compared.
 *
 * Runs the REAL orchestrator over a fixture corpus; no network required.
 *
 *   npx tsx tools/workflow-graph-check.ts
 */

import { runExposureScan } from '../src/lib/scanner/exposure/orchestrator';
import { emptyWorkspace, type WorkspaceFile } from '../src/lib/scanner/exposure/engine-contract';
import { classifyFile } from '../src/lib/scanner/exposure/content/file-discovery';
import { resolveProfile } from '../src/lib/scanner/exposure/profiles';
import { descriptorsForMode } from '../src/lib/scanner/exposure/registry';
import { defaultExclusions, type ExposureAssessment } from '../src/lib/scanner/exposure/types';
import {
  buildWorkflowGraph,
  projectLens,
  WORKFLOW_LENSES,
  type WorkflowGraph,
  type WorkflowNodeKind,
} from '../src/lib/scanner/exposure/workflow-graph';

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

/** A corpus wide enough to exercise several engines, layers and severities. */
const FIXTURE: WorkspaceFile[] = [
  ...Array.from({ length: 24 }, (_, index) =>
    file(`src/module-${index}/crypto.ts`, [
      'import crypto from "crypto";',
      `const pair${index} = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });`,
      'const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);',
      'const legacy = crypto.createHash("md5").update(input).digest("hex");',
    ].join('\n')),
  ),
  ...Array.from({ length: 6 }, (_, index) =>
    file(`src/auth/token-${index}.ts`, [
      'import jwt from "jsonwebtoken";',
      'export const sign = (p) => jwt.sign(p, secret, { algorithm: "HS256" });',
    ].join('\n')),
  ),
  file('package.json', '{"name":"fixture","dependencies":{"jsonwebtoken":"^9.0.0","node-forge":"^1.3.1","bcrypt":"^5.1.1"}}'),
  file('Dockerfile', 'FROM node:20-alpine\nUSER root\nRUN apk add openssl'),
  file('k8s/ingress.yaml', 'apiVersion: networking.k8s.io/v1\nkind: Ingress\nspec:\n  tls:\n    - hosts: ["app.example.com"]'),
  file('.github/workflows/ci.yml', 'name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest'),
  file('terraform/main.tf', 'resource "aws_s3_bucket" "assets" {\n  bucket = "assets"\n}'),
  file('config/app.yaml', 'tls:\n  minVersion: TLSv1.0\n  ciphers: "RC4-SHA:DES-CBC3-SHA"'),
];

/* ────────────────────────────────────────────────────────────── harness ───── */

const results: Array<{ name: string; pass: boolean; detail: string }> = [];
let currentMode: 'local' | 'dev' = 'local';
function check(name: string, pass: boolean, detail: string) {
  results.push({ name: `[${currentMode}] ${name}`, pass, detail });
}

/**
 * The same corpus, assessed in both modes that mount the graph.
 *
 * LOCAL and DEV run different engine sets — Dev adds supply-chain correlation
 * and the connector descriptors, and reaches container, Kubernetes, IaC and
 * CI/CD layers — so the contract is asserted against BOTH. A projection that
 * holds for one engine set is not evidence that it holds for the other.
 */
async function runScan(mode: 'local' | 'dev'): Promise<ExposureAssessment> {
  const workspace = emptyWorkspace();
  workspace.files = FIXTURE;
  /* `standard` resolves to the SAME eight engines in both modes, so running it
     twice would assert nothing about Dev. Dev is therefore exercised on `deep`,
     which is where the mode actually differs: container, Kubernetes, IaC, CI/CD
     and supply-chain correlation, across five more layers. */
  const profileId = mode === 'dev' ? 'deep' : 'standard';
  const { engines } = resolveProfile(mode, profileId, []);
  return runExposureScan({
    scanId: `workflow-graph-check-${mode}`,
    mode,
    target:
      mode === 'local'
        ? { kind: 'local', label: 'fixture', rootName: 'fixture', fileCount: FIXTURE.length, viaAgent: false }
        : {
            kind: 'repository',
            url: 'https://example.invalid/acme/payments',
            provider: 'github',
            owner: 'acme',
            repo: 'payments',
            visibility: 'public',
          },
    profileId,
    engineIds: engines,
    workspace,
    exclusions: defaultExclusions(),
    budgetMs: 120_000,
    concurrency: 2,
    onEvent: () => {},
  });
}

/** Stable fingerprint of a graph, for the determinism assertion. */
function fingerprint(graph: WorkflowGraph): string {
  const nodes = graph.nodes
    .map((node) => `${node.id}|${node.kind}|${node.severity ?? '-'}|${node.detection}|${node.weight}`)
    .sort()
    .join('\n');
  const edges = graph.edges.map((edge) => edge.id).sort().join('\n');
  return `${nodes}\n--\n${edges}`;
}

async function assertMode(mode: 'local' | 'dev') {
  currentMode = mode;
  const assessment = await runScan(mode);
  const descriptors = descriptorsForMode(mode);
  const graph = buildWorkflowGraph(assessment, { descriptors });

  console.log(
    `
=== ${mode.toUpperCase()} ===
` +
      `profile ${assessment.task.profileId}: ${assessment.findings.length} findings, ${assessment.cbom.length} CBOM components, ` +
      `${assessment.exposures.length} exposures, ${assessment.task.runs.length} engine runs`,
  );
  console.log(
    `graph: ${graph.nodes.length} nodes, ${graph.edges.length} edges, ${graph.clusters.length} clusters\n` +
      `counts: ${Object.entries(graph.counts).filter(([, value]) => value > 0).map(([kind, value]) => `${kind}=${value}`).join(' ')}\n`,
  );

  const byKind = new Map<string, number>();
  for (const edge of graph.edges) byKind.set(edge.kind, (byKind.get(edge.kind) ?? 0) + 1);
  console.log('edges by kind: ' + [...byKind.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}=${v}`).join(' '));
  const deg = new Map<string, number>();
  for (const edge of graph.edges) {
    deg.set(edge.source, (deg.get(edge.source) ?? 0) + 1);
    deg.set(edge.target, (deg.get(edge.target) ?? 0) + 1);
  }
  console.log('top degree: ' + [...deg.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `${k}=${v}`).join(' '));

  /* ── 0. the graph is not empty. A silent zero would pass every other test ── */
  check(
    'a real scan produces a plottable graph',
    graph.nodes.length > 10 && graph.edges.length > 10,
    `${graph.nodes.length} nodes / ${graph.edges.length} edges from ${assessment.findings.length} findings`,
  );

  /* ── 1. derived rows enrich, they never add ───────────────────────────── */
  const findingIds = new Set(assessment.findings.map((finding) => finding.id));
  const componentIds = new Set(assessment.cbom.map((component) => component.id));
  const inventedFindings = graph.nodes.filter(
    (node) => node.kind === 'finding' && !findingIds.has(node.findingRef ?? ''),
  );
  check(
    'every finding node traces to a finding in the assessment',
    inventedFindings.length === 0,
    inventedFindings.length === 0
      ? `${graph.counts.finding} finding nodes, all present in the assessment`
      : `${inventedFindings.length} fabricated: ${inventedFindings.slice(0, 3).map((node) => node.id).join(', ')}`,
  );

  const inventedComponents = graph.nodes.filter(
    (node) => node.kind === 'component' && !componentIds.has(node.id.replace(/^component:/, '')),
  );
  check(
    'every CBOM node traces to a component in the assessment',
    inventedComponents.length === 0,
    `${graph.counts.component} component nodes checked against ${assessment.cbom.length} CBOM rows`,
  );

  const badAttachment = graph.nodes.filter((node) =>
    node.findingIds.some((id) => !findingIds.has(id)),
  );
  check(
    'no node claims a finding the assessment does not hold',
    badAttachment.length === 0,
    badAttachment.length === 0
      ? 'every findingIds entry resolves'
      : `${badAttachment.length} nodes reference unknown findings`,
  );

  check(
    'the reconciliation footer states the truth',
    graph.reconciliation.findingsInAssessment === assessment.findings.length &&
      graph.reconciliation.findingsProjected === graph.counts.finding &&
      graph.reconciliation.componentsInAssessment === assessment.cbom.length &&
      graph.reconciliation.componentsProjected === graph.counts.component &&
      graph.reconciliation.exposuresInAssessment === assessment.exposures.length &&
      graph.reconciliation.exposuresProjected === graph.counts.exposure,
    `findings ${graph.reconciliation.findingsProjected}/${graph.reconciliation.findingsInAssessment}, ` +
      `components ${graph.reconciliation.componentsProjected}/${graph.reconciliation.componentsInAssessment}, ` +
      `exposures ${graph.reconciliation.exposuresProjected}/${graph.reconciliation.exposuresInAssessment}`,
  );

  /* Anything capped away must be DECLARED, never silently dropped. */
  const undeclared = (['finding', 'component', 'exposure'] as WorkflowNodeKind[]).filter((kind) => {
    const total =
      kind === 'finding'
        ? assessment.findings.length
        : kind === 'component'
          ? assessment.cbom.length
          : assessment.exposures.length;
    const missing = total - graph.counts[kind];
    if (missing <= 0) return false;
    return !graph.truncation.dropped.some((entry) => entry.kind === kind && entry.dropped === missing);
  });
  check(
    'every capped population is disclosed, not silently dropped',
    undeclared.length === 0,
    undeclared.length === 0
      ? graph.truncation.truncated
        ? `declared: ${graph.truncation.dropped.map((entry) => `${entry.kind} ${entry.dropped}/${entry.total}`).join(', ')}`
        : 'nothing was capped on this corpus'
      : `undeclared shortfall in ${undeclared.join(', ')}`,
  );

  /* ── 2. no orphan edges ───────────────────────────────────────────────── */
  const nodeIds = new Set(graph.nodes.map((node) => node.id));
  const orphans = graph.edges.filter((edge) => !nodeIds.has(edge.source) || !nodeIds.has(edge.target));
  check(
    'no edge points at a node that is not on the canvas',
    orphans.length === 0,
    orphans.length === 0
      ? `${graph.edges.length} edges, both endpoints present`
      : `${orphans.length} dangling: ${orphans.slice(0, 3).map((edge) => edge.id).join(', ')}`,
  );

  const selfLoops = graph.edges.filter((edge) => edge.source === edge.target);
  check('no self-loops', selfLoops.length === 0, `${selfLoops.length} found`);

  const duplicateEdges = graph.edges.length - new Set(graph.edges.map((edge) => edge.id)).size;
  const duplicateNodes = graph.nodes.length - nodeIds.size;
  check(
    'node and edge identity is unique',
    duplicateEdges === 0 && duplicateNodes === 0,
    `${duplicateNodes} duplicate nodes, ${duplicateEdges} duplicate edges`,
  );

  /* ── 3. absence is not safety ─────────────────────────────────────────── */
  const fabricatedSeverity = graph.nodes.filter(
    (node) => node.findingIds.length === 0 && node.severity !== null && node.kind !== 'secret',
  );
  check(
    'a node with no finding behind it is “None”, never a severity band',
    fabricatedSeverity.length === 0,
    fabricatedSeverity.length === 0
      ? `${graph.nodes.filter((node) => node.severity === null).length} nodes correctly carry no band`
      : `${fabricatedSeverity.length} nodes invent a band: ${fabricatedSeverity.slice(0, 3).map((node) => `${node.id}=${node.severity}`).join(', ')}`,
  );

  /* A node's severity may never be milder than the worst finding attached to
     it — that would under-report the risk the picture is meant to convey. */
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
  const byId = new Map(assessment.findings.map((finding) => [finding.id, finding]));
  const understated = graph.nodes.filter((node) => {
    if (node.findingIds.length === 0) return false;
    const worst = node.findingIds
      .map((id) => byId.get(id)?.severity)
      .filter((value): value is keyof typeof severityRank => Boolean(value))
      .sort((a, b) => severityRank[a] - severityRank[b])[0];
    if (!worst) return false;
    return node.severity === null || severityRank[node.severity] > severityRank[worst];
  });
  check(
    'a node never renders milder than its worst attached finding',
    understated.length === 0,
    understated.length === 0
      ? 'every rollup carries the worst severity it contains'
      : `${understated.length} understated: ${understated.slice(0, 3).map((node) => node.id).join(', ')}`,
  );

  /* ── 4. detection survives the projection ─────────────────────────────── */
  const conclusionKinds: WorkflowNodeKind[] = ['algorithm', 'exposure', 'remediation'];
  const misdeclared = graph.nodes.filter(
    (node) => conclusionKinds.includes(node.kind) && node.detection === 'observed',
  );
  check(
    'conclusions are published as inferred, not as observations',
    misdeclared.length === 0,
    misdeclared.length === 0
      ? `${conclusionKinds.join('/')} nodes all carry a non-observed detection method`
      : `${misdeclared.length} conclusions claim to be observed`,
  );

  const observedOnly = projectLens(graph, {
    lens: WORKFLOW_LENSES[0],
    hiddenKinds: new Set(),
    showInferred: false,
    grouping: 'phase',
    query: '',
    hiddenSeverities: new Set(),
  });
  check(
    'switching inferred off leaves only what was literally read',
    observedOnly.nodes.every((node) => node.detection === 'observed') &&
      observedOnly.edges.every((edge) => edge.detection === 'observed'),
    `${observedOnly.nodes.length} nodes / ${observedOnly.edges.length} edges survive, all observed`,
  );
  check(
    'the observed-only view is still a graph, not an empty canvas',
    observedOnly.nodes.length > 0 && observedOnly.edges.length > 0,
    `${observedOnly.nodes.length} observed nodes remain`,
  );

  /* ── 5. the process tree is real ──────────────────────────────────────── */
  const descriptorById = new Map(descriptors.map((entry) => [entry.id, entry]));
  const engineEdges = graph.edges.filter(
    (edge) => edge.kind === 'requires' && edge.source.startsWith('engine:') && edge.target.startsWith('engine:'),
  );
  const unbacked = engineEdges.filter((edge) => {
    const child = edge.source.replace(/^engine:/, '');
    const parent = edge.target.replace(/^engine:/, '');
    return !(descriptorById.get(child)?.dependsOn ?? []).includes(parent);
  });
  check(
    'engine→engine edges come from the registry’s declared dependsOn',
    engineEdges.length > 0 && unbacked.length === 0,
    unbacked.length === 0
      ? `${engineEdges.length} dependency edges, all declared in the registry`
      : `${unbacked.length} invented: ${unbacked.slice(0, 3).map((edge) => edge.id).join(', ')}`,
  );

  const everyEngineHasAParent = graph.nodes
    .filter((node) => node.kind === 'engine')
    .every((node) => graph.edges.some((edge) => edge.kind === 'spawns' && edge.target === node.id));
  check(
    'every engine process hangs off a lifecycle phase',
    everyEngineHasAParent,
    `${graph.counts.engine} engine nodes, each spawned by a phase — no orphan process`,
  );

  const phaseParents = graph.nodes
    .filter((node) => node.kind === 'phase')
    .every((node) => graph.edges.some((edge) => edge.kind === 'orchestrates' && edge.target === node.id));
  check(
    'every phase hangs off the scan root',
    graph.counts.phase > 0 && phaseParents,
    `${graph.counts.phase} phases, all orchestrated by the scan node`,
  );

  /* Findings must attach to the engine that produced them, or the "which
     process found this" question the map exists to answer is unanswerable. */
  const unattached = assessment.findings
    .filter((finding) => graph.nodes.some((node) => node.findingRef === finding.id))
    .filter(
      (finding) =>
        !graph.edges.some((edge) => edge.kind === 'produces' && edge.target === `finding:${finding.id}`),
    );
  check(
    'every plotted finding is attributed to the process that produced it',
    unattached.length === 0,
    unattached.length === 0
      ? `${graph.counts.finding} findings, each linked to its engine`
      : `${unattached.length} findings float free of any engine`,
  );

  /* ── 6. every lens projects something, and only its own kinds ─────────── */
  const lensReport: string[] = [];
  let lensFailures = 0;
  for (const lens of WORKFLOW_LENSES) {
    const projection = projectLens(graph, {
      lens,
      hiddenKinds: new Set(),
      showInferred: true,
      grouping: lens.groupBy,
      query: '',
      hiddenSeverities: new Set(),
    });
    const foreign = projection.nodes.filter((node) => !lens.kinds.includes(node.kind));
    const dangling = projection.edges.filter((edge) => {
      const live = new Set(projection.nodes.map((node) => node.id));
      return !live.has(edge.source) || !live.has(edge.target);
    });
    if (foreign.length > 0 || dangling.length > 0 || projection.nodes.length === 0) lensFailures += 1;
    lensReport.push(`${lens.id}=${projection.nodes.length}n/${projection.edges.length}e`);
  }
  check(
    'every lens projects a non-empty, self-consistent subgraph',
    lensFailures === 0,
    lensReport.join('  '),
  );

  /* Clusters must contain members, or the canvas draws an empty box. */
  const emptyClusters = graph.clusters.filter(
    (cluster) => !graph.nodes.some((node) => node.groups[cluster.grouping] === cluster.id),
  );
  check(
    'no compound box is drawn around nothing',
    emptyClusters.length === 0,
    `${graph.clusters.length} clusters, ${emptyClusters.length} empty`,
  );

  /* ── 6b. the graph stays sparse enough to actually lay out ────────────────
        Engines set `relatedTo` to every sibling in a correlation group, which
        drew a near-complete clique: 1,738 of 2,366 edges on this very corpus,
        all restating what the exposure hub already says. A force layout cannot
        absorb that, and neither can a reader. The exposure node carries the
        relationship as a star instead, so the ratio has to stay low. */
  const density = graph.edges.length / Math.max(1, graph.nodes.length);
  check(
    'the graph is sparse enough for a force layout to resolve',
    density <= 6,
    `${graph.edges.length} edges over ${graph.nodes.length} nodes = ${density.toFixed(2)} per node (limit 6)`,
  );

  const worstLens = WORKFLOW_LENSES.map((lens) => {
    const projection = projectLens(graph, {
      lens,
      hiddenKinds: new Set(),
      showInferred: true,
      grouping: lens.groupBy,
      query: '',
      hiddenSeverities: new Set(),
    });
    return { id: lens.id, edges: projection.edges.length, nodes: projection.nodes.length };
  }).sort((a, b) => b.edges - a.edges)[0];
  check(
    'no single lens renders a hairball',
    worstLens.edges <= 700,
    `densest lens is ${worstLens.id} at ${worstLens.nodes} nodes / ${worstLens.edges} edges`,
  );

  const cliques = graph.edges.filter(
    (edge) => edge.kind === 'correlates' && edge.source.startsWith('finding:') && edge.target.startsWith('finding:'),
  );
  const redundant = cliques.filter((edge) => {
    const a = edge.source.replace(/^finding:/, '');
    const b = edge.target.replace(/^finding:/, '');
    return assessment.exposures.some(
      (exposure) => exposure.findingIds.includes(a) && exposure.findingIds.includes(b),
    );
  });
  check(
    'sibling findings are related through their exposure, not by a clique',
    redundant.length === 0,
    `${cliques.length} finding↔finding edges kept, ${redundant.length} that the exposure hub already covers`,
  );

  /* ── 7. determinism ───────────────────────────────────────────────────── */
  const second = buildWorkflowGraph(assessment, { descriptors });
  if (fingerprint(graph) !== fingerprint(second)) {
    /* Print the divergence rather than just failing: the last regression here
       was a derived node holding — and then mutating — an array that belonged
       to the assessment, and the only visible symptom was one extra edge on the
       second build. */
    const first = fingerprint(graph).split(String.fromCharCode(10));
    const repeat = fingerprint(second).split(String.fromCharCode(10));
    const inFirst = new Set(first);
    const inRepeat = new Set(repeat);
    console.log('  only in build 1: ' + first.filter((line) => !inRepeat.has(line)).slice(0, 12).join('  |  '));
    console.log('  only in build 2: ' + repeat.filter((line) => !inFirst.has(line)).slice(0, 12).join('  |  '));
  }
  check(
    'the same assessment yields byte-identical graphs',
    fingerprint(graph) === fingerprint(second),
    `${graph.nodes.length} nodes fingerprinted twice`,
  );

  /* ── 8. secrets never carry their value ───────────────────────────────── */
  const leaked = graph.nodes
    .filter((node) => node.kind === 'secret')
    .filter((node) => node.facts.some((fact) => fact.label === 'Value' && fact.value !== '[REDACTED]'));
  check(
    'secret nodes carry no secret material',
    leaked.length === 0,
    `${graph.counts.secret} secret nodes, ${leaked.length} carrying a value other than [REDACTED]`,
  );

}

async function main() {
  /* Both mounting surfaces, one contract. */
  await assertMode('local');
  await assertMode('dev');

  let failures = 0;
  console.log('');
  for (const result of results) {
    if (!result.pass) failures += 1;
    console.log(`${result.pass ? 'PASS' : 'FAIL'}  ${result.name}
      ${result.detail}`);
  }
  console.log(`
${results.length - failures}/${results.length} checks passed.`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((error) => {
  console.error('check failed to run:', (error as Error).message);
  console.error((error as Error).stack);
  process.exitCode = 2;
});
