/**
 * Exposure report check — the LIVE pipeline, end to end, offline.
 *
 * `tools/exposure-panel-accuracy-check.ts` asserts the derivations the Local and
 * Dev PANELS render. This tool asserts that the exported REPORTS say the same
 * thing: it runs the real orchestrator over a real corpus, builds every template
 * at every presented depth, and reconciles each document against
 * `reconcileExposure` / `panel-model` / `summariseCbom` / `prioritiseMigration` —
 * the same functions the panels read. Then it renders all seven formats and
 * verifies each artefact is a real file of its type.
 *
 * It exists because a report is the one surface a reader takes away and quotes.
 * A dashboard that disagrees with its own PDF is worse than no PDF, and the only
 * way to know they agree is to compute both from one scan and compare.
 *
 *   npx tsx tools/exposure-report-check.ts [directory] [mode] [profile]
 *
 * Defaults: the repo's own src/components, mode=local, profile=deep.
 * Artefacts land in .report-smoke/exposure (gitignored).
 */

import fs from 'node:fs';
import path from 'node:path';
import { runExposureScan } from '@/lib/scanner/exposure/orchestrator';
import { resolveProfile } from '@/lib/scanner/exposure/profiles';
import { QUANTUM_STATUS_TEXT, reconcileExposure } from '@/lib/scanner/exposure/exposure-truth';
import {
  algorithmChipCoverage,
  evidencePopulation,
  summariseAssets,
  summariseCorrelation,
  summariseStandards,
} from '@/lib/scanner/exposure/panel-model';
import { summariseCbom } from '@/lib/scanner/exposure/cbom';
import { prioritiseMigration } from '@/lib/scanner/exposure/risk';
import { emptyWorkspace, type WorkspaceFile } from '@/lib/scanner/exposure/engine-contract';
import { toWorkspaceFile } from '@/lib/scanner/exposure/content/file-discovery';
import { TERMINAL_ENGINE_STATES, type ExposureAssessment, type ScanMode, type ScanTarget } from '@/lib/scanner/exposure/types';
import {
  EXPOSURE_REPORT_DEPTHS,
  EXPOSURE_REPORT_TEMPLATES,
  buildExposureReport,
  canonicalExposureReport,
  type ExposureReportDepth,
  type ExposureReportTemplate,
} from '@/services/reporting/ExposureReport';
import { sha3Hex } from '@/services/reporting/ReportIntegrity';
import { brandingSchema } from '@/services/reporting/schemas/ReportSchema';
import { DOCUMENT_FORMATS, exportDocument } from '@/services/reporting/exporters/DocumentExporters';
import type { InventoryReport } from '@/services/reporting/InventoryReport';
import type { ReportTable } from '@/services/reporting/schemas/ReportSchema';

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

const BOLD = (text: string) => `\x1b[1m${text}\x1b[0m`;
const DIM = (text: string) => `\x1b[2m${text}\x1b[0m`;
const CYAN = (text: string) => `\x1b[36m${text}\x1b[0m`;
const GREEN = (text: string) => `\x1b[32m${text}\x1b[0m`;
const RED = (text: string) => `\x1b[31m${text}\x1b[0m`;
const AMBER = (text: string) => `\x1b[33m${text}\x1b[0m`;

function panel(title: string) {
  console.log('');
  console.log(CYAN(`-- ${title} ${'-'.repeat(Math.max(0, 62 - title.length))}`));
}

const problems: string[] = [];
let passed = 0;

function assert(ok: boolean, label: string, detail: string) {
  if (ok) {
    passed += 1;
    console.log(`  ${GREEN('ok  ')} ${label}`);
  } else {
    console.log(`  ${RED('FAIL')} ${label} ${DIM(`(${detail})`)}`);
    problems.push(`${label} — ${detail}`);
  }
}

function row(label: string, value: unknown) {
  console.log(`  ${label.padEnd(44)} ${String(value)}`);
}

const nf = (value: number) => value.toLocaleString('en-US');

function tableOf(report: InventoryReport, title: string): ReportTable | undefined {
  return report.tables.find((table) => table.title === title);
}

function columnIndex(table: ReportTable, column: string): number {
  return table.columns.indexOf(column);
}

/* ────────────────────────────────────────────────────────────────── main ── */

async function main() {
  const dir = path.resolve(process.argv[2] || path.join(import.meta.dirname, '..', 'src', 'components'));
  const mode = (process.argv[3] as ScanMode) || 'local';
  const profileId = process.argv[4] || 'deep';

  console.log(BOLD('\nExposure REPORT check — LIVE pipeline, offline'));
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
    scanId: `exposure-report-${Date.now().toString(36)}`,
    mode,
    target,
    profileId,
    engineIds: engines,
    workspace,
    localOnly: mode === 'local',
    budgetMs: 600_000,
    engineBudgetMs: 180_000,
  });

  /* The panel truth — every report figure is compared against THIS. */
  const truth = reconcileExposure(assessment);
  const cbom = summariseCbom(assessment.cbom);
  const assets = summariseAssets(assessment);
  const correlation = summariseCorrelation(assessment.exposures);
  const evidence = evidencePopulation(assessment);
  const standards = summariseStandards(assessment);
  const chips = algorithmChipCoverage(assessment);
  const prioritised = prioritiseMigration(assessment.exposures);

  panel('0. THE SCAN THE REPORTS DESCRIBE');
  row('status', assessment.task.status);
  row('findings', nf(assessment.findings.length));
  row('correlated exposures', nf(assessment.exposures.length));
  row('cbom components', nf(assessment.cbom.length));
  row('vulnerable components / findings', `${nf(truth.components.vulnerable)} / ${nf(truth.findings.vulnerable)}`);
  row('readiness', truth.readiness === null ? 'not measured' : `${truth.readiness}%`);
  row('security / quantum / migration risk', `${assessment.task.scores.securityRisk} / ${assessment.task.scores.quantumRisk} / ${assessment.task.scores.migrationRisk}`);
  row('coverage / confidence', `${assessment.task.scores.coverage} / ${assessment.task.scores.confidence}`);
  row('engines incomplete', nf(truth.incompleteEngines.length));
  row('dimensions not assessed', nf(truth.notAssessed.length));
  row('classically weak components', nf(cbom.classicallyWeak));
  row('migration candidates', nf(prioritised.length));

  assert(
    assessment.findings.length > 0 || assessment.cbom.length > 0,
    'the corpus produced evidence to report on',
    'the scan found nothing, so this run proves nothing about the reports',
  );
  assert(
    assessment.task.runs.every((run) => TERMINAL_ENGINE_STATES.includes(run.state)),
    'every engine reached a terminal state before reporting',
    assessment.task.runs.filter((run) => !TERMINAL_ENGINE_STATES.includes(run.state)).map((run) => `${run.engineId}=${run.state}`).join(', '),
  );

  const branding = brandingSchema.parse({ companyName: 'QGuard Helix', businessUnit: 'Platform Security', reportOwner: 'CISO', reviewer: 'Security Architecture' });
  const generatedBy = 'exposure-report-check';

  /* ═══════════════════════════════════════ 1. headline reconciliation ═══ */
  panel('1. EVERY TEMPLATE RECONCILES WITH THE PANELS');

  const templates = EXPOSURE_REPORT_TEMPLATES.map((spec) => spec.key);
  const built = new Map<ExposureReportTemplate, InventoryReport>();

  for (const template of templates) {
    const report = buildExposureReport({ assessment, template, depth: 'complete', branding, generatedBy, generatedAt: '2026-10-06T09:00:00.000Z' });
    built.set(template, report);
    const document = report.document!;

    const mismatched = report.reconciliation.filter((entry) => !entry.matches);
    assert(
      mismatched.length === 0,
      `${template}: reconciliation table is all MATCH (${report.reconciliation.length} rows)`,
      mismatched.map((entry) => `${entry.metric}: ${entry.dashboard} vs ${entry.exported}`).join('; '),
    );

    const fails = document.validation.checks.filter((check) => check.status === 'fail');
    assert(
      fails.length === 0,
      `${template}: no validation check FAILS (quality ${document.validation.score}/100, ${document.validation.checks.length} checks)`,
      fails.map((check) => `${check.check}: ${check.detail}`).join('; '),
    );

    /* Registers are the Excel sheets and the CSV blocks. Whatever presented
       depth was chosen, they carry every row — that is the promise the
       shortened-table note makes to the reader. */
    const findingsRegister = tableOf(report, 'Findings Register');
    const cbomRegister = tableOf(report, 'Cryptographic Bill of Materials');
    const exposureRegister = tableOf(report, 'Correlated Exposures');
    const inventoryRegister = tableOf(report, 'Scanned Inventory');
    const ledgerRegister = tableOf(report, 'Engine Execution Ledger');
    const algorithmRegister = tableOf(report, 'Algorithms Observed');

    assert(
      (findingsRegister?.rows.length ?? 0) === assessment.findings.length,
      `${template}: findings register holds every finding`,
      `${findingsRegister?.rows.length ?? 0} of ${assessment.findings.length}`,
    );
    assert(
      (cbomRegister?.rows.length ?? 0) === assessment.cbom.length,
      `${template}: CBOM register holds every component`,
      `${cbomRegister?.rows.length ?? 0} of ${assessment.cbom.length}`,
    );
    assert(
      (exposureRegister?.rows.length ?? 0) === assessment.exposures.length,
      `${template}: exposure register holds every correlated exposure`,
      `${exposureRegister?.rows.length ?? 0} of ${assessment.exposures.length}`,
    );
    assert(
      (inventoryRegister?.rows.length ?? 0) === assets.rows.length,
      `${template}: inventory register matches the Scanned Assets panel`,
      `${inventoryRegister?.rows.length ?? 0} of ${assets.rows.length}`,
    );
    assert(
      (ledgerRegister?.rows.length ?? 0) === assessment.task.runs.length,
      `${template}: engine ledger lists every selected engine`,
      `${ledgerRegister?.rows.length ?? 0} of ${assessment.task.runs.length}`,
    );
    assert(
      (algorithmRegister?.rows.length ?? 0) === cbom.byAlgorithm.length,
      `${template}: algorithm register holds every group, not just the dashboard's ${chips.shown} chips`,
      `${algorithmRegister?.rows.length ?? 0} of ${cbom.byAlgorithm.length}`,
    );

    /* Per-unit posture, counted off the register the reader actually gets. */
    if (cbomRegister) {
      const statusAt = columnIndex(cbomRegister, 'Quantum Status');
      const vulnerable = cbomRegister.rows.filter((r) => r[statusAt] === QUANTUM_STATUS_TEXT.vulnerable).length;
      const pqc = cbomRegister.rows.filter((r) => r[statusAt] === QUANTUM_STATUS_TEXT.pqc).length;
      const hybrid = cbomRegister.rows.filter((r) => r[statusAt] === QUANTUM_STATUS_TEXT.hybrid).length;
      assert(vulnerable === truth.components.vulnerable, `${template}: vulnerable COMPONENTS in the register match the Quantum Exposure panel`, `${vulnerable} vs ${truth.components.vulnerable}`);
      assert(pqc === truth.components.pqc, `${template}: post-quantum components match`, `${pqc} vs ${truth.components.pqc}`);
      assert(hybrid === truth.components.hybrid, `${template}: hybrid components are counted separately from post-quantum`, `${hybrid} vs ${truth.components.hybrid}`);
    }
    if (findingsRegister) {
      const statusAt = columnIndex(findingsRegister, 'Quantum Status');
      const severityAt = columnIndex(findingsRegister, 'Severity');
      const vulnerable = findingsRegister.rows.filter((r) => r[statusAt] === QUANTUM_STATUS_TEXT.vulnerable).length;
      const critical = findingsRegister.rows.filter((r) => r[severityAt] === 'Critical').length;
      assert(vulnerable === truth.findings.vulnerable, `${template}: vulnerable FINDINGS in the register match the findings filter`, `${vulnerable} vs ${truth.findings.vulnerable}`);
      assert(critical === truth.severity.critical, `${template}: critical findings match the severity tally`, `${critical} vs ${truth.severity.critical}`);
      const withoutEvidence = findingsRegister.rows.filter((r) => r[columnIndex(findingsRegister, 'Evidence')] === '—').length;
      assert(
        withoutEvidence === assessment.findings.filter((finding) => !finding.evidence[0]?.summary).length,
        `${template}: findings with no evidence summary are not invented`,
        `${withoutEvidence} blank evidence cells`,
      );
    }

    /* Both units appear, each named — the defect exposure-truth exists for. */
    const serialised = JSON.stringify(document);
    assert(
      serialised.includes('COMPONENT') || truth.components.total === 0,
      `${template}: the document names the COMPONENT unit`,
      'no occurrence of the component unit in the narrative',
    );
    assert(
      serialised.includes('FINDING') || assessment.findings.length === 0,
      `${template}: the document names the FINDING unit`,
      'no occurrence of the finding unit in the narrative',
    );
    assert(
      serialised.includes('EXPOSURE') || assessment.exposures.length === 0,
      `${template}: the document names the EXPOSURE unit the scores are weighted over`,
      'no occurrence of the exposure unit in the narrative',
    );

    /* Readiness: null is "not measured", never 0%. */
    const readinessKpi = document.summary.highlights.find((kpi) => kpi.label === 'Post-quantum readiness');
    assert(
      readinessKpi !== undefined && readinessKpi.value === (truth.readiness === null ? 'Not measured' : `${truth.readiness}%`),
      `${template}: readiness is published exactly as the panel publishes it`,
      `${readinessKpi?.value} vs ${truth.readiness === null ? 'Not measured' : `${truth.readiness}%`}`,
    );

    /* A partial scan must say so on the document's own face. */
    if (truth.partial) {
      assert(
        document.cover.scopeLine.includes('partial coverage') || document.summary.paragraphs.some((p) => p.includes('PARTIAL scan')),
        `${template}: a partial scan is declared in the cover or the summary`,
        'nothing in the document says the scan was partial',
      );
      const coverageCheck = document.validation.checks.find((check) => check.check === 'Assessment coverage is complete');
      assert(coverageCheck?.status === 'warn', `${template}: partial coverage raises a validation WARN`, `status=${coverageCheck?.status}`);
    }

    /* The integrity seal must recompute from what a reader is handed. */
    const recomputed = sha3Hex(canonicalExposureReport(report));
    assert(
      report.integrity?.hash === recomputed,
      `${template}: SHA3-256 seal recomputes from the exported JSON`,
      `${report.integrity?.hash?.slice(0, 16)} vs ${recomputed.slice(0, 16)}`,
    );
    assert(
      report.document?.integrity?.hash === report.integrity?.hash,
      `${template}: the document copy of the seal is the same seal`,
      'the two seals differ',
    );
  }

  /* ═══════════════════════════════════════════ 2. honesty invariants ════ */
  panel('2. HONESTY INVARIANTS');

  const technical = built.get('technical')!;
  const technicalDoc = technical.document!;

  assert(
    (truth.readiness === null) === (truth.components.quantumRelevant === 0),
    'readiness is null exactly when nothing quantum-relevant was observed',
    `readiness=${truth.readiness}, quantum-relevant=${truth.components.quantumRelevant}`,
  );

  const serialisedAll = templates.map((template) => JSON.stringify(built.get(template)!)).join('\n');
  /* The one place a cost may be NAMED is the disclaimer saying this assessment
     produces none; anything else that reads like a budget claim is a defect.
     A bare "a cost-like claim appears" is not actionable against a 1.7 MB
     document, so the failure quotes what it matched and where. */
  const costProse = serialisedAll.replace(/no migration cost[^"]*/gi, '').replace(/No migration cost[^"]*/g, '');
  /* MONEY, not the word "budget". `budget of` also matched this engine's own
     honest disclosure — "stopped at its per-run cap … the assessment budget" —
     which is a statement about work units, not spend, and is exactly the kind
     of limit the report is required to publish. What must never appear is a
     currency figure or an investment-return claim, because this assessment
     models neither. */
  const costHits = [...costProse.matchAll(/\b(?:total cost|migration cost|cost forecast|cost estimate|ROI|return on investment)\b|[$£€]\s?\d|\b\d[\d,.]*\s?(?:USD|EUR|GBP)\b/gi)]
    .slice(0, 4)
    .map((match) => `"${match[0]}" in …${costProse.slice(Math.max(0, (match.index ?? 0) - 110), (match.index ?? 0) + 110).replace(/\s+/g, ' ')}…`);
  assert(
    costHits.length === 0,
    'no report asserts a cost, budget or ROI',
    `a cost-like claim appears outside the explicit disclaimer — ${costHits.join(' | ')}`,
  );

  /* Truncation must reach the HEADLINE, not only the limitations prose.
     A dev-mode run over this repo's own src/ stops its source analysis at a
     per-run cap several hundred files short, and published "Coverage 100%" in
     the same document that said "every total in this report is therefore a
     floor". A reader quotes the number, not the footnote. */
  if (assessment.task.coverage.truncated) {
    assert(
      assessment.task.scores.coverage === null || assessment.task.scores.coverage < 100,
      `a truncated analysis does not publish full coverage (coverage ${assessment.task.scores.coverage}%)`,
      'the headline asserts complete coverage of work that was cut short',
    );
    assert(
      assessment.task.coverage.truncatedBy.length > 0,
      `the truncation names the engine it stopped (${assessment.task.coverage.truncatedBy.join(', ') || 'none'})`,
      'truncated is set but no engine is attributed, so coverage cannot discount it',
    );
    const note = assessment.task.coverage.truncationNote ?? '';
    assert(
      /\bunread\b/.test(note) && /\d/.test(note),
      'the truncation note sizes the gap it is disclosing',
      `the note does not say how much was left unread: "${note}"`,
    );
    /* The unit a reader can cross-check. The note used to say the cap was on
       "components" while the bill of materials counted 1,154 of them. */
    assert(
      !/\b\d[\d,]*\s+components\b/.test(note),
      'the truncation note does not state its cap in a unit the CBOM counts differently',
      `the note names a component cap that the bill of materials will not match: "${note}"`,
    );
  }

  const unredacted = assessment.intelligence.secrets.filter((secret) => secret.value !== '[REDACTED]');
  assert(unredacted.length === 0, `every secret value is redacted (${assessment.intelligence.secrets.length} locations reported)`, `${unredacted.length} unredacted`);
  if (assessment.intelligence.secrets.length) {
    const secretsRegister = tableOf(technical, 'Secret Material')!;
    const valueAt = columnIndex(secretsRegister, 'Value');
    assert(
      secretsRegister.rows.every((r) => r[valueAt] === '[REDACTED]'),
      'the secret register carries only the redaction marker in its value column',
      'a value cell holds something else',
    );
  }

  /* PQC role discipline — the rule CLAUDE.md states outright. */
  const cbomRegister = tableOf(technical, 'Cryptographic Bill of Materials')!;
  const usageAt = columnIndex(cbomRegister, 'Usage');
  const targetAt = columnIndex(cbomRegister, 'Post-quantum target');
  const signatureRoles = new Set(['signature', 'certificate', 'code-signing', 'token-signing']);
  const misrouted = cbomRegister.rows.filter((r) => signatureRoles.has(String(r[usageAt])) && /ML-KEM/.test(String(r[targetAt])));
  assert(
    misrouted.length === 0,
    'no signature, certificate or code-signing component is told to adopt ML-KEM',
    `${misrouted.length} rows name a key-establishment algorithm as a signature replacement`,
  );
  const kemRows = cbomRegister.rows.filter((r) => String(r[usageAt]) === 'key-exchange' && String(r[targetAt]) !== 'Not required' && String(r[targetAt]) !== '—');
  assert(
    kemRows.every((r) => /ML-KEM/.test(String(r[targetAt]))),
    'every key-establishment target names ML-KEM (FIPS 203)',
    `${kemRows.filter((r) => !/ML-KEM/.test(String(r[targetAt]))).length} key-exchange rows name something else`,
  );

  /* Correlation, evidence and standards populations are declared, not hidden. */
  const exposuresSection = technicalDoc.sections.find((section) => section.id === 'exposures');
  assert(
    correlation.singletons === 0 || Boolean(exposuresSection && JSON.stringify(exposuresSection).includes('single-finding')),
    'single-finding exposures are declared rather than silently filtered out',
    `${correlation.singletons} singletons with no declaration`,
  );
  const compliance = built.get('compliance')!.document!;
  assert(
    standards.uncited === 0 || JSON.stringify(compliance).includes(nf(standards.uncited)),
    'findings citing no publication are declared in the compliance dossier',
    `${standards.uncited} uncited findings not named`,
  );
  const evidenceSection = compliance.sections.find((section) => section.id === 'evidence');
  assert(
    Boolean(evidenceSection && JSON.stringify(evidenceSection).includes(nf(evidence.unbacked))),
    'findings with no detection layer are declared, not ranked below the table',
    `${evidence.unbacked} unbacked findings not named`,
  );

  /* Classical weakness qualifier on the resistant bucket. */
  if (cbom.classicallyWeak > 0) {
    assert(
      /broken (?:by )?classical/i.test(JSON.stringify(technicalDoc)),
      'the quantum-resistant bucket is qualified where components are classically broken',
      `${cbom.classicallyWeak} classically broken components with no qualifier`,
    );
  } else {
    passed += 1;
    console.log(`  ${GREEN('ok  ')} no classically broken component in scope — no qualifier required`);
  }

  /* Every coverage gap becomes a row; none is rendered as a clean zero. */
  const gapsRegister = tableOf(technical, 'Coverage Gaps');
  const expectedGaps =
    truth.notAssessed.length +
    truth.incompleteEngines.length +
    assessment.task.coverage.exclusions.length +
    (assessment.task.coverage.truncated ? 1 : 0);
  assert(
    (gapsRegister?.rows.length ?? 0) === expectedGaps,
    `every coverage gap is a row (${expectedGaps} expected)`,
    `${gapsRegister?.rows.length ?? 0} rows for ${expectedGaps} gaps`,
  );

  /* ═══════════════════════════════════════════════ 3. presented depth ═══ */
  panel('3. PRESENTED DEPTH SHORTENS HONESTLY');

  for (const depthSpec of EXPOSURE_REPORT_DEPTHS) {
    const report = buildExposureReport({ assessment, template: 'technical', depth: depthSpec.key as ExposureReportDepth, branding, generatedBy });
    const document = report.document!;
    const findingsBlock = document.sections
      .flatMap((section) => section.blocks)
      .find((block) => block.type === 'table' && block.table.title === 'Findings Register');

    const presentedRows = findingsBlock && findingsBlock.type === 'table' ? findingsBlock.table.rows.length : 0;
    const expected = Number.isFinite(depthSpec.rows) ? Math.min(depthSpec.rows, assessment.findings.length) : assessment.findings.length;
    row(`${depthSpec.label} presented findings`, `${nf(presentedRows)} of ${nf(assessment.findings.length)}`);
    assert(presentedRows === expected, `${depthSpec.key}: the narrative presents the chosen depth`, `${presentedRows} vs ${expected}`);

    if (presentedRows < assessment.findings.length) {
      const note = findingsBlock && findingsBlock.type === 'table' ? findingsBlock.note ?? '' : '';
      assert(
        note.includes(nf(assessment.findings.length)) && /Excel, CSV and JSON/.test(note),
        `${depthSpec.key}: a shortened register states the omission and where the full one is`,
        `note="${note.slice(0, 90)}"`,
      );
      const limitCheck = document.validation.checks.find((check) => check.check === 'Registers are presented in full in this format');
      assert(limitCheck?.status === 'warn', `${depthSpec.key}: shortening raises a validation WARN the reader sees`, `status=${limitCheck?.status}`);
    }

    /* The register itself is never shortened, whatever the depth. */
    assert(
      (tableOf(report, 'Findings Register')?.rows.length ?? 0) === assessment.findings.length,
      `${depthSpec.key}: the Excel/CSV register stays complete`,
      `${tableOf(report, 'Findings Register')?.rows.length} of ${assessment.findings.length}`,
    );
  }

  /* ═══════════════════════════════════════════ 4. recorded assessment ═══ */
  panel('4. A RECORDED ASSESSMENT DECLARES ITS EDGES');

  const recorded = buildExposureReport({
    assessment,
    template: 'compliance',
    depth: 'standard',
    branding,
    generatedBy,
    record: {
      recordedAt: '2026-10-01T08:00:00.000Z',
      recordVersion: 3,
      rehydrated: ['findings', 'cryptographic components', 'engine ledger'],
      recomputed: ['correlated exposures', 'risk scores', 'CBOM summary'],
      notRetained: ['raw evidence snippets beyond the first per finding'],
      truncated: ['findings capped at 2,000 rows at storage time'],
    },
  });
  const recordedDoc = recorded.document!;
  assert(
    recordedDoc.sections.some((section) => section.id === 'record'),
    'the compliance dossier carries a Record Provenance section',
    'no record section',
  );
  assert(
    JSON.stringify(recordedDoc).includes('not retained'),
    'a field the record did not keep is reported as not retained, never as empty',
    'the not-retained wording is missing',
  );
  assert(
    recordedDoc.cover.facts.some((fact) => fact.label === 'Source' && fact.value.includes('record')),
    'the cover states the document was built from a stored record',
    recordedDoc.cover.facts.find((fact) => fact.label === 'Source')?.value ?? 'no Source fact',
  );
  assert(
    recordedDoc.validation.checks.some((check) => check.check === 'Record provenance is declared'),
    'record provenance is a validation check in its own right',
    'the check is absent',
  );

  /* ════════════════════════════════════════════════ 5. seven formats ════ */
  panel('5. SEVEN FORMATS RENDER REAL FILES');

  const outDir = path.join(import.meta.dirname, '..', '.report-smoke', 'exposure');
  fs.mkdirSync(outDir, { recursive: true });

  const deckReport = built.get('executive')!;
  const deck = buildExposureReport({ assessment, template: 'executive', depth: 'summary', branding, generatedBy });

  for (const format of DOCUMENT_FORMATS) {
    /* The deck and the PDF are summary formats: a 1,100-row register is not a
       briefing. They are exercised at `summary` depth, which is what the Report
       Studio recommends for them; the spreadsheet formats get the complete
       document so the full registers are exercised too. */
    const source = format === 'pptx' || format === 'pdf' ? deck : deckReport;
    try {
      const result = await exportDocument(source, format);
      const bytes = Buffer.from(await result.blob.arrayBuffer());
      fs.writeFileSync(path.join(outDir, result.filename), bytes);
      const head = bytes.subarray(0, 8);
      const ok =
        format === 'pdf'
          ? head.subarray(0, 4).toString('latin1') === '%PDF'
          : format === 'docx' || format === 'xlsx' || format === 'pptx'
            ? head[0] === 0x50 && head[1] === 0x4b
            : format === 'json'
              ? (() => {
                  try {
                    JSON.parse(bytes.toString('utf8'));
                    return true;
                  } catch {
                    return false;
                  }
                })()
              : format === 'html'
                ? /<!doctype html/i.test(bytes.toString('utf8').slice(0, 200))
                : bytes.toString('utf8').includes('Findings Register');
      assert(ok && bytes.length > 2048, `${format}: renders a valid, non-trivial artefact (${nf(bytes.length)} bytes)`, `magic=${head.subarray(0, 4).toString('hex')} size=${bytes.length}`);
    } catch (error) {
      assert(false, `${format}: renders without throwing`, error instanceof Error ? error.message : String(error));
    }
  }

  /* Text formats must not leak anything the contract redacts. */
  const csv = Buffer.from(await (await exportDocument(technical, 'csv')).blob.arrayBuffer()).toString('utf8');
  const json = Buffer.from(await (await exportDocument(technical, 'json')).blob.arrayBuffer()).toString('utf8');
  for (const [name, body] of [['csv', csv], ['json', json]] as const) {
    assert(
      !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(body),
      `${name}: carries no private key material`,
      'a PEM private key header appears in the export',
    );
    assert(body.includes('Findings Register'), `${name}: carries the complete findings register`, 'the register is missing');
  }
  const csvFindingRows = csv.split(/\r?\n/).filter((line) => line.length > 0).length;
  row('csv lines', nf(csvFindingRows));
  assert(csvFindingRows > assessment.findings.length, 'csv holds at least one line per finding plus headers', `${csvFindingRows} lines for ${assessment.findings.length} findings`);

  /* ═══════════════════════════════════════════════════════ summary ════ */
  panel('RESULT');
  row('checks passed', nf(passed));
  row('artefacts', outDir);
  for (const spec of EXPOSURE_REPORT_TEMPLATES) {
    const document = built.get(spec.key)!.document!;
    const warns = document.validation.checks.filter((check) => check.status === 'warn').length;
    row(`${spec.key}`, `${document.sections.length} sections · quality ${document.validation.score}/100 · ${warns} warn · ${nf(built.get(spec.key)!.tables.length)} registers`);
  }

  if (problems.length) {
    console.log('');
    console.log(RED(BOLD(`${problems.length} problem(s):`)));
    for (const problem of problems) console.log(RED(`  - ${problem}`));
    process.exitCode = 1;
    return;
  }
  console.log('');
  console.log(GREEN(BOLD(`All ${passed} checks passed.`)));
  const warnTotal = templates.reduce((sum, template) => sum + built.get(template)!.document!.validation.checks.filter((check) => check.status === 'warn').length, 0);
  if (warnTotal) console.log(AMBER(`  ${warnTotal} validation warning(s) are printed inside the documents, as designed.`));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
