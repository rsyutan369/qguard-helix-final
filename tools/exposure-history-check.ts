/**
 * Exposure Assessment History — correctness check.
 *
 *   npx tsx tools/exposure-history-check.ts
 *
 * The History tab claims that a recorded assessment reads back as the
 * assessment it was. This proves it, without a database, by round-tripping a
 * realistic assessment through the REAL writer and the REAL reader:
 *
 *     assessment → buildFindingRow / buildInventoryRow / session metadata
 *                → restoreAssessment
 *                → assessment'
 *
 * and then asserting that everything the History tab publishes about
 * `assessment'` equals what it would publish about `assessment`.
 *
 * This is the regression that matters: the writer and reader are two halves of
 * one contract in two files, and nothing else would fail loudly if a field were
 * renamed on one side only — the tab would simply start reporting a recorded
 * scan slightly wrong, forever.
 *
 * With `--live <mode>` and a bearer token in QGUARD_TOKEN it additionally reads
 * the running API and reconciles the list against each detail response.
 */

import {
  buildFindingRow,
  buildInventoryRow,
  type RowContext,
} from '../src/api-server/exposure-persistence';
import {
  buildHistoryEntry,
  buildIntelligenceDigest,
  EXPOSURE_HISTORY_RECORD_VERSION,
  restoreAssessment,
  restoreComponent,
  restoreFinding,
  scannerModeFor,
  summariseHistory,
  type FindingRow,
  type InventoryRow,
  type SessionRow,
} from '../src/lib/scanner/exposure/history';
import { buildCbom, summariseCbom } from '../src/lib/scanner/exposure/cbom';
import { correlateFindings } from '../src/lib/scanner/exposure/correlate';
import { computeScores } from '../src/lib/scanner/exposure/risk';
import { emptyCoverage } from '../src/lib/scanner/exposure/types';
import type {
  ExposureAssessment,
  ExposureFinding,
  ExposureIntelligence,
  ScanCoverage,
} from '../src/lib/scanner/exposure/types';

/* ────────────────────────────────────────────────────────────── reporting ── */

let failures = 0;
let checks = 0;

function check(label: string, condition: boolean, detail?: string) {
  checks += 1;
  if (condition) {
    console.log(`  PASS  ${label}`);
    return;
  }
  failures += 1;
  console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
}

function equal(label: string, actual: unknown, expected: unknown) {
  const same = JSON.stringify(actual) === JSON.stringify(expected);
  check(label, same, same ? undefined : `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

/* ─────────────────────────────────────────────────────── the sample scan ─── */

const NOW = '2026-09-09T10:15:00.000Z';

function finding(overrides: Partial<ExposureFinding> & Pick<ExposureFinding, 'id' | 'title'>): ExposureFinding {
  return {
    scanId: 'scan-1',
    engineId: 'source-crypto',
    mode: 'dev',
    layer: 'source',
    category: 'weak-algorithm',
    title: overrides.title,
    description: 'A description long enough to be realistic for the record.',
    severity: 'high',
    confidence: 'high',
    detection: 'observed',
    quantumStatus: 'vulnerable',
    evidence: [
      {
        summary: 'Observed in source.',
        file: 'src/crypto/sign.ts',
        line: 42,
        observedAt: NOW,
      },
    ],
    firstSeen: NOW,
    lastSeen: NOW,
    ...overrides,
  };
}

const FINDINGS: ExposureFinding[] = [
  finding({
    id: 'source-crypto:rsa-2048',
    title: 'RSA-2048 used for signature verification',
    algorithm: 'RSA',
    canonicalAlgorithm: 'RSA-2048',
    keySize: 2048,
    role: 'authentication',
    severity: 'critical',
    quantumRationale: 'Shor’s algorithm breaks RSA on a cryptographically relevant quantum computer.',
    recommendation: 'Migrate to ML-DSA-65 (FIPS 204).',
    references: ['https://csrc.nist.gov/pubs/fips/204/final'],
    library: 'node:crypto',
    protocol: undefined,
    component: 'auth-service',
    version: '4.2.1',
    migration: { candidate: true, target: 'ML-DSA-65', priority: 'P1', complexity: 'medium', blastRadius: 7 },
  }),
  finding({
    id: 'dependency-scan:ecdsa-p256',
    title: 'ECDSA P-256 signing in a direct dependency',
    engineId: 'dependency-scan',
    layer: 'dependency',
    algorithm: 'ECDSA',
    canonicalAlgorithm: 'ECDSA-P256',
    keySize: 256,
    role: 'code-signing',
    severity: 'high',
    library: 'jose',
    version: '5.2.0',
  }),
  finding({
    id: 'config-scan:aes-gcm',
    title: 'AES-256-GCM configured for payload encryption',
    engineId: 'config-scan',
    layer: 'configuration',
    algorithm: 'AES-256-GCM',
    canonicalAlgorithm: 'AES-256-GCM',
    keySize: 256,
    role: 'encryption',
    severity: 'info',
    quantumStatus: 'resistant',
    detection: 'observed',
  }),
  finding({
    id: 'secret-scan:pem-key',
    title: 'PEM private key block committed to the repository',
    engineId: 'secret-scan',
    layer: 'secret',
    subcategory: 'Private key',
    severity: 'critical',
    quantumStatus: 'unknown',
    confidence: 'medium',
    evidence: [
      {
        summary: 'PEM header found in a tracked file.',
        file: 'deploy/key.pem',
        snippet: '-----BEGIN RSA PRIVATE KEY----- [REDACTED]',
        observedAt: NOW,
      },
    ],
  }),
];

function sampleAssessment(): ExposureAssessment {
  const cbom = buildCbom(FINDINGS);
  const exposures = correlateFindings(FINDINGS);
  const coverage: ScanCoverage = {
    ...emptyCoverage(),
    filesDiscovered: 1_842,
    filesAnalyzed: 1_610,
    filesUnsupported: 132,
    filesSkipped: 100,
    dependencies: 214,
    cryptoComponents: cbom.length,
    exclusions: ['node_modules', 'dist'],
    notAssessed: [
      { dimension: 'Container images', reason: 'No registry credential was supplied.', engineId: 'registry-scan' },
    ],
  };
  const runs = [
    { engineId: 'source-crypto', label: 'Source Cryptography', state: 'completed' as const, progress: 100, startedAt: NOW, completedAt: NOW, findingCount: 1 },
    { engineId: 'dependency-scan', label: 'Dependency Analysis', state: 'completed' as const, progress: 100, startedAt: NOW, completedAt: NOW, findingCount: 1 },
    { engineId: 'config-scan', label: 'Configuration Analysis', state: 'completed' as const, progress: 100, startedAt: NOW, completedAt: NOW, findingCount: 1 },
    { engineId: 'secret-scan', label: 'Secret Detection', state: 'completed' as const, progress: 100, startedAt: NOW, completedAt: NOW, findingCount: 1 },
    { engineId: 'registry-scan', label: 'Registry Scan', state: 'not-assessed' as const, progress: 100, startedAt: null, completedAt: NOW, findingCount: 0, detail: 'No registry credential was supplied.' },
  ];
  const scores = computeScores({ findings: FINDINGS, exposures, coverage, runs });

  const intelligence: ExposureIntelligence = {
    quantum: { ...summariseCbom(cbom), notApplicable: summariseCbom(cbom).notApplicable } as ExposureIntelligence['quantum'],
    severity: { critical: 2, high: 1, medium: 0, low: 0, info: 1 },
    byLayer: [],
    byEngine: [],
    topAlgorithms: [],
    algorithmGroups: 0,
    languages: [{ language: 'TypeScript', files: 1_204 }, { language: 'Python', files: 302 }],
    frameworks: ['Express', 'React'],
    dependencies: [
      { name: 'jose', version: '5.2.0', ecosystem: 'npm', direct: true, cryptoRelevant: true, quantumRelevant: true },
      { name: 'lodash', version: '4.17.21', ecosystem: 'npm', direct: true, cryptoRelevant: false, quantumRelevant: false },
    ],
    secrets: [],
    facts: [
      { label: 'Repository', value: 'qguard/helix', detail: 'github' },
      { label: 'Files analysed', value: '1610 of 1842' },
    ],
    recommendations: [],
    recommendationCandidates: 0,
  };

  return {
    task: {
      scanId: 'scan-1',
      tenantId: null,
      userId: 'user-1',
      mode: 'dev',
      profileId: 'deep',
      target: { kind: 'repository', url: 'https://github.com/qguard/helix', provider: 'github', owner: 'qguard', repo: 'helix', branch: 'main', visibility: 'public' },
      engines: runs.map((run) => run.engineId),
      status: 'partial',
      createdAt: NOW,
      startedAt: NOW,
      completedAt: '2026-09-09T10:19:30.000Z',
      runs,
      coverage,
      scores,
      findingCount: FINDINGS.length,
      failureReason: 'One engine could not read the container registry.',
      exclusions: { directories: ['node_modules', 'dist'], files: [], patterns: [], extensions: [], dependencies: [], secretRules: [] },
      localOnly: false,
    },
    findings: FINDINGS,
    exposures,
    cbom,
    intelligence,
    generatedAt: '2026-09-09T10:19:30.000Z',
    schemaVersion: 1,
  };
}

/* ─────────────────────────────────────────────── the write → read journey ── */

/**
 * Reproduce what `persistExposureAssessment` writes, using its own builders.
 *
 * Only the plumbing is simulated here (the insert calls). Every VALUE comes
 * from the real writer, which is the whole point: this cannot pass while the
 * writer and reader have drifted.
 */
function recordAssessment(assessment: ExposureAssessment, source: 'local' | 'dev') {
  const context: RowContext = {
    userId: 'user-1',
    scanSessionId: 'session-1',
    assetId: 'asset-1',
    source,
    now: NOW,
  };

  const findingRows: FindingRow[] = assessment.findings.map((entry) => ({
    ...buildFindingRow(entry, context),
    created_at: NOW,
  })) as FindingRow[];

  const inventoryRows: InventoryRow[] = assessment.cbom.map((component) => ({
    ...buildInventoryRow(component, context),
  })) as InventoryRow[];

  const session: SessionRow = {
    id: context.scanSessionId,
    user_id: context.userId,
    status: assessment.task.status === 'failed' ? 'failed' : 'completed',
    target_scope: 'github:qguard/helix',
    findings_count: assessment.findings.length,
    started_at: assessment.task.startedAt,
    completed_at: assessment.task.completedAt,
    created_at: NOW,
    updated_at: NOW,
    metadata: {
      scannerMode: scannerModeFor(source),
      exposureMode: assessment.task.mode,
      profileId: assessment.task.profileId,
      engines: assessment.task.engines,
      recordVersion: EXPOSURE_HISTORY_RECORD_VERSION,
      sourceScanId: assessment.task.scanId,
      target: assessment.task.target,
      taskStatus: assessment.task.status,
      failureReason: assessment.task.failureReason ?? null,
      exclusions: assessment.task.exclusions,
      intelligence: buildIntelligenceDigest(assessment.intelligence),
      runs: assessment.task.runs.map((run) => ({
        engineId: run.engineId,
        label: run.label,
        state: run.state,
        findingCount: run.findingCount,
        detail: run.detail,
      })),
      coverage: assessment.task.coverage,
      scores: assessment.task.scores,
      localOnly: assessment.task.localOnly,
      generatedAt: assessment.generatedAt,
    },
  };

  return { session, findingRows, inventoryRows };
}

/* ─────────────────────────────────────────────────────────────── the run ──── */

function runRoundTrip() {
  console.log('\nROUND TRIP — a recorded assessment must read back as the assessment it was');

  const original = sampleAssessment();
  const { session, findingRows, inventoryRows } = recordAssessment(original, 'dev');
  const { assessment: restored, provenance } = restoreAssessment({
    session,
    mode: 'dev',
    findingRows,
    inventoryRows,
  });

  /* ── every finding survives, with its identity ─────────────────────────── */
  equal('every finding row reads back', restored.findings.length, original.findings.length);
  equal(
    'finding identities are preserved',
    [...restored.findings.map((entry) => entry.id)].sort(),
    [...original.findings.map((entry) => entry.id)].sort(),
  );

  const byId = new Map(restored.findings.map((entry) => [entry.id, entry]));
  for (const source of original.findings) {
    const back = byId.get(source.id);
    if (!back) {
      check(`finding ${source.id} present`, false);
      continue;
    }
    const fields: Array<keyof ExposureFinding> = [
      'title',
      'description',
      'severity',
      'confidence',
      'detection',
      'layer',
      'category',
      'subcategory',
      'canonicalAlgorithm',
      'algorithm',
      'keySize',
      'role',
      'quantumStatus',
      'quantumRationale',
      'recommendation',
      'component',
      'version',
      'library',
      'protocol',
      'engineId',
      'firstSeen',
      'lastSeen',
    ];
    const drifted = fields.filter(
      (field) => JSON.stringify(source[field] ?? null) !== JSON.stringify(back[field] ?? null),
    );
    check(
      `finding ${source.id} round-trips every published field`,
      drifted.length === 0,
      drifted.length ? `drifted: ${drifted.join(', ')}` : undefined,
    );
    equal(`finding ${source.id} keeps its references`, back.references ?? [], source.references ?? []);
    equal(`finding ${source.id} keeps its migration hand-off`, back.migration ?? null, source.migration ?? null);
    check(`finding ${source.id} keeps evidence`, back.evidence.length > 0);
  }

  /* ── the CBOM and everything derived from it ───────────────────────────── */
  equal('every component reads back', restored.cbom.length, original.cbom.length);
  equal(
    'quantum split is identical',
    summariseCbom(restored.cbom).vulnerable,
    summariseCbom(original.cbom).vulnerable,
  );
  equal('quantum readiness is identical', summariseCbom(restored.cbom).readiness, summariseCbom(original.cbom).readiness);
  equal('correlated exposures are identical', restored.exposures.length, original.exposures.length);

  /* ── the task record ──────────────────────────────────────────────────── */
  equal('the task status is the task’s own verdict, not the session’s', restored.task.status, original.task.status);
  equal('the structured target survives', restored.task.target, original.task.target);
  equal('the engine ledger survives', restored.task.runs.length, original.task.runs.length);
  equal('coverage survives', restored.task.coverage.filesAnalyzed, original.task.coverage.filesAnalyzed);
  equal('stated limitations survive', restored.task.coverage.notAssessed, original.task.coverage.notAssessed);
  equal('exclusions survive', restored.task.exclusions, original.task.exclusions);

  /* ── the scores are the ones computed at scan time ─────────────────────── */
  equal('scores are the recorded ones', restored.task.scores, original.task.scores);
  check(
    'scores are not silently recomputed',
    !provenance.derived.some((entry) => entry.startsWith('scores recomputed')),
  );

  /* ── intelligence that cannot be recomputed ───────────────────────────── */
  equal('languages survive', restored.intelligence.languages, original.intelligence.languages);
  equal('frameworks survive', restored.intelligence.frameworks, original.intelligence.frameworks);
  equal('dependencies survive', restored.intelligence.dependencies, original.intelligence.dependencies);
  equal('target facts survive', restored.intelligence.facts, original.intelligence.facts);

  /* ── the list row agrees with the detail ──────────────────────────────── */
  const entry = buildHistoryEntry({
    session,
    mode: 'dev',
    findings: restored.findings,
    components: restored.cbom,
    exposureCount: restored.exposures.length,
  });
  equal('list finding count == detail finding count', entry.findingCount, restored.findings.length);
  equal('list component count == detail component count', entry.componentCount, restored.cbom.length);
  equal('list exposure count == detail exposure count', entry.exposureCount, restored.exposures.length);
  equal(
    'list severity split == detail severity split',
    entry.severity,
    restored.findings.reduce(
      (acc, item) => ({ ...acc, [item.severity]: acc[item.severity] + 1 }),
      { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    ),
  );
  equal(
    'list readiness == the CBOM summariser',
    entry.quantumReadiness,
    summariseCbom(restored.cbom).readiness,
  );
  equal('list status == the task verdict', entry.status, original.task.status);
  equal(
    'the originating engine scan id is kept, and is not the record id',
    [entry.sourceScanId, entry.sourceScanId === entry.scanId],
    [original.task.scanId, false],
  );

  /* ── provenance is honest ─────────────────────────────────────────────── */
  check('nothing is reported as not retained for a v2 record with a full digest', provenance.notRetained.length === 0,
    provenance.notRetained.map((item) => item.field).join(', '));
  equal('the record version is published', provenance.recordVersion, EXPOSURE_HISTORY_RECORD_VERSION);
}

/**
 * A record written before the History fields existed must degrade honestly:
 * nothing invented, every gap named.
 */
function runLegacyRecord() {
  console.log('\nLEGACY RECORD — a v1 record must declare what it does not hold, never fake it');

  const original = sampleAssessment();
  const { session, findingRows, inventoryRows } = recordAssessment(original, 'local');

  const legacyMetadata = { ...(session.metadata as Record<string, unknown>) };
  delete legacyMetadata.recordVersion;
  delete legacyMetadata.target;
  delete legacyMetadata.taskStatus;
  delete legacyMetadata.intelligence;
  delete legacyMetadata.exclusions;

  const legacyFindings = findingRows.map((row) => {
    const metadata = { ...(row.metadata as Record<string, unknown>) };
    delete metadata.title;
    delete metadata.references;
    delete metadata.library;
    delete metadata.protocol;
    delete metadata.algorithmRaw;
    return { ...row, metadata };
  });

  const { assessment: restored, provenance } = restoreAssessment({
    session: { ...session, metadata: legacyMetadata },
    mode: 'local',
    findingRows: legacyFindings,
    inventoryRows,
  });

  equal('every finding still reads back', restored.findings.length, original.findings.length);
  check(
    'no finding renders without a headline',
    restored.findings.every((entry) => entry.title.trim().length > 0),
  );
  check(
    'a missing title is filled from the description, never invented',
    restored.findings.every((entry) => original.findings.some((source) => source.description.startsWith(entry.title.replace(/…$/, '')))),
  );
  check(
    'the record version reads as v1',
    provenance.recordVersion === 1,
    `got ${provenance.recordVersion}`,
  );
  for (const field of ['languages', 'frameworks', 'dependencies', 'facts']) {
    check(
      `an absent ${field} list is declared as not retained`,
      provenance.notRetained.some((item) => item.field === field),
    );
  }
  check(
    'the empty dependency list is never presented as "no dependencies"',
    provenance.notRetained.some((item) => item.field === 'dependencies' && /not retained/i.test(item.reason)),
  );
}

/** A row the reader cannot trust must be excluded and disclosed, not guessed. */
function runUnreadableRows() {
  console.log('\nUNREADABLE ROWS — a row that cannot be trusted is excluded and disclosed');

  const original = sampleAssessment();
  const { session, findingRows, inventoryRows } = recordAssessment(original, 'dev');

  const damaged = findingRows.map((row, index) => {
    if (index !== 0) return row;
    const metadata = { ...(row.metadata as Record<string, unknown>) };
    metadata.layer = 'somewhere-else';
    return { ...row, metadata };
  });

  const { assessment: restored, provenance } = restoreAssessment({
    session,
    mode: 'dev',
    findingRows: damaged,
    inventoryRows,
  });

  equal('the unreadable row is excluded', restored.findings.length, original.findings.length - 1);
  check(
    'the exclusion is disclosed rather than silent',
    provenance.notRetained.some((item) => item.field === 'findings'),
  );
  check(
    'no finding was filed under an invented layer',
    restored.findings.every((entry) => entry.layer !== ('somewhere-else' as never)),
  );

  const entry = buildHistoryEntry({
    session,
    mode: 'dev',
    findings: restored.findings,
    components: restored.cbom,
    exposureCount: restored.exposures.length,
  });
  equal('the list reports what is readable, not what the header claims', entry.findingCount, restored.findings.length);
  check(
    'the header count is NOT used as the published total',
    entry.findingCount !== session.findings_count,
    'the sample was constructed so these differ',
  );
}

/** Portfolio totals must be the sum of the rows, never an independent estimate. */
function runSummary() {
  console.log('\nSUMMARY — portfolio totals must equal the sum of their rows');

  const original = sampleAssessment();
  const { session, findingRows, inventoryRows } = recordAssessment(original, 'dev');
  const { assessment: restored } = restoreAssessment({ session, mode: 'dev', findingRows, inventoryRows });

  const first = buildHistoryEntry({ session, mode: 'dev', findings: restored.findings, components: restored.cbom, exposureCount: restored.exposures.length });
  const second = { ...first, scanId: 'session-2', target: 'github:qguard/other' };
  const summary = summariseHistory([first, second]);

  equal('assessments counted', summary.assessments, 2);
  equal('findings summed', summary.findings, first.findingCount * 2);
  equal('components summed', summary.components, first.componentCount * 2);
  equal('distinct targets counted', summary.targets, 2);
  equal('critical severity summed', summary.severity.critical, first.severity.critical * 2);
  equal('latest readiness comes from an assessment that measured components', summary.latestReadiness, first.quantumReadiness);
}

/* ───────────────────────────────────────────────────────── the data layer ─── */

/**
 * A PostgREST stand-in that answers the exact query shapes the reader builds.
 *
 * The round-trip above proves the row MAPPING; this proves the QUERY layer —
 * the tenant predicate, the `scannerMode` marker, and the linking of
 * `crypto_inventory` rows to a session through `metadata->>scanSessionId`,
 * which is the one join in this feature with no foreign key behind it. It also
 * pins the property that matters most: a query ERROR must surface as an error,
 * never as an empty history.
 */
function stubClient(tables: Record<string, Array<Record<string, unknown>>>, failOn?: string) {
  const value = (row: Record<string, unknown>, path: string): unknown => {
    if (!path.includes('->>')) return row[path];
    const [column, key] = path.split('->>');
    const blob = row[column] as Record<string, unknown> | undefined;
    return blob?.[key];
  };

  const builder = (table: string) => {
    let rows = [...(tables[table] ?? [])];
    let single = false;

    const api: Record<string, unknown> = {
      select() { return api; },
      eq(column: string, expected: unknown) {
        rows = rows.filter((row) => String(value(row, column)) === String(expected));
        return api;
      },
      in(column: string, values: unknown[]) {
        const wanted = new Set(values.map(String));
        rows = rows.filter((row) => wanted.has(String(value(row, column))));
        return api;
      },
      or(filter: string) {
        /* `metadata->>scanSessionId.eq.<id>,metadata->>scanSessionId.eq.<id>` */
        const wanted = new Set(
          filter.split(',').map((clause) => clause.slice(clause.lastIndexOf('.eq.') + 4)),
        );
        rows = rows.filter((row) => wanted.has(String(value(row, 'metadata->>scanSessionId'))));
        return api;
      },
      order() { return api; },
      limit() { return api; },
      maybeSingle() { single = true; return api; },
      then(resolve: (result: unknown) => void) {
        if (failOn === table) {
          resolve({ data: null, error: { message: 'relation is unavailable' }, count: null });
          return;
        }
        resolve(single ? { data: rows[0] ?? null, error: null } : { data: rows, error: null, count: rows.length });
      },
    };
    return api;
  };

  return { from: (table: string) => builder(table) } as never;
}

async function runDataLayer() {
  console.log('\nDATA LAYER — the query path must select the right rows, and fail loudly');

  const { loadExposureHistory, loadExposureHistoryDetail, invalidateHistory } = await import(
    '../src/api-server/exposure-history'
  );

  const original = sampleAssessment();
  const recorded = recordAssessment(original, 'dev');

  /* A second tenant's assessment and a Web scanner session, both of which must
     be invisible to this read. */
  const otherTenant = {
    ...recorded.session,
    id: 'session-other',
    user_id: 'user-2',
  };
  const webSession = {
    ...recorded.session,
    id: 'session-web',
    metadata: { ...(recorded.session.metadata as Record<string, unknown>), scannerMode: 'defensive-cryptographic-inventory' },
  };
  const localSession = {
    ...recorded.session,
    id: 'session-local',
    metadata: { ...(recorded.session.metadata as Record<string, unknown>), scannerMode: scannerModeFor('local') },
  };

  const tables = {
    pqc_scan_sessions: [recorded.session, otherTenant, webSession, localSession] as Array<Record<string, unknown>>,
    pqc_scan_results: recorded.findingRows.map((row) => ({ ...row, user_id: 'user-1' })) as Array<Record<string, unknown>>,
    crypto_inventory: recorded.inventoryRows.map((row) => ({ ...row, user_id: 'user-1' })) as Array<Record<string, unknown>>,
  };

  invalidateHistory('user-1');
  const devHistory = await loadExposureHistory(stubClient(tables), 'user-1', 'dev', { fresh: true });

  equal('only this tenant’s Dev assessments are listed', devHistory.entries.map((entry) => entry.scanId), ['session-1']);
  check(
    'another tenant’s assessment is not reachable',
    !devHistory.entries.some((entry) => entry.scanId === 'session-other'),
  );
  check(
    'a Web scanner session is not listed as an exposure assessment',
    !devHistory.entries.some((entry) => entry.scanId === 'session-web'),
  );
  check(
    'a Local assessment is not listed under Dev',
    !devHistory.entries.some((entry) => entry.scanId === 'session-local'),
  );

  const entry = devHistory.entries[0];
  equal('findings are attributed to their own session', entry.findingCount, original.findings.length);
  equal('components are linked through metadata.scanSessionId', entry.componentCount, original.cbom.length);
  equal('the portfolio summary sums the listed entries', devHistory.summary.findings, entry.findingCount);

  invalidateHistory('user-1');
  const localHistory = await loadExposureHistory(stubClient(tables), 'user-1', 'local', { fresh: true });
  equal('the Local surface lists only Local records', localHistory.entries.map((item) => item.scanId), ['session-local']);

  /* ── detail ───────────────────────────────────────────────────────────── */
  const detail = await loadExposureHistoryDetail(stubClient(tables), 'user-1', 'dev', 'session-1');
  check('the detail resolves for a recorded assessment', detail !== null);
  if (detail) {
    equal('detail findings == list findings', detail.assessment.findings.length, entry.findingCount);
    equal('detail components == list components', detail.assessment.cbom.length, entry.componentCount);
    equal('detail exposures == list exposures', detail.assessment.exposures.length, entry.exposureCount);
  }

  const crossTenant = await loadExposureHistoryDetail(stubClient(tables), 'user-2', 'dev', 'session-1');
  check('another tenant cannot open this assessment by id', crossTenant === null);

  const wrongMode = await loadExposureHistoryDetail(stubClient(tables), 'user-1', 'local', 'session-1');
  check('a Dev assessment cannot be opened through the Local surface', wrongMode === null);

  /* ── a failed read is a failure ───────────────────────────────────────── */
  invalidateHistory('user-1');
  let threw = false;
  try {
    await loadExposureHistory(stubClient(tables, 'pqc_scan_sessions'), 'user-1', 'dev', { fresh: true });
  } catch {
    threw = true;
  }
  check('a failed session query throws instead of returning an empty history', threw);

  invalidateHistory('user-1');
  let componentQueryThrew = false;
  try {
    await loadExposureHistory(stubClient(tables, 'crypto_inventory'), 'user-1', 'dev', { fresh: true });
  } catch {
    componentQueryThrew = true;
  }
  check('a failed component query throws instead of reporting zero components', componentQueryThrew);

  invalidateHistory('user-1');
}

/* ────────────────────────────────────────────────────────────── live mode ─── */

async function runLive(mode: 'local' | 'dev') {
  const token = process.env.QGUARD_TOKEN;
  const base = process.env.QGUARD_BASE ?? 'http://localhost:3000';
  if (!token) {
    console.log('\nLIVE — skipped: set QGUARD_TOKEN to a bearer token to reconcile against the running API.');
    return;
  }

  console.log(`\nLIVE — reconciling ${base}/api/v1/exposure/history?mode=${mode}`);
  const headers = { Authorization: `Bearer ${token}` };

  const listResponse = await fetch(`${base}/api/v1/exposure/history?mode=${mode}`, { headers });
  const listBody = await listResponse.json();
  if (!listResponse.ok) {
    check('the history list responds', false, listBody?.error?.message ?? String(listResponse.status));
    return;
  }
  check('the history list responds', true);

  const entries = listBody.data.entries as Array<Record<string, unknown>>;
  console.log(`        ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'} (${listBody.data.total} recorded)`);

  for (const entry of entries.filter((item) => item.origin === 'recorded').slice(0, 5)) {
    const scanId = String(entry.scanId);
    const detailResponse = await fetch(
      `${base}/api/v1/exposure/history/${encodeURIComponent(scanId)}?mode=${mode}`,
      { headers },
    );
    const detailBody = await detailResponse.json();
    if (!detailResponse.ok) {
      check(`detail for ${scanId} responds`, false, detailBody?.error?.message ?? String(detailResponse.status));
      continue;
    }
    const assessment = detailBody.data.assessment as ExposureAssessment;
    equal(`${scanId}: list findings == detail findings`, entry.findingCount, assessment.findings.length);
    equal(`${scanId}: list components == detail components`, entry.componentCount, assessment.cbom.length);
    equal(`${scanId}: list exposures == detail exposures`, entry.exposureCount, assessment.exposures.length);
    equal(
      `${scanId}: list readiness == the CBOM summariser over the detail`,
      entry.quantumReadiness,
      assessment.cbom.length > 0 ? summariseCbom(assessment.cbom).readiness : entry.quantumReadiness,
    );
  }
}

/* ──────────────────────────────────────────────────────────────── entry ───── */

async function main() {
  console.log('QGuard Helix — Exposure Assessment History check');

  runRoundTrip();
  runLegacyRecord();
  runUnreadableRows();
  runSummary();
  await runDataLayer();

  const liveIndex = process.argv.indexOf('--live');
  if (liveIndex >= 0) {
    const mode = process.argv[liveIndex + 1] === 'local' ? 'local' : 'dev';
    await runLive(mode);
  }

  console.log(`\n${checks - failures}/${checks} checks passed`);
  if (failures > 0) {
    console.log(`${failures} FAILED`);
    process.exit(1);
  }
}

void main();
