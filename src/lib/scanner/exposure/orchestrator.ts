/**
 * Scan Orchestrator (§31, §33, §34, §35, §57, §58, §62).
 *
 * Runs a set of engines against one workspace and produces one assessment.
 *
 * THE FOUR GUARANTEES this module exists to provide:
 *
 *  1. TERMINAL STATE FOR EVERY ENGINE (§62). Every selected engine ends in
 *     completed / failed / not-applicable / not-assessed / skipped / cancelled.
 *     An engine that throws, hangs past its budget, or is never reached still
 *     gets a terminal row with a reason. A ledger with a stuck `running` row is
 *     a lost module.
 *
 *  2. PROGRESS FROM REAL WORK (§34). "Do not use fake progress timers."
 *     Overall progress is the weight-share of engines that have SETTLED, plus
 *     the settled fraction of the one currently running — and that fraction is
 *     its own `units.done / units.total`, which are counts of finished work.
 *     Nothing here advances on a clock.
 *
 *  3. PARTIAL IS NOT SUCCESS (§62). If any engine failed, the scan status is
 *     `partial`, never `completed`. The failure reasons are published.
 *
 *  4. CANCELLATION IS IMMEDIATE AND HONEST. Cancelling stops dispatch, marks
 *     unreached engines `cancelled`, and keeps whatever was already found.
 *
 * Isomorphic: runs unchanged in a browser Web Worker and in the api-server.
 */

import type {
  EngineRun,
  ExposureAssessment,
  ExposureFinding,
  ExposureIntelligence,
  ScanCoverage,
  ScanEvent,
  ScanEventSink,
  ScanExclusions,
  ScanMode,
  ScanTarget,
  ScanTask,
} from './types';
import {
  defaultExclusions,
  emptyCoverage,
  mergeCoverage,
} from './types';
import type { EngineContext, EngineCredential, EngineResult, ExposureEngine, ScanWorkspace } from './engine-contract';
import { emptyWorkspace, inventoryObservations } from './engine-contract';
import { engineById } from './registry';
import { correlateFindings } from './correlate';
import { computeScores } from './risk';
import { buildCbom, summariseCbom } from './cbom';
import { RECOMMENDATION_LIMIT, rankRecommendations } from './recommendations';

/* ────────────────────────────────────────────────────────── configuration ── */

export interface OrchestratorOptions {
  scanId: string;
  mode: ScanMode;
  target: ScanTarget;
  profileId: string;
  engineIds: string[];
  workspace?: ScanWorkspace;
  exclusions?: ScanExclusions;
  tenantId?: string | null;
  userId?: string | null;
  /** Wall-clock budget for the whole scan. Engines degrade, they do not hang. */
  budgetMs?: number;
  /** Per-engine budget. Defaults to a share of the scan budget. */
  engineBudgetMs?: number;
  /** How many engines may run at once (§33). */
  concurrency?: number;
  credentials?: Partial<Record<EngineCredential['kind'], EngineCredential>>;
  /** True when raw material must never leave the device (§43). */
  localOnly?: boolean;
  onEvent?: ScanEventSink;
  /** Poll for operator cancellation. */
  isCancelled?: () => boolean;
  /**
   * The slice of the progress bar these engines own.
   *
   * A Dev scan spends most of its wall time ACQUIRING the repository before a
   * single engine runs — measured at 21.1s of acquisition against 0.4s of
   * engines on a 57-file repository. When the engines own 0-100 regardless, the
   * bar sits at zero for 98% of the scan and then sweeps to done in under half
   * a second, which reads as a broken progress bar because it is describing 2%
   * of the work.
   *
   * The caller that knows about an acquisition phase reserves the front of the
   * band for it and hands the engines the rest. Callers with no such phase
   * (Local, connection-only Dev targets) omit this and keep the full range.
   */
  progressRange?: { from: number; to: number };
}

const DEFAULT_SCAN_BUDGET_MS = 180_000;
const DEFAULT_CONCURRENCY = 4;
/** Hard ceiling per engine, so one wedged engine cannot hold the whole scan. */
const DEFAULT_ENGINE_BUDGET_MS = 60_000;

/* ─────────────────────────────────────────────────────────── exclusions ──── */

/** Compile exclusion rules into one predicate (§42). */
export function compileExclusions(exclusions: ScanExclusions): (path: string) => boolean {
  const directories = exclusions.directories.map((entry) => entry.replace(/^\/+|\/+$/g, '').toLowerCase()).filter(Boolean);
  const files = new Set(exclusions.files.map((entry) => entry.toLowerCase()));
  const extensions = new Set(exclusions.extensions.map((entry) => (entry.startsWith('.') ? entry : `.${entry}`).toLowerCase()));
  const patterns = exclusions.patterns
    .map((pattern) => {
      try {
        // Glob → RegExp: `**` any depth, `*` one segment, `?` one character.
        const source = pattern
          .replace(/[.+^${}()|[\]\\]/g, '\\$&')
          /* U+E000 (private use) as the `**` placeholder, NOT a raw NUL.
             The sentinel used to be an actual 0x00 byte written into the
             source, which made git classify this whole file as BINARY — every
             change to the orchestrator showed as "Binary files differ" with no
             reviewable diff. Behaviour is identical; the file is text again. */
          .replace(/\*\*/g, '')
          .replace(/\*/g, '[^/]*')
          .replace(//g, '.*')
          .replace(/\?/g, '.');
        return new RegExp(`^${source}$`, 'i');
      } catch {
        return null;
      }
    })
    .filter((pattern): pattern is RegExp => pattern !== null);

  return (path: string) => {
    const lower = path.toLowerCase();
    if (files.has(lower)) return true;
    const dot = lower.lastIndexOf('.');
    if (dot > 0 && extensions.has(lower.slice(dot))) return true;
    for (const directory of directories) {
      if (lower === directory || lower.startsWith(`${directory}/`) || lower.includes(`/${directory}/`)) return true;
    }
    return patterns.some((pattern) => pattern.test(lower));
  };
}

/* ──────────────────────────────────────────────────────────── the runner ──── */

export async function runExposureScan(options: OrchestratorOptions): Promise<ExposureAssessment> {
  const {
    scanId,
    mode,
    target,
    profileId,
    engineIds,
    tenantId = null,
    userId = null,
    budgetMs = DEFAULT_SCAN_BUDGET_MS,
    concurrency = DEFAULT_CONCURRENCY,
    localOnly = mode === 'local',
    onEvent,
    credentials = {},
  } = options;

  const workspace = options.workspace ?? emptyWorkspace();
  const exclusions = options.exclusions ?? defaultExclusions();
  const isExcluded = compileExclusions(exclusions);
  const startedAt = new Date().toISOString();
  const deadline = Date.now() + budgetMs;

  let cancelled = false;
  const isCancelled = () => {
    if (cancelled) return true;
    if (options.isCancelled?.()) {
      cancelled = true;
      return true;
    }
    if (Date.now() > deadline) {
      cancelled = true;
      return true;
    }
    return false;
  };

  /* ── resolve engines and order them by dependency ─────────────────────── */
  const resolved = engineIds
    .map((id) => engineById(id))
    .filter((engine): engine is ExposureEngine => engine !== null);

  const ordered = topologicalOrder(resolved);

  const runs: EngineRun[] = ordered.map((engine) => ({
    engineId: engine.descriptor.id,
    label: engine.descriptor.label,
    state: 'pending',
    progress: 0,
    startedAt: null,
    completedAt: null,
    findingCount: 0,
  }));
  const runByEngine = new Map(runs.map((run) => [run.engineId, run]));

  const task: ScanTask = {
    scanId,
    tenantId,
    userId,
    mode,
    profileId,
    target,
    engines: ordered.map((engine) => engine.descriptor.id),
    status: 'initializing',
    createdAt: startedAt,
    startedAt,
    completedAt: null,
    runs,
    coverage: emptyCoverage(),
    scores: {
      securityRisk: null, quantumRisk: null, migrationRisk: null,
      coverage: null, confidence: null,
      securityBand: null, quantumBand: null, migrationBand: null,
      basis: [],
    },
    findingCount: 0,
    exclusions,
    localOnly,
  };
  task.coverage.exclusions = describeExclusions(exclusions);

  const emit = (event: Omit<ScanEvent, 'scanId' | 'timestamp'>) => {
    onEvent?.({ ...event, scanId, timestamp: new Date().toISOString() } as ScanEvent);
  };

  emit({ event: 'scan.created', message: `Scan ${scanId} created with ${ordered.length} engines.` });
  emit({ event: 'scan.started', message: `Assessment started in ${mode} mode.` });

  const findings: ExposureFinding[] = [];
  const findingIds = new Set<string>();
  workspace.meta.findings = findings;

  /* ── the dependency-respecting, bounded-concurrency scheduler ─────────── */
  const totalWeight = ordered.reduce((sum, engine) => sum + engine.descriptor.weight, 0) || 1;
  const settled = new Set<string>();
  const failures: string[] = [];

  const runEngine = async (engine: ExposureEngine): Promise<void> => {
    const descriptor = engine.descriptor;
    const run = runByEngine.get(descriptor.id)!;

    if (isCancelled()) {
      run.state = 'cancelled';
      run.detail = 'The operator cancelled the scan before this engine started.';
      run.completedAt = new Date().toISOString();
      settled.add(descriptor.id);
      return;
    }

    /* A dependency that did not complete does not silently skip the dependent:
       it is recorded as skipped WITH the reason, so the ledger explains itself. */
    const unmet = (descriptor.dependsOn ?? []).filter((dependency) => {
      const dependencyRun = runByEngine.get(dependency);
      return dependencyRun && dependencyRun.state !== 'completed' && dependencyRun.state !== 'not-applicable';
    });
    if (unmet.length > 0) {
      run.state = 'skipped';
      run.detail = `Skipped because ${unmet.join(', ')} did not complete.`;
      run.completedAt = new Date().toISOString();
      settled.add(descriptor.id);
      emit({ event: 'engine.completed', engineId: descriptor.id, engineLabel: descriptor.label, state: 'skipped', detail: run.detail, progress: overallProgress() });
      return;
    }

    const context: EngineContext = {
      scanId,
      mode,
      target,
      workspace,
      budgetMs: Math.min(options.engineBudgetMs ?? DEFAULT_ENGINE_BUDGET_MS, Math.max(1_000, deadline - Date.now())),
      isCancelled,
      report: (step, units) => {
        run.step = step;
        run.units = units;
        if (units && units.total > 0) {
          run.progress = Math.min(99, Math.round((units.done / units.total) * 100));
        }
        emit({
          event: 'engine.progress',
          engineId: descriptor.id,
          engineLabel: descriptor.label,
          state: 'running',
          step,
          units,
          progress: overallProgress(),
        });
      },
      emit: (finding) => {
        if (findingIds.has(finding.id)) return;
        findingIds.add(finding.id);
        findings.push(finding);
        run.findingCount += 1;
        emit({
          event: 'finding.discovered',
          engineId: descriptor.id,
          engineLabel: descriptor.label,
          severity: finding.severity,
          finding,
          message: finding.title,
          progress: overallProgress(),
        });
      },
      notAssessed: (dimension, reason) => {
        task.coverage = mergeCoverage(task.coverage, { notAssessed: [{ dimension, reason, engineId: descriptor.id }] });
        emit({ event: 'evidence.collected', engineId: descriptor.id, engineLabel: descriptor.label, detail: `Not assessed — ${dimension}: ${reason}` });
      },
      isExcluded,
      credential: credentialFor(descriptor.id, credentials),
    };

    /* ── applicability ─────────────────────────────────────────────────── */
    let applicable = true;
    let inapplicableReason = '';
    try {
      const verdict = engine.appliesTo(context);
      applicable = verdict.applicable;
      if (!verdict.applicable) inapplicableReason = verdict.reason ?? 'The engine reported nothing to do for this target.';
    } catch (error) {
      applicable = false;
      inapplicableReason = `Applicability check failed: ${(error as Error).message}`;
    }

    if (!applicable) {
      run.state = 'not-applicable';
      run.detail = inapplicableReason;
      run.progress = 100;
      run.completedAt = new Date().toISOString();
      settled.add(descriptor.id);
      emit({ event: 'engine.completed', engineId: descriptor.id, engineLabel: descriptor.label, state: 'not-applicable', detail: run.detail, progress: overallProgress() });
      return;
    }

    run.state = 'running';
    run.startedAt = new Date().toISOString();
    emit({ event: 'engine.started', engineId: descriptor.id, engineLabel: descriptor.label, state: 'running', progress: overallProgress() });

    /* ── execution, with a hard per-engine deadline ────────────────────── */
    let result: EngineResult;
    try {
      result = await withTimeout(
        engine.execute(context),
        context.budgetMs,
        `${descriptor.label} exceeded its ${Math.round(context.budgetMs / 1000)}s budget and was stopped. Findings it had already reported are retained.`,
      );
    } catch (error) {
      const message = (error as Error).message || 'The engine threw an unhandled error.';
      run.state = 'failed';
      run.detail = message;
      run.progress = 100;
      run.completedAt = new Date().toISOString();
      settled.add(descriptor.id);
      failures.push(`${descriptor.label}: ${message}`);
      emit({ event: 'engine.failed', engineId: descriptor.id, engineLabel: descriptor.label, state: 'failed', detail: message, progress: overallProgress() });
      return;
    }

    /* Engines emit as they go; anything returned but not emitted is folded in
       here so a batch-style engine is never lost. */
    for (const finding of result.findings) {
      if (findingIds.has(finding.id)) continue;
      findingIds.add(finding.id);
      findings.push(finding);
      run.findingCount += 1;
    }

    task.coverage = mergeCoverage(task.coverage, result.coverage);
    run.state = result.state;
    run.detail = result.detail;
    run.progress = 100;
    run.completedAt = new Date().toISOString();
    settled.add(descriptor.id);

    if (result.state === 'failed') failures.push(`${descriptor.label}: ${result.detail ?? 'failed'}`);

    emit({
      event: result.state === 'failed' ? 'engine.failed' : 'engine.completed',
      engineId: descriptor.id,
      engineLabel: descriptor.label,
      state: result.state,
      detail: result.detail,
      progress: overallProgress(),
      message: `${descriptor.label}: ${run.findingCount} finding${run.findingCount === 1 ? '' : 's'}`,
    });
  };

  /* Where the engine phase starts and ends on the operator's bar. Defaults to
     the whole thing, so every existing caller is unchanged. */
  const progressFrom = Math.max(0, Math.min(99, options.progressRange?.from ?? 0));
  const progressTo = Math.max(progressFrom, Math.min(99, options.progressRange?.to ?? 99));

  function overallProgress(): number {
    let earned = 0;
    for (const engine of ordered) {
      const run = runByEngine.get(engine.descriptor.id)!;
      const weight = engine.descriptor.weight;
      if (settled.has(engine.descriptor.id)) earned += weight;
      else if (run.state === 'running') earned += weight * (run.progress / 100);
    }
    const fraction = totalWeight > 0 ? earned / totalWeight : 0;
    return Math.min(progressTo, Math.round(progressFrom + fraction * (progressTo - progressFrom)));
  }

  /* ── dispatch in dependency waves, bounded by concurrency ─────────────── */
  task.status = 'discovering';
  const pending = [...ordered];

  while (pending.length > 0) {
    if (isCancelled()) break;

    const ready = pending.filter((engine) =>
      (engine.descriptor.dependsOn ?? []).every((dependency) => !runByEngine.has(dependency) || settled.has(dependency)),
    );

    /* A cycle or an unsatisfiable dependency would otherwise spin forever. If
       nothing is ready, run the head of the queue anyway — its dependency check
       inside `runEngine` will record the skip with a reason. */
    const wave = ready.length > 0 ? ready.slice(0, concurrency) : pending.slice(0, 1);

    task.status = wave.some((engine) => engine.descriptor.capability === 'discovery') ? 'discovering' : 'analyzing';

    await Promise.all(wave.map((engine) => runEngine(engine)));

    for (const engine of wave) {
      const index = pending.indexOf(engine);
      if (index >= 0) pending.splice(index, 1);
    }
  }

  /* Anything still pending after cancellation gets a terminal row. */
  for (const engine of pending) {
    const run = runByEngine.get(engine.descriptor.id)!;
    if (run.state !== 'pending') continue;
    run.state = 'cancelled';
    run.detail = cancelled ? 'The scan was cancelled or exceeded its budget before this engine ran.' : 'The engine was not reached.';
    run.completedAt = new Date().toISOString();
  }

  /* ── correlation ──────────────────────────────────────────────────────── */
  task.status = 'correlating';
  const exposures = correlateFindings(findings);
  emit({ event: 'correlation.completed', message: `${findings.length} findings correlated into ${exposures.length} exposures.` });

  /* ── CBOM (recomputed here so it is definitive even if the engine was not
        in the selected set) ─────────────────────────────────────────────── */
  /* Composed from findings AND inventory — the same union the CBOM engine
     reads — so selecting or deselecting that engine never changes the bill. */
  const inventory = inventoryObservations(workspace);
  const cbom = (workspace.meta.cbom as ReturnType<typeof buildCbom> | undefined) ?? buildCbom([...findings, ...inventory]);
  if (!workspace.meta.cbom) workspace.meta.cbom = cbom;

  /* ── scoring ──────────────────────────────────────────────────────────── */
  task.status = 'scoring';
  task.scores = computeScores({ findings, exposures, components: cbom, coverage: task.coverage, runs });
  task.findingCount = findings.length;
  task.coverage.cryptoComponents = cbom.length;
  emit({ event: 'scoring.completed', message: 'Risk decomposition complete.' });

  /* ── terminal status (§62) ────────────────────────────────────────────── */
  if (cancelled && findings.length === 0) {
    task.status = 'cancelled';
    task.failureReason = 'The scan was cancelled before any engine produced evidence.';
  } else if (cancelled) {
    task.status = 'partial';
    task.failureReason = 'The scan was cancelled or exceeded its time budget; the results below cover only the engines that completed.';
  } else if (failures.length > 0) {
    task.status = 'partial';
    task.failureReason = `${failures.length} engine${failures.length === 1 ? '' : 's'} did not complete: ${failures.join(' · ')} Scores are computed only from the engines that reported.`;
  } else if (task.coverage.notAssessed.length > 0) {
    /* Every engine came back, and part of the estate still went unread. The
       status used to be `completed` here, so the status bar showed a green
       "Assessment complete" directly above an Assessment Coverage panel listing
       the dimensions nothing reached and a completeness note reading "Absent
       evidence is not clean evidence" — the page contradicting itself, with the
       reassuring verdict in the largest type.

       A scan with a hole in it is partial however cleanly its engines exited
       (§64: never treat Not Scanned as Secure). `exposure-persistence` already
       records `partial` as a completed run, so this changes what the reader is
       told, not whether the assessment is kept. */
    task.status = 'partial';
    const dimensions = task.coverage.notAssessed.map((entry) => entry.dimension);
    task.failureReason =
      `Every selected engine completed, but ${dimensions.length} dimension${dimensions.length === 1 ? '' : 's'} could not be read: ${dimensions.join(' · ')}. ` +
      'Those dimensions are reported as unassessed, never as a passing control.';
  } else if (task.coverage.truncated) {
    /* The same rule, for the other shape of hole: an engine that hit its own
       budget stopped before reading its remit, so part of the scope went
       unexamined however cleanly every engine exited. Reported as `completed`,
       it put "Assessment complete" and a 100% coverage ring above a note
       saying 588 of 870 files were never read. */
    task.status = 'partial';
    task.failureReason =
      `Every selected engine completed, but a bounded budget stopped the work before the whole scope was read. ${task.coverage.truncationNote ?? ''} ` +
      'Counts below are a floor: the scope may hold more than was reached.';
  } else {
    task.status = 'completed';
  }
  task.completedAt = new Date().toISOString();

  const assessment: ExposureAssessment = {
    task,
    findings,
    exposures,
    cbom,
    inventory,
    intelligence: buildIntelligence({ findings, exposures, cbom, runs, workspace, coverage: task.coverage }),
    generatedAt: new Date().toISOString(),
    schemaVersion: 1,
  };

  emit({
    event: task.status === 'cancelled' ? 'scan.cancelled' : 'scan.completed',
    message: `Scan ${task.status}: ${findings.length} findings, ${exposures.length} correlated exposures, ${cbom.length} cryptographic components.`,
    result: assessment,
    progress: 100,
  });

  return assessment;
}

/* ────────────────────────────────────────────────────────────── helpers ──── */

function credentialFor(
  engineId: string,
  credentials: Partial<Record<EngineCredential['kind'], EngineCredential>>,
): EngineCredential | null {
  if (engineId.startsWith('cloud-')) return credentials.aws ?? credentials.azure ?? credentials.gcp ?? null;
  if (engineId === 'k8s-live') return credentials.kubeconfig ?? null;
  if (engineId === 'registry-scan') return credentials.registry ?? null;
  if (engineId === 'repository-discovery' || engineId === 'git-history') return credentials['git-token'] ?? null;
  return null;
}

/** Order engines so dependencies come first. Stable, and cycle-tolerant. */
export function topologicalOrder(engines: ExposureEngine[]): ExposureEngine[] {
  const byId = new Map(engines.map((engine) => [engine.descriptor.id, engine]));
  const visited = new Set<string>();
  const visiting = new Set<string>();
  const ordered: ExposureEngine[] = [];

  const visit = (engine: ExposureEngine) => {
    const id = engine.descriptor.id;
    if (visited.has(id)) return;
    // A cycle is a programming error, not a runtime condition. Breaking it here
    // keeps the scan running; the dependency check in `runEngine` then records
    // whichever engine lost the race as skipped, with its reason.
    if (visiting.has(id)) return;
    visiting.add(id);
    for (const dependency of engine.descriptor.dependsOn ?? []) {
      const next = byId.get(dependency);
      if (next) visit(next);
    }
    visiting.delete(id);
    visited.add(id);
    ordered.push(engine);
  };

  for (const engine of engines) visit(engine);
  return ordered;
}

function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function describeExclusions(exclusions: ScanExclusions): string[] {
  const out: string[] = [];
  if (exclusions.directories.length) out.push(`Directories excluded: ${exclusions.directories.join(', ')}`);
  if (exclusions.extensions.length) out.push(`Extensions excluded: ${exclusions.extensions.join(', ')}`);
  if (exclusions.patterns.length) out.push(`Patterns excluded: ${exclusions.patterns.join(', ')}`);
  if (exclusions.files.length) out.push(`Files excluded: ${exclusions.files.length} explicit path${exclusions.files.length === 1 ? '' : 's'}`);
  if (exclusions.dependencies.length) out.push(`Dependencies excluded: ${exclusions.dependencies.join(', ')}`);
  if (exclusions.secretRules.length) out.push(`Secret rules disabled: ${exclusions.secretRules.join(', ')}`);
  /* Only RULES belong here. "Binary files are discovered … but not
     content-analysed" used to be appended to every run, so the coverage basis
     counted it as an exclusion rule in force ("2 exclusion rules" for one) and
     the report tabled it as "Excluded by policy" although binary files are
     collected, not excluded. Binary files are counted as `filesUnsupported` and
     every surface states that figure where it is non-zero. */
  return out;
}

/* ──────────────────────────────────────────────────────── intelligence ───── */

export function buildIntelligence(input: {
  findings: ExposureFinding[];
  exposures: ReturnType<typeof correlateFindings>;
  cbom: ReturnType<typeof buildCbom>;
  runs: EngineRun[];
  workspace: ScanWorkspace;
  coverage: ScanCoverage;
}): ExposureIntelligence {
  const { findings, exposures, cbom, runs, workspace, coverage } = input;
  const cbomSummary = summariseCbom(cbom);

  const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) severity[finding.severity] += 1;

  const layerMap = new Map<string, { findings: number; critical: number; components: number }>();
  for (const finding of findings) {
    const entry = layerMap.get(finding.layer) ?? { findings: 0, critical: 0, components: 0 };
    entry.findings += 1;
    if (finding.severity === 'critical') entry.critical += 1;
    layerMap.set(finding.layer, entry);
  }
  for (const component of cbom) {
    const entry = layerMap.get(component.layer) ?? { findings: 0, critical: 0, components: 0 };
    entry.components += 1;
    layerMap.set(component.layer, entry);
  }

  const secrets = findings
    .filter((finding) => finding.layer === 'secret')
    .map((finding) => ({
      type: finding.subcategory ?? 'Credential',
      location: finding.evidence[0]?.file ?? finding.evidence[0]?.reference ?? 'unknown',
      severity: finding.severity,
      confidence: finding.confidence,
      value: '[REDACTED]' as const,
      historical: Boolean(finding.evidence[0]?.attributes?.historical),
    }));

  /* The panel shows the top of the ONE ranked list; `recommendationCandidates`
     is its full length, the denominator the truncation note prints. The report
     reads the same function for its complete register. */
  const ranked = rankRecommendations({ findings, exposures });
  const recommendationCandidates = ranked.length;

  const facts: Array<{ label: string; value: string; detail?: string }> = [];
  const meta = workspace.meta as Record<string, any>;
  if (meta.repository) {
    facts.push({ label: 'Repository', value: String(meta.repository.fullName ?? ''), detail: meta.repository.provider });
    if (meta.repository.defaultBranch) facts.push({ label: 'Branch', value: String(meta.repository.branch ?? meta.repository.defaultBranch) });
    if (meta.repository.visibility) facts.push({ label: 'Visibility', value: String(meta.repository.visibility) });
  }
  if (meta.git) {
    if (meta.git.head) facts.push({ label: 'HEAD', value: String(meta.git.head) });
    if (Array.isArray(meta.git.branches)) facts.push({ label: 'Branches', value: String(meta.git.branches.length) });
  }
  facts.push({ label: 'Files analysed', value: `${coverage.filesAnalyzed} of ${coverage.filesDiscovered}` });
  if (coverage.filesUnsupported) facts.push({ label: 'Binary / unsupported', value: String(coverage.filesUnsupported) });
  if (Array.isArray(meta.images) && meta.images.length) facts.push({ label: 'Container images', value: String(meta.images.length) });
  if (Array.isArray(meta.workloads) && meta.workloads.length) facts.push({ label: 'Kubernetes workloads', value: String(meta.workloads.length) });
  if (Array.isArray(meta.platforms) && meta.platforms.length) facts.push({ label: 'CI platforms', value: meta.platforms.join(', ') });

  return {
    quantum: {
      vulnerable: cbomSummary.vulnerable,
      hybrid: cbomSummary.hybrid,
      pqc: cbomSummary.pqc,
      resistant: cbomSummary.resistant,
      unknown: cbomSummary.unknown,
      notApplicable: cbomSummary.notApplicable,
      readiness: cbomSummary.readiness,
    },
    severity,
    byLayer: [...layerMap.entries()]
      .map(([layer, entry]) => ({ layer: layer as ExposureFinding['layer'], ...entry }))
      .sort((a, b) => b.findings - a.findings),
    byEngine: runs.map((run) => ({ engineId: run.engineId, label: run.label, findings: run.findingCount, state: run.state })),
    topAlgorithms: cbomSummary.byAlgorithm.slice(0, 12),
    /* The denominator the "Algorithms observed" chip row needs. The chips stop
       at twelve groups; on a real scan that is 12 of 19, covering 487 of 515
       components, and with no denominator a reader sums the chips and gets a
       component total that contradicts the CBOM panel directly above it. */
    algorithmGroups: cbomSummary.byAlgorithm.length,
    languages: (meta.languages as Array<{ language: string; files: number }> | undefined) ?? [],
    frameworks: (meta.frameworks as string[] | undefined) ?? [],
    dependencies: (meta.dependencies as ExposureIntelligence['dependencies'] | undefined) ?? [],
    secrets,
    facts,
    recommendations: ranked.slice(0, RECOMMENDATION_LIMIT),
    recommendationCandidates,
  };
}

