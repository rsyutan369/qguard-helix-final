/**
 * Exposure Assessment History — tenant-scoped reads for /api/v1/exposure/history.
 *
 * The History tab on `/dashboard/scanner?mode=local` and `?mode=dev` reads only
 * from here. Three properties matter and each is enforced in this file rather
 * than left to the caller:
 *
 *  • **Tenant isolation.** Every query runs under the caller's own token
 *    (RLS-scoped) AND carries an explicit `user_id` predicate. Belt and braces:
 *    a policy regression must not become a cross-tenant disclosure.
 *
 *  • **A failed query is never an empty result.** PostgREST answers a missing
 *    column with a 42703 error, and the platform has shipped a defect before
 *    where that was swallowed and 31 certificates rendered as 0. Here a query
 *    error propagates and the route reports it — an empty History tab must mean
 *    "nothing recorded", never "the read failed".
 *
 *  • **It scales.** The list is one bounded session query plus two aggregate
 *    passes over the rows those sessions own; detail is fetched per scan. Both
 *    sit behind a short single-flight cache keyed by tenant and mode, the same
 *    pattern `buildScannerIntelligence` uses, so several open dashboards and
 *    SSE ticks share one computation.
 */

import type { SupabaseClient } from '@supabase/supabase-js';
import { EventEmitter } from 'node:events';
import {
  buildHistoryEntry,
  historyFingerprint,
  restoreAssessment,
  restoreComponent,
  restoreFinding,
  scannerModeFor,
  summariseHistory,
  type ExposureHistoryEntry,
  type ExposureHistoryMode,
  type ExposureHistorySummary,
  type FindingRow,
  type InventoryRow,
  type RestoredAssessment,
  type SessionRow,
} from '@/lib/scanner/exposure/history';
import { correlateFindings } from '@/lib/scanner/exposure/correlate';
import { listJobs } from '@/lib/scanner/exposure/dev/run-dev-scan';
import { TERMINAL_TASK_STATUSES } from '@/lib/scanner/exposure/types';

/* ─────────────────────────────────────────────────────────────── budgets ──── */

/**
 * How many recorded assessments the list covers.
 *
 * Bounded because this is a dashboard read, not an archive export. The response
 * declares `total` alongside `entries` so the UI can say "showing the most
 * recent 100 of 340" rather than silently presenting a prefix as the whole
 * history — silent truncation is a disclosed defect class on this platform.
 */
export const HISTORY_PAGE_MAX = 100;

/** Rows pulled per session-scoped child query. Findings are capped on write at 2 000. */
const CHILD_ROW_MAX = 6_000;

const CACHE_TTL_MS = 15_000;

/* ────────────────────────────────────────────────────────────── the shape ─── */

export interface ExposureHistoryPayload {
  mode: ExposureHistoryMode;
  entries: ExposureHistoryEntry[];
  summary: ExposureHistorySummary;
  /** Recorded assessments that exist for this tenant and mode, before the page cap. */
  total: number;
  truncated: boolean;
  generatedAt: string;
  /** Everything the tab must disclose about what it is showing. */
  notes: string[];
}

export interface ExposureHistoryDetailPayload extends RestoredAssessment {
  entry: ExposureHistoryEntry;
}

/* ───────────────────────────────────────────────────────── change signalling ─ */

/**
 * In-process change signal for the History SSE stream.
 *
 * A sync and the stream that must reflect it run in the same Node process, so
 * the stream is pushed the moment a record is written instead of discovering it
 * on the next poll. The poll remains as the safety net for anything that writes
 * outside this process.
 */
const changes = new EventEmitter();
changes.setMaxListeners(0);

export function onHistoryChanged(listener: (userId: string) => void): () => void {
  changes.on('changed', listener);
  return () => {
    changes.off('changed', listener);
  };
}

/** Called after any write that a History view would show. */
export function notifyHistoryChanged(userId: string): void {
  invalidateHistory(userId);
  changes.emit('changed', userId);
}

/* ──────────────────────────────────────────────────────────────── caching ─── */

const listCache = new Map<string, { at: number; promise: Promise<ExposureHistoryPayload> }>();

function cacheKey(userId: string, mode: ExposureHistoryMode): string {
  return `${userId}:${mode}`;
}

export function invalidateHistory(userId: string): void {
  for (const key of [...listCache.keys()]) {
    if (key.startsWith(`${userId}:`)) listCache.delete(key);
  }
}

/* ─────────────────────────────────────────────────────────────── db access ── */

class HistoryQueryError extends Error {
  constructor(readonly table: string, message: string) {
    super(`The ${table} query failed: ${message}`);
    this.name = 'HistoryQueryError';
  }
}

/**
 * The recorded sessions for one tenant and one exposure mode.
 *
 * Filtered in the database on the `scannerMode` marker, so a Web scanner
 * session can never appear in a Local or Dev history — and a Local one can
 * never appear under Dev.
 */
async function selectSessions(
  client: SupabaseClient,
  userId: string,
  mode: ExposureHistoryMode,
): Promise<{ rows: SessionRow[]; total: number }> {
  const marker = scannerModeFor(mode);
  const { data, error, count } = await client
    .from('pqc_scan_sessions')
    .select('id,user_id,status,target_scope,findings_count,metadata,started_at,completed_at,created_at,updated_at', {
      count: 'exact',
    })
    .eq('user_id', userId)
    .eq('metadata->>scannerMode', marker)
    .order('started_at', { ascending: false })
    .limit(HISTORY_PAGE_MAX);

  if (error) throw new HistoryQueryError('scan session', error.message);
  const rows = (data ?? []) as unknown as SessionRow[];
  return { rows, total: typeof count === 'number' ? count : rows.length };
}

/** Findings belonging to a known set of sessions. */
async function selectFindings(
  client: SupabaseClient,
  userId: string,
  sessionIds: string[],
): Promise<FindingRow[]> {
  if (sessionIds.length === 0) return [];
  const { data, error } = await client
    .from('pqc_scan_results')
    .select('id,scan_session_id,asset_id,finding_type,algorithm,threat_level,description,remediation,metadata,created_at')
    .eq('user_id', userId)
    .in('scan_session_id', sessionIds)
    .limit(CHILD_ROW_MAX);

  if (error) throw new HistoryQueryError('scan result', error.message);
  return (data ?? []) as FindingRow[];
}

/**
 * Components belonging to a known set of sessions.
 *
 * `crypto_inventory` has no session column — the link lives in
 * `metadata.scanSessionId` — so the rows are filtered in the database on that
 * key rather than pulled wholesale and matched in memory. On a tenant with a
 * large inventory the difference is the whole table versus one scan's rows.
 */
async function selectComponents(
  client: SupabaseClient,
  userId: string,
  sessionIds: string[],
): Promise<InventoryRow[]> {
  if (sessionIds.length === 0) return [];

  const out: InventoryRow[] = [];
  /* PostgREST has no `in` for a JSON path, so sessions are queried in small
     OR-batches. The batch is bounded to keep the URL well inside proxy limits. */
  const BATCH = 20;
  for (let index = 0; index < sessionIds.length; index += BATCH) {
    const batch = sessionIds.slice(index, index + BATCH);
    const filter = batch.map((id) => `metadata->>scanSessionId.eq.${id}`).join(',');
    const { data, error } = await client
      .from('crypto_inventory')
      .select('id,asset_id,item_type,name,algorithm,key_size,protocol,exposure_level,is_vulnerable,is_quantum_safe,metadata,discovered_at')
      .eq('user_id', userId)
      .or(filter)
      .limit(CHILD_ROW_MAX);

    if (error) throw new HistoryQueryError('crypto inventory', error.message);
    out.push(...((data ?? []) as InventoryRow[]));
  }
  return out;
}

function sessionIdOf(row: InventoryRow | FindingRow): string | null {
  const metadata = (row.metadata ?? {}) as Record<string, unknown>;
  const fromMetadata = metadata.scanSessionId;
  if (typeof fromMetadata === 'string') return fromMetadata;
  const direct = (row as FindingRow).scan_session_id;
  return typeof direct === 'string' ? direct : null;
}

/* ───────────────────────────────────────────────── in-flight (unrecorded) ─── */

/**
 * Dev scans this API process is holding that were never recorded.
 *
 * These are REAL scans — the operator started them, the server ran them — but
 * they live only in the job store and vanish when it sweeps them. Showing them
 * as `origin: 'session'` is the honest position: the tab would otherwise look
 * empty right after a scan finished, and a user would reasonably conclude the
 * scan had not happened.
 */
function sessionScopedDevEntries(userId: string, recordedSourceIds: Set<string>): ExposureHistoryEntry[] {
  return listJobs(userId)
    /* Matched on the ENGINE's scan id, not the record's row id — those are
       different values, and comparing them would never match, so every scan
       already saved to the platform would keep appearing a second time as an
       unrecorded one until the job store swept it an hour later. */
    .filter((job) => !recordedSourceIds.has(job.scanId))
    .map((job) => {
      const assessment = job.assessment ?? null;
      const findings = assessment?.findings ?? [];
      const components = assessment?.cbom ?? [];
      const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const finding of findings) severity[finding.severity] += 1;
      /* The job store keeps no progress field — progress is carried on the
         event stream — so it is read back from the last frame that reported
         one. Never a timer: a bar that moves without work behind it is the
         defect this platform's scan telemetry rules exist to prevent. */
      const running = !TERMINAL_TASK_STATUSES.includes(job.status);
      const lastProgress = [...job.events].reverse().find((event) => typeof event.progress === 'number')?.progress;
      const coverage = assessment?.task.coverage ?? null;

      return {
        scanId: job.scanId,
        sourceScanId: job.scanId,
        mode: 'dev' as const,
        origin: 'session' as const,
        target: describeJobTarget(job.target),
        targetKind: job.target?.kind ?? 'unknown',
        profileId: job.profileId,
        engines: assessment?.task.engines ?? [],
        status: assessment?.task.status ?? job.status,
        sessionStatus: job.status,
        startedAt: new Date(job.createdAt).toISOString(),
        completedAt: assessment?.task.completedAt ?? null,
        recordedAt: null,
        durationMs: assessment?.task.completedAt
          ? Date.parse(assessment.task.completedAt) - job.createdAt
          : null,
        findingCount: findings.length,
        severity,
        componentCount: components.length,
        quantumVulnerableComponents: assessment?.intelligence.quantum.vulnerable ?? 0,
        quantumReadiness: assessment?.intelligence.quantum.readiness ?? null,
        exposureCount: assessment?.exposures.length ?? 0,
        scores: assessment?.task.scores ?? null,
        coverage: {
          analyzed: coverage?.filesAnalyzed ?? 0,
          discovered: coverage?.filesDiscovered ?? 0,
          percent: coverage && coverage.filesDiscovered > 0
            ? Math.round((coverage.filesAnalyzed / coverage.filesDiscovered) * 1000) / 10
            : null,
          notAssessed: coverage?.notAssessed.length ?? 0,
        },
        engineRuns: (assessment?.task.runs ?? []).map((run) => ({
          engineId: run.engineId,
          label: run.label,
          state: run.state,
          findingCount: run.findingCount,
          detail: run.detail,
        })),
        localOnly: false,
        truncated: false,
        recordVersion: 0,
        live: {
          progress: running ? Math.max(0, Math.min(100, Math.round(lastProgress ?? 0))) : 100,
          running,
          note: running
            ? 'Running in this session. It will be added to the recorded history when you save it to the platform.'
            : 'Held in this API session only. Save it to the platform to keep it in the recorded history.',
        },
      } satisfies ExposureHistoryEntry;
    })
    .sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt));
}

function describeJobTarget(target: unknown): string {
  const value = (target ?? {}) as Record<string, unknown>;
  switch (value.kind) {
    case 'repository': return `${value.provider}:${value.owner}/${value.repo}`;
    case 'kubernetes': return `k8s:${value.cluster}`;
    case 'cloud': return `${value.provider}:${value.account}`;
    case 'container': return `image:${value.image}`;
    case 'local': return `local:${value.rootName ?? value.label}`;
    default: return 'assessment';
  }
}

/* ──────────────────────────────────────────────────────────────── the list ── */

async function computeHistory(
  client: SupabaseClient,
  userId: string,
  mode: ExposureHistoryMode,
): Promise<ExposureHistoryPayload> {
  const { rows: sessions, total } = await selectSessions(client, userId, mode);
  const sessionIds = sessions.map((session) => session.id);

  const [findingRows, inventoryRows] = await Promise.all([
    selectFindings(client, userId, sessionIds),
    selectComponents(client, userId, sessionIds),
  ]);

  const findingsBySession = new Map<string, FindingRow[]>();
  for (const row of findingRows) {
    const id = sessionIdOf(row);
    if (!id) continue;
    const bucket = findingsBySession.get(id);
    if (bucket) bucket.push(row);
    else findingsBySession.set(id, [row]);
  }

  const componentsBySession = new Map<string, InventoryRow[]>();
  for (const row of inventoryRows) {
    const id = sessionIdOf(row);
    if (!id) continue;
    const bucket = componentsBySession.get(id);
    if (bucket) bucket.push(row);
    else componentsBySession.set(id, [row]);
  }

  const entries: ExposureHistoryEntry[] = sessions.map((session) => {
    const findings = (findingsBySession.get(session.id) ?? [])
      .map((row) => restoreFinding(row, { scanId: session.id, mode }))
      .filter((finding): finding is NonNullable<typeof finding> => finding !== null);
    const components = (componentsBySession.get(session.id) ?? [])
      .map((row) => restoreComponent(row))
      .filter((component): component is NonNullable<typeof component> => component !== null);

    return buildHistoryEntry({
      session,
      mode,
      findings,
      components,
      /* Correlation is a pure function of the findings, so the list can state
         the exposure count without opening the detail view — and it will be the
         same number the detail view shows. */
      exposureCount: correlateFindings(findings).length,
    });
  });

  /* A record written before `sourceScanId` was retained cannot be matched to a
     job, so a v1 record plus a still-held job would show both rows. That is the
     honest failure: two rows the operator can tell apart (one "recorded", one
     "session only") beats hiding a real record behind a guess. */
  const recordedSourceIds = new Set(
    entries.map((entry) => entry.sourceScanId).filter((id): id is string => typeof id === 'string'),
  );
  const live = mode === 'dev' ? sessionScopedDevEntries(userId, recordedSourceIds) : [];
  const all = [...live, ...entries];

  const notes: string[] = [];
  if (total > entries.length) {
    notes.push(
      `Showing the ${entries.length} most recent of ${total} recorded assessments. Older assessments remain in the inventory and are reachable from Assets and CBOM.`,
    );
  }
  if (mode === 'local') {
    notes.push(
      'Local assessments run entirely in your browser and are recorded here only when you save one to the platform. An assessment you have not saved is held on your device and is not in this list.',
    );
  } else {
    notes.push(
      'Development assessments run on the platform. Until one is saved, it is held in this API session only and is shown as session-only below.',
    );
  }

  return {
    mode,
    entries: all,
    summary: summariseHistory(all),
    total,
    truncated: total > entries.length,
    generatedAt: new Date().toISOString(),
    notes,
  };
}

/** The tenant's history for one mode, single-flight cached for 15s. */
export function loadExposureHistory(
  client: SupabaseClient,
  userId: string,
  mode: ExposureHistoryMode,
  options: { fresh?: boolean } = {},
): Promise<ExposureHistoryPayload> {
  const key = cacheKey(userId, mode);
  const cached = listCache.get(key);

  /* A running Dev job changes the payload every few seconds, so the cache is
     bypassed while one exists — the same rule the scanner intelligence cache
     applies during a live scan. */
  const hasLiveJob = mode === 'dev' && listJobs(userId).some((job) => !TERMINAL_TASK_STATUSES.includes(job.status));

  if (!options.fresh && !hasLiveJob && cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.promise;

  const promise = computeHistory(client, userId, mode);
  listCache.set(key, { at: Date.now(), promise });
  promise.catch(() => listCache.delete(key));

  if (listCache.size > 500) {
    const now = Date.now();
    for (const [existing, value] of listCache) if (now - value.at > CACHE_TTL_MS) listCache.delete(existing);
  }
  return promise;
}

export { historyFingerprint };

/* ────────────────────────────────────────────────────────────── the detail ── */

/**
 * One recorded assessment, rebuilt in full.
 *
 * Returns null when the scan does not exist FOR THIS TENANT AND MODE — the same
 * answer either way, so the endpoint cannot be used to probe which scan ids
 * exist on another account.
 */
export async function loadExposureHistoryDetail(
  client: SupabaseClient,
  userId: string,
  mode: ExposureHistoryMode,
  scanId: string,
): Promise<ExposureHistoryDetailPayload | null> {
  const { data, error } = await client
    .from('pqc_scan_sessions')
    .select('id,user_id,status,target_scope,findings_count,metadata,started_at,completed_at,created_at,updated_at')
    .eq('user_id', userId)
    .eq('id', scanId)
    .eq('metadata->>scannerMode', scannerModeFor(mode))
    .maybeSingle();

  if (error) throw new HistoryQueryError('scan session', error.message);
  if (!data) return null;

  const session = data as SessionRow;
  const [findingRows, inventoryRows] = await Promise.all([
    selectFindings(client, userId, [session.id]),
    selectComponents(client, userId, [session.id]),
  ]);

  const restored = restoreAssessment({ session, mode, findingRows, inventoryRows });
  const entry = buildHistoryEntry({
    session,
    mode,
    findings: restored.assessment.findings,
    components: restored.assessment.cbom,
    exposureCount: restored.assessment.exposures.length,
  });

  return { ...restored, entry };
}

/* ──────────────────────────────────────────────────────────────── deletion ── */

export interface HistoryDeletionResult {
  scanId: string;
  findings: number;
  components: number;
  exposures: number;
}

/**
 * Delete one recorded assessment and everything it wrote.
 *
 * Children first, then the session: if the session row went first, its
 * `ON DELETE CASCADE` would take the findings but leave the `crypto_inventory`
 * and `crypto_exposures` rows — which have no foreign key to it — orphaned in
 * the tenant's CBOM, where every other dashboard would keep counting them.
 *
 * Scoped by `user_id` AND by the assessment's own session marker on every
 * statement, so this cannot reach another tenant's rows or another scan's.
 */
export async function deleteExposureHistoryEntry(
  client: SupabaseClient,
  userId: string,
  mode: ExposureHistoryMode,
  scanId: string,
): Promise<HistoryDeletionResult | null> {
  const { data: session, error: lookupError } = await client
    .from('pqc_scan_sessions')
    .select('id')
    .eq('user_id', userId)
    .eq('id', scanId)
    .eq('metadata->>scannerMode', scannerModeFor(mode))
    .maybeSingle();

  if (lookupError) throw new HistoryQueryError('scan session', lookupError.message);
  if (!session) return null;

  const inventory = await client
    .from('crypto_inventory')
    .delete()
    .eq('user_id', userId)
    .eq('metadata->>scanSessionId', scanId)
    .select('id');
  if (inventory.error) throw new HistoryQueryError('crypto inventory', inventory.error.message);

  const exposures = await client
    .from('crypto_exposures')
    .delete()
    .eq('user_id', userId)
    .eq('metadata->>scanSessionId', scanId)
    .select('id');
  if (exposures.error) throw new HistoryQueryError('crypto exposure', exposures.error.message);

  const results = await client
    .from('pqc_scan_results')
    .delete()
    .eq('user_id', userId)
    .eq('scan_session_id', scanId)
    .select('id');
  if (results.error) throw new HistoryQueryError('scan result', results.error.message);

  const removed = await client
    .from('pqc_scan_sessions')
    .delete()
    .eq('user_id', userId)
    .eq('id', scanId)
    .select('id');
  if (removed.error) throw new HistoryQueryError('scan session', removed.error.message);

  notifyHistoryChanged(userId);

  return {
    scanId,
    findings: results.data?.length ?? 0,
    components: inventory.data?.length ?? 0,
    exposures: exposures.data?.length ?? 0,
  };
}

export { HistoryQueryError };
