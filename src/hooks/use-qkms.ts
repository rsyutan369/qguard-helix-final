'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type {
  AuditEvidenceRecord,
  DistributionRow,
  EntropyPosture,
  GovernanceViolation,
  KeyIndexEntry,
  KeyPqcPosture,
  LifecycleState,
  ManagedKey,
  MigrationGate,
  MigrationRequirement,
  PqcReadiness,
  QkmsMetrics,
  QkmsMode,
  QkmsPolicy,
  QkmsTelemetryHealth,
  RotationJob,
  RotationJobStatus,
  RotationPosture,
  RotationState,
  StorageBackendPosture,
} from '@/lib/qkms/types';

export type LoadState = 'loading' | 'success' | 'error';

/* ------------------------------------------------------------------ */
/* Payload shapes — mirror projectView() in src/api-server/qkms-dashboard.ts */
/* ------------------------------------------------------------------ */

export interface QkmsCommonPayload {
  mode: QkmsMode;
  generatedAt: string;
  latestEvidenceAt: string | null;
  hasData: boolean;
  metrics: QkmsMetrics;
  telemetry: QkmsTelemetryHealth;
  gate: MigrationGate;
  nav: {
    keys: number;
    violations: number;
    rotationQueue: number;
    criticalRisk: number;
    migrationRequired: number;
  };
}

export interface QkmsDistributions {
  algorithms: DistributionRow[];
  families: DistributionRow[];
  keyClasses: DistributionRow[];
  owners: DistributionRow[];
  environments: DistributionRow[];
  custody: DistributionRow[];
  postures: DistributionRow[];
}

export interface QkmsFacets {
  types: Array<{ value: string; count: number }>;
  algorithms: Array<{ value: string; count: number }>;
  families: Array<{ value: string; count: number }>;
  owners: Array<{ value: string; count: number }>;
  assets: Array<{ value: string; count: number }>;
  environments: Array<{ value: string; count: number }>;
  backends: Array<{ value: string; count: number }>;
  postures: Array<{ value: string; count: number }>;
  lifecycles: Array<{ value: string; count: number }>;
  rotations: Array<{ value: string; count: number }>;
  riskLevels: Array<{ value: string; count: number }>;
  requirements: Array<{ value: string; count: number }>;
}

export interface OverviewPayload extends QkmsCommonPayload {
  mode: 'overview';
  lifecycleFunnel: Array<{ state: LifecycleState; label: string; count: number; percent: number; keyIds: string[] }>;
  rotationPosture: RotationPosture;
  readiness: Pick<PqcReadiness, 'overall' | 'verifiedReady' | 'declaredOnly' | 'decisionScope' | 'bands' | 'postureCounts'>;
  riskDistribution: DistributionRow[];
  distributions: QkmsDistributions;
  topRisks: KeyIndexEntry[];
  topViolations: GovernanceViolation[];
  entropy: EntropyPosture;
  attention: { expired: number; expiringSoon: number; overdueRotation: number; orphaned: number };
  recentAudit: AuditEvidenceRecord[];
}

export interface InventoryPayload extends QkmsCommonPayload {
  mode: 'inventory';
  facets: QkmsFacets;
  keys: KeyIndexEntry[];
  total: number;
  distributions: QkmsDistributions;
}

export interface LifecyclePayload extends QkmsCommonPayload {
  mode: 'lifecycle';
  counts: Record<LifecycleState, number>;
  funnel: Array<{ state: LifecycleState; label: string; count: number; percent: number; keyIds: string[] }>;
  ageBuckets: DistributionRow[];
  expiryBuckets: DistributionRow[];
  attentionCounts: Record<'expired' | 'expiringSoon' | 'overdueRotation' | 'neverRotated' | 'longLived' | 'orphaned' | 'unused', number>;
  attention: Record<'expired' | 'expiringSoon' | 'overdueRotation' | 'neverRotated' | 'longLived' | 'orphaned', KeyIndexEntry[]>;
  keyTypes: DistributionRow[];
  facets: QkmsFacets;
}

export interface GovernancePayload extends QkmsCommonPayload {
  mode: 'governance';
  policies: QkmsPolicy[];
  violations: GovernanceViolation[];
  violationsTotal: number;
  violationsByRule: DistributionRow[];
  violationsBySeverity: DistributionRow[];
  backends: StorageBackendPosture[];
  entropy: EntropyPosture;
  audit: AuditEvidenceRecord[];
  custodyDistribution: DistributionRow[];
}

export interface RotationPayload extends QkmsCommonPayload {
  mode: 'rotation';
  posture: RotationPosture;
  stateCounts: Record<RotationState, number>;
  jobs: RotationJob[];
  jobsTotal: number;
  queue: KeyIndexEntry[];
  queueTotal: number;
  nextDueAt: string | null;
}

export interface ReadinessPayload extends QkmsCommonPayload {
  mode: 'readiness';
  readiness: PqcReadiness;
  migrationRequired: KeyIndexEntry[];
  migrationRequiredTotal: number;
  audit: AuditEvidenceRecord[];
  distributions: { postures: DistributionRow[]; families: DistributionRow[] };
}

export interface RiskPayload extends QkmsCommonPayload {
  mode: 'risk-analysis';
  distribution: DistributionRow[];
  factorAverages: Array<{ key: string; label: string; weight: number; average: number; measuredKeys: number }>;
  topRisks: KeyIndexEntry[];
  remediation: Array<{ keyId: string; keyLabel: string; action: string; score: number; level: string; rationale: string }>;
  violationsBySeverity: DistributionRow[];
  distributions: { families: DistributionRow[]; postures: DistributionRow[]; custody: DistributionRow[] };
  facets: QkmsFacets;
}

export type QkmsPayload =
  | OverviewPayload
  | InventoryPayload
  | LifecyclePayload
  | GovernancePayload
  | RotationPayload
  | ReadinessPayload
  | RiskPayload;

export interface KeyDetail {
  key: ManagedKey;
  violations: GovernanceViolation[];
  rotationJobs: RotationJob[];
  audit: AuditEvidenceRecord[];
  policies: QkmsPolicy[];
  relatedKeys: KeyIndexEntry[];
}

export interface KeyPage {
  keys: KeyIndexEntry[];
  total: number;
  limit: number;
  offset: number;
  facets?: QkmsFacets;
  generatedAt: string;
}

/* ------------------------------------------------------------------ */
/* Wiring                                                              */
/* ------------------------------------------------------------------ */

const API_BASE = '/api/v1/dashboard/qkms';

/**
 * Tables whose mutation can change what any QKMS page shows.
 *
 * Deliberately the union across all seven views: a certificate write changes
 * the Inventory's key list AND the Readiness gate AND the Risk table, so
 * nudging only one page would let the others drift until the next 10s push —
 * which is exactly the disagreement this refactor exists to remove.
 */
const REALTIME_TABLES = [
  'qkms_keys',
  'qkms_key_versions',
  'qkms_policies',
  'qkms_rotation_jobs',
  'qkms_audit_events',
  'qkms_storage_backends',
  'generated_keys',
  'crypto_inventory',
  'certificates',
  'runtime_crypto_events',
  'scanner_evidence',
  'migration_jobs',
  'qrng_events',
  'assets',
] as const;


const RETRY_MIN_MS = 3_000;
const RETRY_MAX_MS = 30_000;

export interface UseQkmsResult<T extends QkmsPayload> {
  data: T | null;
  state: LoadState;
  error: string | null;
  /** True only while the stream is genuinely open. Never "live" on stale data. */
  live: boolean;
  lastSyncedAt: string | null;
  /** When the server last confirmed this view — moves on unchanged rebuilds too. */
  verifiedAt: string | null;
  refresh: (force?: boolean) => Promise<void>;
  reconnect: () => void;
}

/**
 * useQkmsView — the shared data contract for the seven QKMS pages.
 *
 * Three cooperating channels:
 *   1. fetch()            authoritative first paint and every manual refresh.
 *   2. SSE                the live push, over fetch + ReadableStream with an
 *                         Authorization HEADER. EventSource cannot set headers,
 *                         which forces the bearer token into the query string
 *                         where it leaks into access logs and history — the
 *                         predecessor opened four such connections per page.
 *   3. Supabase realtime  a debounced nudge when the tenant's own rows change,
 *                         so an agent write lands without waiting for the push.
 *
 * The stream carries the WHOLE view payload and the page swaps state atomically,
 * so the KPI strip, the charts and the tables can never render a half-applied
 * update.
 */
export function useQkmsView<T extends QkmsPayload>(mode: QkmsMode): UseQkmsResult<T> {
  const { session, user } = useAuth();
  const token = session?.access_token;

  const [data, setData] = useState<T | null>(null);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);
  /** Last time the server re-built the model and confirmed this view unchanged. */
  const [verifiedAt, setVerifiedAt] = useState<string | null>(null);

  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** Guards against an out-of-order frame overwriting newer state. */
  const lastGeneratedRef = useRef<number>(0);

  const apply = useCallback((next: T) => {
    const generated = Date.parse(next.generatedAt || '');
    if (Number.isFinite(generated)) {
      if (generated < lastGeneratedRef.current) return;
      lastGeneratedRef.current = generated;
    }
    setData(next);
    setState('success');
    setError(null);
    setVerifiedAt(next.generatedAt);
    setLastSyncedAt(new Date().toISOString());
  }, []);

  const refresh = useCallback(
    async (force = false) => {
      if (!token) {
        // No session is not an empty estate: rendering "no keys" here would
        // read as a verified zero.
        setError('Sign in to view QKMS intelligence.');
        setState('error');
        return;
      }
      setState((current) => (current === 'success' ? current : 'loading'));
      try {
        const response = await fetch(`${API_BASE}/${mode}${force ? '?refresh=1' : ''}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!payload?.data) throw new Error('QKMS response was empty');
        apply(payload.data as T);
      } catch (err) {
        console.error(`QKMS ${mode} load failed:`, err);
        setError(err instanceof Error ? err.message : 'Unable to load QKMS intelligence');
        // Keep the last good model on screen; the header switches to a
        // disconnected state so nothing reads as live.
        setState((current) => (current === 'success' ? current : 'error'));
      }
    },
    [token, mode, apply],
  );

  const queueRefresh = useCallback(() => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null;
      void refresh(true);
    }, 700);
  }, [refresh]);

  useEffect(
    () => () => {
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
    },
    [],
  );

  useEffect(() => {
    void refresh();
  }, [token, user, refresh]);

  /* ---- SSE: header-authenticated, exponential backoff ------------- */
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    let retry: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let cancelled = false;

    const parseFrame = (frame: string) => {
      let eventName = 'message';
      const dataLines: string[] = [];
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) eventName = line.slice(6).trim();
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''));
        // ':' comment lines are heartbeats — ignored.
      }
      if (!dataLines.length) return;
      const body = dataLines.join('\n');
      if (eventName === 'qkms') {
        try {
          const parsed = JSON.parse(body) as T;
          // Event validation: a frame for another view must never be applied.
          if (parsed && typeof parsed === 'object' && parsed.mode === mode) apply(parsed);
        } catch {
          /* malformed frame — ignore rather than blank the page */
        }
      } else if (eventName === 'qkms-verified') {
        // The model was rebuilt and nothing on this view changed: record when
        // it was last confirmed, without replacing data (and re-querying tables).
        try {
          const parsed = JSON.parse(body) as { mode?: string; generatedAt?: string };
          if (parsed.mode === mode && parsed.generatedAt) setVerifiedAt(parsed.generatedAt);
        } catch {
          /* ignore */
        }
      } else if (eventName === 'qkms-error') {
        try {
          setError(String(JSON.parse(body)?.message || 'QKMS stream error'));
        } catch {
          /* ignore */
        }
      }
    };

    const connect = async () => {
      try {
        const response = await fetch(`${API_BASE}/stream?mode=${encodeURIComponent(mode)}`, {
          headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`SSE ${response.status}`);
        attempt = 0;
        setLive(true);
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let boundary = buffer.indexOf('\n\n');
          while (boundary !== -1) {
            parseFrame(buffer.slice(0, boundary));
            buffer = buffer.slice(boundary + 2);
            boundary = buffer.indexOf('\n\n');
          }
        }
        throw new Error('stream ended');
      } catch {
        if (cancelled || controller.signal.aborted) return;
        setLive(false);
        attempt += 1;
        const delay = Math.min(RETRY_MAX_MS, RETRY_MIN_MS * 2 ** Math.min(attempt - 1, 4));
        if (retry) clearTimeout(retry);
        retry = setTimeout(() => void connect(), delay);
      }
    };

    void connect();
    return () => {
      cancelled = true;
      controller.abort();
      if (retry) clearTimeout(retry);
      setLive(false);
    };
  }, [token, mode, apply]);

  /* ---- Supabase realtime: nudge on the tenant's own writes -------- */
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`qkms-${mode}-${table}`)
        .on(
          'postgres_changes',
          {
            event: '*',
            schema: 'public',
            table,
            // user_id on every table, qkms_* included: those rows carry the caller
            // as both tenant and user, and matching tenant_id alone would let a
            // row another user planted under this tenant's id nudge the page.
            filter: `user_id=eq.${user.id}`,
          },
          queueRefresh,
        )
        .subscribe(),
    );
    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [user, mode, queueRefresh]);

  const reconnect = useCallback(() => {
    void refresh(true);
  }, [refresh]);

  return { data, state, error, live, lastSyncedAt, verifiedAt, refresh, reconnect };
}

/* ------------------------------------------------------------------ */
/* Named wrappers — one per page                                       */
/* ------------------------------------------------------------------ */

export const useQkmsOverview = () => useQkmsView<OverviewPayload>('overview');
export const useKeyInventory = () => useQkmsView<InventoryPayload>('inventory');
export const useKeyLifecycle = () => useQkmsView<LifecyclePayload>('lifecycle');
export const useKeyGovernance = () => useQkmsView<GovernancePayload>('governance');
export const useKeyRotation = () => useQkmsView<RotationPayload>('rotation');
export const usePqcKeyReadiness = () => useQkmsView<ReadinessPayload>('readiness');
export const useKeyRiskAnalysis = () => useQkmsView<RiskPayload>('risk-analysis');

/* ------------------------------------------------------------------ */
/* Server-side key querying                                            */
/* ------------------------------------------------------------------ */

export interface KeyQuery {
  q?: string;
  type?: string;
  algorithm?: string;
  family?: string;
  owner?: string;
  asset?: string;
  environment?: string;
  backend?: string;
  custody?: string;
  posture?: KeyPqcPosture | '';
  lifecycle?: LifecycleState | '';
  rotation?: RotationState | '';
  risk?: string;
  requirement?: MigrationRequirement | '';
  compliance?: string;
  expiring?: string;
  ids?: string;
  sort?: string;
  dir?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
  facets?: boolean;
}

/**
 * Paged, server-side key querying.
 *
 * The tables never hold the whole estate in the browser: filtering, sorting and
 * pagination all happen against the cached tenant model, so a 40 000-key
 * inventory renders in the same time as a 40-key one.
 *
 * `syncTo` is the view's `generatedAt`. When the stream pushes a newer model the
 * page re-queries, so the table never shows keys in a state the KPIs above it
 * have already moved past.
 */
export function useKeyQuery(initial: KeyQuery = {}, syncTo: string | null = null) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [page, setPage] = useState<KeyPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestRef = useRef(0);
  const [query, setQuery] = useState<KeyQuery>({ limit: 25, offset: 0, sort: 'risk', dir: 'desc', ...initial });

  const run = useCallback(
    async (next: KeyQuery) => {
      if (!token) return;
      const ticket = ++requestRef.current;
      setLoading(true);
      setError(null);
      try {
        const params = new URLSearchParams();
        for (const [field, value] of Object.entries(next)) {
          if (value === undefined || value === null || value === '' || value === false) continue;
          params.set(field, value === true ? '1' : String(value));
        }
        const response = await fetch(`${API_BASE}/keys?${params.toString()}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        // Drop a response that a newer query has already superseded.
        if (ticket !== requestRef.current) return;
        setPage(payload.data as KeyPage);
      } catch (err) {
        if (ticket !== requestRef.current) return;
        console.error('QKMS key query failed:', err);
        setError(err instanceof Error ? err.message : 'Unable to load keys');
      } finally {
        if (ticket === requestRef.current) setLoading(false);
      }
    },
    [token],
  );

  useEffect(() => {
    void run(query);
  }, [run, query, syncTo]);

  const update = useCallback((patch: Partial<KeyQuery>) => {
    // Any filter change resets to the first page: leaving the offset in place
    // strands the operator on an empty page of a smaller result set.
    setQuery((current) => ({ ...current, ...patch, offset: 'offset' in patch ? patch.offset ?? 0 : 0 }));
  }, []);

  const setOffset = useCallback((offset: number) => {
    setQuery((current) => ({ ...current, offset }));
  }, []);

  return { page, loading, error, query, update, setOffset, reload: () => void run(query) };
}

/* ------------------------------------------------------------------ */
/* Lazy drill-down                                                     */
/* ------------------------------------------------------------------ */

/**
 * Fetches the full investigation record for one key.
 *
 * The dashboard payloads deliberately do not carry every version, violation and
 * audit event for every key; the drawer asks for the one the operator opened.
 */
export function useKeyDetail() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [detail, setDetail] = useState<KeyDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** Opening key B while key A is still loading must never show A's record. */
  const requestRef = useRef(0);

  const load = useCallback(
    async (keyId: string | null, options: { quiet?: boolean } = {}) => {
      const ticket = ++requestRef.current;
      if (!keyId) {
        setDetail(null);
        setLoading(false);
        return;
      }
      if (!token) return;
      // A quiet reload (live push) keeps the open record on screen meanwhile.
      if (!options.quiet) setLoading(true);
      setError(null);
      try {
        const response = await fetch(`${API_BASE}/keys/${encodeURIComponent(keyId)}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (ticket !== requestRef.current) return;
        setDetail(payload.data as KeyDetail);
      } catch (err) {
        if (ticket !== requestRef.current) return;
        console.error('QKMS key detail failed:', err);
        setError(err instanceof Error ? err.message : 'Unable to load key detail');
        if (!options.quiet) setDetail(null);
      } finally {
        if (ticket === requestRef.current) setLoading(false);
      }
    },
    [token],
  );

  return { detail, loading, error, load, clear: () => setDetail(null) };
}

/* ------------------------------------------------------------------ */
/* Governed actions                                                    */
/* ------------------------------------------------------------------ */

export interface ActionResult {
  ok: boolean;
  message: string;
}

/**
 * The write surface.
 *
 * Every call maps to a governed backend operation that persists state and
 * writes an audit record. There is deliberately no client-side optimistic
 * update: the operator sees the change only once the backend has actually
 * recorded it, because a control that appears to succeed without persisting is
 * the failure mode this module was rebuilt to remove.
 */
export function useQkmsActions(onChanged?: () => void) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [pending, setPending] = useState<string | null>(null);

  const call = useCallback(
    async (id: string, path: string, body: unknown, successMessage: string): Promise<ActionResult> => {
      if (!token) return { ok: false, message: 'Authentication required' };
      setPending(id);
      try {
        const response = await fetch(`${API_BASE}${path}`, {
          method: path.includes('/policies/') ? 'PATCH' : 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(body ?? {}),
        });
        const payload = await response.json().catch(() => ({}));
        // A conflict means the record moved under the operator (another tab, an
        // agent, a double click): reload so the controls reflect the real state.
        if (response.status === 409) onChanged?.();
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        onChanged?.();
        const versionNote = payload?.data?.validationStatus === 'pending'
          ? ' Closed WITHOUT validation evidence: no new version was minted and the migration gate still requires validation.'
          : payload?.data?.versionRecorded === false
            ? ' The new key version could not be recorded; the version chain is unchanged.'
            : '';
        return { ok: true, message: `${successMessage}${versionNote}` };
      } catch (err) {
        return { ok: false, message: err instanceof Error ? err.message : 'Action failed' };
      } finally {
        setPending(null);
      }
    },
    [token, onChanged],
  );

  return {
    pending,
    assignOwner: (keyId: string, owner: string) =>
      call(`owner:${keyId}`, `/keys/${encodeURIComponent(keyId)}/assign-owner`, { owner }, `Owner set to ${owner}.`),
    requestRotation: (keyId: string, reason?: string, priority?: string) =>
      call(`rotate:${keyId}`, `/keys/${encodeURIComponent(keyId)}/rotation`, { reason, priority }, 'Rotation work order raised.'),
    revokeKey: (keyId: string, reason?: string) =>
      call(`revoke:${keyId}`, `/keys/${encodeURIComponent(keyId)}/revoke`, { reason }, 'Key marked revoked.'),
    decommissionKey: (keyId: string, reason?: string) =>
      call(`decommission:${keyId}`, `/keys/${encodeURIComponent(keyId)}/decommission`, { reason }, 'Key decommissioned.'),
    transitionJob: (jobId: string, status: RotationJobStatus, extra?: Record<string, unknown>) =>
      call(`job:${jobId}`, `/rotation-jobs/${encodeURIComponent(jobId.replace(/^job:/, ''))}/transition`, { status, ...extra }, `Work order moved to ${status}.`),
    createPolicy: (body: Record<string, unknown>) =>
      call('policy:new', '/policies', body, 'Policy created.'),
    updatePolicy: (policyId: string, body: Record<string, unknown>) =>
      call(`policy:${policyId}`, `/policies/${encodeURIComponent(policyId.replace(/^policy:/, ''))}`, body, 'Policy updated.'),
    runPrecheck: async (): Promise<{ ok: boolean; message: string; gate?: MigrationGate }> => {
      if (!token) return { ok: false, message: 'Authentication required' };
      setPending('precheck');
      try {
        const response = await fetch(`${API_BASE}/precheck`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: '{}',
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        onChanged?.();
        const gate = payload.data as MigrationGate;
        return { ok: true, message: `Migration gate: ${gate.state.replace(/_/g, ' ')}`, gate };
      } catch (err) {
        return { ok: false, message: err instanceof Error ? err.message : 'Precheck failed' };
      } finally {
        setPending(null);
      }
    },
    /** Pulls the whole model for the client-side report builder. */
    fetchExportModel: async () => {
      if (!token) throw new Error('Authentication required');
      const response = await fetch(`${API_BASE}/export`, {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      return payload.data;
    },
  };
}
