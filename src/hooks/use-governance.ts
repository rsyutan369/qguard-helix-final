'use client';

/**
 * Data contract for the Enterprise Governance Command Layer.
 *
 * Four pages — Compliance, Quantum Governance, Audit Vault, Regulatory Mapping —
 * are projections of one backend model. This hook is the only place any of them
 * talks to it, which is what makes their numbers agree by construction.
 *
 * Three cooperating channels:
 *   1. fetch()            authoritative first paint and every manual refresh.
 *   2. SSE                the live push, over fetch + ReadableStream with an
 *                         Authorization HEADER. EventSource cannot set headers,
 *                         which forces the bearer token into the query string
 *                         where it leaks into access logs and browser history.
 *   3. Supabase realtime  a debounced nudge when the tenant's own rows change,
 *                         so a scan or an attestation lands without waiting for
 *                         the next push.
 *
 * The stream carries the WHOLE view payload and the page swaps state atomically,
 * so the KPI strip, the charts and the tables can never render a half-applied
 * update. Exactly ONE stream and one realtime channel set exists per mounted
 * view, and both are torn down on unmount — there is no polling loop.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type {
  AssetComplianceRecord,
  AuditEvent,
  ControlDomain,
  ControlRecord,
  ControlStatus,
  ControlSubject,
  EvidenceRecord,
  FrameworkRecord,
  GovernanceFacets,
  GovernanceGap,
  GovernanceIntelligence,
  GovernanceScore,
  GovernanceTelemetry,
  GovernanceTrendPoint,
  PolicyRecord,
  PolicyViolation,
  ReconciliationReport,
  RequirementRecord,
} from '@/lib/governance/types';

export type LoadState = 'loading' | 'success' | 'error';
export type GovernanceView = 'compliance' | 'quantum' | 'audit' | 'regulatory';

/* ------------------------------------------------------------------ */
/* Payload shapes — mirror projectView() in src/api-server/governance.ts */
/* ------------------------------------------------------------------ */

/** The bounded control row every table renders; full record is one fetch away. */
export interface ControlSummary {
  id: string;
  code: string;
  title: string;
  domain: ControlDomain;
  status: ControlStatus;
  score: number | null;
  measured: boolean;
  severity: ControlRecord['severity'];
  population: number;
  satisfied: number;
  failing: number;
  owner: string | null;
  ownerSource: ControlRecord['ownerSource'];
  frameworkIds: string[];
  requirementIds: string[];
  affectedAssetCount: number;
  lastValidatedAt: string | null;
  evidenceFreshness: ControlRecord['evidenceFreshness'];
  evidenceAgeDays: number | null;
  remediationRoute: string;
  basis: string;
  weight: number;
  hasException: boolean;
}

export interface DomainRollupRow {
  domain: ControlDomain;
  controls: number;
  measured: number;
  compliant: number;
  failing: number;
  unassessed: number;
  score: number | null;
  failingSubjects: number;
}

interface CommonPayload {
  generatedAt: string;
  latestEvidenceAt: string | null;
  hasData: boolean;
  stale: boolean;
  staleSinceHours: number | null;
  scores: GovernanceIntelligence['scores'];
  totals: GovernanceIntelligence['totals'];
  telemetry: GovernanceTelemetry;
  facets: GovernanceFacets;
  reconciliation: ReconciliationReport;
}

export interface CompliancePayload extends CommonPayload {
  view: 'compliance';
  controls: ControlSummary[];
  controlIndex: Array<{ id: string; code: string; title: string; status: ControlStatus; domain: ControlDomain }>;
  gaps: GovernanceGap[];
  frameworks: FrameworkRecord[];
  assets: AssetComplianceRecord[];
  evidence: EvidenceRecord[];
  trend: GovernanceTrendPoint[];
  domainRollup: DomainRollupRow[];
  requirementSummary: Array<{
    id: string;
    frameworkId: string;
    code: string;
    title: string;
    status: ControlStatus;
    score: number | null;
    measured: boolean;
  }>;
}

export interface QuantumGovernancePayload extends CommonPayload {
  view: 'quantum';
  policies: PolicyRecord[];
  controls: ControlSummary[];
  gaps: GovernanceGap[];
  assets: AssetComplianceRecord[];
  trend: GovernanceTrendPoint[];
  domainRollup: DomainRollupRow[];
  posture: {
    cryptoComponents: number;
    vulnerableComponents: number;
    pqcReadyComponents: number;
    certificates: number;
    keys: number;
    criticalFindings: number;
  };
}

export interface AuditVaultPayload extends CommonPayload {
  view: 'audit';
  auditEvents: AuditEvent[];
  evidence: EvidenceRecord[];
  controls: ControlSummary[];
  gaps: GovernanceGap[];
  trend: GovernanceTrendPoint[];
  integrity: {
    verified: number;
    mismatch: number;
    unanchored: number;
    unavailable: number;
    total: number;
    available: boolean;
    claim: string;
  };
  retention: { active: number; expiring: number; expired: number; unspecified: number; total: number };
  custodyRollup: Array<{ collector: string; count: number }>;
}

export interface RegulatoryPayload extends CommonPayload {
  view: 'regulatory';
  frameworks: FrameworkRecord[];
  requirements: RequirementRecord[];
  controls: ControlSummary[];
  gaps: GovernanceGap[];
  evidence: EvidenceRecord[];
  assets: AssetComplianceRecord[];
  trend: GovernanceTrendPoint[];
}

export type GovernancePayload = CompliancePayload | QuantumGovernancePayload | AuditVaultPayload | RegulatoryPayload;

/* ---- drill-down shapes ---- */

export interface ControlDetail {
  control: ControlRecord;
  definition: {
    id: string;
    code: string;
    title: string;
    objective: string;
    criterion: string;
    evidenceSources: string[];
    remediationRoute: string;
  } | null;
  requirements: RequirementRecord[];
  frameworks: FrameworkRecord[];
  evidence: EvidenceRecord[];
  policies: PolicyRecord[];
  assets: AssetComplianceRecord[];
  auditEvents: AuditEvent[];
  gaps: GovernanceGap[];
}

export interface FrameworkDetail {
  framework: FrameworkRecord;
  definition: { reference: string; scope: string; authority: string; version: string } | null;
  requirements: RequirementRecord[];
  controls: ControlSummary[];
  evidence: EvidenceRecord[];
  gaps: GovernanceGap[];
}

export interface RequirementDetail {
  requirement: RequirementRecord;
  definition: { summary: string; code: string } | null;
  framework: FrameworkRecord | null;
  controls: ControlSummary[];
  evidence: EvidenceRecord[];
}

export interface EvidenceDetail {
  evidence: EvidenceRecord;
  controls: ControlSummary[];
  requirements: RequirementRecord[];
  frameworks: FrameworkRecord[];
  asset: AssetComplianceRecord | null;
  auditEvents: AuditEvent[];
}

export interface AuditEventDetail {
  event: AuditEvent;
  evidence: EvidenceRecord | null;
  controls: ControlSummary[];
  asset: AssetComplianceRecord | null;
  related: AuditEvent[];
}

export interface AssetComplianceDetail {
  asset: AssetComplianceRecord;
  failingControls: ControlSummary[];
  evidence: EvidenceRecord[];
  auditEvents: AuditEvent[];
  gaps: GovernanceGap[];
}

/* ------------------------------------------------------------------ */
/* Wiring                                                              */
/* ------------------------------------------------------------------ */

export const GOVERNANCE_API_BASE: Record<GovernanceView, string> = {
  compliance: '/api/v1/dashboard/compliance',
  quantum: '/api/v1/dashboard/quantum-governance',
  audit: '/api/v1/dashboard/audit-vault',
  regulatory: '/api/v1/dashboard/regulatory-mapping',
};

export const GOVERNANCE_ROUTE: Record<GovernanceView, string> = {
  compliance: '/dashboard/compliance',
  quantum: '/dashboard/quantum-governance',
  audit: '/dashboard/audit-vault',
  regulatory: '/dashboard/regulatory-mapping',
};

/**
 * Tables whose mutation can change what these pages show.
 *
 * Deliberately the union across all four views: an attestation write must nudge
 * Quantum Governance (its evidence-coverage tile) as well as Regulatory
 * Mapping, or the two pages drift apart until the next 10s push — which is
 * exactly the disagreement this layer exists to remove.
 */
const REALTIME_TABLES = [
  'assets',
  'crypto_inventory',
  'crypto_exposures',
  'certificates',
  'generated_keys',
  'runtime_crypto_events',
  'pqc_scan_sessions',
  'pqc_scan_results',
  'vulnerabilities',
  'scanner_alerts',
  'scanner_agents',
  'connector_accounts',
  'migration_jobs',
  'migration_events',
  'compliance_evidence',
  'audit_logs',
  'vault_audit_logs',
  'vault_files',
  'security_events',
  'governance_policies',
  'governance_evidence_anchors',
  'governance_control_assessments',
] as const;

/** Reconnect backoff bounds for the SSE stream, in milliseconds. */
const RETRY_MIN_MS = 3_000;
const RETRY_MAX_MS = 30_000;

export interface UseGovernanceResult<T extends GovernancePayload> {
  data: T | null;
  state: LoadState;
  error: string | null;
  /** True only while the stream is genuinely open. Never "live" on stale data. */
  live: boolean;
  lastSyncedAt: string | null;
  /** Increments on every applied frame, so paged tables can refresh in step. */
  revision: number;
  refresh: (force?: boolean) => Promise<void>;
  reconnect: () => void;
}

export function useGovernanceView<T extends GovernancePayload>(view: GovernanceView): UseGovernanceResult<T> {
  const { session, user } = useAuth();
  const token = session?.access_token;

  const [data, setData] = useState<T | null>(null);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);

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
    setLastSyncedAt(new Date().toISOString());
    setRevision((current) => current + 1);
  }, []);

  const refresh = useCallback(
    async (force = false) => {
      if (!token) {
        setState('success');
        return;
      }
      setState((current) => (current === 'success' ? current : 'loading'));
      try {
        const response = await fetch(`${GOVERNANCE_API_BASE[view]}${force ? '?refresh=1' : ''}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!payload?.data) throw new Error('Governance response was empty');
        apply(payload.data as T);
      } catch (err) {
        console.error(`Governance ${view} load failed:`, err);
        setError(err instanceof Error ? err.message : 'Unable to load governance intelligence');
        // Keep the last good model on screen; the header switches to a
        // disconnected state so nothing reads as live.
        setState((current) => (current === 'success' ? current : 'error'));
      }
    },
    [token, view, apply],
  );

  const queueRefresh = useCallback(() => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null;
      void refresh();
    }, 600);
  }, [refresh]);

  useEffect(
    () => () => {
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
    },
    [],
  );

  useEffect(() => {
    if (!token || !user) {
      setState('success');
      return;
    }
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
      if (eventName === 'governance') {
        try {
          const parsed = JSON.parse(body) as T;
          // Event validation: a frame for another view must never be applied.
          if (parsed && typeof parsed === 'object' && parsed.view === view) apply(parsed);
        } catch {
          /* malformed frame — ignore rather than blank the page */
        }
      } else if (eventName === 'governance-error') {
        try {
          setError(String(JSON.parse(body)?.message || 'Governance stream error'));
        } catch {
          /* ignore */
        }
      }
    };

    const connect = async () => {
      try {
        const response = await fetch(`${GOVERNANCE_API_BASE[view]}/stream`, {
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
  }, [token, view, apply]);

  /* ---- Supabase realtime: nudge on the tenant's own writes -------- */
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`governance-${view}-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [user, view, queueRefresh]);

  const reconnect = useCallback(() => {
    void refresh(true);
  }, [refresh]);

  return { data, state, error, live, lastSyncedAt, revision, refresh, reconnect };
}

/* ------------------------------------------------------------------ */
/* Named wrappers — one per page                                       */
/* ------------------------------------------------------------------ */

export const useComplianceCommandCenter = () => useGovernanceView<CompliancePayload>('compliance');
export const useQuantumGovernance = () => useGovernanceView<QuantumGovernancePayload>('quantum');
export const useAuditVault = () => useGovernanceView<AuditVaultPayload>('audit');
export const useRegulatoryMapping = () => useGovernanceView<RegulatoryPayload>('regulatory');

/* ------------------------------------------------------------------ */
/* Lazy drill-down (§15)                                               */
/* ------------------------------------------------------------------ */

/**
 * Fetches the full investigation record for one governance object.
 *
 * The dashboard payloads deliberately do not ship every failing subject for
 * every control; the drawer asks for the one the user actually opened. An
 * in-flight request is aborted when a newer one starts, so rapid clicking
 * through a table cannot land an older response on a newer drawer.
 */
export function useGovernanceDetail(view: GovernanceView) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [loading, setLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const inFlight = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      inFlight.current?.abort();
    },
    [],
  );

  const load = useCallback(
    async <R,>(path: string): Promise<R | null> => {
      if (!token) return null;
      inFlight.current?.abort();
      const controller = new AbortController();
      inFlight.current = controller;
      setLoading(true);
      setDetailError(null);
      try {
        const response = await fetch(`${GOVERNANCE_API_BASE[view]}${path}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        return (payload.data ?? null) as R | null;
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') return null;
        console.error('Governance detail load failed:', err);
        setDetailError(err instanceof Error ? err.message : 'Unable to load detail');
        return null;
      } finally {
        if (inFlight.current === controller) {
          inFlight.current = null;
          setLoading(false);
        }
      }
    },
    [token, view],
  );

  const loadControl = useCallback((id: string) => load<ControlDetail>(`/controls/${encodeURIComponent(id)}`), [load]);
  const loadFramework = useCallback((id: string) => load<FrameworkDetail>(`/frameworks/${encodeURIComponent(id)}`), [load]);
  const loadRequirement = useCallback((id: string) => load<RequirementDetail>(`/requirements/${encodeURIComponent(id)}`), [load]);
  const loadEvidence = useCallback((id: string) => load<EvidenceDetail>(`/evidence/${encodeURIComponent(id)}`), [load]);
  const loadAuditEvent = useCallback((id: string) => load<AuditEventDetail>(`/audit-events/${encodeURIComponent(id)}`), [load]);
  const loadAsset = useCallback((id: string) => load<AssetComplianceDetail>(`/assets/${encodeURIComponent(id)}`), [load]);

  return { loadControl, loadFramework, loadRequirement, loadEvidence, loadAuditEvent, loadAsset, loading, detailError };
}

/* ------------------------------------------------------------------ */
/* Server-side paged tables (§12)                                      */
/* ------------------------------------------------------------------ */

export interface PagedQuery {
  [key: string]: string | number | undefined;
}

/**
 * Server-side search, filter, sort and paging.
 *
 * Large estates must never ship thousands of rows to the browser to display
 * fifty. Filtering happens on the API against the cached model, so paging costs
 * nothing extra and every page of results is derived from the same snapshot the
 * KPI strip was computed from.
 *
 * `revision` is bumped by the view hook whenever the live model updates, so an
 * open table refreshes in step with the rest of the page.
 */
export function useGovernancePagedResource<T>(
  view: GovernanceView,
  path: string,
  key: string,
  query: PagedQuery,
  revision: number,
) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [rows, setRows] = useState<T[]>([]);
  const [extra, setExtra] = useState<Record<string, unknown>>({});
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const serialized = JSON.stringify(query);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        const params = new URLSearchParams();
        for (const [name, value] of Object.entries(JSON.parse(serialized) as PagedQuery)) {
          if (value === undefined || value === '' || value === 'all') continue;
          params.set(name, String(value));
        }
        const response = await fetch(`${GOVERNANCE_API_BASE[view]}${path}?${params.toString()}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        setRows((payload.data?.[key] ?? []) as T[]);
        setExtra((payload.data ?? {}) as Record<string, unknown>);
        setTotal(Number(payload.data?.total ?? 0));
        setError(null);
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') return;
        console.error('Governance table load failed:', err);
        setError(err instanceof Error ? err.message : 'Unable to load rows');
      } finally {
        setLoading(false);
      }
      // Debounced so typing in the search box does not fire a request per keystroke.
    }, 250);

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token, view, path, key, serialized, revision]);

  return { rows, extra, total, loading, error };
}

/* ------------------------------------------------------------------ */
/* Governance actions (§6 policy management, §7 evidence integrity)    */
/* ------------------------------------------------------------------ */

export interface GovernanceActionResult<T> {
  ok: boolean;
  data: T | null;
  message: string;
}

/**
 * Write actions that change governance state.
 *
 * Each returns a structured result rather than throwing, so the UI can show the
 * backend's own message — including the "apply the governance schema" guidance
 * when a store is not yet available — instead of a generic failure.
 */
export function useGovernanceActions(view: GovernanceView) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [pending, setPending] = useState<string | null>(null);

  const post = useCallback(
    async <T,>(path: string, body: unknown, method: 'POST' | 'PATCH' = 'POST'): Promise<GovernanceActionResult<T>> => {
      if (!token) return { ok: false, data: null, message: 'Not authenticated' };
      setPending(path);
      try {
        const response = await fetch(`${GOVERNANCE_API_BASE[view]}${path}`, {
          method,
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(body ?? {}),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          return { ok: false, data: null, message: payload?.error?.message || `HTTP ${response.status}` };
        }
        return { ok: true, data: (payload.data ?? null) as T, message: String(payload?.data?.message || 'Done') };
      } catch (err) {
        return { ok: false, data: null, message: err instanceof Error ? err.message : 'Request failed' };
      } finally {
        setPending(null);
      }
    },
    [token, view],
  );

  const anchorEvidence = useCallback(
    (input: { evidenceIds?: string[]; scope?: 'unanchored' | 'all' }) =>
      post<{ anchored: number; reanchored: number; total: number; message: string }>('/evidence/anchor', input),
    [post],
  );

  const verifyEvidence = useCallback(
    (evidenceId: string) =>
      post<{
        evidenceId: string;
        recomputedDigest: string;
        anchoredDigest: string | null;
        firstDigest: string | null;
        anchoredAt: string | null;
        reanchorCount: number;
        state: EvidenceRecord['integrity']['state'];
        assurance: string;
        verifiedAt: string;
      }>('/evidence/verify', { evidenceId }),
    [post],
  );

  const updatePolicy = useCallback(
    (
      policyId: string,
      input: { enforcement?: string; severity?: string; parameters?: Record<string, unknown>; note?: string },
    ) => post<{ policy: PolicyRecord | null }>(`/policies/${encodeURIComponent(policyId)}`, input, 'PATCH'),
    [post],
  );

  const updateControlAssessment = useCallback(
    (
      controlId: string,
      input: {
        owner?: string;
        ownerEmail?: string;
        reviewNote?: string;
        attest?: boolean;
        exceptionReason?: string;
        exceptionApprovedBy?: string;
        exceptionExpiresAt?: string;
      },
    ) => post<{ control: ControlRecord | null }>(`/controls/${encodeURIComponent(controlId)}/assessment`, input, 'PATCH'),
    [post],
  );

  return { anchorEvidence, verifyEvidence, updatePolicy, updateControlAssessment, pending };
}

/* ------------------------------------------------------------------ */
/* Shared filter state (§14)                                           */
/* ------------------------------------------------------------------ */

export interface GovernanceFilters {
  search: string;
  status: string;
  domain: string;
  framework: string;
  requirement: string;
  severity: string;
  owner: string;
  environment: string;
  criticality: string;
  exposure: string;
  freshness: string;
  kind: string;
  outcome: string;
  integrity: string;
  retention: string;
  category: string;
  enforcement: string;
  actorType: string;
  asset: string;
  control: string;
  range: string;
  sort: string;
}

export const EMPTY_GOVERNANCE_FILTERS: GovernanceFilters = {
  search: '',
  status: 'all',
  domain: 'all',
  framework: 'all',
  requirement: 'all',
  severity: 'all',
  owner: 'all',
  environment: 'all',
  criticality: 'all',
  exposure: 'all',
  freshness: 'all',
  kind: 'all',
  outcome: 'all',
  integrity: 'all',
  retention: 'all',
  category: 'all',
  enforcement: 'all',
  actorType: 'all',
  asset: '',
  control: 'all',
  range: 'all',
  sort: '',
};

/**
 * One filter object shared by every widget and table on a page, so a framework
 * chosen in the header narrows the chart and the table together rather than
 * only one of them (§14: "filters must produce consistent results").
 *
 * The filter names are identical across all four pages, which is what lets a
 * drill-down carry its context to the next page through the URL.
 */
export function useGovernanceFilters(initial?: Partial<GovernanceFilters>) {
  const [filters, setFilters] = useState<GovernanceFilters>({ ...EMPTY_GOVERNANCE_FILTERS, ...initial });

  const setFilter = useCallback((key: keyof GovernanceFilters, value: string) => {
    setFilters((current) => (current[key] === value ? current : { ...current, [key]: value }));
  }, []);

  const reset = useCallback(() => setFilters({ ...EMPTY_GOVERNANCE_FILTERS, ...initial }), [initial]);

  const activeCount = useMemo(
    () =>
      (Object.keys(filters) as Array<keyof GovernanceFilters>).filter((key) => {
        if (key === 'sort') return false;
        const value = filters[key];
        return value !== '' && value !== 'all';
      }).length,
    [filters],
  );

  return { filters, setFilter, setFilters, reset, activeCount };
}

export type { ControlSubject, PolicyViolation, GovernanceScore };
