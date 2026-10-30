'use client';

import type { SourceRead } from '@/lib/source-read';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type {
  CertificateIntelligence,
  CertificateTrustRecord,
  CloudEstate,
  CloudProviderPosture,
  CloudRegionPosture,
  CloudResource,
  PkiCertificate,
  ReconciliationReport,
  TelemetryHealth,
  TlsEndpoint,
  TlsFinding,
  TrustChainNode,
  TrustChainPath,
  TrustEvent,
  TrustFabricIntelligence,
  TrustKpi,
  TrustNode,
  TrustNodeKind,
  TrustRelationship,
  TrustScore,
  TrustState,
} from '@/lib/trust-fabric/types';

export type LoadState = 'loading' | 'success' | 'error';
export type TrustView = 'trust' | 'discovery' | 'certificate' | 'cloud';

/* ------------------------------------------------------------------ */
/* Payload shapes - mirror `projectView()` in src/api-server/trust-fabric.ts */
/* ------------------------------------------------------------------ */

export interface TrustTotals {
  nodes: number;
  measuredNodes: number;
  relationships: number;
  certificates: number;
  endpoints: number;
  /** Endpoints with real transport evidence - the TLS percentage denominator. */
  measuredEndpoints: number;
  findings: number;
  cloudResources: number;
  attributedCloudResources: number;
  events: number;
  chainPaths: number;
}

interface CommonPayload {
  generatedAt: string;
  latestEvidenceAt: string | null;
  hasData: boolean;
  /** Outcome of every source read. `unavailable` = the query FAILED, so dependent figures are incomplete, not zero. */
  reads: SourceRead[];
  stale: boolean;
  staleSinceHours: number | null;
  scores: TrustScore[];
  telemetry: TelemetryHealth;
  reconciliation: ReconciliationReport;
  facets: TrustFabricIntelligence['facets'];
  totals: TrustTotals;
}

export type NodeSummary = Pick<
  TrustNode,
  | 'id'
  | 'kind'
  | 'label'
  | 'subtitle'
  | 'state'
  | 'stateReason'
  | 'posture'
  | 'riskLevel'
  | 'riskScore'
  | 'assetId'
  | 'certificateId'
  | 'endpointId'
  | 'environment'
  | 'provider'
  | 'providerLabel'
  | 'region'
  | 'dependentCount'
  | 'daysToExpiry'
  | 'measured'
  | 'href'
>;

export interface TrustPayload extends CommonPayload {
  view: 'trust';
  kpis: TrustKpi[];
  stateDistribution: TrustFabricIntelligence['stateDistribution'];
  trend: TrustFabricIntelligence['trend'];
  events: TrustEvent[];
  findings: TlsFinding[];
  criticalNodes: NodeSummary[];
  expiring: CertificateTrustRecord[];
  certificateIntel: Pick<CertificateIntelligence, 'lifecycle' | 'bands' | 'chainValidation' | 'expiryTimeline'>;
  cloudSummary: {
    hasCloudEvidence: boolean;
    connectorsConfigured: number;
    connectorsActive: number;
    providers: CloudProviderPosture[];
    totals: CloudEstate['totals'];
    topRegions: CloudRegionPosture[];
  };
  certificateIndex: Array<{
    id: string;
    name: string;
    subject: string;
    issuer: string;
    daysToExpiry: number | null;
    posture: PkiCertificate['posture'];
  }>;
}

export interface DiscoveryPayload extends CommonPayload {
  view: 'discovery';
  nodes: TrustNode[];
  relationships: TrustRelationship[];
  chainPaths: TrustChainPath[];
  trustChains: TrustChainNode[];
  stateDistribution: TrustFabricIntelligence['stateDistribution'];
  kindDistribution: TrustFabricIntelligence['kindDistribution'];
  findings: TlsFinding[];
  events: TrustEvent[];
  nodeIndex: Array<{ id: string; kind: TrustNodeKind; label: string; state: TrustState; measured: boolean }>;
}

export interface CertificatePayload extends CommonPayload {
  view: 'certificate';
  certificates: PkiCertificate[];
  certificateTrust: CertificateTrustRecord[];
  certificateIntel: CertificateIntelligence;
  chainPaths: TrustChainPath[];
  trustChains: TrustChainNode[];
  findings: TlsFinding[];
  events: TrustEvent[];
  endpointIndex: Array<
    Pick<TlsEndpoint, 'id' | 'assetId' | 'name' | 'host' | 'port' | 'environment' | 'negotiatedVersion' | 'posture'>
  >;
}

export interface CloudPayload extends CommonPayload {
  view: 'cloud';
  cloud: CloudEstate;
  events: TrustEvent[];
  findings: TlsFinding[];
  certificateTrust: CertificateTrustRecord[];
}

export type TrustFabricPayload = TrustPayload | DiscoveryPayload | CertificatePayload | CloudPayload;

/* ---- drill-down shapes ---- */

export interface NodeDetail {
  node: TrustNode;
  edges: TrustRelationship[];
  neighbours: NodeSummary[];
  chain: TrustChainPath | null;
  certificates: PkiCertificate[];
  certificateTrust: CertificateTrustRecord[];
  findings: TlsFinding[];
  events: TrustEvent[];
}

export interface CertificateDetail {
  certificate: PkiCertificate;
  trust: CertificateTrustRecord | null;
  chain: TrustChainPath | null;
  chainNodes: TrustNode[];
  affected: NodeSummary[];
  endpoint: TlsEndpoint | null;
  findings: TlsFinding[];
  events: TrustEvent[];
}

export interface CloudResourceDetail {
  resource: CloudResource;
  certificates: PkiCertificate[];
  certificateTrust: CertificateTrustRecord[];
  endpoints: TlsEndpoint[];
  findings: TlsFinding[];
  region: CloudRegionPosture | null;
  events: TrustEvent[];
}

/* ------------------------------------------------------------------ */
/* Wiring                                                              */
/* ------------------------------------------------------------------ */

const API_BASE: Record<TrustView, string> = {
  trust: '/api/v1/dashboard/trust-dashboard',
  discovery: '/api/v1/dashboard/trust-state-discovery',
  certificate: '/api/v1/dashboard/certificate-telemetry',
  cloud: '/api/v1/dashboard/multi-cloud-telemetry',
};

/**
 * Tables whose mutation can change what these pages show.
 *
 * Deliberately the union across all four views: a certificate write must nudge
 * the Trust Dashboard (its expiry KPI) as well as Certificate Telemetry, or the
 * two pages drift apart until the next 10s push - which is exactly the kind of
 * disagreement this refactor exists to remove.
 */
const REALTIME_TABLES = [
  'assets',
  'asset_relationships',
  'certificates',
  'crypto_inventory',
  'crypto_exposures',
  'runtime_crypto_events',
  'scanner_evidence',
  'scanner_alerts',
  'pqc_scan_results',
  'pqc_scan_sessions',
  'security_events',
  'migration_jobs',
  'migration_plans',
  'connector_accounts',
  'scanner_agents',
  'compliance_evidence',
] as const;

/** Distinguishes realtime channel topics between hook instances. */
let nextRealtimeInstance = 0;

/** Reconnect backoff bounds for the SSE stream, in milliseconds. */
const RETRY_MIN_MS = 3_000;
const RETRY_MAX_MS = 30_000;

export interface UseTrustFabricResult<T extends TrustFabricPayload> {
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

/**
 * useTrustFabricView - the shared data contract for the four trust dashboards.
 *
 * Three cooperating channels:
 *   1. fetch()            authoritative first paint and every manual refresh.
 *   2. SSE                the live push, over fetch + ReadableStream with an
 *                         Authorization HEADER. EventSource cannot set headers,
 *                         which forces the bearer token into the query string
 *                         where it leaks into access logs and history.
 *   3. Supabase realtime  a debounced nudge when the tenant's own rows change,
 *                         so an agent write lands without waiting for the push.
 *
 * The stream carries the WHOLE view payload and the page swaps state atomically,
 * so the KPI strip, the charts and the tables can never render a half-applied
 * update. Exactly one stream and one realtime channel set exists per mounted
 * view, and both are torn down on unmount - there is no polling loop.
 */
export function useTrustFabricView<T extends TrustFabricPayload>(view: TrustView): UseTrustFabricResult<T> {
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
        const response = await fetch(`${API_BASE[view]}${force ? '?refresh=1' : ''}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!payload?.data) throw new Error('Trust intelligence response was empty');
        apply(payload.data as T);
      } catch (err) {
        console.error(`Trust fabric ${view} load failed:`, err);
        setError(err instanceof Error ? err.message : 'Unable to load trust intelligence');
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
        // ':' comment lines are heartbeats - ignored.
      }
      if (!dataLines.length) return;
      const body = dataLines.join('\n');
      if (eventName === 'trust-fabric') {
        try {
          const parsed = JSON.parse(body) as T;
          // Event validation: a frame for another view must never be applied.
          if (parsed && typeof parsed === 'object' && parsed.view === view) apply(parsed);
        } catch {
          /* malformed frame - ignore rather than blank the page */
        }
      } else if (eventName === 'trust-fabric-unchanged') {
        // Re-verified by the server with no content change: freshness advances.
        setLastSyncedAt(new Date().toISOString());
        setLive(true);
      } else if (eventName === 'trust-fabric-error') {
        try {
          setError(String(JSON.parse(body)?.message || 'Trust telemetry stream error'));
        } catch {
          /* ignore */
        }
      }
    };

    const connect = async () => {
      try {
        const response = await fetch(`${API_BASE[view]}/stream`, {
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

  /* ---- Tenant change: nothing from the previous tenant may remain ---- */
  useEffect(() => {
    lastGeneratedRef.current = 0;
    setData(null);
    setLastSyncedAt(null);
  }, [user?.id]);

  /* ---- Supabase realtime: nudge on the tenant's own writes -------- */
  useEffect(() => {
    if (!user) return;
    // Unique per user AND hook instance (common-issues #63).
    const instance = nextRealtimeInstance++;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`trust-fabric-${view}-${table}-${user.id}-${instance}`)
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
/* Named wrappers - one per page                                       */
/* ------------------------------------------------------------------ */

export const useTrustDashboard = () => useTrustFabricView<TrustPayload>('trust');
export const useTrustStateDiscovery = () => useTrustFabricView<DiscoveryPayload>('discovery');
export const useCertificateTelemetry = () => useTrustFabricView<CertificatePayload>('certificate');
export const useMultiCloudTelemetry = () => useTrustFabricView<CloudPayload>('cloud');

/* ------------------------------------------------------------------ */
/* Lazy drill-down (section 11)                                        */
/* ------------------------------------------------------------------ */

/**
 * Fetches the full investigation record for one subject.
 *
 * The dashboard payloads deliberately do not ship every edge and every finding
 * for every node; the drawer asks for the one the user actually opened. An
 * in-flight request is aborted when a newer one starts, so rapid clicking
 * through a table cannot land an older response on a newer drawer.
 */
export function useTrustFabricDetail(view: TrustView) {
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
        const response = await fetch(`${API_BASE[view]}${path}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        return (payload.data ?? null) as R | null;
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') return null;
        console.error('Trust fabric detail load failed:', err);
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

  const loadNode = useCallback((id: string) => load<NodeDetail>(`/nodes/${encodeURIComponent(id)}`), [load]);
  const loadCertificate = useCallback((id: string) => load<CertificateDetail>(`/certificates/${encodeURIComponent(id)}`), [load]);
  const loadCloudResource = useCallback(
    (id: string) => load<CloudResourceDetail>(`/cloud-resources/${encodeURIComponent(id)}`),
    [load],
  );

  return { loadNode, loadCertificate, loadCloudResource, loading, detailError };
}

/* ------------------------------------------------------------------ */
/* Server-side paged tables (section 15)                               */
/* ------------------------------------------------------------------ */

export interface PagedQuery {
  [key: string]: string | number | undefined;
}

/**
 * useTrustPagedResource - server-side search, filter, sort and paging.
 *
 * Large estates must never ship thousands of rows to the browser to display
 * fifty. Filtering happens on the API against the cached model, so paging costs
 * nothing extra and every page of results is derived from the same snapshot the
 * KPI strip was computed from.
 *
 * `revision` is bumped by the view hook whenever the live model updates, so an
 * open table refreshes in step with the rest of the page.
 */
export function useTrustPagedResource<T>(
  view: TrustView,
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
        const response = await fetch(`${API_BASE[view]}${path}?${params.toString()}`, {
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
        console.error('Trust fabric table load failed:', err);
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
/* Shared filter state (section 10)                                    */
/* ------------------------------------------------------------------ */

export interface TrustFilters {
  search: string;
  state: string;
  kind: string;
  environment: string;
  provider: string;
  account: string;
  region: string;
  posture: string;
  risk: string;
  severity: string;
  algorithm: string;
  tlsVersion: string;
  issuer: string;
  owner: string;
  band: string;
  encryption: string;
  compliance: string;
  attribution: string;
  renewal: string;
  issue: string;
  range: string;
  sort: string;
}

export const EMPTY_FILTERS: TrustFilters = {
  search: '',
  state: 'all',
  kind: 'all',
  environment: 'all',
  provider: 'all',
  account: 'all',
  region: 'all',
  posture: 'all',
  risk: 'all',
  severity: 'all',
  algorithm: 'all',
  tlsVersion: 'all',
  issuer: 'all',
  owner: 'all',
  band: 'all',
  encryption: 'all',
  compliance: 'all',
  attribution: 'all',
  renewal: 'all',
  issue: 'all',
  range: 'all',
  sort: '',
};

/**
 * One filter object shared by every widget and table on a page, so a provider
 * chosen in the header narrows the chart and the table together rather than
 * only one of them (section 10: "filters should remain synchronized").
 */
export function useTrustFilters(initial?: Partial<TrustFilters>) {
  const [filters, setFilters] = useState<TrustFilters>({ ...EMPTY_FILTERS, ...initial });

  const setFilter = useCallback((key: keyof TrustFilters, value: string) => {
    setFilters((current) => (current[key] === value ? current : { ...current, [key]: value }));
  }, []);

  const reset = useCallback(() => setFilters({ ...EMPTY_FILTERS, ...initial }), [initial]);

  const activeCount = useMemo(
    () =>
      (Object.keys(filters) as Array<keyof TrustFilters>).filter((key) => {
        if (key === 'sort') return false;
        const value = filters[key];
        return value !== '' && value !== 'all';
      }).length,
    [filters],
  );

  return { filters, setFilter, setFilters, reset, activeCount };
}
