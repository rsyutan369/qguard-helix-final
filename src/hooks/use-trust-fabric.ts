'use client';

import type { SourceRead } from '@/lib/source-read';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useLiveModel } from '@/hooks/use-live-resource';
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
  incompleteChains: number;
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

export interface UseTrustFabricResult<T extends TrustFabricPayload> {
  data: T | null;
  state: LoadState;
  error: string | null;
  /** True while the stream is answering with usable snapshots. */
  live: boolean;
  lastSyncedAt: string | null;
  /** Identifies the applied model so paged tables can refresh in step. */
  revision: number;
  refresh: (force?: boolean) => Promise<void>;
  reconnect: () => void;
}

export function useTrustFabricView<T extends TrustFabricPayload>(view: TrustView): UseTrustFabricResult<T> {
  const url = API_BASE[view];
  const model = useLiveModel<T>({
    url,
    streamUrl: `${url}/stream`,
    event: 'trust-fabric',
    channelPrefix: `trust-fabric-${view}`,
    realtimeTables: REALTIME_TABLES,
    validate: (payload) =>
      payload.view === view && typeof payload.generatedAt === 'string' &&
      Number.isFinite(Date.parse(payload.generatedAt)) && Array.isArray(payload.reads) &&
      Boolean(payload.totals && payload.telemetry),
  });

  return {
    data: model.data,
    state: model.state,
    error: model.error,
    live: model.live,
    lastSyncedAt: model.lastVerifiedAt,
    revision: model.data ? Date.parse(model.data.generatedAt) : 0,
    refresh: model.refresh,
    reconnect: model.reconnect,
  };
}

/* ------------------------------------------------------------------ */
/* Named wrappers - one per page                                       */
/* ------------------------------------------------------------------ */

export const useTrustDashboard = () => useTrustFabricView<TrustPayload>('trust');
export const useTrustStateDiscovery = () => useTrustFabricView<DiscoveryPayload>('discovery');
export const useCertificateTelemetry = () => useTrustFabricView<CertificatePayload>('certificate');
export const useMultiCloudTelemetry = () => useTrustFabricView<CloudPayload>('cloud');

function useTrustAccount() {
  const { session, user } = useAuth();
  const accountId = user && session?.user.id === user.id ? user.id : null;
  return { accountId, token: accountId ? session?.access_token : undefined };
}

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
  const { accountId, token } = useTrustAccount();
  const [loading, setLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const inFlight = useRef<AbortController | null>(null);

  useLayoutEffect(() => {
    setLoading(false);
    setDetailError(null);
    return () => {
      inFlight.current?.abort();
      inFlight.current = null;
    };
  }, [accountId, token, view]);

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
        if (controller.signal.aborted) return null;
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!payload.data || typeof payload.data !== 'object') throw new Error('Trust detail response was empty');
        return payload.data as R;
      } catch (err) {
        if (controller.signal.aborted) return null;
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
  const { accountId, token } = useTrustAccount();
  const serialized = JSON.stringify(query);
  const scope = accountId ? JSON.stringify([accountId, view, path, key, serialized]) : null;
  const [result, setResult] = useState<{
    scope: string;
    rows: T[];
    extra: Record<string, unknown>;
    total: number;
  } | null>(null);
  const [request, setRequest] = useState<{ scope: string; loading: boolean; error: string | null } | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const retry = useCallback(() => setRetryCount((count) => count + 1), []);

  useEffect(() => {
    if (!token || !scope) return;
    const controller = new AbortController();
    setRequest({ scope, loading: true, error: null });
    const timer = setTimeout(async () => {
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
        if (controller.signal.aborted) return;
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!Array.isArray(payload.data?.[key]) || !Number.isSafeInteger(payload.data?.total) || payload.data.total < 0) {
          throw new Error('Trust inventory response was incomplete');
        }
        setResult({ scope, rows: payload.data[key] as T[], extra: payload.data, total: payload.data.total });
        setRequest({ scope, loading: false, error: null });
      } catch (err) {
        if (controller.signal.aborted) return;
        console.error('Trust fabric table load failed:', err);
        setRequest({ scope, loading: false, error: err instanceof Error ? err.message : 'Unable to load rows' });
      }
      // Debounced so typing in the search box does not fire a request per keystroke.
    }, 250);

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token, scope, view, path, key, serialized, revision, retryCount]);

  const current = result?.scope === scope ? result : null;
  const currentRequest = request?.scope === scope ? request : null;
  return {
    rows: current?.rows ?? [],
    extra: current?.extra ?? {},
    total: current?.total ?? 0,
    loading: Boolean(token && (currentRequest?.loading ?? true)),
    error: currentRequest?.error ?? null,
    retry,
  };
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
