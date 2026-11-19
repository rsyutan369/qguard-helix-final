'use client';

import type { SourceRead } from '@/lib/source-read';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useLiveModel } from '@/hooks/use-live-resource';
import type {
  ConfigurationDrift,
  DistributionRow,
  OrchestrationItem,
  OrchestrationState,
  PkiCertificate,
  PqcTlsPosture,
  ProtocolAnalytics,
  TelemetryHealth,
  TlsEndpoint,
  TlsFinding,
  TlsObservation,
  TrustChainNode,
} from '@/lib/tls-pki/types';

export type LoadState = 'loading' | 'success' | 'error';
export type TlsPkiView = 'telemetry' | 'pki' | 'protocol' | 'orchestrator';

/* ------------------------------------------------------------------ */
/* Payload shapes - mirror `projectView()` in src/api-server/tls-pki.ts */
/* ------------------------------------------------------------------ */

interface CommonPayload {
  generatedAt: string;
  latestEvidenceAt: string | null;
  hasData: boolean;
  /** Outcome of every source read. `unavailable` = the query FAILED, so dependent figures are incomplete, not zero. */
  reads: SourceRead[];
  posture: PqcTlsPosture;
  telemetry: TelemetryHealth;
  timeline: Array<{ label: string; date: string; observations: number; certificates: number; findings: number }>;
  totals: {
    endpoints: number;
    /** Endpoints with real transport evidence - the TLS percentage denominator. */
    measuredEndpoints: number;
    certificates: number;
    findings: number;
    /** Weaknesses this engine derives from a measured observation. */
    findingsDerived: number;
    /** Findings the scanner itself reported (reconciles with Scanner counts). */
    findingsFromScanner: number;
    observations: number;
    orchestrationItems: number;
  };
}

export type EndpointSummary = Pick<
  TlsEndpoint,
  'id' | 'assetId' | 'name' | 'host' | 'port' | 'environment' | 'internetFacing' | 'posture' | 'riskLevel' | 'riskScore' | 'negotiatedVersion' | 'transportBasis'
>;

export interface TelemetryPayload extends CommonPayload {
  view: 'telemetry';
  endpoints: TlsEndpoint[];
  versionDistribution: DistributionRow[];
  keyExchangeDistribution: DistributionRow[];
  cipherDistribution: DistributionRow[];
  forwardSecrecy: ProtocolAnalytics['forwardSecrecy'];
  findings: TlsFinding[];
  anomalies: ProtocolAnalytics['anomalies'];
  handshake: { failures: number; measured: boolean; downgradeEndpoints: number; downgradeMeasured: boolean };
}

export interface PkiPayload extends CommonPayload {
  view: 'pki';
  certificates: PkiCertificate[];
  lifecycle: { valid: number; expiring: number; expired: number; revoked: number; notYetValid: number; unknown: number };
  expiryBuckets: Array<{ label: string; count: number; percent: number; certificateIds: string[] }>;
  issuers: Array<{
    issuer: string;
    certificates: number;
    expiring: number;
    expired: number;
    quantumVulnerable: number;
    pqcReady: number;
    averageRisk: number;
    certificateIds: string[];
  }>;
  algorithmDistribution: Array<{ label: string; count: number; percent: number; posture: PkiCertificate['posture']; certificateIds: string[] }>;
  trustChains: TrustChainNode[];
  findings: TlsFinding[];
  endpointIndex: EndpointSummary[];
}

export interface ProtocolPayload extends CommonPayload {
  view: 'protocol';
  protocol: ProtocolAnalytics;
  endpointIndex: EndpointSummary[];
  findings: TlsFinding[];
}

export interface OrchestratorPayload extends CommonPayload {
  queuedAssetIds: string[];
  view: 'orchestrator';
  orchestration: OrchestrationState;
  endpointIndex: EndpointSummary[];
  findings: TlsFinding[];
}

export type TlsPkiPayload = TelemetryPayload | PkiPayload | ProtocolPayload | OrchestratorPayload;

export interface EndpointDetail {
  endpoint: TlsEndpoint;
  observations: TlsObservation[];
  certificates: PkiCertificate[];
  findings: TlsFinding[];
  orchestration: OrchestrationItem[];
}

export interface CertificateDetail {
  certificate: PkiCertificate;
  endpoint: TlsEndpoint | null;
  findings: TlsFinding[];
  chain: TrustChainNode[];
}

/* ------------------------------------------------------------------ */
/* Wiring                                                              */
/* ------------------------------------------------------------------ */

const API_BASE: Record<TlsPkiView, string> = {
  telemetry: '/api/v1/dashboard/tls-telemetry',
  pki: '/api/v1/dashboard/pki-visibility',
  protocol: '/api/v1/dashboard/protocol-analytics',
  orchestrator: '/api/v1/dashboard/tls-orchestrator',
};

/**
 * Tables whose mutation can change what these pages show.
 *
 * Deliberately the union across all four views: a certificate write must nudge
 * TLS Telemetry (its endpoint expiry column) as well as PKI Visibility, or the
 * two pages drift apart until the next 10s push - which is exactly the kind of
 * disagreement this refactor exists to remove.
 */
const REALTIME_TABLES = [
  'assets',
  'runtime_crypto_events',
  'crypto_inventory',
  'certificates',
  'scanner_evidence',
  'pqc_scan_results',
  'pqc_scan_sessions',
  'crypto_exposures',
  'scanner_alerts',
  'security_events',
  'migration_jobs',
  'migration_plans',
  'scanner_agents',
] as const;

export interface UseTlsPkiResult<T extends TlsPkiPayload> {
  data: T | null;
  state: LoadState;
  error: string | null;
  live: boolean;
  lastSyncedAt: string | null;
  refresh: (force?: boolean) => Promise<void>;
  reconnect: () => void;
}

export function useTlsPkiView<T extends TlsPkiPayload>(view: TlsPkiView): UseTlsPkiResult<T> {
  const url = API_BASE[view];
  const model = useLiveModel<T>({
    url,
    streamUrl: url + '/stream',
    event: 'tls-pki',
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'tls-pki-' + view,
    validate: (value) => value.view === view && typeof value.generatedAt === 'string',
  });
  return { ...model, lastSyncedAt: model.lastVerifiedAt };
}

export const useTlsTelemetry = () => useTlsPkiView<TelemetryPayload>('telemetry');
export const usePkiVisibility = () => useTlsPkiView<PkiPayload>('pki');
export const useProtocolAnalytics = () => useTlsPkiView<ProtocolPayload>('protocol');
export const useTlsOrchestrator = () => useTlsPkiView<OrchestratorPayload>('orchestrator');

/* ------------------------------------------------------------------ */
/* Lazy drill-down                                                     */
/* ------------------------------------------------------------------ */

/**
 * Fetches the full investigation record for one endpoint or certificate.
 *
 * The dashboard payloads deliberately do not ship every observation for every
 * endpoint; the drawer asks for the one the user actually opened.
 */
export function useTlsPkiDetail(view: TlsPkiView) {
  const { session } = useAuth();
  const token = session?.access_token;
  const pending = useRef<AbortController | null>(null);
  const [loading, setLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  useEffect(() => () => pending.current?.abort(), [view]);

  const load = useCallback(
    async <R,>(path: string): Promise<R | null> => {
      if (!token) return null;
      pending.current?.abort();
      const controller = new AbortController();
      pending.current = controller;
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
        return (payload.data ?? null) as R | null;
      } catch (err) {
        if (controller.signal.aborted) return null;
        console.error('TLS/PKI detail load failed:', err);
        setDetailError(err instanceof Error ? err.message : 'Unable to load detail');
        return null;
      } finally {
        if (pending.current === controller && !controller.signal.aborted) setLoading(false);
      }
    },
    [token, view],
  );

  const loadEndpoint = useCallback((id: string) => load<EndpointDetail>(`/endpoints/${encodeURIComponent(id)}`), [load]);
  const loadCertificate = useCallback((id: string) => load<CertificateDetail>(`/certificates/${encodeURIComponent(id)}`), [load]);

  return { loadEndpoint, loadCertificate, loading, detailError };
}

/* ------------------------------------------------------------------ */
/* Orchestrator actions - every one calls a real backend               */
/* ------------------------------------------------------------------ */

export type ActionState = 'idle' | 'busy' | 'done' | 'error';

/**
 * The remediation actions the TLS Orchestrator can genuinely perform.
 *
 * Queueing and plan submission go to the Migration Planner's own tenant-verified
 * endpoints rather than to a second queue writer, so the orchestrator and the
 * planner cannot hold different queues. Nothing here simulates a change: if the
 * platform cannot do it, the button is not rendered (see `availableActions` on
 * each item).
 */
export function useTlsOrchestratorActions(onChanged?: () => void) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [actionState, setActionState] = useState<ActionState>('idle');
  const [actionError, setActionError] = useState<string | null>(null);
  const [pendingId, setPendingId] = useState<string | null>(null);

  const authHeaders = useMemo(
    () => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${token ?? ''}` }),
    [token],
  );

  /** Drops the server's cached model so the next read shows the new state. */
  const invalidate = useCallback(async () => {
    if (!token) return;
    try {
      await fetch('/api/v1/dashboard/tls-orchestrator/invalidate', { method: 'POST', headers: authHeaders });
    } catch {
      /* cache invalidation is an optimisation - the 15s TTL covers it anyway */
    }
  }, [token, authHeaders]);

  const run = useCallback(
    async (id: string, work: () => Promise<Response>) => {
      if (!token) return false;
      setPendingId(id);
      setActionState('busy');
      setActionError(null);
      try {
        const response = await work();
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        }
        await invalidate();
        setActionState('done');
        onChanged?.();
        return true;
      } catch (err) {
        console.error('TLS orchestrator action failed:', err);
        setActionError(err instanceof Error ? err.message : 'Action failed');
        setActionState('error');
        return false;
      } finally {
        setPendingId(null);
      }
    },
    [token, invalidate, onChanged],
  );

  const queueAsset = useCallback(
    (assetId: string) =>
      run(assetId, () =>
        fetch('/api/v1/migration-planner/queue', {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ assetId }),
        }),
      ),
    [run, authHeaders],
  );

  const unqueueAsset = useCallback(
    (assetId: string) =>
      run(assetId, () =>
        fetch(`/api/v1/migration-planner/queue/${encodeURIComponent(assetId)}`, { method: 'DELETE', headers: authHeaders }),
      ),
    [run, authHeaders],
  );

  const prioritizeQueue = useCallback(
    () => run('queue:prioritize', () => fetch('/api/v1/migration-planner/queue/prioritize', { method: 'POST', headers: authHeaders })),
    [run, authHeaders],
  );

  const submitPlan = useCallback(
    (name: string, assetIds: string[]) =>
      run('plan:submit', () =>
        fetch('/api/v1/migration-planner/plans', { method: 'POST', headers: authHeaders, body: JSON.stringify({ name, assetIds }) }),
      ),
    [run, authHeaders],
  );

  const resetAction = useCallback(() => {
    setActionState('idle');
    setActionError(null);
  }, []);

  return { queueAsset, unqueueAsset, prioritizeQueue, submitPlan, actionState, actionError, pendingId, resetAction };
}

/* ------------------------------------------------------------------ */
/* Server-side paged tables                                            */
/* ------------------------------------------------------------------ */

export interface PagedQuery {
  [key: string]: string | number | undefined;
}

/**
 * usePagedResource - server-side search, filter, sort and paging.
 *
 * Large estates must never ship thousands of rows to the browser to display
 * fifty. Filtering happens on the API against the cached model, so paging costs
 * nothing extra and every page of results is derived from the same snapshot the
 * KPI strip was computed from.
 *
 * `revision` is bumped by the caller whenever the live model updates, so an
 * open table refreshes in step with the rest of the page.
 */
export function usePagedResource<T>(
  view: TlsPkiView,
  path: string,
  key: string,
  query: PagedQuery,
  revision: number,
) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [rows, setRows] = useState<T[]>([]);
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
        if (controller.signal.aborted) return;
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        setRows((payload.data?.[key] ?? []) as T[]);
        setTotal(Number(payload.data?.total ?? 0));
        setError(null);
      } catch (err) {
        if (controller.signal.aborted) return;
        console.error('TLS/PKI table load failed:', err);
        setError(err instanceof Error ? err.message : 'Unable to load rows');
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
      // Debounced so typing in the search box does not fire a request per keystroke.
    }, 250);

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token, view, path, key, serialized, revision]);

  return { rows, total, loading, error };
}
