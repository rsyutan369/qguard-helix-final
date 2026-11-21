'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type { HandoffReview } from '@/lib/migration/planner-progress';

/**
 * useMigrationAssets — the asset-centric layer of the Migration Planner.
 *
 * Serves the enterprise asset selector (bounded, filterable, paginated), the
 * per-asset migration dossier, the persisted migration queue and the Live
 * Migration handoff. Every value is fetched from /api/v1/migration-planner,
 * which derives it from the SAME engine as the Quantum Readiness snapshot — the
 * hook never recomputes or reshapes a metric locally.
 *
 * Live synchronisation: Supabase realtime on the tenant's evidence tables
 * refreshes the selector and the open dossier in place (throttled to avoid the
 * reload storms a burst of scanner writes would otherwise cause), preserving the
 * current selection and flagging which values changed.
 */

/* ------------------------------------------------------------------ */
/* Contract                                                            */
/* ------------------------------------------------------------------ */

export type Posture = 'pqc' | 'hybrid' | 'vulnerable';
export type MigrationReservation = 'submitted' | 'in-execution' | null;

export interface AssetSummaryRecord {
  id: string;
  name: string;
  type: string;
  hostname: string;
  environment: string;
  owner: string;
  businessCriticality: string;
  internetFacing: boolean;
  hasEvidence: boolean;
  riskScore: number;
  riskLevel: string;
  readinessScore: number;
  readinessLevel: string;
  posture: Posture;
  postureLabel: string;
  priority: string;
  priorityScore: number;
  hndlScore: number;
  hndlLevel: string;
  migrationStatus: string;
  migrationProgressPct: number;
  estimatedDurationLabel: string;
  estimatedEffortHours: number;
  cryptoPostureSummary: string;
  componentCount: number;
  vulnerableComponentCount: number;
  severityCounts: { critical: number; high: number; medium: number; low: number };
  blastRadius: number;
  successProbabilityPct: number;
  queued: boolean;
  reservation?: MigrationReservation;
  tags: string[];
  lastEvidenceAt: string | null;
}

export interface AssetAlgorithm {
  algorithm: string;
  classification: 'vulnerable' | 'pqc' | 'hybrid' | 'unknown';
  instances: number;
  keySizes: number[];
  protocols: string[];
  target: string;
  standard: string;
  rationale: string;
  severity: string;
  category: 'key-establishment' | 'signature' | 'symmetric' | 'hash' | 'protocol' | 'unknown';
}

export interface AssetDossier extends AssetSummaryRecord {
  region: string;
  discoveredAt: string | null;
  migrationStatusDetail: string;
  estimatedDowntime: string;
  pqcComponentCount: number;
  hybridComponentCount: number;
  algorithms: AssetAlgorithm[];
  certificates: Array<{
    id: string; name: string; algorithm: string; keySize: number; issuer: string;
    notAfter: string | null; daysToExpiry: number | null; quantumSafe: boolean; status: string;
  }>;
  tlsConfiguration: { protocols: string[]; cipherSuites: string[]; keyExchange: string[]; forwardSecrecy: string; summary: string };
  findings: Array<{ id: string; title: string; severity: string; algorithm: string; source: string; description: string; detectedAt: string | null; instances: number }>;
  dependencies: Array<{ id: string; name: string; direction: 'upstream' | 'downstream'; relationship: string; posture: Posture | 'unknown'; riskScore: number }>;
  priorityFactors: Array<{ key: string; label: string; score: number; weight: number; contribution: number; evidence: string }>;
  riskAnalysis: { categories: Array<{ key: string; label: string; score: number }>; overall: number; overallLevel: string; explanation: string };
  businessImpact: { revenueImpact: string; operationalImpact: string; complianceImpact: string; customerFacing: boolean; dependents: number; summary: string };
  compatibility: { level: string; score: number; notes: string[] };
  recommendations: Array<{ id: string; title: string; detail: string; severity: string; standard: string; effort: string }>;
  rollbackStrategy: { available: boolean; strategy: string; steps: string[]; recoveryObjective: string };
  requiredApprovals: Array<{ role: string; reason: string; required: boolean }>;
  compliance: Array<{ framework: string; control: string; status: string; detail: string }>;
  timeline: Array<{ phase: string; durationHours: number; owner: string; description: string }>;
  validation: { records: number; lastStatus: string; lastAt: string | null; cutoverBlocked: boolean; blockerReason: string; validated: boolean };
  jobs: Array<{ id: string; status: string; progress: number; jobType: string; targetAlgorithm: string; updatedAt: string; planId: string | null; error: string | null }>;
  latestSandbox: { status: string; updatedAt: string | null; planId: string | null } | null;
  evidence: { sources: string[]; scanResults: number; exposures: number; runtimeEvents: number; certificates: number; components: number; note: string };
}

export interface PortfolioSummary {
  vulnerableAssets: number;
  immediateAttention: number;
  verifiedMigrations: number;
  pendingMigrations: number;
  activeMigrations: number;
  failedMigrations: number;
  unverifiedCompletions: number;
  total: number;
  quantumVulnerable: number;
  hybrid: number;
  pqcReady: number;
  internetFacing: number;
  criticalPriority: number;
  highPriority: number;
  notStarted: number;
  inProgress: number;
  completed: number;
  queued: number;
  averageReadiness: number;
  totalEffortHours: number;
}

export interface QueueEntry {
  reservation?: MigrationReservation;
  sequence: number;
  assetId: string;
  name: string;
  type: string;
  environment: string;
  owner: string;
  priority: string;
  priorityScore: number;
  riskScore: number;
  readinessScore: number;
  estimatedDurationLabel: string;
  estimatedEffortHours: number;
  migrationStatus: string;
  dependencies: number;
  blastRadius: number;
  validationState: string;
  successProbabilityPct: number;
  posture: Posture;
  postureLabel: string;
  targets: string[];
}

export interface AssetFilters {
  search: string;
  posture: string;
  environment: string;
  priority: string;
  status: string;
  sort: string;
}

export const DEFAULT_ASSET_FILTERS: AssetFilters = {
  search: '',
  posture: 'all',
  environment: 'all',
  priority: 'all',
  status: 'all',
  sort: 'name',
};

interface PortfolioResponse {
  generatedAt: string;
  assets: AssetSummaryRecord[];
  total: number;
  totalUnfiltered: number;
  summary: PortfolioSummary;
  recommendedOrder: Array<{ rank: number; assetId: string; name: string; priority: string; priorityScore: number; riskScore: number; rationale: string }>;
  environments: string[];
  reconciliation: {
    snapshot: { assetsAssessed: number; quantumVulnerableAssets: number; pqcReadyAssets: number; hybridAssets: number; vulnerableComponents: number };
    portfolio: { assetsAssessed: number; quantumVulnerableAssets: number; pqcReadyAssets: number; hybridAssets: number; vulnerableComponents: number };
    aligned: boolean;
    note: string;
  };
}

const EMPTY_PORTFOLIO: PortfolioResponse = {
  generatedAt: '',
  assets: [],
  total: 0,
  totalUnfiltered: 0,
  summary: {
    vulnerableAssets: 0, immediateAttention: 0, verifiedMigrations: 0, pendingMigrations: 0,
    activeMigrations: 0, failedMigrations: 0, unverifiedCompletions: 0,
    total: 0, quantumVulnerable: 0, hybrid: 0, pqcReady: 0, internetFacing: 0,
    criticalPriority: 0, highPriority: 0, notStarted: 0, inProgress: 0, completed: 0,
    queued: 0, averageReadiness: 0, totalEffortHours: 0,
  },
  recommendedOrder: [],
  environments: [],
  reconciliation: {
    snapshot: { assetsAssessed: 0, quantumVulnerableAssets: 0, pqcReadyAssets: 0, hybridAssets: 0, vulnerableComponents: 0 },
    portfolio: { assetsAssessed: 0, quantumVulnerableAssets: 0, pqcReadyAssets: 0, hybridAssets: 0, vulnerableComponents: 0 },
    aligned: true,
    note: '',
  },
};

/** Tables whose mutations change an asset's migration posture. */
const REALTIME_TABLES = [
  'assets', 'crypto_inventory', 'pqc_scan_results', 'crypto_exposures',
  'certificates', 'runtime_crypto_events', 'asset_relationships',
  'migration_jobs', 'migration_plans', 'migration_validation_logs',
];

/** Dossier fields whose change is worth flagging to an operator mid-review. */
const WATCHED_FIELDS: Array<keyof AssetDossier> = [
  'riskScore', 'readinessScore', 'priority', 'priorityScore', 'posture',
  'migrationStatus', 'migrationProgressPct', 'componentCount',
  'vulnerableComponentCount', 'hndlScore', 'successProbabilityPct',
  'latestSandbox', 'validation',
];

function diffFields(previous: AssetDossier | null, next: AssetDossier): string[] {
  if (!previous || previous.id !== next.id) return [];
  return WATCHED_FIELDS.filter((field) => JSON.stringify(previous[field]) !== JSON.stringify(next[field])) as string[];
}

/* ------------------------------------------------------------------ */
/* Hook                                                                */
/* ------------------------------------------------------------------ */

export function useMigrationAssets(streamVerifiedAt: string | null) {
  const { session, user } = useAuth();
  const token = session?.access_token;

  const [filters, setFilters] = useState<AssetFilters>(DEFAULT_ASSET_FILTERS);
  const [portfolio, setPortfolio] = useState<PortfolioResponse>(EMPTY_PORTFOLIO);
  const [portfolioLoading, setPortfolioLoading] = useState(true);
  const [page, setPage] = useState(0);
  const pageSize = 100;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [dossier, setDossier] = useState<AssetDossier | null>(null);
  const [position, setPosition] = useState<{ recommendedRank: number | null; totalRanked: number; rationale: string; riskPercentile: number } | null>(null);
  const [dossierLoading, setDossierLoading] = useState(false);
  const [changedFields, setChangedFields] = useState<string[]>([]);
  const [queue, setQueue] = useState<{ planId: string; entries: QueueEntry[]; totalEffortHours: number; outOfOrder: string[]; updatedAt: string | null }>({
    planId: '', entries: [], totalEffortHours: 0, outOfOrder: [], updatedAt: null,
  });
  const [error, setError] = useState<string | null>(null);
  const [portfolioError, setPortfolioError] = useState<string | null>(null);
  const [dossierError, setDossierError] = useState<string | null>(null);
  const [queueError, setQueueError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const actionPending = useRef(false);

  const dossierRef = useRef<AssetDossier | null>(null);
  const selectedRef = useRef<string | null>(null);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const refreshEvidence = useRef(false);
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const filtersRef = useRef(filters);
  const pageRef = useRef(page);
  const portfolioRequest = useRef(0);
  const dossierRequest = useRef(0);
  const queueRequest = useRef(0);
  filtersRef.current = filters;
  pageRef.current = page;
  selectedRef.current = selectedId;

  const authHeaders = useMemo(
    () => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${token || ''}` }),
    [token],
  );

  const request = useCallback(
    async (path: string, init?: RequestInit) => {
      const response = await fetch(`/api/v1/migration-planner${path}`, { ...init, headers: authHeaders });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      return payload.data;
    },
    [authHeaders],
  );

  /* ---- portfolio ---- */
  const loadPortfolio = useCallback(async (force = false) => {
    if (!token) return;
    const generation = ++portfolioRequest.current;
    const active = filtersRef.current;
    const activePage = pageRef.current;
    const params = new URLSearchParams({
      search: active.search,
      posture: active.posture,
      environment: active.environment,
      priority: active.priority,
      status: active.status,
      sort: active.sort,
      limit: String(pageSize),
      offset: String(activePage * pageSize),
    });
    if (force) params.set('refresh', '1');
    try {
      const data = (await request(`/assets?${params.toString()}`)) as PortfolioResponse;
      if (generation !== portfolioRequest.current || filtersRef.current !== active || pageRef.current !== activePage) return;
      if (activePage && activePage * pageSize >= data.total) setPage(Math.max(0, Math.ceil(data.total / pageSize) - 1));
      setPortfolio({ ...EMPTY_PORTFOLIO, ...data });
      setPortfolioError(null);
    } catch (err) {
      if (generation === portfolioRequest.current) setPortfolioError(err instanceof Error ? err.message : 'Unable to load the asset portfolio');
    } finally {
      if (generation === portfolioRequest.current) setPortfolioLoading(false);
    }
  }, [request, token]);

  /* ---- dossier ---- */
  const loadDossier = useCallback(
    async (assetId: string, options: { silent?: boolean } = {}) => {
      if (!token) return;
      const generation = ++dossierRequest.current;
      if (!options.silent) setDossierLoading(true);
      try {
        const data = (await request(`/assets/${encodeURIComponent(assetId)}`)) as { asset: AssetDossier; position: typeof position };
        // A late response for a superseded selection must never overwrite the
        // asset the operator is now looking at.
        if (selectedRef.current !== assetId || generation !== dossierRequest.current) return;
        const changed = options.silent ? diffFields(dossierRef.current, data.asset) : [];
        dossierRef.current = data.asset;
        setDossier(data.asset);
        setPosition(data.position);
        if (changed.length) {
          setChangedFields(changed);
          if (highlightTimer.current) clearTimeout(highlightTimer.current);
          highlightTimer.current = setTimeout(() => setChangedFields([]), 6000);
        }
        setDossierError(null);
      } catch (err) {
        if (selectedRef.current === assetId && generation === dossierRequest.current) setDossierError(err instanceof Error ? err.message : 'Unable to load the asset dossier');
      } finally {
        if (generation === dossierRequest.current) setDossierLoading(false);
      }
    },
    [request, token],
  );

  /* ---- queue ---- */
  const loadQueue = useCallback(async () => {
    if (!token) return;
    const generation = ++queueRequest.current;
    try {
      const data = await request('/queue');
      if (generation !== queueRequest.current) return;
      setQueue({ planId: data.planId, entries: data.entries || [], totalEffortHours: data.totalEffortHours || 0, outOfOrder: data.outOfOrder || [], updatedAt: data.updatedAt || null });
      setQueueError(null);
    } catch (err) {
      if (generation === queueRequest.current) setQueueError(err instanceof Error ? err.message : 'Unable to load the migration queue');
    }
  }, [request, token]);

  const mutateQueue = useCallback(
    async (label: string, run: () => Promise<unknown>) => {
      if (actionPending.current) return;
      actionPending.current = true;
      setBusy(label);
      setError(null);
      try {
        const data = (await run()) as { planId: string; entries: QueueEntry[]; totalEffortHours: number; outOfOrder: string[]; updatedAt: string | null };
        if (data?.entries) {
          ++queueRequest.current;
          setQueue({ planId: data.planId, entries: data.entries, totalEffortHours: data.totalEffortHours || 0, outOfOrder: data.outOfOrder || [], updatedAt: data.updatedAt || null });
          setQueueError(null);
        }
        await Promise.all([loadPortfolio(), selectedRef.current && loadDossier(selectedRef.current, { silent: true })]);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Queue update failed');
        await loadQueue();
      } finally {
        actionPending.current = false;
        setBusy(null);
      }
    },
    [loadDossier, loadPortfolio, loadQueue],
  );

  const enqueue = useCallback(
    (assetIds: string[]) => mutateQueue('enqueue', () => request('/queue', { method: 'POST', body: JSON.stringify({ assetIds }) })),
    [mutateQueue, request],
  );
  const dequeue = useCallback(
    (assetId: string) => mutateQueue('dequeue', () => request(`/queue/${encodeURIComponent(assetId)}`, { method: 'DELETE' })),
    [mutateQueue, request],
  );
  const reorderQueue = useCallback(
    (assetIds: string[]) => mutateQueue('reorder', () => request('/queue/reorder', { method: 'POST', body: JSON.stringify({ assetIds }) })),
    [mutateQueue, request],
  );
  const applyRecommendedOrder = useCallback(
    () => mutateQueue('prioritize', () => request('/queue/prioritize', { method: 'POST' })),
    [mutateQueue, request],
  );

  /* ---- Live Migration handoff ---- */
  /**
   * Dispatches through the platform's existing execution pipeline
   * (POST /api/v1/migration/planner/create, action=start) so real migration_jobs
   * and dispatch bookkeeping are created exactly as the rest of the platform
   * expects, then stamps the server-derived migration context onto the plan and
   * returns the Live Migration deep link.
   */
  const sendToLiveMigration = useCallback(
    async (approvalPlanId: string, assetIds: string[], handoffReview: HandoffReview) => {
      if (!token) throw new Error('Authentication required');
      if (!approvalPlanId || !assetIds.length) throw new Error('Choose an approved proposal with assets in scope.');
      if (actionPending.current) throw new Error('Another migration action is in progress.');
      actionPending.current = true;
      setBusy('dispatch');
      setError(null);
      try {
        const response = await fetch('/api/v1/migration/planner/create', {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ action: 'start', approvalPlanId, assetIds, handoffReview }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || 'Failed to hand off to Live Migration');
        const createdPlanId = payload?.data?.planId;
        if (!createdPlanId) throw new Error('Live Migration did not return a plan identifier.');

        // Stamp the authoritative, server-derived migration context onto the plan
        // so Live Migration loads the same intelligence the planner displayed.
        await request(`/plans/${encodeURIComponent(createdPlanId)}/context`, {
          method: 'POST',
          body: JSON.stringify({ assetIds }),
        }).catch(() => undefined);

        await Promise.all([loadPortfolio(), loadQueue()]);
        return { planId: createdPlanId };
      } finally {
        actionPending.current = false;
        setBusy(null);
      }
    },
    [authHeaders, loadPortfolio, loadQueue, request, token],
  );

  /* ---- selection ---- */
  const selectAsset = useCallback(
    (assetId: string | null) => {
      setSelectedId(assetId);
      selectedRef.current = assetId;
      setChangedFields([]);
      setDossierError(null);
      if (!assetId) {
        ++dossierRequest.current;
        setDossierLoading(false);
        dossierRef.current = null;
        setDossier(null);
        setPosition(null);
        return;
      }
      // Keep the previous dossier mounted while the new one loads when the
      // operator is switching assets, so panels fade rather than flash empty.
      void loadDossier(assetId);
    },
    [loadDossier],
  );

  /* ---- live synchronisation ---- */
  const queueRefresh = useCallback((force = false) => {
    if (force) refreshEvidence.current = true;
    if (refreshTimer.current) return;
    refreshTimer.current = setTimeout(async () => {
      refreshTimer.current = null;
      const fresh = refreshEvidence.current;
      refreshEvidence.current = false;
      if (fresh) await loadPortfolio(true);
      else void loadPortfolio();
      void loadQueue();
      const active = selectedRef.current;
      if (active) void loadDossier(active, { silent: true });
    }, 900);
  }, [loadDossier, loadPortfolio, loadQueue]);

  useEffect(() => {
    if (streamVerifiedAt) queueRefresh();
  }, [streamVerifiedAt, queueRefresh]);

  useEffect(() => {
    if (!token) {
      setPortfolioLoading(false);
      return;
    }
    void loadQueue();
  }, [token, loadQueue]);

  // Single portfolio effect: covers both mount and filter changes. Keeping these
  // in one effect matters — the portfolio request rebuilds the whole tenant
  // evidence set, so a duplicate mount fetch would double that cost and burn one
  // of the browser's limited concurrent connections to the origin (this page also
  // holds a long-lived SSE stream). Typing is debounced; other filters apply at once.
  useEffect(() => {
    if (!token) return;
    const timer = setTimeout(() => void loadPortfolio(), filters.search ? 300 : 0);
    return () => clearTimeout(timer);
  }, [filters, page, token, loadPortfolio]);

  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`migration-assets-${user.id}-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, () => queueRefresh(true))
        .subscribe(),
    );
    return () => { for (const channel of channels) supabase.removeChannel(channel); };
  }, [user, queueRefresh]);

  useEffect(() => () => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    if (highlightTimer.current) clearTimeout(highlightTimer.current);
  }, []);

  return {
    filters,
    setFilters: useCallback((next: AssetFilters) => { setPage(0); setFilters(next); }, []),
    page,
    setPage,
    pageSize,
    portfolio,
    portfolioLoading,
    selectedId,
    selectAsset,
    dossier,
    position,
    dossierLoading,
    changedFields,
    queue,
    enqueue,
    dequeue,
    reorderQueue,
    applyRecommendedOrder,
    sendToLiveMigration,
    refresh: useCallback(async () => {
      await loadPortfolio(true);
      await Promise.all([loadQueue(), selectedRef.current && loadDossier(selectedRef.current, { silent: true })]);
    }, [loadDossier, loadPortfolio, loadQueue]),
    error,
    portfolioError,
    dossierError,
    queueError,
    busy,
  };
}
