'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';

export type MigrationPlannerRangeKey = '7d' | '30d' | '90d' | 'all';

export type MigrationPlannerMetricSnapshot = {
  overallProgress: number;
  assetsInScope: number;
  assetsInScopeDelta: string;
  migratedAssets: number;
  migratedDelta: string;
  highPriorityAssets: number;
  highPriorityDelta: string;
  riskReduced: number;
  riskReducedDelta: string;
  estimatedCompletion: string;
  remainingDays: number;
  activeJobs: number;
  runningJobs: number;
  failedJobs: number;
  completedJobs: number;
};

export type MigrationPlannerAsset = {
  id: string;
  assetId: string | null;
  name: string;
  type: string;
  environment: string;
  owner: string;
  currentAlgorithm: string;
  risk: number;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  priorityColor: string;
  targetSolution: string;
  status: string;
  statusColor: string;
  progress: number;
  detectedAt: string | null;
  hasActiveJob: boolean;
  jobId: string | null;
};

export type MigrationPlannerStep = {
  name: string;
  progress: number;
  status: 'completed' | 'active' | 'pending' | string;
};

export type MigrationPlannerPriority = {
  name: string;
  value: number;
  percent: string;
  color: string;
};

export type MigrationPlannerTimelinePhase = {
  name: string;
  dates: string;
  start: number;
  width: number;
  color: string;
  state: string;
};

export type MigrationPlannerRiskPoint = {
  day: string;
  value: number;
  completed: number;
  newRisk: number;
};

export type MigrationPlannerScenario = {
  mode: string;
  optimization: string;
  confidence: number;
  estimatedDuration: string;
  riskMitigation: number;
  assets: MigrationPlannerAsset[];
  recommendations: Array<{ title: string; detail: string }>;
  playbook: string[];
};

export type MigrationPlannerPlanAction = 'save' | 'export' | 'schedule' | 'start' | 'sandbox';

export type MigrationPlannerCreatePlanInput = {
  action?: MigrationPlannerPlanAction;
  assetIds?: string[];
  selectedAssets?: MigrationPlannerAsset[];
  configuration?: {
    currentAlgorithms?: string[];
    targetAlgorithms?: string[];
    deploymentStrategy?: string;
    controls?: {
      rollback?: boolean;
      validation?: boolean;
      compatibility?: boolean;
      hybridMode?: boolean;
      continuousMonitoring?: boolean;
      complianceValidation?: boolean;
    };
    scheduleAt?: string | null;
    tags?: string[];
    notes?: string;
  };
  limit?: number;
  planId?: string;
};

export type MigrationPlannerSnapshot = {
  generatedAt: string;
  range: { key: MigrationPlannerRangeKey; label: string; days: number | null };
  source: {
    latestActivityAt: string | null;
    latestScanAt: string | null;
    tables: Record<string, number>;
  };
  metrics: MigrationPlannerMetricSnapshot;
  roadmapSteps: MigrationPlannerStep[];
  priorityDistribution: MigrationPlannerPriority[];
  topAssets: MigrationPlannerAsset[];
  timelinePhases: MigrationPlannerTimelinePhase[];
  riskTrendPoints: MigrationPlannerRiskPoint[];
  simulation: {
    confidence: number;
    recommendations: Array<{ title: string; detail: string }>;
  };
  compliance: {
    nistPqc: number;
    policyEvidence: number;
    quantumReadyAssets: number;
    openBlockers: number;
  };
};

export const EMPTY_MIGRATION_PLANNER_SNAPSHOT: MigrationPlannerSnapshot = {
  generatedAt: '',
  range: { key: '7d', label: 'Last 7 Days', days: 7 },
  source: {
    latestActivityAt: null,
    latestScanAt: null,
    tables: {},
  },
  metrics: {
    overallProgress: 0,
    assetsInScope: 0,
    assetsInScopeDelta: '0',
    migratedAssets: 0,
    migratedDelta: '0',
    highPriorityAssets: 0,
    highPriorityDelta: '0',
    riskReduced: 0,
    riskReducedDelta: '0',
    estimatedCompletion: 'Not scheduled',
    remainingDays: 0,
    activeJobs: 0,
    runningJobs: 0,
    failedJobs: 0,
    completedJobs: 0,
  },
  roadmapSteps: [
    { name: 'DISCOVER', progress: 0, status: 'pending' },
    { name: 'ASSESS', progress: 0, status: 'pending' },
    { name: 'PLAN', progress: 0, status: 'pending' },
    { name: 'EXECUTE', progress: 0, status: 'pending' },
    { name: 'VALIDATE', progress: 0, status: 'pending' },
    { name: 'COMPLETE', progress: 0, status: 'pending' },
  ],
  priorityDistribution: [],
  topAssets: [],
  timelinePhases: [],
  riskTrendPoints: [],
  simulation: {
    confidence: 0,
    recommendations: [],
  },
  compliance: {
    nistPqc: 0,
    policyEvidence: 0,
    quantumReadyAssets: 0,
    openBlockers: 0,
  },
};

const CACHE_PREFIX = 'qguard-migration-planner:v1:';

function normalizeSnapshot(payload: unknown, range: MigrationPlannerRangeKey): MigrationPlannerSnapshot {
  const snapshot = (payload || {}) as Partial<MigrationPlannerSnapshot>;
  return {
    ...EMPTY_MIGRATION_PLANNER_SNAPSHOT,
    ...snapshot,
    range: { ...EMPTY_MIGRATION_PLANNER_SNAPSHOT.range, key: range, ...(snapshot.range || {}) },
    source: { ...EMPTY_MIGRATION_PLANNER_SNAPSHOT.source, ...(snapshot.source || {}), tables: { ...(snapshot.source?.tables || {}) } },
    metrics: { ...EMPTY_MIGRATION_PLANNER_SNAPSHOT.metrics, ...(snapshot.metrics || {}) },
    roadmapSteps: Array.isArray(snapshot.roadmapSteps) ? snapshot.roadmapSteps : EMPTY_MIGRATION_PLANNER_SNAPSHOT.roadmapSteps,
    priorityDistribution: Array.isArray(snapshot.priorityDistribution) ? snapshot.priorityDistribution : [],
    topAssets: Array.isArray(snapshot.topAssets) ? snapshot.topAssets : [],
    timelinePhases: Array.isArray(snapshot.timelinePhases) ? snapshot.timelinePhases : [],
    riskTrendPoints: Array.isArray(snapshot.riskTrendPoints) ? snapshot.riskTrendPoints : [],
    simulation: { ...EMPTY_MIGRATION_PLANNER_SNAPSHOT.simulation, ...(snapshot.simulation || {}) },
    compliance: { ...EMPTY_MIGRATION_PLANNER_SNAPSHOT.compliance, ...(snapshot.compliance || {}) },
  };
}

function hasPlannerData(snapshot: MigrationPlannerSnapshot) {
  return Boolean(
    snapshot.metrics.assetsInScope ||
    snapshot.metrics.activeJobs ||
    snapshot.topAssets.length ||
    snapshot.priorityDistribution.some((item) => item.value > 0),
  );
}

function readCache(key: string | null, range: MigrationPlannerRangeKey) {
  if (!key || typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;
    const snapshot = normalizeSnapshot(JSON.parse(raw), range);
    return hasPlannerData(snapshot) ? snapshot : null;
  } catch {
    return null;
  }
}

function writeCache(key: string | null, snapshot: MigrationPlannerSnapshot) {
  if (!key || typeof window === 'undefined' || !hasPlannerData(snapshot)) return;
  try {
    window.localStorage.setItem(key, JSON.stringify(snapshot));
  } catch {
    // Browser storage can be unavailable in private or constrained sessions.
  }
}

function tokenExpiresSoon(token: string | null | undefined, skewSeconds = 60) {
  if (!token || typeof globalThis.atob !== 'function') return false;
  try {
    const payload = token.split('.')[1];
    if (!payload) return false;
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const parsed = JSON.parse(globalThis.atob(padded));
    return typeof parsed.exp === 'number' && parsed.exp <= Math.floor(Date.now() / 1000) + skewSeconds;
  } catch {
    return false;
  }
}

async function resolveAccessToken(fallbackToken: string | null | undefined) {
  let accessToken = fallbackToken || null;
  try {
    const { data } = await supabase.auth.getSession();
    accessToken = data.session?.access_token || accessToken;
    if (tokenExpiresSoon(accessToken)) {
      const refreshed = await supabase.auth.refreshSession();
      accessToken = refreshed.data.session?.access_token || accessToken;
    }
  } catch {
    // The caller will surface the authentication failure if no usable token remains.
  }
  if (!accessToken || tokenExpiresSoon(accessToken, 0)) {
    throw new Error('Authentication expired. Please sign in again before starting the migration handoff.');
  }
  return accessToken;
}

export function useMigrationPlanner(range: MigrationPlannerRangeKey) {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<MigrationPlannerSnapshot>(() => normalizeSnapshot(null, range));
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const streamRef = useRef<EventSource | null>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cacheKey = useMemo(() => {
    const tenantKey =
      session?.user?.app_metadata?.tenant_id ||
      session?.user?.app_metadata?.organization_id ||
      session?.user?.user_metadata?.tenant_id ||
      session?.user?.user_metadata?.organization_id ||
      'default-tenant';
    const userKey = session?.user?.id || token?.slice(0, 24);
    return userKey ? `${CACHE_PREFIX}${tenantKey}:${userKey}:${range}` : null;
  }, [
    range,
    session?.user?.app_metadata?.organization_id,
    session?.user?.app_metadata?.tenant_id,
    session?.user?.id,
    session?.user?.user_metadata?.organization_id,
    session?.user?.user_metadata?.tenant_id,
    token,
  ]);

  const applySnapshot = useCallback((next: MigrationPlannerSnapshot) => {
    setSnapshot(next);
    writeCache(cacheKey, next);
  }, [cacheKey]);

  const refresh = useCallback(async () => {
    if (!token) {
      setSnapshot(normalizeSnapshot(null, range));
      setLoading(false);
      setConnected(false);
      return;
    }

    try {
      setLoading((current) => current && !hasPlannerData(readCache(cacheKey, range) || normalizeSnapshot(null, range)));
      const accessToken = await resolveAccessToken(token);
      const response = await fetch(`/api/v1/migration/planner?range=${encodeURIComponent(range)}`, {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${accessToken}`,
        },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      applySnapshot(normalizeSnapshot(payload.data, range));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load migration planner telemetry');
    } finally {
      setLoading(false);
    }
  }, [applySnapshot, cacheKey, range, token]);

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void refresh();
    }, 250);
  }, [refresh]);

  const createPlan = useCallback(async (options: MigrationPlannerCreatePlanInput = {}) => {
    if (!token) throw new Error('Authentication required');
    const sandboxHandoff = options.action === 'sandbox';
    const startHandoff = options.action === 'start';
    setActionMessage(
      sandboxHandoff
        ? 'Queuing sandbox simulations and opening Migration Sandbox...'
        : startHandoff
          ? 'Starting migration handoff and opening PQC Orchestration...'
          : 'Creating migration plan from live posture...',
    );
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), sandboxHandoff || startHandoff ? 60000 : 30000);
    try {
      const accessToken = await resolveAccessToken(token);
      const response = await fetch('/api/v1/migration/planner/create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({ range, limit: options.limit || Math.max(8, options.assetIds?.length || 0), ...options }),
        signal: controller.signal,
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || 'Failed to create migration plan');
      if (payload.data?.snapshot) applySnapshot(normalizeSnapshot(payload.data.snapshot, range));
      setActionMessage(payload.data?.message || (sandboxHandoff ? 'Migration Sandbox handoff queued.' : 'Migration plan created.'));
      return payload.data;
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') {
        throw new Error(
          sandboxHandoff
            ? 'Migration Sandbox handoff timed out. Please try again.'
            : startHandoff
              ? 'Start Migration handoff timed out before confirmation. Please try again.'
              : 'Migration plan creation timed out. Please try again.',
        );
      }
      throw err;
    } finally {
      window.clearTimeout(timeout);
    }
  }, [applySnapshot, range, token]);

  const runScenario = useCallback(async (options: { targetMode: string; optimization: string }) => {
    if (!token) throw new Error('Authentication required');
    setActionMessage('Running scenario analysis...');
    const accessToken = await resolveAccessToken(token);
    const response = await fetch('/api/v1/migration/planner/scenario', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ ...options, range }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload?.error?.message || 'Failed to run scenario analysis');
    setActionMessage('Scenario analysis ready.');
    return payload.data as MigrationPlannerScenario;
  }, [range, token]);

  const exportRoadmap = useCallback(async (format: 'json' | 'csv' = 'json') => {
    if (!token) throw new Error('Authentication required');
    setActionMessage('Preparing roadmap export...');
    const accessToken = await resolveAccessToken(token);
    const response = await fetch(`/api/v1/migration/planner/export?range=${encodeURIComponent(range)}&format=${format}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload?.error?.message || 'Failed to export migration roadmap');
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `qguard-migration-roadmap-${range}.${format}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
    setActionMessage('Roadmap export generated.');
  }, [range, token]);

  useEffect(() => {
    if (!token) {
      setSnapshot(normalizeSnapshot(null, range));
      setLoading(false);
      return;
    }
    const cached = readCache(cacheKey, range);
    if (cached) {
      setSnapshot(cached);
      setLoading(false);
    } else {
      setSnapshot(normalizeSnapshot(null, range));
      setLoading(true);
    }
    void refresh();
  }, [cacheKey, range, refresh, token]);

  useEffect(() => {
    if (!user) return;
    const tables = [
      'assets',
      'crypto_inventory',
      'crypto_exposures',
      'migration_jobs',
      'migration_plans',
      'migration_plan_configurations',
      'migration_scope',
      'migration_assets',
      'migration_tasks',
      'migration_controls',
      'migration_audit_logs',
      'migration_events',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'runtime_crypto_events',
      'certificates',
      'compliance_evidence',
      'security_events',
      'audit_logs',
    ];

    const channels = tables.map((table) => supabase
      .channel(`migration-planner-${range}-${table}`)
      .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
      .subscribe());

    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [queueRefresh, range, user]);

  useEffect(() => {
    if (!token) {
      streamRef.current?.close();
      setConnected(false);
      return;
    }

    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const close = () => {
      streamRef.current?.close();
      streamRef.current = null;
      setConnected(false);
    };

    const startPolling = () => {
      if (pollTimer) return;
      pollTimer = setInterval(() => void refresh(), 10000);
    };

    const connect = () => {
      close();
      const stream = new EventSource(`/api/v1/migration/planner/stream?range=${encodeURIComponent(range)}&token=${encodeURIComponent(token)}`);
      streamRef.current = stream;

      stream.addEventListener('planner-connected', () => {
        setConnected(true);
        setError(null);
      });

      stream.addEventListener('planner-update', (event) => {
        try {
          const next = normalizeSnapshot(JSON.parse((event as MessageEvent).data), range);
          applySnapshot(next);
          setLoading(false);
          setConnected(true);
          setError(null);
        } catch (err) {
          setError(err instanceof Error ? err.message : 'Unable to parse migration planner stream');
        }
      });

      stream.onerror = () => {
        close();
        startPolling();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 15000);
      };
    };

    connect();
    return () => {
      close();
      if (retryTimer) clearTimeout(retryTimer);
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [applySnapshot, range, refresh, token]);

  useEffect(() => () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
  }, []);

  return {
    snapshot,
    loading,
    connected,
    error,
    actionMessage,
    refresh,
    createPlan,
    runScenario,
    exportRoadmap,
    clearActionMessage: () => setActionMessage(null),
  };
}
