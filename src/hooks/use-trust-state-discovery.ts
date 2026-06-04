'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';

export type TrustGateState = 'ready' | 'review' | 'blocked';
export type TrustGateImpact = 'blocker' | 'review' | 'monitor';
export type TrustSeverity = 'critical' | 'high' | 'medium' | 'low';

export type TrustWorkflowStep = {
  id: string;
  label: string;
  status: TrustGateState;
  score: number;
  count: number;
  detail: string;
  source: string;
};

export type TrustGraphNode = {
  id: string;
  label: string;
  type: string;
  x: number;
  y: number;
  riskScore: number;
  status: string;
  detail: string;
  source?: string;
};

export type TrustGraphEdge = {
  id: string;
  from: string;
  to: string;
  label: string;
  status: string;
};

export type TrustRecord = {
  id: string;
  kind: string;
  name: string;
  assetName: string;
  owner: string;
  issuer: string;
  algorithm: string;
  status: string;
  pqcReady: boolean;
  riskScore: number;
  riskLevel: TrustSeverity;
  gateImpact: TrustGateImpact;
  lastSeen: string | null;
  source: string;
};

export type TrustFinding = {
  id: string;
  source: string;
  category: string;
  severity: TrustSeverity;
  title: string;
  detail: string;
  owner: string;
  assetId: string | null;
  assetName: string;
  trustObject: string;
  recommendation: string;
  gateImpact: TrustGateImpact;
  timestamp: string | null;
  evidence: Record<string, unknown>;
};

export type TrustRecommendation = {
  id: string;
  title: string;
  detail: string;
  severity: TrustSeverity;
  actionHref: string;
  actionLabel?: string;
};

export type TrustActivity = {
  id: string;
  title: string;
  detail: string;
  severity: TrustSeverity;
  timestamp: string | null;
  source: string;
};

export type TrustStateDiscoverySnapshot = {
  generatedAt: string;
  latestActivityAt: string | null;
  gate: {
    state: TrustGateState;
    label: string;
    readiness: number;
    blockers: number;
    reviews: number;
    migrationConflicts: number;
    decision: string;
    rationale: string;
  };
  metrics: {
    visibilityScore: number;
    ownershipScore: number;
    dependencyScore: number;
    riskScore: number;
    gateReadiness: number;
    activeAssets: number;
    discoveredTrustObjects: number;
    ownedAssets: number;
    dependencyEdges: number;
    vendors: number;
    runtimeTrustEvents: number;
    unknownRuntimeCertificates: number;
    highRiskFindings: number;
    activeMigrationJobs: number;
    scannerAgents: number;
    connectors: number;
  };
  workflow: TrustWorkflowStep[];
  graph: {
    nodes: TrustGraphNode[];
    edges: TrustGraphEdge[];
  };
  trustRecords: TrustRecord[];
  findings: TrustFinding[];
  recommendations: TrustRecommendation[];
  activity: TrustActivity[];
  telemetry: {
    assets: number;
    assetRelationships: number;
    certificates: number;
    cryptoInventory: number;
    cryptoExposures: number;
    runtimeCryptoEvents: number;
    scannerEvidence: number;
    scannerAlerts: number;
    scanResults: number;
    vendorAssessments: number;
    migrationJobs: number;
    securityEvents: number;
    scannerAgents: number;
    connectors: number;
    agentHeartbeats: number;
    persistedFindings: number;
    eventPipelineStatus: string;
    latestRuntimeEventAt: string | null;
  };
};

export const EMPTY_TRUST_STATE_DISCOVERY: TrustStateDiscoverySnapshot = {
  generatedAt: '',
  latestActivityAt: null,
  gate: {
    state: 'review',
    label: 'Awaiting Evidence',
    readiness: 0,
    blockers: 0,
    reviews: 0,
    migrationConflicts: 0,
    decision: 'Awaiting trust-state discovery',
    rationale: 'Collector, certificate, dependency, and runtime evidence has not been synchronized yet.',
  },
  metrics: {
    visibilityScore: 0,
    ownershipScore: 0,
    dependencyScore: 0,
    riskScore: 0,
    gateReadiness: 0,
    activeAssets: 0,
    discoveredTrustObjects: 0,
    ownedAssets: 0,
    dependencyEdges: 0,
    vendors: 0,
    runtimeTrustEvents: 0,
    unknownRuntimeCertificates: 0,
    highRiskFindings: 0,
    activeMigrationJobs: 0,
    scannerAgents: 0,
    connectors: 0,
  },
  workflow: [],
  graph: { nodes: [], edges: [] },
  trustRecords: [],
  findings: [],
  recommendations: [],
  activity: [],
  telemetry: {
    assets: 0,
    assetRelationships: 0,
    certificates: 0,
    cryptoInventory: 0,
    cryptoExposures: 0,
    runtimeCryptoEvents: 0,
    scannerEvidence: 0,
    scannerAlerts: 0,
    scanResults: 0,
    vendorAssessments: 0,
    migrationJobs: 0,
    securityEvents: 0,
    scannerAgents: 0,
    connectors: 0,
    agentHeartbeats: 0,
    persistedFindings: 0,
    eventPipelineStatus: 'empty',
    latestRuntimeEventAt: null,
  },
};

function clamp(value: unknown) {
  const num = Number(value);
  if (!Number.isFinite(num)) return 0;
  return Math.max(0, Math.min(100, Math.round(num)));
}

function asArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? value as T[] : [];
}

function normalizeSnapshot(raw: Partial<TrustStateDiscoverySnapshot> | null | undefined): TrustStateDiscoverySnapshot {
  const data = raw || {};
  return {
    ...EMPTY_TRUST_STATE_DISCOVERY,
    ...data,
    gate: {
      ...EMPTY_TRUST_STATE_DISCOVERY.gate,
      ...(data.gate || {}),
      readiness: clamp(data.gate?.readiness),
      state: data.gate?.state === 'ready' || data.gate?.state === 'blocked' ? data.gate.state : data.gate?.state === 'review' ? 'review' : EMPTY_TRUST_STATE_DISCOVERY.gate.state,
    },
    metrics: {
      ...EMPTY_TRUST_STATE_DISCOVERY.metrics,
      ...(data.metrics || {}),
      visibilityScore: clamp(data.metrics?.visibilityScore),
      ownershipScore: clamp(data.metrics?.ownershipScore),
      dependencyScore: clamp(data.metrics?.dependencyScore),
      riskScore: clamp(data.metrics?.riskScore),
      gateReadiness: clamp(data.metrics?.gateReadiness),
    },
    workflow: asArray<TrustWorkflowStep>(data.workflow),
    graph: {
      nodes: asArray<TrustGraphNode>(data.graph?.nodes),
      edges: asArray<TrustGraphEdge>(data.graph?.edges),
    },
    trustRecords: asArray<TrustRecord>(data.trustRecords),
    findings: asArray<TrustFinding>(data.findings),
    recommendations: asArray<TrustRecommendation>(data.recommendations),
    activity: asArray<TrustActivity>(data.activity),
    telemetry: {
      ...EMPTY_TRUST_STATE_DISCOVERY.telemetry,
      ...(data.telemetry || {}),
    },
  };
}

export function useTrustStateDiscovery() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<TrustStateDiscoverySnapshot>(EMPTY_TRUST_STATE_DISCOVERY);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const streamsRef = useRef<EventSource[]>([]);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const closeStreams = useCallback(() => {
    for (const stream of streamsRef.current) stream.close();
    streamsRef.current = [];
    setConnected(false);
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      setSnapshot(EMPTY_TRUST_STATE_DISCOVERY);
      setLoading(false);
      setConnected(false);
      setError(null);
      return;
    }

    try {
      const response = await fetch('/api/v1/dashboard/trust-state-discovery', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setSnapshot(normalizeSnapshot(payload.data));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load trust-state discovery data');
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }, [token]);

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void refresh();
    }, 250);
  }, [refresh]);

  useEffect(() => () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
  }, []);

  useEffect(() => {
    if (!token) {
      setSnapshot(EMPTY_TRUST_STATE_DISCOVERY);
      setLoading(false);
      return;
    }

    void refresh();
  }, [refresh, token]);

  useEffect(() => {
    if (!user) return;
    const tables = [
      'assets',
      'asset_relationships',
      'certificates',
      'crypto_inventory',
      'crypto_exposures',
      'runtime_crypto_events',
      'scanner_evidence',
      'scanner_alerts',
      'pqc_scan_results',
      'vendor_assessments',
      'migration_jobs',
      'security_events',
      'scanner_agents',
      'connector_accounts',
      'agent_heartbeats',
      'trust_state_findings',
    ];

    const channels = tables.map((table) => supabase
      .channel(`trust-state-discovery-${table}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` },
        queueRefresh,
      )
      .subscribe());

    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [queueRefresh, user]);

  useEffect(() => {
    if (!token) {
      closeStreams();
      return;
    }

    let retryTimer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      closeStreams();
      const trustStream = new EventSource(`/api/v1/dashboard/trust-state-discovery/stream?token=${encodeURIComponent(token)}`);
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);
      streamsRef.current = [trustStream, metricsStream, scannerStream];

      const markOpen = () => setConnected(true);
      const scheduleReconnect = () => {
        setConnected(false);
        closeStreams();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10000);
      };
      const refreshFromStream = () => queueRefresh();

      trustStream.onopen = markOpen;
      metricsStream.onopen = markOpen;
      scannerStream.onopen = markOpen;
      trustStream.onerror = scheduleReconnect;
      metricsStream.onerror = scheduleReconnect;
      scannerStream.onerror = scheduleReconnect;
      trustStream.addEventListener('trust-state-connected', refreshFromStream);
      trustStream.addEventListener('trust-state-update', refreshFromStream);
      metricsStream.addEventListener('metrics-update', refreshFromStream);
      metricsStream.addEventListener('runtime-crypto-update', refreshFromStream);
      metricsStream.addEventListener('scan-complete', refreshFromStream);
      scannerStream.addEventListener('scanner-intelligence', refreshFromStream);
      scannerStream.addEventListener('scanner-error', refreshFromStream);
    };

    connect();
    return () => {
      if (retryTimer) clearTimeout(retryTimer);
      closeStreams();
    };
  }, [closeStreams, queueRefresh, token]);

  const gateBlocked = useMemo(() => snapshot.gate.state === 'blocked', [snapshot.gate.state]);

  return { snapshot, loading, error, connected, refresh, gateBlocked };
}
