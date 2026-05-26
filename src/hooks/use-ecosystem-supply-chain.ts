'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';

export type EcosystemRiskLevel =
  | 'Quantum Ready'
  | 'Hybrid Ready'
  | 'Migration Planned'
  | 'Unknown'
  | 'High Risk'
  | 'Critical Dependency';

export type EcosystemSupportStatus = 'Ready' | 'Partial' | 'Planned' | 'Unknown' | 'Blocked';
export type EcosystemChainRisk = 'Critical' | 'High' | 'Medium' | 'Low';
export type EcosystemLabResult = 'Pass' | 'Warning' | 'Fail';

export type EcosystemTrustNode = {
  id: string;
  name: string;
  type: string;
  risk: EcosystemRiskLevel;
  score: number;
  x: number;
  y: number;
  details: string[];
};

export type EcosystemEvidenceSignal = {
  id: string;
  sourceTable: string;
  vendor: string;
  category: string;
  title: string;
  algorithm: string;
  keySize: number;
  severity: EcosystemChainRisk;
  vulnerable: boolean;
  pqcReady: boolean;
  contractGap: boolean;
  timestamp: string | null;
  detail: string;
};

export type EcosystemVendor = {
  name: string;
  category: string;
  readiness: EcosystemRiskLevel;
  score: number;
  support: Record<string, EcosystemSupportStatus>;
  exposure: string;
  contract: string;
  timeline: string;
  evidenceCount: number;
  vulnerableEvidence: number;
  contractGaps: number;
  lastSeen: string | null;
  signals: EcosystemEvidenceSignal[];
};

export type EcosystemTrustChain = {
  name: string;
  path: string[];
  issue: string;
  impact: string;
  risk: EcosystemChainRisk;
};

export type EcosystemLabTest = {
  name: string;
  result: EcosystemLabResult;
  metric: string;
  detail: string;
};

export type EcosystemWorkflowStep = {
  label: string;
  status: 'Active' | 'Waiting' | 'Needs Review';
  detail: string;
  count: number;
};

export type EcosystemSupplyChainSnapshot = {
  generatedAt: string;
  source: {
    mode: string;
    latestActivityAt: string | null;
    tables: Record<string, number>;
  };
  metrics: {
    externalDependencies: number;
    criticalTrustBreaks: number;
    hybridReadyPercent: number;
    contractGaps: number;
    vulnerableVendors: number;
    observedSignals: number;
  };
  trustNodes: EcosystemTrustNode[];
  vendors: EcosystemVendor[];
  chains: EcosystemTrustChain[];
  labTests: EcosystemLabTest[];
  workflow: EcosystemWorkflowStep[];
};

export const EMPTY_ECOSYSTEM_SUPPLY_CHAIN_SNAPSHOT: EcosystemSupplyChainSnapshot = {
  generatedAt: '',
  source: {
    mode: 'empty',
    latestActivityAt: null,
    tables: {},
  },
  metrics: {
    externalDependencies: 0,
    criticalTrustBreaks: 0,
    hybridReadyPercent: 0,
    contractGaps: 0,
    vulnerableVendors: 0,
    observedSignals: 0,
  },
  trustNodes: [],
  vendors: [],
  chains: [],
  labTests: [],
  workflow: [],
};

const CACHE_PREFIX = 'qguard-ecosystem-supply-chain:v1:';

function normalizeSnapshot(payload: unknown): EcosystemSupplyChainSnapshot {
  const snapshot = (payload || {}) as Partial<EcosystemSupplyChainSnapshot>;
  return {
    ...EMPTY_ECOSYSTEM_SUPPLY_CHAIN_SNAPSHOT,
    ...snapshot,
    source: {
      ...EMPTY_ECOSYSTEM_SUPPLY_CHAIN_SNAPSHOT.source,
      ...(snapshot.source || {}),
      tables: { ...(snapshot.source?.tables || {}) },
    },
    metrics: { ...EMPTY_ECOSYSTEM_SUPPLY_CHAIN_SNAPSHOT.metrics, ...(snapshot.metrics || {}) },
    trustNodes: Array.isArray(snapshot.trustNodes) ? snapshot.trustNodes : [],
    vendors: Array.isArray(snapshot.vendors) ? snapshot.vendors : [],
    chains: Array.isArray(snapshot.chains) ? snapshot.chains : [],
    labTests: Array.isArray(snapshot.labTests) ? snapshot.labTests : [],
    workflow: Array.isArray(snapshot.workflow) ? snapshot.workflow : [],
  };
}

function hasData(snapshot: EcosystemSupplyChainSnapshot) {
  return Boolean(
    snapshot.metrics.externalDependencies ||
    snapshot.metrics.observedSignals ||
    snapshot.trustNodes.length ||
    snapshot.vendors.length ||
    snapshot.chains.length ||
    snapshot.labTests.length,
  );
}

function readCache(key: string | null) {
  if (!key || typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;
    const snapshot = normalizeSnapshot(JSON.parse(raw));
    return hasData(snapshot) ? snapshot : null;
  } catch {
    return null;
  }
}

function writeCache(key: string | null, snapshot: EcosystemSupplyChainSnapshot) {
  if (!key || typeof window === 'undefined' || !hasData(snapshot)) return;
  try {
    window.localStorage.setItem(key, JSON.stringify(snapshot));
  } catch {
    // Browser storage can be disabled in hardened sessions.
  }
}

export function useEcosystemSupplyChain() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<EcosystemSupplyChainSnapshot>(EMPTY_ECOSYSTEM_SUPPLY_CHAIN_SNAPSHOT);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
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
    return userKey ? `${CACHE_PREFIX}${tenantKey}:${userKey}` : null;
  }, [
    session?.user?.app_metadata?.organization_id,
    session?.user?.app_metadata?.tenant_id,
    session?.user?.id,
    session?.user?.user_metadata?.organization_id,
    session?.user?.user_metadata?.tenant_id,
    token,
  ]);

  const applySnapshot = useCallback((next: EcosystemSupplyChainSnapshot) => {
    setSnapshot(next);
    writeCache(cacheKey, next);
  }, [cacheKey]);

  const refresh = useCallback(async () => {
    if (!token) {
      setSnapshot(EMPTY_ECOSYSTEM_SUPPLY_CHAIN_SNAPSHOT);
      setLoading(false);
      setConnected(false);
      setError(null);
      return;
    }

    try {
      setLoading((current) => current && !hasData(readCache(cacheKey) || EMPTY_ECOSYSTEM_SUPPLY_CHAIN_SNAPSHOT));
      const response = await fetch('/api/v1/dashboard/ecosystem-supply-chain', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      applySnapshot(normalizeSnapshot(payload.data));
      setError(null);
      setConnected(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load ecosystem supply-chain telemetry');
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }, [applySnapshot, cacheKey, token]);

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void refresh();
    }, 250);
  }, [refresh]);

  useEffect(() => {
    if (!token) {
      setSnapshot(EMPTY_ECOSYSTEM_SUPPLY_CHAIN_SNAPSHOT);
      setLoading(false);
      return;
    }

    const cached = readCache(cacheKey);
    if (cached) {
      setSnapshot(cached);
      setLoading(false);
    } else {
      setLoading(true);
    }

    void refresh();
  }, [cacheKey, refresh, token]);

  useEffect(() => {
    if (!user) return;
    const tables = [
      'assets',
      'asset_relationships',
      'connector_accounts',
      'vendor_assessments',
      'scanner_evidence',
      'scanner_alerts',
      'pqc_scan_results',
      'crypto_inventory',
      'crypto_exposures',
      'certificates',
      'runtime_crypto_events',
      'migration_jobs',
      'compliance_evidence',
      'agent_heartbeats',
    ];

    const channels = tables.map((table) => supabase
      .channel(`ecosystem-supply-chain-${table}`)
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
      streamRef.current?.close();
      streamRef.current = null;
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
      const stream = new EventSource(`/api/v1/dashboard/ecosystem-supply-chain/stream?token=${encodeURIComponent(token)}`);
      streamRef.current = stream;

      stream.addEventListener('ecosystem-supply-chain-connected', () => {
        setConnected(true);
        setError(null);
      });

      stream.addEventListener('ecosystem-supply-chain-update', (event) => {
        try {
          const next = normalizeSnapshot(JSON.parse((event as MessageEvent).data));
          applySnapshot(next);
          setLoading(false);
          setConnected(true);
          setError(null);
        } catch (err) {
          setError(err instanceof Error ? err.message : 'Unable to parse ecosystem supply-chain stream');
        }
      });

      stream.addEventListener('ecosystem-supply-chain-error', (event) => {
        try {
          const payload = JSON.parse((event as MessageEvent).data);
          setError(payload?.message || 'Ecosystem supply-chain stream failed');
        } catch {
          setError('Ecosystem supply-chain stream failed');
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
  }, [applySnapshot, refresh, token]);

  useEffect(() => () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
  }, []);

  return { snapshot, loading, error, connected, refresh };
}
