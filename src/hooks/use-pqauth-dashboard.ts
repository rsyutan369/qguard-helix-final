'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { PQAUTHTABLES } from '@/app/dashboard/_lib/telemetry-sync';
import {
  EMPTY_PQAUTH_SNAPSHOT,
  type PQAuthMode,
  type PQAuthSnapshot,
} from '@/types/pqauth-dashboard';

type LoadState = 'loading' | 'success' | 'error';

function normalizeSnapshot(data: Partial<PQAuthSnapshot> | null | undefined): PQAuthSnapshot {
  return {
    ...EMPTY_PQAUTH_SNAPSHOT,
    ...(data || {}),
    providers: Array.isArray(data?.providers) ? data.providers : [],
    gateways: Array.isArray(data?.gateways) ? data.gateways : [],
    authServices: Array.isArray(data?.authServices) ? data.authServices : [],
    flows: Array.isArray(data?.flows) ? data.flows : [],
    algorithms: Array.isArray(data?.algorithms) ? data.algorithms : [],
    identityRows: Array.isArray(data?.identityRows) ? data.identityRows : [],
    exposureRows: Array.isArray(data?.exposureRows) ? data.exposureRows : [],
    tokenRows: Array.isArray(data?.tokenRows) ? data.tokenRows : [],
    dependencies: Array.isArray(data?.dependencies) ? data.dependencies : [],
    runtimeEvents: Array.isArray(data?.runtimeEvents) ? data.runtimeEvents : [],
    trustNodes: Array.isArray(data?.trustNodes) ? data.trustNodes : [],
    trustEdges: Array.isArray(data?.trustEdges) ? data.trustEdges : [],
    phases: Array.isArray(data?.phases) ? data.phases : [],
    complianceRows: Array.isArray(data?.complianceRows) ? data.complianceRows : [],
    compatibilitySurfaces: Array.isArray(data?.compatibilitySurfaces) ? data.compatibilitySurfaces : [],
    tokenImpacts: Array.isArray(data?.tokenImpacts) ? data.tokenImpacts : [],
    digitalTwinScenarios: Array.isArray(data?.digitalTwinScenarios) ? data.digitalTwinScenarios : [],
    failurePredictions: Array.isArray(data?.failurePredictions) ? data.failurePredictions : [],
    rollbackGates: Array.isArray(data?.rollbackGates) ? data.rollbackGates : [],
    runtimeMetrics: Array.isArray(data?.runtimeMetrics) ? data.runtimeMetrics : [],
    qkmsKeyDomains: Array.isArray(data?.qkmsKeyDomains) ? data.qkmsKeyDomains : [],
    lifecycleControls: Array.isArray(data?.lifecycleControls) ? data.lifecycleControls : [],
    sourceHealth: Array.isArray(data?.sourceHealth) ? data.sourceHealth : [],
    freshness: { ...EMPTY_PQAUTH_SNAPSHOT.freshness, ...(data?.freshness || {}) },
    lineage: { ...EMPTY_PQAUTH_SNAPSHOT.lineage, ...(data?.lineage || {}) },
    integrity: { ...EMPTY_PQAUTH_SNAPSHOT.integrity, ...(data?.integrity || {}) },
    metrics: { ...EMPTY_PQAUTH_SNAPSHOT.metrics, ...(data?.metrics || {}) },
  };
}

export function usePQAuthDashboard(mode: PQAuthMode) {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<PQAuthSnapshot>(EMPTY_PQAUTH_SNAPSHOT);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const streamsRef = useRef<EventSource[]>([]);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const closeStreams = useCallback(() => {
    for (const stream of streamsRef.current) stream.close();
    streamsRef.current = [];
    setSseConnected(false);
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      setSnapshot(EMPTY_PQAUTH_SNAPSHOT);
      setState('success');
      setError(null);
      return;
    }

    setState((current) => current === 'success' ? current : 'loading');
    try {
      const response = await fetch(`/api/v1/dashboard/pqauth/${mode}`, {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setSnapshot(normalizeSnapshot(payload.data));
      setState('success');
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to load PQAuth telemetry';
      console.error('PQAuth dashboard load failed:', err);
      setError(message);
      setState('error');
    }
  }, [mode, token]);

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
    if (!token || !user) {
      setSnapshot(EMPTY_PQAUTH_SNAPSHOT);
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh]);

  useEffect(() => {
    if (!user) return;
    const channels = PQAUTHTABLES.map((table) => {
      const filter = table.startsWith('qkms_') ? `tenant_id=eq.${user.id}` : `user_id=eq.${user.id}`;
      return supabase
        .channel(`pqauth-${mode}-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter }, queueRefresh)
        .subscribe();
    });

    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [mode, queueRefresh, user]);

  useEffect(() => {
    if (!token) {
      closeStreams();
      return;
    }

    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      closeStreams();
      const pqauthStream = new EventSource(`/api/v1/dashboard/pqauth/stream?token=${encodeURIComponent(token)}`);
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);
      const qkmsStream = new EventSource(`/api/v1/dashboard/qkms/stream?token=${encodeURIComponent(token)}`);
      streamsRef.current = [pqauthStream, metricsStream, scannerStream, qkmsStream];

      const markOpen = () => setSseConnected(true);
      const reconnect = () => {
        setSseConnected(false);
        closeStreams();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10000);
      };

      for (const stream of streamsRef.current) {
        stream.onopen = markOpen;
        stream.onerror = reconnect;
      }

      pqauthStream.addEventListener('pqauth-connected', queueRefresh);
      pqauthStream.addEventListener('pqauth-update', queueRefresh);
      metricsStream.addEventListener('metrics-update', queueRefresh);
      metricsStream.addEventListener('runtime-crypto-update', queueRefresh);
      metricsStream.addEventListener('scan-complete', queueRefresh);
      scannerStream.addEventListener('scanner-intelligence', queueRefresh);
      scannerStream.addEventListener('scanner-error', queueRefresh);
      qkmsStream.addEventListener('qkms-connected', queueRefresh);
      qkmsStream.addEventListener('qkms-update', queueRefresh);
    };

    connect();
    return () => {
      if (retryTimer) clearTimeout(retryTimer);
      closeStreams();
    };
  }, [token, queueRefresh, closeStreams]);

  return { snapshot, state, error, sseConnected, refresh };
}
