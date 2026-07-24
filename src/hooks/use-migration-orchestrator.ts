import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import type { OrchestratorSnapshot } from '@/types/migration-orchestrator';

/**
 * useMigrationOrchestrator — live enterprise-scale orchestration state.
 *
 * Fetches the tenant-scoped orchestration snapshot from
 * /api/v1/migration-orchestrator and keeps it live via a header-authenticated
 * SSE stream (token never in a URL). Every metric is derived from real
 * migration_jobs / validation / agent data server-side.
 */

export type LoadState = 'loading' | 'success' | 'error';

export const EMPTY_ORCHESTRATOR: OrchestratorSnapshot = {
  generatedAt: '',
  hasData: false,
  config: { maxConcurrentPerTenant: 64, leaseSeconds: 300, baseBackoffSeconds: 30, maxRetries: 5, workerCapacity: 64 },
  metrics: {
    total: 0, blocked: 0, queued: 0, leased: 0, running: 0, validating: 0, completed: 0, retrying: 0, failed: 0, rolledBack: 0, deadLetter: 0, paused: 0,
    assetsUpgraded: 0, assetsRemaining: 0, overallProgressPct: 0, validationProgressPct: 0,
    throughputPerMin: null, avgDurationSeconds: null, queueDepth: 0, inFlight: 0, workerUtilizationPct: 0, activeWorkers: 0,
    reclaimedLeases: 0, retriesScheduled: 0, deadLetteredThisCycle: 0,
    agentsOnline: 0, agentsDegraded: 0, agentsOffline: 0, connectorsHealthy: 0, connectorsTotal: 0,
    agentCpuPct: null, agentMemoryPct: null, networkLatencyMs: null,
  },
  throughput: [],
  priorityQueue: [],
  agents: [],
  scaleTier: '1–10',
};

export function useMigrationOrchestrator(enabled: boolean) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [data, setData] = useState<OrchestratorSnapshot>(EMPTY_ORCHESTRATOR);
  const [state, setState] = useState<LoadState>('loading');
  const [sseConnected, setSseConnected] = useState(false);

  const apply = useCallback((next: Partial<OrchestratorSnapshot> | null) => {
    setData({ ...EMPTY_ORCHESTRATOR, ...(next || {}) });
  }, []);

  const refresh = useCallback(async () => {
    if (!token || !enabled) { setState('success'); return; }
    setState((c) => (c === 'success' ? c : 'loading'));
    try {
      const res = await fetch('/api/v1/migration-orchestrator', { headers: { Authorization: `Bearer ${token}` } });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(payload?.error?.message || `HTTP ${res.status}`);
      apply(payload.data || {});
      setState('success');
    } catch {
      setState('error');
    }
  }, [token, enabled, apply]);

  useEffect(() => { if (enabled && token) void refresh(); }, [enabled, token, refresh]);

  useEffect(() => {
    if (!enabled || !token) return;
    const controller = new AbortController();
    let retry: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;
    const parseFrame = (frame: string) => {
      let eventName = 'message';
      const lines: string[] = [];
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) eventName = line.slice(6).trim();
        else if (line.startsWith('data:')) lines.push(line.slice(5).replace(/^ /, ''));
      }
      if (eventName === 'orchestrator-update' && lines.length) {
        try { apply(JSON.parse(lines.join('\n'))); setState('success'); } catch { /* ignore */ }
      }
    };
    const connect = async () => {
      try {
        const res = await fetch('/api/v1/migration-orchestrator/stream', { headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' }, signal: controller.signal });
        if (!res.ok || !res.body) throw new Error(`SSE ${res.status}`);
        setSseConnected(true);
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let boundary = buffer.indexOf('\n\n');
          while (boundary !== -1) { parseFrame(buffer.slice(0, boundary)); buffer = buffer.slice(boundary + 2); boundary = buffer.indexOf('\n\n'); }
        }
        throw new Error('stream ended');
      } catch {
        if (cancelled || controller.signal.aborted) return;
        setSseConnected(false);
        if (retry) clearTimeout(retry);
        retry = setTimeout(() => void connect(), 10000);
      }
    };
    void connect();
    return () => { cancelled = true; controller.abort(); if (retry) clearTimeout(retry); setSseConnected(false); };
  }, [enabled, token, apply]);

  return { data, state, sseConnected, refresh };
}
