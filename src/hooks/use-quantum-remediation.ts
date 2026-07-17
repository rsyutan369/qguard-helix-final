import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type { RemediationPlan } from '@/types/quantum-remediation';

/**
 * useQuantumRemediation — live Intelligent Quantum Remediation Engine™ state.
 *
 * Fetches the tenant-scoped Q-REMEDY remediation plan from
 * /api/v1/quantum-remediation, keeps it live via a header-authenticated SSE
 * stream (token never appears in a URL) plus Supabase realtime on the evidence
 * tables the plan derives from — so the Certification Readiness Score updates
 * automatically as vulnerabilities are resolved and assets are rescanned.
 */

export type LoadState = 'loading' | 'success' | 'error';

export const EMPTY_PLAN: RemediationPlan = {
  generatedAt: '',
  hasData: false,
  certificationReadinessPct: 0,
  certificationEligible: false,
  trustScore: 0,
  levelLabel: 'Not Eligible',
  requiredMet: 0,
  requiredTotal: 10,
  quantumReadiness: 0,
  quantumRisk: 0,
  hndlRisk: 0,
  pqcAdoption: 0,
  estimatedCertificationDate: null,
  estimatedCompletionWeeks: 0,
  parallelWorkstreams: 1,
  criteria: [],
  requirements: [],
  actions: [],
  ladder: [],
  queues: { critical: 0, high: 0, medium: 0, low: 0 },
  quickWins: [],
  criticalBlockers: [],
  vendorActions: [],
  replacementsRequired: [],
  advisor: [],
  progress: {
    totalActions: 0,
    openActions: 0,
    inProgressActions: 0,
    resolvedActions: 0,
    completionPct: 0,
    migrationJobsCompleted: 0,
    migrationJobsRunning: 0,
    recentlyFixed: [],
    upcomingTasks: [],
  },
  assetsByRisk: [],
  remainingVulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
  readinessTrend: [],
  methodology: {
    name: '',
    version: '',
    summary: '',
    scoreFormula: '',
    priorityFactors: [],
    simulation: '',
    honesty: '',
  },
};

// Evidence tables whose mutations change the plan (scan findings, CBOM,
// certificates, migration execution, asset inventory).
const REALTIME_TABLES = ['pqc_scan_results', 'crypto_inventory', 'certificates', 'migration_jobs', 'assets'];

export function useQuantumRemediation() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [plan, setPlan] = useState<RemediationPlan>(EMPTY_PLAN);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const apply = useCallback((next: Partial<RemediationPlan> | null) => {
    setPlan({ ...EMPTY_PLAN, ...(next || {}) });
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      apply(EMPTY_PLAN);
      setState('success');
      return;
    }
    setState((current) => (current === 'success' ? current : 'loading'));
    try {
      const response = await fetch('/api/v1/quantum-remediation', {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      apply(payload.data || {});
      setState('success');
      setError(null);
    } catch (err) {
      console.error('Quantum remediation load failed:', err);
      setError(err instanceof Error ? err.message : 'Unable to load remediation engine');
      setState('error');
    }
  }, [token, apply]);

  const queueRefresh = useCallback(() => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null;
      void refresh();
    }, 800);
  }, [refresh]);

  useEffect(() => () => { if (refreshTimer.current) clearTimeout(refreshTimer.current); }, []);

  useEffect(() => {
    if (!token || !user) {
      apply(EMPTY_PLAN);
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh, apply]);

  // Header-authenticated SSE (token never in URL — mirrors useQuantumCertification).
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    let retry: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;

    const parseFrame = (frame: string) => {
      let eventName = 'message';
      const dataLines: string[] = [];
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) eventName = line.slice(6).trim();
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''));
      }
      if (eventName === 'remediation-update' && dataLines.length) {
        try {
          apply(JSON.parse(dataLines.join('\n')));
          setState('success');
          setError(null);
        } catch {
          /* ignore malformed frame */
        }
      }
    };

    const connect = async () => {
      try {
        const response = await fetch('/api/v1/quantum-remediation/stream', {
          headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`SSE ${response.status}`);
        setSseConnected(true);
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
        setSseConnected(false);
        if (retry) clearTimeout(retry);
        retry = setTimeout(() => void connect(), 10000);
      }
    };

    void connect();
    return () => {
      cancelled = true;
      controller.abort();
      if (retry) clearTimeout(retry);
      setSseConnected(false);
    };
  }, [token, apply]);

  // Supabase realtime — refresh (debounced) on evidence mutations.
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`qrem-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => { for (const channel of channels) supabase.removeChannel(channel); };
  }, [user, queueRefresh]);

  return { plan, state, error, sseConnected, refresh };
}
