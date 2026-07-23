'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type { SharedResponsibilityIntelligence } from '@/lib/shared-responsibility';

export type LoadState = 'loading' | 'success' | 'error';

export interface MigrationIntelligence extends SharedResponsibilityIntelligence {
  baseline?: { quantumReadiness: number; quantumReadinessLevel: string };
}

const emptyBucket = () => ({ critical: 0, high: 0, medium: 0, low: 0 });
const emptyReadiness = (domain: 'overall' | 'customer' | 'provider' | 'ecosystem') => ({
  domain,
  score: 0,
  level: 'Not Started',
  total: 0,
  resolved: 0,
  actionable: 0,
  blocked: 0,
});

export const EMPTY_MIGRATION_INTELLIGENCE: MigrationIntelligence = {
  generatedAt: '',
  hasData: false,
  totals: { findings: 0, customer: 0, provider: 0, ecosystem: 0, actionable: 0, waiting: 0, blocked: 0, resolved: 0 },
  readiness: {
    overall: emptyReadiness('overall'),
    customer: emptyReadiness('customer'),
    provider: emptyReadiness('provider'),
    ecosystem: emptyReadiness('ecosystem'),
  },
  domainDistribution: { customer: 0, provider: 0, ecosystem: 0 },
  severityByDomain: { customer: emptyBucket(), provider: emptyBucket(), ecosystem: emptyBucket() },
  matrix: [],
  findings: [],
  blockers: [],
  waves: [],
  widgets: {
    customerFindings: 0,
    providerFindings: 0,
    vendorFindings: 0,
    browserDependencies: 0,
    cloudDependencies: 0,
    migrationBlockers: 0,
    actionableFindings: 0,
    waitingDependencies: 0,
    migrationProgress: 0,
    providerReadiness: 0,
  },
  providerBreakdown: [],
  edgeOrigin: { providerFrontedAssets: 0, edgeManaged: 0, originCustomerControlled: 0, summary: '' },
  attribution: { attributed: 0, unattributed: 0, avgConfidence: 0 },
  baseline: { quantumReadiness: 0, quantumReadinessLevel: 'Not Started' },
};

const REALTIME_TABLES = [
  'assets', 'pqc_scan_results', 'pqc_scan_sessions', 'crypto_inventory', 'crypto_exposures',
  'certificates', 'generated_keys', 'runtime_crypto_events', 'connector_accounts', 'migration_jobs',
];

/**
 * useMigrationIntelligence — fetches the Shared Responsibility Quantum Migration
 * Intelligence model from /api/v1/migration-intelligence, keeps it live via a
 * header-authenticated SSE stream (token never in the URL) and Supabase realtime
 * table subscriptions. Every value is tenant-scoped real data classified into
 * customer / provider / ecosystem ownership domains.
 */
export function useMigrationIntelligence() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [data, setData] = useState<MigrationIntelligence>(EMPTY_MIGRATION_INTELLIGENCE);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const apply = useCallback((next: Partial<MigrationIntelligence> | null) => {
    setData({ ...EMPTY_MIGRATION_INTELLIGENCE, ...(next || {}) });
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      apply(EMPTY_MIGRATION_INTELLIGENCE);
      setState('success');
      return;
    }
    setState((current) => (current === 'success' ? current : 'loading'));
    try {
      const response = await fetch('/api/v1/migration-intelligence', {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      apply(payload || {});
      setState('success');
      setError(null);
    } catch (err) {
      console.error('Migration intelligence load failed:', err);
      setError(err instanceof Error ? err.message : 'Unable to load migration intelligence');
      setState('error');
    }
  }, [token, apply]);

  const queueRefresh = useCallback(() => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null;
      void refresh();
    }, 500);
  }, [refresh]);

  useEffect(() => () => { if (refreshTimer.current) clearTimeout(refreshTimer.current); }, []);

  useEffect(() => {
    if (!token || !user) {
      apply(EMPTY_MIGRATION_INTELLIGENCE);
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh, apply]);

  // Dedicated SSE stream over fetch() + Authorization header (token never in URL).
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
      if (eventName === 'migration-intelligence' && dataLines.length) {
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
        const response = await fetch('/api/v1/migration-intelligence/stream', {
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

  // Supabase realtime — refresh on any tenant scan / crypto / connector mutation.
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`migration-intel-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => { for (const channel of channels) supabase.removeChannel(channel); };
  }, [user, queueRefresh]);

  return { data, state, error, sseConnected, refresh };
}
