'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type { QuantumRiskIntelligence } from '@/lib/quantum-risk/risk-intelligence';

export type LoadState = 'loading' | 'success' | 'error';

/** Tables whose mutation changes the snapshot or the portfolio this page reads. */
const REALTIME_TABLES = [
  'assets', 'crypto_inventory', 'crypto_exposures', 'pqc_scan_results',
  'pqc_scan_sessions', 'certificates', 'migration_jobs', 'runtime_crypto_events',
];

const RETRY_MS = 8000;

/**
 * useQuantumRisk — live data for /dashboard/quantum-risk-scoring.
 *
 * SSE runs over fetch() + ReadableStream with an Authorization HEADER. The
 * implementation this replaces used three `EventSource` connections with the
 * bearer token in the query string, which leaks it into access logs, proxies
 * and browser history — and opened three streams where one carries the whole
 * model.
 */
export function useQuantumRisk() {
  const { session, user } = useAuth();
  const token = session?.access_token;

  const [data, setData] = useState<QuantumRiskIntelligence | null>(null);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [lastGoodAt, setLastGoodAt] = useState<string | null>(null);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const apply = useCallback((next: QuantumRiskIntelligence) => {
    setData(next);
    setState('success');
    setError(null);
    setLastGoodAt(next.generatedAt ?? new Date().toISOString());
  }, []);

  const refresh = useCallback(
    async (force = false) => {
      if (!token) {
        setState('success');
        return;
      }
      setState((current) => (current === 'success' ? current : 'loading'));
      try {
        const response = await fetch(`/api/v1/dashboard/quantum-risk-scoring${force ? '?refresh=1' : ''}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!payload?.data) throw new Error('Quantum risk response was empty');
        apply(payload.data as QuantumRiskIntelligence);
      } catch (err) {
        console.error('Quantum risk load failed:', err);
        setError(err instanceof Error ? err.message : 'Unable to load the quantum risk assessment');
        setState((current) => (current === 'success' ? current : 'error'));
      }
    },
    [token, apply],
  );

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
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh]);

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
      if (!dataLines.length) return;
      if (eventName === 'quantum-risk') {
        try { apply(JSON.parse(dataLines.join('\n')) as QuantumRiskIntelligence); } catch { /* malformed frame */ }
      } else if (eventName === 'quantum-risk-error') {
        try { setError(String(JSON.parse(dataLines.join('\n'))?.message || 'Risk stream error')); } catch { /* ignore */ }
      }
    };

    const connect = async () => {
      try {
        const response = await fetch('/api/v1/dashboard/quantum-risk-scoring/stream', {
          headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`SSE ${response.status}`);
        setLive(true);
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
        setLive(false);
        if (retry) clearTimeout(retry);
        retry = setTimeout(() => void connect(), RETRY_MS);
      }
    };

    void connect();
    return () => {
      cancelled = true;
      controller.abort();
      if (retry) clearTimeout(retry);
      setLive(false);
    };
  }, [token, apply]);

  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`quantum-risk-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => { for (const channel of channels) supabase.removeChannel(channel); };
  }, [user, queueRefresh]);

  const reconnect = useCallback(() => { void refresh(true); }, [refresh]);

  return { data, state, error, live, lastGoodAt, refresh, reconnect };
}
