'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type {
  RuntimeCryptoIntelligence,
  TimeWindowKey,
} from '@/lib/runtime-crypto/runtime-intelligence';

export type LoadState = 'loading' | 'success' | 'error';

/**
 * Tables whose mutation can change what this page shows. Runtime events are the
 * primary signal; migration jobs and assets change the expected-vs-actual
 * baseline and the priority weighting, so a change there must also refresh.
 */
const REALTIME_TABLES = ['runtime_crypto_events', 'migration_jobs', 'assets', 'scanner_agents'];

/** Reconnect backoff for the SSE stream, in milliseconds. */
const RETRY_MS = 8000;

/**
 * useRuntimeCryptoIntel — the live data contract for
 * /dashboard/runtime-crypto-intel.
 *
 * Three cooperating channels, each with a distinct job:
 *   1. fetch()  — the authoritative first paint and every manual refresh.
 *   2. SSE      — the live push, over fetch() + ReadableStream with an
 *                 Authorization HEADER. EventSource cannot set headers, which
 *                 forces the bearer token into the query string where it leaks
 *                 into access logs, proxies and browser history.
 *   3. Supabase realtime — a debounced nudge when the tenant's own rows change,
 *                 so an agent write lands without waiting for the next push.
 *
 * `live` is the honest connection state: it is true only while the stream is
 * actually open. The page must never present stale data as live (§20), so the
 * last successful sync time is tracked separately and shown when the stream
 * drops.
 */
export function useRuntimeCryptoIntel(window: TimeWindowKey = '24h') {
  const { session, user } = useAuth();
  const token = session?.access_token;

  const [data, setData] = useState<RuntimeCryptoIntelligence | null>(null);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [lastGoodAt, setLastGoodAt] = useState<string | null>(null);

  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const apply = useCallback((next: RuntimeCryptoIntelligence) => {
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
        const params = new URLSearchParams({ window });
        if (force) params.set('refresh', '1');
        const response = await fetch(`/api/v1/runtime-crypto-intel?${params.toString()}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!payload?.data) throw new Error('Runtime telemetry response was empty');
        apply(payload.data as RuntimeCryptoIntelligence);
      } catch (err) {
        console.error('Runtime crypto intelligence load failed:', err);
        setError(err instanceof Error ? err.message : 'Unable to load runtime cryptographic intelligence');
        // Keep the last good model on screen rather than blanking the page; the
        // header switches to a "connection lost" state so nothing reads as live.
        setState((current) => (current === 'success' ? current : 'error'));
      }
    },
    [token, window, apply],
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

  /* ---- SSE: header-authenticated, token never in the URL ------------ */
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
        // lines starting with ':' are heartbeats/comments — ignored
      }
      if (!dataLines.length) return;
      if (eventName === 'runtime-intel') {
        try {
          apply(JSON.parse(dataLines.join('\n')) as RuntimeCryptoIntelligence);
        } catch {
          /* ignore malformed frame */
        }
      } else if (eventName === 'runtime-error') {
        try {
          setError(String(JSON.parse(dataLines.join('\n'))?.message || 'Runtime telemetry stream error'));
        } catch {
          /* ignore malformed frame */
        }
      }
    };

    const connect = async () => {
      try {
        const response = await fetch(`/api/v1/runtime-crypto-intel/stream?window=${encodeURIComponent(window)}`, {
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
  }, [token, window, apply]);

  /* ---- Supabase realtime: nudge on the tenant's own writes ---------- */
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`runtime-intel-${table}`)
        .on(
          'postgres_changes',
          { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` },
          queueRefresh,
        )
        .subscribe(),
    );
    return () => { for (const channel of channels) supabase.removeChannel(channel); };
  }, [user, queueRefresh]);

  /** Manual reconnect for the "connection lost" state (§20). */
  const reconnect = useCallback(() => { void refresh(true); }, [refresh]);

  return { data, state, error, live, lastGoodAt, refresh, reconnect };
}
