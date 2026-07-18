'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { EMPTY_EXPOSURE_INTELLIGENCE, type ExposureIntelligence } from '@/types/exposure-graph';

export type LoadState = 'loading' | 'success' | 'error';

// Mirrors EXACTLY the evidence tables the exposure-graph assembler reads.
const REALTIME_TABLES = [
  'assets',
  'asset_relationships',
  'crypto_inventory',
  'crypto_exposures',
  'certificates',
  'runtime_crypto_events',
  'pqc_scan_results',
  'connector_accounts',
  'migration_jobs',
];

/**
 * useExposureGraph — fetches the Enterprise Cryptographic Dependency &
 * Migration Intelligence model (/api/v1/exposure-graph), keeps it live via a
 * dedicated SSE stream (header-authenticated fetch — token never in the URL)
 * plus Supabase realtime table subscriptions. Every value is tenant-scoped
 * real evidence.
 */
export function useExposureGraph() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [data, setData] = useState<ExposureIntelligence>(EMPTY_EXPOSURE_INTELLIGENCE);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const apply = useCallback((next: Partial<ExposureIntelligence> | null) => {
    setData({ ...EMPTY_EXPOSURE_INTELLIGENCE, ...(next || {}) });
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      apply(EMPTY_EXPOSURE_INTELLIGENCE);
      setState('success');
      return;
    }
    setState((current) => (current === 'success' ? current : 'loading'));
    try {
      const response = await fetch('/api/v1/exposure-graph', {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      apply(payload.data || {});
      setState('success');
      setError(null);
    } catch (err) {
      console.error('Exposure graph load failed:', err);
      setError(err instanceof Error ? err.message : 'Unable to load exposure graph intelligence');
      setState('error');
    }
  }, [token, apply]);

  const queueRefresh = useCallback(() => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null;
      void refresh();
    }, 400);
  }, [refresh]);

  useEffect(() => () => { if (refreshTimer.current) clearTimeout(refreshTimer.current); }, []);

  useEffect(() => {
    if (!token || !user) {
      apply(EMPTY_EXPOSURE_INTELLIGENCE);
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh, apply]);

  // Dedicated SSE stream over fetch() + Authorization header (EventSource
  // cannot set headers and would force the bearer token into the URL).
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
      if (eventName === 'exposure-intelligence' && dataLines.length) {
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
        const response = await fetch('/api/v1/exposure-graph/stream', {
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

  // Supabase realtime — refresh on any tenant evidence mutation.
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`exposure-graph-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => { for (const channel of channels) supabase.removeChannel(channel); };
  }, [user, queueRefresh]);

  const downloadJson = useCallback(
    (filenamePrefix: string, payload?: unknown) => {
      const blob = new Blob([JSON.stringify(payload ?? data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    },
    [data],
  );

  return { data, state, error, sseConnected, refresh, downloadJson };
}
