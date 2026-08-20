'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type {
  AlgorithmRow,
  AtRestCoverage,
  DataProtectionPosture,
  EncryptionFinding,
  EncryptionIntelligence,
  EncryptionObservation,
  KeyInventory,
  OperationProfile,
  TelemetryHealth,
  VaultProtection,
} from '@/lib/encryption/types';

export type LoadState = 'loading' | 'success' | 'error';

const API_BASE = '/api/v1/dashboard/encryption-monitoring';

/** Mirrors `projectView()` in src/api-server/encryption-monitoring.ts. */
export interface EncryptionPayload {
  generatedAt: string;
  latestEvidenceAt: string | null;
  hasData: boolean;
  posture: DataProtectionPosture;
  telemetry: TelemetryHealth;
  timeline: EncryptionIntelligence['timeline'];

  symmetric: AlgorithmRow[];
  hashes: AlgorithmRow[];
  macs: AlgorithmRow[];
  kdfs: AlgorithmRow[];
  application: AlgorithmRow[];

  keys: KeyInventory;
  atRest: AtRestCoverage;
  vault: VaultProtection;
  operations: OperationProfile;
  findings: EncryptionFinding[];

  totals: {
    observations: number;
    algorithms: number;
    applicationAlgorithms: number;
    findings: number;
    keys: number;
    atRestRecords: number;
    vaultFiles: number;
  };
}

export interface AlgorithmDetail {
  algorithm: AlgorithmRow;
  observations: EncryptionObservation[];
  findings: EncryptionFinding[];
}

/**
 * Tables whose mutation changes what this page shows.
 *
 * Narrower than the TLS suite's list on purpose: this console reads data
 * protection, so a certificate write is not a reason to re-fetch it.
 */
const REALTIME_TABLES = [
  'assets',
  'crypto_inventory',
  'runtime_crypto_events',
  'scanner_evidence',
  'generated_keys',
  'vault_files',
  'crypto_exposures',
  'pqc_scan_results',
  'scanner_alerts',
] as const;

const RETRY_MIN_MS = 3_000;
const RETRY_MAX_MS = 30_000;

/**
 * useEncryptionMonitoring — the live data contract for
 * /dashboard/encryption-monitoring.
 *
 * Same three-channel pattern as the TLS/PKI hook: an authoritative fetch, a
 * header-authenticated SSE stream carrying the whole payload, and a debounced
 * Supabase realtime nudge. `live` is true only while the stream is genuinely
 * open, so stale figures are never presented as real-time.
 */
export function useEncryptionMonitoring() {
  const { session, user } = useAuth();
  const token = session?.access_token;

  const [data, setData] = useState<EncryptionPayload | null>(null);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);

  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastGeneratedRef = useRef<number>(0);

  const apply = useCallback((next: EncryptionPayload) => {
    const generated = Date.parse(next.generatedAt || '');
    if (Number.isFinite(generated)) {
      if (generated < lastGeneratedRef.current) return;
      lastGeneratedRef.current = generated;
    }
    setData(next);
    setState('success');
    setError(null);
    setLastSyncedAt(new Date().toISOString());
  }, []);

  const refresh = useCallback(
    async (force = false) => {
      if (!token) {
        setState('success');
        return;
      }
      setState((current) => (current === 'success' ? current : 'loading'));
      try {
        const response = await fetch(`${API_BASE}${force ? '?refresh=1' : ''}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!payload?.data) throw new Error('Encryption intelligence response was empty');
        apply(payload.data as EncryptionPayload);
      } catch (err) {
        console.error('Encryption monitoring load failed:', err);
        setError(err instanceof Error ? err.message : 'Unable to load encryption intelligence');
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
    }, 600);
  }, [refresh]);

  useEffect(
    () => () => {
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
    },
    [],
  );

  useEffect(() => {
    if (!token || !user) {
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh]);

  /* ---- SSE ---------------------------------------------------------- */
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    let retry: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let cancelled = false;

    const parseFrame = (frame: string) => {
      let eventName = 'message';
      const dataLines: string[] = [];
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) eventName = line.slice(6).trim();
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''));
      }
      if (!dataLines.length) return;
      const body = dataLines.join('\n');
      if (eventName === 'encryption-intel') {
        try {
          apply(JSON.parse(body) as EncryptionPayload);
        } catch {
          /* malformed frame — keep the last good model */
        }
      } else if (eventName === 'encryption-error') {
        try {
          setError(String(JSON.parse(body)?.message || 'Encryption telemetry stream error'));
        } catch {
          /* ignore */
        }
      }
    };

    const connect = async () => {
      try {
        const response = await fetch(`${API_BASE}/stream`, {
          headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`SSE ${response.status}`);
        attempt = 0;
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
        attempt += 1;
        const delay = Math.min(RETRY_MAX_MS, RETRY_MIN_MS * 2 ** Math.min(attempt - 1, 4));
        if (retry) clearTimeout(retry);
        retry = setTimeout(() => void connect(), delay);
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

  /* ---- Supabase realtime -------------------------------------------- */
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`encryption-monitoring-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [user, queueRefresh]);

  const reconnect = useCallback(() => {
    void refresh(true);
  }, [refresh]);

  return { data, state, error, live, lastSyncedAt, refresh, reconnect };
}

/* ------------------------------------------------------------------ */
/* Drill-down                                                          */
/* ------------------------------------------------------------------ */

export function useAlgorithmDetail() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [loading, setLoading] = useState(false);

  const loadAlgorithm = useCallback(
    async (label: string): Promise<AlgorithmDetail | null> => {
      if (!token) return null;
      setLoading(true);
      try {
        const response = await fetch(`${API_BASE}/algorithms/${encodeURIComponent(label)}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        return (payload.data ?? null) as AlgorithmDetail | null;
      } catch (err) {
        console.error('Algorithm detail load failed:', err);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [token],
  );

  return { loadAlgorithm, loading };
}

/* ------------------------------------------------------------------ */
/* Server-side paged tables                                            */
/* ------------------------------------------------------------------ */

export function useEncryptionTable<T>(
  path: string,
  key: string,
  query: Record<string, string | number | undefined>,
  revision: number,
) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [rows, setRows] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  const serialized = JSON.stringify(query);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        const params = new URLSearchParams();
        for (const [name, value] of Object.entries(JSON.parse(serialized) as Record<string, string | number | undefined>)) {
          if (value === undefined || value === '' || value === 'all') continue;
          params.set(name, String(value));
        }
        const response = await fetch(`${API_BASE}${path}?${params.toString()}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        setRows((payload.data?.[key] ?? []) as T[]);
        setTotal(Number(payload.data?.total ?? 0));
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') return;
        console.error('Encryption table load failed:', err);
      } finally {
        setLoading(false);
      }
    }, 250);

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token, path, key, serialized, revision]);

  return { rows, total, loading };
}
