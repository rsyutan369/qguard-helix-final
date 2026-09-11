'use client';

/**
 * Exposure Assessment History — client hook.
 *
 * Drives `/api/v1/exposure/history` for the History tab on
 * `/dashboard/scanner?mode=local` and `?mode=dev`.
 *
 * The list is delivered over SSE, not polled: the server holds the tenant's
 * recorded assessments and pushes a new snapshot the moment one is written, a
 * Dev assessment moves, or a record is deleted. The initial `GET` exists only so
 * the tab renders before the stream attaches — after that every update arrives
 * on the stream, and a reconnection replays the current snapshot rather than a
 * delta, so a tab left open overnight cannot drift.
 *
 * Detail is fetched per assessment and cached for the life of the hook: opening
 * the same recorded scan twice must not re-run the rehydration, and a scan that
 * is already recorded cannot change underneath the reader.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  ExposureHistoryEntry,
  ExposureHistoryMode,
  ExposureHistorySummary,
  HistoryProvenance,
} from '@/lib/scanner/exposure/history';
import type { ExposureAssessment } from '@/lib/scanner/exposure/types';
import { DEMO_ACCESS_TOKEN, isDemoSessionActive } from '@/lib/demo-account';

export interface ExposureHistoryDetail {
  entry: ExposureHistoryEntry;
  assessment: ExposureAssessment;
  provenance: HistoryProvenance;
}

export interface ExposureHistoryPayload {
  mode: ExposureHistoryMode;
  entries: ExposureHistoryEntry[];
  summary: ExposureHistorySummary;
  total: number;
  truncated: boolean;
  generatedAt: string;
  notes: string[];
}

export interface UseExposureHistoryResult {
  entries: ExposureHistoryEntry[];
  summary: ExposureHistorySummary | null;
  total: number;
  truncated: boolean;
  notes: string[];
  /** When the snapshot on screen was produced by the server. */
  generatedAt: string | null;
  loading: boolean;
  error: string | null;
  /** True while the SSE subscription is attached and delivering snapshots. */
  streamOpen: boolean;

  refresh: () => Promise<void>;
  loadDetail: (scanId: string) => Promise<ExposureHistoryDetail | null>;
  detailFor: (scanId: string) => ExposureHistoryDetail | null;
  detailState: { scanId: string | null; loading: boolean; error: string | null };
  remove: (scanId: string) => Promise<void>;
}

/**
 * The caller's Supabase access token, or null.
 *
 * Found by SHAPE rather than by a hardcoded key, because the storage key is
 * project-ref scoped. Same helper as `use-exposure-scan`, kept local so the two
 * hooks have no import-time dependency on one another.
 */
function accessToken(): string | null {
  /* The demo identity deliberately exists OUTSIDE Supabase (see
     tasks/demo-account.md), so it has no `sb-*-auth-token` to find by shape.
     Without this branch the History tab is the one surface a demo session
     cannot open. `isDemoSessionActive` is false unless the build flag is on,
     so this adds no path in a real deployment. */
  if (isDemoSessionActive()) return DEMO_ACCESS_TOKEN;

  try {
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (!key || !key.startsWith('sb-') || !key.endsWith('-auth-token')) continue;
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      const parsed = JSON.parse(raw);
      const token = parsed?.access_token ?? parsed?.currentSession?.access_token;
      if (typeof token === 'string' && token.length > 0) return token;
    }
  } catch {
    /* no session available */
  }
  return null;
}

function authHeaders(): HeadersInit {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = accessToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function readError(response: Response, fallback: string): Promise<string> {
  try {
    const payload = await response.json();
    return payload?.error?.message ?? fallback;
  } catch {
    return fallback;
  }
}

export function useExposureHistory(
  mode: ExposureHistoryMode,
  /** The tab mounts the hook only when it is visible; a closed tab holds no stream. */
  options: { enabled?: boolean } = {},
): UseExposureHistoryResult {
  const enabled = options.enabled !== false;

  const [payload, setPayload] = useState<ExposureHistoryPayload | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState<string | null>(null);
  const [streamOpen, setStreamOpen] = useState(false);
  const [detailState, setDetailState] = useState<{ scanId: string | null; loading: boolean; error: string | null }>({
    scanId: null,
    loading: false,
    error: null,
  });

  const detailCache = useRef(new Map<string, ExposureHistoryDetail>());
  const sourceRef = useRef<EventSource | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  /* A mode change invalidates every cached detail: scan ids are unique, but the
     cache must not outlive the surface it belongs to. */
  useEffect(() => {
    detailCache.current.clear();
    setDetailState({ scanId: null, loading: false, error: null });
  }, [mode]);

  const refresh = useCallback(async () => {
    if (!enabled) return;
    setLoading(true);
    try {
      const response = await fetch(`/api/v1/exposure/history?mode=${mode}`, { headers: authHeaders() });
      if (!response.ok) {
        setError(await readError(response, 'The assessment history could not be read.'));
        return;
      }
      const body = await response.json();
      if (!mountedRef.current) return;
      setPayload(body.data as ExposureHistoryPayload);
      setError(null);
    } catch (cause) {
      if (mountedRef.current) setError((cause as Error).message || 'The assessment history could not be read.');
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [enabled, mode]);

  /* ── first snapshot ───────────────────────────────────────────────────── */
  useEffect(() => {
    if (!enabled) return;
    void refresh();
  }, [enabled, refresh]);

  /* ── live snapshots ───────────────────────────────────────────────────── */
  useEffect(() => {
    if (!enabled) return;
    const token = accessToken();
    if (!token) return;

    /* `EventSource` cannot set a header, so the token travels in the URL — the
       same widening every other authenticated stream on this platform uses, and
       the reason the route is read-only. */
    const url = `/api/v1/exposure/history/stream?mode=${mode}&token=${encodeURIComponent(token)}`;
    const source = new EventSource(url);
    sourceRef.current = source;

    source.onopen = () => {
      if (mountedRef.current) setStreamOpen(true);
    };

    source.addEventListener('exposure-history', (event) => {
      if (!mountedRef.current) return;
      try {
        const data = JSON.parse((event as MessageEvent).data) as ExposureHistoryPayload;
        setPayload(data);
        setError(null);
        setLoading(false);
        /* A recorded assessment never changes, but a session-only one does, and
           a deleted one must not stay openable. Detail for anything no longer in
           the snapshot — or still running — is dropped. */
        const live = new Set(data.entries.filter((entry) => entry.live?.running !== true).map((entry) => entry.scanId));
        for (const scanId of [...detailCache.current.keys()]) {
          if (!live.has(scanId)) detailCache.current.delete(scanId);
        }
      } catch {
        /* a malformed frame must not tear the stream down */
      }
    });

    source.addEventListener('exposure-history-error', (event) => {
      if (!mountedRef.current) return;
      try {
        const data = JSON.parse((event as MessageEvent).data) as { message?: string };
        setError(data.message ?? 'The assessment history stream reported a failure.');
      } catch {
        setError('The assessment history stream reported a failure.');
      }
    });

    source.onerror = () => {
      if (!mountedRef.current) return;
      setStreamOpen(false);
      /* EventSource reconnects on its own; a CLOSED socket is the only one that
         will not, and that is when the tab falls back to a plain fetch. */
      if (source.readyState === EventSource.CLOSED) void refresh();
    };

    return () => {
      source.close();
      sourceRef.current = null;
      setStreamOpen(false);
    };
  }, [enabled, mode, refresh]);

  /* ── detail ───────────────────────────────────────────────────────────── */
  const loadDetail = useCallback(
    async (scanId: string): Promise<ExposureHistoryDetail | null> => {
      const cached = detailCache.current.get(scanId);
      if (cached) {
        setDetailState({ scanId, loading: false, error: null });
        return cached;
      }

      setDetailState({ scanId, loading: true, error: null });
      try {
        const response = await fetch(
          `/api/v1/exposure/history/${encodeURIComponent(scanId)}?mode=${mode}`,
          { headers: authHeaders() },
        );
        if (!response.ok) {
          const message = await readError(response, 'This assessment could not be opened.');
          if (mountedRef.current) setDetailState({ scanId, loading: false, error: message });
          return null;
        }
        const body = await response.json();
        const detail = body.data as ExposureHistoryDetail;
        detailCache.current.set(scanId, detail);
        if (mountedRef.current) setDetailState({ scanId, loading: false, error: null });
        return detail;
      } catch (cause) {
        const message = (cause as Error).message || 'This assessment could not be opened.';
        if (mountedRef.current) setDetailState({ scanId, loading: false, error: message });
        return null;
      }
    },
    [mode],
  );

  const detailFor = useCallback((scanId: string) => detailCache.current.get(scanId) ?? null, []);

  const remove = useCallback(
    async (scanId: string) => {
      const response = await fetch(
        `/api/v1/exposure/history/${encodeURIComponent(scanId)}?mode=${mode}`,
        { method: 'DELETE', headers: authHeaders() },
      );
      if (!response.ok) throw new Error(await readError(response, 'This assessment could not be deleted.'));
      detailCache.current.delete(scanId);
      /* The server signals its own stream on delete; this keeps the tab correct
         even when the stream is not attached. */
      await refresh();
    },
    [mode, refresh],
  );

  return useMemo(
    () => ({
      entries: payload?.entries ?? [],
      summary: payload?.summary ?? null,
      total: payload?.total ?? 0,
      truncated: payload?.truncated ?? false,
      notes: payload?.notes ?? [],
      generatedAt: payload?.generatedAt ?? null,
      loading,
      error,
      streamOpen,
      refresh,
      loadDetail,
      detailFor,
      detailState,
      remove,
    }),
    [payload, loading, error, streamOpen, refresh, loadDetail, detailFor, detailState, remove],
  );
}
