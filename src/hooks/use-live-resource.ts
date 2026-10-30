'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';

/**
 * useLiveResource — the ONE client for a dashboard payload that the server
 * keeps live over SSE (src/api-server/live-snapshot-stream.ts).
 *
 * The Quantum Readiness, Exposure Graph, Harvest Now, Remediation and
 * Certification hooks each carried a hand-copied fetch + stream reader, and
 * every one of them downloaded the payload twice on mount (REST and the
 * stream's first frame), applied every frame whether or not it had changed,
 * and retried a dead stream every 10s forever. The readiness hook did not
 * consume a stream of its own at all: it refetched the full snapshot each time
 * an unrelated 8s key-count pulse fired.
 *
 * Contract:
 *  • Stream first. The stream's first frame IS the initial load; REST is the
 *    fallback when no frame arrives within FIRST_FRAME_TIMEOUT_MS or the
 *    stream fails, and the path for explicit refreshes and realtime nudges.
 *  • Fingerprint de-dup. A payload whose `fingerprint` matches what is shown is
 *    not applied — no re-render for news that is not news.
 *  • `-unchanged` frames advance `lastVerifiedAt`: the server re-checked the
 *    estate. Liveness is visible without re-sending the data.
 *  • `loading` until the SERVER answers. An empty payload is never a stand-in
 *    for "not loaded yet".
 *  • Reset on tenant change; exponential reconnect backoff (2s → 30s).
 *  • The bearer token travels in the Authorization header, never the URL.
 */

export type LiveLoadState = 'loading' | 'success' | 'error';
export type LiveTransport = 'connecting' | 'stream' | 'polling' | 'offline';

const FIRST_FRAME_TIMEOUT_MS = 4_000;
let nextChannelSeq = 0;
const MAX_BACKOFF_MS = 30_000;
const REALTIME_DEBOUNCE_MS = 600;

export interface LiveResourceOptions<T> {
  url: string;
  streamUrl: string;
  /** Full-frame event name; `-unchanged` and `-error` are derived. */
  event: string;
  empty: T;
  /** Merge a raw payload onto the empty shape (defaults to a shallow merge). */
  normalize?: (raw: Record<string, unknown>) => T;
  /** Tenant tables whose writes should nudge a refresh. */
  realtimeTables?: readonly string[];
  /** Unique per hook, so two pages on one screen do not share channels. */
  channelPrefix: string;
}

export interface LiveResource<T> {
  data: T;
  state: LiveLoadState;
  error: string | null;
  /** True while the server stream is open and has answered. */
  sseConnected: boolean;
  transport: LiveTransport;
  /** Last time the server confirmed this payload is current (full or unchanged frame, or REST). */
  lastVerifiedAt: string | null;
  /**
   * `refresh({ force: true })` asks the server to bypass its single-flight
   * cache (`?refresh=1`). Typed `unknown` on purpose: pages pass `refresh`
   * straight to `onClick`, so a click event must be an acceptable argument
   * (it is simply not a force request).
   */
  refresh: (options?: unknown) => Promise<void>;
}

function isForceRequest(options: unknown): boolean {
  return Boolean(options && typeof options === 'object' && (options as { force?: unknown }).force === true);
}

export function useLiveResource<T>(options: LiveResourceOptions<T>): LiveResource<T> {
  const { url, streamUrl, event, empty, normalize, realtimeTables, channelPrefix } = options;
  const { session, user } = useAuth();
  const token = session?.access_token;
  const userId = user?.id;

  const [data, setData] = useState<T>(empty);
  const [state, setState] = useState<LiveLoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const [transport, setTransport] = useState<LiveTransport>('connecting');
  const [lastVerifiedAt, setLastVerifiedAt] = useState<string | null>(null);

  const fingerprintRef = useRef<string | null>(null);
  const hasDataRef = useRef(false);
  // Latest callbacks/options without re-running the connection effects.
  const normalizeRef = useRef(normalize);
  normalizeRef.current = normalize;
  const emptyRef = useRef(empty);
  emptyRef.current = empty;

  const apply = useCallback((raw: unknown) => {
    const record = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
    const fingerprint = typeof record.fingerprint === 'string' ? record.fingerprint : null;
    setLastVerifiedAt(new Date().toISOString());
    hasDataRef.current = true;
    setState('success');
    setError(null);
    if (fingerprint && fingerprint === fingerprintRef.current) return;
    fingerprintRef.current = fingerprint;
    const next = normalizeRef.current ? normalizeRef.current(record) : ({ ...(emptyRef.current as object), ...record } as T);
    setData(next);
  }, []);

  const refresh = useCallback(async (options?: unknown) => {
    if (!token) return;
    try {
      const target = isForceRequest(options) ? `${url}${url.includes('?') ? '&' : '?'}refresh=1` : url;
      const response = await fetch(target, { headers: { Authorization: `Bearer ${token}` } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      apply(payload.data ?? {});
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Request failed';
      console.error(`Live resource ${url} failed:`, err);
      setError(message);
      // Keep showing the last good payload; only an empty screen becomes an error screen.
      if (!hasDataRef.current) setState('error');
    }
  }, [token, url, apply]);

  // Tenant change ⇒ nothing from the previous tenant may remain on screen.
  // Keyed on the USER, not the token: the access token rotates hourly, and
  // resetting on rotation would blank every open dashboard once an hour.
  useEffect(() => {
    fingerprintRef.current = null;
    hasDataRef.current = false;
    setData(emptyRef.current);
    setError(null);
    setLastVerifiedAt(null);
    setState(userId ? 'loading' : 'success');
  }, [userId]);

  // Stream (primary transport) with REST fallback.
  useEffect(() => {
    if (!token) {
      setTransport('offline');
      setSseConnected(false);
      return;
    }
    const controller = new AbortController();
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let firstFrameTimer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;

    const handleFrame = (frame: string) => {
      let name = 'message';
      const lines: string[] = [];
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) name = line.slice(6).trim();
        else if (line.startsWith('data:')) lines.push(line.slice(5).replace(/^ /, ''));
      }
      if (!lines.length) return; // comment / heartbeat
      if (name === event) {
        try {
          apply(JSON.parse(lines.join('\n')));
          attempt = 0;
          if (firstFrameTimer) clearTimeout(firstFrameTimer);
          setSseConnected(true);
          setTransport('stream');
        } catch {
          /* malformed frame — keep the current payload */
        }
      } else if (name === `${event}-unchanged`) {
        setLastVerifiedAt(new Date().toISOString());
        setSseConnected(true);
        setTransport('stream');
      } else if (name === `${event}-error`) {
        try {
          const detail = JSON.parse(lines.join('\n')) as { message?: string };
          setError(detail?.message || 'Live update failed');
        } catch {
          setError('Live update failed');
        }
        if (!hasDataRef.current) void refresh();
      }
    };

    const connect = async () => {
      setTransport('connecting');
      if (firstFrameTimer) clearTimeout(firstFrameTimer);
      firstFrameTimer = setTimeout(() => {
        if (!cancelled && !hasDataRef.current) void refresh();
      }, FIRST_FRAME_TIMEOUT_MS);
      try {
        const response = await fetch(streamUrl, {
          headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`SSE ${response.status}`);
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n');
          let boundary = buffer.indexOf('\n\n');
          while (boundary !== -1) {
            handleFrame(buffer.slice(0, boundary));
            buffer = buffer.slice(boundary + 2);
            boundary = buffer.indexOf('\n\n');
          }
        }
        throw new Error('stream ended');
      } catch {
        if (cancelled || controller.signal.aborted) return;
        setSseConnected(false);
        setTransport('polling');
        // Keep the page current while the stream is down.
        void refresh();
        attempt += 1;
        const delay = Math.min(MAX_BACKOFF_MS, 2_000 * 2 ** Math.min(attempt - 1, 4));
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(() => void connect(), delay);
      }
    };

    void connect();
    return () => {
      cancelled = true;
      controller.abort();
      if (retryTimer) clearTimeout(retryTimer);
      if (firstFrameTimer) clearTimeout(firstFrameTimer);
      setSseConnected(false);
    };
  }, [token, streamUrl, event, apply, refresh]);

  // Supabase realtime: a tenant write nudges a refresh (de-duplicated by fingerprint).
  const tablesKey = (realtimeTables || []).join(',');
  useEffect(() => {
    if (!userId || !tablesKey) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const nudge = () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => void refresh(), REALTIME_DEBOUNCE_MS);
    };
    // Topic is unique PER HOOK INSTANCE: supabase.channel() returns the existing
    // channel for a duplicate topic, and .on() after .subscribe() throws — two
    // components on one page using the same page hook would blank the tree.
    const instance = nextChannelSeq++;
    const channels = tablesKey.split(',').map((table) =>
      supabase
        .channel(`${channelPrefix}-${table}-${userId}-${instance}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${userId}` }, nudge)
        .subscribe(),
    );
    return () => {
      if (timer) clearTimeout(timer);
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [userId, tablesKey, channelPrefix, refresh]);

  return { data, state, error, sseConnected, transport, lastVerifiedAt, refresh };
}

/**
 * useLiveModel — `useLiveResource` for a page whose model is "absent until the
 * server answers" (`data: T | null`), as the Intelligence dashboards render it.
 *
 * Adds the two things those pages need and the raw resource does not carry:
 *  • `lastGoodAt` — when the data on screen was COMPUTED (its `generatedAt`),
 *    distinct from `lastVerifiedAt`, when the server last confirmed it is still
 *    current. A connection-lost banner quotes the first; a freshness chip the second.
 *  • `refreshing` — a user-initiated refresh in flight, so a Refresh button can
 *    spin without the page dropping back into its loading skeleton.
 */
export interface LiveModel<T> {
  data: T | null;
  state: LiveLoadState;
  error: string | null;
  /** True only while the server stream is open and answering. */
  live: boolean;
  transport: LiveTransport;
  lastVerifiedAt: string | null;
  lastGoodAt: string | null;
  refreshing: boolean;
  /** `force` bypasses the server's single-flight cache. */
  refresh: (force?: boolean) => Promise<void>;
  /** Manual recovery for the connection-lost state: a forced REST read. */
  reconnect: () => void;
}

export function useLiveModel<T extends { generatedAt?: string | null }>(
  options: Omit<LiveResourceOptions<T | null>, 'empty' | 'normalize'>,
): LiveModel<T> {
  const resource = useLiveResource<T | null>({
    ...options,
    empty: null,
    normalize: (raw) => raw as unknown as T,
  });
  const [refreshing, setRefreshing] = useState(false);
  const { refresh: refreshResource } = resource;

  const refresh = useCallback(async (force = false) => {
    setRefreshing(true);
    try {
      await refreshResource({ force });
    } finally {
      setRefreshing(false);
    }
  }, [refreshResource]);

  const reconnect = useCallback(() => { void refresh(true); }, [refresh]);

  return {
    data: resource.data,
    state: resource.state,
    error: resource.error,
    live: resource.sseConnected,
    transport: resource.transport,
    lastVerifiedAt: resource.lastVerifiedAt,
    lastGoodAt: resource.data?.generatedAt ?? resource.lastVerifiedAt,
    refreshing,
    refresh,
    reconnect,
  };
}

/** Download a payload as pretty JSON (shared by the evidence-export buttons). */
export function downloadJsonFile(filenamePrefix: string, payload: unknown): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(href);
}
