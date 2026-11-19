'use client';

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';

/**
 * Dashboard snapshots arrive over SSE, with REST polling while the stream is
 * unavailable. Transport liveness and the snapshot's evidence timestamp are
 * independent. Each response belongs to the session that requested it.
 */

export type LiveLoadState = 'loading' | 'success' | 'error';
export type LiveTransport = 'connecting' | 'stream' | 'polling' | 'offline';

const INITIAL_FALLBACK_MS = 4_000;
const FIRST_FRAME_DEADLINE_MS = 35_000;
// The slowest caller sends snapshots every 30s. Heartbeats do not reset this.
const FRAME_DEADLINE_MS = 65_000;
const POLL_INTERVAL_MS = 15_000;
const REST_TIMEOUT_MS = 12_000;
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
  /** Verify the endpoint-specific payload before accepting either transport. */
  validate?: (raw: Record<string, unknown>) => boolean;
  /** Tenant tables whose writes should nudge a refresh. */
  realtimeTables?: readonly string[];
  /** Unique per hook, so two pages on one screen do not share channels. */
  channelPrefix: string;
  /**
   * Pull the payload out of the REST body. Defaults to the platform envelope
   * (`{ data }`); a route that answers with the bare payload passes its own.
   * Return null for a body that is not a usable payload — it is then an error,
   * never an empty dashboard.
   */
  unwrap?: (body: unknown) => unknown;
}

export interface LiveResource<T> {
  data: T;
  state: LiveLoadState;
  error: string | null;
  /** True while the server stream is open and has answered. */
  sseConnected: boolean;
  transport: LiveTransport;
  /** Server watermark for the displayed model. A cached response does not advance it. */
  lastVerifiedAt: string | null;
  /** Receipt time for the last usable stream frame or REST response. */
  lastReceivedAt: string | null;
  /**
   * `refresh({ force: true })` asks the server to bypass its single-flight
   * cache (`?refresh=1`). Typed `unknown` on purpose: pages pass `refresh`
   * straight to `onClick`, so a click event must be an acceptable argument
   * (it is simply not a force request).
   */
  refresh: (options?: unknown) => Promise<void>;
  /** Restart the stream immediately and request a fresh REST snapshot. */
  reconnect: () => void;
}

function isForceRequest(options: unknown): boolean {
  return Boolean(options && typeof options === 'object' && (options as { force?: unknown }).force === true);
}

type SnapshotRecord = Record<string, unknown>;
type SnapshotState<T> = Omit<LiveResource<T>, 'sseConnected' | 'refresh' | 'reconnect'>;

function nonEmptyRecord(value: unknown): value is SnapshotRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length);
}

function timestamp(value: unknown): string | null {
  return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : null;
}

function watermark(record: SnapshotRecord): string | null {
  return timestamp(record.sourceCheckedAt) ?? timestamp(record.checkedAt) ?? timestamp(record.generatedAt);
}

function isOlder(next: string | null, previous: string | null): boolean {
  return Boolean(next && previous && Date.parse(next) < Date.parse(previous));
}

function initialState<T>(data: T, authenticated: boolean): SnapshotState<T> {
  return {
    data,
    state: authenticated ? 'loading' : 'success',
    error: null,
    transport: authenticated ? 'connecting' : 'offline',
    lastVerifiedAt: null,
    lastReceivedAt: null,
  };
}

export function useLiveResource<T>(options: LiveResourceOptions<T>): LiveResource<T> {
  const { url, streamUrl, event, empty, normalize, validate, realtimeTables, channelPrefix, unwrap } = options;
  const { session, user } = useAuth();
  const userId = user?.id;
  const token = userId && userId === session?.user.id ? session.access_token : undefined;
  const authorized = Boolean(token);
  const scope = useMemo(() => ({}), [userId, authorized, url, streamUrl, event]);
  const activeScope = useRef<object | null>(null);
  const optionsRef = useRef({ empty, normalize, validate, unwrap });
  useLayoutEffect(() => {
    optionsRef.current = { empty, normalize, validate, unwrap };
  }, [empty, normalize, validate, unwrap]);

  const [snapshot, setSnapshot] = useState(() => ({ scope, ...initialState(empty, authorized) }));
  const [reconnectSequence, setReconnectSequence] = useState(0);
  const accepted = useRef<{ fingerprint: string | null; watermark: string | null }>({ fingerprint: null, watermark: null });
  const inFlight = useRef<{ scope: object; token: string; force: boolean; controller: AbortController; promise: Promise<void> } | null>(null);

  useLayoutEffect(() => {
    activeScope.current = scope;
    accepted.current = { fingerprint: null, watermark: null };
    return () => {
      activeScope.current = null;
      if (inFlight.current?.scope === scope) inFlight.current.controller.abort();
    };
  }, [scope]);

  const update = useCallback((change: (current: SnapshotState<T>) => SnapshotState<T>) => {
    if (activeScope.current !== scope) return;
    setSnapshot((current) => ({
      ...change(current.scope === scope ? current : initialState(optionsRef.current.empty, authorized)),
      scope,
    }));
  }, [scope, authorized]);

  const readRecord = useCallback((raw: unknown): SnapshotRecord | null => {
    const check = optionsRef.current.validate;
    return nonEmptyRecord(raw) && (!check || check(raw)) ? raw : null;
  }, []);

  const apply = useCallback((record: SnapshotRecord, fromStream: boolean) => {
    if (activeScope.current !== scope) return;
    const verifiedAt = watermark(record);
    const receivedAt = new Date().toISOString();
    const fingerprint = typeof record.fingerprint === 'string' ? record.fingerprint : null;
    const previous = accepted.current;
    const older = isOlder(verifiedAt, previous.watermark);
    const sameContent = Boolean(fingerprint && fingerprint === previous.fingerprint);
    const payload = older || sameContent ? null : optionsRef.current.normalize
      ? optionsRef.current.normalize(record)
      : ({ ...(optionsRef.current.empty as object), ...record } as T);

    if (!older) {
      accepted.current = { fingerprint, watermark: verifiedAt };
    }
    update((current) => ({
      ...current,
      data: older || sameContent ? current.data : payload as T,
      state: 'success',
      error: null,
      transport: fromStream || current.transport === 'stream' ? 'stream' : 'polling',
      lastVerifiedAt: older ? current.lastVerifiedAt : verifiedAt,
      lastReceivedAt: receivedAt,
    }));
  }, [scope, update]);

  const refresh = useCallback((params?: unknown): Promise<void> => {
    if (!token || activeScope.current !== scope) return Promise.resolve();
    const force = isForceRequest(params);
    const running = inFlight.current;
    if (running?.scope === scope && running.token === token && !running.controller.signal.aborted) {
      if (force && !running.force) return running.promise.then(() => refresh(params));
      return running.promise;
    }
    running?.controller.abort();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REST_TIMEOUT_MS);
    const promise = (async () => {
      try {
        const target = force ? url + (url.includes('?') ? '&' : '?') + 'refresh=1' : url;
        const response = await fetch(target, {
          headers: { Authorization: 'Bearer ' + token },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => null);
        if (!response.ok) throw new Error(payload?.error?.message || 'HTTP ' + response.status);
        const extract = optionsRef.current.unwrap;
        const body = readRecord(extract ? extract(payload) : payload?.data);
        if (!body) throw new Error('The dashboard response was empty or malformed');
        if (!controller.signal.aborted) apply(body, false);
      } catch (err) {
        if (activeScope.current !== scope || (controller.signal.aborted && inFlight.current?.controller !== controller)) return;
        const message = controller.signal.aborted ? 'Dashboard refresh timed out' : err instanceof Error ? err.message : 'Dashboard refresh failed';
        update((current) => current.transport === 'stream' ? current : ({
          ...current,
          error: message,
          state: current.state === 'success' ? 'success' : 'error',
          transport: 'offline',
        }));
      } finally {
        clearTimeout(timeout);
      }
    })();
    inFlight.current = { scope, token, force, controller, promise };
    void promise.finally(() => {
      if (inFlight.current?.controller === controller) inFlight.current = null;
    });
    return promise;
  }, [token, scope, url, apply, update, readRecord]);

  const reconnect = useCallback(() => {
    if (activeScope.current !== scope || !token) return;
    setReconnectSequence((value) => value + 1);
    void refresh({ force: true });
  }, [scope, token, refresh]);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    let healthy = false;
    let attempt = 0;
    let connection: AbortController | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let deadline: ReturnType<typeof setTimeout> | undefined;

    update((current) => ({ ...current, transport: current.lastReceivedAt ? 'polling' : 'connecting' }));
    const initialFallback = setTimeout(() => {
      if (!healthy) void refresh();
    }, INITIAL_FALLBACK_MS);
    const poll = setInterval(() => {
      if (!healthy) void refresh();
    }, POLL_INTERVAL_MS);

    const connect = async () => {
      const controller = new AbortController();
      connection = controller;
      let timeoutMessage = 'The live stream did not send an initial snapshot';
      let receivedFingerprint: string | null = null;
      let receivedSnapshot = false;
      const arm = (time: number, message: string) => {
        clearTimeout(deadline);
        timeoutMessage = message;
        deadline = setTimeout(() => controller.abort(), time);
      };
      const markHealthy = () => {
        healthy = true;
        attempt = 0;
        arm(FRAME_DEADLINE_MS, 'The live stream stopped sending snapshots');
      };
      const frame = (text: string) => {
        let name = '';
        const lines: string[] = [];
        for (const line of text.split('\n')) {
          if (line.startsWith('event:')) name = line.slice(6).trim();
          else if (line.startsWith('data:')) lines.push(line.slice(5).replace(/^ /, ''));
        }
        if (!lines.length) return;
        let json: unknown;
        try { json = JSON.parse(lines.join('\n')); } catch { return; }
        if (name === event + '-error') {
          throw new Error(nonEmptyRecord(json) && typeof json.message === 'string' ? json.message : 'The live stream could not build a snapshot');
        }
        if (name === event) {
          const body = readRecord(json);
          if (!body) return;
          apply(body, true);
          receivedSnapshot = true;
          receivedFingerprint = typeof body.fingerprint === 'string' ? body.fingerprint : null;
          markHealthy();
        } else if (name === event + '-unchanged' && receivedSnapshot && nonEmptyRecord(json)
          && receivedFingerprint && json.fingerprint === receivedFingerprint) {
          const verifiedAt = watermark(json);
          const same = receivedFingerprint === accepted.current.fingerprint;
          const canAdvance = same && verifiedAt && !isOlder(verifiedAt, accepted.current.watermark);
          if (canAdvance) accepted.current.watermark = verifiedAt;
          update((current) => ({
            ...current,
            error: null,
            transport: 'stream',
            lastReceivedAt: new Date().toISOString(),
            lastVerifiedAt: canAdvance ? verifiedAt : current.lastVerifiedAt,
          }));
          markHealthy();
        }
      };

      arm(FIRST_FRAME_DEADLINE_MS, timeoutMessage);
      try {
        const response = await fetch(streamUrl, {
          headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error('Live stream HTTP ' + response.status);
        if (response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'text/event-stream') {
          throw new Error('The dashboard returned a non-stream response');
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (cancelled || activeScope.current !== scope) return;
          if (controller.signal.aborted) throw new Error(timeoutMessage);
          if (done) throw new Error('The live stream ended');
          buffer = (buffer + decoder.decode(value, { stream: true })).replace(/\r\n/g, '\n');
          let boundary = buffer.indexOf('\n\n');
          while (boundary !== -1) {
            frame(buffer.slice(0, boundary));
            buffer = buffer.slice(boundary + 2);
            boundary = buffer.indexOf('\n\n');
          }
          if (buffer.length > 8_000_000) throw new Error('The live stream sent an incomplete snapshot');
        }
      } catch (err) {
        if (cancelled || activeScope.current !== scope) return;
        const message = controller.signal.aborted ? timeoutMessage : err instanceof Error ? err.message : 'The live stream disconnected';
        healthy = false;
        update((current) => ({ ...current, transport: 'polling', error: message }));
        void refresh();
        const delay = Math.min(MAX_BACKOFF_MS, 2_000 * 2 ** Math.min(attempt++, 4));
        retry = setTimeout(() => void connect(), delay);
      } finally {
        clearTimeout(deadline);
        controller.abort();
      }
    };

    void connect();
    return () => {
      cancelled = true;
      connection?.abort();
      clearTimeout(deadline);
      clearTimeout(retry);
      clearTimeout(initialFallback);
      clearInterval(poll);
    };
  }, [token, scope, event, streamUrl, reconnectSequence, apply, refresh, readRecord, update]);

  // Supabase realtime: a tenant write nudges a refresh (de-duplicated by fingerprint).
  const tablesKey = (realtimeTables || []).join(',');
  useEffect(() => {
    if (!authorized || !userId || !tablesKey) return;
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
  }, [authorized, userId, tablesKey, channelPrefix, refresh]);

  const current = snapshot.scope === scope ? snapshot : initialState(empty, authorized);
  return {
    ...current,
    sseConnected: current.transport === 'stream',
    refresh,
    reconnect,
  };
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
  /** Manually restart the stream and request a new REST snapshot. */
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

  const reconnect = resource.reconnect;

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
