import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type { MigrationSnapshot, SnapshotDashboard, SnapshotRestoreResult } from '@/types/migration-snapshot';

/**
 * useMigrationSnapshots — live Migration Snapshot Management™ state.
 *
 * Fetches the tenant-scoped snapshot dashboard from /api/v1/migration-snapshots,
 * keeps it live via a header-authenticated SSE stream + Supabase realtime on
 * the snapshot tables, and exposes create / restore / verify / delete actions.
 * Every value is evidence-driven and tenant-isolated (RLS).
 */

export type LoadState = 'loading' | 'success' | 'error';

export const EMPTY_SNAPSHOT_DASHBOARD: SnapshotDashboard = {
  generatedAt: '',
  schemaReady: true,
  summary: {
    total: 0, successful: 0, restorable: 0, restored: 0, expired: 0,
    automaticRollbacks: 0, manualRollbacks: 0, storageBytes: 0,
    latestSnapshotAt: null, integrityVerified: 0, integrityFailed: 0,
    restoreExecutable: 0, rollbacksInFlight: 0, rollbacksFailed: 0,
    autoRollbackEnabled: true,
  },
  snapshots: [],
  audit: [],
};

interface ActionResult {
  ok: boolean;
  message?: string;
  code?: string;
  snapshot?: MigrationSnapshot;
  /** Present for restore: what the request actually resolved to. */
  restore?: SnapshotRestoreResult;
}

const REALTIME_TABLES = ['migration_snapshots', 'migration_snapshot_audit'];

export function useMigrationSnapshots(enabled: boolean) {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [data, setData] = useState<SnapshotDashboard>(EMPTY_SNAPSHOT_DASHBOARD);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const apply = useCallback((next: Partial<SnapshotDashboard> | null) => {
    setData({ ...EMPTY_SNAPSHOT_DASHBOARD, ...(next || {}) });
  }, []);

  const refresh = useCallback(async () => {
    if (!token || !enabled) { setState('success'); return; }
    setState((c) => (c === 'success' ? c : 'loading'));
    try {
      const res = await fetch('/api/v1/migration-snapshots', { headers: { Authorization: `Bearer ${token}` } });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(payload?.error?.message || `HTTP ${res.status}`);
      apply(payload.data || {});
      setState('success');
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load snapshots');
      setState('error');
    }
  }, [token, enabled, apply]);

  const queueRefresh = useCallback(() => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => { refreshTimer.current = null; void refresh(); }, 600);
  }, [refresh]);

  useEffect(() => () => { if (refreshTimer.current) clearTimeout(refreshTimer.current); }, []);
  useEffect(() => { if (enabled && token) void refresh(); }, [enabled, token, refresh]);

  // Header-authenticated SSE (token never in URL).
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
      if (eventName === 'snapshot-update' && lines.length) {
        try { apply(JSON.parse(lines.join('\n'))); setState('success'); setError(null); } catch { /* ignore */ }
      }
    };
    const connect = async () => {
      try {
        const res = await fetch('/api/v1/migration-snapshots/stream', { headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' }, signal: controller.signal });
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

  // Supabase realtime.
  useEffect(() => {
    if (!enabled || !user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase.channel(`snap-${table}`).on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh).subscribe(),
    );
    return () => { for (const c of channels) supabase.removeChannel(c); };
  }, [enabled, user, queueRefresh]);

  const post = useCallback(async (path: string, body?: unknown, method = 'POST'): Promise<ActionResult> => {
    if (!token) return { ok: false, message: 'Not authenticated' };
    setBusy(true);
    try {
      const res = await fetch(`/api/v1/migration-snapshots${path}`, {
        method,
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: body ? JSON.stringify(body) : undefined,
      });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) return { ok: false, message: payload?.error?.message || `HTTP ${res.status}`, code: payload?.error?.code };
      await refresh();
      return { ok: true, snapshot: payload.data, restore: payload.data };
    } catch (err) {
      return { ok: false, message: err instanceof Error ? err.message : 'Request failed' };
    } finally {
      setBusy(false);
    }
  }, [token, refresh]);

  const createSnapshot = useCallback((body: Record<string, unknown>) => post('/', body), [post]);
  const restoreSnapshot = useCallback((snapshotId: string, reason?: string) => post(`/${encodeURIComponent(snapshotId)}/restore`, { reason }), [post]);
  const verifySnapshot = useCallback((snapshotId: string) => post(`/${encodeURIComponent(snapshotId)}/verify`), [post]);
  const deleteSnapshot = useCallback((snapshotId: string, force = false) => post(`/${encodeURIComponent(snapshotId)}`, { force }, 'DELETE'), [post]);

  return { data, state, error, busy, sseConnected, refresh, createSnapshot, restoreSnapshot, verifySnapshot, deleteSnapshot };
}
