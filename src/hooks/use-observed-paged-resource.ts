import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';

export function useTelemetryAccount() {
  const { user, session } = useAuth();
  const accountId = user && session?.user.id === user.id ? user.id : null;
  return { accountId, token: accountId ? session?.access_token : undefined };
}

export function useObservedDetail<T>(endpoint: string, id: string | null, revision?: string) {
  const { accountId, token } = useTelemetryAccount();
  const scope = accountId && id ? JSON.stringify([accountId, endpoint, id, revision]) : null;
  const [result, setResult] = useState<{ scope: string; data: T | null; error: string | null } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const retry = useCallback(() => setAttempt((value) => value + 1), []);
  useEffect(() => {
    if (!token || !id || !scope) return;
    const controller = new AbortController();
    setResult(null);
    void (async () => {
      try {
        const response = await fetch(`${endpoint}/${encodeURIComponent(id)}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.data || typeof payload.data !== 'object') {
          throw new Error(payload?.error?.message || 'Telemetry details are unavailable.');
        }
        if (!controller.signal.aborted) setResult({ scope, data: payload.data, error: null });
      } catch (error) {
        if (!controller.signal.aborted) setResult({ scope, data: null, error: error instanceof Error ? error.message : 'Telemetry details are unavailable.' });
      }
    })();
    return () => controller.abort();
  }, [endpoint, id, scope, token, attempt]);
  const current = scope && result?.scope === scope ? result : null;
  return { detail: current?.data ?? null, detailError: current?.error ?? null, detailLoading: Boolean(scope && !current), retryDetail: retry };
}

type PagedQuery = Record<string, string | number | undefined>;

export function useObservedPagedResource<T>(
  endpoint: string,
  key: string,
  query: PagedQuery,
  revision: number,
  enabled = true,
) {
  const { accountId, token } = useTelemetryAccount();
  const serialized = JSON.stringify(query);
  const scope = accountId && enabled ? JSON.stringify([accountId, endpoint, key, serialized]) : null;
  const [result, setResult] = useState<{
    scope: string;
    rows: T[];
    extra: Record<string, unknown>;
    total: number;
  } | null>(null);
  const [request, setRequest] = useState<{ scope: string; loading: boolean; error: string | null } | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const retry = useCallback(() => setRetryCount((count) => count + 1), []);

  useEffect(() => {
    if (!token || !scope) return;
    const controller = new AbortController();
    setRequest({ scope, loading: true, error: null });
    const timer = setTimeout(async () => {
      try {
        const params = new URLSearchParams();
        for (const [name, value] of Object.entries(JSON.parse(serialized) as PagedQuery)) {
          if (value === undefined || value === '' || value === 'all') continue;
          params.set(name, String(value));
        }
        const response = await fetch(`${endpoint}?${params.toString()}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (controller.signal.aborted) return;
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!Array.isArray(payload.data?.[key]) || !Number.isSafeInteger(payload.data?.total) || payload.data.total < 0) {
          throw new Error('Telemetry inventory response was incomplete');
        }
        setResult({ scope, rows: payload.data[key] as T[], extra: payload.data, total: payload.data.total });
        setRequest({ scope, loading: false, error: null });
      } catch (err) {
        if (controller.signal.aborted) return;
        console.error('Telemetry table load failed:', err);
        setRequest({ scope, loading: false, error: err instanceof Error ? err.message : 'Unable to load rows' });
      }
      // Debounced so typing in the search box does not fire a request per keystroke.
    }, 250);

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token, scope, endpoint, key, serialized, revision, retryCount]);

  const current = scope && result?.scope === scope ? result : null;
  const currentRequest = scope && request?.scope === scope ? request : null;
  return {
    rows: current?.rows ?? [],
    extra: current?.extra ?? {},
    total: current?.total ?? 0,
    loading: Boolean(token && scope && (currentRequest?.loading ?? true)),
    error: currentRequest?.error ?? null,
    retry,
  };
}

