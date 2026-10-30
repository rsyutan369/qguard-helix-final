import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import type { CopilotLlmProviderId, CopilotLlmSettings } from '@/lib/copilot-llm-catalog';

/**
 * useCopilotLlm — the tenant's bring-your-own-key model connections for Sophia.
 *
 * The browser only ever SENDS a key (once, over the authenticated API); the
 * server verifies it live, seals it, and from then on returns a four-character
 * hint. Nothing key-shaped is kept in React state after a save completes.
 */

export type LlmLoadState = 'idle' | 'loading' | 'success' | 'error';

export interface SaveConnectionInput {
  provider: CopilotLlmProviderId;
  model: string;
  endpoint: string;
  /** Omit to keep the stored key (model / endpoint change only). */
  apiKey?: string;
  consent?: boolean;
  activate?: boolean;
}

export type LlmActionResult = { ok: true; message?: string } | { ok: false; message: string };

export function useCopilotLlm(enabled = true) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [settings, setSettings] = useState<CopilotLlmSettings | null>(null);
  const [state, setState] = useState<LlmLoadState>('idle');
  const [busy, setBusy] = useState<CopilotLlmProviderId | 'active' | null>(null);

  const request = useCallback(async (path: string, init: RequestInit = {}) => {
    const res = await fetch(`/api/v1/copilot/llm${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(init.headers || {}) },
    });
    const payload = await res.json().catch(() => ({}));
    return { res, payload };
  }, [token]);

  const load = useCallback(async () => {
    if (!token) return;
    setState('loading');
    try {
      const { res, payload } = await request('/settings');
      if (!res.ok) throw new Error(payload?.error?.message || `HTTP ${res.status}`);
      setSettings(payload.data);
      setState('success');
    } catch {
      setState('error');
    }
  }, [token, request]);

  const run = useCallback(async (key: CopilotLlmProviderId | 'active', path: string, init: RequestInit): Promise<LlmActionResult> => {
    if (!token) return { ok: false, message: 'Sign in to manage model connections.' };
    setBusy(key);
    try {
      const { res, payload } = await request(path, init);
      if (payload?.data?.settings) setSettings(payload.data.settings);
      if (!res.ok) return { ok: false, message: payload?.error?.message || `Request failed (HTTP ${res.status})` };
      if (payload?.data?.ok === false) return { ok: false, message: payload.data.message || 'Verification failed' };
      return { ok: true, message: payload?.data?.latencyMs ? `Verified in ${payload.data.latencyMs} ms` : undefined };
    } catch {
      return { ok: false, message: 'Could not reach the QGuard API.' };
    } finally {
      setBusy(null);
    }
  }, [token, request]);

  const saveConnection = useCallback((input: SaveConnectionInput) => run(input.provider, `/providers/${input.provider}`, {
    method: 'PUT',
    body: JSON.stringify({ model: input.model, endpoint: input.endpoint, apiKey: input.apiKey || undefined, consent: input.consent === true, activate: input.activate !== false }),
  }), [run]);

  const verifyConnection = useCallback((provider: CopilotLlmProviderId) => run(provider, `/providers/${provider}/verify`, { method: 'POST' }), [run]);

  const setActive = useCallback((provider: CopilotLlmProviderId | null) => run('active', '/active', {
    method: 'POST',
    body: JSON.stringify({ provider }),
  }), [run]);

  const removeConnection = useCallback((provider: CopilotLlmProviderId) => run(provider, `/providers/${provider}`, { method: 'DELETE' }), [run]);

  useEffect(() => {
    if (enabled) void load();
  }, [enabled, load]);

  return { settings, state, busy, load, saveConnection, verifyConnection, setActive, removeConnection };
}
