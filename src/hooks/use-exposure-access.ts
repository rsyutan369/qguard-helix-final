'use client';

/**
 * Who may run which assessment mode.
 *
 * Two readings, deliberately, because they fail in different ways:
 *
 *   LOCAL   `useSubscription()` + the shared matrix. Resolves immediately from
 *           state the app already holds, and stays live over realtime, so the
 *           gate does not flash "locked" at a paying customer on every mount.
 *
 *   SERVER  `/api/v1/exposure/entitlement`. The authoritative answer, and the
 *           same code path the scan endpoints use. It arrives a moment later
 *           and then wins.
 *
 * The server reading wins whenever it has arrived, because the client reading
 * can be stale — a subscription cancelled in another tab, an owner override, a
 * billing row the browser has not refetched. Showing an unlocked panel that the
 * API then refuses with a 403 is worse than a brief lock.
 *
 * This hook is the UX layer only. Enforcement lives in `src/api-server/
 * exposure.ts` (`requireMode`), and both read the same matrix in
 * `src/lib/subscription-access.ts`.
 */

import React from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useSubscription } from '@/hooks/use-subscription';
import {
  exposureModeDenialMessage,
  resolveExposureModeAccess,
  type ExposureModeAccess,
  type ExposureScanMode,
} from '@/lib/subscription-access';
import { supabase } from '@/lib/supabase';

export interface UseExposureAccessResult extends ExposureModeAccess {
  /** True while either reading is still resolving. */
  loading: boolean;
  /** Human sentence for the gate panel. Empty when allowed. */
  message: string;
  /** True when the server could not read billing — say so, do not guess. */
  degraded: boolean;
  /** True once the authoritative server answer has been applied. */
  verified: boolean;
}

interface ServerEntitlement {
  authenticated: boolean;
  degraded: boolean;
  modes: Record<string, ExposureModeAccess & { message: string }>;
}

/** Shared across every hook instance on the page — one fetch, not three. */
let inflight: Promise<ServerEntitlement | null> | null = null;
let cached: { value: ServerEntitlement | null; at: number; key: string } | null = null;
const TTL_MS = 30_000;

async function loadEntitlement(key: string): Promise<ServerEntitlement | null> {
  if (cached && cached.key === key && Date.now() - cached.at < TTL_MS) return cached.value;
  if (inflight) return inflight;

  inflight = (async () => {
    try {
      const { data } = await supabase.auth.getSession();
      const token = data.session?.access_token;
      const response = await fetch('/api/v1/exposure/entitlement', {
        headers: token ? { authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) return null;
      const body = await response.json();
      const value = (body?.data ?? null) as ServerEntitlement | null;
      cached = { value, at: Date.now(), key };
      return value;
    } catch {
      /* Network failure. Fall back to the local reading rather than locking a
         paying customer out because one request did not land. */
      return null;
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}

/** Invalidate the shared entitlement cache — call after a plan change. */
export function refreshExposureAccess(): void {
  cached = null;
}

export function useExposureAccess(mode: ExposureScanMode): UseExposureAccessResult {
  const { user } = useAuth();
  const subscription = useSubscription();
  const [server, setServer] = React.useState<ServerEntitlement | null>(null);
  const [serverLoading, setServerLoading] = React.useState(true);

  const userId = user?.id ?? null;

  React.useEffect(() => {
    let cancelled = false;
    setServerLoading(true);
    void loadEntitlement(userId ?? 'anonymous').then((value) => {
      if (cancelled) return;
      setServer(value);
      setServerLoading(false);
    });
    return () => {
      cancelled = true;
    };
    /* Re-read when the signed-in user or their plan changes — a customer who
       upgrades in another tab should see the gate open here without a reload. */
  }, [userId, subscription.tier, subscription.status]);

  return React.useMemo(() => {
    const local = resolveExposureModeAccess(mode, subscription.tier, subscription.isActive, Boolean(userId));
    const authoritative = server?.modes?.[mode];

    if (authoritative) {
      return {
        ...authoritative,
        message: authoritative.message || exposureModeDenialMessage(authoritative),
        loading: false,
        degraded: Boolean(server?.degraded),
        verified: true,
      };
    }

    return {
      ...local,
      message: exposureModeDenialMessage(local),
      loading: subscription.loading || serverLoading,
      degraded: false,
      verified: false,
    };
  }, [mode, server, serverLoading, subscription.tier, subscription.isActive, subscription.loading, userId]);
}
