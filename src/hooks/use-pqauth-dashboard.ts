'use client';

import { useCallback, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useLiveModel, type LiveModel } from '@/hooks/use-live-resource';
import type { PQAuthSnapshot } from '@/types/pqauth-dashboard';

/**
 * Tables whose writes change what the PQAuth pages show. Each carries a
 * `user_id` column (the realtime filter the live-resource client applies). The
 * qkms_* tables are keyed by `tenant_id`, so they are refreshed by the server
 * stream's tick instead of a realtime channel that could never match.
 */
const REALTIME_TABLES = [
  'identity_providers',
  'identity_signing_keys',
  'identity_trust_relationships',
  'identity_discovery_probes',
  'assets',
  'certificates',
  'migration_jobs',
  'runtime_crypto_events',
] as const;

export type PQAuthLive = LiveModel<PQAuthSnapshot> & {
  /** Start an identity discovery run (optionally limited to some assets). */
  startDiscovery: (assetIds?: string[]) => Promise<void>;
  /** The start request is in flight (the RUN's own state is in the snapshot). */
  discoveryStarting: boolean;
  discoveryError: string | null;
};

/**
 * usePQAuthDashboard — the one client for all PQAuth pages.
 *
 * The previous hook opened FOUR EventSources (PQAuth, metrics, scanner, QKMS)
 * with the bearer token in the query string, and refetched the full ~1 MB
 * snapshot on every frame of any of them — including an unconditional 8-second
 * "update" pulse. A token in the URL also bypassed the Pro subscription gate,
 * which reads only the Authorization header.
 *
 * Now: one fingerprinted stream over fetch() with the header, REST fallback,
 * realtime nudges on the identity tables, and one snapshot shared by every page
 * (all modes read the same model, so switching pages costs no extra build).
 */
export function usePQAuthDashboard(): PQAuthLive {
  const { session } = useAuth();
  const token = session?.access_token;
  const live = useLiveModel<PQAuthSnapshot>({
    url: '/api/v1/dashboard/pqauth',
    streamUrl: '/api/v1/dashboard/pqauth/stream',
    event: 'pqauth-update',
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'pqauth',
  });
  const [discoveryStarting, setDiscoveryStarting] = useState(false);
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);
  const { refresh } = live;

  const startDiscovery = useCallback(async (assetIds?: string[]) => {
    if (!token) return;
    setDiscoveryStarting(true);
    setDiscoveryError(null);
    try {
      const response = await fetch('/api/v1/dashboard/pqauth/discovery/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(assetIds && assetIds.length ? { assetIds } : {}),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok && response.status !== 409) {
        throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      }
      await refresh(true);
    } catch (err) {
      setDiscoveryError(err instanceof Error ? err.message : 'Identity discovery could not be started');
    } finally {
      setDiscoveryStarting(false);
    }
  }, [token, refresh]);

  return { ...live, startDiscovery, discoveryStarting, discoveryError };
}

export default usePQAuthDashboard;
