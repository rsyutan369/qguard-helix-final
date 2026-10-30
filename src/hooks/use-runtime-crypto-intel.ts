'use client';

import { useLiveModel, type LiveModel } from '@/hooks/use-live-resource';
import type { RuntimeCryptoIntelligence, TimeWindowKey } from '@/lib/runtime-crypto/runtime-intelligence';

/**
 * Tables whose mutation can change what this page shows. Runtime events are the
 * primary signal; migration jobs and assets change the expected-vs-actual
 * baseline and the priority weighting; agents change collection coverage.
 */
const REALTIME_TABLES = ['runtime_crypto_events', 'migration_jobs', 'assets', 'scanner_agents'] as const;

/**
 * useRuntimeCryptoIntel — the live data contract for /dashboard/runtime-crypto-intel.
 *
 * Thin wrapper over the shared live-resource client. The time window is part of
 * both URLs, so changing it reconnects the stream for the new projection (the
 * server projects windows from one cached fetch — no extra database cost).
 */
export function useRuntimeCryptoIntel(window: TimeWindowKey = '24h'): LiveModel<RuntimeCryptoIntelligence> {
  const query = `window=${encodeURIComponent(window)}`;
  return useLiveModel<RuntimeCryptoIntelligence>({
    url: `/api/v1/runtime-crypto-intel?${query}`,
    streamUrl: `/api/v1/runtime-crypto-intel/stream?${query}`,
    event: 'runtime-intel',
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'runtime-intel',
  });
}
