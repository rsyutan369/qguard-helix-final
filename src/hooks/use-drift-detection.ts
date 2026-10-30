'use client';

import { useLiveModel, type LiveModel } from '@/hooks/use-live-resource';
import type { DriftIntelligence } from '@/lib/drift/drift-intelligence';

/** Tables whose mutation changes the comparison this page reads. */
const REALTIME_TABLES = [
  'assets', 'crypto_inventory', 'crypto_exposures', 'pqc_scan_results',
  'pqc_scan_sessions', 'certificates', 'migration_jobs', 'runtime_crypto_events',
] as const;

/**
 * useDriftDetection — live data for /dashboard/drift.
 *
 * A thin wrapper over the platform's one live-resource client: the stream's
 * first frame is the initial load (no double download), unchanged frames prove
 * liveness without re-rendering, the bearer token stays in the Authorization
 * header, and realtime channels are keyed per user.
 */
export function useDriftDetection(): LiveModel<DriftIntelligence> {
  return useLiveModel<DriftIntelligence>({
    url: '/api/v1/dashboard/drift',
    streamUrl: '/api/v1/dashboard/drift/stream',
    event: 'drift',
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'drift',
  });
}
