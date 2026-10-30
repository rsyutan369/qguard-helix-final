'use client';

import { useLiveModel, type LiveModel } from '@/hooks/use-live-resource';
import type { CorrelationIntelligence } from '@/lib/telemetry/correlation-intelligence';

/**
 * Tables the correlation engine actually reads. The previous list was copied
 * from Quantum Risk Scoring and omitted `scanner_evidence`, `scanner_agents` and
 * `connector_accounts` — so a new collector observation never nudged a refresh,
 * while unrelated certificate writes did.
 */
const REALTIME_TABLES = [
  'assets', 'scanner_evidence', 'runtime_crypto_events', 'crypto_inventory',
  'scanner_agents', 'connector_accounts', 'pqc_scan_sessions',
] as const;

/**
 * useTelemetryCorrelation — live data for /dashboard/telemetry-correlation.
 *
 * Thin wrapper over the shared live-resource client: stream-first, fingerprint
 * de-dup, header auth, per-user realtime channels, exponential reconnect.
 */
export function useTelemetryCorrelation(): LiveModel<CorrelationIntelligence> {
  return useLiveModel<CorrelationIntelligence>({
    url: '/api/v1/dashboard/telemetry-correlation',
    streamUrl: '/api/v1/dashboard/telemetry-correlation/stream',
    event: 'correlation',
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'correlation',
  });
}
