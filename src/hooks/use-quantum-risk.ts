'use client';

import { useLiveModel, type LiveModel } from '@/hooks/use-live-resource';
import type { QuantumRiskIntelligence } from '@/lib/quantum-risk/risk-intelligence';

/** Tables whose mutation changes the snapshot or the portfolio this page reads. */
const REALTIME_TABLES = [
  'assets', 'crypto_inventory', 'crypto_exposures', 'pqc_scan_results',
  'pqc_scan_sessions', 'certificates', 'migration_jobs', 'runtime_crypto_events',
] as const;

/**
 * useQuantumRisk — live data for /dashboard/quantum-risk-scoring.
 *
 * Thin wrapper over the shared live-resource client (stream-first, fingerprint
 * de-dup, header auth, per-user realtime nudges). The page's model is read,
 * never recomputed, so the score shown is the Quantum Readiness Engine's.
 */
export function useQuantumRisk(): LiveModel<QuantumRiskIntelligence> {
  return useLiveModel<QuantumRiskIntelligence>({
    url: '/api/v1/dashboard/quantum-risk-scoring',
    streamUrl: '/api/v1/dashboard/quantum-risk-scoring/stream',
    event: 'quantum-risk',
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'quantum-risk',
  });
}
