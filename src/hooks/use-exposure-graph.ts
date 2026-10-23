'use client';

import { useCallback } from 'react';
import { EMPTY_EXPOSURE_INTELLIGENCE, type ExposureIntelligence } from '@/types/exposure-graph';
import { downloadJsonFile, useLiveResource, type LiveLoadState } from './use-live-resource';

export type LoadState = LiveLoadState;

// Mirrors EXACTLY the evidence tables the exposure-graph assembler reads.
const REALTIME_TABLES = [
  'assets',
  'asset_relationships',
  'crypto_inventory',
  'crypto_exposures',
  'certificates',
  'runtime_crypto_events',
  'pqc_scan_results',
  'connector_accounts',
  'migration_jobs',
] as const;

/**
 * useExposureGraph — the Enterprise Cryptographic Dependency & Migration
 * Intelligence model (/api/v1/exposure-graph), live over its fingerprinted
 * stream (see use-live-resource.ts). Every value is tenant-scoped evidence.
 */
export function useExposureGraph() {
  const live = useLiveResource<ExposureIntelligence>({
    url: '/api/v1/exposure-graph',
    streamUrl: '/api/v1/exposure-graph/stream',
    event: 'exposure-intelligence',
    empty: EMPTY_EXPOSURE_INTELLIGENCE,
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'exposure-graph',
  });
  const { data } = live;
  const downloadJson = useCallback((filenamePrefix: string, payload?: unknown) => downloadJsonFile(filenamePrefix, payload ?? data), [data]);
  return {
    data,
    state: live.state,
    error: live.error,
    sseConnected: live.sseConnected,
    lastVerifiedAt: live.lastVerifiedAt,
    refresh: live.refresh,
    downloadJson,
  };
}
