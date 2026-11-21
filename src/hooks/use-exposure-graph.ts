'use client';

import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { EMPTY_EXPOSURE_INTELLIGENCE, type ExposureFindingPage, type ExposureIntelligence } from '@/types/exposure-graph';
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
  'vulnerabilities',
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
    validate: (raw) => {
      const graph = raw.graph as ExposureIntelligence['graph'] | undefined;
      return typeof raw.generatedAt === 'string' && typeof raw.hasData === 'boolean' &&
        Boolean(raw.summary && graph && Array.isArray(graph.nodes) && Array.isArray(graph.edges) &&
          Array.isArray(raw.riskPrioritization) && Array.isArray(raw.thirdParty) && raw.migrationOrder && raw.advisor && raw.evidence);
    },
  });
  const { data } = live;
  const downloadJson = useCallback((filenamePrefix: string, payload?: unknown) => downloadJsonFile(filenamePrefix, payload ?? data), [data]);
  return {
    data,
    state: live.state,
    error: live.error,
    sseConnected: live.sseConnected,
    lastVerifiedAt: live.lastVerifiedAt,
    transport: live.transport,
    refresh: live.refresh,
    downloadJson,
  };
}

export function useExposureFindings(assetId: string, revision: string | undefined, offset: number) {
  const { user, session } = useAuth();
  const token = user && session?.user.id === user.id ? session.access_token : null;
  const [retry, setRetry] = useState(0);
  const scope = JSON.stringify([user?.id, Boolean(token), assetId, revision, offset, retry]);
  const [result, setResult] = useState<{ scope: string; data?: ExposureFindingPage; error?: string } | null>(null);
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    const params = new URLSearchParams({ offset: String(offset) });
    void (async () => {
      try {
        const response = await fetch(`/api/v1/exposure-graph/assets/${encodeURIComponent(assetId)}/findings?${params}`, {
          headers: { Authorization: `Bearer ${token}` }, cache: 'no-store',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15_000)]),
        });
        const json = await response.json();
        const data = json?.data as ExposureFindingPage | undefined;
        if (!response.ok || data?.assetId !== assetId || !Array.isArray(data.findings)) {
          throw new Error(json?.error?.message || 'Unable to load findings for this asset.');
        }
        if (!controller.signal.aborted) setResult({ scope, data });
      } catch (error) {
        if (!controller.signal.aborted) setResult({ scope, error: error instanceof Error ? error.message : 'Unable to load findings.' });
      }
    })();
    return () => controller.abort();
  }, [assetId, offset, scope, token]);

  const current = result?.scope === scope ? result : null;
  return { data: current?.data, error: current?.error, retry: () => setRetry((value) => value + 1) };
}
