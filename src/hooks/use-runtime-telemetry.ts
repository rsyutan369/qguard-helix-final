'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useLiveModel } from '@/hooks/use-live-resource';
import type { SourceRead } from '@/lib/source-read';
import type {
  CollectorFleet,
  CoverageRecord,
  IngestionLag,
  PipelineFinding,
  PipelinePosture,
  SignalQuality,
  SourceHealth,
  TelemetryCoverage,
  ThroughputPoint,
} from '@/lib/telemetry-pipeline/types';

export type LoadState = 'loading' | 'success' | 'error';

const API_BASE = '/api/v1/dashboard/runtime-telemetry';

/** Mirrors `projectView()` in src/api-server/runtime-telemetry.ts. */
export interface PipelinePayload {
  generatedAt: string;
  latestEvidenceAt: string | null;
  hasData: boolean;
  posture: PipelinePosture;
  fleet: CollectorFleet;
  ingestion: IngestionLag;
  throughput: ThroughputPoint[];
  sources: SourceHealth[];
  quality: SignalQuality;
  coverage: TelemetryCoverage;
  findings: PipelineFinding[];
  sourceCounts: Record<string, number>;
  reads: SourceRead[];
  truncated: boolean;
  totals: { collectors: number; coverageRecords: number; findings: number; sources: number };
}

/**
 * Tables whose mutation changes the pipeline's own health picture.
 *
 * `scanner_agents` and `agent_heartbeats` matter most here — on every other
 * dashboard they are background context, but on this one they ARE the subject.
 */
const REALTIME_TABLES = [
  'scanner_agents',
  'agent_heartbeats',
  'runtime_crypto_events',
  'scanner_evidence',
  'connector_accounts',
  'pqc_scan_sessions',
] as const;

export function useRuntimeTelemetry() {
  const model = useLiveModel<PipelinePayload>({
    url: API_BASE,
    streamUrl: API_BASE + '/stream',
    event: 'pipeline',
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'runtime-telemetry',
    validate: (value) => typeof value.generatedAt === 'string' && Array.isArray(value.sources),
  });
  return { ...model, lastSyncedAt: model.lastVerifiedAt };
}

/* ------------------------------------------------------------------ */
/* Server-side paged tables                                            */
/* ------------------------------------------------------------------ */

export function usePipelineTable<T>(
  path: string,
  key: string,
  query: Record<string, string | number | undefined>,
  revision: number,
) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [rows, setRows] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  const serialized = JSON.stringify(query);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        const params = new URLSearchParams();
        for (const [name, value] of Object.entries(JSON.parse(serialized) as Record<string, string | number | undefined>)) {
          if (value === undefined || value === '' || value === 'all') continue;
          params.set(name, String(value));
        }
        const response = await fetch(`${API_BASE}${path}?${params.toString()}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (controller.signal.aborted) return;
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        setRows((payload.data?.[key] ?? []) as T[]);
        setTotal(Number(payload.data?.total ?? 0));
      } catch (err) {
        if (controller.signal.aborted) return;
        console.error('Pipeline table load failed:', err);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 250);

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token, path, key, serialized, revision]);

  return { rows, total, loading };
}

export type { CoverageRecord };
