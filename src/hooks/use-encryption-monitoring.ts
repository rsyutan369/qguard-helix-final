'use client';

import type { SourceRead } from '@/lib/source-read';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useLiveModel } from '@/hooks/use-live-resource';
import type {
  AlgorithmRow,
  AtRestCoverage,
  DataProtectionPosture,
  EncryptionFinding,
  EncryptionIntelligence,
  EncryptionObservation,
  KeyInventory,
  OperationProfile,
  TelemetryHealth,
  VaultProtection,
} from '@/lib/encryption/types';

export type LoadState = 'loading' | 'success' | 'error';

const API_BASE = '/api/v1/dashboard/encryption-monitoring';

/** Mirrors `projectView()` in src/api-server/encryption-monitoring.ts. */
export interface EncryptionPayload {
  generatedAt: string;
  latestEvidenceAt: string | null;
  hasData: boolean;
  /** Outcome of every source read. `unavailable` = the query FAILED, so dependent figures are incomplete, not zero. */
  reads: SourceRead[];
  posture: DataProtectionPosture;
  telemetry: TelemetryHealth;
  timeline: EncryptionIntelligence['timeline'];

  symmetric: AlgorithmRow[];
  hashes: AlgorithmRow[];
  macs: AlgorithmRow[];
  kdfs: AlgorithmRow[];
  application: AlgorithmRow[];

  keys: KeyInventory;
  atRest: AtRestCoverage;
  vault: VaultProtection;
  operations: OperationProfile;
  findings: EncryptionFinding[];

  totals: {
    observations: number;
    algorithms: number;
    applicationAlgorithms: number;
    findings: number;
    keys: number;
    atRestRecords: number;
    vaultFiles: number;
  };
}

export interface AlgorithmDetail {
  algorithm: AlgorithmRow;
  observations: EncryptionObservation[];
  findings: EncryptionFinding[];
}

/**
 * Tables whose mutation changes what this page shows.
 *
 * Narrower than the TLS suite's list on purpose: this console reads data
 * protection, so a certificate write is not a reason to re-fetch it.
 */
const REALTIME_TABLES = [
  'assets',
  'crypto_inventory',
  'runtime_crypto_events',
  'scanner_evidence',
  'generated_keys',
  'vault_files',
  'crypto_exposures',
  'pqc_scan_results',
  'scanner_alerts',
] as const;

export function useEncryptionMonitoring() {
  const model = useLiveModel<EncryptionPayload>({
    url: API_BASE,
    streamUrl: API_BASE + '/stream',
    event: 'encryption-intel',
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'encryption-monitoring',
    validate: (value) => typeof value.generatedAt === 'string' && typeof value.hasData === 'boolean' && Array.isArray(value.symmetric),
  });
  return { ...model, lastSyncedAt: model.lastVerifiedAt };
}

/* ------------------------------------------------------------------ */
/* Drill-down                                                          */
/* ------------------------------------------------------------------ */

export function useAlgorithmDetail() {
  const { session } = useAuth();
  const token = session?.access_token;
  const pending = useRef<AbortController | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => () => pending.current?.abort(), []);

  const loadAlgorithm = useCallback(
    async (label: string): Promise<AlgorithmDetail | null> => {
      if (!token) return null;
      pending.current?.abort();
      const controller = new AbortController();
      pending.current = controller;
      setLoading(true);
      try {
        const response = await fetch(`${API_BASE}/algorithms/${encodeURIComponent(label)}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (controller.signal.aborted) return null;
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        return (payload.data ?? null) as AlgorithmDetail | null;
      } catch (err) {
        if (controller.signal.aborted) return null;
        console.error('Algorithm detail load failed:', err);
        return null;
      } finally {
        if (pending.current === controller && !controller.signal.aborted) setLoading(false);
      }
    },
    [token],
  );

  return { loadAlgorithm, loading };
}

/* ------------------------------------------------------------------ */
/* Server-side paged tables                                            */
/* ------------------------------------------------------------------ */

export function useEncryptionTable<T>(
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
        console.error('Encryption table load failed:', err);
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
