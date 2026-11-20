'use client';

import type { SourceRead } from '@/lib/source-read';
import { useObservedPagedResource } from './use-observed-paged-resource';
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
    validate: (value) => typeof value.generatedAt === 'string' && Number.isFinite(Date.parse(value.generatedAt)) && Array.isArray(value.reads) && typeof value.hasData === 'boolean' && Array.isArray(value.symmetric),
  });
  return { ...model, lastSyncedAt: model.lastVerifiedAt };
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
  return useObservedPagedResource<T>(API_BASE + path, key, query, revision);
}
