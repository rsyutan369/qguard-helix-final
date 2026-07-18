/**
 * Migration Snapshot Management™ — shared frontend/backend contract.
 *
 * Every snapshot captures the REAL cryptographic + configuration metadata of a
 * target asset before a migration/remediation runs, so the change is fully
 * reversible. Integrity is a SHA3-256 hash over the canonical crypto-state
 * payload; only metadata is stored (never plaintext secrets/keys).
 */

export type SnapshotStatus = 'restorable' | 'restored' | 'expired' | 'deleted';
export type SnapshotTrigger = 'pre_migration' | 'manual' | 'scheduled';

/** Captured cryptographic + configuration state (metadata only). */
export interface SnapshotCryptoState {
  algorithms: string[];
  tls: { version: string | null; cipherSuites: string[]; group: string | null };
  pki: { issuers: string[]; certificateCount: number };
  certificates: Array<{ name: string; algorithm: string; keySize: number | null; notAfter: string | null }>;
  keys: Array<{ algorithm: string; bitLength: number | null; status: string }>;
  configuration: { version: string | null; paths: string[]; source: string };
  componentCount: number;
}

export interface MigrationSnapshot {
  id: string;
  snapshotId: string;
  assetId: string | null;
  assetName: string;
  assetType: string;
  environment: string;
  migrationJobId: string | null;
  planId: string | null;
  status: SnapshotStatus;
  trigger: SnapshotTrigger;
  cryptoState: SnapshotCryptoState;
  configurationVersion: string | null;
  createdBy: string;
  sizeBytes: number;
  retentionDays: number;
  expiresAt: string | null;
  integrityHash: string;
  integrityAlgorithm: string;
  integrityVerified: boolean;
  restoredAt: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface SnapshotAuditEntry {
  id: string;
  snapshotId: string | null;
  migrationJobId: string | null;
  action: string;
  actor: string;
  reason: string;
  detail: string;
  approvalStatus: string;
  validationResult: string;
  restorationStatus: string;
  integrityStatus: string;
  createdAt: string;
}

export interface SnapshotDashboard {
  generatedAt: string;
  schemaReady: boolean;
  summary: {
    total: number;
    successful: number;
    restorable: number;
    restored: number;
    expired: number;
    automaticRollbacks: number;
    manualRollbacks: number;
    storageBytes: number;
    latestSnapshotAt: string | null;
    integrityVerified: number;
    integrityFailed: number;
    autoRollbackEnabled: boolean;
  };
  snapshots: MigrationSnapshot[];
  audit: SnapshotAuditEntry[];
}
