/**
 * Migration Snapshot Management™ — shared frontend/backend contract.
 *
 * Every snapshot captures the REAL cryptographic + configuration metadata of a
 * target asset before a migration/remediation runs, so the change is fully
 * reversible. Integrity is a SHA3-256 hash over the canonical crypto-state
 * payload; only metadata is stored (never plaintext secrets/keys).
 */

/**
 * Snapshot lifecycle.
 *
 * `restored` asserts the ASSET now matches this snapshot, so it is only ever
 * written after an executor confirmed the restore. A rollback that has been
 * dispatched but not confirmed is `restoring`; one that came back failed is
 * `restore_failed` and — importantly — remains restorable, because the recorded
 * state is still valid, only the attempt failed.
 */
export type SnapshotStatus =
  | 'restorable'
  | 'restoring'
  | 'restored'
  | 'restore_failed'
  | 'expired'
  | 'deleted';
export type SnapshotTrigger = 'pre_migration' | 'manual' | 'scheduled';

/** What a rollback request resolved to. Never inferred — always reported. */
export type RollbackDisposition =
  | 'dispatched'        // handed to a live executor, awaiting confirmation
  | 'restored'          // executor confirmed the asset was restored
  | 'failed'            // executor tried and could not restore
  | 'awaiting-executor' // recorded, nothing changed on the asset
  | 'not-applicable';   // nothing was ever changed, so nothing to roll back

/**
 * The executor-side record of a change that can actually be undone.
 *
 * Written by the agent when it patches a file (target/backup/digests) or by a
 * cloud connector when it changes a managed resource (the provider rollback
 * plan). Without one of these a snapshot documents state but cannot restore it,
 * and the UI must say so rather than offering a Restore button that does
 * nothing.
 */
export interface SnapshotExecutionRecord {
  kind: 'agent-config' | 'cloud-connector';
  /** Agent that applied the change — the ONLY agent able to undo it. */
  agentId?: string | null;
  agentName?: string | null;
  targetPath?: string | null;
  backupPath?: string | null;
  /** SHA-256 of the file as it was BEFORE the patch (what rollback restores to). */
  beforeHash?: string | null;
  afterHash?: string | null;
  connectorId?: string | null;
  provider?: string | null;
  adapter?: string | null;
  /** Provider-specific restore payload recorded by the cloud adapter. */
  rollbackPlan?: Record<string, unknown> | null;
  recordedAt: string;
}

/** Outcome of the last rollback attempt against a snapshot. */
export interface SnapshotRollbackState {
  disposition: RollbackDisposition;
  requestedAt: string;
  requestedBy: string;
  reason: string;
  executorKind: 'agent' | 'connector' | null;
  executorId: string | null;
  executorLabel: string | null;
  commandId: string | null;
  settledAt: string | null;
  /** Verified post-restore digest, when the executor could measure one. */
  verifiedHash?: string | null;
  message: string;
}

/** Captured cryptographic + configuration state (metadata only). */
export interface SnapshotCryptoState {
  /**
   * MEASURED cryptography only. The scanner writes policy/configuration
   * findings into the same table with the finding TITLE in the algorithm
   * column, so a raw read captures "No CAA Issuance Policy" and
   * "Missing X-Frame-Options" as algorithms. A snapshot is the restore
   * source of truth and its integrity hash covers this list, so it must
   * contain cryptography and nothing else.
   */
  algorithms: string[];
  /** Policy/configuration records excluded from `algorithms`, counted so the
   *  capture is auditable rather than silently lossy. */
  policyRecordsExcluded?: number;
  tls: { version: string | null; cipherSuites: string[]; group: string | null };
  pki: { issuers: string[]; certificateCount: number };
  certificates: Array<{ name: string; algorithm: string; keySize: number | null; notAfter: string | null }>;
  keys: Array<{ algorithm: string; bitLength: number | null; status: string }>;
  configuration: { version: string | null; paths: string[]; source: string };
  componentCount: number;
}

/** Result of a restore request, as returned by POST /:snapshotId/restore. */
export interface SnapshotRestoreResult {
  snapshotId: string;
  disposition: RollbackDisposition;
  jobId: string | null;
  assetId: string | null;
  executor: { kind: 'agent' | 'connector'; id: string; label: string } | null;
  commandId: string | null;
  /** True ONLY when the asset was actually changed back. */
  applied: boolean;
  message: string;
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
  /**
   * Result of RE-COMPUTING the SHA3-256 over the stored crypto state, not the
   * boolean written at creation time. An unverifiable snapshot must never read
   * as verified.
   */
  integrityVerified: boolean;
  restoredAt: string | null;
  /** Present only when an executor recorded an undoable change. */
  execution: SnapshotExecutionRecord | null;
  /** Last rollback attempt, when there has been one. */
  rollback: SnapshotRollbackState | null;
  /** True when this snapshot has an executor able to restore it right now. */
  restoreExecutable: boolean;
  /** Why it is not executable, when it is not. Shown instead of a dead button. */
  restoreBlockedReason: string | null;
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
    /** Snapshots with a live executor able to restore them right now. */
    restoreExecutable: number;
    /** Rollbacks dispatched and not yet confirmed. */
    rollbacksInFlight: number;
    /** Rollbacks the executor reported as failed. */
    rollbacksFailed: number;
    autoRollbackEnabled: boolean;
  };
  snapshots: MigrationSnapshot[];
  audit: SnapshotAuditEntry[];
}
