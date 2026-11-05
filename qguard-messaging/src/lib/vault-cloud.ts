// Quantum Vault cloud backup — the transport half (phase 2).
//
// The Rust core decides WHAT to back up and hands over opaque bytes: v5 vault
// containers (no name or type inside) and the vault index sealed under the
// recovery key. This module moves those bytes through Supabase:
//
//   upload:   qv_begin_upload (quota-checked reservation, migration 048)
//             → 8 MiB parts into the private `quantum-vault` bucket
//             → qv_commit_upload (the database counts and sizes the parts)
//             → the core records the object id in its sealed index.
//   delete:   qv_begin_delete → remove parts → qv_finish_delete → core.
//   download: parts → core, which checks each part's SHA3-256 in order and the
//             whole file's at the end, then opens the container itself.
//
// Nothing here sees a key, a file name or plaintext. Every state shown in the
// UI comes from the core (`vault_cloud_state`) or the database (`qv_cloud_usage`).

import { invoke } from "@tauri-apps/api/core";
import { bytesToBase64, ipcArrayBuffer } from "@/lib/encoding";
import { requireSupabase } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";
import type { StoreEntry } from "@/lib/vault-store";
import {
  fetchLibraryState,
  isRevisionConflict,
  libraryCore,
  syncLibraryKey,
  type LibraryDevice,
  type MergeReport,
} from "@/lib/vault-library";

export const VAULT_BUCKET = "quantum-vault";
const PART_ATTEMPTS = 4;

export interface CloudState {
  enabled: boolean;
  enabledAt: string | null;
  lastSyncAt: string | null;
  lastError: string | null;
  recoveryReady: boolean;
  backedUpFiles: number;
  backedUpBytes: number;
  pendingUploads: number;
  pendingUploadBytes: number;
  pendingDeletes: number;
  indexCurrent: boolean;
  restorableMissing: number;
  /** Cloud copies kept only because the file is shared (backup off); not backups. */
  sharedCopies: number;
  sharedCopyBytes: number;
}

export interface CloudUsage {
  plan: string | null;
  has_access: boolean;
  quota_bytes: number;
  used_bytes: number;
  reserved_bytes: number;
  index_bytes: number;
  files: number;
  last_backup_at: string | null;
}

export interface PlanQuota {
  plan: string;
  quota_bytes: number;
}

interface CloudPlan {
  enabled: boolean;
  uploads: Array<{ entryId: string; name: string; storedBytes: number }>;
  deletes: string[];
  indexNeeded: boolean;
}

interface PreparedUpload {
  uploadId: string;
  kind: "file" | "recovery_index";
  entryId: string | null;
  containerBytes: number;
  partSize: number;
  partSha3: string[];
  containerSha3: string;
  deviceId: string;
}

export interface CloudObjectRow {
  id: string;
  /** The owner's storage folder (another user's for a shared file). */
  owner_user_id?: string;
  kind: "file" | "recovery_index";
  entry_id: string | null;
  container_bytes: number;
  part_count: number;
  part_sha3: string[];
  container_sha3: string;
  status: "uploading" | "committed" | "deleting";
  committed_at: string | null;
}

export interface RestoreCandidate {
  entryId: string;
  name: string;
  location: string;
  sizeBytes: number;
  category: string;
  present: boolean;
}

export interface RestorePreview {
  files: RestoreCandidate[];
  folders: number;
}

export interface SyncProgress {
  stage: "planning" | "library" | "uploading" | "index" | "deleting" | "downloading" | "restoring" | "done";
  label: string;
  item: number;
  items: number;
  bytesDone: number;
  bytesTotal: number;
}

export interface SyncReport {
  uploaded: number;
  deleted: number;
  indexUploaded: boolean;
  stoppedBy: string | null;
  /** What the merge brought in from the account's other devices. */
  merged: MergeReport | null;
  libraryPublished: boolean;
  /** This device has no library key yet and no way to get one on its own. */
  waitingForAccess: boolean;
  devices: LibraryDevice[];
}

/** A failure the user can act on, from the database's QV_* codes. */
export class CloudError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
  }
}

const CODE_MESSAGES: Record<string, string> = {
  QV_QUOTA_EXCEEDED: "Cloud storage limit reached. New files stay on this device; free space or upgrade your plan to back them up.",
  QV_NO_CLOUD_ENTITLEMENT: "Your plan does not include cloud backup (or the subscription has lapsed). Existing backups stay available for restore.",
  QV_NOT_AUTHENTICATED: "Your session expired. Sign in again to continue backing up.",
  QV_INDEX_BUSY: "Another backup of your folders is still in progress. Try again shortly.",
  QV_PARTS_MISSING: "The upload was interrupted. It will resume on the next backup.",
  QV_SIZE_MISMATCH: "The cloud copy did not match what was uploaded and was not accepted.",
};

export function describeCloudError(error: unknown): string {
  if (error instanceof CloudError) return error.message;
  const raw = error instanceof Error ? error.message : typeof error === "object" && error && "message" in error ? String((error as { message: unknown }).message) : String(error);
  for (const [code, message] of Object.entries(CODE_MESSAGES)) {
    if (raw.includes(code)) return message;
  }
  if (/Failed to fetch|NetworkError|network/i.test(raw)) return "No connection to the backup service. Backup will resume when you are online.";
  if (raw.includes("does not open this backup")) return "This recovery key does not open this backup.";
  if (raw.includes("recovery key isn't valid")) return "That recovery key isn't valid. Check it and try again.";
  return raw.replace(/^(storage|invalid input|crypto|trust|not found) error: /i, "");
}

function cloudError(error: { message?: string } | null | undefined): CloudError {
  const raw = error?.message ?? "Unknown cloud error";
  const code = raw.match(/QV_[A-Z_]+/)?.[0] ?? "QV_UNKNOWN";
  return new CloudError(code, CODE_MESSAGES[code] ?? raw);
}

const STOPPING_CODES = new Set(["QV_QUOTA_EXCEEDED", "QV_NO_CLOUD_ENTITLEMENT", "QV_NOT_AUTHENTICATED"]);

function partPath(userId: string, objectId: string, index: number): string {
  return `${userId}/${objectId}/${String(index).padStart(5, "0")}`;
}

async function withRetry<T>(attempt: () => Promise<T>): Promise<T> {
  let lastError: unknown;
  for (let tries = 0; tries < PART_ATTEMPTS; tries += 1) {
    try {
      return await attempt();
    } catch (error) {
      lastError = error;
      if (error instanceof CloudError && STOPPING_CODES.has(error.code)) throw error;
      await new Promise((resolve) => setTimeout(resolve, 500 * 2 ** tries));
    }
  }
  throw lastError;
}

// ---------------------------------------------------------------------------
// Core (Rust) calls
// ---------------------------------------------------------------------------

export const vaultCloudCore = {
  state: () => safeInvoke<CloudState>("vault_cloud_state"),
  setEnabled: (enabled: boolean) => safeInvoke<CloudState>("vault_cloud_set_enabled", { enabled }),
  /** `keepObjectIds`: copies a live share still uses; they stay, as shared copies. */
  deleteBackup: (keepObjectIds: string[] = []) => safeInvoke<CloudState>("vault_cloud_delete_backup", { keepObjectIds }),
  /** Queue a shared-only copy for deletion (the core refuses any other copy). */
  releaseShareCopy: (entryId: string, objectId: string) => safeInvoke<boolean>("vault_cloud_release_share_copy", { entryId, objectId }),
};

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

export async function fetchCloudUsage(): Promise<CloudUsage> {
  const { data, error } = await requireSupabase().rpc("qv_cloud_usage");
  if (error) throw cloudError(error);
  return data as CloudUsage;
}

export async function fetchPlanQuotas(): Promise<PlanQuota[]> {
  const { data, error } = await requireSupabase().from("qv_plan_quotas").select("plan,quota_bytes").order("quota_bytes");
  if (error) throw cloudError(error);
  return (data ?? []) as PlanQuota[];
}

export async function fetchBackupObjects(): Promise<CloudObjectRow[]> {
  const { data, error } = await requireSupabase()
    .from("qv_cloud_objects")
    .select("id,owner_user_id,kind,entry_id,container_bytes,part_count,part_sha3,container_sha3,status,committed_at")
    .eq("status", "committed")
    .order("committed_at", { ascending: false });
  if (error) throw cloudError(error);
  return (data ?? []) as CloudObjectRow[];
}

// ---------------------------------------------------------------------------
// Upload / delete
// ---------------------------------------------------------------------------

async function removeObject(userId: string, objectId: string): Promise<void> {
  const client = requireSupabase();
  const begun = await client.rpc("qv_begin_delete", { p_object_id: objectId });
  if (begun.error && !begun.error.message.includes("QV_OBJECT_NOT_FOUND")) throw cloudError(begun.error);
  const prefix = `${userId}/${objectId}`;
  for (;;) {
    const { data: listed, error: listError } = await client.storage.from(VAULT_BUCKET).list(prefix, { limit: 1000 });
    if (listError) throw cloudError(listError);
    if (!listed || listed.length === 0) break;
    const { error: removeError } = await client.storage.from(VAULT_BUCKET).remove(listed.map((item) => `${prefix}/${item.name}`));
    if (removeError) throw cloudError(removeError);
    if (listed.length < 1000) break;
  }
  const finished = await client.rpc("qv_finish_delete", { p_object_id: objectId });
  if (finished.error) throw cloudError(finished.error);
  if (finished.data !== true) throw new CloudError("QV_DELETE_PENDING", "Cloud copy is still being removed; it will be retried.");
}

async function reserve(prepared: PreparedUpload): Promise<CloudObjectRow> {
  const client = requireSupabase();
  const request = () =>
    client.rpc("qv_begin_upload", {
      p_kind: prepared.kind,
      p_entry_id: prepared.entryId,
      p_container_bytes: prepared.containerBytes,
      p_part_sha3: prepared.partSha3,
      p_container_sha3: prepared.containerSha3,
      p_device_id: prepared.deviceId,
    });
  let { data, error } = await request();
  if (error?.message.includes("QV_ENTRY_ALREADY_BACKED_UP") && prepared.entryId) {
    // A different container of this file is (or was being) backed up — an
    // interrupted upload from before it was re-protected. Replace it.
    const { data: stale } = await client
      .from("qv_cloud_objects")
      .select("id")
      .eq("entry_id", prepared.entryId)
      .neq("status", "deleting");
    const { data: session } = await client.auth.getSession();
    const userId = session.session?.user.id;
    if (!userId) throw new CloudError("QV_NOT_AUTHENTICATED", CODE_MESSAGES.QV_NOT_AUTHENTICATED);
    for (const row of stale ?? []) await removeObject(userId, String(row.id));
    ({ data, error } = await request());
  }
  if (error) throw cloudError(error);
  return data as CloudObjectRow;
}

/**
 * Reserve, upload and commit one prepared object. `finalize: "file"` records a
 * file / recovery-index upload in the core at once; a library document is
 * recorded only after it has been published (see publishLibrary).
 */
async function uploadPrepared(
  userId: string,
  prepared: PreparedUpload,
  onPart: (done: number, bytes: number) => void,
  finalize: "file" | "none" = "file",
): Promise<string> {
  const client = requireSupabase();
  try {
    const row = await reserve(prepared);
    if (row.status !== "committed") {
      // Resume: parts already in the bucket belong to this exact container.
      const prefix = `${userId}/${row.id}`;
      const { data: listed, error: listError } = await client.storage.from(VAULT_BUCKET).list(prefix, { limit: 10000 });
      if (listError) throw cloudError(listError);
      const present = new Set((listed ?? []).map((item) => item.name));
      let sent = 0;
      for (let index = 0; index < prepared.partSha3.length; index += 1) {
        const name = String(index).padStart(5, "0");
        const partBytes = Math.min(prepared.partSize, prepared.containerBytes - index * prepared.partSize);
        if (!present.has(name)) {
          await withRetry(async () => {
            // Normalised: over the postMessage IPC this arrives as numbers, and a
            // Blob of numbers would upload their text instead of the part.
            const bytes = ipcArrayBuffer(await invoke<unknown>("vault_cloud_read_part", { uploadId: prepared.uploadId, partIndex: index }));
            const { error } = await client.storage
              .from(VAULT_BUCKET)
              .upload(partPath(userId, row.id, index), new Blob([bytes], { type: "application/octet-stream" }), {
                contentType: "application/octet-stream",
                upsert: false,
              });
            if (error && !/already exists|Duplicate/i.test(error.message)) throw cloudError(error);
          });
        }
        sent += partBytes;
        onPart(index + 1, sent);
      }
      const committed = await withRetry(async () => {
        const { data, error } = await client.rpc("qv_commit_upload", { p_object_id: row.id });
        if (error) throw cloudError(error);
        return data as CloudObjectRow;
      });
      if (committed.status !== "committed") throw new CloudError("QV_PARTS_MISSING", CODE_MESSAGES.QV_PARTS_MISSING);
    }
    if (finalize === "file") await safeInvoke("vault_cloud_complete_upload", { uploadId: prepared.uploadId, objectId: row.id });
    return row.id;
  } catch (error) {
    await safeInvoke("vault_cloud_discard_upload", { uploadId: prepared.uploadId }).catch(() => undefined);
    throw error;
  }
}

let syncInFlight: Promise<SyncReport> | null = null;

// Backup runs and share-copy uploads take turns: both can upload the same file,
// and the server keeps one cloud object per file.
let transfers: Promise<unknown> = Promise.resolve();
function exclusive<T>(task: () => Promise<T>): Promise<T> {
  const run = transfers.then(task, task);
  transfers = run.catch(() => undefined);
  return run;
}

/**
 * Upload ONE file's encrypted container so it can be shared, whether or not
 * cloud backup is on: sharing never requires backing everything up. The core
 * seals it exactly as a backup of it would be; with backup off it is marked a
 * shared copy and taken back once no share uses it. Returns the cloud object
 * id — an existing one if a backup run uploaded the file while this waited.
 */
export function uploadShareCopy(userId: string, entryId: string, onProgress?: (bytesDone: number, bytesTotal: number) => void): Promise<string> {
  return exclusive(async () => {
    const current = (await safeInvoke<StoreEntry[]>("vault_store_list")).find((entry) => entry.id === entryId);
    if (current?.cloudObjectId) return current.cloudObjectId;
    const prepared = await safeInvoke<PreparedUpload>("vault_cloud_prepare_share_copy", { entryId });
    onProgress?.(0, prepared.containerBytes);
    return uploadPrepared(userId, prepared, (_part, sent) => onProgress?.(sent, prepared.containerBytes));
  });
}

async function runDeletes(userId: string, deletes: string[], report: SyncReport, onProgress?: (progress: SyncProgress) => void) {
  for (const [position, objectId] of deletes.entries()) {
    onProgress?.({ stage: "deleting", label: "Removing deleted files from the cloud", item: position + 1, items: deletes.length, bytesDone: 0, bytesTotal: 0 });
    await withRetry(() => removeObject(userId, objectId));
    await safeInvoke("vault_cloud_complete_delete", { objectId });
    report.deleted += 1;
  }
}

function tableMissing(error: unknown): boolean {
  const text = error instanceof Error ? error.message : typeof error === "object" && error && "message" in error ? String((error as { message: unknown }).message) : String(error);
  return /does not exist|schema cache|PGRST20[25]/i.test(text);
}

async function fetchObjectRow(objectId: string): Promise<CloudObjectRow> {
  const { data, error } = await requireSupabase()
    .from("qv_cloud_objects")
    .select("id,owner_user_id,kind,entry_id,container_bytes,part_count,part_sha3,container_sha3,status,committed_at")
    .eq("id", objectId)
    .maybeSingle();
  if (error) throw cloudError(error);
  if (!data) throw new CloudError("QV_OBJECT_NOT_FOUND", "That file is no longer in the cloud.");
  return data as CloudObjectRow;
}

/** Merge the newest library document if another device published one. */
async function pullLibrary(userId: string, onProgress?: (progress: SyncProgress) => void): Promise<MergeReport | null> {
  const status = await libraryCore.status();
  const state = await fetchLibraryState(requireSupabase());
  if (!state?.object_id || state.revision <= status.revision) return null;
  onProgress?.({ stage: "library", label: "Bringing in changes from your other devices", item: 0, items: 0, bytesDone: 0, bytesTotal: 0 });
  const row = await fetchObjectRow(state.object_id);
  const downloadId = await downloadObject(userId, row);
  return safeInvoke<MergeReport>("vault_library_merge", { downloadId, revision: state.revision });
}

/**
 * Publish this device's view of the library as the next revision. Refused by
 * the server when another device published first: merge that, then retry.
 */
async function publishLibrary(userId: string, report: SyncReport, onProgress?: (progress: SyncProgress) => void): Promise<boolean> {
  const client = requireSupabase();
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const status = await libraryCore.status();
    if (!status.hasRing || !status.publishNeeded || status.epoch === null) return false;
    onProgress?.({ stage: "library", label: "Updating your library for your other devices", item: 0, items: 0, bytesDone: 0, bytesTotal: 0 });
    const prepared = await safeInvoke<PreparedUpload>("vault_library_prepare_publish");
    const objectId = await uploadPrepared(userId, prepared, () => undefined, "none");
    const { data, error } = await client.rpc("qv_publish_library", {
      p_object_id: objectId,
      p_expected_revision: status.revision,
      p_epoch: status.epoch,
      p_device_id: status.deviceId,
    });
    if (!error) {
      const published = data as { revision: number; previous_object_id: string | null };
      await safeInvoke("vault_library_published", {
        uploadId: prepared.uploadId,
        objectId,
        revision: published.revision,
        previousObjectId: published.previous_object_id ?? null,
      });
      return true;
    }
    await safeInvoke("vault_cloud_discard_upload", { uploadId: prepared.uploadId }).catch(() => undefined);
    await removeObject(userId, objectId).catch(() => undefined);
    if (!isRevisionConflict(error)) throw cloudError(error);
    const merged = await pullLibrary(userId, onProgress);
    if (merged) report.merged = merged;
  }
  throw new CloudError("QV_REVISION_CONFLICT", "Your other devices are changing the library right now. It will be retried shortly.");
}

/**
 * One sync run:
 *   1. deletions owed to the cloud;
 *   2. the library key ring (receive, start, rotate, hand out);
 *   3. changes published by the account's other devices (merge);
 *   4. every file not yet backed up;
 *   5. this device's changes, published for the others;
 *   6. objects replaced on the way.
 * Single-flight: a call while a run is going returns that run. A share-copy
 * upload in progress finishes first.
 */
export function runCloudSync(userId: string, onProgress?: (progress: SyncProgress) => void): Promise<SyncReport> {
  if (syncInFlight) return syncInFlight;
  syncInFlight = exclusive(async () => {
    const report: SyncReport = { uploaded: 0, deleted: 0, indexUploaded: false, stoppedBy: null, merged: null, libraryPublished: false, waitingForAccess: false, devices: [] };
    let failure: string | null = null;
    try {
      onProgress?.({ stage: "planning", label: "Checking what needs backing up", item: 0, items: 0, bytesDone: 0, bytesTotal: 0 });
      const client = requireSupabase();

      // The library key first: a device that can only join through another one
      // must be able to receive the key before backup can be switched on.
      let libraryReady = false;
      try {
        onProgress?.({ stage: "library", label: "Checking your other devices", item: 0, items: 0, bytesDone: 0, bytesTotal: 0 });
        const keys = await syncLibraryKey(client, userId);
        report.waitingForAccess = keys.waitingForAccess;
        report.devices = keys.devices;
        libraryReady = keys.status.hasRing;
      } catch (error) {
        if (!tableMissing(error)) throw error;
      }

      const plan = await safeInvoke<CloudPlan>("vault_cloud_plan");
      await runDeletes(userId, plan.deletes, report, onProgress);

      // Merging only downloads: a device with its own backup off still sees the
      // library (that is how a restored device gets its files back). Only
      // publishing — sending this device's changes — needs backup on.
      if (libraryReady) {
        report.merged = await pullLibrary(userId, onProgress);
      }

      const totalBytes = plan.uploads.reduce((sum, upload) => sum + upload.storedBytes, 0);
      let doneBytes = 0;
      for (const [position, upload] of plan.uploads.entries()) {
        const label = `Backing up ${upload.name}`;
        onProgress?.({ stage: "uploading", label, item: position + 1, items: plan.uploads.length, bytesDone: doneBytes, bytesTotal: totalBytes });
        try {
          const prepared = await safeInvoke<PreparedUpload>("vault_cloud_prepare_file", { entryId: upload.entryId });
          const base = doneBytes;
          await uploadPrepared(userId, prepared, (_part, sent) =>
            onProgress?.({ stage: "uploading", label, item: position + 1, items: plan.uploads.length, bytesDone: base + sent, bytesTotal: totalBytes }),
          );
          report.uploaded += 1;
        } catch (error) {
          if (error instanceof CloudError && STOPPING_CODES.has(error.code)) {
            report.stoppedBy = error.message;
            break;
          }
          throw error;
        }
        doneBytes += upload.storedBytes;
      }

      if (plan.indexNeeded && report.stoppedBy === null) {
        onProgress?.({ stage: "index", label: "Backing up folders and names (sealed with your recovery key)", item: 0, items: 0, bytesDone: 0, bytesTotal: 0 });
        const prepared = await safeInvoke<PreparedUpload>("vault_cloud_prepare_index");
        await uploadPrepared(userId, prepared, () => undefined);
        report.indexUploaded = true;
      }

      if (plan.enabled && libraryReady && report.stoppedBy === null) {
        report.libraryPublished = await publishLibrary(userId, report, onProgress);
      }

      // Replaced index / library copies are queued now; remove them in this run.
      const after = await safeInvoke<CloudPlan>("vault_cloud_plan");
      await runDeletes(userId, after.deletes, report, onProgress);
      failure = report.stoppedBy;
      return report;
    } catch (error) {
      failure = describeCloudError(error);
      throw error;
    } finally {
      await safeInvoke("vault_cloud_record_sync", { error: failure }).catch(() => undefined);
      onProgress?.({ stage: "done", label: "", item: 0, items: 0, bytesDone: 0, bytesTotal: 0 });
      syncInFlight = null;
    }
  });
  return syncInFlight;
}

// ---------------------------------------------------------------------------
// Download / restore
// ---------------------------------------------------------------------------

/**
 * Download one object into the core part by part; the core checks each part's
 * SHA3-256 before keeping it. `row.owner_user_id` is the owner's folder (a
 * shared file lives under its owner's).
 */
export async function downloadObject(userId: string, row: CloudObjectRow, onPart?: (done: number, total: number) => void): Promise<string> {
  const client = requireSupabase();
  const owner = row.owner_user_id ?? userId;
  const downloadId = await safeInvoke<string>("vault_cloud_download_begin", {
    containerBytes: row.container_bytes,
    partSha3: row.part_sha3,
    containerSha3: row.container_sha3,
  });
  for (let index = 0; index < row.part_count; index += 1) {
    const bytes = await withRetry(async () => {
      const { data, error } = await client.storage.from(VAULT_BUCKET).download(partPath(owner, row.id, index));
      if (error || !data) throw cloudError(error ?? { message: "empty part" });
      return new Uint8Array(await data.arrayBuffer());
    });
    // Base64 in a JSON argument, not a raw body: Android cannot deliver one.
    await invoke("vault_cloud_download_part", { downloadId, partIndex: index, partB64: bytesToBase64(bytes) });
    onPart?.(index + 1, row.part_count);
  }
  return downloadId;
}

/** Bring one backed-up file onto this device (opened and verified on the way). */
export async function downloadToDevice(userId: string, entry: StoreEntry, onPart?: (done: number, total: number) => void): Promise<void> {
  if (!entry.cloudObjectId) throw new CloudError("QV_NOT_BACKED_UP", "This file is not in your cloud backup.");
  const row = await fetchObjectRow(entry.cloudObjectId);
  const downloadId = await downloadObject(userId, row, onPart);
  await safeInvoke("vault_cloud_restore_file", { downloadId, entryId: entry.id, objectId: row.id });
}

/** Bring every file kept in the cloud only onto this device. */
export async function downloadCloudOnlyFiles(
  userId: string,
  entries: StoreEntry[],
  onProgress?: (progress: SyncProgress) => void,
): Promise<{ restored: number; failed: string[] }> {
  const missing = entries.filter((e) => e.kind === "file" && e.cloudObjectId && !e.availableOffline && !e.trashedAt);
  const rows = new Map((await fetchBackupObjects()).map((row) => [row.id, row]));
  const outcome = { restored: 0, failed: [] as string[] };
  for (const [position, entry] of missing.entries()) {
    onProgress?.({ stage: "restoring", label: `Restoring ${entry.name}`, item: position + 1, items: missing.length, bytesDone: 0, bytesTotal: 0 });
    const row = entry.cloudObjectId ? rows.get(entry.cloudObjectId) : undefined;
    if (!row) {
      outcome.failed.push(`${entry.name}: not in the cloud backup`);
      continue;
    }
    try {
      const downloadId = await downloadObject(userId, row);
      await safeInvoke("vault_cloud_restore_file", { downloadId, entryId: entry.id, objectId: row.id });
      outcome.restored += 1;
    } catch (error) {
      outcome.failed.push(`${entry.name}: ${describeCloudError(error)}`);
    }
  }
  await safeInvoke("vault_cloud_restore_end").catch(() => undefined);
  return outcome;
}

/** Download the newest recovery index and open it with the recovery key. */
export async function openBackup(userId: string, recoveryKey: string): Promise<{ preview: RestorePreview; rows: CloudObjectRow[] }> {
  const rows = await fetchBackupObjects();
  const index = rows.find((row) => row.kind === "recovery_index");
  if (!index) throw new CloudError("QV_NO_BACKUP", "No cloud backup was found for this account.");
  const downloadId = await downloadObject(userId, index);
  const preview = await safeInvoke<RestorePreview>("vault_cloud_restore_open_index", { downloadId, recoveryKey });
  return { preview, rows };
}

/** Restore every backed-up file not already here, after `openBackup`. */
export async function restoreFromBackup(
  userId: string,
  preview: RestorePreview,
  rows: CloudObjectRow[],
  onProgress?: (progress: SyncProgress) => void,
): Promise<{ restored: number; failed: string[] }> {
  const byEntry = new Map(rows.filter((row) => row.kind === "file" && row.entry_id).map((row) => [row.entry_id as string, row]));
  const wanted = preview.files.filter((file) => !file.present);
  const totalBytes = wanted.reduce((sum, file) => sum + file.sizeBytes, 0);
  let doneBytes = 0;
  const outcome = { restored: 0, failed: [] as string[] };
  try {
    for (const [position, file] of wanted.entries()) {
      onProgress?.({ stage: "restoring", label: `Restoring ${file.name}`, item: position + 1, items: wanted.length, bytesDone: doneBytes, bytesTotal: totalBytes });
      const row = byEntry.get(file.entryId);
      if (!row) {
        outcome.failed.push(`${file.name}: not in the cloud backup`);
        continue;
      }
      try {
        const downloadId = await downloadObject(userId, row);
        await safeInvoke("vault_cloud_restore_file", { downloadId, entryId: file.entryId, objectId: row.id });
        outcome.restored += 1;
      } catch (error) {
        outcome.failed.push(`${file.name}: ${describeCloudError(error)}`);
      }
      doneBytes += file.sizeBytes;
    }
  } finally {
    await safeInvoke("vault_cloud_restore_end").catch(() => undefined);
  }
  return outcome;
}

export async function endRestore(): Promise<void> {
  await safeInvoke("vault_cloud_restore_end").catch(() => undefined);
}
