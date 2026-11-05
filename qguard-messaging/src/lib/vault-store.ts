// Quantum Vault Storage — client model and API.
//
// The library itself lives in the Rust core (src-tauri/src/vault/store.rs and
// commands/vault_store.rs): containers in the app's private data directory, and
// one index of names / folders / integrity sealed under the PIN-bound vault key.
// Nothing here stores or invents vault state. The helpers below only shape what
// the core returned (tree, filters, sort) and every API call is a Tauri command.

import { Channel } from "@tauri-apps/api/core";
import { ipcArrayBuffer } from "@/lib/encoding";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import type { VaultProgress } from "@/lib/vault-progress";

export type StoreCategory = "image" | "video" | "audio" | "document" | "archive" | "other";
export type StoreIntegrity = "verified" | "unverified" | "failed" | "missing";

export interface StoreEntry {
  id: string;
  kind: "file" | "folder";
  name: string;
  parentId: string | null;
  createdAt: string;
  updatedAt: string;
  trashedAt: string | null;
  favorite: boolean;
  sizeBytes: number;
  storedBytes: number;
  contentType: string;
  category: StoreCategory | "";
  typeCheck: "match" | "mismatch" | "unknown" | "";
  plaintextSha3: string;
  containerVersion: number;
  pinBound: boolean;
  totalChunks: number;
  recoveryProtected: boolean;
  integrity: StoreIntegrity | "";
  lastVerifiedAt: string | null;
  hasThumbnail: boolean;
  /** Cloud backup object holding this file's container, once committed. */
  cloudObjectId?: string | null;
  cloudBackedUpAt?: string | null;
  /** The encrypted object is on this device (false = kept in the cloud only). */
  availableOffline?: boolean;
  /**
   * The cloud copy exists only because the file is shared (cloud backup off):
   * it is not a backup, and it is removed when no share uses it any more.
   */
  cloudSharedOnly?: boolean;
}

export interface StoreActivity {
  id: string;
  at: string;
  action: string;
  entryId: string | null;
  name: string;
  detail: string;
  outcome: "success" | "failed";
}

export interface CategoryUsage {
  files: number;
  bytes: number;
}

export interface StoreStatus {
  state: "ready" | "foreign";
  storageLocation: string;
  vaultId: string;
  files: number;
  folders: number;
  trashed: number;
  favorites: number;
  plaintextBytes: number;
  storedBytes: number;
  categories: Record<StoreCategory, CategoryUsage>;
  verified: number;
  unverified: number;
  failed: number;
  missing: number;
  typeMismatches: number;
  legacyContainers: number;
  recoveryProtected: number;
  orphanedObjects: number;
  recoveryIndex: boolean;
  lastImportAt: string | null;
  lastFullVerifyAt: string | null;
  recentActivity: StoreActivity[];
  limits: { maxPreviewBytes: number; maxImportBytes: number; maxThumbnailBytes: number };
}

export interface ImportOutcome {
  entry: StoreEntry;
  skippedDuplicate: boolean;
}

export interface FolderImportOutcome {
  rootFolderId: string | null;
  imported: number;
  skippedDuplicates: number;
  failed: Array<{ name: string; error: string }>;
}

export interface PurgeOutcome {
  removedEntries: number;
  destroyedObjects: number;
}

export interface VerifyReport {
  checked: number;
  verified: number;
  failed: number;
  missing: number;
  finishedAt: string;
}

export interface ExportOutcome {
  name: string;
  destination: string;
  files: number;
  bytes: number;
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

export const CATEGORY_LABELS: Record<StoreCategory, string> = {
  image: "Photos",
  video: "Videos",
  audio: "Audio",
  document: "Documents",
  archive: "Archives",
  other: "Other",
};

/** Content types the core will decrypt into memory for an in-app preview. */
export const PREVIEWABLE_TYPES = new Set([
  "image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp", "image/avif",
  "video/mp4", "video/webm", "video/quicktime",
  "audio/mpeg", "audio/wav", "audio/aac", "audio/mp4", "audio/flac", "audio/ogg",
  "text/plain", "text/csv", "application/json",
]);

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`;
}

export function canPreview(entry: StoreEntry, maxPreviewBytes: number): boolean {
  return entry.kind === "file" && PREVIEWABLE_TYPES.has(entry.contentType) && entry.sizeBytes <= maxPreviewBytes;
}

/** Map of every entry by id. */
export function byId(entries: StoreEntry[]): Map<string, StoreEntry> {
  return new Map(entries.map((entry) => [entry.id, entry]));
}

/** True when the entry or any folder above it is in the Trash (mirrors the core). */
export function inTrash(index: Map<string, StoreEntry>, id: string): boolean {
  let current = index.get(id);
  let guard = 0;
  while (current && guard < 256) {
    if (current.trashedAt) return true;
    current = current.parentId ? index.get(current.parentId) : undefined;
    guard += 1;
  }
  return false;
}

/** Items in the Trash themselves (their contents go with them). */
export function trashRoots(entries: StoreEntry[]): StoreEntry[] {
  return entries.filter((entry) => entry.trashedAt);
}

export function liveEntries(entries: StoreEntry[]): StoreEntry[] {
  const index = byId(entries);
  return entries.filter((entry) => !inTrash(index, entry.id));
}

export function childrenOf(entries: StoreEntry[], parentId: string | null): StoreEntry[] {
  return entries.filter((entry) => (entry.parentId ?? null) === parentId);
}

/** Folder chain from the top level down to `folderId`. */
export function breadcrumb(index: Map<string, StoreEntry>, folderId: string | null): StoreEntry[] {
  const chain: StoreEntry[] = [];
  let current = folderId ? index.get(folderId) : undefined;
  while (current && chain.length < 256) {
    chain.unshift(current);
    current = current.parentId ? index.get(current.parentId) : undefined;
  }
  return chain;
}

/** Live folders a selection may be moved into (never into itself or below it). */
export function moveTargets(entries: StoreEntry[], moving: Set<string>): StoreEntry[] {
  const index = byId(entries);
  const blocked = (id: string) => {
    let current = index.get(id);
    let guard = 0;
    while (current && guard < 256) {
      if (moving.has(current.id)) return true;
      current = current.parentId ? index.get(current.parentId) : undefined;
      guard += 1;
    }
    return false;
  };
  return liveEntries(entries)
    .filter((entry) => entry.kind === "folder" && !blocked(entry.id))
    .sort((a, b) => breadcrumb(index, a.id).map((e) => e.name).join("/").localeCompare(breadcrumb(index, b.id).map((e) => e.name).join("/")));
}

/** Total size and file count inside a folder (live items only). */
export function folderTotals(entries: StoreEntry[], folderId: string): { files: number; bytes: number } {
  const index = byId(entries);
  let files = 0;
  let bytes = 0;
  for (const entry of entries) {
    if (entry.kind !== "file" || inTrash(index, entry.id)) continue;
    let current = entry.parentId ? index.get(entry.parentId) : undefined;
    let guard = 0;
    while (current && guard < 256) {
      if (current.id === folderId) {
        files += 1;
        bytes += entry.sizeBytes;
        break;
      }
      current = current.parentId ? index.get(current.parentId) : undefined;
      guard += 1;
    }
  }
  return { files, bytes };
}

export type SortKey = "name" | "date" | "size" | "type";
export type SortDirection = "asc" | "desc";

/** Folders first, then files, by the chosen key. */
export function sortEntries(entries: StoreEntry[], key: SortKey, direction: SortDirection): StoreEntry[] {
  const factor = direction === "asc" ? 1 : -1;
  const byName = (a: StoreEntry, b: StoreEntry) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
  return [...entries].sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === "folder" ? -1 : 1;
    let order = 0;
    if (key === "date") order = a.updatedAt.localeCompare(b.updatedAt);
    else if (key === "size") order = a.sizeBytes - b.sizeBytes;
    else if (key === "type") order = a.contentType.localeCompare(b.contentType);
    if (order === 0) order = byName(a, b);
    return order * factor;
  });
}

export interface EntryFilter {
  query?: string;
  categories?: StoreCategory[];
  favoritesOnly?: boolean;
}

export function matchesFilter(entry: StoreEntry, filter: EntryFilter): boolean {
  if (filter.favoritesOnly && !entry.favorite) return false;
  if (filter.categories && filter.categories.length > 0) {
    if (entry.kind !== "file" || !filter.categories.includes(entry.category as StoreCategory)) return false;
  }
  const query = filter.query?.trim().toLowerCase();
  if (query && !entry.name.toLowerCase().includes(query)) return false;
  return true;
}

export function integrityLabel(entry: StoreEntry): string {
  switch (entry.integrity) {
    case "verified":
      return "Integrity verified";
    case "failed":
      return "Integrity check failed";
    case "missing":
      return "Encrypted object missing";
    default:
      return "Not yet verified";
  }
}

/** User-facing text for a Vault Storage error. */
export function describeStoreError(error: unknown): string {
  const raw = error instanceof Error ? error.message : typeof error === "string" ? error : JSON.stringify(error);
  if (raw.includes("VAULT_STORE_FOREIGN_INDEX")) {
    return "This vault storage was sealed by your previous vault key (before a vault reset). Its files are kept and open with your recovery key.";
  }
  if (raw.includes("Quantum Vault is locked")) return "The vault locked. Unlock it to continue.";
  if (raw.includes("AEAD authentication failed") || raw.includes("does not match the SHA3-256")) {
    return "Integrity check failed: the encrypted file has been altered or damaged, so it was not opened.";
  }
  if (raw.includes("missing from the vault")) return "The encrypted object for this file is missing from this device.";
  return raw.replace(/^(storage|invalid input|crypto|trust|not found) error: /i, "").replace(/^(invalid input|not found): /i, "");
}

export function progressPercent(progress: VaultProgress | null): number {
  if (!progress || progress.totalBytes <= 0) return progress?.phase === "done" ? 100 : 0;
  return Math.max(0, Math.min(100, Math.round((progress.processedBytes / progress.totalBytes) * 100)));
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

export function progressChannel(onProgress?: (progress: VaultProgress) => void): Channel<VaultProgress> | null {
  if (!isTauriRuntime()) return null;
  const channel = new Channel<VaultProgress>();
  channel.onmessage = (progress) => onProgress?.(progress);
  return channel;
}

export const vaultStore = {
  status: () => safeInvoke<StoreStatus>("vault_store_status"),
  list: () => safeInvoke<StoreEntry[]>("vault_store_list"),
  activity: () => safeInvoke<StoreActivity[]>("vault_store_activity"),
  pathKind: (path: string) => safeInvoke<"file" | "folder" | "other">("vault_store_path_kind", { path }),
  importFile: (sourcePath: string, parentId: string | null, onProgress?: (p: VaultProgress) => void) =>
    safeInvoke<ImportOutcome>("vault_store_import", { sourcePath, parentId, skipDuplicates: true, onProgress: progressChannel(onProgress) }),
  importFolder: (sourceDir: string, parentId: string | null, onProgress?: (p: VaultProgress) => void) =>
    safeInvoke<FolderImportOutcome>("vault_store_import_folder", { sourceDir, parentId, skipDuplicates: true, onProgress: progressChannel(onProgress) }),
  createFolder: (parentId: string | null, name: string) => safeInvoke<StoreEntry>("vault_store_create_folder", { parentId, name }),
  rename: (id: string, name: string) => safeInvoke<StoreEntry>("vault_store_rename", { id, name }),
  move: (ids: string[], parentId: string | null) => safeInvoke<StoreEntry[]>("vault_store_move", { ids, parentId }),
  setFavorite: (id: string, favorite: boolean) => safeInvoke<StoreEntry>("vault_store_set_favorite", { id, favorite }),
  trash: (ids: string[]) => safeInvoke<StoreEntry[]>("vault_store_trash", { ids }),
  restore: (ids: string[]) => safeInvoke<StoreEntry[]>("vault_store_restore", { ids }),
  purge: (ids: string[]) => safeInvoke<PurgeOutcome>("vault_store_purge", { ids }),
  emptyTrash: () => safeInvoke<PurgeOutcome>("vault_store_empty_trash"),
  verify: (id: string, onProgress?: (p: VaultProgress) => void) =>
    safeInvoke<StoreEntry>("vault_store_verify", { id, onProgress: progressChannel(onProgress) }),
  verifyAll: (onProgress?: (p: VaultProgress) => void) =>
    safeInvoke<VerifyReport>("vault_store_verify_all", { onProgress: progressChannel(onProgress) }),
  /** Authenticated plaintext, decrypted into memory only. */
  preview: async (id: string): Promise<ArrayBuffer> => ipcArrayBuffer(await safeInvoke<unknown>("vault_store_preview", { id })),
  exportFile: (id: string, destPath: string, onProgress?: (p: VaultProgress) => void) =>
    safeInvoke<ExportOutcome>("vault_store_export", { id, destPath, onProgress: progressChannel(onProgress) }),
  exportFolder: (id: string, destDir: string, onProgress?: (p: VaultProgress) => void) =>
    safeInvoke<ExportOutcome>("vault_store_export_folder", { id, destDir, onProgress: progressChannel(onProgress) }),
  setThumbnail: (id: string, dataB64: string) => safeInvoke<void>("vault_store_set_thumbnail", { id, dataB64 }),
  thumbnail: async (id: string): Promise<ArrayBuffer> => ipcArrayBuffer(await safeInvoke<unknown>("vault_store_thumbnail", { id })),
  startFresh: () => safeInvoke<{ archivedTo: string }>("vault_store_start_fresh", { confirmation: "START FRESH" }),
};
