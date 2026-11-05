// Hidden vaults — the open one's API (src-tauri/src/commands/vault_hidden.rs).
//
// A hidden vault is opened only by drawing its pattern on the vault lock
// screen (`patternUnlock` in use-workspace-lock); the app keeps no list of
// them and none of these calls can tell whether any exist. Entries come back
// in the same shape as Vault Storage's, so the same helpers and dialogs work.

import { ipcArrayBuffer } from "@/lib/encoding";
import { safeInvoke } from "@/lib/tauri";
import { progressChannel, type ExportOutcome, type StoreEntry } from "@/lib/vault-store";
import type { VaultProgress } from "@/lib/vault-progress";

export interface HiddenSummary {
  files: number;
  folders: number;
  bytes: number;
  createdAt: string;
  /**
   * Armed: drawing this vault's pattern on the lock screen erases every other
   * hidden vault on this device. Always false once it has fired.
   */
  duressErase: boolean;
  /** A 12-word recovery phrase is set up for this vault. */
  recoveryPhrase: boolean;
}

/** A new recovery phrase: shown once, never stored by the app. */
export interface HiddenRecoverySetup {
  words: string[];
  summary: HiddenSummary;
}

export interface HiddenStatus {
  open: boolean;
  /** Null while a long task holds the vault. */
  summary: HiddenSummary | null;
}

export const hiddenVault = {
  status: () => safeInvoke<HiddenStatus>("vault_hidden_status"),
  list: () => safeInvoke<StoreEntry[]>("vault_hidden_list"),
  importFile: (sourcePath: string, parentId: string | null, onProgress?: (p: VaultProgress) => void) =>
    safeInvoke<StoreEntry>("vault_hidden_import", { sourcePath, parentId, onProgress: progressChannel(onProgress) }),
  createFolder: (parentId: string | null, name: string) => safeInvoke<StoreEntry>("vault_hidden_create_folder", { parentId, name }),
  rename: (id: string, name: string) => safeInvoke<StoreEntry>("vault_hidden_rename", { id, name }),
  move: (ids: string[], parentId: string | null) => safeInvoke<StoreEntry[]>("vault_hidden_move", { ids, parentId }),
  /** Permanent: keys out of the index first, then the content is overwritten. */
  remove: (ids: string[]) => safeInvoke<number>("vault_hidden_delete", { ids }),
  /** Authenticated plaintext, in memory only. */
  preview: async (id: string): Promise<ArrayBuffer> => ipcArrayBuffer(await safeInvoke<unknown>("vault_hidden_preview", { id })),
  exportFile: (id: string, destPath: string, onProgress?: (p: VaultProgress) => void) =>
    safeInvoke<ExportOutcome>("vault_hidden_export", { id, destPath, onProgress: progressChannel(onProgress) }),
  lock: () => safeInvoke<void>("vault_hidden_lock"),
  destroy: () => safeInvoke<void>("vault_hidden_destroy", { confirmation: "DELETE" }),
  /** Arm or disarm duress erase for the open vault. */
  setDuress: (armed: boolean) => safeInvoke<HiddenSummary>("vault_hidden_set_duress", { armed }),
  /** From the unlocked Quantum Vault: create one and open it (the vault locks). */
  create: (pattern: string) => safeInvoke<HiddenSummary>("vault_hidden_create", { pattern }),
  /**
   * From the unlocked Quantum Vault: open one to look after it (the vault
   * locks). Its duress erase does not fire here. Counts as an attempt.
   */
  open: (pattern: string) => safeInvoke<HiddenSummary>("vault_hidden_open", { pattern }),
  /** From the unlocked Quantum Vault: wipe every hidden vault on this device. */
  eraseAll: () => safeInvoke<void>("vault_hidden_erase_all", { confirmation: "ERASE" }),
  /** For the open vault: a new 12-word phrase (any earlier one stops working). */
  setUpRecovery: () => safeInvoke<HiddenRecoverySetup>("vault_hidden_recovery_setup"),
  /** For the open vault: remove its phrase; only the pattern opens it after. */
  removeRecovery: () => safeInvoke<HiddenSummary>("vault_hidden_recovery_remove"),
  /** Which vault a phrase opens, summarised. Opens and changes nothing. */
  checkRecovery: (phrase: string) => safeInvoke<HiddenSummary>("vault_hidden_recovery_check", { phrase }),
  /**
   * A forgotten pattern: the phrase opens the vault, `pattern` replaces its
   * pattern, and it opens (the Quantum Vault locks). Counts as an attempt.
   */
  recover: (phrase: string, pattern: string) => safeInvoke<HiddenSummary>("vault_hidden_recover", { phrase, pattern }),
};

/** Words in a hidden vault recovery phrase. */
export const PHRASE_WORDS = 12;

/**
 * The words in typed or pasted text, lowercase: spaces, new lines, commas and
 * list numbers ("1." / "1)") are all separators. The core checks the words
 * against the BIP-39 list and its checksum.
 */
export function splitPhrase(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((word) => word.replace(/^[^a-z]+|[^a-z]+$/gi, "").toLowerCase())
    .filter(Boolean);
}

/**
 * The 12 word slots after `typed` went into slot `at`: a single word stays in
 * its slot; several (a paste) fill that slot and the ones after it.
 */
export function fillWords(current: readonly string[], at: number, typed: string): string[] {
  const next = Array.from({ length: PHRASE_WORDS }, (_, i) => current[i] ?? "");
  const parts = splitPhrase(typed);
  if (parts.length <= 1) {
    next[at] = typed.replace(/\s+/g, "").toLowerCase();
    return next;
  }
  parts.slice(0, PHRASE_WORDS - at).forEach((word, offset) => {
    next[at + offset] = word;
  });
  return next;
}

/** `count` distinct word positions (0-based, ascending) to confirm a phrase was written down. */
export function pickCheckPositions(count = 3, random: () => number = Math.random): number[] {
  const positions = Array.from({ length: PHRASE_WORDS }, (_, i) => i);
  for (let i = positions.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [positions[i], positions[j]] = [positions[j], positions[i]];
  }
  return positions.slice(0, count).sort((a, b) => a - b);
}
