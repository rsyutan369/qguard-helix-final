// Guarded Tauri dialog wrappers
// ---------------------------------------------------------------------------
// Drop-in replacements for `@tauri-apps/plugin-dialog`'s `open` / `save` that
// register each native dialog with the native-dialog guard for its lifetime.
// Importing from here (instead of the plugin directly) keeps the workspace
// auto-lock from firing while the user is in an app-opened file picker.
// See `native-dialog-guard.ts` and `use-workspace-lock.ts`.

import {
  open as tauriOpen,
  save as tauriSave,
  type OpenDialogOptions,
  type OpenDialogReturn,
  type SaveDialogOptions,
} from "@tauri-apps/plugin-dialog";
import { withNativeDialog } from "@/lib/native-dialog-guard";

export function open<T extends OpenDialogOptions>(options?: T): Promise<OpenDialogReturn<T>> {
  return withNativeDialog(() => tauriOpen(options));
}

export function save(options?: SaveDialogOptions): Promise<string | null> {
  return withNativeDialog(() => tauriSave(options));
}
