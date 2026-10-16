// Guarded Tauri dialog wrappers
// ---------------------------------------------------------------------------
// Drop-in replacements for `@tauri-apps/plugin-dialog`'s `open` / `save` that
// register each native dialog with the native-dialog guard for its lifetime.
// Importing from here (instead of the plugin directly) keeps the workspace
// auto-lock from firing while the user is in an app-opened file picker.
// See `native-dialog-guard.ts` and `use-workspace-lock.ts`.

import {
  ask as tauriAsk,
  open as tauriOpen,
  save as tauriSave,
  type OpenDialogOptions,
  type OpenDialogReturn,
  type SaveDialogOptions,
} from "@tauri-apps/plugin-dialog";
import { withNativeDialog } from "@/lib/native-dialog-guard";

/**
 * A native yes/no question, guarded like every other app-opened dialog so it
 * does not trip the workspace auto-lock while the user is reading it.
 *
 * Used for consent that must not be a stray click away — e.g. opening a vault
 * file whose origin could not be verified. The native dialog cannot be
 * dismissed into "yes", and `window.confirm` is not reliably available in the
 * mobile WebView.
 */
export function ask(message: string, options: { title: string; okLabel: string; cancelLabel: string }): Promise<boolean> {
  return withNativeDialog(() =>
    tauriAsk(message, {
      title: options.title,
      kind: "warning",
      okLabel: options.okLabel,
      cancelLabel: options.cancelLabel,
    }),
  );
}

export function open<T extends OpenDialogOptions>(options?: T): Promise<OpenDialogReturn<T>> {
  return withNativeDialog(() => tauriOpen(options));
}

export function save(options?: SaveDialogOptions): Promise<string | null> {
  return withNativeDialog(() => tauriSave(options));
}
