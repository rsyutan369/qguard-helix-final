// Where decrypted / encrypted vault output goes — shared by the Quantum Vault
// tools and Vault Storage export.

import { open as openDialog } from "@/lib/tauri-dialog";
import { withNativeDialog } from "@/lib/native-dialog-guard";
import { isAndroidRuntime, safeInvoke } from "@/lib/tauri";

export interface VaultFolderChoice {
  /** SAF tree URI (Android) or a filesystem directory path (desktop). */
  path: string;
  /** Human-readable location for the activity log. */
  label: string;
}

/**
 * Ask the user where the output should go.
 *
 * Desktop uses the native directory dialog. Android has no folder picker in the
 * Tauri dialog plugin, so `vault_pick_folder` drives the Storage Access
 * Framework tree picker natively and persists the grant — which is what lets a
 * user-chosen Android folder hold registry-tracked containers that stay
 * decryptable after a restart.
 */
export async function chooseDestinationFolder(title: string): Promise<VaultFolderChoice | null> {
  if (isAndroidRuntime()) {
    // MUST be guarded like any other app-opened native dialog. The SAF picker is
    // a separate Activity, so launching it fires the WebView's `visibilitychange`
    // AND MainActivity.onStop — both of which mean "the user left the app" to the
    // Zero-Trust auto-lock. Unguarded, choosing a folder would drop the user onto
    // the PIN screen and tear the vault operation down mid-flight.
    //
    // No `fallback` on this safeInvoke call: a real Rust/JNI failure must throw,
    // not collapse into the same `null` as a genuine user cancel — a swallowed
    // native error here previously surfaced as a misleading "no destination
    // folder chosen" with no way to tell it apart from an actual cancel.
    const choice = await withNativeDialog(() =>
      safeInvoke<VaultFolderChoice | null>("vault_pick_folder"),
    );
    return choice ?? null;
  }
  const directory = await openDialog({ multiple: false, directory: true, title });
  if (typeof directory !== "string") return null;
  return { path: directory, label: directory };
}

/** Resolve a chosen folder + file name into the concrete output target. */
export async function prepareDestination(folder: string, fileName: string): Promise<string> {
  return safeInvoke<string>("vault_prepare_dest", { folder, fileName });
}
