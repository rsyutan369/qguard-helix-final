import { isAndroidRuntime, isTauriRuntime } from "@/lib/tauri";
import type { Update } from "@tauri-apps/plugin-updater";

/**
 * The installed application version.
 *
 * Sourced from the Tauri bundle config (src-tauri/tauri.conf.json) at build
 * time via Vite `define` (see vite.config.ts). This is the exact version that
 * ships in the signed installer, so it stays truthful across releases without
 * any manual bumping. Falls back gracefully when the constant is absent (e.g.
 * an isolated unit-test runner that skips the define plugin).
 */
export const APP_VERSION: string =
  typeof __APP_VERSION__ === "string" && __APP_VERSION__ ? __APP_VERSION__ : "0.0.0";

export type UpdateProgress = { percent: number | null };

/**
 * Query the signed-update endpoint for a newer release.
 *
 * Returns the pending {@link Update} when a newer signed build is available,
 * or `null` when the app is already current. Returns `null` (never throws) when
 * running outside the desktop runtime, so browser/dev contexts degrade quietly.
 * Genuine failures (offline, unreachable endpoint, signature mismatch) reject —
 * callers decide whether that surfaces to the user.
 */
export async function checkForAppUpdate(): Promise<Update | null> {
  if (!isTauriRuntime()) return null;
  // Android has no updater plugin — releases ship as signed APK/Play updates.
  if (isAndroidRuntime()) return null;
  const { check } = await import("@tauri-apps/plugin-updater");
  return await check();
}

/**
 * Download and install a pending update in-app, reporting download progress as
 * a 0–100 percentage (or `null` when the server omits a content length).
 */
export async function downloadAndInstallUpdate(
  update: Update,
  onProgress?: (progress: UpdateProgress) => void,
): Promise<void> {
  let total = 0;
  let received = 0;
  await update.downloadAndInstall((event) => {
    if (event.event === "Started") {
      total = event.data.contentLength ?? 0;
    }
    if (event.event === "Progress") {
      received += event.data.chunkLength;
      onProgress?.({
        percent: total > 0 ? Math.min(100, Math.round((received / total) * 100)) : null,
      });
    }
  });
}

/** Relaunch the desktop app to finish applying an installed update. */
export async function relaunchApp(): Promise<void> {
  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}
