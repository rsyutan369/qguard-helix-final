import { invokeWithTimeout, isAndroidRuntime } from "@/lib/tauri";

/**
 * Save a file the user asked to keep onto the device.
 *
 * Every save in the app used to be `<a download>` on a blob URL. That works in a
 * desktop WebView, which has a download manager, and does NOTHING on Android:
 * the system WebView has no download manager for page-initiated downloads and
 * cannot hand a blob: URL to one, so it drops the click without an error. The
 * app then reported "decrypted locally" / "recovery codes downloaded" while no
 * file existed — for recovery material, a silent loss.
 *
 * On Android the bytes now go through the native MediaStore bridge
 * (`downloads_save_*` commands) into `Download/QGuard/`, and the result names
 * the file actually written. Desktop keeps the WebView download manager, which
 * saves to the Downloads folder and applies the OS's downloaded-file protections
 * (Mark-of-the-Web / SmartScreen) that a raw native write would skip.
 */

export interface SavedFile {
  /** Name the file was saved under (Android may add a ` (n)` suffix). */
  name: string;
  /** Where the user will find it, phrased for display. */
  location: string;
  /**
   * True when the app wrote the file and confirmed it. False when it handed the
   * file to the WebView's download manager, which reports nothing back.
   */
  confirmed: boolean;
}

export type SaveInvoker = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

/** Plaintext per IPC message; keeps peak memory small on phones. */
export const SAVE_CHUNK_BYTES = 512 * 1024;
/** Per-step bound. Each step is one bounded write, never the whole file. */
const STEP_TIMEOUT_MS = 30_000;

const defaultInvoker: SaveInvoker = (command, args) => invokeWithTimeout(command, args, STEP_TIMEOUT_MS);

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const stride = 0x8000;
  for (let index = 0; index < bytes.length; index += stride) {
    binary += String.fromCharCode(...bytes.subarray(index, index + stride));
  }
  return btoa(binary);
}

/** Android: begin -> chunk* -> commit, aborting the partial file on any failure. */
export async function saveToAndroidDownloads(
  name: string,
  data: Blob,
  invoker: SaveInvoker = defaultInvoker,
): Promise<SavedFile> {
  const handle = await invoker<string>("downloads_save_begin", {
    fileName: name,
    mimeType: data.type || "application/octet-stream",
  });
  try {
    for (let offset = 0; offset < data.size; offset += SAVE_CHUNK_BYTES) {
      const chunk = new Uint8Array(await data.slice(offset, offset + SAVE_CHUNK_BYTES).arrayBuffer());
      const chunkB64 = bytesToBase64(chunk);
      chunk.fill(0);
      await invoker("downloads_save_chunk", { handle, chunkB64 });
    }
    const saved = await invoker<{ name: string; location: string }>("downloads_save_commit", { handle });
    return { name: saved.name, location: saved.location, confirmed: true };
  } catch (error) {
    await invoker("downloads_save_abort", { handle }).catch(() => undefined);
    throw error;
  }
}

/**
 * Desktop / browser: hand the file to the WebView's download manager. The
 * object URL is revoked after a delay, not synchronously: revoking straight
 * after `click()` can race the download manager's read of the blob.
 */
function startBrowserDownload(name: string, data: Blob): SavedFile {
  const url = URL.createObjectURL(data);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  return { name, location: "your Downloads folder", confirmed: false };
}

export async function saveFileToDevice(name: string, data: Blob): Promise<SavedFile> {
  if (isAndroidRuntime()) return saveToAndroidDownloads(name, data);
  return startBrowserDownload(name, data);
}

/** One status line for a completed save, honest about what was confirmed. */
export function describeSavedFile(saved: SavedFile): string {
  return saved.confirmed
    ? `Saved to ${saved.location}`
    : `Download started: ${saved.name} (saved to ${saved.location})`;
}
