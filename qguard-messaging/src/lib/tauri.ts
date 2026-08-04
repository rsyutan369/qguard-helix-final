import { invoke } from "@tauri-apps/api/core";

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/**
 * True when running inside the Android build. The updater/process plugins are
 * not registered on mobile (updates ship as APKs), so update flows must no-op.
 */
export function isAndroidRuntime(): boolean {
  return isTauriRuntime() && /android/i.test(navigator.userAgent);
}

export async function safeInvoke<T>(command: string, args?: Record<string, unknown>, fallback?: T): Promise<T> {
  if (!isTauriRuntime()) {
    if (fallback !== undefined) return fallback;
    throw new Error("This action requires the QGuard desktop app.");
  }

  try {
    return await invoke<T>(command, args);
  } catch (error) {
    if (fallback !== undefined) return fallback;
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("invoke")) {
      throw new Error("This action requires the QGuard desktop app.");
    }
    throw error;
  }
}

/**
 * `safeInvoke` with an upper bound on how long the caller will wait.
 *
 * Use ONLY for commands whose work is inherently bounded (a single message
 * decrypt), never for genuinely long-running ones (vault encryption of a large
 * file), which is why this is opt-in rather than baked into `safeInvoke`.
 *
 * Tauri's IPC has no cancellation, so a timeout does not stop the Rust side —
 * it only stops the caller from awaiting forever. That matters because an
 * un-timed `await invoke(...)` inside a loop means one stalled command can hang
 * the entire enclosing operation with no error surfaced: the Secure Chat
 * history load's `finally` (which clears the loading flag) never runs, leaving
 * the thread pinned on "Loading encrypted history..." indefinitely.
 */
export async function invokeWithTimeout<T>(
  command: string,
  args: Record<string, unknown> | undefined,
  timeoutMs: number,
): Promise<T> {
  let timer: number | undefined;
  try {
    return await Promise.race([
      safeInvoke<T>(command, args),
      new Promise<never>((_resolve, reject) => {
        timer = window.setTimeout(
          () => reject(new Error(`${command} timed out after ${Math.round(timeoutMs / 1000)}s`)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) window.clearTimeout(timer);
  }
}
