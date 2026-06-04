import { invoke } from "@tauri-apps/api/core";

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
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
