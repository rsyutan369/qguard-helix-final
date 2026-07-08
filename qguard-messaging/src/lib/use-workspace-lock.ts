import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { clearChatPlaintextCaches } from "@/lib/chat-plaintext-cache";
import { safeInvoke } from "@/lib/tauri";
import { isNativeDialogOpen } from "@/lib/native-dialog-guard";

// Zero-Trust Workspace Lock — client state for the Secure Chat / Quantum Vault
// gates. Verification + key unlock happen entirely in Rust; this hook only
// reflects status, drives unlock/setup, and enforces auto-lock + inactivity.

export type WorkspaceScope = "chat" | "vault";
export type UnlockMethod = "password" | "pin";

export interface ScopeStatus {
  configured: boolean;
  hasPassword: boolean;
  hasPin: boolean;
  unlocked: boolean;
  failedAttempts: number;
  lockoutUntil: string | null;
  lockdown: boolean;
}

export interface WorkspaceStatus {
  chat: ScopeStatus;
  vault: ScopeStatus;
}

const EMPTY_SCOPE: ScopeStatus = {
  configured: false,
  hasPassword: false,
  hasPin: false,
  unlocked: false,
  failedAttempts: 0,
  lockoutUntil: null,
  lockdown: false,
};

export const INACTIVITY_OPTIONS = [5, 15, 30, 60, 0] as const; // 0 = Never
export const DEFAULT_INACTIVITY_MINUTES = 15;

function inactivityStorageKey(userId: string): string {
  return `qguard.workspace.inactivity:${userId}`;
}

function readInactivityMinutes(userId: string): number {
  try {
    const raw = window.localStorage.getItem(inactivityStorageKey(userId));
    if (raw === null) return DEFAULT_INACTIVITY_MINUTES;
    const value = Number(raw);
    return INACTIVITY_OPTIONS.includes(value as (typeof INACTIVITY_OPTIONS)[number]) ? value : DEFAULT_INACTIVITY_MINUTES;
  } catch {
    return DEFAULT_INACTIVITY_MINUTES;
  }
}

export function useWorkspaceLock(userId: string | null) {
  const [status, setStatus] = useState<WorkspaceStatus | null>(null);
  const [inactivityMinutes, setInactivityMinutesState] = useState<number>(() =>
    userId ? readInactivityMinutes(userId) : DEFAULT_INACTIVITY_MINUTES,
  );
  const inactivityTimerRef = useRef<number | undefined>(undefined);

  const refresh = useCallback(async () => {
    if (!userId) return;
    const next = await safeInvoke<WorkspaceStatus | null>("workspace_status", undefined, null);
    if (next) setStatus(next);
  }, [userId]);

  useEffect(() => {
    if (!userId) {
      setStatus(null);
      return;
    }
    setInactivityMinutesState(readInactivityMinutes(userId));
    void refresh();
  }, [userId, refresh]);

  const unlock = useCallback(
    async (scope: WorkspaceScope, method: UnlockMethod, secret: string) => {
      try {
        const result = await safeInvoke<ScopeStatus>("workspace_unlock", { scope, method, secret });
        setStatus((current) => ({ ...(current ?? { chat: EMPTY_SCOPE, vault: EMPTY_SCOPE }), [scope]: result }));
        return result;
      } catch (error) {
        // Pull the updated attempt counter / lockout window so the UI reflects it.
        await refresh();
        throw error;
      }
    },
    [refresh],
  );

  const setup = useCallback(
    async (scope: WorkspaceScope, method: UnlockMethod, secret: string) => {
      const result = await safeInvoke<ScopeStatus>("workspace_setup_credential", { scope, method, secret });
      setStatus((current) => ({ ...(current ?? { chat: EMPTY_SCOPE, vault: EMPTY_SCOPE }), [scope]: result }));
      return result;
    },
    [],
  );

  // Reset the Secure Chat lock (verifier-only, so no messages are lost). The
  // caller must re-authenticate the account before invoking this.
  const resetChatLock = useCallback(async () => {
    clearChatPlaintextCaches();
    const result = await safeInvoke<ScopeStatus>("workspace_reset_chat_lock");
    setStatus((current) => ({ ...(current ?? { chat: EMPTY_SCOPE, vault: EMPTY_SCOPE }), chat: result }));
    return result;
  }, []);

  // Reset the Quantum Vault lock with a fresh Vault Master Key. `recoveryKey`
  // proves possession of the recovery key; when omitted the caller must have
  // re-authenticated the account password first (destructive "start fresh").
  const resetVault = useCallback(
    async (args: { recoveryKey?: string; method: UnlockMethod; secret: string }) => {
      const result = await safeInvoke<ScopeStatus>("workspace_reset_vault", {
        recoveryKey: args.recoveryKey ?? null,
        method: args.method,
        secret: args.secret,
      });
      setStatus((current) => ({ ...(current ?? { chat: EMPTY_SCOPE, vault: EMPTY_SCOPE }), vault: result }));
      return result;
    },
    [],
  );

  const lock = useCallback(async (scope: WorkspaceScope) => {
    // Locking chat must also wipe the in-memory decrypted history cache — the
    // Rust side drops its cache too; plaintext never outlives the lock.
    if (scope === "chat") clearChatPlaintextCaches();
    const result = await safeInvoke<ScopeStatus>("workspace_lock", { scope });
    setStatus((current) => ({ ...(current ?? { chat: EMPTY_SCOPE, vault: EMPTY_SCOPE }), [scope]: result }));
  }, []);

  const lockAll = useCallback(async () => {
    clearChatPlaintextCaches();
    await safeInvoke("workspace_lock_all", undefined, null);
    setStatus((current) =>
      current
        ? {
            chat: { ...current.chat, unlocked: false },
            vault: { ...current.vault, unlocked: false },
          }
        : current,
    );
  }, []);

  const setInactivityMinutes = useCallback(
    (minutes: number) => {
      setInactivityMinutesState(minutes);
      if (!userId) return;
      try {
        window.localStorage.setItem(inactivityStorageKey(userId), String(minutes));
      } catch {
        // localStorage optional
      }
    },
    [userId],
  );

  const anyUnlocked = Boolean(status && (status.chat.unlocked || status.vault.unlocked));

  // Auto-lock on app blur / minimize / tab hidden / close, and on inactivity.
  useEffect(() => {
    if (!userId) return;

    const lockNow = () => {
      // An app-opened native OS dialog (vault encrypt/decrypt picker, chat/avatar
      // file attach) blurs the WebView and flips visibility to "hidden" without
      // the user actually leaving — never lock mid-dialog. See native-dialog-guard.
      if (isNativeDialogOpen()) return;
      if (status && (status.chat.unlocked || status.vault.unlocked)) void lockAll();
    };

    const resetInactivity = () => {
      if (inactivityTimerRef.current !== undefined) window.clearTimeout(inactivityTimerRef.current);
      if (inactivityMinutes <= 0) return; // Never
      inactivityTimerRef.current = window.setTimeout(lockNow, inactivityMinutes * 60_000);
    };

    // `visibilitychange -> hidden` covers minimize / tab-hide / device sleep.
    // NOTE: on WebView2 this (like window "blur") ALSO fires when the app opens
    // a native file dialog, so `lockNow` consults the native-dialog guard to
    // avoid locking mid-operation. See native-dialog-guard.ts.
    const onVisibility = () => {
      if (document.visibilityState === "hidden") lockNow();
      else resetInactivity();
    };
    const onActivity = () => resetInactivity();

    window.addEventListener("beforeunload", lockNow);
    document.addEventListener("visibilitychange", onVisibility);
    ["mousemove", "mousedown", "keydown", "touchstart", "wheel"].forEach((event) =>
      window.addEventListener(event, onActivity, { passive: true }),
    );
    resetInactivity();

    return () => {
      window.removeEventListener("beforeunload", lockNow);
      document.removeEventListener("visibilitychange", onVisibility);
      ["mousemove", "mousedown", "keydown", "touchstart", "wheel"].forEach((event) =>
        window.removeEventListener(event, onActivity),
      );
      if (inactivityTimerRef.current !== undefined) window.clearTimeout(inactivityTimerRef.current);
    };
  }, [userId, inactivityMinutes, anyUnlocked, lockAll, status]);

  const helpers = useMemo(
    () => ({
      isConfigured: (scope: WorkspaceScope) => Boolean(status?.[scope].configured),
      isUnlocked: (scope: WorkspaceScope) => Boolean(status?.[scope].unlocked),
      scope: (scope: WorkspaceScope) => status?.[scope] ?? null,
    }),
    [status],
  );

  return {
    status,
    refresh,
    unlock,
    setup,
    lock,
    lockAll,
    resetChatLock,
    resetVault,
    inactivityMinutes,
    setInactivityMinutes,
    ...helpers,
  };
}
