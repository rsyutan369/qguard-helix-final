import { useCallback, useEffect, useRef, useState } from "react";
import { isAndroidRuntime, safeInvoke } from "@/lib/tauri";
import { isNativeDialogOpen } from "@/lib/native-dialog-guard";

export interface StoredSession {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  userId: string;
  email: string;
}

export interface AppLockDevice {
  deviceId: string;
  deviceName: string;
  platform: string;
  appVersion: string;
  registeredAt: string;
  lastLoginAt: string;
}

export interface AppLockStatus {
  configured: boolean;
  enabled: boolean;
  locked: boolean;
  digits: number;
  failedAttempts: number;
  attemptsRemaining: number;
  lockoutUntil: string | null;
  inactivityMinutes: number;
  device: AppLockDevice | null;
  requiresFullAuth: boolean;
}

export interface AppLockUnlockResult {
  // null only when the 5th wrong attempt wiped the store (status.requiresFullAuth true).
  session: StoredSession | null;
  status: AppLockStatus;
}

export function useAppLock(userId: string | null) {
  const [status, setStatus] = useState<AppLockStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const inactivityTimerRef = useRef<number | undefined>(undefined);
  const enabled = isAndroidRuntime();

  const refresh = useCallback(async () => {
    if (!enabled) {
      setStatus(null);
      setLoading(false);
      return;
    }
    const next = await safeInvoke<AppLockStatus | null>("applock_status", undefined, null);
    setStatus(next);
    setLoading(false);
  }, [enabled]);

  useEffect(() => {
    void refresh();
  }, [refresh, userId]);

  const setup = useCallback(
    async (digits: number, pin: string, session: StoredSession, deviceName: string, appVersion: string) => {
      const result = await safeInvoke<AppLockStatus>("applock_setup", { digits, pin, session, deviceName, appVersion });
      setStatus(result);
      return result;
    },
    [],
  );

  const unlock = useCallback(async (pin: string) => {
    try {
      const result = await safeInvoke<AppLockUnlockResult>("applock_unlock", { pin });
      setStatus(result.status);
      return result;
    } catch (error) {
      await refresh();
      throw error;
    }
  }, [refresh]);

  const lock = useCallback(async () => {
    if (!enabled) return;
    await safeInvoke("applock_lock", undefined, null);
    setStatus((s) => (s ? { ...s, locked: true } : s));
  }, [enabled]);

  const changePin = useCallback(async (oldPin: string, newPin: string, digits: number) => {
    try {
      const result = await safeInvoke<AppLockStatus>("applock_change_pin", { oldPin, newPin, digits });
      setStatus(result);
      return result;
    } catch (error) {
      await refresh();
      throw error;
    }
  }, [refresh]);

  const remove = useCallback(async () => {
    await safeInvoke("applock_remove", undefined, null);
    await refresh();
  }, [refresh]);

  const reset = useCallback(
    async (digits: number, pin: string, session: StoredSession, deviceName: string, appVersion: string) => {
      const result = await safeInvoke<AppLockStatus>("applock_reset", { digits, pin, session, deviceName, appVersion });
      setStatus(result);
      return result;
    },
    [],
  );

  const setInactivity = useCallback(async (minutes: number) => {
    const result = await safeInvoke<AppLockStatus>("applock_set_inactivity", { minutes });
    setStatus(result);
    return result;
  }, []);

  // Background + inactivity auto-lock (Android only). Lock only on real
  // app-background / inactivity — never on mere blur or while a native dialog
  // is open (permission prompt), honoring the native-dialog-trap lesson.
  const unlocked = Boolean(status && status.configured && !status.locked);
  const inactivityMinutes = status?.inactivityMinutes ?? 10;
  useEffect(() => {
    if (!enabled || !unlocked) return;

    const lockNow = () => {
      if (isNativeDialogOpen()) return;
      void lock();
    };
    const resetInactivity = () => {
      if (inactivityTimerRef.current !== undefined) window.clearTimeout(inactivityTimerRef.current);
      if (inactivityMinutes <= 0) return;
      inactivityTimerRef.current = window.setTimeout(lockNow, inactivityMinutes * 60_000);
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") lockNow();
      else resetInactivity();
    };
    const onActivity = () => resetInactivity();

    document.addEventListener("visibilitychange", onVisibility);
    ["mousedown", "keydown", "touchstart", "wheel"].forEach((e) =>
      window.addEventListener(e, onActivity, { passive: true }),
    );
    resetInactivity();
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      ["mousedown", "keydown", "touchstart", "wheel"].forEach((e) => window.removeEventListener(e, onActivity));
      if (inactivityTimerRef.current !== undefined) window.clearTimeout(inactivityTimerRef.current);
    };
  }, [enabled, unlocked, inactivityMinutes, lock]);

  return { status, loading, enabled, refresh, setup, unlock, lock, changePin, remove, reset, setInactivity };
}
