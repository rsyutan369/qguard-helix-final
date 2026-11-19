import { useCallback, useEffect, useRef, useState } from "react";
import { isAndroidRuntime, safeInvoke } from "@/lib/tauri";
import { isCallActive, onCallActivityChange } from "@/lib/call-activity";
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
  /** A duress PIN is set (reported only while unlocked). */
  duressConfigured: boolean;
  /** Biometric unlock is set up on this device. */
  biometricEnabled: boolean;
  /** Which pad the lock screen shows (older cores do not report it: a PIN). */
  method?: AppLockMethod;
}

/** How the app lock opens: a 6-digit PIN or a drawn 4 × 4 pattern. */
export type AppLockMethod = "pin" | "pattern";

export type BiometricAvailability = "available" | "none_enrolled" | "no_hardware" | "unavailable" | "unsupported";

export interface BiometricStatus {
  availability: BiometricAvailability;
  enabled: boolean;
  /** Sensors the device has: "fingerprint", "face", "iris" (Android decides which its prompt uses). */
  modalities?: string[];
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
    async (digits: number, pin: string, session: StoredSession, deviceName: string, appVersion: string, method: AppLockMethod = "pin") => {
      const result = await safeInvoke<AppLockStatus>("applock_setup", { digits, pin, session, deviceName, appVersion, method });
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

  /** Same result as a correct PIN. A cancelled prompt throws and changes nothing. */
  const unlockWithBiometric = useCallback(async () => {
    try {
      const result = await safeInvoke<AppLockUnlockResult>("applock_biometric_unlock");
      setStatus(result.status);
      return result;
    } catch (error) {
      await refresh();
      throw error;
    }
  }, [refresh]);

  const setDuressPin = useCallback(async (pin: string) => {
    const result = await safeInvoke<AppLockStatus>("applock_set_duress_pin", { pin });
    setStatus(result);
    return result;
  }, []);

  const clearDuressPin = useCallback(async () => {
    const result = await safeInvoke<AppLockStatus>("applock_clear_duress_pin");
    setStatus(result);
    return result;
  }, []);

  const biometricStatus = useCallback(() => safeInvoke<BiometricStatus>("applock_biometric_status"), []);

  const enableBiometric = useCallback(async () => {
    const result = await safeInvoke<BiometricStatus>("applock_biometric_enable");
    await refresh();
    return result;
  }, [refresh]);

  const disableBiometric = useCallback(async () => {
    const result = await safeInvoke<BiometricStatus>("applock_biometric_disable");
    await refresh();
    return result;
  }, [refresh]);

  const lock = useCallback(async () => {
    if (!enabled) return;
    await safeInvoke("applock_lock", undefined, null);
    setStatus((s) => (s ? { ...s, locked: true } : s));
  }, [enabled]);

  const changePin = useCallback(async (oldPin: string, newPin: string, digits: number, newMethod?: AppLockMethod) => {
    try {
      const result = await safeInvoke<AppLockStatus>("applock_change_pin", { oldPin, newPin, digits, newMethod: newMethod ?? null });
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
    async (digits: number, pin: string, session: StoredSession, deviceName: string, appVersion: string, method: AppLockMethod = "pin") => {
      const result = await safeInvoke<AppLockStatus>("applock_reset", { digits, pin, session, deviceName, appVersion, method });
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
      // Never lock out from under a live call. The call overlay shows only
      // call media -- no message history -- so leaving the app unlocked for its
      // duration exposes nothing the lock protects, whereas locking mid-call
      // unmounts the overlay and drops the call.
      if (isCallActive()) return;
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

    // A call that ends while the app is still in the background must not leave
    // it unlocked: re-apply the policy the moment the guard is released.
    const stopWatchingCalls = onCallActivityChange((active) => {
      if (active) return;
      if (document.visibilityState === "hidden") lockNow();
      else resetInactivity();
    });

    document.addEventListener("visibilitychange", onVisibility);
    ["mousedown", "keydown", "touchstart", "wheel"].forEach((e) =>
      window.addEventListener(e, onActivity, { passive: true }),
    );
    resetInactivity();
    // Belt-and-suspenders: expose a global the native Android layer can call
    // from onStop() when the app is backgrounded (best-effort backstop; the
    // visibilitychange listener above is the primary trigger).
    (window as unknown as { __qguardAppLock?: () => void }).__qguardAppLock = () => lockNow();
    return () => {
      stopWatchingCalls();
      document.removeEventListener("visibilitychange", onVisibility);
      ["mousedown", "keydown", "touchstart", "wheel"].forEach((e) => window.removeEventListener(e, onActivity));
      if (inactivityTimerRef.current !== undefined) window.clearTimeout(inactivityTimerRef.current);
      delete (window as unknown as { __qguardAppLock?: () => void }).__qguardAppLock;
    };
  }, [enabled, unlocked, inactivityMinutes, lock]);

  return {
    status, loading, enabled, refresh, setup, unlock, unlockWithBiometric, lock, changePin, remove, reset, setInactivity,
    setDuressPin, clearDuressPin, biometricStatus, enableBiometric, disableBiometric,
  };
}
