import { act, createElement, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const session = {
    access_token: "header.payload.signature",
    refresh_token: "refresh",
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    user: { id: "user-1", email: "person@example.test", app_metadata: {}, user_metadata: {} },
  };
  const auth = {
    getSession: vi.fn(),
    getUser: vi.fn(),
    onAuthStateChange: vi.fn(() => ({ data: { subscription: { unsubscribe: vi.fn() } } })),
    signInWithPassword: vi.fn(),
    signOut: vi.fn(async () => ({ error: null })),
    mfa: { getAuthenticatorAssuranceLevel: vi.fn(async () => ({ data: { currentLevel: "aal1", nextLevel: "aal1" }, error: null })) },
  };
  const client = { auth, rpc: vi.fn(async () => ({ data: true, error: null })) };
  return { session, auth, client, safeInvoke: vi.fn() };
});

vi.mock("@/lib/supabase", () => ({
  supabase: mocks.client,
  requireSupabase: () => mocks.client,
  isSupabaseConfigured: true,
  getSupabaseConfigError: () => null,
}));
vi.mock("@/lib/tauri", () => ({ isTauriRuntime: () => true, isAndroidRuntime: () => false, safeInvoke: mocks.safeInvoke }));
vi.mock("@/lib/core-crypto", () => ({ coreSha3Hex: async () => "hash" }));
vi.mock("@/lib/chat-plaintext-cache", () => ({ clearChatPlaintextCaches: vi.fn() }));

import { AuthProvider, RESET_DEVICE_IDENTITY_CONFIRMATION, useAuth } from "./auth-context";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const UNREADABLE = "storage error: DEVICE_KEYS_UNREADABLE: this device already holds encrypted key material for this account, but it could not be opened";
let current: ReturnType<typeof useAuth>;
let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
let keysReadable: boolean;

function Probe(): ReactNode {
  current = useAuth();
  return null;
}

beforeEach(async () => {
  keysReadable = false;
  mocks.auth.getSession.mockResolvedValue({ data: { session: null }, error: null });
  mocks.auth.signInWithPassword.mockResolvedValue({ data: { session: mocks.session }, error: null });
  mocks.safeInvoke.mockReset().mockImplementation(async (command: string) => {
    if (command === "auth_sync_session") {
      if (!keysReadable) throw new Error(UNREADABLE);
      return {};
    }
    if (command === "keys_reset_device_identity") {
      keysReadable = true;
      return { device_id: "new-device", fingerprint: "f" };
    }
    return null;
  });
  host = document.createElement("div");
  root = createRoot(host);
  await act(async () => root.render(createElement(AuthProvider, null, createElement(Probe))));
});

afterEach(async () => {
  await act(async () => root.unmount());
});

describe("sign-in when this device's keys cannot be opened", () => {
  it("holds the session for recovery instead of failing sign-in with an error", async () => {
    let result: boolean | undefined;
    await act(async () => { result = await current.signIn("person@example.test", "password"); });
    expect(result).toBe(false);
    expect(current.user).toBeNull();
    expect(current.error).toBeNull();
    expect(current.deviceKeyRecovery?.account).toBe("person@example.test");
    expect(current.deviceKeyRecovery?.detail).toContain("DEVICE_KEYS_UNREADABLE");
    expect(mocks.safeInvoke).not.toHaveBeenCalledWith("keys_reset_device_identity", expect.anything());
  });

  it("retries without resetting, then completes sign-in after a confirmed reset", async () => {
    await act(async () => { await current.signIn("person@example.test", "password"); });
    mocks.auth.getSession.mockResolvedValue({ data: { session: mocks.session }, error: null });

    await act(async () => { await current.retryDeviceKeys(); });
    expect(current.user).toBeNull();
    expect(current.deviceKeyRecovery?.error).toContain("still could not be opened");
    expect(mocks.safeInvoke).not.toHaveBeenCalledWith("keys_reset_device_identity", expect.anything());

    let reset: boolean | undefined;
    await act(async () => { reset = await current.resetDeviceKeys(RESET_DEVICE_IDENTITY_CONFIRMATION); });
    expect(mocks.safeInvoke).toHaveBeenCalledWith("keys_reset_device_identity", {
      userId: "user-1", confirmation: RESET_DEVICE_IDENTITY_CONFIRMATION,
    });
    expect(reset).toBe(true);
    expect(current.deviceKeyRecovery).toBeNull();
    expect(current.user?.id).toBe("user-1");
  });

  it("signs out cleanly from the recovery screen", async () => {
    await act(async () => { await current.signIn("person@example.test", "password"); });
    await act(async () => { await current.cancelDeviceKeyRecovery(); });
    expect(current.deviceKeyRecovery).toBeNull();
    expect(mocks.auth.signOut).toHaveBeenCalled();
    expect(mocks.safeInvoke).toHaveBeenCalledWith("auth_logout", { userId: "user-1" }, false);
  });

  it("still reports unrelated native sign-in failures as errors", async () => {
    mocks.safeInvoke.mockImplementation(async (command: string) => {
      if (command === "auth_sync_session") throw new Error("Supabase access token is expired");
      return null;
    });
    await act(async () => { await current.signIn("person@example.test", "password"); });
    expect(current.deviceKeyRecovery).toBeNull();
    expect(current.error).toContain("expired");
  });
});
