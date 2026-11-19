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
  const state: {
    android: boolean;
    listener: ((event: string, session: unknown) => void) | null;
  } = { android: false, listener: null };
  const auth = {
    getSession: vi.fn(),
    getUser: vi.fn(),
    setSession: vi.fn(),
    onAuthStateChange: vi.fn((callback: (event: string, session: unknown) => void) => {
      state.listener = callback;
      return { data: { subscription: { unsubscribe: vi.fn() } } };
    }),
    signInWithPassword: vi.fn(),
    signOut: vi.fn(async () => ({ error: null })),
    mfa: {
      getAuthenticatorAssuranceLevel: vi.fn(),
      listFactors: vi.fn(),
      challenge: vi.fn(),
      verify: vi.fn(),
    },
  };
  const client = { auth, rpc: vi.fn(async () => ({ data: true, error: null })) };
  return { session, state, auth, client, safeInvoke: vi.fn() };
});

vi.mock("@/lib/supabase", () => ({
  supabase: mocks.client,
  requireSupabase: () => mocks.client,
  isSupabaseConfigured: true,
  getSupabaseConfigError: () => null,
}));
vi.mock("@/lib/tauri", () => ({
  isTauriRuntime: () => true,
  isAndroidRuntime: () => mocks.state.android,
  safeInvoke: mocks.safeInvoke,
}));
vi.mock("@/lib/core-crypto", () => ({ coreSha3Hex: async () => "hash" }));
vi.mock("@/lib/chat-plaintext-cache", () => ({ clearChatPlaintextCaches: vi.fn() }));

import { AuthProvider, isTransientAuthError, useAuth, type OfflineSessionInfo } from "./auth-context";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const OFFLINE: OfflineSessionInfo = {
  userId: "user-1",
  email: "person@example.test",
  offlineUntil: Math.floor(Date.now() / 1000) + 30 * 24 * 3600,
  entitlement: { user_id: "user-1", status: "active", plan: "pro" },
};
const STORED = {
  accessToken: "stored.access.token",
  refreshToken: "stored-refresh",
  expiresAt: 0,
  userId: "user-1",
  email: "person@example.test",
};

function unreachable() {
  return Object.assign(new Error("Failed to fetch"), { name: "AuthRetryableFetchError", status: 0 });
}

let current: ReturnType<typeof useAuth>;
let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
let nativeOffline: () => Promise<OfflineSessionInfo>;

function Probe(): ReactNode {
  current = useAuth();
  return null;
}

async function settle() {
  await new Promise((resolve) => setTimeout(resolve, 5));
}

function invoked(command: string) {
  return mocks.safeInvoke.mock.calls.filter(([name]) => name === command);
}

async function mount() {
  host = document.createElement("div");
  root = createRoot(host);
  await act(async () => root.render(createElement(AuthProvider, null, createElement(Probe))));
}

beforeEach(async () => {
  mocks.state.android = false;
  mocks.state.listener = null;
  nativeOffline = async () => OFFLINE;
  mocks.auth.getSession.mockReset().mockResolvedValue({ data: { session: null }, error: null });
  mocks.auth.getUser.mockReset().mockResolvedValue({ data: { user: mocks.session.user }, error: null });
  mocks.auth.setSession.mockReset();
  mocks.auth.signOut.mockClear();
  mocks.auth.signInWithPassword.mockReset().mockResolvedValue({ data: { session: mocks.session }, error: null });
  mocks.auth.mfa.getAuthenticatorAssuranceLevel.mockReset()
    .mockResolvedValue({ data: { currentLevel: "aal1", nextLevel: "aal1" }, error: null });
  mocks.safeInvoke.mockReset().mockImplementation(async (command: string) => {
    if (command === "offline_sign_in" || command === "offline_resume_unlocked") return nativeOffline();
    return null;
  });
  await mount();
});

afterEach(async () => {
  await act(async () => root.unmount());
});

describe("desktop offline sign-in", () => {
  it("enrolls this device after an online password sign-in, without touching the online session", async () => {
    let result: boolean | undefined;
    await act(async () => { result = await current.signIn("Person@Example.test", "correct horse"); });
    expect(result).toBe(true);
    expect(current.session?.access_token).toBe(mocks.session.access_token);
    expect(current.offline).toBeNull();
    expect(invoked("offline_enroll_password")).toEqual([["offline_enroll_password", { userId: "user-1", password: "correct horse" }]]);
    expect(invoked("offline_sign_in")).toHaveLength(0);
  });

  it("signs in offline for Mesh and XFER when the sign-in service cannot be reached", async () => {
    mocks.auth.signInWithPassword.mockResolvedValue({ data: { session: null }, error: unreachable() });
    let result: boolean | undefined;
    await act(async () => { result = await current.signIn("Person@Example.test", "correct horse"); });
    expect(result).toBe(true);
    expect(invoked("offline_sign_in")).toEqual([["offline_sign_in", { email: "person@example.test", password: "correct horse" }]]);
    expect(current.offline).toEqual(OFFLINE);
    expect(current.user?.id).toBe("user-1");
    // No online session exists, so no online service can run.
    expect(current.session).toBeNull();
    expect(current.error).toBeNull();
    expect(invoked("offline_enroll_password")).toHaveLength(0);
  });

  it("shows the native reason when offline sign-in is refused", async () => {
    mocks.auth.signInWithPassword.mockResolvedValue({ data: { session: null }, error: unreachable() });
    nativeOffline = async () => {
      throw new Error("Incorrect password. 4 offline attempts left before offline sign-in locks.");
    };
    let result: boolean | undefined;
    await act(async () => { result = await current.signIn("person@example.test", "wrong"); });
    expect(result).toBe(false);
    expect(current.offline).toBeNull();
    expect(current.user).toBeNull();
    expect(current.error).toContain("Couldn't reach the secure sign-in service");
    expect(current.error).toContain("4 offline attempts left");
  });

  it("never falls back to offline when the server answered", async () => {
    mocks.auth.signInWithPassword.mockResolvedValue({
      data: { session: null },
      error: Object.assign(new Error("Invalid login credentials"), { name: "AuthApiError", status: 400 }),
    });
    await act(async () => { await current.signIn("person@example.test", "wrong"); });
    expect(invoked("offline_sign_in")).toHaveLength(0);
    expect(current.offline).toBeNull();
    expect(current.error).toBe("Invalid login credentials");
  });

  it("enrolls only once the second factor completes an MFA sign-in", async () => {
    mocks.auth.mfa.getAuthenticatorAssuranceLevel.mockResolvedValue({ data: { currentLevel: "aal1", nextLevel: "aal2" }, error: null });
    mocks.auth.mfa.listFactors.mockResolvedValue({ data: { totp: [{ id: "factor-1", friendly_name: "Phone" }] }, error: null });
    mocks.auth.mfa.challenge.mockResolvedValue({ data: { id: "challenge-1" }, error: null });
    mocks.auth.mfa.verify.mockResolvedValue({ error: null });
    await act(async () => { await current.signIn("person@example.test", "correct horse"); });
    expect(current.pendingMfa?.factorId).toBe("factor-1");
    expect(invoked("offline_enroll_password")).toHaveLength(0);

    mocks.auth.getSession.mockResolvedValue({ data: { session: mocks.session }, error: null });
    await act(async () => { await current.verifyMfaSignIn("123456"); });
    expect(current.session?.user.id).toBe("user-1");
    expect(invoked("offline_enroll_password")).toEqual([["offline_enroll_password", { userId: "user-1", password: "correct horse" }]]);
  });

  it("leaves offline mode natively before the online sign-in screen", async () => {
    mocks.auth.signInWithPassword.mockResolvedValue({ data: { session: null }, error: unreachable() });
    await act(async () => { await current.signIn("person@example.test", "correct horse"); });
    await act(async () => { await current.exitOffline(); });
    expect(invoked("offline_sign_out")).toHaveLength(1);
    expect(current.offline).toBeNull();
    expect(current.user).toBeNull();
  });

  it("returns online when this window still holds a valid session for the same account", async () => {
    mocks.auth.signInWithPassword.mockResolvedValue({ data: { session: null }, error: unreachable() });
    await act(async () => { await current.signIn("person@example.test", "correct horse"); });
    mocks.auth.getSession.mockResolvedValue({ data: { session: mocks.session }, error: null });
    let online: boolean | undefined;
    await act(async () => { online = await current.reconnectOnline(); });
    expect(online).toBe(true);
    expect(current.offline).toBeNull();
    expect(current.session?.user.id).toBe("user-1");
  });

  it("keeps the offline user when the auth listener reports no session", async () => {
    mocks.auth.signInWithPassword.mockResolvedValue({ data: { session: null }, error: unreachable() });
    await act(async () => { await current.signIn("person@example.test", "correct horse"); });
    await act(async () => { mocks.state.listener?.("SIGNED_OUT", null); await settle(); });
    expect(current.user?.id).toBe("user-1");
    expect(current.offline).not.toBeNull();
  });

  it("signing out ends offline mode and the native session", async () => {
    mocks.auth.signInWithPassword.mockResolvedValue({ data: { session: null }, error: unreachable() });
    await act(async () => { await current.signIn("person@example.test", "correct horse"); });
    await act(async () => { await current.signOut(); });
    expect(invoked("offline_sign_out")).toHaveLength(1);
    expect(invoked("auth_logout")).toEqual([["auth_logout", { userId: "user-1" }, false]]);
    expect(current.offline).toBeNull();
    expect(current.user).toBeNull();
  });
});

describe("Android offline resume", () => {
  beforeEach(async () => {
    await act(async () => root.unmount());
    mocks.state.android = true;
    await mount();
  });

  it("never offers a password offline sign-in and never stores a password verifier", async () => {
    await act(async () => { await current.signIn("person@example.test", "correct horse"); });
    expect(invoked("offline_enroll_password")).toHaveLength(0);
    mocks.auth.signInWithPassword.mockResolvedValue({ data: { session: null }, error: unreachable() });
    await act(async () => { await current.signIn("person@example.test", "correct horse"); });
    expect(invoked("offline_sign_in")).toHaveLength(0);
  });

  it("resumes offline after an unlock, then returns online by itself when the network is back", async () => {
    await act(async () => { await current.resumeOfflineAfterUnlock(STORED); });
    expect(invoked("offline_resume_unlocked")).toEqual([["offline_resume_unlocked", { userId: "user-1" }]]);
    expect(current.offline?.userId).toBe("user-1");
    expect(current.session).toBeNull();

    mocks.auth.setSession.mockResolvedValue({ data: { session: mocks.session }, error: null });
    await act(async () => { window.dispatchEvent(new Event("online")); await settle(); });
    expect(mocks.auth.setSession).toHaveBeenCalledWith({ access_token: STORED.accessToken, refresh_token: STORED.refreshToken });

    // Supabase reports the restored session; the app completes it online.
    await act(async () => { mocks.state.listener?.("SIGNED_IN", mocks.session); await settle(); });
    expect(current.offline).toBeNull();
    expect(current.session?.access_token).toBe(mocks.session.access_token);
    expect(invoked("applock_update_session")).toHaveLength(1);
  });

  it("stays offline while the network is still down", async () => {
    await act(async () => { await current.resumeOfflineAfterUnlock(STORED); });
    mocks.auth.setSession.mockResolvedValue({ data: { session: null }, error: unreachable() });
    let online: boolean | undefined;
    await act(async () => { online = await current.reconnectOnline(); });
    expect(online).toBe(false);
    expect(current.offline?.userId).toBe("user-1");
    expect(current.error).toBeNull();
  });

  it("asks for a full sign-in when the server rejects the stored session", async () => {
    await act(async () => { await current.resumeOfflineAfterUnlock(STORED); });
    mocks.auth.setSession.mockResolvedValue({
      data: { session: null },
      error: Object.assign(new Error("Invalid Refresh Token: Refresh Token Not Found"), { name: "AuthApiError", status: 400 }),
    });
    await act(async () => { await current.reconnectOnline(); });
    expect(current.offline).toBeNull();
    expect(current.user).toBeNull();
    expect(current.error).toContain("sign in again");
    expect(invoked("offline_sign_out")).toHaveLength(1);
  });

  it("rejects with the native reason when this device has no offline access", async () => {
    nativeOffline = async () => {
      throw new Error("Offline access on this device expired. Connect to the internet and sign in to renew it.");
    };
    await act(async () => {
      await expect(current.resumeOfflineAfterUnlock(STORED)).rejects.toThrow("expired");
    });
    expect(current.offline).toBeNull();
  });
});

describe("isTransientAuthError", () => {
  it("treats only unreachable-server failures as transient", () => {
    expect(isTransientAuthError(unreachable())).toBe(true);
    expect(isTransientAuthError({ name: "AuthRetryableFetchError", message: "", status: 503 })).toBe(true);
    expect(isTransientAuthError(new TypeError("Failed to fetch"))).toBe(true);
    expect(isTransientAuthError(new Error("Invalid login credentials"))).toBe(false);
    expect(isTransientAuthError({ name: "AuthApiError", message: "Invalid Refresh Token" })).toBe(false);
  });
});
