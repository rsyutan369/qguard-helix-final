import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

// `invokeWithTimeout` delegates to `safeInvoke`, which requires the Tauri
// runtime. Stub the Tauri core so these tests exercise the timeout logic only.
const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

import { invokeWithTimeout } from "./tauri";

describe("invokeWithTimeout", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    // safeInvoke short-circuits unless it believes it is inside Tauri.
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
  });

  afterEach(() => {
    delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
  });

  it("returns the command result when it resolves before the deadline", async () => {
    invokeMock.mockResolvedValue({ plaintext: "hello" });
    await expect(invokeWithTimeout("messaging_receive_encrypted_message", {}, 1_000)).resolves.toEqual({
      plaintext: "hello",
    });
  });

  it("rejects once the deadline passes so a stalled command cannot hang the caller", async () => {
    // A command that never settles is exactly the failure this guards: an
    // un-timed await left the Secure Chat history load's `finally` unreachable,
    // pinning the thread on "Loading encrypted history..." forever.
    invokeMock.mockReturnValue(new Promise(() => {}));
    await expect(invokeWithTimeout("messaging_receive_encrypted_message", {}, 20)).rejects.toThrow(
      /timed out/i,
    );
  });

  it("propagates a genuine command failure rather than masking it as a timeout", async () => {
    invokeMock.mockRejectedValue(new Error("local one-time prekey not found"));
    await expect(invokeWithTimeout("messaging_receive_encrypted_message", {}, 1_000)).rejects.toThrow(
      "local one-time prekey not found",
    );
  });
});
