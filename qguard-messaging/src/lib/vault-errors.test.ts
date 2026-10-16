import { describe, expect, it, vi } from "vitest";
import {
  classifyVaultOpenError,
  describeVaultOpenError,
  FOREIGN_VAULT_MARKER,
  UNRECOGNIZED_SIGNER_MARKER,
  VaultConsentDeclinedError,
  withLegacySignerConsent,
} from "./vault-errors";

// Exactly what the Rust core serialises: `QGuardError::Trust` renders as
// "trust error: <message>", and the message starts with the marker.
const foreign = `trust error: ${FOREIGN_VAULT_MARKER}: this container was not sealed by the vault that is unlocked on this device. Open it with your recovery key instead.`;
const unrecognized = `trust error: ${UNRECOGNIZED_SIGNER_MARKER}: this older vault container was signed by a key this device does not recognise.`;

describe("vault open-failure classification", () => {
  it("tells the two authentication refusals apart from an ordinary failure", () => {
    expect(classifyVaultOpenError(foreign)).toBe("foreign_vault");
    expect(classifyVaultOpenError(new Error(unrecognized))).toBe("unrecognized_signer");
    expect(classifyVaultOpenError("crypto error: AEAD authentication failed")).toBe("other");
    expect(classifyVaultOpenError({ message: foreign })).toBe("foreign_vault");
    expect(classifyVaultOpenError(null)).toBe("other");
  });

  it("shows the backend's explanation without the marker, and invents nothing", () => {
    expect(describeVaultOpenError(foreign)).toBe(
      "this container was not sealed by the vault that is unlocked on this device. Open it with your recovery key instead.",
    );
    expect(describeVaultOpenError(unrecognized)).not.toContain(UNRECOGNIZED_SIGNER_MARKER);
    // No marker -> returned unchanged.
    expect(describeVaultOpenError("crypto error: AEAD authentication failed")).toBe(
      "crypto error: AEAD authentication failed",
    );
  });
});

describe("withLegacySignerConsent", () => {
  it("never asks, and never sets the override, when the first attempt succeeds", async () => {
    const run = vi.fn(async (allow: boolean) => (allow ? "overridden" : "clean"));
    const ask = vi.fn(async () => true);
    await expect(withLegacySignerConsent(run, ask)).resolves.toBe("clean");
    expect(run).toHaveBeenCalledTimes(1);
    expect(run).toHaveBeenCalledWith(false);
    expect(ask).not.toHaveBeenCalled();
  });

  it("retries with the override only after the user consents", async () => {
    const run = vi.fn(async (allow: boolean) => {
      if (!allow) throw new Error(unrecognized);
      return "opened";
    });
    const ask = vi.fn(async () => true);
    await expect(withLegacySignerConsent(run, ask)).resolves.toBe("opened");
    expect(ask).toHaveBeenCalledTimes(1);
    expect(run.mock.calls.map(([allow]) => allow)).toEqual([false, true]);
  });

  it("does not retry when the user declines", async () => {
    const run = vi.fn(async (allow: boolean) => {
      if (!allow) throw new Error(unrecognized);
      return "opened";
    });
    const ask = vi.fn(async () => false);
    await expect(withLegacySignerConsent(run, ask)).rejects.toBeInstanceOf(VaultConsentDeclinedError);
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("offers no override for a foreign vault key or any other failure", async () => {
    for (const message of [foreign, "crypto error: AEAD authentication failed"]) {
      const run = vi.fn(async () => {
        throw new Error(message);
      });
      const ask = vi.fn(async () => true);
      await expect(withLegacySignerConsent(run, ask)).rejects.toThrow(message);
      expect(ask).not.toHaveBeenCalled();
      expect(run).toHaveBeenCalledTimes(1);
    }
  });
});
