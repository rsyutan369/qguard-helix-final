import { describe, expect, it } from "vitest";
import {
  PRIVACY_SCREEN_KDF,
  createChatProtectionConfig,
  parseChatProtectionConfig,
  verifyChatProtectionSecret,
} from "@/lib/privacy-screen";

describe("privacy screen verifier", () => {
  it("outside the app (no core) it still works with the PBKDF2 verifier", async () => {
    const config = await createChatProtectionConfig("hunter22");
    expect(config.kdf).toBeUndefined();
    expect(config.iterations).toBeGreaterThanOrEqual(100_000);
    expect((await verifyChatProtectionSecret("hunter22", config)).ok).toBe(true);
    expect((await verifyChatProtectionSecret("hunter23", config)).ok).toBe(false);
    // No core to upgrade with: nothing is replaced.
    expect((await verifyChatProtectionSecret("hunter22", config)).upgraded).toBeNull();
  });

  it("a core-made verifier never opens without the core (negative control)", async () => {
    const result = await verifyChatProtectionSecret("anything", {
      kdf: PRIVACY_SCREEN_KDF,
      salt_b64: "AAAA",
      verifier_b64: "abc",
      created_at: "2026-10-19T00:00:00Z",
    });
    expect(result.ok).toBe(false);
  });

  it("reads stored configs of both kinds and refuses anything else", () => {
    const legacy = parseChatProtectionConfig(JSON.stringify({ salt_b64: "s", verifier_b64: "v", iterations: 600_000 }));
    expect(legacy?.kdf).toBeUndefined();
    expect(legacy?.iterations).toBe(600_000);
    const current = parseChatProtectionConfig(JSON.stringify({ kdf: PRIVACY_SCREEN_KDF, salt_b64: "s", verifier_b64: "v" }));
    expect(current?.kdf).toBe(PRIVACY_SCREEN_KDF);
    expect(current?.iterations).toBeUndefined();
    // A weak legacy verifier, an unknown KDF, junk and nothing are all refused.
    expect(parseChatProtectionConfig(JSON.stringify({ salt_b64: "s", verifier_b64: "v", iterations: 1000 }))).toBeNull();
    expect(parseChatProtectionConfig(JSON.stringify({ kdf: "md5", salt_b64: "s", verifier_b64: "v" }))).toBeNull();
    expect(parseChatProtectionConfig("{not json")).toBeNull();
    expect(parseChatProtectionConfig(null)).toBeNull();
  });
});
