import { describe, expect, it } from "vitest";
import { hashRecoveryCode, normalizedRecoveryCode, recoveryHashScheme } from "@/lib/recovery-code-hash";
import { sha3_256Hex } from "@/lib/sha3";

describe("MFA recovery code hashing", () => {
  it("normalizes codes exactly as consume_qguard_mfa_recovery_code does", () => {
    expect(normalizedRecoveryCode(" ab12-cd34-ef56 ")).toBe("AB12CD34EF56");
  });

  it("writes SHA3 with its prefix, and SHA-256 in the old bare-hex form", async () => {
    expect(await hashRecoveryCode("aa", "abcd-efgh-jkmn", "sha3-256")).toBe(`sha3:${sha3_256Hex("aaABCDEFGHJKMN")}`);
    const legacy = await hashRecoveryCode("aa", "abcd-efgh-jkmn", "sha256");
    expect(legacy).toMatch(/^[0-9a-f]{64}$/);
    expect(legacy).not.toContain("sha3:");
  });

  it("uses SHA3 only once the server says it can check it", async () => {
    const answering = (data: unknown, error: unknown = null) => ({ rpc: async () => ({ data, error }) });
    expect(await recoveryHashScheme(answering(["sha3-256", "sha256"]) as never)).toBe("sha3-256");
    // Migration 037 not applied: function missing, or an old answer.
    expect(await recoveryHashScheme(answering(null, { message: "function does not exist" }) as never)).toBe("sha256");
    expect(await recoveryHashScheme(answering(["sha256"]) as never)).toBe("sha256");
    expect(await recoveryHashScheme({ rpc: async () => { throw new Error("offline"); } } as never)).toBe("sha256");
  });
});
