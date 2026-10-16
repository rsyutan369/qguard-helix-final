import { describe, expect, it } from "vitest";
import { sha3_256Hex } from "./sha3";

describe("sha3_256Hex", () => {
  // FIPS 202 example values — the same vectors the Rust core self-tests against.
  it("matches the published test vectors", () => {
    expect(sha3_256Hex("abc")).toBe("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    expect(sha3_256Hex("")).toBe("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
  });

  it("hashes text and its bytes identically", () => {
    const bytes = new TextEncoder().encode("qguard");
    expect(sha3_256Hex(bytes)).toBe(sha3_256Hex("qguard"));
    expect(sha3_256Hex(bytes.buffer as ArrayBuffer)).toBe(sha3_256Hex("qguard"));
  });
});
