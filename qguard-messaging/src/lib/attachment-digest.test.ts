import { describe, expect, it } from "vitest";
import { attachmentDigestMatches, attachmentDigests, sha3Base64 } from "@/lib/attachment-digest";

const bytes = (text: string) => new TextEncoder().encode(text);

describe("attachment ciphertext digests", () => {
  it("SHA3-256 matches the FIPS 202 test vector", () => {
    // SHA3-256("abc") = 3a985da7…431532
    const expected = btoa(String.fromCharCode(...[
      0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
      0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
    ]));
    expect(sha3Base64(bytes("abc"))).toBe(expected);
  });

  it("a new attachment carries both digests and checks against SHA3", async () => {
    const ciphertext = bytes("ciphertext");
    const digests = await attachmentDigests(ciphertext);
    expect(digests.sha3_b64).toBeTruthy();
    expect(digests.sha256_b64).toBeTruthy();
    expect(await attachmentDigestMatches(ciphertext, digests)).toBe(true);
    expect(await attachmentDigestMatches(bytes("tampered!!"), digests)).toBe(false);
  });

  it("SHA3 decides when present: a matching SHA-256 cannot override a wrong SHA3 (negative control)", async () => {
    const ciphertext = bytes("ciphertext");
    const { sha256_b64 } = await attachmentDigests(ciphertext);
    expect(await attachmentDigestMatches(ciphertext, { sha3_b64: sha3Base64(bytes("other")), sha256_b64 })).toBe(false);
  });

  it("an attachment sent before the change is still checked with SHA-256", async () => {
    const ciphertext = bytes("legacy");
    const { sha256_b64 } = await attachmentDigests(ciphertext);
    expect(await attachmentDigestMatches(ciphertext, { sha256_b64 })).toBe(true);
    expect(await attachmentDigestMatches(bytes("legacy!"), { sha256_b64 })).toBe(false);
    expect(await attachmentDigestMatches(ciphertext, {})).toBe(false);
  });
});
