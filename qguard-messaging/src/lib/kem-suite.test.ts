import { describe, expect, it } from "vitest";
import { describeKemIncompatibility, kemInteroperates } from "./kem-suite";

const fipsSuite = {
  classical_kex: "X25519",
  pq_kem: "ML-KEM-1024",
  kdf: "HKDF-SHA3-256",
  symmetric: "AES-256-GCM",
  classical_signature: "Ed25519",
  pq_signature: "ML-DSA-65",
  pq_kem_standard: "FIPS-203",
};

describe("kemInteroperates", () => {
  it("accepts a device registered by the FIPS 203 build", () => {
    expect(kemInteroperates(fipsSuite)).toBe(true);
    expect(describeKemIncompatibility(fipsSuite)).toBeNull();
  });

  it("rejects a pre-cutover device even though it advertises ML-KEM-1024", () => {
    // This is the exact row a pre-FIPS build wrote: the label is right, the key
    // lengths are right, the signatures verify — and it holds Kyber-1024.
    const { pq_kem_standard: _omitted, ...preFips } = fipsSuite;
    expect(preFips.pq_kem).toBe("ML-KEM-1024");
    expect(kemInteroperates(preFips)).toBe(false);
    expect(describeKemIncompatibility(preFips)).toContain("pre-FIPS-203");
  });

  it("rejects a missing or empty suite rather than assuming the best", () => {
    expect(kemInteroperates(null)).toBe(false);
    expect(kemInteroperates(undefined)).toBe(false);
    expect(kemInteroperates({})).toBe(false);
  });

  it("rejects a mismatched parameter set", () => {
    expect(kemInteroperates({ ...fipsSuite, pq_kem: "ML-KEM-768" })).toBe(false);
  });
});
