import { describe, expect, it } from "vitest";
import { callPeerIdentityFromRow } from "@/lib/call-peer-identity";
import { callSecurityNeedsAttention, describeCallSecurity } from "@/lib/call-security";
import { callReducer, INITIAL_CALL_STATE, type CallState } from "@/lib/call-state";
import { callPeerIdentityPayload, parseCallEphemeralKey } from "@/lib/call-targets";
import { bytesToBytea } from "@/lib/encoding";

function connected(
  role: "caller" | "callee",
  flags: { forwardSecret?: boolean; peerVerified?: boolean; peerVerifiedAt?: number | null; peerPaired?: boolean },
): CallState {
  const started = role === "caller"
    ? callReducer(INITIAL_CALL_STATE, { type: "start-outgoing", callId: "c1", peerUserId: "u2", peerDeviceId: "d2" })
    : callReducer(INITIAL_CALL_STATE, { type: "incoming", callId: "c1", peerUserId: "u2", peerDeviceId: "d2" });
  return callReducer(started, { type: "media-connected", safetyNumber: "0001-0002-0003-0004-0005", ...flags });
}

describe("call security reporting", () => {
  it("says nothing before the call has connected", () => {
    expect(describeCallSecurity(INITIAL_CALL_STATE, "Ana")).toEqual([]);
    const ringing = callReducer(INITIAL_CALL_STATE, { type: "incoming", callId: "c1", peerUserId: "u2", peerDeviceId: "d2" });
    expect(describeCallSecurity(ringing, "Ana")).toEqual([]);
  });

  it("treats flags the core did not report as not established", () => {
    const state = connected("callee", {});
    expect(state.forwardSecret).toBe(false);
    expect(state.peerVerified).toBe(false);
    const lines = describeCallSecurity(state, "Ana");
    expect(lines.every((line) => !line.ok)).toBe(true);
    expect(callSecurityNeedsAttention(lines)).toBe(true);
  });

  it("reports a forward-secret call from a device the user verified, without warnings", () => {
    const lines = describeCallSecurity(
      connected("callee", { forwardSecret: true, peerVerified: true, peerVerifiedAt: 1_790_000_000, peerPaired: true }),
      "Ana",
    );
    expect(lines).toHaveLength(3);
    expect(callSecurityNeedsAttention(lines)).toBe(false);
    expect(lines[0].text).toContain("Forward secret");
    expect(lines[1].text).toContain("Caller verified");
    expect(lines[2].text).toContain("You verified Ana's device on");
    expect(lines[2].text).toContain("Ask them for their phrase");
  });

  it("a registered device is not a verified person: warns until the user verifies them", () => {
    const lines = describeCallSecurity(connected("callee", { forwardSecret: true, peerVerified: true }), "Ana");
    expect(lines).toHaveLength(3);
    expect(lines[2]).toMatchObject({ ok: false });
    expect(lines[2].text).toContain("haven't verified Ana");
    expect(lines[2].text).toContain("cloned voice");
    expect(callSecurityNeedsAttention(lines)).toBe(true);
  });

  it("verified but not yet paired: no phrase is promised", () => {
    const lines = describeCallSecurity(
      connected("caller", { forwardSecret: true, peerVerified: true, peerVerifiedAt: 1_790_000_000, peerPaired: false }),
      "Ana",
    );
    expect(lines[2]).toMatchObject({ ok: true });
    expect(lines[2].text).toContain("becomes available once");
    expect(lines[2].text).not.toContain("Ask them for their phrase");
  });

  it("never vouches for the person on an unproven device, whatever the record says (negative control)", () => {
    const lines = describeCallSecurity(
      connected("callee", { forwardSecret: true, peerVerified: false, peerVerifiedAt: 1_790_000_000, peerPaired: true }),
      "Ana",
    );
    expect(lines).toHaveLength(2);
    expect(lines.some((line) => line.text.includes("You verified"))).toBe(false);
  });

  it("warns when the peer's build has no per-call key", () => {
    const lines = describeCallSecurity(connected("caller", { forwardSecret: false, peerVerified: true }), "Ana");
    expect(lines[0]).toMatchObject({ ok: false });
    expect(lines[0].text).toContain("Not forward secret");
    expect(lines[0].text).toContain("Ana");
    expect(lines[1]).toMatchObject({ ok: true });
    expect(callSecurityNeedsAttention(lines)).toBe(true);
  });

  it("warns the callee when the caller could not be verified", () => {
    const lines = describeCallSecurity(connected("callee", { forwardSecret: true, peerVerified: false }), "Ana");
    expect(lines[0]).toMatchObject({ ok: true });
    expect(lines[1]).toMatchObject({ ok: false });
    expect(lines[1].text).toContain("Caller not verified");
  });

  it("clears the flags when a new call starts", () => {
    const ended = callReducer(connected("caller", { forwardSecret: true, peerVerified: true }), { type: "ended" });
    const next = callReducer(ended, { type: "incoming", callId: "c2", peerUserId: "u3", peerDeviceId: "d3" });
    expect(next.forwardSecret).toBeNull();
    expect(next.peerVerified).toBeNull();
    expect(next.safetyNumber).toBeNull();
  });
});

describe("parseCallEphemeralKey", () => {
  const good = {
    x25519Public: Array.from({ length: 32 }, (_unused, index) => index),
    mlkemPublic: Array.from({ length: 1568 }, (_unused, index) => index & 0xff),
    signature: { ed25519: Array.from({ length: 64 }, () => 7), ml_dsa_65: Array.from({ length: 3309 }, () => 9) },
  };

  it("accepts a well-formed key", () => {
    expect(parseCallEphemeralKey(good)).toEqual(good);
  });

  it("returns null for an accept from a build without per-call keys", () => {
    expect(parseCallEphemeralKey(undefined)).toBeNull();
    expect(parseCallEphemeralKey(null)).toBeNull();
    expect(parseCallEphemeralKey({})).toBeNull();
  });

  it("rejects anything that does not have the shape of a key", () => {
    expect(parseCallEphemeralKey({ ...good, x25519Public: good.x25519Public.slice(1) })).toBeNull();
    // ML-KEM-768 length: not a key this build encapsulates to.
    expect(parseCallEphemeralKey({ ...good, mlkemPublic: good.mlkemPublic.slice(0, 1184) })).toBeNull();
    expect(parseCallEphemeralKey({ ...good, signature: { ed25519: [], ml_dsa_65: good.signature.ml_dsa_65 } })).toBeNull();
    expect(parseCallEphemeralKey({ ...good, signature: null })).toBeNull();
    expect(parseCallEphemeralKey({ ...good, x25519Public: [...good.x25519Public.slice(1), 256] })).toBeNull();
    expect(parseCallEphemeralKey({ ...good, x25519Public: [...good.x25519Public.slice(1), "1"] })).toBeNull();
    expect(parseCallEphemeralKey([good])).toBeNull();
    expect(parseCallEphemeralKey("key")).toBeNull();
  });

  it("drops unknown fields rather than passing them to the core", () => {
    const parsed = parseCallEphemeralKey({ ...good, extra: "x", signature: { ...good.signature, other: [1] } });
    expect(parsed).toEqual(good);
  });
});

describe("call peer identity payloads", () => {
  const device = {
    deviceId: "device-1",
    x25519: [1, 2, 3],
    mlkem: [4, 5],
    ed25519: [6],
    mldsa: [7, 8],
    identitySignature: { ed25519: [9], ml_dsa_65: [10] },
  };

  it("maps an outgoing-call device to the core's argument shape", () => {
    expect(callPeerIdentityPayload("user-1", device)).toEqual({
      user_id: "user-1",
      device_id: "device-1",
      x25519_identity_public: [1, 2, 3],
      mlkem_identity_public: [4, 5],
      ed25519_identity_public: [6],
      mldsa_identity_public: [7, 8],
      identity_signature: { ed25519: [9], ml_dsa_65: [10] },
    });
  });

  it("reads a caller's registry row", () => {
    const row = {
      id: "device-9",
      user_id: "user-9",
      x25519_identity_public: bytesToBytea([1, 2]),
      mlkem_identity_public: bytesToBytea([3]),
      ed25519_identity_public: bytesToBytea([4]),
      mldsa_identity_public: bytesToBytea([5]),
      identity_signature: { ed25519: [6], ml_dsa_65: [7] },
    };
    expect(callPeerIdentityFromRow(row)).toEqual({
      user_id: "user-9",
      device_id: "device-9",
      x25519_identity_public: [1, 2],
      mlkem_identity_public: [3],
      ed25519_identity_public: [4],
      mldsa_identity_public: [5],
      identity_signature: { ed25519: [6], ml_dsa_65: [7] },
    });
  });

  it("yields no identity for a row that could not anchor a signature", () => {
    const base = {
      id: "device-9",
      user_id: "user-9",
      x25519_identity_public: bytesToBytea([1]),
      mlkem_identity_public: bytesToBytea([3]),
      ed25519_identity_public: bytesToBytea([4]),
      mldsa_identity_public: bytesToBytea([5]),
      identity_signature: { ed25519: [6], ml_dsa_65: [7] },
    };
    expect(callPeerIdentityFromRow({ ...base, identity_signature: null })).toBeNull();
    expect(callPeerIdentityFromRow({ ...base, identity_signature: { ed25519: [6] } })).toBeNull();
    expect(callPeerIdentityFromRow({ ...base, mldsa_identity_public: null })).toBeNull();
    expect(callPeerIdentityFromRow({ ...base, user_id: null })).toBeNull();
  });
});
