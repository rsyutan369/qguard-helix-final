import { describe, expect, it } from "vitest";
import { applyDecline, buildCallPeer, GROUP_CALL_SIZE, groupCallBlockedReason, isCallableDevice, type CallCandidateDevice } from "@/lib/call-targets";

function device(id: string, overrides: Partial<CallCandidateDevice> = {}): CallCandidateDevice {
  return {
    user_id: "peer-user",
    device_id: id,
    x25519_identity_public: [1, 2, 3],
    mlkem_identity_public: [4, 5, 6],
    ed25519_identity_public: [7, 8, 9],
    mldsa_identity_public: [10, 11, 12],
    identity_signature: { ed25519: [13], ml_dsa_65: [14] },
    ...overrides,
  };
}

describe("buildCallPeer", () => {
  it("rings EVERY sendable device, not just the most-recently-seen one", () => {
    // The regression: a peer signed in on desktop AND android. Addressing the
    // ring to devices[0] alone meant the other device never rang, the call sat
    // on "Connecting…" until the give-up, and no safety number was ever derived.
    const peer = buildCallPeer([device("desktop-1"), device("android-1")], "M. Oduya");
    expect(peer).not.toBeNull();
    expect(peer!.devices.map((d) => d.deviceId)).toEqual(["desktop-1", "android-1"]);
  });

  it("preserves candidate order so the likeliest device is still tried first", () => {
    const peer = buildCallPeer([device("android-1"), device("desktop-1")], "M. Oduya");
    expect(peer!.devices.map((d) => d.deviceId)).toEqual(["android-1", "desktop-1"]);
  });

  it("carries each device's own identity material for per-device encapsulation", () => {
    const peer = buildCallPeer(
      [
        device("desktop-1", { mlkem_identity_public: [91] }),
        device("android-1", { mlkem_identity_public: [92] }),
      ],
      "M. Oduya",
    );
    expect(peer!.devices[0].mlkem).toEqual([91]);
    expect(peer!.devices[1].mlkem).toEqual([92]);
  });

  it("converts Uint8Array key material to plain arrays for the Rust bridge", () => {
    const peer = buildCallPeer(
      [device("d1", { x25519_identity_public: new Uint8Array([5, 6]) })],
      "M. Oduya",
    );
    expect(peer!.devices[0].x25519).toEqual([5, 6]);
    expect(Array.isArray(peer!.devices[0].x25519)).toBe(true);
  });

  it("skips devices with no identity signature — they can never complete a call", () => {
    const peer = buildCallPeer(
      [device("unsigned", { identity_signature: null }), device("signed")],
      "M. Oduya",
    );
    expect(peer!.devices.map((d) => d.deviceId)).toEqual(["signed"]);
  });

  it("skips devices missing PQC key material", () => {
    expect(isCallableDevice(device("d", { mlkem_identity_public: [] }))).toBe(false);
    expect(isCallableDevice(device("d", { mldsa_identity_public: [] }))).toBe(false);
    expect(isCallableDevice(device("d"))).toBe(true);
  });

  it("returns null when nobody is callable, so the UI keeps the button disabled", () => {
    expect(buildCallPeer([], "M. Oduya")).toBeNull();
    expect(buildCallPeer([device("d", { identity_signature: null })], "M. Oduya")).toBeNull();
  });

  it("never rings a third party's devices", () => {
    const peer = buildCallPeer(
      [device("peer-a"), device("other", { user_id: "someone-else" })],
      "M. Oduya",
    );
    expect(peer!.userId).toBe("peer-user");
    expect(peer!.devices.map((d) => d.deviceId)).toEqual(["peer-a"]);
  });
});

describe("applyDecline", () => {
  it("keeps ringing the other devices when one declines", () => {
    const r = applyDecline(["desktop", "android"], "desktop", null);
    expect(r.remaining).toEqual(["android"]);
    expect(r.endCall).toBe(false);
  });

  it("does NOT cancel the call when one device auto-replies busy", () => {
    // The regression this guards: `busy` is sent automatically by any peer
    // device already on another call. Ending the call there made a peer whose
    // desktop was mid-call unreachable on their phone.
    const r = applyDecline(["desktop", "android"], "desktop", null);
    expect(r.endCall).toBe(false);
    expect(r.remaining).toContain("android");
  });

  it("ends the call once the last device declines", () => {
    const r = applyDecline(["android"], "android", null);
    expect(r.remaining).toEqual([]);
    expect(r.endCall).toBe(true);
  });

  it("after a device answers, only that device can end the call", () => {
    expect(applyDecline(["android"], "android", "android").endCall).toBe(true);
    expect(applyDecline(["android"], "desktop", "android").endCall).toBe(false);
  });

  it("ignores a decline from a device that was never rung", () => {
    const r = applyDecline(["desktop", "android"], "someone-else", null);
    expect(r.remaining).toEqual(["desktop", "android"]);
    expect(r.endCall).toBe(false);
  });
});

describe("groupCallBlockedReason", () => {
  const ready = { supported: true, memberCount: GROUP_CALL_SIZE, peersReady: true, busy: false };

  it("lets a ready group of three start a call", () => {
    expect(groupCallBlockedReason(ready)).toBeNull();
  });

  it("names the first thing in the way, in order", () => {
    expect(groupCallBlockedReason({ ...ready, supported: false })).toMatch(/requires/);
    expect(groupCallBlockedReason({ ...ready, memberCount: 4 })).toBe("Group video calls work in groups of 3 people for now");
    expect(groupCallBlockedReason({ ...ready, memberCount: 2 })).toMatch(/groups of 3/);
    expect(groupCallBlockedReason({ ...ready, peersReady: false })).toMatch(/no device that can take calls/);
    expect(groupCallBlockedReason({ ...ready, busy: true })).toBe("Finish the current call first");
    expect(groupCallBlockedReason({ supported: false, memberCount: 5, peersReady: false, busy: true })).toMatch(/requires/);
  });
});
