import { describe, expect, it } from "vitest";
import {
  chunk,
  formatInviteCode,
  normalizeInviteCode,
  planKeyDistribution,
  rowToSealed,
  sealedToRow,
  type ChannelStatus,
  type SealedChannelPost,
} from "./channels";

const ME = "me";
const status = (overrides: Partial<ChannelStatus> = {}): ChannelStatus => ({
  channelId: "c1",
  currentEpoch: "e1",
  currentSeq: 1,
  recipients: [],
  recipientUsers: [],
  epochsHeld: 1,
  ...overrides,
});
const devices = [
  { deviceId: "my-other-device", userId: ME },
  { deviceId: "a1", userId: "a" },
  { deviceId: "a2", userId: "a" },
  { deviceId: "b1", userId: "b" },
];

describe("planKeyDistribution", () => {
  it("makes a first epoch and hands it to every other member device", () => {
    const plan = planKeyDistribution({ status: status({ currentEpoch: null, currentSeq: null }), memberUserIds: [ME, "a", "b"], memberDevices: devices, myUserId: ME });
    expect(plan).toMatchObject({ needsEpoch: true, rotate: false });
    expect(plan.missing.map((device) => device.deviceId)).toEqual(["a1", "a2", "b1"]);
  });

  it("hands the current key only to devices that have not had it", () => {
    const plan = planKeyDistribution({ status: status({ recipients: ["a1", "b1"], recipientUsers: ["a", "b"] }), memberUserIds: [ME, "a", "b"], memberDevices: devices, myUserId: ME });
    expect(plan).toMatchObject({ needsEpoch: false, rotate: false });
    expect(plan.missing.map((device) => device.deviceId)).toEqual(["a2"]);
  });

  it("starts a new epoch when someone who held the key has left", () => {
    const plan = planKeyDistribution({
      status: status({ recipients: ["a1", "a2", "b1"], recipientUsers: ["a", "b"] }),
      memberUserIds: [ME, "a"],
      memberDevices: devices.filter((device) => device.userId !== "b"),
      myUserId: ME,
    });
    expect(plan.rotate).toBe(true);
    // The new key goes to who remains — never to the one who left.
    expect(plan.missing.map((device) => device.deviceId)).toEqual(["a1", "a2"]);
  });

  it("never hands keys to devices of people who are not members", () => {
    const plan = planKeyDistribution({ status: status(), memberUserIds: [ME, "a"], memberDevices: devices, myUserId: ME });
    expect(plan.missing.some((device) => device.userId === "b")).toBe(false);
  });

  it("is idle when everyone has the key", () => {
    const plan = planKeyDistribution({ status: status({ recipients: ["a1", "a2", "b1"], recipientUsers: ["a", "b"] }), memberUserIds: [ME, "a", "b"], memberDevices: devices, myUserId: ME });
    expect(plan).toEqual({ needsEpoch: false, rotate: false, missing: [] });
  });
});

describe("posts and invites", () => {
  it("maps posts between the core and the table without loss", () => {
    const sealed: SealedChannelPost = {
      postId: "p1", channelId: "c1", epochId: "e1", senderUserId: "u", senderDeviceId: "d",
      nonce: "n", ciphertext: "c", tag: "t", signature: { ed25519: [1], ml_dsa_65: [2] },
    };
    expect(rowToSealed({ ...sealedToRow(sealed), created_at: "2026-10-20T00:00:00Z" })).toEqual(sealed);
  });

  it("accepts invite codes however they are typed, and nothing else", () => {
    const code = "0123456789abcdef0123456789abcdef";
    expect(normalizeInviteCode(formatInviteCode(code).toUpperCase())).toBe(code);
    expect(normalizeInviteCode(` ${code} `)).toBe(code);
    expect(normalizeInviteCode("not-a-code")).toBeNull();
    expect(normalizeInviteCode(code.slice(1))).toBeNull();
    expect(formatInviteCode(code)).toBe("0123-4567-89ab-cdef-0123-4567-89ab-cdef");
  });

  it("splits hand-outs into batches", () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunk([], 50)).toEqual([]);
  });
});
