import { describe, expect, it } from "vitest";
import {
  devicePinInputKey,
  isDeliverableStanding,
  mergeVerdicts,
  pendingDeviceReviews,
  pinCandidate,
  pinsUnavailable,
  type DevicePinIndex,
  type DevicePinStanding,
  type DevicePinVerdict,
  type PinnableDevice,
} from "@/lib/device-pins";

const ME = "user-me";
const ANA = "user-ana";

function device(id: string, overrides: Partial<PinnableDevice> = {}): PinnableDevice {
  return {
    device_id: id,
    user_id: ANA,
    trust_state: "Trusted",
    x25519_identity_public: [1, 2, 3],
    mlkem_identity_public: [4, 5, 6],
    ed25519_identity_public: [7, 8, 9],
    mldsa_identity_public: [10, 11, 12],
    identity_signature: { ed25519: [1], ml_dsa_65: [2] },
    ...overrides,
  };
}

function verdict(deviceId: string, standing: DevicePinStanding, userId = ANA): DevicePinVerdict {
  return { userId, deviceId, standing, fingerprint: `FP-${deviceId}`, pinnedAt: null, source: null };
}

function indexOf(...verdicts: DevicePinVerdict[]): DevicePinIndex {
  return mergeVerdicts(new Map(), { available: true, verdicts });
}

describe("pinCandidate", () => {
  it("maps a device to the core's argument shape", () => {
    expect(pinCandidate(device("phone"))).toEqual({
      user_id: ANA,
      device_id: "phone",
      x25519_identity_public: [1, 2, 3],
      mlkem_identity_public: [4, 5, 6],
      ed25519_identity_public: [7, 8, 9],
      mldsa_identity_public: [10, 11, 12],
      identity_signature: { ed25519: [1], ml_dsa_65: [2] },
    });
  });

  it("yields nothing for a row with no identity to judge", () => {
    expect(pinCandidate(device("phone", { identity_signature: null }))).toBeNull();
    expect(pinCandidate(device("phone", { identity_signature: { ed25519: [], ml_dsa_65: [2] } }))).toBeNull();
    expect(pinCandidate(device("phone", { mlkem_identity_public: [] }))).toBeNull();
    expect(pinCandidate(device("", {}))).toBeNull();
  });

  it("keeps a revoked device out of anyone's first-use record", () => {
    expect(pinCandidate(device("phone", { trust_state: "Revoked" }))).toBeNull();
  });
});

describe("devicePinInputKey", () => {
  it("is stable across refreshes that change nothing a pin depends on", () => {
    const first = devicePinInputKey([device("phone"), device("laptop")]);
    // Reordered, and with unrelated fields changed.
    const second = devicePinInputKey([
      { ...device("laptop"), trust_state: "ThisDevice" },
      device("phone"),
    ]);
    expect(second).toBe(first);
  });

  it("changes when a device appears, disappears, or changes any identity key", () => {
    const base = devicePinInputKey([device("phone")]);
    expect(devicePinInputKey([device("phone"), device("tablet")])).not.toBe(base);
    expect(devicePinInputKey([])).not.toBe(base);
    // Same device id, one key byte different: exactly the case that must be re-judged.
    expect(devicePinInputKey([device("phone", { ed25519_identity_public: [7, 8, 10] })])).not.toBe(base);
    expect(devicePinInputKey([device("phone", { mlkem_identity_public: [4, 5, 7] })])).not.toBe(base);
    expect(devicePinInputKey([device("phone", { mldsa_identity_public: [10, 11] })])).not.toBe(base);
  });

  it("ignores rows that cannot be judged", () => {
    expect(devicePinInputKey([device("phone"), device("ghost", { identity_signature: null })]))
      .toBe(devicePinInputKey([device("phone")]));
  });
});

describe("isDeliverableStanding", () => {
  it("never delivers to a device that needs a decision or is refused", () => {
    expect(isDeliverableStanding("new")).toBe(false);
    expect(isDeliverableStanding("key_changed")).toBe(false);
    expect(isDeliverableStanding("invalid_identity")).toBe(false);
  });

  it("delivers to a pinned device, and leaves unjudged ones to the core", () => {
    expect(isDeliverableStanding("pinned")).toBe(true);
    expect(isDeliverableStanding("unknown")).toBe(true);
    expect(isDeliverableStanding(undefined)).toBe(true);
  });
});

describe("mergeVerdicts", () => {
  it("replaces an earlier verdict with a later assessment's", () => {
    const before = indexOf(verdict("tablet", "new"));
    const after = mergeVerdicts(before, { available: true, verdicts: [verdict("tablet", "pinned")] });
    expect(after.get("tablet")?.standing).toBe("pinned");
    // The earlier index is not mutated.
    expect(before.get("tablet")?.standing).toBe("new");
  });

  it("keeps the worst verdict when one device id is judged twice at once", () => {
    // Two directory rows sharing a device id: the genuine one and an impostor.
    const index = indexOf(verdict("phone", "pinned"), verdict("phone", "key_changed"));
    expect(index.get("phone")?.standing).toBe("key_changed");
    const reversed = indexOf(verdict("phone", "key_changed"), verdict("phone", "pinned"));
    expect(reversed.get("phone")?.standing).toBe("key_changed");
  });

  it("keeps verdicts for devices the new assessment did not mention", () => {
    const index = mergeVerdicts(indexOf(verdict("phone", "pinned")), { available: true, verdicts: [verdict("tablet", "new")] });
    expect([...index.keys()].sort()).toEqual(["phone", "tablet"]);
  });
});

describe("pendingDeviceReviews", () => {
  const devices = [
    device("phone"),
    device("tablet"),
    device("swapped"),
    device("my-laptop", { user_id: ME }),
    device("other-person", { user_id: "user-zed" }),
    device("retired", { trust_state: "Revoked" }),
  ];
  const index = indexOf(
    verdict("phone", "pinned"),
    verdict("tablet", "new"),
    verdict("swapped", "key_changed"),
    verdict("my-laptop", "new", ME),
    verdict("other-person", "new", "user-zed"),
    verdict("retired", "new"),
  );

  it("lists what needs a decision, approvable devices first", () => {
    const reviews = pendingDeviceReviews(devices, index, [ANA, ME], ME);
    expect(reviews.map((review) => [review.device.device_id, review.owner, review.approvable])).toEqual([
      ["tablet", "contact", true],
      ["my-laptop", "self", true],
      ["swapped", "contact", false],
    ]);
  });

  it("is limited to the people asked about", () => {
    const reviews = pendingDeviceReviews(devices, index, [ANA], ME);
    expect(reviews.map((review) => review.device.device_id)).toEqual(["tablet", "swapped"]);
  });

  it("is empty when everything is pinned or nothing has been judged", () => {
    expect(pendingDeviceReviews(devices, indexOf(verdict("phone", "pinned")), [ANA, ME], ME)).toEqual([]);
    expect(pendingDeviceReviews(devices, new Map(), [ANA, ME], ME)).toEqual([]);
  });

  it("shows a device once even if it is listed twice", () => {
    const reviews = pendingDeviceReviews([device("tablet"), device("tablet")], index, [ANA], ME);
    expect(reviews).toHaveLength(1);
  });
});

describe("pinsUnavailable", () => {
  it("reports when the core could not open its record", () => {
    expect(pinsUnavailable(indexOf(verdict("phone", "unknown")))).toBe(true);
    expect(pinsUnavailable(indexOf(verdict("phone", "pinned"), verdict("tablet", "new")))).toBe(false);
    expect(pinsUnavailable(new Map())).toBe(false);
  });
});
