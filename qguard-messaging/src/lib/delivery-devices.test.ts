import { describe, expect, it } from "vitest";
import {
  CALL_RING_POLICY,
  MESSAGE_DELIVERY_POLICY,
  selectDeliveryDevices,
  type DeliveryCandidateDevice,
} from "@/lib/delivery-devices";

const NOW = Date.parse("2026-08-26T03:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;

function device(overrides: Partial<DeliveryCandidateDevice> & { device_id: string }): DeliveryCandidateDevice {
  return {
    user_id: "peer",
    last_seen_at: new Date(NOW - 60_000).toISOString(),
    created_at: new Date(NOW - DAY).toISOString(),
    trust_state: "Trusted",
    ...overrides,
  };
}

describe("selectDeliveryDevices", () => {
  it("addresses every live device of a peer, not just the freshest", () => {
    // The regression: a phone and a desktop that both register the hardcoded
    // "Windows Desktop" label used to collapse into one target.
    const devices = [
      device({ device_id: "desktop", last_seen_at: new Date(NOW - 10 * 60_000).toISOString() }),
      device({ device_id: "phone", last_seen_at: new Date(NOW - 30_000).toISOString() }),
    ];
    const selected = selectDeliveryDevices(devices, ["peer"], null, CALL_RING_POLICY, NOW);
    expect(selected.map((d) => d.device_id)).toEqual(["phone", "desktop"]);
  });

  it("drops identities stranded outside the policy window", () => {
    const devices = [
      device({ device_id: "live", last_seen_at: new Date(NOW - 60_000).toISOString() }),
      device({ device_id: "reinstalled-away", last_seen_at: new Date(NOW - 20 * DAY).toISOString() }),
    ];
    expect(selectDeliveryDevices(devices, ["peer"], null, CALL_RING_POLICY, NOW).map((d) => d.device_id))
      .toEqual(["live"]);
    // Messaging keeps a wider window: the envelope waits for the device.
    expect(selectDeliveryDevices(devices, ["peer"], null, MESSAGE_DELIVERY_POLICY, NOW).map((d) => d.device_id))
      .toEqual(["live", "reinstalled-away"]);
  });

  it("still returns the freshest device when every device has gone quiet", () => {
    // A dormant contact must stay reachable; zero targets would make them
    // permanently unaddressable.
    const devices = [
      device({ device_id: "old", last_seen_at: new Date(NOW - 200 * DAY).toISOString() }),
      device({ device_id: "less-old", last_seen_at: new Date(NOW - 100 * DAY).toISOString() }),
    ];
    expect(selectDeliveryDevices(devices, ["peer"], null, CALL_RING_POLICY, NOW).map((d) => d.device_id))
      .toEqual(["less-old"]);
  });

  it("caps fan-out per user", () => {
    const devices = Array.from({ length: 9 }, (_, i) =>
      device({ device_id: `d${i}`, last_seen_at: new Date(NOW - i * 1000).toISOString() }));
    expect(selectDeliveryDevices(devices, ["peer"], null, CALL_RING_POLICY, NOW)).toHaveLength(CALL_RING_POLICY.maxPerUser);
    expect(selectDeliveryDevices(devices, ["peer"], null, MESSAGE_DELIVERY_POLICY, NOW)).toHaveLength(MESSAGE_DELIVERY_POLICY.maxPerUser);
  });

  it("caps per user, not across the whole group", () => {
    const devices = [
      ...Array.from({ length: 5 }, (_, i) => device({ device_id: `a${i}`, user_id: "a" })),
      ...Array.from({ length: 5 }, (_, i) => device({ device_id: `b${i}`, user_id: "b" })),
    ];
    const selected = selectDeliveryDevices(devices, ["a", "b"], null, CALL_RING_POLICY, NOW);
    expect(selected.filter((d) => d.user_id === "a")).toHaveLength(4);
    expect(selected.filter((d) => d.user_id === "b")).toHaveLength(4);
  });

  it("ignores users that are not targets and de-duplicates repeated rows", () => {
    const dup = device({ device_id: "phone" });
    const selected = selectDeliveryDevices(
      [dup, { ...dup }, device({ device_id: "stranger", user_id: "someone-else" })],
      ["peer"],
      null,
      CALL_RING_POLICY,
      NOW,
    );
    expect(selected.map((d) => d.device_id)).toEqual(["phone"]);
  });

  it("puts the local device first so a self-sync seals to this device before the rest", () => {
    const devices = [
      device({ device_id: "other", last_seen_at: new Date(NOW).toISOString() }),
      device({ device_id: "me", last_seen_at: new Date(NOW - 5 * 60_000).toISOString() }),
    ];
    expect(selectDeliveryDevices(devices, ["peer"], "me", MESSAGE_DELIVERY_POLICY, NOW)[0].device_id).toBe("me");
  });
});
