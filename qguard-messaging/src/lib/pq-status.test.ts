import { describe, expect, it } from "vitest";
import { CURRENT_KEM_COMBINER, CURRENT_PQ_KEM, CURRENT_PQ_KEM_STANDARD } from "@/lib/kem-suite";
import {
  PQ_STATUS_MESSAGE_WINDOW,
  derivePqStatus,
  pqStatusHasWarnings,
  summarizeContactDeviceProtection,
  type PqDeliveryDevice,
  type PqOpenedMessage,
  type PqStatusEvidence,
} from "@/lib/pq-status";

const BOUND_SUITE = { pq_kem: CURRENT_PQ_KEM, pq_kem_standard: CURRENT_PQ_KEM_STANDARD, kem_combiner: CURRENT_KEM_COMBINER };
const LEGACY_COMBINER_SUITE = { pq_kem: CURRENT_PQ_KEM, pq_kem_standard: CURRENT_PQ_KEM_STANDARD };
// The trap documented in kem-suite.ts: the label says ML-KEM-1024, the key is Kyber.
const PRE_FIPS_SUITE = { pq_kem: CURRENT_PQ_KEM, kem_combiner: CURRENT_KEM_COMBINER };

function device(overrides: Partial<PqDeliveryDevice> = {}): PqDeliveryDevice {
  return { deviceId: "d1", label: "Pixel", suite: BOUND_SUITE, standing: "pinned", ...overrides };
}

function opened(overrides: Partial<PqOpenedMessage> = {}): PqOpenedMessage {
  return { incoming: true, kemCombiner: CURRENT_KEM_COMBINER, authenticated: true, ...overrides };
}

function evidence(overrides: Partial<PqStatusEvidence> = {}): PqStatusEvidence {
  return {
    inApp: true,
    peerName: "Ana",
    deliveryDevices: [device()],
    excludedDevices: [],
    openedMessages: [opened()],
    pinsUnavailable: false,
    forwardSecrecy: { healthy: true, summary: "prekeys rotate daily and retired ones are destroyed." },
    ...overrides,
  };
}

const okLines = (status: ReturnType<typeof derivePqStatus>) => status.lines.filter((line) => line.ok);
const warnLines = (status: ReturnType<typeof derivePqStatus>) => status.lines.filter((line) => !line.ok);

describe("derivePqStatus", () => {
  it("reports quantum-safe on known devices only when every check passes", () => {
    const status = derivePqStatus(evidence());
    expect(status.level).toBe("protected-pinned");
    expect(warnLines(status)).toEqual([]);
    expect(status.lines.some((line) => line.text.includes("ML-KEM-1024"))).toBe(true);
  });

  it("says nothing when there is nothing to go on", () => {
    const status = derivePqStatus(evidence({ deliveryDevices: [], openedMessages: [], forwardSecrecy: null }));
    expect(status.level).toBe("unknown");
    expect(status.lines).toEqual([]);
    // Even with this device's prekeys measured: nothing to qualify, nothing said.
    expect(derivePqStatus(evidence({ deliveryDevices: [], openedMessages: [] })).lines).toEqual([]);
  });

  it("history alone never claims the NEXT message is protected", () => {
    const status = derivePqStatus(evidence({ deliveryDevices: [] }));
    expect(status.level).toBe("unknown");
  });

  it("a device not yet checked against the pin record caps the level at protected", () => {
    const status = derivePqStatus(evidence({ deliveryDevices: [device(), device({ deviceId: "d2", label: "Laptop", standing: undefined })] }));
    expect(status.level).toBe("protected");
    expect(warnLines(status).some((line) => line.text.includes("Laptop"))).toBe(true);
  });

  it("an unreadable pin record caps the level at protected", () => {
    expect(derivePqStatus(evidence({ pinsUnavailable: true })).level).toBe("protected");
  });

  it("a browser preview never reads as pinned", () => {
    expect(derivePqStatus(evidence({ inApp: false })).level).toBe("protected");
  });

  // ---- negative controls --------------------------------------------------

  it("a device on the legacy combiner is attention, never quantum-safe", () => {
    const status = derivePqStatus(evidence({ deliveryDevices: [device(), device({ deviceId: "d2", label: "Old phone", suite: LEGACY_COMBINER_SUITE })] }));
    expect(status.level).toBe("attention");
    expect(warnLines(status).some((line) => line.text.includes("Old phone"))).toBe(true);
    expect(okLines(status).some((line) => line.text.startsWith("Every message to"))).toBe(false);
  });

  it("a pre-FIPS device is attention even though its label says ML-KEM-1024", () => {
    const status = derivePqStatus(evidence({ deliveryDevices: [device({ suite: PRE_FIPS_SUITE })] }));
    expect(status.level).toBe("attention");
  });

  it("a missing suite is attention, not a pass", () => {
    expect(derivePqStatus(evidence({ deliveryDevices: [device({ suite: null })] })).level).toBe("attention");
  });

  it("an incoming message made with the legacy combiner is attention", () => {
    const status = derivePqStatus(evidence({ openedMessages: [opened(), opened({ kemCombiner: "" })] }));
    expect(status.level).toBe("attention");
    expect(warnLines(status).some((line) => line.text.startsWith("1 of the last 2"))).toBe(true);
  });

  it("an incoming message whose sender could not be authenticated is attention", () => {
    expect(derivePqStatus(evidence({ openedMessages: [opened({ authenticated: false })] })).level).toBe("attention");
  });

  it("outgoing messages say nothing about the combiner the contact used", () => {
    // Our own sent copies are sealed to OUR device; they are no evidence about
    // what the contact's app does, so a legacy label on one must not count.
    const status = derivePqStatus(evidence({ openedMessages: [opened({ incoming: false, kemCombiner: "" })] }));
    expect(status.level).toBe("protected-pinned");
  });

  it("only the recent window is considered", () => {
    const fresh = Array.from({ length: PQ_STATUS_MESSAGE_WINDOW }, () => opened());
    const status = derivePqStatus(evidence({ openedMessages: [...fresh, opened({ kemCombiner: "" })] }));
    expect(status.level).toBe("protected-pinned");
  });

  it("devices dropped from delivery are named, and alone they mean attention", () => {
    const excludedOnly = derivePqStatus(evidence({ deliveryDevices: [], openedMessages: [], excludedDevices: [{ label: "Tablet", reason: "key_changed" }] }));
    expect(excludedOnly.level).toBe("attention");
    expect(excludedOnly.lines[0]).toEqual({ ok: false, text: expect.stringContaining("Tablet is presenting different identity keys") });
  });

  it("a dropped device beside a healthy one is reported without lowering confidentiality", () => {
    const status = derivePqStatus(evidence({ excludedDevices: [{ label: "Tablet", reason: "awaiting_approval" }] }));
    expect(status.level).toBe("protected-pinned");
    expect(warnLines(status).some((line) => line.text.includes("waiting for your approval"))).toBe(true);
  });

  it("forward secrecy is quoted from the core, and its absence is said out loud", () => {
    const unhealthy = derivePqStatus(evidence({ forwardSecrecy: { healthy: false, summary: "rotation is overdue." } }));
    expect(unhealthy.lines).toContainEqual({ ok: false, text: "On this device: rotation is overdue." });
    const unmeasured = derivePqStatus(evidence({ forwardSecrecy: null }));
    expect(unmeasured.lines).toContainEqual({ ok: false, text: "Forward secrecy on this device is not measured right now." });
  });

  it("the pinned line never claims the PERSON is verified", () => {
    const pinnedLine = okLines(derivePqStatus(evidence())).find((line) => line.text.includes("recorded for"));
    expect(pinnedLine?.text).toContain("proves the device, not the person");
  });

  it("a good level with a note still reports that it has warnings", () => {
    const status = derivePqStatus(evidence({ excludedDevices: [{ label: "Tablet", reason: "awaiting_approval" }] }));
    expect(status.level).toBe("protected-pinned");
    expect(pqStatusHasWarnings(status)).toBe(true);
    expect(pqStatusHasWarnings(derivePqStatus(evidence()))).toBe(false);
  });
});

describe("summarizeContactDeviceProtection", () => {
  it("counts only other people's devices, by the form the next message would take", () => {
    const summary = summarizeContactDeviceProtection([
      { user_id: "me", suite: LEGACY_COMBINER_SUITE },
      { user_id: "ana", suite: BOUND_SUITE },
      { user_id: "ana", suite: LEGACY_COMBINER_SUITE },
      { user_id: "bo", suite: PRE_FIPS_SUITE },
      { user_id: "bo", suite: null },
    ], "me");
    expect(summary).toEqual({ total: 4, strongest: 1, olderCombiner: 1, cannotReceive: 2 });
  });

  it("is all zeros with no contacts", () => {
    expect(summarizeContactDeviceProtection([{ user_id: "me", suite: BOUND_SUITE }], "me"))
      .toEqual({ total: 0, strongest: 0, olderCombiner: 0, cannotReceive: 0 });
  });
});
