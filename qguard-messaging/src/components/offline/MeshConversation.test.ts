import { describe, expect, it } from "vitest";
import { offlineLinkState, type MeshMessage, type OfflinePeer } from "@/lib/offline";
import { COMPOSER_CLEARANCE, meshConversationFit, meshDeliveryState, meshThread, meshUsableBottom } from "./MeshConversation";

const ME = "aa".repeat(32);
const PEER = "bb".repeat(32);
const OTHER = "cc".repeat(32);

function message(id: string, direction: "incoming" | "outgoing", createdAt: number, extra: Partial<MeshMessage> = {}): MeshMessage {
  return {
    id, direction, createdAt, expiresAt: createdAt + 3600, body: id, group: null, emergency: false,
    sender: direction === "incoming" ? PEER : ME, recipients: direction === "incoming" ? [ME] : [PEER],
    status: direction === "incoming" ? "delivered" : "pending", deliveredTo: [], ...extra,
  };
}

describe("Mesh conversation height", () => {
  it("fills the visible scroll area below the notices and above the reserved navigation space", () => {
    // Phone: 640 px visible, 112 px reserved for the floating navigation,
    // 96 px of notices above, 12 px of wrapper padding below.
    const bottom = meshUsableBottom(640, 112, []);
    expect(meshConversationFit({ bottom, top: 96, trailing: 12 })).toBe(420);
  });

  it("keeps clear of a navigation bar that reaches into the scroll area", () => {
    // Android skin: 16 px padding, but a taller rail (gesture inset, large
    // text) whose top edge sits 40 px inside the scroll area.
    expect(meshUsableBottom(600, 16, [560])).toBe(560 - COMPOSER_CLEARANCE);
    // A rail below the scroll area leaves the padding as the limit.
    expect(meshUsableBottom(600, 16, [610])).toBe(584);
    expect(COMPOSER_CLEARANCE).toBeGreaterThanOrEqual(8);
  });

  it("keeps a usable minimum and lets the page scroll when space runs out", () => {
    expect(meshConversationFit({ bottom: meshUsableBottom(420, 112, []), top: 200, trailing: 12 })).toBe(320);
  });
});

describe("Mesh conversation thread", () => {
  it("keeps one device's messages in both directions, oldest first, ties in ledger order", () => {
    const ledger = [
      message("reply", "incoming", 100, { receivedAt: 105 }),
      message("first", "outgoing", 100),
      message("second", "outgoing", 100),
      message("elsewhere", "incoming", 101, { sender: OTHER }),
      message("group", "outgoing", 103, { recipients: [OTHER, PEER] }),
    ];
    expect(meshThread(ledger, PEER).map(({ id }) => id)).toEqual(["first", "second", "group", "reply"]);
    expect(meshThread(ledger, OTHER).map(({ id }) => id)).toEqual(["elsewhere", "group"]);
    expect(meshThread(null, PEER)).toEqual([]);
  });

  it("reports delivery per device from the stored receipt only", () => {
    const pending = message("m", "outgoing", 100, { recipients: [PEER, OTHER] });
    expect(meshDeliveryState(pending, PEER, false)).toEqual({ label: "Waiting for connection", tone: "waiting" });
    expect(meshDeliveryState(pending, PEER, true)).toEqual({ label: "Sending", tone: "sending" });
    const partly = { ...pending, deliveredTo: [PEER] };
    expect(meshDeliveryState(partly, PEER, false).tone).toBe("delivered");
    expect(meshDeliveryState(partly, OTHER, true).tone).toBe("sending");
    expect(meshDeliveryState({ ...pending, relayedTo: [OTHER] }, OTHER, false).label).toBe("Relayed, awaiting delivery");
    expect(meshDeliveryState({ ...pending, status: "expired" }, PEER, true).tone).toBe("failed");
  });
});

describe("offline link state", () => {
  const peer: OfflinePeer = { fingerprint: PEER, label: "Phone", address: null, lastSeen: 100, authenticatedAt: null, trusted: true, discovery: ["ble"] };

  it("calls a device connected only when the core holds a channel to it", () => {
    expect(offlineLinkState(undefined).label).toBe("Not in range");
    expect(offlineLinkState(peer)).toEqual({ label: "In range", detail: "Bluetooth", tone: "idle" });
    expect(offlineLinkState({ ...peer, lastSeen: null }).label).toBe("Not in range");
    expect(offlineLinkState({ ...peer, link: { state: "connecting", transport: null, since: null, session: null, rttMs: null, attempts: 0 } }).label).toBe("Connecting");
    expect(offlineLinkState({ ...peer, link: { state: "reconnecting", transport: null, since: null, session: null, rttMs: null, attempts: 2 } }))
      .toEqual({ label: "Reconnecting", detail: "attempt 3", tone: "pending" });
    expect(offlineLinkState({ ...peer, link: { state: "connected", transport: "lan", since: 100, session: "00", rttMs: null, attempts: 0 } }))
      .toEqual({ label: "Connected", detail: "local network", tone: "connected" });
    expect(offlineLinkState({ ...peer, disconnected: true, link: null }).label).toBe("Disconnected");
    expect(offlineLinkState({ ...peer, blocked: true }).tone).toBe("blocked");
  });
});
