import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MeshMessage, OfflinePeer, OfflineStatus, OfflineTransfer } from "@/lib/offline";

const bridge = vi.hoisted(() => ({ safeInvoke: vi.fn(), listen: vi.fn() }));
vi.mock("@/lib/tauri", () => ({ safeInvoke: bridge.safeInvoke, isAndroidRuntime: () => true }));
vi.mock("@tauri-apps/api/event", () => ({ listen: bridge.listen }));

import OfflinePage from "./OfflinePage";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ACCOUNT = "test-account";
const PEER = "a".repeat(64);
const ME = "b".repeat(64);
const NOW = 1_795_000_000;
const TRANSFER_ID = "0a6d1b53-4d40-4507-bfa1-74eb06f280ad";
const MESSAGE_ID = "c450c865-e2e0-4ec9-871c-8be345fb2d2f";
const status: OfflineStatus = {
  running: true,
  lanDiscoveryRunning: true,
  autoStart: false,
  fingerprint: ME,
  port: 41000,
  networkError: null,
  platform: "android",
  peers: [{
    fingerprint: PEER, label: "Lab workstation", address: "192.168.0.8:41000", trusted: true,
    lastSeen: NOW, authenticatedAt: null, discovery: ["lan"],
  }],
};
const transfer: OfflineTransfer = {
  id: TRANSFER_ID, direction: "outgoing", sender: ME, recipient: PEER,
  files: [{ name: "report.txt", size: 1024 }], status: "active", createdAt: NOW, expiresAt: NOW + 3600,
  localCopyRetained: false, bytesPerSecond: 128, verifiedBytes: 512, totalBytes: 1024, error: null,
};
const message: MeshMessage = {
  id: MESSAGE_ID, direction: "outgoing", sender: ME, recipients: [PEER], body: "Ready at the lab.",
  group: null, emergency: false, createdAt: NOW, expiresAt: NOW + 3600, status: "pending", deliveredTo: [],
};

let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
let transfers: OfflineTransfer[];
let messages: MeshMessage[];

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW * 1000);
  bridge.safeInvoke.mockReset();
  bridge.listen.mockReset().mockResolvedValue(() => {});
  transfers = [];
  messages = [];
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.useRealTimers();
});

async function render(page: "mesh" | "xfer", platform: string, peers = status.peers, initialPeer?: string, transferRoute?: {
  initialTransferId: string;
  onTransferFocus: (id: string | null) => void;
}) {
  bridge.safeInvoke.mockImplementation(async (command: string) => {
    switch (command) {
      case "offline_dashboard_snapshot":
        return { status: { ...status, platform, peers }, messages: page === "mesh" ? messages : null, transfers: page === "xfer" ? transfers : null };
      case "offline_probe_peer": return page === "mesh" ? "ble" : "lan";
      case "offline_pairing_start": return "pairing-request";
      case "offline_xfer_pick_sources": return { token: "opaque-selection", names: ["report.txt"], totalBytes: 1024 };
      case "offline_xfer_offer": return TRANSFER_ID;
      case "offline_mesh_send": return MESSAGE_ID;
    }
  });
  await act(async () => root.render(createElement(OfflinePage, {
    page, accountId: ACCOUNT, vaultUnlocked: false, onNavigate: vi.fn(), initialPeer, ...transferRoute,
  })));
}

async function click(label: string) {
  const button = Array.from(host.querySelectorAll("button")).find((candidate) =>
    (candidate.getAttribute("aria-label") ?? candidate.textContent?.trim()) === label);
  expect(button, `Expected enabled button ${label}`).toBeDefined();
  expect(button?.disabled).toBe(false);
  await act(async () => button?.click());
}

async function pushSnapshot() {
  const onChanged = bridge.listen.mock.calls.find(([event]) => event === "offline:changed")?.[1] as (() => void) | undefined;
  expect(onChanged).toBeTypeOf("function");
  await act(async () => {
    onChanged?.();
    await vi.advanceTimersByTimeAsync(200);
  });
}

describe("incoming Mesh message from a notice", () => {
  it("opens the message, marks it read, shows the encryption suite and replies to the sender", async () => {
    const incoming: MeshMessage = {
      id: "mesh-incoming", direction: "incoming", sender: PEER, recipients: [ME], body: "Meet at the north gate.",
      group: null, emergency: true, createdAt: NOW, expiresAt: NOW + 3600, status: "delivered", deliveredTo: [ME], receivedAt: NOW,
    };
    bridge.safeInvoke.mockImplementation(async (command: string) => command === "offline_dashboard_snapshot"
      ? { status, messages: [incoming], transfers: null }
      : null);
    const onMeshRead = vi.fn();
    await act(async () => root.render(createElement(OfflinePage, {
      page: "mesh", accountId: ACCOUNT, vaultUnlocked: false, onNavigate: vi.fn(),
      initialMessage: { id: incoming.id, sender: PEER }, onMeshRead,
    })));
    expect(host.textContent).toContain("Meet at the north gate.");
    expect(host.textContent).toContain("Emergency message");
    expect(onMeshRead).toHaveBeenCalledWith([{ id: incoming.id, sender: PEER }]);
    const security = host.querySelector('[aria-label="Message encryption"]')?.textContent;
    expect(security).toContain("ML-KEM-768 + X25519");
    expect(security).toContain("ML-DSA-65 + Ed25519");
    expect(security).toContain("AES-256-GCM");
    await click("Reply");
    // A reply continues the conversation with the sender, with the received
    // message already in the thread.
    const conversation = host.querySelector(".mesh-conversation");
    expect(conversation?.getAttribute("aria-label")).toBe("Conversation with Lab workstation");
    expect(conversation?.querySelector("form textarea")).not.toBeNull();
    expect(conversation?.textContent).toContain("Meet at the north gate.");
  });
});

describe.each(["android", "windows"])("%s offline screens", (platform) => {
  it.each(["mesh", "xfer"] as const)("opens %s directly on the discovery radar without a repeated page heading", async (mode) => {
    await render(mode, platform);
    const headings = Array.from(host.querySelectorAll("h1, h2")).map((heading) => heading.textContent?.trim());
    // The shell names the page; the radar screen must not repeat it.
    expect(headings).toEqual(["Discovery radar"]);
    expect(host.textContent).not.toContain("Local file sharing");
    expect(host.textContent).not.toContain("Nearby messaging");
    const settings = host.querySelector<HTMLButtonElement>('.offline-radar-console header button[aria-label="Offline settings"]');
    expect(settings?.disabled).toBe(false);
    const onNavigate = vi.fn();
    await act(async () => root.render(createElement(OfflinePage, {
      page: mode, accountId: ACCOUNT, vaultUnlocked: false, onNavigate,
    })));
    await act(async () => host.querySelector<HTMLButtonElement>('.offline-radar-console header button[aria-label="Offline settings"]')?.click());
    expect(onNavigate).toHaveBeenCalledWith("offline-settings");
  });

  it.each(["mesh", "xfer"] as const)("asks the peer to pair from %s before showing a composer", async (mode) => {
    const remote = { ...status.peers[0], trusted: false, platform: platform === "android" ? "windows" : "android" };
    await render(mode, platform, [remote]);
    await click("Review Lab workstation on radar");

    let finishRequest!: (id: string) => void;
    bridge.safeInvoke.mockReturnValueOnce(new Promise<string>((resolve) => { finishRequest = resolve; }));
    await click("Connect Device");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_start", { peer: PEER, mode, both: false, expectedAccount: ACCOUNT });
    const connect = Array.from(host.querySelectorAll("button")).find((button) => button.textContent?.trim() === "Connect Device");
    expect(connect?.disabled).toBe(true);
    expect(host.querySelector("form")).toBeNull();

    await act(async () => finishRequest("pairing-request"));
    expect(host.querySelector("form")).toBeNull();
    for (const command of ["offline_trust", "offline_probe_peer", "offline_mesh_send", "offline_xfer_offer"]) {
      expect(bridge.safeInvoke).not.toHaveBeenCalledWith(command, expect.anything());
    }
  });

  it("honors a post-pairing shortcut only when the current snapshot still trusts that peer", async () => {
    await render("xfer", platform, [{ ...status.peers[0], trusted: false, blocked: true }], PEER);
    expect(host.querySelector("form")).toBeNull();
    expect(host.querySelector(".offline-radar-marker")).toBeNull();
  });

  it("opens the conversation for a still-trusted peer from a successful pairing shortcut", async () => {
    await render("mesh", platform, status.peers, PEER);
    const conversation = host.querySelector(".mesh-conversation");
    expect(conversation?.getAttribute("aria-label")).toBe("Conversation with Lab workstation");
    expect(conversation?.querySelector("textarea")).not.toBeNull();
    // No channel yet: the header says so instead of claiming a connection.
    expect(conversation?.querySelector('[role="status"]')?.textContent).toContain("In range");
    expect(conversation?.textContent).not.toContain("Connected");
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_mesh_send", expect.anything());
  });

  it("opens XFER progress for the offered ID and waits for native verification before completion", async () => {
    const olderReceipt: OfflineTransfer = {
      ...transfer, id: "f6ed7363-3869-444d-bdaa-e55fc0608c3c", status: "verified",
      files: [{ name: "older.txt", size: 1024 }], verifiedBytes: 1024,
    };
    transfers = [olderReceipt];
    await render("xfer", platform);
    expect(host.querySelector(".offline-radar")).not.toBeNull();
    expect(host.textContent).not.toContain("older.txt");
    expect(host.textContent).not.toContain("Transfer monitor");
    expect(host.querySelector("form")).toBeNull();

    await click("Select Lab workstation on radar");
    expect(host.textContent).toContain("Connect to device");
    expect(host.querySelector(".offline-radar")).toBeNull();
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_probe_peer", expect.anything());
    let finishConnection!: (transport: string) => void;
    bridge.safeInvoke.mockReturnValueOnce(new Promise<string>((resolve) => { finishConnection = resolve; }));
    await click("Connect");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_probe_peer", { peer: PEER, mode: "xfer", expectedAccount: ACCOUNT });
    expect(host.textContent).toContain("Connect to device");
    expect(host.querySelector("form")).toBeNull();
    await act(async () => finishConnection("lan"));
    expect(host.textContent).toContain("Send files");

    await click("Add files");
    await click("Offer selected files");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_offer", { recipient: PEER, selectionTokens: ["opaque-selection"] });
    expect(host.textContent).not.toContain("older.txt");
    expect(host.textContent).not.toContain("Transfer complete");
    transfers = [olderReceipt, transfer];
    await pushSnapshot();
    expect(host.textContent).toContain("File Transfer");
    expect(host.querySelector('[role="progressbar"]')?.getAttribute("aria-valuenow")).toBe("50");

    transfers = [olderReceipt, { ...transfer, verifiedBytes: transfer.totalBytes }];
    await pushSnapshot();
    expect(host.textContent).toContain("Awaiting final verification");
    expect(host.querySelector('[role="progressbar"]')?.getAttribute("aria-valuenow")).toBe("99");
    expect(host.textContent).not.toContain("Successfully transferred");

    transfers = [olderReceipt, { ...transfer, status: "verified", verifiedBytes: transfer.totalBytes }];
    await pushSnapshot();
    expect(host.textContent).toContain("Successfully transferred");
    expect(host.querySelector('[role="progressbar"]')?.getAttribute("aria-valuenow")).toBe("100");
    expect(host.textContent).toContain("report.txt");
    expect(host.textContent).not.toContain("older.txt");
    expect(host.querySelector(".offline-radar")).toBeNull();
  });

  it("opens the receiver's requested live transfer without following another session's updates", async () => {
    const receive: OfflineTransfer = { ...transfer, direction: "incoming", sender: PEER, recipient: ME };
    const unrelated: OfflineTransfer = { ...receive, id: "other-receipt", files: [{ name: "unrelated.pdf", size: 1024 }] };
    const onTransferFocus = vi.fn();
    transfers = [unrelated, receive];
    await render("xfer", platform, status.peers, undefined, { initialTransferId: receive.id, onTransferFocus });

    expect(onTransferFocus).toHaveBeenLastCalledWith(receive.id);
    expect(host.querySelector(".offline-radar")).toBeNull();
    expect(host.textContent).toContain("Lab workstation");
    expect(host.textContent).toContain("report.txt");
    expect(host.textContent).not.toContain("unrelated.pdf");
    expect(host.querySelector('[role="progressbar"]')?.getAttribute("aria-valuenow")).toBe("50");

    transfers = [{ ...unrelated, status: "verified", verifiedBytes: unrelated.totalBytes }, { ...receive, verifiedBytes: 768 }];
    await pushSnapshot();
    expect(host.querySelector('[role="progressbar"]')?.getAttribute("aria-valuenow")).toBe("75");
    expect(host.textContent).not.toContain("Successfully transferred");

    await click("Back to transfers");
    expect(onTransferFocus).toHaveBeenLastCalledWith(null);
    expect(host.querySelector('[role="progressbar"]')).toBeNull();
  });

  it("keeps Mesh in delivery until the exact queued message has a receipt", async () => {
    const olderMessage: MeshMessage = {
      ...message, id: "58f1b57e-901d-43e1-998c-3ff862818612", status: "delivered", deliveredTo: [PEER],
    };
    messages = [olderMessage];
    await render("mesh", platform);
    expect(host.querySelector(".offline-radar")).not.toBeNull();
    expect(host.querySelector("textarea")).toBeNull();
    expect(host.textContent).not.toContain(message.body);

    // The core keeps the channel: selecting a trusted peer opens the
    // conversation without a separate probe session competing for the radio.
    await click("Select Lab workstation on radar");
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_probe_peer", expect.anything());
    const conversation = () => host.querySelector(".mesh-conversation");
    expect(conversation()).not.toBeNull();
    expect(host.querySelector(".offline-radar")).toBeNull();
    const body = conversation()!.querySelector("textarea");
    expect(body).not.toBeNull();
    await act(async () => {
      const setValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
      setValue?.call(body, message.body);
      body?.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click("Send message");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_mesh_send", {
      recipients: [PEER], body: message.body, group: null, emergency: false, ttlSeconds: 86_400,
    });
    // The composer clears and stays open for the next message.
    expect(conversation()?.querySelector("textarea")?.value).toBe("");

    // Every state below comes from the snapshot: the link from the channel
    // registry, delivery from the stored receipt.
    let link: OfflinePeer["link"] = null;
    const base = bridge.safeInvoke.getMockImplementation()!;
    bridge.safeInvoke.mockImplementation(async (command: string, args?: unknown) => command === "offline_dashboard_snapshot"
      ? { status: { ...status, platform, peers: [{ ...status.peers[0], link }] }, messages, transfers: null }
      : base(command, args));
    const lastBubble = () => Array.from(conversation()?.querySelectorAll("li") ?? []).at(-1)?.textContent ?? "";

    messages = [olderMessage, message];
    await pushSnapshot();
    expect(lastBubble()).toContain(message.body);
    expect(lastBubble()).toContain("Waiting for connection");

    link = { state: "connected", transport: "bluetooth", since: NOW, session: "0011223344556677", rttMs: 84, attempts: 0 };
    await pushSnapshot();
    expect(conversation()?.querySelector('[role="status"]')?.textContent).toContain("Connected · Bluetooth · 84 ms");
    expect(lastBubble()).toContain("Sending");
    expect(lastBubble()).not.toContain("Delivered");

    messages = [olderMessage, { ...message, status: "delivered", deliveredTo: [PEER] }];
    await pushSnapshot();
    expect(lastBubble()).toContain("Delivered");
    // Both messages stay in one thread, oldest first; the view never leaves it.
    expect(conversation()?.querySelectorAll("li")).toHaveLength(2);
    expect(host.querySelector(".offline-radar")).toBeNull();
  });
});
