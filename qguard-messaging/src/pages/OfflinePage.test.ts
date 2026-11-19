import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatOfflineTime, type OfflinePageId, type OfflinePeer, type OfflineStatus, type OfflineTransfer, type SmartConnectStatus } from "@/lib/offline";

const bridge = vi.hoisted(() => ({ safeInvoke: vi.fn(), listen: vi.fn(), ask: vi.fn() }));
vi.mock("@/lib/tauri", () => ({ safeInvoke: bridge.safeInvoke, isAndroidRuntime: () => false }));
vi.mock("@tauri-apps/api/event", () => ({ listen: bridge.listen }));
vi.mock("@/lib/tauri-dialog", () => ({ ask: bridge.ask }));

import OfflinePage, { xferArrival } from "./OfflinePage";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const peer = "a".repeat(64);
const me = "b".repeat(64);
const NOW = 1_795_000_000;
const status: OfflineStatus = {
  running: true, lanDiscoveryRunning: true, autoStart: false, fingerprint: me, port: 41000, networkError: null, platform: "windows",
  peers: [{ fingerprint: peer, label: "Lab workstation", address: "192.168.0.8:41000", trusted: true, lastSeen: NOW, authenticatedAt: NOW, discovery: ["lan"] }],
};
const smartConnect: SmartConnectStatus = {
  bluetoothAvailable: true, bluetoothPermissionGranted: true, bluetoothRunning: true,
  bluetoothScanning: true, bluetoothAdvertising: true,
  bluetoothError: null, hotspotAvailable: false, hotspotActive: false,
};
const incoming: OfflineTransfer = {
  id: "test-transfer", direction: "incoming", sender: peer, recipient: me,
  files: [{ name: "inventory.pdf", size: 1024 }], status: "awaitingConsent",
  createdAt: NOW, expiresAt: NOW + 3600, localCopyRetained: false, bytesPerSecond: null, verifiedBytes: 0, totalBytes: 1024, error: null,
};

let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
const onNavigate = vi.fn();

async function render(transfers: OfflineTransfer[], vaultUnlocked = false, snapshot = status, page: OfflinePageId = "xfer", relay: "available" | "unavailable" | "unknown" = "unknown", extra: Record<string, unknown> = {}) {
  bridge.safeInvoke.mockImplementation(async (command: string) => {
    if (command === "offline_dashboard_snapshot") return {
      status: snapshot,
      messages: page === "mesh" ? [] : null,
      transfers: page === "xfer" || page === "transfer-history" ? transfers : null,
    };
    if (command === "offline_probe_peer") return "lan";
    if (command === "offline_pairing_start") return "pairing-request";
    if (command === "offline_xfer_offer") return "offered-transfer";
    if (command === "offline_xfer_pick_sources") return { token: "opaque-selection", names: ["report.txt"] };
    if (command === "offline_hotspot_details") return { ssid: "Qguard-test", password: "test-only-password" };
  });
  await act(async () => root.render(createElement(OfflinePage, { page, accountId: "test-account", vaultUnlocked, onNavigate, relay, ...extra })));
}

function findButton(label: string): HTMLButtonElement | undefined {
  return Array.from(host.querySelectorAll("button")).find((button) => (button.getAttribute("aria-label") ?? button.textContent?.trim()) === label);
}

async function click(label: string) {
  const button = findButton(label);
  expect(button?.disabled, label).toBe(false);
  await act(async () => button?.click());
}

async function openTransfer(name = "inventory.pdf") {
  const queue = Array.from(host.querySelectorAll("button")).find((button) => button.textContent?.trim().startsWith("Transfers"));
  expect(queue).toBeDefined();
  await act(async () => queue?.click());
  const row = Array.from(host.querySelectorAll<HTMLButtonElement>(".offline-mobile-row"))
    .find((button) => button.querySelector("strong")?.textContent === name);
  expect(row, name).toBeDefined();
  await act(async () => row?.click());
}

function transferProgress() {
  return host.querySelector('[role="progressbar"][aria-label="Verified transfer progress"]');
}

beforeEach(() => {
  bridge.safeInvoke.mockReset();
  bridge.listen.mockReset().mockResolvedValue(() => {});
  bridge.ask.mockReset().mockResolvedValue(true);
  onNavigate.mockReset();
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  vi.useRealTimers();
  host.remove();
});

describe("Offline XFER", () => {
  it("shows the incoming manifest before enabling receipt and export", async () => {
    await render([incoming]);
    expect(host.textContent).not.toContain("inventory.pdf");
    await openTransfer();
    expect(host.textContent).toContain("inventory.pdf");
    expect(host.textContent).toContain("SenderLab workstation");
    expect(host.textContent).toContain("After you accept");
    expect(host.textContent).not.toContain("Files are verified in protected local transfer storage");
    expect(findButton("Save file")).toBeUndefined();
    await act(async () => findButton("Accept files")?.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_respond", { id: incoming.id, accept: true });
  });

  it("uses native selection tokens when offering files", async () => {
    await render([]);
    expect(host.querySelector("form")).toBeNull();
    await act(async () => host.querySelector<HTMLButtonElement>('[aria-label="Select Lab workstation on radar"]')?.click());
    await click("Connect");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_probe_peer", { peer, mode: "xfer", expectedAccount: "test-account" });
    expect(findButton("Add folder")).toBeDefined();
    expect(findButton("Offer selected files")?.disabled).toBe(true);
    await act(async () => findButton("Add files")?.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_pick_sources", { folder: false });
    expect(host.textContent).toContain("report.txt");
    await act(async () => findButton("Offer selected files")?.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_offer", { recipient: peer, selectionTokens: ["opaque-selection"] });
  });

  it("queues selected files for a pinned peer without a local endpoint", async () => {
    await render([], false, {
      ...status, smartConnect, peers: [{ ...status.peers[0], address: null, authenticatedAt: null, discovery: ["ble"] }],
    });
    await click("Nearby devices");
    await act(async () => host.querySelector<HTMLButtonElement>(".offline-mobile-row")?.click());
    await click("Continue without connection");
    await act(async () => findButton("Add files")?.click());
    expect(findButton("Queue transfer")?.disabled).toBe(false);
    await act(async () => findButton("Queue transfer")?.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_offer", { recipient: peer, selectionTokens: ["opaque-selection"] });
    expect(host.textContent).toContain("Waiting for the local record");
  });

  it("accepts Android file-picker selections while discovery is stopped", async () => {
    await render([], false, {
      ...status, platform: "android", running: false, port: null,
      peers: [{ ...status.peers[0], address: null, authenticatedAt: null }],
    });
    await act(async () => findButton("Nearby devices")?.click());
    const savedPeer = Array.from(host.querySelectorAll("button")).find((button) => button.textContent?.includes("Lab workstation"));
    expect(savedPeer).toBeDefined();
    await act(async () => savedPeer?.click());
    await act(async () => findButton("Continue without connection")?.click());
    await act(async () => findButton("Add files")?.click());
    expect(findButton("Add folder")).toBeDefined();
    expect(host.textContent).toContain("Android file picker");
    expect(host.textContent).not.toContain("direct filesystem path");
    await act(async () => findButton("Queue transfer")?.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_offer", { recipient: peer, selectionTokens: ["opaque-selection"] });
  });

  it("uses the native Android folder picker before sending", async () => {
    await render([], false, { ...status, platform: "android" });
    await click("Nearby devices");
    const peerRow = Array.from(host.querySelectorAll("button")).find((button) => button.textContent?.includes("Lab workstation"));
    expect(peerRow).toBeDefined();
    await act(async () => peerRow?.click());
    await click("Continue without connection");
    await click("Add folder");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_pick_sources", { folder: true });
  });

  it("requests automatic import only through the explicit unlocked Vault action", async () => {
    await render([incoming], true);
    await openTransfer();
    await act(async () => findButton("Accept into Quantum Vault")?.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_respond", { id: incoming.id, accept: true, intoVault: true });
  });

  it("routes a verified receipt through the existing Vault lock before import", async () => {
    const verified: OfflineTransfer = { ...incoming, status: "verified", localCopyRetained: true, verifiedBytes: incoming.totalBytes };
    await render([verified]);
    await openTransfer();
    expect(findButton("Import into Vault")).toBeUndefined();
    await act(async () => findButton("Unlock Quantum Vault")?.click());
    expect(onNavigate).toHaveBeenCalledWith("vault");
    await render([verified], true);
    await act(async () => findButton("Import into Vault")?.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_import_vault", { id: verified.id, file: 0 });
  });

  it("keeps a verified receipt visible after the protected copy expires", async () => {
    await render([{ ...incoming, status: "verified", verifiedBytes: incoming.totalBytes, expiresAt: NOW - 1 }], true);
    await openTransfer();
    expect(host.textContent).toContain("Integrity verified");
    expect(host.textContent).toContain("The protected local file copy has expired.");
    expect(host.textContent).not.toContain("Save file");
    expect(host.textContent).not.toContain("Import into Vault");
  });

  it("starts mutual pairing for an unverified radar peer and keeps file sending unavailable", async () => {
    const discovered = status.peers[0];
    const fingerprint = "c".repeat(64);
    await render([], false, {
      ...status, smartConnect,
      peers: [
        { ...discovered, discovery: ["lan"] },
        { ...discovered, fingerprint, label: "New peer", discovery: ["lan"], trusted: false, authenticatedAt: null },
      ],
    });
    await act(async () => host.querySelector<HTMLButtonElement>('[aria-label="Review New peer on radar"]')?.click());
    expect(host.textContent).toContain("Connect to device");
    expect(host.querySelector(".offline-radar")).toBeNull();
    expect(host.querySelector('input[type="checkbox"]')).toBeNull();
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_pairing_start", expect.anything());
    const scopes = Array.from(host.querySelectorAll<HTMLInputElement>('fieldset.offline-scope input[type="radio"]'));
    expect(scopes.map((input) => input.closest("label")?.querySelector("strong")?.textContent))
      .toEqual(["XFER file transfer only", "Mesh messaging and XFER"]);
    expect(scopes[0].checked).toBe(true);
    await click("Connect Device");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_start", { peer: fingerprint, mode: "xfer", both: false, expectedAccount: "test-account" });
    await act(async () => scopes[1].click());
    await click("Connect Device");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_start", { peer: fingerprint, mode: "xfer", both: true, expectedAccount: "test-account" });
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_probe_peer", expect.anything());
    expect(findButton("Add files")).toBeUndefined();
    expect(findButton("Continue without connection")).toBeUndefined();
    expect(onNavigate).not.toHaveBeenCalled();
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_trust", expect.anything());
  });

  it("shows native verified progress and keeps the transfer monitor and filtered queue on separate screens", async () => {
    const active: OfflineTransfer = { ...incoming, status: "active", verifiedBytes: 512, bytesPerSecond: 128 };
    const verified: OfflineTransfer = { ...incoming, id: "verified-receipt", status: "verified", verifiedBytes: 1024, files: [{ name: "verified.pdf", size: 1024 }] };
    await render([active, verified]);
    await openTransfer();
    expect(transferProgress()?.getAttribute("aria-valuenow")).toBe("50");
    expect(host.textContent).toContain("128 B/s");
    expect(host.textContent).not.toContain("verified.pdf");
    await click("Pause");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_pause", { id: active.id });
    await click("Back to transfers");
    await click("Verified");
    expect(host.textContent).not.toContain("inventory.pdf");
    expect(host.textContent).toContain("verified.pdf");
  });

  it("refreshes progress on native push, reserves success for a verified receipt, and clears records when authorization is lost", async () => {
    vi.useFakeTimers();
    const active: OfflineTransfer = { ...incoming, status: "active", verifiedBytes: 512, bytesPerSecond: 128 };
    await render([active]);
    await openTransfer();
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_dashboard_snapshot", { page: "xfer", expectedAccount: "test-account" });
    const onChanged = bridge.listen.mock.calls.find(([event]) => event === "offline:changed")?.[1] as () => void;
    expect(onChanged).toBeTypeOf("function");
    async function push() {
      await act(async () => {
        onChanged();
        await vi.advanceTimersByTimeAsync(200);
      });
    }

    bridge.safeInvoke.mockResolvedValueOnce({
      status, messages: null, transfers: [{ ...active, verifiedBytes: active.totalBytes }],
    });
    await push();
    expect(host.textContent).toContain("Awaiting final verification");
    expect(transferProgress()?.getAttribute("aria-valuenow")).toBe("99");
    expect(host.querySelector(".offline-guided-flow")?.getAttribute("data-screen")).not.toBe("complete");

    bridge.safeInvoke.mockResolvedValueOnce({
      status, messages: null, transfers: [{ ...active, status: "verified", verifiedBytes: active.totalBytes, bytesPerSecond: null }],
    });
    await push();
    expect(host.querySelector(".offline-guided-flow")?.getAttribute("data-screen")).toBe("complete");
    expect(transferProgress()?.getAttribute("aria-valuenow")).toBe("100");

    bridge.safeInvoke.mockRejectedValueOnce("OFFLINE_PRINCIPAL_UNVERIFIED: Verify account");
    await push();
    expect(transferProgress()).toBeNull();
    expect(host.textContent).not.toContain("inventory.pdf");
    expect(findButton("Verify local account")).toBeDefined();
  });

  it("coalesces changes during a read and re-fetches the latest snapshot after it resolves", async () => {
    vi.useFakeTimers();
    await render([incoming]);
    await openTransfer();
    const onChanged = bridge.listen.mock.calls.find(([event]) => event === "offline:changed")?.[1] as () => void;
    let finishRead!: (snapshot: { status: OfflineStatus; messages: null; transfers: OfflineTransfer[] }) => void;
    const delayed = new Promise<{ status: OfflineStatus; messages: null; transfers: OfflineTransfer[] }>((resolve) => { finishRead = resolve; });
    bridge.safeInvoke.mockReturnValueOnce(delayed);
    await act(async () => { onChanged(); await vi.advanceTimersByTimeAsync(200); });
    expect(bridge.safeInvoke).toHaveBeenCalledTimes(2);
    await act(async () => { onChanged(); onChanged(); await vi.advanceTimersByTimeAsync(500); });
    expect(bridge.safeInvoke).toHaveBeenCalledTimes(2);
    const cancelled: OfflineTransfer = { ...incoming, status: "cancelled" };
    bridge.safeInvoke.mockResolvedValueOnce({ status, messages: null, transfers: [cancelled] });
    await act(async () => { finishRead({ status, messages: null, transfers: [incoming] }); });
    await act(async () => { await vi.advanceTimersByTimeAsync(200); });
    expect(bridge.safeInvoke).toHaveBeenCalledTimes(3);
    expect(host.textContent).toContain("Cancelled");
    expect(findButton("Accept files")).toBeUndefined();
  });

  it("separates a confirmed checkpoint-preserving stop from cancelling an active transfer", async () => {
    await render([{ ...incoming, status: "active", verifiedBytes: 512 }]);
    await openTransfer();

    bridge.ask.mockResolvedValueOnce(false);
    await click("Stop");
    expect(bridge.ask).toHaveBeenCalledWith(expect.stringMatching(/resum/i), expect.objectContaining({ title: "Stop transfer" }));
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_xfer_stop", expect.anything());

    await click("Stop");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_stop", { id: incoming.id, expectedAccount: "test-account" });
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_xfer_cancel", expect.anything());

    await click("Cancel");
    expect(bridge.ask).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ title: "Cancel transfer" }));
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_cancel", { id: incoming.id });
  });

  it("resumes a stopped transfer by ID without replacing its checkpoint", async () => {
    await render([{ ...incoming, status: "stopped", verifiedBytes: 512 }]);
    await openTransfer();
    expect(host.textContent).toContain("Stopped");
    expect(transferProgress()?.getAttribute("aria-valuenow")).toBe("50");
    expect(findButton("Pause")).toBeUndefined();
    await click("Resume");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_resume", { id: incoming.id });
  });

  it("cannot locally resume a remote-only hold and never invents a live speed", async () => {
    await render([{ ...incoming, status: "paused", remoteHold: "pause", verifiedBytes: 512, bytesPerSecond: 128 }]);
    await openTransfer();

    expect(transferProgress()?.getAttribute("aria-valuenow")).toBe("50");
    expect(findButton("Resume")?.disabled).toBe(true);
    expect(host.textContent).not.toContain("128 B/s");
    expect(host.textContent).toContain("No recent throughput measurements");
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_xfer_resume", expect.anything());
  });

  it("opens only a verified receipt's saved file through an account-scoped native request", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW * 1_000);
    const saved = { ...incoming.files[0], destination: "C:\\Users\\test\\Downloads\\inventory.pdf", canOpenFile: true, canOpenFolder: true };
    const offered: OfflineTransfer = { ...incoming, files: [saved] };
    await render([offered]);
    await openTransfer();
    expect(findButton("Open file")).toBeUndefined();
    expect(findButton("Open folder")).toBeUndefined();

    const onChanged = bridge.listen.mock.calls.find(([event]) => event === "offline:changed")?.[1] as () => void;
    bridge.safeInvoke.mockResolvedValueOnce({
      status, messages: null, transfers: [{ ...offered, status: "verified", verifiedBytes: offered.totalBytes }],
    });
    await act(async () => {
      onChanged();
      await vi.advanceTimersByTimeAsync(200);
    });

    await click("Open file");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_open", { id: offered.id, file: 0, target: "file", expectedAccount: "test-account" });
    await click("Open folder");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_open", { id: offered.id, file: 0, target: "folder", expectedAccount: "test-account" });
  });
});

describe("Direct Wi-Fi link (Bluetooth-only pairs)", () => {
  const withLink = (wifiLink: NonNullable<OfflinePeer["wifiLink"]>): OfflineStatus => ({
    ...status, peers: [{ ...status.peers[0], wifiLink }],
  });

  it("asks before this computer joins the other device's Wi-Fi link, then joins through the native core", async () => {
    await render([], false, withLink({ state: "joinPrompt", role: "join", automaticJoin: true }));
    const card = host.querySelector('[aria-label="Wi-Fi link with Lab workstation"]');
    expect(card?.textContent).toContain("Join Lab workstation's Wi-Fi link");
    expect(card?.textContent).toContain("returns to it automatically afterwards");
    // The network name and password stay inside the native core.
    expect(card?.textContent).not.toContain("Password");
    await click("Join Wi-Fi link");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_wifi_link_join", { peer, accept: true, expectedAccount: "test-account" });
  });

  it("lets the user decline the link", async () => {
    await render([], false, withLink({ state: "joinPrompt", role: "join", automaticJoin: true }));
    await click("Not now");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_wifi_link_join", { peer, accept: false, expectedAccount: "test-account" });
  });

  it("shows the network to join by hand only where joining cannot be automatic", async () => {
    await render([], false, withLink({ state: "manual", role: "join", automaticJoin: false, network: "AndroidShare_4821", passphrase: "link-passphrase" }));
    const card = host.querySelector('[aria-label="Wi-Fi link with Lab workstation"]');
    expect(card?.textContent).toContain("AndroidShare_4821");
    expect(card?.textContent).toContain("link-passphrase");
    expect(findButton("Join Wi-Fi link")).toBeUndefined();
  });

  it("explains a failed link and offers to try again", async () => {
    await render([], false, withLink({ state: "failed", role: "host", automaticJoin: true, error: "Android could not start a temporary hotspot." }));
    expect(host.textContent).toContain("Android could not start a temporary hotspot.");
    await click("Try again");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_wifi_link_close", { peer, expectedAccount: "test-account" });
  });

  it("shows nothing when no link exists", async () => {
    await render([]);
    expect(host.querySelector(".wifi-link-card")).toBeNull();
  });
});

describe("Nearby picture setting", () => {
  it("is off by default and turns on only by the user's choice", async () => {
    await render([], false, { ...status, sharePictureNearby: false, localAvatar: "ab".repeat(32) }, "offline-settings");
    const toggle = Array.from(host.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'))
      .find((input) => input.closest("label")?.textContent?.includes("Show my picture to nearby devices"));
    expect(toggle?.checked).toBe(false);
    await act(async () => toggle?.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_set_share_picture", { enabled: true, expectedAccount: "test-account" });
  });
});

describe("XFER connection session", () => {
  const sent: OfflineTransfer = {
    ...incoming, id: "sent-transfer", direction: "outgoing", sender: me, recipient: peer, status: "verified", verifiedBytes: 1024,
  };
  const received: OfflineTransfer = { ...incoming, id: "received-transfer", status: "verified", verifiedBytes: 1024 };

  async function push(transfers: OfflineTransfer[]) {
    const onChanged = bridge.listen.mock.calls.find(([event]) => event === "offline:changed")?.[1] as () => void;
    expect(onChanged).toBeTypeOf("function");
    bridge.safeInvoke.mockResolvedValueOnce({ status, messages: null, transfers });
    await act(async () => {
      onChanged();
      await vi.advanceTimersByTimeAsync(200);
    });
  }

  it("picks the offer a waiting receiver should open", () => {
    expect(xferArrival([received], peer, new Set([received.id]))).toBeNull();
    expect(xferArrival([received, incoming], peer, new Set([received.id, incoming.id]))?.id).toBe(incoming.id);
    expect(xferArrival([{ ...incoming, status: "active" }], peer, new Set())?.id).toBe(incoming.id);
    expect(xferArrival([incoming], "c".repeat(64), new Set())).toBeNull();
    expect(xferArrival([sent], peer, new Set())).toBeNull();
  });

  it("waits for files after pairing instead of returning to the radar, then opens the offer", async () => {
    vi.useFakeTimers();
    await render([received], false, status, "xfer", "unknown", { initialPeer: peer, initialIntent: "receive" });
    expect(host.textContent).toContain("Ready to receive");
    expect(host.textContent).toContain("Waiting for Lab workstation to choose files");
    expect(host.querySelector('[aria-label="Select Lab workstation on radar"]')).toBeNull();
    // An earlier receipt from this device is history, not a new arrival.
    expect(findButton("Accept files")).toBeUndefined();

    await push([received, incoming]);
    expect(host.textContent).toContain("inventory.pdf");
    expect(findButton("Accept files")?.disabled).toBe(false);
  });

  it("offers Send more files after a verified send and keeps the same device selected", async () => {
    await render([sent]);
    await openTransfer();
    expect(host.textContent).toContain("Successfully transferred and verified");
    await click("Send more files");
    expect(host.textContent).toContain("Lab workstation");
    expect(host.textContent).toContain("Trusted device. Qguard authenticates the connection when sending.");
    // The file picker opens at once, exactly once, for the same device.
    expect(bridge.safeInvoke.mock.calls.filter(([command]) => command === "offline_xfer_pick_sources")).toHaveLength(1);
    expect(host.textContent).toContain("report.txt");
    await click("Offer selected files");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_offer", { recipient: peer, selectionTokens: ["opaque-selection"] });
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_pairing_start", expect.anything());
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_probe_peer", expect.anything());
  });

  it("shows the live session and disconnects only after confirmation", async () => {
    const connected = { ...status, peers: [{ ...status.peers[0], link: { state: "connected" as const, transport: "lan" as const, since: NOW, session: "0011223344556677", rttMs: 9, attempts: 0 } }] };
    await render([], false, connected, "xfer", "unknown", { initialPeer: peer, initialIntent: "receive" });
    expect(host.querySelector(".offline-session-bar [role=status]")?.textContent).toContain("Connected · local network · 9 ms");
    bridge.ask.mockResolvedValueOnce(false);
    await click("Disconnect");
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_disconnect_peer", expect.anything());
    await click("Disconnect");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_disconnect_peer", { peer, expectedAccount: "test-account" });
    expect(host.querySelector('[aria-label="Select Lab workstation on radar"]')).not.toBeNull();
  });

  it("shows the picture a trusted peer shared, keyed by its fingerprint and digest", async () => {
    const digest = "ab".repeat(32);
    const pictured = { ...status, localAvatar: null, peers: [{ ...status.peers[0], avatar: digest }] };
    const dataUrl = "data:image/jpeg;base64,/9j/AA==";
    await render([sent], false, pictured);
    bridge.safeInvoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "offline_avatar") return args?.peer === peer ? { digest, dataUrl } : null;
      if (command === "offline_dashboard_snapshot") return { status: pictured, messages: null, transfers: [sent] };
      return null;
    });
    await openTransfer();
    await act(async () => { await Promise.resolve(); });
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_avatar", { peer, expectedAccount: "test-account" });
    const receiver = Array.from(host.querySelectorAll(".xfer-live-participant")).find((node) => node.getAttribute("data-local") === "false");
    expect(receiver?.querySelector("img")?.getAttribute("src")).toBe(dataUrl);
  });

  it("returns the receiver to waiting after a verified receipt", async () => {
    await render([received]);
    await openTransfer();
    expect(findButton("Send more files")).toBeUndefined();
    await click("Wait for more files");
    expect(host.textContent).toContain("Ready to receive");
    expect(findButton("Accept files")).toBeUndefined();
  });

  it("lets a trusted XFER device be waited for from the connect screen", async () => {
    await render([]);
    await act(async () => host.querySelector<HTMLButtonElement>('[aria-label="Select Lab workstation on radar"]')?.click());
    await click("Wait for files");
    expect(host.textContent).toContain("Ready to receive");
    await click("Stop waiting");
    expect(host.querySelector('[aria-label="Select Lab workstation on radar"]')).not.toBeNull();
  });
});

describe("Mesh dashboard", () => {
  it("keeps pinned recipients available when the radar has no live discoveries", async () => {
    await render([], false, { ...status, running: false, peers: [{ ...status.peers[0], lastSeen: null }] }, "mesh");
    expect(host.querySelectorAll(".offline-radar-marker")).toHaveLength(0);
    await click("Nearby devices");
    const saved = host.querySelector<HTMLButtonElement>(".offline-mobile-row")!;
    await act(async () => saved.click());
    // A pinned peer out of range still opens its conversation: a message
    // written now waits in the encrypted queue for the channel.
    const conversation = host.querySelector(".mesh-conversation");
    expect(conversation).not.toBeNull();
    expect(conversation?.querySelector('[role="status"]')?.textContent).toContain("Not in range");
    expect(conversation?.textContent).toContain("Local networking is stopped");
    expect(conversation?.querySelector("textarea")?.disabled).toBe(false);
    expect(findButton("Send message")?.disabled).toBe(true);
  });

  it("opens the Mesh group composer from a conversation for several recipients", async () => {
    await render([], false, status, "mesh");
    await act(async () => host.querySelector<HTMLButtonElement>('[aria-label="Select Lab workstation on radar"]')?.click());
    await click("Send to several devices");
    expect(host.querySelector<HTMLInputElement>("#offline-compose fieldset input")?.checked).toBe(true);
    expect(findButton("Queue message")?.disabled).toBe(true);
    await click("Back");
    expect(host.querySelector(".mesh-conversation")).not.toBeNull();
  });
});

describe("Offline trusted devices", () => {
  it("shows authenticated device metadata and waits for approval before disconnecting or revoking", async () => {
    const trusted: OfflinePeer = {
      ...status.peers[0], platform: "android", pairedAt: NOW - 120, connected: true, capabilities: ["mesh", "xfer"],
    };
    await render([], false, { ...status, peers: [trusted] }, "offline-settings");
    const entry = Array.from(host.querySelectorAll("article")).find((article) => article.textContent?.includes("Lab workstation"));
    expect(entry?.textContent).toContain("Android · Mutually paired");
    expect(entry?.textContent).toContain("Connected");
    const details = entry?.querySelector("details");
    const summary = details?.querySelector("summary");
    expect(summary?.textContent).toContain("View device details");
    await act(async () => summary?.click());
    expect(details?.textContent).toContain(peer);
    expect(details?.textContent).toContain(formatOfflineTime(NOW - 120));
    expect(details?.textContent).toContain(formatOfflineTime(NOW));
    expect(details?.textContent).toContain("Mesh messaging · XFER file transfer");
    expect(findButton("Add Mesh access")).toBeUndefined();
    expect(findButton("Add XFER access")).toBeUndefined();

    bridge.ask.mockResolvedValueOnce(false);
    await click("Disconnect");
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_disconnect_peer", expect.anything());
    await click("Disconnect");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_disconnect_peer", { peer, expectedAccount: "test-account" });
    await click("Revoke trust");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_revoke", { fingerprint: peer, expectedAccount: "test-account" });
    await click("Block device");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_block_peer", { peer, expectedAccount: "test-account" });
  });

  it("requires a native authenticated probe to reconnect a disconnected device", async () => {
    await render([], false, {
      ...status, peers: [{ ...status.peers[0], pairedAt: NOW - 60, capabilities: ["xfer"], disconnected: true }],
    }, "offline-settings");
    expect(host.textContent).toContain("Disconnected");
    expect(findButton("Disconnect")?.disabled).toBe(true);
    await click("Connect");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_probe_peer", { peer, mode: "xfer", expectedAccount: "test-account" });
  });

  it("shows a scoped pairing and asks both users before adding the missing capability", async () => {
    await render([], false, {
      ...status, peers: [{ ...status.peers[0], pairedAt: NOW - 60, capabilities: ["mesh"], owner: "Alex Rivera" }],
    }, "offline-settings");
    const entry = host.querySelector("article");
    expect(entry?.textContent).toContain("Alex Rivera");
    expect(entry?.textContent).toContain("Lab workstation");
    expect(entry?.querySelector("[aria-label='Approved capabilities']")?.textContent).toBe("Mesh messaging");
    expect(findButton("Add Mesh access")).toBeUndefined();
    await click("Add XFER access");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_start", {
      peer, mode: "xfer", both: false, expectedAccount: "test-account",
    });
  });

  it("lets the user turn background Mesh and relaying on and off", async () => {
    await render([], false, { ...status, running: true, background: false, relay: true, relayCarrying: 3 }, "offline-settings");
    const reach = host.querySelector("[aria-label='Mesh reach']");
    expect(reach?.textContent).toContain("Carrying 3 right now.");
    expect(reach?.textContent).toContain("cannot read");
    const [background, relayToggle] = Array.from(reach?.querySelectorAll("input[type='checkbox']") ?? []) as HTMLInputElement[];
    expect(background.checked).toBe(false);
    expect(relayToggle.checked).toBe(true);
    await act(async () => background.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_set_background", { enabled: true });
    await act(async () => relayToggle.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_set_relay", { enabled: false });
  });

  it("hides the Mesh reach settings when the native core does not report them", async () => {
    await render([], false, status, "offline-settings");
    expect(host.querySelector("[aria-label='Mesh reach']")).toBeNull();
  });

  it("offers only unblock for a blocked device", async () => {
    await render([], false, {
      ...status, peers: [{ ...status.peers[0], trusted: false, blocked: true }],
    }, "offline-settings");
    expect(host.textContent).toContain("Blocked");
    expect(findButton("Connect")).toBeUndefined();
    expect(findButton("Revoke trust")).toBeUndefined();
    await click("Unblock device");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_unblock_peer", { peer, expectedAccount: "test-account" });
  });
});

describe("Helix Smart Connect", () => {
  it("does not show scanning or nearby markers when Bluetooth only advertises", async () => {
    await render([], false, {
      ...status, lanDiscoveryRunning: false,
      smartConnect: { ...smartConnect, bluetoothScanning: false, bluetoothAdvertising: true },
      peers: [{ ...status.peers[0], discovery: ["ble"] }],
    }, "mesh");
    expect(host.querySelector(".offline-radar")?.getAttribute("data-sweeping")).toBe("false");
    expect(host.querySelectorAll(".offline-radar-marker")).toHaveLength(0);
    expect(host.querySelector(".offline-radar-console")?.textContent).toContain("Bluetooth advertising");
    expect(host.textContent).toContain("0 discovered · 1 saved");
  });

  it("prompts to start discovery before making a Bluetooth availability assertion", async () => {
    await render([], false, {
      ...status, running: false, port: null,
      smartConnect: { ...smartConnect, bluetoothAvailable: false, bluetoothRunning: false },
    }, "offline-settings");
    expect(host.textContent).toContain("Start local discovery to check Bluetooth");
    expect(host.textContent).not.toContain("Bluetooth discovery unavailable");
    expect(findButton("Allow Nearby devices")).toBeUndefined();
  });

  it("offers Android permission and Bluetooth retry only in the applicable states", async () => {
    await render([], false, {
      ...status, platform: "android", smartConnect: {
        ...smartConnect, bluetoothPermissionGranted: false, bluetoothRunning: false,
        bluetoothScanning: false, bluetoothAdvertising: false,
      },
    }, "mesh");
    expect(host.textContent).toContain("Bluetooth permission required");
    expect(findButton("Retry Bluetooth discovery")).toBeUndefined();
    await act(async () => findButton("Allow Nearby devices")?.click());
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_bluetooth_permissions");
  });

  it("does not show a Bluetooth discovery as a trusted device or offer manual pinning", async () => {
    await render([], false, {
      ...status, smartConnect, peers: [{ ...status.peers[0], address: null, trusted: false, authenticatedAt: null, discovery: ["ble"] }],
    }, "offline-settings");
    expect(host.textContent).toMatch(/trusted devices/i);
    expect(host.textContent).not.toContain("Lab workstation");
    expect(host.querySelector("#pair-identity")).toBeNull();
    expect(findButton("Pin fingerprint")).toBeUndefined();
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_trust", expect.anything());
  });

  it("reveals hotspot credentials only after the explicit action and hides them again", async () => {
    await render([], false, {
      ...status, smartConnect: { ...smartConnect, hotspotAvailable: true, hotspotActive: true },
    }, "offline-settings");
    expect(host.textContent).not.toContain("test-only-password");
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_hotspot_details");
    await act(async () => findButton("Show hotspot details")?.click());
    expect(host.textContent).toContain("Qguard-test");
    expect(host.textContent).toContain("test-only-password");
    await act(async () => findButton("Hide hotspot details")?.click());
    expect(host.textContent).not.toContain("test-only-password");
  });

  it("keeps an asynchronous hotspot request pending until native confirmation", async () => {
    await render([], false, {
      ...status, smartConnect: {
        ...smartConnect, hotspotAvailable: true, hotspotStarting: true,
        hotspotError: "Nearby Wi-Fi permission is required.",
      },
    }, "offline-settings");
    expect(host.textContent).toContain("Waiting for system hotspot…");
    expect(host.textContent).toContain("Nearby Wi-Fi permission is required.");
    expect(findButton("Waiting for hotspot")?.disabled).toBe(true);
    expect(findButton("Show hotspot details")).toBeUndefined();
    expect(host.textContent).not.toContain("Temporary hotspot active");
  });

  it("keeps legacy trust visible without presenting Bluetooth advertising as verified metadata", async () => {
    await render([], false, {
      ...status, smartConnect,
      peers: [{ ...status.peers[0], address: null, trusted: true, authenticatedAt: null, discovery: ["ble"], bleMesh: true }],
    }, "offline-settings");
    expect(host.textContent).toContain("Trusted fingerprint");
    expect(host.textContent).not.toContain("Mutually paired");
    const details = host.querySelector("article details");
    // Fingerprints pinned before scoped pairing keep the access they had.
    expect(details?.textContent).toMatch(/Approved capabilities\s+Mesh messaging · XFER file transfer/);
    expect(details?.textContent).toMatch(/Last connected\s+Unavailable/);
  });

  it("routes online sharing through the existing Secure Chat workspace", async () => {
    await render([], false, { ...status, smartConnect }, "xfer", "available");
    await click("Transfers");
    await click("Share online in Secure Chat");
    expect(onNavigate).toHaveBeenCalledWith("chat");
  });
});
