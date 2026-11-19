import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OfflinePairing } from "@/lib/offline";

const bridge = vi.hoisted(() => ({ safeInvoke: vi.fn(), listen: vi.fn() }));
vi.mock("@/lib/tauri", () => ({ safeInvoke: bridge.safeInvoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: bridge.listen }));

import { OfflinePairingHost } from "./OfflinePairingHost";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const accountId = "test-account";
const pairing: OfflinePairing = {
  id: "initial-request",
  peer: "a".repeat(64),
  label: "Nearby workstation",
  platform: "windows",
  capabilities: ["mesh", "xfer"],
  requested: ["mesh"],
  direction: "incoming",
  status: "awaitingApproval",
  code: null,
  error: null,
};
const code = "1C4E-63A0-85D9-00B2";
const onOpen = vi.fn();
let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
let snapshot: OfflinePairing[];

beforeEach(() => {
  vi.useFakeTimers();
  onOpen.mockReset();
  snapshot = [];
  bridge.listen.mockReset().mockResolvedValue(() => {});
  bridge.safeInvoke.mockReset().mockImplementation(async (command) => {
    if (command === "offline_pairing_snapshot") return snapshot;
    if (command === "offline_pairing_start") return "retry-request";
  });
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.useRealTimers();
});

function dialog() {
  return document.querySelector("dialog[open]");
}

function button(label: string) {
  return Array.from(dialog()?.querySelectorAll("button") ?? []).find((candidate) => candidate.textContent?.trim() === label);
}

async function click(label: string) {
  const control = button(label);
  expect(control?.disabled, label).toBe(false);
  await act(async () => control?.click());
}

async function mount() {
  await act(async () => root.render(createElement(OfflinePairingHost, { accountId, onOpen })));
}

async function receive(...pairings: OfflinePairing[]) {
  snapshot = pairings;
  const onChanged = bridge.listen.mock.calls.find(([name]) => name === "offline:changed")?.[1];
  expect(onChanged).toBeTypeOf("function");
  await act(async () => {
    onChanged();
    await vi.advanceTimersByTimeAsync(200);
  });
}

describe("App-wide offline pairing", () => {
  it("shows an incoming request and waits for native mutual trust before opening a feature", async () => {
    await mount();
    expect(dialog()).toBeNull();
    await receive(pairing);
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_snapshot", { expectedAccount: accountId });
    expect(dialog()?.textContent).toContain("New device connection request");
    expect(dialog()?.textContent).toContain(pairing.label);
    expect(dialog()?.textContent).toContain("Windows");
    expect(dialog()?.querySelector("dt")?.textContent).toBe("Connection type");
    expect(dialog()?.querySelector("dd")?.textContent).toBe("Mesh messaging");
    expect(dialog()?.textContent).not.toContain("XFER file transfer");
    expect(button("Start messaging")).toBeUndefined();

    await click("Allow connection");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_decide", { id: pairing.id, decision: "allow", expectedAccount: accountId });
    expect(button("They match · Trust device")).toBeUndefined();
    await receive({ ...pairing, status: "verifying", code });
    expect(dialog()?.textContent).toContain(code);
    await click("They match · Trust device");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_decide", { id: pairing.id, decision: "confirm", expectedAccount: accountId });

    await receive({ ...pairing, status: "awaitingConfirmation", code });
    expect(dialog()?.textContent).toContain("Waiting for mutual confirmation");
    expect(button("Start messaging")).toBeUndefined();
    expect(onOpen).not.toHaveBeenCalled();

    await receive({ ...pairing, status: "trusted" });
    expect(dialog()?.textContent).toContain("Device successfully trusted");
    // The device supports both, but trust covers only what the users approved.
    expect(dialog()?.textContent).toContain("Approved capabilities");
    expect(dialog()?.textContent).toContain("Mesh messaging");
    expect(dialog()?.textContent).not.toContain("XFER file transfer");
    expect(button("Send files")).toBeUndefined();
    expect(dialog()?.textContent).not.toContain(code);
    await click("Start messaging");
    expect(onOpen).toHaveBeenCalledWith("mesh", pairing.peer);
    expect(dialog()).toBeNull();
  });

  it("rejects an incoming request and cancels after a code mismatch without granting trust", async () => {
    await mount();
    await receive(pairing);
    await click("Do not allow");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_decide", { id: pairing.id, decision: "reject", expectedAccount: accountId });
    const rejected = { ...pairing, status: "rejected" } as const;
    await receive(rejected);
    expect(dialog()?.textContent).toContain("Connection declined");
    await click("Close");

    const second = { ...pairing, id: "second-request", status: "verifying", code } as const;
    await receive(rejected, second);
    await click("They don’t match");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_decide", { id: second.id, decision: "cancel", expectedAccount: accountId });
    await receive(rejected, { ...second, status: "cancelled", code: null });
    expect(dialog()?.textContent).toContain("Pairing cancelled");
    expect(button("Start messaging")).toBeUndefined();
    expect(onOpen).not.toHaveBeenCalled();
  });

  it("retries an expired outgoing request in the same feature", async () => {
    await mount();
    await receive({ ...pairing, direction: "outgoing", status: "expired", requested: ["xfer"] });
    expect(dialog()?.textContent).toContain("Pairing request expired");
    await click("Try again");
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_pairing_start", { peer: pairing.peer, mode: "xfer", both: false, expectedAccount: accountId });
    await receive({ ...pairing, id: "retry-request", direction: "outgoing", status: "awaitingApproval", requested: ["xfer"] });
    expect(dialog()?.textContent).toContain("Connection request sent");
    expect(button("Allow connection")).toBeUndefined();
  });

  it("offers both features after a combined Mesh and XFER pairing", async () => {
    await mount();
    await receive({ ...pairing, direction: "outgoing", status: "trusted", requested: ["mesh", "xfer"] });
    expect(dialog()?.textContent).toContain("Mesh messaging and XFER file transfer");
    expect(button("Start messaging")).toBeDefined();
    await click("Send files");
    expect(onOpen).toHaveBeenCalledWith("xfer", pairing.peer, "send");
  });

  it("lets the approving device wait for files instead of returning to the radar", async () => {
    await mount();
    await receive({ ...pairing, direction: "incoming", status: "trusted", requested: ["xfer"] });
    expect(button("Wait for files")?.hasAttribute("data-primary")).toBe(true);
    expect(button("Send files")?.hasAttribute("data-primary")).toBe(false);
    await click("Wait for files");
    expect(onOpen).toHaveBeenCalledWith("xfer", pairing.peer, "receive");
    expect(dialog()).toBeNull();
  });
});
