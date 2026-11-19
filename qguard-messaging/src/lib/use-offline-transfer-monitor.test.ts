import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const bridge = vi.hoisted(() => ({ safeInvoke: vi.fn(), listen: vi.fn() }));
vi.mock("@/lib/tauri", () => ({ safeInvoke: bridge.safeInvoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: bridge.listen }));

import { useOfflineTransferMonitor } from "./use-offline-transfer-monitor";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type MonitorOptions = Parameters<typeof useOfflineTransferMonitor>[0];
type MonitorState = ReturnType<typeof useOfflineTransferMonitor>;

const accountId = "test-account";
const now = 1_795_000_000_000;
const active = { id: "xfer-active", direction: "incoming", status: "active", createdAt: now / 1000, startedAtMs: now } as const;
const offer = { id: "xfer-offer", direction: "incoming", status: "awaitingConsent", createdAt: now / 1000 } as const;
const old = { id: "xfer-old", direction: "outgoing", status: "verified", createdAt: now / 1000 - 120, completedAtMs: now - 60_000 } as const;
const otherActive = { ...active, id: "xfer-second", direction: "outgoing" } as const;

let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
let view: MonitorState;
let rows: object[];
const onOpen = vi.fn();

function Probe(props: MonitorOptions) {
  view = useOfflineTransferMonitor(props);
  return null;
}

async function render(options: Partial<MonitorOptions> = {}) {
  await act(async () => root.render(createElement(Probe, { accountId, enabled: true, focusedId: null, onOpen, ...options })));
}

async function change() {
  const callback = bridge.listen.mock.calls.filter(([event]) => event === "offline:changed").at(-1)?.[1];
  expect(callback).toBeTypeOf("function");
  await act(async () => {
    callback?.();
    await vi.advanceTimersByTimeAsync(200);
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(now);
  rows = [];
  onOpen.mockReset();
  bridge.safeInvoke.mockReset().mockImplementation(async () => rows);
  bridge.listen.mockReset().mockResolvedValue(() => {});
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.useRealTimers();
});

describe("offline transfer monitor", () => {
  it("opens a newly verified transfer even if it finished between progress snapshots", async () => {
    await render();
    rows = [{ ...active, status: "verified", completedAtMs: now + 50 }];
    await change();
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(onOpen).toHaveBeenCalledWith(active.id);
    await change();
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it("restores a current transfer without reopening it after Back or notifying for history", async () => {
    rows = [old, offer, active];
    await render();

    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_monitor", { expectedAccount: accountId });
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(onOpen).toHaveBeenCalledWith(active.id);
    expect(view.notices).toContainEqual(expect.objectContaining({ id: offer.id, status: "awaitingConsent" }));
    expect(view.notices.some(({ id }) => id === old.id)).toBe(false);

    await render({ focusedId: active.id });
    await render({ focusedId: null });
    await change();
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_xfer_respond", expect.anything());
  });

  it("keeps a simultaneous session in a notice and announces only a new verified receipt", async () => {
    rows = [old, active];
    await render({ focusedId: active.id });
    expect(onOpen).not.toHaveBeenCalled();

    rows = [old, active, otherActive];
    await change();
    expect(view.notices).toContainEqual(expect.objectContaining({ id: otherActive.id, status: "active" }));
    expect(onOpen).not.toHaveBeenCalled();

    rows = [old, { ...active, status: "verified", completedAtMs: Date.now() }, otherActive];
    await change();
    const receipt = view.notices.find(({ id, status }) => id === active.id && status === "verified");
    expect(receipt).toBeDefined();
    expect(view.notices.some(({ id }) => id === old.id)).toBe(false);
    expect(onOpen).not.toHaveBeenCalled();

    await act(async () => view.dismiss(receipt!));
    await change();
    expect(view.notices.some(({ id }) => id === active.id)).toBe(false);

    const concurrent = view.notices.find(({ id }) => id === otherActive.id);
    expect(concurrent).toBeDefined();
    await act(async () => view.open(concurrent!));
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(onOpen).toHaveBeenCalledWith(otherActive.id);
  });

  it("ignores in-flight data for a previous account and masks results while disabled", async () => {
    let resolvePrevious!: (records: object[]) => void;
    const previous = new Promise<object[]>((resolve) => { resolvePrevious = resolve; });
    bridge.safeInvoke.mockImplementation(async (_command, { expectedAccount }) => expectedAccount === accountId ? previous : []);

    await render({ enabled: false });
    expect(bridge.safeInvoke).not.toHaveBeenCalled();
    await render();
    await render({ accountId: "second-account" });
    await act(async () => resolvePrevious([offer, active]));
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_xfer_monitor", { expectedAccount: "second-account" });
    expect(onOpen).not.toHaveBeenCalled();
    expect(view.notices).toEqual([]);

    bridge.safeInvoke.mockResolvedValue([offer]);
    await change();
    expect(view.notices).toContainEqual(expect.objectContaining({ id: offer.id }));
    await render({ accountId: "second-account", enabled: false });
    expect(view.notices).toEqual([]);
  });
});
