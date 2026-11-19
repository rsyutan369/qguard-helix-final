import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MeshNotice } from "@/lib/offline";

const bridge = vi.hoisted(() => ({ safeInvoke: vi.fn(), listen: vi.fn() }));
vi.mock("@/lib/tauri", () => ({ safeInvoke: bridge.safeInvoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: bridge.listen }));

import { useOfflineMeshMonitor } from "./use-offline-mesh-monitor";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const accountId = "test-account";
const sender = "a".repeat(64);
const message: MeshNotice = {
  id: "mesh-1", sender, senderName: "Alex", preview: "Meet at the north gate", group: null, emergency: false, receivedAt: 1_795_000_000,
};
let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
let view: ReturnType<typeof useOfflineMeshMonitor>;
let unread: MeshNotice[];

function Probe(props: { enabled: boolean }) {
  view = useOfflineMeshMonitor({ accountId, enabled: props.enabled });
  return null;
}

async function render(enabled = true) {
  await act(async () => root.render(createElement(Probe, { enabled })));
}

async function nativeChange() {
  const callback = bridge.listen.mock.calls.filter(([event]) => event === "offline:changed").at(-1)?.[1];
  expect(callback).toBeTypeOf("function");
  await act(async () => {
    callback?.();
    await vi.advanceTimersByTimeAsync(200);
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  unread = [];
  bridge.listen.mockReset().mockResolvedValue(() => {});
  bridge.safeInvoke.mockReset().mockImplementation(async (command: string, args: { messages?: { id: string }[] }) => {
    if (command === "offline_mesh_monitor") return unread;
    if (command === "offline_mesh_mark_read") {
      const ids = new Set(args.messages?.map(({ id }) => id));
      unread = unread.filter(({ id }) => !ids.has(id));
    }
    return null;
  });
  host = document.createElement("div");
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  vi.useRealTimers();
});

describe("real-time Mesh message notices", () => {
  it("shows a message as soon as the native core reports it, then clears it once read", async () => {
    await render();
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(view.notices).toEqual([]);
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_mesh_monitor", { expectedAccount: accountId });

    unread = [message];
    await nativeChange();
    expect(view.notices).toEqual([message]);

    await act(async () => { await view.markRead([message]); });
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_mesh_mark_read", {
      messages: [{ id: message.id, sender }], expectedAccount: accountId,
    });
    expect(view.notices).toEqual([]);
    await nativeChange();
    expect(view.notices).toEqual([]);
  });

  it("does not read or notify while offline access is unavailable", async () => {
    unread = [message];
    await render(false);
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(view.notices).toEqual([]);
    expect(bridge.safeInvoke).not.toHaveBeenCalledWith("offline_mesh_monitor", expect.anything());
  });
});
