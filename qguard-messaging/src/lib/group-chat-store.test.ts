import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// A stand-in for the core's encrypted name store (commands/conversation_names.rs).
const store = vi.hoisted(() => ({
  tauri: true,
  entries: [] as Array<{ conversationId: string; name: string; at: string; senderUserId: string }>,
  calls: [] as Array<{ command: string; args?: Record<string, unknown> }>,
}));

vi.mock("@/lib/tauri", () => ({
  isTauriRuntime: () => store.tauri,
  safeInvoke: vi.fn(async (command: string, args?: Record<string, unknown>) => {
    store.calls.push({ command, args });
    if (command === "conversation_names_list") return store.entries;
    if (command === "conversation_names_remember") {
      store.entries.push(...(args?.entries as typeof store.entries));
      return 1;
    }
    if (command === "conversation_names_forget") {
      store.entries = store.entries.filter((entry) => entry.conversationId !== args?.conversationId);
      return null;
    }
    throw new Error(`unexpected command ${command}`);
  }),
}));

import { forgetGroupNames, forgetStoredGroupName, groupName, loadStoredGroupNames, rememberGroupName, setGroupOwnerHistory } from "./group-chat";

const OWNER = "owner-1";
const MEMBER = "member-1";

beforeEach(() => {
  store.tauri = true;
  store.entries = [];
  store.calls = [];
});
afterEach(() => forgetGroupNames());

describe("names kept on this device", () => {
  it("stores a new name and reads it back after memory is wiped (an app restart)", async () => {
    expect(rememberGroupName("g1", "Ops room", "2026-10-22T08:00:00.000Z", OWNER)).toBe(true);
    expect(store.entries).toEqual([{ conversationId: "g1", name: "Ops room", at: "2026-10-22T08:00:00.000Z", senderUserId: OWNER }]);

    forgetGroupNames();
    expect(groupName("g1", OWNER)).toBeNull();
    expect(await loadStoredGroupNames()).toBe(true);
    expect(groupName("g1", OWNER)).toBe("Ops room");
  });

  it("does not write back what it just read, nor a duplicate", async () => {
    store.entries = [{ conversationId: "g1", name: "Ops room", at: "2026-10-22T08:00:00.000Z", senderUserId: OWNER }];
    await loadStoredGroupNames();
    expect(store.calls.filter((call) => call.command === "conversation_names_remember")).toHaveLength(0);
    expect(rememberGroupName("g1", "Ops room", "2026-10-22T08:00:00.000Z", OWNER)).toBe(false);
    expect(await loadStoredGroupNames()).toBe(false);
  });

  it("still applies the owner check to stored names", async () => {
    store.entries = [
      { conversationId: "g1", name: "Real", at: "2026-10-22T08:00:00.000Z", senderUserId: OWNER },
      { conversationId: "g1", name: "Hijack", at: "2026-10-22T09:00:00.000Z", senderUserId: MEMBER },
    ];
    await loadStoredGroupNames();
    expect(groupName("g1", OWNER)).toBe("Real");
    // After a transfer the old owner's later names stop counting, stored or not.
    setGroupOwnerHistory("g1", [
      { ownerUserId: OWNER, from: "2026-10-01T00:00:00.000Z", until: "2026-10-22T08:30:00.000Z" },
      { ownerUserId: MEMBER, from: "2026-10-22T08:30:00.000Z", until: null },
    ]);
    expect(groupName("g1", MEMBER)).toBe("Hijack");
  });

  it("forgets a conversation here and in the store", () => {
    rememberGroupName("g1", "Ops room", "2026-10-22T08:00:00.000Z", OWNER);
    rememberGroupName("g2", "Other", "2026-10-22T08:00:00.000Z", OWNER);
    forgetStoredGroupName("g1");
    expect(groupName("g1", OWNER)).toBeNull();
    expect(groupName("g2", OWNER)).toBe("Other");
    expect(store.entries.map((entry) => entry.conversationId)).toEqual(["g2"]);
  });

  it("refuses a name without a readable time, and stores nothing outside the app shell", async () => {
    expect(rememberGroupName("g1", "Ops room", "not a time", OWNER)).toBe(false);
    store.tauri = false;
    expect(rememberGroupName("g1", "Ops room", "2026-10-22T08:00:00.000Z", OWNER)).toBe(true);
    expect(await loadStoredGroupNames()).toBe(false);
    expect(store.calls).toHaveLength(0);
  });
});
