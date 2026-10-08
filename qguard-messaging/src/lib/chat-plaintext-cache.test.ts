import { beforeEach, describe, expect, it } from "vitest";
import {
  chatHistorySnapshot,
  chatMessageCache,
  clearChatHistorySnapshot,
  clearChatPlaintextCaches,
  ensureChatCacheOwner,
  setChatHistorySnapshot,
} from "./chat-plaintext-cache";

beforeEach(() => {
  clearChatPlaintextCaches();
});

describe("history snapshots", () => {
  it("returns the thread last rendered for a conversation", () => {
    setChatHistorySnapshot("conversation-1", [{ id: "a" }, { id: "b" }]);
    expect(chatHistorySnapshot<{ id: string }>("conversation-1")).toEqual([{ id: "a" }, { id: "b" }]);
  });

  it("distinguishes 'never opened' from 'opened and empty'", () => {
    // These must not collapse: an unopened conversation has to load, while a
    // genuinely empty one should render its empty state instantly rather than
    // showing a spinner that resolves to nothing.
    expect(chatHistorySnapshot("conversation-1")).toBeNull();
    setChatHistorySnapshot("conversation-1", []);
    expect(chatHistorySnapshot("conversation-1")).toEqual([]);
  });

  it("hands back a copy, so downstream mutation cannot corrupt the cache", () => {
    setChatHistorySnapshot("conversation-1", [{ id: "a" }]);
    const first = chatHistorySnapshot<{ id: string }>("conversation-1");
    first?.push({ id: "injected" });
    expect(chatHistorySnapshot("conversation-1")).toHaveLength(1);
  });

  it("ignores a blank conversation id", () => {
    setChatHistorySnapshot("", [{ id: "a" }]);
    expect(chatHistorySnapshot("")).toBeNull();
  });

  it("evicts the least recently written conversation beyond the bound", () => {
    for (let index = 0; index < 10; index += 1) {
      setChatHistorySnapshot(`conversation-${index}`, [{ id: String(index) }]);
    }
    expect(chatHistorySnapshot("conversation-0")).toBeNull();
    expect(chatHistorySnapshot("conversation-1")).toBeNull();
    expect(chatHistorySnapshot("conversation-9")).not.toBeNull();
  });

  it("treats a re-write as a fresh use for eviction ordering", () => {
    setChatHistorySnapshot("keep-me", [{ id: "x" }]);
    for (let index = 0; index < 7; index += 1) {
      setChatHistorySnapshot(`filler-${index}`, [{ id: String(index) }]);
    }
    // One more write would evict "keep-me" if it were still the oldest.
    setChatHistorySnapshot("keep-me", [{ id: "x2" }]);
    setChatHistorySnapshot("newcomer", [{ id: "n" }]);
    expect(chatHistorySnapshot("keep-me")).toEqual([{ id: "x2" }]);
  });

  it("forgets a single conversation on request", () => {
    setChatHistorySnapshot("conversation-1", [{ id: "a" }]);
    setChatHistorySnapshot("conversation-2", [{ id: "b" }]);
    clearChatHistorySnapshot("conversation-1");
    expect(chatHistorySnapshot("conversation-1")).toBeNull();
    expect(chatHistorySnapshot("conversation-2")).not.toBeNull();
  });
});

describe("snapshot wipe semantics", () => {
  it("is wiped by the workspace lock / logout path", () => {
    // Snapshots hold decrypted plaintext, so every path that wipes the other
    // plaintext caches MUST wipe these too.
    setChatHistorySnapshot("conversation-1", [{ id: "a" }]);
    clearChatPlaintextCaches();
    expect(chatHistorySnapshot("conversation-1")).toBeNull();
  });

  it("is wiped when a different user takes over the session", () => {
    ensureChatCacheOwner("user-1", "device-1");
    setChatHistorySnapshot("conversation-1", [{ id: "a" }]);
    ensureChatCacheOwner("user-2", "device-2");
    expect(chatHistorySnapshot("conversation-1")).toBeNull();
  });

  it("is wiped when the same user switches to a genuinely different device", () => {
    ensureChatCacheOwner("user-1", "device-1");
    setChatHistorySnapshot("conversation-1", [{ id: "a" }]);
    ensureChatCacheOwner("user-1", "device-2");
    expect(chatHistorySnapshot("conversation-1")).toBeNull();
  });

  it("survives the remount where the device is not resolved yet", () => {
    // Adopting an unknown device is what keeps the warm cache across a remount;
    // wiping there would reintroduce the full decrypt on every page revisit.
    ensureChatCacheOwner("user-1", "device-1");
    setChatHistorySnapshot("conversation-1", [{ id: "a" }]);
    ensureChatCacheOwner("user-1", null);
    expect(chatHistorySnapshot("conversation-1")).toEqual([{ id: "a" }]);
    ensureChatCacheOwner("user-1", "device-1");
    expect(chatHistorySnapshot("conversation-1")).toEqual([{ id: "a" }]);
  });

  it("keeps the per-group decrypt cache and the snapshots consistent on wipe", () => {
    ensureChatCacheOwner("user-1", "device-1");
    chatMessageCache<{ id: string }>().set("group-1", { id: "a" });
    setChatHistorySnapshot("conversation-1", [{ id: "a" }]);
    ensureChatCacheOwner("user-2", "device-9");
    expect(chatMessageCache().size).toBe(0);
    expect(chatHistorySnapshot("conversation-1")).toBeNull();
  });
});
