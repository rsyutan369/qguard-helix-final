import { afterEach, describe, expect, it } from "vitest";
import {
  GROUP_MAX_OTHER_MEMBERS,
  GROUP_NAME_MAX_CHARS,
  forgetGroupNames,
  groupFallbackTitle,
  groupName,
  groupPermissions,
  groupSelectionError,
  ownerAt,
  rememberGroupName,
  sanitizeGroupName,
  setGroupOwnerHistory,
  strongestRole,
} from "./group-chat";
import { clearChatPlaintextCaches, ensureChatCacheOwner } from "./chat-plaintext-cache";

afterEach(() => forgetGroupNames());

const OWNER = "owner-1";
const NEXT_OWNER = "owner-2";
const MEMBER = "member-1";

describe("group names", () => {
  it("strips control characters, collapses whitespace and caps length", () => {
    expect(sanitizeGroupName("  Team\u0000\n  Alpha\t ")).toBe("Team Alpha");
    expect(sanitizeGroupName("x".repeat(200))).toHaveLength(GROUP_NAME_MAX_CHARS);
    expect(sanitizeGroupName(" \u0007 ")).toBe("");
  });

  it("keeps the owner's newest name, whatever order history replays in", () => {
    expect(rememberGroupName("g1", "Renamed", "2026-10-19T11:00:00.000Z", OWNER)).toBe(true);
    expect(rememberGroupName("g1", "First", "2026-10-19T10:00:00.000Z", OWNER)).toBe(true);
    expect(rememberGroupName("g1", "First", "2026-10-19T10:00:00.000Z", OWNER)).toBe(false);
    expect(rememberGroupName("g1", "   ", "2026-10-19T12:00:00.000Z", OWNER)).toBe(false);
    expect(groupName("g1", OWNER)).toBe("Renamed");
    expect(groupName("g2", OWNER)).toBeNull();
  });

  it("ignores names from anyone but the owner (owner-only rename)", () => {
    rememberGroupName("g1", "Real name", "2026-10-19T10:00:00.000Z", OWNER);
    rememberGroupName("g1", "Hijacked", "2026-10-19T11:00:00.000Z", MEMBER);
    expect(groupName("g1", OWNER)).toBe("Real name");
    // Without a known owner nothing counts.
    expect(groupName("g1", null)).toBeNull();
  });

  it("honours each name by who owned the group when it was sent", () => {
    setGroupOwnerHistory("g1", [
      { ownerUserId: OWNER, from: "2026-10-01T00:00:00.000Z", until: "2026-10-19T12:00:00.000Z" },
      { ownerUserId: NEXT_OWNER, from: "2026-10-19T12:00:00.000Z", until: null },
    ]);
    rememberGroupName("g1", "Old owner's name", "2026-10-19T10:00:00.000Z", OWNER);
    expect(groupName("g1", NEXT_OWNER)).toBe("Old owner's name");
    // The previous owner can no longer rename after the transfer.
    rememberGroupName("g1", "Too late", "2026-10-19T13:00:00.000Z", OWNER);
    expect(groupName("g1", NEXT_OWNER)).toBe("Old owner's name");
    rememberGroupName("g1", "New owner's name", "2026-10-19T14:00:00.000Z", NEXT_OWNER);
    expect(groupName("g1", NEXT_OWNER)).toBe("New owner's name");
    // A name the new owner "sent" before owning the group never counts.
    forgetGroupNames();
    setGroupOwnerHistory("g1", [
      { ownerUserId: OWNER, from: "2026-10-01T00:00:00.000Z", until: "2026-10-19T12:00:00.000Z" },
      { ownerUserId: NEXT_OWNER, from: "2026-10-19T12:00:00.000Z", until: null },
    ]);
    rememberGroupName("g1", "Premature", "2026-10-19T11:00:00.000Z", NEXT_OWNER);
    expect(groupName("g1", NEXT_OWNER)).toBeNull();
  });

  it("finds the owner at a moment in the history", () => {
    const history = [
      { ownerUserId: OWNER, from: "2026-10-01T00:00:00.000Z", until: "2026-10-10T00:00:00.000Z" },
      { ownerUserId: NEXT_OWNER, from: "2026-10-10T00:00:00.000Z", until: null },
    ];
    expect(ownerAt(history, "2026-10-05T00:00:00.000Z")).toBe(OWNER);
    expect(ownerAt(history, "2026-10-10T00:00:00.000Z")).toBe(NEXT_OWNER);
    expect(ownerAt(history, "2026-09-01T00:00:00.000Z")).toBeNull();
  });

  it("is wiped with the decrypted-message caches", () => {
    rememberGroupName("g1", "Secret project", "2026-10-19T10:00:00.000Z", OWNER);
    clearChatPlaintextCaches();
    expect(groupName("g1", OWNER)).toBeNull();

    ensureChatCacheOwner("user-a", "device-a");
    rememberGroupName("g1", "Secret project", "2026-10-19T10:00:00.000Z", OWNER);
    ensureChatCacheOwner("user-b", "device-b");
    expect(groupName("g1", OWNER)).toBeNull();
  });

  it("falls back to a neutral title", () => {
    expect(groupFallbackTitle(1)).toBe("Group · 1 person");
    expect(groupFallbackTitle(4)).toBe("Group · 4 people");
  });
});

describe("member selection", () => {
  it("needs a name and at least two other people", () => {
    expect(groupSelectionError(["a", "b"], "  ")).toMatch(/name/);
    expect(groupSelectionError(["a"], "Team")).toMatch(/at least two/);
    expect(groupSelectionError(["a", "a"], "Team")).toMatch(/at least two/);
    expect(groupSelectionError(["a", "b"], "Team")).toBeNull();
  });

  it("caps the group size", () => {
    const max = Array.from({ length: GROUP_MAX_OTHER_MEMBERS }, (_, index) => `u${index}`);
    expect(groupSelectionError(max, "Team")).toBeNull();
    expect(groupSelectionError([...max, "one-more"], "Team")).toMatch(/at most 32/);
  });
});

describe("roles", () => {
  it("mirrors the server's rules", () => {
    const owner = groupPermissions("owner", "member", 0);
    expect(owner).toMatchObject({ rename: true, addMembers: true, remove: true, makeAdmin: true, transferTo: true, leave: false });
    expect(groupPermissions("owner", "member", 3).makeAdmin).toBe(false);
    expect(groupPermissions("owner", "admin", 3)).toMatchObject({ remove: true, dismissAdmin: true, makeAdmin: false });
    expect(groupPermissions("owner", "owner", 0)).toMatchObject({ remove: false, transferTo: false });

    const admin = groupPermissions("admin", "member", 1);
    expect(admin).toMatchObject({ rename: false, addMembers: true, remove: true, makeAdmin: false, transferTo: false, leave: true });
    expect(groupPermissions("admin", "admin", 2).remove).toBe(false);
    expect(groupPermissions("admin", "owner", 2).remove).toBe(false);

    expect(groupPermissions("member", "member", 0)).toMatchObject({ rename: false, addMembers: false, remove: false, leave: true });
  });

  it("takes the strongest role across a user's devices", () => {
    expect(strongestRole(["member", "admin"])).toBe("admin");
    expect(strongestRole(["member", "owner", "admin"])).toBe("owner");
    expect(strongestRole([])).toBe("member");
  });
});
