import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_MEMBER_LIMITS,
  GROUP_MAX_OTHER_MEMBERS,
  GROUP_NAME_MAX_CHARS,
  conversationFallbackTitle,
  conversationKind,
  formatMemberLimit,
  forgetGroupNames,
  groupFallbackTitle,
  parseMemberLimits,
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
    expect(groupSelectionError([...max, "one-more"], "Team")).toMatch(/at most 32 .*large group for up to 1,000/);
  });

  it("lets a large group start small and grow to 1,000", () => {
    expect(groupSelectionError([], "Town hall", "large_group")).toBeNull();
    const full = Array.from({ length: 999 }, (_, index) => `u${index}`);
    expect(groupSelectionError(full, "Town hall", "large_group")).toBeNull();
    expect(groupSelectionError([...full, "one-more"], "Town hall", "large_group")).toMatch(/at most 1,000/);
  });

  it("follows the server's limits once they are read", () => {
    const limits = parseMemberLimits([{ kind: "large_group", max_members: 10000 }, { kind: "group", max_members: 32 }]);
    expect(limits).toEqual({ group: 32, large_group: 10000, channel: 1000 });
    const many = Array.from({ length: 5000 }, (_, index) => `u${index}`);
    expect(groupSelectionError(many, "Town hall", "large_group", limits)).toBeNull();
  });
});

describe("member limits", () => {
  it("keeps the defaults for missing, unknown or nonsense rows", () => {
    expect(parseMemberLimits(null)).toEqual(DEFAULT_MEMBER_LIMITS);
    expect(parseMemberLimits([{ kind: "mega", max_members: 5 }, { kind: "channel", max_members: "lots" }, { kind: "group", max_members: 1 }]))
      .toEqual(DEFAULT_MEMBER_LIMITS);
    expect(DEFAULT_MEMBER_LIMITS).toEqual({ group: 32, large_group: 1000, channel: 1000 });
  });

  it("formats limits the way people read them", () => {
    expect(formatMemberLimit(1000)).toBe("1,000");
    expect(formatMemberLimit(100000)).toBe("100,000");
  });
});

describe("conversation kinds and titles", () => {
  it("tells groups, large groups and channels apart", () => {
    expect(conversationKind({ conversation_type: "group" })).toBe("group");
    expect(conversationKind({ conversation_type: "channel", member_posting: true })).toBe("large_group");
    expect(conversationKind({ conversation_type: "channel", member_posting: false })).toBe("channel");
    expect(conversationKind({ conversation_type: "channel" })).toBe("channel");
    expect(conversationKind({ conversation_type: "direct" })).toBeNull();
  });

  it("never falls back to a generic \"Encrypted … conversation\" label", () => {
    expect(conversationFallbackTitle("channel", 1, "")).toBe("Channel");
    // A reader sees only the staff, so their names would read like a direct chat.
    expect(conversationFallbackTitle("channel", 2, "Owner Person")).toBe("Channel");
    expect(conversationFallbackTitle("group", 3, "Ana, Ben")).toBe("Ana, Ben");
    expect(conversationFallbackTitle("group", 3, "")).toBe("Group · 3 people");
    expect(conversationFallbackTitle("large_group", 1, "")).toBe("Large group · 1 person");
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
