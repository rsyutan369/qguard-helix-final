/**
 * Group chats (roadmap 7.1).
 *
 * A group is a `messaging_conversations` row of type `group` whose members'
 * devices each get their own sealed copy of every message — the same per-device
 * fan-out, pins, signatures and (opt-in) ratchet sessions as a direct chat.
 * Nothing about a group is shared key material, so removing someone needs no
 * re-keying: their devices simply stop being delivery targets. (MLS, RFC 9420,
 * was evaluated — see docs/superpowers/specs/2026-10-19-groups-design.md.)
 *
 * The group's NAME is end-to-end encrypted: it travels as a `group_meta`
 * control message (or inside a channel key hand-out), never in a database
 * column. Only the owner may name a group (owner decision 2026-10-20): a name
 * counts only if its sender owned the group when it was sent, checked against
 * the server's ownership history (migration 042).
 *
 * Accepted names are kept in memory (wiped with the plaintext caches, see
 * chat-plaintext-cache.ts) AND in the core's encrypted per-user storage
 * (commands/conversation_names.rs), so the conversation list shows them after
 * a restart instead of a generic label, and a channel nobody has joined yet
 * keeps its name. Only names that arrived authenticated, or that this account
 * sent, are ever passed to rememberGroupName; the owner check still runs on
 * every read, so a stored name cannot outlive an ownership change.
 *
 * Sizes (migration 047): a group seals every message once per member device,
 * so it stays at 32 people. A large group (a channel whose members all post)
 * and a channel encrypt each post once, and start at 1,000. The server holds
 * the real limits in messaging_conversation_limits; these are the defaults
 * used until that table has been read.
 */

import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

export type ConversationKind = "group" | "large_group" | "channel";

export type MemberLimits = Record<ConversationKind, number>;

export const DEFAULT_MEMBER_LIMITS: MemberLimits = { group: 32, large_group: 1000, channel: 1000 };

/** Members besides yourself in a group. Each member's devices are sealed to separately. */
export const GROUP_MAX_OTHER_MEMBERS = DEFAULT_MEMBER_LIMITS.group - 1;
export const GROUP_NAME_MAX_CHARS = 64;
/** Admins besides the owner (migration 042 enforces the same cap). */
export const GROUP_MAX_ADMINS = 3;

export type GroupRole = "owner" | "admin" | "member";

export interface GroupOwnerPeriod {
  ownerUserId: string;
  from: string;
  until: string | null;
}

interface NameCandidate {
  name: string;
  at: string;
  senderUserId: string;
}

const candidates = new Map<string, NameCandidate[]>();
const ownerHistories = new Map<string, GroupOwnerPeriod[]>();

export function sanitizeGroupName(raw: string): string {
  return raw.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, GROUP_NAME_MAX_CHARS);
}

/**
 * Record a `group_meta` name (whoever sent it; validity is decided when the
 * name is read, once the ownership history is known). Returns true when it is
 * new, so the caller can re-render. New names are also stored on this device
 * unless `persist` is false (names just read back from that store).
 */
export function rememberGroupName(
  conversationId: string,
  rawName: string,
  at: string,
  senderUserId: string,
  options: { persist?: boolean } = {},
): boolean {
  const name = sanitizeGroupName(rawName);
  if (!name || !senderUserId || Number.isNaN(new Date(at).getTime())) return false;
  const list = candidates.get(conversationId) ?? [];
  if (list.some((item) => item.at === at && item.senderUserId === senderUserId && item.name === name)) return false;
  list.push({ name, at, senderUserId });
  candidates.set(conversationId, list);
  if (options.persist !== false && isTauriRuntime()) {
    const entry = { conversationId, name, at: new Date(at).toISOString(), senderUserId };
    void safeInvoke("conversation_names_remember", { entries: [entry] })
      .catch((error) => console.warn("[group-chat] Name not stored on this device:", error));
  }
  return true;
}

/**
 * Read back the names stored on this device (after a start or an unlock).
 * Returns true when any was new to memory. Outside the app shell there is no
 * store and nothing changes.
 */
export async function loadStoredGroupNames(): Promise<boolean> {
  if (!isTauriRuntime()) return false;
  const stored = await safeInvoke<Array<{ conversationId: string; name: string; at: string; senderUserId: string }>>("conversation_names_list");
  let changed = false;
  for (const entry of stored) {
    if (rememberGroupName(entry.conversationId, entry.name, entry.at, entry.senderUserId, { persist: false })) changed = true;
  }
  return changed;
}

/** Forget one conversation's names here and on this device (left, removed, deleted). */
export function forgetStoredGroupName(conversationId: string): void {
  candidates.delete(conversationId);
  ownerHistories.delete(conversationId);
  if (isTauriRuntime()) {
    void safeInvoke("conversation_names_forget", { conversationId })
      .catch((error) => console.warn("[group-chat] Stored name not removed:", error));
  }
}

export function setGroupOwnerHistory(conversationId: string, history: GroupOwnerPeriod[]): void {
  ownerHistories.set(conversationId, history);
}

/** Who owned the group at `at`, per the server's history; null when unknown. */
export function ownerAt(history: readonly GroupOwnerPeriod[], at: string): string | null {
  const time = new Date(at).getTime();
  const period = history.find((item) => (
    new Date(item.from).getTime() <= time && (item.until === null || time < new Date(item.until).getTime())
  ));
  return period?.ownerUserId ?? null;
}

/**
 * The group's name: the newest one sent by whoever owned the group at the
 * time. Until the history is loaded, only the current owner's names count.
 */
export function groupName(conversationId: string, currentOwnerUserId?: string | null): string | null {
  const history = ownerHistories.get(conversationId);
  const valid = (candidates.get(conversationId) ?? []).filter((item) => (
    history && history.length > 0
      ? ownerAt(history, item.at) === item.senderUserId
      : Boolean(currentOwnerUserId) && item.senderUserId === currentOwnerUserId
  ));
  if (valid.length === 0) return null;
  return valid.reduce((newest, item) => (new Date(item.at).getTime() > new Date(newest.at).getTime() ? item : newest)).name;
}

export function forgetGroupNames(): void {
  candidates.clear();
  ownerHistories.clear();
}

export function groupFallbackTitle(memberCount: number): string {
  return `Group · ${memberCount} ${memberCount === 1 ? "person" : "people"}`;
}

/** Which size class a multi-party conversation is in; null for a direct chat. */
export function conversationKind(conversation: { conversation_type: string; member_posting?: boolean | null }): ConversationKind | null {
  if (conversation.conversation_type === "group") return "group";
  if (conversation.conversation_type === "channel") return conversation.member_posting ? "large_group" : "channel";
  return null;
}

export function conversationKindLabel(kind: ConversationKind): string {
  if (kind === "large_group") return "Large group";
  if (kind === "channel") return "Channel";
  return "Group";
}

/**
 * The title until the encrypted name is known. It says what the conversation
 * is rather than "Encrypted channel conversation". A channel reader sees only
 * the staff, whose names would read like a direct chat, so they are not used.
 */
export function conversationFallbackTitle(kind: ConversationKind, memberCount: number, memberNames: string): string {
  if (kind === "channel") return "Channel";
  if (memberNames) return memberNames;
  return kind === "large_group"
    ? `Large group · ${memberCount} ${memberCount === 1 ? "person" : "people"}`
    : groupFallbackTitle(memberCount);
}

/** "1,000": limits are shown the way people read them. */
export function formatMemberLimit(limit: number): string {
  return limit.toLocaleString("en-US");
}

/**
 * Validate a member selection; returns an error message, or null when fine.
 * A group needs two other people (one is a direct chat); a large group may
 * start with nobody else, since most people join it with an invite code.
 */
export function groupSelectionError(
  otherMemberIds: string[],
  name: string,
  kind: Exclude<ConversationKind, "channel"> = "group",
  limits: MemberLimits = DEFAULT_MEMBER_LIMITS,
): string | null {
  if (!sanitizeGroupName(name)) return "Give the group a name.";
  const unique = new Set(otherMemberIds);
  if (kind === "group" && unique.size < 2) return "Choose at least two people (for one person, start a direct chat).";
  const max = limits[kind];
  if (unique.size + 1 > max) {
    return kind === "group"
      ? `A group can have at most ${formatMemberLimit(max)} people. Make it a large group for up to ${formatMemberLimit(limits.large_group)}.`
      : `A large group can have at most ${formatMemberLimit(max)} people.`;
  }
  return null;
}

/**
 * The server's limits (migration 047), from rows of
 * messaging_conversation_limits. Unknown or missing rows keep the defaults,
 * which match what the server enforced before that table existed.
 */
export function parseMemberLimits(rows: ReadonlyArray<{ kind?: unknown; max_members?: unknown }> | null | undefined): MemberLimits {
  const limits = { ...DEFAULT_MEMBER_LIMITS };
  for (const row of rows ?? []) {
    const kind = String(row.kind ?? "");
    const max = Number(row.max_members);
    if (kind in limits && Number.isSafeInteger(max) && max >= 2) limits[kind as ConversationKind] = max;
  }
  return limits;
}

/** What `actor` may do to `target` in a group — mirrors migration 042's checks. */
export function groupPermissions(actorRole: GroupRole | null, targetRole: GroupRole | null, adminCount: number) {
  const isOwner = actorRole === "owner";
  const isAdmin = actorRole === "admin";
  return {
    rename: isOwner,
    addMembers: isOwner || isAdmin,
    remove: targetRole !== null && targetRole !== "owner" && (isOwner || (isAdmin && targetRole === "member")),
    makeAdmin: isOwner && targetRole === "member" && adminCount < GROUP_MAX_ADMINS,
    dismissAdmin: isOwner && targetRole === "admin",
    transferTo: isOwner && targetRole !== null && targetRole !== "owner",
    leave: actorRole !== null && actorRole !== "owner",
  };
}

/** Strongest role a user holds across their device rows. */
export function strongestRole(roles: Iterable<string>): GroupRole {
  let best: GroupRole = "member";
  for (const role of roles) {
    if (role === "owner") return "owner";
    if (role === "admin") best = "admin";
  }
  return best;
}
