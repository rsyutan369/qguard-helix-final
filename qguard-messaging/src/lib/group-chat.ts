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
 * control message, never in a database column, and like all decrypted content
 * it is kept in memory only (see chat-plaintext-cache.ts). Only the owner may
 * name a group (owner decision 2026-10-20): a name counts only if its sender
 * owned the group when it was sent, checked against the server's ownership
 * history (migration 042). After a cold start a group shows its members' names
 * until its thread is opened.
 */

/** Members besides yourself. Each member's devices are sealed to separately. */
export const GROUP_MAX_OTHER_MEMBERS = 31;
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
 * new, so the caller can re-render.
 */
export function rememberGroupName(conversationId: string, rawName: string, at: string, senderUserId: string): boolean {
  const name = sanitizeGroupName(rawName);
  if (!name || !senderUserId) return false;
  const list = candidates.get(conversationId) ?? [];
  if (list.some((item) => item.at === at && item.senderUserId === senderUserId && item.name === name)) return false;
  list.push({ name, at, senderUserId });
  candidates.set(conversationId, list);
  return true;
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

/** Validate a member selection; returns an error message, or null when fine. */
export function groupSelectionError(otherMemberIds: string[], name: string): string | null {
  if (!sanitizeGroupName(name)) return "Give the group a name.";
  const unique = new Set(otherMemberIds);
  if (unique.size < 2) return "Choose at least two people (for one person, start a direct chat).";
  if (unique.size > GROUP_MAX_OTHER_MEMBERS) return `A group can have at most ${GROUP_MAX_OTHER_MEMBERS + 1} people.`;
  return null;
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
