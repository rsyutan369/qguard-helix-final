/**
 * Group calls (roadmap 7.2; owner decision 2026-10-20: direct connections
 * between up to 3 people).
 *
 * A group call is a MESH of ordinary one-to-one calls — each link with its own
 * hybrid X25519 + ML-KEM-1024 setup to the other device, its own media key and
 * its own per-frame AES-256-GCM transform — tied together by a group invite
 * carried on each link's ring and offer. Nothing is shared between links, so
 * a participant can only ever decrypt the links they are an end of.
 *
 * Who connects to whom: the inviter rings everyone; once you join, you ring
 * each other invited member whose user id sorts after yours. So every pair is
 * linked exactly once, and a link to someone who has joined is accepted
 * without ringing — but ONLY for a group call you already accepted, from a
 * member of that same invite, in the same conversation.
 */

/** Everyone in the call, including you. */
export const GROUP_CALL_MAX_PEOPLE = 3;

export interface GroupInvite {
  id: string;
  conversationId: string;
  inviterUserId: string;
  /** Every invited person's user id, the inviter included. */
  members: string[];
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function makeGroupInvite(conversationId: string, inviterUserId: string, others: string[]): GroupInvite {
  const members = Array.from(new Set([inviterUserId, ...others]));
  if (members.length < 3) throw new Error("A group call needs three people; for two, use a normal call.");
  if (members.length > GROUP_CALL_MAX_PEOPLE) throw new Error(`A group call can have at most ${GROUP_CALL_MAX_PEOPLE} people.`);
  return { id: crypto.randomUUID(), conversationId, inviterUserId, members };
}

/** A group invite from a signal's payload, or null when malformed. */
export function parseGroupInvite(raw: unknown): GroupInvite | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const value = raw as Record<string, unknown>;
  const members = Array.isArray(value.members) ? value.members.filter((item): item is string => typeof item === "string" && UUID.test(item)) : [];
  const unique = Array.from(new Set(members));
  if (typeof value.id !== "string" || !UUID.test(value.id)) return null;
  if (typeof value.conversationId !== "string" || !UUID.test(value.conversationId)) return null;
  if (typeof value.inviterUserId !== "string" || !unique.includes(value.inviterUserId)) return null;
  if (unique.length < 2 || unique.length > GROUP_CALL_MAX_PEOPLE || unique.length !== members.length) return null;
  return { id: value.id, conversationId: value.conversationId, inviterUserId: value.inviterUserId, members: unique };
}

/**
 * May this ring join (or open) the group call on this device?
 *   - no group yet: a fresh invite that names me, from one of its members;
 *   - a group already: only a link of THAT call, from a member of it, in the
 *     same conversation — a different group call is busy.
 */
export function admitGroupRing(input: {
  invite: GroupInvite;
  fromUserId: string;
  conversationId: string;
  myUserId: string;
  current: GroupInvite | null;
  oneToOneBusy: boolean;
}): boolean {
  const { invite, fromUserId, conversationId, myUserId, current, oneToOneBusy } = input;
  if (oneToOneBusy) return false;
  if (invite.conversationId !== conversationId) return false;
  if (!invite.members.includes(myUserId) || !invite.members.includes(fromUserId) || fromUserId === myUserId) return false;
  if (!current) return true;
  if (current.id !== invite.id || current.conversationId !== invite.conversationId) return false;
  // The invite on a later link must not add people to the call.
  return invite.members.every((member) => current.members.includes(member));
}

/** Whom I ring after joining: members sorting after me, not yet linked. */
export function meshTargets(invite: GroupInvite, myUserId: string, linkedUserIds: Iterable<string>): string[] {
  const linked = new Set(linkedUserIds);
  return invite.members
    .filter((member) => member !== myUserId && member !== invite.inviterUserId && !linked.has(member) && member > myUserId)
    .sort();
}

/** Free link slots, in order. */
export const GROUP_LINK_SLOTS = ["group-1", "group-2"] as const;
export type GroupLinkSlot = (typeof GROUP_LINK_SLOTS)[number];
