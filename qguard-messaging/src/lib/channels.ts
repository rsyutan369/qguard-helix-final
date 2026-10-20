/**
 * Channels (roadmap 7.4; owner decision 2026-10-20): one sender to many
 * readers. Crypto lives in the core (src-tauri/src/commands/channels.rs);
 * this module decides WHO needs the current epoch key and WHEN a new epoch is
 * due, and maps posts between the core and the `messaging_channel_posts` table
 * (migration 043). Design: docs/superpowers/specs/2026-10-19-groups-design.md §5.
 */

export interface ChannelStatus {
  channelId: string;
  currentEpoch: string | null;
  currentSeq: number | null;
  /** Devices / users the current epoch key was handed to. */
  recipients: string[];
  recipientUsers: string[];
  epochsHeld: number;
}

export interface DualSignatureJson {
  ed25519: number[];
  ml_dsa_65: number[];
}

/** A post as the core seals and opens it. */
export interface SealedChannelPost {
  postId: string;
  channelId: string;
  epochId: string;
  senderUserId: string;
  senderDeviceId: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  signature: DualSignatureJson;
}

/** A row of `messaging_channel_posts`. */
export interface ChannelPostRow {
  id: string;
  conversation_id: string;
  sender_user_id: string;
  sender_device_id: string;
  epoch_id: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  signature: DualSignatureJson;
  created_at: string;
}

export function sealedToRow(post: SealedChannelPost): Omit<ChannelPostRow, "created_at"> {
  return {
    id: post.postId,
    conversation_id: post.channelId,
    sender_user_id: post.senderUserId,
    sender_device_id: post.senderDeviceId,
    epoch_id: post.epochId,
    nonce: post.nonce,
    ciphertext: post.ciphertext,
    tag: post.tag,
    signature: post.signature,
  };
}

export function rowToSealed(row: ChannelPostRow): SealedChannelPost {
  return {
    postId: String(row.id),
    channelId: String(row.conversation_id),
    epochId: String(row.epoch_id),
    senderUserId: String(row.sender_user_id),
    senderDeviceId: String(row.sender_device_id),
    nonce: String(row.nonce),
    ciphertext: String(row.ciphertext),
    tag: String(row.tag),
    signature: row.signature,
  };
}

export interface ReaderDevice {
  deviceId: string;
  userId: string;
}

export interface KeyDistributionPlan {
  /** No epoch on this device yet: make one before anything else. */
  needsEpoch: boolean;
  /** Someone who received the current key is no longer a member: start a new epoch. */
  rotate: boolean;
  /** Devices to hand the (current or new) epoch key to. */
  missing: ReaderDevice[];
}

/**
 * What a staff device must do so that exactly the current members can read:
 * a first epoch, a new epoch when anyone who held the current one has left or
 * been removed, and the key for every member device that has not had it.
 */
export function planKeyDistribution(input: {
  status: ChannelStatus;
  memberUserIds: string[];
  memberDevices: ReaderDevice[];
  myUserId: string;
}): KeyDistributionPlan {
  const members = new Set(input.memberUserIds);
  const others = input.memberDevices.filter((device) => device.userId !== input.myUserId && members.has(device.userId));
  const needsEpoch = !input.status.currentEpoch;
  const rotate = !needsEpoch && input.status.recipientUsers.some((user) => !members.has(user));
  const handed = new Set(input.status.recipients);
  const missing = needsEpoch || rotate ? others : others.filter((device) => !handed.has(device.deviceId));
  return { needsEpoch, rotate, missing };
}

/** Key hand-outs are sealed in batches of this many devices. */
export const CHANNEL_KEY_BATCH = 50;

export function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let index = 0; index < items.length; index += size) out.push(items.slice(index, index + size));
  return out;
}

export const CHANNEL_INVITE_CHOICES = [
  { label: "1 person · 24 hours", hours: 24, uses: 1 },
  { label: "10 people · 7 days", hours: 24 * 7, uses: 10 },
  { label: "100 people · 30 days", hours: 24 * 30, uses: 100 },
] as const;

/** An invite code as typed or pasted: 32 hex characters, spaces and dashes ignored. */
export function normalizeInviteCode(raw: string): string | null {
  const code = raw.replace(/[\s-]/g, "").toLowerCase();
  return /^[0-9a-f]{32}$/.test(code) ? code : null;
}

/** Shown in groups of four so it can be read aloud. */
export function formatInviteCode(code: string): string {
  return code.replace(/(.{4})(?=.)/g, "$1-");
}
