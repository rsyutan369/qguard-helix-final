// Quantum Vault phase 4 — share a stored file with other QGuard users.
//
// One encrypted copy (the file's cloud object) however many people it goes
// to. Cloud backup is optional and never required: a file without a cloud
// copy gets one when it is shared (only that file), and with backup off that
// copy is taken back once no share uses it. Each recipient DEVICE gets an
// envelope sealed and signed by this device in the Rust core
// (src-tauri/src/commands/vault_share.rs); this module stores and fetches those
// envelopes and the share's terms in Supabase (migration 049), which decides
// who may download the object: recipients who accepted, while the share is
// neither revoked nor expired.

import { callPeerIdentityFromRow, fetchCallPeerIdentity } from "@/lib/call-peer-identity";
import type { CallPeerIdentityPayload } from "@/lib/call-targets";
import { ipcArrayBuffer } from "@/lib/encoding";
import { requireSupabase } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";
import { CloudError, describeCloudError, downloadObject, uploadShareCopy, vaultCloudCore, type CloudObjectRow } from "@/lib/vault-cloud";
import type { StoreEntry } from "@/lib/vault-store";

export type SharePermission = "view" | "download";

export interface PersonResult {
  userId: string;
  displayName: string;
  username: string | null;
}

/** A file shared with this account, as opened on this device. */
export interface IncomingShare {
  shareId: string;
  ownerUserId: string;
  ownerName: string;
  status: "pending" | "accepted";
  permission: SharePermission;
  expiresAt: string | null;
  sharedAt: string;
  /** Opened from this device's envelope; null when there is none for it yet. */
  file: SharedFileInfo | null;
  envelope: unknown | null;
  sender: CallPeerIdentityPayload | null;
  /** Why the envelope could not be opened (tampered, unknown sender device…). */
  problem: string | null;
}

export interface SharedFileInfo {
  shareId: string;
  ownerUserId: string;
  objectId: string;
  fileId: string;
  containerSha3: string;
  name: string;
  contentType: string;
  category: string;
  sizeBytes: number;
  permission: SharePermission;
  expiresAt: number | null;
  createdAt: number;
}

export interface OutgoingShare {
  shareId: string;
  objectId: string;
  fileName: string;
  permission: SharePermission;
  expiresAt: string | null;
  createdAt: string;
  revokedAt: string | null;
  recipients: Array<{ userId: string; name: string; status: string; respondedAt: string | null }>;
  events: Array<{ event: string; actor: string; at: string }>;
}

interface SealedShare {
  envelopes: Array<{ recipientUserId: string; recipientDeviceId: string; senderDeviceId: string } & Record<string, unknown>>;
  skipped: Array<{ userId: string; deviceId: string; reason: string }>;
}

const SHARE_MESSAGES: Record<string, string> = {
  QV_NO_CLOUD_ENTITLEMENT: "Sharing keeps one encrypted copy of the file in the cloud, and your plan does not include cloud storage (or the subscription has lapsed).",
  QV_QUOTA_EXCEEDED: "Your cloud storage is full, so this file cannot be shared until space is freed or your plan is upgraded.",
  QV_OBJECT_NOT_FOUND: "This file's encrypted cloud copy is no longer there. Try sharing it again.",
  QV_SHARE_NOT_AVAILABLE: "This share is no longer available (it was revoked or has expired).",
  QV_INVALID_EXPIRY: "Choose an expiry within the next year.",
  QV_INVALID_RECIPIENTS: "Choose at least one person (up to 50).",
  QV_SHARES_UNCHECKED: "Your shares could not all be checked, so nothing was removed. Try again.",
  VAULT_SHARE_EXPIRED: "This share has expired.",
};

export function describeShareError(error: unknown): string {
  // A CloudError from the upload carries backup wording; sharing words it its own way.
  if (error instanceof CloudError && SHARE_MESSAGES[error.code]) return SHARE_MESSAGES[error.code];
  const raw = error instanceof Error ? error.message : typeof error === "object" && error && "message" in error ? String((error as { message: unknown }).message) : String(error);
  for (const [code, message] of Object.entries(SHARE_MESSAGES)) if (raw.includes(code)) return message;
  return describeCloudError(error);
}

function fail(error: { message?: string } | null): never {
  const raw = error?.message ?? "Unknown error";
  const code = raw.match(/QV_[A-Z_]+/)?.[0] ?? "QV_UNKNOWN";
  throw new CloudError(code, SHARE_MESSAGES[code] ?? raw);
}

async function displayNames(ids: string[]): Promise<Map<string, string>> {
  const names = new Map<string, string>();
  if (ids.length === 0) return names;
  const { data } = await requireSupabase().from("profiles").select("id,name,username").in("id", ids);
  for (const row of (data ?? []) as Array<{ id: string; name: string | null; username: string | null }>) {
    names.set(row.id, row.name || (row.username ? `@${row.username}` : "QGuard user"));
  }
  return names;
}

/** Directory search (same rate-limited RPC as Secure Chat). */
export async function searchPeople(query: string): Promise<PersonResult[]> {
  const normalized = query.trim().toLowerCase().replace(/^@/, "");
  if (normalized.length < 3) return [];
  const { data, error } = await requireSupabase().rpc("search_messaging_users", { p_query: normalized });
  if (error) {
    if (/too many searches/i.test(error.message)) throw new CloudError("QV_RATE", "Too many searches. Wait a moment and try again.");
    throw error;
  }
  return ((data ?? []) as Array<{ user_id: string; display_name: string | null; username: string | null }>).map((row) => ({
    userId: row.user_id,
    displayName: row.display_name || (row.username ? `@${row.username}` : "QGuard user"),
    username: row.username,
  }));
}

async function liveDevicesOf(userIds: string[]): Promise<CallPeerIdentityPayload[]> {
  if (userIds.length === 0) return [];
  const { data, error } = await requireSupabase()
    .from("messaging_devices")
    .select("id,user_id,revoked_at,trust_state,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature")
    .in("user_id", userIds);
  if (error) throw error;
  return ((data ?? []) as Array<Record<string, unknown>>)
    .filter((row) => !row.revoked_at && row.trust_state !== "revoked")
    .map((row) => callPeerIdentityFromRow(row))
    .filter((identity): identity is CallPeerIdentityPayload => identity !== null);
}

async function sealAndStore(
  entry: StoreEntry,
  shareId: string,
  object: { id: string; container_sha3: string },
  permission: SharePermission,
  expiresAt: Date | null,
  recipients: CallPeerIdentityPayload[],
): Promise<SealedShare> {
  const sealed = await safeInvoke<SealedShare>("vault_share_seal", {
    request: {
      shareId,
      entryId: entry.id,
      objectId: object.id,
      containerSha3: object.container_sha3,
      permission,
      expiresAt: expiresAt ? Math.floor(expiresAt.getTime() / 1000) : null,
      recipients,
    },
  });
  if (sealed.envelopes.length > 0) {
    const { error } = await requireSupabase()
      .from("qv_share_envelopes")
      .upsert(
        sealed.envelopes.map((envelope) => ({
          share_id: shareId,
          recipient_user_id: envelope.recipientUserId,
          recipient_device_id: envelope.recipientDeviceId,
          sender_device_id: envelope.senderDeviceId,
          envelope,
        })),
        { onConflict: "share_id,recipient_device_id", ignoreDuplicates: true },
      );
    if (error) throw error;
  }
  return sealed;
}

/**
 * Share a file. One without a cloud copy gets one first: the encrypted
 * container of THIS file only, uploaded whether or not cloud backup is on
 * (`onUpload` reports its progress). Returns how many people got it and any
 * device that could not be included (and why). People who blocked you are left
 * out by the server without telling you, exactly as with messages.
 */
export async function createShare(
  userId: string,
  entry: StoreEntry,
  recipients: PersonResult[],
  permission: SharePermission,
  expiresAt: Date | null,
  onUpload?: (bytesDone: number, bytesTotal: number) => void,
): Promise<{ shareId: string; people: number; devices: number; skipped: string[] }> {
  if (recipients.length === 0 || recipients.length > 50) {
    throw new CloudError("QV_INVALID_RECIPIENTS", SHARE_MESSAGES.QV_INVALID_RECIPIENTS);
  }
  const client = requireSupabase();
  const uploaded = !entry.cloudObjectId;
  const objectId = entry.cloudObjectId ?? (await uploadShareCopy(userId, entry.id, onUpload));
  try {
    const { data: object, error: objectError } = await client
      .from("qv_cloud_objects")
      .select("id,container_sha3,status")
      .eq("id", objectId)
      .maybeSingle();
    if (objectError) throw objectError;
    if (!object || object.status !== "committed") throw new CloudError("QV_OBJECT_NOT_FOUND", SHARE_MESSAGES.QV_OBJECT_NOT_FOUND);

    const { data, error } = await client.rpc("qv_share_create", {
      p_object_id: object.id,
      p_recipients: recipients.map((person) => person.userId),
      p_permission: permission,
      p_expires_at: expiresAt ? expiresAt.toISOString() : null,
    });
    if (error) fail(error);
    const created = data as { share_id: string; recipients: string[] };
    const included = created.recipients ?? [];
    const devices = await liveDevicesOf(included);
    const sealed = await sealAndStore(entry, created.share_id, object, permission, expiresAt, devices);
    if (sealed.envelopes.length === 0) {
      await client.rpc("qv_share_revoke", { p_share_id: created.share_id, p_recipient: null });
      throw new CloudError(
        "QV_NO_DEVICES",
        "None of these people has a device this file could be sealed to yet." + (sealed.skipped.length ? ` (${sealed.skipped[0].reason})` : ""),
      );
    }
    const peopleReached = new Set(sealed.envelopes.map((e) => e.recipientUserId)).size;
    return {
      shareId: created.share_id,
      people: peopleReached,
      devices: sealed.envelopes.length,
      skipped: sealed.skipped.map((s) => s.reason),
    };
  } catch (error) {
    // The copy made for this share goes again when no share came of it. The
    // core keeps it if it is a backup (backup on) rather than a shared copy.
    if (uploaded) await vaultCloudCore.releaseShareCopy(entry.id, objectId).catch(() => false);
    throw error;
  }
}

/** A copy this new may still be getting its share (see createShare). */
const SHARE_COPY_GRACE_MS = 15 * 60 * 1000;
/** PostgREST's default row cap: a full page means some rows were not seen. */
const ROW_CAP = 1000;

/**
 * Cloud objects of this account that a live share still uses: not revoked,
 * not expired, with at least one recipient who neither declined nor was
 * removed. Throws rather than answer from a partial list — a share missed here
 * would lose its file.
 */
export async function liveSharedObjectIds(userId: string): Promise<Set<string>> {
  const client = requireSupabase();
  const { data: shares, error } = await client
    .from("qv_shares")
    .select("id,object_id,expires_at")
    .eq("owner_user_id", userId)
    .is("revoked_at", null);
  if (error) throw error;
  const shareRows = (shares ?? []) as Array<{ id: string; object_id: string; expires_at: string | null }>;
  if (shareRows.length >= ROW_CAP) throw new CloudError("QV_SHARES_UNCHECKED", SHARE_MESSAGES.QV_SHARES_UNCHECKED);
  const now = Date.now();
  const open = shareRows.filter((share) => !share.expires_at || Date.parse(share.expires_at) > now);
  if (open.length === 0) return new Set();
  // Recipient rows the caller may read: those of their own shares (and of
  // shares sent to them, which match none of `open`).
  const { data: recipients, error: recipientError } = await client
    .from("qv_share_recipients")
    .select("share_id")
    .in("status", ["pending", "accepted"]);
  if (recipientError) throw recipientError;
  const recipientRows = (recipients ?? []) as Array<{ share_id: string }>;
  if (recipientRows.length >= ROW_CAP) throw new CloudError("QV_SHARES_UNCHECKED", SHARE_MESSAGES.QV_SHARES_UNCHECKED);
  const reached = new Set(recipientRows.map((row) => row.share_id));
  return new Set(open.filter((share) => reached.has(share.id)).map((share) => share.object_id));
}

/**
 * Take back cloud copies that were uploaded only so a file could be shared
 * (cloud backup off) once no live share uses them. Backups are never touched:
 * the core only releases a copy it marked shared-only. Returns how many were
 * queued for deletion (the next sync removes them).
 */
export async function releaseUnusedShareCopies(userId: string, entries: StoreEntry[]): Promise<number> {
  const now = Date.now();
  const copies = entries.filter((entry) => {
    if (entry.kind !== "file" || !entry.cloudSharedOnly || !entry.cloudObjectId) return false;
    const uploadedAt = entry.cloudBackedUpAt ? Date.parse(entry.cloudBackedUpAt) : 0;
    return now - (Number.isFinite(uploadedAt) ? uploadedAt : 0) >= SHARE_COPY_GRACE_MS;
  });
  if (copies.length === 0) return 0;
  const inUse = await liveSharedObjectIds(userId);
  let released = 0;
  for (const entry of copies) {
    const objectId = entry.cloudObjectId as string;
    if (inUse.has(objectId)) continue;
    if (await vaultCloudCore.releaseShareCopy(entry.id, objectId)) released += 1;
  }
  return released;
}

/** Files other people shared with this account, opened on this device. */
export async function listSharedWithMe(userId: string, deviceId: string): Promise<IncomingShare[]> {
  const client = requireSupabase();
  const { data: rows, error } = await client
    .from("qv_share_recipients")
    .select("share_id,status,created_at")
    .eq("recipient_user_id", userId)
    .in("status", ["pending", "accepted"]);
  if (error) throw error;
  const recipientRows = (rows ?? []) as Array<{ share_id: string; status: "pending" | "accepted"; created_at: string }>;
  if (recipientRows.length === 0) return [];
  const shareIds = recipientRows.map((r) => r.share_id);
  const [{ data: shares }, { data: envelopes }] = await Promise.all([
    client.from("qv_shares").select("id,owner_user_id,permission,expires_at,created_at").in("id", shareIds),
    client.from("qv_share_envelopes").select("share_id,sender_device_id,envelope").in("share_id", shareIds).eq("recipient_device_id", deviceId),
  ]);
  const shareById = new Map(((shares ?? []) as Array<{ id: string; owner_user_id: string; permission: SharePermission; expires_at: string | null; created_at: string }>).map((s) => [s.id, s]));
  const envelopeByShare = new Map(((envelopes ?? []) as Array<{ share_id: string; sender_device_id: string; envelope: unknown }>).map((e) => [e.share_id, e]));
  const names = await displayNames([...new Set([...shareById.values()].map((s) => s.owner_user_id))]);

  const out: IncomingShare[] = [];
  for (const row of recipientRows) {
    const share = shareById.get(row.share_id);
    if (!share) continue; // revoked or expired: the server no longer shows it
    const envelopeRow = envelopeByShare.get(row.share_id);
    let file: SharedFileInfo | null = null;
    let sender: CallPeerIdentityPayload | null = null;
    let problem: string | null = null;
    if (envelopeRow) {
      sender = await fetchCallPeerIdentity(share.owner_user_id, envelopeRow.sender_device_id);
      if (!sender) problem = "The sender's device could not be verified.";
      else {
        try {
          file = await safeInvoke<SharedFileInfo>("vault_share_open", { envelope: envelopeRow.envelope, sender });
        } catch (error) {
          problem = describeShareError(error);
        }
      }
    } else {
      problem = "Not yet available on this device — it appears once the sender's app is online.";
    }
    out.push({
      shareId: row.share_id,
      ownerUserId: share.owner_user_id,
      ownerName: names.get(share.owner_user_id) ?? "QGuard user",
      status: row.status,
      permission: share.permission,
      expiresAt: share.expires_at,
      sharedAt: share.created_at,
      file,
      envelope: envelopeRow?.envelope ?? null,
      sender,
      problem,
    });
  }
  return out.sort((a, b) => b.sharedAt.localeCompare(a.sharedAt));
}

/**
 * A file someone shared with this account that is still waiting for an answer —
 * what the app-wide notification shows. Deliberately WITHOUT the file name:
 * the name is inside the device envelope, which opens only in the Rust core,
 * and a notification can appear while the vault is locked.
 */
export interface PendingShareNotice {
  shareId: string;
  ownerUserId: string;
  ownerName: string;
  sharedAt: string;
  expiresAt: string | null;
}

/**
 * Pending notices from raw rows (exported for tests). A share the server no
 * longer returns (revoked, expired: RLS hides it) or that expired since is
 * dropped; newest first.
 */
export function buildShareNotices(
  recipientRows: Array<{ share_id: string; status: string; created_at: string }>,
  shareRows: Array<{ id: string; owner_user_id: string; expires_at: string | null; revoked_at?: string | null }>,
  names: Map<string, string>,
  now: number,
): PendingShareNotice[] {
  const shares = new Map(shareRows.map((share) => [share.id, share]));
  return recipientRows
    .filter((row) => row.status === "pending")
    .flatMap((row) => {
      const share = shares.get(row.share_id);
      if (!share || share.revoked_at) return [];
      if (share.expires_at && Date.parse(share.expires_at) <= now) return [];
      return [{
        shareId: row.share_id,
        ownerUserId: share.owner_user_id,
        ownerName: names.get(share.owner_user_id) ?? "A QGuard user",
        sharedAt: row.created_at,
        expiresAt: share.expires_at,
      }];
    })
    .sort((a, b) => Date.parse(b.sharedAt) - Date.parse(a.sharedAt));
}

/** Files shared with this account that are waiting for Accept / Decline. */
export async function listPendingShareNotices(userId: string): Promise<PendingShareNotice[]> {
  const client = requireSupabase();
  const { data: rows, error } = await client
    .from("qv_share_recipients")
    .select("share_id,status,created_at")
    .eq("recipient_user_id", userId)
    .eq("status", "pending");
  if (error) throw error;
  const recipientRows = (rows ?? []) as Array<{ share_id: string; status: string; created_at: string }>;
  if (recipientRows.length === 0) return [];
  const { data: shares, error: sharesError } = await client
    .from("qv_shares")
    .select("id,owner_user_id,expires_at,revoked_at")
    .in("id", recipientRows.map((row) => row.share_id));
  if (sharesError) throw sharesError;
  const shareRows = (shares ?? []) as Array<{ id: string; owner_user_id: string; expires_at: string | null; revoked_at: string | null }>;
  const names = await displayNames([...new Set(shareRows.map((share) => share.owner_user_id))]);
  return buildShareNotices(recipientRows, shareRows, names, Date.now());
}

export async function respondToShare(shareId: string, accept: boolean): Promise<void> {
  const { error } = await requireSupabase().rpc("qv_share_respond", { p_share_id: shareId, p_accept: accept });
  if (error) fail(error);
}

async function downloadShared(userId: string, share: IncomingShare): Promise<string> {
  if (!share.file) throw new CloudError("QV_SHARE_NOT_AVAILABLE", share.problem ?? SHARE_MESSAGES.QV_SHARE_NOT_AVAILABLE);
  const { data, error } = await requireSupabase()
    .from("qv_cloud_objects")
    .select("id,owner_user_id,kind,entry_id,container_bytes,part_count,part_sha3,container_sha3,status,committed_at")
    .eq("id", share.file.objectId)
    .maybeSingle();
  if (error) throw error;
  if (!data) throw new CloudError("QV_SHARE_NOT_AVAILABLE", SHARE_MESSAGES.QV_SHARE_NOT_AVAILABLE);
  return downloadObject(userId, data as CloudObjectRow);
}

/** Decrypt a shared file in memory (verified against what the sender signed). */
export async function previewShared(userId: string, share: IncomingShare): Promise<ArrayBuffer> {
  const downloadId = await downloadShared(userId, share);
  const bytes = ipcArrayBuffer(await safeInvoke<unknown>("vault_share_preview", { envelope: share.envelope, sender: share.sender, downloadId }));
  await requireSupabase().rpc("qv_share_record", { p_share_id: share.shareId, p_event: "opened" });
  return bytes;
}

/** Save a shared file into this vault as your own copy. */
export async function saveShared(userId: string, share: IncomingShare, parentId: string | null): Promise<StoreEntry> {
  const downloadId = await downloadShared(userId, share);
  const entry = await safeInvoke<StoreEntry>("vault_share_save", { envelope: share.envelope, sender: share.sender, downloadId, parentId });
  await requireSupabase().rpc("qv_share_record", { p_share_id: share.shareId, p_event: "saved" });
  return entry;
}

/**
 * Shares this account made, with recipients and access history. Also seals
 * the file to recipients' devices added since (a new phone, say), so the share
 * reaches them without the sender doing anything.
 */
export async function listSharedByMe(userId: string, entries: StoreEntry[]): Promise<OutgoingShare[]> {
  const client = requireSupabase();
  const { data: shares, error } = await client
    .from("qv_shares")
    .select("id,object_id,permission,expires_at,created_at,revoked_at")
    .eq("owner_user_id", userId)
    .order("created_at", { ascending: false })
    .limit(200);
  if (error) throw error;
  const shareRows = (shares ?? []) as Array<{ id: string; object_id: string; permission: SharePermission; expires_at: string | null; created_at: string; revoked_at: string | null }>;
  if (shareRows.length === 0) return [];
  const ids = shareRows.map((s) => s.id);
  const [{ data: recipients }, { data: events }, { data: envelopes }] = await Promise.all([
    client.from("qv_share_recipients").select("share_id,recipient_user_id,status,responded_at").in("share_id", ids),
    client.from("qv_share_events").select("share_id,actor_user_id,event,created_at").in("share_id", ids).order("created_at", { ascending: false }),
    client.from("qv_share_envelopes").select("share_id,recipient_device_id").in("share_id", ids),
  ]);
  const recipientRows = (recipients ?? []) as Array<{ share_id: string; recipient_user_id: string; status: string; responded_at: string | null }>;
  const eventRows = (events ?? []) as Array<{ share_id: string; actor_user_id: string; event: string; created_at: string }>;
  const envelopeRows = (envelopes ?? []) as Array<{ share_id: string; recipient_device_id: string }>;
  const names = await displayNames([...new Set([...recipientRows.map((r) => r.recipient_user_id), ...eventRows.map((e) => e.actor_user_id)])]);
  const byObject = new Map(entries.filter((e) => e.cloudObjectId).map((e) => [e.cloudObjectId as string, e]));

  // Top up: recipients' devices that have no envelope yet.
  for (const share of shareRows) {
    const live = !share.revoked_at && (!share.expires_at || new Date(share.expires_at) > new Date());
    const entry = byObject.get(share.object_id);
    if (!live || !entry) continue;
    const people = recipientRows.filter((r) => r.share_id === share.id && (r.status === "pending" || r.status === "accepted")).map((r) => r.recipient_user_id);
    if (people.length === 0) continue;
    const have = new Set(envelopeRows.filter((e) => e.share_id === share.id).map((e) => e.recipient_device_id));
    const missing = (await liveDevicesOf(people)).filter((device) => !have.has(device.device_id));
    if (missing.length === 0) continue;
    try {
      const { data: object } = await client.from("qv_cloud_objects").select("id,container_sha3").eq("id", share.object_id).maybeSingle();
      if (object) await sealAndStore(entry, share.id, object, share.permission, share.expires_at ? new Date(share.expires_at) : null, missing);
    } catch {
      // Retried the next time the list is opened.
    }
  }

  const now = new Date();
  return shareRows.map((share) => ({
    shareId: share.id,
    objectId: share.object_id,
    fileName:
      byObject.get(share.object_id)?.name ??
      (share.revoked_at || (share.expires_at && new Date(share.expires_at) <= now)
        ? "Share ended · its encrypted copy was removed from the cloud"
        : "File no longer in this vault"),
    permission: share.permission,
    expiresAt: share.expires_at,
    createdAt: share.created_at,
    revokedAt: share.revoked_at,
    recipients: recipientRows
      .filter((r) => r.share_id === share.id)
      .map((r) => ({ userId: r.recipient_user_id, name: names.get(r.recipient_user_id) ?? "QGuard user", status: r.status, respondedAt: r.responded_at })),
    events: eventRows
      .filter((e) => e.share_id === share.id)
      .slice(0, 20)
      .map((e) => ({ event: e.event, actor: e.actor_user_id === userId ? "You" : names.get(e.actor_user_id) ?? "QGuard user", at: e.created_at })),
  }));
}

export async function revokeShare(shareId: string, recipientUserId: string | null): Promise<void> {
  const { error } = await requireSupabase().rpc("qv_share_revoke", { p_share_id: shareId, p_recipient: recipientUserId });
  if (error) fail(error);
}
