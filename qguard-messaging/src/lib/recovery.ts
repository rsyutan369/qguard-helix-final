import type { SupabaseClient } from "@supabase/supabase-js";
import { callPeerIdentityFromRow, fetchCallPeerIdentity } from "@/lib/call-peer-identity";
import type { CallPeerIdentityPayload } from "@/lib/call-targets";
import { fetchContactVerification } from "@/lib/contact-verification";
import { safeInvoke } from "@/lib/tauri";

/**
 * Recovery (roadmap Phase 5; src-tauri/src/commands/recovery.rs,
 * docs/superpowers/specs/2026-10-19-recovery-design.md).
 *
 * The core makes and opens everything secret. This module moves the sealed
 * pieces between the core and the relay tables of migration 038, which hold
 * nothing that opens anything on its own.
 */

// ---- History backup (5.3) ---------------------------------------------------

export interface HistoryBackupExport {
  fileB64: string;
  fileName: string;
  entries: number;
}

export interface HistoryBackupImport {
  added: number;
  alreadyHeld: number;
}

export const exportHistoryBackup = (recoveryKey: string, accountVerifier: string | null) =>
  safeInvoke<HistoryBackupExport>("history_backup_export", { recoveryKey, accountVerifier });

export const importHistoryBackup = (recoveryKey: string, accountVerifier: string | null, fileB64: string) =>
  safeInvoke<HistoryBackupImport>("history_backup_import", { recoveryKey, accountVerifier, fileB64 });

export function base64ToBlob(b64: string, type = "application/json"): Blob {
  const binary = atob(b64);
  return new Blob([Uint8Array.from(binary, (char) => char.charCodeAt(0))], { type });
}

export async function fileToBase64(file: Blob): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

// ---- Social recovery (5.1) --------------------------------------------------

export interface GuardianRef {
  userId: string;
  deviceId: string;
  x: number;
}

export interface SocialRecoveryRecord {
  v: number;
  setupId: string;
  threshold: number;
  shareCount: number;
  saltB64: string;
  wrappedRoot: unknown;
  guardians: GuardianRef[];
  createdAt: number;
}

type Sealed = Record<string, unknown>;
export type ShareOffer = Sealed & { setupId: string; ownerUserId: string; ownerDeviceId: string; guardianUserId: string; guardianDeviceId: string };
export type RecoveryRequest = Sealed & { requestId: string; userId: string; deviceId: string; createdAt: number };
export type ShareRelease = Sealed & { requestId: string; guardianUserId: string; guardianDeviceId: string };

export interface HeldShareSummary {
  ownerUserId: string;
  setupId: string;
  threshold: number;
  shareCount: number;
  receivedAt: number;
}

/** A contact device the user has verified (Phase 3) — the only kind that can be a helper. */
export interface GuardianCandidate {
  userId: string;
  deviceId: string;
  name: string;
  deviceLabel: string;
  identity: CallPeerIdentityPayload;
}

/** Contact devices this device has verified, as possible recovery helpers. */
export async function verifiedContactDevices(client: SupabaseClient, ownerUserId: string): Promise<GuardianCandidate[]> {
  const { data: contacts, error } = await client
    .from("messaging_contacts")
    .select("contact_user_id,alias")
    .eq("owner_user_id", ownerUserId)
    .neq("trust_state", "removed");
  if (error) throw error;
  const contactIds = Array.from(new Set((contacts ?? []).map((row) => String(row.contact_user_id)).filter(Boolean)));
  if (contactIds.length === 0) return [];
  const [{ data: devices, error: devicesError }, { data: profiles }] = await Promise.all([
    client
      .from("messaging_devices")
      .select("id,user_id,device_label,trust_state,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature")
      .in("user_id", contactIds)
      .neq("trust_state", "revoked"),
    client.from("profiles").select("id,name,username").in("id", contactIds),
  ]);
  if (devicesError) throw devicesError;
  const alias = new Map((contacts ?? []).map((row) => [String(row.contact_user_id), row.alias ? String(row.alias) : ""]));
  const names = new Map((profiles ?? []).map((row) => [String(row.id), String(row.name || row.username || "Contact")]));
  const candidates: GuardianCandidate[] = [];
  for (const row of devices ?? []) {
    const identity = callPeerIdentityFromRow(row as Record<string, unknown>);
    if (!identity) continue;
    const status = await fetchContactVerification(identity).catch(() => null);
    if (!status || status.standing !== "pinned" || status.verifiedAt === null) continue;
    candidates.push({
      userId: identity.user_id,
      deviceId: identity.device_id,
      name: alias.get(identity.user_id) || names.get(identity.user_id) || "Contact",
      deviceLabel: String((row as Record<string, unknown>).device_label ?? "Device"),
      identity,
    });
  }
  return candidates;
}

/** Owner: split, seal to each helper, publish record + shares. */
export async function setupSocialRecovery(
  client: SupabaseClient,
  ownerUserId: string,
  options: { recoveryKey: string; accountVerifier: string | null; pin: string; threshold: number; guardians: GuardianCandidate[] },
): Promise<SocialRecoveryRecord> {
  const setup = await safeInvoke<{ record: SocialRecoveryRecord; offers: ShareOffer[] }>("social_recovery_setup", {
    recoveryKey: options.recoveryKey,
    accountVerifier: options.accountVerifier,
    pin: options.pin,
    threshold: options.threshold,
    guardians: options.guardians.map((guardian) => guardian.identity),
  });
  // A new setup replaces the old one entirely: old shares are withdrawn.
  await client.from("messaging_recovery_shares").delete().eq("owner_user_id", ownerUserId);
  const { error: recordError } = await client.from("messaging_social_recovery").upsert({
    user_id: ownerUserId,
    setup_id: setup.record.setupId,
    record: setup.record,
    guardian_user_ids: Array.from(new Set(setup.record.guardians.map((guardian) => guardian.userId))),
    updated_at: new Date().toISOString(),
  });
  if (recordError) throw recordError;
  const { error: sharesError } = await client.from("messaging_recovery_shares").insert(
    setup.offers.map((offer) => ({
      setup_id: offer.setupId,
      owner_user_id: ownerUserId,
      guardian_user_id: offer.guardianUserId,
      guardian_device_id: offer.guardianDeviceId,
      offer,
    })),
  );
  if (sharesError) throw sharesError;
  return setup.record;
}

export async function loadSocialRecovery(client: SupabaseClient, ownerUserId: string): Promise<SocialRecoveryRecord | null> {
  const { data, error } = await client.from("messaging_social_recovery").select("record").eq("user_id", ownerUserId).maybeSingle();
  if (error) {
    if (/does not exist|schema cache|PGRST205/i.test(error.message ?? "")) return null;
    throw error;
  }
  return data?.record ? (data.record as SocialRecoveryRecord) : null;
}

/**
 * Helper: store shares sealed to THIS device in the core, then remove them
 * from the relay. Returns how many were taken in. Shares for another of the
 * user's devices are left for that device.
 */
export async function collectIncomingShares(client: SupabaseClient, myUserId: string, myDeviceId: string): Promise<number> {
  const { data, error } = await client
    .from("messaging_recovery_shares")
    .select("id,owner_user_id,guardian_device_id,offer")
    .eq("guardian_user_id", myUserId)
    .eq("guardian_device_id", myDeviceId);
  if (error) {
    if (/does not exist|schema cache|PGRST205/i.test(error.message ?? "")) return 0;
    throw error;
  }
  let taken = 0;
  for (const row of data ?? []) {
    const offer = row.offer as ShareOffer;
    const owner = await fetchCallPeerIdentity(String(row.owner_user_id), String(offer.ownerDeviceId));
    if (!owner) continue;
    try {
      await safeInvoke<HeldShareSummary>("social_recovery_hold_share", { offer, owner });
      await client.from("messaging_recovery_shares").delete().eq("id", row.id);
      taken += 1;
    } catch (reason) {
      console.warn("[recovery] share not accepted:", reason instanceof Error ? reason.message : reason);
    }
  }
  return taken;
}

export const heldShares = () => safeInvoke<HeldShareSummary[]>("social_recovery_held");

export interface PendingHelpRequest {
  request: RecoveryRequest;
  code: string[];
  ownerUserId: string;
}

/** Helper: open requests from people whose share this device holds. */
export async function helpRequests(client: SupabaseClient): Promise<PendingHelpRequest[]> {
  const held = await heldShares().catch(() => [] as HeldShareSummary[]);
  if (held.length === 0) return [];
  const owners = held.map((share) => share.ownerUserId);
  const { data, error } = await client
    .from("messaging_recovery_requests")
    .select("request_id,user_id,request,status")
    .in("user_id", owners)
    .eq("status", "open");
  if (error) throw error;
  const out: PendingHelpRequest[] = [];
  for (const row of data ?? []) {
    const request = row.request as RecoveryRequest;
    const code = await safeInvoke<string[]>("social_recovery_request_code", { request });
    out.push({ request, code, ownerUserId: String(row.user_id) });
  }
  return out;
}

/** Helper, after comparing the code with the person out of band. */
export async function approveHelpRequest(client: SupabaseClient, myUserId: string, pending: PendingHelpRequest): Promise<void> {
  const requester = await fetchCallPeerIdentity(pending.request.userId, pending.request.deviceId);
  if (!requester) throw new Error("The requesting device's identity could not be read.");
  const release = await safeInvoke<ShareRelease>("social_recovery_release", { request: pending.request, requester });
  const { error } = await client.from("messaging_recovery_releases").insert({
    request_id: pending.request.requestId,
    owner_user_id: pending.ownerUserId,
    guardian_user_id: myUserId,
    release,
  });
  if (error) throw error;
}

/** Owner, on a new device: make (or reuse) the request and publish it. */
export async function openRecoveryRequest(client: SupabaseClient, ownerUserId: string): Promise<{ request: RecoveryRequest; code: string[] }> {
  const view = await safeInvoke<{ request: RecoveryRequest; code: string[] }>("social_recovery_request");
  const { error } = await client.from("messaging_recovery_requests").upsert({
    request_id: view.request.requestId,
    user_id: ownerUserId,
    device_id: view.request.deviceId,
    request: view.request,
    status: "open",
  });
  if (error) throw error;
  return view;
}

export async function releasesFor(client: SupabaseClient, requestId: string): Promise<ShareRelease[]> {
  const { data, error } = await client.from("messaging_recovery_releases").select("release").eq("request_id", requestId);
  if (error) throw error;
  return (data ?? []).map((row) => row.release as ShareRelease);
}

/** Owner: rebuild the recovery key from the releases and the PIN. */
export async function finishRecovery(
  client: SupabaseClient,
  ownerUserId: string,
  record: SocialRecoveryRecord,
  requestId: string,
  pin: string,
): Promise<string> {
  const releases = await releasesFor(client, requestId);
  const guardians = (await Promise.all(record.guardians.map((guardian) => fetchCallPeerIdentity(guardian.userId, guardian.deviceId))))
    .filter((identity): identity is CallPeerIdentityPayload => identity !== null);
  const recoveryKey = await safeInvoke<string>("social_recovery_finish", { record, releases, guardians, pin });
  await client.from("messaging_recovery_requests").update({ status: "completed" }).eq("request_id", requestId).eq("user_id", ownerUserId);
  return recoveryKey;
}
