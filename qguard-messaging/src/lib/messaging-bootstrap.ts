import type { SupabaseClient, User } from "@supabase/supabase-js";
import { byteaToBytes, bytesToBytea, randomHex } from "@/lib/encoding";
import { ONE_TIME_PREKEY_MIN, ONE_TIME_PREKEY_TARGET } from "@/lib/security-score";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

export interface PublicIdentityBundle {
  user_id: string;
  device_id: string;
  identity_id: string;
  device_label: string;
  /**
   * A device row this launch superseded by re-keying. Present only when the
   * local identity was replaced (the FIPS 203 cutover, or an explicit reset).
   */
  replaced_device_id?: string | null;
  x25519_identity_public: number[];
  mlkem_identity_public: number[];
  ed25519_identity_public: number[];
  mldsa_identity_public: number[];
  signature: Record<string, unknown>;
  fingerprint: string;
  suite: Record<string, unknown>;
}

interface PublicSignedPrekey {
  prekey_id: string;
  device_id: string;
  x25519_public: number[];
  mlkem_public: number[];
  signature: Record<string, unknown>;
  fingerprint: string;
  created_at: string;
  expires_at: string;
}

interface PublicOneTimePrekey {
  prekey_id: string;
  device_id: string;
  x25519_public: number[];
  mlkem_public: number[];
  signature: Record<string, unknown>;
  fingerprint: string;
  created_at: string;
}

const defaultsReadyUsers = new Set<string>();
const defaultsPromises = new Map<string, Promise<void>>();
const profileReadyUsers = new Set<string>();
const profilePromises = new Map<string, Promise<void>>();
const deviceBootstrappedUsers = new Set<string>();
const bootstrapPromises = new Map<string, Promise<void>>();
const defaultsTimeoutMs = 3_500;
const workspaceBootstrapTimeoutMs = 20_000;
const currentMlKemPublicKeyLength = 1568;

async function withTimeout<T>(task: PromiseLike<T>, timeoutMs: number, label: string): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
  });
  try {
    return await Promise.race([task, timeout]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

export async function ensureMessagingWorkspace(client: SupabaseClient, user: User): Promise<void> {
  await ensureMessagingProfile(client, user);
  await ensureMessagingDefaults(client, user.id);
  await startMessagingWorkspaceBootstrap(client, user);
}

export function startMessagingWorkspaceBootstrap(client: SupabaseClient, user: User): Promise<void> {
  if (deviceBootstrappedUsers.has(user.id)) return Promise.resolve();
  const existingBootstrap = bootstrapPromises.get(user.id);
  if (existingBootstrap) return existingBootstrap;

  const bootstrap = withTimeout(runMessagingBootstrap(client, user), workspaceBootstrapTimeoutMs, "Messaging device bootstrap")
    .then(() => {
      deviceBootstrappedUsers.add(user.id);
    })
    .catch(() => {
      // Device bootstrap is retried by later sync actions and realtime refreshes.
    })
    .finally(() => {
      bootstrapPromises.delete(user.id);
    });
  bootstrapPromises.set(user.id, bootstrap);
  return bootstrap;
}

export async function ensureMessagingProfile(client: SupabaseClient, user: User): Promise<void> {
  if (profileReadyUsers.has(user.id)) return;
  const existingProfile = profilePromises.get(user.id);
  if (existingProfile) return existingProfile;

  const email = user.email ?? "";
  const metadata = user.user_metadata ?? {};
  const displayName = String(metadata.full_name ?? metadata.name ?? email.split("@")[0] ?? "QGuard User");
  const username = `${email.split("@")[0] || "qguard"}_${user.id.replace(/-/g, "").slice(0, 6)}`
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "_");

  const profile = withTimeout(
    client.rpc("ensure_qguard_profile", {
      p_user_id: user.id,
      p_email: email || null,
      p_name: displayName || null,
    }).then(async ({ error }) => {
      if (!error) return;
      const { error: upsertError } = await client.from("profiles").upsert({
        id: user.id,
        email: email || null,
        name: displayName || "QGuard User",
        username,
      }, { onConflict: "id" });
      if (upsertError) throw error;
    }),
    defaultsTimeoutMs,
    "QGuard profile bootstrap",
  )
    .then(() => {
      profileReadyUsers.add(user.id);
    })
    .finally(() => {
      profilePromises.delete(user.id);
    });

  profilePromises.set(user.id, profile);
  return profile;
}

async function ensureMessagingDefaults(client: SupabaseClient, userId: string): Promise<void> {
  if (defaultsReadyUsers.has(userId)) return;
  const existingDefaults = defaultsPromises.get(userId);
  if (existingDefaults) return existingDefaults;

  const defaults = withTimeout(
    client.rpc("ensure_messaging_defaults", { p_user_id: userId }).then(() => undefined),
    defaultsTimeoutMs,
    "Messaging defaults",
  )
    .then(() => {
      defaultsReadyUsers.add(userId);
    })
    .catch(() => {
      // Older databases may not have the helper until migrations are applied.
    })
    .finally(() => {
      defaultsPromises.delete(userId);
    });

  defaultsPromises.set(userId, defaults);
  return defaults;
}

async function runMessagingBootstrap(client: SupabaseClient, user: User): Promise<void> {
  await ensureMessagingProfile(client, user);
  await ensureMessagingDefaults(client, user.id);

  const bundle = await syncCurrentMessagingDevice(client, user.id);
  const deviceId = bundle?.device_id ?? null;

  await ensureStarterConversation(client, user.id, deviceId);
}

export async function syncCurrentMessagingDevice(client: SupabaseClient, userId: string): Promise<PublicIdentityBundle | null> {
  if (!isTauriRuntime()) return null;
  return ensureDesktopDevice(client, userId);
}

const prekeyReadinessLastRun = new Map<string, number>();
const prekeyReadinessPromises = new Map<string, Promise<void>>();
const prekeyReadinessThrottleMs = 60_000;

// Runtime self-healing for prekey depletion. The workspace bootstrap runs once
// per app session, but peers keep claiming one-time prekeys while the app is
// open; whenever a dashboard refresh sees the pool below its readiness floor it
// calls this to republish/replenish. Throttled so realtime-triggered refresh
// storms cannot loop key generation, and deduped so concurrent refreshes share
// one pass. The resulting prekey inserts emit realtime events that refresh the
// dashboard counts on their own.
export function ensurePrekeyReadiness(client: SupabaseClient, userId: string): Promise<void> {
  if (!isTauriRuntime()) return Promise.resolve();
  const inFlight = prekeyReadinessPromises.get(userId);
  if (inFlight) return inFlight;
  const lastRun = prekeyReadinessLastRun.get(userId) ?? 0;
  if (Date.now() - lastRun < prekeyReadinessThrottleMs) return Promise.resolve();
  prekeyReadinessLastRun.set(userId, Date.now());

  const readiness = ensureDesktopDevice(client, userId)
    .then(() => undefined)
    .catch(() => {
      // Retried by the next low-inventory refresh once the throttle expires.
    })
    .finally(() => {
      prekeyReadinessPromises.delete(userId);
    });
  prekeyReadinessPromises.set(userId, readiness);
  return readiness;
}

async function ensureDesktopDevice(client: SupabaseClient, userId: string): Promise<PublicIdentityBundle> {
  const bundle = await safeInvoke<PublicIdentityBundle>("keys_upload_identity_bundle", { userId });

  const { error: deviceError } = await client.rpc("register_messaging_device", {
    p_device_id: bundle.device_id,
    p_device_label: bundle.device_label,
    p_identity_id: bundle.identity_id,
    p_x25519_identity_public: bytesToBytea(bundle.x25519_identity_public),
    p_mlkem_identity_public: bytesToBytea(bundle.mlkem_identity_public),
    p_ed25519_identity_public: bytesToBytea(bundle.ed25519_identity_public),
    p_mldsa_identity_public: bytesToBytea(bundle.mldsa_identity_public),
    p_identity_signature: bundle.signature,
    p_fingerprint: bundle.fingerprint,
    p_suite: bundle.suite,
  });
  if (deviceError) throw deviceError;

  await ensureSignedPrekey(client, userId, bundle.device_id);
  await ensureOneTimePrekeys(client, userId, bundle.device_id);
  await retireSupersededDevice(client, bundle);
  return bundle;
}

/**
 * Revoke the device row a re-key replaced.
 *
 * A re-key mints a new `device_id`, and the row the previous identity
 * registered keeps sitting in `messaging_devices`: trusted, recently seen, with
 * an active signed prekey. Peers go on selecting it for delivery and sealing
 * envelopes to a private key that no longer exists anywhere -- messages that
 * are unreadable the instant they are written. That is how one account ended up
 * with five dead prekey ids and hundreds of undecryptable envelopes.
 *
 * Revoke, not delete: `messaging_message_envelopes.recipient_device_id` is
 * `ON DELETE SET NULL`, so deleting the row would silently erase which device
 * each historical envelope was for, which is exactly the evidence needed to
 * explain an unreadable history. Revoked rows are already filtered out of
 * device loading, so revoking is enough to stop delivery.
 *
 * Only acknowledged to the backend once the revoke succeeds; a failure leaves
 * the id in the bundle so the next sync retries it.
 */
async function retireSupersededDevice(client: SupabaseClient, bundle: PublicIdentityBundle): Promise<void> {
  const supersededId = bundle.replaced_device_id;
  if (!supersededId || supersededId === bundle.device_id) return;
  try {
    const { error } = await client.rpc("revoke_messaging_device", { p_device_id: supersededId });
    if (error) {
      const { error: fallbackError } = await client
        .from("messaging_devices")
        .update({ trust_state: "revoked", revoked_at: new Date().toISOString() })
        .eq("id", supersededId)
        .eq("user_id", bundle.user_id);
      if (fallbackError) throw fallbackError;
    }
    await safeInvoke("keys_ack_superseded_device", {}, null);
  } catch {
    // Left unacknowledged on purpose: the next bootstrap or prekey-readiness
    // pass reports the same id and tries again.
  }
}

async function ensureSignedPrekey(client: SupabaseClient, userId: string, deviceId: string): Promise<void> {
  const prekey = await safeInvoke<PublicSignedPrekey>("keys_upload_signed_prekey", { userId });
  const { data: activePrekeys, error: activeError } = await client
    .from("messaging_signed_prekeys")
    .select("id,mlkem_public")
    .eq("user_id", userId)
    .eq("device_id", deviceId)
    .eq("is_active", true);

  if (activeError) throw activeError;
  const activePrekeyRows = (activePrekeys ?? []) as Array<Record<string, unknown>>;
  const currentPrekeyAlreadyActive = activePrekeyRows.some((record) => {
    const publicBytes = byteaToBytes(record.mlkem_public);
    return (
      String(record.id) === prekey.prekey_id
      && publicBytes.length === prekey.mlkem_public.length
      && publicBytes.every((byte, index) => byte === prekey.mlkem_public[index])
    );
  });
  const staleActivePrekeyExists = activePrekeyRows.some((record) => {
    const publicBytes = byteaToBytes(record.mlkem_public);
    return String(record.id) !== prekey.prekey_id || publicBytes.length !== prekey.mlkem_public.length;
  });
  if (currentPrekeyAlreadyActive && !staleActivePrekeyExists && prekey.mlkem_public.length === currentMlKemPublicKeyLength) return;

  // ORDER MATTERS: publish the new active prekey FIRST, deactivate the old ones
  // second. The previous order (deactivate → publish) stranded a device with
  // ZERO active prekeys whenever the publish step failed mid-flight, making it
  // unreachable for messages and calls ("Awaiting prekey material"). A brief
  // overlap of two active prekeys is harmless — peers pick the newest.
  const { error } = await client.from("messaging_signed_prekeys").upsert({
    id: prekey.prekey_id,
    user_id: userId,
    device_id: deviceId,
    x25519_public: bytesToBytea(prekey.x25519_public),
    mlkem_public: bytesToBytea(prekey.mlkem_public),
    signature: prekey.signature,
    fingerprint: prekey.fingerprint,
    is_active: true,
    expires_at: prekey.expires_at,
    created_at: prekey.created_at,
  }, { onConflict: "id" });
  if (error) throw error;

  const { error: deactivateError } = await client
    .from("messaging_signed_prekeys")
    .update({ is_active: false })
    .eq("user_id", userId)
    .eq("device_id", deviceId)
    .neq("id", prekey.prekey_id);
  if (deactivateError) throw deactivateError;
}

async function ensureOneTimePrekeys(client: SupabaseClient, userId: string, deviceId: string): Promise<void> {
  // Fetch ALL published rows for this device (consumed included). Consumed
  // rows keep their id forever, so re-upserting the same static local pool
  // with ignoreDuplicates inserts nothing — the pool must be diffed against
  // every published id and topped up with FRESH keys, or a device whose 24
  // initial prekeys were all claimed stays at 0 available permanently
  // ("Awaiting prekey material").
  const { data: publishedRows, error: publishedError } = await client
    .from("messaging_one_time_prekeys")
    .select("id,consumed_at")
    .eq("user_id", userId)
    .eq("device_id", deviceId)
    .order("created_at", { ascending: false })
    .limit(1000);
  if (publishedError) throw publishedError;

  const published = (publishedRows ?? []) as Array<{ id: unknown; consumed_at: unknown }>;
  const publishedIds = new Set(published.map((row) => String(row.id)));
  const available = published.filter((row) => !row.consumed_at).length;
  if (available >= ONE_TIME_PREKEY_MIN) return;

  const localPool = await safeInvoke<PublicOneTimePrekey[]>("keys_upload_one_time_prekeys", { userId });
  const unpublished = localPool.filter((prekey) => !publishedIds.has(prekey.prekey_id));
  const deficit = ONE_TIME_PREKEY_TARGET - available - unpublished.length;
  const fresh = deficit > 0
    ? await safeInvoke<PublicOneTimePrekey[]>("keys_replenish_one_time_prekeys", { userId, needed: deficit })
    : [];

  const rows = [...unpublished, ...fresh].map((prekey) => ({
    id: prekey.prekey_id,
    user_id: userId,
    device_id: deviceId,
    x25519_public: bytesToBytea(prekey.x25519_public),
    mlkem_public: bytesToBytea(prekey.mlkem_public),
    signature: prekey.signature,
    fingerprint: prekey.fingerprint,
    created_at: prekey.created_at,
  }));
  if (rows.length > 0) {
    const { error } = await client
      .from("messaging_one_time_prekeys")
      .upsert(rows, { onConflict: "id", ignoreDuplicates: true });
    if (error) throw error;
  }

  // Hygiene: prune consumed rows older than 30 days so the published-rows
  // select above never outgrows its 1000-row window. Only rows absent from
  // the CURRENT local pool are deleted — a row still in the pool must stay
  // published so the diff above can never re-insert (republish) a consumed
  // one-time prekey. Non-fatal: cleanup must never break replenishment.
  try {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    let prune = client
      .from("messaging_one_time_prekeys")
      .delete()
      .eq("user_id", userId)
      .eq("device_id", deviceId)
      .lt("consumed_at", cutoff);
    const localIds = localPool.map((prekey) => prekey.prekey_id).filter(Boolean);
    if (localIds.length > 0) {
      prune = prune.not("id", "in", `(${localIds.join(",")})`);
    }
    await prune;
  } catch {
    // Next low-inventory pass retries the prune.
  }
}

async function ensureStarterConversation(client: SupabaseClient, userId: string, deviceId: string | null): Promise<void> {
  const { data: existing, error: existingError } = await client
    .from("messaging_conversations")
    .select("id")
    .eq("owner_user_id", userId)
    .order("created_at", { ascending: true })
    .limit(1);

  if (existingError) throw existingError;
  const conversationId = existing?.[0]?.id as string | undefined;
  const activeConversationId = conversationId ?? await createConversation(client, userId);

  if (!deviceId) return;

  const { error: memberError } = await client.from("messaging_conversation_members").upsert({
    conversation_id: activeConversationId,
    user_id: userId,
    device_id: deviceId,
    role: "owner",
  }, { onConflict: "conversation_id,user_id,device_id" });
  if (memberError) throw memberError;
}

async function createConversation(client: SupabaseClient, userId: string): Promise<string> {
  const { data, error } = await client
    .from("messaging_conversations")
    .insert({
      owner_user_id: userId,
      conversation_type: "direct",
      encrypted_title: {
        version: 1,
        label_hash: randomHex(16),
        note: "client-local title metadata",
      },
    })
    .select("id")
    .single();

  if (error) throw error;
  return String(data.id);
}
