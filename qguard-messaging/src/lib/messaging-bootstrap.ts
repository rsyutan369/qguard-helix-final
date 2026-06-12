import type { SupabaseClient, User } from "@supabase/supabase-js";
import { byteaToBytes, bytesToBytea, randomHex } from "@/lib/encoding";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

export interface PublicIdentityBundle {
  user_id: string;
  device_id: string;
  identity_id: string;
  device_label: string;
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
  return bundle;
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

  const { error: deactivateError } = await client
    .from("messaging_signed_prekeys")
    .update({ is_active: false })
    .eq("user_id", userId)
    .eq("device_id", deviceId)
    .neq("id", prekey.prekey_id);
  if (deactivateError) throw deactivateError;

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
}

async function ensureOneTimePrekeys(client: SupabaseClient, userId: string, deviceId: string): Promise<void> {
  const { count, error: countError } = await client
    .from("messaging_one_time_prekeys")
    .select("id", { count: "exact", head: true })
    .eq("user_id", userId)
    .eq("device_id", deviceId)
    .is("consumed_at", null);

  if (countError) throw countError;
  if ((count ?? 0) >= 8) return;

  const prekeys = await safeInvoke<PublicOneTimePrekey[]>("keys_upload_one_time_prekeys", { userId });
  const rows = prekeys.slice(0, 24).map((prekey) => ({
    id: prekey.prekey_id,
    user_id: userId,
    device_id: deviceId,
    x25519_public: bytesToBytea(prekey.x25519_public),
    mlkem_public: bytesToBytea(prekey.mlkem_public),
    signature: prekey.signature,
    fingerprint: prekey.fingerprint,
    created_at: prekey.created_at,
  }));

  const { error } = await client
    .from("messaging_one_time_prekeys")
    .upsert(rows, { onConflict: "id", ignoreDuplicates: true });
  if (error) throw error;
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
