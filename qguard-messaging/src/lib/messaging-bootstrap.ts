import type { SupabaseClient, User } from "@supabase/supabase-js";
import { bytesToBytea, randomHex } from "@/lib/encoding";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

interface PublicIdentityBundle {
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

const bootstrappedUsers = new Set<string>();
const bootstrapPromises = new Map<string, Promise<void>>();

export async function ensureMessagingWorkspace(client: SupabaseClient, user: User): Promise<void> {
  if (bootstrappedUsers.has(user.id)) return;
  const existingBootstrap = bootstrapPromises.get(user.id);
  if (existingBootstrap) return existingBootstrap;

  const bootstrap = runMessagingBootstrap(client, user)
    .then(() => {
      bootstrappedUsers.add(user.id);
    })
    .finally(() => {
      bootstrapPromises.delete(user.id);
    });
  bootstrapPromises.set(user.id, bootstrap);
  return bootstrap;
}

async function runMessagingBootstrap(client: SupabaseClient, user: User): Promise<void> {
  try {
    await client.rpc("ensure_messaging_defaults", { p_user_id: user.id });
  } catch {
    // Older databases may not have the helper until migrations are applied.
  }

  let deviceId: string | null = null;
  if (isTauriRuntime()) {
    deviceId = await ensureDesktopDevice(client, user);
  }

  await ensureStarterConversation(client, user.id, deviceId);
}

async function ensureDesktopDevice(client: SupabaseClient, user: User): Promise<string | null> {
  const bundle = await safeInvoke<PublicIdentityBundle>("keys_upload_identity_bundle", {});

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

  await ensureSignedPrekey(client, user.id, bundle.device_id);
  await ensureOneTimePrekeys(client, user.id, bundle.device_id);
  return bundle.device_id;
}

async function ensureSignedPrekey(client: SupabaseClient, userId: string, deviceId: string): Promise<void> {
  const { data: activePrekey, error: activeError } = await client
    .from("messaging_signed_prekeys")
    .select("id")
    .eq("user_id", userId)
    .eq("device_id", deviceId)
    .eq("is_active", true)
    .maybeSingle();

  if (activeError) throw activeError;
  if (activePrekey) return;

  const prekey = await safeInvoke<PublicSignedPrekey>("keys_upload_signed_prekey", {});
  const { error } = await client.from("messaging_signed_prekeys").insert({
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
  });
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

  const prekeys = await safeInvoke<PublicOneTimePrekey[]>("keys_upload_one_time_prekeys", {});
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
