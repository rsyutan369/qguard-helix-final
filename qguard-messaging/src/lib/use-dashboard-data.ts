import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Session, User } from "@supabase/supabase-js";
import { ensureMessagingWorkspace } from "@/lib/messaging-bootstrap";
import { byteaToBytes } from "@/lib/encoding";
import { requireSupabase } from "@/lib/supabase";
import { useQGuardLiveSse } from "@/lib/live-sse";
import { fallbackHardeningStatus, loadSecurityHardeningStatus } from "@/lib/security-hardening";
import { buildSecurityPosture } from "@/lib/security-score";
import type {
  ConversationSummary,
  ContactSummary,
  DashboardData,
  DashboardSnapshot,
  KeyInventory,
  MessagingModule,
  Profile,
  OrgMemberSummary,
  Page,
  SecurityEvent,
  SignedPrekeySummary,
  TelemetryEvent,
  TrustedDevice,
  VaultFileSummary,
} from "@/lib/types";

const pageIds = new Set<Page>([
  "dashboard",
  "chat",
  "vault",
  "keys",
  "devices",
  "verification",
  "audit",
  "quantum",
  "admin",
  "settings",
]);

interface SupabaseDataError {
  code?: string;
  message?: string;
  details?: string;
  hint?: string;
}

function describeDataError(error: unknown, tableName: string): string {
  if (!error) return "";
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  const dataError = error as SupabaseDataError;
  const rawMessage = [dataError.message, dataError.details, dataError.hint].filter(Boolean).join(" ");
  if (dataError.code === "PGRST205" || /could not find|does not exist|schema cache/i.test(rawMessage)) {
    return `${tableName} is not available yet. Apply the QGuard Messaging Supabase migrations.`;
  }
  if (/infinite recursion|recursion/i.test(rawMessage)) {
    return `${tableName} access policy needs the QGuard Messaging dashboard access fix migration.`;
  }
  return rawMessage || `${tableName} could not be loaded.`;
}

function isMissingRelationError(error: unknown): boolean {
  if (!error || typeof error === "string" || error instanceof Error) return false;
  const dataError = error as SupabaseDataError;
  const rawMessage = [dataError.message, dataError.details, dataError.hint, dataError.code].filter(Boolean).join(" ");
  return dataError.code === "PGRST205" || /could not find|does not exist|schema cache|relation/i.test(rawMessage);
}

function bytesToDisplay(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

function latestIso(...values: Array<unknown>): string {
  const latest = values
    .map((value) => new Date(String(value ?? "")).getTime())
    .filter(Number.isFinite)
    .sort((a, b) => b - a)[0];
  return latest ? new Date(latest).toISOString() : new Date().toISOString();
}

function recordTime(record: Record<string, unknown>, key: string): number {
  const parsed = new Date(String(record[key] ?? "")).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function messageGroupId(row: Record<string, unknown>): string {
  return String(row.client_message_id ?? row.id);
}

function messageKindLabel(value: unknown): string {
  const kind = String(value ?? "message");
  if (/file/i.test(kind)) return "Encrypted file";
  if (/voice/i.test(kind)) return "Encrypted voice note";
  if (/system|control/i.test(kind)) return "Secure control event";
  return "Text message";
}

function mapTrustState(value: string): TrustedDevice["trust_state"] {
  if (value === "this_device") return "ThisDevice";
  if (value === "trusted") return "Trusted";
  if (value === "pending") return "PendingQrApproval";
  if (value === "revoked") return "Revoked";
  return "Suspicious";
}

function emptySnapshot(): DashboardSnapshot {
  return {
    e2ee_status: "Needs Device",
    pqc_status: "Awaiting Keys",
    active_sessions: 0,
    vault_storage: "0 B",
    device_count: 0,
    quantum_safe_score: 0,
    hndl_status: "Not Ready",
  };
}

function emptyKeyInventory(): KeyInventory {
  return {
    identity_device_count: 0,
    active_signed_prekeys: 0,
    available_one_time_prekeys: 0,
    next_signed_prekey_expiry: null,
    rotation_events: 0,
    algorithms: [],
  };
}

function isPage(value: unknown): value is Page {
  return typeof value === "string" && pageIds.has(value as Page);
}

function emptyDashboardData(): DashboardData {
  return {
    profile: null,
    modules: [],
    devices: [],
    contacts: [],
    conversations: [],
    vaultFiles: [],
    securityEvents: [],
    orgMembers: [],
    keyInventory: emptyKeyInventory(),
    telemetry: [],
    hardening: fallbackHardeningStatus(),
    snapshot: emptySnapshot(),
    report: {
      hybrid_session_status: "Not Established",
      pqc_algorithm: "No active device keys",
      forward_secrecy: "No active sessions",
      hndl_protection: "Not Ready",
      quantum_safe_score: 0,
      key_rotation_history: [],
      warnings: [],
    },
  };
}

export function useDashboardData(user: User | null, session: Session | null) {
  const [data, setData] = useState<DashboardData>(emptyDashboardData);
  const [loading, setLoading] = useState(Boolean(user));
  const [error, setError] = useState<string | null>(null);
  const hasLoadedRef = useRef(false);
  const refreshInFlightRef = useRef<Promise<void> | null>(null);
  const refreshQueuedRef = useRef(false);
  const refreshSequenceRef = useRef(0);
  const refreshCoreRef = useRef<() => Promise<void>>(async () => undefined);

  const refreshCore = useCallback(async () => {
    if (!user || !session) {
      refreshSequenceRef.current += 1;
      setData(emptyDashboardData());
      setLoading(false);
      hasLoadedRef.current = false;
      return;
    }
    const refreshSequence = ++refreshSequenceRef.current;
    const initialLoad = !hasLoadedRef.current;
    if (initialLoad) setLoading(true);
    setError(null);
    try {
      const client = requireSupabase();
      await ensureMessagingWorkspace(client, user);
      // The Quantum Vault is strictly local (no cloud storage), so vault files and
      // operations are no longer read from Supabase. These resolve empty to keep
      // the dashboard data shape unchanged.
      const emptyResult = () => Promise.resolve({ data: [] as Array<Record<string, unknown>>, error: null });
      const [profileResult, modulesResult] = await Promise.all([
        client.from("profiles").select("id,email,name,username,avatar_storage_path,avatar_updated_at,tier,q_score,vault_storage_used,max_vault_storage").eq("id", user.id).maybeSingle(),
        client.from("messaging_user_modules").select("module_id,label,icon,route,enabled,sort_order").eq("user_id", user.id).eq("enabled", true).order("sort_order"),
      ]);

      if (profileResult.error) {
        throw new Error(describeDataError(profileResult.error, "User profile"));
      }
      if (modulesResult.error) {
        throw new Error(describeDataError(modulesResult.error, "Dashboard modules"));
      }

      const [
        devicesResult,
        conversationsResult,
        envelopesResult,
        vaultFilesResult,
        securityEventsResult,
        orgMembersResult,
        contactsResult,
        conversationMembersResult,
        conversationStatesResult,
        messageUserStatesResult,
        signedPrekeysResult,
        oneTimePrekeysResult,
        cryptoTelemetryResult,
        vaultOperationsResult,
        hardeningStatus,
      ] = await Promise.all([
        client.from("messaging_devices").select("id,user_id,device_label,fingerprint,trust_state,suite,last_seen_at,created_at,revoked_at,approved_by_device_id,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature").order("last_seen_at", { ascending: false }),
        client.from("messaging_conversations").select("id,owner_user_id,conversation_type,encrypted_title,updated_at,created_at").order("updated_at", { ascending: false }).limit(100),
        client.from("messaging_message_envelopes").select("id,conversation_id,client_message_id,message_kind,created_at,recipient_user_id,sender_user_id,deleted_at,expires_at,lifecycle").order("created_at", { ascending: false }).limit(500),
        emptyResult(),
        client.from("messaging_security_events").select("id,device_id,event_type,severity,encrypted_details,event_hash,previous_hash,created_at").eq("user_id", user.id).order("created_at", { ascending: false }).limit(30),
        client.from("messaging_org_members").select("org_id,user_id,role,created_at").eq("user_id", user.id).order("created_at", { ascending: false }).limit(30),
        client.from("messaging_contacts").select("id,contact_user_id,alias,trust_state,created_at,updated_at").eq("owner_user_id", user.id).neq("trust_state", "removed").order("updated_at", { ascending: false }),
        client.from("messaging_conversation_members").select("conversation_id,user_id,device_id,role,revoked_at").is("revoked_at", null),
        client.from("messaging_conversation_user_states").select("conversation_id,archived_at,hidden_at,deleted_at,updated_at").eq("user_id", user.id),
        client.from("messaging_message_user_states").select("conversation_id,client_message_id,first_read_at,hidden_at").eq("user_id", user.id),
        client.from("messaging_signed_prekeys").select("id,user_id,device_id,x25519_public,mlkem_public,signature,fingerprint,is_active,expires_at,created_at").eq("is_active", true).order("expires_at", { ascending: true }),
        client.from("messaging_one_time_prekeys").select("id,device_id,consumed_at,created_at").eq("user_id", user.id).is("consumed_at", null),
        client.from("messaging_crypto_telemetry").select("id,user_id,device_id,event_scope,stage,detail,progress,status,created_at").eq("user_id", user.id).order("created_at", { ascending: false }).limit(50),
        emptyResult(),
        loadSecurityHardeningStatus(),
      ]);

      const firstQueryError = [
        [devicesResult.error, "Messaging devices"],
        [conversationsResult.error, "Conversations"],
        [envelopesResult.error, "Message envelopes"],
        [vaultFilesResult.error, "Vault files"],
        [securityEventsResult.error, "Security events"],
        [orgMembersResult.error, "Organization membership"],
        [contactsResult.error, "Contacts"],
        [conversationMembersResult.error, "Conversation members"],
        [conversationStatesResult.error && !isMissingRelationError(conversationStatesResult.error) ? conversationStatesResult.error : null, "Conversation privacy states"],
        [messageUserStatesResult.error && !isMissingRelationError(messageUserStatesResult.error) ? messageUserStatesResult.error : null, "Message read states"],
        [signedPrekeysResult.error, "Signed prekeys"],
        [oneTimePrekeysResult.error, "One-time prekeys"],
        [cryptoTelemetryResult.error, "Crypto telemetry"],
        [vaultOperationsResult.error, "Vault operations"],
      ].find(([queryError]) => Boolean(queryError));

      if (firstQueryError) {
        throw new Error(describeDataError(firstQueryError[0], String(firstQueryError[1])));
      }

      const profile = profileResult.data as Profile | null;
      if (!profile) {
        throw new Error("User profile could not be loaded for this authenticated account.");
      }
      const modules = ((modulesResult.data ?? []) as Array<Record<string, unknown>>)
        .filter((module) => isPage(module.module_id) && isPage(module.route) && module.module_id !== "admin" && module.route !== "admin")
        .map((module) => ({
          module_id: module.module_id as Page,
          label: module.module_id === "quantum" ? "Quantum Security" : String(module.label),
          icon: String(module.icon),
          route: module.route as Page,
          enabled: Boolean(module.enabled),
          sort_order: Number(module.sort_order ?? 0),
        } satisfies MessagingModule));
      const activeSignedPrekeys = signedPrekeysResult.error ? [] : (signedPrekeysResult.data ?? []) as Array<Record<string, unknown>>;
      const signedPrekeysByDevice = new Map<string, SignedPrekeySummary>();
      activeSignedPrekeys
        .sort((a, b) => recordTime(b, "created_at") - recordTime(a, "created_at") || recordTime(b, "expires_at") - recordTime(a, "expires_at"))
        .forEach((prekey) => {
        const deviceId = String(prekey.device_id);
        if (signedPrekeysByDevice.has(deviceId)) return;
        signedPrekeysByDevice.set(deviceId, {
          prekey_id: String(prekey.id),
          x25519_public: byteaToBytes(prekey.x25519_public),
          mlkem_public: byteaToBytes(prekey.mlkem_public),
          signature: (prekey.signature as SignedPrekeySummary["signature"]) ?? { ed25519: [], ml_dsa_65: [] },
          fingerprint: String(prekey.fingerprint ?? ""),
          expires_at: prekey.expires_at ? String(prekey.expires_at) : undefined,
        });
      });

      const devices = (devicesResult.error ? [] : (devicesResult.data ?? []) as Array<Record<string, unknown>>).map((device) => {
        const suite = device.suite as Record<string, string> | null;
        const identitySignature = device.identity_signature as SignedPrekeySummary["signature"] | null;
        return {
          device_id: String(device.id),
          user_id: String(device.user_id),
          label: String(device.device_label),
          fingerprint: String(device.fingerprint),
          trust_state: mapTrustState(String(device.trust_state)),
          pqc_status: suite?.pq_kem ? `${suite.pq_kem} + ${suite.classical_kex ?? "X25519"}` : "Unknown",
          suite: suite ?? {},
          last_seen_at: String(device.last_seen_at),
          created_at: String(device.created_at ?? device.last_seen_at),
          revoked_at: device.revoked_at ? String(device.revoked_at) : null,
          approved_by_device_id: device.approved_by_device_id ? String(device.approved_by_device_id) : null,
          x25519_identity_public: byteaToBytes(device.x25519_identity_public),
          mlkem_identity_public: byteaToBytes(device.mlkem_identity_public),
          ed25519_identity_public: byteaToBytes(device.ed25519_identity_public),
          mldsa_identity_public: byteaToBytes(device.mldsa_identity_public),
          identity_signature: identitySignature ?? null,
          signed_prekey: signedPrekeysByDevice.get(String(device.id)) ?? null,
        } satisfies TrustedDevice;
      });
      const myDevices = devices.filter((device) => device.user_id === user.id);

      const envelopeRows = envelopesResult.error ? [] : (envelopesResult.data ?? []) as Array<Record<string, unknown>>;
      const memberRows = conversationMembersResult.error ? [] : (conversationMembersResult.data ?? []) as Array<Record<string, unknown>>;
      const conversationStateRows = conversationStatesResult.error ? [] : (conversationStatesResult.data ?? []) as Array<Record<string, unknown>>;
      const messageUserStateRows = messageUserStatesResult.error ? [] : (messageUserStatesResult.data ?? []) as Array<Record<string, unknown>>;
      const messageStatesByClientId = new Map(messageUserStateRows.map((state) => [String(state.client_message_id), {
        first_read_at: state.first_read_at ? String(state.first_read_at) : null,
        hidden_at: state.hidden_at ? String(state.hidden_at) : null,
      }]));
      const conversationStatesById = new Map(conversationStateRows.map((state) => [String(state.conversation_id), {
        archived_at: state.archived_at ? String(state.archived_at) : null,
        hidden_at: state.hidden_at ? String(state.hidden_at) : null,
        deleted_at: state.deleted_at ? String(state.deleted_at) : null,
      }]));
      const userConversationIds = new Set(memberRows
        .filter((member) => String(member.user_id) === user.id)
        .map((member) => String(member.conversation_id)));
      const contactRows = contactsResult.error ? [] : (contactsResult.data ?? []) as Array<Record<string, unknown>>;
      // Resolve real usernames for conversation members and contacts so direct
      // chats show who the messages come from instead of the generic
      // "Encrypted direct conversation" label. Only public directory fields
      // (username/name/email) are read; message content stays encrypted.
      const directoryUserIds = Array.from(new Set([
        ...memberRows.map((member) => String(member.user_id)),
        ...contactRows.map((contact) => String(contact.contact_user_id)),
        // Envelope participants cover conversations whose membership rows are
        // not visible to this account (older threads), so DM titles still resolve.
        ...envelopeRows.map((envelope) => String(envelope.sender_user_id)),
        ...envelopeRows.map((envelope) => String(envelope.recipient_user_id)),
      ])).filter((id) => id && id !== user.id);
      const profileDirectory = new Map<string, { username: string | null; name: string | null; email: string | null }>();
      if (directoryUserIds.length > 0) {
        const { data: directoryRows, error: directoryError } = await client
          .from("profiles")
          .select("id,username,name,email")
          .in("id", directoryUserIds);
        if (!directoryError) {
          ((directoryRows ?? []) as Array<Record<string, unknown>>).forEach((row) => {
            profileDirectory.set(String(row.id), {
              username: row.username ? String(row.username) : null,
              name: row.name ? String(row.name) : null,
              email: row.email ? String(row.email) : null,
            });
          });
        }
      }
      const memberDisplayName = (memberId: string): string | null => {
        const profile = profileDirectory.get(memberId);
        if (!profile) return null;
        return profile.username || profile.name || (profile.email ? profile.email.split("@")[0] : null);
      };
      const conversations = (conversationsResult.error ? [] : (conversationsResult.data ?? []) as Array<Record<string, unknown>>)
        .filter((conversation) => String(conversation.owner_user_id) === user.id || userConversationIds.has(String(conversation.id)))
        .filter((conversation) => !conversationStatesById.get(String(conversation.id))?.deleted_at)
        .map((conversation) => {
        const conversationEnvelopeRows = envelopeRows.filter((envelope) => String(envelope.conversation_id) === String(conversation.id) && !envelope.deleted_at);
        const latestEnvelope = conversationEnvelopeRows[0] ?? null;
        const unreadGroups = new Set<string>();
        conversationEnvelopeRows
          // Own sent messages also arrive as self-device sync envelopes with
          // recipient_user_id = me; they must never count as unread.
          .filter((envelope) => String(envelope.recipient_user_id) === user.id && String(envelope.sender_user_id) !== user.id)
          // Reaction/edit control envelopes and already-expired disappearing
          // messages are never rendered as readable messages, so they must not
          // keep the unread bubble alive.
          .filter((envelope) => {
            const lifecycle = (envelope.lifecycle ?? {}) as Record<string, unknown>;
            if (lifecycle.control_type) return false;
            const expiresAtMs = envelope.expires_at ? new Date(String(envelope.expires_at)).getTime() : Number.NaN;
            if (Number.isFinite(expiresAtMs) && expiresAtMs <= Date.now()) return false;
            return true;
          })
          .forEach((envelope) => {
            const state = messageStatesByClientId.get(messageGroupId(envelope));
            if (!state?.first_read_at && !state?.hidden_at) unreadGroups.add(messageGroupId(envelope));
          });
        const memberUserIds = Array.from(new Set(memberRows
          .filter((member) => String(member.conversation_id) === String(conversation.id))
          .map((member) => String(member.user_id))));
        const peerUserIds = Array.from(new Set([
          ...memberUserIds,
          ...conversationEnvelopeRows.flatMap((envelope) => [String(envelope.sender_user_id), String(envelope.recipient_user_id)]),
        ])).filter((memberId) => memberId && memberId !== user.id);
        const peerNames = peerUserIds
          .map((memberId) => memberDisplayName(memberId))
          .filter((value): value is string => Boolean(value));
        const peerTitle = peerNames.length > 3
          ? `${peerNames.slice(0, 3).join(", ")} +${peerNames.length - 3}`
          : peerNames.join(", ");
        const state = conversationStatesById.get(String(conversation.id));
        const updatedAt = latestIso(conversation.updated_at, conversation.created_at, latestEnvelope?.created_at);
        return {
          id: String(conversation.id),
          conversation_type: String(conversation.conversation_type),
          title: peerTitle || `Encrypted ${String(conversation.conversation_type)} conversation`,
          last_activity: latestEnvelope ? messageKindLabel(latestEnvelope.message_kind) : "No encrypted messages yet",
          unread_count: unreadGroups.size,
          updated_at: updatedAt,
          member_user_ids: memberUserIds,
          archived_at: state?.archived_at ?? null,
          hidden_at: state?.hidden_at ?? null,
          deleted_at: state?.deleted_at ?? null,
        } satisfies ConversationSummary;
      }).sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());

      const contacts = contactRows.map((contact) => {
        const contactUserId = String(contact.contact_user_id);
        const alias = contact.alias ? String(contact.alias) : null;
        const profile = profileDirectory.get(contactUserId);
        return {
          id: String(contact.id),
          contact_user_id: contactUserId,
          alias,
          display_name: alias ?? profile?.name ?? profile?.username ?? `Contact ${contactUserId.slice(0, 8)}`,
          username: profile?.username ?? (profile?.email ? profile.email.split("@")[0] : contactUserId),
          trust_state: String(contact.trust_state) as ContactSummary["trust_state"],
          created_at: String(contact.created_at),
          updated_at: String(contact.updated_at),
        } satisfies ContactSummary;
      });

      const vaultFiles = (vaultFilesResult.error ? [] : (vaultFilesResult.data ?? []) as Array<Record<string, unknown>>).map((file) => ({
        id: String(file.id),
        storage_path: String(file.storage_path),
        display_name_hint: file.display_name_hint ? String(file.display_name_hint) : null,
        size_bytes: Number(file.size_bytes ?? 0),
        content_type: String(file.content_type),
        suite: (file.suite as Record<string, unknown>) ?? {},
        created_at: String(file.created_at),
        revoked_at: file.revoked_at ? String(file.revoked_at) : null,
      } satisfies VaultFileSummary));

      const securityEvents = (securityEventsResult.error ? [] : (securityEventsResult.data ?? []) as Array<Record<string, unknown>>).map((event) => ({
        id: String(event.id),
        device_id: event.device_id ? String(event.device_id) : null,
        event_type: String(event.event_type),
        severity: String(event.severity) as SecurityEvent["severity"],
        encrypted_details: (event.encrypted_details as Record<string, unknown> | null) ?? null,
        event_hash: String(event.event_hash),
        previous_hash: event.previous_hash ? String(event.previous_hash) : null,
        created_at: String(event.created_at),
      }));
      const orgMembers = (orgMembersResult.error ? [] : (orgMembersResult.data ?? []) as Array<Record<string, unknown>>).map((member) => ({
        org_id: String(member.org_id),
        user_id: String(member.user_id),
        role: String(member.role),
        created_at: String(member.created_at),
      } satisfies OrgMemberSummary));

      const availableOneTimePrekeys = oneTimePrekeysResult.error ? [] : (oneTimePrekeysResult.data ?? []) as Array<Record<string, unknown>>;
      const algorithmNames = new Set<string>();
      myDevices.forEach((device) => {
        if (device.pqc_status && device.pqc_status !== "Unknown") algorithmNames.add(device.pqc_status);
      });
      const keyInventory: KeyInventory = {
        identity_device_count: myDevices.length,
        active_signed_prekeys: activeSignedPrekeys.filter((prekey) => String(prekey.user_id) === user.id).length,
        available_one_time_prekeys: availableOneTimePrekeys.length,
        next_signed_prekey_expiry: activeSignedPrekeys.find((prekey) => String(prekey.user_id) === user.id)?.expires_at
          ? String(activeSignedPrekeys.find((prekey) => String(prekey.user_id) === user.id)?.expires_at)
          : null,
        rotation_events: securityEvents.filter((event) => event.event_type.includes("key") || event.event_type.includes("prekey")).length,
        algorithms: Array.from(algorithmNames),
      };

      const cryptoTelemetryRows = cryptoTelemetryResult.error ? [] : (cryptoTelemetryResult.data ?? []) as Array<Record<string, unknown>>;
      const vaultOperationRows = vaultOperationsResult.error ? [] : (vaultOperationsResult.data ?? []) as Array<Record<string, unknown>>;
      const cryptoTelemetry = cryptoTelemetryRows.map((event) => ({
        id: String(event.id),
        stage: String(event.stage ?? event.event_scope ?? "crypto"),
        detail: String(event.detail ?? event.status ?? "recorded"),
        progress: Number(event.progress ?? 100),
        created_at: String(event.created_at),
      } satisfies TelemetryEvent));
      const vaultTelemetry = vaultOperationRows.map((operation) => ({
        id: `vault-${String(operation.id)}`,
        stage: `vault_${String(operation.operation_type)}`,
        detail: `${String(operation.status)} - ${String(operation.current_operation)} - ${String(operation.display_name_hint)}`,
        progress: Number(operation.progress ?? 0),
        created_at: String(operation.updated_at ?? operation.started_at),
      } satisfies TelemetryEvent));
      const telemetry = [...cryptoTelemetry, ...vaultTelemetry]
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
        .slice(0, 50);

      const totalVaultBytes = vaultFiles.reduce((sum, file) => sum + file.size_bytes, 0);
      const { snapshot, report } = buildSecurityPosture({
        profile,
        devices,
        conversations,
        vaultFiles,
        keyInventory,
        telemetry,
        securityEvents,
        hardening: hardeningStatus,
        vaultStorageLabel: bytesToDisplay(totalVaultBytes),
      });

      const nextData = {
        profile,
        modules,
        devices,
        contacts,
        conversations,
        vaultFiles,
        securityEvents,
        orgMembers,
        keyInventory,
        telemetry,
        hardening: hardeningStatus,
        snapshot,
        report,
      };
      if (refreshSequence !== refreshSequenceRef.current) return;
      setData(nextData);
      setError(null);
    } catch (err) {
      if (refreshSequence === refreshSequenceRef.current) {
        const message = describeDataError(err, "Dashboard data");
        if (!hasLoadedRef.current) {
          setError(message);
        } else {
          console.warn("QGuard dashboard live refresh delayed:", message);
        }
      }
    } finally {
      if (refreshSequence === refreshSequenceRef.current) {
        setLoading(false);
        hasLoadedRef.current = true;
      }
    }
  }, [session, user]);

  refreshCoreRef.current = refreshCore;

  const refresh = useCallback(async () => {
    if (refreshInFlightRef.current) {
      refreshQueuedRef.current = true;
      await refreshInFlightRef.current;
      return;
    }

    do {
      refreshQueuedRef.current = false;
      const refreshPromise = refreshCoreRef.current();
      refreshInFlightRef.current = refreshPromise;
      try {
        await refreshPromise;
      } finally {
        if (refreshInFlightRef.current === refreshPromise) {
          refreshInFlightRef.current = null;
        }
      }
    } while (refreshQueuedRef.current);
  }, []);

  useEffect(() => {
    hasLoadedRef.current = false;
    refreshSequenceRef.current += 1;
    setError(null);
    setLoading(Boolean(user && session));
    if (!user || !session) setData(emptyDashboardData());
  }, [user?.id]);

  useEffect(() => {
    refresh();
  }, [refresh, session?.access_token, user?.id]);

  const live = useQGuardLiveSse(user?.id ?? null, refresh);

  return useMemo(() => ({
    data,
    loading,
    error,
    refresh,
    liveEvents: live.events,
    liveStatus: live.status,
  }), [data, error, live.events, live.status, loading, refresh]);
}
