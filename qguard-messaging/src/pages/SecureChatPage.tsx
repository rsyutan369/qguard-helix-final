import { AlertTriangle, Archive, ArchiveRestore, Ban, Clock, Download, Eye, EyeOff, Loader2, LockKeyhole, Mic, MoreVertical, Paperclip, Pencil, QrCode, Reply, Search, Send, ShieldCheck, Smile, Square, Terminal, TimerReset, Trash2, UnlockKeyhole, UserPlus } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import { byteaToBytes, bytesToBytea } from "@/lib/encoding";
import {
  createSecureDecryptionStream,
  enforceClientDecryptionRateLimit,
  normalizeDecryptionError,
  unlockDevicePrivateKey,
  validateDecryptionSession,
  wipeBytes,
  type DecryptionStatus,
} from "@/lib/secure-decryption";
import { syncCurrentMessagingDevice } from "@/lib/messaging-bootstrap";
import { supabase } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";
import type { ContactSummary, ConversationSummary, DualSignature, SignedPrekeySummary, TrustedDevice, UserSearchResult } from "@/lib/types";

interface SecureChatPageProps {
  userId: string;
  conversations: ConversationSummary[];
  devices: TrustedDevice[];
  contacts: ContactSummary[];
  onSent: () => void;
}

interface EncryptedMessageEnvelope {
  message_id: string;
  conversation_id: string;
  sender_user_id: string;
  recipient_user_id: string;
  sender_device_id: string;
  recipient_device_id: string;
  counter: number;
  kind: string;
  sealed_sender: boolean;
  envelope: {
    nonce: number[];
    ciphertext: number[];
    tag: number[];
  };
  aad: number[];
  hybrid_ciphertext: {
    x25519_ephemeral_public: number[];
    ml_kem_ciphertext: number[];
    suite: Record<string, unknown>;
  };
  prekey_id: string;
  prekey_kind: string;
  message_signature: DualSignature;
  sender_ed25519_public: number[];
  sender_mldsa_public: number[];
  suite: Record<string, unknown>;
  created_at: string;
}

interface MessageEnvelopeRow {
  id: string;
  conversation_id: string;
  client_message_id: string | null;
  parent_client_message_id: string | null;
  sender_user_id: string;
  recipient_user_id: string;
  sender_device_id: string | null;
  recipient_device_id: string | null;
  message_kind: string;
  sealed_sender_envelope: Record<string, unknown>;
  ciphertext: unknown;
  nonce: unknown;
  auth_tag: unknown;
  aad: unknown;
  ratchet_counter: number;
  suite: Record<string, unknown>;
  lifecycle: Record<string, unknown>;
  verification_state: "pending" | "valid" | "tampered" | "expired" | "revoked";
  threat_result: Record<string, unknown>;
  deleted_at: string | null;
  created_at: string;
}

interface DecryptedChatEnvelope {
  message_id: string;
  conversation_id: string;
  plaintext: string;
  authenticated: boolean;
  replay_protected: boolean;
}

interface LocalIdentityBundle {
  device_id: string;
  fingerprint: string;
}

interface LocalSignedPrekeyBundle {
  prekey_id: string;
  device_id: string;
}

interface ChatMessage {
  id: string;
  client_message_id: string;
  row_ids: string[];
  conversation_id: string;
  sender_user_id: string;
  recipient_user_id: string;
  kind: string;
  plaintext: string;
  attachment: SecureChatAttachment | null;
  reply_to: string | null;
  edited_at: string | null;
  reactions: Array<{ actor_user_id: string; reaction: string; created_at: string }>;
  expires_at: string | null;
  available_at: string | null;
  read_once: boolean;
  view_once: boolean;
  threat: ThreatAssessment;
  status: "decrypted" | "sealed" | "failed";
  authenticated: boolean;
  replay_protected: boolean;
  created_at: string;
  error: string | null;
  can_delete: boolean;
}

interface MessageUserState {
  client_message_id: string;
  first_read_at: string | null;
  hidden_at: string | null;
  verification_state: "pending" | "valid" | "tampered" | "expired" | "revoked";
  threat_score: number;
  threat_flags: string[];
}

interface TypingIndicator {
  user_id: string;
  device_id: string | null;
  expires_at: string;
}

interface ChatTelemetryEvent {
  id: string;
  stage: string;
  detail: string;
  progress: number;
  status: string;
  created_at: string;
}

interface ThreatAssessment {
  score: number;
  flags: string[];
  suspicious: boolean;
}

interface SecureChatAttachment {
  kind: "file" | "voice";
  storage_path: string;
  name: string;
  size_bytes: number;
  content_type: string;
  key_b64: string;
  iv_b64: string;
  sha256_b64: string;
  duration_ms: number | null;
  created_at: string;
}

interface DownloadedAttachmentRecord {
  id: string;
  message_id: string;
  name: string;
  kind: SecureChatAttachment["kind"];
  size_bytes: number;
  content_type: string;
  status: DecryptionStatus;
  progress: number;
  detail: string;
  created_at: string;
}

interface SecurePlaintextMessage {
  body: string;
  reply_to: string | null;
  attachment: SecureChatAttachment | null;
  lifecycle: {
    expires_at: string | null;
    available_at: string | null;
    read_once: boolean;
    view_once: boolean;
  };
}

type SecureControlMessage =
  | { type: "reaction"; target_client_message_id: string; reaction: string }
  | { type: "edit"; target_client_message_id: string; body: string };

type ConversationView = "active" | "archived" | "hidden";
type ProtectedConversationView = "archived" | "hidden";

interface ChatProtectionConfig {
  salt_b64: string;
  verifier_b64: string;
  iterations: number;
  created_at: string;
}

function toMessageKind(value: string): string {
  if (value === "FileReference") return "file_reference";
  if (value === "VoiceNote") return "voice_note";
  if (value === "System") return "system";
  return "text";
}

function fromMessageKind(value: string): "Text" | "FileReference" | "VoiceNote" | "System" {
  if (value === "file_reference") return "FileReference";
  if (value === "voice_note") return "VoiceNote";
  if (value === "system") return "System";
  return "Text";
}

function messageKindLabel(kind: string): string {
  if (kind === "file_reference") return "Encrypted file";
  if (kind === "voice_note") return "Voice note";
  if (kind === "system") return "System";
  return "Message";
}

function emptyThreat(): ThreatAssessment {
  return { score: 0, flags: [], suspicious: false };
}

const maxChatAttachmentBytes = 25 * 1024 * 1024;
const chatProtectionIterations = 210_000;
const protectedConversationUnlockMs = 5 * 60 * 1000;

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

function formatDurationMs(ms: number | null): string {
  if (!ms || ms <= 0) return "";
  const seconds = Math.max(1, Math.round(ms / 1000));
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return minutes > 0 ? `${minutes}:${rest.toString().padStart(2, "0")}` : `${seconds}s`;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.slice(index, index + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function chatProtectionStorageKey(userId: string): string {
  return `qguard-chat-protection:${userId}`;
}

function readChatProtectionConfig(userId: string): ChatProtectionConfig | null {
  try {
    const raw = localStorage.getItem(chatProtectionStorageKey(userId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<ChatProtectionConfig>;
    if (!parsed.salt_b64 || !parsed.verifier_b64 || !parsed.iterations) return null;
    return {
      salt_b64: parsed.salt_b64,
      verifier_b64: parsed.verifier_b64,
      iterations: parsed.iterations,
      created_at: parsed.created_at ?? new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

async function deriveChatProtectionVerifier(secret: string, saltB64: string, iterations: number): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: toArrayBuffer(base64ToBytes(saltB64)),
      iterations,
    },
    keyMaterial,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

async function createChatProtectionConfig(secret: string): Promise<ChatProtectionConfig> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = bytesToBase64(salt);
  return {
    salt_b64: saltB64,
    verifier_b64: await deriveChatProtectionVerifier(secret, saltB64, chatProtectionIterations),
    iterations: chatProtectionIterations,
    created_at: new Date().toISOString(),
  };
}

async function verifyChatProtectionSecret(secret: string, config: ChatProtectionConfig): Promise<boolean> {
  const verifier = await deriveChatProtectionVerifier(secret, config.salt_b64, config.iterations);
  return verifier === config.verifier_b64;
}

async function sha256Base64(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes));
  return bytesToBase64(new Uint8Array(digest));
}

function safeAttachmentFileName(name: string): string {
  const cleaned = name.replace(/[^\w.-]+/g, "_").replace(/^_+|_+$/g, "");
  return cleaned.slice(0, 96) || "attachment";
}

function downloadBlob(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

function parseJsonPayload(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function parseSecureAttachment(value: unknown): SecureChatAttachment | null {
  const record = asRecord(value);
  const kind = record.kind === "voice" ? "voice" : record.kind === "file" ? "file" : null;
  const storagePath = typeof record.storage_path === "string" ? record.storage_path : "";
  const keyB64 = typeof record.key_b64 === "string" ? record.key_b64 : "";
  const ivB64 = typeof record.iv_b64 === "string" ? record.iv_b64 : "";
  const sha256B64 = typeof record.sha256_b64 === "string" ? record.sha256_b64 : "";
  if (!kind || !storagePath || !keyB64 || !ivB64 || !sha256B64) return null;
  return {
    kind,
    storage_path: storagePath,
    name: String(record.name ?? (kind === "voice" ? "Encrypted voice note" : "Encrypted attachment")),
    size_bytes: Number(record.size_bytes ?? 0),
    content_type: String(record.content_type ?? "application/octet-stream"),
    key_b64: keyB64,
    iv_b64: ivB64,
    sha256_b64: sha256B64,
    duration_ms: typeof record.duration_ms === "number" ? record.duration_ms : null,
    created_at: String(record.created_at ?? new Date().toISOString()),
  };
}

function parseSecurePlaintext(value: string): SecurePlaintextMessage {
  const parsed = parseJsonPayload(value);
  const lifecycle = asRecord(parsed?.lifecycle);
  if (parsed?.qguard_message_v1 === true) {
    return {
      body: String(parsed.body ?? ""),
      reply_to: typeof parsed.reply_to === "string" ? parsed.reply_to : null,
      attachment: parseSecureAttachment(parsed.attachment),
      lifecycle: {
        expires_at: typeof lifecycle.expires_at === "string" ? lifecycle.expires_at : null,
        available_at: typeof lifecycle.available_at === "string" ? lifecycle.available_at : null,
        read_once: Boolean(lifecycle.read_once),
        view_once: Boolean(lifecycle.view_once),
      },
    };
  }
  return {
    body: value,
    reply_to: null,
    attachment: null,
    lifecycle: {
      expires_at: null,
      available_at: null,
      read_once: false,
      view_once: false,
    },
  };
}

function parseSecureControl(value: string): SecureControlMessage | null {
  const parsed = parseJsonPayload(value);
  if (parsed?.qguard_control_v1 !== true) return null;
  const target = typeof parsed.target_client_message_id === "string" ? parsed.target_client_message_id : "";
  if (!target) return null;
  if (parsed.type === "reaction") {
    return {
      type: "reaction",
      target_client_message_id: target,
      reaction: String(parsed.reaction ?? "").slice(0, 8) || "+1",
    };
  }
  if (parsed.type === "edit") {
    return {
      type: "edit",
      target_client_message_id: target,
      body: String(parsed.body ?? ""),
    };
  }
  return null;
}

function serializeSecureMessage(
  body: string,
  replyTo: string | null,
  lifecycle: SecurePlaintextMessage["lifecycle"],
  attachment: SecureChatAttachment | null = null,
): string {
  return JSON.stringify({
    qguard_message_v1: true,
    body,
    reply_to: replyTo,
    attachment,
    lifecycle,
  });
}

function serializeSecureControl(control: SecureControlMessage): string {
  return JSON.stringify({
    qguard_control_v1: true,
    ...control,
  });
}

function assessThreatLocally(body: string): ThreatAssessment {
  const normalized = body.toLowerCase();
  const flags: string[] = [];
  let score = 0;

  if (/https?:\/\/|www\./i.test(body)) {
    flags.push("link");
    score += 20;
  }
  if (/(password|passcode|seed phrase|recovery phrase|private key|otp|2fa|mfa)/i.test(body)) {
    flags.push("credential_request");
    score += 30;
  }
  if (/(urgent|immediately|verify now|account locked|suspended|final warning)/i.test(body)) {
    flags.push("urgency");
    score += 20;
  }
  if (/(bit\.ly|tinyurl|t\.co|free gift|airdrop|wallet connect|crypto bonus)/i.test(body)) {
    flags.push("phishing_pattern");
    score += 25;
  }
  if (/\.(exe|scr|bat|cmd|ps1|js|vbs)(\s|$|\?)/i.test(normalized)) {
    flags.push("risky_attachment");
    score += 35;
  }

  const uniqueFlags = Array.from(new Set(flags));
  const boundedScore = Math.min(100, score);
  return {
    score: boundedScore,
    flags: uniqueFlags,
    suspicious: boundedScore >= 45,
  };
}

function visibleContactName(contact: ContactSummary): string {
  return contact.alias || contact.display_name || contact.username || contact.contact_user_id.slice(0, 8);
}

function mapDeviceTrustState(value: string): TrustedDevice["trust_state"] {
  const normalized = value.toLowerCase();
  if (value === "ThisDevice" || normalized === "this_device") return "ThisDevice";
  if (value === "Trusted" || normalized === "trusted") return "Trusted";
  if (value === "PendingQrApproval" || normalized === "pending") return "PendingQrApproval";
  if (value === "Revoked" || normalized === "revoked") return "Revoked";
  return "Suspicious";
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function numberArray(value: unknown): number[] {
  return Array.isArray(value) ? value.map((item) => Number(item) & 0xff) : [];
}

function normalizeSignature(value: unknown): DualSignature {
  const signature = asRecord(value);
  return {
    ed25519: numberArray(signature.ed25519),
    ml_dsa_65: numberArray(signature.ml_dsa_65),
  };
}

function messageGroupId(row: MessageEnvelopeRow): string {
  if (row.client_message_id) return row.client_message_id;
  const clientMessageId = row.sealed_sender_envelope.client_message_id;
  return typeof clientMessageId === "string" && clientMessageId.length > 0 ? clientMessageId : row.id;
}

function envelopeString(row: MessageEnvelopeRow, key: string): string | null {
  const value = row.sealed_sender_envelope[key];
  return typeof value === "string" && value.trim() ? value : null;
}

function originalSenderUserId(row: MessageEnvelopeRow): string {
  return envelopeString(row, "sync_original_sender_user_id")
    ?? envelopeString(row, "original_sender_user_id")
    ?? row.sender_user_id;
}

function originalSenderDeviceId(row: MessageEnvelopeRow): string | null {
  return envelopeString(row, "sync_original_sender_device_id")
    ?? envelopeString(row, "original_sender_device_id")
    ?? row.sender_device_id;
}

function envelopeControlType(row: MessageEnvelopeRow): string | null {
  return envelopeString(row, "control_type");
}

function buildTauriEnvelope(row: MessageEnvelopeRow): EncryptedMessageEnvelope {
  const sealed = row.sealed_sender_envelope;
  const hybrid = asRecord(sealed.hybrid_ciphertext);
  return {
    message_id: row.id,
    conversation_id: row.conversation_id,
    sender_user_id: row.sender_user_id,
    recipient_user_id: row.recipient_user_id,
    sender_device_id: row.sender_device_id ?? "",
    recipient_device_id: row.recipient_device_id ?? "",
    counter: Number(row.ratchet_counter ?? 0),
    kind: fromMessageKind(row.message_kind),
    sealed_sender: Boolean(sealed.sealed_sender ?? true),
    envelope: {
      nonce: byteaToBytes(row.nonce),
      ciphertext: byteaToBytes(row.ciphertext),
      tag: byteaToBytes(row.auth_tag),
    },
    aad: byteaToBytes(row.aad),
    hybrid_ciphertext: {
      x25519_ephemeral_public: numberArray(hybrid.x25519_ephemeral_public),
      ml_kem_ciphertext: numberArray(hybrid.ml_kem_ciphertext),
      suite: asRecord(hybrid.suite),
    },
    prekey_id: String(sealed.prekey_id ?? ""),
    prekey_kind: String(sealed.prekey_kind ?? "signed_prekey"),
    message_signature: normalizeSignature(sealed.message_signature),
    sender_ed25519_public: numberArray(sealed.sender_ed25519_public),
    sender_mldsa_public: numberArray(sealed.sender_mldsa_public),
    suite: row.suite,
    created_at: row.created_at,
  };
}

const mlKemPublicKeyLengths = new Set([1184, 1568]);

function hasValidMlKemPublicKey(bytes: number[]): boolean {
  return mlKemPublicKeyLengths.has(bytes.length);
}

function hasSendableKeyBundle(device: TrustedDevice): boolean {
  return Boolean(
    device.identity_signature
    && device.x25519_identity_public.length > 0
    && hasValidMlKemPublicKey(device.mlkem_identity_public)
    && device.ed25519_identity_public.length > 0
    && device.mldsa_identity_public.length > 0
    && device.signed_prekey
    && device.signed_prekey.x25519_public.length > 0
    && hasValidMlKemPublicKey(device.signed_prekey.mlkem_public)
    && device.signed_prekey.signature.ed25519.length > 0
    && device.signed_prekey.signature.ml_dsa_65.length > 0
  );
}

function isTrustedDeviceForDelivery(device: TrustedDevice): boolean {
  return device.trust_state === "ThisDevice" || device.trust_state === "Trusted";
}

function isSendableDevice(device: TrustedDevice): boolean {
  return isTrustedDeviceForDelivery(device) && hasSendableKeyBundle(device);
}

function deviceTime(value: string | null | undefined): number {
  const parsed = new Date(value ?? "").getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function recordTime(record: Record<string, unknown>, key: string): number {
  return deviceTime(typeof record[key] === "string" ? String(record[key]) : null);
}

function deliveryDeviceBucket(device: TrustedDevice): string {
  const stableLabel = device.label.trim().toLowerCase();
  return `${device.user_id}:${stableLabel || device.fingerprint || device.device_id}`;
}

function compareDeliveryDevices(a: TrustedDevice, b: TrustedDevice, localDeviceId: string | null = null): number {
  const aLocal = localDeviceId && a.device_id === localDeviceId ? 1 : 0;
  const bLocal = localDeviceId && b.device_id === localDeviceId ? 1 : 0;
  if (aLocal !== bLocal) return bLocal - aLocal;
  const aCurrent = a.trust_state === "ThisDevice" ? 1 : 0;
  const bCurrent = b.trust_state === "ThisDevice" ? 1 : 0;
  if (aCurrent !== bCurrent) return bCurrent - aCurrent;
  const lastSeenDelta = deviceTime(b.last_seen_at) - deviceTime(a.last_seen_at);
  if (lastSeenDelta !== 0) return lastSeenDelta;
  return deviceTime(b.created_at) - deviceTime(a.created_at);
}

function selectDeliveryDevicesForUsers(
  devices: TrustedDevice[],
  userIds: string[],
  localDeviceId: string | null = null,
): TrustedDevice[] {
  const targetUserIds = new Set(userIds.filter(Boolean));
  if (targetUserIds.size === 0) return [];

  const selectedByBucket = new Map<string, TrustedDevice>();
  devices
    .filter((device) => targetUserIds.has(device.user_id) && isSendableDevice(device))
    .sort((a, b) => compareDeliveryDevices(a, b, localDeviceId))
    .forEach((device) => {
      const bucket = deliveryDeviceBucket(device);
      if (!selectedByBucket.has(bucket)) selectedByBucket.set(bucket, device);
    });

  return Array.from(selectedByBucket.values()).sort((a, b) => compareDeliveryDevices(a, b, localDeviceId));
}

function envelopePrekeyId(row: MessageEnvelopeRow): string | null {
  return envelopeString(row, "prekey_id");
}

function mapSignedPrekeyRow(record: Record<string, unknown>): SignedPrekeySummary {
  return {
    prekey_id: String(record.id),
    x25519_public: byteaToBytes(record.x25519_public),
    mlkem_public: byteaToBytes(record.mlkem_public),
    signature: (record.signature as SignedPrekeySummary["signature"]) ?? { ed25519: [], ml_dsa_65: [] },
    fingerprint: String(record.fingerprint ?? ""),
    expires_at: record.expires_at ? String(record.expires_at) : undefined,
  };
}

function mapTrustedDeviceRow(
  record: Record<string, unknown>,
  signedPrekeysByDevice: Map<string, SignedPrekeySummary>,
): TrustedDevice {
  const suite = record.suite as Record<string, string> | null;
  return {
    device_id: String(record.id),
    user_id: String(record.user_id),
    label: String(record.device_label),
    fingerprint: String(record.fingerprint),
    trust_state: mapDeviceTrustState(String(record.trust_state)),
    pqc_status: suite?.pq_kem ?? "Unknown",
    suite: suite ?? {},
    last_seen_at: String(record.last_seen_at ?? record.created_at),
    created_at: String(record.created_at ?? record.last_seen_at),
    revoked_at: record.revoked_at ? String(record.revoked_at) : null,
    approved_by_device_id: record.approved_by_device_id ? String(record.approved_by_device_id) : null,
    x25519_identity_public: byteaToBytes(record.x25519_identity_public),
    mlkem_identity_public: byteaToBytes(record.mlkem_identity_public),
    ed25519_identity_public: byteaToBytes(record.ed25519_identity_public),
    mldsa_identity_public: byteaToBytes(record.mldsa_identity_public),
    identity_signature: (record.identity_signature as DualSignature | null) ?? null,
    signed_prekey: signedPrekeysByDevice.get(String(record.id)) ?? null,
  };
}

async function claimOneTimePrekey(recipientDevice: TrustedDevice, senderDeviceId: string): Promise<SignedPrekeySummary | null> {
  const { data, error } = await supabase.rpc("claim_messaging_one_time_prekey", {
    p_device_id: recipientDevice.device_id,
    p_sender_device_id: senderDeviceId,
  });
  if (error) return null;
  const row = Array.isArray(data) ? data[0] : data;
  if (!row || typeof row !== "object") return null;
  const record = row as Record<string, unknown>;
  const signature = record.signature as DualSignature | undefined;
  if (!signature?.ed25519?.length || !signature?.ml_dsa_65?.length) return null;
  return {
    prekey_id: String(record.prekey_id),
    x25519_public: byteaToBytes(record.x25519_public),
    mlkem_public: byteaToBytes(record.mlkem_public),
    signature,
    fingerprint: String(record.fingerprint ?? ""),
  };
}

async function loadTrustedDevicesForUsers(userIds: string[]): Promise<TrustedDevice[]> {
  const uniqueUserIds = Array.from(new Set(userIds.filter(Boolean)));
  if (uniqueUserIds.length === 0) return [];

  const { data: deviceRows, error: deviceError } = await supabase
    .from("messaging_devices")
    .select("id,user_id,device_label,fingerprint,trust_state,suite,last_seen_at,created_at,revoked_at,approved_by_device_id,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature")
    .in("user_id", uniqueUserIds)
    .neq("trust_state", "revoked")
    .order("last_seen_at", { ascending: false });
  if (deviceError) throw deviceError;

  const rows = (deviceRows ?? []) as Array<Record<string, unknown>>;
  const deviceIds = rows.map((device) => String(device.id));
  const signedPrekeysByDevice = new Map<string, SignedPrekeySummary>();

  if (deviceIds.length > 0) {
    const { data: prekeyRows, error: prekeyError } = await supabase
      .from("messaging_signed_prekeys")
      .select("id,user_id,device_id,x25519_public,mlkem_public,signature,fingerprint,is_active,expires_at,created_at")
      .in("device_id", deviceIds)
      .eq("is_active", true)
      .order("expires_at", { ascending: true });
    if (prekeyError) throw prekeyError;

    ((prekeyRows ?? []) as Array<Record<string, unknown>>)
      .sort((a, b) => recordTime(b, "created_at") - recordTime(a, "created_at") || recordTime(b, "expires_at") - recordTime(a, "expires_at"))
      .forEach((prekey) => {
        const deviceId = String(prekey.device_id);
        if (!signedPrekeysByDevice.has(deviceId)) signedPrekeysByDevice.set(deviceId, mapSignedPrekeyRow(prekey));
      });
  }

  return rows.map((device) => mapTrustedDeviceRow(device, signedPrekeysByDevice));
}

function recipientKeyBundle(device: TrustedDevice, oneTimePrekey: SignedPrekeySummary | null) {
  if (!device.identity_signature || !device.signed_prekey) return null;
  return {
    identity: {
      userId: device.user_id,
      deviceId: device.device_id,
      x25519IdentityPublic: device.x25519_identity_public,
      mlkemIdentityPublic: device.mlkem_identity_public,
      ed25519IdentityPublic: device.ed25519_identity_public,
      mldsaIdentityPublic: device.mldsa_identity_public,
      identitySignature: device.identity_signature,
    },
    signedPrekey: {
      prekeyId: device.signed_prekey.prekey_id,
      x25519Public: device.signed_prekey.x25519_public,
      mlkemPublic: device.signed_prekey.mlkem_public,
      signature: device.signed_prekey.signature,
    },
    oneTimePrekey: oneTimePrekey ? {
      prekeyId: oneTimePrekey.prekey_id,
      x25519Public: oneTimePrekey.x25519_public,
      mlkemPublic: oneTimePrekey.mlkem_public,
      signature: oneTimePrekey.signature,
    } : null,
  };
}

export default function SecureChatPage({ userId, conversations, devices, contacts, onSent }: SecureChatPageProps) {
  const [activeConversationId, setActiveConversationId] = useState(conversations[0]?.id ?? "");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState("Ready");
  const [query, setQuery] = useState("");
  const [searchResults, setSearchResults] = useState<UserSearchResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [searchFeedback, setSearchFeedback] = useState<string | null>(null);
  const [contactAction, setContactAction] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [messagesLoading, setMessagesLoading] = useState(false);
  const [messageAction, setMessageAction] = useState<string | null>(null);
  const [openMessageMenuId, setOpenMessageMenuId] = useState<string | null>(null);
  const [deletingMessageId, setDeletingMessageId] = useState<string | null>(null);
  const [replyToMessage, setReplyToMessage] = useState<ChatMessage | null>(null);
  const [editingMessage, setEditingMessage] = useState<ChatMessage | null>(null);
  const [readOnce, setReadOnce] = useState(false);
  const [viewOnce, setViewOnce] = useState(false);
  const [disappearSeconds, setDisappearSeconds] = useState(0);
  const [customExpiresAt, setCustomExpiresAt] = useState("");
  const [attachmentBusy, setAttachmentBusy] = useState<"file" | "voice" | "download" | null>(null);
  const [recordingState, setRecordingState] = useState<"idle" | "recording" | "processing">("idle");
  const [attachmentPreviewUrls, setAttachmentPreviewUrls] = useState<Record<string, string>>({});
  const [downloadedFiles, setDownloadedFiles] = useState<DownloadedAttachmentRecord[]>([]);
  const [typingIndicators, setTypingIndicators] = useState<TypingIndicator[]>([]);
  const [chatTelemetry, setChatTelemetry] = useState<ChatTelemetryEvent[]>([]);
  const [typingEnabled, setTypingEnabled] = useState(true);
  const [conversationView, setConversationView] = useState<ConversationView>("active");
  const [openConversationMenuId, setOpenConversationMenuId] = useState<string | null>(null);
  const [conversationBusyId, setConversationBusyId] = useState<string | null>(null);
  const [conversationAction, setConversationAction] = useState<string | null>(null);
  const [contactChatBusyId, setContactChatBusyId] = useState<string | null>(null);
  const [localDeviceId, setLocalDeviceId] = useState<string | null>(null);
  const [localSignedPrekeyId, setLocalSignedPrekeyId] = useState<string | null>(null);
  const [conversationStateOverrides, setConversationStateOverrides] = useState<Record<string, Pick<ConversationSummary, "archived_at" | "hidden_at" | "deleted_at">>>({});
  const [protectionConfig, setProtectionConfig] = useState<ChatProtectionConfig | null>(() => readChatProtectionConfig(userId));
  const [protectedUnlockUntil, setProtectedUnlockUntil] = useState<Record<ProtectedConversationView, number>>({ archived: 0, hidden: 0 });
  const [protectionDialog, setProtectionDialog] = useState<{ target: ProtectedConversationView; conversationId?: string } | null>(null);
  const [protectionSecret, setProtectionSecret] = useState("");
  const [protectionConfirm, setProtectionConfirm] = useState("");
  const [protectionBusy, setProtectionBusy] = useState(false);
  const [protectionError, setProtectionError] = useState<string | null>(null);
  const messageViewportRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const voiceChunksRef = useRef<Blob[]>([]);
  const voiceStartedAtRef = useRef<number>(0);
  const attachmentPreviewUrlsRef = useRef<Record<string, string>>({});
  const decryptedMessageCacheRef = useRef<Map<string, ChatMessage>>(new Map());
  const decryptedControlCacheRef = useRef<Map<string, SecureControlMessage & { sender_user_id: string; created_at: string }>>(new Map());
  const decryptInFlightRef = useRef<Map<string, Promise<DecryptedChatEnvelope>>>(new Map());
  const syncInFlightRef = useRef<Set<string>>(new Set());
  const syncedEnvelopeTargetsRef = useRef<Set<string>>(new Set());
  const searchRequestRef = useRef(0);
  const threatTelemetryRef = useRef<Set<string>>(new Set());
  const typingPulseRef = useRef<number>(0);
  const effectiveConversations = useMemo(() => conversations
    .map((conversation) => ({ ...conversation, ...(conversationStateOverrides[conversation.id] ?? {}) }))
    .filter((conversation) => !conversation.deleted_at), [conversationStateOverrides, conversations]);
  const activeConversations = useMemo(() => effectiveConversations.filter((conversation) => !conversation.archived_at && !conversation.hidden_at), [effectiveConversations]);
  const archivedConversations = useMemo(() => effectiveConversations.filter((conversation) => Boolean(conversation.archived_at) && !conversation.hidden_at), [effectiveConversations]);
  const hiddenConversations = useMemo(() => effectiveConversations.filter((conversation) => Boolean(conversation.hidden_at)), [effectiveConversations]);
  const isArchivedUnlocked = protectedUnlockUntil.archived > Date.now();
  const isHiddenUnlocked = protectedUnlockUntil.hidden > Date.now();
  const visibleConversations = useMemo(() => {
    if (conversationView === "archived") return isArchivedUnlocked ? archivedConversations : [];
    if (conversationView === "hidden") return isHiddenUnlocked ? hiddenConversations : [];
    return activeConversations;
  }, [activeConversations, archivedConversations, conversationView, hiddenConversations, isArchivedUnlocked, isHiddenUnlocked]);
  const activeConversation = visibleConversations.find((conversation) => conversation.id === activeConversationId) ?? visibleConversations[0] ?? null;
  const myDevices = devices.filter((device) => device.user_id === userId && isTrustedDeviceForDelivery(device));
  const rawLocalDevice = localDeviceId ? myDevices.find((device) => device.device_id === localDeviceId) ?? null : null;
  const localDevice = rawLocalDevice
    && localSignedPrekeyId
    && rawLocalDevice.signed_prekey?.prekey_id === localSignedPrekeyId
    ? rawLocalDevice
    : null;
  const currentDevice = localDeviceId
    ? localDevice
    : myDevices.find((device) => device.trust_state === "ThisDevice" && hasSendableKeyBundle(device)) ?? myDevices.find(hasSendableKeyBundle) ?? myDevices[0] ?? null;
  const activeContact = activeConversation
    ? contacts.find((contact) => (
      activeConversation.member_user_ids.includes(contact.contact_user_id)
      || chatMessages.some((chatMessage) => (
        chatMessage.conversation_id === activeConversation.id
        && (chatMessage.sender_user_id === contact.contact_user_id || chatMessage.recipient_user_id === contact.contact_user_id)
      ))
    ))
    : null;
  const activeRecipientUserIds = useMemo(() => {
    const recipientIds = new Set<string>();
    if (activeConversation) {
      activeConversation.member_user_ids.forEach((memberId) => {
        if (memberId && memberId !== userId) recipientIds.add(memberId);
      });
    }
    if (activeContact?.contact_user_id && activeContact.contact_user_id !== userId) {
      recipientIds.add(activeContact.contact_user_id);
    }
    chatMessages.forEach((chatMessage) => {
      if (!activeConversation || chatMessage.conversation_id !== activeConversation.id) return;
      if (chatMessage.sender_user_id && chatMessage.sender_user_id !== userId) recipientIds.add(chatMessage.sender_user_id);
      if (chatMessage.recipient_user_id && chatMessage.recipient_user_id !== userId) recipientIds.add(chatMessage.recipient_user_id);
    });
    return Array.from(recipientIds);
  }, [activeContact, activeConversation, chatMessages, userId]);
  const recipientDevices = useMemo(() => {
    if (!activeConversation) return [];
    return devices.filter((device) => activeRecipientUserIds.includes(device.user_id) && isTrustedDeviceForDelivery(device));
  }, [activeConversation, activeRecipientUserIds, devices]);
  const sendableRecipientDevices = useMemo(
    () => selectDeliveryDevicesForUsers(recipientDevices, activeRecipientUserIds, localDeviceId),
    [activeRecipientUserIds, localDeviceId, recipientDevices],
  );
  const recipientDevicesMissingPrekeys = activeRecipientUserIds.length > 0 && sendableRecipientDevices.length === 0 && recipientDevices.length > 0;
  const recipientDevicesReady = sendableRecipientDevices.length > 0;

  useEffect(() => {
    setProtectionConfig(readChatProtectionConfig(userId));
    setProtectedUnlockUntil({ archived: 0, hidden: 0 });
    setConversationStateOverrides({});
    setLocalDeviceId(null);
    setLocalSignedPrekeyId(null);
    decryptedMessageCacheRef.current.clear();
    decryptedControlCacheRef.current.clear();
    decryptInFlightRef.current.clear();
    syncInFlightRef.current.clear();
    syncedEnvelopeTargetsRef.current.clear();
  }, [userId]);

  useEffect(() => {
    let cancelled = false;
    const wait = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));
    async function syncLocalDevice() {
      for (let attempt = 0; attempt < 4 && !cancelled; attempt += 1) {
        try {
          const bundle = await safeInvoke<LocalIdentityBundle | null>("keys_upload_identity_bundle", { userId }, null);
          if (cancelled) return;
          if (bundle?.device_id) setLocalDeviceId(bundle.device_id);

          const signedPrekey = await safeInvoke<LocalSignedPrekeyBundle | null>("keys_upload_signed_prekey", { userId }, null);
          if (cancelled) return;
          if (signedPrekey?.prekey_id) setLocalSignedPrekeyId(signedPrekey.prekey_id);

          const registeredBundle = await syncCurrentMessagingDevice(supabase, userId);
          if (cancelled) return;
          if (registeredBundle?.device_id) {
            setLocalDeviceId(registeredBundle.device_id);
            await recordCryptoTelemetry({
              userId,
              deviceId: registeredBundle.device_id,
              scope: "message",
              stage: "chat_device_sync_completed",
              detail: "Current desktop identity and signed prekey published for secure chat",
              progress: 100,
              status: "complete",
              metadata: { module: "secure_chat" },
            }).catch(() => undefined);
            onSent();
          }
          return;
        } catch {
          if (attempt < 3) await wait(600);
        }
      }
    }
    syncLocalDevice();
    return () => {
      cancelled = true;
    };
  }, [userId]);

  useEffect(() => {
    decryptedMessageCacheRef.current.clear();
    decryptedControlCacheRef.current.clear();
    decryptInFlightRef.current.clear();
    syncInFlightRef.current.clear();
    syncedEnvelopeTargetsRef.current.clear();
  }, [localDeviceId]);

  useEffect(() => {
    setConversationStateOverrides((current) => {
      const knownIds = new Set(conversations.map((conversation) => conversation.id));
      return Object.fromEntries(Object.entries(current).filter(([conversationId]) => knownIds.has(conversationId)));
    });
  }, [conversations]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      const now = Date.now();
      setProtectedUnlockUntil((current) => {
        const archived = current.archived > now ? current.archived : 0;
        const hidden = current.hidden > now ? current.hidden : 0;
        return archived === current.archived && hidden === current.hidden ? current : { archived, hidden };
      });
    }, 15_000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    if ((conversationView === "archived" && !isArchivedUnlocked) || (conversationView === "hidden" && !isHiddenUnlocked)) {
      setConversationView("active");
      setActiveConversationId(activeConversations[0]?.id ?? "");
    }
  }, [activeConversations, conversationView, isArchivedUnlocked, isHiddenUnlocked]);

  useEffect(() => {
    if (visibleConversations.length === 0) {
      setActiveConversationId("");
      return;
    }
    if (!visibleConversations.some((conversation) => conversation.id === activeConversationId)) {
      setActiveConversationId(visibleConversations[0].id);
    }
  }, [activeConversationId, visibleConversations]);

  useEffect(() => {
    if (localDeviceId && rawLocalDevice && !localSignedPrekeyId) setStatus("Syncing this desktop signed prekey");
    else if (localDeviceId && rawLocalDevice && localSignedPrekeyId && rawLocalDevice.signed_prekey?.prekey_id !== localSignedPrekeyId) setStatus("Refreshing this desktop signed prekey");
    else if (localDeviceId && !currentDevice) setStatus("Sync this desktop device before decrypting or sending");
    else if (myDevices.length === 0) setStatus("Open the desktop app to activate this device");
    else if (activeConversation && activeRecipientUserIds.length === 0) setStatus("Open a contact chat before sending");
    else if (activeConversation && recipientDevices.length === 0) setStatus("Add a trusted contact device");
    else if (activeConversation && !recipientDevicesReady) setStatus("Waiting for recipient PQC prekeys");
    else if (recipientDevicesMissingPrekeys) setStatus("Ready - some trusted devices need PQC prekeys");
    else setStatus("Ready");
  }, [activeConversation, activeRecipientUserIds.length, currentDevice, localDeviceId, localSignedPrekeyId, myDevices.length, rawLocalDevice, recipientDevices.length, recipientDevicesMissingPrekeys, recipientDevicesReady]);

  useEffect(() => {
    attachmentPreviewUrlsRef.current = attachmentPreviewUrls;
  }, [attachmentPreviewUrls]);

  useEffect(() => () => {
    Object.values(attachmentPreviewUrlsRef.current).forEach((url) => URL.revokeObjectURL(url));
  }, []);

  useEffect(() => () => {
    const recorder = mediaRecorderRef.current;
    if (recorder?.state === "recording") recorder.stop();
    recorder?.stream.getTracks().forEach((track) => track.stop());
  }, []);

  function attachmentDownloadId(chatMessage: ChatMessage): string {
    return `${chatMessage.client_message_id}:${chatMessage.attachment?.storage_path ?? "attachment"}`;
  }

  function upsertDownloadedFile(record: DownloadedAttachmentRecord) {
    setDownloadedFiles((current) => {
      const withoutCurrent = current.filter((item) => item.id !== record.id);
      return [record, ...withoutCurrent].slice(0, 12);
    });
  }

  function patchDownloadedFile(id: string, patch: Partial<DownloadedAttachmentRecord>) {
    setDownloadedFiles((current) =>
      current.map((item) => item.id === id ? { ...item, ...patch } : item),
    );
  }

  function attachmentDecryptionStatus(chatMessage: ChatMessage): DecryptionStatus {
    if (!chatMessage.attachment) return "encrypted";
    return downloadedFiles.find((item) => item.id === attachmentDownloadId(chatMessage))?.status ?? "encrypted";
  }

  function renderAttachmentStatus(statusValue: DecryptionStatus) {
    const tone = statusValue === "decrypted"
      ? "bg-emerald-50 text-emerald-600"
      : statusValue === "decrypting"
        ? "bg-cyan-50 text-cyan-700"
        : statusValue === "failed"
          ? "bg-rose-50 text-rose-600"
          : "bg-ink-50 text-ink-600";
    const Icon = statusValue === "decrypted" ? UnlockKeyhole : statusValue === "decrypting" ? Loader2 : LockKeyhole;
    return (
      <span className={`status-pill ${tone}`}>
        <Icon className={statusValue === "decrypting" ? "animate-spin" : ""} size={13} />
        {statusValue}
      </span>
    );
  }

  function appendChatDecryptionEvent(stage: string, detail: string, progress: number, statusValue: string) {
    setChatTelemetry((current) => [
      {
        id: `local-${crypto.randomUUID()}`,
        stage,
        detail,
        progress,
        status: statusValue,
        created_at: new Date().toISOString(),
      },
      ...current,
    ].slice(0, 40));
  }

  function conversationTitle(conversation: ConversationSummary): string {
    const contact = contacts.find((item) => conversation.member_user_ids.includes(item.contact_user_id));
    return contact ? visibleContactName(contact) : conversation.title;
  }

  function describeMessageError(error: unknown): string {
    if (error instanceof Error) return error.message;
    return String(error);
  }

  async function syncMissingDeviceEnvelopes(
    groupId: string,
    sourceRow: MessageEnvelopeRow,
    orderedRows: MessageEnvelopeRow[],
    plaintext: string,
  ): Promise<void> {
    if (!activeConversation || !currentDevice || !hasSendableKeyBundle(currentDevice)) return;

    const syncRunKey = `${activeConversation.id}:${groupId}:${currentDevice.device_id}`;
    if (syncInFlightRef.current.has(syncRunKey)) return;
    syncInFlightRef.current.add(syncRunKey);

    try {
      const participantUserIds = Array.from(new Set([
        userId,
        ...activeConversation.member_user_ids,
        originalSenderUserId(sourceRow),
        sourceRow.recipient_user_id,
      ].filter(Boolean)));
      const participantDevices = selectDeliveryDevicesForUsers(
        await loadTrustedDevicesForUsers(participantUserIds),
        participantUserIds,
        localDeviceId,
      );
      const existingTargets = new Set(
        orderedRows
          .filter((row) => !row.deleted_at && row.recipient_device_id)
          .map((row) => `${row.recipient_user_id}:${row.recipient_device_id}`),
      );
      const missingDevices = participantDevices.filter((device) => !existingTargets.has(`${device.user_id}:${device.device_id}`));
      if (missingDevices.length === 0) return;

      appendChatDecryptionEvent(
        "device_sync_started",
        `Rewrapping encrypted history for ${missingDevices.length} trusted device${missingDevices.length === 1 ? "" : "s"}`,
        18,
        "progress",
      );
      await recordCryptoTelemetry({
        userId,
        deviceId: currentDevice.device_id,
        scope: "message",
        stage: "device_sync_started",
        detail: "Trusted-device envelope synchronization started",
        progress: 18,
        status: "started",
        metadata: {
          conversation_id: activeConversation.id,
          client_message_id: groupId,
          missing_devices: missingDevices.length,
          source_envelope_id: sourceRow.id,
        },
      });

      let syncedCount = 0;
      for (const targetDevice of missingDevices) {
        const targetKey = `${activeConversation.id}:${groupId}:${targetDevice.device_id}`;
        if (syncedEnvelopeTargetsRef.current.has(targetKey)) continue;
        syncedEnvelopeTargetsRef.current.add(targetKey);

        const recipient = recipientKeyBundle(targetDevice, null);
        if (!recipient) continue;

        const { data: existingRows, error: existingError } = await supabase
          .from("messaging_message_envelopes")
          .select("id")
          .eq("conversation_id", activeConversation.id)
          .eq("client_message_id", groupId)
          .eq("recipient_user_id", targetDevice.user_id)
          .eq("recipient_device_id", targetDevice.device_id)
          .is("deleted_at", null)
          .limit(1);
        if (!existingError && existingRows && existingRows.length > 0) continue;

        const envelope = await safeInvoke<EncryptedMessageEnvelope>("messaging_send_encrypted_message", {
          request: {
            conversationId: activeConversation.id,
            senderUserId: userId,
            recipientUserId: targetDevice.user_id,
            recipientDeviceId: targetDevice.device_id,
            plaintext,
            kind: fromMessageKind(sourceRow.message_kind),
            recipient,
          },
        });

        const sourceLifecycle = sourceRow.lifecycle;
        const sourceExpiresAt = typeof sourceLifecycle.expires_at === "string" ? sourceLifecycle.expires_at : null;
        const { error } = await supabase.from("messaging_message_envelopes").insert({
          id: envelope.message_id,
          conversation_id: envelope.conversation_id,
          client_message_id: groupId,
          parent_client_message_id: sourceRow.parent_client_message_id,
          sender_user_id: userId,
          sender_device_id: envelope.sender_device_id,
          recipient_user_id: targetDevice.user_id,
          recipient_device_id: envelope.recipient_device_id,
          message_kind: sourceRow.message_kind,
          sealed_sender_envelope: {
            sealed_sender: envelope.sealed_sender,
            desktop_envelope_version: 3,
            client_message_id: groupId,
            parent_client_message_id: sourceRow.parent_client_message_id,
            control_type: envelopeControlType(sourceRow),
            local_archive: targetDevice.user_id === userId,
            synced_from_envelope_id: sourceRow.id,
            sync_original_sender_user_id: originalSenderUserId(sourceRow),
            sync_original_sender_device_id: originalSenderDeviceId(sourceRow),
            sync_rewrapped_by_user_id: userId,
            sync_rewrapped_by_device_id: currentDevice.device_id,
            sync_rewrapped_at: new Date().toISOString(),
            hybrid_ciphertext: envelope.hybrid_ciphertext,
            prekey_id: envelope.prekey_id,
            prekey_kind: envelope.prekey_kind,
            message_signature: envelope.message_signature,
            sender_ed25519_public: envelope.sender_ed25519_public,
            sender_mldsa_public: envelope.sender_mldsa_public,
          },
          ciphertext: bytesToBytea(envelope.envelope.ciphertext),
          nonce: bytesToBytea(envelope.envelope.nonce),
          auth_tag: bytesToBytea(envelope.envelope.tag),
          aad: bytesToBytea(envelope.aad),
          ratchet_counter: envelope.counter,
          suite: envelope.suite,
          expires_at: sourceExpiresAt,
          lifecycle: sourceRow.lifecycle,
          verification_state: "valid",
          threat_result: {
            ...sourceRow.threat_result,
            synced_from_envelope_id: sourceRow.id,
            sync_rewrapped_by_device_id: currentDevice.device_id,
          },
        });
        if (error) {
          syncedEnvelopeTargetsRef.current.delete(targetKey);
          throw error;
        }
        syncedCount += 1;
      }

      if (syncedCount > 0) {
        appendChatDecryptionEvent(
          "device_sync_completed",
          `Historical envelope rewrapped for ${syncedCount} trusted device${syncedCount === 1 ? "" : "s"}`,
          100,
          "complete",
        );
        await recordCryptoTelemetry({
          userId,
          deviceId: currentDevice.device_id,
          scope: "message",
          stage: "device_sync_completed",
          detail: "Historical message envelopes rewrapped for trusted devices",
          progress: 100,
          status: "complete",
          metadata: {
            conversation_id: activeConversation.id,
            client_message_id: groupId,
            synced_devices: syncedCount,
            source_envelope_id: sourceRow.id,
          },
        });
      }
    } catch (error) {
      const detail = describeMessageError(error);
      appendChatDecryptionEvent("device_sync_failed", detail, 0, "failed");
      await recordCryptoTelemetry({
        userId,
        deviceId: currentDevice.device_id,
        scope: "message",
        stage: "device_sync_failed",
        detail,
        progress: 0,
        status: "failed",
        metadata: {
          conversation_id: activeConversation.id,
          client_message_id: groupId,
          source_envelope_id: sourceRow.id,
        },
      });
    } finally {
      syncInFlightRef.current.delete(syncRunKey);
    }
  }

  async function hydrateMessageRows(rows: MessageEnvelopeRow[], userStates: Map<string, MessageUserState>): Promise<ChatMessage[]> {
    const groups = new Map<string, MessageEnvelopeRow[]>();
    rows
      .filter((row) => !row.deleted_at)
      .forEach((row) => {
        const groupId = messageGroupId(row);
        groups.set(groupId, [...(groups.get(groupId) ?? []), row]);
      });

    const hydrated: ChatMessage[] = [];
    const controls: Array<SecureControlMessage & { sender_user_id: string; created_at: string }> = [];
    const decryptDeviceId = localDeviceId ?? currentDevice?.device_id ?? null;
    for (const [groupId, groupRows] of groups) {
      const orderedRows = [...groupRows].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
      const candidateRows = orderedRows.filter((row) => row.recipient_user_id === userId);
      const exactLocalRow = decryptDeviceId
        ? orderedRows.find((row) => row.recipient_user_id === userId && row.recipient_device_id === decryptDeviceId)
        : null;
      const decryptRows = (exactLocalRow
        ? [exactLocalRow, ...candidateRows.filter((row) => row.id !== exactLocalRow.id)]
        : candidateRows)
        .sort((a, b) => {
          const aPrekeyMatch = localSignedPrekeyId && envelopePrekeyId(a) === localSignedPrekeyId ? 1 : 0;
          const bPrekeyMatch = localSignedPrekeyId && envelopePrekeyId(b) === localSignedPrekeyId ? 1 : 0;
          if (aPrekeyMatch !== bPrekeyMatch) return bPrekeyMatch - aPrekeyMatch;
          const aDeviceMatch = decryptDeviceId && a.recipient_device_id === decryptDeviceId ? 1 : 0;
          const bDeviceMatch = decryptDeviceId && b.recipient_device_id === decryptDeviceId ? 1 : 0;
          if (aDeviceMatch !== bDeviceMatch) return bDeviceMatch - aDeviceMatch;
          return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        });
      const userRow = candidateRows[0] ?? null;
      const displayRow = exactLocalRow ?? userRow ?? orderedRows[0];
      const isMine = originalSenderUserId(displayRow) === userId;
      const state = userStates.get(groupId);
      const cachedControl = decryptedControlCacheRef.current.get(groupId);
      if (cachedControl) {
        controls.push(cachedControl);
        continue;
      }
      const cached = decryptedMessageCacheRef.current.get(groupId);
      if (cached) {
        if (!isMine && (cached.read_once || cached.view_once) && state?.first_read_at) continue;
        hydrated.push({
          ...cached,
          row_ids: orderedRows.map((row) => row.id),
          can_delete: isMine,
        });
        continue;
      }

      if (decryptRows.length > 0) {
        let lastDecryptError: string | null = null;
        let handledGroup = false;
        for (const localRow of decryptRows) {
          try {
          const decryptKey = `${groupId}:${localRow.id}`;
          let decryptedPromise = decryptInFlightRef.current.get(decryptKey);
          if (!decryptedPromise) {
            decryptedPromise = safeInvoke<DecryptedChatEnvelope>("messaging_receive_encrypted_message", {
              envelope: buildTauriEnvelope(localRow),
            });
            decryptInFlightRef.current.set(decryptKey, decryptedPromise);
            decryptedPromise.finally(() => {
              if (decryptInFlightRef.current.get(decryptKey) === decryptedPromise) {
                decryptInFlightRef.current.delete(decryptKey);
              }
            }).catch(() => undefined);
          }
          const decrypted = await decryptedPromise;
          const localRowSenderUserId = originalSenderUserId(localRow);
          const localRowIsMine = localRowSenderUserId === userId;
          const control = parseSecureControl(decrypted.plaintext);
          if (control) {
            void syncMissingDeviceEnvelopes(groupId, localRow, orderedRows, decrypted.plaintext);
            const controlMessage = { ...control, sender_user_id: localRowSenderUserId, created_at: localRow.created_at };
            decryptedControlCacheRef.current.set(groupId, controlMessage);
            controls.push(controlMessage);
            handledGroup = true;
            break;
          }
          const secureMessage = parseSecurePlaintext(decrypted.plaintext);
          const isExpired = Boolean(secureMessage.lifecycle.expires_at && new Date(secureMessage.lifecycle.expires_at).getTime() <= Date.now());
          const isLocked = Boolean(secureMessage.lifecycle.available_at && new Date(secureMessage.lifecycle.available_at).getTime() > Date.now());
          if (state?.hidden_at || isExpired || (!localRowIsMine && (secureMessage.lifecycle.read_once || secureMessage.lifecycle.view_once) && state?.first_read_at)) {
            handledGroup = true;
            break;
          }
          void syncMissingDeviceEnvelopes(groupId, localRow, orderedRows, decrypted.plaintext);
          const threat = assessThreatLocally(secureMessage.body);
          const chatMessage: ChatMessage = {
            id: decrypted.message_id,
            client_message_id: groupId,
            row_ids: orderedRows.map((row) => row.id),
            conversation_id: decrypted.conversation_id,
            sender_user_id: localRowSenderUserId,
            recipient_user_id: localRow.recipient_user_id,
            kind: localRow.message_kind,
            plaintext: isLocked ? `Time-locked message unlocks ${new Date(secureMessage.lifecycle.available_at ?? "").toLocaleString()}` : secureMessage.body,
            attachment: isLocked ? null : secureMessage.attachment,
            reply_to: secureMessage.reply_to,
            edited_at: null,
            reactions: [],
            expires_at: secureMessage.lifecycle.expires_at,
            available_at: secureMessage.lifecycle.available_at,
            read_once: secureMessage.lifecycle.read_once,
            view_once: secureMessage.lifecycle.view_once,
            threat,
            status: "decrypted",
            authenticated: decrypted.authenticated,
            replay_protected: decrypted.replay_protected,
            created_at: localRow.created_at,
            error: null,
            can_delete: localRowIsMine,
          };
          decryptedMessageCacheRef.current.set(groupId, chatMessage);
          hydrated.push(chatMessage);
          handledGroup = true;
          break;
        } catch (error) {
          const replayMessage = describeMessageError(error);
          lastDecryptError = replayMessage;
          const cachedAfterReplay = decryptedMessageCacheRef.current.get(groupId);
          if (replayMessage.toLowerCase().includes("replay detected") && cachedAfterReplay) {
            if (!isMine && (cachedAfterReplay.read_once || cachedAfterReplay.view_once) && state?.first_read_at) {
              handledGroup = true;
              break;
            }
            hydrated.push({
              ...cachedAfterReplay,
              row_ids: orderedRows.map((row) => row.id),
              can_delete: isMine,
            });
            handledGroup = true;
            break;
          }
          const cachedControlAfterReplay = decryptedControlCacheRef.current.get(groupId);
          if (replayMessage.toLowerCase().includes("replay detected") && cachedControlAfterReplay) {
            controls.push(cachedControlAfterReplay);
            handledGroup = true;
            break;
          }
        }
        }
        if (handledGroup) continue;
        const failedRow = decryptRows[0];
        const failedRowSenderUserId = originalSenderUserId(failedRow);
          hydrated.push({
            id: failedRow.id,
            client_message_id: groupId,
            row_ids: orderedRows.map((row) => row.id),
            conversation_id: failedRow.conversation_id,
            sender_user_id: failedRowSenderUserId,
            recipient_user_id: failedRow.recipient_user_id,
            kind: failedRow.message_kind,
            plaintext: messageKindLabel(failedRow.message_kind),
            attachment: null,
            reply_to: null,
            edited_at: null,
            reactions: [],
            expires_at: null,
            available_at: null,
            read_once: false,
            view_once: false,
            threat: emptyThreat(),
            status: "failed",
            authenticated: false,
            replay_protected: false,
            created_at: failedRow.created_at,
            error: lastDecryptError ?? "No decryptable trusted-device envelope could be recovered locally.",
            can_delete: failedRowSenderUserId === userId,
          });
      } else if (isMine) {
        hydrated.push({
          id: displayRow.id,
          client_message_id: groupId,
          row_ids: orderedRows.map((row) => row.id),
          conversation_id: displayRow.conversation_id,
          sender_user_id: originalSenderUserId(displayRow),
          recipient_user_id: displayRow.recipient_user_id,
          kind: displayRow.message_kind,
          plaintext: "Sent encrypted message",
          attachment: null,
          reply_to: null,
          edited_at: null,
          reactions: [],
          expires_at: null,
          available_at: null,
          read_once: false,
          view_once: false,
          threat: emptyThreat(),
          status: "sealed",
          authenticated: true,
          replay_protected: true,
          created_at: displayRow.created_at,
          error: "Syncing this older sent message to the current trusted device.",
          can_delete: true,
        });
      } else if (userRow) {
        const sealedReason = decryptDeviceId
          ? "Waiting for trusted-device synchronization. No sender resend is required once a device with message access comes online."
          : "No local desktop private key is active. Sign in with the QGuard desktop app to sync trusted devices.";
        hydrated.push({
          id: userRow.id,
          client_message_id: groupId,
          row_ids: orderedRows.map((row) => row.id),
          conversation_id: userRow.conversation_id,
          sender_user_id: originalSenderUserId(userRow),
          recipient_user_id: userRow.recipient_user_id,
          kind: userRow.message_kind,
          plaintext: messageKindLabel(userRow.message_kind),
          attachment: null,
          reply_to: null,
          edited_at: null,
          reactions: [],
          expires_at: null,
          available_at: null,
          read_once: false,
          view_once: false,
          threat: emptyThreat(),
          status: "sealed",
          authenticated: false,
          replay_protected: false,
          created_at: userRow.created_at,
          error: sealedReason,
          can_delete: false,
        });
      }
    }

    const byId = new Map(hydrated.map((item) => [item.client_message_id, item]));
    controls.forEach((control) => {
      const target = byId.get(control.target_client_message_id);
      if (!target) return;
      if (control.type === "reaction") {
        const withoutPrevious = target.reactions.filter((reaction) => reaction.actor_user_id !== control.sender_user_id);
        target.reactions = [...withoutPrevious, {
          actor_user_id: control.sender_user_id,
          reaction: control.reaction,
          created_at: control.created_at,
        }];
      }
      if (control.type === "edit" && target.sender_user_id === control.sender_user_id) {
        target.plaintext = control.body;
        target.edited_at = control.created_at;
        target.threat = assessThreatLocally(control.body);
      }
    });

    return hydrated.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
  }

  async function persistMessageUserStates(messages: ChatMessage[]) {
    if (!activeConversation) return;
    const rows = messages
      .filter((item) => item.status === "decrypted")
      .map((item) => {
        const markAsRead = item.sender_user_id !== userId && (item.read_once || (item.view_once && !item.attachment));
        return {
          user_id: userId,
          conversation_id: activeConversation.id,
          client_message_id: item.client_message_id,
          first_read_at: markAsRead ? new Date().toISOString() : null,
          verification_state: item.authenticated ? "valid" : "tampered",
          threat_score: item.threat.score,
          threat_flags: item.threat.flags,
          proof: {
            suite: "X25519 + ML-KEM-1024, HKDF-SHA3-256, AES-256-GCM, Ed25519 + ML-DSA-65",
            replay_protected: item.replay_protected,
            local_only_plaintext: true,
          },
          updated_at: new Date().toISOString(),
        };
      });
    if (rows.length === 0) return;
    await supabase
      .from("messaging_message_user_states")
      .upsert(rows, { onConflict: "user_id,conversation_id,client_message_id" });

    for (const item of messages) {
      if (!item.threat.suspicious || threatTelemetryRef.current.has(item.client_message_id)) continue;
      threatTelemetryRef.current.add(item.client_message_id);
      await recordCryptoTelemetry({
        userId,
        deviceId: currentDevice?.device_id ?? null,
        scope: "message",
        stage: "message_threat_detected",
        detail: "Suspicious message detected by local threat intelligence",
        progress: item.threat.score,
        status: "verified",
        metadata: {
          conversation_id: item.conversation_id,
          client_message_id: item.client_message_id,
          risk_score: item.threat.score,
        },
      });
    }
  }

  async function markViewOnceAttachmentOpened(chatMessage: ChatMessage) {
    if (!activeConversation || chatMessage.sender_user_id === userId || !chatMessage.view_once || !chatMessage.attachment) return;
    const viewedAt = new Date().toISOString();
    const { error } = await supabase
      .from("messaging_message_user_states")
      .upsert({
        user_id: userId,
        conversation_id: activeConversation.id,
        client_message_id: chatMessage.client_message_id,
        first_read_at: viewedAt,
        verification_state: chatMessage.authenticated ? "valid" : "tampered",
        threat_score: chatMessage.threat.score,
        threat_flags: chatMessage.threat.flags,
        proof: {
          suite: "X25519 + ML-KEM-1024, HKDF-SHA3-256, AES-256-GCM, Ed25519 + ML-DSA-65",
          replay_protected: chatMessage.replay_protected,
          local_only_plaintext: true,
          view_once_opened: true,
        },
        updated_at: viewedAt,
      }, { onConflict: "user_id,conversation_id,client_message_id" });
    if (error) throw error;
  }

  const loadConversationMessages = useCallback(async () => {
    if (!activeConversation) {
      setChatMessages([]);
      return;
    }

    setMessagesLoading(true);
    setMessageAction(null);
    try {
      const [{ data, error }, statesResult] = await Promise.all([
        supabase
        .from("messaging_message_envelopes")
        .select("id,conversation_id,client_message_id,parent_client_message_id,sender_user_id,sender_device_id,recipient_user_id,recipient_device_id,message_kind,sealed_sender_envelope,ciphertext,nonce,auth_tag,aad,ratchet_counter,suite,lifecycle,verification_state,threat_result,deleted_at,created_at")
        .eq("conversation_id", activeConversation.id)
        .is("deleted_at", null)
        .order("created_at", { ascending: true })
        .limit(250),
        supabase
          .from("messaging_message_user_states")
          .select("client_message_id,first_read_at,hidden_at,verification_state,threat_score,threat_flags")
          .eq("conversation_id", activeConversation.id)
          .eq("user_id", userId),
      ]);
      if (error) throw error;

      const rows = ((data ?? []) as Array<Record<string, unknown>>).map((row) => ({
        id: String(row.id),
        conversation_id: String(row.conversation_id),
        client_message_id: row.client_message_id ? String(row.client_message_id) : null,
        parent_client_message_id: row.parent_client_message_id ? String(row.parent_client_message_id) : null,
        sender_user_id: String(row.sender_user_id),
        sender_device_id: row.sender_device_id ? String(row.sender_device_id) : null,
        recipient_user_id: String(row.recipient_user_id),
        recipient_device_id: row.recipient_device_id ? String(row.recipient_device_id) : null,
        message_kind: String(row.message_kind ?? "text"),
        sealed_sender_envelope: asRecord(row.sealed_sender_envelope),
        ciphertext: row.ciphertext,
        nonce: row.nonce,
        auth_tag: row.auth_tag,
        aad: row.aad,
        ratchet_counter: Number(row.ratchet_counter ?? 0),
        suite: asRecord(row.suite),
        lifecycle: asRecord(row.lifecycle),
        verification_state: String(row.verification_state ?? "pending") as MessageEnvelopeRow["verification_state"],
        threat_result: asRecord(row.threat_result),
        deleted_at: row.deleted_at ? String(row.deleted_at) : null,
        created_at: String(row.created_at),
      } satisfies MessageEnvelopeRow));
      const stateRows = statesResult.error ? [] : (statesResult.data ?? []) as Array<Record<string, unknown>>;
      const userStates = new Map(stateRows.map((row) => [String(row.client_message_id), {
        client_message_id: String(row.client_message_id),
        first_read_at: row.first_read_at ? String(row.first_read_at) : null,
        hidden_at: row.hidden_at ? String(row.hidden_at) : null,
        verification_state: String(row.verification_state ?? "pending") as MessageUserState["verification_state"],
        threat_score: Number(row.threat_score ?? 0),
        threat_flags: Array.isArray(row.threat_flags) ? row.threat_flags.map(String) : [],
      } satisfies MessageUserState]));
      const hydrated = await hydrateMessageRows(rows, userStates);
      setChatMessages(hydrated);
      persistMessageUserStates(hydrated).catch(() => undefined);
    } catch (error) {
      setMessageAction(describeMessageError(error));
    } finally {
      setMessagesLoading(false);
    }
  }, [activeConversation, currentDevice?.device_id, localDeviceId, localSignedPrekeyId, userId]);

  useEffect(() => {
    loadConversationMessages();
  }, [loadConversationMessages]);

  useEffect(() => {
    if (!activeConversation) return undefined;
    const channel = supabase
      .channel(`qguard-chat-messages-${activeConversation.id}`)
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "messaging_message_envelopes", filter: `conversation_id=eq.${activeConversation.id}` },
        () => {
          loadConversationMessages();
        },
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "messaging_message_user_states", filter: `conversation_id=eq.${activeConversation.id}` },
        () => {
          loadConversationMessages();
        },
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [activeConversation, loadConversationMessages]);

  useEffect(() => {
    const viewport = messageViewportRef.current;
    if (!viewport) return;
    viewport.scrollTop = viewport.scrollHeight;
  }, [activeConversationId, chatMessages.length]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      const now = Date.now();
      setChatMessages((items) => items.filter((item) => !item.expires_at || new Date(item.expires_at).getTime() > now));
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const loadChatTelemetry = useCallback(async () => {
    const { data, error } = await supabase
      .from("messaging_crypto_telemetry")
      .select("id,stage,detail,progress,status,created_at,redacted_metadata")
      .eq("user_id", userId)
      .eq("event_scope", "message")
      .order("created_at", { ascending: false })
      .limit(40);
    if (error) return;
    setChatTelemetry(((data ?? []) as Array<Record<string, unknown>>).map((row) => ({
      id: String(row.id),
      stage: String(row.stage),
      detail: String(row.detail),
      progress: Number(row.progress ?? 0),
      status: String(row.status ?? "progress"),
      created_at: String(row.created_at),
    } satisfies ChatTelemetryEvent)));
  }, [userId]);

  const loadTypingIndicators = useCallback(async () => {
    if (!activeConversation) {
      setTypingIndicators([]);
      return;
    }
    try {
      await supabase.rpc("prune_expired_messaging_typing_indicators");
    } catch {
      // Migration may not be applied yet; typing cleanup is best-effort.
    }
    const { data, error } = await supabase
      .from("messaging_typing_indicators")
      .select("user_id,device_id,expires_at,is_typing")
      .eq("conversation_id", activeConversation.id)
      .neq("user_id", userId)
      .eq("is_typing", true)
      .gt("expires_at", new Date().toISOString());
    if (error) return;
    setTypingIndicators(((data ?? []) as Array<Record<string, unknown>>).map((row) => ({
      user_id: String(row.user_id),
      device_id: row.device_id ? String(row.device_id) : null,
      expires_at: String(row.expires_at),
    } satisfies TypingIndicator)));
  }, [activeConversation, userId]);

  useEffect(() => {
    loadChatTelemetry();
  }, [loadChatTelemetry]);

  useEffect(() => {
    loadTypingIndicators();
  }, [loadTypingIndicators]);

  useEffect(() => {
    if (!activeConversation) return undefined;
    const channel = supabase
      .channel(`qguard-chat-security-${activeConversation.id}-${userId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "messaging_typing_indicators", filter: `conversation_id=eq.${activeConversation.id}` }, loadTypingIndicators)
      .on("postgres_changes", { event: "*", schema: "public", table: "messaging_crypto_telemetry", filter: `user_id=eq.${userId}` }, loadChatTelemetry)
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [activeConversation, loadChatTelemetry, loadTypingIndicators, userId]);

  async function pulseTyping() {
    if (!activeConversation || !currentDevice || !typingEnabled) return;
    const now = Date.now();
    if (now - typingPulseRef.current < 2500) return;
    typingPulseRef.current = now;
    await supabase.from("messaging_typing_indicators").upsert({
      conversation_id: activeConversation.id,
      user_id: userId,
      device_id: currentDevice.device_id,
      is_typing: true,
      expires_at: new Date(now + 8000).toISOString(),
      updated_at: new Date(now).toISOString(),
    }, { onConflict: "conversation_id,user_id,device_id" });
  }

  async function searchUsers() {
    const trimmed = query.trim();
    if (trimmed.length < 2) {
      setSearchResults([]);
      setSearchFeedback(null);
      return;
    }
    await runUserSearch(trimmed);
  }

  function normalizeUserSearchQuery(value: string): string {
    const trimmed = value.trim();
    if (trimmed.toLowerCase().startsWith("qguard-user:")) return trimmed.slice("qguard-user:".length).trim();
    return trimmed.replace(/^qr:/i, "").trim();
  }

  function mapProfileSearchRows(rows: Array<Record<string, unknown>>): UserSearchResult[] {
    const byId = new Map<string, UserSearchResult>();
    rows.forEach((row) => {
      const userIdValue = String(row.id ?? row.user_id ?? "");
      if (!userIdValue || userIdValue === userId) return;
      const emailPrefix = String(row.email ?? "").split("@")[0];
      const username = String(row.username ?? emailPrefix ?? userIdValue.slice(0, 8));
      byId.set(userIdValue, {
        user_id: userIdValue,
        display_name: String(row.name ?? row.display_name ?? (username || "QGuard User")),
        username,
      });
    });
    return Array.from(byId.values()).slice(0, 10);
  }

  async function fallbackSearchProfiles(rawQuery: string): Promise<UserSearchResult[]> {
    const normalized = normalizeUserSearchQuery(rawQuery);
    if (normalized.length < 2) return [];
    const escaped = normalized.replace(/[%_]/g, "\\$&");
    const columns = "id,email,name,username";
    const queries = [
      supabase.from("profiles").select(columns).neq("id", userId).ilike("username", `${escaped}%`).limit(10),
      supabase.from("profiles").select(columns).neq("id", userId).ilike("name", `${escaped}%`).limit(10),
      supabase.from("profiles").select(columns).neq("id", userId).ilike("email", `${escaped}%`).limit(10),
    ];
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(normalized)) {
      queries.unshift(supabase.from("profiles").select(columns).eq("id", normalized).limit(1));
    }
    const results = await Promise.allSettled(queries);
    const rows = results.flatMap((result) => result.status === "fulfilled" && !result.value.error ? (result.value.data ?? []) as Array<Record<string, unknown>> : []);
    return mapProfileSearchRows(rows);
  }

  async function runUserSearch(rawQuery: string) {
    const trimmed = rawQuery.trim();
    if (trimmed.length < 2) {
      setSearchResults([]);
      setSearchFeedback(null);
      return;
    }
    const requestId = ++searchRequestRef.current;
    setSearching(true);
    setSearchFeedback(null);
    setContactAction(null);
    try {
      const normalized = normalizeUserSearchQuery(trimmed);
      const { data, error } = await supabase.rpc("search_messaging_users", { p_query: normalized });
      let results = error ? [] : (data ?? []) as UserSearchResult[];
      if (results.length === 0) {
        const fallbackResults = await fallbackSearchProfiles(trimmed);
        if (fallbackResults.length > 0) results = fallbackResults;
      }
      if (searchRequestRef.current !== requestId) return;
      setSearchResults(results);
      setSearchFeedback(results.length === 0 ? `No users found for "${trimmed}".` : null);
    } catch (err) {
      if (searchRequestRef.current !== requestId) return;
      const fallbackResults = await fallbackSearchProfiles(trimmed);
      setSearchResults(fallbackResults);
      setSearchFeedback(fallbackResults.length > 0 ? null : (err instanceof Error ? err.message : String(err)));
    } finally {
      if (searchRequestRef.current === requestId) setSearching(false);
    }
  }

  useEffect(() => {
    const trimmed = query.trim();
    if (trimmed.length < 2) {
      searchRequestRef.current += 1;
      setSearchResults([]);
      setSearchFeedback(null);
      setSearching(false);
      return undefined;
    }
    const timer = window.setTimeout(() => {
      void runUserSearch(trimmed);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [query]);

  async function ensureCurrentUserProfile() {
    const { data, error } = await supabase.auth.getUser();
    if (error) throw error;
    const authUser = data.user;
    if (!authUser || authUser.id !== userId) return;
    const email = authUser.email ?? "";
    const metadata = authUser.user_metadata ?? {};
    const displayName = String(metadata.full_name ?? metadata.name ?? email.split("@")[0] ?? "QGuard User");
    const { error: rpcError } = await supabase.rpc("ensure_qguard_profile", {
      p_user_id: userId,
      p_email: email || null,
      p_name: displayName || null,
    });
    if (!rpcError) return;
    const username = `${email.split("@")[0] || "qguard"}_${userId.replace(/-/g, "").slice(0, 6)}`
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, "_");
    const { error: upsertError } = await supabase.from("profiles").upsert({
      id: userId,
      email: email || null,
      name: displayName || "QGuard User",
      username,
    }, { onConflict: "id" });
    if (upsertError) throw rpcError;
  }

  async function addContact(result: UserSearchResult) {
    setContactAction(null);
    try {
      await ensureCurrentUserProfile();
    } catch (error) {
      setContactAction(describeMessageError(error));
      return;
    }
    const { error } = await supabase.from("messaging_contacts").upsert({
      owner_user_id: userId,
      contact_user_id: result.user_id,
      alias: result.display_name,
      trust_state: "added",
      updated_at: new Date().toISOString(),
    }, { onConflict: "owner_user_id,contact_user_id" });
    if (error) {
      setContactAction(error.message);
      return;
    }
    setContactAction(`${result.display_name} added`);
    setQuery("");
    setSearchResults([]);
    setSearchFeedback(null);
    onSent();
  }

  async function updateContact(contact: ContactSummary, trustState: "blocked" | "removed" | "added") {
    setContactAction(null);
    const { error } = await supabase
      .from("messaging_contacts")
      .update({ trust_state: trustState, updated_at: new Date().toISOString() })
      .eq("id", contact.id);
    if (error) {
      setContactAction(error.message);
      return;
    }
    setContactAction(trustState === "added" ? `${visibleContactName(contact)} restored` : `${visibleContactName(contact)} ${trustState}`);
    onSent();
  }

  function protectedViewUnlocked(target: ProtectedConversationView): boolean {
    return target === "archived" ? isArchivedUnlocked : isHiddenUnlocked;
  }

  function requestProtectedView(target: ProtectedConversationView, conversationId?: string): boolean {
    if (protectedViewUnlocked(target)) {
      setConversationView(target);
      if (conversationId) setActiveConversationId(conversationId);
      return true;
    }
    setProtectionDialog({ target, conversationId });
    setProtectionSecret("");
    setProtectionConfirm("");
    setProtectionError(null);
    return false;
  }

  function switchConversationView(view: ConversationView) {
    setOpenConversationMenuId(null);
    if (view === "active") {
      setConversationView("active");
      return;
    }
    requestProtectedView(view);
  }

  function conversationHome(thread: ConversationSummary): ConversationView {
    if (thread.hidden_at) return "hidden";
    if (thread.archived_at) return "archived";
    return "active";
  }

  function openConversation(thread: ConversationSummary) {
    const target = conversationHome(thread);
    if (target === "hidden" || target === "archived") {
      if (!requestProtectedView(target, thread.id)) return;
    } else {
      setConversationView("active");
      setActiveConversationId(thread.id);
    }
    setStatus("Private chat ready");
  }

  async function submitProtectionDialog() {
    if (!protectionDialog) return;
    const secret = protectionSecret.trim();
    if (secret.length < 4) {
      setProtectionError("Use at least 4 characters for the chat PIN or password.");
      return;
    }
    if (!protectionConfig && secret !== protectionConfirm.trim()) {
      setProtectionError("PIN/password confirmation does not match.");
      return;
    }

    setProtectionBusy(true);
    setProtectionError(null);
    try {
      let config = protectionConfig;
      if (!config) {
        config = await createChatProtectionConfig(secret);
        localStorage.setItem(chatProtectionStorageKey(userId), JSON.stringify(config));
        setProtectionConfig(config);
      } else {
        const verified = await verifyChatProtectionSecret(secret, config);
        if (!verified) throw new Error("Invalid PIN or password.");
      }

      setProtectedUnlockUntil((current) => ({
        ...current,
        [protectionDialog.target]: Date.now() + protectedConversationUnlockMs,
      }));
      setConversationView(protectionDialog.target);
      if (protectionDialog.conversationId) setActiveConversationId(protectionDialog.conversationId);
      setProtectionDialog(null);
      setProtectionSecret("");
      setProtectionConfirm("");
      setStatus(`${protectionDialog.target === "archived" ? "Archived" : "Hidden"} conversations unlocked`);
    } catch (error) {
      setProtectionError(describeMessageError(error));
    } finally {
      setProtectionBusy(false);
    }
  }

  async function updateConversationPrivacyState(
    thread: ConversationSummary,
    action: "archive" | "unarchive" | "hide" | "unhide" | "delete",
  ) {
    const target = conversationHome(thread);
    if ((action === "unarchive" && target === "archived" && !protectedViewUnlocked("archived"))
      || (action === "unhide" && target === "hidden" && !protectedViewUnlocked("hidden"))) {
      requestProtectedView(target as ProtectedConversationView, thread.id);
      return;
    }
    if (action === "delete" && !window.confirm("Delete this conversation from your Secure Chat view? Encrypted history for other participants is not destroyed.")) {
      return;
    }

    const now = new Date().toISOString();
    const nextState = {
      user_id: userId,
      conversation_id: thread.id,
      archived_at: action === "archive" ? now : null,
      hidden_at: action === "hide" ? now : null,
      deleted_at: action === "delete" ? now : null,
      updated_at: now,
    };

    setConversationBusyId(`${thread.id}:${action}`);
    setOpenConversationMenuId(null);
    setConversationAction(null);
    try {
      const { error } = await supabase
        .from("messaging_conversation_user_states")
        .upsert(nextState, { onConflict: "user_id,conversation_id" });
      if (error) throw error;
      setConversationStateOverrides((current) => ({
        ...current,
        [thread.id]: {
          archived_at: nextState.archived_at,
          hidden_at: nextState.hidden_at,
          deleted_at: nextState.deleted_at,
        },
      }));

      await recordCryptoTelemetry({
        userId,
        deviceId: currentDevice?.device_id ?? null,
        scope: "message",
        stage: `conversation_${action}`,
        detail: `Secure conversation ${action} action recorded`,
        progress: 100,
        status: "complete",
        metadata: { conversation_id: thread.id },
      }).catch(() => undefined);

      if (activeConversationId === thread.id && (action === "archive" || action === "hide" || action === "delete")) {
        setActiveConversationId("");
      }
      if (action === "archive") setConversationView("active");
      if (action === "hide") setConversationView("active");
      setConversationAction(`Conversation ${action === "delete" ? "deleted" : action === "unarchive" ? "restored" : action === "unhide" ? "unhidden" : action === "hide" ? "hidden" : "archived"}.`);
      onSent();
    } catch (error) {
      setConversationAction(describeMessageError(error));
    } finally {
      setConversationBusyId(null);
    }
  }

  async function loadContactDevices(contact: ContactSummary): Promise<TrustedDevice[]> {
    return loadTrustedDevicesForUsers([contact.contact_user_id]);
  }

  async function startPrivateChat(contact: ContactSummary) {
    if (contactChatBusyId) return;

    setContactChatBusyId(contact.id);
    setContactAction(null);
    setStatus(`Opening private chat with ${visibleContactName(contact)}`);

    try {
      if (contact.trust_state === "blocked") {
        setStatus("Unblock this contact before starting a chat");
        setContactAction(`${visibleContactName(contact)} is blocked. Restore the contact before opening chat.`);
        return;
      }

      const existing = effectiveConversations.find((conversation) => conversation.member_user_ids.includes(contact.contact_user_id));
      if (existing) {
        openConversation(existing);
        setContactAction(`Opened chat with ${visibleContactName(contact)}.`);
        return;
      }

      if (myDevices.length === 0) {
        setStatus("Open the desktop app to activate this device");
        setContactAction("This account needs a registered QGuard desktop device before it can start encrypted chats.");
        return;
      }

      const localDevices = localDeviceId
        ? (localDevice && isSendableDevice(localDevice) ? [localDevice] : [])
        : selectDeliveryDevicesForUsers(myDevices, [userId], localDeviceId);
      if (localDevices.length === 0) {
        setStatus("Local device is missing signed PQC prekeys");
        setContactAction("This account needs a trusted QGuard desktop device with active signed PQC prekeys before it can start encrypted chats.");
        return;
      }

      const latestContactDevices = await loadContactDevices(contact);
      const fallbackDevices = devices.filter((device) => device.user_id === contact.contact_user_id && isTrustedDeviceForDelivery(device));
      const contactDevices = latestContactDevices.length > 0 ? latestContactDevices : fallbackDevices;
      const trustedContactDevices = contactDevices.filter(isTrustedDeviceForDelivery);
      const sendableContactDevices = selectDeliveryDevicesForUsers(trustedContactDevices, [contact.contact_user_id], localDeviceId);

      if (trustedContactDevices.length === 0) {
        setStatus("This contact has no trusted device yet");
        setContactAction(`${visibleContactName(contact)} has not registered a trusted QGuard desktop device yet. Ask them to sign in to QGuard Messaging on desktop, then press Chat again.`);
        await Promise.resolve(onSent());
        return;
      }

      if (sendableContactDevices.length === 0) {
        setStatus("Waiting for recipient PQC prekeys");
        setContactAction(`${visibleContactName(contact)} has a device, but it has not published active PQC prekeys yet. Ask them to open QGuard Messaging once more, then press Chat again.`);
        await Promise.resolve(onSent());
        return;
      }

      const { data: conversation, error: conversationError } = await supabase
        .from("messaging_conversations")
        .insert({
          owner_user_id: userId,
          conversation_type: "direct",
          encrypted_title: { version: 1, contact_hint: contact.contact_user_id.slice(0, 8) },
        })
        .select("id")
        .single();
      if (conversationError) throw conversationError;

      const conversationId = String(conversation.id);
      const rows = [
        ...localDevices.map((device) => ({
          conversation_id: conversationId,
          user_id: userId,
          device_id: device.device_id,
          role: "owner",
        })),
        ...sendableContactDevices.map((device) => ({
          conversation_id: conversationId,
          user_id: contact.contact_user_id,
          device_id: device.device_id,
          role: "member",
        })),
      ];

      const { error: memberError } = await supabase
        .from("messaging_conversation_members")
        .insert(rows);
      if (memberError) throw memberError;

      setActiveConversationId(conversationId);
      setConversationView("active");
      setStatus("Private chat ready");
      setContactAction(`Private chat opened with ${visibleContactName(contact)}.`);
      await Promise.resolve(onSent());
    } catch (error) {
      const detail = describeMessageError(error);
      setStatus(detail);
      setContactAction(detail);
    } finally {
      setContactChatBusyId(null);
    }
  }

  function buildComposeLifecycle(): SecurePlaintextMessage["lifecycle"] {
    const customExpiry = customExpiresAt ? new Date(customExpiresAt) : null;
    if (customExpiry && customExpiry.getTime() <= Date.now()) {
      throw new Error("Custom expiry must be in the future.");
    }
    return {
      expires_at: customExpiry
        ? customExpiry.toISOString()
        : disappearSeconds > 0
          ? new Date(Date.now() + disappearSeconds * 1000).toISOString()
          : null,
      available_at: null,
      read_once: readOnce,
      view_once: viewOnce,
    };
  }

  function resetComposeControls() {
    setMessage("");
    setReplyToMessage(null);
    setReadOnce(false);
    setViewOnce(false);
    setDisappearSeconds(0);
    setCustomExpiresAt("");
  }

  async function uploadChatAttachmentWithRetry(path: string, body: Blob): Promise<void> {
    let lastError: unknown = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const { error } = await supabase.storage.from("messaging-files").upload(path, body, {
        contentType: "application/qguard-chat-attachment",
        upsert: false,
      });
      if (!error) return;
      lastError = error;
      await new Promise((resolve) => window.setTimeout(resolve, 250 * (attempt + 1)));
    }
    throw lastError instanceof Error ? lastError : new Error(describeMessageError(lastError ?? "Attachment upload failed"));
  }

  async function encryptAndUploadAttachment(
    source: Blob,
    displayName: string,
    kind: SecureChatAttachment["kind"],
    clientMessageId: string,
    durationMs: number | null,
  ): Promise<SecureChatAttachment> {
    if (!activeConversation) throw new Error("Select a secure conversation before attaching files.");
    if (source.size <= 0) throw new Error("Attachment is empty.");
    if (source.size > maxChatAttachmentBytes) {
      throw new Error(`Attachment limit is ${formatBytes(maxChatAttachmentBytes)}.`);
    }

    const plaintext = new Uint8Array(await source.arrayBuffer());
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(plaintext)));
    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    const storagePath = `${userId}/chat-attachments/${activeConversation.id}/${clientMessageId}/${kind}-${Date.now()}.bin`;

    await uploadChatAttachmentWithRetry(storagePath, new Blob([encrypted], { type: "application/qguard-chat-attachment" }));

    return {
      kind,
      storage_path: storagePath,
      name: displayName,
      size_bytes: source.size,
      content_type: source.type || "application/octet-stream",
      key_b64: bytesToBase64(rawKey),
      iv_b64: bytesToBase64(iv),
      sha256_b64: await sha256Base64(encrypted),
      duration_ms: durationMs,
      created_at: new Date().toISOString(),
    };
  }

  async function decryptAttachmentBlob(
    attachment: SecureChatAttachment,
    emitProgress: (stage: string, detail: string, progress: number, statusValue: string) => void,
  ): Promise<Blob> {
    emitProgress("attachment_download", "Downloading ciphertext attachment", 32, "progress");
    const { data, error } = await supabase.storage.from("messaging-files").download(attachment.storage_path);
    if (error || !data) throw error ?? new Error("Attachment download failed");

    const encrypted = new Uint8Array(await data.arrayBuffer());
    emitProgress("integrity_verification", "Checking attachment ciphertext digest", 52, "progress");
    const actualDigest = await sha256Base64(encrypted);
    if (actualDigest !== attachment.sha256_b64) {
      wipeBytes(encrypted);
      throw new Error("Attachment integrity check failed.");
    }
    emitProgress("integrity_verification", "Attachment digest verified", 64, "verified");
    const attachmentKey = base64ToBytes(attachment.key_b64);
    const key = await crypto.subtle.importKey("raw", toArrayBuffer(attachmentKey), "AES-GCM", false, ["decrypt"]);
    wipeBytes(attachmentKey);
    emitProgress("aes_gcm_decrypt", "Decrypting attachment locally with AES-256-GCM", 82, "progress");
    const iv = base64ToBytes(attachment.iv_b64);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(encrypted));
    wipeBytes(iv);
    wipeBytes(encrypted);
    const plaintextBytes = new Uint8Array(plaintext);
    const blob = new Blob([plaintextBytes.slice()], { type: attachment.content_type || "application/octet-stream" });
    wipeBytes(plaintextBytes);
    return blob;
  }

  async function openAttachment(chatMessage: ChatMessage) {
    if (!chatMessage.attachment) return;
    const downloadId = attachmentDownloadId(chatMessage);
    const attachment = chatMessage.attachment;
    setAttachmentBusy("download");
    setMessageAction(null);
    upsertDownloadedFile({
      id: downloadId,
      message_id: chatMessage.client_message_id,
      name: attachment.name,
      kind: attachment.kind,
      size_bytes: attachment.size_bytes,
      content_type: attachment.content_type,
      status: "decrypting",
      progress: 4,
      detail: "Queued for decryption",
      created_at: new Date().toISOString(),
    });
    const stream = createSecureDecryptionStream("message", (event) => {
      appendChatDecryptionEvent(event.data.stage, event.data.detail, event.data.progress, event.data.status);
      patchDownloadedFile(downloadId, {
        status: event.data.status === "failed" ? "failed" : event.data.status === "complete" ? "decrypted" : "decrypting",
        progress: event.data.progress,
        detail: event.data.detail,
      });
    });
    try {
      await validateDecryptionSession(userId, stream);
      enforceClientDecryptionRateLimit(userId, `attachment:${attachment.storage_path}`, stream);
      await unlockDevicePrivateKey(stream, userId);
      await recordCryptoTelemetry({
        userId,
        deviceId: currentDevice?.device_id ?? null,
        scope: "download",
        stage: "attachment_decrypt_started",
        detail: "Client-side attachment decrypt started",
        progress: 5,
        status: "started",
        metadata: { conversation_id: chatMessage.conversation_id, client_message_id: chatMessage.client_message_id },
      });
      const blob = await decryptAttachmentBlob(attachment, (stage, detail, progress, statusValue) => {
        stream.emit({
          stage,
          detail,
          progress,
          status: statusValue as "progress" | "verified",
          level: statusValue === "verified" ? "success" : "info",
        });
      });
      if (attachment.kind === "voice") {
        setAttachmentPreviewUrls((current) => {
          if (current[chatMessage.client_message_id]) URL.revokeObjectURL(current[chatMessage.client_message_id]);
          return {
            ...current,
            [chatMessage.client_message_id]: URL.createObjectURL(blob),
          };
        });
      } else {
        downloadBlob(attachment.name, blob);
        await markViewOnceAttachmentOpened(chatMessage);
      }
      stream.emit({
        stage: "attachment_decrypt_completed",
        detail: attachment.kind === "voice" ? "Voice note decrypted locally" : "Attachment restored locally",
        progress: 100,
        status: "complete",
        level: "success",
      });
      await recordCryptoTelemetry({
        userId,
        deviceId: currentDevice?.device_id ?? null,
        scope: "download",
        stage: "attachment_decrypt_completed",
        detail: "Attachment integrity verified and decrypted locally",
        progress: 100,
        status: "complete",
        metadata: { conversation_id: chatMessage.conversation_id, client_message_id: chatMessage.client_message_id },
      });
      setStatus("Attachment decrypted locally");
    } catch (error) {
      const message = normalizeDecryptionError(error);
      stream.emit({
        stage: "attachment_decrypt_failed",
        detail: message,
        progress: 0,
        status: "failed",
        level: "error",
      });
      patchDownloadedFile(downloadId, { status: "failed", progress: 0, detail: message });
      setMessageAction(message);
    } finally {
      setAttachmentBusy(null);
    }
  }

  async function sendSecureAttachment(
    source: Blob,
    displayName: string,
    kind: SecureChatAttachment["kind"],
    durationMs: number | null = null,
  ) {
    if (!activeConversation || !recipientDevicesReady) {
      setStatus("Select a secure conversation with a trusted recipient device");
      return;
    }
    if (editingMessage) {
      setStatus("Finish or cancel editing before attaching media");
      return;
    }

    const clientMessageId = crypto.randomUUID();
    let uploadedPath: string | null = null;
    setAttachmentBusy(kind);
    setMessageAction(null);
    setStatus(kind === "voice" ? "Encrypting voice note locally" : "Encrypting attachment locally");
    try {
      const lifecycle = buildComposeLifecycle();
      const attachment = await encryptAndUploadAttachment(source, displayName, kind, clientMessageId, durationMs);
      uploadedPath = attachment.storage_path;
      const caption = message.trim() || (kind === "voice" ? "Voice note" : displayName);
      await sendEncryptedPayload(serializeSecureMessage(caption, replyToMessage?.client_message_id ?? null, lifecycle, attachment), {
        clientMessageId,
        parentClientMessageId: replyToMessage?.client_message_id ?? null,
        lifecycle,
        messageKind: kind === "voice" ? "VoiceNote" : "FileReference",
      });
      await recordCryptoTelemetry({
        userId,
        deviceId: currentDevice?.device_id ?? null,
        scope: "message",
        stage: kind === "voice" ? "voice_note_attachment_uploaded" : "file_attachment_uploaded",
        detail: "Encrypted attachment ciphertext uploaded; key sealed inside message envelope",
        progress: 100,
        status: "complete",
        metadata: { conversation_id: activeConversation.id, client_message_id: clientMessageId, bytes: source.size },
      });
      resetComposeControls();
      setStatus(kind === "voice" ? "Voice note sealed" : "Attachment sealed");
      await loadConversationMessages();
      onSent();
    } catch (error) {
      if (uploadedPath) {
        await supabase.storage.from("messaging-files").remove([uploadedPath]).catch(() => undefined);
      }
      setStatus(describeMessageError(error));
    } finally {
      setAttachmentBusy(null);
    }
  }

  async function handleAttachmentSelected(file: File | null) {
    if (!file) return;
    await sendSecureAttachment(file, file.name, "file");
  }

  function preferredAudioMimeType(): string {
    const candidates = ["audio/webm;codecs=opus", "audio/webm", "audio/mp4", "audio/ogg;codecs=opus"];
    return candidates.find((candidate) => MediaRecorder.isTypeSupported(candidate)) ?? "";
  }

  async function toggleVoiceRecording() {
    if (recordingState === "recording") {
      setRecordingState("processing");
      mediaRecorderRef.current?.stop();
      return;
    }
    if (recordingState === "processing") return;
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") {
      setStatus("Microphone recording is not available in this browser runtime");
      return;
    }
    if (!activeConversation || !recipientDevicesReady) {
      setStatus("Select a secure conversation with a trusted recipient device");
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mimeType = preferredAudioMimeType();
      const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
      voiceChunksRef.current = [];
      voiceStartedAtRef.current = Date.now();
      mediaRecorderRef.current = recorder;
      recorder.ondataavailable = (event) => {
        if (event.data.size > 0) voiceChunksRef.current.push(event.data);
      };
      recorder.onstop = () => {
        const durationMs = Date.now() - voiceStartedAtRef.current;
        const chunks = voiceChunksRef.current;
        voiceChunksRef.current = [];
        stream.getTracks().forEach((track) => track.stop());
        const blob = new Blob(chunks, { type: recorder.mimeType || "audio/webm" });
        sendSecureAttachment(blob, `voice-note-${new Date().toISOString().replace(/[:.]/g, "-")}.webm`, "voice", durationMs)
          .finally(() => {
            mediaRecorderRef.current = null;
            setRecordingState("idle");
          });
      };
      recorder.start();
      setRecordingState("recording");
      setStatus("Recording encrypted voice note");
    } catch (error) {
      setRecordingState("idle");
      setStatus(describeMessageError(error));
    }
  }

  async function sendEncryptedPayload(
    plaintext: string,
    options: {
      clientMessageId?: string;
      parentClientMessageId?: string | null;
      controlType?: string | null;
      lifecycle?: SecurePlaintextMessage["lifecycle"];
      messageKind?: "Text" | "FileReference" | "VoiceNote" | "System";
    } = {},
  ): Promise<string> {
    if (!activeConversation || !plaintext.trim()) throw new Error("No active recipient devices");
    const senderDevice = currentDevice;
    if (!senderDevice) {
      throw new Error("Open the desktop app to activate this device");
    }
    if (!hasSendableKeyBundle(senderDevice)) {
      throw new Error("Local device is missing signed PQC prekeys");
    }
    const recipientUserIds = activeRecipientUserIds;
    if (recipientUserIds.length === 0) {
      throw new Error("Open a direct chat with a contact before sending");
    }
    let latestRecipientDevices: TrustedDevice[] = [];
    try {
      latestRecipientDevices = await loadTrustedDevicesForUsers(recipientUserIds);
    } catch {
      latestRecipientDevices = [];
    }
    const deliveryRecipientDevices = selectDeliveryDevicesForUsers(
      latestRecipientDevices.length > 0 ? latestRecipientDevices : recipientDevices,
      recipientUserIds,
      localDeviceId,
    );
    if (deliveryRecipientDevices.length === 0) {
      throw new Error("Recipient device is missing signed PQC prekeys");
    }
    const clientMessageId = options.clientMessageId ?? crypto.randomUUID();
    const deliveryDevices = Array.from(new Map([...deliveryRecipientDevices, senderDevice].map((device) => [device.device_id, device])).values());
    const threat = options.controlType ? emptyThreat() : assessThreatLocally(parseSecurePlaintext(plaintext).body);
    const lifecycle = options.lifecycle ?? parseSecurePlaintext(plaintext).lifecycle;

    await recordCryptoTelemetry({
      userId,
      deviceId: senderDevice.device_id,
      scope: "message",
      stage: "message_key_generation",
      detail: "Fresh hybrid key exchange started",
      progress: 15,
      status: "started",
      metadata: { conversation_id: activeConversation.id, recipients: deliveryRecipientDevices.length, client_message_id: clientMessageId },
    });
    for (const recipientDevice of deliveryDevices) {
      const isLocalArchive = recipientDevice.user_id === userId;
      const oneTimePrekey = null;
      const recipient = recipientKeyBundle(recipientDevice, oneTimePrekey);
      if (!recipient) throw new Error("Recipient key bundle is incomplete");
      const envelope = await safeInvoke<EncryptedMessageEnvelope>("messaging_send_encrypted_message", {
        request: {
          conversationId: activeConversation.id,
          senderUserId: userId,
          recipientUserId: recipientDevice.user_id,
          recipientDeviceId: recipientDevice.device_id,
          plaintext,
          kind: options.messageKind ?? "Text",
          recipient,
        },
      });

      const { error } = await supabase.from("messaging_message_envelopes").insert({
        id: envelope.message_id,
        conversation_id: envelope.conversation_id,
        client_message_id: clientMessageId,
        parent_client_message_id: options.parentClientMessageId ?? null,
        sender_user_id: userId,
        sender_device_id: envelope.sender_device_id,
        recipient_user_id: recipientDevice.user_id,
        recipient_device_id: envelope.recipient_device_id,
        message_kind: toMessageKind(envelope.kind),
        sealed_sender_envelope: {
          sealed_sender: envelope.sealed_sender,
          desktop_envelope_version: 2,
          client_message_id: clientMessageId,
          parent_client_message_id: options.parentClientMessageId ?? null,
          control_type: options.controlType ?? null,
          local_archive: isLocalArchive,
          original_sender_user_id: userId,
          original_sender_device_id: senderDevice.device_id,
          hybrid_ciphertext: envelope.hybrid_ciphertext,
          prekey_id: envelope.prekey_id,
          prekey_kind: envelope.prekey_kind,
          message_signature: envelope.message_signature,
          sender_ed25519_public: envelope.sender_ed25519_public,
          sender_mldsa_public: envelope.sender_mldsa_public,
        },
        ciphertext: bytesToBytea(envelope.envelope.ciphertext),
        nonce: bytesToBytea(envelope.envelope.nonce),
        auth_tag: bytesToBytea(envelope.envelope.tag),
        aad: bytesToBytea(envelope.aad),
        ratchet_counter: envelope.counter,
        suite: envelope.suite,
        expires_at: lifecycle.expires_at,
        lifecycle: {
          ...lifecycle,
          reply_to: options.parentClientMessageId ?? null,
          control_type: options.controlType ?? null,
        },
        verification_state: "valid",
        threat_result: {
          score: threat.score,
          flags: threat.flags,
        },
      });
      if (error) throw error;
    }

    await recordCryptoTelemetry({
      userId,
      deviceId: senderDevice.device_id,
      scope: "message",
      stage: options.controlType ? `message_control_${options.controlType}` : "message_envelope_committed",
      detail: options.controlType ? "Encrypted message control committed" : "Ciphertext envelope relayed with dual signatures",
      progress: 100,
      status: "complete",
      metadata: { conversation_id: activeConversation.id, recipients: deliveryRecipientDevices.length, client_message_id: clientMessageId },
    });

    const cachedAt = new Date().toISOString();
    const control = parseSecureControl(plaintext);
    if (control) {
      decryptedControlCacheRef.current.set(clientMessageId, {
        ...control,
        sender_user_id: userId,
        created_at: cachedAt,
      });
    } else {
      const secureMessage = parseSecurePlaintext(plaintext);
      const isLocked = Boolean(secureMessage.lifecycle.available_at && new Date(secureMessage.lifecycle.available_at).getTime() > Date.now());
      decryptedMessageCacheRef.current.set(clientMessageId, {
        id: clientMessageId,
        client_message_id: clientMessageId,
        row_ids: [],
        conversation_id: activeConversation.id,
        sender_user_id: userId,
        recipient_user_id: deliveryRecipientDevices[0]?.user_id ?? userId,
        kind: toMessageKind(options.messageKind ?? "Text"),
        plaintext: isLocked ? `Time-locked message unlocks ${new Date(secureMessage.lifecycle.available_at ?? "").toLocaleString()}` : secureMessage.body,
        attachment: isLocked ? null : secureMessage.attachment,
        reply_to: secureMessage.reply_to,
        edited_at: null,
        reactions: [],
        expires_at: secureMessage.lifecycle.expires_at,
        available_at: secureMessage.lifecycle.available_at,
        read_once: secureMessage.lifecycle.read_once,
        view_once: secureMessage.lifecycle.view_once,
        threat,
        status: "decrypted",
        authenticated: true,
        replay_protected: true,
        created_at: cachedAt,
        error: null,
        can_delete: true,
      });
    }
    return clientMessageId;
  }

  async function sendMessage() {
    if (!activeConversation || !message.trim()) return;
    const senderDevice = currentDevice;
    setStatus("Securing message");
    try {
      if (editingMessage) {
        await sendEncryptedPayload(serializeSecureControl({
          type: "edit",
          target_client_message_id: editingMessage.client_message_id,
          body: message.trim(),
        }), {
          parentClientMessageId: editingMessage.client_message_id,
          controlType: "edit",
        });
        setEditingMessage(null);
      } else {
        const lifecycle = buildComposeLifecycle();
        await sendEncryptedPayload(serializeSecureMessage(message.trim(), replyToMessage?.client_message_id ?? null, lifecycle), {
          parentClientMessageId: replyToMessage?.client_message_id ?? null,
          lifecycle,
        });
      }

      setStatus("Message sealed");
      resetComposeControls();
      await loadConversationMessages();
      onSent();
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      setStatus(detail.includes("desktop app") ? "Open the desktop app to send securely" : detail);
      if (senderDevice) {
        await recordCryptoTelemetry({
          userId,
          deviceId: senderDevice.device_id,
          scope: "message",
          stage: "message_encryption_failed",
          detail,
          progress: 0,
          status: "failed",
          metadata: { conversation_id: activeConversation.id },
        });
      }
    }
  }

  async function reactToMessage(chatMessage: ChatMessage, reaction: string) {
    setOpenMessageMenuId(null);
    setMessageAction(null);
    try {
      await sendEncryptedPayload(serializeSecureControl({
        type: "reaction",
        target_client_message_id: chatMessage.client_message_id,
        reaction,
      }), {
        parentClientMessageId: chatMessage.client_message_id,
        controlType: "reaction",
      });
      await loadConversationMessages();
    } catch (error) {
      setMessageAction(describeMessageError(error));
    }
  }

  function startReply(chatMessage: ChatMessage) {
    setReplyToMessage(chatMessage);
    setEditingMessage(null);
    setOpenMessageMenuId(null);
  }

  function startEdit(chatMessage: ChatMessage) {
    setEditingMessage(chatMessage);
    setReplyToMessage(null);
    setMessage(chatMessage.plaintext);
    setOpenMessageMenuId(null);
  }

  async function deleteChatMessage(chatMessage: ChatMessage) {
    if (!chatMessage.can_delete) return;
    const confirmed = window.confirm("Delete this encrypted message from the conversation?");
    if (!confirmed) return;

    setDeletingMessageId(chatMessage.id);
    setOpenMessageMenuId(null);
    setMessageAction(null);
    try {
      await safeInvoke<boolean>("messaging_delete_encrypted_message", { messageId: chatMessage.id }, true);
      const deletedAt = new Date().toISOString();
      const baseMutation = supabase
        .from("messaging_message_envelopes")
        .update({ deleted_at: deletedAt })
        .eq("conversation_id", chatMessage.conversation_id)
        .eq("sender_user_id", userId);

      const { error } = chatMessage.client_message_id && chatMessage.client_message_id !== chatMessage.id
        ? await baseMutation.contains("sealed_sender_envelope", { client_message_id: chatMessage.client_message_id })
        : await baseMutation.in("id", chatMessage.row_ids);
      if (error) throw error;
      if (chatMessage.attachment?.storage_path) {
        await supabase.storage.from("messaging-files").remove([chatMessage.attachment.storage_path]).catch(() => undefined);
      }

      await recordCryptoTelemetry({
        userId,
        deviceId: currentDevice?.device_id ?? null,
        scope: "message",
        stage: "message_deleted",
        detail: "Encrypted chat envelope marked deleted",
        progress: 100,
        status: "complete",
        metadata: { conversation_id: chatMessage.conversation_id, client_message_id: chatMessage.client_message_id },
      });
      decryptedMessageCacheRef.current.delete(chatMessage.client_message_id);
      setChatMessages((items) => items.filter((item) => item.client_message_id !== chatMessage.client_message_id));
      setMessageAction("Message deleted");
      onSent();
    } catch (error) {
      setMessageAction(describeMessageError(error));
    } finally {
      setDeletingMessageId(null);
    }
  }

  const messageByClientId = new Map(chatMessages.map((item) => [item.client_message_id, item]));
  const typingNames = typingIndicators
    .map((indicator) => contacts.find((contact) => contact.contact_user_id === indicator.user_id))
    .filter(Boolean)
    .map((contact) => visibleContactName(contact as ContactSummary));
  const suspiciousCount = chatMessages.filter((item) => item.threat.suspicious).length;
  const conversationViews: Array<{ id: ConversationView; label: string; count: number; protected: boolean }> = [
    { id: "active", label: "Active", count: activeConversations.length, protected: false },
    { id: "archived", label: "Archived", count: archivedConversations.length, protected: true },
    { id: "hidden", label: "Hidden", count: hiddenConversations.length, protected: true },
  ];
  const emptyConversationText = conversationView === "active"
    ? "Add a trusted contact to start a private encrypted chat."
    : conversationView === "archived"
      ? "No archived conversations."
      : "No hidden conversations.";

  return (
    <>
    <div className="grid h-[calc(100vh-124px)] grid-cols-[300px_1fr_330px] gap-4">
      <section className="shell-card overflow-hidden">
        <div className="border-b border-line p-4">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-bold text-ink-950">Secure Conversations</h2>
            <span className="status-pill bg-ink-50 text-ink-600">{visibleConversations.length}</span>
          </div>
          <div className="mt-3 grid grid-cols-3 gap-1 rounded-lg border border-line bg-canvas p-1">
            {conversationViews.map((view) => {
              const Icon = view.id === "active" ? ShieldCheck : view.id === "archived" ? Archive : EyeOff;
              const unlocked = view.id === "active" || protectedViewUnlocked(view.id);
              return (
                <button
                  key={view.id}
                  type="button"
                  onClick={() => switchConversationView(view.id)}
                  className={`flex min-w-0 items-center justify-center gap-1 rounded-md px-2 py-2 text-xs font-bold transition ${conversationView === view.id ? "conversation-segment-active" : "text-ink-600 hover:bg-white/70"}`}
                  title={view.protected && !unlocked ? `${view.label} locked` : view.label}
                >
                  <Icon size={13} />
                  <span className="truncate">{view.label}</span>
                  <span className="rounded-full bg-ink-100 px-1.5 py-0.5 text-[10px] text-ink-600">{view.count}</span>
                </button>
              );
            })}
          </div>
          {conversationAction && (
            <div className="mt-3 rounded-lg border border-line bg-white/80 px-3 py-2 text-xs font-semibold text-ink-600">
              {conversationAction}
            </div>
          )}
        </div>
        <div className="divide-y divide-line">
          {visibleConversations.length === 0 && (
            <div className="p-4 text-sm text-ink-600">{emptyConversationText}</div>
          )}
          {visibleConversations.map((thread) => {
            const threadBusy = conversationBusyId?.startsWith(`${thread.id}:`) ?? false;
            return (
              <div
                key={thread.id}
                className={`group relative flex items-center gap-2 p-3 ${thread.id === activeConversation?.id ? "conversation-row-active" : "hover:bg-canvas/80"}`}
              >
                <button
                  type="button"
                  onClick={() => openConversation(thread)}
                  className="flex min-w-0 flex-1 items-center gap-3 text-left"
                >
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-violet-500 text-sm font-bold text-white">
                    {conversationTitle(thread).slice(0, 2).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-bold text-ink-950">{conversationTitle(thread)}</div>
                    <div className="truncate text-xs text-ink-600">{thread.last_activity}</div>
                    <div className="mt-1 flex items-center gap-1">
                      {thread.archived_at && <span className="status-pill bg-violet-50 text-violet-600"><Archive size={12} />Archived</span>}
                      {thread.hidden_at && <span className="status-pill bg-cyan-50 text-cyan-700"><EyeOff size={12} />Hidden</span>}
                      {thread.unread_count > 0 && <span className="status-pill bg-emerald-50 text-emerald-600">{thread.unread_count} new</span>}
                    </div>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => setOpenConversationMenuId(openConversationMenuId === thread.id ? null : thread.id)}
                  className="icon-button h-8 w-8 shrink-0 bg-white/80"
                  title="Conversation actions"
                  aria-label="Conversation actions"
                >
                  {threadBusy ? <Loader2 className="animate-spin" size={15} /> : <MoreVertical size={15} />}
                </button>
                {openConversationMenuId === thread.id && (
                  <div className="absolute right-3 top-12 z-20 w-48 rounded-lg border border-line bg-white p-1 shadow-soft">
                    {!thread.archived_at && !thread.hidden_at && (
                      <button
                        onClick={() => updateConversationPrivacyState(thread, "archive")}
                        disabled={threadBusy}
                        className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Archive size={14} />
                        Archive
                      </button>
                    )}
                    {thread.archived_at && (
                      <button
                        onClick={() => updateConversationPrivacyState(thread, "unarchive")}
                        disabled={threadBusy}
                        className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <ArchiveRestore size={14} />
                        Unarchive
                      </button>
                    )}
                    {!thread.hidden_at && (
                      <button
                        onClick={() => updateConversationPrivacyState(thread, "hide")}
                        disabled={threadBusy}
                        className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <EyeOff size={14} />
                        Hide
                      </button>
                    )}
                    {thread.hidden_at && (
                      <button
                        onClick={() => updateConversationPrivacyState(thread, "unhide")}
                        disabled={threadBusy}
                        className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Eye size={14} />
                        Unhide
                      </button>
                    )}
                    <button
                      onClick={() => updateConversationPrivacyState(thread, "delete")}
                      disabled={threadBusy}
                      className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs font-bold text-rose-600 hover:bg-rose-50 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <Trash2 size={14} />
                      Delete
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      <section className="shell-card flex min-h-0 flex-col overflow-hidden">
        <div className="flex items-center justify-between border-b border-line p-4">
          <div>
            <h2 className="text-sm font-bold text-ink-950">{activeConversation ? conversationTitle(activeConversation) : "Select or start a private chat"}</h2>
            <div className="mt-1 flex items-center gap-2 text-xs font-semibold text-emerald-600">
              <ShieldCheck size={14} />
              E2EE active - ML-KEM-1024 - Forward secrecy
            </div>
          </div>
          <span className="status-pill bg-emerald-50 text-emerald-600">{status}</span>
        </div>
        <div ref={messageViewportRef} className="flex-1 space-y-4 overflow-y-auto bg-canvas p-5">
          <div className="rounded-lg border border-line bg-white p-4 text-sm text-ink-600">
            Private messages are sealed locally for each trusted recipient device.
          </div>
          {activeContact && (
            <div className="max-w-md rounded-lg bg-violet-600 p-4 text-sm text-white shadow-tight">
              Private channel with {visibleContactName(activeContact)}
            </div>
          )}
          {messageAction && (
            <div className="rounded-lg border border-line bg-white p-3 text-sm text-ink-600">{messageAction}</div>
          )}
          {messagesLoading && chatMessages.length === 0 && (
            <div className="rounded-lg border border-line bg-white p-4 text-sm text-ink-600">Loading encrypted history...</div>
          )}
          {!messagesLoading && activeConversation && chatMessages.length === 0 && (
            <div className="rounded-lg border border-dashed border-line bg-white/70 p-6 text-center text-sm text-ink-500">
              No visible encrypted messages yet.
            </div>
          )}
          <div className="space-y-3">
            {chatMessages.map((chatMessage) => {
              const mine = chatMessage.sender_user_id === userId;
              const attachmentStatus = attachmentDecryptionStatus(chatMessage);
              return (
                <div key={chatMessage.client_message_id} className={`flex items-start gap-2 ${mine ? "justify-end" : "justify-start"}`}>
                  {!mine && (
                    <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-white text-xs font-bold text-violet-600 shadow-tight">
                      {activeContact ? visibleContactName(activeContact).slice(0, 2).toUpperCase() : "QG"}
                    </div>
                  )}
                  <div className={`group relative max-w-[74%] ${mine ? "order-1" : ""}`}>
                    <div className={`rounded-2xl px-4 py-3 shadow-tight ${mine ? "rounded-br-md bg-violet-600 text-white" : "rounded-bl-md border border-line bg-white text-ink-900"}`}>
                      {chatMessage.reply_to && messageByClientId.get(chatMessage.reply_to) && (
                        <div className={`mb-2 rounded-lg border-l-2 px-3 py-2 text-xs ${mine ? "border-white/60 bg-white/10 text-violet-50" : "border-violet-300 bg-violet-50 text-ink-600"}`}>
                          <div className="font-bold">Reply</div>
                          <div className="truncate">{messageByClientId.get(chatMessage.reply_to)?.plaintext}</div>
                        </div>
                      )}
                      {chatMessage.threat.suspicious && (
                        <div className={`mb-2 flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-bold ${mine ? "bg-amber-50 text-amber-700" : "bg-amber-50 text-amber-700"}`}>
                          <AlertTriangle size={14} />
                          Suspicious message detected - risk {chatMessage.threat.score}/100
                        </div>
                      )}
                      {chatMessage.attachment && (
                        <div className={`mb-2 rounded-lg border px-3 py-3 ${mine ? "border-white/20 bg-white/10" : "border-line bg-canvas"}`}>
                          <div className="flex min-w-0 items-center gap-3">
                            <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${mine ? "bg-white/15" : "bg-white"}`}>
                              {chatMessage.attachment.kind === "voice" ? <Mic size={17} /> : <Paperclip size={17} />}
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="truncate text-xs font-bold">{chatMessage.attachment.name}</div>
                              <div className={`mt-0.5 text-[11px] ${mine ? "text-violet-100" : "text-ink-500"}`}>
                                {formatBytes(chatMessage.attachment.size_bytes)}
                                {chatMessage.attachment.duration_ms ? ` - ${formatDurationMs(chatMessage.attachment.duration_ms)}` : ""}
                              </div>
                              <div className="mt-1">{renderAttachmentStatus(attachmentStatus)}</div>
                            </div>
                            <button
                              type="button"
                              disabled={attachmentBusy === "download"}
                              onClick={() => openAttachment(chatMessage)}
                              className={`flex h-8 shrink-0 items-center gap-1 rounded-md px-2 text-xs font-bold transition disabled:cursor-not-allowed disabled:opacity-50 ${
                                mine ? "bg-white text-violet-700 hover:bg-violet-50" : "bg-violet-600 text-white hover:bg-violet-700"
                              }`}
                            >
                              {attachmentBusy === "download" && attachmentStatus === "decrypting" ? <Loader2 className="animate-spin" size={14} /> : attachmentStatus === "decrypted" ? <Download size={14} /> : <UnlockKeyhole size={14} />}
                              {chatMessage.attachment.kind === "voice" && attachmentStatus === "decrypted" ? "Play" : "Decrypt"}
                            </button>
                          </div>
                          {chatMessage.attachment.kind === "voice" && attachmentPreviewUrls[chatMessage.client_message_id] && (
                            <audio
                              controls
                              src={attachmentPreviewUrls[chatMessage.client_message_id]}
                              className="mt-3 w-full"
                              onEnded={() => markViewOnceAttachmentOpened(chatMessage).catch((error) => setMessageAction(describeMessageError(error)))}
                            />
                          )}
                        </div>
                      )}
                      {chatMessage.plaintext && <div className="whitespace-pre-wrap break-words text-sm leading-6">{chatMessage.plaintext}</div>}
                      {chatMessage.status !== "decrypted" && (
                        <div className={`mt-2 text-xs ${mine ? "text-violet-100" : "text-ink-500"}`}>
                          {chatMessage.status === "failed" ? "Decryption failed" : "Sealed envelope"}{chatMessage.error ? ` - ${chatMessage.error}` : ""}
                        </div>
                      )}
                      <div className={`mt-2 flex flex-wrap items-center gap-2 text-[11px] ${mine ? "text-violet-100" : "text-ink-400"}`}>
                        <span>{new Date(chatMessage.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                        {chatMessage.authenticated && <span>Verified</span>}
                        {chatMessage.replay_protected && <span>Replay-safe</span>}
                        {chatMessage.edited_at && <span>Edited</span>}
                        {chatMessage.read_once && <span>Read once</span>}
                        {chatMessage.view_once && <span>View once</span>}
                        {chatMessage.expires_at && <span>Expires {new Date(chatMessage.expires_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>}
                      </div>
                    </div>
                    {chatMessage.reactions.length > 0 && (
                      <div className={`mt-1 flex gap-1 ${mine ? "justify-end" : "justify-start"}`}>
                        {chatMessage.reactions.map((reaction) => (
                          <span key={`${reaction.actor_user_id}-${reaction.created_at}`} className="rounded-full border border-line bg-white px-2 py-0.5 text-xs shadow-tight">
                            {reaction.reaction}
                          </span>
                        ))}
                      </div>
                    )}
                    <div className={`absolute top-1 ${mine ? "-left-10" : "-right-10"}`}>
                      <button
                        className="icon-button h-8 w-8 bg-white/90 opacity-0 shadow-tight transition group-hover:opacity-100 focus:opacity-100"
                        onClick={() => setOpenMessageMenuId(openMessageMenuId === chatMessage.client_message_id ? null : chatMessage.client_message_id)}
                        title="Message actions"
                        aria-label="Message actions"
                      >
                        <MoreVertical size={16} />
                      </button>
                      {openMessageMenuId === chatMessage.client_message_id && (
                        <div className={`absolute top-9 z-10 w-44 rounded-lg border border-line bg-white p-1 shadow-soft ${mine ? "right-0" : "left-0"}`}>
                          <button
                            onClick={() => startReply(chatMessage)}
                            className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs font-bold text-ink-700 hover:bg-canvas"
                          >
                            <Reply size={14} />
                            Reply
                          </button>
                          <button
                            onClick={() => reactToMessage(chatMessage, "+1")}
                            className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs font-bold text-ink-700 hover:bg-canvas"
                          >
                            <Smile size={14} />
                            React
                          </button>
                          {mine && (
                            <button
                              onClick={() => startEdit(chatMessage)}
                              className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs font-bold text-ink-700 hover:bg-canvas"
                            >
                              <Pencil size={14} />
                              Edit
                            </button>
                          )}
                          <button
                            disabled={!chatMessage.can_delete || deletingMessageId === chatMessage.id}
                            onClick={() => deleteChatMessage(chatMessage)}
                            className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs font-bold text-rose-600 hover:bg-rose-50 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            <Trash2 size={14} />
                            {deletingMessageId === chatMessage.id ? "Deleting..." : "Delete"}
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          {typingNames.length > 0 && (
            <div className="text-xs font-semibold text-ink-500">
              {typingNames.slice(0, 2).join(", ")} {typingNames.length === 1 ? "is" : "are"} typing...
            </div>
          )}
        </div>
        <div className="border-t border-line bg-white p-4">
          {(replyToMessage || editingMessage) && (
            <div className="mb-3 flex items-center justify-between rounded-lg border border-line bg-canvas px-3 py-2 text-xs text-ink-600">
              <div className="min-w-0">
                <div className="font-bold text-ink-800">{editingMessage ? "Editing encrypted message" : "Replying securely"}</div>
                <div className="truncate">{(editingMessage ?? replyToMessage)?.plaintext}</div>
              </div>
              <button
                onClick={() => {
                  setReplyToMessage(null);
                  setEditingMessage(null);
                  setMessage("");
                }}
                className="rounded-md px-2 py-1 font-bold text-ink-600 hover:bg-white"
              >
                Cancel
              </button>
            </div>
          )}
          <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
            <button
              type="button"
              disabled={Boolean(editingMessage)}
              onClick={() => setReadOnce((value) => !value)}
              className={`flex items-center gap-1 rounded-lg border px-2 py-1 font-bold transition disabled:cursor-not-allowed disabled:opacity-50 ${readOnce ? "border-violet-300 bg-violet-50 text-violet-700" : "border-line text-ink-600"}`}
            >
              <EyeOff size={14} />
              Read once
            </button>
            <button
              type="button"
              disabled={Boolean(editingMessage)}
              onClick={() => setViewOnce((value) => !value)}
              className={`flex items-center gap-1 rounded-lg border px-2 py-1 font-bold transition disabled:cursor-not-allowed disabled:opacity-50 ${viewOnce ? "border-violet-300 bg-violet-50 text-violet-700" : "border-line text-ink-600"}`}
            >
              <TimerReset size={14} />
              View once
            </button>
            <select
              value={disappearSeconds}
              disabled={Boolean(editingMessage)}
              onChange={(event) => {
                setDisappearSeconds(Number(event.target.value));
                setCustomExpiresAt("");
              }}
              className="rounded-lg border border-line bg-white px-2 py-1 font-bold text-ink-600 outline-none disabled:cursor-not-allowed disabled:opacity-50"
              aria-label="Disappearing message expiry"
            >
              <option value={0}>No expiry</option>
              <option value={60}>Disappear 1m</option>
              <option value={300}>Disappear 5m</option>
              <option value={900}>Disappear 15m</option>
              <option value={3600}>Disappear 1h</option>
              <option value={86400}>Disappear 24h</option>
              <option value={604800}>Disappear 7d</option>
            </select>
            <label className="flex items-center gap-1 rounded-lg border border-line px-2 py-1 font-bold text-ink-600">
              <Clock size={14} />
              <input
                value={customExpiresAt}
                disabled={Boolean(editingMessage)}
                onChange={(event) => {
                  setCustomExpiresAt(event.target.value);
                  if (event.target.value) setDisappearSeconds(0);
                }}
                type="datetime-local"
                min={new Date(Date.now() + 60_000).toISOString().slice(0, 16)}
                className="bg-transparent outline-none disabled:cursor-not-allowed"
                aria-label="Exact disappearance date and time"
                title="Exact disappearance date and time"
              />
            </label>
            <label className="ml-auto flex items-center gap-2 font-bold text-ink-600">
              <input checked={typingEnabled} onChange={(event) => setTypingEnabled(event.target.checked)} type="checkbox" />
              Typing
            </label>
          </div>
          <div className="flex items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={(event) => {
                const selected = event.currentTarget.files?.[0] ?? null;
                handleAttachmentSelected(selected).catch((error) => setStatus(describeMessageError(error)));
                event.currentTarget.value = "";
              }}
            />
            <button
              type="button"
              disabled={!activeConversation || !recipientDevicesReady || Boolean(editingMessage) || Boolean(attachmentBusy) || recordingState !== "idle"}
              onClick={() => fileInputRef.current?.click()}
              className="icon-button disabled:cursor-not-allowed disabled:opacity-50"
              title={attachmentBusy === "file" ? "Encrypting attachment" : "Attach encrypted file"}
              aria-label="Attach encrypted file"
            >
              <Paperclip size={18} />
            </button>
            <button
              type="button"
              disabled={!activeConversation || !recipientDevicesReady || Boolean(editingMessage) || Boolean(attachmentBusy) || recordingState === "processing"}
              onClick={toggleVoiceRecording}
              className={`icon-button disabled:cursor-not-allowed disabled:opacity-50 ${recordingState === "recording" ? "border-rose-200 bg-rose-50 text-rose-600" : ""}`}
              title={recordingState === "recording" ? "Stop and send encrypted voice note" : "Record encrypted voice note"}
              aria-label={recordingState === "recording" ? "Stop and send encrypted voice note" : "Record encrypted voice note"}
            >
              {recordingState === "recording" ? <Square size={16} /> : <Mic size={18} />}
            </button>
            <textarea
              value={message}
              onChange={(event) => {
                setMessage(event.target.value);
                pulseTyping().catch(() => undefined);
              }}
              className="min-h-10 flex-1 resize-none rounded-lg border border-line px-3 py-2 text-sm outline-none focus:border-violet-300"
              aria-label={activeConversation ? "Message composer" : "No conversation selected"}
            />
            <button
              disabled={!activeConversation || !message.trim() || Boolean(attachmentBusy) || recordingState !== "idle"}
              onClick={sendMessage}
              className="flex h-10 items-center gap-2 rounded-lg bg-violet-600 px-4 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Send size={17} />
              {editingMessage ? "Update" : "Send"}
            </button>
          </div>
        </div>
      </section>

      <section className="shell-card overflow-hidden">
        <div className="border-b border-line p-4">
          <h2 className="text-sm font-bold text-ink-950">Contacts</h2>
          <div className="mt-3 flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 text-ink-400" size={16} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") searchUsers();
                }}
                className="w-full rounded-lg border border-line bg-canvas py-2 pl-9 pr-3 text-sm outline-none focus:border-violet-300"
                placeholder="User ID, username, or QR payload"
              />
            </div>
            <button onClick={searchUsers} className="icon-button" title="Search"><QrCode size={16} /></button>
          </div>
        </div>

          <div className="max-h-64 overflow-y-auto border-b border-line p-3">
          {searching && <div className="py-3 text-sm text-ink-600">Searching...</div>}
          {!searching && searchFeedback && (
            <div className="py-3 text-sm text-ink-600">{searchFeedback}</div>
          )}
          {!searching && !searchFeedback && searchResults.length === 0 && (
            <div className="py-3 text-sm text-ink-600">Search by user ID, username, email, or QR payload.</div>
          )}
          <div className="space-y-2">
            {searchResults.map((result) => (
              <div key={result.user_id} className="rounded-lg border border-line p-3">
                <div className="text-sm font-bold text-ink-950">{result.display_name}</div>
                <div className="mt-1 truncate font-mono text-xs text-ink-400">{result.username || result.user_id}</div>
                <button onClick={() => addContact(result)} className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg bg-violet-600 py-2 text-sm font-bold text-white hover:bg-violet-700">
                  <UserPlus size={16} />
                  Add Contact
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className="max-h-[calc(100vh-430px)] overflow-y-auto p-3">
          {contactAction && <div className="mb-3 rounded-lg bg-canvas p-3 text-sm text-ink-600">{contactAction}</div>}
          {contacts.length === 0 && <div className="py-3 text-sm text-ink-600">No contacts added yet.</div>}
          <div className="space-y-2">
            {contacts.map((contact) => {
              const contactDevices = devices.filter((device) => device.user_id === contact.contact_user_id && isTrustedDeviceForDelivery(device));
              const readyDeviceCount = selectDeliveryDevicesForUsers(contactDevices, [contact.contact_user_id], localDeviceId).length;
              const isOpeningChat = contactChatBusyId === contact.id;
              return (
                <div key={contact.id} className="rounded-lg border border-line p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-bold text-ink-950">{visibleContactName(contact)}</div>
                      <div className="mt-1 truncate font-mono text-xs text-ink-400">{contact.username}</div>
                      <div className="mt-1 text-xs font-semibold text-ink-500">
                        {readyDeviceCount > 0 ? `${readyDeviceCount} trusted device${readyDeviceCount === 1 ? "" : "s"} ready` : "No trusted device ready yet"}
                      </div>
                    </div>
                    <span className={`status-pill ${contact.trust_state === "blocked" ? "bg-rose-50 text-rose-500" : "bg-emerald-50 text-emerald-600"}`}>
                      {contact.trust_state}
                    </span>
                  </div>
                  <div className="mt-3 grid grid-cols-3 gap-2">
                    <button
                      type="button"
                      disabled={isOpeningChat}
                      onClick={() => startPrivateChat(contact)}
                      className="flex items-center justify-center gap-1 rounded-lg bg-violet-600 px-2 py-2 text-xs font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {isOpeningChat && <Loader2 className="animate-spin" size={13} />}
                      {isOpeningChat ? "Opening" : "Chat"}
                    </button>
                    <button type="button" onClick={() => updateContact(contact, contact.trust_state === "blocked" ? "added" : "blocked")} className="flex items-center justify-center rounded-lg border border-line px-2 py-2 text-xs font-bold text-ink-700 hover:bg-canvas">
                      <Ban size={14} />
                    </button>
                    <button type="button" onClick={() => updateContact(contact, "removed")} className="flex items-center justify-center rounded-lg border border-line px-2 py-2 text-xs font-bold text-ink-700 hover:bg-canvas">
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
        <div className="border-t border-line p-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
              <Download size={16} />
              Downloaded Files
            </div>
            <span className="status-pill bg-ink-50 text-ink-600">{downloadedFiles.length}</span>
          </div>
          <div className="mt-3 max-h-56 space-y-2 overflow-y-auto pr-1">
            {downloadedFiles.length === 0 && (
              <div className="rounded-lg bg-canvas p-3 text-xs text-ink-500">No decrypted downloads yet.</div>
            )}
            {downloadedFiles.map((item) => (
              <div key={item.id} className="rounded-lg border border-line bg-white p-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-xs font-bold text-ink-800">{item.name}</div>
                    <div className="mt-1 text-[11px] text-ink-500">{formatBytes(item.size_bytes)} - {item.kind}</div>
                  </div>
                  {renderAttachmentStatus(item.status)}
                </div>
                <div className="mt-2 text-xs text-ink-500">{item.detail}</div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-canvas">
                  <div className="h-full rounded-full bg-cyan-500 transition-all duration-300" style={{ width: `${Math.max(4, Math.min(100, item.progress))}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="border-t border-line p-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
              <Terminal size={16} />
              Cyber Terminal
            </div>
            <span className={`status-pill ${suspiciousCount > 0 ? "bg-amber-50 text-amber-700" : "bg-emerald-50 text-emerald-600"}`}>
              {suspiciousCount > 0 ? `${suspiciousCount} risk` : "Clean"}
            </span>
          </div>
          <div className="mt-3 max-h-80 space-y-2 overflow-y-auto pr-1">
            {chatTelemetry.length === 0 && (
              <div className="rounded-lg bg-canvas p-3 text-xs text-ink-500">No message telemetry yet.</div>
            )}
            {chatTelemetry.map((event) => (
              <div key={event.id} className="rounded-lg border border-line bg-white p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="truncate text-xs font-bold text-ink-800">{event.stage}</div>
                  <div className="text-[11px] text-ink-400">{event.progress}%</div>
                </div>
                <div className="mt-1 text-xs text-ink-500">{event.detail}</div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-canvas">
                  <div className="h-full rounded-full bg-violet-500" style={{ width: `${Math.max(4, Math.min(100, event.progress))}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
    {protectionDialog && (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/40 p-4 backdrop-blur-sm">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            submitProtectionDialog();
          }}
          className="w-full max-w-md rounded-xl border border-white/30 bg-white/90 p-5 shadow-soft backdrop-blur-xl"
        >
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-base font-bold text-ink-950">
                {protectionConfig ? `Unlock ${protectionDialog.target}` : "Create Chat PIN"}
              </h2>
              <div className="mt-1 flex items-center gap-2 text-xs font-semibold text-cyan-700">
                <LockKeyhole size={14} />
                Client-side protection
              </div>
            </div>
            <span className="status-pill bg-violet-50 text-violet-600">
              {protectionDialog.target}
            </span>
          </div>

          <div className="mt-4 grid gap-3">
            <label className="grid gap-1 text-xs font-bold text-ink-600">
              PIN or Password
              <input
                autoFocus
                value={protectionSecret}
                onChange={(event) => setProtectionSecret(event.target.value)}
                type="password"
                className="rounded-lg border border-line bg-white px-3 py-2 text-sm text-ink-900 outline-none focus:border-violet-300"
              />
            </label>
            {!protectionConfig && (
              <label className="grid gap-1 text-xs font-bold text-ink-600">
                Confirm
                <input
                  value={protectionConfirm}
                  onChange={(event) => setProtectionConfirm(event.target.value)}
                  type="password"
                  className="rounded-lg border border-line bg-white px-3 py-2 text-sm text-ink-900 outline-none focus:border-violet-300"
                />
              </label>
            )}
          </div>

          {protectionError && (
            <div className="mt-3 rounded-lg border border-rose-100 bg-rose-50 px-3 py-2 text-xs font-semibold text-rose-600">
              {protectionError}
            </div>
          )}

          <div className="mt-5 flex justify-end gap-2">
            <button
              type="button"
              onClick={() => {
                setProtectionDialog(null);
                setProtectionSecret("");
                setProtectionConfirm("");
                setProtectionError(null);
              }}
              className="rounded-lg border border-line px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={protectionBusy}
              className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {protectionBusy ? <Loader2 className="animate-spin" size={16} /> : <UnlockKeyhole size={16} />}
              {protectionConfig ? "Unlock" : "Create"}
            </button>
          </div>
        </form>
      </div>
    )}
    </>
  );
}
