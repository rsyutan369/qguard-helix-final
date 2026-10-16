import { AlertTriangle, Archive, ArchiveRestore, ArrowLeft, Ban, ChevronDown, Clock, Download, Eye, EyeOff, Loader2, LockKeyhole, MessageSquarePlus, Mic, MoreVertical, Paperclip, Pencil, QrCode, Reply, Search, Send, ShieldCheck, Smile, Square, Terminal, TimerReset, Trash2, UnlockKeyhole, UserPlus, Users, X } from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import { inlineMediaKind } from "@/lib/attachment-media";
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
import {
  chatControlCache,
  chatHistorySnapshot,
  chatMessageCache,
  ensureChatCacheOwner,
  setChatHistorySnapshot,
} from "@/lib/chat-plaintext-cache";
import {
  HISTORY_STAGES,
  completeTimeline,
  createTimeline,
  describeTimeline,
  markTimeline,
  publishTimeline,
  type Timeline,
} from "@/lib/perf-timeline";
import { deriveReadState } from "@/lib/chat-read-state";
import { syncCurrentMessagingDevice } from "@/lib/messaging-bootstrap";
import {
  approveDevicePins,
  assessDevicePins,
  devicePinInputKey,
  isDeliverableStanding,
  mergeVerdicts,
  pendingDeviceReviews,
  pinsUnavailable,
  type DevicePinIndex,
} from "@/lib/device-pins";
import { ENVELOPE_INDEX_COLUMNS, EnvelopeBodyCache, envelopeIndexEntry, planBodyFetch } from "@/lib/envelope-history";
import { attributedSenderUserId, describeRejectedEnvelopes, screenEnvelopeRows } from "@/lib/envelope-integrity";
import { parseMessageAad } from "@/lib/message-envelope-identity";
import { asRecord, hybridCiphertextFromSealed, numberArray, prekeyReferenceFromSealed } from "@/lib/message-envelope-rows";
import { guardNativeFileInput } from "@/lib/native-dialog-guard";
import { describeSavedFile, saveFileToDevice } from "@/lib/save-file";
import { supabase } from "@/lib/supabase";
import { isTauriRuntime, safeInvoke, invokeWithTimeout } from "@/lib/tauri";
import { fetchPrekeyStatus } from "@/lib/prekey-hygiene";
import { derivePqStatus, type PqExcludedDevice } from "@/lib/pq-status";
import { PqStatusBadge } from "@/components/PqStatusBadge";
import type { ContactSummary, ConversationSummary, DualSignature, SignedPrekeySummary, TrustedDevice, UserSearchResult } from "@/lib/types";
import { useCall } from "@/components/call/CallProvider";
import { buildCallPeer } from "@/lib/call-targets";
import {
  CALL_RING_POLICY,
  MESSAGE_DELIVERY_POLICY,
  deviceTime,
  selectDeliveryDevices,
  type DeliverySelectionPolicy,
} from "@/lib/delivery-devices";
import { describeKemIncompatibility, kemInteroperates } from "@/lib/kem-suite";
import { CallButton } from "@/components/call/CallButton";
import { UserAvatar } from "@/components/UserAvatar";
import { useIsMobile } from "@/lib/use-mobile";

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
  /** True only when `sender_verification` is `registered_device`. */
  authenticated: boolean;
  /**
   * How the backend proved who sent this message.
   *
   * `registered_device` — the envelope's dual signature validated AND its
   * signing keys are the ones that device published to `messaging_devices`.
   * `unverified_device` — the signature is self-consistent, but no registered
   * identity was available to anchor it to, so the sender is unproven.
   */
  /**
   * `unapproved_device` — the keys match the directory's row for the sender
   * device, but that device was added after this device first recorded the
   * sender's devices and has not been approved here. Not authenticated.
   */
  sender_verification: "registered_device" | "unverified_device" | "unapproved_device";
}

/**
 * The sender device's registered identity, as the Rust verifier expects it.
 *
 * Supplying this is what turns the envelope's signature into authentication:
 * without it the backend can only confirm that the envelope is internally
 * consistent, which anyone able to write to the relay can arrange. See
 * `verify_sender_identity` in src-tauri/src/commands/messaging.rs.
 */
interface SenderIdentityPayload {
  userId: string;
  deviceId: string;
  x25519IdentityPublic: number[];
  mlkemIdentityPublic: number[];
  ed25519IdentityPublic: number[];
  mldsaIdentityPublic: number[];
  identitySignature: DualSignature;
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
  status: "decrypted" | "sealed" | "failed" | "retired";
  authenticated: boolean;
  /** Unverified specifically because the sending device awaits approval here. */
  sender_unapproved?: boolean;
  replay_protected: boolean;
  /**
   * The hybrid combiner the envelope that OPENED was made with ("" = legacy).
   * Set only on decrypted messages: the core refuses an unknown combiner, so
   * an envelope that opened proves its label. Evidence for the PQ status badge.
   */
  kem_combiner?: string;
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
  /**
   * SHA-256 of the CIPHERTEXT. A transfer checksum, not the integrity control:
   * authenticity comes from the AES-256-GCM tag (and, since `aad_version` 1,
   * from the container binding below). Kept because it turns a truncated or
   * corrupted download into a clear message instead of an opaque AEAD failure.
   */
  sha256_b64: string;
  /**
   * Which associated-data binding sealed this attachment. Absent on anything
   * sealed before the binding existed — those were encrypted with no AAD and
   * must be decrypted with none, or every historical attachment breaks.
   */
  aad_version?: number;
  duration_ms: number | null;
  created_at: string;
}

/** Current attachment AAD binding. Bump only alongside `attachmentAad`. */
const ATTACHMENT_AAD_VERSION = 1;

/**
 * Associated data binding one attachment ciphertext to the exact object it is
 * stored as, and to the message that announced it.
 */
function attachmentAad(storagePath: string, conversationId: string, clientMessageId: string): Uint8Array {
  return new TextEncoder().encode(`QGuard-Chat-Attachment-v1|${storagePath}|${conversationId}|${clientMessageId}`);
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

/** Short label for the disappearing-message presets offered in the composer. */
function disappearLabel(seconds: number): string {
  if (seconds === 60) return "1m";
  if (seconds === 300) return "5m";
  if (seconds === 900) return "15m";
  if (seconds === 3600) return "1h";
  if (seconds === 86400) return "24h";
  if (seconds === 604800) return "7d";
  return "";
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
// The conversation gate is a privacy SCREEN, not encryption: messages are
// already end-to-end encrypted, and the workspace lock (Argon2id, in the Rust
// core) is what protects them at rest. Its verifier lives in the WebView, whose
// crypto offers PBKDF2 but neither Argon2id nor SHA-3, so it uses
// PBKDF2-HMAC-SHA-256 at the iteration count OWASP currently recommends for it.
const chatProtectionIterations = 600_000;
// A stored verifier weaker than this was not written by any released build.
const chatProtectionMinIterations = 100_000;
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
    if (!Number.isInteger(parsed.iterations) || parsed.iterations < chatProtectionMinIterations) return null;
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
    aad_version: typeof record.aad_version === "number" ? record.aad_version : undefined,
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

// Lightweight breadcrumb logging for the Secure Chat open/navigation flow.
// Printed to the webview console, which surfaces in `adb logcat` on Android and
// devtools on desktop, so a failed "open conversation" is never silent.
function logChatFlow(event: string, detail?: Record<string, unknown>): void {
  try {
    console.info(`[secure-chat] ${event}`, detail ?? "");
  } catch {
    // Never let diagnostics throw on the navigation path.
  }
}

// --- Resizable chat columns ---------------------------------------------------
// Lightweight, dependency-free panel resizing. Widths are clamped, persisted per
// user, and updated directly on the DOM while dragging so we never trigger a
// React re-render per pointer move (keeps the UI snappy with no hangs).
const CHAT_COLUMN_DEFAULTS = { left: 300, right: 330 };
const CHAT_COLUMN_LIMITS = {
  left: { min: 220, max: 480 },
  right: { min: 260, max: 540 },
  centerMin: 360,
};

interface ChatColumnWidths {
  left: number;
  right: number;
}

function chatColumnsStorageKey(userId: string): string {
  return `qguard-chat-columns:${userId}`;
}

function clampNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(Math.max(value, min), Math.max(min, max));
}

function readChatColumnWidths(userId: string): ChatColumnWidths {
  if (typeof window === "undefined") return { ...CHAT_COLUMN_DEFAULTS };
  try {
    const raw = window.localStorage.getItem(chatColumnsStorageKey(userId));
    if (!raw) return { ...CHAT_COLUMN_DEFAULTS };
    const parsed = JSON.parse(raw) as Partial<ChatColumnWidths>;
    return {
      left: clampNumber(Number(parsed.left ?? CHAT_COLUMN_DEFAULTS.left), CHAT_COLUMN_LIMITS.left.min, CHAT_COLUMN_LIMITS.left.max),
      right: clampNumber(Number(parsed.right ?? CHAT_COLUMN_DEFAULTS.right), CHAT_COLUMN_LIMITS.right.min, CHAT_COLUMN_LIMITS.right.max),
    };
  } catch {
    return { ...CHAT_COLUMN_DEFAULTS };
  }
}

function chatGridTemplate(widths: ChatColumnWidths): string {
  return `${widths.left}px 10px minmax(0, 1fr) 10px ${widths.right}px`;
}

// --- Network resilience -------------------------------------------------------
// Supabase only throws (rather than returning { error }) when the request never
// reaches the server: "Failed to fetch", a timeout, or a dropped connection.
// Free-tier projects in particular can fail the first request while they wake,
// so retrying transient failures once or twice recovers the common case.
function isTransientNetworkError(error: unknown): boolean {
  const message = (error instanceof Error ? error.message : String(error ?? "")).toLowerCase();
  return /failed to fetch|networkerror|network error|load failed|timed out|timeout|connection|fetch failed|abort|err_/i.test(message);
}

/**
 * Run one PostgREST query under an explicit deadline.
 *
 * The Supabase client's own 30s global fetch timeout is a last-resort guard,
 * not a user-facing deadline: a request that is going to fail usually fails
 * long before it, and one that stalls holds the caller for the full half
 * minute. Pairing a short per-attempt deadline with `withFetchRetry` turns a
 * stalled round trip into a fast retry instead of a long wait, which is what
 * actually recovers a dropped mobile connection.
 *
 * The in-flight request is aborted on expiry rather than merely abandoned, so a
 * retry does not leave its predecessor consuming a connection — on a
 * constrained project, abandoned requests are themselves a source of stalling.
 * The rejection carries a message `isTransientNetworkError` recognises, so the
 * retry loop treats a deadline the same way it treats a dropped connection.
 */
async function queryWithDeadline<T>(
  build: (signal: AbortSignal) => PromiseLike<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  const controller = new AbortController();
  let timer: number | undefined;
  try {
    return await Promise.race([
      build(controller.signal),
      new Promise<never>((_resolve, reject) => {
        timer = window.setTimeout(() => {
          controller.abort();
          reject(new Error(`${label} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) window.clearTimeout(timer);
  }
}

async function withFetchRetry<T>(task: () => Promise<T>, attempts = 3, delayMs = 600): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await task();
    } catch (error) {
      lastError = error;
      if (!isTransientNetworkError(error) || attempt === attempts - 1) throw error;
      await new Promise((resolve) => setTimeout(resolve, delayMs * (attempt + 1)));
    }
  }
  throw lastError;
}

const DIRECTORY_UNREACHABLE_MESSAGE = "Couldn't reach the directory service. Check your connection and try again in a moment.";

// Safety-net cadence for the open thread's realtime reload, mirroring
// call-signaling.ts's IDLE_POLL_MS: a slow poll for the window where the
// WebView's realtime socket has died silently (Android background/screen-off
// suspend, a Wi-Fi/cellular handoff) without ever firing CHANNEL_ERROR/CLOSED
// and without a visibilitychange/online transition to catch it. Without this,
// a message sent into that gap never appears until an unrelated event nudges
// a reload — which reads to the user as "messages aren't showing up".
const CHAT_IDLE_POLL_MS = 12_000;

// Upper bound on a single message decrypt round-trip. Generous enough for the
// portable (non-NEON) ML-KEM/ML-DSA build on a slow phone, where every decrypt
// also queues behind the global Rust key-scope mutex — but no longer so
// generous that a single stalled decrypt can hold the thread past the point a
// user has given up. A group that exceeds it falls through to the next
// candidate envelope and finally to a visible "failed" bubble, so overshooting
// costs one bubble, never the whole conversation.
const DECRYPT_TIMEOUT_MS = 9_000;
// How often the protection badge re-reads this device's prekey rotation state.
// Rotation is daily, so minutes are ample; each read is one small core call.
const FORWARD_SECRECY_REFRESH_MS = 5 * 60_000;

// Per-attempt deadline for the history fetch itself.
//
// This is the gap that produced the "Loading encrypted history..." hang. The
// Supabase client has a 30s global fetch timeout and this query was not
// retried, so one stalled round trip — routine on mobile, and routine against a
// resource-constrained project — pinned the thread for half a minute with
// nothing on screen. The deadline is per attempt and `withFetchRetry` gives
// three of them, which recovers from a dropped connection far faster than a
// single long wait ever could.
const HISTORY_FETCH_TIMEOUT_MS = 6_000;

// Per-attempt deadline for one chunk of envelope bodies. A chunk is about
// 0.7 MB (see `envelope-history.ts`), so it gets longer than the listing: a
// deadline shorter than the link needs to carry the chunk fails every attempt.
const HISTORY_BODY_TIMEOUT_MS = 15_000;

// Body chunks requested at once after the first. Kept low: the WebView shares
// its connections with the realtime socket and the dashboard refresh.
const HISTORY_BODY_PARALLEL_REQUESTS = 3;

// Everything the verifier and the decrypt path read from an envelope row.
const ENVELOPE_BODY_COLUMNS = "id,conversation_id,client_message_id,parent_client_message_id,sender_user_id,sender_device_id,recipient_user_id,recipient_device_id,message_kind,sealed_sender_envelope,ciphertext,nonce,auth_tag,aad,ratchet_counter,suite,lifecycle,verification_state,threat_result,deleted_at,created_at";

// Hard ceiling on how long the "Loading encrypted history..." gate may be shown
// before the UI must say something actionable instead.
//
// Every individual step below is bounded now, but bounded steps still compose:
// a retried fetch plus a page of slow decrypts can legitimately add up. This is
// the backstop that makes "stuck forever" unrepresentable regardless of how the
// steps compose — it never cancels the load (which may still be making
// progress and will paint when it lands), it just refuses to keep claiming that
// loading is all that is happening.
const HISTORY_RENDER_DEADLINE_MS = 10_000;

// How long the first paint may wait on a sender-identity anchor it does not yet
// have cached. See the call site in `hydrateMessageRows`.
const SENDER_IDENTITY_PRIME_BUDGET_MS = 2_500;

// How long the send path may trust its cached recipient-device list before it
// must re-read the authoritative one.
//
// A message is sealed per RECIPIENT DEVICE, so a device missing from that list
// gets no envelope at all — and no amount of reloading or polling on the peer's
// side can recover a row that was never written. Only re-sealing (the
// `syncMissingDeviceEnvelopes` repair) fixes it, and that runs only when the
// SENDER later re-decrypts the message, so if the sender closes the app the
// message can stay undelivered indefinitely. Previously the send path refetched
// only when the cache yielded ZERO devices, so a peer who added a device — or
// whose registration hadn't reached this client yet (Android suspends the
// realtime socket while backgrounded) — silently received nothing.
//
// A short TTL keeps the burst case fast (rapid consecutive sends still hit the
// cache, which is what made sends slow before) while bounding how long a send
// can address a stale device set.
const DEVICE_LIST_MAX_STALENESS_MS = 20_000;

function mapDeviceTrustState(value: string): TrustedDevice["trust_state"] {
  const normalized = value.toLowerCase();
  if (value === "ThisDevice" || normalized === "this_device") return "ThisDevice";
  if (value === "Trusted" || normalized === "trusted") return "Trusted";
  if (value === "PendingQrApproval" || normalized === "pending") return "PendingQrApproval";
  if (value === "Revoked" || normalized === "revoked") return "Revoked";
  return "Suspicious";
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

/**
 * Whose message this is. Decided from what the sender SIGNED; the unsigned
 * author note is believed only on an envelope this account's own devices
 * re-sealed for sync. See `attributedSenderUserId`.
 */
function originalSenderUserId(row: MessageEnvelopeRow, localUserId: string): string {
  return attributedSenderUserId(row, localUserId);
}

function originalSenderDeviceId(row: MessageEnvelopeRow): string | null {
  return envelopeString(row, "sync_original_sender_device_id")
    ?? envelopeString(row, "original_sender_device_id")
    ?? row.sender_device_id;
}

function envelopeControlType(row: MessageEnvelopeRow): string | null {
  return envelopeString(row, "control_type");
}

/**
 * The envelope id a realtime change says was deleted — soft (an UPDATE that
 * sets `deleted_at`) or hard (a DELETE) — or null for any other change.
 */
function deletedEnvelopeId(payload: { eventType?: string; new?: unknown; old?: unknown }): string | null {
  if (payload.eventType === "DELETE") {
    const id = asRecord(payload.old).id;
    return id ? String(id) : null;
  }
  if (payload.eventType === "UPDATE") {
    const next = asRecord(payload.new);
    return next.deleted_at && next.id ? String(next.id) : null;
  }
  return null;
}

function buildTauriEnvelope(row: MessageEnvelopeRow): EncryptedMessageEnvelope {
  const sealed = row.sealed_sender_envelope;
  // The identity fields the SENDER signed, taken from the AAD rather than from
  // the row's columns. `sender_device_id` / `recipient_device_id` are FK columns
  // declared ON DELETE SET NULL, so retiring a device nulls them in messages
  // signed long beforehand -- and rebuilding the signable from them then fails
  // every one of those messages with "Ed25519 signature verification failed".
  // See parseMessageAad for why the AAD is the stricter source, not just the
  // surviving one. Columns remain the fallback when the AAD is unreadable.
  const signed = parseMessageAad(row.aad);
  return {
    message_id: signed?.message_id ?? row.id,
    conversation_id: signed?.conversation_id ?? row.conversation_id,
    sender_user_id: signed?.sender_user_id ?? row.sender_user_id,
    recipient_user_id: signed?.recipient_user_id ?? row.recipient_user_id,
    sender_device_id: signed?.sender_device_id ?? row.sender_device_id ?? "",
    recipient_device_id: signed?.recipient_device_id ?? row.recipient_device_id ?? "",
    counter: signed?.counter ?? Number(row.ratchet_counter ?? 0),
    kind: fromMessageKind(row.message_kind),
    sealed_sender: Boolean(sealed.sealed_sender ?? true),
    envelope: {
      nonce: byteaToBytes(row.nonce),
      ciphertext: byteaToBytes(row.ciphertext),
      tag: byteaToBytes(row.auth_tag),
    },
    aad: byteaToBytes(row.aad),
    hybrid_ciphertext: hybridCiphertextFromSealed(sealed),
    ...prekeyReferenceFromSealed(sealed),
    message_signature: normalizeSignature(sealed.message_signature),
    sender_ed25519_public: numberArray(sealed.sender_ed25519_public),
    sender_mldsa_public: numberArray(sealed.sender_mldsa_public),
    suite: row.suite,
    created_at: row.created_at,
  };
}

// ML-KEM-1024 only (1568 bytes). 1184 -- the ML-KEM-768 length -- used to be
// accepted here, but this build's `encapsulate` refuses anything except
// ML-KEM-1024: there is one accepted parameter set precisely so there is nothing
// to negotiate down to. Accepting 768 here only made the UI call a device ready
// that the backend would then refuse to seal to.
const mlKemPublicKeyLengths = new Set([1568]);

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

/**
 * A device is only addressable if this build's KEM can actually interoperate
 * with the one that produced its keys. See lib/kem-suite.ts: `suite.pq_kem`
 * says "ML-KEM-1024" on pre-FIPS-203 devices too, and Kyber-1024 keys are the
 * same length, so without this check every key/signature test above passes and
 * we happily seal an envelope the recipient can never open.
 */
function isSendableDevice(device: TrustedDevice): boolean {
  return isTrustedDeviceForDelivery(device)
    && hasSendableKeyBundle(device)
    && kemInteroperates(device.suite);
}

function recordTime(record: Record<string, unknown>, key: string): number {
  return deviceTime(typeof record[key] === "string" ? String(record[key]) : null);
}

/**
 * Devices to address for `userIds`, most-likely endpoint first.
 *
 * Selection itself lives in lib/delivery-devices.ts (pure + unit-tested); this
 * wrapper only applies the page's "can this device be addressed at all" filter.
 * The policy argument matters: message delivery seals to a wide set because an
 * envelope waits for the device, while a ring is real time and is aimed at the
 * devices that could actually answer right now.
 */
function selectDeliveryDevicesForUsers(
  devices: TrustedDevice[],
  userIds: string[],
  localDeviceId: string | null = null,
  policy: DeliverySelectionPolicy = MESSAGE_DELIVERY_POLICY,
  // The device-pin gate (lib/device-pins.ts): a device that appeared after
  // first use and has not been approved, or whose keys changed, is never
  // addressed. The Rust core refuses such a device too; filtering here keeps a
  // send from failing on it.
  accept: (device: TrustedDevice) => boolean = () => true,
): TrustedDevice[] {
  return selectDeliveryDevices(devices.filter((device) => isSendableDevice(device) && accept(device)), userIds, localDeviceId, policy);
}

/** The pin gate for one judged index. */
function pinGate(index: DevicePinIndex): (device: TrustedDevice) => boolean {
  return (device) => isDeliverableStanding(index.get(device.device_id)?.standing);
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

  const { data: deviceRows, error: deviceError } = await withFetchRetry(() => Promise.resolve(supabase
    .from("messaging_devices")
    .select("id,user_id,device_label,fingerprint,trust_state,suite,last_seen_at,created_at,revoked_at,approved_by_device_id,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature")
    .in("user_id", uniqueUserIds)
    .neq("trust_state", "revoked")
    .order("last_seen_at", { ascending: false })));
  if (deviceError) throw deviceError;

  const rows = (deviceRows ?? []) as Array<Record<string, unknown>>;
  const deviceIds = rows.map((device) => String(device.id));
  const signedPrekeysByDevice = new Map<string, SignedPrekeySummary>();

  if (deviceIds.length > 0) {
    const { data: prekeyRows, error: prekeyError } = await withFetchRetry(() => Promise.resolve(supabase
      .from("messaging_signed_prekeys")
      .select("id,user_id,device_id,x25519_public,mlkem_public,signature,fingerprint,is_active,expires_at,created_at")
      .in("device_id", deviceIds)
      .eq("is_active", true)
      .order("expires_at", { ascending: true })));
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

/**
 * Registered identities for the devices that SENT the messages being opened,
 * keyed by device id.
 *
 * Deliberately a separate query from `loadTrustedDevicesForUsers`, for two
 * reasons:
 *   - that one filters `trust_state <> 'revoked'`, because it answers "where may
 *     I send?". This one answers "who signed this?", and retiring a key does not
 *     retroactively unsign the messages it signed while it was live.
 *   - it needs no prekeys, so it stays one round trip over a small column set.
 *
 * Cached for the session: a device's identity keys are immutable — a re-key
 * mints a NEW device id rather than rewriting an existing row.
 */
const senderIdentityCache = new Map<string, SenderIdentityPayload | null>();

async function primeSenderIdentities(deviceIds: string[]): Promise<void> {
  const wanted = Array.from(new Set(deviceIds.filter(Boolean))).filter((id) => !senderIdentityCache.has(id));
  if (wanted.length === 0) return;
  const { data, error } = await withFetchRetry(() => Promise.resolve(supabase
    .from("messaging_devices")
    .select("id,user_id,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature")
    .in("id", wanted)));
  // A failed lookup must not be cached as "no such device": that would pin every
  // message from those senders to `unverified_device` for the rest of the
  // session over one transient network error.
  if (error) return;
  const found = new Set<string>();
  ((data ?? []) as Array<Record<string, unknown>>).forEach((row) => {
    const deviceId = String(row.id);
    const signature = row.identity_signature as DualSignature | null;
    if (!signature?.ed25519?.length || !signature?.ml_dsa_65?.length) {
      senderIdentityCache.set(deviceId, null);
      found.add(deviceId);
      return;
    }
    senderIdentityCache.set(deviceId, {
      userId: String(row.user_id),
      deviceId,
      x25519IdentityPublic: byteaToBytes(row.x25519_identity_public),
      mlkemIdentityPublic: byteaToBytes(row.mlkem_identity_public),
      ed25519IdentityPublic: byteaToBytes(row.ed25519_identity_public),
      mldsaIdentityPublic: byteaToBytes(row.mldsa_identity_public),
      identitySignature: signature,
    });
    found.add(deviceId);
  });
  // Devices the query legitimately returned nothing for (deleted rows, or a
  // peer's revoked device that RLS hides) are cached as "no anchor available".
  wanted.filter((id) => !found.has(id)).forEach((id) => senderIdentityCache.set(id, null));
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
      // Sent so the BACKEND, not just this client-side filter, decides whether
      // an envelope is produced at all (verify_recipient_kem_interoperates).
      suite: device.suite,
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
  // Optimistic overlay for conversations we just created locally. The parent
  // `conversations` prop only updates after an async refresh + realtime round
  // trip, so a freshly created conversation is briefly absent from it. Without
  // this overlay the "keep a valid selection" effect below would immediately
  // reset `activeConversationId` away from the new conversation (landing the
  // user on the wrong/self-only thread, or bouncing back to the list). Entries
  // are pruned once the real row arrives in `conversations`.
  const [pendingConversations, setPendingConversations] = useState<ConversationSummary[]>([]);
  // Phone layout shows one pane at a time: the conversation list, or the
  // active thread (opened by tapping a conversation, closed with Back).
  const isMobile = useIsMobile();
  const [mobilePane, setMobilePane] = useState<"list" | "thread">("list");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState("Ready");
  const [query, setQuery] = useState("");
  const [searchResults, setSearchResults] = useState<UserSearchResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [searchFeedback, setSearchFeedback] = useState<string | null>(null);
  const [contactAction, setContactAction] = useState<string | null>(null);
  const [showMyQrPayload, setShowMyQrPayload] = useState(false);
  const [myQrPayloadCopied, setMyQrPayloadCopied] = useState(false);
  const [showNewChat, setShowNewChat] = useState(false);
  const [newChatBusyId, setNewChatBusyId] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [messagesLoading, setMessagesLoading] = useState(false);
  // True once the history render deadline has passed with nothing to show, so
  // the pane can offer recovery instead of an endless spinner.
  const [historyStalled, setHistoryStalled] = useState(false);
  const [sending, setSending] = useState(false);
  const [messageAction, setMessageAction] = useState<string | null>(null);
  const [openMessageMenuId, setOpenMessageMenuId] = useState<string | null>(null);
  const [deletingMessageId, setDeletingMessageId] = useState<string | null>(null);
  const [replyToMessage, setReplyToMessage] = useState<ChatMessage | null>(null);
  const [editingMessage, setEditingMessage] = useState<ChatMessage | null>(null);
  const [readOnce, setReadOnce] = useState(false);
  const [viewOnce, setViewOnce] = useState(false);
  const [disappearSeconds, setDisappearSeconds] = useState(0);
  const [customExpiresAt, setCustomExpiresAt] = useState("");
  // Collapsed by default: these five controls occupied three rows above the
  // input, which on a phone left almost no room for the conversation itself.
  const [composerOptionsOpen, setComposerOptionsOpen] = useState(false);
  const [attachmentBusy, setAttachmentBusy] = useState<"file" | "voice" | "download" | null>(null);
  const [recordingState, setRecordingState] = useState<"idle" | "recording" | "processing">("idle");
  const [attachmentPreviewUrls, setAttachmentPreviewUrls] = useState<Record<string, string>>({});
  const [lightbox, setLightbox] = useState<{ url: string; name: string } | null>(null);
  const [downloadedFiles, setDownloadedFiles] = useState<DownloadedAttachmentRecord[]>([]);
  const [typingIndicators, setTypingIndicators] = useState<TypingIndicator[]>([]);
  const [chatTelemetry, setChatTelemetry] = useState<ChatTelemetryEvent[]>([]);
  const [typingEnabled, setTypingEnabled] = useState(true);
  // Anything armed here changes how the NEXT message behaves -- a burn-on-read
  // or an expiry the sender cannot see is a trap, so whatever is active stays
  // on screen in the collapsed summary. Only the controls are hidden, never the
  // state they hold.
  const composerOptionSummary = useMemo(() => {
    const active: string[] = [];
    if (readOnce) active.push("Read once");
    if (viewOnce) active.push("View once");
    if (customExpiresAt) active.push("Custom expiry");
    else if (disappearSeconds > 0) active.push(`Disappears ${disappearLabel(disappearSeconds)}`);
    if (!typingEnabled) active.push("Typing off");
    return active;
  }, [readOnce, viewOnce, customExpiresAt, disappearSeconds, typingEnabled]);
  const [conversationView, setConversationView] = useState<ConversationView>("active");
  const [openConversationMenuId, setOpenConversationMenuId] = useState<string | null>(null);
  const [conversationBusyId, setConversationBusyId] = useState<string | null>(null);
  const [conversationAction, setConversationAction] = useState<string | null>(null);
  const [contactChatBusyId, setContactChatBusyId] = useState<string | null>(null);
  const [chatColumnWidths, setChatColumnWidths] = useState<ChatColumnWidths>(() => readChatColumnWidths(userId));
  const [contactOverrides, setContactOverrides] = useState<Record<string, ContactSummary["trust_state"]>>({});
  const [rightTab, setRightTab] = useState<"contacts" | "files" | "terminal">("contacts");
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
  const chatGridRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const voiceChunksRef = useRef<Blob[]>([]);
  const voiceStartedAtRef = useRef<number>(0);
  const attachmentPreviewUrlsRef = useRef<Record<string, string>>({});
  // Module-scope plaintext caches (see chat-plaintext-cache.ts): they survive
  // page remounts so revisiting the chat never re-decrypts the whole history,
  // and are wiped on workspace lock / logout / user-device change.
  const decryptedMessageCacheRef = useRef<Map<string, ChatMessage>>(chatMessageCache<ChatMessage>());
  const decryptedControlCacheRef = useRef<Map<string, SecureControlMessage & { sender_user_id: string; created_at: string }>>(
    chatControlCache<SecureControlMessage & { sender_user_id: string; created_at: string }>(),
  );
  const decryptInFlightRef = useRef<Map<string, Promise<DecryptedChatEnvelope>>>(new Map());
  const syncInFlightRef = useRef<Set<string>>(new Set());
  // When the send path last read the AUTHORITATIVE recipient-device list from
  // the server, keyed by the recipient set. See DEVICE_LIST_MAX_STALENESS_MS.
  const deviceListFetchedAtRef = useRef<Map<string, number>>(new Map());
  // Newest envelope `created_at` the open thread has loaded, used by the idle
  // catch-up probe to avoid reloading when nothing new exists.
  const newestEnvelopeAtRef = useRef<string>("");
  // Envelope bodies already downloaded for the open thread, so a reload fetches
  // only the rows it does not hold. Holds one conversation at a time.
  const envelopeBodyCacheRef = useRef(new EnvelopeBodyCache<MessageEnvelopeRow>());
  const syncedEnvelopeTargetsRef = useRef<Set<string>>(new Set());
  // Refused envelope rows already reported, so a reload does not report the
  // same replayed copy again every few seconds.
  const reportedRejectedRowsRef = useRef<Set<string>>(new Set());
  const searchRequestRef = useRef(0);
  const messageLoadSeqRef = useRef(0);
  const threatTelemetryRef = useRef<Set<string>>(new Set());
  const expiredAttachmentCleanupRef = useRef<Set<string>>(new Set());
  const typingPulseRef = useRef<number>(0);

  // Contacts shown in the panel: apply optimistic overrides on top of the live
  // props so block/unblock/delete feel instant, then hide soft-removed entries.
  const displayedContacts = useMemo(() => contacts
    .map((contact) => (contactOverrides[contact.id] ? { ...contact, trust_state: contactOverrides[contact.id] } : contact))
    .filter((contact) => contact.trust_state !== "removed"), [contacts, contactOverrides]);
  const blockedContactCount = useMemo(() => displayedContacts.filter((contact) => contact.trust_state === "blocked").length, [displayedContacts]);

  // Drop optimistic overrides once the refreshed server state confirms them, so
  // we never keep a stale local value after the realtime refresh lands.
  useEffect(() => {
    setContactOverrides((previous) => {
      if (Object.keys(previous).length === 0) return previous;
      const next: Record<string, ContactSummary["trust_state"]> = {};
      for (const [id, state] of Object.entries(previous)) {
        const fresh = contacts.find((contact) => contact.id === id);
        if (state === "removed") {
          if (fresh) next[id] = state;
        } else if (fresh && fresh.trust_state !== state) {
          next[id] = state;
        }
      }
      return next;
    });
  }, [contacts]);

  const persistChatColumnWidths = useCallback((widths: ChatColumnWidths) => {
    try {
      window.localStorage.setItem(chatColumnsStorageKey(userId), JSON.stringify(widths));
    } catch {
      // Persisting layout is best-effort; in-memory widths still apply.
    }
  }, [userId]);

  const startColumnResize = useCallback((side: "left" | "right", event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    event.preventDefault();
    const grid = chatGridRef.current;
    if (!grid) return;
    const handle = event.currentTarget;
    const startX = event.clientX;
    const startWidths = { ...chatColumnWidths };
    let nextWidths = { ...startWidths };
    try {
      handle.setPointerCapture(event.pointerId);
    } catch {
      // Pointer capture is an optimization; dragging still works without it.
    }
    document.body.style.userSelect = "none";
    document.body.style.cursor = "col-resize";

    const onMove = (moveEvent: PointerEvent) => {
      const gridWidth = grid.getBoundingClientRect().width;
      const delta = moveEvent.clientX - startX;
      if (side === "left") {
        const max = Math.min(CHAT_COLUMN_LIMITS.left.max, gridWidth - startWidths.right - CHAT_COLUMN_LIMITS.centerMin - 20);
        nextWidths = { ...nextWidths, left: clampNumber(startWidths.left + delta, CHAT_COLUMN_LIMITS.left.min, max) };
      } else {
        const max = Math.min(CHAT_COLUMN_LIMITS.right.max, gridWidth - startWidths.left - CHAT_COLUMN_LIMITS.centerMin - 20);
        nextWidths = { ...nextWidths, right: clampNumber(startWidths.right - delta, CHAT_COLUMN_LIMITS.right.min, max) };
      }
      // Update the DOM directly during the drag — no React re-render per frame.
      grid.style.gridTemplateColumns = chatGridTemplate(nextWidths);
    };

    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
      try {
        handle.releasePointerCapture(event.pointerId);
      } catch {
        // ignore
      }
      setChatColumnWidths(nextWidths);
      persistChatColumnWidths(nextWidths);
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  }, [chatColumnWidths, persistChatColumnWidths]);

  const effectiveConversations = useMemo(() => {
    const known = new Set(conversations.map((conversation) => conversation.id));
    // Server rows first, then any still-unmerged optimistic rows we created.
    const merged = [
      ...conversations,
      ...pendingConversations.filter((conversation) => !known.has(conversation.id)),
    ];
    return merged
      .map((conversation) => ({ ...conversation, ...(conversationStateOverrides[conversation.id] ?? {}) }))
      .filter((conversation) => !conversation.deleted_at);
  }, [conversationStateOverrides, conversations, pendingConversations]);

  // Drop optimistic conversations once the real row lands in the prop. Returning
  // the same reference when nothing changed avoids a re-render loop.
  useEffect(() => {
    setPendingConversations((current) => {
      if (current.length === 0) return current;
      const known = new Set(conversations.map((conversation) => conversation.id));
      const next = current.filter((conversation) => !known.has(conversation.id));
      return next.length === current.length ? current : next;
    });
  }, [conversations]);
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
  // Stable identity for the message-load and realtime effects. `activeConversation`
  // is a NEW object on every dashboard refresh (see `effectiveConversations`), so
  // depending on it churned both effects; the id only changes on a real switch.
  const activeConversationLoadId = activeConversation?.id ?? null;
  // Live mirror for async work that finishes after a conversation switch.
  const activeConversationIdRef = useRef<string | null>(activeConversationLoadId);
  activeConversationIdRef.current = activeConversationLoadId;
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

  // Every device id this client already knows — the peers' and its own, since
  // a sent message also arrives as a self-sync envelope from one of my devices.
  // Held in a ref ON PURPOSE: `devices` is rebuilt by every dashboard refresh,
  // so taking it as a dependency of the history loader would re-create that
  // callback constantly and, through it, re-fire the load and tear down the
  // realtime channel — the exact churn the loader's dependency list was
  // narrowed to a string to avoid.
  const knownDeviceIds = useMemo(() => devices.map((device) => device.device_id), [devices]);
  const knownDeviceIdsRef = useRef<string[]>(knownDeviceIds);
  knownDeviceIdsRef.current = knownDeviceIds;

  /**
   * Warm the sender-identity anchors for the devices already known here.
   *
   * Runs concurrently with the envelope fetch so verification costs nothing on
   * the first-paint path. A failure is swallowed deliberately: the anchors
   * decide the "Verified" vs "Sender unverified" badge, and a missing anchor
   * must degrade the badge, never block the message.
   */
  const prewarmSenderIdentities = useCallback(
    (): Promise<void> => primeSenderIdentities(knownDeviceIdsRef.current).catch(() => undefined),
    [],
  );
  // ---- Device pins -------------------------------------------------------
  // What the core has recorded about each listed device. Re-asked whenever a
  // device appears, disappears or changes a key — not on every refresh.
  const [pinIndex, setPinIndex] = useState<DevicePinIndex>(() => new Map());
  const pinIndexRef = useRef<DevicePinIndex>(pinIndex);
  pinIndexRef.current = pinIndex;
  const refreshDevicePins = useCallback(async (list: TrustedDevice[]): Promise<DevicePinIndex> => {
    const assessment = await assessDevicePins(list);
    if (!assessment) return pinIndexRef.current;
    const next = mergeVerdicts(pinIndexRef.current, assessment);
    pinIndexRef.current = next;
    setPinIndex(next);
    return next;
  }, []);
  const devicesRef = useRef<TrustedDevice[]>(devices);
  devicesRef.current = devices;
  const devicePinKey = useMemo(() => devicePinInputKey(devices), [devices]);
  useEffect(() => {
    void refreshDevicePins(devicesRef.current);
  }, [devicePinKey, refreshDevicePins]);
  const acceptsDelivery = useMemo(() => pinGate(pinIndex), [pinIndex]);
  // Devices of the people in this conversation (and of this account) that the
  // user has to decide about before anything is sent to them.
  const deviceReviews = useMemo(
    () => pendingDeviceReviews(devices, pinIndex, [...activeRecipientUserIds, userId], userId),
    [activeRecipientUserIds, devices, pinIndex, userId],
  );
  const devicePinsUnavailable = useMemo(() => pinsUnavailable(pinIndex), [pinIndex]);
  // The contact's devices that could be delivered to the moment the user
  // approves them. Counted separately because the remedy is on THIS screen.
  const recipientDevicesAwaitingApproval = useMemo(
    () => deviceReviews.filter((review) => review.owner === "contact" && review.approvable && hasSendableKeyBundle(review.device)).length,
    [deviceReviews],
  );
  const [approvingDeviceId, setApprovingDeviceId] = useState<string | null>(null);

  const sendableRecipientDevices = useMemo(
    () => selectDeliveryDevicesForUsers(recipientDevices, activeRecipientUserIds, localDeviceId, MESSAGE_DELIVERY_POLICY, acceptsDelivery),
    [acceptsDelivery, activeRecipientUserIds, localDeviceId, recipientDevices],
  );
  const recipientDevicesMissingPrekeys = activeRecipientUserIds.length > 0 && sendableRecipientDevices.length === 0 && recipientDevices.length > 0;
  const recipientDevicesReady = sendableRecipientDevices.length > 0;

  // Peer devices dropped from delivery purely because their KEM cannot
  // interoperate. Distinguished from "missing prekeys" because the remedy is
  // different and lives elsewhere: nothing on THIS device can fix it, the peer
  // has to update their app. Left unnamed, this presents as an unreachable
  // contact with a fully green key bundle.
  const recipientDevicesOnStaleBuild = useMemo(
    () => recipientDevices.filter((device) => hasSendableKeyBundle(device) && !kemInteroperates(device.suite)),
    [recipientDevices],
  );

  // True once a decrypt has actually reported a retired key in this thread, so
  // the banner is evidence-driven rather than guessed from device metadata.
  const retiredKeyMessageCount = useMemo(
    () => chatMessages.filter((item) => item.conversation_id === activeConversationId && item.status === "retired").length,
    [activeConversationId, chatMessages],
  );

  // This device's forward-secrecy state in the core's own words, for the
  // protection badge. Null outside the app or when the core does not answer:
  // the badge then says "not measured" instead of guessing.
  const [forwardSecrecy, setForwardSecrecy] = useState<{ healthy: boolean; summary: string } | null>(null);
  useEffect(() => {
    if (!isTauriRuntime() || !userId) return undefined;
    let cancelled = false;
    const read = () => {
      fetchPrekeyStatus(userId)
        .then((prekeys) => {
          if (!cancelled) setForwardSecrecy({ healthy: prekeys.forwardSecrecyHealthy, summary: prekeys.forwardSecrecySummary });
        })
        .catch(() => { if (!cancelled) setForwardSecrecy(null); });
    };
    read();
    const timer = window.setInterval(read, FORWARD_SECRECY_REFRESH_MS);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [userId]);

  // The conversation's protection badge (lib/pq-status.ts), from the same
  // device lists and verdicts that decide delivery — so the badge cannot say
  // something different from what the next send will actually do.
  const pqStatus = useMemo(() => {
    if (!activeConversation) return null;
    const excluded = new Map<string, PqExcludedDevice>();
    for (const device of recipientDevicesOnStaleBuild) {
      excluded.set(device.device_id, { label: device.label, reason: "older_build" });
    }
    for (const review of deviceReviews) {
      if (review.owner !== "contact" || excluded.has(review.device.device_id)) continue;
      const standing = review.verdict.standing;
      excluded.set(review.device.device_id, {
        label: review.device.label,
        reason: standing === "new" ? "awaiting_approval" : standing === "key_changed" ? "key_changed" : "invalid_identity",
      });
    }
    const openedMessages = chatMessages
      // Only messages that opened HERE and recorded the combiner that opened
      // them; anything else is no evidence either way.
      .filter((item) => item.conversation_id === activeConversation.id && item.status === "decrypted" && item.kem_combiner !== undefined)
      .sort((left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime())
      .map((item) => ({
        incoming: item.sender_user_id !== userId,
        kemCombiner: item.kem_combiner ?? "",
        authenticated: item.authenticated,
      }));
    return derivePqStatus({
      inApp: isTauriRuntime(),
      peerName: conversationTitle(activeConversation),
      deliveryDevices: sendableRecipientDevices.map((device) => ({
        deviceId: device.device_id,
        label: device.label,
        suite: device.suite,
        standing: pinIndex.get(device.device_id)?.standing,
      })),
      excludedDevices: [...excluded.values()],
      openedMessages,
      pinsUnavailable: devicePinsUnavailable,
      forwardSecrecy,
    });
    // conversationTitle reads contacts; it is a plain function of this render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeConversation, chatMessages, contacts, deviceReviews, devicePinsUnavailable, forwardSecrecy, pinIndex, recipientDevicesOnStaleBuild, sendableRecipientDevices, userId]);

  // Ring targets are chosen with the CALL policy, not the message policy: a
  // ring is real time, so it goes to the devices that could actually answer
  // now, while messages fan out to a wider set that includes devices which are
  // merely away. Both come from the same selector, so a device that can receive
  // a message can always be rung.
  const callableRecipientDevices = useMemo(
    () => selectDeliveryDevicesForUsers(recipientDevices, activeRecipientUserIds, localDeviceId, CALL_RING_POLICY, acceptsDelivery),
    [acceptsDelivery, activeRecipientUserIds, localDeviceId, recipientDevices],
  );

  const callPeer = useMemo(() => {
    if (activeConversation?.conversation_type !== "direct") return null;
    // EVERY device the peer can receive on — the same list messages fan out to.
    // Taking [0] here (the most-recently-seen device) is what stopped calls
    // ringing whenever the peer was using their other device; see
    // lib/call-targets.ts for the full account.
    return buildCallPeer(callableRecipientDevices, conversationTitle(activeConversation));
  }, [activeConversation, callableRecipientDevices]);

  // App-level call engine (CallProvider): incoming calls ring on every page;
  // this page only supplies the outgoing-call target.
  const call = useCall();

  useEffect(() => {
    setProtectionConfig(readChatProtectionConfig(userId));
    setProtectedUnlockUntil({ archived: 0, hidden: 0 });
    setConversationStateOverrides({});
    setLocalDeviceId(null);
    setLocalSignedPrekeyId(null);
    // Plaintext caches are module-scoped: only wiped when the OWNER changes
    // (different user/device), not on every page mount — that reuse is what
    // makes returning to the chat instant instead of a full re-decrypt.
    ensureChatCacheOwner(userId, null);
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
    if (!localDeviceId) return;
    ensureChatCacheOwner(userId, localDeviceId);
    decryptInFlightRef.current.clear();
    syncInFlightRef.current.clear();
    syncedEnvelopeTargetsRef.current.clear();
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
      if (activeConversationId) setActiveConversationId("");
      return;
    }
    if (!activeConversationId) {
      setActiveConversationId(visibleConversations[0].id);
      return;
    }
    // Recover a fallback selection ONLY when the current conversation has truly
    // disappeared from the full set (deleted/left) — never merely because it is
    // filtered out by the active/archived/hidden view, or is still settling in
    // the optimistic overlay after being created. Clobbering a just-created
    // conversation here is exactly what stranded users on the wrong/self-only
    // thread (or bounced them back to the list) right after tapping a user.
    const stillExists = effectiveConversations.some((conversation) => conversation.id === activeConversationId);
    if (!stillExists) {
      setActiveConversationId(visibleConversations[0].id);
    }
  }, [activeConversationId, effectiveConversations, visibleConversations]);

  useEffect(() => {
    if (localDeviceId && rawLocalDevice && !localSignedPrekeyId) setStatus("Syncing this desktop signed prekey");
    else if (localDeviceId && rawLocalDevice && localSignedPrekeyId && rawLocalDevice.signed_prekey?.prekey_id !== localSignedPrekeyId) setStatus("Refreshing this desktop signed prekey");
    else if (localDeviceId && !currentDevice) setStatus("Sync this desktop device before decrypting or sending");
    else if (myDevices.length === 0) setStatus("Open the desktop app to activate this device");
    else if (activeConversation && activeRecipientUserIds.length === 0) setStatus("Open a contact chat before sending");
    else if (activeConversation && recipientDevices.length === 0) setStatus("Add a trusted contact device");
    else if (activeConversation && !recipientDevicesReady && recipientDevicesOnStaleBuild.length > 0) setStatus("Recipient device is on an older build - it must update before messages can be delivered");
    // Before "waiting for prekeys": a device held back for the user's decision
    // has its prekeys, and waiting will never change anything.
    else if (activeConversation && !recipientDevicesReady && recipientDevicesAwaitingApproval > 0) setStatus("Approve your contact's new device to send");
    else if (activeConversation && !recipientDevicesReady) setStatus("Waiting for recipient PQC prekeys");
    else if (recipientDevicesOnStaleBuild.length > 0) setStatus("Ready - some recipient devices are on an older build and are not being delivered to");
    else if (recipientDevicesMissingPrekeys) setStatus("Ready - some trusted devices need PQC prekeys");
    else setStatus("Ready");
  }, [activeConversation, activeRecipientUserIds.length, currentDevice, localDeviceId, localSignedPrekeyId, myDevices.length, rawLocalDevice, recipientDevices.length, recipientDevicesAwaitingApproval, recipientDevicesMissingPrekeys, recipientDevicesOnStaleBuild.length, recipientDevicesReady]);

  useEffect(() => {
    attachmentPreviewUrlsRef.current = attachmentPreviewUrls;
  }, [attachmentPreviewUrls]);

  useEffect(() => () => {
    Object.values(attachmentPreviewUrlsRef.current).forEach((url) => URL.revokeObjectURL(url));
  }, []);

  // Drop previews whose message is gone (burned, expired, deleted) or has been
  // re-locked. Without this the decrypted blob stays alive for the rest of the
  // session, which would let a view-once photo outlive the message that carried
  // it - the object URL keeps the plaintext reachable until it is revoked.
  useEffect(() => {
    const live = new Set(
      chatMessages.filter((item) => item.attachment).map((item) => item.client_message_id),
    );
    const stale = Object.keys(attachmentPreviewUrlsRef.current).filter((id) => !live.has(id));
    if (stale.length === 0) return;
    setAttachmentPreviewUrls((current) => {
      const next = { ...current };
      for (const id of stale) {
        if (next[id]) URL.revokeObjectURL(next[id]);
        delete next[id];
      }
      return next;
    });
  }, [chatMessages]);

  useEffect(() => {
    if (!lightbox) return;
    const stillLive = Object.values(attachmentPreviewUrls).includes(lightbox.url);
    if (!stillLive) setLightbox(null);
  }, [attachmentPreviewUrls, lightbox]);

  useEffect(() => {
    if (!lightbox) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setLightbox(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lightbox]);

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

  /** The other participant of a direct conversation (drives its avatar). */
  function conversationPeerUserId(conversation: ConversationSummary): string | null {
    if (conversation.conversation_type !== "direct") return null;
    const contact = contacts.find((item) => conversation.member_user_ids.includes(item.contact_user_id));
    return contact?.contact_user_id
      ?? conversation.member_user_ids.find((memberId) => memberId && memberId !== userId)
      ?? null;
  }

  /**
   * Marker the Rust receive path puts on "this device no longer holds the key
   * this message was sealed to". Keep in sync with `RETIRED_PREKEY_MARKER` in
   * src-tauri/src/commands/messaging.rs.
   */
  const RETIRED_PREKEY_MARKER = "sealed to a retired device key";

  /**
   * A retired key is NOT a decryption failure, and rendering it as one is what
   * made a whole re-keyed history read as a broken cipher. It means the device
   * re-keyed after these messages were sealed — a reinstall, a rotation past
   * the legacy window, or the FIPS 203 cutover — so the private key that could
   * open them no longer exists anywhere. Nothing is wrong and nothing can be
   * retried; the message is simply not readable on this device, ever.
   */
  function isRetiredKeyError(message: string): boolean {
    return message.toLowerCase().includes(RETIRED_PREKEY_MARKER);
  }

  function describeMessageError(error: unknown): string {
    if (error instanceof Error) return error.message;
    if (typeof error === "string") return error;
    if (error && typeof error === "object") {
      const record = error as Record<string, unknown>;
      const message = record.message ?? record.error_description ?? record.error ?? record.details ?? record.hint;
      if (typeof message === "string" && message.trim()) {
        return typeof record.code === "string" && record.code ? `${message} (${record.code})` : message;
      }
      try {
        const serialized = JSON.stringify(error);
        if (serialized && serialized !== "{}") return serialized;
      } catch {
        // fall through to the generic message
      }
    }
    return "Unexpected error";
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
        originalSenderUserId(sourceRow, userId),
        sourceRow.recipient_user_id,
      ].filter(Boolean)));
      // History is only ever re-sealed to devices this device has accepted.
      // This path fills in ANY listed device that lacks a copy, so without the
      // gate a device the directory added would be handed the whole thread.
      const participantCandidates = await loadTrustedDevicesForUsers(participantUserIds);
      const participantDevices = selectDeliveryDevicesForUsers(
        participantCandidates,
        participantUserIds,
        localDeviceId,
        MESSAGE_DELIVERY_POLICY,
        pinGate(await refreshDevicePins(participantCandidates)),
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
            sync_original_sender_user_id: originalSenderUserId(sourceRow, userId),
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

  async function hydrateMessageRows(
    rows: MessageEnvelopeRow[],
    userStates: Map<string, MessageUserState>,
    onPartial?: (messages: ChatMessage[]) => void,
    timeline?: Timeline,
  ): Promise<ChatMessage[]> {
    // Before anything is decrypted: every row must sit where its envelope was
    // signed to be. A genuine envelope copied into a new row (a replay), or
    // into another conversation, verifies perfectly on its own — only its
    // position gives it away. Refused rows are never shown.
    const screening = screenEnvelopeRows(rows.filter((row) => !row.deleted_at));
    const newlyRefused = screening.rejected.filter(({ row }) => !reportedRejectedRowsRef.current.has(row.id));
    if (newlyRefused.length > 0) {
      newlyRefused.forEach(({ row }) => reportedRejectedRowsRef.current.add(row.id));
      console.warn(
        "[secure-chat] Ignored envelope rows that do not match what their sender signed:",
        newlyRefused.map(({ row, reason }) => ({ id: row.id, reason })),
      );
      setMessageAction(describeRejectedEnvelopes(screening.rejected.length));
      void recordCryptoTelemetry({
        userId,
        deviceId: currentDevice?.device_id ?? null,
        scope: "message",
        stage: "message_integrity_rejected",
        detail: "Envelope rows refused: they do not match the identity their sender signed",
        progress: 0,
        status: "failed",
        metadata: {
          conversation_id: rows[0]?.conversation_id ?? null,
          refused: newlyRefused.length,
          envelope_ids: newlyRefused.map(({ row }) => row.id).join(","),
          reasons: Array.from(new Set(newlyRefused.map(({ reason }) => reason))).join(","),
        },
      }).catch(() => undefined);
    }

    const groups = new Map<string, MessageEnvelopeRow[]>();
    screening.accepted.forEach((row) => {
      const groupId = messageGroupId(row);
      groups.set(groupId, [...(groups.get(groupId) ?? []), row]);
    });

    const hydrated: ChatMessage[] = [];
    const controls: Array<SecureControlMessage & { sender_user_id: string; created_at: string }> = [];
    const decryptDeviceId = localDeviceId ?? currentDevice?.device_id ?? null;

    // One batched lookup for every sender in this page of history, so each
    // decrypt below can hand the backend the identity it must match the
    // envelope's signing keys against. Best-effort: a failure here degrades
    // messages to "sender unverified", never to undecryptable.
    //
    // Normally free: `primeSenderIdentitiesForConversation` has already warmed
    // these ids concurrently with the envelope fetch, so this resolves from the
    // session cache without touching the network. It can still cost a round
    // trip when a peer has registered a device this client has never seen, so
    // it is bounded — a sender anchor is worth a short wait (it decides
    // "Verified" vs "Sender unverified") but never worth holding the whole
    // thread behind. Past the bound the page renders and the next reload, by
    // then primed, upgrades the badges.
    await Promise.race([
      primeSenderIdentities(
        screening.accepted.map((row) => buildTauriEnvelope(row).sender_device_id),
      ).catch(() => undefined),
      new Promise((resolve) => window.setTimeout(resolve, SENDER_IDENTITY_PRIME_BUDGET_MS)),
    ]);

    // Controls (edits/reactions) are re-applied on every partial flush; both
    // operations are idempotent per (actor, target), so repeats are safe.
    const applyControlsAndSort = (): ChatMessage[] => {
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
      return [...hydrated].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
    };

    const hydrateGroup = async (groupId: string, groupRows: MessageEnvelopeRow[]): Promise<void> => {
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
      const isMine = originalSenderUserId(displayRow, userId) === userId;
      const state = userStates.get(groupId);
      const cachedControl = decryptedControlCacheRef.current.get(groupId);
      if (cachedControl) {
        controls.push(cachedControl);
        return;
      }
      const cached = decryptedMessageCacheRef.current.get(groupId);
      if (cached) {
        if (!isMine && (cached.read_once || cached.view_once) && state?.first_read_at) return;
        hydrated.push({
          ...cached,
          row_ids: orderedRows.map((row) => row.id),
          can_delete: isMine,
        });
        return;
      }

      if (decryptRows.length > 0) {
        let lastDecryptError: string | null = null;
        let handledGroup = false;
        for (const localRow of decryptRows) {
          try {
          const decryptKey = `${groupId}:${localRow.id}`;
          let decryptedPromise = decryptInFlightRef.current.get(decryptKey);
          if (!decryptedPromise) {
            // Bounded wait: one message decrypt is fixed-size crypto, so it can
            // never legitimately take this long. Un-timed, a single stalled
            // round-trip (the global Rust `key_scope` mutex serializes every
            // key operation) hangs the whole `Promise.all` chunk, so
            // `hydrateMessageRows` never returns and the load's `finally` never
            // clears `messagesLoading` — the "Loading encrypted history..."
            // hang. On timeout the group falls through to the normal decrypt
            // failure path and renders as a failed bubble instead.
            const tauriEnvelope = buildTauriEnvelope(localRow);
            decryptedPromise = invokeWithTimeout<DecryptedChatEnvelope>("messaging_receive_encrypted_message", {
              envelope: tauriEnvelope,
              senderIdentity: senderIdentityCache.get(tauriEnvelope.sender_device_id) ?? null,
            }, DECRYPT_TIMEOUT_MS);
            decryptInFlightRef.current.set(decryptKey, decryptedPromise);
            decryptedPromise.finally(() => {
              if (decryptInFlightRef.current.get(decryptKey) === decryptedPromise) {
                decryptInFlightRef.current.delete(decryptKey);
              }
            }).catch(() => undefined);
          }
          const decrypted = await decryptedPromise;
          const localRowSenderUserId = originalSenderUserId(localRow, userId);
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
            // Expired attachments: the storage path only exists inside the
            // decrypted plaintext, so the sender's client is the one place the
            // ciphertext blob can be cleaned up once the message expires.
            const expiredPath = secureMessage.attachment?.storage_path;
            if (isExpired && localRowIsMine && expiredPath && !expiredAttachmentCleanupRef.current.has(expiredPath)) {
              expiredAttachmentCleanupRef.current.add(expiredPath);
              void supabase.storage.from("messaging-files").remove([expiredPath]).catch(() => undefined);
            }
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
            sender_unapproved: decrypted.sender_verification === "unapproved_device",
            // Checked, not assumed: this row's id and conversation are the ones
            // the sender signed, so it is not a copy of an older envelope.
            replay_protected: screening.positionVerified.has(localRow.id),
            kem_combiner: String(hybridCiphertextFromSealed(localRow.sealed_sender_envelope).suite.kem_combiner ?? ""),
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
        if (handledGroup) return;
        const failedRow = decryptRows[0];
        const failedRowSenderUserId = originalSenderUserId(failedRow, userId);
        const retiredKey = Boolean(lastDecryptError && isRetiredKeyError(lastDecryptError));
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
            status: retiredKey ? "retired" : "failed",
            authenticated: false,
            replay_protected: false,
            created_at: failedRow.created_at,
            error: retiredKey
              ? "Encrypted to a key this device has since replaced. Nothing can recover it here."
              : lastDecryptError ?? "No decryptable trusted-device envelope could be recovered locally.",
            can_delete: failedRowSenderUserId === userId,
          });
      } else if (isMine) {
        // Suppress the noisy "Sent encrypted message — Syncing…" stub for our own
        // older messages that have no envelope sealed for this device yet.
        // Trusted-device sync rewraps a decryptable copy, after which the real
        // message renders normally; until then we render nothing rather than a
        // confusing placeholder bubble.
      } else if (userRow) {
        const sealedReason = decryptDeviceId
          ? "Waiting for trusted-device synchronization. No sender resend is required once a device with message access comes online."
          : "No local desktop private key is active. Sign in with the QGuard desktop app to sync trusted devices.";
        hydrated.push({
          id: userRow.id,
          client_message_id: groupId,
          row_ids: orderedRows.map((row) => row.id),
          conversation_id: userRow.conversation_id,
          sender_user_id: originalSenderUserId(userRow, userId),
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
    };

    // Newest-first, bounded-parallel hydration. The visible tail of the
    // conversation decrypts and flushes to the UI first, and up to `chunkSize`
    // envelope decrypts overlap instead of serializing one Tauri round-trip at
    // a time — this is what turned "Loading encrypted history..." from tens of
    // seconds into a progressive render. Chunk size stays modest so parallel
    // decrypts don't monopolize the Rust async worker pool.
    const entries = [...groups.entries()].sort((a, b) => {
      const newest = (list: MessageEnvelopeRow[]) =>
        list.reduce((max, row) => Math.max(max, new Date(row.created_at).getTime()), 0);
      return newest(b[1]) - newest(a[1]);
    });
    // The FIRST chunk is deliberately smaller than the rest. Time-to-first-paint
    // is what the user experiences as "did it load?", and it is gated on the
    // slowest decrypt in the first chunk — so a narrow first chunk paints the
    // newest messages sooner, after which wider chunks give better throughput
    // for the rest of the page.
    const firstChunkSize = 3;
    const chunkSize = 8;
    if (timeline) markTimeline(timeline, HISTORY_STAGES.decryptStart, performance.now());
    let index = 0;
    let isFirstChunk = true;
    while (index < entries.length) {
      const take = isFirstChunk ? firstChunkSize : chunkSize;
      const chunk = entries.slice(index, index + take);
      await Promise.all(chunk.map(([groupId, groupRows]) => hydrateGroup(groupId, groupRows)));
      index += take;
      isFirstChunk = false;
      if (onPartial && index < entries.length) onPartial(applyControlsAndSort());
    }
    if (timeline) markTimeline(timeline, HISTORY_STAGES.decryptComplete, performance.now());

    return applyControlsAndSort();
  }

  // Returns true when a NEW read was actually recorded, so the caller can
  // refresh the unread badges exactly once per real change (not on every
  // idempotent reload). Keyed to an explicit conversationId — never the live
  // `activeConversation` — so a conversation switch mid-load can't misroute the
  // write to the wrong thread.
  async function persistMessageUserStates(
    messages: ChatMessage[],
    existingStates: Map<string, MessageUserState> | undefined,
    conversationId: string,
  ): Promise<boolean> {
    if (!conversationId) return false;
    const readAt = new Date().toISOString();
    const entries = messages
      .map((item) => {
        // Read/verification semantics live in the pure `deriveReadState` helper
        // (unit-tested in chat-read-state.test.ts): peer rows — including
        // undecryptable "failed"/"sealed" stubs — are marked read so they can't
        // hold the unread badge hostage; own rows and unopened view-once
        // attachments are not; and an already-recorded read is preserved.
        // Only rows whose persisted state actually CHANGED are written: writing
        // unchanged rows (just bumping updated_at) re-fired this client's own
        // messaging_message_user_states realtime subscription — a write-on-read
        // feedback loop that kept the chat re-decrypting and starved sends. The
        // `newRead` flag (null -> timestamp) is what tells the caller to refresh
        // the unread badges, and only once per genuine read.
        const existing = existingStates?.get(item.client_message_id);
        const { nextReadAt, nextVerification, changed, newRead } = deriveReadState(
          {
            senderUserId: item.sender_user_id,
            viewOnce: item.view_once,
            hasAttachment: Boolean(item.attachment),
            status: item.status,
            authenticated: item.authenticated,
            threatScore: item.threat.score,
          },
          existing
            ? { firstReadAt: existing.first_read_at, verificationState: existing.verification_state, threatScore: existing.threat_score }
            : undefined,
          userId,
          readAt,
        );
        return {
          changed,
          newRead,
          row: {
            user_id: userId,
            conversation_id: conversationId,
            client_message_id: item.client_message_id,
            first_read_at: nextReadAt,
            verification_state: nextVerification,
            threat_score: item.threat.score,
            threat_flags: item.threat.flags,
            proof: {
              suite: "X25519 + ML-KEM-1024, HKDF-SHA3-256, AES-256-GCM, Ed25519 + ML-DSA-65",
              replay_protected: item.replay_protected,
              local_only_plaintext: true,
            },
            updated_at: readAt,
          },
        };
      });
    const rows = entries.filter((entry) => entry.changed).map((entry) => entry.row);
    const recordedNewRead = entries.some((entry) => entry.changed && entry.newRead);
    let wroteNewRead = false;
    if (rows.length > 0) {
      const { error } = await supabase
        .from("messaging_message_user_states")
        .upsert(rows, { onConflict: "user_id,conversation_id,client_message_id" });
      if (error) {
        // Surface instead of swallowing: a silently-rejected read write is
        // exactly what leaves the unread bubble stuck after a thread is read.
        console.warn("[secure-chat] Failed to persist message read states:", error.message);
      } else {
        wroteNewRead = recordedNewRead;
      }
    }

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
    return wroteNewRead;
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
        // Same rule as deriveReadState: an unanchored sender is "pending"
        // (proof absent), never "tampered" (proof failed).
        verification_state: chatMessage.authenticated ? "valid" : "pending",
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
    // Opening a view-once attachment is its read event — refresh so the unread
    // badges drop this message immediately.
    onSent();
  }

  const loadConversationMessages = useCallback(async () => {
    if (!activeConversationLoadId) {
      messageLoadSeqRef.current += 1;
      setChatMessages([]);
      return;
    }

    // Bind read-state persistence to the conversation THIS load is for, so a
    // fast switch to another thread can't misroute the "mark read" write.
    const conversationForLoad = activeConversationLoadId;
    const loadSeq = ++messageLoadSeqRef.current;
    const timeline = createTimeline("history", conversationForLoad, performance.now());
    markTimeline(timeline, HISTORY_STAGES.loadStart, performance.now());
    setMessageAction(null);

    // Paint from memory FIRST, then reconcile with the backend.
    //
    // This is the structural fix for the "Loading encrypted history..." hang.
    // Rendering used to be a precondition of the network: nothing appeared
    // until a 250-envelope fetch and a page of decrypts had both finished, so
    // every stalled round trip was indistinguishable from a broken app. A
    // thread that was already decrypted in this session is re-shown
    // immediately, the spinner is never raised over content the user can
    // already read, and the fetch below becomes a background refresh whose
    // slowness is invisible.
    const cachedThread = chatHistorySnapshot<ChatMessage>(conversationForLoad);
    if (cachedThread !== null) {
      // Non-destructive on purpose. This loader also runs for every realtime
      // reload of the conversation already on screen, and by then the thread
      // can legitimately hold things the snapshot does not — above all the
      // optimistic echo of a message just sent. Overwriting would make that
      // message vanish and reappear on every incoming event. So the snapshot
      // fills an EMPTY pane (the "Loading encrypted history..." case this is
      // here to eliminate) and never overwrites a populated one; the fetch
      // below is what reconciles a populated thread.
      setChatMessages((current) => (current.length > 0 ? current : cachedThread));
      setMessagesLoading(false);
      markTimeline(timeline, HISTORY_STAGES.cacheRendered, performance.now());
      markTimeline(timeline, HISTORY_STAGES.rendered, performance.now());
    } else {
      setMessagesLoading(true);
    }
    describeTimeline(timeline, { cache: cachedThread !== null });

    // Warm the sender anchors concurrently with the fetch, from the device
    // registry this client already has. Priming used to run only AFTER the
    // envelopes arrived, which put a second serial network round trip in front
    // of the first paint; the senders in a conversation are its members'
    // devices, which are already known here, so the post-fetch prime is
    // normally a cache hit costing nothing.
    const identityPrewarm = prewarmSenderIdentities();

    try {
      markTimeline(timeline, HISTORY_STAGES.fetchStart, performance.now());
      const bodyCache = envelopeBodyCacheRef.current;
      bodyCache.bind(conversationForLoad);
      // The listing: which envelopes exist, and whom each is sealed to. A few
      // kilobytes, so it stays cheap on every realtime reload. The bodies are
      // fetched below, and only the ones this session does not hold yet.
      const [{ data, error }, statesResult] = await Promise.all([
        withFetchRetry(() => queryWithDeadline((signal) => supabase
          .from("messaging_message_envelopes")
          .select(ENVELOPE_INDEX_COLUMNS)
          .eq("conversation_id", conversationForLoad)
          .is("deleted_at", null)
          // Newest 250 — ascending+limit returned the OLDEST page, so long
          // conversations could never even see their recent messages.
          .order("created_at", { ascending: false })
          .limit(250)
          .abortSignal(signal), HISTORY_FETCH_TIMEOUT_MS, "encrypted history listing")),
        withFetchRetry(() => queryWithDeadline((signal) => supabase
          .from("messaging_message_user_states")
          .select("client_message_id,first_read_at,hidden_at,verification_state,threat_score,threat_flags")
          .eq("conversation_id", conversationForLoad)
          .eq("user_id", userId)
          .abortSignal(signal), HISTORY_FETCH_TIMEOUT_MS, "read-state fetch"))
          // Read state decides badges and burn-on-read timing, not whether a
          // message can be shown. Losing it must degrade the thread, never
          // block it.
          .catch((stateError) => ({ data: null, error: stateError })),
      ]);
      if (error) throw error;
      const index = ((data ?? []) as unknown as Array<Record<string, unknown>>).map(envelopeIndexEntry);

      const fetchBodies = async (ids: string[]): Promise<void> => {
        const { data: bodyData, error: bodyError } = await withFetchRetry(() => queryWithDeadline((signal) => supabase
          .from("messaging_message_envelopes")
          .select(ENVELOPE_BODY_COLUMNS)
          .in("id", ids)
          .abortSignal(signal), HISTORY_BODY_TIMEOUT_MS, "encrypted history fetch"));
        if (bodyError) throw bodyError;
        bodyCache.store(conversationForLoad, ((bodyData ?? []) as unknown as Array<Record<string, unknown>>).map((row) => ({
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
        } satisfies MessageEnvelopeRow)));
      };

      const stateRows = statesResult.error ? [] : (statesResult.data ?? []) as Array<Record<string, unknown>>;
      const userStates = new Map(stateRows.map((row) => [String(row.client_message_id), {
        client_message_id: String(row.client_message_id),
        first_read_at: row.first_read_at ? String(row.first_read_at) : null,
        hidden_at: row.hidden_at ? String(row.hidden_at) : null,
        verification_state: String(row.verification_state ?? "pending") as MessageUserState["verification_state"],
        threat_score: Number(row.threat_score ?? 0),
        threat_flags: Array.isArray(row.threat_flags) ? row.threat_flags.map(String) : [],
      } satisfies MessageUserState]));
      // Progressive render: each decrypted chunk flushes to the screen
      // immediately (newest messages first) instead of holding the whole
      // conversation behind one long "Loading encrypted history..." gate.
      const hydrateHeld = () => hydrateMessageRows(bodyCache.resolve(conversationForLoad, index), userStates, (partial) => {
        if (messageLoadSeqRef.current !== loadSeq) return;
        setChatMessages(partial);
        setMessagesLoading(false);
        markTimeline(timeline, HISTORY_STAGES.rendered, performance.now());
      }, timeline);

      // Bodies still to download: this device's copies first, then in small
      // parallel groups. The first chunk alone is enough to paint, so the
      // thread appears after one small request instead of after all of them.
      const pendingChunks = planBodyFetch(
        index,
        (id) => bodyCache.has(id),
        { userId, deviceId: localDeviceId ?? currentDevice?.device_id ?? null },
      );
      const stages: string[][][] = pendingChunks.length > 0 ? [[pendingChunks[0]]] : [];
      for (let start = 1; start < pendingChunks.length; start += HISTORY_BODY_PARALLEL_REQUESTS) {
        stages.push(pendingChunks.slice(start, start + HISTORY_BODY_PARALLEL_REQUESTS));
      }
      let bodyFetchError: unknown = null;
      for (let stage = 0; stage < stages.length; stage += 1) {
        const settled = await Promise.allSettled(stages[stage].map(fetchBodies));
        if (stage === 0) markTimeline(timeline, HISTORY_STAGES.fetchComplete, performance.now());
        const failure = settled.find((result): result is PromiseRejectedResult => result.status === "rejected");
        if (failure) {
          // Stop at the first failed group: what has arrived is shown, and the
          // next reload asks only for what is still missing.
          bodyFetchError = failure.reason;
          break;
        }
        // A newer load of this thread has started; it plans from what is held
        // now, so continuing here would download the same rows twice.
        if (messageLoadSeqRef.current !== loadSeq) break;
        if (stage < stages.length - 1) {
          if (stage === 0) await identityPrewarm;
          const partial = await hydrateHeld();
          if (messageLoadSeqRef.current === loadSeq) setChatMessages(partial);
        }
      }
      if (stages.length === 0) markTimeline(timeline, HISTORY_STAGES.fetchComplete, performance.now());
      await identityPrewarm;

      const rows = bodyCache.resolve(conversationForLoad, index);
      if (bodyFetchError) {
        // Nothing at all to show is a failed load. Anything less is a partial
        // one: show it rather than hide readable messages behind an error.
        if (rows.length === 0) throw bodyFetchError;
        console.warn("[secure-chat] Part of the encrypted history has not arrived yet:", bodyFetchError);
      }
      // Watermark for the idle catch-up probe: the newest envelope this load
      // actually holds. The probe compares against it, so a reload runs when
      // the server has something newer — including a row that failed to
      // download just now.
      if (conversationForLoad === activeConversationIdRef.current) {
        newestEnvelopeAtRef.current = rows.reduce(
          (newest, row) => (row.created_at > newest ? row.created_at : newest),
          "",
        );
      }
      const hydrated = await hydrateHeld();
      // Only the current load may repaint the thread, so a slow earlier load
      // can never overwrite the conversation now on screen.
      if (messageLoadSeqRef.current === loadSeq) {
        setChatMessages(hydrated);
        markTimeline(timeline, HISTORY_STAGES.rendered, performance.now());
      }
      // Remember the rendered thread so reopening this conversation — or a
      // realtime reload of it — paints instantly instead of waiting on the
      // network again. Recorded even when this load lost the repaint race: it
      // is still the freshest decrypted view of `conversationForLoad`, and the
      // conversation now on screen keeps its own snapshot.
      setChatHistorySnapshot(conversationForLoad, hydrated);
      describeTimeline(timeline, { rows: rows.length, messages: hydrated.length });
      // Read-state persistence is deliberately NOT gated on winning that repaint
      // race. These messages were decrypted and shown for `conversationForLoad`,
      // so they are genuinely read — recording that is what clears the unread
      // bubbles. Because the write is keyed to the load's own conversation id, a
      // same-conversation realtime reload can't drop the read and a switch can't
      // misroute it. When a NEW read is recorded, refresh the dashboard so the
      // unread badges (conversation list, sidebar, and top-bar bell) clear
      // immediately instead of waiting for the next realtime tick or 30s poll.
      try {
        const recordedNewRead = await persistMessageUserStates(hydrated, userStates, conversationForLoad);
        if (recordedNewRead) onSent();
      } catch (persistError) {
        console.warn("[secure-chat] Read-state persistence failed:", persistError);
      }
    } catch (error) {
      // The realtime subscription reloads on every envelope change, so a transient
      // reload failure must not flash a banner over an already-rendered conversation;
      // the next realtime tick retries. Surface it only when there is nothing to show.
      if (messageLoadSeqRef.current !== loadSeq) {
        publishTimeline(completeTimeline(timeline, "abandoned", performance.now()));
        return;
      }
      console.error("[secure-chat] Failed to load conversation messages:", error);
      completeTimeline(timeline, "error", performance.now());
      describeTimeline(timeline, { error: error instanceof Error ? error.message : String(error) });
      if (decryptedMessageCacheRef.current.size === 0 && decryptedControlCacheRef.current.size === 0) {
        setMessageAction(describeMessageError(error));
      }
    } finally {
      if (messageLoadSeqRef.current === loadSeq) setMessagesLoading(false);
      publishTimeline(completeTimeline(
        timeline,
        messageLoadSeqRef.current === loadSeq ? "ok" : "abandoned",
        performance.now(),
      ));
    }
    // Deliberately keyed on the conversation ID (a string), never the
    // conversation OBJECT. The dashboard refresh that follows every send and
    // every live event rebuilds `conversations` — and `effectiveConversations`
    // spreads each row into a fresh object — so the object identity changed
    // constantly. That re-created this callback, which re-fired the load effect
    // (a full 250-envelope re-fetch) AND tore down + re-subscribed the realtime
    // channel below, losing any insert that landed in the gap. Keying on the id
    // makes both effects stable for the lifetime of the open conversation.
  }, [activeConversationLoadId, currentDevice?.device_id, localDeviceId, localSignedPrekeyId, userId, onSent, prewarmSenderIdentities]);

  // Switching conversations must instantly show a clean slate. Clearing in a
  // layout effect (keyed on the conversation id, so it only fires on a real
  // switch — not on the realtime reloads of the same chat) wipes the previous
  // chat's messages before the browser paints, so no other user's history is
  // ever shown in a different conversation.
  useLayoutEffect(() => {
    const switchingTo = activeConversation?.id ?? null;
    // Seed the incoming thread from its own snapshot in the SAME layout effect
    // that wipes the outgoing one, so switching between warm conversations
    // never flashes an empty pane or a spinner. Only this conversation's own
    // snapshot is ever used, so no other thread's plaintext can be shown here.
    const warm = switchingTo ? chatHistorySnapshot<ChatMessage>(switchingTo) : null;
    setChatMessages(warm ?? []);
    setMessageAction(null);
    decryptInFlightRef.current.clear();
    setMessagesLoading(Boolean(activeConversation) && warm === null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeConversation?.id]);

  useEffect(() => {
    loadConversationMessages();
  }, [loadConversationMessages]);

  /**
   * Watchdog: "Loading encrypted history..." must never be a terminal state.
   *
   * Every step of the load is individually bounded now, but bounded steps still
   * compose — a retried fetch followed by a page of slow decrypts can
   * legitimately run long, and a bug in any future step could run longer. This
   * makes "stuck forever" unrepresentable rather than merely unlikely: past the
   * deadline with nothing on screen, the UI stops claiming that loading is all
   * that is happening and one automatic recovery attempt is made.
   *
   * It deliberately does NOT cancel the in-flight load. That load may still be
   * making progress and will paint the moment it lands; cancelling would throw
   * away work and could turn a slow success into a guaranteed failure. The
   * retry counter resets as soon as anything renders, so a thread that
   * recovers on its own leaves no trace.
   */
  const historyAutoRetriesRef = useRef(0);
  useEffect(() => {
    if (!messagesLoading || chatMessages.length > 0) {
      setHistoryStalled(false);
      historyAutoRetriesRef.current = 0;
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setHistoryStalled(true);
      if (historyAutoRetriesRef.current >= 1) return;
      historyAutoRetriesRef.current += 1;
      console.warn("[secure-chat] History render deadline exceeded; retrying load.");
      void loadConversationMessages();
    }, HISTORY_RENDER_DEADLINE_MS);
    return () => window.clearTimeout(timer);
  }, [messagesLoading, chatMessages.length, loadConversationMessages]);

  useEffect(() => {
    const conversationId = activeConversationLoadId;
    if (!conversationId) return undefined;
    // Coalesce realtime bursts into ONE reload per window. Every envelope insert
    // (a send writes one per recipient device) and every read-state write (ours
    // AND the peer's — the filter is conversation-scoped) previously triggered a
    // full re-fetch. When both users were in the chat the read-state ping-pong
    // fired reloads faster than a load could finish, and each new load superseded
    // the previous one before it set `chatMessages` — so the view was pinned on
    // "Loading encrypted history..." forever. Throttling lets a reload complete
    // before the next starts, and collapses the post-send churn to a single tick.
    let disposed = false;
    let reloadTimer: number | undefined;
    let channel: ReturnType<typeof supabase.channel> | null = null;
    let resubscribeTimer: number | undefined;
    let idlePollTimer: number | undefined;
    let attempts = 0;

    const scheduleReload = (delayMs = 500) => {
      if (disposed || reloadTimer !== undefined) return;
      reloadTimer = window.setTimeout(() => {
        reloadTimer = undefined;
        loadConversationMessages();
      }, delayMs);
    };

    const open = () => {
      if (disposed) return;
      if (channel) {
        const previous = channel;
        channel = null;
        void supabase.removeChannel(previous);
      }
      // Unique channel name per attempt: re-subscribing an object the server
      // already closed silently never rejoins.
      const next = supabase
        .channel(`qguard-chat-messages-${conversationId}-${crypto.randomUUID()}`)
        .on(
          "postgres_changes",
          { event: "*", schema: "public", table: "messaging_message_envelopes", filter: `conversation_id=eq.${conversationId}` },
          (payload) => {
            // A message its sender just deleted: destroy this device's recorded
            // key for it now, not only stop listing it. (Deletions that happen
            // while this screen is closed are reconciled by prekey-hygiene.)
            const deletedId = deletedEnvelopeId(payload);
            if (deletedId) {
              void safeInvoke<number>("messaging_forget_message_keys", { userId, messageIds: [deletedId] }, 0);
            }
            scheduleReload();
          },
        )
        .on(
          "postgres_changes",
          { event: "*", schema: "public", table: "messaging_message_user_states", filter: `conversation_id=eq.${conversationId}` },
          () => scheduleReload(),
        );
      channel = next;
      next.subscribe((status) => {
        if (disposed || channel !== next) return;
        if (status === "SUBSCRIBED") {
          attempts = 0;
          // Pull anything written while the channel was down — postgres_changes
          // has no replay, so without this the messages that landed during a
          // suspend/reconnect would only appear on the next unrelated event.
          scheduleReload(0);
          return;
        }
        if (status === "CHANNEL_ERROR" || status === "TIMED_OUT" || status === "CLOSED") {
          attempts += 1;
          if (resubscribeTimer !== undefined) window.clearTimeout(resubscribeTimer);
          resubscribeTimer = window.setTimeout(open, Math.min(15_000, 1_000 * 2 ** Math.min(4, attempts)));
        }
      });
    };

    // Android suspends the WebView socket when the app is backgrounded and the
    // screen turns off; on resume the channel is often dead with no event to
    // prove it. Re-open and re-read on every return to the foreground.
    const onResume = () => {
      if (disposed) return;
      if (document.visibilityState !== "visible") {
        // Heading to the background, where Android may end the process without
        // warning: write out the message keys recorded since the last save.
        void safeInvoke<boolean>("messaging_flush_message_keys", { userId }, false);
        return;
      }
      open();
      scheduleReload(0);
    };
    document.addEventListener("visibilitychange", onResume);
    window.addEventListener("online", onResume);

    // Belt-and-suspenders catch-up: the channel can look SUBSCRIBED forever
    // while the underlying socket is actually dead, so this is the only thing
    // that bounds how long a delivered-but-unseen message stays invisible when
    // no status change and no visibility/online event ever fires.
    //
    // Deliberately a CHEAP probe, not a blind reload: one indexed single-row
    // read of the newest envelope, and the expensive 250-row reload runs only
    // when that is actually newer than what the thread already has. A blind
    // periodic reload would add constant background cost to the very screen
    // this is meant to make faster.
    const probeForNewMessages = async () => {
      if (disposed || document.visibilityState !== "visible") return;
      try {
        const { data, error } = await supabase
          .from("messaging_message_envelopes")
          .select("created_at")
          .eq("conversation_id", conversationId)
          .order("created_at", { ascending: false })
          .limit(1);
        if (error || disposed || conversationId !== activeConversationIdRef.current) return;
        const newest = data?.[0]?.created_at ? String(data[0].created_at) : "";
        // Empty watermark means the thread has not completed a load yet; let
        // that load finish rather than racing another one against it.
        if (newest && newestEnvelopeAtRef.current && newest > newestEnvelopeAtRef.current) {
          scheduleReload(0);
        }
      } catch {
        // Offline/transient: the next tick retries. Never throw into the timer.
      }
    };
    idlePollTimer = window.setInterval(() => void probeForNewMessages(), CHAT_IDLE_POLL_MS);

    open();

    return () => {
      disposed = true;
      document.removeEventListener("visibilitychange", onResume);
      window.removeEventListener("online", onResume);
      if (reloadTimer !== undefined) window.clearTimeout(reloadTimer);
      if (resubscribeTimer !== undefined) window.clearTimeout(resubscribeTimer);
      if (idlePollTimer !== undefined) window.clearInterval(idlePollTimer);
      if (channel) void supabase.removeChannel(channel);
    };
  }, [activeConversationLoadId, loadConversationMessages, userId]);

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

  // Disappearing messages must not leave ciphertext at rest: hard-delete
  // expired envelope rows server-side once per chat session (best-effort —
  // the migration may not be applied yet).
  useEffect(() => {
    supabase.rpc("purge_expired_messaging_envelopes").then(() => undefined, () => undefined);
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
    const conversationId = activeConversationIdRef.current;
    if (!conversationId) {
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
      .eq("conversation_id", conversationId)
      .neq("user_id", userId)
      .eq("is_typing", true)
      .gt("expires_at", new Date().toISOString());
    if (error) return;
    setTypingIndicators(((data ?? []) as Array<Record<string, unknown>>).map((row) => ({
      user_id: String(row.user_id),
      device_id: row.device_id ? String(row.device_id) : null,
      expires_at: String(row.expires_at),
    } satisfies TypingIndicator)));
    // Reads the conversation id from a ref rather than depending on the
    // conversation OBJECT: this callback gates the typing/telemetry realtime
    // channel below, and depending on the object tore that channel down and
    // re-subscribed it on every dashboard refresh — socket churn competing with
    // the message and call-signal channels on the same connection.
  }, [userId]);

  useEffect(() => {
    loadChatTelemetry();
  }, [loadChatTelemetry]);

  useEffect(() => {
    loadTypingIndicators();
  }, [loadTypingIndicators]);

  useEffect(() => {
    if (!activeConversationLoadId) return undefined;
    const channel = supabase
      .channel(`qguard-chat-security-${activeConversationLoadId}-${userId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "messaging_typing_indicators", filter: `conversation_id=eq.${activeConversationLoadId}` }, loadTypingIndicators)
      .on("postgres_changes", { event: "*", schema: "public", table: "messaging_crypto_telemetry", filter: `user_id=eq.${userId}` }, loadChatTelemetry)
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [activeConversationLoadId, loadChatTelemetry, loadTypingIndicators, userId]);

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
    const runners: Array<() => PromiseLike<{ data: unknown; error: unknown }>> = [
      () => supabase.from("profiles").select(columns).neq("id", userId).ilike("username", `${escaped}%`).limit(10),
      () => supabase.from("profiles").select(columns).neq("id", userId).ilike("name", `${escaped}%`).limit(10),
      () => supabase.from("profiles").select(columns).neq("id", userId).ilike("email", `${escaped}%`).limit(10),
    ];
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(normalized)) {
      runners.unshift(() => supabase.from("profiles").select(columns).eq("id", normalized).limit(1));
    }
    const results = await Promise.allSettled(runners.map((run) => withFetchRetry(() => Promise.resolve(run()))));
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
      const { data, error } = await withFetchRetry(() => Promise.resolve(supabase.rpc("search_messaging_users", { p_query: normalized })));
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
      const fallbackResults = await fallbackSearchProfiles(trimmed).catch(() => [] as UserSearchResult[]);
      setSearchResults(fallbackResults);
      if (fallbackResults.length > 0) {
        setSearchFeedback(null);
      } else {
        setSearchFeedback(isTransientNetworkError(err) ? DIRECTORY_UNREACHABLE_MESSAGE : describeMessageError(err));
      }
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
      await withFetchRetry(() => ensureCurrentUserProfile());
      const { error } = await withFetchRetry(() => Promise.resolve(supabase.from("messaging_contacts").upsert({
        owner_user_id: userId,
        contact_user_id: result.user_id,
        alias: result.display_name,
        trust_state: "added",
        updated_at: new Date().toISOString(),
      }, { onConflict: "owner_user_id,contact_user_id" })));
      if (error) {
        setContactAction(error.message);
        return;
      }
    } catch (error) {
      setContactAction(isTransientNetworkError(error) ? DIRECTORY_UNREACHABLE_MESSAGE : describeMessageError(error));
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
    // Apply the change to the panel immediately, then reconcile with the server.
    setContactOverrides((previous) => ({ ...previous, [contact.id]: trustState }));
    const { error } = await supabase
      .from("messaging_contacts")
      .update({ trust_state: trustState, updated_at: new Date().toISOString() })
      .eq("id", contact.id);
    if (error) {
      // Roll back the optimistic change so the panel reflects real server state.
      setContactOverrides((previous) => {
        const next = { ...previous };
        delete next[contact.id];
        return next;
      });
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
    // Phone layout: tapping a conversation slides to the thread pane.
    setMobilePane("thread");
    setStatus("Private chat ready");
    logChatFlow("openConversation", { conversationId: thread.id, view: target });
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
      if (protectionDialog.conversationId) {
        setActiveConversationId(protectionDialog.conversationId);
        setMobilePane("thread");
      }
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
        setMobilePane("list");
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

  // Opens (or creates) the direct conversation with `contact` and navigates to
  // its thread. Returns true when the thread was opened, false when it could not
  // be (blocked contact, missing local/recipient keys, or an error) — the caller
  // uses this to decide whether to close the New Chat modal. Every failure path
  // sets a visible `contactAction` message and logs a breadcrumb, so a tap can
  // never fail silently or bounce the user back with no explanation.
  async function startPrivateChat(contact: ContactSummary): Promise<boolean> {
    if (contactChatBusyId) return false;

    setContactChatBusyId(contact.id);
    setContactAction(null);
    setStatus(`Opening private chat with ${visibleContactName(contact)}`);
    logChatFlow("startPrivateChat:begin", { contactUserId: contact.contact_user_id });

    try {
      if (contact.trust_state === "blocked") {
        setStatus("Unblock this contact before starting a chat");
        setContactAction(`${visibleContactName(contact)} is blocked. Restore the contact before opening chat.`);
        logChatFlow("startPrivateChat:blocked", { contactUserId: contact.contact_user_id });
        return false;
      }

      const existing = effectiveConversations.find((conversation) => conversation.member_user_ids.includes(contact.contact_user_id));
      if (existing) {
        openConversation(existing);
        setContactAction(`Opened chat with ${visibleContactName(contact)}.`);
        logChatFlow("startPrivateChat:openExisting", { conversationId: existing.id });
        return true;
      }

      if (myDevices.length === 0) {
        setStatus("Activate this device first");
        setContactAction("This account has no trusted device yet. Open QGuard Messaging on this device (or desktop) to publish its keys, then try again.");
        logChatFlow("startPrivateChat:noLocalDevice");
        return false;
      }

      const localDevices = localDeviceId
        ? (localDevice && isSendableDevice(localDevice) ? [localDevice] : [])
        : selectDeliveryDevicesForUsers(myDevices, [userId], localDeviceId);
      if (localDevices.length === 0) {
        setStatus("Local device is missing signed PQC prekeys");
        setContactAction("This device is still publishing its quantum-safe prekeys. Wait a moment, then try again.");
        logChatFlow("startPrivateChat:noLocalSendableDevice");
        return false;
      }

      const latestContactDevices = await loadContactDevices(contact);
      const fallbackDevices = devices.filter((device) => device.user_id === contact.contact_user_id && isTrustedDeviceForDelivery(device));
      const contactDevices = latestContactDevices.length > 0 ? latestContactDevices : fallbackDevices;
      const trustedContactDevices = contactDevices.filter(isTrustedDeviceForDelivery);
      const sendableContactDevices = selectDeliveryDevicesForUsers(trustedContactDevices, [contact.contact_user_id], localDeviceId);

      if (trustedContactDevices.length === 0) {
        setStatus("This contact has no trusted device yet");
        setContactAction(`${visibleContactName(contact)} has not set up a QGuard device yet. Ask them to sign in to QGuard Messaging (desktop or Android) so their quantum-safe keys are published, then try again.`);
        logChatFlow("startPrivateChat:recipientNoDevice", { contactUserId: contact.contact_user_id });
        await Promise.resolve(onSent());
        return false;
      }

      if (sendableContactDevices.length === 0) {
        setStatus("Waiting for recipient PQC prekeys");
        setContactAction(`${visibleContactName(contact)} has a device, but it has not published active PQC prekeys yet. Ask them to open QGuard Messaging once more, then try again.`);
        logChatFlow("startPrivateChat:recipientNoPrekeys", { contactUserId: contact.contact_user_id });
        await Promise.resolve(onSent());
        return false;
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

      logChatFlow("startPrivateChat:created", { conversationId });
      // Register the conversation in the optimistic overlay BEFORE selecting it,
      // so it is already present in the visible list when the "keep a valid
      // selection" effect runs — otherwise that effect would reset the selection
      // (the new row is not in the `conversations` prop until the async refresh
      // lands) and strand the user on the wrong thread.
      registerOptimisticConversation(conversationId, contact);
      setActiveConversationId(conversationId);
      setConversationView("active");
      setMobilePane("thread");
      setStatus("Private chat ready");
      setContactAction(`Private chat opened with ${visibleContactName(contact)}.`);
      await Promise.resolve(onSent());
      return true;
    } catch (error) {
      const detail = describeMessageError(error);
      setStatus(detail);
      setContactAction(detail);
      logChatFlow("startPrivateChat:error", { message: detail });
      return false;
    } finally {
      setContactChatBusyId(null);
    }
  }

  // Adds a minimal, immediately-usable conversation row to the optimistic
  // overlay so the thread resolves the recipient (and can send) the instant it
  // is created, before the server row round-trips back through the data hook.
  function registerOptimisticConversation(conversationId: string, contact: ContactSummary) {
    const optimistic: ConversationSummary = {
      id: conversationId,
      conversation_type: "direct",
      title: visibleContactName(contact),
      last_activity: "No encrypted messages yet",
      unread_count: 0,
      updated_at: new Date().toISOString(),
      member_user_ids: Array.from(new Set([userId, contact.contact_user_id])),
      archived_at: null,
      hidden_at: null,
      deleted_at: null,
    };
    setPendingConversations((current) => [optimistic, ...current.filter((conversation) => conversation.id !== conversationId)]);
  }

  function openNewChat() {
    setQuery("");
    setSearchResults([]);
    setSearchFeedback(null);
    setContactAction(null);
    setNewChatBusyId(null);
    setShowNewChat(true);
  }

  function closeNewChat() {
    setShowNewChat(false);
    setQuery("");
    setSearchResults([]);
    setSearchFeedback(null);
  }

  // One-motion "New Chat": add the person as a contact (so RLS lets us read
  // their published PQC prekeys) and immediately open the encrypted thread. The
  // modal is closed ONLY once the thread actually opens; if opening fails, the
  // modal stays open showing the reason (via `contactAction`) instead of
  // silently closing and dropping the user back on the list — the exact bounce
  // this flow used to produce.
  async function startChatWithUser(result: UserSearchResult) {
    if (newChatBusyId) return;
    setNewChatBusyId(result.user_id);
    setContactAction(null);
    logChatFlow("startChatWithUser:begin", { userId: result.user_id, username: result.username });
    try {
      await ensureCurrentUserProfile();
      const { data, error } = await supabase
        .from("messaging_contacts")
        .upsert({
          owner_user_id: userId,
          contact_user_id: result.user_id,
          alias: result.display_name,
          trust_state: "added",
          updated_at: new Date().toISOString(),
        }, { onConflict: "owner_user_id,contact_user_id" })
        .select("id,contact_user_id,alias,trust_state,created_at,updated_at")
        .single();
      if (error) throw error;

      const contact: ContactSummary = {
        id: String(data.id),
        contact_user_id: result.user_id,
        alias: result.display_name,
        display_name: result.display_name,
        username: result.username,
        trust_state: "added",
        created_at: String(data.created_at ?? new Date().toISOString()),
        updated_at: String(data.updated_at ?? new Date().toISOString()),
      };

      await Promise.resolve(onSent());
      const opened = await startPrivateChat(contact);
      if (opened) {
        closeNewChat();
      }
      logChatFlow("startChatWithUser:done", { userId: result.user_id, opened });
    } catch (error) {
      setContactAction(describeMessageError(error));
      logChatFlow("startChatWithUser:error", { message: describeMessageError(error) });
    } finally {
      setNewChatBusyId(null);
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
    const storagePath = `${userId}/chat-attachments/${activeConversation.id}/${clientMessageId}/${kind}-${Date.now()}.bin`;
    // Bind the ciphertext to the exact object it is stored as. Without AAD the
    // blob authenticates on its own merits and nothing ties it to the message
    // that announced it, so anyone with write access to the bucket could move a
    // ciphertext between paths. As AAD the path, conversation and message id are
    // inside the GCM tag: a relocated blob no longer opens.
    const aad = attachmentAad(storagePath, activeConversation.id, clientMessageId);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad) },
      key,
      toArrayBuffer(plaintext),
    ));
    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));

    await uploadChatAttachmentWithRetry(storagePath, new Blob([encrypted], { type: "application/qguard-chat-attachment" }));

    return {
      kind,
      storage_path: storagePath,
      aad_version: ATTACHMENT_AAD_VERSION,
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
    conversationIdForAttachment: string,
    messageIdForAttachment: string,
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
    // Attachments sealed before the AAD binding carry no `aad_version`, and must
    // still open — their ciphertext was produced without associated data, so
    // supplying any would break every one of them.
    const aadParams = attachment.aad_version === ATTACHMENT_AAD_VERSION
      ? { additionalData: toArrayBuffer(attachmentAad(attachment.storage_path, conversationIdForAttachment, messageIdForAttachment)) }
      : {};
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: toArrayBuffer(iv), ...aadParams }, key, toArrayBuffer(encrypted));
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
      const blob = await decryptAttachmentBlob(
        attachment,
        chatMessage.conversation_id,
        chatMessage.client_message_id,
        (stage, detail, progress, statusValue) => {
        stream.emit({
          stage,
          detail,
          progress,
          status: statusValue as "progress" | "verified",
          level: statusValue === "verified" ? "success" : "info",
        });
        },
      );
      const mediaKind = inlineMediaKind(attachment);
      let savedLine: string | null = null;
      if (mediaKind) {
        // Images, video and audio stay in memory as an object URL and render in
        // the conversation. They are NOT written to disk automatically: this is a
        // disappearing-message channel, and silently dropping plaintext copies of
        // every viewed photo into Downloads would outlive the message itself.
        // "Save" below is the deliberate way to keep one.
        setAttachmentPreviewUrls((current) => {
          if (current[chatMessage.client_message_id]) URL.revokeObjectURL(current[chatMessage.client_message_id]);
          return {
            ...current,
            [chatMessage.client_message_id]: URL.createObjectURL(blob),
          };
        });
        // Rendering it IS the view event - the rule the voice note already
        // followed ("listen once"), now applied to images and video too.
        await markViewOnceAttachmentOpened(chatMessage);
      } else {
        // Written to the device BEFORE the view-once burn: if the save fails,
        // the throw below leaves the message intact to try again.
        savedLine = describeSavedFile(await saveFileToDevice(attachment.name, blob));
        await markViewOnceAttachmentOpened(chatMessage);
      }
      stream.emit({
        stage: "attachment_decrypt_completed",
        detail: mediaKind ? "Decrypted locally - now visible in the conversation" : `Decrypted locally - ${savedLine}`,
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
      setStatus(mediaKind ? "Attachment decrypted - shown in the conversation" : `Attachment decrypted - ${savedLine}`);
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

  /**
   * Write an already-decrypted preview to disk on request. Reads the bytes back
   * out of the object URL instead of holding a second copy of the plaintext in
   * component state, and never re-downloads or re-decrypts the ciphertext.
   */
  async function saveDecryptedAttachment(chatMessage: ChatMessage) {
    const previewUrl = attachmentPreviewUrls[chatMessage.client_message_id];
    if (!previewUrl || !chatMessage.attachment) return;
    try {
      const response = await fetch(previewUrl);
      const saved = await saveFileToDevice(chatMessage.attachment.name, await response.blob());
      setStatus(describeSavedFile(saved));
    } catch (error) {
      setMessageAction(describeMessageError(error));
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
    // Use the already-loaded, realtime-maintained device list so a burst of
    // sends does not each block on a device query (a full network round-trip on
    // the critical path of every message). But re-read the authoritative list
    // when the cache is empty OR older than DEVICE_LIST_MAX_STALENESS_MS: a
    // device missing here never receives an envelope, and the peer cannot
    // recover a row that was never written for them.
    const recipientCacheKey = [...recipientUserIds].sort().join(",");
    const lastFetchedAt = deviceListFetchedAtRef.current.get(recipientCacheKey) ?? 0;
    // Judged before anything is sealed: a device the core has no verdict for
    // yet is assessed now rather than assumed.
    let sendPins = pinIndexRef.current;
    if (recipientDevices.some((device) => !sendPins.has(device.device_id))) {
      sendPins = await refreshDevicePins(recipientDevices);
    }
    let deliveryRecipientDevices = selectDeliveryDevicesForUsers(
      recipientDevices,
      recipientUserIds,
      localDeviceId,
      MESSAGE_DELIVERY_POLICY,
      pinGate(sendPins),
    );
    let awaitingApproval = selectDeliveryDevicesForUsers(recipientDevices, recipientUserIds, localDeviceId).length
      > deliveryRecipientDevices.length;
    if (
      deliveryRecipientDevices.length === 0 ||
      Date.now() - lastFetchedAt > DEVICE_LIST_MAX_STALENESS_MS
    ) {
      let fetched: TrustedDevice[] = [];
      try {
        fetched = await loadTrustedDevicesForUsers(recipientUserIds);
      } catch {
        fetched = [];
      }
      if (fetched.length > 0) sendPins = await refreshDevicePins(fetched);
      const fresh = selectDeliveryDevicesForUsers(fetched, recipientUserIds, localDeviceId, MESSAGE_DELIVERY_POLICY, pinGate(sendPins));
      if (fetched.length > 0) {
        awaitingApproval = selectDeliveryDevicesForUsers(fetched, recipientUserIds, localDeviceId).length > fresh.length;
      }
      // Keep the cached list when the refresh yields nothing (offline, transient
      // failure) — a stale addressee set still delivers to the devices we know,
      // whereas an empty one would abort a send that could have succeeded.
      if (fresh.length > 0) {
        deliveryRecipientDevices = fresh;
        deviceListFetchedAtRef.current.set(recipientCacheKey, Date.now());
      }
    }
    if (deliveryRecipientDevices.length === 0) {
      throw new Error(awaitingApproval
        ? "This contact's device is new and is waiting for your approval above. Nothing is sent to it until you approve it."
        : "Recipient device is missing signed PQC prekeys");
    }
    const clientMessageId = options.clientMessageId ?? crypto.randomUUID();
    const deliveryDevices = Array.from(new Map([...deliveryRecipientDevices, senderDevice].map((device) => [device.device_id, device])).values());
    const threat = options.controlType ? emptyThreat() : assessThreatLocally(parseSecurePlaintext(plaintext).body);
    const lifecycle = options.lifecycle ?? parseSecurePlaintext(plaintext).lifecycle;

    // Telemetry is audit-only and must never sit on the send critical path — a
    // couple of awaited Supabase writes here made every send wait on two extra
    // network round-trips. Fire-and-forget so the message seals immediately.
    void recordCryptoTelemetry({
      userId,
      deviceId: senderDevice.device_id,
      scope: "message",
      stage: "message_key_generation",
      detail: "Fresh hybrid key exchange started",
      progress: 15,
      status: "started",
      metadata: { conversation_id: activeConversation.id, recipients: deliveryRecipientDevices.length, client_message_id: clientMessageId },
    }).catch(() => undefined);
    // Seal every recipient-device envelope, then write them all in ONE insert.
    // The seals fire together (the Rust side serializes the key ops internally),
    // and collapsing N per-device inserts into a single batched write is what
    // removes the "send scales with device count x relay latency" delay — the
    // dominant cost of a slow send on a constrained relay.
    const sealed = await Promise.all(
      deliveryDevices.map(async (recipientDevice) => {
        const recipient = recipientKeyBundle(recipientDevice, null);
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
        return { recipientDevice, isLocalArchive: recipientDevice.user_id === userId, envelope };
      }),
    );

    const envelopeRows = sealed.map(({ recipientDevice, isLocalArchive, envelope }) => ({
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
    }));

    const { error } = await supabase.from("messaging_message_envelopes").insert(envelopeRows);
    if (error) throw error;

    void recordCryptoTelemetry({
      userId,
      deviceId: senderDevice.device_id,
      scope: "message",
      stage: options.controlType ? `message_control_${options.controlType}` : "message_envelope_committed",
      detail: options.controlType ? "Encrypted message control committed" : "Ciphertext envelope relayed with dual signatures",
      progress: 100,
      status: "complete",
      metadata: { conversation_id: activeConversation.id, recipients: deliveryRecipientDevices.length, client_message_id: clientMessageId },
    }).catch(() => undefined);

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
      const localEcho: ChatMessage = {
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
      };
      decryptedMessageCacheRef.current.set(clientMessageId, localEcho);
      // Paint the sender's own message NOW. Previously it only appeared after
      // `loadConversationMessages()` finished a fresh 250-envelope fetch +
      // hydrate — a full network round trip the sender had to sit through
      // watching "Sending". The reload still runs behind this to reconcile the
      // real row ids; it replaces this entry with an identical one.
      // A conversation switch during the seal/insert must not drop this echo
      // into someone else's thread.
      if (activeConversationIdRef.current === activeConversation.id) {
        setChatMessages((current) => {
          if (current.some((item) => item.client_message_id === clientMessageId)) return current;
          return [...current, localEcho]
            .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
        });
      }
    }
    return clientMessageId;
  }

  async function sendMessage() {
    // Re-entry guard: a single in-flight send at a time. This is what stops the
    // "click Send, nothing happens, click again, message sent twice" bug.
    if (sending) return;
    if (!activeConversation || !message.trim()) return;
    const senderDevice = currentDevice;
    const text = message.trim();
    const editing = editingMessage;
    const replyTo = replyToMessage;
    // Clear the composer immediately so the action feels instant and the same
    // text cannot be queued twice while the encrypt + relay round-trip runs.
    setSending(true);
    setMessage("");
    setStatus("Securing message");
    try {
      if (editing) {
        await sendEncryptedPayload(serializeSecureControl({
          type: "edit",
          target_client_message_id: editing.client_message_id,
          body: text,
        }), {
          parentClientMessageId: editing.client_message_id,
          controlType: "edit",
        });
        setEditingMessage(null);
      } else {
        const lifecycle = buildComposeLifecycle();
        await sendEncryptedPayload(serializeSecureMessage(text, replyTo?.client_message_id ?? null, lifecycle), {
          parentClientMessageId: replyTo?.client_message_id ?? null,
          lifecycle,
        });
      }

      setStatus("Message sealed");
      resetComposeControls();
      // The local echo is already on screen; the reload reconciles server rows
      // in the background. Awaiting it here kept the composer stuck on
      // "Sending" for the whole history round-trip.
      void loadConversationMessages();
      onSent();
    } catch (err) {
      // Restore the text so a failed send never silently loses the message,
      // and surface a readable reason (Supabase errors are plain objects, so
      // String(err) would render the useless "[object Object]").
      setMessage(text);
      const detail = describeMessageError(err);
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
    } finally {
      setSending(false);
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

  /**
   * The user has looked at a newly listed device and accepts it. The core
   * records it; from then on messages are sealed to it, history is synced to
   * it, and what it signs can be verified.
   */
  async function approveDevice(device: TrustedDevice) {
    setApprovingDeviceId(device.device_id);
    try {
      const assessment = await approveDevicePins([device]);
      const next = mergeVerdicts(pinIndexRef.current, assessment);
      pinIndexRef.current = next;
      setPinIndex(next);
      // Messages from this device were decrypted as unverified; drop those
      // cached copies so the reload re-checks them against the new record.
      decryptedMessageCacheRef.current.forEach((cached, key) => {
        if (cached.sender_unapproved) decryptedMessageCacheRef.current.delete(key);
      });
      void recordCryptoTelemetry({
        userId,
        deviceId: currentDevice?.device_id ?? null,
        scope: "verification",
        stage: "device_pin_approved",
        detail: "Newly listed device approved on this device",
        progress: 100,
        status: "complete",
        metadata: { approved_device_id: device.device_id, approved_user_id: device.user_id },
      }).catch(() => undefined);
      void loadConversationMessages();
    } catch (error) {
      setMessageAction(describeMessageError(error));
    } finally {
      setApprovingDeviceId(null);
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
      // Every envelope of this message that this device may have opened: its
      // recorded message keys are destroyed, not just the relay row marked.
      await safeInvoke<boolean>(
        "messaging_delete_encrypted_message",
        { messageId: chatMessage.id, messageIds: chatMessage.row_ids },
        true,
      );
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
    <div
      ref={chatGridRef}
      className="grid h-full min-h-0 gap-0"
      style={{ gridTemplateColumns: isMobile ? "minmax(0, 1fr)" : chatGridTemplate(chatColumnWidths) }}
    >
      <section className={`shell-card overflow-hidden ${isMobile && mobilePane !== "list" ? "hidden" : ""}`}>
        <div className="border-b border-line p-4">
          <div className="flex items-center justify-between gap-3">
            <div className="flex min-w-0 items-center gap-2">
              <h2 className="truncate text-sm font-bold text-ink-950">Secure Conversations</h2>
              <span className="status-pill bg-ink-50 text-ink-600">{visibleConversations.length}</span>
            </div>
            <button
              type="button"
              onClick={openNewChat}
              className="flex shrink-0 items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-bold text-white shadow-sm transition hover:bg-violet-700"
              title="Start a new encrypted chat"
            >
              <MessageSquarePlus size={15} />
              New Chat
            </button>
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
            <div className="px-4 py-8 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-violet-50 text-violet-600">
                <MessageSquarePlus size={22} />
              </div>
              <p className="mx-auto mt-3 max-w-[220px] text-sm text-ink-600">{emptyConversationText}</p>
              {conversationView === "active" && (
                <button
                  type="button"
                  onClick={openNewChat}
                  className="mx-auto mt-4 flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-2 text-xs font-bold text-white hover:bg-violet-700"
                >
                  <MessageSquarePlus size={14} />
                  New Chat
                </button>
              )}
            </div>
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
                  {conversationPeerUserId(thread) ? (
                    <UserAvatar userId={conversationPeerUserId(thread)} name={conversationTitle(thread)} size={40} />
                  ) : (
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-violet-500 text-white">
                      <Users size={18} />
                    </div>
                  )}
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

      <div
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize conversations panel"
        onPointerDown={(event) => startColumnResize("left", event)}
        onDoubleClick={() => {
          const reset = { ...chatColumnWidths, left: CHAT_COLUMN_DEFAULTS.left };
          setChatColumnWidths(reset);
          persistChatColumnWidths(reset);
        }}
        className="group relative z-20 flex cursor-col-resize touch-none items-center justify-center"
        title="Drag to resize · double-click to reset"
      >
        {/* Widened, finger-sized touch target that overhangs both panels;
            pointerdown bubbles to the separator's handler. */}
        <span className="absolute inset-y-0 -left-3 -right-3" aria-hidden="true" />
        <div className="h-20 w-1.5 rounded-full bg-line transition group-hover:h-24 group-hover:w-2 group-hover:bg-violet-400 group-active:bg-violet-500" />
      </div>

      <section className={`shell-card flex min-h-0 flex-col overflow-hidden ${isMobile && mobilePane !== "thread" ? "hidden" : ""}`}>
        <div className="flex items-center justify-between border-b border-line p-4">
          <div className="flex min-w-0 items-center gap-3">
            {isMobile && (
              <button
                type="button"
                onClick={() => setMobilePane("list")}
                className="icon-button shrink-0"
                title="Back to conversations"
              >
                <ArrowLeft size={16} />
              </button>
            )}
            {activeConversation && (
              conversationPeerUserId(activeConversation) ? (
                <UserAvatar userId={conversationPeerUserId(activeConversation)} name={conversationTitle(activeConversation)} size={40} />
              ) : (
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-violet-500 text-white">
                  <Users size={18} />
                </div>
              )
            )}
            <div className="min-w-0">
              <h2 className="truncate text-sm font-bold text-ink-950">{activeConversation ? conversationTitle(activeConversation) : "Select or start a private chat"}</h2>
              {pqStatus && <PqStatusBadge status={pqStatus} />}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <CallButton
              disabled={!call.supported || !callPeer || !activeConversation || call.state.phase !== "idle" && call.state.phase !== "ended"}
              title={call.supported ? "Start quantum-encrypted video call" : "Video calling requires the desktop app"}
              onClick={() => { if (callPeer && activeConversation) void call.startCall(callPeer, activeConversation.id); }}
            />
            <span className="status-pill bg-emerald-50 text-emerald-600">{status}</span>
          </div>
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
          {/* Devices the directory lists that this device has not accepted.
              Shown with the fingerprint the core computed from the device's
              own keys, so the user has something real to compare. */}
          {deviceReviews.length > 0 && (
            // Pinned to the top of the thread while it is the reason nothing
            // can be sent: the thread opens scrolled to its newest message, so
            // an unpinned card sits out of sight above a long history.
            <div className={`rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900 ${!recipientDevicesReady && recipientDevicesAwaitingApproval > 0 ? "sticky top-0 z-10 shadow-md" : ""}`}>
              <div className="flex items-start gap-2">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div className="min-w-0 flex-1 space-y-3">
                  <div>
                    <div className="font-bold">
                      {deviceReviews.length === 1 ? "A device needs your decision" : `${deviceReviews.length} devices need your decision`}
                    </div>
                    <div className="mt-1 leading-6">
                      {deviceReviews.length === 1 ? "This device was" : "These devices were"} not there when you first exchanged keys.
                      Nothing is sent to {deviceReviews.length === 1 ? "it" : "them"}, and messages from{" "}
                      {deviceReviews.length === 1 ? "it" : "them"} are marked unverified, until you approve here. If you were not
                      expecting a new device, compare the fingerprint with its owner over a channel you trust first.
                    </div>
                  </div>
                  {deviceReviews.map((review) => (
                    <div key={review.device.device_id} className="rounded-md border border-amber-200 bg-white/70 p-3">
                      <div className="font-semibold">
                        {review.owner === "self"
                          ? "Your account"
                          : contacts.find((contact) => contact.contact_user_id === review.device.user_id)?.display_name ?? "Contact"}
                        {" - "}{review.device.label}
                      </div>
                      <div className="mt-1 break-all font-mono text-xs">{review.verdict.fingerprint}</div>
                      {review.approvable ? (
                        <button
                          type="button"
                          className="mt-2 rounded-md border border-amber-300 bg-white px-3 py-1.5 text-xs font-bold text-amber-900 hover:bg-amber-100 disabled:opacity-60"
                          disabled={approvingDeviceId !== null}
                          onClick={() => void approveDevice(review.device)}
                        >
                          {approvingDeviceId === review.device.device_id ? "Approving..." : "Approve this device"}
                        </button>
                      ) : (
                        <div className="mt-2 text-xs font-semibold text-rose-700">
                          {review.verdict.standing === "key_changed"
                            ? "This device is presenting different identity keys than the ones recorded for it. It cannot be approved, and nothing is sent to it."
                            : "This device's identity does not verify. Nothing is sent to it."}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
          {devicePinsUnavailable && (
            <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
              Device changes cannot be checked right now: this device&apos;s own record of your contacts&apos; devices could not be
              opened. It is retried automatically.
            </div>
          )}
          {/* Explain a re-keyed history ONCE, here, instead of leaving the user
              to infer it from a wall of identical failure bubbles. Driven by
              messages that actually reported a retired key, so it never appears
              on a healthy thread. */}
          {retiredKeyMessageCount > 0 && (
            <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
              <div className="font-bold">
                {retiredKeyMessageCount} earlier {retiredKeyMessageCount === 1 ? "message is" : "messages are"} no longer readable on this device
              </div>
              <div className="mt-1 leading-6">
                They were encrypted to a device key that has since been replaced - by a reinstall, a key
                rotation, or this build&apos;s move to ML-KEM-1024 (FIPS 203). The private key that could open
                them no longer exists, so nothing can recover them here and no resend will help. New messages
                are unaffected.
              </div>
            </div>
          )}
          {/* A peer on an older build looks perfectly reachable - valid keys,
              valid signatures, right lengths - so say plainly why nothing is
              being delivered to them. */}
          {recipientDevicesOnStaleBuild.length > 0 && (
            <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
              <div className="font-bold">
                {recipientDevicesOnStaleBuild.length} recipient {recipientDevicesOnStaleBuild.length === 1 ? "device is" : "devices are"} running an older build
              </div>
              <div className="mt-1 leading-6">
                {recipientDevicesOnStaleBuild.map((device) => device.label).join(", ")} {recipientDevicesOnStaleBuild.length === 1 ? "is" : "are"}{" "}
                {describeKemIncompatibility(recipientDevicesOnStaleBuild[0].suite)}. Messages are not being
                sealed to {recipientDevicesOnStaleBuild.length === 1 ? "it" : "them"}, because anything sealed
                now could never be opened there.
              </div>
            </div>
          )}
          {messagesLoading && chatMessages.length === 0 && !historyStalled && (
            <div className="rounded-lg border border-line bg-white p-4 text-sm text-ink-600">Loading encrypted history...</div>
          )}
          {messagesLoading && chatMessages.length === 0 && historyStalled && (
            <div className="rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900">
              <div className="flex items-start gap-2">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div className="space-y-2">
                  <div className="font-medium">Encrypted history is taking longer than expected.</div>
                  <div className="text-amber-800">
                    Your messages are safe — this device just hasn&apos;t been able to reach the message
                    store yet. Retrying automatically; check your connection if it persists.
                  </div>
                  <button
                    type="button"
                    onClick={() => { setHistoryStalled(false); void loadConversationMessages(); }}
                    className="rounded-md border border-amber-400 bg-white px-3 py-1.5 text-xs font-medium text-amber-900 transition hover:bg-amber-100"
                  >
                    Retry now
                  </button>
                </div>
              </div>
            </div>
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
              const attachmentMedia = chatMessage.attachment ? inlineMediaKind(chatMessage.attachment) : null;
              const attachmentPreviewUrl = attachmentPreviewUrls[chatMessage.client_message_id];
              return (
                <div key={chatMessage.client_message_id} className={`flex items-start gap-2 ${mine ? "justify-end" : "justify-start"}`}>
                  {!mine && (
                    <UserAvatar
                      userId={chatMessage.sender_user_id}
                      name={activeContact
                        ? visibleContactName(activeContact)
                        : activeConversation
                          ? conversationTitle(activeConversation)
                          : "QG"}
                      size={32}
                      className="mt-1 shadow-tight"
                    />
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
                              onClick={() => (attachmentPreviewUrl ? saveDecryptedAttachment(chatMessage) : openAttachment(chatMessage))}
                              title={attachmentPreviewUrl ? "Save a copy to this device" : "Decrypt locally"}
                              className={`flex h-8 shrink-0 items-center gap-1 rounded-md px-2 text-xs font-bold transition disabled:cursor-not-allowed disabled:opacity-50 ${
                                mine ? "bg-white text-violet-700 hover:bg-violet-50" : "bg-violet-600 text-white hover:bg-violet-700"
                              }`}
                            >
                              {attachmentBusy === "download" && attachmentStatus === "decrypting" ? <Loader2 className="animate-spin" size={14} /> : attachmentPreviewUrl || attachmentStatus === "decrypted" ? <Download size={14} /> : <UnlockKeyhole size={14} />}
                              {attachmentPreviewUrl ? "Save" : "Decrypt"}
                            </button>
                          </div>
                          {/*
                            Decrypted media renders here, in the conversation. The
                            source is an in-memory object URL - nothing is written to
                            disk unless the reader presses Save.
                          */}
                          {attachmentPreviewUrl && attachmentMedia === "image" && (
                            <img
                              src={attachmentPreviewUrl}
                              alt={chatMessage.attachment.name}
                              loading="lazy"
                              onClick={() => setLightbox({ url: attachmentPreviewUrl, name: chatMessage.attachment!.name })}
                              className="mt-3 max-h-80 w-full cursor-zoom-in rounded-lg bg-black/5 object-contain"
                            />
                          )}
                          {attachmentPreviewUrl && attachmentMedia === "video" && (
                            <video
                              src={attachmentPreviewUrl}
                              controls
                              playsInline
                              preload="metadata"
                              className="mt-3 max-h-80 w-full rounded-lg bg-black"
                            />
                          )}
                          {attachmentPreviewUrl && attachmentMedia === "audio" && (
                            <audio
                              controls
                              src={attachmentPreviewUrl}
                              className="mt-3 w-full"
                              onEnded={() => markViewOnceAttachmentOpened(chatMessage).catch((error) => setMessageAction(describeMessageError(error)))}
                            />
                          )}
                        </div>
                      )}
                      {chatMessage.plaintext && <div className="whitespace-pre-wrap break-words text-sm leading-6">{chatMessage.plaintext}</div>}
                      {chatMessage.status !== "decrypted" && (
                        <div className={`mt-2 text-xs ${mine ? "text-violet-100" : "text-ink-500"}`}>
                          {chatMessage.status === "failed" ? "Decryption failed" : chatMessage.status === "retired" ? "Sealed to a retired device key" : "Sealed envelope"}{chatMessage.error ? ` - ${chatMessage.error}` : ""}
                        </div>
                      )}
                      <div className={`mt-2 flex flex-wrap items-center gap-2 text-[11px] ${mine ? "text-violet-100" : "text-ink-400"}`}>
                        <span>{new Date(chatMessage.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                        {chatMessage.authenticated && <span>Verified</span>}
                        {/* Decrypted but the sender's signing keys could not be
                            matched against a registered device, so "who sent
                            this" is unproven. Saying nothing here would let an
                            unanchored message read exactly like a verified one. */}
                        {!chatMessage.authenticated && chatMessage.status === "decrypted" && (
                          <span
                            title={chatMessage.sender_unapproved
                              ? "This message decrypted and is signed by a device listed for the sender, but that device was added after you first exchanged keys and you have not approved it on this device."
                              : "This message decrypted, but the sender's device identity could not be checked against the device registry, so the sender is unproven."}
                            className={mine ? "font-bold text-amber-100" : "font-bold text-amber-600"}
                          >
                            {chatMessage.sender_unapproved ? "New device - not approved" : "Sender unverified"}
                          </span>
                        )}
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
          <div className="mb-3">
            <button
              type="button"
              onClick={() => setComposerOptionsOpen((value) => !value)}
              aria-expanded={composerOptionsOpen}
              aria-controls="composer-options"
              className="flex w-full items-center gap-2 rounded-lg border border-line px-2 py-1 text-xs font-bold text-ink-600 transition hover:bg-white"
            >
              <ChevronDown
                size={14}
                className={`shrink-0 transition-transform ${composerOptionsOpen ? "rotate-180" : ""}`}
                aria-hidden
              />
              <span className="shrink-0">Message options</span>
              {composerOptionSummary.length > 0 && (
                <span className="truncate rounded-md bg-violet-50 px-2 py-0.5 text-[11px] font-bold text-violet-700">
                  {composerOptionSummary.join(" · ")}
                </span>
              )}
            </button>
            {composerOptionsOpen && (
            <div id="composer-options" className="mt-2 flex flex-wrap items-center gap-2 text-xs">
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
                min={new Date(Date.now() + 60_000 - new Date().getTimezoneOffset() * 60_000).toISOString().slice(0, 16)}
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
            )}
          </div>
          <div className="flex items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onClick={() => guardNativeFileInput()}
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
              onKeyDown={(event) => {
                // Enter sends, Shift+Enter inserts a newline.
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  if (!sending && message.trim() && !attachmentBusy && recordingState === "idle") {
                    void sendMessage();
                  }
                }
              }}
              className="min-h-10 flex-1 resize-none rounded-lg border border-line px-3 py-2 text-sm outline-none focus:border-violet-300"
              aria-label={activeConversation ? "Message composer" : "No conversation selected"}
            />
            <button
              disabled={!activeConversation || !message.trim() || sending || Boolean(attachmentBusy) || recordingState !== "idle"}
              onClick={sendMessage}
              className="flex h-10 items-center gap-2 rounded-lg bg-violet-600 px-4 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {sending ? <Loader2 className="animate-spin" size={17} /> : <Send size={17} />}
              {sending ? "Sending" : editingMessage ? "Update" : "Send"}
            </button>
          </div>
        </div>
      </section>

      <div
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize contacts panel"
        onPointerDown={(event) => startColumnResize("right", event)}
        onDoubleClick={() => {
          const reset = { ...chatColumnWidths, right: CHAT_COLUMN_DEFAULTS.right };
          setChatColumnWidths(reset);
          persistChatColumnWidths(reset);
        }}
        className="group relative z-20 flex cursor-col-resize touch-none items-center justify-center"
        title="Drag to resize · double-click to reset"
      >
        <span className="absolute inset-y-0 -left-3 -right-3" aria-hidden="true" />
        <div className="h-20 w-1.5 rounded-full bg-line transition group-hover:h-24 group-hover:w-2 group-hover:bg-violet-400 group-active:bg-violet-500" />
      </div>

      <section className={`shell-card flex min-h-0 flex-col overflow-hidden ${isMobile ? "hidden" : ""}`}>
        <div className="border-b border-line p-2">
          <div className="grid grid-cols-3 gap-1 rounded-lg border border-line bg-canvas p-1">
            <button
              type="button"
              onClick={() => setRightTab("contacts")}
              className={`flex min-w-0 items-center justify-center gap-1 rounded-md px-2 py-1.5 text-xs font-bold transition ${rightTab === "contacts" ? "conversation-segment-active" : "text-ink-600 hover:bg-white/70"}`}
              title="Contacts"
            >
              <Users size={13} />
              <span className="truncate">Contacts</span>
              <span className="rounded-full bg-ink-100 px-1.5 py-0.5 text-[10px] text-ink-600">{displayedContacts.length}</span>
            </button>
            <button
              type="button"
              onClick={() => setRightTab("files")}
              className={`flex min-w-0 items-center justify-center gap-1 rounded-md px-2 py-1.5 text-xs font-bold transition ${rightTab === "files" ? "conversation-segment-active" : "text-ink-600 hover:bg-white/70"}`}
              title="Downloaded files"
            >
              <Download size={13} />
              <span className="truncate">Files</span>
              <span className="rounded-full bg-ink-100 px-1.5 py-0.5 text-[10px] text-ink-600">{downloadedFiles.length}</span>
            </button>
            <button
              type="button"
              onClick={() => setRightTab("terminal")}
              className={`flex min-w-0 items-center justify-center gap-1 rounded-md px-2 py-1.5 text-xs font-bold transition ${rightTab === "terminal" ? "conversation-segment-active" : "text-ink-600 hover:bg-white/70"}`}
              title="Cyber terminal"
            >
              <Terminal size={13} />
              <span className="truncate">Terminal</span>
              {suspiciousCount > 0 && <span className="rounded-full bg-amber-100 px-1.5 py-0.5 text-[10px] font-bold text-amber-700">{suspiciousCount}</span>}
            </button>
          </div>
        </div>

        {rightTab === "contacts" && (
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="border-b border-line p-3">
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-2.5 text-ink-400" size={16} />
                  <input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") searchUsers();
                    }}
                    className="w-full rounded-lg border border-line bg-canvas py-2 pl-9 pr-3 text-sm outline-none focus:border-violet-300"
                    placeholder="Search a user to add"
                  />
                </div>
                <button
                  onClick={() => {
                    setShowMyQrPayload((value) => !value);
                    setMyQrPayloadCopied(false);
                  }}
                  className={`icon-button ${showMyQrPayload ? "border-violet-300 bg-violet-50 text-violet-600" : ""}`}
                  title="Show my contact QR payload"
                  aria-label="Show my contact QR payload"
                >
                  <QrCode size={16} />
                </button>
              </div>
              {showMyQrPayload && (
                <div className="mt-2 rounded-lg border border-violet-100 bg-violet-50/60 p-3">
                  <div className="text-[11px] font-bold uppercase tracking-wide text-violet-600">My contact QR payload</div>
                  <div className="mt-1.5 break-all rounded-md border border-line bg-white px-2 py-1.5 font-mono text-xs text-ink-700">
                    qguard-user:{userId}
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(`qguard-user:${userId}`).then(
                        () => setMyQrPayloadCopied(true),
                        () => setMyQrPayloadCopied(false),
                      );
                    }}
                    className="mt-2 w-full rounded-lg bg-violet-600 py-1.5 text-xs font-bold text-white transition hover:bg-violet-700"
                  >
                    {myQrPayloadCopied ? "Copied — share it securely" : "Copy payload"}
                  </button>
                  <div className="mt-2 text-[11px] leading-4 text-ink-500">
                    Share this payload (or its QR code) with a teammate. Pasting it into the search box above resolves the exact
                    account — no name lookup, no typos.
                  </div>
                </div>
              )}
              {blockedContactCount > 0 && (
                <div className="mt-2 text-[11px] font-semibold text-rose-500">{blockedContactCount} blocked contact{blockedContactCount === 1 ? "" : "s"}</div>
              )}
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto p-3">
              {(searching || searchFeedback || searchResults.length > 0) && (
                <div className="mb-3 rounded-lg border border-line bg-canvas/60 p-2">
                  <div className="flex items-center justify-between gap-2 px-1 pb-1.5">
                    <span className="text-[11px] font-bold uppercase tracking-wide text-ink-400">Directory search</span>
                    {(searchResults.length > 0 || searchFeedback) && (
                      <button type="button" onClick={() => { setQuery(""); setSearchResults([]); setSearchFeedback(null); }} className="text-[11px] font-semibold text-violet-600 hover:underline">Clear</button>
                    )}
                  </div>
                  {searching && <div className="px-1 py-2 text-sm text-ink-600">Searching...</div>}
                  {!searching && searchFeedback && (
                    <div className="px-1 py-2 text-sm text-ink-600">{searchFeedback}</div>
                  )}
                  <div className="space-y-2">
                    {searchResults.map((result) => (
                      <div key={result.user_id} className="rounded-lg border border-line bg-white p-3">
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
              )}
              {contactAction && <div className="mb-3 rounded-lg bg-canvas p-3 text-sm text-ink-600">{contactAction}</div>}
              {displayedContacts.length === 0 && <div className="py-3 text-sm text-ink-600">No contacts yet. Search above and press Add Contact.</div>}
              <div className="space-y-2">
            {displayedContacts.map((contact) => {
              const contactDevices = devices.filter((device) => device.user_id === contact.contact_user_id && isTrustedDeviceForDelivery(device));
              const readyDeviceCount = selectDeliveryDevicesForUsers(contactDevices, [contact.contact_user_id], localDeviceId).length;
              const isOpeningChat = contactChatBusyId === contact.id;
              const isBlocked = contact.trust_state === "blocked";
              return (
                <div key={contact.id} className="rounded-lg border border-line p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex min-w-0 items-start gap-3">
                      <UserAvatar userId={contact.contact_user_id} name={visibleContactName(contact)} size={36} />
                      <div className="min-w-0">
                        <div className="truncate text-sm font-bold text-ink-950">{visibleContactName(contact)}</div>
                        <div className="mt-1 truncate font-mono text-xs text-ink-400">{contact.username}</div>
                        <div className="mt-1 text-xs font-semibold text-ink-500">
                          {readyDeviceCount > 0 ? `${readyDeviceCount} trusted device${readyDeviceCount === 1 ? "" : "s"} ready` : "No trusted device ready yet"}
                        </div>
                      </div>
                    </div>
                    <span className={`status-pill ${contact.trust_state === "blocked" ? "bg-rose-50 text-rose-500" : "bg-emerald-50 text-emerald-600"}`}>
                      {contact.trust_state}
                    </span>
                  </div>
                  <div className="mt-3 grid grid-cols-3 gap-2">
                    <button
                      type="button"
                      disabled={isOpeningChat || isBlocked}
                      onClick={() => startPrivateChat(contact)}
                      title={isBlocked ? "Unblock this contact to chat" : "Open private encrypted chat"}
                      className="flex items-center justify-center gap-1 rounded-lg bg-violet-600 px-2 py-2 text-xs font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {isOpeningChat ? <Loader2 className="animate-spin" size={13} /> : <MessageSquarePlus size={13} />}
                      {isOpeningChat ? "Opening" : "Chat"}
                    </button>
                    <button
                      type="button"
                      onClick={() => updateContact(contact, isBlocked ? "added" : "blocked")}
                      title={isBlocked ? "Unblock contact" : "Block contact"}
                      className={`flex items-center justify-center gap-1 rounded-lg border px-2 py-2 text-xs font-bold transition ${isBlocked ? "border-emerald-200 text-emerald-600 hover:bg-emerald-50" : "border-line text-ink-700 hover:bg-canvas"}`}
                    >
                      {isBlocked ? <ShieldCheck size={14} /> : <Ban size={14} />}
                      {isBlocked ? "Unblock" : "Block"}
                    </button>
                    <button
                      type="button"
                      onClick={() => updateContact(contact, "removed")}
                      title="Delete contact"
                      className="flex items-center justify-center gap-1 rounded-lg border border-line px-2 py-2 text-xs font-bold text-rose-600 hover:bg-rose-50"
                    >
                      <Trash2 size={14} />
                      Delete
                    </button>
                  </div>
                </div>
              );
            })}
              </div>
            </div>
          </div>
        )}

        {rightTab === "files" && (
          <div className="min-h-0 flex-1 overflow-y-auto p-3">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
                <Download size={16} />
                Downloaded Files
              </div>
              <span className="status-pill bg-ink-50 text-ink-600">{downloadedFiles.length}</span>
            </div>
            <div className="mt-3 space-y-2">
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
        )}

        {rightTab === "terminal" && (
          <div className="min-h-0 flex-1 overflow-y-auto p-3">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
                <Terminal size={16} />
                Cyber Terminal
              </div>
              <span className={`status-pill ${suspiciousCount > 0 ? "bg-amber-50 text-amber-700" : "bg-emerald-50 text-emerald-600"}`}>
                {suspiciousCount > 0 ? `${suspiciousCount} risk` : "Clean"}
              </span>
            </div>
            <div className="mt-3 space-y-2">
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
        )}
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
    {showNewChat && (
      <div
        className="fixed inset-0 z-50 flex items-start justify-center bg-ink-950/40 p-4 pt-[12vh] backdrop-blur-sm"
        onClick={closeNewChat}
      >
        <div
          className="w-full max-w-lg overflow-hidden rounded-xl border border-white/30 bg-white/95 shadow-soft backdrop-blur-xl"
          onClick={(event) => event.stopPropagation()}
        >
          <div className="flex items-start justify-between gap-3 border-b border-line p-5">
            <div>
              <h2 className="text-base font-bold text-ink-950">New encrypted chat</h2>
              <div className="mt-1 flex items-center gap-2 text-xs font-semibold text-cyan-700">
                <ShieldCheck size={14} />
                Hybrid PQC · ML-KEM-1024 · end-to-end encrypted
              </div>
            </div>
            <button
              type="button"
              onClick={closeNewChat}
              className="icon-button h-8 w-8 shrink-0 bg-white/80"
              aria-label="Close new chat"
            >
              <X size={16} />
            </button>
          </div>

          <div className="p-5 pb-3">
            <div className="relative">
              <Search className="absolute left-3 top-3 text-ink-400" size={18} />
              <input
                autoFocus
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search by name, username, email, or user ID"
                className="w-full rounded-lg border border-line bg-canvas py-3 pl-10 pr-10 text-sm outline-none focus:border-violet-300"
                aria-label="Search for a user to chat with"
              />
              {searching && <Loader2 className="absolute right-3 top-3 animate-spin text-violet-500" size={18} />}
            </div>
            {contactAction && (
              <div className="mt-3 rounded-lg border border-line bg-canvas px-3 py-2 text-xs font-semibold text-ink-600">
                {contactAction}
              </div>
            )}
          </div>

          <div className="max-h-[46vh] overflow-y-auto px-3 pb-2">
            {query.trim().length < 2 && (
              <div className="px-2 py-10 text-center text-sm text-ink-500">
                Start typing to find someone on QGuard.
              </div>
            )}
            {query.trim().length >= 2 && !searching && searchResults.length === 0 && (
              <div className="px-2 py-10 text-center text-sm text-ink-500">
                {searchFeedback ?? `No users found for "${query.trim()}".`}
              </div>
            )}
            <div className="space-y-1">
              {searchResults.map((result) => {
                const busy = newChatBusyId === result.user_id;
                return (
                  <button
                    key={result.user_id}
                    type="button"
                    disabled={Boolean(newChatBusyId)}
                    onClick={() => startChatWithUser(result)}
                    className="group flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left transition hover:bg-violet-50 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <UserAvatar userId={result.user_id} name={result.display_name || result.username || "QG"} size={40} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-bold text-ink-950">{result.display_name}</div>
                      <div className="truncate font-mono text-xs text-ink-400">{result.username || result.user_id}</div>
                    </div>
                    <span className="flex shrink-0 items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-bold text-white transition group-hover:bg-violet-700">
                      {busy ? <Loader2 className="animate-spin" size={14} /> : <MessageSquarePlus size={14} />}
                      {busy ? "Opening" : "Message"}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="border-t border-line bg-canvas/60 px-5 py-3 text-xs text-ink-500">
            The person you message must have opened QGuard Messaging on desktop at least once so their quantum-safe keys are published.
          </div>
        </div>
      </div>
    )}
    {/*
      Full-size view for a decrypted image. Same in-memory object URL the bubble
      uses - opening it copies nothing to disk.
    */}
    {lightbox && (
      <div
        role="dialog"
        aria-modal="true"
        aria-label={lightbox.name}
        onClick={() => setLightbox(null)}
        className="fixed inset-0 z-[120] flex items-center justify-center bg-black/85 p-4 backdrop-blur-sm"
      >
        <button
          type="button"
          aria-label="Close image"
          onClick={() => setLightbox(null)}
          className="absolute right-4 top-4 rounded-lg bg-white/10 p-2 text-white transition hover:bg-white/20"
        >
          <X size={18} />
        </button>
        <img
          src={lightbox.url}
          alt={lightbox.name}
          onClick={(event) => event.stopPropagation()}
          className="max-h-full max-w-full rounded-lg object-contain"
        />
      </div>
    )}
    {/* Incoming-call modal and in-call overlay render app-wide in CallProvider. */}
    </>
  );
}
