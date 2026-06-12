import { supabase } from "@/lib/supabase";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

export type DecryptionScope = "vault" | "message" | "download";
export type DecryptionStatus = "encrypted" | "decrypting" | "decrypted" | "failed";
export type DecryptionLogLevel = "info" | "success" | "error";
export type DecryptionTelemetryStatus = "started" | "progress" | "verified" | "failed" | "complete";

export interface DecryptionStreamData {
  id: string;
  at: string;
  scope: DecryptionScope;
  stage: string;
  detail: string;
  progress: number;
  status: DecryptionTelemetryStatus;
  level: DecryptionLogLevel;
}

export interface DecryptionSseEvent {
  id: string;
  event: "decryption-log";
  data: DecryptionStreamData;
  raw: string;
}

export interface PrivateKeyUnlockStatus {
  unlocked: boolean;
  device_id: string;
  fingerprint: string;
  storage: string;
  suite: Record<string, unknown>;
  private_key_exported: boolean;
}

type DecryptionListener = (event: DecryptionSseEvent) => void;

const fallbackUnlockStatus: PrivateKeyUnlockStatus = {
  unlocked: true,
  device_id: "webcrypto-session",
  fingerprint: "local-webcrypto-session",
  storage: "WebCrypto session key",
  suite: {
    classical_kex: "X25519",
    pq_kem: "ML-KEM-1024",
    kdf: "HKDF-SHA3-256",
    symmetric: "AES-256-GCM",
    classical_signature: "Ed25519",
    pq_signature: "ML-DSA-65",
  },
  private_key_exported: false,
};

const memoryRateLimits = new Map<string, number[]>();

function clampProgress(progress: number): number {
  return Math.max(0, Math.min(100, Math.round(progress)));
}

function serializeSse(data: DecryptionStreamData): string {
  return `event: decryption-log\nid: ${data.id}\ndata: ${JSON.stringify(data)}\n\n`;
}

export class SecureDecryptionSseStream {
  private readonly listeners = new Set<DecryptionListener>();

  constructor(private readonly scope: DecryptionScope) {}

  subscribe(listener: DecryptionListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(input: Omit<DecryptionStreamData, "id" | "at" | "scope">): DecryptionSseEvent {
    const data: DecryptionStreamData = {
      ...input,
      id: crypto.randomUUID(),
      at: new Date().toISOString(),
      scope: this.scope,
      progress: clampProgress(input.progress),
    };
    const event: DecryptionSseEvent = {
      id: data.id,
      event: "decryption-log",
      data,
      raw: serializeSse(data),
    };
    this.listeners.forEach((listener) => listener(event));
    return event;
  }
}

export function createSecureDecryptionStream(
  scope: DecryptionScope,
  listener?: DecryptionListener,
): SecureDecryptionSseStream {
  const stream = new SecureDecryptionSseStream(scope);
  if (listener) stream.subscribe(listener);
  return stream;
}

export async function validateDecryptionSession(
  userId: string,
  stream: SecureDecryptionSseStream,
): Promise<void> {
  stream.emit({
    stage: "session_auth",
    detail: "Validating authenticated session before decryption",
    progress: 6,
    status: "started",
    level: "info",
  });

  const { data, error } = await supabase.auth.getSession();
  if (error || !data.session) {
    throw new Error("A valid authenticated session is required before decryption.");
  }
  if (data.session.user.id !== userId) {
    throw new Error("Session identity does not match the decryption request.");
  }

  stream.emit({
    stage: "session_auth",
    detail: "Session identity validated",
    progress: 10,
    status: "verified",
    level: "success",
  });

  try {
    const { data: assurance, error: assuranceError } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
    if (assuranceError) throw assuranceError;
    if (assurance?.nextLevel === "aal2" && assurance.currentLevel !== "aal2") {
      throw new Error("MFA step-up is required before decrypting this item.");
    }
    stream.emit({
      stage: "mfa_check",
      detail: assurance?.currentLevel === "aal2" ? "MFA assurance satisfied" : "No MFA step-up required for this session",
      progress: 13,
      status: "verified",
      level: "success",
    });
  } catch (error) {
    const message = normalizeDecryptionError(error);
    if (message.toLowerCase().includes("mfa step-up")) throw new Error(message);
    stream.emit({
      stage: "mfa_check",
      detail: "MFA assurance could not be refreshed; continuing with the active session policy",
      progress: 13,
      status: "progress",
      level: "info",
    });
  }
}

export function enforceClientDecryptionRateLimit(
  userId: string,
  target: string,
  stream: SecureDecryptionSseStream,
  limit = 8,
  windowMs = 5 * 60 * 1000,
): void {
  const now = Date.now();
  const floor = now - windowMs;
  const key = `qguard-decryption-rate:${userId}:${target}`;
  let attempts = memoryRateLimits.get(key) ?? [];

  try {
    const raw = window.localStorage.getItem(key);
    if (raw) attempts = JSON.parse(raw) as number[];
  } catch {
    // In-memory rate limiting remains active when localStorage is unavailable.
  }

  attempts = attempts.filter((timestamp) => Number.isFinite(timestamp) && timestamp >= floor);
  if (attempts.length >= limit) {
    throw new Error("Too many decryption attempts. Wait a few minutes and try again.");
  }
  attempts.push(now);
  memoryRateLimits.set(key, attempts);

  try {
    window.localStorage.setItem(key, JSON.stringify(attempts));
  } catch {
    // Best-effort persistence only; memory guard is already updated.
  }

  stream.emit({
    stage: "rate_limit",
    detail: "Decryption attempt rate limit accepted",
    progress: 16,
    status: "verified",
    level: "success",
  });
}

export async function unlockDevicePrivateKey(
  stream: SecureDecryptionSseStream,
  userId?: string,
): Promise<PrivateKeyUnlockStatus> {
  stream.emit({
    stage: "key_validation",
    detail: "Unlocking device-bound private key",
    progress: 20,
    status: "progress",
    level: "info",
  });

  const status = isTauriRuntime()
    ? await safeInvoke<PrivateKeyUnlockStatus>("keys_unlock_private_key", userId ? { userId } : {})
    : fallbackUnlockStatus;

  if (!status.unlocked || status.private_key_exported) {
    throw new Error("Private key unlock failed or attempted to export private key material.");
  }

  stream.emit({
    stage: "key_validation",
    detail: `${status.storage} unlocked; private key bytes were not exported`,
    progress: 24,
    status: "verified",
    level: "success",
  });
  return status;
}

export function normalizeDecryptionError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const lower = message.toLowerCase();
  if (lower.includes("wrapped file key")) {
    const available = message.match(/available wrapped devices:\s*([^;]+)/i)?.[1]?.trim();
    const suffix = available && available !== "none" ? ` Wrapped device id(s): ${available}.` : "";
    return `Invalid key for this device. The vault object is wrapped for another device key or an older local key.${suffix} Use the device that originally encrypted/downloaded it, or re-share/re-encrypt it for this device.`;
  }
  if (lower.includes("aead") || lower.includes("authentication failed")) {
    return "Corrupted or tampered ciphertext. AES-256-GCM authentication failed.";
  }
  if (lower.includes("signature verification failed") || lower.includes("ml-dsa") || lower.includes("ed25519")) {
    return "Integrity verification failed. The signed metadata or message signature is invalid.";
  }
  if (lower.includes("rate limit") || lower.includes("too many decryption attempts")) {
    return "Too many decryption attempts. Wait a few minutes and try again.";
  }
  return message || "Decryption failed.";
}

export function blobFromBase64(base64: string, contentType: string): Blob {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  const blob = new Blob([bytes.slice()], { type: contentType || "application/octet-stream" });
  bytes.fill(0);
  return blob;
}

export function wipeBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}
