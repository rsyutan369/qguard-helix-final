/**
 * Link a device by QR code — the client half of the `device-link` Edge Function
 * (supabase/functions/device-link in the platform repo).
 *
 * The NEW (signed-out) device opens a request and shows a QR code. A SIGNED-IN
 * device of the account scans it, the user approves, and the new device claims
 * its own, independent session.
 *
 * The QR code carries two things:
 *   * the approval CODE — the approving device sends it to the server, which
 *     knows it only as a hash;
 *   * a BINDING secret — never sent to the server. Once the new device has
 *     signed in and registered its identity keys, it proves with this secret
 *     which device it is (HMAC-SHA3-256 over its fingerprint). The approving
 *     device checks that proof against the fingerprint its own core computes
 *     from the keys, and only then trusts the device. A relay that substituted
 *     another device cannot forge the proof.
 * A code typed by hand has no binding secret: the device still signs in, but is
 * left for the user to approve in the Device Trust Center like any new device.
 */
import { hmac } from "@noble/hashes/hmac.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { supabaseAnonKey, supabaseUrl } from "@/lib/supabase";
import { isAndroidRuntime, isTauriRuntime } from "@/lib/tauri";

export const LINK_PAYLOAD_PREFIX = "qguard-link:v2:";
const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export type LinkPlatform = "windows" | "macos" | "linux" | "android" | "ios" | "web" | "unknown";

export interface StartedLink {
  linkId: string;
  code: string;
  claimSecret: string;
  expiresAt: string;
  ttlSeconds: number;
  pollIntervalMs: number;
}

export type LinkCredential =
  | { method: "email_token"; tokenHash: string }
  | { method: "sms_code"; phone: string; code: string };

export type ClaimResult =
  | { status: "pending"; expiresAt: string }
  | { status: "approved"; credential: LinkCredential }
  | { status: "expired" }
  | { status: "rejected" }
  | { status: "used" }
  | { status: "failed"; reason: string };

export interface LinkInspection {
  linkId: string;
  label: string;
  platform: LinkPlatform;
  ip: string | null;
  createdAt: string;
  expiresAt: string;
}

export interface LinkStatus {
  linkId: string;
  status: "pending" | "approved" | "claiming" | "consumed" | "rejected" | "failed";
  label: string;
  linkedDeviceId: string | null;
  linkProof: string | null;
  failureReason: string | null;
}

export class DeviceLinkError extends Error {
  constructor(message: string, readonly code: string, readonly status: number | null) {
    super(message);
    this.name = "DeviceLinkError";
  }
}

export function deviceLinkOrigin(url: string = supabaseUrl): string {
  const base = url.trim().replace(/\/+$/, "");
  return base ? `${base}/functions/v1/device-link` : "";
}

async function call<T>(route: string, body: unknown, accessToken?: string | null): Promise<T> {
  const origin = deviceLinkOrigin();
  if (!origin) throw new DeviceLinkError("Device linking is not configured for this build.", "NOT_CONFIGURED", null);
  let response: Response;
  try {
    response = await fetch(`${origin}${route}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        apikey: supabaseAnonKey,
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      },
      body: JSON.stringify(body),
    });
  } catch {
    throw new DeviceLinkError("Couldn't reach the device-linking service. Check your connection and try again.", "NETWORK", null);
  }
  const payload = await response.json().catch(() => null) as (T & { error?: { code?: string; message?: string } }) | null;
  if (!response.ok) {
    const code = payload?.error?.code ?? (response.status === 404 ? "NOT_DEPLOYED" : "HTTP_ERROR");
    const message = payload?.error?.message
      ?? (response.status === 404 ? "Device linking is not available on this server yet." : `Device linking failed (${response.status}).`);
    throw new DeviceLinkError(message, code, response.status);
  }
  if (!payload) throw new DeviceLinkError("The device-linking service returned an unreadable response.", "BAD_RESPONSE", response.status);
  return payload;
}

// ---- new device ------------------------------------------------------------

export const startLink = (label: string, platform: LinkPlatform) => call<StartedLink>("/start", { label, platform });
export const claimLink = (linkId: string, claimSecret: string) => call<ClaimResult>("/claim", { linkId, claimSecret });
export const completeLink = (linkId: string, claimSecret: string, deviceId: string, proof: string, accessToken: string) =>
  call<{ linkId: string; linkedDeviceId: string }>("/complete", { linkId, claimSecret, deviceId, proof }, accessToken);

// ---- approving device ------------------------------------------------------

export const inspectLink = (code: string, accessToken: string) => call<LinkInspection>("/inspect", { code }, accessToken);
export const approveLink = (code: string, deviceId: string | null, accessToken: string) =>
  call<{ linkId: string; status: "approved"; method: LinkCredential["method"] }>("/approve", { code, deviceId }, accessToken);
export const rejectLink = (code: string, accessToken: string) => call<{ linkId: string; status: string }>("/reject", { code }, accessToken);
export const linkStatus = (linkId: string, accessToken: string) => call<LinkStatus>("/status", { linkId }, accessToken);

// ---- QR payload ------------------------------------------------------------

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generateBindingSecret(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

/** Same rules as the server: Crockford base32, case/spacing/look-alikes forgiven. */
export function normalizeLinkCode(input: string): string | null {
  const compact = input.toUpperCase().replace(/[\s-]+/g, "").replace(/[IL]/g, "1").replace(/O/g, "0");
  if (compact.length !== 12 || [...compact].some((char) => !CODE_ALPHABET.includes(char))) return null;
  return `${compact.slice(0, 4)}-${compact.slice(4, 8)}-${compact.slice(8, 12)}`;
}

export function buildLinkPayload(code: string, bindingSecret: string): string {
  return `${LINK_PAYLOAD_PREFIX}${code}#${bindingSecret}`;
}

export interface ParsedLinkPayload {
  code: string;
  /** Null when the code was typed by hand: sign-in works, auto-trust does not. */
  bindingSecret: string | null;
}

/** A scanned QR payload or a hand-typed code; null when it is neither. */
export function parseLinkPayload(raw: string): ParsedLinkPayload | null {
  const text = raw.trim();
  if (text.startsWith(LINK_PAYLOAD_PREFIX)) {
    const [codePart, secretPart] = text.slice(LINK_PAYLOAD_PREFIX.length).split("#");
    const code = normalizeLinkCode(codePart ?? "");
    if (!code) return null;
    const bindingSecret = secretPart && /^[A-Za-z0-9_-]{43}$/.test(secretPart) ? secretPart : null;
    return { code, bindingSecret };
  }
  const code = normalizeLinkCode(text);
  return code ? { code, bindingSecret: null } : null;
}

// ---- binding proof ---------------------------------------------------------

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

export interface LinkProofInput {
  bindingSecret: string;
  linkId: string;
  userId: string;
  deviceId: string;
  /** The device's safety fingerprint (Ed25519 + ML-DSA identity keys). */
  fingerprint: string;
}

export function computeLinkProof(input: LinkProofInput): string {
  const message = ["qguard-device-link/v2", input.linkId, input.userId, input.deviceId, input.fingerprint].join("|");
  const mac = hmac(sha3_256, fromBase64Url(input.bindingSecret), new TextEncoder().encode(message));
  return Array.from(mac, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function verifyLinkProof(input: LinkProofInput, proof: string | null | undefined): boolean {
  if (!proof || !/^[0-9a-f]{64}$/.test(proof)) return false;
  const expected = computeLinkProof(input);
  let diff = 0;
  for (let index = 0; index < expected.length; index += 1) diff |= expected.charCodeAt(index) ^ proof.charCodeAt(index);
  return diff === 0;
}

// ---- new device: report back once signed in --------------------------------

export interface PendingLinkCompletion {
  linkId: string;
  claimSecret: string;
  bindingSecret: string;
}

// In memory only: it must survive the MFA step between redeeming the credential
// and the workspace mounting, and nothing longer. Lost on reload, the device is
// simply left for the user to approve by hand.
let pendingCompletion: PendingLinkCompletion | null = null;

export function rememberLinkCompletion(value: PendingLinkCompletion | null): void {
  pendingCompletion = value;
}

export function hasPendingLinkCompletion(): boolean {
  return pendingCompletion !== null;
}

export interface RegisteredIdentity {
  device_id: string;
  fingerprint: string;
}

/**
 * Tell the approving device which device this is, with a proof only the holder
 * of the QR's binding secret can produce. `registerDevice` must return this
 * device's identity as registered in the directory.
 */
export async function finishPendingLinkCompletion(
  userId: string,
  accessToken: string,
  registerDevice: () => Promise<RegisteredIdentity | null>,
): Promise<"completed" | "none" | "failed"> {
  const pending = pendingCompletion;
  if (!pending) return "none";
  pendingCompletion = null;
  try {
    const identity = await registerDevice();
    if (!identity?.device_id || !identity.fingerprint) return "failed";
    const proof = computeLinkProof({
      bindingSecret: pending.bindingSecret,
      linkId: pending.linkId,
      userId,
      deviceId: identity.device_id,
      fingerprint: identity.fingerprint,
    });
    await completeLink(pending.linkId, pending.claimSecret, identity.device_id, proof, accessToken);
    return "completed";
  } catch {
    return "failed";
  }
}

// ---- this device -----------------------------------------------------------

export function thisDevicePlatform(userAgent: string = typeof navigator !== "undefined" ? navigator.userAgent : ""): LinkPlatform {
  if (isAndroidRuntime() || /android/i.test(userAgent)) return "android";
  if (/iphone|ipad|ios/i.test(userAgent)) return "ios";
  if (/windows/i.test(userAgent)) return "windows";
  if (/mac os|macintosh/i.test(userAgent)) return "macos";
  if (/linux/i.test(userAgent)) return "linux";
  return isTauriRuntime() ? "unknown" : "web";
}

const PLATFORM_LABELS: Record<LinkPlatform, string> = {
  windows: "Windows desktop",
  macos: "macOS desktop",
  linux: "Linux desktop",
  android: "Android phone",
  ios: "iPhone",
  web: "Web browser",
  unknown: "New device",
};

export function platformLabel(platform: LinkPlatform | string): string {
  return PLATFORM_LABELS[platform as LinkPlatform] ?? PLATFORM_LABELS.unknown;
}

/** What the approving user is told when a step fails. */
export function describeLinkError(error: unknown): string {
  if (error instanceof DeviceLinkError) return error.message;
  return error instanceof Error ? error.message : "Device linking failed. Try again.";
}

/** Human text for a `failed` claim's reason code. */
export function describeClaimFailure(reason: string): string {
  switch (reason) {
    case "sms_rate_limited":
      return "A sign-in code was requested for this account in the last minute. Wait a minute, then show a new QR code.";
    case "sms_hook_not_capturing":
    case "sms_hook_not_configured":
      return "QR linking for mobile-number accounts isn't enabled on this server. Sign in with your number and the SMS code instead.";
    case "email_token_unavailable":
      return "The server couldn't issue a sign-in for this account. Sign in with your email and password instead.";
    default:
      return "Linking couldn't be completed. Show a new QR code and try again.";
  }
}
