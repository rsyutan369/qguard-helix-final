/**
 * Pure logic for the `device-link` Edge Function (index.ts).
 *
 * Runtime-agnostic on purpose — only Web Crypto and plain JS — so it runs under
 * Deno in the function and under Node in tools/device-link-edge-check.ts,
 * exactly like the billing function's logic module.
 */

/** How long a QR code stays scannable. Short: a code is a sign-in invitation. */
export const LINK_TTL_SECONDS = 120;
/** After approval, the requesting device has this long past expiry to claim. */
export const CLAIM_GRACE_SECONDS = 120;
/** Per-IP cap on new link requests (unauthenticated endpoint). */
export const MAX_STARTS_PER_IP = 12;
export const START_WINDOW_SECONDS = 600;
/** Per-account cap on approvals, so a stolen unlocked phone cannot mint sessions in bulk. */
export const MAX_APPROVALS_PER_USER = 10;
export const APPROVAL_WINDOW_SECONDS = 600;
/** The SMS hook only diverts a code the claim asked for within this window. */
export const OTP_CAPTURE_WINDOW_SECONDS = 30;
/** Standard Webhooks timestamp tolerance. */
export const WEBHOOK_TOLERANCE_SECONDS = 300;

export const PLACEHOLDER_EMAIL_DOMAIN = "@qguard.local";

export type LinkPlatform = "windows" | "macos" | "linux" | "android" | "ios" | "web" | "unknown";
export type CredentialMethod = "email_token" | "sms_code";
export type LinkStatus = "pending" | "approved" | "claiming" | "consumed" | "rejected" | "failed";

// Crockford base32: no I, L, O or U, so a typed code cannot be misread.
const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LENGTH = 12; // 60 bits

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64_RE = /^[0-9a-f]{64}$/;

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_RE.test(value);
}

export function isHex64(value: unknown): value is string {
  return typeof value === "string" && HEX64_RE.test(value);
}

/** The path after `/device-link`, e.g. `/start`. */
export function routeOf(url: string): string {
  const path = new URL(url).pathname.replace(/\/+$/, "");
  const marker = "/device-link";
  const index = path.indexOf(marker);
  const rest = index >= 0 ? path.slice(index + marker.length) : path;
  return rest || "/";
}

export function bearerToken(header: string | null): string | null {
  const match = /^Bearer\s+(.+)$/i.exec(header?.trim() ?? "");
  return match ? match[1].trim() : null;
}

/** A 60-bit approval code, grouped XXXX-XXXX-XXXX for reading aloud or typing. */
export function generateLinkCode(random: (bytes: Uint8Array) => Uint8Array = (bytes) => crypto.getRandomValues(bytes)): string {
  const bytes = random(new Uint8Array(CODE_LENGTH));
  // 256 is a multiple of 32, so `& 31` is unbiased.
  const chars = Array.from(bytes, (byte) => CODE_ALPHABET[byte & 31]).join("");
  return `${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}`;
}

/**
 * Canonical form of a typed or scanned code, or null when it cannot be one.
 * Accepts lower case, spaces and dashes, and the Crockford look-alikes.
 */
export function normalizeLinkCode(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const compact = input
    .toUpperCase()
    .replace(/[\s-]+/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
  if (compact.length !== CODE_LENGTH) return null;
  for (const char of compact) {
    if (!CODE_ALPHABET.includes(char)) return null;
  }
  return `${compact.slice(0, 4)}-${compact.slice(4, 8)}-${compact.slice(8, 12)}`;
}

export function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 256-bit secret, base64url. */
export function generateSecret(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export function isSecret(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqualText(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return diff === 0;
}

/** A device label the approving user will read: printable, trimmed, bounded. */
export function sanitizeLabel(value: unknown): string {
  const text = typeof value === "string" ? value : "";
  // Strip control and bidi-override characters so a label cannot disguise itself.
  const cleaned = text.replace(/[\u0000-\u001f\u007f‎‏‪-‮⁦-⁩]/g, "").replace(/\s+/g, " ").trim();
  return (cleaned || "New device").slice(0, 64);
}

export function normalizePlatform(value: unknown): LinkPlatform {
  const text = typeof value === "string" ? value.toLowerCase() : "";
  const known: LinkPlatform[] = ["windows", "macos", "linux", "android", "ios", "web"];
  return (known as string[]).includes(text) ? (text as LinkPlatform) : "unknown";
}

/** The caller's address as the edge proxy reports it (first hop of x-forwarded-for). */
export function clientIp(headers: { get(name: string): string | null }): string | null {
  const forwarded = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const candidate = forwarded || headers.get("cf-connecting-ip")?.trim() || headers.get("x-real-ip")?.trim() || "";
  if (!candidate || candidate.length > 64 || !/^[0-9a-fA-F:.]+$/.test(candidate)) return null;
  return candidate;
}

export function isPlaceholderEmail(email: string | null | undefined): boolean {
  return Boolean(email && email.trim().toLowerCase().endsWith(PLACEHOLDER_EMAIL_DOMAIN));
}

export interface AuthUserLike {
  email?: string | null;
  email_confirmed_at?: string | null;
  phone?: string | null;
  phone_confirmed_at?: string | null;
}

/**
 * How a new device of this account can be given its own session.
 *
 * A confirmed email gets a one-time magic-link token (admin generateLink: no
 * email is sent). A phone-only account gets an SMS code that the Send-SMS hook
 * diverts to the claim instead of texting it. Neither exists → no QR linking.
 */
export function credentialMethodFor(user: AuthUserLike): CredentialMethod | null {
  const email = (user.email ?? "").trim();
  if (email && !isPlaceholderEmail(email) && user.email_confirmed_at) return "email_token";
  if ((user.phone ?? "").trim() && user.phone_confirmed_at) return "sms_code";
  return null;
}

/** GoTrue stores phones without '+'; the verify endpoint wants E.164. */
export function e164(phone: string): string {
  const digits = phone.replace(/[^\d]/g, "");
  return `+${digits}`;
}

export interface LinkRowState {
  status: LinkStatus;
  expires_at: string;
  failure_reason?: string | null;
}

export type ClaimView =
  | { status: "pending"; expiresAt: string }
  | { status: "expired" }
  | { status: "rejected" }
  | { status: "used" }
  | { status: "failed"; reason: string }
  | { status: "ready" };

/** What the requesting device is told while it polls. `ready` means mint now. */
export function claimView(row: LinkRowState, nowMs: number): ClaimView {
  const expiresMs = Date.parse(row.expires_at);
  switch (row.status) {
    case "pending":
      return nowMs > expiresMs ? { status: "expired" } : { status: "pending", expiresAt: row.expires_at };
    case "approved":
      return nowMs > expiresMs + CLAIM_GRACE_SECONDS * 1000 ? { status: "expired" } : { status: "ready" };
    case "rejected":
      return { status: "rejected" };
    case "failed":
      return { status: "failed", reason: row.failure_reason || "link_failed" };
    default:
      return { status: "used" };
  }
}

export function decodeJwtClaims(token: string): Record<string, unknown> {
  const payload = token.split(".")[1];
  if (!payload) return {};
  try {
    const padded = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payload.length / 4) * 4, "=");
    const parsed = JSON.parse(atob(padded));
    return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

// ---- Send-SMS hook (Standard Webhooks) -------------------------------------

/** A plain ArrayBuffer (not a typed-array view), which every Web Crypto typing accepts. */
function base64ToBuffer(value: string): ArrayBuffer {
  const binary = atob(value);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let index = 0; index < binary.length; index += 1) view[index] = binary.charCodeAt(index);
  return buffer;
}

/**
 * Verify a Supabase Auth hook delivery (Standard Webhooks spec): HMAC-SHA256
 * over `${id}.${timestamp}.${body}` with the secret configured as
 * `v1,whsec_<base64>`. The signature header may list several `v1,<sig>`.
 */
export async function verifyStandardWebhook(
  secret: string,
  headers: { get(name: string): string | null },
  body: string,
  nowSeconds: number,
): Promise<boolean> {
  const id = headers.get("webhook-id");
  const timestamp = headers.get("webhook-timestamp");
  const signatureHeader = headers.get("webhook-signature");
  if (!id || !timestamp || !signatureHeader) return false;
  const sentAt = Number(timestamp);
  if (!Number.isFinite(sentAt) || Math.abs(nowSeconds - sentAt) > WEBHOOK_TOLERANCE_SECONDS) return false;

  const keyText = secret.replace(/^v1,/, "").replace(/^whsec_/, "");
  let keyBytes: ArrayBuffer;
  try {
    keyBytes = base64ToBuffer(keyText);
  } catch {
    return false;
  }
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${id}.${timestamp}.${body}`)));
  let expected = "";
  for (const byte of mac) expected += String.fromCharCode(byte);
  expected = btoa(expected);

  return signatureHeader
    .split(" ")
    .map((part) => part.trim())
    .filter((part) => part.startsWith("v1,"))
    .some((part) => timingSafeEqualText(part.slice(3), expected));
}

export interface SmsHookPayload {
  userId: string;
  phone: string;
  otp: string;
}

export function parseSmsHookPayload(value: unknown): SmsHookPayload | null {
  if (!value || typeof value !== "object") return null;
  const record = value as { user?: { id?: unknown; phone?: unknown }; sms?: { otp?: unknown } };
  const userId = record.user?.id;
  const phone = record.user?.phone;
  const otp = record.sms?.otp;
  if (!isUuid(userId) || typeof phone !== "string" || !phone.trim() || typeof otp !== "string" || !/^[0-9]{6,10}$/.test(otp)) {
    return null;
  }
  return { userId, phone: e164(phone), otp };
}

export function smsBody(otp: string): string {
  return `Your QGuard Helix code is ${otp}. Never share this code — QGuard will never ask you for it.`;
}

export interface TwilioConfig {
  accountSid: string;
  authToken: string;
  messagingServiceSid: string | null;
  fromNumber: string | null;
}

export function twilioConfig(env: (key: string) => string | undefined): TwilioConfig | null {
  const accountSid = env("TWILIO_ACCOUNT_SID")?.trim();
  const authToken = env("TWILIO_AUTH_TOKEN")?.trim();
  const messagingServiceSid = env("TWILIO_MESSAGING_SERVICE_SID")?.trim() || null;
  const fromNumber = env("TWILIO_FROM_NUMBER")?.trim() || null;
  if (!accountSid || !authToken || (!messagingServiceSid && !fromNumber)) return null;
  return { accountSid, authToken, messagingServiceSid, fromNumber };
}

/** Form body for Twilio's Messages API. */
export function twilioMessageForm(config: TwilioConfig, to: string, body: string): URLSearchParams {
  const form = new URLSearchParams({ To: to, Body: body });
  if (config.messagingServiceSid) form.set("MessagingServiceSid", config.messagingServiceSid);
  else if (config.fromNumber) form.set("From", config.fromNumber);
  return form;
}
