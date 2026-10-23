/**
 * QGuard device linking — Supabase Edge Function (`/functions/v1/device-link`).
 *
 * "Link a device" the way Signal, WhatsApp and Telegram do it: a signed-out
 * device shows a QR code, a signed-in device of the account scans it and
 * approves, and the new device receives its OWN session (never a copy of the
 * approver's — a shared refresh token would be revoked by GoTrue's reuse
 * detection and sign both devices out).
 *
 * Routes:
 *   GET  /health     configuration booleans only
 *   POST /start      new device: open a link request          (no auth, IP-limited)
 *   POST /inspect    approver: what is asking to be linked     (auth)
 *   POST /approve    approver: approve it                      (auth, aal2 if MFA)
 *   POST /reject     approver: refuse it                       (auth)
 *   POST /claim      new device: poll; on approval get a credential (claim secret)
 *   POST /complete   new device: report its device id + binding proof (auth)
 *   POST /status     approver: follow the link to completion   (auth)
 *   POST /sms-hook   Supabase Auth "Send SMS" hook             (Standard Webhooks signature)
 *
 * Security model:
 *   * The QR code carries an approval CODE (sent to this function by the
 *     approver) and a binding SECRET (never sent here). The requesting device
 *     alone holds the CLAIM secret. The table stores only SHA-256 hashes.
 *   * The credential is minted at claim time and returned once; it is never
 *     stored. Email accounts get a one-time magic-link token_hash (admin
 *     generateLink sends no email). Phone-only accounts get an SMS code that
 *     /sms-hook diverts to the claim instead of texting it — only when this
 *     project delivers SMS through that hook.
 *   * A linked session is aal1. If the account has MFA, the new device must
 *     still pass its TOTP challenge, exactly like a password sign-in.
 *   * Identity always comes from the verified access token, never the body.
 *
 * Deployed with verify_jwt = false: /start, /claim and /sms-hook carry no user
 * JWT. Every user route verifies the caller's access token itself.
 *
 * Secrets: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_ANON_KEY (runtime).
 * Optional, for phone-only accounts: SEND_SMS_HOOK_SECRET (the `v1,whsec_…`
 * value from Auth → Hooks), TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and one of
 * TWILIO_MESSAGING_SERVICE_SID / TWILIO_FROM_NUMBER.
 */
import { createClient, type SupabaseClient, type User } from "jsr:@supabase/supabase-js@2";
import {
  APPROVAL_WINDOW_SECONDS,
  bearerToken,
  claimView,
  clientIp,
  credentialMethodFor,
  decodeJwtClaims,
  e164,
  generateLinkCode,
  generateSecret,
  isHex64,
  isSecret,
  isUuid,
  LINK_TTL_SECONDS,
  MAX_APPROVALS_PER_USER,
  MAX_STARTS_PER_IP,
  normalizeLinkCode,
  normalizePlatform,
  OTP_CAPTURE_WINDOW_SECONDS,
  parseSmsHookPayload,
  routeOf,
  sanitizeLabel,
  sha256Hex,
  smsBody,
  START_WINDOW_SECONDS,
  timingSafeEqualText,
  twilioConfig,
  twilioMessageForm,
  verifyStandardWebhook,
} from "./logic.ts";

const env = (key: string) => Deno.env.get(key);
const TABLE = "messaging_device_link_sessions";

// Bearer-token API with no cookies: a wildcard origin grants a foreign page
// nothing, and an allowlist would break whichever webview origin it forgot.
const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
  "Access-Control-Max-Age": "600",
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

function serviceClient(): SupabaseClient {
  const url = env("SUPABASE_URL");
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) throw new HttpError(503, "SERVICE_UNAVAILABLE", "Device linking is not configured");
  return createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
}

async function readJson(req: Request): Promise<Record<string, unknown>> {
  try {
    const value = await req.json();
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

interface Caller {
  user: User;
  token: string;
}

async function requireUser(req: Request, db: SupabaseClient): Promise<Caller> {
  const token = bearerToken(req.headers.get("Authorization"));
  if (!token) throw new HttpError(401, "UNAUTHORIZED", "Sign in to link a device");
  const { data, error } = await db.auth.getUser(token);
  if (error || !data?.user) throw new HttpError(401, "UNAUTHORIZED", "Your session has expired — sign in again");
  return { user: data.user, token };
}

/** An account with MFA may only approve from a session that passed it. */
async function requireAssurance(db: SupabaseClient, caller: Caller): Promise<void> {
  const { data, error } = await db.auth.admin.mfa.listFactors({ userId: caller.user.id });
  if (error) throw new HttpError(503, "MFA_CHECK_FAILED", "Could not confirm this account's MFA state");
  const verified = (data?.factors ?? []).some((factor) => factor.status === "verified");
  if (verified && decodeJwtClaims(caller.token).aal !== "aal2") {
    throw new HttpError(403, "MFA_REQUIRED", "Complete authenticator verification on this device before linking another one");
  }
}

async function requireOwnDevice(db: SupabaseClient, userId: string, deviceId: unknown): Promise<string> {
  if (!isUuid(deviceId)) throw new HttpError(400, "BAD_DEVICE", "A device id is required");
  const { data, error } = await db
    .from("messaging_devices")
    .select("id,user_id,trust_state,revoked_at")
    .eq("id", deviceId)
    .maybeSingle();
  if (error) throw new HttpError(503, "STORAGE_ERROR", "Could not read the device registry");
  if (!data || data.user_id !== userId || data.revoked_at || data.trust_state === "revoked") {
    throw new HttpError(403, "NOT_YOUR_DEVICE", "That device does not belong to this account");
  }
  return deviceId;
}

function smsHookConfigured(): boolean {
  return Boolean(env("SEND_SMS_HOOK_SECRET")?.trim());
}

interface LinkRow {
  id: string;
  code_hash: string;
  claim_secret_hash: string;
  status: "pending" | "approved" | "claiming" | "consumed" | "rejected" | "failed";
  requester_label: string;
  requester_platform: string;
  requester_ip: string | null;
  user_id: string | null;
  credential_method: "email_token" | "sms_code" | null;
  sms_otp: string | null;
  linked_device_id: string | null;
  link_proof: string | null;
  failure_reason: string | null;
  created_at: string;
  expires_at: string;
}

const ROW_COLUMNS =
  "id,code_hash,claim_secret_hash,status,requester_label,requester_platform,requester_ip,user_id,credential_method,sms_otp,linked_device_id,link_proof,failure_reason,created_at,expires_at";

async function rowByCode(db: SupabaseClient, rawCode: unknown): Promise<LinkRow> {
  const code = normalizeLinkCode(rawCode);
  if (!code) throw new HttpError(400, "BAD_CODE", "That is not a QGuard link code");
  const { data, error } = await db.from(TABLE).select(ROW_COLUMNS).eq("code_hash", await sha256Hex(code)).maybeSingle();
  if (error) throw new HttpError(503, "STORAGE_ERROR", "Could not read link requests");
  if (!data) throw new HttpError(404, "LINK_NOT_FOUND", "No link request matches this code. Refresh the QR code on the new device and scan again.");
  return data as LinkRow;
}

/** Look up by id and prove possession of the claim secret. Unknown and wrong look the same. */
async function rowByClaim(db: SupabaseClient, linkId: unknown, claimSecret: unknown): Promise<LinkRow> {
  if (!isUuid(linkId) || !isSecret(claimSecret)) throw new HttpError(400, "BAD_REQUEST", "Link id and claim secret are required");
  const { data, error } = await db.from(TABLE).select(ROW_COLUMNS).eq("id", linkId).maybeSingle();
  if (error) throw new HttpError(503, "STORAGE_ERROR", "Could not read link requests");
  const row = data as LinkRow | null;
  if (!row || !timingSafeEqualText(row.claim_secret_hash, await sha256Hex(claimSecret))) {
    throw new HttpError(404, "LINK_NOT_FOUND", "This link request no longer exists");
  }
  return row;
}

function assertPendingAndLive(row: LinkRow): void {
  if (row.status !== "pending") throw new HttpError(409, "LINK_USED", "This QR code was already used. Ask the new device for a fresh one.");
  if (Date.now() > Date.parse(row.expires_at)) throw new HttpError(410, "LINK_EXPIRED", "This QR code has expired. Refresh it on the new device.");
}

async function markFailed(db: SupabaseClient, id: string, reason: string): Promise<void> {
  await db.from(TABLE).update({ status: "failed", failure_reason: reason.slice(0, 64), sms_otp: null }).eq("id", id);
}

// ---- routes ----------------------------------------------------------------

async function start(req: Request, db: SupabaseClient): Promise<Response> {
  const body = await readJson(req);
  const ip = clientIp(req.headers);
  const ipHash = await sha256Hex(`device-link-ip:${ip ?? "unknown"}`);
  const now = Date.now();

  // Housekeeping: requests (and the IPs they carry) do not outlive an hour past expiry.
  await db.from(TABLE).delete().lt("expires_at", new Date(now - 3600_000).toISOString());

  const { count, error: countError } = await db
    .from(TABLE)
    .select("id", { count: "exact", head: true })
    .eq("requester_ip_hash", ipHash)
    .gt("created_at", new Date(now - START_WINDOW_SECONDS * 1000).toISOString());
  if (countError) throw new HttpError(503, "STORAGE_ERROR", "Could not open a link request");
  if ((count ?? 0) >= MAX_STARTS_PER_IP) {
    throw new HttpError(429, "RATE_LIMITED", "Too many QR codes requested from this network. Wait a few minutes and try again.");
  }

  const label = sanitizeLabel(body.label);
  const platform = normalizePlatform(body.platform);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const code = generateLinkCode();
    const claimSecret = generateSecret();
    const expiresAt = new Date(now + LINK_TTL_SECONDS * 1000).toISOString();
    const { data, error } = await db
      .from(TABLE)
      .insert({
        code_hash: await sha256Hex(code),
        claim_secret_hash: await sha256Hex(claimSecret),
        requester_label: label,
        requester_platform: platform,
        requester_ip: ip,
        requester_ip_hash: ipHash,
        expires_at: expiresAt,
      })
      .select("id")
      .single();
    if (!error && data) {
      return json(200, { linkId: data.id, code, claimSecret, expiresAt, ttlSeconds: LINK_TTL_SECONDS, pollIntervalMs: 2000 });
    }
    if (error?.code !== "23505") break; // only a code collision is worth one retry
  }
  throw new HttpError(503, "STORAGE_ERROR", "Could not open a link request");
}

async function inspect(req: Request, db: SupabaseClient): Promise<Response> {
  await requireUser(req, db);
  // No per-user cap here: a code is 60 random bits alive for two minutes, so
  // guessing one is out of reach at any request rate this endpoint can serve.
  const row = await rowByCode(db, (await readJson(req)).code);
  assertPendingAndLive(row);
  return json(200, {
    linkId: row.id,
    label: row.requester_label,
    platform: row.requester_platform,
    ip: row.requester_ip,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  });
}

async function approve(req: Request, db: SupabaseClient): Promise<Response> {
  const caller = await requireUser(req, db);
  const body = await readJson(req);
  await requireAssurance(db, caller);

  const method = credentialMethodFor(caller.user);
  if (!method) {
    throw new HttpError(409, "NO_SIGN_IN_METHOD", "This account has no confirmed email or mobile number to sign a new device in with.");
  }
  if (method === "sms_code" && !smsHookConfigured()) {
    throw new HttpError(409, "SMS_LINK_UNAVAILABLE", "QR linking for mobile-number accounts is not enabled on this server yet. Sign in on the new device with your number and the SMS code instead.");
  }
  const approverDeviceId = body.deviceId == null ? null : await requireOwnDevice(db, caller.user.id, body.deviceId);

  const { count, error: countError } = await db
    .from(TABLE)
    .select("id", { count: "exact", head: true })
    .eq("user_id", caller.user.id)
    .neq("status", "rejected")
    .gt("created_at", new Date(Date.now() - APPROVAL_WINDOW_SECONDS * 1000).toISOString());
  if (countError) throw new HttpError(503, "STORAGE_ERROR", "Could not approve the link request");
  if ((count ?? 0) >= MAX_APPROVALS_PER_USER) {
    throw new HttpError(429, "RATE_LIMITED", "Too many devices linked in a short time. Wait a few minutes and try again.");
  }

  const row = await rowByCode(db, body.code);
  assertPendingAndLive(row);
  const { data, error } = await db
    .from(TABLE)
    .update({
      status: "approved",
      user_id: caller.user.id,
      approved_by_device_id: approverDeviceId,
      approved_at: new Date().toISOString(),
      credential_method: method,
    })
    .eq("id", row.id)
    .eq("status", "pending")
    .gt("expires_at", new Date().toISOString())
    .select("id");
  if (error) throw new HttpError(503, "STORAGE_ERROR", "Could not approve the link request");
  if (!data?.length) throw new HttpError(409, "LINK_USED", "This QR code was already used or has expired.");
  return json(200, { linkId: row.id, status: "approved", method });
}

async function reject(req: Request, db: SupabaseClient): Promise<Response> {
  const caller = await requireUser(req, db);
  const row = await rowByCode(db, (await readJson(req)).code);
  if (row.status !== "pending") return json(200, { linkId: row.id, status: row.status });
  await db.from(TABLE).update({ status: "rejected", user_id: caller.user.id }).eq("id", row.id).eq("status", "pending");
  return json(200, { linkId: row.id, status: "rejected" });
}

async function mintEmailToken(db: SupabaseClient, user: User): Promise<{ method: "email_token"; tokenHash: string }> {
  const { data, error } = await db.auth.admin.generateLink({ type: "magiclink", email: user.email! });
  const tokenHash = data?.properties?.hashed_token;
  if (error || !tokenHash) throw new Error("email_token_unavailable");
  return { method: "email_token", tokenHash };
}

async function mintSmsCode(db: SupabaseClient, row: LinkRow, user: User): Promise<{ method: "sms_code"; phone: string; code: string }> {
  if (!smsHookConfigured()) throw new Error("sms_hook_not_configured");
  const phone = e164(user.phone ?? "");
  await db.from(TABLE).update({ otp_requested_at: new Date().toISOString(), sms_otp: null }).eq("id", row.id);

  // Ask GoTrue for a code exactly as a sign-in would; the Send-SMS hook sees
  // this claim waiting and stores the code on the row instead of texting it.
  const response = await fetch(`${env("SUPABASE_URL")}/auth/v1/otp`, {
    method: "POST",
    headers: { apikey: env("SUPABASE_ANON_KEY") ?? "", "Content-Type": "application/json" },
    body: JSON.stringify({ phone, create_user: false, channel: "sms" }),
  });
  if (!response.ok) throw new Error(response.status === 429 ? "sms_rate_limited" : "sms_code_unavailable");

  const { data } = await db.from(TABLE).select("sms_otp").eq("id", row.id).maybeSingle();
  const code = (data as { sms_otp?: string | null } | null)?.sms_otp;
  if (!code) throw new Error("sms_hook_not_capturing");
  return { method: "sms_code", phone, code };
}

async function claim(req: Request, db: SupabaseClient): Promise<Response> {
  const body = await readJson(req);
  const row = await rowByClaim(db, body.linkId, body.claimSecret);
  const view = claimView(row, Date.now());
  if (view.status !== "ready") return json(200, view);

  // Exactly one poll wins the right to mint.
  const { data: won, error } = await db.from(TABLE).update({ status: "claiming" }).eq("id", row.id).eq("status", "approved").select("id");
  if (error) throw new HttpError(503, "STORAGE_ERROR", "Could not complete the link");
  if (!won?.length) return json(200, { status: "used" });

  try {
    const { data: found, error: userError } = await db.auth.admin.getUserById(row.user_id!);
    if (userError || !found?.user) throw new Error("account_unavailable");
    const credential = row.credential_method === "sms_code"
      ? await mintSmsCode(db, row, found.user)
      : await mintEmailToken(db, found.user);
    await db.from(TABLE).update({ status: "consumed", consumed_at: new Date().toISOString(), sms_otp: null }).eq("id", row.id);
    return json(200, { status: "approved", credential });
  } catch (cause) {
    const reason = cause instanceof Error ? cause.message : "link_failed";
    await markFailed(db, row.id, reason);
    return json(200, { status: "failed", reason });
  }
}

async function complete(req: Request, db: SupabaseClient): Promise<Response> {
  const caller = await requireUser(req, db);
  const body = await readJson(req);
  const row = await rowByClaim(db, body.linkId, body.claimSecret);
  if (row.user_id !== caller.user.id || row.status !== "consumed") {
    throw new HttpError(409, "LINK_NOT_COMPLETABLE", "This link request does not belong to this session");
  }
  if (!isHex64(body.proof)) throw new HttpError(400, "BAD_PROOF", "A link proof is required");
  const deviceId = await requireOwnDevice(db, caller.user.id, body.deviceId);
  await db.from(TABLE).update({ linked_device_id: deviceId, link_proof: body.proof }).eq("id", row.id);
  return json(200, { linkId: row.id, linkedDeviceId: deviceId });
}

async function status(req: Request, db: SupabaseClient): Promise<Response> {
  const caller = await requireUser(req, db);
  const linkId = (await readJson(req)).linkId;
  if (!isUuid(linkId)) throw new HttpError(400, "BAD_REQUEST", "A link id is required");
  const { data, error } = await db.from(TABLE).select(ROW_COLUMNS).eq("id", linkId).eq("user_id", caller.user.id).maybeSingle();
  if (error) throw new HttpError(503, "STORAGE_ERROR", "Could not read the link request");
  if (!data) throw new HttpError(404, "LINK_NOT_FOUND", "This link request no longer exists");
  const row = data as LinkRow;
  return json(200, {
    linkId: row.id,
    status: row.status,
    label: row.requester_label,
    linkedDeviceId: row.linked_device_id,
    linkProof: row.link_proof,
    failureReason: row.failure_reason,
  });
}

/** Supabase Auth "Send SMS" hook. Diverts a code a link claim asked for; texts every other one. */
async function smsHook(req: Request, db: SupabaseClient): Promise<Response> {
  const hookError = (httpCode: number, message: string) => json(httpCode, { error: { http_code: httpCode, message } });
  const secret = env("SEND_SMS_HOOK_SECRET")?.trim();
  if (!secret) return hookError(500, "SMS hook is not configured");
  const raw = await req.text();
  if (!(await verifyStandardWebhook(secret, req.headers, raw, Math.floor(Date.now() / 1000)))) {
    return hookError(401, "Invalid hook signature");
  }
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = null;
  }
  const payload = parseSmsHookPayload(parsed);
  if (!payload) return hookError(400, "Unsupported hook payload");

  const { data: captured } = await db
    .from(TABLE)
    .update({ sms_otp: payload.otp })
    .eq("user_id", payload.userId)
    .eq("status", "claiming")
    .eq("credential_method", "sms_code")
    .is("sms_otp", null)
    .gt("otp_requested_at", new Date(Date.now() - OTP_CAPTURE_WINDOW_SECONDS * 1000).toISOString())
    .select("id");
  if (captured?.length) return json(200, {});

  const twilio = twilioConfig(env);
  if (!twilio) return hookError(500, "SMS delivery is not configured");
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${twilio.accountSid}/Messages.json`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${btoa(`${twilio.accountSid}:${twilio.authToken}`)}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: twilioMessageForm(twilio, payload.phone, smsBody(payload.otp)),
  });
  if (!response.ok) return hookError(502, "The SMS provider rejected the message");
  return json(200, {});
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });
  const route = routeOf(req.url);
  try {
    if (req.method === "GET" && route === "/health") {
      return json(200, { ok: true, smsHook: smsHookConfigured(), twilio: Boolean(twilioConfig(env)) });
    }
    if (req.method !== "POST") throw new HttpError(405, "METHOD_NOT_ALLOWED", "Use POST");
    const db = serviceClient();
    switch (route) {
      case "/start": return await start(req, db);
      case "/inspect": return await inspect(req, db);
      case "/approve": return await approve(req, db);
      case "/reject": return await reject(req, db);
      case "/claim": return await claim(req, db);
      case "/complete": return await complete(req, db);
      case "/status": return await status(req, db);
      case "/sms-hook": return await smsHook(req, db);
      default: throw new HttpError(404, "NOT_FOUND", "Unknown route");
    }
  } catch (error) {
    if (error instanceof HttpError) return json(error.status, { error: { code: error.code, message: error.message } });
    console.error("device-link error", error instanceof Error ? error.message : String(error));
    return json(500, { error: { code: "INTERNAL", message: "Device linking failed. Try again." } });
  }
});
