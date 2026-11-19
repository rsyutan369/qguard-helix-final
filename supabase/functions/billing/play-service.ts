/**
 * QGuard subscription service — Google Play verification, RTDN lifecycle,
 * reconciliation and the account-facing subscription API.
 *
 * Runtime-agnostic: no Deno globals, no remote imports. The SAME module serves
 *   - the `billing` Supabase Edge Function (supabase/functions/billing/index.ts),
 *   - the Express API (src/api-server/subscriptions.ts + play-billing.ts),
 * so "how a Play purchase is verified and what it grants" has exactly one
 * implementation. Callers inject the service-role Supabase client, the env
 * getter and fetch; identity always comes from the caller's verified JWT.
 *
 * Source of truth: Google Play (via the Developer API) → billing_subscriptions
 * (one row per account) → user_entitlements (computed in the SAME transaction
 * by the database trigger in supabase/google-play-billing-v2.sql) → clients via
 * Supabase Realtime. Nothing the app reports is trusted except the purchase
 * token, which is only ever used to ask Google.
 */
import {
  BILLING_AUDIT,
  bearerToken,
  decodeJwt,
  decryptPurchaseToken,
  encryptPurchaseToken,
  type EnvGetter,
  GOOGLE_JWKS_URL,
  inboxClaimDecision,
  isPlausiblePurchaseToken,
  isPlayConfigured,
  isUuid,
  normalizeCycle,
  parseRtdnMessage,
  pemToDer,
  planChangeAction,
  PLAY_NOTIFICATION_TYPES,
  playAccountIdFor,
  playBindingMatches,
  playFacts,
  type PlayFacts,
  playInvoiceRow,
  playJwtSigningInput,
  playMayReplaceRow,
  playNotificationAuditAction,
  playPackageName,
  playProductIdFor,
  PlayPurchaseError,
  playServiceAccount,
  playSubscriptionRow,
  pubsubClaimsProblem,
  RECONCILE_STATUSES,
  RTDN_MAX_ATTEMPTS,
  rowGrantsAccess,
  sanitizeRtdnPayload,
  sha256Hex,
  timingSafeEqualText,
  tokenEncryptionKeyBytes,
  TIERS,
  base64Url,
} from "./logic.ts";
import { ENTITLEMENT_CATALOG, entitlementsForTier } from "./entitlements.ts";

// deno-lint-ignore no-explicit-any
type Db = any;

export interface ServiceDeps {
  env: EnvGetter;
  /** Service-role Supabase client (bypasses RLS; never exposed to clients). */
  db: Db;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  /** Stops a PayPal subscription a Play purchase supersedes (index.ts / paypal.ts provide it). */
  cancelPaypalSubscription?: (providerSubscriptionId: string, reason: string) => Promise<void>;
}

export class BillingHttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

const now = (deps: ServiceDeps) => (deps.nowMs ? deps.nowMs() : Date.now());
const isoNow = (deps: ServiceDeps) => new Date(now(deps)).toISOString();
const fetchOf = (deps: ServiceDeps) => deps.fetchImpl ?? fetch;

function logError(label: string, error: unknown) {
  console.error(`[billing] ${label}:`, error instanceof Error ? error.message : error);
}

async function mustSucceed(operation: PromiseLike<{ error: unknown }>, label: string): Promise<void> {
  const { error } = await operation;
  if (error) {
    const message = (error as { message?: string })?.message || (error as { code?: string })?.code || "database error";
    const wrapped = new Error(`${label} failed: ${message}`) as Error & { code?: string };
    wrapped.code = (error as { code?: string })?.code;
    throw wrapped;
  }
}

async function bestEffort(label: string, operation: () => PromiseLike<unknown>): Promise<void> {
  try {
    await operation();
  } catch (error) {
    logError(label, error);
  }
}

export async function audit(db: Db, userId: string | null, action: string, message: string, metadata: Record<string, unknown>) {
  if (!userId) return; // billing_audit_events.user_id is NOT NULL; unbound events stay in the inbox.
  await bestEffort("audit", async () => {
    const { error } = await db.from("billing_audit_events").insert({ user_id: userId, action, message, metadata });
    if (error) throw new Error(`${action}: ${error.message}`);
  });
}

async function notify(db: Db, userId: string, severity: string, title: string, message: string) {
  await bestEffort("notification", async () => {
    const { error } = await db.from("billing_notifications").insert({ user_id: userId, type: "subscription", severity, title, message });
    if (error) throw new Error(error.message);
  });
}

function day(iso: string | null): string {
  return iso ? iso.slice(0, 10) : "the end of the paid period";
}

// ---- Google Play Developer API client ----------------------------------------

const googleTokens = new Map<string, { token: string; expiresAt: number }>();

async function googleAccessToken(deps: ServiceDeps): Promise<string> {
  const account = playServiceAccount(deps.env);
  if (!account) throw new BillingHttpError(503, "PLAY_NOT_CONFIGURED", "Google Play Billing is not configured on the server");
  const cached = googleTokens.get(account.email);
  const nowMs = Date.now();
  if (cached && cached.expiresAt > nowMs + 60_000) return cached.token;
  const key = await crypto.subtle.importKey(
    "pkcs8",
    new Uint8Array(pemToDer(account.privateKey)),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const input = playJwtSigningInput(account.email, Math.floor(nowMs / 1000));
  const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(input)));
  const response = await fetchOf(deps)("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: `${input}.${base64Url(signature)}` }).toString(),
  });
  const body: Record<string, any> = await response.json().catch(() => ({}));
  if (!response.ok || !body?.access_token) {
    throw new Error(body?.error_description || body?.error || `Google token exchange failed (HTTP ${response.status})`);
  }
  googleTokens.set(account.email, { token: body.access_token, expiresAt: nowMs + (Number(body.expires_in) || 3000) * 1000 });
  return body.access_token;
}

export class PlayApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function playApi(deps: ServiceDeps, path: string, init: { method?: string; body?: unknown } = {}): Promise<Record<string, any>> {
  const token = await googleAccessToken(deps);
  const response = await fetchOf(deps)(
    `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(playPackageName(deps.env))}${path}`,
    {
      method: init.method ?? "GET",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    },
  );
  const text = await response.text();
  let body: Record<string, any> = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = {};
  }
  if (!response.ok) throw new PlayApiError(response.status, body?.error?.message || `Google Play API request failed (HTTP ${response.status})`);
  return body;
}

/** purchases.subscriptionsv2.get — the authoritative subscription state. */
export function getPlaySubscription(deps: ServiceDeps, purchaseToken: string) {
  return playApi(deps, `/purchases/subscriptionsv2/tokens/${encodeURIComponent(purchaseToken)}`);
}

/** purchases.subscriptions.acknowledge (subscriptionsv2 has no acknowledge method). */
function acknowledgePlay(deps: ServiceDeps, productId: string, purchaseToken: string) {
  return playApi(deps, `/purchases/subscriptions/${encodeURIComponent(productId)}/tokens/${encodeURIComponent(purchaseToken)}:acknowledge`, { method: "POST", body: {} });
}

const isGoneError = (error: unknown) => error instanceof PlayApiError && [400, 404, 410].includes(error.status);

// ---- Applying an authoritative Play resource ----------------------------------

type SubscriptionRow = {
  id: string;
  user_id: string;
  plan: string;
  status: string;
  provider: string | null;
  provider_subscription_id: string | null;
  linked_purchase_token_hash: string | null;
  purchase_token_encrypted: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean | null;
  cancelled_at: string | null;
  auto_renew: boolean | null;
  acknowledgement_state: string | null;
  billing_cycle: string | null;
};

const ROW_COLUMNS = "id, user_id, plan, status, provider, provider_subscription_id, linked_purchase_token_hash, purchase_token_encrypted, current_period_end, cancel_at_period_end, cancelled_at, auto_renew, acknowledgement_state, billing_cycle";

async function rowForUser(db: Db, userId: string): Promise<SubscriptionRow | null> {
  const { data, error } = await db.from("billing_subscriptions").select(ROW_COLUMNS).eq("user_id", userId).maybeSingle();
  if (error) throw new Error(`subscription lookup failed: ${error.message}`);
  return data ?? null;
}

async function rowForToken(db: Db, tokenHash: string, column = "provider_subscription_id"): Promise<SubscriptionRow | null> {
  const { data, error } = await db.from("billing_subscriptions").select(ROW_COLUMNS)
    .eq("provider", "google_play").eq(column, tokenHash).limit(1).maybeSingle();
  if (error) throw new Error(`play token lookup failed: ${error.message}`);
  return data ?? null;
}

async function insertInvoiceOnce(db: Db, row: Record<string, unknown>): Promise<boolean> {
  const reference = row.provider_invoice_id as string | null;
  if (reference) {
    const { data: existing, error } = await db.from("billing_invoices").select("id").eq("provider_invoice_id", reference).maybeSingle();
    if (error) throw new Error(`invoice lookup failed: ${error.message}`);
    if (existing?.id) return false;
  }
  const { error } = await db.from("billing_invoices").insert(row);
  if (error && (error as { code?: string }).code === "23505") return false;
  if (error) throw new Error(`invoice insert failed: ${error.message}`);
  return true;
}

export interface AppliedPlay {
  applied: boolean;
  userId: string;
  facts: PlayFacts;
  tokenHash: string;
  reason?: string;
}

/**
 * Write what Google says about one purchase token to the account it belongs
 * to. Idempotent: re-applying the same resource rewrites the same row, records
 * no second invoice, and adds no second lifecycle event.
 */
export async function applyPlayResource(
  deps: ServiceDeps,
  input: { resource: Record<string, any>; purchaseToken: string; userId: string; source: string; notificationType?: number | null },
): Promise<AppliedPlay> {
  const { db, env } = deps;
  const nowIso = isoNow(deps);
  const facts = playFacts(env, input.resource, now(deps));
  const tokenHash = await sha256Hex(input.purchaseToken);
  const linkedTokenHash = facts.linkedPurchaseToken ? await sha256Hex(facts.linkedPurchaseToken) : null;

  // One purchase token can only ever unlock ONE account (replay / sharing).
  const claimed = await rowForToken(db, tokenHash);
  if (claimed && claimed.user_id !== input.userId) {
    await audit(db, input.userId, BILLING_AUDIT.purchaseRejected, "Google Play purchase rejected: token already linked to another account", { purchaseTokenHash: tokenHash, source: input.source, reason: "TOKEN_ALREADY_CLAIMED" });
    throw new BillingHttpError(409, "TOKEN_ALREADY_CLAIMED", "This purchase is already linked to another QGuard account");
  }
  // A replacement (upgrade/downgrade) must stay on the account that owned the old token.
  if (linkedTokenHash) {
    const linkedOwner = await rowForToken(db, linkedTokenHash);
    if (linkedOwner && linkedOwner.user_id !== input.userId) {
      throw new BillingHttpError(409, "TOKEN_ALREADY_CLAIMED", "This purchase replaces a subscription that belongs to another QGuard account");
    }
  }

  const current = await rowForUser(db, input.userId);
  if (!playMayReplaceRow(current, { tokenHash, entitled: facts.mapped.entitled }, now(deps))) {
    await audit(db, input.userId, "play.stale_token_ignored", `Google Play ${facts.mapped.status} for a replaced or superseded purchase — current plan unchanged`, {
      purchaseTokenHash: tokenHash, state: facts.mapped.status, source: input.source,
    });
    return { applied: false, userId: input.userId, facts, tokenHash, reason: "superseded" };
  }

  const keyBytes = tokenEncryptionKeyBytes(env);
  const sameToken = current?.provider === "google_play" && current.provider_subscription_id === tokenHash;
  const tokenEncrypted = keyBytes ? await encryptPurchaseToken(keyBytes, input.purchaseToken) : sameToken ? current?.purchase_token_encrypted ?? null : null;
  const row = playSubscriptionRow(facts, { userId: input.userId, tokenHash, tokenEncrypted, linkedTokenHash }, sameToken ? current : null, nowIso);

  try {
    // The entitlement trigger recomputes user_entitlements in this same statement's transaction.
    await mustSucceed(db.from("billing_subscriptions").upsert(row, { onConflict: "user_id" }), "play subscription upsert");
  } catch (error) {
    if ((error as { code?: string }).code === "23505") {
      throw new BillingHttpError(409, "TOKEN_ALREADY_CLAIMED", "This purchase is already linked to another QGuard account");
    }
    throw error;
  }

  // A Play plan that replaces a live PayPal one must stop PayPal billing.
  if (facts.mapped.entitled && current?.provider === "paypal" && current.provider_subscription_id && rowGrantsAccess(current, now(deps)) && deps.cancelPaypalSubscription) {
    await bestEffort("cancel superseded PayPal subscription", () =>
      deps.cancelPaypalSubscription!(current.provider_subscription_id!, "Superseded by a Google Play subscription"));
    await audit(db, input.userId, BILLING_AUDIT.replaced, "PayPal subscription superseded by Google Play", { fromProvider: "paypal", providerSubscriptionId: current.provider_subscription_id, source: input.source });
  }

  if (facts.mapped.entitled) {
    await mustSucceed(db.from("profiles").update({ tier: facts.tier.toLowerCase(), updated_at: nowIso }).eq("id", input.userId), "profile tier mirror");
  }

  const invoice = playInvoiceRow(facts, input.userId, tokenHash, nowIso);
  if (invoice && await insertInvoiceOnce(db, invoice)) {
    await audit(db, input.userId, BILLING_AUDIT.paymentSucceeded, `Google Play payment: ${facts.tier} ${facts.cycle} ${(Number(invoice.amount_paid_cents) / 100).toFixed(2)} ${invoice.currency}${facts.testPurchase ? " (test purchase, not revenue)" : ""}`, {
      orderId: facts.orderId, purchaseTokenHash: tokenHash, amountCents: invoice.amount_paid_cents, currency: invoice.currency,
      amountSource: (invoice.metadata as Record<string, unknown>).amountSource, source: "google_play",
    });
  }

  // Acknowledge AFTER the purchase is durably recorded. Pending purchases are
  // never acknowledged; a failure leaves acknowledgement_state 'pending' and
  // the reconciliation sweep retries well inside Google's 3-day window.
  if (!facts.acknowledged && facts.mapped.entitled) {
    try {
      await acknowledgePlay(deps, facts.productId, input.purchaseToken);
      await mustSucceed(db.from("billing_subscriptions").update({ acknowledgement_state: "acknowledged" }).eq("user_id", input.userId).eq("provider_subscription_id", tokenHash), "acknowledgement state");
      await audit(db, input.userId, BILLING_AUDIT.purchaseAcknowledged, `Google Play purchase acknowledged (${facts.productId})`, { purchaseTokenHash: tokenHash, source: input.source });
    } catch (error) {
      logError("play acknowledge", error);
      await audit(db, input.userId, "purchase.acknowledge_failed", "Google Play acknowledgement failed — will retry", { purchaseTokenHash: tokenHash, error: error instanceof Error ? error.message.slice(0, 200) : "unknown" });
    }
  }

  await recordLifecycle(deps, { current, facts, tokenHash, linkedTokenHash, userId: input.userId, source: input.source, notificationType: input.notificationType ?? null });
  return { applied: true, userId: input.userId, facts, tokenHash };
}

/** Audit + customer notice for what this application of Google's state changed. */
async function recordLifecycle(
  deps: ServiceDeps,
  ctx: { current: SubscriptionRow | null; facts: PlayFacts; tokenHash: string; linkedTokenHash: string | null; userId: string; source: string; notificationType: number | null },
) {
  const { db } = deps;
  const { current, facts } = ctx;
  const sameToken = current?.provider === "google_play" && current.provider_subscription_id === ctx.tokenHash;
  const base = { purchaseTokenHash: ctx.tokenHash, productId: facts.productId, state: facts.mapped.status, source: ctx.source, notificationType: ctx.notificationType };
  const label = `${facts.tier} (${facts.cycle === "annual" ? "yearly" : "monthly"}, Google Play)`;

  if (!sameToken) {
    if (!facts.mapped.entitled) {
      if (facts.mapped.status === "incomplete") {
        await audit(db, ctx.userId, "purchase.pending", `Google Play purchase pending payment: ${label}`, base);
        await notify(db, ctx.userId, "info", "Purchase pending", `Your ${facts.tier} purchase is waiting for payment to complete in Google Play. Access starts once Google confirms it.`);
      }
      return;
    }
    const wasEntitled = current ? rowGrantsAccess(current, now(deps)) : false;
    const change = wasEntitled ? planChangeAction(current?.plan, facts.tier) : null;
    const action = ctx.linkedTokenHash && wasEntitled ? (change ?? BILLING_AUDIT.replaced) : change ?? BILLING_AUDIT.activated;
    await audit(db, ctx.userId, BILLING_AUDIT.purchaseVerified, `Google Play purchase verified: ${label}`, base);
    await audit(db, ctx.userId, action, `Google Play subscription ${action.split(".")[1]}: ${current?.plan && wasEntitled && current.plan !== facts.tier ? `${current.plan} → ` : ""}${facts.tier}`, { ...base, fromPlan: current?.plan ?? null, toPlan: facts.tier, linkedPurchaseTokenHash: ctx.linkedTokenHash });
    await notify(db, ctx.userId, "success", "Subscription active", `Your ${label} subscription is active${facts.expiryTime ? ` until ${day(facts.expiryTime)}, renewing automatically` : ""}.`);
    return;
  }

  const fromStatus = String(current?.status ?? "");
  const wasRenewing = Boolean(current?.auto_renew);
  const periodMoved = facts.expiryTime && current?.current_period_end && Date.parse(facts.expiryTime) > Date.parse(current.current_period_end);
  const notified = playNotificationAuditAction(ctx.notificationType);

  if (facts.mapped.entitled && !facts.mapped.autoRenew && wasRenewing) {
    await audit(db, ctx.userId, BILLING_AUDIT.cancelled, `Google Play renewal cancelled; access until ${facts.expiryTime}`, { ...base, accessUntil: facts.expiryTime, fromStatus });
    await notify(db, ctx.userId, "warning", "Subscription cancelled", `Your subscription is canceled and will remain active until ${day(facts.expiryTime)}.`);
  } else if (facts.mapped.entitled && facts.mapped.autoRenew && !wasRenewing && fromStatus && rowGrantsAccess(current!, now(deps))) {
    await audit(db, ctx.userId, BILLING_AUDIT.restarted, "Google Play renewal re-enabled", base);
  }
  if (periodMoved && facts.mapped.entitled) {
    await audit(db, ctx.userId, BILLING_AUDIT.renewed, `Google Play subscription renewed until ${facts.expiryTime}`, { ...base, previousPeriodEnd: current?.current_period_end, periodEnd: facts.expiryTime });
  }
  if (fromStatus !== facts.mapped.status) {
    const action = notified && notified !== BILLING_AUDIT.renewed && notified !== BILLING_AUDIT.cancelled && notified !== BILLING_AUDIT.activated
      ? notified
      : facts.mapped.status === "expired" ? BILLING_AUDIT.expired
      : facts.mapped.status === "past_due" ? BILLING_AUDIT.onHold
      : facts.mapped.status === "pending_renewal" ? BILLING_AUDIT.inGracePeriod
      : facts.mapped.status === "active" && (fromStatus === "past_due" || fromStatus === "pending_renewal") ? BILLING_AUDIT.recovered
      : BILLING_AUDIT.statusChanged;
    await audit(db, ctx.userId, action, `Google Play subscription: ${fromStatus || "none"} → ${facts.mapped.status}`, { ...base, fromStatus, toStatus: facts.mapped.status });
    const notices: Record<string, [string, string, string]> = {
      [BILLING_AUDIT.onHold]: ["critical", "Payment problem", "Google Play could not renew your subscription. Update your payment method in Google Play to restore access."],
      [BILLING_AUDIT.inGracePeriod]: ["warning", "Payment problem", "Google Play could not charge your payment method. Your access continues while Google retries — update your payment method in Google Play."],
      [BILLING_AUDIT.expired]: ["critical", "Subscription expired", `Your ${facts.tier} subscription has expired. Your account, billing history and on-device vault data are kept; subscribe again to restore access.`],
      [BILLING_AUDIT.revoked]: ["critical", "Subscription revoked", `Google Play revoked your ${facts.tier} subscription (for example after a refund). Your account and on-device data are kept.`],
      [BILLING_AUDIT.recovered]: ["success", "Payment recovered", `Your ${facts.tier} subscription is active again.`],
      [BILLING_AUDIT.suspended]: ["warning", "Subscription paused", `Your ${facts.tier} subscription is paused in Google Play.`],
    };
    const notice = notices[action];
    if (notice) await notify(db, ctx.userId, notice[0], notice[1], notice[2]);
  }
}

// ---- Rate limiting (works across Edge isolates and API pods) -------------------

export async function assertRateLimit(db: Db, userId: string, action: string, max: number, windowSeconds: number) {
  const since = new Date(Date.now() - windowSeconds * 1000).toISOString();
  const { count, error } = await db.from("billing_audit_events").select("id", { count: "exact", head: true })
    .eq("user_id", userId).eq("action", action).gte("created_at", since);
  if (error) throw new Error(`rate limit lookup failed: ${error.message}`);
  if ((count ?? 0) >= max) throw new BillingHttpError(429, "RATE_LIMITED", "Too many purchase checks — wait a minute and try again");
}

// ---- Account association (obfuscatedAccountId) --------------------------------

/** The obfuscated account id for this user, recorded so RTDN can map it back. */
export async function ensurePlayAccount(db: Db, userId: string): Promise<string> {
  const accountId = await playAccountIdFor(userId);
  await mustSucceed(db.from("billing_play_accounts").upsert({ user_id: userId, obfuscated_account_id: accountId }, { onConflict: "user_id" }), "play account association");
  return accountId;
}

async function userForBinding(db: Db, boundAccount: string): Promise<string | null> {
  if (!boundAccount) return null;
  if (isUuid(boundAccount)) return boundAccount; // builds before 2026-11-12 sent the raw user id
  const { data, error } = await db.from("billing_play_accounts").select("user_id").eq("obfuscated_account_id", boundAccount).maybeSingle();
  if (error) throw new Error(`play account lookup failed: ${error.message}`);
  return data?.user_id ?? null;
}

// ---- Customer: verify / restore ------------------------------------------------

export interface VerifyResult {
  productId: string;
  plan: string;
  cycle: string;
  status: string;
  entitled: boolean;
  expiryTime: string | null;
  autoRenew: boolean;
  pending: boolean;
  applied: boolean;
}

function requirePlay(env: EnvGetter) {
  if (!isPlayConfigured(env)) {
    throw new BillingHttpError(503, "PLAY_NOT_CONFIGURED", "Google Play purchases cannot be verified yet. You have not been charged by QGuard; please try again later.");
  }
}

/** The ONLY way a Play purchase unlocks an account. */
export async function verifyPurchase(deps: ServiceDeps, userId: string, purchaseToken: unknown, source = "client_verify"): Promise<VerifyResult> {
  requirePlay(deps.env);
  if (!isPlausiblePurchaseToken(purchaseToken)) throw new BillingHttpError(400, "INVALID_TOKEN", "Missing or malformed purchase token");
  const { db } = deps;
  await assertRateLimit(db, userId, "purchase.verify_requested", 20, 60);
  const tokenHash = await sha256Hex(purchaseToken);
  await audit(db, userId, "purchase.verify_requested", "Google Play purchase submitted for verification", { purchaseTokenHash: tokenHash, source });

  let resource: Record<string, any>;
  try {
    resource = await getPlaySubscription(deps, purchaseToken);
  } catch (error) {
    if (isGoneError(error)) {
      await audit(db, userId, BILLING_AUDIT.verificationFailed, "Google Play did not recognize the purchase token", { purchaseTokenHash: tokenHash, source, httpStatus: (error as PlayApiError).status });
      throw new BillingHttpError(400, "PURCHASE_NOT_FOUND", "Google Play did not recognize this purchase");
    }
    if (error instanceof BillingHttpError) throw error;
    logError("play verify", error);
    await audit(db, userId, BILLING_AUDIT.verificationFailed, "Google Play verification unavailable", { purchaseTokenHash: tokenHash, source });
    throw new BillingHttpError(502, "PLAY_VERIFY_FAILED", "Could not reach Google Play to verify the purchase — try again shortly");
  }

  let facts: PlayFacts;
  try {
    facts = playFacts(deps.env, resource, now(deps));
  } catch (error) {
    if (error instanceof PlayPurchaseError) {
      await audit(db, userId, BILLING_AUDIT.purchaseRejected, `Google Play purchase rejected: ${error.code}`, { purchaseTokenHash: tokenHash, source, reason: error.code });
      throw new BillingHttpError(400, error.code, error.message);
    }
    throw error;
  }
  if (!await playBindingMatches(facts.boundAccount, userId)) {
    const code = facts.boundAccount ? "ACCOUNT_MISMATCH" : "NOT_BOUND";
    await audit(db, userId, BILLING_AUDIT.purchaseRejected, `Google Play purchase rejected: ${code}`, { purchaseTokenHash: tokenHash, source, reason: code });
    throw new BillingHttpError(409, code, code === "NOT_BOUND"
      ? "This purchase is not linked to a QGuard account"
      : "This purchase belongs to a different QGuard account");
  }

  const applied = await applyPlayResource(deps, { resource, purchaseToken, userId, source });
  await bestEffort("verify ledger", () => db.from("play_webhook_events").insert({
    event_id: `verify_${tokenHash.slice(0, 32)}_${facts.orderId ?? facts.mapped.status}`,
    notification_type: source,
    purchase_token_hash: tokenHash,
    user_id: userId,
    status: "processed",
    processed_at: isoNow(deps),
    raw: { subscriptionState: resource?.subscriptionState ?? null, productId: facts.productId, orderId: facts.orderId },
  }));
  return {
    productId: facts.productId,
    plan: facts.tier,
    cycle: facts.cycle,
    status: facts.mapped.status,
    entitled: facts.mapped.entitled && applied.applied,
    expiryTime: facts.expiryTime,
    autoRenew: facts.mapped.autoRenew,
    pending: facts.mapped.status === "incomplete",
    applied: applied.applied,
  };
}

/** Restore: re-verify every token Google Play returns on this device. */
export async function restorePurchases(deps: ServiceDeps, userId: string, tokens: unknown) {
  requirePlay(deps.env);
  const list = Array.isArray(tokens) ? [...new Set(tokens.filter(isPlausiblePurchaseToken))].slice(0, 10) : [];
  await audit(deps.db, userId, BILLING_AUDIT.restoreInitiated, `Restore purchases started (${list.length} Google Play purchase${list.length === 1 ? "" : "s"})`, { count: list.length });
  const results: Array<{ ok: boolean; result?: VerifyResult; error?: { code: string; message: string } }> = [];
  for (const token of list) {
    try {
      results.push({ ok: true, result: await verifyPurchase(deps, userId, token, "restore") });
    } catch (error) {
      const err = error instanceof BillingHttpError ? { code: error.code, message: error.message } : { code: "RESTORE_FAILED", message: "Could not verify one purchase" };
      results.push({ ok: false, error: err });
    }
  }
  const restored = results.filter((entry) => entry.ok && entry.result?.entitled).length;
  await audit(deps.db, userId, BILLING_AUDIT.restoreCompleted, `Restore purchases finished: ${restored} active of ${list.length}`, { restored, checked: list.length });
  return { checked: list.length, restored, results, subscription: await subscriptionSummary(deps, userId) };
}

// ---- RTDN (Pub/Sub push) --------------------------------------------------------

let jwksCache: { keys: Map<string, CryptoKey>; fetchedAt: number } | null = null;

async function googleKey(deps: ServiceDeps, kid: string): Promise<CryptoKey | null> {
  if (!jwksCache || Date.now() - jwksCache.fetchedAt > 3600_000 || !jwksCache.keys.has(kid)) {
    const response = await fetchOf(deps)(GOOGLE_JWKS_URL);
    if (!response.ok) throw new Error(`Google JWKS fetch failed (HTTP ${response.status})`);
    const body = await response.json() as { keys?: Array<Record<string, any>> };
    const keys = new Map<string, CryptoKey>();
    for (const jwk of body.keys ?? []) {
      if (jwk.kty !== "RSA" || !jwk.kid) continue;
      keys.set(String(jwk.kid), await crypto.subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]));
    }
    jwksCache = { keys, fetchedAt: Date.now() };
  }
  return jwksCache.keys.get(kid) ?? null;
}

/**
 * Pub/Sub push authentication. With PLAY_RTDN_AUDIENCE set, a Google-signed
 * OIDC token for that audience (and PLAY_RTDN_SERVICE_ACCOUNT, when set) is
 * REQUIRED. With PLAY_RTDN_TOKEN set, the `?token=` shared secret is required
 * too. At least one must be configured or RTDN is refused outright.
 */
export async function authenticatePubsub(deps: ServiceDeps, request: { url: string; authorization: string | null }): Promise<string | null> {
  const audience = (deps.env("PLAY_RTDN_AUDIENCE") ?? "").trim();
  const secret = (deps.env("PLAY_RTDN_TOKEN") ?? "").trim();
  if (!audience && !secret) return "RTDN_DISABLED";
  if (secret) {
    const provided = new URL(request.url).searchParams.get("token") ?? "";
    if (!provided || !timingSafeEqualText(provided, secret)) return "BAD_SHARED_SECRET";
  }
  if (audience) {
    const jwt = bearerToken(request.authorization);
    const decoded = jwt ? decodeJwt(jwt) : null;
    if (!decoded || decoded.header?.alg !== "RS256" || !decoded.header?.kid) return "MISSING_OIDC_TOKEN";
    const problem = pubsubClaimsProblem(decoded.claims, { audience, email: (deps.env("PLAY_RTDN_SERVICE_ACCOUNT") ?? "").trim() || null }, Math.floor(Date.now() / 1000));
    if (problem) return `OIDC_${problem.toUpperCase()}`;
    const key = await googleKey(deps, String(decoded.header.kid));
    if (!key) return "OIDC_UNKNOWN_KEY";
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, new Uint8Array(decoded.signature), new TextEncoder().encode(decoded.signingInput));
    if (!ok) return "OIDC_BAD_SIGNATURE";
  }
  return null;
}

type InboxRow = { event_id: string; status: string | null; claimed_at: string | null; attempts: number | null };

async function claimInbox(deps: ServiceDeps, row: Record<string, unknown>): Promise<"run" | "duplicate" | "in-progress" | "dead-letter"> {
  const { db } = deps;
  const nowIso = isoNow(deps);
  const { error } = await db.from("play_webhook_events").insert({ ...row, status: "processing", claimed_at: nowIso, received_at: nowIso, attempts: 1 });
  if (!error) return "run";
  if ((error as { code?: string }).code !== "23505") throw new Error(`inbox claim failed: ${error.message}`);
  const { data: existing, error: readError } = await db.from("play_webhook_events").select("event_id, status, claimed_at, attempts").eq("event_id", row.event_id).maybeSingle();
  if (readError) throw new Error(`inbox read failed: ${readError.message}`);
  const decision = inboxClaimDecision(existing as InboxRow | null, now(deps));
  if (decision !== "run" || !existing) return decision;
  let reclaim = db.from("play_webhook_events")
    .update({ status: "processing", claimed_at: nowIso, attempts: (Number(existing.attempts) || 0) + 1 })
    .eq("event_id", row.event_id).eq("status", existing.status);
  reclaim = existing.claimed_at ? reclaim.eq("claimed_at", existing.claimed_at) : reclaim.is("claimed_at", null);
  const { data: reclaimed, error: reclaimError } = await reclaim.select("event_id");
  if (reclaimError) throw new Error(`inbox re-claim failed: ${reclaimError.message}`);
  return reclaimed && reclaimed.length > 0 ? "run" : "in-progress";
}

async function finishInbox(deps: ServiceDeps, eventId: string, patch: Record<string, unknown>) {
  await bestEffort("inbox finish", async () => {
    const { error } = await deps.db.from("play_webhook_events").update(patch).eq("event_id", eventId);
    if (error) throw new Error(error.message);
  });
}

/** Resolve which QGuard account a purchase token belongs to. */
async function userForToken(deps: ServiceDeps, tokenHash: string, resource: Record<string, any> | null): Promise<string | null> {
  const existing = await rowForToken(deps.db, tokenHash);
  if (existing) return existing.user_id;
  if (resource) {
    const linked = typeof resource.linkedPurchaseToken === "string" && resource.linkedPurchaseToken ? await rowForToken(deps.db, await sha256Hex(resource.linkedPurchaseToken)) : null;
    if (linked) return linked.user_id;
    return userForBinding(deps.db, String(resource?.externalAccountIdentifiers?.obfuscatedExternalAccountId ?? ""));
  }
  return null;
}

/** Process one subscription event: re-query Google, then apply. */
async function processSubscriptionToken(deps: ServiceDeps, purchaseToken: string, notificationType: number | null, source: string): Promise<string> {
  const tokenHash = await sha256Hex(purchaseToken);
  let resource: Record<string, any> | null = null;
  try {
    resource = await getPlaySubscription(deps, purchaseToken);
  } catch (error) {
    if (!isGoneError(error)) throw error;
    // Google no longer resolves the token: apply terminal states from the
    // notification itself so the account still locks.
    if (notificationType === 12 || notificationType === 13) {
      const row = await rowForToken(deps.db, tokenHash);
      if (row) {
        await mustSucceed(deps.db.from("billing_subscriptions").update({ status: "expired", auto_renew: false, cancel_at_period_end: false, updated_at: isoNow(deps) }).eq("id", row.id), "terminal play state");
        await audit(deps.db, row.user_id, notificationType === 12 ? BILLING_AUDIT.revoked : BILLING_AUDIT.expired, "Google Play subscription ended (token no longer resolvable)", { purchaseTokenHash: tokenHash, source });
      }
      return row ? "terminal_applied" : "unknown_token";
    }
    return "token_not_found";
  }
  const userId = await userForToken(deps, tokenHash, resource);
  if (!userId) {
    // Bought on a build that never reported the account, or the mapping is not
    // recorded yet: the app's own verify/restore will bind it. Retry later.
    throw new Error("UNBOUND: purchase is not yet linked to a QGuard account");
  }
  const facts = playFacts(deps.env, resource, now(deps));
  if (facts.boundAccount && !await playBindingMatches(facts.boundAccount, userId)) {
    throw new BillingHttpError(409, "ACCOUNT_MISMATCH", "purchase binding does not match the account that holds it");
  }
  const applied = await applyPlayResource(deps, { resource, purchaseToken, userId, source, notificationType });
  return applied.applied ? "applied" : applied.reason ?? "skipped";
}

/** A refund/chargeback Google reports for an order (voidedPurchaseNotification). */
async function processVoided(deps: ServiceDeps, voided: Record<string, any>): Promise<string> {
  const orderId = String(voided?.orderId ?? "");
  const nowIso = isoNow(deps);
  if (orderId) {
    const { data: invoice, error } = await deps.db.from("billing_invoices").select("id, user_id, amount_paid_cents, currency, subscription_plan, metadata").eq("provider_invoice_id", orderId).maybeSingle();
    if (error) throw new Error(`voided invoice lookup failed: ${error.message}`);
    if (invoice) {
      const metadata = (invoice.metadata ?? {}) as Record<string, unknown>;
      const full = Number(voided?.refundType ?? 1) === 1;
      if (!metadata.playVoidedAt) {
        await mustSucceed(deps.db.from("billing_invoices").update({
          status: "refunded",
          updated_at: nowIso,
          metadata: { ...metadata, playVoidedAt: nowIso, refundedAt: nowIso, refundType: full ? "full" : "partial", ...(full ? { refundedCents: invoice.amount_paid_cents } : {}) },
        }).eq("id", invoice.id), "voided invoice");
        await audit(deps.db, invoice.user_id, BILLING_AUDIT.paymentRefunded, `Google Play ${full ? "full" : "partial"} refund recorded for order ${orderId}`, { orderId, refundType: full ? "full" : "partial", source: "play.rtdn.voided" });
        await notify(deps.db, invoice.user_id, "warning", "Payment refunded", `A Google Play payment for your ${invoice.subscription_plan} subscription was refunded.`);
      }
    }
  }
  // Re-query: Google decides whether the refund also revoked access.
  const token = typeof voided?.purchaseToken === "string" ? voided.purchaseToken : "";
  if (token && Number(voided?.productType ?? 1) === 1) return processSubscriptionToken(deps, token, null, "play.rtdn.voided");
  return orderId ? "refund_recorded" : "ignored";
}

export async function handleRtdn(
  deps: ServiceDeps,
  request: { url: string; authorization: string | null; body: unknown },
): Promise<{ status: number; body: Record<string, unknown> }> {
  const authProblem = await authenticatePubsub(deps, request);
  if (authProblem === "RTDN_DISABLED") return { status: 503, body: { error: { code: authProblem, message: "RTDN authentication is not configured" } } };
  if (authProblem) {
    console.warn(`[billing] RTDN refused: ${authProblem}`);
    return { status: 401, body: { error: { code: "UNAUTHORIZED", message: "Unauthenticated push" } } };
  }
  if (!isPlayConfigured(deps.env)) return { status: 503, body: { error: { code: "PLAY_NOT_CONFIGURED", message: "Play verification is not configured" } } };

  const parsed = parseRtdnMessage(request.body);
  if (!parsed) return { status: 200, body: { received: true, ignored: "malformed" } };
  const { messageId, payload } = parsed;
  if (payload?.testNotification) return { status: 200, body: { received: true, test: true } };
  if (payload?.packageName && payload.packageName !== playPackageName(deps.env)) return { status: 200, body: { received: true, ignored: "package_mismatch" } };

  const subscription = payload?.subscriptionNotification ?? null;
  const voided = payload?.voidedPurchaseNotification ?? null;
  if (!subscription && !voided) return { status: 200, body: { received: true, ignored: "not_subscription" } };
  const purchaseToken = String(subscription?.purchaseToken ?? voided?.purchaseToken ?? "");
  const tokenHash = purchaseToken ? await sha256Hex(purchaseToken) : null;
  const eventId = `rtdn_${messageId || await sha256Hex(JSON.stringify(payload))}`;
  const notificationType = subscription ? Number(subscription.notificationType) : null;
  const keyBytes = tokenEncryptionKeyBytes(deps.env);

  // Persist BEFORE processing (the inbox is the durable record), then process.
  const claim = await claimInbox(deps, {
    event_id: eventId,
    message_id: messageId || null,
    notification_type: subscription ? (PLAY_NOTIFICATION_TYPES[notificationType!] ?? String(notificationType)) : "VOIDED_PURCHASE",
    purchase_token_hash: tokenHash,
    purchase_token_encrypted: keyBytes && purchaseToken ? await encryptPurchaseToken(keyBytes, purchaseToken) : null,
    raw: sanitizeRtdnPayload(payload),
  });
  if (claim === "duplicate" || claim === "dead-letter") return { status: 200, body: { received: true, duplicate: claim === "duplicate", deadLetter: claim === "dead-letter" } };
  if (claim === "in-progress") return { status: 409, body: { received: false, error: "event_in_progress" } };

  try {
    const outcome = voided ? await processVoided(deps, voided) : await processSubscriptionToken(deps, purchaseToken, notificationType, "play.rtdn");
    const userId = tokenHash ? (await rowForToken(deps.db, tokenHash))?.user_id ?? null : null;
    await finishInbox(deps, eventId, { status: "processed", processed_at: isoNow(deps), last_error: null, outcome, user_id: userId });
    return { status: 200, body: { received: true, outcome } };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const { data: current } = await deps.db.from("play_webhook_events").select("attempts").eq("event_id", eventId).maybeSingle();
    const attempts = Number(current?.attempts ?? 1);
    const dead = attempts >= RTDN_MAX_ATTEMPTS;
    await finishInbox(deps, eventId, { status: dead ? "dead_letter" : "failed", last_error: message.slice(0, 500) });
    logError(`RTDN ${eventId} (attempt ${attempts})`, message);
    // Dead-lettered messages stop retrying (200) and stay visible to the admin dashboard.
    return dead ? { status: 200, body: { received: true, deadLetter: true } } : { status: 500, body: { received: false, error: "processing_failed" } };
  }
}

// ---- Reconciliation ------------------------------------------------------------

/**
 * Re-query Google for every Play row that may have drifted: near or past its
 * period end, unacknowledged, or not verified for a day — plus inbox messages
 * whose processing failed. Needs PLAY_TOKEN_ENCRYPTION_KEY (a hash cannot be
 * used to ask Google again).
 */
export async function reconcilePlay(deps: ServiceDeps) {
  const summary = { playChecked: 0, playUpdated: 0, playErrors: 0, inboxRetried: 0, inboxRecovered: 0, skippedNoKey: 0 };
  if (!isPlayConfigured(deps.env)) return { ...summary, skipped: "PLAY_NOT_CONFIGURED" };
  const keyBytes = tokenEncryptionKeyBytes(deps.env);
  if (!keyBytes) return { ...summary, skipped: "PLAY_TOKEN_ENCRYPTION_KEY missing" };
  const soon = new Date(now(deps) + 3600_000).toISOString();
  const stale = new Date(now(deps) - 24 * 3600_000).toISOString();
  const { data: rows, error } = await deps.db.from("billing_subscriptions")
    .select("user_id, purchase_token_encrypted, provider_subscription_id")
    .eq("provider", "google_play")
    .in("status", RECONCILE_STATUSES)
    .or(`current_period_end.lte.${soon},acknowledgement_state.eq.pending,last_verified_at.lte.${stale},last_verified_at.is.null`)
    .limit(100);
  if (error) throw new Error(`play reconcile query failed: ${error.message}`);
  for (const row of rows ?? []) {
    if (!row.purchase_token_encrypted) { summary.skippedNoKey += 1; continue; }
    summary.playChecked += 1;
    try {
      const token = await decryptPurchaseToken(keyBytes, row.purchase_token_encrypted);
      const outcome = await processSubscriptionToken(deps, token, null, "play.reconcile");
      if (outcome === "applied" || outcome === "terminal_applied") summary.playUpdated += 1;
    } catch (err) {
      summary.playErrors += 1;
      logError(`play reconcile ${String(row.provider_subscription_id).slice(0, 12)}`, err);
      await audit(deps.db, row.user_id, "billing.reconciliation_error", "Google Play reconciliation failed for this subscription", { purchaseTokenHash: row.provider_subscription_id, error: err instanceof Error ? err.message.slice(0, 200) : "unknown" });
    }
  }
  const olderThan = new Date(now(deps) - 15 * 60_000).toISOString();
  const { data: failed } = await deps.db.from("play_webhook_events")
    .select("event_id, purchase_token_encrypted, notification_type, attempts")
    .eq("status", "failed").lte("claimed_at", olderThan).not("purchase_token_encrypted", "is", null).limit(50);
  for (const message of failed ?? []) {
    summary.inboxRetried += 1;
    const attempts = (Number(message.attempts) || 0) + 1;
    try {
      const token = await decryptPurchaseToken(keyBytes, message.purchase_token_encrypted);
      const outcome = await processSubscriptionToken(deps, token, null, "play.reconcile.inbox");
      await finishInbox(deps, message.event_id, { status: "processed", processed_at: isoNow(deps), last_error: null, outcome, attempts });
      summary.inboxRecovered += 1;
    } catch (err) {
      await finishInbox(deps, message.event_id, { status: attempts >= RTDN_MAX_ATTEMPTS ? "dead_letter" : "failed", attempts, claimed_at: isoNow(deps), last_error: (err instanceof Error ? err.message : String(err)).slice(0, 500) });
    }
  }
  return summary;
}

// ---- Account-facing subscription API -------------------------------------------

export async function subscriptionCatalog(deps: ServiceDeps, platform: string | null) {
  let query = deps.db.from("subscription_products")
    .select("product_id, tier, billing_period, platform, display_name, description, price_amount, currency, is_active, sort_order")
    .eq("is_active", true).order("sort_order", { ascending: true });
  if (platform) query = query.eq("platform", platform);
  const { data, error } = await query;
  if (error) throw new BillingHttpError(503, "CATALOG_UNAVAILABLE", "The subscription catalog is unavailable");
  const products = (data ?? []).map((row: Record<string, any>) => ({
    productId: row.product_id,
    tier: row.tier,
    billingPeriod: row.billing_period,
    platform: row.platform,
    displayName: row.display_name,
    description: row.description,
    // USD list price for display where the store cannot localize it; Google
    // Play's ProductDetails price is what an Android buyer is charged.
    listPrice: { amount: Number(row.price_amount), currency: row.currency },
  }));
  const tiers = TIERS.map((tier) => ({
    tier,
    entitlements: ENTITLEMENT_CATALOG.filter((entry) => entry.minTier === tier).map(({ key, label }) => ({ key, label })),
    includes: TIERS.slice(0, TIERS.indexOf(tier)),
  }));
  const annualDiscount = products.some((yearly) => yearly.billingPeriod === "yearly" && products.some((monthly) =>
    monthly.billingPeriod === "monthly" && monthly.platform === yearly.platform && monthly.tier === yearly.tier &&
    monthly.listPrice.currency === yearly.listPrice.currency && yearly.listPrice.amount < monthly.listPrice.amount * 12
  ));
  return {
    products,
    tiers,
    rules: { freeTier: false, freeTrial: false, annualDiscount, moneyBackGuarantee: false },
    playProducts: Object.fromEntries(TIERS.map((tier) => [tier, { monthly: playProductIdFor(deps.env, tier, "monthly"), yearly: playProductIdFor(deps.env, tier, "yearly") }])),
  };
}

export async function effectiveEntitlements(deps: ServiceDeps, userId: string) {
  const { data, error } = await deps.db.from("user_entitlements")
    .select("entitlement_key, is_enabled, valid_from, valid_until, source_subscription_id")
    .eq("user_id", userId).eq("is_enabled", true);
  if (error) throw new Error(`entitlement lookup failed: ${error.message}`);
  const nowMs = now(deps);
  const active = (data ?? []).filter((row: Record<string, any>) => !row.valid_until || Date.parse(row.valid_until) > nowMs);
  return {
    keys: active.map((row: Record<string, any>) => row.entitlement_key).sort(),
    validUntil: active.reduce((max: string | null, row: Record<string, any>) => (row.valid_until && (!max || row.valid_until > max) ? row.valid_until : max), null),
  };
}

const PROVIDER_LABELS: Record<string, string> = { google_play: "Google Play", paypal: "PayPal", manual: "QGuard (complimentary)" };

export async function subscriptionSummary(deps: ServiceDeps, userId: string) {
  const { data, error } = await deps.db.from("billing_subscriptions")
    .select("plan, status, provider, billing_cycle, auto_renew, cancel_at_period_end, current_period_start, current_period_end, renewal_date, cancelled_at, created_at, updated_at, product_id, acknowledgement_state, verification_state, last_verified_at")
    .eq("user_id", userId).maybeSingle();
  if (error) throw new Error(`subscription lookup failed: ${error.message}`);
  const entitlements = await effectiveEntitlements(deps, userId);
  if (!data) return { subscription: null, access: false, entitlements, message: "No active subscription. Choose a plan to get started." };
  const access = rowGrantsAccess(data, now(deps));
  const cancelledButActive = access && Boolean(data.cancel_at_period_end);
  return {
    subscription: {
      plan: data.plan,
      status: data.status,
      provider: data.provider,
      providerLabel: PROVIDER_LABELS[String(data.provider)] ?? data.provider,
      productId: data.product_id,
      billingPeriod: data.billing_cycle === "annual" ? "yearly" : "monthly",
      purchaseDate: data.created_at,
      currentPeriodStart: data.current_period_start,
      // Only a renewing subscription has a next renewal; never a guessed date.
      nextRenewal: access && data.auto_renew && !data.cancel_at_period_end ? data.renewal_date ?? data.current_period_end : null,
      expiration: data.current_period_end,
      autoRenew: Boolean(data.auto_renew) && !data.cancel_at_period_end,
      cancelled: Boolean(data.cancel_at_period_end) || data.status === "cancelled",
      cancelledAt: data.cancelled_at,
      verificationState: data.verification_state,
      lastVerifiedAt: data.last_verified_at,
    },
    access,
    entitlements,
    message: cancelledButActive && data.current_period_end
      ? `Your subscription is canceled and will remain active until ${day(data.current_period_end)}.`
      : null,
  };
}

export async function subscriptionHistory(deps: ServiceDeps, userId: string) {
  const [invoices, events] = await Promise.all([
    deps.db.from("billing_invoices").select("id, invoice_id, payment_date, amount_paid_cents, currency, payment_method_summary, subscription_plan, status, created_at")
      .eq("user_id", userId).order("created_at", { ascending: false }).limit(50),
    deps.db.from("billing_audit_events").select("id, action, message, created_at")
      .eq("user_id", userId).not("action", "in", "(purchase.verify_requested)").order("created_at", { ascending: false }).limit(100),
  ]);
  if (invoices.error) throw new Error(`invoice history failed: ${invoices.error.message}`);
  if (events.error) throw new Error(`event history failed: ${events.error.message}`);
  return { invoices: invoices.data ?? [], events: events.data ?? [] };
}

/** Normalised `?platform=` (catalog filter). */
export function platformParam(value: string | null): string | null {
  const text = String(value ?? "").toLowerCase();
  return text === "google_play" || text === "android" ? "google_play" : text === "paypal" || text === "web" || text === "desktop" ? "paypal" : null;
}

export { entitlementsForTier, normalizeCycle };
