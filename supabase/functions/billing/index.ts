/**
 * QGuard billing service — Supabase Edge Function (`/functions/v1/billing`).
 *
 * Why this exists: the QGuard Messaging apps sent every checkout to
 * `https://api.qguard.dev`, a domain that does not exist, and the Express
 * billing router (src/api-server/paypal.ts + billing.ts) had never been deployed
 * anywhere public — so "Upgrade" failed with "Failed to fetch" and no PayPal
 * webhook could ever activate a subscription. This function is the public
 * billing endpoint, on the project that already holds the billing tables.
 *
 * Routes (the same `/api/v1/...` paths as the Express API):
 *   GET  /health                                 configuration booleans only
 *   POST /api/v1/paypal/subscribe                start or change a plan (auth)
 *   POST /api/v1/paypal/confirm                  activate from PayPal's own state (auth)
 *   POST /api/v1/billing/subscription/actions    cancel | reactivate (auth)
 *   POST /api/v1/paypal/webhook                  PayPal events (PayPal signature)
 *   POST /api/v1/paypal/reconcile                missed-webhook repair (X-Reconcile-Secret, scheduled)
 *   GET  /api/v1/subscriptions/catalog           plans, products, tier entitlements (public)
 *   GET  /api/v1/subscriptions/me                verified subscription + playAccountId (auth)
 *   GET  /api/v1/subscriptions/entitlements      effective entitlement keys (auth)
 *   GET  /api/v1/subscriptions/history           invoices + lifecycle events (auth)
 *   POST /api/v1/subscriptions/verify            verify a Google Play purchase token (auth; alias /play-billing/verify)
 *   POST /api/v1/subscriptions/restore           re-verify the device's Play purchases (auth)
 *   POST /api/v1/webhooks/google-play/rtdn       Play RTDN, authenticated Pub/Sub push (alias /play-billing/rtdn)
 *
 * Google Play logic lives in play-service.ts, shared with the Express API.
 * Deployed with verify_jwt = false because PayPal's webhook carries no Supabase
 * JWT. Every user route verifies the caller's access token itself
 * (auth.getUser), and identity always comes from that token — never the body.
 *
 * Secrets (Edge Function secrets): PAYPAL_CLIENT_ID, PAYPAL_SECRET_KEY,
 * PAYPAL_ENV, PAYPAL_WEBHOOK_ID, PAYPAL_PLAN_<TIER>_<CYCLE> (8), optional
 * APP_ORIGIN, PAYPAL_RECONCILE_SECRET (enables /reconcile). Google Play (optional; /health reports playVerification only
 * when set): GOOGLE_PLAY_PACKAGE_NAME, GOOGLE_PLAY_SERVICE_ACCOUNT_JSON (or
 * GOOGLE_PLAY_SA_EMAIL + GOOGLE_PLAY_SA_PRIVATE_KEY), PLAY_TOKEN_ENCRYPTION_KEY
 * (32 random bytes, base64), RTDN auth: PLAY_RTDN_AUDIENCE (+ optional
 * PLAY_RTDN_SERVICE_ACCOUNT) for Pub/Sub OIDC and/or PLAY_RTDN_TOKEN; optional
 * PLAY_PRODUCT_<TIER>_<CYCLE>. SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are
 * provided by the runtime.
 */
import { createClient, type SupabaseClient } from "jsr:@supabase/supabase-js@2";
import {
  activationAuditAction,
  activationRow,
  appOrigin,
  approvalLink,
  bearerToken,
  BILLING_AUDIT,
  type BillingAuditAction,
  cancellationPatch,
  configurationReport,
  type Cycle,
  failedPaymentInvoiceRow,
  invoiceRow,
  isAccessGranting,
  isPaypalConfigured,
  isCancellationRecorded,
  moneyBackRefundCancels,
  invoiceRowFromTransaction,
  reconcileAction,
  RECONCILE_CHECKOUT_LOOKBACK_DAYS,
  RECONCILE_PAYMENT_LOOKBACK_DAYS,
  RECONCILE_STATUSES,
  refundCancellationPatch,
  timingSafeEqualText,
  isPaypalSubscriptionId,
  isUuid,
  mapPaypalStatus,
  normalizeCycle,
  normalizeTier,
  paypalApiBase,
  paypalSecret,
  planChangeAction,
  planEnvKey,
  planIdFor,
  planInfoFromId,
  refundInvoicePatch,
  REVISABLE_STATUSES,
  routeOf,
  statusAuditAction,
  type Tier,
  toDbCycle,
  webhookClaimDecision,
  webhookVerificationBody,
} from "./logic.ts";
import {
  BillingHttpError,
  effectiveEntitlements,
  ensurePlayAccount,
  handleRtdn,
  platformParam,
  reconcilePlay,
  restorePurchases,
  type ServiceDeps,
  subscriptionCatalog,
  subscriptionHistory,
  subscriptionSummary,
  verifyPurchase,
} from "./play-service.ts";

const env = (key: string) => Deno.env.get(key);

// Bearer-token API with no cookies or other ambient credentials: a foreign page
// cannot obtain the user's access token, so a wildcard origin grants it nothing.
// An allowlist, by contrast, silently re-creates "Failed to fetch" for any
// webview origin it forgets (tauri.localhost over http or https, tauri://).
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

function fail(status: number, code: string, message: string): Response {
  return json(status, { error: { code, message } });
}

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

function serviceClient(): SupabaseClient {
  const url = env("SUPABASE_URL");
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) throw new HttpError(503, "SERVICE_UNAVAILABLE", "Billing storage is not configured");
  return createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
}

async function requireUser(req: Request, db: SupabaseClient): Promise<{ id: string; email: string | null }> {
  const token = bearerToken(req.headers.get("Authorization"));
  if (!token) throw new HttpError(401, "UNAUTHORIZED", "Sign in to manage your subscription");
  const { data, error } = await db.auth.getUser(token);
  if (error || !data?.user) throw new HttpError(401, "UNAUTHORIZED", "Your session has expired — sign in again");
  return { id: data.user.id, email: data.user.email ?? null };
}

async function readJson(req: Request): Promise<Record<string, unknown>> {
  try {
    const value = await req.json();
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

// ---- PayPal REST client ----------------------------------------------------

let cachedToken: { token: string; expiresAt: number } | null = null;

async function paypalToken(): Promise<string> {
  if (!isPaypalConfigured(env)) throw new HttpError(503, "PAYPAL_NOT_CONFIGURED", "PayPal is not configured on the billing service");
  const now = Date.now();
  if (cachedToken && cachedToken.expiresAt > now + 60_000) return cachedToken.token;
  const basic = btoa(`${(env("PAYPAL_CLIENT_ID") ?? "").trim()}:${paypalSecret(env)}`);
  const response = await fetch(`${paypalApiBase(env)}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || !body?.access_token) {
    throw new HttpError(502, "PAYPAL_AUTH_FAILED", body?.error_description || `PayPal authentication failed (HTTP ${response.status})`);
  }
  cachedToken = { token: body.access_token, expiresAt: now + (Number(body.expires_in) || 3000) * 1000 };
  return cachedToken.token;
}

async function paypal(path: string, init: { method?: string; body?: string; headers?: Record<string, string> } = {}): Promise<any> {
  const token = await paypalToken();
  const response = await fetch(`${paypalApiBase(env)}${path}`, {
    method: init.method ?? "GET",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(init.headers ?? {}) },
    body: init.body,
  });
  const text = await response.text();
  let body: any = {};
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = {};
    }
  }
  if (!response.ok) {
    const detail = body?.details?.[0]?.description || body?.message || `HTTP ${response.status}`;
    const error = new HttpError(502, body?.name || "PAYPAL_REQUEST_FAILED", `PayPal: ${detail}`);
    (error as HttpError & { paypalName?: string }).paypalName = body?.name;
    throw error;
  }
  return body;
}

function requirePlanId(tier: Tier, cycle: Cycle): string {
  const planId = planIdFor(env, tier, cycle);
  if (!planId) throw new HttpError(503, "PLAN_NOT_CONFIGURED", `PayPal plan ${planEnvKey(tier, cycle)} is not configured`);
  return planId;
}

function applicationContext(returnUrl: string, cancelUrl: string) {
  return {
    brand_name: "QGuard Helix",
    locale: "en-US",
    shipping_preference: "NO_SHIPPING",
    user_action: "SUBSCRIBE_NOW",
    return_url: returnUrl,
    cancel_url: cancelUrl,
  };
}

async function createPaypalSubscription(opts: {
  userId: string;
  email: string | null;
  tier: Tier;
  cycle: Cycle;
  returnUrl: string;
  cancelUrl: string;
}): Promise<{ approvalUrl: string; subscriptionId: string }> {
  const created = await paypal("/v1/billing/subscriptions", {
    method: "POST",
    headers: { "PayPal-Request-Id": `qguard-sub-${opts.userId}-${opts.tier}-${opts.cycle}-${Date.now()}` },
    body: JSON.stringify({
      plan_id: requirePlanId(opts.tier, opts.cycle),
      custom_id: opts.userId,
      subscriber: opts.email ? { email_address: opts.email } : undefined,
      application_context: {
        ...applicationContext(opts.returnUrl, opts.cancelUrl),
        payment_method: { payer_selected: "PAYPAL", payee_preferred: "IMMEDIATE_PAYMENT_REQUIRED" },
      },
    }),
  });
  const approvalUrl = approvalLink(created);
  if (!approvalUrl || typeof created?.id !== "string") {
    throw new HttpError(502, "NO_APPROVAL_URL", "PayPal did not return a checkout link");
  }
  return { approvalUrl, subscriptionId: created.id };
}

/** Change an existing subscription in place (PayPal prorates; same id, no double billing). */
async function revisePaypalSubscription(subscriptionId: string, tier: Tier, cycle: Cycle, returnUrl: string, cancelUrl: string) {
  const revised = await paypal(`/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}/revise`, {
    method: "POST",
    body: JSON.stringify({ plan_id: requirePlanId(tier, cycle), application_context: applicationContext(returnUrl, cancelUrl) }),
  });
  return { approvalUrl: approvalLink(revised) };
}

// ---- Persistence -------------------------------------------------------------

async function mustSucceed(operation: PromiseLike<{ error: unknown }>, label: string): Promise<void> {
  const { error } = await operation;
  if (error) {
    const message = (error as { message?: string; code?: string })?.message || (error as { code?: string })?.code || "database error";
    throw new Error(`${label} failed: ${message}`);
  }
}

async function bestEffort(label: string, operation: () => PromiseLike<unknown>): Promise<void> {
  try {
    await operation();
  } catch (error) {
    console.error(`[billing] ${label} failed:`, error instanceof Error ? error.message : error);
  }
}

/**
 * Audit and notification writes never fail the delivery, but a failed write is
 * LOGGED: supabase-js reports it in `{ error }` rather than throwing, so a bare
 * try/catch would drop the record without a trace.
 */
async function audit(db: SupabaseClient, userId: string, action: string, message: string, metadata: Record<string, unknown>) {
  await bestEffort("audit", async () => {
    const { error } = await db.from("billing_audit_events").insert({ user_id: userId, action, message, metadata });
    if (error) throw new Error(`${action}: ${error.message}`);
  });
}

async function notify(db: SupabaseClient, userId: string, type: string, severity: string, title: string, message: string) {
  await bestEffort("notification", async () => {
    const { error } = await db.from("billing_notifications").insert({ user_id: userId, type, severity, title, message });
    if (error) throw new Error(error.message);
  });
}

const PLAN_CHANGE_COPY: Partial<Record<BillingAuditAction, { title: string; verb: string }>> = {
  [BILLING_AUDIT.activated]: { title: "Subscription activated", verb: "is now active" },
  [BILLING_AUDIT.upgraded]: { title: "Plan upgraded", verb: "upgrade is active" },
  [BILLING_AUDIT.downgraded]: { title: "Plan changed", verb: "plan change is active" },
};

/** Audit + customer notification for an activation or plan change. */
async function recordActivation(
  db: SupabaseClient,
  activated: { userId: string; tier: Tier; action: BillingAuditAction | null; previousPlan: string | null },
  providerSubscriptionId: string | null,
  source: string,
) {
  if (!activated.action) return;
  const copy = PLAN_CHANGE_COPY[activated.action] ?? PLAN_CHANGE_COPY[BILLING_AUDIT.activated]!;
  await notify(db, activated.userId, "subscription", "success", copy.title, `Your ${activated.tier} subscription ${copy.verb} via PayPal.`);
  await audit(db, activated.userId, activated.action, `PayPal subscription ${activated.action.split(".")[1]}: ${activated.previousPlan && activated.previousPlan !== activated.tier ? `${activated.previousPlan} → ` : ""}${activated.tier}`, {
    providerSubscriptionId,
    fromPlan: activated.previousPlan,
    toPlan: activated.tier,
    source,
  });
}

async function currentSubscription(db: SupabaseClient, userId: string) {
  const { data, error } = await db
    .from("billing_subscriptions")
    .select("id, plan, status, provider, provider_subscription_id, billing_cycle, renewal_date, current_period_end, cancel_at_period_end, cancelled_at")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw new Error(`subscription lookup failed: ${error.message}`);
  return data as {
    id: string;
    plan: string;
    status: string;
    provider: string | null;
    provider_subscription_id: string | null;
    billing_cycle: string | null;
    renewal_date: string | null;
    current_period_end: string | null;
    cancel_at_period_end: boolean | null;
    cancelled_at: string | null;
  } | null;
}

/**
 * Persist an ACTIVE PayPal subscription (webhook and confirm share this).
 * `action` is the audit transition this statement represents, or null when it
 * only re-states what we already hold (the second of confirm + webhook).
 */
async function activate(
  db: SupabaseClient,
  resource: Record<string, any>,
): Promise<{ userId: string; tier: Tier; action: BillingAuditAction | null; previousPlan: string | null } | null> {
  const activation = activationRow(env, resource, new Date().toISOString());
  if (!activation) return null;
  const { userId, tier, row } = activation;
  const previous = await currentSubscription(db, userId);

  // A new subscription that supersedes an older PayPal one (a plan change made
  // by checkout rather than revise) must stop the old one billing.
  await bestEffort("cancel superseded subscription", async () => {
    const prior = previous?.provider_subscription_id;
    if (previous?.provider === "paypal" && prior && prior !== resource?.id) {
      await paypal(`/v1/billing/subscriptions/${encodeURIComponent(prior)}/cancel`, {
        method: "POST",
        body: JSON.stringify({ reason: "Superseded by a new QGuard subscription" }),
      });
    }
  });

  await mustSucceed(db.from("billing_subscriptions").upsert(row, { onConflict: "user_id" }), "subscription activation");
  await mustSucceed(
    db.from("profiles").update({ tier: tier.toLowerCase(), updated_at: new Date().toISOString() }).eq("id", userId),
    "profile tier activation",
  );
  const action = activationAuditAction(previous, { plan: tier, providerSubscriptionId: typeof resource?.id === "string" ? resource.id : null });
  return { userId, tier, action, previousPlan: previous?.plan ?? null };
}

async function subscriptionByProviderId(db: SupabaseClient, providerSubscriptionId: string) {
  const { data } = await db
    .from("billing_subscriptions")
    .select("user_id, plan, status, billing_cycle, current_period_end, cancel_at_period_end, cancelled_at")
    .eq("provider_subscription_id", providerSubscriptionId)
    .maybeSingle();
  return data as {
    user_id: string;
    plan: string;
    status: string;
    billing_cycle: string | null;
    current_period_end: string | null;
    cancel_at_period_end: boolean | null;
    cancelled_at: string | null;
  } | null;
}

/** Select-then-insert by provider_invoice_id (the partial unique index rejects ON CONFLICT). */
async function insertInvoiceOnce(db: SupabaseClient, row: Record<string, unknown>, label: string): Promise<boolean> {
  const reference = row.provider_invoice_id as string | null;
  if (reference) {
    const { data: existing, error } = await db.from("billing_invoices").select("id").eq("provider_invoice_id", reference).maybeSingle();
    if (error) throw new Error(`${label} lookup failed: ${error.message}`);
    if (existing?.id) return false;
  }
  const { error } = await db.from("billing_invoices").insert(row);
  // 23505: a concurrent delivery recorded the same row first — already done.
  if (error && (error as { code?: string }).code === "23505") return false;
  if (error) throw new Error(`${label} failed: ${error.message}`);
  return true;
}

/**
 * Record a completed sale. Select-then-write rather than upsert: the only
 * uniqueness on provider_invoice_id is a PARTIAL index (WHERE ... IS NOT NULL),
 * which Postgres will not accept as a bare ON CONFLICT target — an upsert fails
 * with 42P10 on every delivery, and the webhook would be retried forever.
 */
async function recordPayment(db: SupabaseClient, resource: Record<string, any>): Promise<void> {
  const subscriptionId = resource?.billing_agreement_id;
  if (typeof subscriptionId !== "string" || !subscriptionId) return;
  const subscription = await subscriptionByProviderId(db, subscriptionId);
  if (!subscription?.user_id) return;

  const row = invoiceRow(resource, subscription, new Date().toISOString());
  const inserted = await insertInvoiceOnce(db, row, "invoice recording");
  if (inserted) {
    await audit(db, subscription.user_id, BILLING_AUDIT.paymentSucceeded, `Payment received: ${subscription.plan} ${(Number(row.amount_paid_cents) / 100).toFixed(2)} ${row.currency}`, {
      saleId: row.provider_invoice_id,
      amountCents: row.amount_paid_cents,
      currency: row.currency,
      providerSubscriptionId: subscriptionId,
      source: "paypal.webhook",
    });
  }

  await bestEffort("renewal refresh", async () => {
    const remote = await paypal(`/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}`);
    const next = remote?.billing_info?.next_billing_time;
    if (next) {
      await db
        .from("billing_subscriptions")
        .update({ renewal_date: next, current_period_end: next, status: "active", updated_at: new Date().toISOString() })
        .eq("provider_subscription_id", subscriptionId);
    }
  });
}

async function updateStatus(db: SupabaseClient, resource: Record<string, any>, status: "cancelled" | "suspended" | "expired" | "past_due") {
  const subscriptionId = resource?.id;
  if (typeof subscriptionId !== "string" || !subscriptionId) return;
  const nowIso = new Date().toISOString();
  const subscription = await subscriptionByProviderId(db, subscriptionId);

  // Every failed attempt is its own payment record (PayPal retries a failed
  // charge several times while the subscription stays past_due).
  if (status === "past_due" && subscription?.user_id) {
    const failedRow = failedPaymentInvoiceRow(resource, subscription, nowIso);
    if (failedRow && await insertInvoiceOnce(db, failedRow, "failed payment recording")) {
      await audit(db, subscription.user_id, BILLING_AUDIT.paymentFailed, `Payment failed: ${subscription.plan} ${(Number(failedRow.amount_paid_cents) / 100).toFixed(2)} ${failedRow.currency}`, {
        reference: failedRow.provider_invoice_id,
        attemptedCents: failedRow.amount_paid_cents,
        reasonCode: (failedRow.metadata as Record<string, unknown>)?.reasonCode ?? null,
        providerSubscriptionId: subscriptionId,
        source: "paypal.webhook",
      });
    }
  }

  if (status === "cancelled") {
    // PayPal has stopped billing. The customer keeps the period already paid
    // for; the scheduled expiry ends access at current_period_end.
    if (isCancellationRecorded(subscription)) return;
    const { patch, accessUntil } = cancellationPatch(subscription, nowIso);
    await mustSucceed(db.from("billing_subscriptions").update(patch).eq("provider_subscription_id", subscriptionId), "subscription cancellation");
    if (subscription?.user_id) {
      await notify(
        db,
        subscription.user_id,
        "subscription",
        "warning",
        "Subscription cancelled",
        accessUntil
          ? `Your ${subscription.plan} subscription is cancelled and will not renew. You keep access until ${accessUntil.slice(0, 10)}.`
          : `Your ${subscription.plan} subscription is now cancelled.`,
      );
      await audit(db, subscription.user_id, BILLING_AUDIT.cancelled, accessUntil ? `PayPal subscription cancelled; access until ${accessUntil}` : "PayPal subscription cancelled", {
        fromStatus: subscription.status,
        toStatus: accessUntil ? subscription.status : "cancelled",
        accessUntil,
        plan: subscription.plan,
        providerSubscriptionId: subscriptionId,
        source: "paypal.webhook",
      });
    }
    return;
  }

  // A redelivered status the row already holds changes nothing and must not
  // notify the customer twice.
  if (subscription && String(subscription.status).toLowerCase() === status) return;

  const patch: Record<string, unknown> = { status, updated_at: nowIso };
  if (status === "suspended" || status === "expired") patch.auto_renew = false;
  await mustSucceed(db.from("billing_subscriptions").update(patch).eq("provider_subscription_id", subscriptionId), "subscription status update");
  if (subscription?.user_id) {
    await notify(
      db,
      subscription.user_id,
      "subscription",
      "critical",
      `Subscription ${status.replace("_", " ")}`,
      status === "past_due"
        ? `A payment for your ${subscription.plan} subscription failed. Update your PayPal payment method to avoid interruption.`
        : `Your ${subscription.plan} subscription is now ${status}.`,
    );
    await audit(db, subscription.user_id, statusAuditAction(status), `PayPal subscription ${status.replace("_", " ")}`, {
      fromStatus: subscription.status,
      toStatus: status,
      plan: subscription.plan,
      providerSubscriptionId: subscriptionId,
      source: "paypal.webhook",
    });
  }
}

/** True when no earlier charge of the same PayPal subscription was recorded. */
async function isFirstPayment(db: SupabaseClient, invoice: { id: string; user_id: string; payment_date: string | null }, subscriptionId: string): Promise<boolean> {
  if (!invoice.payment_date) return false;
  const { data, error } = await db
    .from("billing_invoices")
    .select("id")
    .eq("user_id", invoice.user_id)
    .eq("metadata->>subscriptionId", subscriptionId)
    .in("status", ["paid", "refunded"])
    .lt("payment_date", invoice.payment_date)
    .neq("id", invoice.id)
    .limit(1);
  if (error) throw new Error(`first payment lookup failed: ${error.message}`);
  return !data || data.length === 0;
}

/**
 * Full first-payment refund: stop PayPal billing and end access now. Runs BEFORE the
 * invoice is marked refunded, so a failure here (5xx → PayPal redelivers) is
 * retried rather than lost behind the refund's own idempotency check.
 */
async function cancelForRefund(db: SupabaseClient, subscriptionId: string, userId: string, refundCents: number, currency: string) {
  const subscription = await subscriptionByProviderId(db, subscriptionId);
  if (!subscription || subscription.user_id !== userId) return;
  if (String(subscription.status).toLowerCase() === "cancelled") return;
  if (!subscription.cancel_at_period_end) {
    try {
      await paypal(`/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}/cancel`, {
        method: "POST",
        body: JSON.stringify({ reason: "First payment refunded in full" }),
      });
    } catch (error) {
      // Already cancelled at PayPal is fine; anything else means PayPal would keep billing.
      if ((error as { paypalName?: string }).paypalName !== "UNPROCESSABLE_ENTITY") throw error;
    }
  }
  const nowIso = new Date().toISOString();
  await mustSucceed(
    db.from("billing_subscriptions").update(refundCancellationPatch(subscription, nowIso)).eq("provider_subscription_id", subscriptionId),
    "refund cancellation",
  );
  await notify(db, userId, "subscription", "warning", "Subscription cancelled after refund",
    `Your ${subscription.plan} payment was refunded (${(refundCents / 100).toFixed(2)} ${currency}), so the subscription is cancelled and will not renew.`);
  await audit(db, userId, BILLING_AUDIT.cancelled, "Subscription cancelled: first payment refunded in full", {
    providerSubscriptionId: subscriptionId,
    fromStatus: subscription.status,
    toStatus: "cancelled",
    plan: subscription.plan,
    refundCents,
    source: "paypal.refund",
  });
}

async function recordRefund(db: SupabaseClient, resource: Record<string, any>, eventType: string) {
  const saleId = resource?.sale_id ?? resource?.id;
  if (typeof saleId !== "string" || !saleId) return;
  const { data: invoice, error } = await db
    .from("billing_invoices")
    .select("id, user_id, amount_paid_cents, currency, subscription_plan, payment_date, metadata")
    .eq("provider_invoice_id", saleId)
    .maybeSingle();
  if (error) throw new Error(`refund invoice lookup failed: ${error.message}`);
  if (!invoice) {
    console.warn(`[billing] ${eventType} for unknown sale ${saleId} — no invoice to refund`);
    return;
  }
  const nowIso = new Date().toISOString();
  const refund = refundInvoicePatch(invoice, resource, eventType, nowIso);
  if (!refund.isNew) return;
  const subscriptionId = (invoice.metadata as Record<string, unknown> | null)?.subscriptionId;
  if (isPaypalSubscriptionId(subscriptionId)) {
    const refundedCents = Number((refund.patch.metadata as Record<string, unknown>).refundedCents) || 0;
    const cancels = moneyBackRefundCancels({
      eventType,
      amountPaidCents: invoice.amount_paid_cents,
      refundedCents,
      paymentDate: invoice.payment_date,
      refundedAt: resource?.create_time ?? nowIso,
      isFirstPayment: refundedCents > 0 && await isFirstPayment(db, invoice, subscriptionId),
    });
    if (cancels) await cancelForRefund(db, subscriptionId, invoice.user_id, refundedCents, invoice.currency);
  }
  await mustSucceed(db.from("billing_invoices").update(refund.patch).eq("id", invoice.id), "invoice refund");
  await notify(db, invoice.user_id, "billing", "warning", "Payment refunded", `${(refund.refundCents / 100).toFixed(2)} ${invoice.currency} of a ${invoice.subscription_plan} payment was refunded.`);
  await audit(db, invoice.user_id, BILLING_AUDIT.paymentRefunded, `Refund recorded: ${(refund.refundCents / 100).toFixed(2)} ${invoice.currency}`, {
    saleId,
    refundId: refund.refundId,
    refundCents: refund.refundCents,
    reversal: eventType === "PAYMENT.SALE.REVERSED",
    source: "paypal.webhook",
  });
}

async function syncUpdate(db: SupabaseClient, resource: Record<string, any>) {
  const subscriptionId = resource?.id;
  if (typeof subscriptionId !== "string" || !subscriptionId) return;
  const subscription = await subscriptionByProviderId(db, subscriptionId);
  if (!subscription) return;
  const info = planInfoFromId(env, resource?.plan_id);
  const mapped = mapPaypalStatus(resource?.status);
  const next = resource?.billing_info?.next_billing_time ?? null;
  const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
  if (info) Object.assign(patch, { plan: info.tier, billing_cycle: toDbCycle(info.cycle) });
  if (mapped) patch.status = mapped;
  if (next) Object.assign(patch, { renewal_date: next, current_period_end: next });
  await mustSucceed(db.from("billing_subscriptions").update(patch).eq("provider_subscription_id", subscriptionId), "subscription update sync");
  const base = { providerSubscriptionId: subscriptionId, source: "paypal.webhook" };
  const planAction = info ? planChangeAction(subscription.plan, info.tier) : null;
  if (info && planAction) {
    await mustSucceed(
      db.from("profiles").update({ tier: info.tier.toLowerCase(), updated_at: new Date().toISOString() }).eq("id", subscription.user_id),
      "profile tier sync",
    );
    await notify(db, subscription.user_id, "subscription", "success", "Plan changed", `Your subscription is now ${info.tier}.`);
    await audit(db, subscription.user_id, planAction, `Plan changed: ${subscription.plan} → ${info.tier}`, { ...base, fromPlan: subscription.plan, toPlan: info.tier });
  }
  if (info && subscription.billing_cycle && toDbCycle(info.cycle) !== subscription.billing_cycle) {
    await audit(db, subscription.user_id, BILLING_AUDIT.cycleChanged, `Billing cycle changed: ${subscription.billing_cycle} → ${toDbCycle(info.cycle)}`, { ...base, fromCycle: subscription.billing_cycle, toCycle: toDbCycle(info.cycle) });
  }
  if (mapped && mapped !== String(subscription.status).toLowerCase()) {
    await audit(db, subscription.user_id, BILLING_AUDIT.statusChanged, `Subscription status: ${subscription.status} → ${mapped}`, { ...base, fromStatus: subscription.status, toStatus: mapped });
  }
}

// ---- Routes ------------------------------------------------------------------

async function handleSubscribe(req: Request, db: SupabaseClient): Promise<Response> {
  const user = await requireUser(req, db);
  if (!isPaypalConfigured(env)) throw new HttpError(503, "PAYPAL_NOT_CONFIGURED", "PayPal is not configured on the billing service");
  const body = await readJson(req);
  const tier = normalizeTier(body.plan);
  if (!tier) throw new HttpError(400, "INVALID_PLAN", "Unknown or missing plan");
  const cycle = normalizeCycle(body.cycle ?? body.billingPeriod);
  requirePlanId(tier, cycle);

  const origin = appOrigin(env);
  const returnUrl = `${origin}/subscription/thank-you?plan=${tier}&cycle=${cycle}`;
  // Neutral landing for an abandoned checkout: the thank-you page announces a
  // confirmed subscription and must never be shown for a cancelled one.
  const cancelUrl = `${origin}/?checkout=cancelled`;

  const existing = await currentSubscription(db, user.id);
  // One account, one subscription: a live Google Play plan is changed in
  // Google Play, never by stacking a PayPal subscription on top of it.
  if (existing?.provider === "google_play" && isAccessGranting(existing.status) && !existing.cancel_at_period_end) {
    throw new HttpError(409, "MANAGED_BY_GOOGLE_PLAY", "This account's subscription is billed by Google Play. Change or cancel it in Google Play on your Android device.");
  }
  // A subscription cancelled at period end is already cancelled at PayPal and
  // cannot be revised; a new plan needs a fresh checkout.
  const liveSubscriptionId = existing?.provider === "paypal"
    && existing.provider_subscription_id
    && !existing.cancel_at_period_end
    && REVISABLE_STATUSES.has(String(existing.status).toLowerCase())
    ? existing.provider_subscription_id
    : null;

  if (liveSubscriptionId) {
    const revised = await revisePaypalSubscription(liveSubscriptionId, tier, cycle, returnUrl, cancelUrl);
    await audit(db, user.id, "paypal.subscription.revise_requested", `Plan change to ${tier} ${cycle} requested`, {
      providerSubscriptionId: liveSubscriptionId,
      plan: tier,
      cycle,
    });
    return json(200, {
      data: { approvalUrl: revised.approvalUrl, subscriptionId: liveSubscriptionId, plan: tier, cycle, mode: "revise" },
    });
  }

  const created = await createPaypalSubscription({ userId: user.id, email: user.email, tier, cycle, returnUrl, cancelUrl });
  await audit(db, user.id, "paypal.subscription.checkout_created", `PayPal checkout created for ${tier} ${cycle}`, {
    providerSubscriptionId: created.subscriptionId,
    plan: tier,
    cycle,
  });
  return json(200, { data: { ...created, plan: tier, cycle, mode: "create" } });
}

/**
 * Activate from PayPal's authoritative state, so a paid subscription unlocks the
 * account within seconds even if the webhook is delayed. The client only names
 * the subscription; PayPal must confirm it is ACTIVE and bound (custom_id) to
 * the caller, so the route can grant exactly what the webhook would.
 */
async function handleConfirm(req: Request, db: SupabaseClient): Promise<Response> {
  const user = await requireUser(req, db);
  const body = await readJson(req);
  const subscriptionId = body.subscriptionId;
  if (!isPaypalSubscriptionId(subscriptionId)) throw new HttpError(400, "INVALID_SUBSCRIPTION", "Unknown subscription reference");
  const remote = await paypal(`/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}`);
  if (remote?.custom_id !== user.id) throw new HttpError(403, "FORBIDDEN", "This subscription belongs to a different account");
  const status = String(remote?.status ?? "").toUpperCase();
  if (status !== "ACTIVE") return json(200, { data: { status: status.toLowerCase() || "unknown", activated: false } });
  const activated = await activate(db, remote);
  if (!activated) throw new HttpError(409, "PLAN_UNKNOWN", "PayPal reported a plan this service does not sell");
  await recordActivation(db, activated, subscriptionId, "paypal.confirm");
  return json(200, { data: { status: "active", activated: true, plan: activated.tier } });
}

async function handleActions(req: Request, db: SupabaseClient): Promise<Response> {
  const user = await requireUser(req, db);
  const body = await readJson(req);
  const action = String(body.action ?? "");
  const subscription = await currentSubscription(db, user.id);
  if (!subscription) throw new HttpError(404, "NO_SUBSCRIPTION", "This account has no subscription to change");

  if (action === "cancel") {
    if (subscription.provider === "paypal" && subscription.provider_subscription_id) {
      try {
        await paypal(`/v1/billing/subscriptions/${encodeURIComponent(subscription.provider_subscription_id)}/cancel`, {
          method: "POST",
          body: JSON.stringify({ reason: "Customer cancelled from QGuard" }),
        });
      } catch (error) {
        // PayPal refuses to cancel what is already cancelled; anything else means
        // PayPal would keep billing, so the local record must NOT claim otherwise.
        const name = (error as { paypalName?: string }).paypalName;
        if (name !== "UNPROCESSABLE_ENTITY") throw error;
      }
    }
    if (isCancellationRecorded(subscription)) {
      return json(200, { data: { action, status: "completed", accessUntil: subscription.cancel_at_period_end ? subscription.current_period_end : null } });
    }
    const nowIso = new Date().toISOString();
    const { patch, accessUntil } = cancellationPatch(subscription, nowIso);
    await mustSucceed(
      db.from("billing_subscriptions").update(patch).eq("id", subscription.id).eq("user_id", user.id),
      "subscription cancellation",
    );
    await audit(db, user.id, BILLING_AUDIT.cancelled, accessUntil ? `Subscription cancelled by the customer; access until ${accessUntil}` : "Subscription cancelled by the customer", {
      providerSubscriptionId: subscription.provider_subscription_id,
      fromStatus: subscription.status,
      toStatus: accessUntil ? subscription.status : "cancelled",
      accessUntil,
      plan: subscription.plan,
      source: "customer",
    });
    return json(200, { data: { action, status: "completed", accessUntil } });
  }

  if (action === "reactivate") {
    if (!isPaypalConfigured(env)) throw new HttpError(503, "PAYPAL_NOT_CONFIGURED", "PayPal is not configured on the billing service");
    const tier = normalizeTier(subscription.plan) ?? "Starter";
    const cycle: Cycle = subscription.billing_cycle === "annual" ? "yearly" : "monthly";
    const origin = appOrigin(env);
    const created = await createPaypalSubscription({
      userId: user.id,
      email: user.email,
      tier,
      cycle,
      returnUrl: `${origin}/subscription/thank-you?plan=${tier}&cycle=${cycle}`,
      cancelUrl: `${origin}/?checkout=cancelled`,
    });
    await audit(db, user.id, "paypal.subscription.reactivate_requested", `Reactivation checkout created for ${tier} ${cycle}`, {
      providerSubscriptionId: created.subscriptionId,
    });
    return json(200, { data: { action, status: "checkout_required", redirectUrl: created.approvalUrl, subscriptionId: created.subscriptionId } });
  }

  throw new HttpError(400, "INVALID_ACTION", "Unsupported billing action");
}

async function handleWebhook(req: Request): Promise<Response> {
  const raw = await req.text();
  let event: Record<string, any>;
  try {
    event = JSON.parse(raw);
  } catch {
    return json(400, { received: false, error: "invalid_json" });
  }

  const webhookId = (env("PAYPAL_WEBHOOK_ID") ?? "").trim();
  let verified = false;
  if (webhookId && isPaypalConfigured(env)) {
    try {
      const result = await paypal("/v1/notifications/verify-webhook-signature", {
        method: "POST",
        body: webhookVerificationBody(req.headers, webhookId, raw),
      });
      verified = result?.verification_status === "SUCCESS";
    } catch (error) {
      console.error("[billing] webhook verification error:", error instanceof Error ? error.message : error);
    }
  }
  if (!verified) {
    // Unverified deliveries change nothing. 200 so a forged request learns nothing.
    console.warn("[billing] PayPal webhook not verified — ignored");
    return json(200, { received: true, verified: false });
  }

  const db = serviceClient();
  const eventId = String(event.id ?? "");
  const type = String(event.event_type ?? "");
  const resource = (event.resource ?? {}) as Record<string, any>;

  if (!eventId) return json(400, { received: false, error: "missing_event_id" });

  const claim = await claimWebhookEvent(db, eventId, type, resource, event);
  if (claim === "duplicate") return json(200, { received: true, duplicate: true });
  // Another delivery of this event is running right now: a non-2xx makes
  // PayPal retry later, by which time it has either finished or gone stale.
  if (claim === "in-progress") return json(409, { received: false, error: "event_in_progress" });

  try {
    switch (type) {
      case "BILLING.SUBSCRIPTION.ACTIVATED": {
        const activated = await activate(db, resource);
        if (activated) await recordActivation(db, activated, typeof resource?.id === "string" ? resource.id : null, "paypal.webhook");
        break;
      }
      case "BILLING.SUBSCRIPTION.UPDATED":
        await syncUpdate(db, resource);
        break;
      case "PAYMENT.SALE.COMPLETED":
        await recordPayment(db, resource);
        break;
      case "PAYMENT.SALE.REFUNDED":
      case "PAYMENT.SALE.REVERSED":
        await recordRefund(db, resource, type);
        break;
      case "BILLING.SUBSCRIPTION.PAYMENT.FAILED":
        await updateStatus(db, resource, "past_due");
        break;
      case "BILLING.SUBSCRIPTION.CANCELLED":
        await updateStatus(db, resource, "cancelled");
        break;
      case "BILLING.SUBSCRIPTION.SUSPENDED":
        await updateStatus(db, resource, "suspended");
        break;
      case "BILLING.SUBSCRIPTION.EXPIRED":
        await updateStatus(db, resource, "expired");
        break;
      default:
        break;
    }
  } catch (error) {
    // Claim released as `failed`: a 5xx makes PayPal redeliver, and the retry
    // runs again, so no activation, payment or refund is lost.
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[billing] webhook ${type} (${eventId}) failed:`, message);
    await bestEffort("release webhook claim", async () => {
      const { error: releaseError } = await db.from("paypal_webhook_events")
        .update({ status: "failed", last_error: message.slice(0, 500) })
        .eq("event_id", eventId);
      if (releaseError) throw new Error(releaseError.message);
    });
    return json(500, { received: false, error: "processing_failed" });
  }

  await bestEffort("mark webhook processed", async () => {
    const { error } = await db.from("paypal_webhook_events")
      .update({ status: "processed", processed_at: new Date().toISOString(), last_error: null })
      .eq("event_id", eventId);
    if (error) throw new Error(error.message);
  });
  return json(200, { received: true, verified: true });
}

/**
 * Claim a delivery BEFORE any side effect (see webhookClaimDecision). The
 * unique event_id makes the first insert the claim; a later delivery reads the
 * claim and either skips (processed), backs off (running), or re-claims it with
 * a compare-and-set on the claim it saw (failed or stale).
 */
async function claimWebhookEvent(
  db: SupabaseClient,
  eventId: string,
  type: string,
  resource: Record<string, any>,
  event: Record<string, any>,
): Promise<"run" | "duplicate" | "in-progress"> {
  const nowIso = new Date().toISOString();
  const { error } = await db.from("paypal_webhook_events").insert({
    event_id: eventId,
    event_type: type,
    resource_id: resource?.id ?? resource?.billing_agreement_id ?? null,
    user_id: isUuid(resource?.custom_id) ? resource.custom_id : null,
    raw: event,
    status: "processing",
    claimed_at: nowIso,
    attempts: 1,
  });
  if (!error) return "run";
  if ((error as { code?: string }).code !== "23505") throw new HttpError(503, "WEBHOOK_LEDGER_UNAVAILABLE", `webhook claim failed: ${error.message}`);

  const { data: existing, error: readError } = await db
    .from("paypal_webhook_events")
    .select("status, claimed_at, processed_at, attempts")
    .eq("event_id", eventId)
    .maybeSingle();
  if (readError) throw new HttpError(503, "WEBHOOK_LEDGER_UNAVAILABLE", `webhook claim read failed: ${readError.message}`);
  const decision = webhookClaimDecision(existing, Date.now());
  if (decision !== "run" || !existing) return decision;

  let reclaim = db.from("paypal_webhook_events")
    .update({ status: "processing", claimed_at: nowIso, attempts: (Number(existing.attempts) || 0) + 1 })
    .eq("event_id", eventId)
    .eq("status", existing.status);
  reclaim = existing.claimed_at ? reclaim.eq("claimed_at", existing.claimed_at) : reclaim.is("claimed_at", null);
  const { data: reclaimed, error: reclaimError } = await reclaim.select("event_id");
  if (reclaimError) throw new HttpError(503, "WEBHOOK_LEDGER_UNAVAILABLE", `webhook re-claim failed: ${reclaimError.message}`);
  return reclaimed && reclaimed.length > 0 ? "run" : "in-progress";
}

// ---- Reconciliation (missed-webhook repair) ----------------------------------

/** PayPal's view of a subscription, or null when PayPal no longer has it (abandoned checkout). */
async function remoteSubscription(subscriptionId: string): Promise<Record<string, any> | null> {
  try {
    return await paypal(`/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}`);
  } catch (error) {
    if ((error as { paypalName?: string }).paypalName === "RESOURCE_NOT_FOUND") return null;
    throw error;
  }
}

/** Record completed charges PayPal holds for a subscription that we never received a webhook for. */
async function reconcilePayments(db: SupabaseClient, subscriptionId: string): Promise<number> {
  const subscription = await subscriptionByProviderId(db, subscriptionId);
  if (!subscription?.user_id) return 0;
  const end = new Date();
  const start = new Date(end.getTime() - RECONCILE_PAYMENT_LOOKBACK_DAYS * 86_400_000);
  const history = await paypal(
    `/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}/transactions?start_time=${start.toISOString()}&end_time=${end.toISOString()}`,
  );
  let recorded = 0;
  for (const transaction of Array.isArray(history?.transactions) ? history.transactions : []) {
    const row = invoiceRowFromTransaction(transaction, subscription, subscriptionId, end.toISOString());
    if (!row || !await insertInvoiceOnce(db, row, "reconciled invoice")) continue;
    recorded += 1;
    await audit(db, subscription.user_id, BILLING_AUDIT.paymentSucceeded, `Payment received: ${subscription.plan} ${(Number(row.amount_paid_cents) / 100).toFixed(2)} ${row.currency}`, {
      saleId: row.provider_invoice_id,
      amountCents: row.amount_paid_cents,
      currency: row.currency,
      providerSubscriptionId: subscriptionId,
      source: "paypal.reconcile",
    });
  }
  return recorded;
}

/**
 * Re-read PayPal for (1) recent checkouts that never activated locally, (2)
 * every live local PayPal subscription, and (3) their recent payments, and
 * apply whatever the webhooks would have. Every step reuses the webhook
 * handlers, so a repair writes exactly the rows a delivered event would have,
 * and running it again changes nothing.
 */
async function reconcile(db: SupabaseClient) {
  const summary = { checkoutsChecked: 0, activated: 0, subscriptionsChecked: 0, statusRepaired: 0, paymentsRecorded: 0, errors: 0 };
  const since = new Date(Date.now() - RECONCILE_CHECKOUT_LOOKBACK_DAYS * 86_400_000).toISOString();

  const { data: checkouts, error: checkoutError } = await db
    .from("billing_audit_events")
    .select("user_id, metadata")
    .in("action", ["paypal.subscription.checkout_created", "paypal.subscription.reactivate_requested"])
    .gte("created_at", since)
    .limit(200);
  if (checkoutError) throw new Error(`reconcile checkout query failed: ${checkoutError.message}`);
  const pending = new Map<string, string>();
  for (const row of checkouts ?? []) {
    const id = (row.metadata as Record<string, unknown> | null)?.providerSubscriptionId;
    if (isPaypalSubscriptionId(id) && isUuid(row.user_id)) pending.set(id, row.user_id);
  }
  for (const [subscriptionId, userId] of pending) {
    if (await subscriptionByProviderId(db, subscriptionId)) continue; // already recorded
    summary.checkoutsChecked += 1;
    try {
      const remote = await remoteSubscription(subscriptionId);
      // Only a checkout PayPal reports ACTIVE and bound to the same account activates.
      if (!remote || String(remote.status).toUpperCase() !== "ACTIVE" || remote.custom_id !== userId) continue;
      const activated = await activate(db, remote);
      if (!activated) continue;
      await recordActivation(db, activated, subscriptionId, "paypal.reconcile");
      summary.activated += 1;
    } catch (error) {
      summary.errors += 1;
      console.error(`[billing] reconcile checkout ${subscriptionId} failed:`, error instanceof Error ? error.message : error);
    }
  }

  const { data: rows, error } = await db
    .from("billing_subscriptions")
    .select("plan, status, renewal_date, cancel_at_period_end, provider_subscription_id")
    .eq("provider", "paypal")
    .not("provider_subscription_id", "is", null)
    .in("status", RECONCILE_STATUSES)
    .limit(200);
  if (error) throw new Error(`reconcile subscription query failed: ${error.message}`);
  for (const row of rows ?? []) {
    const subscriptionId = String(row.provider_subscription_id);
    if (!isPaypalSubscriptionId(subscriptionId)) continue;
    summary.subscriptionsChecked += 1;
    try {
      const remote = await remoteSubscription(subscriptionId);
      if (!remote) continue;
      const action = reconcileAction(env, row, remote);
      if (action === "sync") await syncUpdate(db, remote);
      else if (action) await updateStatus(db, remote, action);
      if (action) summary.statusRepaired += 1;
      summary.paymentsRecorded += await reconcilePayments(db, subscriptionId);
    } catch (error) {
      summary.errors += 1;
      console.error(`[billing] reconcile subscription ${subscriptionId} failed:`, error instanceof Error ? error.message : error);
    }
  }
  return summary;
}

/** Scheduler-only: `X-Reconcile-Secret: <PAYPAL_RECONCILE_SECRET>` (supabase/paypal-reconcile-schedule.sql). */
async function handleReconcile(req: Request, db: SupabaseClient): Promise<Response> {
  const secret = (env("PAYPAL_RECONCILE_SECRET") ?? "").trim();
  if (!secret) return fail(503, "RECONCILE_DISABLED", "Reconciliation is disabled (set PAYPAL_RECONCILE_SECRET)");
  const provided = req.headers.get("X-Reconcile-Secret") ?? bearerToken(req.headers.get("Authorization")) ?? "";
  if (!provided || !timingSafeEqualText(provided, secret)) return fail(401, "UNAUTHORIZED", "Invalid reconcile secret");
  // One scheduled sweep repairs both providers (supabase/paypal-reconcile-schedule.sql).
  const paypalSummary = isPaypalConfigured(env) ? await reconcile(db) : { skipped: "PAYPAL_NOT_CONFIGURED" };
  let playSummary: Record<string, unknown>;
  try {
    playSummary = await reconcilePlay(serviceDeps(db));
  } catch (error) {
    console.error("[billing] play reconcile failed:", error instanceof Error ? error.message : error);
    playSummary = { error: "play_reconcile_failed" };
  }
  const summary = { ...paypalSummary, play: playSummary };
  console.log("[billing] reconcile", JSON.stringify(summary));
  return json(200, { data: summary });
}

// ---- Google Play Billing + subscription API ------------------------------------
//
// Everything below delegates to play-service.ts, the runtime-agnostic module
// the Express API mounts too (src/api-server/subscriptions.ts), so the Edge
// Function and Express verify purchases and compute entitlements identically.

function serviceDeps(db: SupabaseClient): ServiceDeps {
  return {
    env,
    db,
    cancelPaypalSubscription: async (subscriptionId: string, reason: string) => {
      if (!isPaypalConfigured(env)) return;
      try {
        await paypal(`/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}/cancel`, { method: "POST", body: JSON.stringify({ reason }) });
      } catch (error) {
        if ((error as { paypalName?: string }).paypalName !== "UNPROCESSABLE_ENTITY") throw error;
      }
    },
  };
}

function asHttp(error: unknown): never {
  if (error instanceof BillingHttpError) throw new HttpError(error.status, error.code, error.message);
  throw error;
}

async function handlePlayVerify(req: Request, db: SupabaseClient): Promise<Response> {
  const user = await requireUser(req, db);
  const body = await readJson(req);
  try {
    return json(200, { data: await verifyPurchase(serviceDeps(db), user.id, body.purchaseToken) });
  } catch (error) {
    return asHttp(error);
  }
}

async function handleRestore(req: Request, db: SupabaseClient): Promise<Response> {
  const user = await requireUser(req, db);
  const body = await readJson(req);
  try {
    return json(200, { data: await restorePurchases(serviceDeps(db), user.id, body.purchaseTokens) });
  } catch (error) {
    return asHttp(error);
  }
}

async function handlePlayRtdn(req: Request, db: SupabaseClient): Promise<Response> {
  const result = await handleRtdn(serviceDeps(db), {
    url: req.url,
    authorization: req.headers.get("Authorization"),
    body: await readJson(req),
  });
  return json(result.status, result.body);
}

async function handleSubscriptionGet(req: Request, route: string, db: SupabaseClient): Promise<Response> {
  const deps = serviceDeps(db);
  try {
    if (route === "/api/v1/subscriptions/catalog") {
      return json(200, { data: await subscriptionCatalog(deps, platformParam(new URL(req.url).searchParams.get("platform"))) });
    }
    const user = await requireUser(req, db);
    if (route === "/api/v1/subscriptions/me") {
      const summary = await subscriptionSummary(deps, user.id);
      // Recorded here so a Play purchase's obfuscated account id maps back to
      // this account even if the app never gets to call /verify.
      const playAccountId = await ensurePlayAccount(db, user.id);
      return json(200, { data: { ...summary, playAccountId } });
    }
    if (route === "/api/v1/subscriptions/entitlements") return json(200, { data: await effectiveEntitlements(deps, user.id) });
    if (route === "/api/v1/subscriptions/history") return json(200, { data: await subscriptionHistory(deps, user.id) });
  } catch (error) {
    return asHttp(error);
  }
  return fail(404, "NOT_FOUND", `No billing route ${route}`);
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

  const route = routeOf(new URL(req.url).pathname);
  try {
    if (req.method === "GET" && (route === "/" || route === "/health")) {
      return json(200, { data: configurationReport(env) });
    }
    if (req.method === "GET" && route.startsWith("/api/v1/subscriptions/")) {
      return await handleSubscriptionGet(req, route, serviceClient());
    }
    if (req.method !== "POST") return fail(405, "METHOD_NOT_ALLOWED", "Use GET for reads and POST for actions");

    switch (route) {
      case "/api/v1/paypal/webhook":
        return await handleWebhook(req);
      case "/api/v1/paypal/subscribe":
        return await handleSubscribe(req, serviceClient());
      case "/api/v1/paypal/confirm":
        return await handleConfirm(req, serviceClient());
      case "/api/v1/paypal/reconcile":
        return await handleReconcile(req, serviceClient());
      case "/api/v1/billing/subscription/actions":
        return await handleActions(req, serviceClient());
      case "/api/v1/subscriptions/verify":
      case "/api/v1/play-billing/verify":
        return await handlePlayVerify(req, serviceClient());
      case "/api/v1/subscriptions/restore":
        return await handleRestore(req, serviceClient());
      case "/api/v1/webhooks/google-play/rtdn":
      case "/api/v1/play-billing/rtdn":
        return await handlePlayRtdn(req, serviceClient());
      default:
        return fail(404, "NOT_FOUND", `No billing route ${route}`);
    }
  } catch (error) {
    if (error instanceof HttpError) return fail(error.status, error.code, error.message);
    console.error(`[billing] ${route} failed:`, error instanceof Error ? error.message : error);
    return fail(500, "BILLING_ERROR", "The billing service could not complete the request");
  }
});
