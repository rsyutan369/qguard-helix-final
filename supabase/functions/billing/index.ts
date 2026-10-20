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
 *   POST /api/v1/play-billing/verify             verify a Google Play purchase token (auth)
 *   POST /api/v1/play-billing/rtdn?token=…       Play Real-Time Developer Notifications (shared secret)
 *
 * Deployed with verify_jwt = false because PayPal's webhook carries no Supabase
 * JWT. Every user route verifies the caller's access token itself
 * (auth.getUser), and identity always comes from that token — never the body.
 *
 * Secrets (Edge Function secrets): PAYPAL_CLIENT_ID, PAYPAL_SECRET_KEY,
 * PAYPAL_ENV, PAYPAL_WEBHOOK_ID, PAYPAL_PLAN_<TIER>_<CYCLE> (8), optional
 * APP_ORIGIN. Google Play (optional; /health reports playVerification only
 * when set): GOOGLE_PLAY_PACKAGE_NAME, GOOGLE_PLAY_SERVICE_ACCOUNT_JSON (or
 * GOOGLE_PLAY_SA_EMAIL + GOOGLE_PLAY_SA_PRIVATE_KEY), PLAY_RTDN_TOKEN, optional
 * PLAY_PRODUCT_<TIER>. SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are provided by
 * the runtime.
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
  isPaypalConfigured,
  isCancellationRecorded,
  isPlayConfigured,
  mapPlayState,
  parseRtdnMessage,
  pemToDer,
  playJwtSigningInput,
  playPackageName,
  PlayPurchaseError,
  playServiceAccount,
  playSubscriptionRows,
  base64Url,
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

async function recordRefund(db: SupabaseClient, resource: Record<string, any>, eventType: string) {
  const saleId = resource?.sale_id ?? resource?.id;
  if (typeof saleId !== "string" || !saleId) return;
  const { data: invoice, error } = await db
    .from("billing_invoices")
    .select("id, user_id, amount_paid_cents, currency, subscription_plan, metadata")
    .eq("provider_invoice_id", saleId)
    .maybeSingle();
  if (error) throw new Error(`refund invoice lookup failed: ${error.message}`);
  if (!invoice) {
    console.warn(`[billing] ${eventType} for unknown sale ${saleId} — no invoice to refund`);
    return;
  }
  const refund = refundInvoicePatch(invoice, resource, eventType, new Date().toISOString());
  if (!refund.isNew) return;
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

// ---- Google Play Billing (roadmap 4.6) --------------------------------------
//
// The Edge port of src/api-server/play-billing.ts. Nothing the app sends is
// trusted but the purchase token: Google's subscriptionsv2 resource is the
// truth, the purchase must be bound (obfuscatedExternalAccountId) to the
// caller, one token can only ever unlock one account, and the purchase is
// acknowledged so Google does not auto-refund it. Raw tokens are never stored:
// rows are keyed by their SHA-256 (the same key the Express API uses).

let googleToken: { token: string; expiresAt: number } | null = null;

async function googleAccessToken(): Promise<string> {
  const account = playServiceAccount(env);
  if (!account) throw new HttpError(503, "PLAY_NOT_CONFIGURED", "Google Play Billing is not configured on the server");
  const now = Date.now();
  if (googleToken && googleToken.expiresAt > now + 60_000) return googleToken.token;
  const key = await crypto.subtle.importKey(
    "pkcs8",
    new Uint8Array(pemToDer(account.privateKey)), // a plain ArrayBuffer, as importKey requires
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const input = playJwtSigningInput(account.email, Math.floor(now / 1000));
  const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(input)));
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: `${input}.${base64Url(signature)}`,
    }).toString(),
  });
  const body: any = await response.json().catch(() => ({}));
  if (!response.ok || !body?.access_token) {
    throw new Error(body?.error_description || body?.error || `Google token exchange failed (HTTP ${response.status})`);
  }
  googleToken = { token: body.access_token, expiresAt: now + (Number(body.expires_in) || 3000) * 1000 };
  return googleToken.token;
}

class PlayApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function playApi(pathname: string, init: { method?: string; body?: unknown } = {}): Promise<any> {
  const token = await googleAccessToken();
  const response = await fetch(`https://androidpublisher.googleapis.com/androidpublisher/v3${pathname}`, {
    method: init.method ?? "GET",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  const text = await response.text();
  let body: any = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = {};
  }
  if (!response.ok) throw new PlayApiError(response.status, body?.error?.message || `Google Play API request failed (HTTP ${response.status})`);
  return body;
}

const playPackagePath = () => `/applications/${encodeURIComponent(playPackageName(env))}`;

async function sha256Hex(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Apply an authoritative subscriptionsv2 resource to the account it is bound to. */
async function applyPlaySubscription(
  db: SupabaseClient,
  resource: Record<string, any>,
  purchaseToken: string,
  expectedUserId: string | null,
) {
  const tokenHash = await sha256Hex(purchaseToken);
  const nowIso = new Date().toISOString();
  const applied = playSubscriptionRows(env, resource, tokenHash, expectedUserId, nowIso);

  // One purchase token can only ever unlock ONE account (replay / sharing).
  const { data: claimed, error: claimError } = await db
    .from("billing_subscriptions")
    .select("user_id")
    .eq("provider", "google_play")
    .eq("provider_subscription_id", tokenHash)
    .maybeSingle();
  if (claimError) throw new Error(`play token lookup failed: ${claimError.message}`);
  if (claimed?.user_id && claimed.user_id !== applied.userId) {
    throw new HttpError(409, "TOKEN_ALREADY_CLAIMED", "this purchase is already linked to another account");
  }

  await mustSucceed(db.from("billing_subscriptions").upsert(applied.subscription, { onConflict: "user_id" }), "play subscription upsert");
  if (applied.mapped.entitled) {
    await mustSucceed(
      db.from("profiles").update({ tier: applied.tier.toLowerCase(), updated_at: nowIso }).eq("id", applied.userId),
      "profile tier activation",
    );
  }
  if (applied.invoice && await insertInvoiceOnce(db, applied.invoice, "play invoice")) {
    await audit(db, applied.userId, "payment.succeeded", `Google Play payment recorded: ${applied.tier} ${applied.cycle} (list price)`, {
      orderId: applied.invoice.provider_invoice_id,
      purchaseTokenHash: tokenHash,
      amountSource: "catalog_list_price",
      source: "google_play",
    });
  }
  // Acknowledge within Google's 3-day window or the purchase is refunded.
  if (String(resource?.acknowledgementState ?? "") === "ACKNOWLEDGEMENT_STATE_PENDING" && applied.productId) {
    await bestEffort("play acknowledge", () =>
      playApi(`${playPackagePath()}/purchases/subscriptions/${encodeURIComponent(applied.productId)}/tokens/${encodeURIComponent(purchaseToken)}:acknowledge`, { method: "POST", body: {} })
    );
  }
  await audit(db, applied.userId, "play.subscription.synced", `Google Play subscription synced: ${applied.tier} ${applied.cycle} (${applied.mapped.status})`, {
    purchaseTokenHash: tokenHash,
    state: resource?.subscriptionState ?? null,
  });
  return { ...applied, tokenHash };
}

async function getPlaySubscription(purchaseToken: string): Promise<Record<string, any>> {
  return playApi(`${playPackagePath()}/purchases/subscriptionsv2/tokens/${encodeURIComponent(purchaseToken)}`);
}

/**
 * The ONLY way a Play purchase unlocks an account. Also serves "Restore
 * purchases": the app re-submits the tokens Google returns.
 */
async function handlePlayVerify(req: Request, db: SupabaseClient): Promise<Response> {
  if (!isPlayConfigured(env)) {
    return fail(503, "PLAY_NOT_CONFIGURED", "Google Play purchase verification is not available yet — use PayPal checkout");
  }
  const user = await requireUser(req, db);
  const body = await readJson(req);
  const purchaseToken = String(body.purchaseToken ?? "");
  if (purchaseToken.length < 20 || purchaseToken.length > 4096) {
    return fail(400, "INVALID_TOKEN", "Missing or malformed purchase token");
  }
  try {
    const resource = await getPlaySubscription(purchaseToken);
    const result = await applyPlaySubscription(db, resource, purchaseToken, user.id);
    await bestEffort("play verify ledger", () =>
      db.from("play_webhook_events").insert({
        event_id: `verify_${result.tokenHash.slice(0, 32)}_${String(resource?.latestOrderId ?? "").slice(0, 64)}`,
        notification_type: "client_verify",
        purchase_token_hash: result.tokenHash,
        user_id: user.id,
        raw: { subscriptionState: resource?.subscriptionState ?? null, latestOrderId: resource?.latestOrderId ?? null },
      })
    );
    return json(200, {
      data: { plan: result.tier, cycle: result.cycle, status: result.mapped.status, entitled: result.mapped.entitled, expiryTime: result.expiryTime },
    });
  } catch (error) {
    if (error instanceof PlayPurchaseError) {
      return fail(error.code === "UNKNOWN_PRODUCT" ? 400 : 409, error.code, error.message);
    }
    if (error instanceof PlayApiError && (error.status === 404 || error.status === 400 || error.status === 410)) {
      return fail(400, "PURCHASE_NOT_FOUND", "Google Play did not recognize this purchase");
    }
    if (error instanceof HttpError) throw error;
    console.error("[billing] play verify failed:", error instanceof Error ? error.message : error);
    return fail(502, "PLAY_VERIFY_FAILED", "Could not verify the purchase with Google Play");
  }
}

/**
 * Real-Time Developer Notifications (Pub/Sub push to
 * `.../api/v1/play-billing/rtdn?token=<PLAY_RTDN_TOKEN>`). Every notification
 * re-fetches the authoritative state; idempotent by Pub/Sub message id; a
 * failed write answers 5xx so Pub/Sub redelivers.
 */
async function handlePlayRtdn(req: Request, db: SupabaseClient): Promise<Response> {
  const secret = (env("PLAY_RTDN_TOKEN") ?? "").trim();
  if (!secret) return fail(503, "RTDN_DISABLED", "RTDN is disabled (set PLAY_RTDN_TOKEN)");
  const provided = new URL(req.url).searchParams.get("token") ?? "";
  if (!provided || !timingSafeEqualText(provided, secret)) return fail(401, "UNAUTHORIZED", "Invalid RTDN token");

  const parsed = parseRtdnMessage(await readJson(req));
  if (!parsed) return json(200, { received: true, ignored: "malformed" });
  const { messageId, payload } = parsed;
  if (payload?.testNotification) return json(200, { received: true, test: true });
  if (payload?.packageName && playPackageName(env) && payload.packageName !== playPackageName(env)) {
    return json(200, { received: true, ignored: "package_mismatch" });
  }
  const notification = payload?.subscriptionNotification;
  const purchaseToken = String(notification?.purchaseToken ?? "");
  if (!notification || !purchaseToken) return json(200, { received: true, ignored: "not_subscription" });

  const tokenHash = await sha256Hex(purchaseToken);
  const eventId = messageId ? `rtdn_${messageId}` : `rtdn_${await sha256Hex(JSON.stringify(payload))}`;
  const { data: seen } = await db.from("play_webhook_events").select("event_id").eq("event_id", eventId).maybeSingle();
  if (seen) return json(200, { received: true, duplicate: true });

  try {
    const resource = await getPlaySubscription(purchaseToken);
    const result = await applyPlaySubscription(db, resource, purchaseToken, null);
    if (!result.mapped.entitled) {
      await notify(db, result.userId, "subscription", result.mapped.status === "expired" ? "critical" : "warning",
        `Subscription ${result.mapped.status.replace("_", " ")}`,
        `Your ${result.tier} subscription (Google Play) is now ${result.mapped.status.replace("_", " ")}.`);
    }
  } catch (error) {
    // A token Google no longer resolves: apply terminal states from the
    // notification itself so the account still locks.
    const type = Number(notification.notificationType);
    if (type === 12 || type === 13) { // REVOKED | EXPIRED
      await bestEffort("play terminal state", () =>
        db.from("billing_subscriptions")
          .update({ status: "expired", auto_renew: false, updated_at: new Date().toISOString() })
          .eq("provider", "google_play")
          .eq("provider_subscription_id", tokenHash)
      );
    } else {
      console.error(`[billing] RTDN ${eventId} failed, asking Pub/Sub to retry:`, error instanceof Error ? error.message : error);
      return fail(500, "RTDN_FAILED", "processing failed");
    }
  }
  await bestEffort("rtdn ledger", () =>
    db.from("play_webhook_events").insert({
      event_id: eventId,
      notification_type: String(notification.notificationType ?? ""),
      purchase_token_hash: tokenHash,
      raw: payload,
    })
  );
  return json(200, { received: true });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

  const route = routeOf(new URL(req.url).pathname);
  try {
    if (req.method === "GET" && (route === "/" || route === "/health")) {
      return json(200, { data: configurationReport(env) });
    }
    if (req.method !== "POST") return fail(405, "METHOD_NOT_ALLOWED", "Use POST");

    switch (route) {
      case "/api/v1/paypal/webhook":
        return await handleWebhook(req);
      case "/api/v1/paypal/subscribe":
        return await handleSubscribe(req, serviceClient());
      case "/api/v1/paypal/confirm":
        return await handleConfirm(req, serviceClient());
      case "/api/v1/billing/subscription/actions":
        return await handleActions(req, serviceClient());
      case "/api/v1/play-billing/verify":
        return await handlePlayVerify(req, serviceClient());
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
