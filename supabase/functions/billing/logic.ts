/**
 * Runtime-agnostic billing logic for the `billing` Edge Function.
 *
 * No Deno globals and no remote imports, so the same file runs inside the
 * Supabase Edge Runtime AND under Node (tools/billing-edge-check.ts), which is
 * how the rules below are tested without a Deno toolchain.
 *
 * Mirrors src/api-server/paypal.ts (tiers, plan-id env names, status mapping):
 * the Express router remains the implementation for a self-hosted API, and
 * both read the same PAYPAL_* configuration.
 */

export type Tier = "Starter" | "Basic" | "Pro" | "Elite";
export type Cycle = "monthly" | "yearly";
export type DbCycle = "monthly" | "annual";
export type DbStatus =
  | "active"
  | "trial"
  | "expired"
  | "suspended"
  | "pending_renewal"
  | "cancelled"
  | "past_due"
  | "incomplete";

export type EnvGetter = (key: string) => string | undefined;

export const TIERS: Tier[] = ["Starter", "Basic", "Pro", "Elite"];
export const CYCLES: Cycle[] = ["monthly", "yearly"];

/** Public site: PayPal return/cancel pages live here. A constant, never a request header. */
export const DEFAULT_APP_ORIGIN = "https://qguardhelix.com";

/** Statuses in which a PayPal subscription can be revised in place. */
export const REVISABLE_STATUSES = new Set(["active", "past_due", "suspended", "pending_renewal"]);

export function normalizeTier(value: unknown): Tier | null {
  const text = String(value ?? "").trim().toLowerCase();
  return TIERS.find((tier) => tier.toLowerCase() === text) ?? null;
}

export function normalizeCycle(value: unknown): Cycle {
  const text = String(value ?? "").trim().toLowerCase();
  return text.startsWith("year") || text === "annual" ? "yearly" : "monthly";
}

export function toDbCycle(cycle: Cycle): DbCycle {
  return cycle === "yearly" ? "annual" : "monthly";
}

export function planEnvKey(tier: Tier, cycle: Cycle): string {
  return `PAYPAL_PLAN_${tier.toUpperCase()}_${cycle.toUpperCase()}`;
}

export function planIdFor(env: EnvGetter, tier: Tier, cycle: Cycle): string | null {
  const value = env(planEnvKey(tier, cycle))?.trim();
  return value ? value : null;
}

export function planInfoFromId(env: EnvGetter, planId: unknown): { tier: Tier; cycle: Cycle } | null {
  if (typeof planId !== "string" || !planId) return null;
  for (const tier of TIERS) {
    for (const cycle of CYCLES) {
      if (planIdFor(env, tier, cycle) === planId) return { tier, cycle };
    }
  }
  return null;
}

export function paypalApiBase(env: EnvGetter): string {
  return String(env("PAYPAL_ENV") ?? "live").trim().toLowerCase() === "sandbox"
    ? "https://api-m.sandbox.paypal.com"
    : "https://api-m.paypal.com";
}

export function paypalSecret(env: EnvGetter): string {
  return (env("PAYPAL_SECRET_KEY") || env("PAYPAL_CLIENT_SECRET") || "").trim();
}

export function isPaypalConfigured(env: EnvGetter): boolean {
  return Boolean((env("PAYPAL_CLIENT_ID") ?? "").trim() && paypalSecret(env));
}

export function appOrigin(env: EnvGetter): string {
  const configured = (env("APP_ORIGIN") ?? "").trim();
  return (configured || DEFAULT_APP_ORIGIN).replace(/\/+$/, "");
}

/** Booleans only — safe to publish from the unauthenticated health route. */
export function configurationReport(env: EnvGetter) {
  const plans: Record<string, boolean> = {};
  for (const tier of TIERS) {
    for (const cycle of CYCLES) plans[`${tier.toLowerCase()}_${cycle}`] = Boolean(planIdFor(env, tier, cycle));
  }
  return {
    configured: isPaypalConfigured(env),
    webhookConfigured: Boolean((env("PAYPAL_WEBHOOK_ID") ?? "").trim()),
    // The Android app launches Google Play purchases only when this is true
    // (billingSupportsPlayVerification in qguard-messaging/src/lib/billing-api.ts).
    playVerification: isPlayConfigured(env),
    playRtdn: Boolean((env("PLAY_RTDN_TOKEN") ?? "").trim()),
    env: paypalApiBase(env).includes("sandbox") ? "sandbox" : "live",
    plans,
  };
}

/**
 * The route below the function mount. The runtime may present the path with or
 * without the `/functions/v1` gateway prefix; both reduce to the same route, and
 * the client keeps the `/api/v1/...` paths the Express API uses, so pointing the
 * app back at a self-hosted API is only an origin change.
 */
export function routeOf(pathname: string): string {
  const route = pathname.replace(/^\/functions\/v1(?=\/)/, "").replace(/^\/billing(?=\/|$)/, "");
  const trimmed = route.replace(/\/+$/, "");
  return trimmed || "/";
}

export function mapPaypalStatus(status: unknown): DbStatus | null {
  switch (String(status ?? "").toUpperCase()) {
    case "ACTIVE":
      return "active";
    case "SUSPENDED":
      return "suspended";
    case "CANCELLED":
      return "cancelled";
    case "EXPIRED":
      return "expired";
    case "APPROVAL_PENDING":
    case "APPROVED":
      return "incomplete";
    default:
      return null;
  }
}

/** PayPal subscription ids look like `I-BW452GLLEP1G`. */
export function isPaypalSubscriptionId(value: unknown): value is string {
  return typeof value === "string" && /^I-[A-Z0-9]{6,32}$/.test(value);
}

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

/** Bearer token from an Authorization header — header only, never a query parameter. */
export function bearerToken(header: string | null): string | null {
  if (!header || !header.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  return token || null;
}

/**
 * Body for PayPal's verify-webhook-signature call, built around the RAW event
 * text. PayPal verifies the signature over the event exactly as it was sent;
 * re-serialising a parsed object can reorder keys or reformat numbers and turn
 * a genuine delivery into a verification failure.
 */
export function webhookVerificationBody(
  headers: { get(name: string): string | null },
  webhookId: string,
  rawEvent: string,
): string {
  const field = (name: string) => JSON.stringify(headers.get(name) ?? "");
  return `{"auth_algo":${field("paypal-auth-algo")},"cert_url":${field("paypal-cert-url")},`
    + `"transmission_id":${field("paypal-transmission-id")},"transmission_sig":${field("paypal-transmission-sig")},`
    + `"transmission_time":${field("paypal-transmission-time")},"webhook_id":${JSON.stringify(webhookId)},`
    + `"webhook_event":${rawEvent}}`;
}

/** The approval link from a PayPal create/revise response, if any. */
export function approvalLink(response: unknown): string | null {
  const links = (response as { links?: Array<{ rel?: string; href?: string }> } | null)?.links;
  if (!Array.isArray(links)) return null;
  const approve = links.find((link) => link?.rel === "approve" && typeof link.href === "string");
  return approve?.href ?? null;
}

/**
 * Row written when PayPal reports a subscription ACTIVE — by the webhook or by
 * the confirm route. Both paths write the identical row, so whichever arrives
 * first wins and the second is a no-op re-statement of the same facts.
 */
export function activationRow(
  env: EnvGetter,
  resource: Record<string, any>,
  nowIso: string,
): { userId: string; tier: Tier; row: Record<string, unknown> } | null {
  const userId = resource?.custom_id;
  if (!isUuid(userId)) return null;
  const info = planInfoFromId(env, resource?.plan_id);
  if (!info) return null;
  const providerSubId: string | null = typeof resource?.id === "string" ? resource.id : null;
  const nextBilling: string | null = resource?.billing_info?.next_billing_time ?? null;
  return {
    userId,
    tier: info.tier,
    row: {
      user_id: userId,
      subscription_id: providerSubId ?? `paypal_${nowIso}`,
      provider: "paypal",
      provider_subscription_id: providerSubId,
      plan: info.tier,
      status: "active",
      billing_cycle: toDbCycle(info.cycle),
      auto_renew: true,
      cancel_at_period_end: false,
      current_period_start: resource?.start_time ?? nowIso,
      current_period_end: nextBilling,
      renewal_date: nextBilling,
      cancelled_at: null,
      metadata: {
        paypalPlanId: resource?.plan_id ?? null,
        payerEmail: resource?.subscriber?.email_address ?? null,
      },
      updated_at: nowIso,
    },
  };
}

/** Invoice row for a completed PayPal sale. */
export function invoiceRow(
  resource: Record<string, any>,
  subscription: { user_id: string; plan: string },
  nowIso: string,
): Record<string, unknown> {
  const amount = resource?.amount ?? {};
  const gross = amount?.total ?? amount?.value ?? "0";
  const currency = String(amount?.currency ?? amount?.currency_code ?? "USD").toUpperCase();
  const saleId: string | null = typeof resource?.id === "string" ? resource.id : null;
  return {
    user_id: subscription.user_id,
    invoice_id: saleId ?? `paypal_${nowIso}`,
    provider_invoice_id: saleId,
    transaction_id: saleId,
    amount_paid_cents: Math.round(Number(gross) * 100) || 0,
    tax_cents: 0,
    currency,
    status: "paid",
    payment_method_summary: "PayPal",
    subscription_plan: subscription.plan,
    payment_date: resource?.create_time ?? nowIso,
    metadata: { paypalSaleId: saleId, subscriptionId: resource?.billing_agreement_id ?? null },
  };
}

// ---- Billing audit vocabulary + lifecycle transitions ----------------------
//
// These strings are the audit trail's contract. Revenue Intelligence counts
// upgrades/downgrades by EXACT action name (src/lib/billing/revenue-model.ts
// PLAN_CHANGE_ACTIONS); tools/revenue-intelligence-check.ts asserts the two
// modules agree, so a renamed action cannot silently zero a dashboard.

export const BILLING_AUDIT = {
  activated: "subscription.activated",
  upgraded: "subscription.upgraded",
  downgraded: "subscription.downgraded",
  cycleChanged: "subscription.cycle_changed",
  statusChanged: "subscription.status_changed",
  cancelled: "subscription.cancelled",
  suspended: "subscription.suspended",
  expired: "subscription.expired",
  pastDue: "subscription.past_due",
  paymentSucceeded: "payment.succeeded",
  paymentFailed: "payment.failed",
  paymentRefunded: "payment.refunded",
} as const;

export type BillingAuditAction = (typeof BILLING_AUDIT)[keyof typeof BILLING_AUDIT];

const ACCESS_GRANTING = new Set(["active", "trial", "pending_renewal"]);

export function isAccessGranting(status: unknown): boolean {
  return ACCESS_GRANTING.has(String(status ?? "").toLowerCase());
}

export function tierRank(value: unknown): number {
  const tier = normalizeTier(value);
  return tier ? TIERS.indexOf(tier) + 1 : 0;
}

/** Upgrade / downgrade between two plans, or null when the tier did not move. */
export function planChangeAction(fromPlan: unknown, toPlan: unknown): BillingAuditAction | null {
  const from = tierRank(fromPlan);
  const to = tierRank(toPlan);
  if (!from || !to || from === to) return null;
  return to > from ? BILLING_AUDIT.upgraded : BILLING_AUDIT.downgraded;
}

export function statusAuditAction(status: "cancelled" | "suspended" | "expired" | "past_due"): BillingAuditAction {
  if (status === "cancelled") return BILLING_AUDIT.cancelled;
  if (status === "suspended") return BILLING_AUDIT.suspended;
  if (status === "expired") return BILLING_AUDIT.expired;
  return BILLING_AUDIT.pastDue;
}

/**
 * What an ACTIVE-subscription statement changes, given the row we already
 * hold. The webhook and the confirm route both activate the same
 * subscription, so the second arrival must be a no-op for the audit trail and
 * the customer's notifications — not a second "activated" event.
 */
export function activationAuditAction(
  previous: { plan?: string | null; status?: string | null; provider_subscription_id?: string | null } | null,
  next: { plan: string; providerSubscriptionId: string | null },
): BillingAuditAction | null {
  if (!previous) return BILLING_AUDIT.activated;
  const wasGranting = isAccessGranting(previous.status);
  const sameSubscription = Boolean(next.providerSubscriptionId) && previous.provider_subscription_id === next.providerSubscriptionId;
  if (sameSubscription && wasGranting) return planChangeAction(previous.plan, next.plan);
  if (wasGranting) return planChangeAction(previous.plan, next.plan) ?? BILLING_AUDIT.activated;
  return BILLING_AUDIT.activated;
}

function centsFromAmount(amount: unknown): number {
  const record = (amount ?? {}) as { total?: unknown; value?: unknown };
  const value = Number(record.total ?? record.value ?? 0);
  return Number.isFinite(value) ? Math.max(0, Math.round(value * 100)) : 0;
}

function currencyFromAmount(amount: unknown): string {
  const record = (amount ?? {}) as { currency?: unknown; currency_code?: unknown };
  return String(record.currency ?? record.currency_code ?? "USD").toUpperCase();
}

/**
 * Invoice row for a FAILED recurring charge (BILLING.SUBSCRIPTION.PAYMENT.FAILED
 * carries the subscription; the attempt is in billing_info.last_failed_payment).
 * `amount_paid_cents` holds the ATTEMPTED amount — nothing was collected, and
 * revenue totals only ever sum paid/refunded rows. The reference is derived from
 * the subscription and the attempt time, so a redelivery maps to the same row.
 */
export function failedPaymentInvoiceRow(
  resource: Record<string, any>,
  subscription: { user_id: string; plan: string },
  nowIso: string,
): Record<string, unknown> | null {
  const subscriptionId = typeof resource?.id === "string" ? resource.id : null;
  if (!subscriptionId) return null;
  const last = resource?.billing_info?.last_failed_payment ?? {};
  const amount = last?.amount ?? resource?.billing_info?.outstanding_balance ?? null;
  const attemptedAt = typeof last?.time === "string" && last.time ? last.time : nowIso;
  const reference = `failed:${subscriptionId}:${attemptedAt}`;
  const attemptedCents = centsFromAmount(amount);
  return {
    user_id: subscription.user_id,
    invoice_id: reference,
    provider_invoice_id: reference,
    transaction_id: null,
    amount_paid_cents: attemptedCents,
    tax_cents: 0,
    currency: currencyFromAmount(amount),
    status: "failed",
    payment_method_summary: "PayPal",
    subscription_plan: subscription.plan,
    payment_date: attemptedAt,
    metadata: {
      failedPayment: true,
      attemptedCents,
      reasonCode: last?.reason_code ?? null,
      subscriptionId,
      note: "amount_paid_cents is the attempted charge; nothing was collected",
    },
  };
}

/**
 * Patch for an invoice PayPal reports refunded (PAYMENT.SALE.REFUNDED: the
 * resource is the refund and its amount is what was refunded) or reversed
 * (PAYMENT.SALE.REVERSED: the resource is the sale itself). Refunds accumulate
 * by id, so a redelivered refund is not counted twice and a second partial
 * refund adds to the first.
 */
export function refundInvoicePatch(
  invoice: { amount_paid_cents?: unknown; metadata?: Record<string, unknown> | null },
  resource: Record<string, any>,
  eventType: string,
  nowIso: string,
): { patch: Record<string, unknown>; refundId: string; refundCents: number; isNew: boolean } {
  const amountPaid = Math.max(0, Math.round(Number(invoice.amount_paid_cents) || 0));
  const reversal = eventType === "PAYMENT.SALE.REVERSED";
  const refundId = String(resource?.id ?? `refund:${nowIso}`);
  const refundCents = reversal ? amountPaid : (centsFromAmount(resource?.amount) || amountPaid);
  const at = typeof resource?.create_time === "string" && resource.create_time ? resource.create_time : nowIso;
  const metadata = invoice.metadata && typeof invoice.metadata === "object" ? invoice.metadata : {};
  const prior = Array.isArray(metadata.refunds) ? (metadata.refunds as Array<{ id?: string; amountCents?: number; at?: string }>) : [];
  const isNew = !prior.some((entry) => entry?.id === refundId);
  const refunds = isNew ? [...prior, { id: refundId, amountCents: refundCents, at, type: reversal ? "reversal" : "refund" }] : prior;
  const total = refunds.reduce((sum, entry) => sum + (Number(entry?.amountCents) || 0), 0);
  const latest = refunds.map((entry) => String(entry?.at ?? "")).sort().pop() || at;
  return {
    refundId,
    refundCents,
    isNew,
    patch: {
      status: "refunded",
      updated_at: nowIso,
      metadata: { ...metadata, refunds, refundedCents: amountPaid ? Math.min(amountPaid, total) : total, refundedAt: latest },
    },
  };
}

// ---- Money-back refunds cancel the subscription ------------------------------
//
// The Refund Policy (src/pages/Refund.tsx) promises that a money-back refund —
// the full refund of a subscriber's FIRST payment, requested within the window —
// cancels the subscription. PayPal does not do that on its own: refunding a sale
// leaves the subscription billing. Renewal refunds (duplicate charge, charge
// after cancellation) are goodwill corrections and leave the subscription alone.

/** Money-back window in days. MUST equal REFUND_POLICY.initialWindowDays (asserted by tools/billing-edge-check.ts). */
export const REFUND_WINDOW_DAYS = 7;
/**
 * Calendar-day allowance for issuing an approved refund: the policy promises
 * processing within REFUND_POLICY.processingDays (10) BUSINESS days, so a
 * request made on day 7 can be refunded up to two weeks later.
 */
export const REFUND_PROCESSING_GRACE_DAYS = 14;

const DAY_MS = 86_400_000;

export function moneyBackRefundCancels(opts: {
  eventType: string;
  amountPaidCents: unknown;
  refundedCents: unknown;
  paymentDate: unknown;
  refundedAt: unknown;
  isFirstPayment: boolean;
}): boolean {
  if (opts.eventType !== "PAYMENT.SALE.REFUNDED" || !opts.isFirstPayment) return false;
  const paid = Math.round(Number(opts.amountPaidCents) || 0);
  if (paid <= 0 || Math.round(Number(opts.refundedCents) || 0) < paid) return false;
  const paidAt = Date.parse(String(opts.paymentDate ?? ""));
  const refundedAt = Date.parse(String(opts.refundedAt ?? ""));
  if (!Number.isFinite(paidAt) || !Number.isFinite(refundedAt)) return false;
  return refundedAt - paidAt <= (REFUND_WINDOW_DAYS + REFUND_PROCESSING_GRACE_DAYS) * DAY_MS;
}

/** A money-back refund ends access now — the refunded period was not paid for. */
export function refundCancellationPatch(row: { cancelled_at?: string | null } | null, nowIso: string): Record<string, unknown> {
  return {
    status: "cancelled",
    auto_renew: false,
    cancel_at_period_end: true,
    cancelled_at: row?.cancelled_at ?? nowIso,
    updated_at: nowIso,
  };
}

// ---- Reconciliation (repair for missed webhooks) -----------------------------
//
// PayPal retries a failed webhook for a few days, then gives up. The reconcile
// route (POST /api/v1/paypal/reconcile, scheduled by
// supabase/paypal-reconcile-schedule.sql) re-reads PayPal's own state so a
// lost ACTIVATED, status change or PAYMENT.SALE.COMPLETED is still applied.

/** Checkouts younger than this are re-checked for an approval whose webhook was lost. */
export const RECONCILE_CHECKOUT_LOOKBACK_DAYS = 7;
/** Payment history window re-read per subscription. */
export const RECONCILE_PAYMENT_LOOKBACK_DAYS = 35;
/** Local statuses whose PayPal subscription may still change. */
export const RECONCILE_STATUSES = ["active", "trial", "past_due", "suspended", "pending_renewal", "incomplete"];

/**
 * What a remote subscription resource requires of the local row, or null when
 * the two already agree. `sync` covers ACTIVE (status, plan and renewal date);
 * the others are the webhook's own status transitions.
 */
export function reconcileAction(
  env: EnvGetter,
  local: { plan?: string | null; status?: string | null; renewal_date?: string | null; cancel_at_period_end?: boolean | null },
  remote: Record<string, any>,
): "sync" | "cancelled" | "suspended" | "expired" | null {
  const remoteStatus = String(remote?.status ?? "").toUpperCase();
  const localStatus = String(local.status ?? "").toLowerCase();
  if (remoteStatus === "CANCELLED") return local.cancel_at_period_end || localStatus === "cancelled" ? null : "cancelled";
  if (remoteStatus === "SUSPENDED") return localStatus === "suspended" ? null : "suspended";
  if (remoteStatus === "EXPIRED") return localStatus === "expired" ? null : "expired";
  if (remoteStatus !== "ACTIVE") return null;
  const info = planInfoFromId(env, remote?.plan_id);
  const next = remote?.billing_info?.next_billing_time ?? null;
  const sameTime = (a: unknown, b: unknown) => Date.parse(String(a ?? "")) === Date.parse(String(b ?? ""));
  const drift = localStatus !== "active"
    || (info !== null && info.tier !== normalizeTier(local.plan))
    || (next !== null && !sameTime(next, local.renewal_date));
  return drift ? "sync" : null;
}

/**
 * Invoice row for a completed charge read from
 * GET /v1/billing/subscriptions/{id}/transactions. The transaction id is the
 * sale id PAYMENT.SALE.COMPLETED carries, so a payment the webhook already
 * recorded maps to the same provider_invoice_id and is not inserted twice.
 */
export function invoiceRowFromTransaction(
  transaction: Record<string, any>,
  subscription: { user_id: string; plan: string },
  subscriptionId: string,
  nowIso: string,
): Record<string, unknown> | null {
  if (String(transaction?.status ?? "").toUpperCase() !== "COMPLETED") return null;
  const saleId = typeof transaction?.id === "string" && transaction.id ? transaction.id : null;
  if (!saleId) return null;
  const gross = transaction?.amount_with_breakdown?.gross_amount ?? {};
  return invoiceRow(
    { id: saleId, amount: gross, create_time: transaction?.time ?? nowIso, billing_agreement_id: subscriptionId },
    subscription,
    nowIso,
  );
}

// ---- Cancellation: access until the end of the paid period -------------------
//
// A customer who cancels keeps what they already paid for. Provider billing
// stops immediately (PayPal cancels on its side), but the row stays in its
// access-granting status with cancel_at_period_end = true until
// current_period_end; the scheduled database function
// public.qguard_expire_cancelled_subscriptions() then moves it to 'cancelled'
// (supabase/subscription-period-end-cancellation.sql). With no paid period left
// — or no known period end — access ends immediately.

export function cancellationPatch(
  row: { status?: string | null; current_period_end?: string | null } | null,
  nowIso: string,
): { patch: Record<string, unknown>; accessUntil: string | null } {
  const periodEnd = row?.current_period_end ? Date.parse(row.current_period_end) : Number.NaN;
  const keepsAccess = Boolean(row) && isAccessGranting(row?.status) && Number.isFinite(periodEnd) && periodEnd > Date.parse(nowIso);
  const base = { auto_renew: false, cancel_at_period_end: true, cancelled_at: nowIso, updated_at: nowIso };
  return keepsAccess
    ? { patch: base, accessUntil: row!.current_period_end! }
    : { patch: { ...base, status: "cancelled" }, accessUntil: null };
}

/** A cancellation already recorded (redelivery / second click) changes nothing. */
export function isCancellationRecorded(row: { status?: string | null; cancel_at_period_end?: boolean | null; cancelled_at?: string | null } | null): boolean {
  if (!row) return false;
  if (String(row.status ?? "").toLowerCase() === "cancelled") return true;
  return Boolean(row.cancel_at_period_end && row.cancelled_at);
}

// ---- Webhook idempotency ----------------------------------------------------
//
// A delivery is CLAIMED before any side effect runs (paypal_webhook_events has
// a unique event_id). A concurrent redelivery sees the claim and backs off; a
// claim left behind by a crashed run is stale after WEBHOOK_CLAIM_STALE_MS and
// may run again; a finished event is a duplicate. A failure marks the claim
// failed so PayPal's retry runs it again — nothing is lost, and nothing runs
// twice at the same time.

export const WEBHOOK_CLAIM_STALE_MS = 2 * 60_000;

export function webhookClaimDecision(
  existing: { status?: string | null; claimed_at?: string | null; processed_at?: string | null } | null,
  nowMs: number,
): "run" | "duplicate" | "in-progress" {
  if (!existing) return "run";
  const status = String(existing.status ?? "processed").toLowerCase();
  if (status === "processed") return "duplicate";
  if (status === "failed") return "run";
  const claimedAt = Date.parse(String(existing.claimed_at ?? existing.processed_at ?? ""));
  if (!Number.isFinite(claimedAt)) return "run";
  return nowMs - claimedAt > WEBHOOK_CLAIM_STALE_MS ? "run" : "in-progress";
}

// ---- Google Play Billing (roadmap 4.6) --------------------------------------
//
// Mirrors src/api-server/play-billing.ts, the Express implementation: the
// same env names, product-id convention, state mapping and ledger rows, so the
// two can never disagree about what a Play purchase grants.

/** List prices (USD) for Play invoices — Google does not return the charged
 *  amount. MUST equal src/lib/billing/plan-pricing.ts PLAN_PRICING;
 *  tools/billing-edge-check.ts asserts it. */
export const PLAY_LIST_PRICING: Record<Tier, { monthly: number; yearlyPerMonth: number }> = {
  Starter: { monthly: 1, yearlyPerMonth: 1 },
  Basic: { monthly: 8, yearlyPerMonth: 5 },
  Pro: { monthly: 30, yearlyPerMonth: 20 },
  Elite: { monthly: 199, yearlyPerMonth: 150 },
};

export function playPackageName(env: EnvGetter): string {
  return (env("GOOGLE_PLAY_PACKAGE_NAME") ?? "").trim();
}

export function playServiceAccount(env: EnvGetter): { email: string; privateKey: string } | null {
  const raw = env("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON");
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed?.client_email && parsed?.private_key) {
        return { email: String(parsed.client_email), privateKey: String(parsed.private_key) };
      }
    } catch {
      // fall through to the pair form
    }
  }
  const email = env("GOOGLE_PLAY_SA_EMAIL");
  const privateKey = env("GOOGLE_PLAY_SA_PRIVATE_KEY")?.replace(/\\n/g, "\n");
  return email && privateKey ? { email, privateKey } : null;
}

export function isPlayConfigured(env: EnvGetter): boolean {
  return Boolean(playPackageName(env) && playServiceAccount(env));
}

/** Play product id for a tier: `qguard_<tier>` unless PLAY_PRODUCT_<TIER> overrides it. */
export function playProductIdFor(env: EnvGetter, tier: Tier): string {
  return (env(`PLAY_PRODUCT_${tier.toUpperCase()}`) ?? "").trim() || `qguard_${tier.toLowerCase()}`;
}

export function tierForPlayProduct(env: EnvGetter, productId: string): Tier | null {
  return TIERS.find((tier) => playProductIdFor(env, tier) === productId) ?? null;
}

/** basePlanId → billing cycle. Convention: 'monthly' / 'yearly' (or 'annual'). */
export function cycleForPlayBasePlan(basePlanId: unknown): DbCycle {
  const text = String(basePlanId ?? "").toLowerCase();
  return text.includes("year") || text.includes("annual") ? "annual" : "monthly";
}

/**
 * Google subscriptionState → our status. Per Play policy the user KEEPS the
 * entitlement in a grace period and while CANCELED but not yet expired
 * (cancellation only turns off auto-renew).
 */
export function mapPlayState(state: unknown): { status: DbStatus; entitled: boolean; autoRenew: boolean } {
  switch (String(state ?? "")) {
    case "SUBSCRIPTION_STATE_ACTIVE":
      return { status: "active", entitled: true, autoRenew: true };
    case "SUBSCRIPTION_STATE_IN_GRACE_PERIOD":
      return { status: "pending_renewal", entitled: true, autoRenew: true };
    case "SUBSCRIPTION_STATE_CANCELED":
      return { status: "active", entitled: true, autoRenew: false };
    case "SUBSCRIPTION_STATE_ON_HOLD":
    case "SUBSCRIPTION_STATE_PAUSED":
      return { status: "suspended", entitled: false, autoRenew: false };
    case "SUBSCRIPTION_STATE_EXPIRED":
      return { status: "expired", entitled: false, autoRenew: false };
    default:
      return { status: "incomplete", entitled: false, autoRenew: false };
  }
}

export class PlayPurchaseError extends Error {
  constructor(readonly code: "NOT_BOUND" | "ACCOUNT_MISMATCH" | "UNKNOWN_PRODUCT", message: string) {
    super(message);
  }
}

/**
 * What a verified subscriptionsv2 resource grants, and the rows that record it.
 * `expectedUserId` is the authenticated caller on /verify and must equal the
 * obfuscatedExternalAccountId the app set at checkout (the anti-spoof binding);
 * RTDN passes null and relies on the binding Google recorded.
 */
export function playSubscriptionRows(
  env: EnvGetter,
  resource: Record<string, any>,
  tokenHash: string,
  expectedUserId: string | null,
  nowIso: string,
): {
  userId: string;
  tier: Tier;
  cycle: DbCycle;
  mapped: ReturnType<typeof mapPlayState>;
  productId: string;
  expiryTime: string | null;
  subscription: Record<string, unknown>;
  invoice: Record<string, unknown> | null;
} {
  const boundUserId = String(resource?.externalAccountIdentifiers?.obfuscatedExternalAccountId ?? "");
  const userId = expectedUserId || boundUserId;
  if (!userId) throw new PlayPurchaseError("NOT_BOUND", "purchase is not bound to a QGuard account (missing obfuscatedExternalAccountId)");
  if (expectedUserId && boundUserId && boundUserId !== expectedUserId) {
    throw new PlayPurchaseError("ACCOUNT_MISMATCH", "purchase belongs to a different QGuard account");
  }
  const line = Array.isArray(resource?.lineItems) ? resource.lineItems[0] : null;
  const productId = String(line?.productId ?? "");
  const tier = tierForPlayProduct(env, productId);
  if (!tier) throw new PlayPurchaseError("UNKNOWN_PRODUCT", `unrecognized Play product: ${productId || "(none)"}`);
  const cycle = cycleForPlayBasePlan(line?.offerDetails?.basePlanId);
  const mapped = mapPlayState(resource?.subscriptionState);
  const expiryTime: string | null = line?.expiryTime ?? null;
  const subscription = {
    user_id: userId,
    subscription_id: `gp_${tokenHash.slice(0, 48)}`,
    provider: "google_play",
    provider_customer_id: boundUserId || userId,
    provider_subscription_id: tokenHash,
    plan: tier,
    status: mapped.status,
    billing_cycle: cycle,
    auto_renew: mapped.autoRenew,
    cancel_at_period_end: !mapped.autoRenew && mapped.entitled,
    current_period_start: resource?.startTime ?? nowIso,
    current_period_end: expiryTime,
    renewal_date: mapped.autoRenew ? expiryTime : null,
    cancelled_at: mapped.status === "cancelled" ? nowIso : null,
    metadata: {
      playProductId: productId,
      playBasePlanId: line?.offerDetails?.basePlanId ?? null,
      latestOrderId: resource?.latestOrderId ?? null,
      subscriptionState: resource?.subscriptionState ?? null,
    },
    updated_at: nowIso,
  };
  const orderId = resource?.latestOrderId ? String(resource.latestOrderId) : null;
  const price = PLAY_LIST_PRICING[tier];
  const amountCents = Math.round((cycle === "annual" ? price.yearlyPerMonth * 12 : price.monthly) * 100);
  const invoice = orderId && mapped.entitled
    ? {
      user_id: userId,
      invoice_id: orderId,
      provider_invoice_id: orderId,
      transaction_id: orderId,
      amount_paid_cents: amountCents,
      tax_cents: 0,
      currency: "USD",
      status: "paid",
      payment_method_summary: "Google Play",
      subscription_plan: tier,
      // subscriptionsv2 carries no per-order charge time; the call that first
      // sees an order is the closest recorded moment of payment.
      payment_date: nowIso,
      metadata: { playOrderId: orderId, purchaseTokenHash: tokenHash, amountSource: "catalog_list_price" },
    }
    : null;
  return { userId, tier, cycle, mapped, productId, expiryTime, subscription, invoice };
}

/** Decode a Pub/Sub push envelope into the RTDN payload; null when malformed. */
export function parseRtdnMessage(body: unknown): { messageId: string; payload: any } | null {
  const message = (body as any)?.message;
  if (!message?.data) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64ToBytes(String(message.data))));
    return { messageId: String(message.messageId ?? message.message_id ?? ""), payload };
  } catch {
    return null;
  }
}

/** Constant-time string comparison for the RTDN shared secret. */
export function timingSafeEqualText(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) diff |= left[index] ^ right[index];
  return diff === 0;
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, ""));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function base64Url(bytes: Uint8Array | string): string {
  const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The DER body of a PEM private key ("-----BEGIN PRIVATE KEY-----" PKCS#8). */
export function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----BEGIN [^-]+-----/, "").replace(/-----END [^-]+-----/, "").replace(/\s+/g, "");
  if (!body) throw new Error("empty private key");
  return base64ToBytes(body);
}

/** Header + claims of the service-account JWT that buys an androidpublisher token. */
export function playJwtSigningInput(serviceAccountEmail: string, nowSeconds: number): string {
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64Url(JSON.stringify({
    iss: serviceAccountEmail,
    scope: "https://www.googleapis.com/auth/androidpublisher",
    aud: "https://oauth2.googleapis.com/token",
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  }));
  return `${header}.${claims}`;
}
