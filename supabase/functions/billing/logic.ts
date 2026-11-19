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
    playRtdn: Boolean((env("PLAY_RTDN_TOKEN") ?? "").trim() || (env("PLAY_RTDN_AUDIENCE") ?? "").trim()),
    playRtdnOidc: Boolean((env("PLAY_RTDN_AUDIENCE") ?? "").trim()),
    playTokenEncryption: tokenEncryptionKeyBytes(env) !== null,
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
  // Store lifecycle (Google Play RTDN + verification).
  renewed: "subscription.renewed",
  recovered: "subscription.recovered",
  restarted: "subscription.restarted",
  onHold: "subscription.on_hold",
  inGracePeriod: "subscription.in_grace_period",
  revoked: "subscription.revoked",
  replaced: "subscription.replaced",
  purchaseVerified: "purchase.verified",
  purchaseRejected: "purchase.rejected",
  purchaseAcknowledged: "purchase.acknowledged",
  verificationFailed: "purchase.verification_failed",
  restoreInitiated: "restore.initiated",
  restoreCompleted: "restore.completed",
} as const;

export type BillingAuditAction = (typeof BILLING_AUDIT)[keyof typeof BILLING_AUDIT];

// No free trial exists in the catalog (Qguard_Wiki/GooglePlay_Billing §1), so
// 'trial' is not access-granting. Same set as src/lib/subscription-access.ts,
// qguard-messaging/src/lib/subscription.ts and SQL qguard_subscription_grants_access.
const ACCESS_GRANTING = new Set(["active", "pending_renewal"]);

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

// ---- A full refund of the first payment ends the subscription ----------------
//
// QGuard offers NO promotional money-back guarantee (owner decision
// 2026-11-12). Refunds still happen — through PayPal or Google Play, or because
// consumer law requires them — and the subscription lifecycle must reflect
// them: a FULL refund of a subscriber's FIRST payment means the plan was never
// paid for, so the subscription is cancelled and access ends. PayPal does not
// do that on its own (refunding a sale leaves the subscription billing).
// Renewal refunds (duplicate charge, charge after cancellation) are
// corrections and leave the subscription alone.

/** A first-payment refund issued within this many days of the charge cancels the plan. */
export const REFUND_WINDOW_DAYS = 7;
/** Allowance for a refund decided inside the window but issued later. */
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
/** Local statuses whose provider subscription may still change. */
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

// ---- Google Play Billing ------------------------------------------------------
//
// Four paid tiers with no trials or introductory offers. Each of the eight
// Play products has one base plan. Its ID identifies the tier and billing period:
//
//   qh_starter_monthly  qh_starter_yearly   $1   / $12
//   qh_basic_monthly    qh_basic_yearly     $8   / $60
//   qh_pro_monthly      qh_pro_yearly       $30  / $240
//   qh_elite_monthly    qh_elite_yearly     $199 / $1,800
//
// Every rule here is shared by the Edge Function, the Express API
// (src/api-server/play-billing.ts) and the Node checks, so the three can never
// disagree about what a Play purchase grants.

/** List prices (USD). MUST equal src/lib/billing/plan-pricing.ts PLAN_PRICING;
 *  tools/billing-edge-check.ts asserts it. Google Play's localized price is what the buyer
 *  is charged — these are catalog figures, used only when Google does not
 *  report the recurring price. */
export const PLAY_LIST_PRICING: Record<Tier, { monthly: number; yearlyPerMonth: number }> = {
  Starter: { monthly: 1, yearlyPerMonth: 1 },
  Basic: { monthly: 8, yearlyPerMonth: 5 },
  Pro: { monthly: 30, yearlyPerMonth: 20 },
  Elite: { monthly: 199, yearlyPerMonth: 150 },
};

/** Catalog charge for one billing period, in cents. */
export function listPriceCents(tier: Tier, cycle: DbCycle | Cycle): number {
  const price = PLAY_LIST_PRICING[tier];
  return Math.round((cycle === "annual" || cycle === "yearly" ? price.yearlyPerMonth * 12 : price.monthly) * 100);
}

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

/**
 * Play product id for a tier + period: `qh_<tier>_<monthly|yearly>` unless
 * PLAY_PRODUCT_<TIER>_<CYCLE> overrides it (a product id cannot be reused once
 * deleted in Play Console, so the mapping must be remappable without a build).
 */
export function playProductIdFor(env: EnvGetter, tier: Tier, cycle: Cycle | DbCycle): string {
  const period: Cycle = cycle === "annual" || cycle === "yearly" ? "yearly" : "monthly";
  return (env(`PLAY_PRODUCT_${tier.toUpperCase()}_${period.toUpperCase()}`) ?? "").trim()
    || `qh_${tier.toLowerCase()}_${period}`;
}

/** Every product this service sells on Play, in catalog order. */
export function playProductCatalog(env: EnvGetter): Array<{ productId: string; tier: Tier; cycle: Cycle }> {
  const out: Array<{ productId: string; tier: Tier; cycle: Cycle }> = [];
  for (const tier of TIERS) {
    for (const cycle of CYCLES) out.push({ productId: playProductIdFor(env, tier, cycle), tier, cycle });
  }
  return out;
}

/** Tier + billing period a Play product id stands for; null for anything we do not sell. */
export function playProductInfo(env: EnvGetter, productId: unknown): { tier: Tier; cycle: DbCycle } | null {
  if (typeof productId !== "string" || !productId) return null;
  const match = playProductCatalog(env).find((entry) => entry.productId === productId);
  return match ? { tier: match.tier, cycle: toDbCycle(match.cycle) } : null;
}

export type PlayMapped = {
  status: DbStatus;
  /** Google currently grants the subscriber access. */
  entitled: boolean;
  autoRenew: boolean;
  /** A payment problem the customer must fix in Google Play. */
  paymentIssue: boolean;
};

/**
 * Google subscriptionState → our status, per Play policy:
 *  - IN_GRACE_PERIOD keeps access (Google is retrying the payment);
 *  - CANCELED only stops renewal — access continues until expiryTime;
 *  - ON_HOLD (payment failed after grace) and PAUSED lose access;
 *  - PENDING (a purchase awaiting payment) NEVER grants access.
 * `expiryTime` matters only for CANCELED: once the paid-through time passes,
 * a canceled subscription is expired even if Google's state has not moved yet.
 */
export function mapPlayState(state: unknown, expiryTime?: unknown, nowMs: number = Date.now()): PlayMapped {
  switch (String(state ?? "")) {
    case "SUBSCRIPTION_STATE_ACTIVE":
      return { status: "active", entitled: true, autoRenew: true, paymentIssue: false };
    case "SUBSCRIPTION_STATE_IN_GRACE_PERIOD":
      return { status: "pending_renewal", entitled: true, autoRenew: true, paymentIssue: true };
    case "SUBSCRIPTION_STATE_CANCELED": {
      const expiry = Date.parse(String(expiryTime ?? ""));
      const paidThrough = !Number.isFinite(expiry) || expiry > nowMs;
      return paidThrough
        ? { status: "active", entitled: true, autoRenew: false, paymentIssue: false }
        : { status: "expired", entitled: false, autoRenew: false, paymentIssue: false };
    }
    case "SUBSCRIPTION_STATE_ON_HOLD":
      return { status: "past_due", entitled: false, autoRenew: true, paymentIssue: true };
    case "SUBSCRIPTION_STATE_PAUSED":
      return { status: "suspended", entitled: false, autoRenew: true, paymentIssue: false };
    case "SUBSCRIPTION_STATE_EXPIRED":
      return { status: "expired", entitled: false, autoRenew: false, paymentIssue: false };
    case "SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED":
      return { status: "cancelled", entitled: false, autoRenew: false, paymentIssue: false };
    case "SUBSCRIPTION_STATE_PENDING":
    default:
      return { status: "incomplete", entitled: false, autoRenew: false, paymentIssue: false };
  }
}

export class PlayPurchaseError extends Error {
  constructor(
    readonly code: "NOT_BOUND" | "ACCOUNT_MISMATCH" | "UNKNOWN_PRODUCT" | "NO_LINE_ITEM",
    message: string,
  ) {
    super(message);
  }
}

/** Google Money ({ currencyCode, units, nanos }) → integer cents; null when absent. */
export function moneyToCents(money: unknown): { cents: number; currency: string } | null {
  const value = money as { currencyCode?: unknown; units?: unknown; nanos?: unknown } | null;
  if (!value || typeof value.currencyCode !== "string" || !value.currencyCode) return null;
  const units = Number(value.units ?? 0);
  const nanos = Number(value.nanos ?? 0);
  if (!Number.isFinite(units) || !Number.isFinite(nanos)) return null;
  return { cents: Math.round(units * 100 + nanos / 10_000_000), currency: value.currencyCode.toUpperCase() };
}

/** What one authoritative subscriptionsv2 resource says, independent of any account. */
export interface PlayFacts {
  productId: string;
  tier: Tier;
  cycle: DbCycle;
  mapped: PlayMapped;
  expiryTime: string | null;
  startTime: string | null;
  orderId: string | null;
  linkedPurchaseToken: string | null;
  boundAccount: string;
  acknowledged: boolean;
  testPurchase: boolean;
  /** Recurring price Google reports for the base plan (taxes excluded), or the catalog list price. */
  price: { cents: number; currency: string; source: "play_recurring_price" | "catalog_list_price" };
  cancelReason: string | null;
}

export function playFacts(env: EnvGetter, resource: Record<string, any>, nowMs: number = Date.now()): PlayFacts {
  const items: Array<Record<string, any>> = Array.isArray(resource?.lineItems) ? resource.lineItems : [];
  if (items.length === 0) throw new PlayPurchaseError("NO_LINE_ITEM", "Google Play returned a subscription without line items");
  // A plan change can leave the outgoing item listed; the item that expires
  // last is the one the customer holds now.
  const line = [...items].sort((a, b) => (Date.parse(String(b?.expiryTime ?? "")) || 0) - (Date.parse(String(a?.expiryTime ?? "")) || 0))[0];
  const productId = String(line?.productId ?? "");
  const info = playProductInfo(env, productId);
  if (!info) throw new PlayPurchaseError("UNKNOWN_PRODUCT", `unrecognized Play product: ${productId || "(none)"}`);
  const expiryTime: string | null = typeof line?.expiryTime === "string" ? line.expiryTime : null;
  const reported = moneyToCents(line?.autoRenewingPlan?.recurringPrice);
  const cancelContext = resource?.canceledStateContext ?? null;
  const cancelReason = cancelContext
    ? cancelContext.userInitiatedCancellation ? "user"
      : cancelContext.systemInitiatedCancellation ? "system"
      : cancelContext.developerInitiatedCancellation ? "developer"
      : cancelContext.replacementCancellation ? "replaced"
      : "unknown"
    : null;
  return {
    productId,
    tier: info.tier,
    cycle: info.cycle,
    mapped: mapPlayState(resource?.subscriptionState, expiryTime, nowMs),
    expiryTime,
    startTime: typeof resource?.startTime === "string" ? resource.startTime : null,
    orderId: String(line?.latestSuccessfulOrderId ?? resource?.latestOrderId ?? "") || null,
    linkedPurchaseToken: typeof resource?.linkedPurchaseToken === "string" && resource.linkedPurchaseToken ? resource.linkedPurchaseToken : null,
    boundAccount: String(resource?.externalAccountIdentifiers?.obfuscatedExternalAccountId ?? ""),
    acknowledged: String(resource?.acknowledgementState ?? "") === "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED",
    testPurchase: Boolean(resource?.testPurchase),
    price: reported
      ? { ...reported, source: "play_recurring_price" }
      : { cents: listPriceCents(info.tier, info.cycle), currency: "USD", source: "catalog_list_price" },
    cancelReason,
  };
}

/**
 * The account id the app passes to Google Play as obfuscatedAccountId: a
 * SHA-256 of the Supabase user id, so Google never receives our internal
 * identifier (64 hex chars = Play's maximum length). The server is the only
 * party that maps it back (billing_play_accounts).
 */
export async function playAccountIdFor(userId: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`qguard-play-account:v1:${userId}`)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Whether the purchase's recorded binding belongs to `userId`. Accepts the
 * hashed account id the app sends today and the raw user id earlier builds
 * sent. An empty binding never matches: an unbound token could belong to anyone.
 */
export async function playBindingMatches(boundAccount: string, userId: string): Promise<boolean> {
  if (!boundAccount) return false;
  if (boundAccount === userId) return true;
  return timingSafeEqualText(boundAccount, await playAccountIdFor(userId));
}

/** billing_subscriptions row for a verified Play purchase. */
export function playSubscriptionRow(
  facts: PlayFacts,
  ids: { userId: string; tokenHash: string; tokenEncrypted: string | null; linkedTokenHash: string | null },
  previous: { cancelled_at?: string | null } | null,
  nowIso: string,
): Record<string, unknown> {
  const { mapped } = facts;
  return {
    user_id: ids.userId,
    subscription_id: `gp_${ids.tokenHash.slice(0, 48)}`,
    provider: "google_play",
    provider_customer_id: facts.boundAccount || null,
    provider_subscription_id: ids.tokenHash,
    product_id: facts.productId,
    plan: facts.tier,
    status: mapped.status,
    billing_cycle: facts.cycle,
    auto_renew: mapped.autoRenew,
    cancel_at_period_end: mapped.entitled && !mapped.autoRenew,
    current_period_start: facts.startTime ?? nowIso,
    current_period_end: facts.expiryTime,
    renewal_date: mapped.autoRenew && mapped.entitled ? facts.expiryTime : null,
    cancelled_at: facts.cancelReason ? previous?.cancelled_at ?? nowIso : null,
    cancel_reason: facts.cancelReason,
    purchase_token_encrypted: ids.tokenEncrypted,
    linked_purchase_token_hash: ids.linkedTokenHash,
    google_order_id: facts.orderId,
    acknowledgement_state: facts.acknowledged ? "acknowledged" : "pending",
    verification_state: "verified",
    last_verified_at: nowIso,
    amount_cents: facts.testPurchase ? 0 : facts.price.cents,
    currency: facts.price.currency,
    metadata: {
      playProductId: facts.productId,
      latestOrderId: facts.orderId,
      subscriptionState: mapped.status,
      priceSource: facts.price.source,
      ...(facts.testPurchase ? { testPurchase: true, complimentary: true } : {}),
    },
    updated_at: nowIso,
  };
}

/**
 * Invoice for the order Google reports. Each renewal carries a new order id,
 * so a renewal becomes its own row and a repeat of the same order is a no-op
 * (provider_invoice_id is unique). License-tester purchases are free: they are
 * recorded for history at zero so they can never inflate revenue.
 */
export function playInvoiceRow(facts: PlayFacts, userId: string, tokenHash: string, nowIso: string): Record<string, unknown> | null {
  if (!facts.orderId || !facts.mapped.entitled) return null;
  return {
    user_id: userId,
    invoice_id: facts.orderId,
    provider_invoice_id: facts.orderId,
    transaction_id: facts.orderId,
    amount_paid_cents: facts.testPurchase ? 0 : facts.price.cents,
    tax_cents: 0,
    currency: facts.price.currency,
    status: "paid",
    payment_method_summary: facts.testPurchase ? "Google Play (test purchase)" : "Google Play",
    subscription_plan: facts.tier,
    // subscriptionsv2 carries no per-order charge time; the call that first
    // sees an order is the closest recorded moment of payment.
    payment_date: nowIso,
    metadata: {
      playOrderId: facts.orderId,
      purchaseTokenHash: tokenHash,
      productId: facts.productId,
      billingCycle: facts.cycle,
      amountSource: facts.testPurchase ? "test_purchase" : facts.price.source,
      grossOfStoreFee: true,
      ...(facts.testPurchase ? { testPurchase: true, listPriceCents: listPriceCents(facts.tier, facts.cycle) } : {}),
    },
  };
}

/**
 * Whether a Play resource may overwrite the account's current row. The row is
 * one per account, so a stale token must never clobber a newer subscription:
 * after an upgrade Google sends EXPIRED for the REPLACED token, which must not
 * lock the customer out of the plan that replaced it.
 */
export function playMayReplaceRow(
  current: { provider?: string | null; provider_subscription_id?: string | null; linked_purchase_token_hash?: string | null; status?: string | null; current_period_end?: string | null } | null,
  incoming: { tokenHash: string; entitled: boolean },
  nowMs: number = Date.now(),
): boolean {
  if (!current) return true;
  if (current.provider === "google_play" && current.provider_subscription_id === incoming.tokenHash) return true;
  if (current.provider === "google_play" && current.linked_purchase_token_hash === incoming.tokenHash) return false;
  if (incoming.entitled) return true;
  // A non-entitled statement about some other token replaces only a row that
  // grants nothing itself.
  return !rowGrantsAccess(current, nowMs);
}

/** Access-granting statuses: no trial exists in the catalog. */
const ACCESS_STATUS_SET = new Set(["active", "pending_renewal"]);

/** Tolerance after the recorded period end before access is withdrawn without a provider event. */
export function accessGraceMs(provider: unknown): number {
  // Google moves expiryTime itself during a grace period; only RTDN delivery
  // latency needs covering. PayPal renewals can lag the charge by days.
  return String(provider ?? "") === "google_play" ? 60 * 60 * 1000 : 72 * 60 * 60 * 1000;
}

/** The same rule as SQL public.qguard_subscription_grants_access (asserted by the checks). */
export function rowGrantsAccess(
  row: { provider?: string | null; status?: string | null; current_period_end?: string | null },
  nowMs: number = Date.now(),
): boolean {
  if (!ACCESS_STATUS_SET.has(String(row.status ?? "").toLowerCase())) return false;
  if (!row.current_period_end) return true;
  const end = Date.parse(row.current_period_end);
  return !Number.isFinite(end) || end + accessGraceMs(row.provider) > nowMs;
}

/** Real-Time Developer Notification types (subscriptionNotification.notificationType). */
export const PLAY_NOTIFICATION_TYPES: Record<number, string> = {
  1: "SUBSCRIPTION_RECOVERED",
  2: "SUBSCRIPTION_RENEWED",
  3: "SUBSCRIPTION_CANCELED",
  4: "SUBSCRIPTION_PURCHASED",
  5: "SUBSCRIPTION_ON_HOLD",
  6: "SUBSCRIPTION_IN_GRACE_PERIOD",
  7: "SUBSCRIPTION_RESTARTED",
  8: "SUBSCRIPTION_PRICE_CHANGE_CONFIRMED",
  9: "SUBSCRIPTION_DEFERRED",
  10: "SUBSCRIPTION_PAUSED",
  11: "SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED",
  12: "SUBSCRIPTION_REVOKED",
  13: "SUBSCRIPTION_EXPIRED",
  19: "SUBSCRIPTION_PRICE_CHANGE_UPDATED",
  20: "SUBSCRIPTION_PENDING_PURCHASE_CANCELED",
};

/** Lifecycle audit action an RTDN type stands for (null: re-sync only). */
export function playNotificationAuditAction(type: unknown): string | null {
  switch (Number(type)) {
    case 1: return BILLING_AUDIT.recovered;
    case 2: return BILLING_AUDIT.renewed;
    case 3: return BILLING_AUDIT.cancelled;
    case 4: return BILLING_AUDIT.activated;
    case 5: return BILLING_AUDIT.onHold;
    case 6: return BILLING_AUDIT.inGracePeriod;
    case 7: return BILLING_AUDIT.restarted;
    case 10: return BILLING_AUDIT.suspended;
    case 12: return BILLING_AUDIT.revoked;
    case 13: return BILLING_AUDIT.expired;
    default: return null;
  }
}

/**
 * The RTDN payload as it may be stored: purchase tokens removed (they are
 * bearer credentials for the subscription), everything else kept for audit.
 */
export function sanitizeRtdnPayload(payload: Record<string, any>): Record<string, unknown> {
  const clean = JSON.parse(JSON.stringify(payload ?? {}));
  if (clean?.subscriptionNotification) delete clean.subscriptionNotification.purchaseToken;
  if (clean?.voidedPurchaseNotification) delete clean.voidedPurchaseNotification.purchaseToken;
  if (clean?.oneTimeProductNotification) delete clean.oneTimeProductNotification.purchaseToken;
  return clean;
}

/** After this many failed attempts an inbox message is parked as dead-letter and stops retrying. */
export const RTDN_MAX_ATTEMPTS = 8;

/** Inbox claim decision; same contract as webhookClaimDecision plus dead-letter. */
export function inboxClaimDecision(
  existing: { status?: string | null; claimed_at?: string | null; attempts?: number | null } | null,
  nowMs: number,
): "run" | "duplicate" | "in-progress" | "dead-letter" {
  if (!existing) return "run";
  const status = String(existing.status ?? "processed").toLowerCase();
  if (status === "processed" || status === "ignored") return "duplicate";
  if (status === "dead_letter") return "dead-letter";
  if (status === "failed") return Number(existing.attempts ?? 0) >= RTDN_MAX_ATTEMPTS ? "dead-letter" : "run";
  const claimedAt = Date.parse(String(existing.claimed_at ?? ""));
  if (!Number.isFinite(claimedAt)) return "run";
  return nowMs - claimedAt > WEBHOOK_CLAIM_STALE_MS ? "run" : "in-progress";
}

// ---- Pub/Sub push authentication (OIDC) --------------------------------------
//
// Pub/Sub push subscriptions with authentication send
// `Authorization: Bearer <Google-signed OIDC JWT>`. We verify the RS256
// signature against Google's published keys, the issuer, the audience we
// configured on the subscription, the expiry, and the service account that
// Pub/Sub signs as. A forged or replayed-after-expiry request is refused.

export const GOOGLE_OIDC_ISSUERS = new Set(["https://accounts.google.com", "accounts.google.com"]);
export const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

export function decodeJwt(token: string): { header: Record<string, any>; claims: Record<string, any>; signingInput: string; signature: Uint8Array } | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const text = (part: string) => new TextDecoder().decode(base64ToBytes(part));
    return {
      header: JSON.parse(text(parts[0])),
      claims: JSON.parse(text(parts[1])),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: base64ToBytes(parts[2]),
    };
  } catch {
    return null;
  }
}

/** Claim checks for a Pub/Sub push token; the signature is verified separately. */
export function pubsubClaimsProblem(
  claims: Record<string, any>,
  expected: { audience: string; email: string | null },
  nowSeconds: number,
): string | null {
  if (!GOOGLE_OIDC_ISSUERS.has(String(claims?.iss ?? ""))) return "issuer";
  const audiences = Array.isArray(claims?.aud) ? claims.aud : [claims?.aud];
  if (!audiences.includes(expected.audience)) return "audience";
  const exp = Number(claims?.exp);
  if (!Number.isFinite(exp) || exp + 60 < nowSeconds) return "expired";
  const iat = Number(claims?.iat);
  if (Number.isFinite(iat) && iat - 300 > nowSeconds) return "issued_in_future";
  if (expected.email) {
    if (String(claims?.email ?? "").toLowerCase() !== expected.email.toLowerCase()) return "email";
    if (claims?.email_verified !== true && claims?.email_verified !== "true") return "email_unverified";
  }
  return null;
}

// ---- Purchase-token encryption at rest ----------------------------------------
//
// A purchase token is needed again to re-query Google during reconciliation,
// so it is kept — encrypted with AES-256-GCM under PLAY_TOKEN_ENCRYPTION_KEY
// (32 random bytes, base64). Lookups and deduplication use the SHA-256
// fingerprint; the ciphertext is never indexed or logged.

export function tokenEncryptionKeyBytes(env: EnvGetter): Uint8Array | null {
  const raw = (env("PLAY_TOKEN_ENCRYPTION_KEY") ?? "").trim();
  if (!raw) return null;
  try {
    const bytes = base64ToBytes(raw);
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

async function tokenKey(keyBytes: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", new Uint8Array(keyBytes), { name: "AES-GCM" }, false, [usage]);
}

export async function encryptPurchaseToken(keyBytes: Uint8Array, token: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode("qguard-play-token:v1") },
    await tokenKey(keyBytes, "encrypt"),
    new TextEncoder().encode(token),
  ));
  return `v1.${base64Url(iv)}.${base64Url(sealed)}`;
}

export async function decryptPurchaseToken(keyBytes: Uint8Array, sealed: string): Promise<string> {
  const [version, iv, body] = sealed.split(".");
  if (version !== "v1" || !iv || !body) throw new Error("unsupported purchase-token envelope");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(base64ToBytes(iv)), additionalData: new TextEncoder().encode("qguard-play-token:v1") },
    await tokenKey(keyBytes, "decrypt"),
    new Uint8Array(base64ToBytes(body)),
  );
  return new TextDecoder().decode(plain);
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Purchase tokens are opaque, URL-safe strings of a few hundred chars. */
export function isPlausiblePurchaseToken(value: unknown): value is string {
  return typeof value === "string" && value.length >= 20 && value.length <= 4096 && /^[A-Za-z0-9._\-]+$/.test(value);
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
