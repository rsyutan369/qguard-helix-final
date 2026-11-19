// Subscription paywall model (Qguard_Wiki/GooglePlay_Billing, Android_Paywall_Guidelines).
//
// The subscription belongs to the ACCOUNT: public.billing_subscriptions in
// Supabase is the single source of truth, written only by the verified payment
// backends (Google Play verification + RTDN, the PayPal webhook + confirm
// route; see src/lib/billing-api.ts), and public.user_entitlements is computed
// from it by the database in the same transaction. Both are mirrored here
// read-only. Client access checks are PRESENTATION — the database enforces the
// same rule server-side via qguard_has_messaging_access() on every
// message/conversation/call-signal insert.
//
// Commercial rules (owner decision 2026-11-12): four PAID tiers that form a
// ladder (each includes the ones below), no free tier, no free trial and no
// money-back guarantee. Cancelling keeps access to the verified
// end of the paid period.

export type PlanTier = "Starter" | "Basic" | "Pro" | "Elite";
export type BillingPeriod = "monthly" | "yearly";

export interface MessagingSubscription {
  id: string;
  user_id: string;
  subscription_id: string;
  provider: string | null;
  provider_subscription_id: string | null;
  plan: PlanTier | string;
  status: string;
  billing_cycle: "monthly" | "annual" | string;
  auto_renew: boolean;
  cancel_at_period_end: boolean;
  renewal_date: string | null;
  current_period_start: string | null;
  current_period_end: string | null;
  cancelled_at: string | null;
  created_at: string;
  updated_at: string;
  product_id?: string | null;
  acknowledgement_state?: string | null;
  verification_state?: string | null;
  last_verified_at?: string | null;
}

export interface BillingInvoice {
  id: string;
  invoice_id: string;
  transaction_id: string | null;
  payment_date: string | null;
  amount_paid_cents: number;
  currency: string;
  payment_method_summary: string | null;
  subscription_plan: string;
  status: string;
  created_at: string;
}

export interface EntitlementRow {
  entitlement_key: string;
  is_enabled: boolean;
  valid_until: string | null;
}

// Statuses that grant access — MUST stay in sync with
// supabase/functions/billing/logic.ts rowGrantsAccess, src/lib/subscription-access.ts
// (platform) and SQL qguard_subscription_access_until. No trial exists.
export const ACCESS_STATUSES = new Set(["active", "pending_renewal"]);

// Tolerance after the recorded period end before the client locks without a
// provider event. Google moves expiryTime itself during a payment grace
// period, so Play only needs to cover notification latency; PayPal renewal
// webhooks can lag the charge. Status flips (expired/past_due/...) arrive via
// realtime and lock IMMEDIATELY regardless of the period.
export const PLAY_GRACE_MS = 60 * 60 * 1000;
export const PERIOD_GRACE_MS = 72 * 60 * 60 * 1000;
/** Offline (Mesh/XFER without internet) the last verified row is honoured this long past its end. */
export const OFFLINE_GRACE_MS = 72 * 60 * 60 * 1000;

export function accessGraceMs(sub: Pick<MessagingSubscription, "provider"> | null): number {
  return sub?.provider === "google_play" ? PLAY_GRACE_MS : PERIOD_GRACE_MS;
}

/** True when this subscription row grants access to the messaging app now. */
export function hasMessagingAccess(sub: MessagingSubscription | null, nowMs: number = Date.now(), graceMs?: number): boolean {
  if (!sub) return false;
  if (!ACCESS_STATUSES.has(String(sub.status || "").toLowerCase())) return false;
  if (!sub.current_period_end) return true;
  const end = Date.parse(sub.current_period_end);
  if (Number.isNaN(end)) return true;
  return end + (graceMs ?? accessGraceMs(sub)) > nowMs;
}

/**
 * Milliseconds until the current access verdict can flip on its own (the
 * period-end grace boundary) — used to arm a re-check timer so an expiry
 * locks the app immediately even if no realtime event arrives. Null when
 * there is no future boundary to watch.
 */
export function msUntilAccessBoundary(sub: MessagingSubscription | null, nowMs: number = Date.now()): number | null {
  if (!sub || !sub.current_period_end) return null;
  if (!ACCESS_STATUSES.has(String(sub.status || "").toLowerCase())) return null;
  const boundary = Date.parse(sub.current_period_end) + accessGraceMs(sub);
  if (Number.isNaN(boundary)) return null;
  const delta = boundary - nowMs;
  return delta > 0 ? delta : null;
}

/** Human status label for the subscription card. */
export function subscriptionStatusLabel(sub: MessagingSubscription | null): string {
  if (!sub) return "No subscription";
  const status = String(sub.status || "").toLowerCase();
  if (status === "active" && sub.cancel_at_period_end) return "Cancelled — active until period end";
  const labels: Record<string, string> = {
    active: "Active",
    trial: "Not active",
    pending_renewal: "Payment issue — retrying",
    past_due: "On hold — payment failed",
    suspended: "Paused",
    cancelled: "Cancelled",
    expired: "Expired",
    incomplete: "Awaiting payment",
  };
  return labels[status] ?? status;
}

/**
 * "Your subscription is canceled and will remain active until [date]." —
 * only for a cancelled plan that still grants access, and only with the
 * verified period end (never a guessed date).
 */
export function cancellationNotice(sub: MessagingSubscription | null, nowMs: number = Date.now()): string | null {
  if (!sub || !sub.cancel_at_period_end || !sub.current_period_end) return null;
  if (!hasMessagingAccess(sub, nowMs)) return null;
  const date = new Date(sub.current_period_end);
  if (Number.isNaN(date.getTime())) return null;
  return `Your subscription is canceled and will remain active until ${date.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })}.`;
}

// ---- Plan catalog -----------------------------------------------------------
// USD list prices MUST equal src/lib/billing/plan-pricing.ts (platform) and
// subscription_products (database); the billing service's /catalog serves the
// authoritative copy. On Android the price shown is Google Play's localized
// ProductDetails price — the amount the buyer is actually charged.

export interface PlanInfo {
  tier: PlanTier;
  /** USD per month on the monthly plan. */
  monthly: number;
  /** Full USD charge for the yearly plan. */
  yearly: number;
  tagline: string;
  highlights: string[];
}

export const PLAN_CATALOG: PlanInfo[] = [
  {
    tier: "Starter",
    monthly: 1,
    yearly: 12,
    tagline: "Quantum-safe messaging & on-device vault",
    highlights: [
      "Quantum Messaging & end-to-end encrypted Secure Chat",
      "Encrypted voice & video calls, one-tap call verification",
      "Disappearing messages & multi-device trust",
      "On-device Quantum Vault & Hidden Vault (never uploaded)",
      "OffGrid Mesh and XFER",
    ],
  },
  {
    tier: "Basic",
    monthly: 8,
    yearly: 60,
    tagline: "Messaging + quantum readiness",
    highlights: [
      "Everything in Starter",
      "Quantum Readiness & Assessment Engine",
      "Risk Analysis & Migration Planner",
      "AI Migration & Executive Advisors",
      "Assessment reports",
    ],
  },
  {
    tier: "Pro",
    monthly: 30,
    yearly: 240,
    tagline: "Operational PQC readiness",
    highlights: [
      "Everything in Basic",
      "Crypto asset discovery & CBOM Explorer",
      "PQC-Auth, orchestration, live migration & rollback",
      "Runtime intelligence, supply chain & trust chain",
      "Crypto Agility Engine · email support",
    ],
  },
  {
    tier: "Elite",
    monthly: 199,
    yearly: 1800,
    tagline: "Enterprise crypto agility",
    highlights: [
      "Everything in Pro",
      "Enterprise cryptographic estate governance",
      "Full QKMS: overview, inventory, governance, readiness",
      "SOC 2, PCI DSS 4.0.1, NIST & custom control mapping",
      "Email support",
    ],
  },
];

export const TIER_ORDER: PlanTier[] = ["Starter", "Basic", "Pro", "Elite"];

export function tierRank(tier: string | null | undefined): number {
  const index = TIER_ORDER.findIndex((entry) => entry.toLowerCase() === String(tier ?? "").toLowerCase());
  return index + 1;
}

/**
 * Google Play product id (mirrors the backend's playProductIdFor). The
 * billing service's /catalog `playProducts` map wins when it is loaded, so a
 * product remapped in Play Console needs no app release.
 */
export function playProductIdFor(tier: PlanTier, period: BillingPeriod, overrides?: Partial<Record<PlanTier, Partial<Record<BillingPeriod, string>>>> | null): string {
  return overrides?.[tier]?.[period] || `qh_${tier.toLowerCase()}_${period}`;
}

export function allPlayProductIds(overrides?: Partial<Record<PlanTier, Partial<Record<BillingPeriod, string>>>> | null): string[] {
  return TIER_ORDER.flatMap((tier) => (["monthly", "yearly"] as BillingPeriod[]).map((period) => playProductIdFor(tier, period, overrides)));
}

/** Deep link to Google Play's own subscription management screen. */
export function playManageUrl(productId: string | null): string {
  const base = "https://play.google.com/store/account/subscriptions";
  return productId
    ? `${base}?sku=${encodeURIComponent(productId)}&package=com.qguard.messaging`
    : base;
}

export function formatMoney(cents: number, currency: string): string {
  return `${(cents / 100).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${currency}`;
}

export function formatUsd(amount: number): string {
  return `$${amount.toLocaleString("en-US")}`;
}
