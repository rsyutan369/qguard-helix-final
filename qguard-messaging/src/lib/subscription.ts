// Subscription paywall model (Qguard_Wiki/Android_Paywall_Guidelines).
//
// The subscription belongs to the ACCOUNT: public.billing_subscriptions in
// Supabase is the single source of truth, written only by the verified payment
// backends (the billing Edge Function's PayPal webhook + confirm route; see
// src/lib/billing-api.ts)
// and mirrored here read-only. Client access checks are PRESENTATION — the
// database enforces the same rule server-side via qguard_has_messaging_access()
// (migration 030) on every message/conversation/call-signal insert.

export type PlanTier = "Starter" | "Basic" | "Pro" | "Elite";

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

// Statuses that grant access — MUST stay in sync with
// src/lib/subscription-access.ts (platform) and migration 030 (database).
export const ACCESS_STATUSES = new Set(["active", "trial", "pending_renewal"]);

// Renewal webhooks can lag the actual charge; the period end gets this much
// grace before the client locks. Status flips (cancelled/expired/past_due)
// arrive via realtime and lock IMMEDIATELY regardless of the period.
export const PERIOD_GRACE_MS = 72 * 60 * 60 * 1000;

/** True when this subscription row grants access to the messaging app now. */
export function hasMessagingAccess(sub: MessagingSubscription | null, nowMs: number = Date.now()): boolean {
  if (!sub) return false;
  if (!ACCESS_STATUSES.has(String(sub.status || "").toLowerCase())) return false;
  if (!sub.current_period_end) return true;
  const end = Date.parse(sub.current_period_end);
  if (Number.isNaN(end)) return true;
  return end + PERIOD_GRACE_MS > nowMs;
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
  const boundary = Date.parse(sub.current_period_end) + PERIOD_GRACE_MS;
  if (Number.isNaN(boundary)) return null;
  const delta = boundary - nowMs;
  return delta > 0 ? delta : null;
}

/** Human status label for the subscription card. */
export function subscriptionStatusLabel(sub: MessagingSubscription | null): string {
  if (!sub) return "No subscription";
  const status = String(sub.status || "").toLowerCase();
  if (status === "active" && sub.cancel_at_period_end) return "Active (ends at period end)";
  const labels: Record<string, string> = {
    active: "Active",
    trial: "Trial",
    pending_renewal: "Renewal in progress",
    past_due: "Payment failed",
    suspended: "Suspended",
    cancelled: "Cancelled",
    expired: "Expired",
    incomplete: "Awaiting payment",
  };
  return labels[status] ?? status;
}

// ---- Plan catalog (source of truth: src/api-server/paypal.ts PLAN_PRICING) ----

export interface PlanInfo {
  tier: PlanTier;
  monthly: number;
  yearlyPerMonth: number;
  tagline: string;
  highlights: string[];
}

export const PLAN_CATALOG: PlanInfo[] = [
  {
    tier: "Starter",
    monthly: 1,
    yearlyPerMonth: 1,
    tagline: "Unlock QGuard Messaging",
    highlights: ["Quantum-safe messaging", "Encrypted voice & video calls", "Quantum Vault file encryption", "All your devices, one account"],
  },
  {
    tier: "Basic",
    monthly: 8,
    yearlyPerMonth: 5,
    tagline: "Messaging + PQC readiness",
    highlights: ["Everything in Starter", "Quantum Readiness Engine", "Migration Planner & Sandbox", "Asset scanning"],
  },
  {
    tier: "Pro",
    monthly: 30,
    yearlyPerMonth: 20,
    tagline: "Full discovery & operations",
    highlights: ["Everything in Basic", "Discovery & Intelligence modules", "PQAuth identity migration", "Trust Center"],
  },
  {
    tier: "Elite",
    monthly: 199,
    yearlyPerMonth: 150,
    tagline: "The complete platform",
    highlights: ["Everything in Pro", "QKMS key management", "Governance & compliance", "Priority support"],
  },
];

/** Google Play product id convention (mirrors the backend's productIdFor). */
export function playProductIdFor(tier: PlanTier): string {
  return `qguard_${tier.toLowerCase()}`;
}

export function playBasePlanFor(cycle: "monthly" | "yearly"): string {
  return cycle;
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
