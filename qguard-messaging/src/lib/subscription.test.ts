import { describe, expect, it } from "vitest";
import {
  hasMessagingAccess,
  msUntilAccessBoundary,
  PERIOD_GRACE_MS,
  subscriptionStatusLabel,
  type MessagingSubscription,
} from "./subscription";

const NOW = Date.parse("2026-07-15T12:00:00Z");

function sub(overrides: Partial<MessagingSubscription>): MessagingSubscription {
  return {
    id: "row-1",
    user_id: "user-1",
    subscription_id: "sub-1",
    provider: "paypal",
    provider_subscription_id: "I-XYZ",
    plan: "Starter",
    status: "active",
    billing_cycle: "monthly",
    auto_renew: true,
    cancel_at_period_end: false,
    renewal_date: null,
    current_period_start: "2026-07-01T00:00:00Z",
    current_period_end: "2026-08-01T00:00:00Z",
    cancelled_at: null,
    created_at: "2026-07-01T00:00:00Z",
    updated_at: "2026-07-01T00:00:00Z",
    ...overrides,
  };
}

describe("hasMessagingAccess", () => {
  it("grants access for active/trial/pending_renewal within the period", () => {
    expect(hasMessagingAccess(sub({ status: "active" }), NOW)).toBe(true);
    expect(hasMessagingAccess(sub({ status: "trial" }), NOW)).toBe(true);
    expect(hasMessagingAccess(sub({ status: "pending_renewal" }), NOW)).toBe(true);
  });

  it("denies without a subscription row (new-user paywall)", () => {
    expect(hasMessagingAccess(null, NOW)).toBe(false);
  });

  it("denies expired / cancelled / past_due / suspended immediately", () => {
    for (const status of ["expired", "cancelled", "past_due", "suspended", "incomplete"]) {
      expect(hasMessagingAccess(sub({ status }), NOW)).toBe(false);
    }
  });

  it("keeps access through the 72h grace after period end, then locks", () => {
    const ended = sub({ current_period_end: "2026-07-15T00:00:00Z" }); // 12h ago
    expect(hasMessagingAccess(ended, NOW)).toBe(true);
    const longEnded = sub({ current_period_end: "2026-07-10T00:00:00Z" }); // 5.5 days ago
    expect(hasMessagingAccess(longEnded, NOW)).toBe(false);
  });

  it("treats a missing period end as provider-managed (status decides)", () => {
    expect(hasMessagingAccess(sub({ current_period_end: null }), NOW)).toBe(true);
  });
});

describe("msUntilAccessBoundary", () => {
  it("returns the time until period end + grace for an active sub", () => {
    const boundary = msUntilAccessBoundary(sub({ current_period_end: "2026-07-16T12:00:00Z" }), NOW);
    expect(boundary).toBe(24 * 60 * 60 * 1000 + PERIOD_GRACE_MS);
  });

  it("returns null when there is nothing to watch", () => {
    expect(msUntilAccessBoundary(null, NOW)).toBeNull();
    expect(msUntilAccessBoundary(sub({ current_period_end: null }), NOW)).toBeNull();
    expect(msUntilAccessBoundary(sub({ status: "expired" }), NOW)).toBeNull();
    // Boundary already passed.
    expect(msUntilAccessBoundary(sub({ current_period_end: "2026-07-01T00:00:00Z" }), NOW)).toBeNull();
  });
});

describe("subscriptionStatusLabel", () => {
  it("labels the common states", () => {
    expect(subscriptionStatusLabel(null)).toBe("No subscription");
    expect(subscriptionStatusLabel(sub({ status: "active" }))).toBe("Active");
    expect(subscriptionStatusLabel(sub({ status: "active", cancel_at_period_end: true }))).toBe(
      "Active (ends at period end)",
    );
    expect(subscriptionStatusLabel(sub({ status: "past_due" }))).toBe("Payment failed");
  });
});
