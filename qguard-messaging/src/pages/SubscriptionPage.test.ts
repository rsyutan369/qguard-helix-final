import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { MessagingSubscription } from "@/lib/subscription";
import type { SubscriptionState } from "@/lib/use-subscription";

vi.mock("@/lib/supabase", () => ({ supabase: {} }));

import SubscriptionPage from "./SubscriptionPage";

function state(overrides: Partial<SubscriptionState>): SubscriptionState {
  return { subscription: null, invoices: [], entitlements: [], access: false, loading: false, error: null, refresh: async () => undefined, ...overrides };
}

function playRow(overrides: Partial<MessagingSubscription>): MessagingSubscription {
  const future = new Date(Date.now() + 20 * 86_400_000).toISOString();
  return {
    id: "row", user_id: "u", subscription_id: "gp_abc", provider: "google_play", provider_subscription_id: "h",
    plan: "Pro", status: "active", billing_cycle: "monthly", auto_renew: false, cancel_at_period_end: true,
    renewal_date: null, current_period_start: new Date().toISOString(), current_period_end: future, cancelled_at: new Date().toISOString(),
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(), product_id: "qh_pro_monthly",
    ...overrides,
  };
}

const render = (s: SubscriptionState, mode: "paywall" | "manage") =>
  renderToStaticMarkup(createElement(SubscriptionPage, { userId: "u", email: null, accessToken: "t", state: s, mode }));

describe("SubscriptionPage", () => {
  it("paywall: four paid plans at the confirmed prices, no trial or money-back promise", () => {
    const html = render(state({}), "paywall");
    for (const tier of ["Starter", "Basic", "Pro", "Elite"]) expect(html).toContain(tier);
    for (const price of ["$1", "$8", "$30", "$199"]) expect(html).toContain(`>${price}<`);
    expect(html).toContain("billed once per year at the displayed yearly price");
    expect(html).toContain("there is no free trial");
    expect(html).not.toMatch(/money-back|free trial available|save \d+%|-20%/i);
    expect(html).toContain("No active subscription");
  });

  it("a cancelled Google Play plan states the verified end date and offers Play management", () => {
    const sub = playRow({});
    const html = render(state({ subscription: sub, access: true, entitlements: ["quantum_messaging"] }), "manage");
    expect(html).toContain("Your subscription is canceled and will remain active until");
    expect(html).toContain("Billed through Google Play");
    expect(html).toContain("Manage in Google Play");
    expect(html).toContain("Auto-renew:");
    expect(html).not.toContain("Next renewal:");
  });

  it("an expired plan keeps the account and says local data is kept", () => {
    const html = render(state({ subscription: playRow({ status: "expired", cancel_at_period_end: false }), access: false }), "paywall");
    expect(html).toContain("Expired");
    expect(html).toContain("on-device vault files are kept");
  });
});
