import { useCallback, useEffect, useRef, useState } from "react";
import {
  BadgeCheck,
  CalendarClock,
  CreditCard,
  ExternalLink,
  Loader2,
  RefreshCcw,
  ShieldCheck,
  Smartphone,
  XCircle,
} from "lucide-react";
import { safeInvoke } from "@/lib/tauri";
import {
  billingApiOrigin,
  formatMoney,
  PLAN_CATALOG,
  playBasePlanFor,
  playManageUrl,
  playProductIdFor,
  subscriptionStatusLabel,
  type PlanTier,
} from "@/lib/subscription";
import type { SubscriptionState } from "@/lib/use-subscription";

type Cycle = "monthly" | "yearly";

interface PlayPurchase {
  purchaseToken: string;
  orderId: string;
  products: string[];
  state: "purchased" | "pending" | "unspecified";
  acknowledged: boolean;
}

interface PlayState {
  available: boolean;
  platform?: string;
  connectionState?: string;
  lastEvent?: string;
  purchases?: PlayPurchase[];
}

async function apiPost(path: string, accessToken: string, body: unknown): Promise<any> {
  const response = await fetch(`${billingApiOrigin()}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify(body),
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(json?.error?.message || `Request failed (HTTP ${response.status})`);
  }
  return json?.data;
}

const statusTone: Record<string, string> = {
  active: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  trial: "bg-cyan-50 text-cyan-700 ring-cyan-200",
  pending_renewal: "bg-amber-50 text-amber-700 ring-amber-200",
  past_due: "bg-rose-50 text-rose-700 ring-rose-200",
  suspended: "bg-rose-50 text-rose-700 ring-rose-200",
  cancelled: "bg-ink-100 text-ink-600 ring-ink-200",
  expired: "bg-rose-50 text-rose-700 ring-rose-200",
  incomplete: "bg-amber-50 text-amber-700 ring-amber-200",
};

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/**
 * Subscription center: status, plans, purchase (PayPal on desktop, Google Play
 * on Android with PayPal fallback), restore purchases, cancel/reactivate, and
 * billing history. Activation is ALWAYS server-verified — this page only
 * starts checkouts and then waits for billing_subscriptions to change (the
 * realtime stream in use-subscription flips access automatically).
 */
export default function SubscriptionPage(props: {
  userId: string;
  email: string | null;
  accessToken: string | null;
  state: SubscriptionState;
  /** "paywall" = locked app context; "manage" = normal in-app page. */
  mode: "paywall" | "manage";
}) {
  const { subscription, invoices, access, loading, error, refresh } = props.state;
  const [cycle, setCycle] = useState<Cycle>("monthly");
  const [busyPlan, setBusyPlan] = useState<PlanTier | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [platform, setPlatform] = useState<"android" | "desktop">("desktop");
  const pollRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    void safeInvoke<string>("billing_platform", undefined, "desktop").then((value) =>
      setPlatform(value === "android" ? "android" : "desktop"),
    );
    return () => {
      if (pollRef.current !== undefined) window.clearInterval(pollRef.current);
    };
  }, []);

  const currentPlan = (subscription?.plan as PlanTier | undefined) ?? null;
  const provider = subscription?.provider ?? null;

  const say = (message: string) => {
    setNotice(message);
    setProblem(null);
  };
  const fail = (message: string) => {
    setProblem(message);
    setNotice(null);
  };

  /** Submit a Play purchase token for server-side verification + activation. */
  const verifyPlayToken = useCallback(
    async (purchaseToken: string): Promise<boolean> => {
      if (!props.accessToken) return false;
      try {
        const data = await apiPost("/api/v1/play-billing/verify", props.accessToken, { purchaseToken });
        if (data?.entitled) {
          say(`Your ${data.plan} plan is active. Welcome to QGuard.`);
          await refresh();
          return true;
        }
        return false;
      } catch (e) {
        fail(e instanceof Error ? e.message : "Purchase verification failed");
        return false;
      }
    },
    [props.accessToken, refresh],
  );

  /** Google Play purchase: launch, poll for the token, verify server-side. */
  const purchaseWithPlay = useCallback(
    async (tier: PlanTier) => {
      const productId = playProductIdFor(tier);
      // In-place plan change: reuse the device's own raw token so an upgrade
      // can never create a second subscription (duplicate-purchase guard).
      let oldToken: string | null = null;
      if (provider === "google_play") {
        const state = await safeInvoke<PlayState>("billing_state", undefined, { available: false });
        oldToken =
          state.purchases?.find((purchase) => purchase.state === "purchased")?.purchaseToken ?? null;
      }
      await safeInvoke(
        "billing_launch_purchase",
        { productId, basePlanId: playBasePlanFor(cycle), accountId: props.userId, oldPurchaseToken: oldToken },
        null,
      );
      say("Complete the purchase in Google Play — this page unlocks automatically.");

      // Poll the billing state for the resulting token (~3 minutes max).
      if (pollRef.current !== undefined) window.clearInterval(pollRef.current);
      let ticks = 0;
      pollRef.current = window.setInterval(async () => {
        ticks += 1;
        if (ticks > 90) {
          if (pollRef.current !== undefined) window.clearInterval(pollRef.current);
          pollRef.current = undefined;
          setBusyPlan(null);
          return;
        }
        const state = await safeInvoke<PlayState>("billing_state", undefined, { available: false });
        const match = state.purchases?.find(
          (purchase) => purchase.state === "purchased" && purchase.products.includes(productId),
        );
        if (match) {
          if (pollRef.current !== undefined) window.clearInterval(pollRef.current);
          pollRef.current = undefined;
          const ok = await verifyPlayToken(match.purchaseToken);
          if (!ok) fail("Google Play reported the purchase but verification failed — try Restore purchases.");
          setBusyPlan(null);
        }
        if (state.lastEvent === "purchase_cancelled") {
          if (pollRef.current !== undefined) window.clearInterval(pollRef.current);
          pollRef.current = undefined;
          setNotice(null);
          setBusyPlan(null);
        }
      }, 2_000);
    },
    [cycle, props.userId, provider, verifyPlayToken],
  );

  /** PayPal purchase: server builds the checkout, system browser approves it. */
  const purchaseWithPaypal = useCallback(
    async (tier: PlanTier) => {
      if (!props.accessToken) throw new Error("Session expired — sign in again.");
      const data = await apiPost("/api/v1/paypal/subscribe", props.accessToken, { plan: tier, cycle });
      if (!data?.approvalUrl) throw new Error("PayPal did not return a checkout link");
      await safeInvoke("billing_open_checkout", { url: String(data.approvalUrl) }, null);
      say("Approve the subscription in the browser window — this app unlocks automatically after payment.");
    },
    [cycle, props.accessToken],
  );

  const subscribe = useCallback(
    async (tier: PlanTier) => {
      setBusyPlan(tier);
      setProblem(null);
      try {
        if (platform === "android") {
          const state = await safeInvoke<PlayState>("billing_state", undefined, { available: false });
          if (state.available) {
            await purchaseWithPlay(tier);
            return; // busyPlan cleared by the poll
          }
        }
        await purchaseWithPaypal(tier);
      } catch (e) {
        fail(e instanceof Error ? e.message : "Could not start the checkout");
      } finally {
        if (platform !== "android") setBusyPlan(null);
      }
    },
    [platform, purchaseWithPaypal, purchaseWithPlay],
  );

  /** Restore purchases (reinstall / new device / lost state). */
  const restore = useCallback(async () => {
    setBusyAction("restore");
    setProblem(null);
    try {
      if (platform === "android") {
        await safeInvoke("billing_refresh_purchases", undefined, null);
        await new Promise((resolve) => window.setTimeout(resolve, 2_500));
        const state = await safeInvoke<PlayState>("billing_state", undefined, { available: false });
        const purchased = state.purchases?.filter((purchase) => purchase.state === "purchased") ?? [];
        let restored = false;
        for (const purchase of purchased) {
          if (await verifyPlayToken(purchase.purchaseToken)) restored = true;
        }
        if (restored) say("Purchases restored — your subscription is active.");
        else if (purchased.length === 0) {
          await refresh();
          say(access ? "Subscription restored from your account." : "No Google Play purchases found for this account.");
        }
      } else {
        // Desktop: the subscription lives on the account — re-sync from the backend.
        await refresh();
        say(access ? "Subscription restored from your account." : "No active subscription found on this account.");
      }
    } catch (e) {
      fail(e instanceof Error ? e.message : "Restore failed");
    } finally {
      setBusyAction(null);
    }
  }, [access, platform, refresh, verifyPlayToken]);

  const cancelSubscription = useCallback(async () => {
    if (!subscription) return;
    setBusyAction("cancel");
    setProblem(null);
    try {
      if (provider === "google_play") {
        // Google Play owns the billing relationship — cancellation happens there;
        // the RTDN webhook syncs our record automatically.
        const productId = playProductIdFor((subscription.plan as PlanTier) ?? "Starter");
        await safeInvoke("billing_open_checkout", { url: playManageUrl(productId) }, null);
        say("Manage or cancel the subscription in Google Play — changes sync automatically.");
      } else {
        if (!props.accessToken) throw new Error("Session expired — sign in again.");
        await apiPost("/api/v1/billing/subscription/actions", props.accessToken, { action: "cancel" });
        await refresh();
        say("Subscription cancelled. You keep access until the end of the paid period.");
      }
    } catch (e) {
      fail(e instanceof Error ? e.message : "Cancellation failed");
    } finally {
      setBusyAction(null);
    }
  }, [props.accessToken, provider, refresh, subscription]);

  const reactivate = useCallback(async () => {
    setBusyAction("reactivate");
    setProblem(null);
    try {
      if (!props.accessToken) throw new Error("Session expired — sign in again.");
      const data = await apiPost("/api/v1/billing/subscription/actions", props.accessToken, { action: "reactivate" });
      if (data?.redirectUrl) {
        await safeInvoke("billing_open_checkout", { url: String(data.redirectUrl) }, null);
        say("Approve the renewal in the browser — this app updates automatically.");
      } else {
        await refresh();
        say("Subscription reactivated.");
      }
    } catch (e) {
      fail(e instanceof Error ? e.message : "Reactivation failed");
    } finally {
      setBusyAction(null);
    }
  }, [props.accessToken, refresh]);

  const status = String(subscription?.status ?? "").toLowerCase();
  const tone = statusTone[status] ?? "bg-ink-100 text-ink-600 ring-ink-200";
  const cancellable = subscription && ["active", "trial", "pending_renewal", "past_due"].includes(status) && !subscription.cancel_at_period_end;
  const reactivatable = subscription && (status === "cancelled" || subscription.cancel_at_period_end) && provider !== "google_play";

  return (
    <div className="mx-auto grid w-full max-w-4xl gap-5">
      {props.mode === "paywall" && (
        <div className="shell-card border-violet-200 bg-gradient-to-br from-violet-50 to-white p-6 text-center">
          <ShieldCheck className="mx-auto text-violet-500" size={32} />
          <h1 className="mt-2 text-xl font-bold text-ink-950">Activate QGuard Messaging</h1>
          <p className="mx-auto mt-2 max-w-lg text-sm text-ink-600">
            {access
              ? "Your subscription is active — opening your secure workspace…"
              : subscription
                ? "Your subscription no longer grants access. Renew below to unlock quantum-safe messaging, calls, and the vault on every device."
                : "A Starter plan unlocks quantum-safe messaging, encrypted voice & video calls, and the Quantum Vault — on Android and Desktop with this one account."}
          </p>
        </div>
      )}

      {(notice || problem || error) && (
        <div
          className={`shell-card p-4 text-sm font-semibold ${problem || error ? "border-rose-100 bg-rose-50 text-rose-700" : "border-emerald-100 bg-emerald-50 text-emerald-700"}`}
        >
          {problem || error || notice}
        </div>
      )}

      {/* Current subscription status card */}
      <div className="shell-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-violet-100 text-violet-600">
              <BadgeCheck size={20} />
            </div>
            <div>
              <div className="text-sm font-bold text-ink-950">
                {subscription ? `${subscription.plan} plan` : "No active subscription"}
              </div>
              <div className="text-xs text-ink-500">
                {provider === "google_play" ? "Billed through Google Play" : provider === "paypal" ? "Billed through PayPal" : provider ? `Provider: ${provider}` : "Choose a plan below to get started"}
              </div>
            </div>
          </div>
          <span className={`rounded-full px-3 py-1 text-xs font-bold ring-1 ${tone}`}>
            {loading ? "Checking…" : subscriptionStatusLabel(subscription)}
          </span>
        </div>
        {subscription && (
          <div className="mt-4 grid gap-3 text-xs text-ink-600 sm:grid-cols-3">
            <div className="flex items-center gap-2">
              <CalendarClock size={14} className="text-ink-400" />
              <span>
                {subscription.cancel_at_period_end || status === "cancelled" ? "Access until" : "Renews"}:{" "}
                <strong className="text-ink-800">{formatDate(subscription.current_period_end ?? subscription.renewal_date)}</strong>
              </span>
            </div>
            <div className="flex items-center gap-2">
              <CreditCard size={14} className="text-ink-400" />
              <span>
                Billing: <strong className="text-ink-800">{subscription.billing_cycle === "annual" ? "Yearly" : "Monthly"}</strong>
              </span>
            </div>
            <div className="truncate">
              Ref: <span className="font-mono text-[11px] text-ink-500">{subscription.subscription_id.slice(0, 24)}</span>
            </div>
          </div>
        )}
        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void restore()}
            disabled={busyAction !== null}
            className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas disabled:opacity-50"
          >
            {busyAction === "restore" ? <Loader2 size={13} className="animate-spin" /> : <RefreshCcw size={13} />}
            Restore purchases
          </button>
          {cancellable && (
            <button
              type="button"
              onClick={() => void cancelSubscription()}
              disabled={busyAction !== null}
              className="flex items-center gap-1.5 rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-xs font-bold text-rose-600 hover:bg-rose-50 disabled:opacity-50"
            >
              {busyAction === "cancel" ? <Loader2 size={13} className="animate-spin" /> : <XCircle size={13} />}
              {provider === "google_play" ? "Manage in Google Play" : "Cancel subscription"}
            </button>
          )}
          {reactivatable && (
            <button
              type="button"
              onClick={() => void reactivate()}
              disabled={busyAction !== null}
              className="flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-violet-700 disabled:opacity-50"
            >
              {busyAction === "reactivate" ? <Loader2 size={13} className="animate-spin" /> : <BadgeCheck size={13} />}
              Reactivate
            </button>
          )}
        </div>
      </div>

      {/* Plans */}
      <div className="shell-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Plans</h2>
            <p className="text-xs text-ink-500">
              {platform === "android" ? (
                <span className="inline-flex items-center gap-1">
                  <Smartphone size={12} /> Pay with Google Play, or PayPal in the browser
                </span>
              ) : (
                "Pay securely with PayPal — the checkout opens in your browser"
              )}
            </p>
          </div>
          <div className="flex items-center rounded-full bg-canvas p-0.5 ring-1 ring-line">
            {(["monthly", "yearly"] as Cycle[]).map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => setCycle(option)}
                className={`rounded-full px-3 py-1 text-xs font-bold transition ${cycle === option ? "bg-violet-600 text-white" : "text-ink-500 hover:text-ink-800"}`}
              >
                {option === "monthly" ? "Monthly" : "Yearly"}
              </button>
            ))}
          </div>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {PLAN_CATALOG.map((plan) => {
            const price = cycle === "yearly" ? plan.yearlyPerMonth : plan.monthly;
            const isCurrent = access && currentPlan === plan.tier;
            const busy = busyPlan === plan.tier;
            return (
              <div
                key={plan.tier}
                className={`flex flex-col rounded-xl border p-4 ${isCurrent ? "border-violet-300 bg-violet-50/50 ring-1 ring-violet-200" : plan.tier === "Starter" && !access ? "border-violet-200 shadow-tight" : "border-line bg-white"}`}
              >
                <div className="flex items-center justify-between">
                  <div className="text-sm font-bold text-ink-950">{plan.tier}</div>
                  {isCurrent && <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[10px] font-bold text-violet-700">Current</span>}
                  {plan.tier === "Starter" && !access && !isCurrent && (
                    <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-bold text-emerald-700">Unlocks messaging</span>
                  )}
                </div>
                <div className="mt-2">
                  <span className="text-2xl font-bold text-ink-950">${price}</span>
                  <span className="text-xs text-ink-500">/mo{cycle === "yearly" ? ", billed yearly" : ""}</span>
                </div>
                <div className="mt-1 text-[11px] font-semibold text-ink-500">{plan.tagline}</div>
                <ul className="mt-3 flex-1 space-y-1.5">
                  {plan.highlights.map((highlight) => (
                    <li key={highlight} className="flex items-start gap-1.5 text-[11px] text-ink-600">
                      <BadgeCheck size={12} className="mt-0.5 shrink-0 text-emerald-500" />
                      {highlight}
                    </li>
                  ))}
                </ul>
                <button
                  type="button"
                  disabled={isCurrent || busyPlan !== null}
                  onClick={() => void subscribe(plan.tier)}
                  className={`mt-4 flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-xs font-bold transition disabled:opacity-60 ${isCurrent ? "bg-ink-100 text-ink-400" : "bg-violet-600 text-white hover:bg-violet-700"}`}
                >
                  {busy && <Loader2 size={13} className="animate-spin" />}
                  {isCurrent ? "Active" : access ? (currentPlan && PLAN_CATALOG.findIndex((entry) => entry.tier === currentPlan) > PLAN_CATALOG.findIndex((entry) => entry.tier === plan.tier) ? "Switch" : "Upgrade") : "Subscribe"}
                  {!busy && !isCurrent && <ExternalLink size={12} />}
                </button>
              </div>
            );
          })}
        </div>
        <p className="mt-3 text-[11px] leading-relaxed text-ink-400">
          Payments are verified server-side before activation; your account unlocks on every device automatically.
          Prices in USD. Yearly billing charges the discounted rate once per year.
        </p>
      </div>

      {/* Billing history */}
      <div className="shell-card p-5">
        <h2 className="text-sm font-bold text-ink-950">Payment history</h2>
        {invoices.length === 0 ? (
          <p className="mt-2 text-xs text-ink-500">
            No payments yet. Your invoices and receipts appear here after your first charge.
          </p>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[480px] text-left text-xs">
              <thead>
                <tr className="border-b border-line text-[11px] uppercase tracking-wide text-ink-400">
                  <th className="pb-2 pr-3 font-semibold">Date</th>
                  <th className="pb-2 pr-3 font-semibold">Plan</th>
                  <th className="pb-2 pr-3 font-semibold">Amount</th>
                  <th className="pb-2 pr-3 font-semibold">Method</th>
                  <th className="pb-2 font-semibold">Status</th>
                </tr>
              </thead>
              <tbody>
                {invoices.map((invoice) => (
                  <tr key={invoice.id} className="border-b border-line/60 text-ink-700">
                    <td className="py-2 pr-3">{formatDate(invoice.payment_date ?? invoice.created_at)}</td>
                    <td className="py-2 pr-3">{invoice.subscription_plan}</td>
                    <td className="py-2 pr-3 font-semibold">{formatMoney(invoice.amount_paid_cents, invoice.currency)}</td>
                    <td className="py-2 pr-3">{invoice.payment_method_summary ?? "—"}</td>
                    <td className="py-2">
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${invoice.status === "paid" ? "bg-emerald-50 text-emerald-700" : invoice.status === "refunded" ? "bg-amber-50 text-amber-700" : "bg-rose-50 text-rose-700"}`}
                      >
                        {invoice.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
