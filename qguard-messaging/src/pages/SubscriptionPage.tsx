import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import {
  billingSupportsPlayVerification,
  fetchCatalog,
  fetchSubscriptionSummary,
  postBilling,
  restorePlayPurchases,
  type ServerCatalog,
  type ServerSubscriptionSummary,
  verifyPlayPurchase,
} from "@/lib/billing-api";
import {
  launchPlayPurchase,
  NO_PLAY,
  playResultMessage,
  purchasesForAccount,
  queryPlayProducts,
  readPlayState,
  refreshPlayPurchases,
  resultAfter,
  type PlayProduct,
  type PlayState,
} from "@/lib/play-billing";
import { safeInvoke } from "@/lib/tauri";
import {
  allPlayProductIds,
  cancellationNotice,
  formatMoney,
  formatUsd,
  PLAN_CATALOG,
  playManageUrl,
  playProductIdFor,
  subscriptionStatusLabel,
  tierRank,
  type BillingPeriod,
  type PlanTier,
} from "@/lib/subscription";
import type { SubscriptionState } from "@/lib/use-subscription";

/** How long to keep asking PayPal whether a just-approved checkout is paid. */
const ACTIVATION_WATCH_MS = 15 * 60_000;
const ACTIVATION_POLL_MS = 8_000;
/** How long to wait for Google Play's purchase sheet to report back. */
const PLAY_WATCH_MS = 5 * 60_000;
const PLAY_POLL_MS = 1_500;

const statusTone: Record<string, string> = {
  active: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  pending_renewal: "bg-amber-50 text-amber-700 ring-amber-200",
  past_due: "bg-rose-50 text-rose-700 ring-rose-200",
  suspended: "bg-amber-50 text-amber-700 ring-amber-200",
  cancelled: "bg-ink-100 text-ink-600 ring-ink-200",
  expired: "bg-rose-50 text-rose-700 ring-rose-200",
  incomplete: "bg-amber-50 text-amber-700 ring-amber-200",
};

const PROVIDER_LABEL: Record<string, string> = {
  google_play: "Google Play",
  paypal: "PayPal",
  manual: "QGuard (complimentary)",
};

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));

/**
 * Subscription center: verified status, plans, purchase (Google Play on
 * Android, PayPal on desktop), restore purchases, cancel/manage, and billing
 * history. Activation is ALWAYS server-verified — this page only starts
 * checkouts and submits Google Play purchase tokens; the realtime stream in
 * use-subscription flips access when the backend has recorded the purchase.
 *
 * Inside the Play-distributed Android app, digital subscriptions are sold
 * ONLY through Google Play Billing (no web-payment fallback).
 */
export default function SubscriptionPage(props: {
  userId: string;
  email: string | null;
  accessToken: string | null;
  state: SubscriptionState;
  /** "paywall" = locked app context; "manage" = normal in-app page. */
  mode: "paywall" | "manage";
}) {
  const { subscription, invoices, entitlements, access, loading, error, refresh } = props.state;
  const [period, setPeriod] = useState<BillingPeriod>("monthly");
  const [busyPlan, setBusyPlan] = useState<PlanTier | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [platform, setPlatform] = useState<"android" | "desktop">("desktop");
  const [summary, setSummary] = useState<ServerSubscriptionSummary | null>(null);
  const [catalog, setCatalog] = useState<ServerCatalog | null>(null);
  const [playProducts, setPlayProducts] = useState<Record<string, PlayProduct>>({});
  const [playReady, setPlayReady] = useState<boolean | null>(null);
  const [restoreStatus, setRestoreStatus] = useState<string | null>(null);

  // Watchers outlive renders: read the latest session token through a ref.
  const accessTokenRef = useRef(props.accessToken);
  useEffect(() => {
    accessTokenRef.current = props.accessToken;
  }, [props.accessToken]);
  const activationRef = useRef<number | undefined>(undefined);
  const playWatchRef = useRef(0); // generation counter cancels stale Play watchers
  const stopActivationWatch = useCallback(() => {
    if (activationRef.current !== undefined) window.clearInterval(activationRef.current);
    activationRef.current = undefined;
  }, []);
  useEffect(() => () => {
    stopActivationWatch();
    playWatchRef.current += 1;
  }, [stopActivationWatch]);

  const say = (message: string | null) => {
    setNotice(message);
    setProblem(null);
  };
  const fail = (message: string) => {
    setProblem(message);
    setNotice(null);
  };

  const currentPlan = (subscription?.plan as PlanTier | undefined) ?? null;
  const provider = subscription?.provider ?? null;
  const status = String(subscription?.status ?? "").toLowerCase();

  // ---- Load: platform, server-verified summary, catalog, localized Play prices ----
  useEffect(() => {
    void safeInvoke<string>("billing_platform", undefined, "desktop").then((value) =>
      setPlatform(value === "android" ? "android" : "desktop"),
    );
  }, []);

  const loadSummary = useCallback(async () => {
    const token = accessTokenRef.current;
    if (!token) return null;
    try {
      const data = await fetchSubscriptionSummary(token);
      setSummary(data);
      return data;
    } catch {
      return null; // the realtime row still drives the page; the summary adds detail
    }
  }, []);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary, subscription?.updated_at, subscription?.status]);

  useEffect(() => {
    let cancelled = false;
    void fetchCatalog(platform === "android" ? "google_play" : "paypal")
      .then((data) => {
        if (!cancelled) setCatalog(data);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [platform]);

  const playOverrides = catalog?.playProducts as Parameters<typeof playProductIdFor>[2] | undefined;

  useEffect(() => {
    if (platform !== "android") return undefined;
    let cancelled = false;
    void (async () => {
      const [state, verifiable] = await Promise.all([readPlayState(), billingSupportsPlayVerification()]);
      if (cancelled) return;
      setPlayReady(state.available && verifiable);
      if (!state.available) return;
      await queryPlayProducts(allPlayProductIds(playOverrides));
      for (let attempt = 0; attempt < 10 && !cancelled; attempt += 1) {
        await sleep(600);
        const next = await readPlayState();
        if (next.products && next.products.length > 0) {
          setPlayProducts(Object.fromEntries(next.products.map((product) => [product.productId, product])));
          return;
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [platform, playOverrides]);

  // ---- Google Play purchase ----
  const verifyToken = useCallback(async (purchaseToken: string): Promise<boolean> => {
    const token = accessTokenRef.current;
    if (!token) throw new Error("Session expired — sign in again.");
    const data = await verifyPlayPurchase(token, purchaseToken);
    if (data.pending) {
      say("Your payment is pending in Google Play. Your plan starts automatically once Google confirms it.");
      return false;
    }
    if (data.entitled) {
      say(`Your ${data.plan} plan is active. Thank you!`);
      await refresh();
      await loadSummary();
      return true;
    }
    fail(`Google Play reports this purchase as ${data.status.replace("_", " ")} — it does not grant access.`);
    return false;
  }, [loadSummary, refresh]);

  const purchaseWithPlay = useCallback(async (tier: PlanTier) => {
    if (!playReady) {
      throw new Error("Purchases are temporarily unavailable in this app. You have not been charged — please try again later.");
    }
    const accountId = summary?.playAccountId ?? (await loadSummary())?.playAccountId;
    if (!accountId) throw new Error("Couldn't load your account's billing details. Check your connection and try again.");
    if (access && provider && provider !== "google_play" && provider !== "manual") {
      throw new Error(`Your current plan is billed by ${PROVIDER_LABEL[provider] ?? provider}. Change it where you bought it, or cancel it there first.`);
    }
    const productId = playProductIdFor(tier, period, playOverrides);
    // In-place plan change: replace the device's own Play subscription so an
    // upgrade can never create a second, parallel subscription.
    const before = await readPlayState();
    let oldPurchaseToken: string | null = null;
    if (provider === "google_play" && access) {
      oldPurchaseToken = purchasesForAccount(before, accountId).find((purchase) => purchase.state === "purchased")?.purchaseToken ?? null;
      if (!oldPurchaseToken) {
        throw new Error("Your Google Play subscription isn't on this device's Play account. Use Restore purchases on the device that bought it, or change the plan in Google Play.");
      }
    }
    const upgrade = !currentPlan || tierRank(tier) > tierRank(currentPlan) || (tier === currentPlan && period === "yearly");
    const startSeq = before.seq ?? 0;
    await launchPlayPurchase({ productId, accountId, oldPurchaseToken, replacement: upgrade ? "upgrade" : "downgrade" });
    say("Complete the purchase in Google Play — this page updates automatically.");

    const generation = ++playWatchRef.current;
    const deadline = Date.now() + PLAY_WATCH_MS;
    let seen = startSeq;
    while (Date.now() < deadline && generation === playWatchRef.current) {
      await sleep(PLAY_POLL_MS);
      const state: PlayState = await readPlayState().catch(() => NO_PLAY);
      const result = resultAfter(state, seen);
      if (!result) continue;
      seen = result.seq;
      if (result.action !== "purchase" || result.status === "flow_started") continue;
      if (result.status === "purchased") {
        const match = purchasesForAccount(state, accountId).find(
          (purchase) => purchase.state === "purchased" && purchase.products.includes(productId),
        );
        if (!match) continue;
        await verifyToken(match.purchaseToken);
        return;
      }
      const message = playResultMessage(result.status);
      if (result.status === "pending") say(message);
      else if (message) fail(message);
      else say(null); // cancelled by the buyer
      return;
    }
  }, [access, currentPlan, loadSummary, period, playOverrides, playReady, provider, summary?.playAccountId, verifyToken]);

  // ---- PayPal purchase (desktop / web) ----
  const watchActivation = useCallback((subscriptionId: string) => {
    stopActivationWatch();
    const startedAt = Date.now();
    let inFlight = false;
    activationRef.current = window.setInterval(async () => {
      const token = accessTokenRef.current;
      if (!token || Date.now() - startedAt > ACTIVATION_WATCH_MS) {
        stopActivationWatch();
        return;
      }
      if (inFlight) return;
      inFlight = true;
      try {
        const data = await postBilling<{ activated?: boolean; status?: string; plan?: string }>(
          "/api/v1/paypal/confirm",
          token,
          { subscriptionId },
        );
        if (data?.activated) {
          stopActivationWatch();
          say(`Payment confirmed — your ${data.plan ?? ""} plan is active.`);
          await refresh();
        } else if (data?.status && ["cancelled", "expired", "suspended"].includes(data.status)) {
          stopActivationWatch();
        }
      } catch {
        // Offline or PayPal busy: keep watching until the deadline.
      } finally {
        inFlight = false;
      }
    }, ACTIVATION_POLL_MS);
  }, [refresh, stopActivationWatch]);

  const openExternal = useCallback(async (url: string) => {
    try {
      await safeInvoke("billing_open_checkout", { url });
    } catch (e) {
      throw new Error(`Couldn't open the page: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, []);

  const purchaseWithPaypal = useCallback(async (tier: PlanTier) => {
    const token = accessTokenRef.current;
    if (!token) throw new Error("Session expired — sign in again.");
    const data = await postBilling<{ approvalUrl?: string | null; subscriptionId?: string; mode?: string }>(
      "/api/v1/paypal/subscribe",
      token,
      { plan: tier, cycle: period },
    );
    if (data?.mode === "revise" && !data.approvalUrl) {
      say("PayPal accepted the plan change — it will show here as soon as PayPal confirms it.");
      await refresh();
      return;
    }
    if (!data?.approvalUrl) throw new Error("PayPal did not return a checkout link");
    await openExternal(String(data.approvalUrl));
    say("Approve the subscription in the browser window — this app unlocks automatically after payment.");
    if (data.mode !== "revise" && data.subscriptionId) watchActivation(data.subscriptionId);
  }, [openExternal, period, refresh, watchActivation]);

  const subscribe = useCallback(async (tier: PlanTier) => {
    setBusyPlan(tier);
    setProblem(null);
    try {
      if (platform === "android") await purchaseWithPlay(tier);
      else {
        if (provider === "google_play" && access && !subscription?.cancel_at_period_end) {
          throw new Error("This subscription is billed by Google Play. Change or cancel it in Google Play on your Android device.");
        }
        await purchaseWithPaypal(tier);
      }
    } catch (e) {
      fail(e instanceof Error ? e.message : "Could not start the checkout");
    } finally {
      setBusyPlan(null);
    }
  }, [access, platform, provider, purchaseWithPaypal, purchaseWithPlay, subscription?.cancel_at_period_end]);

  // ---- Restore purchases (reinstall / new device) ----
  const restore = useCallback(async () => {
    setBusyAction("restore");
    setProblem(null);
    setRestoreStatus(null);
    try {
      if (platform === "android") {
        const token = accessTokenRef.current;
        if (!token) throw new Error("Session expired — sign in again.");
        const startSeq = (await readPlayState()).seq ?? 0;
        await refreshPlayPurchases();
        let state: PlayState = NO_PLAY;
        for (let attempt = 0; attempt < 12; attempt += 1) {
          await sleep(500);
          state = await readPlayState();
          const result = resultAfter(state, startSeq);
          if (result?.action === "refresh") {
            if (result.status !== "ok") throw new Error(playResultMessage(result.status) ?? "Google Play could not list your purchases.");
            break;
          }
        }
        const owned = (state.purchases ?? []).filter((purchase) => purchase.state === "purchased");
        if (owned.length === 0) {
          await refresh();
          setRestoreStatus(access ? "Your subscription is linked to this account." : "No Google Play subscriptions were found on this device's Play account.");
          return;
        }
        const outcome = await restorePlayPurchases(token, owned.map((purchase) => purchase.purchaseToken));
        await refresh();
        await loadSummary();
        const firstError = outcome.results.find((entry) => !entry.ok)?.error?.message;
        setRestoreStatus(
          outcome.restored > 0
            ? "Purchases restored — your subscription is active on this account."
            : firstError ?? "Google Play purchases were found, but none is an active QGuard subscription for this account.",
        );
      } else {
        await refresh();
        await loadSummary();
        setRestoreStatus(access ? "Your subscription is linked to this account." : "No active subscription found on this account.");
      }
    } catch (e) {
      fail(e instanceof Error ? e.message : "Restore failed");
    } finally {
      setBusyAction(null);
    }
  }, [access, loadSummary, platform, refresh]);

  // ---- Manage / cancel ----
  const manage = useCallback(async () => {
    if (!subscription) return;
    setBusyAction("cancel");
    setProblem(null);
    try {
      if (provider === "google_play") {
        // Google Play owns the billing relationship; RTDN syncs every change here.
        await openExternal(playManageUrl(subscription.product_id ?? null));
        say("Manage or cancel the subscription in Google Play — changes appear here automatically.");
      } else {
        const token = accessTokenRef.current;
        if (!token) throw new Error("Session expired — sign in again.");
        const data = await postBilling<{ accessUntil?: string | null }>("/api/v1/billing/subscription/actions", token, { action: "cancel" });
        await refresh();
        say(data?.accessUntil
          ? `Your subscription is canceled and will remain active until ${formatDate(data.accessUntil)}.`
          : "Subscription cancelled.");
      }
    } catch (e) {
      fail(e instanceof Error ? e.message : "Cancellation failed");
    } finally {
      setBusyAction(null);
    }
  }, [openExternal, provider, refresh, subscription]);

  const reactivate = useCallback(async () => {
    setBusyAction("reactivate");
    setProblem(null);
    try {
      const token = accessTokenRef.current;
      if (!token) throw new Error("Session expired — sign in again.");
      const data = await postBilling<{ redirectUrl?: string; subscriptionId?: string }>(
        "/api/v1/billing/subscription/actions",
        token,
        { action: "reactivate" },
      );
      if (data?.redirectUrl) {
        await openExternal(String(data.redirectUrl));
        say("Approve the renewal in the browser — this app updates automatically.");
        if (data.subscriptionId) watchActivation(data.subscriptionId);
      } else {
        await refresh();
        say("Subscription reactivated.");
      }
    } catch (e) {
      fail(e instanceof Error ? e.message : "Reactivation failed");
    } finally {
      setBusyAction(null);
    }
  }, [openExternal, refresh, watchActivation]);

  // ---- Derived view state ----
  const tone = statusTone[status] ?? "bg-ink-100 text-ink-600 ring-ink-200";
  const cancelNotice = cancellationNotice(subscription);
  const renewing = access && Boolean(subscription?.auto_renew) && !subscription?.cancel_at_period_end;
  const manageable = subscription && provider !== "manual" && ["active", "pending_renewal", "past_due", "suspended"].includes(status) && !(provider !== "google_play" && subscription.cancel_at_period_end);
  const reactivatable = platform === "desktop" && subscription && provider !== "google_play" && provider !== "manual" && (status === "cancelled" || status === "expired" || subscription.cancel_at_period_end);
  const androidBlocked = platform === "android" && playReady === false;
  const entitlementLabels = useMemo(() => {
    const labels = new Map((catalog?.tiers ?? []).flatMap((tier) => tier.entitlements.map((entry) => [entry.key, entry.label] as const)));
    return entitlements.map((key) => labels.get(key) ?? key.replace(/_/g, " "));
  }, [catalog, entitlements]);

  function priceFor(tier: PlanTier): { main: string; sub: string } {
    const plan = PLAN_CATALOG.find((entry) => entry.tier === tier)!;
    const listed = period === "yearly" ? plan.yearly : plan.monthly;
    if (platform === "android") {
      const product = playProducts[playProductIdFor(tier, period, playOverrides)];
      if (product?.formattedPrice) {
        return { main: product.formattedPrice, sub: period === "yearly" ? "per year · Google Play" : "per month · Google Play" };
      }
      return { main: formatUsd(listed), sub: period === "yearly" ? "per year (USD list price)" : "per month (USD list price)" };
    }
    return { main: formatUsd(listed), sub: period === "yearly" ? "per year, billed once a year" : "per month" };
  }

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
                ? "Your subscription no longer grants access. Your account, billing history and on-device vault files are kept — choose a plan to continue."
                : "Every plan unlocks quantum-safe messaging, encrypted calls, the on-device Quantum Vault and OffGrid Mesh/XFER on Android and desktop with this one account."}
          </p>
        </div>
      )}

      {(notice || problem || error) && (
        <div
          role={problem || error ? "alert" : "status"}
          className={`shell-card p-4 text-sm font-semibold ${problem || error ? "border-rose-100 bg-rose-50 text-rose-700" : "border-emerald-100 bg-emerald-50 text-emerald-700"}`}
        >
          {problem || error || notice}
        </div>
      )}

      {/* Verified subscription status */}
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
                {provider ? `Billed through ${PROVIDER_LABEL[provider] ?? provider}` : "Choose a plan below to get started"}
              </div>
            </div>
          </div>
          <span className={`rounded-full px-3 py-1 text-xs font-bold ring-1 ${tone}`}>
            {loading ? "Checking…" : subscriptionStatusLabel(subscription)}
          </span>
        </div>

        {cancelNotice && (
          <p className="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs font-semibold text-amber-800">{cancelNotice}</p>
        )}
        {status === "past_due" && provider === "google_play" && (
          <p className="mt-3 rounded-lg bg-rose-50 px-3 py-2 text-xs font-semibold text-rose-700">
            Google Play couldn't renew your subscription. Update your payment method in Google Play to restore access.
          </p>
        )}

        {subscription && (
          <dl className="mt-4 grid gap-3 text-xs text-ink-600 sm:grid-cols-3">
            <div className="flex items-center gap-2">
              <CreditCard size={14} className="text-ink-400" />
              <dt>Billing period:</dt>
              <dd><strong className="text-ink-800">{subscription.billing_cycle === "annual" ? "Yearly" : "Monthly"}</strong></dd>
            </div>
            <div className="flex items-center gap-2">
              <CalendarClock size={14} className="text-ink-400" />
              <dt>{renewing ? "Next renewal:" : "Access until:"}</dt>
              <dd><strong className="text-ink-800">{formatDate(renewing ? subscription.renewal_date ?? subscription.current_period_end : subscription.current_period_end)}</strong></dd>
            </div>
            <div className="flex items-center gap-2">
              <dt>Auto-renew:</dt>
              <dd><strong className="text-ink-800">{provider === "manual" ? "—" : renewing ? "On" : "Off"}</strong></dd>
            </div>
            <div className="flex items-center gap-2">
              <dt>Subscribed:</dt>
              <dd><strong className="text-ink-800">{formatDate(subscription.created_at)}</strong></dd>
            </div>
            <div className="flex items-center gap-2">
              <dt>Verified:</dt>
              <dd><strong className="text-ink-800">{subscription.last_verified_at ? formatDate(subscription.last_verified_at) : provider === "manual" ? "—" : "By provider events"}</strong></dd>
            </div>
            <div className="truncate">
              Ref: <span className="font-mono text-[11px] text-ink-500">{subscription.subscription_id.slice(0, 24)}</span>
            </div>
          </dl>
        )}

        {access && entitlementLabels.length > 0 && (
          <details className="mt-4 text-xs text-ink-600">
            <summary className="cursor-pointer font-bold text-ink-800">Included in your plan ({entitlementLabels.length})</summary>
            <ul className="mt-2 grid gap-1 sm:grid-cols-2">
              {entitlementLabels.map((label) => (
                <li key={label} className="flex items-start gap-1.5">
                  <BadgeCheck size={12} className="mt-0.5 shrink-0 text-emerald-500" />
                  {label}
                </li>
              ))}
            </ul>
          </details>
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
          {manageable && (
            <button
              type="button"
              onClick={() => void manage()}
              disabled={busyAction !== null}
              className="flex items-center gap-1.5 rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-xs font-bold text-rose-600 hover:bg-rose-50 disabled:opacity-50"
            >
              {busyAction === "cancel" ? <Loader2 size={13} className="animate-spin" /> : provider === "google_play" ? <ExternalLink size={13} /> : <XCircle size={13} />}
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
              Resubscribe
            </button>
          )}
        </div>
        {restoreStatus && <p className="mt-2 text-xs text-ink-500" role="status">{restoreStatus}</p>}
        {summary?.message && !cancelNotice && <p className="mt-2 text-xs text-ink-500">{summary.message}</p>}
      </div>

      {/* Plans */}
      <div className="shell-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Plans</h2>
            <p className="text-xs text-ink-500">
              {platform === "android" ? (
                <span className="inline-flex items-center gap-1">
                  <Smartphone size={12} /> Billed and renewed by Google Play
                </span>
              ) : (
                "Pay securely with PayPal — the checkout opens in your browser"
              )}
            </p>
          </div>
          <div className="flex items-center rounded-full bg-canvas p-0.5 ring-1 ring-line" role="group" aria-label="Billing period">
            {(["monthly", "yearly"] as BillingPeriod[]).map((option) => (
              <button
                key={option}
                type="button"
                aria-pressed={period === option}
                onClick={() => setPeriod(option)}
                className={`rounded-full px-3 py-1 text-xs font-bold transition ${period === option ? "bg-violet-600 text-white" : "text-ink-500 hover:text-ink-800"}`}
              >
                {option === "monthly" ? "Monthly" : "Yearly"}
              </button>
            ))}
          </div>
        </div>

        {androidBlocked && (
          <p className="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs font-semibold text-amber-800">
            Google Play purchases are temporarily unavailable in this app. You have not been charged — please try again later.
          </p>
        )}

        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {PLAN_CATALOG.map((plan) => {
            const isCurrent = access && currentPlan === plan.tier && (subscription?.billing_cycle === "annual") === (period === "yearly");
            const busy = busyPlan === plan.tier;
            const price = priceFor(plan.tier);
            const label = isCurrent
              ? "Current plan"
              : access && currentPlan
                ? tierRank(plan.tier) > tierRank(currentPlan) ? "Upgrade" : "Switch"
                : "Subscribe";
            return (
              <div
                key={plan.tier}
                className={`flex flex-col rounded-xl border p-4 ${isCurrent ? "border-violet-300 bg-violet-50/50 ring-1 ring-violet-200" : "border-line bg-white"}`}
              >
                <div className="flex items-center justify-between">
                  <div className="text-sm font-bold text-ink-950">{plan.tier}</div>
                  {isCurrent && <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[10px] font-bold text-violet-700">Current</span>}
                </div>
                <div className="mt-2">
                  <span className="text-2xl font-bold text-ink-950">{price.main}</span>
                  <div className="text-[11px] text-ink-500">{price.sub}</div>
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
                  disabled={isCurrent || busyPlan !== null || androidBlocked}
                  onClick={() => void subscribe(plan.tier)}
                  className={`mt-4 flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-xs font-bold transition disabled:opacity-60 ${isCurrent ? "bg-ink-100 text-ink-400" : "bg-violet-600 text-white hover:bg-violet-700"}`}
                >
                  {busy && <Loader2 size={13} className="animate-spin" />}
                  {label}
                </button>
              </div>
            );
          })}
        </div>
        <p className="mt-3 text-[11px] leading-relaxed text-ink-400">
          All plans are paid subscriptions that renew automatically until cancelled — there is no free trial. Each plan
          includes everything in the plans below it. Purchases are verified by QGuard's servers before access is granted,
          and your plan unlocks on every device where you sign in. Cancelling stops the next renewal; access continues
          until the end of the period you paid for.{" "}
          {platform === "android"
            ? "Refunds follow Google Play's refund policy."
            : "Yearly plans are billed once per year at the displayed yearly price. See the Refund Policy at qguardhelix.com/refund."}
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
