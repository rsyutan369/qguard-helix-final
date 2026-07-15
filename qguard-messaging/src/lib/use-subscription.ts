import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { supabase } from "@/lib/supabase";
import {
  hasMessagingAccess,
  msUntilAccessBoundary,
  type BillingInvoice,
  type MessagingSubscription,
} from "@/lib/subscription";

export interface SubscriptionState {
  /** The account's subscription row (billing_subscriptions), if any. */
  subscription: MessagingSubscription | null;
  /** Payment/billing history (billing_invoices, newest first). */
  invoices: BillingInvoice[];
  /** Authoritative-for-UI access verdict (server enforces independently). */
  access: boolean;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

/**
 * Account subscription state with REAL-TIME cross-device sync.
 *
 * The subscription belongs to the account, not the device: a purchase
 * completed on Android (Google Play) or in the browser (PayPal) is written to
 * billing_subscriptions by the verified backend, and the realtime stream below
 * unlocks/locks every logged-in session instantly — no manual refresh, no
 * re-purchase prompt on other platforms. A local timer also re-evaluates at
 * the period-end grace boundary so an expiry locks the app even if realtime
 * is briefly disconnected.
 */
export function useSubscription(userId: string | null): SubscriptionState {
  const [subscription, setSubscription] = useState<MessagingSubscription | null>(null);
  const [invoices, setInvoices] = useState<BillingInvoice[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Bumped by the boundary timer to force a re-evaluation of `access` when the
  // current period (plus grace) lapses without any realtime event.
  const [evalTick, setEvalTick] = useState(0);
  const timerRef = useRef<number | undefined>(undefined);

  const load = useCallback(async () => {
    if (!userId) {
      setSubscription(null);
      setInvoices([]);
      setLoading(false);
      return;
    }
    try {
      setError(null);
      const [subResult, invoicesResult] = await Promise.all([
        supabase
          .from("billing_subscriptions")
          .select(
            "id,user_id,subscription_id,provider,provider_subscription_id,plan,status,billing_cycle,auto_renew,cancel_at_period_end,renewal_date,current_period_start,current_period_end,cancelled_at,created_at,updated_at",
          )
          .eq("user_id", userId)
          .order("updated_at", { ascending: false })
          .limit(1)
          .maybeSingle(),
        supabase
          .from("billing_invoices")
          .select(
            "id,invoice_id,transaction_id,payment_date,amount_paid_cents,currency,payment_method_summary,subscription_plan,status,created_at",
          )
          .eq("user_id", userId)
          .order("created_at", { ascending: false })
          .limit(24),
      ]);
      if (subResult.error) throw new Error(subResult.error.message);
      setSubscription((subResult.data as MessagingSubscription | null) ?? null);
      // Invoices are decorative history — a missing table must not break the paywall.
      setInvoices(invoicesResult.error ? [] : ((invoicesResult.data as BillingInvoice[]) ?? []));
    } catch (e) {
      // Fail CLOSED for access (no fabricated entitlement), but surface why.
      setError(e instanceof Error ? e.message : "Could not load subscription");
    } finally {
      setLoading(false);
    }
  }, [userId]);

  useEffect(() => {
    setLoading(true);
    void load();
  }, [load]);

  // Real-time: subscription + invoice changes for THIS account re-load state.
  // billing_subscriptions/billing_invoices are in the supabase_realtime
  // publication (billing schema + migration 030 assert it).
  useEffect(() => {
    if (!userId) return undefined;
    const channel = supabase
      .channel(`billing-${userId}`)
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "billing_subscriptions", filter: `user_id=eq.${userId}` },
        () => void load(),
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "billing_invoices", filter: `user_id=eq.${userId}` },
        () => void load(),
      )
      .subscribe();
    return () => {
      void supabase.removeChannel(channel);
    };
  }, [userId, load]);

  // Boundary timer: when the current period (+grace) lapses, re-evaluate and
  // re-fetch — the paywall must engage immediately, not on next app start.
  useEffect(() => {
    if (timerRef.current !== undefined) {
      window.clearTimeout(timerRef.current);
      timerRef.current = undefined;
    }
    const delay = msUntilAccessBoundary(subscription);
    if (delay === null) return undefined;
    // Clamp: setTimeout overflows past ~24.8 days; re-arm at most daily.
    const clamped = Math.min(delay + 1_000, 24 * 60 * 60 * 1000);
    timerRef.current = window.setTimeout(() => {
      timerRef.current = undefined;
      setEvalTick((tick) => tick + 1);
      void load();
    }, clamped);
    return () => {
      if (timerRef.current !== undefined) {
        window.clearTimeout(timerRef.current);
        timerRef.current = undefined;
      }
    };
  }, [subscription, load]);

  const access = useMemo(
    () => hasMessagingAccess(subscription),
    // evalTick forces re-evaluation when the boundary timer fires.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [subscription, evalTick],
  );

  return { subscription, invoices, access, loading, error, refresh: load };
}
