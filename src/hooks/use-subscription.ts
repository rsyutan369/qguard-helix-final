import { useEffect, useRef, useState, useCallback } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import {
  normalizeTier,
  isAccessGrantingStatus,
  type AccessTier,
} from '@/lib/subscription-access';
import { DEMO_ACCOUNT_TIER, isDemoModeEnabled, isDemoUserId } from '@/lib/demo-account';

// Lightweight entitlement read for route/nav gating. Reads the caller's own
// billing_subscriptions row (RLS-scoped) with a profiles.tier fallback, and
// stays live via realtime. This is deliberately small — the heavy billing
// bundle (`useBillingSettings` -> /api/v1/billing) is only loaded where full
// subscription management UI is shown. Gating is ALSO enforced server-side (see
// src/api-server/subscription-guard.ts); this hook is the UX layer.

export interface SubscriptionState {
  tier: AccessTier;            // 'none' | 'starter' | 'basic' | 'pro' | 'elite'
  status: string | null;      // raw billing status
  isActive: boolean;          // status grants access
  billingCycle: 'monthly' | 'annual' | null;
  autoRenew: boolean;
  cancelAtPeriodEnd: boolean;
  renewalDate: string | null;
  provider: string | null;
  subscriptionId: string | null;
  loading: boolean;
}

// Monotonic suffix so every hook instance gets its own realtime channel topic.
let nextChannelSeq = 0;

const EMPTY: SubscriptionState = {
  tier: 'none',
  status: null,
  isActive: false,
  billingCycle: null,
  autoRenew: false,
  cancelAtPeriodEnd: false,
  renewalDate: null,
  provider: null,
  subscriptionId: null,
  loading: true,
};

export function useSubscription(): SubscriptionState & { refresh: () => Promise<void> } {
  const { user } = useAuth();
  /* Keyed on the user ID, never the user OBJECT.
     `DashboardLayout` renders its loading shell instead of `<Outlet/>` while
     this hook reports `loading`, so anything that makes the hook restart
     unmounts the entire page. Depending on the object identity did exactly
     that on every browser-tab switch. */
  const userId = user?.id ?? null;
  const [state, setState] = useState<SubscriptionState>(EMPTY);
  /** The user whose entitlement `state` describes — drives the loading gate. */
  const resolvedFor = useRef<string | null>(null);

  const load = useCallback(async () => {
    if (!userId) {
      resolvedFor.current = null;
      setState({ ...EMPTY, loading: false });
      return;
    }
    /* Demo account (src/lib/demo-account.ts): entitlement is a constant, not a
       billing row — there is no reachable database to read one from. Mirrors
       `resolveEntitlement`'s demo branch in src/api-server/subscription-guard.ts
       so the UI gate and the API gate cannot disagree. */
    if (isDemoModeEnabled() && isDemoUserId(userId)) {
      resolvedFor.current = userId;
      setState({
        ...EMPTY,
        tier: DEMO_ACCOUNT_TIER,
        status: 'active',
        isActive: true,
        provider: 'demo',
        loading: false,
      });
      return;
    }
    try {
      const { data: sub } = await supabase
        .from('billing_subscriptions')
        .select('plan,status,billing_cycle,auto_renew,cancel_at_period_end,renewal_date,provider,provider_subscription_id,updated_at')
        .eq('user_id', userId)
        .order('updated_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (sub) {
        resolvedFor.current = userId;
        setState({
          tier: normalizeTier(sub.plan),
          status: sub.status ?? null,
          isActive: isAccessGrantingStatus(sub.status),
          billingCycle: (sub.billing_cycle as 'monthly' | 'annual') ?? null,
          autoRenew: Boolean(sub.auto_renew),
          cancelAtPeriodEnd: Boolean(sub.cancel_at_period_end),
          renewalDate: sub.renewal_date ?? null,
          provider: sub.provider ?? null,
          subscriptionId: sub.provider_subscription_id ?? null,
          loading: false,
        });
        return;
      }

      // No subscription row — fall back to the profile tier (may be 'free'/null).
      const { data: profile } = await supabase
        .from('profiles')
        .select('tier')
        .eq('id', userId)
        .maybeSingle();
      const tier = normalizeTier(profile?.tier);
      resolvedFor.current = userId;
      setState({
        ...EMPTY,
        tier,
        // A bare profile tier with no subscription row is only trusted for the
        // free/none case; a paid tier requires an actual active subscription row.
        status: tier === 'none' ? null : 'incomplete',
        isActive: false,
        loading: false,
      });
    } catch {
      resolvedFor.current = userId;
      setState({ ...EMPTY, loading: false });
    }
  }, [userId]);

  useEffect(() => {
    /* `loading` means "this user's entitlement has never been resolved", NOT
       "a refresh is in flight". A background re-read must not blank the
       dashboard: `DashboardLayout` renders its loading shell in place of
       `<Outlet/>` while this is true, so flipping it on every refresh
       destroyed and rebuilt every page under it — losing in-progress work. */
    if (resolvedFor.current !== userId) {
      setState((current) => (current.loading ? current : { ...current, loading: true }));
    }
    void load();
  }, [load, userId]);

  // Live updates when the subscription changes (activation, cancel, switch).
  useEffect(() => {
    if (!userId) return;
    // The demo account has no billing row to watch, and opening a realtime
    // socket to a restricted project just produces a reconnect loop.
    if (isDemoModeEnabled() && isDemoUserId(userId)) return;
    // Topic must be unique PER HOOK INSTANCE: supabase.channel() returns the
    // existing channel for a duplicate topic, and .on() after .subscribe()
    // throws — two components using this hook on one page (DashboardLayout +
    // ScannerDashboard) would crash the whole tree to a blank screen.
    const channel = supabase
      .channel(`subscription-access-${userId}-${nextChannelSeq++}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'billing_subscriptions', filter: `user_id=eq.${userId}` },
        () => void load(),
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [userId, load]);

  return { ...state, refresh: load };
}
