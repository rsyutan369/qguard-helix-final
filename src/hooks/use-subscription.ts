import { useEffect, useState, useCallback } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import {
  normalizeTier,
  isAccessGrantingStatus,
  type AccessTier,
} from '@/lib/subscription-access';

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
  const [state, setState] = useState<SubscriptionState>(EMPTY);

  const load = useCallback(async () => {
    if (!user) {
      setState({ ...EMPTY, loading: false });
      return;
    }
    try {
      const { data: sub } = await supabase
        .from('billing_subscriptions')
        .select('plan,status,billing_cycle,auto_renew,cancel_at_period_end,renewal_date,provider,provider_subscription_id,updated_at')
        .eq('user_id', user.id)
        .order('updated_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (sub) {
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
        .eq('id', user.id)
        .maybeSingle();
      const tier = normalizeTier(profile?.tier);
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
      setState({ ...EMPTY, loading: false });
    }
  }, [user]);

  useEffect(() => {
    setState((s) => ({ ...s, loading: true }));
    void load();
  }, [load]);

  // Live updates when the subscription changes (activation, cancel, switch).
  useEffect(() => {
    if (!user) return;
    const channel = supabase
      .channel(`subscription-access-${user.id}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'billing_subscriptions', filter: `user_id=eq.${user.id}` },
        () => void load(),
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [user, load]);

  return { ...state, refresh: load };
}
