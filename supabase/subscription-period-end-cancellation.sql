-- QGuard — cancellation keeps access until the end of the paid period (2026-09-22)
-- Run AFTER billing-integrity-hardening.sql. Idempotent.
--
-- Product rule (owner decision 2026-09-22): a customer who cancels keeps the
-- plan they already paid for until current_period_end; access then ends
-- automatically. Provider billing stops at the moment of cancellation.
--
-- Writers (billing Edge Function, src/api-server/billing.ts, the PayPal
-- webhook) keep a cancelled row in its access-granting status with
-- cancel_at_period_end = true (supabase/functions/billing/logic.ts
-- cancellationPatch). This function is the ONE transition that ends that
-- access, so status stays the single source of truth for every reader
-- (DashboardLayout, subscription-guard, qguard_has_messaging_access, Revenue
-- Intelligence). It runs in the database on a schedule, so it does not depend
-- on any API server being hosted.

CREATE OR REPLACE FUNCTION public.qguard_expire_cancelled_subscriptions()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  ended_count INTEGER := 0;
BEGIN
  -- Data-modifying CTEs always run to completion, whether or not the final
  -- SELECT reads them: the flip, its audit rows and the customer notices
  -- happen together or (on error) not at all.
  WITH ended AS (
    UPDATE public.billing_subscriptions s
       SET status = 'cancelled', auto_renew = FALSE, updated_at = NOW()
     WHERE s.cancel_at_period_end
       AND lower(s.status) IN ('active', 'trial', 'pending_renewal')
       AND s.current_period_end IS NOT NULL
       AND s.current_period_end <= NOW()
    RETURNING s.id, s.user_id, s.plan, s.current_period_end, s.provider_subscription_id
  ), audited AS (
    INSERT INTO public.billing_audit_events (user_id, action, message, metadata)
    SELECT e.user_id,
           'subscription.access_ended',
           'Paid period ended after cancellation; access ended',
           jsonb_build_object(
             'subscriptionId', e.id,
             'plan', e.plan,
             'periodEnd', e.current_period_end,
             'providerSubscriptionId', e.provider_subscription_id,
             'source', 'scheduled_expiry'
           )
      FROM ended e
    RETURNING 1
  ), notified AS (
    INSERT INTO public.billing_notifications (user_id, type, severity, title, message)
    SELECT e.user_id, 'subscription', 'warning', 'Subscription ended',
           format('Your %s subscription has ended. Choose a plan to regain access.', e.plan)
      FROM ended e
    RETURNING 1
  )
  SELECT count(*) INTO ended_count FROM ended;
  RETURN ended_count;
END;
$$;

-- Callable by the scheduler (runs as the function owner) and the service role
-- only — never through the public Data API.
REVOKE EXECUTE ON FUNCTION public.qguard_expire_cancelled_subscriptions() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.qguard_expire_cancelled_subscriptions() FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qguard_expire_cancelled_subscriptions() TO service_role;

-- Every 10 minutes: access ends at most ~10 minutes after the paid period.
CREATE EXTENSION IF NOT EXISTS pg_cron WITH SCHEMA pg_catalog;
DO $$
BEGIN
  PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname = 'qguard-expire-cancelled-subscriptions';
  PERFORM cron.schedule(
    'qguard-expire-cancelled-subscriptions',
    '*/10 * * * *',
    'SELECT public.qguard_expire_cancelled_subscriptions()'
  );
END $$;
