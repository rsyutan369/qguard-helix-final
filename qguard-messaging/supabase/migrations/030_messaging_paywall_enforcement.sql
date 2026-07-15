-- 030: Messaging paywall — server-side subscription enforcement
-- (Qguard_Wiki/Android_Paywall_Guidelines)
--
-- The subscription belongs to the ACCOUNT: public.billing_subscriptions
-- (installed by supabase/billing-subscription-schema.sql on this project) is the
-- single source of truth for every platform. This migration adds the messaging
-- database's OWN enforcement so a tampered client can never send messages or
-- place calls without an access-granting plan — the UI paywall is presentation,
-- these policies are the security boundary.
--
-- Design:
--   * qguard_has_messaging_access(uid): STARTER or higher with an
--     access-granting status ('active' | 'trial' | 'pending_renewal' — the same
--     set as src/lib/subscription-access.ts) and a current period that has not
--     lapsed by more than a 72h grace window (renewal webhooks can lag a little;
--     hard expiry/cancellation flips `status`, which locks immediately).
--   * RESTRICTIVE policies AND with the existing permissive ones, so existing
--     membership/ownership rules are untouched — this only ADDS the
--     subscription requirement on the write paths that matter:
--       - messaging_message_envelopes INSERT  (sending messages / attachments)
--       - messaging_conversations    INSERT  (starting conversations)
--       - messaging_call_signals     INSERT  (placing/answering calls)
--     Reads stay ungated so a lapsed account still sees its own history and the
--     Subscription/Settings pages keep working; the app gate hides the UI.
--
-- Ops note — granting access manually (owner/support comp):
--   INSERT INTO public.billing_subscriptions (user_id, subscription_id, provider, plan, status, billing_cycle)
--   VALUES ('<user-uuid>', 'comp_<user-uuid>', 'manual', 'Starter', 'active', 'monthly')
--   ON CONFLICT (user_id) DO UPDATE SET plan = EXCLUDED.plan, status = 'active', updated_at = now();

-- Refuse to install the paywall when the billing schema is missing — otherwise
-- the helper would error at runtime and lock EVERYONE out.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'billing_subscriptions'
  ) THEN
    RAISE EXCEPTION 'billing_subscriptions is missing. Run supabase/billing-subscription-schema.sql (and paypal-subscription-migration.sql) before 030_messaging_paywall_enforcement.sql';
  END IF;
END $$;

CREATE OR REPLACE FUNCTION public.qguard_has_messaging_access(uid uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.billing_subscriptions s
    WHERE s.user_id = uid
      AND lower(s.status) IN ('active', 'trial', 'pending_renewal')
      AND (
        s.current_period_end IS NULL
        OR s.current_period_end > (now() - interval '72 hours')
      )
  );
$$;

REVOKE ALL ON FUNCTION public.qguard_has_messaging_access(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.qguard_has_messaging_access(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qguard_has_messaging_access(uuid) TO service_role;

-- Sending encrypted messages requires an active plan.
DROP POLICY IF EXISTS messaging_envelopes_require_subscription ON public.messaging_message_envelopes;
CREATE POLICY messaging_envelopes_require_subscription
  ON public.messaging_message_envelopes
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (public.qguard_has_messaging_access(auth.uid()));

-- Creating conversations requires an active plan.
DROP POLICY IF EXISTS messaging_conversations_require_subscription ON public.messaging_conversations;
CREATE POLICY messaging_conversations_require_subscription
  ON public.messaging_conversations
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (public.qguard_has_messaging_access(auth.uid()));

-- Placing or answering quantum-encrypted calls requires an active plan.
DROP POLICY IF EXISTS messaging_call_signals_require_subscription ON public.messaging_call_signals;
CREATE POLICY messaging_call_signals_require_subscription
  ON public.messaging_call_signals
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (public.qguard_has_messaging_access(auth.uid()));

-- Real-time cross-device sync: subscription + invoice changes must stream to
-- every logged-in session (desktop unlocks the instant an Android purchase
-- activates, and vice versa). Idempotent — the billing schema may already have
-- added these to the publication.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'billing_subscriptions'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.billing_subscriptions;
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'billing_invoices'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.billing_invoices;
    END IF;
  END IF;
END $$;

COMMENT ON FUNCTION public.qguard_has_messaging_access(uuid) IS
  'True when the account has an access-granting subscription (active/trial/pending_renewal, period not lapsed beyond 72h grace). Backing check for the QGuard Messaging paywall RESTRICTIVE policies.';
