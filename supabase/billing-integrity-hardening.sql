-- QGuard Helix — billing integrity hardening (Revenue Intelligence audit, 2026-09-22)
-- Run AFTER billing-subscription-schema.sql, paypal-subscription-migration.sql,
-- admin-dashboard-schema.sql, data-api-grants.sql and rpc-and-rls-hardening.sql.
-- Idempotent: safe to run more than once.
--
-- Why each block exists:
--
-- 1. billing_subscriptions carried INSERT/UPDATE policies scoped only by
--    `user_id = auth.uid()`. Any signed-in user could therefore PATCH their own
--    row through the public Data API — `plan = 'Elite', status = 'active'` —
--    and receive Elite entitlement, a paid QGuard Messaging seat, and a
--    fabricated MRR contribution on the owner's Revenue Intelligence
--    dashboard. No client ever writes this table; every legitimate writer (the
--    PayPal webhook, Play verification, the billing API, the Admin console) is
--    server-side with the service role.
--
-- 2. profiles_update_own lets a user change EVERY column of their profile,
--    including tier (read by the billing API as the plan to bootstrap),
--    access role (read by Copilot/Admin RBAC), account_status, permissions,
--    tenant_id, mfa_required and quotas. The
--    trigger below leaves profile editing intact and refuses changes to the
--    platform-managed columns from user tokens.
--
-- 3. paypal_webhook_events becomes a claim ledger (status / claimed_at /
--    attempts / last_error) so a webhook is claimed before its side effects run
--    and concurrent redeliveries cannot both run. Existing rows (and rows the
--    previous function version inserts after processing) default to 'processed'.
--
-- 4. billing_notifications is subscribed to by Settings > Billing (realtime) but
--    was never in the supabase_realtime publication, so billing alerts only
--    appeared after a reload.
--
-- 5. Indexes for the ordered, paged reads Revenue Intelligence performs.

-- 1) Entitlement rows are server-written only ---------------------------------
DROP POLICY IF EXISTS billing_subscriptions_insert_own ON public.billing_subscriptions;
DROP POLICY IF EXISTS billing_subscriptions_update_own ON public.billing_subscriptions;

-- 2) Platform-managed profile columns ----------------------------------------
CREATE OR REPLACE FUNCTION public.qguard_protect_profile_managed_columns()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
BEGIN
  -- Only untrusted Data API roles are constrained. The service role, SECURITY
  -- DEFINER functions (current_user = their owner) and the auth trigger that
  -- creates the profile row are the platform itself.
  IF current_user NOT IN ('authenticated', 'anon') THEN
    RETURN NEW;
  END IF;
  IF COALESCE(public.qguard_is_owner(), FALSE) THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    NEW.tier := 'free';
    NEW.role := NULL;
    NEW.account_status := 'active';
    NEW.permissions := ARRAY[]::TEXT[];
    NEW.tenant_id := NULL;
    NEW.mfa_required := FALSE;
    NEW.max_keys_per_day := 10;
    NEW.max_vault_storage := 104857600;
    NEW.paypal_payer_id := NULL;
    NEW.paypal_subscription_id := NULL;
    NEW.last_admin_action_at := NULL;
    RETURN NEW;
  END IF;

  IF NEW.tier IS DISTINCT FROM OLD.tier
    OR NEW.role IS DISTINCT FROM OLD.role
    OR NEW.account_status IS DISTINCT FROM OLD.account_status
    OR NEW.permissions IS DISTINCT FROM OLD.permissions
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.mfa_required IS DISTINCT FROM OLD.mfa_required
    OR NEW.max_keys_per_day IS DISTINCT FROM OLD.max_keys_per_day
    OR NEW.max_vault_storage IS DISTINCT FROM OLD.max_vault_storage
    OR NEW.paypal_payer_id IS DISTINCT FROM OLD.paypal_payer_id
    OR NEW.paypal_subscription_id IS DISTINCT FROM OLD.paypal_subscription_id
    OR NEW.last_admin_action_at IS DISTINCT FROM OLD.last_admin_action_at
  THEN
    RAISE EXCEPTION 'tier, access role, account status, permissions, tenant, MFA policy, quotas and billing references are managed by the platform'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_profiles_protect_managed_columns ON public.profiles;
CREATE TRIGGER trg_profiles_protect_managed_columns
  BEFORE INSERT OR UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.qguard_protect_profile_managed_columns();

-- 3) Webhook claim ledger ------------------------------------------------------
ALTER TABLE public.paypal_webhook_events ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'processed';
ALTER TABLE public.paypal_webhook_events ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
ALTER TABLE public.paypal_webhook_events ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 1;
ALTER TABLE public.paypal_webhook_events ADD COLUMN IF NOT EXISTS last_error TEXT;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.paypal_webhook_events'::regclass
      AND conname = 'paypal_webhook_events_status_check'
  ) THEN
    ALTER TABLE public.paypal_webhook_events
      ADD CONSTRAINT paypal_webhook_events_status_check CHECK (status IN ('processing', 'processed', 'failed'));
  END IF;
END $$;
COMMENT ON COLUMN public.paypal_webhook_events.status IS
  'processing = claimed, side effects running; processed = done; failed = released for PayPal''s retry. processed_at is the claim time until the event finishes.';

-- 4) Realtime for billing notifications ----------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime')
    AND NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'billing_notifications'
    )
  THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.billing_notifications;
  END IF;
END $$;

-- 5) Indexes for Revenue Intelligence's ordered, paged reads --------------------
CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_updated_at ON public.billing_subscriptions(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_invoices_created_at ON public.billing_invoices(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_audit_events_created_at ON public.billing_audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_audit_events_action_created ON public.billing_audit_events(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_notifications_created_at ON public.billing_notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_created_at ON public.profiles(created_at DESC);
