-- QGuard Helix Billing & Subscription Schema
-- Run in Supabase SQL Editor after profile-security-schema.sql and dashboard-schema.sql.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE OR REPLACE FUNCTION public.qguard_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS public.billing_subscriptions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  subscription_id TEXT NOT NULL UNIQUE,
  provider TEXT,
  provider_customer_id TEXT,
  provider_subscription_id TEXT,
  plan TEXT NOT NULL DEFAULT 'Starter' CHECK (plan IN ('Starter', 'Pro', 'Elite')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'trial', 'expired', 'suspended', 'pending_renewal', 'cancelled', 'past_due', 'incomplete')),
  billing_cycle TEXT NOT NULL DEFAULT 'monthly' CHECK (billing_cycle IN ('monthly', 'annual')),
  auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
  cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
  renewal_date TIMESTAMPTZ,
  trial_expires_at TIMESTAMPTZ,
  account_created_at TIMESTAMPTZ,
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_subscriptions_user_unique ON public.billing_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_status ON public.billing_subscriptions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_provider ON public.billing_subscriptions(provider, provider_subscription_id);

DROP TRIGGER IF EXISTS trg_billing_subscriptions_updated_at ON public.billing_subscriptions;
CREATE TRIGGER trg_billing_subscriptions_updated_at
  BEFORE UPDATE ON public.billing_subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.qguard_set_updated_at();

ALTER TABLE public.billing_subscriptions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_subscriptions_select_own ON public.billing_subscriptions;
DROP POLICY IF EXISTS billing_subscriptions_insert_own ON public.billing_subscriptions;
DROP POLICY IF EXISTS billing_subscriptions_update_own ON public.billing_subscriptions;
CREATE POLICY billing_subscriptions_select_own ON public.billing_subscriptions FOR SELECT USING (user_id = auth.uid());
CREATE POLICY billing_subscriptions_insert_own ON public.billing_subscriptions FOR INSERT WITH CHECK (user_id = auth.uid());
CREATE POLICY billing_subscriptions_update_own ON public.billing_subscriptions FOR UPDATE USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

CREATE TABLE IF NOT EXISTS public.billing_payment_methods (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'tokenized',
  provider_payment_method_id TEXT,
  brand TEXT NOT NULL DEFAULT 'Card',
  last4 TEXT NOT NULL CHECK (last4 ~ '^[0-9]{0,4}$'),
  exp_month INTEGER CHECK (exp_month BETWEEN 1 AND 12),
  exp_year INTEGER CHECK (exp_year BETWEEN 2024 AND 2200),
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  billing_name TEXT,
  billing_address JSONB NOT NULL DEFAULT '{}'::JSONB,
  country TEXT,
  tax_region TEXT,
  last_used_at TIMESTAMPTZ,
  removed_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (provider_payment_method_id IS NULL OR provider_payment_method_id <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_payment_methods_provider_id
  ON public.billing_payment_methods(provider_payment_method_id)
  WHERE provider_payment_method_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_billing_payment_methods_user_active
  ON public.billing_payment_methods(user_id, is_default DESC, updated_at DESC)
  WHERE removed_at IS NULL;

DROP TRIGGER IF EXISTS trg_billing_payment_methods_updated_at ON public.billing_payment_methods;
CREATE TRIGGER trg_billing_payment_methods_updated_at
  BEFORE UPDATE ON public.billing_payment_methods
  FOR EACH ROW EXECUTE FUNCTION public.qguard_set_updated_at();

ALTER TABLE public.billing_payment_methods ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_payment_methods_own ON public.billing_payment_methods;
CREATE POLICY billing_payment_methods_own ON public.billing_payment_methods
  FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

CREATE TABLE IF NOT EXISTS public.billing_invoices (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  invoice_id TEXT NOT NULL,
  provider_invoice_id TEXT,
  transaction_id TEXT,
  payment_date TIMESTAMPTZ,
  amount_paid_cents INTEGER NOT NULL DEFAULT 0,
  tax_cents INTEGER NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  payment_method_summary TEXT,
  subscription_plan TEXT NOT NULL DEFAULT 'Starter' CHECK (subscription_plan IN ('Starter', 'Pro', 'Elite')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('paid', 'failed', 'pending', 'refunded')),
  hosted_invoice_url TEXT,
  receipt_url TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_invoices_provider_invoice
  ON public.billing_invoices(provider_invoice_id)
  WHERE provider_invoice_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_billing_invoices_user_created ON public.billing_invoices(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_invoices_user_status ON public.billing_invoices(user_id, status);

DROP TRIGGER IF EXISTS trg_billing_invoices_updated_at ON public.billing_invoices;
CREATE TRIGGER trg_billing_invoices_updated_at
  BEFORE UPDATE ON public.billing_invoices
  FOR EACH ROW EXECUTE FUNCTION public.qguard_set_updated_at();

ALTER TABLE public.billing_invoices ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_invoices_select_own ON public.billing_invoices;
CREATE POLICY billing_invoices_select_own ON public.billing_invoices FOR SELECT USING (user_id = auth.uid());

CREATE TABLE IF NOT EXISTS public.billing_usage_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  metric_key TEXT NOT NULL,
  quantity NUMERIC NOT NULL DEFAULT 1,
  source TEXT NOT NULL DEFAULT 'platform',
  idempotency_key TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_usage_events_idempotency
  ON public.billing_usage_events(user_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_billing_usage_events_user_metric_created
  ON public.billing_usage_events(user_id, metric_key, created_at DESC);

ALTER TABLE public.billing_usage_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_usage_events_select_own ON public.billing_usage_events;
DROP POLICY IF EXISTS billing_usage_events_insert_own ON public.billing_usage_events;
CREATE POLICY billing_usage_events_select_own ON public.billing_usage_events FOR SELECT USING (user_id = auth.uid());
CREATE POLICY billing_usage_events_insert_own ON public.billing_usage_events FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE TABLE IF NOT EXISTS public.billing_notification_settings (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email_notifications BOOLEAN NOT NULL DEFAULT TRUE,
  in_app_alerts BOOLEAN NOT NULL DEFAULT TRUE,
  webhook_notifications BOOLEAN NOT NULL DEFAULT FALSE,
  webhook_url TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_billing_notification_settings_updated_at ON public.billing_notification_settings;
CREATE TRIGGER trg_billing_notification_settings_updated_at
  BEFORE UPDATE ON public.billing_notification_settings
  FOR EACH ROW EXECUTE FUNCTION public.qguard_set_updated_at();

ALTER TABLE public.billing_notification_settings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_notification_settings_own ON public.billing_notification_settings;
CREATE POLICY billing_notification_settings_own ON public.billing_notification_settings
  FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

CREATE TABLE IF NOT EXISTS public.billing_notifications (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  type TEXT NOT NULL DEFAULT 'billing',
  severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'success', 'warning', 'critical')),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  delivery_channels JSONB NOT NULL DEFAULT '["in_app"]'::JSONB,
  read_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_notifications_user_created ON public.billing_notifications(user_id, created_at DESC);
ALTER TABLE public.billing_notifications ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_notifications_select_own ON public.billing_notifications;
DROP POLICY IF EXISTS billing_notifications_update_own ON public.billing_notifications;
CREATE POLICY billing_notifications_select_own ON public.billing_notifications FOR SELECT USING (user_id = auth.uid());
CREATE POLICY billing_notifications_update_own ON public.billing_notifications FOR UPDATE USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

CREATE TABLE IF NOT EXISTS public.billing_audit_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  message TEXT NOT NULL,
  ip_address INET,
  user_agent TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_audit_events_user_created ON public.billing_audit_events(user_id, created_at DESC);
ALTER TABLE public.billing_audit_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS billing_audit_events_select_own ON public.billing_audit_events;
CREATE POLICY billing_audit_events_select_own ON public.billing_audit_events FOR SELECT USING (user_id = auth.uid());

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime'
        AND schemaname = 'public'
        AND tablename = 'billing_subscriptions'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.billing_subscriptions;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime'
        AND schemaname = 'public'
        AND tablename = 'billing_payment_methods'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.billing_payment_methods;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime'
        AND schemaname = 'public'
        AND tablename = 'billing_invoices'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.billing_invoices;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime'
        AND schemaname = 'public'
        AND tablename = 'billing_usage_events'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.billing_usage_events;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime'
        AND schemaname = 'public'
        AND tablename = 'billing_notifications'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.billing_notifications;
    END IF;
  END IF;
END $$;

COMMENT ON TABLE public.billing_payment_methods IS
  'Stores tokenized payment method metadata only: brand, last4, expiry, and provider token reference. Full card numbers and CVV values must never be stored.';
