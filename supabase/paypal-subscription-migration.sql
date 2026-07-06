-- QGuard Helix — PayPal subscription support
-- Run in the Supabase SQL Editor AFTER billing-subscription-schema.sql.
-- Idempotent: safe to run more than once.

-- 1) Allow the new "Basic" tier on the billing tables (was Starter/Pro/Elite only).
ALTER TABLE public.billing_subscriptions
  DROP CONSTRAINT IF EXISTS billing_subscriptions_plan_check;
ALTER TABLE public.billing_subscriptions
  ADD CONSTRAINT billing_subscriptions_plan_check
  CHECK (plan IN ('Starter', 'Basic', 'Pro', 'Elite'));

ALTER TABLE public.billing_invoices
  DROP CONSTRAINT IF EXISTS billing_invoices_subscription_plan_check;
ALTER TABLE public.billing_invoices
  ADD CONSTRAINT billing_invoices_subscription_plan_check
  CHECK (subscription_plan IN ('Starter', 'Basic', 'Pro', 'Elite'));

-- 2) Webhook idempotency + audit ledger for PayPal events.
--    Written only by the server (service role); RLS on with no policies means
--    normal authenticated/anon clients cannot read or write it.
CREATE TABLE IF NOT EXISTS public.paypal_webhook_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT,
  resource_id TEXT,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  raw JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_paypal_webhook_events_resource
  ON public.paypal_webhook_events(resource_id);

ALTER TABLE public.paypal_webhook_events ENABLE ROW LEVEL SECURITY;
-- Intentionally no policies: only the service role (which bypasses RLS) touches it.

COMMENT ON TABLE public.paypal_webhook_events IS
  'Idempotency + audit ledger for processed PayPal webhook events. Server/service-role only.';
