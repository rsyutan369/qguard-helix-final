-- QGuard — Google Play Billing subscription support
-- Run in the Supabase SQL Editor AFTER billing-subscription-schema.sql.
-- Idempotent: safe to run more than once.
--
-- Google Play purchases activate subscriptions through
-- src/api-server/play-billing.ts:
--   * POST /api/v1/play-billing/verify — the app submits a purchase token; the
--     server verifies it with the Google Play Developer API and upserts
--     billing_subscriptions (provider 'google_play').
--   * POST /api/v1/play-billing/rtdn — Real-Time Developer Notifications
--     (Pub/Sub push) keep renewals/cancellations/expirations in sync.

-- 1) Webhook/RTDN idempotency + audit ledger (mirrors paypal_webhook_events).
--    Written only by the server (service role); RLS on with no policies means
--    normal authenticated/anon clients cannot read or write it.
CREATE TABLE IF NOT EXISTS public.play_webhook_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event_id TEXT NOT NULL UNIQUE,
  notification_type TEXT,
  purchase_token_hash TEXT,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  raw JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_play_webhook_events_token
  ON public.play_webhook_events(purchase_token_hash);

ALTER TABLE public.play_webhook_events ENABLE ROW LEVEL SECURITY;
-- Intentionally no policies: only the service role (which bypasses RLS) touches it.

COMMENT ON TABLE public.play_webhook_events IS
  'Idempotency + audit ledger for processed Google Play RTDN messages and purchase verifications. Server/service-role only. purchase_token_hash is SHA-256 — raw purchase tokens are never stored outside billing_subscriptions metadata.';
