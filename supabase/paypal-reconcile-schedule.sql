-- QGuard — hourly PayPal reconciliation (missed-webhook repair) (2026-10-23)
-- Idempotent. Run after the `billing` Edge Function with the /reconcile route is
-- deployed and PAYPAL_RECONCILE_SECRET is set as a function secret.
--
-- PayPal retries a failed webhook for a few days, then drops it. Without this
-- job a lost BILLING.SUBSCRIPTION.ACTIVATED would leave a paying customer
-- locked out, and a lost PAYMENT.SALE.COMPLETED would leave revenue unrecorded.
-- The job calls POST /functions/v1/billing/api/v1/paypal/reconcile, which
-- re-reads PayPal's own state (supabase/functions/billing/index.ts reconcile).
--
-- The shared secret lives in Supabase Vault, never in this file:
--   SELECT vault.create_secret('<PAYPAL_RECONCILE_SECRET value>', 'paypal_reconcile_secret',
--                              'X-Reconcile-Secret for the billing function');
--   SELECT vault.create_secret('https://<project-ref>.supabase.co/functions/v1/billing/api/v1/paypal/reconcile',
--                              'paypal_reconcile_url', 'Billing reconcile endpoint for this project');
-- To rotate: vault.update_secret(id, '<new>') and `supabase secrets set
-- PAYPAL_RECONCILE_SECRET=<new>` together.

CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS pg_cron WITH SCHEMA pg_catalog;

DO $$
DECLARE
  reconcile_url text;
BEGIN
  SELECT decrypted_secret INTO reconcile_url
    FROM vault.decrypted_secrets WHERE name = 'paypal_reconcile_url';
  IF reconcile_url IS NULL OR reconcile_url !~ '^https://[a-z0-9]+\.supabase\.co/functions/v1/billing/api/v1/paypal/reconcile$' THEN
    RAISE EXCEPTION 'Set paypal_reconcile_url in Vault to the billing endpoint for this Supabase project';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM vault.decrypted_secrets WHERE name = 'paypal_reconcile_secret' AND length(decrypted_secret) > 0) THEN
    RAISE EXCEPTION 'Set paypal_reconcile_secret in Vault to the matching Edge Function secret';
  END IF;
  PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname = 'qguard-paypal-reconcile';
  PERFORM cron.schedule(
    'qguard-paypal-reconcile',
    '17 * * * *',
    format($job$
      SELECT net.http_post(
        url := %L,
        headers := jsonb_build_object(
          'Content-Type', 'application/json',
          'X-Reconcile-Secret', (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'paypal_reconcile_secret')
        ),
        body := '{}'::jsonb,
        timeout_milliseconds := 120000
      )
    $job$, reconcile_url)
  );
END $$;
