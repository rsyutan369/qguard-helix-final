-- QGuard — Google Play Billing v2: products, entitlements, notification inbox
-- Spec: Qguard_Wiki/GooglePlay_Billing (owner decisions 2026-11-12)
--
-- Run AFTER billing-subscription-schema.sql, paypal-subscription-migration.sql,
-- play-billing-migration.sql, billing-integrity-hardening.sql,
-- subscription-period-end-cancellation.sql and qguard-messaging migration 030.
-- Idempotent: safe to run more than once.
--
-- What this adds, and why (everything EXTENDS existing tables — no second
-- subscription store):
--
-- 1. billing_subscriptions (one row per account; strict tier ladder) gains the
--    Play purchase facts: product id, AES-256-GCM-encrypted purchase token (for
--    server-side re-verification; the SHA-256 fingerprint stays in
--    provider_subscription_id for lookups), linked (replaced) token fingerprint,
--    order id, cancel reason, acknowledgement + verification state. A partial
--    unique index makes "one purchase token = one account" a database rule.
-- 2. play_webhook_events becomes the durable RTDN INBOX: a message is claimed
--    (persisted) before processing, retried on failure, dead-lettered after
--    repeated failure, and never stores a raw purchase token.
-- 3. billing_play_accounts maps the obfuscated account id the app hands Google
--    (SHA-256 of the user id) back to the account.
-- 4. subscription_products: the 8 Google Play products + 8 PayPal plans, USD
--    list prices (separate monthly and annual charges, no trial).
-- 5. subscription_entitlement_catalog + user_entitlements: explicit entitlement
--    keys per tier, recomputed by trigger in the SAME transaction as every
--    billing_subscriptions write, swept on expiry, streamed over Realtime.
-- 6. One access rule, provider-aware grace: Google moves expiryTime itself
--    during a grace period (1 h tolerance for RTDN delivery); PayPal renewals
--    can lag the charge (72 h). 'trial' no longer grants access (no trials).
-- 7. billing_audit_events is append-only.

-- 1) Play purchase facts on the existing subscription row ---------------------
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS product_id TEXT;
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS purchase_token_encrypted TEXT;
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS linked_purchase_token_hash TEXT;
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS google_order_id TEXT;
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS cancel_reason TEXT;
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS acknowledgement_state TEXT;
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS verification_state TEXT;
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS amount_cents BIGINT NOT NULL DEFAULT 0;
ALTER TABLE public.billing_subscriptions ADD COLUMN IF NOT EXISTS currency TEXT NOT NULL DEFAULT 'USD';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.billing_subscriptions'::regclass AND conname = 'billing_subscriptions_ack_state_check') THEN
    ALTER TABLE public.billing_subscriptions ADD CONSTRAINT billing_subscriptions_ack_state_check
      CHECK (acknowledgement_state IS NULL OR acknowledgement_state IN ('pending', 'acknowledged'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.billing_subscriptions'::regclass AND conname = 'billing_subscriptions_verification_state_check') THEN
    ALTER TABLE public.billing_subscriptions ADD CONSTRAINT billing_subscriptions_verification_state_check
      CHECK (verification_state IS NULL OR verification_state IN ('pending', 'verified', 'failed'));
  END IF;
END $$;

-- One purchase token can belong to one account only (fingerprint = SHA-256).
CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_subscriptions_play_token
  ON public.billing_subscriptions(provider_subscription_id)
  WHERE provider = 'google_play' AND provider_subscription_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_play_linked
  ON public.billing_subscriptions(linked_purchase_token_hash)
  WHERE linked_purchase_token_hash IS NOT NULL;

COMMENT ON COLUMN public.billing_subscriptions.purchase_token_encrypted IS
  'Google Play purchase token sealed with AES-256-GCM (server key PLAY_TOKEN_ENCRYPTION_KEY, AAD qguard-play-token:v1). Needed to re-query Google; never logged or indexed. provider_subscription_id holds its SHA-256 fingerprint.';
COMMENT ON COLUMN public.billing_subscriptions.linked_purchase_token_hash IS
  'SHA-256 of the Play token this subscription replaced (upgrade/downgrade). Lifecycle events for that older token never overwrite this row.';

-- Clients only ever READ billing rows (RLS). TRUNCATE ignores RLS entirely, and
-- TRIGGER/REFERENCES have no client use: take them away from the API roles.
REVOKE TRUNCATE, TRIGGER, REFERENCES ON public.billing_subscriptions FROM anon, authenticated;
REVOKE TRUNCATE, TRIGGER, REFERENCES ON public.billing_invoices FROM anon, authenticated;
REVOKE TRUNCATE, TRIGGER, REFERENCES ON public.billing_audit_events FROM anon, authenticated;

-- 2) RTDN inbox (extends play_webhook_events) -----------------------------------
ALTER TABLE public.play_webhook_events ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'processed';
ALTER TABLE public.play_webhook_events ADD COLUMN IF NOT EXISTS message_id TEXT;
ALTER TABLE public.play_webhook_events ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE public.play_webhook_events ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
ALTER TABLE public.play_webhook_events ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 1;
ALTER TABLE public.play_webhook_events ADD COLUMN IF NOT EXISTS last_error TEXT;
ALTER TABLE public.play_webhook_events ADD COLUMN IF NOT EXISTS outcome TEXT;
ALTER TABLE public.play_webhook_events ADD COLUMN IF NOT EXISTS purchase_token_encrypted TEXT;
-- A claimed message is not processed yet.
ALTER TABLE public.play_webhook_events ALTER COLUMN processed_at DROP NOT NULL;
ALTER TABLE public.play_webhook_events ALTER COLUMN processed_at DROP DEFAULT;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.play_webhook_events'::regclass AND conname = 'play_webhook_events_status_check') THEN
    ALTER TABLE public.play_webhook_events ADD CONSTRAINT play_webhook_events_status_check
      CHECK (status IN ('processing', 'processed', 'failed', 'dead_letter', 'ignored'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_play_webhook_events_status ON public.play_webhook_events(status, claimed_at);
CREATE INDEX IF NOT EXISTS idx_play_webhook_events_received ON public.play_webhook_events(received_at DESC);

-- Earlier code stored the full RTDN payload, which contains the purchase token.
UPDATE public.play_webhook_events
   SET raw = raw #- '{subscriptionNotification,purchaseToken}' #- '{voidedPurchaseNotification,purchaseToken}'
 WHERE raw ? 'subscriptionNotification' OR raw ? 'voidedPurchaseNotification';

COMMENT ON TABLE public.play_webhook_events IS
  'Google Play notification inbox + verification ledger. A Pub/Sub message is persisted (status processing) BEFORE it is processed; failures are retried by Pub/Sub and the reconcile sweep, then parked as dead_letter after 8 attempts. raw never holds a purchase token; purchase_token_encrypted (AES-256-GCM) lets the sweep replay. Service-role only.';

-- Retention: keep 400 days (covers a yearly renewal cycle plus audit lookback).
CREATE OR REPLACE FUNCTION public.qguard_purge_play_inbox()
RETURNS INTEGER
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH purged AS (
    DELETE FROM public.play_webhook_events
     WHERE status IN ('processed', 'ignored') AND received_at < NOW() - INTERVAL '400 days'
    RETURNING 1
  )
  SELECT count(*)::INTEGER FROM purged;
$$;
REVOKE EXECUTE ON FUNCTION public.qguard_purge_play_inbox() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qguard_purge_play_inbox() TO service_role;

-- 3) Obfuscated account id → account ----------------------------------------------
CREATE TABLE IF NOT EXISTS public.billing_play_accounts (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  obfuscated_account_id TEXT NOT NULL UNIQUE CHECK (obfuscated_account_id ~ '^[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.billing_play_accounts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.billing_play_accounts FROM anon, authenticated;
COMMENT ON TABLE public.billing_play_accounts IS
  'obfuscatedAccountId (SHA-256 of qguard-play-account:v1:<user id>) the app passes to Google Play, mapped back to the account for RTDN. Service-role only.';

-- 4) Product catalog ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.subscription_products (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id TEXT NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN ('google_play', 'paypal')),
  tier TEXT NOT NULL CHECK (tier IN ('Starter', 'Basic', 'Pro', 'Elite')),
  billing_period TEXT NOT NULL CHECK (billing_period IN ('monthly', 'yearly')),
  display_name TEXT NOT NULL,
  description TEXT,
  price_amount NUMERIC(10, 2) NOT NULL CHECK (price_amount > 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order INTEGER NOT NULL DEFAULT 0,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (platform, product_id),
  UNIQUE (platform, tier, billing_period)
);

DROP TRIGGER IF EXISTS trg_subscription_products_updated_at ON public.subscription_products;
CREATE TRIGGER trg_subscription_products_updated_at
  BEFORE UPDATE ON public.subscription_products
  FOR EACH ROW EXECUTE FUNCTION public.qguard_set_updated_at();

ALTER TABLE public.subscription_products ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.subscription_products FROM anon, authenticated;
GRANT SELECT ON public.subscription_products TO anon, authenticated;
DROP POLICY IF EXISTS subscription_products_read_active ON public.subscription_products;
CREATE POLICY subscription_products_read_active ON public.subscription_products FOR SELECT USING (is_active);

INSERT INTO public.subscription_products (product_id, platform, tier, billing_period, display_name, description, price_amount, sort_order, metadata)
SELECT v.product_id, v.platform, v.tier, v.period, v.tier || CASE WHEN v.period = 'yearly' THEN ' (yearly)' ELSE ' (monthly)' END,
       v.description, v.price, v.sort_order, v.metadata::JSONB
  FROM (VALUES
    ('qh_starter_monthly', 'google_play', 'Starter', 'monthly', 1.00, 11, 'Quantum Messaging, calls, local Quantum Vault, Hidden Vault, OffGrid Mesh/XFER', '{"basePlan":"monthly"}'),
    ('qh_starter_yearly',  'google_play', 'Starter', 'yearly', 12.00, 12, 'Quantum Messaging, calls, local Quantum Vault, Hidden Vault, OffGrid Mesh/XFER', '{"basePlan":"yearly"}'),
    ('qh_basic_monthly',   'google_play', 'Basic',   'monthly', 8.00, 21, 'Everything in Starter + Quantum Readiness & Assessment', '{"basePlan":"monthly"}'),
    ('qh_basic_yearly',    'google_play', 'Basic',   'yearly', 60.00, 22, 'Everything in Starter + Quantum Readiness & Assessment', '{"basePlan":"yearly"}'),
    ('qh_pro_monthly',     'google_play', 'Pro',     'monthly', 30.00, 31, 'Everything in Basic + operational PQC readiness', '{"basePlan":"monthly"}'),
    ('qh_pro_yearly',      'google_play', 'Pro',     'yearly', 240.00, 32, 'Everything in Basic + operational PQC readiness', '{"basePlan":"yearly"}'),
    ('qh_elite_monthly',   'google_play', 'Elite',   'monthly', 199.00, 41, 'Everything in Pro + QKMS and compliance control mapping', '{"basePlan":"monthly"}'),
    ('qh_elite_yearly',    'google_play', 'Elite',   'yearly', 1800.00, 42, 'Everything in Pro + QKMS and compliance control mapping', '{"basePlan":"yearly"}'),
    ('paypal_starter_monthly', 'paypal', 'Starter', 'monthly', 1.00, 11, 'Quantum Messaging, calls, local Quantum Vault, Hidden Vault, OffGrid Mesh/XFER', '{"planEnvKey":"PAYPAL_PLAN_STARTER_MONTHLY"}'),
    ('paypal_starter_yearly',  'paypal', 'Starter', 'yearly', 12.00, 12, 'Quantum Messaging, calls, local Quantum Vault, Hidden Vault, OffGrid Mesh/XFER', '{"planEnvKey":"PAYPAL_PLAN_STARTER_YEARLY"}'),
    ('paypal_basic_monthly',   'paypal', 'Basic',   'monthly', 8.00, 21, 'Everything in Starter + Quantum Readiness & Assessment', '{"planEnvKey":"PAYPAL_PLAN_BASIC_MONTHLY"}'),
    ('paypal_basic_yearly',    'paypal', 'Basic',   'yearly', 60.00, 22, 'Everything in Starter + Quantum Readiness & Assessment', '{"planEnvKey":"PAYPAL_PLAN_BASIC_YEARLY"}'),
    ('paypal_pro_monthly',     'paypal', 'Pro',     'monthly', 30.00, 31, 'Everything in Basic + operational PQC readiness', '{"planEnvKey":"PAYPAL_PLAN_PRO_MONTHLY"}'),
    ('paypal_pro_yearly',      'paypal', 'Pro',     'yearly', 240.00, 32, 'Everything in Basic + operational PQC readiness', '{"planEnvKey":"PAYPAL_PLAN_PRO_YEARLY"}'),
    ('paypal_elite_monthly',   'paypal', 'Elite',   'monthly', 199.00, 41, 'Everything in Pro + QKMS and compliance control mapping', '{"planEnvKey":"PAYPAL_PLAN_ELITE_MONTHLY"}'),
    ('paypal_elite_yearly',    'paypal', 'Elite',   'yearly', 1800.00, 42, 'Everything in Pro + QKMS and compliance control mapping', '{"planEnvKey":"PAYPAL_PLAN_ELITE_YEARLY"}')
  ) AS v(product_id, platform, tier, period, price, sort_order, description, metadata)
ON CONFLICT (platform, product_id) DO UPDATE
  SET tier = EXCLUDED.tier, billing_period = EXCLUDED.billing_period, display_name = EXCLUDED.display_name,
      description = EXCLUDED.description, price_amount = EXCLUDED.price_amount, sort_order = EXCLUDED.sort_order,
      metadata = EXCLUDED.metadata, is_active = TRUE;

COMMENT ON TABLE public.subscription_products IS
  'Authoritative QGuard product catalog: 4 paid tiers x monthly/yearly, for Google Play (Android) and PayPal (web/desktop). USD list prices with separate monthly and annual charges. No trial or introductory offer. Google Play''s ProductDetails price is what an Android buyer is charged.';

-- 5) Entitlement catalog + per-account entitlements -------------------------------
CREATE TABLE IF NOT EXISTS public.subscription_entitlement_catalog (
  entitlement_key TEXT PRIMARY KEY CHECK (entitlement_key ~ '^[a-z][a-z0-9_]{1,63}$'),
  min_tier TEXT NOT NULL CHECK (min_tier IN ('Starter', 'Basic', 'Pro', 'Elite')),
  label TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0
);
ALTER TABLE public.subscription_entitlement_catalog ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.subscription_entitlement_catalog FROM anon, authenticated;
GRANT SELECT ON public.subscription_entitlement_catalog TO anon, authenticated;
DROP POLICY IF EXISTS subscription_entitlement_catalog_read ON public.subscription_entitlement_catalog;
CREATE POLICY subscription_entitlement_catalog_read ON public.subscription_entitlement_catalog FOR SELECT USING (TRUE);

-- MUST match supabase/functions/billing/entitlements.ts (tools/billing-edge-check.ts asserts it).
INSERT INTO public.subscription_entitlement_catalog (entitlement_key, min_tier, label, sort_order) VALUES
  ('quantum_messaging', 'Starter', 'Quantum Messaging', 101),
  ('secure_chat', 'Starter', 'End-to-end encrypted Secure Chat', 102),
  ('encrypted_voice_calls', 'Starter', 'Encrypted voice calls', 103),
  ('encrypted_video_calls', 'Starter', 'Encrypted video calls', 104),
  ('disappearing_messages', 'Starter', 'Disappearing messages', 105),
  ('multi_device_trust', 'Starter', 'Multi-device trust', 106),
  ('call_verification', 'Starter', 'One-tap call verification', 107),
  ('quantum_vault_local', 'Starter', 'On-device Quantum Vault (local only)', 108),
  ('hidden_vault', 'Starter', 'Hidden Vault', 109),
  ('offgrid_mesh_xfer', 'Starter', 'OffGrid Mesh and XFER', 110),
  ('qrae', 'Basic', 'Quantum Readiness & Assessment Engine', 201),
  ('risk_analysis', 'Basic', 'Risk Analysis', 202),
  ('migration_planner', 'Basic', 'Migration Planner', 203),
  ('migration_sandbox', 'Basic', 'Migration Sandbox', 204),
  ('ai_migration_advisor', 'Basic', 'AI Migration Advisor', 205),
  ('ai_executive_advisor', 'Basic', 'AI Executive Advisor', 206),
  ('assessment_reports', 'Basic', 'Quantum Readiness & Assessment Reports', 207),
  ('crypto_asset_discovery', 'Basic', 'Cryptographic asset discovery', 208),
  ('cbom_explorer', 'Basic', 'Assets & CBOM Explorer', 209),
  ('hndl_center', 'Basic', 'Harvest Now, Decrypt Later Center', 210),
  ('migration_timeline', 'Pro', 'Migration Timeline', 301),
  ('pqc_auth', 'Pro', 'PQC-Auth Identity Migration Engine', 302),
  ('pqc_orchestration', 'Pro', 'PQC Orchestration', 303),
  ('live_migration', 'Pro', 'Live Migration Operations', 304),
  ('rollback_operations', 'Pro', 'Rollback operations', 305),
  ('runtime_crypto_intelligence', 'Pro', 'Runtime & Cryptographic Intelligence', 306),
  ('supply_chain_readiness', 'Pro', 'Supply Chain Readiness Center', 307),
  ('trust_chain_analysis', 'Pro', 'Trust Chain Analysis', 308),
  ('crypto_agility', 'Pro', 'Crypto Agility Engine', 309),
  ('email_support', 'Pro', 'Email support', 310),
  ('enterprise_crypto_governance', 'Elite', 'Enterprise cryptographic estate governance', 401),
  ('qkms', 'Elite', 'QKMS overview, inventory, governance & readiness', 402),
  ('compliance_control_mapping', 'Elite', 'SOC 2, PCI DSS 4.0.1, NIST & custom control mapping', 403)
ON CONFLICT (entitlement_key) DO UPDATE SET min_tier = EXCLUDED.min_tier, label = EXCLUDED.label, sort_order = EXCLUDED.sort_order;

CREATE TABLE IF NOT EXISTS public.user_entitlements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  entitlement_key TEXT NOT NULL REFERENCES public.subscription_entitlement_catalog(entitlement_key) ON DELETE CASCADE,
  is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  source_subscription_id UUID REFERENCES public.billing_subscriptions(id) ON DELETE SET NULL,
  valid_from TIMESTAMPTZ,
  valid_until TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, entitlement_key)
);
CREATE INDEX IF NOT EXISTS idx_user_entitlements_expiry ON public.user_entitlements(valid_until) WHERE is_enabled;

ALTER TABLE public.user_entitlements ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.user_entitlements FROM anon, authenticated;
GRANT SELECT ON public.user_entitlements TO authenticated;
DROP POLICY IF EXISTS user_entitlements_select_own ON public.user_entitlements;
CREATE POLICY user_entitlements_select_own ON public.user_entitlements FOR SELECT TO authenticated USING (user_id = auth.uid());

COMMENT ON TABLE public.user_entitlements IS
  'Effective entitlements per account, computed ONLY by public.qguard_recalculate_entitlements (trigger on billing_subscriptions + expiry sweep). Clients read their own rows; nobody but the platform writes them. valid_until = when access ends (provider period end + grace), NULL = no end date.';

-- 6) The access rule ---------------------------------------------------------------
-- MUST match rowGrantsAccess/accessGraceMs in supabase/functions/billing/logic.ts.
CREATE OR REPLACE FUNCTION public.qguard_subscription_access_until(p_provider TEXT, p_status TEXT, p_period_end TIMESTAMPTZ)
RETURNS TIMESTAMPTZ
LANGUAGE sql
IMMUTABLE
SET search_path = public
AS $$
  SELECT CASE
    WHEN lower(coalesce(p_status, '')) NOT IN ('active', 'pending_renewal') THEN NULL
    WHEN p_period_end IS NULL THEN 'infinity'::TIMESTAMPTZ
    WHEN p_provider = 'google_play' THEN p_period_end + INTERVAL '1 hour'
    ELSE p_period_end + INTERVAL '72 hours'
  END;
$$;

CREATE OR REPLACE FUNCTION public.qguard_subscription_grants_access(p_provider TEXT, p_status TEXT, p_period_end TIMESTAMPTZ)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = public
AS $$
  SELECT coalesce(public.qguard_subscription_access_until(p_provider, p_status, p_period_end) > NOW(), FALSE);
$$;

CREATE OR REPLACE FUNCTION public.qguard_tier_rank(p_tier TEXT)
RETURNS INTEGER
LANGUAGE sql
IMMUTABLE
SET search_path = public
AS $$
  SELECT CASE lower(coalesce(p_tier, '')) WHEN 'starter' THEN 1 WHEN 'basic' THEN 2 WHEN 'pro' THEN 3 WHEN 'elite' THEN 4 ELSE 0 END;
$$;

-- Messaging paywall (migration 030's function, same signature and caller
-- check): any paid tier includes Starter's messaging.
CREATE OR REPLACE FUNCTION public.qguard_has_messaging_access(uid uuid)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT (COALESCE(auth.role(), '') NOT IN ('anon', 'authenticated') OR uid = auth.uid())
    AND EXISTS (
      SELECT 1
        FROM public.billing_subscriptions s
       WHERE s.user_id = uid
         AND public.qguard_tier_rank(s.plan) >= 1
         AND public.qguard_subscription_grants_access(s.provider, s.status, s.current_period_end)
    );
$$;
COMMENT ON FUNCTION public.qguard_has_messaging_access(uuid) IS
  'True when the account holds an access-granting paid subscription (active/pending_renewal; period end + provider grace not passed). No trial, no free tier. Backing check for the QGuard Messaging paywall RESTRICTIVE policies.';

-- Recompute one account's entitlements from its subscription row.
CREATE OR REPLACE FUNCTION public.qguard_recalculate_entitlements(p_user UUID)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  sub RECORD;
  access_until TIMESTAMPTZ;
  rank INTEGER := 0;
  granted TEXT[];
  removed TEXT[];
  changed INTEGER := 0;
BEGIN
  IF p_user IS NULL THEN
    RETURN 0;
  END IF;
  SELECT id, plan, status, provider, current_period_start, current_period_end
    INTO sub
    FROM public.billing_subscriptions
   WHERE user_id = p_user;

  IF FOUND THEN
    access_until := public.qguard_subscription_access_until(sub.provider, sub.status, sub.current_period_end);
    IF access_until IS NOT NULL AND access_until > NOW() THEN
      rank := public.qguard_tier_rank(sub.plan);
    END IF;
  END IF;

  -- `prior` reads the pre-statement snapshot (data-modifying CTEs do not see
  -- each other's writes), so transitions are computed against the old state.
  WITH prior AS (
    SELECT entitlement_key, is_enabled FROM public.user_entitlements WHERE user_id = p_user
  ), desired AS (
    SELECT c.entitlement_key,
           (rank > 0 AND public.qguard_tier_rank(c.min_tier) <= rank) AS enabled
      FROM public.subscription_entitlement_catalog c
  ), upserted AS (
    INSERT INTO public.user_entitlements AS ue (user_id, entitlement_key, is_enabled, source_subscription_id, valid_from, valid_until, metadata, updated_at)
    SELECT p_user, d.entitlement_key, d.enabled,
           CASE WHEN d.enabled THEN sub.id END,
           CASE WHEN d.enabled THEN coalesce(sub.current_period_start, NOW()) END,
           CASE WHEN d.enabled AND access_until <> 'infinity'::TIMESTAMPTZ THEN access_until END,
           CASE WHEN d.enabled THEN jsonb_build_object('plan', sub.plan, 'provider', sub.provider, 'verifiedPeriodEnd', sub.current_period_end) ELSE '{}'::JSONB END,
           NOW()
      FROM desired d
     WHERE d.enabled
        OR EXISTS (SELECT 1 FROM prior x WHERE x.entitlement_key = d.entitlement_key)
    ON CONFLICT (user_id, entitlement_key) DO UPDATE
       SET is_enabled = EXCLUDED.is_enabled,
           source_subscription_id = EXCLUDED.source_subscription_id,
           valid_from = CASE WHEN ue.is_enabled AND EXCLUDED.is_enabled THEN ue.valid_from ELSE EXCLUDED.valid_from END,
           valid_until = EXCLUDED.valid_until,
           metadata = EXCLUDED.metadata,
           updated_at = NOW()
     WHERE ue.is_enabled IS DISTINCT FROM EXCLUDED.is_enabled
        OR ue.valid_until IS DISTINCT FROM EXCLUDED.valid_until
        OR ue.source_subscription_id IS DISTINCT FROM EXCLUDED.source_subscription_id
        OR ue.metadata IS DISTINCT FROM EXCLUDED.metadata
    RETURNING ue.entitlement_key, ue.is_enabled
  )
  SELECT array_agg(u.entitlement_key ORDER BY u.entitlement_key)
           FILTER (WHERE u.is_enabled AND NOT coalesce(p.is_enabled, FALSE)),
         array_agg(u.entitlement_key ORDER BY u.entitlement_key)
           FILTER (WHERE NOT u.is_enabled AND coalesce(p.is_enabled, FALSE)),
         count(*)
    INTO granted, removed, changed
    FROM upserted u
    LEFT JOIN prior p ON p.entitlement_key = u.entitlement_key;

  -- Audit only real grant/remove transitions (validity extensions on renewal
  -- are recorded by the subscription lifecycle events instead).
  IF removed IS NOT NULL THEN
    INSERT INTO public.billing_audit_events (user_id, action, message, metadata)
    VALUES (p_user, 'entitlement.removed', format('%s entitlement(s) removed', cardinality(removed)),
            jsonb_build_object('keys', removed, 'plan', sub.plan, 'status', sub.status, 'source', 'entitlement_engine'));
  END IF;
  IF granted IS NOT NULL THEN
    INSERT INTO public.billing_audit_events (user_id, action, message, metadata)
    VALUES (p_user, 'entitlement.granted', format('%s entitlement(s) granted (%s)', cardinality(granted), sub.plan),
            jsonb_build_object('keys', granted, 'plan', sub.plan, 'validUntil', access_until, 'source', 'entitlement_engine'));
  END IF;
  RETURN coalesce(changed, 0);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.qguard_recalculate_entitlements(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qguard_recalculate_entitlements(UUID) TO service_role;

-- Same transaction as the subscription write.
CREATE OR REPLACE FUNCTION public.qguard_billing_subscriptions_entitlements()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM public.qguard_recalculate_entitlements(OLD.user_id);
    RETURN OLD;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.user_id IS DISTINCT FROM NEW.user_id THEN
    PERFORM public.qguard_recalculate_entitlements(OLD.user_id);
  END IF;
  PERFORM public.qguard_recalculate_entitlements(NEW.user_id);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_billing_subscriptions_entitlements ON public.billing_subscriptions;
CREATE TRIGGER trg_billing_subscriptions_entitlements
  AFTER INSERT OR DELETE OR UPDATE OF user_id, plan, status, provider, current_period_start, current_period_end
  ON public.billing_subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.qguard_billing_subscriptions_entitlements();

-- Time passes without a row change: withdraw entitlements whose access ended.
CREATE OR REPLACE FUNCTION public.qguard_sweep_expired_entitlements()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  account UUID;
  swept INTEGER := 0;
BEGIN
  FOR account IN
    SELECT DISTINCT user_id FROM public.user_entitlements
     WHERE is_enabled AND valid_until IS NOT NULL AND valid_until <= NOW()
     LIMIT 1000
  LOOP
    PERFORM public.qguard_recalculate_entitlements(account);
    swept := swept + 1;
  END LOOP;
  RETURN swept;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.qguard_sweep_expired_entitlements() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qguard_sweep_expired_entitlements() TO service_role;

-- Server-side feature gate for protected operations (service role / definer callers).
CREATE OR REPLACE FUNCTION public.qguard_has_entitlement(p_user UUID, p_key TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_entitlements
     WHERE user_id = p_user AND entitlement_key = p_key AND is_enabled
       AND (valid_until IS NULL OR valid_until > NOW())
  );
$$;
REVOKE EXECUTE ON FUNCTION public.qguard_has_entitlement(UUID, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qguard_has_entitlement(UUID, TEXT) TO service_role;

-- 7) Append-only audit trail --------------------------------------------------------
CREATE OR REPLACE FUNCTION public.qguard_billing_audit_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'billing_audit_events is append-only' USING ERRCODE = '42501';
END;
$$;
DROP TRIGGER IF EXISTS trg_billing_audit_events_immutable ON public.billing_audit_events;
CREATE TRIGGER trg_billing_audit_events_immutable
  BEFORE UPDATE ON public.billing_audit_events
  FOR EACH ROW EXECUTE FUNCTION public.qguard_billing_audit_immutable();

-- 8) Realtime: entitlement changes stream to the account's signed-in devices ------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime')
    AND NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'user_entitlements')
  THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.user_entitlements;
  END IF;
END $$;

-- 9) Schedules (pg_cron) -----------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname IN ('qguard-sweep-expired-entitlements', 'qguard-purge-play-inbox');
    PERFORM cron.schedule('qguard-sweep-expired-entitlements', '*/5 * * * *', 'SELECT public.qguard_sweep_expired_entitlements()');
    PERFORM cron.schedule('qguard-purge-play-inbox', '17 3 * * *', 'SELECT public.qguard_purge_play_inbox()');
  END IF;
END $$;

-- 10) Backfill every existing account ------------------------------------------------------
SELECT public.qguard_recalculate_entitlements(user_id) FROM public.billing_subscriptions;
