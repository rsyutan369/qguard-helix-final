-- ============================================================================
-- QGuard Helix — Quantum Trust Certification Engine™ schema
-- Run in Supabase SQL Editor after billing-subscription-schema.sql.
--
-- NAMING: the issued-certificate table is `quantum_trust_certificates` — NOT
-- `certificates`. The platform already ships a `certificates` table that is the
-- X.509 / TLS certificate INVENTORY (columns not_before/not_after/…); the
-- Quantum Trust Certification Engine must never redefine or collide with it. The
-- engine reads that inventory (read-only) for the "expired certificates"
-- eligibility criterion and writes its own certificates here.
--
-- Every table is tenant-scoped by user_id with owner-only RLS. The public
-- verification portal NEVER reads these tables directly from the browser — it
-- goes through the Express verification endpoint (service role), which returns
-- only the non-sensitive public certificate fields.
--
-- This script is idempotent and safe to re-run.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE OR REPLACE FUNCTION public.qguard_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------------------
-- quantum_trust_certificates — one row per issued Quantum Trust Certificate™
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.quantum_trust_certificates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  certificate_id TEXT NOT NULL UNIQUE,                    -- QTH-2026-000123
  organization TEXT NOT NULL,
  organization_logo TEXT,                                 -- data URL (kept private; never in public payload)
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked', 'expired', 'superseded')),
  level TEXT NOT NULL CHECK (level IN ('bronze', 'silver', 'gold', 'platinum', 'diamond')),
  trust_score INTEGER NOT NULL CHECK (trust_score BETWEEN 0 AND 1000),
  overall_readiness INTEGER NOT NULL,
  quantum_risk INTEGER NOT NULL,
  hndl_risk INTEGER NOT NULL,
  residual_risk INTEGER NOT NULL,
  residual_risk_level TEXT NOT NULL DEFAULT '',
  assessment_confidence INTEGER NOT NULL,
  pqc_adoption INTEGER NOT NULL,
  assessment_id TEXT NOT NULL DEFAULT '',
  assessment_version TEXT NOT NULL DEFAULT '',
  scope JSONB NOT NULL DEFAULT '[]'::JSONB,               -- verified assessment scope bullets
  payload JSONB NOT NULL DEFAULT '{}'::JSONB,             -- canonical signed payload (integrity source of truth)
  certificate_hash TEXT NOT NULL,                         -- SHA3-256 hex of canonical payload
  verification_url TEXT NOT NULL DEFAULT '',
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  renewed_from TEXT,                                      -- previous certificate_id when renewal
  suspended_reason TEXT,
  revoked_reason TEXT,
  last_validated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_qtc_certificates_user ON public.quantum_trust_certificates(user_id, status);
CREATE INDEX IF NOT EXISTS idx_qtc_certificates_org ON public.quantum_trust_certificates(lower(organization));
CREATE INDEX IF NOT EXISTS idx_qtc_certificates_expiry ON public.quantum_trust_certificates(expires_at);

-- ----------------------------------------------------------------------------
-- certificate_assets — validated assets covered by a certificate
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_assets (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  certificate_id TEXT NOT NULL,
  asset_name TEXT NOT NULL,
  asset_type TEXT NOT NULL DEFAULT 'asset',
  environment TEXT NOT NULL DEFAULT 'unknown',
  posture TEXT NOT NULL DEFAULT 'unknown',                -- pqc | hybrid | vulnerable | unknown
  risk_score INTEGER NOT NULL DEFAULT 0,
  internet_facing BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certificate_assets_cert ON public.certificate_assets(certificate_id);
CREATE INDEX IF NOT EXISTS idx_certificate_assets_user ON public.certificate_assets(user_id);

-- ----------------------------------------------------------------------------
-- certificate_algorithms — verified cryptographic stack at issuance
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_algorithms (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  certificate_id TEXT NOT NULL,
  category TEXT NOT NULL,                                 -- Key Establishment / Digital Signatures / ...
  algorithm TEXT NOT NULL,
  standard TEXT NOT NULL DEFAULT '',                      -- FIPS 203 / 204 / 205 / ...
  verified BOOLEAN NOT NULL DEFAULT TRUE,
  evidence TEXT NOT NULL DEFAULT '',                      -- where the algorithm was observed
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certificate_algorithms_cert ON public.certificate_algorithms(certificate_id);
CREATE INDEX IF NOT EXISTS idx_certificate_algorithms_user ON public.certificate_algorithms(user_id);

-- ----------------------------------------------------------------------------
-- certificate_signatures — digital signature record per certificate
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_signatures (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  certificate_id TEXT NOT NULL UNIQUE,
  algorithm TEXT NOT NULL DEFAULT 'ML-DSA-65',
  signature_hex TEXT NOT NULL,
  public_key_hex TEXT NOT NULL,
  key_id TEXT NOT NULL DEFAULT '',
  certificate_hash TEXT NOT NULL,
  signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  chain JSONB NOT NULL DEFAULT '[]'::JSONB,               -- issuer chain metadata
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certificate_signatures_user ON public.certificate_signatures(user_id);

-- ----------------------------------------------------------------------------
-- certificate_signing_keys — platform issuer keypair (SERVICE ROLE ONLY)
-- RLS enabled with NO policies: clients can never read the signing seed.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_signing_keys (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  key_id TEXT NOT NULL UNIQUE,
  algorithm TEXT NOT NULL DEFAULT 'ML-DSA-65',
  seed_hex TEXT NOT NULL,
  public_key_hex TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------------------
-- certificate_history — lifecycle events per certificate
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_history (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  certificate_id TEXT NOT NULL,
  event TEXT NOT NULL CHECK (event IN ('issued', 'renewed', 'revoked', 'suspended', 'reinstated', 'expired', 'superseded', 'validated', 'downloaded', 'verification_requested')),
  detail TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT 'system',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certificate_history_cert ON public.certificate_history(certificate_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_certificate_history_user ON public.certificate_history(user_id, created_at DESC);

-- ----------------------------------------------------------------------------
-- certificate_downloads — export/download audit trail
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_downloads (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  certificate_id TEXT NOT NULL,
  format TEXT NOT NULL CHECK (format IN ('pdf', 'png', 'svg', 'json', 'audit-package', 'executive-summary')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certificate_downloads_user ON public.certificate_downloads(user_id, created_at DESC);

-- ----------------------------------------------------------------------------
-- certificate_validation — every eligibility / re-validation run
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_validation (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  certificate_id TEXT,                                    -- null for pre-issuance eligibility runs
  eligible BOOLEAN NOT NULL,
  trust_score INTEGER NOT NULL DEFAULT 0,
  level TEXT,
  required_met INTEGER NOT NULL DEFAULT 0,
  required_total INTEGER NOT NULL DEFAULT 0,
  checks JSONB NOT NULL DEFAULT '[]'::JSONB,
  trigger TEXT NOT NULL DEFAULT 'manual',                 -- manual | issue | renewal | monitoring
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certificate_validation_user ON public.certificate_validation(user_id, created_at DESC);

-- ----------------------------------------------------------------------------
-- certificate_policies — configurable eligibility thresholds per tenant
-- (platform minimum floors are enforced server-side; a tenant can tighten,
-- never loosen, the published criteria)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_policies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  rules JSONB NOT NULL DEFAULT '{}'::JSONB,
  updated_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_policies_user ON public.certificate_policies(user_id);
DROP TRIGGER IF EXISTS trg_certificate_policies_updated_at ON public.certificate_policies;
CREATE TRIGGER trg_certificate_policies_updated_at
  BEFORE UPDATE ON public.certificate_policies
  FOR EACH ROW EXECUTE FUNCTION public.qguard_set_updated_at();

-- ----------------------------------------------------------------------------
-- certificate_audit — append-only audit log for every engine action
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_audit (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  certificate_id TEXT,
  action TEXT NOT NULL,                                   -- issued/renewed/revoked/suspended/reinstated/downloaded/verification_requested/policy_changed/administrator_override
  detail TEXT NOT NULL DEFAULT '',
  actor_email TEXT NOT NULL DEFAULT '',
  ip_address TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certificate_audit_user ON public.certificate_audit(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_certificate_audit_cert ON public.certificate_audit(certificate_id, created_at DESC);

-- ----------------------------------------------------------------------------
-- certificate_verification_logs — public portal lookups (service role writes)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_verification_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  certificate_id TEXT NOT NULL,
  result TEXT NOT NULL,                                   -- valid | suspended | expired | revoked | not_found | tampered
  lookup_by TEXT NOT NULL DEFAULT 'certificate_id',       -- certificate_id | company | qr
  ip_address TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certificate_verification_logs_cert ON public.certificate_verification_logs(certificate_id, created_at DESC);

-- ----------------------------------------------------------------------------
-- certificate_notifications — expiry / suspension / renewal notices
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificate_notifications (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  certificate_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('expiring_soon', 'expired', 'suspended', 'revoked', 'renewed', 'reinstated', 'drift_detected')),
  message TEXT NOT NULL,
  read BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certificate_notifications_user ON public.certificate_notifications(user_id, read, created_at DESC);

-- ============================================================================
-- Row Level Security — owner-only for tenant tables; deny-all for platform
-- tables (service role bypasses RLS). The public portal is served by the
-- Express verification endpoint with the service role, never by client RLS.
-- ============================================================================
ALTER TABLE public.quantum_trust_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_algorithms ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_signing_keys ENABLE ROW LEVEL SECURITY;  -- no policies: service role only
ALTER TABLE public.certificate_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_downloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_validation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_verification_logs ENABLE ROW LEVEL SECURITY;  -- no policies: service role only
ALTER TABLE public.certificate_notifications ENABLE ROW LEVEL SECURITY;

-- Owner-only SELECT + INSERT on every tenant table (auth-scoped engine writes
-- go through the caller's JWT client so RLS stays the enforcement point).
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'quantum_trust_certificates', 'certificate_assets', 'certificate_algorithms', 'certificate_signatures',
    'certificate_history', 'certificate_downloads', 'certificate_validation',
    'certificate_policies', 'certificate_audit', 'certificate_notifications'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I_select_own ON public.%I', t, t);
    EXECUTE format('CREATE POLICY %I_select_own ON public.%I FOR SELECT USING (auth.uid() = user_id)', t, t);
    EXECUTE format('DROP POLICY IF EXISTS %I_insert_own ON public.%I', t, t);
    EXECUTE format('CREATE POLICY %I_insert_own ON public.%I FOR INSERT WITH CHECK (auth.uid() = user_id)', t, t);
  END LOOP;
END $$;

-- Tenants may mark their own notifications read.
DROP POLICY IF EXISTS certificate_notifications_update_own ON public.certificate_notifications;
CREATE POLICY certificate_notifications_update_own ON public.certificate_notifications
  FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- Certificate lifecycle status transitions + policy edits by the owner.
DROP POLICY IF EXISTS quantum_trust_certificates_update_own ON public.quantum_trust_certificates;
CREATE POLICY quantum_trust_certificates_update_own ON public.quantum_trust_certificates
  FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS certificate_policies_update_own ON public.certificate_policies;
CREATE POLICY certificate_policies_update_own ON public.certificate_policies
  FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP TRIGGER IF EXISTS trg_qtc_certificates_updated_at ON public.quantum_trust_certificates;
CREATE TRIGGER trg_qtc_certificates_updated_at
  BEFORE UPDATE ON public.quantum_trust_certificates
  FOR EACH ROW EXECUTE FUNCTION public.qguard_set_updated_at();

-- ============================================================================
-- Realtime — certificate lifecycle events stream to the dashboard
-- (same convention as quantum-readiness-realtime.sql)
-- ============================================================================
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['quantum_trust_certificates', 'certificate_history', 'certificate_notifications'] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = t
    ) THEN
      EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', t);
    END IF;
  END LOOP;
END $$;
