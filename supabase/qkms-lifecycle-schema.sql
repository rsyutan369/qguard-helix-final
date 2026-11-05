-- Qguard Helix QKMS - Quantum-Safe Key Lifecycle Manager
-- Adds tenant-scoped lifecycle tables used by src/api-server/qkms-dashboard.ts.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.qkms_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  user_id UUID NOT NULL,
  key_alias TEXT NOT NULL,
  key_type TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  purpose TEXT,
  owner_id TEXT,
  asset_id UUID,
  certificate_id UUID,
  storage_backend TEXT DEFAULT 'Local encrypted software vault',
  storage_reference TEXT,
  environment TEXT DEFAULT 'unknown',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  last_rotated_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  rotation_interval_days INTEGER DEFAULT 180,
  status TEXT DEFAULT 'active',
  pqc_readiness TEXT DEFAULT 'Unknown',
  risk_score INTEGER DEFAULT 0,
  compliance_status TEXT DEFAULT 'Evidence needed',
  exportable BOOLEAN DEFAULT FALSE,
  hsm_backed BOOLEAN DEFAULT FALSE,
  entropy_source TEXT DEFAULT 'OS CSPRNG',
  metadata_json JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS public.qkms_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  user_id UUID NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  allowed_algorithms TEXT[] DEFAULT ARRAY[]::TEXT[],
  blocked_algorithms TEXT[] DEFAULT ARRAY[]::TEXT[],
  max_key_age_days INTEGER DEFAULT 365,
  rotation_interval_days INTEGER DEFAULT 180,
  require_owner BOOLEAN DEFAULT TRUE,
  require_hsm BOOLEAN DEFAULT FALSE,
  allow_export BOOLEAN DEFAULT FALSE,
  environment_scope TEXT DEFAULT 'all',
  severity TEXT DEFAULT 'medium',
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.qkms_rotation_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  user_id UUID NOT NULL,
  key_id UUID,
  status TEXT DEFAULT 'pending',
  reason TEXT,
  requested_by TEXT,
  approved_by TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  failure_reason TEXT,
  evidence_json JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS public.qkms_audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  user_id UUID NOT NULL,
  key_id UUID,
  event_type TEXT NOT NULL,
  actor_id TEXT,
  event_summary TEXT,
  before_json JSONB,
  after_json JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.qkms_storage_backends (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  user_id UUID NOT NULL,
  provider TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT DEFAULT 'tenant default',
  protection_level TEXT DEFAULT 'software custody',
  hsm_backed BOOLEAN DEFAULT FALSE,
  status TEXT DEFAULT 'configured',
  last_verified_at TIMESTAMPTZ,
  config_reference TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.qkms_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qkms_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qkms_rotation_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qkms_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qkms_storage_backends ENABLE ROW LEVEL SECURITY;

-- Tenant isolation. The predicate is the TENANT, not "tenant OR user": the
-- disjunction let a signed-in user insert a row carrying another tenant's
-- tenant_id under their own user_id, planting it in that tenant's view.
-- Writes must name the caller as both tenant and user.
DROP POLICY IF EXISTS qkms_keys_tenant_isolation ON public.qkms_keys;
CREATE POLICY qkms_keys_tenant_isolation ON public.qkms_keys
  FOR ALL TO authenticated USING (auth.uid() = tenant_id)
  WITH CHECK (auth.uid() = tenant_id AND auth.uid() = user_id);

DROP POLICY IF EXISTS qkms_policies_tenant_isolation ON public.qkms_policies;
CREATE POLICY qkms_policies_tenant_isolation ON public.qkms_policies
  FOR ALL TO authenticated USING (auth.uid() = tenant_id)
  WITH CHECK (auth.uid() = tenant_id AND auth.uid() = user_id);

DROP POLICY IF EXISTS qkms_rotation_jobs_tenant_isolation ON public.qkms_rotation_jobs;
CREATE POLICY qkms_rotation_jobs_tenant_isolation ON public.qkms_rotation_jobs
  FOR ALL TO authenticated USING (auth.uid() = tenant_id)
  WITH CHECK (auth.uid() = tenant_id AND auth.uid() = user_id);

-- The audit trail is append-only for clients: tenants read and insert their own
-- records but can neither edit nor delete them. Retention runs as service role.
DROP POLICY IF EXISTS qkms_audit_events_tenant_isolation ON public.qkms_audit_events;
DROP POLICY IF EXISTS qkms_audit_events_tenant_read ON public.qkms_audit_events;
CREATE POLICY qkms_audit_events_tenant_read ON public.qkms_audit_events
  FOR SELECT TO authenticated USING (auth.uid() = tenant_id);
DROP POLICY IF EXISTS qkms_audit_events_tenant_append ON public.qkms_audit_events;
CREATE POLICY qkms_audit_events_tenant_append ON public.qkms_audit_events
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = tenant_id AND auth.uid() = user_id);

DROP POLICY IF EXISTS qkms_storage_backends_tenant_isolation ON public.qkms_storage_backends;
CREATE POLICY qkms_storage_backends_tenant_isolation ON public.qkms_storage_backends
  FOR ALL TO authenticated USING (auth.uid() = tenant_id)
  WITH CHECK (auth.uid() = tenant_id AND auth.uid() = user_id);

CREATE INDEX IF NOT EXISTS idx_qkms_keys_tenant ON public.qkms_keys(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_qkms_keys_asset ON public.qkms_keys(asset_id);
CREATE INDEX IF NOT EXISTS idx_qkms_keys_algorithm ON public.qkms_keys(algorithm);
CREATE INDEX IF NOT EXISTS idx_qkms_policies_tenant ON public.qkms_policies(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_qkms_rotation_jobs_tenant ON public.qkms_rotation_jobs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_qkms_audit_events_tenant ON public.qkms_audit_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_qkms_storage_backends_tenant ON public.qkms_storage_backends(tenant_id, updated_at DESC);

DO $$
DECLARE
  tbl TEXT;
BEGIN
  FOREACH tbl IN ARRAY ARRAY[
    'qkms_keys',
    'qkms_policies',
    'qkms_rotation_jobs',
    'qkms_audit_events',
    'qkms_storage_backends'
  ]
  LOOP
    BEGIN
      EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', tbl);
    EXCEPTION
      WHEN duplicate_object THEN NULL;
      WHEN undefined_object THEN NULL;
    END;
  END LOOP;
END $$;
