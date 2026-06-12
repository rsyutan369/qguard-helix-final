-- QGuardHelix Owner Administrator Dashboard
-- Apply after the base profile, billing, and dashboard schemas.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION public.qguard_is_owner()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT LOWER(COALESCE(auth.email(), '')) = 'zachmatthew369@gmail.com';
$$;

CREATE OR REPLACE FUNCTION public.qguard_touch_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TABLE IF NOT EXISTS public.organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT UNIQUE,
  owner_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'active',
  plan TEXT NOT NULL DEFAULT 'free',
  quota_users INTEGER NOT NULL DEFAULT 5,
  quota_storage_gb NUMERIC NOT NULL DEFAULT 5,
  readiness_score INTEGER NOT NULL DEFAULT 0 CHECK (readiness_score BETWEEN 0 AND 100),
  security_score INTEGER NOT NULL DEFAULT 0 CHECK (security_score BETWEEN 0 AND 100),
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.organizations
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS name TEXT,
  ADD COLUMN IF NOT EXISTS slug TEXT,
  ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'free',
  ADD COLUMN IF NOT EXISTS quota_users INTEGER NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS quota_storage_gb NUMERIC NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS readiness_score INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS security_score INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_organizations_status ON public.organizations(status);
CREATE INDEX IF NOT EXISTS idx_organizations_owner ON public.organizations(owner_user_id);

DROP TRIGGER IF EXISTS trg_organizations_updated_at ON public.organizations;
CREATE TRIGGER trg_organizations_updated_at
  BEFORE UPDATE ON public.organizations
  FOR EACH ROW EXECUTE FUNCTION public.qguard_touch_updated_at();

CREATE TABLE IF NOT EXISTS public.organization_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member',
  status TEXT NOT NULL DEFAULT 'active',
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, user_id)
);

ALTER TABLE public.organization_members
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'member',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_organization_members_org ON public.organization_members(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_organization_members_user ON public.organization_members(user_id);

DROP TRIGGER IF EXISTS trg_organization_members_updated_at ON public.organization_members;
CREATE TRIGGER trg_organization_members_updated_at
  BEFORE UPDATE ON public.organization_members
  FOR EACH ROW EXECUTE FUNCTION public.qguard_touch_updated_at();

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS account_status TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS permissions TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN IF NOT EXISTS last_admin_action_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_profiles_tenant ON public.profiles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_profiles_account_status ON public.profiles(account_status);
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);

CREATE TABLE IF NOT EXISTS public.user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  session_id TEXT,
  ip_address INET,
  user_agent TEXT,
  device_fingerprint TEXT,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  revoked_reason TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.user_sessions
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS session_id TEXT,
  ADD COLUMN IF NOT EXISTS ip_address INET,
  ADD COLUMN IF NOT EXISTS user_agent TEXT,
  ADD COLUMN IF NOT EXISTS device_fingerprint TEXT,
  ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS revoked_reason TEXT,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_user_sessions_admin_user_seen ON public.user_sessions(user_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_sessions_admin_active ON public.user_sessions(user_id, revoked_at);

CREATE TABLE IF NOT EXISTS public.user_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  device_name TEXT,
  device_fingerprint TEXT,
  platform TEXT,
  browser TEXT,
  ip_address INET,
  trusted BOOLEAN NOT NULL DEFAULT FALSE,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.user_devices
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS device_name TEXT,
  ADD COLUMN IF NOT EXISTS device_fingerprint TEXT,
  ADD COLUMN IF NOT EXISTS platform TEXT,
  ADD COLUMN IF NOT EXISTS browser TEXT,
  ADD COLUMN IF NOT EXISTS ip_address INET,
  ADD COLUMN IF NOT EXISTS trusted BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_user_devices_admin_user_seen ON public.user_devices(user_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_devices_admin_trusted ON public.user_devices(user_id, trusted, revoked_at);

CREATE TABLE IF NOT EXISTS public.admin_session_revocations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  revoked_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  reason TEXT NOT NULL DEFAULT 'admin_force_logout',
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.admin_session_revocations
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS revoked_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT 'admin_force_logout',
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_admin_session_revocations_user ON public.admin_session_revocations(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.admin_audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  actor_email TEXT,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  details JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.admin_audit_events
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS actor_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS actor_email TEXT,
  ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'admin_event',
  ADD COLUMN IF NOT EXISTS entity_type TEXT NOT NULL DEFAULT 'platform',
  ADD COLUMN IF NOT EXISTS entity_id TEXT,
  ADD COLUMN IF NOT EXISTS ip_address TEXT,
  ADD COLUMN IF NOT EXISTS user_agent TEXT,
  ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_admin_audit_events_actor ON public.admin_audit_events(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_events_entity ON public.admin_audit_events(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_events_action ON public.admin_audit_events(action, created_at DESC);

CREATE TABLE IF NOT EXISTS public.admin_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT,
  role_type TEXT NOT NULL DEFAULT 'custom',
  status TEXT NOT NULL DEFAULT 'active',
  tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  permission_scope TEXT NOT NULL DEFAULT 'Custom',
  permission_count INTEGER NOT NULL DEFAULT 0,
  permissions TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.admin_roles
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS role_key TEXT,
  ADD COLUMN IF NOT EXISTS name TEXT,
  ADD COLUMN IF NOT EXISTS description TEXT,
  ADD COLUMN IF NOT EXISTS role_type TEXT NOT NULL DEFAULT 'custom',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS permission_scope TEXT NOT NULL DEFAULT 'Custom',
  ADD COLUMN IF NOT EXISTS permission_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS permissions TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_roles_role_key ON public.admin_roles(role_key);
CREATE INDEX IF NOT EXISTS idx_admin_roles_type_status ON public.admin_roles(role_type, status);
CREATE INDEX IF NOT EXISTS idx_admin_roles_tenant ON public.admin_roles(tenant_id, status);

DROP TRIGGER IF EXISTS trg_admin_roles_updated_at ON public.admin_roles;
CREATE TRIGGER trg_admin_roles_updated_at
  BEFORE UPDATE ON public.admin_roles
  FOR EACH ROW EXECUTE FUNCTION public.qguard_touch_updated_at();

CREATE TABLE IF NOT EXISTS public.admin_governance_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'access',
  status TEXT NOT NULL DEFAULT 'enabled',
  enforcement_level TEXT NOT NULL DEFAULT 'monitor',
  description TEXT,
  config JSONB NOT NULL DEFAULT '{}'::JSONB,
  updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.admin_governance_policies
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS policy_key TEXT,
  ADD COLUMN IF NOT EXISTS name TEXT,
  ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'access',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'enabled',
  ADD COLUMN IF NOT EXISTS enforcement_level TEXT NOT NULL DEFAULT 'monitor',
  ADD COLUMN IF NOT EXISTS description TEXT,
  ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_admin_governance_policies_category ON public.admin_governance_policies(category, status);

DROP TRIGGER IF EXISTS trg_admin_governance_policies_updated_at ON public.admin_governance_policies;
CREATE TRIGGER trg_admin_governance_policies_updated_at
  BEFORE UPDATE ON public.admin_governance_policies
  FOR EACH ROW EXECUTE FUNCTION public.qguard_touch_updated_at();

CREATE TABLE IF NOT EXISTS public.admin_compliance_evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  framework TEXT NOT NULL DEFAULT 'QGuardHelix Governance',
  evidence_type TEXT NOT NULL DEFAULT 'admin_snapshot',
  status TEXT NOT NULL DEFAULT 'generated',
  generated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.admin_compliance_evidence
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS title TEXT,
  ADD COLUMN IF NOT EXISTS framework TEXT NOT NULL DEFAULT 'QGuardHelix Governance',
  ADD COLUMN IF NOT EXISTS evidence_type TEXT NOT NULL DEFAULT 'admin_snapshot',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'generated',
  ADD COLUMN IF NOT EXISTS generated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_admin_compliance_evidence_framework ON public.admin_compliance_evidence(framework, created_at DESC);

CREATE TABLE IF NOT EXISTS public.billing_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  plan TEXT NOT NULL DEFAULT 'free',
  status TEXT NOT NULL DEFAULT 'inactive',
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.billing_subscriptions
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'free',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'inactive',
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS billing_cycle TEXT NOT NULL DEFAULT 'monthly',
  ADD COLUMN IF NOT EXISTS plan_interval TEXT,
  ADD COLUMN IF NOT EXISTS seats INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'not_required',
  ADD COLUMN IF NOT EXISTS current_period_end TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS canceled_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS subscription_id TEXT,
  ADD COLUMN IF NOT EXISTS provider TEXT,
  ADD COLUMN IF NOT EXISTS provider_customer_id TEXT,
  ADD COLUMN IF NOT EXISTS provider_subscription_id TEXT,
  ADD COLUMN IF NOT EXISTS auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS renewal_date TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS trial_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS account_created_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS current_period_start TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS amount_cents BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS currency TEXT NOT NULL DEFAULT 'USD';

CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_admin_tenant ON public.billing_subscriptions(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_admin_expiry ON public.billing_subscriptions(current_period_end);
CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_subscriptions_user_unique ON public.billing_subscriptions(user_id);

CREATE TABLE IF NOT EXISTS public.billing_payment_methods (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'tokenized',
  provider_payment_method_id TEXT,
  brand TEXT NOT NULL DEFAULT 'Card',
  last4 TEXT NOT NULL DEFAULT '',
  exp_month INTEGER,
  exp_year INTEGER,
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  billing_name TEXT,
  billing_address JSONB NOT NULL DEFAULT '{}'::JSONB,
  country TEXT,
  tax_region TEXT,
  last_used_at TIMESTAMPTZ,
  removed_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.billing_payment_methods
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'tokenized',
  ADD COLUMN IF NOT EXISTS provider_payment_method_id TEXT,
  ADD COLUMN IF NOT EXISTS brand TEXT NOT NULL DEFAULT 'Card',
  ADD COLUMN IF NOT EXISTS last4 TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS exp_month INTEGER,
  ADD COLUMN IF NOT EXISTS exp_year INTEGER,
  ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS billing_name TEXT,
  ADD COLUMN IF NOT EXISTS billing_address JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS country TEXT,
  ADD COLUMN IF NOT EXISTS tax_region TEXT,
  ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_payment_methods_provider_id
  ON public.billing_payment_methods(provider_payment_method_id)
  WHERE provider_payment_method_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_billing_payment_methods_admin_user
  ON public.billing_payment_methods(user_id, is_default DESC, updated_at DESC)
  WHERE removed_at IS NULL;

DROP TRIGGER IF EXISTS trg_billing_payment_methods_updated_at ON public.billing_payment_methods;
CREATE TRIGGER trg_billing_payment_methods_updated_at
  BEFORE UPDATE ON public.billing_payment_methods
  FOR EACH ROW EXECUTE FUNCTION public.qguard_touch_updated_at();

CREATE TABLE IF NOT EXISTS public.billing_invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  currency TEXT NOT NULL DEFAULT 'usd',
  amount_due BIGINT NOT NULL DEFAULT 0,
  amount_paid BIGINT NOT NULL DEFAULT 0,
  total BIGINT NOT NULL DEFAULT 0,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.billing_invoices
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'draft',
  ADD COLUMN IF NOT EXISTS currency TEXT NOT NULL DEFAULT 'usd',
  ADD COLUMN IF NOT EXISTS amount_due BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS amount_paid BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS total BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_billing_invoices_admin_user ON public.billing_invoices(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_invoices_admin_tenant ON public.billing_invoices(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.billing_usage_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  metric_key TEXT NOT NULL,
  quantity NUMERIC NOT NULL DEFAULT 0,
  source TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.billing_usage_events
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS metric_key TEXT NOT NULL DEFAULT 'usage',
  ADD COLUMN IF NOT EXISTS quantity NUMERIC NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS source TEXT,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_billing_usage_events_admin_tenant ON public.billing_usage_events(tenant_id, metric_key, created_at DESC);

CREATE TABLE IF NOT EXISTS public.collector_agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  name TEXT NOT NULL DEFAULT 'Collector Agent',
  agent_type TEXT NOT NULL DEFAULT 'data_collector',
  status TEXT NOT NULL DEFAULT 'pending',
  version TEXT,
  region TEXT,
  hostname TEXT,
  ip_address INET,
  health_score INTEGER NOT NULL DEFAULT 100,
  last_seen_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.collector_agents
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT 'Collector Agent',
  ADD COLUMN IF NOT EXISTS agent_type TEXT NOT NULL DEFAULT 'data_collector',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS version TEXT,
  ADD COLUMN IF NOT EXISTS region TEXT,
  ADD COLUMN IF NOT EXISTS hostname TEXT,
  ADD COLUMN IF NOT EXISTS ip_address INET,
  ADD COLUMN IF NOT EXISTS health_score INTEGER NOT NULL DEFAULT 100,
  ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_collector_agents_admin_tenant ON public.collector_agents(tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_collector_agents_admin_last_seen ON public.collector_agents(last_seen_at DESC);

DROP TRIGGER IF EXISTS trg_collector_agents_updated_at ON public.collector_agents;
CREATE TRIGGER trg_collector_agents_updated_at
  BEFORE UPDATE ON public.collector_agents
  FOR EACH ROW EXECUTE FUNCTION public.qguard_touch_updated_at();

CREATE TABLE IF NOT EXISTS public.service_integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  name TEXT NOT NULL DEFAULT 'Service Integration',
  provider TEXT NOT NULL DEFAULT 'custom',
  integration_type TEXT NOT NULL DEFAULT 'security',
  status TEXT NOT NULL DEFAULT 'pending',
  region TEXT,
  last_sync_at TIMESTAMPTZ,
  health_score INTEGER NOT NULL DEFAULT 100,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.service_integrations
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT 'Service Integration',
  ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'custom',
  ADD COLUMN IF NOT EXISTS integration_type TEXT NOT NULL DEFAULT 'security',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS region TEXT,
  ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS health_score INTEGER NOT NULL DEFAULT 100,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_service_integrations_admin_tenant ON public.service_integrations(tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_integrations_admin_provider ON public.service_integrations(provider, integration_type);

DROP TRIGGER IF EXISTS trg_service_integrations_updated_at ON public.service_integrations;
CREATE TRIGGER trg_service_integrations_updated_at
  BEFORE UPDATE ON public.service_integrations
  FOR EACH ROW EXECUTE FUNCTION public.qguard_touch_updated_at();

CREATE TABLE IF NOT EXISTS public.sensor_nodes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  name TEXT NOT NULL DEFAULT 'Sensor Node',
  sensor_type TEXT NOT NULL DEFAULT 'security_sensor',
  status TEXT NOT NULL DEFAULT 'pending',
  region TEXT,
  hostname TEXT,
  ip_address INET,
  health_score INTEGER NOT NULL DEFAULT 100,
  last_seen_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.sensor_nodes
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT 'Sensor Node',
  ADD COLUMN IF NOT EXISTS sensor_type TEXT NOT NULL DEFAULT 'security_sensor',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS region TEXT,
  ADD COLUMN IF NOT EXISTS hostname TEXT,
  ADD COLUMN IF NOT EXISTS ip_address INET,
  ADD COLUMN IF NOT EXISTS health_score INTEGER NOT NULL DEFAULT 100,
  ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_sensor_nodes_admin_tenant ON public.sensor_nodes(tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_sensor_nodes_admin_last_seen ON public.sensor_nodes(last_seen_at DESC);

DROP TRIGGER IF EXISTS trg_sensor_nodes_updated_at ON public.sensor_nodes;
CREATE TRIGGER trg_sensor_nodes_updated_at
  BEFORE UPDATE ON public.sensor_nodes
  FOR EACH ROW EXECUTE FUNCTION public.qguard_touch_updated_at();

CREATE TABLE IF NOT EXISTS public.admin_platform_settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  setting_key TEXT NOT NULL UNIQUE,
  setting_value JSONB NOT NULL DEFAULT '{}'::JSONB,
  updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.admin_platform_settings
  ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS setting_key TEXT,
  ADD COLUMN IF NOT EXISTS setting_value JSONB NOT NULL DEFAULT '{}'::JSONB,
  ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

DROP TRIGGER IF EXISTS trg_admin_platform_settings_updated_at ON public.admin_platform_settings;
CREATE TRIGGER trg_admin_platform_settings_updated_at
  BEFORE UPDATE ON public.admin_platform_settings
  FOR EACH ROW EXECUTE FUNCTION public.qguard_touch_updated_at();

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_session_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_governance_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_compliance_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_platform_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.billing_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.billing_payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.billing_invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.billing_usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.collector_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.service_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sensor_nodes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS organizations_owner_admin_all ON public.organizations;
CREATE POLICY organizations_owner_admin_all ON public.organizations
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS organization_members_owner_admin_all ON public.organization_members;
CREATE POLICY organization_members_owner_admin_all ON public.organization_members
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS admin_session_revocations_owner_all ON public.admin_session_revocations;
CREATE POLICY admin_session_revocations_owner_all ON public.admin_session_revocations
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS user_sessions_owner_admin_all ON public.user_sessions;
CREATE POLICY user_sessions_owner_admin_all ON public.user_sessions
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS user_devices_owner_admin_all ON public.user_devices;
CREATE POLICY user_devices_owner_admin_all ON public.user_devices
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS admin_audit_events_owner_all ON public.admin_audit_events;
CREATE POLICY admin_audit_events_owner_all ON public.admin_audit_events
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS admin_roles_owner_all ON public.admin_roles;
CREATE POLICY admin_roles_owner_all ON public.admin_roles
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS admin_governance_policies_owner_all ON public.admin_governance_policies;
CREATE POLICY admin_governance_policies_owner_all ON public.admin_governance_policies
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS admin_compliance_evidence_owner_all ON public.admin_compliance_evidence;
CREATE POLICY admin_compliance_evidence_owner_all ON public.admin_compliance_evidence
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS admin_platform_settings_owner_all ON public.admin_platform_settings;
CREATE POLICY admin_platform_settings_owner_all ON public.admin_platform_settings
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS profiles_owner_admin_all ON public.profiles;
CREATE POLICY profiles_owner_admin_all ON public.profiles
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS billing_subscriptions_owner_admin_all ON public.billing_subscriptions;
CREATE POLICY billing_subscriptions_owner_admin_all ON public.billing_subscriptions
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS billing_payment_methods_owner_admin_all ON public.billing_payment_methods;
CREATE POLICY billing_payment_methods_owner_admin_all ON public.billing_payment_methods
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS billing_invoices_owner_admin_all ON public.billing_invoices;
CREATE POLICY billing_invoices_owner_admin_all ON public.billing_invoices
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS billing_usage_events_owner_admin_all ON public.billing_usage_events;
CREATE POLICY billing_usage_events_owner_admin_all ON public.billing_usage_events
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS collector_agents_owner_admin_all ON public.collector_agents;
CREATE POLICY collector_agents_owner_admin_all ON public.collector_agents
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS service_integrations_owner_admin_all ON public.service_integrations;
CREATE POLICY service_integrations_owner_admin_all ON public.service_integrations
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

DROP POLICY IF EXISTS sensor_nodes_owner_admin_all ON public.sensor_nodes;
CREATE POLICY sensor_nodes_owner_admin_all ON public.sensor_nodes
  FOR ALL USING (public.qguard_is_owner()) WITH CHECK (public.qguard_is_owner());

INSERT INTO public.admin_governance_policies (policy_key, name, category, status, enforcement_level, description, config)
VALUES
  ('owner-only-admin-dashboard', 'Owner-only administrator dashboard', 'access', 'enabled', 'enforce', 'Only the verified QGuardHelix owner can access platform administration APIs and UI.', '{"ownerEmail":"zachmatthew369@gmail.com"}'::JSONB),
  ('privileged-mfa-required', 'Privileged MFA requirement', 'access', 'enabled', 'enforce', 'Require MFA for privileged or tenant-administrator accounts.', '{}'::JSONB),
  ('admin-audit-retention', 'Administrator audit retention', 'retention', 'enabled', 'monitor', 'Retain owner action trails and governance evidence for compliance review.', '{"retentionDays":365}'::JSONB)
ON CONFLICT (policy_key) DO UPDATE SET
  name = EXCLUDED.name,
  category = EXCLUDED.category,
  status = EXCLUDED.status,
  enforcement_level = EXCLUDED.enforcement_level,
  description = EXCLUDED.description,
  config = EXCLUDED.config,
  updated_at = NOW();

INSERT INTO public.admin_roles (role_key, name, description, role_type, status, permission_scope, permission_count, permissions, metadata)
VALUES
  ('super_admin', 'Super Admin', 'Full access to all platform features, settings, and administrative functions.', 'system', 'active', 'All', 256, ARRAY['*'], '{"icon":"crown","protected":true}'::JSONB),
  ('security_admin', 'Security Admin', 'Manage security configurations, policies, threat response, and audit logs.', 'system', 'active', 'Security', 128, ARRAY['security.*','audit.*','policies.*'], '{"icon":"shield","protected":true}'::JSONB),
  ('tenant_admin', 'Tenant Admin', 'Manage tenant settings, users, roles, and subscriptions.', 'system', 'active', 'Tenant', 96, ARRAY['tenant.*','users.manage','subscriptions.manage'], '{"icon":"tenant","protected":true}'::JSONB),
  ('security_analyst', 'Security Analyst', 'Monitor threats, investigate alerts, and generate security reports.', 'custom', 'active', 'Security', 64, ARRAY['security.read','alerts.manage','reports.generate'], '{"icon":"analysis"}'::JSONB),
  ('compliance_officer', 'Compliance Officer', 'Manage compliance frameworks, audit tasks, and regulatory reports.', 'custom', 'active', 'Compliance', 48, ARRAY['compliance.*','audit.read','evidence.generate'], '{"icon":"compliance"}'::JSONB),
  ('readonly_auditor', 'Read Only Auditor', 'Read-only access for audits', 'custom', 'inactive', 'Read Only', 24, ARRAY['*.read','audit.read','reports.read'], '{"icon":"lock"}'::JSONB),
  ('incident_responder', 'Incident Responder', 'Respond to incidents, manage cases, and coordinate remediation.', 'custom', 'active', 'Security', 72, ARRAY['incidents.*','security.read','remediation.manage'], '{"icon":"incident"}'::JSONB)
ON CONFLICT (role_key) DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  role_type = EXCLUDED.role_type,
  status = EXCLUDED.status,
  permission_scope = EXCLUDED.permission_scope,
  permission_count = EXCLUDED.permission_count,
  permissions = EXCLUDED.permissions,
  metadata = public.admin_roles.metadata || EXCLUDED.metadata,
  updated_at = NOW();

DO $$
DECLARE
  tbl TEXT;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    FOREACH tbl IN ARRAY ARRAY[
      'organizations',
      'organization_members',
      'admin_audit_events',
      'admin_roles',
      'admin_governance_policies',
      'admin_compliance_evidence',
      'admin_session_revocations',
      'billing_subscriptions',
      'billing_payment_methods',
      'billing_invoices',
      'billing_usage_events',
      'collector_agents',
      'service_integrations',
      'sensor_nodes',
      'user_sessions',
      'user_devices'
    ] LOOP
      IF NOT EXISTS (
        SELECT 1
        FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime'
          AND schemaname = 'public'
          AND tablename = tbl
      ) THEN
        EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', tbl);
      END IF;
    END LOOP;
  END IF;
END $$;
