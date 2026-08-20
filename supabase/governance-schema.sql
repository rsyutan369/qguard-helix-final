-- ============================================================================
-- QGuard Helix — Enterprise Governance, Compliance & Audit schema
-- Run in Supabase SQL Editor after dashboard-schema.sql.
--
-- Backs the four-page governance command layer:
--   /dashboard/compliance          /dashboard/quantum-governance
--   /dashboard/audit-vault         /dashboard/regulatory-mapping
--
-- The governance engine READS the tenant's existing evidence (assets,
-- crypto_inventory, certificates, generated_keys, runtime_crypto_events,
-- pqc_scan_*, vulnerabilities, compliance_evidence, audit_logs, vault_*).
-- These three tables hold the state that governance itself OWNS and that has
-- nowhere else to live:
--
--   governance_policies              tenant overrides of the crypto policy rules
--   governance_evidence_anchors      SHA3-256 content digests → tamper-evidence
--   governance_control_assessments   control ownership, exceptions, attestations
--
-- The API degrades gracefully when this script has not been applied: policy
-- rules fall back to platform defaults, evidence integrity reports
-- "unavailable" rather than a false "verified", and the exception control
-- reports "not assessed". Nothing is fabricated in the absence of these tables.
--
-- Every table is tenant-scoped by user_id with owner-only RLS.
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
-- governance_policies — tenant overrides for the cryptographic policy rules.
--
-- The platform ships a baseline rule set in code (src/lib/governance/policy.ts).
-- A row here overrides ONE rule for ONE tenant: its enforcement mode, its
-- severity, and any of its parameters (key-size floors, TLS minimum, renewal
-- window, risk ceiling…). Absent rows mean "use the platform default", so a new
-- tenant needs no seeding and a new rule needs no backfill.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.governance_policies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  policy_id TEXT NOT NULL,                                       -- e.g. POL-ALG-FORBIDDEN
  enforcement TEXT NOT NULL DEFAULT 'enforced'
    CHECK (enforcement IN ('enforced', 'monitored', 'disabled')),
  severity TEXT NOT NULL DEFAULT 'medium'
    CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  -- Parameter overrides keyed by the rule's parameter key. Only keys the rule
  -- declares are honoured; unknown keys are ignored by the evaluator.
  parameters JSONB NOT NULL DEFAULT '{}'::JSONB,
  note TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, policy_id)
);

ALTER TABLE public.governance_policies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS governance_policies_owner ON public.governance_policies;
CREATE POLICY governance_policies_owner ON public.governance_policies
  FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_gov_policies_user ON public.governance_policies(user_id);

DROP TRIGGER IF EXISTS trg_gov_policies_updated ON public.governance_policies;
CREATE TRIGGER trg_gov_policies_updated
  BEFORE UPDATE ON public.governance_policies
  FOR EACH ROW EXECUTE FUNCTION public.qguard_set_updated_at();

-- ----------------------------------------------------------------------------
-- governance_evidence_anchors — tamper-evidence for governance evidence.
--
-- One row per evidence record, holding the SHA3-256 digest of that record's
-- canonical content at the moment it was first anchored. On every read the
-- engine recomputes the digest; a difference proves the source row changed
-- after anchoring.
--
-- WHAT THIS IS NOT: this does not make the source row immutable, and it is not
-- a third-party notarisation — the anchor lives in the same database. The UI
-- must therefore say "tamper-evident", never "immutable". `digest` is
-- deliberately NOT updatable by the application: re-anchoring a changed record
-- is an explicit re-anchor action that writes `reanchored_at` and keeps the
-- original digest in `first_digest`, so the change remains visible.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.governance_evidence_anchors (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL,                                     -- e.g. attestation:<uuid>
  evidence_kind TEXT NOT NULL DEFAULT '',
  source_table TEXT NOT NULL DEFAULT '',
  source_record_id TEXT NOT NULL DEFAULT '',
  algorithm TEXT NOT NULL DEFAULT 'SHA3-256',
  digest TEXT NOT NULL,                                          -- current anchored digest (hex)
  first_digest TEXT NOT NULL DEFAULT '',                         -- digest at first anchor; never overwritten
  anchored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reanchored_at TIMESTAMPTZ,
  reanchor_count INTEGER NOT NULL DEFAULT 0,
  anchored_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, evidence_id)
);

ALTER TABLE public.governance_evidence_anchors ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS governance_anchors_owner ON public.governance_evidence_anchors;
CREATE POLICY governance_anchors_owner ON public.governance_evidence_anchors
  FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_gov_anchors_user ON public.governance_evidence_anchors(user_id);
CREATE INDEX IF NOT EXISTS idx_gov_anchors_evidence ON public.governance_evidence_anchors(user_id, evidence_id);
CREATE INDEX IF NOT EXISTS idx_gov_anchors_anchored ON public.governance_evidence_anchors(user_id, anchored_at DESC);

-- Preserve the ORIGINAL digest across re-anchors so a change is never erased.
CREATE OR REPLACE FUNCTION public.governance_anchor_guard()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.first_digest IS NULL OR NEW.first_digest = '' THEN
      NEW.first_digest := NEW.digest;
    END IF;
    RETURN NEW;
  END IF;

  -- The first anchored digest is immutable at the database level.
  NEW.first_digest := OLD.first_digest;
  NEW.anchored_at := OLD.anchored_at;
  IF NEW.digest IS DISTINCT FROM OLD.digest THEN
    NEW.reanchored_at := NOW();
    NEW.reanchor_count := OLD.reanchor_count + 1;
  END IF;
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_gov_anchor_guard ON public.governance_evidence_anchors;
CREATE TRIGGER trg_gov_anchor_guard
  BEFORE INSERT OR UPDATE ON public.governance_evidence_anchors
  FOR EACH ROW EXECUTE FUNCTION public.governance_anchor_guard();

-- ----------------------------------------------------------------------------
-- governance_control_assessments — control ownership and exceptions.
--
-- A row exists only for controls the tenant has actively governed: assigned an
-- owner, recorded an exception, or attested a manual review. Controls with no
-- row are evaluated purely from evidence, which is the default.
--
-- An exception scopes a control OUT of the compliance score. That is a
-- deliberate governance act, so it must carry an approver and an expiry — and
-- CTL-GOV-02 audits exactly that, which is why scoping something out is never
-- free.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.governance_control_assessments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  control_id TEXT NOT NULL,                                      -- e.g. CTL-ALG-01
  owner TEXT NOT NULL DEFAULT '',
  owner_email TEXT NOT NULL DEFAULT '',
  review_note TEXT NOT NULL DEFAULT '',
  attested_at TIMESTAMPTZ,
  attested_by TEXT NOT NULL DEFAULT '',
  exception_reason TEXT NOT NULL DEFAULT '',
  exception_approved_by TEXT NOT NULL DEFAULT '',
  exception_approved_at TIMESTAMPTZ,
  exception_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, control_id)
);

ALTER TABLE public.governance_control_assessments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS governance_assessments_owner ON public.governance_control_assessments;
CREATE POLICY governance_assessments_owner ON public.governance_control_assessments
  FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_gov_assessments_user ON public.governance_control_assessments(user_id);
CREATE INDEX IF NOT EXISTS idx_gov_assessments_control ON public.governance_control_assessments(user_id, control_id);

DROP TRIGGER IF EXISTS trg_gov_assessments_updated ON public.governance_control_assessments;
CREATE TRIGGER trg_gov_assessments_updated
  BEFORE UPDATE ON public.governance_control_assessments
  FOR EACH ROW EXECUTE FUNCTION public.qguard_set_updated_at();

-- ----------------------------------------------------------------------------
-- Realtime — so the governance dashboards refresh on the tenant's own writes
-- without waiting for the next SSE push.
-- ----------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    BEGIN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.governance_policies;
    EXCEPTION WHEN duplicate_object THEN NULL;
    END;
    BEGIN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.governance_evidence_anchors;
    EXCEPTION WHEN duplicate_object THEN NULL;
    END;
    BEGIN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.governance_control_assessments;
    EXCEPTION WHEN duplicate_object THEN NULL;
    END;
  END IF;
END $$;

-- ============================================================================
-- Verification
-- ============================================================================
-- SELECT table_name FROM information_schema.tables
--  WHERE table_schema = 'public' AND table_name LIKE 'governance_%';
