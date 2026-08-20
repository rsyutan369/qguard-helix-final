-- Qguard Helix — QKMS Command Center schema extension
--
-- Additive and idempotent. Extends supabase/qkms-lifecycle-schema.sql; run that
-- first (or run this alone — every statement is guarded).
--
-- Why each change exists:
--
--  * key_ref TEXT
--      The canonical QKMS key id is a string like `key:fp:1a2b3c` or
--      `key:d:9x8y7z`, because a key must keep the same identity across
--      re-scans and across the five tables it can be discovered in. The
--      original `key_id UUID` column could only ever address rows whose id
--      happened to be a UUID, so rotation jobs and audit events raised against
--      a fingerprint- or derivation-identified key silently detached from it.
--      `key_id` is retained for existing rows; `key_ref` is what the engine
--      joins on.
--
--  * qkms_key_versions
--      Brief section 3 requires a key VERSION identity. A version row is minted
--      only when a rotation work order completes, so the chain always
--      corresponds to a governed, audited operation rather than a guess.
--
--  * validation columns on qkms_rotation_jobs
--      A completed rotation is not a validated rotation. Recording the two
--      separately is what lets the migration gate report VALIDATION_REQUIRED
--      instead of claiming MIGRATED off an unvalidated job.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

/* ------------------------------------------------------------------ */
/* qkms_keys — canonical id, version, lifecycle timestamps             */
/* ------------------------------------------------------------------ */

ALTER TABLE IF EXISTS public.qkms_keys ADD COLUMN IF NOT EXISTS key_ref TEXT;
ALTER TABLE IF EXISTS public.qkms_keys ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
ALTER TABLE IF EXISTS public.qkms_keys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
ALTER TABLE IF EXISTS public.qkms_keys ADD COLUMN IF NOT EXISTS decommissioned_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS idx_qkms_keys_tenant_key_ref
  ON public.qkms_keys(tenant_id, key_ref)
  WHERE key_ref IS NOT NULL;

/* ------------------------------------------------------------------ */
/* qkms_policies — PQC requirement rule                                */
/* ------------------------------------------------------------------ */

ALTER TABLE IF EXISTS public.qkms_policies ADD COLUMN IF NOT EXISTS require_pqc BOOLEAN DEFAULT FALSE;

/* ------------------------------------------------------------------ */
/* qkms_rotation_jobs — canonical key ref, versions, validation        */
/* ------------------------------------------------------------------ */

ALTER TABLE IF EXISTS public.qkms_rotation_jobs ADD COLUMN IF NOT EXISTS key_ref TEXT;
ALTER TABLE IF EXISTS public.qkms_rotation_jobs ADD COLUMN IF NOT EXISTS previous_version INTEGER;
ALTER TABLE IF EXISTS public.qkms_rotation_jobs ADD COLUMN IF NOT EXISTS new_version INTEGER;
ALTER TABLE IF EXISTS public.qkms_rotation_jobs ADD COLUMN IF NOT EXISTS validation_status TEXT DEFAULT 'not-started';
ALTER TABLE IF EXISTS public.qkms_rotation_jobs ADD COLUMN IF NOT EXISTS validation_detail TEXT;

CREATE INDEX IF NOT EXISTS idx_qkms_rotation_jobs_key_ref
  ON public.qkms_rotation_jobs(tenant_id, key_ref, created_at DESC);

/* ------------------------------------------------------------------ */
/* qkms_audit_events — canonical key ref                               */
/* ------------------------------------------------------------------ */

ALTER TABLE IF EXISTS public.qkms_audit_events ADD COLUMN IF NOT EXISTS key_ref TEXT;

CREATE INDEX IF NOT EXISTS idx_qkms_audit_events_key_ref
  ON public.qkms_audit_events(tenant_id, key_ref, created_at DESC);

/* ------------------------------------------------------------------ */
/* qkms_key_versions — the version chain                               */
/* ------------------------------------------------------------------ */

CREATE TABLE IF NOT EXISTS public.qkms_key_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  user_id UUID NOT NULL,
  -- Canonical QKMS key id this version belongs to.
  key_ref TEXT NOT NULL,
  version INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  algorithm TEXT,
  -- The work order that produced this version. NULL only for the version that
  -- already existed when the key was first brought under management.
  rotation_job_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  activated_at TIMESTAMPTZ,
  superseded_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (tenant_id, key_ref, version)
);

ALTER TABLE public.qkms_key_versions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS qkms_key_versions_tenant_isolation ON public.qkms_key_versions;
CREATE POLICY qkms_key_versions_tenant_isolation ON public.qkms_key_versions
  FOR ALL USING (auth.uid() = tenant_id OR auth.uid() = user_id)
  WITH CHECK (auth.uid() = tenant_id OR auth.uid() = user_id);

CREATE INDEX IF NOT EXISTS idx_qkms_key_versions_tenant
  ON public.qkms_key_versions(tenant_id, key_ref, version);

/* ------------------------------------------------------------------ */
/* Backfill key_ref for rows created before this migration             */
/* ------------------------------------------------------------------ */

-- Registry rows are identified as `key:qkms:<uuid>`, matching identityFor().
UPDATE public.qkms_keys
   SET key_ref = 'key:qkms:' || id::text
 WHERE key_ref IS NULL;

-- Historic jobs and audit events referenced a bare UUID. It cannot be resolved
-- to a canonical id in general, but where it addressed a registry row the
-- mapping is exact, so those are recoverable.
UPDATE public.qkms_rotation_jobs j
   SET key_ref = 'key:qkms:' || j.key_id::text
  FROM public.qkms_keys k
 WHERE j.key_ref IS NULL
   AND j.key_id IS NOT NULL
   AND k.id = j.key_id
   AND k.tenant_id = j.tenant_id;

UPDATE public.qkms_audit_events a
   SET key_ref = 'key:qkms:' || a.key_id::text
  FROM public.qkms_keys k
 WHERE a.key_ref IS NULL
   AND a.key_id IS NOT NULL
   AND k.id = a.key_id
   AND k.tenant_id = a.tenant_id;

/* ------------------------------------------------------------------ */
/* Realtime                                                            */
/* ------------------------------------------------------------------ */

DO $$
DECLARE
  tbl TEXT;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['qkms_key_versions']
  LOOP
    BEGIN
      EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', tbl);
    EXCEPTION
      WHEN duplicate_object THEN NULL;
      WHEN undefined_object THEN NULL;
    END;
  END LOOP;
END $$;
