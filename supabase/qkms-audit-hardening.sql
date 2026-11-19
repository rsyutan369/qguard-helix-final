-- Apply after qkms-lifecycle-schema.sql and qkms-command-center-schema.sql.
-- Existing duplicate open orders must be reconciled by an operator first.
-- This migration does not edit key material or rewrite historical evidence.
BEGIN;

DO $$
DECLARE
  tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['qkms_keys','qkms_policies','qkms_rotation_jobs','qkms_storage_backends','qkms_key_versions']
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', tbl || '_tenant_isolation', tbl);
    EXECUTE format(
      'CREATE POLICY %I ON public.%I FOR ALL TO authenticated USING (auth.uid() = tenant_id AND auth.uid() = user_id) WITH CHECK (auth.uid() = tenant_id AND auth.uid() = user_id)',
      tbl || '_tenant_isolation', tbl
    );
  END LOOP;
END $$;

DROP POLICY IF EXISTS qkms_audit_events_tenant_isolation ON public.qkms_audit_events;
DROP POLICY IF EXISTS qkms_audit_events_tenant_read ON public.qkms_audit_events;
CREATE POLICY qkms_audit_events_tenant_read ON public.qkms_audit_events
  FOR SELECT TO authenticated USING (auth.uid() = tenant_id AND auth.uid() = user_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_qkms_rotation_one_open_order
  ON public.qkms_rotation_jobs (tenant_id, key_ref)
  WHERE key_ref IS NOT NULL AND status IN ('requested', 'approved', 'in-progress', 'awaiting-validation', 'pending');

COMMIT;
