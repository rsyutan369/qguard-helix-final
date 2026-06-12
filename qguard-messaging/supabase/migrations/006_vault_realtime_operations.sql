-- QGuard Quantum Vault realtime operation telemetry and lifecycle controls.
-- Run after 005_profile_security_settings.sql.

CREATE TABLE IF NOT EXISTS public.qguard_vault_operations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  file_id UUID REFERENCES public.messaging_vault_files(id) ON DELETE SET NULL,
  operation_type TEXT NOT NULL CHECK (operation_type IN ('encrypt', 'verify', 'download_encrypted', 'decrypt_download', 'delete')),
  display_name_hint TEXT NOT NULL DEFAULT 'vault object',
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'processing', 'completed', 'failed')),
  current_operation TEXT NOT NULL DEFAULT 'Queued',
  progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  size_bytes BIGINT NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
  processed_bytes BIGINT NOT NULL DEFAULT 0 CHECK (processed_bytes >= 0),
  algorithm TEXT NOT NULL DEFAULT 'ML-KEM-1024 + X25519 + HKDF-SHA3-256 + AES-256-GCM + ML-DSA-65 + Ed25519',
  integrity_status TEXT NOT NULL DEFAULT 'pending' CHECK (integrity_status IN ('pending', 'verified', 'failed', 'not_checked')),
  error_message TEXT,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  redacted_metadata JSONB NOT NULL DEFAULT '{}',
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);

ALTER TABLE public.qguard_vault_operations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS qguard_vault_operations_owner ON public.qguard_vault_operations;
CREATE POLICY qguard_vault_operations_owner ON public.qguard_vault_operations
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE INDEX IF NOT EXISTS idx_qguard_vault_operations_user_updated
  ON public.qguard_vault_operations(user_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_qguard_vault_operations_file
  ON public.qguard_vault_operations(file_id, updated_at DESC);

DROP POLICY IF EXISTS messaging_vault_owner_delete ON public.messaging_vault_files;
CREATE POLICY messaging_vault_owner_delete ON public.messaging_vault_files
  FOR DELETE USING (owner_user_id = auth.uid());

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.qguard_vault_operations;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

NOTIFY pgrst, 'reload schema';
