-- QGuard quantum encryption enforcement.
-- Run after 001_secure_messaging.sql, 002_dashboard_access_fix.sql, and 003_chat_contacts.sql.

ALTER TABLE public.messaging_one_time_prekeys
  ADD COLUMN IF NOT EXISTS signature JSONB;

CREATE TABLE IF NOT EXISTS public.messaging_crypto_telemetry (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  event_scope TEXT NOT NULL CHECK (event_scope IN ('message', 'vault', 'key', 'upload', 'download', 'verification')),
  stage TEXT NOT NULL,
  detail TEXT NOT NULL,
  progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  status TEXT NOT NULL DEFAULT 'progress' CHECK (status IN ('started', 'progress', 'verified', 'failed', 'complete')),
  redacted_metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.messaging_crypto_telemetry ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_crypto_telemetry_owner ON public.messaging_crypto_telemetry;
CREATE POLICY messaging_crypto_telemetry_owner ON public.messaging_crypto_telemetry
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE INDEX IF NOT EXISTS idx_messaging_crypto_telemetry_user_created
  ON public.messaging_crypto_telemetry(user_id, created_at DESC);

CREATE OR REPLACE FUNCTION public.claim_messaging_one_time_prekey(
  p_device_id UUID,
  p_sender_device_id UUID
)
RETURNS TABLE (
  prekey_id UUID,
  device_id UUID,
  x25519_public BYTEA,
  mlkem_public BYTEA,
  signature JSONB,
  fingerprint TEXT,
  created_at TIMESTAMPTZ
) AS $$
DECLARE
  v_sender_user_id UUID := auth.uid();
  v_recipient_user_id UUID;
BEGIN
  IF v_sender_user_id IS NULL THEN
    RETURN;
  END IF;

  SELECT d.user_id
    INTO v_recipient_user_id
  FROM public.messaging_devices d
  WHERE d.id = p_device_id
    AND d.trust_state <> 'revoked';

  IF v_recipient_user_id IS NULL THEN
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.messaging_devices d
    WHERE d.id = p_sender_device_id
      AND d.user_id = v_sender_user_id
      AND d.trust_state <> 'revoked'
  ) THEN
    RETURN;
  END IF;

  IF NOT (
    v_sender_user_id = v_recipient_user_id
    OR public.is_messaging_contact(v_sender_user_id, v_recipient_user_id)
    OR public.is_messaging_contact(v_recipient_user_id, v_sender_user_id)
  ) THEN
    RETURN;
  END IF;

  RETURN QUERY
  WITH claimed AS (
    SELECT k.id
    FROM public.messaging_one_time_prekeys k
    WHERE k.device_id = p_device_id
      AND k.consumed_at IS NULL
      AND k.signature IS NOT NULL
    ORDER BY k.created_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
  ),
  updated AS (
    UPDATE public.messaging_one_time_prekeys k
       SET consumed_at = now(),
           consumed_by_device_id = p_sender_device_id
      FROM claimed
     WHERE k.id = claimed.id
     RETURNING k.id, k.device_id, k.x25519_public, k.mlkem_public, k.signature, k.fingerprint, k.created_at
  )
  SELECT u.id, u.device_id, u.x25519_public, u.mlkem_public, u.signature, u.fingerprint, u.created_at
  FROM updated u;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

DROP POLICY IF EXISTS messaging_envelopes_sender_insert ON public.messaging_message_envelopes;
CREATE POLICY messaging_envelopes_sender_insert ON public.messaging_message_envelopes
  FOR INSERT WITH CHECK (
    sender_user_id = auth.uid()
    AND sender_device_id IS NOT NULL
    AND recipient_device_id IS NOT NULL
    AND public.is_messaging_conversation_member(conversation_id, sender_user_id)
    AND public.is_messaging_conversation_member(conversation_id, recipient_user_id)
    AND EXISTS (
      SELECT 1 FROM public.messaging_devices d
      WHERE d.id = sender_device_id
        AND d.user_id = sender_user_id
        AND d.trust_state <> 'revoked'
    )
    AND EXISTS (
      SELECT 1 FROM public.messaging_devices d
      WHERE d.id = recipient_device_id
        AND d.user_id = recipient_user_id
        AND d.trust_state <> 'revoked'
    )
    AND octet_length(ciphertext) > 0
    AND octet_length(nonce) = 12
    AND octet_length(auth_tag) = 16
    AND octet_length(aad) > 0
    AND sealed_sender_envelope ? 'hybrid_ciphertext'
    AND sealed_sender_envelope ? 'message_signature'
  );

DROP POLICY IF EXISTS messaging_vault_owner_write ON public.messaging_vault_files;
CREATE POLICY messaging_vault_owner_write ON public.messaging_vault_files
  FOR INSERT WITH CHECK (
    owner_user_id = auth.uid()
    AND storage_path LIKE auth.uid()::TEXT || '/%'
    AND encrypted_metadata ? 'metadata'
    AND encrypted_metadata ? 'chunk_paths'
    AND metadata_signature ? 'ed25519'
    AND metadata_signature ? 'ml_dsa_65'
  );

DROP POLICY IF EXISTS messaging_files_storage_update ON storage.objects;
CREATE POLICY messaging_files_storage_update ON storage.objects
  FOR UPDATE USING (
    bucket_id = 'messaging-files'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  )
  WITH CHECK (
    bucket_id = 'messaging-files'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  );

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_crypto_telemetry;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;
