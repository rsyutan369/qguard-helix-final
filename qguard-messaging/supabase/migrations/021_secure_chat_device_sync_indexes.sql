-- Speed up trusted-device history synchronization checks.
-- The Secure Chat client keeps E2EE by rewrapping decrypted plaintext locally
-- into new per-device ML-KEM/X25519 envelopes; Supabase stores only ciphertext.

CREATE INDEX IF NOT EXISTS idx_messaging_envelopes_device_sync_target
  ON public.messaging_message_envelopes(
    conversation_id,
    client_message_id,
    recipient_user_id,
    recipient_device_id
  )
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_messaging_envelopes_client_recovery_source
  ON public.messaging_message_envelopes(conversation_id, client_message_id, created_at)
  WHERE deleted_at IS NULL;
