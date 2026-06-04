-- QGuard Secure Chat advanced controls and per-user security state.
-- Run after 006_vault_realtime_operations.sql.

ALTER TABLE public.messaging_message_envelopes
  ADD COLUMN IF NOT EXISTS client_message_id UUID,
  ADD COLUMN IF NOT EXISTS parent_client_message_id UUID,
  ADD COLUMN IF NOT EXISTS lifecycle JSONB NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS verification_state TEXT NOT NULL DEFAULT 'pending'
    CHECK (verification_state IN ('pending', 'valid', 'tampered', 'expired', 'revoked')),
  ADD COLUMN IF NOT EXISTS threat_result JSONB NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_messaging_envelopes_conversation_client
  ON public.messaging_message_envelopes(conversation_id, client_message_id, created_at)
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS public.messaging_message_user_states (
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  client_message_id UUID NOT NULL,
  first_read_at TIMESTAMPTZ,
  hidden_at TIMESTAMPTZ,
  verification_state TEXT NOT NULL DEFAULT 'pending'
    CHECK (verification_state IN ('pending', 'valid', 'tampered', 'expired', 'revoked')),
  threat_score INTEGER NOT NULL DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
  threat_flags TEXT[] NOT NULL DEFAULT '{}',
  proof JSONB NOT NULL DEFAULT '{}',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, conversation_id, client_message_id)
);

CREATE TABLE IF NOT EXISTS public.messaging_typing_indicators (
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  is_typing BOOLEAN NOT NULL DEFAULT true,
  expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '8 seconds',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (conversation_id, user_id, device_id)
);

ALTER TABLE public.messaging_message_user_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_typing_indicators ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_message_user_states_owner ON public.messaging_message_user_states;
CREATE POLICY messaging_message_user_states_owner ON public.messaging_message_user_states
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (
    auth.uid() = user_id
    AND public.is_messaging_conversation_member(conversation_id, auth.uid())
  );

DROP POLICY IF EXISTS messaging_typing_indicators_visible ON public.messaging_typing_indicators;
CREATE POLICY messaging_typing_indicators_visible ON public.messaging_typing_indicators
  FOR SELECT USING (public.is_messaging_conversation_member(conversation_id, auth.uid()));

DROP POLICY IF EXISTS messaging_typing_indicators_self_insert ON public.messaging_typing_indicators;
CREATE POLICY messaging_typing_indicators_self_insert ON public.messaging_typing_indicators
  FOR INSERT WITH CHECK (
    auth.uid() = user_id
    AND public.is_messaging_conversation_member(conversation_id, auth.uid())
  );

DROP POLICY IF EXISTS messaging_typing_indicators_self_update ON public.messaging_typing_indicators;
CREATE POLICY messaging_typing_indicators_self_update ON public.messaging_typing_indicators
  FOR UPDATE USING (auth.uid() = user_id)
  WITH CHECK (
    auth.uid() = user_id
    AND public.is_messaging_conversation_member(conversation_id, auth.uid())
  );

DROP POLICY IF EXISTS messaging_typing_indicators_self_delete ON public.messaging_typing_indicators;
CREATE POLICY messaging_typing_indicators_self_delete ON public.messaging_typing_indicators
  FOR DELETE USING (auth.uid() = user_id);

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
    AND (
      client_message_id IS NULL
      OR sealed_sender_envelope->>'client_message_id' = client_message_id::TEXT
    )
    AND (
      parent_client_message_id IS NULL
      OR lifecycle ? 'reply_to'
      OR sealed_sender_envelope ? 'parent_client_message_id'
    )
  );

CREATE OR REPLACE FUNCTION public.prune_expired_messaging_typing_indicators()
RETURNS VOID AS $$
BEGIN
  DELETE FROM public.messaging_typing_indicators
  WHERE expires_at < now();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_message_user_states;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_typing_indicators;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;
