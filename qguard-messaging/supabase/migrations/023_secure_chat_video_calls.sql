-- Ephemeral 1:1 call signaling (offer/answer/ice/control). Payloads are not
-- secret: the media key is bootstrapped by a hybrid-KEM ciphertext only the
-- callee can decapsulate, and media frames are separately AES-256-GCM encrypted.
CREATE TABLE IF NOT EXISTS public.messaging_call_signals (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  call_id         UUID NOT NULL,
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  from_user_id    UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  from_device_id  UUID NOT NULL,
  to_user_id      UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  to_device_id    UUID NOT NULL,
  signal_type     TEXT NOT NULL CHECK (signal_type IN ('ring','offer','answer','ice','accept','reject','hangup','busy')),
  payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS messaging_call_signals_to_idx
  ON public.messaging_call_signals (to_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS messaging_call_signals_call_idx
  ON public.messaging_call_signals (call_id, created_at);

ALTER TABLE public.messaging_call_signals ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_call_signals_member_select ON public.messaging_call_signals;
CREATE POLICY messaging_call_signals_member_select ON public.messaging_call_signals
  FOR SELECT USING (public.is_messaging_conversation_member(conversation_id, auth.uid()));

DROP POLICY IF EXISTS messaging_call_signals_member_insert ON public.messaging_call_signals;
CREATE POLICY messaging_call_signals_member_insert ON public.messaging_call_signals
  FOR INSERT WITH CHECK (
    auth.uid() = from_user_id
    AND public.is_messaging_conversation_member(conversation_id, auth.uid())
  );

DROP POLICY IF EXISTS messaging_call_signals_member_delete ON public.messaging_call_signals;
CREATE POLICY messaging_call_signals_member_delete ON public.messaging_call_signals
  FOR DELETE USING (auth.uid() = from_user_id);

CREATE OR REPLACE FUNCTION public.prune_expired_messaging_call_signals()
RETURNS VOID AS $$
BEGIN
  DELETE FROM public.messaging_call_signals WHERE created_at < now() - INTERVAL '1 hour';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_call_signals;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;