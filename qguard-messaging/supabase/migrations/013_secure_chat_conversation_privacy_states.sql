-- User-scoped Secure Chat conversation controls.
-- Archive, hide, and delete are intentionally per-user so one participant's
-- privacy action does not destroy another participant's zero-knowledge history.

CREATE TABLE IF NOT EXISTS public.messaging_conversation_user_states (
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  archived_at TIMESTAMPTZ,
  hidden_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, conversation_id),
  CHECK (
    deleted_at IS NULL
    OR (archived_at IS NULL AND hidden_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_messaging_conversation_user_states_user_visible
  ON public.messaging_conversation_user_states(user_id, updated_at DESC)
  WHERE deleted_at IS NULL;

ALTER TABLE public.messaging_conversation_user_states ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_conversation_user_states_owner ON public.messaging_conversation_user_states;
CREATE POLICY messaging_conversation_user_states_owner ON public.messaging_conversation_user_states
  FOR ALL
  USING (
    auth.uid() = user_id
    AND public.is_messaging_conversation_member(conversation_id, auth.uid())
  )
  WITH CHECK (
    auth.uid() = user_id
    AND public.is_messaging_conversation_member(conversation_id, auth.uid())
  );

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_conversation_user_states;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;
