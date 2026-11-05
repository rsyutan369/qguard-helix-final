-- 050: per-chat Mute / Notifications & Sounds, and Report (owner request 2026-11-05).
--
-- * messaging_notification_settings — one row per user: the app-wide defaults
--   for new-message alerts, the message sound and the incoming-call ring.
-- * messaging_chat_preferences — one row per (user, conversation): mute until a
--   time, and per-chat overrides of those defaults (NULL = use the default).
--   `peer_user_id` names the other person of a direct chat so an incoming call
--   from them can be silenced without the client first finding the chat.
--   Both tables are private to their owner and in the realtime publication, so
--   a change made on one device applies on the others at once.
-- * messaging_reports — "Report" on a contact or conversation. Messages are end-
--   to-end encrypted, so a report carries only who, which conversation, a
--   reason and the reporter's own words: the server never receives message
--   content. Written only through messaging_submit_report (validated, rate
--   limited); readable by the reporter and by operators (messaging_app_roles).

-- ---------------------------------------------------------------------------
-- App-wide notification defaults
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.messaging_notification_settings (
  user_id UUID PRIMARY KEY DEFAULT auth.uid() REFERENCES public.profiles(id) ON DELETE CASCADE,
  message_alerts BOOLEAN NOT NULL DEFAULT true,
  message_sound TEXT NOT NULL DEFAULT 'chime' CHECK (message_sound IN ('chime', 'pop', 'soft', 'none')),
  call_ring BOOLEAN NOT NULL DEFAULT true,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.messaging_notification_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_notification_settings REPLICA IDENTITY FULL;

DROP POLICY IF EXISTS messaging_notification_settings_own ON public.messaging_notification_settings;
CREATE POLICY messaging_notification_settings_own ON public.messaging_notification_settings
  FOR ALL TO authenticated
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- ---------------------------------------------------------------------------
-- Per-chat preferences
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.messaging_chat_preferences (
  user_id UUID NOT NULL DEFAULT auth.uid() REFERENCES public.profiles(id) ON DELETE CASCADE,
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  peer_user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  -- NULL: not muted. A time: muted until then ('9999-12-31' = until unmuted).
  muted_until TIMESTAMPTZ,
  message_alerts BOOLEAN,
  message_sound TEXT CHECK (message_sound IS NULL OR message_sound IN ('chime', 'pop', 'soft', 'none')),
  call_ring BOOLEAN,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, conversation_id)
);

CREATE INDEX IF NOT EXISTS messaging_chat_preferences_peer
  ON public.messaging_chat_preferences(user_id, peer_user_id) WHERE peer_user_id IS NOT NULL;

ALTER TABLE public.messaging_chat_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_chat_preferences REPLICA IDENTITY FULL;

DROP POLICY IF EXISTS messaging_chat_preferences_read ON public.messaging_chat_preferences;
CREATE POLICY messaging_chat_preferences_read ON public.messaging_chat_preferences
  FOR SELECT TO authenticated
  USING (user_id = auth.uid());

-- Only for a conversation the caller belongs to.
DROP POLICY IF EXISTS messaging_chat_preferences_insert ON public.messaging_chat_preferences;
CREATE POLICY messaging_chat_preferences_insert ON public.messaging_chat_preferences
  FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid() AND public.is_messaging_conversation_member(conversation_id, auth.uid()));

DROP POLICY IF EXISTS messaging_chat_preferences_update ON public.messaging_chat_preferences;
CREATE POLICY messaging_chat_preferences_update ON public.messaging_chat_preferences
  FOR UPDATE TO authenticated
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid() AND public.is_messaging_conversation_member(conversation_id, auth.uid()));

DROP POLICY IF EXISTS messaging_chat_preferences_delete ON public.messaging_chat_preferences;
CREATE POLICY messaging_chat_preferences_delete ON public.messaging_chat_preferences
  FOR DELETE TO authenticated
  USING (user_id = auth.uid());

-- ---------------------------------------------------------------------------
-- Reports
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.messaging_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  reported_user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  conversation_id UUID REFERENCES public.messaging_conversations(id) ON DELETE SET NULL,
  reason TEXT NOT NULL CHECK (reason IN ('spam', 'harassment', 'scam', 'impersonation', 'inappropriate', 'other')),
  details TEXT CHECK (details IS NULL OR char_length(details) <= 1000),
  also_blocked BOOLEAN NOT NULL DEFAULT false,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewing', 'actioned', 'dismissed')),
  reviewed_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (reported_user_id IS NOT NULL OR conversation_id IS NOT NULL),
  CHECK (reported_user_id IS DISTINCT FROM reporter_user_id)
);

CREATE INDEX IF NOT EXISTS messaging_reports_reporter ON public.messaging_reports(reporter_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS messaging_reports_open ON public.messaging_reports(status, created_at DESC);

ALTER TABLE public.messaging_reports ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.is_messaging_operator(p_user_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (SELECT 1 FROM public.messaging_app_roles r WHERE r.user_id = p_user_id AND r.role = 'operator');
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

DROP POLICY IF EXISTS messaging_reports_read ON public.messaging_reports;
CREATE POLICY messaging_reports_read ON public.messaging_reports
  FOR SELECT TO authenticated
  USING (reporter_user_id = auth.uid() OR public.is_messaging_operator(auth.uid()));

-- Operators move a report through review; nobody else may change one.
DROP POLICY IF EXISTS messaging_reports_review ON public.messaging_reports;
CREATE POLICY messaging_reports_review ON public.messaging_reports
  FOR UPDATE TO authenticated
  USING (public.is_messaging_operator(auth.uid()))
  WITH CHECK (public.is_messaging_operator(auth.uid()));

-- The only way to file a report. The caller must actually know the person or
-- be in the conversation, so reports cannot be aimed at arbitrary accounts,
-- and at most 20 reports per 24 hours are accepted from one account.
CREATE OR REPLACE FUNCTION public.messaging_submit_report(
  p_reported_user_id UUID,
  p_conversation_id UUID,
  p_reason TEXT,
  p_details TEXT DEFAULT NULL,
  p_also_blocked BOOLEAN DEFAULT false
)
RETURNS UUID AS $$
DECLARE
  uid UUID := auth.uid();
  v_id UUID;
  v_details TEXT := NULLIF(btrim(COALESCE(p_details, '')), '');
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QG_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  IF p_reported_user_id IS NULL AND p_conversation_id IS NULL THEN
    RAISE EXCEPTION 'QG_REPORT_TARGET_REQUIRED';
  END IF;
  IF p_reported_user_id = uid THEN
    RAISE EXCEPTION 'QG_REPORT_SELF';
  END IF;
  IF p_conversation_id IS NOT NULL AND NOT public.is_messaging_conversation_member(p_conversation_id, uid) THEN
    RAISE EXCEPTION 'QG_REPORT_NOT_MEMBER';
  END IF;
  IF p_reported_user_id IS NOT NULL AND NOT (
    EXISTS (SELECT 1 FROM public.messaging_contacts c
            WHERE (c.owner_user_id = uid AND c.contact_user_id = p_reported_user_id)
               OR (c.owner_user_id = p_reported_user_id AND c.contact_user_id = uid))
    OR EXISTS (SELECT 1 FROM public.messaging_conversation_members a
               JOIN public.messaging_conversation_members b ON b.conversation_id = a.conversation_id
               WHERE a.user_id = uid AND b.user_id = p_reported_user_id)
  ) THEN
    RAISE EXCEPTION 'QG_REPORT_UNKNOWN_USER';
  END IF;
  IF (SELECT count(*) FROM public.messaging_reports
      WHERE reporter_user_id = uid AND created_at > now() - interval '24 hours') >= 20 THEN
    RAISE EXCEPTION 'QG_REPORT_RATE_LIMITED';
  END IF;
  IF v_details IS NOT NULL AND char_length(v_details) > 1000 THEN
    v_details := left(v_details, 1000);
  END IF;

  INSERT INTO public.messaging_reports (reporter_user_id, reported_user_id, conversation_id, reason, details, also_blocked)
  VALUES (uid, p_reported_user_id, p_conversation_id, p_reason, v_details, COALESCE(p_also_blocked, false))
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- ---------------------------------------------------------------------------
-- Grants (Supabase grants anon/authenticated by default: say exactly what is allowed)
-- ---------------------------------------------------------------------------
REVOKE ALL ON public.messaging_notification_settings, public.messaging_chat_preferences, public.messaging_reports FROM anon, PUBLIC;
REVOKE ALL ON public.messaging_reports FROM authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.messaging_notification_settings, public.messaging_chat_preferences TO authenticated;
GRANT SELECT ON public.messaging_reports TO authenticated;
GRANT UPDATE (status, reviewed_by, reviewed_at) ON public.messaging_reports TO authenticated;

REVOKE ALL ON FUNCTION public.messaging_submit_report(UUID, UUID, TEXT, TEXT, BOOLEAN) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.messaging_submit_report(UUID, UUID, TEXT, TEXT, BOOLEAN) TO authenticated;
REVOKE ALL ON FUNCTION public.is_messaging_operator(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_messaging_operator(UUID) TO authenticated;

-- ---------------------------------------------------------------------------
-- Realtime: preferences follow the user across devices.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND tablename = 'messaging_chat_preferences') THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_chat_preferences;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND tablename = 'messaging_notification_settings') THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_notification_settings;
    END IF;
  END IF;
END $$;
