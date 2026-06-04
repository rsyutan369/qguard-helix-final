-- QGuard Messaging contacts and private-chat access.
-- Run after 001_secure_messaging.sql and 002_dashboard_access_fix.sql.

CREATE TABLE IF NOT EXISTS public.messaging_contacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  contact_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  alias TEXT,
  trust_state TEXT NOT NULL DEFAULT 'added' CHECK (trust_state IN ('added', 'blocked', 'removed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_user_id, contact_user_id)
);

ALTER TABLE public.messaging_contacts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_contacts_owner ON public.messaging_contacts;
CREATE POLICY messaging_contacts_owner ON public.messaging_contacts
  FOR ALL USING (auth.uid() = owner_user_id) WITH CHECK (auth.uid() = owner_user_id);

CREATE OR REPLACE FUNCTION public.is_messaging_contact(p_owner_user_id UUID, p_contact_user_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.messaging_contacts c
    WHERE c.owner_user_id = p_owner_user_id
      AND c.contact_user_id = p_contact_user_id
      AND c.trust_state = 'added'
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.owns_messaging_conversation(p_conversation_id UUID, p_user_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.messaging_conversations c
    WHERE c.id = p_conversation_id
      AND c.owner_user_id = p_user_id
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.search_messaging_users(p_query TEXT)
RETURNS TABLE (
  user_id UUID,
  display_name TEXT,
  username TEXT
) AS $$
  SELECT
    p.id AS user_id,
    COALESCE(NULLIF(p.name, ''), split_part(p.email, '@', 1), 'QGuard User') AS display_name,
    split_part(p.email, '@', 1) AS username
  FROM public.profiles p
  WHERE p.id <> auth.uid()
    AND length(trim(p_query)) >= 2
    AND (
      p.id::TEXT = trim(p_query)
      OR lower(COALESCE(p.name, '')) LIKE lower(trim(p_query)) || '%'
      OR lower(split_part(p.email, '@', 1)) LIKE lower(trim(p_query)) || '%'
      OR lower(p.email) = lower(trim(p_query))
      OR lower(trim(p_query)) LIKE 'qguard-user:%' AND p.id::TEXT = replace(lower(trim(p_query)), 'qguard-user:', '')
    )
  ORDER BY p.created_at DESC
  LIMIT 10;
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

DROP POLICY IF EXISTS messaging_members_owner_insert ON public.messaging_conversation_members;
CREATE POLICY messaging_members_owner_insert ON public.messaging_conversation_members
  FOR INSERT WITH CHECK (
    user_id = auth.uid()
    OR public.owns_messaging_conversation(conversation_id, auth.uid())
  );

DROP POLICY IF EXISTS messaging_devices_contact_select ON public.messaging_devices;
CREATE POLICY messaging_devices_contact_select ON public.messaging_devices
  FOR SELECT USING (
    auth.uid() = user_id
    OR (
      trust_state <> 'revoked'
      AND public.is_messaging_contact(auth.uid(), user_id)
    )
  );

DROP POLICY IF EXISTS messaging_signed_prekeys_contact_select ON public.messaging_signed_prekeys;
CREATE POLICY messaging_signed_prekeys_contact_select ON public.messaging_signed_prekeys
  FOR SELECT USING (
    auth.uid() = user_id
    OR (
      is_active = true
      AND public.is_messaging_contact(auth.uid(), user_id)
    )
  );

DROP POLICY IF EXISTS messaging_one_time_prekeys_contact_select ON public.messaging_one_time_prekeys;
CREATE POLICY messaging_one_time_prekeys_contact_select ON public.messaging_one_time_prekeys
  FOR SELECT USING (
    auth.uid() = user_id
    OR (
      consumed_at IS NULL
      AND public.is_messaging_contact(auth.uid(), user_id)
    )
  );

DROP POLICY IF EXISTS messaging_contacts_realtime_select ON public.messaging_contacts;
CREATE POLICY messaging_contacts_realtime_select ON public.messaging_contacts
  FOR SELECT USING (auth.uid() = owner_user_id);

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_contacts;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;
