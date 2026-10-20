-- 043: channels — one sender to many readers (roadmap 7.4, owner decision 2026-10-20).
--
-- A channel is a conversation of type 'channel'. Its owner and up to 3 admins
-- (migration 042 roles) post; everyone else reads. Posts live in
-- messaging_channel_posts, encrypted ONCE under the channel's epoch key and
-- signed by the posting device (src-tauri/src/commands/channels.rs); the relay
-- stores ciphertext only. Epoch keys travel as ordinary sealed pairwise
-- envelopes inside the channel conversation, so:
--
--   * in a channel, every envelope must be to or from the owner or an admin —
--     a reader cannot broadcast to the other readers through envelopes;
--   * readers do not see who else reads: member rows of a channel are visible
--     to its owner and admins, and to each reader only for themselves and the
--     staff;
--   * people join with an invite code the owner or an admin creates. Only the
--     SHA3-256 of the code is stored; the code is shown once.

-- ---------------------------------------------------------------------------
-- The conversation type
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  v_name TEXT;
BEGIN
  FOR v_name IN
    SELECT con.conname
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
    WHERE nsp.nspname = 'public'
      AND rel.relname = 'messaging_conversations'
      AND con.contype = 'c'
      AND pg_get_constraintdef(con.oid) ILIKE '%conversation_type%'
  LOOP
    EXECUTE format('ALTER TABLE public.messaging_conversations DROP CONSTRAINT %I', v_name);
  END LOOP;
END $$;

ALTER TABLE public.messaging_conversations
  ADD CONSTRAINT messaging_conversations_conversation_type_check
  CHECK (conversation_type IN ('direct', 'group', 'channel'));

-- Owner or admin of a group or channel.
CREATE OR REPLACE FUNCTION public.is_messaging_conversation_staff(p_conversation_id UUID, p_user_id UUID)
RETURNS BOOLEAN AS $$
  SELECT public.owns_messaging_conversation(p_conversation_id, p_user_id)
    OR public.is_messaging_group_admin(p_conversation_id, p_user_id);
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.is_messaging_conversation_staff(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_messaging_conversation_staff(UUID, UUID) TO authenticated;

CREATE OR REPLACE FUNCTION public.is_messaging_channel(p_conversation_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.messaging_conversations c
    WHERE c.id = p_conversation_id AND c.conversation_type = 'channel'
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.is_messaging_channel(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_messaging_channel(UUID) TO authenticated;

-- Migration 042's group management applies to channels too (admins, transfer,
-- remove); leaving works for both.
CREATE OR REPLACE FUNCTION public.qguard_group_for_update(p_conversation_id UUID)
RETURNS UUID AS $$
DECLARE
  v_type TEXT;
  v_owner UUID;
BEGIN
  SELECT c.conversation_type, c.owner_user_id INTO v_type, v_owner
  FROM public.messaging_conversations c
  WHERE c.id = p_conversation_id
  FOR UPDATE;
  IF v_type IS NULL OR v_type NOT IN ('group', 'channel') THEN
    RAISE EXCEPTION 'not a group or channel';
  END IF;
  RETURN v_owner;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_group_for_update(UUID) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.leave_messaging_conversation(p_conversation_id UUID)
RETURNS INTEGER AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_owner UUID;
  v_count INTEGER;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;
  v_owner := public.qguard_group_for_update(p_conversation_id);
  IF NOT public.is_messaging_conversation_member(p_conversation_id, v_user_id) THEN
    RAISE EXCEPTION 'not a member of this group';
  END IF;
  IF v_owner = v_user_id THEN
    RAISE EXCEPTION 'the owner cannot leave; transfer ownership first';
  END IF;
  UPDATE public.messaging_conversation_members m
  SET revoked_at = now()
  WHERE m.conversation_id = p_conversation_id
    AND m.user_id = v_user_id
    AND m.revoked_at IS NULL;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.leave_messaging_conversation(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.leave_messaging_conversation(UUID) TO authenticated;

-- ---------------------------------------------------------------------------
-- Who sees whom
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.qguard_member_row_visible(p_conversation_id UUID, p_row_user UUID, p_viewer UUID)
RETURNS BOOLEAN AS $$
  SELECT p_row_user = p_viewer
    OR (
      public.is_messaging_conversation_member(p_conversation_id, p_viewer)
      AND (
        NOT public.is_messaging_channel(p_conversation_id)
        OR public.is_messaging_conversation_staff(p_conversation_id, p_viewer)
        OR public.is_messaging_conversation_staff(p_conversation_id, p_row_user)
      )
    );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_member_row_visible(UUID, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.qguard_member_row_visible(UUID, UUID, UUID) TO authenticated;

DROP POLICY IF EXISTS messaging_members_visible ON public.messaging_conversation_members;
CREATE POLICY messaging_members_visible ON public.messaging_conversation_members
  FOR SELECT USING (public.qguard_member_row_visible(conversation_id, user_id, auth.uid()));

-- In a channel every envelope is to or from staff (key hand-out, key requests).
CREATE OR REPLACE FUNCTION public.qguard_channel_envelope_allowed(p_conversation_id UUID, p_sender UUID, p_recipient UUID)
RETURNS BOOLEAN AS $$
  SELECT NOT public.is_messaging_channel(p_conversation_id)
    OR public.is_messaging_conversation_staff(p_conversation_id, p_sender)
    OR public.is_messaging_conversation_staff(p_conversation_id, p_recipient);
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_channel_envelope_allowed(UUID, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.qguard_channel_envelope_allowed(UUID, UUID, UUID) TO authenticated;

DROP POLICY IF EXISTS messaging_envelopes_channel_staff_only ON public.messaging_message_envelopes;
CREATE POLICY messaging_envelopes_channel_staff_only
  ON public.messaging_message_envelopes
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (public.qguard_channel_envelope_allowed(conversation_id, sender_user_id, recipient_user_id));

-- ---------------------------------------------------------------------------
-- Posts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.messaging_channel_posts (
  id UUID PRIMARY KEY,
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  sender_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  sender_device_id UUID NOT NULL REFERENCES public.messaging_devices(id) ON DELETE CASCADE,
  epoch_id TEXT NOT NULL CHECK (char_length(epoch_id) BETWEEN 1 AND 64),
  nonce TEXT NOT NULL CHECK (char_length(nonce) BETWEEN 8 AND 64),
  ciphertext TEXT NOT NULL CHECK (char_length(ciphertext) BETWEEN 4 AND 90000),
  tag TEXT NOT NULL CHECK (char_length(tag) BETWEEN 8 AND 64),
  signature JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS messaging_channel_posts_conversation_idx ON public.messaging_channel_posts(conversation_id, created_at DESC);

ALTER TABLE public.messaging_channel_posts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_channel_posts_member_read ON public.messaging_channel_posts;
CREATE POLICY messaging_channel_posts_member_read ON public.messaging_channel_posts
  FOR SELECT USING (public.is_messaging_conversation_member(conversation_id, auth.uid()));

DROP POLICY IF EXISTS messaging_channel_posts_staff_insert ON public.messaging_channel_posts;
CREATE POLICY messaging_channel_posts_staff_insert ON public.messaging_channel_posts
  FOR INSERT WITH CHECK (
    sender_user_id = auth.uid()
    AND public.is_messaging_channel(conversation_id)
    AND public.is_messaging_conversation_staff(conversation_id, auth.uid())
    AND public.is_messaging_conversation_member(conversation_id, auth.uid())
    AND EXISTS (
      SELECT 1 FROM public.messaging_devices d
      WHERE d.id = sender_device_id AND d.user_id = sender_user_id AND d.trust_state <> 'revoked' AND d.revoked_at IS NULL
    )
  );

-- Moderation: the poster, the owner or an admin may delete a post.
DROP POLICY IF EXISTS messaging_channel_posts_staff_delete ON public.messaging_channel_posts;
CREATE POLICY messaging_channel_posts_staff_delete ON public.messaging_channel_posts
  FOR DELETE USING (
    sender_user_id = auth.uid()
    OR public.is_messaging_conversation_staff(conversation_id, auth.uid())
  );

DO $$
BEGIN
  IF to_regprocedure('public.qguard_has_messaging_access(uuid)') IS NOT NULL THEN
    EXECUTE 'DROP POLICY IF EXISTS messaging_channel_posts_require_subscription ON public.messaging_channel_posts';
    EXECUTE 'CREATE POLICY messaging_channel_posts_require_subscription ON public.messaging_channel_posts
      AS RESTRICTIVE FOR INSERT TO authenticated WITH CHECK (public.qguard_has_messaging_access(auth.uid()))';
  END IF;
END $$;

GRANT SELECT, INSERT, DELETE ON public.messaging_channel_posts TO authenticated;
REVOKE ALL ON public.messaging_channel_posts FROM anon;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime')
     AND NOT EXISTS (
       SELECT 1 FROM pg_publication_tables
       WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'messaging_channel_posts'
     ) THEN
    EXECUTE 'ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_channel_posts';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Invites
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.messaging_channel_invites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL UNIQUE,
  created_by UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  max_uses INTEGER NOT NULL CHECK (max_uses BETWEEN 1 AND 1000),
  uses INTEGER NOT NULL DEFAULT 0,
  revoked_at TIMESTAMPTZ
);

ALTER TABLE public.messaging_channel_invites ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS messaging_channel_invites_staff_read ON public.messaging_channel_invites;
CREATE POLICY messaging_channel_invites_staff_read ON public.messaging_channel_invites
  FOR SELECT USING (public.is_messaging_conversation_staff(conversation_id, auth.uid()));
REVOKE INSERT, UPDATE, DELETE ON public.messaging_channel_invites FROM authenticated, anon;
GRANT SELECT ON public.messaging_channel_invites TO authenticated;

/** Readers per channel: every key rotation is sealed to each of their devices. */
CREATE OR REPLACE FUNCTION public.qguard_channel_reader_limit()
RETURNS INTEGER AS $$ SELECT 1000 $$ LANGUAGE sql IMMUTABLE;

-- Owner or admin: a new invite code, returned ONCE (only its hash is kept).
CREATE OR REPLACE FUNCTION public.create_messaging_channel_invite(p_conversation_id UUID, p_valid_hours INTEGER, p_max_uses INTEGER)
RETURNS TEXT AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_code TEXT;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;
  IF NOT public.is_messaging_channel(p_conversation_id) OR NOT public.is_messaging_conversation_staff(p_conversation_id, v_user_id) THEN
    RAISE EXCEPTION 'only the channel owner or an admin can invite';
  END IF;
  IF p_valid_hours IS NULL OR p_valid_hours < 1 OR p_valid_hours > 24 * 30 THEN
    RAISE EXCEPTION 'an invite lasts 1 hour to 30 days';
  END IF;
  v_code := encode(gen_random_bytes(16), 'hex');
  INSERT INTO public.messaging_channel_invites (conversation_id, code_hash, created_by, expires_at, max_uses)
  VALUES (p_conversation_id, encode(digest(v_code, 'sha3-256'), 'hex'), v_user_id, now() + make_interval(hours => p_valid_hours), COALESCE(p_max_uses, 1));
  RETURN v_code;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, extensions;

CREATE OR REPLACE FUNCTION public.revoke_messaging_channel_invite(p_invite_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  v_conversation UUID;
BEGIN
  SELECT i.conversation_id INTO v_conversation FROM public.messaging_channel_invites i WHERE i.id = p_invite_id;
  IF v_conversation IS NULL OR NOT public.is_messaging_conversation_staff(v_conversation, auth.uid()) THEN
    RAISE EXCEPTION 'only the channel owner or an admin can revoke invites';
  END IF;
  UPDATE public.messaging_channel_invites SET revoked_at = now() WHERE id = p_invite_id AND revoked_at IS NULL;
  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Join with a code: every one of the caller's active devices becomes a reader.
CREATE OR REPLACE FUNCTION public.join_messaging_channel(p_code TEXT)
RETURNS UUID AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_invite public.messaging_channel_invites%ROWTYPE;
  v_readers INTEGER;
  v_added INTEGER;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;
  SELECT * INTO v_invite
  FROM public.messaging_channel_invites i
  WHERE i.code_hash = encode(digest(lower(trim(COALESCE(p_code, ''))), 'sha3-256'), 'hex')
  FOR UPDATE;
  IF v_invite.id IS NULL OR v_invite.revoked_at IS NOT NULL OR v_invite.expires_at <= now() OR v_invite.uses >= v_invite.max_uses THEN
    RAISE EXCEPTION 'this invite is not valid (wrong, expired, used up or revoked)';
  END IF;
  IF public.is_messaging_conversation_member(v_invite.conversation_id, v_user_id) THEN
    RETURN v_invite.conversation_id;
  END IF;
  SELECT count(DISTINCT m.user_id) INTO v_readers
  FROM public.messaging_conversation_members m
  WHERE m.conversation_id = v_invite.conversation_id AND m.revoked_at IS NULL;
  IF v_readers >= public.qguard_channel_reader_limit() THEN
    RAISE EXCEPTION 'this channel is full';
  END IF;
  INSERT INTO public.messaging_conversation_members (conversation_id, user_id, device_id, role)
  SELECT v_invite.conversation_id, v_user_id, d.id, 'member'
  FROM public.messaging_devices d
  WHERE d.user_id = v_user_id AND d.trust_state <> 'revoked' AND d.revoked_at IS NULL
  -- A fresh invite from staff readmits someone removed earlier.
  ON CONFLICT (conversation_id, user_id, device_id) DO UPDATE SET revoked_at = NULL
    WHERE public.messaging_conversation_members.revoked_at IS NOT NULL;
  GET DIAGNOSTICS v_added = ROW_COUNT;
  IF v_added = 0 THEN
    RAISE EXCEPTION 'this account has no active device to join with';
  END IF;
  UPDATE public.messaging_channel_invites SET uses = uses + 1 WHERE id = v_invite.id;
  RETURN v_invite.conversation_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, extensions;

REVOKE ALL ON FUNCTION public.create_messaging_channel_invite(UUID, INTEGER, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.revoke_messaging_channel_invite(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.join_messaging_channel(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_messaging_channel_invite(UUID, INTEGER, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_messaging_channel_invite(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.join_messaging_channel(TEXT) TO authenticated;
