-- 047: restrict and block that the server enforces, member limits it enforces,
-- and large groups (owner request 2026-10-22).
--
-- Before this migration:
--   * "Block" only changed a label in messaging_contacts. Nothing on the server
--     read it, so a blocked person's messages and calls still arrived.
--   * The 32-person cap on groups lived only in the client, and the 1,000-reader
--     cap on channels only in join_messaging_channel: an owner or admin adding
--     contacts directly was never counted.
--
-- After it:
--   * messaging_contacts.trust_state gains 'restricted'. A restricted contact can
--     still message you, but cannot call you or add you to a group or channel.
--     A blocked contact can do none of that: their envelopes and call signals to
--     you are dropped by the relay. Like Signal, the sender is not told — the
--     rows are simply not stored — so blocking does not announce itself.
--   * Every member count is checked by the server against
--     messaging_conversation_limits, one row per kind of conversation. Raising a
--     limit (to 10,000 or 100,000) is an UPDATE of that table; nothing in the
--     schema or the app hard-codes the number.
--   * A large group is a channel whose members may all post
--     (member_posting = true): posts are encrypted once under the shared epoch
--     key (migration 043), so a message costs the same for 1,000 members as for
--     10, where a group seals a separate copy for every member device. Members
--     of a large group see each other, as in a group; readers of a channel still
--     see only themselves and the staff.

-- ---------------------------------------------------------------------------
-- Contacts: 'restricted'
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
      AND rel.relname = 'messaging_contacts'
      AND con.contype = 'c'
      AND pg_get_constraintdef(con.oid) ILIKE '%trust_state%'
  LOOP
    EXECUTE format('ALTER TABLE public.messaging_contacts DROP CONSTRAINT %I', v_name);
  END LOOP;
END $$;

ALTER TABLE public.messaging_contacts
  ADD CONSTRAINT messaging_contacts_trust_state_check
  CHECK (trust_state IN ('added', 'restricted', 'blocked', 'removed'));

-- A restricted contact is still a contact: you can chat with them, see their
-- devices and add them to your own groups. Only what THEY can do to you changes.
CREATE OR REPLACE FUNCTION public.is_messaging_contact(p_owner_user_id UUID, p_contact_user_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.messaging_contacts c
    WHERE c.owner_user_id = p_owner_user_id
      AND c.contact_user_id = p_contact_user_id
      AND c.trust_state IN ('added', 'restricted')
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

-- How p_owner has filed p_other. Not granted to clients: whether someone has
-- blocked you is theirs to know, so only the triggers below read it.
CREATE OR REPLACE FUNCTION public.qguard_contact_state(p_owner UUID, p_other UUID)
RETURNS TEXT AS $$
  SELECT c.trust_state
  FROM public.messaging_contacts c
  WHERE c.owner_user_id = p_owner AND c.contact_user_id = p_other;
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_contact_state(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.qguard_contact_state(UUID, UUID) FROM authenticated, anon;

-- Blocked: nothing reaches the person who blocked. Restricted: messages do,
-- calls do not.
CREATE OR REPLACE FUNCTION public.qguard_drop_blocked_envelope()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.recipient_user_id IS DISTINCT FROM NEW.sender_user_id
     AND public.qguard_contact_state(NEW.recipient_user_id, NEW.sender_user_id) = 'blocked' THEN
    RETURN NULL;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_drop_blocked_envelope() FROM PUBLIC;

DROP TRIGGER IF EXISTS qguard_drop_blocked_envelope ON public.messaging_message_envelopes;
CREATE TRIGGER qguard_drop_blocked_envelope
  BEFORE INSERT ON public.messaging_message_envelopes
  FOR EACH ROW EXECUTE FUNCTION public.qguard_drop_blocked_envelope();

CREATE OR REPLACE FUNCTION public.qguard_drop_blocked_call_signal()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.to_user_id IS DISTINCT FROM NEW.from_user_id
     AND public.qguard_contact_state(NEW.to_user_id, NEW.from_user_id) IN ('blocked', 'restricted') THEN
    RETURN NULL;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_drop_blocked_call_signal() FROM PUBLIC;

DO $$
BEGIN
  IF to_regclass('public.messaging_call_signals') IS NOT NULL THEN
    EXECUTE 'DROP TRIGGER IF EXISTS qguard_drop_blocked_call_signal ON public.messaging_call_signals';
    EXECUTE 'CREATE TRIGGER qguard_drop_blocked_call_signal BEFORE INSERT ON public.messaging_call_signals
      FOR EACH ROW EXECUTE FUNCTION public.qguard_drop_blocked_call_signal()';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Large groups
-- ---------------------------------------------------------------------------
ALTER TABLE public.messaging_conversations
  ADD COLUMN IF NOT EXISTS member_posting BOOLEAN NOT NULL DEFAULT false;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'messaging_conversations_member_posting_check'
  ) THEN
    ALTER TABLE public.messaging_conversations
      ADD CONSTRAINT messaging_conversations_member_posting_check
      CHECK (NOT member_posting OR conversation_type = 'channel');
  END IF;
END $$;

-- As migration 042, plus: whether members may post is fixed at creation.
CREATE OR REPLACE FUNCTION public.qguard_conversation_owner_guard()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO public.messaging_conversation_owner_history (conversation_id, owner_user_id, owner_from)
    VALUES (NEW.id, NEW.owner_user_id, COALESCE(NEW.created_at, now()))
    ON CONFLICT DO NOTHING;
    RETURN NEW;
  END IF;
  IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id THEN
    IF current_setting('qguard.ownership_transfer', true) IS DISTINCT FROM 'on' THEN
      RAISE EXCEPTION 'ownership changes only through transfer_messaging_group_ownership';
    END IF;
    UPDATE public.messaging_conversation_owner_history
    SET owner_until = now()
    WHERE conversation_id = NEW.id AND owner_until IS NULL;
    INSERT INTO public.messaging_conversation_owner_history (conversation_id, owner_user_id, owner_from)
    VALUES (NEW.id, NEW.owner_user_id, now());
  END IF;
  IF NEW.conversation_type IS DISTINCT FROM OLD.conversation_type THEN
    RAISE EXCEPTION 'a conversation''s type cannot change';
  END IF;
  IF NEW.member_posting IS DISTINCT FROM OLD.member_posting THEN
    RAISE EXCEPTION 'whether members may post is fixed when the conversation is created';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.is_messaging_large_group(p_conversation_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.messaging_conversations c
    WHERE c.id = p_conversation_id AND c.conversation_type = 'channel' AND c.member_posting
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.is_messaging_large_group(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_messaging_large_group(UUID) TO authenticated;

-- Members of a large group see each other; channel readers still do not.
CREATE OR REPLACE FUNCTION public.qguard_member_row_visible(p_conversation_id UUID, p_row_user UUID, p_viewer UUID)
RETURNS BOOLEAN AS $$
  SELECT p_row_user = p_viewer
    OR (
      public.is_messaging_conversation_member(p_conversation_id, p_viewer)
      AND (
        NOT public.is_messaging_channel(p_conversation_id)
        OR public.is_messaging_large_group(p_conversation_id)
        OR public.is_messaging_conversation_staff(p_conversation_id, p_viewer)
        OR public.is_messaging_conversation_staff(p_conversation_id, p_row_user)
      )
    );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

-- In a large group every member posts, with a device of their own that is not revoked.
DROP POLICY IF EXISTS messaging_channel_posts_staff_insert ON public.messaging_channel_posts;
CREATE POLICY messaging_channel_posts_staff_insert ON public.messaging_channel_posts
  FOR INSERT WITH CHECK (
    sender_user_id = auth.uid()
    AND public.is_messaging_channel(conversation_id)
    AND (
      public.is_messaging_conversation_staff(conversation_id, auth.uid())
      OR public.is_messaging_large_group(conversation_id)
    )
    AND public.is_messaging_conversation_member(conversation_id, auth.uid())
    AND EXISTS (
      SELECT 1 FROM public.messaging_devices d
      WHERE d.id = sender_device_id AND d.user_id = sender_user_id AND d.trust_state <> 'revoked' AND d.revoked_at IS NULL
    )
  );

-- ---------------------------------------------------------------------------
-- Member limits
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.messaging_conversation_limits (
  kind TEXT PRIMARY KEY CHECK (kind IN ('group', 'large_group', 'channel')),
  -- People, not devices. 100,000 is the most this schema is meant to carry;
  -- past it, member lists and key rotation need the work in the groups design (§8).
  max_members INTEGER NOT NULL CHECK (max_members BETWEEN 2 AND 100000),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A group seals every message once per member device, so its cap stays where
-- the client has always held it (32 people). Large groups and channels encrypt
-- once per post and start at 1,000.
INSERT INTO public.messaging_conversation_limits (kind, max_members) VALUES
  ('group', 32),
  ('large_group', 1000),
  ('channel', 1000)
ON CONFLICT (kind) DO NOTHING;

ALTER TABLE public.messaging_conversation_limits ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS messaging_conversation_limits_read ON public.messaging_conversation_limits;
CREATE POLICY messaging_conversation_limits_read ON public.messaging_conversation_limits
  FOR SELECT TO authenticated USING (true);
REVOKE INSERT, UPDATE, DELETE ON public.messaging_conversation_limits FROM authenticated, anon;
GRANT SELECT ON public.messaging_conversation_limits TO authenticated;

-- The limit for a conversation; NULL for a direct chat (not limited here).
CREATE OR REPLACE FUNCTION public.qguard_member_limit(p_conversation_id UUID)
RETURNS INTEGER AS $$
  SELECT l.max_members
  FROM public.messaging_conversations c
  JOIN public.messaging_conversation_limits l ON l.kind = CASE
    WHEN c.conversation_type = 'group' THEN 'group'
    WHEN c.conversation_type = 'channel' AND c.member_posting THEN 'large_group'
    WHEN c.conversation_type = 'channel' THEN 'channel'
  END
  WHERE c.id = p_conversation_id;
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_member_limit(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.qguard_member_limit(UUID) TO authenticated;

-- Kept for callers of migration 043; the channel kind's limit.
CREATE OR REPLACE FUNCTION public.qguard_channel_reader_limit()
RETURNS INTEGER AS $$
  SELECT COALESCE((SELECT l.max_members FROM public.messaging_conversation_limits l WHERE l.kind = 'channel'), 1000);
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

-- Once per statement, after the rows are in: lock each conversation that
-- gained a person, then count its active people. The lock makes concurrent
-- additions queue, so two that each fit cannot together pass the limit. An
-- UPDATE counts only where someone became active (a reinstated row), so role
-- changes and device rebinding are never refused.
CREATE OR REPLACE FUNCTION public.qguard_enforce_member_limit()
RETURNS TRIGGER AS $$
DECLARE
  v_conversations UUID[];
  v_conversation UUID;
  v_limit INTEGER;
  v_count INTEGER;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    SELECT array_agg(DISTINCT n.conversation_id ORDER BY n.conversation_id) INTO v_conversations
    FROM new_rows n
    WHERE n.revoked_at IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM old_rows o
        WHERE o.conversation_id = n.conversation_id AND o.user_id = n.user_id AND o.revoked_at IS NULL
      );
  ELSE
    SELECT array_agg(DISTINCT n.conversation_id ORDER BY n.conversation_id) INTO v_conversations
    FROM new_rows n
    WHERE n.revoked_at IS NULL;
  END IF;
  FOREACH v_conversation IN ARRAY COALESCE(v_conversations, ARRAY[]::UUID[])
  LOOP
    PERFORM 1 FROM public.messaging_conversations c WHERE c.id = v_conversation FOR UPDATE;
    v_limit := public.qguard_member_limit(v_conversation);
    IF v_limit IS NULL THEN
      CONTINUE;
    END IF;
    SELECT count(DISTINCT m.user_id) INTO v_count
    FROM public.messaging_conversation_members m
    WHERE m.conversation_id = v_conversation AND m.revoked_at IS NULL;
    IF v_count > v_limit THEN
      RAISE EXCEPTION 'this conversation is full (at most % people)', v_limit
        USING ERRCODE = 'check_violation';
    END IF;
  END LOOP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_enforce_member_limit() FROM PUBLIC;

DROP TRIGGER IF EXISTS qguard_member_limit_insert ON public.messaging_conversation_members;
CREATE TRIGGER qguard_member_limit_insert
  AFTER INSERT ON public.messaging_conversation_members
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.qguard_enforce_member_limit();
DROP TRIGGER IF EXISTS qguard_member_limit_update ON public.messaging_conversation_members;
CREATE TRIGGER qguard_member_limit_update
  AFTER UPDATE ON public.messaging_conversation_members
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.qguard_enforce_member_limit();

-- Someone who restricted or blocked you cannot be put into a conversation by
-- you — neither as a new row nor by reinstating a revoked one. Joining with an
-- invite code (the person adds themselves) is unaffected.
CREATE OR REPLACE FUNCTION public.qguard_member_consent_guard()
RETURNS TRIGGER AS $$
DECLARE
  v_actor UUID := auth.uid();
BEGIN
  IF v_actor IS NULL OR NEW.user_id = v_actor OR NEW.revoked_at IS NOT NULL THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.revoked_at IS NULL THEN
    RETURN NEW;
  END IF;
  IF public.qguard_contact_state(NEW.user_id, v_actor) IN ('blocked', 'restricted') THEN
    RAISE EXCEPTION 'this person cannot be added to this conversation'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_member_consent_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS qguard_member_consent_guard ON public.messaging_conversation_members;
CREATE TRIGGER qguard_member_consent_guard
  BEFORE INSERT OR UPDATE ON public.messaging_conversation_members
  FOR EACH ROW EXECUTE FUNCTION public.qguard_member_consent_guard();

-- Invites: up to the largest limit, so an owner can hand one code to everyone.
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
      AND rel.relname = 'messaging_channel_invites'
      AND con.contype = 'c'
      AND pg_get_constraintdef(con.oid) ILIKE '%max_uses%'
  LOOP
    EXECUTE format('ALTER TABLE public.messaging_channel_invites DROP CONSTRAINT %I', v_name);
  END LOOP;
END $$;
ALTER TABLE public.messaging_channel_invites
  ADD CONSTRAINT messaging_channel_invites_max_uses_check CHECK (max_uses BETWEEN 1 AND 100000);

-- As migration 043, with the conversation's own limit (large group or channel).
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
  IF v_readers >= COALESCE(public.qguard_member_limit(v_invite.conversation_id), public.qguard_channel_reader_limit()) THEN
    RAISE EXCEPTION 'this conversation is full';
  END IF;
  INSERT INTO public.messaging_conversation_members (conversation_id, user_id, device_id, role)
  SELECT v_invite.conversation_id, v_user_id, d.id, 'member'
  FROM public.messaging_devices d
  WHERE d.user_id = v_user_id AND d.trust_state <> 'revoked' AND d.revoked_at IS NULL
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
REVOKE ALL ON FUNCTION public.join_messaging_channel(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.join_messaging_channel(TEXT) TO authenticated;
