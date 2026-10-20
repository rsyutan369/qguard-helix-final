-- 042: group admins, ownership transfer and owner-only naming (roadmap 7.1, owner decision 2026-10-20).
--
-- Decisions: only the owner renames a group; a group has at most 3 admins; the
-- owner can hand ownership to another member.
--
--   * Admins (role 'admin' on every one of their device rows) may add their own
--     contacts and remove plain members. They cannot remove the owner or other
--     admins, rename, appoint admins or transfer ownership.
--   * Roles can no longer be chosen by whoever writes a row: a trigger derives
--     the role of every inserted row from the conversation (owner → 'owner',
--     an existing admin → 'admin', anyone else → 'member') and freezes it on
--     UPDATE unless one of the functions below is changing it. Before this, the
--     "add my own other device" path of migration 040 accepted any role.
--   * owner_user_id changes only through transfer_messaging_group_ownership,
--     and every owner is recorded in messaging_conversation_owner_history so a
--     client can check that a name message came from whoever owned the group
--     WHEN it was sent (names are end-to-end encrypted; the server never sees
--     them, so this check is the client's).

-- ---------------------------------------------------------------------------
-- Ownership history
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.messaging_conversation_owner_history (
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  owner_user_id UUID NOT NULL,
  owner_from TIMESTAMPTZ NOT NULL,
  owner_until TIMESTAMPTZ,
  PRIMARY KEY (conversation_id, owner_from)
);

ALTER TABLE public.messaging_conversation_owner_history ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS messaging_owner_history_member_read ON public.messaging_conversation_owner_history;
CREATE POLICY messaging_owner_history_member_read ON public.messaging_conversation_owner_history
  FOR SELECT USING (public.is_messaging_conversation_member(conversation_id, auth.uid()));
REVOKE INSERT, UPDATE, DELETE ON public.messaging_conversation_owner_history FROM authenticated, anon;
GRANT SELECT ON public.messaging_conversation_owner_history TO authenticated;

-- Existing conversations: their creator has owned them since creation.
INSERT INTO public.messaging_conversation_owner_history (conversation_id, owner_user_id, owner_from)
SELECT c.id, c.owner_user_id, c.created_at
FROM public.messaging_conversations c
ON CONFLICT DO NOTHING;

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
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

DROP TRIGGER IF EXISTS qguard_conversation_owner_guard ON public.messaging_conversations;
CREATE TRIGGER qguard_conversation_owner_guard
  AFTER INSERT ON public.messaging_conversations
  FOR EACH ROW EXECUTE FUNCTION public.qguard_conversation_owner_guard();
DROP TRIGGER IF EXISTS qguard_conversation_owner_guard_update ON public.messaging_conversations;
CREATE TRIGGER qguard_conversation_owner_guard_update
  BEFORE UPDATE ON public.messaging_conversations
  FOR EACH ROW EXECUTE FUNCTION public.qguard_conversation_owner_guard();

-- ---------------------------------------------------------------------------
-- Roles on member rows
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.is_messaging_group_admin(p_conversation_id UUID, p_user_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.messaging_conversation_members m
    WHERE m.conversation_id = p_conversation_id
      AND m.user_id = p_user_id
      AND m.role = 'admin'
      AND m.revoked_at IS NULL
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.is_messaging_group_admin(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_messaging_group_admin(UUID, UUID) TO authenticated;

CREATE OR REPLACE FUNCTION public.qguard_member_role_guard()
RETURNS TRIGGER AS $$
DECLARE
  v_owner UUID;
BEGIN
  SELECT c.owner_user_id INTO v_owner FROM public.messaging_conversations c WHERE c.id = NEW.conversation_id;
  IF TG_OP = 'INSERT' THEN
    NEW.role := CASE
      WHEN NEW.user_id = v_owner THEN 'owner'
      WHEN public.is_messaging_group_admin(NEW.conversation_id, NEW.user_id) THEN 'admin'
      ELSE 'member'
    END;
    RETURN NEW;
  END IF;
  IF NEW.conversation_id IS DISTINCT FROM OLD.conversation_id OR NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    RAISE EXCEPTION 'a membership row cannot move to another conversation or user';
  END IF;
  IF NEW.role IS DISTINCT FROM OLD.role AND current_setting('qguard.member_role_change', true) IS DISTINCT FROM 'on' THEN
    NEW.role := OLD.role;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

DROP TRIGGER IF EXISTS qguard_member_role_guard ON public.messaging_conversation_members;
CREATE TRIGGER qguard_member_role_guard
  BEFORE INSERT OR UPDATE ON public.messaging_conversation_members
  FOR EACH ROW EXECUTE FUNCTION public.qguard_member_role_guard();

-- Admins add their own contacts too (otherwise as migration 040).
DROP POLICY IF EXISTS messaging_members_insert ON public.messaging_conversation_members;
CREATE POLICY messaging_members_insert ON public.messaging_conversation_members
  FOR INSERT WITH CHECK (
    public.messaging_device_belongs_to(device_id, user_id)
    AND (
      (
        public.owns_messaging_conversation(conversation_id, auth.uid())
        AND (user_id = auth.uid() OR public.is_messaging_contact(auth.uid(), user_id))
      )
      OR (
        public.is_messaging_group_admin(conversation_id, auth.uid())
        AND public.is_messaging_contact(auth.uid(), user_id)
      )
      OR (
        user_id = auth.uid()
        AND public.is_messaging_conversation_member(conversation_id, auth.uid())
      )
    )
  );

-- ---------------------------------------------------------------------------
-- Functions
-- ---------------------------------------------------------------------------
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
  IF v_type IS DISTINCT FROM 'group' THEN
    RAISE EXCEPTION 'not a group';
  END IF;
  RETURN v_owner;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_group_for_update(UUID) FROM PUBLIC;

-- Remove a member: the owner removes anyone but itself; an admin removes plain members.
CREATE OR REPLACE FUNCTION public.remove_messaging_conversation_member(p_conversation_id UUID, p_user_id UUID)
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
  IF p_user_id = v_owner THEN
    RAISE EXCEPTION 'the group owner cannot be removed';
  END IF;
  IF v_user_id <> v_owner THEN
    IF NOT public.is_messaging_group_admin(p_conversation_id, v_user_id) THEN
      RAISE EXCEPTION 'only the group owner or an admin can remove members';
    END IF;
    IF public.is_messaging_group_admin(p_conversation_id, p_user_id) THEN
      RAISE EXCEPTION 'only the group owner can remove an admin';
    END IF;
  END IF;
  UPDATE public.messaging_conversation_members m
  SET revoked_at = now()
  WHERE m.conversation_id = p_conversation_id
    AND m.user_id = p_user_id
    AND m.revoked_at IS NULL;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Appoint or dismiss an admin (owner only, at most 3 admins).
CREATE OR REPLACE FUNCTION public.set_messaging_group_admin(p_conversation_id UUID, p_user_id UUID, p_admin BOOLEAN)
RETURNS INTEGER AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_owner UUID;
  v_admins INTEGER;
  v_count INTEGER;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;
  v_owner := public.qguard_group_for_update(p_conversation_id);
  IF v_owner IS DISTINCT FROM v_user_id THEN
    RAISE EXCEPTION 'only the group owner can appoint admins';
  END IF;
  IF p_user_id = v_owner THEN
    RAISE EXCEPTION 'the owner is not an admin';
  END IF;
  IF NOT public.is_messaging_conversation_member(p_conversation_id, p_user_id) THEN
    RAISE EXCEPTION 'not a member of this group';
  END IF;
  IF p_admin AND NOT public.is_messaging_group_admin(p_conversation_id, p_user_id) THEN
    SELECT count(DISTINCT m.user_id) INTO v_admins
    FROM public.messaging_conversation_members m
    WHERE m.conversation_id = p_conversation_id AND m.role = 'admin' AND m.revoked_at IS NULL;
    IF v_admins >= 3 THEN
      RAISE EXCEPTION 'a group can have at most 3 admins';
    END IF;
  END IF;
  PERFORM set_config('qguard.member_role_change', 'on', true);
  UPDATE public.messaging_conversation_members m
  SET role = CASE WHEN p_admin THEN 'admin' ELSE 'member' END
  WHERE m.conversation_id = p_conversation_id
    AND m.user_id = p_user_id
    AND m.revoked_at IS NULL;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  PERFORM set_config('qguard.member_role_change', 'off', true);
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Hand ownership to another active member. The previous owner stays in the
-- group as an admin when there is room, otherwise as a member.
CREATE OR REPLACE FUNCTION public.transfer_messaging_group_ownership(p_conversation_id UUID, p_new_owner UUID)
RETURNS BOOLEAN AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_owner UUID;
  v_admins INTEGER;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;
  v_owner := public.qguard_group_for_update(p_conversation_id);
  IF v_owner IS DISTINCT FROM v_user_id THEN
    RAISE EXCEPTION 'only the group owner can transfer ownership';
  END IF;
  IF p_new_owner = v_owner THEN
    RAISE EXCEPTION 'already the owner';
  END IF;
  IF NOT public.is_messaging_conversation_member(p_conversation_id, p_new_owner) THEN
    RAISE EXCEPTION 'the new owner must be a member of this group';
  END IF;

  PERFORM set_config('qguard.ownership_transfer', 'on', true);
  UPDATE public.messaging_conversations SET owner_user_id = p_new_owner, updated_at = now() WHERE id = p_conversation_id;
  PERFORM set_config('qguard.ownership_transfer', 'off', true);

  PERFORM set_config('qguard.member_role_change', 'on', true);
  UPDATE public.messaging_conversation_members m
  SET role = 'owner'
  WHERE m.conversation_id = p_conversation_id AND m.user_id = p_new_owner AND m.revoked_at IS NULL;
  SELECT count(DISTINCT m.user_id) INTO v_admins
  FROM public.messaging_conversation_members m
  WHERE m.conversation_id = p_conversation_id AND m.role = 'admin' AND m.revoked_at IS NULL;
  UPDATE public.messaging_conversation_members m
  SET role = CASE WHEN v_admins < 3 THEN 'admin' ELSE 'member' END
  WHERE m.conversation_id = p_conversation_id AND m.user_id = v_owner AND m.revoked_at IS NULL;
  PERFORM set_config('qguard.member_role_change', 'off', true);
  RETURN TRUE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.remove_messaging_conversation_member(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.set_messaging_group_admin(UUID, UUID, BOOLEAN) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.transfer_messaging_group_ownership(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.remove_messaging_conversation_member(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.set_messaging_group_admin(UUID, UUID, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION public.transfer_messaging_group_ownership(UUID, UUID) TO authenticated;
