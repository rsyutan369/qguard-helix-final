-- 040: conversation membership is granted, never taken (roadmap 7.1, groups).
--
-- Migration 001 created two permissive policies on messaging_conversation_members:
--   * messaging_members_insert_self  INSERT WITH CHECK (user_id = auth.uid())
--   * messaging_members_update_self  UPDATE USING (user_id = auth.uid())
-- Permissive policies are OR-ed, so any signed-in account that knew a
-- conversation's id could add itself to it, and a member whose rows were
-- revoked could clear its own revoked_at. Senders seal to every active member,
-- so a self-added row is a silent extra recipient. For a direct chat only past
-- participants know the id; for a group, a removed member does — which would
-- make removal meaningless.
--
-- After this migration:
--   * INSERT: only the conversation's owner adds rows — for itself, or for a
--     user it has as an 'added' contact — or an active member adds a row for
--     another of its OWN devices. Every row's device must belong to its user.
--     (Device rebinding after a re-key stays in the SECURITY DEFINER
--     reinstate_messaging_conversation_membership of migration 033.)
--   * UPDATE: only the owner, with the same device check. Members change their
--     own standing through leave_messaging_conversation below.
--   * Groups get leave (any member) and remove (owner) as SECURITY DEFINER
--     functions that only ever REVOKE rows.

CREATE OR REPLACE FUNCTION public.messaging_device_belongs_to(p_device_id UUID, p_user_id UUID)
RETURNS BOOLEAN AS $$
  SELECT p_device_id IS NULL OR EXISTS (
    SELECT 1
    FROM public.messaging_devices d
    WHERE d.id = p_device_id
      AND d.user_id = p_user_id
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.messaging_device_belongs_to(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.messaging_device_belongs_to(UUID, UUID) TO authenticated;

DROP POLICY IF EXISTS messaging_members_insert_self ON public.messaging_conversation_members;
DROP POLICY IF EXISTS messaging_members_owner_insert ON public.messaging_conversation_members;
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
        user_id = auth.uid()
        AND public.is_messaging_conversation_member(conversation_id, auth.uid())
      )
    )
  );

DROP POLICY IF EXISTS messaging_members_update_self ON public.messaging_conversation_members;
DROP POLICY IF EXISTS messaging_members_owner_update ON public.messaging_conversation_members;
CREATE POLICY messaging_members_owner_update ON public.messaging_conversation_members
  FOR UPDATE
  USING (public.owns_messaging_conversation(conversation_id, auth.uid()))
  WITH CHECK (
    public.owns_messaging_conversation(conversation_id, auth.uid())
    AND public.messaging_device_belongs_to(device_id, user_id)
  );

-- Leave a group: revoke every row the caller holds in it. The owner cannot
-- leave (it would strand the group without anyone able to manage it).
CREATE OR REPLACE FUNCTION public.leave_messaging_conversation(p_conversation_id UUID)
RETURNS INTEGER AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_type TEXT;
  v_owner UUID;
  v_count INTEGER;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;
  SELECT c.conversation_type, c.owner_user_id INTO v_type, v_owner
  FROM public.messaging_conversations c
  WHERE c.id = p_conversation_id;
  IF v_type IS DISTINCT FROM 'group' OR NOT public.is_messaging_conversation_member(p_conversation_id, v_user_id) THEN
    RAISE EXCEPTION 'not a member of this group';
  END IF;
  IF v_owner = v_user_id THEN
    RAISE EXCEPTION 'the group owner cannot leave';
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

-- Remove a member from a group (owner only). Revokes, never deletes: the rows
-- stay as the record of who was a member, and nothing can reinstate them
-- (migration 033's rebind only follows ACTIVE membership for groups).
CREATE OR REPLACE FUNCTION public.remove_messaging_conversation_member(p_conversation_id UUID, p_user_id UUID)
RETURNS INTEGER AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_type TEXT;
  v_owner UUID;
  v_count INTEGER;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;
  SELECT c.conversation_type, c.owner_user_id INTO v_type, v_owner
  FROM public.messaging_conversations c
  WHERE c.id = p_conversation_id;
  IF v_type IS DISTINCT FROM 'group' OR v_owner IS DISTINCT FROM v_user_id THEN
    RAISE EXCEPTION 'only the group owner can remove members';
  END IF;
  IF p_user_id = v_user_id THEN
    RAISE EXCEPTION 'the group owner cannot remove themselves';
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

REVOKE ALL ON FUNCTION public.leave_messaging_conversation(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.remove_messaging_conversation_member(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.leave_messaging_conversation(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.remove_messaging_conversation_member(UUID, UUID) TO authenticated;
