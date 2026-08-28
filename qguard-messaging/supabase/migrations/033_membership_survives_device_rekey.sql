-- 033: Conversation membership must survive a device re-key
--
-- Symptom this fixes: after a device re-key (the FIPS 203 cutover, a reinstall,
-- or a manual "Delete device" in the Device Trust Center) the account could
-- still sign in, still register keys, still open the thread -- and every send
-- failed with
--
--   new row violates row-level security policy for table
--   "messaging_message_envelopes" (42501)
--
-- surfaced to the user only as a generic "Encryption failed".
--
-- Root cause: membership is keyed per DEVICE -- messaging_conversation_members
-- has PRIMARY KEY (conversation_id, user_id, device_id) -- while the envelope
-- INSERT policy (004/007) gates on the USER:
--
--   AND public.is_messaging_conversation_member(conversation_id, sender_user_id)
--   AND public.is_messaging_conversation_member(conversation_id, recipient_user_id)
--
-- Retiring a device tears that membership down:
--   * revoke_messaging_device  sets messaging_conversation_members.revoked_at
--     for every row bound to the retired device;
--   * delete_messaging_device  DELETEs those rows outright.
-- Both are correct about the OLD device. Neither ever binds the membership to
-- the REPLACEMENT device, and nothing else does either: the bootstrap's
-- ensureStarterConversation only touches the caller's oldest OWNED
-- conversation, so the thread people actually use is left with zero active
-- members. The account is then permanently unable to send into any existing
-- conversation, with no UI anywhere that can repair it.
--
-- Fix: bind membership to the current device at registration time, from
-- evidence the account really belongs to the conversation.
--
-- Deliberately NOT a blanket "re-add everyone": a member removed on purpose
-- must stay removed. Reinstatement is limited to
--   (a) conversations where the account still holds an ACTIVE membership on
--       some other device -- it is provably still a member, this device just
--       is not bound yet; or
--   (b) DIRECT (two-party) conversations the account owns or has exchanged
--       envelopes in -- these have no "remove member" semantics to subvert.
-- Group conversations whose every membership row was revoked are left alone;
-- the owner re-adds the member explicitly.

-- Shared binder. Internal: callers are responsible for authorising p_user_id.
CREATE OR REPLACE FUNCTION public.qguard_bind_messaging_membership(
  p_user_id UUID,
  p_device_id UUID
)
RETURNS INTEGER AS $$
DECLARE
  v_bound INTEGER := 0;
BEGIN
  IF p_user_id IS NULL OR p_device_id IS NULL THEN
    RETURN 0;
  END IF;

  -- Never bind to a device that is not the account's own, or that is revoked:
  -- the envelope policy rejects a revoked sender_device_id anyway, so binding
  -- one would manufacture membership that still cannot send.
  IF NOT EXISTS (
    SELECT 1
    FROM public.messaging_devices d
    WHERE d.id = p_device_id
      AND d.user_id = p_user_id
      AND d.trust_state <> 'revoked'
      AND d.revoked_at IS NULL
  ) THEN
    RETURN 0;
  END IF;

  WITH entitled AS (
    SELECT
      c.id AS conversation_id,
      CASE WHEN c.owner_user_id = p_user_id THEN 'owner' ELSE 'member' END AS member_role
    FROM public.messaging_conversations c
    WHERE
      -- (a) still an active member on another device
      EXISTS (
        SELECT 1
        FROM public.messaging_conversation_members m
        WHERE m.conversation_id = c.id
          AND m.user_id = p_user_id
          AND m.revoked_at IS NULL
      )
      -- (b) a direct thread this account owns or has demonstrably used
      OR (
        c.conversation_type = 'direct'
        AND (
          c.owner_user_id = p_user_id
          OR EXISTS (
            SELECT 1
            FROM public.messaging_message_envelopes e
            WHERE e.conversation_id = c.id
              AND (e.sender_user_id = p_user_id OR e.recipient_user_id = p_user_id)
          )
          OR EXISTS (
            SELECT 1
            FROM public.messaging_conversation_members m2
            WHERE m2.conversation_id = c.id
              AND m2.user_id = p_user_id
          )
        )
      )
  ), bound AS (
    INSERT INTO public.messaging_conversation_members AS m
      (conversation_id, user_id, device_id, role)
    SELECT e.conversation_id, p_user_id, p_device_id, e.member_role
    FROM entitled e
    ON CONFLICT (conversation_id, user_id, device_id) DO UPDATE
      SET revoked_at = NULL,
          role = EXCLUDED.role
      WHERE m.revoked_at IS NOT NULL
    RETURNING 1
  )
  SELECT count(*) INTO v_bound FROM bound;

  RETURN v_bound;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Called by the client immediately after register_messaging_device, so a
-- freshly re-keyed device rejoins the account's own threads on first launch.
CREATE OR REPLACE FUNCTION public.reinstate_messaging_conversation_membership(p_device_id UUID)
RETURNS INTEGER AS $$
DECLARE
  v_user_id UUID := auth.uid();
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;
  RETURN public.qguard_bind_messaging_membership(v_user_id, p_device_id);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Retiring a device must not stand the account down from its own conversations
-- when another usable device is still registered. Rebinding here closes the
-- window between the retirement and the next launch's registration pass.
CREATE OR REPLACE FUNCTION public.qguard_rebind_membership_after_retirement(p_user_id UUID)
RETURNS INTEGER AS $$
DECLARE
  v_device_id UUID;
BEGIN
  SELECT d.id INTO v_device_id
  FROM public.messaging_devices d
  WHERE d.user_id = p_user_id
    AND d.trust_state <> 'revoked'
    AND d.revoked_at IS NULL
  ORDER BY d.last_seen_at DESC NULLS LAST, d.created_at DESC
  LIMIT 1;

  IF v_device_id IS NULL THEN
    RETURN 0;
  END IF;

  RETURN public.qguard_bind_messaging_membership(p_user_id, v_device_id);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- revoke_messaging_device: unchanged behaviour for the retired device, plus a
-- rebind onto a surviving device.
CREATE OR REPLACE FUNCTION public.revoke_messaging_device(p_device_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_revoked_device_id UUID;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;

  UPDATE public.messaging_devices
  SET trust_state = 'revoked',
      revoked_at = COALESCE(revoked_at, now()),
      last_seen_at = now()
  WHERE id = p_device_id
    AND user_id = v_user_id
  RETURNING id INTO v_revoked_device_id;

  IF v_revoked_device_id IS NULL THEN
    RETURN false;
  END IF;

  UPDATE public.messaging_signed_prekeys
  SET is_active = false
  WHERE user_id = v_user_id
    AND device_id = p_device_id;

  UPDATE public.messaging_one_time_prekeys
  SET consumed_at = COALESCE(consumed_at, now())
  WHERE user_id = v_user_id
    AND device_id = p_device_id
    AND consumed_at IS NULL;

  UPDATE public.messaging_conversation_members
  SET revoked_at = COALESCE(revoked_at, now())
  WHERE user_id = v_user_id
    AND device_id = p_device_id
    AND revoked_at IS NULL;

  UPDATE public.messaging_file_grants
  SET revoked_at = COALESCE(revoked_at, now())
  WHERE recipient_user_id = v_user_id
    AND recipient_device_id = p_device_id
    AND revoked_at IS NULL;

  PERFORM public.qguard_rebind_membership_after_retirement(v_user_id);

  RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- delete_messaging_device: same addition. The DELETE of the device-bound
-- membership rows stays -- those rows reference a device row that is about to
-- disappear -- but the account is rebound to a surviving device first.
CREATE OR REPLACE FUNCTION public.delete_messaging_device(p_device_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_deleted_count INTEGER;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.messaging_devices d
    WHERE d.id = p_device_id
      AND d.user_id = v_user_id
  ) THEN
    RETURN false;
  END IF;

  PERFORM public.revoke_messaging_device(p_device_id);

  DELETE FROM public.messaging_device_link_requests
  WHERE user_id = v_user_id
    AND (
      approved_device_id = p_device_id
      OR approved_by_device_id = p_device_id
      OR requested_fingerprint IN (
        SELECT d.fingerprint
        FROM public.messaging_devices d
        WHERE d.id = p_device_id
          AND d.user_id = v_user_id
      )
    );

  DELETE FROM public.messaging_conversation_members
  WHERE user_id = v_user_id
    AND device_id = p_device_id;

  DELETE FROM public.messaging_signed_prekeys
  WHERE user_id = v_user_id
    AND device_id = p_device_id;

  DELETE FROM public.messaging_one_time_prekeys
  WHERE user_id = v_user_id
    AND device_id = p_device_id;

  DELETE FROM public.messaging_devices
  WHERE id = p_device_id
    AND user_id = v_user_id;

  GET DIAGNOSTICS v_deleted_count = ROW_COUNT;

  PERFORM public.qguard_rebind_membership_after_retirement(v_user_id);

  RETURN v_deleted_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.qguard_bind_messaging_membership(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.qguard_rebind_membership_after_retirement(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.reinstate_messaging_conversation_membership(UUID) FROM PUBLIC;

-- Only the auth.uid()-scoped wrapper is reachable by the app; the binder and
-- the rebinder take an arbitrary p_user_id and stay service-side.
GRANT EXECUTE ON FUNCTION public.reinstate_messaging_conversation_membership(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qguard_bind_messaging_membership(UUID, UUID) TO service_role;
GRANT EXECUTE ON FUNCTION public.qguard_rebind_membership_after_retirement(UUID) TO service_role;
