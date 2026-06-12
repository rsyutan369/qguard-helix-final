-- Secure Chat public bundle visibility repair.
-- Allows existing conversation participants to read the public device and active
-- signed-prekey rows required to encrypt replies, even if a local contact row is
-- missing or has not refreshed yet.

CREATE OR REPLACE FUNCTION public.shares_messaging_conversation(
  p_owner_user_id UUID,
  p_peer_user_id UUID
)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.messaging_conversation_members owner_member
    JOIN public.messaging_conversation_members peer_member
      ON peer_member.conversation_id = owner_member.conversation_id
    WHERE owner_member.user_id = p_owner_user_id
      AND owner_member.revoked_at IS NULL
      AND peer_member.user_id = p_peer_user_id
      AND peer_member.revoked_at IS NULL
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.shares_messaging_conversation(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.shares_messaging_conversation(UUID, UUID) TO authenticated;

DROP POLICY IF EXISTS messaging_devices_conversation_select ON public.messaging_devices;
CREATE POLICY messaging_devices_conversation_select ON public.messaging_devices
  FOR SELECT USING (
    auth.uid() = user_id
    OR (
      trust_state <> 'revoked'
      AND public.shares_messaging_conversation(auth.uid(), user_id)
    )
  );

DROP POLICY IF EXISTS messaging_signed_prekeys_conversation_select ON public.messaging_signed_prekeys;
CREATE POLICY messaging_signed_prekeys_conversation_select ON public.messaging_signed_prekeys
  FOR SELECT USING (
    auth.uid() = user_id
    OR (
      is_active = true
      AND public.shares_messaging_conversation(auth.uid(), user_id)
    )
  );

NOTIFY pgrst, 'reload schema';
