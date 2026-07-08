-- Avatar directory visibility.
--
-- Settings has let users upload a profile avatar since 005, but both the
-- profiles row and the 'profile-avatars' storage object were readable by the
-- OWNER ONLY - so nobody else could ever see an avatar, and Secure Chat /
-- calls had nothing to render beside usernames.
--
-- This migration keeps the privacy-first posture while making avatars usable:
--   * profiles rows become readable by users you share a live conversation
--     with, or who have you in their contact list (same gate the device /
--     prekey registry already uses via shares_messaging_conversation).
--   * 'profile-avatars' objects follow the identical rule. Avatars are NOT
--     public: a stranger who has never messaged you still cannot fetch yours.
-- Writes (insert/update/delete) on both stay owner-only.

-- Visibility gate: self, shared live conversation, or an 'added' contact edge
-- in either direction. Reuses the SECURITY DEFINER helpers from 003 and 018
-- (messaging_contacts / conversation membership are owner-scoped by RLS).
CREATE OR REPLACE FUNCTION public.can_view_messaging_profile(
  p_viewer_user_id UUID,
  p_target_user_id UUID
)
RETURNS BOOLEAN AS $$
  SELECT
    p_viewer_user_id = p_target_user_id
    OR public.shares_messaging_conversation(p_viewer_user_id, p_target_user_id)
    OR public.is_messaging_contact(p_viewer_user_id, p_target_user_id)
    OR public.is_messaging_contact(p_target_user_id, p_viewer_user_id);
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.can_view_messaging_profile(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.can_view_messaging_profile(UUID, UUID) TO authenticated;

-- profiles: peers can read the directory row (username / name / avatar path).
-- The owner-only select policy from 019 stays; policies are OR'd.
DROP POLICY IF EXISTS qguard_profiles_peer_select ON public.profiles;
CREATE POLICY qguard_profiles_peer_select ON public.profiles
  FOR SELECT USING (
    auth.uid() IS NOT NULL
    AND public.can_view_messaging_profile(auth.uid(), id)
  );

-- profile-avatars storage: same visibility rule as the profiles row.
-- Object names are '<user_id>/avatar.webp'; the insert policy has always
-- forced the first folder segment to auth.uid(), so the uuid cast is safe.
DROP POLICY IF EXISTS profile_avatars_owner_select ON storage.objects;
DROP POLICY IF EXISTS profile_avatars_peer_select ON storage.objects;
CREATE POLICY profile_avatars_peer_select ON storage.objects
  FOR SELECT USING (
    bucket_id = 'profile-avatars'
    AND auth.uid() IS NOT NULL
    AND (
      auth.uid()::TEXT = (storage.foldername(name))[1]
      OR public.can_view_messaging_profile(auth.uid(), ((storage.foldername(name))[1])::UUID)
    )
  );

NOTIFY pgrst, 'reload schema';
