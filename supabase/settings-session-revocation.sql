-- Settings > Security > Active sessions: end ONE of a user's own Auth sessions.
--
-- Apply once in the Supabase SQL editor (idempotent). Until it is applied,
-- DELETE /api/v1/profile/sessions/:id answers 503 SESSION_REVOCATION_UNAVAILABLE
-- and changes nothing — it no longer pretends a session was revoked.
--
-- Deleting the auth.sessions row cascades to that session's refresh tokens
-- (refresh_tokens_session_id_fkey ON DELETE CASCADE), so the device cannot
-- mint a new access token. The user id is part of the predicate: a caller can
-- only ever end a session that belongs to the user the API authenticated.
-- service_role only — the API calls it after verifying the caller's JWT and
-- that the Settings row belongs to them.

CREATE OR REPLACE FUNCTION public.qguard_revoke_auth_session(p_user_id uuid, p_session_id uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_count integer;
BEGIN
  IF p_user_id IS NULL OR p_session_id IS NULL THEN
    RAISE EXCEPTION 'qguard_revoke_auth_session: user id and session id are required' USING ERRCODE = '22023';
  END IF;
  DELETE FROM auth.sessions WHERE id = p_session_id AND user_id = p_user_id;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;

REVOKE ALL ON FUNCTION public.qguard_revoke_auth_session(uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.qguard_revoke_auth_session(uuid, uuid) TO service_role;

COMMENT ON FUNCTION public.qguard_revoke_auth_session(uuid, uuid) IS
  'Settings: end one Auth session (and its refresh tokens) of one user. service_role only.';
