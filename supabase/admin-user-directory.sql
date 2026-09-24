-- ============================================================================
-- Owner Admin > Users — authoritative identity, session and MFA reads
-- ============================================================================
--
-- The Users console used to measure sessions from public.user_sessions and
-- MFA from profiles.mfa_required. user_sessions is only written when a user
-- opens Settings, so it held 0 rows while Supabase Auth held 41 live sessions;
-- mfa_required is a policy flag, not an enrollment. "Force logout" revoked
-- rows in that empty table and never touched a real session.
--
-- Supabase Auth (the auth schema) is the source of truth for sign-in, bans,
-- sessions and MFA factors, and PostgREST does not expose it. These three
-- SECURITY DEFINER functions are the only bridge, and ONLY service_role may
-- execute them (the admin API calls them with the service client after
-- requireOwner). Nothing here writes user data except the explicit revoke.
--
-- Idempotent: safe to re-run.
-- ============================================================================

-- One row per auth user: sign-in, confirmation, ban, providers, live session
-- count + last activity, and verified MFA factors.
CREATE OR REPLACE FUNCTION public.admin_user_auth_directory()
RETURNS TABLE (
  user_id uuid,
  email text,
  created_at timestamptz,
  last_sign_in_at timestamptz,
  email_confirmed_at timestamptz,
  invited_at timestamptz,
  banned_until timestamptz,
  is_anonymous boolean,
  providers text[],
  app_role text,
  session_count integer,
  aal2_session_count integer,
  last_session_activity_at timestamptz,
  last_session_ip text,
  last_session_user_agent text,
  mfa_verified_factors integer,
  mfa_factor_types text[]
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  WITH live_sessions AS (
    SELECT
      ss.user_id,
      ss.aal::text AS aal,
      host(ss.ip) AS ip,
      ss.user_agent,
      -- A session's last activity is its latest token refresh. refresh_tokens
      -- rotate on every refresh, so max(created_at) per session is the
      -- freshest signal; refreshed_at is timestamp WITHOUT time zone (UTC).
      GREATEST(
        ss.created_at,
        COALESCE(ss.updated_at, ss.created_at),
        COALESCE(ss.refreshed_at AT TIME ZONE 'utc', ss.created_at),
        COALESCE(rt.last_refresh_at, ss.created_at)
      ) AS last_activity_at
    FROM auth.sessions ss
    LEFT JOIN LATERAL (
      SELECT max(r.created_at) AS last_refresh_at
      FROM auth.refresh_tokens r
      WHERE r.session_id = ss.id
    ) rt ON TRUE
    WHERE ss.not_after IS NULL OR ss.not_after > now()
  ),
  session_rollup AS (
    SELECT
      ls.user_id,
      count(*)::int AS session_count,
      count(*) FILTER (WHERE ls.aal = 'aal2')::int AS aal2_session_count,
      max(ls.last_activity_at) AS last_activity_at,
      (array_agg(ls.ip ORDER BY ls.last_activity_at DESC NULLS LAST))[1] AS last_ip,
      (array_agg(ls.user_agent ORDER BY ls.last_activity_at DESC NULLS LAST))[1] AS last_user_agent
    FROM live_sessions ls
    GROUP BY ls.user_id
  ),
  factor_rollup AS (
    SELECT
      f.user_id,
      count(*)::int AS verified_count,
      array_agg(DISTINCT f.factor_type::text) AS factor_types
    FROM auth.mfa_factors f
    WHERE f.status::text = 'verified'
    GROUP BY f.user_id
  )
  SELECT
    u.id,
    u.email::text,
    u.created_at,
    u.last_sign_in_at,
    u.email_confirmed_at,
    u.invited_at,
    u.banned_until,
    COALESCE(u.is_anonymous, FALSE),
    COALESCE(
      ARRAY(SELECT jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(u.raw_app_meta_data -> 'providers') = 'array'
          THEN u.raw_app_meta_data -> 'providers' ELSE '[]'::jsonb END)),
      ARRAY[]::text[]
    ),
    NULLIF(u.raw_app_meta_data ->> 'role', ''),
    COALESCE(s.session_count, 0),
    COALESCE(s.aal2_session_count, 0),
    s.last_activity_at,
    s.last_ip,
    s.last_user_agent,
    COALESCE(f.verified_count, 0),
    COALESCE(f.factor_types, ARRAY[]::text[])
  FROM auth.users u
  LEFT JOIN session_rollup s ON s.user_id = u.id
  LEFT JOIN factor_rollup f ON f.user_id = u.id
  WHERE u.deleted_at IS NULL;
$$;

-- Live sessions of ONE user, newest activity first (detail drawer).
CREATE OR REPLACE FUNCTION public.admin_user_auth_sessions(p_user_id uuid)
RETURNS TABLE (
  session_id uuid,
  created_at timestamptz,
  last_activity_at timestamptz,
  not_after timestamptz,
  aal text,
  ip text,
  user_agent text,
  refresh_count integer
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT
    ss.id,
    ss.created_at,
    GREATEST(
      ss.created_at,
      COALESCE(ss.updated_at, ss.created_at),
      COALESCE(ss.refreshed_at AT TIME ZONE 'utc', ss.created_at),
      COALESCE(rt.last_refresh_at, ss.created_at)
    ) AS last_activity_at,
    ss.not_after,
    ss.aal::text,
    host(ss.ip),
    ss.user_agent,
    GREATEST(COALESCE(rt.token_count, 0) - 1, 0)::int
  FROM auth.sessions ss
  LEFT JOIN LATERAL (
    SELECT max(r.created_at) AS last_refresh_at, count(*) AS token_count
    FROM auth.refresh_tokens r
    WHERE r.session_id = ss.id
  ) rt ON TRUE
  WHERE ss.user_id = p_user_id
    AND (ss.not_after IS NULL OR ss.not_after > now())
  ORDER BY 3 DESC
  LIMIT 100;
$$;

-- Revoke EVERY session of a user. Deleting auth.sessions cascades to their
-- refresh tokens (refresh_tokens_session_id_fkey ON DELETE CASCADE), so no
-- device can mint a new access token; legacy session-less refresh tokens are
-- revoked explicitly. Returns the number of sessions ended.
CREATE OR REPLACE FUNCTION public.admin_revoke_user_sessions(p_user_id uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_count integer;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'admin_revoke_user_sessions: user id is required' USING ERRCODE = '22023';
  END IF;
  DELETE FROM auth.sessions WHERE user_id = p_user_id;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  UPDATE auth.refresh_tokens
     SET revoked = TRUE, updated_at = now()
   WHERE user_id = p_user_id::text AND revoked IS DISTINCT FROM TRUE;
  RETURN v_count;
END;
$$;

REVOKE ALL ON FUNCTION public.admin_user_auth_directory() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.admin_user_auth_sessions(uuid) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.admin_revoke_user_sessions(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_user_auth_directory() TO service_role;
GRANT EXECUTE ON FUNCTION public.admin_user_auth_sessions(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.admin_revoke_user_sessions(uuid) TO service_role;

COMMENT ON FUNCTION public.admin_user_auth_directory() IS
  'Owner Admin Users: auth sign-in/ban/confirmation, live session rollup and verified MFA factors per user. service_role only.';
COMMENT ON FUNCTION public.admin_user_auth_sessions(uuid) IS
  'Owner Admin Users: live auth sessions of one user. service_role only.';
COMMENT ON FUNCTION public.admin_revoke_user_sessions(uuid) IS
  'Owner Admin Users: end every auth session (and refresh token) of one user. service_role only.';
