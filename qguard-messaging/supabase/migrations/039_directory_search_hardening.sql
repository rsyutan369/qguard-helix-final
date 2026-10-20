-- 039_directory_search_hardening.sql
--
-- Roadmap 6.3 (private contact discovery review —
-- docs/superpowers/specs/2026-10-19-metadata-protection-design.md §2).
--
-- `search_messaging_users` (migration 017) let any signed-in account:
--   * learn other users' email addresses: the LOCAL PART of every email was
--     prefix-matched and returned as the username fallback, so typing "jo"
--     listed accounts whose address starts with "jo";
--   * enumerate the whole directory: two-character prefixes, no rate limit.
--
-- This version keeps every way people actually find each other (username or
-- name prefix, an exact full email, a user id or QR code) and removes the two
-- leaks:
--   * an email matches only EXACTLY, and is never returned or derived into a
--     display value;
--   * at least 3 characters, and at most 60 searches per account per 5
--     minutes (a QR / exact-id lookup counts like any other).
-- A result's username is the username or, failing that, a short id — never a
-- piece of the email.

CREATE TABLE IF NOT EXISTS public.messaging_directory_search_log (
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  searched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_directory_search_log_user ON public.messaging_directory_search_log(user_id, searched_at DESC);
ALTER TABLE public.messaging_directory_search_log ENABLE ROW LEVEL SECURITY;
-- No policies: only the SECURITY DEFINER function below touches it.

CREATE OR REPLACE FUNCTION public.search_messaging_users(p_query TEXT)
RETURNS TABLE (
  user_id UUID,
  display_name TEXT,
  username TEXT
) AS $$
DECLARE
  v_caller UUID := auth.uid();
  v_lookup TEXT := regexp_replace(lower(trim(COALESCE(p_query, ''))), '^(qr:|qguard-user:)', '');
  v_recent INT;
BEGIN
  IF v_caller IS NULL OR length(v_lookup) < 3 THEN
    RETURN;
  END IF;

  DELETE FROM public.messaging_directory_search_log
   WHERE messaging_directory_search_log.user_id = v_caller
     AND searched_at < now() - interval '1 day';
  SELECT count(*) INTO v_recent
    FROM public.messaging_directory_search_log l
   WHERE l.user_id = v_caller AND l.searched_at > now() - interval '5 minutes';
  IF v_recent >= 60 THEN
    RAISE EXCEPTION 'Too many searches. Try again in a few minutes.' USING ERRCODE = 'P0001';
  END IF;
  INSERT INTO public.messaging_directory_search_log (user_id) VALUES (v_caller);

  RETURN QUERY
  SELECT
    p.id,
    COALESCE(NULLIF(p.name, ''), NULLIF(p.username, ''), 'QGuard User'),
    COALESCE(NULLIF(p.username, ''), 'user-' || left(replace(p.id::TEXT, '-', ''), 8))
  FROM public.profiles p
  WHERE p.id <> v_caller
    AND (
      p.id::TEXT = v_lookup
      OR lower(COALESCE(p.username, '')) LIKE v_lookup || '%'
      OR lower(ltrim(COALESCE(p.username, ''), '@')) LIKE ltrim(v_lookup, '@') || '%'
      OR lower(COALESCE(p.name, '')) LIKE v_lookup || '%'
      OR (position('@' IN v_lookup) > 1 AND lower(COALESCE(p.email, '')) = v_lookup)
    )
  ORDER BY
    CASE
      WHEN p.id::TEXT = v_lookup THEN 0
      WHEN lower(COALESCE(p.email, '')) = v_lookup THEN 0
      WHEN lower(ltrim(COALESCE(p.username, ''), '@')) = ltrim(v_lookup, '@') THEN 1
      WHEN lower(COALESCE(p.name, '')) = v_lookup THEN 2
      ELSE 3
    END,
    p.created_at DESC
  LIMIT 10;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.search_messaging_users(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.search_messaging_users(TEXT) TO authenticated;

NOTIFY pgrst, 'reload schema';
