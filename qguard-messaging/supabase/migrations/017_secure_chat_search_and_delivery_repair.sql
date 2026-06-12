-- Secure Chat search and delivery repair.
-- Restores username-aware contact search and grants RPC execution explicitly.

CREATE OR REPLACE FUNCTION public.search_messaging_users(p_query TEXT)
RETURNS TABLE (
  user_id UUID,
  display_name TEXT,
  username TEXT
) AS $$
WITH normalized AS (
  SELECT
    trim(COALESCE(p_query, '')) AS raw_query,
    regexp_replace(lower(trim(COALESCE(p_query, ''))), '^(qr:|qguard-user:)', '') AS lookup_query
)
SELECT
  p.id AS user_id,
  COALESCE(NULLIF(p.name, ''), NULLIF(p.username, ''), split_part(p.email, '@', 1), 'QGuard User') AS display_name,
  COALESCE(NULLIF(p.username, ''), split_part(p.email, '@', 1), p.id::TEXT) AS username
FROM public.profiles p
CROSS JOIN normalized n
WHERE p.id <> auth.uid()
  AND length(n.lookup_query) >= 2
  AND (
    p.id::TEXT = n.lookup_query
    OR lower(COALESCE(p.username, '')) LIKE n.lookup_query || '%'
    OR lower(ltrim(COALESCE(p.username, ''), '@')) LIKE n.lookup_query || '%'
    OR lower(COALESCE(p.name, '')) LIKE n.lookup_query || '%'
    OR lower(split_part(COALESCE(p.email, ''), '@', 1)) LIKE n.lookup_query || '%'
    OR lower(COALESCE(p.email, '')) = n.lookup_query
  )
ORDER BY
  CASE
    WHEN lower(COALESCE(p.username, '')) = n.lookup_query THEN 0
    WHEN lower(ltrim(COALESCE(p.username, ''), '@')) = n.lookup_query THEN 1
    WHEN lower(split_part(COALESCE(p.email, ''), '@', 1)) = n.lookup_query THEN 2
    WHEN lower(COALESCE(p.name, '')) = n.lookup_query THEN 3
    ELSE 4
  END,
  p.created_at DESC
LIMIT 10;
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.search_messaging_users(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.search_messaging_users(TEXT) TO authenticated;

REVOKE ALL ON FUNCTION public.claim_messaging_one_time_prekey(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.claim_messaging_one_time_prekey(UUID, UUID) TO authenticated;

NOTIFY pgrst, 'reload schema';
