-- Apply in the Supabase SQL editor on projects that already ran
-- vault-security-hardening.sql. Safe to rerun. Projects without the legacy
-- function need no change. Existing share links and rows are untouched.

BEGIN;

DO $$
DECLARE
  share_verifier regprocedure := to_regprocedure('public.verify_share_link_access(uuid,text)');
BEGIN
  IF share_verifier IS NULL THEN
    RETURN;
  END IF;

  REVOKE ALL ON FUNCTION public.verify_share_link_access(UUID, TEXT) FROM PUBLIC, anon, authenticated;
  GRANT EXECUTE ON FUNCTION public.verify_share_link_access(UUID, TEXT) TO service_role;

  IF has_function_privilege('anon', share_verifier, 'EXECUTE')
    OR has_function_privilege('authenticated', share_verifier, 'EXECUTE') THEN
    RAISE EXCEPTION 'Client roles still inherit EXECUTE on the legacy vault share verifier';
  END IF;
END;
$$;

NOTIFY pgrst, 'reload schema';

COMMIT;
