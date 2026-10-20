-- 037_mfa_recovery_codes_sha3.sql
--
-- Roadmap 4.4: MFA recovery codes are hashed with SHA3-256 (the platform's
-- approved hash) instead of SHA-256.
--
-- New codes are stored as 'sha3:' || hex(SHA3-256(salt || CODE)). Codes made
-- before this keep their SHA-256 hash (it cannot be converted — the code
-- itself is not stored) and still work until used or regenerated. The prefix
-- keeps the two apart: a SHA3 hash can never be mistaken for a SHA-256 one.
--
-- Rollout order: the app asks `qguard_mfa_recovery_hash_schemes()` before it
-- writes a SHA3 hash, and keeps writing SHA-256 while that function does not
-- exist. So the app may ship before or after this migration; codes keep
-- working either way.
--
-- pgcrypto's digest() takes 'sha3-256' with OpenSSL 1.1.1 or later (every
-- supported Postgres image). Reviewed against 005 (the function below is 005's
-- with only the hash comparison changed).

CREATE OR REPLACE FUNCTION public.qguard_mfa_recovery_hash_schemes()
RETURNS TEXT[] AS $$
  SELECT ARRAY['sha3-256', 'sha256']::TEXT[];
$$ LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path = public;

GRANT EXECUTE ON FUNCTION public.qguard_mfa_recovery_hash_schemes() TO authenticated;

CREATE OR REPLACE FUNCTION public.consume_qguard_mfa_recovery_code(p_code TEXT)
RETURNS BOOLEAN AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_code_id UUID;
BEGIN
  IF v_user_id IS NULL OR length(trim(p_code)) < 8 THEN
    RETURN false;
  END IF;

  SELECT c.id
    INTO v_code_id
  FROM public.qguard_mfa_recovery_codes c
  WHERE c.user_id = v_user_id
    AND c.used_at IS NULL
    AND (
      c.code_hash = 'sha3:' || encode(digest(c.salt || upper(replace(trim(p_code), '-', '')), 'sha3-256'), 'hex')
      OR c.code_hash = encode(digest(c.salt || upper(replace(trim(p_code), '-', '')), 'sha256'), 'hex')
    )
  ORDER BY c.created_at ASC
  LIMIT 1
  FOR UPDATE SKIP LOCKED;

  IF v_code_id IS NULL THEN
    PERFORM public.log_qguard_profile_security_event(
      'mfa_recovery_code_failed',
      'warning',
      '{}',
      NULL,
      v_user_id
    );
    RETURN false;
  END IF;

  UPDATE public.qguard_mfa_recovery_codes
     SET used_at = now()
   WHERE id = v_code_id;

  PERFORM public.log_qguard_profile_security_event(
    'mfa_recovery_code_consumed',
    'info',
    '{}',
    NULL,
    v_user_id
  );

  RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
