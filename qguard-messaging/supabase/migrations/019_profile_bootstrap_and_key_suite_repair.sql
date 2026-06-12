-- Authenticated profile bootstrap and key-suite repair.
-- Fixes accounts that exist in auth.users but do not yet have public.profiles
-- rows, which otherwise breaks workspace loading and messaging_contacts FKs.

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS qguard_profiles_owner_select ON public.profiles;
CREATE POLICY qguard_profiles_owner_select ON public.profiles
  FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS qguard_profiles_owner_insert ON public.profiles;
CREATE POLICY qguard_profiles_owner_insert ON public.profiles
  FOR INSERT WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS qguard_profiles_owner_update ON public.profiles;
CREATE POLICY qguard_profiles_owner_update ON public.profiles
  FOR UPDATE USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

CREATE OR REPLACE FUNCTION public.ensure_qguard_profile(
  p_user_id UUID DEFAULT auth.uid(),
  p_email TEXT DEFAULT NULL,
  p_name TEXT DEFAULT NULL
)
RETURNS VOID AS $$
DECLARE
  v_auth_email TEXT;
  v_auth_metadata JSONB;
  v_email TEXT;
  v_name TEXT;
  v_username TEXT;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'authenticated Supabase session required'
      USING ERRCODE = '42501';
  END IF;

  IF p_user_id IS NULL OR p_user_id <> auth.uid() THEN
    RAISE EXCEPTION 'cannot bootstrap another user profile'
      USING ERRCODE = '42501';
  END IF;

  SELECT u.email, u.raw_user_meta_data
    INTO v_auth_email, v_auth_metadata
  FROM auth.users u
  WHERE u.id = p_user_id;

  v_email := COALESCE(NULLIF(trim(p_email), ''), NULLIF(trim(v_auth_email), ''), p_user_id::TEXT || '@qguard.local');
  v_name := COALESCE(
    NULLIF(trim(p_name), ''),
    NULLIF(trim(v_auth_metadata ->> 'full_name'), ''),
    NULLIF(trim(v_auth_metadata ->> 'name'), ''),
    NULLIF(split_part(v_email, '@', 1), ''),
    'QGuard User'
  );
  v_username := lower(regexp_replace(split_part(v_email, '@', 1), '[^a-z0-9_]+', '_', 'g'));
  v_username := trim(both '_' from left(COALESCE(NULLIF(v_username, ''), 'qguard'), 24));
  v_username := COALESCE(NULLIF(v_username, ''), 'qguard') || '_' || left(replace(p_user_id::TEXT, '-', ''), 6);

  INSERT INTO public.profiles (
    id,
    email,
    name,
    username,
    tier,
    q_score,
    vault_storage_used,
    max_vault_storage
  )
  VALUES (
    p_user_id,
    v_email,
    v_name,
    v_username,
    'user',
    0,
    0,
    104857600
  )
  ON CONFLICT (id) DO UPDATE
  SET email = COALESCE(NULLIF(public.profiles.email, ''), EXCLUDED.email),
      name = COALESCE(NULLIF(public.profiles.name, ''), EXCLUDED.name),
      username = COALESCE(NULLIF(public.profiles.username, ''), EXCLUDED.username),
      tier = COALESCE(NULLIF(public.profiles.tier, ''), EXCLUDED.tier),
      q_score = COALESCE(public.profiles.q_score, EXCLUDED.q_score),
      vault_storage_used = COALESCE(public.profiles.vault_storage_used, EXCLUDED.vault_storage_used),
      max_vault_storage = COALESCE(public.profiles.max_vault_storage, EXCLUDED.max_vault_storage);

  PERFORM public.ensure_messaging_defaults(p_user_id);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.ensure_qguard_profile(UUID, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ensure_qguard_profile(UUID, TEXT, TEXT) TO authenticated;

NOTIFY pgrst, 'reload schema';
