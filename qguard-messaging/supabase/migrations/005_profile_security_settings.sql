-- QGuard enterprise profile and security settings.
-- Run after 004_quantum_encryption_enforcement.sql.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS username TEXT,
  ADD COLUMN IF NOT EXISTS avatar_storage_path TEXT,
  ADD COLUMN IF NOT EXISTS avatar_updated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS profile_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE UNIQUE INDEX IF NOT EXISTS uniq_profiles_username_lower
  ON public.profiles (lower(username))
  WHERE username IS NOT NULL AND username <> '';

CREATE TABLE IF NOT EXISTS public.qguard_profile_audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  actor_user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  email_hash TEXT,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  redacted_metadata JSONB NOT NULL DEFAULT '{}',
  ip_hash TEXT,
  user_agent_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_qguard_profile_audit_user_created
  ON public.qguard_profile_audit_events(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.qguard_profile_action_rate_limits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  email_hash TEXT,
  action TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_qguard_profile_rate_limit_lookup
  ON public.qguard_profile_action_rate_limits(user_id, email_hash, action, created_at DESC);

CREATE TABLE IF NOT EXISTS public.qguard_mfa_recovery_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, code_hash)
);

CREATE INDEX IF NOT EXISTS idx_qguard_mfa_recovery_codes_active
  ON public.qguard_mfa_recovery_codes(user_id, created_at DESC)
  WHERE used_at IS NULL;

ALTER TABLE public.qguard_profile_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qguard_profile_action_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qguard_mfa_recovery_codes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS qguard_profile_audit_owner_select ON public.qguard_profile_audit_events;
CREATE POLICY qguard_profile_audit_owner_select ON public.qguard_profile_audit_events
  FOR SELECT USING (auth.uid() = user_id OR auth.uid() = actor_user_id);

DROP POLICY IF EXISTS qguard_profile_rate_limit_no_direct_access ON public.qguard_profile_action_rate_limits;
CREATE POLICY qguard_profile_rate_limit_no_direct_access ON public.qguard_profile_action_rate_limits
  FOR SELECT USING (false);

DROP POLICY IF EXISTS qguard_mfa_recovery_codes_owner ON public.qguard_mfa_recovery_codes;
CREATE POLICY qguard_mfa_recovery_codes_owner ON public.qguard_mfa_recovery_codes
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS qguard_profiles_owner_update ON public.profiles;
CREATE POLICY qguard_profiles_owner_update ON public.profiles
  FOR UPDATE USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'profile-avatars',
  'profile-avatars',
  false,
  3145728,
  ARRAY['image/png', 'image/jpeg', 'image/webp']
)
ON CONFLICT (id) DO UPDATE
SET public = false,
    file_size_limit = 3145728,
    allowed_mime_types = ARRAY['image/png', 'image/jpeg', 'image/webp'];

DROP POLICY IF EXISTS profile_avatars_owner_insert ON storage.objects;
CREATE POLICY profile_avatars_owner_insert ON storage.objects
  FOR INSERT WITH CHECK (
    bucket_id = 'profile-avatars'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  );

DROP POLICY IF EXISTS profile_avatars_owner_select ON storage.objects;
CREATE POLICY profile_avatars_owner_select ON storage.objects
  FOR SELECT USING (
    bucket_id = 'profile-avatars'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  );

DROP POLICY IF EXISTS profile_avatars_owner_update ON storage.objects;
CREATE POLICY profile_avatars_owner_update ON storage.objects
  FOR UPDATE USING (
    bucket_id = 'profile-avatars'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  )
  WITH CHECK (
    bucket_id = 'profile-avatars'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  );

DROP POLICY IF EXISTS profile_avatars_owner_delete ON storage.objects;
CREATE POLICY profile_avatars_owner_delete ON storage.objects
  FOR DELETE USING (
    bucket_id = 'profile-avatars'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  );

CREATE OR REPLACE FUNCTION public.check_qguard_profile_rate_limit(
  p_action TEXT,
  p_email_hash TEXT DEFAULT NULL,
  p_limit INTEGER DEFAULT 5,
  p_window_seconds INTEGER DEFAULT 300
)
RETURNS BOOLEAN AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_count INTEGER;
BEGIN
  DELETE FROM public.qguard_profile_action_rate_limits
  WHERE created_at < now() - interval '1 day';

  SELECT count(*)
    INTO v_count
  FROM public.qguard_profile_action_rate_limits r
  WHERE r.action = p_action
    AND r.created_at > now() - make_interval(secs => p_window_seconds)
    AND (
      (v_user_id IS NOT NULL AND r.user_id = v_user_id)
      OR (p_email_hash IS NOT NULL AND r.email_hash = p_email_hash)
    );

  IF v_count >= p_limit THEN
    RETURN false;
  END IF;

  INSERT INTO public.qguard_profile_action_rate_limits(user_id, email_hash, action)
  VALUES (v_user_id, p_email_hash, p_action);

  RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.log_qguard_profile_security_event(
  p_event_type TEXT,
  p_severity TEXT DEFAULT 'info',
  p_metadata JSONB DEFAULT '{}',
  p_email_hash TEXT DEFAULT NULL,
  p_user_id UUID DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
  v_actor UUID := auth.uid();
  v_user UUID := COALESCE(p_user_id, v_actor);
  v_id UUID;
BEGIN
  IF p_severity NOT IN ('info', 'warning', 'critical') THEN
    p_severity := 'warning';
  END IF;

  IF v_actor IS NOT NULL AND v_user IS NOT NULL AND v_actor <> v_user THEN
    RAISE EXCEPTION 'actor cannot write audit events for another user';
  END IF;

  INSERT INTO public.qguard_profile_audit_events(
    user_id,
    actor_user_id,
    email_hash,
    event_type,
    severity,
    redacted_metadata
  )
  VALUES (
    v_user,
    v_actor,
    p_email_hash,
    p_event_type,
    p_severity,
    COALESCE(p_metadata, '{}')
  )
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

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
    AND c.code_hash = encode(digest(c.salt || upper(replace(trim(p_code), '-', '')), 'sha256'), 'hex')
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

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.qguard_profile_audit_events;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;
