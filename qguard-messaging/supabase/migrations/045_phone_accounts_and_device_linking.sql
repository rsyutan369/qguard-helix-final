-- 045: mobile-number accounts and QR device linking.
--
-- 1. Phone accounts. Supabase Auth creates a user with `phone` set and `email`
--    NULL. Two profile paths assumed an email:
--      * qguard_handle_new_user() stored '' — a second phone account would
--        collide with the first if profiles.email ever gains a unique index;
--      * ensure_qguard_profile() fell back to `<uuid>@qguard.local` for the
--        address (fine) but then derived the display NAME and USERNAME from that
--        address, so a phone account was shown to its contacts as a UUID.
--    Both now use a per-user placeholder address that is never delivered to and
--    never displayed (the app hides `@qguard.local`), and fall back to
--    "QGuard User" / "qguard_<id>" for the name and handle.
--    The phone number itself is NEVER copied into public.profiles: it stays in
--    auth.users, readable only by its owner's session and the service role.
--
-- 2. Device linking (supabase/functions/device-link in the platform repo). A
--    signed-out device shows a short-lived QR code; a signed-in device of the
--    account scans it and approves; the new device then receives its OWN
--    session. The table below is the rendezvous. It is service-role only: RLS
--    is on with no policies and the client roles hold no grants, so every read
--    and write goes through the Edge Function, which checks the caller.
--    Nothing in a row lets anyone sign in: the approval code and claim secret
--    are stored as SHA-256 hashes, the session credential is minted at claim
--    time and never stored, and an SMS code captured for a phone-only account
--    lives in the row for the duration of one request.

-- ---------------------------------------------------------------------------
-- 1. Phone-account profile bootstrap
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.qguard_handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, name, full_name, avatar_url)
  VALUES (
    NEW.id,
    COALESCE(NULLIF(trim(NEW.email), ''), NEW.id::TEXT || '@qguard.local'),
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name'),
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name'),
    NEW.raw_user_meta_data->>'avatar_url'
  )
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.user_preferences (user_id)
  VALUES (NEW.id)
  ON CONFLICT (user_id) DO NOTHING;

  INSERT INTO public.user_security_settings (user_id)
  VALUES (NEW.id)
  ON CONFLICT (user_id) DO NOTHING;

  INSERT INTO public.user_security_events (user_id, event_type, severity, message)
  VALUES (NEW.id, 'account.created', 'success', 'Account profile initialized')
  ON CONFLICT DO NOTHING;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE EXECUTE ON FUNCTION public.qguard_handle_new_user() FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.ensure_qguard_profile(
  p_user_id UUID DEFAULT auth.uid(),
  p_email TEXT DEFAULT NULL,
  p_name TEXT DEFAULT NULL
)
RETURNS VOID AS $$
DECLARE
  v_auth_email TEXT;
  v_auth_metadata JSONB;
  v_real_email TEXT;
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

  -- Only a real address may name the account; the placeholder never does.
  v_real_email := COALESCE(NULLIF(trim(p_email), ''), NULLIF(trim(v_auth_email), ''));
  IF v_real_email ILIKE '%@qguard.local' THEN
    v_real_email := NULL;
  END IF;
  v_email := COALESCE(v_real_email, p_user_id::TEXT || '@qguard.local');
  v_name := COALESCE(
    NULLIF(trim(p_name), ''),
    NULLIF(trim(v_auth_metadata ->> 'full_name'), ''),
    NULLIF(trim(v_auth_metadata ->> 'name'), ''),
    NULLIF(split_part(v_real_email, '@', 1), ''),
    'QGuard User'
  );
  v_username := lower(regexp_replace(COALESCE(split_part(v_real_email, '@', 1), ''), '[^a-z0-9_]+', '_', 'g'));
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
      -- A name that is just the account's UUID came from the old fallback;
      -- replace it rather than keep showing contacts an identifier.
      name = CASE
        WHEN NULLIF(public.profiles.name, '') IS NULL OR public.profiles.name = p_user_id::TEXT THEN EXCLUDED.name
        ELSE public.profiles.name
      END,
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

-- ---------------------------------------------------------------------------
-- 2. Device-link rendezvous (service role only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.messaging_device_link_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- SHA-256 of the approval code the QR carries (and the user can type).
  code_hash TEXT NOT NULL UNIQUE CHECK (code_hash ~ '^[0-9a-f]{64}$'),
  -- SHA-256 of the secret only the requesting device holds; required to claim.
  claim_secret_hash TEXT NOT NULL CHECK (claim_secret_hash ~ '^[0-9a-f]{64}$'),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'claiming', 'consumed', 'rejected', 'failed')),
  requester_label TEXT NOT NULL CHECK (char_length(requester_label) BETWEEN 1 AND 64),
  requester_platform TEXT NOT NULL
    CHECK (requester_platform IN ('windows', 'macos', 'linux', 'android', 'ios', 'web', 'unknown')),
  -- Shown to the approving user so a request from somewhere unexpected stands
  -- out; deleted with the row (rows are purged an hour after they expire).
  requester_ip TEXT CHECK (requester_ip IS NULL OR char_length(requester_ip) <= 64),
  requester_ip_hash TEXT CHECK (requester_ip_hash IS NULL OR requester_ip_hash ~ '^[0-9a-f]{64}$'),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  approved_by_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  approved_at TIMESTAMPTZ,
  credential_method TEXT CHECK (credential_method IS NULL OR credential_method IN ('email_token', 'sms_code')),
  sms_otp TEXT CHECK (sms_otp IS NULL OR sms_otp ~ '^[0-9]{6,10}$'),
  otp_requested_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  linked_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  -- HMAC-SHA3-256 the new device computes with the secret in the QR code (which
  -- the relay never sees); the approving device verifies it before trusting.
  link_proof TEXT CHECK (link_proof IS NULL OR link_proof ~ '^[0-9a-f]{64}$'),
  failure_reason TEXT CHECK (failure_reason IS NULL OR char_length(failure_reason) <= 64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);

CREATE INDEX IF NOT EXISTS idx_device_link_sessions_ip ON public.messaging_device_link_sessions(requester_ip_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_device_link_sessions_user ON public.messaging_device_link_sessions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_device_link_sessions_expiry ON public.messaging_device_link_sessions(expires_at);

ALTER TABLE public.messaging_device_link_sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.messaging_device_link_sessions FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.messaging_device_link_sessions TO service_role;

COMMENT ON TABLE public.messaging_device_link_sessions IS
  'QR device-link rendezvous. Service role only (Edge Function device-link). Holds hashes, never a usable credential.';

NOTIFY pgrst, 'reload schema';
