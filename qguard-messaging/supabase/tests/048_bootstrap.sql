-- Minimal Supabase stand-in for checking migration 048 on plain Postgres 16.
-- Mirrors only what 048 touches: auth.uid(), profiles, billing_subscriptions,
-- the migration-030 access rule, and storage (buckets, objects, foldername,
-- filename) with RLS enabled as on Supabase. Test-only; never applied to a
-- real project.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY);
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::UUID
$$;

CREATE TABLE IF NOT EXISTS public.profiles (id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS public.billing_subscriptions (
  user_id UUID UNIQUE NOT NULL,
  plan TEXT NOT NULL,
  status TEXT NOT NULL,
  current_period_end TIMESTAMPTZ
);

-- Verbatim rule from migration 030.
CREATE OR REPLACE FUNCTION public.qguard_has_messaging_access(uid uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.billing_subscriptions s
    WHERE s.user_id = uid
      AND lower(s.status) IN ('active', 'trial', 'pending_renewal')
      AND (s.current_period_end IS NULL OR s.current_period_end > (now() - interval '72 hours'))
  );
$$;

-- For 049: devices (001) and contact block states (047).
CREATE TABLE IF NOT EXISTS public.messaging_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  revoked_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS public.messaging_contacts (
  owner_user_id UUID NOT NULL,
  contact_user_id UUID NOT NULL,
  trust_state TEXT NOT NULL
);
CREATE OR REPLACE FUNCTION public.qguard_contact_state(p_owner UUID, p_other UUID)
RETURNS TEXT AS $$
  SELECT c.trust_state FROM public.messaging_contacts c
  WHERE c.owner_user_id = p_owner AND c.contact_user_id = p_other;
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.qguard_contact_state(UUID, UUID) FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS storage;
CREATE TABLE IF NOT EXISTS storage.buckets (
  id TEXT PRIMARY KEY, name TEXT, public BOOLEAN, file_size_limit BIGINT, allowed_mime_types TEXT[]
);
CREATE TABLE IF NOT EXISTS storage.objects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bucket_id TEXT REFERENCES storage.buckets(id),
  name TEXT NOT NULL,
  owner UUID,
  metadata JSONB,
  UNIQUE (bucket_id, name)
);
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;

-- Same definitions as Supabase storage.
CREATE OR REPLACE FUNCTION storage.foldername(name TEXT) RETURNS TEXT[] LANGUAGE plpgsql AS $$
DECLARE _parts TEXT[];
BEGIN
  SELECT string_to_array(name, '/') INTO _parts;
  RETURN _parts[1:array_length(_parts, 1) - 1];
END $$;
CREATE OR REPLACE FUNCTION storage.filename(name TEXT) RETURNS TEXT LANGUAGE plpgsql AS $$
DECLARE _parts TEXT[];
BEGIN
  SELECT string_to_array(name, '/') INTO _parts;
  RETURN _parts[array_length(_parts, 1)];
END $$;

-- Supabase's default privileges: every new table and function in `public` is
-- granted to anon / authenticated / service_role directly, so a migration's
-- `REVOKE ... FROM PUBLIC` alone does not take them away. Reproduced here so the
-- checks see the grants a real project has.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;

GRANT USAGE ON SCHEMA auth, storage, public TO authenticated, anon;
GRANT EXECUTE ON FUNCTION auth.uid() TO authenticated, anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON storage.objects TO authenticated;
GRANT SELECT ON storage.buckets TO authenticated;
