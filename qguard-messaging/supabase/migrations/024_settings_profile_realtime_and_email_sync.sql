-- Settings accuracy + realtime hardening.
-- Run after 023_secure_chat_video_calls.sql.
--
-- Two corrections that make the Settings page's profile data accurate and live
-- regardless of whether the standalone root profile schema was ever applied:
--
--   1. Ensure `public.profiles` is in the `supabase_realtime` publication so the
--      Settings page (and live-sse.ts) actually receive profile / avatar / name
--      change events. The messaging migration set never added it on its own — it
--      only existed in the ad-hoc root `profile-security-schema.sql`.
--   2. Keep `public.profiles.email` in sync with `auth.users.email`. The mirror
--      is set at signup and never updated, so after a confirmed email change the
--      profile row (and anything reading it) showed the OLD address. An AFTER
--      UPDATE trigger on auth.users now syncs it (and bumps profile_updated_at,
--      which itself fires a realtime profiles event so the UI refreshes).

-- 1) Realtime publication for profiles (idempotent; safe if already present).
DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.profiles;
EXCEPTION
  WHEN duplicate_object THEN NULL;
  WHEN undefined_object THEN NULL;
  WHEN insufficient_privilege THEN NULL;
END $$;

-- 2) Sync profiles.email when the authoritative auth.users.email changes.
CREATE OR REPLACE FUNCTION public.qguard_sync_profile_email()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.email IS DISTINCT FROM OLD.email AND NEW.email IS NOT NULL AND NEW.email <> '' THEN
    UPDATE public.profiles
       SET email = NEW.email,
           profile_updated_at = now()
     WHERE id = NEW.id
       AND email IS DISTINCT FROM NEW.email;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Creating a trigger on auth.users needs elevated privileges. Wrap defensively
-- so restricted environments don't hard-fail the migration; the frontend still
-- prefers the authoritative auth email for display in that case.
DO $$
BEGIN
  DROP TRIGGER IF EXISTS on_auth_user_email_synced_qguard ON auth.users;
  CREATE TRIGGER on_auth_user_email_synced_qguard
    AFTER UPDATE OF email ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.qguard_sync_profile_email();
EXCEPTION
  WHEN insufficient_privilege THEN NULL;
END $$;

NOTIFY pgrst, 'reload schema';
