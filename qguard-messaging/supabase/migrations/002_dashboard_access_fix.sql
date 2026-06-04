-- QGuard Messaging dashboard access fix.
-- This patch is idempotent and can be run after 001_secure_messaging.sql.
-- It fixes recursive RLS checks that can surface as 500 responses in Supabase
-- and ensures dashboard module/settings tables exist for authenticated users.

CREATE TABLE IF NOT EXISTS public.messaging_user_settings (
  user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
  theme TEXT NOT NULL DEFAULT 'system' CHECK (theme IN ('light', 'dark', 'system')),
  realtime_enabled BOOLEAN NOT NULL DEFAULT true,
  metadata_retention_days INTEGER NOT NULL DEFAULT 30 CHECK (metadata_retention_days BETWEEN 1 AND 365),
  security_alerts_enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.messaging_user_modules (
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  module_id TEXT NOT NULL CHECK (module_id IN ('dashboard', 'chat', 'vault', 'keys', 'devices', 'verification', 'audit', 'quantum', 'admin', 'settings')),
  label TEXT NOT NULL,
  icon TEXT NOT NULL,
  route TEXT NOT NULL CHECK (route IN ('dashboard', 'chat', 'vault', 'keys', 'devices', 'verification', 'audit', 'quantum', 'admin', 'settings')),
  enabled BOOLEAN NOT NULL DEFAULT true,
  sort_order INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, module_id)
);

ALTER TABLE public.messaging_user_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_user_modules ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_user_settings_owner ON public.messaging_user_settings;
CREATE POLICY messaging_user_settings_owner ON public.messaging_user_settings
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS messaging_user_modules_owner ON public.messaging_user_modules;
CREATE POLICY messaging_user_modules_owner ON public.messaging_user_modules
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION public.ensure_messaging_defaults(p_user_id UUID)
RETURNS VOID AS $$
BEGIN
  INSERT INTO public.messaging_user_settings (user_id)
  VALUES (p_user_id)
  ON CONFLICT (user_id) DO NOTHING;

  INSERT INTO public.messaging_user_modules (user_id, module_id, label, icon, route, enabled, sort_order)
  VALUES
    (p_user_id, 'dashboard', 'Dashboard', 'dashboard', 'dashboard', true, 10),
    (p_user_id, 'chat', 'Secure Chat', 'chat', 'chat', true, 20),
    (p_user_id, 'vault', 'Quantum Vault', 'vault', 'vault', true, 30),
    (p_user_id, 'keys', 'Key Management', 'keys', 'keys', true, 40),
    (p_user_id, 'devices', 'Device Trust Center', 'devices', 'devices', true, 50),
    (p_user_id, 'verification', 'Security Verification', 'verification', 'verification', true, 60),
    (p_user_id, 'audit', 'Message Audit Logs', 'audit', 'audit', true, 70),
    (p_user_id, 'quantum', 'Quantum Security', 'quantum', 'quantum', true, 80),
    (p_user_id, 'admin', 'Admin Security Console', 'admin', 'admin', false, 90),
    (p_user_id, 'settings', 'Settings', 'settings', 'settings', true, 100)
  ON CONFLICT (user_id, module_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.handle_messaging_profile_defaults()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM public.ensure_messaging_defaults(NEW.id);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

DROP TRIGGER IF EXISTS on_profile_messaging_defaults ON public.profiles;
CREATE TRIGGER on_profile_messaging_defaults
  AFTER INSERT ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.handle_messaging_profile_defaults();

SELECT public.ensure_messaging_defaults(id) FROM public.profiles;

CREATE OR REPLACE FUNCTION public.is_messaging_conversation_member(
  p_conversation_id UUID,
  p_user_id UUID
)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.messaging_conversation_members m
    WHERE m.conversation_id = p_conversation_id
      AND m.user_id = p_user_id
      AND m.revoked_at IS NULL
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.owns_messaging_vault_file(
  p_file_id UUID,
  p_user_id UUID
)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.messaging_vault_files f
    WHERE f.id = p_file_id
      AND f.owner_user_id = p_user_id
      AND f.revoked_at IS NULL
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.can_read_messaging_vault_file(
  p_file_id UUID,
  p_user_id UUID
)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.messaging_vault_files f
    WHERE f.id = p_file_id
      AND f.owner_user_id = p_user_id
      AND f.revoked_at IS NULL
  )
  OR EXISTS (
    SELECT 1
    FROM public.messaging_file_grants g
    WHERE g.file_id = p_file_id
      AND g.recipient_user_id = p_user_id
      AND g.revoked_at IS NULL
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

DROP POLICY IF EXISTS messaging_conversations_member_select ON public.messaging_conversations;
CREATE POLICY messaging_conversations_member_select ON public.messaging_conversations
  FOR SELECT USING (
    owner_user_id = auth.uid()
    OR public.is_messaging_conversation_member(id, auth.uid())
  );

DROP POLICY IF EXISTS messaging_members_visible ON public.messaging_conversation_members;
CREATE POLICY messaging_members_visible ON public.messaging_conversation_members
  FOR SELECT USING (
    user_id = auth.uid()
    OR public.is_messaging_conversation_member(conversation_id, auth.uid())
  );

DROP POLICY IF EXISTS messaging_vault_owner_or_grant ON public.messaging_vault_files;
CREATE POLICY messaging_vault_owner_or_grant ON public.messaging_vault_files
  FOR SELECT USING (public.can_read_messaging_vault_file(id, auth.uid()));

DROP POLICY IF EXISTS messaging_file_grants_visible ON public.messaging_file_grants;
CREATE POLICY messaging_file_grants_visible ON public.messaging_file_grants
  FOR SELECT USING (
    recipient_user_id = auth.uid()
    OR public.owns_messaging_vault_file(file_id, auth.uid())
  );

DROP POLICY IF EXISTS messaging_file_grants_owner_insert ON public.messaging_file_grants;
CREATE POLICY messaging_file_grants_owner_insert ON public.messaging_file_grants
  FOR INSERT WITH CHECK (public.owns_messaging_vault_file(file_id, auth.uid()));

DROP POLICY IF EXISTS messaging_file_grants_owner_update ON public.messaging_file_grants;
CREATE POLICY messaging_file_grants_owner_update ON public.messaging_file_grants
  FOR UPDATE USING (public.owns_messaging_vault_file(file_id, auth.uid()));
