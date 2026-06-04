-- QGuard sidebar navigation cleanup.
-- Run after 010_secure_chat_attachments_storage.sql.

UPDATE public.messaging_user_modules
SET label = 'Quantum Security',
    enabled = TRUE,
    updated_at = now()
WHERE module_id = 'quantum';

UPDATE public.messaging_user_modules
SET enabled = FALSE,
    updated_at = now()
WHERE module_id = 'admin';

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
  ON CONFLICT (user_id, module_id) DO UPDATE
  SET label = EXCLUDED.label,
      enabled = EXCLUDED.enabled,
      sort_order = EXCLUDED.sort_order,
      updated_at = now();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

NOTIFY pgrst, 'reload schema';
