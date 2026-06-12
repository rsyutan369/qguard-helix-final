-- QGuard Messaging zero-knowledge relay schema.
-- Server stores public keys, public prekeys, ciphertext envelopes, encrypted files,
-- delivery receipts, and minimum routing metadata. It must not store private keys,
-- raw session keys, plaintext messages, plaintext files, or recovery secrets.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.messaging_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  device_label TEXT NOT NULL,
  identity_id UUID NOT NULL,
  x25519_identity_public BYTEA NOT NULL,
  mlkem_identity_public BYTEA NOT NULL,
  ed25519_identity_public BYTEA NOT NULL,
  mldsa_identity_public BYTEA NOT NULL,
  identity_signature JSONB NOT NULL,
  fingerprint TEXT NOT NULL,
  trust_state TEXT NOT NULL DEFAULT 'pending' CHECK (trust_state IN ('this_device', 'trusted', 'pending', 'revoked', 'suspicious')),
  suite JSONB NOT NULL DEFAULT '{"classical_kex":"X25519","pq_kem":"ML-KEM-1024","kdf":"HKDF-SHA3-256","symmetric":"AES-256-GCM","classical_signature":"Ed25519","pq_signature":"ML-DSA-65"}',
  approved_by_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  revoked_at TIMESTAMPTZ,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS public.messaging_signed_prekeys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES public.messaging_devices(id) ON DELETE CASCADE,
  x25519_public BYTEA NOT NULL,
  mlkem_public BYTEA NOT NULL,
  signature JSONB NOT NULL,
  fingerprint TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_messaging_signed_prekey
  ON public.messaging_signed_prekeys(device_id)
  WHERE is_active = true;

CREATE TABLE IF NOT EXISTS public.messaging_one_time_prekeys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES public.messaging_devices(id) ON DELETE CASCADE,
  x25519_public BYTEA NOT NULL,
  mlkem_public BYTEA NOT NULL,
  fingerprint TEXT NOT NULL,
  consumed_by_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_messaging_otk_available
  ON public.messaging_one_time_prekeys(device_id, created_at)
  WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS public.messaging_conversations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  conversation_type TEXT NOT NULL DEFAULT 'direct' CHECK (conversation_type IN ('direct', 'group')),
  encrypted_title JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.messaging_conversation_members (
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  PRIMARY KEY (conversation_id, user_id, device_id)
);

CREATE TABLE IF NOT EXISTS public.messaging_message_envelopes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  sender_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  sender_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  recipient_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  recipient_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  message_kind TEXT NOT NULL DEFAULT 'text' CHECK (message_kind IN ('text', 'file_reference', 'voice_note', 'system')),
  sealed_sender_envelope JSONB NOT NULL,
  ciphertext BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  auth_tag BYTEA NOT NULL,
  aad BYTEA NOT NULL,
  ratchet_counter BIGINT NOT NULL,
  suite JSONB NOT NULL,
  expires_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_messaging_queue_recipient
  ON public.messaging_message_envelopes(recipient_user_id, recipient_device_id, created_at)
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS public.messaging_delivery_receipts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id UUID NOT NULL REFERENCES public.messaging_message_envelopes(id) ON DELETE CASCADE,
  recipient_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  recipient_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'delivered', 'read', 'deleted')),
  encrypted_receipt JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.messaging_vault_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  owner_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  storage_path TEXT NOT NULL UNIQUE,
  encrypted_metadata JSONB NOT NULL,
  metadata_signature JSONB NOT NULL,
  merkle_root TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  suite JSONB NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.messaging_file_grants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  file_id UUID NOT NULL REFERENCES public.messaging_vault_files(id) ON DELETE CASCADE,
  recipient_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  recipient_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE CASCADE,
  hybrid_ciphertext JSONB NOT NULL,
  wrapped_file_key JSONB NOT NULL,
  grant_signature JSONB NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(file_id, recipient_user_id, recipient_device_id)
);

CREATE TABLE IF NOT EXISTS public.messaging_security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  encrypted_details JSONB,
  event_hash TEXT NOT NULL,
  previous_hash TEXT,
  retention_until TIMESTAMPTZ NOT NULL DEFAULT now() + interval '30 days',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.messaging_orgs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  encrypted_name JSONB NOT NULL,
  policy JSONB NOT NULL DEFAULT '{"require_mfa":true,"require_qr_device_approval":true,"metadata_retention_days":30}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.messaging_org_members (
  org_id UUID NOT NULL REFERENCES public.messaging_orgs(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'auditor')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

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

ALTER TABLE public.messaging_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_signed_prekeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_one_time_prekeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_conversation_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_message_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_delivery_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_vault_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_file_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_org_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_user_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_user_modules ENABLE ROW LEVEL SECURITY;

CREATE POLICY messaging_devices_owner ON public.messaging_devices
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE POLICY messaging_signed_prekeys_owner ON public.messaging_signed_prekeys
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE POLICY messaging_one_time_prekeys_owner ON public.messaging_one_time_prekeys
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE POLICY messaging_conversations_member_select ON public.messaging_conversations
  FOR SELECT USING (
    owner_user_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.messaging_conversation_members m
      WHERE m.conversation_id = id AND m.user_id = auth.uid() AND m.revoked_at IS NULL
    )
  );
CREATE POLICY messaging_conversations_owner_write ON public.messaging_conversations
  FOR INSERT WITH CHECK (owner_user_id = auth.uid());
CREATE POLICY messaging_conversations_owner_update ON public.messaging_conversations
  FOR UPDATE USING (owner_user_id = auth.uid());

CREATE POLICY messaging_members_visible ON public.messaging_conversation_members
  FOR SELECT USING (
    user_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.messaging_conversation_members m
      WHERE m.conversation_id = conversation_id AND m.user_id = auth.uid() AND m.revoked_at IS NULL
    )
  );
CREATE POLICY messaging_members_insert_self ON public.messaging_conversation_members
  FOR INSERT WITH CHECK (user_id = auth.uid());
CREATE POLICY messaging_members_update_self ON public.messaging_conversation_members
  FOR UPDATE USING (user_id = auth.uid());

CREATE POLICY messaging_envelopes_sender_recipient ON public.messaging_message_envelopes
  FOR SELECT USING (sender_user_id = auth.uid() OR recipient_user_id = auth.uid());
CREATE POLICY messaging_envelopes_sender_insert ON public.messaging_message_envelopes
  FOR INSERT WITH CHECK (sender_user_id = auth.uid());
CREATE POLICY messaging_envelopes_sender_delete_marker ON public.messaging_message_envelopes
  FOR UPDATE USING (sender_user_id = auth.uid() OR recipient_user_id = auth.uid());

CREATE POLICY messaging_receipts_participant ON public.messaging_delivery_receipts
  FOR SELECT USING (
    recipient_user_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.messaging_message_envelopes e
      WHERE e.id = message_id AND e.sender_user_id = auth.uid()
    )
  );
CREATE POLICY messaging_receipts_recipient_insert ON public.messaging_delivery_receipts
  FOR INSERT WITH CHECK (recipient_user_id = auth.uid());

CREATE POLICY messaging_vault_owner_or_grant ON public.messaging_vault_files
  FOR SELECT USING (
    owner_user_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.messaging_file_grants g
      WHERE g.file_id = id AND g.recipient_user_id = auth.uid() AND g.revoked_at IS NULL
    )
  );
CREATE POLICY messaging_vault_owner_write ON public.messaging_vault_files
  FOR INSERT WITH CHECK (owner_user_id = auth.uid());
CREATE POLICY messaging_vault_owner_update ON public.messaging_vault_files
  FOR UPDATE USING (owner_user_id = auth.uid());

CREATE POLICY messaging_file_grants_visible ON public.messaging_file_grants
  FOR SELECT USING (
    recipient_user_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.messaging_vault_files f
      WHERE f.id = file_id AND f.owner_user_id = auth.uid()
    )
  );
CREATE POLICY messaging_file_grants_owner_insert ON public.messaging_file_grants
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.messaging_vault_files f
      WHERE f.id = file_id AND f.owner_user_id = auth.uid()
    )
  );
CREATE POLICY messaging_file_grants_owner_update ON public.messaging_file_grants
  FOR UPDATE USING (
    EXISTS (
      SELECT 1 FROM public.messaging_vault_files f
      WHERE f.id = file_id AND f.owner_user_id = auth.uid()
    )
  );

CREATE POLICY messaging_security_events_owner ON public.messaging_security_events
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE POLICY messaging_orgs_member_select ON public.messaging_orgs
  FOR SELECT USING (
    owner_user_id = auth.uid()
    OR EXISTS (SELECT 1 FROM public.messaging_org_members m WHERE m.org_id = id AND m.user_id = auth.uid())
  );
CREATE POLICY messaging_orgs_owner_write ON public.messaging_orgs
  FOR INSERT WITH CHECK (owner_user_id = auth.uid());
CREATE POLICY messaging_orgs_owner_update ON public.messaging_orgs
  FOR UPDATE USING (owner_user_id = auth.uid());

CREATE POLICY messaging_org_members_member_select ON public.messaging_org_members
  FOR SELECT USING (user_id = auth.uid());
CREATE POLICY messaging_org_members_owner_insert ON public.messaging_org_members
  FOR INSERT WITH CHECK (
    user_id = auth.uid()
    OR EXISTS (SELECT 1 FROM public.messaging_orgs o WHERE o.id = org_id AND o.owner_user_id = auth.uid())
  );

CREATE POLICY messaging_user_settings_owner ON public.messaging_user_settings
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

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

INSERT INTO storage.buckets (id, name, public)
VALUES ('messaging-files', 'messaging-files', false)
ON CONFLICT (id) DO NOTHING;

CREATE POLICY messaging_files_storage_insert ON storage.objects
  FOR INSERT WITH CHECK (
    bucket_id = 'messaging-files'
    AND auth.uid()::text = (storage.foldername(name))[1]
  );

CREATE POLICY messaging_files_storage_select ON storage.objects
  FOR SELECT USING (
    bucket_id = 'messaging-files'
    AND (
      auth.uid()::text = (storage.foldername(name))[1]
      OR EXISTS (
        SELECT 1
        FROM public.messaging_vault_files f
        JOIN public.messaging_file_grants g ON g.file_id = f.id
        WHERE f.storage_path = name
          AND g.recipient_user_id = auth.uid()
          AND g.revoked_at IS NULL
      )
    )
  );

CREATE POLICY messaging_files_storage_delete ON storage.objects
  FOR DELETE USING (
    bucket_id = 'messaging-files'
    AND auth.uid()::text = (storage.foldername(name))[1]
  );

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_user_modules;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_devices;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_conversations;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_message_envelopes;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_vault_files;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_security_events;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_org_members;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;
