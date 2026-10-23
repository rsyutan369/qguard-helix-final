-- 044: account sealing key wraps (roadmap: encrypt app-only fields at rest).
--
-- A few rows the relay stores are not message content but are only ever read by
-- the account's own devices: the details of an audit event, crypto telemetry
-- details. They used to be plaintext (one column was even called
-- `encrypted_details`). The app now seals them with a per-account key that lives
-- only on the user's devices (src-tauri/src/commands/account_key.rs).
--
-- This table carries that key from one of the user's devices to another. Each
-- row is the key ring SEALED to ONE device (hybrid X25519 + ML-KEM-1024, signed
-- by the sending device). The relay stores it and cannot open it; a device that
-- has not pinned the sender refuses it.
--
-- Nothing here changes who can read what: RLS stays "only the owner". The
-- receiving device marks a row accepted and blanks its payload, so a delivered
-- key does not sit on the relay.
--
-- The app works without this migration: with no table the account key simply
-- never leaves the device that made it, and fields written there stay readable
-- only there. Apply it to make the key available on every device.

CREATE TABLE IF NOT EXISTS public.messaging_account_key_wraps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  from_device_id UUID NOT NULL REFERENCES public.messaging_devices(id) ON DELETE CASCADE,
  to_device_id UUID NOT NULL REFERENCES public.messaging_devices(id) ON DELETE CASCADE,
  epoch INTEGER NOT NULL CHECK (epoch BETWEEN 1 AND 100000),
  wrap JSONB NOT NULL CHECK (octet_length(wrap::text) < 65536),
  accepted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (from_device_id <> to_device_id),
  UNIQUE (to_device_id, epoch)
);

CREATE INDEX IF NOT EXISTS idx_account_key_wraps_user ON public.messaging_account_key_wraps(user_id);

ALTER TABLE public.messaging_account_key_wraps ENABLE ROW LEVEL SECURITY;

-- True only when the device belongs to the signed-in user. Both ends of a wrap
-- must: a wrap can never be addressed to, or claim to come from, someone else's
-- device.
CREATE OR REPLACE FUNCTION public.messaging_owns_device(p_device_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.messaging_devices d
    WHERE d.id = p_device_id AND d.user_id = auth.uid()
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.messaging_owns_device(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.messaging_owns_device(UUID) TO authenticated;

DROP POLICY IF EXISTS account_key_wraps_select ON public.messaging_account_key_wraps;
CREATE POLICY account_key_wraps_select ON public.messaging_account_key_wraps
  FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS account_key_wraps_insert ON public.messaging_account_key_wraps;
CREATE POLICY account_key_wraps_insert ON public.messaging_account_key_wraps
  FOR INSERT WITH CHECK (
    auth.uid() = user_id
    AND public.messaging_owns_device(from_device_id)
    AND public.messaging_owns_device(to_device_id)
  );

DROP POLICY IF EXISTS account_key_wraps_update ON public.messaging_account_key_wraps;
CREATE POLICY account_key_wraps_update ON public.messaging_account_key_wraps
  FOR UPDATE USING (auth.uid() = user_id)
  WITH CHECK (
    auth.uid() = user_id
    AND public.messaging_owns_device(from_device_id)
    AND public.messaging_owns_device(to_device_id)
  );

DROP POLICY IF EXISTS account_key_wraps_delete ON public.messaging_account_key_wraps;
CREATE POLICY account_key_wraps_delete ON public.messaging_account_key_wraps
  FOR DELETE USING (auth.uid() = user_id);

-- Say what the two audit columns now hold, so the next reader of the schema is
-- not misled by a name again.
COMMENT ON COLUMN public.messaging_security_events.encrypted_details IS
  'Sealed on the device with the account key as {"sealed":{"v","e","n","c"}} (AES-256-GCM). Rows written before this migration may hold plaintext JSON.';
COMMENT ON COLUMN public.messaging_crypto_telemetry.redacted_metadata IS
  'Sealed on the device with the account key as {"sealed":{"v","e","n","c"}}; carries the event detail and metadata. Rows written before this migration may hold plaintext JSON.';
