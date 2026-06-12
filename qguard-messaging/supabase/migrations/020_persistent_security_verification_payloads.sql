-- Persist signed security-verification payloads by device fingerprint.
-- A trusted device should only need a fresh safety-number payload when its
-- cryptographic fingerprint is new, revoked, or intentionally rotated.

CREATE TABLE IF NOT EXISTS public.messaging_device_verification_payloads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  fingerprint TEXT NOT NULL,
  display TEXT,
  safety_number TEXT,
  qr_payload TEXT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT true,
  suite JSONB NOT NULL DEFAULT '{}',
  signed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_messaging_device_verification_payloads_device
  ON public.messaging_device_verification_payloads(device_id);

ALTER TABLE public.messaging_device_verification_payloads ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_device_verification_payloads_owner
  ON public.messaging_device_verification_payloads;

CREATE POLICY messaging_device_verification_payloads_owner
  ON public.messaging_device_verification_payloads
  FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION public.touch_messaging_device_verification_payloads()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

DROP TRIGGER IF EXISTS touch_messaging_device_verification_payloads
  ON public.messaging_device_verification_payloads;

CREATE TRIGGER touch_messaging_device_verification_payloads
  BEFORE UPDATE ON public.messaging_device_verification_payloads
  FOR EACH ROW EXECUTE FUNCTION public.touch_messaging_device_verification_payloads();

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_device_verification_payloads;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;
