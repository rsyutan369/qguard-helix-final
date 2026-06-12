-- Device Trust Center management and pairing.
-- Revoke terminates a device's access paths immediately; delete removes the
-- device registry row and active key material so it cannot appear in the
-- Trusted Devices panel after realtime refresh.

CREATE TABLE IF NOT EXISTS public.messaging_device_link_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  pairing_token TEXT NOT NULL UNIQUE,
  requested_device_label TEXT NOT NULL,
  requested_fingerprint TEXT NOT NULL,
  requested_suite JSONB NOT NULL DEFAULT '{"classical_kex":"X25519","pq_kem":"ML-KEM-1024","kdf":"HKDF-SHA3-256","symmetric":"AES-256-GCM","classical_signature":"Ed25519","pq_signature":"ML-DSA-65"}',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'expired', 'rejected')),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes',
  approved_by_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  approved_device_id UUID REFERENCES public.messaging_devices(id) ON DELETE SET NULL,
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_messaging_device_link_requests_user_status
  ON public.messaging_device_link_requests(user_id, status, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_messaging_device_link_requests_fingerprint
  ON public.messaging_device_link_requests(user_id, requested_fingerprint);

ALTER TABLE public.messaging_device_link_requests ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_device_link_requests_owner ON public.messaging_device_link_requests;
CREATE POLICY messaging_device_link_requests_owner ON public.messaging_device_link_requests
  FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

ALTER TABLE public.messaging_devices REPLICA IDENTITY FULL;
ALTER TABLE public.messaging_device_link_requests REPLICA IDENTITY FULL;

CREATE OR REPLACE FUNCTION public.create_messaging_device_link_request(
  p_requested_device_label TEXT,
  p_requested_fingerprint TEXT,
  p_pairing_token TEXT,
  p_requested_suite JSONB DEFAULT '{"classical_kex":"X25519","pq_kem":"ML-KEM-1024","kdf":"HKDF-SHA3-256","symmetric":"AES-256-GCM","classical_signature":"Ed25519","pq_signature":"ML-DSA-65"}',
  p_ttl_minutes INTEGER DEFAULT 10
)
RETURNS UUID AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_request_id UUID;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;

  IF length(trim(COALESCE(p_requested_device_label, ''))) = 0
    OR length(trim(COALESCE(p_requested_fingerprint, ''))) < 16
    OR length(trim(COALESCE(p_pairing_token, ''))) < 16
  THEN
    RAISE EXCEPTION 'invalid device link request payload';
  END IF;

  UPDATE public.messaging_device_link_requests
  SET status = 'expired',
      updated_at = now()
  WHERE user_id = v_user_id
    AND status = 'pending'
    AND expires_at <= now();

  INSERT INTO public.messaging_device_link_requests (
    user_id,
    pairing_token,
    requested_device_label,
    requested_fingerprint,
    requested_suite,
    expires_at
  )
  VALUES (
    v_user_id,
    trim(p_pairing_token),
    trim(p_requested_device_label),
    trim(p_requested_fingerprint),
    COALESCE(p_requested_suite, '{}'),
    now() + make_interval(mins => LEAST(GREATEST(COALESCE(p_ttl_minutes, 10), 1), 60))
  )
  ON CONFLICT (pairing_token) DO UPDATE
    SET requested_device_label = EXCLUDED.requested_device_label,
        requested_fingerprint = EXCLUDED.requested_fingerprint,
        requested_suite = EXCLUDED.requested_suite,
        status = 'pending',
        expires_at = EXCLUDED.expires_at,
        approved_by_device_id = NULL,
        approved_device_id = NULL,
        approved_at = NULL,
        updated_at = now()
    WHERE public.messaging_device_link_requests.user_id = v_user_id
  RETURNING id INTO v_request_id;

  IF v_request_id IS NULL THEN
    RAISE EXCEPTION 'device link token is not available for this account';
  END IF;

  RETURN v_request_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.approve_messaging_device_link(
  p_request_id UUID,
  p_approved_by_device_id UUID DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_request public.messaging_device_link_requests%ROWTYPE;
  v_approved_device_id UUID;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;

  SELECT *
    INTO v_request
  FROM public.messaging_device_link_requests
  WHERE id = p_request_id
    AND user_id = v_user_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'device link request not found';
  END IF;

  IF v_request.status <> 'pending' THEN
    RAISE EXCEPTION 'device link request is not pending';
  END IF;

  IF v_request.expires_at <= now() THEN
    UPDATE public.messaging_device_link_requests
    SET status = 'expired',
        updated_at = now()
    WHERE id = v_request.id;
    RAISE EXCEPTION 'device link request expired';
  END IF;

  IF p_approved_by_device_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM public.messaging_devices d
    WHERE d.id = p_approved_by_device_id
      AND d.user_id = v_user_id
      AND d.trust_state IN ('this_device', 'trusted')
  ) THEN
    RAISE EXCEPTION 'approving device is not trusted';
  END IF;

  UPDATE public.messaging_devices
  SET trust_state = 'trusted',
      approved_by_device_id = p_approved_by_device_id,
      revoked_at = NULL,
      last_seen_at = now()
  WHERE user_id = v_user_id
    AND fingerprint = v_request.requested_fingerprint
    AND trust_state IN ('pending', 'suspicious', 'trusted')
  RETURNING id INTO v_approved_device_id;

  IF v_approved_device_id IS NULL THEN
    RAISE EXCEPTION 'pending device is not registered for this pairing request';
  END IF;

  UPDATE public.messaging_device_link_requests
  SET status = 'approved',
      approved_by_device_id = p_approved_by_device_id,
      approved_device_id = v_approved_device_id,
      approved_at = now(),
      updated_at = now()
  WHERE id = v_request.id;

  RETURN v_approved_device_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.revoke_messaging_device(p_device_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_revoked_device_id UUID;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;

  UPDATE public.messaging_devices
  SET trust_state = 'revoked',
      revoked_at = COALESCE(revoked_at, now()),
      last_seen_at = now()
  WHERE id = p_device_id
    AND user_id = v_user_id
  RETURNING id INTO v_revoked_device_id;

  IF v_revoked_device_id IS NULL THEN
    RETURN false;
  END IF;

  UPDATE public.messaging_signed_prekeys
  SET is_active = false
  WHERE user_id = v_user_id
    AND device_id = p_device_id;

  UPDATE public.messaging_one_time_prekeys
  SET consumed_at = COALESCE(consumed_at, now())
  WHERE user_id = v_user_id
    AND device_id = p_device_id
    AND consumed_at IS NULL;

  UPDATE public.messaging_conversation_members
  SET revoked_at = COALESCE(revoked_at, now())
  WHERE user_id = v_user_id
    AND device_id = p_device_id
    AND revoked_at IS NULL;

  UPDATE public.messaging_file_grants
  SET revoked_at = COALESCE(revoked_at, now())
  WHERE recipient_user_id = v_user_id
    AND recipient_device_id = p_device_id
    AND revoked_at IS NULL;

  RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.delete_messaging_device(p_device_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_deleted_count INTEGER;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.messaging_devices d
    WHERE d.id = p_device_id
      AND d.user_id = v_user_id
  ) THEN
    RETURN false;
  END IF;

  PERFORM public.revoke_messaging_device(p_device_id);

  DELETE FROM public.messaging_device_link_requests
  WHERE user_id = v_user_id
    AND (
      approved_device_id = p_device_id
      OR approved_by_device_id = p_device_id
      OR requested_fingerprint IN (
        SELECT d.fingerprint
        FROM public.messaging_devices d
        WHERE d.id = p_device_id
          AND d.user_id = v_user_id
      )
    );

  DELETE FROM public.messaging_conversation_members
  WHERE user_id = v_user_id
    AND device_id = p_device_id;

  DELETE FROM public.messaging_signed_prekeys
  WHERE user_id = v_user_id
    AND device_id = p_device_id;

  DELETE FROM public.messaging_one_time_prekeys
  WHERE user_id = v_user_id
    AND device_id = p_device_id;

  DELETE FROM public.messaging_devices
  WHERE id = p_device_id
    AND user_id = v_user_id;

  GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
  RETURN v_deleted_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.create_messaging_device_link_request(TEXT, TEXT, TEXT, JSONB, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.approve_messaging_device_link(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.revoke_messaging_device(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.delete_messaging_device(UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.create_messaging_device_link_request(TEXT, TEXT, TEXT, JSONB, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION public.approve_messaging_device_link(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_messaging_device(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.delete_messaging_device(UUID) TO authenticated;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_device_link_requests;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_devices;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

NOTIFY pgrst, 'reload schema';
