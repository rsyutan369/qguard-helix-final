-- Keep the device registry deterministic for Key Management.
-- A user can have many trusted devices, but only the latest registered desktop
-- identity should be marked as this_device.

CREATE OR REPLACE FUNCTION public.register_messaging_device(
  p_device_id UUID,
  p_device_label TEXT,
  p_identity_id UUID,
  p_x25519_identity_public BYTEA,
  p_mlkem_identity_public BYTEA,
  p_ed25519_identity_public BYTEA,
  p_mldsa_identity_public BYTEA,
  p_identity_signature JSONB,
  p_fingerprint TEXT,
  p_suite JSONB DEFAULT '{"classical_kex":"X25519","pq_kem":"ML-KEM-768","kdf":"HKDF-SHA3-256","symmetric":"AES-256-GCM","classical_signature":"Ed25519","pq_signature":"ML-DSA-65"}'
)
RETURNS UUID AS $$
DECLARE
  v_user_id UUID := auth.uid();
  v_existing_owner UUID;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'authentication required';
  END IF;

  IF p_device_id IS NULL
    OR p_identity_id IS NULL
    OR length(trim(COALESCE(p_device_label, ''))) = 0
    OR length(trim(COALESCE(p_fingerprint, ''))) = 0
    OR octet_length(p_x25519_identity_public) <> 32
    OR octet_length(p_mlkem_identity_public) = 0
    OR octet_length(p_ed25519_identity_public) <> 32
    OR octet_length(p_mldsa_identity_public) = 0
    OR NOT (p_identity_signature ? 'ed25519')
    OR NOT (p_identity_signature ? 'ml_dsa_65')
  THEN
    RAISE EXCEPTION 'invalid messaging device registration payload';
  END IF;

  SELECT d.user_id
    INTO v_existing_owner
  FROM public.messaging_devices d
  WHERE d.id = p_device_id;

  IF v_existing_owner IS NOT NULL AND v_existing_owner <> v_user_id THEN
    RAISE EXCEPTION 'device identity belongs to another account; clear local QGuard device keys or sign in with the original account';
  END IF;

  INSERT INTO public.messaging_devices (
    id,
    user_id,
    device_label,
    identity_id,
    x25519_identity_public,
    mlkem_identity_public,
    ed25519_identity_public,
    mldsa_identity_public,
    identity_signature,
    fingerprint,
    trust_state,
    suite,
    last_seen_at
  )
  VALUES (
    p_device_id,
    v_user_id,
    trim(p_device_label),
    p_identity_id,
    p_x25519_identity_public,
    p_mlkem_identity_public,
    p_ed25519_identity_public,
    p_mldsa_identity_public,
    p_identity_signature,
    p_fingerprint,
    'this_device',
    COALESCE(p_suite, '{}'),
    now()
  )
  ON CONFLICT (id) DO UPDATE
    SET device_label = EXCLUDED.device_label,
        identity_id = EXCLUDED.identity_id,
        x25519_identity_public = EXCLUDED.x25519_identity_public,
        mlkem_identity_public = EXCLUDED.mlkem_identity_public,
        ed25519_identity_public = EXCLUDED.ed25519_identity_public,
        mldsa_identity_public = EXCLUDED.mldsa_identity_public,
        identity_signature = EXCLUDED.identity_signature,
        fingerprint = EXCLUDED.fingerprint,
        trust_state = CASE
          WHEN public.messaging_devices.trust_state = 'revoked' THEN 'revoked'
          ELSE 'this_device'
        END,
        suite = EXCLUDED.suite,
        revoked_at = CASE
          WHEN public.messaging_devices.trust_state = 'revoked' THEN public.messaging_devices.revoked_at
          ELSE NULL
        END,
        last_seen_at = now()
    WHERE public.messaging_devices.user_id = v_user_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'device registration was blocked by ownership checks';
  END IF;

  UPDATE public.messaging_devices
  SET trust_state = 'trusted',
      last_seen_at = now()
  WHERE user_id = v_user_id
    AND id <> p_device_id
    AND trust_state = 'this_device';

  RETURN p_device_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.register_messaging_device(
  UUID,
  TEXT,
  UUID,
  BYTEA,
  BYTEA,
  BYTEA,
  BYTEA,
  JSONB,
  TEXT,
  JSONB
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.register_messaging_device(
  UUID,
  TEXT,
  UUID,
  BYTEA,
  BYTEA,
  BYTEA,
  BYTEA,
  JSONB,
  TEXT,
  JSONB
) TO authenticated;
