-- 049: Quantum Vault — one library across an account's devices (phase 3) and
-- secure sharing between users (phase 4). Builds on 048. Design:
-- qguard-messaging/docs/QUANTUM_VAULT_STORAGE.md §9–§10.
--
-- Everything stored here is ciphertext or opaque to the server:
--   * The library document (kind 'library_index') is sealed under the account's
--     library key, which only the account's devices hold. qv_library_state
--     names the current one and its revision; publishing is compare-and-swap,
--     so a device can never overwrite a newer library it has not merged.
--   * qv_library_key_wraps carries the library key ring from one of the user's
--     devices to another (hybrid KEM to the target device, dual-signed). Same
--     shape and rules as messaging_account_key_wraps (migration 044).
--   * qv_library_recovery holds the ring sealed under the account's recovery
--     key. Setting it is how the first device claims the library: a second
--     device racing to start one is told it lost, and adopts the winner.
--   * A share is one cloud object (no copy) plus one envelope per recipient
--     device, sealed and signed by the sender's device. The server decides who
--     may download the object: recipients who accepted, while the share is
--     neither revoked nor expired, and only while the object is committed.
--
-- Privileges are granted per role by name (Supabase grants new objects to
-- anon/authenticated by default; see 048). Nothing here is readable by anon.
--
-- Rollback: drop the qv_share_* and qv_library_* tables and functions, the
-- qv_storage_share_read and qv_objects_share_read policies, restore 048's
-- kind check and qv_begin_upload.

DO $$
BEGIN
  IF to_regclass('public.qv_cloud_objects') IS NULL THEN
    RAISE EXCEPTION '049 needs migration 048 (qv_cloud_objects)';
  END IF;
  IF to_regclass('public.messaging_devices') IS NULL THEN
    RAISE EXCEPTION '049 needs messaging_devices (migration 001)';
  END IF;
END $$;

-- True only when the device belongs to the signed-in user (also in 044).
CREATE OR REPLACE FUNCTION public.messaging_owns_device(p_device_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.messaging_devices d
    WHERE d.id = p_device_id AND d.user_id = auth.uid()
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
REVOKE ALL ON FUNCTION public.messaging_owns_device(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.messaging_owns_device(UUID) TO authenticated;

-- ===========================================================================
-- Phase 3: library
-- ===========================================================================

ALTER TABLE public.qv_cloud_objects DROP CONSTRAINT IF EXISTS qv_cloud_objects_kind_check;
ALTER TABLE public.qv_cloud_objects
  ADD CONSTRAINT qv_cloud_objects_kind_check CHECK (kind IN ('file', 'recovery_index', 'library_index'));

-- 048's reservation, extended to the library document: like the recovery
-- index it needs entitlement but is not charged, is capped at 64 MiB, and at
-- most three copies live at once (current, the one being replaced, in flight).
CREATE OR REPLACE FUNCTION public.qv_begin_upload(
  p_kind TEXT,
  p_entry_id UUID,
  p_container_bytes BIGINT,
  p_part_sha3 TEXT[],
  p_container_sha3 TEXT,
  p_device_id TEXT DEFAULT NULL
)
RETURNS public.qv_cloud_objects
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
  v_part_size CONSTANT INTEGER := 8388608;
  v_row public.qv_cloud_objects;
  v_quota BIGINT;
  v_used BIGINT;
  v_live_limit INTEGER;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  IF p_kind NOT IN ('file', 'recovery_index', 'library_index') THEN
    RAISE EXCEPTION 'QV_INVALID_KIND';
  END IF;
  IF (p_kind = 'file') <> (p_entry_id IS NOT NULL) THEN
    RAISE EXCEPTION 'QV_INVALID_ENTRY';
  END IF;
  IF p_container_sha3 IS NULL OR p_container_sha3 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'QV_INVALID_HASH';
  END IF;
  IF p_part_sha3 IS NULL OR EXISTS (SELECT 1 FROM unnest(p_part_sha3) h WHERE h IS NULL OR h !~ '^[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'QV_INVALID_HASH';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtext('qv_cloud:' || uid::TEXT));

  SELECT * INTO v_row FROM public.qv_cloud_objects o
  WHERE o.owner_user_id = uid
    AND o.kind = p_kind
    AND o.entry_id IS NOT DISTINCT FROM p_entry_id
    AND o.container_sha3 = p_container_sha3
    AND o.status IN ('uploading', 'committed')
  LIMIT 1;
  IF FOUND THEN
    RETURN v_row;
  END IF;

  IF p_kind = 'file' AND EXISTS (
    SELECT 1 FROM public.qv_cloud_objects o
    WHERE o.owner_user_id = uid AND o.kind = 'file' AND o.entry_id = p_entry_id AND o.status <> 'deleting'
  ) THEN
    RAISE EXCEPTION 'QV_ENTRY_ALREADY_BACKED_UP';
  END IF;

  v_quota := public.qv_cloud_quota_bytes(uid);
  IF v_quota <= 0 THEN
    RAISE EXCEPTION 'QV_NO_CLOUD_ENTITLEMENT';
  END IF;

  IF p_kind IN ('recovery_index', 'library_index') THEN
    IF p_container_bytes > 67108864 THEN
      RAISE EXCEPTION 'QV_INDEX_TOO_LARGE';
    END IF;
    v_live_limit := CASE WHEN p_kind = 'library_index' THEN 3 ELSE 2 END;
    IF (SELECT count(*) FROM public.qv_cloud_objects o
        WHERE o.owner_user_id = uid AND o.kind = p_kind AND o.status <> 'deleting') >= v_live_limit THEN
      RAISE EXCEPTION 'QV_INDEX_BUSY';
    END IF;
  ELSE
    v_used := public.qv_cloud_used_bytes(uid);
    IF v_used + p_container_bytes > v_quota THEN
      RAISE EXCEPTION 'QV_QUOTA_EXCEEDED' USING DETAIL = format('used=%s requested=%s quota=%s', v_used, p_container_bytes, v_quota);
    END IF;
  END IF;

  INSERT INTO public.qv_cloud_objects (
    owner_user_id, kind, entry_id, container_bytes, part_size, part_count, part_sha3, container_sha3, device_id
  ) VALUES (
    uid, p_kind, p_entry_id, p_container_bytes, v_part_size,
    ((p_container_bytes + v_part_size - 1) / v_part_size)::INTEGER,
    p_part_sha3, p_container_sha3, left(p_device_id, 128)
  )
  RETURNING * INTO v_row;

  INSERT INTO public.qv_cloud_audit (owner_user_id, event, object_id, kind, bytes, used_bytes_after)
  VALUES (uid, 'upload_reserved', v_row.id, p_kind, p_container_bytes, public.qv_cloud_used_bytes(uid));
  RETURN v_row;
END;
$$;

CREATE TABLE IF NOT EXISTS public.qv_library_state (
  owner_user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
  revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
  object_id UUID REFERENCES public.qv_cloud_objects(id) ON DELETE SET NULL,
  epoch INTEGER NOT NULL DEFAULT 1 CHECK (epoch BETWEEN 1 AND 100000),
  updated_by_device TEXT CHECK (updated_by_device IS NULL OR length(updated_by_device) <= 128),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE public.qv_library_state ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS qv_library_state_owner_read ON public.qv_library_state;
CREATE POLICY qv_library_state_owner_read ON public.qv_library_state
  FOR SELECT TO authenticated USING (owner_user_id = auth.uid());

-- Publish a committed library document as the next revision, but only if the
-- caller merged the current one. Returns the new revision and the object it
-- replaced (which the caller then deletes).
CREATE OR REPLACE FUNCTION public.qv_publish_library(
  p_object_id UUID,
  p_expected_revision BIGINT,
  p_epoch INTEGER,
  p_device_id TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
  v_state public.qv_library_state;
  v_previous UUID;
  v_revision BIGINT;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  IF p_epoch IS NULL OR p_epoch < 1 THEN
    RAISE EXCEPTION 'QV_INVALID_EPOCH';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('qv_library:' || uid::TEXT));
  IF NOT EXISTS (
    SELECT 1 FROM public.qv_cloud_objects o
    WHERE o.id = p_object_id AND o.owner_user_id = uid AND o.kind = 'library_index' AND o.status = 'committed'
  ) THEN
    RAISE EXCEPTION 'QV_OBJECT_NOT_FOUND';
  END IF;
  SELECT * INTO v_state FROM public.qv_library_state WHERE owner_user_id = uid FOR UPDATE;
  IF COALESCE(v_state.revision, 0) <> p_expected_revision THEN
    RAISE EXCEPTION 'QV_REVISION_CONFLICT' USING DETAIL = format('current=%s expected=%s', COALESCE(v_state.revision, 0), p_expected_revision);
  END IF;
  IF v_state.owner_user_id IS NOT NULL AND p_epoch < v_state.epoch THEN
    RAISE EXCEPTION 'QV_STALE_EPOCH';
  END IF;
  v_previous := v_state.object_id;
  v_revision := COALESCE(v_state.revision, 0) + 1;
  INSERT INTO public.qv_library_state (owner_user_id, revision, object_id, epoch, updated_by_device, updated_at)
  VALUES (uid, v_revision, p_object_id, p_epoch, left(p_device_id, 128), now())
  ON CONFLICT (owner_user_id) DO UPDATE
    SET revision = EXCLUDED.revision, object_id = EXCLUDED.object_id, epoch = EXCLUDED.epoch,
        updated_by_device = EXCLUDED.updated_by_device, updated_at = now();
  RETURN jsonb_build_object('revision', v_revision, 'previous_object_id', v_previous);
END;
$$;

CREATE TABLE IF NOT EXISTS public.qv_library_key_wraps (
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
CREATE INDEX IF NOT EXISTS qv_library_key_wraps_user ON public.qv_library_key_wraps(user_id);
ALTER TABLE public.qv_library_key_wraps ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS qv_library_key_wraps_select ON public.qv_library_key_wraps;
CREATE POLICY qv_library_key_wraps_select ON public.qv_library_key_wraps
  FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS qv_library_key_wraps_insert ON public.qv_library_key_wraps;
CREATE POLICY qv_library_key_wraps_insert ON public.qv_library_key_wraps
  FOR INSERT TO authenticated WITH CHECK (
    auth.uid() = user_id AND public.messaging_owns_device(from_device_id) AND public.messaging_owns_device(to_device_id)
  );
DROP POLICY IF EXISTS qv_library_key_wraps_update ON public.qv_library_key_wraps;
CREATE POLICY qv_library_key_wraps_update ON public.qv_library_key_wraps
  FOR UPDATE TO authenticated USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id AND public.messaging_owns_device(from_device_id) AND public.messaging_owns_device(to_device_id));
DROP POLICY IF EXISTS qv_library_key_wraps_delete ON public.qv_library_key_wraps;
CREATE POLICY qv_library_key_wraps_delete ON public.qv_library_key_wraps
  FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS public.qv_library_recovery (
  owner_user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
  epoch INTEGER NOT NULL CHECK (epoch BETWEEN 1 AND 100000),
  envelope JSONB NOT NULL CHECK (octet_length(envelope::text) < 65536),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE public.qv_library_recovery ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS qv_library_recovery_owner_read ON public.qv_library_recovery;
CREATE POLICY qv_library_recovery_owner_read ON public.qv_library_recovery
  FOR SELECT TO authenticated USING (owner_user_id = auth.uid());

-- Store the recovery copy of the ring. The first copy claims the library
-- (epoch 1); later copies only for a NEWER epoch. A device that tries to set
-- an epoch someone already set lost a race and must adopt that copy.
CREATE OR REPLACE FUNCTION public.qv_library_set_recovery(p_epoch INTEGER, p_envelope JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
  v_row public.qv_library_recovery;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  IF p_epoch IS NULL OR p_epoch < 1 OR p_envelope IS NULL OR octet_length(p_envelope::text) >= 65536 THEN
    RAISE EXCEPTION 'QV_INVALID_ENVELOPE';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('qv_library:' || uid::TEXT));
  SELECT * INTO v_row FROM public.qv_library_recovery WHERE owner_user_id = uid FOR UPDATE;
  IF FOUND AND v_row.epoch >= p_epoch THEN
    RAISE EXCEPTION 'QV_RECOVERY_EXISTS' USING DETAIL = format('stored=%s offered=%s', v_row.epoch, p_epoch);
  END IF;
  INSERT INTO public.qv_library_recovery (owner_user_id, epoch, envelope, updated_at)
  VALUES (uid, p_epoch, p_envelope, now())
  ON CONFLICT (owner_user_id) DO UPDATE SET epoch = EXCLUDED.epoch, envelope = EXCLUDED.envelope, updated_at = now();
  RETURN jsonb_build_object('epoch', p_epoch);
END;
$$;

-- ===========================================================================
-- Phase 4: sharing
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.qv_shares (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  object_id UUID NOT NULL REFERENCES public.qv_cloud_objects(id) ON DELETE CASCADE,
  permission TEXT NOT NULL CHECK (permission IN ('view', 'download')),
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS qv_shares_owner ON public.qv_shares(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS qv_shares_object ON public.qv_shares(object_id);

CREATE TABLE IF NOT EXISTS public.qv_share_recipients (
  share_id UUID NOT NULL REFERENCES public.qv_shares(id) ON DELETE CASCADE,
  recipient_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined', 'revoked')),
  responded_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (share_id, recipient_user_id)
);
CREATE INDEX IF NOT EXISTS qv_share_recipients_user ON public.qv_share_recipients(recipient_user_id, status);

CREATE TABLE IF NOT EXISTS public.qv_share_envelopes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  share_id UUID NOT NULL REFERENCES public.qv_shares(id) ON DELETE CASCADE,
  recipient_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  recipient_device_id UUID NOT NULL REFERENCES public.messaging_devices(id) ON DELETE CASCADE,
  sender_device_id UUID NOT NULL REFERENCES public.messaging_devices(id) ON DELETE CASCADE,
  envelope JSONB NOT NULL CHECK (octet_length(envelope::text) < 65536),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (share_id, recipient_device_id)
);
CREATE INDEX IF NOT EXISTS qv_share_envelopes_recipient ON public.qv_share_envelopes(recipient_user_id, recipient_device_id);

CREATE TABLE IF NOT EXISTS public.qv_share_events (
  id BIGSERIAL PRIMARY KEY,
  share_id UUID NOT NULL REFERENCES public.qv_shares(id) ON DELETE CASCADE,
  actor_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK (event IN ('created', 'accepted', 'declined', 'opened', 'saved', 'revoked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS qv_share_events_share ON public.qv_share_events(share_id, created_at DESC);

ALTER TABLE public.qv_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qv_share_recipients ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qv_share_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.qv_share_events ENABLE ROW LEVEL SECURITY;

-- Helpers for the policies (SECURITY DEFINER so policies do not recurse into
-- each other's RLS). Each answers only about the caller.
CREATE OR REPLACE FUNCTION public.qv_share_owned(p_share_id UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.qv_shares s WHERE s.id = p_share_id AND s.owner_user_id = auth.uid());
$$;

-- The caller is a recipient whose access is live: not revoked, not declined,
-- share not revoked or expired, object committed. `p_accepted` additionally
-- requires the caller to have accepted.
CREATE OR REPLACE FUNCTION public.qv_share_live_for_me(p_share_id UUID, p_accepted BOOLEAN)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.qv_shares s
    JOIN public.qv_share_recipients r ON r.share_id = s.id
    JOIN public.qv_cloud_objects o ON o.id = s.object_id
    WHERE s.id = p_share_id
      AND r.recipient_user_id = auth.uid()
      AND s.revoked_at IS NULL
      AND (s.expires_at IS NULL OR s.expires_at > now())
      AND o.status = 'committed'
      AND (CASE WHEN p_accepted THEN r.status = 'accepted' ELSE r.status IN ('pending', 'accepted') END)
  );
$$;

CREATE OR REPLACE FUNCTION public.qv_object_shared_with_me(p_object_id UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.qv_shares s
    WHERE s.object_id = p_object_id AND public.qv_share_live_for_me(s.id, true)
  );
$$;

-- A live (not revoked) device of that user. Its own definer function so the
-- envelope rule does not depend on how messaging_devices' RLS evolves.
CREATE OR REPLACE FUNCTION public.qv_device_belongs_to(p_device_id UUID, p_user_id UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.messaging_devices d
    WHERE d.id = p_device_id AND d.user_id = p_user_id AND d.revoked_at IS NULL
  );
$$;
REVOKE ALL ON FUNCTION public.qv_device_belongs_to(UUID, UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.qv_device_belongs_to(UUID, UUID) TO authenticated;

REVOKE ALL ON FUNCTION public.qv_share_owned(UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_share_live_for_me(UUID, BOOLEAN) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_object_shared_with_me(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.qv_share_owned(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_share_live_for_me(UUID, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_object_shared_with_me(UUID) TO authenticated;

DROP POLICY IF EXISTS qv_shares_read ON public.qv_shares;
CREATE POLICY qv_shares_read ON public.qv_shares
  FOR SELECT TO authenticated
  USING (owner_user_id = auth.uid() OR public.qv_share_live_for_me(id, false));

DROP POLICY IF EXISTS qv_share_recipients_read ON public.qv_share_recipients;
CREATE POLICY qv_share_recipients_read ON public.qv_share_recipients
  FOR SELECT TO authenticated
  USING (recipient_user_id = auth.uid() OR public.qv_share_owned(share_id));

DROP POLICY IF EXISTS qv_share_envelopes_read ON public.qv_share_envelopes;
CREATE POLICY qv_share_envelopes_read ON public.qv_share_envelopes
  FOR SELECT TO authenticated
  USING (
    public.qv_share_owned(share_id)
    OR (recipient_user_id = auth.uid() AND public.qv_share_live_for_me(share_id, false))
  );

-- The sender adds envelopes for recipients of their own live share, from one
-- of their own devices, to a device of that recipient.
DROP POLICY IF EXISTS qv_share_envelopes_insert ON public.qv_share_envelopes;
CREATE POLICY qv_share_envelopes_insert ON public.qv_share_envelopes
  FOR INSERT TO authenticated
  WITH CHECK (
    public.qv_share_owned(share_id)
    AND public.messaging_owns_device(sender_device_id)
    AND EXISTS (
      SELECT 1 FROM public.qv_share_recipients r
      WHERE r.share_id = qv_share_envelopes.share_id
        AND r.recipient_user_id = qv_share_envelopes.recipient_user_id
        AND r.status IN ('pending', 'accepted')
    )
    AND public.qv_device_belongs_to(recipient_device_id, recipient_user_id)
    AND EXISTS (SELECT 1 FROM public.qv_shares s WHERE s.id = qv_share_envelopes.share_id AND s.revoked_at IS NULL)
  );

DROP POLICY IF EXISTS qv_share_events_read ON public.qv_share_events;
CREATE POLICY qv_share_events_read ON public.qv_share_events
  FOR SELECT TO authenticated
  USING (public.qv_share_owned(share_id) OR actor_user_id = auth.uid());

-- Recipients read the shared object's row (sizes and hashes, to download and
-- check it) — and nothing else of the owner's.
DROP POLICY IF EXISTS qv_objects_share_read ON public.qv_cloud_objects;
CREATE POLICY qv_objects_share_read ON public.qv_cloud_objects
  FOR SELECT TO authenticated
  USING (kind = 'file' AND public.qv_object_shared_with_me(id));

-- ...and its parts in storage.
DROP POLICY IF EXISTS qv_storage_share_read ON storage.objects;
CREATE POLICY qv_storage_share_read ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'quantum-vault'
    AND array_length(storage.foldername(name), 1) = 2
    -- Compared as text: Postgres may evaluate policy conditions in any order,
    -- so a cast here could fail on a name in another folder.
    AND EXISTS (
      SELECT 1 FROM public.qv_shares s
      WHERE s.object_id::TEXT = (storage.foldername(name))[2]
        AND s.owner_user_id::TEXT = (storage.foldername(name))[1]
        AND public.qv_share_live_for_me(s.id, true)
    )
  );

-- Create a share of one of the caller's committed file objects. Recipients who
-- blocked or restricted the caller are silently left out (as with messages,
-- the sender is not told). Returns the share id and who was included.
CREATE OR REPLACE FUNCTION public.qv_share_create(
  p_object_id UUID,
  p_recipients UUID[],
  p_permission TEXT,
  p_expires_at TIMESTAMPTZ DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
  v_share UUID;
  v_included UUID[] := ARRAY[]::UUID[];
  v_recipient UUID;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  IF p_permission NOT IN ('view', 'download') THEN
    RAISE EXCEPTION 'QV_INVALID_PERMISSION';
  END IF;
  IF p_expires_at IS NOT NULL AND (p_expires_at <= now() OR p_expires_at > now() + interval '366 days') THEN
    RAISE EXCEPTION 'QV_INVALID_EXPIRY';
  END IF;
  IF p_recipients IS NULL OR array_length(p_recipients, 1) IS NULL OR array_length(p_recipients, 1) > 50 THEN
    RAISE EXCEPTION 'QV_INVALID_RECIPIENTS';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.qv_cloud_objects o
    WHERE o.id = p_object_id AND o.owner_user_id = uid AND o.kind = 'file' AND o.status = 'committed'
  ) THEN
    RAISE EXCEPTION 'QV_OBJECT_NOT_FOUND';
  END IF;
  -- A plan with cloud backup is what sharing is part of.
  IF public.qv_cloud_quota_bytes(uid) <= 0 THEN
    RAISE EXCEPTION 'QV_NO_CLOUD_ENTITLEMENT';
  END IF;

  INSERT INTO public.qv_shares (owner_user_id, object_id, permission, expires_at)
  VALUES (uid, p_object_id, p_permission, p_expires_at)
  RETURNING id INTO v_share;

  FOREACH v_recipient IN ARRAY p_recipients LOOP
    CONTINUE WHEN v_recipient IS NULL OR v_recipient = uid OR v_recipient = ANY (v_included);
    CONTINUE WHEN NOT EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = v_recipient);
    CONTINUE WHEN COALESCE(public.qguard_contact_state(v_recipient, uid), '') IN ('blocked', 'restricted');
    INSERT INTO public.qv_share_recipients (share_id, recipient_user_id) VALUES (v_share, v_recipient);
    v_included := v_included || v_recipient;
  END LOOP;

  INSERT INTO public.qv_share_events (share_id, actor_user_id, event) VALUES (v_share, uid, 'created');
  RETURN jsonb_build_object('share_id', v_share, 'recipients', to_jsonb(v_included));
END;
$$;

CREATE OR REPLACE FUNCTION public.qv_share_respond(p_share_id UUID, p_accept BOOLEAN)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
  v_status TEXT := CASE WHEN p_accept THEN 'accepted' ELSE 'declined' END;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  IF NOT public.qv_share_live_for_me(p_share_id, false) THEN
    RAISE EXCEPTION 'QV_SHARE_NOT_AVAILABLE';
  END IF;
  UPDATE public.qv_share_recipients
  SET status = v_status, responded_at = now()
  WHERE share_id = p_share_id AND recipient_user_id = uid;
  INSERT INTO public.qv_share_events (share_id, actor_user_id, event) VALUES (p_share_id, uid, v_status);
  IF NOT p_accept THEN
    DELETE FROM public.qv_share_envelopes WHERE share_id = p_share_id AND recipient_user_id = uid;
  END IF;
  RETURN v_status;
END;
$$;

-- Revoke a whole share (p_recipient NULL) or one recipient. Envelopes go too,
-- so the relay stops holding keys for them.
CREATE OR REPLACE FUNCTION public.qv_share_revoke(p_share_id UUID, p_recipient UUID DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  IF NOT public.qv_share_owned(p_share_id) THEN
    RAISE EXCEPTION 'QV_SHARE_NOT_FOUND';
  END IF;
  IF p_recipient IS NULL THEN
    UPDATE public.qv_shares SET revoked_at = COALESCE(revoked_at, now()) WHERE id = p_share_id;
    UPDATE public.qv_share_recipients SET status = 'revoked', responded_at = now() WHERE share_id = p_share_id;
    DELETE FROM public.qv_share_envelopes WHERE share_id = p_share_id;
  ELSE
    UPDATE public.qv_share_recipients SET status = 'revoked', responded_at = now()
    WHERE share_id = p_share_id AND recipient_user_id = p_recipient;
    DELETE FROM public.qv_share_envelopes WHERE share_id = p_share_id AND recipient_user_id = p_recipient;
  END IF;
  INSERT INTO public.qv_share_events (share_id, actor_user_id, event) VALUES (p_share_id, uid, 'revoked');
  RETURN TRUE;
END;
$$;

-- A recipient's own record that they opened or saved the file (the server
-- cannot observe either: both happen on the recipient's device).
CREATE OR REPLACE FUNCTION public.qv_share_record(p_share_id UUID, p_event TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  IF p_event NOT IN ('opened', 'saved') THEN
    RAISE EXCEPTION 'QV_INVALID_EVENT';
  END IF;
  IF NOT public.qv_share_live_for_me(p_share_id, true) THEN
    RAISE EXCEPTION 'QV_SHARE_NOT_AVAILABLE';
  END IF;
  INSERT INTO public.qv_share_events (share_id, actor_user_id, event) VALUES (p_share_id, uid, p_event);
  RETURN TRUE;
END;
$$;

-- ===========================================================================
-- Privileges (per role; see 048 for why)
-- ===========================================================================
REVOKE ALL ON FUNCTION public.qv_begin_upload(TEXT, UUID, BIGINT, TEXT[], TEXT, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.qv_begin_upload(TEXT, UUID, BIGINT, TEXT[], TEXT, TEXT) TO authenticated;

REVOKE ALL ON FUNCTION public.qv_publish_library(UUID, BIGINT, INTEGER, TEXT) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_library_set_recovery(INTEGER, JSONB) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_share_create(UUID, UUID[], TEXT, TIMESTAMPTZ) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_share_respond(UUID, BOOLEAN) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_share_revoke(UUID, UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_share_record(UUID, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.qv_publish_library(UUID, BIGINT, INTEGER, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_library_set_recovery(INTEGER, JSONB) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_share_create(UUID, UUID[], TEXT, TIMESTAMPTZ) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_share_respond(UUID, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_share_revoke(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_share_record(UUID, TEXT) TO authenticated;

REVOKE ALL ON public.qv_library_state, public.qv_library_key_wraps, public.qv_library_recovery,
  public.qv_shares, public.qv_share_recipients, public.qv_share_envelopes, public.qv_share_events
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON SEQUENCE public.qv_share_events_id_seq FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.qv_library_state, public.qv_library_recovery,
  public.qv_shares, public.qv_share_recipients, public.qv_share_events TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.qv_library_key_wraps TO authenticated;
GRANT SELECT, INSERT ON public.qv_share_envelopes TO authenticated;

-- Live updates for incoming shares and library changes.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND tablename = 'qv_share_recipients') THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.qv_share_recipients;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND tablename = 'qv_library_state') THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.qv_library_state;
    END IF;
  END IF;
END $$;

NOTIFY pgrst, 'reload schema';
