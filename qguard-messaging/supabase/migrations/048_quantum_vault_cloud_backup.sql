-- 048: Quantum Vault cloud backup (phase 2, Qguard_Wiki/Quantum Vault §4B, §8, §9).
--
-- What the server holds: ciphertext only. A backed-up file is the device's
-- existing v5 vault container (AES-256-GCM chunks, per-file key sealed under the
-- vault key and the user's recovery key, Ed25519 + ML-DSA-87 signed header),
-- whose header carries no file name or type. Names, folders and types travel
-- only inside the index copy sealed under the user's recovery key. The server
-- never receives a key, a name, a type or a plaintext hash.
--
-- Shape:
--   * Every object (a file container, or the sealed recovery index) is split into
--     8 MiB parts at `quantum-vault/<user>/<object id>/<part, 5 digits>`. Parts are
--     immutable (no UPDATE policy), and the bucket refuses anything over 8 MiB, so
--     the bytes a reservation can actually consume are bounded by its part count.
--   * Writing a part requires an `uploading` row in qv_cloud_objects for that
--     object, owned by the caller, with the part index in range. Rows are created
--     ONLY by qv_begin_upload, which checks the caller's quota under a per-user
--     lock. So the quota is enforced by the database, never by the client.
--   * qv_commit_upload counts the parts and their sizes in storage.objects and
--     marks the object committed only when every part is present and the sizes
--     add up exactly to the reserved container size.
--   * Quotas come from qv_plan_quotas (one row per plan; change a row to change a
--     plan's quota) and the account's subscription in billing_subscriptions, using
--     the same access rule and 72 h grace as the messaging paywall (migration
--     030). A lapsed subscription stops NEW uploads only: reading, downloading and
--     deleting existing backups keep working, and nothing is deleted.
--
-- Rollback: DROP the four qv_* functions, the qv_cloud_* tables, qv_plan_quotas,
-- the four qv_storage_* policies, and (after emptying it) the bucket.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'qguard_has_messaging_access') THEN
    RAISE EXCEPTION '048 needs qguard_has_messaging_access (migration 030) for the subscription rule';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Plan quotas (configuration, not code)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.qv_plan_quotas (
  plan TEXT PRIMARY KEY CHECK (plan = lower(plan)),
  quota_bytes BIGINT NOT NULL CHECK (quota_bytes >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO public.qv_plan_quotas (plan, quota_bytes) VALUES
  ('starter', 0),
  ('basic', 2147483648),
  ('pro', 10737418240),
  ('elite', 107374182400)
ON CONFLICT (plan) DO NOTHING;

ALTER TABLE public.qv_plan_quotas ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS qv_plan_quotas_read ON public.qv_plan_quotas;
CREATE POLICY qv_plan_quotas_read ON public.qv_plan_quotas FOR SELECT TO authenticated USING (true);

-- ---------------------------------------------------------------------------
-- Backed-up objects
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.qv_cloud_objects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  -- 'file': one vault container. 'recovery_index': the vault index sealed under
  -- the user's recovery key (names / folders, opaque to the server).
  kind TEXT NOT NULL CHECK (kind IN ('file', 'recovery_index')),
  -- The vault entry id (a random UUID) for files; NULL for the index.
  entry_id UUID,
  container_bytes BIGINT NOT NULL CHECK (container_bytes > 0 AND container_bytes <= 35433480192),
  part_size INTEGER NOT NULL CHECK (part_size = 8388608),
  part_count INTEGER NOT NULL,
  -- SHA3-256 per part and of the whole container, computed by the device. The
  -- server cannot compute SHA3; the device re-checks both on every download.
  part_sha3 TEXT[] NOT NULL,
  container_sha3 TEXT NOT NULL CHECK (container_sha3 ~ '^[0-9a-f]{64}$'),
  -- Measured from storage.objects at commit.
  stored_bytes BIGINT,
  status TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'committed', 'deleting')),
  device_id TEXT CHECK (device_id IS NULL OR length(device_id) <= 128),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  committed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT qv_cloud_objects_entry_matches_kind CHECK ((kind = 'file') = (entry_id IS NOT NULL)),
  CONSTRAINT qv_cloud_objects_part_count CHECK (
    part_count = ((container_bytes + part_size - 1) / part_size)
    AND array_length(part_sha3, 1) = part_count
  )
);

-- At most one live copy of each vault file.
CREATE UNIQUE INDEX IF NOT EXISTS qv_cloud_objects_one_live_file
  ON public.qv_cloud_objects(owner_user_id, entry_id)
  WHERE kind = 'file' AND status <> 'deleting';
CREATE INDEX IF NOT EXISTS qv_cloud_objects_owner_status
  ON public.qv_cloud_objects(owner_user_id, status, kind);

ALTER TABLE public.qv_cloud_objects ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS qv_cloud_objects_owner_read ON public.qv_cloud_objects;
CREATE POLICY qv_cloud_objects_owner_read ON public.qv_cloud_objects
  FOR SELECT TO authenticated USING (owner_user_id = auth.uid());
-- No INSERT / UPDATE / DELETE policies: rows change only through the
-- SECURITY DEFINER functions below, which check ownership and quota.

-- ---------------------------------------------------------------------------
-- Storage history (no names; sizes and events only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.qv_cloud_audit (
  id BIGSERIAL PRIMARY KEY,
  owner_user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK (event IN ('upload_reserved', 'upload_committed', 'delete_started', 'delete_finished')),
  object_id UUID,
  kind TEXT,
  bytes BIGINT,
  used_bytes_after BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS qv_cloud_audit_owner_time ON public.qv_cloud_audit(owner_user_id, created_at DESC);
ALTER TABLE public.qv_cloud_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS qv_cloud_audit_owner_read ON public.qv_cloud_audit;
CREATE POLICY qv_cloud_audit_owner_read ON public.qv_cloud_audit
  FOR SELECT TO authenticated USING (owner_user_id = auth.uid());

-- ---------------------------------------------------------------------------
-- Quota
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.qv_cloud_quota_bytes(uid UUID)
RETURNS BIGINT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT CASE WHEN public.qguard_has_messaging_access(uid) THEN
    COALESCE((
      SELECT q.quota_bytes
      FROM public.billing_subscriptions s
      JOIN public.qv_plan_quotas q ON q.plan = lower(s.plan)
      WHERE s.user_id = uid
      ORDER BY q.quota_bytes DESC
      LIMIT 1
    ), 0)
  ELSE 0 END;
$$;

-- Bytes charged to the quota: every file object, measured once committed and
-- reserved before. The recovery index is not charged (see qv_begin_upload).
CREATE OR REPLACE FUNCTION public.qv_cloud_used_bytes(uid UUID)
RETURNS BIGINT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT COALESCE(SUM(COALESCE(o.stored_bytes, o.container_bytes)), 0)::BIGINT
  FROM public.qv_cloud_objects o
  WHERE o.owner_user_id = uid AND o.kind = 'file';
$$;

CREATE OR REPLACE FUNCTION public.qv_cloud_usage()
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
  v_plan TEXT;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  SELECT s.plan INTO v_plan FROM public.billing_subscriptions s WHERE s.user_id = uid LIMIT 1;
  RETURN jsonb_build_object(
    'plan', v_plan,
    'has_access', public.qguard_has_messaging_access(uid),
    'quota_bytes', public.qv_cloud_quota_bytes(uid),
    -- Exactly what qv_begin_upload charges: file objects in any state.
    'used_bytes', (SELECT COALESCE(SUM(COALESCE(stored_bytes, container_bytes)), 0) FROM public.qv_cloud_objects WHERE owner_user_id = uid AND kind = 'file' AND status <> 'uploading'),
    'reserved_bytes', (SELECT COALESCE(SUM(container_bytes), 0) FROM public.qv_cloud_objects WHERE owner_user_id = uid AND kind = 'file' AND status = 'uploading'),
    'index_bytes', (SELECT COALESCE(SUM(COALESCE(stored_bytes, container_bytes)), 0) FROM public.qv_cloud_objects WHERE owner_user_id = uid AND kind = 'recovery_index'),
    'files', (SELECT count(*) FROM public.qv_cloud_objects WHERE owner_user_id = uid AND kind = 'file' AND status = 'committed'),
    'last_backup_at', (SELECT max(committed_at) FROM public.qv_cloud_objects WHERE owner_user_id = uid AND status = 'committed')
  );
END;
$$;

-- ---------------------------------------------------------------------------
-- Upload lifecycle
-- ---------------------------------------------------------------------------

-- Reserve space for one object. Idempotent: the same object (same kind, entry
-- and container hash) returns the existing row, so an interrupted upload
-- resumes instead of reserving twice.
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
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  IF p_kind NOT IN ('file', 'recovery_index') THEN
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

  -- One reservation decision at a time per user.
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

  IF p_kind = 'recovery_index' THEN
    -- The index is small and replaced as a whole: at most the current copy and
    -- one replacement in flight, and capped at 64 MiB. It is not charged to the
    -- quota, so a user at their quota can still keep their names recoverable.
    IF p_container_bytes > 67108864 THEN
      RAISE EXCEPTION 'QV_INDEX_TOO_LARGE';
    END IF;
    IF (SELECT count(*) FROM public.qv_cloud_objects o
        WHERE o.owner_user_id = uid AND o.kind = 'recovery_index' AND o.status <> 'deleting') >= 2 THEN
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

-- Mark an object committed once storage holds exactly its parts.
CREATE OR REPLACE FUNCTION public.qv_commit_upload(p_object_id UUID)
RETURNS public.qv_cloud_objects
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, storage
AS $$
DECLARE
  uid UUID := auth.uid();
  v_row public.qv_cloud_objects;
  v_parts INTEGER;
  v_bytes BIGINT;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('qv_cloud:' || uid::TEXT));
  SELECT * INTO v_row FROM public.qv_cloud_objects WHERE id = p_object_id AND owner_user_id = uid FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'QV_OBJECT_NOT_FOUND';
  END IF;
  IF v_row.status = 'committed' THEN
    RETURN v_row;
  END IF;
  IF v_row.status <> 'uploading' THEN
    RAISE EXCEPTION 'QV_OBJECT_NOT_UPLOADING';
  END IF;

  SELECT count(*), COALESCE(SUM((so.metadata->>'size')::BIGINT), 0)
  INTO v_parts, v_bytes
  FROM storage.objects so
  WHERE so.bucket_id = 'quantum-vault'
    AND so.name LIKE uid::TEXT || '/' || p_object_id::TEXT || '/%';

  IF v_parts <> v_row.part_count THEN
    RAISE EXCEPTION 'QV_PARTS_MISSING' USING DETAIL = format('have=%s need=%s', v_parts, v_row.part_count);
  END IF;
  IF v_bytes <> v_row.container_bytes THEN
    RAISE EXCEPTION 'QV_SIZE_MISMATCH' USING DETAIL = format('have=%s need=%s', v_bytes, v_row.container_bytes);
  END IF;

  UPDATE public.qv_cloud_objects
  SET status = 'committed', stored_bytes = v_bytes, committed_at = now(), updated_at = now()
  WHERE id = p_object_id
  RETURNING * INTO v_row;

  INSERT INTO public.qv_cloud_audit (owner_user_id, event, object_id, kind, bytes, used_bytes_after)
  VALUES (uid, 'upload_committed', v_row.id, v_row.kind, v_bytes, public.qv_cloud_used_bytes(uid));
  RETURN v_row;
END;
$$;

-- Start deleting an object (also how an abandoned upload is aborted). Its space
-- stays counted until qv_finish_delete confirms the parts are gone.
CREATE OR REPLACE FUNCTION public.qv_begin_delete(p_object_id UUID)
RETURNS public.qv_cloud_objects
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
  v_row public.qv_cloud_objects;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  UPDATE public.qv_cloud_objects
  SET status = 'deleting', updated_at = now()
  WHERE id = p_object_id AND owner_user_id = uid
  RETURNING * INTO v_row;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'QV_OBJECT_NOT_FOUND';
  END IF;
  INSERT INTO public.qv_cloud_audit (owner_user_id, event, object_id, kind, bytes)
  VALUES (uid, 'delete_started', v_row.id, v_row.kind, COALESCE(v_row.stored_bytes, v_row.container_bytes));
  RETURN v_row;
END;
$$;

-- Remove the row once no part remains in storage. Returns false (and keeps the
-- row) while parts are still there. An unknown id is already deleted: true.
CREATE OR REPLACE FUNCTION public.qv_finish_delete(p_object_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, storage
AS $$
DECLARE
  uid UUID := auth.uid();
  v_row public.qv_cloud_objects;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'QV_NOT_AUTHENTICATED' USING ERRCODE = '28000';
  END IF;
  SELECT * INTO v_row FROM public.qv_cloud_objects WHERE id = p_object_id AND owner_user_id = uid FOR UPDATE;
  IF NOT FOUND THEN
    RETURN TRUE;
  END IF;
  IF v_row.status <> 'deleting' THEN
    RAISE EXCEPTION 'QV_OBJECT_NOT_DELETING';
  END IF;
  IF EXISTS (
    SELECT 1 FROM storage.objects so
    WHERE so.bucket_id = 'quantum-vault'
      AND so.name LIKE uid::TEXT || '/' || p_object_id::TEXT || '/%'
  ) THEN
    RETURN FALSE;
  END IF;
  DELETE FROM public.qv_cloud_objects WHERE id = p_object_id;
  INSERT INTO public.qv_cloud_audit (owner_user_id, event, object_id, kind, bytes, used_bytes_after)
  VALUES (uid, 'delete_finished', p_object_id, v_row.kind, COALESCE(v_row.stored_bytes, v_row.container_bytes), public.qv_cloud_used_bytes(uid));
  RETURN TRUE;
END;
$$;

-- Privileges. Supabase grants every new table and function in `public` to
-- anon / authenticated / service_role directly (default privileges), so
-- `REVOKE ... FROM PUBLIC` alone takes nothing away. Each role is named.
--   * The quota helpers take ANY user id: only the functions above may call
--     them, or any caller could read another account's quota and usage.
--   * The RPCs are for signed-in users only.
--   * Tables: read-only for signed-in users (RLS limits rows to their own);
--     nothing for anon. TRUNCATE in particular bypasses RLS entirely.
REVOKE ALL ON FUNCTION public.qv_cloud_quota_bytes(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.qv_cloud_used_bytes(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.qv_cloud_usage() FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_begin_upload(TEXT, UUID, BIGINT, TEXT[], TEXT, TEXT) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_commit_upload(UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_begin_delete(UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.qv_finish_delete(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.qv_cloud_usage() TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_begin_upload(TEXT, UUID, BIGINT, TEXT[], TEXT, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_commit_upload(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_begin_delete(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.qv_finish_delete(UUID) TO authenticated;

REVOKE ALL ON public.qv_plan_quotas, public.qv_cloud_objects, public.qv_cloud_audit FROM PUBLIC, anon, authenticated;
REVOKE ALL ON SEQUENCE public.qv_cloud_audit_id_seq FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.qv_plan_quotas TO authenticated;
GRANT SELECT ON public.qv_cloud_objects TO authenticated;
GRANT SELECT ON public.qv_cloud_audit TO authenticated;

-- ---------------------------------------------------------------------------
-- Storage: private bucket, ciphertext parts only
-- ---------------------------------------------------------------------------
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('quantum-vault', 'quantum-vault', false, 8388608, ARRAY['application/octet-stream'])
ON CONFLICT (id) DO UPDATE
  SET public = false, file_size_limit = 8388608, allowed_mime_types = ARRAY['application/octet-stream'];

DROP POLICY IF EXISTS qv_storage_read ON storage.objects;
CREATE POLICY qv_storage_read ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'quantum-vault'
    AND (storage.foldername(name))[1] = auth.uid()::TEXT
  );

-- A part may be written only into a reservation made by qv_begin_upload.
DROP POLICY IF EXISTS qv_storage_insert ON storage.objects;
CREATE POLICY qv_storage_insert ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'quantum-vault'
    AND (storage.foldername(name))[1] = auth.uid()::TEXT
    AND array_length(storage.foldername(name), 1) = 2
    AND storage.filename(name) ~ '^[0-9]{5}$'
    AND EXISTS (
      SELECT 1 FROM public.qv_cloud_objects o
      WHERE o.id::TEXT = (storage.foldername(name))[2]
        AND o.owner_user_id = auth.uid()
        AND o.status = 'uploading'
        AND storage.filename(name)::INTEGER < o.part_count
    )
  );

-- No UPDATE policy: parts are immutable (no upsert / overwrite).
DROP POLICY IF EXISTS qv_storage_update ON storage.objects;

DROP POLICY IF EXISTS qv_storage_delete ON storage.objects;
CREATE POLICY qv_storage_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'quantum-vault'
    AND (storage.foldername(name))[1] = auth.uid()::TEXT
  );

NOTIFY pgrst, 'reload schema';
