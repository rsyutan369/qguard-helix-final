-- Checks for migration 048, run as real `authenticated` sessions against RLS.
-- Order: 048_bootstrap.sql, migrations/048_quantum_vault_cloud_backup.sql, this file.
-- Every check RAISEs on failure; the run ends with 'ALL 048 CHECKS PASSED'.

\set ON_ERROR_STOP on

CREATE SCHEMA IF NOT EXISTS qvtest;
GRANT USAGE ON SCHEMA qvtest TO authenticated, anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA qvtest GRANT EXECUTE ON FUNCTIONS TO authenticated, anon;

CREATE OR REPLACE FUNCTION qvtest.act_as(uid UUID) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  PERFORM set_config('request.jwt.claim.sub', uid::TEXT, true);
  PERFORM set_config('role', 'authenticated', true);
END $$;

CREATE OR REPLACE FUNCTION qvtest.act_as_admin() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  PERFORM set_config('role', 'postgres', true);
  PERFORM set_config('request.jwt.claim.sub', '', true);
END $$;

-- Expect `stmt` to fail with an error whose message contains `needle`.
CREATE OR REPLACE FUNCTION qvtest.expect_error(stmt TEXT, needle TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  BEGIN
    EXECUTE stmt;
  EXCEPTION WHEN OTHERS THEN
    IF position(needle IN SQLERRM) = 0 THEN
      RAISE EXCEPTION 'expected error containing "%" from [%], got: %', needle, stmt, SQLERRM;
    END IF;
    RETURN;
  END;
  RAISE EXCEPTION 'expected error containing "%" from [%], but it succeeded', needle, stmt;
END $$;

CREATE OR REPLACE FUNCTION qvtest.hashes(n INTEGER) RETURNS TEXT[] LANGUAGE sql AS $$
  SELECT array_agg(repeat('a', 63) || (i % 10)::TEXT) FROM generate_series(1, n) i
$$;

-- Accounts: A Basic active, B Pro active, C no subscription, D Pro expired,
-- E Starter active (local-only plan).
INSERT INTO auth.users VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001'), ('bbbbbbbb-0000-4000-8000-000000000002'),
  ('cccccccc-0000-4000-8000-000000000003'), ('dddddddd-0000-4000-8000-000000000004'),
  ('eeeeeeee-0000-4000-8000-000000000005');
INSERT INTO public.profiles SELECT id FROM auth.users;
INSERT INTO public.billing_subscriptions VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', 'Basic', 'active', now() + interval '20 days'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'Pro', 'active', NULL),
  ('dddddddd-0000-4000-8000-000000000004', 'Pro', 'expired', now() - interval '10 days'),
  ('eeeeeeee-0000-4000-8000-000000000005', 'Starter', 'active', NULL);

DO $$
DECLARE
  a CONSTANT UUID := 'aaaaaaaa-0000-4000-8000-000000000001';
  b CONSTANT UUID := 'bbbbbbbb-0000-4000-8000-000000000002';
  c CONSTANT UUID := 'cccccccc-0000-4000-8000-000000000003';
  d CONSTANT UUID := 'dddddddd-0000-4000-8000-000000000004';
  e CONSTANT UUID := 'eeeeeeee-0000-4000-8000-000000000005';
  entry1 CONSTANT UUID := '11111111-1111-4111-8111-111111111111';
  part CONSTANT BIGINT := 8388608;
  usage JSONB;
  obj public.qv_cloud_objects;
  again public.qv_cloud_objects;
  n INTEGER;
  ok BOOLEAN;
  u UUID;
BEGIN
  -- Quotas come from the plan table and the subscription.
  PERFORM qvtest.act_as(a);
  usage := public.qv_cloud_usage();
  IF (usage->>'quota_bytes')::BIGINT <> 2147483648 OR (usage->>'has_access')::BOOLEAN IS NOT TRUE THEN
    RAISE EXCEPTION 'Basic quota wrong: %', usage;
  END IF;
  PERFORM qvtest.act_as(b);
  IF (public.qv_cloud_usage()->>'quota_bytes')::BIGINT <> 10737418240 THEN RAISE EXCEPTION 'Pro quota wrong'; END IF;
  RAISE NOTICE 'ok: plan quotas (Basic 2 GiB, Pro 10 GiB)';

  -- No subscription, an expired one, or a local-only plan: no new uploads.
  FOREACH u IN ARRAY ARRAY[c, d, e] LOOP
    PERFORM qvtest.act_as(u);
    PERFORM qvtest.expect_error(
      format('SELECT public.qv_begin_upload(%L, %L, 100, %L, %L)', 'file', entry1, qvtest.hashes(1), repeat('b', 64)),
      'QV_NO_CLOUD_ENTITLEMENT');
    PERFORM qvtest.expect_error(
      format('SELECT public.qv_begin_upload(%L, NULL, 100, %L, %L)', 'recovery_index', qvtest.hashes(1), repeat('b', 64)),
      'QV_NO_CLOUD_ENTITLEMENT');
  END LOOP;
  RAISE NOTICE 'ok: no entitlement (none / expired / Starter) blocks file and index uploads';

  -- A reserves a 3-part object; the same request again is the same reservation.
  PERFORM qvtest.act_as(a);
  obj := public.qv_begin_upload('file', entry1, 2 * part + 100, qvtest.hashes(3), repeat('c', 64), 'device-1');
  IF obj.part_count <> 3 OR obj.status <> 'uploading' OR obj.owner_user_id <> a THEN RAISE EXCEPTION 'bad reservation %', obj; END IF;
  again := public.qv_begin_upload('file', entry1, 2 * part + 100, qvtest.hashes(3), repeat('c', 64), 'device-1');
  IF again.id <> obj.id THEN RAISE EXCEPTION 'begin_upload is not idempotent'; END IF;
  -- Malformed requests.
  PERFORM qvtest.expect_error(format('SELECT public.qv_begin_upload(%L, %L, %s, %L, %L)', 'file', entry1, 2 * part + 100, qvtest.hashes(2), repeat('d', 64)), 'QV_ENTRY_ALREADY_BACKED_UP');
  PERFORM qvtest.expect_error(format('SELECT public.qv_begin_upload(%L, gen_random_uuid(), %s, %L, %L)', 'file', 2 * part + 100, qvtest.hashes(2), repeat('d', 64)), 'qv_cloud_objects_part_count');
  PERFORM qvtest.expect_error(format('SELECT public.qv_begin_upload(%L, gen_random_uuid(), 10, %L, %L)', 'file', ARRAY['not-a-hash'], repeat('d', 64)), 'QV_INVALID_HASH');
  PERFORM qvtest.expect_error(format('SELECT public.qv_begin_upload(%L, NULL, 10, %L, %L)', 'file', qvtest.hashes(1), repeat('d', 64)), 'QV_INVALID_ENTRY');
  RAISE NOTICE 'ok: reservation, idempotency, one live copy per entry, input validation';

  -- Quota: 2 GiB cannot be reserved on top of what A already holds.
  PERFORM qvtest.expect_error(
    format('SELECT public.qv_begin_upload(%L, gen_random_uuid(), %s, %L, %L)', 'file', 2147483648, qvtest.hashes(256), repeat('e', 64)),
    'QV_QUOTA_EXCEEDED');
  RAISE NOTICE 'ok: quota enforced by the database, counting reservations';

  -- Clients cannot write rows directly (Supabase grants the table; RLS has no
  -- write policy, so inserts are refused and updates / deletes match nothing).
  PERFORM qvtest.expect_error(
    format('INSERT INTO public.qv_cloud_objects (owner_user_id, kind, entry_id, container_bytes, part_size, part_count, part_sha3, container_sha3, status) VALUES (%L, %L, gen_random_uuid(), 1, %s, 1, %L, %L, %L)', a, 'file', part, qvtest.hashes(1), repeat('f', 64), 'committed'),
    'permission denied');
  PERFORM qvtest.expect_error(format('UPDATE public.qv_cloud_objects SET status = %L, container_bytes = 1', 'committed'), 'permission denied');
  PERFORM qvtest.expect_error('DELETE FROM public.qv_cloud_objects', 'permission denied');
  PERFORM qvtest.expect_error(format('INSERT INTO public.qv_cloud_audit (owner_user_id, event) VALUES (%L, %L)', a, 'upload_committed'), 'permission denied');
  -- TRUNCATE ignores RLS: it must not be granted at all.
  PERFORM qvtest.expect_error('TRUNCATE public.qv_cloud_objects CASCADE', 'permission denied');
  PERFORM qvtest.expect_error('TRUNCATE public.qv_cloud_audit', 'permission denied');
  PERFORM qvtest.expect_error('TRUNCATE public.qv_plan_quotas', 'permission denied');
  PERFORM qvtest.expect_error(format('UPDATE public.qv_plan_quotas SET quota_bytes = %s', 999999999999), 'permission denied');
  RAISE NOTICE 'ok: no direct writes to qv_cloud_objects, qv_cloud_audit or qv_plan_quotas';

  -- Storage: parts only inside the reservation.
  INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES
    ('quantum-vault', a || '/' || obj.id || '/00000', a, jsonb_build_object('size', part)),
    ('quantum-vault', a || '/' || obj.id || '/00001', a, jsonb_build_object('size', part));
  PERFORM qvtest.expect_error(format('SELECT public.qv_commit_upload(%L)', obj.id), 'QV_PARTS_MISSING');
  PERFORM qvtest.expect_error(format('INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES (%L, %L, %L, %L)',
    'quantum-vault', a || '/' || obj.id || '/00003', a, '{"size":1}'), 'row-level security');
  PERFORM qvtest.expect_error(format('INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES (%L, %L, %L, %L)',
    'quantum-vault', a || '/' || obj.id || '/part-2', a, '{"size":1}'), 'row-level security');
  PERFORM qvtest.expect_error(format('INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES (%L, %L, %L, %L)',
    'quantum-vault', a || '/' || gen_random_uuid() || '/00000', a, '{"size":1}'), 'row-level security');
  -- Parts are immutable: UPDATE matches nothing.
  UPDATE storage.objects SET metadata = '{"size":1}' WHERE bucket_id = 'quantum-vault';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'storage parts were updatable'; END IF;
  -- A wrong-sized last part is refused at commit.
  INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES
    ('quantum-vault', a || '/' || obj.id || '/00002', a, jsonb_build_object('size', 99));
  PERFORM qvtest.expect_error(format('SELECT public.qv_commit_upload(%L)', obj.id), 'QV_SIZE_MISMATCH');
  RAISE NOTICE 'ok: storage writes confined to the reservation; parts immutable; commit checks count and size';

  -- Fix the part (as the owner: delete then re-insert) and commit.
  DELETE FROM storage.objects WHERE name = a || '/' || obj.id || '/00002';
  INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES
    ('quantum-vault', a || '/' || obj.id || '/00002', a, jsonb_build_object('size', 100));
  obj := public.qv_commit_upload(obj.id);
  IF obj.status <> 'committed' OR obj.stored_bytes <> 2 * part + 100 OR obj.committed_at IS NULL THEN RAISE EXCEPTION 'commit wrong %', obj; END IF;
  IF (public.qv_commit_upload(obj.id)).status <> 'committed' THEN RAISE EXCEPTION 'commit not idempotent'; END IF;
  usage := public.qv_cloud_usage();
  IF (usage->>'used_bytes')::BIGINT <> 2 * part + 100 OR (usage->>'files')::INT <> 1 THEN RAISE EXCEPTION 'usage after commit wrong %', usage; END IF;
  -- No more parts can be written once committed.
  PERFORM qvtest.expect_error(format('INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES (%L, %L, %L, %L)',
    'quantum-vault', a || '/' || obj.id || '/00000', a, '{"size":1}'), 'row-level security');
  RAISE NOTICE 'ok: commit, measured usage, no writes after commit';

  -- Another account sees nothing of A and cannot write into A's space.
  PERFORM qvtest.act_as(b);
  SELECT count(*) INTO n FROM public.qv_cloud_objects;
  IF n <> 0 THEN RAISE EXCEPTION 'B can see A''s objects'; END IF;
  SELECT count(*) INTO n FROM storage.objects WHERE bucket_id = 'quantum-vault';
  IF n <> 0 THEN RAISE EXCEPTION 'B can see A''s parts'; END IF;
  SELECT count(*) INTO n FROM public.qv_cloud_audit;
  IF n <> 0 THEN RAISE EXCEPTION 'B can see A''s audit'; END IF;
  PERFORM qvtest.expect_error(format('INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES (%L, %L, %L, %L)',
    'quantum-vault', a || '/' || obj.id || '/00000', b, '{"size":1}'), 'row-level security');
  PERFORM qvtest.expect_error(format('SELECT public.qv_commit_upload(%L)', obj.id), 'QV_OBJECT_NOT_FOUND');
  PERFORM qvtest.expect_error(format('SELECT public.qv_begin_delete(%L)', obj.id), 'QV_OBJECT_NOT_FOUND');
  -- The internal helpers take any user id: nobody may call them directly.
  PERFORM qvtest.expect_error(format('SELECT public.qv_cloud_used_bytes(%L)', a), 'permission denied');
  PERFORM qvtest.expect_error(format('SELECT public.qv_cloud_quota_bytes(%L)', a), 'permission denied');
  DELETE FROM storage.objects WHERE bucket_id = 'quantum-vault';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'B deleted A''s parts'; END IF;
  RAISE NOTICE 'ok: tenant isolation (rows, parts, audit, RPCs)';

  -- Unauthenticated callers get nothing.
  PERFORM qvtest.act_as_admin();
  PERFORM set_config('role', 'anon', true);
  PERFORM qvtest.expect_error('SELECT public.qv_cloud_usage()', 'permission denied');
  PERFORM qvtest.expect_error(format('SELECT public.qv_begin_upload(%L, NULL, 10, %L, %L)', 'recovery_index', qvtest.hashes(1), repeat('a', 64)), 'permission denied');
  PERFORM qvtest.expect_error(format('SELECT public.qv_cloud_used_bytes(%L)', a), 'permission denied');
  PERFORM qvtest.expect_error('SELECT count(*) FROM public.qv_cloud_objects', 'permission denied');
  PERFORM qvtest.expect_error('SELECT count(*) FROM public.qv_cloud_audit', 'permission denied');
  PERFORM qvtest.act_as_admin();
  RAISE NOTICE 'ok: anon cannot call the RPCs';

  -- Recovery index: needs entitlement, not charged, at most two live copies.
  PERFORM qvtest.act_as(a);
  again := public.qv_begin_upload('recovery_index', NULL, 1000, qvtest.hashes(1), repeat('1', 64));
  again := public.qv_begin_upload('recovery_index', NULL, 1000, qvtest.hashes(1), repeat('2', 64));
  PERFORM qvtest.expect_error(format('SELECT public.qv_begin_upload(%L, NULL, 1000, %L, %L)', 'recovery_index', qvtest.hashes(1), repeat('3', 64)), 'QV_INDEX_BUSY');
  PERFORM qvtest.expect_error(format('SELECT public.qv_begin_upload(%L, NULL, %s, %L, %L)', 'recovery_index', 67108865, qvtest.hashes(9), repeat('4', 64)), 'QV_INDEX_TOO_LARGE');
  IF (public.qv_cloud_usage()->>'used_bytes')::BIGINT <> 2 * part + 100 THEN RAISE EXCEPTION 'index was charged to the quota'; END IF;
  RAISE NOTICE 'ok: recovery index rules';

  -- Delete: space stays counted until the parts are gone.
  obj := public.qv_begin_delete(obj.id);
  IF obj.status <> 'deleting' THEN RAISE EXCEPTION 'begin_delete wrong'; END IF;
  ok := public.qv_finish_delete(obj.id);
  IF ok THEN RAISE EXCEPTION 'finish_delete succeeded with parts left'; END IF;
  DELETE FROM storage.objects WHERE bucket_id = 'quantum-vault' AND name LIKE a || '/' || obj.id || '/%';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 3 THEN RAISE EXCEPTION 'owner could not delete own parts (%)', n; END IF;
  ok := public.qv_finish_delete(obj.id);
  IF NOT ok THEN RAISE EXCEPTION 'finish_delete failed after parts were removed'; END IF;
  IF public.qv_finish_delete(obj.id) IS NOT TRUE THEN RAISE EXCEPTION 'finish_delete not idempotent'; END IF;
  SELECT count(*) INTO n FROM public.qv_cloud_objects WHERE id = obj.id;
  IF n <> 0 THEN RAISE EXCEPTION 'row survived delete'; END IF;
  IF (public.qv_cloud_usage()->>'used_bytes')::BIGINT <> 0 THEN RAISE EXCEPTION 'usage not released'; END IF;
  SELECT count(*) INTO n FROM public.qv_cloud_audit WHERE object_id = obj.id;
  IF n <> 4 THEN RAISE EXCEPTION 'expected 4 audit events for the object, got %', n; END IF;
  RAISE NOTICE 'ok: delete lifecycle and audit trail';

  -- A lapsed subscription keeps read access to existing backups.
  PERFORM qvtest.act_as_admin();
  INSERT INTO public.qv_cloud_objects (owner_user_id, kind, entry_id, container_bytes, part_size, part_count, part_sha3, container_sha3, status)
  VALUES (d, 'file', gen_random_uuid(), 10, part, 1, qvtest.hashes(1), repeat('9', 64), 'committed');
  INSERT INTO storage.objects (bucket_id, name, owner, metadata)
  SELECT 'quantum-vault', d || '/' || id || '/00000', d, '{"size":10}' FROM public.qv_cloud_objects WHERE owner_user_id = d;
  PERFORM qvtest.act_as(d);
  SELECT count(*) INTO n FROM public.qv_cloud_objects;
  IF n <> 1 THEN RAISE EXCEPTION 'expired account cannot see its backup'; END IF;
  SELECT count(*) INTO n FROM storage.objects WHERE bucket_id = 'quantum-vault';
  IF n <> 1 THEN RAISE EXCEPTION 'expired account cannot read its parts'; END IF;
  RAISE NOTICE 'ok: expired subscription keeps existing backups readable';

  PERFORM qvtest.act_as_admin();
  -- Bucket is private and capped at one part.
  IF NOT EXISTS (SELECT 1 FROM storage.buckets WHERE id = 'quantum-vault' AND public = false AND file_size_limit = part) THEN
    RAISE EXCEPTION 'bucket misconfigured';
  END IF;
  RAISE NOTICE 'ALL 048 CHECKS PASSED';
END $$;
