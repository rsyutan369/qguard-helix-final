-- Checks for migration 049 (library + sharing), as real `authenticated`
-- sessions against RLS, with Supabase's default grants (see 048_bootstrap.sql).
-- Order: 048_bootstrap.sql, migrations 048 and 049, 048 test (creates the
-- qvtest helpers), then this file. Ends with 'ALL 049 CHECKS PASSED'.

\set ON_ERROR_STOP on

DO $$
DECLARE
  a CONSTANT UUID := 'a0000000-0000-4000-8000-000000000001';  -- Pro, the owner
  b CONSTANT UUID := 'b0000000-0000-4000-8000-000000000002';  -- Pro, recipient
  c CONSTANT UUID := 'c0000000-0000-4000-8000-000000000003';  -- blocked a
  s CONSTANT UUID := 'd0000000-0000-4000-8000-000000000004';  -- Starter (no cloud)
  a_laptop UUID := gen_random_uuid();
  a_phone UUID := gen_random_uuid();
  b_phone UUID := gen_random_uuid();
  c_phone UUID := gen_random_uuid();
  part CONSTANT BIGINT := 8388608;
  lib1 public.qv_cloud_objects;
  lib2 public.qv_cloud_objects;
  file1 public.qv_cloud_objects;
  file2 public.qv_cloud_objects;
  result JSONB;
  share UUID;
  share2 UUID;
  n INTEGER;
BEGIN
  PERFORM qvtest.act_as_admin();
  INSERT INTO auth.users VALUES (a), (b), (c), (s);
  INSERT INTO public.profiles VALUES (a), (b), (c), (s);
  INSERT INTO public.billing_subscriptions VALUES
    (a, 'Pro', 'active', NULL), (b, 'Pro', 'active', NULL), (c, 'Pro', 'active', NULL), (s, 'Starter', 'active', NULL);
  INSERT INTO public.messaging_devices (id, user_id) VALUES (a_laptop, a), (a_phone, a), (b_phone, b), (c_phone, c);
  INSERT INTO public.messaging_contacts VALUES (c, a, 'blocked');

  -- ---- library ----------------------------------------------------------
  PERFORM qvtest.act_as(a);
  lib1 := public.qv_begin_upload('library_index', NULL, 100, qvtest.hashes(1), repeat('1', 64), 'laptop');
  -- Publishing needs a committed document.
  PERFORM qvtest.expect_error(format('SELECT public.qv_publish_library(%L, 0, 1)', lib1.id), 'QV_OBJECT_NOT_FOUND');
  INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES ('quantum-vault', a || '/' || lib1.id || '/00000', a, '{"size":100}');
  lib1 := public.qv_commit_upload(lib1.id);
  result := public.qv_publish_library(lib1.id, 0, 1, 'laptop');
  IF (result->>'revision')::INT <> 1 OR result->>'previous_object_id' IS NOT NULL THEN RAISE EXCEPTION 'first publish wrong %', result; END IF;

  -- A second device that has not merged revision 1 cannot overwrite it.
  lib2 := public.qv_begin_upload('library_index', NULL, 100, qvtest.hashes(1), repeat('2', 64), 'phone');
  INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES ('quantum-vault', a || '/' || lib2.id || '/00000', a, '{"size":100}');
  lib2 := public.qv_commit_upload(lib2.id);
  PERFORM qvtest.expect_error(format('SELECT public.qv_publish_library(%L, 0, 1)', lib2.id), 'QV_REVISION_CONFLICT');
  result := public.qv_publish_library(lib2.id, 1, 1, 'phone');
  IF (result->>'revision')::INT <> 2 OR (result->>'previous_object_id')::UUID <> lib1.id THEN RAISE EXCEPTION 'second publish wrong %', result; END IF;
  -- An older epoch cannot replace a newer one.
  result := public.qv_publish_library(lib2.id, 2, 3, 'laptop');
  PERFORM qvtest.expect_error(format('SELECT public.qv_publish_library(%L, 3, 2)', lib2.id), 'QV_STALE_EPOCH');
  -- Library copies are bounded and not charged to the quota.
  PERFORM public.qv_begin_upload('library_index', NULL, 100, qvtest.hashes(1), repeat('3', 64));
  PERFORM qvtest.expect_error(format('SELECT public.qv_begin_upload(%L, NULL, 100, %L, %L)', 'library_index', qvtest.hashes(1), repeat('4', 64)), 'QV_INDEX_BUSY');
  IF (public.qv_cloud_usage()->>'used_bytes')::BIGINT <> 0 THEN RAISE EXCEPTION 'library charged to quota'; END IF;
  RAISE NOTICE 'ok: library publish is compare-and-swap, epochs never go back, copies bounded and uncharged';

  -- Recovery copy: first claims, later only newer.
  result := public.qv_library_set_recovery(1, '{"v":1}');
  PERFORM qvtest.expect_error('SELECT public.qv_library_set_recovery(1, ''{"v":1}'')', 'QV_RECOVERY_EXISTS');
  result := public.qv_library_set_recovery(2, '{"v":1}');
  PERFORM qvtest.expect_error('SELECT public.qv_library_set_recovery(1, ''{"v":1}'')', 'QV_RECOVERY_EXISTS');
  RAISE NOTICE 'ok: the recovery copy elects the first library and only moves forward';

  -- Key wraps only between the caller's own devices.
  INSERT INTO public.qv_library_key_wraps (user_id, from_device_id, to_device_id, epoch, wrap) VALUES (a, a_laptop, a_phone, 1, '{}');
  PERFORM qvtest.expect_error(format('INSERT INTO public.qv_library_key_wraps (user_id, from_device_id, to_device_id, epoch, wrap) VALUES (%L, %L, %L, 2, %L)', a, a_laptop, b_phone, '{}'), 'row-level security');
  PERFORM qvtest.expect_error(format('INSERT INTO public.qv_library_key_wraps (user_id, from_device_id, to_device_id, epoch, wrap) VALUES (%L, %L, %L, 3, %L)', b, a_laptop, a_phone, '{}'), 'row-level security');

  PERFORM qvtest.act_as(b);
  SELECT count(*) INTO n FROM public.qv_library_state; IF n <> 0 THEN RAISE EXCEPTION 'b sees a''s library state'; END IF;
  SELECT count(*) INTO n FROM public.qv_library_recovery; IF n <> 0 THEN RAISE EXCEPTION 'b sees a''s recovery copy'; END IF;
  SELECT count(*) INTO n FROM public.qv_library_key_wraps; IF n <> 0 THEN RAISE EXCEPTION 'b sees a''s key wraps'; END IF;
  PERFORM qvtest.expect_error(format('SELECT public.qv_publish_library(%L, 3, 3)', lib2.id), 'QV_OBJECT_NOT_FOUND');
  PERFORM qvtest.expect_error('TRUNCATE public.qv_library_state', 'permission denied');
  PERFORM qvtest.expect_error('TRUNCATE public.qv_library_key_wraps', 'permission denied');
  RAISE NOTICE 'ok: library state, recovery copy and key wraps are the owner''s alone';

  -- ---- sharing ------------------------------------------------------------
  PERFORM qvtest.act_as(a);
  file1 := public.qv_begin_upload('file', gen_random_uuid(), 100, qvtest.hashes(1), repeat('5', 64));
  INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES ('quantum-vault', a || '/' || file1.id || '/00000', a, '{"size":100}');
  file1 := public.qv_commit_upload(file1.id);
  file2 := public.qv_begin_upload('file', gen_random_uuid(), 100, qvtest.hashes(1), repeat('6', 64));
  INSERT INTO storage.objects (bucket_id, name, owner, metadata) VALUES ('quantum-vault', a || '/' || file2.id || '/00000', a, '{"size":100}');
  file2 := public.qv_commit_upload(file2.id);

  result := public.qv_share_create(file1.id, ARRAY[b, c, a, b], 'download', NULL);
  share := (result->>'share_id')::UUID;
  IF result->'recipients' <> to_jsonb(ARRAY[b]) THEN RAISE EXCEPTION 'recipients should be [b] (c blocked a, a is self, b once): %', result; END IF;
  PERFORM qvtest.expect_error(format('SELECT public.qv_share_create(%L, ARRAY[%L]::uuid[], %L)', lib2.id, b, 'view'), 'QV_OBJECT_NOT_FOUND');
  PERFORM qvtest.expect_error(format('SELECT public.qv_share_create(%L, ARRAY[%L]::uuid[], %L, now() - interval ''1 day'')', file1.id, b, 'view'), 'QV_INVALID_EXPIRY');
  PERFORM qvtest.expect_error(format('SELECT public.qv_share_create(%L, ARRAY[%L]::uuid[], %L)', file1.id, b, 'edit'), 'QV_INVALID_PERMISSION');

  -- Envelopes: only to a device of a recipient, from one of a's devices.
  INSERT INTO public.qv_share_envelopes (share_id, recipient_user_id, recipient_device_id, sender_device_id, envelope) VALUES (share, b, b_phone, a_laptop, '{}');
  PERFORM qvtest.expect_error(format('INSERT INTO public.qv_share_envelopes (share_id, recipient_user_id, recipient_device_id, sender_device_id, envelope) VALUES (%L, %L, %L, %L, %L)', share, c, c_phone, a_laptop, '{}'), 'row-level security');
  PERFORM qvtest.expect_error(format('INSERT INTO public.qv_share_envelopes (share_id, recipient_user_id, recipient_device_id, sender_device_id, envelope) VALUES (%L, %L, %L, %L, %L)', share, b, c_phone, a_phone, '{}'), 'row-level security');
  PERFORM qvtest.expect_error(format('INSERT INTO public.qv_share_envelopes (share_id, recipient_user_id, recipient_device_id, sender_device_id, envelope) VALUES (%L, %L, %L, %L, %L)', share, b, b_phone, b_phone, '{}'), 'row-level security');
  RAISE NOTICE 'ok: shares skip blocked people and self; envelopes only to recipients'' devices from the owner''s';

  -- Pending: b sees the invitation and envelope, not the file.
  PERFORM qvtest.act_as(b);
  SELECT count(*) INTO n FROM public.qv_shares WHERE id = share; IF n <> 1 THEN RAISE EXCEPTION 'b cannot see the invitation'; END IF;
  SELECT count(*) INTO n FROM public.qv_share_envelopes; IF n <> 1 THEN RAISE EXCEPTION 'b cannot see its envelope'; END IF;
  SELECT count(*) INTO n FROM public.qv_cloud_objects; IF n <> 0 THEN RAISE EXCEPTION 'pending b sees the object row'; END IF;
  SELECT count(*) INTO n FROM storage.objects WHERE bucket_id = 'quantum-vault'; IF n <> 0 THEN RAISE EXCEPTION 'pending b sees parts'; END IF;
  PERFORM qvtest.expect_error(format('SELECT public.qv_share_record(%L, %L)', share, 'opened'), 'QV_SHARE_NOT_AVAILABLE');

  -- Accepted: exactly the shared object, nothing else of a's.
  PERFORM public.qv_share_respond(share, true);
  SELECT count(*) INTO n FROM public.qv_cloud_objects; IF n <> 1 THEN RAISE EXCEPTION 'accepted b should see exactly the shared row, sees %', n; END IF;
  SELECT count(*) INTO n FROM storage.objects WHERE bucket_id = 'quantum-vault'; IF n <> 1 THEN RAISE EXCEPTION 'accepted b should see exactly the shared part, sees %', n; END IF;
  SELECT count(*) INTO n FROM storage.objects WHERE bucket_id = 'quantum-vault' AND name LIKE '%' || file2.id || '%';
  IF n <> 0 THEN RAISE EXCEPTION 'b sees an unshared object'; END IF;
  PERFORM public.qv_share_record(share, 'opened');
  -- b cannot manage a's share, write envelopes, or touch the tables.
  PERFORM qvtest.expect_error(format('SELECT public.qv_share_revoke(%L)', share), 'QV_SHARE_NOT_FOUND');
  PERFORM qvtest.expect_error(format('INSERT INTO public.qv_share_envelopes (share_id, recipient_user_id, recipient_device_id, sender_device_id, envelope) VALUES (%L, %L, %L, %L, %L)', share, b, b_phone, b_phone, '{}'), 'row-level security');
  PERFORM qvtest.expect_error(format('UPDATE public.qv_shares SET permission = %L', 'download'), 'permission denied');
  PERFORM qvtest.expect_error(format('UPDATE public.qv_share_recipients SET status = %L', 'accepted'), 'permission denied');
  PERFORM qvtest.expect_error('DELETE FROM public.qv_share_events', 'permission denied');
  PERFORM qvtest.expect_error('TRUNCATE public.qv_shares CASCADE', 'permission denied');
  RAISE NOTICE 'ok: pending sees the invitation only; accepted sees exactly the shared object';

  -- The owner sees the access history.
  PERFORM qvtest.act_as(a);
  SELECT count(*) INTO n FROM public.qv_share_events WHERE share_id = share;
  IF n <> 3 THEN RAISE EXCEPTION 'expected created/accepted/opened, got % events', n; END IF;

  -- Expiry ends access without anyone acting.
  PERFORM qvtest.act_as_admin();
  UPDATE public.qv_shares SET expires_at = now() - interval '1 minute' WHERE id = share;
  PERFORM qvtest.act_as(b);
  SELECT count(*) INTO n FROM storage.objects WHERE bucket_id = 'quantum-vault'; IF n <> 0 THEN RAISE EXCEPTION 'expired share still downloadable'; END IF;
  SELECT count(*) INTO n FROM public.qv_share_envelopes; IF n <> 0 THEN RAISE EXCEPTION 'expired share envelope still visible'; END IF;
  PERFORM qvtest.act_as_admin();
  UPDATE public.qv_shares SET expires_at = NULL WHERE id = share;

  -- Revocation ends access and removes the envelope from the relay.
  PERFORM qvtest.act_as(a);
  PERFORM public.qv_share_revoke(share, b);
  PERFORM qvtest.act_as(b);
  SELECT count(*) INTO n FROM storage.objects WHERE bucket_id = 'quantum-vault'; IF n <> 0 THEN RAISE EXCEPTION 'revoked recipient still downloads'; END IF;
  PERFORM qvtest.act_as_admin();
  SELECT count(*) INTO n FROM public.qv_share_envelopes WHERE share_id = share; IF n <> 0 THEN RAISE EXCEPTION 'revoked envelope kept'; END IF;
  RAISE NOTICE 'ok: expiry and revocation end access; envelopes leave the relay';

  -- Declining removes the envelope; nobody can share someone else's file.
  PERFORM qvtest.act_as(a);
  result := public.qv_share_create(file2.id, ARRAY[b], 'view', now() + interval '7 days');
  share2 := (result->>'share_id')::UUID;
  INSERT INTO public.qv_share_envelopes (share_id, recipient_user_id, recipient_device_id, sender_device_id, envelope) VALUES (share2, b, b_phone, a_laptop, '{}');
  PERFORM qvtest.act_as(b);
  PERFORM public.qv_share_respond(share2, false);
  SELECT count(*) INTO n FROM public.qv_share_envelopes; IF n <> 0 THEN RAISE EXCEPTION 'declined envelope kept'; END IF;
  PERFORM qvtest.act_as(s);
  PERFORM qvtest.expect_error(format('SELECT public.qv_share_create(%L, ARRAY[%L]::uuid[], %L)', file2.id, b, 'view'), 'QV_OBJECT_NOT_FOUND');

  -- Deleting the object deletes its shares.
  PERFORM qvtest.act_as(a);
  PERFORM public.qv_begin_delete(file2.id);
  DELETE FROM storage.objects WHERE bucket_id = 'quantum-vault' AND name LIKE a || '/' || file2.id || '/%';
  PERFORM public.qv_finish_delete(file2.id);
  SELECT count(*) INTO n FROM public.qv_shares WHERE id = share2; IF n <> 0 THEN RAISE EXCEPTION 'share survived its object'; END IF;
  RAISE NOTICE 'ok: declining drops the envelope; deleting the file ends its shares';

  -- anon: nothing.
  PERFORM qvtest.act_as_admin();
  PERFORM set_config('role', 'anon', true);
  PERFORM qvtest.expect_error(format('SELECT public.qv_share_create(%L, ARRAY[%L]::uuid[], %L)', file1.id, b, 'view'), 'permission denied');
  PERFORM qvtest.expect_error('SELECT count(*) FROM public.qv_shares', 'permission denied');
  PERFORM qvtest.expect_error('SELECT count(*) FROM public.qv_library_key_wraps', 'permission denied');
  PERFORM qvtest.expect_error(format('SELECT public.qv_publish_library(%L, 0, 1)', lib1.id), 'permission denied');
  PERFORM qvtest.act_as_admin();
  RAISE NOTICE 'ok: anon cannot reach library or sharing';

  RAISE NOTICE 'ALL 049 CHECKS PASSED';
END $$;
