-- Realtime publication completeness for live key + membership telemetry.
-- Run after 024_settings_profile_realtime_and_email_sync.sql.
--
-- `src/lib/live-sse.ts` subscribes to these tables, but they were never added to
-- the `supabase_realtime` publication, so those subscriptions silently received
-- no events. That broke real-time updates for:
--   * Key Management — signed/one-time prekey inventory changes (rotation,
--     consumption) did not stream to other sessions/devices.
--   * Quantum Security — the quantum-safe score depends on the prekey inventory.
--   * Secure Chat — conversation membership changes did not stream.
-- Adding them to the publication makes the SSE genuinely real-time end to end.
-- Idempotent and privilege-safe: re-running (or running where a table is already
-- published) is a no-op.

DO $$
DECLARE
  tbl TEXT;
  tables TEXT[] := ARRAY[
    'messaging_signed_prekeys',
    'messaging_one_time_prekeys',
    'messaging_conversation_members'
  ];
BEGIN
  FOREACH tbl IN ARRAY tables LOOP
    BEGIN
      EXECUTE FORMAT('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', tbl);
    EXCEPTION
      WHEN duplicate_object THEN NULL;     -- already in the publication
      WHEN undefined_object THEN NULL;     -- publication not present in this env
      WHEN undefined_table THEN NULL;      -- table not present in this env
      WHEN insufficient_privilege THEN NULL;
    END;
  END LOOP;
END $$;

NOTIFY pgrst, 'reload schema';
