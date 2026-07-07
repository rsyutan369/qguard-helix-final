-- Quantum Readiness Assessment Engine™ — realtime publication registration.
--
-- The QR pages (useQuantumReadiness in src/app/dashboard/quantum-readiness/_shared.tsx)
-- subscribe to postgres_changes on every evidence table the aggregation router
-- (src/api-server/quantum-readiness.ts buildSnapshot) reads, so dashboards update
-- the moment new evidence lands. Supabase only delivers postgres_changes for
-- tables that are members of the `supabase_realtime` publication — this script
-- registers them idempotently (skips missing tables and tables already added).
--
-- Run in the Supabase SQL editor (or psql) once per environment.

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'assets',
    'asset_relationships',
    'pqc_scan_sessions',
    'pqc_scan_results',
    'crypto_inventory',
    'crypto_exposures',
    'certificates',
    'generated_keys',
    'runtime_crypto_events',
    'scanner_alerts',
    'scanner_evidence',
    'connector_accounts',
    'vault_files'
  ]
  LOOP
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = t)
       AND NOT EXISTS (
         SELECT 1 FROM pg_publication_tables
         WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = t
       ) THEN
      EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', t);
      RAISE NOTICE 'Added public.% to supabase_realtime', t;
    END IF;
  END LOOP;
END $$;

-- Verify:
--   SELECT tablename FROM pg_publication_tables
--   WHERE pubname = 'supabase_realtime' AND schemaname = 'public'
--   ORDER BY tablename;
