-- RPC privilege + row level security hardening for the platform schema.
-- Idempotent. Safe to run before or after data-api-grants.sql, and to re-run.
--
-- Why this exists:
--
-- 1. Cross-tenant reads through /rest/v1/rpc.
--    Five SECURITY DEFINER functions (dashboard-schema.sql and
--    profile-security-schema.sql) take a user id as an argument and never compare
--    it with auth.uid(). SECURITY DEFINER runs them with the owner's rights, so
--    RLS does not apply inside them, and Postgres grants EXECUTE on every new
--    function to PUBLIC. Anyone holding the public anon key could therefore call
--
--        POST /rest/v1/rpc/get_profile_security_snapshot  {"p_user_id": "<any user id>"}
--
--    and read another tenant's profile, preferences and security settings (or
--    dashboard summary, exposure map, security events, risk score). Nothing in
--    the application calls these functions, so they become service-role only.
--
-- 2. Tables without row level security.
--    schema.sql created eight tables without RLS; a table without RLS in an
--    exposed schema is one GRANT away from being readable and writable by
--    everyone. RLS is enabled on all eight.
--      - quantum_governance_* get the platform's owner-isolation policy. The
--        Crypto Agility API reads quantum_governance_exceptions with the user's
--        own token (createAuthClient), so RLS without a policy would make every
--        tenant's exception list silently empty.
--      - migrations, migration_logs, risk_scores, telemetry get no client policy:
--        only the service role, which bypasses RLS, reaches them. Only the retired
--        Next.js route handlers ever used them.
--
-- Run in the Supabase SQL Editor. The final SELECT lists every SECURITY DEFINER
-- function in public and which roles can execute it.

DO $$
DECLARE
  signature text;
  fn regprocedure;
  server_only_functions text[] := ARRAY[
    'public.get_profile_security_snapshot(uuid)',
    'public.get_dashboard_summary(uuid)',
    'public.get_exposure_map(uuid)',
    'public.get_recent_security_events(uuid, integer)',
    'public.calculate_quantum_risk_score(uuid)'
  ];
BEGIN
  FOREACH signature IN ARRAY server_only_functions LOOP
    fn := to_regprocedure(signature);
    IF fn IS NULL THEN
      RAISE NOTICE 'not present, skipped: %', signature;
      CONTINUE;
    END IF;
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated', fn);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', fn);
  END LOOP;
END $$;

DO $$
DECLARE
  tbl text;
  tables_without_rls text[] := ARRAY[
    'migrations',
    'migration_logs',
    'risk_scores',
    'telemetry',
    'quantum_governance_assets',
    'quantum_governance_controls',
    'quantum_governance_exceptions',
    'quantum_governance_pki_debt'
  ];
BEGIN
  FOREACH tbl IN ARRAY tables_without_rls LOOP
    IF to_regclass(format('public.%I', tbl)) IS NULL THEN
      RAISE NOTICE 'not present, skipped: public.%', tbl;
      CONTINUE;
    END IF;
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl);
    IF tbl LIKE 'quantum_governance_%' THEN
      EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', tbl || '_user_isolation', tbl);
      EXECUTE format(
        'CREATE POLICY %I ON public.%I FOR ALL TO authenticated '
        'USING (user_id = (SELECT auth.uid())) WITH CHECK (user_id = (SELECT auth.uid()))',
        tbl || '_user_isolation', tbl
      );
    END IF;
  END LOOP;
END $$;

SELECT
  p.oid::regprocedure AS security_definer_function,
  has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_can_execute,
  has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authenticated_can_execute,
  has_function_privilege('service_role', p.oid, 'EXECUTE') AS service_role_can_execute
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.prosecdef
  AND p.prorettype <> 'trigger'::regtype
ORDER BY anon_can_execute DESC, authenticated_can_execute DESC, 1;
