-- Data API grants — restore table access on Supabase projects created after
-- 2026-05-30.
--
-- Why this exists:
--   Supabase stopped granting anon / authenticated / service_role on tables
--   created in `public` ("Breaking Change: Tables not exposed to Data and
--   GraphQL API automatically", supabase discussion #45329). Every migration in
--   this repository was written for the old default, so on a new project the
--   tables exist but every Data API call is refused before RLS is evaluated:
--
--       42501  permission denied for table billing_subscriptions
--
--   The service-role key is refused too, so the API server, every dashboard,
--   and the subscription gate fail together,
--   and users land on "no subscription" no matter what billing says.
--
-- What it grants (idempotent — re-run after applying any new migration):
--   service_role          select/insert/update/delete on every table, select on
--                         every view. The API server's key; it bypasses RLS.
--   authenticated, anon   the same, but ONLY on tables with row level security
--                         enabled. A table without RLS is readable and writable
--                         by anyone holding the public anon key, so it stays
--                         backend-only and any existing client grant on it is
--                         revoked. Views run with their owner's rights (which
--                         bypass RLS) unless declared security_invoker, so they
--                         follow the same rule; materialized views never qualify.
--   sequences             usage/select for all three roles (inserts need them).
--   future objects        service_role only by default. Client roles are added
--                         by re-running this script once the new table has RLS.
--
-- Run in the Supabase SQL Editor. The final SELECT lists what each role can
-- read, backend-only objects first.

GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

DO $$
DECLARE
  obj record;
  client_safe boolean;
BEGIN
  FOR obj IN
    SELECT
      c.relname,
      c.relkind,
      c.relrowsecurity,
      EXISTS (
        SELECT 1 FROM unnest(coalesce(c.reloptions, '{}')) AS opt
        WHERE opt ~* '^security_invoker=(true|on|yes|1)$'
      ) AS security_invoker
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p', 'v', 'm')
      -- Objects an extension installed into public (e.g. spatial_ref_sys) keep
      -- the grants their extension manages.
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend d
        WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'
      )
  LOOP
    BEGIN
      IF obj.relkind IN ('r', 'p') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO service_role', obj.relname);
        client_safe := obj.relrowsecurity;
        IF client_safe THEN
          EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO anon, authenticated', obj.relname);
        END IF;
      ELSE
        EXECUTE format('GRANT SELECT ON TABLE public.%I TO service_role', obj.relname);
        client_safe := obj.relkind = 'v' AND obj.security_invoker;
        IF client_safe THEN
          EXECUTE format('GRANT SELECT ON TABLE public.%I TO anon, authenticated', obj.relname);
        END IF;
      END IF;

      IF NOT client_safe THEN
        EXECUTE format('REVOKE ALL ON TABLE public.%I FROM anon, authenticated', obj.relname);
      END IF;
    EXCEPTION WHEN insufficient_privilege THEN
      -- Not owned by the role running this script; the final SELECT shows the
      -- object's real privileges, so nothing is hidden by continuing.
      RAISE NOTICE 'skipped public.% (%)', obj.relname, SQLERRM;
    END;
  END LOOP;
END $$;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO anon, authenticated, service_role;

SELECT
  c.relname AS object,
  CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view' ELSE 'table' END AS kind,
  c.relrowsecurity AS rls_enabled,
  has_table_privilege('service_role', c.oid, 'SELECT') AS service_role_can_read,
  has_table_privilege('authenticated', c.oid, 'SELECT') AS authenticated_can_read,
  has_table_privilege('anon', c.oid, 'SELECT') AS anon_can_read
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'v', 'm')
ORDER BY authenticated_can_read, c.relname;
