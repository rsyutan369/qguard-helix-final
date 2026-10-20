-- 041: role-based operator access (roadmap 10.3).
--
-- Until now the app decided who sees backend/telemetry internals by comparing
-- the signed-in email with one address compiled into the client
-- (src/lib/admin.ts). That gated display only — every panel shows the
-- caller's own RLS-scoped rows — but it could not be changed without a new
-- release, and could not name more than one person.
--
-- Roles now live here. A user can read only their own row; there is no
-- INSERT/UPDATE/DELETE policy, so roles are granted only with the service role
-- (SQL editor / admin tooling), never through the app's API:
--
--   INSERT INTO public.messaging_app_roles (user_id, role, note)
--   SELECT id, 'operator', 'granted by <who>, <why>' FROM auth.users WHERE lower(email) = lower('<email>');
--
-- The 'operator' role still grants no data access — it only shows the internal
-- panels. Anything that must be privileged has to be enforced server-side.

CREATE TABLE IF NOT EXISTS public.messaging_app_roles (
  user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('operator')),
  note TEXT,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.messaging_app_roles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_app_roles_self_read ON public.messaging_app_roles;
CREATE POLICY messaging_app_roles_self_read ON public.messaging_app_roles
  FOR SELECT USING (user_id = auth.uid());

REVOKE ALL ON public.messaging_app_roles FROM anon;
REVOKE INSERT, UPDATE, DELETE ON public.messaging_app_roles FROM authenticated;
GRANT SELECT ON public.messaging_app_roles TO authenticated;

-- Carry over the one administrator the client used to hard-code, so applying
-- this migration together with the client change loses nobody's access.
INSERT INTO public.messaging_app_roles (user_id, role, note)
SELECT u.id, 'operator', 'carried over from the client-side ADMIN_EMAIL (migration 041)'
FROM auth.users u
JOIN public.profiles p ON p.id = u.id
WHERE lower(u.email) = lower('zachmatthew369@gmail.com')
ON CONFLICT (user_id) DO NOTHING;
