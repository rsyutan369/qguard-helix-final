-- 038_social_recovery.sql
--
-- Roadmap 5.1: recover the vault recovery key with help from k of n verified
-- contacts plus a PIN only the owner knows
-- (docs/superpowers/specs/2026-10-19-recovery-design.md §3).
--
-- What the relay holds, and why none of it opens anything:
--   * messaging_social_recovery — the owner's record: the recovery key wrapped
--     under HKDF(S || Argon2id(PIN)), the threshold and the guardian list.
--     S exists only as Shamir shares; the PIN only in the owner's head.
--   * messaging_recovery_shares — each share sealed (hybrid X25519 +
--     ML-KEM-1024) to ONE guardian device and signed by the owner's device.
--   * messaging_recovery_requests — a new device's public request key.
--   * messaging_recovery_releases — a guardian's share re-sealed to that key.
--
-- Access: owners manage their own rows; a guardian sees only shares sealed to
-- them and OPEN requests of people who named them; only the owner reads the
-- releases. No table is readable by anyone else.

CREATE TABLE IF NOT EXISTS public.messaging_social_recovery (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  setup_id TEXT NOT NULL CHECK (setup_id ~ '^[0-9a-f]{32}$'),
  record JSONB NOT NULL CHECK (octet_length(record::text) < 65536),
  guardian_user_ids UUID[] NOT NULL CHECK (cardinality(guardian_user_ids) BETWEEN 2 AND 16),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.messaging_recovery_shares (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  setup_id TEXT NOT NULL,
  owner_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  guardian_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  guardian_device_id TEXT NOT NULL,
  offer JSONB NOT NULL CHECK (octet_length(offer::text) < 65536),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (owner_user_id <> guardian_user_id),
  UNIQUE (setup_id, guardian_device_id)
);
CREATE INDEX IF NOT EXISTS idx_recovery_shares_guardian ON public.messaging_recovery_shares(guardian_user_id);

CREATE TABLE IF NOT EXISTS public.messaging_recovery_requests (
  request_id TEXT PRIMARY KEY CHECK (request_id ~ '^[0-9a-f]{32}$'),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  request JSONB NOT NULL CHECK (octet_length(request::text) < 65536),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'completed', 'cancelled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days')
);
CREATE INDEX IF NOT EXISTS idx_recovery_requests_user ON public.messaging_recovery_requests(user_id);

CREATE TABLE IF NOT EXISTS public.messaging_recovery_releases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id TEXT NOT NULL REFERENCES public.messaging_recovery_requests(request_id) ON DELETE CASCADE,
  owner_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  guardian_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  release JSONB NOT NULL CHECK (octet_length(release::text) < 65536),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (request_id, guardian_user_id)
);

-- Whether `p_guardian` is one of `p_owner`'s recovery helpers. SECURITY DEFINER
-- so other tables' policies can ask without reading the owner's row.
CREATE OR REPLACE FUNCTION public.is_recovery_guardian(p_owner UUID, p_guardian UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.messaging_social_recovery s
    WHERE s.user_id = p_owner AND p_guardian = ANY (s.guardian_user_ids)
  );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.is_recovery_guardian(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_recovery_guardian(UUID, UUID) TO authenticated;

ALTER TABLE public.messaging_social_recovery ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_recovery_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_recovery_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messaging_recovery_releases ENABLE ROW LEVEL SECURITY;

-- Owner record: the owner only.
DROP POLICY IF EXISTS social_recovery_owner ON public.messaging_social_recovery;
CREATE POLICY social_recovery_owner ON public.messaging_social_recovery
  FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Shares: the owner writes and withdraws them; the guardian reads and
-- deletes the ones sealed to them (after storing them on their device).
DROP POLICY IF EXISTS recovery_shares_owner_insert ON public.messaging_recovery_shares;
CREATE POLICY recovery_shares_owner_insert ON public.messaging_recovery_shares
  FOR INSERT WITH CHECK (owner_user_id = auth.uid());
DROP POLICY IF EXISTS recovery_shares_read ON public.messaging_recovery_shares;
CREATE POLICY recovery_shares_read ON public.messaging_recovery_shares
  FOR SELECT USING (owner_user_id = auth.uid() OR guardian_user_id = auth.uid());
DROP POLICY IF EXISTS recovery_shares_delete ON public.messaging_recovery_shares;
CREATE POLICY recovery_shares_delete ON public.messaging_recovery_shares
  FOR DELETE USING (owner_user_id = auth.uid() OR guardian_user_id = auth.uid());

-- Requests: the owner makes and closes them; a guardian of that owner sees
-- the OPEN, unexpired ones.
DROP POLICY IF EXISTS recovery_requests_owner ON public.messaging_recovery_requests;
CREATE POLICY recovery_requests_owner ON public.messaging_recovery_requests
  FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS recovery_requests_guardian_read ON public.messaging_recovery_requests;
CREATE POLICY recovery_requests_guardian_read ON public.messaging_recovery_requests
  FOR SELECT USING (
    status = 'open' AND expires_at > now() AND public.is_recovery_guardian(user_id, auth.uid())
  );

-- Releases: a guardian of the owner answers an open request of that owner;
-- only the owner (and the guardian, for their own row) reads them.
DROP POLICY IF EXISTS recovery_releases_guardian_insert ON public.messaging_recovery_releases;
CREATE POLICY recovery_releases_guardian_insert ON public.messaging_recovery_releases
  FOR INSERT WITH CHECK (
    guardian_user_id = auth.uid()
    AND public.is_recovery_guardian(owner_user_id, auth.uid())
    AND EXISTS (
      SELECT 1 FROM public.messaging_recovery_requests r
      WHERE r.request_id = messaging_recovery_releases.request_id
        AND r.user_id = messaging_recovery_releases.owner_user_id
        AND r.status = 'open'
        AND r.expires_at > now()
    )
  );
DROP POLICY IF EXISTS recovery_releases_read ON public.messaging_recovery_releases;
CREATE POLICY recovery_releases_read ON public.messaging_recovery_releases
  FOR SELECT USING (owner_user_id = auth.uid() OR guardian_user_id = auth.uid());

GRANT SELECT, INSERT, UPDATE, DELETE ON public.messaging_social_recovery TO authenticated;
GRANT SELECT, INSERT, DELETE ON public.messaging_recovery_shares TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.messaging_recovery_requests TO authenticated;
GRANT SELECT, INSERT ON public.messaging_recovery_releases TO authenticated;
