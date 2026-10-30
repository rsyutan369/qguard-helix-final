-- ============================================================
-- Agent request signing — key binding (AGENT_SECURITY.md, "Request signing")
--
-- Each deployed agent signs every request with keys generated on its own
-- host (Ed25519, plus ML-DSA-65 where the runtime supports it). The control
-- plane pins the PUBLIC keys here on the agent's first signed request; from
-- then on a request signed by any other key, or missing a bound algorithm,
-- is refused. No private key is ever stored by the platform.
--
-- Idempotent: safe to run more than once.
-- ============================================================

ALTER TABLE public.scanner_agents
  ADD COLUMN IF NOT EXISTS signing_public_keys JSONB,
  ADD COLUMN IF NOT EXISTS signing_key_bound_at TIMESTAMP WITH TIME ZONE,
  -- Compare-and-set counter: binding, extending and resetting all require the
  -- version they read, so concurrent requests cannot both bind and a reset
  -- cannot be silently undone.
  ADD COLUMN IF NOT EXISTS signing_key_version INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN public.scanner_agents.signing_public_keys IS
  'Bound request-signing public keys: {"ed25519": base64 SPKI DER, "ml-dsa-65": base64 SPKI DER}. Written only by the control plane.';

-- The owner RLS policy allows a tenant session to UPDATE its own agent rows
-- through the Data API. The binding must change only through the audited
-- control-plane paths (first signed request, operator reset), never from a
-- browser session — a hijacked session must not be able to pin its own key.
CREATE OR REPLACE FUNCTION public.scanner_agents_guard_signing_keys()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF current_user IN ('authenticated', 'anon') THEN
    IF TG_OP = 'INSERT' THEN
      IF NEW.signing_public_keys IS NOT NULL OR NEW.signing_key_bound_at IS NOT NULL THEN
        RAISE EXCEPTION 'scanner_agents signing keys are managed by the control plane' USING ERRCODE = '42501';
      END IF;
    ELSIF NEW.signing_public_keys IS DISTINCT FROM OLD.signing_public_keys
       OR NEW.signing_key_bound_at IS DISTINCT FROM OLD.signing_key_bound_at
       OR NEW.signing_key_version IS DISTINCT FROM OLD.signing_key_version THEN
      RAISE EXCEPTION 'scanner_agents signing keys are managed by the control plane' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS scanner_agents_guard_signing_keys ON public.scanner_agents;
CREATE TRIGGER scanner_agents_guard_signing_keys
  BEFORE INSERT OR UPDATE ON public.scanner_agents
  FOR EACH ROW EXECUTE FUNCTION public.scanner_agents_guard_signing_keys();

-- PostgREST caches the schema; make the new columns visible immediately.
NOTIFY pgrst, 'reload schema';
