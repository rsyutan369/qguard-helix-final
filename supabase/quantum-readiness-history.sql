-- Quantum Readiness score history — the series behind every "Readiness vs Risk"
-- trend on the Quantum Readiness pages, the Remediation Engine and the reports.
--
-- Why this exists:
--   The trend used to be computed per scan session as
--   `100 - findings_count / total_assets * 100` — a findings-per-asset ratio
--   that is a DIFFERENT metric from the headline Quantum Readiness / Quantum
--   Risk scores it was drawn beside (the Executive dashboard had already
--   stopped using it for that reason). A trend is only honest when it is the
--   metric's own history, so the assessment engine now appends one row here
--   when the scored evidence changes (at most one row per tenant every ten
--   minutes, so an in-flight scan does not write a row per refresh), and the
--   trend reads these rows back.
--
-- Writer: src/api-server/quantum-readiness-history.ts (user-scoped client, RLS
-- enforced). Until this script is applied the engine detects the missing table,
-- publishes `scoreHistory.available = false`, and the pages say so instead of
-- drawing a borrowed series.
--
-- Run in the Supabase SQL editor once per environment, then re-run
-- supabase/data-api-grants.sql so the authenticated role can reach the table.

CREATE TABLE IF NOT EXISTS public.quantum_readiness_history (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Headline scores exactly as the engine published them (0-100).
  quantum_readiness SMALLINT NOT NULL CHECK (quantum_readiness BETWEEN 0 AND 100),
  quantum_risk      SMALLINT NOT NULL CHECK (quantum_risk BETWEEN 0 AND 100),
  hndl_risk         SMALLINT NOT NULL CHECK (hndl_risk BETWEEN 0 AND 100),
  pqc_adoption      SMALLINT NOT NULL CHECK (pqc_adoption BETWEEN 0 AND 100),
  -- Populations the scores were computed over, so a reader can tell a real
  -- improvement from a change in what was measured.
  assets_assessed       INTEGER NOT NULL DEFAULT 0 CHECK (assets_assessed >= 0),
  crypto_components     INTEGER NOT NULL DEFAULT 0 CHECK (crypto_components >= 0),
  vulnerable_components INTEGER NOT NULL DEFAULT 0 CHECK (vulnerable_components >= 0),
  critical_findings     INTEGER NOT NULL DEFAULT 0 CHECK (critical_findings >= 0),
  high_findings         INTEGER NOT NULL DEFAULT 0 CHECK (high_findings >= 0),
  -- sha1 of the scored inputs; consecutive identical fingerprints are not stored.
  fingerprint      TEXT NOT NULL CHECK (char_length(fingerprint) <= 64),
  engine_version   TEXT NOT NULL DEFAULT '1' CHECK (char_length(engine_version) <= 16)
);

CREATE INDEX IF NOT EXISTS idx_qrh_user_recorded
  ON public.quantum_readiness_history (user_id, recorded_at DESC);

ALTER TABLE public.quantum_readiness_history ENABLE ROW LEVEL SECURITY;

-- History is append-only for tenants: they may read and insert their own rows,
-- never rewrite or delete the record of what was measured.
DROP POLICY IF EXISTS qrh_select_own ON public.quantum_readiness_history;
CREATE POLICY qrh_select_own ON public.quantum_readiness_history
  FOR SELECT USING (user_id = auth.uid());

DROP POLICY IF EXISTS qrh_insert_own ON public.quantum_readiness_history;
CREATE POLICY qrh_insert_own ON public.quantum_readiness_history
  FOR INSERT WITH CHECK (user_id = auth.uid());

GRANT SELECT, INSERT ON public.quantum_readiness_history TO authenticated;
GRANT ALL ON public.quantum_readiness_history TO service_role;

-- Verify:
--   SELECT recorded_at, quantum_readiness, quantum_risk
--   FROM public.quantum_readiness_history
--   WHERE user_id = auth.uid() ORDER BY recorded_at DESC LIMIT 12;
