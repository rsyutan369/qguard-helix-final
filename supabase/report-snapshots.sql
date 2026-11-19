BEGIN;

CREATE TABLE IF NOT EXISTS public.report_snapshots (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  organization_id uuid,
  report_family text NOT NULL CHECK (report_family IN ('readiness', 'asset')),
  created_at timestamptz NOT NULL DEFAULT now(),
  summary jsonb NOT NULL CHECK (jsonb_typeof(summary) = 'object'),
  model jsonb NOT NULL CHECK (jsonb_typeof(model) = 'object')
);

CREATE INDEX IF NOT EXISTS report_snapshots_owner_history_idx
  ON public.report_snapshots (user_id, report_family, created_at DESC, id DESC);

ALTER TABLE public.report_snapshots ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.report_snapshots FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT, INSERT ON TABLE public.report_snapshots TO service_role;

COMMENT ON TABLE public.report_snapshots IS
  'Append-only server captures. The API must authenticate callers and constrain all reads to the owner and authorized organization.';

COMMIT;
