-- 027: Operator-managed STUN/TURN relay configuration for video calls.
--
-- The desktop client resolves ICE servers at call time from this single-row
-- table (see src/lib/call-ice.ts), so the operator can deploy or rotate their
-- own TURN relay WITHOUT shipping a new installer. If the row/table is missing
-- the client falls back to build-time env config and then the public Open
-- Relay, so this migration is required only to CUSTOMIZE relays.
--
-- Credentials here are readable by any AUTHENTICATED user (they need them to
-- place calls); rotate them by updating this row. Media through any relay is
-- end-to-end encrypted — a relay only ever forwards ciphertext.

CREATE TABLE IF NOT EXISTS public.messaging_call_relay (
  id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  stun_urls jsonb NOT NULL DEFAULT '["stun:stun.l.google.com:19302","stun:stun1.l.google.com:19302"]'::jsonb,
  turn_urls jsonb NOT NULL DEFAULT '[]'::jsonb,
  turn_username text NOT NULL DEFAULT '',
  turn_credential text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.messaging_call_relay ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_call_relay_read ON public.messaging_call_relay;
CREATE POLICY messaging_call_relay_read ON public.messaging_call_relay
  FOR SELECT TO authenticated USING (true);
-- No INSERT/UPDATE/DELETE policies: only the service role manages this row.

-- Seed with the public Open Relay so calls traverse strict NATs immediately;
-- replace with your own coturn/Twilio/Cloudflare relay for production scale.
INSERT INTO public.messaging_call_relay (id, turn_urls, turn_username, turn_credential)
VALUES (
  1,
  '["turn:openrelay.metered.ca:80","turn:openrelay.metered.ca:443","turns:openrelay.metered.ca:443?transport=tcp"]'::jsonb,
  'openrelayproject',
  'openrelayproject'
)
ON CONFLICT (id) DO NOTHING;
