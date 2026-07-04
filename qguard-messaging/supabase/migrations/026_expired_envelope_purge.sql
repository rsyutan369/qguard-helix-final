-- QGuard Secure Chat: purge expired disappearing-message ciphertext at rest.
-- Run after 025_realtime_keys_and_membership.sql.
--
-- Disappearing messages (composer expiry presets and the calendar expiry) were
-- only hidden client-side; the encrypted envelope rows stayed in the database
-- forever. That contradicts the ephemeral-message contract and leaves harvestable
-- ciphertext at rest. This migration hard-deletes envelopes once their expiry
-- passes, plus tombstoned ("delete for everyone") rows after a 30-day grace
-- period. The function follows the prune_expired_messaging_typing_indicators
-- pattern: SECURITY DEFINER, invoked opportunistically by any signed-in client.

CREATE INDEX IF NOT EXISTS idx_messaging_envelopes_expires_at
  ON public.messaging_message_envelopes(expires_at)
  WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_messaging_envelopes_deleted_at
  ON public.messaging_message_envelopes(deleted_at)
  WHERE deleted_at IS NOT NULL;

CREATE OR REPLACE FUNCTION public.purge_expired_messaging_envelopes()
RETURNS INTEGER AS $$
DECLARE
  removed INTEGER := 0;
  tombstoned INTEGER := 0;
BEGIN
  DELETE FROM public.messaging_message_envelopes
  WHERE expires_at IS NOT NULL AND expires_at < now();
  GET DIAGNOSTICS removed = ROW_COUNT;

  DELETE FROM public.messaging_message_envelopes
  WHERE deleted_at IS NOT NULL AND deleted_at < now() - interval '30 days';
  GET DIAGNOSTICS tombstoned = ROW_COUNT;

  RETURN removed + tombstoned;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.purge_expired_messaging_envelopes() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.purge_expired_messaging_envelopes() TO authenticated;
