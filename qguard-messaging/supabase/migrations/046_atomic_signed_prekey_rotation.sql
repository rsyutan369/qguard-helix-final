-- 046: publishing a rotated signed prekey retires the old one atomically.
--
-- Migration 001 allows ONE active signed prekey per device
-- (uniq_active_messaging_signed_prekey). Every client publishes a rotated
-- prekey new-first, old-second: upsert the new row as active, then deactivate
-- the rest. Inserting first was deliberate (deactivating first stranded a
-- device with no active prekey whenever the publish failed), but against the
-- unique index the insert itself fails with 23505 the moment an older active
-- prekey exists. The very first prekey of a device published fine; every
-- daily rotation after it was refused. The device kept the new private key
-- while the relay kept advertising the old one, and Secure Chat, which only
-- sends from a device whose published prekey matches its own, stopped
-- sending ("Refreshing this desktop signed prekey" / "Open the desktop app to
-- send securely") on every device a day after it was registered.
--
-- This trigger retires the device's other active prekeys inside the same
-- statement that activates a new one, so the swap is atomic: there is never a
-- moment with two active prekeys or with none, and a failed publish leaves
-- the old prekey active. It fixes clients already installed, without an app
-- update: their existing upsert now succeeds and their follow-up deactivate
-- finds nothing left to do.
--
-- SECURITY INVOKER on purpose: the UPDATE runs under the caller's RLS
-- (messaging_signed_prekeys_owner: auth.uid() = user_id), so a row naming
-- another account's device can never retire that account's prekeys.

CREATE OR REPLACE FUNCTION public.messaging_retire_superseded_signed_prekeys()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
BEGIN
  UPDATE public.messaging_signed_prekeys
  SET is_active = false
  WHERE device_id = NEW.device_id
    AND user_id = NEW.user_id
    AND id <> NEW.id
    AND is_active = true;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS messaging_signed_prekeys_retire_superseded ON public.messaging_signed_prekeys;
CREATE TRIGGER messaging_signed_prekeys_retire_superseded
  BEFORE INSERT OR UPDATE OF is_active ON public.messaging_signed_prekeys
  FOR EACH ROW
  WHEN (NEW.is_active = true)
  EXECUTE FUNCTION public.messaging_retire_superseded_signed_prekeys();
