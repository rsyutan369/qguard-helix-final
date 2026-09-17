-- 034: A retired signing key must stay VERIFIABLE, even though it is no longer
--      usable for delivery
--
-- Context: as of this release the client no longer treats an inbound message's
-- own attached public keys as proof of who sent it. `verify_sender_identity`
-- (src-tauri/src/commands/messaging.rs) requires those keys to be the ones the
-- named device actually published to `messaging_devices`; a message whose
-- signing key is not the registered one is refused outright, and a message
-- whose sender device cannot be looked up at all is shown as
-- "Sender unverified" rather than "Verified".
--
-- That lookup has to be able to see the device row. Migration 018 scoped peer
-- visibility to non-revoked devices:
--
--   OR (trust_state <> 'revoked'
--       AND public.shares_messaging_conversation(auth.uid(), user_id))
--
-- which is the right rule for "where may I SEND?" but the wrong rule for "who
-- SIGNED this?". Retiring a key does not retroactively unsign the messages it
-- signed while it was live, and device rows are retired routinely -- a
-- reinstall, a rotation, the FIPS 203 cutover. Under the old policy every
-- message a peer sent before their last re-key would permanently read as
-- "Sender unverified", which trains people to ignore the one badge that is
-- supposed to mean something.
--
-- Fix: peers in a shared conversation may SELECT a device row regardless of
-- trust_state. This discloses nothing new -- those exact identity columns were
-- readable by the same peers while the device was active, and they are public
-- key material by construction.
--
-- Delivery is NOT widened by this. The client's delivery query filters
-- `.neq("trust_state", "revoked")` itself, `isTrustedDeviceForDelivery` accepts
-- only ThisDevice/Trusted, and the signed-prekey policy below still hides
-- inactive prekeys -- so a revoked device remains unaddressable, it is merely
-- no longer unverifiable.
--
-- Safe to re-run.

DROP POLICY IF EXISTS messaging_devices_conversation_select ON public.messaging_devices;
CREATE POLICY messaging_devices_conversation_select ON public.messaging_devices
  FOR SELECT USING (
    auth.uid() = user_id
    OR public.shares_messaging_conversation(auth.uid(), user_id)
  );

-- Unchanged, restated so the two policies stay legible side by side: a peer may
-- only read prekeys that are still ACTIVE. Prekeys are for sealing new
-- messages, so unlike identity keys there is nothing to verify retrospectively.
DROP POLICY IF EXISTS messaging_signed_prekeys_conversation_select ON public.messaging_signed_prekeys;
CREATE POLICY messaging_signed_prekeys_conversation_select ON public.messaging_signed_prekeys
  FOR SELECT USING (
    auth.uid() = user_id
    OR (
      is_active = true
      AND public.shares_messaging_conversation(auth.uid(), user_id)
    )
  );

NOTIFY pgrst, 'reload schema';
