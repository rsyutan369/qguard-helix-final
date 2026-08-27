-- 032 — Reset the call relay to "not configured", and document how to set a real one.
--
-- WHY
-- ---
-- `messaging_call_relay` row 1 pointed at the free Open Relay Project TURN
-- (`openrelay.metered.ca`). It is dead, and measurably so: driving real
-- Chromium ICE against it returns `TURN allocate error` (code 400) and gathers
-- ZERO `typ relay` candidates. Every call in `messaging_call_signals` from
-- 2026-08-13 to 2026-08-26 confirms it — not one relay candidate was ever
-- exchanged, so no call across two different networks could ever have
-- connected.
--
-- The second, less obvious harm is why this row is being cleared rather than
-- just left alone: an unallocatable TURN entry stops ICE gathering from
-- COMPLETING at all. Chromium keeps retrying the dead allocation for the whole
-- gathering timeout, which delayed even same-LAN host candidates by ~28s and
-- pushed calls past the caller's 45s give-up. Measured on the same machine:
--
--     STUN only ................. gathering complete in 605 ms
--     STUN + openrelay TURN ..... gathering NEVER completes, 0 relay candidates
--
-- So a broken relay was strictly worse than no relay. With the row cleared,
-- calls run on STUN: same network and cooperative NATs connect immediately.
--
-- WHAT AN OPERATOR SHOULD DO
-- --------------------------
-- Cross-network calling (a phone on mobile data reaching a desktop behind a
-- home router) REQUIRES a TURN relay. Stand up coturn and point this row at it:
--
--   UPDATE public.messaging_call_relay SET
--     stun_urls      = ARRAY['stun:relay.example.com:3478'],
--     turn_urls      = ARRAY['turn:relay.example.com:3478',
--                            'turns:relay.example.com:5349?transport=tcp'],
--     turn_username  = 'qguard',
--     turn_credential= '<shared secret>',
--     updated_at     = now()
--   WHERE id = 1;
--
-- The app re-reads this row every 5 minutes, so a relay can be rotated without
-- shipping a new build. Media stays end-to-end encrypted either way: a relay
-- only ever forwards AES-256-GCM ciphertext and never holds a key. The client
-- verifies the relay by gathering with `iceTransportPolicy: "relay"` and drops
-- a relay that cannot allocate, so a misconfigured row degrades to STUN instead
-- of stalling every call.

UPDATE public.messaging_call_relay
SET
  turn_urls = ARRAY[]::text[],
  turn_username = '',
  turn_credential = '',
  updated_at = now()
WHERE id = 1
  AND EXISTS (
    SELECT 1 FROM unnest(turn_urls) AS url
    WHERE url ILIKE '%openrelay.metered.ca%'
       OR url ILIKE '%relay.metered.ca%'
  );

COMMENT ON TABLE public.messaging_call_relay IS
  'STUN/TURN configuration for quantum-encrypted calls. turn_urls empty = no relay: '
  'same-network and cooperative-NAT calls work, cross-network calls do not. '
  'Never point this at a relay that cannot allocate - an unreachable TURN entry '
  'stops ICE gathering from completing and slows every call, including local ones.';
