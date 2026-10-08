-- 035 — Actually clear the dead call relay, and make it unrepresentable.
--
-- WHY THIS EXISTS WHEN 032 ALREADY "DID" IT
-- -----------------------------------------
-- Migration 032 was supposed to permanently clear the dead public TURN relay
-- (`openrelay.metered.ca`) out of `messaging_call_relay`. It never ran. It was
-- written against `text[]` semantics:
--
--     SET turn_urls = ARRAY[]::text[]
--     WHERE EXISTS (SELECT 1 FROM unnest(turn_urls) AS url ...)
--
-- but 027 declares `turn_urls` (and `stun_urls`) as **jsonb**. Verified against
-- the live database:
--
--     ERROR: 42883: function unnest(jsonb) does not exist
--
-- So 032's UPDATE throws, the statement is rolled back, and the relay row keeps
-- its dead TURN entries. The only thing that ever cleared them was a one-off
-- manual edit, which did not survive — leaving the repo with a fix that looked
-- permanent, was tested by nobody, and could not work.
--
-- WHY A DEAD RELAY IS WORSE THAN NO RELAY
-- ---------------------------------------
-- An unallocatable TURN entry does not merely fail to help; it stops ICE
-- gathering from COMPLETING. Chromium retries the dead allocation for the whole
-- gathering timeout, which starves even same-LAN host candidates. Re-measured
-- with real Chromium on 2026-10-07, driving ICE over CDP:
--
--     STUN only ................. gathering complete in 2,903 ms
--     STUN + openrelay TURN ..... NEVER completes (15s budget), 9 ICE errors
--     openrelay, relay-only ..... 0 relay candidates, TURN allocate error (400)
--
-- That is why this row is cleared rather than left for the client to work
-- around, and why the client now also withholds any relay it has not PROVEN
-- can allocate (src/lib/call-ice.ts, `RelayAdmission`).
--
-- WHAT AN OPERATOR SHOULD DO
-- --------------------------
-- Cross-network calling (a phone on mobile data reaching a desktop behind a
-- home router) REQUIRES a working TURN relay. Point this row at your own:
--
--   UPDATE public.messaging_call_relay SET
--     stun_urls       = '["stun:relay.example.com:3478"]'::jsonb,
--     turn_urls       = '["turn:relay.example.com:3478",
--                         "turns:relay.example.com:5349?transport=tcp"]'::jsonb,
--     turn_username   = 'qguard',
--     turn_credential = '<shared secret>',
--     updated_at      = now()
--   WHERE id = 1;
--
-- The client re-reads this row every 5 minutes and verifies it by gathering
-- with `iceTransportPolicy: "relay"`, so a relay can be rotated without
-- shipping a build, and a misconfigured one degrades to STUN instead of
-- stalling every call. Media stays end-to-end encrypted through any relay: it
-- only ever forwards AES-256-GCM ciphertext and never holds a key.

-- 1. Clear the dead relay. jsonb this time, and guarded on jsonb_typeof so a
--    hand-edited scalar or null cannot make this migration throw the way 032
--    did.
UPDATE public.messaging_call_relay
SET
  turn_urls = '[]'::jsonb,
  turn_username = '',
  turn_credential = '',
  updated_at = now()
WHERE id = 1
  AND jsonb_typeof(turn_urls) = 'array'
  AND EXISTS (
    SELECT 1
    FROM jsonb_array_elements_text(turn_urls) AS url
    WHERE url ILIKE '%metered.ca%'
  );

-- 2. Make the known-dead relay unrepresentable, so this cannot regress a third
--    time through a re-seed, a restore, or a copy-pasted snippet.
--
--    Scoped deliberately narrowly: it names the one relay that has been
--    measured dead twice, rather than trying to guess which relays are good.
--    Any other relay — including a paid Metered account on a different host —
--    is unaffected. If that service is ever worth using again, dropping this
--    constraint is a one-line, obvious decision rather than an accident.
ALTER TABLE public.messaging_call_relay
  DROP CONSTRAINT IF EXISTS messaging_call_relay_no_known_dead_relay;

--    Expressed as a scalar test on the rendered jsonb rather than over
--    `jsonb_array_elements_text`, because a CHECK constraint may not contain a
--    subquery — the trap that would have made this migration fail at DDL time
--    the same way 032 failed at DML time.
ALTER TABLE public.messaging_call_relay
  ADD CONSTRAINT messaging_call_relay_no_known_dead_relay
  CHECK (turn_urls::text NOT ILIKE '%openrelay.metered.ca%');

COMMENT ON TABLE public.messaging_call_relay IS
  'STUN/TURN configuration for quantum-encrypted calls. turn_urls empty = no relay: '
  'same-network and cooperative-NAT calls connect, cross-network calls do not. '
  'Never point this at a relay that cannot allocate - an unreachable TURN entry stops '
  'ICE gathering from completing and breaks every call, local ones included. The client '
  'verifies a relay before using it and withholds any it has not proven.';
