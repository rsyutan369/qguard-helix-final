-- 036_ratchet_envelope_header.sql
--
-- Post-quantum session ratchet (roadmap Phase 2; design:
-- docs/superpowers/specs/2026-10-16-pq-ratchet-design.md §4.4 and §7).
--
-- A ratchet envelope stores its header in `sealed_sender_envelope.ratchet`.
-- The first messages of a session (`kind = 'init'`) still carry the hybrid
-- X25519 + ML-KEM-1024 encapsulation that seeds it; ordinary messages
-- (`kind = 'msg'`) take their key from the session and carry
-- `hybrid_ciphertext: null`.
--
-- The client writes the `hybrid_ciphertext` KEY on every row (null for a
-- ratchet message), so the insert policy of migration 007
-- (`sealed_sender_envelope ? 'hybrid_ciphertext'`) already admits ratchet
-- rows and the app works with or without this migration. What this migration
-- adds is the tightening the design asks for: a null encapsulation is accepted
-- ONLY on a well-formed ratchet `msg`, every ratchet header must have its
-- required fields, and an `init` must carry its seed.
--
-- The relay still stores ciphertext and public material only: the header is a
-- session id, a public X25519 ratchet key, two counters and, now and then, a
-- public ML-KEM-1024 encapsulation key or ciphertext. No RLS read rule changes.
--
-- Reviewed against 004 and 007 (the insert policy, reproduced below with only
-- the encapsulation clause changed), 026 (expired-envelope purge: unaffected,
-- it deletes by expires_at / deleted_at), and 030 (paywall policy: separate,
-- unaffected).

-- ---------------------------------------------------------------------------
-- Header shape, for every writer (including the service role).
-- NOT VALID + VALIDATE: no existing row has a `ratchet` key, so validation
-- cannot fail, and it does not hold a long lock while it scans.
-- ---------------------------------------------------------------------------
ALTER TABLE public.messaging_message_envelopes
  DROP CONSTRAINT IF EXISTS messaging_envelopes_ratchet_header_shape;
ALTER TABLE public.messaging_message_envelopes
  ADD CONSTRAINT messaging_envelopes_ratchet_header_shape CHECK (
    NOT (sealed_sender_envelope ? 'ratchet')
    OR (
      jsonb_typeof(sealed_sender_envelope->'ratchet') = 'object'
      AND (sealed_sender_envelope->'ratchet') ?& ARRAY['v', 'kind', 'session', 'dh', 'pn', 'n']
      AND sealed_sender_envelope->'ratchet'->>'kind' IN ('init', 'msg')
      AND jsonb_typeof(sealed_sender_envelope->'ratchet'->'dh') = 'array'
      AND jsonb_array_length(sealed_sender_envelope->'ratchet'->'dh') = 32
      AND (
        sealed_sender_envelope->'ratchet'->>'kind' = 'msg'
        OR jsonb_typeof(sealed_sender_envelope->'hybrid_ciphertext') = 'object'
      )
    )
  ) NOT VALID;
ALTER TABLE public.messaging_message_envelopes
  VALIDATE CONSTRAINT messaging_envelopes_ratchet_header_shape;

-- ---------------------------------------------------------------------------
-- Insert policy: identical to 007 except the encapsulation clause.
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS messaging_envelopes_sender_insert ON public.messaging_message_envelopes;
CREATE POLICY messaging_envelopes_sender_insert ON public.messaging_message_envelopes
  FOR INSERT WITH CHECK (
    sender_user_id = auth.uid()
    AND sender_device_id IS NOT NULL
    AND recipient_device_id IS NOT NULL
    AND public.is_messaging_conversation_member(conversation_id, sender_user_id)
    AND public.is_messaging_conversation_member(conversation_id, recipient_user_id)
    AND EXISTS (
      SELECT 1 FROM public.messaging_devices d
      WHERE d.id = sender_device_id
        AND d.user_id = sender_user_id
        AND d.trust_state <> 'revoked'
    )
    AND EXISTS (
      SELECT 1 FROM public.messaging_devices d
      WHERE d.id = recipient_device_id
        AND d.user_id = recipient_user_id
        AND d.trust_state <> 'revoked'
    )
    AND octet_length(ciphertext) > 0
    AND octet_length(nonce) = 12
    AND octet_length(auth_tag) = 16
    AND octet_length(aad) > 0
    AND sealed_sender_envelope ? 'hybrid_ciphertext'
    AND (
      -- One-shot envelopes and ratchet inits carry their encapsulation...
      jsonb_typeof(sealed_sender_envelope->'hybrid_ciphertext') = 'object'
      -- ...an ordinary ratchet message carries none: its key is the session's.
      OR (
        jsonb_typeof(sealed_sender_envelope->'hybrid_ciphertext') = 'null'
        AND sealed_sender_envelope->'ratchet'->>'kind' = 'msg'
      )
    )
    AND sealed_sender_envelope ? 'message_signature'
    AND (
      client_message_id IS NULL
      OR sealed_sender_envelope->>'client_message_id' = client_message_id::TEXT
    )
    AND (
      parent_client_message_id IS NULL
      OR lifecycle ? 'reply_to'
      OR sealed_sender_envelope ? 'parent_client_message_id'
    )
  );
