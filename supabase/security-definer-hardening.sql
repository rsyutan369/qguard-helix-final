-- QGuard — SECURITY DEFINER hardening (2026-09-22)
-- Run AFTER rpc-and-rls-hardening.sql, billing-integrity-hardening.sql and the
-- messaging migrations. Idempotent.
--
-- Supabase's advisor flagged 28 SECURITY DEFINER functions executable by `anon`
-- and 45 by `authenticated`, plus 19 functions with a mutable search_path.
-- Each function below was classified by who actually needs it (RLS policies,
-- column defaults, triggers, app RPC callers — traced 2026-09-22) and hardened
-- accordingly. Nothing here changes behaviour for a legitimate caller.
--
--   A. Guards inside RLS predicate helpers. They MUST stay executable by the
--      roles their policies apply to (policies are `TO public`, including
--      storage.objects — revoking would turn anon's empty result into an error
--      on unrelated buckets), so the fix is inside: an end-user JWT caller may
--      only ask about themselves. Service role / cron / GoTrue contexts (no
--      anon/authenticated claim) are unaffected.
--        * messaging_envelopes_sender_insert checks the RECIPIENT's membership,
--          so is_messaging_conversation_member also answers for another user
--          when the caller is a member of that conversation.
--        * can_view_messaging_profile and claim_messaging_one_time_prekey call
--          is_messaging_contact with the caller in EITHER position, so the two-
--          party helpers accept the caller as either party.
--   B. Real holes, not just lint:
--        * ensure_messaging_defaults(p_user_id) had no caller check: anyone —
--          even anon — could reset another user's messaging modules.
--        * log_qguard_profile_security_event let anon write events into any
--          user's security log.
--        * qguard_has_messaging_access(uid) told any user whether another user
--          holds a messaging subscription.
--   C. EXECUTE revoked where nobody legitimate calls the function as an RPC:
--      trigger / event-trigger functions (PostgreSQL does not check EXECUTE
--      when a trigger fires — verified live as `authenticated`) and unused
--      maintenance helpers. generate_secure_token keeps `authenticated`: it is
--      the column default of vault_shared_links.token.
--   D. search_path pinned (public, extensions) on every flagged function.

-- ---------------------------------------------------------------------------
-- A. Guarded RLS predicate helpers (signatures, volatility and search_path unchanged)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.is_messaging_contact(p_owner_user_id uuid, p_contact_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT (
      COALESCE(auth.role(), '') NOT IN ('anon', 'authenticated')
      OR COALESCE(auth.uid() IN (p_owner_user_id, p_contact_user_id), false)
    )
    AND EXISTS (
      SELECT 1
      FROM public.messaging_contacts c
      WHERE c.owner_user_id = p_owner_user_id
        AND c.contact_user_id = p_contact_user_id
        AND c.trust_state = 'added'
    );
$function$;

CREATE OR REPLACE FUNCTION public.shares_messaging_conversation(p_owner_user_id uuid, p_peer_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT (
      COALESCE(auth.role(), '') NOT IN ('anon', 'authenticated')
      OR COALESCE(auth.uid() IN (p_owner_user_id, p_peer_user_id), false)
    )
    AND EXISTS (
      SELECT 1
      FROM public.messaging_conversation_members owner_member
      JOIN public.messaging_conversation_members peer_member
        ON peer_member.conversation_id = owner_member.conversation_id
      WHERE owner_member.user_id = p_owner_user_id
        AND owner_member.revoked_at IS NULL
        AND peer_member.user_id = p_peer_user_id
        AND peer_member.revoked_at IS NULL
    );
$function$;

CREATE OR REPLACE FUNCTION public.can_view_messaging_profile(p_viewer_user_id uuid, p_target_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT (
      COALESCE(auth.role(), '') NOT IN ('anon', 'authenticated')
      OR COALESCE(auth.uid() IN (p_viewer_user_id, p_target_user_id), false)
    )
    AND (
      p_viewer_user_id = p_target_user_id
      OR public.shares_messaging_conversation(p_viewer_user_id, p_target_user_id)
      OR public.is_messaging_contact(p_viewer_user_id, p_target_user_id)
      OR public.is_messaging_contact(p_target_user_id, p_viewer_user_id)
    );
$function$;

CREATE OR REPLACE FUNCTION public.is_messaging_conversation_member(p_conversation_id uuid, p_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT (
      COALESCE(auth.role(), '') NOT IN ('anon', 'authenticated')
      OR p_user_id = auth.uid()
      OR EXISTS (
        SELECT 1
        FROM public.messaging_conversation_members caller
        WHERE caller.conversation_id = p_conversation_id
          AND caller.user_id = auth.uid()
          AND caller.revoked_at IS NULL
      )
    )
    AND EXISTS (
      SELECT 1
      FROM public.messaging_conversation_members m
      WHERE m.conversation_id = p_conversation_id
        AND m.user_id = p_user_id
        AND m.revoked_at IS NULL
    );
$function$;

CREATE OR REPLACE FUNCTION public.owns_messaging_conversation(p_conversation_id uuid, p_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT (COALESCE(auth.role(), '') NOT IN ('anon', 'authenticated') OR p_user_id = auth.uid())
    AND EXISTS (
      SELECT 1
      FROM public.messaging_conversations c
      WHERE c.id = p_conversation_id
        AND c.owner_user_id = p_user_id
    );
$function$;

CREATE OR REPLACE FUNCTION public.owns_messaging_vault_file(p_file_id uuid, p_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT (COALESCE(auth.role(), '') NOT IN ('anon', 'authenticated') OR p_user_id = auth.uid())
    AND EXISTS (
      SELECT 1
      FROM public.messaging_vault_files f
      WHERE f.id = p_file_id
        AND f.owner_user_id = p_user_id
        AND f.revoked_at IS NULL
    );
$function$;

CREATE OR REPLACE FUNCTION public.can_read_messaging_vault_file(p_file_id uuid, p_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT (COALESCE(auth.role(), '') NOT IN ('anon', 'authenticated') OR p_user_id = auth.uid())
    AND (
      EXISTS (
        SELECT 1
        FROM public.messaging_vault_files f
        WHERE f.id = p_file_id
          AND f.owner_user_id = p_user_id
          AND f.revoked_at IS NULL
      )
      OR EXISTS (
        SELECT 1
        FROM public.messaging_file_grants g
        WHERE g.file_id = p_file_id
          AND g.recipient_user_id = p_user_id
          AND g.revoked_at IS NULL
      )
    );
$function$;

CREATE OR REPLACE FUNCTION public.can_read_messaging_chat_attachment(p_storage_path text, p_user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE SECURITY DEFINER
SET search_path TO 'public', 'storage'
AS $function$
DECLARE
  path_parts TEXT[];
  conversation_id_text TEXT;
  client_message_id_text TEXT;
BEGIN
  IF COALESCE(auth.role(), '') IN ('anon', 'authenticated') AND p_user_id IS DISTINCT FROM auth.uid() THEN
    RETURN FALSE;
  END IF;

  path_parts := storage.foldername(p_storage_path);

  IF array_length(path_parts, 1) < 4 OR path_parts[2] <> 'chat-attachments' THEN
    RETURN FALSE;
  END IF;

  conversation_id_text := path_parts[3];
  client_message_id_text := path_parts[4];

  RETURN EXISTS (
    SELECT 1
    FROM public.messaging_conversation_members m
    WHERE m.conversation_id::TEXT = conversation_id_text
      AND m.user_id = p_user_id
      AND m.revoked_at IS NULL
  )
  AND EXISTS (
    SELECT 1
    FROM public.messaging_message_envelopes e
    WHERE e.conversation_id::TEXT = conversation_id_text
      AND e.client_message_id::TEXT = client_message_id_text
      AND e.deleted_at IS NULL
      AND (
        e.sender_user_id = p_user_id
        OR e.recipient_user_id = p_user_id
        OR public.is_messaging_conversation_member(e.conversation_id, p_user_id)
      )
  );
END;
$function$;

-- ---------------------------------------------------------------------------
-- B. Real holes
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.qguard_has_messaging_access(uid uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT (COALESCE(auth.role(), '') NOT IN ('anon', 'authenticated') OR uid = auth.uid())
    AND EXISTS (
      SELECT 1
      FROM public.billing_subscriptions s
      WHERE s.user_id = uid
        AND lower(s.status) IN ('active', 'trial', 'pending_renewal')
        AND (
          s.current_period_end IS NULL
          OR s.current_period_end > (now() - interval '72 hours')
        )
    );
$function$;

DO $$
DECLARE
  def TEXT;
BEGIN
  -- ensure_messaging_defaults: prepend a caller check to the existing body.
  SELECT pg_get_functiondef('public.ensure_messaging_defaults(uuid)'::regprocedure) INTO def;
  IF position('may only initialise their own messaging defaults' IN def) = 0 THEN
    def := regexp_replace(
      def,
      '(\$function\$\s*BEGIN)',
      E'\\1\n  IF COALESCE(auth.role(), '''') IN (''anon'', ''authenticated'') AND p_user_id IS DISTINCT FROM auth.uid() THEN\n    RAISE EXCEPTION ''a user may only initialise their own messaging defaults'' USING ERRCODE = ''42501'';\n  END IF;'
    );
    EXECUTE def;
  END IF;

  -- log_qguard_profile_security_event: an unauthenticated caller may log
  -- (pre-auth rate limiting / failed sign-in by email hash) but may not
  -- attribute the event to a user id it cannot prove it owns.
  SELECT pg_get_functiondef('public.log_qguard_profile_security_event(text,text,jsonb,text,uuid)'::regprocedure) INTO def;
  IF position('unauthenticated callers cannot attribute' IN def) = 0 THEN
    def := regexp_replace(
      def,
      '(\$function\$\s*DECLARE.*?BEGIN)',
      E'\\1\n  -- unauthenticated callers cannot attribute an event to a user id\n  IF v_actor IS NULL AND COALESCE(auth.role(), '''') = ''anon'' THEN\n    v_user := NULL;\n  END IF;'
    );
    EXECUTE def;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- C. EXECUTE only where it is needed
-- ---------------------------------------------------------------------------

-- Trigger / event-trigger functions: never meaningful as an RPC.
REVOKE EXECUTE ON FUNCTION public.enforce_vault_unlock_rate_limit() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.handle_messaging_profile_defaults() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.qguard_handle_new_user() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.qguard_sync_profile_email() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.touch_migration_cost_assumptions() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.update_vault_storage_quota() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.rls_auto_enable() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.copilot_touch_updated_at() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.governance_anchor_guard() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.qguard_set_updated_at() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.qguard_touch_updated_at() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.set_generated_keys_updated_at() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.set_updated_at() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.qguard_protect_profile_managed_columns() FROM PUBLIC, anon, authenticated;

-- Maintenance helpers with no RPC caller, policy or default (traced 2026-09-22).
REVOKE EXECUTE ON FUNCTION public.cleanup_expired_vault_sessions() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.prune_expired_messaging_call_signals() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.check_vault_rate_limit(text, integer, integer) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.has_active_vault_session(text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.vault_folder_item_count(uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.requesting_user_id() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.cleanup_expired_vault_sessions() TO service_role;
GRANT EXECUTE ON FUNCTION public.prune_expired_messaging_call_signals() TO service_role;
GRANT EXECUTE ON FUNCTION public.check_vault_rate_limit(text, integer, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.has_active_vault_session(text) TO service_role;
GRANT EXECUTE ON FUNCTION public.vault_folder_item_count(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.requesting_user_id() TO service_role;

-- Signed-in only (their callers are authenticated app code / column defaults).
REVOKE EXECUTE ON FUNCTION public.consume_qguard_mfa_recovery_code(text) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.ensure_messaging_defaults(uuid) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.prune_expired_messaging_typing_indicators() FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.vault_folder_path_array(uuid) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.generate_secure_token(integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.consume_qguard_mfa_recovery_code(text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.ensure_messaging_defaults(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.prune_expired_messaging_typing_indicators() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.vault_folder_path_array(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.generate_secure_token(integer) TO authenticated, service_role;

-- ---------------------------------------------------------------------------
-- D. Pinned search_path (a SECURITY DEFINER function resolving names through
--    the caller's search_path can be made to call the caller's objects)
-- ---------------------------------------------------------------------------
ALTER FUNCTION public.calculate_quantum_risk_score(uuid) SET search_path = public, extensions;
ALTER FUNCTION public.check_vault_rate_limit(text, integer, integer) SET search_path = public, extensions;
ALTER FUNCTION public.ensure_vault_profile() SET search_path = public, extensions;
ALTER FUNCTION public.generate_secure_token(integer) SET search_path = public, extensions;
ALTER FUNCTION public.get_dashboard_summary(uuid) SET search_path = public, extensions;
ALTER FUNCTION public.get_exposure_map(uuid) SET search_path = public, extensions;
ALTER FUNCTION public.get_profile_security_snapshot(uuid) SET search_path = public, extensions;
ALTER FUNCTION public.get_recent_security_events(uuid, integer) SET search_path = public, extensions;
ALTER FUNCTION public.has_active_vault_session(text) SET search_path = public, extensions;
ALTER FUNCTION public.prune_expired_messaging_call_signals() SET search_path = public, extensions;
ALTER FUNCTION public.requesting_user_id() SET search_path = public, extensions;
ALTER FUNCTION public.vault_folder_item_count(uuid) SET search_path = public, extensions;
ALTER FUNCTION public.vault_folder_path_array(uuid) SET search_path = public, extensions;
ALTER FUNCTION public.copilot_touch_updated_at() SET search_path = public, extensions;
ALTER FUNCTION public.governance_anchor_guard() SET search_path = public, extensions;
ALTER FUNCTION public.qguard_set_updated_at() SET search_path = public, extensions;
ALTER FUNCTION public.qguard_touch_updated_at() SET search_path = public, extensions;
ALTER FUNCTION public.set_generated_keys_updated_at() SET search_path = public, extensions;
ALTER FUNCTION public.set_updated_at() SET search_path = public, extensions;
