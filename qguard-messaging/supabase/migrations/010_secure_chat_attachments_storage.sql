-- QGuard Secure Chat encrypted attachment storage access.
-- Run after 009_quantum_vault_operations_repair.sql.

CREATE OR REPLACE FUNCTION public.can_read_messaging_chat_attachment(
  p_storage_path TEXT,
  p_user_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
  path_parts TEXT[];
  conversation_id_text TEXT;
  client_message_id_text TEXT;
BEGIN
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
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, storage;

DROP POLICY IF EXISTS messaging_files_storage_select ON storage.objects;
CREATE POLICY messaging_files_storage_select ON storage.objects
  FOR SELECT USING (
    bucket_id = 'messaging-files'
    AND (
      auth.uid()::TEXT = (storage.foldername(name))[1]
      OR public.can_read_messaging_chat_attachment(name, auth.uid())
      OR EXISTS (
        SELECT 1
        FROM public.messaging_vault_files f
        JOIN public.messaging_file_grants g ON g.file_id = f.id
        WHERE f.storage_path = name
          AND g.recipient_user_id = auth.uid()
          AND g.revoked_at IS NULL
      )
    )
  );

NOTIFY pgrst, 'reload schema';
