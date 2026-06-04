-- QGuard Quantum Vault filename hints and delete repair.
-- Run after 011_sidebar_navigation_cleanup.sql.

ALTER TABLE public.messaging_vault_files
  ADD COLUMN IF NOT EXISTS display_name_hint TEXT NOT NULL DEFAULT 'vault object';

UPDATE public.messaging_vault_files f
SET display_name_hint = latest.display_name_hint
FROM (
  SELECT DISTINCT ON (file_id)
    file_id,
    display_name_hint
  FROM public.qguard_vault_operations
  WHERE file_id IS NOT NULL
    AND display_name_hint IS NOT NULL
    AND btrim(display_name_hint) <> ''
    AND lower(display_name_hint) NOT LIKE 'vault object%'
  ORDER BY file_id, updated_at DESC
) latest
WHERE f.id = latest.file_id
  AND (f.display_name_hint = 'vault object' OR btrim(f.display_name_hint) = '');

DROP POLICY IF EXISTS messaging_vault_owner_delete ON public.messaging_vault_files;
CREATE POLICY messaging_vault_owner_delete ON public.messaging_vault_files
  FOR DELETE USING (owner_user_id = auth.uid());

DROP POLICY IF EXISTS messaging_files_storage_delete ON storage.objects;
CREATE POLICY messaging_files_storage_delete ON storage.objects
  FOR DELETE USING (
    bucket_id = 'messaging-files'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  );

DROP POLICY IF EXISTS messaging_files_storage_update ON storage.objects;
CREATE POLICY messaging_files_storage_update ON storage.objects
  FOR UPDATE USING (
    bucket_id = 'messaging-files'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  )
  WITH CHECK (
    bucket_id = 'messaging-files'
    AND auth.uid()::TEXT = (storage.foldername(name))[1]
  );

CREATE OR REPLACE FUNCTION public.delete_messaging_vault_file_record(p_file_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM public.messaging_vault_files
  WHERE id = p_file_id
    AND owner_user_id = auth.uid();

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.delete_messaging_vault_file_record(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.delete_messaging_vault_file_record(UUID) TO authenticated;

NOTIFY pgrst, 'reload schema';
