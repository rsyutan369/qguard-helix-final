-- Quantum Vault hard-delete consistency.
-- Deleted vault files must remove active operation rows instead of orphaning them
-- into the Operations panel.

ALTER TABLE public.qguard_vault_operations
  DROP CONSTRAINT IF EXISTS qguard_vault_operations_file_id_fkey;

ALTER TABLE public.qguard_vault_operations
  ADD CONSTRAINT qguard_vault_operations_file_id_fkey
  FOREIGN KEY (file_id)
  REFERENCES public.messaging_vault_files(id)
  ON DELETE CASCADE;

ALTER TABLE public.messaging_vault_files REPLICA IDENTITY FULL;
ALTER TABLE public.qguard_vault_operations REPLICA IDENTITY FULL;

CREATE OR REPLACE FUNCTION public.delete_messaging_vault_file_record(p_file_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM public.qguard_vault_operations
  WHERE file_id = p_file_id
    AND user_id = auth.uid();

  DELETE FROM public.messaging_vault_files
  WHERE id = p_file_id
    AND owner_user_id = auth.uid();

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

REVOKE ALL ON FUNCTION public.delete_messaging_vault_file_record(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.delete_messaging_vault_file_record(UUID) TO authenticated;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_vault_files;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.qguard_vault_operations;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;

NOTIFY pgrst, 'reload schema';
