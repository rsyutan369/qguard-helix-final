-- QGuard Helix — enterprise-scale composite indexes (idempotent, safe re-run).
--
-- Every platform aggregation is tenant-scoped (user_id) and typically ordered
-- by recency with a row cap, e.g.:
--   .eq('user_id', ...).order('created_at', { ascending: false }).limit(N)
-- Plain single-column user_id indexes (already present from the module
-- schemas) satisfy small tenants; at 10k–100k+ rows per table the composite
-- (user_id, <order column> DESC) indexes below let PostgreSQL serve these as
-- pure index scans, and the partial/status composites accelerate the exact
-- HEAD counts the snapshot uses for truthful headline numbers.
--
-- Each block is guarded so missing optional tables never fail the run.

do $$
begin
  if to_regclass('public.assets') is not null then
    create index if not exists idx_assets_user_updated on public.assets (user_id, updated_at desc);
  end if;

  if to_regclass('public.crypto_inventory') is not null then
    create index if not exists idx_crypto_inventory_user_created on public.crypto_inventory (user_id, created_at desc);
    create index if not exists idx_crypto_inventory_user_vuln on public.crypto_inventory (user_id, is_vulnerable);
    create index if not exists idx_crypto_inventory_user_safe on public.crypto_inventory (user_id, is_quantum_safe);
    create index if not exists idx_crypto_inventory_user_asset on public.crypto_inventory (user_id, asset_id);
  end if;

  if to_regclass('public.pqc_scan_results') is not null then
    create index if not exists idx_pqc_scan_results_user_created on public.pqc_scan_results (user_id, created_at desc);
    create index if not exists idx_pqc_scan_results_user_asset on public.pqc_scan_results (user_id, asset_id);
  end if;

  if to_regclass('public.pqc_scan_sessions') is not null then
    create index if not exists idx_pqc_scan_sessions_user_created on public.pqc_scan_sessions (user_id, created_at desc);
  end if;

  if to_regclass('public.crypto_exposures') is not null then
    create index if not exists idx_crypto_exposures_user_created on public.crypto_exposures (user_id, created_at desc);
  end if;

  if to_regclass('public.certificates') is not null then
    create index if not exists idx_certificates_user_updated on public.certificates (user_id, updated_at desc);
    create index if not exists idx_certificates_user_not_after on public.certificates (user_id, not_after);
  end if;

  if to_regclass('public.generated_keys') is not null then
    create index if not exists idx_generated_keys_user_created on public.generated_keys (user_id, created_at desc);
  end if;

  if to_regclass('public.runtime_crypto_events') is not null then
    create index if not exists idx_runtime_crypto_events_user_observed on public.runtime_crypto_events (user_id, observed_at desc);
  end if;

  if to_regclass('public.security_events') is not null then
    create index if not exists idx_security_events_user_created on public.security_events (user_id, created_at desc);
  end if;

  if to_regclass('public.scanner_alerts') is not null then
    create index if not exists idx_scanner_alerts_user_created on public.scanner_alerts (user_id, created_at desc);
  end if;

  if to_regclass('public.scanner_evidence') is not null then
    create index if not exists idx_scanner_evidence_user_observed on public.scanner_evidence (user_id, observed_at desc);
  end if;

  if to_regclass('public.asset_relationships') is not null then
    create index if not exists idx_asset_relationships_user on public.asset_relationships (user_id);
  end if;

  if to_regclass('public.connector_accounts') is not null then
    create index if not exists idx_connector_accounts_user on public.connector_accounts (user_id);
  end if;

  if to_regclass('public.vault_files') is not null then
    create index if not exists idx_vault_files_user on public.vault_files (user_id);
  end if;

  if to_regclass('public.migration_jobs') is not null then
    create index if not exists idx_migration_jobs_user_updated on public.migration_jobs (user_id, updated_at desc);
    create index if not exists idx_migration_jobs_user_status on public.migration_jobs (user_id, status);
  end if;

  if to_regclass('public.migration_plans') is not null then
    create index if not exists idx_migration_plans_user_updated on public.migration_plans (user_id, updated_at desc);
    create index if not exists idx_migration_plans_user_status on public.migration_plans (user_id, status);
  end if;

  if to_regclass('public.migration_validation_logs') is not null then
    create index if not exists idx_migration_validation_logs_user_created on public.migration_validation_logs (user_id, created_at desc);
  end if;

  if to_regclass('public.migration_events') is not null then
    create index if not exists idx_migration_events_user_created on public.migration_events (user_id, created_at desc);
  end if;

  if to_regclass('public.quantum_trust_certificates') is not null then
    create index if not exists idx_qtc_user_issued on public.quantum_trust_certificates (user_id, issued_at desc);
  end if;
end $$;
