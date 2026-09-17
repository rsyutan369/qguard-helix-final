-- QGuard Helix — Migration Snapshot Management (idempotent, safe re-run).
--
-- Pre-migration snapshots capture an asset's cryptographic + configuration
-- state BEFORE any remediation/upgrade, so any migration is fully reversible.
-- Security: tenant-isolated via RLS (a snapshot is only ever visible to the
-- user who owns it), integrity-verified with a SHA3-256 hash over the canonical
-- crypto-state payload, retention-bounded, and fully audited. Only metadata is
-- stored — never plaintext secrets/keys. Postgres encrypts all data at rest.

create table if not exists public.migration_snapshots (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  snapshot_id text not null,
  asset_id text,
  asset_name text not null default 'Unknown asset',
  asset_type text not null default 'asset',
  environment text not null default 'unknown',
  migration_job_id text,
  plan_id text,
  -- restorable | restoring | restored | restore_failed | expired | deleted
  --   restoring      = rollback dispatched to an executor, NOT yet confirmed
  --   restored       = an executor confirmed the asset matches this snapshot
  --   restore_failed = the executor tried and could not; still a valid source
  status text not null default 'restorable',
  trigger text not null default 'pre_migration',        -- pre_migration | manual | scheduled
  crypto_state jsonb not null default '{}'::jsonb,       -- algorithms/tls/pki/certificates/keys/config (metadata only)
  configuration_version text,
  created_by text,
  size_bytes bigint not null default 0,
  retention_days integer not null default 90,
  expires_at timestamptz,
  integrity_hash text not null default '',
  integrity_algorithm text not null default 'SHA3-256',
  integrity_verified boolean not null default true,
  restored_at timestamptz,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, snapshot_id)
);

create table if not exists public.migration_snapshot_audit (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  snapshot_id text,
  migration_job_id text,
  action text not null,                                  -- created | execution_recorded | restore_requested | restored | rollback_failed | auto_rollback | deleted | verified
  actor text,
  reason text,
  detail text,
  approval_status text,
  validation_result text,
  restoration_status text,
  integrity_status text,
  created_at timestamptz not null default now()
);

create index if not exists idx_migration_snapshots_user_created on public.migration_snapshots (user_id, created_at desc);
create index if not exists idx_migration_snapshots_user_status on public.migration_snapshots (user_id, status);
create index if not exists idx_migration_snapshots_user_job on public.migration_snapshots (user_id, migration_job_id);
create index if not exists idx_migration_snapshots_user_asset on public.migration_snapshots (user_id, asset_id);
create index if not exists idx_migration_snapshot_audit_user_created on public.migration_snapshot_audit (user_id, created_at desc);

alter table public.migration_snapshots enable row level security;
alter table public.migration_snapshot_audit enable row level security;

do $$
begin
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'migration_snapshots' and policyname = 'migration_snapshots_tenant') then
    create policy migration_snapshots_tenant on public.migration_snapshots
      for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
  end if;
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'migration_snapshot_audit' and policyname = 'migration_snapshot_audit_tenant') then
    create policy migration_snapshot_audit_tenant on public.migration_snapshot_audit
      for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
  end if;
end $$;

-- Realtime so the Live Migration snapshot dashboard updates on any change.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    begin
      alter publication supabase_realtime add table public.migration_snapshots;
    exception when duplicate_object then null; end;
    begin
      alter publication supabase_realtime add table public.migration_snapshot_audit;
    exception when duplicate_object then null; end;
  end if;
end $$;
