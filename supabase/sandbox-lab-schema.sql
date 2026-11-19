-- Dedicated evidence records. User sessions can read their history, while
-- only the backend worker can write claims, results and evidence links.
create table if not exists public.sandbox_lab_runs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  asset_id uuid references public.assets(id) on delete set null,
  source_plan_id text references public.migration_plans(id) on delete set null,
  attached_plan_id text references public.migration_plans(id) on delete set null,
  attached_at timestamptz,
  configuration jsonb not null,
  asset_snapshot jsonb not null,
  status text not null default 'queued' check (status in ('queued','running','cancelling','finished','failed','cancelled')),
  current_operation text not null default 'Waiting for a lab executor',
  results jsonb not null default '[]'::jsonb,
  planned_checks integer not null default 0 check (planned_checks between 0 and 32),
  logs jsonb not null default '[]'::jsonb,
  error text,
  lease_expires_at timestamptz,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz,
  cleanup_status text not null default 'pending' check (cleanup_status in ('pending','released','interrupted')),
  updated_at timestamptz not null default now()
);
alter table public.sandbox_lab_runs add column if not exists planned_checks integer not null default 0;

alter table public.sandbox_lab_runs enable row level security;
revoke all on public.sandbox_lab_runs from public, anon, authenticated;
grant select on public.sandbox_lab_runs to authenticated;
grant all on public.sandbox_lab_runs to service_role;
drop policy if exists sandbox_lab_runs_read_own on public.sandbox_lab_runs;
create policy sandbox_lab_runs_read_own on public.sandbox_lab_runs
  for select to authenticated using (auth.uid() = user_id);

create unique index if not exists sandbox_lab_one_live_run_per_user
  on public.sandbox_lab_runs (user_id) where status in ('queued','running','cancelling');
create index if not exists sandbox_lab_user_history on public.sandbox_lab_runs (user_id, created_at desc);
create index if not exists sandbox_lab_queued on public.sandbox_lab_runs (created_at) where status = 'queued';
create index if not exists sandbox_lab_active_lease on public.sandbox_lab_runs (lease_expires_at)
  where status in ('running','cancelling');

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'sandbox_lab_runs'
     ) then
    alter publication supabase_realtime add table public.sandbox_lab_runs;
  end if;
end $$;
