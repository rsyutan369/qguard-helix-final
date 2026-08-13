-- QGuard Helix — Tenant migration cost assumptions (idempotent, safe re-run).
--
-- Every currency figure the platform shows for a migration programme is a
-- PLANNING ESTIMATE built on assumptions, not measured spend. Those assumptions
-- were previously hardcoded ($165/hr, 38 hrs/week, $250k / $40k per asset), so a
-- tenant whose real rates differ saw a forecast they could not correct and could
-- not audit. This table lets each tenant supply their own rates, per-asset
-- values and approved budget; anything left null falls back to the published
-- default in src/lib/migration/cost-model.ts.
--
-- Security: tenant-isolated by RLS — a row is only ever readable or writable by
-- the user who owns it. No secrets are stored; these are planning inputs only.

create table if not exists public.migration_cost_assumptions (
  user_id uuid primary key references auth.users (id) on delete cascade,
  -- All money columns are nullable: NULL means "use the published default",
  -- which is a different statement from "the tenant entered zero".
  blended_rate_usd numeric(12, 2),
  hours_per_week numeric(5, 2),
  value_per_critical_asset_usd numeric(16, 2),
  value_per_standard_asset_usd numeric(16, 2),
  budget_usd numeric(16, 2),
  currency text not null default 'USD',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- Bounds mirror COST_ASSUMPTION_LIMITS so an out-of-range value cannot be
  -- persisted even if a caller bypasses the API validator.
  constraint migration_cost_assumptions_rate_range
    check (blended_rate_usd is null or (blended_rate_usd >= 1 and blended_rate_usd <= 2000)),
  constraint migration_cost_assumptions_hours_range
    check (hours_per_week is null or (hours_per_week >= 1 and hours_per_week <= 80)),
  constraint migration_cost_assumptions_critical_range
    check (value_per_critical_asset_usd is null or (value_per_critical_asset_usd >= 0 and value_per_critical_asset_usd <= 1000000000)),
  constraint migration_cost_assumptions_standard_range
    check (value_per_standard_asset_usd is null or (value_per_standard_asset_usd >= 0 and value_per_standard_asset_usd <= 1000000000)),
  constraint migration_cost_assumptions_budget_range
    check (budget_usd is null or (budget_usd >= 0 and budget_usd <= 10000000000))
);

comment on table public.migration_cost_assumptions is
  'Per-tenant planning assumptions for migration cost and business-value forecasting. Never telemetry.';

alter table public.migration_cost_assumptions enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'migration_cost_assumptions'
      and policyname = 'migration_cost_assumptions_owner'
  ) then
    create policy migration_cost_assumptions_owner
      on public.migration_cost_assumptions
      for all
      using (auth.uid() = user_id)
      with check (auth.uid() = user_id);
  end if;
end
$$;

-- Keep updated_at honest so the UI can show when assumptions were last changed.
create or replace function public.touch_migration_cost_assumptions()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_touch_migration_cost_assumptions on public.migration_cost_assumptions;
create trigger trg_touch_migration_cost_assumptions
  before update on public.migration_cost_assumptions
  for each row execute function public.touch_migration_cost_assumptions();
