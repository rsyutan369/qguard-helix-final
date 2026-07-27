-- 031_trusted_devices.sql
-- Trusted-device registry for banking-grade app-entry PIN (Android).
-- One row per (user, device); owner-only RLS. Revoking a row forces the target
-- device to full re-auth on its next unlock (checked client-side).

create table if not exists public.trusted_devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  device_id text not null,
  device_name text,
  platform text,
  app_version text,
  registered_at timestamptz not null default now(),
  last_login_at timestamptz,
  revoked_at timestamptz,
  unique (user_id, device_id)
);

create index if not exists trusted_devices_user_idx on public.trusted_devices (user_id);

alter table public.trusted_devices enable row level security;

drop policy if exists "trusted_devices_select_own" on public.trusted_devices;
create policy "trusted_devices_select_own" on public.trusted_devices
  for select using (auth.uid() = user_id);

drop policy if exists "trusted_devices_insert_own" on public.trusted_devices;
create policy "trusted_devices_insert_own" on public.trusted_devices
  for insert with check (auth.uid() = user_id);

drop policy if exists "trusted_devices_update_own" on public.trusted_devices;
create policy "trusted_devices_update_own" on public.trusted_devices
  for update using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "trusted_devices_delete_own" on public.trusted_devices;
create policy "trusted_devices_delete_own" on public.trusted_devices
  for delete using (auth.uid() = user_id);
