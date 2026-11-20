begin;

create table if not exists public.public_scan_usage (
  account_id uuid not null references auth.users(id) on delete cascade,
  scan_id uuid not null,
  usage_day date not null,
  lease_until timestamptz not null,
  completed_at timestamptz,
  primary key (account_id, scan_id)
);

create index if not exists public_scan_usage_account_day
  on public.public_scan_usage (account_id, usage_day);

alter table public.public_scan_usage enable row level security;
revoke all on public.public_scan_usage from public, anon, authenticated;

-- One lock per authenticated account, across dates and API replicas. A scan is
-- counted against its admission day. Expired leases never count as successes.
create or replace function public.manage_public_scan_quota(
  p_account_id uuid, p_operation text, p_scan_id uuid default null
) returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_now timestamptz;
  v_day date;
  v_used integer;
  v_status text := 'ok';
  v_active boolean;
  v_limit constant integer := 3;
begin
  if p_account_id is null or p_operation is null
    or p_operation not in ('usage', 'reserve', 'complete', 'release')
    or (p_operation <> 'usage' and p_scan_id is null) then
    raise exception 'Invalid quota operation';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_account_id::text, 184281));
  v_now := pg_catalog.clock_timestamp();
  v_day := (v_now at time zone 'UTC')::date;

  delete from public.public_scan_usage
  where account_id = p_account_id and completed_at is null and lease_until <= v_now;

  select count(*) into v_used from public.public_scan_usage
  where account_id = p_account_id and usage_day = v_day and completed_at is not null;

  if p_operation = 'reserve' then
    if exists (
      select 1 from public.public_scan_usage
      where account_id = p_account_id and scan_id = p_scan_id and completed_at is null
    ) then
      v_status := 'ok'; -- retry after an ambiguous HTTP response
    elsif v_used >= v_limit then
      v_status := 'exhausted';
    elsif exists (
      select 1 from public.public_scan_usage
      where account_id = p_account_id and completed_at is null
    ) then
      v_status := 'active';
    else
      insert into public.public_scan_usage (account_id, scan_id, usage_day, lease_until)
      values (p_account_id, p_scan_id, v_day, v_now + interval '3 minutes');
    end if;
  elsif p_operation = 'complete' then
    update public.public_scan_usage set completed_at = v_now
    where account_id = p_account_id and scan_id = p_scan_id and completed_at is null;
    if not exists (
      select 1 from public.public_scan_usage
      where account_id = p_account_id and scan_id = p_scan_id and completed_at is not null
    ) then
      v_status := 'expired';
    end if;
  elsif p_operation = 'release' then
    delete from public.public_scan_usage
    where account_id = p_account_id and scan_id = p_scan_id and completed_at is null;
  end if;

  select count(*) into v_used from public.public_scan_usage
  where account_id = p_account_id and usage_day = v_day and completed_at is not null;
  select exists (
    select 1 from public.public_scan_usage
    where account_id = p_account_id and completed_at is null
  ) into v_active;

  return jsonb_build_object(
    'status', v_status,
    'limit', v_limit,
    'remaining', v_limit - v_used,
    'resetAt', ((v_day + 1)::timestamp at time zone 'UTC'),
    'inProgress', v_active
  );
end;
$$;

revoke all on function public.manage_public_scan_quota(uuid, text, uuid) from public, anon, authenticated;
grant execute on function public.manage_public_scan_quota(uuid, text, uuid) to service_role;
grant select, insert, update, delete on public.public_scan_usage to service_role;
notify pgrst, 'reload schema';

commit;
