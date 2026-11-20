-- Run with psql -X against a new, disposable PostgreSQL database.
\set ON_ERROR_STOP on

create role anon;
create role authenticated;
create role service_role bypassrls;
create schema auth;
create table auth.users (id uuid primary key);

\ir ../supabase/public-scan-quota.sql
\ir ../supabase/public-scan-quota.sql

insert into auth.users values
  ('10000000-0000-4000-8000-000000000001'),
  ('10000000-0000-4000-8000-000000000002');

do $$
begin
  if has_table_privilege('authenticated', 'public.public_scan_usage', 'SELECT,INSERT,UPDATE,DELETE')
    or has_table_privilege('anon', 'public.public_scan_usage', 'SELECT,INSERT,UPDATE,DELETE')
    or has_function_privilege('authenticated', 'public.manage_public_scan_quota(uuid,text,uuid)', 'EXECUTE')
    or has_function_privilege('anon', 'public.manage_public_scan_quota(uuid,text,uuid)', 'EXECUTE') then
    raise exception 'Browser roles can access account quotas directly';
  end if;
end;
$$;

-- The API executes the RPC under service_role with a verified account UUID.
set role service_role;
do $$
declare
  alice constant uuid := '10000000-0000-4000-8000-000000000001';
  bob constant uuid := '10000000-0000-4000-8000-000000000002';
  request_id uuid := gen_random_uuid();
  other_id uuid := gen_random_uuid();
  result jsonb;
begin
  if (public.manage_public_scan_quota(alice, 'usage')->>'remaining')::int <> 3 then
    raise exception 'New account allowance';
  end if;

  result := public.manage_public_scan_quota(alice, 'reserve', request_id);
  if result->>'status' <> 'ok' or not (result->>'inProgress')::boolean then
    raise exception 'First reservation';
  end if;
  if public.manage_public_scan_quota(alice, 'reserve', request_id)->>'status' <> 'ok'
    or public.manage_public_scan_quota(alice, 'reserve', other_id)->>'status' <> 'active'
    or public.manage_public_scan_quota(bob, 'complete', request_id)->>'status' <> 'expired'
    or public.manage_public_scan_quota(bob, 'reserve', other_id)->>'status' <> 'ok' then
    raise exception 'Reservation retry, in-progress exclusion or account isolation';
  end if;

  if (public.manage_public_scan_quota(alice, 'release', request_id)->>'remaining')::int <> 3 then
    raise exception 'Releasing a failed attempt must restore its reservation';
  end if;

  for credits in reverse 2..0 loop
    request_id := gen_random_uuid();
    if public.manage_public_scan_quota(alice, 'reserve', request_id)->>'status' <> 'ok' then
      raise exception 'A permitted scan was blocked';
    end if;
    result := public.manage_public_scan_quota(alice, 'complete', request_id);
    if (result->>'remaining')::int <> credits or (result->>'inProgress')::boolean then
      raise exception 'Completion charged an incorrect allowance';
    end if;
    result := public.manage_public_scan_quota(alice, 'complete', request_id);
    if (result->>'remaining')::int <> credits then
      raise exception 'Completion retry double-charged';
    end if;
  end loop;
  if public.manage_public_scan_quota(alice, 'reserve', gen_random_uuid())->>'status' <> 'exhausted' then
    raise exception 'Fourth scan was not refused';
  end if;
  if (public.manage_public_scan_quota(alice, 'release', request_id)->>'remaining')::int <> 0 then
    raise exception 'Release erased a completed scan';
  end if;

  -- Seed yesterday's records and an expired lease to exercise reset and crash recovery.
  update public.public_scan_usage set usage_day = (clock_timestamp() at time zone 'UTC')::date - 1
  where account_id = alice;
  update public.public_scan_usage set lease_until = clock_timestamp() - interval '1 second'
  where account_id = bob;
  result := public.manage_public_scan_quota(alice, 'usage');
  if (result->>'remaining')::int <> 3 or (result->>'resetAt')::timestamptz <>
    (((clock_timestamp() at time zone 'UTC')::date + 1)::timestamp at time zone 'UTC') then
    raise exception 'Reset must use midnight UTC';
  end if;
  if public.manage_public_scan_quota(bob, 'complete', other_id)->>'status' <> 'expired'
    or public.manage_public_scan_quota(bob, 'reserve', gen_random_uuid())->>'status' <> 'ok' then
    raise exception 'Expired leases must release capacity without charging';
  end if;
end;
$$;

reset role;
select 'Public Scan quota migration checks passed' as result;
