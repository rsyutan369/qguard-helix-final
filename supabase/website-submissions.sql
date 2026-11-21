create table if not exists public.website_submissions (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  kind text not null check (kind in ('demo', 'pqc-checklist')),
  source text not null check (source in ('navigation', 'footer', 'homepage', 'checklist')),
  name text not null,
  email text not null,
  organization text not null,
  details jsonb not null default '{}'::jsonb,
  email_status text not null check (email_status in ('pending', 'accepted', 'failed', 'not_configured', 'not_applicable'))
);

create index if not exists website_submissions_kind_created_idx
  on public.website_submissions (kind, created_at desc, id desc);
create index if not exists website_submissions_created_idx
  on public.website_submissions (created_at desc, id desc);

alter table public.website_submissions enable row level security;
revoke all on table public.website_submissions from public, anon, authenticated, service_role;
grant select, insert, update on table public.website_submissions to service_role;
