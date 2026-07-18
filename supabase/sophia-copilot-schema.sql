-- Sophia — QGuard Helix AI Security Copilot™ conversation persistence.
--
-- Tenant-isolated conversation + message history for the AI Security Copilot.
-- Every row is owned by exactly one user; RLS enforces auth.uid() = user_id so
-- a tenant can never read or write another tenant's conversations. The gateway
-- (src/api-server/copilot.ts) degrades to a bounded in-memory store until this
-- schema is applied, so the copilot works before this runs — apply it to make
-- conversation history durable across sessions and devices.
--
-- Idempotent: safe to run more than once.

/* ------------------------------------------------------------------ */
/* Conversations                                                       */
/* ------------------------------------------------------------------ */
create table if not exists public.copilot_conversations (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references auth.users (id) on delete cascade,
  title         text not null default 'Conversation',
  pinned        boolean not null default false,
  message_count integer not null default 0,
  metadata      jsonb not null default '{}'::jsonb,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create index if not exists copilot_conversations_user_updated_idx
  on public.copilot_conversations (user_id, updated_at desc);

create index if not exists copilot_conversations_user_pinned_idx
  on public.copilot_conversations (user_id, pinned);

/* ------------------------------------------------------------------ */
/* Messages                                                            */
/* ------------------------------------------------------------------ */
create table if not exists public.copilot_messages (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references auth.users (id) on delete cascade,
  conversation_id uuid not null references public.copilot_conversations (id) on delete cascade,
  role            text not null check (role in ('user', 'assistant')),
  content         text not null default '',
  -- The full structured CopilotAnswer (summary/evidence/reasoning/…) for
  -- assistant turns; null for user turns.
  answer          jsonb,
  created_at      timestamptz not null default now()
);

create index if not exists copilot_messages_conversation_idx
  on public.copilot_messages (user_id, conversation_id, created_at);

/* ------------------------------------------------------------------ */
/* Row Level Security — strict per-tenant isolation                    */
/* ------------------------------------------------------------------ */
alter table public.copilot_conversations enable row level security;
alter table public.copilot_messages enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'copilot_conversations' and policyname = 'copilot_conversations_owner'
  ) then
    create policy copilot_conversations_owner on public.copilot_conversations
      for all
      using (auth.uid() = user_id)
      with check (auth.uid() = user_id);
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'copilot_messages' and policyname = 'copilot_messages_owner'
  ) then
    create policy copilot_messages_owner on public.copilot_messages
      for all
      using (auth.uid() = user_id)
      with check (auth.uid() = user_id);
  end if;
end $$;

/* ------------------------------------------------------------------ */
/* updated_at maintenance                                              */
/* ------------------------------------------------------------------ */
create or replace function public.copilot_touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists copilot_conversations_touch on public.copilot_conversations;
create trigger copilot_conversations_touch
  before update on public.copilot_conversations
  for each row execute function public.copilot_touch_updated_at();
