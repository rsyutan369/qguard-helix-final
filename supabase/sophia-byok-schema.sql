-- Sophia — Bring-Your-Own-Key model connections.
--
-- One row per (user, provider): the tenant's own API key for Anthropic, OpenAI,
-- Nous Hermes, Moonshot Kimi, Zhipu GLM or DeepSeek, sealed with AES-256-GCM by
-- the API server (src/api-server/copilot-llm.ts). The plaintext key never
-- reaches the database or the browser.
--
-- Access model: RLS is ON and NO policy is granted to `anon` or `authenticated`,
-- so the browser's Supabase client cannot read even the ciphertext. Only the API
-- server (service role) touches this table, and it pins every query to the
-- user id taken from the verified access token. The gateway falls back to a
-- bounded in-memory store until this schema is applied.
--
-- Idempotent: safe to run more than once.

create table if not exists public.copilot_llm_providers (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null references auth.users (id) on delete cascade,
  provider         text not null check (provider in ('anthropic', 'openai', 'hermes', 'kimi', 'glm', 'deepseek')),
  model            text not null check (char_length(model) between 1 and 100),
  endpoint         text not null default 'global' check (char_length(endpoint) between 1 and 40),
  -- v1.<mode>.<iv>.<tag>.<ciphertext>; AAD binds it to user_id + provider.
  key_ciphertext   text not null,
  key_hint         text not null default '' check (char_length(key_hint) <= 8),
  is_active        boolean not null default false,
  status           text not null default 'unverified' check (status in ('verified', 'unverified', 'invalid', 'error')),
  last_verified_at timestamptz,
  last_error       text check (last_error is null or char_length(last_error) <= 600),
  last_used_at     timestamptz,
  request_count    integer not null default 0,
  input_tokens     bigint not null default 0,
  output_tokens    bigint not null default 0,
  -- When the user confirmed platform evidence may be sent to this provider.
  consent_at       timestamptz,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  unique (user_id, provider)
);

-- At most one active engine per user.
create unique index if not exists copilot_llm_providers_one_active_idx
  on public.copilot_llm_providers (user_id)
  where is_active;

alter table public.copilot_llm_providers enable row level security;

-- Deliberately no policies: deny-by-default for every client role.
revoke all on public.copilot_llm_providers from anon, authenticated;
