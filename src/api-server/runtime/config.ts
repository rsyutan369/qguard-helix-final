/**
 * Production configuration preflight for the standalone API server.
 *
 * Only src/api-server/standalone.ts calls this, and only when
 * NODE_ENV=production. The Vite-mounted dev API never runs it, so local
 * development keeps working with a partial .env exactly as before.
 *
 * The goal is to fail safely and loudly at boot instead of degrading silently
 * at request time. Without it, a missing service-role key quietly falls back
 * to the anon key (supabase-server.ts primaryConfig), a missing APP_ORIGIN makes
 * PayPal return URLs fail closed, a missing QGUARD_CONTROL_PLANE_URL makes the
 * agent installer derive its phone-home URL from a Host header, and a leftover
 * dev flag (auto-confirm, shadow enforcement) weakens a production pod.
 *
 * Nothing here reads or prints secret VALUES — only whether names are set.
 */

import { readAgentEnvironment, validateControlPlane } from '@/lib/agent-installer/agent-environment'

export interface ConfigCheck {
  errors: string[]
  warnings: string[]
}

type Env = Record<string, string | undefined>

function isSet(env: Env, name: string): boolean {
  const value = env[name]
  return typeof value === 'string' && value.trim().length > 0
}

function firstSet(env: Env, names: string[]): string | null {
  for (const name of names) if (isSet(env, name)) return name
  return null
}

/**
 * Platform-wide repository credentials. The Dev scanner falls back to these
 * when a tenant supplies no token of its own (repo-providers.ts
 * resolveProviderToken), so on a multi-tenant API pod any tenant could read
 * every private repository the operator's token can see.
 */
export const PLATFORM_REPO_TOKEN_VARS = [
  'GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_ACCESS_TOKEN',
  'GITLAB_TOKEN', 'GITLAB_ACCESS_TOKEN', 'CI_JOB_TOKEN',
  'BITBUCKET_TOKEN', 'BITBUCKET_ACCESS_TOKEN', 'BITBUCKET_APP_PASSWORD',
  'AZURE_DEVOPS_TOKEN', 'AZURE_DEVOPS_PAT', 'SYSTEM_ACCESSTOKEN',
  'GITEA_TOKEN', 'FORGEJO_TOKEN',
] as const

/**
 * The dual-project fallback. When set in production it pins anonymous visitors
 * to a second Supabase project and splits tenant data across two databases.
 */
export const SUPABASE_FALLBACK_VARS = [
  'VITE_SUPABASE_FALLBACK_URL', 'VITE_SUPABASE_FALLBACK_ANON_KEY', 'SUPABASE_FALLBACK_SERVICE_ROLE_KEY',
  'NEXT_PUBLIC_SUPABASE_FALLBACK_URL', 'NEXT_PUBLIC_SUPABASE_FALLBACK_ANON_KEY',
] as const

export function checkProductionConfig(env: Env = process.env): ConfigCheck {
  const errors: string[] = []
  const warnings: string[] = []
  // Unsafe-but-present settings are errors unless the operator explicitly
  // accepts them. Missing REQUIRED settings are never overridable.
  const allowUnsafe = env.QGUARD_ALLOW_UNSAFE_CONFIG === 'true'
  const unsafe = (message: string) => (allowUnsafe ? warnings : errors).push(message)

  // --- Required -------------------------------------------------------------
  if (!firstSet(env, ['VITE_SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL'])) {
    errors.push('VITE_SUPABASE_URL is not set (Supabase project URL).')
  }
  if (!firstSet(env, ['VITE_SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY'])) {
    errors.push('VITE_SUPABASE_ANON_KEY is not set (Supabase anon/publishable key).')
  }
  if (!isSet(env, 'SUPABASE_SERVICE_ROLE_KEY')) {
    errors.push('SUPABASE_SERVICE_ROLE_KEY is not set. Without it every server-side write silently runs as anon and fails under RLS.')
  }
  if (!firstSet(env, ['APP_ORIGIN', 'PUBLIC_APP_ORIGIN'])) {
    errors.push('APP_ORIGIN is not set (public web origin, e.g. https://qguardhelix.com). PayPal return URLs fail closed and CORS has no allow-list without it.')
  }

  const agentEnvironment = readAgentEnvironment(env.QGUARD_ENVIRONMENT)
  const controlPlaneUrl = env.QGUARD_CONTROL_PLANE_URL || env.QGUARD_PUBLIC_API_URL || env.VITE_PUBLIC_APP_URL
  if (!controlPlaneUrl) {
    errors.push('QGUARD_CONTROL_PLANE_URL is not set (public HTTPS API origin baked into every agent installer, e.g. https://api.qguardhelix.com).')
  } else {
    const validation = validateControlPlane(controlPlaneUrl, agentEnvironment)
    for (const problem of validation.errors) errors.push(`QGUARD_CONTROL_PLANE_URL: ${problem}`)
  }
  if (agentEnvironment !== 'production') {
    warnings.push(`QGUARD_ENVIRONMENT is "${agentEnvironment}", not "production": agent control-plane validation is relaxed.`)
  }

  // --- Unsafe when present ----------------------------------------------------
  if (String(env.REGISTRATION_AUTO_CONFIRM || '').toLowerCase() === 'true') {
    unsafe('REGISTRATION_AUTO_CONFIRM=true creates pre-verified accounts without proving inbox ownership. Configure Supabase custom SMTP and leave it unset/false.')
  }
  const enforcement = String(env.SUBSCRIPTION_ENFORCEMENT || 'enforce').toLowerCase()
  if (enforcement !== 'enforce') {
    unsafe(`SUBSCRIPTION_ENFORCEMENT="${enforcement}" disables server-side plan enforcement.`)
  }
  const fallbackVars = SUPABASE_FALLBACK_VARS.filter((name) => isSet(env, name))
  if (fallbackVars.length || env.SUPABASE_USE_FALLBACK === 'true' || env.VITE_SUPABASE_USE_FALLBACK === 'true') {
    unsafe(`Supabase fallback-project settings are present (${[...fallbackVars, 'SUPABASE_USE_FALLBACK'].filter((name) => isSet(env, name)).join(', ')}). Production must run on a single project.`)
  }
  const repoTokens = PLATFORM_REPO_TOKEN_VARS.filter((name) => isSet(env, name))
  if (repoTokens.length) {
    unsafe(`Platform repository tokens are set (${repoTokens.join(', ')}). Tenants' Dev scans would inherit them. Remove them from the API pod.`)
  }

  // --- Advisory ---------------------------------------------------------------
  if (!firstSet(env, ['PUBLIC_APP_URL', 'VITE_PUBLIC_APP_URL'])) {
    warnings.push('PUBLIC_APP_URL is not set: admin password-recovery links fall back to the request Origin/Host header.')
  }
  if (!isSet(env, 'TRUSTED_CLIENT_IP_HEADER')) {
    warnings.push('TRUSTED_CLIENT_IP_HEADER is not set: behind Cloudflare/the load balancer, per-IP rate limits key on proxy addresses. Set it to cf-connecting-ip once the origin only accepts Cloudflare traffic.')
  }
  if (!firstSet(env, ['PAYPAL_CLIENT_ID'])) {
    warnings.push('PAYPAL_CLIENT_ID is not set: in-app subscription management actions will report billing as unavailable.')
  }
  if (env.QGUARD_ENABLE_CLOUD_SDK_PATCHES === 'true') {
    warnings.push('QGUARD_ENABLE_CLOUD_SDK_PATCHES=true acts with the pod\'s own ambient cloud credentials, not per-tenant ones.')
  }

  return { errors, warnings }
}
