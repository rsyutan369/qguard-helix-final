import { createClient, SupabaseClient } from '@supabase/supabase-js'
import type { Request } from 'express'

type SupabaseSource = 'primary' | 'fallback'

interface ServerSupabaseConfig {
  source: SupabaseSource
  url: string
  anonKey: string
  serviceKey: string
}

function primaryConfig(): ServerSupabaseConfig {
  return {
    source: 'primary',
    url: process.env.VITE_SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '',
    anonKey: process.env.VITE_SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '',
    serviceKey:
      process.env.SUPABASE_SERVICE_ROLE_KEY ||
      process.env.VITE_SUPABASE_ANON_KEY ||
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
      '',
  }
}

function fallbackConfig(): ServerSupabaseConfig {
  return {
    source: 'fallback',
    url: process.env.VITE_SUPABASE_FALLBACK_URL || process.env.NEXT_PUBLIC_SUPABASE_FALLBACK_URL || '',
    anonKey: process.env.VITE_SUPABASE_FALLBACK_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_FALLBACK_ANON_KEY || '',
    serviceKey:
      process.env.SUPABASE_FALLBACK_SERVICE_ROLE_KEY ||
      process.env.VITE_SUPABASE_FALLBACK_ANON_KEY ||
      process.env.NEXT_PUBLIC_SUPABASE_FALLBACK_ANON_KEY ||
      '',
  }
}

function hasAuthConfig(config: ServerSupabaseConfig): boolean {
  return Boolean(config.url && config.anonKey)
}

function hasServiceConfig(config: ServerSupabaseConfig): boolean {
  return Boolean(config.url && config.serviceKey)
}

function shouldForceFallback(): boolean {
  return process.env.SUPABASE_USE_FALLBACK === 'true' || process.env.VITE_SUPABASE_USE_FALLBACK === 'true'
}

function jwtPayload(token: string): Record<string, unknown> | null {
  try {
    const [, payload] = token.split('.')
    if (!payload) return null
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/')
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8')) as Record<string, unknown>
  } catch {
    return null
  }
}

function tokenMatchesConfig(token: string, config: ServerSupabaseConfig): boolean {
  if (!config.url) return false
  const payload = jwtPayload(token)
  const issuer = typeof payload?.iss === 'string' ? payload.iss : ''
  const ref = typeof payload?.ref === 'string' ? payload.ref : ''
  try {
    const host = new URL(config.url).host
    return issuer.includes(host) || (!!ref && host.startsWith(`${ref}.`))
  } catch {
    return false
  }
}

function resolveAuthConfig(token?: string | null): ServerSupabaseConfig {
  const primary = primaryConfig()
  const fallback = fallbackConfig()
  if (hasAuthConfig(fallback) && (shouldForceFallback() || (token && tokenMatchesConfig(token, fallback)))) {
    return fallback
  }
  if (hasAuthConfig(primary)) return primary
  if (hasAuthConfig(fallback)) return fallback
  return primary
}

function resolveServiceConfig(): ServerSupabaseConfig {
  const primary = primaryConfig()
  const fallback = fallbackConfig()
  if (hasServiceConfig(fallback) && shouldForceFallback()) return fallback
  if (hasServiceConfig(primary)) return primary
  if (hasServiceConfig(fallback)) return fallback
  return primary
}

function createAuthClientForConfig(token: string, config: ServerSupabaseConfig): SupabaseClient {
  return createClient(config.url, config.anonKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
    global: {
      headers: { Authorization: `Bearer ${token}` }
    }
  })
}

/**
 * Create a Supabase client with service role key for server-side operations.
 * Bypasses RLS. Use only for authenticated user data when combined with explicit user_id filters.
 */
export function getServiceClient(): SupabaseClient | null {
  const config = resolveServiceConfig()
  if (!hasServiceConfig(config)) {
    console.warn('Supabase service client: missing URL or service key')
    return null
  }
  return createClient(config.url, config.serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  })
}

/**
 * Create a Supabase client authenticated with the user's JWT token.
 * Respects RLS policies.
 */
export function createAuthClient(token: string): SupabaseClient | null {
  const config = resolveAuthConfig(token)
  if (!hasAuthConfig(config)) {
    console.warn('Supabase auth client: missing URL or anon key')
    return null
  }
  return createAuthClientForConfig(token, config)
}

/**
 * Extract Bearer token from Express request headers.
 */
export function getToken(req: Request): string | null {
  const authHeader = req.headers.authorization
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }
  return null
}

/**
 * Validate a Supabase JWT token and return the user.
 */
export async function getServerUser(token: string) {
  const config = resolveAuthConfig(token)
  const client = hasAuthConfig(config) ? createAuthClientForConfig(token, config) : null
  if (!client) return null

  const { data: { user }, error } = await client.auth.getUser(token)
  if (!error && user) return user

  const fallback = fallbackConfig()
  if (config.source !== 'fallback' && hasAuthConfig(fallback)) {
    const fallbackClient = createAuthClientForConfig(token, fallback)
    const fallbackResult = await fallbackClient.auth.getUser(token)
    return fallbackResult.error ? null : fallbackResult.data.user
  }

  return null
}
