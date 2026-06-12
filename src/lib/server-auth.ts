import { createClient } from '@supabase/supabase-js'

type HeaderLikeRequest = {
  headers: {
    get(name: string): string | null
  }
  nextUrl?: {
    searchParams: URLSearchParams
  }
  url?: string
}

type SupabaseSource = 'primary' | 'fallback'

interface ServerAuthConfig {
  source: SupabaseSource
  url: string
  serviceKey: string
}

function primaryConfig(): ServerAuthConfig {
  return {
    source: 'primary',
    url: process.env.VITE_SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '',
    serviceKey:
      process.env.SUPABASE_SERVICE_ROLE_KEY ||
      process.env.VITE_SUPABASE_ANON_KEY ||
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
      '',
  }
}

function fallbackConfig(): ServerAuthConfig {
  return {
    source: 'fallback',
    url: process.env.VITE_SUPABASE_FALLBACK_URL || process.env.NEXT_PUBLIC_SUPABASE_FALLBACK_URL || '',
    serviceKey:
      process.env.SUPABASE_FALLBACK_SERVICE_ROLE_KEY ||
      process.env.VITE_SUPABASE_FALLBACK_ANON_KEY ||
      process.env.NEXT_PUBLIC_SUPABASE_FALLBACK_ANON_KEY ||
      '',
  }
}

function hasConfig(config: ServerAuthConfig): boolean {
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

function tokenMatchesConfig(token: string, config: ServerAuthConfig): boolean {
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

function resolveConfig(token?: string | null): ServerAuthConfig {
  const primary = primaryConfig()
  const fallback = fallbackConfig()
  if (hasConfig(fallback) && (shouldForceFallback() || (token && tokenMatchesConfig(token, fallback)))) {
    return fallback
  }
  if (hasConfig(primary)) return primary
  if (hasConfig(fallback)) return fallback
  return primary
}

/**
 * Server-side helper to get the current user from a Supabase auth token.
 * Kept framework-agnostic so legacy route files do not force a Next.js dependency.
 */
export async function getServerUser(request: HeaderLikeRequest) {
  const token = getToken(request)
  return getServerUserFromToken(token)
}

export async function getServerUserFromToken(token: string | null) {
  if (!token) return null

  const config = resolveConfig(token)
  if (!hasConfig(config)) {
    return null
  }

  const client = createClient(config.url, config.serviceKey)
  const { data: { user }, error } = await client.auth.getUser(token)
  
  if (!error && user) {
    return user
  }

  const fallback = fallbackConfig()
  if (config.source !== 'fallback' && hasConfig(fallback)) {
    const fallbackClient = createClient(fallback.url, fallback.serviceKey)
    const fallbackResult = await fallbackClient.auth.getUser(token)
    return fallbackResult.error ? null : fallbackResult.data.user
  }

  return null
}

/**
 * Extracts the Bearer token from the Authorization header.
 */
export function getToken(request: HeaderLikeRequest) {
  const authHeader = request.headers.get('Authorization')
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }
  return null
}

export function getTokenFromHeaderOrQuery(request: HeaderLikeRequest) {
  const headerToken = getToken(request)
  if (headerToken) return headerToken
  const queryToken = request.nextUrl?.searchParams.get('token')
  if (queryToken) return queryToken
  if (request.url) {
    try {
      return new URL(request.url).searchParams.get('token')
    } catch {
      return null
    }
  }
  return null
}
