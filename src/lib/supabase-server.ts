import { createClient, SupabaseClient, User } from '@supabase/supabase-js'
import type { Request } from 'express'
import { supabaseFetch } from './supabase-fetch'

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
      headers: { Authorization: `Bearer ${token}` },
      // Bounded + retrying transport. Without it a dashboard's 12-54 query
      // fan-out opens that many simultaneous TLS handshakes and undici's 10s
      // connect timeout blanks the page. See lib/supabase-fetch.ts.
      fetch: supabaseFetch,
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
    auth: { autoRefreshToken: false, persistSession: false },
    global: { fetch: supabaseFetch },
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

// --- Token verification (fast path) --------------------------------------
//
// PERFORMANCE: the previous implementation called `auth.getUser(token)` — a
// network round-trip to Supabase's GoTrue auth server — on EVERY authenticated
// API request, and created a throwaway client each time. A single dashboard
// load fires 12+ concurrent authenticated requests (fetches + SSE streams);
// gated ones validate twice (gateway + route). That burst of GoTrue calls was
// both the page-load latency AND the source of intermittent 401s (GoTrue
// rate-limits/transient-fails the burst → getServerUser returned null → 401).
//
// Supabase now signs access tokens with an ASYMMETRIC key (ES256), so a token
// can be verified LOCALLY against the project's published JWKS — no network
// round-trip. `auth.getClaims(token)` does exactly this (verifies the ES256
// signature with WebCrypto after a one-time, per-client-instance JWKS fetch;
// it transparently falls back to a network getUser only for legacy symmetric
// tokens or when WebCrypto is unavailable). To keep the JWKS cache warm, the
// verifying clients are REUSED across requests (module singletons) instead of
// recreated per call. A short-TTL positive cache + single-flight dedup then
// collapse the concurrent burst into a single verification per token.

// Reused verifying clients (no per-request Authorization header — the token is
// passed explicitly to getClaims/getUser). Keyed by config identity so the
// getClaims JWKS cache persists across requests.
const verifyClients = new Map<string, SupabaseClient>()

function verifyClientFor(config: ServerSupabaseConfig): SupabaseClient | null {
  if (!hasAuthConfig(config)) return null
  const key = `${config.url}::${config.anonKey.slice(0, 16)}`
  let client = verifyClients.get(key)
  if (!client) {
    client = createClient(config.url, config.anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
      global: { fetch: supabaseFetch },
    })
    verifyClients.set(key, client)
  }
  return client
}

// Build a User-shaped object from verified JWT claims. Covers every field the
// API routes read off the auth user (id, email, role, phone, app/user
// metadata). Fields NOT present in the JWT (created_at, last_sign_in_at) are
// only consumed by low-traffic profile/billing routes, which opt into the
// full-fidelity network path via getServerUser(token, { full: true }).
function claimsToUser(claims: Record<string, unknown>): User {
  const obj = (k: string) =>
    (claims[k] && typeof claims[k] === 'object' ? claims[k] : {}) as Record<string, unknown>
  return {
    id: String(claims.sub ?? ''),
    aud: (claims.aud as string) ?? 'authenticated',
    role: (claims.role as string) ?? 'authenticated',
    email: typeof claims.email === 'string' ? claims.email : undefined,
    phone: typeof claims.phone === 'string' ? claims.phone : undefined,
    app_metadata: obj('app_metadata'),
    user_metadata: obj('user_metadata'),
    created_at: '',
  } as unknown as User
}

async function verifyWithClient(client: SupabaseClient, token: string): Promise<User | null> {
  try {
    const { data, error } = await client.auth.getClaims(token)
    const claims = data?.claims as Record<string, unknown> | undefined
    if (!error && claims?.sub) return claimsToUser(claims)
  } catch {
    // Invalid signature / JWKS lookup miss (e.g. token belongs to the other
    // project) → let the caller try the fallback config, then 401.
  }
  return null
}

async function verifyTokenLocal(token: string): Promise<User | null> {
  const primary = resolveAuthConfig(token)
  const primaryClient = verifyClientFor(primary)
  if (primaryClient) {
    const user = await verifyWithClient(primaryClient, token)
    if (user) return user
  }
  // Dual-project fallback: the token may have been issued by the fallback
  // Supabase project (verify against its JWKS).
  const fallback = fallbackConfig()
  if (primary.source !== 'fallback' && hasAuthConfig(fallback)) {
    const fallbackClient = verifyClientFor(fallback)
    if (fallbackClient) {
      const user = await verifyWithClient(fallbackClient, token)
      if (user) return user
    }
  }
  return null
}

// Full-fidelity path: fetch the complete user record from the auth server.
// Used only where JWT claims are insufficient (created_at / last_sign_in_at).
async function fetchServerUserFromNetwork(token: string): Promise<User | null> {
  const config = resolveAuthConfig(token)
  const client = verifyClientFor(config)
  if (!client) return null

  const { data: { user }, error } = await client.auth.getUser(token)
  if (!error && user) return user

  const fallback = fallbackConfig()
  if (config.source !== 'fallback' && hasAuthConfig(fallback)) {
    const fallbackClient = verifyClientFor(fallback)
    if (fallbackClient) {
      const fallbackResult = await fallbackClient.auth.getUser(token)
      return fallbackResult.error ? null : fallbackResult.data.user
    }
  }
  return null
}

interface CachedVerification {
  user: User
  verifiedAt: number
  expMs: number
}

// Re-verify at most every VERIFICATION_TTL_MS per token, and never serve past
// the token's own exp. Bounds staleness after a sign-out/revocation to <=TTL
// (the same trade-off any local JWT verification makes for short-lived tokens).
const VERIFICATION_TTL_MS = 60_000
const verificationCache = new Map<string, CachedVerification>()
const inflightVerifications = new Map<string, Promise<User | null>>()

function pruneVerificationCache(now: number) {
  if (verificationCache.size <= 1000) return
  for (const [token, entry] of verificationCache) {
    if (now >= entry.expMs || now - entry.verifiedAt >= VERIFICATION_TTL_MS) {
      verificationCache.delete(token)
    }
  }
}

// --- Admin token revocation ---------------------------------------------
//
// Access tokens are verified LOCALLY (above), so ending a user's Supabase Auth
// sessions (Owner Admin "Sign out everywhere" / suspend / disable) only stops
// NEW access tokens being minted — one already issued would keep working until
// its exp (default 1h). The admin API records the revocation instant here and
// every verification rejects that user's tokens issued (iat) before it. The
// map is hydrated from public.admin_session_revocations on first use, so a
// server restart does not reopen the window. Entries outlive any access token.
const TOKEN_REVOCATION_TTL_MS = 24 * 60 * 60_000
const tokenRevocations = new Map<string, number>()
let tokenRevocationsHydrated = false

export function revokeUserTokensIssuedBefore(userId: string, revokedAtMs = Date.now()) {
  if (!userId) return
  const current = tokenRevocations.get(userId) || 0
  if (revokedAtMs > current) tokenRevocations.set(userId, revokedAtMs)
}

function isTokenRevoked(userId: string, token: string): boolean {
  const revokedAt = tokenRevocations.get(userId)
  if (!revokedAt) return false
  if (Date.now() - revokedAt > TOKEN_REVOCATION_TTL_MS) {
    tokenRevocations.delete(userId)
    return false
  }
  const iat = jwtPayload(token)?.iat
  // A Supabase access token always carries iat; one without it is not trusted.
  return typeof iat !== 'number' || iat * 1000 < revokedAt
}

async function hydrateTokenRevocations() {
  const db = getServiceClient()
  if (!db) return
  try {
    const since = new Date(Date.now() - TOKEN_REVOCATION_TTL_MS).toISOString()
    const { data, error } = await db
      .from('admin_session_revocations')
      .select('user_id,created_at')
      .gte('created_at', since)
      .order('created_at', { ascending: false })
      .limit(1000)
    if (error) {
      console.error('[auth] token revocations not hydrated:', error.message)
      return
    }
    for (const row of data || []) {
      const at = Date.parse(String(row.created_at))
      if (row.user_id && Number.isFinite(at)) revokeUserTokensIssuedBefore(String(row.user_id), at)
    }
  } catch (err) {
    console.error('[auth] token revocations not hydrated:', err instanceof Error ? err.message : err)
  }
}

/**
 * Validate a Supabase JWT token and return the user.
 *
 * Fast path (default): verifies the token's ES256 signature LOCALLY against the
 * cached project JWKS — no network round-trip — with a short-TTL result cache
 * and single-flight dedup so a burst of concurrent requests validates once.
 * Tokens issued before an admin revocation of the user are rejected.
 *
 * @param options.full  Skip the cache/local path and fetch the complete user
 *   record from the auth server (needed only for created_at / last_sign_in_at).
 */
export async function getServerUser(token: string, options?: { full?: boolean }): Promise<User | null> {
  if (!token) return null
  if (!tokenRevocationsHydrated) {
    tokenRevocationsHydrated = true
    void hydrateTokenRevocations()
  }
  const user = await verifyServerUser(token, options)
  return user && isTokenRevoked(user.id, token) ? null : user
}

async function verifyServerUser(token: string, options?: { full?: boolean }): Promise<User | null> {
  if (options?.full) {
    return fetchServerUserFromNetwork(token)
  }

  const now = Date.now()
  const cached = verificationCache.get(token)
  if (cached && now < cached.expMs && now - cached.verifiedAt < VERIFICATION_TTL_MS) {
    return cached.user
  }

  const existing = inflightVerifications.get(token)
  if (existing) return existing

  const promise = (async () => {
    try {
      const user = await verifyTokenLocal(token)
      if (user) {
        const payload = jwtPayload(token)
        const expSec = typeof payload?.exp === 'number' ? payload.exp : 0
        const expMs = expSec ? expSec * 1000 : now + VERIFICATION_TTL_MS
        verificationCache.set(token, { user, verifiedAt: now, expMs })
        pruneVerificationCache(now)
      }
      return user
    } finally {
      inflightVerifications.delete(token)
    }
  })()
  inflightVerifications.set(token, promise)
  return promise
}
