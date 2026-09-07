/**
 * Demo / test account — a development identity that signs in WITHOUT Supabase.
 *
 * WHY THIS EXISTS
 * ---------------
 * When the tenant's Supabase project is restricted (quota, suspension, an
 * outage) the restriction applies to the WHOLE project API, not just GoTrue.
 * There is then no way to reach the product at all: sign-in fails, so every
 * dashboard behind `DashboardLayout` is unreachable, so the platform cannot be
 * demonstrated or tested. This module supplies an identity that lives entirely
 * in the application — no auth server, no billing row — and resolves to the
 * ELITE tier so every module route opens.
 *
 * SAFETY MODEL — read before changing anything here
 * -------------------------------------------------
 * 1. OFF BY DEFAULT. Nothing below activates unless `VITE_DEMO_ACCOUNT=true`
 *    (browser bundle) / `VITE_DEMO_ACCOUNT` or `DEMO_ACCOUNT` = 'true' (API
 *    server process). With the flag absent, `DEMO_ACCESS_TOKEN` is just an
 *    unrecognised string: `getServerUser` returns null and every gated route
 *    answers 401, exactly as it does today.
 * 2. NOT THE OWNER. `DEMO_ACCOUNT_EMAIL` is deliberately not the address in
 *    `src/lib/admin-access.ts`, so the Owner Administrator dashboard,
 *    `/api/v1/admin` and Revenue Intelligence stay closed to it. Elite is a
 *    subscription tier; owner is not, and this account only gets the tier.
 * 3. VISIBLE. `DemoModeBadge` renders while a demo session is live and the API
 *    server logs a warning at boot, so an enabled demo mode cannot be mistaken
 *    for a real session or shipped unnoticed.
 * 4. SINGLE OWNER. Every demo constant and predicate lives in this file. To
 *    remove the feature, delete this module and the call sites it is imported
 *    from (listed in `tasks/demo-account.md`).
 *
 * ISOMORPHIC: imported by the browser bundle AND by the Express API under tsx.
 * Keep it free of browser-only and Node-only APIs at module scope — every such
 * access below is feature-detected.
 */

import type { Session, User } from '@supabase/supabase-js'
import type { PlanTier } from './subscription-access'

/** Credentials typed into the normal login form (or filled by the demo button). */
export const DEMO_ACCOUNT_EMAIL = 'demo@qguard-helix.test'
export const DEMO_ACCOUNT_PASSWORD = 'QguardDemo!2026'

/** Stable synthetic user id. Never collides with a Supabase-issued uuid. */
export const DEMO_ACCOUNT_USER_ID = 'd3f0a1b2-c3d4-4e5f-8a9b-0c1d2e3f4a5b'

/** Tier the demo identity resolves to. Elite = every subscription-gated module. */
export const DEMO_ACCOUNT_TIER: PlanTier = 'elite'

export const DEMO_ACCOUNT_DISPLAY_NAME = 'Demo (Elite)'

/**
 * Bearer token the browser sends and the API recognises.
 *
 * Deliberately NOT JWT-shaped: `getServerUser`'s local verification path splits
 * on '.' and base64-decodes a payload, and a malformed JWT would be a slow,
 * noisy failure. A token that cannot be mistaken for a JWT is short-circuited
 * before any of that runs.
 */
export const DEMO_ACCESS_TOKEN = 'qguard-demo-session.v1.development-only'

/** localStorage key that keeps a demo sign-in alive across a page reload. */
export const DEMO_SESSION_STORAGE_KEY = 'qguard:demo-session'

/** Env var that enables the whole feature. */
export const DEMO_ENV_FLAG = 'VITE_DEMO_ACCOUNT'

/**
 * Read an env var from whichever environment we are in.
 *
 * Vite replaces `import.meta.env` with a real object in the browser bundle;
 * under Node/tsx `import.meta.env` is undefined, so the property read is
 * guarded and we fall through to `process.env`. Both lookups are wrapped
 * because either global can be absent depending on the bundle target.
 */
function readEnv(key: string): string | undefined {
  try {
    const metaEnv = (import.meta as unknown as { env?: Record<string, string | undefined> }).env
    const value = metaEnv?.[key]
    if (value != null) return value
  } catch {
    /* not a Vite/import.meta context */
  }
  try {
    if (typeof process !== 'undefined' && process.env && process.env[key] != null) {
      return process.env[key]
    }
  } catch {
    /* no process global (browser) */
  }
  return undefined
}

function isTrue(value: string | undefined): boolean {
  return String(value ?? '').trim().toLowerCase() === 'true'
}

/**
 * Is the demo account enabled in this process?
 *
 * Read on every call rather than cached at module load: under `tsx`/Vite the
 * module can be imported before `vite.config.ts` has copied the flag into
 * `process.env`, and a cached `false` would then be wrong for the life of the
 * server.
 */
export function isDemoModeEnabled(): boolean {
  return isTrue(readEnv(DEMO_ENV_FLAG)) || isTrue(readEnv('DEMO_ACCOUNT'))
}

export function isDemoEmail(email?: string | null): boolean {
  return String(email ?? '').trim().toLowerCase() === DEMO_ACCOUNT_EMAIL
}

export function isDemoUserId(userId?: string | null): boolean {
  return String(userId ?? '') === DEMO_ACCOUNT_USER_ID
}

/** Do these login-form values name the demo account? Flag-gated by the caller. */
export function isDemoCredential(email: string, password: string): boolean {
  return isDemoEmail(email) && password === DEMO_ACCOUNT_PASSWORD
}

/**
 * Is this the demo bearer token? Returns false unless demo mode is enabled, so
 * a stale token from a previous run cannot authenticate a normal deployment.
 */
export function isDemoToken(token?: string | null): boolean {
  if (!isDemoModeEnabled()) return false
  return token === DEMO_ACCESS_TOKEN
}

/** Supabase-shaped `User` for the demo identity. */
export function createDemoUser(): User {
  const now = new Date().toISOString()
  return {
    id: DEMO_ACCOUNT_USER_ID,
    aud: 'authenticated',
    role: 'authenticated',
    email: DEMO_ACCOUNT_EMAIL,
    email_confirmed_at: now,
    phone: '',
    confirmed_at: now,
    last_sign_in_at: now,
    app_metadata: { provider: 'demo', providers: ['demo'] },
    user_metadata: {
      full_name: DEMO_ACCOUNT_DISPLAY_NAME,
      demo_account: true,
      tier: DEMO_ACCOUNT_TIER,
    },
    identities: [],
    created_at: now,
    updated_at: now,
  } as unknown as User
}

/**
 * Supabase-shaped `Session`. `expires_at` is far future so nothing in the app
 * treats the session as expiring and tries to refresh it against the auth
 * server that is unavailable in the first place.
 */
export function createDemoSession(): Session {
  const expiresInSeconds = 60 * 60 * 24 * 365
  return {
    access_token: DEMO_ACCESS_TOKEN,
    refresh_token: DEMO_ACCESS_TOKEN + '.refresh',
    token_type: 'bearer',
    expires_in: expiresInSeconds,
    expires_at: Math.floor(Date.now() / 1000) + expiresInSeconds,
    user: createDemoUser(),
  } as unknown as Session
}

/** Entitlement the demo identity resolves to everywhere tiers are evaluated. */
export function demoEntitlement() {
  return {
    tier: DEMO_ACCOUNT_TIER,
    status: 'active',
    isActive: true,
    /* Elite is a PLAN. Owner is not a plan, and the demo account is not it. */
    isOwner: false,
  }
}

// --- Browser session persistence -----------------------------------------
// A demo sign-in must survive F5, but it must not survive a sign-out and it
// must be inert when the flag is off. Every access is feature-detected because
// this module is also imported server-side and localStorage can throw in
// strict browser privacy modes.

function storage(): Storage | null {
  try {
    return globalThis.localStorage ?? null
  } catch {
    return null
  }
}

export function markDemoSessionActive(): void {
  try {
    storage()?.setItem(DEMO_SESSION_STORAGE_KEY, DEMO_ACCOUNT_EMAIL)
  } catch {
    /* Storage unavailable — the session still works for this page load. */
  }
}

export function clearDemoSession(): void {
  try {
    storage()?.removeItem(DEMO_SESSION_STORAGE_KEY)
  } catch {
    /* nothing to clear */
  }
}

/** True when a demo sign-in is live in THIS browser and the flag is still on. */
export function isDemoSessionActive(): boolean {
  if (!isDemoModeEnabled()) return false
  try {
    return storage()?.getItem(DEMO_SESSION_STORAGE_KEY) === DEMO_ACCOUNT_EMAIL
  } catch {
    return false
  }
}
