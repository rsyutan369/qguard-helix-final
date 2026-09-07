import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { createDemoSession, createDemoUser, isDemoSessionActive } from './demo-account';

type SupabaseSource = 'primary' | 'fallback'

interface BrowserSupabaseConfig {
  source: SupabaseSource
  url: string
  anonKey: string
}

const FALLBACK_SELECTION_KEY = 'qguard:supabase-source'
const primaryConfig: BrowserSupabaseConfig = {
  source: 'primary',
  url: import.meta.env.VITE_SUPABASE_URL || '',
  anonKey: import.meta.env.VITE_SUPABASE_ANON_KEY || '',
}
const fallbackConfig: BrowserSupabaseConfig = {
  source: 'fallback',
  url: import.meta.env.VITE_SUPABASE_FALLBACK_URL || '',
  anonKey: import.meta.env.VITE_SUPABASE_FALLBACK_ANON_KEY || '',
}

function hasConfig(config: BrowserSupabaseConfig): boolean {
  return Boolean(config.url && config.anonKey)
}

function shouldForceFallback(): boolean {
  return import.meta.env.VITE_SUPABASE_USE_FALLBACK === 'true'
}

function storedFallbackSelected(): boolean {
  try {
    return globalThis.localStorage?.getItem(FALLBACK_SELECTION_KEY) === 'fallback'
  } catch {
    return false
  }
}

function rememberFallbackSelection(): void {
  try {
    globalThis.localStorage?.setItem(FALLBACK_SELECTION_KEY, 'fallback')
  } catch {
    // Storage can be unavailable in strict browser privacy modes.
  }
}

function resolveInitialConfig(): BrowserSupabaseConfig {
  if (hasConfig(fallbackConfig) && (shouldForceFallback() || storedFallbackSelected())) {
    return fallbackConfig
  }
  if (hasConfig(primaryConfig)) return primaryConfig
  if (hasConfig(fallbackConfig)) return fallbackConfig
  return primaryConfig
}

function createSupabaseClient(config: BrowserSupabaseConfig): SupabaseClient {
  return createClient(config.url || 'https://example.invalid', config.anonKey || 'missing-anon-key')
}

let activeConfig = resolveInitialConfig()
let activeClient = createSupabaseClient(activeConfig)

export function getActiveSupabaseSource(): SupabaseSource {
  return activeConfig.source
}

export function canUseFallbackSupabase(): boolean {
  return activeConfig.source !== 'fallback' && hasConfig(fallbackConfig)
}

export function switchToFallbackSupabase(): SupabaseClient | null {
  if (!hasConfig(fallbackConfig)) return null
  activeConfig = fallbackConfig
  activeClient = createSupabaseClient(fallbackConfig)
  rememberFallbackSelection()
  return activeClient
}

export function getSupabaseClient(): SupabaseClient {
  return activeClient
}

type SupabaseAuth = SupabaseClient['auth']

/**
 * Demo-session overlay on `.auth` — see src/lib/demo-account.ts.
 *
 * Nine files ask the client directly for the current session/user
 * (`supabase.auth.getSession()`) instead of reading `useAuth()`, and each one
 * uses the answer to attach the Bearer token to an API call or to decide
 * whether the caller is signed in. Under a demo session those calls would hit
 * the unreachable Supabase project, get nothing back, and render the feature as
 * signed-out — so the identity is answered here, once, rather than in nine
 * places that would drift apart.
 *
 * ONLY the identity reads are overridden. `.from()`, `.channel()`, `.storage`
 * and every auth mutation still go to the real client, so nothing silently
 * pretends a write succeeded.
 */
function demoAuthOverlay(realAuth: SupabaseAuth): SupabaseAuth {
  return new Proxy(realAuth as unknown as object, {
    get(target, prop) {
      if (prop === 'getSession') {
        return async () => ({ data: { session: createDemoSession() }, error: null })
      }
      if (prop === 'getUser') {
        return async () => ({ data: { user: createDemoUser() }, error: null })
      }
      const value = Reflect.get(target, prop)
      // Bound to the REAL auth client: GoTrueClient methods read private
      // fields, which a proxy receiver cannot satisfy.
      return typeof value === 'function' ? value.bind(target) : value
    },
  }) as unknown as SupabaseAuth
}

export const supabase = new Proxy({} as SupabaseClient, {
  get(_target, prop) {
    if (prop === 'auth' && isDemoSessionActive()) {
      return demoAuthOverlay(activeClient.auth)
    }
    const value = (activeClient as unknown as Record<PropertyKey, unknown>)[prop]
    return typeof value === 'function' ? value.bind(activeClient) : value
  },
})
