import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { clearAuthReturnUrl } from './oauth-callback'

type SupabaseSource = 'primary' | 'fallback'

interface BrowserSupabaseConfig {
  source: SupabaseSource
  url: string
  anonKey: string
}

const FALLBACK_SELECTION_KEY = 'qguard:supabase-source'
const OAUTH_SOURCE_KEY = 'qguard:google-oauth-source'
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
  if (typeof window !== 'undefined' && window.location.pathname === '/auth/callback') {
    try {
      const pendingSource = sessionStorage.getItem(OAUTH_SOURCE_KEY)
      if (pendingSource === 'primary' && hasConfig(primaryConfig)) return primaryConfig
      if (pendingSource === 'fallback' && hasConfig(fallbackConfig)) return fallbackConfig
    } catch {
      // The callback page reports a storage error without consuming the code.
    }
  }
  if (hasConfig(fallbackConfig) && (shouldForceFallback() || storedFallbackSelected())) {
    return fallbackConfig
  }
  if (hasConfig(primaryConfig)) return primaryConfig
  if (hasConfig(fallbackConfig)) return fallbackConfig
  return primaryConfig
}

function createSupabaseClient(config: BrowserSupabaseConfig): SupabaseClient {
  const client = createClient(config.url || 'https://example.invalid', config.anonKey || 'missing-anon-key')
  // Let the SDK consume legacy email/recovery fragments before removing them,
  // including when verification fails.
  const cleanLegacyUrl = () => clearAuthReturnUrl({ legacyOnly: true })
  void client.auth.initialize().then(cleanLegacyUrl).catch(cleanLegacyUrl)
  return client
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

const oauthClients = new Map<SupabaseSource, SupabaseClient>()

function googleOAuthClient(config: BrowserSupabaseConfig): SupabaseClient {
  let client = oauthClients.get(config.source)
  if (client) return client
  const verifierKey = `qguard:google-oauth:${config.source}-code-verifier`
  client = createClient(config.url, config.anonKey, {
    auth: {
      flowType: 'pkce',
      detectSessionInUrl: false,
      autoRefreshToken: false,
      persistSession: true,
      storageKey: `qguard:google-oauth:${config.source}`,
      // Only the one-time PKCE verifier survives navigation. The session
      // returned by exchangeCodeForSession moves directly into the main client.
      storage: {
        getItem: (key) => key === verifierKey ? sessionStorage.getItem(key) : null,
        setItem: (key, value) => {
          if (key === verifierKey) sessionStorage.setItem(key, value)
        },
        removeItem: (key) => {
          if (key === verifierKey) sessionStorage.removeItem(key)
        },
      },
    },
  })
  oauthClients.set(config.source, client)
  return client
}

export async function beginGoogleOAuth(redirectTo: string) {
  if (!globalThis.crypto?.subtle) throw new Error('Google sign-in requires HTTPS or a secure localhost browser.')
  // Failing here gives a recoverable error when browser storage is disabled,
  // before navigating away with an unusable PKCE flow.
  sessionStorage.setItem(OAUTH_SOURCE_KEY, activeConfig.source)
  return googleOAuthClient(activeConfig).auth.signInWithOAuth({
    provider: 'google',
    options: { redirectTo, skipBrowserRedirect: true },
  })
}

export async function finishGoogleOAuth(code: string) {
  const source = sessionStorage.getItem(OAUTH_SOURCE_KEY)
  const config = source === 'primary' ? primaryConfig : source === 'fallback' ? fallbackConfig : null
  if (!config || !hasConfig(config)) throw new Error('Start Google sign-in again in this browser tab.')
  try {
    const result = await googleOAuthClient(config).auth.exchangeCodeForSession(code)
    if (result.error) throw result.error
    if (!result.data.session) throw new Error('Google sign-in did not return a session.')
    if (activeConfig.source !== config.source) {
      activeConfig = config
      activeClient = createSupabaseClient(config)
      if (config.source === 'fallback') rememberFallbackSelection()
    }
    const { access_token, refresh_token } = result.data.session
    return await activeClient.auth.setSession({ access_token, refresh_token })
  } finally {
    sessionStorage.removeItem(OAUTH_SOURCE_KEY)
    sessionStorage.removeItem(`qguard:google-oauth:${config.source}-code-verifier`)
  }
}

const confirmationClients = new Map<SupabaseSource, SupabaseClient>()

/** Verify signup without replacing an existing browser session. */
export async function confirmSignupEmail(tokenHash: string, source: SupabaseSource): Promise<boolean> {
  const config = source === 'primary' ? primaryConfig : fallbackConfig
  if (!hasConfig(config)) return false

  let client = confirmationClients.get(source)
  if (!client) {
    client = createClient(config.url, config.anonKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
        storageKey: `qguard:signup-confirmation:${source}`,
      },
    })
    confirmationClients.set(source, client)
  }
  const { error } = await client.auth.verifyOtp({ token_hash: tokenHash, type: 'signup' })
  return !error
}

export const supabase = new Proxy({} as SupabaseClient, {
  get(_target, prop) {
    const value = (activeClient as unknown as Record<PropertyKey, unknown>)[prop]
    return typeof value === 'function' ? value.bind(activeClient) : value
  },
})
