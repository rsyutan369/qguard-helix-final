import { createClient, type SupabaseClient } from '@supabase/supabase-js';

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

export const supabase = new Proxy({} as SupabaseClient, {
  get(_target, prop) {
    const value = (activeClient as unknown as Record<PropertyKey, unknown>)[prop]
    return typeof value === 'function' ? value.bind(activeClient) : value
  },
})
