// Render stand-in: every call is inert (only effects reach it, and SSR runs none).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const inert: any = new Proxy(function () {}, { get: () => inert, apply: () => inert })
export const supabase = inert
export const getSupabaseClient = () => inert
export const getActiveSupabaseSource = () => 'primary'
export const canUseFallbackSupabase = () => false
export const switchToFallbackSupabase = () => null
