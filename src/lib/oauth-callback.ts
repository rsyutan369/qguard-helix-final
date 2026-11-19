export const GOOGLE_CALLBACK_PATH = '/auth/callback'

/** Remove authentication credentials while preserving unrelated navigation state. */
export function cleanAuthReturnUrl(href: string): string {
  const url = new URL(href)
  if (url.pathname === GOOGLE_CALLBACK_PATH) {
    for (const key of ['code', 'state', 'error', 'error_code', 'error_description']) {
      url.searchParams.delete(key)
    }
  }
  const hash = new URLSearchParams(url.hash.slice(1))
  if (hash.has('access_token') || hash.has('refresh_token')) {
    for (const key of ['access_token', 'refresh_token', 'provider_token', 'provider_refresh_token', 'expires_at', 'expires_in', 'token_type', 'type', 'sb']) {
      hash.delete(key)
    }
    url.hash = hash.toString()
  }
  return url.pathname + url.search + url.hash
}

export function clearAuthReturnUrl({ legacyOnly = false } = {}) {
  if (typeof window === 'undefined') return
  const hash = new URLSearchParams(window.location.hash.slice(1))
  if (legacyOnly && !hash.has('access_token') && !hash.has('refresh_token')) return
  const next = cleanAuthReturnUrl(window.location.href)
  const current = window.location.pathname + window.location.search + window.location.hash
  if (next !== current) window.history.replaceState(window.history.state, '', next)
}
