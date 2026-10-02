/**
 * Pure URL logic behind src/lib/api-origin.ts, kept free of `window` and
 * `import.meta.env` so it can be verified in Node (tools/api-origin-check.ts).
 */

/** Normalise a configured API origin; null when unset or not http(s). */
export function normaliseApiOrigin(value: string | null | undefined): string | null {
  const raw = String(value ?? '').trim()
  if (!raw) return null
  try {
    const url = new URL(raw)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
    return url.origin
  } catch {
    return null
  }
}

/**
 * Rewrite a same-origin `/api/...` URL to the configured API origin. Anything
 * else — Supabase, fonts, other hosts, non-API paths — is returned unchanged,
 * as is every URL when no API origin is configured.
 */
export function resolveApiUrl(input: string, apiOrigin: string | null, pageHref: string): string {
  if (!apiOrigin) return input
  let url: URL
  try {
    url = new URL(input, pageHref)
  } catch {
    return input
  }
  const pageOrigin = new URL(pageHref).origin
  if (url.origin !== pageOrigin) return input
  if (!url.pathname.startsWith('/api/')) return input
  return `${apiOrigin}${url.pathname}${url.search}${url.hash}`
}
