/**
 * Split-origin API routing (optional).
 *
 * The SPA addresses the API with relative `/api/v1/...` URLs from ~160 fetch
 * call sites and ~35 EventSource streams. When the SPA is served by Vercel and
 * the API runs on Kubernetes at a separate origin (e.g. https://api.qguardhelix.com),
 * setting VITE_API_ORIGIN at build time routes those same-origin `/api/` calls
 * to the API origin — without touching any call site.
 *
 * Unset (local `npm run dev`, or a deployment that proxies /api on the same
 * origin), this module does nothing at all.
 *
 * Scope is deliberately narrow: only same-origin URLs whose path starts with
 * `/api/` are rewritten; credentials are never added (the API authenticates
 * with Bearer headers / `?token=` on streams, not cookies). The build-time CSP
 * adds VITE_API_ORIGIN to connect-src (vite.config.ts), and the API allows the
 * SPA origin through ALLOWED_ORIGINS.
 *
 * MUST be imported by src/main.tsx before App, so it is in place before any
 * module issues a request.
 */
import { normaliseApiOrigin, resolveApiUrl } from './api-origin-core'

export const API_ORIGIN = normaliseApiOrigin(import.meta.env.VITE_API_ORIGIN as string | undefined)

function install(apiOrigin: string) {
  const scope = window as Window & { __qguardApiOriginInstalled?: boolean }
  if (scope.__qguardApiOriginInstalled) return
  if (apiOrigin === window.location.origin) return
  scope.__qguardApiOriginInstalled = true

  const rewrite = (input: string) => resolveApiUrl(input, apiOrigin, window.location.href)

  const nativeFetch = window.fetch.bind(window)
  window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    try {
      if (typeof input === 'string') return nativeFetch(rewrite(input), init)
      if (input instanceof URL) {
        const next = rewrite(input.href)
        return nativeFetch(next === input.href ? input : next, init)
      }
      if (input instanceof Request) {
        const next = rewrite(input.url)
        if (next !== input.url) return nativeFetch(new Request(next, input), init)
      }
    } catch {
      // Never let routing break a request: fall through to the original input.
    }
    return nativeFetch(input, init)
  }) as typeof window.fetch

  const NativeEventSource = window.EventSource
  if (typeof NativeEventSource === 'function') {
    class ApiOriginEventSource extends NativeEventSource {
      constructor(url: string | URL, init?: EventSourceInit) {
        super(rewrite(typeof url === 'string' ? url : url.href), init)
      }
    }
    window.EventSource = ApiOriginEventSource as typeof EventSource
  }
}

if (API_ORIGIN && typeof window !== 'undefined') install(API_ORIGIN)
