/**
 * Where the browser sends billing requests.
 *
 * The public site is a static build: it serves no /api/v1 routes, so a
 * relative `/api/v1/paypal/subscribe` answers 405 in production and checkout
 * never reaches PayPal. Billing runs as the `billing` Edge Function on the
 * Supabase project the app already talks to (supabase/functions/billing),
 * which serves the same `/api/v1/...` paths as the Express router — so the
 * choice here is only an origin.
 *
 * VITE_BILLING_API_ORIGIN overrides the derived origin (e.g. a self-hosted
 * Express API); that host then also needs a CSP connect-src entry. With neither
 * variable set, requests stay same-origin. Mirrors
 * qguard-messaging/src/lib/billing-api.ts.
 */

type EnvLike = Partial<Record<string, string | undefined>>

/**
 * Each variable is read individually on purpose: Vite replaces
 * `import.meta.env.X` with that one value, but an `import.meta.env` used as an
 * object is inlined WHOLE — every exposed variable copied into this chunk.
 */
function buildEnv(): EnvLike {
  return {
    VITE_BILLING_API_ORIGIN: import.meta.env.VITE_BILLING_API_ORIGIN as string | undefined,
    VITE_SUPABASE_URL: import.meta.env.VITE_SUPABASE_URL as string | undefined,
  }
}

export function billingApiOrigin(env: EnvLike = buildEnv()): string {
  const configured = env.VITE_BILLING_API_ORIGIN?.trim()
  if (configured) return configured.replace(/\/+$/, '')
  const supabase = (env.VITE_SUPABASE_URL || '').trim().replace(/\/+$/, '')
  return supabase ? `${supabase}/functions/v1/billing` : ''
}

/** Absolute URL for a billing route such as `/api/v1/paypal/subscribe`. */
export function billingApiUrl(path: string, env?: EnvLike): string {
  const origin = billingApiOrigin(env)
  return origin ? `${origin}${path}` : path
}
