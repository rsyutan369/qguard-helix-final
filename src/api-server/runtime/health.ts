import { Router } from 'express'
import { supabaseTransportStats } from '@/lib/supabase-fetch'
import { buildInfo, isDraining, lifecycleSnapshot } from './lifecycle'

/**
 * Kubernetes / load-balancer probes.
 *
 * Mounted in createApiServer() AHEAD of the HTTPS-enforcement middleware: the
 * kubelet and the DO load balancer probe the pod over plain HTTP with no
 * X-Forwarded-Proto, and a 308 to https://<podIP> would fail every probe.
 *
 *   GET /api/v1/healthz  liveness  — the event loop answers. No dependencies,
 *                                    so a Supabase outage never restarts pods.
 *   GET /api/v1/readyz   readiness — 503 while draining (SIGTERM) or when the
 *                                    Supabase configuration is missing. A
 *                                    Supabase reachability probe is REPORTED;
 *                                    it only fails readiness when
 *                                    READINESS_REQUIRE_SUPABASE=true, so a
 *                                    platform blip cannot pull every pod out of
 *                                    the load balancer at once.
 *
 * The existing GET /api/v1/health is left untouched (the docs page reads it).
 * Everything reported here is measured; nothing is asserted as "operational".
 */

const PROBE_TTL_MS = 15_000
// Generous: a cold TLS handshake to Supabase can take >2 s from a congested
// network. readyz never waits this long — see READYZ_MAX_WAIT_MS.
const PROBE_TIMEOUT_MS = 5_000
// readyz answers within this budget (kubelet timeoutSeconds is 5): it waits for
// an in-flight probe only this long, otherwise reports the last known result
// while the refresh completes in the background.
const READYZ_MAX_WAIT_MS = 1_500

interface SupabaseProbe {
  reachable: boolean | null
  status: number | null
  latencyMs: number | null
  checkedAt: string | null
  error: string | null
}

let lastProbe: SupabaseProbe = { reachable: null, status: null, latencyMs: null, checkedAt: null, error: null }
let lastProbeAt = 0
let inflight: Promise<SupabaseProbe> | null = null

function supabaseSettings() {
  return {
    url: process.env.VITE_SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '',
    anonKey: process.env.VITE_SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '',
    hasServiceKey: Boolean(process.env.SUPABASE_SERVICE_ROLE_KEY),
  }
}

async function probeSupabase(): Promise<SupabaseProbe> {
  const { url, anonKey } = supabaseSettings()
  if (!url || !anonKey) {
    return { reachable: null, status: null, latencyMs: null, checkedAt: new Date().toISOString(), error: 'not configured' }
  }
  const started = Date.now()
  try {
    const response = await fetch(`${url.replace(/\/+$/, '')}/auth/v1/health`, {
      headers: { apikey: anonKey },
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    })
    return {
      reachable: response.ok,
      status: response.status,
      latencyMs: Date.now() - started,
      checkedAt: new Date().toISOString(),
      error: response.ok ? null : `HTTP ${response.status}`,
    }
  } catch (err) {
    return {
      reachable: false,
      status: null,
      latencyMs: Date.now() - started,
      checkedAt: new Date().toISOString(),
      error: err instanceof Error ? err.name : 'probe failed',
    }
  }
}

function cachedSupabaseProbe(): Promise<SupabaseProbe> {
  if (Date.now() - lastProbeAt < PROBE_TTL_MS) return Promise.resolve(lastProbe)
  if (!inflight) {
    inflight = probeSupabase()
      .then((result) => {
        lastProbe = result
        lastProbeAt = Date.now()
        return result
      })
      .finally(() => {
        inflight = null
      })
  }
  return inflight
}

export const healthProbeRoutes = Router()

healthProbeRoutes.get('/api/v1/healthz', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  res.json({ status: 'ok', ...lifecycleSnapshot() })
})

healthProbeRoutes.get('/api/v1/readyz', async (_req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  const lifecycle = lifecycleSnapshot()
  // Runtime versions (node/openssl) stay in the startup log only — this route
  // is reachable through the public load balancer.
  const { version, commit, environment } = buildInfo()
  const build = { version, commit, environment }

  if (isDraining()) {
    res.status(503).json({ status: 'draining', ...lifecycle, build })
    return
  }

  const settings = supabaseSettings()
  const configured = Boolean(settings.url && settings.anonKey && settings.hasServiceKey)
  const supabase = await Promise.race([
    cachedSupabaseProbe(),
    new Promise<SupabaseProbe>((resolve) => setTimeout(() => resolve(lastProbe), READYZ_MAX_WAIT_MS).unref()),
  ])
  const requireSupabase = process.env.READINESS_REQUIRE_SUPABASE === 'true'

  let status: 'ready' | 'degraded' | 'misconfigured' = 'ready'
  if (!configured) status = 'misconfigured'
  else if (supabase.reachable === false) status = 'degraded'

  const httpStatus = status === 'misconfigured' || (status === 'degraded' && requireSupabase) ? 503 : 200
  res.status(httpStatus).json({
    status,
    ...lifecycle,
    build,
    checks: {
      supabaseConfigured: configured,
      supabase,
      supabaseTransport: supabaseTransportStats(),
    },
  })
})
