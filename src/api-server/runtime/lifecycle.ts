/**
 * Process lifecycle state shared by the standalone server and the probe routes.
 *
 * The standalone entry (standalone.ts) flips `draining` on SIGTERM so the
 * readiness probe starts failing BEFORE the listener closes. Kubernetes and the
 * load balancer then stop routing new requests to this pod while in-flight
 * scans and SSE streams are given time to finish. Under `npm run dev` (the
 * Vite-mounted API) nothing ever calls beginDrain(), so this module is inert.
 *
 * State lives on globalThis because the Vite dev loader re-imports the API
 * module tree on edit; a module-level `let` would silently reset.
 */

interface LifecycleState {
  startedAt: number
  draining: boolean
  drainStartedAt: number | null
}

const scope = globalThis as typeof globalThis & { __qguardLifecycle?: LifecycleState }

function state(): LifecycleState {
  if (!scope.__qguardLifecycle) {
    scope.__qguardLifecycle = { startedAt: Date.now(), draining: false, drainStartedAt: null }
  }
  return scope.__qguardLifecycle
}

export function beginDrain(): void {
  const current = state()
  if (current.draining) return
  current.draining = true
  current.drainStartedAt = Date.now()
}

export function isDraining(): boolean {
  return state().draining
}

export function lifecycleSnapshot() {
  const current = state()
  return {
    startedAt: new Date(current.startedAt).toISOString(),
    uptimeSeconds: Math.round((Date.now() - current.startedAt) / 1000),
    draining: current.draining,
    drainStartedAt: current.drainStartedAt ? new Date(current.drainStartedAt).toISOString() : null,
  }
}

/**
 * Deployment identity for logs and probes. Values come from the environment the
 * container is started with (the CI pipeline stamps APP_VERSION / GIT_SHA);
 * nothing here is inferred or invented when they are absent.
 */
export function buildInfo() {
  return {
    version: process.env.APP_VERSION || null,
    commit: process.env.GIT_SHA || null,
    environment: process.env.QGUARD_ENVIRONMENT || process.env.NODE_ENV || 'development',
    node: process.version,
    openssl: process.versions.openssl,
  }
}
