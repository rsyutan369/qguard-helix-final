// Render stand-in for src/hooks/use-live-resource.ts. Returns, for the SSE
// event the real hook would subscribe to, the case's payload and connection
// state (set by harness.tsx on globalThis.__LIVE_CASE__). Exposes the same
// three exports the real module does.
export type LiveLoadState = 'loading' | 'success' | 'error'
export type LiveTransport = 'connecting' | 'stream' | 'polling' | 'offline'

interface LiveCase {
  payload: unknown
  state?: LiveLoadState
  transport?: LiveTransport
  error?: string | null
  lastVerifiedAt?: string | null
}

function caseFor(event: string): LiveCase {
  const cases = ((globalThis as Record<string, unknown>).__LIVE_CASE__ || {}) as Record<string, LiveCase>
  return cases[event] || { payload: null, state: 'loading', transport: 'connecting' }
}

export function useLiveResource(options: any) {
  const c = caseFor(options.event)
  const raw = c.payload as Record<string, unknown> | null
  const data = raw == null ? options.empty : options.normalize ? options.normalize(raw) : { ...options.empty, ...raw }
  const transport = c.transport ?? (c.state === 'loading' ? 'connecting' : 'stream')
  return {
    data,
    state: c.state ?? (raw == null ? 'loading' : 'success'),
    error: c.error ?? null,
    sseConnected: transport === 'stream',
    transport,
    // Relative to now: a fixed date ages past the 90 s stale threshold and every page (correctly) reads Stale.
    lastVerifiedAt: c.lastVerifiedAt === undefined ? (raw == null ? null : new Date(Date.now() - 30_000).toISOString()) : c.lastVerifiedAt,
    refresh: async () => undefined,
  }
}

export function useLiveModel(options: any) {
  const resource = useLiveResource({ ...options, empty: null, normalize: (raw: unknown) => raw })
  return {
    data: resource.data,
    state: resource.state,
    error: resource.error,
    live: resource.sseConnected,
    transport: resource.transport,
    lastVerifiedAt: resource.lastVerifiedAt,
    lastGoodAt: (resource.data as { generatedAt?: string } | null)?.generatedAt ?? resource.lastVerifiedAt,
    refreshing: false,
    refresh: async () => undefined,
    reconnect: () => undefined,
  }
}

export function downloadJsonFile() {}
