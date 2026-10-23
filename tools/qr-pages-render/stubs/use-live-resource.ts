// Render-smoke stand-in for src/hooks/use-live-resource.ts: returns the fixture
// payload for the stream event the real hook would subscribe to. Fixtures are
// produced by the real server assemblers (fixtures.ts).
export type LiveLoadState = 'loading' | 'success' | 'error'
export type LiveTransport = 'connecting' | 'stream' | 'polling' | 'offline'
export function useLiveResource(options: any) {
  const fixtures = (globalThis as any).__LIVE_FIXTURES__ || {}
  const mode = (globalThis as any).__LIVE_MODE__ || 'populated'
  const raw = mode === 'populated' ? fixtures[options.event] : undefined
  const data = raw ? (options.normalize ? options.normalize(raw) : { ...options.empty, ...raw }) : options.empty
  return {
    data,
    state: mode === 'loading' ? 'loading' : 'success',
    error: null,
    sseConnected: mode !== 'loading',
    transport: 'stream',
    lastVerifiedAt: '2026-10-21T08:00:00.000Z',
    refresh: async () => undefined,
  }
}
export function downloadJsonFile() {}
