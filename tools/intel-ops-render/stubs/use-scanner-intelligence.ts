// Render stand-in for src/lib/scanner/use-scanner-intelligence.ts. Re-exports the
// real module (types, EMPTY_SNAPSHOT, helpers) and replaces only the hook, which
// returns `__HOOK_FIXTURES__.scanner` (a ScannerIntelligenceSnapshot) or the
// hook's own empty initial state.
import { EMPTY_SNAPSHOT } from '../../../src/lib/scanner/use-scanner-intelligence'

export * from '../../../src/lib/scanner/use-scanner-intelligence'

export function useScannerIntelligence() {
  const fixtures = ((globalThis as Record<string, unknown>).__HOOK_FIXTURES__ || {}) as Record<string, unknown>
  const data = (fixtures.scanner as typeof EMPTY_SNAPSHOT | undefined) ?? EMPTY_SNAPSHOT
  return {
    data,
    loading: false,
    error: null,
    connected: true,
    refresh: async () => undefined,
    source: 'network' as const,
    resolved: true,
    transport: 'stream' as const,
    lastVerifiedAt: '2026-10-27T11:59:30.000Z',
  }
}
