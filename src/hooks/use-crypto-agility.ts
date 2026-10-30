import { useLiveModel, type LiveModel } from '@/hooks/use-live-resource'
import type { CryptoAgilityIntelligence } from '@/lib/crypto-agility/agility-intelligence'

/** Tables whose mutation changes the agility inputs (inventory, keys, jobs, policy). */
const REALTIME_TABLES = [
  'assets', 'crypto_inventory', 'crypto_exposures', 'certificates', 'runtime_crypto_events',
  'migration_jobs', 'generated_keys', 'quantum_governance_exceptions',
] as const

/**
 * useCryptoAgility — live Crypto Agility Command Center™ state.
 *
 * The previous hook opened an `EventSource` with the bearer token in the query
 * string. Besides leaking the token into access logs and browser history, the
 * subscription gateway reads only the Authorization header, so that stream was
 * served without the Pro entitlement check. This wrapper streams over fetch()
 * with the header, through the platform's one live-resource client.
 *
 * Load states stay explicit so the UI can distinguish "loading", "no evidence"
 * and "request failed" — a failure must never render as zeros.
 */
export function useCryptoAgility(): LiveModel<CryptoAgilityIntelligence> {
  return useLiveModel<CryptoAgilityIntelligence>({
    url: '/api/v1/crypto-agility',
    streamUrl: '/api/v1/crypto-agility/stream',
    event: 'agility-update',
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'crypto-agility',
  })
}

export default useCryptoAgility
