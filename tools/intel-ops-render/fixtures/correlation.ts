// Fixture copied from tools/telemetry-correlation-check.ts (lines 37–93) so render cases run the REAL
// derivation over the same evidence the check tool asserts on.
import { buildAssetPortfolio, type Row } from '../../../src/lib/migration/asset-intelligence'
import type { CorrelationInputs } from '../../../src/lib/telemetry/correlation-intelligence'

const NOW = Date.parse('2026-08-13T12:00:00Z')
const minutesAgo = (n: number) => new Date(NOW - n * 60_000).toISOString()
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString()

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

const assets: Row[] = [
  // Seen by three channels ⇒ corroborated.
  { id: 'a-edge', name: 'edge.example.com', type: 'web-service', environment: 'production', service_owner: 'Platform', criticality: 'high', metadata: { hostname: 'edge.example.com', internet_facing: true }, created_at: daysAgo(60), updated_at: daysAgo(1) },
  // Seen by one channel only ⇒ single source.
  { id: 'a-batch', name: 'batch.example.com', type: 'service', environment: 'staging', service_owner: 'Data', criticality: 'medium', metadata: { hostname: 'batch.example.com' }, created_at: daysAgo(60), updated_at: daysAgo(1) },
  // Seen by NOBODY ⇒ blind spot, and it is internet-facing and critical.
  { id: 'a-dark', name: 'legacy.example.com', type: 'server', environment: 'production', service_owner: 'Infra', criticality: 'critical', metadata: { hostname: 'legacy.example.com', internet_facing: true }, created_at: daysAgo(60), updated_at: daysAgo(1) },
  // Discovery says post-quantum, runtime says classical ⇒ CONFLICT.
  { id: 'a-conflict', name: 'api.example.com', type: 'api', environment: 'production', service_owner: 'Payments', criticality: 'critical', metadata: { hostname: 'api.example.com', internet_facing: true }, created_at: daysAgo(60), updated_at: daysAgo(1) },
]

const portfolio = buildAssetPortfolio({
  assets, cryptoInventory: [], scanResults: [], cryptoExposures: [], certificates: [], runtimeEvents: [],
  relationships: [], migrationJobs: [], validationLogs: [], complianceEvidence: [], now: NOW,
})

const scannerEvidence: Row[] = [
  { id: 'se1', asset_name: 'edge.example.com', host: 'edge.example.com', protocol: 'TLS', observed_algorithm: 'X25519MLKEM768', observed_at: minutesAgo(30), created_at: minutesAgo(30) },
  { id: 'se2', asset_name: 'api.example.com', host: 'api.example.com', protocol: 'TLS', observed_algorithm: 'X25519MLKEM768', observed_at: minutesAgo(30), created_at: minutesAgo(30) },
  // Same channel, second reading on edge — must NOT count as a second source.
  { id: 'se3', asset_name: 'edge.example.com', host: 'edge.example.com', protocol: 'TLS', observed_algorithm: 'AES-256-GCM', observed_at: minutesAgo(25), created_at: minutesAgo(25) },
]

const runtimeEvents: Row[] = [
  { id: 'rt1', asset_id: 'a-edge', asset_name: 'edge.example.com', agent_id: 'agent-1', key_exchange_algorithm: 'X25519MLKEM768', protocol: 'TLS', observed_at: minutesAgo(5), created_at: minutesAgo(5) },
  // Runtime disagrees with discovery on api.example.com.
  { id: 'rt2', asset_id: 'a-conflict', asset_name: 'api.example.com', agent_id: 'agent-1', key_exchange_algorithm: 'X25519', protocol: 'TLS', observed_at: minutesAgo(5), created_at: minutesAgo(5) },
  // An unclassifiable reading — must never be treated as disagreement.
  { id: 'rt3', asset_id: 'a-edge', asset_name: 'edge.example.com', agent_id: 'agent-1', algorithm: 'proprietary-wrapper', observed_at: minutesAgo(4), created_at: minutesAgo(4) },
]

const cryptoInventory: Row[] = [
  { id: 'ci1', asset_id: 'a-edge', item_type: 'protocol', name: 'edge tls', algorithm: 'X25519MLKEM768', protocol: 'TLS 1.3', discovered_at: daysAgo(2), created_at: daysAgo(2) },
  { id: 'ci2', asset_id: 'a-batch', item_type: 'algorithm', name: 'batch signing', algorithm: 'RSA-2048', discovered_at: daysAgo(2), created_at: daysAgo(2) },
]

const scannerAgents: Row[] = [
  { id: 'agent-1', name: 'collector-01', status: 'active', hostname: 'host-1', platform: 'linux', last_seen_at: minutesAgo(2) },
  // Gone quiet for days ⇒ silent.
  { id: 'agent-2', name: 'collector-02', status: 'active', hostname: 'host-2', platform: 'windows', last_seen_at: daysAgo(9) },
]

const connectorAccounts: Row[] = [{ id: 'cn1', provider: 'aws', status: 'connected' }]
const scanSessions: Row[] = [{ id: 's1', status: 'completed', completed_at: daysAgo(2), created_at: daysAgo(2) }]

const base: CorrelationInputs = {
  assets: portfolio.assets, scannerEvidence, runtimeEvents, cryptoInventory,
  scannerAgents, connectorAccounts, scanSessions, now: NOW,
}

export { NOW, base }
