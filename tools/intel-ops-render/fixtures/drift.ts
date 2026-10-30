// Fixture copied from tools/drift-check.ts (lines 41–100) so render cases run the REAL
// derivation over the same evidence the check tool asserts on.
import { buildAssetPortfolio, type Row } from '../../../src/lib/migration/asset-intelligence'
import type { DriftInputs } from '../../../src/lib/drift/drift-intelligence'

const NOW = Date.parse('2026-08-13T12:00:00Z')
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString()
const hoursAgo = (n: number) => new Date(NOW - n * 3_600_000).toISOString()

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

const assets: Row[] = [
  { id: 'a-pay', name: 'payments.example.com', type: 'api', environment: 'production', service_owner: 'Payments', criticality: 'critical', metadata: { hostname: 'payments.example.com' }, created_at: daysAgo(90), updated_at: daysAgo(1) },
  { id: 'a-edge', name: 'edge.example.com', type: 'web-service', environment: 'production', service_owner: 'Platform', criticality: 'high', metadata: { hostname: 'edge.example.com' }, created_at: daysAgo(90), updated_at: daysAgo(1) },
  { id: 'a-dev', name: 'dev.example.com', type: 'server', environment: 'development', service_owner: 'Platform', criticality: 'low', metadata: { hostname: 'dev.example.com' }, created_at: daysAgo(90), updated_at: daysAgo(1) },
]

const portfolio = buildAssetPortfolio({
  assets, cryptoInventory: [], scanResults: [], cryptoExposures: [], certificates: [], runtimeEvents: [],
  relationships: [], migrationJobs: [], validationLogs: [], complianceEvidence: [], now: NOW,
})

const scanSessions: Row[] = [
  { id: 'session-old', status: 'completed', completed_at: daysAgo(7), created_at: daysAgo(7) },
  { id: 'session-new', status: 'completed', completed_at: daysAgo(1), created_at: daysAgo(1) },
  { id: 'session-running', status: 'running', completed_at: null, created_at: hoursAgo(1) },
]

const scanResults: Row[] = [
  /* ---- baseline (session-old) ---- */
  // Persisted unchanged into the new scan.
  { id: 'r1', scan_session_id: 'session-old', asset_id: 'a-pay', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Signing key', created_at: daysAgo(7) },
  // Disappears in the new scan and IS explained by a completed migration ⇒ planned.
  { id: 'r2', scan_session_id: 'session-old', asset_id: 'a-edge', algorithm: 'ECDHE-RSA-AES128-SHA', threat_level: 'high', description: 'Legacy suite', created_at: daysAgo(7) },
  // Disappears with NO migration ⇒ unplanned improvement.
  { id: 'r3', scan_session_id: 'session-old', asset_id: 'a-dev', algorithm: 'SHA-1', threat_level: 'medium', description: 'Legacy hash', created_at: daysAgo(7) },
  // Severity worsens in the new scan ⇒ regression.
  { id: 'r4', scan_session_id: 'session-old', asset_id: 'a-dev', algorithm: 'AES-128-CBC', threat_level: 'low', description: 'Weak mode', created_at: daysAgo(7) },

  /* ---- current (session-new) ---- */
  // Same item, different row id and different narrative — must NOT be drift.
  { id: 'r5', scan_session_id: 'session-new', asset_id: 'a-pay', algorithm: 'RSA-2048', threat_level: 'critical', description: 'RSA signing key detected on host', created_at: daysAgo(1) },
  // NEW vulnerable crypto with no migration ⇒ regression.
  { id: 'r6', scan_session_id: 'session-new', asset_id: 'a-pay', algorithm: 'X25519', threat_level: 'high', description: 'Classical key exchange', created_at: daysAgo(1) },
  // NEW post-quantum crypto explained by a migration ⇒ planned.
  { id: 'r7', scan_session_id: 'session-new', asset_id: 'a-edge', algorithm: 'X25519MLKEM768', threat_level: 'low', description: 'Hybrid group', created_at: daysAgo(1) },
  // Severity worsened.
  { id: 'r8', scan_session_id: 'session-new', asset_id: 'a-dev', algorithm: 'AES-128-CBC', threat_level: 'high', description: 'Weak mode', created_at: daysAgo(1) },
]

const migrationJobs: Row[] = [
  { id: 'j1', asset_id: 'a-edge', name: 'Edge hybrid TLS cutover', status: 'completed', target_algorithm: 'X25519MLKEM768', completed_at: daysAgo(3), updated_at: daysAgo(3), created_at: daysAgo(10) },
]

const runtimeEvents: Row[] = [
  ...Array.from({ length: 4 }, (_, i) => ({
    id: `d${i}`, asset_id: 'a-pay', asset_name: 'payments.example.com', key_exchange_algorithm: 'X25519',
    downgrade_detected: true, observed_at: hoursAgo(i + 1), created_at: hoursAgo(i + 1),
  })),
  { id: 'not-a-downgrade', asset_id: 'a-pay', asset_name: 'payments.example.com', key_exchange_algorithm: 'X25519MLKEM768', downgrade_detected: false, observed_at: hoursAgo(1), created_at: hoursAgo(1) },
]

const base: DriftInputs = { scanSessions, scanResults, runtimeEvents, migrationJobs, assets: portfolio.assets, now: NOW }

export { NOW, base }
