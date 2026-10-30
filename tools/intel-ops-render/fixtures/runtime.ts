// Fixture copied from tools/runtime-crypto-intel-check.ts (lines 49–168) so render cases run the REAL
// derivation over the same evidence the check tool asserts on.
import { buildAssetPortfolio, type Row } from '../../../src/lib/migration/asset-intelligence'
import type { RuntimeIntelInputs, RuntimeSnapshotFacts } from '../../../src/lib/runtime-crypto/runtime-intelligence'

const NOW = Date.parse('2026-08-13T12:00:00Z')
const minutesAgo = (n: number) => new Date(NOW - n * 60_000).toISOString()
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString()

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

const assets: Row[] = [
  { id: 'a-pay', name: 'Payment API', type: 'api', environment: 'production', service_owner: 'Payments', criticality: 'critical', metadata: { internet_facing: true, hostname: 'pay.example.com' }, created_at: daysAgo(200), updated_at: daysAgo(1) },
  { id: 'a-auth', name: 'Auth Service', type: 'service', environment: 'production', service_owner: 'Identity', criticality: 'high', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
  { id: 'a-legacy', name: 'Legacy API', type: 'api', environment: 'production', service_owner: 'Platform', criticality: 'medium', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
  { id: 'a-dev', name: 'Dev Sandbox', type: 'server', environment: 'development', service_owner: 'Platform', criticality: 'low', metadata: {}, created_at: daysAgo(200), updated_at: daysAgo(1) },
]

const cryptoInventory: Row[] = [
  { id: 'c1', asset_id: 'a-pay', item_type: 'algorithm', name: 'payment signing', algorithm: 'RSA-2048', is_vulnerable: true, metadata: {}, discovered_at: daysAgo(10), created_at: daysAgo(10) },
  { id: 'c2', asset_id: 'a-auth', item_type: 'algorithm', name: 'token signing', algorithm: 'ML-DSA-65', is_quantum_safe: true, metadata: {}, discovered_at: daysAgo(10), created_at: daysAgo(10) },
]

const portfolio = buildAssetPortfolio({
  assets,
  cryptoInventory,
  scanResults: [],
  cryptoExposures: [],
  certificates: [],
  runtimeEvents: [],
  relationships: [],
  migrationJobs: [],
  validationLogs: [],
  complianceEvidence: [],
  now: NOW,
})

const snapshot: RuntimeSnapshotFacts = {
  hasData: true,
  lastAssessmentAt: daysAgo(1),
  scores: {
    quantumReadiness: 61,
    pqcAdoption: 44,
    quantumRisk: 58,
    quantumRiskLevel: 'High',
    hndlRisk: 63,
    hndlRiskLevel: 'High',
  },
  inventory: { assetsAssessed: 4, cryptoComponents: 2, vulnerableComponents: 1, certificatesAnalyzed: 0 },
}

const baseEvent = {
  source_type: 'local-agent',
  severity: 'low',
  risk_score: 0,
  is_pqc: false,
  is_legacy: false,
  downgrade_detected: false,
  shadow_crypto: false,
  hndl_risk: false,
  metadata: {},
}

const runtimeEvents: Row[] = [
  // Payment API — TLS 1.3, hybrid group. Suite names ONLY the bulk cipher.
  {
    ...baseEvent, id: 'e1', asset_id: 'a-pay', asset_name: 'Payment API', event_type: 'tls_handshake', operation_type: 'key_exchange',
    protocol: 'TLS', tls_version: 'TLS 1.3', cipher_suite: 'TLS_AES_256_GCM_SHA384', key_exchange_algorithm: 'X25519MLKEM768',
    algorithm: 'ML-DSA-65', host: 'pay.example.com', port: 443, is_pqc: true, observed_at: minutesAgo(3), created_at: minutesAgo(3),
  },
  // Auth Service — ML-DSA signing.
  {
    ...baseEvent, id: 'e2', asset_id: 'a-auth', asset_name: 'Auth Service', event_type: 'jwt_sign', operation_type: 'signing',
    algorithm: 'ML-DSA-65', observed_at: minutesAgo(5), created_at: minutesAgo(5),
  },
  // Legacy API — classical X25519 key exchange over TLS 1.2, seen four times.
  ...[10, 12, 14, 16].map((minute, index) => ({
    ...baseEvent, id: `e-legacy-${index}`, asset_id: 'a-legacy', asset_name: 'Legacy API', event_type: 'tls_handshake',
    operation_type: 'key_exchange', protocol: 'TLS', tls_version: 'TLS 1.2', key_exchange_algorithm: 'X25519',
    cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', hndl_risk: true, is_legacy: true,
    observed_at: minutesAgo(minute), created_at: minutesAgo(minute),
  })),
  // Dev Sandbox — the SAME classical primitive, on a low-criticality dev box.
  {
    ...baseEvent, id: 'e-dev', asset_id: 'a-dev', asset_name: 'Dev Sandbox', event_type: 'tls_handshake', operation_type: 'key_exchange',
    protocol: 'TLS', tls_version: 'TLS 1.2', key_exchange_algorithm: 'X25519', observed_at: minutesAgo(20), created_at: minutesAgo(20),
  },
  // A pure bulk-cipher observation: quantum-resistant, must never read critical.
  {
    ...baseEvent, id: 'e-aes', asset_id: 'a-auth', asset_name: 'Auth Service', event_type: 'data_encrypt', operation_type: 'encryption',
    algorithm: 'AES-256-GCM', observed_at: minutesAgo(7), created_at: minutesAgo(7),
  },
  // An observation whose primitive cannot be determined.
  {
    ...baseEvent, id: 'e-unknown', asset_id: 'a-dev', asset_name: 'Dev Sandbox', event_type: 'crypto_call', operation_type: 'other',
    algorithm: 'proprietary-wrapper-v2', observed_at: minutesAgo(25), created_at: minutesAgo(25),
  },
  // Post-cutover evidence for the Payment API migration (below).
  {
    ...baseEvent, id: 'e-post', asset_id: 'a-pay', asset_name: 'Payment API', event_type: 'jwt_sign', operation_type: 'signing',
    algorithm: 'ML-DSA-65', is_pqc: true, observed_at: minutesAgo(2), created_at: minutesAgo(2),
    // Secret-shaped metadata that must never reach the browser.
    metadata: { region: 'eu-west-1', private_key: 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ', api_token: 'sk_live_abc123' },
  },
]

const migrationJobs: Row[] = [
  { id: 'j1', asset_id: 'a-pay', name: 'Payment API — ML-DSA cutover', job_type: 'signature', status: 'completed', target_algorithm: 'ML-DSA-65', progress: 100, metadata: { from_algorithm: 'RSA-2048' }, completed_at: minutesAgo(30), updated_at: minutesAgo(30), created_at: daysAgo(5) },
  { id: 'j2', asset_id: 'a-legacy', name: 'Legacy API — hybrid TLS', job_type: 'transport', status: 'completed', target_algorithm: 'X25519MLKEM768', progress: 100, metadata: {}, completed_at: minutesAgo(60), updated_at: minutesAgo(60), created_at: daysAgo(5) },
]

const inputs: RuntimeIntelInputs = {
  snapshot,
  assets: portfolio.assets,
  runtimeEvents,
  migrationJobs,
  scannerAgents: [{ id: 'ag1', name: 'collector-01', status: 'active', last_seen_at: minutesAgo(1) }],
  connectorAccounts: [{ id: 'cn1', provider: 'aws', status: 'connected' }],
  runtimeEventsTruncated: false,
  window: '24h',
  now: NOW,
}


export { NOW, inputs }
