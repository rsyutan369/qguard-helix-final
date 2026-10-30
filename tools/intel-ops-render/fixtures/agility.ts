// Fixture copied from tools/crypto-agility-check.ts (lines 48–150) so render cases run the REAL
// derivation over the same evidence the check tool asserts on.
import { buildAssetPortfolio, type Row } from '../../../src/lib/migration/asset-intelligence'
import type { AgilityInputs } from '../../../src/lib/crypto-agility/agility-intelligence'

const NOW = Date.parse('2026-08-10T00:00:00Z')

const assets: Row[] = [
  // a1 — cryptography embedded in source ⇒ RIGID (code modification)
  { id: 'a1', name: 'checkout-api', type: 'api', environment: 'production', service_owner: 'Payments Platform', criticality: 'critical', metadata: {}, created_at: '2026-01-05T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
  // a2 — fully managed, TLS 1.3 + hybrid, managed CA ⇒ AGILE
  { id: 'a2', name: 'edge.company.com', type: 'web-service', environment: 'production', service_owner: 'Platform Team', criticality: 'high', metadata: { hostname: 'edge.company.com' }, created_at: '2026-01-05T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
  // a3 — deprecated provider ⇒ CONDITIONAL (library upgrade)
  { id: 'a3', name: 'reporting-worker', type: 'service', environment: 'staging', service_owner: 'Data Platform', criticality: 'medium', metadata: {}, created_at: '2026-02-05T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
  // a4 — discovered but never assessed ⇒ UNKNOWN
  { id: 'a4', name: 'legacy-batch', type: 'server', environment: 'development', service_owner: 'Unassigned', metadata: {}, created_at: '2026-03-05T00:00:00Z', updated_at: '2026-08-01T00:00:00Z' },
]

const cryptoInventory: Row[] = [
  // Code-located ⇒ hard-coded algorithm coupling on a1.
  { id: 'c1', asset_id: 'a1', item_type: 'algorithm', name: 'payment signing', algorithm: 'RSA-2048', key_size: 2048, protocol: 'TLS 1.2', is_vulnerable: true, metadata: { file: 'src/payments/sign.ts', line: 42 }, discovered_at: '2026-04-01T00:00:00Z', created_at: '2026-04-01T00:00:00Z' },
  { id: 'c2', asset_id: 'a1', item_type: 'algorithm', name: 'legacy hash', algorithm: 'SHA-1', is_vulnerable: true, metadata: {}, discovered_at: '2026-04-01T00:00:00Z', created_at: '2026-04-01T00:00:00Z' },
  // Config-driven, already hybrid on a2.
  { id: 'c3', asset_id: 'a2', item_type: 'protocol', name: 'edge tls', algorithm: 'X25519MLKEM768', protocol: 'TLS 1.3', is_quantum_safe: true, metadata: {}, discovered_at: '2026-05-01T00:00:00Z', created_at: '2026-05-01T00:00:00Z' },
  { id: 'c4', asset_id: 'a2', item_type: 'algorithm', name: 'edge signing', algorithm: 'ML-DSA-65', is_quantum_safe: true, metadata: {}, discovered_at: '2026-05-01T00:00:00Z', created_at: '2026-05-01T00:00:00Z' },
  // Deprecated provider on a3.
  { id: 'c5', asset_id: 'a3', item_type: 'library', name: 'OpenSSL 1.1.1', algorithm: 'RSA-3072', is_vulnerable: true, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
  { id: 'c6', asset_id: 'a3', item_type: 'algorithm', name: 'aes', algorithm: 'AES-128', is_vulnerable: false, metadata: {}, discovered_at: '2026-06-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' },
]

const cryptoExposures: Row[] = [
  { id: 'e1', asset_id: 'a1', exposure_type: 'weak_tls', severity: 'high', description: 'TLS 1.2 with classical key exchange', detected_value: 'TLS 1.2', metadata: {}, created_at: '2026-07-01T00:00:00Z' },
  { id: 'e2', asset_id: 'a3', exposure_type: 'deprecated_lib', severity: 'high', description: 'OpenSSL 1.1.1 reached end of life', detected_value: 'OpenSSL 1.1.1', metadata: {}, created_at: '2026-07-01T00:00:00Z' },
]

const scanResults: Row[] = [
  { id: 's1', asset_id: 'a1', algorithm: 'RSA-2048', threat_level: 'critical', description: 'Quantum-vulnerable signing key', created_at: '2026-07-15T00:00:00Z' },
  { id: 's2', asset_id: 'a3', algorithm: 'RSA-3072', threat_level: 'medium', description: 'Classical key transport', created_at: '2026-07-15T00:00:00Z' },
]

const certificates: Row[] = [
  // Self-signed ⇒ static trust anchor coupling on a1.
  { id: 'x1', asset_id: 'a1', name: 'checkout-internal', subject: 'checkout-internal', algorithm: 'RSA-2048', key_size: 2048, issuer: 'checkout-internal', not_after: '2026-12-01T00:00:00Z', is_quantum_safe: false, status: 'active', created_at: '2026-04-01T00:00:00Z' },
  // Managed issuer ⇒ certificate automation evidence on a2.
  { id: 'x2', asset_id: 'a2', name: 'edge.company.com', subject: 'edge.company.com', algorithm: 'ML-DSA-65', issuer: "Let's Encrypt", not_after: '2027-02-01T00:00:00Z', is_quantum_safe: true, status: 'active', created_at: '2026-05-01T00:00:00Z' },
]

const runtimeEvents: Row[] = [
  { id: 'r1', asset_id: 'a1', asset_name: 'checkout-api', algorithm: 'RSA-2048', key_exchange_algorithm: 'ECDHE-RSA', cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', protocol: 'TLS 1.2', severity: 'high', risk_score: 72, is_legacy: true, hndl_risk: true, observed_at: '2026-08-05T00:00:00Z', created_at: '2026-08-05T00:00:00Z' },
  { id: 'r2', asset_id: 'a2', asset_name: 'edge.company.com', algorithm: 'ML-KEM-768', key_exchange_algorithm: 'X25519MLKEM768', protocol: 'TLS 1.3', severity: 'low', risk_score: 4, is_pqc: true, observed_at: '2026-08-05T00:00:00Z', created_at: '2026-08-05T00:00:00Z' },
]

const relationships: Row[] = [
  { id: 'rel1', source_asset_id: 'a1', target_asset_id: 'a3', relationship_type: 'calls' },
  { id: 'rel2', source_asset_id: 'a2', target_asset_id: 'a1', relationship_type: 'proxies' },
]

const migrationJobs: Row[] = [
  { id: 'j1', asset_id: 'a3', name: 'reporting tls migration', job_type: 'tls_migration', status: 'running', target_algorithm: 'ML-KEM-768', progress: 35, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-06T00:00:00Z' },
]

const portfolio = buildAssetPortfolio({
  assets,
  cryptoInventory,
  scanResults,
  cryptoExposures,
  certificates,
  runtimeEvents,
  relationships,
  migrationJobs,
  validationLogs: [],
  complianceEvidence: [],
  now: NOW,
})

const inputs: AgilityInputs = {
  assets: portfolio.assets,
  portfolioSummary: portfolio.summary,
  snapshot: {
    hasData: true,
    lastAssessmentAt: '2026-08-05T00:00:00Z',
    scores: { quantumReadiness: 48, pqcAdoption: 33, quantumRisk: 61, hndlRisk: 55 },
    inventory: {
      assetsAssessed: 4,
      cryptoComponents: cryptoInventory.length,
      vulnerableComponents: 4,
      pqcReadyComponents: 2,
      certificatesAnalyzed: certificates.length,
      keysDiscovered: 0,
      trustRelationships: relationships.length,
      cloudAccounts: 0,
      domainsScanned: 2,
    },
    sharedResponsibility: null,
  },
  cryptoInventory,
  cryptoExposures,
  certificates,
  runtimeEvents,
  generatedKeys: [],
  migrationJobs,
  scanSessions: [{ id: 'sess1', status: 'completed', findings_count: 4, completed_at: '2026-08-05T00:00:00Z', created_at: '2026-08-05T00:00:00Z' }],
  securityEvents: [],
  connectorAccounts: [],
  relationships,
  policyExceptions: [],
  now: NOW,
}

export { NOW, inputs }
