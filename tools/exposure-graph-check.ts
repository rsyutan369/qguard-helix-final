/**
 * Offline verification for the Quantum Exposure Graph™ Enterprise Dependency &
 * Migration Intelligence engine (Crypto_Exposure_Graph_Enhancement). Drives the
 * pure assembleExposureIntelligence() with a synthetic-but-realistic tenant
 * topology and asserts every intelligence section derives from evidence —
 * graph nodes/edges, five-state posture, external entity derivation (CA /
 * vendor hosts), migration waves & clusters & blockers, Blast Radius
 * Analysis™, Migration Impact Analysis™, risk prioritisation and the honest
 * empty state (no fabricated values). No server/Supabase required.
 *
 *   npx tsx tools/exposure-graph-check.ts
 */
import { assembleExposureIntelligence, type ExposureRawRows } from '../src/api-server/exposure-graph'
import { buildExposureWorkflowGraph } from '../src/lib/exposure-graph-workflow'
import { computeBlastRadius, computeMigrationImpact, pqcTargetFor, classifyAlgorithmClass, classifyAssetCategory, tierForCategory } from '../src/lib/exposure-graph-intel'

type AssembleSnapshot = Parameters<typeof assembleExposureIntelligence>[0]

const NOW = new Date().toISOString()

let passed = 0
let failed = 0
function check(name: string, condition: boolean, detail = '') {
  if (condition) {
    passed += 1
    console.log(`  PASS  ${name}`)
  } else {
    failed += 1
    console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

/* ---- Synthetic enterprise snapshot (QR contract shape) ------------- */
const SNAPSHOT = {
  generatedAt: NOW,
  lastAssessmentAt: NOW,
  assessmentProgress: 85,
  assessmentStatus: 'in_progress',
  hasData: true,
  scores: {
    quantumReadiness: 34, quantumReadinessLevel: 'Early Stage',
    quantumRisk: 61, quantumRiskLevel: 'High',
    hndlRisk: 58, hndlRiskLevel: 'Elevated',
    cryptoExposure: 55, cryptoExposureLevel: 'Elevated',
    migrationComplexity: 48, migrationComplexityLevel: 'Elevated',
    migrationEffort: 52, pqcAdoption: 18,
  },
  inventory: {
    assetsAssessed: 11, certificatesAnalyzed: 3, keysDiscovered: 12, trustRelationships: 8,
    domainsScanned: 6, identitiesAnalyzed: 0, cloudAccounts: 1, dataRepositories: 2,
    pqcReadyAssets: 1, hybridAssets: 2, quantumVulnerableAssets: 7,
    cryptoComponents: 40, vulnerableComponents: 21, pqcReadyComponents: 6,
  },
  riskDistribution: { critical: 4, high: 7, medium: 6, low: 2 },
  readinessFactors: [],
  riskFactors: [],
  criticalFindings: [
    { id: 'F1', title: 'RSA-2048 issuing key', asset: 'internal-pki.acme.local', assetType: 'pki service', environment: 'production', severity: 'critical', algorithm: 'RSA-2048', detectedAt: NOW, instances: 3 },
    { id: 'F2', title: 'Legacy TLS suite', asset: 'payments-api.acme.com', assetType: 'internal api', environment: 'production', severity: 'critical', algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', detectedAt: NOW, instances: 2 },
  ],
  recommendedActions: [],
  topRiskAssets: [],
  exposureGraph: { nodes: [], edges: [] },
  riskTrend: [],
  estimates: { migrationTimelineWeeks: 22, migrationCostUsd: 138000, parallelWorkstreams: 2 },
  telemetry: { runtimeEvents: 220, scanResults: 40, scanSessions: 4, securityEvents: 10, certificates: 3, keys: 12, assets: 11, connectors: 1, latestEventAt: NOW },
} as unknown as AssembleSnapshot

/* ---- Synthetic tenant topology ------------------------------------- */
const A = {
  pki: 'a-pki', kms: 'a-kms', idp: 'a-idp', vpn: 'a-vpn', lb: 'a-lb',
  api1: 'a-api1', api2: 'a-api2', db: 'a-db', k8s: 'a-k8s', web: 'a-web', ws: 'a-ws',
}
const STRIPE = 'ext:api.stripe.com'

const ROWS: ExposureRawRows = {
  assets: [
    { id: A.pki, name: 'internal-pki.acme.local', type: 'pki service', environment: 'production', region: 'us-east-1', service_owner: 'Security', criticality: 'critical', metadata: {} },
    { id: A.kms, name: 'vault-kms.acme.local', type: 'kms', environment: 'production', region: 'us-east-1', service_owner: 'Security', criticality: 'critical', metadata: {} },
    { id: A.idp, name: 'sso.acme.com', type: 'identity provider', environment: 'production', region: 'us-east-1', service_owner: 'IAM', criticality: 'critical', metadata: {} },
    { id: A.vpn, name: 'vpn-gw.acme.com', type: 'vpn gateway', environment: 'production', region: 'us-east-1', service_owner: 'Network', criticality: 'high', metadata: {} },
    { id: A.lb, name: 'edge-lb.acme.com', type: 'load balancer', environment: 'dmz', region: 'us-east-1', service_owner: 'Platform', criticality: 'high', metadata: { internet_facing: true } },
    { id: A.api1, name: 'payments-api.acme.com', type: 'internal api', environment: 'production', region: 'us-east-1', service_owner: 'Payments', criticality: 'critical', metadata: {} },
    { id: A.api2, name: 'orders-api.acme.com', type: 'microservice', environment: 'production', region: 'us-east-1', service_owner: 'Orders', criticality: 'high', metadata: {} },
    { id: A.db, name: 'postgres-primary.acme.local', type: 'database', environment: 'production', region: 'us-east-1', service_owner: 'Data', criticality: 'critical', metadata: {} },
    { id: A.k8s, name: 'prod-cluster', type: 'kubernetes cluster', environment: 'production', region: 'us-east-1', service_owner: 'Platform', criticality: 'high', metadata: { provider: 'aws-eks' } },
    { id: A.web, name: 'portal.acme.com', type: 'web application', environment: 'production', region: 'us-east-1', service_owner: 'Web', criticality: 'medium', metadata: {} },
    { id: A.ws, name: 'eng-workstation-042', type: 'workstation', environment: 'corp', region: 'us-east-1', service_owner: 'IT', criticality: 'low', metadata: {} },
  ],
  relationships: [
    { source_asset_id: A.web, target_asset_id: A.lb, relationship_type: 'tls-terminates-at' },
    { source_asset_id: A.lb, target_asset_id: A.api1, relationship_type: 'routes-api-traffic' },
    { source_asset_id: A.api1, target_asset_id: A.api2, relationship_type: 'mutual-tls' },
    { source_asset_id: A.api1, target_asset_id: A.db, relationship_type: 'uses-tls' },
    { source_asset_id: A.api1, target_asset_id: A.idp, relationship_type: 'oauth-authenticates' },
    { source_asset_id: A.k8s, target_asset_id: A.kms, relationship_type: 'key-wrapping' },
    { source_asset_id: A.vpn, target_asset_id: A.idp, relationship_type: 'saml-auth' },
  ],
  cryptoInventory: [
    { asset_id: A.pki, name: 'internal-pki.acme.local', algorithm: 'RSA-2048', protocol: 'X.509', is_vulnerable: true, is_quantum_safe: false },
    { asset_id: A.kms, name: 'vault-kms.acme.local', algorithm: 'RSA-4096', protocol: 'KMIP', is_vulnerable: true, is_quantum_safe: false },
    { asset_id: A.idp, name: 'sso.acme.com', algorithm: 'ECDSA-P256', protocol: 'TLS1.2', is_vulnerable: true, is_quantum_safe: false },
    { asset_id: A.vpn, name: 'vpn-gw.acme.com', algorithm: 'DH-2048', protocol: 'IPsec', is_vulnerable: true, is_quantum_safe: false },
    { asset_id: A.lb, name: 'edge-lb.acme.com', algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', protocol: 'TLS1.2', is_vulnerable: true, is_quantum_safe: false },
    { asset_id: A.api1, name: 'payments-api.acme.com', algorithm: 'ECDHE-RSA-AES256-GCM', protocol: 'TLS1.2', is_vulnerable: true, is_quantum_safe: false },
    { asset_id: A.api2, name: 'orders-api.acme.com', algorithm: 'RSA-2048', protocol: 'TLS1.2', is_vulnerable: true, is_quantum_safe: false },
    { asset_id: A.db, name: 'postgres-primary.acme.local', algorithm: 'ML-KEM-768', protocol: 'TLS1.3-hybrid', is_vulnerable: false, is_quantum_safe: true },
    { asset_id: A.web, name: 'portal.acme.com', algorithm: 'SHA-1', protocol: 'TLS1.2', is_vulnerable: true, is_quantum_safe: false },
    // a-k8s gets crypto evidence but is mid-migration (job below) → migrating
    { asset_id: A.k8s, name: 'prod-cluster', algorithm: 'ECDSA-P256', protocol: 'mTLS', is_vulnerable: true, is_quantum_safe: false },
    // a-ws intentionally has NO crypto evidence → unknown posture
  ],
  certificates: [
    { asset_id: A.lb, name: 'edge-lb.acme.com', algorithm: 'RSA-2048', issuer: 'CN=DigiCert Global CA G2, O=DigiCert Inc', not_after: '2026-11-01', is_quantum_safe: false, is_expiring_soon: true },
    { asset_id: A.api1, name: 'payments-api.acme.com', algorithm: 'RSA-2048', issuer: 'CN=DigiCert Global CA G2, O=DigiCert Inc', not_after: '2027-02-01', is_quantum_safe: false, is_expiring_soon: false },
    { asset_id: A.api2, name: 'orders-api.acme.com', algorithm: 'ECDSA-P256', issuer: 'CN=internal-pki.acme.local', not_after: '2026-09-15', is_quantum_safe: false, is_expiring_soon: false },
  ],
  runtimeEvents: [
    { asset_id: A.api1, event_type: 'tls-handshake', metadata: { observationKind: 'runtime-observation' }, algorithm: 'TLS_RSA_WITH_AES_128_GCM_SHA256', host: 'api.stripe.com', risk_score: 72 },
    { asset_id: A.api1, event_type: 'tls-handshake', metadata: { observationKind: 'runtime-observation' }, algorithm: 'TLS_RSA_WITH_AES_128_GCM_SHA256', host: 'api.stripe.com', risk_score: 72 },
    { asset_id: A.web, asset_name: 'portal.acme.com', algorithm: 'ECDHE-RSA-AES256', host: 'sso.acme.com', risk_score: 40, is_legacy: false, is_pqc: false },
  ],
  scanResults: [
    { id: 'scan-pki', asset_id: A.pki, algorithm: 'RSA-2048', threat_level: 'critical' },
    { id: 'scan-lb', asset_id: A.lb, algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', threat_level: 'high' },
  ],
  cryptoExposures: [{ asset_id: A.idp, exposure_type: 'legacy-signature', severity: 'high' }],
  connectorAccounts: [{ id: 'conn-1', provider: 'aws', status: 'connected' }],
  migrationJobs: [{ id: 'job-1', asset_id: A.k8s, status: 'running', progress: 40, job_type: 'pqc-migration' }],
}

console.log('Quantum Exposure Graph™ — offline intelligence verification\n')

/* ================= 1. Assembler on enterprise topology ============== */
const intel = assembleExposureIntelligence(SNAPSHOT, ROWS)
const nodes = intel.graph.nodes
const edges = intel.graph.edges
const byId = new Map(nodes.map((n) => [n.id, n]))
const recordedEdges = edges.filter((edge) => edge.provenance !== 'inferred')

console.log('— Graph assembly')
check('hasData true with evidence', intel.hasData === true)
check('all 11 assets became nodes', nodes.filter((n) => n.kind === 'asset').length === 11, `got ${nodes.filter((n) => n.kind === 'asset').length}`)
check('external CA node derived from certificate issuers', nodes.some((n) => n.id.startsWith('ca:') && /digicert/i.test(n.label)))
check('external vendor node derived from runtime hosts', nodes.some((n) => n.id === STRIPE))
check('cloud provider node linked via metadata evidence', nodes.some((n) => n.id.startsWith('cloud:')))
check('relationship edges materialised', edges.filter((e) => e.trustClass === 'mtls' || e.trustClass === 'identity' || e.trustClass === 'kms').length >= 3)
check('certificate-chain edges to external CA', edges.some((e) => e.trustClass === 'certificate-chain' && e.target.startsWith('ca:')))
check('internal issuer resolves to internal PKI edge (no duplicate CA node)', edges.some((e) => e.trustClass === 'certificate-chain' && e.target === A.pki) && !nodes.some((n) => n.id.startsWith('ca:') && /internal-pki/i.test(n.label)))
check('repeated handshake observes one vendor link', edges.filter((e) => e.source === A.api1 && e.target === STRIPE && e.provenance === 'observed').length === 1)
check('internal host match is inferred', edges.some((e) => e.source === A.web && e.target === A.idp && e.provenance === 'inferred'))
check('external issuer key posture is unknown', nodes.find((n) => n.id.startsWith('ca:'))?.posture === 'unknown')
const workflow = buildExposureWorkflowGraph(nodes, edges, null, [])
check('workflow preserves real asset IDs and evidence link directions', workflow.nodes.length === nodes.length && workflow.edges.every((edge, index) =>
  edge.source === edges[index].source && edge.target === edges[index].target && edge.provenance === edges[index].provenance))
const onlyWeb = buildExposureWorkflowGraph(nodes.filter((node) => node.id === A.web), edges, null, [])
check('workflow filtering drops links to hidden nodes', onlyWeb.nodes.length === 1 && onlyWeb.edges.length === 0)

console.log('\n— Five-state posture')
check('vulnerable posture derived', byId.get(A.pki)?.posture === 'vulnerable')
check('pqc posture derived', byId.get(A.db)?.posture === 'pqc')
check('migrating posture from active migration job', byId.get(A.k8s)?.posture === 'migrating')
check('unknown posture for evidence-free asset', byId.get(A.ws)?.posture === 'unknown')
check('crypto posture counts sum to all loaded assets', intel.summary.quantumVulnerable + intel.summary.hybridAssets + intel.summary.pqcReadyAssets + intel.summary.unknownPosture === 11)
check('active jobs preserve the measured crypto posture', intel.summary.migrationInProgress === 1 && byId.get(A.k8s)?.cryptoPosture === 'vulnerable')
check('posture ignores bare policy labels and distinguishes symmetric crypto', classifyAlgorithmClass('Hybrid readiness policy') === 'unknown' && classifyAlgorithmClass('AES-256-GCM') === 'safe')
check('X25519 and hybrid signature evidence are recognized', classifyAlgorithmClass('X25519') === 'vulnerable' && classifyAlgorithmClass('Ed25519 + ML-DSA-65') === 'hybrid')

console.log('\n— Categorisation & tiers')
check('classifyAssetCategory maps PKI', classifyAssetCategory('pki service', 'internal-pki.acme.local') === 'pki')
check('classifyAssetCategory maps KMS', classifyAssetCategory('kms', 'vault-kms') === 'kms')
check('tier ladder: CA before endpoints', tierForCategory('certificate-authority').tier < tierForCategory('workstation').tier)
check('node carries tier label', Boolean(byId.get(A.db)?.tierLabel))

console.log('\n— Summary metrics')
check('total assets reflects loaded inventory', intel.summary.totalAssets === 11)
check('internet-facing counts require recorded exposure', intel.summary.internetFacingAssets === 1)
check('third-party dependencies counted', intel.summary.thirdPartyDependencies >= 2)
check('critical trust relationships flagged', intel.summary.criticalTrustRelationships >= 1)
check('certificate KPI counts certificate records', intel.summary.pkiObjects === 3)
check('trust KPI excludes inferred connections', intel.summary.trustRelationships === recordedEdges.length && intel.summary.inferredRelationships === edges.length - recordedEdges.length)
check('max blast radius computed', intel.summary.maxBlastRadius >= 4)
check('readiness scores mirror snapshot', intel.summary.quantumReadinessScore === 34 && intel.summary.quantumRiskScore === 61)

console.log('\n— Blast Radius Analysis™')
const blastWeb = computeBlastRadius(nodes, recordedEdges, A.web)
check('direct dependencies correct for portal', blastWeb.direct.includes(A.lb), `direct=${JSON.stringify(blastWeb.direct)}`)
check('indirect propagation reaches api tier', blastWeb.indirect.includes(A.api1) && blastWeb.indirect.includes(A.api2))
check('trust-chain members tracked', computeBlastRadius(nodes, edges, A.api1).trustChain.length >= 1)
check('depth map includes root at 0', blastWeb.depths[A.web] === 0)
check('environments aggregated', blastWeb.environments.length >= 1)
check('blast radius excludes inferred shortcuts', !blastWeb.direct.includes(A.idp))

console.log('\n— Migration Impact Analysis™')
const impact = computeMigrationImpact(nodes, edges, A.api1)
check('impact computed for payments-api', impact !== null)
if (impact) {
  check('proposed migration includes ML-DSA signature target', impact.proposedMigration.some((p) => /ML-DSA/.test(p.to)))
  check('proposed migration includes key-establishment target', impact.proposedMigration.some((p) => /ML-KEM/.test(p.to)))
  check('what-will-break lists dependent API', impact.potentialInterruptions.some((i) => /orders-api/.test(i.label)))
  check('what-will-break lists third-party compatibility', impact.potentialInterruptions.some((i) => /stripe/i.test(i.label)))
  check('remediation includes certificate replacement', impact.requiredRemediation.some((r) => /certificate/i.test(r.label)))
  check('estimated risk is High/Critical for critical hub', impact.estimatedRisk === 'Critical' || impact.estimatedRisk === 'High')
  check('downtime window bounded and non-zero', impact.estimatedDowntimeHours.max > 0 && impact.estimatedDowntimeHours.max <= 24)
  check('confidence within honest bounds', impact.confidencePct >= 35 && impact.confidencePct <= 95)
}
check('pqcTargetFor maps SHA-1 → SHA3', /SHA3/.test(pqcTargetFor('SHA-1', false)?.to || ''))
check('pqcTargetFor leaves ML-KEM untouched', pqcTargetFor('ML-KEM-768', false) === null)

console.log('\n— Migration Dependency Intelligence™')
const waveTiers = intel.migrationOrder.waves.map((w) => w.tierLabel)
const pkiWaveIndex = waveTiers.findIndex((t) => /PKI/.test(t))
const webWaveIndex = waveTiers.findIndex((t) => /Web/.test(t))
check('waves generated', intel.migrationOrder.waves.length >= 4, `got ${intel.migrationOrder.waves.length}`)
check('PKI wave precedes web wave', pkiWaveIndex !== -1 && webWaveIndex !== -1 && pkiWaveIndex < webWaveIndex, `pki=${pkiWaveIndex} web=${webWaveIndex}`)
check('PQC-ready asset excluded from waves', !intel.migrationOrder.waves.some((w) => w.nodes.some((n) => n.id === A.db)))
check('mTLS pair must migrate together', intel.migrationOrder.clusters.some((c) => {
  const ids = c.nodes.map((n) => n.id)
  return ids.includes(A.api1) && ids.includes(A.api2)
}))
check('vulnerable KMS flagged as blocker', intel.migrationOrder.blockers.some((b) => b.id === A.kms))
check('vulnerable vendor flagged as blocker', intel.migrationOrder.blockers.some((b) => b.id === STRIPE))

console.log('\n— Third-party dependency analysis')
check('external CA row present', intel.thirdParty.some((t) => /digicert/i.test(t.vendor) && t.category === 'External PKI / CA'))
check('payment vendor categorised', intel.thirdParty.some((t) => /stripe/i.test(t.vendor) && t.category === 'Payment Gateway'))
check('vendor readiness reflects observed crypto', intel.thirdParty.find((t) => /stripe/i.test(t.vendor))?.readiness === 'vulnerable')
check('vendor rows carry connected assets', (intel.thirdParty.find((t) => /stripe/i.test(t.vendor))?.connectedAssets || 0) >= 1)

console.log('\n— Live evidence scope')
const scoped = assembleExposureIntelligence(SNAPSHOT, {
  ...ROWS,
  assets: [...ROWS.assets,
    { id: 'same-name', name: 'internal-pki.acme.local', status: 'active' },
    { id: 'old-asset', name: 'Archived asset', status: 'archived' }],
  runtimeEvents: [...ROWS.runtimeEvents, { asset_id: A.web, host: 'internal-pki.acme.local', algorithm: 'ML-KEM-768' }],
  migrationJobs: [...ROWS.migrationJobs, { id: 'sim-job', asset_id: A.ws, status: 'running', metadata: { dryRun: true } }],
  scanResults: [...ROWS.scanResults,
    { id: 'scan-low', asset_id: 'same-name', algorithm: 'A recorded low finding', threat_level: 'low', created_at: NOW },
    { id: 'unlinked', asset_name: 'internal-pki.acme.local', algorithm: 'Unlinked high finding', threat_level: 'high' }],
})
const scopedNodes = new Map(scoped.graph.nodes.map((node) => [node.id, node]))
check('same-name assets count only their own findings, including low severity', scopedNodes.get('same-name')?.findingsCount === 1)
check('archived asset is omitted and dry run is excluded from live migration counts', !scopedNodes.has('old-asset') && scoped.summary.migrationInProgress === 1)
check('ambiguous telemetry name is disclosed without inventing a dependency', !scoped.graph.edges.some((edge) => edge.source === A.web && (edge.target === A.pki || edge.target === 'same-name')) &&
  scoped.evidence.limitations?.some((notice) => notice.includes('more than one workspace asset')) === true)

console.log('\n— AI Migration Advisor™ & prioritisation')
check('advisor recommends trust-anchor-first sequencing', intel.advisor.recommendations.some((r) => r.category === 'Sequencing'))
check('advisor recommends hybrid TLS for internet-facing endpoints', intel.advisor.recommendations.some((r) => /Hybrid TLS/i.test(r.title)))
check('advisor flags vendor dependency', intel.advisor.recommendations.some((r) => r.category === 'Third-Party'))
check('estimates mirror snapshot complexity/duration', intel.advisor.estimates.migrationComplexity === 48 && intel.advisor.estimates.estimatedDurationWeeks === 22)
check('risk prioritisation ranked and explained', intel.riskPrioritization.length >= 5 && intel.riskPrioritization[0].priorityScore >= intel.riskPrioritization[intel.riskPrioritization.length - 1].priorityScore && intel.riskPrioritization[0].drivers.length > 0)
check('critical internet-facing hub prioritised Critical/High', ['Critical', 'High'].includes(byId.get(A.api1)?.priority || ''))

/* ================= 2. Honest empty state ============================ */
console.log('\n— Empty-state honesty (no fabrication)')
const EMPTY_SNAPSHOT = { ...(SNAPSHOT as unknown as Record<string, unknown>), hasData: false, criticalFindings: [], inventory: { ...(SNAPSHOT as unknown as { inventory: Record<string, number> }).inventory, assetsAssessed: 0, trustRelationships: 0, certificatesAnalyzed: 0 } } as unknown as AssembleSnapshot
const EMPTY_ROWS: ExposureRawRows = { assets: [], relationships: [], cryptoInventory: [], certificates: [], runtimeEvents: [], scanResults: [], cryptoExposures: [], connectorAccounts: [], migrationJobs: [] }
const empty = assembleExposureIntelligence(EMPTY_SNAPSHOT, EMPTY_ROWS)
check('empty tenant → hasData false', empty.hasData === false)
check('empty tenant → zero nodes/edges', empty.graph.nodes.length === 0 && empty.graph.edges.length === 0)
check('empty tenant → zero summary metrics', Object.values(empty.summary).every((v) => v === 0))
check('empty tenant → no waves/clusters/blockers', empty.migrationOrder.waves.length === 0 && empty.migrationOrder.clusters.length === 0 && empty.migrationOrder.blockers.length === 0)
check('empty tenant → no advisor recommendations', empty.advisor.recommendations.length === 0)
check('empty tenant → guidance note present', /discovery scan/i.test(empty.evidence.note))

console.log(`\n${passed + failed} checks — ${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
