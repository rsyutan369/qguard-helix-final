/**
 * Offline verification for the Enterprise Migration Sandbox Digital Twin engine.
 *
 * Exercises the pure intelligence module (src/api-server/sandbox-twin.ts)
 * without a DB or server:
 *  - digital twin is a metadata-only clone with honest coverage/fidelity
 *  - dependency graph: observed asset_relationships + labeled inferred edges,
 *    blast radius, dependsOn/usedBy
 *  - topology heat map classification (green/yellow/orange/red)
 *  - failure predictions are evidence-backed (empty tenant → none)
 *  - performance benchmark discloses methodology and derives from the real mix
 *  - rollback analysis (RTO/RPO/success probability) and business impact
 *  - Sophia advisor scores/sequence and the production approval gate
 *  - 15-stage enterprise pipeline + 14 simulation types
 *
 * No server / Supabase required:  npx tsx tools/sandbox-twin-check.ts
 */
import {
  ENGINE_PIPELINE_STAGES,
  ENTERPRISE_PIPELINE,
  SIMULATION_TYPES,
  assembleTwinIntelligence,
  buildApprovalGate,
  buildBusinessImpact,
  buildDependencyGraph,
  buildDigitalTwin,
  buildPerformanceBenchmark,
  buildRollbackAnalysis,
  buildSophiaAdvisor,
  buildTelemetryFrame,
  buildTopology,
  classifyComponent,
  heatStatusForNode,
  pipelineStageForProgress,
  predictFailures,
  simulationTypeById,
  type TwinBundle,
} from '../src/api-server/sandbox-twin'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const NOW = Date.now()
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString()

/* ── Fixture: a realistic small tenant ─────────────────────────────────────── */
const assets = [
  { id: 'a-ca', name: 'Internal Root CA', type: 'pki', environment: 'production', region: 'us-east-1', service_owner: 'PKI Team', criticality: 'critical' },
  { id: 'a-lb', name: 'Edge Load Balancer', type: 'load-balancer', environment: 'production', region: 'us-east-1', service_owner: 'Platform', criticality: 'high' },
  { id: 'a-web', name: 'Customer Portal Web', type: 'web-server', environment: 'production', region: 'us-east-1', service_owner: 'Web Team', criticality: 'high' },
  { id: 'a-db', name: 'Payments Database', type: 'database', environment: 'production', region: 'us-east-1', service_owner: 'Data', criticality: 'critical' },
  { id: 'a-vpn', name: 'Site VPN Gateway', type: 'vpn', environment: 'production', region: 'eu-west-1', service_owner: 'Network', criticality: 'medium' },
  { id: 'a-dev', name: 'Dev Sandbox VM', type: 'vm', environment: 'development', region: 'us-east-1', service_owner: 'Eng', criticality: 'low' },
]
const inventory = [
  { id: 'i1', asset_id: 'a-ca', item_type: 'signing key', name: 'CA signing key', algorithm: 'RSA-4096', protocol: '', is_vulnerable: true, is_quantum_safe: false },
  { id: 'i2', asset_id: 'a-lb', item_type: 'tls', name: 'TLS terminator', algorithm: 'RSA-2048', protocol: 'TLS 1.2', is_vulnerable: true, is_quantum_safe: false },
  { id: 'i3', asset_id: 'a-web', item_type: 'tls', name: 'Legacy listener', algorithm: 'ECDSA P-256', protocol: 'TLSv1.1', is_vulnerable: true, is_quantum_safe: false },
  { id: 'i4', asset_id: 'a-db', item_type: 'cipher', name: 'Legacy column cipher', algorithm: '3DES', protocol: '', is_vulnerable: true, is_quantum_safe: false },
  { id: 'i5', asset_id: 'a-db', item_type: 'cipher', name: 'Envelope cipher', algorithm: 'AES-256-GCM', protocol: 'TLS 1.3', is_vulnerable: false, is_quantum_safe: true },
  { id: 'i6', asset_id: 'a-vpn', item_type: 'kex', name: 'IKE profile', algorithm: 'ECDH P-256', protocol: 'IKEv2', is_vulnerable: true, is_quantum_safe: false },
]
const exposures = [
  { id: 'e1', asset_id: 'a-ca', exposure_type: 'quantum_vulnerable_signing', severity: 'critical', detected_value: 'RSA-4096', created_at: iso(-3600e3) },
  { id: 'e2', asset_id: 'a-web', exposure_type: 'legacy_tls', severity: 'high', detected_value: 'TLSv1.1', created_at: iso(-7200e3) },
]
const certificates = [
  { id: 'c1', asset_id: 'a-lb', name: 'edge.example.com', algorithm: 'RSA-2048', key_size: 2048, issuer: 'Internal Root CA', not_after: iso(365 * 864e5), is_quantum_safe: false, is_expiring_soon: false, status: 'active' },
  { id: 'c2', asset_id: 'a-web', name: 'portal.example.com', algorithm: 'RSA-2048', key_size: 2048, issuer: 'Internal Root CA', not_after: iso(-10 * 864e5), is_quantum_safe: false, is_expiring_soon: true, status: 'expired' },
  { id: 'c3', asset_id: 'a-vpn', name: 'vpn.example.com', algorithm: 'ECDSA-P256', key_size: 256, issuer: '', not_after: iso(200 * 864e5), is_quantum_safe: false, is_expiring_soon: false, status: 'active' },
]
const relationships = [
  { id: 'r1', source_asset_id: 'a-web', target_asset_id: 'a-lb', relationship_type: 'served-by' },
  { id: 'r2', source_asset_id: 'a-web', target_asset_id: 'a-db', relationship_type: 'depends-on' },
  { id: 'r3', source_asset_id: 'a-lb', target_asset_id: 'a-ca', relationship_type: 'trusts' },
]
const runtimeEvents = [
  { id: 'rt1', asset_id: 'a-web', algorithm: 'RSA-2048', event_type: 'tls_handshake', created_at: iso(-4 * 60e3) },
  { id: 'rt2', asset_id: 'a-lb', algorithm: 'openssl 1.1.1', event_type: 'library_signal', created_at: iso(-9 * 60e3) },
  { id: 'rt3', asset_id: 'a-db', algorithm: 'AES-256-GCM', event_type: 'cert_validation', created_at: iso(-14 * 60e3) },
]
const workflows = [
  { id: 'w1', assetId: 'a-web', name: 'Sandbox: Customer Portal Web (RSA-2048 → ML-KEM-768)', status: 'completed', progress: 100, isSandbox: true, completedAt: iso(-3600e3), metadata: { snapshots: [{ id: 'snap1' }], approval: { decision: 'approve', decidedBy: 'ciso@example.com', decidedAt: iso(-1800e3) } } },
  { id: 'w2', assetId: 'a-lb', name: 'Sandbox: Edge Load Balancer (RSA-2048 → ML-KEM-768)', status: 'running', progress: 55, isSandbox: true, metadata: { evidence: { vulnerableItems: 2 } } },
  { id: 'w3', assetId: 'a-vpn', name: 'Remediation: VPN', status: 'queued', progress: 0, isSandbox: false, metadata: {} },
]
const events = [
  { id: 'ev1', migration_id: 'w1', event_type: 'sandbox-simulation-completed', severity: 'success', message: 'Simulation completed validation.', created_at: iso(-3600e3) },
  { id: 'ev2', migration_id: 'w2', event_type: 'sandbox-phase-transition', severity: 'info', message: 'Entered Compatibility Validation.', created_at: iso(-8 * 60e3) },
  { id: 'ev3', migration_id: 'w2', event_type: 'sandbox-warning', severity: 'warning', message: 'Legacy TLS detected during validation.', created_at: iso(-6 * 60e3) },
]

const bundle: TwinBundle = { assets, inventory, exposures, certificates, relationships, runtimeEvents, vulns: [], scanResults: [], events, workflows }
const EMPTY: TwinBundle = { assets: [], inventory: [], exposures: [], certificates: [], relationships: [], runtimeEvents: [], vulns: [], scanResults: [], events: [], workflows: [] }

/* [1] Pipeline + simulation types */
console.log('\n[1] Enterprise pipeline & simulation type catalog')
assert(ENTERPRISE_PIPELINE.length === 15, '15-stage lifecycle (Discovery → Production Ready)', `${ENTERPRISE_PIPELINE.length}`)
assert(ENGINE_PIPELINE_STAGES.length === 13, '13 engine-executable stages (approval gates excluded)', `${ENGINE_PIPELINE_STAGES.length}`)
assert(ENTERPRISE_PIPELINE[0].id === 'discovery' && ENTERPRISE_PIPELINE[14].id === 'production_ready', 'stage ordering anchored')
assert(pipelineStageForProgress(0).id === 'discovery', 'progress 0 → discovery')
assert(pipelineStageForProgress(55).id === 'compatibility_validation', 'progress 55 → compatibility validation', pipelineStageForProgress(55).id)
assert(pipelineStageForProgress(100).id === 'ai_risk_analysis', 'progress 100 → ai risk analysis (engine ceiling)', pipelineStageForProgress(100).id)
assert(SIMULATION_TYPES.length === 14, '14 simulation types', `${SIMULATION_TYPES.length}`)
assert(simulationTypeById('blue_green_migration').label === 'Blue-Green Migration', 'type lookup by id')
assert(simulationTypeById('nonsense').id === 'custom_scenario', 'unknown type falls back to custom scenario')

/* [2] Digital twin */
console.log('\n[2] Digital twin — metadata-only clone')
const twin = buildDigitalTwin(bundle)
assert(twin.summary.totalNodes === 6, 'clones every asset as a twin node', `${twin.summary.totalNodes}`)
assert(twin.summary.nodesWithEvidence === 6 - 1, 'evidence coverage counts real evidence only', `${twin.summary.nodesWithEvidence}`)
assert(twin.summary.coveragePct > 0 && twin.summary.fidelityPct > 0, 'coverage/fidelity computed', `${twin.summary.coveragePct}% / ${twin.summary.fidelityPct}%`)
assert(twin.isolation.scope === 'metadata-only' && twin.isolation.productionWrites === 'blocked', 'isolation attestation present')
assert(twin.isolation.excludedDatasets.includes('private keys'), 'private keys explicitly excluded from twin')
assert(classifyComponent({ type: 'pki', name: 'Internal Root CA' }).id === 'pki', 'CA classified as PKI')
assert(classifyComponent({ type: 'database', name: 'Payments Database' }).id === 'databases', 'database classified')
const caNode = twin.nodes.find((n) => n.id === 'a-ca')!
assert(caNode.criticalExposures === 1 && caNode.vulnerableItems === 1, 'twin node carries real exposure/vuln counts')
const emptyTwin = buildDigitalTwin(EMPTY)
assert(emptyTwin.summary.totalNodes === 0 && emptyTwin.summary.coveragePct === 0, 'empty tenant → honest empty twin')

/* [3] Dependency graph */
console.log('\n[3] Dependency graph — observed + inferred edges, blast radius')
const graph = buildDependencyGraph(bundle)
assert(graph.stats.observedEdges === 3, 'observed edges from asset_relationships', `${graph.stats.observedEdges}`)
assert(graph.stats.inferredEdges >= 1, 'inferred shared-issuer trust edges labeled', `${graph.stats.inferredEdges}`)
const webNode = graph.nodes.find((n) => n.id === 'a-web')!
assert(webNode.dependsOn.some((d) => d.id === 'a-lb') && webNode.dependsOn.some((d) => d.id === 'a-db'), 'dependsOn resolved')
const caGraphNode = graph.nodes.find((n) => n.id === 'a-ca')!
assert(caGraphNode.usedBy.length >= 1 && caGraphNode.blastRadius >= 2, 'CA blast radius includes transitive consumers', `radius ${caGraphNode.blastRadius}`)
assert(graph.nodes[0].impactScore >= graph.nodes[graph.nodes.length - 1].impactScore, 'nodes sorted by impact score')

/* [4] Topology heat map */
console.log('\n[4] Topology heat map')
const topology = buildTopology(twin)
assert(topology.zones.length === 2, 'zones grouped by environment', topology.zones.map((z) => z.environment).join(','))
assert(heatStatusForNode({ criticalExposures: 1, vulnerableItems: 0 }) === 'blocked', 'critical exposure → red/blocked')
assert(heatStatusForNode({ criticalExposures: 0, vulnerableItems: 3 }) === 'high_risk', '3+ vulns → orange/high risk')
assert(heatStatusForNode({ criticalExposures: 0, vulnerableItems: 1 }) === 'attention', 'some vulns → yellow/attention')
assert(heatStatusForNode({ criticalExposures: 0, vulnerableItems: 0, hasEvidence: true }) === 'ready', 'clean asset → green/ready')
assert(topology.totals.blocked >= 1, 'blocked assets counted in totals', `${topology.totals.blocked}`)

/* [5] Failure prediction */
console.log('\n[5] Failure prediction engine')
const predictions = predictFailures(bundle, graph)
const categories = predictions.predictions.map((p) => p.category)
assert(categories.includes('expired_certificates'), 'expired certificate predicted', categories.join(','))
assert(categories.includes('tls_incompatibility'), 'legacy TLS predicted')
assert(categories.includes('cipher_incompatibility'), '3DES cipher predicted')
assert(categories.includes('pki_failure'), 'vulnerable CA → PKI failure predicted')
assert(categories.includes('unsupported_library'), 'OpenSSL 1.x runtime signal predicted')
assert(predictions.predictions.every((p) => p.probabilityPct >= 5 && p.probabilityPct <= 95), 'probabilities bounded 5–95%')
assert(predictions.predictions.every((p) => p.evidence.length > 0 && p.recommendation.length > 0), 'every prediction carries evidence + recommendation')
assert(predictions.overallFailureProbabilityPct > 0, 'overall failure probability aggregated', `${predictions.overallFailureProbabilityPct}%`)
const noPred = predictFailures(EMPTY, buildDependencyGraph(EMPTY))
assert(noPred.predictions.length === 0 && noPred.overallFailureProbabilityPct === 0, 'empty tenant → zero predictions (no fabrication)')

/* [6] Performance benchmark */
console.log('\n[6] Performance benchmark (modeled, disclosed)')
const benchmark = buildPerformanceBenchmark(bundle)
assert(benchmark.available === true && benchmark.sampleSize === inventory.length, 'derived from real inventory sample', `${benchmark.sampleSize} records`)
assert(benchmark.methodology.toLowerCase().includes('modeled'), 'methodology disclosure present')
assert(benchmark.metrics.length === 13, '13 benchmark dimensions', `${benchmark.metrics.length}`)
const handshake = benchmark.metrics.find((m: any) => m.id === 'tls_handshake')!
assert(handshake.after < handshake.before && handshake.improved, 'hybrid ML-KEM improves handshake vs RSA-heavy mix', `${handshake.before} → ${handshake.after} ms`)
const certVal = benchmark.metrics.find((m: any) => m.id === 'cert_validation')!
assert(typeof certVal.deltaPct === 'number', 'delta computed for every metric')
assert(buildPerformanceBenchmark(EMPTY).available === false, 'empty inventory → benchmark unavailable (no fabricated numbers)')

/* [7] Business impact + rollback */
console.log('\n[7] Business impact + rollback analysis')
const impact = buildBusinessImpact(bundle, predictions)
assert(impact.categories.length > 0, 'business categories found from real assets', impact.categories.map((c: any) => c.id).join(','))
assert(impact.categories.some((c: any) => c.id === 'customer_portals'), 'customer portal category detected')
assert(buildBusinessImpact(EMPTY, noPred).categories.length === 0, 'empty tenant → no business impact categories')
const rollback = buildRollbackAnalysis(bundle, predictions)
assert(rollback.successProbabilityPct > 0 && rollback.rtoMinutes > 0, 'RTO + success probability computed', `RTO ${rollback.rtoMinutes}m, ${rollback.successProbabilityPct}%`)
assert(rollback.rpoMinutes === 5, 'snapshot coverage drives RPO', `${rollback.rpoMinutes}m`)
assert(rollback.restorationChecklist.length === 6, 'restoration checklist covers certs/keys/config/policies/trust/secrets')
assert(buildRollbackAnalysis(EMPTY, noPred).successProbabilityPct === 0, 'empty tenant → no rollback probability')

/* [8] Sophia advisor */
console.log('\n[8] Sophia AI Migration Advisor')
const context = { pqcReadiness: 33, riskScore: 48, complianceScore: 61 }
const sophia = buildSophiaAdvisor(bundle, twin, graph, predictions, benchmark, rollback, impact, context)
assert(sophia.migrationConfidencePct > 0 && sophia.migrationConfidencePct <= 100, 'migration confidence bounded', `${sophia.migrationConfidencePct}%`)
assert(sophia.compatibilityScorePct > 0, 'compatibility score computed', `${sophia.compatibilityScorePct}%`)
assert(sophia.recommendedSequence.length > 0 && sophia.recommendedSequence[0].component === 'pki', 'migration sequence starts at PKI trust anchor', sophia.recommendedSequence[0].label)
assert(sophia.recommendedSequence.every((s: any) => s.rationale.length > 0), 'every sequence step is explained')
assert(sophia.detectedBlockers.length > 0, 'critical blockers surfaced', `${sophia.detectedBlockers.length}`)
assert(sophia.rootCauses.some((r: string) => r.toLowerCase().includes('pki') || r.toLowerCase().includes('ca')), 'root cause names the CA tier')
assert(sophia.executiveSummary.length > 50, 'executive summary generated')
assert(sophia.evidenceBasis.assets === 6, 'evidence basis disclosed')
const emptySophia = buildSophiaAdvisor(EMPTY, emptyTwin, buildDependencyGraph(EMPTY), noPred, buildPerformanceBenchmark(EMPTY), buildRollbackAnalysis(EMPTY, noPred), buildBusinessImpact(EMPTY, noPred), { pqcReadiness: 0, riskScore: 100, complianceScore: 0 })
assert(emptySophia.verdict === 'no_data' && emptySophia.migrationConfidencePct === 0, 'empty tenant → no_data verdict, zero confidence')

/* [9] Approval gate */
console.log('\n[9] Production approval gate')
const gate = buildApprovalGate(bundle, sophia, predictions, rollback, context.complianceScore)
assert(['PASS', 'FAILED', 'PENDING'].includes(gate.simulationStatus), 'verdict is PASS/FAILED/PENDING', gate.simulationStatus)
assert(gate.simulationStatus === 'FAILED', 'critical blockers force FAILED verdict', gate.simulationStatus)
assert(gate.gates.length === 5, '5 readiness gates (confidence/rollback/risk/downtime/compliance)')
assert(gate.decisions.length === 1 && gate.decisions[0].decision === 'approve', 'approval decisions read from job metadata')
assert(gate.guarantee.toLowerCase().includes('never'), 'production-safety guarantee stated')
const cleanWorkflows = [{ ...workflows[0] }]
const cleanBundle: TwinBundle = { ...bundle, workflows: cleanWorkflows, exposures: [], certificates: [certificates[0]], inventory: [inventory[4]], runtimeEvents: [] }
const cleanGraph = buildDependencyGraph(cleanBundle)
const cleanPred = predictFailures(cleanBundle, cleanGraph)
const cleanTwin = buildDigitalTwin(cleanBundle)
const cleanRollback = buildRollbackAnalysis(cleanBundle, cleanPred)
const cleanImpact = buildBusinessImpact(cleanBundle, cleanPred)
const cleanSophia = buildSophiaAdvisor(cleanBundle, cleanTwin, cleanGraph, cleanPred, buildPerformanceBenchmark(cleanBundle), cleanRollback, cleanImpact, { pqcReadiness: 92, riskScore: 88, complianceScore: 85 })
const cleanGate = buildApprovalGate(cleanBundle, cleanSophia, cleanPred, cleanRollback, 85)
assert(cleanGate.simulationStatus === 'PASS', 'clean completed simulation → PASS', cleanGate.simulationStatus)
const emptyGate = buildApprovalGate(EMPTY, emptySophia, noPred, buildRollbackAnalysis(EMPTY, noPred), 0)
assert(emptyGate.simulationStatus === 'PENDING', 'no simulations → PENDING')

/* [10] Telemetry frame + full assembly */
console.log('\n[10] Telemetry frame + aggregate assembly')
const frame = buildTelemetryFrame(bundle)
assert(frame.series.length === 6, '6 real bucketed series')
assert(frame.totals.cryptoOps === 3, 'runtime events bucketed', `${frame.totals.cryptoOps}`)
assert(frame.totals.warnings === 1 && frame.totals.errors === 0, 'severities bucketed from migration events')
assert(frame.simulatedLoad.length === 1 && frame.simulatedLoad[0].modeled === true, 'running-sim load labeled modeled')
const intel = assembleTwinIntelligence(bundle, context)
for (const key of ['digitalTwin', 'dependencyGraph', 'topology', 'failurePrediction', 'performanceBenchmark', 'rollbackAnalysis', 'businessImpact', 'sophia', 'approvalGate', 'timeline', 'telemetryFrame', 'simulationTypes', 'pipeline'] as const) {
  assert((intel as any)[key] != null, `assembled payload includes ${key}`)
}
assert(intel.timeline.length === events.length, 'timeline built from real migration events', `${intel.timeline.length}`)

console.log(`\n${failures === 0 ? '✅ ALL CHECKS PASSED' : `❌ ${failures} CHECK(S) FAILED`}`)
process.exit(failures === 0 ? 0 : 1)
