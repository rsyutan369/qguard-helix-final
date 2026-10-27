/**
 * Vendor / Trust / Lab workflow graphs — offline invariant check.
 *
 * Runs the PURE graph builders over the real External Trust engine output for a
 * fixture tenant and asserts the honesty guarantees the canvases depend on:
 *
 *   1. Every drawn edge is backed by a field of the authoritative payload, and
 *      every edge states its provenance and basis.
 *   2. A vendor claim, an unknown and a stale assessment are never green.
 *   3. Trust edges point the way trust is delegated; inferred anchors and
 *      name-matched vendors are marked inferred.
 *   4. Path explanations: broken ⇒ untrusted, inferred ⇒ unknown.
 *   5. Collapsing a group can never hide a worse status.
 *   6. The lab never colours a step without an experiment for that exact
 *      profile; ML-KEM is never drawn as a signature; evidence-derived passes
 *      are not green.
 *   7. Layout is deterministic and never stacks two nodes on one slot.
 *   8. An empty tenant produces empty graphs, not placeholders.
 *
 * Run: npx tsx tools/trust-workflow-graph-check.ts
 */

import type { Row } from '../src/lib/migration/asset-intelligence'
import {
  buildExternalTrustIntelligence, computeEcosystemBlastRadius, toExperimentRecord,
  type ExperimentRecord, type ExternalTrustInputs, type VendorRecord,
} from '../src/lib/ecosystem/external-trust-intelligence'
import {
  LAB_MODE_PROFILE, algorithmStatus, buildEcosystemGraph, buildLabGraph, buildTrustGraph, buildVendorGraph, explainTrustPath,
  latestExperimentFor, vendorStatus,
} from '../src/components/trust-workflow/graph-builders'
import {
  buildAdjacency, collapseGroups, layoutLayered, shortestPath, traverse, worstStatus,
  type WorkflowGraph, type WorkflowNode,
} from '../src/components/trust-workflow/graph-model'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const NOW = Date.parse('2026-08-10T00:00:00Z')

const assets: Row[] = [
  { id: 'a1', name: 'checkout.company.com', type: 'web-service', environment: 'production', service_owner: 'Payments', criticality: 'critical', metadata: { hostname: 'checkout.company.com' } },
  { id: 'a2', name: 'identity.company.com', type: 'identity-provider', environment: 'production', service_owner: 'Identity', criticality: 'high', metadata: { hostname: 'identity.company.com' } },
  { id: 'a3', name: 'reporting-batch', type: 'service', environment: 'staging', service_owner: 'Data', criticality: 'low', metadata: {} },
]
const certificates: Row[] = [
  { id: 'c1', asset_id: 'a1', name: 'checkout.company.com', subject: 'checkout.company.com', algorithm: 'ECDSA P-256', key_size: 256, issuer: "Let's Encrypt", not_before: '2026-05-01T00:00:00Z', not_after: '2026-11-01T00:00:00Z', is_quantum_safe: false, metadata: {} },
  { id: 'c2', asset_id: 'a2', name: 'identity-internal', subject: 'identity-internal', algorithm: 'RSA-2048', key_size: 2048, issuer: 'identity-internal', not_before: '2026-01-01T00:00:00Z', not_after: '2026-08-01T00:00:00Z', is_quantum_safe: false, metadata: { signature_algorithm: 'sha1WithRSAEncryption' } },
]
const inputs: ExternalTrustInputs = {
  assets,
  assetRelationships: [
    { id: 'r1', source_asset_id: 'a1', target_asset_id: 'a2', relationship_type: 'authenticates-with' },
    { id: 'r2', source_asset_id: 'a3', target_asset_id: 'a1', relationship_type: 'calls' },
  ],
  certificates,
  cryptoInventory: [
    { id: 'i1', asset_id: 'a1', item_type: 'protocol', name: 'edge tls', algorithm: 'ECDSA P-256', protocol: 'TLS 1.3', is_vulnerable: true, metadata: {} },
  ],
  cryptoExposures: [], scanResults: [], scannerEvidence: [], scannerAlerts: [],
  runtimeEvents: [
    { id: 'e1', asset_id: 'a1', asset_name: 'checkout', host: 'api.stripe.com', protocol: 'TLS 1.3', algorithm: 'ECDHE-RSA', key_exchange_algorithm: 'X25519', severity: 'medium', is_legacy: true, observed_at: '2026-08-05T00:00:00Z' },
    { id: 'e2', asset_id: 'a2', asset_name: 'identity', host: 'login.microsoftonline.com', protocol: 'TLS 1.3', algorithm: 'X25519MLKEM768', key_exchange_algorithm: 'X25519MLKEM768', severity: 'low', is_pqc: true, observed_at: '2026-08-05T00:00:00Z' },
  ],
  connectorAccounts: [{ id: 'k1', provider: 'aws', display_name: 'AWS Production', status: 'connected', last_sync_at: '2026-08-08T00:00:00Z', metadata: {} }],
  vendorAssessments: [
    { id: 'v1', vendor_name: 'Acme Payments', category: 'payment', readiness_status: 'Quantum Ready', score: 90, support: { 'ML-KEM': 'Ready' }, metadata: {}, last_assessed_at: '2026-07-01T00:00:00Z' },
  ],
  trustFindings: [], migrationJobs: [], complianceEvidence: [], evidenceRequests: [], experiments: [],
  now: NOW,
}

function endpointsExist(graph: WorkflowGraph): boolean {
  const ids = new Set(graph.nodes.map((node) => node.id))
  return graph.edges.every((edge) => ids.has(edge.source) && ids.has(edge.target))
}

function main() {
  const intel = buildExternalTrustIntelligence(inputs)
  const vendors = intel.vendors.records

  /* ---------------------------------------------------------------- */
  console.log('\n[1] Vendor graph edges are backed by the payload')
  const vendorGraph = buildVendorGraph({ vendors, ecosystem: intel.ecosystem, now: NOW })
  assert(vendorGraph.nodes.some((node) => node.kind === 'vendor'), 'vendors are drawn', String(vendorGraph.nodes.filter((node) => node.kind === 'vendor').length))
  assert(endpointsExist(vendorGraph), 'no dangling edges')
  assert(vendorGraph.edges.every((edge) => edge.basis.length > 0 && Boolean(edge.provenance)), 'every edge has provenance and a basis')
  const vendorById = new Map(vendors.map((vendor) => [`vendor:${vendor.id}`, vendor]))
  const consumes = vendorGraph.edges.filter((edge) => edge.relation === 'consumes')
  assert(consumes.every((edge) => vendorById.get(edge.target)?.linkedAssetIds.includes(edge.source.slice('asset:'.length)) === true),
    'every consumes edge is a linkedAssetId of its vendor', `${consumes.length} edge(s)`)
  const operates = vendorGraph.edges.filter((edge) => edge.relation === 'operates')
  assert(operates.every((edge) => {
    const vendor = vendorById.get(edge.source)!
    return vendor.observedHosts.some((host) => edge.target.endsWith(`:${host}`))
  }), 'every surface edge is an observed host of its vendor', `${operates.length} edge(s)`)
  const usesAlgorithm = vendorGraph.edges.filter((edge) => edge.relation === 'uses-algorithm')
  assert(usesAlgorithm.every((edge) => vendorById.get(edge.source)!.position.currentAlgorithms.some((algorithm) => edge.target === `algo:${algorithm.toLowerCase()}`)),
    'every algorithm edge is an observed algorithm of its vendor', `${usesAlgorithm.length} edge(s)`)
  const dependsOn = vendorGraph.edges.filter((edge) => edge.relation === 'depends-on')
  assert(dependsOn.every((edge) => intel.ecosystem.edges.some((stored) => stored.kind === 'depends-on' && stored.source === edge.source && stored.target === edge.target)),
    'every depends-on edge is a stored asset relationship', `${dependsOn.length} edge(s)`)
  assert(vendorGraph.edges.filter((edge) => edge.relation === 'operates-ca').every((edge) => edge.provenance === 'inferred'), 'vendor→CA (name match) edges are inferred')

  const noEcosystem = buildVendorGraph({ vendors, ecosystem: null, now: NOW })
  assert(noEcosystem.nodes.every((node) => node.layer !== 1 && node.layer !== 0), 'without the ecosystem snapshot no internal systems are drawn')
  assert(noEcosystem.notices.some((notice) => /still loading/i.test(notice)), 'the missing ecosystem is disclosed')

  const capped = buildVendorGraph({ vendors, ecosystem: intel.ecosystem, maxVendors: 1, now: NOW })
  assert(vendors.length < 2 || capped.notices.some((notice) => /Showing 1 of/.test(notice)), 'a capped vendor set is disclosed')
  if (vendors.length >= 2) {
    const last = [...vendors].sort((a, b) => a.name.localeCompare(b.name)).at(-1)!
    const pinned = buildVendorGraph({ vendors, ecosystem: intel.ecosystem, maxVendors: 1, pinnedVendorIds: [last.id], now: NOW })
    assert(pinned.nodes.some((node) => node.id === `vendor:${last.id}`), 'a pinned vendor is drawn even beyond the cap')
  }

  /* ---------------------------------------------------------------- */
  console.log('\n[2] Claims, unknowns and stale assessments are never green')
  const acme = vendors.find((vendor) => vendor.name === 'Acme Payments')
  if (acme) {
    const status = vendorStatus(acme, NOW)
    assert(status.status !== 'verified', 'a vendor that only CLAIMS readiness is not green', `${acme.readiness} → ${status.status}`)
  }
  for (const vendor of vendors) {
    if (vendor.readiness === 'unknown') assert(vendorStatus(vendor, NOW).status === 'unknown', `${vendor.name}: unknown readiness renders gray`)
  }
  const template = vendors[0]
  const fakeReady: VendorRecord = { ...template, readiness: 'ready', lastAssessmentAt: '2025-01-01T00:00:00Z', nextReviewAt: '2025-06-01T00:00:00Z' }
  assert(vendorStatus(fakeReady, NOW).status === 'unknown', 'a stale "ready" assessment is downgraded to gray')
  const freshReady: VendorRecord = { ...template, readiness: 'ready', lastAssessmentAt: '2026-08-01T00:00:00Z', nextReviewAt: '2026-12-01T00:00:00Z' }
  assert(vendorStatus(freshReady, NOW).status === 'verified', 'positive control: a fresh measured "ready" is green')
  const critical: VendorRecord = { ...template, readiness: 'not-ready', risk: 'critical' }
  assert(vendorStatus(critical, NOW).status === 'critical', 'not-ready with critical risk is red')

  /* ---------------------------------------------------------------- */
  console.log('\n[3] Trust graph direction and inference')
  const trustGraph = buildTrustGraph({ chains: intel.trust.chains, findings: intel.trust.findings, certificates: intel.trust.certificates, showAlgorithms: true, showVendors: true })
  assert(endpointsExist(trustGraph), 'no dangling edges')
  const byId = new Map(trustGraph.nodes.map((node) => [node.id, node]))
  const issued = trustGraph.edges.filter((edge) => edge.relation === 'issued' || edge.relation === 'self-signs')
  assert(issued.length > 0 && issued.every((edge) => byId.get(edge.target)?.kind === 'certificate'), 'issuance edges point CA → certificate', `${issued.length}`)
  assert(trustGraph.edges.filter((edge) => edge.relation === 'authenticates').every((edge) => byId.get(edge.source)?.kind === 'certificate'), 'certificates point to the systems they authenticate')
  assert(trustGraph.edges.filter((edge) => edge.relation === 'anchors').every((edge) => edge.provenance === 'inferred'), 'inferred roots are marked inferred')
  assert(trustGraph.nodes.filter((node) => node.kind === 'trust-anchor').every((node) => node.inferred === true), 'trust-anchor nodes are flagged inferred')
  assert(trustGraph.edges.filter((edge) => edge.relation === 'operates').every((edge) => edge.provenance === 'inferred'), 'vendor → CA edges are inferred')
  const certificateIds = new Set(intel.trust.certificates.map((certificate) => `cert:${certificate.id}`))
  assert(trustGraph.nodes.filter((node) => node.kind === 'certificate').every((node) => certificateIds.has(node.id)), 'every certificate node is a real certificate record')

  /* ---------------------------------------------------------------- */
  console.log('\n[4] Path explanations')
  const anchor = trustGraph.nodes.find((node) => node.kind === 'trust-anchor')
  const leCert = trustGraph.nodes.find((node) => node.id === 'cert:c1')
  if (anchor && leCert) {
    const path = shortestPath(trustGraph.edges, anchor.id, leCert.id)
    assert(Boolean(path?.directed), 'anchor → certificate path follows trust direction')
    if (path) assert(explainTrustPath(path, byId).verdict === 'unknown', 'a path through an inferred anchor is UNKNOWN, not trusted')
  }
  const expired = trustGraph.nodes.find((node) => node.id === 'cert:c2')
  const expiredApp = trustGraph.nodes.find((node) => node.id === 'asset:a2')
  if (expired && expiredApp) {
    const path = shortestPath(trustGraph.edges, expired.id, expiredApp.id)
    assert(expired.status === 'critical', 'an expired certificate is red', expired.statusLabel)
    if (path) assert(explainTrustPath(path, byId).verdict === 'untrusted', 'a path through an expired certificate is UNTRUSTED')
  }
  const reverse = leCert && anchor ? shortestPath(trustGraph.edges, leCert.id, anchor.id) : null
  assert(!reverse || !reverse.directed, 'an against-the-flow path is flagged undirected')
  const synthetic: WorkflowGraph = {
    nodes: [mk('x', 'verified'), mk('y', 'verified'), mk('z', 'verified')],
    edges: [{ id: 'x→y', source: 'x', target: 'y', relation: 'issued', label: 'Issued', provenance: 'explicit', basis: 'test' }],
    groups: [], notices: [], legend: {},
  }
  const clean = shortestPath(synthetic.edges, 'x', 'y')!
  assert(explainTrustPath(clean, new Map(synthetic.nodes.map((node) => [node.id, node]))).verdict === 'trusted', 'positive control: an all-valid explicit path is TRUSTED')
  assert(shortestPath(synthetic.edges, 'x', 'z') === null, 'disconnected components have no path')

  /* ---------------------------------------------------------------- */
  console.log('\n[5] Collapsing never hides a worse status')
  const grouped: WorkflowGraph = {
    nodes: [mk('v', 'verified'), { ...mk('h1', 'verified'), groupId: 'g' }, { ...mk('h2', 'critical'), groupId: 'g' }, { ...mk('h3', 'unknown'), groupId: 'g' }],
    edges: ['h1', 'h2', 'h3'].map((target) => ({ id: `v→${target}`, source: 'v', target, relation: 'operates', label: 'Operates', provenance: 'observed' as const, basis: 'test' })),
    groups: [{ id: 'g', label: 'Hosts', icon: 'surface' }], notices: [], legend: {},
  }
  const collapsed = collapseGroups(grouped, new Set(['g']))
  const aggregate = collapsed.nodes.find((node) => node.id === 'group:g')
  assert(aggregate?.status === 'critical', 'the aggregate takes the worst member status', aggregate?.status)
  assert(collapsed.edges.length === 1 && endpointsExist(collapsed), 'edges are rewired and de-duplicated')
  assert(worstStatus(['verified', 'unknown']) === 'unknown', 'unknown outranks verified in roll-ups')

  /* ---------------------------------------------------------------- */
  console.log('\n[6] The lab colours only what a matching experiment measured')
  const target = intel.lab.targets[0]
  assert(Boolean(target), 'a lab target exists')
  const hybridConfig = { protocol: 'TLS 1.3' as const, ...LAB_MODE_PROFILE.hybrid, symmetric: 'AES-256-GCM' as const, kdf: 'HKDF-SHA3-256' as const, hash: 'SHA3-256' as const }
  const untested = buildLabGraph({ config: hybridConfig, target, experiment: null, executionMode: 'simulation' })
  assert(untested.nodes.every((node) => node.status === 'unknown'), 'no experiment ⇒ every step is gray')
  assert(untested.nodes.filter((node) => node.kind === 'signature').every((node) => !/ML-KEM/i.test(node.label)), 'ML-KEM never appears as a signature')
  assert(untested.nodes.filter((node) => /ML-KEM/i.test(node.label)).every((node) => node.kind === 'kem' && /encapsulation/i.test(node.kindLabel)), 'ML-KEM is drawn as key encapsulation')
  assert(untested.nodes.some((node) => node.label === 'X25519') && untested.nodes.some((node) => node.label === 'ML-KEM-768'), 'hybrid mode shows both key-establishment components')
  assert(['X25519', 'Ed25519'].every((name) => algorithmStatus(name).label === 'Quantum-vulnerable'), 'X25519 / Ed25519 are classified quantum-vulnerable, not "unclassified"')
  assert(algorithmStatus('ML-KEM-768').status === 'verified' && algorithmStatus('AES-256-GCM').status === 'verified', 'positive control: ML-KEM-768 and AES-256-GCM are not flagged')
  const pq = buildLabGraph({ config: { ...hybridConfig, ...LAB_MODE_PROFILE['post-quantum'] }, target, experiment: null, executionMode: 'simulation' })
  assert(!pq.nodes.some((node) => node.label === 'X25519' || node.label === 'Ed25519'), 'post-quantum mode has no classical components')

  const experiment = toExperimentRecord({
    id: 'x1', created_at: '2026-08-09T00:00:00Z', execution_mode: 'controlled-test', outcome: 'conditional', risk: 'high', duration_ms: 420,
    payload: { target, proposedConfiguration: hybridConfig },
    result: {
      checks: [
        { key: 'protocol', label: 'Protocol', verdict: 'pass', method: 'measured', detail: 'TLS 1.3' },
        { key: 'crypto', label: 'Crypto', verdict: 'pass', method: 'evidence-derived', detail: 'stored evidence' },
        { key: 'certificate', label: 'Certificate', verdict: 'fail', method: 'measured', detail: 'ECDSA' },
      ],
      findings: [], basis: 'test',
      probe: { measured: true, negotiatedProtocol: 'TLSv1.3', hybridGroups: ['X25519MLKEM768'], hybridProbed: true, chainLength: 3 },
    },
  }, NOW)
  assert(experiment.probe?.negotiatedProtocol === 'TLSv1.3' && experiment.probe.hybridGroups[0] === 'X25519MLKEM768', 'the stored probe is projected onto the record')
  assert(toExperimentRecord({ id: 'x2', result: {} }, NOW).probe === null, 'no probe ⇒ probe is null, not an empty success')
  const tested = buildLabGraph({ config: hybridConfig, target, experiment, executionMode: 'controlled-test' })
  const status = (id: string) => tested.nodes.find((node) => node.id === id)?.status
  assert(status('handshake') === 'verified', 'measured pass ⇒ green')
  assert(status('kem') === 'hybrid', 'evidence-derived pass ⇒ blue, not green', status('kem'))
  assert(status('sig-0') === 'critical', 'measured failure ⇒ red')
  assert(status('session') !== 'verified', 'the session is never better than its weakest input', status('session'))
  assert(tested.nodes.find((node) => node.id === 'kem')?.meta?.some((line) => /X25519MLKEM768/.test(line)) === true, 'the accepted hybrid group is shown on the KEM step')
  const others: ExperimentRecord[] = [experiment, { ...experiment, id: 'x3', proposedConfiguration: { ...hybridConfig, ...LAB_MODE_PROFILE.classical } }]
  assert(latestExperimentFor(others, target.id, LAB_MODE_PROFILE['post-quantum']) === null, 'a different profile’s experiment is never reused')
  assert(latestExperimentFor(others, target.id, LAB_MODE_PROFILE.classical)?.id === 'x3', 'the matching profile is found')

  /* ---------------------------------------------------------------- */
  console.log('\n[7] Layout is deterministic and collision-free')
  const options = { nodeWidth: 240, nodeHeight: 128, columnGap: 104, rowGap: 26 }
  const first = layoutLayered(vendorGraph.nodes, vendorGraph.edges, options)
  const second = layoutLayered(vendorGraph.nodes, vendorGraph.edges, options)
  assert([...first.positions].every(([id, position]) => second.positions.get(id)?.x === position.x && second.positions.get(id)?.y === position.y), 'same graph ⇒ same positions')
  const slots = new Set([...first.positions.values()].map((position) => `${position.x}:${position.y}`))
  assert(slots.size === first.positions.size, 'no two nodes share a slot')
  const cyclic = layoutLayered([mk('p', 'unknown'), mk('q', 'unknown')], [
    { id: 'p→q', source: 'p', target: 'q', relation: 'r', label: 'r', provenance: 'explicit', basis: 't' },
    { id: 'q→p', source: 'q', target: 'p', relation: 'r', label: 'r', provenance: 'explicit', basis: 't' },
  ], options)
  assert(cyclic.positions.size === 2, 'a cycle lays out without hanging')

  /* ---------------------------------------------------------------- */
  console.log('\n[8] An empty tenant draws nothing')
  const empty = buildExternalTrustIntelligence({ ...inputs, assets: [], assetRelationships: [], certificates: [], cryptoInventory: [], runtimeEvents: [], connectorAccounts: [], vendorAssessments: [] })
  assert(buildVendorGraph({ vendors: empty.vendors.records, ecosystem: empty.ecosystem }).nodes.length === 0, 'no vendors ⇒ empty vendor graph')
  assert(buildTrustGraph({ chains: empty.trust.chains, findings: [], certificates: [], showAlgorithms: true, showVendors: true }).nodes.length === 0, 'no certificates ⇒ empty trust graph')

  /* ---------------------------------------------------------------- */
  console.log('\n[9] Ecosystem graph mirrors the stored relationships')
  const eco = buildEcosystemGraph({ nodes: intel.ecosystem.nodes, edges: intel.ecosystem.edges })
  assert(eco.nodes.length === intel.ecosystem.nodes.length, 'every ecosystem node is drawn when uncapped', `${eco.nodes.length}`)
  assert(eco.edges.length === intel.ecosystem.edges.length, 'every stored edge is drawn — none invented, none dropped', `${eco.edges.length}`)
  assert(endpointsExist(eco), 'no dangling edges')
  assert(eco.edges.every((edge) => {
    const stored = intel.ecosystem.edges.find((candidate) => candidate.source === edge.source && candidate.target === edge.target)
    return Boolean(stored) && (edge.provenance === 'inferred') === !stored!.explicit
  }), 'provenance follows the stored explicit flag')
  const ecoById = new Map(intel.ecosystem.nodes.map((node) => [node.id, node]))
  assert(eco.nodes.every((node) => ecoById.get(node.id)!.hasEvidence || node.status === 'unknown'), 'a node without evidence is gray')
  assert(eco.nodes.every((node) => node.status !== 'verified' || ecoById.get(node.id)!.readiness === 'ready'), 'green only where readiness is ready')
  const inheritedNodes = eco.nodes.filter((node) => {
    const source = ecoById.get(node.id)!
    return !source.external && source.kind !== 'vendor' && source.readiness !== 'unknown' && source.hasEvidence
  })
  assert(inheritedNodes.every((node) => /via vendors/.test(node.statusLabel)), 'inherited readiness on internal systems says so', `${inheritedNodes.length}`)
  const vendorNode = intel.ecosystem.nodes.find((node) => node.kind === 'vendor')
  if (vendorNode) {
    const radius = computeEcosystemBlastRadius(intel.ecosystem.nodes, intel.ecosystem.edges, vendorNode.id)
    const withBlast = buildEcosystemGraph({ nodes: intel.ecosystem.nodes, edges: intel.ecosystem.edges, blastRadius: radius })
    const affected = withBlast.nodes.filter((node) => node.badges?.some((badge) => /^Affected/.test(badge.label)))
    assert(affected.length === (radius?.affectedNodeIds.length ?? 0), 'every server blast-radius member is badged, and only those', `${affected.length}`)
    const upstream = traverse(buildAdjacency(withBlast.edges), vendorNode.id, 'upstream').nodeIds
    assert((radius?.affectedNodeIds ?? []).every((id) => upstream.has(id)), 'canvas "Upstream" covers the server blast radius')
    const capped = buildEcosystemGraph({ nodes: intel.ecosystem.nodes, edges: intel.ecosystem.edges, blastRadius: radius, maxNodes: 2 })
    assert(capped.notices.some((notice) => /Showing 2 of/.test(notice)), 'a capped ecosystem is disclosed')
    assert(capped.nodes.some((node) => node.id === vendorNode.id), 'the blast-radius origin survives the cap')
  }
  const filteredEco = buildEcosystemGraph({ nodes: intel.ecosystem.nodes, edges: intel.ecosystem.edges, kinds: new Set(['vendor']) })
  assert(filteredEco.nodes.every((node) => node.kind === 'vendor') && endpointsExist(filteredEco), 'a kind filter drops nodes and their edges together')

  console.log(failures ? `\n✗ ${failures} check(s) failed` : '\n✓ all workflow-graph invariants hold')
  process.exit(failures ? 1 : 0)
}

function mk(id: string, status: WorkflowNode['status']): WorkflowNode {
  return { id, kind: 'test', kindLabel: 'Test', label: id, status, statusLabel: status, icon: 'group', shape: 'card', searchText: id }
}

main()
