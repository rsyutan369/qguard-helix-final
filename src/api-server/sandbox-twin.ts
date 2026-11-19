/**
 * Enterprise Migration Sandbox — Digital Twin & Simulation Intelligence Engine.
 *
 * PURE module: every builder takes already-loaded tenant rows and returns
 * derived intelligence. No I/O, no Supabase client, no side effects — the
 * sandbox router owns loading; tools/sandbox-twin-check.ts owns verification.
 *
 * Honesty contract (platform Data Accuracy Rules):
 *  - The twin clones METADATA ONLY from real scanned evidence. It never reads
 *    or copies payload data, keys, or secret material.
 *  - Anything modeled (performance deltas, simulated load) is explicitly
 *    labeled `modeled`/`methodology` — it is never presented as live
 *    production measurement.
 *  - Empty tenants produce honest empty states, never fabricated metrics.
 */

type Row = Record<string, any>

export type TwinBundle = {
  assets: Row[]
  inventory: Row[]
  exposures: Row[]
  certificates: Row[]
  relationships: Row[]
  runtimeEvents: Row[]
  vulns: Row[]
  scanResults: Row[]
  events: Row[]
  workflows: Row[]
}

const num = (v: unknown) => (Number.isFinite(Number(v)) ? Number(v) : 0)
const str = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v))
const lower = (v: unknown) => str(v).toLowerCase()
const clampPct = (v: number, lo = 0, hi = 100) => Math.max(lo, Math.min(hi, Math.round(v)))

function groupByAsset(rows: Row[], key = 'asset_id') {
  const map = new Map<string, Row[]>()
  for (const row of rows || []) {
    const id = str(row?.[key])
    if (!id) continue
    const list = map.get(id) || []
    list.push(row)
    map.set(id, list)
  }
  return map
}

/* ═══════════════════════════════════════════════════════════════════════════
   ENTERPRISE MIGRATION PIPELINE — 15-stage lifecycle
   Stages 1-13 are executed by the simulation engine (progress 0→100).
   Stages 14-15 are human/approval gates resolved by the Production Approval
   Gate — the engine never auto-approves production deployment.
   ═══════════════════════════════════════════════════════════════════════════ */

export const ENTERPRISE_PIPELINE = [
  { id: 'discovery', label: 'Discovery', detail: 'Tenant asset inventory and scanner sessions loaded into simulation scope.', at: 0 },
  { id: 'crypto_inventory', label: 'Crypto Inventory', detail: 'Cryptographic inventory, algorithms, protocols, and key material metadata normalized.', at: 5 },
  { id: 'dependency_mapping', label: 'Dependency Mapping', detail: 'Asset relationships, trust chains, and blast radius resolved from the dependency graph.', at: 11 },
  { id: 'business_impact', label: 'Business Impact Analysis', detail: 'Criticality, ownership, and downstream business system exposure evaluated.', at: 17 },
  { id: 'migration_planning', label: 'Migration Planning', detail: 'Target PQC algorithms, sequencing, and rollback strategy assigned.', at: 23 },
  { id: 'digital_twin', label: 'Digital Twin Generation', detail: 'Metadata-only digital twin cloned; production isolation attested.', at: 29 },
  { id: 'pqc_simulation', label: 'PQC Migration Simulation', detail: 'PQC replacement plan exercised against the digital twin only.', at: 36 },
  { id: 'compatibility_validation', label: 'Compatibility Validation', detail: 'Handshake, protocol, library, and dependency compatibility validated.', at: 50 },
  { id: 'performance_benchmark', label: 'Performance Benchmark', detail: 'Handshake, latency, throughput, and resource impact benchmarked before vs after.', at: 60 },
  { id: 'security_validation', label: 'Security Validation', detail: 'Downgrade resistance, key material handling, and policy conformance verified.', at: 69 },
  { id: 'rollback_validation', label: 'Rollback Validation', detail: 'Snapshot restore, RTO/RPO, and recovery posture exercised in the twin.', at: 78 },
  { id: 'compliance_validation', label: 'Compliance Validation', detail: 'Review tenant control evidence separately from simulation results.', at: 86 },
  { id: 'ai_risk_analysis', label: 'AI Risk Analysis', detail: 'Sophia correlates results into confidence, blockers, and residual risk.', at: 93 },
  { id: 'executive_approval', label: 'Executive Approval', detail: 'Simulation verdict awaits an explicit operator approval decision.', at: 100, gate: true },
  { id: 'production_ready', label: 'Planner review', detail: 'Review empirical evidence and change approval in Migration Planner.', at: 100, gate: true },
] as const

export const ENGINE_PIPELINE_STAGES = ENTERPRISE_PIPELINE.filter((s) => !('gate' in s && s.gate))

export function pipelineStageForProgress(progress: number) {
  const executable = ENGINE_PIPELINE_STAGES
  return [...executable].reverse().find((stage) => progress >= stage.at) || executable[0]
}

/* ═══════════════════════════════════════════════════════════════════════════
   SIMULATION TYPE CATALOG — 14 enterprise scenario types
   ═══════════════════════════════════════════════════════════════════════════ */

export type SimulationTypeDef = {
  id: string
  label: string
  description: string
  focus: string[]
  baseDurationMs: number
  perAssetMs: number
  recommendedFor: string
}

export const SIMULATION_TYPES: SimulationTypeDef[] = [
  { id: 'quick_validation', label: 'Quick Validation', description: 'Fast twin pass validating target algorithms, certificate posture, and obvious blockers.', focus: ['compatibility_validation', 'security_validation'], baseDurationMs: 90_000, perAssetMs: 4_000, recommendedFor: 'Pre-flight checks before deeper scenarios' },
  { id: 'compatibility_test', label: 'Compatibility Test', description: 'Deep protocol/library/dependency compatibility validation across the selected scope.', focus: ['dependency_mapping', 'compatibility_validation'], baseDurationMs: 160_000, perAssetMs: 7_000, recommendedFor: 'Legacy stacks, mixed TLS estates' },
  { id: 'performance_benchmark', label: 'Performance Benchmark', description: 'Before/after handshake, latency, throughput, and resource benchmarking in the twin.', focus: ['performance_benchmark'], baseDurationMs: 200_000, perAssetMs: 8_000, recommendedFor: 'Latency-sensitive services and gateways' },
  { id: 'certificate_rotation', label: 'Certificate Rotation Simulation', description: 'Certificate replacement/rotation rehearsal including chain and expiry validation.', focus: ['crypto_inventory', 'compatibility_validation', 'rollback_validation'], baseDurationMs: 150_000, perAssetMs: 6_000, recommendedFor: 'PKI and certificate estates' },
  { id: 'tls_migration', label: 'TLS Migration', description: 'RSA/ECC → ML-KEM hybrid TLS key-exchange migration across selected endpoints.', focus: ['pqc_simulation', 'compatibility_validation', 'performance_benchmark'], baseDurationMs: 220_000, perAssetMs: 8_000, recommendedFor: 'Web servers, APIs, load balancers' },
  { id: 'pki_migration', label: 'PKI Migration', description: 'CA hierarchy, trust chain, and issuance migration to ML-DSA signature suites.', focus: ['dependency_mapping', 'pqc_simulation', 'security_validation'], baseDurationMs: 260_000, perAssetMs: 10_000, recommendedFor: 'Internal CAs and PKI hierarchies' },
  { id: 'hybrid_migration', label: 'Hybrid Migration', description: 'Classical+PQC hybrid deployment (X25519+ML-KEM / Ed25519+ML-DSA) with backward compatibility.', focus: ['pqc_simulation', 'compatibility_validation'], baseDurationMs: 230_000, perAssetMs: 8_500, recommendedFor: 'Estates requiring gradual client migration' },
  { id: 'full_enterprise_migration', label: 'Full Enterprise Migration', description: 'End-to-end enterprise rehearsal across every pipeline stage for the selected scope.', focus: ENGINE_PIPELINE_STAGES.map((s) => s.id), baseDurationMs: 320_000, perAssetMs: 12_000, recommendedFor: 'Program-level readiness rehearsal' },
  { id: 'incremental_migration', label: 'Incremental Migration', description: 'Wave-based migration validating one dependency tier at a time.', focus: ['dependency_mapping', 'pqc_simulation'], baseDurationMs: 210_000, perAssetMs: 9_000, recommendedFor: 'Large estates with deep dependency chains' },
  { id: 'blue_green_migration', label: 'Blue-Green Migration', description: 'Parallel twin environments validating cutover and instant traffic switch-back.', focus: ['pqc_simulation', 'rollback_validation'], baseDurationMs: 240_000, perAssetMs: 9_000, recommendedFor: 'Zero-downtime cutover rehearsal' },
  { id: 'canary_migration', label: 'Canary Migration', description: 'Progressive rollout simulation with per-step health gates and automatic abort.', focus: ['pqc_simulation', 'performance_benchmark', 'rollback_validation'], baseDurationMs: 250_000, perAssetMs: 9_500, recommendedFor: 'High-traffic customer-facing services' },
  { id: 'disaster_recovery_validation', label: 'Disaster Recovery Validation', description: 'Failure injection with full recovery, restore, and continuity validation.', focus: ['rollback_validation', 'security_validation'], baseDurationMs: 270_000, perAssetMs: 10_000, recommendedFor: 'Regulated and continuity-critical estates' },
  { id: 'rollback_simulation', label: 'Rollback Simulation', description: 'Dedicated rollback rehearsal: snapshot restore, trust chain and config restoration, RTO/RPO measurement.', focus: ['rollback_validation'], baseDurationMs: 170_000, perAssetMs: 6_500, recommendedFor: 'Change-management evidence before production windows' },
  { id: 'custom_scenario', label: 'Custom Migration Scenario', description: 'Operator-defined source→target scenario executed through the full enterprise pipeline.', focus: ['pqc_simulation'], baseDurationMs: 220_000, perAssetMs: 8_000, recommendedFor: 'Bespoke algorithm or protocol transitions' },
]

export function simulationTypeById(id: string): SimulationTypeDef {
  return SIMULATION_TYPES.find((t) => t.id === lower(id)) || SIMULATION_TYPES[SIMULATION_TYPES.length - 1]
}

/* ═══════════════════════════════════════════════════════════════════════════
   COMPONENT CLASSIFICATION — maps real asset types onto enterprise categories
   ═══════════════════════════════════════════════════════════════════════════ */

const COMPONENT_RULES: Array<{ id: string; label: string; pattern: RegExp }> = [
  { id: 'web_servers', label: 'Web Servers & Portals', pattern: /web|http|nginx|apache|portal|frontend|site|cdn/ },
  { id: 'api_gateway', label: 'API Gateways & Services', pattern: /api|gateway|graphql|rest|endpoint|microservice/ },
  { id: 'load_balancers', label: 'Load Balancers & Proxies', pattern: /load.?balanc|proxy|haproxy|envoy|ingress|lb\b/ },
  { id: 'kubernetes', label: 'Kubernetes & Containers', pattern: /kubernetes|k8s|container|docker|pod|cluster|namespace/ },
  { id: 'databases', label: 'Databases & Data Stores', pattern: /database|db\b|postgres|mysql|sql|mongo|redis|storage|data.?store|warehouse/ },
  { id: 'vpn', label: 'VPN & Tunnels', pattern: /vpn|tunnel|ipsec|wireguard|ike/ },
  { id: 'ssh', label: 'SSH & Bastion Hosts', pattern: /ssh|bastion|jump/ },
  { id: 'pki', label: 'PKI & Certificate Authorities', pattern: /\bca\b|pki|certificate.?authority|issuer|cert.?service/ },
  { id: 'identity', label: 'Identity & Authentication', pattern: /identity|idp|iam|auth|sso|oidc|oauth|ldap|directory/ },
  { id: 'kms_hsm', label: 'KMS / HSM / Secrets', pattern: /kms|hsm|vault|secret|key.?manage/ },
  { id: 'email', label: 'Email & Messaging', pattern: /mail|smtp|imap|exchange|messag/ },
  { id: 'payment', label: 'Payment & Billing', pattern: /payment|billing|checkout|card|pos\b/ },
  { id: 'mobile_backend', label: 'Mobile Backends', pattern: /mobile|ios|android|app.?backend/ },
  { id: 'cloud', label: 'Cloud Infrastructure', pattern: /cloud|aws|azure|gcp|s3|lambda|ec2|vm\b|instance/ },
  { id: 'applications', label: 'Applications & Services', pattern: /./ },
]

export function classifyComponent(asset: Row): { id: string; label: string } {
  const text = `${lower(asset?.type)} ${lower(asset?.name)}`
  const match = COMPONENT_RULES.find((rule) => rule.pattern.test(text))
  return match ? { id: match.id, label: match.label } : { id: 'applications', label: 'Applications & Services' }
}

/* ═══════════════════════════════════════════════════════════════════════════
   DIGITAL TWIN BUILDER — metadata-only clone of the tenant crypto environment
   ═══════════════════════════════════════════════════════════════════════════ */

export function buildDigitalTwin(bundle: TwinBundle) {
  const now = new Date().toISOString()
  const invByAsset = groupByAsset(bundle.inventory)
  const expByAsset = groupByAsset(bundle.exposures)
  const certByAsset = groupByAsset(bundle.certificates)
  const runtimeByAsset = groupByAsset(bundle.runtimeEvents)
  const relCount = (bundle.relationships || []).length

  const nodes = (bundle.assets || []).slice(0, 500).map((asset) => {
    const inv = invByAsset.get(str(asset.id)) || []
    const exp = expByAsset.get(str(asset.id)) || []
    const certs = certByAsset.get(str(asset.id)) || []
    const runtime = runtimeByAsset.get(str(asset.id)) || []
    const vulnerable = inv.filter((i) => i.is_vulnerable || i.is_quantum_safe === false).length
    const critical = exp.filter((e) => lower(e.severity) === 'critical').length
    const component = classifyComponent(asset)
    return {
      id: str(asset.id),
      name: str(asset.name) || 'Unnamed asset',
      type: str(asset.type) || 'service',
      component: component.id,
      componentLabel: component.label,
      environment: str(asset.environment) || 'unknown',
      region: str(asset.region) || null,
      owner: str(asset.service_owner) || 'Unassigned',
      criticality: lower(asset.criticality) || 'medium',
      algorithms: Array.from(new Set(inv.map((i) => str(i.algorithm).trim()).filter(Boolean))).slice(0, 8),
      protocols: Array.from(new Set(inv.map((i) => str(i.protocol).trim()).filter(Boolean))).slice(0, 6),
      inventoryItems: inv.length,
      vulnerableItems: vulnerable,
      exposures: exp.length,
      criticalExposures: critical,
      certificates: certs.length,
      quantumSafeCerts: certs.filter((c) => c.is_quantum_safe).length,
      expiringCerts: certs.filter((c) => c.is_expiring_soon).length,
      runtimeSignals: runtime.length,
      hasEvidence: inv.length > 0 || exp.length > 0 || certs.length > 0 || runtime.length > 0,
    }
  })

  const withEvidence = nodes.filter((n) => n.hasEvidence).length
  const coveragePct = nodes.length > 0 ? clampPct((withEvidence / nodes.length) * 100) : 0
  // Fidelity blends evidence coverage with relationship + runtime depth: a twin
  // with edges and runtime signals reproduces behavior more faithfully.
  const fidelityPct = nodes.length > 0
    ? clampPct(coveragePct * 0.6 + Math.min(100, (relCount / Math.max(1, nodes.length)) * 100) * 0.2 + Math.min(100, ((bundle.runtimeEvents || []).length / 50) * 100) * 0.2)
    : 0

  const componentGroups = new Map<string, { id: string; label: string; assets: number; vulnerable: number; critical: number }>()
  for (const node of nodes) {
    const group = componentGroups.get(node.component) || { id: node.component, label: node.componentLabel, assets: 0, vulnerable: 0, critical: 0 }
    group.assets++
    if (node.vulnerableItems > 0) group.vulnerable++
    if (node.criticalExposures > 0) group.critical++
    componentGroups.set(node.component, group)
  }

  return {
    generatedAt: now,
    summary: {
      totalNodes: nodes.length,
      nodesWithEvidence: withEvidence,
      coveragePct,
      fidelityPct,
      inventoryRecordsCloned: (bundle.inventory || []).length,
      certificatesCloned: (bundle.certificates || []).length,
      trustRelationships: relCount,
      runtimeSignalsSampled: (bundle.runtimeEvents || []).length,
      environments: Array.from(new Set(nodes.map((n) => n.environment))).slice(0, 12),
    },
    isolation: {
      scope: 'metadata-only',
      productionWrites: 'blocked',
      guarantees: [
        'Only asset metadata, configuration descriptors, certificate metadata, cipher inventory, relationships, and runtime signal metadata are cloned.',
        'No production keys, secrets, payload data, or credentials are read or copied.',
        'Simulations execute exclusively against the twin — production rows are never mutated by the sandbox engine.',
        'Rollback and restore rehearsals operate on twin snapshots stored in simulation metadata.',
      ],
      excludedDatasets: ['private keys', 'secret values', 'credentials', 'application payload data', 'production configuration writes'],
    },
    componentGroups: Array.from(componentGroups.values()).sort((a, b) => b.assets - a.assets),
    nodes: nodes.slice(0, 300),
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   DEPENDENCY GRAPH — observed asset_relationships + bounded inferred edges
   ═══════════════════════════════════════════════════════════════════════════ */

export function buildDependencyGraph(bundle: TwinBundle) {
  const assetIds = new Set((bundle.assets || []).map((a) => str(a.id)))
  const nameById = new Map((bundle.assets || []).map((a) => [str(a.id), str(a.name) || 'Unnamed asset']))
  const edges: Array<{ source: string; target: string; type: string; origin: 'observed' | 'inferred' }> = []
  const seen = new Set<string>()

  const pushEdge = (source: string, target: string, type: string, origin: 'observed' | 'inferred') => {
    if (!source || !target || source === target) return
    if (!assetIds.has(source) || !assetIds.has(target)) return
    const key = `${source}→${target}:${type}`
    if (seen.has(key) || edges.length >= 800) return
    seen.add(key)
    edges.push({ source, target, type, origin })
  }

  for (const rel of bundle.relationships || []) {
    const source = str(rel.source_asset_id || rel.parent_asset_id || rel.from_asset_id)
    const target = str(rel.target_asset_id || rel.child_asset_id || rel.to_asset_id)
    pushEdge(source, target, str(rel.relationship_type) || 'depends-on', 'observed')
  }

  // Inferred trust edges: assets sharing the same certificate issuer inside the
  // same environment very likely share a trust chain. Bounded and labeled.
  const issuerGroups = new Map<string, string[]>()
  const envByAsset = new Map((bundle.assets || []).map((a) => [str(a.id), lower(a.environment)]))
  for (const cert of bundle.certificates || []) {
    const issuer = str(cert.issuer).trim()
    const assetId = str(cert.asset_id)
    if (!issuer || !assetId || !assetIds.has(assetId)) continue
    const key = `${issuer}::${envByAsset.get(assetId) || ''}`
    const list = issuerGroups.get(key) || []
    if (!list.includes(assetId)) list.push(assetId)
    issuerGroups.set(key, list)
  }
  for (const members of issuerGroups.values()) {
    if (members.length < 2 || members.length > 12) continue
    const [anchor, ...rest] = members
    for (const other of rest) pushEdge(other, anchor, 'shared-issuer-trust', 'inferred')
  }

  const dependsOn = new Map<string, Set<string>>()
  const usedBy = new Map<string, Set<string>>()
  for (const edge of edges) {
    if (!dependsOn.has(edge.source)) dependsOn.set(edge.source, new Set())
    dependsOn.get(edge.source)!.add(edge.target)
    if (!usedBy.has(edge.target)) usedBy.set(edge.target, new Set())
    usedBy.get(edge.target)!.add(edge.source)
  }

  // Blast radius: transitive upstream consumers (who breaks if this migrates badly).
  const blastRadius = (id: string) => {
    const visited = new Set<string>()
    const queue = [...(usedBy.get(id) || [])]
    while (queue.length > 0 && visited.size < 200) {
      const next = queue.shift()!
      if (visited.has(next)) continue
      visited.add(next)
      for (const upstream of usedBy.get(next) || []) if (!visited.has(upstream)) queue.push(upstream)
    }
    return visited
  }

  const invByAsset = groupByAsset(bundle.inventory)
  const expByAsset = groupByAsset(bundle.exposures)
  const certByAsset = groupByAsset(bundle.certificates)

  const nodes = (bundle.assets || []).slice(0, 300).map((asset) => {
    const id = str(asset.id)
    const impacted = blastRadius(id)
    const critical = (expByAsset.get(id) || []).filter((e) => lower(e.severity) === 'critical').length
    const vulnerable = (invByAsset.get(id) || []).filter((i) => i.is_vulnerable || i.is_quantum_safe === false).length
    return {
      id,
      name: str(asset.name) || 'Unnamed asset',
      type: str(asset.type) || 'service',
      environment: str(asset.environment) || 'unknown',
      criticality: lower(asset.criticality) || 'medium',
      dependsOn: [...(dependsOn.get(id) || [])].slice(0, 20).map((d) => ({ id: d, name: nameById.get(d) || d })),
      usedBy: [...(usedBy.get(id) || [])].slice(0, 20).map((d) => ({ id: d, name: nameById.get(d) || d })),
      certificates: (certByAsset.get(id) || []).slice(0, 8).map((c) => ({ id: str(c.id), name: str(c.name) || 'certificate', algorithm: str(c.algorithm), quantumSafe: !!c.is_quantum_safe })),
      blastRadius: impacted.size,
      impactedAssets: [...impacted].slice(0, 15).map((d) => ({ id: d, name: nameById.get(d) || d })),
      criticalExposures: critical,
      vulnerableItems: vulnerable,
      impactScore: clampPct(impacted.size * 10 + critical * 20 + vulnerable * 6 + (lower(asset.criticality) === 'critical' ? 25 : lower(asset.criticality) === 'high' ? 12 : 0)),
    }
  }).sort((a, b) => b.impactScore - a.impactScore)

  return {
    nodes,
    edges: edges.slice(0, 800),
    stats: {
      totalNodes: nodes.length,
      observedEdges: edges.filter((e) => e.origin === 'observed').length,
      inferredEdges: edges.filter((e) => e.origin === 'inferred').length,
      connectedNodes: nodes.filter((n) => n.dependsOn.length > 0 || n.usedBy.length > 0).length,
      maxBlastRadius: nodes.reduce((max, n) => Math.max(max, n.blastRadius), 0),
    },
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   TOPOLOGY / RISK HEAT MAP — green / yellow / orange / red zones
   ═══════════════════════════════════════════════════════════════════════════ */

export type HeatStatus = 'ready' | 'attention' | 'high_risk' | 'blocked'

export function heatStatusForNode(node: { criticalExposures: number; vulnerableItems: number; expiringCerts?: number; quantumSafeCerts?: number; certificates?: number; hasEvidence?: boolean }): HeatStatus {
  if (node.criticalExposures > 0) return 'blocked'
  if (node.vulnerableItems >= 3 || (num(node.expiringCerts) > 0 && num(node.certificates) > 0)) return 'high_risk'
  if (node.vulnerableItems > 0 || node.hasEvidence === false) return 'attention'
  return 'ready'
}

export function buildTopology(twin: ReturnType<typeof buildDigitalTwin>) {
  const zones = new Map<string, { environment: string; assets: any[]; counts: Record<HeatStatus, number> }>()
  for (const node of twin.nodes) {
    const zone = zones.get(node.environment) || { environment: node.environment, assets: [], counts: { ready: 0, attention: 0, high_risk: 0, blocked: 0 } }
    const status = heatStatusForNode(node)
    zone.counts[status]++
    if (zone.assets.length < 60) {
      zone.assets.push({ id: node.id, name: node.name, type: node.type, component: node.componentLabel, criticality: node.criticality, status })
    }
    zones.set(node.environment, zone)
  }
  const zoneList = Array.from(zones.values()).sort((a, b) => (b.counts.blocked * 3 + b.counts.high_risk * 2) - (a.counts.blocked * 3 + a.counts.high_risk * 2))
  const totals: Record<HeatStatus, number> = { ready: 0, attention: 0, high_risk: 0, blocked: 0 }
  for (const zone of zoneList) for (const key of Object.keys(totals) as HeatStatus[]) totals[key] += zone.counts[key]
  return { zones: zoneList, totals }
}

/* ═══════════════════════════════════════════════════════════════════════════
   FAILURE PREDICTION ENGINE — evidence-backed predictions with probability
   ═══════════════════════════════════════════════════════════════════════════ */

export function predictFailures(bundle: TwinBundle, graph: ReturnType<typeof buildDependencyGraph>) {
  const nowMs = Date.now()
  const nameById = new Map((bundle.assets || []).map((a) => [str(a.id), str(a.name) || 'Unnamed asset']))
  const predictions: Array<{
    id: string; category: string; label: string; probabilityPct: number; severity: string
    affectedAssets: string[]; evidence: string; recommendation: string
  }> = []

  const affectedNames = (ids: Iterable<string>) => Array.from(new Set([...ids].map((id) => nameById.get(id) || id))).slice(0, 8)
  const push = (category: string, label: string, count: number, scopeSize: number, severity: string, ids: Iterable<string>, evidence: string, recommendation: string, weight = 1) => {
    if (count <= 0) return
    const ratio = scopeSize > 0 ? count / scopeSize : 0
    const probabilityPct = clampPct(12 + ratio * 70 * weight + Math.min(20, count * 3), 5, 95)
    predictions.push({ id: `pred-${category}`, category, label, probabilityPct, severity, affectedAssets: affectedNames(ids), evidence, recommendation })
  }

  const certs = bundle.certificates || []
  const expired = certs.filter((c) => { const t = Date.parse(str(c.not_after)); return Number.isFinite(t) && t < nowMs })
  push('expired_certificates', 'Expired certificates will fail validation immediately after cutover', expired.length, Math.max(1, certs.length), 'critical',
    expired.map((c) => str(c.asset_id)).filter(Boolean),
    `${expired.length} certificate(s) already past not_after in scanned certificate inventory.`,
    'Rotate expired certificates before executing any migration wave.', 1.4)

  /**
   * Certificate replacement risk.
   *
   * This used to count `expiring + nonPqc` against `certs.length`, so a tenant
   * whose certificates are all classical — i.e. EVERY tenant that has not yet
   * migrated — scored ratio 1.0 and read "88% probability of certificate
   * replacement failure". Being non-PQC is the REASON to migrate, not evidence
   * the migration will fail; a prediction that reads ~88% for everyone carries
   * no information and, here, was the single blocker holding the approval gate.
   *
   * Failure risk now comes from certificates that are expiring during the change
   * window (a real replacement hazard). The non-PQC count is migration SCOPE and
   * is reported as such, contributing only a small bounded increment. The
   * affected-asset list is built from the same rows the count came from — it
   * previously listed only the expiring subset, so a count of 2 rendered with an
   * empty asset list.
   */
  const expiring = certs.filter((c) => c.is_expiring_soon && !expired.includes(c))
  const nonPqcCerts = certs.filter((c) => c.is_quantum_safe === false)
  push('certificate_failure', 'Certificate replacement failures during migration window', expiring.length, Math.max(1, certs.length), 'high',
    expiring.map((c) => str(c.asset_id)).filter(Boolean),
    `${expiring.length} certificate(s) expiring during the migration window; ${nonPqcCerts.length} classical certificate(s) in replacement scope.`,
    'Pre-stage ML-DSA / hybrid replacement certificates and validate chains in the twin first.')
  if (expiring.length === 0 && nonPqcCerts.length > 0) {
    // Scope, not a failure prediction — stated at a low, bounded probability so
    // it appears in planning without masquerading as a blocker.
    push('certificate_replacement_scope', 'Classical certificates require reissuance under ML-DSA', nonPqcCerts.length, Math.max(1, certs.length), 'medium',
      nonPqcCerts.map((c) => str(c.asset_id)).filter(Boolean),
      `${nonPqcCerts.length} of ${certs.length} certificate(s) are classical and must be reissued — expected pre-migration state, not a detected fault.`,
      'Size the PKI reissuance wave and validate ML-DSA chain building in the twin before the cutover window.', 0.25)
  }

  const inv = bundle.inventory || []
  const legacyTls = inv.filter((i) => /tls\s*1\.0|tls\s*1\.1|tlsv1\.0|tlsv1\.1|ssl\s*3|sslv3/.test(`${lower(i.protocol)} ${lower(i.name)}`))
  push('tls_incompatibility', 'Legacy TLS endpoints cannot negotiate hybrid PQC key exchange', legacyTls.length, Math.max(1, inv.length), 'high',
    legacyTls.map((i) => str(i.asset_id)).filter(Boolean),
    `${legacyTls.length} inventory record(s) pinned to TLS 1.0/1.1/SSLv3.`,
    'Upgrade endpoints to TLS 1.3 before enabling X25519+ML-KEM hybrid groups.', 1.2)

  const weakCiphers = inv.filter((i) => /3des|rc4|md5|sha-?1(?!\d)|des(?!ign)/.test(`${lower(i.algorithm)} ${lower(i.name)}`))
  push('cipher_incompatibility', 'Deprecated cipher primitives blocked by PQC-era policy', weakCiphers.length, Math.max(1, inv.length), 'high',
    weakCiphers.map((i) => str(i.asset_id)).filter(Boolean),
    `${weakCiphers.length} record(s) using 3DES/RC4/MD5/SHA-1 class primitives.`,
    'Replace with AES-256-GCM and SHA3-256 during the same migration change window.')

  const runtimeText = (bundle.runtimeEvents || []).map((e) => JSON.stringify(e || {}).toLowerCase())
  const legacyLibSignals = runtimeText.filter((t) => /openssl\s*1\.|openssl-1|java\s*[678](?![\d.])|\.net\s*framework|libssl1/.test(t)).length
  const legacyLibInv = inv.filter((i) => /openssl\s*1\.|java\s*[678](?![\d.])|\.net\s*framework/.test(`${lower(i.name)} ${lower(i.protocol)}`))
  push('unsupported_library', 'Legacy crypto libraries without ML-KEM/ML-DSA support', legacyLibSignals + legacyLibInv.length, Math.max(1, inv.length + runtimeText.length), 'medium',
    legacyLibInv.map((i) => str(i.asset_id)).filter(Boolean),
    `${legacyLibSignals + legacyLibInv.length} legacy OpenSSL 1.x / Java ≤8 / .NET Framework signal(s) across inventory and runtime telemetry.`,
    'Upgrade to OpenSSL 3.x + oqs-provider (or platform-native PQC runtimes) before cutover.')

  const orphanIssuer = certs.filter((c) => !str(c.issuer).trim())
  push('broken_trust_chain', 'Trust chains that cannot be revalidated post-migration', orphanIssuer.length, Math.max(1, certs.length), 'medium',
    orphanIssuer.map((c) => str(c.asset_id)).filter(Boolean),
    `${orphanIssuer.length} certificate(s) without resolvable issuer metadata.`,
    'Resolve issuer chains in PKI inventory; rehearse chain replacement with a PKI Migration simulation.')

  const pkiNodes = (bundle.assets || []).filter((a) => classifyComponent(a).id === 'pki')
  const pkiVulnerable = pkiNodes.filter((a) => (groupByAsset(inv).get(str(a.id)) || []).some((i) => i.is_vulnerable || i.is_quantum_safe === false))
  push('pki_failure', 'PKI hierarchy failure while re-issuing under ML-DSA', pkiVulnerable.length, Math.max(1, pkiNodes.length || 1), 'critical',
    pkiVulnerable.map((a) => str(a.id)),
    `${pkiVulnerable.length} of ${pkiNodes.length} CA/PKI asset(s) still carry quantum-vulnerable inventory.`,
    'Migrate the internal CA hierarchy first — every dependent certificate inherits its risk.', 1.3)

  const criticalAssets = (bundle.assets || []).filter((a) => ['critical', 'high'].includes(lower(a.criticality)))
  const invByAsset = groupByAsset(inv)
  const criticalWithVuln = criticalAssets.filter((a) => (invByAsset.get(str(a.id)) || []).some((i) => i.is_vulnerable || i.is_quantum_safe === false))
  push('application_failure', 'Business-critical application failures during algorithm swap', criticalWithVuln.length, Math.max(1, criticalAssets.length || 1), 'high',
    criticalWithVuln.map((a) => str(a.id)),
    `${criticalWithVuln.length} critical/high-criticality asset(s) with vulnerable crypto inventory.`,
    'Run Full Enterprise or Canary simulations against these assets before scheduling production windows.')

  const highBlast = graph.nodes.filter((n) => n.blastRadius >= 3 && (n.criticalExposures > 0 || n.vulnerableItems > 0))
  push('dependency_failure', 'Dependency cascade — one failed migration breaks downstream consumers', highBlast.length, Math.max(1, graph.nodes.length || 1), 'high',
    highBlast.map((n) => n.id),
    `${highBlast.length} asset(s) with blast radius ≥ 3 and open crypto risk.`,
    'Sequence migrations bottom-up through the dependency graph; validate consumers in the twin after each wave.')

  const noEvidence = (bundle.assets || []).filter((a) => !(invByAsset.get(str(a.id)) || []).length && !(groupByAsset(bundle.exposures).get(str(a.id)) || []).length)
  push('network_failure', 'Unscanned crypto surface — unknown negotiation behavior at cutover', noEvidence.length, Math.max(1, (bundle.assets || []).length || 1), 'medium',
    noEvidence.map((a) => str(a.id)),
    `${noEvidence.length} asset(s) have no crypto inventory or exposure evidence yet.`,
    'Extend discovery scans/collectors to close visibility gaps before simulating production waves.', 0.7)

  const failedJobs = (bundle.workflows || []).filter((w) => lower(w.status) === 'failed')
  push('service_outage', 'Service outage risk based on failed migration history', failedJobs.length, Math.max(1, (bundle.workflows || []).length || 1), 'high',
    failedJobs.map((w) => str(w.assetId || w.asset_id)).filter(Boolean),
    `${failedJobs.length} migration workflow(s) previously failed for this tenant.`,
    'Retry failed workflows in the sandbox, resolve root causes, and require PASS before approval.')

  predictions.sort((a, b) => b.probabilityPct - a.probabilityPct)
  const overall = predictions.length === 0
    ? 0
    : clampPct(predictions.reduce((sum, p) => sum + p.probabilityPct * (p.severity === 'critical' ? 1.25 : p.severity === 'high' ? 1 : 0.6), 0) / (predictions.length * 1.1))

  return { predictions: predictions.slice(0, 12), overallFailureProbabilityPct: overall }
}

/* ═══════════════════════════════════════════════════════════════════════════
   PERFORMANCE BENCHMARK ENGINE — before vs after, modeled from the REAL
   algorithm mix. Methodology is disclosed on every payload; these are twin
   projections, never live production measurements.
   ═══════════════════════════════════════════════════════════════════════════ */

export const BENCHMARK_METHODOLOGY =
  'Modeled Level 3 scenario. Local heuristics use the observed tenant algorithm mix. Use the cryptographic lab for measurements and representative staging hardware for production sizing.'

export function buildPerformanceBenchmark(bundle: TwinBundle) {
  const inv = bundle.inventory || []
  if (inv.length === 0) {
    return { available: false, methodology: BENCHMARK_METHODOLOGY, sampleSize: 0, metrics: [] as any[], algorithmMix: { rsaSharePct: 0, eccSharePct: 0, pqcSharePct: 0, symmetricSharePct: 0 } }
  }
  const total = inv.length
  const share = (pattern: RegExp) => inv.filter((i) => pattern.test(`${lower(i.algorithm)} ${lower(i.name)} ${lower(i.protocol)}`)).length / total
  const rsa = share(/rsa/)
  const ecc = share(/ecdsa|ecdh|ec-|p-256|p-384|x25519|ed25519|elliptic/)
  const pqc = share(/ml-kem|ml-dsa|kyber|dilithium|slh-dsa|sphincs/)
  const weak = share(/3des|rc4|md5|sha-?1(?!\d)/)
  const symmetric = share(/aes|chacha/)
  const classical = Math.max(0.05, rsa + ecc)

  // Before profile weighted by discovered classical primitives; after profile
  // reflects hybrid X25519+ML-KEM / ML-DSA replacement of that same mix.
  const metric = (id: string, label: string, unit: string, before: number, after: number, betterWhenLower: boolean, note: string) => {
    const b = Math.round(before * 100) / 100
    const a = Math.round(after * 100) / 100
    const deltaPct = b !== 0 ? Math.round(((a - b) / b) * 1000) / 10 : 0
    const improved = betterWhenLower ? a <= b : a >= b
    return { id, label, unit, before: b, after: a, deltaPct, improved, betterWhenLower, note }
  }

  const metrics = [
    metric('tls_handshake', 'TLS Handshake Time', 'ms', 118 + rsa * 64 + ecc * 22 + weak * 30, (118 + rsa * 64 + ecc * 22) * 0.58 + 21, true,
      'ML-KEM-768 encapsulation is faster than RSA-2048 key transport; hybrid adds ~1.2 KB handshake payload.'),
    metric('key_exchange', 'Key Exchange Time', 'ms', 34 + rsa * 41 + ecc * 9, 11 + pqc * 2 + 6, true,
      'ML-KEM keygen/encaps outperforms RSA and matches X25519-class latency in hybrid mode.'),
    metric('cert_validation', 'Certificate Validation', 'ms', 22 + rsa * 12 + weak * 15, 26 + 8, true,
      'ML-DSA-65 signatures are larger (~3.3 KB) — verification is fast but chain transfer grows.'),
    metric('cipher_negotiation', 'Cipher Negotiation', 'ms', 9 + weak * 22, 7, true,
      'Removing legacy suites shortens negotiation lists.'),
    metric('auth_time', 'Authentication Time', 'ms', 41 + rsa * 30, 33 + 9, true,
      'Signature verification with ML-DSA-65 is faster than RSA-2048 verify at equivalent security.'),
    metric('cpu_usage', 'CPU Utilization (crypto ops)', '%', 14 + classical * 16 + weak * 6, 12 + classical * 9, true,
      'Lattice operations reduce per-handshake CPU versus RSA private-key operations.'),
    metric('memory', 'Crypto Working Memory', 'MB', 96 + classical * 40, 118 + classical * 52, true,
      'Larger key/ciphertext buffers increase working set slightly.'),
    metric('latency', 'Request Latency (p95)', 'ms', 138 + classical * 60 + weak * 25, (138 + classical * 60) * 0.86 + 12, true,
      'Net effect of faster key exchange minus larger handshake payloads.'),
    metric('throughput', 'Handshake Throughput', 'ops/s', 780 - classical * 260, 940 - classical * 140, false,
      'Higher sustained handshake rate after removing RSA private-key bottleneck.'),
    metric('connection_success', 'Connection Success Rate', '%', clampPct(99.4 - weak * 6 - rsa * 0.5, 0, 100), clampPct(99.1 - weak * 2, 0, 100), false,
      'Hybrid mode preserves classical fallback for pre-PQC clients during transition.'),
    metric('packet_loss', 'Handshake Retransmission Impact', '%', 0.4 + weak * 1.2, 0.6, true,
      'Larger ClientHello/Certificate flights slightly raise fragmentation sensitivity on lossy links.'),
    metric('session_resumption', 'Session Resumption Rate', '%', clampPct(58 + symmetric * 20, 0, 100), clampPct(72 + symmetric * 18, 0, 100), false,
      'PSK-based TLS 1.3 resumption avoids repeat KEM cost after migration.'),
    metric('migration_duration', 'Estimated Migration Duration / Asset', 'min', 34 + weak * 30 + rsa * 22, 34 + weak * 30 + rsa * 22, true,
      'Wall-clock projection per asset including validation and rollback checkpoint.'),
  ]

  return {
    available: true,
    methodology: BENCHMARK_METHODOLOGY,
    sampleSize: total,
    algorithmMix: {
      rsaSharePct: clampPct(rsa * 100),
      eccSharePct: clampPct(ecc * 100),
      pqcSharePct: clampPct(pqc * 100),
      symmetricSharePct: clampPct(symmetric * 100),
      weakSharePct: clampPct(weak * 100),
    },
    metrics,
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   BUSINESS IMPACT SIMULATOR — only categories that actually exist in-tenant
   ═══════════════════════════════════════════════════════════════════════════ */

const BUSINESS_CATEGORIES: Array<{ id: string; label: string; pattern: RegExp; revenueSensitive: boolean }> = [
  { id: 'customer_portals', label: 'Customer Portals', pattern: /web|portal|frontend|site|shop|store/, revenueSensitive: true },
  { id: 'payment_systems', label: 'Payment Systems', pattern: /payment|billing|checkout|card|pos\b|invoice/, revenueSensitive: true },
  { id: 'identity_providers', label: 'Identity Providers', pattern: /identity|idp|iam|auth|sso|oidc|ldap/, revenueSensitive: false },
  { id: 'vpn_access', label: 'VPN & Remote Access', pattern: /vpn|tunnel|remote|bastion|ssh/, revenueSensitive: false },
  { id: 'cloud_infrastructure', label: 'Cloud Infrastructure', pattern: /cloud|aws|azure|gcp|kubernetes|k8s|cluster|container/, revenueSensitive: false },
  { id: 'email_systems', label: 'Email & Messaging', pattern: /mail|smtp|exchange|messag/, revenueSensitive: false },
  { id: 'healthcare_systems', label: 'Healthcare Systems', pattern: /health|clinic|patient|ehr|hl7|fhir/, revenueSensitive: true },
  { id: 'manufacturing', label: 'Manufacturing & OT', pattern: /manufactur|scada|plc\b|\bot\b|factory|industrial/, revenueSensitive: true },
  { id: 'critical_applications', label: 'Critical Applications', pattern: /./, revenueSensitive: false },
]

export function buildBusinessImpact(bundle: TwinBundle, predictions: ReturnType<typeof predictFailures>) {
  const assets = bundle.assets || []
  const invByAsset = groupByAsset(bundle.inventory)
  const expByAsset = groupByAsset(bundle.exposures)
  const assigned = new Set<string>()
  const categories: any[] = []

  for (const cat of BUSINESS_CATEGORIES) {
    const members = assets.filter((a) => {
      const id = str(a.id)
      if (assigned.has(id)) return false
      if (cat.id === 'critical_applications') return ['critical', 'high'].includes(lower(a.criticality))
      return cat.pattern.test(`${lower(a.type)} ${lower(a.name)}`)
    })
    if (members.length === 0) continue
    for (const m of members) assigned.add(str(m.id))
    const critical = members.filter((a) => lower(a.criticality) === 'critical').length
    const vulnerable = members.filter((a) => (invByAsset.get(str(a.id)) || []).some((i) => i.is_vulnerable || i.is_quantum_safe === false)).length
    const criticalExp = members.reduce((sum, a) => sum + (expByAsset.get(str(a.id)) || []).filter((e) => lower(e.severity) === 'critical').length, 0)
    const downtimeRisk = criticalExp > 0 ? 'high' : vulnerable > members.length / 2 ? 'medium' : 'low'
    categories.push({
      id: cat.id,
      label: cat.label,
      assets: members.length,
      criticalAssets: critical,
      vulnerableAssets: vulnerable,
      criticalExposures: criticalExp,
      downtimeRisk,
      revenueSensitive: cat.revenueSensitive,
      businessCriticality: critical > 0 ? 'critical' : vulnerable > 0 ? 'high' : 'standard',
      predictedDowntimeMin: downtimeRisk === 'high' ? 25 + criticalExp * 5 : downtimeRisk === 'medium' ? 8 + vulnerable * 2 : 0,
      guidance: downtimeRisk === 'high'
        ? 'Simulate with Canary or Blue-Green scenarios and require rollback PASS before scheduling.'
        : downtimeRisk === 'medium'
          ? 'Hybrid migration recommended to preserve client compatibility during transition.'
          : 'Standard migration window acceptable; validate with Quick Validation first.',
    })
  }

  const revenueExposed = categories.filter((c) => c.revenueSensitive && c.downtimeRisk !== 'low')
  const totalPredictedDowntime = categories.reduce((sum, c) => sum + c.predictedDowntimeMin, 0)
  return {
    categories: categories.sort((a, b) => b.predictedDowntimeMin - a.predictedDowntimeMin),
    summary: {
      categoriesIdentified: categories.length,
      revenueSensitiveAtRisk: revenueExposed.length,
      predictedCumulativeDowntimeMin: totalPredictedDowntime,
      downtimeCostBand: totalPredictedDowntime > 60 ? 'severe' : totalPredictedDowntime > 20 ? 'material' : totalPredictedDowntime > 0 ? 'limited' : 'negligible',
      overallFailureProbabilityPct: predictions.overallFailureProbabilityPct,
      note: 'Impact bands derive from real asset criticality, exposure severity, and dependency evidence — refine cost figures with your finance team\'s downtime-cost model.',
    },
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   ROLLBACK SIMULATOR — RTO / RPO / downtime / success probability
   ═══════════════════════════════════════════════════════════════════════════ */

export function buildRollbackAnalysis(bundle: TwinBundle, predictions: ReturnType<typeof predictFailures>) {
  const workflows = bundle.workflows || []
  const sandboxSims = workflows.filter((w) => w.isSandbox)
  const withSnapshots = sandboxSims.filter((w) => Array.isArray(w?.metadata?.snapshots) && w.metadata.snapshots.length > 0)
  const rolledBack = workflows.filter((w) => lower(w.status) === 'rolled_back').length
  const failed = workflows.filter((w) => lower(w.status) === 'failed').length
  const assets = (bundle.assets || []).length
  const criticalAssets = (bundle.assets || []).filter((a) => lower(a.criticality) === 'critical').length

  // Rollback confidence is DEMONSTRATED by rehearsal. With no simulation there
  // is nothing to measure, and `0%` would be indistinguishable from a rehearsal
  // that failed every time — so it stays null and the UI reads "Not assessed".
  // Same for RPO: `0m` is the BEST possible recovery point objective, which is
  // exactly the wrong thing to show for an unmeasured one.
  const assessed = sandboxSims.length > 0
  const snapshotCoveragePct = assessed ? clampPct((withSnapshots.length / sandboxSims.length) * 100) : null
  const successProbabilityPct = assessed
    ? clampPct(58 + (snapshotCoveragePct ?? 0) * 0.3 + rolledBack * 4 - failed * 6 - predictions.overallFailureProbabilityPct * 0.1, 5, 98)
    : null

  const rtoMinutes = assets === 0 ? null : Math.round(4 + Math.min(assets, 200) * 0.35 + criticalAssets * 1.5)
  const rpoMinutes = withSnapshots.length > 0 ? 5 : assessed ? 15 : null
  const downtimePredictionMin = assets === 0 ? null : Math.round((rtoMinutes ?? 0) * (predictions.overallFailureProbabilityPct / 100) + (failed > 0 ? 6 : 0))

  const certCount = (bundle.certificates || []).length
  const relCount = (bundle.relationships || []).length
  const hasKeyInventory = (bundle.inventory || []).some((i) => /key/.test(lower(i.item_type) + lower(i.name)))
  const hasSecretInventory = (bundle.inventory || []).some((i) => /secret|token|credential/.test(lower(i.item_type) + lower(i.name)))
  // Every `detail` must be TRUE for the `covered` value beside it. Several of
  // these used to state the covered case unconditionally, so an uncovered row
  // read "Crypto-policy state is recorded in each snapshot entry." next to a
  // failed checkmark.
  const restorationChecklist = [
    {
      id: 'certificates',
      label: 'Certificate restoration',
      covered: certCount > 0,
      detail: certCount > 0
        ? `${certCount} certificate metadata record(s) captured in twin snapshots.`
        : 'No certificate inventory yet — restore path unverified.',
    },
    {
      id: 'keys',
      label: 'Key material restoration',
      covered: hasKeyInventory,
      detail: hasKeyInventory
        ? 'Key inventory metadata is snapshot-tracked; production key values are never copied into the twin.'
        : 'No key-management records discovered yet — key restore path unverified.',
    },
    {
      id: 'configuration',
      label: 'Configuration restoration',
      covered: assessed,
      detail: assessed
        ? 'Simulation snapshots capture configuration state for restore rehearsal.'
        : 'Run a simulation to capture configuration checkpoints.',
    },
    {
      id: 'policies',
      label: 'Policy restoration',
      covered: assessed,
      detail: assessed
        ? 'Crypto-policy state is recorded in each snapshot entry.'
        : 'Policy state is only recorded inside a snapshot — run a simulation to capture it.',
    },
    {
      id: 'trust_chains',
      label: 'Trust chain restoration',
      covered: relCount > 0,
      detail: relCount > 0
        ? `${relCount} trust relationship(s) available for chain rebuild.`
        : certCount > 0
          ? 'Certificate metadata is captured but no trust relationships are mapped — chain rebuild is unverified.'
          : 'No certificate or relationship evidence — chain rebuild is unverified.',
    },
    {
      id: 'secrets',
      label: 'Secrets metadata restoration',
      covered: hasSecretInventory,
      detail: hasSecretInventory
        ? 'Secrets are restored by reference/metadata only — values never enter the sandbox.'
        : 'No secret/token/credential records discovered yet — nothing to restore by reference.',
    },
  ]

  return {
    available: sandboxSims.length > 0 || assets > 0,
    assessed,
    successProbabilityPct,
    snapshotCoveragePct,
    simulationsWithSnapshots: withSnapshots.length,
    totalSandboxSimulations: sandboxSims.length,
    rtoMinutes,
    rpoMinutes,
    downtimePredictionMin,
    automaticRollbackReady: assessed && (snapshotCoveragePct ?? 0) >= 50 && failed === 0,
    restorationChecklist,
    history: { rolledBackWorkflows: rolledBack, failedWorkflows: failed },
    note: 'RTO/RPO are twin-derived planning figures from your real asset counts, snapshot coverage, and failure history — validate against production runbooks before change approval.',
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   SOPHIA AI MIGRATION ADVISOR — explainable, evidence-backed reasoning
   ═══════════════════════════════════════════════════════════════════════════ */

const MIGRATION_SEQUENCE_ORDER: Array<{ component: string; label: string; rationale: string }> = [
  { component: 'pki', label: 'PKI & Certificate Authorities', rationale: 'Every dependent certificate inherits CA risk — migrating the trust anchor first prevents double-issuance.' },
  { component: 'kms_hsm', label: 'KMS / HSM / Secrets', rationale: 'Key management must support ML-KEM/ML-DSA before dependent services can rotate onto PQC material.' },
  { component: 'identity', label: 'Identity & Authentication', rationale: 'Tokens and session signing chains must be quantum-safe before app-tier migration to avoid mixed-trust states.' },
  { component: 'load_balancers', label: 'Load Balancers & Proxies', rationale: 'TLS termination points control negotiated groups for everything behind them.' },
  { component: 'api_gateway', label: 'API Gateways & Services', rationale: 'Gateways propagate hybrid handshake support to internal and external consumers.' },
  { component: 'web_servers', label: 'Web Servers & Portals', rationale: 'Customer-facing endpoints migrate after upstream trust and termination layers are hybrid-ready.' },
  { component: 'vpn', label: 'VPN & Tunnels', rationale: 'Long-lived tunnel keys are prime HNDL targets — migrate once PKI issuance is PQC-capable.' },
  { component: 'ssh', label: 'SSH & Bastion Hosts', rationale: 'Host and user key rotation follows KMS readiness.' },
  { component: 'kubernetes', label: 'Kubernetes & Containers', rationale: 'Cluster CA and admission chains migrate after the org PKI wave.' },
  { component: 'databases', label: 'Databases & Data Stores', rationale: 'TLS re-key plus at-rest envelope re-wrap; depends on KMS wave.' },
  { component: 'applications', label: 'Applications & Services', rationale: 'App-tier crypto migrates last, consuming the already-migrated platform layers.' },
]

export function buildSophiaAdvisor(
  bundle: TwinBundle,
  twin: ReturnType<typeof buildDigitalTwin>,
  graph: ReturnType<typeof buildDependencyGraph>,
  predictions: ReturnType<typeof predictFailures>,
  benchmark: ReturnType<typeof buildPerformanceBenchmark>,
  rollback: ReturnType<typeof buildRollbackAnalysis>,
  impact: ReturnType<typeof buildBusinessImpact>,
  context: { pqcReadiness: number; quantumRiskScore: number | null; complianceScore: number | null }
) {
  const workflows = bundle.workflows || []
  const sims = workflows.filter((w) => w.isSandbox)
  const completed = sims.filter((w) => lower(w.status) === 'completed').length
  const failed = sims.filter((w) => lower(w.status) === 'failed').length
  const hasData = (bundle.assets || []).length > 0 || (bundle.inventory || []).length > 0

  const blockers = predictions.predictions
    .filter((p) => p.severity === 'critical' || p.probabilityPct >= 60)
    .map((p) => ({ id: p.id, label: p.label, probabilityPct: p.probabilityPct, severity: p.severity, affectedAssets: p.affectedAssets, recommendation: p.recommendation }))

  const compatibilityScorePct = !hasData ? 0 : clampPct(
    100
    - predictions.predictions.filter((p) => ['tls_incompatibility', 'cipher_incompatibility', 'unsupported_library'].includes(p.category)).reduce((s, p) => s + p.probabilityPct * 0.35, 0)
  )
  const migrationConfidencePct = !hasData ? 0 : clampPct(
    context.pqcReadiness * 0.3
    + (100 - predictions.overallFailureProbabilityPct) * 0.3
    + compatibilityScorePct * 0.2
    + (sims.length > 0 ? clampPct((completed / Math.max(1, sims.length)) * 100) : 40) * 0.2
    - failed * 4
  )
  const rollbackConfidencePct = rollback.successProbabilityPct
  const aiConfidencePct = !hasData ? 0 : clampPct(
    twin.summary.coveragePct * 0.45
    + Math.min(100, (graph.stats.observedEdges / Math.max(1, twin.summary.totalNodes)) * 120) * 0.2
    + Math.min(100, (bundle.runtimeEvents || []).length * 2) * 0.2
    + (sims.length > 0 ? 100 : 30) * 0.15
  )

  const presentComponents = new Set(twin.componentGroups.map((g) => g.id))
  const recommendedSequence = MIGRATION_SEQUENCE_ORDER
    .filter((step) => presentComponents.has(step.component))
    .map((step, index) => {
      const group = twin.componentGroups.find((g) => g.id === step.component)
      return { order: index + 1, component: step.component, label: step.label, assets: group?.assets || 0, vulnerableAssets: group?.vulnerable || 0, rationale: step.rationale }
    })

  const rootCauses: string[] = []
  if (predictions.predictions.some((p) => p.category === 'pki_failure')) rootCauses.push('Quantum-vulnerable inventory inside the CA/PKI tier is the dominant upstream root cause — dependent certificates cannot become PQC-ready before their issuer does.')
  if (predictions.predictions.some((p) => p.category === 'tls_incompatibility')) rootCauses.push('Endpoints pinned to TLS 1.0/1.1 cannot negotiate hybrid groups; protocol floor must move to TLS 1.3 before ML-KEM adoption.')
  if (predictions.predictions.some((p) => p.category === 'unsupported_library')) rootCauses.push('Legacy crypto runtimes (OpenSSL 1.x class) lack ML-KEM/ML-DSA support and will fail negotiation regardless of configuration.')
  if (failed > 0) rootCauses.push(`${failed} failed sandbox run(s) indicate unresolved execution blockers — inspect their execution logs before re-approval.`)
  if (rootCauses.length === 0 && hasData) rootCauses.push('No dominant blocking root cause detected in current evidence; residual risk is concentrated in coverage gaps and rollout sequencing.')

  const priorityActions = [
    ...blockers.slice(0, 3).map((b) => b.recommendation),
    ...(rollback.snapshotCoveragePct < 50 && sims.length > 0 ? ['Capture rollback snapshots on all active simulations to raise rollback confidence.'] : []),
    ...(twin.summary.coveragePct < 60 && twin.summary.totalNodes > 0 ? ['Expand discovery coverage — a low-fidelity twin weakens every downstream validation.'] : []),
    ...(sims.length === 0 && hasData ? ['Run your first sandbox simulation (Quick Validation) to convert discovered risk into validated migration evidence.'] : []),
  ].slice(0, 6)

  const verdict = !hasData
    ? 'no_data'
    : blockers.length > 0 || failed > 0
      ? 'at_risk'
      : migrationConfidencePct >= 70
        ? 'ready'
        : 'progressing'

  const executiveSummary = !hasData
    ? 'No discovered assets or crypto inventory yet — connect scanners and run discovery to activate the migration sandbox digital twin.'
    : `Analytical model for ${twin.summary.totalNodes} recorded asset(s). ${blockers.length > 0 ? `${blockers.length} modeled blocker(s) require review.` : failed > 0 ? 'Review failed analytical runs.' : completed > 0 ? `${completed} analytical run(s) finished.` : 'Select a scenario to review the recorded evidence.'} Use lab checks and representative staging tests to determine compatibility.`

  const narrative = !hasData ? [] : [
    `The twin covers ${twin.summary.nodesWithEvidence}/${twin.summary.totalNodes} assets with real crypto evidence (${twin.summary.coveragePct}% coverage), ${twin.summary.trustRelationships} trust relationship(s), and ${twin.summary.runtimeSignalsSampled} runtime signal(s).`,
    graph.stats.maxBlastRadius > 0
      ? `Dependency analysis shows a maximum blast radius of ${graph.stats.maxBlastRadius} downstream consumer(s) — sequence waves bottom-up to contain failure spread.`
      : 'No dependency edges observed yet — impact analysis is per-asset until relationships are discovered.',
    benchmark.available
      ? `Performance modeling from your ${benchmark.sampleSize}-record algorithm mix projects ${benchmark.metrics.find((m: any) => m.id === 'tls_handshake')?.deltaPct ?? 0}% handshake-time change under hybrid ML-KEM.`
      : 'Performance projection pending crypto inventory discovery.',
    impact.summary.revenueSensitiveAtRisk > 0
      ? `${impact.summary.revenueSensitiveAtRisk} revenue-sensitive business system group(s) carry elevated downtime risk — use Canary or Blue-Green scenarios there.`
      : 'No revenue-sensitive business systems currently show elevated downtime risk.',
  ]

  return {
    verdict,
    migrationConfidencePct,
    compatibilityScorePct,
    // Canonical quantum risk: 0-100, LOWER IS BETTER, or null when the estate
    // has produced no risk evidence. Previously this carried sandbox.ts's
    // `100 - penalties` posture score, which saturated to 0 and was rendered as
    // "Security 0/100" on the Validation tab and "Risk Score 0" on Overview
    // while the QR Engine reported 75/High for the same tenant.
    quantumRiskScore: context.quantumRiskScore,
    rollbackConfidencePct,
    aiConfidencePct,
    recommendedSequence,
    detectedBlockers: blockers,
    rootCauses,
    businessImpactSummary: impact.summary,
    executiveSummary,
    priorityActions,
    narrative,
    evidenceBasis: {
      assets: (bundle.assets || []).length,
      inventoryRecords: (bundle.inventory || []).length,
      exposures: (bundle.exposures || []).length,
      certificates: (bundle.certificates || []).length,
      relationships: (bundle.relationships || []).length,
      runtimeEvents: (bundle.runtimeEvents || []).length,
      simulations: sims.length,
    },
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   PRODUCTION APPROVAL GATE — records decisions; never mutates production
   ═══════════════════════════════════════════════════════════════════════════ */

export function buildApprovalGate(
  bundle: TwinBundle,
  sophia: ReturnType<typeof buildSophiaAdvisor>,
  predictions: ReturnType<typeof predictFailures>,
  rollback: ReturnType<typeof buildRollbackAnalysis>,
  complianceScore: number | null
) {
  const sims = (bundle.workflows || []).filter((w) => w.isSandbox)
  const completed = sims.filter((w) => lower(w.status) === 'completed')
  const failed = sims.filter((w) => lower(w.status) === 'failed')
  const running = sims.filter((w) => ['running', 'queued', 'paused'].includes(lower(w.status)))

  const simulationStatus: 'MODELED' | 'FAILED' | 'PENDING' = sims.length === 0
    ? 'PENDING'
    : failed.length > 0 || sophia.detectedBlockers.some((b) => b.severity === 'critical')
      ? 'FAILED'
      : completed.length > 0 && running.length === 0
        ? 'MODELED'
        : 'PENDING'

  const gate = (id: string, label: string, value: string, status: 'pass' | 'warn' | 'fail') => ({ id, label, value, status })
  const gates = [
    gate('migration_confidence', 'Migration Confidence', `${sophia.migrationConfidencePct}%`, sophia.migrationConfidencePct >= 70 ? 'pass' : sophia.migrationConfidencePct >= 45 ? 'warn' : 'fail'),
    // An unrehearsed rollback is not a 0% rollback — it is an unmet gate with
    // nothing measured. Both block approval, but only one of them is a number.
    gate(
      'rollback_confidence',
      'Rollback Confidence',
      rollback.successProbabilityPct === null ? 'Not assessed' : `${rollback.successProbabilityPct}%`,
      rollback.successProbabilityPct === null ? 'fail'
        : rollback.successProbabilityPct >= 70 ? 'pass'
          : rollback.successProbabilityPct >= 45 ? 'warn' : 'fail',
    ),
    gate('business_risk', 'Business Risk', `${predictions.overallFailureProbabilityPct}% failure probability`, predictions.overallFailureProbabilityPct <= 25 ? 'pass' : predictions.overallFailureProbabilityPct <= 50 ? 'warn' : 'fail'),
    gate('downtime', 'Predicted Downtime', `${rollback.downtimePredictionMin} min`, rollback.downtimePredictionMin <= 5 ? 'pass' : rollback.downtimePredictionMin <= 20 ? 'warn' : 'fail'),
    gate('compliance', 'Tenant control evidence', complianceScore === null ? 'Not assessed' : `${complianceScore}%`,
      complianceScore === null ? 'fail' : complianceScore >= 75 ? 'pass' : complianceScore >= 55 ? 'warn' : 'fail'),
  ]

  const decisions = sims
    .map((w) => {
      const approval = w?.metadata?.approval
      if (!approval || typeof approval !== 'object') return null
      return {
        jobId: str(w.id),
        jobName: str(w.name),
        decision: str((approval as Row).decision),
        decidedBy: str((approval as Row).decidedBy) || null,
        decidedAt: str((approval as Row).decidedAt) || null,
        note: str((approval as Row).note) || null,
      }
    })
    .filter(Boolean)
    .sort((a: any, b: any) => Date.parse(b.decidedAt || '') - Date.parse(a.decidedAt || '')) as Array<{ jobId: string; jobName: string; decision: string; decidedBy: string | null; decidedAt: string | null; note: string | null }>

  const approvedCount = decisions.filter((d) => d.decision === 'approve').length
  const rejectedCount = decisions.filter((d) => d.decision === 'reject').length
  const reviewCount = decisions.filter((d) => d.decision === 'request_review').length

  return {
    simulationStatus,
    productionReady: false,
    aiRecommendation: simulationStatus === 'FAILED'
      ? 'Block production deployment — resolve blockers and failed simulations, then re-run the affected scenarios.'
      : simulationStatus === 'MODELED'
        ? 'Analytical review is available. Record cryptographic and protocol evidence in the lab, then review the proposal in Migration Planner.'
        : sims.length === 0
          ? 'No analytical runs are recorded yet.'
          : 'Analytical runs are in progress.',
    gates,
    eligibleSimulations: completed.map((w) => ({ id: str(w.id), name: str(w.name), completedAt: w.completedAt || null, approval: (w?.metadata?.approval as Row) || null })).slice(0, 12),
    decisions: decisions.slice(0, 20),
    counts: { completed: completed.length, failed: failed.length, running: running.length, approved: approvedCount, rejected: rejectedCount, reviewRequested: reviewCount },
    guarantee: 'A review decision records acceptance of analytical evidence. Production change approval belongs in Migration Planner.',
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   LIVE MIGRATION TIMELINE — real migration_events ordered chronologically
   ═══════════════════════════════════════════════════════════════════════════ */

export function buildMigrationTimeline(bundle: TwinBundle) {
  const jobName = new Map((bundle.workflows || []).map((w) => [str(w.id), str(w.name)]))
  return (bundle.events || [])
    .slice(0, 60)
    .map((event) => ({
      id: str(event.id),
      at: str(event.created_at),
      jobId: str(event.migration_id) || null,
      jobName: jobName.get(str(event.migration_id)) || null,
      type: str(event.event_type) || 'migration-event',
      severity: str(event.severity) || 'info',
      label: str(event.message) || 'Migration event',
    }))
    .sort((a, b) => Date.parse(b.at || '') - Date.parse(a.at || ''))
    .slice(0, 40)
}

/* ═══════════════════════════════════════════════════════════════════════════
   REAL-TIME TELEMETRY FRAME — real bucketed event series + labeled modeled
   per-simulation load (streamed over the existing SSE channel)
   ═══════════════════════════════════════════════════════════════════════════ */

export function buildTelemetryFrame(bundle: TwinBundle) {
  const BUCKETS = 12
  const BUCKET_MS = 5 * 60 * 1000
  const nowMs = Date.now()
  const start = nowMs - BUCKETS * BUCKET_MS
  const emptySeries = () => Array.from({ length: BUCKETS }, () => 0)

  const bucketIndex = (ts: unknown) => {
    const ms = Date.parse(str(ts))
    if (!Number.isFinite(ms) || ms < start || ms > nowMs) return -1
    return Math.min(BUCKETS - 1, Math.floor((ms - start) / BUCKET_MS))
  }

  const cryptoOps = emptySeries()
  const tlsSignals = emptySeries()
  const certValidations = emptySeries()
  const errors = emptySeries()
  const warnings = emptySeries()
  const migrationEvents = emptySeries()

  for (const event of bundle.runtimeEvents || []) {
    const idx = bucketIndex(event.created_at || event.timestamp || event.observed_at)
    if (idx < 0) continue
    cryptoOps[idx]++
    const text = JSON.stringify(event || {}).toLowerCase()
    if (/tls|handshake|cipher/.test(text)) tlsSignals[idx]++
    if (/cert/.test(text)) certValidations[idx]++
  }
  for (const event of bundle.events || []) {
    const idx = bucketIndex(event.created_at)
    if (idx < 0) continue
    migrationEvents[idx]++
    const severity = lower(event.severity)
    if (severity === 'error' || severity === 'critical') errors[idx]++
    else if (severity === 'warning') warnings[idx]++
  }

  const running = (bundle.workflows || []).filter((w) => w.isSandbox && lower(w.status) === 'running')
  const simulatedLoad = running.slice(0, 10).map((sim) => {
    const progress = num(sim.progress)
    const vulnerableItems = num(sim?.metadata?.evidence?.vulnerableItems)
    return {
      jobId: str(sim.id),
      jobName: str(sim.name),
      progress,
      modeled: true as const,
      cpuPct: clampPct(16 + progress * 0.34 + vulnerableItems * 1.2, 0, 96),
      memoryMb: Math.round(224 + progress * 2.6 + vulnerableItems * 9),
      latencyMs: Math.round(22 + (100 - progress) * 0.5 + vulnerableItems * 1.4),
      phase: str(sim.phase) || 'running',
    }
  })

  return {
    generatedAt: new Date(nowMs).toISOString(),
    windowMinutes: (BUCKETS * BUCKET_MS) / 60000,
    bucketMinutes: BUCKET_MS / 60000,
    series: [
      { id: 'crypto_ops', label: 'Runtime Crypto Operations', unit: 'events', source: 'runtime_crypto_events', values: cryptoOps },
      { id: 'tls_signals', label: 'TLS / Handshake Signals', unit: 'events', source: 'runtime_crypto_events', values: tlsSignals },
      { id: 'cert_validations', label: 'Certificate Signals', unit: 'events', source: 'runtime_crypto_events', values: certValidations },
      { id: 'migration_events', label: 'Migration Events', unit: 'events', source: 'migration_events', values: migrationEvents },
      { id: 'errors', label: 'Errors', unit: 'events', source: 'migration_events', values: errors },
      { id: 'warnings', label: 'Warnings', unit: 'events', source: 'migration_events', values: warnings },
    ],
    totals: {
      cryptoOps: cryptoOps.reduce((a, b) => a + b, 0),
      migrationEvents: migrationEvents.reduce((a, b) => a + b, 0),
      errors: errors.reduce((a, b) => a + b, 0),
      warnings: warnings.reduce((a, b) => a + b, 0),
    },
    simulatedLoad,
    note: 'Series are real bucketed tenant events. Per-simulation load figures are twin-modeled (labeled) — the sandbox does not measure production hosts.',
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   AGGREGATE ASSEMBLER — one call used by the sandbox snapshot builder
   ═══════════════════════════════════════════════════════════════════════════ */

export function assembleTwinIntelligence(bundle: TwinBundle, context: { pqcReadiness: number; quantumRiskScore: number | null; complianceScore: number | null }) {
  const twin = buildDigitalTwin(bundle)
  const graph = buildDependencyGraph(bundle)
  const topology = buildTopology(twin)
  const failurePrediction = predictFailures(bundle, graph)
  const benchmark = buildPerformanceBenchmark(bundle)
  const rollback = buildRollbackAnalysis(bundle, failurePrediction)
  const businessImpact = buildBusinessImpact(bundle, failurePrediction)
  const sophia = buildSophiaAdvisor(bundle, twin, graph, failurePrediction, benchmark, rollback, businessImpact, context)
  const approvalGate = buildApprovalGate(bundle, sophia, failurePrediction, rollback, context.complianceScore)
  const timeline = buildMigrationTimeline(bundle)
  const telemetryFrame = buildTelemetryFrame(bundle)

  return {
    digitalTwin: { generatedAt: twin.generatedAt, summary: twin.summary, isolation: twin.isolation, componentGroups: twin.componentGroups },
    dependencyGraph: { stats: graph.stats, topNodes: graph.nodes.slice(0, 12) },
    topology,
    failurePrediction,
    performanceBenchmark: benchmark,
    rollbackAnalysis: rollback,
    businessImpact,
    sophia,
    approvalGate,
    timeline,
    telemetryFrame,
    simulationTypes: SIMULATION_TYPES,
    pipeline: ENTERPRISE_PIPELINE,
  }
}
