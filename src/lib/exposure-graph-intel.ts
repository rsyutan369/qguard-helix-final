/**
 * Quantum Exposure Graph™ — isomorphic cryptographic dependency intelligence.
 *
 * Pure, deterministic functions shared by the Express assembler
 * (src/api-server/exposure-graph.ts), the interactive frontend
 * (src/app/dashboard/quantum-readiness/exposure-graph/*) and the offline
 * verification tool (tools/exposure-graph-check.ts). Keeping Blast Radius
 * Analysis™ and Migration Impact Analysis™ in ONE module guarantees the
 * numbers a customer sees while exploring the graph are exactly the numbers
 * the API and the verification suite compute — no duplicated logic.
 *
 * Everything here is a function of real evidence (nodes, edges, observed
 * algorithms, certificates). Downtime and confidence figures are labelled
 * planning estimates and are bounded, monotonic functions of evidence counts.
 */

import type {
  AssetCategory,
  BlastRadiusResult,
  EdgeTrustClass,
  ExposureGraphEdge,
  ExposureGraphNode,
  ImpactItem,
  MigrationImpactAnalysis,
  NodePosture,
  PriorityLabel,
  ProposedAlgorithmChange,
} from '@/types/exposure-graph'

/* ================================================================== */
/* Algorithm classification                                            */
/* ================================================================== */

export type AlgorithmClass = 'vulnerable' | 'hybrid' | 'pqc' | 'safe' | 'unknown'

/** Canonical algorithm classifier for the exposure graph (mirrors platform rules). */
export function classifyAlgorithmClass(raw: string): AlgorithmClass {
  const a = (raw || '').toUpperCase()
  if (!a.trim()) return 'unknown'
  if (/HYBRID|X25519\s*\+|\+\s*ML-KEM|ED25519\s*\+|X25519MLKEM/.test(a)) return 'hybrid'
  if (/ML-KEM|ML-DSA|SLH-DSA|KYBER|DILITHIUM|SPHINCS|FALCON|FIPS\s?20[345]|HQC|FRODOKEM/.test(a)) return 'pqc'
  if (/AES-?256|SHA3|SHA-?384|SHA-?512|CHACHA20/.test(a) && !/RSA|ECDSA|ECDH|\bDH\b|\bDSA\b/.test(a)) return 'safe'
  if (/RSA|ECDSA|ECDH|ELGAMAL|EL-GAMAL|\bDSA\b|DIFFIE|\bDH\b|\bEC\b|P-256|P-384|P-521|SECP|CURVE\s?25519$|3DES|\bDES\b|RC4|MD5|SHA-?1\b|TLS_RSA|SSH-RSA/.test(a)) return 'vulnerable'
  return 'unknown'
}

/** Map an algorithm class onto the node/edge posture vocabulary. */
export function postureFromAlgorithmClass(cls: AlgorithmClass): NodePosture {
  if (cls === 'vulnerable') return 'vulnerable'
  if (cls === 'hybrid') return 'hybrid'
  if (cls === 'pqc' || cls === 'safe') return 'pqc'
  return 'unknown'
}

/* ================================================================== */
/* Asset categorisation & migration tiers                              */
/* ================================================================== */

/**
 * Migration Dependency Intelligence™ tier ladder. Trust anchors migrate first
 * (everything downstream re-chains onto them), endpoints migrate last. This is
 * the canonical enterprise PQC sequencing order (CA → KMS → IdP → PKI → VPN →
 * LB → API → DB → K8s → Web → Endpoint → Vendor).
 */
export const MIGRATION_TIERS: Array<{ tier: number; label: string; categories: AssetCategory[]; rationale: string }> = [
  { tier: 1, label: 'Certificate Authorities', categories: ['certificate-authority'], rationale: 'Trust anchor — every downstream certificate re-chains onto the migrated CA hierarchy.' },
  { tier: 2, label: 'Key Management (KMS / HSM)', categories: ['kms', 'hsm'], rationale: 'Key custody must support ML-KEM / ML-DSA before dependent systems can rotate onto PQC keys.' },
  { tier: 3, label: 'Identity Providers & Directory', categories: ['identity-provider', 'directory'], rationale: 'Authentication trust must be quantum-safe before service credentials and tokens are reissued.' },
  { tier: 4, label: 'Internal PKI', categories: ['pki'], rationale: 'Issuing infrastructure signs the replacement certificate estate for every later wave.' },
  { tier: 5, label: 'VPN & Network Gateways', categories: ['vpn-gateway'], rationale: 'Secure transport backbone — tunnels must accept hybrid key establishment before endpoint waves.' },
  { tier: 6, label: 'TLS Load Balancers & Edge', categories: ['load-balancer', 'tls-endpoint'], rationale: 'TLS termination points adopt hybrid TLS so clients negotiate PQC without breaking legacy peers.' },
  { tier: 7, label: 'Internal APIs & Services', categories: ['api', 'service'], rationale: 'Service-to-service trust (mTLS, tokens) re-established on the migrated identity and PKI base.' },
  { tier: 8, label: 'Databases & Data Stores', categories: ['database'], rationale: 'Data-in-transit TLS updates and re-encryption follow once serving infrastructure is ready.' },
  { tier: 9, label: 'Kubernetes & Containers', categories: ['kubernetes', 'container'], rationale: 'Workload certificates and mesh trust rotate with orchestrated restarts.' },
  { tier: 10, label: 'Web Applications & SaaS Frontends', categories: ['web-application', 'saas', 'email', 'dns', 'cloud-resource'], rationale: 'User-facing applications cut over after their upstream dependencies are quantum-safe.' },
  { tier: 11, label: 'Servers, VMs & Endpoints', categories: ['server', 'vm', 'workstation', 'ssh-server'], rationale: 'Host key rotation and endpoint crypto complete the estate after core services.' },
  { tier: 12, label: 'External & Vendor Services', categories: ['vendor'], rationale: 'Third-party migration depends on vendor PQC support — tracked, validated, not directly controlled.' },
]

const CATEGORY_MATCHERS: Array<{ category: AssetCategory; pattern: RegExp }> = [
  { category: 'certificate-authority', pattern: /certificate.?authority|issuing.?ca|root.?ca|intermediate.?ca|\bca\b(?!che)|cert.?authority/i },
  { category: 'hsm', pattern: /\bhsm\b|hardware.?security.?module/i },
  { category: 'kms', pattern: /\bkms\b|key.?manage|key.?vault|secrets?.?manager/i },
  { category: 'identity-provider', pattern: /identity|idp\b|\bsso\b|oauth|oidc|saml|okta|auth0|keycloak|cognito|login/i },
  { category: 'directory', pattern: /active.?directory|\bldap\b|\bad\s?ds\b|domain.?controller/i },
  { category: 'pki', pattern: /\bpki\b|cert.?service|certificate.?service/i },
  { category: 'vpn-gateway', pattern: /vpn|ipsec|wireguard|tunnel/i },
  { category: 'load-balancer', pattern: /load.?balanc|\balb\b|\belb\b|\bnlb\b|haproxy|nginx|ingress|reverse.?proxy|\bproxy\b|\bcdn\b/i },
  { category: 'kubernetes', pattern: /kubernetes|\bk8s\b|\beks\b|\baks\b|\bgke\b|cluster/i },
  { category: 'container', pattern: /container|docker|\bpod\b/i },
  { category: 'database', pattern: /database|\bdb\b|postgres|mysql|mongo|redis|oracle|mariadb|dynamo|cassandra|sql/i },
  { category: 'api', pattern: /\bapi\b|graphql|grpc|rest|endpoint.?service|microservice/i },
  { category: 'email', pattern: /email|smtp|imap|mail/i },
  { category: 'dns', pattern: /\bdns\b|domain.?name.?service|resolver/i },
  { category: 'ssh-server', pattern: /\bssh\b|bastion|jump.?host/i },
  { category: 'tls-endpoint', pattern: /tls|https|ssl/i },
  { category: 'saas', pattern: /saas|third.?party|vendor|external.?service/i },
  { category: 'workstation', pattern: /workstation|laptop|desktop|endpoint.?device|mobile/i },
  { category: 'vm', pattern: /virtual.?machine|\bvm\b|\bec2\b|instance/i },
  { category: 'cloud-resource', pattern: /cloud|\baws\b|azure|\bgcp\b|\bs3\b|lambda|storage.?account/i },
  { category: 'web-application', pattern: /web|portal|site|frontend|app\b|application/i },
  { category: 'server', pattern: /server|host|node\b/i },
]

/** Normalize a raw asset type/name into an enterprise category. */
export function classifyAssetCategory(type: string, name = ''): AssetCategory {
  const text = `${type} ${name}`
  for (const matcher of CATEGORY_MATCHERS) {
    if (matcher.pattern.test(text)) return matcher.category
  }
  return 'service'
}

const TIER_BY_CATEGORY = new Map<AssetCategory, { tier: number; label: string }>(
  MIGRATION_TIERS.flatMap((t) => t.categories.map((c) => [c, { tier: t.tier, label: t.label }] as [AssetCategory, { tier: number; label: string }])),
)

export function tierForCategory(category: AssetCategory): { tier: number; label: string } {
  return TIER_BY_CATEGORY.get(category) || { tier: 7, label: 'Internal APIs & Services' }
}

export const CATEGORY_LABELS: Record<AssetCategory, string> = {
  'certificate-authority': 'Certificate Authority',
  kms: 'Key Management (KMS)',
  hsm: 'HSM',
  'identity-provider': 'Identity Provider',
  pki: 'PKI Infrastructure',
  'vpn-gateway': 'VPN Gateway',
  'load-balancer': 'Load Balancer',
  api: 'API / Service',
  database: 'Database',
  kubernetes: 'Kubernetes Cluster',
  container: 'Container',
  'cloud-resource': 'Cloud Resource',
  server: 'Server',
  vm: 'Virtual Machine',
  workstation: 'Workstation',
  'web-application': 'Web Application',
  saas: 'SaaS Platform',
  email: 'Email System',
  dns: 'DNS Service',
  directory: 'Directory Service',
  'ssh-server': 'SSH Server',
  'tls-endpoint': 'TLS Endpoint',
  vendor: 'Third-Party Vendor',
  service: 'Internal Service',
}

/* ================================================================== */
/* Trust-class classification for edges                                */
/* ================================================================== */

export function classifyTrustClass(relationshipType: string): EdgeTrustClass {
  const t = (relationshipType || '').toLowerCase()
  if (/mtls|mutual/.test(t)) return 'mtls'
  if (/cert|issued|chain|signs|pki/.test(t)) return 'certificate-chain'
  if (/identity|auth|oauth|oidc|saml|sso|token|federat/.test(t)) return 'identity'
  if (/kms|key|hsm|encrypt|wrap/.test(t)) return 'kms'
  if (/vpn|tunnel|ipsec/.test(t)) return 'vpn'
  if (/ssh/.test(t)) return 'ssh'
  if (/mesh|sidecar|envoy|istio/.test(t)) return 'service-mesh'
  if (/api|calls|invokes|consumes/.test(t)) return 'api'
  if (/tls|https|ssl/.test(t)) return 'tls'
  if (/cloud|hosted|provider/.test(t)) return 'cloud'
  if (/communicat|connect|talks|traffic/.test(t)) return 'communication'
  return 'dependency'
}

/** Trust classes whose failure propagates through the trust chain itself. */
export const TRUST_CHAIN_CLASSES: ReadonlySet<EdgeTrustClass> = new Set(['certificate-chain', 'mtls', 'identity', 'kms'])

/* ================================================================== */
/* Risk prioritisation                                                 */
/* ================================================================== */

export function priorityFromScore(score: number): PriorityLabel {
  if (score >= 75) return 'Critical'
  if (score >= 55) return 'High'
  if (score >= 30) return 'Medium'
  return 'Low'
}

export function criticalityLabel(raw: string): PriorityLabel {
  const t = (raw || '').toLowerCase()
  if (t.includes('critical')) return 'Critical'
  if (t.includes('high')) return 'High'
  if (t.includes('low')) return 'Low'
  return 'Medium'
}

/**
 * Composite migration priority for a node — deterministic blend of the risk
 * dimensions named in the platform spec: quantum exposure, business
 * criticality, internet exposure, trust centrality, certificate expiry and
 * cryptographic strength. Returns the score plus human-readable drivers so
 * every priority is explainable.
 */
export function computePriority(input: {
  posture: NodePosture
  riskScore: number
  internetFacing: boolean
  businessCriticality: PriorityLabel
  dependents: number
  dependencies: number
  expiringCertificates: number
  vulnerableAlgorithms: number
  findingsCount: number
}): { score: number; priority: PriorityLabel; drivers: string[] } {
  const drivers: string[] = []
  let score = 0

  if (input.posture === 'vulnerable') {
    score += 30
    drivers.push('Quantum-vulnerable cryptography in use')
  } else if (input.posture === 'unknown') {
    score += 12
    drivers.push('Unverified cryptographic posture')
  } else if (input.posture === 'hybrid') {
    score += 8
    drivers.push('Partial (hybrid) migration state')
  }

  if (input.internetFacing) {
    score += 14
    drivers.push('Internet-facing exposure')
  }
  if (input.businessCriticality === 'Critical') {
    score += 18
    drivers.push('Business-critical asset')
  } else if (input.businessCriticality === 'High') {
    score += 11
    drivers.push('High business criticality')
  }

  const centrality = Math.min(14, (input.dependents + input.dependencies) * 1.4)
  if (centrality >= 4) drivers.push(`${input.dependents + input.dependencies} trust relationship(s)`)
  score += centrality

  if (input.expiringCertificates > 0) {
    score += Math.min(10, input.expiringCertificates * 4)
    drivers.push(`${input.expiringCertificates} certificate(s) expiring soon`)
  }
  if (input.vulnerableAlgorithms > 0) {
    score += Math.min(10, input.vulnerableAlgorithms * 2.5)
    drivers.push(`${input.vulnerableAlgorithms} weak algorithm(s) observed`)
  }
  if (input.findingsCount > 0) {
    score += Math.min(8, input.findingsCount * 2)
    drivers.push(`${input.findingsCount} scan finding(s)`)
  }
  score += Math.min(16, input.riskScore * 0.16)

  const clamped = Math.max(0, Math.min(100, Math.round(score)))
  return { score: clamped, priority: priorityFromScore(clamped), drivers: drivers.slice(0, 5) }
}

/* ================================================================== */
/* Blast Radius Analysis™                                              */
/* ================================================================== */

type AdjacencyEntry = { neighbor: string; edge: ExposureGraphEdge }

export function buildAdjacency(edges: ExposureGraphEdge[]): Map<string, AdjacencyEntry[]> {
  const adjacency = new Map<string, AdjacencyEntry[]>()
  const push = (from: string, neighbor: string, edge: ExposureGraphEdge) => {
    const list = adjacency.get(from)
    if (list) list.push({ neighbor, edge })
    else adjacency.set(from, [{ neighbor, edge }])
  }
  for (const edge of edges) {
    push(edge.source, edge.target, edge)
    push(edge.target, edge.source, edge)
  }
  return adjacency
}

/**
 * BFS blast radius from a node (undirected — a broken trust link disrupts both
 * sides), depth-capped so mega-graphs stay bounded. Trust-chain membership is
 * tracked per node: reached through a certificate/identity/KMS-class edge.
 */
export function computeBlastRadius(
  nodes: ExposureGraphNode[],
  edges: ExposureGraphEdge[],
  rootId: string,
  maxDepth = 6,
  adjacency?: Map<string, AdjacencyEntry[]>,
): BlastRadiusResult {
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const adj = adjacency || buildAdjacency(edges)
  const depths: Record<string, number> = {}
  const trustChain = new Set<string>()
  const queue: Array<{ id: string; depth: number }> = [{ id: rootId, depth: 0 }]
  depths[rootId] = 0

  while (queue.length) {
    const { id, depth } = queue.shift()!
    if (depth >= maxDepth) continue
    for (const { neighbor, edge } of adj.get(id) || []) {
      if (depths[neighbor] !== undefined) continue
      depths[neighbor] = depth + 1
      if (TRUST_CHAIN_CLASSES.has(edge.trustClass) || trustChain.has(id)) trustChain.add(neighbor)
      queue.push({ id: neighbor, depth: depth + 1 })
    }
  }

  const direct: string[] = []
  const indirect: string[] = []
  const environments = new Set<string>()
  let internetFacing = 0
  let businessCritical = 0
  const tierCounts = new Map<string, number>()

  for (const [id, depth] of Object.entries(depths)) {
    if (id === rootId || depth === 0) continue
    if (depth === 1) direct.push(id)
    else indirect.push(id)
    const node = byId.get(id)
    if (!node) continue
    if (node.environment) environments.add(node.environment)
    if (node.internetFacing) internetFacing += 1
    if (node.businessCriticality === 'Critical' || node.businessCriticality === 'High') businessCritical += 1
    tierCounts.set(node.tierLabel, (tierCounts.get(node.tierLabel) || 0) + 1)
  }

  return {
    nodeId: rootId,
    direct,
    indirect,
    trustChain: [...trustChain].filter((id) => id !== rootId),
    depths,
    totalAffected: direct.length + indirect.length,
    internetFacing,
    businessCritical,
    environments: [...environments].sort(),
    affectedByTier: [...tierCounts.entries()].map(([tierLabel, count]) => ({ tierLabel, count })).sort((a, b) => b.count - a.count),
  }
}

/* ================================================================== */
/* Migration Impact Analysis™                                          */
/* ================================================================== */

/** NIST-approved target for each classical primitive family. */
export function pqcTargetFor(algorithm: string, internetFacing: boolean): ProposedAlgorithmChange | null {
  const a = algorithm.toUpperCase()
  const cls = classifyAlgorithmClass(a)
  if (cls === 'pqc' || cls === 'hybrid') return null
  if (/TLS_RSA|RSA.?KEY.?EXCHANGE/.test(a)) return { from: algorithm, to: internetFacing ? 'Hybrid TLS 1.3 (X25519 + ML-KEM-768)' : 'TLS 1.3 + ML-KEM-768 (FIPS 203)', kind: 'Key establishment' }
  if (/ECDHE?|X25519$|X448|DIFFIE|\bDH\b|CURVE\s?25519/.test(a)) return { from: algorithm, to: internetFacing ? 'Hybrid X25519 + ML-KEM-768' : 'ML-KEM-768 (FIPS 203)', kind: 'Key establishment' }
  if (/ECDSA|ED25519|\bDSA\b|P-256|P-384|P-521|SECP/.test(a)) return { from: algorithm, to: 'ML-DSA-65 (FIPS 204)', kind: 'Digital signature' }
  if (/SSH-RSA/.test(a)) return { from: algorithm, to: 'SSH with ML-KEM key exchange + ML-DSA host keys', kind: 'SSH transport' }
  if (/RSA/.test(a)) return { from: algorithm, to: 'ML-DSA-65 (FIPS 204) signatures / ML-KEM-768 key transport', kind: 'Asymmetric replacement' }
  if (/MD5|SHA-?1\b/.test(a)) return { from: algorithm, to: 'SHA3-256 (FIPS 202)', kind: 'Hash upgrade' }
  if (/3DES|\bDES\b|RC4|AES-?128/.test(a)) return { from: algorithm, to: 'AES-256-GCM', kind: 'Symmetric upgrade' }
  if (cls === 'vulnerable') return { from: algorithm, to: 'ML-KEM-768 / ML-DSA-65 (per usage)', kind: 'Asymmetric replacement' }
  return null
}

function neighborInterruption(node: ExposureGraphNode, edge: ExposureGraphEdge): ImpactItem | null {
  const severity: PriorityLabel = node.businessCriticality === 'Critical' ? 'Critical' : edge.posture === 'vulnerable' ? 'High' : 'Medium'
  switch (node.category) {
    case 'api':
    case 'service':
      return { label: `${node.label} — API authentication`, detail: 'Service credentials and TLS sessions must re-handshake against the migrated trust chain; calls fail until both peers negotiate compatible suites.', severity }
    case 'vpn-gateway':
      return { label: `${node.label} — VPN tunnel`, detail: 'Tunnel renegotiation requires hybrid key establishment support on both peers; legacy IKE profiles will not connect.', severity }
    case 'ssh-server':
      return { label: `${node.label} — SSH clients`, detail: 'Host key rotation invalidates known_hosts entries; clients need updated key algorithms before reconnecting.', severity }
    case 'database':
      return { label: `${node.label} — database TLS`, detail: 'Connection strings and drivers must trust the replacement certificate chain; stale pools drop until refreshed.', severity }
    case 'kubernetes':
    case 'container':
      return { label: `${node.label} — workload restart`, detail: 'Mesh/workload certificates rotate with a rolling restart; unsupported sidecars block the rollout.', severity }
    case 'load-balancer':
    case 'tls-endpoint':
      return { label: `${node.label} — TLS termination`, detail: 'Listener profiles need hybrid cipher configuration; strict legacy-only policies will refuse the new chain.', severity }
    case 'identity-provider':
    case 'directory':
      return { label: `${node.label} — identity federation`, detail: 'Token signing and federation metadata must be re-published; sessions signed by the old keys are rejected.', severity }
    case 'vendor':
    case 'saas':
      return { label: `${node.label} — third-party compatibility`, detail: 'Vendor endpoint must accept the migrated crypto; validate PQC/hybrid support before cutover.', severity }
    case 'certificate-authority':
    case 'pki':
      return { label: `${node.label} — trust chain`, detail: 'Issued certificates re-chain onto the migrated hierarchy; un-reissued leaves become invalid.', severity }
    case 'kms':
    case 'hsm':
      return { label: `${node.label} — key custody`, detail: 'Key wrapping and envelope policies must support the replacement algorithms before dependent rotation.', severity }
    default:
      if (TRUST_CHAIN_CLASSES.has(edge.trustClass)) {
        return { label: `${node.label} — trust relationship`, detail: `The ${edge.trustClass} link must be re-established after migration; the peer needs compatible crypto.`, severity }
      }
      return { label: `${node.label} — connectivity`, detail: 'Communication path renegotiates under the migrated configuration; verify peer compatibility.', severity: 'Medium' }
  }
}

/**
 * Simulate upgrading a node to PQC: current state, NIST target mapping,
 * what-will-break prediction across its real neighbors, required remediation
 * and bounded planning estimates. Deterministic function of the graph.
 */
export function computeMigrationImpact(
  nodes: ExposureGraphNode[],
  edges: ExposureGraphEdge[],
  nodeId: string,
  blast?: BlastRadiusResult,
): MigrationImpactAnalysis | null {
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const node = byId.get(nodeId)
  if (!node) return null

  const incident = edges.filter((e) => e.source === nodeId || e.target === nodeId)
  const radius = blast || computeBlastRadius(nodes, edges, nodeId)

  const proposed: ProposedAlgorithmChange[] = []
  const seenTargets = new Set<string>()
  const candidateAlgorithms = [...node.algorithms, ...node.certificates.map((c) => c.algorithm)]
  for (const algorithm of candidateAlgorithms) {
    const change = pqcTargetFor(algorithm, node.internetFacing)
    if (!change) continue
    const key = `${change.from}→${change.to}`
    if (seenTargets.has(key)) continue
    seenTargets.add(key)
    proposed.push(change)
  }
  if (!proposed.length && node.posture === 'vulnerable') {
    proposed.push({ from: 'Classical asymmetric cryptography', to: 'ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204)', kind: 'Asymmetric replacement' })
  }

  const interruptions: ImpactItem[] = []
  const seenNeighbors = new Set<string>()
  for (const edge of incident) {
    const neighborId = edge.source === nodeId ? edge.target : edge.source
    if (seenNeighbors.has(neighborId)) continue
    seenNeighbors.add(neighborId)
    const neighbor = byId.get(neighborId)
    if (!neighbor) continue
    const item = neighborInterruption(neighbor, edge)
    if (item) interruptions.push(item)
  }
  const severityRank: Record<PriorityLabel, number> = { Critical: 3, High: 2, Medium: 1, Low: 0 }
  interruptions.sort((a, b) => severityRank[b.severity] - severityRank[a.severity])

  const vulnerableCerts = node.certificates.filter((c) => !c.quantumSafe && classifyAlgorithmClass(c.algorithm) === 'vulnerable')
  const remediation: ImpactItem[] = []
  if (vulnerableCerts.length) {
    remediation.push({ label: `Replace ${vulnerableCerts.length} classical certificate(s)`, detail: 'Reissue RSA/ECDSA certificates under ML-DSA-65 or hybrid chains and redeploy to every consumer.', severity: 'Critical' })
  }
  const certChainEdges = incident.filter((e) => e.trustClass === 'certificate-chain')
  if (certChainEdges.length) {
    remediation.push({ label: `Revalidate ${certChainEdges.length} trust chain(s)`, detail: 'Certificate chains anchored on this node become invalid until re-chained to the migrated hierarchy.', severity: 'High' })
  }
  if (node.algorithms.some((a) => /ssh/i.test(a)) || node.category === 'ssh-server') {
    remediation.push({ label: 'Rotate SSH host keys', detail: 'Publish ML-DSA host keys and coordinate client known_hosts updates.', severity: 'High' })
  }
  if (incident.some((e) => e.trustClass === 'kms')) {
    remediation.push({ label: 'Update KMS key policies', detail: 'Key wrapping, envelope and rotation policies must allow the replacement PQC algorithms.', severity: 'High' })
  }
  if (node.internetFacing) {
    remediation.push({ label: 'Deploy Hybrid TLS (X25519 + ML-KEM-768)', detail: 'Hybrid key establishment preserves interoperability with legacy internet clients during transition.', severity: 'Medium' })
  }
  if (node.posture === 'vulnerable' || vulnerableCerts.length) {
    remediation.push({ label: 'Upgrade TLS / crypto library profiles', detail: 'Runtime libraries (OpenSSL 3.5+, BoringSSL, JDK 24+) must expose ML-KEM / ML-DSA cipher support.', severity: 'Medium' })
  }
  if (node.category === 'certificate-authority' || node.category === 'pki') {
    remediation.push({ label: 'Re-issue subordinate hierarchy', detail: 'Every certificate issued by this authority requires reissuance under the PQC root of trust.', severity: 'Critical' })
  }

  const neighborNodes = [...seenNeighbors].map((id) => byId.get(id)).filter((n): n is ExposureGraphNode => Boolean(n))
  const compatibleNeighbors = neighborNodes.filter((n) => n.posture === 'pqc' || n.posture === 'hybrid' || n.posture === 'migrating').length
  const compatibilityScorePct = neighborNodes.length ? Math.round((compatibleNeighbors / neighborNodes.length) * 100) : 100

  const criticalInterruptions = interruptions.filter((i) => i.severity === 'Critical').length
  const riskScoreComposite =
    (node.businessCriticality === 'Critical' ? 30 : node.businessCriticality === 'High' ? 18 : 6) +
    Math.min(30, radius.totalAffected * 3) +
    criticalInterruptions * 10 +
    (100 - compatibilityScorePct) * 0.2
  const estimatedRisk = priorityFromScore(Math.min(100, Math.round(riskScoreComposite)))

  // Planning estimate: each incompatible direct dependency costs a bounded
  // re-establishment window; fully compatible neighborhoods approach zero.
  const incompatibleDirect = radius.direct.filter((id) => {
    const n = byId.get(id)
    return n ? n.posture === 'vulnerable' || n.posture === 'unknown' : false
  }).length
  const downtimeMin = incompatibleDirect === 0 ? 0 : Math.round(incompatibleDirect * 0.25 * 10) / 10
  const downtimeMax = Math.round(Math.min(24, incompatibleDirect * 1.5 + criticalInterruptions * 1.5) * 10) / 10

  const evidencedNeighbors = neighborNodes.filter((n) => n.algorithms.length > 0 || n.certificates.length > 0).length
  const selfEvidence = node.algorithms.length > 0 || node.certificates.length > 0 ? 1 : 0
  const coverage = (evidencedNeighbors + selfEvidence) / Math.max(1, neighborNodes.length + 1)
  const confidencePct = Math.round(35 + coverage * 60)

  return {
    nodeId,
    currentState: {
      algorithms: node.algorithms,
      protocols: node.protocols,
      certificates: node.certificates.length,
      vulnerableCertificates: vulnerableCerts.length,
      trustRelationships: incident.filter((e) => TRUST_CHAIN_CLASSES.has(e.trustClass)).length,
      dependencies: node.dependencies,
      dependents: node.dependents,
      communicationPaths: incident.length,
    },
    proposedMigration: proposed.slice(0, 8),
    potentialInterruptions: interruptions.slice(0, 10),
    requiredRemediation: remediation.slice(0, 8),
    affected: {
      direct: radius.direct.length,
      indirect: radius.indirect.length,
      trustChain: radius.trustChain.length,
      internetFacing: radius.internetFacing,
      businessCritical: radius.businessCritical,
      environments: radius.environments,
    },
    estimatedRisk,
    estimatedDowntimeHours: { min: downtimeMin, max: downtimeMax },
    compatibilityScorePct,
    confidencePct,
    evidenceNote:
      node.algorithms.length || node.certificates.length
        ? `Derived from ${node.algorithms.length} observed algorithm(s), ${node.certificates.length} certificate(s) and ${incident.length} real trust relationship(s). Downtime figures are planning estimates.`
        : 'Limited cryptographic evidence for this node — run a targeted scan to raise confidence. Downtime figures are planning estimates.',
  }
}
