/**
 * Trust relationship graph construction.
 *
 * Builds the hierarchy the brief draws in section 4:
 *
 *     Root CA -> Intermediate CA -> Certificate -> TLS Endpoint
 *             -> Service -> Application -> Cloud Resource
 *
 * Every node and every edge is derived from a row the tenant owns. Where a CA
 * exists only as an issuer STRING on a leaf certificate - which is the normal
 * case for a scanner that never captured the chain - the node is emitted with
 * `measured: false` and the edge with `measured: false`, so the graph shows the
 * inferred link honestly instead of pretending the CA certificate was collected.
 *
 * `dependentCount` is a real reachability count over the edge set (how many
 * nodes are downstream of this one), not an estimate. It is what makes
 * "which assets are affected by this certificate expiring" answerable.
 */

import type {
  PkiCertificate,
  TlsEndpoint,
  TlsFinding,
  TrustChainPath,
  TrustNode,
  TrustNodeKind,
  TrustRelationship,
  TrustState,
} from './types'
import { TRUST_STATE_RANK } from './types'

/* ------------------------------------------------------------------ */
/* Node identity                                                       */
/* ------------------------------------------------------------------ */

export const nodeId = {
  ca: (issuer: string) => `ca:${issuer.toLowerCase().replace(/\s+/g, ' ').trim()}`,
  certificate: (id: string) => `cert:${id}`,
  endpoint: (id: string) => `endpoint:${id}`,
  asset: (id: string) => `asset:${id}`,
  cloud: (id: string) => `cloud:${id}`,
}

/**
 * Classifies a tenant asset into the trust vocabulary using its declared type
 * and name. Falls back to the generic `asset` kind rather than guessing a
 * specific role the evidence does not support.
 */
export function assetNodeKind(assetType: string, name: string): TrustNodeKind {
  const corpus = `${assetType} ${name}`.toLowerCase()
  if (/\bk8s\b|kubernetes|kube|\bpod\b|deployment|statefulset|daemonset/.test(corpus)) return 'kubernetes-workload'
  if (/container|docker|\bimage\b|\becr\b|registry/.test(corpus)) return 'container'
  if (/load ?balancer|\belb\b|\balb\b|\bnlb\b|ingress|haproxy|nginx-lb/.test(corpus)) return 'load-balancer'
  if (/gateway|\bapigw\b|api ?gateway|\bproxy\b|envoy|\bwaf\b/.test(corpus)) return 'gateway'
  if (/\bidp\b|identity|\bsso\b|\boidc\b|\boauth\b|\bldap\b|active ?directory|entra|okta|keycloak|cognito|\bsaml\b/.test(corpus))
    return 'identity-system'
  if (/\bkms\b|key ?vault|keystore|\bhsm\b|key ?management|\bqkms\b|secrets? ?manager/.test(corpus)) return 'key-management'
  if (/encryption|\bcipher\b|crypto ?service|tokeniz/.test(corpus)) return 'encryption-service'
  if (/\bapi\b|endpoint|\brest\b|graphql|\bgrpc\b|\brpc\b/.test(corpus)) return 'api'
  if (/cloud|\bvm\b|\bec2\b|instance|\bs3\b|bucket|storage ?account|blob|\brds\b|\bvpc\b|lambda|function ?app/.test(corpus))
    return 'cloud-resource'
  if (/\bapp\b|application|frontend|web ?app|\bspa\b|portal|site|website/.test(corpus)) return 'application'
  if (/service|micro ?service|daemon|worker|\bapi-/.test(corpus)) return 'service'
  if (/domain|\bdns\b|hostname|\bfqdn\b/.test(corpus)) return 'domain'
  if (/server|host|node|database|\bdb\b|cluster|middleware|queue|cache/.test(corpus)) return 'service'
  return 'asset'
}

/* ------------------------------------------------------------------ */
/* State derivation                                                    */
/* ------------------------------------------------------------------ */

/** The worse of two states, using the shared rank table. */
export function worseState(a: TrustState, b: TrustState): TrustState {
  return TRUST_STATE_RANK[a] >= TRUST_STATE_RANK[b] ? a : b
}

/**
 * Certificate trust state from measured lifecycle and posture.
 *
 * Order matters and is deliberate: an expired certificate is `expired` even if
 * it is also quantum vulnerable, because the operator must fix the outage
 * before the migration. A certificate with no expiry recorded is `unknown` -
 * not `healthy`.
 */
export function certificateState(certificate: PkiCertificate): { state: TrustState; reason: string } {
  if (certificate.lifecycle === 'revoked') {
    return { state: 'invalid', reason: 'Certificate is marked revoked in the tenant inventory.' }
  }
  if (certificate.lifecycle === 'expired') {
    const days = certificate.daysToExpiry
    return {
      state: 'expired',
      reason: days !== null ? `Expired ${Math.abs(days)} days ago; any TLS handshake using it now fails.` : 'Certificate validity window has passed.',
    }
  }
  if (certificate.selfSigned) {
    return { state: 'invalid', reason: 'Self-signed: no external authority vouches for this certificate.' }
  }
  if (certificate.unknownIssuer) {
    return { state: 'degraded', reason: 'Issuer could not be matched to any CA observed in this tenant, so the chain cannot be walked.' }
  }
  const days = certificate.daysToExpiry
  if (days !== null && days <= 7) {
    return { state: 'critical', reason: `Expires in ${days} day${days === 1 ? '' : 's'} - renewal must already be in flight.` }
  }
  if (days !== null && days <= 30) {
    return { state: 'at-risk', reason: `Expires in ${days} days; standard renewal lead time is exceeded.` }
  }
  if (certificate.posture === 'quantum-vulnerable' || certificate.posture === 'legacy') {
    return {
      state: 'quantum-vulnerable',
      reason: `${certificate.algorithmLabel} offers no protection against a cryptographically relevant quantum computer.`,
    }
  }
  if (certificate.posture === 'migration-required') {
    return { state: 'migration-required', reason: 'Certificate algorithm is scheduled for replacement under the tenant PQC plan.' }
  }
  if (certificate.posture === 'quantum-safe' || certificate.posture === 'pqc-ready' || certificate.posture === 'hybrid-ready') {
    return { state: 'pqc-ready', reason: `${certificate.algorithmLabel} is post-quantum or hybrid.` }
  }
  if (days === null) {
    return { state: 'unknown', reason: 'No validity window recorded for this certificate, so lifecycle health cannot be stated.' }
  }
  if (days <= 60) {
    return { state: 'degraded', reason: `Expires in ${days} days - inside the 60-day warning window.` }
  }
  return { state: 'healthy', reason: `Valid for ${days} more days with a complete, non-self-signed chain.` }
}

/** Endpoint trust state from measured transport posture. */
export function endpointState(endpoint: TlsEndpoint): { state: TrustState; reason: string } {
  if (!endpoint.hasTransportEvidence) {
    return {
      state: 'unknown',
      reason: 'This endpoint has never been observed negotiating TLS, so its transport posture is unmeasured.',
    }
  }
  if (endpoint.criticalFindings > 0) {
    return { state: 'critical', reason: `${endpoint.criticalFindings} critical transport finding(s) open on this endpoint.` }
  }
  if (endpoint.daysToExpiry !== null && endpoint.daysToExpiry < 0) {
    return { state: 'expired', reason: 'The certificate serving this endpoint has expired.' }
  }
  if (endpoint.posture === 'quantum-vulnerable' || endpoint.posture === 'legacy') {
    return { state: 'quantum-vulnerable', reason: endpoint.postureReason || 'Negotiated transport cryptography is classical only.' }
  }
  if (endpoint.highFindings > 0) {
    return { state: 'at-risk', reason: `${endpoint.highFindings} high-severity transport finding(s) open on this endpoint.` }
  }
  if (endpoint.posture === 'migration-required') {
    return { state: 'migration-required', reason: endpoint.postureReason || 'Endpoint requires a transport migration.' }
  }
  if (endpoint.posture === 'quantum-safe' || endpoint.posture === 'pqc-ready' || endpoint.posture === 'hybrid-ready') {
    return { state: 'pqc-ready', reason: endpoint.postureReason || 'Endpoint negotiates hybrid or post-quantum key agreement.' }
  }
  if (endpoint.riskLevel === 'medium') {
    return { state: 'degraded', reason: endpoint.postureReason || 'Transport configuration has open weaknesses below high severity.' }
  }
  return { state: 'healthy', reason: endpoint.postureReason || 'Measured transport posture is within policy.' }
}

/* ------------------------------------------------------------------ */
/* Reachability                                                        */
/* ------------------------------------------------------------------ */

/**
 * Downstream reachability per node over the directed edge set.
 *
 * Iterative DFS with a visited set, so a cyclic relationship graph (which real
 * `asset_relationships` data does contain) terminates instead of overflowing.
 * Bounded by `maxNodes` because blast radius is a decision aid, not a census:
 * past a few hundred the answer is "most of the estate" either way.
 */
export function computeDownstream(
  nodes: TrustNode[],
  edges: TrustRelationship[],
  maxVisit = 400,
): { dependents: Map<string, number>; dependencies: Map<string, number> } {
  const forward = new Map<string, string[]>()
  const reverse = new Map<string, string[]>()
  const known = new Set(nodes.map((node) => node.id))

  for (const edge of edges) {
    if (!known.has(edge.from) || !known.has(edge.to)) continue
    const out = forward.get(edge.from)
    if (out) out.push(edge.to)
    else forward.set(edge.from, [edge.to])
    const back = reverse.get(edge.to)
    if (back) back.push(edge.from)
    else reverse.set(edge.to, [edge.from])
  }

  const walk = (start: string, adjacency: Map<string, string[]>) => {
    const seen = new Set<string>([start])
    const stack = [start]
    let count = 0
    while (stack.length > 0 && count < maxVisit) {
      const current = stack.pop() as string
      for (const next of adjacency.get(current) || []) {
        if (seen.has(next)) continue
        seen.add(next)
        count += 1
        stack.push(next)
        if (count >= maxVisit) break
      }
    }
    return count
  }

  const dependents = new Map<string, number>()
  const dependencies = new Map<string, number>()
  for (const node of nodes) {
    dependents.set(node.id, walk(node.id, forward))
    dependencies.set(node.id, walk(node.id, reverse))
  }
  return { dependents, dependencies }
}

/* ------------------------------------------------------------------ */
/* Chain paths                                                         */
/* ------------------------------------------------------------------ */

/**
 * Assembles Root -> Intermediate -> Certificate -> Endpoint -> Asset paths.
 *
 * A path is `complete` only when every tier it claims is backed by a node that
 * exists. An inferred CA still produces a path (the operator needs to see it),
 * but `complete` is false and `incompleteReason` names exactly which tier is
 * missing - which is what section 5's "clearly explain why a trust chain is
 * failing" requires.
 */
export function buildChainPaths(input: {
  nodes: Map<string, TrustNode>
  edges: TrustRelationship[]
  certificates: PkiCertificate[]
  dependents: Map<string, number>
}): TrustChainPath[] {
  const { nodes, edges, certificates, dependents } = input

  // Parent lookup restricted to the hierarchy edges that form a chain.
  const parentOf = new Map<string, string>()
  for (const edge of edges) {
    if (edge.kind !== 'issued' && edge.kind !== 'signs-for') continue
    if (!parentOf.has(edge.to)) parentOf.set(edge.to, edge.from)
  }

  const childrenOf = new Map<string, string[]>()
  for (const edge of edges) {
    if (edge.kind !== 'protects' && edge.kind !== 'deployed-on') continue
    const list = childrenOf.get(edge.from)
    if (list) list.push(edge.to)
    else childrenOf.set(edge.from, [edge.to])
  }

  const paths: TrustChainPath[] = []

  for (const certificate of certificates) {
    const certNode = nodes.get(nodeId.certificate(certificate.id))
    if (!certNode) continue

    /* ---- walk upward to the root ---- */
    const upward: string[] = []
    let cursor = parentOf.get(certNode.id)
    let guard = 0
    while (cursor && guard < 8) {
      upward.unshift(cursor)
      cursor = parentOf.get(cursor)
      guard += 1
    }

    /* ---- walk downward one tier (endpoint) then to its asset ---- */
    const downward: string[] = []
    const endpoints = childrenOf.get(certNode.id) || []
    if (endpoints.length > 0) {
      downward.push(endpoints[0])
      const assets = childrenOf.get(endpoints[0]) || []
      if (assets.length > 0) downward.push(assets[0])
    }

    const nodeIds = [...upward, certNode.id, ...downward]
    const pathNodes = nodeIds.map((id) => nodes.get(id)).filter((node): node is TrustNode => Boolean(node))
    if (pathNodes.length === 0) continue

    let state: TrustState = 'healthy'
    let weakest = pathNodes[0]
    for (const node of pathNodes) {
      if (TRUST_STATE_RANK[node.state] > TRUST_STATE_RANK[state]) {
        state = node.state
        weakest = node
      }
    }
    // A chain of entirely-unknown links is unknown, not healthy.
    if (pathNodes.every((node) => node.state === 'unknown')) state = 'unknown'

    const hasRoot = pathNodes.some((node) => node.kind === 'root-ca')
    const hasEndpoint = pathNodes.some((node) => node.kind === 'tls-endpoint')
    const allMeasured = pathNodes.every((node) => node.measured)

    const missing: string[] = []
    if (!hasRoot) missing.push('no root CA certificate was collected')
    if (!hasEndpoint) missing.push('the certificate is not bound to an observed TLS endpoint')
    if (!allMeasured) missing.push('one or more CA links exist only as an issuer name, not a collected certificate')

    paths.push({
      id: `chain:${certificate.id}`,
      nodeIds,
      state,
      weakestNodeId: weakest.id,
      weakestReason: weakest.stateReason,
      blastRadius: dependents.get(certNode.id) ?? 0,
      daysToExpiry: certificate.daysToExpiry,
      complete: hasRoot && hasEndpoint && allMeasured,
      incompleteReason: missing.length > 0 ? missing.join('; ') : '',
    })
  }

  return paths.sort(
    (a, b) => TRUST_STATE_RANK[b.state] - TRUST_STATE_RANK[a.state] || b.blastRadius - a.blastRadius,
  )
}

/* ------------------------------------------------------------------ */
/* Finding attachment                                                  */
/* ------------------------------------------------------------------ */

/** Indexes findings by the endpoint and asset they name, for node attachment. */
export function indexFindings(findings: TlsFinding[]) {
  const byEndpoint = new Map<string, TlsFinding[]>()
  const byAsset = new Map<string, TlsFinding[]>()
  for (const finding of findings) {
    if (finding.endpointId) {
      const list = byEndpoint.get(finding.endpointId)
      if (list) list.push(finding)
      else byEndpoint.set(finding.endpointId, [finding])
    }
    if (finding.assetId) {
      const list = byAsset.get(finding.assetId)
      if (list) list.push(finding)
      else byAsset.set(finding.assetId, [finding])
    }
  }
  return { byEndpoint, byAsset }
}
