/**
 * TLS Intelligence Engine™ — Edge vs Origin.
 *
 * Public TLS often terminates at a provider edge (CDN / load balancer / hosting
 * platform) while the customer still controls the ORIGIN TLS stack behind it.
 * Confusing the two makes a customer look powerless ("your TLS is provider
 * managed"). A public observation can indicate a provider edge, but it cannot
 * establish ownership or cryptography at an unobserved origin.
 */

import type {
  EdgeOriginIntelligence,
  OwnershipFindingInput,
  ProviderAttribution,
  TlsLayer,
} from './types'

const PROVIDER_FRONTED_CATEGORIES = new Set(['cdn_edge', 'load_balancer', 'hosting_platform'])

/** Does this finding concern transport / TLS cryptography at all? */
export function isTransportFinding(input: OwnershipFindingInput): boolean {
  const hay = `${input.algorithm ?? ''} ${input.category ?? ''} ${input.protocol ?? ''} ${input.title ?? ''} ${input.description ?? ''}`.toLowerCase()
  return /\b(tls|ssl|https|cipher|handshake|hsts|sni|alpn)\b|\btls[_-]|\b(?:tls|ssl)v\d/.test(hay)
}

/**
 * Classify a transport finding into edge / origin (and application) layers.
 * Returns null when the finding is not transport-related.
 */
export function classifyEdgeVsOrigin(
  input: OwnershipFindingInput,
  attribution: ProviderAttribution,
): EdgeOriginIntelligence | null {
  if (!isTransportFinding(input)) return null

  const providerFronted =
    (attribution.attributed && PROVIDER_FRONTED_CATEGORIES.has(attribution.category)) ||
    (input.assetType ? new Set(['cdn-service', 'reverse-proxy', 'cloud-load-balancer']).has(input.assetType) : false)

  if (!providerFronted) return null
  const providerName = attribution.attributed ? attribution.providerName : 'Edge provider'
  const edge: TlsLayer = {
    layer: 'edge',
    owner: providerName,
    domain: 'provider',
    managed: true,
    customerControl: 'no',
    observedProtocol: input.protocol,
    observedAlgorithm: input.algorithm,
    hybridSupported: 'unknown',
    recommendation: 'Confirm TLS termination in the provider configuration and verify the origin separately.',
  }
  return {
    isProviderFronted: true,
    edge,
    origin: null,
    layers: [edge],
    summary: `TLS evidence indicates a provider edge (${providerName}). Origin ownership and configuration are unverified.`,
  }
}
