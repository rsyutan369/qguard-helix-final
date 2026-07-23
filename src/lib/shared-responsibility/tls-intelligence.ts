/**
 * TLS Intelligence Engine™ — Edge vs Origin.
 *
 * Public TLS often terminates at a provider edge (CDN / load balancer / hosting
 * platform) while the customer still controls the ORIGIN TLS stack behind it.
 * Confusing the two makes a customer look powerless ("your TLS is provider
 * managed") when they can in fact upgrade their origin today. This engine splits
 * a transport finding into its termination layers and assigns ownership to each.
 */

import type {
  EdgeOriginIntelligence,
  OwnershipFindingInput,
  ProviderAttribution,
  TlsLayer,
} from './types'

const TLS_TARGET_TYPES = new Set([
  'cdn-service',
  'reverse-proxy',
  'public-tls-endpoint',
  'cloud-load-balancer',
  'api-gateway',
  'web-application',
])

const PROVIDER_FRONTED_CATEGORIES = new Set(['cdn_edge', 'load_balancer', 'hosting_platform'])

/** Does this finding concern transport / TLS cryptography at all? */
export function isTransportFinding(input: OwnershipFindingInput): boolean {
  const hay = `${input.algorithm ?? ''} ${input.category ?? ''} ${input.protocol ?? ''} ${input.title ?? ''} ${input.description ?? ''}`.toLowerCase()
  if (/\b(tls|ssl|https|cipher|handshake|certificate|cert|hsts|sni|alpn|protocol)\b/.test(hay)) return true
  if (input.assetType && TLS_TARGET_TYPES.has(input.assetType)) return true
  return false
}

function hybridFromRoadmap(status: ProviderAttribution['pqRoadmapStatus']): TlsLayer['hybridSupported'] {
  if (status === 'shipping') return 'yes'
  if (status === 'in_progress' || status === 'announced') return 'unknown'
  return 'unknown'
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

  const layers: TlsLayer[] = []

  if (providerFronted) {
    const providerName = attribution.attributed ? attribution.providerName : 'Edge provider'
    const hybrid = hybridFromRoadmap(attribution.pqRoadmapStatus)
    const edge: TlsLayer = {
      layer: 'edge',
      owner: providerName,
      domain: 'provider',
      managed: true,
      customerControl: 'no',
      observedProtocol: input.protocol,
      hybridSupported: hybrid,
      recommendation:
        hybrid === 'yes'
          ? `${providerName} already negotiates post-quantum hybrid TLS for compatible clients. Enable full/strict origin mode and monitor the ${providerName} roadmap — no customer edge-certificate change is required.`
          : `Edge TLS terminates at ${providerName} and is provider-managed. Monitor the ${providerName} post-quantum roadmap; the customer cannot replace the edge certificate directly.`,
    }
    const origin: TlsLayer = {
      layer: 'origin',
      owner: 'Customer',
      domain: 'customer',
      managed: false,
      customerControl: 'yes',
      observedProtocol: input.protocol,
      observedAlgorithm: input.algorithm,
      hybridSupported: 'unknown',
      recommendation:
        'Origin TLS is customer-controlled. Upgrade the origin crypto library (e.g. OpenSSL 3.5+), deploy an ML-KEM hybrid key exchange (X25519+ML-KEM), and enforce full-strict verification between edge and origin.',
    }
    layers.push(edge, origin)
    return {
      isProviderFronted: true,
      edge,
      origin,
      layers,
      summary: `Public TLS terminates at ${providerName} (provider-managed edge); the origin behind it is customer-controlled and can be hardened today.`,
    }
  }

  // Not provider-fronted — a single customer-controlled origin/application layer.
  const origin: TlsLayer = {
    layer: 'origin',
    owner: 'Customer',
    domain: 'customer',
    managed: false,
    customerControl: 'yes',
    observedProtocol: input.protocol,
    observedAlgorithm: input.algorithm,
    hybridSupported: 'unknown',
    recommendation:
      'This TLS endpoint is customer-controlled end to end. Upgrade the TLS library, replace RSA/ECC key exchange with an ML-KEM hybrid, and rotate to a quantum-safe certificate profile when your CA supports it.',
  }
  layers.push(origin)
  return {
    isProviderFronted: false,
    edge: null,
    origin,
    layers,
    summary: 'TLS is customer-controlled end to end — directly actionable without a provider dependency.',
  }
}
