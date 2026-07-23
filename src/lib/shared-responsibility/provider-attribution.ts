/**
 * Evidence-derived provider attribution.
 *
 * Given a normalized finding input and tenant-wide context, attribute the
 * finding to a catalog provider using ONLY signals already present in real
 * tenant evidence (hostnames, per-finding provider tags, response headers,
 * keywords, scanner target types). No outbound network calls are made.
 *
 * Honesty rules (evidence-driven, never fabricated):
 *  - A tenant-wide connected account NEVER blanket-attributes unrelated
 *    findings; it only CORROBORATES a provider the finding's own evidence
 *    already points to, or promotes an ambiguous target-type match.
 *  - A target type alone (e.g. `cdn-service`) does not name a specific provider
 *    unless the tenant actually uses one; otherwise the finding is labelled with
 *    an honest generic provider domain (`attributed: false`).
 *  - When nothing matches, ownership defaults to the customer with
 *    `attributed: false`.
 */

import { CUSTOMER_PROFILE, PROVIDER_CATALOG } from './provider-catalog'
import type {
  AttributionContext,
  OwnershipFindingInput,
  ProviderAttribution,
  ProviderCategory,
  ProviderProfile,
} from './types'

function lower(value: unknown): string {
  return typeof value === 'string' ? value.toLowerCase() : value == null ? '' : String(value).toLowerCase()
}

/** Scanner target types that terminate TLS at a provider edge. */
const EDGE_TARGET_TYPES = new Set(['cdn-service', 'reverse-proxy', 'cloud-load-balancer'])
const SAAS_TARGET_TYPES = new Set(['saas-application'])

function buildCorpus(input: OwnershipFindingInput): string {
  const parts: string[] = [input.host, input.location, input.assetName, input.title, input.description, input.protocol].filter(
    Boolean,
  ) as string[]
  const meta = input.metadata
  if (meta && typeof meta === 'object') {
    for (const value of Object.values(meta)) {
      if (typeof value === 'string') parts.push(value)
      else if (value && typeof value === 'object') {
        try {
          parts.push(JSON.stringify(value))
        } catch {
          /* ignore non-serializable metadata */
        }
      }
    }
  }
  return parts.join('  ').toLowerCase()
}

function anyIncludes(corpus: string, needles?: string[]): string | null {
  if (!needles) return null
  for (const needle of needles) {
    const n = needle.toLowerCase()
    if (n && corpus.includes(n)) return needle
  }
  return null
}

interface Match {
  profile: ProviderProfile
  confidence: number
  method: ProviderAttribution['method']
  reason: string
}

/** Is this profile backed by a tenant-connected account? */
function isConnected(profile: ProviderProfile, connectors: string[]): boolean {
  if (!profile.fingerprints.connectorProvider) return false
  return profile.fingerprints.connectorProvider.some((p) => connectors.includes(p.toLowerCase()))
}

/**
 * Score a provider against a finding's OWN evidence. `connected` (whether the
 * tenant has a matching connected account) only strengthens an intrinsic match
 * or promotes an ambiguous target-type match — it never fabricates one.
 */
function scoreProfile(
  profile: ProviderProfile,
  input: OwnershipFindingInput,
  corpus: string,
  connected: boolean,
): Match | null {
  const fp = profile.fingerprints
  const assetType = input.assetType
  const providerHint = lower(input.provider)

  // Per-finding provider tag (ScanTarget.provider) — strongest intrinsic signal.
  if (providerHint) {
    const hintMatch =
      providerHint === profile.id ||
      providerHint === lower(profile.name) ||
      (fp.connectorProvider ? fp.connectorProvider.some((p) => p.toLowerCase() === providerHint) : false)
    if (hintMatch) {
      return {
        profile,
        confidence: 90,
        method: 'metadata',
        reason: `Finding is explicitly tagged with provider "${input.provider}" (${profile.name}).`,
      }
    }
  }

  // Hostname / CNAME evidence.
  const hostMatch = anyIncludes(corpus, fp.hostname) || anyIncludes(corpus, fp.cname)
  if (hostMatch) {
    return {
      profile,
      confidence: connected ? 96 : 90,
      method: 'hostname',
      reason: `Hostname / DNS evidence matched ${profile.name} marker "${hostMatch}"${connected ? ' (corroborated by a connected account)' : ''}.`,
    }
  }

  // Response header markers captured in evidence metadata.
  const headerMatch = anyIncludes(corpus, fp.header)
  if (headerMatch) {
    return {
      profile,
      confidence: connected ? 92 : 86,
      method: 'header',
      reason: `Response header evidence matched ${profile.name} marker "${headerMatch}".`,
    }
  }

  // Keyword reference in the finding's own text.
  const keywordMatch = anyIncludes(corpus, fp.keywords)
  if (keywordMatch) {
    return {
      profile,
      confidence: connected ? 80 : 66,
      method: 'keyword',
      reason: `Evidence text referenced ${profile.name} ("${keywordMatch}")${connected ? ' and the tenant has a connected account' : ''}.`,
    }
  }

  // Target type alone is ambiguous (many providers share `cloud-load-balancer`),
  // so it only NAMES a provider when the tenant actually uses that provider.
  if (connected && assetType && fp.targetType?.includes(assetType as never)) {
    return {
      profile,
      confidence: 64,
      method: 'target-type',
      reason: `Scanner target type "${assetType}" matches ${profile.name}, which the tenant has connected.`,
    }
  }

  return null
}

/** Honest generic attribution for a provider-fronted target we cannot name. */
function genericFallback(input: OwnershipFindingInput): ProviderAttribution | null {
  const assetType = input.assetType
  if (assetType && EDGE_TARGET_TYPES.has(assetType)) {
    const category: ProviderCategory = assetType === 'cloud-load-balancer' ? 'load_balancer' : 'cdn_edge'
    return {
      providerId: null,
      providerName: 'Edge / Cloud Provider',
      domain: 'provider',
      category,
      confidence: 45,
      method: 'target-type',
      reason: `Target type "${assetType}" is provider-fronted, but the specific provider could not be attributed from evidence. Capture TLS/header evidence or connect the provider account to identify it.`,
      attributed: false,
      pqRoadmapStatus: 'unknown',
      customerInfluence: 'low',
    }
  }
  if (assetType && SAAS_TARGET_TYPES.has(assetType)) {
    return {
      providerId: null,
      providerName: 'SaaS Vendor',
      domain: 'provider',
      category: 'saas',
      confidence: 45,
      method: 'target-type',
      reason: `Target type "${assetType}" is a SaaS application; the specific vendor could not be attributed from evidence.`,
      attributed: false,
      pqRoadmapStatus: 'unknown',
      customerInfluence: 'low',
    }
  }
  return null
}

/**
 * Attribute a finding to a provider using evidence only. Never fabricates: an
 * unmatched finding returns either an honest generic provider label (for
 * provider-fronted target types) or the customer profile — both with
 * `attributed: false`.
 */
export function attributeProvider(
  input: OwnershipFindingInput,
  context: AttributionContext = {},
): ProviderAttribution {
  const corpus = buildCorpus(input)
  const connectors = (context.connectorProviders || []).map(lower)
  let best: Match | null = null

  for (const profile of PROVIDER_CATALOG) {
    const connected = isConnected(profile, connectors)
    const match = scoreProfile(profile, input, corpus, connected)
    if (match && (!best || match.confidence > best.confidence)) best = match
  }

  if (best) {
    return {
      providerId: best.profile.id,
      providerName: best.profile.name,
      domain: best.profile.domain,
      category: best.profile.category,
      confidence: best.confidence,
      method: best.method,
      reason: best.reason,
      attributed: true,
      pqRoadmapStatus: best.profile.pqRoadmapStatus,
      pqRoadmapNote: best.profile.pqRoadmapNote,
      customerInfluence: best.profile.customerInfluence,
      reference: best.profile.reference,
    }
  }

  const generic = genericFallback(input)
  if (generic) return generic

  // No evidence matched — honest default to customer ownership.
  return {
    providerId: null,
    providerName: CUSTOMER_PROFILE.name,
    domain: 'customer',
    category: 'unknown',
    confidence: 40,
    method: 'default',
    reason:
      'No provider evidence matched; ownership defaults to the customer. Connect a provider account or capture TLS/header evidence to raise attribution confidence.',
    attributed: false,
    pqRoadmapStatus: 'not_applicable',
    customerInfluence: 'high',
  }
}
