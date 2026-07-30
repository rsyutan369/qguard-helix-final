/**
 * Shared Responsibility classifier.
 *
 * Turns a normalized finding input into a fully classified `OwnershipFinding`:
 * responsibility domain, owner, responsible party, actionability, business
 * impact, effort/timeline, provider attribution, edge/origin intelligence, the
 * migration-dependency chain and layered confidence.
 *
 * Reconciliation: when a caller passes the existing `RemediationModel.authority`
 * (from `ScanFinding`), it takes precedence for the domain decision so this
 * engine stays backward compatible with the platform's current model. Otherwise
 * the domain is derived from evidence-based attribution.
 */

import { attributeProvider } from './provider-attribution'
import { buildDependencyChain, deriveMigrationDependencyStatus } from './dependency-graph'
import { classifyEdgeVsOrigin, isTransportFinding } from './tls-intelligence'
import type {
  AttributionContext,
  BusinessImpact,
  CustomerActionability,
  FindingPriority,
  FindingSeverityLevel,
  MigrationComplexity,
  OwnershipConfidence,
  OwnershipFinding,
  OwnershipFindingInput,
  ProviderAttribution,
  ResponsibilityDomain,
} from './types'

function normalizeSeverity(raw?: string): FindingSeverityLevel {
  const s = (raw ?? '').toLowerCase()
  if (s.includes('critical')) return 'critical'
  if (s.includes('high')) return 'high'
  if (s.includes('medium') || s.includes('moderate')) return 'medium'
  if (s.includes('low')) return 'low'
  if (s.includes('safe') || s.includes('info') || s.includes('none')) return 'safe'
  return 'medium'
}

function severityToScore(severity: FindingSeverityLevel): number {
  switch (severity) {
    case 'critical':
      return 90
    case 'high':
      return 72
    case 'medium':
      return 48
    case 'low':
      return 24
    default:
      return 8
  }
}

function severityToPriority(severity: FindingSeverityLevel): FindingPriority {
  switch (severity) {
    case 'critical':
      return 'critical'
    case 'high':
      return 'high'
    case 'medium':
      return 'medium'
    case 'low':
      return 'low'
    default:
      return 'informational'
  }
}

/** Which internal team owns a customer-controlled finding of this shape. */
function inferCustomerTeam(input: OwnershipFindingInput): string {
  const hay = `${input.algorithm ?? ''} ${input.category ?? ''} ${input.assetType ?? ''} ${input.title ?? ''} ${input.description ?? ''}`.toLowerCase()
  if (/jwt|token|oauth|oidc|saml|identity|sso/.test(hay)) return 'Identity Team'
  if (/database|db |postgres|mysql|mongo|data-at-rest|storage encryption/.test(hay)) return 'Data / Database Team'
  if (/key|hsm|kms|keystore|keyring|vault|secret/.test(hay)) return 'Key Management Team'
  if (/code sign|signing|artifact|supply chain|package/.test(hay)) return 'Application / Platform Team'
  if (/ssh|vpn/.test(hay)) return 'Infrastructure Team'
  if (/tls|ssl|certificate|cert|pki|https|cipher|handshake/.test(hay)) return 'PKI / Infrastructure Team'
  if (/api|jwt|app|web|service/.test(hay)) return 'Application / Platform Team'
  return 'Infrastructure Team'
}

/** Asset types the customer deploys and therefore controls directly. */
const CUSTOMER_DEPLOYED_ASSET_TYPES = new Set([
  'workstation',
  'server',
  'virtual-machine',
  'local-file',
  'local-keystore',
  'device-certificate',
  'ssh-directory',
  'database',
  'network-device',
  'pki-infrastructure',
  'cloud-infrastructure',
  'cloud-database',
  'cloud-storage',
  'cloud-kms',
  'cloud-hsm',
  'kubernetes-cluster',
  'container',
  'web-application',
  'api-gateway',
  'endpoint-security',
  'certificate',
  'app',
  'developer-platform',
])

/**
 * Libraries, runtimes and operating systems the customer DEPLOYS are
 * customer-controlled (upgrading OpenSSL/Java/.NET on your own server is your
 * action), even though the same technology is an ecosystem dependency when it
 * lives in a third-party device the customer does not run.
 */
const ADOPTABLE_ECOSYSTEM_CATEGORIES = new Set(['crypto_library', 'runtime', 'operating_system'])

function isCustomerDeployedAsset(input: OwnershipFindingInput): boolean {
  if (input.assetType && CUSTOMER_DEPLOYED_ASSET_TYPES.has(input.assetType)) return true
  const env = (input.environment ?? '').toLowerCase()
  return /internal|on-?prem|corporate|private|datacenter|data center|staging|production/.test(env)
}

/** Flip an ecosystem library/runtime/OS finding to customer when self-deployed. */
function refineEcosystemDomain(base: ResponsibilityDomain, input: OwnershipFindingInput, attribution: ProviderAttribution): ResponsibilityDomain {
  if (base === 'ecosystem' && ADOPTABLE_ECOSYSTEM_CATEGORIES.has(attribution.category) && isCustomerDeployedAsset(input)) {
    return 'customer'
  }
  return base
}

/** Decide the ownership domain, reconciling with the existing RemediationModel. */
function resolveDomain(input: OwnershipFindingInput, attribution: ProviderAttribution): ResponsibilityDomain {
  switch (input.remediationAuthority) {
    case 'qguard_controlled':
    case 'customer_admin_configurable':
      return 'customer'
    case 'provider_owned':
      return attribution.attributed && attribution.domain === 'ecosystem' ? 'ecosystem' : 'provider'
    case 'advisory_only':
      return refineEcosystemDomain(attribution.domain !== 'customer' ? attribution.domain : 'ecosystem', input, attribution)
    default:
      // Attribution always returns a meaningful domain: a matched provider, an
      // honest generic provider domain for provider-fronted targets, or the
      // customer default when nothing matched.
      return refineEcosystemDomain(attribution.domain, input, attribution)
  }
}

function resolveActionability(
  domain: ResponsibilityDomain,
  input: OwnershipFindingInput,
  isProviderFrontedTransport: boolean,
): CustomerActionability {
  if (domain === 'customer') {
    return input.remediationAuthority === 'customer_admin_configurable' ? 'partial' : 'yes'
  }
  // Provider-fronted TLS: edge is provider-managed but the origin is fixable.
  if (domain === 'provider' && isProviderFrontedTransport) return 'partial'
  return 'no'
}

function resolvePriority(
  domain: ResponsibilityDomain,
  severity: FindingSeverityLevel,
  actionable: CustomerActionability,
): FindingPriority {
  // Only actionable customer work carries real priority — the platform
  // prioritizes what the customer can actually do.
  if (domain === 'customer') return severityToPriority(severity)
  if (actionable === 'partial') return severity === 'critical' || severity === 'high' ? 'high' : 'medium'
  if (domain === 'ecosystem') return severity === 'critical' || severity === 'high' ? 'medium' : 'informational'
  return 'informational'
}

function resolveComplexity(domain: ResponsibilityDomain, input: OwnershipFindingInput, severity: FindingSeverityLevel): MigrationComplexity {
  if (domain !== 'customer') return 'low'
  const hay = `${input.category ?? ''} ${input.assetType ?? ''} ${input.title ?? ''}`.toLowerCase()
  if (/pki|certificate|database|hsm|kms|key/.test(hay) && (severity === 'critical' || severity === 'high')) return 'high'
  if (severity === 'critical' || severity === 'high') return 'medium'
  return 'low'
}

function effortFor(domain: ResponsibilityDomain, complexity: MigrationComplexity): { effort: string; timeline: string } {
  if (domain !== 'customer') return { effort: 'None (monitor provider/ecosystem roadmap)', timeline: 'Provider / ecosystem dependent' }
  switch (complexity) {
    case 'high':
      return { effort: '~1 FTE-week', timeline: '2–4 weeks' }
    case 'medium':
      return { effort: '~2 FTE-days', timeline: '1 week' }
    default:
      return { effort: '~0.5 FTE-day', timeline: '1–2 days' }
  }
}

function businessImpactFor(input: OwnershipFindingInput, severity: FindingSeverityLevel, domain: ResponsibilityDomain): BusinessImpact {
  const internet = /public|internet|external|edge|dmz/.test((input.environment ?? '').toLowerCase())
  const hndl = input.isHNDL === true
  let level: BusinessImpact['level'] = 'low'
  if (severity === 'critical' && (internet || hndl)) level = 'critical'
  else if (severity === 'critical' || (severity === 'high' && (internet || hndl))) level = 'high'
  else if (severity === 'high' || severity === 'medium') level = 'medium'

  const parts: string[] = []
  if (hndl) parts.push('long-lived data is exposed to harvest-now-decrypt-later')
  if (internet) parts.push('the asset is internet-facing')
  const owner =
    domain === 'customer'
      ? 'directly remediable by the organization'
      : domain === 'provider'
        ? 'dependent on the provider roadmap'
        : 'dependent on ecosystem adoption'
  const context = parts.length ? ` — ${parts.join(' and ')}` : ''
  return { level, summary: `${level.charAt(0).toUpperCase() + level.slice(1)} business impact${context}; ${owner}.` }
}

function ownerLabels(
  domain: ResponsibilityDomain,
  attribution: ProviderAttribution,
  input: OwnershipFindingInput,
): { ownerType: string; responsibleParty: string; remediationDomain: string } {
  if (domain === 'customer') {
    const team = inferCustomerTeam(input)
    return { ownerType: 'Customer', responsibleParty: team, remediationDomain: team }
  }
  if (domain === 'provider') {
    const name = attribution.attributed ? attribution.providerName : 'Provider'
    return { ownerType: name, responsibleParty: name, remediationDomain: `${name} (Provider Managed)` }
  }
  // ecosystem
  const name = attribution.attributed ? attribution.providerName : 'Industry Ecosystem'
  const remediation =
    attribution.category === 'browser'
      ? 'Browser Vendor'
      : attribution.category === 'hardware'
        ? 'Hardware / Firmware Vendor'
        : attribution.category === 'standards_body' || attribution.category === 'certificate_authority'
          ? 'Standards Body / CA'
          : name
  return { ownerType: 'Industry Ecosystem', responsibleParty: name, remediationDomain: remediation }
}

/**
 * Which NIST primitive class replaces this finding.
 *
 * `isTransportFinding` matches the word "certificate", so a certificate SIGNATURE
 * finding used to be handed the ML-KEM key-exchange recommendation — ML-KEM is a
 * key-establishment mechanism (FIPS 203) and can never replace a signature.
 * Cipher-suite identifiers are checked first: `TLS_ECDHE_ECDSA_…` names both a
 * key exchange and a signature, and its quantum-vulnerable key agreement (ECDHE)
 * is what ML-KEM replaces.
 */
export type RemediationTarget = 'key-establishment' | 'signature' | 'general'

export function classifyRemediationTarget(input: OwnershipFindingInput): RemediationTarget {
  const algorithm = `${input.algorithm ?? ''}`.trim()
  const hay = `${algorithm} ${input.category ?? ''} ${input.title ?? ''} ${input.description ?? ''}`.toLowerCase()

  // A cipher-suite / key-agreement finding — ML-KEM (FIPS 203) territory.
  if (/^tls[_-]/i.test(algorithm)) return 'key-establishment'
  if (/cipher suite|key exchange|key agreement|forward secrecy|\bkex\b|\becdh\b|\bdhe?\b|handshake|x25519/.test(hay)) {
    return 'key-establishment'
  }
  // A signature / certificate-chain finding — ML-DSA (FIPS 204) territory.
  if (/signature|certificate|\bcert\b|\becdsa\b|ed25519|\bdsa\b|\bx\.?509\b|signing|sha-?1\s*with|with-?sha/.test(hay)) {
    return 'signature'
  }
  return 'general'
}

function recommendedActionFor(
  domain: ResponsibilityDomain,
  attribution: ProviderAttribution,
  input: OwnershipFindingInput,
  isProviderFrontedTransport: boolean,
): { action: string; status: string; allowed: string[] } {
  if (domain === 'customer') {
    const target = classifyRemediationTarget(input)
    const action =
      target === 'key-establishment'
        ? 'Replace RSA/ECC key exchange with an ML-KEM hybrid (X25519+ML-KEM, FIPS 203) and upgrade the origin TLS library.'
        : target === 'signature'
          ? 'Migrate the certificate / signature chain to ML-DSA-65 (FIPS 204), hybrid with ECDSA P-256 where interoperability requires, and re-issue affected certificates.'
          : 'Migrate to the NIST-approved PQC replacement and rotate affected keys/certificates.'
    return {
      action,
      status: 'Action Required',
      allowed: ['migrate', 'rotate_key', 'deploy_hybrid', 'create_ticket', 'enable_monitoring'],
    }
  }
  if (domain === 'provider') {
    const name = attribution.attributed ? attribution.providerName : 'the provider'
    if (isProviderFrontedTransport) {
      return {
        action: `Edge TLS is managed by ${name}: monitor its PQ roadmap and enable full-strict mode. Separately, upgrade your customer-controlled origin TLS to an ML-KEM hybrid.`,
        status: 'Provider Managed (origin actionable)',
        allowed: ['monitor_provider_roadmap', 'enable_full_strict', 'harden_origin', 'track_vendor_readiness'],
      }
    }
    return {
      action: `Monitor ${name}'s post-quantum roadmap, protect sensitive data before it reaches the provider, and track vendor readiness.`,
      status: 'Provider Managed',
      allowed: ['monitor_provider_roadmap', 'protect_data', 'track_vendor_readiness', 'create_vendor_ticket'],
    }
  }
  return {
    action: 'Monitor ecosystem adoption (browser / OS / standards / hardware) and plan for the compatibility window; no direct customer remediation exists today.',
    status: 'Ecosystem Dependency',
    allowed: ['monitor_adoption', 'assign_owner', 'document_residual_risk'],
  }
}

function computeConfidence(
  input: OwnershipFindingInput,
  attribution: ProviderAttribution,
  domain: ResponsibilityDomain,
): OwnershipConfidence {
  const providerAttribution = attribution.confidence
  const authorityKnown = Boolean(input.remediationAuthority)
  const ownership = authorityKnown ? 90 : attribution.attributed ? Math.min(90, attribution.confidence + 5) : 55
  const actionability = domain === 'customer' ? (authorityKnown ? 92 : 70) : attribution.attributed ? 80 : 55
  const overall = Math.round(ownership * 0.4 + actionability * 0.3 + providerAttribution * 0.3)
  return { overall, ownership, actionability, providerAttribution }
}

/** Compact ownership tag — a cheap classification for high-volume surfaces
 * (e.g. tagging every scanner finding) that skips the dependency chain and
 * edge/origin detail while staying consistent with the full classifier. */
export interface OwnershipTag {
  domain: ResponsibilityDomain
  ownerType: string
  responsibleParty: string
  customerActionable: CustomerActionability
  providerName: string
  providerAttributed: boolean
  providerAttributionConfidence: number
  migrationDependencyStatus: OwnershipFinding['migrationDependencyStatus']
}

export function quickOwnershipTag(input: OwnershipFindingInput, context: AttributionContext = {}): OwnershipTag {
  const attribution = attributeProvider(input, context)
  const domain = resolveDomain(input, attribution)
  const customerActionable = resolveActionability(domain, input, false)
  const { ownerType, responsibleParty } = ownerLabels(domain, attribution, input)
  const migrationDependencyStatus = deriveMigrationDependencyStatus(domain, attribution, customerActionable)
  return {
    domain,
    ownerType,
    responsibleParty,
    customerActionable,
    providerName: attribution.providerName,
    providerAttributed: attribution.attributed,
    providerAttributionConfidence: attribution.confidence,
    migrationDependencyStatus,
  }
}

/** Classify a single finding input into the normalized ownership model. */
export function classifyFinding(input: OwnershipFindingInput, context: AttributionContext = {}): OwnershipFinding {
  const severity = normalizeSeverity(input.severity)
  const attribution = attributeProvider(input, context)
  const domain = resolveDomain(input, attribution)
  const edgeOrigin = classifyEdgeVsOrigin(input, attribution)
  const isProviderFrontedTransport = Boolean(edgeOrigin?.isProviderFronted) && domain === 'provider'

  const customerActionable = resolveActionability(domain, input, isProviderFrontedTransport)
  const priority = resolvePriority(domain, severity, customerActionable)
  const complexity = resolveComplexity(domain, input, severity)
  const { effort, timeline } = effortFor(domain, complexity)
  const businessImpact = businessImpactFor(input, severity, domain)
  const { ownerType, responsibleParty, remediationDomain } = ownerLabels(domain, attribution, input)
  const { action, status, allowed } = recommendedActionFor(domain, attribution, input, isProviderFrontedTransport)

  const migrationDependencyStatus = deriveMigrationDependencyStatus(domain, attribution, customerActionable)
  const dependencyChain = buildDependencyChain(migrationDependencyStatus, attribution, domain, isTransportFinding(input))
  const confidence = computeConfidence(input, attribution, domain)

  const providerDependency =
    domain === 'provider'
      ? attribution.attributed
        ? attribution.providerName
        : 'Provider'
      : isProviderFrontedTransport
        ? attribution.providerName
        : null
  const ecosystemDependency =
    domain === 'ecosystem'
      ? attribution.category === 'browser'
        ? 'Browser Support'
        : attribution.category === 'hardware'
          ? 'Hardware / Firmware'
          : attribution.category === 'standards_body' || attribution.category === 'certificate_authority'
            ? 'Standards / CA Issuance'
            : attribution.attributed
              ? attribution.providerName
              : 'Industry Adoption'
      : null

  const canFixLabel =
    customerActionable === 'yes' ? 'Immediately actionable' : customerActionable === 'partial' ? 'Partially actionable' : 'Not customer-actionable'

  const title =
    input.title ||
    `${input.algorithm || input.category || 'Quantum-vulnerable cryptography'}${input.assetName ? ` on ${input.assetName}` : ''}`

  return {
    id: input.id,
    title,
    description: input.description || `${input.algorithm || 'Cryptographic'} finding classified under the ${domain}-controlled responsibility domain.`,
    severity,
    priority,
    quantumRiskScore: typeof input.quantumRiskScore === 'number' ? Math.round(input.quantumRiskScore) : severityToScore(severity),

    domain,
    ownerType,
    responsibleParty,
    remediationDomain,

    customerActionable,
    providerDependency,
    ecosystemDependency,

    actionability: {
      canCustomerFix: customerActionable,
      label: canFixLabel,
      reason:
        domain === 'customer'
          ? 'The organization owns this asset and controls the remediation path.'
          : domain === 'provider'
            ? `${attribution.attributed ? attribution.providerName : 'The provider'} manages this cryptographic surface from outside the customer's control.`
            : 'Remediation depends on ecosystem participants (browsers, operating systems, hardware or standards).',
      recommendedAction: action,
      allowedActions: allowed,
    },
    migrationDependencyStatus,
    businessImpact,
    migrationComplexity: complexity,
    estimatedEffort: effort,
    estimatedTimeline: timeline,

    attribution,
    dependencyChain,
    edgeOrigin,
    confidence,
    evidence: {
      detectionMethod: input.detectionMethod || 'Scanner intelligence classification',
      evidenceSource: input.evidenceSource || 'QGuard scanner intelligence',
      confidence: confidence.overall,
      ownershipReason:
        domain === 'customer'
          ? 'Asset is customer-owned / customer-deployed.'
          : `${attribution.reason}`,
      actionabilityReason: canFixLabel,
      providerAttributionReason: attribution.reason,
    },
    references: attribution.reference ? [{ label: `${attribution.providerName} reference`, url: attribution.reference }] : [],

    recommendedAction: action,
    status,
    asset: input.assetName || input.location || input.host || 'Unknown asset',
    assetType: input.assetType || 'asset',
    algorithm: input.algorithm || '',
  }
}
