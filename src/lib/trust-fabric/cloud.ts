/**
 * Cloud estate normalisation for the Trust Fabric.
 *
 * Brief section 6 sets one hard constraint: "Do not assume a cloud asset exists
 * unless it actually exists in the user's tenant data." There is no
 * `cloud_resources` table in this platform, so a cloud resource here is always a
 * real row the tenant already owns - an `assets` record, a `connector_accounts`
 * record, or an asset corroborated by scanner/runtime evidence - projected into
 * a provider-normalised shape.
 *
 * Attribution reuses the shared-responsibility provider catalog rather than a
 * second keyword table, so a host attributed to AWS on the Migration
 * Intelligence page is attributed to AWS here too. When nothing in the row's own
 * evidence names a cloud, the resource is bucketed as `unattributed` with
 * `attributed: false` and is EXCLUDED from every per-provider percentage - it is
 * not quietly assigned to whichever cloud the tenant happens to have connected.
 */

import { attributeProvider } from '@/lib/shared-responsibility/provider-attribution'
import type { AttributionContext } from '@/lib/shared-responsibility/types'
import { CLOUD_PROVIDER_LABEL, type CloudProviderId } from './types'

/* ------------------------------------------------------------------ */
/* Provider identity                                                   */
/* ------------------------------------------------------------------ */

/**
 * Maps a catalog provider id (or a raw connector `provider` column) onto the
 * cloud vocabulary these pages publish. Anything that is a real vendor but not
 * one of the named clouds becomes `other`, never a guess at one of the big three.
 */
const PROVIDER_ALIASES: Array<{ id: CloudProviderId; test: RegExp }> = [
  { id: 'aws', test: /^(aws|amazon|amazon-web-services|amazonaws|ec2|s3|cloudfront|acm|elb|alb|route53)$/i },
  { id: 'azure', test: /^(azure|microsoft|microsoft-azure|ms-azure|entra|azuread|azure-ad|keyvault|key-vault)$/i },
  { id: 'gcp', test: /^(gcp|google|google-cloud|googlecloud|gce|gke|google-cloud-platform)$/i },
  { id: 'kubernetes', test: /^(k8s|kubernetes|openshift|eks|aks|rancher)$/i },
  { id: 'oracle', test: /^(oci|oracle|oracle-cloud)$/i },
  { id: 'ibm', test: /^(ibm|ibm-cloud|softlayer)$/i },
  { id: 'alibaba', test: /^(alibaba|aliyun|alicloud)$/i },
  { id: 'digitalocean', test: /^(digitalocean|do|digital-ocean)$/i },
  { id: 'cloudflare', test: /^(cloudflare|cf)$/i },
  { id: 'private-cloud', test: /^(private|on-prem|onprem|on-premise|datacenter|data-center|vmware|vsphere|openstack|nutanix)$/i },
  { id: 'hybrid', test: /^(hybrid|hybrid-cloud|multi-cloud|multicloud)$/i },
]

/** Free-text signals, applied only to a row's OWN evidence corpus. */
const PROVIDER_SIGNALS: Array<{ id: CloudProviderId; test: RegExp }> = [
  { id: 'aws', test: /\b(aws|amazonaws|amazon web services|ec2|eks|s3\.|rds\.|elasticbeanstalk|cloudfront|\.amazonaws\.com|arn:aws)\b/i },
  { id: 'azure', test: /\b(azure|azurewebsites|blob\.core\.windows\.net|\.azure\.com|vault\.azure\.net|microsoft\.com\/subscriptions|aks)\b/i },
  { id: 'gcp', test: /\b(gcp|google cloud|googleapis|appspot|\.run\.app|gke|cloudkms|projects\/[a-z0-9-]+\/locations)\b/i },
  { id: 'kubernetes', test: /\b(kubernetes|k8s|kube-system|\.svc\.cluster\.local|openshift|ingress-nginx)\b/i },
  { id: 'oracle', test: /\b(oraclecloud|ocid1\.|oci_)\b/i },
  { id: 'ibm', test: /\b(ibmcloud|bluemix|softlayer)\b/i },
  { id: 'alibaba', test: /\b(aliyuncs|alibabacloud|aliyun)\b/i },
  { id: 'digitalocean', test: /\b(digitalocean|\.ondigitalocean\.app)\b/i },
  { id: 'cloudflare', test: /\b(cloudflare|\.workers\.dev|\.pages\.dev)\b/i },
  { id: 'private-cloud', test: /\b(on-?prem(ise)?|datacenter|data ?cent(er|re)|vmware|vsphere|openstack|nutanix|\.local\b|\.internal\b|\.corp\b)\b/i },
]

/** Region tokens that themselves name a cloud, e.g. `us-east-1` or `eastus2`. */
const REGION_SIGNALS: Array<{ id: CloudProviderId; test: RegExp }> = [
  { id: 'aws', test: /^(us|eu|ap|sa|ca|me|af|il)-(east|west|north|south|central|northeast|southeast|northwest|southwest)-\d$/i },
  { id: 'gcp', test: /^(us|europe|asia|australia|southamerica|northamerica|me)-(east|west|north|south|central|northeast|southeast)\d?$/i },
  { id: 'azure', test: /^(east|west|north|south|central|southeast|northeast)?(us|europe|asia|india|japan|australia|canada|brazil|uk|france|germany|norway|korea|africa)\d*$/i },
]

export function normalizeProviderId(value: unknown): CloudProviderId | null {
  const raw = String(value ?? '').trim()
  if (!raw) return null
  const slug = raw.toLowerCase().replace(/[\s_]+/g, '-')
  for (const alias of PROVIDER_ALIASES) if (alias.test.test(slug)) return alias.id
  return null
}

export function providerLabelFor(provider: CloudProviderId): string {
  return CLOUD_PROVIDER_LABEL[provider] || CLOUD_PROVIDER_LABEL.other
}

export interface ProviderAttributionResult {
  provider: CloudProviderId
  providerLabel: string
  method: string
  confidence: number
  reason: string
  attributed: boolean
}

const UNATTRIBUTED: ProviderAttributionResult = {
  provider: 'unattributed',
  providerLabel: CLOUD_PROVIDER_LABEL.unattributed,
  method: 'none',
  confidence: 0,
  reason: 'No hostname, tag, region or connector evidence names a cloud provider for this resource.',
  attributed: false,
}

/**
 * Attributes one subject to a cloud provider using only its own evidence.
 *
 * Order of authority, strongest first:
 *   1. an explicit provider field the tenant recorded (metadata / connector row)
 *   2. the shared-responsibility catalog match on the row's evidence corpus
 *   3. a raw signal in the corpus (hostname, ARN, cluster DNS)
 *   4. a region token that only one cloud uses
 *
 * A tenant-connected account never blanket-attributes an unrelated resource; it
 * only raises confidence on a match the resource's own evidence already made.
 */
export function attributeCloudProvider(input: {
  explicitProvider?: unknown
  name?: string
  host?: string
  assetType?: string
  region?: string
  corpus?: string
  connectors: string[]
}): ProviderAttributionResult {
  const explicit = normalizeProviderId(input.explicitProvider)
  if (explicit) {
    return {
      provider: explicit,
      providerLabel: providerLabelFor(explicit),
      method: 'declared',
      confidence: 100,
      reason: 'Provider recorded on the tenant record itself.',
      attributed: true,
    }
  }

  const corpus = [input.name, input.host, input.assetType, input.region, input.corpus].filter(Boolean).join('  ')

  // 2. Catalog attribution - the same engine Migration Intelligence uses.
  if (corpus.trim()) {
    const context: AttributionContext = { connectorProviders: input.connectors }
    try {
      const match = attributeProvider(
        {
          id: 'trust-fabric-attribution',
          host: input.host || '',
          assetName: input.name || '',
          assetType: input.assetType || '',
          description: input.corpus || '',
        },
        context,
      )
      if (match?.attributed) {
        const mapped = normalizeProviderId(match.providerId) || normalizeProviderId(match.providerName)
        if (mapped) {
          return {
            provider: mapped,
            providerLabel: providerLabelFor(mapped),
            method: match.method || 'catalog',
            confidence: Math.round(match.confidence ?? 70),
            reason: match.reason || 'Matched the shared provider catalog on this resource evidence.',
            attributed: true,
          }
        }
      }
    } catch {
      // Attribution is an enrichment; a catalog miss must never fail the model.
    }
  }

  // 3. Raw signal in this resource's own evidence.
  const lower = corpus.toLowerCase()
  for (const signal of PROVIDER_SIGNALS) {
    if (signal.test.test(lower)) {
      const connected = input.connectors.includes(signal.id)
      return {
        provider: signal.id,
        providerLabel: providerLabelFor(signal.id),
        method: connected ? 'evidence + connected account' : 'evidence',
        confidence: connected ? 92 : 74,
        reason: connected
          ? `Resource evidence names ${providerLabelFor(signal.id)} and the tenant has a connected ${providerLabelFor(signal.id)} account.`
          : `Resource hostname or identifier names ${providerLabelFor(signal.id)}.`,
        attributed: true,
      }
    }
  }

  // 4. Region token unique to one cloud.
  const region = String(input.region || '').trim()
  if (region) {
    for (const signal of REGION_SIGNALS) {
      if (!signal.test.test(region)) continue
      // A region pattern alone is weak; require the tenant to actually use that
      // cloud before naming it, otherwise report it honestly as unattributed.
      if (!input.connectors.includes(signal.id)) continue
      return {
        provider: signal.id,
        providerLabel: providerLabelFor(signal.id),
        method: 'region + connected account',
        confidence: 68,
        reason: `Region "${region}" follows the ${providerLabelFor(signal.id)} naming scheme and that account is connected.`,
        attributed: true,
      }
    }
  }

  return UNATTRIBUTED
}

/* ------------------------------------------------------------------ */
/* Account / service identity                                          */
/* ------------------------------------------------------------------ */

const ACCOUNT_KEYS = [
  'account',
  'account_id',
  'accountId',
  'aws_account_id',
  'subscription',
  'subscription_id',
  'subscriptionId',
  'project',
  'project_id',
  'projectId',
  'tenant_id',
  'tenantId',
  'namespace',
  'cluster',
]

/** Reads the account/subscription/project the tenant actually recorded. */
export function readAccount(metadata: Record<string, unknown>): string {
  for (const key of ACCOUNT_KEYS) {
    const value = metadata[key]
    if (typeof value === 'string' && value.trim()) return value.trim()
    if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  }
  return ''
}

const REGION_KEYS = ['region', 'location', 'availability_zone', 'availabilityZone', 'zone', 'datacenter']

export function readRegion(metadata: Record<string, unknown>, fallback = ''): string {
  for (const key of REGION_KEYS) {
    const value = metadata[key]
    if (typeof value === 'string' && value.trim()) return value.trim()
  }
  return fallback
}

/**
 * The cloud SERVICE a resource belongs to, e.g. `S3`, `Key Vault`, `GKE`.
 * Only returns a value the evidence actually supports.
 */
export function readService(input: { assetType: string; name: string; metadata: Record<string, unknown> }): string {
  const declared = ['service', 'service_name', 'serviceName', 'resource_type', 'resourceType']
    .map((key) => input.metadata[key])
    .find((value) => typeof value === 'string' && value.trim())
  if (typeof declared === 'string') return declared.trim()

  const corpus = `${input.name} ${input.assetType}`.toLowerCase()
  const known: Array<[RegExp, string]> = [
    [/\bs3\b|bucket/, 'Object Storage'],
    [/\brds\b|aurora|postgres|mysql|database|sql/, 'Managed Database'],
    [/\bkms\b|key ?vault|cloudkms|hsm/, 'Key Management'],
    [/\bacm\b|certificate manager|cert-manager/, 'Certificate Manager'],
    [/\belb\b|\balb\b|\bnlb\b|load ?balancer/, 'Load Balancer'],
    [/cloudfront|\bcdn\b/, 'Content Delivery'],
    [/lambda|function|cloud ?run|app ?service/, 'Serverless Compute'],
    [/\bec2\b|instance|\bvm\b|virtual machine|compute/, 'Compute'],
    [/\beks\b|\baks\b|\bgke\b|kubernetes|k8s/, 'Kubernetes'],
    [/api ?gateway|gateway/, 'API Gateway'],
    [/\bsqs\b|\bsns\b|queue|topic|pubsub|service ?bus/, 'Messaging'],
    [/\bvpc\b|network|subnet/, 'Networking'],
    [/\biam\b|identity|entra|cognito/, 'Identity'],
  ]
  for (const [test, label] of known) if (test.test(corpus)) return label
  return ''
}

/* ------------------------------------------------------------------ */
/* Key management                                                      */
/* ------------------------------------------------------------------ */

const KMS_SIGNALS: Array<[RegExp, string]> = [
  [/\baws[- ]?kms\b|\bkms\b.*aws|arn:aws:kms/i, 'AWS KMS'],
  [/cloudhsm/i, 'AWS CloudHSM'],
  [/key ?vault|azure ?kms/i, 'Azure Key Vault'],
  [/managed ?hsm/i, 'Azure Managed HSM'],
  [/cloud ?kms|google ?kms/i, 'Google Cloud KMS'],
  [/\bhashicorp\b|\bvault\b(?!.*azure)/i, 'HashiCorp Vault'],
  [/\bqkms\b|quantum key/i, 'QKMS'],
  [/\bhsm\b|luna|thales|entrust ?nshield/i, 'Hardware Security Module'],
  [/customer ?managed|\bcmk\b/i, 'Customer-Managed Key'],
  [/provider ?managed|platform ?managed|\bsse-s3\b/i, 'Provider-Managed Key'],
]

/** Names the key manager only when a real signal says so - never a default. */
export function readKeyManagement(corpus: string): { value: string; known: boolean } {
  for (const [test, label] of KMS_SIGNALS) {
    if (test.test(corpus)) return { value: label, known: true }
  }
  return { value: 'Not observed', known: false }
}
