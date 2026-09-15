import { Router, Request, Response, NextFunction } from 'express'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { SupabaseClient, User } from '@supabase/supabase-js'
import { createAuthClient, getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { scanEvidenceWithModules } from '@/lib/scanner/scanner_2/modules'
import { matchFingerprints } from '@/lib/scanner/scanner_2/engine/fingerprint-matcher'
import { evaluateFindings } from '@/lib/scanner/scanner_2/rules/detection-rules'
import { calculateQuantumRiskScore } from '@/lib/scanner/scanner_2/engine/risk-scoring'
import { analyzeHNDLRisks } from '@/lib/scanner/scanner_2/hndl-analyzer'
import { buildQuantumRiskAssessment } from '@/lib/scanner/scanner_2/correlation-engine'
import { calculateQuantumReadiness, getMigrationRecommendation } from '@/lib/scanner/scanner_2/pqc-migration-engine'
import {
  MANDATORY_PQC_CONFIG_VALUES,
  MANDATORY_PQC_STACK,
  mandatoryPqcStackMetadata,
} from '@/lib/crypto/mandatory-pqc-stack'
import {
  cloudSdkPatchAdapterReadiness,
  executeCloudConnectorPatch,
} from './cloud-patch-adapters'
import {
  HEARTBEAT_ONLINE_WINDOW_MS,
  MAX_COMMAND_HISTORY,
  type AgentEventName,
} from '@/lib/agent-installer/agent-release'
import { publishAgentEvent } from './agent-event-bus'
import { agentRole } from '@/lib/agent-installer/agent-release'
import {
  agentMayWrite,
  decideAgentRole,
  decideScanTypes,
  type AgentEntitlementRequest,
} from './agent-entitlement'
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'
import type { ScannerEvidenceRecord, ScanFinding, FindingSeverity } from '@/types/scanner.types'

const router = Router()

type AuthedRequest = Request & {
  user?: User
  token?: string
  client?: SupabaseClient | null
}

type AgentRequest = Request & {
  agent?: any
  client?: SupabaseClient | null
}

const memoryStore = (() => {
  const g = globalThis as typeof globalThis & {
    __qguard_agent_scanner_store__?: {
      agents: any[]
      policies: any[]
      heartbeats: any[]
      connectors: any[]
      evidence: any[]
      alerts: any[]
      runtimeCryptoEvents: any[]
      operatorActions: any[]
    }
  }
  if (!g.__qguard_agent_scanner_store__) {
    g.__qguard_agent_scanner_store__ = {
      agents: [],
      policies: [],
      heartbeats: [],
      connectors: [],
      evidence: [],
      alerts: [],
      runtimeCryptoEvents: [],
      operatorActions: [],
    }
  }
  return g.__qguard_agent_scanner_store__
})()

function randomId(prefix: string) {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID()
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
}

function hashToken(token: string) {
  return createHash('sha256').update(token).digest('hex')
}

function safeCompareHash(candidate: string, expected: string) {
  const a = Buffer.from(candidate)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

function generateAgentToken() {
  return `qga_${randomBytes(32).toString('base64url')}`
}

function cleanString(value: unknown, max = 255): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.slice(0, max)
}

function severityRank(severity: string) {
  switch (severity) {
    case 'critical': return 5
    case 'high': return 4
    case 'moderate':
    case 'medium': return 3
    case 'low': return 2
    case 'safe': return 1
    default: return 0
  }
}

function isMissingRuntimeTable(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return text.includes('42p01') || text.includes('pgrst205') || text.includes('does not exist') || text.includes('could not find the table')
}

function jsonError(res: Response, status: number, code: string, message: string, detail?: unknown) {
  /* `detail` carries the structured half of a refusal — which role was asked
     for, which tier it needs, which roles this plan does include — so the UI
     can render an actionable gate instead of re-deriving policy from prose. */
  return res.status(status).json({ error: { code, message, ...(detail === undefined ? {} : { detail }) } })
}

const DEFAULT_AGENT_SCAN_TYPES = [
  'tls',
  'certificates',
  'pki',
  'ssh',
  'packages',
  'configs',
  'libraries',
  'vpn',
  'kubernetes',
  'service_mesh',
  'api_gateway',
  'load_balancer',
  'hsm',
  'cloud',
  'cloud_kms',
  'cloud_hsm',
  'cloud_database',
  'cloud_storage',
  'cloud_load_balancer',
  'web_application',
  'public_tls',
  'api',
  'cdn',
  'saas',
  'database',
  'network_device',
  'containers',
  'runtime',
]

const REMEDIATION_WORKFLOW_STAGES = ['DISCOVER', 'ANALYZE', 'APPROVE', 'PATCH', 'VALIDATE', 'MONITOR', 'REPORT']

const SUPPORTED_REMEDIATION_ENVIRONMENTS = [
  {
    id: 'local_on_prem',
    label: 'Local / On-Premises',
    assets: ['workstations', 'servers', 'virtual-machines', 'databases', 'internal-applications', 'pki', 'certificates-keys', 'tls-configurations', 'network-devices'],
    execution: ['local-collector', 'operator-patcher', 'connector-assisted'],
  },
  {
    id: 'multi_cloud',
    label: 'Multi-Cloud',
    assets: ['aws', 'azure', 'gcp', 'oracle-cloud', 'alibaba-cloud', 'cloud-databases', 'cloud-storage', 'kms', 'cloud-hsm', 'load-balancers', 'cloud-native-applications'],
    execution: ['cloud-connector', 'operator-patcher', 'agent-validation'],
  },
  {
    id: 'kubernetes_container',
    label: 'Kubernetes / Containers',
    assets: ['clusters', 'ingress', 'gateway-api', 'cert-manager', 'service-mesh', 'containers', 'registries', 'workload-crypto-config'],
    execution: ['kubernetes-connector', 'operator-patcher', 'local-sidecar-collector'],
  },
  {
    id: 'web_public_edge',
    label: 'Web / Internet-Facing',
    assets: ['websites', 'web-applications', 'apis', 'api-gateways', 'reverse-proxies', 'cdn-services', 'customer-portals', 'e-commerce-platforms', 'public-tls-endpoints'],
    execution: ['external-scanner', 'edge-connector', 'operator-patcher', 'agent-validation'],
  },
  {
    id: 'saas_identity',
    label: 'SaaS / Identity Platforms',
    assets: ['saas-applications', 'oidc-applications', 'saml-applications', 'jwt-signing-policy', 'trust-federation', 'api-keys', 'certificates'],
    execution: ['saas-connector', 'identity-connector', 'operator-patcher'],
  },
]

const LOCAL_COLLECTOR_CLARIFICATION = {
  definition: 'A Local Collector is a tenant-owned QGuard agent installed on an endpoint, server, VM, container, sidecar, or controlled jump host.',
  localOnly: false,
  monitorsLocalResourcesWhenAuthorized: true,
  canCallCloudApis: true,
  canDiscoverExternalAssets: true,
  canTriggerRemoteRemediation: true,
  remoteMutationRule: 'Remote cloud, SaaS, Kubernetes, web, and edge changes require explicit connector credentials, declared scopes, tenant admin approval, change approval, snapshots, validation, and audit logging.',
  credentialBoundary: 'Collectors and connectors never receive global credentials from QGuard; customers authorize least-privilege access in their own environment.',
}

const MANDATORY_QUANTUM_STACK_METADATA = mandatoryPqcStackMetadata()

function defaultRemediationCapabilities(overrides: Record<string, unknown> = {}) {
  return {
    scope: SUPPORTED_REMEDIATION_ENVIRONMENTS,
    localCollector: LOCAL_COLLECTOR_CLARIFICATION,
    mandatoryQuantumStack: MANDATORY_QUANTUM_STACK_METADATA,
    discover: ['asset-inventory', 'tls', 'certificates', 'pki', 'keys', 'trust-relationships', 'ssh', 'vpn', 'api-gateway', 'reverse-proxy', 'cdn', 'load-balancer', 'hsm', 'kms', 'kubernetes', 'containers', 'service-mesh', 'cloud-databases', 'cloud-storage', 'saas-apps', 'crypto-libraries'],
    assess: ['quantum-vulnerable-assets', 'non-compliant-configurations', 'nist-readiness', 'fips-status', 'migration-feasibility', 'dependency-chain', 'blast-radius', 'pqc-readiness'],
    remediate: ['tls13-upgrade', 'weak-cipher-removal', 'hybrid-x25519-ml-kem-768', 'ml-kem-768-deployment', 'ml-dsa-65-certificate-migration', 'ed25519-ml-dsa-65-hybrid-certificate', 'slh-dsa-readiness', 'hybrid-certificate-deployment', 'ssh-ed25519-policy', 'oqs-provider-config', 'oqs-openssl-hybrid-build', 'aes-256-gcm-policy', 'hkdf-sha3-256-policy', 'sha3-256-512-integrity', 'vpn-pqc-profile', 'kubernetes-tls-policy', 'cloud-kms-policy', 'cloud-load-balancer-policy', 'cdn-edge-policy', 'saas-crypto-policy', 'database-tls-policy'],
    validation: ['before-state', 'after-state', 'verification', 'functional-testing', 'service-reachability', 'certificate-chain', 'cipher-negotiation', 'dependency-validation', 'rollback-validation', 'compliance-validation'],
    rollback: ['configuration-snapshot', 'certificate-backup', 'key-backup-metadata', 'tls-policy-snapshot', 'automatic-restore-on-failed-validation'],
    monitoring: ['runtime-crypto-intelligence', 'tls-handshakes', 'certificate-health', 'certificate-changes', 'key-rotations', 'trust-fabric', 'library-updates', 'pqc-adoption', 'crypto-agility', 'drift-detection', 'unauthorized-crypto-changes'],
    workflow: REMEDIATION_WORKFLOW_STAGES,
    heartbeatSeconds: { min: 30, max: 60 },
    executionMode: 'tenant-approved-local-agent-cloud-connector-operator-patcher',
    ...overrides,
  }
}

function remediationExecutionContract(option?: Record<string, any>) {
  return {
    workflow: REMEDIATION_WORKFLOW_STAGES,
    mandatoryQuantumStack: MANDATORY_QUANTUM_STACK_METADATA,
    mandatoryConfigValues: MANDATORY_PQC_CONFIG_VALUES,
    mustUseApprovedQuantumStack: true,
    approvalRequired: true,
    rbacRequired: true,
    tenantAdminApprovalRequired: true,
    changeApprovalActions: ['approve', 'reject', 'schedule'],
    snapshotsRequired: ['configuration', 'certificate', 'key-metadata', 'tls-policy'],
    rollback: {
      automaticOnValidationFailure: true,
      restoreOriginalConfiguration: true,
      preserveBackupMetadata: true,
    },
    validation: {
      beforeStateRequired: true,
      afterStateRequired: true,
      verificationRequired: true,
      requiredVerificationFields: ['migrationSuccessful', 'certificateValid', 'serviceReachable', 'rollbackRequired'],
    },
    telemetry: {
      stream: ['sse', 'websocket-compatible'],
      heartbeatSeconds: { min: 30, max: 60 },
    },
    supportedEnvironments: SUPPORTED_REMEDIATION_ENVIRONMENTS.map((item) => item.id),
    localCollector: LOCAL_COLLECTOR_CLARIFICATION,
    remoteExecution: {
      localCollectorCanOrchestrate: true,
      connectorRequiredForRemoteMutation: true,
      allowedRemoteTargets: ['aws', 'azure', 'gcp', 'oracle-cloud', 'alibaba-cloud', 'kubernetes', 'containers', 'web-applications', 'apis', 'cdn', 'pki', 'saas'],
      credentialBoundary: LOCAL_COLLECTOR_CLARIFICATION.credentialBoundary,
    },
    actionType: option?.actionType || null,
    requiredScopes: option?.requiredScopes || [],
  }
}

function userApprovalRole(user: User | null | undefined) {
  const metadata = {
    ...(user?.app_metadata || {}),
    ...(user?.user_metadata || {}),
  } as Record<string, unknown>
  return cleanString(metadata.role || metadata.account_role || metadata.tenantRole || metadata.tenant_role, 80) || 'authenticated_tenant_admin'
}

async function recordAgentAudit(client: SupabaseClient | null, row: {
  userId: string
  action: string
  entityType: string
  entityId?: string | null
  details: Record<string, unknown>
}) {
  if (!client) return
  const { error } = await client.from('audit_logs').insert({
    user_id: row.userId,
    action: row.action,
    entity_type: row.entityType,
    entity_id: row.entityId || null,
    details: row.details,
  })
  if (error && !isMissingRuntimeTable(error)) console.warn('[agent-scanner] audit log insert failed:', error.message)
}

async function recordAgentSecurityEvent(client: SupabaseClient | null, row: {
  userId: string
  eventType: string
  severity: string
  message: string
  assetId?: string | null
  resourceName?: string | null
  resourceType?: string | null
  metadata: Record<string, unknown>
}) {
  if (!client) return
  const { error } = await client.from('security_events').insert({
    user_id: row.userId,
    event_type: row.eventType,
    severity: row.severity,
    message: row.message,
    asset_id: row.assetId || null,
    resource_name: row.resourceName || null,
    resource_type: row.resourceType || null,
    metadata: row.metadata,
    created_at: new Date().toISOString(),
  })
  if (error && !isMissingRuntimeTable(error)) console.warn('[agent-scanner] security event insert failed:', error.message)
}

function connectorProviderCapabilities(providerValue: unknown, scopes: string[], overrides: Record<string, unknown> = {}) {
  const provider = cleanString(providerValue, 100)?.toLowerCase() || 'custom'
  const cloudProvider = /aws|azure|gcp|google|oracle|oci|alibaba|aliyun/.test(provider)
  const kubernetesProvider = /kubernetes|k8s|openshift|eks|aks|gke|oke/.test(provider)
  const edgeProvider = /cloudflare|akamai|fastly|cdn|edge|front.?door|api.?gateway|kong|apigee/.test(provider)
  const identityProvider = /okta|entra|azure-ad|auth0|identity|saml|oidc|idp/.test(provider)
  const pkiProvider = /pki|certificate|cert-manager|acm|private-ca|key-vault/.test(provider)
  const hsmProvider = /hsm|kms|key-vault|cloudhsm|nshield|luna/.test(provider)

  return {
    provider,
    providerCategory: cloudProvider
      ? 'multi-cloud'
      : kubernetesProvider
        ? 'kubernetes-container'
        : edgeProvider
          ? 'web-edge'
          : identityProvider
            ? 'saas-identity'
            : pkiProvider || hsmProvider
              ? 'pki-key-management'
              : 'custom',
    supportedEnvironments: SUPPORTED_REMEDIATION_ENVIRONMENTS.map((item) => item.id),
    mandatoryQuantumStack: MANDATORY_QUANTUM_STACK_METADATA,
    discover: ['remote-asset-inventory', 'crypto-asset-inventory', 'certificate-inventory', 'key-inventory', 'trust-relationship-inventory', 'pqc-readiness'],
    assess: ['quantum-vulnerable-assets', 'non-compliant-configurations', 'nist-readiness', 'fips-status', 'migration-feasibility', 'dependency-chain', 'blast-radius'],
    remediate: ['tls-upgrades', 'certificate-replacement', 'weak-cipher-removal', 'legacy-crypto-replacement', 'ml-kem-768-deployment', 'x25519-ml-kem-768-hybrid', 'ml-dsa-65-deployment', 'ed25519-ml-dsa-65-hybrid', 'slh-dsa-readiness', 'aes-256-gcm-policy', 'hkdf-sha3-256-policy', 'sha3-256-512-integrity', 'hybrid-cryptography', 'key-rotation', 'configuration-hardening', 'compliance-policy-enforcement'],
    validate: ['post-remediation-verification', 'functional-testing', 'tls-validation', 'certificate-validation', 'dependency-validation', 'rollback-validation', 'compliance-validation'],
    monitor: ['runtime-crypto-intelligence', 'pqc-adoption-tracking', 'certificate-health', 'crypto-agility', 'trust-fabric-monitoring'],
    executionMode: 'authorized-connector-operator-patcher',
    sdkPatchAdapters: ['aws-sdk', 'azure-sdk', 'gcp-sdk'],
    sdkPatchExecutionRequires: ['QGUARD_ENABLE_CLOUD_SDK_PATCHES=true', 'connector.metadata.sdkPatchEnabled=true', 'tenant-admin-approval', 'target-allowlist', 'least-privilege-scopes'],
    requiresCustomerAuthorization: true,
    scopes,
    ...overrides,
  }
}

async function requireUserAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) {
    jsonError(res, 401, 'UNAUTHORIZED', 'Authentication required')
    return
  }

  const user = await getServerUser(token)
  if (!user) {
    jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired token')
    return
  }

  req.user = user
  req.token = token
  req.client = createAuthClient(token) || getServiceClient()
  next()
}

function getAgentToken(req: Request) {
  const header = req.headers.authorization
  if (header?.startsWith('Bearer ')) return header.slice(7)
  const agentToken = req.headers['x-qguard-agent-token']
  return typeof agentToken === 'string' ? agentToken : null
}

async function requireAgentAuth(req: AgentRequest, res: Response, next: NextFunction) {
  const agentId = typeof req.headers['x-qguard-agent-id'] === 'string' ? req.headers['x-qguard-agent-id'] : null
  const token = getAgentToken(req)
  if (!agentId || !token) {
    jsonError(res, 401, 'AGENT_UNAUTHORIZED', 'Agent id and token are required')
    return
  }

  const tokenHash = hashToken(token)
  const client = getServiceClient()
  let agent: any = null

  if (client) {
    const { data } = await client.from('scanner_agents').select('*').eq('id', agentId).limit(1).maybeSingle()
    agent = data
  } else {
    agent = memoryStore.agents.find((item) => item.id === agentId)
  }

  if (!agent || agent.status === 'revoked' || agent.revoked_at) {
    jsonError(res, 401, 'AGENT_REVOKED', 'Agent is not active')
    return
  }
  if (!safeCompareHash(tokenHash, agent.token_hash)) {
    jsonError(res, 401, 'AGENT_UNAUTHORIZED', 'Invalid agent token')
    return
  }

  req.agent = agent
  req.client = client
  next()
}

function normalizePolicy(raw: any) {
  return {
    enabled: raw?.enabled !== false,
    intervalSeconds: Math.max(30, Math.min(60, Number(raw?.intervalSeconds || raw?.interval_seconds || 60))),
    allowedTargets: Array.isArray(raw?.allowedTargets) ? raw.allowedTargets : Array.isArray(raw?.allowed_targets) ? raw.allowed_targets : [],
    allowedPaths: Array.isArray(raw?.allowedPaths) ? raw.allowedPaths : Array.isArray(raw?.allowed_paths) ? raw.allowed_paths : [],
    scanTypes: Array.isArray(raw?.scanTypes) ? raw.scanTypes : Array.isArray(raw?.scan_types) ? raw.scan_types : DEFAULT_AGENT_SCAN_TYPES,
    alertThreshold: cleanString(raw?.alertThreshold || raw?.alert_threshold, 20) || 'moderate',
  }
}

function normalizeEvidence(raw: any, sourceType: ScannerEvidenceRecord['sourceType'], agent?: any, connector?: any): ScannerEvidenceRecord | null {
  const evidenceType = cleanString(raw?.evidenceType || raw?.evidence_type, 100) as ScannerEvidenceRecord['evidenceType'] | null
  const assetName = cleanString(raw?.assetName || raw?.asset_name || raw?.host || raw?.target || raw?.filePath || raw?.packageName)
  if (!evidenceType || !assetName) return null

  return {
    id: cleanString(raw?.id, 120) || undefined,
    userId: agent?.user_id || connector?.user_id || cleanString(raw?.userId || raw?.user_id, 80) || undefined,
    agentId: agent?.id || raw?.agentId || raw?.agent_id || null,
    connectorAccountId: connector?.id || raw?.connectorAccountId || raw?.connector_account_id || null,
    sourceType,
    evidenceType,
    assetName,
    assetType: cleanString(raw?.assetType || raw?.asset_type, 100),
    target: cleanString(raw?.target, 500),
    host: cleanString(raw?.host, 255),
    port: raw?.port === undefined || raw?.port === null ? null : Number(raw.port),
    protocol: cleanString(raw?.protocol, 50),
    observedAlgorithm: cleanString(raw?.observedAlgorithm || raw?.observed_algorithm, 100),
    keySize: raw?.keySize || raw?.key_size ? Number(raw?.keySize || raw?.key_size) : null,
    certificateFingerprint: cleanString(raw?.certificateFingerprint || raw?.certificate_fingerprint, 255),
    filePath: cleanString(raw?.filePath || raw?.file_path, 1000),
    packageName: cleanString(raw?.packageName || raw?.package_name, 255),
    packageVersion: cleanString(raw?.packageVersion || raw?.package_version, 100),
    confidence: raw?.confidence === 'low' || raw?.confidence === 'medium' || raw?.confidence === 'high' ? raw.confidence : 'high',
    rawEvidence: typeof raw?.rawEvidence === 'object' && raw.rawEvidence ? raw.rawEvidence : typeof raw?.raw_evidence === 'object' && raw.raw_evidence ? raw.raw_evidence : {},
    observedAt: cleanString(raw?.observedAt || raw?.observed_at, 80) || new Date().toISOString(),
  }
}

function normalizePathLike(value: string) {
  return value.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase()
}

function parsePolicyTarget(value: string) {
  const trimmed = value.trim()
  if (!trimmed) return null
  try {
    const url = trimmed.includes('://') ? new URL(trimmed) : new URL(`tls://${trimmed}`)
    return {
      host: url.hostname.toLowerCase(),
      port: url.port ? Number(url.port) : url.protocol === 'ssh:' ? 22 : 443,
      raw: trimmed.toLowerCase(),
    }
  } catch {
    const [host, port] = trimmed.split(':')
    return host ? { host: host.toLowerCase(), port: port ? Number(port) : null, raw: trimmed.toLowerCase() } : null
  }
}

function normalizedPolicyText(value: unknown) {
  return String(value || '').trim().replace(/\\/g, '/').replace(/\s+/g, ' ').toLowerCase()
}

function evidenceResourceIdentifiers(evidence: ScannerEvidenceRecord) {
  const raw = evidence.rawEvidence && typeof evidence.rawEvidence === 'object' ? evidence.rawEvidence as Record<string, unknown> : {}
  return [
    evidence.target,
    evidence.host,
    evidence.assetName,
    evidence.assetType,
    raw.resourceId,
    raw.resource_id,
    raw.cloudResourceId,
    raw.cloud_resource_id,
    raw.arn,
    raw.azureResourceId,
    raw.azure_resource_id,
    raw.gcpResourceName,
    raw.gcp_resource_name,
    raw.oracleOcid,
    raw.oci_ocid,
    raw.alibabaResourceId,
    raw.clusterResource,
    raw.kubernetesResource,
    raw.namespace,
    raw.serviceName,
    raw.apiId,
    raw.gatewayId,
    raw.loadBalancerId,
    raw.cdnDistributionId,
    raw.certificateId,
    raw.kmsKeyId,
    raw.hsmClusterId,
    raw.databaseId,
    raw.storageBucket,
    raw.saasTenantId,
    raw.applicationId,
  ].map(normalizedPolicyText).filter(Boolean)
}

/**
 * Normalises a host label for identity comparison: case-folded, trailing dot
 * stripped, and reduced to its short name so `TestVM`, `testvm.` and
 * `testvm.corp.local` all resolve to the same machine.
 */
function hostIdentity(value: unknown) {
  const text = String(value || '').trim().toLowerCase().replace(/\.+$/, '')
  if (!text) return null
  return text.split('.')[0] || null
}

/**
 * True when an observation describes the host the agent is INSTALLED ON rather
 * than something it reached out to.
 *
 * `allowedTargets` scopes which remote endpoints an agent may probe and
 * `allowedPaths` scopes which filesystem roots it may read. Neither vocabulary
 * can express "this machine", so validating host-local telemetry — process
 * crypto inventory, the local certificate store, ETW/eBPF crypto calls — against
 * them rejected 100% of it and left freshly enrolled agents dead at
 * "Calculating quantum exposure" (85%).
 *
 * Host-local telemetry is authorised by ENROLMENT: an operator who installed an
 * agent on a machine authorised that machine to be reported. The check stays
 * narrow so it cannot be used to smuggle in third-party surface:
 *   - the observed host must be the host this agent registered from, and
 *   - it must not name a network port, because a port means a service was
 *     reached rather than the host inspected, and reaching stays allowlisted.
 */
function isSelfHostObservation(evidence: ScannerEvidenceRecord, agent: any) {
  const agentHost = hostIdentity(agent?.hostname)
  if (!agentHost) return false
  if (evidence.port) return false
  return hostIdentity(evidence.host) === agentHost
}

/**
 * The single authorisation predicate for agent-sourced observations: in scope
 * when the agent's enrolment covers it (its own host) or when the operator's
 * allowlist covers it (anything it reached).
 */
function agentObservationInScope(
  evidence: ScannerEvidenceRecord,
  policy: ReturnType<typeof normalizePolicy>,
  agent: any,
) {
  return isSelfHostObservation(evidence, agent) || evidenceAllowedByPolicy(evidence, policy)
}

function evidenceAllowedByPolicy(evidence: ScannerEvidenceRecord, policy: ReturnType<typeof normalizePolicy>, allowEmptyPolicy = false) {
  const allowedTargets = policy.allowedTargets.map(String).filter(Boolean)
  const allowedPaths = policy.allowedPaths.map(String).filter(Boolean)
  if (allowedTargets.length === 0 && allowedPaths.length === 0) return allowEmptyPolicy

  if (evidence.filePath && allowedPaths.length > 0) {
    const evidencePath = normalizePathLike(evidence.filePath)
    if (allowedPaths.some((allowedPath) => evidencePath.startsWith(normalizePathLike(allowedPath)))) return true
  }

  const evidenceHost = evidence.host?.toLowerCase()
  const evidenceTarget = evidence.target?.toLowerCase()
  if (evidenceHost || evidenceTarget) {
    for (const allowedTarget of allowedTargets) {
      const parsed = parsePolicyTarget(allowedTarget)
      if (!parsed) continue
      if (evidenceHost && parsed.host === evidenceHost && (!evidence.port || !parsed.port || parsed.port === evidence.port)) return true
      if (evidenceTarget && (evidenceTarget === parsed.raw || evidenceTarget.includes(parsed.host))) return true
    }
  }

  const identifiers = evidenceResourceIdentifiers(evidence)
  for (const allowedTarget of allowedTargets) {
    const allowed = normalizedPolicyText(allowedTarget)
    if (!allowed) continue
    if (identifiers.some((identifier) => {
      if (identifier === allowed) return true
      if (identifier.length >= 8 && allowed.length >= 8 && (identifier.includes(allowed) || allowed.includes(identifier))) return true
      return false
    })) return true
  }

  return false
}

function patchTargetAllowedByPolicy(target: string | null, policy: ReturnType<typeof normalizePolicy>, allowEmptyPolicy = false) {
  if (!target) return false
  return evidenceAllowedByPolicy({
    sourceType: 'connector',
    evidenceType: 'cloud-resource',
    assetName: target,
    target,
    host: cleanString(target, 255),
    rawEvidence: {
      resourceId: target,
      cloudResourceId: target,
      arn: target.startsWith('arn:') ? target : undefined,
      azureResourceId: target.startsWith('/subscriptions/') ? target : undefined,
      gcpResourceName: target,
    },
    observedAt: new Date().toISOString(),
  } as unknown as ScannerEvidenceRecord, policy, allowEmptyPolicy)
}

const RUNTIME_FORBIDDEN_KEYS = new Set([
  'body',
  'content',
  'data',
  'packet',
  'password',
  'payload',
  'plaintext',
  'private_key',
  'privatekey',
  'raw_body',
  'raw_content',
  'raw_payload',
  'secret',
  'token',
])

const RUNTIME_EVIDENCE_TYPES = new Set([
  'tls-certificate',
  'tls-protocol',
  'tls-cipher',
  'ssh-metadata',
  'pki-metadata',
  'vpn-crypto-profile',
  'api-gateway-crypto-policy',
  'load-balancer-crypto-policy',
  'kubernetes-crypto-policy',
  'service-mesh-crypto-policy',
  'hsm-integration',
  'trust-store',
  'cloud-kms-policy',
  'cloud-hsm-policy',
  'cloud-certificate-manager',
  'cloud-database-crypto-policy',
  'cloud-storage-encryption-policy',
  'cloud-iam-key-policy',
  'cdn-tls-policy',
  'web-application-crypto-policy',
  'saas-crypto-policy',
  'network-device-crypto-policy',
  'database-crypto-policy',
  'container-crypto-policy',
  'package-manifest',
  'config-reference',
  'jwt-algorithm',
  'crypto-library',
])

type RuntimeCryptoEventRecord = {
  userId?: string
  agentId?: string | null
  connectorAccountId?: string | null
  assetId?: string | null
  sourceType: string
  eventType: string
  operationType: string
  severity: FindingSeverity
  riskScore: number
  assetName: string
  assetType?: string | null
  host?: string | null
  port?: number | null
  protocol?: string | null
  tlsVersion?: string | null
  cipherSuite?: string | null
  keyExchangeAlgorithm?: string | null
  algorithm?: string | null
  keySize?: number | null
  certificateFingerprint?: string | null
  packageName?: string | null
  packageVersion?: string | null
  processName?: string | null
  processId?: number | null
  isPqc: boolean
  isLegacy: boolean
  downgradeDetected: boolean
  shadowCrypto: boolean
  hndlRisk: boolean
  eventHash: string
  metadata: Record<string, unknown>
  observedAt: string
}

function containsForbiddenRuntimeField(value: unknown): string | null {
  const visit = (current: unknown, path: string, depth: number): string | null => {
    if (!current || typeof current !== 'object' || depth > 6) return null
    if (Array.isArray(current)) {
      for (let index = 0; index < current.length; index += 1) {
        const found = visit(current[index], `${path}[${index}]`, depth + 1)
        if (found) return found
      }
      return null
    }
    for (const [key, nested] of Object.entries(current as Record<string, unknown>)) {
      const normalized = key.toLowerCase().replace(/[\s-]+/g, '_')
      if (RUNTIME_FORBIDDEN_KEYS.has(normalized)) return path ? `${path}.${key}` : key
      const found = visit(nested, path ? `${path}.${key}` : key, depth + 1)
      if (found) return found
    }
    return null
  }
  return visit(value, '', 0)
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, nested]) => nested !== undefined)
    .sort(([a], [b]) => a.localeCompare(b))
  return `{${entries.map(([key, nested]) => `${JSON.stringify(key)}:${stableJson(nested)}`).join(',')}}`
}

function runtimeEventHash(event: Omit<RuntimeCryptoEventRecord, 'eventHash'>) {
  return createHash('sha256').update(stableJson({
    userId: event.userId,
    agentId: event.agentId,
    sourceType: event.sourceType,
    eventType: event.eventType,
    assetName: event.assetName,
    host: event.host,
    port: event.port,
    protocol: event.protocol,
    tlsVersion: event.tlsVersion,
    cipherSuite: event.cipherSuite,
    keyExchangeAlgorithm: event.keyExchangeAlgorithm,
    algorithm: event.algorithm,
    certificateFingerprint: event.certificateFingerprint,
    packageName: event.packageName,
    packageVersion: event.packageVersion,
    processName: event.processName,
    observedAt: event.observedAt,
  })).digest('hex')
}

function sanitizeRuntimeMetadata(value: unknown, depth = 0): unknown {
  if (depth > 3) return undefined
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return value
  if (typeof value === 'string') return value.slice(0, 500)
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => sanitizeRuntimeMetadata(item, depth + 1)).filter((item) => item !== undefined)
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {}
    for (const [key, nested] of Object.entries(value as Record<string, unknown>).slice(0, 40)) {
      const normalized = key.toLowerCase().replace(/[\s-]+/g, '_')
      if (RUNTIME_FORBIDDEN_KEYS.has(normalized)) continue
      const sanitized = sanitizeRuntimeMetadata(nested, depth + 1)
      if (sanitized !== undefined) output[key.slice(0, 80)] = sanitized
    }
    return output
  }
  return undefined
}

function normalizeRuntimeProtocol(value: unknown) {
  const protocol = cleanString(value, 50)
  if (!protocol) return null
  return protocol.replace(/^TLSv/i, 'TLS-').replace(/^TLS\s+/i, 'TLS-')
}

function runtimeOperationType(text: string) {
  const lower = text.toLowerCase()
  if (lower.includes('decrypt') || lower.includes('unwrap')) return 'decryption'
  if (lower.includes('encrypt') || lower.includes('cipher') || lower.includes('aes')) return 'encryption'
  if (lower.includes('sign') || lower.includes('jwt') || lower.includes('signature')) return 'signing'
  if (lower.includes('verify') || lower.includes('validation')) return 'verification'
  if (lower.includes('package') || lower.includes('config') || lower.includes('library')) return 'discovery'
  if (lower.includes('tls') || lower.includes('ssh') || lower.includes('handshake') || lower.includes('key exchange') || lower.includes('kex')) return 'key_exchange'
  if (lower.includes('key') || lower.includes('entropy') || lower.includes('rotate')) return 'key_usage'
  return 'other'
}

function runtimeSeverity(input: {
  explicitSeverity?: string | null
  isPqc: boolean
  isLegacy: boolean
  downgradeDetected: boolean
  shadowCrypto: boolean
  hndlRisk: boolean
  keySize?: number | null
  algorithmText: string
}) {
  let computed: FindingSeverity = input.isPqc && !input.isLegacy ? 'safe' : 'low'
  if (input.shadowCrypto) computed = 'moderate'
  if (input.isLegacy) computed = 'high'
  if (input.downgradeDetected || input.hndlRisk || (input.keySize && input.keySize <= 1024)) computed = 'critical'
  // Word-bounded: unbounded `ssl` matched "OpenSSL-compatible crypto library"
  // and unbounded `des` matched inside unrelated words, so naming a library was
  // enough to publish a critical. A broken primitive has to be NAMED as one.
  if (/\b(?:md5|sha-?1|3des|triple-?des|rc4|des|sslv?[23]|tls-?1\.[01]|tlsv1\.[01])\b/i.test(input.algorithmText)) computed = 'critical'
  const explicit = cleanString(input.explicitSeverity, 20) as FindingSeverity | null
  return explicit && severityRank(explicit) > severityRank(computed) ? explicit : computed
}

function runtimeRiskScore(severity: FindingSeverity, flags: { isLegacy: boolean; downgradeDetected: boolean; shadowCrypto: boolean; hndlRisk: boolean }) {
  const base = severity === 'critical' ? 90 : severity === 'high' ? 72 : severity === 'moderate' || severity === 'medium' ? 55 : severity === 'low' ? 28 : 5
  const boost = (flags.downgradeDetected ? 5 : 0) + (flags.hndlRisk ? 5 : 0) + (flags.shadowCrypto ? 3 : 0) + (flags.isLegacy ? 2 : 0)
  return Math.max(0, Math.min(100, base + boost))
}

function normalizeRuntimeCryptoEvent(raw: any, sourceType: string, agent?: any, connector?: any): RuntimeCryptoEventRecord | null {
  const eventType = cleanString(raw?.eventType || raw?.event_type || raw?.evidenceType || raw?.evidence_type, 100)
  const assetName = cleanString(raw?.assetName || raw?.asset_name || raw?.host || raw?.target || raw?.packageName || raw?.package_name || raw?.filePath || raw?.file_path, 255)
  if (!eventType || !assetName) return null

  const metadata = (sanitizeRuntimeMetadata(raw?.metadata || raw?.rawEvidence || raw?.raw_evidence || {}) || {}) as Record<string, unknown>
  const algorithm = cleanString(raw?.algorithm || raw?.observedAlgorithm || raw?.observed_algorithm, 100)
  const keyExchangeAlgorithm = cleanString(raw?.keyExchangeAlgorithm || raw?.key_exchange_algorithm || metadata.keyExchangeAlgorithm || metadata.key_exchange_algorithm, 100)
  const cipherSuite = cleanString(raw?.cipherSuite || raw?.cipher_suite || metadata.cipherSuite || metadata.cipher_suite, 255)
  const tlsVersion = normalizeRuntimeProtocol(raw?.tlsVersion || raw?.tls_version || (eventType.includes('tls-protocol') ? algorithm : null) || metadata.protocol)
  const protocol = normalizeRuntimeProtocol(raw?.protocol || metadata.protocol)
  const keySize = raw?.keySize || raw?.key_size ? Number(raw?.keySize || raw?.key_size) : null
  const observedAt = cleanString(raw?.observedAt || raw?.observed_at, 80) || new Date().toISOString()
  // Classification reads the STATED primitives through the platform's single
  // crypto model. It previously swept a regex over the whole event including
  // `JSON.stringify(metadata)`, which is how a process that had merely loaded
  // `ncryptsslp.dll` was published as a CRITICAL TLS downgrade: the substring
  // "ssl" in a module name matched the downgrade pattern, and "library" in a
  // signal label matched the shadow-crypto pattern. A second, looser model
  // living here also silently overrode the collector's own honest verdict,
  // because every flag was `agentSaidTrue || regexOverBlob`.
  const statedAlgorithm = keyExchangeAlgorithm || cipherSuite || algorithm
  const anatomy = analyzeCryptoObservation(
    { name: statedAlgorithm, algorithm: statedAlgorithm, protocol: protocol || tlsVersion },
    Boolean(statedAlgorithm),
  )
  const algorithmText = `${statedAlgorithm || ''} ${tlsVersion || ''} ${protocol || ''}`.toLowerCase()

  const isPqc = Boolean(raw?.isPqc || raw?.is_pqc) || anatomy.quantumClass === 'safe' || anatomy.quantumClass === 'hybrid'
  const isLegacy = Boolean(raw?.isLegacy || raw?.is_legacy) || anatomy.quantumClass === 'vulnerable'

  // A downgrade needs an OBSERVED weak protocol version. Nothing else can
  // establish it, so nothing else may assert it.
  const observedProtocol = `${tlsVersion || ''} ${protocol || ''}`.toLowerCase()
  // A claim still requires the evidence for that claim, even when an agent
  // asserts it: an uploader that reports `downgradeDetected` without having
  // observed any protocol version has not observed a downgrade. This also keeps
  // older agent builds - and any third-party collector - from writing a critical
  // the control plane cannot substantiate.
  const weakProtocolObserved = /\b(?:sslv?[23]|tls-?1\.[01]|tlsv1(?:\.[01])?)\b/.test(observedProtocol)
  const downgradeClaimed = Boolean(raw?.downgradeDetected || raw?.downgrade_detected)
  const downgradeDetected = weakProtocolObserved || (downgradeClaimed && Boolean(observedProtocol.trim()))

  // Shadow crypto means cryptography outside the DECLARED inventory. A host
  // agent has no inventory to compare against, so it cannot establish this and
  // its claim is not published; the control plane decides it during
  // reconciliation. Other sources keep their own determination.
  const shadowCrypto = sourceType === 'local-agent'
    ? false
    : Boolean(raw?.shadowCrypto || raw?.shadow_crypto)

  // Harvest-now-decrypt-later needs quantum-vulnerable key establishment
  // protecting data in transit, not merely a legacy-sounding string.
  const hndlRisk = Boolean(raw?.hndlRisk || raw?.hndl_risk)
    || (isLegacy && !isPqc && Boolean(raw?.host || raw?.target) && anatomy.kind === 'key-exchange')
  const severity = runtimeSeverity({
    explicitSeverity: raw?.severity,
    isPqc,
    isLegacy,
    downgradeDetected,
    shadowCrypto,
    hndlRisk,
    keySize,
    algorithmText,
  })
  const riskScore = Number(raw?.riskScore || raw?.risk_score) || runtimeRiskScore(severity, { isLegacy, downgradeDetected, shadowCrypto, hndlRisk })
  const withoutHash = {
    userId: agent?.user_id || connector?.user_id || cleanString(raw?.userId || raw?.user_id, 80) || undefined,
    agentId: agent?.id || cleanString(raw?.agentId || raw?.agent_id, 80) || null,
    connectorAccountId: connector?.id || cleanString(raw?.connectorAccountId || raw?.connector_account_id, 80) || null,
    assetId: cleanString(raw?.assetId || raw?.asset_id, 80) || null,
    sourceType,
    eventType,
    operationType: cleanString(raw?.operationType || raw?.operation_type, 100) || runtimeOperationType(algorithmText),
    severity,
    riskScore: Math.max(0, Math.min(100, Math.round(riskScore))),
    assetName,
    assetType: cleanString(raw?.assetType || raw?.asset_type, 100),
    host: cleanString(raw?.host, 255),
    port: raw?.port === undefined || raw?.port === null ? null : Number(raw.port),
    protocol,
    tlsVersion,
    cipherSuite,
    keyExchangeAlgorithm,
    algorithm,
    keySize,
    certificateFingerprint: cleanString(raw?.certificateFingerprint || raw?.certificate_fingerprint, 255),
    packageName: cleanString(raw?.packageName || raw?.package_name, 255),
    packageVersion: cleanString(raw?.packageVersion || raw?.package_version, 100),
    processName: cleanString(raw?.processName || raw?.process_name, 255),
    processId: raw?.processId || raw?.process_id ? Number(raw?.processId || raw?.process_id) : null,
    isPqc,
    isLegacy,
    downgradeDetected,
    shadowCrypto,
    hndlRisk,
    metadata,
    observedAt,
  }

  return {
    ...withoutHash,
    eventHash: cleanString(raw?.eventHash || raw?.event_hash, 128) || runtimeEventHash(withoutHash),
  }
}

function runtimeEventDbRow(event: RuntimeCryptoEventRecord, userId: string) {
  return {
    user_id: userId,
    agent_id: event.agentId || null,
    connector_account_id: event.connectorAccountId || null,
    asset_id: event.assetId || null,
    source_type: event.sourceType,
    event_type: event.eventType,
    operation_type: event.operationType,
    severity: event.severity,
    risk_score: event.riskScore,
    asset_name: event.assetName,
    asset_type: event.assetType || null,
    host: event.host || null,
    port: event.port || null,
    protocol: event.protocol || null,
    tls_version: event.tlsVersion || null,
    cipher_suite: event.cipherSuite || null,
    key_exchange_algorithm: event.keyExchangeAlgorithm || null,
    algorithm: event.algorithm || null,
    key_size: event.keySize || null,
    certificate_fingerprint: event.certificateFingerprint || null,
    package_name: event.packageName || null,
    package_version: event.packageVersion || null,
    process_name: event.processName || null,
    process_id: event.processId || null,
    is_pqc: event.isPqc,
    is_legacy: event.isLegacy,
    downgrade_detected: event.downgradeDetected,
    shadow_crypto: event.shadowCrypto,
    hndl_risk: event.hndlRisk,
    event_hash: event.eventHash,
    metadata: event.metadata || {},
    observed_at: event.observedAt,
  }
}

async function persistRuntimeCryptoEvents(client: SupabaseClient | null, userId: string, events: RuntimeCryptoEventRecord[]) {
  if (events.length === 0) return { accepted: 0, inserted: 0, duplicateCount: 0, tableAvailable: true }
  const rows = events.map((event) => runtimeEventDbRow(event, userId))

  if (client) {
    const { data, error } = await (client.from('runtime_crypto_events') as any)
      .upsert(rows, { onConflict: 'user_id,event_hash', ignoreDuplicates: true })
      .select('id,event_hash')
    if (error) {
      if (isMissingRuntimeTable(error)) {
        console.warn('runtime_crypto_events table missing; runtime event persistence skipped')
        return { accepted: events.length, inserted: 0, duplicateCount: 0, tableAvailable: false }
      }
      throw error
    }
    const inserted = data?.length || 0
    return { accepted: events.length, inserted, duplicateCount: Math.max(0, events.length - inserted), tableAvailable: true }
  }

  let inserted = 0
  for (const row of rows) {
    const duplicate = memoryStore.runtimeCryptoEvents.some((item) => item.user_id === userId && item.event_hash === row.event_hash)
    if (duplicate) continue
    memoryStore.runtimeCryptoEvents.unshift({ id: randomId('runtime-event'), ...row, created_at: new Date().toISOString() })
    inserted += 1
  }
  return { accepted: events.length, inserted, duplicateCount: Math.max(0, events.length - inserted), tableAvailable: true }
}

function runtimeEventToEvidence(event: RuntimeCryptoEventRecord): ScannerEvidenceRecord {
  const eventType = RUNTIME_EVIDENCE_TYPES.has(event.eventType) ? event.eventType : event.protocol?.toLowerCase().includes('ssh') ? 'ssh-metadata' : event.protocol?.toLowerCase().includes('tls') || event.tlsVersion ? 'tls-protocol' : event.packageName ? 'package-manifest' : event.metadata?.filePath ? 'config-reference' : 'crypto-library'
  return {
    userId: event.userId,
    agentId: event.agentId,
    connectorAccountId: event.connectorAccountId,
    sourceType: event.sourceType as ScannerEvidenceRecord['sourceType'],
    evidenceType: eventType as ScannerEvidenceRecord['evidenceType'],
    assetName: event.assetName,
    assetType: event.assetType || null,
    target: event.host ? `${event.protocol || 'runtime'}://${event.host}${event.port ? `:${event.port}` : ''}` : null,
    host: event.host || null,
    port: event.port || null,
    protocol: event.protocol || event.tlsVersion || null,
    observedAlgorithm: event.algorithm || event.keyExchangeAlgorithm || event.cipherSuite || event.tlsVersion || null,
    keySize: event.keySize || null,
    certificateFingerprint: event.certificateFingerprint || null,
    filePath: cleanString(event.metadata?.filePath || event.metadata?.file_path, 1000),
    packageName: event.packageName || null,
    packageVersion: event.packageVersion || null,
    confidence: 'high',
    rawEvidence: {
      ...event.metadata,
      runtimeEventHash: event.eventHash,
      operationType: event.operationType,
      isPqc: event.isPqc,
      isLegacy: event.isLegacy,
      downgradeDetected: event.downgradeDetected,
      shadowCrypto: event.shadowCrypto,
      hndlRisk: event.hndlRisk,
      riskScore: event.riskScore,
    },
    observedAt: event.observedAt,
  }
}

function runtimeEventsFromEvidence(evidence: ScannerEvidenceRecord[]) {
  return evidence
    .map((item) => normalizeRuntimeCryptoEvent({
      eventType: item.evidenceType,
      operationType: runtimeOperationType(`${item.evidenceType} ${item.observedAlgorithm || ''} ${item.protocol || ''}`),
      assetName: item.assetName,
      assetType: item.assetType,
      target: item.target,
      host: item.host,
      port: item.port,
      protocol: item.protocol,
      tlsVersion: item.evidenceType === 'tls-protocol' ? item.observedAlgorithm : item.protocol,
      cipherSuite: item.evidenceType === 'tls-cipher' ? item.observedAlgorithm : null,
      keyExchangeAlgorithm: item.evidenceType === 'ssh-metadata' ? item.observedAlgorithm : null,
      algorithm: item.observedAlgorithm,
      keySize: item.keySize,
      certificateFingerprint: item.certificateFingerprint,
      filePath: item.filePath,
      packageName: item.packageName,
      packageVersion: item.packageVersion,
      rawEvidence: item.rawEvidence,
      metadata: {
        ...(item.rawEvidence || {}),
        evidenceId: item.id,
        evidenceType: item.evidenceType,
        target: item.target,
        filePath: item.filePath,
      },
      observedAt: item.observedAt,
    }, item.sourceType, { id: item.agentId, user_id: item.userId }, item.connectorAccountId ? { id: item.connectorAccountId, user_id: item.userId } : undefined))
    .filter(Boolean) as RuntimeCryptoEventRecord[]
}

function dbEvidenceRow(evidence: ScannerEvidenceRecord, userId: string) {
  return {
    user_id: userId,
    agent_id: evidence.agentId || null,
    connector_account_id: evidence.connectorAccountId || null,
    source_type: evidence.sourceType,
    evidence_type: evidence.evidenceType,
    asset_name: evidence.assetName,
    asset_type: evidence.assetType || null,
    target: evidence.target || null,
    host: evidence.host || null,
    port: evidence.port || null,
    protocol: evidence.protocol || null,
    observed_algorithm: evidence.observedAlgorithm || null,
    key_size: evidence.keySize || null,
    certificate_fingerprint: evidence.certificateFingerprint || null,
    file_path: evidence.filePath || null,
    package_name: evidence.packageName || null,
    package_version: evidence.packageVersion || null,
    confidence: evidence.confidence || 'high',
    raw_evidence: evidence.rawEvidence || {},
    observed_at: evidence.observedAt || new Date().toISOString(),
  }
}

function itemTypeForFinding(finding: ScanFinding) {
  if (finding.algorithmCategory === 'protocol') return 'protocol'
  if (finding.algorithmCategory === 'hash') return 'hash'
  if (finding.algorithmCategory === 'signature') return 'signature'
  if (finding.moduleId.includes('certificate')) return 'certificate'
  if (finding.moduleId.includes('ssh')) return 'key_exchange'
  if (finding.moduleId.includes('library')) return 'library'
  return 'algorithm'
}

function isPqcReadyEvidence(evidence: ScannerEvidenceRecord) {
  const value = `${evidence.observedAlgorithm || ''} ${JSON.stringify(evidence.rawEvidence || {})}`.toLowerCase()
  return (
    value.includes('ml-kem') ||
    value.includes('ml-dsa') ||
    value.includes('kyber') ||
    value.includes('dilithium') ||
    value.includes('sphincs') ||
    value.includes('sntrup') ||
    value.includes('post-quantum') ||
    value.includes('pqc') ||
    value.includes('hybrid')
  )
}

async function persistEvidenceFindings(
  client: SupabaseClient | null,
  userId: string,
  evidence: ScannerEvidenceRecord[],
  findings: ScanFinding[],
  sourceLabel: string,
  options: { alertThreshold?: string; persistRuntimeEvents?: boolean } = {}
) {
  const now = new Date().toISOString()
  const linkedAssetIds: string[] = []
  const linkedCbomIds: string[] = []
  const linkedExposureIds: string[] = []
  const linkedAlertIds: string[] = []
  const pqcReadyEvidence = evidence.filter(isPqcReadyEvidence)

  const sessionSummary = {
    totalFindings: findings.length,
    critical: findings.filter((item) => item.severity === 'critical').length,
    high: findings.filter((item) => item.severity === 'high').length,
    medium: findings.filter((item) => item.severity === 'moderate' || item.severity === 'medium').length,
    low: findings.filter((item) => item.severity === 'low').length,
    safe: findings.filter((item) => item.severity === 'safe').length + pqcReadyEvidence.length,
    pqcReadyEvidence: pqcReadyEvidence.length,
  }

  let scanSessionId: string | null = null
  if (client) {
    const { data } = await client.from('pqc_scan_sessions').insert({
      user_id: userId,
      status: 'completed',
      target_scope: `${sourceLabel} evidence batch`,
      progress: 100,
      total_assets: new Set(evidence.map((item) => item.assetName)).size,
      scanned_assets: new Set(evidence.map((item) => item.assetName)).size,
      findings_count: findings.length,
      metadata: {
        scannerMode: 'continuous-agent-evidence',
        sourceLabel,
        summary: sessionSummary,
      },
      started_at: now,
      completed_at: now,
    }).select('id').single()
    scanSessionId = data?.id || null
  }

  for (const finding of findings) {
    let assetId: string | null = null
    const evidenceMatch = evidence.find((item) =>
      item.assetName === finding.target.name ||
      item.host === finding.target.metadata?.host ||
      item.filePath === finding.target.metadata?.filePath
    )
    const assetName = finding.target.name
    const riskScore = Math.max(0, Math.min(100, Math.round(finding.riskScore / 10)))
    const assetMetadata = {
      source: sourceLabel,
      evidenceType: evidenceMatch?.evidenceType,
      target: evidenceMatch?.target,
      host: evidenceMatch?.host,
      port: evidenceMatch?.port,
      last_scanned_at: now,
      riskScore,
      qScore: Math.max(0, 100 - riskScore),
      scannerEvidence: true,
    }

    if (client) {
      const { data: existingAsset } = await client.from('assets').select('*').eq('user_id', userId).eq('name', assetName).limit(1).maybeSingle()
      if (existingAsset?.id) {
        const { data } = await client.from('assets').update({
          type: finding.target.type,
          ip_address: evidenceMatch?.host || null,
          criticality: riskScore >= 80 ? 'critical' : riskScore >= 60 ? 'high' : riskScore >= 40 ? 'medium' : 'low',
          status: 'active',
          metadata: { ...(existingAsset.metadata || {}), ...assetMetadata },
          updated_at: now,
        }).eq('id', existingAsset.id).eq('user_id', userId).select('id').single()
        assetId = data?.id || existingAsset.id
      } else {
        const { data } = await client.from('assets').insert({
          user_id: userId,
          name: assetName,
          type: finding.target.type,
          ip_address: evidenceMatch?.host || null,
          criticality: riskScore >= 80 ? 'critical' : riskScore >= 60 ? 'high' : riskScore >= 40 ? 'medium' : 'low',
          status: 'active',
          metadata: assetMetadata,
        }).select('id').single()
        assetId = data?.id || null
      }
    } else {
      assetId = randomId('asset')
    }

    if (!assetId) continue
    linkedAssetIds.push(assetId)

    const commonMetadata = {
      source: sourceLabel,
      scanSessionId,
      evidence: finding.evidence,
      remediation: finding.remediation,
      recommendation: finding.recommendation,
      pqcReplacement: finding.pqcReplacement,
      fingerprintId: finding.fingerprintId,
      ruleId: finding.ruleId,
      evidenceRecord: evidenceMatch || null,
    }

    if (client) {
      const { data: cbom } = await client.from('crypto_inventory').insert({
        user_id: userId,
        asset_id: assetId,
        item_type: itemTypeForFinding(finding),
        name: `${finding.moduleId}: ${finding.detectedAlgorithm}`,
        algorithm: finding.detectedAlgorithm,
        key_size: evidenceMatch?.keySize || null,
        protocol: evidenceMatch?.protocol || null,
        exposure_level: finding.severity,
        is_vulnerable: finding.threatLevel !== 'safe',
        is_quantum_safe: finding.threatLevel === 'safe',
        metadata: commonMetadata,
        discovered_at: now,
      }).select('id').single()
      if (cbom?.id) linkedCbomIds.push(cbom.id)

      await client.from('pqc_scan_results').insert({
        user_id: userId,
        scan_session_id: scanSessionId,
        asset_id: assetId,
        finding_type: finding.moduleId,
        algorithm: finding.detectedAlgorithm,
        threat_level: finding.severity,
        description: finding.description,
        remediation: finding.recommendation,
        metadata: commonMetadata,
      })

      if (finding.threatLevel !== 'safe') {
        const { data: exposure } = await client.from('crypto_exposures').insert({
          user_id: userId,
          asset_id: assetId,
          exposure_type: finding.quantumThreat,
          severity: finding.severity === 'medium' ? 'moderate' : finding.severity,
          description: finding.description,
          detected_value: finding.detectedAlgorithm,
          metadata: commonMetadata,
        }).select('id').single()
        if (exposure?.id) linkedExposureIds.push(exposure.id)

        if (severityRank(finding.severity) >= severityRank(options.alertThreshold || 'moderate')) {
          const { data: alert } = await client.from('scanner_alerts').insert({
            user_id: userId,
            agent_id: evidenceMatch?.agentId || null,
            connector_account_id: evidenceMatch?.connectorAccountId || null,
            evidence_id: evidenceMatch?.id || null,
            severity: finding.severity,
            category: finding.moduleId,
            title: `${finding.detectedAlgorithm} detected on ${assetName}`,
            message: finding.description,
            recommendation: finding.recommendation,
            status: 'open',
            metadata: commonMetadata,
          }).select('id').single()
          if (alert?.id) linkedAlertIds.push(alert.id)
        }
      }
    }
  }

  for (const record of pqcReadyEvidence) {
    if (!client) continue
    const assetName = record.assetName || record.host || record.target || 'PQC-ready asset'
    const assetMetadata = {
      source: sourceLabel,
      evidenceType: record.evidenceType,
      target: record.target,
      host: record.host,
      port: record.port,
      last_scanned_at: now,
      riskScore: 0,
      qScore: 100,
      scannerEvidence: true,
      pqcReady: true,
    }

    const { data: existingAsset } = await client.from('assets').select('*').eq('user_id', userId).eq('name', assetName).limit(1).maybeSingle()
    let assetId = existingAsset?.id as string | null
    if (assetId) {
      await client.from('assets').update({
        type: record.assetType || 'endpoint',
        ip_address: record.host || null,
        criticality: existingAsset.criticality || 'low',
        status: 'active',
        metadata: { ...(existingAsset.metadata || {}), ...assetMetadata },
        updated_at: now,
      }).eq('id', assetId).eq('user_id', userId)
    } else {
      const { data: insertedAsset } = await client.from('assets').insert({
        user_id: userId,
        name: assetName,
        type: record.assetType || 'endpoint',
        ip_address: record.host || null,
        criticality: 'low',
        status: 'active',
        metadata: assetMetadata,
      }).select('id').single()
      assetId = insertedAsset?.id || null
    }
    if (!assetId) continue
    linkedAssetIds.push(assetId)

    const metadata = {
      source: sourceLabel,
      scanSessionId,
      evidenceRecord: record,
      recommendation: 'Maintain PQC/hybrid configuration and monitor vendor implementation maturity.',
      pqcReady: true,
    }
    const { data: cbom } = await client.from('crypto_inventory').insert({
      user_id: userId,
      asset_id: assetId,
      item_type: record.evidenceType.includes('tls') || record.evidenceType.includes('ssh') ? 'protocol' : 'algorithm',
      name: `PQC-ready: ${record.observedAlgorithm || record.evidenceType}`,
      algorithm: record.observedAlgorithm || 'PQC-ready',
      key_size: record.keySize || null,
      protocol: record.protocol || null,
      exposure_level: 'safe',
      is_vulnerable: false,
      is_quantum_safe: true,
      metadata,
      discovered_at: now,
    }).select('id').single()
    if (cbom?.id) linkedCbomIds.push(cbom.id)

    await client.from('pqc_scan_results').insert({
      user_id: userId,
      scan_session_id: scanSessionId,
      asset_id: assetId,
      finding_type: 'pqc-ready-evidence',
      algorithm: record.observedAlgorithm || 'PQC-ready',
      threat_level: 'safe',
      description: `PQC-ready or hybrid cryptographic evidence observed from ${record.evidenceType}.`,
      remediation: 'No immediate migration required; keep continuous monitoring enabled.',
      metadata,
    })
  }

  if (client) {
    await client.from('security_events').insert({
      user_id: userId,
      event_type: 'continuous_scanner_evidence_processed',
      severity: sessionSummary.critical || sessionSummary.high ? 'warning' : 'success',
      message: `${sourceLabel} evidence processed: ${findings.length} finding(s)`,
      resource_name: sourceLabel,
      resource_type: 'scanner_agent',
      metadata: { scanSessionId, sessionSummary, linkedAssetIds, linkedCbomIds, linkedExposureIds, linkedAlertIds },
    })
    await client.from('audit_logs').insert({
      user_id: userId,
      action: 'continuous_scanner_evidence_processed',
      entity_type: 'scanner_evidence',
      entity_id: scanSessionId,
      details: { sourceLabel, evidenceCount: evidence.length, findingCount: findings.length, linkedAssetIds, linkedCbomIds, linkedExposureIds, linkedAlertIds },
    })
  }

  return { scanSessionId, linkedAssetIds, linkedCbomIds, linkedExposureIds, linkedAlertIds }
}

async function processEvidenceBatch(
  client: SupabaseClient | null,
  userId: string,
  evidence: ScannerEvidenceRecord[],
  sourceLabel: string,
  options: { alertThreshold?: string; persistRuntimeEvents?: boolean } = {}
) {
  const rows = evidence.map((item) => dbEvidenceRow(item, userId))
  let insertedEvidence: ScannerEvidenceRecord[] = evidence

  if (client && rows.length > 0) {
    const { data } = await client.from('scanner_evidence').insert(rows).select('*')
    insertedEvidence = (data || []).map((row: any) => ({
      id: row.id,
      userId: row.user_id,
      agentId: row.agent_id,
      connectorAccountId: row.connector_account_id,
      sourceType: row.source_type,
      evidenceType: row.evidence_type,
      assetName: row.asset_name,
      assetType: row.asset_type,
      target: row.target,
      host: row.host,
      port: row.port,
      protocol: row.protocol,
      observedAlgorithm: row.observed_algorithm,
      keySize: row.key_size,
      certificateFingerprint: row.certificate_fingerprint,
      filePath: row.file_path,
      packageName: row.package_name,
      packageVersion: row.package_version,
      confidence: row.confidence,
      rawEvidence: row.raw_evidence,
      observedAt: row.observed_at,
    }))
  } else {
    for (const item of insertedEvidence) {
      const row = { id: randomId('evidence'), ...dbEvidenceRow(item, userId), created_at: new Date().toISOString() }
      memoryStore.evidence.unshift(row)
      item.id = row.id
    }
  }

  if (options.persistRuntimeEvents !== false) {
    await persistRuntimeCryptoEvents(client, userId, runtimeEventsFromEvidence(insertedEvidence))
  }

  const scanId = randomId('evidence-scan')
  const observedFindings = scanEvidenceWithModules(insertedEvidence, scanId)
  const enrichedFindings = matchFingerprints(observedFindings)
  const ruleResults = evaluateFindings(enrichedFindings)

  for (const ruleResult of ruleResults) {
    const finding = enrichedFindings.find((item) => item.id === ruleResult.finding.id)
    if (finding && ruleResult.adjustedRiskScore > finding.riskScore) {
      finding.riskScore = ruleResult.adjustedRiskScore
      finding.severity = ruleResult.severity
      finding.ruleId = ruleResult.ruleId
    }
  }

  const scanner2 = {
    observedFindings,
    enrichedFindings,
    ruleResults,
    hndlRisks: analyzeHNDLRisks(enrichedFindings),
    attackAssessment: buildQuantumRiskAssessment(enrichedFindings),
    quantumRiskScore: calculateQuantumRiskScore(enrichedFindings),
    quantumReadiness: calculateQuantumReadiness(enrichedFindings),
    migrationRecommendations: Array.from(new Map(
      enrichedFindings
        .map((finding) => getMigrationRecommendation(finding.detectedAlgorithm))
        .filter(Boolean)
        .map((recommendation) => [recommendation!.classicalAlgorithm, recommendation])
    ).values()),
  }

  const links = await persistEvidenceFindings(client, userId, insertedEvidence, enrichedFindings, sourceLabel, options)
  const certificates = await persistCertificateEvidence(client, userId, insertedEvidence, sourceLabel)

  return {
    evidenceCount: insertedEvidence.length,
    findingCount: enrichedFindings.length,
    scanner2,
    links,
    certificates,
  }
}

/**
 * Materialises observed X.509 certificates into the canonical `certificates`
 * table so the Certificate and PKI dashboards see agent-discovered PKI instead
 * of only connector-sourced inventory (spec §14).
 *
 * Rules:
 *  - keyed on (user_id, serial_number) with the SHA-256 fingerprint as the
 *    tiebreaker, so a repeat scan UPDATES the row rather than duplicating it;
 *  - `is_quantum_safe` is written only when the signing/public-key algorithm is
 *    actually determined. An algorithm we could not classify stays NULL — never
 *    coerced to `true` (spec §29) and never to `false`, which would publish a
 *    vulnerability we did not observe;
 *  - every row records the agent, evidence id and observation time so a finding
 *    remains traceable to the evidence that produced it (spec §16).
 */
async function persistCertificateEvidence(
  client: SupabaseClient | null,
  userId: string,
  evidence: ScannerEvidenceRecord[],
  sourceLabel: string,
) {
  const certificateEvidence = evidence.filter(
    (item) => item.evidenceType === 'tls-certificate' && item.certificateFingerprint,
  )
  if (!client || certificateEvidence.length === 0) return { inserted: 0, updated: 0 }

  let inserted = 0
  let updated = 0
  const now = new Date().toISOString()

  for (const item of certificateEvidence) {
    const raw = asRecord(item.rawEvidence)
    const subject = cleanString(typeof raw.subject === 'string' ? raw.subject : JSON.stringify(raw.subject ?? ''), 500)
    const issuer = cleanString(typeof raw.issuer === 'string' ? raw.issuer : JSON.stringify(raw.issuer ?? ''), 500)
    const serial = cleanString(raw.serialNumber, 200) || item.certificateFingerprint!.slice(0, 64)
    const notBefore = parseCertificateDate(raw.validFrom)
    const notAfter = parseCertificateDate(raw.validTo)
    const algorithm = cleanString(item.observedAlgorithm, 120) || 'Unknown'

    // One classifier for the whole platform — no rival quantum-posture model.
    const anatomy = analyzeCryptoObservation({ name: algorithm, algorithm }, true)
    const quantumSafe =
      anatomy.quantumClass === 'safe' ? true : anatomy.quantumClass === 'vulnerable' ? false : null

    const expiringSoon = notAfter
      ? Date.parse(notAfter) - Date.now() < 30 * 24 * 60 * 60 * 1000 && Date.parse(notAfter) > Date.now()
      : null
    const expired = notAfter ? Date.parse(notAfter) < Date.now() : false

    const metadata = {
      source: sourceLabel,
      agentId: item.agentId || null,
      evidenceId: item.id || null,
      evidenceType: item.evidenceType,
      fingerprintSha256: item.certificateFingerprint,
      host: item.host || null,
      port: item.port || null,
      target: item.target || null,
      publicKeyType: raw.publicKeyType ?? null,
      publicKeyDetails: raw.publicKeyDetails ?? null,
      confidence: item.confidence || 'high',
      observedAt: item.observedAt || now,
      detectionMethod: 'agent-tls-handshake-observation',
      quantumClassification:
        anatomy.quantumClass === 'safe'
          ? 'Quantum Resilient'
          : anatomy.quantumClass === 'hybrid'
            ? 'Hybrid'
            : anatomy.quantumClass === 'vulnerable'
              ? 'Quantum Vulnerable'
              : 'Unknown',
      cryptoFamily: anatomy.family,
    }

    const { data: existing, error: lookupError } = await client
      .from('certificates')
      .select('id, metadata')
      .eq('user_id', userId)
      .eq('serial_number', serial)
      .limit(1)
      .maybeSingle()

    if (lookupError && !isMissingRuntimeTable(lookupError)) {
      console.warn('[agent-scanner] certificate lookup failed:', lookupError.message)
      continue
    }

    const assetId = await resolveAssetIdByName(client, userId, item.assetName)
    const row = {
      user_id: userId,
      asset_id: assetId,
      name: item.assetName || subject || serial,
      algorithm,
      key_size: item.keySize ?? null,
      issuer,
      subject,
      serial_number: serial,
      not_before: notBefore,
      not_after: notAfter,
      is_quantum_safe: quantumSafe,
      is_expiring_soon: expiringSoon,
      status: expired ? 'expired' : 'active',
      updated_at: now,
    }

    if (existing?.id) {
      const { error } = await client
        .from('certificates')
        .update({ ...row, metadata: { ...(existing.metadata || {}), ...metadata } })
        .eq('id', existing.id)
        .eq('user_id', userId)
      if (error && !isMissingRuntimeTable(error)) {
        console.warn('[agent-scanner] certificate update failed:', error.message)
      } else if (!error) {
        updated += 1
      }
    } else {
      const { error } = await client.from('certificates').insert({ ...row, metadata })
      if (error && !isMissingRuntimeTable(error)) {
        console.warn('[agent-scanner] certificate insert failed:', error.message)
      } else if (!error) {
        inserted += 1
      }
    }
  }

  return { inserted, updated }
}

/** Node's X509 `validFrom`/`validTo` are RFC-822 style strings, not ISO. */
function parseCertificateDate(value: unknown): string | null {
  const text = typeof value === 'string' ? value.trim() : ''
  if (!text) return null
  const parsed = Date.parse(text)
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null
}

async function resolveAssetIdByName(client: SupabaseClient, userId: string, assetName: string | null | undefined) {
  const name = cleanString(assetName, 255)
  if (!name) return null
  const { data, error } = await client
    .from('assets')
    .select('id')
    .eq('user_id', userId)
    .eq('name', name)
    .limit(1)
    .maybeSingle()
  if (error && !isMissingRuntimeTable(error)) return null
  return data?.id || null
}

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, any> : {}
}

async function activePolicyForAgent(client: SupabaseClient | null, agent: any) {
  if (client) {
    const { data } = await client
      .from('scanner_agent_policies')
      .select('*')
      .eq('agent_id', agent.id)
      .eq('user_id', agent.user_id)
      .eq('enabled', true)
      .limit(1)
      .maybeSingle()
    if (data) return normalizePolicy(data)
  }
  return normalizePolicy(agent.policy || {})
}

function remediationJobMetadata(job: any) {
  return asRecord(job?.metadata)
}

function remediationJobIsHndl(job: any) {
  const metadata = remediationJobMetadata(job)
  const text = [
    job?.name,
    job?.job_type,
    job?.target_algorithm,
    job?.strategy,
    metadata.source,
    metadata.workflow,
    metadata.workflowType,
    metadata.findingType,
    metadata.hndlFindingId,
    metadata.sourceFindingId,
    metadata.detectionId,
    metadata.riskCategory,
  ].filter(Boolean).join(' ').toLowerCase()
  return (
    text.includes('hndl') ||
    text.includes('harvest-now') ||
    text.includes('harvest now') ||
    text.includes('decrypt later')
  )
}

function migrationJobIsAgentExecutable(job: any) {
  if (remediationJobIsHndl(job)) return true
  const metadata = remediationJobMetadata(job)
  const text = [
    job?.name,
    job?.job_type,
    job?.target_algorithm,
    job?.strategy,
    metadata.source,
    metadata.workflow,
    metadata.workflowType,
    metadata.planAction,
    metadata.migrationType,
    metadata.assetType,
  ].filter(Boolean).join(' ').toLowerCase()
  return /post-quantum|pqc|migration-planner|ml-kem|ml-dsa|hybrid|certificate|cert|key_rotation|key rotation|protocol_upgrade|encryption_upgrade|signature_transition/.test(text)
}

function remediationTarget(job: any) {
  const metadata = remediationJobMetadata(job)
  return cleanString(
    metadata.target ||
    metadata.endpoint ||
    metadata.url ||
    metadata.host ||
    metadata.assetName ||
    metadata.asset_name ||
    metadata.location ||
    job?.asset_name ||
    job?.name,
    500
  )
}

function remediationFilePath(job: any) {
  const metadata = remediationJobMetadata(job)
  return cleanString(metadata.filePath || metadata.file_path || metadata.path || metadata.configPath || metadata.config_path, 1000)
}

function remediationAdapter(job: any) {
  const metadata = remediationJobMetadata(job)
  const text = [
    job?.name,
    job?.job_type,
    metadata.assetType,
    metadata.asset_type,
    metadata.resourceType,
    metadata.provider,
    metadata.target,
    metadata.location,
    metadata.filePath,
    metadata.path,
    metadata.remediationAdapter,
  ].filter(Boolean).join(' ').toLowerCase()

  if (/kubernetes|k8s|cluster|ingress|helm|namespace/.test(text)) return 'kubernetes'
  if (/container|docker|image|registry|podman/.test(text)) return 'container'
  if (/saas|salesforce|servicenow|workday|zendesk|shopify|customer portal|commerce|e-commerce/.test(text)) return 'saas_application'
  if (/database|postgres|mysql|mariadb|sql server|oracle db|rds|aurora|cloud sql|cosmos|spanner|dynamodb|mongodb/.test(text)) return 'database'
  if (/api.?gateway|gateway api|kong|apigee|azure api management|aws api gateway/.test(text)) return 'api_gateway'
  if (/network device|router|switch|firewall|f5|big-ip|citrix|netscaler|palo alto|fortinet|checkpoint|vpn/.test(text)) return 'network_device'
  if (/website|web app|web_application|portal|reverse proxy|nginx|apache|iis|cdn|cloudfront|cloudflare|akamai|fastly|public tls|https?:\/\//.test(text)) return 'web_application'
  if (/aws|azure|gcp|google cloud|oracle cloud|oci|alibaba|aliyun|cloud|load balancer|alb|elb|nlb|front door|kms|key vault|hsm|bucket|storage/.test(text)) return 'cloud'
  if (/iam|identity|access|oauth|oidc|saml|jwt|credential|secret|key vault|kms/.test(text)) return 'identity_access'
  if (/repo|source|code|package|dependency|manifest|config|library|application/.test(text)) return 'code_application'
  if (/https?:\/\/|website|web app|web_application|tls|ssl|ssh|protocol|certificate|cipher/.test(text)) return 'network_protocol'
  return 'universal'
}

function remediationProbeEvidence(job: any, agent: any): ScannerEvidenceRecord | null {
  const target = remediationTarget(job)
  const filePath = remediationFilePath(job)
  const assetName = cleanString(remediationJobMetadata(job).assetName || remediationJobMetadata(job).asset_name || job?.name, 255) || 'HNDL remediation target'

  if (filePath) {
    return normalizeEvidence({
      evidenceType: 'config-reference',
      assetName,
      assetType: remediationAdapter(job),
      filePath,
      rawEvidence: {
        remediationJobId: job?.id,
        remediationProbe: true,
      },
    }, 'local-agent', agent)
  }

  if (!target) return null
  const parsed = parsePolicyTarget(target)
  if (!parsed?.host) {
    return normalizeEvidence({
      evidenceType: 'config-reference',
      assetName,
      assetType: remediationAdapter(job),
      target,
      rawEvidence: {
        remediationJobId: job?.id,
        remediationProbe: true,
      },
    }, 'local-agent', agent)
  }

  return normalizeEvidence({
    evidenceType: parsed.port === 22 ? 'ssh-metadata' : 'tls-protocol',
    assetName: parsed.host,
    assetType: remediationAdapter(job),
    target,
    host: parsed.host,
    port: parsed.port || (target.toLowerCase().startsWith('ssh') ? 22 : 443),
    protocol: parsed.port === 22 ? 'SSH' : 'TLS',
    rawEvidence: {
      remediationJobId: job?.id,
      remediationProbe: true,
    },
  }, 'local-agent', agent)
}

/** The migration plan a queued job belongs to, when it declares one. */
function planIdForJob(job: any) {
  const metadata = remediationJobMetadata(job)
  return cleanString(metadata.planId || metadata.plan_id, 120) || ''
}

/**
 * Plan ids among these jobs whose approval decision forbids execution.
 *
 * Reads the governance state written by POST /migration-planner/plans/:id/
 * approval. A read failure returns an EMPTY set rather than blocking the whole
 * fleet: a database hiccup must not look like a mass revocation, and the
 * dispatch-time gate in migration.ts has already applied the same rule.
 */
async function rejectedPlanIdsFor(client: any, userId: string, jobs: any[]): Promise<Set<string>> {
  const planIds = Array.from(new Set(jobs.map(planIdForJob).filter(Boolean)))
  if (planIds.length === 0) return new Set()
  try {
    const { data, error } = await client
      .from('migration_plans')
      .select('id, status')
      .eq('user_id', userId)
      .in('id', planIds)
    if (error) {
      console.warn('[agent-remediation] Plan approval re-check skipped:', error.message)
      return new Set()
    }
    return new Set(
      ((data as any[]) || [])
        .filter((row) => ['rejected', 'pending_approval'].includes(String(row.status || '').toLowerCase()))
        .map((row) => String(row.id))
    )
  } catch (error: any) {
    console.warn('[agent-remediation] Plan approval re-check failed:', error?.message || error)
    return new Set()
  }
}

function remediationJobAllowedForAgent(job: any, policy: ReturnType<typeof normalizePolicy>, agent: any) {
  const probe = remediationProbeEvidence(job, agent)
  if (!probe) {
    if (!migrationJobIsAgentExecutable(job)) return policy.allowedTargets.length === 0 && policy.allowedPaths.length === 0
    const scanTypes = new Set(policy.scanTypes.map((item: string) => String(item).toLowerCase()))
    const migrationAllowed = DEFAULT_AGENT_SCAN_TYPES.some((type) => scanTypes.has(type))
    return migrationAllowed || (policy.allowedTargets.length === 0 && policy.allowedPaths.length === 0)
  }
  return evidenceAllowedByPolicy(probe, policy, true)
}

function remediationJobPayload(job: any) {
  const metadata = remediationJobMetadata(job)
  return {
    id: job.id,
    assetId: job.asset_id || null,
    name: job.name || 'HNDL Remediation',
    jobType: job.job_type || 'hndl_mitigation',
    status: job.status || 'running',
    targetAlgorithm: job.target_algorithm || 'ML-KEM-768 hybrid',
    strategy: job.strategy || 'guarded_agent_execution',
    progress: Number(job.progress || 0),
    adapter: remediationAdapter(job),
    target: remediationTarget(job),
    filePath: remediationFilePath(job),
    metadata,
    startedAt: job.started_at || null,
    completedAt: job.completed_at || null,
    createdAt: job.created_at || null,
    updatedAt: job.updated_at || null,
  }
}

function remediationEventSeverity(status: string) {
  if (status === 'failed') return 'error'
  if (status === 'blocked' || status === 'manual_required' || status === 'paused') return 'warning'
  if (status === 'completed') return 'success'
  return 'info'
}

function sanitizeAgentMetadata(value: unknown) {
  return (sanitizeRuntimeMetadata(value || {}) || {}) as Record<string, unknown>
}

function migrationMetricType(eventType: string, message: string, job: any) {
  const text = `${eventType} ${message} ${job?.job_type || ''} ${job?.target_algorithm || ''}`.toLowerCase()
  if (/tls|handshake|cipher|session|protocol/.test(text)) return 'tls_handshake'
  if (/cert|certificate|issuer|chain|pki/.test(text)) return 'certificate_replacement'
  if (/key|rotation|kem|envelope/.test(text)) return 'key_rotation'
  if (/compatib|fallback|interoperab/.test(text)) return 'compatibility_check'
  if (/validat|verify|evidence|pqc|quantum/.test(text)) return 'pqc_validation'
  return 'execution_progress'
}

function validationPassed(validation: Record<string, any>) {
  const status = String(validation.status || validation.result || '').toLowerCase()
  return validation.passed === true || ['passed', 'success', 'successful', 'validated', 'valid'].includes(status)
}

async function persistMigrationExecution(client: SupabaseClient, agent: any, job: any, payload: {
  status: string
  progress: number
  currentStep: string
  metadata: Record<string, unknown>
  now: string
}) {
  const metadata = remediationJobMetadata(job)
  const planId = cleanString(metadata.planId || asRecord(metadata.plan).id, 255)
  const { error } = await client.from('migration_execution').upsert({
    user_id: agent.user_id,
    migration_id: job.id,
    plan_id: planId || null,
    agent_id: agent.id,
    status: payload.status,
    progress: payload.status === 'completed' ? 100 : payload.progress,
    current_step: payload.currentStep,
    started_at: job.started_at || payload.now,
    completed_at: payload.status === 'completed' ? payload.now : null,
    metadata: payload.metadata,
    created_at: job.started_at || payload.now,
    updated_at: payload.now,
  }, { onConflict: 'migration_id,user_id' })
  if (error && !isMissingRuntimeTable(error)) console.warn('[agent-remediation] migration_execution upsert failed:', error.message)
}

async function persistMigrationTelemetry(client: SupabaseClient, agent: any, job: any, payload: {
  eventType: string
  message: string
  progress: number
  metadata: Record<string, unknown>
  now: string
}) {
  const { error } = await client.from('migration_telemetry').insert({
    user_id: agent.user_id,
    migration_id: job.id,
    agent_id: agent.id,
    event_type: payload.eventType,
    metric_type: migrationMetricType(payload.eventType, payload.message, job),
    metric_value: payload.progress,
    message: payload.message,
    metadata: payload.metadata,
    observed_at: payload.now,
    created_at: payload.now,
  })
  if (error && !isMissingRuntimeTable(error)) console.warn('[agent-remediation] migration_telemetry insert failed:', error.message)
}

async function persistMigrationValidation(client: SupabaseClient, agent: any, job: any, payload: {
  validation: Record<string, unknown>
  evidence: Record<string, unknown>
  status: string
  type: string
  metadata: Record<string, unknown>
  now: string
}) {
  const { error } = await client.from('migration_validation_logs').insert({
    user_id: agent.user_id,
    migration_id: job.id,
    agent_id: agent.id,
    validation_type: payload.type,
    status: payload.status,
    evidence: payload.evidence,
    metadata: {
      ...payload.metadata,
      validation: payload.validation,
    },
    created_at: payload.now,
  })
  if (error && !isMissingRuntimeTable(error)) console.warn('[agent-remediation] migration_validation_logs insert failed:', error.message)
}

const PATCH_OPTION_GROUPS = {
  kubernetes: [
    {
      id: 'k8s-ingress-tls-profile',
      label: 'Patch Ingress TLS Profile',
      actionType: 'patch_kubernetes_ingress_tls',
      requiresConnector: true,
      requiredScopes: ['kubernetes:read', 'kubernetes:patch:ingress'],
      summary: 'Patch Ingress or Gateway TLS policy to enforce approved TLS versions, certificate references, and hybrid/PQC-ready termination where supported.',
      validation: 'Upload connector evidence for the patched ingress/gateway and rescan the public endpoint.',
    },
    {
      id: 'k8s-cert-manager-issuer',
      label: 'Patch cert-manager Issuer',
      actionType: 'patch_kubernetes_cert_manager',
      requiresConnector: true,
      requiredScopes: ['kubernetes:read', 'kubernetes:patch:cert-manager'],
      summary: 'Update Issuer, ClusterIssuer, Certificate, or Secret references used by TLS workloads.',
      validation: 'Upload certificate evidence and verify the served certificate/key exchange after rollout.',
    },
    {
      id: 'k8s-service-mesh-mtls',
      label: 'Patch Service Mesh mTLS Policy',
      actionType: 'patch_kubernetes_service_mesh',
      requiresConnector: true,
      requiredScopes: ['kubernetes:read', 'kubernetes:patch:service-mesh'],
      summary: 'Patch Istio, Linkerd, Consul, or mesh policy objects that control mTLS, cipher, and workload TLS settings.',
      validation: 'Upload mesh policy evidence and runtime TLS observations from the affected workload.',
    },
    {
      id: 'k8s-workload-crypto-config',
      label: 'Patch Workload Crypto Config',
      actionType: 'patch_kubernetes_workload_config',
      requiresConnector: true,
      requiredScopes: ['kubernetes:read', 'kubernetes:patch:workload'],
      summary: 'Patch ConfigMap, Secret reference, Deployment env, or mounted configuration used by application crypto.',
      validation: 'Upload changed manifest/config evidence and rescan the workload endpoint or app folder.',
    },
  ],
  cloud: [
    {
      id: 'cloud-load-balancer-tls-policy',
      label: 'Patch Load Balancer TLS Policy',
      actionType: 'patch_cloud_load_balancer_tls',
      requiresConnector: true,
      requiredScopes: ['cloud:read', 'cloud:patch:load-balancer'],
      summary: 'Update AWS ALB/NLB, Azure Application Gateway/Front Door, GCP HTTPS LB, or equivalent TLS/security policy.',
      validation: 'Connector uploads LB policy evidence, then QGuard rescans the public endpoint.',
    },
    {
      id: 'cloud-cdn-edge-tls-policy',
      label: 'Patch CDN / Edge TLS Policy',
      actionType: 'patch_cloud_cdn_tls',
      requiresConnector: true,
      requiredScopes: ['cloud:read', 'cloud:patch:cdn'],
      summary: 'Apply an approved TLS/certificate profile at CloudFront, Azure Front Door/CDN, Cloud CDN, or edge gateway.',
      validation: 'Connector uploads edge config evidence and endpoint TLS evidence after propagation.',
    },
    {
      id: 'cloud-kms-key-policy',
      label: 'Patch KMS / Key Policy',
      actionType: 'patch_cloud_kms_policy',
      requiresConnector: true,
      requiredScopes: ['cloud:read', 'cloud:patch:kms'],
      summary: 'Rotate, wrap, or re-policy vulnerable key usage through KMS, Key Vault, Cloud KMS, HSM, or private CA services.',
      validation: 'Connector uploads KMS/key metadata and runtime evidence that vulnerable key usage stopped.',
    },
    {
      id: 'cloud-certificate-manager',
      label: 'Patch Certificate Manager',
      actionType: 'patch_cloud_certificate_manager',
      requiresConnector: true,
      requiredScopes: ['cloud:read', 'cloud:patch:certificate'],
      summary: 'Replace or reissue certificates through ACM, Azure Key Vault Certificates, Google Certificate Manager, or private CA.',
      validation: 'Upload certificate-manager evidence and rescan served certificates.',
    },
    {
      id: 'cloud-database-encryption-policy',
      label: 'Patch Cloud Database TLS / Encryption',
      actionType: 'patch_cloud_database_crypto_policy',
      requiresConnector: true,
      requiredScopes: ['cloud:read', 'cloud:patch:database'],
      summary: 'Patch RDS, Aurora, Cloud SQL, Azure SQL, Cosmos DB, Spanner, Oracle, or Alibaba database TLS, certificate, and key-policy settings where supported.',
      validation: 'Connector uploads database TLS/encryption evidence and QGuard validates client reachability and certificate trust.',
    },
    {
      id: 'cloud-storage-encryption-policy',
      label: 'Patch Cloud Storage Encryption',
      actionType: 'patch_cloud_storage_encryption_policy',
      requiresConnector: true,
      requiredScopes: ['cloud:read', 'cloud:patch:storage'],
      summary: 'Enforce approved encryption, key rotation, and KMS/HSM binding for buckets, blobs, object stores, and managed file services.',
      validation: 'Connector uploads storage encryption policy and key metadata after the approved change.',
    },
    {
      id: 'cloud-hsm-provider-policy',
      label: 'Patch Cloud HSM / KMS Provider',
      actionType: 'patch_cloud_hsm_provider_policy',
      requiresConnector: true,
      requiredScopes: ['cloud:read', 'cloud:patch:hsm', 'cloud:patch:kms'],
      summary: 'Update CloudHSM, Key Vault, Cloud KMS, OCI Vault, Alibaba KMS, or private CA provider policy and key backup metadata.',
      validation: 'Connector uploads HSM/KMS provider evidence and runtime key-use proof.',
    },
  ],
  identity_access: [
    {
      id: 'iam-oidc-jwt-algorithm-policy',
      label: 'Patch OIDC / JWT Algorithm Policy',
      actionType: 'patch_iam_jwt_algorithm_policy',
      requiresConnector: true,
      requiredScopes: ['identity:read', 'identity:patch:policy'],
      summary: 'Migrate token signing or verification policy away from vulnerable RSA/ECDSA-only assumptions where the provider supports stronger/hybrid controls.',
      validation: 'Upload IdP policy metadata and signed-token header evidence after rotation.',
    },
    {
      id: 'iam-saml-certificate-rotation',
      label: 'Patch SAML Signing Certificate',
      actionType: 'patch_iam_saml_certificate',
      requiresConnector: true,
      requiredScopes: ['identity:read', 'identity:patch:certificate'],
      summary: 'Rotate SAML signing/encryption certificates and update relying-party trust metadata.',
      validation: 'Upload IdP certificate evidence and relying-party metadata confirmation.',
    },
    {
      id: 'iam-kms-credential-rotation',
      label: 'Patch Credential / KMS Binding',
      actionType: 'patch_iam_kms_binding',
      requiresConnector: true,
      requiredScopes: ['identity:read', 'identity:patch:credential'],
      summary: 'Rotate exposed credentials or rebind identity workloads to approved KMS/HSM-backed keys.',
      validation: 'Upload credential/key metadata and runtime evidence showing old key usage has stopped.',
    },
  ],
  network_protocol: [
    {
      id: 'network-tls-profile',
      label: 'Patch TLS Protocol Profile',
      actionType: 'patch_network_tls_profile',
      requiresConnector: false,
      requiredScopes: ['agent:target-scan'],
      summary: 'Apply approved TLS versions, cipher suites, certificate chain, and hybrid/PQC-capable termination through the owning server/LB/CDN.',
      validation: 'Agent rescans TLS certificate, protocol, and cipher evidence.',
    },
    {
      id: 'network-ssh-kex-policy',
      label: 'Patch SSH KEX Policy',
      actionType: 'patch_network_ssh_policy',
      requiresConnector: false,
      requiredScopes: ['agent:target-scan'],
      summary: 'Update SSH KEX/host-key policy and remove deprecated DH/DSA/RSA-only algorithms where operationally safe.',
      validation: 'Agent rescans SSH metadata and uploads observed KEX/host-key algorithms.',
    },
  ],
  certificate_pki: [
    {
      id: 'pki-ml-dsa-certificate-migration',
      label: 'Migrate Certificate to ML-DSA / Hybrid',
      actionType: 'patch_pki_certificate_migration',
      requiresConnector: true,
      requiredScopes: ['pki:read', 'pki:issue', 'pki:replace-certificate', 'pki:update-trust-store'],
      summary: 'Generate CSR or certificate material, replace RSA/ECC certificates with ML-DSA or hybrid Ed25519 + ML-DSA where the PKI ecosystem supports it, and update trust stores.',
      validation: 'Validate certificate chain integrity, served certificate fingerprints, trust store updates, and rollback metadata.',
    },
    {
      id: 'pki-trust-store-update',
      label: 'Patch Trust Store',
      actionType: 'patch_pki_trust_store',
      requiresConnector: true,
      requiredScopes: ['pki:read', 'pki:update-trust-store'],
      summary: 'Update authorized trust stores after certificate migration and preserve certificate/key backup metadata before replacement.',
      validation: 'Upload trust store evidence and rescan the endpoint or application path using the new chain.',
    },
  ],
  vpn: [
    {
      id: 'vpn-hybrid-pqc-profile',
      label: 'Patch Hybrid PQC VPN Profile',
      actionType: 'patch_vpn_hybrid_profile',
      requiresConnector: true,
      requiredScopes: ['vpn:read', 'vpn:patch:profile'],
      summary: 'Patch IPSec, OpenVPN, WireGuard, or SSL VPN profiles away from RSA/ECDH/ECDSA-only dependencies toward supported hybrid PQC profiles.',
      validation: 'Upload VPN configuration evidence and handshake telemetry after the approved profile change.',
    },
  ],
  api_gateway: [
    {
      id: 'gateway-tls-cipher-profile',
      label: 'Patch API Gateway TLS / Cipher Profile',
      actionType: 'patch_api_gateway_tls_profile',
      requiresConnector: true,
      requiredScopes: ['gateway:read', 'gateway:patch:tls'],
      summary: 'Patch API gateways, reverse proxies, and edge gateways to enforce TLS 1.3, approved cipher suites, certificate references, and hybrid KEM groups where supported.',
      validation: 'Connector uploads gateway policy evidence and QGuard rescans endpoint negotiation.',
    },
    {
      id: 'gateway-api-signing-policy',
      label: 'Patch API Signing / JWT Policy',
      actionType: 'patch_api_gateway_signing_policy',
      requiresConnector: true,
      requiredScopes: ['gateway:read', 'gateway:patch:signing'],
      summary: 'Patch API signing, JWT verification, client certificate, and mTLS trust policy away from vulnerable RSA/ECDSA-only assumptions.',
      validation: 'Connector uploads gateway policy and signed-token/certificate evidence after rollout.',
    },
  ],
  hsm: [
    {
      id: 'hsm-pqc-provider-profile',
      label: 'Patch HSM / KMS PQC Provider Profile',
      actionType: 'patch_hsm_pqc_provider_profile',
      requiresConnector: true,
      requiredScopes: ['hsm:read', 'hsm:patch:policy', 'hsm:rotate-key-metadata'],
      summary: 'Patch HSM, KMS, PKCS#11, or key-vault integration profiles and record key backup metadata before rotation or policy change.',
      validation: 'Upload HSM/KMS policy evidence plus runtime proof that vulnerable RSA/ECC key usage stopped.',
    },
  ],
  code_application: [
    {
      id: 'code-crypto-config-toggle',
      label: 'Patch App Crypto Configuration',
      actionType: 'patch_code_crypto_config',
      requiresConnector: false,
      requiredScopes: ['agent:path-scan'],
      summary: 'Patch approved local config toggles such as PQC_ENABLED, HYBRID_KEM, TLS_HYBRID_KEM, and TLS protocol settings.',
      validation: 'Agent rescans the authorized app folder and uploads config evidence.',
    },
    {
      id: 'code-dependency-upgrade-plan',
      label: 'Create Dependency Upgrade Plan',
      actionType: 'patch_code_dependency_plan',
      requiresConnector: false,
      requiredScopes: ['agent:path-scan'],
      summary: 'Create an operator-approved package upgrade plan for vulnerable crypto libraries found in manifests.',
      validation: 'Agent rescans manifests after the developer upgrades dependencies.',
    },
  ],
  container: [
    {
      id: 'container-image-crypto-profile',
      label: 'Patch Container Crypto Profile',
      actionType: 'patch_container_crypto_profile',
      requiresConnector: true,
      requiredScopes: ['container:read', 'container:patch:image'],
      summary: 'Patch image/runtime crypto config, rebuild, and redeploy through the container delivery system.',
      validation: 'Upload image digest/config evidence and rescan the running endpoint.',
    },
  ],
  web_application: [
    {
      id: 'web-public-tls-profile',
      label: 'Patch Public TLS Endpoint',
      actionType: 'patch_web_public_tls_profile',
      requiresConnector: true,
      requiredScopes: ['web:read', 'web:patch:tls'],
      summary: 'Patch website, portal, e-commerce, reverse proxy, or public TLS endpoint certificate and TLS profile through the owning edge/server connector.',
      validation: 'QGuard rescans the public endpoint, certificate chain, protocol, cipher suite, and service reachability.',
    },
    {
      id: 'web-reverse-proxy-crypto-policy',
      label: 'Patch Reverse Proxy Crypto Policy',
      actionType: 'patch_web_reverse_proxy_crypto_policy',
      requiresConnector: true,
      requiredScopes: ['web:read', 'web:patch:reverse-proxy'],
      summary: 'Patch Nginx, Apache, IIS, Envoy, HAProxy, Traefik, or equivalent proxy TLS/cipher/certificate policy.',
      validation: 'Connector uploads proxy configuration evidence and QGuard validates endpoint negotiation.',
    },
    {
      id: 'web-cdn-edge-pqc-profile',
      label: 'Patch CDN / Edge PQC Profile',
      actionType: 'patch_web_cdn_edge_pqc_profile',
      requiresConnector: true,
      requiredScopes: ['web:read', 'web:patch:cdn'],
      summary: 'Patch Cloudflare, Akamai, Fastly, CloudFront, Front Door, or equivalent edge TLS/certificate policy where supported.',
      validation: 'Connector uploads edge policy evidence and public scans verify propagation.',
    },
  ],
  saas_application: [
    {
      id: 'saas-certificate-trust-rotation',
      label: 'Patch SaaS Certificate / Trust Rotation',
      actionType: 'patch_saas_certificate_trust_rotation',
      requiresConnector: true,
      requiredScopes: ['saas:read', 'saas:patch:certificate'],
      summary: 'Rotate SaaS application certificates, custom domain TLS, trust metadata, or federation certificates using approved tenant API scopes.',
      validation: 'Connector uploads SaaS certificate/trust metadata and QGuard validates public or federation endpoints.',
    },
    {
      id: 'saas-api-crypto-policy',
      label: 'Patch SaaS API Crypto Policy',
      actionType: 'patch_saas_api_crypto_policy',
      requiresConnector: true,
      requiredScopes: ['saas:read', 'saas:patch:api-security'],
      summary: 'Patch SaaS API signing, mTLS, webhook signature, key rotation, and allowed algorithm policy where the provider exposes controls.',
      validation: 'Connector uploads API policy evidence plus post-change functional verification.',
    },
  ],
  database: [
    {
      id: 'database-tls-certificate-policy',
      label: 'Patch Database TLS / Certificate Policy',
      actionType: 'patch_database_tls_certificate_policy',
      requiresConnector: true,
      requiredScopes: ['database:read', 'database:patch:tls'],
      summary: 'Patch PostgreSQL, MySQL, SQL Server, Oracle, MongoDB, or managed database TLS, certificate, and trust-store settings.',
      validation: 'Connector uploads database TLS policy evidence and validates client connectivity plus certificate chain integrity.',
    },
    {
      id: 'database-key-rotation-policy',
      label: 'Patch Database Key Rotation',
      actionType: 'patch_database_key_rotation_policy',
      requiresConnector: true,
      requiredScopes: ['database:read', 'database:patch:key-rotation'],
      summary: 'Rotate or rebind database encryption keys through KMS/HSM or database-native key management after approval.',
      validation: 'Connector uploads key metadata, rotation status, and service health evidence.',
    },
  ],
  network_device: [
    {
      id: 'network-device-tls-ssh-policy',
      label: 'Patch Network Device TLS / SSH Policy',
      actionType: 'patch_network_device_tls_ssh_policy',
      requiresConnector: true,
      requiredScopes: ['network-device:read', 'network-device:patch:crypto-policy'],
      summary: 'Patch routers, switches, firewalls, F5, Citrix, VPN concentrators, and appliances away from weak TLS, SSH RSA/DSA, and legacy cipher suites.',
      validation: 'Connector uploads device config diff, snapshot metadata, and post-change TLS/SSH evidence.',
    },
    {
      id: 'network-device-vpn-pqc-profile',
      label: 'Patch Network Device VPN Profile',
      actionType: 'patch_network_device_vpn_pqc_profile',
      requiresConnector: true,
      requiredScopes: ['network-device:read', 'network-device:patch:vpn'],
      summary: 'Patch IPSec, SSL VPN, and appliance VPN profiles toward approved hybrid PQC settings where supported by the device ecosystem.',
      validation: 'Connector uploads VPN profile evidence and handshake or tunnel health validation.',
    },
  ],
}

function patchOptionsForAssetClass(assetClass: string) {
  const key = assetClass.replace(/-/g, '_').toLowerCase()
  const options = (PATCH_OPTION_GROUPS as Record<string, any[]>)[key] || PATCH_OPTION_GROUPS.network_protocol
  return options.map((option) => ({
    ...option,
    mandatoryQuantumStack: MANDATORY_QUANTUM_STACK_METADATA,
    executionContract: remediationExecutionContract(option),
  }))
}

function allPatchOptionGroups() {
  return Object.keys(PATCH_OPTION_GROUPS).map((assetClass) => ({ assetClass, options: patchOptionsForAssetClass(assetClass) }))
}

function publicAgent(agent: any) {
  if (!agent) return agent
  const { token_hash, tokenHash, ...safeAgent } = agent
  return safeAgent
}

function rowsFromResult<T = any>(result: { data?: T[] | null; error?: any } | null | undefined, fallback: T[] = []) {
  if (!result) return fallback
  if (result.error) {
    if (isMissingRuntimeTable(result.error)) return fallback
    throw new Error(result.error.message || 'Database query failed')
  }
  return result.data || []
}

function summarizeAgentScannerSnapshot(agents: any[], evidence: any[], alerts: any[], connectors: any[], operatorActions: any[]) {
  const nowMs = Date.now()
  const onlineAgents = agents.filter((agent) => {
    if (agent?.revoked_at || String(agent?.status || '').toLowerCase() === 'revoked') return false
    const seenAt = Date.parse(agent?.last_seen_at || '')
    return Number.isFinite(seenAt) && nowMs - seenAt < 10 * 60 * 1000
  }).length
  const openAlerts = alerts.filter((alert) => !['resolved', 'closed', 'suppressed'].includes(String(alert?.status || 'open').toLowerCase())).length
  const activeConnectors = connectors.filter((connector) => String(connector?.status || 'active').toLowerCase() !== 'revoked').length
  const pendingActions = operatorActions.filter((action) => ['requested', 'approved', 'applied'].includes(String(action?.status || '').toLowerCase())).length

  return {
    agents: agents.length,
    onlineAgents,
    evidence: evidence.length,
    openAlerts,
    connectors: activeConnectors,
    operatorActions: operatorActions.length,
    pendingActions,
  }
}

async function buildAgentScannerSnapshot(client: SupabaseClient | null, userId: string) {
  const generatedAt = new Date().toISOString()

  if (client) {
    const [agentsResult, evidenceResult, alertsResult, connectorsResult, operatorActionsResult] = await Promise.all([
      client
        .from('scanner_agents')
        .select('id, user_id, name, status, hostname, platform, version, capabilities, policy, last_seen_at, revoked_at, metadata, created_at, updated_at')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(100),
      client
        .from('scanner_evidence')
        .select('id, user_id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, certificate_fingerprint, file_path, package_name, package_version, confidence, raw_evidence, processed_at, observed_at, created_at')
        .eq('user_id', userId)
        .order('observed_at', { ascending: false })
        .limit(200),
      client
        .from('scanner_alerts')
        .select('id, user_id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, acknowledged_at, resolved_at, created_at, updated_at')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(200),
      client
        .from('connector_accounts')
        .select('id, user_id, provider, provider_account_id, display_name, status, scopes, capabilities, policy, last_sync_at, metadata, created_at, updated_at')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(100),
      client
        .from('remediation_operator_actions')
        .select('id, user_id, migration_id, connector_account_id, action_type, asset_class, status, approval_mode, patch_plan, evidence, validation, metadata, requested_at, approved_at, applied_at, validated_at, created_at, updated_at')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(200),
    ])

    const agents = rowsFromResult(agentsResult).map(publicAgent)
    const evidence = rowsFromResult(evidenceResult)
    const alerts = rowsFromResult(alertsResult)
    const connectors = rowsFromResult(connectorsResult)
    const operatorActions = rowsFromResult(
      operatorActionsResult,
      memoryStore.operatorActions.filter((item) => item.user_id === userId),
    )

    return {
      generatedAt,
      mode: 'database',
      agents,
      evidence,
      alerts,
      connectors,
      operatorActions,
      patchOptions: allPatchOptionGroups(),
      summary: summarizeAgentScannerSnapshot(agents, evidence, alerts, connectors, operatorActions),
    }
  }

  const agents = Array.from(memoryStore.agents.values()).filter((agent) => agent.user_id === userId).map(publicAgent)
  const evidence = memoryStore.evidence.filter((item) => item.user_id === userId).slice(0, 200)
  const alerts = memoryStore.alerts.filter((item) => item.user_id === userId).slice(0, 200)
  const connectors = memoryStore.connectors
    .filter((item) => item.user_id === userId)
    .slice(0, 100)
    .map(({ token_ref, ...connector }) => connector)
  const operatorActions = memoryStore.operatorActions.filter((item) => item.user_id === userId).slice(0, 200)

  return {
    generatedAt,
    mode: 'memory',
    agents,
    evidence,
    alerts,
    connectors,
    operatorActions,
    patchOptions: allPatchOptionGroups(),
    summary: summarizeAgentScannerSnapshot(agents, evidence, alerts, connectors, operatorActions),
  }
}

function sendAgentScannerSse(res: Response, event: string, data: any) {
  res.write(`event: ${event}\n`)
  res.write(`data: ${JSON.stringify(data)}\n\n`)
}

function actionStatusTimestamp(status: string, now: string) {
  if (status === 'approved') return { approved_at: now }
  if (status === 'applied') return { applied_at: now }
  if (status === 'validated') return { validated_at: now, applied_at: now }
  return {}
}

router.post('/agents/enroll', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const now = new Date().toISOString()
  const token = generateAgentToken()
  const tokenHash = hashToken(token)
  const policy = normalizePolicy(req.body?.policy || {})

  /*
   * ROLE IS SERVER-RESOLVED (Agent_Installer_Refactor §41, §15).
   *
   * The role used to come straight out of caller-supplied `metadata.role`,
   * which is spread into the row verbatim — so a tenant on any plan could mint
   * a `patcher` (an agent that WRITES to their hosts) by editing one JSON
   * field. The requested role is now checked against the tenant's plan before
   * anything is written, and an unknown role is refused rather than defaulted.
   *
   *   collector, scanner  read-only     BASIC
   *   patcher, operator   writes hosts  PRO
   */
  const roleDecision = await decideAgentRole(
    req as AgentEntitlementRequest,
    req.body?.role ?? req.body?.metadata?.role,
    (id) => agentRole(id).label,
  )
  if (!roleDecision.ok) {
    jsonError(res, roleDecision.status, roleDecision.code, roleDecision.message, roleDecision.detail)
    return
  }
  const resolvedRole = roleDecision.role

  /*
   * Scan modules are clamped to the plan, and the removals are RECORDED.
   * Dropping them silently would leave the agent never reporting on those
   * dimensions, and an absent dimension reads as a clean one.
   */
  const scanTypeDecision = await decideScanTypes(
    req as AgentEntitlementRequest,
    Array.isArray(policy.scanTypes) && policy.scanTypes.length ? policy.scanTypes.map(String) : agentRole(resolvedRole).scanTypes,
  )
  policy.scanTypes = scanTypeDecision.allowed

  /*
   * Asset binding must be verified, not trusted. `metadata` is caller-supplied and
   * was spread in verbatim, so a tenant could bind their agent to ANOTHER tenant's
   * asset UUID. That never granted them the other tenant's data (every read filters
   * on user_id), but it would plant a foreign asset reference in their own
   * inventory, reports and migration scope. Reject it outright rather than silently
   * dropping it, so the caller learns the binding did not take.
   */
  const requestedAssetId = cleanString(req.body?.metadata?.assetId, 80)
  let resolvedAsset: { id: string; name: string; type: string | null } | null = null
  if (requestedAssetId && client) {
    const { data: asset, error: assetError } = await client
      .from('assets')
      .select('id, name, type')
      .eq('id', requestedAssetId)
      .eq('user_id', user.id)
      .limit(1)
      .maybeSingle()
    if (assetError && !isMissingRuntimeTable(assetError)) {
      jsonError(res, 500, 'ASSET_LOOKUP_FAILED', assetError.message)
      return
    }
    if (!asset) {
      jsonError(res, 404, 'ASSET_NOT_FOUND', 'The selected asset does not exist in this tenant')
      return
    }
    resolvedAsset = asset as { id: string; name: string; type: string | null }
  }

  const agentBase = {
    user_id: user.id,
    name: cleanString(req.body?.name, 255) || 'QGuard Local Agent',
    token_hash: tokenHash,
    status: 'active',
    hostname: cleanString(req.body?.hostname, 255),
    platform: cleanString(req.body?.platform, 100),
    version: cleanString(req.body?.version, 100) || '0.1.0',
    /* Capabilities follow the SERVER-RESOLVED role. A caller asking for
       `remediation: true` on a collector gets a collector, because the role
       definition is the authority on what a role may do (§40, §41). */
    capabilities: defaultRemediationCapabilities({
      ...(typeof req.body?.capabilities === 'object' && req.body.capabilities ? req.body.capabilities : {}),
      ...agentRole(resolvedRole).capabilities,
    }),
    policy,
    metadata: {
      ...(typeof req.body?.metadata === 'object' && req.body.metadata ? req.body.metadata : {}),
      // Server-resolved, never caller-asserted: the id and display name both come
      // from the row we just proved this tenant owns.
      assetId: resolvedAsset?.id || null,
      assetName: resolvedAsset?.name || null,
      assetType: resolvedAsset?.type || null,
      environment: cleanString(req.body?.environment, 80) || cleanString(req.body?.metadata?.environment, 80) || 'production',
      enrolledBy: user.id,
      /* Written AFTER the caller's metadata spread so it overwrites any
         `role` the caller supplied. This is the authoritative value; the
         agent's own claim is informational only (§41). */
      role: resolvedRole,
      roleResolvedBy: 'control-plane',
      entitlementTier: scanTypeDecision.tier,
      /* Modules this plan does not include. Surfaced in the Agent Center as
         "not included in your plan" so a dimension nobody looked at is never
         mistaken for a dimension that came back clean. */
      scanTypesDeniedByPlan: scanTypeDecision.denied,
      remediationWorkflow: REMEDIATION_WORKFLOW_STAGES,
      supportedEnvironments: SUPPORTED_REMEDIATION_ENVIRONMENTS.map((item) => item.id),
      localCollector: LOCAL_COLLECTOR_CLARIFICATION,
      securityGates: ['rbac-validation', 'tenant-admin-approval', 'change-approval', 'snapshot-before-patch', 'post-patch-validation'],
    },
    created_at: now,
    updated_at: now,
  }

  let agent: any
  if (client) {
    const { data, error } = await client.from('scanner_agents').insert(agentBase).select('*').single()
    if (error || !data) {
      jsonError(res, 500, 'AGENT_ENROLL_FAILED', error?.message || 'Agent enrollment failed')
      return
    }
    agent = data
    const policyInsert = await client.from('scanner_agent_policies').insert({
      user_id: user.id,
      agent_id: agent.id,
      name: 'Default scanner policy',
      enabled: policy.enabled,
      interval_seconds: policy.intervalSeconds,
      allowed_targets: policy.allowedTargets,
      allowed_paths: policy.allowedPaths,
      scan_types: policy.scanTypes,
      alert_threshold: policy.alertThreshold,
      metadata: {
        remediationWorkflow: REMEDIATION_WORKFLOW_STAGES,
        heartbeatSeconds: { min: 30, max: 60 },
        supportedEnvironments: SUPPORTED_REMEDIATION_ENVIRONMENTS.map((item) => item.id),
        localCollector: LOCAL_COLLECTOR_CLARIFICATION,
        executionContract: remediationExecutionContract(),
      },
    })
    if (policyInsert.error && !isMissingRuntimeTable(policyInsert.error)) {
      jsonError(res, 500, 'AGENT_POLICY_CREATE_FAILED', policyInsert.error.message || 'Agent policy creation failed')
      return
    }
  } else {
    agent = { id: randomId('agent'), ...agentBase }
    memoryStore.agents.unshift(agent)
    memoryStore.policies.unshift({ id: randomId('policy'), user_id: user.id, agent_id: agent.id, ...policy })
  }

  await recordAgentSecurityEvent(client, {
    userId: user.id,
    eventType: 'scanner_agent_enrolled',
    severity: 'success',
    message: `${agentBase.name} enrolled for ${agentBase.metadata.environment || 'tenant'} telemetry collection.`,
    assetId: typeof agentBase.metadata.assetId === 'string' ? agentBase.metadata.assetId : null,
    resourceName: agentBase.name,
    resourceType: 'scanner_agent',
    metadata: {
      source: agentBase.metadata.source || 'agent-scanner',
      agentId: agent.id,
      hostname: agentBase.hostname,
      platform: agentBase.platform,
      environment: agentBase.metadata.environment,
      policy,
      capabilities: agentBase.capabilities,
      selectedAsset: {
        id: agentBase.metadata.assetId || null,
        name: agentBase.metadata.assetName || agentBase.hostname || null,
        type: agentBase.metadata.assetType || agentBase.platform || null,
        criticality: agentBase.metadata.criticality || null,
        riskScore: agentBase.metadata.riskScore || null,
      },
    },
  })
  await recordAgentAudit(client, {
    userId: user.id,
    action: 'scanner_agent_enrolled',
    entityType: 'scanner_agent',
    entityId: agent.id,
    details: {
      source: agentBase.metadata.source || 'agent-scanner',
      agentName: agentBase.name,
      hostname: agentBase.hostname,
      platform: agentBase.platform,
      environment: agentBase.metadata.environment,
      selectedAssetId: agentBase.metadata.assetId || null,
      selectedAssetName: agentBase.metadata.assetName || null,
      ipAddress: req.ip?.replace('::ffff:', '') || null,
      userAgent: String(req.headers['user-agent'] || '').slice(0, 500),
      tokenShownOnce: true,
    },
  })

  res.json({
    data: {
      agent: { ...agent, token_hash: undefined },
      enrollment: {
        agentId: agent.id,
        agentToken: token,
        tokenWarning: 'Store this token now. It is shown once and cannot be recovered.',
      },
    },
  })
})

router.get('/agents', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  if (client) {
    const { data, error } = await client.from('scanner_agents').select('id, user_id, name, status, hostname, platform, version, capabilities, policy, last_seen_at, revoked_at, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false })
    if (error) {
      jsonError(res, 500, 'AGENTS_LOAD_FAILED', error.message)
      return
    }
    res.json({ data: { agents: data || [] } })
    return
  }
  res.json({ data: { agents: memoryStore.agents.filter((item) => item.user_id === user.id).map(({ token_hash, ...agent }) => agent) } })
})

router.post('/agents/:id/revoke', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const now = new Date().toISOString()

  /*
   * Revocation is a security control, so it must never report success it did not
   * achieve. The tenant filter alone is not enough: an id belonging to another
   * tenant (or a stale one) matched zero rows and still returned 200, so an
   * operator revoking a compromised collector saw "revoked" while the agent kept
   * running. Confirm ownership first, 404 otherwise, and report only what the
   * write actually changed.
   */
  if (client) {
    const { data: agent, error: lookupError } = await client
      .from('scanner_agents')
      .select('id, name, status, revoked_at')
      .eq('id', req.params.id)
      .eq('user_id', user.id)
      .limit(1)
      .maybeSingle()
    if (lookupError && !isMissingRuntimeTable(lookupError)) {
      jsonError(res, 500, 'AGENT_LOOKUP_FAILED', lookupError.message)
      return
    }
    if (!agent) {
      jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
      return
    }

    const { data: updated, error } = await client
      .from('scanner_agents')
      .update({ status: 'revoked', revoked_at: now, updated_at: now })
      .eq('id', req.params.id)
      .eq('user_id', user.id)
      .select('id')
    if (error) {
      jsonError(res, 500, 'AGENT_REVOKE_FAILED', error.message)
      return
    }
    if (!updated || updated.length === 0) {
      jsonError(res, 500, 'AGENT_REVOKE_FAILED', 'Revocation did not modify the agent record')
      return
    }

    await recordAgentAudit(client, {
      userId: user.id,
      action: 'scanner_agent_revoked',
      entityType: 'scanner_agent',
      entityId: req.params.id,
      details: { agentName: agent.name, revokedAt: now, previousStatus: agent.status },
    })
    publishAgentEvent(user.id, 'agent.disconnected', req.params.id, { reason: 'revoked', revokedAt: now })
  } else {
    const agent = memoryStore.agents.find((item) => item.id === req.params.id && item.user_id === user.id)
    if (!agent) {
      jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
      return
    }
    Object.assign(agent, { status: 'revoked', revoked_at: now, updated_at: now })
  }

  res.json({ data: { agentId: req.params.id, status: 'revoked', revokedAt: now } })
})

router.post('/agents/:id/token/rotate', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const now = new Date().toISOString()
  const token = generateAgentToken()
  const tokenHash = hashToken(token)

  if (client) {
    const { data: agent, error: lookupError } = await client
      .from('scanner_agents')
      .select('id, user_id, name, status, metadata')
      .eq('id', req.params.id)
      .eq('user_id', user.id)
      .limit(1)
      .maybeSingle()
    if (lookupError || !agent) {
      jsonError(res, 404, 'AGENT_NOT_FOUND', lookupError?.message || 'Agent not found')
      return
    }

    const { error } = await client
      .from('scanner_agents')
      .update({
        token_hash: tokenHash,
        status: agent.status === 'revoked' ? 'active' : agent.status,
        revoked_at: null,
        updated_at: now,
        /*
         * MERGE, never replace. This column carries the agent's role, environment,
         * assigned asset and its bounded command queue/history — writing a bare
         * `{ rotatedAt, rotatedBy }` silently wiped all of it, so rotating a token
         * turned a Migration Operator back into an unassigned collector and
         * discarded any queued work.
         */
        metadata: { ...(agent.metadata || {}), rotatedAt: now, rotatedBy: user.id },
      })
      .eq('id', req.params.id)
      .eq('user_id', user.id)
    if (error) {
      jsonError(res, 500, 'TOKEN_ROTATE_FAILED', error.message)
      return
    }

    await client.from('audit_logs').insert({
      user_id: user.id,
      action: 'scanner_agent_token_rotated',
      entity_type: 'scanner_agent',
      entity_id: req.params.id,
      details: { rotatedAt: now },
    })
  } else {
    const agent = memoryStore.agents.find((item) => item.id === req.params.id && item.user_id === user.id)
    if (!agent) {
      jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found')
      return
    }
    Object.assign(agent, { token_hash: tokenHash, revoked_at: null, updated_at: now, metadata: { ...(agent.metadata || {}), rotatedAt: now } })
  }

  res.json({
    data: {
      agentId: req.params.id,
      agentToken: token,
      tokenWarning: 'Store this token now. It is shown once and cannot be recovered.',
      rotatedAt: now,
    },
  })
})

router.delete('/agents/:id', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!

  if (client) {
    // `delete ... eq(user_id)` on someone else's id removes nothing but still
    // returned 200 and wrote an audit row claiming a deletion that never
    // happened. Confirm ownership, then report only the rows actually removed.
    const { data: deleted, error } = await client
      .from('scanner_agents')
      .delete()
      .eq('id', req.params.id)
      .eq('user_id', user.id)
      .select('id, name')
    if (error) {
      jsonError(res, 500, 'AGENT_DELETE_FAILED', error.message)
      return
    }
    if (!deleted || deleted.length === 0) {
      jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
      return
    }
    await client.from('audit_logs').insert({
      user_id: user.id,
      action: 'scanner_agent_deleted',
      entity_type: 'scanner_agent',
      entity_id: req.params.id,
      details: { deletedAt: new Date().toISOString(), agentName: deleted[0]?.name || null },
    })
  } else {
    const owned = memoryStore.agents.some((item) => item.id === req.params.id && item.user_id === user.id)
    if (!owned) {
      jsonError(res, 404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
      return
    }
    memoryStore.agents = memoryStore.agents.filter((item) => !(item.id === req.params.id && item.user_id === user.id))
    memoryStore.policies = memoryStore.policies.filter((item) => !(item.agent_id === req.params.id && item.user_id === user.id))
  }

  res.json({ data: { agentId: req.params.id, deleted: true } })
})

router.get('/agents/:id/policy', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  if (client) {
    const { data } = await client.from('scanner_agent_policies').select('*').eq('agent_id', req.params.id).eq('user_id', user.id).limit(1).maybeSingle()
    res.json({ data: { policy: data ? normalizePolicy(data) : normalizePolicy({}) } })
    return
  }
  const policy = memoryStore.policies.find((item) => item.agent_id === req.params.id && item.user_id === user.id)
  res.json({ data: { policy: normalizePolicy(policy || {}) } })
})

router.get('/agents/:id/heartbeats', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  if (client) {
    const { data, error } = await client
      .from('agent_heartbeats')
      .select('*')
      .eq('agent_id', req.params.id)
      .eq('user_id', user.id)
      .order('observed_at', { ascending: false })
      .limit(200)
    if (error) {
      jsonError(res, 500, 'HEARTBEATS_LOAD_FAILED', error.message)
      return
    }
    res.json({ data: { heartbeats: data || [] } })
    return
  }
  res.json({ data: { heartbeats: memoryStore.heartbeats.filter((item) => item.agent_id === req.params.id && item.user_id === user.id) } })
})

router.put('/agents/:id/policy', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const policy = normalizePolicy(req.body || {})
  if (client) {
    const { data: existing } = await client.from('scanner_agent_policies').select('id').eq('agent_id', req.params.id).eq('user_id', user.id).limit(1).maybeSingle()
    if (existing?.id) {
      await client.from('scanner_agent_policies').update({
        enabled: policy.enabled,
        interval_seconds: policy.intervalSeconds,
        allowed_targets: policy.allowedTargets,
        allowed_paths: policy.allowedPaths,
        scan_types: policy.scanTypes,
        alert_threshold: policy.alertThreshold,
        metadata: {
          remediationWorkflow: REMEDIATION_WORKFLOW_STAGES,
          heartbeatSeconds: { min: 30, max: 60 },
          supportedEnvironments: SUPPORTED_REMEDIATION_ENVIRONMENTS.map((item) => item.id),
          localCollector: LOCAL_COLLECTOR_CLARIFICATION,
          executionContract: remediationExecutionContract(),
        },
        updated_at: new Date().toISOString(),
      }).eq('id', existing.id).eq('user_id', user.id)
    } else {
      await client.from('scanner_agent_policies').insert({
        user_id: user.id,
        agent_id: req.params.id,
        enabled: policy.enabled,
        interval_seconds: policy.intervalSeconds,
        allowed_targets: policy.allowedTargets,
        allowed_paths: policy.allowedPaths,
        scan_types: policy.scanTypes,
        alert_threshold: policy.alertThreshold,
        metadata: {
          remediationWorkflow: REMEDIATION_WORKFLOW_STAGES,
          heartbeatSeconds: { min: 30, max: 60 },
          supportedEnvironments: SUPPORTED_REMEDIATION_ENVIRONMENTS.map((item) => item.id),
          localCollector: LOCAL_COLLECTOR_CLARIFICATION,
          executionContract: remediationExecutionContract(),
        },
      })
    }
    await client.from('scanner_agents').update({ policy, updated_at: new Date().toISOString() }).eq('id', req.params.id).eq('user_id', user.id)
  }
  res.json({ data: { policy } })
})

router.get('/alerts', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  if (client) {
    const { data } = await client.from('scanner_alerts').select('*').eq('user_id', user.id).order('created_at', { ascending: false }).limit(200)
    res.json({ data: { alerts: data || [] } })
    return
  }
  res.json({ data: { alerts: memoryStore.alerts.filter((item) => item.user_id === user.id) } })
})

router.get('/evidence', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  if (client) {
    const { data } = await client.from('scanner_evidence').select('*').eq('user_id', user.id).order('observed_at', { ascending: false }).limit(500)
    res.json({ data: { evidence: data || [] } })
    return
  }
  res.json({ data: { evidence: memoryStore.evidence.filter((item) => item.user_id === user.id) } })
})

router.get('/connectors', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  if (client) {
    const { data, error } = await client
      .from('connector_accounts')
      .select('id, user_id, provider, provider_account_id, display_name, status, scopes, capabilities, policy, last_sync_at, metadata, created_at, updated_at')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
    if (error) {
      jsonError(res, 500, 'CONNECTORS_LOAD_FAILED', error.message)
      return
    }
    res.json({ data: { connectors: data || [] } })
    return
  }
  res.json({ data: { connectors: memoryStore.connectors.filter((item) => item.user_id === user.id).map(({ token_ref, ...connector }) => connector) } })
})

router.post('/connectors', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const provider = cleanString(req.body?.provider, 100) || 'custom'
  const scopes = Array.isArray(req.body?.scopes) ? req.body.scopes.slice(0, 50).map(String) : []
  const capabilityOverrides = typeof req.body?.capabilities === 'object' && req.body.capabilities ? req.body.capabilities : {}
  const row = {
    user_id: user.id,
    provider,
    provider_account_id: cleanString(req.body?.providerAccountId || req.body?.provider_account_id, 255),
    display_name: cleanString(req.body?.displayName || req.body?.display_name, 255),
    status: 'connected',
    scopes,
    capabilities: connectorProviderCapabilities(provider, scopes, capabilityOverrides),
    policy: normalizePolicy(req.body?.policy || {}),
    metadata: sanitizeAgentMetadata({
      ...(typeof req.body?.metadata === 'object' && req.body.metadata ? req.body.metadata : {}),
      supportedEnvironments: SUPPORTED_REMEDIATION_ENVIRONMENTS.map((item) => item.id),
      localCollectorRelationship: 'Local collectors can discover and validate remote assets; connector credentials are required for remote mutations.',
      securityGates: ['least-privilege-scopes', 'rbac-validation', 'tenant-admin-approval', 'change-approval', 'snapshot-before-patch', 'post-patch-validation', 'audit-log'],
      credentialBoundary: LOCAL_COLLECTOR_CLARIFICATION.credentialBoundary,
    }),
  }
  if (client) {
    const { data, error } = await client.from('connector_accounts').insert(row).select('*').single()
    if (error) {
      jsonError(res, 500, 'CONNECTOR_CREATE_FAILED', error.message)
      return
    }
    res.json({ data: { connector: data } })
    return
  }
  const connector = { id: randomId('connector'), ...row, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
  memoryStore.connectors.unshift(connector)
  res.json({ data: { connector } })
})

router.post('/connectors/:id/evidence', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  let connector: any = null
  if (client) {
    const { data } = await client.from('connector_accounts').select('*').eq('id', req.params.id).eq('user_id', user.id).limit(1).maybeSingle()
    connector = data
  } else {
    connector = memoryStore.connectors.find((item) => item.id === req.params.id && item.user_id === user.id)
  }
  if (!connector) {
    jsonError(res, 404, 'CONNECTOR_NOT_FOUND', 'Connector account not found')
    return
  }
  const payload = Array.isArray(req.body?.evidence) ? req.body.evidence : []
  const policy = normalizePolicy(connector.policy || {})
  const normalizedEvidence = payload.slice(0, 500).map((item: any) => normalizeEvidence(item, 'connector', null, connector)).filter(Boolean) as ScannerEvidenceRecord[]
  const evidence = normalizedEvidence.filter((item) => evidenceAllowedByPolicy(item, policy, true))
  const rejectedEvidenceCount = normalizedEvidence.length - evidence.length
  if (evidence.length === 0 && normalizedEvidence.length > 0) {
    jsonError(res, 403, 'EVIDENCE_OUT_OF_POLICY', 'Uploaded connector evidence does not match this connector policy')
    return
  }
  const result = await processEvidenceBatch(client, user.id, evidence, `connector:${connector.provider}`, {
    alertThreshold: policy.alertThreshold,
  })
  res.json({ data: { ...result, rejectedEvidenceCount } })
})

router.get('/remediation/patch-options', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const jobId = cleanString(req.query.jobId, 120)
  let job: any = null
  let connectors: any[] = []

  if (client) {
    if (jobId) {
      const { data } = await client
        .from('migration_jobs')
        .select('id, name, job_type, status, target_algorithm, strategy, metadata')
        .eq('id', jobId)
        .eq('user_id', user.id)
        .limit(1)
        .maybeSingle()
      job = data || null
    }
    const { data } = await client
      .from('connector_accounts')
      .select('id, provider, display_name, status, scopes, capabilities, policy, last_sync_at, metadata, created_at, updated_at')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
    connectors = data || []
  } else {
    connectors = memoryStore.connectors.filter((item) => item.user_id === user.id).map(({ token_ref, ...connector }) => connector)
  }

  const recommendedAssetClass = job ? remediationAdapter(job) : cleanString(req.query.assetClass, 80) || 'network_protocol'
  res.json({
    data: {
      recommendedAssetClass,
      options: allPatchOptionGroups(),
      recommendedOptions: patchOptionsForAssetClass(recommendedAssetClass),
      connectors,
      job: job ? remediationJobPayload(job) : null,
    },
  })
})

router.get('/remediation/operator-actions', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const jobId = cleanString(req.query.jobId, 120)

  if (client) {
    let query = client
      .from('remediation_operator_actions')
      .select('id, user_id, migration_id, connector_account_id, action_type, asset_class, status, approval_mode, patch_plan, evidence, validation, metadata, requested_at, approved_at, applied_at, validated_at, created_at, updated_at')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(200)
    if (jobId) query = query.eq('migration_id', jobId)
    const { data, error } = await query
    if (error && !isMissingRuntimeTable(error)) {
      jsonError(res, 500, 'OPERATOR_ACTIONS_LOAD_FAILED', error.message)
      return
    }
    if (!error) {
      res.json({ data: { actions: data || [] } })
      return
    }
  }

  const actions = memoryStore.operatorActions
    .filter((item) => item.user_id === user.id && (!jobId || item.migration_id === jobId))
    .slice(0, 200)
  res.json({ data: { actions } })
})

router.get('/stream', async (req, res) => {
  const queryToken = typeof req.query.token === 'string'
    ? req.query.token
    : Array.isArray(req.query.token)
      ? String(req.query.token[0] || '')
      : ''
  const token = getToken(req) || queryToken

  if (!token) {
    return jsonError(res, 401, 'UNAUTHORIZED', 'Authentication required')
  }

  const user = await getServerUser(token)
  if (!user) {
    return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired token')
  }

  const client = createAuthClient(token) || getServiceClient()
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  })

  let closed = false
  const emitSnapshot = async () => {
    if (closed) return
    try {
      const snapshot = await buildAgentScannerSnapshot(client, user.id)
      sendAgentScannerSse(res, 'agent-scanner-sync', snapshot)
    } catch (error) {
      sendAgentScannerSse(res, 'agent-scanner-error', {
        generatedAt: new Date().toISOString(),
        message: error instanceof Error ? error.message : 'Agent scanner sync failed',
      })
    }
  }

  await emitSnapshot()
  const heartbeatTimer = setInterval(() => sendAgentScannerSse(res, 'heartbeat', { generatedAt: new Date().toISOString() }), 25_000)
  const snapshotTimer = setInterval(() => {
    void emitSnapshot()
  }, 8_000)

  req.on('close', () => {
    closed = true
    clearInterval(heartbeatTimer)
    clearInterval(snapshotTimer)
    res.end()
  })
})

router.post('/remediation/operator-actions', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const now = new Date().toISOString()
  const jobId = cleanString(req.body?.jobId || req.body?.migrationId || req.body?.migration_id, 120)
  const connectorId = cleanString(req.body?.connectorId || req.body?.connector_account_id, 120)
  const assetClass = (cleanString(req.body?.assetClass || req.body?.asset_class, 80) || 'network_protocol').replace(/-/g, '_').toLowerCase()
  const optionId = cleanString(req.body?.optionId || req.body?.option_id, 120)
  const option = patchOptionsForAssetClass(assetClass).find((item) => item.id === optionId) || patchOptionsForAssetClass(assetClass)[0]
  const actionType = cleanString(req.body?.actionType || req.body?.action_type, 120) || option.actionType
  const approvalMode = cleanString(req.body?.approvalMode || req.body?.approval_mode, 80) || 'operator_approved'
  const requestedStatus = cleanString(req.body?.status, 50) || 'planned'
  const target = cleanString(req.body?.target, 500)
  const connectorRequired = option.requiresConnector === true

  let connector: any = null
  let job: any = null
  if (client) {
    if (connectorId) {
      const { data } = await client.from('connector_accounts').select('*').eq('id', connectorId).eq('user_id', user.id).limit(1).maybeSingle()
      connector = data || null
      if (!connector) {
        jsonError(res, 404, 'CONNECTOR_NOT_FOUND', 'Connector account not found for this tenant')
        return
      }
    }
    if (jobId) {
      const { data } = await client.from('migration_jobs').select('*').eq('id', jobId).eq('user_id', user.id).limit(1).maybeSingle()
      job = data || null
      if (!job) {
        jsonError(res, 404, 'MIGRATION_JOB_NOT_FOUND', 'Migration job not found for this tenant')
        return
      }
    }
  } else {
    connector = connectorId ? memoryStore.connectors.find((item) => item.id === connectorId && item.user_id === user.id) : null
  }

  if (connectorRequired && !connectorId) {
    jsonError(res, 400, 'CONNECTOR_REQUIRED', 'This patch option requires a connector with scoped permissions')
    return
  }

  const connectorScopes = new Set((connector?.scopes || []).map((scope: string) => String(scope).toLowerCase()))
  const missingScopes = connector && Array.isArray(option.requiredScopes)
    ? option.requiredScopes.filter((scope: string) => !connectorScopes.has(scope.toLowerCase()))
    : []
  const connectorPolicy = normalizePolicy(connector?.policy || {})
  const targetAllowed = connector ? patchTargetAllowedByPolicy(target, connectorPolicy, false) : !connectorRequired
  const targetPolicyViolation = connector && target ? !targetAllowed : false
  const sdkPatchReadiness = connector ? cloudSdkPatchAdapterReadiness(connector) : null

  const patchPlan = sanitizeAgentMetadata({
    optionId: option.id,
    optionLabel: option.label,
    target,
    summary: option.summary,
    validation: option.validation,
    requiredScopes: option.requiredScopes,
    missingScopes,
    targetAllowed,
    targetPolicyViolation,
    requestedBy: user.id,
    requestedAt: now,
    workflow: REMEDIATION_WORKFLOW_STAGES,
    mandatoryQuantumStack: MANDATORY_QUANTUM_STACK_METADATA,
    mandatoryConfigValues: MANDATORY_PQC_CONFIG_VALUES,
    executionContract: option.executionContract || remediationExecutionContract(option),
    securityGates: {
      rbacValidation: true,
      tenantAdminApproval: true,
      changeApproval: true,
      approvalRole: userApprovalRole(user),
      approvedBy: null,
      rejectedBy: null,
      scheduledBy: null,
    },
    beforeStateSchema: {
      tlsVersion: 'TLS1.2',
      certificate: 'RSA-2048',
    },
    afterStateSchema: {
      tlsVersion: 'TLS1.3',
      certificate: MANDATORY_PQC_STACK.signatures.primary,
      signature: MANDATORY_PQC_STACK.signatures.hybrid,
      keyExchange: MANDATORY_PQC_STACK.tls.keyExchange,
      symmetricEncryption: MANDATORY_PQC_STACK.encryption.symmetric,
      kdf: MANDATORY_PQC_STACK.kdf.primary,
      hashing: MANDATORY_PQC_STACK.hashes,
    },
    verificationSchema: {
      migrationSuccessful: true,
      certificateValid: true,
      serviceReachable: true,
      rollbackRequired: false,
    },
    rollbackPlan: {
      configurationSnapshot: true,
      certificateBackup: true,
      keyBackupMetadata: true,
      tlsPolicySnapshot: true,
      automaticRollbackOnValidationFailure: true,
    },
    dryRun: req.body?.dryRun !== false,
    sdkPatchReadiness,
    payload: sanitizeAgentMetadata(req.body?.payload),
  })

  const row = {
    user_id: user.id,
    migration_id: jobId || null,
    connector_account_id: connectorId || null,
    action_type: actionType,
    asset_class: assetClass,
    status: missingScopes.length > 0 || targetPolicyViolation ? 'blocked' : requestedStatus,
    approval_mode: approvalMode,
    patch_plan: patchPlan,
    evidence: {},
    validation: {},
    metadata: sanitizeAgentMetadata({
      connectorProvider: connector?.provider || null,
      connectorDisplayName: connector?.display_name || null,
      jobName: job?.name || null,
      source: 'dashboard-operator-workflow',
      remediationWorkflow: REMEDIATION_WORKFLOW_STAGES,
      mandatoryQuantumStack: MANDATORY_QUANTUM_STACK_METADATA,
      executionContract: option.executionContract || remediationExecutionContract(option),
    }),
    requested_at: now,
    created_at: now,
    updated_at: now,
  }

  let action: any = null
  if (client) {
    const { data, error } = await client.from('remediation_operator_actions').insert(row).select('*').single()
    if (error && !isMissingRuntimeTable(error)) {
      jsonError(res, 500, 'OPERATOR_ACTION_CREATE_FAILED', error.message)
      return
    }
    action = data || { id: randomId('operator-action'), ...row }
    if (error && isMissingRuntimeTable(error)) memoryStore.operatorActions.unshift(action)

    await recordAgentAudit(client, {
      userId: user.id,
      action: 'remediation_operator_action_created',
      entityType: 'remediation_operator_action',
      entityId: action.id,
      details: {
        actionType,
        assetClass,
        status: action.status || row.status,
        requestedBy: user.id,
        connectorId: connectorId || null,
        target,
        missingScopes,
        targetAllowed,
        targetPolicyViolation,
        sdkPatchReadiness,
        beforeStateRequired: true,
        afterStateRequired: true,
        rollbackRequired: true,
      },
    })

    if (jobId && job) {
      const metadata = remediationJobMetadata(job)
      const actions = Array.isArray(metadata.operatorActions) ? metadata.operatorActions.slice(-19) : []
      await client.from('migration_jobs').update({
        status: job.status === 'completed' ? job.status : 'paused',
        updated_at: now,
        metadata: {
          ...metadata,
          operatorActions: [...actions, {
            id: action.id,
            actionType,
            assetClass,
            status: action.status || row.status,
            connectorId: connectorId || null,
            optionId: option.id,
            requestedAt: now,
          }],
          lastOperatorPatchAction: {
            id: action.id,
            actionType,
            assetClass,
            status: action.status || row.status,
            connectorId: connectorId || null,
            requestedAt: now,
          },
        },
      }).eq('id', jobId).eq('user_id', user.id)

      await client.from('migration_events').insert({
        user_id: user.id,
        migration_id: jobId,
        event_type: 'operator-patch-action-created',
        severity: missingScopes.length > 0 ? 'warning' : 'info',
        message: `${option.label} action ${missingScopes.length > 0 ? 'blocked by missing connector scopes' : targetPolicyViolation ? 'blocked by target policy' : 'created'} for ${job.name || 'HNDL remediation'}.`,
        metadata: { actionId: action.id, assetClass, actionType, option, connectorId, missingScopes, targetAllowed, targetPolicyViolation, sdkPatchReadiness },
        created_at: now,
      })
    }
  } else {
    action = { id: randomId('operator-action'), ...row }
    memoryStore.operatorActions.unshift(action)
  }

  res.json({ data: { action, missingScopes, option } })
})

router.post('/remediation/operator-actions/:id/status', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const now = new Date().toISOString()
  const status = (cleanString(req.body?.status, 50) || 'applied').toLowerCase()
  const allowedStatuses = new Set(['planned', 'approved', 'rejected', 'scheduled', 'blocked', 'applying', 'applied', 'validating', 'validated', 'failed', 'cancelled'])
  if (!allowedStatuses.has(status)) {
    jsonError(res, 400, 'INVALID_OPERATOR_ACTION_STATUS', 'Unsupported operator action status')
    return
  }

  let action: any = null
  if (client) {
    const { data, error } = await client
      .from('remediation_operator_actions')
      .select('*')
      .eq('id', req.params.id)
      .eq('user_id', user.id)
      .limit(1)
      .maybeSingle()
    if (error && !isMissingRuntimeTable(error)) {
      jsonError(res, 500, 'OPERATOR_ACTION_READ_FAILED', error.message)
      return
    }
    action = data || null
    if (error && isMissingRuntimeTable(error)) {
      action = memoryStore.operatorActions.find((item) => item.id === req.params.id && item.user_id === user.id) || null
    }
  } else {
    action = memoryStore.operatorActions.find((item) => item.id === req.params.id && item.user_id === user.id)
  }
  if (!action) {
    jsonError(res, 404, 'OPERATOR_ACTION_NOT_FOUND', 'Operator action not found for this tenant')
    return
  }

  let connector: any = null
  if (client && action.connector_account_id) {
    const { data } = await client.from('connector_accounts').select('*').eq('id', action.connector_account_id).eq('user_id', user.id).limit(1).maybeSingle()
    connector = data || null
  } else if (!client && action.connector_account_id) {
    connector = memoryStore.connectors.find((item) => item.id === action.connector_account_id && item.user_id === user.id) || null
  }
  const previousPatchPlan = asRecord(action.patch_plan)
  const previousSecurityGates = asRecord(previousPatchPlan.securityGates)
  const connectorPolicy = normalizePolicy(connector?.policy || {})
  const actionTarget = cleanString(previousPatchPlan.target, 500)
  const targetAllowed = connector ? patchTargetAllowedByPolicy(actionTarget, connectorPolicy, false) : true

  const payloadEvidence = Array.isArray(req.body?.evidence) ? req.body.evidence : []
  const normalizedEvidence = payloadEvidence
    .slice(0, 300)
    .map((item: any) => normalizeEvidence(item, connector ? 'connector' : 'scanner-api', null, connector))
    .filter(Boolean) as ScannerEvidenceRecord[]
  const evidence = normalizedEvidence.filter((item) => evidenceAllowedByPolicy(item, connectorPolicy, true))
  if (normalizedEvidence.length > 0 && evidence.length === 0) {
    jsonError(res, 403, 'OPERATOR_EVIDENCE_OUT_OF_POLICY', 'Submitted validation evidence is outside connector policy')
    return
  }

  let evidenceResult: Awaited<ReturnType<typeof processEvidenceBatch>> | null = null
  let validation = sanitizeAgentMetadata(req.body?.validation)
  if (evidence.length > 0) {
    evidenceResult = await processEvidenceBatch(client, user.id, evidence, connector ? `connector-remediation:${connector.provider}` : 'operator-remediation', {
      alertThreshold: connectorPolicy.alertThreshold,
    })
    const hndlRiskCount = Array.isArray(evidenceResult.scanner2?.hndlRisks) ? evidenceResult.scanner2.hndlRisks.length : 0
    validation = {
      ...validation,
      passed: hndlRiskCount === 0,
      hndlRiskRemaining: hndlRiskCount > 0,
      hndlRiskCount,
      evidenceCount: evidenceResult.evidenceCount,
      findingCount: evidenceResult.findingCount,
      scanSessionId: evidenceResult.links?.scanSessionId || null,
      validatedAt: now,
    }
  }

  const executeRequested = req.body?.execute === true || req.body?.executeConnector === true
  const executionDryRun = req.body?.dryRun === undefined ? previousPatchPlan.dryRun !== false : req.body?.dryRun !== false
  let cloudPatchResult: Awaited<ReturnType<typeof executeCloudConnectorPatch>> | null = null
  if (executeRequested || (connector && ['applied', 'applying'].includes(status))) {
    if (!targetAllowed) {
      cloudPatchResult = {
        attempted: false,
        executed: false,
        blocked: true,
        dryRun: executionDryRun,
        provider: cloudSdkPatchAdapterReadiness(connector).provider,
        adapter: `${connector?.provider || 'connector'}:${action.action_type || 'unknown'}`,
        status: 'blocked',
        reason: 'Patch target is outside this connector policy allowlist.',
        verification: {
          migrationSuccessful: false,
          certificateValid: false,
          serviceReachable: false,
          rollbackRequired: false,
          blocked: true,
        },
      }
    } else {
      cloudPatchResult = await executeCloudConnectorPatch({
        action,
        connector,
        requestedBy: user.id,
        status,
        execute: executeRequested || ['applied', 'applying'].includes(status),
        dryRun: executionDryRun,
        now,
      })
    }

    const cloudEvidence = (cloudPatchResult.evidence || [])
      .map((item: any) => normalizeEvidence(item, 'connector', null, connector))
      .filter(Boolean) as ScannerEvidenceRecord[]
    if (cloudEvidence.length > 0) {
      evidenceResult = await processEvidenceBatch(client, user.id, cloudEvidence, `connector-sdk-patch:${connector?.provider || 'cloud'}`, {
        alertThreshold: connectorPolicy.alertThreshold,
      })
    }
    validation = sanitizeAgentMetadata({
      ...validation,
      cloudSdkPatch: cloudPatchResult.verification || null,
      cloudSdkPatchStatus: cloudPatchResult.status,
      cloudSdkPatchBlocked: cloudPatchResult.blocked,
      cloudSdkPatchExecuted: cloudPatchResult.executed,
      cloudSdkDryRun: cloudPatchResult.dryRun,
      provider: cloudPatchResult.provider,
      adapter: cloudPatchResult.adapter,
      passed: validation.passed === true || (cloudPatchResult.executed && cloudPatchResult.verification?.migrationSuccessful === true),
      validatedAt: validation.validatedAt || now,
    })
  }

  let nextStatus = status === 'validated' && validation.passed !== true ? 'validating' : status
  if (cloudPatchResult?.status === 'blocked') nextStatus = 'blocked'
  if (cloudPatchResult?.status === 'failed') nextStatus = 'failed'
  if (cloudPatchResult?.status === 'dry_run') nextStatus = 'approved'
  if (cloudPatchResult?.executed) nextStatus = 'applied'
  const approvalRole = userApprovalRole(user)
  const decisionMetadata = {
    rbacValidation: true,
    tenantAdminApproval: ['approved', 'scheduled', 'rejected'].includes(nextStatus),
    changeApproval: ['approved', 'scheduled'].includes(nextStatus),
    approvalRole,
    approvedBy: nextStatus === 'approved' ? user.id : previousSecurityGates.approvedBy || null,
    rejectedBy: nextStatus === 'rejected' ? user.id : previousSecurityGates.rejectedBy || null,
    scheduledBy: nextStatus === 'scheduled' ? user.id : previousSecurityGates.scheduledBy || null,
    decisionAt: ['approved', 'scheduled', 'rejected'].includes(nextStatus) ? now : previousSecurityGates.decisionAt || null,
  }
  const updatePayload: Record<string, unknown> = {
    status: nextStatus,
    patch_plan: sanitizeAgentMetadata({
      ...previousPatchPlan,
      targetAllowed,
      sdkPatchReadiness: connector ? cloudSdkPatchAdapterReadiness(connector) : null,
      cloudSdkPatchResult: cloudPatchResult,
      beforeState: cloudPatchResult?.beforeState || previousPatchPlan.beforeState || null,
      afterState: cloudPatchResult?.afterState || previousPatchPlan.afterState || null,
      snapshot: cloudPatchResult?.snapshot || previousPatchPlan.snapshot || null,
      rollbackPlan: cloudPatchResult?.rollbackPlan || previousPatchPlan.rollbackPlan || null,
      securityGates: {
        ...previousSecurityGates,
        ...decisionMetadata,
      },
    }),
    evidence: sanitizeAgentMetadata({
      ...(action.evidence || {}),
      submittedAt: now,
      evidenceCount: evidence.length,
      payload: sanitizeAgentMetadata(req.body?.evidenceMetadata),
      cloudSdkPatchEvidence: cloudPatchResult?.evidence || null,
    }),
    validation,
    metadata: sanitizeAgentMetadata({
      ...(action.metadata || {}),
      lastStatusMessage: cleanString(req.body?.message, 1000),
      lastDecision: decisionMetadata,
      lastCloudSdkPatchResult: cloudPatchResult,
      rollbackRequired: nextStatus === 'failed' || validation?.rollbackRequired === true || validation?.passed === false,
    }),
    updated_at: now,
    ...actionStatusTimestamp(nextStatus, now),
  }

  if (client) {
    const { data, error } = await client
      .from('remediation_operator_actions')
      .update(updatePayload)
      .eq('id', req.params.id)
      .eq('user_id', user.id)
      .select('*')
      .single()
    if (error && !isMissingRuntimeTable(error)) {
      jsonError(res, 500, 'OPERATOR_ACTION_UPDATE_FAILED', error.message)
      return
    }
    action = data || { ...action, ...updatePayload }
    if (error && isMissingRuntimeTable(error)) Object.assign(action, updatePayload)

    await recordAgentAudit(client, {
      userId: user.id,
      action: `remediation_operator_action_${nextStatus}`,
      entityType: 'remediation_operator_action',
      entityId: action.id,
      details: {
        actionType: action.action_type,
        assetClass: action.asset_class,
        changedBy: user.id,
        approvalRole,
        beforeState: previousPatchPlan.beforeState || null,
        afterState: previousPatchPlan.afterState || null,
        validation,
        evidenceCount: evidence.length,
        cloudSdkPatchResult: cloudPatchResult,
        status: nextStatus,
        rollbackRequired: nextStatus === 'failed' || validation?.rollbackRequired === true || validation?.passed === false,
      },
    })

    if (action.migration_id) {
      const migrationUpdate: Record<string, unknown> = {
        updated_at: now,
        metadata: {
          ...(await client.from('migration_jobs').select('metadata').eq('id', action.migration_id).eq('user_id', user.id).limit(1).maybeSingle()).data?.metadata || {},
          lastOperatorPatchAction: {
            id: action.id,
            actionType: action.action_type,
            assetClass: action.asset_class,
            status: nextStatus,
            changedBy: user.id,
            approvalRole,
            validation,
            cloudSdkPatchResult: cloudPatchResult,
            updatedAt: now,
          },
        },
      }
      if (nextStatus === 'validated' && validation.passed === true) {
        migrationUpdate.status = 'completed'
        migrationUpdate.progress = 100
        migrationUpdate.completed_at = now
      } else if (nextStatus === 'failed') {
        migrationUpdate.status = 'failed'
      } else {
        migrationUpdate.status = 'paused'
      }
      await client.from('migration_jobs').update(migrationUpdate).eq('id', action.migration_id).eq('user_id', user.id)
      await client.from('migration_events').insert({
        user_id: user.id,
        migration_id: action.migration_id,
        event_type: `operator-patch-action-${nextStatus}`,
        severity: nextStatus === 'failed' ? 'error' : nextStatus === 'validated' ? 'success' : 'info',
        message: cleanString(req.body?.message, 1000) || `Operator patch action ${nextStatus}.`,
        metadata: { actionId: action.id, status: nextStatus, validation, evidenceResult, cloudSdkPatchResult: cloudPatchResult },
        created_at: now,
      })
    }
  } else {
    Object.assign(action, updatePayload)
  }

  res.json({
    data: {
      action,
      validation,
      cloudSdkPatchResult: cloudPatchResult,
      evidence: evidenceResult ? {
        evidenceCount: evidenceResult.evidenceCount,
        findingCount: evidenceResult.findingCount,
        scanSessionId: evidenceResult.links?.scanSessionId || null,
      } : null,
    },
  })
})

router.post('/alerts/:id/acknowledge', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const now = new Date().toISOString()
  if (client) {
    const { error } = await client.from('scanner_alerts').update({
      status: 'acknowledged',
      acknowledged_at: now,
      updated_at: now,
    }).eq('id', req.params.id).eq('user_id', user.id)
    if (error) {
      jsonError(res, 500, 'ALERT_ACK_FAILED', error.message)
      return
    }
  } else {
    const alert = memoryStore.alerts.find((item) => item.id === req.params.id && item.user_id === user.id)
    if (alert) Object.assign(alert, { status: 'acknowledged', acknowledged_at: now, updated_at: now })
  }
  res.json({ data: { alertId: req.params.id, status: 'acknowledged' } })
})

router.post('/alerts/:id/resolve', requireUserAuth, async (req: AuthedRequest, res) => {
  const client = req.client || null
  const user = req.user!
  const now = new Date().toISOString()
  if (client) {
    const { error } = await client.from('scanner_alerts').update({
      status: 'resolved',
      resolved_at: now,
      updated_at: now,
    }).eq('id', req.params.id).eq('user_id', user.id)
    if (error) {
      jsonError(res, 500, 'ALERT_RESOLVE_FAILED', error.message)
      return
    }
  } else {
    const alert = memoryStore.alerts.find((item) => item.id === req.params.id && item.user_id === user.id)
    if (alert) Object.assign(alert, { status: 'resolved', resolved_at: now, updated_at: now })
  }
  res.json({ data: { alertId: req.params.id, status: 'resolved' } })
})

router.post('/agent/heartbeat', requireAgentAuth, async (req: AgentRequest, res) => {
  const client = req.client || null
  const agent = req.agent!
  const now = new Date().toISOString()
  const telemetry = typeof req.body?.telemetry === 'object' && req.body.telemetry ? req.body.telemetry : {}

  if (client) {
    await client.from('agent_heartbeats').insert({
      user_id: agent.user_id,
      agent_id: agent.id,
      status: cleanString(req.body?.status, 50) || 'online',
      telemetry,
      ip_address: req.ip?.replace('::ffff:', '') || null,
      user_agent: String(req.headers['user-agent'] || 'qguard-agent').slice(0, 500),
      observed_at: now,
    })
    await client.from('scanner_agents').update({
      status: cleanString(req.body?.status, 50) || 'active',
      hostname: cleanString(req.body?.hostname, 255) || agent.hostname,
      platform: cleanString(req.body?.platform, 100) || agent.platform,
      version: cleanString(req.body?.version, 100) || agent.version,
      last_seen_at: now,
      updated_at: now,
      metadata: {
        ...(agent.metadata || {}),
        lastIpAddress: req.ip?.replace('::ffff:', '') || null,
        lastUserAgent: String(req.headers['user-agent'] || 'qguard-agent').slice(0, 500),
        lastTelemetry: telemetry,
      },
    }).eq('id', agent.id).eq('user_id', agent.user_id)
  } else {
    memoryStore.heartbeats.unshift({ id: randomId('heartbeat'), user_id: agent.user_id, agent_id: agent.id, status: req.body?.status || 'online', telemetry, observed_at: now })
    Object.assign(agent, { status: req.body?.status || 'active', last_seen_at: now, updated_at: now })
  }

  // A heartbeat after silence IS the connection event — the Agent Center shows
  // "Connected" only once this has actually arrived (spec §10, §28).
  const wasConnected = agent.last_seen_at
    ? Date.now() - Date.parse(agent.last_seen_at) <= HEARTBEAT_ONLINE_WINDOW_MS
    : false
  const reportedStatus = cleanString(req.body?.status, 50) || 'active'
  const reportedPhase = typeof telemetry === 'object' ? (telemetry as any).phase || null : null
  // A failure heartbeat is an ERROR event, not a routine heartbeat. Publishing
  // every heartbeat under the same name meant an open scan stream had no way to
  // learn that the run it was following had died, so the live progress card kept
  // rendering the last stage it had seen.
  const heartbeatEvent =
    reportedStatus === 'error' || reportedPhase === 'failed'
      ? 'agent.error'
      : wasConnected
        ? 'agent.heartbeat'
        : 'agent.connected'
  publishAgentEvent(agent.user_id, heartbeatEvent, agent.id, {
    status: reportedStatus,
    hostname: cleanString(req.body?.hostname, 255) || agent.hostname,
    version: cleanString(req.body?.version, 100) || agent.version,
    phase: reportedPhase,
    error: typeof telemetry === 'object' ? cleanString((telemetry as any).error, 500) : null,
  })

  res.json({ data: { status: 'accepted', observedAt: now } })
})

router.get('/agent/policy', requireAgentAuth, async (req: AgentRequest, res) => {
  const client = req.client || null
  const agent = req.agent!

  /*
   * The policy poll doubles as the command channel. Commands live in the agent
   * row's own metadata (bounded queue) rather than a parallel jobs table, so
   * tenant isolation is structural — an agent can only ever read the queue that
   * hangs off its own record. Handing them out marks them `delivered`; the agent
   * acknowledges completion through /agent/commands/:id/ack.
   */
  const queue: any[] = Array.isArray(agent.metadata?.commandQueue) ? agent.metadata.commandQueue : []
  const deliverable = queue.filter((item) => item?.status === 'queued' || item?.status === 'delivered')

  if (client && deliverable.length > 0) {
    const now = new Date().toISOString()
    const updatedQueue = queue.map((item) =>
      item?.status === 'queued' ? { ...item, status: 'delivered', deliveredAt: now } : item,
    )
    const { error } = await client
      .from('scanner_agents')
      .update({ metadata: { ...(agent.metadata || {}), commandQueue: updatedQueue }, updated_at: now })
      .eq('id', agent.id)
      .eq('user_id', agent.user_id)
    if (error && !isMissingRuntimeTable(error)) {
      console.warn('[agent-scanner] command delivery update failed:', error.message)
    }
  }

  const commands = deliverable.map((item) => ({
    id: item.id,
    type: item.type,
    queuedAt: item.queuedAt,
    payload: item.payload || {},
  }))

  if (client) {
    const { data } = await client.from('scanner_agent_policies').select('*').eq('agent_id', agent.id).eq('user_id', agent.user_id).eq('enabled', true).limit(1).maybeSingle()
    res.json({ data: { policy: data ? normalizePolicy(data) : normalizePolicy(agent.policy || {}), commands } })
    return
  }
  const policy = memoryStore.policies.find((item) => item.agent_id === agent.id && item.user_id === agent.user_id)
  res.json({ data: { policy: normalizePolicy(policy || agent.policy || {}), commands } })
})

/**
 * Command acknowledgement. Moves a delivered command through running ->
 * completed/failed and files the finished record into a bounded history so the
 * Agent Center shows real execution state instead of an optimistic "requested".
 */
router.post('/agent/commands/:id/ack', requireAgentAuth, async (req: AgentRequest, res) => {
  const client = req.client || null
  const agent = req.agent!
  const commandId = cleanString(req.params.id, 120)
  const status = cleanString(req.body?.status, 30) || ''
  if (!commandId) {
    jsonError(res, 400, 'COMMAND_REQUIRED', 'Command id is required')
    return
  }
  if (!['running', 'completed', 'failed'].includes(status)) {
    jsonError(res, 400, 'INVALID_COMMAND_STATUS', 'status must be running, completed or failed')
    return
  }

  const queue: any[] = Array.isArray(agent.metadata?.commandQueue) ? agent.metadata.commandQueue : []
  const history: any[] = Array.isArray(agent.metadata?.commandHistory) ? agent.metadata.commandHistory : []
  const command = queue.find((item) => item?.id === commandId)
  if (!command) {
    jsonError(res, 404, 'COMMAND_NOT_FOUND', 'Command is not queued for this agent')
    return
  }

  const now = new Date().toISOString()
  const errorMessage = cleanString(req.body?.error, 500)
  const result = typeof req.body?.result === 'object' && req.body.result ? req.body.result : null
  const settled = status === 'completed' || status === 'failed'
  const updated = { ...command, status, completedAt: settled ? now : null, result, error: errorMessage }

  const nextQueue = settled ? queue.filter((item) => item?.id !== commandId) : queue.map((item) => (item?.id === commandId ? updated : item))
  const nextHistory = settled ? [updated, ...history].slice(0, MAX_COMMAND_HISTORY) : history

  if (client) {
    const { error } = await client
      .from('scanner_agents')
      .update({
        metadata: { ...(agent.metadata || {}), commandQueue: nextQueue, commandHistory: nextHistory },
        updated_at: now,
      })
      .eq('id', agent.id)
      .eq('user_id', agent.user_id)
    if (error && !isMissingRuntimeTable(error)) {
      jsonError(res, 500, 'COMMAND_ACK_FAILED', error.message)
      return
    }
    await client.from('agent_heartbeats').insert({
      user_id: agent.user_id,
      agent_id: agent.id,
      status: `command:${command.type}:${status}`,
      telemetry: { commandId, type: command.type, status, result, error: errorMessage },
      observed_at: now,
    })
  }

  const eventName: AgentEventName =
    command.type === 'upgrade'
      ? status === 'completed'
        ? 'agent.upgrade_completed'
        : status === 'failed'
          ? 'agent.error'
          : 'agent.upgrade_started'
      : status === 'completed'
        ? 'agent.scan_completed'
        : status === 'failed'
          ? 'agent.error'
          : 'agent.scan_started'
  publishAgentEvent(agent.user_id, eventName, agent.id, { commandId, type: command.type, status, error: errorMessage })

  res.json({ data: { accepted: true, commandId, status, observedAt: now } })
})

/**
 * Live scan progress. Persisted as an ordered heartbeat row (so the activity
 * timeline and the Agent Center replay identically after a refresh) and pushed
 * onto the realtime bus for the open SSE streams.
 */
router.post('/agent/scan-progress', requireAgentAuth, async (req: AgentRequest, res) => {
  const client = req.client || null
  const agent = req.agent!
  const stage = cleanString(req.body?.stage, 60)
  const message = cleanString(req.body?.message, 300)
  const progressRaw = Number(req.body?.progress)
  const progress = Number.isFinite(progressRaw) ? Math.max(0, Math.min(100, Math.round(progressRaw))) : null
  if (!stage) {
    jsonError(res, 400, 'STAGE_REQUIRED', 'stage is required')
    return
  }

  const now = new Date().toISOString()
  const metadata = typeof req.body?.metadata === 'object' && req.body.metadata ? req.body.metadata : {}

  if (client) {
    const { error } = await client.from('agent_heartbeats').insert({
      user_id: agent.user_id,
      agent_id: agent.id,
      status: 'scan_progress',
      telemetry: { stage, progress, message, ...metadata },
      observed_at: now,
    })
    if (error && !isMissingRuntimeTable(error)) {
      console.warn('[agent-scanner] scan progress insert failed:', error.message)
    }
  }

  publishAgentEvent(
    agent.user_id,
    stage === 'scan_complete' ? 'agent.scan_completed' : 'agent.scan_progress',
    agent.id,
    { stage, progress, message, ...metadata },
  )

  res.json({ data: { accepted: true, stage, progress, observedAt: now } })
})

router.post('/agent/telemetry', requireAgentAuth, async (req: AgentRequest, res) => {
  const client = req.client || null
  const agent = req.agent!
  const telemetry = typeof req.body === 'object' && req.body ? req.body : {}
  if (client) {
    await client.from('agent_heartbeats').insert({
      user_id: agent.user_id,
      agent_id: agent.id,
      status: 'telemetry',
      telemetry,
      observed_at: new Date().toISOString(),
    })
  }
  res.json({ data: { status: 'accepted' } })
})

router.post('/agent/runtime-events', requireAgentAuth, async (req: AgentRequest, res) => {
  const client = req.client || null
  const agent = req.agent!
  const payload = Array.isArray(req.body?.events) ? req.body.events : []
  if (payload.length === 0) {
    jsonError(res, 400, 'NO_RUNTIME_EVENTS', 'events array is required')
    return
  }
  if (payload.length > 1000) {
    jsonError(res, 413, 'TOO_MANY_RUNTIME_EVENTS', 'A maximum of 1000 runtime events can be uploaded at once')
    return
  }

  const forbidden = payload.map((item: any) => containsForbiddenRuntimeField(item)).find(Boolean)
  if (forbidden) {
    jsonError(res, 400, 'RUNTIME_EVENT_CONTAINS_FORBIDDEN_DATA', `Runtime crypto events are metadata-only. Remove forbidden field "${forbidden}".`)
    return
  }

  const policy = normalizePolicy(agent.policy || {})
  const scanTypes = new Set(policy.scanTypes.map((item: string) => String(item).toLowerCase()))
  const runtimeAllowed = scanTypes.has('runtime') || DEFAULT_AGENT_SCAN_TYPES.some((type) => scanTypes.has(type))
  if (!runtimeAllowed) {
    jsonError(res, 403, 'RUNTIME_TELEMETRY_DISABLED', 'Runtime crypto telemetry is disabled by this agent policy')
    return
  }

  const normalized = payload
    .map((item: any) => normalizeRuntimeCryptoEvent(item, 'local-agent', agent))
    .filter(Boolean) as RuntimeCryptoEventRecord[]
  const policyAllowed = normalized.filter((event) => agentObservationInScope(runtimeEventToEvidence(event), policy, agent))
  const rejectedEventCount = normalized.length - policyAllowed.length

  // Policy filtering is a NORMAL outcome, not an agent fault. Answering a fully
  // out-of-scope batch with 403 turned routine scoping into a thrown error
  // inside the agent's scan loop: it aborted the scan mid-flight and left the
  // Agent Center's progress bar frozen at the last stage it had seen (85%).
  // The batch is now accounted for and acknowledged — nothing policy excludes
  // is persisted, and the operator is told exactly what was dropped and why.
  if (policyAllowed.length === 0) {
    if (client) {
      await client.from('agent_heartbeats').insert({
        user_id: agent.user_id,
        agent_id: agent.id,
        status: 'policy_rejected_runtime_events',
        telemetry: {
          rejectedEventCount,
          reason: 'out_of_policy',
          allowedTargets: policy.allowedTargets.length,
          allowedPaths: policy.allowedPaths.length,
        },
        observed_at: new Date().toISOString(),
      })
    }
    res.json({
      data: {
        inserted: 0,
        duplicateCount: 0,
        acceptedEventCount: 0,
        rejectedEventCount,
        outOfPolicy: true,
        reason: 'RUNTIME_EVENTS_OUT_OF_POLICY',
        message: 'No uploaded runtime event is in scope for this agent policy.',
        evidence: { evidenceCount: 0, findingCount: 0, links: [] },
      },
    })
    return
  }

  const persistence = await persistRuntimeCryptoEvents(client, agent.user_id, policyAllowed)
  const evidence = policyAllowed.map(runtimeEventToEvidence)
  const evidenceResult = await processEvidenceBatch(client, agent.user_id, evidence, `agent-runtime:${agent.name || agent.id}`, {
    alertThreshold: policy.alertThreshold,
    persistRuntimeEvents: false,
  })

  if (client) {
    await client.from('agent_heartbeats').insert({
      user_id: agent.user_id,
      agent_id: agent.id,
      status: 'runtime_events',
      telemetry: {
        acceptedRuntimeEvents: policyAllowed.length,
        insertedRuntimeEvents: persistence.inserted,
        duplicateRuntimeEvents: persistence.duplicateCount,
        rejectedEventCount,
      },
      observed_at: new Date().toISOString(),
    })
  }

  res.json({
    data: {
      ...persistence,
      acceptedEventCount: policyAllowed.length,
      rejectedEventCount,
      outOfPolicy: false,
      evidence: {
        evidenceCount: evidenceResult.evidenceCount,
        findingCount: evidenceResult.findingCount,
        links: evidenceResult.links,
      },
    },
  })
})

router.post('/agent/evidence', requireAgentAuth, async (req: AgentRequest, res) => {
  const client = req.client || null
  const agent = req.agent!
  const payload = Array.isArray(req.body?.evidence) ? req.body.evidence : []
  if (payload.length === 0) {
    jsonError(res, 400, 'NO_EVIDENCE', 'Evidence array is required')
    return
  }
  const policy = normalizePolicy(agent.policy || {})
  const normalizedEvidence = payload.slice(0, 1000).map((item: any) => normalizeEvidence(item, 'local-agent', agent)).filter(Boolean) as ScannerEvidenceRecord[]
  const evidence = normalizedEvidence.filter((item) => agentObservationInScope(item, policy, agent))
  const rejectedEvidenceCount = normalizedEvidence.length - evidence.length
  // Out-of-scope evidence is filtered, accounted for and acknowledged — never
  // turned into an error that aborts the agent's scan. See the identical note
  // on /agent/runtime-events.
  if (evidence.length === 0) {
    if (client) {
      await client.from('agent_heartbeats').insert({
        user_id: agent.user_id,
        agent_id: agent.id,
        status: 'policy_rejected_evidence',
        telemetry: {
          rejectedEvidenceCount,
          reason: 'out_of_policy',
          allowedTargets: policy.allowedTargets.length,
          allowedPaths: policy.allowedPaths.length,
        },
        observed_at: new Date().toISOString(),
      })
    }
    res.json({
      data: {
        evidenceCount: 0,
        findingCount: 0,
        links: [],
        rejectedEvidenceCount,
        outOfPolicy: true,
        reason: 'EVIDENCE_OUT_OF_POLICY',
        message: 'No uploaded evidence is in scope for this agent policy.',
      },
    })
    return
  }
  if (client && rejectedEvidenceCount > 0) {
    await client.from('agent_heartbeats').insert({
      user_id: agent.user_id,
      agent_id: agent.id,
      status: 'policy_rejected_evidence',
      telemetry: { rejectedEvidenceCount },
      observed_at: new Date().toISOString(),
    })
  }
  const result = await processEvidenceBatch(client, agent.user_id, evidence, `agent:${agent.name || agent.id}`, {
    alertThreshold: policy.alertThreshold,
  })
  res.json({ data: { ...result, rejectedEvidenceCount } })
})

router.get('/agent/remediation/jobs', requireAgentAuth, async (req: AgentRequest, res) => {
  const client = req.client || null
  const agent = req.agent!
  if (!client) {
    res.json({ data: { jobs: [], observedAt: new Date().toISOString(), reason: 'database_unavailable' } })
    return
  }

  const policy = await activePolicyForAgent(client, agent)
  if (!policy.enabled) {
    res.json({ data: { jobs: [], observedAt: new Date().toISOString(), reason: 'agent_policy_disabled' } })
    return
  }

  /*
   * Re-check the WRITE entitlement on every poll (§15, §41, §53).
   *
   * An agent enrolled as a patcher while the tenant held Pro keeps its row
   * after a downgrade — deleting a fleet on a billing change would be worse
   * than leaving it idle. What must stop immediately is the work: a tenant on
   * Basic has no plan entitlement to an agent that modifies their hosts, so the
   * job queue returns empty with the reason stated rather than silently.
   *
   * Checked here rather than only at enrolment because this is the last point
   * before a host is changed, and because it is the check a downgrade, a
   * lapsed card or a revocation all have to pass through.
   */
  const writeAccess = await agentMayWrite(client, agent, 'remediation')
  if (!writeAccess.allowed) {
    res.json({ data: { jobs: [], observedAt: new Date().toISOString(), reason: writeAccess.reason } })
    return
  }

  const now = new Date().toISOString()
  const { data: jobs, error } = await client
    .from('migration_jobs')
    .select('*')
    .eq('user_id', agent.user_id)
    .in('status', ['queued', 'awaiting_agent', 'running', 'in_progress', 'executing'])
    .order('updated_at', { ascending: true })
    .limit(25)

  if (error) {
    jsonError(res, 500, 'REMEDIATION_JOB_READ_FAILED', error.message)
    return
  }

  /*
   * Governance re-check, for the same reason the write entitlement is
   * re-checked above: this is the last point before a host is changed.
   *
   * A job can be queued while its plan is approved and claimed after the plan
   * is rejected — the operator revokes approval precisely because they want the
   * work to stop, and nothing was reading that decision here. Only plans in an
   * explicit governance state block; a job with no owning plan is unaffected.
   */
  const blockedPlanIds = await rejectedPlanIdsFor(client, agent.user_id, jobs || [])

  const claimable = (jobs || [])
    .filter((job: any) => migrationJobIsAgentExecutable(job))
    .filter((job: any) => {
      const metadata = remediationJobMetadata(job)
      const assignedAgentId = cleanString(metadata.assignedAgentId || metadata.assigned_agent_id, 120)
      return !assignedAgentId || assignedAgentId === agent.id
    })
    .filter((job: any) => !blockedPlanIds.has(planIdForJob(job)))
    .filter((job: any) => remediationJobAllowedForAgent(job, policy, agent))
    .slice(0, 5)

  const claimedJobs: any[] = []
  for (const job of claimable) {
    const metadata = remediationJobMetadata(job)
    const claimedAt = cleanString(metadata.claimedAt || metadata.claimed_at, 80) || now
    const nextMetadata = {
      ...metadata,
      assignedAgentId: agent.id,
      assignedAgentName: agent.name || agent.hostname || agent.id,
      assignedAgentHostname: agent.hostname || null,
      claimedAt,
      lastClaimedAt: now,
      executorMode: 'guarded-agent',
      executorAdapter: remediationAdapter(job),
      executorVersion: agent.version || null,
      execution: {
        ...asRecord(metadata.execution),
        agentRequired: true,
        agentDispatchStatus: 'claimed',
        sequenceState: 'agent_executing',
        claimedAt,
      },
    }

    const { error: updateError } = await client
      .from('migration_jobs')
      .update({
        status: 'running',
        progress: Math.max(1, Number(job.progress || 0)),
        started_at: job.started_at || now,
        updated_at: now,
        metadata: nextMetadata,
      })
      .eq('id', job.id)
      .eq('user_id', agent.user_id)

    if (updateError) {
      console.warn('[agent-remediation] Claim failed:', updateError.message)
      continue
    }

    await persistMigrationExecution(client, agent, job, {
      status: 'running',
      progress: Math.max(1, Number(job.progress || 0)),
      currentStep: 'Agent claimed migration package',
      metadata: {
        source: 'agent-remediation',
        claimedAt,
        agentName: agent.name || null,
        adapter: remediationAdapter(job),
      },
      now,
    })

    await persistMigrationTelemetry(client, agent, job, {
      eventType: 'agent-job-claimed',
      message: `QGuard agent ${agent.name || agent.id} claimed migration workflow.`,
      progress: Math.max(1, Number(job.progress || 0)),
      metadata: {
        agentId: agent.id,
        adapter: remediationAdapter(job),
        target: remediationTarget(job),
      },
      now,
    })

    await client.from('execution_queues').update({
      assigned_agent_id: agent.id,
      queue_status: 'claimed',
      claimed_at: now,
      updated_at: now,
      metadata: {
        source: 'agent-remediation',
        agentName: agent.name || null,
        claimedAt: now,
      },
    }).eq('migration_job_id', job.id).eq('user_id', agent.user_id).then(({ error: queueError }: any) => {
      if (queueError && !isMissingRuntimeTable(queueError)) console.warn('[agent-remediation] execution queue claim update failed:', queueError.message)
    })

    await client.from('orchestration_jobs').update({
      status: 'claimed',
      updated_at: now,
      metadata: {
        source: 'agent-remediation',
        agentId: agent.id,
        agentName: agent.name || null,
        currentStep: 'Agent claimed migration package',
      },
    }).eq('migration_job_id', job.id).eq('user_id', agent.user_id).then(({ error: orchestrationError }: any) => {
      if (orchestrationError && !isMissingRuntimeTable(orchestrationError)) console.warn('[agent-remediation] orchestration claim update failed:', orchestrationError.message)
    })

    await client.from('migration_events').insert({
      user_id: agent.user_id,
      migration_id: job.id,
      event_type: 'agent-remediation-claimed',
      severity: 'info',
      message: `QGuard agent ${agent.name || agent.id} claimed migration workflow.`,
      metadata: {
        agentId: agent.id,
        agentName: agent.name || null,
        adapter: remediationAdapter(job),
        target: remediationTarget(job),
      },
      created_at: now,
    })

    claimedJobs.push({ ...job, metadata: nextMetadata, status: 'running', started_at: job.started_at || now, updated_at: now })
  }

  await client.from('agent_heartbeats').insert({
    user_id: agent.user_id,
    agent_id: agent.id,
    status: 'remediation_poll',
    telemetry: {
      availableJobs: jobs?.length || 0,
      claimedJobs: claimedJobs.length,
      hndlCandidates: (jobs || []).filter((job: any) => remediationJobIsHndl(job)).length,
      pqcCandidates: (jobs || []).filter((job: any) => migrationJobIsAgentExecutable(job)).length,
    },
    observed_at: now,
  })

  res.json({
    data: {
      jobs: claimedJobs.map(remediationJobPayload),
      observedAt: now,
    },
  })
})

router.post('/agent/remediation/jobs/:id/event', requireAgentAuth, async (req: AgentRequest, res) => {
  const client = req.client || null
  const agent = req.agent!
  if (!client) {
    jsonError(res, 503, 'DATABASE_UNAVAILABLE', 'Remediation job execution requires the database-backed migration workflow')
    return
  }

  const { data: job, error: readError } = await client
    .from('migration_jobs')
    .select('*')
    .eq('id', req.params.id)
    .eq('user_id', agent.user_id)
    .maybeSingle()

  if (readError || !job) {
    jsonError(res, 404, 'REMEDIATION_JOB_NOT_FOUND', 'Remediation job not found for this tenant')
    return
  }
  const isHndlJob = remediationJobIsHndl(job)
  if (!migrationJobIsAgentExecutable(job)) {
    jsonError(res, 400, 'NOT_AGENT_EXECUTABLE_MIGRATION', 'Only queued PQC migration or HNDL remediation jobs can be executed by this endpoint')
    return
  }

  const policy = await activePolicyForAgent(client, agent)
  if (!policy.enabled || !remediationJobAllowedForAgent(job, policy, agent)) {
    jsonError(res, 403, 'REMEDIATION_OUT_OF_POLICY', 'This remediation job is outside the agent policy scope')
    return
  }

  const now = new Date().toISOString()
  const currentMetadata = remediationJobMetadata(job)
  const assignedAgentId = cleanString(currentMetadata.assignedAgentId || currentMetadata.assigned_agent_id, 120)
  if (assignedAgentId && assignedAgentId !== agent.id) {
    jsonError(res, 403, 'REMEDIATION_JOB_ASSIGNED', 'This remediation job is assigned to a different agent')
    return
  }

  const eventType = cleanString(req.body?.eventType || req.body?.event_type, 100) || 'agent-remediation-progress'
  const message = cleanString(req.body?.message, 1000) || (isHndlJob ? 'HNDL remediation agent event recorded.' : 'PQC migration agent event recorded.')
  const requestedStatus = (cleanString(req.body?.status, 50) || 'running').toLowerCase()
  const requestedProgress = Number(req.body?.progress)
  const progress = Number.isFinite(requestedProgress)
    ? Math.max(0, Math.min(100, Math.round(requestedProgress)))
    : Math.max(0, Math.min(100, Number(job.progress || 0)))
  const eventMetadata = sanitizeAgentMetadata(req.body?.metadata)
  let validation = sanitizeAgentMetadata(req.body?.validation)

  const payloadEvidence = Array.isArray(req.body?.evidence) ? req.body.evidence : []
  const normalizedEvidence = payloadEvidence
    .slice(0, 200)
    .map((item: any) => normalizeEvidence(item, 'local-agent', agent))
    .filter(Boolean) as ScannerEvidenceRecord[]
  // Same authorisation model as evidence/runtime uploads: an agent may always
  // report on the host it is installed on; anything it reached stays allowlisted.
  const evidence = normalizedEvidence.filter((item) => agentObservationInScope(item, policy, agent))
  const rejectedEvidenceCount = normalizedEvidence.length - evidence.length
  if (normalizedEvidence.length > 0 && evidence.length === 0) {
    jsonError(res, 403, 'REMEDIATION_EVIDENCE_OUT_OF_POLICY', 'Validation evidence does not match this agent policy')
    return
  }

  let evidenceResult: Awaited<ReturnType<typeof processEvidenceBatch>> | null = null
  if (evidence.length > 0) {
    try {
      evidenceResult = await processEvidenceBatch(client, agent.user_id, evidence, `agent-remediation:${agent.name || agent.id}`, {
        alertThreshold: policy.alertThreshold,
      })
      const hndlRiskCount = Array.isArray(evidenceResult.scanner2?.hndlRisks) ? evidenceResult.scanner2.hndlRisks.length : 0
      validation = {
        ...validation,
        passed: isHndlJob ? hndlRiskCount === 0 : validation.passed !== false,
        hndlRiskRemaining: hndlRiskCount > 0,
        hndlRiskCount,
        evidenceCount: evidenceResult.evidenceCount,
        findingCount: evidenceResult.findingCount,
        scanSessionId: evidenceResult.links?.scanSessionId || null,
        quantumReadiness: evidenceResult.scanner2?.quantumReadiness || null,
        validatedAt: now,
      }
    } catch (error) {
      jsonError(res, 500, 'REMEDIATION_EVIDENCE_PROCESS_FAILED', (error as Error).message)
      return
    }
  }

  if (requestedStatus === 'completed') {
    const hndlValidated = validation.passed === true && validation.hndlRiskRemaining === false && Boolean(evidenceResult)
    const pqcValidated = validationPassed(validation) || Boolean(evidenceResult)
    if ((isHndlJob && !hndlValidated) || (!isHndlJob && !pqcValidated)) {
      jsonError(res, 409, isHndlJob ? 'REMEDIATION_VALIDATION_REQUIRED' : 'MIGRATION_VALIDATION_REQUIRED', isHndlJob ? 'Completion requires fresh validation evidence proving no active HNDL risk remains' : 'Completion requires agent validation or evidence for the PQC migration job')
      return
    }
  }

  let nextStatus = job.status || 'running'
  if (['running', 'in_progress', 'executing', 'validating', 'planned'].includes(requestedStatus)) nextStatus = 'running'
  if (['blocked', 'manual_required', 'paused', 'requires_manual_change'].includes(requestedStatus)) nextStatus = 'paused'
  if (requestedStatus === 'failed') nextStatus = 'failed'
  if (requestedStatus === 'completed') nextStatus = 'completed'

  const eventRecord = {
    eventType,
    status: requestedStatus,
    progress,
    message,
    at: now,
    agentId: agent.id,
    adapter: remediationAdapter(job),
  }
  const recentEvents = Array.isArray(currentMetadata.executorEvents)
    ? currentMetadata.executorEvents.slice(-19)
    : []
  const nextMetadata = {
    ...currentMetadata,
    assignedAgentId: agent.id,
    assignedAgentName: agent.name || agent.hostname || agent.id,
    assignedAgentHostname: agent.hostname || null,
    executorMode: 'guarded-agent',
    executorAdapter: remediationAdapter(job),
    executorVersion: agent.version || null,
    executorState: {
      status: requestedStatus,
      progress,
      currentStep: message,
      lastUpdatedAt: now,
      evidenceCount: evidence.length,
      rejectedEvidenceCount,
    },
    lastRemediationState: {
      beforeState: eventMetadata.beforeState || currentMetadata.lastRemediationState?.beforeState || null,
      afterState: eventMetadata.afterState || eventMetadata.failedAfterState || currentMetadata.lastRemediationState?.afterState || null,
      verification: eventMetadata.verification || currentMetadata.lastRemediationState?.verification || null,
      rollback: eventMetadata.rollback || currentMetadata.lastRemediationState?.rollback || null,
    },
    lastExecutorEvent: eventRecord,
    lastValidation: validation,
    lastEvidenceResult: evidenceResult ? {
      evidenceCount: evidenceResult.evidenceCount,
      findingCount: evidenceResult.findingCount,
      scanSessionId: evidenceResult.links?.scanSessionId || null,
    } : currentMetadata.lastEvidenceResult || null,
    executorEvents: [...recentEvents, eventRecord],
  }

  const updatePayload: Record<string, unknown> = {
    status: nextStatus,
    progress: nextStatus === 'completed' ? 100 : progress,
    started_at: job.started_at || now,
    updated_at: now,
    metadata: nextMetadata,
  }
  if (nextStatus === 'completed') updatePayload.completed_at = now

  const { error: updateError } = await client
    .from('migration_jobs')
    .update(updatePayload)
    .eq('id', job.id)
    .eq('user_id', agent.user_id)

  if (updateError) {
    jsonError(res, 500, 'REMEDIATION_JOB_UPDATE_FAILED', updateError.message)
    return
  }

  await persistMigrationExecution(client, agent, job, {
    status: nextStatus,
    progress: Number(updatePayload.progress || progress),
    currentStep: message,
    metadata: {
      ...eventMetadata,
      source: 'agent-remediation',
      agentName: agent.name || null,
      adapter: remediationAdapter(job),
      validation,
      evidenceCount: evidence.length,
      rejectedEvidenceCount,
    },
    now,
  })

  await persistMigrationTelemetry(client, agent, job, {
    eventType,
    message,
    progress: Number(updatePayload.progress || progress),
    metadata: {
      ...eventMetadata,
      status: requestedStatus,
      validation,
      evidenceCount: evidence.length,
      rejectedEvidenceCount,
    },
    now,
  })

  if (Object.keys(validation).length > 0 || evidenceResult) {
    await persistMigrationValidation(client, agent, job, {
      validation,
      evidence: {
        evidenceCount: evidenceResult?.evidenceCount ?? evidence.length,
        findingCount: evidenceResult?.findingCount ?? 0,
        scanSessionId: evidenceResult?.links?.scanSessionId || null,
      },
      status: validationPassed(validation) ? 'passed' : requestedStatus === 'completed' ? 'blocked' : 'recorded',
      type: isHndlJob ? 'hndl-risk-clearance' : 'pqc-migration-validation',
      metadata: {
        eventType,
        agentName: agent.name || null,
        adapter: remediationAdapter(job),
      },
      now,
    })
  }

  await client.from('execution_queues').update({
    queue_status: nextStatus === 'completed' ? 'completed' : nextStatus === 'failed' ? 'failed' : nextStatus === 'paused' ? 'paused' : 'executing',
    assigned_agent_id: agent.id,
    claimed_at: currentMetadata.claimedAt || now,
    updated_at: now,
    metadata: {
      source: 'agent-remediation',
      eventType,
      status: nextStatus,
      progress: updatePayload.progress,
      agentName: agent.name || null,
    },
  }).eq('migration_job_id', job.id).eq('user_id', agent.user_id).then(({ error: queueError }: any) => {
    if (queueError && !isMissingRuntimeTable(queueError)) console.warn('[agent-remediation] execution queue status update failed:', queueError.message)
  })

  await client.from('orchestration_jobs').update({
    status: nextStatus,
    updated_at: now,
    metadata: {
      source: 'agent-remediation',
      eventType,
      currentStep: message,
      progress: updatePayload.progress,
      agentId: agent.id,
      agentName: agent.name || null,
    },
  }).eq('migration_job_id', job.id).eq('user_id', agent.user_id).then(({ error: orchestrationError }: any) => {
    if (orchestrationError && !isMissingRuntimeTable(orchestrationError)) console.warn('[agent-remediation] orchestration status update failed:', orchestrationError.message)
  })

  await client.from('migration_events').insert({
    user_id: agent.user_id,
    migration_id: job.id,
    event_type: eventType,
    severity: remediationEventSeverity(requestedStatus),
    message,
    metadata: {
      ...eventMetadata,
      agentId: agent.id,
      adapter: remediationAdapter(job),
      status: requestedStatus,
      progress,
      validation,
      evidenceCount: evidence.length,
      rejectedEvidenceCount,
    },
    created_at: now,
  })

  await recordAgentAudit(client, {
    userId: agent.user_id,
    action: `agent_remediation_${requestedStatus}`,
    entityType: 'migration_job',
    entityId: job.id,
    details: {
      agentId: agent.id,
      agentName: agent.name || null,
      eventType,
      status: requestedStatus,
      progress,
      beforeState: eventMetadata.beforeState || null,
      afterState: eventMetadata.afterState || eventMetadata.failedAfterState || null,
      verification: eventMetadata.verification || validation || null,
      rollback: eventMetadata.rollback || null,
      validation,
      evidenceCount: evidence.length,
      rejectedEvidenceCount,
    },
  })

  res.json({
    data: {
      jobId: job.id,
      status: nextStatus,
      progress: updatePayload.progress,
      validation,
      evidence: evidenceResult ? {
        evidenceCount: evidenceResult.evidenceCount,
        findingCount: evidenceResult.findingCount,
        scanSessionId: evidenceResult.links?.scanSessionId || null,
      } : null,
      observedAt: now,
    },
  })
})

let schedulerStarted = false
export function startAgentScannerScheduler() {
  if (schedulerStarted) return
  schedulerStarted = true
  setInterval(async () => {
    const client = getServiceClient()
    if (!client) return
    const cutoffMs = Date.now() - 15 * 60 * 1000
    const { data: agents } = await client.from('scanner_agents').select('*').eq('status', 'active')
    for (const agent of agents || []) {
      const lastActivityMs = Date.parse(agent.last_seen_at || agent.created_at || agent.updated_at || '')
      if (Number.isFinite(lastActivityMs) && lastActivityMs > cutoffMs) continue

      const { data: existingAlert } = await client
        .from('scanner_alerts')
        .select('id')
        .eq('user_id', agent.user_id)
        .eq('agent_id', agent.id)
        .eq('category', 'agent-heartbeat')
        .eq('status', 'open')
        .limit(1)
        .maybeSingle()

      await client.from('scanner_agents').update({ status: 'offline', updated_at: new Date().toISOString() }).eq('id', agent.id).eq('user_id', agent.user_id)
      if (existingAlert?.id) continue

      await client.from('scanner_alerts').insert({
        user_id: agent.user_id,
        agent_id: agent.id,
        severity: 'moderate',
        category: 'agent-heartbeat',
        title: `Scanner agent offline: ${agent.name}`,
        message: `Agent has not sent a heartbeat since ${agent.last_seen_at || agent.created_at || 'initial enrollment'}.`,
        recommendation: 'Verify the local scanner service is running and has outbound HTTPS access to QGuard.',
        status: 'open',
        metadata: { lastSeenAt: agent.last_seen_at, enrolledAt: agent.created_at },
      })
    }

    const staleConnectorCutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
    const { data: connectors } = await client
      .from('connector_accounts')
      .select('*')
      .eq('status', 'connected')
      .or(`last_sync_at.is.null,last_sync_at.lt.${staleConnectorCutoff}`)

    for (const connector of connectors || []) {
      const { data: existingAlert } = await client
        .from('scanner_alerts')
        .select('id')
        .eq('user_id', connector.user_id)
        .eq('connector_account_id', connector.id)
        .eq('category', 'connector-sync')
        .eq('status', 'open')
        .limit(1)
        .maybeSingle()
      if (existingAlert?.id) continue

      await client.from('scanner_alerts').insert({
        user_id: connector.user_id,
        connector_account_id: connector.id,
        severity: 'low',
        category: 'connector-sync',
        title: `Connector needs fresh evidence: ${connector.display_name || connector.provider}`,
        message: `Connector has not synchronized cryptographic evidence in the last 24 hours.`,
        recommendation: 'Run the connector sync or verify connector authorization and network access.',
        status: 'open',
        metadata: { lastSyncAt: connector.last_sync_at, provider: connector.provider },
      })
    }
  }, 60_000).unref?.()
}

export default router
