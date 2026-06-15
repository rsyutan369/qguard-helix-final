import { randomUUID } from 'crypto'
import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildTenantTelemetrySync } from './tenant-telemetry-sync'
import type {
  PQAuthAlgorithmExposure,
  PQAuthCompatibilitySurface,
  PQAuthCountRow,
  PQAuthMode,
  PQAuthRuntimeMetric,
  PQAuthSignal,
  PQAuthSnapshot,
  PQAuthSourceHealth,
} from '@/types/pqauth-dashboard'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

const MODES = new Set<PQAuthMode>([
  'overview',
  'discovery',
  'trust-graph',
  'token-intelligence',
  'exposure-analysis',
  'compatibility',
  'digital-twin',
  'migration-center',
  'runtime-telemetry',
  'compliance',
  'qkms',
])

const ONE_DAY_MS = 24 * 60 * 60 * 1000
const SOURCE_STALE_MS = ONE_DAY_MS

const PROVIDER_PATTERNS = [
  ['keycloak', 'Keycloak', 'OAuth/OIDC Provider'],
  ['auth0', 'Auth0', 'OAuth/OIDC Provider'],
  ['okta', 'Okta', 'OAuth/OIDC Provider'],
  ['entra|azure active directory|aad', 'Microsoft Entra ID', 'OIDC/SAML Provider'],
  ['ping identity|pingfederate|pingone', 'Ping Identity', 'Federation Provider'],
  ['forgerock|openam', 'ForgeRock', 'Identity Platform'],
  ['cognito', 'AWS Cognito', 'Cloud IdP'],
  ['google identity|google oauth|accounts\\.google', 'Google Identity', 'Cloud IdP'],
  ['custom oauth|oauth provider|authorization server', 'Custom OAuth Provider', 'Authorization Server'],
] as const

const GATEWAY_PATTERNS = [
  ['kong', 'Kong', 'API Gateway'],
  ['apigee', 'Apigee', 'API Gateway'],
  ['nginx', 'NGINX', 'Reverse Proxy'],
  ['f5|big-ip', 'F5', 'Load Balancer'],
  ['azure api management|apim', 'Azure API Management', 'API Gateway'],
  ['gateway|proxy|waf|service mesh|ingress', 'Gateway / WAF / Mesh', 'Policy Enforcement'],
] as const

const SERVICE_PATTERNS = [
  ['jwt issuer|issuer|jwks', 'JWT Issuers', 'Signing Authority'],
  ['token validator|validator|introspection|verification', 'Token Validators', 'Verification Service'],
  ['authorization server|authz server', 'Authorization Servers', 'OAuth Core'],
  ['resource server|api server|microservice', 'Resource Servers', 'Protected API'],
  ['certificate|x509|pki|ca\\b|trust anchor', 'Certificates', 'Trust Material'],
] as const

const FLOW_PATTERNS = [
  ['oauth|authorization code|client credentials|device code', 'OAuth 2.0', 'Authorization Flow'],
  ['oidc|openid|id token', 'OpenID Connect', 'Identity Flow'],
  ['saml', 'SAML', 'Federation Flow'],
  ['jwt|jws|jwe|opaque token|refresh token|access token', 'JWT / Token', 'Token Flow'],
] as const

const ALGORITHM_PATTERNS = [
  { id: 'rsa', label: 'RSA', family: 'Classical public-key', regex: /\bRSA(?:[-_\s]?(1024|2048|3072|4096))?\b|\bRS(256|384|512)\b/i, replacement: 'ML-DSA for signatures; ML-KEM for key establishment', risk: 'Shor-vulnerable' },
  { id: 'ecc', label: 'ECC', family: 'Elliptic curve', regex: /\bECC\b|\bP-(256|384|521)\b|\bsecp(256|384|521)|prime256v1/i, replacement: 'ML-DSA or hybrid certificate profiles', risk: 'Shor-vulnerable' },
  { id: 'ecdsa', label: 'ECDSA', family: 'JWT / certificate signatures', regex: /\bECDSA\b|\bES(256|384|512)\b/i, replacement: 'ML-DSA token signing', risk: 'Shor-vulnerable' },
  { id: 'eddsa', label: 'EdDSA', family: 'JWT signatures', regex: /\bEdDSA\b|\bEd25519\b|\bEd448\b/i, replacement: 'ML-DSA token signing', risk: 'Quantum transition required' },
  { id: 'dh', label: 'DH', family: 'Key agreement', regex: /\bDH\b|\bdiffie[-\s]?hellman\b/i, replacement: 'ML-KEM or hybrid TLS KEX', risk: 'Shor-vulnerable' },
  { id: 'ecdh', label: 'ECDH', family: 'Key agreement', regex: /\bECDH\b|\bX25519\b|\bX448\b/i, replacement: 'ML-KEM hybrid KEX', risk: 'Shor-vulnerable' },
] as const

const COMPATIBILITY_SURFACES = [
  { id: 'apps', label: 'Applications', regex: /application|frontend|spa|service|client/i, icon: 'Boxes' },
  { id: 'apis', label: 'APIs', regex: /api|resource server|endpoint|rest|graphql/i, icon: 'Globe' },
  { id: 'mobile', label: 'Mobile Apps', regex: /mobile|ios|android/i, icon: 'Fingerprint' },
  { id: 'gateways', label: 'Gateways / WAFs', regex: /gateway|waf|proxy|ingress|nginx|kong|apigee|f5/i, icon: 'Network' },
  { id: 'mesh', label: 'Service Meshes', regex: /mesh|sidecar|istio|linkerd|envoy/i, icon: 'Workflow' },
  { id: 'cloud', label: 'Cloud Platforms', regex: /aws|azure|gcp|cloud|cognito|entra/i, icon: 'Cpu' },
] as const

const COMPLIANCE_FRAMEWORKS = [
  'NIST CSF',
  'NIST SP 800-208',
  'NIST IR 8547',
  'NSA CNSA 2.0',
  'PCI-DSS',
  'ISO 27001',
  'SOC 2',
  'FedRAMP',
] as const

function tokenFromRequest(req: Request) {
  const headerToken = getToken(req)
  if (headerToken) return headerToken
  const queryToken = req.query.token
  return typeof queryToken === 'string' && queryToken.length > 0 ? queryToken : null
}

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = tokenFromRequest(req)
  if (!token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  const user = await getServerUser(token)
  if (!user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  }

  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}

function recordOf(value: unknown): Record<string, unknown> {
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}
    } catch {
      return {}
    }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function textValue(value: unknown, fallback = '') {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

function numberValue(value: unknown, fallback = 0) {
  const number = Number(value)
  return Number.isFinite(number) ? number : fallback
}

function dateMs(value: unknown) {
  const ms = new Date(String(value || '')).getTime()
  return Number.isFinite(ms) ? ms : 0
}

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
}

function rowTimestamp(row: any) {
  return row?.observed_at
    || row?.processed_at
    || row?.completed_at
    || row?.started_at
    || row?.last_seen_at
    || row?.updated_at
    || row?.discovered_at
    || row?.created_at
    || row?.timestamp
}

function clamp(value: number, min = 0, max = 100) {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, Math.round(value)))
}

function percentOf(value: number, total: number) {
  return total > 0 ? clamp((value / total) * 100) : 0
}

function titleCase(value: unknown, fallback = 'PQAuth Signal') {
  const text = String(value || fallback).replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
  return text.replace(/\b\w/g, (char) => char.toUpperCase()) || fallback
}

function severityRank(value: unknown) {
  const lower = String(value || '').toLowerCase()
  if (lower.includes('critical')) return 4
  if (lower.includes('high') || lower.includes('error') || lower.includes('failed')) return 3
  if (lower.includes('medium') || lower.includes('moderate') || lower.includes('warning')) return 2
  if (lower.includes('low') || lower.includes('info')) return 1
  return 0
}

function normalizeJobStatus(value: unknown) {
  const status = String(value || '').toLowerCase()
  if (/complete|success|done/.test(status)) return 'completed'
  if (/fail|error|blocked|cancel/.test(status)) return 'failed'
  if (/running|progress|active|queued|pending|scheduled/.test(status)) return 'running'
  return status || 'pending'
}

function isPqcAlgorithm(value: string) {
  return /ml-kem|ml_dsa|ml-dsa|slh-dsa|slh_dsa|sphincs|kyber|dilithium|falcon|bike|hqc|ntru|hybrid|pqc|post.quantum/i.test(value)
}

function isClassicalVulnerable(value: string, keySize = 0) {
  const text = `${value} ${keySize}`.toLowerCase()
  if (/rsa[_ -]?(1024|2048)?|ecdh|ecdsa|ecc|p-?256|p-?384|p-?521|secp|prime256v1|ed25519|ed448|diffie|dh\b/.test(text)) return true
  return /rsa/.test(text) && (!keySize || keySize < 3072)
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`PQAuth ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`PQAuth ${table} query failed:`, error?.message || error)
    return []
  }
}

function rowText(row: any) {
  return Object.values(row || {})
    .map((value) => {
      if (value == null) return ''
      if (typeof value === 'object') return JSON.stringify(value).slice(0, 500)
      return String(value)
    })
    .join(' ')
}

function rowLabel(row: any, fallback = 'Identity signal') {
  const metadata = recordOf(row?.metadata || row?.metadata_json || row?.details)
  return textValue(
    row?.name,
    textValue(
      row?.title,
      textValue(
        row?.asset_name,
        textValue(row?.resource_name, textValue(metadata.name, textValue(row?.target, textValue(row?.host, fallback)))),
      ),
    ),
  )
}

function normalizeDisplayRow(row: any, sourceTable: string, originService: string, correlationId: string) {
  const metadata = recordOf(row?.metadata || row?.metadata_json || row?.details)
  const id = textValue(row?.id, `${sourceTable}:${rowLabel(row)}`)
  return {
    ...row,
    id,
    name: rowLabel(row, id),
    detail: textValue(row?.detail, textValue(row?.message, textValue(row?.description, textValue(row?.evidence, titleCase(row?.event_type || row?.finding_type || sourceTable))))),
    sourceTable,
    originService,
    assetId: textValue(row?.asset_id, textValue(metadata.assetId || metadata.asset_id, '')) || null,
    telemetryId: id,
    correlationId,
    lastUpdated: rowTimestamp(row),
  }
}

function withLineage(table: string, rows: any[], originService: string, correlationId: string) {
  return (rows || []).map((row) => normalizeDisplayRow(row, table, originService, correlationId))
}

function dedupeRows(rows: any[]) {
  const byId = new Map<string, any>()
  for (const row of rows) {
    const key = `${row.sourceTable || 'source'}:${row.id || row.telemetryId || rowLabel(row)}`
    const existing = byId.get(key)
    if (!existing || dateMs(row.lastUpdated) > dateMs(existing.lastUpdated)) byId.set(key, row)
  }
  return [...byId.values()]
}

function countMatches(rows: any[], regex: RegExp) {
  return rows.reduce((count, row) => count + (regex.test(rowText(row)) ? 1 : 0), 0)
}

function matchedTables(rows: any[], regex: RegExp) {
  return Array.from(new Set(rows.filter((row) => regex.test(rowText(row))).map((row) => String(row.sourceTable || 'unknown'))))
}

function latestForRows(rows: any[]) {
  return latestDate(...rows.map(rowTimestamp), ...rows.map((row) => row.lastUpdated))
}

function collectSignals(rows: any[], patterns: readonly (readonly [string, string, string])[]): PQAuthSignal[] {
  return patterns
    .map(([pattern, label, category]) => {
      const regex = new RegExp(pattern, 'i')
      const matches = rows.filter((row) => regex.test(rowText(row)))
      return {
        id: label.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
        label,
        category,
        count: matches.length,
        sourceTables: Array.from(new Set(matches.map((row) => String(row.sourceTable || 'unknown')))),
        latestAt: latestForRows(matches),
      }
    })
    .filter((signal) => signal.count > 0)
}

function sourceHealth(label: string, table: string, rows: any[], staleAfterMs = SOURCE_STALE_MS): PQAuthSourceHealth {
  const latestAt = latestDate(...(rows || []).map(rowTimestamp))
  const latestMs = dateMs(latestAt)
  const count = (rows || []).length
  const status = count === 0
    ? 'waiting'
    : latestMs && Date.now() - latestMs <= staleAfterMs
      ? 'live'
      : 'stale'

  return {
    id: table,
    label,
    table,
    count,
    latestAt,
    status,
    percent: status === 'live' ? 100 : status === 'stale' ? 45 : 0,
  }
}

function buildAlgorithms(rows: any[]): PQAuthAlgorithmExposure[] {
  return ALGORITHM_PATTERNS
    .map((algorithm) => {
      const matches = rows.filter((row) => algorithm.regex.test(rowText(row)))
      return {
        id: algorithm.id,
        label: algorithm.label,
        family: algorithm.family,
        replacement: algorithm.replacement,
        risk: algorithm.risk,
        count: matches.length,
        sourceTables: Array.from(new Set(matches.map((row) => String(row.sourceTable || 'unknown')))),
        latestAt: latestForRows(matches),
      }
    })
    .filter((algorithm) => algorithm.count > 0)
}

function tokenSize(row: any) {
  const metadata = recordOf(row.metadata || row.metadata_json || row.details)
  const candidates = [
    row.token_size,
    row.tokenSize,
    row.jwt_size,
    row.jwtSize,
    row.size,
    row.header_size && row.payload_size && row.signature_size
      ? numberValue(row.header_size) + numberValue(row.payload_size) + numberValue(row.signature_size)
      : undefined,
    metadata.token_size,
    metadata.tokenSize,
    metadata.jwt_size,
    metadata.totalTokenSize,
  ]
  const found = candidates.map((value) => numberValue(value, 0)).find((value) => value > 0)
  return found || 0
}

function algorithmFromRow(row: any) {
  const metadata = recordOf(row.metadata || row.metadata_json || row.details)
  return textValue(
    row.algorithm,
    textValue(
      row.signing_algorithm,
      textValue(row.alg, textValue(metadata.algorithm, textValue(metadata.alg, rowText(row)))),
    ),
  )
}

function pqcSignatureSizeFor(algorithm: string) {
  if (/es256|p-?256|ecdsa/i.test(algorithm)) return { target: 'ML-DSA-44', size: 2420 }
  if (/rs512|rsa-4096|es512|p-?521/i.test(algorithm)) return { target: 'ML-DSA-87', size: 4627 }
  return { target: 'ML-DSA-65', size: 3309 }
}

function currentSignatureSizeFor(algorithm: string, fallbackSize: number) {
  if (/es256|es384|es512|eddsa|ed25519|ed448/i.test(algorithm)) return fallbackSize || 64
  if (/rs512|rsa-4096/i.test(algorithm)) return fallbackSize || 512
  if (/rs256|rs384|rsa/i.test(algorithm)) return fallbackSize || 256
  return fallbackSize || 0
}

function buildTokenImpacts(tokenRows: any[]) {
  return tokenRows
    .filter((row) => /jwt|jws|jwe|token|rs256|rs384|rs512|es256|es384|es512|eddsa|rsa|ecdsa/i.test(rowText(row)))
    .slice(0, 12)
    .map((row, index) => {
      const algorithm = algorithmFromRow(row)
      const currentSize = currentSignatureSizeFor(algorithm, tokenSize(row))
      const target = pqcSignatureSizeFor(algorithm)
      const expansion = currentSize > 0 ? Number((target.size / currentSize).toFixed(1)) : 0
      return {
        id: `${row.sourceTable || 'token'}:${row.id || index}`,
        current: algorithm && algorithm.length < 80 ? algorithm : 'Discovered token signature',
        currentSize,
        target: target.target,
        pqcSize: target.size,
        expansion,
        risk: expansion >= 20 ? 'Header, proxy, cookie, and mobile limit review' : expansion >= 8 ? 'Gateway and browser limit review' : 'Compatibility validation required',
        projected: true,
        sourceTable: String(row.sourceTable || 'unknown'),
        telemetryId: textValue(row.telemetryId || row.id, '') || null,
        latestAt: rowTimestamp(row),
      }
    })
}

function countAssetsForRows(rows: any[]) {
  const ids = new Set<string>()
  for (const row of rows) {
    const assetId = textValue(row.asset_id, textValue(row.assetId, textValue(row.assetId, '')))
    if (assetId) ids.add(assetId)
  }
  return ids.size || rows.length
}

function buildTrustGraph(input: {
  providers: PQAuthSignal[]
  gateways: PQAuthSignal[]
  authServices: PQAuthSignal[]
  tokenRows: any[]
  dependencies: any[]
  certificates: any[]
  keys: any[]
  assets: any[]
  relationships: any[]
  correlationId: string
}) {
  const nodes = []
  const edges = []
  const subjectCount = input.assets.length
  if (subjectCount) {
    nodes.push({
      id: 'subjects',
      label: 'Users / Machines / Apps',
      detail: `${subjectCount} tenant asset(s)`,
      x: 7,
      y: 38,
      color: '#22D3EE',
      icon: 'UserCheck',
      sourceTable: 'assets',
      assetId: null,
      correlationId: input.correlationId,
      latestAt: latestForRows(input.assets),
    })
  }
  if (input.providers.length) {
    nodes.push({
      id: 'provider',
      label: input.providers[0].label,
      detail: `${input.providers.length} provider type(s)`,
      x: 25,
      y: 18,
      color: '#2478FF',
      icon: 'Fingerprint',
      sourceTable: input.providers[0].sourceTables[0] || 'discovery',
      assetId: null,
      correlationId: input.correlationId,
      latestAt: input.providers[0].latestAt,
    })
  }
  if (input.tokenRows.length || input.authServices.length) {
    nodes.push({
      id: 'issuer',
      label: input.authServices.find((row) => /issuer/i.test(row.label))?.label || 'JWT Issuer',
      detail: `${input.tokenRows.length} token signal(s)`,
      x: 45,
      y: 38,
      color: '#FBBF24',
      icon: 'KeyRound',
      sourceTable: input.tokenRows[0]?.sourceTable || input.authServices[0]?.sourceTables[0] || 'runtime',
      assetId: input.tokenRows[0]?.assetId || null,
      correlationId: input.correlationId,
      latestAt: latestForRows(input.tokenRows),
    })
  }
  if (input.gateways.length) {
    nodes.push({
      id: 'gateway',
      label: input.gateways[0].label,
      detail: `${input.gateways.length} gateway type(s)`,
      x: 65,
      y: 18,
      color: '#8B5CF6',
      icon: 'Network',
      sourceTable: input.gateways[0].sourceTables[0] || 'discovery',
      assetId: null,
      correlationId: input.correlationId,
      latestAt: input.gateways[0].latestAt,
    })
  }
  if (input.dependencies.length) {
    nodes.push({
      id: 'resource',
      label: 'APIs / Resource Servers',
      detail: `${input.dependencies.length} dependency row(s)`,
      x: 84,
      y: 38,
      color: '#F97316',
      icon: 'Globe',
      sourceTable: input.dependencies[0]?.sourceTable || 'asset_relationships',
      assetId: input.dependencies[0]?.assetId || null,
      correlationId: input.correlationId,
      latestAt: latestForRows(input.dependencies),
    })
  }
  if (input.certificates.length || input.keys.length) {
    nodes.push({
      id: 'trust-material',
      label: 'Certificates / Keys',
      detail: `${input.certificates.length + input.keys.length} trust material row(s)`,
      x: 50,
      y: 76,
      color: '#14B8A6',
      icon: 'Database',
      sourceTable: input.certificates[0]?.sourceTable || input.keys[0]?.sourceTable || 'certificates',
      assetId: input.certificates[0]?.assetId || input.keys[0]?.assetId || null,
      correlationId: input.correlationId,
      latestAt: latestForRows([...input.certificates, ...input.keys]),
    })
  }

  const addEdge = (from: string, to: string, label: string, sourceTable: string) => {
    if (!nodes.some((node) => node.id === from) || !nodes.some((node) => node.id === to)) return
    edges.push({ id: `${from}-${to}`, from, to, label, sourceTable, correlationId: input.correlationId })
  }
  addEdge('subjects', 'provider', 'OIDC / SAML', 'auth_events')
  addEdge('provider', 'issuer', 'JWT / JWS', 'runtime_crypto_events')
  addEdge('issuer', 'gateway', 'verify', 'scanner_evidence')
  addEdge('gateway', 'resource', 'authorize', 'asset_relationships')
  addEdge('resource', 'trust-material', 'trust chain', 'certificates')
  addEdge('provider', 'trust-material', 'signing keys', 'qkms_keys')

  for (const relationship of input.relationships.slice(0, 6)) {
    if (nodes.length < 2) break
    edges.push({
      id: `relationship:${relationship.id}`,
      from: nodes[0].id,
      to: nodes[Math.min(nodes.length - 1, 3)].id,
      label: titleCase(relationship.relationship_type || relationship.type || 'depends on'),
      sourceTable: 'asset_relationships',
      correlationId: input.correlationId,
    })
  }

  return { nodes, edges }
}

function buildPhaseRows(hasEvidence: boolean, readinessScore: number, blockers: number, evidenceRows: any[]) {
  const phaseDefs = [
    ['discovery', 'Discovery', 'Discover providers, gateways, JWT issuers, keys, certificates, and dependencies.', /discover|provider|gateway|asset|scan|evidence/i],
    ['assessment', 'Assessment', 'Score RSA, ECC, ECDSA, EdDSA, DH, ECDH, token flows, and exposed applications.', /risk|vulnerab|exposure|rsa|ecdsa|ecdh|finding/i],
    ['dependency', 'Dependency Analysis', 'Resolve applications, APIs, proxies, WAFs, and service mesh dependencies.', /relationship|dependency|gateway|api|service|mesh/i],
    ['simulation', 'Simulation', 'Model RSA to ML-DSA, ECDSA to ML-DSA, ECDH to ML-KEM, and hybrid deployments.', /simulation|sandbox|migration|ml-dsa|ml-kem|hybrid/i],
    ['pilot', 'Pilot Deployment', 'Pilot PQ token verification, hybrid certificates, and gateway compatibility.', /pilot|compatib|gateway|certificate|verify/i],
    ['hybrid', 'Hybrid Deployment', 'Bridge legacy applications through PQ token gateway and hybrid verification.', /hybrid|bridge|legacy|gateway/i],
    ['rollout', 'Full PQC Rollout', 'Enforce NIST FIPS 203, FIPS 204, and FIPS 205 migration policy.', /rollout|completed|ml-kem|ml-dsa|slh-dsa/i],
    ['validation', 'Validation', 'Validate readiness, interoperability, performance, compliance, and rollback criteria.', /validate|compliance|audit|evidence|policy/i],
    ['monitoring', 'Continuous Monitoring', 'Monitor identity drift, trust failures, runtime token validation, and audit evidence.', /runtime|auth|telemetry|event|monitor/i],
  ] as const

  return phaseDefs.map(([id, label, objective, regex], index) => {
    const matches = evidenceRows.filter((row) => regex.test(rowText(row)))
    const score = hasEvidence ? clamp(readinessScore - index * 8 + Math.min(28, matches.length * 4) - blockers * 2) : 0
    const status = !hasEvidence
      ? (index === 0 ? 'active' : 'waiting')
      : score >= 82
        ? 'complete'
        : score >= 48
          ? 'active'
          : blockers > 0 && index >= 3
            ? 'review'
            : 'waiting'
    return {
      id,
      label,
      objective,
      status,
      score,
      evidence: matches.length,
      sourceTables: Array.from(new Set(matches.map((row) => String(row.sourceTable || 'unknown')))),
    }
  })
}

function buildSourceCountRow(id: string, label: string, count: number, detail: string, status?: string, sourceTables: string[] = []): PQAuthCountRow {
  return { id, label, count, detail, status, sourceTables }
}

async function buildPQAuthSnapshot(mode: PQAuthMode, token: string, userId: string): Promise<PQAuthSnapshot> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
    assets,
    relationships,
    cryptoInventory,
    cryptoExposures,
    vulnerabilities,
    certificates,
    generatedKeys,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanSessions,
    scanResults,
    migrationJobs,
    complianceEvidence,
    securityEvents,
    authEvents,
    userSessions,
    userSecurityEvents,
    qkmsKeys,
    qkmsAuditEvents,
    qkmsRotationJobs,
    qkmsPolicies,
    connectorAccounts,
    scannerAgents,
    agentHeartbeats,
    vaultAuditLogs,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2500)),
    safeRows(client, 'asset_relationships', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'crypto_inventory', (q) => q.select('*').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(3000)),
    safeRows(client, 'crypto_exposures', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2500)),
    safeRows(client, 'vulnerabilities', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2200)),
    safeRows(client, 'certificates', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2200)),
    safeRows(client, 'generated_keys', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(5000)),
    safeRows(client, 'scanner_evidence', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(3000)),
    safeRows(client, 'scanner_alerts', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(800)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(3000)),
    safeRows(client, 'migration_jobs', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1400)),
    safeRows(client, 'compliance_evidence', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'security_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'auth_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'user_sessions', (q) => q.select('*').eq('user_id', userId).order('last_seen_at', { ascending: false }).limit(1200)),
    safeRows(client, 'user_security_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'qkms_keys', (q) => q.select('*').eq('tenant_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'qkms_audit_events', (q) => q.select('*').eq('tenant_id', userId).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'qkms_rotation_jobs', (q) => q.select('*').eq('tenant_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'qkms_policies', (q) => q.select('*').eq('tenant_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'connector_accounts', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'scanner_agents', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1600)),
    safeRows(client, 'vault_audit_logs', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
  ])

  const correlationId = randomUUID()
  const originService = 'PQAuth Identity Migration Engine'
  const sourceRows = {
    assets: withLineage('assets', assets, originService, correlationId),
    relationships: withLineage('asset_relationships', relationships, originService, correlationId),
    cryptoInventory: withLineage('crypto_inventory', cryptoInventory, originService, correlationId),
    cryptoExposures: withLineage('crypto_exposures', cryptoExposures, originService, correlationId),
    vulnerabilities: withLineage('vulnerabilities', vulnerabilities, originService, correlationId),
    certificates: withLineage('certificates', certificates, originService, correlationId),
    generatedKeys: withLineage('generated_keys', generatedKeys, originService, correlationId),
    runtimeEvents: withLineage('runtime_crypto_events', runtimeEvents, originService, correlationId),
    scannerEvidence: withLineage('scanner_evidence', scannerEvidence, originService, correlationId),
    scannerAlerts: withLineage('scanner_alerts', scannerAlerts, originService, correlationId),
    scanSessions: withLineage('pqc_scan_sessions', scanSessions, originService, correlationId),
    scanResults: withLineage('pqc_scan_results', scanResults, originService, correlationId),
    migrationJobs: withLineage('migration_jobs', migrationJobs, originService, correlationId),
    complianceEvidence: withLineage('compliance_evidence', complianceEvidence, originService, correlationId),
    securityEvents: withLineage('security_events', securityEvents, originService, correlationId),
    authEvents: withLineage('auth_events', authEvents, originService, correlationId),
    userSessions: withLineage('user_sessions', userSessions, originService, correlationId),
    userSecurityEvents: withLineage('user_security_events', userSecurityEvents, originService, correlationId),
    qkmsKeys: withLineage('qkms_keys', qkmsKeys, originService, correlationId),
    qkmsAuditEvents: withLineage('qkms_audit_events', qkmsAuditEvents, originService, correlationId),
    qkmsRotationJobs: withLineage('qkms_rotation_jobs', qkmsRotationJobs, originService, correlationId),
    qkmsPolicies: withLineage('qkms_policies', qkmsPolicies, originService, correlationId),
    connectorAccounts: withLineage('connector_accounts', connectorAccounts, originService, correlationId),
    scannerAgents: withLineage('scanner_agents', scannerAgents, originService, correlationId),
    agentHeartbeats: withLineage('agent_heartbeats', agentHeartbeats, originService, correlationId),
    vaultAuditLogs: withLineage('vault_audit_logs', vaultAuditLogs, originService, correlationId),
  }

  const allEvidenceRows = dedupeRows([
    ...sourceRows.assets,
    ...sourceRows.relationships,
    ...sourceRows.cryptoInventory,
    ...sourceRows.cryptoExposures,
    ...sourceRows.vulnerabilities,
    ...sourceRows.certificates,
    ...sourceRows.generatedKeys,
    ...sourceRows.runtimeEvents,
    ...sourceRows.scannerEvidence,
    ...sourceRows.scannerAlerts,
    ...sourceRows.scanSessions,
    ...sourceRows.scanResults,
    ...sourceRows.migrationJobs,
    ...sourceRows.complianceEvidence,
    ...sourceRows.securityEvents,
    ...sourceRows.authEvents,
    ...sourceRows.userSessions,
    ...sourceRows.userSecurityEvents,
    ...sourceRows.qkmsKeys,
    ...sourceRows.qkmsAuditEvents,
    ...sourceRows.qkmsRotationJobs,
    ...sourceRows.qkmsPolicies,
    ...sourceRows.connectorAccounts,
    ...sourceRows.scannerAgents,
    ...sourceRows.agentHeartbeats,
    ...sourceRows.vaultAuditLogs,
  ])

  const identityRegex = /oauth|oidc|openid|saml|jwt|jws|jwe|token|identity|auth|sso|mfa|session|issuer|jwks|certificate|pki|keycloak|auth0|okta|entra|ping|forgerock|cognito|google identity|user|service account|machine/i
  const tokenRegex = /jwt|jws|jwe|opaque token|refresh token|access token|id token|rs256|rs384|rs512|es256|es384|es512|eddsa|signing|verification/i
  const exposureRegex = /rsa|ecc|ecdsa|eddsa|ed25519|ed448|dh|ecdh|rs256|rs384|rs512|es256|es384|es512|vulnerab|weak|legacy|downgrade|hndl|harvest/i

  const identityRows = allEvidenceRows.filter((row) => identityRegex.test(rowText(row)) || exposureRegex.test(rowText(row))).slice(0, 700)
  const tokenRows = allEvidenceRows.filter((row) => tokenRegex.test(rowText(row))).slice(0, 500)
  const exposureRows = identityRows.filter((row) => exposureRegex.test(rowText(row))).slice(0, 500)
  const providers = collectSignals(allEvidenceRows, PROVIDER_PATTERNS)
  const gateways = collectSignals(allEvidenceRows, GATEWAY_PATTERNS)
  const authServices = collectSignals(allEvidenceRows, SERVICE_PATTERNS)
  const flows = collectSignals(allEvidenceRows, FLOW_PATTERNS)
  const algorithms = buildAlgorithms(identityRows.length ? identityRows : allEvidenceRows)
  const dependencies = dedupeRows([
    ...sourceRows.relationships,
    ...sourceRows.assets.filter((row) => /api|application|service|gateway|identity|oauth|oidc|saml|jwt/i.test(rowText(row))),
    ...identityRows.filter((row) => /dependency|depends|resource server|api|application|gateway|service/i.test(rowText(row))),
  ]).slice(0, 60)
  const runtimeIdentityRows = dedupeRows([
    ...sourceRows.runtimeEvents.filter((row) => /auth|jwt|token|sign|verify|certificate|identity|session/i.test(rowText(row))),
    ...sourceRows.authEvents,
    ...sourceRows.userSessions,
    ...sourceRows.userSecurityEvents,
    ...sourceRows.securityEvents.filter((row) => /auth|identity|session|token|mfa/i.test(rowText(row))),
  ]).slice(0, 120)

  const hasEvidence = allEvidenceRows.length > 0
  const classicalExposureSignals = algorithms.reduce((sum, algorithm) => sum + algorithm.count, 0)
  const criticalFindings = allEvidenceRows.filter((row) => severityRank(row.severity || row.threat_level || row.threatLevel || row.riskSeverity || row.status) >= 4).length
  const highFindings = allEvidenceRows.filter((row) => severityRank(row.severity || row.threat_level || row.threatLevel || row.riskSeverity || row.status) >= 3).length
  const vulnerableComponents = exposureRows.length
  const pqcReadyCryptoRows = [
    ...sourceRows.cryptoInventory,
    ...sourceRows.certificates,
    ...sourceRows.generatedKeys,
    ...sourceRows.qkmsKeys,
  ].filter((row) => row.is_quantum_safe || row.quantumReady || row.pqc_ready || isPqcAlgorithm(`${row.algorithm || ''} ${row.pqc_readiness || ''} ${row.status || ''}`))
  const pqcReadySystems = countAssetsForRows(pqcReadyCryptoRows)
  const quantumVulnerableSystems = countAssetsForRows(exposureRows.filter((row) => {
    const keySize = numberValue(row.key_size || row.keySize || row.bit_length || row.bitLength)
    return isClassicalVulnerable(rowText(row), keySize)
  }))
  const totalCryptoItems = sourceRows.cryptoInventory.length + sourceRows.certificates.length + sourceRows.generatedKeys.length + sourceRows.qkmsKeys.length
  const readinessScore = hasEvidence ? percentOf(pqcReadyCryptoRows.length, Math.max(1, totalCryptoItems)) : 0
  const coverageScore = percentOf(identityRows.length, Math.max(1, sourceRows.assets.length + totalCryptoItems + sourceRows.runtimeEvents.length))
  const riskPressure = clamp(criticalFindings * 10 + highFindings * 6 + classicalExposureSignals * 2 + tokenRows.length)
  const identityRiskScore = hasEvidence ? clamp(riskPressure + Math.max(0, 40 - readinessScore) + (providers.length ? 0 : 6)) : 0
  const oauthReadiness = hasEvidence ? clamp((readinessScore * 0.65) + (coverageScore * 0.25) + (flows.some((flow) => flow.label === 'OAuth 2.0') ? 10 : 0) - gateways.length) : 0
  const oidcReadiness = hasEvidence ? clamp((readinessScore * 0.62) + (coverageScore * 0.23) + (flows.some((flow) => flow.label === 'OpenID Connect') ? 15 : 0) - Math.min(12, tokenRows.length)) : 0
  const jwtMigrationScore = hasEvidence ? clamp((readinessScore * 0.7) + (tokenRows.length ? 8 : 0) - Math.min(34, algorithms.filter((row) => /RSA|ECDSA|EdDSA/.test(row.label)).reduce((sum, row) => sum + row.count, 0))) : 0
  const trustReadiness = hasEvidence ? clamp((readinessScore * 0.5) + percentOf(dependencies.length, Math.max(1, sourceRows.assets.length)) * 0.25 + (sourceRows.certificates.length ? 15 : 0) + (sourceRows.qkmsKeys.length ? 10 : 0)) : 0
  const slhDsaReadiness = hasEvidence ? clamp(readinessScore + countMatches([...sourceRows.certificates, ...sourceRows.generatedKeys, ...sourceRows.qkmsKeys], /slh-dsa|sphincs/i) * 8 - classicalExposureSignals) : 0
  const tokenImpacts = buildTokenImpacts(tokenRows)
  const tokenImpactBlockers = tokenImpacts.filter((row) => row.expansion >= 8).length + countMatches(tokenRows, /header limit|cookie limit|proxy limit|gateway limit|browser limit|mobile constraint/i)
  const compatibilityBlockers = algorithms.length + tokenImpactBlockers + (readinessScore < 55 && hasEvidence ? 1 : 0)
  const migrationCompleted = sourceRows.migrationJobs.filter((job) => normalizeJobStatus(job.status) === 'completed').length
  const migrationRunning = sourceRows.migrationJobs.filter((job) => normalizeJobStatus(job.status) === 'running').length
  const migrationFailed = sourceRows.migrationJobs.filter((job) => normalizeJobStatus(job.status) === 'failed').length

  const compatibilitySurfaces: PQAuthCompatibilitySurface[] = COMPATIBILITY_SURFACES.map((surface) => {
    const matches = allEvidenceRows.filter((row) => surface.regex.test(rowText(row)))
    const score = hasEvidence ? clamp(readinessScore - (matches.length ? 0 : 8) - compatibilityBlockers * 4) : 0
    return {
      id: surface.id,
      label: surface.label,
      count: matches.length,
      score,
      icon: surface.icon,
      sourceTables: Array.from(new Set(matches.map((row) => String(row.sourceTable || 'unknown')))),
      latestAt: latestForRows(matches),
    }
  })

  const graph = buildTrustGraph({
    providers,
    gateways,
    authServices,
    tokenRows,
    dependencies,
    certificates: sourceRows.certificates,
    keys: [...sourceRows.generatedKeys, ...sourceRows.qkmsKeys],
    assets: sourceRows.assets,
    relationships: sourceRows.relationships,
    correlationId,
  })

  const sourceHealthRows = [
    sourceHealth('Asset Inventory', 'assets', assets),
    sourceHealth('Asset Relationships', 'asset_relationships', relationships),
    sourceHealth('Crypto Inventory', 'crypto_inventory', cryptoInventory),
    sourceHealth('Crypto Exposures', 'crypto_exposures', cryptoExposures),
    sourceHealth('Certificates', 'certificates', certificates),
    sourceHealth('Runtime Crypto Events', 'runtime_crypto_events', runtimeEvents),
    sourceHealth('Scanner Evidence', 'scanner_evidence', scannerEvidence),
    sourceHealth('Scanner Alerts', 'scanner_alerts', scannerAlerts),
    sourceHealth('Scan Sessions', 'pqc_scan_sessions', scanSessions),
    sourceHealth('Scan Results', 'pqc_scan_results', scanResults),
    sourceHealth('Auth Events', 'auth_events', authEvents),
    sourceHealth('User Sessions', 'user_sessions', userSessions),
    sourceHealth('Migration Jobs', 'migration_jobs', migrationJobs),
    sourceHealth('Compliance Evidence', 'compliance_evidence', complianceEvidence),
    sourceHealth('QKMS Keys', 'qkms_keys', qkmsKeys),
    sourceHealth('QKMS Audit', 'qkms_audit_events', qkmsAuditEvents),
  ]
  const tenantSync = buildTenantTelemetrySync({
    assets,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    scanSessions,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanResults,
    cryptoInventory,
    cryptoExposures,
    securityEvents,
    generatedKeys,
    certificates,
    vaultAuditLogs,
    vulnerabilities,
    authEvents,
    userSecurityEvents,
    userSessions,
    complianceEvidence,
    migrationJobs,
  })
  const activeSources = sourceHealthRows.filter((row) => row.status === 'live').length
  const staleSources = sourceHealthRows.filter((row) => row.status === 'stale').length
  const normalizedRecords = allEvidenceRows.length
  const duplicateRecords = [
    ...sourceRows.cryptoInventory,
    ...sourceRows.certificates,
    ...sourceRows.generatedKeys,
    ...sourceRows.qkmsKeys,
  ].length - dedupeRows([...sourceRows.cryptoInventory, ...sourceRows.certificates, ...sourceRows.generatedKeys, ...sourceRows.qkmsKeys]).length
  const generatedAt = new Date().toISOString()
  const latestTelemetry = latestDate(
    ...sourceRows.runtimeEvents.map(rowTimestamp),
    ...sourceRows.authEvents.map(rowTimestamp),
    ...sourceRows.userSecurityEvents.map(rowTimestamp),
    ...sourceRows.qkmsAuditEvents.map(rowTimestamp),
  )

  const metrics = {
    identityRiskScore,
    readinessScore,
    oauthReadiness,
    oidcReadiness,
    jwtMigrationScore,
    trustReadiness,
    slhDsaReadiness,
    totalAssets: sourceRows.assets.length,
    totalComponents: totalCryptoItems,
    totalFindings: sourceRows.scanResults.length + sourceRows.scannerAlerts.length + sourceRows.vulnerabilities.length + sourceRows.cryptoExposures.length,
    criticalFindings,
    vulnerableComponents,
    pqcReadyComponents: pqcReadyCryptoRows.length,
    tokenImpactBlockers,
    compatibilityBlockers,
    runtimeSignals: runtimeIdentityRows.length || sourceRows.runtimeEvents.length,
    totalIdentityProviders: providers.length,
    authenticationFlows: flows.length,
    tokenRecords: tokenRows.length,
    trustDependencies: dependencies.length,
    gatewaySignals: gateways.length,
    authServiceSignals: authServices.length,
    classicalExposureSignals,
    certificateSignals: sourceRows.certificates.length,
    qkmsKeySignals: sourceRows.qkmsKeys.length + sourceRows.generatedKeys.length,
    activeJwtSignatures: tokenRows.filter((row) => /sign|signed|signature|jwt|jws|rs256|es256|eddsa/i.test(rowText(row))).length,
    pqcReadySystems,
    quantumVulnerableSystems,
  }

  const complianceBase = hasEvidence ? clamp((readinessScore * 0.55) + ((100 - identityRiskScore) * 0.25) + (sourceRows.complianceEvidence.length ? 20 : 0)) : 0
  const complianceRows = COMPLIANCE_FRAMEWORKS.map((framework) => {
    const regex = new RegExp(framework.replace(/[.\s-]+/g, '.*'), 'i')
    const matches = sourceRows.complianceEvidence.filter((row) => regex.test(rowText(row)))
    const fallbackEvidence = sourceRows.complianceEvidence.length || sourceRows.vaultAuditLogs.length || sourceRows.securityEvents.length
    return {
      id: framework.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      label: framework,
      score: hasEvidence ? clamp(complianceBase + Math.min(10, matches.length * 3)) : 0,
      evidence: `${matches.length || fallbackEvidence} evidence signal(s)`,
      evidenceCount: matches.length || fallbackEvidence,
      sourceTables: matches.length ? Array.from(new Set(matches.map((row) => String(row.sourceTable || 'unknown')))) : ['compliance_evidence'],
      latestAt: latestForRows(matches.length ? matches : sourceRows.complianceEvidence),
    }
  })

  const phases = buildPhaseRows(hasEvidence, readinessScore, compatibilityBlockers, allEvidenceRows)
  const digitalTwinScenarios = [
    { id: 'rsa-ml-dsa', label: 'RSA to ML-DSA', active: algorithms.some((row) => row.id === 'rsa'), detail: 'Token and certificate signature replacement', status: algorithms.some((row) => row.id === 'rsa') ? 'active' : 'waiting', sourceTables: matchedTables(identityRows, /rsa/i), evidence: countMatches(identityRows, /rsa/i) },
    { id: 'ecdsa-ml-dsa', label: 'ECDSA to ML-DSA', active: algorithms.some((row) => row.id === 'ecdsa' || row.id === 'ecc'), detail: 'JWT and identity signature replacement', status: algorithms.some((row) => row.id === 'ecdsa' || row.id === 'ecc') ? 'active' : 'waiting', sourceTables: matchedTables(identityRows, /ecdsa|ecc|p-?256|secp/i), evidence: countMatches(identityRows, /ecdsa|ecc|p-?256|secp/i) },
    { id: 'ecdh-ml-kem', label: 'ECDH to ML-KEM', active: algorithms.some((row) => row.id === 'ecdh' || row.id === 'dh'), detail: 'Hybrid TLS key establishment', status: algorithms.some((row) => row.id === 'ecdh' || row.id === 'dh') ? 'active' : 'waiting', sourceTables: matchedTables(identityRows, /ecdh|diffie|dh\b|x25519/i), evidence: countMatches(identityRows, /ecdh|diffie|dh\b|x25519/i) },
    { id: 'hybrid-deployment', label: 'Hybrid Deployment', active: compatibilityBlockers > 0 || migrationRunning > 0, detail: 'Legacy and PQC verification bridge', status: compatibilityBlockers > 0 ? 'review' : migrationRunning > 0 ? 'active' : 'waiting', sourceTables: ['migration_jobs', 'runtime_crypto_events'], evidence: compatibilityBlockers + migrationRunning },
  ] as const

  const failurePredictions = [
    buildSourceCountRow('token-rejection', 'Token Rejection', tokenImpactBlockers, 'JWT size or algorithm compatibility blockers', undefined, ['runtime_crypto_events', 'scanner_evidence']),
    buildSourceCountRow('gateway-failure', 'Gateway Failure', gateways.length ? compatibilityBlockers : 0, 'Gateway, proxy, WAF, and ingress compatibility signals', undefined, gateways.flatMap((row) => row.sourceTables)),
    buildSourceCountRow('certificate-issue', 'Certificate Issue', countMatches(sourceRows.certificates, /rsa|ecdsa|ecc|expired|expiring|weak/i), 'Classical or expiring certificate evidence', undefined, ['certificates']),
    buildSourceCountRow('performance-degradation', 'Performance Degradation', tokenImpactBlockers + compatibilityBlockers, 'Token expansion and runtime compatibility pressure', undefined, ['runtime_crypto_events', 'pqc_scan_results']),
    buildSourceCountRow('trust-chain-breakage', 'Trust Chain Breakage', dependencies.length && classicalExposureSignals ? classicalExposureSignals : 0, 'Dependency and trust-material breakage signals', undefined, ['asset_relationships', 'certificates', 'qkms_keys']),
  ]
  const rollbackGates = [
    buildSourceCountRow('auth-failures', 'Authentication Failures', criticalFindings, 'Critical authentication or identity security signals', criticalFindings ? 'review' : 'ready', ['auth_events', 'security_events']),
    buildSourceCountRow('token-validation', 'Token Validation Failures', tokenImpactBlockers, 'Token validation and size-impact blockers', tokenImpactBlockers ? 'review' : 'ready', ['runtime_crypto_events']),
    buildSourceCountRow('performance', 'Performance Thresholds Exceeded', compatibilityBlockers, 'Compatibility blockers requiring staged rollout', compatibilityBlockers ? 'review' : 'ready', ['pqc_scan_results', 'scanner_evidence']),
    buildSourceCountRow('trust-chain', 'Trust Chain Failures', classicalExposureSignals, 'Classical algorithm exposure in identity trust chains', classicalExposureSignals ? 'review' : 'ready', ['crypto_inventory', 'certificates']),
  ]
  const runtimeMetrics: PQAuthRuntimeMetric[] = [
    { id: 'runtime-events', label: 'Runtime Events', value: metrics.runtimeSignals, detail: 'authentication, authorization, token, or scanner telemetry' },
    { id: 'token-validation', label: 'Token Validation', value: tokenRows.length, detail: 'JWS, JWE, access-token, refresh-token signals' },
    { id: 'certificate-usage', label: 'Certificate Usage', value: sourceRows.certificates.length, detail: 'trust material evidence' },
    { id: 'trust-failures', label: 'Trust Failures', value: compatibilityBlockers, detail: 'drift, blocker, or failure-class signals' },
    { id: 'identity-drift', label: 'Identity Drift', value: vulnerableComponents, detail: 'vulnerable or review components' },
  ]
  const qkmsKeyDomains = [
    buildSourceCountRow('signing-keys', 'Signing Keys', tokenRows.length + countMatches(sourceRows.qkmsKeys, /sign|verify|ml-dsa|slh-dsa|ecdsa|rsa/i), 'ML-DSA verification and signing readiness', undefined, ['qkms_keys', 'generated_keys', 'runtime_crypto_events']),
    buildSourceCountRow('verification-keys', 'Verification Keys', authServices.length + countMatches(sourceRows.qkmsKeys, /verify|jwks|issuer/i), 'JWT issuer and validator ownership', undefined, ['qkms_keys', 'scanner_evidence']),
    buildSourceCountRow('tls-keys', 'TLS Keys', countMatches([...sourceRows.certificates, ...sourceRows.qkmsKeys], /tls|https|certificate|x509|ml-kem/i), 'ML-KEM and hybrid TLS key establishment', undefined, ['certificates', 'qkms_keys']),
    buildSourceCountRow('certificate-keys', 'Certificate Keys', sourceRows.certificates.length, 'SLH-DSA long-term trust anchors', undefined, ['certificates']),
    buildSourceCountRow('identity-keys', 'Identity Keys', providers.length + flows.length + countMatches(sourceRows.qkmsKeys, /identity|saml|oauth|oidc/i), 'operator, workload, and federation identity keys', undefined, ['qkms_keys', 'auth_events']),
    buildSourceCountRow('machine-identity-keys', 'Machine Identity Keys', countMatches(identityRows, /machine|device|service account|workload|agent/i), 'service account and workload identity custody', undefined, ['assets', 'scanner_agents', 'qkms_keys']),
  ]
  const lifecycleControls = [
    buildSourceCountRow('ownership', 'Ownership', countMatches([...sourceRows.qkmsKeys, ...sourceRows.generatedKeys], /owner|owned|assigned/i), 'Owner mapping evidence', sourceRows.qkmsKeys.length || sourceRows.generatedKeys.length ? 'active' : 'waiting', ['qkms_keys', 'generated_keys']),
    buildSourceCountRow('rotation', 'Rotation', qkmsRotationJobs.length + countMatches(sourceRows.generatedKeys, /rotated|rotation/i), 'Rotation job and key history evidence', qkmsRotationJobs.length ? 'active' : 'waiting', ['qkms_rotation_jobs', 'generated_keys']),
    buildSourceCountRow('expiration', 'Expiration', countMatches([...sourceRows.certificates, ...sourceRows.generatedKeys, ...sourceRows.qkmsKeys], /expire|not_after|expires/i), 'Expiration tracking evidence', 'active', ['certificates', 'generated_keys', 'qkms_keys']),
    buildSourceCountRow('revocation', 'Revocation', countMatches([...sourceRows.certificates, ...sourceRows.generatedKeys, ...sourceRows.qkmsKeys], /revoked|disabled|blocked|compromised/i), 'Revocation and block evidence', 'active', ['certificates', 'generated_keys', 'qkms_keys']),
    buildSourceCountRow('pqc-readiness', 'PQC Readiness', pqcReadyCryptoRows.length, 'PQC readiness evidence', pqcReadyCryptoRows.length ? 'active' : 'waiting', ['crypto_inventory', 'certificates', 'qkms_keys']),
  ]

  const freshness = {
    lastTelemetryReceived: latestTelemetry,
    lastScanTimestamp: tenantSync.latestScanAt,
    lastIdentitySync: latestDate(latestTelemetry, ...sourceRows.authEvents.map(rowTimestamp), ...sourceRows.userSessions.map(rowTimestamp)),
    lastOAuthDiscovery: latestForRows(allEvidenceRows.filter((row) => /oauth|oidc|saml|keycloak|auth0|okta|entra|cognito/i.test(rowText(row)))),
    lastJwtAnalysis: latestForRows(tokenRows),
    lastRiskCalculation: generatedAt,
    lastComplianceEvaluation: latestForRows(sourceRows.complianceEvidence),
  }
  const telemetryIds = allEvidenceRows
    .slice()
    .sort((a, b) => dateMs(rowTimestamp(b)) - dateMs(rowTimestamp(a)))
    .slice(0, 24)
    .map((row) => `${row.sourceTable}:${row.id}`)

  return {
    generatedAt,
    hasEvidence,
    mode,
    providers,
    gateways,
    authServices,
    flows,
    algorithms,
    identityRows: identityRows.slice(0, 120),
    exposureRows: exposureRows.slice(0, 120),
    tokenRows: tokenRows.slice(0, 120),
    dependencies,
    runtimeEvents: runtimeIdentityRows,
    trustNodes: graph.nodes,
    trustEdges: graph.edges,
    phases,
    complianceRows,
    compatibilitySurfaces,
    tokenImpacts,
    digitalTwinScenarios: digitalTwinScenarios.map((row) => ({ ...row })),
    failurePredictions,
    rollbackGates,
    runtimeMetrics,
    qkmsKeyDomains,
    lifecycleControls,
    sourceHealth: sourceHealthRows,
    freshness,
    lineage: {
      source: 'api-server/pqauth-dashboard',
      originService,
      generatedAt,
      correlationId,
      sourceTables: sourceHealthRows.filter((row) => row.count > 0).map((row) => row.table),
      telemetryIds,
    },
    integrity: {
      duplicateRecords: Math.max(0, duplicateRecords),
      normalizedRecords,
      deterministicTransforms: true,
      staleSources,
      activeSources,
    },
    metrics,
  }
}

function sseHeaders(res: Response) {
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()
}

function writeSse(res: Response, event: string, data: unknown) {
  if (!res.writableEnded) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
}

const router = Router()
router.use(requireAuth)

router.get('/stream', async (req: AuthedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  sseHeaders(res)
  writeSse(res, 'pqauth-connected', {
    timestamp: new Date().toISOString(),
    source: 'dashboard.pqauth',
  })

  let closed = false
  const emitUpdate = () => {
    if (closed) return
    writeSse(res, 'pqauth-update', {
      timestamp: new Date().toISOString(),
      source: 'dashboard.pqauth',
      reason: 'tenant-pqauth-sync',
    })
  }

  emitUpdate()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': pqauth heartbeat\n\n')
  }, 25000)
  const syncPoll = setInterval(emitUpdate, 8000)

  req.on('close', () => {
    closed = true
    clearInterval(heartbeat)
    clearInterval(syncPoll)
  })
})

router.get('/', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    const data = await buildPQAuthSnapshot('overview', req.token, req.user.id)
    return res.json({ data })
  } catch (error: any) {
    console.error('PQAuth dashboard overview error:', error)
    return res.status(500).json({ error: { code: 'PQAUTH_OVERVIEW_FAILED', message: error?.message || 'Failed to fetch PQAuth dashboard data' } })
  }
})

router.get('/:mode', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    const mode = String(req.params.mode || 'overview') as PQAuthMode
    if (!MODES.has(mode)) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'PQAuth page not found' } })
    }
    const data = await buildPQAuthSnapshot(mode, req.token, req.user.id)
    return res.json({ data })
  } catch (error: any) {
    console.error('PQAuth dashboard error:', error)
    return res.status(500).json({ error: { code: 'PQAUTH_SNAPSHOT_FAILED', message: error?.message || 'Failed to fetch PQAuth dashboard data' } })
  }
})

export default router
