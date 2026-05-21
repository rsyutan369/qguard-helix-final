import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'

const ONE_DAY_MS = 24 * 60 * 60 * 1000

type ObservabilityKind = 'runtime' | 'certificate' | 'keys' | 'api' | 'cloud'
type Severity = 'critical' | 'high' | 'medium' | 'low'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

type Signal = {
  id: string
  sourceTable: string
  pillar: string
  title: string
  subject: string
  subjectType: string
  provider: string
  region: string
  protocol: string
  algorithm: string
  keySize: number
  status: string
  severity: Severity
  riskScore: number
  encrypted: boolean
  pqcReady: boolean
  weak: boolean
  expiring: boolean
  runtime: boolean
  api: boolean
  certificate: boolean
  key: boolean
  cloud: boolean
  timestamp: string | null
  ms: number
  detail: string
}

const ROUTE_META: Record<ObservabilityKind, { eventPrefix: string; routeLabel: string }> = {
  runtime: { eventPrefix: 'runtime-telemetry', routeLabel: 'Runtime telemetry' },
  certificate: { eventPrefix: 'certificate-telemetry', routeLabel: 'Certificate telemetry' },
  keys: { eventPrefix: 'key-analytics', routeLabel: 'Key analytics' },
  api: { eventPrefix: 'api-encryption', routeLabel: 'API encryption' },
  cloud: { eventPrefix: 'multi-cloud-telemetry', routeLabel: 'Multi-cloud telemetry' },
}

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
  const num = Number(value)
  return Number.isFinite(num) ? num : fallback
}

function dateMs(value: unknown) {
  const ms = new Date(String(value || '')).getTime()
  return Number.isFinite(ms) ? ms : 0
}

function clamp(value: number, min = 0, max = 100) {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, Math.round(value)))
}

function percentOf(value: number, total: number) {
  return total > 0 ? clamp((value / total) * 100) : 0
}

function deltaPercent(current: number, previous: number) {
  if (previous <= 0) return current > 0 ? 100 : 0
  return Math.round(((current - previous) / previous) * 100)
}

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
}

function titleCase(value: unknown, fallback = 'Telemetry Signal') {
  const text = String(value || fallback)
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return text.replace(/\b\w/g, (char) => char.toUpperCase()) || fallback
}

function normalizeSeverity(value: unknown): Severity {
  const lower = String(value || '').toLowerCase()
  if (lower === 'critical') return 'critical'
  if (lower === 'high' || lower === 'error' || lower === 'failed') return 'high'
  if (lower === 'medium' || lower === 'moderate' || lower === 'warning') return 'medium'
  return 'low'
}

function severityRank(value: unknown) {
  const lower = String(value || '').toLowerCase()
  if (lower === 'critical') return 4
  if (lower === 'high') return 3
  if (lower === 'medium' || lower === 'moderate' || lower === 'warning') return 2
  if (lower === 'low') return 1
  return 0
}

function severityForScore(score: number): Severity {
  if (score >= 86) return 'critical'
  if (score >= 68) return 'high'
  if (score >= 38) return 'medium'
  return 'low'
}

function isPqcAlgorithm(value: string) {
  return /ml-kem|ml_dsa|ml-dsa|kyber|dilithium|sphincs|falcon|bike|hqc|ntru|hybrid|pqc|post.quantum/i.test(value)
}

function isWeakCrypto(value: string, keySize = 0) {
  const text = `${value} ${keySize}`.toLowerCase()
  if (/ssl|tls\s*1\.[01]|rc4|3des|des|cbc|sha-?1|md5|null|export|anon|rsa_with|dh anon|dsa/.test(text)) return true
  if (/rsa/.test(text) && keySize > 0 && keySize < 3072) return true
  if (/ec|ecc|ecdsa|ecdh|prime256v1|secp256|p-256|p256/.test(text)) return true
  return false
}

function firstString(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = textValue(record[key])
    if (value) return value
  }
  return ''
}

function inferProvider(value: string) {
  const lower = value.toLowerCase()
  if (/aws|amazon|s3|ec2|lambda|kms|us-east|us-west|eu-west|ap-southeast/.test(lower)) return 'AWS'
  if (/azure|microsoft|aks|keyvault|eastus|westeurope|centralus/.test(lower)) return 'Azure'
  if (/gcp|google|gke|cloud run|cloudrun|us-central|europe-west|asia-east/.test(lower)) return 'GCP'
  if (/cloudflare|r2|workers/.test(lower)) return 'Cloudflare'
  if (/oracle|oci/.test(lower)) return 'OCI'
  return 'Private / Hybrid'
}

function inferRegion(value: string) {
  const match = value.match(/\b(us|eu|ap|sa|ca|me|af)[-_][a-z]+[-_]\d\b/i)
  if (match) return match[0].replace(/_/g, '-')
  const words = value.match(/\b(eastus|westus|centralus|westeurope|northeurope|global|local|edge)\b/i)
  return words ? words[0] : 'global'
}

function inferProtocol(value: string) {
  const text = value.toLowerCase()
  if (/quic|http3|http\/3/.test(text)) return 'QUIC / HTTP3'
  if (/http\/2|h2/.test(text)) return 'HTTP/2 TLS'
  if (/mtls|m-tls|mutual tls/.test(text)) return 'mTLS'
  if (/grpc/.test(text)) return 'gRPC TLS'
  if (/graphql/.test(text)) return 'GraphQL HTTPS'
  if (/rest|api|gateway|webhook/.test(text)) return 'API HTTPS'
  if (/ldaps/.test(text)) return 'LDAPS'
  if (/imaps/.test(text)) return 'IMAPS'
  if (/smtps/.test(text)) return 'SMTPS'
  if (/ssh/.test(text)) return 'SSH'
  if (/ipsec|vpn|wireguard/.test(text)) return 'VPN / IPSec'
  if (/https|tls|ssl|443/.test(text)) return 'HTTPS / TLS'
  return 'Unknown'
}

function isApiText(value: string) {
  return /api|gateway|graphql|grpc|rest|webhook|oauth|jwt|token|service mesh|ingress|egress|http|https|mtls|endpoint/i.test(value)
}

function isCertificateText(value: string) {
  return /cert|certificate|x509|issuer|subject|serial|tls|ssl|trust chain|revocation|ocsp|crl/i.test(value)
}

function isKeyText(value: string) {
  return /key|kms|hsm|secret|vault|rotation|wrap|unwrap|sign|verify|encrypt|decrypt|qrng|entropy|token|rsa|ecdsa|ml-kem|ml-dsa|kyber|dilithium/i.test(value)
}

function countBy<T>(items: T[], keyFn: (item: T) => string, limit = 8) {
  const counts = new Map<string, number>()
  for (const item of items) {
    const key = keyFn(item) || 'Unknown'
    counts.set(key, (counts.get(key) || 0) + 1)
  }
  const total = items.length
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([label, count]) => ({ label, count, percent: percentOf(count, total) }))
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
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Observability dashboard ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Observability dashboard ${table} query failed:`, error?.message || error)
    return []
  }
}

function buildRouter(kind: ObservabilityKind) {
  const router = Router()
  const meta = ROUTE_META[kind]
  router.use(requireAuth)

  router.get('/stream', async (req: AuthedRequest, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    }

    sseHeaders(res)
    writeSse(res, `${meta.eventPrefix}-connected`, {
      timestamp: new Date().toISOString(),
      source: `dashboard.${meta.eventPrefix}`,
    })

    let closed = false
    const emitUpdate = () => {
      if (closed) return
      writeSse(res, `${meta.eventPrefix}-update`, {
        timestamp: new Date().toISOString(),
        source: `dashboard.${meta.eventPrefix}`,
        reason: `tenant-${meta.eventPrefix}-sync`,
      })
    }

    emitUpdate()
    const heartbeat = setInterval(() => {
      if (!closed) res.write(`: ${meta.eventPrefix} heartbeat\n\n`)
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
      if (!req.user || !req.token) {
        return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
      }

      const data = await buildObservabilitySnapshot(kind, req.token, req.user.id)
      return res.json({ data })
    } catch (error: any) {
      console.error(`${meta.routeLabel} dashboard error:`, error)
      return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || `Failed to fetch ${meta.routeLabel.toLowerCase()} data` } })
    }
  })

  return router
}

async function buildObservabilitySnapshot(kind: ObservabilityKind, token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
    assets,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanResults,
    cryptoInventory,
    cryptoExposures,
    certificates,
    generatedKeys,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    qrngEvents,
    vaultAuditLogs,
    complianceEvidence,
    migrationJobs,
    securityEvents,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(6000)),
    safeRows(client, 'scanner_evidence', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(3000)),
    safeRows(client, 'scanner_alerts', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(2600)),
    safeRows(client, 'crypto_inventory', (q) => q.select('*').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(2600)),
    safeRows(client, 'crypto_exposures', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2200)),
    safeRows(client, 'certificates', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2200)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'scanner_agents', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'connector_accounts', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1800)),
    safeRows(client, 'qrng_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'vault_audit_logs', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'compliance_evidence', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'migration_jobs', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(900)),
    safeRows(client, 'security_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
  ])

  const now = Date.now()
  const recentStart = now - 7 * ONE_DAY_MS
  const previousStart = now - 14 * ONE_DAY_MS
  const staleStart = now - 30 * ONE_DAY_MS
  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
  const signals: Signal[] = []
  const seen = new Set<string>()

  const assetName = (assetId: unknown, fallback = 'Unmapped asset') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.name, fallback)
  }

  const addSignal = (input: {
    id: string
    sourceTable: string
    pillar: string
    title: string
    subject?: string
    subjectType?: string
    assetId?: string | null
    provider?: string
    region?: string
    protocol?: string
    algorithm?: string
    keySize?: unknown
    status?: string
    severity?: unknown
    riskScore?: unknown
    encrypted?: boolean
    pqcReady?: boolean
    weak?: boolean
    expiring?: boolean
    runtime?: boolean
    api?: boolean
    certificate?: boolean
    key?: boolean
    cloud?: boolean
    timestamp?: string | null
    detail?: string
  }) => {
    if (seen.has(input.id)) return
    seen.add(input.id)
    const timestamp = input.timestamp || null
    const ms = dateMs(timestamp)
    const text = `${input.pillar} ${input.title} ${input.subject || ''} ${input.detail || ''} ${input.provider || ''} ${input.region || ''}`
    const keySize = numberValue(input.keySize)
    const algorithm = textValue(input.algorithm)
    const protocol = textValue(input.protocol, inferProtocol(text))
    const provider = textValue(input.provider, inferProvider(text))
    const region = textValue(input.region, inferRegion(text))
    const weak = input.weak ?? isWeakCrypto(`${algorithm} ${protocol}`, keySize)
    const encrypted = input.encrypted ?? !/plaintext|cleartext|unencrypted|disabled/i.test(text)
    const pqcReady = input.pqcReady ?? isPqcAlgorithm(algorithm)
    const severity = normalizeSeverity(input.severity)
    let riskScore = Number(input.riskScore || 0)
    if (!Number.isFinite(riskScore) || riskScore <= 0) {
      riskScore = 16
      if (weak) riskScore += 34
      if (!encrypted) riskScore += 22
      if (!pqcReady && /key|certificate|crypto|tls|api/i.test(text)) riskScore += 8
      if (input.expiring) riskScore += 14
      if (severityRank(severity) >= 3) riskScore += 28
      else if (severityRank(severity) === 2) riskScore += 14
      if (ms && ms < staleStart) riskScore += 6
    }
    const finalScore = clamp(riskScore)
    const finalSeverity = severityRank(severity) > 1 ? severity : severityForScore(finalScore)

    signals.push({
      id: input.id,
      sourceTable: input.sourceTable,
      pillar: input.pillar,
      title: titleCase(input.title),
      subject: textValue(input.subject, input.assetId ? assetName(input.assetId) : 'Telemetry subject'),
      subjectType: textValue(input.subjectType, 'Telemetry object'),
      provider,
      region,
      protocol,
      algorithm,
      keySize,
      status: textValue(input.status, weak ? 'review' : encrypted ? 'protected' : 'observed'),
      severity: finalSeverity,
      riskScore: finalScore,
      encrypted,
      pqcReady,
      weak,
      expiring: Boolean(input.expiring),
      runtime: Boolean(input.runtime),
      api: input.api ?? isApiText(text),
      certificate: input.certificate ?? isCertificateText(text),
      key: input.key ?? isKeyText(text),
      cloud: input.cloud ?? provider !== 'Private / Hybrid',
      timestamp,
      ms,
      detail: input.detail || '',
    })
  }

  for (const asset of assets || []) {
    const metadata = recordOf(asset.metadata)
    const provider = firstString(metadata, ['provider', 'cloud', 'cloudProvider']) || inferProvider(`${asset.name || ''} ${asset.type || ''} ${asset.region || ''} ${JSON.stringify(metadata)}`)
    const region = textValue(asset.region, firstString(metadata, ['region', 'location']) || inferRegion(JSON.stringify(metadata)))
    const active = !/unknown|unmanaged|inactive|retired/.test(String(asset.status || '').toLowerCase())
    addSignal({
      id: `asset-${asset.id}`,
      sourceTable: 'assets',
      pillar: provider !== 'Private / Hybrid' ? 'Cloud Asset' : 'Asset Scope',
      title: `${asset.type || 'Asset'} telemetry scope`,
      subject: textValue(asset.name, 'Asset'),
      subjectType: textValue(asset.type, 'Asset'),
      assetId: asset.id,
      provider,
      region,
      status: textValue(asset.status, active ? 'active' : 'review'),
      severity: active ? 'low' : 'medium',
      encrypted: Boolean(metadata.encrypted || metadata.tls || metadata.encryption),
      pqcReady: Boolean(metadata.pqc_ready || metadata.quantum_safe || metadata.is_quantum_safe),
      runtime: /server|host|node|container|kubernetes|service|application/i.test(`${asset.type || ''} ${asset.name || ''}`),
      api: /api|gateway|service|application|webhook/i.test(`${asset.type || ''} ${asset.name || ''}`),
      certificate: /cert|certificate|tls|domain/i.test(`${asset.type || ''} ${asset.name || ''}`),
      key: /key|kms|hsm|vault|secret/i.test(`${asset.type || ''} ${asset.name || ''}`),
      cloud: provider !== 'Private / Hybrid',
      timestamp: asset.updated_at || asset.created_at,
      detail: `${asset.environment || ''} ${asset.service_owner || ''} ${asset.criticality || ''}`,
    })
  }

  for (const event of runtimeEvents || []) {
    const metadata = recordOf(event.metadata)
    const algorithm = textValue(event.algorithm, textValue(event.key_exchange_algorithm, textValue(event.cipher_suite, '')))
    const text = `${event.source_type || ''} ${event.event_type || ''} ${event.operation_type || ''} ${event.asset_name || ''} ${event.host || ''} ${event.protocol || ''} ${algorithm} ${JSON.stringify(metadata)}`
    const weak = Boolean(event.is_legacy || event.downgrade_detected || event.shadow_crypto || isWeakCrypto(`${algorithm} ${event.tls_version || ''}`, numberValue(event.key_size)))
    addSignal({
      id: `runtime-${event.id}`,
      sourceTable: 'runtime_crypto_events',
      pillar: isApiText(text) ? 'API Runtime' : inferProvider(text) !== 'Private / Hybrid' ? 'Cloud Runtime' : 'Runtime Crypto',
      title: event.event_type || event.operation_type || 'Runtime crypto event',
      subject: textValue(event.process_name, textValue(event.asset_name, textValue(event.host, assetName(event.asset_id)))),
      subjectType: textValue(event.asset_type, textValue(event.source_type, 'Runtime')),
      assetId: event.asset_id,
      provider: firstString(metadata, ['provider', 'cloud']) || inferProvider(text),
      region: firstString(metadata, ['region', 'location']) || inferRegion(text),
      protocol: textValue(event.protocol, inferProtocol(text)),
      algorithm,
      keySize: event.key_size,
      status: weak ? 'runtime_weakness' : 'observed',
      severity: event.severity,
      riskScore: event.risk_score,
      encrypted: !/plaintext|cleartext|unencrypted/i.test(text),
      pqcReady: Boolean(event.is_pqc) || isPqcAlgorithm(`${algorithm}`),
      weak,
      runtime: true,
      api: isApiText(text),
      certificate: isCertificateText(text),
      key: isKeyText(text),
      cloud: inferProvider(text) !== 'Private / Hybrid',
      timestamp: event.observed_at || event.created_at,
      detail: `${event.asset_name || ''} ${event.host || ''} ${event.tls_version || ''} ${event.cipher_suite || ''}`,
    })
  }

  for (const evidence of scannerEvidence || []) {
    const raw = recordOf(evidence.raw_evidence)
    const algorithm = textValue(evidence.observed_algorithm, firstString(raw, ['algorithm', 'cipher', 'cipher_suite']))
    const text = `${evidence.source_type || ''} ${evidence.evidence_type || ''} ${evidence.asset_name || ''} ${evidence.target || ''} ${evidence.host || ''} ${evidence.protocol || ''} ${algorithm} ${JSON.stringify(raw)}`
    const weak = isWeakCrypto(`${algorithm} ${evidence.protocol || ''}`, numberValue(evidence.key_size))
    addSignal({
      id: `evidence-${evidence.id}`,
      sourceTable: 'scanner_evidence',
      pillar: isApiText(text) ? 'API Evidence' : isCertificateText(text) ? 'Certificate Evidence' : isKeyText(text) ? 'Key Evidence' : inferProvider(text) !== 'Private / Hybrid' ? 'Cloud Evidence' : 'Runtime Evidence',
      title: evidence.evidence_type || 'Scanner evidence',
      subject: textValue(evidence.asset_name, textValue(evidence.host, textValue(evidence.target, 'Evidence'))),
      subjectType: textValue(evidence.asset_type, textValue(evidence.source_type, 'Evidence')),
      provider: inferProvider(text),
      region: inferRegion(text),
      protocol: textValue(evidence.protocol, inferProtocol(text)),
      algorithm,
      keySize: evidence.key_size,
      status: weak ? 'weak_evidence' : 'captured',
      severity: weak ? 'medium' : 'low',
      encrypted: !/plaintext|cleartext/i.test(JSON.stringify(raw)),
      pqcReady: isPqcAlgorithm(`${algorithm}`),
      weak,
      runtime: true,
      api: isApiText(text),
      certificate: isCertificateText(text),
      key: isKeyText(text),
      cloud: inferProvider(text) !== 'Private / Hybrid',
      timestamp: evidence.observed_at || evidence.processed_at || evidence.created_at,
      detail: `${algorithm} ${evidence.protocol || ''} confidence:${evidence.confidence || ''}`,
    })
  }

  for (const alert of scannerAlerts || []) {
    const metadata = recordOf(alert.metadata)
    const text = `${alert.category || ''} ${alert.title || ''} ${alert.message || ''} ${alert.recommendation || ''} ${JSON.stringify(metadata)}`
    addSignal({
      id: `scanner-alert-${alert.id}`,
      sourceTable: 'scanner_alerts',
      pillar: isApiText(text) ? 'API Finding' : isCertificateText(text) ? 'Certificate Finding' : isKeyText(text) ? 'Key Finding' : inferProvider(text) !== 'Private / Hybrid' ? 'Cloud Finding' : 'Runtime Finding',
      title: alert.title || alert.category || 'Scanner alert',
      subject: firstString(metadata, ['assetName', 'resourceName', 'hostname', 'target']) || textValue(alert.category, 'Scanner alert'),
      subjectType: firstString(metadata, ['assetType', 'resourceType']) || 'Scanner Alert',
      provider: inferProvider(text),
      region: inferRegion(text),
      status: textValue(alert.status, 'open'),
      severity: alert.severity,
      encrypted: !/plaintext|cleartext|unencrypted/i.test(text),
      pqcReady: isPqcAlgorithm(text),
      weak: true,
      runtime: true,
      api: isApiText(text),
      certificate: isCertificateText(text),
      key: isKeyText(text),
      cloud: inferProvider(text) !== 'Private / Hybrid',
      timestamp: alert.updated_at || alert.created_at,
      detail: `${alert.message || ''} ${alert.recommendation || ''}`,
    })
  }

  for (const result of scanResults || []) {
    const text = `${result.finding_type || ''} ${result.algorithm || ''} ${result.description || ''} ${result.remediation || ''}`
    addSignal({
      id: `scan-result-${result.id}`,
      sourceTable: 'pqc_scan_results',
      pillar: isCertificateText(text) ? 'Certificate Finding' : isKeyText(text) ? 'Key Finding' : 'PQC Finding',
      title: result.finding_type || 'PQC scan finding',
      subject: assetName(result.asset_id, 'Scan finding'),
      subjectType: 'Scan Result',
      assetId: result.asset_id,
      algorithm: result.algorithm,
      status: 'active',
      severity: result.threat_level,
      encrypted: true,
      pqcReady: isPqcAlgorithm(`${result.algorithm || ''}`),
      weak: !isPqcAlgorithm(`${result.algorithm || ''}`),
      runtime: true,
      api: isApiText(text),
      certificate: isCertificateText(text),
      key: isKeyText(text),
      timestamp: result.created_at,
      detail: `${result.description || ''} ${result.remediation || ''}`,
    })
  }

  for (const item of cryptoInventory || []) {
    const metadata = recordOf(item.metadata)
    const text = `${item.item_type || ''} ${item.name || ''} ${item.algorithm || ''} ${item.protocol || ''} ${JSON.stringify(metadata)}`
    const weak = Boolean(item.is_vulnerable && !item.is_quantum_safe) || isWeakCrypto(`${item.algorithm || ''} ${item.protocol || ''}`, numberValue(item.key_size))
    addSignal({
      id: `inventory-${item.id}`,
      sourceTable: 'crypto_inventory',
      pillar: isCertificateText(text) ? 'Certificate Inventory' : isKeyText(text) ? 'Key Inventory' : isApiText(text) ? 'API Crypto' : inferProvider(text) !== 'Private / Hybrid' ? 'Cloud Crypto' : 'Crypto Inventory',
      title: item.item_type || 'Crypto inventory',
      subject: textValue(item.name, assetName(item.asset_id)),
      subjectType: textValue(item.item_type, 'Crypto Item'),
      assetId: item.asset_id,
      provider: inferProvider(text),
      region: inferRegion(text),
      protocol: item.protocol,
      algorithm: item.algorithm,
      keySize: item.key_size,
      status: item.is_quantum_safe ? 'pqc_ready' : weak ? 'weak' : 'observed',
      severity: weak ? item.exposure_level || 'medium' : 'low',
      encrypted: true,
      pqcReady: Boolean(item.is_quantum_safe) || isPqcAlgorithm(`${item.algorithm || ''}`),
      weak,
      runtime: true,
      api: isApiText(text),
      certificate: isCertificateText(text),
      key: isKeyText(text),
      cloud: inferProvider(text) !== 'Private / Hybrid',
      timestamp: item.discovered_at || item.created_at,
      detail: `${item.algorithm || ''} ${item.protocol || ''} ${item.key_size || ''}`,
    })
  }

  for (const exposure of cryptoExposures || []) {
    const text = `${exposure.exposure_type || ''} ${exposure.description || ''} ${exposure.detected_value || ''} ${JSON.stringify(recordOf(exposure.metadata))}`
    addSignal({
      id: `exposure-${exposure.id}`,
      sourceTable: 'crypto_exposures',
      pillar: isCertificateText(text) ? 'Certificate Exposure' : isKeyText(text) ? 'Key Exposure' : isApiText(text) ? 'API Exposure' : inferProvider(text) !== 'Private / Hybrid' ? 'Cloud Exposure' : 'Runtime Exposure',
      title: exposure.exposure_type || 'Crypto exposure',
      subject: assetName(exposure.asset_id, 'Crypto exposure'),
      subjectType: 'Exposure',
      assetId: exposure.asset_id,
      provider: inferProvider(text),
      region: inferRegion(text),
      status: 'active',
      severity: exposure.severity,
      encrypted: !/plaintext|cleartext|unencrypted/i.test(text),
      pqcReady: isPqcAlgorithm(text),
      weak: true,
      runtime: true,
      api: isApiText(text),
      certificate: isCertificateText(text),
      key: isKeyText(text),
      cloud: inferProvider(text) !== 'Private / Hybrid',
      timestamp: exposure.updated_at || exposure.created_at,
      detail: `${exposure.description || ''} ${exposure.detected_value || ''}`,
    })
  }

  for (const cert of certificates || []) {
    const expiresAt = dateMs(cert.not_after)
    const expiring = Boolean(cert.is_expiring_soon || (expiresAt && expiresAt < now + 30 * ONE_DAY_MS))
    const expired = Boolean(expiresAt && expiresAt < now)
    const weak = !cert.is_quantum_safe && isWeakCrypto(`${cert.algorithm || ''}`, numberValue(cert.key_size))
    addSignal({
      id: `certificate-${cert.id}`,
      sourceTable: 'certificates',
      pillar: 'Certificate Lifecycle',
      title: expired ? 'Certificate expired' : expiring ? 'Certificate expiring' : 'Certificate active',
      subject: textValue(cert.name, textValue(cert.subject, assetName(cert.asset_id, 'Certificate'))),
      subjectType: 'Certificate',
      assetId: cert.asset_id,
      provider: inferProvider(`${cert.issuer || ''} ${cert.subject || ''} ${JSON.stringify(recordOf(cert.metadata))}`),
      region: inferRegion(`${cert.issuer || ''} ${cert.subject || ''}`),
      protocol: 'HTTPS / TLS',
      algorithm: cert.algorithm,
      keySize: cert.key_size,
      status: expired ? 'expired' : expiring ? 'expiring' : textValue(cert.status, 'active'),
      severity: expired || weak ? 'high' : expiring ? 'medium' : 'low',
      encrypted: true,
      pqcReady: Boolean(cert.is_quantum_safe) || isPqcAlgorithm(`${cert.algorithm || ''}`),
      weak,
      expiring,
      api: true,
      certificate: true,
      key: true,
      timestamp: cert.updated_at || cert.created_at,
      detail: `${cert.issuer || ''} ${cert.subject || ''} expires:${cert.not_after || ''}`,
    })
  }

  for (const key of generatedKeys || []) {
    const label = recordOf(key.label)
    const metadata = recordOf(key.metadata)
    const algorithm = textValue(key.algorithm, 'Generated key')
    const status = String(key.status || 'active').toLowerCase()
    const expired = key.expires_at && dateMs(key.expires_at) < now
    const expiring = key.expires_at && dateMs(key.expires_at) < now + 30 * ONE_DAY_MS
    const revoked = Boolean(key.revoked_at || /revoked|compromised|expired/.test(status))
    const weak = isWeakCrypto(algorithm, numberValue(key.bit_length))
    addSignal({
      id: `key-${key.id}`,
      sourceTable: 'generated_keys',
      pillar: 'Key Lifecycle',
      title: algorithm,
      subject: firstString(label, ['purpose', 'common_name', 'token_id']) || algorithm,
      subjectType: textValue(key.entropy_source, 'Generated Key'),
      provider: inferProvider(`${JSON.stringify(label)} ${JSON.stringify(metadata)}`),
      region: inferRegion(`${JSON.stringify(label)} ${JSON.stringify(metadata)}`),
      algorithm,
      keySize: key.bit_length,
      status: revoked ? 'revoked' : expired ? 'expired' : status,
      severity: revoked || weak ? 'high' : expiring ? 'medium' : 'low',
      encrypted: true,
      pqcReady: isPqcAlgorithm(algorithm),
      weak,
      expiring: Boolean(expiring),
      key: true,
      cloud: inferProvider(`${JSON.stringify(label)} ${JSON.stringify(metadata)}`) !== 'Private / Hybrid',
      timestamp: key.updated_at || key.created_at,
      detail: `${key.bit_length || ''} ${key.entropy_source || ''} quality:${key.quality_score || ''}`,
    })
  }

  for (const connector of connectorAccounts || []) {
    const metadata = recordOf(connector.metadata)
    const policy = recordOf(connector.policy)
    const provider = textValue(connector.provider, inferProvider(`${connector.display_name || ''} ${JSON.stringify(metadata)}`))
    const healthy = /connected|active|healthy|ok|synced/i.test(String(connector.status || ''))
    addSignal({
      id: `connector-${connector.id}`,
      sourceTable: 'connector_accounts',
      pillar: 'Cloud Connector',
      title: `${provider} connector`,
      subject: textValue(connector.display_name, provider),
      subjectType: 'Cloud Connector',
      provider: provider.toUpperCase().includes('AWS') ? 'AWS' : provider.toLowerCase().includes('azure') ? 'Azure' : provider.toLowerCase().includes('gcp') || provider.toLowerCase().includes('google') ? 'GCP' : provider,
      region: firstString(metadata, ['region', 'location']) || inferRegion(JSON.stringify(metadata)),
      status: healthy ? 'synchronized' : 'review',
      severity: healthy ? 'low' : 'medium',
      encrypted: true,
      pqcReady: /pqc|kms|kyber|ml-kem/i.test(JSON.stringify(metadata) + JSON.stringify(policy)),
      weak: !healthy,
      cloud: true,
      timestamp: connector.last_sync_at || connector.updated_at || connector.created_at,
      detail: `${connector.provider || ''} ${connector.status || ''}`,
    })
  }

  for (const agent of scannerAgents || []) {
    const online = /online|active|healthy|running/i.test(String(agent.status || '')) || dateMs(agent.last_seen_at || agent.updated_at) >= now - 15 * 60 * 1000
    addSignal({
      id: `agent-${agent.id}`,
      sourceTable: 'scanner_agents',
      pillar: 'Runtime Source',
      title: online ? 'Collector online' : 'Collector stale',
      subject: textValue(agent.name, textValue(agent.hostname, 'Scanner agent')),
      subjectType: textValue(agent.platform, 'Collector'),
      status: textValue(agent.status, online ? 'online' : 'stale'),
      severity: online ? 'low' : 'medium',
      encrypted: true,
      weak: !online,
      runtime: true,
      cloud: inferProvider(`${agent.hostname || ''} ${agent.platform || ''} ${JSON.stringify(recordOf(agent.metadata))}`) !== 'Private / Hybrid',
      provider: inferProvider(`${agent.hostname || ''} ${agent.platform || ''} ${JSON.stringify(recordOf(agent.metadata))}`),
      region: inferRegion(JSON.stringify(recordOf(agent.metadata))),
      timestamp: agent.last_seen_at || agent.updated_at || agent.created_at,
      detail: `${agent.hostname || ''} ${agent.platform || ''}`,
    })
  }

  for (const heartbeat of agentHeartbeats || []) {
    const telemetry = recordOf(heartbeat.telemetry)
    const healthy = !/error|offline|failed/i.test(String(heartbeat.status || ''))
    addSignal({
      id: `heartbeat-${heartbeat.id}`,
      sourceTable: 'agent_heartbeats',
      pillar: 'Runtime Heartbeat',
      title: 'Agent heartbeat',
      subject: textValue(heartbeat.agent_id, 'Agent heartbeat'),
      subjectType: 'Heartbeat',
      status: textValue(heartbeat.status, healthy ? 'healthy' : 'review'),
      severity: healthy ? 'low' : 'medium',
      encrypted: true,
      weak: !healthy,
      runtime: true,
      cloud: inferProvider(JSON.stringify(telemetry)) !== 'Private / Hybrid',
      provider: inferProvider(JSON.stringify(telemetry)),
      region: inferRegion(JSON.stringify(telemetry)),
      timestamp: heartbeat.observed_at || heartbeat.created_at,
      detail: Object.values(telemetry).filter((value) => typeof value === 'string').slice(0, 5).join(' '),
    })
  }

  for (const event of qrngEvents || []) {
    const metadata = recordOf(event.metadata)
    const ok = !/fail|error|fallback/i.test(`${event.status || ''} ${event.event_type || ''} ${JSON.stringify(metadata)}`)
    addSignal({
      id: `qrng-${event.id}`,
      sourceTable: 'qrng_events',
      pillar: 'Key Entropy',
      title: event.event_type || 'QRNG event',
      subject: firstString(metadata, ['algorithm', 'purpose', 'consumer']) || 'Entropy event',
      subjectType: 'Entropy',
      status: textValue(event.status, ok ? 'approved' : 'review'),
      severity: ok ? 'low' : 'medium',
      encrypted: true,
      pqcReady: true,
      weak: !ok,
      key: true,
      timestamp: event.created_at,
      detail: Object.values(metadata).filter((value) => typeof value === 'string').slice(0, 5).join(' '),
    })
  }

  for (const log of vaultAuditLogs || []) {
    const metadata = recordOf(log.metadata)
    const text = `${log.event_type || ''} ${log.description || log.details || ''} ${JSON.stringify(metadata)}`
    const ok = !/fail|error|denied|destroyed|revoked/i.test(text)
    addSignal({
      id: `vault-${log.id}`,
      sourceTable: 'vault_audit_logs',
      pillar: isKeyText(text) ? 'Key Audit' : 'Vault Audit',
      title: log.event_type || log.operation || 'Vault audit',
      subject: textValue(log.resource_type, textValue(log.file_id, 'Vault event')),
      subjectType: 'Vault Audit',
      status: textValue(log.result || log.status, ok ? 'success' : 'review'),
      severity: log.severity || (ok ? 'low' : 'medium'),
      encrypted: true,
      pqcReady: /ml-kem|pqc|quantum/i.test(JSON.stringify(metadata)),
      weak: !ok,
      key: isKeyText(text),
      timestamp: log.created_at,
      detail: `${log.description || log.details || ''} ${log.ip_address || ''}`,
    })
  }

  for (const item of complianceEvidence || []) {
    const passed = /pass|met|compliant|approved|complete/i.test(String(item.status || ''))
    addSignal({
      id: `compliance-${item.id}`,
      sourceTable: 'compliance_evidence',
      pillar: 'Compliance Evidence',
      title: `${item.framework || 'Compliance'} ${item.control_id || ''}`.trim(),
      subject: textValue(item.description, textValue(item.control_id, 'Compliance evidence')),
      subjectType: textValue(item.evidence_type, 'Compliance'),
      status: textValue(item.status, passed ? 'passed' : 'review'),
      severity: passed ? 'low' : 'medium',
      encrypted: true,
      weak: !passed,
      api: /api|tls|transport/i.test(`${item.framework || ''} ${item.control_id || ''} ${item.description || ''}`),
      certificate: /cert|tls/i.test(`${item.framework || ''} ${item.control_id || ''} ${item.description || ''}`),
      key: /key|crypto|kms/i.test(`${item.framework || ''} ${item.control_id || ''} ${item.description || ''}`),
      timestamp: item.updated_at || item.created_at,
      detail: `${item.framework || ''} ${item.control_id || ''} ${item.evidence_type || ''}`,
    })
  }

  for (const job of migrationJobs || []) {
    const complete = /done|complete|success|migrated/i.test(String(job.status || ''))
    addSignal({
      id: `migration-${job.id}`,
      sourceTable: 'migration_jobs',
      pillar: 'Migration Telemetry',
      title: complete ? 'Migration completed' : 'Migration pending',
      subject: assetName(job.asset_id, 'Migration job'),
      subjectType: 'Migration',
      assetId: job.asset_id,
      algorithm: textValue(job.algorithm_to, textValue(job.algorithm_from)),
      status: textValue(job.status, complete ? 'completed' : 'pending'),
      severity: complete ? 'low' : job.priority || 'medium',
      encrypted: true,
      pqcReady: complete || isPqcAlgorithm(`${job.algorithm_to || ''}`),
      weak: !complete,
      key: isKeyText(`${job.algorithm_from || ''} ${job.algorithm_to || ''}`),
      timestamp: job.updated_at || job.created_at,
      detail: `${job.algorithm_from || ''} -> ${job.algorithm_to || ''}`,
    })
  }

  for (const event of securityEvents || []) {
    const metadata = recordOf(event.metadata)
    const text = `${event.event_type || ''} ${event.message || ''} ${JSON.stringify(metadata)}`
    const ok = !/fail|error|denied|suspicious/i.test(text)
    addSignal({
      id: `security-${event.id}`,
      sourceTable: 'security_events',
      pillar: 'Security Event',
      title: event.event_type || event.action || 'Security event',
      subject: textValue(event.ip_address, 'Security activity'),
      subjectType: 'Security Event',
      status: ok ? 'observed' : 'review',
      severity: event.severity,
      encrypted: true,
      weak: !ok,
      api: isApiText(text),
      cloud: inferProvider(text) !== 'Private / Hybrid',
      provider: inferProvider(text),
      region: inferRegion(text),
      timestamp: event.created_at,
      detail: `${event.message || ''} ${event.user_agent || ''}`,
    })
  }

  signals.sort((a, b) => b.ms - a.ms)
  const current = signals.filter((signal) => signal.ms >= recentStart)
  const previous = signals.filter((signal) => signal.ms >= previousStart && signal.ms < recentStart)
  const runtimeSignals = signals.filter((signal) => signal.runtime)
  const certificateSignals = signals.filter((signal) => signal.certificate)
  const keySignals = signals.filter((signal) => signal.key)
  const apiSignals = signals.filter((signal) => signal.api)
  const cloudSignals = signals.filter((signal) => signal.cloud)
  const highRisk = signals.filter((signal) => severityRank(signal.severity) >= 3 || signal.riskScore >= 68)
  const weak = signals.filter((signal) => signal.weak)
  const encrypted = signals.filter((signal) => signal.encrypted)
  const pqcReady = signals.filter((signal) => signal.pqcReady)
  const stale = signals.filter((signal) => signal.ms && signal.ms < staleStart)
  const expiringCertificates = certificateSignals.filter((signal) => signal.expiring || /expir/i.test(signal.status))
  const weakKeys = keySignals.filter((signal) => signal.weak)
  const total = signals.length

  const timelineStart = new Date()
  timelineStart.setHours(0, 0, 0, 0)
  timelineStart.setDate(timelineStart.getDate() - 6)
  const timeline = Array.from({ length: 7 }, (_, index) => {
    const start = timelineStart.getTime() + index * ONE_DAY_MS
    const end = start + ONE_DAY_MS
    const bucket = signals.filter((signal) => signal.ms >= start && signal.ms < end)
    return {
      label: new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      runtime: bucket.filter((signal) => signal.runtime).length,
      secure: bucket.filter((signal) => signal.encrypted && !signal.weak).length,
      risk: bucket.filter((signal) => signal.weak || severityRank(signal.severity) >= 2).length,
      certificates: bucket.filter((signal) => signal.certificate).length,
      keys: bucket.filter((signal) => signal.key).length,
      api: bucket.filter((signal) => signal.api).length,
      cloud: bucket.filter((signal) => signal.cloud).length,
    }
  })

  const groupRows = (items: Signal[], keyFn: (signal: Signal) => string, limit = 12) => countBy(items, keyFn, limit).map((row) => {
    const scoped = items.filter((signal) => keyFn(signal) === row.label)
    return {
      ...row,
      secure: scoped.filter((signal) => signal.encrypted && !signal.weak).length,
      weak: scoped.filter((signal) => signal.weak).length,
      pqcReady: scoped.filter((signal) => signal.pqcReady).length,
      riskScore: clamp(scoped.reduce((sum, signal) => sum + signal.riskScore, 0) / Math.max(1, scoped.length)),
      latestSeen: latestDate(...scoped.map((signal) => signal.timestamp)),
    }
  })

  const inventory = signals
    .slice()
    .sort((a, b) => b.riskScore - a.riskScore || b.ms - a.ms)
    .slice(0, 24)
    .map((signal) => ({
      id: signal.id,
      pillar: signal.pillar,
      title: signal.title,
      subject: signal.subject,
      subjectType: signal.subjectType,
      provider: signal.provider,
      region: signal.region,
      protocol: signal.protocol,
      algorithm: signal.algorithm,
      keySize: signal.keySize,
      status: signal.status,
      severity: signal.severity,
      riskScore: signal.riskScore,
      encrypted: signal.encrypted,
      pqcReady: signal.pqcReady,
      weak: signal.weak,
      expiring: signal.expiring,
      source: signal.sourceTable,
      timestamp: signal.timestamp,
      detail: signal.detail,
    }))

  const alerts = signals
    .filter((signal) => signal.weak || signal.expiring || severityRank(signal.severity) >= 2 || signal.riskScore >= 38)
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.riskScore - a.riskScore || b.ms - a.ms)
    .slice(0, 18)
    .map((signal) => ({
      id: signal.id,
      title: signal.title,
      detail: `${signal.subject} - ${signal.detail || signal.pillar}`,
      severity: signal.severity,
      timestamp: signal.timestamp,
      source: signal.sourceTable,
      pillar: signal.pillar,
    }))

  const recommendations = [
    highRisk.length > 0 && {
      id: 'resolve-high-risk-observability',
      title: 'Investigate high-risk cryptographic telemetry',
      detail: `${highRisk.length} high-risk runtime, key, certificate, API, or cloud signal${highRisk.length === 1 ? '' : 's'} need triage.`,
      impact: 'high',
      count: highRisk.length,
      actionHref: '/dashboard/telemetry-correlation',
    },
    expiringCertificates.length > 0 && {
      id: 'renew-expiring-certificates',
      title: 'Renew expiring certificates',
      detail: `${expiringCertificates.length} certificate signal${expiringCertificates.length === 1 ? '' : 's'} indicate expiry or lifecycle risk.`,
      impact: 'medium',
      count: expiringCertificates.length,
      actionHref: '/dashboard/certificate-telemetry',
    },
    weakKeys.length > 0 && {
      id: 'rotate-weak-keys',
      title: 'Rotate weak or exposed keys',
      detail: `${weakKeys.length} key lifecycle signal${weakKeys.length === 1 ? '' : 's'} require rotation or PQC migration.`,
      impact: 'high',
      count: weakKeys.length,
      actionHref: '/dashboard/key-analytics',
    },
    apiSignals.filter((signal) => signal.weak || !signal.encrypted).length > 0 && {
      id: 'enforce-api-encryption',
      title: 'Enforce API transport encryption',
      detail: `${apiSignals.filter((signal) => signal.weak || !signal.encrypted).length} API encryption signal${apiSignals.filter((signal) => signal.weak || !signal.encrypted).length === 1 ? '' : 's'} show weak transport posture.`,
      impact: 'medium',
      count: apiSignals.filter((signal) => signal.weak || !signal.encrypted).length,
      actionHref: '/dashboard/api-encryption',
    },
    stale.length > 0 && {
      id: 'refresh-stale-observability',
      title: 'Refresh stale observability evidence',
      detail: `${stale.length} telemetry signal${stale.length === 1 ? '' : 's'} are older than 30 days.`,
      impact: 'low',
      count: stale.length,
      actionHref: '/dashboard/scanner',
    },
  ].filter(Boolean)

  const eventPipelineStatus = current.length
    ? 'active'
    : total
      ? 'inventory_only'
      : scannerAgents.length || connectorAccounts.length
        ? 'waiting_for_events'
        : 'no_sources'

  return {
    generatedAt: new Date().toISOString(),
    latestActivityAt: latestDate(...signals.slice(0, 100).map((signal) => signal.timestamp)),
    metrics: {
      totalSignals: total,
      signalDelta: deltaPercent(current.length, previous.length),
      runtimeEvents: runtimeSignals.length,
      activeProcesses: new Set(runtimeSignals.map((signal) => signal.subject)).size,
      anomalies: weak.length,
      encryptedCoverage: percentOf(encrypted.length, total),
      riskScore: clamp(highRisk.reduce((sum, signal) => sum + signal.riskScore, 0) / Math.max(1, highRisk.length)),
      assetsCovered: new Set(signals.map((signal) => signal.subject).filter(Boolean)).size,
      certificates: certificateSignals.length,
      expiringCertificates: expiringCertificates.length,
      certificateCompliance: percentOf(certificateSignals.filter((signal) => !signal.weak && !signal.expiring).length, certificateSignals.length),
      keys: keySignals.length,
      activeKeys: keySignals.filter((signal) => /active|protected|approved|observed/i.test(signal.status) && !signal.weak).length,
      rotatedKeys: keySignals.filter((signal) => /rotat|migration|wrap|unwrap/i.test(`${signal.title} ${signal.detail} ${signal.status}`)).length,
      weakKeys: weakKeys.length,
      keyPqcReadiness: percentOf(keySignals.filter((signal) => signal.pqcReady).length, keySignals.length),
      apiEvents: apiSignals.length,
      apiSecureRate: percentOf(apiSignals.filter((signal) => signal.encrypted && !signal.weak).length, apiSignals.length),
      apiPolicyViolations: apiSignals.filter((signal) => signal.weak || !signal.encrypted || severityRank(signal.severity) >= 2).length,
      cloudProviders: new Set(cloudSignals.map((signal) => signal.provider).filter(Boolean)).size,
      cloudRegions: new Set(cloudSignals.map((signal) => signal.region).filter(Boolean)).size,
      cloudAssets: cloudSignals.length,
      cloudTrustScore: percentOf(cloudSignals.filter((signal) => signal.encrypted && !signal.weak).length, cloudSignals.length),
      highRiskFindings: highRisk.length,
      activeSources: scannerAgents.length + connectorAccounts.length,
      pqcReadiness: percentOf(pqcReady.length, total),
      staleSignals: stale.length,
    },
    timeline,
    runtimeRows: groupRows(runtimeSignals, (signal) => signal.subject, 14),
    certificateRows: groupRows(certificateSignals, (signal) => signal.subject, 14),
    keyRows: groupRows(keySignals, (signal) => signal.algorithm || signal.subject, 14),
    apiRows: groupRows(apiSignals, (signal) => signal.protocol || signal.subject, 14),
    cloudRows: groupRows(cloudSignals, (signal) => signal.provider, 10),
    regionRows: groupRows(cloudSignals, (signal) => signal.region, 10),
    protocolDistribution: countBy(signals, (signal) => signal.protocol, 8),
    algorithmDistribution: countBy(signals, (signal) => signal.algorithm || 'Unknown Algorithm', 8),
    providerDistribution: countBy(cloudSignals, (signal) => signal.provider, 8),
    severityDistribution: countBy(signals, (signal) => titleCase(signal.severity), 5),
    statusDistribution: countBy(signals, (signal) => titleCase(signal.status), 8),
    sourceDistribution: countBy(signals, (signal) => signal.sourceTable, 10),
    alerts,
    recommendations,
    activity: signals.slice(0, 18).map((signal) => ({
      id: signal.id,
      title: signal.title,
      detail: `${signal.subject} - ${signal.pillar}`,
      severity: signal.severity,
      timestamp: signal.timestamp,
      source: signal.sourceTable,
    })),
    inventory,
    telemetry: {
      assets: assets.length,
      runtimeEvents: runtimeEvents.length,
      scannerEvidence: scannerEvidence.length,
      scannerAlerts: scannerAlerts.length,
      scanResults: scanResults.length,
      cryptoInventory: cryptoInventory.length,
      cryptoExposures: cryptoExposures.length,
      certificates: certificates.length,
      generatedKeys: generatedKeys.length,
      scannerAgents: scannerAgents.length,
      connectors: connectorAccounts.length,
      agentHeartbeats: agentHeartbeats.length,
      qrngEvents: qrngEvents.length,
      vaultAuditLogs: vaultAuditLogs.length,
      complianceEvidence: complianceEvidence.length,
      migrationJobs: migrationJobs.length,
      securityEvents: securityEvents.length,
      eventPipelineStatus,
      latestRuntimeEventAt: latestDate(...runtimeEvents.map((event: any) => event.observed_at || event.created_at)),
    },
  }
}

export const runtimeTelemetryRoutes = buildRouter('runtime')
export const certificateTelemetryRoutes = buildRouter('certificate')
export const keyAnalyticsRoutes = buildRouter('keys')
export const apiEncryptionRoutes = buildRouter('api')
export const multiCloudTelemetryRoutes = buildRouter('cloud')
