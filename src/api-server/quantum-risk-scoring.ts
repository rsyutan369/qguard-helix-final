import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'

const router = Router()
const ONE_DAY_MS = 24 * 60 * 60 * 1000

type Severity = 'critical' | 'high' | 'medium' | 'low'
type RiskCategory =
  | 'Cryptographic Vulnerabilities'
  | 'PQC Readiness'
  | 'Protocol & TLS Security'
  | 'Key & Certificate Health'
  | 'Algorithm Strength'
  | 'Other Factors'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

type RiskFinding = {
  id: string
  sourceTable: string
  assetId: string | null
  assetName: string
  assetType: string
  factor: string
  category: RiskCategory
  severity: Severity
  riskScore: number
  timestamp: string | null
  ms: number
  region: string
  text: string
}

type CryptoObservation = {
  id: string
  safe: boolean
  timestamp: string | null
  ms: number
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

router.use(requireAuth)

function recordOf(value: unknown): Record<string, unknown> {
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

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
}

function titleCase(value: unknown, fallback = 'Observed Finding') {
  const text = String(value || fallback)
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return text.replace(/\b\w/g, (char) => char.toUpperCase()) || fallback
}

function deltaPercent(current: number, previous: number) {
  if (previous <= 0) return current > 0 ? 100 : 0
  return Math.round(((current - previous) / previous) * 100)
}

function normalizeSeverity(value: unknown): Severity {
  const lower = String(value || '').toLowerCase()
  if (lower === 'critical') return 'critical'
  if (lower === 'high' || lower === 'error' || lower === 'failed') return 'high'
  if (lower === 'medium' || lower === 'moderate' || lower === 'warning') return 'medium'
  return 'low'
}

function severityRank(severity: unknown) {
  const value = String(severity || '').toLowerCase()
  if (value === 'critical') return 4
  if (value === 'high') return 3
  if (value === 'medium' || value === 'moderate' || value === 'warning') return 2
  if (value === 'low') return 1
  return 0
}

function riskForSeverity(severity: Severity) {
  if (severity === 'critical') return 96
  if (severity === 'high') return 84
  if (severity === 'medium') return 62
  return 24
}

function levelForScore(score: number) {
  if (score >= 90) return 'Critical'
  if (score >= 75) return 'High'
  if (score >= 55) return 'Medium'
  if (score >= 30) return 'Low'
  return 'Minimal'
}

function impactForScore(score: number) {
  if (score >= 75) return 'High'
  if (score >= 45) return 'Medium'
  return 'Low'
}

function isPqcAlgorithm(value: string) {
  return /ml-kem|ml_dsa|ml-dsa|kyber|dilithium|sphincs|falcon|bike|hqc|ntru|hybrid|pqc|post.quantum/i.test(value)
}

function isLegacyAlgorithm(value: string) {
  return /rsa|rs256|ecdsa|ecdh|dh-|dsa|sha-1|sha1|md5|des|3des|rc4|aes-128-cbc|tls\s*1\.[012]|ssl|weak cipher|cbc/i.test(value)
}

function isOutdatedProtocol(value: string) {
  return /tls\s*1\.[01]|ssl|rc4|3des|des|cbc|sha1|md5|weak tls|deprecated protocol/i.test(value)
}

// Quantum threat-model classes. Shor's algorithm breaks the public-key trust
// fabric (RSA/ECC/DH key exchange and signatures) outright, while Grover's
// only halves symmetric search margins — two very different migration
// urgencies that must never be lumped into one "weak crypto" bucket.
type ThreatClass = 'shor' | 'grover' | 'hash' | 'pqc' | 'unclassified'

function threatClassFor(value: string): ThreatClass {
  const lower = value.toLowerCase()
  if (isPqcAlgorithm(lower)) return 'pqc'
  if (/\brsa\b|rsa-?\d|rs256|ps256|ecdsa|ecdh|\becc\b|ed25519|x25519|secp\d|prime256|p-256|p-384|p-521|diffie|dhe?\b|dh-|\bdsa\b/.test(lower)) return 'shor'
  if (/aes[-_ ]?128|3des|\bdes\b|rc4|blowfish|idea|\b128[- ]?bit key|camellia-?128/.test(lower)) return 'grover'
  if (/sha-?1\b|\bmd5\b|\bmd4\b|ripemd/.test(lower)) return 'hash'
  return 'unclassified'
}

function hasHndlSignal(value: string) {
  return /hndl|harvest now|decrypt later|long.term|long lived|sensitive|regulated|financial|health|pii|confidential/i.test(value)
}

function normalizeRegion(value: unknown) {
  const text = String(value || '').toLowerCase()
  if (/us|ca|north america|virginia|oregon|ohio|california|canada/.test(text)) return 'North America'
  if (/eu|europe|london|frankfurt|paris|ireland|amsterdam/.test(text)) return 'Europe'
  if (/asia|apac|singapore|tokyo|seoul|mumbai|hong kong|china|india/.test(text)) return 'Asia'
  if (/au|australia|sydney|oceania/.test(text)) return 'Oceania'
  if (/br|south america|sao paulo|brazil|latam/.test(text)) return 'South America'
  if (/africa|cape town|me-south|uae|dubai/.test(text)) return 'Africa'
  return 'Global'
}

function categoryForFactor(factor: string, text: string): RiskCategory {
  const haystack = `${factor} ${text}`.toLowerCase()
  if (/pqc|hybrid|post.quantum|readiness/.test(haystack)) return 'PQC Readiness'
  if (/tls|protocol|cipher|ssl/.test(haystack)) return 'Protocol & TLS Security'
  if (/key|certificate|cert|rotation|vault|issuer|expiry|expired/.test(haystack)) return 'Key & Certificate Health'
  if (/algorithm|rsa|ecc|ecdsa|sha|md5|strength|weak/.test(haystack)) return 'Algorithm Strength'
  if (/crypto|exposure|vulnerab|legacy|hndl/.test(haystack)) return 'Cryptographic Vulnerabilities'
  return 'Other Factors'
}

function classifyFactor(text: string, fallback = 'Cryptographic Telemetry') {
  const lower = text.toLowerCase()
  if (hasHndlSignal(lower)) return 'HNDL Exposure'
  if (/shadow/.test(lower)) return 'Shadow Crypto'
  if (/tls\s*1\.[01]|ssl|weak tls|rc4|3des|cbc/.test(lower)) return 'Weak TLS Protocol'
  if (/certificate|cert|issuer|subject|expired|expiring|revoked/.test(lower)) return 'Certificate Health'
  if (/rsa|ecc|ecdsa|ecdh|dsa|sha1|sha-1|md5/.test(lower)) return 'RSA & ECC Usage'
  if (/key|rotation|entropy|vault|revoked/.test(lower)) return 'Key Management'
  if (/pqc|hybrid|post.quantum|kyber|dilithium|ml-kem|ml-dsa/.test(lower)) return 'PQC Readiness'
  if (/sprawl|unmanaged|unknown|inventory/.test(lower)) return 'Crypto Sprawl'
  return fallback
}

function firstStringValue(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = textValue(record[key])
    if (value) return value
  }
  return ''
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Quantum risk scoring ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Quantum risk scoring ${table} query failed:`, error?.message || error)
    return []
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
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
}

async function buildQuantumRiskSnapshot(token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) {
    throw new Error('Database connection failed')
  }

  const [
    assets,
    runtimeEvents,
    scannerAlerts,
    scannerEvidence,
    scannerAgents,
    connectorAccounts,
    scanResults,
    scanSessions,
    exposures,
    inventory,
    securityEvents,
    generatedKeys,
    certificates,
    qrngEvents,
    vaultAuditLogs,
    agentHeartbeats,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, package_name, package_version, process_name, process_id, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(5000)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'scanner_evidence', (q) => q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, package_name, package_version, confidence, raw_evidence, processed_at, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1800)),
    safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, capabilities, last_seen_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(400)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, provider_account_id, display_name, status, scopes, capabilities, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(400)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(180)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(2000)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'qrng_events', (q) => q.select('id, event_type, key_type, algorithm, key_length, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(800)),
    safeRows(client, 'vault_audit_logs', (q) => q.select('id, event_type, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(800)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('id, agent_id, status, telemetry, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1200)),
  ])

  const now = Date.now()
  const current7dStart = now - 7 * ONE_DAY_MS
  const previous7dStart = now - 14 * ONE_DAY_MS
  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
  const agentMap = new Map<string, any>((scannerAgents || []).map((agent: any) => [agent.id, agent]))
  const connectorMap = new Map<string, any>((connectorAccounts || []).map((connector: any) => [connector.id, connector]))
  const findings: RiskFinding[] = []
  const observations: CryptoObservation[] = []
  const seen = new Set<string>()

  const assetMetadata = (assetId: unknown) => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return recordOf(asset?.metadata)
  }

  const assetName = (assetId: unknown, fallback = 'Unmapped asset') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.name, fallback)
  }

  const assetType = (assetId: unknown, fallback = 'Asset') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return titleCase(textValue(asset?.type, fallback), fallback)
  }

  const regionFor = (assetId: unknown, metadata: Record<string, unknown> = {}) => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    const assetMeta = recordOf(asset?.metadata)
    return normalizeRegion(asset?.region || assetMeta.region || assetMeta.location || metadata.region || metadata.location || metadata.cloudRegion)
  }

  const sourceNameFromIds = (agentId: unknown, connectorId: unknown, fallback = 'Telemetry source') => {
    const agent = typeof agentId === 'string' ? agentMap.get(agentId) : null
    if (agent) return textValue(agent.name, textValue(agent.hostname, fallback))
    const connector = typeof connectorId === 'string' ? connectorMap.get(connectorId) : null
    if (connector) return textValue(connector.display_name, textValue(connector.provider, fallback))
    return fallback
  }

  const observe = (id: string, algorithmText: string, timestamp: string | null, explicitSafe?: boolean) => {
    const text = algorithmText || ''
    if (!text.trim()) return
    observations.push({
      id,
      safe: typeof explicitSafe === 'boolean' ? explicitSafe : isPqcAlgorithm(text) && !isLegacyAlgorithm(text),
      timestamp,
      ms: dateMs(timestamp),
    })
  }

  const addFinding = (input: {
    id: string
    sourceTable: string
    assetId?: string | null
    assetName?: string
    assetType?: string
    factor?: string
    category?: RiskCategory
    severity?: unknown
    riskScore?: unknown
    timestamp?: string | null
    region?: string
    text?: string
  }) => {
    if (seen.has(input.id)) return
    seen.add(input.id)

    const severity = normalizeSeverity(input.severity)
    const text = String(input.text || '')
    const factor = input.factor || classifyFactor(text)
    const score = clamp(numberValue(input.riskScore, riskForSeverity(severity)))
    const meta = assetMetadata(input.assetId)

    findings.push({
      id: input.id,
      sourceTable: input.sourceTable,
      assetId: input.assetId || null,
      assetName: textValue(input.assetName, assetName(input.assetId, firstStringValue(meta, ['assetName', 'hostname', 'target']) || 'Unmapped asset')),
      assetType: titleCase(textValue(input.assetType, assetType(input.assetId, firstStringValue(meta, ['assetType', 'resourceType']) || 'Asset'))),
      factor,
      category: input.category || categoryForFactor(factor, text),
      severity,
      riskScore: score,
      timestamp: input.timestamp || null,
      ms: dateMs(input.timestamp),
      region: input.region || regionFor(input.assetId, meta),
      text,
    })
  }

  for (const event of runtimeEvents || []) {
    const metadata = recordOf(event.metadata)
    const text = `${event.event_type || ''} ${event.operation_type || ''} ${event.algorithm || ''} ${event.key_exchange_algorithm || ''} ${event.cipher_suite || ''} ${event.tls_version || ''} ${event.protocol || ''} ${event.package_name || ''} ${event.process_name || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`
    const timestamp = event.observed_at || event.created_at
    observe(`runtime-${event.id}`, `${event.algorithm || ''} ${event.key_exchange_algorithm || ''} ${event.cipher_suite || ''} ${event.tls_version || ''}`, timestamp, Boolean(event.is_pqc))
    const risky = Boolean(event.is_legacy || event.downgrade_detected || event.shadow_crypto || event.hndl_risk || isLegacyAlgorithm(text) || isOutdatedProtocol(text) || severityRank(event.severity) >= 2)
    addFinding({
      id: `runtime-${event.id}`,
      sourceTable: 'runtime_crypto_events',
      assetId: event.asset_id,
      assetName: textValue(event.asset_name, textValue(event.host, textValue(event.process_name, sourceNameFromIds(event.agent_id, event.connector_account_id)))),
      assetType: textValue(event.asset_type, textValue(event.source_type, textValue(event.protocol, 'Runtime Asset'))),
      factor: classifyFactor(text, risky ? 'Runtime Crypto Risk' : 'Runtime Crypto Telemetry'),
      severity: event.severity || (risky ? 'medium' : 'low'),
      riskScore: event.risk_score || (risky ? undefined : 12),
      timestamp,
      text,
    })
  }

  for (const evidence of scannerEvidence || []) {
    const text = `${evidence.evidence_type || ''} ${evidence.observed_algorithm || ''} ${evidence.protocol || ''} ${evidence.package_name || ''} ${evidence.target || ''} ${evidence.confidence || ''}`
    const timestamp = evidence.observed_at || evidence.processed_at || evidence.created_at
    observe(`evidence-${evidence.id}`, `${evidence.observed_algorithm || ''} ${evidence.protocol || ''}`, timestamp)
    addFinding({
      id: `evidence-${evidence.id}`,
      sourceTable: 'scanner_evidence',
      assetName: textValue(evidence.asset_name, textValue(evidence.host, textValue(evidence.target, 'Scanner evidence'))),
      assetType: textValue(evidence.asset_type, `${evidence.evidence_type || ''} ${evidence.protocol || ''}`),
      factor: classifyFactor(text, 'Scanner Evidence'),
      severity: isLegacyAlgorithm(text) || isOutdatedProtocol(text) ? 'medium' : 'low',
      riskScore: isLegacyAlgorithm(text) || isOutdatedProtocol(text) ? undefined : 18,
      timestamp,
      text,
    })
  }

  for (const alert of scannerAlerts || []) {
    const metadata = recordOf(alert.metadata)
    const text = `${alert.title || ''} ${alert.category || ''} ${alert.message || ''} ${alert.recommendation || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`
    addFinding({
      id: `scanner-alert-${alert.id}`,
      sourceTable: 'scanner_alerts',
      assetName: textValue(metadata.assetName || metadata.resourceName || metadata.hostname || metadata.target, textValue(alert.category, 'Scanner alert')),
      assetType: textValue(metadata.assetType || metadata.resourceType, textValue(alert.category, 'Scanner Asset')),
      factor: classifyFactor(text, titleCase(alert.category, 'Scanner Alert')),
      severity: alert.severity,
      timestamp: alert.updated_at || alert.created_at,
      text,
    })
  }

  for (const result of scanResults || []) {
    const text = `${result.finding_type || ''} ${result.algorithm || ''} ${result.description || ''} ${result.threat_level || ''} ${result.remediation || ''}`
    const timestamp = result.created_at
    observe(`scan-result-${result.id}`, `${result.algorithm || ''}`, timestamp)
    addFinding({
      id: `scan-result-${result.id}`,
      sourceTable: 'pqc_scan_results',
      assetId: result.asset_id,
      assetName: assetName(result.asset_id, 'Scan finding'),
      assetType: assetType(result.asset_id, 'Scanned Asset'),
      factor: classifyFactor(text, titleCase(result.finding_type, 'Scan Finding')),
      severity: result.threat_level,
      timestamp,
      text,
    })
  }

  for (const exposure of exposures || []) {
    const text = `${exposure.exposure_type || ''} ${exposure.description || ''} ${exposure.detected_value || ''}`
    addFinding({
      id: `exposure-${exposure.id}`,
      sourceTable: 'crypto_exposures',
      assetId: exposure.asset_id,
      factor: classifyFactor(text, titleCase(exposure.exposure_type, 'Crypto Exposure')),
      severity: exposure.severity,
      timestamp: exposure.updated_at || exposure.created_at,
      text,
    })
  }

  for (const item of inventory || []) {
    const text = `${item.item_type || ''} ${item.name || ''} ${item.algorithm || ''} ${item.protocol || ''} ${item.exposure_level || ''}`
    const timestamp = item.discovered_at || item.created_at
    observe(`inventory-${item.id}`, `${item.algorithm || ''} ${item.protocol || ''}`, timestamp, Boolean(item.is_quantum_safe))
    addFinding({
      id: `inventory-${item.id}`,
      sourceTable: 'crypto_inventory',
      assetId: item.asset_id,
      assetName: textValue(item.name, assetName(item.asset_id, 'Inventory item')),
      assetType: textValue(item.item_type, assetType(item.asset_id, 'Inventory Asset')),
      factor: classifyFactor(text, item.is_quantum_safe ? 'PQC Readiness' : 'Crypto Inventory Risk'),
      severity: item.is_vulnerable && !item.is_quantum_safe ? item.exposure_level || 'medium' : 'low',
      riskScore: item.is_vulnerable && !item.is_quantum_safe ? undefined : 14,
      timestamp,
      text,
    })
  }

  for (const event of securityEvents || []) {
    const metadata = recordOf(event.metadata)
    const text = `${event.event_type || ''} ${event.message || ''} ${event.resource_type || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`
    addFinding({
      id: `security-${event.id}`,
      sourceTable: 'security_events',
      assetId: event.asset_id,
      assetName: textValue(event.resource_name, assetName(event.asset_id, 'Security event')),
      assetType: textValue(event.resource_type, assetType(event.asset_id, 'Security Resource')),
      factor: classifyFactor(text, titleCase(event.event_type, 'Security Event')),
      severity: event.severity,
      riskScore: event.is_read ? 24 : undefined,
      timestamp: event.created_at,
      text,
    })
  }

  for (const key of generatedKeys || []) {
    const text = `${key.algorithm || ''} ${key.status || ''} ${key.bit_length || ''} ${key.entropy_source || ''} ${key.label || ''}`
    const timestamp = key.updated_at || key.created_at
    observe(`key-${key.id}`, `${key.algorithm || ''} ${key.entropy_source || ''}`, timestamp)
    const expired = key.expires_at && dateMs(key.expires_at) < now
    const revoked = String(key.status || '').toLowerCase().includes('revoked') || Boolean(key.revoked_at)
    const weak = isLegacyAlgorithm(text) || numberValue(key.quality_score, 1) < 0.7
    addFinding({
      id: `key-${key.id}`,
      sourceTable: 'generated_keys',
      assetName: textValue(key.label, 'Generated key'),
      assetType: 'Key Material',
      factor: classifyFactor(text, 'Key Management'),
      severity: revoked || expired ? 'medium' : weak ? 'medium' : 'low',
      riskScore: revoked || expired || weak ? undefined : 10,
      timestamp,
      text,
    })
  }

  for (const cert of certificates || []) {
    const text = `${cert.name || ''} ${cert.algorithm || ''} ${cert.status || ''} ${cert.issuer || ''} ${cert.subject || ''} ${cert.is_expiring_soon ? 'expiring soon' : ''}`
    const timestamp = cert.updated_at || cert.created_at
    observe(`certificate-${cert.id}`, `${cert.algorithm || ''}`, timestamp, Boolean(cert.is_quantum_safe))
    const risky = Boolean(cert.is_expiring_soon || !cert.is_quantum_safe || isLegacyAlgorithm(text))
    addFinding({
      id: `certificate-${cert.id}`,
      sourceTable: 'certificates',
      assetId: cert.asset_id,
      assetName: textValue(cert.name, textValue(cert.subject, assetName(cert.asset_id, 'Certificate'))),
      assetType: 'Certificate',
      factor: 'Certificate Health',
      severity: risky ? 'medium' : 'low',
      riskScore: risky ? undefined : 12,
      timestamp,
      text,
    })
  }

  for (const event of qrngEvents || []) {
    const text = `${event.event_type || ''} ${event.key_type || ''} ${event.algorithm || ''} ${event.key_length || ''}`
    observe(`qrng-${event.id}`, `${event.algorithm || ''} QRNG`, event.created_at, true)
  }

  for (const log of vaultAuditLogs || []) {
    const metadata = recordOf(log.metadata)
    const text = `${log.event_type || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`
    addFinding({
      id: `vault-${log.id}`,
      sourceTable: 'vault_audit_logs',
      assetName: textValue(metadata.resourceName || metadata.resource_name || metadata.fileName || metadata.file_name, 'Vault record'),
      assetType: 'Vault',
      factor: classifyFactor(text, 'Key Management'),
      severity: metadata.severity || metadata.result || metadata.status,
      riskScore: hasHndlSignal(text) ? 76 : 16,
      timestamp: log.created_at,
      text,
    })
  }

  for (const heartbeat of agentHeartbeats || []) {
    const agent = agentMap.get(heartbeat.agent_id) || {}
    const text = `${heartbeat.status || ''} ${Object.values(recordOf(heartbeat.telemetry)).filter((value) => typeof value === 'string').join(' ')}`
    const stale = dateMs(heartbeat.observed_at || heartbeat.created_at) > 0 && now - dateMs(heartbeat.observed_at || heartbeat.created_at) > ONE_DAY_MS
    addFinding({
      id: `heartbeat-${heartbeat.id}`,
      sourceTable: 'agent_heartbeats',
      assetName: textValue(agent.name, textValue(agent.hostname, 'Agent heartbeat')),
      assetType: textValue(agent.platform, 'Collector Agent'),
      factor: 'Telemetry Coverage',
      category: 'Other Factors',
      severity: String(heartbeat.status || '').toLowerCase().includes('error') || String(heartbeat.status || '').toLowerCase().includes('offline') || stale ? 'medium' : 'low',
      riskScore: stale ? 48 : 10,
      timestamp: heartbeat.observed_at || heartbeat.created_at,
      text,
    })
  }

  findings.sort((a, b) => b.ms - a.ms)
  observations.sort((a, b) => b.ms - a.ms)

  const current7d = findings.filter((finding) => finding.ms >= current7dStart)
  const previous7d = findings.filter((finding) => finding.ms >= previous7dStart && finding.ms < current7dStart)
  const currentRiskAvg = current7d.length ? current7d.reduce((sum, finding) => sum + finding.riskScore, 0) / current7d.length : 0
  const previousRiskAvg = previous7d.length ? previous7d.reduce((sum, finding) => sum + finding.riskScore, 0) / previous7d.length : 0

  type AssetScore = {
    id: string
    name: string
    type: string
    score: number
    region: string
    primaryRiskFactor: string
    latestAt: string | null
  }

  const assetScores = new Map<string, AssetScore>()
  for (const asset of assets || []) {
    const metadata = recordOf(asset.metadata)
    const criticalityBoost = /critical|high/i.test(String(asset.criticality || '')) ? 18 : /medium/i.test(String(asset.criticality || '')) ? 8 : 0
    assetScores.set(`asset:${asset.id}`, {
      id: asset.id,
      name: textValue(asset.name, 'Unnamed asset'),
      type: titleCase(asset.type, 'Asset'),
      score: criticalityBoost,
      region: normalizeRegion(asset.region || metadata.region || metadata.location),
      primaryRiskFactor: criticalityBoost ? 'Business Criticality' : 'No Active Finding',
      latestAt: asset.updated_at || asset.created_at || null,
    })
  }

  for (const finding of findings) {
    const key = finding.assetId ? `asset:${finding.assetId}` : `virtual:${finding.assetName}:${finding.assetType}`
    const existing = assetScores.get(key) || {
      id: key,
      name: finding.assetName,
      type: finding.assetType,
      score: 0,
      region: finding.region,
      primaryRiskFactor: finding.factor,
      latestAt: null,
    }

    if (finding.riskScore >= existing.score) {
      existing.score = finding.riskScore
      existing.primaryRiskFactor = finding.factor
    }
    existing.latestAt = latestDate(existing.latestAt, finding.timestamp)
    existing.region = existing.region || finding.region
    assetScores.set(key, existing)
  }

  const scoredAssets = Array.from(assetScores.values()).sort((a, b) => b.score - a.score || dateMs(b.latestAt) - dateMs(a.latestAt))
  const totalAssets = Math.max(assets.length, scoredAssets.length)
  const riskyAssets = scoredAssets.filter((asset) => asset.score >= 30)
  const assetAverage = scoredAssets.length ? scoredAssets.reduce((sum, asset) => sum + asset.score, 0) / scoredAssets.length : 0
  const highestScore = scoredAssets[0]?.score || 0
  const criticalExposureCount = findings.filter((finding) => finding.severity === 'critical' || finding.riskScore >= 90).length
  const hndlFindings = findings.filter((finding) => hasHndlSignal(`${finding.factor} ${finding.text}`))
  const hndlExposureScore = hndlFindings.length
    ? clamp(42 + Math.min(35, hndlFindings.length * 5) + Math.max(...hndlFindings.map((finding) => severityRank(finding.severity))) * 5)
    : 0
  const pqcAdoptionScore = percentOf(observations.filter((item) => item.safe).length, observations.length)
  const riskPenalty = Math.min(18, criticalExposureCount * 1.5)
  const quantumRiskScore = clamp(assetAverage * 0.42 + highestScore * 0.38 + hndlExposureScore * 0.14 + riskPenalty)

  const categoryLabels: RiskCategory[] = [
    'Cryptographic Vulnerabilities',
    'PQC Readiness',
    'Protocol & TLS Security',
    'Key & Certificate Health',
    'Algorithm Strength',
    'Other Factors',
  ]
  const categoryTotal = Math.max(1, findings.length)
  const breakdown = categoryLabels.map((label) => {
    const rows = findings.filter((finding) => finding.category === label)
    const score = rows.length ? clamp(rows.reduce((sum, finding) => sum + finding.riskScore, 0) / rows.length) : 0
    return { label, count: rows.length, percent: percentOf(rows.length, categoryTotal), score }
  })

  const distributionLabels = ['Critical', 'High', 'Medium', 'Low', 'Minimal']
  const distribution = distributionLabels.map((label) => {
    const count = scoredAssets.filter((asset) => levelForScore(asset.score) === label).length
    return { label, count, percent: percentOf(count, Math.max(1, scoredAssets.length)) }
  })

  const factorDefinitions = [
    { label: 'RSA & ECC Usage', test: (finding: RiskFinding) => /rsa|ecc|ecdsa|ecdh|dsa/i.test(`${finding.factor} ${finding.text}`) },
    { label: 'PQC Adoption', test: (finding: RiskFinding) => /pqc|hybrid|post.quantum|readiness/i.test(`${finding.factor} ${finding.text}`) || (!pqcAdoptionScore && observations.length > 0) },
    { label: 'TLS/Protocol Security', test: (finding: RiskFinding) => /tls|protocol|ssl|cipher|rc4|3des|cbc/i.test(`${finding.factor} ${finding.text}`) },
    { label: 'Key Management', test: (finding: RiskFinding) => /key|rotation|vault|entropy|revoked/i.test(`${finding.factor} ${finding.text}`) },
    { label: 'Certificate Health', test: (finding: RiskFinding) => /certificate|cert|issuer|expired|expiring/i.test(`${finding.factor} ${finding.text}`) },
    { label: 'Algorithm Strength', test: (finding: RiskFinding) => /algorithm|sha1|md5|weak|legacy/i.test(`${finding.factor} ${finding.text}`) },
    { label: 'HNDL Exposure', test: (finding: RiskFinding) => hasHndlSignal(`${finding.factor} ${finding.text}`) },
  ]
  const riskFactors = factorDefinitions.map((factor) => {
    const rows = findings.filter(factor.test)
    const current = rows.filter((finding) => finding.ms >= current7dStart).length
    const previous = rows.filter((finding) => finding.ms >= previous7dStart && finding.ms < current7dStart).length
    const score = factor.label === 'PQC Adoption'
      ? clamp(100 - pqcAdoptionScore)
      : rows.length
        ? clamp(rows.reduce((sum, finding) => sum + finding.riskScore, 0) / rows.length)
        : 0
    return {
      factor: factor.label,
      impact: impactForScore(score),
      score,
      trend: deltaPercent(current, previous),
    }
  })

  const weakAlgorithmCount = findings.filter((finding) => /rsa|ecc|ecdsa|ecdh|dsa|sha1|md5|weak|legacy/i.test(`${finding.factor} ${finding.text}`)).length
  const outdatedProtocolCount = findings.filter((finding) => isOutdatedProtocol(`${finding.factor} ${finding.text}`)).length
  const certificateIssueCount = findings.filter((finding) => /certificate|cert|issuer|expired|expiring/i.test(`${finding.factor} ${finding.text}`) && finding.riskScore >= 30).length
  const keyManagementCount = findings.filter((finding) => /key|rotation|vault|entropy|revoked/i.test(`${finding.factor} ${finding.text}`) && finding.riskScore >= 30).length
  const cryptoSprawlCount = new Set(findings.map((finding) => `${finding.assetName}:${finding.factor}`).filter(Boolean)).size
  const pqcReadinessGap = Math.max(0, observations.length - observations.filter((item) => item.safe).length)

  const previousDriverCounts = {
    weakAlgorithms: previous7d.filter((finding) => /rsa|ecc|ecdsa|ecdh|dsa|sha1|md5|weak|legacy/i.test(`${finding.factor} ${finding.text}`)).length,
    outdatedProtocols: previous7d.filter((finding) => isOutdatedProtocol(`${finding.factor} ${finding.text}`)).length,
    certificateIssues: previous7d.filter((finding) => /certificate|cert|issuer|expired|expiring/i.test(`${finding.factor} ${finding.text}`)).length,
    keyManagement: previous7d.filter((finding) => /key|rotation|vault|entropy|revoked/i.test(`${finding.factor} ${finding.text}`)).length,
    cryptoSprawl: new Set(previous7d.map((finding) => `${finding.assetName}:${finding.factor}`).filter(Boolean)).size,
    pqcReadiness: observations.filter((item) => !item.safe && item.ms >= previous7dStart && item.ms < current7dStart).length,
  }

  const drivers = [
    { key: 'weakAlgorithms', label: 'Weak Algorithms', detail: 'Assets using RSA/ECC/SHA1/MD5', value: weakAlgorithmCount, delta: deltaPercent(weakAlgorithmCount, previousDriverCounts.weakAlgorithms), severity: 'critical' },
    { key: 'outdatedProtocols', label: 'Outdated Protocols', detail: 'Assets using TLS 1.0/1.1 or weak ciphers', value: outdatedProtocolCount, delta: deltaPercent(outdatedProtocolCount, previousDriverCounts.outdatedProtocols), severity: 'high' },
    { key: 'certificateIssues', label: 'Certificate Issues', detail: 'Expired, expiring, or weak-signature certs', value: certificateIssueCount, delta: deltaPercent(certificateIssueCount, previousDriverCounts.certificateIssues), severity: 'medium' },
    { key: 'keyManagement', label: 'Key Management', detail: 'Key lifecycle and hygiene gaps', value: keyManagementCount, delta: deltaPercent(keyManagementCount, previousDriverCounts.keyManagement), severity: 'low' },
    { key: 'cryptoSprawl', label: 'Crypto Sprawl', detail: 'Unmanaged crypto instances', value: cryptoSprawlCount, delta: deltaPercent(cryptoSprawlCount, previousDriverCounts.cryptoSprawl), severity: 'info' },
    { key: 'pqcReadiness', label: 'PQC Readiness', detail: 'Non-PQC or hybrid-disabled observations', value: pqcReadinessGap, delta: deltaPercent(pqcReadinessGap, previousDriverCounts.pqcReadiness), severity: 'pqc' },
  ]

  const timelineStart = new Date()
  timelineStart.setHours(0, 0, 0, 0)
  timelineStart.setDate(timelineStart.getDate() - 7)
  const timeline = Array.from({ length: 8 }, (_, index) => {
    const start = timelineStart.getTime() + index * ONE_DAY_MS
    const end = start + ONE_DAY_MS
    const dayFindings = findings.filter((finding) => finding.ms >= start && finding.ms < end)
    const dayObservations = observations.filter((item) => item.ms >= start && item.ms < end)
    const dayRiskAssets = new Set(dayFindings.filter((finding) => finding.riskScore >= 30).map((finding) => finding.assetId || `${finding.assetName}:${finding.assetType}`))
    return {
      label: new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      riskScore: dayFindings.length ? clamp(dayFindings.reduce((sum, finding) => sum + finding.riskScore, 0) / dayFindings.length) : 0,
      assetsAtRisk: dayRiskAssets.size,
      assetsAtRiskPercent: percentOf(dayRiskAssets.size, Math.max(1, totalAssets)),
      pqcAdoption: percentOf(dayObservations.filter((item) => item.safe).length, dayObservations.length),
    }
  })

  const regionValues = ['North America', 'Europe', 'Asia', 'South America', 'Oceania', 'Africa', 'Global'].map((region) => {
    const rows = scoredAssets.filter((asset) => asset.region === region)
    return {
      region,
      riskScore: rows.length ? clamp(rows.reduce((sum, asset) => sum + asset.score, 0) / rows.length) : 0,
      assets: rows.length,
    }
  })

  const sortedScores = scoredAssets.map((asset) => asset.score).sort((a, b) => b - a)
  const top25Count = Math.max(1, Math.ceil(sortedScores.length * 0.25))
  const low10Start = Math.max(0, Math.floor(sortedScores.length * 0.9))
  const top25Average = sortedScores.length ? clamp(sortedScores.slice(0, top25Count).reduce((sum, score) => sum + score, 0) / top25Count) : 0
  const low10Scores = sortedScores.slice(low10Start)
  const low10Average = low10Scores.length ? clamp(low10Scores.reduce((sum, score) => sum + score, 0) / low10Scores.length) : 0

  const recommendations = [
    weakAlgorithmCount > 0 ? {
      id: 'replace-classical',
      title: `Replace RSA/ECC usage on ${weakAlgorithmCount} findings`,
      detail: 'Migrate vulnerable classical algorithms to PQC or hybrid alternatives',
      severity: weakAlgorithmCount > 10 ? 'High' : 'Medium',
    } : null,
    pqcReadinessGap > 0 ? {
      id: 'enable-hybrid',
      title: `Enable PQC hybrid modes on ${pqcReadinessGap} observations`,
      detail: 'Reduce quantum vulnerability exposure across runtime and scan telemetry',
      severity: pqcReadinessGap > 10 ? 'High' : 'Medium',
    } : null,
    outdatedProtocolCount > 0 ? {
      id: 'disable-protocols',
      title: `Disable weak protocol findings on ${outdatedProtocolCount} endpoints`,
      detail: 'Enforce TLS 1.2+ and remove weak cipher suites',
      severity: outdatedProtocolCount > 5 ? 'High' : 'Medium',
    } : null,
    certificateIssueCount > 0 ? {
      id: 'rotate-certs',
      title: `Rotate or renew ${certificateIssueCount} certificate issues`,
      detail: 'Replace weak, expiring, or non-quantum-safe certificates',
      severity: certificateIssueCount > 5 ? 'High' : 'Medium',
    } : null,
    criticalExposureCount > 0 ? {
      id: 'review-critical',
      title: `Review ${criticalExposureCount} critical exposure findings`,
      detail: 'Investigate highest-risk assets and related detections',
      severity: 'High',
    } : null,
  ].filter(Boolean)

  if (!recommendations.length) {
    recommendations.push({
      id: 'monitor',
      title: 'No active quantum-risk mitigation gaps detected',
      detail: 'Continue monitoring scans, runtime telemetry, and collector streams',
      severity: 'Low',
    })
  }

  // Shor vs Grover decomposition: which cryptographic assumptions are at risk,
  // and how deeply. Shor-exposed findings (public-key trust fabric) set the
  // migration priority; Grover findings only adjust symmetric key-size margins.
  const classifyFinding = (finding: RiskFinding) => threatClassFor(`${finding.factor} ${finding.text}`)
  const threatClassRows = new Map<ThreatClass, RiskFinding[]>([
    ['shor', []], ['grover', []], ['hash', []], ['pqc', []], ['unclassified', []],
  ])
  for (const finding of findings) {
    threatClassRows.get(classifyFinding(finding))?.push(finding)
  }
  const threatClassSummary = (threatClass: ThreatClass) => {
    const rows = threatClassRows.get(threatClass) || []
    const current = rows.filter((finding) => finding.ms >= current7dStart).length
    const previous = rows.filter((finding) => finding.ms >= previous7dStart && finding.ms < current7dStart).length
    return {
      findings: rows.length,
      share: percentOf(rows.length, Math.max(1, findings.length)),
      affectedAssets: new Set(rows.map((finding) => finding.assetId || `${finding.assetName}:${finding.assetType}`)).size,
      averageRisk: rows.length ? clamp(rows.reduce((sum, finding) => sum + finding.riskScore, 0) / rows.length) : 0,
      trend: deltaPercent(current, previous),
      topAssets: [...new Set(rows.sort((a, b) => b.riskScore - a.riskScore).map((finding) => finding.assetName).filter(Boolean))].slice(0, 3),
    }
  }
  const shorSummary = threatClassSummary('shor')
  const groverSummary = threatClassSummary('grover')
  const hashSummary = threatClassSummary('hash')
  const pqcSummary = threatClassSummary('pqc')
  const threatModel = {
    shorExposed: {
      ...shorSummary,
      label: 'Shor-exposed public-key trust',
      detail: 'RSA / ECC / DH key exchange and signatures. Broken outright by Shor — this class sets migration priority.',
      urgency: shorSummary.findings > 0 ? 'migrate' : 'clear',
    },
    groverWatch: {
      ...groverSummary,
      label: 'Grover symmetric margin',
      detail: 'AES-128 / legacy symmetric ciphers. Grover halves brute-force margins; plan key-size upgrades (AES-256), not emergency replacement.',
      urgency: groverSummary.findings > 0 ? 'plan' : 'clear',
    },
    hashLegacy: {
      ...hashSummary,
      label: 'Legacy hash functions',
      detail: 'SHA-1 / MD5 usage is classically broken already — replace independent of the quantum timeline.',
      urgency: hashSummary.findings > 0 ? 'replace' : 'clear',
    },
    pqcProtected: {
      ...pqcSummary,
      label: 'PQC / hybrid protected',
      detail: 'ML-KEM, ML-DSA/SLH-DSA, or hybrid observations already on quantum-safe assumptions.',
      urgency: 'protected',
    },
    guidance: shorSummary.findings > 0
      ? `Shor sets the priority: ${shorSummary.findings} public-key finding${shorSummary.findings === 1 ? '' : 's'} across ${shorSummary.affectedAssets} asset${shorSummary.affectedAssets === 1 ? '' : 's'} threaten the trust fabric (TLS, certificates, signatures) and should lead the migration roadmap${groverSummary.findings > 0 ? `; ${groverSummary.findings} Grover-class finding${groverSummary.findings === 1 ? '' : 's'} only need key-size margin planning` : ''}.`
      : groverSummary.findings > 0 || hashSummary.findings > 0
        ? 'No Shor-exposed public-key findings detected. Remaining work is symmetric key-size margins and legacy hash cleanup.'
        : findings.length
          ? 'Telemetry shows no algorithm-classified quantum exposure; keep discovery agents and connectors streaming.'
          : 'No classified findings yet — run scans or connect agents to build the threat-model decomposition.',
  }

  const latestRuntimeEventAt = latestDate(...runtimeEvents.map((event: any) => event.observed_at || event.created_at))
  const eventPipelineStatus = findings.some((finding) => finding.ms >= current7dStart)
    ? 'active'
    : findings.length
      ? 'stale'
      : scannerAgents.length || connectorAccounts.length
        ? 'waiting_for_runtime_events'
        : 'no_agents'

  return {
    generatedAt: new Date().toISOString(),
    latestActivityAt: latestDate(...findings.slice(0, 30).map((finding) => finding.timestamp), latestRuntimeEventAt),
    latestScanAt: latestDate(...scanSessions.map((session: any) => session.completed_at || session.updated_at || session.started_at || session.created_at)),
    filters: {
      environments: Array.from(new Set((assets || []).map((asset: any) => asset.environment).filter(Boolean))).sort(),
    },
    metrics: {
      quantumRiskScore,
      riskScoreLevel: levelForScore(quantumRiskScore),
      assetsAtRisk: riskyAssets.length,
      assetsAtRiskPercent: percentOf(riskyAssets.length, Math.max(1, totalAssets)),
      criticalExposures: criticalExposureCount,
      criticalExposurePercent: percentOf(criticalExposureCount, Math.max(1, findings.length)),
      pqcAdoptionScore,
      pqcAdoptionLevel: pqcAdoptionScore >= 80 ? 'Strong' : pqcAdoptionScore >= 45 ? 'Moderate' : pqcAdoptionScore > 0 ? 'Limited' : 'No PQC telemetry',
      riskTrendPercent: deltaPercent(currentRiskAvg, previousRiskAvg),
      hndlExposureScore,
      hndlExposureLevel: hndlExposureScore >= 75 ? 'High' : hndlExposureScore >= 45 ? 'Medium' : hndlExposureScore > 0 ? 'Low' : 'None',
      totalAssets,
      findings: findings.length,
    },
    timeline,
    breakdown,
    distribution,
    threatModel,
    topAssets: scoredAssets.slice(0, 6).map((asset) => ({
      asset: asset.name,
      assetType: asset.type,
      riskScore: clamp(asset.score),
      riskLevel: levelForScore(asset.score),
      primaryRiskFactor: asset.primaryRiskFactor,
    })),
    heatmap: regionValues,
    riskFactors,
    drivers,
    benchmark: [
      { label: 'Your Organization', value: quantumRiskScore },
      { label: 'Fleet Average', value: clamp(assetAverage) },
      { label: 'Highest Risk 25%', value: top25Average },
      { label: 'Lowest Risk 10%', value: low10Average },
    ],
    recommendations: recommendations.slice(0, 5),
    recentActivity: findings.slice(0, 10).map((finding) => ({
      id: finding.id,
      time: finding.timestamp,
      event: finding.factor,
      source: finding.sourceTable,
      asset: finding.assetName,
      severity: finding.severity,
      score: finding.riskScore,
    })),
    telemetry: {
      runtimeEvents: runtimeEvents.length,
      scannerEvidence: scannerEvidence.length,
      scannerAlerts: scannerAlerts.length,
      scanResults: scanResults.length,
      securityEvents: securityEvents.length,
      assets: assets.length,
      scannerAgents: scannerAgents.length,
      connectors: connectorAccounts.length,
      certificates: certificates.length,
      keys: generatedKeys.length,
      qrngEvents: qrngEvents.length,
      vaultAuditLogs: vaultAuditLogs.length,
      eventPipelineStatus,
      latestRuntimeEventAt,
    },
  }
}

router.get('/stream', async (req: AuthedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  sseHeaders(res)
  writeSse(res, 'quantum-risk-connected', {
    timestamp: new Date().toISOString(),
    source: 'dashboard.quantum-risk-scoring',
  })

  let closed = false
  const emitUpdate = () => {
    if (closed) return
    writeSse(res, 'quantum-risk-update', {
      timestamp: new Date().toISOString(),
      source: 'dashboard.quantum-risk-scoring',
      reason: 'tenant-risk-sync',
    })
  }

  emitUpdate()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': quantum-risk heartbeat\n\n')
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

    const data = await buildQuantumRiskSnapshot(req.token, req.user.id)
    return res.json({ data })
  } catch (error: any) {
    console.error('Quantum risk scoring dashboard error:', error)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || 'Failed to fetch quantum risk scoring data' } })
  }
})

export default router
