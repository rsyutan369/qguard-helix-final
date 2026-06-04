import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildTenantTelemetrySync } from './tenant-telemetry-sync'

const ONE_DAY_MS = 24 * 60 * 60 * 1000

type DashboardKind = 'protocol' | 'encryption'
type Severity = 'critical' | 'high' | 'medium' | 'low'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

type Observation = {
  id: string
  sourceTable: string
  category: string
  name: string
  assetId: string | null
  assetName: string
  assetType: string
  protocol: string
  version: string
  algorithm: string
  keySize: number
  status: string
  source: string
  severity: Severity
  riskScore: number
  pqcReady: boolean
  weak: boolean
  encrypted: boolean
  rotation: boolean
  downgrade: boolean
  hndl: boolean
  timestamp: string | null
  ms: number
  text: string
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

function titleCase(value: unknown, fallback = 'Telemetry Event') {
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
  if (score >= 90) return 'critical'
  if (score >= 72) return 'high'
  if (score >= 42) return 'medium'
  return 'low'
}

function isPqcAlgorithm(value: string) {
  return /ml-kem|ml_dsa|ml-dsa|kyber|dilithium|sphincs|falcon|bike|hqc|ntru|hybrid|pqc|post.quantum/i.test(value)
}

function isWeakAlgorithm(value: string, keySize = 0) {
  const text = `${value} ${keySize}`.toLowerCase()
  if (/ssl|tls\s*1\.[01]|rc4|3des|des|cbc|sha-?1|md5|null|export|anon|rsa_with|dh anon|dsa/.test(text)) return true
  if (/rsa/.test(text) && keySize > 0 && keySize < 3072) return true
  if (/ec|ecc|ecdsa|ecdh|prime256v1|secp256|p-256|p256/.test(text)) return true
  return false
}

function isProtocolText(value: string) {
  return /tls|ssl|https|ldaps|imaps|smtps|ssh|ipsec|vpn|wireguard|http\/2|http3|quic|grpc|mtls|m-tls|cipher|handshake|protocol|ja3|sni/i.test(value)
}

function isEncryptionText(value: string) {
  return /encrypt|decrypt|cipher|crypto|key|kms|vault|token|qrng|entropy|pki|certificate|tls|ssl|aes|rsa|ecdsa|ecdh|ml-kem|ml-dsa|kyber|dilithium|sphincs|hsm|rotation|wrapped|sealed/i.test(value)
}

function inferProtocol(value: string) {
  const text = value.toLowerCase()
  if (/quic|http3|http\/3/.test(text)) return 'QUIC / HTTP3'
  if (/http\/2|h2/.test(text)) return 'HTTP/2 TLS'
  if (/mtls|m-tls|mutual tls/.test(text)) return 'mTLS'
  if (/ldaps/.test(text)) return 'LDAPS'
  if (/imaps/.test(text)) return 'IMAPS'
  if (/smtps/.test(text)) return 'SMTPS'
  if (/ssh/.test(text)) return 'SSH'
  if (/ipsec|vpn|wireguard/.test(text)) return 'VPN / IPSec'
  if (/https|tls|ssl|443/.test(text)) return 'HTTPS / TLS'
  return 'Unknown Protocol'
}

function inferVersion(value: string) {
  const text = value.toUpperCase().replace(/_/g, '.')
  if (/TLS[\s-]?1\.3/.test(text)) return 'TLS 1.3'
  if (/TLS[\s-]?1\.2/.test(text)) return 'TLS 1.2'
  if (/TLS[\s-]?1\.1/.test(text)) return 'TLS 1.1'
  if (/TLS[\s-]?1\.0/.test(text)) return 'TLS 1.0'
  if (/SSL[\s-]?3/.test(text)) return 'SSL 3.0'
  if (/HTTP\/3|QUIC/.test(text)) return 'QUIC'
  if (/SSH[\s-]?2/.test(text)) return 'SSH 2'
  return 'Unknown'
}

function encryptionContext(value: string) {
  const text = value.toLowerCase()
  if (/vault|sealed|secret/.test(text)) return 'Vault & Secrets'
  if (/kms|cloud|bucket|storage|s3|gcs|azure/.test(text)) return 'Cloud Storage'
  if (/api|token|jwt|oauth/.test(text)) return 'API Encryption'
  if (/pki|cert|certificate|x509/.test(text)) return 'PKI Certificates'
  if (/tls|ssl|https|cipher|handshake/.test(text)) return 'Transport Encryption'
  if (/database|db|postgres|mysql|mongo/.test(text)) return 'Database Encryption'
  if (/key|qrng|entropy|rotation|wrap/.test(text)) return 'Key Lifecycle'
  return 'Runtime Crypto'
}

function firstString(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = textValue(record[key])
    if (value) return value
  }
  return ''
}

function firstNumber(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = numberValue(record[key], Number.NaN)
    if (Number.isFinite(value) && value > 0) return value
  }
  return 0
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
      console.warn(`Crypto operations ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Crypto operations ${table} query failed:`, error?.message || error)
    return []
  }
}

function riskScore(input: {
  severity: Severity
  weak: boolean
  pqcReady: boolean
  downgrade: boolean
  hndl: boolean
  encrypted: boolean
}) {
  let score = input.severity === 'critical' ? 88 : input.severity === 'high' ? 74 : input.severity === 'medium' ? 48 : 18
  if (input.weak) score += 18
  if (!input.pqcReady) score += 8
  if (input.downgrade) score += 18
  if (input.hndl) score += 10
  if (!input.encrypted) score += 12
  return clamp(score)
}

function buildRouter(kind: DashboardKind) {
  const router = Router()
  router.use(requireAuth)

  router.get('/stream', async (req: AuthedRequest, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    }

    const eventPrefix = kind === 'protocol' ? 'protocol-analytics' : 'encryption-monitoring'
    sseHeaders(res)
    writeSse(res, `${eventPrefix}-connected`, {
      timestamp: new Date().toISOString(),
      source: `dashboard.${eventPrefix}`,
    })

    let closed = false
    const emitUpdate = () => {
      if (closed) return
      writeSse(res, `${eventPrefix}-update`, {
        timestamp: new Date().toISOString(),
        source: `dashboard.${eventPrefix}`,
        reason: `tenant-${eventPrefix}-sync`,
      })
    }

    emitUpdate()
    const heartbeat = setInterval(() => {
      if (!closed) res.write(`: ${eventPrefix} heartbeat\n\n`)
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

      const data = await buildSnapshot(kind, req.token, req.user.id)
      return res.json({ data })
    } catch (error: any) {
      const label = kind === 'protocol' ? 'Protocol analytics' : 'Encryption monitoring'
      console.error(`${label} dashboard error:`, error)
      return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || `Failed to fetch ${label.toLowerCase()} data` } })
    }
  })

  return router
}

async function buildSnapshot(kind: DashboardKind, token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
    assets,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanSessions,
    scanResults,
    cryptoInventory,
    cryptoExposures,
    securityEvents,
    generatedKeys,
    certificates,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    qrngEvents,
    vaultAuditLogs,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, status, environment, region, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, package_name, package_version, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(5000)),
    safeRows(client, 'scanner_evidence', (q) => q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, package_name, package_version, confidence, raw_evidence, processed_at, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(2500)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1500)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, target_scope, progress, total_assets, scanned_assets, findings_count, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(600)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(2200)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1500)),
    safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, last_seen_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(400)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, display_name, status, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(400)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('id, agent_id, status, telemetry, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1200)),
    safeRows(client, 'qrng_events', (q) => q.select('id, event_type, key_type, algorithm, key_length, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(800)),
    safeRows(client, 'vault_audit_logs', (q) => q.select('id, event_type, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(800)),
  ])

  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
  const observations: Observation[] = []
  const seen = new Set<string>()

  const assetName = (assetId: unknown, fallback = 'Unmapped asset') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.name, fallback)
  }

  const assetType = (assetId: unknown, fallback = 'Runtime Endpoint') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.type, fallback)
  }

  const includeText = kind === 'protocol' ? isProtocolText : isEncryptionText

  const addObservation = (input: {
    id: string
    sourceTable: string
    category?: string
    name?: string
    assetId?: string | null
    assetName?: string
    assetType?: string
    protocol?: string
    version?: string
    algorithm?: string
    keySize?: number
    status?: string
    source?: string
    severity?: unknown
    riskScore?: unknown
    pqcReady?: boolean
    weak?: boolean
    encrypted?: boolean
    rotation?: boolean
    downgrade?: boolean
    hndl?: boolean
    timestamp?: string | null
    text?: string
  }) => {
    if (seen.has(input.id)) return
    const text = `${input.name || ''} ${input.protocol || ''} ${input.version || ''} ${input.algorithm || ''} ${input.text || ''}`.trim()
    if (!includeText(text)) return
    seen.add(input.id)

    const algorithm = textValue(input.algorithm, 'Unknown')
    const keySize = numberValue(input.keySize)
    const protocol = textValue(input.protocol, inferProtocol(text))
    const version = textValue(input.version, inferVersion(text))
    const pqcReady = Boolean(input.pqcReady) || isPqcAlgorithm(`${algorithm} ${text}`)
    const weak = Boolean(input.weak) || isWeakAlgorithm(`${algorithm} ${protocol} ${version} ${text}`, keySize)
    const downgrade = Boolean(input.downgrade) || /downgrade|fallback|tls\s*1\.[01]|ssl/i.test(text)
    const hndl = Boolean(input.hndl) || /hndl|harvest now|decrypt later|long.term|regulated|pii|confidential/i.test(text)
    const encrypted = input.encrypted ?? !/plaintext|unencrypted|cleartext|no encryption/i.test(text)
    const severity = normalizeSeverity(input.severity)
    const score = clamp(Number(input.riskScore || 0) || riskScore({ severity, weak, pqcReady, downgrade, hndl, encrypted }))
    const timestamp = input.timestamp || null

    observations.push({
      id: input.id,
      sourceTable: input.sourceTable,
      category: input.category || (kind === 'protocol' ? protocol : encryptionContext(text)),
      name: titleCase(input.name || input.category || (kind === 'protocol' ? protocol : encryptionContext(text))),
      assetId: input.assetId || null,
      assetName: textValue(input.assetName, assetName(input.assetId)),
      assetType: textValue(input.assetType, assetType(input.assetId)),
      protocol,
      version,
      algorithm,
      keySize,
      status: textValue(input.status, weak ? 'review' : 'observed'),
      source: textValue(input.source, input.sourceTable),
      severity: severityForScore(Math.max(score, severity === 'low' ? 0 : riskScore({ severity, weak, pqcReady, downgrade, hndl, encrypted }))),
      riskScore: score,
      pqcReady,
      weak,
      encrypted,
      rotation: Boolean(input.rotation) || /rotat|renew|revok|replace|wrap|unwrap|key lifecycle/i.test(text),
      downgrade,
      hndl,
      timestamp,
      ms: dateMs(timestamp),
      text,
    })
  }

  for (const event of runtimeEvents || []) {
    const metadata = recordOf(event.metadata)
    const protocol = textValue(event.protocol, inferProtocol(`${event.tls_version || ''} ${event.cipher_suite || ''} ${event.host || ''}`))
    addObservation({
      id: `runtime-${event.id}`,
      sourceTable: 'runtime_crypto_events',
      category: kind === 'protocol' ? protocol : encryptionContext(`${event.operation_type || ''} ${event.algorithm || ''} ${event.cipher_suite || ''} ${protocol}`),
      name: event.event_type || event.operation_type || 'Runtime Crypto Event',
      assetId: event.asset_id,
      assetName: textValue(event.asset_name, textValue(event.host, textValue(event.process_name, assetName(event.asset_id)))),
      assetType: textValue(event.asset_type, textValue(event.source_type, 'Runtime Endpoint')),
      protocol,
      version: textValue(event.tls_version, inferVersion(`${event.tls_version || ''} ${event.cipher_suite || ''}`)),
      algorithm: textValue(event.algorithm, textValue(event.key_exchange_algorithm, textValue(event.cipher_suite, 'Unknown'))),
      keySize: numberValue(event.key_size),
      status: event.is_legacy ? 'legacy' : event.is_pqc ? 'pqc' : 'observed',
      source: textValue(event.source_type, 'Runtime Telemetry'),
      severity: event.severity,
      riskScore: event.risk_score,
      pqcReady: Boolean(event.is_pqc),
      weak: Boolean(event.is_legacy) || isWeakAlgorithm(`${event.algorithm || ''} ${event.cipher_suite || ''} ${event.tls_version || ''}`, numberValue(event.key_size)),
      encrypted: !/plaintext|cleartext/i.test(`${event.operation_type || ''} ${event.event_type || ''}`),
      downgrade: Boolean(event.downgrade_detected),
      hndl: Boolean(event.hndl_risk),
      timestamp: event.observed_at || event.created_at,
      text: `${event.operation_type || ''} ${event.cipher_suite || ''} ${event.key_exchange_algorithm || ''} ${event.package_name || ''} ${event.process_name || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`,
    })
  }

  for (const evidence of scannerEvidence || []) {
    const raw = recordOf(evidence.raw_evidence)
    addObservation({
      id: `evidence-${evidence.id}`,
      sourceTable: 'scanner_evidence',
      category: kind === 'protocol' ? inferProtocol(`${evidence.protocol || ''} ${evidence.observed_algorithm || ''}`) : encryptionContext(`${evidence.evidence_type || ''} ${evidence.observed_algorithm || ''}`),
      name: evidence.evidence_type || 'Scanner Evidence',
      assetName: textValue(evidence.asset_name, textValue(evidence.host, textValue(evidence.target, 'Scanned endpoint'))),
      assetType: textValue(evidence.asset_type, textValue(evidence.source_type, 'Scanner Evidence')),
      protocol: textValue(evidence.protocol, inferProtocol(`${evidence.evidence_type || ''} ${evidence.target || ''}`)),
      version: inferVersion(`${evidence.protocol || ''} ${evidence.observed_algorithm || ''} ${JSON.stringify(raw)}`),
      algorithm: textValue(evidence.observed_algorithm, firstString(raw, ['algorithm', 'cipher', 'cipher_suite'])),
      keySize: numberValue(evidence.key_size, firstNumber(raw, ['key_size', 'bits'])),
      source: 'Scanner Evidence',
      severity: isWeakAlgorithm(`${evidence.observed_algorithm || ''} ${evidence.protocol || ''}`, numberValue(evidence.key_size)) ? 'medium' : 'low',
      pqcReady: isPqcAlgorithm(`${evidence.observed_algorithm || ''} ${JSON.stringify(raw)}`),
      encrypted: !/plaintext|cleartext|unencrypted/i.test(JSON.stringify(raw)),
      timestamp: evidence.observed_at || evidence.processed_at || evidence.created_at,
      text: `${evidence.source_type || ''} ${evidence.evidence_type || ''} ${evidence.package_name || ''} ${JSON.stringify(raw)}`,
    })
  }

  for (const item of cryptoInventory || []) {
    const metadata = recordOf(item.metadata)
    addObservation({
      id: `inventory-${item.id}`,
      sourceTable: 'crypto_inventory',
      category: kind === 'protocol' ? inferProtocol(`${item.protocol || ''} ${item.algorithm || ''}`) : encryptionContext(`${item.item_type || ''} ${item.algorithm || ''} ${item.protocol || ''}`),
      name: item.name || item.item_type || 'Crypto Inventory',
      assetId: item.asset_id,
      assetName: textValue(item.name, assetName(item.asset_id)),
      assetType: textValue(item.item_type, assetType(item.asset_id)),
      protocol: textValue(item.protocol, inferProtocol(`${item.item_type || ''} ${item.algorithm || ''}`)),
      version: inferVersion(`${item.protocol || ''} ${JSON.stringify(metadata)}`),
      algorithm: textValue(item.algorithm, firstString(metadata, ['algorithm', 'cipher', 'cipher_suite'])),
      keySize: numberValue(item.key_size, firstNumber(metadata, ['key_size', 'bits', 'bit_length'])),
      status: item.is_quantum_safe ? 'pqc-ready' : item.is_vulnerable ? 'vulnerable' : 'observed',
      source: 'Crypto Inventory',
      severity: item.is_vulnerable && !item.is_quantum_safe ? item.exposure_level || 'medium' : 'low',
      pqcReady: Boolean(item.is_quantum_safe),
      weak: Boolean(item.is_vulnerable && !item.is_quantum_safe),
      encrypted: true,
      timestamp: item.discovered_at || item.created_at,
      text: `${item.item_type || ''} ${item.exposure_level || ''} ${JSON.stringify(metadata)}`,
    })
  }

  for (const exposure of cryptoExposures || []) {
    const metadata = recordOf(exposure.metadata)
    addObservation({
      id: `exposure-${exposure.id}`,
      sourceTable: 'crypto_exposures',
      category: kind === 'protocol' ? inferProtocol(`${exposure.exposure_type || ''} ${exposure.detected_value || ''}`) : encryptionContext(`${exposure.exposure_type || ''} ${exposure.description || ''}`),
      name: exposure.exposure_type || 'Crypto Exposure',
      assetId: exposure.asset_id,
      assetName: assetName(exposure.asset_id, 'Crypto exposure'),
      assetType: assetType(exposure.asset_id, 'Exposure'),
      protocol: inferProtocol(`${exposure.exposure_type || ''} ${exposure.detected_value || ''} ${exposure.description || ''}`),
      algorithm: textValue(exposure.detected_value, firstString(metadata, ['algorithm', 'cipher', 'protocol'])),
      keySize: firstNumber(metadata, ['key_size', 'bits', 'bit_length']),
      status: 'active',
      source: 'Crypto Exposure',
      severity: exposure.severity,
      pqcReady: isPqcAlgorithm(`${exposure.detected_value || ''} ${exposure.description || ''}`),
      weak: true,
      encrypted: !/plaintext|cleartext|unencrypted/i.test(`${exposure.description || ''} ${exposure.detected_value || ''}`),
      hndl: /hndl|harvest now|decrypt later/i.test(`${exposure.description || ''} ${exposure.detected_value || ''}`),
      timestamp: exposure.updated_at || exposure.created_at,
      text: `${exposure.description || ''} ${JSON.stringify(metadata)}`,
    })
  }

  for (const alert of scannerAlerts || []) {
    const metadata = recordOf(alert.metadata)
    addObservation({
      id: `scanner-alert-${alert.id}`,
      sourceTable: 'scanner_alerts',
      category: kind === 'protocol' ? inferProtocol(`${alert.category || ''} ${alert.title || ''}`) : encryptionContext(`${alert.category || ''} ${alert.title || ''}`),
      name: alert.title || alert.category || 'Scanner Alert',
      assetName: firstString(metadata, ['assetName', 'resourceName', 'hostname', 'target']) || 'Scanner alert',
      assetType: firstString(metadata, ['assetType', 'resourceType']) || 'Scanner Alert',
      protocol: inferProtocol(`${alert.category || ''} ${alert.title || ''} ${alert.message || ''}`),
      algorithm: firstString(metadata, ['algorithm', 'cipher', 'protocol']) || 'Unknown',
      status: textValue(alert.status, 'active'),
      source: 'Scanner Alert',
      severity: alert.severity,
      weak: true,
      encrypted: !/plaintext|cleartext|unencrypted/i.test(`${alert.message || ''} ${alert.recommendation || ''}`),
      timestamp: alert.updated_at || alert.created_at,
      text: `${alert.message || ''} ${alert.recommendation || ''} ${JSON.stringify(metadata)}`,
    })
  }

  for (const result of scanResults || []) {
    const metadata = recordOf(result.metadata)
    addObservation({
      id: `scan-result-${result.id}`,
      sourceTable: 'pqc_scan_results',
      category: kind === 'protocol' ? inferProtocol(`${result.finding_type || ''} ${result.algorithm || ''}`) : encryptionContext(`${result.finding_type || ''} ${result.algorithm || ''}`),
      name: result.finding_type || 'Scan Finding',
      assetId: result.asset_id,
      assetName: assetName(result.asset_id, 'Scan finding'),
      assetType: assetType(result.asset_id, 'Scan Result'),
      protocol: inferProtocol(`${result.finding_type || ''} ${result.algorithm || ''}`),
      algorithm: textValue(result.algorithm, firstString(metadata, ['algorithm', 'cipher'])),
      status: 'active',
      source: 'PQC Scan Result',
      severity: result.threat_level,
      pqcReady: isPqcAlgorithm(`${result.algorithm || ''}`),
      weak: true,
      timestamp: result.created_at,
      text: `${result.description || ''} ${result.remediation || ''} ${JSON.stringify(metadata)}`,
    })
  }

  for (const event of securityEvents || []) {
    const metadata = recordOf(event.metadata)
    addObservation({
      id: `security-${event.id}`,
      sourceTable: 'security_events',
      category: kind === 'protocol' ? inferProtocol(`${event.event_type || ''} ${event.message || ''}`) : encryptionContext(`${event.event_type || ''} ${event.message || ''}`),
      name: event.event_type || 'Security Event',
      assetId: event.asset_id,
      assetName: textValue(event.resource_name, assetName(event.asset_id, 'Security event')),
      assetType: textValue(event.resource_type, assetType(event.asset_id, 'Security Event')),
      protocol: inferProtocol(`${event.event_type || ''} ${event.message || ''}`),
      algorithm: firstString(metadata, ['algorithm', 'cipher', 'protocol']) || 'Unknown',
      status: event.is_read ? 'resolved' : 'active',
      source: 'Security Events',
      severity: event.severity,
      weak: severityRank(event.severity) >= 2,
      timestamp: event.created_at,
      text: `${event.message || ''} ${JSON.stringify(metadata)}`,
    })
  }

  for (const key of generatedKeys || []) {
    const label = recordOf(key.label)
    const metadata = recordOf(key.metadata)
    addObservation({
      id: `generated-key-${key.id}`,
      sourceTable: 'generated_keys',
      category: encryptionContext(`${key.algorithm || ''} ${key.entropy_source || ''}`),
      name: key.algorithm || 'Generated Key',
      protocol: inferProtocol(`${key.algorithm || ''} ${JSON.stringify(label)}`),
      algorithm: textValue(key.algorithm, 'Unknown'),
      keySize: numberValue(key.bit_length),
      status: textValue(key.status, 'active'),
      source: 'Key Management',
      severity: String(key.status || '').toLowerCase().includes('revoked') ? 'medium' : 'low',
      pqcReady: isPqcAlgorithm(`${key.algorithm || ''}`),
      weak: isWeakAlgorithm(`${key.algorithm || ''}`, numberValue(key.bit_length)),
      encrypted: true,
      rotation: Boolean(key.rotated_from) || /rotat|revok|renew/i.test(`${key.status || ''} ${JSON.stringify(metadata)}`),
      timestamp: key.updated_at || key.created_at,
      text: `${key.algorithm || ''} ${key.entropy_source || ''} ${JSON.stringify(label)} ${JSON.stringify(metadata)}`,
    })
  }

  for (const cert of certificates || []) {
    const metadata = recordOf(cert.metadata)
    addObservation({
      id: `certificate-${cert.id}`,
      sourceTable: 'certificates',
      category: kind === 'protocol' ? inferProtocol(`${cert.algorithm || ''} certificate tls`) : 'PKI Certificates',
      name: cert.name || cert.subject || 'Certificate',
      assetId: cert.asset_id,
      assetName: textValue(cert.name, assetName(cert.asset_id, 'Certificate')),
      assetType: assetType(cert.asset_id, 'Certificate'),
      protocol: inferProtocol(`${cert.algorithm || ''} tls certificate`),
      algorithm: textValue(cert.algorithm, firstString(metadata, ['algorithm', 'signature_algorithm'])),
      keySize: numberValue(cert.key_size, firstNumber(metadata, ['key_size', 'bits'])),
      status: textValue(cert.status, cert.is_expiring_soon ? 'expiring' : 'active'),
      source: 'Certificate Inventory',
      severity: cert.is_expiring_soon || (!cert.is_quantum_safe && isWeakAlgorithm(`${cert.algorithm || ''}`, numberValue(cert.key_size))) ? 'medium' : 'low',
      pqcReady: Boolean(cert.is_quantum_safe),
      weak: !cert.is_quantum_safe && isWeakAlgorithm(`${cert.algorithm || ''}`, numberValue(cert.key_size)),
      encrypted: true,
      timestamp: cert.updated_at || cert.created_at,
      text: `${cert.subject || ''} ${cert.issuer || ''} ${cert.not_after || ''} ${JSON.stringify(metadata)}`,
    })
  }

  for (const event of qrngEvents || []) {
    addObservation({
      id: `qrng-${event.id}`,
      sourceTable: 'qrng_events',
      category: 'Key Lifecycle',
      name: event.event_type || 'QRNG Event',
      protocol: 'QRNG',
      algorithm: textValue(event.algorithm, 'QRNG'),
      keySize: numberValue(event.key_length),
      source: 'QRNG Telemetry',
      severity: 'low',
      pqcReady: true,
      encrypted: true,
      rotation: /key|seed|generate|derive/i.test(`${event.event_type || ''}`),
      timestamp: event.created_at,
      text: `${event.key_type || ''} ${event.algorithm || ''} ${JSON.stringify(recordOf(event.metadata))}`,
    })
  }

  for (const log of vaultAuditLogs || []) {
    const metadata = recordOf(log.metadata)
    addObservation({
      id: `vault-${log.id}`,
      sourceTable: 'vault_audit_logs',
      category: 'Vault & Secrets',
      name: log.event_type || 'Vault Audit',
      protocol: 'Vault',
      algorithm: firstString(metadata, ['algorithm', 'cipher']) || 'Envelope Encryption',
      source: 'Vault Audit',
      severity: metadata.severity || metadata.result || metadata.status,
      encrypted: true,
      timestamp: log.created_at,
      text: Object.values(metadata).filter((value) => typeof value === 'string').join(' '),
    })
  }

  const now = Date.now()
  const currentStart = now - 7 * ONE_DAY_MS
  const previousStart = now - 14 * ONE_DAY_MS
  observations.sort((a, b) => b.ms - a.ms)

  const current = observations.filter((item) => item.ms >= currentStart)
  const previous = observations.filter((item) => item.ms >= previousStart && item.ms < currentStart)
  const currentAssets = new Set(current.map((item) => item.assetId || item.assetName).filter(Boolean))
  const previousAssets = new Set(previous.map((item) => item.assetId || item.assetName).filter(Boolean))
  const weak = observations.filter((item) => item.weak)
  const highRisk = observations.filter((item) => severityRank(item.severity) >= 3 || item.riskScore >= 72)
  const pqcReady = observations.filter((item) => item.pqcReady)
  const encrypted = observations.filter((item) => item.encrypted)
  const downgrades = observations.filter((item) => item.downgrade)
  const rotations = observations.filter((item) => item.rotation)
  const hndl = observations.filter((item) => item.hndl)
  const activeProtocols = new Set(observations.map((item) => item.protocol).filter((protocol) => protocol && protocol !== 'Unknown Protocol')).size
  const legacyProtocols = observations.filter((item) => item.weak || /ssl|tls 1\.0|tls 1\.1|unknown/i.test(`${item.protocol} ${item.version}`)).length
  const healthScore = observations.length
    ? clamp(100 - (weak.length * 5 + highRisk.length * 6 + downgrades.length * 8 + hndl.length * 3) / Math.max(1, observations.length))
    : 0
  const risk = observations.length ? clamp(100 - healthScore + percentOf(highRisk.length, observations.length) / 2) : 0

  const timelineStart = new Date()
  timelineStart.setHours(0, 0, 0, 0)
  timelineStart.setDate(timelineStart.getDate() - 6)
  const timeline = Array.from({ length: 7 }, (_, index) => {
    const start = timelineStart.getTime() + index * ONE_DAY_MS
    const end = start + ONE_DAY_MS
    const bucket = observations.filter((item) => item.ms >= start && item.ms < end)
    return {
      label: new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      primary: bucket.length,
      secure: bucket.filter((item) => item.encrypted && !item.weak).length,
      weak: bucket.filter((item) => item.weak).length,
      findings: bucket.filter((item) => severityRank(item.severity) >= 2 || item.riskScore >= 42).length,
    }
  })

  const protocolRows = [...new Map(observations.map((item) => [kind === 'protocol' ? item.protocol : item.category, kind === 'protocol' ? item.protocol : item.category])).keys()]
    .map((label) => {
      const scoped = observations.filter((item) => (kind === 'protocol' ? item.protocol : item.category) === label)
      const assetsForRow = new Set(scoped.map((item) => item.assetId || item.assetName).filter(Boolean))
      return {
        label,
        events: scoped.length,
        assets: assetsForRow.size,
        secure: scoped.filter((item) => item.encrypted && !item.weak).length,
        weak: scoped.filter((item) => item.weak).length,
        pqcReady: percentOf(scoped.filter((item) => item.pqcReady).length, scoped.length),
        riskScore: clamp(scoped.reduce((sum, item) => sum + item.riskScore, 0) / Math.max(1, scoped.length)),
        latestSeen: latestDate(...scoped.map((item) => item.timestamp)),
      }
    })
    .sort((a, b) => b.riskScore - a.riskScore || b.events - a.events)
    .slice(0, 10)

  const inventory = observations
    .slice()
    .sort((a, b) => b.riskScore - a.riskScore || b.ms - a.ms)
    .slice(0, 14)
    .map((item) => ({
      id: item.id,
      name: item.name,
      category: kind === 'protocol' ? item.protocol : item.category,
      assetName: item.assetName,
      assetType: item.assetType,
      protocol: item.protocol,
      version: item.version,
      algorithm: item.algorithm,
      keySize: item.keySize,
      status: item.status,
      riskLevel: item.severity,
      riskScore: item.riskScore,
      pqcReady: item.pqcReady,
      weak: item.weak,
      encrypted: item.encrypted,
      source: item.source,
      lastSeen: item.timestamp,
    }))

  const alertRows = observations
    .filter((item) => item.weak || item.downgrade || !item.encrypted || severityRank(item.severity) >= 2 || item.hndl)
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.riskScore - a.riskScore || b.ms - a.ms)
    .slice(0, 12)
    .map((item) => ({
      id: item.id,
      title: item.downgrade
        ? 'Protocol downgrade detected'
        : !item.encrypted
          ? 'Unencrypted operation detected'
          : item.weak
            ? kind === 'protocol' ? 'Weak protocol or cipher detected' : 'Weak encryption detected'
            : item.hndl
              ? 'HNDL-sensitive encryption exposure'
              : item.name,
      detail: `${item.assetName} - ${item.algorithm || item.protocol}`,
      severity: item.severity,
      timestamp: item.timestamp,
      source: item.source,
    }))

  const recommendations = [
    kind === 'protocol' && legacyProtocols > 0 && {
      id: 'retire-legacy-protocols',
      title: 'Retire legacy protocol usage',
      detail: `${legacyProtocols} observations show SSL, TLS 1.0/1.1, weak ciphers, or unknown protocol posture.`,
      impact: legacyProtocols > 10 ? 'high' : 'medium',
      count: legacyProtocols,
      actionHref: '/dashboard/tls-telemetry',
    },
    kind === 'protocol' && downgrades.length > 0 && {
      id: 'block-downgrades',
      title: 'Block downgrade and fallback paths',
      detail: `${downgrades.length} downgrade signal${downgrades.length === 1 ? '' : 's'} were correlated across runtime telemetry.`,
      impact: 'high',
      count: downgrades.length,
      actionHref: '/dashboard/telemetry-correlation',
    },
    kind === 'encryption' && weak.length > 0 && {
      id: 'replace-weak-encryption',
      title: 'Replace weak encryption algorithms',
      detail: `${weak.length} weak encryption observation${weak.length === 1 ? '' : 's'} require migration to PQC-ready or stronger primitives.`,
      impact: weak.length > 10 ? 'high' : 'medium',
      count: weak.length,
      actionHref: '/dashboard/quantum-risk-scoring',
    },
    kind === 'encryption' && hndl.length > 0 && {
      id: 'reduce-hndl-exposure',
      title: 'Prioritize HNDL-sensitive workloads',
      detail: `${hndl.length} encryption event${hndl.length === 1 ? '' : 's'} touched long-lived or sensitive data contexts.`,
      impact: 'high',
      count: hndl.length,
      actionHref: '/dashboard/runtime-crypto-intel',
    },
    observations.length > 0 && pqcReady.length < observations.length && {
      id: 'increase-pqc-adoption',
      title: kind === 'protocol' ? 'Expand PQC-ready protocol coverage' : 'Expand PQC-ready encryption coverage',
      detail: `${observations.length - pqcReady.length} observation${observations.length - pqcReady.length === 1 ? '' : 's'} are not marked quantum safe.`,
      impact: 'medium',
      count: observations.length - pqcReady.length,
      actionHref: '/dashboard/pqc-orchestration',
    },
    observations.length > 0 && currentAssets.size < assets.length && {
      id: 'extend-runtime-coverage',
      title: 'Extend telemetry coverage',
      detail: `${Math.max(0, assets.length - currentAssets.size)} tenant asset${Math.max(0, assets.length - currentAssets.size) === 1 ? '' : 's'} have no recent ${kind === 'protocol' ? 'protocol' : 'encryption'} telemetry.`,
      impact: 'low',
      count: Math.max(0, assets.length - currentAssets.size),
      actionHref: '/dashboard/scanner',
    },
  ].filter(Boolean)

  const activity = observations
    .slice(0, 14)
    .map((item) => ({
      id: item.id,
      title: item.name,
      detail: `${item.assetName} - ${kind === 'protocol' ? item.protocol : item.algorithm}`,
      severity: item.severity,
      timestamp: item.timestamp,
      source: item.source,
    }))

  const sync = buildTenantTelemetrySync({
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
    qrngEvents,
    vaultAuditLogs,
  })
  const eventPipelineStatus = current.length
    ? 'active'
    : sync.runningScans
      ? 'scan_running'
    : observations.length
      ? 'inventory_only'
      : scannerAgents.length || connectorAccounts.length
        ? `waiting_for_${kind}_events`
        : 'no_agents'

  return {
    generatedAt: new Date().toISOString(),
    latestActivityAt: latestDate(...observations.slice(0, 40).map((item) => item.timestamp), sync.latestScanAt, sync.latestDiscoveryAt),
    metrics: {
      totalEvents: observations.length,
      totalEventsDelta: deltaPercent(current.length, previous.length),
      assetsCovered: currentAssets.size,
      assetsDelta: deltaPercent(currentAssets.size, previousAssets.size),
      secureEvents: encrypted.filter((item) => !item.weak).length,
      weakEvents: weak.length,
      pqcReady: pqcReady.length,
      pqcReadyPercent: percentOf(pqcReady.length, observations.length),
      highRiskFindings: highRisk.length,
      healthScore,
      riskScore: risk,
      activeProtocols,
      legacyProtocols,
      downgradeDetections: downgrades.length,
      encryptedAssets: new Set(encrypted.map((item) => item.assetId || item.assetName).filter(Boolean)).size,
      totalKeys: generatedKeys.length,
      keyRotations: rotations.length,
      hndlExposure: hndl.length,
      activeSources: scannerAgents.length + connectorAccounts.length,
    },
    timeline,
    primaryDistribution: countBy(observations, (item) => kind === 'protocol' ? item.protocol : item.category, 8),
    secondaryDistribution: countBy(observations, (item) => kind === 'protocol' ? item.version : item.algorithm, 8),
    statusDistribution: countBy(observations, (item) => titleCase(item.status), 6),
    assetTypeDistribution: countBy(observations, (item) => item.assetType || 'Runtime Endpoint', 6),
    postureRows: protocolRows,
    inventory,
    alerts: alertRows,
    recommendations,
    activity,
    telemetry: {
      assets: assets.length,
      runtimeEvents: runtimeEvents.length,
      scannerEvidence: scannerEvidence.length,
      scannerAlerts: scannerAlerts.length,
      scanResults: scanResults.length,
      cryptoInventory: cryptoInventory.length,
      cryptoExposures: cryptoExposures.length,
      securityEvents: securityEvents.length,
      generatedKeys: generatedKeys.length,
      certificates: certificates.length,
      qrngEvents: qrngEvents.length,
      vaultAuditLogs: vaultAuditLogs.length,
      scannerAgents: scannerAgents.length,
      connectors: connectorAccounts.length,
      agentHeartbeats: agentHeartbeats.length,
      eventPipelineStatus,
      latestRuntimeEventAt: latestDate(...runtimeEvents.map((event: any) => event.observed_at || event.created_at)),
      ...sync,
    },
  }
}

export const protocolAnalyticsRoutes = buildRouter('protocol')
export const encryptionMonitoringRoutes = buildRouter('encryption')
