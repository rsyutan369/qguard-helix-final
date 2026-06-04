import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildTenantTelemetrySync } from './tenant-telemetry-sync'

const router = Router()
const ONE_DAY_MS = 24 * 60 * 60 * 1000

type Severity = 'critical' | 'high' | 'medium' | 'low'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

type TlsEvent = {
  id: string
  sourceTable: string
  server: string
  serverIp: string
  client: string
  domain: string
  protocol: string
  tlsVersion: string
  cipherSuite: string
  ja3: string
  bytes: number
  connections: number
  success: boolean
  failed: boolean
  alert: boolean
  severity: Severity
  riskScore: number
  timestamp: string | null
  ms: number
  certificateValidDays: number | null
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

function deltaPercent(current: number, previous: number) {
  if (previous <= 0) return current > 0 ? 100 : 0
  return Math.round(((current - previous) / previous) * 100)
}

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
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

function titleCase(value: unknown, fallback = 'TLS Telemetry') {
  const text = String(value || fallback)
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return text.replace(/\b\w/g, (char) => char.toUpperCase()) || fallback
}

function isWeakTls(value: string) {
  return /ssl|tls\s*1\.[01]|tls-?1\.[01]|rc4|3des|des|cbc|sha1|sha-1|md5|null|export|anon|rsa_with|rsa key exchange/i.test(value)
}

function isTlsText(value: string) {
  return /tls|ssl|https|ldaps|imaps|smtps|cipher|handshake|certificate|x509|sni|ja3/i.test(value)
}

function inferProtocol(value: string) {
  const text = value.toLowerCase()
  if (/ldaps/.test(text)) return 'LDAPS'
  if (/imaps/.test(text)) return 'IMAPS'
  if (/smtps/.test(text)) return 'SMTPS'
  if (/https|http|tls|ssl|443/.test(text)) return 'HTTPS'
  return 'Others'
}

function inferTlsVersion(value: string) {
  const text = value.toUpperCase().replace(/_/g, '.')
  if (/TLS[\s-]?1\.3/.test(text)) return 'TLS 1.3'
  if (/TLS[\s-]?1\.2/.test(text)) return 'TLS 1.2'
  if (/TLS[\s-]?1\.1/.test(text)) return 'TLS 1.1'
  if (/TLS[\s-]?1\.0/.test(text)) return 'TLS 1.0'
  if (/SSL[\s-]?3/.test(text)) return 'SSL 3.0'
  return 'Unknown'
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

function certificateDays(value: unknown) {
  const ms = dateMs(value)
  if (!ms) return null
  return Math.max(0, Math.ceil((ms - Date.now()) / ONE_DAY_MS))
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`TLS telemetry ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`TLS telemetry ${table} query failed:`, error?.message || error)
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

async function buildTlsTelemetrySnapshot(token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
    assets,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanSessions,
    scanResults,
    certificates,
    securityEvents,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, status, environment, region, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(5000)),
    safeRows(client, 'scanner_evidence', (q) => q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, raw_evidence, processed_at, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(2000)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, target_scope, progress, total_assets, scanned_assets, findings_count, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(600)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1500)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, last_seen_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(400)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, display_name, status, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(400)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('id, agent_id, status, telemetry, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1200)),
  ])

  const now = Date.now()
  const currentStart = now - 7 * ONE_DAY_MS
  const previousStart = now - 14 * ONE_DAY_MS
  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
  const events: TlsEvent[] = []
  const seen = new Set<string>()

  const assetName = (assetId: unknown, fallback = 'Unknown server') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.name, fallback)
  }

  const addEvent = (input: {
    id: string
    sourceTable: string
    assetId?: string | null
    server?: string
    serverIp?: string
    client?: string
    domain?: string
    protocol?: string
    tlsVersion?: string
    cipherSuite?: string
    ja3?: string
    bytes?: number
    connections?: number
    success?: boolean
    failed?: boolean
    alert?: boolean
    severity?: unknown
    riskScore?: unknown
    timestamp?: string | null
    certificateValidDays?: number | null
    text?: string
  }) => {
    if (seen.has(input.id)) return
    seen.add(input.id)

    const text = String(input.text || '')
    const metadataText = `${input.server || ''} ${input.domain || ''} ${input.protocol || ''} ${input.tlsVersion || ''} ${input.cipherSuite || ''} ${text}`
    if (!isTlsText(metadataText) && !input.tlsVersion && !input.cipherSuite && !input.certificateValidDays) return

    const severity = normalizeSeverity(input.severity)
    const weak = isWeakTls(metadataText)
    const failed = Boolean(input.failed || /fail|failed|error|timeout|reject|abort|alert/.test(text.toLowerCase()))
    const success = typeof input.success === 'boolean' ? input.success : !failed
    const tlsVersion = input.tlsVersion && input.tlsVersion !== 'Unknown' ? input.tlsVersion : inferTlsVersion(metadataText)
    const protocol = input.protocol ? inferProtocol(input.protocol) : inferProtocol(metadataText)
    const server = textValue(input.server, assetName(input.assetId, textValue(input.domain, 'TLS endpoint')))

    events.push({
      id: input.id,
      sourceTable: input.sourceTable,
      server,
      serverIp: textValue(input.serverIp, server),
      client: textValue(input.client, 'Unknown client'),
      domain: textValue(input.domain, server),
      protocol,
      tlsVersion,
      cipherSuite: textValue(input.cipherSuite, 'Unknown'),
      ja3: textValue(input.ja3, 'Unavailable'),
      bytes: Math.max(0, Math.round(input.bytes || 0)),
      connections: Math.max(1, Math.round(input.connections || 1)),
      success,
      failed,
      alert: Boolean(input.alert || failed || weak || severityRank(severity) >= 2),
      severity: weak && severity === 'low' ? 'medium' : severity,
      riskScore: clamp(numberValue(input.riskScore, weak ? 68 : severityRank(severity) >= 3 ? 84 : severityRank(severity) === 2 ? 56 : 14)),
      timestamp: input.timestamp || null,
      ms: dateMs(input.timestamp),
      certificateValidDays: typeof input.certificateValidDays === 'number' ? input.certificateValidDays : null,
      text,
    })
  }

  for (const row of runtimeEvents || []) {
    const metadata = recordOf(row.metadata)
    const text = `${row.event_type || ''} ${row.operation_type || ''} ${row.source_type || ''} ${row.protocol || ''} ${row.tls_version || ''} ${row.cipher_suite || ''} ${row.key_exchange_algorithm || ''} ${row.algorithm || ''} ${row.process_name || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`
    addEvent({
      id: `runtime-${row.id}`,
      sourceTable: 'runtime_crypto_events',
      assetId: row.asset_id,
      server: textValue(row.asset_name, textValue(row.host, assetName(row.asset_id))),
      serverIp: textValue(row.host, textValue(row.asset_name, 'Unknown server')),
      client: firstString(metadata, ['client_ip', 'clientIp', 'source_ip', 'sourceIp', 'remote_addr', 'remoteAddress', 'peer_ip']),
      domain: firstString(metadata, ['sni', 'server_name', 'serverName', 'domain', 'hostname']) || textValue(row.host, row.asset_name),
      protocol: textValue(row.protocol, row.source_type),
      tlsVersion: textValue(row.tls_version, inferTlsVersion(text)),
      cipherSuite: textValue(row.cipher_suite, textValue(row.key_exchange_algorithm, row.algorithm)),
      ja3: firstString(metadata, ['ja3', 'ja3_fingerprint', 'ja3Fingerprint']),
      bytes: firstNumber(metadata, ['bytes', 'bytes_transferred', 'bytesTransferred', 'encrypted_bytes', 'encryptedBytes', 'payload_bytes']),
      connections: firstNumber(metadata, ['connections', 'connection_count', 'connectionCount', 'handshakes']) || 1,
      failed: Boolean(row.downgrade_detected || /fail|error|reject|timeout/.test(text.toLowerCase())),
      alert: Boolean(row.is_legacy || row.downgrade_detected || row.shadow_crypto || row.hndl_risk),
      severity: row.severity,
      riskScore: row.risk_score,
      timestamp: row.observed_at || row.created_at,
      text,
    })
  }

  for (const row of scannerEvidence || []) {
    const raw = recordOf(row.raw_evidence)
    const text = `${row.source_type || ''} ${row.evidence_type || ''} ${row.protocol || ''} ${row.observed_algorithm || ''} ${row.target || ''} ${row.host || ''} ${Object.values(raw).filter((value) => typeof value === 'string').join(' ')}`
    addEvent({
      id: `evidence-${row.id}`,
      sourceTable: 'scanner_evidence',
      server: textValue(row.asset_name, textValue(row.host, textValue(row.target, 'Scanner TLS endpoint'))),
      serverIp: textValue(row.host, textValue(row.target, 'Scanner TLS endpoint')),
      domain: firstString(raw, ['sni', 'domain', 'hostname']) || textValue(row.target, row.host),
      protocol: textValue(row.protocol, row.source_type),
      tlsVersion: inferTlsVersion(text),
      cipherSuite: textValue(row.observed_algorithm, firstString(raw, ['cipherSuite', 'cipher_suite'])),
      ja3: firstString(raw, ['ja3', 'ja3Fingerprint']),
      bytes: firstNumber(raw, ['bytes', 'encryptedBytes', 'encrypted_bytes']),
      severity: isWeakTls(text) ? 'medium' : 'low',
      timestamp: row.observed_at || row.processed_at || row.created_at,
      text,
    })
  }

  for (const row of scannerAlerts || []) {
    const metadata = recordOf(row.metadata)
    const text = `${row.category || ''} ${row.title || ''} ${row.message || ''} ${row.recommendation || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`
    addEvent({
      id: `alert-${row.id}`,
      sourceTable: 'scanner_alerts',
      server: firstString(metadata, ['assetName', 'hostname', 'target', 'domain']) || textValue(row.category, 'TLS alert'),
      serverIp: firstString(metadata, ['host', 'serverIp', 'server_ip', 'target']),
      domain: firstString(metadata, ['sni', 'domain', 'hostname', 'target']),
      protocol: firstString(metadata, ['protocol']),
      tlsVersion: inferTlsVersion(text),
      cipherSuite: firstString(metadata, ['cipherSuite', 'cipher_suite', 'algorithm']) || inferTlsVersion(text),
      failed: /fail|error|reject|timeout/.test(text.toLowerCase()),
      alert: true,
      severity: row.severity,
      timestamp: row.updated_at || row.created_at,
      text,
    })
  }

  for (const row of scanResults || []) {
    const metadata = recordOf(row.metadata)
    const text = `${row.finding_type || ''} ${row.algorithm || ''} ${row.description || ''} ${row.threat_level || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`
    addEvent({
      id: `scan-${row.id}`,
      sourceTable: 'pqc_scan_results',
      assetId: row.asset_id,
      server: assetName(row.asset_id, firstString(metadata, ['target', 'hostname', 'domain']) || 'TLS scan target'),
      serverIp: firstString(metadata, ['host', 'serverIp', 'server_ip', 'target']),
      domain: firstString(metadata, ['sni', 'domain', 'hostname', 'target']),
      protocol: firstString(metadata, ['protocol']) || text,
      tlsVersion: inferTlsVersion(text),
      cipherSuite: textValue(row.algorithm, firstString(metadata, ['cipherSuite', 'cipher_suite'])),
      severity: row.threat_level,
      alert: true,
      timestamp: row.created_at,
      text,
    })
  }

  for (const cert of certificates || []) {
    const metadata = recordOf(cert.metadata)
    const text = `${cert.name || ''} ${cert.algorithm || ''} ${cert.status || ''} ${cert.issuer || ''} ${cert.subject || ''} ${cert.is_expiring_soon ? 'expiring soon' : ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`
    const days = certificateDays(cert.not_after)
    addEvent({
      id: `certificate-${cert.id}`,
      sourceTable: 'certificates',
      assetId: cert.asset_id,
      server: textValue(cert.name, textValue(cert.subject, assetName(cert.asset_id, 'TLS certificate'))),
      serverIp: firstString(metadata, ['host', 'serverIp', 'server_ip', 'target']),
      domain: firstString(metadata, ['sni', 'domain', 'hostname', 'target']) || textValue(cert.subject, cert.name),
      protocol: 'HTTPS',
      tlsVersion: inferTlsVersion(text),
      cipherSuite: textValue(cert.algorithm, 'Certificate'),
      certificateValidDays: days,
      severity: cert.is_expiring_soon || !cert.is_quantum_safe || isWeakTls(text) ? 'medium' : 'low',
      alert: Boolean(cert.is_expiring_soon || !cert.is_quantum_safe || isWeakTls(text)),
      timestamp: cert.updated_at || cert.created_at,
      text,
    })
  }

  for (const event of securityEvents || []) {
    const metadata = recordOf(event.metadata)
    const text = `${event.event_type || ''} ${event.message || ''} ${event.resource_type || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`
    addEvent({
      id: `security-${event.id}`,
      sourceTable: 'security_events',
      assetId: event.asset_id,
      server: textValue(event.resource_name, assetName(event.asset_id, 'TLS security event')),
      serverIp: firstString(metadata, ['host', 'serverIp', 'server_ip', 'target']),
      domain: firstString(metadata, ['sni', 'domain', 'hostname', 'target']),
      protocol: firstString(metadata, ['protocol']) || textValue(event.resource_type, ''),
      tlsVersion: inferTlsVersion(text),
      cipherSuite: firstString(metadata, ['cipherSuite', 'cipher_suite', 'algorithm']),
      failed: !event.is_read && severityRank(event.severity) >= 3,
      alert: true,
      severity: event.severity,
      timestamp: event.created_at,
      text,
    })
  }

  events.sort((a, b) => b.ms - a.ms)
  const current = events.filter((event) => event.ms >= currentStart)
  const previous = events.filter((event) => event.ms >= previousStart && event.ms < currentStart)

  const sumConnections = (rows: TlsEvent[]) => rows.reduce((sum, event) => sum + event.connections, 0)
  const currentConnections = sumConnections(current)
  const previousConnections = sumConnections(previous)
  const successfulConnections = current.filter((event) => event.success && !event.failed).reduce((sum, event) => sum + event.connections, 0)
  const failedConnections = current.filter((event) => event.failed).reduce((sum, event) => sum + event.connections, 0)
  const previousSuccessful = previous.filter((event) => event.success && !event.failed).reduce((sum, event) => sum + event.connections, 0)
  const previousFailed = previous.filter((event) => event.failed).reduce((sum, event) => sum + event.connections, 0)
  const uniqueClients = new Set(current.map((event) => event.client).filter((client) => client && client !== 'Unknown client')).size
  const previousClients = new Set(previous.map((event) => event.client).filter((client) => client && client !== 'Unknown client')).size
  const uniqueServers = new Set(current.map((event) => event.server).filter(Boolean)).size
  const previousServers = new Set(previous.map((event) => event.server).filter(Boolean)).size
  const trafficBytes = current.reduce((sum, event) => sum + event.bytes, 0)
  const previousTrafficBytes = previous.reduce((sum, event) => sum + event.bytes, 0)
  const weakConnections = current.filter((event) => isWeakTls(`${event.tlsVersion} ${event.cipherSuite} ${event.text}`) || event.alert).reduce((sum, event) => sum + event.connections, 0)
  const weakAlgorithms = current.filter((event) => isWeakTls(`${event.cipherSuite} ${event.text}`)).reduce((sum, event) => sum + event.connections, 0)
  const quantumRiskScore = clamp(percentOf(weakConnections, Math.max(1, currentConnections)) * 0.72 + percentOf(failedConnections, Math.max(1, currentConnections)) * 0.28)

  const timelineStart = new Date()
  timelineStart.setHours(0, 0, 0, 0)
  timelineStart.setDate(timelineStart.getDate() - 7)
  const timeline = Array.from({ length: 8 }, (_, index) => {
    const start = timelineStart.getTime() + index * ONE_DAY_MS
    const end = start + ONE_DAY_MS
    const bucket = events.filter((event) => event.ms >= start && event.ms < end)
    return {
      label: new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      total: sumConnections(bucket),
      successful: bucket.filter((event) => event.success && !event.failed).reduce((sum, event) => sum + event.connections, 0),
      failed: bucket.filter((event) => event.failed).reduce((sum, event) => sum + event.connections, 0),
    }
  })

  const topByConnections = <T extends { connections: number }>(rows: T[], limit = 6) => rows.sort((a, b) => b.connections - a.connections).slice(0, limit)
  const versionLabels = ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0', 'Unknown']
  const tlsVersionDistribution = versionLabels.map((version) => {
    const count = current.filter((event) => event.tlsVersion === version).reduce((sum, event) => sum + event.connections, 0)
    return { label: version, count, percent: percentOf(count, Math.max(1, currentConnections)) }
  }).filter((row) => row.count > 0 || row.label !== 'Unknown')

  const connectionTypes = ['HTTPS', 'LDAPS', 'IMAPS', 'SMTPS', 'Others'].map((type) => {
    const count = current.filter((event) => event.protocol === type).reduce((sum, event) => sum + event.connections, 0)
    return { label: type, count, percent: percentOf(count, Math.max(1, currentConnections)) }
  })

  const cipherMap = new Map<string, number>()
  const domainMap = new Map<string, number>()
  const clientMap = new Map<string, { count: number; bytes: number; ja3: string }>()
  const serverMap = new Map<string, { count: number; bytes: number; certValidity: number | null }>()

  for (const event of current) {
    cipherMap.set(event.cipherSuite, (cipherMap.get(event.cipherSuite) || 0) + event.connections)
    domainMap.set(event.domain, (domainMap.get(event.domain) || 0) + event.connections)
    const clientRow = clientMap.get(event.client) || { count: 0, bytes: 0, ja3: event.ja3 }
    clientRow.count += event.connections
    clientRow.bytes += event.bytes
    clientRow.ja3 = clientRow.ja3 === 'Unavailable' ? event.ja3 : clientRow.ja3
    clientMap.set(event.client, clientRow)
    const serverRow = serverMap.get(event.serverIp) || { count: 0, bytes: 0, certValidity: event.certificateValidDays }
    serverRow.count += event.connections
    serverRow.bytes += event.bytes
    serverRow.certValidity = serverRow.certValidity == null ? event.certificateValidDays : Math.min(serverRow.certValidity, event.certificateValidDays ?? serverRow.certValidity)
    serverMap.set(event.serverIp, serverRow)
  }

  const topCipherSuites = topByConnections(Array.from(cipherMap.entries()).map(([cipherSuite, count]) => ({
    cipherSuite,
    connections: count,
    percent: percentOf(count, Math.max(1, currentConnections)),
  })), 6)

  const topDomains = topByConnections(Array.from(domainMap.entries()).map(([domain, count]) => ({
    domain,
    connections: count,
    percent: percentOf(count, Math.max(1, currentConnections)),
  })), 5)

  const topClients = topByConnections(Array.from(clientMap.entries()).map(([clientIp, row]) => ({
    clientIp,
    connections: row.count,
    percent: percentOf(row.count, Math.max(1, currentConnections)),
    bytes: row.bytes,
    ja3Fingerprint: row.ja3,
  })), 5)

  const topServers = topByConnections(Array.from(serverMap.entries()).map(([serverIp, row]) => ({
    serverIp,
    connections: row.count,
    percent: percentOf(row.count, Math.max(1, currentConnections)),
    bytes: row.bytes,
    certValidityDays: row.certValidity,
  })), 5)

  const alerts = current
    .filter((event) => event.alert || event.failed || severityRank(event.severity) >= 2)
    .sort((a, b) => b.riskScore - a.riskScore || b.ms - a.ms)
    .slice(0, 5)
    .map((event) => ({
      id: event.id,
      title: isWeakTls(`${event.tlsVersion} ${event.cipherSuite}`) ? `${event.tlsVersion || 'Weak TLS'} connection detected` : titleCase(event.text, 'TLS alert detected'),
      detail: event.serverIp || event.domain,
      severity: severityRank(event.severity) >= 3 || event.riskScore >= 75 ? 'High' : severityRank(event.severity) >= 2 || event.riskScore >= 45 ? 'Medium' : 'Low',
      time: event.timestamp,
    }))

  const insights = [
    {
      id: 'tls13-adoption',
      title: `TLS 1.3 adoption is ${percentOf(tlsVersionDistribution.find((row) => row.label === 'TLS 1.3')?.count || 0, Math.max(1, currentConnections))}%`,
      detail: 'Strong encryption posture',
      severity: 'success',
    },
    {
      id: 'cipher-suite',
      title: `Most used cipher suite is ${topCipherSuites[0]?.cipherSuite || 'Unavailable'}`,
      detail: 'Best performance and security',
      severity: isWeakTls(topCipherSuites[0]?.cipherSuite || '') ? 'warning' : 'success',
    },
    {
      id: 'failure-rate',
      title: `${percentOf(failedConnections, Math.max(1, currentConnections))}% handshake failure rate`,
      detail: 'Monitor failing endpoints',
      severity: failedConnections ? 'warning' : 'info',
    },
    {
      id: 'cert-expiry',
      title: `${certificates.filter((cert: any) => cert.is_expiring_soon || certificateDays(cert.not_after)! <= 30).length} certificates expiring within 30 days`,
      detail: 'Review and renew to avoid disruptions',
      severity: 'info',
    },
  ]

  const latestRuntimeEventAt = latestDate(...runtimeEvents.map((event: any) => event.observed_at || event.created_at))
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
    certificates,
    securityEvents,
  })
  const eventPipelineStatus = current.length
    ? 'active'
    : sync.runningScans
      ? 'scan_running'
    : events.length
      ? 'stale'
      : scannerAgents.length || connectorAccounts.length
        ? 'waiting_for_tls_events'
        : 'no_agents'

  return {
    generatedAt: new Date().toISOString(),
    latestActivityAt: latestDate(...events.slice(0, 20).map((event) => event.timestamp), latestRuntimeEventAt, sync.latestScanAt, sync.latestDiscoveryAt),
    metrics: {
      totalConnections: currentConnections,
      totalConnectionsDelta: deltaPercent(currentConnections, previousConnections),
      successfulHandshakes: successfulConnections,
      successfulHandshakesDelta: deltaPercent(successfulConnections, previousSuccessful),
      failedHandshakes: failedConnections,
      failedHandshakesDelta: deltaPercent(failedConnections, previousFailed),
      uniqueClients,
      uniqueClientsDelta: deltaPercent(uniqueClients, previousClients),
      uniqueServers,
      uniqueServersDelta: deltaPercent(uniqueServers, previousServers),
      encryptedTrafficBytes: trafficBytes,
      encryptedTrafficDelta: deltaPercent(trafficBytes, previousTrafficBytes),
      quantumRiskScore,
      quantumRiskLevel: quantumRiskScore >= 75 ? 'High Risk' : quantumRiskScore >= 45 ? 'Medium Risk' : quantumRiskScore > 0 ? 'Low Risk' : 'No Risk',
      connectionsAtRiskPercent: percentOf(weakConnections, Math.max(1, currentConnections)),
      weakAlgorithmsPercent: percentOf(weakAlgorithms, Math.max(1, currentConnections)),
    },
    timeline,
    tlsVersionDistribution,
    topCipherSuites,
    connectionTypes,
    topDomains,
    recentAlerts: alerts,
    topClients,
    topServers,
    insights,
    telemetry: {
      runtimeEvents: runtimeEvents.length,
      scannerEvidence: scannerEvidence.length,
      scannerAlerts: scannerAlerts.length,
      scanResults: scanResults.length,
      certificates: certificates.length,
      securityEvents: securityEvents.length,
      assets: assets.length,
      scannerAgents: scannerAgents.length,
      connectors: connectorAccounts.length,
      agentHeartbeats: agentHeartbeats.length,
      eventPipelineStatus,
      latestRuntimeEventAt,
      ...sync,
    },
  }
}

router.get('/stream', async (req: AuthedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  sseHeaders(res)
  writeSse(res, 'tls-telemetry-connected', {
    timestamp: new Date().toISOString(),
    source: 'dashboard.tls-telemetry',
  })

  let closed = false
  const emitUpdate = () => {
    if (closed) return
    writeSse(res, 'tls-telemetry-update', {
      timestamp: new Date().toISOString(),
      source: 'dashboard.tls-telemetry',
      reason: 'tenant-tls-sync',
    })
  }

  emitUpdate()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': tls-telemetry heartbeat\n\n')
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

    const data = await buildTlsTelemetrySnapshot(req.token, req.user.id)
    return res.json({ data })
  } catch (error: any) {
    console.error('TLS telemetry dashboard error:', error)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || 'Failed to fetch TLS telemetry data' } })
  }
})

export default router
