import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'

const router = Router()
const ONE_DAY_MS = 24 * 60 * 60 * 1000
const ONE_HOUR_MS = 60 * 60 * 1000

type Severity = 'critical' | 'high' | 'medium' | 'low'
type CorrelationCategory = 'Threat Detections' | 'Anomalies' | 'Policy Violations' | 'Crypto Weakness' | 'Informational'

type TelemetryEvent = {
  id: string
  sourceTable: string
  sourceName: string
  endpoint: string
  endpointType: string
  assetId: string | null
  agentId: string | null
  connectorAccountId: string | null
  event: string
  category: CorrelationCategory
  severity: Severity
  riskScore: number
  status: string
  timestamp: string | null
  ms: number
  text: string
}

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
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

function titleCase(value: unknown, fallback = 'Telemetry Event') {
  const text = String(value || fallback)
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return text.replace(/\b\w/g, (char) => char.toUpperCase()) || fallback
}

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
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
  return 28
}

function isLegacyAlgorithm(value: string) {
  return /rsa|rs256|ecdsa|ecdh|dh-|dsa|sha-1|sha1|md5|des|3des|rc4|aes-128-cbc|tls\s*1\.[012]|ssl|weak cipher|cbc/i.test(value)
}

function isAnomaly(value: string) {
  return /anomal|unusual|spike|shadow|rare|burst|surge|drift|unexpected|uncommon/i.test(value)
}

function classifyCategory(input: { text: string; severity?: unknown; flags?: Record<string, boolean> }): CorrelationCategory {
  const text = input.text.toLowerCase()
  const severity = normalizeSeverity(input.severity)
  if (input.flags?.downgradeDetected || input.flags?.hndlRisk || /attack|threat|suspicious|unauthorized|malware|exploit|downgrade/.test(text)) return 'Threat Detections'
  if (input.flags?.shadowCrypto || isAnomaly(text)) return 'Anomalies'
  if (/policy|compliance|trust|certificate chain|expired|revoked|violation|control|exception/.test(text)) return 'Policy Violations'
  if (input.flags?.isLegacy || isLegacyAlgorithm(text) || /weak|legacy|cipher|algorithm|crypto weakness|sha1|md5/.test(text)) return 'Crypto Weakness'
  if (severityRank(severity) >= 3) return 'Threat Detections'
  return 'Informational'
}

function sourceGroupFor(value: string) {
  const text = value.toLowerCase()
  if (/api|gateway|edge|ingress/.test(text)) return 'API Gateways'
  if (/db|database|postgres|mysql|mongo|redis|sql/.test(text)) return 'Databases'
  if (/k8s|kubernetes|cluster|container|pod|node/.test(text)) return 'Kubernetes Clusters'
  if (/aws|azure|gcp|cloud|lambda|s3|ec2|iam/.test(text)) return 'Cloud Services'
  if (/network|vpn|router|switch|firewall|ssh|ipsec|tls/.test(text)) return 'Network Devices'
  if (/web|app|frontend|service|http/.test(text)) return 'Web Applications'
  return 'Endpoints'
}

function statusFor(value: unknown, severity: Severity) {
  const explicit = String(value || '').trim()
  if (explicit) return titleCase(explicit)
  return severityRank(severity) >= 3 ? 'Active' : severity === 'medium' ? 'Investigating' : 'Resolved'
}

function eventScore(event: TelemetryEvent, sourceCount = 1, categoryCount = 1, endpointCount = 1) {
  return clamp(
    event.riskScore +
    Math.min(18, sourceCount * 5) +
    Math.min(12, categoryCount * 4) +
    Math.min(10, endpointCount * 2),
  )
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Telemetry correlation ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Telemetry correlation ${table} query failed:`, error?.message || error)
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

router.get('/stream', async (req: AuthedRequest, res: Response) => {
  const user = req.user
  if (!user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  sseHeaders(res)
  writeSse(res, 'telemetry-correlation-connected', {
    timestamp: new Date().toISOString(),
    source: 'dashboard.telemetry-correlation',
  })

  let closed = false
  const emitUpdate = () => {
    if (closed) return
    writeSse(res, 'telemetry-correlation-update', {
      timestamp: new Date().toISOString(),
      source: 'dashboard.telemetry-correlation',
      reason: 'tenant-telemetry-sync',
    })
  }

  emitUpdate()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': telemetry-correlation heartbeat\n\n')
  }, 25000)
  const syncPoll = setInterval(emitUpdate, 8000)

  req.on('close', () => {
    closed = true
    clearInterval(heartbeat)
    clearInterval(syncPoll)
  })
})

router.get('/', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
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
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1000)),
      safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, package_name, package_version, process_name, process_id, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', user.id).order('observed_at', { ascending: false }).limit(4000)),
      safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
      safeRows(client, 'scanner_evidence', (q) => q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, package_name, package_version, confidence, raw_evidence, processed_at, observed_at, created_at').eq('user_id', user.id).order('observed_at', { ascending: false }).limit(1500)),
      safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, capabilities, last_seen_at, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(300)),
      safeRows(client, 'connector_accounts', (q) => q.select('id, provider, provider_account_id, display_name, status, scopes, capabilities, last_sync_at, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(300)),
      safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1500)),
      safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(160)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1200)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(1500)),
      safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(800)),
      safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
      safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1000)),
      safeRows(client, 'qrng_events', (q) => q.select('id, event_type, key_type, algorithm, key_length, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(600)),
      safeRows(client, 'vault_audit_logs', (q) => q.select('id, event_type, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(600)),
      safeRows(client, 'agent_heartbeats', (q) => q.select('id, agent_id, status, telemetry, observed_at, created_at').eq('user_id', user.id).order('observed_at', { ascending: false }).limit(1000)),
    ])

    const now = Date.now()
    const current7dStart = now - 7 * ONE_DAY_MS
    const previous7dStart = now - 14 * ONE_DAY_MS
    const last24hStart = now - ONE_DAY_MS
    const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
    const agentMap = new Map<string, any>((scannerAgents || []).map((agent: any) => [agent.id, agent]))
    const connectorMap = new Map<string, any>((connectorAccounts || []).map((connector: any) => [connector.id, connector]))
    const events: TelemetryEvent[] = []
    const seen = new Set<string>()

    const endpointFromAsset = (assetId: unknown, fallback = 'Unmapped endpoint') => {
      const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
      return textValue(asset?.name, fallback)
    }

    const sourceNameFromIds = (agentId: unknown, connectorId: unknown, fallback = 'Telemetry source') => {
      const agent = typeof agentId === 'string' ? agentMap.get(agentId) : null
      if (agent) return textValue(agent.name, textValue(agent.hostname, fallback))
      const connector = typeof connectorId === 'string' ? connectorMap.get(connectorId) : null
      if (connector) return textValue(connector.display_name, textValue(connector.provider, fallback))
      return fallback
    }

    const addEvent = (input: {
      id: string
      sourceTable: string
      sourceName?: string
      endpoint?: string
      endpointType?: string
      assetId?: string | null
      agentId?: string | null
      connectorAccountId?: string | null
      event: string
      text?: string
      category?: CorrelationCategory
      severity?: unknown
      riskScore?: unknown
      status?: unknown
      timestamp?: string | null
      flags?: Record<string, boolean>
    }) => {
      if (seen.has(input.id)) return
      seen.add(input.id)

      const text = `${input.event || ''} ${input.text || ''}`.trim()
      const severity = normalizeSeverity(input.severity)
      const category = input.category || classifyCategory({ text, severity, flags: input.flags })
      const riskScore = clamp(Number(input.riskScore || 0) || riskForSeverity(severity) + (category === 'Threat Detections' ? 8 : category === 'Crypto Weakness' ? 5 : 0))
      const endpoint = textValue(input.endpoint, endpointFromAsset(input.assetId, textValue(input.sourceName, 'Telemetry endpoint')))
      const endpointType = textValue(input.endpointType, sourceGroupFor(`${endpoint} ${input.text || ''}`))
      const sourceName = textValue(input.sourceName, sourceNameFromIds(input.agentId, input.connectorAccountId, endpoint))
      const timestamp = input.timestamp || null

      events.push({
        id: input.id,
        sourceTable: input.sourceTable,
        sourceName,
        endpoint,
        endpointType: sourceGroupFor(`${endpointType} ${endpoint}`),
        assetId: input.assetId || null,
        agentId: input.agentId || null,
        connectorAccountId: input.connectorAccountId || null,
        event: titleCase(input.event),
        category,
        severity,
        riskScore,
        status: statusFor(input.status, severity),
        timestamp,
        ms: dateMs(timestamp),
        text,
      })
    }

    for (const event of runtimeEvents || []) {
      const metadata = recordOf(event.metadata)
      const sourceName = sourceNameFromIds(event.agent_id, event.connector_account_id, textValue(event.host, textValue(event.source_type, 'Runtime collector')))
      addEvent({
        id: `runtime-${event.id}`,
        sourceTable: 'runtime_crypto_events',
        sourceName,
        endpoint: textValue(event.asset_name, textValue(event.host, textValue(event.process_name, endpointFromAsset(event.asset_id)))),
        endpointType: textValue(event.asset_type, textValue(event.source_type, textValue(event.protocol, 'runtime'))),
        assetId: event.asset_id,
        agentId: event.agent_id,
        connectorAccountId: event.connector_account_id,
        event: event.event_type || event.operation_type || 'Runtime Crypto Event',
        text: `${event.operation_type || ''} ${event.algorithm || ''} ${event.key_exchange_algorithm || ''} ${event.cipher_suite || ''} ${event.tls_version || ''} ${event.protocol || ''} ${event.package_name || ''} ${event.process_name || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`,
        severity: event.severity,
        riskScore: event.risk_score,
        timestamp: event.observed_at || event.created_at,
        flags: {
          isLegacy: Boolean(event.is_legacy),
          downgradeDetected: Boolean(event.downgrade_detected),
          shadowCrypto: Boolean(event.shadow_crypto),
          hndlRisk: Boolean(event.hndl_risk),
        },
      })
    }

    for (const evidence of scannerEvidence || []) {
      addEvent({
        id: `evidence-${evidence.id}`,
        sourceTable: 'scanner_evidence',
        sourceName: sourceNameFromIds(evidence.agent_id, evidence.connector_account_id, textValue(evidence.source_type, 'Scanner evidence')),
        endpoint: textValue(evidence.asset_name, textValue(evidence.host, textValue(evidence.target, 'Evidence endpoint'))),
        endpointType: textValue(evidence.asset_type, `${evidence.evidence_type || ''} ${evidence.protocol || ''}`),
        agentId: evidence.agent_id,
        connectorAccountId: evidence.connector_account_id,
        event: evidence.evidence_type || 'Scanner Evidence',
        text: `${evidence.observed_algorithm || ''} ${evidence.protocol || ''} ${evidence.package_name || ''} ${evidence.confidence || ''}`,
        severity: isLegacyAlgorithm(`${evidence.observed_algorithm || ''} ${evidence.protocol || ''}`) ? 'medium' : 'low',
        timestamp: evidence.observed_at || evidence.processed_at || evidence.created_at,
        flags: {
          isLegacy: isLegacyAlgorithm(`${evidence.observed_algorithm || ''} ${evidence.protocol || ''}`),
        },
      })
    }

    for (const alert of scannerAlerts || []) {
      const metadata = recordOf(alert.metadata)
      addEvent({
        id: `scanner-alert-${alert.id}`,
        sourceTable: 'scanner_alerts',
        sourceName: sourceNameFromIds(alert.agent_id, alert.connector_account_id, textValue(alert.category, 'Scanner alert')),
        endpoint: textValue(metadata.assetName || metadata.resourceName || metadata.hostname || metadata.target, textValue(alert.category, 'Scanner alert')),
        endpointType: textValue(metadata.assetType || metadata.resourceType, textValue(alert.category, 'scanner')),
        agentId: alert.agent_id,
        connectorAccountId: alert.connector_account_id,
        event: alert.title || alert.category || 'Scanner Alert',
        text: `${alert.message || ''} ${alert.recommendation || ''}`,
        severity: alert.severity,
        status: alert.status,
        timestamp: alert.updated_at || alert.created_at,
      })
    }

    for (const result of scanResults || []) {
      addEvent({
        id: `scan-result-${result.id}`,
        sourceTable: 'pqc_scan_results',
        sourceName: 'PQC scan engine',
        endpoint: endpointFromAsset(result.asset_id, 'Scan finding'),
        endpointType: `${result.finding_type || ''} ${result.algorithm || ''}`,
        assetId: result.asset_id,
        event: result.finding_type || 'Scan Finding',
        text: `${result.description || ''} ${result.algorithm || ''} ${result.threat_level || ''} ${result.remediation || ''}`,
        severity: result.threat_level,
        timestamp: result.created_at,
      })
    }

    for (const exposure of exposures || []) {
      addEvent({
        id: `exposure-${exposure.id}`,
        sourceTable: 'crypto_exposures',
        sourceName: 'Exposure map',
        endpoint: endpointFromAsset(exposure.asset_id, 'Crypto exposure'),
        endpointType: `${exposure.exposure_type || ''} ${exposure.detected_value || ''}`,
        assetId: exposure.asset_id,
        event: exposure.exposure_type || 'Crypto Exposure',
        text: `${exposure.description || ''} ${exposure.detected_value || ''}`,
        severity: exposure.severity,
        timestamp: exposure.updated_at || exposure.created_at,
      })
    }

    for (const item of inventory || []) {
      addEvent({
        id: `inventory-${item.id}`,
        sourceTable: 'crypto_inventory',
        sourceName: 'Crypto inventory',
        endpoint: textValue(item.name, endpointFromAsset(item.asset_id, 'Inventory item')),
        endpointType: `${item.item_type || ''} ${item.protocol || ''}`,
        assetId: item.asset_id,
        event: item.item_type || 'Crypto Inventory',
        text: `${item.algorithm || ''} ${item.protocol || ''} ${item.exposure_level || ''}`,
        severity: item.is_vulnerable && !item.is_quantum_safe ? item.exposure_level || 'medium' : 'low',
        status: item.is_quantum_safe ? 'Resolved' : item.is_vulnerable ? 'Active' : 'Observed',
        timestamp: item.discovered_at || item.created_at,
        flags: {
          isLegacy: Boolean(item.is_vulnerable && !item.is_quantum_safe) || isLegacyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`),
        },
      })
    }

    for (const event of securityEvents || []) {
      addEvent({
        id: `security-${event.id}`,
        sourceTable: 'security_events',
        sourceName: 'Security events',
        endpoint: textValue(event.resource_name, endpointFromAsset(event.asset_id, textValue(event.resource_type, 'Security event'))),
        endpointType: textValue(event.resource_type, event.event_type),
        assetId: event.asset_id,
        event: event.event_type || 'Security Event',
        text: event.message || '',
        severity: event.severity,
        status: event.is_read ? 'Resolved' : 'Active',
        timestamp: event.created_at,
      })
    }

    for (const key of generatedKeys || []) {
      addEvent({
        id: `key-${key.id}`,
        sourceTable: 'generated_keys',
        sourceName: 'Key management',
        endpoint: textValue(key.label, 'Generated key'),
        endpointType: `${key.algorithm || ''} ${key.entropy_source || ''}`,
        event: 'Key Lifecycle Event',
        text: `${key.algorithm || ''} ${key.status || ''} ${key.bit_length || ''} ${key.entropy_source || ''}`,
        severity: String(key.status || '').toLowerCase().includes('revoked') || String(key.status || '').toLowerCase().includes('compromised') ? 'medium' : 'low',
        status: key.status,
        timestamp: key.updated_at || key.created_at,
      })
    }

    for (const cert of certificates || []) {
      addEvent({
        id: `certificate-${cert.id}`,
        sourceTable: 'certificates',
        sourceName: 'Certificate inventory',
        endpoint: textValue(cert.name, textValue(cert.subject, endpointFromAsset(cert.asset_id, 'Certificate'))),
        endpointType: `${cert.algorithm || ''} certificate`,
        assetId: cert.asset_id,
        event: 'Certificate Telemetry',
        text: `${cert.algorithm || ''} ${cert.status || ''} ${cert.is_expiring_soon ? 'expiring soon' : ''}`,
        severity: cert.is_expiring_soon || (!cert.is_quantum_safe && isLegacyAlgorithm(`${cert.algorithm || ''}`)) ? 'medium' : 'low',
        status: cert.status,
        timestamp: cert.updated_at || cert.created_at,
        flags: {
          isLegacy: !cert.is_quantum_safe && isLegacyAlgorithm(`${cert.algorithm || ''}`),
        },
      })
    }

    for (const event of qrngEvents || []) {
      addEvent({
        id: `qrng-${event.id}`,
        sourceTable: 'qrng_events',
        sourceName: 'QRNG telemetry',
        endpoint: textValue(event.key_type, 'QRNG key material'),
        endpointType: `${event.algorithm || ''} entropy`,
        event: event.event_type || 'QRNG Event',
        text: `${event.algorithm || ''} ${event.key_length || ''}`,
        severity: 'low',
        timestamp: event.created_at,
      })
    }

    for (const log of vaultAuditLogs || []) {
      const metadata = recordOf(log.metadata)
      addEvent({
        id: `vault-${log.id}`,
        sourceTable: 'vault_audit_logs',
        sourceName: 'Vault audit',
        endpoint: textValue(metadata.resourceName || metadata.resource_name || metadata.fileName || metadata.file_name, 'Vault record'),
        endpointType: 'vault',
        event: log.event_type || 'Vault Audit',
        text: Object.values(metadata).filter((value) => typeof value === 'string').join(' '),
        severity: metadata.severity || metadata.result || metadata.status,
        timestamp: log.created_at,
      })
    }

    for (const heartbeat of agentHeartbeats || []) {
      const agent = agentMap.get(heartbeat.agent_id) || {}
      addEvent({
        id: `heartbeat-${heartbeat.id}`,
        sourceTable: 'agent_heartbeats',
        sourceName: textValue(agent.name, textValue(agent.hostname, 'Agent heartbeat')),
        endpoint: textValue(agent.hostname, textValue(agent.name, 'Agent heartbeat')),
        endpointType: textValue(agent.platform, 'local agent'),
        agentId: heartbeat.agent_id,
        event: 'Agent Heartbeat',
        text: `${heartbeat.status || ''} ${Object.values(recordOf(heartbeat.telemetry)).filter((value) => typeof value === 'string').join(' ')}`,
        severity: String(heartbeat.status || '').toLowerCase().includes('error') || String(heartbeat.status || '').toLowerCase().includes('offline') ? 'medium' : 'low',
        status: heartbeat.status,
        timestamp: heartbeat.observed_at || heartbeat.created_at,
      })
    }

    events.sort((a, b) => b.ms - a.ms)

    const current7d = events.filter((event) => event.ms >= current7dStart)
    const previous7d = events.filter((event) => event.ms >= previous7dStart && event.ms < current7dStart)
    const events24h = events.filter((event) => event.ms >= last24hStart)
    const endpointsCurrent = new Set(current7d.map((event) => event.endpoint).filter(Boolean))
    const endpointsPrevious = new Set(previous7d.map((event) => event.endpoint).filter(Boolean))

    const flowWindowEvents = events24h
    const sourceGroups = ['Web Applications', 'API Gateways', 'Databases', 'Kubernetes Clusters', 'Cloud Services', 'Network Devices', 'Endpoints']
      .map((label) => ({
        label,
        count: flowWindowEvents.filter((event) => event.endpointType === label).length,
      }))
      .filter((row) => row.count > 0 || row.label !== 'Endpoints')

    const categoryLabels: CorrelationCategory[] = ['Threat Detections', 'Anomalies', 'Policy Violations', 'Crypto Weakness', 'Informational']
    const categoryTotal = Math.max(1, events.length)
    const categoryDistribution = categoryLabels.map((label) => {
      const count = events.filter((event) => event.category === label).length
      return { label, count, percent: percentOf(count, categoryTotal) }
    })
    const flowCategoryTotal = Math.max(1, flowWindowEvents.length)
    const flowCategoryDistribution = categoryLabels.map((label) => {
      const count = flowWindowEvents.filter((event) => event.category === label).length
      return { label, count, percent: percentOf(count, flowCategoryTotal) }
    })

    const correlationGroupMap = new Map<string, {
      key: string
      title: string
      category: CorrelationCategory
      severity: Severity
      events: TelemetryEvent[]
      endpoints: Set<string>
      sources: Set<string>
      firstSeen: string | null
      latestSeen: string | null
      score: number
    }>()

    for (const event of current7d) {
      const keyTitle = titleCase(event.event.replace(/\b(event|telemetry|behavior)\b/ig, '').trim() || event.category)
      const key = `${event.category}:${keyTitle.toLowerCase()}`
      const existing = correlationGroupMap.get(key) || {
        key,
        title: keyTitle,
        category: event.category,
        severity: event.severity,
        events: [],
        endpoints: new Set<string>(),
        sources: new Set<string>(),
        firstSeen: null,
        latestSeen: null,
        score: 0,
      }
      existing.events.push(event)
      existing.endpoints.add(event.endpoint)
      existing.sources.add(event.sourceName)
      existing.firstSeen = existing.firstSeen
        ? (dateMs(event.timestamp) < dateMs(existing.firstSeen) ? event.timestamp : existing.firstSeen)
        : event.timestamp
      existing.latestSeen = latestDate(existing.latestSeen, event.timestamp)
      existing.severity = severityRank(event.severity) > severityRank(existing.severity) ? event.severity : existing.severity
      existing.score = Math.max(existing.score, eventScore(event, existing.sources.size, new Set(existing.events.map((item) => item.category)).size, existing.endpoints.size))
      correlationGroupMap.set(key, existing)
    }

    const correlationGroups = Array.from(correlationGroupMap.values())
      .filter((group) => group.events.length > 1 || group.endpoints.size > 1 || severityRank(group.severity) >= 2)
      .sort((a, b) => b.score - a.score || b.events.length - a.events.length)

    const previousGroupKeys = new Set(previous7d.map((event) => `${event.category}:${titleCase(event.event.replace(/\b(event|telemetry|behavior)\b/ig, '').trim() || event.category).toLowerCase()}`))
    const highRiskGroups = correlationGroups.filter((group) => severityRank(group.severity) >= 3)
    const previousHighRisk = previous7d.filter((event) => severityRank(event.severity) >= 3).length
    const currentHighRiskEvents = current7d.filter((event) => severityRank(event.severity) >= 3).length
    const currentCorrelationMatches = correlationGroups.reduce((sum, group) => sum + group.events.length, 0)
    const previousCorrelationMatches = previous7d.filter((event) => previousGroupKeys.has(`${event.category}:${titleCase(event.event.replace(/\b(event|telemetry|behavior)\b/ig, '').trim() || event.category).toLowerCase()}`)).length

    const timelineStart = new Date()
    timelineStart.setHours(0, 0, 0, 0)
    timelineStart.setDate(timelineStart.getDate() - 7)
    const timeline = Array.from({ length: 8 }, (_, index) => {
      const start = timelineStart.getTime() + index * ONE_DAY_MS
      const end = start + ONE_DAY_MS
      const bucket = events.filter((event) => event.ms >= start && event.ms < end)
      return {
        label: new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        threatDetections: bucket.filter((event) => event.category === 'Threat Detections').length,
        anomalies: bucket.filter((event) => event.category === 'Anomalies').length,
        policyViolations: bucket.filter((event) => event.category === 'Policy Violations').length,
        cryptoWeakness: bucket.filter((event) => event.category === 'Crypto Weakness').length,
        infoEvents: bucket.filter((event) => event.category === 'Informational').length,
      }
    })

    const heatmapRows = sourceGroups.slice(0, 6).map((source) => {
      const values = Array.from({ length: 24 }, (_, hourIndex) => {
        const start = now - (23 - hourIndex) * ONE_HOUR_MS
        const end = start + ONE_HOUR_MS
        const bucket = events.filter((event) => event.endpointType === source.label && event.ms >= start && event.ms < end)
        const weighted = bucket.reduce((sum, event) => sum + Math.max(1, severityRank(event.severity)), 0)
        return {
          hour: new Date(start).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit' }),
          value: weighted,
        }
      })
      return { label: source.label, values }
    })

    const sourceHealthMap = new Map<string, { source: string; events24h: number; total: number; latest: string | null; severity: Severity }>()
    for (const event of events) {
      const key = event.sourceName || event.endpoint
      const existing = sourceHealthMap.get(key) || { source: key, events24h: 0, total: 0, latest: null, severity: 'low' as Severity }
      existing.total += 1
      if (event.ms >= last24hStart) existing.events24h += 1
      existing.latest = latestDate(existing.latest, event.timestamp)
      existing.severity = severityRank(event.severity) > severityRank(existing.severity) ? event.severity : existing.severity
      sourceHealthMap.set(key, existing)
    }
    for (const agent of scannerAgents || []) {
      const key = textValue(agent.name, textValue(agent.hostname, 'Scanner agent'))
      if (!sourceHealthMap.has(key)) {
        sourceHealthMap.set(key, {
          source: key,
          events24h: 0,
          total: 0,
          latest: agent.last_seen_at || agent.updated_at || agent.created_at,
          severity: String(agent.status || '').toLowerCase() === 'active' ? 'low' : 'medium',
        })
      }
    }

    const sourceHealth = Array.from(sourceHealthMap.values())
      .sort((a, b) => dateMs(b.latest) - dateMs(a.latest) || b.events24h - a.events24h)
      .slice(0, 8)
      .map((row) => {
        const ageMs = row.latest ? now - dateMs(row.latest) : Number.POSITIVE_INFINITY
        const status = severityRank(row.severity) >= 3
          ? 'Critical'
          : ageMs <= 5 * 60 * 1000
            ? 'Healthy'
            : ageMs <= ONE_DAY_MS
              ? 'Warning'
              : 'Stale'
        return {
          source: row.source,
          status,
          events24h: row.events24h,
          lastSeenAt: row.latest,
        }
      })

    const latestRuntimeEventAt = latestDate(...runtimeEvents.map((event: any) => event.observed_at || event.created_at))
    const totalSourceNames = new Set(events.map((event) => event.sourceName).filter(Boolean)).size
    const runtimeEvents24h = (runtimeEvents || []).filter((event: any) => dateMs(event.observed_at || event.created_at) >= last24hStart)
    const latencySamples = runtimeEvents24h
      .map((event: any) => dateMs(event.created_at) && dateMs(event.observed_at) ? Math.max(0, dateMs(event.created_at) - dateMs(event.observed_at)) : 0)
      .filter((value: number) => value > 0)
    const correlationLatencyMs = latencySamples.length
      ? Math.round(latencySamples.reduce((sum: number, value: number) => sum + value, 0) / latencySamples.length)
      : 0
    const processingRate = Number((events24h.length / (24 * 60 * 60)).toFixed(events24h.length >= 86400 ? 1 : 3))
    const flowSourceNames = new Set(flowWindowEvents.map((event) => event.sourceName).filter(Boolean)).size
    const coverageScore = percentOf(endpointsCurrent.size, Math.max(1, assets.length + scannerAgents.length + connectorAccounts.length))
    const freshnessScore = latestRuntimeEventAt && now - dateMs(latestRuntimeEventAt) <= ONE_DAY_MS ? 25 : latestRuntimeEventAt ? 12 : 0
    const riskPenalty = Math.min(28, highRiskGroups.length * 3 + currentHighRiskEvents)
    const correlationScore = clamp(52 + coverageScore * 0.35 + freshnessScore + Math.min(18, totalSourceNames * 2) - riskPenalty)
    const eventPipelineStatus = events24h.length
      ? 'active'
      : events.length
        ? 'stale'
        : scannerAgents.length || connectorAccounts.length
          ? 'waiting_for_runtime_events'
          : 'no_agents'

    return res.json({
      data: {
        generatedAt: new Date().toISOString(),
        latestEventAt: latestDate(...events.slice(0, 20).map((event) => event.timestamp)),
        latestScanAt: latestDate(...scanSessions.map((session: any) => session.completed_at || session.updated_at || session.started_at || session.created_at)),
        filters: {
          environments: Array.from(new Set((assets || []).map((asset: any) => asset.environment).filter(Boolean))).sort(),
        },
        metrics: {
          telemetryEvents: current7d.length,
          telemetryEventsDelta: deltaPercent(current7d.length, previous7d.length),
          correlatedAlerts: correlationGroups.length,
          correlatedAlertsDelta: deltaPercent(correlationGroups.length, previousGroupKeys.size),
          endpointsMonitored: endpointsCurrent.size || new Set(events.map((event) => event.endpoint)).size,
          endpointsDelta: deltaPercent(endpointsCurrent.size, endpointsPrevious.size),
          correlationMatches: currentCorrelationMatches,
          correlationMatchesDelta: deltaPercent(currentCorrelationMatches, previousCorrelationMatches),
          highRiskCorrelations: highRiskGroups.length || currentHighRiskEvents,
          highRiskDelta: deltaPercent(highRiskGroups.length || currentHighRiskEvents, previousHighRisk),
          correlationScore,
          correlationScoreLevel: correlationScore >= 85 ? 'Excellent' : correlationScore >= 65 ? 'Good' : correlationScore > 0 ? 'Needs Attention' : 'No Runtime Data',
        },
        flow: {
          sourceGroups,
          outcomes: flowCategoryDistribution,
          processingRate,
          correlationLatencyMs,
          dataSources: flowSourceNames,
          timeWindowHours: 24,
        },
        timeline,
        topAlerts: correlationGroups.slice(0, 6).map((group) => ({
          id: group.key,
          alertName: group.title,
          correlationScore: group.score,
          endpoints: group.endpoints.size,
          firstSeenAt: group.firstSeen,
          status: group.severity === 'critical' ? 'Critical' : group.severity === 'high' ? 'High' : group.severity === 'medium' ? 'Medium' : 'Low',
          category: group.category,
          severity: group.severity,
        })),
        categoryDistribution,
        heatmap: heatmapRows,
        dataSourcesHealth: sourceHealth,
        recentEvents: events.slice(0, 12).map((event) => {
          const relatedEndpoints = correlationGroups.find((group) => group.events.some((item) => item.id === event.id))?.endpoints.size || 1
          const relatedSources = correlationGroups.find((group) => group.events.some((item) => item.id === event.id))?.sources.size || 1
          return {
            id: event.id,
            time: event.timestamp,
            event: event.event,
            source: event.sourceName,
            relatedEndpoints,
            correlationScore: eventScore(event, relatedSources, 1, relatedEndpoints),
            category: event.category.replace(/s$/, ''),
            severity: event.severity,
            status: event.status,
          }
        }),
        telemetry: {
          runtimeEvents: runtimeEvents.length,
          scannerEvidence: scannerEvidence.length,
          scannerAlerts: scannerAlerts.length,
          scanResults: scanResults.length,
          securityEvents: securityEvents.length,
          assets: assets.length,
          scannerAgents: scannerAgents.length,
          connectors: connectorAccounts.length,
          eventPipelineStatus,
          latestRuntimeEventAt,
        },
      },
    })
  } catch (err) {
    console.error('Telemetry correlation dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch telemetry correlation data' } })
  }
})

export default router
