import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'

const router = Router()
const ONE_DAY_MS = 24 * 60 * 60 * 1000

type OperationSeverity = 'critical' | 'high' | 'medium' | 'low'

type BehavioralOperation = {
  id: string
  source: string
  entity: string
  event: string
  pattern: string
  severity: OperationSeverity
  confidence: number
  status: string
  action: string
  timestamp: string | null
  ms: number
  riskScore: number
  type: string
  anomalous: boolean
  text: string
}

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const queryToken = typeof req.query.token === 'string' ? req.query.token : null
  const token = getToken(req) || queryToken
  if (!token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  const user = await getServerUser(token)
  if (!user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  }

  ;(req as any).user = user
  ;(req as any).token = token
  next()
}

router.use(requireAuth)

function sseHeaders(res: Response) {
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()
}

function writeSse(res: Response, event: string, data: unknown) {
  if (res.writableEnded) return
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
}

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

function titleCase(value: unknown) {
  return String(value || '')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase()) || 'Observed Event'
}

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
}

function normalizeSeverity(value: unknown): OperationSeverity {
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

function isLegacyAlgorithm(value: string) {
  return /rsa|rs256|ecdsa|ecdh|dh-|dsa|sha-1|sha1|md5|des|3des|rc4|aes-128-cbc|tls\s*1\.[012]|ssl/i.test(value)
}

function isPqcReadyAlgorithm(value: string) {
  const lower = value.toLowerCase()
  return ['ml-kem', 'ml-dsa', 'falcon', 'sphincs', 'kyber', 'dilithium', 'aes-256', 'sha3', 'sha-3', 'tls 1.3', 'tls-1.3'].some((token) => lower.includes(token))
}

function operationType(text: string) {
  const lower = text.toLowerCase()
  if (lower.includes('decrypt') || lower.includes('unwrap')) return 'decryption'
  if (lower.includes('verify') || lower.includes('validation')) return 'verification'
  if (lower.includes('sign') || lower.includes('jwt') || lower.includes('signature')) return 'signing'
  if (lower.includes('handshake') || lower.includes('kem') || lower.includes('key exchange') || lower.includes('tls') || lower.includes('dh')) return 'keyExchange'
  if (lower.includes('key') || lower.includes('rotate') || lower.includes('qrng') || lower.includes('entropy')) return 'keyUsage'
  if (lower.includes('encrypt') || lower.includes('cipher') || lower.includes('aes')) return 'encryption'
  return 'other'
}

function classifyPattern(input: {
  text: string
  type: string
  timestamp: string | null
  metadata?: Record<string, unknown>
  flags?: Record<string, boolean>
}) {
  const lower = input.text.toLowerCase()
  const hour = input.timestamp ? new Date(input.timestamp).getHours() : -1
  if (input.flags?.downgradeDetected || input.flags?.isLegacy || isLegacyAlgorithm(input.text)) return 'Weak Algorithm Usage'
  if (input.flags?.shadowCrypto || /shadow|unapproved|unauthorized|unexpected|rare|uncommon/.test(lower)) return 'Rare Crypto Library'
  if (input.type === 'decryption' || /decrypt|unwrap/.test(lower)) return 'Excessive Decryption'
  if (input.type === 'keyUsage' || input.type === 'keyExchange' || /key rotation|key usage|kem|handshake/.test(lower)) return 'Unusual Key Usage'
  if (hour >= 0 && (hour < 6 || hour > 20)) return 'Unusual Time Pattern'
  if (/spike|burst|surge|volume|threshold|anomal/.test(lower)) return 'Volume Pattern'
  return 'Normal Behavior'
}

function statusFrom(value: unknown, severity: OperationSeverity) {
  const explicit = String(value || '').trim()
  if (explicit) return titleCase(explicit)
  return severity === 'critical' || severity === 'high' ? 'Active' : severity === 'medium' ? 'Investigating' : 'Resolved'
}

function confidenceFrom(score: number, source: string, hasMetadata: boolean) {
  const sourceWeight = source === 'runtime_crypto_events' ? 18 : source === 'scanner_alerts' ? 14 : source === 'pqc_scan_results' ? 12 : 8
  return clamp(62 + sourceWeight + Math.min(15, score / 6) + (hasMetadata ? 5 : 0), 0, 99)
}

function deltaPercent(current: number, previous: number) {
  if (previous <= 0) return current > 0 ? 100 : 0
  return Math.round(((current - previous) / previous) * 100)
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Behavioral analytics ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Behavioral analytics ${table} query failed:`, error?.message || error)
    return []
  }
}

router.get('/stream', async (req: Request, res: Response) => {
  sseHeaders(res)
  writeSse(res, 'behavioral-analytics-connected', {
    timestamp: new Date().toISOString(),
    source: 'dashboard.behavioral-analytics',
  })

  let closed = false
  const emitUpdate = () => {
    if (closed) return
    writeSse(res, 'behavioral-analytics-update', {
      timestamp: new Date().toISOString(),
      source: 'dashboard.behavioral-analytics',
      reason: 'tenant-behavioral-sync',
    })
  }

  emitUpdate()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': behavioral-analytics heartbeat\n\n')
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
      inventory,
      exposures,
      scanResults,
      scanSessions,
      securityEvents,
      generatedKeys,
      certificates,
      scannerAlerts,
      scannerAgents,
      qrngEvents,
      vaultAuditLogs,
    ] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, package_name, package_version, process_name, process_id, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', user.id).order('observed_at', { ascending: false }).limit(2500)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(1200)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1000)),
      safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
      safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(120)),
      safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(650)),
      safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
      safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(800)),
      safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(700)),
      safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, capabilities, last_seen_at, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(250)),
      safeRows(client, 'qrng_events', (q) => q.select('id, event_type, key_type, algorithm, key_length, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(500)),
      safeRows(client, 'vault_audit_logs', (q) => q.select('id, event_type, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(500)),
    ])

    const now = Date.now()
    const current7dStart = now - 7 * ONE_DAY_MS
    const previous7dStart = now - 14 * ONE_DAY_MS
    const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
    const operations: BehavioralOperation[] = []
    const seen = new Set<string>()

    const assetName = (assetId: unknown, fallback = 'Runtime entity') => {
      const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
      return textValue(asset?.name, fallback)
    }

    const addOperation = (input: {
      id: string
      source: string
      entity: string
      event: string
      text?: string
      severity?: unknown
      riskScore?: unknown
      type?: string
      timestamp?: string | null
      metadata?: Record<string, unknown>
      flags?: Record<string, boolean>
      status?: unknown
      action?: string
    }) => {
      if (seen.has(input.id)) return
      seen.add(input.id)

      const timestamp = input.timestamp || null
      const text = `${input.event || ''} ${input.text || ''}`.trim()
      const type = input.type || operationType(text)
      const pattern = classifyPattern({ text, type, timestamp, metadata: input.metadata, flags: input.flags })
      const explicitRisk = Number(input.riskScore || 0)
      const severity = explicitRisk >= 85 ? 'critical' : explicitRisk >= 65 ? 'high' : explicitRisk >= 40 ? 'medium' : normalizeSeverity(input.severity)
      const flagRisk = input.flags && Object.values(input.flags).some(Boolean)
      const riskScore = clamp(
        explicitRisk ||
        (severity === 'critical' ? 92 : severity === 'high' ? 74 : severity === 'medium' ? 48 : 18) +
        (pattern !== 'Normal Behavior' ? 10 : 0) +
        (flagRisk ? 12 : 0),
      )
      const anomalous = pattern !== 'Normal Behavior' || severityRank(severity) >= 2 || flagRisk

      operations.push({
        id: input.id,
        source: input.source,
        entity: textValue(input.entity, 'Runtime entity'),
        event: titleCase(input.event),
        pattern,
        severity,
        confidence: confidenceFrom(riskScore, input.source, Boolean(input.metadata && Object.keys(input.metadata).length)),
        status: statusFrom(input.status, severity),
        action: input.action || 'Inspect',
        timestamp,
        ms: dateMs(timestamp),
        riskScore,
        type,
        anomalous,
        text,
      })
    }

    for (const event of runtimeEvents || []) {
      const metadata = recordOf(event.metadata)
      addOperation({
        id: `runtime-${event.id}`,
        source: 'runtime_crypto_events',
        entity: textValue(event.asset_name, textValue(event.host, textValue(event.process_name, assetName(event.asset_id)))),
        event: event.event_type || event.operation_type || 'Runtime Crypto Event',
        text: `${event.operation_type || ''} ${event.algorithm || ''} ${event.key_exchange_algorithm || ''} ${event.cipher_suite || ''} ${event.tls_version || ''} ${event.protocol || ''} ${event.package_name || ''} ${event.process_name || ''}`,
        severity: event.severity,
        riskScore: event.risk_score,
        type: event.operation_type === 'key_exchange' ? 'keyExchange' : event.operation_type === 'key_usage' ? 'keyUsage' : event.operation_type || undefined,
        timestamp: event.observed_at || event.created_at,
        metadata,
        flags: {
          isLegacy: Boolean(event.is_legacy),
          downgradeDetected: Boolean(event.downgrade_detected),
          shadowCrypto: Boolean(event.shadow_crypto),
          hndlRisk: Boolean(event.hndl_risk),
          isPqc: Boolean(event.is_pqc),
        },
      })
    }

    for (const result of scanResults || []) {
      addOperation({
        id: `scan-result-${result.id}`,
        source: 'pqc_scan_results',
        entity: assetName(result.asset_id, 'Scan finding'),
        event: result.finding_type || 'Scan Finding',
        text: `${result.description || ''} ${result.algorithm || ''} ${result.threat_level || ''}`,
        severity: result.threat_level,
        type: operationType(`${result.finding_type || ''} ${result.algorithm || ''}`),
        timestamp: result.created_at,
        metadata: recordOf(result.metadata),
        action: result.remediation ? 'Remediate' : 'Inspect',
      })
    }

    for (const exposure of exposures || []) {
      addOperation({
        id: `exposure-${exposure.id}`,
        source: 'crypto_exposures',
        entity: assetName(exposure.asset_id, 'Crypto exposure'),
        event: exposure.exposure_type || 'Crypto Exposure',
        text: `${exposure.description || ''} ${exposure.detected_value || ''}`,
        severity: exposure.severity,
        timestamp: exposure.updated_at || exposure.created_at,
        metadata: recordOf(exposure.metadata),
        action: 'Review',
      })
    }

    for (const item of inventory || []) {
      addOperation({
        id: `inventory-${item.id}`,
        source: 'crypto_inventory',
        entity: textValue(item.name, assetName(item.asset_id, 'Discovered crypto')),
        event: item.item_type || 'Crypto Inventory',
        text: `${item.algorithm || ''} ${item.protocol || ''} ${item.exposure_level || ''}`,
        severity: item.is_vulnerable && !item.is_quantum_safe ? item.exposure_level || 'medium' : 'low',
        type: operationType(`${item.item_type || ''} ${item.algorithm || ''} ${item.protocol || ''}`),
        timestamp: item.discovered_at || item.created_at,
        metadata: recordOf(item.metadata),
        flags: {
          isLegacy: Boolean(item.is_vulnerable && !item.is_quantum_safe) || isLegacyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`),
          isPqc: Boolean(item.is_quantum_safe) || isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`),
        },
        status: item.is_quantum_safe ? 'Observed' : item.is_vulnerable ? 'Active' : 'Resolved',
      })
    }

    for (const event of securityEvents || []) {
      addOperation({
        id: `security-${event.id}`,
        source: 'security_events',
        entity: textValue(event.resource_name, assetName(event.asset_id, textValue(event.resource_type, 'Security event'))),
        event: event.event_type || 'Security Event',
        text: event.message || '',
        severity: event.severity,
        timestamp: event.created_at,
        metadata: recordOf(event.metadata),
        status: event.is_read ? 'Resolved' : 'Active',
      })
    }

    for (const key of generatedKeys || []) {
      addOperation({
        id: `key-${key.id}`,
        source: 'generated_keys',
        entity: textValue(key.label, 'Generated key'),
        event: 'Key Lifecycle Event',
        text: `${key.algorithm || ''} ${key.entropy_source || ''} ${key.status || ''} ${key.bit_length || ''}`,
        severity: String(key.status || '').toLowerCase().includes('revoked') || String(key.status || '').toLowerCase().includes('compromised') ? 'medium' : 'low',
        type: 'keyUsage',
        timestamp: key.updated_at || key.created_at,
        metadata: recordOf(key.metadata),
        status: key.status,
      })
    }

    for (const cert of certificates || []) {
      addOperation({
        id: `certificate-${cert.id}`,
        source: 'certificates',
        entity: textValue(cert.name, textValue(cert.subject, assetName(cert.asset_id, 'Certificate'))),
        event: 'Certificate Behavior',
        text: `${cert.algorithm || ''} ${cert.status || ''} ${cert.is_expiring_soon ? 'expiring soon' : ''}`,
        severity: cert.is_expiring_soon || (!cert.is_quantum_safe && isLegacyAlgorithm(`${cert.algorithm || ''}`)) ? 'medium' : 'low',
        timestamp: cert.updated_at || cert.created_at,
        metadata: recordOf(cert.metadata),
        flags: {
          isLegacy: !cert.is_quantum_safe && isLegacyAlgorithm(`${cert.algorithm || ''}`),
          isPqc: Boolean(cert.is_quantum_safe),
        },
        status: cert.status,
      })
    }

    for (const alert of scannerAlerts || []) {
      const metadata = recordOf(alert.metadata)
      addOperation({
        id: `scanner-alert-${alert.id}`,
        source: 'scanner_alerts',
        entity: textValue(metadata.assetName || metadata.resourceName || metadata.hostname, textValue(alert.category, 'Scanner alert')),
        event: alert.title || alert.category || 'Scanner Alert',
        text: `${alert.message || ''} ${alert.recommendation || ''}`,
        severity: alert.severity,
        timestamp: alert.updated_at || alert.created_at,
        metadata,
        status: alert.status,
        action: alert.recommendation ? 'Remediate' : 'Inspect',
      })
    }

    for (const event of qrngEvents || []) {
      addOperation({
        id: `qrng-${event.id}`,
        source: 'qrng_events',
        entity: textValue(event.key_type, 'QRNG key material'),
        event: event.event_type || 'QRNG Event',
        text: `${event.algorithm || ''} ${event.key_length || ''}`,
        severity: 'low',
        type: 'keyUsage',
        timestamp: event.created_at,
        metadata: recordOf(event.metadata),
      })
    }

    for (const log of vaultAuditLogs || []) {
      const metadata = recordOf(log.metadata)
      addOperation({
        id: `vault-${log.id}`,
        source: 'vault_audit_logs',
        entity: textValue(metadata.resourceName || metadata.resource_name || metadata.fileName || metadata.file_name, 'Vault record'),
        event: log.event_type || 'Vault Audit',
        text: Object.values(metadata).filter((value) => typeof value === 'string').join(' '),
        severity: metadata.severity || metadata.result || metadata.status,
        timestamp: log.created_at,
        metadata,
      })
    }

    operations.sort((a, b) => b.ms - a.ms)

    const currentOps7d = operations.filter((item) => item.ms >= current7dStart)
    const previousOps7d = operations.filter((item) => item.ms >= previous7dStart && item.ms < current7dStart)
    const recentOps24h = operations.filter((item) => item.ms >= now - ONE_DAY_MS)
    const currentAnomalies = currentOps7d.filter((item) => item.anomalous)
    const previousAnomalies = previousOps7d.filter((item) => item.anomalous)
    const anomalousEntitySet = new Set(currentAnomalies.map((item) => item.entity))
    const averageRisk = currentOps7d.length
      ? currentOps7d.reduce((sum, item) => sum + item.riskScore, 0) / currentOps7d.length
      : operations.length
        ? operations.slice(0, 100).reduce((sum, item) => sum + item.riskScore, 0) / Math.min(100, operations.length)
        : 0
    const severeAnomalyWeight = currentAnomalies.filter((item) => severityRank(item.severity) >= 3).length * 2
    const behaviorRiskScore = clamp(averageRisk + percentOf(currentAnomalies.length, Math.max(1, currentOps7d.length)) * 0.25 + severeAnomalyWeight)

    const ratePerSecond = (count: number) => Number((count / (24 * 60 * 60)).toFixed(count >= 86400 ? 1 : 3))
    const cryptoOpsPerSec = ratePerSecond(recentOps24h.length)
    const operationsDelta = deltaPercent(currentOps7d.length, previousOps7d.length)
    const unusualPatternCount = currentAnomalies.length
    const unusualPatternDelta = deltaPercent(currentAnomalies.length, previousAnomalies.length)

    const evidenceSources = [
      runtimeEvents,
      scanResults,
      exposures,
      securityEvents,
      inventory,
      certificates,
      generatedKeys,
      scannerAlerts,
      qrngEvents,
      vaultAuditLogs,
    ]
    const activeSources = evidenceSources.filter((rows) => (rows || []).length > 0).length
    const latestEventAt = latestDate(...operations.slice(0, 20).map((item) => item.timestamp), ...scanSessions.map((session: any) => session.updated_at || session.completed_at || session.started_at))
    const freshnessHours = latestEventAt ? (now - dateMs(latestEventAt)) / (60 * 60 * 1000) : Number.POSITIVE_INFINITY
    const freshnessScore = freshnessHours <= 24 ? 18 : freshnessHours <= 168 ? 10 : 2
    const aiConfidence = operations.length ? clamp(44 + activeSources * 4 + Math.min(18, operations.length / 18) + freshnessScore) : 0

    const bucketStart = new Date()
    bucketStart.setHours(0, 0, 0, 0)
    bucketStart.setDate(bucketStart.getDate() - 7)
    const behaviorTrend = Array.from({ length: 8 }, (_, index) => {
      const start = bucketStart.getTime() + index * ONE_DAY_MS
      const end = start + ONE_DAY_MS
      const bucketOps = operations.filter((item) => item.ms >= start && item.ms < end)
      const anomalous = bucketOps.filter((item) => item.anomalous).length
      const normal = bucketOps.length - anomalous
      return {
        label: new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        normal,
        anomalous,
        predicted: Math.round((normal + anomalous + (index > 0 ? anomalous : 0)) / (index > 0 ? 2 : 1)),
      }
    })

    const distributionRows = [
      { label: 'Normal', count: operations.filter((item) => !item.anomalous).length },
      { label: 'Anomalous', count: operations.filter((item) => item.anomalous && severityRank(item.severity) >= 3).length },
      { label: 'Potential Risk', count: operations.filter((item) => item.anomalous && severityRank(item.severity) < 3).length },
      { label: 'Unknown', count: operations.filter((item) => item.type === 'other' && item.pattern === 'Normal Behavior').length },
    ]
    const distributionTotal = distributionRows.reduce((sum, row) => sum + row.count, 0)
    const behaviorDistribution = distributionRows.map((row) => ({
      ...row,
      percent: percentOf(row.count, Math.max(1, distributionTotal)),
    }))

    const patternOrder = ['Unusual Key Usage', 'Excessive Decryption', 'Weak Algorithm Usage', 'Unusual Time Pattern', 'Rare Crypto Library', 'Volume Pattern']
    const categoryTotal = Math.max(1, currentAnomalies.length)
    const anomalyCategories = patternOrder
      .map((label) => {
        const count = currentAnomalies.filter((item) => item.pattern === label).length
        return { label, count, percent: percentOf(count, categoryTotal) }
      })
      .filter((row) => row.count > 0)

    const scoreFor = (label: string) => percentOf(currentAnomalies.filter((item) => item.pattern === label).length, Math.max(1, currentOps7d.length))
    const behavioralPatternScore = [
      { label: 'Key Usage', you: clamp(100 - scoreFor('Unusual Key Usage')), baseline: clamp(100 - percentOf(previousAnomalies.filter((item) => item.pattern === 'Unusual Key Usage').length, Math.max(1, previousOps7d.length))) },
      { label: 'Algorithm Strength', you: clamp(100 - scoreFor('Weak Algorithm Usage')), baseline: clamp(100 - percentOf(previousAnomalies.filter((item) => item.pattern === 'Weak Algorithm Usage').length, Math.max(1, previousOps7d.length))) },
      { label: 'Time Pattern', you: clamp(100 - scoreFor('Unusual Time Pattern')), baseline: clamp(100 - percentOf(previousAnomalies.filter((item) => item.pattern === 'Unusual Time Pattern').length, Math.max(1, previousOps7d.length))) },
      { label: 'Volume Pattern', you: clamp(100 - scoreFor('Volume Pattern')), baseline: clamp(100 - percentOf(previousAnomalies.filter((item) => item.pattern === 'Volume Pattern').length, Math.max(1, previousOps7d.length))) },
      { label: 'Entity Reputation', you: clamp(100 - percentOf(anomalousEntitySet.size, Math.max(1, assets.length || anomalousEntitySet.size))), baseline: clamp(100 - percentOf(new Set(previousAnomalies.map((item) => item.entity)).size, Math.max(1, assets.length || anomalousEntitySet.size))) },
    ]

    const entityMap = new Map<string, { entity: string; count: number; current: number; previous: number; risk: number; latest: string | null }>()
    for (const item of operations.filter((operation) => operation.anomalous)) {
      const row = entityMap.get(item.entity) || { entity: item.entity, count: 0, current: 0, previous: 0, risk: 0, latest: null }
      row.count += 1
      row.risk = Math.max(row.risk, item.riskScore)
      row.latest = latestDate(row.latest, item.timestamp)
      if (item.ms >= current7dStart) row.current += 1
      if (item.ms >= previous7dStart && item.ms < current7dStart) row.previous += 1
      entityMap.set(item.entity, row)
    }

    const topEntities = Array.from(entityMap.values())
      .map((row) => ({
        entity: row.entity,
        anomalyScore: clamp(row.risk),
        change: deltaPercent(row.current, row.previous),
        latestSeenAt: row.latest,
      }))
      .sort((a, b) => b.anomalyScore - a.anomalyScore || b.change - a.change)
      .slice(0, 6)

    const insights = [
      ...currentAnomalies
        .filter((item) => severityRank(item.severity) >= 3)
        .slice(0, 3)
        .map((item) => ({
          id: item.id,
          title: item.pattern,
          message: `${item.entity} reported ${item.event.toLowerCase()}.`,
          severity: item.severity,
          timestamp: item.timestamp,
        })),
      ...anomalyCategories.slice(0, 2).map((category) => ({
        id: `category-${category.label}`,
        title: `${category.label} Increased`,
        message: `${category.count} authenticated event${category.count === 1 ? '' : 's'} matched this pattern in the selected window.`,
        severity: category.percent >= 40 ? 'high' as OperationSeverity : 'medium' as OperationSeverity,
        timestamp: latestEventAt,
      })),
    ].slice(0, 4)

    const events = operations
      .slice(0, 12)
      .map((item) => ({
        id: item.id,
        time: item.timestamp,
        entity: item.entity,
        event: item.event,
        pattern: item.pattern,
        severity: item.severity,
        confidence: item.confidence,
        status: item.status,
        action: item.action,
      }))

    const modelDrift = clamp(Math.abs(percentOf(currentAnomalies.length, Math.max(1, currentOps7d.length)) - percentOf(previousAnomalies.length, Math.max(1, previousOps7d.length))))
    const falsePositiveAlerts = (scannerAlerts || []).filter((alert: any) => /false[_ -]?positive|suppressed/i.test(`${alert.status || ''} ${alert.category || ''}`)).length
    const falsePositiveRate = Number((falsePositiveAlerts / Math.max(1, (scannerAlerts || []).length) * 100).toFixed(1))
    const modelAccuracy = clamp(aiConfidence ? aiConfidence - Math.min(12, falsePositiveRate / 2) - Math.min(8, modelDrift / 5) : 0)

    return res.json({
      data: {
        generatedAt: new Date().toISOString(),
        latestEventAt,
        latestScanAt: latestDate(...scanSessions.map((session: any) => session.completed_at || session.updated_at || session.started_at || session.created_at)),
        filters: {
          environments: Array.from(new Set((assets || []).map((asset: any) => asset.environment).filter(Boolean))).sort(),
        },
        metrics: {
          behaviorRiskScore,
          behaviorRiskLevel: behaviorRiskScore >= 75 ? 'High Risk' : behaviorRiskScore >= 45 ? 'Medium Risk' : behaviorRiskScore > 0 ? 'Low Risk' : 'No Runtime Data',
          riskDelta: deltaPercent(currentAnomalies.reduce((sum, item) => sum + item.riskScore, 0), previousAnomalies.reduce((sum, item) => sum + item.riskScore, 0)),
          anomalousEntities: anomalousEntitySet.size,
          anomalousEntitiesDelta: deltaPercent(anomalousEntitySet.size, new Set(previousAnomalies.map((item) => item.entity)).size),
          cryptoOpsPerSec,
          cryptoOpsDelta: operationsDelta,
          unusualPatterns: unusualPatternCount,
          unusualPatternsDelta: unusualPatternDelta,
          aiConfidence,
          totalOperations: operations.length,
          totalAssets: assets.length,
          totalFindings: scanResults.length + exposures.length + scannerAlerts.length,
        },
        behaviorTrend,
        behaviorDistribution,
        anomalyCategories,
        behavioralPatternScore,
        insights,
        topEntities,
        events,
        modelPerformance: {
          modelAccuracy,
          falsePositiveRate,
          modelDrift,
          lastModelUpdate: latestEventAt,
        },
        telemetry: {
          connectedAgents: (scannerAgents || []).filter((agent: any) => String(agent.status || '').toLowerCase() === 'active').length,
          totalAgents: scannerAgents.length,
          runtimeEvents: runtimeEvents.length,
          eventPipelineStatus: runtimeEvents.length ? 'active' : scannerAgents.length ? 'waiting_for_runtime_events' : 'no_agents',
          sources: {
            runtimeEvents: runtimeEvents.length,
            scanResults: scanResults.length,
            exposures: exposures.length,
            securityEvents: securityEvents.length,
            inventory: inventory.length,
            certificates: certificates.length,
            generatedKeys: generatedKeys.length,
            scannerAlerts: scannerAlerts.length,
          },
        },
      },
    })
  } catch (err) {
    console.error('Behavioral analytics dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch behavioral analytics telemetry' } })
  }
})

export default router
