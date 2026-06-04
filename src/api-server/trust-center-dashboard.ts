import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildTenantTelemetrySync } from './tenant-telemetry-sync'

const ONE_DAY_MS = 24 * 60 * 60 * 1000

type TrustDashboardKind = 'continuous' | 'identity' | 'device' | 'analytics' | 'zero'
type Severity = 'critical' | 'high' | 'medium' | 'low'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

type TrustSignal = {
  id: string
  sourceTable: string
  domain: string
  title: string
  subject: string
  subjectType: string
  status: string
  severity: Severity
  score: number
  trusted: boolean
  pqcReady: boolean
  encrypted: boolean
  recent: boolean
  timestamp: string | null
  ms: number
  detail: string
}

const ROUTE_META: Record<TrustDashboardKind, { eventPrefix: string; routeLabel: string }> = {
  continuous: { eventPrefix: 'continuous-trust', routeLabel: 'Continuous trust validation' },
  identity: { eventPrefix: 'identity-trust', routeLabel: 'Identity trust' },
  device: { eventPrefix: 'device-trust', routeLabel: 'Device trust' },
  analytics: { eventPrefix: 'trust-analytics', routeLabel: 'Trust analytics' },
  zero: { eventPrefix: 'zero-trust', routeLabel: 'Zero trust validation' },
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

function titleCase(value: unknown, fallback = 'Trust Signal') {
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
  if (score >= 85) return 'critical'
  if (score >= 68) return 'high'
  if (score >= 38) return 'medium'
  return 'low'
}

function isPqcAlgorithm(value: string) {
  return /ml-kem|ml_dsa|ml-dsa|kyber|dilithium|sphincs|falcon|bike|hqc|ntru|hybrid|pqc|post.quantum/i.test(value)
}

function isWeakCrypto(value: string, keySize = 0) {
  const text = `${value} ${keySize}`.toLowerCase()
  if (/ssl|tls\s*1\.[01]|rc4|3des|des|cbc|sha-?1|md5|null|export|anon|rsa_with|dsa/.test(text)) return true
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
      console.warn(`Trust center ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Trust center ${table} query failed:`, error?.message || error)
    return []
  }
}

function buildRouter(kind: TrustDashboardKind) {
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

      const data = await buildTrustSnapshot(kind, req.token, req.user.id)
      return res.json({ data })
    } catch (error: any) {
      console.error(`${meta.routeLabel} dashboard error:`, error)
      return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || `Failed to fetch ${meta.routeLabel.toLowerCase()} data` } })
    }
  })

  return router
}

async function buildTrustSnapshot(kind: TrustDashboardKind, token: string, userId: string) {
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
    vulnerabilities,
    certificates,
    generatedKeys,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    profileRows,
    securitySettings,
    userDevices,
    userSessions,
    userSecurityEvents,
    authEvents,
    securityEvents,
    vaultAuditLogs,
    auditLogs,
    migrationJobs,
    complianceEvidence,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(5000)),
    safeRows(client, 'scanner_evidence', (q) => q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, protocol, observed_algorithm, key_size, confidence, raw_evidence, processed_at, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(2500)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, target_scope, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(220)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(2200)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'vulnerabilities', (q) => q.select('id, asset_id, title, description, severity, cvss_score, status, source, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, capabilities, last_seen_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(600)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, display_name, status, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('id, agent_id, status, telemetry, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1500)),
    safeRows(client, 'profiles', (q) => q.select('*').eq('id', userId).limit(1)),
    safeRows(client, 'user_security_settings', (q) => q.select('*').eq('user_id', userId).limit(1)),
    safeRows(client, 'user_devices', (q) => q.select('*').eq('user_id', userId).order('last_active', { ascending: false }).limit(500)),
    safeRows(client, 'user_sessions', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(500)),
    safeRows(client, 'user_security_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'auth_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1400)),
    safeRows(client, 'vault_audit_logs', (q) => q.select('id, event_type, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(900)),
    safeRows(client, 'audit_logs', (q) => q.select('id, action, entity_type, entity_id, details, ip_address, user_agent, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(900)),
    safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, status, priority, algorithm_from, algorithm_to, metadata, created_at, updated_at, completed_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(600)),
    safeRows(client, 'compliance_evidence', (q) => q.select('id, asset_id, framework, control_id, status, evidence_type, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(900)),
  ])

  const now = Date.now()
  const recentStart = now - 7 * ONE_DAY_MS
  const previousStart = now - 14 * ONE_DAY_MS
  const staleStart = now - 30 * ONE_DAY_MS
  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
  const signals: TrustSignal[] = []
  const seen = new Set<string>()

  const assetName = (assetId: unknown, fallback = 'Unmapped asset') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.name, fallback)
  }

  const assetType = (assetId: unknown, fallback = 'Trust subject') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.type, fallback)
  }

  const addSignal = (input: {
    id: string
    sourceTable: string
    domain: string
    title: string
    subject?: string
    subjectType?: string
    assetId?: string | null
    status?: string
    severity?: unknown
    score?: unknown
    trusted?: boolean
    pqcReady?: boolean
    encrypted?: boolean
    timestamp?: string | null
    detail?: string
  }) => {
    if (seen.has(input.id)) return
    seen.add(input.id)
    const timestamp = input.timestamp || null
    const ms = dateMs(timestamp)
    const severity = normalizeSeverity(input.severity)
    const trusted = Boolean(input.trusted)
    const pqcReady = Boolean(input.pqcReady)
    const encrypted = input.encrypted ?? false
    let score = Number(input.score || 0)
    if (!Number.isFinite(score) || score <= 0) {
      score = 22
      if (severityRank(severity) >= 3) score += 48
      else if (severityRank(severity) === 2) score += 24
      if (!trusted) score += 8
      if (!pqcReady && /crypto|certificate|key|runtime|zero/i.test(input.domain)) score += 8
      if (!encrypted && /encryption|runtime|vault|zero/i.test(input.domain)) score += 8
      if (ms && ms < staleStart) score += 6
    }
    const finalScore = clamp(score)
    const finalSeverity = severityRank(severity) > 1 ? severity : severityForScore(finalScore)

    signals.push({
      id: input.id,
      sourceTable: input.sourceTable,
      domain: input.domain,
      title: titleCase(input.title),
      subject: textValue(input.subject, assetName(input.assetId, 'Trust subject')),
      subjectType: textValue(input.subjectType, assetType(input.assetId)),
      status: textValue(input.status, trusted ? 'trusted' : finalScore >= 68 ? 'review' : 'observed'),
      severity: finalSeverity,
      score: finalScore,
      trusted,
      pqcReady,
      encrypted,
      recent: Boolean(ms && ms >= recentStart),
      timestamp,
      ms,
      detail: input.detail || '',
    })
  }

  for (const asset of assets || []) {
    const metadata = recordOf(asset.metadata)
    const status = textValue(asset.status, 'observed')
    const criticality = String(asset.criticality || metadata.criticality || '').toLowerCase()
    const trusted = !/unknown|unmanaged|inactive|retired|compromised/.test(status.toLowerCase())
    addSignal({
      id: `asset-${asset.id}`,
      sourceTable: 'assets',
      domain: 'Asset Trust',
      title: `${asset.type || 'Asset'} posture`,
      subject: textValue(asset.name, 'Asset'),
      subjectType: textValue(asset.type, 'Asset'),
      assetId: asset.id,
      status,
      severity: /critical|high/.test(criticality) && !trusted ? 'high' : trusted ? 'low' : 'medium',
      trusted,
      pqcReady: Boolean(metadata.pqc_ready || metadata.quantum_safe || metadata.is_quantum_safe),
      encrypted: Boolean(metadata.encrypted || metadata.tls || metadata.encryption),
      timestamp: asset.updated_at || asset.created_at,
      detail: `${asset.environment || ''} ${asset.region || ''} ${criticality}`,
    })
  }

  for (const event of runtimeEvents || []) {
    const metadata = recordOf(event.metadata)
    const algorithm = textValue(event.algorithm, textValue(event.key_exchange_algorithm, textValue(event.cipher_suite, '')))
    const weak = Boolean(event.is_legacy || event.downgrade_detected || event.shadow_crypto || isWeakCrypto(`${algorithm} ${event.tls_version || ''}`, numberValue(event.key_size)))
    addSignal({
      id: `runtime-${event.id}`,
      sourceTable: 'runtime_crypto_events',
      domain: event.hndl_risk ? 'HNDL Trust' : weak ? 'Runtime Drift' : 'Runtime Trust',
      title: event.event_type || event.operation_type || 'Runtime crypto event',
      subject: textValue(event.asset_name, textValue(event.host, assetName(event.asset_id))),
      subjectType: textValue(event.asset_type, textValue(event.source_type, 'Runtime')),
      assetId: event.asset_id,
      status: weak ? 'review' : 'trusted',
      severity: event.severity,
      score: event.risk_score,
      trusted: !weak,
      pqcReady: Boolean(event.is_pqc) || isPqcAlgorithm(`${algorithm}`),
      encrypted: !/plaintext|cleartext|unencrypted/i.test(`${event.operation_type || ''} ${event.event_type || ''} ${JSON.stringify(metadata)}`),
      timestamp: event.observed_at || event.created_at,
      detail: `${event.protocol || ''} ${event.tls_version || ''} ${algorithm} ${event.process_name || ''}`,
    })
  }

  for (const item of cryptoInventory || []) {
    const metadata = recordOf(item.metadata)
    const weak = Boolean(item.is_vulnerable && !item.is_quantum_safe) || isWeakCrypto(`${item.algorithm || ''} ${item.protocol || ''}`, numberValue(item.key_size))
    addSignal({
      id: `inventory-${item.id}`,
      sourceTable: 'crypto_inventory',
      domain: 'Cryptographic Trust',
      title: item.item_type || 'Crypto inventory',
      subject: textValue(item.name, assetName(item.asset_id)),
      subjectType: textValue(item.item_type, assetType(item.asset_id, 'Crypto item')),
      assetId: item.asset_id,
      status: item.is_quantum_safe ? 'pqc-ready' : weak ? 'vulnerable' : 'observed',
      severity: weak ? item.exposure_level || 'medium' : 'low',
      trusted: !weak,
      pqcReady: Boolean(item.is_quantum_safe) || isPqcAlgorithm(`${item.algorithm || ''}`),
      encrypted: true,
      timestamp: item.discovered_at || item.created_at,
      detail: `${item.algorithm || ''} ${item.protocol || ''} ${JSON.stringify(metadata)}`,
    })
  }

  for (const exposure of cryptoExposures || []) {
    addSignal({
      id: `exposure-${exposure.id}`,
      sourceTable: 'crypto_exposures',
      domain: 'Crypto Exposure',
      title: exposure.exposure_type || 'Crypto exposure',
      subject: assetName(exposure.asset_id, 'Crypto exposure'),
      subjectType: assetType(exposure.asset_id, 'Exposure'),
      assetId: exposure.asset_id,
      status: 'active',
      severity: exposure.severity,
      trusted: false,
      pqcReady: isPqcAlgorithm(`${exposure.detected_value || ''} ${exposure.description || ''}`),
      encrypted: !/plaintext|cleartext|unencrypted/i.test(`${exposure.description || ''} ${exposure.detected_value || ''}`),
      timestamp: exposure.updated_at || exposure.created_at,
      detail: `${exposure.description || ''} ${exposure.detected_value || ''}`,
    })
  }

  for (const alert of scannerAlerts || []) {
    const metadata = recordOf(alert.metadata)
    addSignal({
      id: `scanner-alert-${alert.id}`,
      sourceTable: 'scanner_alerts',
      domain: 'Scanner Trust',
      title: alert.title || alert.category || 'Scanner alert',
      subject: firstString(metadata, ['assetName', 'resourceName', 'hostname', 'target']) || textValue(alert.category, 'Scanner alert'),
      subjectType: firstString(metadata, ['assetType', 'resourceType']) || 'Scanner',
      status: textValue(alert.status, 'active'),
      severity: alert.severity,
      trusted: false,
      pqcReady: isPqcAlgorithm(`${alert.message || ''} ${alert.recommendation || ''}`),
      encrypted: true,
      timestamp: alert.updated_at || alert.created_at,
      detail: `${alert.message || ''} ${alert.recommendation || ''}`,
    })
  }

  for (const session of scanSessions || []) {
    const metadata = recordOf(session.metadata)
    const status = String(session.status || 'pending').toLowerCase()
    const failed = /fail|error|cancel|blocked/.test(status)
    const running = /run|scan|progress|pending|queued/.test(status)
    const findings = numberValue(session.findings_count)
    addSignal({
      id: `scan-session-${session.id}`,
      sourceTable: 'pqc_scan_sessions',
      domain: 'Scan Lifecycle',
      title: failed ? 'Scan requires attention' : running ? 'Scan in progress' : 'Scan completed',
      subject: textValue(session.target_scope, firstString(metadata, ['target', 'targetScope', 'scope']) || 'PQC scan'),
      subjectType: 'Scan Session',
      status: textValue(session.status, running ? 'running' : 'completed'),
      severity: failed ? 'high' : findings > 0 ? 'medium' : 'low',
      trusted: !failed,
      pqcReady: !failed && findings === 0,
      encrypted: true,
      timestamp: session.completed_at || session.updated_at || session.started_at || session.created_at,
      detail: `${numberValue(session.progress)}% complete - ${findings} finding${findings === 1 ? '' : 's'} - ${numberValue(session.scanned_assets)}/${numberValue(session.total_assets)} assets`,
    })
  }

  for (const evidence of scannerEvidence || []) {
    const raw = recordOf(evidence.raw_evidence)
    const algorithm = textValue(evidence.observed_algorithm, firstString(raw, ['algorithm', 'cipher', 'cipher_suite']))
    const weak = isWeakCrypto(`${algorithm} ${evidence.protocol || ''}`, numberValue(evidence.key_size))
    addSignal({
      id: `evidence-${evidence.id}`,
      sourceTable: 'scanner_evidence',
      domain: 'Scanner Evidence',
      title: evidence.evidence_type || 'Evidence',
      subject: textValue(evidence.asset_name, textValue(evidence.host, textValue(evidence.target, 'Evidence'))),
      subjectType: textValue(evidence.asset_type, textValue(evidence.source_type, 'Evidence')),
      status: weak ? 'review' : 'observed',
      severity: weak ? 'medium' : 'low',
      trusted: !weak,
      pqcReady: isPqcAlgorithm(`${algorithm}`),
      encrypted: !/plaintext|cleartext/i.test(JSON.stringify(raw)),
      timestamp: evidence.observed_at || evidence.processed_at || evidence.created_at,
      detail: `${algorithm} ${evidence.protocol || ''} ${evidence.confidence || ''}`,
    })
  }

  for (const result of scanResults || []) {
    addSignal({
      id: `scan-result-${result.id}`,
      sourceTable: 'pqc_scan_results',
      domain: 'Scan Finding',
      title: result.finding_type || 'Scan finding',
      subject: assetName(result.asset_id, 'Scan finding'),
      subjectType: assetType(result.asset_id, 'Scan result'),
      assetId: result.asset_id,
      status: 'active',
      severity: result.threat_level,
      trusted: false,
      pqcReady: isPqcAlgorithm(`${result.algorithm || ''}`),
      encrypted: true,
      timestamp: result.created_at,
      detail: `${result.algorithm || ''} ${result.description || ''} ${result.remediation || ''}`,
    })
  }

  for (const vulnerability of vulnerabilities || []) {
    const metadata = recordOf(vulnerability.metadata)
    const status = String(vulnerability.status || 'open').toLowerCase()
    const resolved = /resolved|closed|fixed|false_positive|accepted/.test(status)
    addSignal({
      id: `vulnerability-${vulnerability.id}`,
      sourceTable: 'vulnerabilities',
      domain: 'Vulnerability Trust',
      title: vulnerability.title || 'Vulnerability finding',
      subject: assetName(vulnerability.asset_id, 'Vulnerability'),
      subjectType: assetType(vulnerability.asset_id, 'Vulnerability'),
      assetId: vulnerability.asset_id,
      status: textValue(vulnerability.status, resolved ? 'resolved' : 'open'),
      severity: vulnerability.severity,
      score: numberValue(vulnerability.cvss_score) * 10,
      trusted: resolved,
      pqcReady: Boolean(metadata.pqc_ready || metadata.quantum_safe || metadata.is_quantum_safe),
      encrypted: true,
      timestamp: vulnerability.updated_at || vulnerability.created_at,
      detail: `${vulnerability.source || ''} ${vulnerability.description || ''}`,
    })
  }

  for (const cert of certificates || []) {
    const keySize = numberValue(cert.key_size)
    const weak = !cert.is_quantum_safe && isWeakCrypto(`${cert.algorithm || ''}`, keySize)
    addSignal({
      id: `certificate-${cert.id}`,
      sourceTable: 'certificates',
      domain: 'Certificate Trust',
      title: cert.is_expiring_soon ? 'Certificate renewal required' : 'Certificate telemetry',
      subject: textValue(cert.name, textValue(cert.subject, assetName(cert.asset_id, 'Certificate'))),
      subjectType: 'Certificate',
      assetId: cert.asset_id,
      status: textValue(cert.status, cert.is_expiring_soon ? 'expiring' : 'active'),
      severity: cert.is_expiring_soon || weak ? 'medium' : 'low',
      trusted: !cert.is_expiring_soon && !weak,
      pqcReady: Boolean(cert.is_quantum_safe) || isPqcAlgorithm(`${cert.algorithm || ''}`),
      encrypted: true,
      timestamp: cert.updated_at || cert.created_at,
      detail: `${cert.algorithm || ''} ${cert.issuer || ''} ${cert.not_after || ''}`,
    })
  }

  for (const key of generatedKeys || []) {
    const label = recordOf(key.label)
    const metadata = recordOf(key.metadata)
    const algorithm = textValue(key.algorithm, 'Generated key')
    const status = String(key.status || 'active').toLowerCase()
    const revoked = Boolean(key.revoked_at || /revoked|compromised|expired/.test(status))
    const weak = isWeakCrypto(algorithm, numberValue(key.bit_length))
    addSignal({
      id: `key-${key.id}`,
      sourceTable: 'generated_keys',
      domain: /otp|token/i.test(algorithm) ? 'Identity Trust' : 'Key Trust',
      title: algorithm,
      subject: firstString(label, ['purpose', 'common_name', 'token_id']) || algorithm,
      subjectType: textValue(key.entropy_source, 'Generated key'),
      status,
      severity: revoked || weak ? 'medium' : 'low',
      trusted: !revoked && !weak,
      pqcReady: isPqcAlgorithm(algorithm),
      encrypted: true,
      timestamp: key.updated_at || key.created_at,
      detail: `${key.bit_length || ''} ${key.entropy_source || ''} ${JSON.stringify(metadata)}`,
    })
  }

  for (const device of userDevices || []) {
    const trusted = Boolean(device.trusted && !device.revoked_at)
    addSignal({
      id: `user-device-${device.id}`,
      sourceTable: 'user_devices',
      domain: 'Device Trust',
      title: trusted ? 'Trusted device' : 'Standard device',
      subject: textValue(device.device_name, 'Unknown device'),
      subjectType: textValue(device.device_type, 'Device'),
      status: device.revoked_at ? 'revoked' : trusted ? 'trusted' : 'standard',
      severity: device.revoked_at ? 'medium' : trusted ? 'low' : 'medium',
      trusted,
      encrypted: true,
      timestamp: device.last_active || device.updated_at || device.created_at,
      detail: `${device.ip_address || ''} ${device.user_agent || ''}`,
    })
  }

  for (const session of userSessions || []) {
    const expired = session.expires_at && dateMs(session.expires_at) < now
    const revoked = Boolean(session.revoked_at)
    addSignal({
      id: `user-session-${session.id}`,
      sourceTable: 'user_sessions',
      domain: 'Identity Trust',
      title: revoked ? 'Revoked session' : expired ? 'Expired session' : 'Active session',
      subject: textValue(session.device_name, 'User session'),
      subjectType: 'Session',
      status: revoked ? 'revoked' : expired ? 'expired' : session.trusted ? 'trusted' : 'active',
      severity: revoked ? 'medium' : expired ? 'low' : session.trusted ? 'low' : 'medium',
      trusted: Boolean(session.trusted && !revoked && !expired),
      encrypted: true,
      timestamp: session.last_seen_at || session.created_at,
      detail: `${session.ip_address || ''} ${session.user_agent || ''}`,
    })
  }

  for (const event of userSecurityEvents || []) {
    addSignal({
      id: `${event.event_type || 'security'}-${event.id}`,
      sourceTable: 'user_security_events',
      domain: 'Identity Trust',
      title: event.event_type || 'Identity event',
      subject: textValue(event.ip_address, 'Account activity'),
      subjectType: 'Identity Event',
      status: /success|enabled|trusted|updated/i.test(`${event.severity || ''} ${event.event_type || ''}`) ? 'trusted' : 'review',
      severity: event.severity,
      trusted: /success|enabled|trusted|updated/i.test(`${event.severity || ''} ${event.event_type || ''}`),
      encrypted: true,
      timestamp: event.created_at,
      detail: `${event.message || ''} ${event.user_agent || ''}`,
    })
  }

  for (const event of authEvents || []) {
    const metadata = recordOf(event.metadata)
    const ok = Boolean(event.success) || /success|enabled|trusted|updated|login/i.test(`${event.severity || ''} ${event.event_type || ''}`)
    const denied = /fail|error|denied|suspicious|blocked/i.test(`${event.severity || ''} ${event.event_type || ''} ${JSON.stringify(metadata)}`)
    addSignal({
      id: `auth-${event.event_type || 'security'}-${event.id}`,
      sourceTable: 'auth_events',
      domain: 'Identity Trust',
      title: event.event_type || 'Authentication event',
      subject: textValue(event.ip_address, 'Authentication activity'),
      subjectType: 'Auth Event',
      status: ok && !denied ? 'trusted' : 'review',
      severity: event.severity || (ok && !denied ? 'low' : 'medium'),
      trusted: ok && !denied,
      encrypted: true,
      timestamp: event.created_at,
      detail: `${event.message || firstString(metadata, ['message', 'detail']) || ''} ${event.user_agent || ''}`,
    })
  }

  for (const event of securityEvents || []) {
    const metadata = recordOf(event.metadata)
    const severity = normalizeSeverity(event.severity)
    const trusted = severityRank(severity) <= 1 && !/fail|error|denied|suspicious|blocked/i.test(`${event.event_type || ''} ${event.message || ''}`)
    addSignal({
      id: `security-event-${event.id}`,
      sourceTable: 'security_events',
      domain: 'Security Events',
      title: event.event_type || 'Security event',
      subject: textValue(event.resource_name, assetName(event.asset_id, 'Security event')),
      subjectType: textValue(event.resource_type, assetType(event.asset_id, 'Security')),
      assetId: event.asset_id,
      status: event.is_read ? 'reviewed' : trusted ? 'observed' : 'unread',
      severity,
      trusted,
      pqcReady: /pqc|quantum|ml-kem|ml-dsa/i.test(`${event.message || ''} ${JSON.stringify(metadata)}`),
      encrypted: true,
      timestamp: event.created_at,
      detail: `${event.message || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').join(' ')}`,
    })
  }

  for (const log of vaultAuditLogs || []) {
    const metadata = recordOf(log.metadata)
    addSignal({
      id: `vault-${log.id}`,
      sourceTable: 'vault_audit_logs',
      domain: 'Vault Trust',
      title: log.event_type || 'Vault audit',
      subject: firstString(metadata, ['resourceName', 'resource_name', 'fileName', 'file_name']) || 'Vault record',
      subjectType: 'Vault',
      status: firstString(metadata, ['status', 'result']) || 'observed',
      severity: metadata.severity || metadata.result || metadata.status,
      trusted: !/fail|error|denied|revoked/i.test(`${log.event_type || ''} ${JSON.stringify(metadata)}`),
      pqcReady: /ml-kem|pqc|quantum/i.test(JSON.stringify(metadata)),
      encrypted: true,
      timestamp: log.created_at,
      detail: Object.values(metadata).filter((value) => typeof value === 'string').join(' '),
    })
  }

  for (const log of auditLogs || []) {
    const details = recordOf(log.details)
    const ok = !/fail|error|denied|revoked|blocked/i.test(`${log.action || ''} ${log.entity_type || ''} ${JSON.stringify(details)}`)
    addSignal({
      id: `audit-${log.id}`,
      sourceTable: 'audit_logs',
      domain: 'Audit Trail',
      title: log.action || 'Audit event',
      subject: textValue(log.entity_type, 'Audit record'),
      subjectType: 'Audit Log',
      status: ok ? 'recorded' : 'review',
      severity: ok ? 'low' : 'medium',
      trusted: ok,
      encrypted: true,
      timestamp: log.created_at,
      detail: `${log.ip_address || ''} ${log.user_agent || ''} ${Object.values(details).filter((value) => typeof value === 'string').join(' ')}`,
    })
  }

  for (const agent of scannerAgents || []) {
    const lastSeen = dateMs(agent.last_seen_at || agent.updated_at)
    const online = /online|active|healthy|running/i.test(String(agent.status || '')) || lastSeen >= now - 15 * 60 * 1000
    addSignal({
      id: `agent-${agent.id}`,
      sourceTable: 'scanner_agents',
      domain: 'Device Trust',
      title: online ? 'Collector online' : 'Collector attention required',
      subject: textValue(agent.name, textValue(agent.hostname, 'Scanner agent')),
      subjectType: textValue(agent.platform, 'Collector'),
      status: textValue(agent.status, online ? 'online' : 'stale'),
      severity: online ? 'low' : 'medium',
      trusted: online,
      encrypted: true,
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
      domain: 'Continuous Validation',
      title: 'Agent heartbeat',
      subject: textValue(heartbeat.agent_id, 'Agent heartbeat'),
      subjectType: 'Heartbeat',
      status: textValue(heartbeat.status, healthy ? 'healthy' : 'review'),
      severity: healthy ? 'low' : 'medium',
      trusted: healthy,
      encrypted: true,
      timestamp: heartbeat.observed_at || heartbeat.created_at,
      detail: Object.values(telemetry).filter((value) => typeof value === 'string').join(' '),
    })
  }

  for (const connector of connectorAccounts || []) {
    const healthy = /connected|active|healthy|ok|synced/i.test(String(connector.status || ''))
    addSignal({
      id: `connector-${connector.id}`,
      sourceTable: 'connector_accounts',
      domain: 'Continuous Validation',
      title: `${connector.provider || 'Connector'} sync`,
      subject: textValue(connector.display_name, textValue(connector.provider, 'Connector')),
      subjectType: 'Connector',
      status: textValue(connector.status, healthy ? 'active' : 'review'),
      severity: healthy ? 'low' : 'medium',
      trusted: healthy,
      encrypted: true,
      timestamp: connector.last_sync_at || connector.updated_at || connector.created_at,
      detail: `${connector.provider || ''}`,
    })
  }

  for (const job of migrationJobs || []) {
    const complete = /done|complete|success|migrated/i.test(String(job.status || ''))
    addSignal({
      id: `migration-${job.id}`,
      sourceTable: 'migration_jobs',
      domain: 'Remediation Trust',
      title: complete ? 'Migration completed' : 'Migration pending',
      subject: assetName(job.asset_id, 'Migration job'),
      subjectType: 'Migration',
      assetId: job.asset_id,
      status: textValue(job.status, complete ? 'completed' : 'pending'),
      severity: complete ? 'low' : job.priority || 'medium',
      trusted: complete,
      pqcReady: complete || isPqcAlgorithm(`${job.algorithm_to || ''}`),
      encrypted: true,
      timestamp: job.updated_at || job.created_at,
      detail: `${job.algorithm_from || ''} -> ${job.algorithm_to || ''}`,
    })
  }

  for (const evidence of complianceEvidence || []) {
    const passed = /pass|met|compliant|approved|complete/i.test(String(evidence.status || ''))
    addSignal({
      id: `compliance-${evidence.id}`,
      sourceTable: 'compliance_evidence',
      domain: 'Compliance Trust',
      title: `${evidence.framework || 'Compliance'} ${evidence.control_id || ''}`.trim(),
      subject: assetName(evidence.asset_id, textValue(evidence.control_id, 'Compliance evidence')),
      subjectType: textValue(evidence.evidence_type, 'Compliance'),
      assetId: evidence.asset_id,
      status: textValue(evidence.status, passed ? 'passed' : 'review'),
      severity: passed ? 'low' : 'medium',
      trusted: passed,
      encrypted: true,
      timestamp: evidence.updated_at || evidence.created_at,
      detail: `${evidence.framework || ''} ${evidence.control_id || ''}`,
    })
  }

  const profile = profileRows[0] || {}
  const security = securitySettings[0] || {}
  const hasProfile = Boolean(profile.id)
  const mfaRequired = Boolean(security.mfa_enforced)
  addSignal({
    id: `profile-${userId}`,
    sourceTable: 'profiles',
    domain: 'Identity Trust',
    title: hasProfile ? 'Profile synchronized' : 'Profile missing',
    subject: textValue(profile.email, userId),
    subjectType: 'Operator',
    status: hasProfile ? 'active' : 'review',
    severity: hasProfile ? 'low' : 'medium',
    trusted: hasProfile,
    encrypted: true,
    timestamp: profile.updated_at || profile.created_at,
    detail: `${profile.role || ''} ${profile.company || ''}`,
  })
  addSignal({
    id: `security-settings-${userId}`,
    sourceTable: 'user_security_settings',
    domain: 'Identity Trust',
    title: mfaRequired ? 'MFA enforcement enabled' : 'MFA enforcement not enabled',
    subject: textValue(profile.email, userId),
    subjectType: 'Security Policy',
    status: mfaRequired ? 'enforced' : 'optional',
    severity: mfaRequired ? 'low' : 'medium',
    trusted: mfaRequired,
    encrypted: true,
    timestamp: security.updated_at || profile.updated_at,
    detail: `Trusted device expiry ${security.trusted_device_expiry_days || 30} days`,
  })

  signals.sort((a, b) => b.ms - a.ms)
  const current = signals.filter((signal) => signal.ms >= recentStart)
  const previous = signals.filter((signal) => signal.ms >= previousStart && signal.ms < recentStart)
  const trusted = signals.filter((signal) => signal.trusted)
  const review = signals.filter((signal) => !signal.trusted || severityRank(signal.severity) >= 2 || signal.score >= 38)
  const highRisk = signals.filter((signal) => severityRank(signal.severity) >= 3 || signal.score >= 68)
  const pqcReady = signals.filter((signal) => signal.pqcReady)
  const encrypted = signals.filter((signal) => signal.encrypted)
  const stale = signals.filter((signal) => signal.ms && signal.ms < staleStart)
  const total = signals.length
  const trustScore = total ? clamp((trusted.length / total) * 100 - (highRisk.length / Math.max(1, total)) * 16 - (stale.length / Math.max(1, total)) * 8) : 0
  const validationRate = percentOf(current.filter((signal) => signal.trusted).length, current.length)
  const identities = userSessions.length + generatedKeys.filter((key: any) => /otp|token|pki|sign|identity|jwt/i.test(String(key.algorithm || key.label || ''))).length + userSecurityEvents.length + authEvents.length
  const devices = userDevices.length + scannerAgents.length + assets.filter((asset: any) => /device|endpoint|server|workstation|host|node/i.test(`${asset.type || ''} ${asset.name || ''}`)).length
  const zeroControls = [
    { id: 'identity', label: 'Identity Verification', score: percentOf(signals.filter((s) => s.domain === 'Identity Trust' && s.trusted).length, Math.max(1, signals.filter((s) => s.domain === 'Identity Trust').length)), passed: signals.filter((s) => s.domain === 'Identity Trust' && !s.trusted).length === 0, evidence: signals.filter((s) => s.domain === 'Identity Trust').length },
    { id: 'device', label: 'Device Posture', score: percentOf(signals.filter((s) => s.domain === 'Device Trust' && s.trusted).length, Math.max(1, signals.filter((s) => s.domain === 'Device Trust').length)), passed: signals.filter((s) => s.domain === 'Device Trust' && !s.trusted).length === 0, evidence: signals.filter((s) => s.domain === 'Device Trust').length },
    { id: 'crypto', label: 'Crypto Assurance', score: percentOf(signals.filter((s) => /crypto|key|certificate|runtime/i.test(s.domain) && s.trusted).length, Math.max(1, signals.filter((s) => /crypto|key|certificate|runtime/i.test(s.domain)).length)), passed: signals.filter((s) => /crypto|key|certificate|runtime/i.test(s.domain) && !s.trusted).length === 0, evidence: signals.filter((s) => /crypto|key|certificate|runtime/i.test(s.domain)).length },
    { id: 'telemetry', label: 'Continuous Telemetry', score: percentOf(current.length, Math.max(1, total)), passed: current.length > 0, evidence: current.length },
    { id: 'vault', label: 'Vault And Secret Access', score: percentOf(signals.filter((s) => s.domain === 'Vault Trust' && s.trusted).length, Math.max(1, signals.filter((s) => s.domain === 'Vault Trust').length)), passed: signals.filter((s) => s.domain === 'Vault Trust' && !s.trusted).length === 0, evidence: signals.filter((s) => s.domain === 'Vault Trust').length },
    { id: 'compliance', label: 'Compliance Evidence', score: percentOf(signals.filter((s) => s.domain === 'Compliance Trust' && s.trusted).length, Math.max(1, signals.filter((s) => s.domain === 'Compliance Trust').length)), passed: signals.filter((s) => s.domain === 'Compliance Trust' && !s.trusted).length === 0, evidence: signals.filter((s) => s.domain === 'Compliance Trust').length },
  ].map((control) => ({ ...control, status: control.evidence === 0 ? 'waiting' : control.passed ? 'passed' : control.score >= 70 ? 'partial' : 'failed' }))

  const timelineStart = new Date()
  timelineStart.setHours(0, 0, 0, 0)
  timelineStart.setDate(timelineStart.getDate() - 6)
  const timeline = Array.from({ length: 7 }, (_, index) => {
    const start = timelineStart.getTime() + index * ONE_DAY_MS
    const end = start + ONE_DAY_MS
    const bucket = signals.filter((signal) => signal.ms >= start && signal.ms < end)
    return {
      label: new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      validations: bucket.length,
      trusted: bucket.filter((signal) => signal.trusted).length,
      review: bucket.filter((signal) => !signal.trusted || severityRank(signal.severity) >= 2).length,
      highRisk: bucket.filter((signal) => severityRank(signal.severity) >= 3).length,
    }
  })

  const domainRows = countBy(signals, (signal) => signal.domain, 10).map((row) => {
    const scoped = signals.filter((signal) => signal.domain === row.label)
    return {
      ...row,
      trusted: scoped.filter((signal) => signal.trusted).length,
      review: scoped.filter((signal) => !signal.trusted || severityRank(signal.severity) >= 2).length,
      riskScore: clamp(scoped.reduce((sum, signal) => sum + signal.score, 0) / Math.max(1, scoped.length)),
      latestSeen: latestDate(...scoped.map((signal) => signal.timestamp)),
    }
  })

  const subjectRows = [...new Map(signals.map((signal) => [signal.subject, signal.subject])).keys()]
    .map((subject) => {
      const scoped = signals.filter((signal) => signal.subject === subject)
      return {
        subject,
        type: scoped[0]?.subjectType || 'Trust subject',
        signals: scoped.length,
        trusted: scoped.filter((signal) => signal.trusted).length,
        riskScore: clamp(scoped.reduce((sum, signal) => sum + signal.score, 0) / Math.max(1, scoped.length)),
        latestSeen: latestDate(...scoped.map((signal) => signal.timestamp)),
      }
    })
    .sort((a, b) => b.riskScore - a.riskScore || b.signals - a.signals)
    .slice(0, 14)

  const alerts = review
    .slice()
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.score - a.score || b.ms - a.ms)
    .slice(0, 14)
    .map((signal) => ({
      id: signal.id,
      title: signal.title,
      detail: `${signal.subject} - ${signal.detail || signal.domain}`,
      severity: signal.severity,
      timestamp: signal.timestamp,
      source: signal.sourceTable,
      domain: signal.domain,
    }))

  const recommendations = [
    highRisk.length > 0 && {
      id: 'resolve-high-risk-trust',
      title: 'Resolve high-risk trust breaks',
      detail: `${highRisk.length} high-risk trust signal${highRisk.length === 1 ? '' : 's'} require review or remediation.`,
      impact: 'high',
      count: highRisk.length,
      actionHref: '/dashboard/telemetry-correlation',
    },
    userDevices.filter((device: any) => !device.trusted && !device.revoked_at).length > 0 && {
      id: 'review-untrusted-devices',
      title: 'Review untrusted devices',
      detail: `${userDevices.filter((device: any) => !device.trusted && !device.revoked_at).length} account device${userDevices.filter((device: any) => !device.trusted && !device.revoked_at).length === 1 ? '' : 's'} are not trusted.`,
      impact: 'medium',
      count: userDevices.filter((device: any) => !device.trusted && !device.revoked_at).length,
      actionHref: '/dashboard/settings',
    },
    !mfaRequired && {
      id: 'enforce-mfa',
      title: 'Enforce MFA for privileged actions',
      detail: 'Identity trust improves when MFA enforcement is enabled in account security settings.',
      impact: 'medium',
      count: 1,
      actionHref: '/dashboard/settings',
    },
    pqcReady.length < signals.filter((signal) => /crypto|key|certificate|runtime/i.test(signal.domain)).length && {
      id: 'increase-pqc-trust',
      title: 'Increase quantum-safe trust coverage',
      detail: `${signals.filter((signal) => /crypto|key|certificate|runtime/i.test(signal.domain)).length - pqcReady.length} cryptographic trust signal${signals.filter((signal) => /crypto|key|certificate|runtime/i.test(signal.domain)).length - pqcReady.length === 1 ? '' : 's'} are not marked PQC-ready.`,
      impact: 'medium',
      count: Math.max(0, signals.filter((signal) => /crypto|key|certificate|runtime/i.test(signal.domain)).length - pqcReady.length),
      actionHref: '/dashboard/pqc-orchestration',
    },
    current.length === 0 && total > 0 && {
      id: 'refresh-trust-telemetry',
      title: 'Refresh trust telemetry',
      detail: 'Trust evidence exists, but no current validation signal has arrived in the last 7 days.',
      impact: 'low',
      count: total,
      actionHref: '/dashboard/scanner',
    },
  ].filter(Boolean)

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
    vaultAuditLogs,
    vulnerabilities,
    auditLogs,
    authEvents,
    userSecurityEvents,
    userSessions,
    userDevices,
    complianceEvidence,
    migrationJobs,
  })

  const activeConnectors = connectorAccounts.filter((connector: any) => /connected|active|healthy|ok|synced/i.test(String(connector.status || ''))).length

  let eventPipelineStatus = 'no_agents'
  if (current.length) {
    eventPipelineStatus = 'active'
  } else if (sync.runningScans) {
    eventPipelineStatus = 'scan_running'
  } else if (total) {
    eventPipelineStatus = 'inventory_only'
  } else if (scannerAgents.length || connectorAccounts.length) {
    eventPipelineStatus = 'waiting_for_trust_events'
  }

  return {
    generatedAt: new Date().toISOString(),
    latestActivityAt: latestDate(...signals.slice(0, 60).map((signal) => signal.timestamp), sync.latestScanAt, sync.latestDiscoveryAt, sync.latestAgentHeartbeatAt),
    metrics: {
      trustScore,
      trustScoreDelta: deltaPercent(current.filter((signal) => signal.trusted).length, previous.filter((signal) => signal.trusted).length),
      validations: total,
      validationsDelta: deltaPercent(current.length, previous.length),
      validationRate,
      trustedSignals: trusted.length,
      reviewSignals: review.length,
      highRiskSignals: highRisk.length,
      assetsCovered: Math.max(sync.activeAssets, new Set(signals.map((signal) => signal.subject).filter(Boolean)).size),
      identities,
      devices,
      activeSessions: userSessions.filter((session: any) => !session.revoked_at && (!session.expires_at || dateMs(session.expires_at) > now)).length,
      trustedDevices: userDevices.filter((device: any) => device.trusted && !device.revoked_at).length,
      mfaEnforced: mfaRequired,
      pqcReadyPercent: percentOf(pqcReady.length, total),
      encryptedPercent: percentOf(encrypted.length, total),
      staleSignals: stale.length,
      zeroTrustPassRate: percentOf(zeroControls.filter((control) => control.status === 'passed').length, zeroControls.length),
      activeSources: sync.onlineAgents + activeConnectors,
    },
    timeline,
    domainRows,
    subjectRows,
    zeroControls,
    severityDistribution: countBy(signals, (signal) => titleCase(signal.severity), 5),
    statusDistribution: countBy(signals, (signal) => titleCase(signal.status), 8),
    sourceDistribution: countBy(signals, (signal) => signal.sourceTable, 8),
    alerts,
    recommendations,
    activity: signals.slice(0, 14).map((signal) => ({
      id: signal.id,
      title: signal.title,
      detail: `${signal.subject} - ${signal.domain}`,
      severity: signal.severity,
      timestamp: signal.timestamp,
      source: signal.sourceTable,
    })),
    inventory: signals
      .slice()
      .sort((a, b) => b.score - a.score || b.ms - a.ms)
      .slice(0, 18)
      .map((signal) => ({
        id: signal.id,
        domain: signal.domain,
        title: signal.title,
        subject: signal.subject,
        subjectType: signal.subjectType,
        status: signal.status,
        severity: signal.severity,
        score: signal.score,
        trusted: signal.trusted,
        pqcReady: signal.pqcReady,
        encrypted: signal.encrypted,
        timestamp: signal.timestamp,
        source: signal.sourceTable,
        detail: signal.detail,
      })),
    telemetry: {
      ...sync,
      assets: assets.length,
      runtimeEvents: runtimeEvents.length,
      scannerEvidence: scannerEvidence.length,
      scannerAlerts: scannerAlerts.length,
      scanSessions: sync.scanSessions,
      scanResults: scanResults.length,
      vulnerabilities: vulnerabilities.length,
      cryptoInventory: cryptoInventory.length,
      cryptoExposures: cryptoExposures.length,
      certificates: certificates.length,
      generatedKeys: generatedKeys.length,
      scannerAgents: scannerAgents.length,
      connectors: connectorAccounts.length,
      agentHeartbeats: agentHeartbeats.length,
      profileRecords: profileRows.length,
      securitySettings: securitySettings.length,
      userDevices: userDevices.length,
      userSessions: userSessions.length,
      userSecurityEvents: userSecurityEvents.length,
      authEvents: authEvents.length,
      securityEvents: securityEvents.length,
      vaultAuditLogs: vaultAuditLogs.length,
      auditLogs: auditLogs.length,
      migrationJobs: migrationJobs.length,
      complianceEvidence: complianceEvidence.length,
      eventPipelineStatus,
      latestRuntimeEventAt: latestDate(...runtimeEvents.map((event: any) => event.observed_at || event.created_at)),
    },
  }
}

export const continuousTrustRoutes = buildRouter('continuous')
export const identityTrustRoutes = buildRouter('identity')
export const deviceTrustRoutes = buildRouter('device')
export const trustAnalyticsRoutes = buildRouter('analytics')
export const zeroTrustRoutes = buildRouter('zero')
