import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'

const ONE_DAY_MS = 24 * 60 * 60 * 1000

type GovernanceKind = 'quantum' | 'audit' | 'regulatory'
type Severity = 'critical' | 'high' | 'medium' | 'low'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

type GovernanceSignal = {
  id: string
  sourceTable: string
  domain: string
  title: string
  subject: string
  subjectType: string
  framework: string
  control: string
  status: string
  severity: Severity
  score: number
  compliant: boolean
  evidence: boolean
  policyEnforced: boolean
  immutable: boolean
  encrypted: boolean
  pqcReady: boolean
  timestamp: string | null
  ms: number
  detail: string
}

const ROUTE_META: Record<GovernanceKind, { eventPrefix: string; routeLabel: string }> = {
  quantum: { eventPrefix: 'quantum-governance', routeLabel: 'Quantum governance' },
  audit: { eventPrefix: 'audit-vault', routeLabel: 'Audit vault' },
  regulatory: { eventPrefix: 'regulatory-mapping', routeLabel: 'Regulatory mapping' },
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

function titleCase(value: unknown, fallback = 'Governance Signal') {
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

function arrayLength(value: unknown) {
  return Array.isArray(value) ? value.length : 0
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

function frameworkFor(text: string) {
  const lower = text.toLowerCase()
  if (/pci|card|payment/.test(lower)) return { framework: 'PCI DSS 4.0', control: 'REQ-3 / REQ-4' }
  if (/hipaa|phi|health/.test(lower)) return { framework: 'HIPAA Security', control: '164.312' }
  if (/gdpr|privacy|personal/.test(lower)) return { framework: 'GDPR', control: 'Article 32' }
  if (/soc|audit|vault|access|identity|session|auth/.test(lower)) return { framework: 'SOC 2', control: 'CC6 / CC7' }
  if (/iso|27001|asset|inventory|certificate/.test(lower)) return { framework: 'ISO 27001', control: 'A.5 / A.8' }
  if (/nist|pqc|quantum|crypto|algorithm|key|tls|certificate/.test(lower)) return { framework: 'NIST CSF 2.0', control: 'PR.DS / GV.RM' }
  return { framework: 'Internal Crypto Standard', control: 'CRYPTO-GOV' }
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
      console.warn(`Governance dashboard ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Governance dashboard ${table} query failed:`, error?.message || error)
    return []
  }
}

function buildRouter(kind: GovernanceKind) {
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

      const data = await buildGovernanceSnapshot(kind, req.token, req.user.id)
      return res.json({ data })
    } catch (error: any) {
      console.error(`${meta.routeLabel} dashboard error:`, error)
      return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || `Failed to fetch ${meta.routeLabel.toLowerCase()} data` } })
    }
  })

  return router
}

async function buildGovernanceSnapshot(kind: GovernanceKind, token: string, userId: string) {
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
    scannerPolicies,
    connectorAccounts,
    agentHeartbeats,
    vaultFiles,
    vaultAuditLogs,
    auditLogs,
    complianceEvidence,
    migrationJobs,
    securityEvents,
    userSecurityEvents,
    authEvents,
    qrngEvents,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(4500)),
    safeRows(client, 'scanner_evidence', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(2200)),
    safeRows(client, 'scanner_alerts', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(500)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'crypto_inventory', (q) => q.select('*').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(2200)),
    safeRows(client, 'crypto_exposures', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'vulnerabilities', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'certificates', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'scanner_agents', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(700)),
    safeRows(client, 'scanner_agent_policies', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, display_name, status, scopes, capabilities, policy, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(600)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1200)),
    safeRows(client, 'vault_files', (q) => q.select('id, original_filename, mime_type, original_size, encryption_status, encryption_algorithm, algorithm_version, signature_status, key_rotation_status, is_deleted, is_latest, uploaded_at, encrypted_at, processed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1400)),
    safeRows(client, 'vault_audit_logs', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'audit_logs', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'compliance_evidence', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'migration_jobs', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'security_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'user_security_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'auth_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'qrng_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
  ])

  const now = Date.now()
  const recentStart = now - 7 * ONE_DAY_MS
  const previousStart = now - 14 * ONE_DAY_MS
  const staleStart = now - 30 * ONE_DAY_MS
  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
  const signals: GovernanceSignal[] = []
  const seen = new Set<string>()

  const assetName = (assetId: unknown, fallback = 'Unmapped asset') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.name, fallback)
  }

  const addSignal = (input: {
    id: string
    sourceTable: string
    domain: string
    title: string
    subject?: string
    subjectType?: string
    assetId?: string | null
    framework?: string
    control?: string
    status?: string
    severity?: unknown
    score?: unknown
    compliant?: boolean
    evidence?: boolean
    policyEnforced?: boolean
    immutable?: boolean
    encrypted?: boolean
    pqcReady?: boolean
    timestamp?: string | null
    detail?: string
  }) => {
    if (seen.has(input.id)) return
    seen.add(input.id)
    const timestamp = input.timestamp || null
    const ms = dateMs(timestamp)
    const mapped = frameworkFor(`${input.domain} ${input.title} ${input.detail || ''} ${input.framework || ''}`)
    const compliant = Boolean(input.compliant)
    const policyEnforced = Boolean(input.policyEnforced)
    const evidence = input.evidence ?? Boolean(ms)
    let score = Number(input.score || 0)
    const severity = normalizeSeverity(input.severity)
    if (!Number.isFinite(score) || score <= 0) {
      score = 18
      if (!compliant) score += 30
      if (!policyEnforced && /policy|runtime|scanner|connector/i.test(input.domain)) score += 14
      if (!evidence) score += 10
      if (severityRank(severity) >= 3) score += 30
      else if (severityRank(severity) === 2) score += 14
      if (ms && ms < staleStart) score += 8
    }
    const finalScore = clamp(score)
    const finalSeverity = severityRank(severity) > 1 ? severity : severityForScore(finalScore)

    signals.push({
      id: input.id,
      sourceTable: input.sourceTable,
      domain: input.domain,
      title: titleCase(input.title),
      subject: textValue(input.subject, input.assetId ? assetName(input.assetId) : 'Governance subject'),
      subjectType: textValue(input.subjectType, 'Governance object'),
      framework: textValue(input.framework, mapped.framework),
      control: textValue(input.control, mapped.control),
      status: textValue(input.status, compliant ? 'compliant' : 'review'),
      severity: finalSeverity,
      score: finalScore,
      compliant,
      evidence,
      policyEnforced,
      immutable: Boolean(input.immutable),
      encrypted: Boolean(input.encrypted),
      pqcReady: Boolean(input.pqcReady),
      timestamp,
      ms,
      detail: input.detail || '',
    })
  }

  for (const asset of assets || []) {
    const metadata = recordOf(asset.metadata)
    const active = !/unknown|unmanaged|inactive|retired/.test(String(asset.status || '').toLowerCase())
    addSignal({
      id: `asset-${asset.id}`,
      sourceTable: 'assets',
      domain: 'Asset Governance',
      title: `${asset.type || 'Asset'} ownership`,
      subject: textValue(asset.name, 'Asset'),
      subjectType: textValue(asset.type, 'Asset'),
      assetId: asset.id,
      status: active ? 'covered' : 'review',
      severity: active ? 'low' : 'medium',
      compliant: active,
      evidence: true,
      policyEnforced: Boolean(asset.service_owner || metadata.owner || metadata.policy || metadata.control),
      encrypted: Boolean(metadata.encrypted || metadata.tls || metadata.encryption),
      pqcReady: Boolean(metadata.pqc_ready || metadata.quantum_safe || metadata.is_quantum_safe),
      timestamp: asset.updated_at || asset.created_at,
      detail: `${asset.environment || ''} ${asset.region || ''} ${asset.service_owner || ''} ${asset.criticality || ''}`,
    })
  }

  for (const policy of scannerPolicies || []) {
    const scanTypes = Array.isArray(policy.scan_types) ? policy.scan_types : []
    const enabled = Boolean(policy.enabled)
    const targetCount = arrayLength(policy.allowed_targets)
    const pathCount = arrayLength(policy.allowed_paths)
    addSignal({
      id: `scanner-policy-${policy.id}`,
      sourceTable: 'scanner_agent_policies',
      domain: 'Crypto Policy',
      title: policy.name || 'Scanner policy',
      subject: textValue(policy.agent_id, 'Scanner policy'),
      subjectType: 'Scanner Policy',
      status: enabled ? 'enforced' : 'disabled',
      severity: enabled ? 'low' : 'high',
      compliant: enabled,
      evidence: true,
      policyEnforced: enabled,
      encrypted: true,
      timestamp: policy.updated_at || policy.created_at,
      detail: `${scanTypes.join(', ')} targets:${targetCount} paths:${pathCount} threshold:${policy.alert_threshold || ''}`,
    })
  }

  for (const agent of scannerAgents || []) {
    const policy = recordOf(agent.policy)
    const hasPolicy = Object.keys(policy).length > 0
    const online = /online|active|healthy|running/i.test(String(agent.status || '')) || dateMs(agent.last_seen_at || agent.updated_at) >= now - 15 * 60 * 1000
    addSignal({
      id: `agent-${agent.id}`,
      sourceTable: 'scanner_agents',
      domain: 'Collector Governance',
      title: online ? 'Collector policy online' : 'Collector policy stale',
      subject: textValue(agent.name, textValue(agent.hostname, 'Scanner agent')),
      subjectType: textValue(agent.platform, 'Collector'),
      status: online ? 'online' : 'stale',
      severity: online ? 'low' : 'medium',
      compliant: online,
      evidence: true,
      policyEnforced: hasPolicy,
      encrypted: true,
      timestamp: agent.last_seen_at || agent.updated_at || agent.created_at,
      detail: `${agent.hostname || ''} ${agent.platform || ''}`,
    })
  }

  for (const connector of connectorAccounts || []) {
    const policy = recordOf(connector.policy)
    const healthy = /connected|active|healthy|ok|synced/i.test(String(connector.status || ''))
    addSignal({
      id: `connector-${connector.id}`,
      sourceTable: 'connector_accounts',
      domain: 'Connector Governance',
      title: `${connector.provider || 'Connector'} policy`,
      subject: textValue(connector.display_name, textValue(connector.provider, 'Connector')),
      subjectType: 'Connector',
      status: healthy ? 'synchronized' : 'review',
      severity: healthy ? 'low' : 'medium',
      compliant: healthy,
      evidence: Boolean(connector.last_sync_at || connector.updated_at),
      policyEnforced: Object.keys(policy).length > 0,
      encrypted: true,
      timestamp: connector.last_sync_at || connector.updated_at || connector.created_at,
      detail: `${connector.provider || ''}`,
    })
  }

  for (const event of runtimeEvents || []) {
    const algorithm = textValue(event.algorithm, textValue(event.key_exchange_algorithm, textValue(event.cipher_suite, '')))
    const weak = Boolean(event.is_legacy || event.downgrade_detected || event.shadow_crypto || isWeakCrypto(`${algorithm} ${event.tls_version || ''}`, numberValue(event.key_size)))
    addSignal({
      id: `runtime-${event.id}`,
      sourceTable: 'runtime_crypto_events',
      domain: 'Runtime Policy',
      title: event.event_type || event.operation_type || 'Runtime crypto event',
      subject: textValue(event.asset_name, textValue(event.host, assetName(event.asset_id))),
      subjectType: textValue(event.asset_type, textValue(event.source_type, 'Runtime')),
      assetId: event.asset_id,
      status: weak ? 'policy_break' : 'allowed',
      severity: event.severity,
      score: event.risk_score,
      compliant: !weak,
      evidence: true,
      policyEnforced: true,
      encrypted: !/plaintext|cleartext|unencrypted/i.test(`${event.operation_type || ''} ${event.event_type || ''}`),
      pqcReady: Boolean(event.is_pqc) || isPqcAlgorithm(`${algorithm}`),
      timestamp: event.observed_at || event.created_at,
      detail: `${event.protocol || ''} ${event.tls_version || ''} ${algorithm} ${event.process_name || ''}`,
    })
  }

  for (const item of cryptoInventory || []) {
    const weak = Boolean(item.is_vulnerable && !item.is_quantum_safe) || isWeakCrypto(`${item.algorithm || ''} ${item.protocol || ''}`, numberValue(item.key_size))
    addSignal({
      id: `inventory-${item.id}`,
      sourceTable: 'crypto_inventory',
      domain: 'Algorithm Policy',
      title: item.item_type || 'Crypto inventory',
      subject: textValue(item.name, assetName(item.asset_id)),
      subjectType: textValue(item.item_type, 'Crypto item'),
      assetId: item.asset_id,
      status: item.is_quantum_safe ? 'approved' : weak ? 'restricted' : 'observed',
      severity: weak ? item.exposure_level || 'medium' : 'low',
      compliant: !weak,
      evidence: true,
      policyEnforced: true,
      encrypted: true,
      pqcReady: Boolean(item.is_quantum_safe) || isPqcAlgorithm(`${item.algorithm || ''}`),
      timestamp: item.discovered_at || item.created_at,
      detail: `${item.algorithm || ''} ${item.protocol || ''} ${item.key_size || ''}`,
    })
  }

  for (const exposure of cryptoExposures || []) {
    addSignal({
      id: `exposure-${exposure.id}`,
      sourceTable: 'crypto_exposures',
      domain: 'Policy Violation',
      title: exposure.exposure_type || 'Crypto exposure',
      subject: assetName(exposure.asset_id, 'Crypto exposure'),
      subjectType: 'Exposure',
      assetId: exposure.asset_id,
      status: 'active',
      severity: exposure.severity,
      compliant: false,
      evidence: true,
      policyEnforced: true,
      encrypted: !/plaintext|cleartext|unencrypted/i.test(`${exposure.description || ''} ${exposure.detected_value || ''}`),
      pqcReady: isPqcAlgorithm(`${exposure.detected_value || ''} ${exposure.description || ''}`),
      timestamp: exposure.updated_at || exposure.created_at,
      detail: `${exposure.description || ''} ${exposure.detected_value || ''}`,
    })
  }

  for (const alert of scannerAlerts || []) {
    const metadata = recordOf(alert.metadata)
    addSignal({
      id: `scanner-alert-${alert.id}`,
      sourceTable: 'scanner_alerts',
      domain: 'Policy Violation',
      title: alert.title || alert.category || 'Scanner alert',
      subject: firstString(metadata, ['assetName', 'resourceName', 'hostname', 'target']) || textValue(alert.category, 'Scanner alert'),
      subjectType: firstString(metadata, ['assetType', 'resourceType']) || 'Scanner Alert',
      status: textValue(alert.status, 'open'),
      severity: alert.severity,
      compliant: /resolved|suppressed|acknowledged/i.test(String(alert.status || '')) && severityRank(alert.severity) < 3,
      evidence: true,
      policyEnforced: true,
      encrypted: true,
      pqcReady: isPqcAlgorithm(`${alert.message || ''} ${alert.recommendation || ''}`),
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
    const scannedAssets = numberValue(session.scanned_assets)
    const totalAssets = numberValue(session.total_assets)
    addSignal({
      id: `scan-session-${session.id}`,
      sourceTable: 'pqc_scan_sessions',
      domain: 'Scan Governance',
      title: failed ? 'Scan requires governance review' : running ? 'Scan in progress' : 'Scan completed',
      subject: textValue(session.target_scope, firstString(metadata, ['target', 'targetScope', 'scope']) || 'PQC scan'),
      subjectType: 'Scan Session',
      status: textValue(session.status, running ? 'running' : 'completed'),
      severity: failed ? 'high' : findings > 0 ? 'medium' : 'low',
      score: failed ? 80 : findings > 0 ? 54 : 12,
      compliant: !failed && findings === 0,
      evidence: true,
      policyEnforced: true,
      encrypted: true,
      pqcReady: !failed && findings === 0,
      timestamp: session.completed_at || session.updated_at || session.started_at || session.created_at,
      detail: `${numberValue(session.progress)}% complete - ${findings} finding${findings === 1 ? '' : 's'} - ${scannedAssets}/${totalAssets} assets`,
    })
  }

  for (const evidence of scannerEvidence || []) {
    const raw = recordOf(evidence.raw_evidence)
    const algorithm = textValue(evidence.observed_algorithm, firstString(raw, ['algorithm', 'cipher', 'cipher_suite']))
    const weak = isWeakCrypto(`${algorithm} ${evidence.protocol || ''}`, numberValue(evidence.key_size))
    addSignal({
      id: `evidence-${evidence.id}`,
      sourceTable: 'scanner_evidence',
      domain: 'Evidence Collection',
      title: evidence.evidence_type || 'Scanner evidence',
      subject: textValue(evidence.asset_name, textValue(evidence.host, textValue(evidence.target, 'Evidence'))),
      subjectType: textValue(evidence.asset_type, textValue(evidence.source_type, 'Evidence')),
      status: weak ? 'restricted' : 'captured',
      severity: weak ? 'medium' : 'low',
      compliant: !weak,
      evidence: true,
      policyEnforced: true,
      encrypted: !/plaintext|cleartext/i.test(JSON.stringify(raw)),
      pqcReady: isPqcAlgorithm(`${algorithm}`),
      timestamp: evidence.observed_at || evidence.processed_at || evidence.created_at,
      detail: `${algorithm} ${evidence.protocol || ''} ${evidence.confidence || ''}`,
    })
  }

  for (const result of scanResults || []) {
    addSignal({
      id: `scan-result-${result.id}`,
      sourceTable: 'pqc_scan_results',
      domain: 'Policy Violation',
      title: result.finding_type || 'Scan finding',
      subject: assetName(result.asset_id, 'Scan finding'),
      subjectType: 'PQC Finding',
      assetId: result.asset_id,
      status: 'active',
      severity: result.threat_level,
      compliant: false,
      evidence: true,
      policyEnforced: true,
      encrypted: true,
      pqcReady: isPqcAlgorithm(`${result.algorithm || ''}`),
      timestamp: result.created_at,
      detail: `${result.algorithm || ''} ${result.description || ''} ${result.remediation || ''}`,
    })
  }

  for (const vulnerability of vulnerabilities || []) {
    const metadata = recordOf(vulnerability.metadata)
    const status = String(vulnerability.status || 'open').toLowerCase()
    const resolved = /resolved|closed|fixed|false_positive|accepted/.test(status)
    const severity = normalizeSeverity(vulnerability.severity)
    addSignal({
      id: `vulnerability-${vulnerability.id}`,
      sourceTable: 'vulnerabilities',
      domain: 'Vulnerability Governance',
      title: vulnerability.title || 'Vulnerability finding',
      subject: assetName(vulnerability.asset_id, firstString(metadata, ['assetName', 'hostname', 'resourceName']) || 'Vulnerability'),
      subjectType: firstString(metadata, ['assetType', 'resourceType']) || 'Vulnerability',
      assetId: vulnerability.asset_id,
      status: textValue(vulnerability.status, resolved ? 'resolved' : 'open'),
      severity,
      score: numberValue(vulnerability.cvss_score) * 10,
      compliant: resolved,
      evidence: true,
      policyEnforced: true,
      encrypted: true,
      pqcReady: Boolean(metadata.pqc_ready || metadata.quantum_safe || metadata.is_quantum_safe),
      timestamp: vulnerability.updated_at || vulnerability.created_at,
      detail: `${vulnerability.source || ''} ${vulnerability.description || ''}`,
    })
  }

  for (const cert of certificates || []) {
    const keySize = numberValue(cert.key_size)
    const weak = !cert.is_quantum_safe && isWeakCrypto(`${cert.algorithm || ''}`, keySize)
    const compliant = !cert.is_expiring_soon && !weak && !/revoked|expired/i.test(String(cert.status || ''))
    addSignal({
      id: `certificate-${cert.id}`,
      sourceTable: 'certificates',
      domain: 'Certificate Policy',
      title: cert.is_expiring_soon ? 'Certificate renewal required' : 'Certificate control',
      subject: textValue(cert.name, textValue(cert.subject, assetName(cert.asset_id, 'Certificate'))),
      subjectType: 'Certificate',
      assetId: cert.asset_id,
      status: textValue(cert.status, cert.is_expiring_soon ? 'expiring' : 'active'),
      severity: compliant ? 'low' : 'medium',
      compliant,
      evidence: true,
      policyEnforced: true,
      encrypted: true,
      pqcReady: Boolean(cert.is_quantum_safe) || isPqcAlgorithm(`${cert.algorithm || ''}`),
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
      domain: 'Key Policy',
      title: algorithm,
      subject: firstString(label, ['purpose', 'common_name', 'token_id']) || algorithm,
      subjectType: textValue(key.entropy_source, 'Generated key'),
      status,
      severity: revoked || weak ? 'medium' : 'low',
      compliant: !revoked && !weak,
      evidence: true,
      policyEnforced: Boolean(metadata.policy || metadata.purpose || label),
      encrypted: true,
      pqcReady: isPqcAlgorithm(algorithm),
      timestamp: key.updated_at || key.created_at,
      detail: `${key.bit_length || ''} ${key.entropy_source || ''}`,
    })
  }

  for (const file of vaultFiles || []) {
    const encrypted = /encrypted|complete|processed|sealed/i.test(`${file.encryption_status || ''} ${file.processing_status || ''}`)
    const signed = /valid|verified|signed/i.test(String(file.signature_status || ''))
    const current = !file.is_deleted && file.is_latest !== false
    addSignal({
      id: `vault-file-${file.id}`,
      sourceTable: 'vault_files',
      domain: 'Audit Vault',
      title: encrypted ? 'Vault object protected' : 'Vault object pending',
      subject: textValue(file.original_filename, 'Vault file'),
      subjectType: textValue(file.mime_type, 'Vault Object'),
      status: file.is_deleted ? 'deleted' : encrypted ? 'protected' : textValue(file.encryption_status, 'pending'),
      severity: encrypted && current ? 'low' : 'medium',
      compliant: encrypted && current,
      evidence: true,
      policyEnforced: true,
      immutable: signed,
      encrypted,
      pqcReady: isPqcAlgorithm(`${file.encryption_algorithm || ''}`),
      timestamp: file.updated_at || file.processed_at || file.encrypted_at || file.uploaded_at || file.created_at,
      detail: `${file.encryption_algorithm || ''} ${file.algorithm_version || ''} ${file.key_rotation_status || ''}`,
    })
  }

  for (const log of vaultAuditLogs || []) {
    const metadata = recordOf(log.metadata)
    const result = `${log.result || log.status || firstString(metadata, ['result', 'status']) || ''}`
    const ok = !/fail|error|denied|destroyed|revoked/i.test(`${log.event_type || ''} ${result}`)
    addSignal({
      id: `vault-audit-${log.id}`,
      sourceTable: 'vault_audit_logs',
      domain: 'Audit Trail',
      title: log.event_type || log.operation || 'Vault audit',
      subject: textValue(log.resource_type, textValue(log.file_id, 'Vault event')),
      subjectType: 'Vault Audit',
      status: textValue(result, ok ? 'success' : 'review'),
      severity: log.severity || (ok ? 'low' : 'medium'),
      compliant: ok,
      evidence: true,
      policyEnforced: true,
      immutable: true,
      encrypted: true,
      timestamp: log.created_at,
      detail: `${log.description || log.details || ''} ${log.ip_address || ''} ${Object.values(metadata).filter((value) => typeof value === 'string').slice(0, 4).join(' ')}`,
    })
  }

  for (const log of auditLogs || []) {
    const details = recordOf(log.details)
    const action = textValue(log.action, 'Audit action')
    const ok = !/fail|error|denied|destroyed|delete_forced/i.test(`${action} ${JSON.stringify(details)}`)
    addSignal({
      id: `audit-${log.id}`,
      sourceTable: 'audit_logs',
      domain: 'Audit Trail',
      title: action,
      subject: textValue(log.entity_type, 'Audit record'),
      subjectType: textValue(log.entity_type, 'Audit'),
      status: ok ? 'recorded' : 'review',
      severity: ok ? 'low' : 'medium',
      compliant: ok,
      evidence: true,
      policyEnforced: true,
      immutable: true,
      encrypted: true,
      timestamp: log.created_at,
      detail: `${log.entity_id || ''} ${log.ip_address || ''} ${Object.values(details).filter((value) => typeof value === 'string').slice(0, 4).join(' ')}`,
    })
  }

  for (const item of complianceEvidence || []) {
    const metadata = recordOf(item.metadata)
    const passed = /pass|met|compliant|approved|complete|accepted/i.test(String(item.status || ''))
    addSignal({
      id: `compliance-${item.id}`,
      sourceTable: 'compliance_evidence',
      domain: 'Regulatory Evidence',
      title: `${item.framework || 'Framework'} ${item.control_id || ''}`.trim(),
      subject: textValue(item.description, textValue(item.control_id, 'Compliance evidence')),
      subjectType: textValue(item.evidence_type, 'Compliance'),
      framework: textValue(item.framework, firstString(metadata, ['framework'])),
      control: textValue(item.control_id, firstString(metadata, ['control', 'control_id'])),
      status: textValue(item.status, passed ? 'passed' : 'pending'),
      severity: passed ? 'low' : 'medium',
      compliant: passed,
      evidence: true,
      policyEnforced: true,
      immutable: true,
      encrypted: true,
      timestamp: item.updated_at || item.created_at,
      detail: `${item.description || ''} ${item.evidence_type || ''}`,
    })
  }

  for (const job of migrationJobs || []) {
    const complete = /done|complete|success|migrated/i.test(String(job.status || ''))
    addSignal({
      id: `migration-${job.id}`,
      sourceTable: 'migration_jobs',
      domain: 'Remediation Evidence',
      title: complete ? 'Migration completed' : 'Migration pending',
      subject: assetName(job.asset_id, 'Migration job'),
      subjectType: 'Migration',
      assetId: job.asset_id,
      status: textValue(job.status, complete ? 'completed' : 'pending'),
      severity: complete ? 'low' : job.priority || 'medium',
      compliant: complete,
      evidence: true,
      policyEnforced: true,
      encrypted: true,
      pqcReady: complete || isPqcAlgorithm(`${job.algorithm_to || ''}`),
      timestamp: job.updated_at || job.created_at,
      detail: `${job.algorithm_from || ''} -> ${job.algorithm_to || ''}`,
    })
  }

  const addSecurityGovernanceEvent = (event: any, sourceTable: string, idPrefix: string) => {
    const metadata = recordOf(event.metadata)
    const ok = /success|enabled|trusted|updated|login/i.test(`${event.severity || ''} ${event.event_type || ''} ${event.action || ''}`) && !/fail|error|denied|suspicious/i.test(`${event.message || ''} ${JSON.stringify(metadata)}`)
    addSignal({
      id: `${idPrefix}-${event.id}`,
      sourceTable,
      domain: 'Access Governance',
      title: event.event_type || event.action || 'Security event',
      subject: textValue(event.ip_address, 'Account activity'),
      subjectType: 'Identity Event',
      status: ok ? 'approved' : 'review',
      severity: event.severity,
      compliant: ok,
      evidence: true,
      policyEnforced: true,
      immutable: true,
      encrypted: true,
      timestamp: event.created_at,
      detail: `${event.message || ''} ${event.user_agent || ''}`,
    })
  }

  for (const event of securityEvents || []) addSecurityGovernanceEvent(event, 'security_events', 'security')
  for (const event of userSecurityEvents || []) addSecurityGovernanceEvent(event, 'user_security_events', 'user-security')
  for (const event of authEvents || []) addSecurityGovernanceEvent(event, 'auth_events', 'auth')

  for (const event of qrngEvents || []) {
    const metadata = recordOf(event.metadata)
    const ok = !/fail|error|fallback/i.test(`${event.status || ''} ${event.event_type || ''} ${JSON.stringify(metadata)}`)
    addSignal({
      id: `qrng-${event.id}`,
      sourceTable: 'qrng_events',
      domain: 'Entropy Governance',
      title: event.event_type || 'QRNG event',
      subject: firstString(metadata, ['algorithm', 'purpose', 'consumer']) || 'Entropy event',
      subjectType: 'Entropy',
      status: textValue(event.status, ok ? 'approved' : 'review'),
      severity: ok ? 'low' : 'medium',
      compliant: ok,
      evidence: true,
      policyEnforced: true,
      encrypted: true,
      pqcReady: true,
      timestamp: event.created_at,
      detail: Object.values(metadata).filter((value) => typeof value === 'string').slice(0, 4).join(' '),
    })
  }

  signals.sort((a, b) => b.ms - a.ms)
  const current = signals.filter((signal) => signal.ms >= recentStart)
  const previous = signals.filter((signal) => signal.ms >= previousStart && signal.ms < recentStart)
  const compliant = signals.filter((signal) => signal.compliant)
  const violations = signals.filter((signal) => !signal.compliant || severityRank(signal.severity) >= 2 || signal.score >= 38)
  const highRisk = signals.filter((signal) => severityRank(signal.severity) >= 3 || signal.score >= 68)
  const policySignals = signals.filter((signal) => /policy|collector|connector|runtime|algorithm|certificate|key/i.test(signal.domain))
  const auditSignals = signals.filter((signal) => /audit|vault|access/i.test(signal.domain))
  const regulatorySignals = signals.filter((signal) => /regulatory|compliance|remediation|policy|asset|audit/i.test(signal.domain))
  const encrypted = signals.filter((signal) => signal.encrypted)
  const pqcReady = signals.filter((signal) => signal.pqcReady)
  const stale = signals.filter((signal) => signal.ms && signal.ms < staleStart)
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
      evidence: bucket.length,
      compliant: bucket.filter((signal) => signal.compliant).length,
      violations: bucket.filter((signal) => !signal.compliant || severityRank(signal.severity) >= 2).length,
      audit: bucket.filter((signal) => /audit|vault|access/i.test(signal.domain)).length,
    }
  })

  const domainRows = countBy(signals, (signal) => signal.domain, 10).map((row) => {
    const scoped = signals.filter((signal) => signal.domain === row.label)
    return {
      ...row,
      compliant: scoped.filter((signal) => signal.compliant).length,
      violations: scoped.filter((signal) => !signal.compliant || severityRank(signal.severity) >= 2).length,
      coverage: percentOf(scoped.filter((signal) => signal.compliant).length, scoped.length),
      riskScore: clamp(scoped.reduce((sum, signal) => sum + signal.score, 0) / Math.max(1, scoped.length)),
      latestSeen: latestDate(...scoped.map((signal) => signal.timestamp)),
    }
  })

  const policyRows = [
    { label: 'Runtime Crypto Allowlist', matcher: /Runtime Policy|Algorithm Policy|Policy Violation|Evidence Collection/i, scope: `${new Set(signals.filter((s) => /Runtime Policy|Algorithm Policy|Policy Violation|Evidence Collection/i.test(s.domain)).map((s) => s.subject)).size} subjects`, actionHref: '/dashboard/runtime-crypto-intel' },
    { label: 'Scan And Vulnerability Governance', matcher: /Scan Governance|Vulnerability Governance/i, scope: `${scanSessions.length + vulnerabilities.length + scanResults.length} findings`, actionHref: '/dashboard/vulnerabilities' },
    { label: 'Collector Evidence Scope', matcher: /Collector Governance|Connector Governance|Evidence Collection/i, scope: `${scannerAgents.length + connectorAccounts.length} sources`, actionHref: '/dashboard/scanner' },
    { label: 'Certificate And Key Controls', matcher: /Certificate Policy|Key Policy/i, scope: `${certificates.length + generatedKeys.length} objects`, actionHref: '/dashboard/keys' },
    { label: 'Audit Vault Retention', matcher: /Audit Trail|Audit Vault|Access Governance/i, scope: `${vaultFiles.length + vaultAuditLogs.length + auditLogs.length} records`, actionHref: '/dashboard/audit-vault' },
    { label: 'Regulatory Evidence Mapping', matcher: /Regulatory Evidence|Remediation Evidence/i, scope: `${complianceEvidence.length + migrationJobs.length} evidence items`, actionHref: '/dashboard/regulatory-mapping' },
  ]
    .map((policy) => {
      const scoped = signals.filter((signal) => policy.matcher.test(signal.domain))
      return {
        label: policy.label,
        scope: policy.scope,
        enforced: scoped.some((signal) => signal.policyEnforced),
        evidence: scoped.length,
        compliant: scoped.filter((signal) => signal.compliant).length,
        violations: scoped.filter((signal) => !signal.compliant || severityRank(signal.severity) >= 2).length,
        coverage: percentOf(scoped.filter((signal) => signal.compliant).length, scoped.length),
        riskScore: clamp(scoped.reduce((sum, signal) => sum + signal.score, 0) / Math.max(1, scoped.length)),
        latestSeen: latestDate(...scoped.map((signal) => signal.timestamp)),
        actionHref: policy.actionHref,
      }
    })
    .filter((row) => row.evidence > 0)

  const regulatoryRows = [...new Map(regulatorySignals.map((signal) => [`${signal.framework}:${signal.control}`, signal])).values()]
    .map((seed) => {
      const scoped = regulatorySignals.filter((signal) => signal.framework === seed.framework && signal.control === seed.control)
      return {
        framework: seed.framework,
        control: seed.control,
        evidence: scoped.length,
        compliant: scoped.filter((signal) => signal.compliant).length,
        findings: scoped.filter((signal) => !signal.compliant || severityRank(signal.severity) >= 2).length,
        coverage: percentOf(scoped.filter((signal) => signal.compliant).length, scoped.length),
        latestSeen: latestDate(...scoped.map((signal) => signal.timestamp)),
      }
    })
    .sort((a, b) => b.findings - a.findings || b.evidence - a.evidence)
    .slice(0, 14)

  const subjectRows = [...new Map(signals.map((signal) => [signal.subject, signal])).values()]
    .map((seed) => {
      const scoped = signals.filter((signal) => signal.subject === seed.subject)
      return {
        subject: seed.subject,
        type: seed.subjectType,
        evidence: scoped.length,
        compliant: scoped.filter((signal) => signal.compliant).length,
        violations: scoped.filter((signal) => !signal.compliant || severityRank(signal.severity) >= 2).length,
        riskScore: clamp(scoped.reduce((sum, signal) => sum + signal.score, 0) / Math.max(1, scoped.length)),
        latestSeen: latestDate(...scoped.map((signal) => signal.timestamp)),
      }
    })
    .sort((a, b) => b.riskScore - a.riskScore || b.evidence - a.evidence)
    .slice(0, 14)

  const auditRows = auditSignals.slice(0, 18).map((signal) => ({
    id: signal.id,
    event: signal.title,
    actor: signal.subject,
    source: signal.sourceTable,
    result: signal.status,
    immutable: signal.immutable,
    severity: signal.severity,
    timestamp: signal.timestamp,
    detail: signal.detail,
  }))

  const recommendations = [
    violations.length > 0 && {
      id: 'resolve-governance-violations',
      title: 'Resolve governance violations',
      detail: `${violations.length} policy, audit, or regulatory signal${violations.length === 1 ? '' : 's'} need review.`,
      impact: 'high',
      count: violations.length,
      actionHref: '/dashboard/telemetry-correlation',
    },
    policyRows.filter((row) => !row.enforced).length > 0 && {
      id: 'enforce-policy-scope',
      title: 'Enforce policy scope',
      detail: `${policyRows.filter((row) => !row.enforced).length} policy area${policyRows.filter((row) => !row.enforced).length === 1 ? '' : 's'} have evidence but no active enforcement marker.`,
      impact: 'medium',
      count: policyRows.filter((row) => !row.enforced).length,
      actionHref: '/dashboard/scanner',
    },
    regulatoryRows.filter((row) => row.findings > 0).length > 0 && {
      id: 'close-regulatory-findings',
      title: 'Close regulatory evidence gaps',
      detail: `${regulatoryRows.filter((row) => row.findings > 0).length} mapped control${regulatoryRows.filter((row) => row.findings > 0).length === 1 ? '' : 's'} contain non-compliant evidence.`,
      impact: 'medium',
      count: regulatoryRows.filter((row) => row.findings > 0).length,
      actionHref: '/dashboard/regulatory-mapping',
    },
    auditSignals.filter((signal) => !signal.immutable).length > 0 && {
      id: 'strengthen-audit-immutability',
      title: 'Strengthen audit immutability',
      detail: `${auditSignals.filter((signal) => !signal.immutable).length} audit-related signal${auditSignals.filter((signal) => !signal.immutable).length === 1 ? '' : 's'} lack an immutability marker.`,
      impact: 'medium',
      count: auditSignals.filter((signal) => !signal.immutable).length,
      actionHref: '/dashboard/audit-vault',
    },
    stale.length > 0 && {
      id: 'refresh-governance-evidence',
      title: 'Refresh stale governance evidence',
      detail: `${stale.length} evidence signal${stale.length === 1 ? '' : 's'} are older than 30 days.`,
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
        ? 'waiting_for_governance_events'
        : 'no_sources'

  return {
    generatedAt: new Date().toISOString(),
    latestActivityAt: latestDate(...signals.slice(0, 80).map((signal) => signal.timestamp)),
    metrics: {
      totalEvidence: total,
      evidenceDelta: deltaPercent(current.length, previous.length),
      policyScore: percentOf(policySignals.filter((signal) => signal.compliant).length, policySignals.length),
      policyCoverage: percentOf(policySignals.filter((signal) => signal.policyEnforced).length, policySignals.length),
      activePolicies: policyRows.filter((row) => row.enforced).length + scannerPolicies.filter((policy: any) => policy.enabled).length,
      policyViolations: violations.filter((signal) => /policy|runtime|algorithm|certificate|key|scanner|scan|vulnerability/i.test(signal.domain)).length,
      auditEvents: auditSignals.length,
      immutableEvents: auditSignals.filter((signal) => signal.immutable).length,
      vaultObjects: vaultFiles.length,
      vaultIntegrityScore: percentOf(auditSignals.filter((signal) => signal.compliant && signal.encrypted).length, auditSignals.length),
      frameworksMapped: new Set(regulatoryRows.map((row) => row.framework)).size,
      controlsMapped: regulatoryRows.length,
      complianceScore: percentOf(regulatorySignals.filter((signal) => signal.compliant).length, regulatorySignals.length),
      evidenceGaps: regulatoryRows.filter((row) => row.findings > 0 || row.coverage < 70).length,
      highRiskFindings: highRisk.length,
      assetsCovered: new Set(signals.map((signal) => signal.subject).filter(Boolean)).size,
      runtimeFindings: runtimeEvents.length + scanSessions.length + scanResults.length + scannerEvidence.length + scannerAlerts.length + vulnerabilities.length,
      staleEvidence: stale.length,
      activeSources: scannerAgents.length + connectorAccounts.length,
      pqcReadiness: percentOf(pqcReady.length, total),
      encryptedCoverage: percentOf(encrypted.length, total),
    },
    timeline,
    domainRows,
    policyRows,
    regulatoryRows,
    subjectRows,
    auditRows,
    severityDistribution: countBy(signals, (signal) => titleCase(signal.severity), 5),
    statusDistribution: countBy(signals, (signal) => titleCase(signal.status), 8),
    sourceDistribution: countBy(signals, (signal) => signal.sourceTable, 10),
    frameworkDistribution: countBy(regulatorySignals, (signal) => signal.framework, 8),
    alerts: violations
      .slice()
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.score - a.score || b.ms - a.ms)
      .slice(0, 16)
      .map((signal) => ({
        id: signal.id,
        title: signal.title,
        detail: `${signal.subject} - ${signal.detail || signal.domain}`,
        severity: signal.severity,
        timestamp: signal.timestamp,
        source: signal.sourceTable,
        domain: signal.domain,
      })),
    recommendations,
    activity: signals.slice(0, 16).map((signal) => ({
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
      .slice(0, 20)
      .map((signal) => ({
        id: signal.id,
        domain: signal.domain,
        title: signal.title,
        subject: signal.subject,
        subjectType: signal.subjectType,
        framework: signal.framework,
        control: signal.control,
        status: signal.status,
        severity: signal.severity,
        score: signal.score,
        compliant: signal.compliant,
        evidence: signal.evidence,
        policyEnforced: signal.policyEnforced,
        immutable: signal.immutable,
        encrypted: signal.encrypted,
        pqcReady: signal.pqcReady,
        timestamp: signal.timestamp,
        source: signal.sourceTable,
        detail: signal.detail,
      })),
    telemetry: {
      assets: assets.length,
      runtimeEvents: runtimeEvents.length,
      scannerEvidence: scannerEvidence.length,
      scannerAlerts: scannerAlerts.length,
      scanSessions: scanSessions.length,
      scanResults: scanResults.length,
      vulnerabilities: vulnerabilities.length,
      cryptoInventory: cryptoInventory.length,
      cryptoExposures: cryptoExposures.length,
      certificates: certificates.length,
      generatedKeys: generatedKeys.length,
      scannerAgents: scannerAgents.length,
      scannerPolicies: scannerPolicies.length,
      connectors: connectorAccounts.length,
      agentHeartbeats: agentHeartbeats.length,
      vaultFiles: vaultFiles.length,
      vaultAuditLogs: vaultAuditLogs.length,
      auditLogs: auditLogs.length,
      complianceEvidence: complianceEvidence.length,
      migrationJobs: migrationJobs.length,
      securityEvents: securityEvents.length + userSecurityEvents.length + authEvents.length,
      qrngEvents: qrngEvents.length,
      eventPipelineStatus,
      latestRuntimeEventAt: latestDate(...runtimeEvents.map((event: any) => event.observed_at || event.created_at)),
    },
  }
}

export const quantumGovernanceRoutes = buildRouter('quantum')
export const auditVaultRoutes = buildRouter('audit')
export const regulatoryMappingRoutes = buildRouter('regulatory')
