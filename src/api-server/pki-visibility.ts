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

type PkiCertificate = {
  id: string
  sourceTable: string
  name: string
  subject: string
  issuer: string
  serialNumber: string
  assetId: string | null
  assetName: string
  assetType: string
  algorithm: string
  keySize: number
  status: string
  expiresAt: string | null
  daysRemaining: number | null
  pqcReady: boolean
  weak: boolean
  selfSigned: boolean
  riskLevel: Severity
  riskScore: number
  source: string
  createdAt: string | null
  updatedAt: string | null
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

function daysUntil(value: unknown) {
  const ms = dateMs(value)
  if (!ms) return null
  return Math.ceil((ms - Date.now()) / ONE_DAY_MS)
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

function titleCase(value: unknown, fallback = 'PKI Event') {
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
  if (score >= 75) return 'high'
  if (score >= 45) return 'medium'
  return 'low'
}

function isPqcAlgorithm(value: string) {
  return /ml-kem|ml_dsa|ml-dsa|kyber|dilithium|sphincs|falcon|bike|hqc|ntru|hybrid|pqc|post.quantum/i.test(value)
}

function isWeakAlgorithm(value: string, keySize = 0) {
  const text = `${value} ${keySize}`.toLowerCase()
  if (/sha-?1|md5|dsa|des|3des|rc4|rsa-?1024|rsa\s*1024/.test(text)) return true
  if (/rsa/.test(text) && keySize > 0 && keySize < 3072) return true
  if (/ec|ecc|ecdsa|ecdh|prime256v1|secp256|p-256|p256/.test(text)) return true
  return false
}

function isCertificateText(value: string) {
  return /pki|certificate|cert|x509|x\.509|issuer|subject|serial|tls|ssl|sni|pem|pkcs|keystore|trust|chain|root ca|intermediate/i.test(value)
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

function countBy<T>(items: T[], keyFn: (item: T) => string, limit = 6) {
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
      console.warn(`PKI visibility ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`PKI visibility ${table} query failed:`, error?.message || error)
    return []
  }
}

function inferCertStatus(rowStatus: unknown, expiresAt: unknown, revokedAt?: unknown) {
  const status = String(rowStatus || '').toLowerCase()
  if (status === 'revoked' || revokedAt) return 'revoked'
  if (status === 'rotated') return 'rotated'
  const days = daysUntil(expiresAt)
  if (days !== null && days < 0) return 'expired'
  if (status) return status
  return 'active'
}

function riskForCertificate(input: {
  status: string
  daysRemaining: number | null
  pqcReady: boolean
  weak: boolean
  selfSigned: boolean
  missingIssuer: boolean
  unmanaged: boolean
}) {
  let score = 16
  if (input.status === 'expired') score = 96
  else if (input.status === 'revoked') score = 90
  else if (input.daysRemaining !== null && input.daysRemaining <= 7) score = 84
  else if (input.daysRemaining !== null && input.daysRemaining <= 30) score = 68
  else if (input.daysRemaining !== null && input.daysRemaining <= 90) score = 42

  if (input.weak) score += 22
  if (!input.pqcReady) score += 10
  if (input.selfSigned) score += 14
  if (input.missingIssuer) score += 8
  if (input.unmanaged) score += 6
  return clamp(score)
}

function makeAlert(id: string, title: string, detail: string, severity: Severity, timestamp: string | null, source: string) {
  return { id, title, detail, severity, timestamp, source }
}

async function buildPkiVisibilitySnapshot(token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
    assets,
    certificates,
    generatedPki,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanSessions,
    scanResults,
    cryptoInventory,
    cryptoExposures,
    securityEvents,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, status, environment, region, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, serial_number, not_before, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, fingerprint, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', userId).like('algorithm', 'PKI-%').order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(5000)),
    safeRows(client, 'scanner_evidence', (q) => q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, raw_evidence, processed_at, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(2500)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1500)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, target_scope, progress, total_assets, scanned_assets, findings_count, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(600)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(1800)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, last_seen_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(400)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, display_name, status, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(400)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('id, agent_id, status, telemetry, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1200)),
  ])

  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
  const certRecords: PkiCertificate[] = []
  const seen = new Set<string>()

  const assetName = (assetId: unknown, fallback = 'Unassigned asset') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.name, fallback)
  }

  const assetType = (assetId: unknown, fallback = 'PKI Endpoint') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.type, fallback)
  }

  const addCertificate = (cert: Omit<PkiCertificate, 'riskScore' | 'riskLevel'>) => {
    if (seen.has(cert.id)) return
    seen.add(cert.id)
    const missingIssuer = !cert.issuer || cert.issuer === 'Unknown issuer'
    const unmanaged = !cert.assetId || cert.assetName === 'Unassigned asset'
    const score = riskForCertificate({
      status: cert.status,
      daysRemaining: cert.daysRemaining,
      pqcReady: cert.pqcReady,
      weak: cert.weak,
      selfSigned: cert.selfSigned,
      missingIssuer,
      unmanaged,
    })
    certRecords.push({ ...cert, riskScore: score, riskLevel: severityForScore(score) })
  }

  for (const row of certificates || []) {
    const metadata = recordOf(row.metadata)
    const algorithm = textValue(row.algorithm, firstString(metadata, ['algorithm', 'signature_algorithm', 'public_key_algorithm']) || 'Unknown')
    const keySize = numberValue(row.key_size, firstNumber(metadata, ['key_size', 'bits', 'bit_length']))
    const subject = textValue(row.subject, firstString(metadata, ['subject', 'common_name', 'cn', 'domain']) || textValue(row.name, 'Unknown subject'))
    const issuer = textValue(row.issuer, firstString(metadata, ['issuer', 'issuer_cn', 'ca', 'authority']) || 'Unknown issuer')
    const serialNumber = textValue(row.serial_number, firstString(metadata, ['serial_number', 'serial']) || String(row.id).slice(0, 12))
    const expiresAt = textValue(row.not_after, firstString(metadata, ['not_after', 'expires_at', 'valid_to'])) || null
    const status = inferCertStatus(row.status, expiresAt)
    const daysRemaining = daysUntil(expiresAt)
    const pqcReady = Boolean(row.is_quantum_safe) || isPqcAlgorithm(algorithm)
    const weak = isWeakAlgorithm(algorithm, keySize)
    const selfSigned = issuer && subject ? issuer.toLowerCase() === subject.toLowerCase() : Boolean(metadata.self_signed)

    addCertificate({
      id: `certificate:${row.id}`,
      sourceTable: 'certificates',
      name: textValue(row.name, subject),
      subject,
      issuer,
      serialNumber,
      assetId: textValue(row.asset_id) || null,
      assetName: assetName(row.asset_id),
      assetType: assetType(row.asset_id),
      algorithm,
      keySize,
      status,
      expiresAt,
      daysRemaining,
      pqcReady,
      weak,
      selfSigned,
      source: 'Discovered Certificate',
      createdAt: textValue(row.created_at) || null,
      updatedAt: latestDate(row.updated_at, row.created_at),
      text: `${row.name || ''} ${subject} ${issuer} ${algorithm} ${JSON.stringify(metadata)}`,
    })
  }

  for (const row of generatedPki || []) {
    const label = recordOf(row.label)
    const metadata = recordOf(row.metadata)
    const algorithm = textValue(row.algorithm, 'PKI-ML-DSA').replace(/^PKI-/i, '')
    const subject = firstString(label, ['common_name', 'subject', 'cn']) || firstString(metadata, ['common_name', 'subject', 'cn']) || 'Issued certificate'
    const issuer = firstString(label, ['organization', 'issuer', 'ca']) || firstString(metadata, ['issuer', 'ca']) || 'QGuard PKI'
    const expiresAt = textValue(row.expires_at) || null
    const status = inferCertStatus(row.status, expiresAt, row.revoked_at)
    const keySize = numberValue(row.bit_length)
    const pqcReady = isPqcAlgorithm(algorithm)
    const weak = isWeakAlgorithm(algorithm, keySize)
    const selfSigned = Boolean(label.self_signed || metadata.self_signed)

    addCertificate({
      id: `generated_keys:${row.id}`,
      sourceTable: 'generated_keys',
      name: subject,
      subject,
      issuer,
      serialNumber: firstString(label, ['serial_number', 'serial']) || textValue(row.fingerprint, String(row.id).slice(0, 12)),
      assetId: null,
      assetName: 'QGuard Issued PKI',
      assetType: 'Managed Certificate',
      algorithm,
      keySize,
      status,
      expiresAt,
      daysRemaining: daysUntil(expiresAt),
      pqcReady,
      weak,
      selfSigned,
      source: 'QGuard PKI',
      createdAt: textValue(row.created_at) || null,
      updatedAt: latestDate(row.updated_at, row.created_at),
      text: `${subject} ${issuer} ${algorithm} ${JSON.stringify(label)} ${JSON.stringify(metadata)}`,
    })
  }

  for (const row of cryptoInventory || []) {
    const metadata = recordOf(row.metadata)
    const text = `${row.item_type || ''} ${row.name || ''} ${row.algorithm || ''} ${row.protocol || ''} ${JSON.stringify(metadata)}`
    if (!isCertificateText(text)) continue
    const algorithm = textValue(row.algorithm, firstString(metadata, ['algorithm', 'signature_algorithm']) || 'Unknown')
    const keySize = numberValue(row.key_size, firstNumber(metadata, ['key_size', 'bits', 'bit_length']))
    const expiresAt = firstString(metadata, ['not_after', 'expires_at', 'valid_to']) || null
    const status = inferCertStatus(metadata.status, expiresAt)
    const issuer = firstString(metadata, ['issuer', 'issuer_cn', 'ca', 'authority']) || 'Unknown issuer'
    const subject = textValue(row.name, firstString(metadata, ['subject', 'common_name', 'cn', 'domain']) || 'Inventory certificate')
    const pqcReady = Boolean(row.is_quantum_safe) || isPqcAlgorithm(algorithm)
    const weak = Boolean(row.is_vulnerable) || isWeakAlgorithm(algorithm, keySize)

    addCertificate({
      id: `crypto_inventory:${row.id}`,
      sourceTable: 'crypto_inventory',
      name: subject,
      subject,
      issuer,
      serialNumber: firstString(metadata, ['serial_number', 'serial']) || String(row.id).slice(0, 12),
      assetId: textValue(row.asset_id) || null,
      assetName: assetName(row.asset_id),
      assetType: assetType(row.asset_id, textValue(row.item_type, 'PKI Endpoint')),
      algorithm,
      keySize,
      status,
      expiresAt,
      daysRemaining: daysUntil(expiresAt),
      pqcReady,
      weak,
      selfSigned: Boolean(metadata.self_signed) || (issuer && subject ? issuer.toLowerCase() === subject.toLowerCase() : false),
      source: 'Crypto Inventory',
      createdAt: latestDate(row.discovered_at, row.created_at),
      updatedAt: latestDate(row.discovered_at, row.created_at),
      text,
    })
  }

  const certTexts = certRecords.map((cert) => cert.text).join(' ')
  const certRuntimeEvents = (runtimeEvents || []).filter((event: any) => {
    const metadata = recordOf(event.metadata)
    return isCertificateText(`${event.event_type || ''} ${event.operation_type || ''} ${event.asset_name || ''} ${event.host || ''} ${event.protocol || ''} ${event.algorithm || ''} ${event.cipher_suite || ''} ${JSON.stringify(metadata)}`)
  })
  const certEvidence = (scannerEvidence || []).filter((row: any) => isCertificateText(`${row.evidence_type || ''} ${row.source_type || ''} ${row.target || ''} ${row.host || ''} ${row.protocol || ''} ${row.observed_algorithm || ''} ${JSON.stringify(row.raw_evidence || {})}`))
  const certAlerts = (scannerAlerts || []).filter((row: any) => isCertificateText(`${row.category || ''} ${row.title || ''} ${row.message || ''} ${row.recommendation || ''} ${JSON.stringify(row.metadata || {})}`))
  const certScanResults = (scanResults || []).filter((row: any) => isCertificateText(`${row.finding_type || ''} ${row.algorithm || ''} ${row.description || ''} ${row.remediation || ''} ${JSON.stringify(row.metadata || {})}`))
  const certExposures = (cryptoExposures || []).filter((row: any) => isCertificateText(`${row.exposure_type || ''} ${row.description || ''} ${row.detected_value || ''} ${JSON.stringify(row.metadata || {})}`))
  const certSecurityEvents = (securityEvents || []).filter((row: any) => isCertificateText(`${row.event_type || ''} ${row.message || ''} ${row.resource_name || ''} ${row.resource_type || ''} ${JSON.stringify(row.metadata || {})}`))

  const now = Date.now()
  const currentStart = now - 7 * ONE_DAY_MS
  const previousStart = now - 14 * ONE_DAY_MS
  const currentCreated = certRecords.filter((cert) => dateMs(cert.createdAt || cert.updatedAt) >= currentStart).length
  const previousCreated = certRecords.filter((cert) => {
    const ms = dateMs(cert.createdAt || cert.updatedAt)
    return ms >= previousStart && ms < currentStart
  }).length

  const activeCertificates = certRecords.filter((cert) => cert.status === 'active').length
  const expiredCertificates = certRecords.filter((cert) => cert.status === 'expired').length
  const revokedCertificates = certRecords.filter((cert) => cert.status === 'revoked').length
  const expiringSoon = certRecords.filter((cert) => cert.status === 'active' && cert.daysRemaining !== null && cert.daysRemaining <= 30).length
  const pqcReady = certRecords.filter((cert) => cert.pqcReady).length
  const weakAlgorithms = certRecords.filter((cert) => cert.weak).length
  const selfSigned = certRecords.filter((cert) => cert.selfSigned).length
  const unmanaged = certRecords.filter((cert) => !cert.assetId && cert.sourceTable !== 'generated_keys').length
  const chainIssues = selfSigned + certRecords.filter((cert) => !cert.issuer || cert.issuer === 'Unknown issuer').length + certExposures.filter((row: any) => /chain|issuer|trust|root|intermediate|self-signed|self signed/i.test(`${row.exposure_type || ''} ${row.description || ''}`)).length
  const highRiskCertificates = certRecords.filter((cert) => cert.riskLevel === 'critical' || cert.riskLevel === 'high').length
  const totalCertificates = certRecords.length
  const healthScore = totalCertificates
    ? clamp(100 - (expiredCertificates * 12 + revokedCertificates * 9 + expiringSoon * 6 + weakAlgorithms * 5 + selfSigned * 4 + unmanaged * 3) / Math.max(1, totalCertificates))
    : 0
  const pkiRiskScore = totalCertificates ? clamp(100 - healthScore + percentOf(certExposures.length + certAlerts.length, Math.max(1, totalCertificates + certRuntimeEvents.length)) / 2) : 0

  const dateLabels = Array.from({ length: 7 }, (_, index) => {
    const date = new Date(now - (6 - index) * ONE_DAY_MS)
    date.setHours(0, 0, 0, 0)
    return date
  })

  const timeline = dateLabels.map((date) => {
    const start = date.getTime()
    const end = start + ONE_DAY_MS
    const label = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
    return {
      label,
      issued: certRecords.filter((cert) => {
        const ms = dateMs(cert.createdAt)
        return ms >= start && ms < end
      }).length,
      expiring: certRecords.filter((cert) => {
        const ms = dateMs(cert.expiresAt)
        return ms >= start && ms < end
      }).length,
      findings: [
        ...certRuntimeEvents,
        ...certAlerts,
        ...certScanResults,
        ...certExposures,
        ...certSecurityEvents,
      ].filter((row: any) => {
        const ms = dateMs(row.observed_at || row.created_at || row.updated_at)
        return ms >= start && ms < end
      }).length,
    }
  })

  const expiryBuckets = [
    { label: 'Expired', count: expiredCertificates },
    { label: '0-7 days', count: certRecords.filter((cert) => cert.status === 'active' && cert.daysRemaining !== null && cert.daysRemaining >= 0 && cert.daysRemaining <= 7).length },
    { label: '8-30 days', count: certRecords.filter((cert) => cert.status === 'active' && cert.daysRemaining !== null && cert.daysRemaining > 7 && cert.daysRemaining <= 30).length },
    { label: '31-90 days', count: certRecords.filter((cert) => cert.status === 'active' && cert.daysRemaining !== null && cert.daysRemaining > 30 && cert.daysRemaining <= 90).length },
    { label: '90+ days', count: certRecords.filter((cert) => cert.status === 'active' && (cert.daysRemaining === null || cert.daysRemaining > 90)).length },
  ].map((row) => ({ ...row, percent: percentOf(row.count, totalCertificates) }))

  const algorithmDistribution = countBy(certRecords, (cert) => cert.algorithm || 'Unknown', 7)
  const issuerDistribution = countBy(certRecords, (cert) => cert.issuer || 'Unknown issuer', 7)
  const statusDistribution = countBy(certRecords, (cert) => titleCase(cert.status), 6)
  const assetTypeDistribution = countBy(certRecords, (cert) => cert.assetType || 'PKI Endpoint', 6)

  const issuerRows = [...new Map(certRecords.map((cert) => [cert.issuer || 'Unknown issuer', cert.issuer || 'Unknown issuer'])).keys()]
    .map((issuer) => {
      const scoped = certRecords.filter((cert) => (cert.issuer || 'Unknown issuer') === issuer)
      return {
        issuer,
        certificates: scoped.length,
        expiring: scoped.filter((cert) => cert.daysRemaining !== null && cert.daysRemaining <= 30).length,
        pqcReady: percentOf(scoped.filter((cert) => cert.pqcReady).length, scoped.length),
        riskScore: clamp(scoped.reduce((sum, cert) => sum + cert.riskScore, 0) / Math.max(1, scoped.length)),
      }
    })
    .sort((a, b) => b.certificates - a.certificates || b.riskScore - a.riskScore)
    .slice(0, 8)

  const inventory = certRecords
    .sort((a, b) => b.riskScore - a.riskScore || dateMs(b.updatedAt) - dateMs(a.updatedAt))
    .slice(0, 12)
    .map((cert) => ({
      id: cert.id,
      name: cert.name,
      subject: cert.subject,
      issuer: cert.issuer,
      assetName: cert.assetName,
      assetType: cert.assetType,
      algorithm: cert.algorithm,
      keySize: cert.keySize,
      status: cert.status,
      expiresAt: cert.expiresAt,
      daysRemaining: cert.daysRemaining,
      pqcReady: cert.pqcReady,
      riskLevel: cert.riskLevel,
      riskScore: cert.riskScore,
      source: cert.source,
    }))

  const alertRows = [
    ...certRecords
      .filter((cert) => cert.status === 'expired')
      .map((cert) => makeAlert(`expired-${cert.id}`, 'Expired certificate detected', `${cert.subject} expired under ${cert.issuer}`, 'critical', cert.expiresAt, cert.source)),
    ...certRecords
      .filter((cert) => cert.status === 'revoked')
      .map((cert) => makeAlert(`revoked-${cert.id}`, 'Revoked certificate still tracked', `${cert.subject} remains in inventory`, 'high', cert.updatedAt, cert.source)),
    ...certRecords
      .filter((cert) => cert.status === 'active' && cert.daysRemaining !== null && cert.daysRemaining <= 30)
      .map((cert) => makeAlert(`expiring-${cert.id}`, 'Certificate renewal window open', `${cert.subject} expires in ${Math.max(0, cert.daysRemaining || 0)} days`, cert.daysRemaining !== null && cert.daysRemaining <= 7 ? 'high' : 'medium', cert.expiresAt, cert.source)),
    ...certRecords
      .filter((cert) => cert.weak)
      .map((cert) => makeAlert(`weak-${cert.id}`, 'Weak certificate algorithm', `${cert.algorithm || 'Unknown algorithm'} on ${cert.subject}`, 'high', cert.updatedAt, cert.source)),
    ...certRecords
      .filter((cert) => cert.selfSigned)
      .map((cert) => makeAlert(`self-${cert.id}`, 'Self-signed certificate detected', `${cert.subject} is outside managed trust`, 'medium', cert.updatedAt, cert.source)),
    ...certAlerts.map((alert: any) => makeAlert(
      `scanner-${alert.id}`,
      textValue(alert.title, 'Scanner PKI alert'),
      textValue(alert.message, textValue(alert.recommendation, 'Scanner reported certificate risk')),
      normalizeSeverity(alert.severity),
      latestDate(alert.updated_at, alert.created_at),
      'Scanner Alert',
    )),
    ...certExposures.map((exposure: any) => makeAlert(
      `exposure-${exposure.id}`,
      titleCase(exposure.exposure_type, 'PKI exposure'),
      textValue(exposure.description, textValue(exposure.detected_value, 'Exposure detected in certificate telemetry')),
      normalizeSeverity(exposure.severity),
      latestDate(exposure.updated_at, exposure.created_at),
      'Crypto Exposure',
    )),
    ...certScanResults.map((result: any) => makeAlert(
      `scan-${result.id}`,
      titleCase(result.finding_type, 'PKI scan finding'),
      textValue(result.description, textValue(result.remediation, 'Scan detected certificate posture drift')),
      normalizeSeverity(result.threat_level),
      textValue(result.created_at) || null,
      'Scan Result',
    )),
  ]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || dateMs(b.timestamp) - dateMs(a.timestamp))
    .slice(0, 12)

  const recommendations = [
    expiredCertificates > 0 && {
      id: 'replace-expired',
      title: 'Replace expired certificates',
      detail: `${expiredCertificates} expired certificate${expiredCertificates === 1 ? '' : 's'} need renewal or removal from active trust paths.`,
      impact: 'critical',
      count: expiredCertificates,
      actionHref: '/dashboard/pki',
    },
    expiringSoon > 0 && {
      id: 'renew-expiring',
      title: 'Renew certificates inside 30 days',
      detail: `${expiringSoon} active certificate${expiringSoon === 1 ? '' : 's'} are inside the renewal window.`,
      impact: expiringSoon > 5 ? 'high' : 'medium',
      count: expiringSoon,
      actionHref: '/dashboard/pki',
    },
    weakAlgorithms > 0 && {
      id: 'replace-weak-algorithms',
      title: 'Migrate weak certificate algorithms',
      detail: `${weakAlgorithms} certificate${weakAlgorithms === 1 ? '' : 's'} use RSA/ECC/SHA-1/legacy cryptography or weak key sizes.`,
      impact: 'high',
      count: weakAlgorithms,
      actionHref: '/dashboard/quantum-risk-scoring',
    },
    totalCertificates > 0 && pqcReady < totalCertificates && {
      id: 'adopt-pqc-certificates',
      title: 'Increase PQC certificate adoption',
      detail: `${totalCertificates - pqcReady} certificate${totalCertificates - pqcReady === 1 ? '' : 's'} are not marked post-quantum ready.`,
      impact: 'medium',
      count: totalCertificates - pqcReady,
      actionHref: '/dashboard/pki',
    },
    selfSigned > 0 && {
      id: 'remove-self-signed',
      title: 'Review self-signed trust paths',
      detail: `${selfSigned} self-signed certificate${selfSigned === 1 ? '' : 's'} should be replaced or explicitly approved.`,
      impact: 'medium',
      count: selfSigned,
      actionHref: '/dashboard/scanner',
    },
    unmanaged > 0 && {
      id: 'assign-owners',
      title: 'Assign certificate ownership',
      detail: `${unmanaged} discovered certificate${unmanaged === 1 ? '' : 's'} are not linked to a known tenant asset.`,
      impact: 'low',
      count: unmanaged,
      actionHref: '/dashboard/assets',
    },
  ].filter(Boolean)

  const activity = [
    ...certRecords.map((cert) => ({
      id: `cert-${cert.id}`,
      title: cert.sourceTable === 'generated_keys' ? 'Certificate issued' : 'Certificate observed',
      detail: `${cert.subject} via ${cert.source}`,
      severity: cert.riskLevel,
      timestamp: cert.updatedAt || cert.createdAt,
      source: cert.source,
    })),
    ...certRuntimeEvents.slice(0, 40).map((event: any) => ({
      id: `runtime-${event.id}`,
      title: titleCase(event.event_type || event.operation_type, 'Runtime PKI event'),
      detail: textValue(event.asset_name, textValue(event.host, textValue(event.protocol, 'Runtime certificate telemetry'))),
      severity: normalizeSeverity(event.severity),
      timestamp: textValue(event.observed_at || event.created_at) || null,
      source: 'Runtime Telemetry',
    })),
    ...certSecurityEvents.slice(0, 30).map((event: any) => ({
      id: `security-${event.id}`,
      title: titleCase(event.event_type, 'Security event'),
      detail: textValue(event.message, textValue(event.resource_name, 'Security event')),
      severity: normalizeSeverity(event.severity),
      timestamp: textValue(event.created_at) || null,
      source: 'Security Events',
    })),
  ]
    .sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp))
    .slice(0, 12)

  const latestRuntimeEventAt = latestDate(...certRuntimeEvents.map((event: any) => event.observed_at || event.created_at))
  const sync = buildTenantTelemetrySync({
    assets,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    scanSessions,
    runtimeEvents: certRuntimeEvents,
    scannerEvidence: certEvidence,
    scannerAlerts: certAlerts,
    scanResults: certScanResults,
    cryptoInventory,
    cryptoExposures: certExposures,
    securityEvents: certSecurityEvents,
    generatedKeys: generatedPki,
    certificates: certRecords,
  })
  const latestActivityAt = latestDate(
    ...certRecords.map((cert) => cert.updatedAt || cert.createdAt || cert.expiresAt),
    latestRuntimeEventAt,
    sync.latestScanAt,
    sync.latestDiscoveryAt,
    ...certAlerts.map((alert: any) => alert.updated_at || alert.created_at),
    ...certExposures.map((exposure: any) => exposure.updated_at || exposure.created_at),
  )
  const eventPipelineStatus = certRuntimeEvents.length || certEvidence.length || certAlerts.length
    ? 'active'
    : sync.runningScans
      ? 'scan_running'
    : totalCertificates || certTexts
      ? 'inventory_only'
      : scannerAgents.length || connectorAccounts.length
        ? 'waiting_for_pki_events'
        : 'no_agents'

  return {
    generatedAt: new Date().toISOString(),
    latestActivityAt,
    metrics: {
      totalCertificates,
      totalCertificatesDelta: deltaPercent(currentCreated, previousCreated),
      activeCertificates,
      expiringSoon,
      expiredCertificates,
      revokedCertificates,
      pqcReady,
      pqcReadyPercent: percentOf(pqcReady, totalCertificates),
      weakAlgorithms,
      selfSigned,
      chainIssues,
      unmanagedCertificates: unmanaged,
      highRiskCertificates,
      pkiHealthScore: healthScore,
      pkiRiskScore,
      issuers: new Set(certRecords.map((cert) => cert.issuer).filter(Boolean)).size,
      assetsCovered: new Set(certRecords.map((cert) => cert.assetId || cert.assetName).filter(Boolean)).size,
      expiryRiskPercent: percentOf(expiringSoon + expiredCertificates + revokedCertificates, totalCertificates),
    },
    timeline,
    expiryBuckets,
    algorithmDistribution,
    issuerDistribution,
    statusDistribution,
    assetTypeDistribution,
    issuerRows,
    inventory,
    alerts: alertRows,
    recommendations,
    activity,
    telemetry: {
      assets: assets.length,
      certificates: certificates.length,
      generatedPki: generatedPki.length,
      runtimeEvents: certRuntimeEvents.length,
      scannerEvidence: certEvidence.length,
      scannerAlerts: certAlerts.length,
      scanResults: certScanResults.length,
      cryptoInventory: cryptoInventory.length,
      cryptoExposures: certExposures.length,
      securityEvents: certSecurityEvents.length,
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
  writeSse(res, 'pki-visibility-connected', {
    timestamp: new Date().toISOString(),
    source: 'dashboard.pki-visibility',
  })

  let closed = false
  const emitUpdate = () => {
    if (closed) return
    writeSse(res, 'pki-visibility-update', {
      timestamp: new Date().toISOString(),
      source: 'dashboard.pki-visibility',
      reason: 'tenant-pki-sync',
    })
  }

  emitUpdate()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': pki-visibility heartbeat\n\n')
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

    const data = await buildPkiVisibilitySnapshot(req.token, req.user.id)
    return res.json({ data })
  } catch (error: any) {
    console.error('PKI visibility dashboard error:', error)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || 'Failed to fetch PKI visibility data' } })
  }
})

export default router
