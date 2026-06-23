import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildTenantTelemetrySync } from './tenant-telemetry-sync'

type QkmsMode = 'overview' | 'inventory' | 'governance' | 'readiness' | 'lifecycle' | 'rotation' | 'risk-analysis'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

const MODES = new Set<QkmsMode>(['overview', 'inventory', 'governance', 'readiness', 'lifecycle', 'rotation', 'risk-analysis'])
const ONE_DAY_MS = 24 * 60 * 60 * 1000
const SOURCE_STALE_MS = ONE_DAY_MS
const EXPIRY_WARNING_MS = 45 * ONE_DAY_MS
const APPROVED_STORAGE_PATTERN = /hsm|kms|vault|key vault|cloudhsm|softhsm|yubihsm|qrng/i
const BLOCKED_REQUEST_FIELDS = ['private_key', 'privateKey', 'secret', 'secretValue', 'raw_key', 'rawKey', 'plaintext', 'key_material', 'keyMaterial']

const ALLOWED_ALGORITHMS = [
  'AES-256-GCM',
  'RSA-3072',
  'RSA-4096',
  'Ed25519',
  'X25519',
  'ML-KEM-512',
  'ML-KEM-768',
  'ML-KEM-1024',
  'ML-DSA-44',
  'ML-DSA-65',
  'ML-DSA-87',
  'SLH-DSA',
  'HKDF-SHA3-256',
  'SHA3-256',
  'SHA3-512',
]

const DEFAULT_POLICY_BLUEPRINTS = [
  {
    id: 'block-rsa-2048-new',
    name: 'Block RSA-2048 for new production keys',
    description: 'Require a PQC or hybrid alternative when key establishment can use ML-KEM or hybrid TLS.',
    allowedAlgorithms: ['ML-KEM-768', 'ML-KEM-1024', 'X25519+ML-KEM-768', 'AES-256-GCM'],
    blockedAlgorithms: ['RSA-2048', 'ECDSA P-256', 'ECDH P-256', '3DES', 'RC4'],
    maxKeyAgeDays: 365,
    rotationIntervalDays: 180,
    requireOwner: true,
    requireHsm: true,
    allowExport: false,
    environmentScope: 'production',
    severity: 'high',
    enabled: true,
    status: 'enforced',
    owner: 'QKMS policy engine',
  },
  {
    id: 'warn-long-lived-ec',
    name: 'Warn on long-lived ECDSA/ECDH exposure',
    description: 'Surface classical elliptic-curve keys protecting long-lived data or signing paths.',
    allowedAlgorithms: ['ML-DSA-65', 'SLH-DSA', 'Ed25519'],
    blockedAlgorithms: ['ECDSA P-256', 'ECDH P-256'],
    maxKeyAgeDays: 180,
    rotationIntervalDays: 90,
    requireOwner: true,
    requireHsm: false,
    allowExport: false,
    environmentScope: 'all',
    severity: 'medium',
    enabled: true,
    status: 'review',
    owner: 'Cryptographic authority',
  },
  {
    id: 'signing-audit-evidence',
    name: 'Require audit evidence for signing keys',
    description: 'Every signing key must have owner, custody, rotation, and readiness evidence.',
    allowedAlgorithms: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA', 'Ed25519'],
    blockedAlgorithms: ['DSA', 'RSA-1024'],
    maxKeyAgeDays: 365,
    rotationIntervalDays: 365,
    requireOwner: true,
    requireHsm: true,
    allowExport: false,
    environmentScope: 'all',
    severity: 'high',
    enabled: true,
    status: 'enforced',
    owner: 'Audit control plane',
  },
]

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

function titleCase(value: unknown, fallback = 'QKMS Signal') {
  const text = String(value || fallback).replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
  return text.replace(/\b\w/g, (char) => char.toUpperCase()) || fallback
}

function isPqcAlgorithm(value: string) {
  return /ml-kem|ml_dsa|ml-dsa|slh-dsa|slh_dsa|sphincs|kyber|dilithium|falcon|bike|hqc|ntru|hybrid|pqc|post.quantum/i.test(value)
}

function isKemAlgorithm(value: string) {
  return /ml-kem|kyber|kem|key establishment|key exchange|encapsulation|hybrid/i.test(value)
}

function isSignatureAlgorithm(value: string) {
  return /ml-dsa|ml_dsa|slh-dsa|slh_dsa|sphincs|dilithium|falcon|sign|signature|verify/i.test(value)
}

function isWeakAlgorithm(value: string, keySize = 0) {
  const text = `${value} ${keySize}`.toLowerCase()
  if (/des|3des|rc4|md5|sha-?1|dsa|rsa[_ -]?1024|rsa[_ -]?2048|ecdh|ecdsa|p-?256|secp256|prime256v1|cbc|null|export/.test(text)) return true
  if (/rsa/.test(text) && keySize > 0 && keySize < 3072) return true
  return false
}

function isSymmetricAlgorithm(value: string) {
  return /aes-?256|aes_gcm|aes-?gcm|chacha20|xchacha/i.test(value)
}

function isHashKdfAlgorithm(value: string) {
  return /sha3|hkdf|shake|kmac/i.test(value)
}

function isKeyText(value: string) {
  return /key|kms|hsm|vault|softhsm|rotation|wrap|unwrap|sign|verify|encrypt|decrypt|qrng|entropy|kem|ml-kem|ml-dsa|slh-dsa|rsa|ecdsa|kyber|dilithium/i.test(value)
}

function inferStorageBackend(value: string) {
  const text = value.toLowerCase()
  if (/aws|cloudhsm|cloud hsm|kms/.test(text)) return 'Cloud KMS'
  if (/azure|key vault/.test(text)) return 'Azure Key Vault'
  if (/gcp|google|cloud kms/.test(text)) return 'Google Cloud KMS'
  if (/softhsm|soft hsm/.test(text)) return 'SoftHSM'
  if (/\bhsm\b|hardware security/.test(text)) return 'HSM'
  if (/vault|hashicorp/.test(text)) return 'Vault'
  if (/qrng|quantum random|entropy/.test(text)) return 'QRNG Entropy'
  return 'Application Key Store'
}

function inferKeyType(value: string) {
  const text = value.toLowerCase()
  if (/token|tokenization/.test(text)) return 'Tokenization key'
  if (/database|db|transparent data|tde/.test(text)) return 'Database encryption key'
  if (/api secret|api[_ -]?key|webhook|client secret/.test(text)) return 'API secret'
  if (/ssh/.test(text)) return 'SSH key'
  if (/tls|certificate|x509|private key/.test(text)) return 'TLS private key'
  if (/sign|verify|signature|ml-dsa|slh-dsa|ecdsa|ed25519|dilithium|sphincs/.test(text)) return 'Signing key'
  if (/vault|wrap|unwrap|hsm|kms/.test(text)) return 'Vault key'
  if (/ml-kem|kyber|hybrid|x25519|kem|key exchange|encapsulation/.test(text)) return 'PQC/hybrid key'
  if (/aes|encrypt|decrypt|symmetric/.test(text)) return 'Symmetric encryption key'
  return 'Cryptographic key'
}

function inferEnvironment(value: string, fallback = 'unknown') {
  const text = value.toLowerCase()
  if (/prod|production|critical|customer/.test(text)) return 'production'
  if (/stage|staging|preprod|uat/.test(text)) return 'staging'
  if (/dev|development|local|test|sandbox/.test(text)) return 'development'
  return fallback
}

function inferEntropySource(value: string) {
  const text = value.toLowerCase()
  if (/id quantique|idq/.test(text)) return 'ID Quantique QRNG'
  if (/ibm.*qrng|quantum demo/.test(text)) return 'IBM Quantum QRNG Demo'
  if (/qrng|quantum random/.test(text)) return 'QRNG Provider'
  if (/hsm rng|hardware rng|hsm/.test(text)) return 'HSM RNG'
  if (/os|csprng|system/.test(text)) return 'OS CSPRNG'
  return 'OS CSPRNG'
}

function pqcReadinessStatus(value: string, weak = false) {
  if (weak) return 'Deprecated'
  if (/hybrid|x25519.*ml-kem|ml-kem.*x25519/i.test(value)) return 'Hybrid-Ready'
  if (/ml-kem|ml-dsa|slh-dsa|sphincs|dilithium|kyber|pqc|post.quantum/i.test(value)) return 'Quantum-Ready'
  if (/blocked|revoked|disabled|compromised/i.test(value)) return 'Blocked'
  if (/rsa|ecdsa|ecdh|ed25519|x25519|aes|sha3|hkdf/i.test(value)) return 'Classical Only'
  return 'Unknown'
}

function rotationStatusFor(input: {
  status: string
  expiresAt: unknown
  rotationRequired: boolean
  weak: boolean
  lastRotatedAt: unknown
}) {
  const lower = input.status.toLowerCase()
  const expiryMs = dateMs(input.expiresAt)
  const rotatedMs = dateMs(input.lastRotatedAt)
  const ageMs = rotatedMs ? Date.now() - rotatedMs : 0
  if (/failed|error/.test(lower)) return 'Failed'
  if (/rotating|in_progress|processing/.test(lower)) return 'Rotating'
  if (/rotated|completed|success/.test(lower)) return 'Completed'
  if (/blocked|revoked|disabled|compromised/.test(lower) || input.weak) return 'Blocked'
  if (expiryMs && expiryMs < Date.now()) return 'Overdue'
  if (expiryMs && expiryMs - Date.now() <= EXPIRY_WARNING_MS) return 'Due Soon'
  if (ageMs > 365 * ONE_DAY_MS || input.rotationRequired) return 'Due Soon'
  return 'Healthy'
}

function complianceStatusFor(input: { owner: string; backend: string; weak: boolean; rotationRequired: boolean; auditEvents: number }) {
  if (!input.owner || /unassigned|unknown|none/i.test(input.owner)) return 'Missing owner'
  if (!APPROVED_STORAGE_PATTERN.test(input.backend)) return 'Storage review'
  if (input.weak) return 'Deprecated algorithm'
  if (input.rotationRequired) return 'Rotation due'
  if (!input.auditEvents) return 'Evidence needed'
  return 'Compliant'
}

function riskExplanationFor(key: any) {
  if (key.weak) return 'Deprecated or weak algorithm detected in key posture or runtime telemetry.'
  if (key.orphaned) return 'Key is missing a reliable owner or asset mapping.'
  if (key.rotationRequired) return 'Key is expired, revoked, stale, or due for lifecycle rotation.'
  if (!key.hsmBacked) return 'Key is not currently mapped to an approved HSM, KMS, or vault backend.'
  return 'No blocking key lifecycle risk detected from synchronized telemetry.'
}

function recommendedActionFor(key: any) {
  if (key.weak) return isKemAlgorithm(`${key.algorithm} ${key.purpose}`)
    ? 'Plan hybrid X25519 + ML-KEM or ML-KEM migration and block new weak key use.'
    : isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`)
      ? 'Create ML-DSA or SLH-DSA signing migration plan and rotate dependent certificates.'
      : 'Create a rotation job and replace deprecated cryptography.'
  if (key.orphaned) return 'Assign a responsible owner before allowing migration.'
  if (key.rotationRequired) return 'Create or resume a rotation job and attach evidence when complete.'
  if (!key.hsmBacked) return 'Move custody to approved HSM, KMS, or vault backend.'
  return 'Maintain evidence and continue lifecycle monitoring.'
}

function csvEscape(value: unknown) {
  const text = String(value ?? '')
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

function hasBlockedSecretFields(body: Record<string, any>) {
  return Object.keys(body || {}).some((key) => BLOCKED_REQUEST_FIELDS.includes(key))
}

function isMissingTable(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return text.includes('42p01') || text.includes('pgrst205') || text.includes('does not exist') || text.includes('could not find the table')
}

function severityRank(value: unknown) {
  const lower = String(value || '').toLowerCase()
  if (lower === 'critical') return 4
  if (lower === 'high' || lower === 'error' || lower === 'failed') return 3
  if (lower === 'medium' || lower === 'moderate' || lower === 'warning') return 2
  if (lower === 'low' || lower === 'info') return 1
  return 0
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`QKMS ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`QKMS ${table} query failed:`, error?.message || error)
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

function withSource(table: string, rows: any[]) {
  return (rows || []).map((row) => ({ ...row, sourceTable: table }))
}

function sourceHealth(label: string, table: string, rows: any[], staleAfterMs = SOURCE_STALE_MS) {
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

function dedupeKeyRecords(records: any[]) {
  const byIdentity = new Map<string, any>()

  for (const record of records) {
    const fingerprint = textValue(record.fingerprint || record.metadata?.fingerprint || record.metadata?.fingerprint_sha256)
    const identity = fingerprint
      ? `fingerprint:${fingerprint.toLowerCase()}`
      : [
        textValue(record.assetId, textValue(record.assetName, 'unmapped')).toLowerCase(),
        textValue(record.algorithm, 'unknown').toLowerCase(),
        textValue(record.name, 'key').toLowerCase(),
        textValue(record.backend, 'store').toLowerCase(),
      ].join(':')

    const existing = byIdentity.get(identity)
    if (!existing) {
      byIdentity.set(identity, { ...record, sources: [record.source].filter(Boolean) })
      continue
    }

    const sources = Array.from(new Set([...(existing.sources || []), record.source].filter(Boolean)))
    byIdentity.set(identity, {
      ...existing,
      quantumReady: Boolean(existing.quantumReady || record.quantumReady),
      weak: Boolean(existing.weak || record.weak),
      orphaned: Boolean(existing.orphaned && record.orphaned),
      rotationRequired: Boolean(existing.rotationRequired || record.rotationRequired),
      runtimeUsage: Math.max(numberValue(existing.runtimeUsage), numberValue(record.runtimeUsage)),
      certificateLinks: Math.max(numberValue(existing.certificateLinks), numberValue(record.certificateLinks)),
      trustScore: Math.max(numberValue(existing.trustScore), numberValue(record.trustScore)),
      updatedAt: latestDate(existing.updatedAt, record.updatedAt) || existing.updatedAt || record.updatedAt,
      sources,
      source: sources.join(', '),
    })
  }

  return [...byIdentity.values()]
}

async function buildQkmsSnapshot(mode: QkmsMode, token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
    assets,
    generatedKeys,
    cryptoInventory,
    cryptoExposures,
    certificates,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanSessions,
    scanResults,
    migrationJobs,
    complianceEvidence,
    vaultAuditLogs,
    qrngEvents,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    securityEvents,
    vulnerabilities,
    auditLogs,
    scannerPolicies,
    qkmsKeys,
    qkmsPolicies,
    qkmsRotationJobs,
    qkmsAuditEvents,
    qkmsStorageBackends,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, fingerprint, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2400)),
    safeRows(client, 'crypto_inventory', (q) => q.select('*').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(2600)),
    safeRows(client, 'crypto_exposures', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2000)),
    safeRows(client, 'certificates', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(5000)),
    safeRows(client, 'scanner_evidence', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(2600)),
    safeRows(client, 'scanner_alerts', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(500)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(2600)),
    safeRows(client, 'migration_jobs', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(900)),
    safeRows(client, 'compliance_evidence', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'vault_audit_logs', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'qrng_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'scanner_agents', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'connector_accounts', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('*').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1800)),
    safeRows(client, 'security_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'vulnerabilities', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'audit_logs', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'scanner_agent_policies', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'qkms_keys', (q) => q.select('*').eq('tenant_id', userId).order('updated_at', { ascending: false }).limit(2400)),
    safeRows(client, 'qkms_policies', (q) => q.select('*').eq('tenant_id', userId).order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'qkms_rotation_jobs', (q) => q.select('*').eq('tenant_id', userId).order('created_at', { ascending: false }).limit(900)),
    safeRows(client, 'qkms_audit_events', (q) => q.select('*').eq('tenant_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'qkms_storage_backends', (q) => q.select('*').eq('tenant_id', userId).order('updated_at', { ascending: false }).limit(500)),
  ])

  const now = Date.now()
  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
  const assetName = (assetId: unknown, fallback = 'Unmapped asset') => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    return textValue(asset?.name, fallback)
  }
  const assetOwner = (assetId: unknown) => {
    const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
    const metadata = recordOf(asset?.metadata)
    return textValue(asset?.owner, textValue(metadata.owner, textValue(metadata.team, 'Unassigned')))
  }

  const rawKeyRecords: any[] = []
  const addKey = (input: any) => {
    const metadata = recordOf(input.metadata)
    const algorithm = textValue(input.algorithm, textValue(metadata.algorithm, 'Unknown'))
    const keySize = numberValue(input.keySize || input.bit_length || input.key_size || metadata.key_size)
    const fingerprint = textValue(input.fingerprint, textValue(metadata.fingerprint, textValue(metadata.fingerprint_sha256)))
    const status = textValue(input.status, textValue(metadata.status, 'observed'))
    const owner = textValue(input.owner, textValue(metadata.owner, textValue(metadata.team, assetOwner(input.assetId))))
    const sourceText = `${input.name || ''} ${algorithm} ${input.backend || ''} ${input.purpose || ''} ${input.environment || ''} ${JSON.stringify(metadata)}`
    const weak = Boolean(input.weak) || isWeakAlgorithm(sourceText, keySize)
    const pqcReady = Boolean(input.pqcReady || metadata.pqc_ready || metadata.quantum_safe || metadata.is_quantum_safe || isPqcAlgorithm(sourceText))
    const expiresAt = input.expiresAt || input.expires_at || metadata.expires_at || null
    const expired = expiresAt ? dateMs(expiresAt) < now : false
    const revoked = Boolean(input.revoked || input.revoked_at || /revoked|disabled|expired|compromised/i.test(status))
    const rotationRequired = Boolean(metadata.rotation_required || metadata.rotate || expired || revoked || weak || /rotate|required|expired|stale/i.test(status))
    const assetId = input.assetId || input.asset_id || metadata.asset_id || null
    const certificateId = input.certificateId || input.certificate_id || metadata.certificate_id || null
    const backend = inferStorageBackend(`${input.backend || input.storage_backend || ''} ${input.entropy_source || ''} ${sourceText}`)
    const keyType = textValue(input.keyType, textValue(input.key_type, textValue(metadata.key_type, inferKeyType(sourceText))))
    const environment = inferEnvironment(`${input.environment || input.environment_scope || metadata.environment || metadata.env || ''} ${sourceText}`)
    const purpose = textValue(input.purpose, textValue(metadata.purpose, isSignatureAlgorithm(sourceText) ? 'Digital signatures' : isKemAlgorithm(sourceText) ? 'Key establishment / encapsulation' : 'General protection'))
    const entropySource = inferEntropySource(`${input.entropy_source || input.entropySource || metadata.entropy_source || metadata.entropySource || backend}`)
    const exportable = Boolean(input.exportable ?? metadata.exportable ?? /exportable|outside approved vault/i.test(sourceText))
    const hsmBacked = Boolean(input.hsmBacked ?? input.hsm_backed ?? metadata.hsm_backed ?? metadata.hsmBacked ?? APPROVED_STORAGE_PATTERN.test(backend))
    const storageReference = textValue(input.storage_reference, textValue(input.storageReference, textValue(metadata.storage_reference, textValue(metadata.key_reference, fingerprint ? `${backend}:${fingerprint.slice(0, 12)}` : backend))))
    const lastRotatedAt = input.lastRotatedAt || input.last_rotated_at || metadata.last_rotated_at || metadata.rotated_at || input.rotated_at || input.updatedAt || input.updated_at || input.createdAt || input.created_at || null
    const linkedCertificates = (certificates || []).filter((cert: any) => {
      const certText = `${cert.algorithm || ''} ${cert.subject || ''} ${cert.issuer || ''} ${JSON.stringify(recordOf(cert.metadata))}`.toLowerCase()
      return (certificateId && cert.id === certificateId) || (assetId && cert.asset_id === assetId) || (algorithm && certText.includes(algorithm.toLowerCase()))
    })
    const runtimeMatches = (runtimeEvents || []).filter((event: any) => {
      const text = `${event.algorithm || ''} ${event.key_exchange_algorithm || ''} ${event.operation_type || ''} ${event.cipher_suite || ''} ${event.asset_id || ''}`.toLowerCase()
      return (assetId && event.asset_id === assetId) || (algorithm && text.includes(algorithm.toLowerCase()))
    })
    const migrationMatches = (migrationJobs || []).filter((job: any) => {
      const text = `${job.algorithm_from || ''} ${job.algorithm_to || ''} ${job.status || ''} ${JSON.stringify(recordOf(job.metadata))}`.toLowerCase()
      return (assetId && job.asset_id === assetId) || (algorithm && text.includes(algorithm.toLowerCase())) || (input.id && text.includes(String(input.id).toLowerCase()))
    })
    const rotationMatches = (qkmsRotationJobs || []).filter((job: any) => {
      return job.key_id === input.id || job.key_id === String(input.id || '').replace(/^(generated|inventory|certificate|qkms)-/, '')
    })
    const auditMatches = [
      ...(qkmsAuditEvents || []).filter((event: any) => event.key_id === input.id || event.key_id === String(input.id || '').replace(/^(generated|inventory|certificate|qkms)-/, '')),
      ...(auditLogs || []).filter((event: any) => {
        const text = JSON.stringify(event).toLowerCase()
        return (assetId && event.asset_id === assetId) || (algorithm && text.includes(algorithm.toLowerCase())) || (input.id && text.includes(String(input.id).toLowerCase()))
      }),
      ...(vaultAuditLogs || []).filter((event: any) => {
        const text = JSON.stringify(event).toLowerCase()
        return (assetId && event.asset_id === assetId) || (algorithm && text.includes(algorithm.toLowerCase())) || (input.id && text.includes(String(input.id).toLowerCase()))
      }),
    ].sort((a, b) => dateMs(rowTimestamp(b)) - dateMs(rowTimestamp(a)))
    const rotationStatus = rotationStatusFor({ status, expiresAt, rotationRequired, weak, lastRotatedAt })
    const nearExpiry = Boolean(expiresAt && dateMs(expiresAt) >= now && dateMs(expiresAt) - now <= EXPIRY_WARNING_MS)
    const pqcReadiness = pqcReadinessStatus(`${algorithm} ${purpose} ${status} ${sourceText}`, weak)
    const trustScore = clamp((pqcReady ? 38 : 0) + (!weak ? 22 : 0) + (!rotationRequired ? 16 : 0) + (runtimeMatches.length ? 6 : 0) + (!/unassigned/i.test(owner) ? 8 : 0) + (hsmBacked ? 10 : 0))
    const riskScore = clamp(100 - trustScore + (exportable ? 10 : 0) + (nearExpiry ? 8 : 0))
    const complianceStatus = complianceStatusFor({ owner, backend, weak, rotationRequired, auditEvents: auditMatches.length })
    const baseRecord = {
      id: input.id,
      source: input.source,
      name: textValue(input.name, algorithm || 'Key material'),
      keyAlias: textValue(input.key_alias, textValue(input.alias, textValue(input.name, algorithm || 'Key material'))),
      keyType,
      algorithm,
      keySize,
      fingerprint,
      status,
      owner,
      assetId,
      certificateId,
      assetName: assetName(assetId, textValue(input.assetName, 'Unmapped asset')),
      purpose,
      environment,
      backend,
      storageReference,
      entropySource,
      exportable,
      hsmBacked,
      quantumReady: pqcReady || /Quantum-Ready|Hybrid-Ready/.test(pqcReadiness),
      pqcReadiness,
      weak,
      orphaned: !assetId && /unassigned|unknown|none/i.test(owner),
      rotationRequired,
      rotationStatus,
      nearExpiry,
      expiresAt,
      createdAt: input.createdAt || input.created_at || null,
      lastRotatedAt,
      updatedAt: input.updatedAt || input.updated_at || input.createdAt || input.created_at || null,
      runtimeUsage: runtimeMatches.length,
      certificateLinks: linkedCertificates.length,
      linkedAssets: assetId ? [{ id: assetId, name: assetName(assetId), environment }] : [],
      linkedCertificates: linkedCertificates.slice(0, 8).map((cert: any) => ({
        id: cert.id,
        subject: textValue(cert.subject, textValue(cert.name, 'Certificate')),
        algorithm: textValue(cert.algorithm, 'Unknown'),
        expiresAt: cert.not_after || cert.expires_at || null,
        status: textValue(cert.status, cert.is_expiring_soon ? 'expiring' : 'observed'),
      })),
      linkedMigrationJobs: [...migrationMatches, ...rotationMatches].slice(0, 8).map((job: any) => ({
        id: job.id,
        status: textValue(job.status, 'pending'),
        reason: textValue(job.reason, textValue(recordOf(job.metadata).reason, textValue(job.algorithm_to, 'QKMS migration / rotation'))),
        updatedAt: rowTimestamp(job),
      })),
      runtimeEvents: runtimeMatches.slice(0, 10).map((event: any) => ({
        id: event.id,
        operation: textValue(event.operation_type, textValue(event.algorithm, textValue(event.key_exchange_algorithm, 'runtime usage'))),
        assetId: event.asset_id || null,
        observedAt: event.observed_at || event.created_at || null,
        risk: Boolean(event.is_legacy || event.downgrade_detected || event.shadow_crypto || event.hndl_risk),
      })),
      rotationHistory: [
        ...rotationMatches.map((job: any) => ({
          id: job.id,
          status: textValue(job.status, 'pending'),
          summary: textValue(job.reason, 'QKMS rotation job'),
          timestamp: job.completed_at || job.started_at || job.created_at,
        })),
        ...migrationMatches.map((job: any) => ({
          id: job.id,
          status: textValue(job.status, 'pending'),
          summary: `Migration ${job.algorithm_from || 'legacy'} to ${job.algorithm_to || 'target'}`,
          timestamp: job.completed_at || job.updated_at || job.created_at,
        })),
      ].sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp)).slice(0, 8),
      accessPolicy: {
        ownerRequired: true,
        hsmRequired: environment === 'production' || riskScore >= 50,
        exportAllowed: exportable,
        approvalRequired: environment === 'production' || riskScore >= 50,
      },
      auditTrail: auditMatches.slice(0, 10).map((event: any) => ({
        id: event.id,
        eventType: textValue(event.event_type, textValue(event.action, 'audit_event')),
        summary: textValue(event.event_summary, textValue(event.description, textValue(event.message, 'QKMS audit event'))),
        actor: textValue(event.actor_id, textValue(event.user_id, 'system')),
        createdAt: rowTimestamp(event),
      })),
      complianceStatus,
      riskScore,
      trustScore,
      riskExplanation: '',
      pqcExplanation: isKemAlgorithm(`${algorithm} ${purpose}`)
        ? 'ML-KEM is treated as key establishment / encapsulation readiness, including hybrid TLS shared-secret exchange.'
        : isSignatureAlgorithm(`${algorithm} ${purpose}`)
          ? 'ML-DSA and SLH-DSA are treated as digital-signature readiness for certificates, code signing, and assertions.'
          : isSymmetricAlgorithm(algorithm)
            ? 'AES-256-GCM is tracked as symmetric encryption readiness; symmetric keys still require custody and rotation evidence.'
            : isHashKdfAlgorithm(algorithm)
              ? 'SHA3 and HKDF-SHA3 are tracked as hash/KDF readiness.'
              : 'Classical or unknown key usage requires migration planning evidence before the gate can allow migration.',
      recommendedAction: '',
      metadata,
    }

    rawKeyRecords.push({
      ...baseRecord,
      riskExplanation: riskExplanationFor(baseRecord),
      recommendedAction: recommendedActionFor(baseRecord),
    })
  }

  for (const key of qkmsKeys || []) {
    addKey({
      id: `qkms-${key.id}`,
      source: 'qkms_keys',
      name: textValue(key.key_alias, textValue(key.id, 'QKMS key')),
      key_alias: key.key_alias,
      keyType: key.key_type,
      algorithm: key.algorithm,
      purpose: key.purpose,
      owner: key.owner_id,
      assetId: key.asset_id,
      certificateId: key.certificate_id,
      backend: key.storage_backend,
      storage_reference: key.storage_reference,
      environment: key.environment,
      status: key.status,
      pqcReady: /quantum|hybrid/i.test(String(key.pqc_readiness || '')),
      expiresAt: key.expires_at,
      lastRotatedAt: key.last_rotated_at,
      exportable: key.exportable,
      hsmBacked: key.hsm_backed,
      entropy_source: key.entropy_source,
      metadata: key.metadata_json,
      createdAt: key.created_at,
      updatedAt: key.updated_at,
    })
  }

  for (const key of generatedKeys || []) {
    const labelMetadata = recordOf(key.label)
    addKey({
      id: `generated-${key.id}`,
      source: 'generated_keys',
      name: textValue(labelMetadata.key_alias, textValue(labelMetadata.name, textValue(key.label, key.algorithm || 'Generated key'))),
      algorithm: key.algorithm,
      keySize: key.bit_length,
      fingerprint: key.fingerprint,
      entropy_source: key.entropy_source,
      status: key.status,
      expiresAt: key.expires_at,
      revoked: key.revoked_at,
      metadata: { ...labelMetadata, ...recordOf(key.metadata) },
      createdAt: key.created_at,
      updatedAt: key.updated_at,
    })
  }

  for (const item of cryptoInventory || []) {
    const text = `${item.item_type || ''} ${item.name || ''} ${item.algorithm || ''} ${item.protocol || ''} ${JSON.stringify(recordOf(item.metadata))}`
    if (!isKeyText(text)) continue
    addKey({
      id: `inventory-${item.id}`,
      source: 'crypto_inventory',
      name: textValue(item.name, textValue(item.item_type, 'Inventory key')),
      algorithm: item.algorithm,
      keySize: item.key_size,
      status: item.exposure_level || (item.is_vulnerable ? 'review' : 'observed'),
      assetId: item.asset_id,
      pqcReady: item.is_quantum_safe,
      weak: item.is_vulnerable,
      metadata: item.metadata,
      createdAt: item.created_at,
      updatedAt: item.discovered_at || item.created_at,
    })
  }

  for (const cert of certificates || []) {
    addKey({
      id: `certificate-${cert.id}`,
      source: 'certificates',
      name: textValue(cert.name, textValue(cert.subject, 'Certificate key')),
      algorithm: cert.algorithm,
      keySize: cert.key_size,
      status: cert.status || (cert.is_expiring_soon ? 'expiring' : 'observed'),
      assetId: cert.asset_id,
      purpose: 'Certificate signing or TLS',
      pqcReady: cert.is_quantum_safe,
      weak: cert.is_expiring_soon,
      expiresAt: cert.not_after,
      metadata: cert.metadata,
      createdAt: cert.created_at,
      updatedAt: cert.updated_at,
    })
  }

  const keyRecords = dedupeKeyRecords(rawKeyRecords)

  const keyTextRows = [
    ...withSource('crypto_exposures', cryptoExposures),
    ...withSource('scanner_alerts', scannerAlerts),
    ...withSource('security_events', securityEvents),
    ...withSource('vulnerabilities', vulnerabilities),
    ...withSource('pqc_scan_results', scanResults),
  ].filter((row: any) => isKeyText(JSON.stringify(row)))

  const weakAlgorithms = keyRecords.filter((key) => key.weak).length + keyTextRows.filter((row: any) => isWeakAlgorithm(JSON.stringify(row), numberValue(row.key_size))).length
  const policyViolations = keyTextRows.filter((row: any) => /policy|violation|weak|expired|rotation|orphan|exposure|leak|high|critical|fail/i.test(JSON.stringify(row))).length
  const orphanedKeys = keyRecords.filter((key) => key.orphaned).length
  const rotationRequired = keyRecords.filter((key) => key.rotationRequired).length
  const quantumReadyKeys = keyRecords.filter((key) => key.quantumReady).length
  const keysNearExpiry = keyRecords.filter((key) => key.nearExpiry).length
  const hsmProtectedKeys = keyRecords.filter((key) => key.hsmBacked).length
  const exportableProductionKeys = keyRecords.filter((key) => key.exportable && key.environment === 'production').length
  const keyPostureFindings = keyRecords.filter((key) => key.weak || key.orphaned || key.rotationRequired).length
  const findings = keyTextRows.length + keyPostureFindings
  const detections = cryptoExposures.length + scannerAlerts.length + securityEvents.length + vulnerabilities.length + scanResults.length
  const totalKeys = keyRecords.length
  const auditReadinessScore = totalKeys
    ? clamp(
      percentOf(complianceEvidence.length, totalKeys) * 0.35 +
      percentOf(vaultAuditLogs.length, totalKeys) * 0.35 +
      (policyViolations ? Math.max(0, 20 - policyViolations * 2) : 20) +
      (orphanedKeys ? Math.max(0, 10 - orphanedKeys) : 10),
    )
    : 0
  const pqcReadinessScore = percentOf(quantumReadyKeys, totalKeys)
  const gateStatus = weakAlgorithms || policyViolations > 2
    ? 'block'
    : rotationRequired || orphanedKeys || pqcReadinessScore < 75
      ? 'warn'
      : 'allow'

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
    vulnerabilities,
    auditLogs,
    complianceEvidence,
    migrationJobs,
  })

  const sourceHealthRows = [
    sourceHealth('Assets', 'assets', assets),
    sourceHealth('Generated Keys', 'generated_keys', generatedKeys),
    sourceHealth('Crypto Inventory', 'crypto_inventory', cryptoInventory),
    sourceHealth('Crypto Exposures', 'crypto_exposures', cryptoExposures),
    sourceHealth('Certificates', 'certificates', certificates),
    sourceHealth('Runtime Events', 'runtime_crypto_events', runtimeEvents),
    sourceHealth('Scanner Evidence', 'scanner_evidence', scannerEvidence),
    sourceHealth('Scanner Alerts', 'scanner_alerts', scannerAlerts),
    sourceHealth('Scan Sessions', 'pqc_scan_sessions', scanSessions),
    sourceHealth('Scan Results', 'pqc_scan_results', scanResults),
    sourceHealth('Migration Jobs', 'migration_jobs', migrationJobs),
    sourceHealth('Compliance Evidence', 'compliance_evidence', complianceEvidence),
    sourceHealth('Vault Audit Logs', 'vault_audit_logs', vaultAuditLogs),
    sourceHealth('QRNG Events', 'qrng_events', qrngEvents),
    sourceHealth('Scanner Agents', 'scanner_agents', scannerAgents),
    sourceHealth('Connectors', 'connector_accounts', connectorAccounts),
    sourceHealth('Agent Heartbeats', 'agent_heartbeats', agentHeartbeats),
    sourceHealth('Security Events', 'security_events', securityEvents),
    sourceHealth('Vulnerabilities', 'vulnerabilities', vulnerabilities),
    sourceHealth('Audit Logs', 'audit_logs', auditLogs),
    sourceHealth('Scanner Policies', 'scanner_agent_policies', scannerPolicies),
    sourceHealth('QKMS Keys', 'qkms_keys', qkmsKeys),
    sourceHealth('QKMS Policies', 'qkms_policies', qkmsPolicies),
    sourceHealth('QKMS Rotation Jobs', 'qkms_rotation_jobs', qkmsRotationJobs),
    sourceHealth('QKMS Audit Events', 'qkms_audit_events', qkmsAuditEvents),
    sourceHealth('QKMS Storage Backends', 'qkms_storage_backends', qkmsStorageBackends),
  ].sort((a, b) => dateMs(b.latestAt) - dateMs(a.latestAt) || b.count - a.count)
  const activeConnectorCount = connectorAccounts.filter((row: any) => /active|connected|healthy|synced|ok/i.test(String(row.status || ''))).length
  const liveSourceCount = sourceHealthRows.filter((row) => row.status === 'live').length
  const observedSourceCount = sourceHealthRows.filter((row) => row.count > 0).length
  const eventPipelineStatus = sync.runningScans
    ? 'scan_running'
    : liveSourceCount >= 3
      ? 'active'
      : observedSourceCount
        ? 'stale_or_partial'
        : scannerAgents.length || connectorAccounts.length
          ? 'waiting_for_key_events'
          : 'no_sources'

  const persistedPolicies = (qkmsPolicies || []).map((row: any) => ({
    id: `policy-${row.id}`,
    name: textValue(row.name, 'QKMS policy'),
    description: textValue(row.description, 'Tenant-specific QKMS policy'),
    status: row.enabled === false ? 'disabled' : 'configured',
    coverage: 100,
    violations: 0,
    owner: 'Tenant policy',
    allowedAlgorithms: row.allowed_algorithms || [],
    blockedAlgorithms: row.blocked_algorithms || [],
    maxKeyAgeDays: numberValue(row.max_key_age_days),
    rotationIntervalDays: numberValue(row.rotation_interval_days),
    requireOwner: row.require_owner !== false,
    requireHsm: Boolean(row.require_hsm),
    allowExport: Boolean(row.allow_export),
    environmentScope: textValue(row.environment_scope, 'all'),
    severity: textValue(row.severity, 'medium'),
    enabled: row.enabled !== false,
  }))

  const policyRows = [
    ...persistedPolicies,
    ...DEFAULT_POLICY_BLUEPRINTS.map((policy) => ({
      ...policy,
      coverage: policy.id === 'block-rsa-2048-new'
        ? percentOf(keyRecords.filter((key) => !/rsa-?2048/i.test(key.algorithm)).length, totalKeys)
        : policy.id === 'warn-long-lived-ec'
          ? percentOf(keyRecords.filter((key) => !/ecdsa|ecdh|p-?256/i.test(`${key.algorithm} ${key.purpose}`)).length, totalKeys)
          : percentOf(keyRecords.filter((key) => key.auditTrail?.length || !isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`)).length, totalKeys),
      violations: policy.id === 'block-rsa-2048-new'
        ? keyRecords.filter((key) => /rsa-?2048/i.test(key.algorithm)).length
        : policy.id === 'warn-long-lived-ec'
          ? keyRecords.filter((key) => /ecdsa|ecdh|p-?256/i.test(`${key.algorithm} ${key.purpose}`)).length
          : keyRecords.filter((key) => isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`) && !key.auditTrail?.length).length,
    })),
    {
      id: 'kem-readiness',
      name: 'ML-KEM key establishment',
      status: pqcReadinessScore >= 70 ? 'enforced' : totalKeys ? 'partial' : 'waiting',
      coverage: percentOf(keyRecords.filter((key) => isKemAlgorithm(`${key.algorithm} ${key.purpose}`) && key.quantumReady).length, Math.max(1, keyRecords.filter((key) => isKemAlgorithm(`${key.algorithm} ${key.purpose}`)).length)),
      violations: keyRecords.filter((key) => isKemAlgorithm(`${key.algorithm} ${key.purpose}`) && !key.quantumReady).length,
      owner: 'QKMS policy engine',
    },
    {
      id: 'signature-readiness',
      name: 'ML-DSA / SLH-DSA signatures',
      status: keyRecords.some((key) => isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`) && key.quantumReady) ? 'enforced' : totalKeys ? 'partial' : 'waiting',
      coverage: percentOf(keyRecords.filter((key) => isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`) && key.quantumReady).length, Math.max(1, keyRecords.filter((key) => isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`)).length)),
      violations: keyRecords.filter((key) => isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`) && !key.quantumReady).length,
      owner: 'Cryptographic authority',
    },
    {
      id: 'rotation-sla',
      name: 'Rotation and expiry automation',
      status: rotationRequired ? 'review' : totalKeys ? 'enforced' : 'waiting',
      coverage: percentOf(totalKeys - rotationRequired, totalKeys),
      violations: rotationRequired,
      owner: 'Key lifecycle service',
    },
    {
      id: 'custody-backend',
      name: 'HSM / KMS / Vault custody',
      status: keyRecords.some((key) => /hsm|kms|vault|key vault/i.test(key.backend)) ? 'enforced' : totalKeys ? 'partial' : 'waiting',
      coverage: percentOf(keyRecords.filter((key) => /hsm|kms|vault|key vault/i.test(key.backend)).length, totalKeys),
      violations: keyRecords.filter((key) => !/hsm|kms|vault|key vault/i.test(key.backend)).length,
      owner: 'QKMS storage control',
    },
    {
      id: 'qrng-entropy',
      name: 'QRNG entropy configuration',
      status: qrngEvents.length || keyRecords.some((key) => /qrng/i.test(`${key.backend} ${key.metadata?.entropy_source || ''}`)) ? 'enforced' : 'waiting',
      coverage: percentOf(qrngEvents.length + keyRecords.filter((key) => /qrng/i.test(`${key.backend} ${JSON.stringify(key.metadata)}`)).length, Math.max(1, totalKeys)),
      violations: qrngEvents.length ? 0 : Math.min(totalKeys, 1),
      owner: 'Entropy service',
    },
  ]

  const derivedStorageBackends = countBy(keyRecords, (key) => key.backend, 8).map((row) => ({
    ...row,
    provider: row.label,
    location: 'tenant default',
    protectionLevel: /hsm|kms|vault/i.test(row.label) ? 'hardware or managed custody' : 'software custody',
    exportable: keyRecords.some((key) => key.backend === row.label && key.exportable),
    hsmBacked: APPROVED_STORAGE_PATTERN.test(row.label),
    readiness: APPROVED_STORAGE_PATTERN.test(row.label) ? 'ready' : row.count ? 'review' : 'waiting',
    lastVerifiedAt: latestDate(...keyRecords.filter((key) => key.backend === row.label).map((key) => key.updatedAt || key.createdAt)),
    keys: row.count,
  }))

  const storageBackends = [
    ...(qkmsStorageBackends || []).map((row: any) => ({
      id: `storage-${row.id}`,
      label: textValue(row.name, textValue(row.provider, 'QKMS storage backend')),
      provider: textValue(row.provider, 'Local encrypted software vault'),
      location: textValue(row.location, 'tenant default'),
      protectionLevel: textValue(row.protection_level, row.hsm_backed ? 'HSM-backed' : 'software custody'),
      exportable: false,
      hsmBacked: Boolean(row.hsm_backed),
      readiness: textValue(row.status, 'configured'),
      status: textValue(row.status, 'configured'),
      lastVerifiedAt: row.last_verified_at || row.updated_at || row.created_at || null,
      keys: keyRecords.filter((key) => key.backend === row.provider || key.backend === row.name).length,
      count: keyRecords.filter((key) => key.backend === row.provider || key.backend === row.name).length,
      percent: 100,
    })),
    ...derivedStorageBackends,
  ].slice(0, 12)

  const rotationJobs = [
    ...(qkmsRotationJobs || [])
      .slice(0, 12)
      .map((job: any) => ({
        id: `qkms-job-${job.id}`,
        title: textValue(job.reason, 'QKMS rotation job'),
        status: textValue(job.status, 'pending'),
        owner: textValue(job.requested_by, 'QKMS operator'),
        priority: /blocked|failed|overdue/i.test(String(job.status || '')) ? 'high' : 'medium',
        dueAt: job.completed_at || job.started_at || job.created_at,
        evidence: recordOf(job.evidence_json),
      })),
    ...migrationJobs
      .filter((job: any) => isKeyText(`${job.algorithm_from || ''} ${job.algorithm_to || ''} ${job.status || ''} ${JSON.stringify(recordOf(job.metadata))}`))
      .slice(0, 12)
      .map((job: any) => ({
        id: `job-${job.id}`,
        title: textValue(recordOf(job.metadata).title, `Rotate ${job.algorithm_from || 'legacy'} to ${job.algorithm_to || 'target'}`),
        status: textValue(job.status, 'pending'),
        owner: assetOwner(job.asset_id),
        priority: textValue(job.priority, 'medium'),
        dueAt: job.completed_at || job.updated_at || job.created_at,
      })),
    ...keyRecords
      .filter((key) => key.rotationRequired)
      .slice(0, 12)
      .map((key) => ({
        id: `key-rotation-${key.id}`,
        title: `Rotate ${key.name}`,
        status: key.expiresAt && dateMs(key.expiresAt) < now ? 'expired' : 'required',
        owner: key.owner,
        priority: key.weak ? 'high' : 'medium',
        dueAt: key.expiresAt || key.updatedAt,
      })),
  ].slice(0, 16)

  const runtimeUsage = countBy(
    runtimeEvents.filter((event: any) => isKeyText(`${event.algorithm || ''} ${event.operation_type || ''} ${event.key_exchange_algorithm || ''} ${event.cipher_suite || ''}`)),
    (event: any) => titleCase(event.operation_type || event.algorithm || event.key_exchange_algorithm || 'Runtime key usage'),
    8,
  )

  const trustNodes = [
    ...keyRecords.slice(0, 22).map((key) => ({ id: key.id, label: key.name, type: 'key', status: key.quantumReady ? 'ready' : key.weak ? 'risk' : 'review' })),
    ...[...new Set(keyRecords.map((key) => key.assetName).filter(Boolean))].slice(0, 12).map((name) => ({ id: `asset-${name}`, label: name, type: 'asset', status: 'observed' })),
    ...storageBackends.slice(0, 6).map((backend) => ({ id: `backend-${backend.label}`, label: backend.label, type: 'backend', status: backend.readiness })),
  ]
  const trustEdges = keyRecords.slice(0, 28).flatMap((key) => [
    { from: key.id, to: `asset-${key.assetName}`, label: 'protects' },
    { from: key.id, to: `backend-${key.backend}`, label: 'stored in' },
  ])

  const readiness = {
    mlKem: percentOf(keyRecords.filter((key) => isKemAlgorithm(`${key.algorithm} ${key.purpose}`) && key.quantumReady).length, Math.max(1, keyRecords.filter((key) => isKemAlgorithm(`${key.algorithm} ${key.purpose}`)).length)),
    mlDsa: percentOf(keyRecords.filter((key) => isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`) && key.quantumReady).length, Math.max(1, keyRecords.filter((key) => isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`)).length)),
    symmetric: percentOf(keyRecords.filter((key) => isSymmetricAlgorithm(`${key.algorithm} ${key.purpose}`) && !key.weak).length, Math.max(1, keyRecords.filter((key) => isSymmetricAlgorithm(`${key.algorithm} ${key.purpose}`)).length)),
    hashKdf: percentOf(keyRecords.filter((key) => isHashKdfAlgorithm(`${key.algorithm} ${key.purpose}`) && !key.weak).length, Math.max(1, keyRecords.filter((key) => isHashKdfAlgorithm(`${key.algorithm} ${key.purpose}`)).length)),
    hybridTls: percentOf((certificates || []).filter((cert: any) => isPqcAlgorithm(`${cert.algorithm || ''} ${JSON.stringify(recordOf(cert.metadata))}`)).length + (runtimeEvents || []).filter((event: any) => /hybrid|pqc|ml-kem|kyber/i.test(`${event.cipher_suite || ''} ${event.key_exchange_algorithm || ''} ${event.algorithm || ''}`)).length, Math.max(1, certificates.length + runtimeEvents.length)),
    certificate: percentOf((certificates || []).filter((cert: any) => isSignatureAlgorithm(`${cert.algorithm || ''} ${JSON.stringify(recordOf(cert.metadata))}`) && isPqcAlgorithm(`${cert.algorithm || ''} ${JSON.stringify(recordOf(cert.metadata))}`)).length, Math.max(1, certificates.length)),
    migrationPrecheck: gateStatus === 'allow' ? 100 : gateStatus === 'warn' ? 62 : 28,
  }

  const runtimeMissingInventory = runtimeEvents.filter((event: any) => {
    const text = `${event.algorithm || ''} ${event.key_exchange_algorithm || ''} ${event.operation_type || ''} ${event.cipher_suite || ''}`.toLowerCase()
    if (!isKeyText(text)) return false
    return !keyRecords.some((key) => {
      return (event.asset_id && key.assetId === event.asset_id) || (key.algorithm && text.includes(String(key.algorithm).toLowerCase()))
    })
  }).length
  const noRotationHistory = keyRecords.filter((key) => !key.rotationHistory?.length && key.environment === 'production').length
  const unknownStorageBackends = keyRecords.filter((key) => !APPROVED_STORAGE_PATTERN.test(key.backend)).length
  const vendorUnknownReadiness = keyRecords.filter((key) => /vendor|managed|third.party/i.test(`${key.backend} ${JSON.stringify(key.metadata)}`) && /Unknown|Classical Only/.test(key.pqcReadiness)).length
  const signingPlanGaps = keyRecords.filter((key) => isSignatureAlgorithm(`${key.algorithm} ${key.purpose}`) && !/Quantum-Ready|Hybrid-Ready/.test(key.pqcReadiness)).length
  const establishmentPlanGaps = keyRecords.filter((key) => isKemAlgorithm(`${key.algorithm} ${key.purpose}`) && !/Quantum-Ready|Hybrid-Ready/.test(key.pqcReadiness)).length

  const prechecks = [
    { id: 'owners', label: 'No owner gaps', decision: orphanedKeys ? 'block' : 'allow', count: orphanedKeys },
    { id: 'storage-backend', label: 'Approved storage backend', decision: unknownStorageBackends ? 'block' : 'allow', count: unknownStorageBackends },
    { id: 'weak-algorithms', label: 'Deprecated algorithms outside critical path', decision: weakAlgorithms ? 'block' : 'allow', count: weakAlgorithms },
    { id: 'runtime-inventory', label: 'Runtime keys present in inventory', decision: runtimeMissingInventory ? 'block' : 'allow', count: runtimeMissingInventory },
    { id: 'rotation-history', label: 'Rotation history available', decision: noRotationHistory ? 'warn' : 'allow', count: noRotationHistory },
    { id: 'vendor-readiness', label: 'Vendor-managed readiness known', decision: vendorUnknownReadiness ? 'warn' : 'allow', count: vendorUnknownReadiness },
    { id: 'signing-plan', label: 'ML-DSA / SLH-DSA signing plan', decision: signingPlanGaps ? 'warn' : 'allow', count: signingPlanGaps },
    { id: 'kem-plan', label: 'ML-KEM / hybrid key establishment plan', decision: establishmentPlanGaps ? establishmentPlanGaps > 2 ? 'block' : 'warn' : 'allow', count: establishmentPlanGaps },
    { id: 'policy', label: 'Policy violations cleared', decision: policyViolations ? policyViolations > 2 ? 'block' : 'warn' : 'allow', count: policyViolations },
    { id: 'audit', label: 'Audit evidence ready', decision: auditReadinessScore >= 80 ? 'allow' : auditReadinessScore >= 50 ? 'warn' : 'block', count: complianceEvidence.length + vaultAuditLogs.length + qkmsAuditEvents.length },
  ]
  const migrationGateStatus = prechecks.some((row) => row.decision === 'block')
    ? 'block'
    : prechecks.some((row) => row.decision === 'warn')
      ? 'warn'
      : 'allow'
  readiness.migrationPrecheck = migrationGateStatus === 'allow' ? 100 : migrationGateStatus === 'warn' ? 62 : 28

  const auditEvidence = [
    ...qkmsAuditEvents.slice(0, 12).map((row: any) => ({
      id: `qkms-audit-${row.id}`,
      title: textValue(row.event_summary, titleCase(row.event_type, 'QKMS lifecycle event')),
      source: 'qkms_audit_events',
      status: textValue(row.event_type, 'recorded'),
      timestamp: row.created_at,
    })),
    ...complianceEvidence.slice(0, 10).map((row: any) => ({
      id: `compliance-${row.id}`,
      title: `${row.framework || 'Compliance'} ${row.control_id || ''}`.trim(),
      source: 'compliance_evidence',
      status: textValue(row.status, 'observed'),
      timestamp: row.updated_at || row.created_at,
    })),
    ...vaultAuditLogs.slice(0, 10).map((row: any) => ({
      id: `vault-${row.id}`,
      title: titleCase(row.event_type, 'Vault custody event'),
      source: 'vault_audit_logs',
      status: textValue(row.status, 'sealed'),
      timestamp: row.created_at,
    })),
  ].sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp)).slice(0, 14)

  const alerts = [
    ...keyRecords.filter((key) => key.weak || key.rotationRequired || key.orphaned).slice(0, 16).map((key) => ({
      id: `key-alert-${key.id}`,
      title: key.weak ? 'Weak key algorithm' : key.orphaned ? 'Owner mapping missing' : 'Rotation required',
      detail: `${key.name} - ${key.algorithm}`,
      severity: key.weak ? 'high' : 'medium',
      source: key.source,
      timestamp: key.updatedAt,
    })),
    ...keyTextRows.slice(0, 12).map((row: any, index: number) => ({
      id: `finding-${row.id || row.asset_id || index}`,
      title: titleCase(row.title || row.finding_type || row.event_type || row.category || 'QKMS finding'),
      detail: textValue(row.message, textValue(row.description, textValue(row.remediation, 'Key management finding'))),
      severity: textValue(row.severity, textValue(row.threat_level, 'medium')),
      source: textValue(row.sourceTable, 'telemetry'),
      timestamp: row.updated_at || row.created_at,
    })),
  ].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || dateMs(b.timestamp) - dateMs(a.timestamp)).slice(0, 20)

  const reports = [
    { id: 'key-inventory-export', title: 'Key inventory export', status: totalKeys ? 'ready' : 'waiting', records: totalKeys, formats: ['json', 'csv'] },
    { id: 'audit-evidence-export', title: 'QKMS audit evidence export', status: auditEvidence.length ? 'ready' : 'waiting', records: auditEvidence.length, formats: ['json', 'csv', 'pdf'] },
    { id: 'migration-gate-report', title: 'Migration gate decision report', status: migrationGateStatus, records: prechecks.length, formats: ['json', 'csv'] },
    { id: 'pqc-readiness-report', title: 'PQC readiness report', status: pqcReadinessScore >= 75 ? 'ready' : 'review', records: totalKeys, formats: ['json', 'csv', 'pdf'] },
    { id: 'rotation-report', title: 'Rotation and expiry report', status: rotationRequired ? 'review' : 'ready', records: rotationJobs.length, formats: ['json', 'csv'] },
    { id: 'hsm-protection-report', title: 'HSM/KMS protection report', status: hsmProtectedKeys === totalKeys && totalKeys ? 'ready' : 'review', records: hsmProtectedKeys, formats: ['json', 'csv'] },
  ]

  return {
    mode,
    generatedAt: new Date().toISOString(),
    latestActivityAt: latestDate(
      sync.latestDiscoveryAt,
      sync.latestScanAt,
      sync.latestAgentHeartbeatAt,
      ...keyRecords.map((key) => key.updatedAt || key.createdAt),
      ...auditEvidence.map((row) => row.timestamp),
    ),
    metrics: {
      totalKeys,
      quantumReadyKeys,
      orphanedKeys,
      weakAlgorithms,
      rotationRequired,
      policyViolations,
      keysNearExpiry,
      hsmProtectedKeys,
      exportableProductionKeys,
      findings,
      detections,
      auditEvidenceCount: auditEvidence.length,
      auditReadinessScore,
      migrationGateStatus,
      pqcReadinessScore,
      mlKemReadiness: readiness.mlKem,
      mlDsaReadiness: readiness.mlDsa,
      symmetricReadiness: readiness.symmetric,
      hashKdfReadiness: readiness.hashKdf,
      hybridTlsReadiness: readiness.hybridTls,
      certificateReadiness: readiness.certificate,
      migrationPrecheck: readiness.migrationPrecheck,
      activeBackends: storageBackends.length,
      runtimeUsages: runtimeUsage.reduce((sum, row) => sum + row.count, 0),
      complianceReports: reports.filter((row) => row.status === 'ready').length,
    },
    inventory: keyRecords.sort((a, b) => b.trustScore - a.trustScore || dateMs(b.updatedAt) - dateMs(a.updatedAt)).slice(0, 260),
    policies: policyRows,
    rotationJobs,
    storageBackends,
    qrng: {
      configured: qrngEvents.length > 0 || keyRecords.some((key) => /qrng/i.test(`${key.backend} ${JSON.stringify(key.metadata)}`)),
      events: qrngEvents.length,
      latestAt: latestDate(...qrngEvents.map((event: any) => event.created_at)),
      algorithms: countBy(qrngEvents, (event: any) => textValue(event.algorithm, 'Entropy event'), 6),
    },
    readiness,
    prechecks,
    decisions: prechecks,
    auditEvidence,
    reports,
    runtimeUsage,
    trustGraph: { nodes: trustNodes, edges: trustEdges },
    distributions: {
      algorithms: countBy(keyRecords, (key) => key.algorithm, 10),
      backends: storageBackends,
      owners: countBy(keyRecords, (key) => key.owner, 10),
      status: countBy(keyRecords, (key) => key.status, 8),
    },
    alerts,
    sourceHealth: sourceHealthRows,
    telemetry: {
      ...sync,
      assets: assets.length,
      generatedKeys: generatedKeys.length,
      cryptoInventory: cryptoInventory.length,
      cryptoExposures: cryptoExposures.length,
      certificates: certificates.length,
      runtimeEvents: runtimeEvents.length,
      scannerEvidence: scannerEvidence.length,
      scannerAlerts: scannerAlerts.length,
      scanSessions: sync.scanSessions,
      scanResults: scanResults.length,
      migrationJobs: migrationJobs.length,
      complianceEvidence: complianceEvidence.length,
      vaultAuditLogs: vaultAuditLogs.length,
      qrngEvents: qrngEvents.length,
      scannerAgents: scannerAgents.length,
      connectors: connectorAccounts.length,
      activeSources: liveSourceCount || sync.onlineAgents + activeConnectorCount,
      observedSources: observedSourceCount,
      securityEvents: securityEvents.length,
      vulnerabilities: vulnerabilities.length,
      auditLogs: auditLogs.length,
      scannerPolicies: scannerPolicies.length,
      eventPipelineStatus,
      latestRuntimeEventAt: latestDate(...runtimeEvents.map((event: any) => event.observed_at || event.created_at)),
    },
  }
}

function cleanKeyId(id: string) {
  return String(id || '').replace(/^(generated|inventory|certificate|qkms|key-rotation|qkms-job)-/, '')
}

async function snapshotForRequest(req: AuthedRequest, mode: QkmsMode = 'overview') {
  if (!req.user || !req.token) throw new Error('Authentication required')
  return buildQkmsSnapshot(mode, req.token, req.user.id)
}

function findSnapshotKey(snapshot: any, id: string) {
  const clean = cleanKeyId(id)
  return (snapshot.inventory || []).find((key: any) => key.id === id || cleanKeyId(key.id) === clean)
}

async function auditQkmsEvent(client: any, userId: string, keyId: string | null, eventType: string, summary: string, before: unknown = null, after: unknown = null) {
  const payload = {
    tenant_id: userId,
    user_id: userId,
    key_id: keyId ? cleanKeyId(keyId) : null,
    event_type: eventType,
    actor_id: userId,
    event_summary: summary,
    before_json: before || null,
    after_json: after || null,
  }

  const { error } = await client.from('qkms_audit_events').insert(payload)
  if (error && !isMissingTable(error)) console.warn('QKMS audit event persist failed:', error.message || error)
}

async function insertGeneratedMetadataKey(client: any, userId: string, body: Record<string, any>) {
  const label = JSON.stringify({
    key_alias: body.key_alias || body.alias || body.name || body.algorithm || 'QKMS key',
    key_type: body.key_type || body.keyType || inferKeyType(`${body.algorithm || ''} ${body.purpose || ''}`),
    purpose: body.purpose || 'General protection',
    owner: body.owner_id || body.owner || null,
    environment: body.environment || 'unknown',
    storage_backend: body.storage_backend || body.storageBackend || 'Application Key Store',
    storage_reference: body.storage_reference || body.storageReference || null,
    qkms_managed: true,
  })

  const { data, error } = await client
    .from('generated_keys')
    .insert({
      user_id: userId,
      algorithm: body.algorithm || 'ML-KEM-768',
      bit_length: numberValue(body.key_size || body.bit_length || body.bitLength, 256),
      entropy_source: body.entropy_source || body.entropySource || 'OS CSPRNG',
      quality_score: numberValue(body.quality_score || body.qualityScore, 0.99),
      status: body.status || 'active',
      expires_at: body.expires_at || body.expiresAt || null,
      label,
      metadata: {
        source: 'qkms_api',
        pqc_readiness: body.pqc_readiness || body.pqcReadiness || pqcReadinessStatus(String(body.algorithm || '')),
        exportable: Boolean(body.exportable),
        hsm_backed: Boolean(body.hsm_backed || body.hsmBacked),
      },
    })
    .select('id, created_at')
    .single()

  if (error) throw error
  return { id: `generated-${data.id}`, persistedTo: 'generated_keys', createdAt: data.created_at }
}

function exportPayload(snapshot: any, format: string) {
  const packagePayload = {
    generatedAt: new Date().toISOString(),
    metrics: snapshot.metrics,
    readiness: snapshot.readiness,
    prechecks: snapshot.prechecks,
    inventory: snapshot.inventory,
    policies: snapshot.policies,
    rotationJobs: snapshot.rotationJobs,
    auditEvidence: snapshot.auditEvidence,
    storageBackends: snapshot.storageBackends,
  }

  if (format === 'csv') {
    const header = ['id', 'alias', 'type', 'algorithm', 'purpose', 'owner', 'asset', 'environment', 'backend', 'expiresAt', 'rotationStatus', 'pqcReadiness', 'riskScore', 'complianceStatus']
    const rows = (snapshot.inventory || []).map((key: any) => [
      key.id,
      key.keyAlias || key.name,
      key.keyType,
      key.algorithm,
      key.purpose,
      key.owner,
      key.assetName,
      key.environment,
      key.backend,
      key.expiresAt,
      key.rotationStatus,
      key.pqcReadiness,
      key.riskScore,
      key.complianceStatus,
    ].map(csvEscape).join(','))
    return { contentType: 'text/csv; charset=utf-8', body: [header.join(','), ...rows].join('\n') }
  }

  return { contentType: 'application/json; charset=utf-8', body: JSON.stringify(packagePayload, null, 2) }
}

const router = Router()
router.use(requireAuth)

router.get('/overview', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await snapshotForRequest(req, 'overview')
    return res.json({ data })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_OVERVIEW_FAILED', message: error?.message || 'Failed to fetch QKMS overview' } })
  }
})

router.get('/keys', async (req: AuthedRequest, res: Response) => {
  try {
    const snapshot = await snapshotForRequest(req, 'inventory')
    return res.json({ data: snapshot.inventory, meta: { total: snapshot.inventory.length, generatedAt: snapshot.generatedAt } })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_KEYS_FAILED', message: error?.message || 'Failed to fetch QKMS keys' } })
  }
})

router.post('/keys', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    const body = req.body || {}
    if (hasBlockedSecretFields(body)) {
      return res.status(400).json({ error: { code: 'RAW_KEY_REJECTED', message: 'QKMS never accepts raw private keys or plaintext secret material through this API.' } })
    }

    const client = createAuthClient(req.token)
    if (!client) throw new Error('Database connection failed')

    const qkmsPayload = {
      tenant_id: req.user.id,
      user_id: req.user.id,
      key_alias: body.key_alias || body.alias || body.name || `${body.algorithm || 'ML-KEM-768'} key`,
      key_type: body.key_type || body.keyType || inferKeyType(`${body.algorithm || ''} ${body.purpose || ''}`),
      algorithm: body.algorithm || 'ML-KEM-768',
      purpose: body.purpose || 'General protection',
      owner_id: body.owner_id || body.owner || null,
      asset_id: body.asset_id || body.assetId || null,
      certificate_id: body.certificate_id || body.certificateId || null,
      storage_backend: body.storage_backend || body.storageBackend || 'Local encrypted software vault',
      storage_reference: body.storage_reference || body.storageReference || null,
      environment: body.environment || 'unknown',
      expires_at: body.expires_at || body.expiresAt || null,
      rotation_interval_days: numberValue(body.rotation_interval_days || body.rotationIntervalDays, 180),
      status: body.status || 'active',
      pqc_readiness: body.pqc_readiness || body.pqcReadiness || pqcReadinessStatus(String(body.algorithm || 'ML-KEM-768')),
      exportable: Boolean(body.exportable),
      hsm_backed: Boolean(body.hsm_backed || body.hsmBacked),
      entropy_source: body.entropy_source || body.entropySource || 'OS CSPRNG',
      metadata_json: { source: 'qkms_api', notes: body.notes || null },
    }

    const { data, error } = await client.from('qkms_keys').insert(qkmsPayload).select('id, created_at').single()
    if (error) {
      if (!isMissingTable(error)) throw error
      const fallback = await insertGeneratedMetadataKey(client, req.user.id, body)
      await auditQkmsEvent(client, req.user.id, fallback.id, 'key_created', `Created ${qkmsPayload.key_alias}`, null, qkmsPayload)
      return res.status(201).json({ data: fallback, meta: { qkmsTableConfigured: false } })
    }

    await auditQkmsEvent(client, req.user.id, data.id, 'key_created', `Created ${qkmsPayload.key_alias}`, null, qkmsPayload)
    return res.status(201).json({ data: { id: `qkms-${data.id}`, persistedTo: 'qkms_keys', createdAt: data.created_at }, meta: { qkmsTableConfigured: true } })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_KEY_CREATE_FAILED', message: error?.message || 'Failed to create QKMS key metadata' } })
  }
})

router.get('/keys/:id', async (req: AuthedRequest, res: Response) => {
  try {
    const snapshot = await snapshotForRequest(req, 'inventory')
    const key = findSnapshotKey(snapshot, req.params.id)
    if (!key) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'QKMS key not found' } })
    return res.json({ data: key })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_KEY_FAILED', message: error?.message || 'Failed to fetch QKMS key' } })
  }
})

router.post('/keys/:id/rotate', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    const client = createAuthClient(req.token)
    if (!client) throw new Error('Database connection failed')
    const keyId = cleanKeyId(req.params.id)
    const payload = {
      tenant_id: req.user.id,
      user_id: req.user.id,
      key_id: keyId,
      status: 'pending',
      reason: req.body?.reason || 'QKMS rotation requested',
      requested_by: req.user.id,
      evidence_json: { requested_from: 'qkms_dashboard', priority: req.body?.priority || 'medium' },
    }
    const { data, error } = await client.from('qkms_rotation_jobs').insert(payload).select('id, created_at').single()
    if (error && !isMissingTable(error)) throw error
    await auditQkmsEvent(client, req.user.id, keyId, 'rotation_requested', payload.reason, null, payload)
    return res.status(202).json({ data: { id: data?.id ? `qkms-job-${data.id}` : `rotation-${keyId}`, keyId, status: 'pending', persisted: Boolean(data?.id) } })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_ROTATE_FAILED', message: error?.message || 'Failed to create rotation job' } })
  }
})

router.post('/keys/:id/revoke', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    const client = createAuthClient(req.token)
    if (!client) throw new Error('Database connection failed')
    const rawId = req.params.id
    const keyId = cleanKeyId(rawId)
    const revokedAt = new Date().toISOString()
    if (rawId.startsWith('generated-')) {
      const { error } = await client.from('generated_keys').update({ status: 'revoked', revoked_at: revokedAt }).eq('id', keyId).eq('user_id', req.user.id)
      if (error && !isMissingTable(error)) throw error
    } else {
      const { error } = await client.from('qkms_keys').update({ status: 'revoked', updated_at: revokedAt }).eq('id', keyId).eq('tenant_id', req.user.id)
      if (error && !isMissingTable(error)) throw error
    }
    await auditQkmsEvent(client, req.user.id, keyId, 'key_revoked', req.body?.reason || 'QKMS key revoked', null, { revokedAt })
    return res.json({ data: { id: rawId, status: 'revoked', revokedAt } })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_REVOKE_FAILED', message: error?.message || 'Failed to revoke key' } })
  }
})

router.post('/keys/:id/assign-owner', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    const owner = String(req.body?.owner_id || req.body?.owner || '').trim()
    if (!owner) return res.status(400).json({ error: { code: 'OWNER_REQUIRED', message: 'owner_id or owner is required' } })
    const client = createAuthClient(req.token)
    if (!client) throw new Error('Database connection failed')
    const rawId = req.params.id
    const keyId = cleanKeyId(rawId)
    if (rawId.startsWith('generated-')) {
      const { data: existing } = await client.from('generated_keys').select('metadata').eq('id', keyId).eq('user_id', req.user.id).limit(1).maybeSingle()
      const metadata = { ...recordOf(existing?.metadata), owner, owner_assigned_at: new Date().toISOString() }
      const { error } = await client.from('generated_keys').update({ metadata }).eq('id', keyId).eq('user_id', req.user.id)
      if (error && !isMissingTable(error)) throw error
    } else {
      const { error } = await client.from('qkms_keys').update({ owner_id: owner, updated_at: new Date().toISOString() }).eq('id', keyId).eq('tenant_id', req.user.id)
      if (error && !isMissingTable(error)) throw error
    }
    await auditQkmsEvent(client, req.user.id, keyId, 'owner_assigned', `Assigned owner ${owner}`, null, { owner })
    return res.json({ data: { id: rawId, owner } })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_OWNER_FAILED', message: error?.message || 'Failed to assign owner' } })
  }
})

router.get('/policies', async (req: AuthedRequest, res: Response) => {
  const snapshot = await snapshotForRequest(req, 'governance')
  return res.json({ data: snapshot.policies, meta: { total: snapshot.policies.length } })
})

router.post('/policies', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    const client = createAuthClient(req.token)
    if (!client) throw new Error('Database connection failed')
    const body = req.body || {}
    const payload = {
      tenant_id: req.user.id,
      user_id: req.user.id,
      name: body.name || 'QKMS policy',
      description: body.description || null,
      allowed_algorithms: body.allowed_algorithms || body.allowedAlgorithms || ALLOWED_ALGORITHMS,
      blocked_algorithms: body.blocked_algorithms || body.blockedAlgorithms || ['RSA-2048', 'ECDSA P-256', '3DES', 'RC4'],
      max_key_age_days: numberValue(body.max_key_age_days || body.maxKeyAgeDays, 365),
      rotation_interval_days: numberValue(body.rotation_interval_days || body.rotationIntervalDays, 180),
      require_owner: body.require_owner ?? body.requireOwner ?? true,
      require_hsm: body.require_hsm ?? body.requireHsm ?? false,
      allow_export: body.allow_export ?? body.allowExport ?? false,
      environment_scope: body.environment_scope || body.environmentScope || 'all',
      severity: body.severity || 'medium',
      enabled: body.enabled ?? true,
    }
    const { data, error } = await client.from('qkms_policies').insert(payload).select('id, created_at').single()
    if (error && !isMissingTable(error)) throw error
    await auditQkmsEvent(client, req.user.id, null, 'policy_created', `Created policy ${payload.name}`, null, payload)
    return res.status(201).json({ data: { id: data?.id ? `policy-${data.id}` : `policy-${Date.now()}`, ...payload, persisted: Boolean(data?.id) } })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_POLICY_CREATE_FAILED', message: error?.message || 'Failed to create policy' } })
  }
})

router.put('/policies/:id', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    const client = createAuthClient(req.token)
    if (!client) throw new Error('Database connection failed')
    const policyId = cleanKeyId(req.params.id).replace(/^policy-/, '')
    const updates = { ...req.body, updated_at: new Date().toISOString() }
    const { error } = await client.from('qkms_policies').update(updates).eq('id', policyId).eq('tenant_id', req.user.id)
    if (error && !isMissingTable(error)) throw error
    await auditQkmsEvent(client, req.user.id, null, 'policy_updated', `Updated policy ${policyId}`, null, updates)
    return res.json({ data: { id: req.params.id, updated: true, persisted: !error } })
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_POLICY_UPDATE_FAILED', message: error?.message || 'Failed to update policy' } })
  }
})

router.get('/readiness', async (req: AuthedRequest, res: Response) => {
  const snapshot = await snapshotForRequest(req, 'readiness')
  return res.json({ data: snapshot })
})

router.post('/precheck', async (req: AuthedRequest, res: Response) => {
  const snapshot = await snapshotForRequest(req, 'readiness')
  return res.json({ data: { decision: snapshot.metrics.migrationGateStatus, prechecks: snapshot.prechecks, generatedAt: snapshot.generatedAt } })
})

router.get('/audit-evidence', async (req: AuthedRequest, res: Response) => {
  const snapshot = await snapshotForRequest(req, 'readiness')
  return res.json({ data: snapshot.auditEvidence, meta: { total: snapshot.auditEvidence.length, reports: snapshot.reports } })
})

router.post('/export', async (req: AuthedRequest, res: Response) => {
  try {
    const format = String(req.body?.format || req.query.format || 'json').toLowerCase()
    if (format === 'pdf') {
      const snapshot = await snapshotForRequest(req, 'readiness')
      return res.status(202).json({
        data: {
          format,
          status: 'queued',
          message: 'PDF renderer is not configured in this environment; JSON/CSV exports are available immediately.',
          records: snapshot.auditEvidence.length,
        },
      })
    }
    if (!['json', 'csv'].includes(format)) {
      return res.status(400).json({ error: { code: 'UNSUPPORTED_EXPORT', message: 'Supported export formats are json, csv, and pdf.' } })
    }
    const snapshot = await snapshotForRequest(req, 'readiness')
    const payload = exportPayload(snapshot, format)
    res.setHeader('Content-Type', payload.contentType)
    res.setHeader('Content-Disposition', `attachment; filename="qkms-export-${new Date().toISOString().slice(0, 10)}.${format}"`)
    return res.send(payload.body)
  } catch (error: any) {
    return res.status(500).json({ error: { code: 'QKMS_EXPORT_FAILED', message: error?.message || 'Failed to export QKMS evidence' } })
  }
})

router.get('/stream', async (req: AuthedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  sseHeaders(res)
  writeSse(res, 'qkms-connected', {
    timestamp: new Date().toISOString(),
    source: 'dashboard.qkms',
  })

  let closed = false
  const emitUpdate = () => {
    if (closed) return
    writeSse(res, 'qkms-update', {
      timestamp: new Date().toISOString(),
      source: 'dashboard.qkms',
      reason: 'tenant-qkms-sync',
    })
  }

  emitUpdate()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': qkms heartbeat\n\n')
  }, 25000)
  const syncPoll = setInterval(emitUpdate, 8000)

  req.on('close', () => {
    closed = true
    clearInterval(heartbeat)
    clearInterval(syncPoll)
  })
})

router.get('/:mode', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    }

    const mode = String(req.params.mode || 'overview') as QkmsMode
    if (!MODES.has(mode)) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'QKMS page not found' } })
    }

    const data = await buildQkmsSnapshot(mode, req.token, req.user.id)
    return res.json({ data })
  } catch (error: any) {
    console.error('QKMS dashboard error:', error)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || 'Failed to fetch QKMS dashboard data' } })
  }
})

export default router
