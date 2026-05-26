import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'

type RiskLevel = 'Quantum Ready' | 'Hybrid Ready' | 'Migration Planned' | 'Unknown' | 'High Risk' | 'Critical Dependency'
type SupportStatus = 'Ready' | 'Partial' | 'Planned' | 'Unknown' | 'Blocked'
type ChainRisk = 'Critical' | 'High' | 'Medium' | 'Low'
type LabResult = 'Pass' | 'Warning' | 'Fail'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

type EvidenceSignal = {
  id: string
  sourceTable: string
  vendor: string
  category: string
  title: string
  algorithm: string
  keySize: number
  severity: ChainRisk
  vulnerable: boolean
  pqcReady: boolean
  contractGap: boolean
  tls: boolean
  api: boolean
  vpn: boolean
  device: boolean
  certificate: boolean
  jwt: boolean
  mlDsaRejected: boolean
  certSizeRisk: boolean
  timestamp: string | null
  detail: string
}

type VendorAggregate = {
  name: string
  category: string
  score: number
  readiness: RiskLevel
  support: Record<string, SupportStatus>
  exposure: string
  contract: string
  timeline: string
  evidenceCount: number
  vulnerableEvidence: number
  contractGaps: number
  lastSeen: string | null
  signals: EvidenceSignal[]
}

type EcosystemSnapshot = {
  generatedAt: string
  source: {
    mode: string
    latestActivityAt: string | null
    tables: Record<string, number>
  }
  metrics: {
    externalDependencies: number
    criticalTrustBreaks: number
    hybridReadyPercent: number
    contractGaps: number
    vulnerableVendors: number
    observedSignals: number
  }
  trustNodes: Array<{
    id: string
    name: string
    type: string
    risk: RiskLevel
    score: number
    x: number
    y: number
    details: string[]
  }>
  vendors: VendorAggregate[]
  chains: Array<{
    name: string
    path: string[]
    issue: string
    impact: string
    risk: ChainRisk
  }>
  labTests: Array<{
    name: string
    result: LabResult
    metric: string
    detail: string
  }>
  workflow: Array<{
    label: string
    status: 'Active' | 'Waiting' | 'Needs Review'
    detail: string
    count: number
  }>
}

const router = Router()

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

function latestIso(...values: unknown[]) {
  const newest = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)[0]
  return newest ? new Date(newest).toISOString() : null
}

function clamp(value: number, min = 0, max = 100) {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, Math.round(value)))
}

function percent(value: number, total: number) {
  return total > 0 ? clamp((value / total) * 100) : 0
}

function titleCase(value: unknown, fallback = 'External Dependency') {
  const text = String(value || fallback)
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return text.replace(/\b\w/g, (char) => char.toUpperCase()) || fallback
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'dependency'
}

function normalizeHost(value: unknown) {
  const text = textValue(value)
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
  return text || ''
}

function rootDomain(value: unknown) {
  const host = normalizeHost(value)
  if (!host) return ''
  const parts = host.split('.').filter(Boolean)
  if (parts.length <= 2) return host
  return parts.slice(-2).join('.')
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

function severityRank(value: unknown) {
  const lower = String(value || '').toLowerCase()
  if (lower === 'critical') return 4
  if (lower === 'high' || lower === 'error' || lower === 'failed') return 3
  if (lower === 'medium' || lower === 'moderate' || lower === 'warning') return 2
  if (lower === 'low' || lower === 'info') return 1
  return 0
}

function chainRisk(value: unknown): ChainRisk {
  const rank = severityRank(value)
  if (rank >= 4) return 'Critical'
  if (rank === 3) return 'High'
  if (rank === 2) return 'Medium'
  return 'Low'
}

function isPqcAlgorithm(value: string) {
  return /ml[-_ ]?kem|ml[-_ ]?dsa|kyber|dilithium|sphincs|slh[-_ ]?dsa|falcon|bike|hqc|ntru|hybrid|pqc|post[-_ ]?quantum/i.test(value)
}

function isWeakAlgorithm(value: string, keySize = 0) {
  const text = `${value} ${keySize}`.toLowerCase()
  if (/ssl|tls\s*1\.[01]|rc4|3des|des|cbc|sha-?1|md5|null|export|anon|rsa_with|static rsa|dsa/.test(text)) return true
  if (/\brsa\b/.test(text) && (keySize === 0 || keySize < 3072)) return true
  if (/ecdh|ecdsa|ecc|prime256v1|secp256|p-256|p256|secp384|p-384/.test(text)) return true
  if (/\bdh\b|diffie/.test(text) && keySize < 3072) return true
  return false
}

function inferCategory(text: string) {
  const lower = text.toLowerCase()
  if (/okta|auth0|azure ad|entra|saml|sso|identity|oauth|oidc|jwt|federation/.test(lower)) return 'Identity Federation'
  if (/vpn|ipsec|wireguard|fortinet|palo|juniper|cisco|network|gateway|edge/.test(lower)) return 'Network Edge'
  if (/api|webhook|sdk|gateway|partner|payment|stripe|twilio|sendgrid/.test(lower)) return 'API Trust Chain'
  if (/ca|pki|certificate|issuer|digicert|sectigo|lets encrypt|root|intermediate/.test(lower)) return 'PKI Dependency'
  if (/aws|azure|gcp|cloud|kms|vault|bucket|storage/.test(lower)) return 'Cloud Trust Path'
  if (/package|library|npm|pip|maven|nuget|sdk|dependency/.test(lower)) return 'Vendor SDK / Library'
  if (/device|appliance|printer|iot|firmware|endpoint/.test(lower)) return 'Device / Appliance'
  return 'External Dependency'
}

function vendorFromPackage(value: unknown) {
  const pkg = textValue(value)
  if (!pkg) return ''
  if (pkg.startsWith('@')) return pkg.split('/').slice(0, 2).join('/')
  return pkg.split('/')[0] || pkg
}

function inferVendorName(row: any, source: string, connectorMap: Map<string, any>) {
  const metadata = recordOf(row?.metadata)
  const raw = recordOf(row?.raw_evidence)
  const connectorId = textValue(row?.connector_account_id)
  const connector = connectorId ? connectorMap.get(connectorId) : null
  const connectorName = textValue(connector?.display_name) || textValue(connector?.provider)
  if (connectorName) return titleCase(connectorName)

  const direct = firstString(metadata, ['vendor', 'vendor_name', 'provider', 'supplier', 'third_party', 'issuer', 'package_vendor'])
  if (direct) return titleCase(direct)

  const rawDirect = firstString(raw, ['vendor', 'provider', 'issuer', 'organization'])
  if (rawDirect) return titleCase(rawDirect)

  const packageName = vendorFromPackage(row?.package_name || metadata.package_name || metadata.package)
  if (packageName) return packageName

  if (source === 'certificates') {
    const issuer = textValue(row?.issuer) || firstString(metadata, ['issuer', 'ca', 'root_ca'])
    if (issuer) return titleCase(issuer)
  }

  const host = rootDomain(row?.host || row?.target || metadata.host || metadata.domain || metadata.url)
  if (host) return host

  const assetName = textValue(row?.asset_name) || textValue(row?.name)
  if (/vendor|partner|api|sdk|cloud|vpn|sso|identity|ca|gateway/i.test(assetName)) return titleCase(assetName)

  return ''
}

function supportFromRecord(record: Record<string, unknown>, key: string): SupportStatus | null {
  const value = String(record[key] || record[key.toLowerCase()] || '').toLowerCase()
  if (!value) return null
  if (/ready|supported|yes|true/.test(value)) return 'Ready'
  if (/partial|hybrid|pilot/.test(value)) return 'Partial'
  if (/planned|roadmap|pending/.test(value)) return 'Planned'
  if (/blocked|no|false|unsupported/.test(value)) return 'Blocked'
  return 'Unknown'
}

function mergeSupport(current: SupportStatus, next: SupportStatus): SupportStatus {
  const rank: Record<SupportStatus, number> = { Ready: 5, Partial: 4, Planned: 3, Unknown: 2, Blocked: 1 }
  return rank[next] > rank[current] ? next : current
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Ecosystem supply-chain ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Ecosystem supply-chain ${table} query failed:`, error?.message || error)
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

function addSignal(signals: EvidenceSignal[], signal: EvidenceSignal) {
  if (!signal.vendor) return
  signals.push(signal)
}

function buildSignals(input: {
  connectorAccounts: any[]
  vendorAssessments: any[]
  runtimeEvents: any[]
  scannerEvidence: any[]
  scannerAlerts: any[]
  scanResults: any[]
  cryptoInventory: any[]
  cryptoExposures: any[]
  certificates: any[]
  complianceEvidence: any[]
}) {
  const connectorMap = new Map<string, any>((input.connectorAccounts || []).map((row: any) => [row.id, row]))
  const signals: EvidenceSignal[] = []

  for (const row of input.connectorAccounts || []) {
    const metadata = recordOf(row.metadata)
    const vendor = titleCase(textValue(row.display_name) || textValue(row.provider) || textValue(row.provider_account_id) || 'External Connector')
    const text = `${vendor} ${row.provider || ''} ${JSON.stringify(metadata)}`
    const hasPqc = /pqc|ml-kem|ml-dsa|hybrid/i.test(text)
    const contractGap = /no pqc|missing|not configured|not present|unknown/i.test(`${metadata.contract_status || ''} ${metadata.pqc_obligation || ''}`)
    addSignal(signals, {
      id: `connector-${row.id}`,
      sourceTable: 'connector_accounts',
      vendor,
      category: inferCategory(text),
      title: `${vendor} connector`,
      algorithm: textValue(metadata.algorithm) || textValue(metadata.crypto_algorithm),
      keySize: firstNumber(metadata, ['key_size', 'keySize']),
      severity: contractGap ? 'Medium' : 'Low',
      vulnerable: /legacy|rsa|ecc|ecdsa|ecdh|dh|dsa/i.test(text) && !hasPqc,
      pqcReady: hasPqc,
      contractGap,
      tls: /tls|https|certificate|mtls/i.test(text),
      api: /api|webhook|sdk|oauth|jwt/i.test(text),
      vpn: /vpn|ipsec|network/i.test(text),
      device: /device|agent|appliance/i.test(text),
      certificate: /cert|pki|ca/i.test(text),
      jwt: /jwt|saml|oauth|oidc/i.test(text),
      mlDsaRejected: /ml-dsa.*reject|reject.*ml-dsa/i.test(text),
      certSizeRisk: /certificate.*size|buffer|mtu|fragment/i.test(text),
      timestamp: latestIso(row.last_sync_at, row.updated_at, row.created_at),
      detail: `Connector status: ${textValue(row.status, 'unknown')}`,
    })
  }

  for (const row of input.vendorAssessments || []) {
    const metadata = recordOf(row.metadata)
    const support = recordOf(row.support || metadata.support)
    const vendor = titleCase(textValue(row.vendor_name) || textValue(row.name) || firstString(metadata, ['vendor', 'vendor_name']) || 'Vendor Assessment')
    const readinessText = `${row.readiness_status || row.status || metadata.readiness || ''}`
    const score = numberValue(row.score ?? metadata.score, 0)
    const vulnerable = /critical|high|blocked|unknown/i.test(readinessText) || score < 50
    addSignal(signals, {
      id: `vendor-assessment-${row.id || vendor}`,
      sourceTable: 'vendor_assessments',
      vendor,
      category: textValue(row.category) || firstString(metadata, ['category', 'vendor_type']) || inferCategory(`${vendor} ${JSON.stringify(metadata)}`),
      title: `${vendor} PQC assessment`,
      algorithm: firstString(metadata, ['algorithm', 'legacy_algorithm']),
      keySize: firstNumber(metadata, ['key_size', 'keySize']),
      severity: score > 0 && score < 40 ? 'Critical' : vulnerable ? 'High' : 'Low',
      vulnerable,
      pqcReady: /ready/i.test(readinessText) || Object.values(support).some((value) => /ready|supported/i.test(String(value))),
      contractGap: /missing|none|gap|absent|no/i.test(`${row.contract_status || metadata.contract_status || ''}`),
      tls: /tls|hybrid/i.test(JSON.stringify(support)),
      api: /api|sdk|jwt|webhook/i.test(`${row.category || ''} ${JSON.stringify(metadata)}`),
      vpn: /vpn|network/i.test(`${row.category || ''} ${JSON.stringify(metadata)}`),
      device: /device|appliance|firmware/i.test(`${row.category || ''} ${JSON.stringify(metadata)}`),
      certificate: /cert|pki|ca/i.test(JSON.stringify(support)),
      jwt: /jwt|saml|oidc|oauth/i.test(`${row.category || ''} ${JSON.stringify(metadata)}`),
      mlDsaRejected: /ml-dsa.*reject|reject.*ml-dsa|blocked/i.test(JSON.stringify(support)),
      certSizeRisk: /cert.*size|larger cert|buffer|mtu|fragment/i.test(JSON.stringify(metadata)),
      timestamp: latestIso(row.last_assessed_at, row.updated_at, row.created_at),
      detail: textValue(row.exposure_summary) || textValue(row.notes) || 'Vendor assessment evidence synchronized.',
    })
  }

  const scanLikeRows: Array<[string, any[]]> = [
    ['runtime_crypto_events', input.runtimeEvents],
    ['scanner_evidence', input.scannerEvidence],
    ['scanner_alerts', input.scannerAlerts],
    ['pqc_scan_results', input.scanResults],
    ['crypto_inventory', input.cryptoInventory],
    ['crypto_exposures', input.cryptoExposures],
    ['certificates', input.certificates],
    ['compliance_evidence', input.complianceEvidence],
  ]

  for (const [sourceTable, rows] of scanLikeRows) {
    for (const row of rows || []) {
      const metadata = recordOf(row.metadata)
      const raw = recordOf(row.raw_evidence)
      const vendor = inferVendorName(row, sourceTable, connectorMap)
      if (!vendor) continue

      const algorithm = textValue(row.algorithm)
        || textValue(row.observed_algorithm)
        || textValue(row.key_exchange_algorithm)
        || textValue(row.cipher_suite)
        || firstString(metadata, ['algorithm', 'observed_algorithm', 'key_exchange_algorithm', 'cipher_suite', 'signature_algorithm'])
        || firstString(raw, ['algorithm', 'observed_algorithm', 'cipher_suite'])
      const keySize = numberValue(row.key_size ?? row.keySize ?? metadata.key_size ?? metadata.keySize, 0)
      const text = [
        vendor,
        row.title,
        row.message,
        row.description,
        row.remediation,
        row.finding_type,
        row.exposure_type,
        row.evidence_type,
        row.source_type,
        row.asset_type,
        row.protocol,
        row.tls_version,
        row.host,
        row.package_name,
        algorithm,
        JSON.stringify(metadata),
        JSON.stringify(raw),
      ].filter(Boolean).join(' ')
      const pqcReady = Boolean(row.is_pqc || row.is_quantum_safe) || isPqcAlgorithm(text)
      const vulnerable = Boolean(row.is_legacy || row.downgrade_detected || row.hndl_risk || row.is_vulnerable) || isWeakAlgorithm(text, keySize)
      const severity = chainRisk(row.severity || row.threat_level || row.exposure_level || metadata.severity || (vulnerable ? 'high' : 'low'))
      const api = /api|gateway|webhook|jwt|oauth|oidc|saml|token|sdk|graphql|rest/i.test(text)
      const tls = /tls|ssl|https|cipher|handshake|mtls|certificate/i.test(text)
      const certificate = sourceTable === 'certificates' || /cert|pki|x509|issuer|root ca|intermediate/i.test(text)
      const vpn = /vpn|ipsec|wireguard|openvpn|network edge|gateway|mtu|fragment/i.test(text)
      const device = /device|appliance|printer|iot|firmware|endpoint|legacy client|browser|client/i.test(text)
      addSignal(signals, {
        id: `${sourceTable}-${row.id || signals.length}`,
        sourceTable,
        vendor,
        category: inferCategory(text),
        title: titleCase(row.title || row.finding_type || row.exposure_type || row.evidence_type || row.name || `${vendor} signal`),
        algorithm,
        keySize,
        severity,
        vulnerable,
        pqcReady,
        contractGap: /contract.*missing|no pqc obligation|obligation.*missing|pqc clause.*missing/i.test(text),
        tls,
        api,
        vpn,
        device,
        certificate,
        jwt: /jwt|jose|saml|oauth|oidc|signature/i.test(text),
        mlDsaRejected: /ml[-_ ]?dsa.*reject|reject.*ml[-_ ]?dsa|signature payload|jose.*reject/i.test(text),
        certSizeRisk: /cert.*size|larger cert|large certificate|buffer|mtu|fragment|handshake.*size|chain.*size/i.test(text),
        timestamp: latestIso(row.observed_at, row.processed_at, row.updated_at, row.created_at, row.discovered_at, row.not_after),
        detail: textValue(row.message) || textValue(row.description) || textValue(row.remediation) || textValue(metadata.detail) || `Observed through ${sourceTable.replace(/_/g, ' ')}`,
      })
    }
  }

  return signals
}

function buildSupport(signals: EvidenceSignal[]) {
  const support: Record<string, SupportStatus> = {
    'ML-KEM': 'Unknown',
    'ML-DSA': 'Unknown',
    'Hybrid TLS': 'Unknown',
    'PQC Certificates': 'Unknown',
    'Crypto Agility': 'Unknown',
  }

  for (const signal of signals) {
    const text = `${signal.title} ${signal.algorithm} ${signal.detail}`
    if (/ml[-_ ]?kem|kyber/i.test(text)) support['ML-KEM'] = mergeSupport(support['ML-KEM'], signal.pqcReady ? 'Ready' : 'Partial')
    if (/ml[-_ ]?dsa|dilithium|slh[-_ ]?dsa|sphincs/i.test(text)) support['ML-DSA'] = mergeSupport(support['ML-DSA'], signal.mlDsaRejected ? 'Blocked' : signal.pqcReady ? 'Ready' : 'Partial')
    if (signal.tls && /hybrid|pqc|ml[-_ ]?kem|kyber/i.test(text)) support['Hybrid TLS'] = mergeSupport(support['Hybrid TLS'], 'Partial')
    if (signal.certificate && signal.pqcReady) support['PQC Certificates'] = mergeSupport(support['PQC Certificates'], 'Ready')
    if (/crypto.?agility|policy|algorithm.*config|migration|orchestration|hybrid/i.test(text)) support['Crypto Agility'] = mergeSupport(support['Crypto Agility'], signal.vulnerable ? 'Planned' : 'Partial')
  }

  if (signals.some((signal) => signal.certificate && signal.vulnerable && !signal.pqcReady)) support['PQC Certificates'] = mergeSupport(support['PQC Certificates'], 'Blocked')
  if (signals.some((signal) => signal.mlDsaRejected)) support['ML-DSA'] = 'Blocked'
  if (signals.some((signal) => signal.tls && signal.vulnerable && !signal.pqcReady)) support['Hybrid TLS'] = mergeSupport(support['Hybrid TLS'], 'Planned')

  return support
}

function readinessFromScore(score: number, vulnerable: number, contractGaps: number, pqcReadySignals: number): RiskLevel {
  if (score >= 86 && pqcReadySignals > 0) return 'Quantum Ready'
  if (score >= 70 && pqcReadySignals > 0) return 'Hybrid Ready'
  if (score >= 55) return 'Migration Planned'
  if (vulnerable >= 3 || contractGaps >= 2 || score < 35) return 'Critical Dependency'
  if (vulnerable > 0 || score < 55) return 'High Risk'
  return 'Unknown'
}

function buildVendors(signals: EvidenceSignal[]) {
  const groups = new Map<string, EvidenceSignal[]>()
  for (const signal of signals) {
    const key = signal.vendor.toLowerCase()
    groups.set(key, [...(groups.get(key) || []), signal])
  }

  return [...groups.values()]
    .map<VendorAggregate>((items) => {
      const newest = items.map((item) => item.timestamp).filter(Boolean).sort((a, b) => dateMs(b) - dateMs(a))[0] || null
      const name = items[0]?.vendor || 'External Dependency'
      const categories = new Map<string, number>()
      const algorithms = new Set<string>()
      let vulnerable = 0
      let critical = 0
      let pqcReady = 0
      let contractGaps = 0

      for (const item of items) {
        categories.set(item.category, (categories.get(item.category) || 0) + 1)
        if (item.algorithm) algorithms.add(item.algorithm)
        if (item.vulnerable) vulnerable += 1
        if (item.severity === 'Critical' || item.severity === 'High') critical += 1
        if (item.pqcReady) pqcReady += 1
        if (item.contractGap) contractGaps += 1
      }

      const category = [...categories.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || 'External Dependency'
      const score = clamp(92 - vulnerable * 13 - critical * 9 - contractGaps * 10 + pqcReady * 6)
      const readiness = readinessFromScore(score, vulnerable, contractGaps, pqcReady)
      const algorithmList = [...algorithms].filter(Boolean).slice(0, 4).join(', ')
      const exposure = vulnerable
        ? `${vulnerable} quantum-vulnerable signal${vulnerable === 1 ? '' : 's'} observed${algorithmList ? `: ${algorithmList}` : ''}.`
        : pqcReady
          ? `${pqcReady} PQC or hybrid-ready signal${pqcReady === 1 ? '' : 's'} synchronized from live evidence.`
          : `${items.length} ecosystem signal${items.length === 1 ? '' : 's'} awaiting vendor PQC evidence.`
      const contract = contractGaps
        ? `${contractGaps} contract or obligation gap${contractGaps === 1 ? '' : 's'} detected in synchronized evidence.`
        : readiness === 'Unknown'
          ? 'No explicit PQC obligation evidence synchronized yet.'
          : 'No open PQC obligation gap detected from current evidence.'
      const timeline = readiness === 'Critical Dependency'
        ? 'Immediate vendor escalation required before PQC rollout.'
        : readiness === 'High Risk'
          ? 'Risk owner review recommended within the current migration window.'
          : readiness === 'Unknown'
            ? 'Awaiting questionnaire, roadmap, or connector evidence.'
            : 'Compatible with staged PQC migration controls.'

      return {
        name,
        category,
        readiness,
        score,
        support: buildSupport(items),
        exposure,
        contract,
        timeline,
        evidenceCount: items.length,
        vulnerableEvidence: vulnerable,
        contractGaps,
        lastSeen: newest,
        signals: items.sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp)).slice(0, 10),
      }
    })
    .sort((a, b) => a.score - b.score || b.evidenceCount - a.evidenceCount)
    .slice(0, 16)
}

function buildTrustNodes(vendors: VendorAggregate[], totalSignals: number) {
  const readyCount = vendors.filter((vendor) => vendor.readiness === 'Quantum Ready' || vendor.readiness === 'Hybrid Ready').length
  const tenantScore = vendors.length ? percent(readyCount, vendors.length) : 0
  const nodes = [{
    id: 'qguard',
    name: 'QGuard Helix Tenant',
    type: 'Control Plane',
    risk: (tenantScore >= 80 ? 'Quantum Ready' : tenantScore >= 50 ? 'Hybrid Ready' : 'Migration Planned') as RiskLevel,
    score: vendors.length ? tenantScore : 0,
    x: 50,
    y: 50,
    details: [
      `${totalSignals} synchronized supply-chain signal${totalSignals === 1 ? '' : 's'}`,
      `${vendors.length} external dependenc${vendors.length === 1 ? 'y' : 'ies'} correlated`,
      'Tenant-scoped CBOM, scanner, runtime, certificate, and connector evidence',
    ],
  }]

  const radiusX = 34
  const radiusY = 32
  vendors.slice(0, 10).forEach((vendor, index, arr) => {
    const angle = ((Math.PI * 2) / Math.max(arr.length, 1)) * index - Math.PI / 2
    nodes.push({
      id: slug(vendor.name),
      name: vendor.name,
      type: vendor.category,
      risk: vendor.readiness,
      score: vendor.score,
      x: clamp(50 + Math.cos(angle) * radiusX, 12, 88),
      y: clamp(50 + Math.sin(angle) * radiusY, 12, 88),
      details: [
        vendor.exposure,
        vendor.contract,
        `Evidence: ${vendor.evidenceCount} signal${vendor.evidenceCount === 1 ? '' : 's'} | Last seen: ${vendor.lastSeen ? new Date(vendor.lastSeen).toLocaleString('en-US') : 'awaiting evidence'}`,
      ],
    })
  })

  return nodes
}

function issueForVendor(vendor: VendorAggregate) {
  const signals = vendor.signals
  if (signals.some((signal) => signal.mlDsaRejected)) return 'API or JWT validation rejects ML-DSA signature payloads.'
  if (signals.some((signal) => signal.certSizeRisk)) return 'Certificate chain size or buffer tolerance may break under PQC certificates.'
  if (signals.some((signal) => signal.vpn)) return 'Network edge or VPN path may fail hybrid TLS handshakes or MTU tolerance.'
  if (signals.some((signal) => signal.certificate && signal.vulnerable)) return 'PKI dependency still relies on quantum-vulnerable certificate algorithms.'
  if (signals.some((signal) => signal.jwt || signal.api)) return 'API authentication or federation trust path requires PQC compatibility validation.'
  if (vendor.contractGaps > 0) return 'Vendor contract lacks synchronized PQC support obligations.'
  return 'Vendor PQC readiness evidence is incomplete for migration assurance.'
}

function pathForVendor(vendor: VendorAggregate) {
  if (/identity|federation/i.test(vendor.category)) return [vendor.name, 'SSO / Federation', 'QGuard Helix Trust Policy', 'Protected Application']
  if (/network|vpn|edge/i.test(vendor.category)) return [vendor.name, 'VPN / Network Edge', 'TLS Gateway', 'Privileged Access Flow']
  if (/api|sdk/i.test(vendor.category)) return [vendor.name, 'API Gateway / SDK', 'Signature Validator', 'Business Transaction']
  if (/pki|certificate/i.test(vendor.category)) return [vendor.name, 'Root / Intermediate CA', 'mTLS Trust Chain', 'Workload Identity']
  if (/cloud/i.test(vendor.category)) return [vendor.name, 'Cloud IAM / KMS', 'Service Identity', 'Production Workload']
  return [vendor.name, vendor.category, 'QGuard Helix Control Plane', 'Tenant Workload']
}

function riskForVendor(vendor: VendorAggregate): ChainRisk {
  if (vendor.readiness === 'Critical Dependency') return 'Critical'
  if (vendor.readiness === 'High Risk') return 'High'
  if (vendor.readiness === 'Unknown' || vendor.readiness === 'Migration Planned') return 'Medium'
  return 'Low'
}

function buildChains(vendors: VendorAggregate[]) {
  return vendors
    .filter((vendor) => vendor.vulnerableEvidence > 0 || vendor.contractGaps > 0 || vendor.readiness === 'Unknown')
    .slice(0, 8)
    .map((vendor) => ({
      name: `${vendor.name} Trust Path`,
      path: pathForVendor(vendor),
      issue: issueForVendor(vendor),
      impact: vendor.readiness === 'Critical Dependency'
        ? 'Cascading outage or rollback risk during post-quantum migration.'
        : vendor.readiness === 'High Risk'
          ? 'Operational interruption possible without vendor remediation evidence.'
          : 'Requires validation before the migration phase can be marked assured.',
      risk: riskForVendor(vendor),
    }))
}

function labResult(fail: number, warn: number): LabResult {
  if (fail > 0) return 'Fail'
  if (warn > 0) return 'Warning'
  return 'Pass'
}

function buildLabTests(signals: EvidenceSignal[], vendors: VendorAggregate[]) {
  const tlsSignals = signals.filter((signal) => signal.tls)
  const weakTls = tlsSignals.filter((signal) => signal.vulnerable && !signal.pqcReady)
  const hybridSignals = tlsSignals.filter((signal) => /hybrid|ml[-_ ]?kem|kyber|pqc/i.test(`${signal.algorithm} ${signal.detail}`))
  const certSignals = signals.filter((signal) => signal.certificate)
  const certSize = signals.filter((signal) => signal.certSizeRisk)
  const vpnSignals = signals.filter((signal) => signal.vpn)
  const apiSignals = signals.filter((signal) => signal.api || signal.jwt)
  const apiRejects = signals.filter((signal) => signal.mlDsaRejected || ((signal.api || signal.jwt) && signal.vulnerable && /ecdsa|rsa|jose|jwt|signature/i.test(`${signal.algorithm} ${signal.detail}`)))
  const deviceSignals = signals.filter((signal) => signal.device || signal.vpn || /device|appliance|firmware|legacy/i.test(`${signal.detail} ${signal.category}`))
  const readyVendors = vendors.filter((vendor) => vendor.readiness === 'Quantum Ready' || vendor.readiness === 'Hybrid Ready').length

  return [
    {
      name: 'Hybrid TLS handshake',
      result: tlsSignals.length ? labResult(0, weakTls.length) : 'Warning' as LabResult,
      metric: tlsSignals.length ? `${hybridSignals.length}/${tlsSignals.length} hybrid signals` : 'Awaiting TLS evidence',
      detail: tlsSignals.length
        ? `${weakTls.length} TLS trust path${weakTls.length === 1 ? '' : 's'} still require hybrid or PQC validation.`
        : 'Run scanner or collector TLS telemetry to model hybrid handshake readiness.',
    },
    {
      name: 'Certificate size impact',
      result: certSignals.length ? labResult(certSize.length, certSignals.filter((signal) => signal.vulnerable).length) : 'Warning' as LabResult,
      metric: certSignals.length ? `${certSignals.filter((signal) => signal.vulnerable).length} cert blockers` : 'Awaiting cert rows',
      detail: certSize.length
        ? `${certSize.length} certificate path${certSize.length === 1 ? '' : 's'} mention larger-chain, buffer, or fragmentation risk.`
        : 'Certificate telemetry is synchronized; no explicit size failure signal is currently active.',
    },
    {
      name: 'MTU fragmentation',
      result: vpnSignals.length ? labResult(vpnSignals.filter((signal) => signal.certSizeRisk).length, vpnSignals.filter((signal) => signal.vulnerable).length) : 'Warning' as LabResult,
      metric: vpnSignals.length ? `${vpnSignals.length} VPN/path signals` : 'Awaiting VPN data',
      detail: vpnSignals.length
        ? 'VPN, IPSec, or network-edge telemetry is included in hybrid rollout risk scoring.'
        : 'Deploy collector telemetry on VPN and edge paths to confirm MTU tolerance.',
    },
    {
      name: 'ML-DSA API signatures',
      result: apiSignals.length ? labResult(apiRejects.length, apiSignals.filter((signal) => signal.vulnerable).length) : 'Warning' as LabResult,
      metric: apiSignals.length ? `${apiRejects.length} API reject risks` : 'Awaiting API evidence',
      detail: apiRejects.length
        ? `${apiRejects.length} API, JWT, JOSE, or webhook path${apiRejects.length === 1 ? '' : 's'} need ML-DSA compatibility review.`
        : 'No ML-DSA signature rejection has been observed in current API evidence.',
    },
    {
      name: 'Client and browser compatibility',
      result: vendors.length ? labResult(0, vendors.length - readyVendors) : 'Warning' as LabResult,
      metric: vendors.length ? `${percent(readyVendors, vendors.length)}% vendor ready` : 'Awaiting vendors',
      detail: vendors.length
        ? 'Vendor readiness and connector evidence are used as compatibility coverage signals.'
        : 'Connect vendor accounts or import vendor assessments to populate compatibility coverage.',
    },
    {
      name: 'Legacy device tolerance',
      result: deviceSignals.length ? labResult(deviceSignals.filter((signal) => signal.vulnerable).length, 0) : 'Warning' as LabResult,
      metric: deviceSignals.length ? `${deviceSignals.filter((signal) => signal.vulnerable).length} device risks` : 'Awaiting device data',
      detail: deviceSignals.length
        ? 'Device, appliance, firmware, and edge-path signals are correlated from scanner and runtime telemetry.'
        : 'No device or appliance telemetry is synchronized yet.',
    },
  ]
}

function buildWorkflow(vendors: VendorAggregate[], signals: EvidenceSignal[]) {
  const unknown = vendors.filter((vendor) => vendor.readiness === 'Unknown').length
  const risky = vendors.filter((vendor) => vendor.readiness === 'Critical Dependency' || vendor.readiness === 'High Risk').length
  const contractGaps = vendors.reduce((sum, vendor) => sum + vendor.contractGaps, 0)
  return [
    {
      label: 'Vendor discovery synchronized',
      status: vendors.length ? 'Active' : 'Waiting',
      detail: `${vendors.length} external dependencies correlated from connectors, CBOM, scans, certificates, and runtime telemetry.`,
      count: vendors.length,
    },
    {
      label: 'Questionnaire and evidence requests',
      status: unknown || contractGaps ? 'Needs Review' : 'Active',
      detail: `${unknown + contractGaps} vendor evidence package${unknown + contractGaps === 1 ? '' : 's'} need questionnaire, roadmap, or contract data.`,
      count: unknown + contractGaps,
    },
    {
      label: 'Architecture review queue',
      status: risky ? 'Needs Review' : signals.length ? 'Active' : 'Waiting',
      detail: `${risky} high-risk vendor trust path${risky === 1 ? '' : 's'} require migration architecture review.`,
      count: risky,
    },
    {
      label: 'Compliance survey mapped',
      status: signals.some((signal) => signal.sourceTable === 'compliance_evidence') ? 'Active' : 'Waiting',
      detail: 'NIST-aligned supply-chain evidence is linked when compliance evidence rows are synchronized.',
      count: signals.filter((signal) => signal.sourceTable === 'compliance_evidence').length,
    },
  ] as EcosystemSnapshot['workflow']
}

async function buildSnapshot(token: string, userId: string): Promise<EcosystemSnapshot> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
    connectorAccounts,
    vendorAssessments,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanResults,
    cryptoInventory,
    cryptoExposures,
    certificates,
    complianceEvidence,
    assets,
    assetRelationships,
    migrationJobs,
    agentHeartbeats,
  ] = await Promise.all([
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, provider_account_id, display_name, status, scopes, capabilities, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'vendor_assessments', (q) => q.select('id, vendor_name, category, readiness_status, score, support, exposure_summary, contract_status, timeline, questionnaire_status, evidence, metadata, last_assessed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, package_name, package_version, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(5000)),
    safeRows(client, 'scanner_evidence', (q) => q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, package_name, package_version, confidence, raw_evidence, processed_at, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(3000)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2500)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(2500)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2200)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1800)),
    safeRows(client, 'compliance_evidence', (q) => q.select('id, asset_id, framework, control_id, status, evidence_type, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'asset_relationships', (q) => q.select('id, source_asset_id, target_asset_id, relationship_type, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, status, priority, algorithm_from, algorithm_to, metadata, created_at, updated_at, completed_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('id, agent_id, status, telemetry, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1600)),
  ])

  const signals = buildSignals({
    connectorAccounts,
    vendorAssessments,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanResults,
    cryptoInventory,
    cryptoExposures,
    certificates,
    complianceEvidence,
  })
  const vendors = buildVendors(signals)
  const chains = buildChains(vendors)
  const labTests = buildLabTests(signals, vendors)
  const contractGaps = vendors.reduce((sum, vendor) => sum + vendor.contractGaps, 0)
  const ready = vendors.filter((vendor) => vendor.readiness === 'Quantum Ready' || vendor.readiness === 'Hybrid Ready').length
  const latestActivityAt = latestIso(
    ...signals.map((signal) => signal.timestamp),
    ...migrationJobs.map((row: any) => row.updated_at || row.created_at),
    ...agentHeartbeats.map((row: any) => row.observed_at || row.created_at),
  )

  return {
    generatedAt: new Date().toISOString(),
    source: {
      mode: 'tenant-live-ecosystem',
      latestActivityAt,
      tables: {
        connector_accounts: connectorAccounts.length,
        vendor_assessments: vendorAssessments.length,
        runtime_crypto_events: runtimeEvents.length,
        scanner_evidence: scannerEvidence.length,
        scanner_alerts: scannerAlerts.length,
        pqc_scan_results: scanResults.length,
        crypto_inventory: cryptoInventory.length,
        crypto_exposures: cryptoExposures.length,
        certificates: certificates.length,
        compliance_evidence: complianceEvidence.length,
        assets: assets.length,
        asset_relationships: assetRelationships.length,
        migration_jobs: migrationJobs.length,
        agent_heartbeats: agentHeartbeats.length,
      },
    },
    metrics: {
      externalDependencies: vendors.length,
      criticalTrustBreaks: chains.filter((chain) => chain.risk === 'Critical' || chain.risk === 'High').length,
      hybridReadyPercent: percent(ready, vendors.length),
      contractGaps,
      vulnerableVendors: vendors.filter((vendor) => vendor.vulnerableEvidence > 0).length,
      observedSignals: signals.length,
    },
    trustNodes: buildTrustNodes(vendors, signals.length),
    vendors,
    chains,
    labTests,
    workflow: buildWorkflow(vendors, signals),
  }
}

router.use(requireAuth)

router.get('/stream', async (req: AuthedRequest, res: Response) => {
  if (!req.user || !req.token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  sseHeaders(res)
  writeSse(res, 'ecosystem-supply-chain-connected', {
    timestamp: new Date().toISOString(),
    source: 'dashboard.ecosystem-supply-chain',
  })

  let closed = false
  const emitSnapshot = async () => {
    if (closed || !req.user || !req.token) return
    try {
      const snapshot = await buildSnapshot(req.token, req.user.id)
      writeSse(res, 'ecosystem-supply-chain-update', snapshot)
    } catch (error: any) {
      writeSse(res, 'ecosystem-supply-chain-error', {
        message: error?.message || 'Ecosystem supply-chain stream failed',
        timestamp: new Date().toISOString(),
      })
    }
  }

  await emitSnapshot()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': ecosystem supply-chain heartbeat\n\n')
  }, 25000)
  const syncPoll = setInterval(() => {
    void emitSnapshot()
  }, 9000)

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

    const data = await buildSnapshot(req.token, req.user.id)
    return res.json({ data })
  } catch (error: any) {
    console.error('Ecosystem supply-chain dashboard error:', error)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || 'Failed to fetch ecosystem supply-chain data' } })
  }
})

export default router
