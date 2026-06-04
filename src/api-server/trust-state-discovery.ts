import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'

const router = Router()
const ONE_DAY_MS = 24 * 60 * 60 * 1000

type Severity = 'critical' | 'high' | 'medium' | 'low'
type GateState = 'ready' | 'review' | 'blocked'

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

type TrustFinding = {
  id: string
  source: string
  category: string
  severity: Severity
  title: string
  detail: string
  owner: string
  assetId: string | null
  assetName: string
  trustObject: string
  recommendation: string
  gateImpact: 'blocker' | 'review' | 'monitor'
  timestamp: string | null
  evidence: Record<string, unknown>
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

function boolValue(value: unknown) {
  return value === true || value === 'true' || value === 1 || value === '1'
}

function dateMs(value: unknown) {
  const ms = new Date(String(value || '')).getTime()
  return Number.isFinite(ms) ? ms : 0
}

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
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

function titleCase(value: unknown, fallback = 'Trust Event') {
  const text = String(value || fallback)
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return text.replace(/\b\w/g, (char) => char.toUpperCase()) || fallback
}

function firstString(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = textValue(record[key])
    if (value) return value
  }
  return ''
}

function normalizeSeverity(value: unknown): Severity {
  const lower = String(value || '').toLowerCase()
  if (lower === 'critical') return 'critical'
  if (lower === 'high' || lower === 'error' || lower === 'failed' || lower === 'blocked') return 'high'
  if (lower === 'medium' || lower === 'moderate' || lower === 'warning' || lower === 'review') return 'medium'
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
  if (score >= 70) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}

function isPqcAlgorithm(value: string) {
  return /ml[-_ ]?kem|ml[-_ ]?dsa|slh[-_ ]?dsa|sphincs|kyber|dilithium|falcon|fn[-_ ]?dsa|hqc|bike|ntru|hybrid|pqc|post.quantum/i.test(value)
}

function isLegacyAlgorithm(value: string, keySize = 0) {
  const text = `${value} ${keySize}`.toLowerCase()
  if (/sha-?1|md5|dsa|des|3des|rc4|rsa-?1024|rsa\s*1024/.test(text)) return true
  if (/rsa/.test(text) && (keySize === 0 || keySize < 3072)) return true
  if (/ec|ecc|ecdsa|ecdh|ed25519|x25519|prime256v1|secp256|p-256|p256|dh|dhe/.test(text)) return true
  return false
}

function isTrustText(value: string) {
  return /trust|certificate|cert|x509|x\.509|issuer|subject|serial|tls|ssl|sni|pem|pkcs|keystore|truststore|trust store|chain|root ca|intermediate|saml|oauth|oidc|jwt|jwks|mtls|m-tls|mutual tls|pki|ca\b|identity|federation/i.test(value)
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Trust-state discovery ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Trust-state discovery ${table} query failed:`, error?.message || error)
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

function vendorStatus(value: unknown) {
  const lower = String(value || '').toLowerCase()
  if (/ready|supported|complete|available/.test(lower)) return 'ready'
  if (/partial|hybrid|pilot|testing/.test(lower)) return 'partial'
  if (/planned|roadmap|committed/.test(lower)) return 'planned'
  if (/block|unsupported|reject|fail/.test(lower)) return 'blocked'
  return 'unknown'
}

function gateStateFor(blockers: number, reviews: number): GateState {
  if (blockers > 0) return 'blocked'
  if (reviews > 0) return 'review'
  return 'ready'
}

function gateLabel(state: GateState) {
  if (state === 'ready') return 'Ready'
  if (state === 'review') return 'Needs Review'
  return 'Blocked'
}

async function buildTrustStateSnapshot(token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
    assets,
    relationships,
    certificates,
    cryptoInventory,
    cryptoExposures,
    runtimeEvents,
    scannerEvidence,
    scannerAlerts,
    scanResults,
    vendors,
    migrationJobs,
    securityEvents,
    scannerAgents,
    connectors,
    heartbeats,
    persistedFindings,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'asset_relationships', (q) => q.select('id, source_asset_id, target_asset_id, relationship_type, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2200)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, serial_number, not_before, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2200)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(2600)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2200)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, certificate_fingerprint, package_name, package_version, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(5200)),
    safeRows(client, 'scanner_evidence', (q) => q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, certificate_fingerprint, file_path, package_name, package_version, confidence, raw_evidence, processed_at, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(3600)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2200)),
    safeRows(client, 'vendor_assessments', (q) => q.select('id, vendor_name, category, readiness_status, score, support, exposure_summary, contract_status, timeline, questionnaire_status, evidence, metadata, last_assessed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(900)),
    safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, priority, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, version, capabilities, last_seen_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, display_name, status, scopes, capabilities, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('id, agent_id, status, telemetry, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(1500)),
    safeRows(client, 'trust_state_findings', (q) => q.select('id, asset_id, category, severity, title, detail, gate_impact, status, owner, evidence, metadata, observed_at, resolved_at, created_at, updated_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(500)),
  ])

  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [String(asset.id), asset]))
  const getAsset = (assetId: unknown) => typeof assetId === 'string' ? assetMap.get(assetId) : null
  const assetName = (assetId: unknown, fallback = 'Unassigned trust object') => textValue(getAsset(assetId)?.name, fallback)
  const assetOwner = (assetId: unknown, fallback = 'Unassigned') => {
    const asset = getAsset(assetId)
    const metadata = recordOf(asset?.metadata)
    return textValue(asset?.service_owner, firstString(metadata, ['owner', 'serviceOwner', 'service_owner', 'application_owner']) || fallback)
  }

  const now = Date.now()
  const activeAssets = (assets || []).filter((asset: any) => !['archived', 'deleted', 'retired'].includes(String(asset.status || '').toLowerCase()))
  const ownedAssets = activeAssets.filter((asset: any) => {
    const metadata = recordOf(asset.metadata)
    return Boolean(textValue(asset.service_owner) || firstString(metadata, ['owner', 'serviceOwner', 'service_owner', 'application_owner']))
  })

  const trustRuntimeEvents = (runtimeEvents || []).filter((event: any) => {
    const metadata = recordOf(event.metadata)
    return isTrustText(`${event.event_type || ''} ${event.operation_type || ''} ${event.asset_name || ''} ${event.asset_type || ''} ${event.host || ''} ${event.protocol || ''} ${event.tls_version || ''} ${event.cipher_suite || ''} ${event.key_exchange_algorithm || ''} ${event.algorithm || ''} ${event.certificate_fingerprint || ''} ${event.package_name || ''} ${event.process_name || ''} ${JSON.stringify(metadata)}`)
  })
  const trustEvidence = (scannerEvidence || []).filter((row: any) => isTrustText(`${row.source_type || ''} ${row.evidence_type || ''} ${row.asset_name || ''} ${row.asset_type || ''} ${row.target || ''} ${row.host || ''} ${row.protocol || ''} ${row.observed_algorithm || ''} ${row.certificate_fingerprint || ''} ${row.package_name || ''} ${JSON.stringify(row.raw_evidence || {})}`))
  const trustAlerts = (scannerAlerts || []).filter((row: any) => isTrustText(`${row.category || ''} ${row.title || ''} ${row.message || ''} ${row.recommendation || ''} ${JSON.stringify(row.metadata || {})}`))
  const trustInventory = (cryptoInventory || []).filter((row: any) => {
    const metadata = recordOf(row.metadata)
    return isTrustText(`${row.item_type || ''} ${row.name || ''} ${row.algorithm || ''} ${row.protocol || ''} ${JSON.stringify(metadata)}`)
  })
  const trustExposures = (cryptoExposures || []).filter((row: any) => isTrustText(`${row.exposure_type || ''} ${row.description || ''} ${row.detected_value || ''} ${JSON.stringify(row.metadata || {})}`))
  const trustScanResults = (scanResults || []).filter((row: any) => isTrustText(`${row.finding_type || ''} ${row.algorithm || ''} ${row.description || ''} ${row.remediation || ''} ${JSON.stringify(row.metadata || {})}`))
  const trustSecurityEvents = (securityEvents || []).filter((row: any) => isTrustText(`${row.event_type || ''} ${row.message || ''} ${row.resource_name || ''} ${row.resource_type || ''} ${JSON.stringify(row.metadata || {})}`))

  const certificateFingerprints = new Set<string>()
  for (const cert of certificates || []) {
    const metadata = recordOf(cert.metadata)
    const fp = firstString(metadata, ['fingerprint', 'certificate_fingerprint', 'sha256', 'sha256_fingerprint', 'thumbprint'])
    if (fp) certificateFingerprints.add(fp.toLowerCase())
  }
  for (const row of trustEvidence || []) {
    const fp = textValue(row.certificate_fingerprint)
    if (fp) certificateFingerprints.add(fp.toLowerCase())
  }

  const findings: TrustFinding[] = []
  const seenFindings = new Set<string>()
  const addFinding = (finding: TrustFinding) => {
    const key = `${finding.category}:${finding.assetId || finding.assetName}:${finding.trustObject}:${finding.title}`
    if (seenFindings.has(key)) return
    seenFindings.add(key)
    findings.push(finding)
  }

  for (const cert of certificates || []) {
    const metadata = recordOf(cert.metadata)
    const issuer = textValue(cert.issuer, firstString(metadata, ['issuer', 'issuer_cn', 'ca', 'authority']) || 'Unknown issuer')
    const subject = textValue(cert.subject, firstString(metadata, ['subject', 'common_name', 'cn', 'domain']) || textValue(cert.name, 'Unknown certificate'))
    const algorithm = textValue(cert.algorithm, firstString(metadata, ['algorithm', 'signature_algorithm', 'public_key_algorithm']) || 'Unknown')
    const keySize = numberValue(cert.key_size, numberValue(metadata.key_size))
    const days = daysUntil(cert.not_after)
    const selfSigned = issuer && subject ? issuer.toLowerCase() === subject.toLowerCase() : boolValue(metadata.self_signed)
    const pqcReady = boolValue(cert.is_quantum_safe) || isPqcAlgorithm(algorithm)
    const weak = isLegacyAlgorithm(algorithm, keySize)
    const assetId = textValue(cert.asset_id) || null
    const owner = assetOwner(assetId)
    const base = {
      assetId,
      assetName: assetName(assetId, subject),
      owner,
      trustObject: subject,
      timestamp: latestDate(cert.updated_at, cert.created_at, cert.not_after),
      evidence: { sourceTable: 'certificates', certificateId: cert.id, issuer, algorithm, keySize, notAfter: cert.not_after },
    }

    if (!assetId) {
      addFinding({
        id: `certificate-owner-${cert.id}`,
        source: 'certificates',
        category: 'Ownership',
        severity: 'high',
        title: 'Certificate is not linked to an owned asset',
        detail: `${subject} is present in the trust estate but has no mapped asset owner.`,
        recommendation: 'Assign the certificate to an asset and service owner before migration sequencing.',
        gateImpact: 'blocker',
        ...base,
      })
    }

    if (!issuer || issuer === 'Unknown issuer' || selfSigned) {
      addFinding({
        id: `certificate-issuer-${cert.id}`,
        source: 'certificates',
        category: 'Visibility',
        severity: selfSigned ? 'high' : 'medium',
        title: selfSigned ? 'Self-signed trust path detected' : 'Certificate issuer is unknown',
        detail: `${subject} cannot be fully placed in a governed trust hierarchy.`,
        recommendation: 'Reconstruct the issuing CA path, root/intermediate chain, and trust-store consumers.',
        gateImpact: selfSigned ? 'blocker' : 'review',
        ...base,
      })
    }

    if (weak || !pqcReady) {
      addFinding({
        id: `certificate-algorithm-${cert.id}`,
        source: 'certificates',
        category: 'Risk',
        severity: weak ? 'high' : 'medium',
        title: weak ? 'Quantum-vulnerable certificate algorithm' : 'Certificate is not PQC-ready',
        detail: `${subject} uses ${algorithm}${keySize ? ` (${keySize} bit)` : ''}.`,
        recommendation: 'Plan certificate/signature migration separately from ML-KEM key-establishment rollout.',
        gateImpact: weak ? 'blocker' : 'review',
        ...base,
      })
    }

    if (days !== null && days <= 30) {
      addFinding({
        id: `certificate-expiry-${cert.id}`,
        source: 'certificates',
        category: 'Migration Gate',
        severity: days < 0 ? 'critical' : days <= 7 ? 'high' : 'medium',
        title: days < 0 ? 'Expired certificate in trust estate' : 'Certificate expires inside migration window',
        detail: `${subject} ${days < 0 ? 'expired' : `expires in ${days} days`}.`,
        recommendation: 'Renew or replace before migration cutover and validate all relying-party trust stores.',
        gateImpact: days <= 7 ? 'blocker' : 'review',
        ...base,
      })
    }
  }

  for (const asset of activeAssets) {
    const metadata = recordOf(asset.metadata)
    const owner = textValue(asset.service_owner, firstString(metadata, ['owner', 'serviceOwner', 'service_owner', 'application_owner']))
    if (!owner) {
      addFinding({
        id: `asset-owner-${asset.id}`,
        source: 'assets',
        category: 'Ownership',
        severity: 'medium',
        title: 'Asset owner is missing',
        detail: `${asset.name || 'Asset'} cannot pass migration gate without a service owner.`,
        owner: 'Unassigned',
        assetId: asset.id,
        assetName: textValue(asset.name, 'Unnamed asset'),
        trustObject: textValue(asset.type, 'Asset'),
        recommendation: 'Assign service owner and escalation contact before sequencing trust changes.',
        gateImpact: 'review',
        timestamp: latestDate(asset.updated_at, asset.created_at),
        evidence: { sourceTable: 'assets', assetId: asset.id, criticality: asset.criticality, environment: asset.environment },
      })
    }
  }

  const runtimeFingerprints: string[] = trustRuntimeEvents
    .map((event: any) => textValue(event.certificate_fingerprint))
    .filter((fingerprint: string): fingerprint is string => Boolean(fingerprint))
  const unmanagedRuntimeFingerprints = [...new Set(runtimeFingerprints.filter((fp) => !certificateFingerprints.has(fp.toLowerCase())))]
  for (const fp of unmanagedRuntimeFingerprints.slice(0, 20)) {
    const event = trustRuntimeEvents.find((row: any) => textValue(row.certificate_fingerprint).toLowerCase() === fp.toLowerCase())
    addFinding({
      id: `runtime-fingerprint-${fp}`,
      source: 'runtime_crypto_events',
      category: 'Visibility',
      severity: 'high',
      title: 'Runtime trust object is outside certificate inventory',
      detail: `${event?.asset_name || event?.host || 'Runtime endpoint'} presented certificate fingerprint ${fp.slice(0, 18)}... that is not mapped to inventory.`,
      owner: assetOwner(event?.asset_id),
      assetId: textValue(event?.asset_id) || null,
      assetName: assetName(event?.asset_id, textValue(event?.asset_name, textValue(event?.host, 'Runtime endpoint'))),
      trustObject: fp,
      recommendation: 'Promote the observed certificate into inventory, map issuer chain, and attach ownership.',
      gateImpact: 'blocker',
      timestamp: latestDate(event?.observed_at, event?.created_at),
      evidence: { sourceTable: 'runtime_crypto_events', eventId: event?.id, fingerprint: fp },
    })
  }

  for (const event of trustRuntimeEvents || []) {
    const score = numberValue(event.risk_score)
    const highRisk = boolValue(event.is_legacy) || boolValue(event.downgrade_detected) || boolValue(event.shadow_crypto) || boolValue(event.hndl_risk) || score >= 70 || severityRank(event.severity) >= 3
    if (!highRisk) continue
    const title = boolValue(event.shadow_crypto)
      ? 'Shadow trust usage detected at runtime'
      : boolValue(event.downgrade_detected)
        ? 'Trust negotiation downgrade detected'
        : boolValue(event.hndl_risk)
          ? 'HNDL-sensitive trust path detected'
          : 'High-risk runtime trust event'
    addFinding({
      id: `runtime-${event.id}`,
      source: 'runtime_crypto_events',
      category: 'Risk',
      severity: severityForScore(Math.max(score, severityRank(event.severity) * 24)),
      title,
      detail: `${event.asset_name || event.host || 'Runtime endpoint'} observed ${event.algorithm || event.key_exchange_algorithm || event.cipher_suite || event.protocol || 'trust telemetry'}.`,
      owner: assetOwner(event.asset_id),
      assetId: textValue(event.asset_id) || null,
      assetName: assetName(event.asset_id, textValue(event.asset_name, textValue(event.host, 'Runtime endpoint'))),
      trustObject: textValue(event.certificate_fingerprint, textValue(event.algorithm, textValue(event.key_exchange_algorithm, textValue(event.protocol, 'Runtime trust object')))),
      recommendation: 'Pause migration on this path until runtime downgrade, shadow crypto, or HNDL risk is remediated.',
      gateImpact: score >= 80 || boolValue(event.downgrade_detected) || boolValue(event.shadow_crypto) ? 'blocker' : 'review',
      timestamp: latestDate(event.observed_at, event.created_at),
      evidence: { sourceTable: 'runtime_crypto_events', eventId: event.id, riskScore: score, eventType: event.event_type },
    })
  }

  const missingRelationshipCoverage = activeAssets.length >= 3 && relationships.length === 0 && (certificates.length || trustRuntimeEvents.length || trustInventory.length)
  if (missingRelationshipCoverage) {
    addFinding({
      id: 'dependency-map-empty',
      source: 'asset_relationships',
      category: 'Dependencies',
      severity: 'high',
      title: 'No dependency graph for discovered trust estate',
      detail: 'Trust objects exist, but asset relationships are empty. Certificate replacement blast radius cannot be proven.',
      owner: 'Platform owner',
      assetId: null,
      assetName: 'Tenant trust estate',
      trustObject: 'Dependency graph',
      recommendation: 'Populate service, certificate, issuer, vendor, identity, and runtime dependency edges before migration cutover.',
      gateImpact: 'blocker',
      timestamp: latestDate(...(certificates || []).map((cert: any) => cert.updated_at || cert.created_at)),
      evidence: { sourceTable: 'asset_relationships', relationshipCount: relationships.length },
    })
  }

  for (const vendor of vendors || []) {
    const status = vendorStatus(`${vendor.readiness_status || ''} ${vendor.contract_status || ''} ${JSON.stringify(vendor.support || {})}`)
    const metadata = recordOf(vendor.metadata)
    const evidence = recordOf(vendor.evidence)
    const name = textValue(vendor.vendor_name, firstString(metadata, ['vendor', 'provider', 'issuer']) || 'Unknown vendor')
    if (status === 'ready') continue
    const severity: Severity = status === 'blocked' ? 'high' : status === 'unknown' ? 'medium' : 'low'
    addFinding({
      id: `vendor-${vendor.id}`,
      source: 'vendor_assessments',
      category: 'Dependencies',
      severity,
      title: status === 'blocked' ? 'Vendor blocks PQC trust migration' : 'Vendor PQC readiness is not verified',
      detail: `${name} readiness is ${vendor.readiness_status || 'unknown'} and contract status is ${vendor.contract_status || 'unconfirmed'}.`,
      owner: firstString(metadata, ['owner', 'account_owner', 'relationship_owner']) || 'Vendor owner',
      assetId: null,
      assetName: name,
      trustObject: textValue(vendor.category, 'Supplier trust dependency'),
      recommendation: 'Request vendor evidence for ML-KEM, ML-DSA/SLH-DSA, hybrid TLS, certificate size, and rollback support.',
      gateImpact: status === 'blocked' ? 'blocker' : 'review',
      timestamp: latestDate(vendor.last_assessed_at, vendor.updated_at, vendor.created_at),
      evidence: { sourceTable: 'vendor_assessments', vendorId: vendor.id, support: vendor.support, evidence },
    })
  }

  for (const alert of trustAlerts || []) {
    const closed = ['resolved', 'suppressed', 'closed'].includes(String(alert.status || '').toLowerCase())
    if (closed) continue
    addFinding({
      id: `scanner-alert-${alert.id}`,
      source: 'scanner_alerts',
      category: /owner|ownership/i.test(`${alert.title} ${alert.message}`) ? 'Ownership' : /depend|vendor|chain|issuer/i.test(`${alert.title} ${alert.message}`) ? 'Dependencies' : 'Risk',
      severity: normalizeSeverity(alert.severity),
      title: textValue(alert.title, 'Trust scanner alert'),
      detail: textValue(alert.message, textValue(alert.recommendation, 'Scanner reported trust-state risk')),
      owner: 'Scanner operator',
      assetId: null,
      assetName: 'Scanner evidence',
      trustObject: textValue(alert.category, 'Trust finding'),
      recommendation: textValue(alert.recommendation, 'Review scanner evidence and attach remediation ownership.'),
      gateImpact: severityRank(alert.severity) >= 3 ? 'blocker' : 'review',
      timestamp: latestDate(alert.updated_at, alert.created_at),
      evidence: { sourceTable: 'scanner_alerts', alertId: alert.id, metadata: recordOf(alert.metadata) },
    })
  }

  for (const row of persistedFindings || []) {
    if (['resolved', 'suppressed', 'closed'].includes(String(row.status || '').toLowerCase())) continue
    const metadata = recordOf(row.metadata)
    addFinding({
      id: `trust-state-finding-${row.id}`,
      source: 'trust_state_findings',
      category: titleCase(row.category, 'Migration Gate'),
      severity: normalizeSeverity(row.severity),
      title: textValue(row.title, 'Trust-state finding'),
      detail: textValue(row.detail, 'Operator-recorded trust-state finding'),
      owner: textValue(row.owner, firstString(metadata, ['owner', 'service_owner']) || 'Trust owner'),
      assetId: textValue(row.asset_id) || null,
      assetName: assetName(row.asset_id, textValue(metadata.asset_name, 'Operator finding')),
      trustObject: firstString(metadata, ['trust_object', 'certificate', 'issuer', 'vendor']) || titleCase(row.category),
      recommendation: firstString(metadata, ['recommendation', 'next_step']) || 'Resolve this operator-recorded trust finding before migration gate approval.',
      gateImpact: row.gate_impact === 'blocker' || row.gate_impact === 'review' || row.gate_impact === 'monitor' ? row.gate_impact : 'review',
      timestamp: latestDate(row.observed_at, row.updated_at, row.created_at),
      evidence: { sourceTable: 'trust_state_findings', findingId: row.id, evidence: recordOf(row.evidence) },
    })
  }

  const blockers = findings.filter((finding) => finding.gateImpact === 'blocker')
  const reviews = findings.filter((finding) => finding.gateImpact === 'review')
  const criticalFindings = findings.filter((finding) => finding.severity === 'critical' || finding.severity === 'high')
  const gateState = gateStateFor(blockers.length, reviews.length)
  const discoveredTrustObjects = certificates.length + trustInventory.length + trustRuntimeEvents.length + trustEvidence.length
  const trustLinkedAssets = new Set([
    ...(certificates || []).map((cert: any) => cert.asset_id).filter(Boolean),
    ...trustInventory.map((row: any) => row.asset_id).filter(Boolean),
    ...trustRuntimeEvents.map((event: any) => event.asset_id).filter(Boolean),
  ])
  const relationshipAssetCoverage = new Set([
    ...(relationships || []).map((rel: any) => rel.source_asset_id).filter(Boolean),
    ...(relationships || []).map((rel: any) => rel.target_asset_id).filter(Boolean),
  ])
  const activeJobs = (migrationJobs || []).filter((job: any) => !['completed', 'cancelled', 'failed'].includes(String(job.status || '').toLowerCase()))
  const migrationTouchedAssets = new Set(activeJobs.map((job: any) => job.asset_id).filter(Boolean))
  const blockedTouchedAssets = new Set(blockers.map((finding) => finding.assetId).filter(Boolean))
  const migrationConflicts = [...migrationTouchedAssets].filter((assetId) => blockedTouchedAssets.has(assetId as string)).length

  const visibilityScore = clamp(percentOf(discoveredTrustObjects, Math.max(1, activeAssets.length + certificates.length)) - percentOf(blockers.filter((finding) => finding.category === 'Visibility').length, Math.max(1, discoveredTrustObjects)) / 2)
  const ownershipScore = percentOf(ownedAssets.length + [...trustLinkedAssets].filter((assetId) => assetOwner(assetId, '')).length, Math.max(1, activeAssets.length + trustLinkedAssets.size))
  const dependencyScore = clamp(percentOf(relationshipAssetCoverage.size + vendors.length, Math.max(1, activeAssets.length + vendors.length)) - (missingRelationshipCoverage ? 35 : 0))
  const riskScore = clamp(criticalFindings.length * 10 + trustExposures.length * 4 + trustAlerts.length * 5 + migrationConflicts * 12)
  const gateReadiness = clamp((visibilityScore * 0.24) + (ownershipScore * 0.22) + (dependencyScore * 0.24) + ((100 - riskScore) * 0.3) - blockers.length * 4)

  const workflow = [
    {
      id: 'visibility',
      label: 'Visibility',
      status: gateStateFor(blockers.filter((finding) => finding.category === 'Visibility').length, reviews.filter((finding) => finding.category === 'Visibility').length),
      score: visibilityScore,
      count: discoveredTrustObjects,
      detail: `${discoveredTrustObjects} trust objects observed across inventory, certificates, scanner evidence, and runtime telemetry.`,
      source: 'certificates + crypto_inventory + scanner_evidence + runtime_crypto_events',
    },
    {
      id: 'ownership',
      label: 'Ownership',
      status: gateStateFor(blockers.filter((finding) => finding.category === 'Ownership').length, reviews.filter((finding) => finding.category === 'Ownership').length),
      score: ownershipScore,
      count: ownedAssets.length,
      detail: `${ownedAssets.length}/${activeAssets.length} active assets have service ownership.`,
      source: 'assets.service_owner',
    },
    {
      id: 'dependencies',
      label: 'Dependencies',
      status: gateStateFor(blockers.filter((finding) => finding.category === 'Dependencies').length, reviews.filter((finding) => finding.category === 'Dependencies').length),
      score: dependencyScore,
      count: relationships.length + vendors.length,
      detail: `${relationships.length} internal dependency edges and ${vendors.length} supplier readiness records are mapped.`,
      source: 'asset_relationships + vendor_assessments',
    },
    {
      id: 'risk',
      label: 'Risk',
      status: gateStateFor(blockers.filter((finding) => finding.category === 'Risk').length, reviews.filter((finding) => finding.category === 'Risk').length),
      score: clamp(100 - riskScore),
      count: criticalFindings.length,
      detail: `${criticalFindings.length} high-impact trust findings require disposition.`,
      source: 'runtime_crypto_events + scanner_alerts + crypto_exposures',
    },
    {
      id: 'migration-gate',
      label: 'Migration Gate',
      status: gateState,
      score: gateReadiness,
      count: blockers.length,
      detail: gateState === 'ready'
        ? 'Trust estate is ready for controlled migration sequencing.'
        : gateState === 'review'
          ? 'Review findings remain before approving migration sequencing.'
          : 'Blockers prevent safe PQC migration cutover.',
      source: 'derived trust-state policy',
    },
  ]

  const issuerCounts = new Map<string, { count: number; risk: number; pqc: number }>()
  for (const cert of certificates || []) {
    const metadata = recordOf(cert.metadata)
    const issuer = textValue(cert.issuer, firstString(metadata, ['issuer', 'issuer_cn', 'ca', 'authority']) || 'Unknown issuer')
    const algorithm = textValue(cert.algorithm, firstString(metadata, ['algorithm', 'signature_algorithm']) || '')
    const keySize = numberValue(cert.key_size, numberValue(metadata.key_size))
    const risk = isLegacyAlgorithm(algorithm, keySize) || issuer === 'Unknown issuer' ? 70 : isPqcAlgorithm(algorithm) || boolValue(cert.is_quantum_safe) ? 20 : 45
    const current = issuerCounts.get(issuer) || { count: 0, risk: 0, pqc: 0 }
    current.count += 1
    current.risk += risk
    if (isPqcAlgorithm(algorithm) || boolValue(cert.is_quantum_safe)) current.pqc += 1
    issuerCounts.set(issuer, current)
  }

  const trustRecords = [
    ...(certificates || []).map((cert: any) => {
      const metadata = recordOf(cert.metadata)
      const issuer = textValue(cert.issuer, firstString(metadata, ['issuer', 'issuer_cn', 'ca']) || 'Unknown issuer')
      const algorithm = textValue(cert.algorithm, firstString(metadata, ['algorithm', 'signature_algorithm']) || 'Unknown')
      const keySize = numberValue(cert.key_size)
      const pqcReady = boolValue(cert.is_quantum_safe) || isPqcAlgorithm(algorithm)
      const weak = isLegacyAlgorithm(algorithm, keySize)
      const assetId = textValue(cert.asset_id) || null
      const risk = clamp((weak ? 72 : pqcReady ? 18 : 44) + (issuer === 'Unknown issuer' ? 15 : 0) + (cert.is_expiring_soon ? 12 : 0))
      return {
        id: `certificate:${cert.id}`,
        kind: 'Certificate',
        name: textValue(cert.name, textValue(cert.subject, 'Certificate')),
        assetName: assetName(assetId, textValue(cert.subject, 'Unassigned certificate')),
        owner: assetOwner(assetId),
        issuer,
        algorithm,
        status: textValue(cert.status, 'active'),
        pqcReady,
        riskScore: risk,
        riskLevel: severityForScore(risk),
        gateImpact: findings.some((finding) => finding.assetId === assetId && finding.gateImpact === 'blocker') ? 'blocker' : risk >= 60 ? 'review' : 'monitor',
        lastSeen: latestDate(cert.updated_at, cert.created_at),
        source: 'certificates',
      }
    }),
    ...trustInventory.slice(0, 60).map((row: any) => {
      const metadata = recordOf(row.metadata)
      const algorithm = textValue(row.algorithm, firstString(metadata, ['algorithm']) || 'Unknown')
      const keySize = numberValue(row.key_size)
      const pqcReady = boolValue(row.is_quantum_safe) || isPqcAlgorithm(algorithm)
      const weak = boolValue(row.is_vulnerable) || isLegacyAlgorithm(algorithm, keySize)
      const risk = clamp((weak ? 68 : pqcReady ? 18 : 42) + severityRank(row.exposure_level) * 8)
      return {
        id: `inventory:${row.id}`,
        kind: titleCase(row.item_type, 'Inventory Trust Object'),
        name: textValue(row.name, textValue(row.protocol, 'Inventory trust object')),
        assetName: assetName(row.asset_id),
        owner: assetOwner(row.asset_id),
        issuer: firstString(metadata, ['issuer', 'ca', 'authority']) || 'Inventory',
        algorithm,
        status: boolValue(row.is_vulnerable) ? 'vulnerable' : 'observed',
        pqcReady,
        riskScore: risk,
        riskLevel: severityForScore(risk),
        gateImpact: risk >= 70 ? 'blocker' : risk >= 40 ? 'review' : 'monitor',
        lastSeen: latestDate(row.discovered_at, row.created_at),
        source: 'crypto_inventory',
      }
    }),
    ...trustRuntimeEvents.slice(0, 60).map((event: any) => {
      const algorithm = textValue(event.algorithm, textValue(event.key_exchange_algorithm, textValue(event.cipher_suite, textValue(event.protocol, 'Runtime trust object'))))
      const risk = clamp(Math.max(numberValue(event.risk_score), boolValue(event.downgrade_detected) || boolValue(event.shadow_crypto) ? 82 : boolValue(event.is_legacy) ? 68 : isPqcAlgorithm(algorithm) || boolValue(event.is_pqc) ? 18 : 38))
      return {
        id: `runtime:${event.id}`,
        kind: titleCase(event.event_type, 'Runtime Trust Event'),
        name: textValue(event.asset_name, textValue(event.host, 'Runtime endpoint')),
        assetName: assetName(event.asset_id, textValue(event.asset_name, textValue(event.host, 'Runtime endpoint'))),
        owner: assetOwner(event.asset_id),
        issuer: textValue(event.certificate_fingerprint, 'Runtime'),
        algorithm,
        status: boolValue(event.downgrade_detected) ? 'downgrade' : boolValue(event.shadow_crypto) ? 'shadow' : 'observed',
        pqcReady: boolValue(event.is_pqc) || isPqcAlgorithm(algorithm),
        riskScore: risk,
        riskLevel: severityForScore(risk),
        gateImpact: risk >= 75 ? 'blocker' : risk >= 45 ? 'review' : 'monitor',
        lastSeen: latestDate(event.observed_at, event.created_at),
        source: 'runtime_crypto_events',
      }
    }),
  ]
    .sort((a, b) => b.riskScore - a.riskScore || dateMs(b.lastSeen) - dateMs(a.lastSeen))
    .slice(0, 140)

  const selectedCertificates = (certificates || [])
    .map((cert: any) => {
      const metadata = recordOf(cert.metadata)
      const issuer = textValue(cert.issuer, firstString(metadata, ['issuer', 'issuer_cn', 'ca', 'authority']) || 'Unknown issuer')
      const algorithm = textValue(cert.algorithm, firstString(metadata, ['algorithm', 'signature_algorithm', 'public_key_algorithm']) || 'Unknown')
      const keySize = numberValue(cert.key_size, numberValue(metadata.key_size))
      const riskScore = clamp((isLegacyAlgorithm(algorithm, keySize) ? 72 : isPqcAlgorithm(algorithm) || boolValue(cert.is_quantum_safe) ? 18 : 44) + (issuer === 'Unknown issuer' ? 15 : 0) + (cert.is_expiring_soon ? 12 : 0))
      return { cert, metadata, issuer, algorithm, keySize, riskScore }
    })
    .sort((a: any, b: any) => b.riskScore - a.riskScore || dateMs(b.cert.updated_at || b.cert.created_at) - dateMs(a.cert.updated_at || a.cert.created_at))
    .slice(0, 10)

  const selectedRuntimeEvents = (trustRuntimeEvents || [])
    .map((event: any) => {
      const algorithm = textValue(event.algorithm, textValue(event.key_exchange_algorithm, textValue(event.cipher_suite, textValue(event.protocol, 'Runtime trust object'))))
      const riskScore = clamp(Math.max(numberValue(event.risk_score), boolValue(event.downgrade_detected) || boolValue(event.shadow_crypto) ? 82 : boolValue(event.is_legacy) ? 68 : isPqcAlgorithm(algorithm) || boolValue(event.is_pqc) ? 18 : 38))
      return { event, algorithm, riskScore }
    })
    .sort((a: any, b: any) => b.riskScore - a.riskScore || dateMs(b.event.observed_at || b.event.created_at) - dateMs(a.event.observed_at || a.event.created_at))
    .slice(0, 7)

  const graphAssetIds = new Set<string>([
    ...selectedCertificates.map(({ cert }: any) => cert.asset_id).filter(Boolean),
    ...selectedRuntimeEvents.map(({ event }: any) => event.asset_id).filter(Boolean),
    ...(relationships || []).slice(0, 18).flatMap((rel: any) => [rel.source_asset_id, rel.target_asset_id]).filter(Boolean),
    ...([...blockedTouchedAssets].filter(Boolean) as string[]),
  ])

  const assetNodes = activeAssets
    .filter((asset: any) => graphAssetIds.has(asset.id) || trustLinkedAssets.has(asset.id) || relationshipAssetCoverage.has(asset.id))
    .slice(0, 12)
    .map((asset: any, index: number) => ({
      id: `asset:${asset.id}`,
      label: textValue(asset.name, 'Asset'),
      type: textValue(asset.type, 'Asset'),
      x: 58 + (index % 4) * 8,
      y: 28 + Math.floor(index / 4) * 18,
      riskScore: clamp(findings.filter((finding) => finding.assetId === asset.id).reduce((sum, finding) => sum + severityRank(finding.severity) * 12, 0)),
      status: findings.some((finding) => finding.assetId === asset.id && finding.gateImpact === 'blocker') ? 'blocked' : 'mapped',
      detail: assetOwner(asset.id),
      source: 'assets',
    }))

  const issuerNodes = [...issuerCounts.entries()]
    .sort((a, b) => b[1].risk - a[1].risk || b[1].count - a[1].count)
    .slice(0, 7)
    .map(([issuer, value], index) => ({
      id: `issuer:${issuer}`,
      label: issuer,
      type: 'Issuer / CA',
      x: 12 + (index % 3) * 12,
      y: 18 + Math.floor(index / 3) * 20,
      riskScore: clamp(value.risk / Math.max(1, value.count)),
      status: issuer === 'Unknown issuer' ? 'blocked' : value.pqc === value.count ? 'ready' : 'review',
      detail: `${value.count} certificate${value.count === 1 ? '' : 's'}`,
      source: 'certificates',
    }))

  const certificateNodes = selectedCertificates.map(({ cert, issuer, algorithm, riskScore }: any, index: number) => ({
    id: `certificate:${cert.id}`,
    label: textValue(cert.subject, textValue(cert.name, 'Certificate')),
    type: 'Certificate / Trust Object',
    x: 35 + (index % 3) * 10,
    y: 22 + Math.floor(index / 3) * 16,
    riskScore,
    status: riskScore >= 75 || issuer === 'Unknown issuer' ? 'blocked' : riskScore >= 45 ? 'review' : 'ready',
    detail: `${issuer} - ${algorithm}`,
    source: 'certificates',
  }))

  const runtimeNodes = selectedRuntimeEvents.map(({ event, algorithm, riskScore }: any, index: number) => ({
    id: `runtime:${event.id}`,
    label: textValue(event.asset_name, textValue(event.host, 'Runtime trust event')),
    type: 'Runtime Trust Event',
    x: 44 + (index % 3) * 12,
    y: 70 + Math.floor(index / 3) * 12,
    riskScore,
    status: riskScore >= 75 ? 'blocked' : riskScore >= 45 ? 'review' : 'observed',
    detail: algorithm,
    source: 'runtime_crypto_events',
  }))

  const vendorNodes = (vendors || []).slice(0, 5).map((vendor: any, index: number) => {
    const status = vendorStatus(`${vendor.readiness_status || ''} ${vendor.contract_status || ''} ${JSON.stringify(vendor.support || {})}`)
    return {
      id: `vendor:${vendor.id}`,
      label: textValue(vendor.vendor_name, 'Vendor'),
      type: textValue(vendor.category, 'Vendor'),
      x: 82,
      y: 20 + index * 13,
      riskScore: status === 'ready' ? 18 : status === 'blocked' ? 86 : status === 'unknown' ? 58 : 36,
      status,
      detail: textValue(vendor.readiness_status, 'Unknown readiness'),
      source: 'vendor_assessments',
    }
  })

  const graphNodes = [...issuerNodes, ...certificateNodes, ...runtimeNodes, ...assetNodes, ...vendorNodes].slice(0, 36)
  const graphNodeIds = new Set(graphNodes.map((node) => node.id))
  const graphEdges = [
    ...selectedCertificates.flatMap(({ cert, issuer, riskScore }: any) => {
      const status = issuer === 'Unknown issuer' || riskScore >= 75 ? 'blocked' : riskScore >= 45 ? 'review' : 'ready'
      return [
        {
          id: `issuer-cert:${cert.id}`,
          from: `issuer:${issuer}`,
          to: `certificate:${cert.id}`,
          label: 'issues',
          status,
        },
        {
          id: `cert-asset:${cert.id}`,
          from: `certificate:${cert.id}`,
          to: `asset:${cert.asset_id}`,
          label: 'protects',
          status,
        },
      ]
    }),
    ...selectedRuntimeEvents.map(({ event, riskScore }: any) => ({
      id: `runtime-asset:${event.id}`,
      from: `runtime:${event.id}`,
      to: `asset:${event.asset_id}`,
      label: textValue(event.event_type, 'observed on'),
      status: riskScore >= 75 ? 'blocked' : riskScore >= 45 ? 'review' : 'ready',
    })),
    ...(relationships || []).slice(0, 24).map((rel: any) => ({
      id: `relationship:${rel.id}`,
      from: `asset:${rel.source_asset_id}`,
      to: `asset:${rel.target_asset_id}`,
      label: textValue(rel.relationship_type, 'depends on'),
      status: blockedTouchedAssets.has(rel.source_asset_id) || blockedTouchedAssets.has(rel.target_asset_id) ? 'blocked' : 'mapped',
    })),
    ...(vendors || []).slice(0, 5).flatMap((vendor: any) => {
      const metadata = recordOf(vendor.metadata)
      const linkedAssetIds = [
        firstString(metadata, ['asset_id', 'critical_asset_id', 'service_asset_id']),
        ...(Array.isArray(metadata.asset_ids) ? metadata.asset_ids.map((value) => textValue(value)).filter(Boolean) : []),
      ].filter(Boolean)
      const status = vendorStatus(`${vendor.readiness_status || ''} ${vendor.contract_status || ''} ${JSON.stringify(vendor.support || {})}`)
      return linkedAssetIds.map((assetId) => ({
        id: `vendor-asset:${vendor.id}:${assetId}`,
        from: `vendor:${vendor.id}`,
        to: `asset:${assetId}`,
        label: 'supports',
        status: status === 'blocked' ? 'blocked' : status === 'ready' ? 'ready' : 'review',
      }))
    }),
  ].filter((edge: any) => edge.to !== 'asset:null' && edge.to !== 'asset:undefined' && graphNodeIds.has(edge.from) && graphNodeIds.has(edge.to)).slice(0, 54)

  const actionLabels: Record<string, string> = {
    '/dashboard/assets': 'Open Assets & CBOM',
    '/dashboard/ecosystem-dependency-map': 'Open Dependency Map',
    '/dashboard/live-migration': 'Open Live Migration Ops',
    '/dashboard/pki-visibility': 'Open PKI Visibility',
    '/dashboard/runtime-crypto-intel': 'Open Runtime Crypto Intel',
    '/dashboard/scanner': 'Open PQC Scanner',
    '/dashboard/vendor-pqc-readiness': 'Open Vendor Readiness Center',
  }

  const blockerActionHref = (() => {
    const text = blockers.map((finding) => `${finding.category} ${finding.source} ${finding.title} ${finding.detail} ${finding.trustObject}`).join(' ').toLowerCase()
    if (/dependency|relationship|asset_relationship|trust chain|blast radius/.test(text)) return '/dashboard/ecosystem-dependency-map'
    if (/runtime|downgrade|shadow|hndl|telemetry|fingerprint/.test(text)) return '/dashboard/runtime-crypto-intel'
    if (/scanner|evidence|scan/.test(text)) return '/dashboard/scanner'
    if (/owner|ownership|unassigned|accountability/.test(text)) return '/dashboard/assets'
    if (/vendor|supplier|third-party|third party/.test(text)) return '/dashboard/vendor-pqc-readiness'
    if (/migration|rollback|cutover|job/.test(text)) return '/dashboard/live-migration'
    return '/dashboard/pki-visibility'
  })()

  const recommendations = [
    blockers.length > 0 && {
      id: 'resolve-blockers',
      title: 'Hold migration gate until trust blockers are cleared',
      detail: `${blockers.length} blocker${blockers.length === 1 ? '' : 's'} would make a PQC rollout unsafe.`,
      severity: 'critical',
      actionHref: blockerActionHref,
      actionLabel: actionLabels[blockerActionHref],
    },
    missingRelationshipCoverage && {
      id: 'build-dependency-graph',
      title: 'Build dependency map before certificate replacement',
      detail: 'Asset relationships are missing while trust objects already exist.',
      severity: 'high',
      actionHref: '/dashboard/ecosystem-dependency-map',
      actionLabel: actionLabels['/dashboard/ecosystem-dependency-map'],
    },
    unmanagedRuntimeFingerprints.length > 0 && {
      id: 'promote-runtime-trust',
      title: 'Promote runtime certificates into inventory',
      detail: `${unmanagedRuntimeFingerprints.length} runtime certificate fingerprint${unmanagedRuntimeFingerprints.length === 1 ? '' : 's'} are not inventoried.`,
      severity: 'high',
      actionHref: '/dashboard/pki-visibility',
      actionLabel: actionLabels['/dashboard/pki-visibility'],
    },
    vendors.some((vendor: any) => vendorStatus(`${vendor.readiness_status || ''} ${vendor.contract_status || ''}`) !== 'ready') && {
      id: 'verify-vendors',
      title: 'Verify supplier PQC support',
      detail: 'Supplier evidence must cover ML-KEM, signature migration, certificate size, API validation, and rollback support.',
      severity: 'medium',
      actionHref: '/dashboard/vendor-pqc-readiness',
      actionLabel: actionLabels['/dashboard/vendor-pqc-readiness'],
    },
    activeJobs.length > 0 && migrationConflicts > 0 && {
      id: 'pause-conflicting-jobs',
      title: 'Pause migration jobs touching blocked trust paths',
      detail: `${migrationConflicts} active migration job${migrationConflicts === 1 ? '' : 's'} overlap unresolved trust blockers.`,
      severity: 'high',
      actionHref: '/dashboard/live-migration',
      actionLabel: actionLabels['/dashboard/live-migration'],
    },
  ].filter(Boolean)

  const activity = [
    ...findings.slice(0, 30).map((finding) => ({
      id: finding.id,
      title: finding.title,
      detail: `${finding.category} - ${finding.assetName}`,
      severity: finding.severity,
      timestamp: finding.timestamp,
      source: finding.source,
    })),
    ...trustSecurityEvents.slice(0, 18).map((event: any) => ({
      id: `security:${event.id}`,
      title: titleCase(event.event_type, 'Trust security event'),
      detail: textValue(event.message, textValue(event.resource_name, 'Security event')),
      severity: normalizeSeverity(event.severity),
      timestamp: textValue(event.created_at) || null,
      source: 'security_events',
    })),
  ]
    .sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp))
    .slice(0, 16)

  const latestActivityAt = latestDate(
    ...trustRecords.map((record) => record.lastSeen),
    ...findings.map((finding) => finding.timestamp),
    ...heartbeats.map((heartbeat: any) => heartbeat.observed_at || heartbeat.created_at),
  )

  return {
    generatedAt: new Date().toISOString(),
    latestActivityAt,
    gate: {
      state: gateState,
      label: gateLabel(gateState),
      readiness: gateReadiness,
      blockers: blockers.length,
      reviews: reviews.length,
      migrationConflicts,
      decision: gateState === 'ready'
        ? 'Approved for controlled sequencing'
        : gateState === 'review'
          ? 'Review required before migration sequencing'
          : 'Migration gate blocked',
      rationale: gateState === 'ready'
        ? 'Visibility, ownership, dependencies, and runtime risk are within threshold.'
        : gateState === 'review'
          ? 'Non-blocking trust findings remain and need owner disposition.'
          : 'Trust blockers would create outage or hidden dependency risk during migration.',
    },
    metrics: {
      visibilityScore,
      ownershipScore,
      dependencyScore,
      riskScore,
      gateReadiness,
      activeAssets: activeAssets.length,
      discoveredTrustObjects,
      ownedAssets: ownedAssets.length,
      dependencyEdges: relationships.length,
      vendors: vendors.length,
      runtimeTrustEvents: trustRuntimeEvents.length,
      unknownRuntimeCertificates: unmanagedRuntimeFingerprints.length,
      highRiskFindings: criticalFindings.length,
      activeMigrationJobs: activeJobs.length,
      scannerAgents: scannerAgents.length,
      connectors: connectors.length,
    },
    workflow,
    graph: {
      nodes: graphNodes,
      edges: graphEdges,
    },
    trustRecords,
    findings: findings
      .sort((a, b) => {
        const gateRank = (value: string) => value === 'blocker' ? 3 : value === 'review' ? 2 : 1
        return gateRank(b.gateImpact) - gateRank(a.gateImpact) || severityRank(b.severity) - severityRank(a.severity) || dateMs(b.timestamp) - dateMs(a.timestamp)
      })
      .slice(0, 80),
    recommendations,
    activity,
    telemetry: {
      assets: assets.length,
      assetRelationships: relationships.length,
      certificates: certificates.length,
      cryptoInventory: cryptoInventory.length,
      cryptoExposures: trustExposures.length,
      runtimeCryptoEvents: trustRuntimeEvents.length,
      scannerEvidence: trustEvidence.length,
      scannerAlerts: trustAlerts.length,
      scanResults: trustScanResults.length,
      vendorAssessments: vendors.length,
      migrationJobs: migrationJobs.length,
      securityEvents: trustSecurityEvents.length,
      scannerAgents: scannerAgents.length,
      connectors: connectors.length,
      agentHeartbeats: heartbeats.length,
      persistedFindings: persistedFindings.length,
      eventPipelineStatus: trustRuntimeEvents.length || trustEvidence.length || trustAlerts.length
        ? 'active'
        : scannerAgents.length || connectors.length
          ? 'waiting_for_trust_events'
          : discoveredTrustObjects
            ? 'inventory_only'
            : 'no_agents',
      latestRuntimeEventAt: latestDate(...trustRuntimeEvents.map((event: any) => event.observed_at || event.created_at)),
    },
  }
}

router.get('/stream', async (req: AuthedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }

  sseHeaders(res)
  writeSse(res, 'trust-state-connected', {
    timestamp: new Date().toISOString(),
    source: 'dashboard.trust-state-discovery',
  })

  let closed = false
  const emitUpdate = () => {
    if (closed) return
    writeSse(res, 'trust-state-update', {
      timestamp: new Date().toISOString(),
      source: 'dashboard.trust-state-discovery',
      reason: 'tenant-trust-state-sync',
    })
  }

  emitUpdate()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': trust-state heartbeat\n\n')
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

    const data = await buildTrustStateSnapshot(req.token, req.user.id)
    return res.json({ data })
  } catch (error: any) {
    console.error('Trust-state discovery dashboard error:', error)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: error?.message || 'Failed to fetch trust-state discovery data' } })
  }
})

export default router
