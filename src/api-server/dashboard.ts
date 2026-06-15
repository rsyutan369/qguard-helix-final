import { Router, Request, Response } from 'express'
import { getToken, getServerUser, getServiceClient, createAuthClient } from '@/lib/supabase-server'

const router = Router()

/**
 * Middleware: require authentication on all dashboard routes.
 */
async function requireAuth(req: Request, res: Response, next: Function) {
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

function setSseHeaders(res: Response) {
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

router.use(requireAuth)

function openDashboardSyncStream(req: Request, res: Response, eventBase: string, source: string, reason: string) {
  setSseHeaders(res)
  writeSse(res, `${eventBase}-connected`, {
    timestamp: new Date().toISOString(),
    source,
  })

  let closed = false
  const emitUpdate = () => {
    if (closed) return
    writeSse(res, `${eventBase}-update`, {
      timestamp: new Date().toISOString(),
      source,
      reason,
    })
  }

  emitUpdate()
  const heartbeat = setInterval(() => {
    if (!closed) res.write(`: ${eventBase} heartbeat\n\n`)
  }, 25000)
  const syncPoll = setInterval(emitUpdate, 8000)

  req.on('close', () => {
    closed = true
    clearInterval(heartbeat)
    clearInterval(syncPoll)
  })
}

function isMissingRpc(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return text.includes('42883') || text.includes('pgrst202') || text.includes('could not find the function') || text.includes('does not exist')
}

function isMissingTable(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return text.includes('42p01') || text.includes('pgrst205') || text.includes('does not exist') || text.includes('could not find the table')
}

async function safeCount(client: any, table: string, userId: string, apply?: (query: any) => any) {
  try {
    let query = client.from(table).select('id', { count: 'exact', head: true }).eq('user_id', userId)
    if (apply) query = apply(query)
    const { count, error } = await query
    if (error) return 0
    return count || 0
  } catch {
    return 0
  }
}

async function safeLatestScanAt(client: any, userId: string) {
  try {
    const { data, error } = await client
      .from('pqc_scan_sessions')
      .select('completed_at, started_at, created_at')
      .eq('user_id', userId)
      .eq('status', 'completed')
      .order('completed_at', { ascending: false })
      .limit(1)
    if (error || !data?.length) return null
    return data[0].completed_at || data[0].started_at || data[0].created_at || null
  } catch {
    return null
  }
}

async function getMigrationProgress(client: any, userId: string) {
  try {
    const [completed, active, failed, total] = await Promise.all([
      safeCount(client, 'migration_jobs', userId, (q) => q.eq('status', 'completed')),
      safeCount(client, 'migration_jobs', userId, (q) => q.in('status', ['pending', 'queued', 'running', 'in_progress', 'paused'])),
      safeCount(client, 'migration_jobs', userId, (q) => q.eq('status', 'failed')),
      safeCount(client, 'migration_jobs', userId),
    ])

    return {
      completedMigrations: completed,
      activeMigrations: active,
      failedMigrations: failed,
      migrationCompletionRate: total ? Math.round((completed / total) * 100) : 0,
    }
  } catch {
    return {
      completedMigrations: 0,
      activeMigrations: 0,
      failedMigrations: 0,
      migrationCompletionRate: 0,
    }
  }
}

async function buildDashboardSummaryFallback(client: any, userId: string) {
  const now = Date.now()
  const sevenDays = 7 * 86400000
  const recentStart = now - sevenDays
  const previousStart = now - sevenDays * 2
  const [
    assets,
    inventory,
    exposures,
    vulnerabilities,
    scanSessions,
    scanResults,
    scannerAlerts,
    runtimeEvents,
    certificates,
    generatedKeys,
    jobs,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(3000)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe, discovered_at, created_at, updated_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(4000)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(3000)),
    safeRows(client, 'vulnerabilities', (q) => q.select('id, asset_id, severity, status, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2500)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, findings_count, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(500)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, asset_id, threat_level, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(3000)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, severity, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2000)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, asset_id, host, severity, risk_score, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(4000)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, status, algorithm, not_after, is_quantum_safe, is_expiring_soon, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2500)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, status, expires_at, revoked_at, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2500)),
    safeRows(client, 'migration_jobs', (q) => q.select('id, status, progress, created_at, updated_at, completed_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
  ])

  const activeAssets = (assets || []).filter((asset: any) => !['archived', 'deleted', 'retired'].includes(String(asset.status || 'active').toLowerCase()))
  const completedJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'completed')
  const activeJobs = (jobs || []).filter((job: any) => ['pending', 'running'].includes(normalizeJobStatus(job.status)))
  const failedJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'failed')
  const openVulnerabilities = (vulnerabilities || []).filter((row: any) => !['resolved', 'remediated', 'false_positive', 'accepted', 'closed'].includes(String(row.status || 'open').toLowerCase()))
  const openAlerts = (scannerAlerts || []).filter((row: any) => !['resolved', 'suppressed', 'closed'].includes(String(row.status || 'open').toLowerCase()))
  const vulnerableInventory = (inventory || []).filter((row: any) => row.is_vulnerable && !row.is_quantum_safe)
  const riskyRuntime = (runtimeEvents || []).filter((row: any) => row.is_legacy || row.downgrade_detected || row.shadow_crypto || row.hndl_risk || severityRank(String(row.severity || '')) >= 3 || Number(row.risk_score || 0) >= 68)
  const expiringCertRows = (certificates || []).filter((cert: any) => {
    const expiresAt = dateMs(cert.not_after)
    return cert.is_expiring_soon || (expiresAt && expiresAt < now + 30 * 86400000 && !['revoked', 'deleted'].includes(String(cert.status || '').toLowerCase()))
  })
  const weakCertRows = (certificates || []).filter((cert: any) => !cert.is_quantum_safe && !isPqcReadyAlgorithm(`${cert.algorithm || ''}`))

  const addRiskSubject = (set: Set<string>, value: unknown, fallback?: unknown) => {
    const key = textValue(value, textValue(fallback))
    if (key) set.add(key)
  }
  const vulnerableSubjects = new Set<string>()
  for (const row of exposures || []) if (severityRank(String(row.severity || '')) >= 2) addRiskSubject(vulnerableSubjects, row.asset_id, row.id)
  for (const row of openVulnerabilities) addRiskSubject(vulnerableSubjects, row.asset_id, row.id)
  for (const row of scanResults || []) addRiskSubject(vulnerableSubjects, row.asset_id, row.id)
  for (const row of vulnerableInventory) addRiskSubject(vulnerableSubjects, row.asset_id, row.id)
  for (const row of riskyRuntime) addRiskSubject(vulnerableSubjects, row.asset_id, row.host || row.id)
  for (const row of [...expiringCertRows, ...weakCertRows]) addRiskSubject(vulnerableSubjects, row.asset_id, row.name || row.id)

  const riskSignals = [
    ...(exposures || []).map((row: any) => ({ severity: row.severity, timestamp: row.updated_at || row.created_at })),
    ...openVulnerabilities.map((row: any) => ({ severity: row.severity, timestamp: row.updated_at || row.created_at })),
    ...(scanResults || []).map((row: any) => ({ severity: row.threat_level, timestamp: row.created_at })),
    ...openAlerts.map((row: any) => ({ severity: row.severity, timestamp: row.updated_at || row.created_at })),
    ...riskyRuntime.map((row: any) => ({ severity: row.severity || (Number(row.risk_score || 0) >= 86 ? 'critical' : 'high'), timestamp: row.observed_at || row.created_at })),
    ...expiringCertRows.map((row: any) => ({ severity: 'medium', timestamp: row.updated_at || row.created_at })),
  ]
  const criticalExposures = riskSignals.filter((signal) => severityRank(String(signal.severity || '')) >= 4).length
  const highExposures = riskSignals.filter((signal) => severityRank(String(signal.severity || '')) >= 3).length
  const mediumFindings = riskSignals.filter((signal) => severityRank(String(signal.severity || '')) === 2).length
  const currentFindings = riskSignals.filter((signal) => dateMs(signal.timestamp) >= recentStart).length
  const previousFindings = riskSignals.filter((signal) => {
    const ms = dateMs(signal.timestamp)
    return ms >= previousStart && ms < recentStart
  }).length

  const assessedAssets = new Set([
    ...(inventory || []).map((row: any) => row.asset_id).filter(Boolean),
    ...(scanResults || []).map((row: any) => row.asset_id).filter(Boolean),
    ...(runtimeEvents || []).map((row: any) => row.asset_id).filter(Boolean),
    ...(certificates || []).map((row: any) => row.asset_id).filter(Boolean),
  ])
  const pqcReadyCrypto = [
    ...(inventory || []).filter((row: any) => row.is_quantum_safe || isPqcReadyAlgorithm(`${row.algorithm || ''} ${row.protocol || ''}`)),
    ...(certificates || []).filter((row: any) => row.is_quantum_safe || isPqcReadyAlgorithm(`${row.algorithm || ''}`)),
    ...(generatedKeys || []).filter((row: any) => isPqcReadyAlgorithm(`${row.algorithm || ''}`)),
  ].length
  const totalCryptoItems = (inventory || []).length + (certificates || []).length + (generatedKeys || []).length
  const readinessScore = percentOf(pqcReadyCrypto + completedJobs.length, Math.max(1, totalCryptoItems + (jobs || []).length))
  const coverageScore = percentOf(assessedAssets.size, Math.max(1, activeAssets.length))
  const riskPressure = clampPercent(criticalExposures * 12 + Math.max(0, highExposures - criticalExposures) * 7 + mediumFindings * 3 + failedJobs.length * 8 + expiringCertRows.length * 2)
  const hasTelemetry = activeAssets.length || totalCryptoItems || scanSessions.length || runtimeEvents.length || riskSignals.length
  const quantumRiskScore = hasTelemetry
    ? Math.max(0, Math.min(1000, Math.round(((readinessScore * 0.45) + (coverageScore * 0.2) + ((100 - riskPressure) * 0.35)) * 10)))
    : 0
  const riskBand = !hasTelemetry
    ? 'No Baseline'
    : quantumRiskScore >= 850
    ? 'Quantum Ready'
    : quantumRiskScore >= 650
      ? 'Moderate'
      : quantumRiskScore >= 400
        ? 'Vulnerable'
        : 'Critical'

  return {
    quantumRiskScore,
    riskBand,
    riskTrend: previousFindings - currentFindings,
    vulnerableAssetsCount: vulnerableSubjects.size,
    newVulnerableAssets: currentFindings,
    totalCbomItems: totalCryptoItems,
    activeMigrations: activeJobs.length,
    failedMigrations: failedJobs.length,
    completedMigrations: completedJobs.length,
    migrationCompletionRate: (jobs || []).length ? Math.round((completedJobs.length / (jobs || []).length) * 100) : 0,
    criticalExposures,
    highExposures,
    unresolvedVulns: openVulnerabilities.length + (scanResults || []).length + openAlerts.length,
    expiringCerts: expiringCertRows.length,
    totalAssets: activeAssets.length,
    lastScanAt: latestDate(...(scanSessions || []).map((scan: any) => scan.completed_at || scan.updated_at || scan.started_at || scan.created_at)),
    monitoringStatus: (scanSessions || []).some((scan: any) => ['pending', 'queued', 'running', 'analyzing'].includes(String(scan.status || '').toLowerCase()))
      ? 'scanning'
      : runtimeEvents.length || scannerAlerts.length
        ? 'active'
        : hasTelemetry
          ? 'standby'
          : 'no_baseline',
  }
}

function dashboardEventSeverity(value: unknown): 'critical' | 'warning' | 'info' | 'success' {
  const text = String(value || '').toLowerCase()
  if (text.includes('critical') || text.includes('high') || text.includes('fail') || text.includes('error')) return 'critical'
  if (text.includes('warning') || text.includes('medium') || text.includes('moderate') || text.includes('open')) return 'warning'
  if (text.includes('success') || text.includes('complete') || text.includes('resolved') || text.includes('trusted')) return 'success'
  return 'info'
}

async function buildEventsFallback(client: any, userId: string, limit: number) {
  const [securityEvents, scannerAlerts, scanSessions, scanResults, runtimeEvents, vulnerabilities, auditLogs] = await Promise.all([
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(limit)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, severity, category, title, message, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(limit)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, findings_count, target_scope, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(limit)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, asset_id, finding_type, algorithm, threat_level, description, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(limit)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, asset_id, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, algorithm, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(limit)),
    safeRows(client, 'vulnerabilities', (q) => q.select('id, asset_id, title, severity, status, source, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(limit)),
    safeRows(client, 'audit_logs', (q) => q.select('id, action, entity_type, entity_id, details, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(limit)),
  ])

  const events = [
    ...(securityEvents || []).map((ev: any) => ({
      id: `security-${ev.id}`,
      timestamp: ev.created_at,
      severity: dashboardEventSeverity(ev.severity),
      eventType: ev.event_type || 'security_event',
      message: ev.message || titleCase(String(ev.event_type || 'Security event')),
      assetId: ev.asset_id,
      resourceName: ev.resource_name,
      resourceType: ev.resource_type,
      metadata: recordOf(ev.metadata),
      isRead: Boolean(ev.is_read),
    })),
    ...(scannerAlerts || []).map((alert: any) => ({
      id: `scanner-alert-${alert.id}`,
      timestamp: alert.updated_at || alert.created_at,
      severity: dashboardEventSeverity(`${alert.severity || ''} ${alert.status || ''}`),
      eventType: alert.category || 'scanner_alert',
      message: alert.title || alert.message || 'Scanner alert captured',
      assetId: null,
      resourceName: textValue(recordOf(alert.metadata).assetName || recordOf(alert.metadata).hostname || recordOf(alert.metadata).target, 'Scanner finding'),
      resourceType: 'scanner_alert',
      metadata: recordOf(alert.metadata),
      isRead: ['resolved', 'closed', 'suppressed'].includes(String(alert.status || '').toLowerCase()),
    })),
    ...(scanSessions || []).map((scan: any) => ({
      id: `scan-${scan.id}`,
      timestamp: scan.completed_at || scan.updated_at || scan.started_at || scan.created_at,
      severity: dashboardEventSeverity(Number(scan.findings_count || 0) > 0 ? 'warning' : scan.status),
      eventType: 'pqc_scan_session',
      message: `PQC scan ${String(scan.status || 'recorded').replace(/_/g, ' ')} with ${Number(scan.findings_count || 0)} finding${Number(scan.findings_count || 0) === 1 ? '' : 's'}`,
      assetId: null,
      resourceName: textValue(scan.target_scope, 'PQC scan'),
      resourceType: 'scan_session',
      metadata: recordOf(scan.metadata),
      isRead: false,
    })),
    ...(scanResults || []).map((result: any) => ({
      id: `scan-result-${result.id}`,
      timestamp: result.created_at,
      severity: dashboardEventSeverity(result.threat_level),
      eventType: result.finding_type || 'scan_finding',
      message: result.description || `${result.algorithm || 'Crypto'} scan finding`,
      assetId: result.asset_id,
      resourceName: result.algorithm || 'PQC finding',
      resourceType: 'scan_result',
      metadata: recordOf(result.metadata),
      isRead: false,
    })),
    ...(runtimeEvents || []).map((event: any) => ({
      id: `runtime-${event.id}`,
      timestamp: event.observed_at || event.created_at,
      severity: dashboardEventSeverity(event.severity || (Number(event.risk_score || 0) >= 68 ? 'high' : 'info')),
      eventType: event.event_type || event.operation_type || 'runtime_crypto_event',
      message: `${event.asset_name || event.host || 'Runtime'} observed ${event.algorithm || event.operation_type || 'cryptographic activity'}`,
      assetId: event.asset_id,
      resourceName: event.asset_name || event.host,
      resourceType: event.asset_type || 'runtime',
      metadata: {},
      isRead: false,
    })),
    ...(vulnerabilities || []).map((vuln: any) => ({
      id: `vulnerability-${vuln.id}`,
      timestamp: vuln.updated_at || vuln.created_at,
      severity: dashboardEventSeverity(`${vuln.severity || ''} ${vuln.status || ''}`),
      eventType: 'vulnerability',
      message: vuln.title || 'Vulnerability finding',
      assetId: vuln.asset_id,
      resourceName: vuln.source || 'Vulnerability',
      resourceType: 'vulnerability',
      metadata: recordOf(vuln.metadata),
      isRead: ['resolved', 'closed', 'false_positive'].includes(String(vuln.status || '').toLowerCase()),
    })),
    ...(auditLogs || []).map((log: any) => ({
      id: `audit-${log.id}`,
      timestamp: log.created_at,
      severity: dashboardEventSeverity(log.action),
      eventType: log.action || 'audit_event',
      message: `${log.action || 'Audit event'} ${log.entity_type || ''}`.trim(),
      assetId: null,
      resourceName: log.entity_id || log.entity_type,
      resourceType: log.entity_type || 'audit',
      metadata: recordOf(log.details),
      isRead: true,
    })),
  ].filter((event) => event.timestamp)

  return events
    .sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp))
    .slice(0, limit)
}

async function buildExposureMapFallback(client: any, userId: string) {
  const [assets, relationships, exposures, vulnerabilities, scanResults, runtimeEvents, inventory, certificates] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(300)),
    safeRows(client, 'asset_relationships', (q) => q.select('source_asset_id, target_asset_id, relationship_type').eq('user_id', userId).limit(600)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, severity, updated_at, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2000)),
    safeRows(client, 'vulnerabilities', (q) => q.select('id, asset_id, severity, status, updated_at, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, asset_id, threat_level, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, asset_id, severity, risk_score, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(2400)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, is_vulnerable, is_quantum_safe, exposure_level, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(1600)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, status, algorithm, not_after, is_quantum_safe, is_expiring_soon, updated_at, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
  ])

  const riskByAsset = new Map<string, number>()
  const addRisk = (assetId: unknown, score: number) => {
    const id = textValue(assetId)
    if (!id) return
    riskByAsset.set(id, (riskByAsset.get(id) || 0) + score)
  }

  for (const exposure of exposures || []) addRisk(exposure.asset_id, severityRank(String(exposure.severity || '')) * 3 || 2)
  for (const vuln of vulnerabilities || []) {
    if (['resolved', 'closed', 'false_positive', 'accepted'].includes(String(vuln.status || '').toLowerCase())) continue
    addRisk(vuln.asset_id, severityRank(String(vuln.severity || '')) * 3 || 2)
  }
  for (const result of scanResults || []) addRisk(result.asset_id, severityRank(String(result.threat_level || '')) * 3 || 2)
  for (const event of runtimeEvents || []) {
    const risky = event.is_legacy || event.downgrade_detected || event.shadow_crypto || event.hndl_risk || severityRank(String(event.severity || '')) >= 3 || Number(event.risk_score || 0) >= 68
    if (risky) addRisk(event.asset_id, Math.max(2, Math.ceil(Number(event.risk_score || 0) / 20)))
  }
  for (const item of inventory || []) {
    if (item.is_vulnerable && !item.is_quantum_safe) addRisk(item.asset_id, severityRank(String(item.exposure_level || 'medium')) * 2 || 2)
  }
  for (const cert of certificates || []) {
    const expiresAt = dateMs(cert.not_after)
    const expiring = cert.is_expiring_soon || (expiresAt && expiresAt < Date.now() + 30 * 86400000)
    if (expiring || (!cert.is_quantum_safe && !isPqcReadyAlgorithm(`${cert.algorithm || ''}`))) addRisk(cert.asset_id, expiring ? 2 : 3)
  }

  const nodes = (assets || []).map((asset: any) => {
    const riskScore = riskByAsset.get(asset.id) || 0
    return {
      id: asset.id,
      name: asset.name,
      type: asset.type,
      environment: asset.environment || 'unknown',
      criticality: asset.criticality || 'medium',
      status: asset.status || 'active',
      riskScore,
      color: getRiskColor(riskScore, asset.status || 'active'),
    }
  })

  const edges = (relationships || []).map((edge: any) => ({
    source: edge.source_asset_id,
    target: edge.target_asset_id,
    type: edge.relationship_type,
  }))

  return { nodes, edges }
}

/**
 * GET /api/v1/dashboard/summary
 * Returns user-specific dashboard summary with risk score, counts, and status.
 */
router.get('/summary', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const summary = await buildDashboardSummaryFallback(client, user.id)
    return res.json({ data: summary })
  } catch (err) {
    console.error('Dashboard summary error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch dashboard summary' } })
  }
})

/**
 * GET /api/v1/dashboard/events
 * Returns recent security events for the authenticated user.
 */
router.get('/events', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const events = await buildEventsFallback(client, user.id, limit)
    return res.json({ data: { events } })
  } catch (err) {
    console.error('Dashboard events error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch security events' } })
  }
})

/**
 * GET /api/v1/dashboard/exposure-map
 * Returns nodes and edges for the Quantum Exposure Map.
 */
router.get('/exposure-map', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const mapData = await buildExposureMapFallback(client, user.id)
    return res.json({ data: mapData })
  } catch (err) {
    console.error('Exposure map error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch exposure map' } })
  }
})

function getRiskColor(riskScore: number, status: string): string {
  if (status === 'migrated' || status === 'protected') return '#10b981' // green
  if (!riskScore || riskScore === 0) return '#3b82f6' // blue
  if (riskScore >= 3) return '#ef4444' // red - critical
  if (riskScore >= 2) return '#f97316' // orange - high
  return '#eab308' // yellow - moderate
}

/**
 * GET /api/v1/dashboard/activity
 * Returns recent user activities across all modules.
 */
router.get('/activity', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    // Parallel fetch of recent activities from multiple tables
    const [
      { data: scans },
      { data: migrations },
      { data: vaultLogs },
      { data: qrngEvents },
      { data: compliance },
      { data: auditLogs }
    ] = await Promise.all([
      client.from('pqc_scan_sessions').select('id, status, progress, started_at, completed_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(limit),
      client.from('migration_jobs').select('id, name, status, progress, started_at, completed_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(limit),
      client.from('vault_audit_logs').select('id, event_type, operation, status, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(limit),
      client.from('qrng_events').select('id, event_type, algorithm, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(limit),
      client.from('compliance_evidence').select('id, framework, control_id, status, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(limit),
      client.from('audit_logs').select('id, action, entity_type, details, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(limit),
    ])

    const activities = [
      ...(scans || []).map((s: any) => ({
        id: s.id,
        type: 'scan',
        title: `PQC Scan ${s.status}`,
        description: `Scan ${s.status === 'completed' ? 'completed' : `progress: ${s.progress}%`}`,
        status: s.status,
        timestamp: s.completed_at || s.started_at,
      })),
      ...(migrations || []).map((m: any) => ({
        id: m.id,
        type: 'migration',
        title: m.name,
        description: `Migration ${m.status} — ${m.progress}%`,
        status: m.status,
        timestamp: m.completed_at || m.started_at,
      })),
      ...(vaultLogs || []).map((v: any) => ({
        id: v.id,
        type: 'vault',
        title: `Vault ${v.event_type}`,
        description: `${v.operation || v.event_type} — ${v.status}`,
        status: v.status,
        timestamp: v.created_at,
      })),
      ...(qrngEvents || []).map((q: any) => ({
        id: q.id,
        type: 'qrng',
        title: `QRNG ${q.event_type}`,
        description: q.algorithm ? `Algorithm: ${q.algorithm}` : 'Entropy event',
        status: 'completed',
        timestamp: q.created_at,
      })),
      ...(compliance || []).map((c: any) => ({
        id: c.id,
        type: 'compliance',
        title: `${c.framework} ${c.control_id}`,
        description: `Compliance evidence ${c.status}`,
        status: c.status,
        timestamp: c.created_at,
      })),
      ...(auditLogs || []).map((a: any) => ({
        id: a.id,
        type: 'audit',
        title: a.action,
        description: `${a.entity_type || 'system'} action`,
        status: 'completed',
        timestamp: a.created_at,
      })),
    ]

    activities.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())

    return res.json({ data: { activities: activities.slice(0, limit) } })
  } catch (err) {
    console.error('Dashboard activity error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch activity' } })
  }
})

/**
 * GET /api/v1/dashboard/health
 * Returns backend, realtime, and worker health status.
 */
router.get('/health', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)
    const serviceClient = getServiceClient()

    let supabaseStatus = 'unknown'
    if (client) {
      const { error } = await client.from('assets').select('id', { count: 'exact', head: true }).eq('user_id', user.id)
      supabaseStatus = error ? 'degraded' : 'healthy'
    }

    // Check for active scans and migrations
    let scannerStatus = 'idle'
    let migrationStatus = 'idle'

    if (client) {
      const { count: activeScans } = await client
        .from('pqc_scan_sessions')
        .select('id', { count: 'exact', head: true })
        .eq('user_id', user.id)
        .eq('status', 'running')
      if ((activeScans || 0) > 0) scannerStatus = 'scanning'

      const { count: activeMigrations } = await client
        .from('migration_jobs')
        .select('id', { count: 'exact', head: true })
        .eq('user_id', user.id)
        .eq('status', 'running')
      if ((activeMigrations || 0) > 0) migrationStatus = 'migrating'
    }

    return res.json({
      data: {
        status: supabaseStatus === 'healthy' ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        services: {
          supabase: supabaseStatus,
          scanner: scannerStatus,
          migration: migrationStatus,
          realtime: supabaseStatus === 'healthy' ? 'connected' : 'disconnected',
        },
        version: '2.0.0'
      }
    })
  } catch (err) {
    console.error('Dashboard health error:', err)
    return res.status(200).json({
      data: {
        status: 'degraded',
        timestamp: new Date().toISOString(),
        services: { supabase: 'unknown', scanner: 'unknown', migration: 'unknown', realtime: 'disconnected' },
        version: '2.0.0'
      }
    })
  }
})

/**
 * GET /api/v1/dashboard/recommendations
 * Returns prioritized remediation actions based on actual findings.
 */
router.get('/recommendations', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const recommendations: any[] = []

    // Check for RSA/ECC exposures
    const { data: cryptoExposures } = await client
      .from('crypto_exposures')
      .select('id, asset_id, exposure_type, severity, assets(name)')
      .eq('user_id', user.id)
      .in('exposure_type', ['rsa', 'ecc', 'dh'])
      .order('severity', { ascending: false })
      .limit(10)

    for (const exp of (cryptoExposures || [])) {
      const assetName = (exp as any).assets?.name || 'Unknown asset'
      recommendations.push({
        id: `exp-${exp.id}`,
        priority: exp.severity === 'critical' ? 1 : exp.severity === 'high' ? 2 : 3,
        category: 'cryptography',
        title: `Replace ${exp.exposure_type.toUpperCase()} on ${assetName}`,
        description: `Detected quantum-vulnerable ${exp.exposure_type.toUpperCase()} cryptography requiring migration to PQC algorithms (ML-KEM, ML-DSA).`,
        assetId: exp.asset_id,
        action: 'start_migration',
        estimatedEffort: 'medium',
      })
    }

    // Check for weak TLS
    const { data: tlsExposures } = await client
      .from('crypto_exposures')
      .select('id, asset_id, exposure_type, severity, assets(name)')
      .eq('user_id', user.id)
      .eq('exposure_type', 'weak_tls')
      .limit(5)

    for (const exp of (tlsExposures || [])) {
      const assetName = (exp as any).assets?.name || 'Unknown asset'
      recommendations.push({
        id: `tls-${exp.id}`,
        priority: exp.severity === 'critical' ? 1 : 2,
        category: 'protocol',
        title: `Upgrade TLS configuration on ${assetName}`,
        description: 'Weak TLS version or cipher suite detected. Enable TLS 1.3 with hybrid post-quantum key exchange.',
        assetId: exp.asset_id,
        action: 'upgrade_tls',
        estimatedEffort: 'low',
      })
    }

    // Check for expiring certificates
    const { data: expiringCerts } = await client
      .from('certificates')
      .select('id, asset_id, name, not_after, algorithm, assets(name)')
      .eq('user_id', user.id)
      .eq('status', 'active')
      .lt('not_after', new Date(Date.now() + 30 * 86400000).toISOString())
      .order('not_after', { ascending: true })
      .limit(5)

    for (const cert of (expiringCerts || [])) {
      const assetName = (cert as any).assets?.name || 'Unknown asset'
      const daysLeft = Math.ceil((new Date(cert.not_after!).getTime() - Date.now()) / 86400000)
      recommendations.push({
        id: `cert-${cert.id}`,
        priority: daysLeft <= 7 ? 1 : 2,
        category: 'certificate',
        title: `Renew certificate: ${cert.name}`,
        description: `Certificate expires in ${daysLeft} days on ${assetName}. Transition to ML-DSA or hybrid certificate.`,
        assetId: cert.asset_id,
        action: 'renew_certificate',
        estimatedEffort: 'medium',
      })
    }

    // Check for failed migrations
    const { data: failedMigrations } = await client
      .from('migration_jobs')
      .select('id, asset_id, name, job_type')
      .eq('user_id', user.id)
      .eq('status', 'failed')
      .limit(5)

    for (const job of (failedMigrations || [])) {
      recommendations.push({
        id: `migrate-${job.id}`,
        priority: 2,
        category: 'migration',
        title: `Review failed migration: ${job.name}`,
        description: `Migration job failed. Review logs and retry with corrected parameters.`,
        assetId: job.asset_id,
        action: 'review_migration',
        estimatedEffort: 'high',
      })
    }

    // Check for unscanned assets
    const { count: unscannedCount } = await client
      .from('assets')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', user.id)
      .eq('status', 'active')

    const { count: scannedCount } = await client
      .from('pqc_scan_results')
      .select('asset_id', { count: 'exact', head: true })
      .eq('user_id', user.id)

    if ((unscannedCount || 0) > 0 && (scannedCount || 0) === 0) {
      recommendations.push({
        id: 'scan-assets',
        priority: 1,
        category: 'discovery',
        title: 'Run PQC Discovery Scan',
        description: `${unscannedCount} assets have not been scanned for quantum vulnerabilities. Start a comprehensive scan to build your CBOM.`,
        action: 'start_scan',
        estimatedEffort: 'low',
      })
    }

    // Sort by priority
    recommendations.sort((a, b) => a.priority - b.priority)

    return res.json({ data: { recommendations: recommendations.slice(0, 20) } })
  } catch (err) {
    console.error('Dashboard recommendations error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to generate recommendations' } })
  }
})

type AgilityStatus = 'Ready' | 'Staged' | 'Blocked' | 'Not Scanned'

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

function clampPercent(value: number) {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, Math.round(value)))
}

function percentOf(value: number, total: number) {
  return total > 0 ? clampPercent((value / total) * 100) : 0
}

function titleCase(value: string) {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase())
}

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
}

function isPqcReadyAlgorithm(value: string) {
  const lower = value.toLowerCase()
  return ['ml-kem', 'ml-dsa', 'falcon', 'sphincs', 'kyber', 'dilithium', 'aes-256', 'sha3', 'sha-3', 'tls 1.3', 'tls-1.3'].some((token) => lower.includes(token))
}

function replacementForAlgorithm(algorithm: string, context = '') {
  const value = `${algorithm} ${context}`.toLowerCase()
  if (value.includes('rsa') || value.includes('key exchange') || value.includes('tls')) return 'ML-KEM-768 hybrid'
  if (value.includes('ecdsa') || value.includes('ed25519') || value.includes('dsa') || value.includes('jwt') || value.includes('sign')) return 'ML-DSA-44'
  if (value.includes('aes-128') || value.includes('cbc') || value.includes('3des') || value.includes('des')) return 'AES-256-GCM'
  if (value.includes('dh') || value.includes('dhe') || value.includes('ecdh') || value.includes('x25519') || value.includes('ssh')) return 'ML-KEM hybrid KEX'
  if (value.includes('sha1') || value.includes('sha-1') || value.includes('md5')) return 'SHA3/SHA-384 policy'
  if (isPqcReadyAlgorithm(value)) return algorithm || 'PQC-ready'
  return 'NIST PQC approved bundle'
}

function severityRank(severity: string) {
  const value = severity.toLowerCase()
  if (value === 'critical') return 4
  if (value === 'high') return 3
  if (value === 'moderate' || value === 'medium' || value === 'warning') return 2
  if (value === 'low') return 1
  return 0
}

function normalizeJobStatus(status: unknown) {
  const value = String(status || 'pending').toLowerCase().replace(/\s+/g, '_')
  if (['completed', 'complete', 'done', 'success', 'successful'].includes(value)) return 'completed'
  if (['failed', 'error', 'errored'].includes(value)) return 'failed'
  if (['running', 'in_progress', 'migrating', 'executing'].includes(value)) return 'running'
  if (['paused', 'cancelled', 'canceled', 'rollback_requested', 'rolled_back'].includes(value)) return 'paused'
  return 'pending'
}

function statusFromReadiness(readiness: number, blocker: string): AgilityStatus {
  if (!readiness) return 'Not Scanned'
  if (readiness < 60 || blocker.toLowerCase().includes('critical') || blocker.toLowerCase().includes('failed')) return 'Blocked'
  if (readiness < 85 || blocker !== 'None') return 'Staged'
  return 'Ready'
}

async function safeRows(client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Dashboard telemetry ${table} query skipped:`, error.message || error)
      return []
    }
    return data || []
  } catch (error: any) {
    console.warn(`Dashboard telemetry ${table} query failed:`, error?.message || error)
    return []
  }
}

function buildTrend(jobs: any[], exposures: any[]) {
  const buckets = Array.from({ length: 6 }, (_, index) => {
    const start = new Date()
    start.setHours(0, 0, 0, 0)
    start.setDate(start.getDate() - (25 - index * 5))
    const end = new Date(start)
    end.setDate(start.getDate() + 5)
    return {
      key: start.toISOString().slice(0, 10),
      label: start.toLocaleDateString('en-US', { month: 'short', day: '2-digit' }),
      start: start.getTime(),
      end: end.getTime(),
      successful: 0,
      staged: 0,
      blocked: 0,
    }
  })

  for (const job of jobs) {
    const status = normalizeJobStatus(job.status)
    const time = dateMs(job.completed_at || job.updated_at || job.created_at)
    const bucket = buckets.find((item) => time >= item.start && time < item.end)
    if (!bucket) continue
    if (status === 'completed') bucket.successful += 1
    else if (status === 'failed') bucket.blocked += 1
    else bucket.staged += 1
  }

  for (const exposure of exposures) {
    if (severityRank(exposure.severity || '') < 3) continue
    const time = dateMs(exposure.updated_at || exposure.created_at)
    const bucket = buckets.find((item) => time >= item.start && time < item.end)
    if (bucket) bucket.blocked += 1
  }

  return buckets.map(({ label, successful, staged, blocked }) => ({ label, successful, staged, blocked }))
}

function policyGroupFor(row: any) {
  const haystack = `${row.domain} ${row.from} ${row.to} ${row.assetType}`.toLowerCase()
  if (haystack.includes('tls') || haystack.includes('api') || haystack.includes('edge') || haystack.includes('protocol')) return 'edge'
  if (haystack.includes('jwt') || haystack.includes('sign') || haystack.includes('dsa') || haystack.includes('ecdsa')) return 'identity'
  if (haystack.includes('database') || haystack.includes('vault') || haystack.includes('aes') || haystack.includes('encrypt')) return 'data'
  if (row.status === 'Blocked' || haystack.includes('dh') || haystack.includes('sha1') || haystack.includes('md5') || haystack.includes('des')) return 'legacy'
  return 'general'
}

function packLabel(key: string) {
  if (key === 'edge') return { name: 'PQC TLS Edge', description: 'Hybrid key exchange for external and protocol-facing assets.' }
  if (key === 'identity') return { name: 'PQC Identity', description: 'Dual-signing and signature migration for tokens and trust chains.' }
  if (key === 'data') return { name: 'Data-at-Rest Strong', description: 'Stronger encryption profile for databases, vaults, and file stores.' }
  if (key === 'legacy') return { name: 'Legacy Quarantine', description: 'Disable weak fallbacks and isolate legacy cryptographic protocols.' }
  return { name: 'General Crypto Policy', description: 'Policy bundle derived from discovered cryptographic inventory.' }
}

/**
 * GET /api/v1/dashboard/crypto-agility
 * Returns user-specific crypto-agility telemetry derived from scans, CBOM,
 * exposures, migration jobs, and runtime events.
 */
router.get('/crypto-agility', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const [assets, inventory, exposures, jobs, scanSessions, securityEvents] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, service_owner, criticality, status, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(750)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(250)),
      safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(40)),
      safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, resource_name, resource_type, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(100)),
    ])

    const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
    const exposuresByAsset = new Map<string, any[]>()
    for (const exposure of exposures || []) {
      if (!exposure.asset_id) continue
      const list = exposuresByAsset.get(exposure.asset_id) || []
      list.push(exposure)
      exposuresByAsset.set(exposure.asset_id, list)
    }

    const jobsByAsset = new Map<string, any[]>()
    for (const job of jobs || []) {
      if (!job.asset_id) continue
      const list = jobsByAsset.get(job.asset_id) || []
      list.push(job)
      jobsByAsset.set(job.asset_id, list)
    }

    const latestJobForAsset = (assetId: string | null) => {
      if (!assetId) return null
      return (jobsByAsset.get(assetId) || []).sort((a, b) => dateMs(b.updated_at || b.created_at) - dateMs(a.updated_at || a.created_at))[0] || null
    }

    const buildSwitchRow = (source: any, sourceType: 'inventory' | 'exposure') => {
      const asset = assetMap.get(source.asset_id) || {}
      const assetId = source.asset_id || null
      const assetExposures = assetId ? exposuresByAsset.get(assetId) || [] : []
      const highestExposure = [...assetExposures, sourceType === 'exposure' ? source : null]
        .filter(Boolean)
        .sort((a: any, b: any) => severityRank(b.severity || '') - severityRank(a.severity || ''))[0]
      const job = latestJobForAsset(assetId)
      const jobStatus = normalizeJobStatus(job?.status)
      const metadata = recordOf(source.metadata)
      const from = textValue(source.algorithm, textValue(source.detected_value, textValue(source.exposure_type, 'Unknown')))
      const target = textValue(job?.target_algorithm, textValue(metadata.pqcReplacement || metadata.pqc_replacement || metadata.recommendedPQC, replacementForAlgorithm(from, `${source.item_type || ''} ${source.exposure_type || ''}`)))
      const quantumSafe = Boolean(source.is_quantum_safe) || isPqcReadyAlgorithm(from)
      const vulnerable = source.is_vulnerable !== false && !quantumSafe
      let readiness = quantumSafe ? 96 : vulnerable ? 68 : 82
      const rank = severityRank(highestExposure?.severity || source.exposure_level || '')
      if (rank >= 4) readiness = 38
      else if (rank === 3) readiness = 56
      else if (rank === 2) readiness = Math.min(readiness, 72)
      if (jobStatus === 'completed') readiness = Math.max(readiness, 96)
      else if (jobStatus === 'running') readiness = Math.max(readiness, 78)
      else if (jobStatus === 'pending') readiness = Math.max(readiness, 64)
      else if (jobStatus === 'failed') readiness = Math.min(readiness, 34)

      const blocker = jobStatus === 'failed'
        ? 'Failed migration'
        : rank >= 4
          ? 'Critical exposure'
          : rank === 3
            ? 'High exposure'
            : rank === 2
              ? 'Owner validation'
              : 'None'
      const status = statusFromReadiness(readiness, blocker)
      const domain = textValue(asset.name, textValue(source.name, titleCase(source.exposure_type || source.item_type || 'Cryptographic domain')))

      return {
        id: `${sourceType}-${source.id}`,
        assetId,
        domain,
        assetType: textValue(asset.type, textValue(source.item_type, 'asset')),
        environment: textValue(asset.environment, 'unknown'),
        owner: textValue(asset.service_owner, 'Unassigned'),
        from,
        to: target,
        readiness: clampPercent(readiness),
        blockers: blocker,
        status,
        lastScanAt: latestDate(source.discovered_at, source.updated_at, source.created_at, job?.updated_at, job?.completed_at),
      }
    }

    const rows: any[] = []
    const seen = new Set<string>()
    for (const item of inventory || []) {
      const key = `${item.asset_id || 'none'}:${item.item_type || ''}:${item.algorithm || item.name || item.id}`
      if (seen.has(key)) continue
      seen.add(key)
      rows.push(buildSwitchRow(item, 'inventory'))
    }
    for (const exposure of exposures || []) {
      const key = `${exposure.asset_id || 'none'}:${exposure.exposure_type || ''}:${exposure.detected_value || exposure.id}`
      if (seen.has(key)) continue
      seen.add(key)
      rows.push(buildSwitchRow(exposure, 'exposure'))
    }
    rows.sort((a, b) => a.status === 'Blocked' && b.status !== 'Blocked' ? -1 : b.readiness - a.readiness)
    const switchReadiness = rows.slice(0, 12)

    const ready = rows.filter((row) => row.status === 'Ready').length
    const staged = rows.filter((row) => row.status === 'Staged').length
    const blocked = rows.filter((row) => row.status === 'Blocked').length
    const notScanned = Math.max(0, (assets || []).length - new Set(rows.map((row) => row.assetId).filter(Boolean)).size)
    const totalDomains = rows.length + notScanned
    const avgReadiness = rows.length ? Math.round(rows.reduce((sum, row) => sum + row.readiness, 0) / rows.length) : 0

    const completedJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'completed')
    const failedJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'failed')
    const activeJobs = (jobs || []).filter((job: any) => ['pending', 'running'].includes(normalizeJobStatus(job.status)))
    const now = Date.now()
    const autoRotations = completedJobs.filter((job: any) => {
      const type = `${job.job_type || ''} ${job.name || ''}`.toLowerCase()
      return dateMs(job.completed_at || job.updated_at) >= now - 30 * 86400000 && ['rotation', 'cert', 'key', 'protocol', 'encryption'].some((token) => type.includes(token))
    }).length

    const discoveredAssets = (assets || []).length
    const classifiedAssets = new Set((inventory || []).map((item: any) => item.asset_id).filter(Boolean)).size
    const discoverPct = discoveredAssets ? 100 : 0
    const classifyPct = percentOf(classifiedAssets, Math.max(1, discoveredAssets))
    const abstractPct = rows.length ? percentOf(rows.filter((row) => row.to && row.to !== 'NIST PQC approved bundle').length, rows.length) : 0
    const switchPct = percentOf(completedJobs.length, Math.max(1, (jobs || []).length))
    const validatePct = (jobs || []).length ? percentOf(completedJobs.length, completedJobs.length + failedJobs.length) : (blocked === 0 && rows.length ? avgReadiness : 0)

    const lifecycle = [
      { key: 'discover', label: 'Discover', value: discoverPct },
      { key: 'classify', label: 'Classify', value: classifyPct },
      { key: 'abstract', label: 'Abstract', value: abstractPct },
      { key: 'switch', label: 'Switch', value: switchPct },
      { key: 'validate', label: 'Validate', value: validatePct },
    ]
    const readinessGates = {
      passed: lifecycle.filter((step) => step.value >= 75).length,
      total: lifecycle.length,
    }

    const blockerCounts = new Map<string, number>()
    for (const exposure of exposures || []) {
      if (severityRank(exposure.severity || '') < 2) continue
      const key = titleCase(exposure.exposure_type || 'crypto exposure')
      blockerCounts.set(key, (blockerCounts.get(key) || 0) + 1)
    }
    if (failedJobs.length) blockerCounts.set('Failed Migrations', failedJobs.length)
    const topBlockers = Array.from(blockerCounts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)

    const automationQueue = [
      ...activeJobs.slice(0, 8).map((job: any) => ({
        id: `job-${job.id}`,
        title: job.name || titleCase(job.job_type || 'Migration job'),
        priority: normalizeJobStatus(job.status) === 'running' ? 'High Priority' : 'Medium Priority',
        status: normalizeJobStatus(job.status) === 'running' ? 'Running' : 'Scheduled',
        eta: job.started_at ? 'In progress' : 'Queued',
        assetId: job.asset_id || null,
      })),
      ...failedJobs.slice(0, 4).map((job: any) => ({
        id: `failed-${job.id}`,
        title: `Review ${job.name || titleCase(job.job_type || 'failed switch')}`,
        priority: 'High Priority',
        status: 'Blocked',
        eta: 'Needs owner',
        assetId: job.asset_id || null,
      })),
      ...rows.filter((row) => row.status === 'Blocked').slice(0, 6).map((row) => ({
        id: `row-${row.id}`,
        title: `Resolve ${row.domain} switch blocker`,
        priority: row.blockers.includes('Critical') ? 'High Priority' : 'Medium Priority',
        status: 'Pending',
        eta: row.blockers,
        assetId: row.assetId,
      })),
    ].slice(0, 8)

    const policyGroups = new Map<string, any[]>()
    for (const row of rows) {
      const group = policyGroupFor(row)
      const list = policyGroups.get(group) || []
      list.push(row)
      policyGroups.set(group, list)
    }
    const policyPacks = Array.from(policyGroups.entries()).map(([key, groupRows]) => {
      const label = packLabel(key)
      const successRate = groupRows.length ? Math.round(groupRows.reduce((sum, row) => sum + row.readiness, 0) / groupRows.length) : 0
      const blockedInGroup = groupRows.filter((row) => row.status === 'Blocked').length
      const algorithms = Array.from(new Set(groupRows.map((row) => row.to).filter(Boolean))).slice(0, 2).join(' + ') || 'Policy target pending'
      return {
        id: key,
        name: label.name,
        algorithms,
        description: label.description,
        status: blockedInGroup ? 'Review' : successRate >= 80 ? 'Active' : 'Staged',
        version: `v${Math.max(1, groupRows.length)}.${blockedInGroup}.${completedJobs.length}`,
        standard: key === 'legacy' ? 'NIST SP 800-131A' : key === 'identity' ? 'NIST SP 800-208' : 'NIST SP 800-57',
        domains: groupRows.length,
        assets: new Set(groupRows.map((row) => row.assetId).filter(Boolean)).size,
        successRate,
      }
    }).sort((a, b) => b.domains - a.domains)

    const agilityScore = totalDomains ? avgReadiness : 0

    return res.json({
      data: {
        generatedAt: new Date().toISOString(),
        metrics: {
          agilityScore,
          policyPacks: policyPacks.length,
          blockedSwitches: blocked,
          autoRotations,
          readinessGates,
          totalDomains,
          ready,
          staged,
          blocked,
          notScanned,
        },
        switchReadiness,
        lifecycle,
        overview: {
          domainStatus: { ready, staged, blocked, notScanned, total: totalDomains },
          switchTrend: buildTrend(jobs || [], exposures || []),
          topBlockers,
        },
        automationQueue,
        policyPacks,
        latest: {
          lastScanAt: latestDate(...(scanSessions || []).map((scan: any) => scan.completed_at || scan.updated_at || scan.created_at)),
          latestEvent: securityEvents?.[0] || null,
          activeScans: (scanSessions || []).filter((scan: any) => ['pending', 'running', 'analyzing'].includes(String(scan.status || '').toLowerCase())).length,
        },
      },
    })
  } catch (err) {
    console.error('Crypto agility dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch crypto agility telemetry' } })
  }
})

function priorityForJob(job: any, exposures: any[]) {
  const metadata = recordOf(job?.metadata)
  const explicit = textValue(metadata.priority, '')
  if (explicit) return titleCase(explicit)
  const maxSeverity = Math.max(0, ...exposures.map((exposure) => severityRank(exposure.severity || '')))
  if (maxSeverity >= 4) return 'Critical'
  if (maxSeverity >= 3) return 'High'
  if (maxSeverity >= 2) return 'Medium'
  return 'Low'
}

function etaForJob(job: any) {
  const metadata = recordOf(job?.metadata)
  const explicit = textValue(metadata.eta || metadata.estimatedEta || metadata.estimated_eta, '')
  if (explicit) return explicit
  const progress = Number(job?.progress || 0)
  if (normalizeJobStatus(job?.status) === 'completed') return 'Done'
  if (normalizeJobStatus(job?.status) === 'failed') return 'Review'
  if (progress <= 0) return 'Scheduled'
  return `${Math.max(5, Math.round((100 - progress) / 5) * 5)}m`
}

function stageState(progress: number, threshold: number, status: string) {
  if (status === 'failed') return 'failed'
  if (progress >= threshold) return 'completed'
  if (progress >= threshold - 20) return 'active'
  return 'pending'
}

function complianceStatus(label: string, evidence: any[], metrics: { readiness: number; critical: number; high: number; failed: number; totalAssets: number }) {
  const matched = evidence.find((item) => {
    const text = `${item.framework || ''} ${item.control_id || ''}`.toLowerCase()
    return text.includes(label.toLowerCase().split(' ')[0]) || text.includes(label.toLowerCase())
  })
  if (matched?.status) return titleCase(String(matched.status))
  if (!metrics.totalAssets) return 'Not Assessed'
  if (label.includes('FIPS 204')) return metrics.failed > 0 ? 'Non-Compliant' : metrics.readiness >= 75 ? 'Compliant' : 'At Risk'
  if (metrics.critical > 0) return 'At Risk'
  if (metrics.readiness >= 70 && metrics.high <= Math.max(1, Math.floor(metrics.totalAssets * 0.15))) return 'Compliant'
  return 'At Risk'
}

function onboardingTaskStatus(done: boolean, active: boolean, blocked = false) {
  if (blocked) return 'overdue'
  if (done) return 'completed'
  if (active) return 'in_progress'
  return 'pending'
}

function onboardingTone(status: string) {
  if (status === 'completed') return 'green'
  if (status === 'in_progress') return 'blue'
  if (status === 'overdue') return 'red'
  return 'amber'
}

function normalizedSeverity(value: unknown) {
  const text = String(value || '').toLowerCase()
  if (text.includes('critical')) return 'critical'
  if (text.includes('high')) return 'high'
  if (text.includes('medium') || text.includes('moderate') || text.includes('warning')) return 'medium'
  if (text.includes('low')) return 'low'
  return 'info'
}

function statusLabelForOnboarding(status: string) {
  if (status === 'completed') return 'Completed'
  if (status === 'in_progress') return 'In Progress'
  if (status === 'overdue') return 'Overdue'
  return 'Pending'
}

function resourceForStep(step: number) {
  const resources = [
    [
      { title: 'Tenant Readiness Checklist', type: 'Profile and governance record', href: '/dashboard/settings' },
      { title: 'Scope Definition Worksheet', type: 'Asset ownership workflow', href: '/dashboard/assets' },
      { title: 'Access and Session Controls', type: 'Security configuration', href: '/dashboard/settings' },
      { title: 'Onboarding Evidence Vault', type: 'Audit evidence collection', href: '/dashboard/audit-vault' },
    ],
    [
      { title: 'Discovery Scanner Console', type: 'Live scanner telemetry', href: '/dashboard/scanner' },
      { title: 'CBOM Explorer', type: 'Cryptographic inventory', href: '/dashboard/cbom' },
      { title: 'Runtime Telemetry', type: 'Agent and runtime coverage', href: '/dashboard/runtime-telemetry' },
      { title: 'Assets & CBOM', type: 'Tenant-scoped asset graph', href: '/dashboard/assets' },
    ],
    [
      { title: 'Quantum Risk Scoring', type: 'Risk and exposure scoring', href: '/dashboard/quantum-risk-scoring' },
      { title: 'Vulnerability Review', type: 'Open finding triage', href: '/dashboard/vulnerabilities' },
      { title: 'Harvest Now Risk Review', type: 'HNDL exposure workflow', href: '/dashboard/harvest-now' },
      { title: 'Telemetry Correlation', type: 'Cross-source event analysis', href: '/dashboard/telemetry-correlation' },
    ],
    [
      { title: 'Migration Execution Guide', type: 'Live orchestration workflow', href: '/dashboard/pqc-orchestration' },
      { title: 'PQC Implementation Best Practices', type: 'Crypto-agility policy packs', href: '/dashboard/crypto-agility' },
      { title: 'Live Migration Operations', type: 'Migration operations and logs', href: '/dashboard/live-migration' },
      { title: 'Rollback Procedures', type: 'Sandbox and rollback validation', href: '/dashboard/migration-sandbox' },
    ],
    [
      { title: 'Migration Sandbox', type: 'Pre-production validation', href: '/dashboard/migration-sandbox' },
      { title: 'Live Migration Operations', type: 'Cutover monitoring', href: '/dashboard/live-migration' },
      { title: 'TLS Telemetry Validation', type: 'Protocol verification', href: '/dashboard/tls-telemetry' },
      { title: 'PKI Visibility Review', type: 'Certificate posture validation', href: '/dashboard/pki-visibility' },
    ],
    [
      { title: 'Audit Vault', type: 'Final migration evidence', href: '/dashboard/audit-vault' },
      { title: 'Continuous Trust Validation', type: 'Steady-state control checks', href: '/dashboard/continuous-trust' },
      { title: 'Regulatory Mapping', type: 'Compliance evidence mapping', href: '/dashboard/regulatory-mapping' },
      { title: 'Runtime Telemetry', type: 'Continuous event monitoring', href: '/dashboard/runtime-telemetry' },
    ],
  ]
  return resources[Math.max(0, Math.min(5, step - 1))]
}

async function buildPqcOnboardingSnapshot(client: any, user: any) {
  const [profileRows, assets, inventory, exposures, jobs, migrationEvents, scanSessions, scanResults, securityEvents, complianceEvidence, runtimeEvents, scannerAgents, scannerAlerts, generatedKeys, certificates] = await Promise.all([
    safeRows(client, 'profiles', (q) => q.select('*').eq('id', user.id).limit(1)),
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(1200)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1200)),
    safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'migration_events', (q) => q.select('id, migration_id, event_type, message, severity, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(700)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, target_scope, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(120)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1600)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(700)),
    safeRows(client, 'compliance_evidence', (q) => q.select('id, framework, control_id, status, evidence_type, description, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(300)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, package_name, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', user.id).order('observed_at', { ascending: false }).limit(2400)),
    safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, capabilities, last_seen_at, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(900)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, label, purpose, status, entropy_source, quality_score, created_at, expires_at, rotated_from').eq('user_id', user.id).order('created_at', { ascending: false }).limit(800)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, status, algorithm, not_after, is_quantum_safe, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(700)),
  ])

  const profile = profileRows?.[0] || {}
  const now = Date.now()
  const oneDay = 86_400_000
  const since24h = now - oneDay

  const activeAssets = (assets || []).filter((asset: any) => String(asset.status || 'active').toLowerCase() !== 'archived')
  const completedJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'completed')
  const runningJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'running')
  const pendingJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'pending')
  const failedJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'failed')
  const activeScans = (scanSessions || []).filter((scan: any) => ['pending', 'running', 'analyzing', 'queued'].includes(String(scan.status || '').toLowerCase()))
  const openAlerts = (scannerAlerts || []).filter((alert: any) => !['resolved', 'suppressed', 'closed'].includes(String(alert.status || '').toLowerCase()))
  const criticalExposures = (exposures || []).filter((exposure: any) => severityRank(exposure.severity || '') >= 4).length
  const highExposures = (exposures || []).filter((exposure: any) => severityRank(exposure.severity || '') >= 3).length
  const openFindings = (scanResults || []).length + (exposures || []).length + openAlerts.length
  const runtimeRisks = (runtimeEvents || []).filter((event: any) => event.is_legacy || event.downgrade_detected || event.shadow_crypto || event.hndl_risk || severityRank(event.severity || '') >= 3)
  const runtime24h = (runtimeEvents || []).filter((event: any) => dateMs(event.observed_at || event.created_at) >= since24h)
  const assessedAssets = new Set([
    ...(inventory || []).map((item: any) => item.asset_id).filter(Boolean),
    ...(scanResults || []).map((item: any) => item.asset_id).filter(Boolean),
    ...(runtimeEvents || []).map((event: any) => event.asset_id).filter(Boolean),
  ])
  const safeInventory = (inventory || []).filter((item: any) => item.is_quantum_safe || isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`))
  const vulnerableInventory = (inventory || []).filter((item: any) => item.is_vulnerable && !item.is_quantum_safe)
  const pqcCerts = (certificates || []).filter((cert: any) => cert.is_quantum_safe || isPqcReadyAlgorithm(`${cert.algorithm || ''}`))
  const totalCryptoItems = Math.max(1, (inventory || []).length + (certificates || []).length)
  const readinessScore = clampPercent(((safeInventory.length + pqcCerts.length + completedJobs.length) / Math.max(1, totalCryptoItems + jobs.length)) * 100)
  const coverageScore = percentOf(assessedAssets.size, Math.max(1, activeAssets.length))
  const riskScore = clampPercent(100 - Math.min(100, criticalExposures * 12 + Math.max(0, highExposures - criticalExposures) * 7 + runtimeRisks.length * 3 + failedJobs.length * 8))
  const averageJobProgress = (jobs || []).length
    ? clampPercent((jobs || []).reduce((sum: number, job: any) => sum + Number(job.progress || (normalizeJobStatus(job.status) === 'completed' ? 100 : 0)), 0) / jobs.length)
    : 0
  const validationScore = clampPercent((readinessScore * 0.45) + (riskScore * 0.35) + (complianceEvidence?.length ? 20 : 0))

  let currentStep = 1
  if (activeAssets.length || scanSessions.length || runtimeEvents.length || inventory.length) currentStep = 2
  if (inventory.length || scanResults.length || exposures.length || runtimeRisks.length) currentStep = 3
  if (jobs.length || migrationEvents.length) currentStep = 4
  if (completedJobs.length && (failedJobs.length || openFindings || complianceEvidence.length || certificates.length)) currentStep = 5
  if (completedJobs.length && validationScore >= 80 && failedJobs.length === 0 && criticalExposures === 0) currentStep = 6

  const taskSets: Record<number, Array<{ label: string; detail: string; href: string; status: string; count: number; source: string }>> = {
    1: [
      { label: 'Confirm Tenant Profile', detail: 'Company, owner, and role profile are configured.', href: '/dashboard/settings', status: onboardingTaskStatus(Boolean(profile.company || profile.full_name || user.email), false), count: profile.company ? 1 : 0, source: 'profiles' },
      { label: 'Register Business Assets', detail: 'Tenant assets are present for migration scoping.', href: '/dashboard/assets', status: onboardingTaskStatus(activeAssets.length > 0, activeAssets.length === 0), count: activeAssets.length, source: 'assets' },
      { label: 'Assign Service Owners', detail: 'Assets include service ownership metadata.', href: '/dashboard/assets', status: onboardingTaskStatus(activeAssets.some((asset: any) => asset.service_owner), activeAssets.length > 0), count: activeAssets.filter((asset: any) => asset.service_owner).length, source: 'assets.service_owner' },
      { label: 'Prepare Audit Evidence', detail: 'Compliance and audit evidence collection has started.', href: '/dashboard/audit-vault', status: onboardingTaskStatus((complianceEvidence || []).length > 0, activeAssets.length > 0), count: (complianceEvidence || []).length, source: 'compliance_evidence' },
    ],
    2: [
      { label: 'Run Discovery Scan', detail: 'PQC scan sessions have been recorded.', href: '/dashboard/scanner', status: onboardingTaskStatus(scanSessions.length > 0, activeScans.length > 0), count: scanSessions.length, source: 'pqc_scan_sessions' },
      { label: 'Inventory Crypto Assets', detail: 'Cryptographic inventory rows are available.', href: '/dashboard/cbom', status: onboardingTaskStatus(inventory.length > 0, scanSessions.length > 0), count: inventory.length, source: 'crypto_inventory' },
      { label: 'Collect Runtime Telemetry', detail: 'Runtime crypto events are flowing from agents or integrations.', href: '/dashboard/runtime-crypto-intel', status: onboardingTaskStatus(runtimeEvents.length > 0, scannerAgents.length > 0), count: runtimeEvents.length, source: 'runtime_crypto_events' },
      { label: 'Register Collector Agents', detail: 'Scanner agents are connected for live discovery.', href: '/dashboard/scanner', status: onboardingTaskStatus(scannerAgents.length > 0, false), count: scannerAgents.length, source: 'scanner_agents' },
    ],
    3: [
      { label: 'Tally Quantum Findings', detail: 'Scan findings and exposure rows are available for scoring.', href: '/dashboard/vulnerabilities', status: onboardingTaskStatus(openFindings > 0, scanSessions.length > 0), count: openFindings, source: 'pqc_scan_results + crypto_exposures + scanner_alerts' },
      { label: 'Rank Critical Exposures', detail: 'Critical and high crypto risks are prioritized.', href: '/dashboard/quantum-risk-scoring', status: onboardingTaskStatus(highExposures > 0 || riskScore >= 90, openFindings > 0), count: criticalExposures + highExposures, source: 'crypto_exposures' },
      { label: 'Correlate Runtime Detections', detail: 'Runtime risk events are included in the risk posture.', href: '/dashboard/telemetry-correlation', status: onboardingTaskStatus(runtimeRisks.length > 0, runtimeEvents.length > 0), count: runtimeRisks.length, source: 'runtime_crypto_events' },
      { label: 'Build Migration Backlog', detail: 'Findings have a migration or remediation plan.', href: '/dashboard/migration-planner', status: onboardingTaskStatus(jobs.length > 0, openFindings > 0), count: jobs.length, source: 'migration_jobs' },
    ],
    4: [
      { label: 'Implement PQC Algorithms', detail: 'Completed jobs or PQC-ready crypto items have been observed.', href: '/dashboard/pqc-orchestration', status: onboardingTaskStatus(completedJobs.length > 0 || safeInventory.length > 0, runningJobs.length > 0), count: completedJobs.length + safeInventory.length, source: 'migration_jobs + crypto_inventory' },
      { label: 'Migrate Infrastructure Components', detail: 'Migration jobs are running across tenant assets.', href: '/dashboard/live-migration', status: onboardingTaskStatus(averageJobProgress >= 80 && jobs.length > 0, runningJobs.length > 0 || pendingJobs.length > 0, failedJobs.length > 0), count: jobs.length, source: 'migration_jobs' },
      { label: 'Update Applications and Services', detail: 'Application and service assets are being moved to PQC targets.', href: '/dashboard/live-migration', status: onboardingTaskStatus(completedJobs.length >= Math.max(1, Math.ceil(jobs.length * 0.6)) && jobs.length > 0, jobs.length > 0), count: completedJobs.length, source: 'migration_jobs' },
      { label: 'Data Migration and Encryption', detail: 'Keys, certificates, and encryption services are being updated.', href: '/dashboard/keys', status: onboardingTaskStatus((generatedKeys || []).length > 0 && readinessScore >= 60, (generatedKeys || []).length > 0 || runningJobs.length > 0), count: (generatedKeys || []).length, source: 'generated_keys' },
      { label: 'Configure Security Controls', detail: 'Compliance evidence and security policies are being recorded.', href: '/dashboard/crypto-policies', status: onboardingTaskStatus((complianceEvidence || []).length > 0, jobs.length > 0), count: (complianceEvidence || []).length, source: 'compliance_evidence' },
      { label: 'Validate Migration Integrity', detail: 'Failed jobs, alerts, and runtime risks are reconciled.', href: '/dashboard/migration-sandbox', status: onboardingTaskStatus(completedJobs.length > 0 && failedJobs.length === 0 && criticalExposures === 0, completedJobs.length > 0, failedJobs.length > 0), count: failedJobs.length, source: 'migration_jobs + crypto_exposures' },
    ],
    5: [
      { label: 'Execute Sandbox Tests', detail: 'Completed migration jobs are ready for validation.', href: '/dashboard/migration-sandbox', status: onboardingTaskStatus(completedJobs.length > 0, runningJobs.length > 0), count: completedJobs.length, source: 'migration_jobs' },
      { label: 'Validate TLS and PKI', detail: 'PQC certificates and TLS telemetry are checked.', href: '/dashboard/tls-telemetry', status: onboardingTaskStatus(pqcCerts.length > 0 || runtimeEvents.some((event: any) => event.is_pqc), runtimeEvents.length > 0), count: pqcCerts.length, source: 'certificates + runtime_crypto_events' },
      { label: 'Resolve Failed Jobs', detail: 'No failed migration jobs remain.', href: '/dashboard/live-migration', status: onboardingTaskStatus(failedJobs.length === 0 && jobs.length > 0, failedJobs.length > 0, failedJobs.length > 0), count: failedJobs.length, source: 'migration_jobs' },
      { label: 'Attach Audit Evidence', detail: 'Compliance evidence confirms the migration outcome.', href: '/dashboard/audit-vault', status: onboardingTaskStatus(complianceEvidence.length > 0, completedJobs.length > 0), count: complianceEvidence.length, source: 'compliance_evidence' },
    ],
    6: [
      { label: 'Enable Continuous Monitoring', detail: 'Runtime telemetry and scanner agents remain active.', href: '/dashboard/runtime-telemetry', status: onboardingTaskStatus(runtime24h.length > 0 || scannerAgents.length > 0, true), count: runtime24h.length + scannerAgents.length, source: 'runtime_crypto_events + scanner_agents' },
      { label: 'Maintain Governance Evidence', detail: 'Compliance records continue to sync.', href: '/dashboard/regulatory-mapping', status: onboardingTaskStatus(complianceEvidence.length > 0, completedJobs.length > 0), count: complianceEvidence.length, source: 'compliance_evidence' },
      { label: 'Monitor Residual Risk', detail: 'High-risk detections are reduced and tracked.', href: '/dashboard/quantum-risk-scoring', status: onboardingTaskStatus(runtimeRisks.length === 0 && criticalExposures === 0, runtimeEvents.length > 0, runtimeRisks.length > 0 || criticalExposures > 0), count: runtimeRisks.length + criticalExposures, source: 'runtime_crypto_events + crypto_exposures' },
      { label: 'Keep PQC Inventory Current', detail: 'PQC-ready inventory remains visible across the tenant.', href: '/dashboard/cbom', status: onboardingTaskStatus(readinessScore >= 80, inventory.length > 0), count: safeInventory.length, source: 'crypto_inventory' },
    ],
  }

  const currentTasks = taskSets[currentStep]
  const completedTasks = currentTasks.filter((task) => task.status === 'completed').length
  const inProgressTasks = currentTasks.filter((task) => task.status === 'in_progress').length
  const pendingTaskCount = currentTasks.filter((task) => task.status === 'pending').length
  const overdueTaskCount = currentTasks.filter((task) => task.status === 'overdue').length
  const stepProgress = clampPercent(((completedTasks + inProgressTasks * 0.5) / Math.max(1, currentTasks.length)) * 100)
  const overallProgress = clampPercent((((currentStep - 1) / 6) * 100) + (stepProgress / 6))

  const stepNames = [
    { id: 1, title: 'Awareness & Preparation', href: '/dashboard/settings' },
    { id: 2, title: 'Discovery & Inventory', href: '/dashboard/scanner' },
    { id: 3, title: 'Risk Assessment & Planning', href: '/dashboard/quantum-risk-scoring' },
    { id: 4, title: 'Migration Execution', href: '/dashboard/pqc-orchestration' },
    { id: 5, title: 'Migration Testing', href: '/dashboard/migration-sandbox' },
    { id: 6, title: 'Validation & Monitoring', href: '/dashboard/audit-vault' },
  ]

  const steps = stepNames.map((step) => ({
    ...step,
    status: step.id < currentStep ? 'completed' : step.id === currentStep ? 'current' : 'pending',
    progress: step.id < currentStep ? 100 : step.id === currentStep ? stepProgress : 0,
  }))

  const currentStepMeta = stepNames[currentStep - 1]
  const nextStep = stepNames[currentStep] || null
  const firstAssetMeta = recordOf((assets || [])[0]?.metadata)
  const allStartDates = [
    profile.created_at,
    ...(assets || []).map((asset: any) => asset.created_at),
    ...(scanSessions || []).map((scan: any) => scan.started_at || scan.created_at),
    ...(jobs || []).map((job: any) => job.started_at || job.created_at),
  ].map(dateMs).filter(Boolean).sort((a, b) => a - b)
  const targetDates = (jobs || [])
    .map((job: any) => recordOf(job.metadata).targetGoLive || recordOf(job.metadata).target_go_live || recordOf(job.metadata).goLive || recordOf(job.metadata).go_live || job.completed_at)
    .map(dateMs)
    .filter(Boolean)
    .sort((a, b) => b - a)

  const projectManager = textValue(
    profile.full_name || profile.name || profile.username || profile.email || user.email,
    textValue(activeAssets.find((asset: any) => asset.service_owner)?.service_owner, 'Not assigned'),
  )
  const status = failedJobs.length || criticalExposures > 0
    ? 'Action Required'
    : currentStep === 6
      ? 'Monitoring'
      : jobs.length || activeScans.length || openFindings
        ? 'In Progress'
        : 'Preparing'

  const activityItems = [
    ...(migrationEvents || []).map((event: any) => ({
      id: `migration-${event.id}`,
      type: 'migration',
      title: event.message || titleCase(event.event_type || 'Migration event'),
      actor: textValue(recordOf(event.metadata).actor || recordOf(event.metadata).operator, 'Migration pipeline'),
      timestamp: event.created_at,
      severity: normalizedSeverity(event.severity),
    })),
    ...(securityEvents || []).map((event: any) => ({
      id: `security-${event.id}`,
      type: 'security',
      title: event.message || titleCase(event.event_type || 'Security event'),
      actor: textValue(event.resource_name, textValue(event.resource_type, 'Security telemetry')),
      timestamp: event.created_at,
      severity: normalizedSeverity(event.severity),
    })),
    ...(runtimeEvents || []).map((event: any) => ({
      id: `runtime-${event.id}`,
      type: 'runtime',
      title: titleCase(event.event_type || event.operation_type || 'Runtime crypto event'),
      actor: textValue(event.asset_name || event.host || event.source_type, 'Runtime collector'),
      timestamp: event.observed_at || event.created_at,
      severity: normalizedSeverity(event.severity || (event.is_legacy || event.downgrade_detected ? 'high' : 'info')),
    })),
    ...(scanSessions || []).map((scan: any) => ({
      id: `scan-${scan.id}`,
      type: 'scan',
      title: `PQC scan ${titleCase(String(scan.status || 'recorded'))}`,
      actor: 'Scanner engine',
      timestamp: scan.completed_at || scan.updated_at || scan.started_at || scan.created_at,
      severity: normalizedSeverity(Number(scan.findings_count || 0) > 0 ? 'medium' : 'info'),
    })),
    ...(openAlerts || []).map((alert: any) => ({
      id: `alert-${alert.id}`,
      type: 'alert',
      title: alert.title || alert.message || titleCase(alert.category || 'Scanner alert'),
      actor: 'Agent scanner',
      timestamp: alert.updated_at || alert.created_at,
      severity: normalizedSeverity(alert.severity),
    })),
  ].filter((item) => item.timestamp)
    .sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp))
    .slice(0, 10)

  const benefits = [
    {
      label: 'Quantum-Ready Infrastructure',
      value: `${readinessScore}%`,
      detail: `${safeInventory.length + pqcCerts.length} PQC-ready crypto items`,
      status: readinessScore >= 80 ? 'completed' : readinessScore > 0 ? 'in_progress' : 'pending',
    },
    {
      label: 'Risk Reduction & Resilience',
      value: `${riskScore}%`,
      detail: `${criticalExposures + highExposures} high-priority exposures`,
      status: riskScore >= 80 ? 'completed' : criticalExposures ? 'overdue' : 'in_progress',
    },
    {
      label: 'Regulatory Compliance',
      value: String(complianceEvidence.length),
      detail: 'Compliance evidence records',
      status: complianceEvidence.length > 0 ? 'completed' : jobs.length > 0 ? 'in_progress' : 'pending',
    },
    {
      label: 'Future-Proof Investment',
      value: `${completedJobs.length}/${Math.max(1, jobs.length)}`,
      detail: 'Completed migration workflows',
      status: completedJobs.length === jobs.length && jobs.length > 0 ? 'completed' : jobs.length > 0 ? 'in_progress' : 'pending',
    },
    {
      label: 'Continuous Protection',
      value: String(runtime24h.length + scannerAgents.length),
      detail: 'Runtime events and collectors',
      status: runtime24h.length || scannerAgents.length ? 'in_progress' : 'pending',
    },
  ]

  return {
    generatedAt: new Date().toISOString(),
    currentStep,
    currentStepTitle: currentStepMeta.title,
    currentStepStatus: status,
    nextStep: nextStep ? { title: nextStep.title, href: nextStep.href } : null,
    overallProgress,
    stepProgress,
    steps,
    stepOverview: {
      bullets: currentTasks.map((task) => task.detail),
      tasksCompleted: completedTasks,
      inProgress: inProgressTasks,
      pending: pendingTaskCount,
      overdue: overdueTaskCount,
      totalTasks: currentTasks.length,
    },
    tasks: currentTasks.map((task) => ({
      ...task,
      labelStatus: statusLabelForOnboarding(task.status),
      tone: onboardingTone(task.status),
    })),
    resources: resourceForStep(currentStep),
    activity: activityItems,
    client: {
      name: textValue(profile.company || firstAssetMeta.organization || firstAssetMeta.clientName || firstAssetMeta.client_name, textValue(profile.full_name || profile.name || user.email, 'Not configured')),
      industry: textValue(profile.industry || firstAssetMeta.industry || firstAssetMeta.sector, 'Not configured'),
      onboardingStartDate: allStartDates.length ? new Date(allStartDates[0]).toISOString() : null,
      targetGoLive: targetDates.length ? new Date(targetDates[0]).toISOString() : null,
      projectManager,
      status,
      avatarUrl: profile.avatar_url || user.user_metadata?.avatar_url || null,
      email: user.email || profile.email || null,
    },
    metrics: {
      assets: activeAssets.length,
      assessedAssets: assessedAssets.size,
      findings: openFindings,
      criticalExposures,
      highExposures,
      riskScore,
      readinessScore,
      migrationJobs: jobs.length,
      completedMigrations: completedJobs.length,
      runningMigrations: runningJobs.length,
      failedMigrations: failedJobs.length,
      runtimeEvents: runtimeEvents.length,
      runtimeEvents24h: runtime24h.length,
      activeScans: activeScans.length,
      scannerAgents: scannerAgents.length,
      openAlerts: openAlerts.length,
      generatedKeys: (generatedKeys || []).length,
      certificates: (certificates || []).length,
      vulnerableCryptoItems: vulnerableInventory.length,
      coverageScore,
    },
    benefits,
    sync: {
      userId: user.id,
      sourceTables: {
        assets: assets.length,
        crypto_inventory: inventory.length,
        crypto_exposures: exposures.length,
        migration_jobs: jobs.length,
        migration_events: migrationEvents.length,
        pqc_scan_sessions: scanSessions.length,
        pqc_scan_results: scanResults.length,
        security_events: securityEvents.length,
        compliance_evidence: complianceEvidence.length,
        runtime_crypto_events: runtimeEvents.length,
        scanner_agents: scannerAgents.length,
        scanner_alerts: scannerAlerts.length,
        generated_keys: generatedKeys.length,
        certificates: certificates.length,
      },
    },
  }
}

router.get('/pqc-onboarding', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    return res.json({ data: await buildPqcOnboardingSnapshot(client, user) })
  } catch (err) {
    console.error('PQC onboarding dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch PQC onboarding telemetry' } })
  }
})

router.get('/pqc-onboarding/stream', async (req: Request, res: Response) => {
  const user = (req as any).user
  const token = (req as any).token
  const client = createAuthClient(token)

  if (!client) {
    return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
  }

  setSseHeaders(res)
  writeSse(res, 'connected', { timestamp: new Date().toISOString(), userId: user.id })

  const emitSnapshot = async () => {
    const snapshot = await buildPqcOnboardingSnapshot(client, user)
    writeSse(res, 'pqc-onboarding-update', snapshot)
  }

  await emitSnapshot().catch((error) => console.warn('PQC onboarding stream initial emit failed:', error?.message || error))
  const heartbeat = setInterval(() => writeSse(res, 'heartbeat', { ts: Date.now() }), 15_000)
  const poll = setInterval(() => emitSnapshot().catch(() => undefined), 8_000)

  req.on('close', () => {
    clearInterval(heartbeat)
    clearInterval(poll)
    res.end()
  })
})

function complianceControlScore(status: unknown) {
  const value = String(status || '').toLowerCase().replace(/[_-]+/g, ' ')
  if (/(compliant|passed|approved|complete|completed|validated|verified|enforced|ready|active)/.test(value) && !/(non compliant|failed|fail|risk)/.test(value)) return 100
  if (/(partial|in progress|pending|review|at risk|warning)/.test(value)) return 55
  if (/(non compliant|failed|fail|critical|blocked|expired)/.test(value)) return 0
  return 40
}

function compliancePolicyStatus(score: number) {
  return score >= 75 ? 'Compliant' : 'Review'
}

function complianceGovernanceStatus(score: number) {
  return score >= 75 ? 'Enforced' : 'Draft'
}

function certificateStatus(cert: any): 'Active' | 'Expired' | 'Expiring Soon' {
  const status = String(cert?.status || '').toLowerCase()
  const expiresAt = dateMs(cert?.not_after)
  if (status.includes('expired') || (expiresAt && expiresAt < Date.now())) return 'Expired'
  if (cert?.is_expiring_soon || (expiresAt && expiresAt < Date.now() + 30 * 86400000)) return 'Expiring Soon'
  return 'Active'
}

function complianceSeverityLabel(value: unknown): 'High' | 'Medium' | 'Low' {
  const rank = severityRank(String(value || ''))
  if (rank >= 3) return 'High'
  if (rank >= 2) return 'Medium'
  return 'Low'
}

function timeAgoLabel(value: unknown) {
  const ms = dateMs(value)
  if (!ms) return 'unsynced'
  const diff = Math.max(0, Date.now() - ms)
  const minutes = Math.floor(diff / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function controlMatcher(label: string, evidence: any[]) {
  const lowerLabel = label.toLowerCase()
  const primary = lowerLabel.split(/[ /()]+/).filter(Boolean)[0] || lowerLabel
  return evidence.filter((item) => {
    const text = `${item.framework || ''} ${item.control_id || ''} ${item.evidence_type || ''} ${item.description || ''}`.toLowerCase()
    return text.includes(lowerLabel) || text.includes(primary)
  })
}

function averageScore(scores: number[]) {
  if (!scores.length) return 0
  return clampPercent(scores.reduce((sum, score) => sum + score, 0) / scores.length)
}

function complianceFrameworkScore(label: string, evidence: any[], fallbackScore: number) {
  const matched = controlMatcher(label, evidence)
  if (!matched.length) return fallbackScore
  return averageScore(matched.map((item) => complianceControlScore(item.status)))
}

async function buildComplianceDashboardSnapshot(client: any, user: any) {
  const [
    assets,
    inventory,
    exposures,
    jobs,
    migrationEvents,
    scanSessions,
    scanResults,
    securityEvents,
    complianceEvidence,
    runtimeEvents,
    certificates,
    generatedKeys,
    vulnerabilities,
    scannerAlerts,
    scannerAgents,
    vaultAuditLogs,
    relationships,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1000)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(1600)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1600)),
    safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1000)),
    safeRows(client, 'migration_events', (q) => q.select('id, migration_id, event_type, message, severity, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, target_scope, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(160)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1800)),
    safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'compliance_evidence', (q) => q.select('id, asset_id, framework, control_id, status, evidence_type, description, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1000)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, package_name, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', user.id).order('observed_at', { ascending: false }).limit(2800)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, status, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1000)),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, label, purpose, status, entropy_source, quality_score, bit_length, expires_at, revoked_at, rotated_from, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'vulnerabilities', (q) => q.select('id, asset_id, title, description, severity, status, source, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1000)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, capabilities, last_seen_at, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'vault_audit_logs', (q) => q.select('id, event_type, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'asset_relationships', (q) => q.select('id, source_asset_id, target_asset_id, relationship_type, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
  ])

  const now = Date.now()
  const oneDay = 86400000
  const activeAssets = (assets || []).filter((asset: any) => String(asset.status || 'active').toLowerCase() !== 'archived')
  const assetMap = new Map<string, any>((activeAssets || []).map((asset: any) => [asset.id, asset]))
  const completedJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'completed')
  const runningJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'running')
  const pendingJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'pending')
  const failedJobs = (jobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'failed')
  const activeScans = (scanSessions || []).filter((scan: any) => ['pending', 'queued', 'running', 'analyzing'].includes(String(scan.status || '').toLowerCase()))
  const completedScans = (scanSessions || []).filter((scan: any) => String(scan.status || '').toLowerCase() === 'completed')
  const openAlerts = (scannerAlerts || []).filter((alert: any) => !['resolved', 'suppressed', 'closed'].includes(String(alert.status || '').toLowerCase()))
  const openVulnerabilities = (vulnerabilities || []).filter((vuln: any) => !['resolved', 'remediated', 'false_positive', 'closed'].includes(String(vuln.status || '').toLowerCase()))

  const safeInventory = (inventory || []).filter((item: any) => item.is_quantum_safe || isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`))
  const vulnerableInventory = (inventory || []).filter((item: any) => (item.is_vulnerable && !item.is_quantum_safe) || isLegacyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`))
  const pqcCertificates = (certificates || []).filter((cert: any) => cert.is_quantum_safe || isPqcReadyAlgorithm(`${cert.algorithm || ''}`))
  const expiredCertificates = (certificates || []).filter((cert: any) => certificateStatus(cert) === 'Expired')
  const expiringCertificates = (certificates || []).filter((cert: any) => certificateStatus(cert) === 'Expiring Soon')
  const activeCertificates = (certificates || []).filter((cert: any) => certificateStatus(cert) === 'Active')
  const secureKeys = (generatedKeys || []).filter((key: any) => {
    const status = String(key.status || 'active').toLowerCase()
    return !['revoked', 'expired', 'compromised'].includes(status) && isPqcReadyAlgorithm(`${key.algorithm || ''} ${key.bit_length || ''}`)
  })

  const vulnerableAssetIds = new Set<string>()
  for (const item of vulnerableInventory || []) if (item.asset_id) vulnerableAssetIds.add(item.asset_id)
  for (const exposure of exposures || []) if (severityRank(String(exposure.severity || '')) >= 3 && exposure.asset_id) vulnerableAssetIds.add(exposure.asset_id)
  for (const result of scanResults || []) if (severityRank(String(result.threat_level || '')) >= 3 && result.asset_id) vulnerableAssetIds.add(result.asset_id)
  for (const vuln of openVulnerabilities || []) if (vuln.asset_id) vulnerableAssetIds.add(vuln.asset_id)

  const quantumSafeAssetIds = new Set<string>()
  for (const item of safeInventory || []) if (item.asset_id) quantumSafeAssetIds.add(item.asset_id)
  for (const cert of pqcCertificates || []) if (cert.asset_id) quantumSafeAssetIds.add(cert.asset_id)
  for (const job of completedJobs || []) if (job.asset_id) quantumSafeAssetIds.add(job.asset_id)

  const criticalFindings =
    (exposures || []).filter((row: any) => severityRank(String(row.severity || '')) >= 4).length +
    (scanResults || []).filter((row: any) => severityRank(String(row.threat_level || '')) >= 4).length +
    openVulnerabilities.filter((row: any) => severityRank(String(row.severity || '')) >= 4).length +
    openAlerts.filter((row: any) => severityRank(String(row.severity || '')) >= 4).length
  const highFindings =
    (exposures || []).filter((row: any) => severityRank(String(row.severity || '')) >= 3).length +
    (scanResults || []).filter((row: any) => severityRank(String(row.threat_level || '')) >= 3).length +
    openVulnerabilities.filter((row: any) => severityRank(String(row.severity || '')) >= 3).length +
    openAlerts.filter((row: any) => severityRank(String(row.severity || '')) >= 3).length

  const hndlFindings = [
    ...(scanResults || []).filter((row: any) => isHndlScanFinding(row)),
    ...(runtimeEvents || []).filter((row: any) => row.hndl_risk),
    ...(securityEvents || []).filter((row: any) => /harvest now|decrypt later|hndl/i.test(`${row.event_type || ''} ${row.message || ''}`)),
  ]
  const runtimeRisks = (runtimeEvents || []).filter((event: any) => event.is_legacy || event.downgrade_detected || event.shadow_crypto || event.hndl_risk || severityRank(String(event.severity || '')) >= 3)
  const runtimeEvents24h = (runtimeEvents || []).filter((event: any) => dateMs(event.observed_at || event.created_at) >= now - oneDay).length
  const hybridDeployments = (inventory || []).filter((item: any) => /hybrid/i.test(`${item.algorithm || ''} ${item.protocol || ''} ${JSON.stringify(item.metadata || {})}`)).length
  const mlKemDeployments = (inventory || []).filter((item: any) => /ml-kem|kyber/i.test(`${item.algorithm || ''} ${item.protocol || ''}`)).length + (jobs || []).filter((job: any) => /ml-kem|kyber/i.test(`${job.target_algorithm || ''}`)).length
  const mlDsaDeployments = (inventory || []).filter((item: any) => /ml-dsa|dilithium/i.test(`${item.algorithm || ''} ${item.protocol || ''}`)).length + (jobs || []).filter((job: any) => /ml-dsa|dilithium/i.test(`${job.target_algorithm || ''}`)).length

  const totalAssets = activeAssets.length
  const totalCryptoItems = (inventory || []).length + (certificates || []).length + (generatedKeys || []).length
  const pqcComponentScore = percentOf(safeInventory.length + pqcCertificates.length + secureKeys.length, Math.max(1, totalCryptoItems))
  const pqcAssetScore = percentOf(quantumSafeAssetIds.size, Math.max(1, totalAssets))
  const migrationCompletionRate = percentOf(completedJobs.length, Math.max(1, (jobs || []).length))
  const qScore = clampPercent(100 - Math.min(100, criticalFindings * 8 + highFindings * 3 + failedJobs.length * 5 + expiredCertificates.length * 3 + hndlFindings.length * 4))
  const readinessScore = clampPercent(pqcAssetScore * 0.42 + pqcComponentScore * 0.38 + migrationCompletionRate * 0.2)
  const evidenceScore = complianceEvidence.length ? averageScore((complianceEvidence || []).map((item: any) => complianceControlScore(item.status))) : 0
  const validationScore = clampPercent(readinessScore * 0.35 + qScore * 0.25 + evidenceScore * 0.25 + percentOf(completedScans.length, Math.max(1, (scanSessions || []).length)) * 0.15)
  const complianceScore = clampPercent(readinessScore * 0.34 + qScore * 0.24 + evidenceScore * 0.27 + validationScore * 0.15)
  const policyAdherence = complianceScore
  const remediatedItems = completedJobs.length + (migrationEvents || []).filter((event: any) => /remediat|resolved|rotated|completed|mitigated/i.test(`${event.event_type || ''} ${event.message || ''}`)).length

  const frameworkLabels = ['NIST SP 800-208', 'NIST SP 800-57', 'NIST SP 800-131A', 'CNSA 2.0', 'FIPS 203 (ML-KEM)', 'FIPS 204 (ML-DSA)', 'FIPS 205 (SLH-DSA)', 'ISO/IEC 27001']
  const frameworkAlignment = frameworkLabels.map((label) => ({
    name: label,
    score: complianceFrameworkScore(label, complianceEvidence || [], label.includes('FIPS 203') ? Math.max(readinessScore, mlKemDeployments ? 75 : 0) : label.includes('FIPS 204') ? Math.max(readinessScore, mlDsaDeployments ? 75 : 0) : complianceScore),
  }))

  const controlGroups = [
    { name: 'Cryptographic Inventory Coverage', category: 'Discovery', score: percentOf((inventory || []).length, Math.max(1, totalAssets)), updated: latestDate(...(inventory || []).map((row: any) => row.discovered_at || row.created_at)) },
    { name: 'Quantum Risk Classification', category: 'Risk', score: qScore, updated: latestDate(...(exposures || []).map((row: any) => row.updated_at || row.created_at), ...(scanResults || []).map((row: any) => row.created_at)) },
    { name: 'PQC Migration Execution', category: 'Migration', score: migrationCompletionRate, updated: latestDate(...(jobs || []).map((row: any) => row.updated_at || row.completed_at || row.created_at)) },
    { name: 'Runtime Crypto Monitoring', category: 'Monitoring', score: runtimeEvents.length ? qScore : 0, updated: latestDate(...(runtimeEvents || []).map((row: any) => row.observed_at || row.created_at)) },
    { name: 'Certificate Lifecycle Control', category: 'Certificates', score: percentOf(activeCertificates.length + pqcCertificates.length, Math.max(1, (certificates || []).length * 2)), updated: latestDate(...(certificates || []).map((row: any) => row.updated_at || row.created_at)) },
    { name: 'Audit Evidence Retention', category: 'Audit', score: evidenceScore || percentOf((vaultAuditLogs || []).length, Math.max(1, totalAssets)), updated: latestDate(...(complianceEvidence || []).map((row: any) => row.updated_at || row.created_at), ...(vaultAuditLogs || []).map((row: any) => row.created_at)) },
    { name: 'HNDL Mitigation Control', category: 'Remediation', score: hndlFindings.length ? percentOf(remediatedItems, remediatedItems + hndlFindings.length) : qScore, updated: latestDate(...hndlFindings.map((row: any) => row.observed_at || row.created_at || row.updated_at)) },
    { name: 'Vendor Trust Dependency Tracking', category: 'Third Party', score: relationships.length ? complianceScore : 0, updated: latestDate(...(relationships || []).map((row: any) => row.created_at)) },
  ]

  const evidencePolicies = (complianceEvidence || []).slice(0, 10).map((item: any) => {
    const score = complianceControlScore(item.status)
    return {
      name: textValue(item.control_id, textValue(item.framework, 'Compliance Control')),
      category: textValue(item.framework, textValue(item.evidence_type, 'Compliance')),
      status: compliancePolicyStatus(score),
      lastReviewed: new Date(dateMs(item.updated_at || item.created_at) || now).toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }),
    }
  })
  const policies = (evidencePolicies.length ? evidencePolicies : controlGroups.map((control) => ({
    name: control.name,
    category: control.category,
    status: compliancePolicyStatus(control.score),
    lastReviewed: control.updated ? new Date(control.updated).toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }) : 'No evidence',
  }))).slice(0, 8)

  const governancePolicyMatrix = controlGroups.map((control) => ({
    name: control.name,
    category: control.category,
    status: complianceGovernanceStatus(control.score),
    coverage: control.score,
    updated: control.updated ? new Date(control.updated).toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }) : 'Awaiting evidence',
  }))

  const certificatesRows = (certificates || []).slice(0, 8).map((cert: any) => ({
    algorithm: textValue(cert.algorithm, 'Unknown'),
    issuedTo: textValue(cert.subject || cert.name, textValue(assetMap.get(cert.asset_id)?.name, 'Unassigned asset')),
    issuedOn: new Date(dateMs(cert.created_at) || now).toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }),
    expiresOn: cert.not_after ? new Date(dateMs(cert.not_after)).toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }) : 'Not recorded',
    status: certificateStatus(cert),
  }))

  const policyViolations: any[] = []
  const addViolation = (input: any) => {
    if (!input.title || policyViolations.some((row) => row.id === input.id)) return
    policyViolations.push(input)
  }
  for (const exposure of (exposures || []).filter((row: any) => severityRank(String(row.severity || '')) >= 2).slice(0, 8)) {
    addViolation({
      id: `exposure-${exposure.id}`,
      title: titleCase(textValue(exposure.exposure_type || exposure.description, 'Crypto exposure')),
      detail: textValue(exposure.description, textValue(exposure.detected_value, 'Cryptographic exposure requires review')),
      severity: complianceSeverityLabel(exposure.severity),
      time: timeAgoLabel(exposure.updated_at || exposure.created_at),
      type: severityRank(String(exposure.severity || '')) >= 3 ? 'warning' : 'info',
    })
  }
  for (const evidence of (complianceEvidence || []).filter((row: any) => complianceControlScore(row.status) < 75).slice(0, 8)) {
    addViolation({
      id: `evidence-${evidence.id}`,
      title: textValue(evidence.control_id, textValue(evidence.framework, 'Compliance evidence review')),
      detail: textValue(evidence.description, `Control status: ${textValue(evidence.status, 'review')}`),
      severity: complianceControlScore(evidence.status) <= 0 ? 'High' : 'Medium',
      time: timeAgoLabel(evidence.updated_at || evidence.created_at),
      type: 'warning',
    })
  }
  for (const vuln of openVulnerabilities.slice(0, 8)) {
    addViolation({
      id: `vuln-${vuln.id}`,
      title: textValue(vuln.title, 'Open vulnerability'),
      detail: textValue(vuln.description, textValue(vuln.source, 'Vulnerability needs remediation')),
      severity: complianceSeverityLabel(vuln.severity),
      time: timeAgoLabel(vuln.updated_at || vuln.created_at),
      type: 'warning',
    })
  }
  policyViolations.sort((a, b) => severityRank(a.severity) - severityRank(b.severity)).reverse()

  const trend = Array.from({ length: 7 }, (_, index) => {
    const start = startOfDayMs(6 - index)
    const end = start + oneDay
    const evidenceBucket = (complianceEvidence || []).filter((row: any) => {
      const time = dateMs(row.updated_at || row.created_at)
      return time >= start && time < end
    })
    const riskBucket =
      (exposures || []).filter((row: any) => dateMs(row.updated_at || row.created_at) >= start && dateMs(row.updated_at || row.created_at) < end).length +
      (scanResults || []).filter((row: any) => dateMs(row.created_at) >= start && dateMs(row.created_at) < end).length +
      (securityEvents || []).filter((row: any) => dateMs(row.created_at) >= start && dateMs(row.created_at) < end && severityRank(String(row.severity || '')) >= 2).length
    const migrationBucket = (jobs || []).filter((row: any) => dateMs(row.completed_at || row.updated_at) >= start && dateMs(row.completed_at || row.updated_at) < end && normalizeJobStatus(row.status) === 'completed').length
    const bucketScore = evidenceBucket.length
      ? averageScore(evidenceBucket.map((row: any) => complianceControlScore(row.status)))
      : clampPercent(complianceScore - Math.max(0, 6 - index) * Math.max(1, Math.round((riskBucket - migrationBucket) / 2)))
    return {
      label: dateLabel(start),
      value: bucketScore,
    }
  })

  const compliantRequirements = frameworkAlignment.filter((row) => row.score >= 75).length + safeInventory.length + pqcCertificates.length + completedJobs.length
  const partialRequirements = frameworkAlignment.filter((row) => row.score > 0 && row.score < 75).length + runningJobs.length + pendingJobs.length
  const nonCompliantRequirements = criticalFindings + highFindings + failedJobs.length + expiredCertificates.length
  const notApplicableRequirements = Math.max(0, totalAssets - new Set((inventory || []).map((row: any) => row.asset_id).filter(Boolean)).size)

  const requirementBreakdown = [
    { label: 'Compliant', value: compliantRequirements, color: '#42D95B' },
    { label: 'Partially Compliant', value: partialRequirements, color: '#FFCF33' },
    { label: 'Non-Compliant', value: nonCompliantRequirements, color: '#FF5D52' },
    { label: 'Not Applicable', value: notApplicableRequirements, color: '#B8B8B8' },
  ]

  const maturityLevels = [
    { label: 'Level 5 - Optimized', value: complianceScore >= 90 ? Math.max(5, complianceScore - 82) : 0, color: '#FFD36B' },
    { label: 'Level 4 - Managed', value: complianceScore >= 70 ? Math.min(55, Math.max(8, complianceScore - 42)) : 0, color: '#D49B18' },
    { label: 'Level 3 - Defined', value: complianceScore >= 45 ? Math.min(60, Math.max(10, complianceScore - 30)) : 0, color: '#8F6B19' },
    { label: 'Level 2 - Repeatable', value: complianceScore >= 20 ? Math.min(50, Math.max(8, complianceScore - 12)) : 0, color: '#4D3910' },
    { label: 'Level 1 - Initial', value: complianceScore < 20 ? Math.max(5, complianceScore) : Math.max(0, 100 - complianceScore), color: '#2B210B' },
  ]

  const latestActivityAt = latestDate(
    ...(securityEvents || []).map((row: any) => row.created_at),
    ...(migrationEvents || []).map((row: any) => row.created_at),
    ...(runtimeEvents || []).map((row: any) => row.observed_at || row.created_at),
    ...(complianceEvidence || []).map((row: any) => row.updated_at || row.created_at),
    ...(scanSessions || []).map((row: any) => row.updated_at || row.completed_at || row.started_at || row.created_at),
  )

  return {
    generatedAt: new Date().toISOString(),
    source: {
      mode: 'authenticated-live-aggregate',
      latestActivityAt,
      latestScanAt: latestDate(...(scanSessions || []).map((row: any) => row.completed_at || row.updated_at || row.started_at || row.created_at)),
      tables: {
        assets: activeAssets.length,
        cryptoInventory: (inventory || []).length,
        cryptoExposures: (exposures || []).length,
        scanResults: (scanResults || []).length,
        migrationJobs: (jobs || []).length,
        runtimeEvents: (runtimeEvents || []).length,
        complianceEvidence: (complianceEvidence || []).length,
        certificates: (certificates || []).length,
        generatedKeys: (generatedKeys || []).length,
        scannerAlerts: openAlerts.length,
      },
    },
    metrics: {
      complianceScore,
      qScore,
      readinessScore,
      validationScore,
      policyAdherence,
      totalAssets,
      totalComponents: totalCryptoItems,
      vulnerableAssets: vulnerableAssetIds.size,
      vulnerableComponents: vulnerableInventory.length,
      quantumSecuredAssets: quantumSafeAssetIds.size,
      pqcReadyComponents: safeInventory.length + pqcCertificates.length + secureKeys.length,
      criticalFindings,
      highFindings,
      openFindings: policyViolations.length + openAlerts.length,
      totalCertificates: (certificates || []).length,
      activeCertificates: activeCertificates.length,
      expiredCertificates: expiredCertificates.length,
      expiringCertificates: expiringCertificates.length,
      totalPolicies: Math.max(controlGroups.length, policies.length, frameworkAlignment.length),
      enforcedPolicies: governancePolicyMatrix.filter((row) => row.status === 'Enforced').length,
      activeScans: activeScans.length,
      completedScans: completedScans.length,
      activeMigrationJobs: runningJobs.length + pendingJobs.length,
      completedMigrationJobs: completedJobs.length,
      failedMigrationJobs: failedJobs.length,
      migrationCompletionRate,
      hybridDeployments,
      mlKemDeployments,
      mlDsaDeployments,
      keyCount: (generatedKeys || []).length,
      secureKeys: secureKeys.length,
      auditEvents: (vaultAuditLogs || []).length + (complianceEvidence || []).length,
      runtimeEvents24h,
      hndlExposures: hndlFindings.length,
      remediatedItems,
      scannerAgents: (scannerAgents || []).length,
      trustDependencies: (relationships || []).length,
    },
    checklist: [
      { label: 'Asset discovery status synchronized', complete: activeAssets.length > 0, detail: `${activeAssets.length} active assets` },
      { label: 'Crypto inventory / CBOM evidence available', complete: (inventory || []).length > 0, detail: `${(inventory || []).length} crypto inventory rows` },
      { label: 'Quantum risk scoring calculated', complete: totalCryptoItems > 0 || criticalFindings > 0 || highFindings > 0, detail: `Q-Score ${qScore}` },
      { label: 'PQC migration execution tracked', complete: (jobs || []).length > 0, detail: `${completedJobs.length}/${(jobs || []).length} jobs completed` },
      { label: 'Runtime telemetry and drift monitored', complete: runtimeEvents.length > 0 || securityEvents.length > 0, detail: `${runtimeEvents24h} runtime events in 24h` },
      { label: 'Audit and compliance evidence retained', complete: (complianceEvidence || []).length > 0 || (vaultAuditLogs || []).length > 0, detail: `${(complianceEvidence || []).length} evidence rows` },
      { label: 'Post-quantum readiness validated', complete: complianceScore >= 80, detail: `${complianceScore}% compliance score` },
    ],
    certificates: certificatesRows,
    policies,
    frameworkAlignment,
    maturityLevels,
    policyTrend: trend,
    governancePolicyMatrix,
    policyViolations: policyViolations.slice(0, 8),
    requirementBreakdown,
    capabilityHighlights: [
      { label: 'Policy Enforcement', detail: `${governancePolicyMatrix.filter((row) => row.status === 'Enforced').length} controls enforced`, iconKey: 'shield' },
      { label: 'Audit Trail', detail: `${(vaultAuditLogs || []).length + (complianceEvidence || []).length} evidence events`, iconKey: 'audit' },
      { label: 'Automated Compliance', detail: `${activeScans.length} active scans, ${runtimeEvents24h} runtime events`, iconKey: 'check' },
      { label: 'Risk Based Approach', detail: `${criticalFindings + highFindings} prioritized findings`, iconKey: 'target' },
      { label: 'Migration Readiness', detail: `${migrationCompletionRate}% migration completion`, iconKey: 'clipboard' },
      { label: 'Trust Dependencies', detail: `${(relationships || []).length} dependency links tracked`, iconKey: 'building' },
    ],
    telemetry: [
      ...(runtimeEvents || []).slice(0, 8).map((event: any) => ({
        id: `runtime-${event.id}`,
        source: 'runtime_crypto_events',
        title: titleCase(textValue(event.event_type, 'Runtime crypto event')),
        detail: textValue(event.asset_name || event.host || event.algorithm || event.cipher_suite, 'Runtime telemetry observed'),
        severity: String(event.severity || 'low'),
        timestamp: event.observed_at || event.created_at,
      })),
      ...(securityEvents || []).slice(0, 8).map((event: any) => ({
        id: `security-${event.id}`,
        source: 'security_events',
        title: titleCase(textValue(event.event_type, 'Security event')),
        detail: textValue(event.message || event.resource_name, 'Security telemetry observed'),
        severity: String(event.severity || 'low'),
        timestamp: event.created_at,
      })),
      ...(migrationEvents || []).slice(0, 8).map((event: any) => ({
        id: `migration-${event.id}`,
        source: 'migration_events',
        title: titleCase(textValue(event.event_type, 'Migration event')),
        detail: textValue(event.message, 'Migration telemetry observed'),
        severity: String(event.severity || 'low'),
        timestamp: event.created_at,
      })),
    ].sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp)).slice(0, 16),
  }
}

router.get('/compliance', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    return res.json({ data: await buildComplianceDashboardSnapshot(client, user) })
  } catch (err) {
    console.error('Compliance dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch compliance telemetry' } })
  }
})

router.get('/compliance/stream', async (req: Request, res: Response) => {
  const user = (req as any).user
  const token = (req as any).token
  const client = createAuthClient(token)

  if (!client) {
    return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
  }

  setSseHeaders(res)
  writeSse(res, 'compliance-connected', { timestamp: new Date().toISOString(), userId: user.id })

  const emitSnapshot = async () => {
    const snapshot = await buildComplianceDashboardSnapshot(client, user)
    writeSse(res, 'compliance-update', snapshot)
  }

  await emitSnapshot().catch((error) => console.warn('Compliance stream initial emit failed:', error?.message || error))
  const heartbeat = setInterval(() => writeSse(res, 'heartbeat', { ts: Date.now() }), 15_000)
  const poll = setInterval(() => emitSnapshot().catch(() => undefined), 8_000)

  req.on('close', () => {
    clearInterval(heartbeat)
    clearInterval(poll)
    res.end()
  })
})

type HndlRemediationCandidate = {
  findingId: string
  assetId: string | null
  name: string
  subtitle: string
  assetName: string
  environment: string
  assetType: string
  priority: string
  detectedAt: string
  algorithm: string
  category: string
  recommendation: string
  targetAlgorithm: string
  jobType: string
}

function linkedHndlFindingId(job: any) {
  const metadata = recordOf(job?.metadata)
  return textValue(metadata.hndlFindingId || metadata.hndl_finding_id || metadata.sourceFindingId || metadata.source_finding_id, '')
}

function hndlFindingSeverity(row: any) {
  const metadata = recordOf(row?.metadata)
  const raw = recordOf(metadata.raw)
  return textValue(
    row?.threat_level ||
    metadata.severity ||
    metadata.threatLevel ||
    metadata.threat_level ||
    raw.severity ||
    raw.threatLevel ||
    raw.threat_level,
    'low'
  )
}

function hndlPriority(row: any) {
  const severity = hndlFindingSeverity(row).toLowerCase()
  if (severity === 'critical') return 'Critical'
  if (severity === 'high') return 'High'
  if (severity === 'moderate' || severity === 'medium') return 'Medium'
  if (severity === 'safe' || severity === 'info') return 'Low'
  return titleCase(severity || 'Low')
}

function hndlFindingText(row: any) {
  const metadata = recordOf(row?.metadata)
  const raw = recordOf(metadata.raw)
  return [
    row?.finding_type,
    row?.algorithm,
    row?.description,
    row?.remediation,
    row?.threat_level,
    metadata.algorithm,
    metadata.category,
    metadata.status,
    metadata.evidence,
    metadata.recommendation,
    metadata.source,
    raw.algorithm,
    raw.category,
    raw.status,
    raw.evidence,
    raw.recommendation,
    raw.source,
  ].filter(Boolean).join(' ').toLowerCase()
}

function isHndlScanFinding(row: any) {
  const severity = severityRank(hndlFindingSeverity(row))
  const text = hndlFindingText(row)
  return severity >= 2 || /rsa|ecc|ecdsa|ecdh|dhe|diffie|dsa|sha-1|sha1|md5|legacy|vulnerable|hndl|harvest|decrypt|quantum/.test(text)
}

function hndlJobType(row: any) {
  const text = hndlFindingText(row)
  if (text.includes('cert')) return 'cert_transition'
  if (text.includes('tls') || text.includes('ssh') || text.includes('protocol') || text.includes('key exchange') || text.includes('kex')) return 'protocol_upgrade'
  if (text.includes('sign') || text.includes('jwt') || text.includes('ecdsa') || text.includes('dsa')) return 'signature_transition'
  if (text.includes('encrypt') || text.includes('database') || text.includes('storage')) return 'encryption_upgrade'
  return 'hndl_remediation'
}

function hndlDetectedAt(row: any) {
  const metadata = recordOf(row?.metadata)
  const raw = recordOf(metadata.raw)
  return textValue(
    row?.created_at ||
    metadata.detectedAt ||
    metadata.detected_at ||
    metadata.timestamp ||
    raw.detectedAt ||
    raw.detected_at ||
    raw.timestamp,
    new Date().toISOString()
  )
}

function hndlAssetName(row: any, asset: any) {
  const metadata = recordOf(row?.metadata)
  const raw = recordOf(metadata.raw)
  return textValue(asset?.name || raw.location || metadata.location || metadata.target || row?.description, 'Unassigned HNDL asset')
}

function hndlRowsFromScanSessions(scanSessions: any[]) {
  const rows: any[] = []

  for (const session of scanSessions || []) {
    const metadata = recordOf(session?.metadata)
    const results = Array.isArray(metadata.results) ? metadata.results : []

    results.forEach((result: any, resultIndex: number) => {
      const findings = Array.isArray(result?.findings) ? result.findings : []
      findings.forEach((finding: any, findingIndex: number) => {
        const findingMetadata = recordOf(finding?.metadata)
        const raw = recordOf(finding?.raw)
        const createdAt = textValue(
          finding?.timestamp ||
          finding?.detectedAt ||
          finding?.detected_at ||
          raw.timestamp ||
          raw.detectedAt ||
          raw.detected_at ||
          result?.startedAt ||
          result?.started_at ||
          session?.started_at ||
          session?.created_at,
          new Date().toISOString()
        )

        rows.push({
          id: String(finding?.id || raw.id || `${session?.id || 'session'}-hndl-${resultIndex}-${findingIndex}`),
          scan_session_id: session?.id || null,
          asset_id: finding?.asset_id || raw.asset_id || null,
          finding_type: finding?.category || raw.category || finding?.type || 'HNDL finding',
          algorithm: finding?.algorithm || raw.algorithm || finding?.name || 'Detected cryptographic exposure',
          threat_level: finding?.threatLevel || finding?.severity || raw.threatLevel || raw.severity || findingMetadata.threatLevel || findingMetadata.severity,
          description: finding?.description || raw.description || 'Harvest Now, Decrypt Later exposure',
          remediation: finding?.recommendation || raw.recommendation || findingMetadata.recommendation,
          metadata: {
            ...findingMetadata,
            raw: finding?.raw || finding,
            target: result?.target || session?.target_scope,
            location: finding?.location || raw.location || result?.target || session?.target_scope,
            status: finding?.status || raw.status,
            evidence: finding?.evidence || raw.evidence,
            source: finding?.source || raw.source || 'authorized-scanner-history',
            timestamp: createdAt,
          },
          created_at: createdAt,
        })
      })
    })
  }

  return rows
}

function buildHndlRemediationCandidates(scanResults: any[], assets: any[], jobs: any[]) {
  const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
  const linkedFindingIds = new Set((jobs || []).map(linkedHndlFindingId).filter(Boolean))
  const seen = new Set<string>()
  const candidates: HndlRemediationCandidate[] = []

  for (const row of scanResults || []) {
    const findingId = String(row?.id || '')
    if (!findingId || seen.has(findingId) || linkedFindingIds.has(findingId) || !isHndlScanFinding(row)) continue
    seen.add(findingId)

    const metadata = recordOf(row?.metadata)
    const raw = recordOf(metadata.raw)
    const asset = row?.asset_id ? assetMap.get(row.asset_id) : null
    const category = textValue(row?.finding_type || metadata.category || raw.category, 'HNDL finding')
    const algorithm = textValue(row?.algorithm || metadata.algorithm || raw.algorithm, category)
    const priority = hndlPriority(row)
    const targetAlgorithm = replacementForAlgorithm(algorithm, category)
    const assetName = hndlAssetName(row, asset)

    candidates.push({
      findingId,
      assetId: row?.asset_id || null,
      name: `HNDL Remediation: ${assetName}`,
      subtitle: `${titleCase(category)} detected by Harvest Now telemetry`,
      assetName,
      environment: textValue(asset?.environment || metadata.environment || raw.environment, 'tenant scope'),
      assetType: textValue(asset?.type || category, 'HNDL finding'),
      priority,
      detectedAt: hndlDetectedAt(row),
      algorithm,
      category,
      recommendation: textValue(row?.remediation || metadata.recommendation || raw.recommendation, 'Create a PQC remediation workflow and validate the asset after mitigation.'),
      targetAlgorithm,
      jobType: hndlJobType(row),
    })
  }

  return candidates.sort((a, b) => {
    const priorityDiff = severityRank(b.priority) - severityRank(a.priority)
    if (priorityDiff) return priorityDiff
    return dateMs(b.detectedAt) - dateMs(a.detectedAt)
  })
}

function hndlWorkflowFromCandidate(candidate: HndlRemediationCandidate) {
  return {
    id: `hndl-${candidate.findingId}`,
    name: candidate.name,
    subtitle: candidate.subtitle,
    assetName: candidate.assetName,
    environment: candidate.environment,
    assetType: candidate.assetType,
    status: 'pending',
    rawStatus: 'hndl_pending',
    priority: candidate.priority,
    eta: 'Queue required',
    progress: 0,
    targetAlgorithm: candidate.targetAlgorithm,
    currentStep: 'HNDL remediation intake',
    startedAt: null,
    completedAt: null,
    updatedAt: candidate.detectedAt,
    events: [],
    source: 'harvest-now',
    sourceFindingId: candidate.findingId,
    materialized: false,
  }
}

function migrationJobFromHndlCandidate(userId: string, candidate: HndlRemediationCandidate) {
  return {
    user_id: userId,
    asset_id: candidate.assetId,
    name: candidate.name,
    job_type: candidate.jobType,
    status: 'pending',
    target_algorithm: candidate.targetAlgorithm,
    strategy: 'hndl_mitigate_validate',
    progress: 0,
    metadata: {
      source: 'harvest-now',
      workflow: 'hndl-remediation',
      hndlFindingId: candidate.findingId,
      sourceFindingId: candidate.findingId,
      subtitle: candidate.subtitle,
      priority: candidate.priority,
      eta: 'Pending launch',
      assetName: candidate.assetName,
      environment: candidate.environment,
      algorithm: candidate.algorithm,
      category: candidate.category,
      recommendation: candidate.recommendation,
      responseWindowHours: 1,
    },
  }
}

const HNDL_DEFENSE_ACTIONS: Record<string, {
  actionType: string
  label: string
  detail: string
  eventType: string
  assetClass: string
  optionLabel: string
  redirectPath: string
  severity: 'critical' | 'warning' | 'info'
  playbook: string[]
}> = {
  isolate_asset: {
    actionType: 'isolate_asset',
    label: 'Isolate Asset',
    detail: 'Block propagation by isolating affected assets or network paths.',
    eventType: 'hndl-defense-isolate-asset',
    assetClass: 'network_protocol',
    optionLabel: 'Isolate affected asset',
    redirectPath: '/dashboard/assets',
    severity: 'critical',
    playbook: ['Confirm owner and blast radius', 'Apply approved containment policy', 'Validate asset isolation with fresh telemetry'],
  },
  kill_process: {
    actionType: 'kill_process',
    label: 'Kill Process',
    detail: 'Terminate or quarantine the runtime process producing HNDL telemetry.',
    eventType: 'hndl-defense-kill-process',
    assetClass: 'code_application',
    optionLabel: 'Terminate malicious process',
    redirectPath: '/dashboard/runtime-crypto-intel',
    severity: 'critical',
    playbook: ['Identify process and workload owner', 'Terminate or quarantine through the authorized agent', 'Rescan runtime crypto events for recurrence'],
  },
  revoke_credentials: {
    actionType: 'revoke_credentials',
    label: 'Revoke Credentials',
    detail: 'Invalidate exposed credentials, tokens, certificates, and key bindings.',
    eventType: 'hndl-defense-revoke-credentials',
    assetClass: 'identity_access',
    optionLabel: 'Revoke exposed credentials',
    redirectPath: '/dashboard/identity-trust',
    severity: 'critical',
    playbook: ['Locate exposed identity or key material', 'Rotate or revoke through connector-approved controls', 'Validate new credential evidence'],
  },
  patch_harden: {
    actionType: 'patch_harden',
    label: 'Patch & Harden',
    detail: 'Apply TLS, crypto policy, dependency, or platform hardening.',
    eventType: 'hndl-defense-patch-harden',
    assetClass: 'network_protocol',
    optionLabel: 'Patch and harden HNDL exposure',
    redirectPath: '/dashboard/scanner',
    severity: 'warning',
    playbook: ['Create approved patch plan', 'Apply change through agent, connector, or operator workflow', 'Rescan target and validate HNDL risk is cleared'],
  },
  backup_restore: {
    actionType: 'backup_restore',
    label: 'Backup & Restore',
    detail: 'Recover affected service or configuration from a known-clean baseline.',
    eventType: 'hndl-defense-backup-restore',
    assetClass: 'code_application',
    optionLabel: 'Backup and restore clean baseline',
    redirectPath: '/dashboard/migration-sandbox',
    severity: 'warning',
    playbook: ['Snapshot current state', 'Restore known-clean baseline or configuration', 'Run sandbox validation before production cutover'],
  },
  deploy_honeypot: {
    actionType: 'deploy_honeypot',
    label: 'Deploy Honeypot',
    detail: 'Divert suspicious activity into monitored deception telemetry.',
    eventType: 'hndl-defense-deploy-honeypot',
    assetClass: 'network_protocol',
    optionLabel: 'Deploy HNDL deception monitor',
    redirectPath: '/dashboard/runtime-crypto-intel',
    severity: 'warning',
    playbook: ['Define decoy scope and safe telemetry boundary', 'Deploy monitored deception endpoint', 'Correlate runtime events and scanner alerts'],
  },
}

function harvestRedirect(path: string, actionType: string, extra: Record<string, string | number | boolean | null | undefined> = {}) {
  const params = new URLSearchParams({
    source: 'harvest-now',
    defenseAction: actionType,
  })
  for (const [key, value] of Object.entries(extra)) {
    if (value !== null && value !== undefined && value !== '') params.set(key, String(value))
  }
  return `${path}?${params.toString()}`
}

function migrationJobFromDefenseThreat(userId: string, threat: any, action: typeof HNDL_DEFENSE_ACTIONS[string], now: string) {
  const row = recordOf(threat)
  const findingId = textValue(row.id, `hndl-defense-${Date.now()}`)
  const assetName = textValue(row.location, 'Tenant HNDL scope')
  const severity = textValue(row.severity, 'High')
  const algorithm = textValue(row.name, 'Harvest Now, Decrypt Later exposure')
  return {
    user_id: userId,
    asset_id: null,
    name: `HNDL Remediation: ${assetName}`,
    job_type: 'hndl_remediation',
    status: 'pending',
    target_algorithm: replacementForAlgorithm(algorithm, 'hndl remediation'),
    strategy: 'hndl_mitigate_validate',
    progress: 0,
    metadata: {
      source: 'harvest-now',
      workflow: 'hndl-remediation',
      hndlFindingId: findingId,
      sourceFindingId: findingId,
      subtitle: `${action.label} response from Harvest Now telemetry`,
      priority: titleCase(severity),
      eta: 'Pending launch',
      assetName,
      environment: 'tenant scope',
      algorithm,
      category: 'HNDL defense action',
      recommendation: textValue(row.recommendation, action.detail),
      responseWindowHours: 1,
      defenseAction: action.actionType,
      defenseActionLabel: action.label,
      defensePlaybook: action.playbook,
      requestedAt: now,
    },
  }
}

router.post('/harvest-now/defense-action', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)
    const body = recordOf(req.body)
    const actionType = textValue(body.actionType || body.action_type, '').replace(/-/g, '_').toLowerCase()
    const action = HNDL_DEFENSE_ACTIONS[actionType]

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }
    if (!action) {
      return res.status(400).json({ error: { code: 'INVALID_DEFENSE_ACTION', message: 'Unsupported Harvest Now defense action' } })
    }

    const now = new Date().toISOString()
    const requestedFindingIds = new Set(
      (Array.isArray(body.threatIds) ? body.threatIds : [])
        .map((item) => String(item || '').trim())
        .filter(Boolean)
    )
    const activeThreatCount = Math.max(0, Number(body.activeThreatCount || 0))
    const linkedSignalCount = Math.max(0, Number(body.linkedSignalCount || activeThreatCount || 0))
    const primaryThreat = recordOf(body.primaryThreat)
    const threats = Array.isArray(body.threats) ? body.threats.slice(0, 25).map(recordOf) : []

    const [assets, jobs, scanResults, scanSessions] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, service_owner, criticality, status, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
      safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, target_scope, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(80)),
    ])

    const existingHndlJobs = (jobs || [])
      .filter((job: any) => {
        const findingId = linkedHndlFindingId(job)
        const metadata = recordOf(job.metadata)
        const source = textValue(metadata.source, '')
        const workflow = textValue(metadata.workflow, '')
        const rawStatus = String(job.status || '').toLowerCase()
        const active = normalizeJobStatus(job.status) !== 'completed' && !['cancelled', 'canceled'].includes(rawStatus)
        const requested = requestedFindingIds.size === 0 || (findingId && requestedFindingIds.has(findingId))
        return active && requested && (source === 'harvest-now' || workflow === 'hndl-remediation' || Boolean(findingId))
      })
      .slice(0, 100)

    const candidates = buildHndlRemediationCandidates([...(scanResults || []), ...hndlRowsFromScanSessions(scanSessions || [])], assets || [], jobs || [])
      .filter((candidate) => requestedFindingIds.size === 0 || requestedFindingIds.has(candidate.findingId))

    let createdJobs: any[] = []
    const rows = candidates.map((candidate) => {
      const job = migrationJobFromHndlCandidate(user.id, candidate)
      return {
        ...job,
        metadata: {
          ...job.metadata,
          defenseAction: action.actionType,
          defenseActionLabel: action.label,
          defensePlaybook: action.playbook,
          requestedAt: now,
        },
      }
    })

    if (rows.length === 0 && existingHndlJobs.length === 0 && (primaryThreat.id || threats.length > 0)) {
      rows.push(migrationJobFromDefenseThreat(user.id, primaryThreat.id ? primaryThreat : threats[0], action, now))
    }

    if (rows.length > 0) {
      const { data: inserted, error } = await client
        .from('migration_jobs')
        .insert(rows)
        .select('id, name, status, metadata, created_at, updated_at')

      if (error) {
        return res.status(500).json({ error: { code: 'DEFENSE_WORKFLOW_QUEUE_FAILED', message: error.message || 'Failed to queue Harvest Now defense workflows' } })
      }
      createdJobs = inserted || []
    }

    const linkedJobs = [...existingHndlJobs, ...createdJobs]
    const primaryJob = linkedJobs[0] || null
    const patchPlan = {
      optionId: `harvest-${action.actionType}`,
      optionLabel: action.optionLabel,
      target: textValue(primaryThreat.location, textValue(primaryThreat.name, 'Tenant HNDL scope')),
      summary: action.detail,
      validation: 'Validate with fresh scanner, connector, runtime, or agent evidence before marking remediation complete.',
      requiredScopes: [],
      missingScopes: [],
      requestedBy: user.id,
      requestedAt: now,
      source: 'harvest-now',
      activeThreatCount,
      linkedSignalCount,
      threatIds: Array.from(requestedFindingIds).slice(0, 100),
      playbook: action.playbook,
    }

    let operatorAction: any = null
    const operatorRow = {
      user_id: user.id,
      migration_id: primaryJob?.id || null,
      connector_account_id: null,
      action_type: action.actionType,
      asset_class: action.assetClass,
      status: 'planned',
      approval_mode: 'operator_approved',
      patch_plan: patchPlan,
      evidence: {},
      validation: {},
      metadata: {
        source: 'harvest-now',
        workflow: 'hndl-defense-action',
        linkedJobIds: linkedJobs.map((job: any) => job.id).filter(Boolean).slice(0, 100),
        threats,
      },
      requested_at: now,
      created_at: now,
      updated_at: now,
    }

    const operatorInsert = await client
      .from('remediation_operator_actions')
      .insert(operatorRow)
      .select('id, action_type, asset_class, status, migration_id, patch_plan, created_at')
      .single()
    if (operatorInsert.error && !isMissingTable(operatorInsert.error)) {
      return res.status(500).json({ error: { code: 'DEFENSE_OPERATOR_ACTION_FAILED', message: operatorInsert.error.message || 'Failed to create operator action' } })
    }
    operatorAction = operatorInsert.data || null

    const migrationEvents = linkedJobs.map((job: any) => ({
      user_id: user.id,
      migration_id: job.id,
      event_type: action.eventType,
      severity: action.severity,
      message: `${action.label} requested from Harvest Now for ${job.name || 'HNDL remediation workflow'}.`,
      metadata: {
        source: 'harvest-now',
        workflow: 'hndl-defense-action',
        defenseAction: action.actionType,
        operatorActionId: operatorAction?.id || null,
        linkedSignalCount,
        activeThreatCount,
        playbook: action.playbook,
      },
      created_at: now,
    }))
    if (migrationEvents.length > 0) {
      const { error } = await client.from('migration_events').insert(migrationEvents)
      if (error && !isMissingTable(error)) {
        return res.status(500).json({ error: { code: 'DEFENSE_EVENT_FAILED', message: error.message || 'Failed to record migration event' } })
      }
    }

    const { error: securityEventError } = await client.from('security_events').insert({
      user_id: user.id,
      event_type: action.eventType,
      severity: action.severity,
      message: `${action.label} playbook requested for ${linkedSignalCount || activeThreatCount} Harvest Now linked signal(s).`,
      asset_id: null,
      resource_name: textValue(primaryThreat.location, textValue(primaryThreat.name, 'Harvest Now telemetry')),
      resource_type: 'hndl-defense-action',
      metadata: {
        source: 'harvest-now',
        workflow: 'hndl-defense-action',
        defenseAction: action.actionType,
        operatorActionId: operatorAction?.id || null,
        linkedJobIds: linkedJobs.map((job: any) => job.id).filter(Boolean).slice(0, 100),
        linkedSignalCount,
        activeThreatCount,
        redirectPath: action.redirectPath,
      },
      created_at: now,
    })
    if (securityEventError && !isMissingTable(securityEventError)) {
      return res.status(500).json({ error: { code: 'DEFENSE_SECURITY_EVENT_FAILED', message: securityEventError.message || 'Failed to record security event' } })
    }

    await client.from('audit_logs').insert({
      user_id: user.id,
      action: 'hndl_defense_action_requested',
      entity_type: 'hndl_defense_action',
      entity_id: null,
      details: {
        defenseAction: action.actionType,
        linkedJobIds: linkedJobs.map((job: any) => job.id).filter(Boolean).slice(0, 100),
        operatorActionId: operatorAction?.id || null,
        linkedSignalCount,
        activeThreatCount,
      },
      ip_address: req.ip?.replace('::ffff:', '') || null,
      user_agent: String(req.headers['user-agent'] || '').slice(0, 500),
      created_at: now,
    })

    return res.json({
      data: {
        action: action.actionType,
        label: action.label,
        status: 'planned',
        createdJobs: createdJobs.length,
        linkedJobs: linkedJobs.length,
        operatorAction,
        redirectUrl: harvestRedirect(action.redirectPath, action.actionType, { jobs: linkedJobs.length, operatorAction: operatorAction?.id || null }),
        orchestrationUrl: harvestRedirect('/dashboard/pqc-orchestration', action.actionType, { jobs: linkedJobs.length }),
        recordedAt: now,
      },
    })
  } catch (err) {
    console.error('Harvest Now defense action error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to record Harvest Now defense action' } })
  }
})

router.post('/pqc-orchestration/hndl-remediation', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)
    const body = recordOf(req.body)
    const findingId = textValue(body.findingId, '')

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const [assets, jobs, scanResults, scanSessions] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, service_owner, criticality, status, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
      safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, target_scope, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(80)),
    ])

    const candidates = buildHndlRemediationCandidates([...(scanResults || []), ...hndlRowsFromScanSessions(scanSessions || [])], assets || [], jobs || [])
      .filter((candidate) => !findingId || candidate.findingId === findingId)

    if (candidates.length === 0) {
      return res.json({ data: { created: 0, skipped: true, message: 'No unqueued HNDL remediation findings are available.' } })
    }

    const rows = candidates.map((candidate) => migrationJobFromHndlCandidate(user.id, candidate))
    const { data: inserted, error } = await client
      .from('migration_jobs')
      .insert(rows)
      .select('id, name, metadata')

    if (error) {
      return res.status(500).json({ error: { code: 'QUEUE_FAILED', message: error.message || 'Failed to queue HNDL remediation workflows' } })
    }

    const eventRows = (inserted || []).map((job: any) => ({
      user_id: user.id,
      migration_id: job.id,
      event_type: 'hndl-remediation-queued',
      message: `Harvest Now remediation workflow queued for ${job.name}.`,
      severity: 'warning',
      metadata: {
        source: 'harvest-now',
        workflow: 'hndl-remediation',
        hndlFindingId: recordOf(job.metadata).hndlFindingId,
      },
    }))

    if (eventRows.length > 0) {
      const { error: eventError } = await client.from('migration_events').insert(eventRows)
      if (eventError) console.warn('HNDL remediation event insert failed:', eventError.message || eventError)
    }

    return res.json({ data: { created: inserted?.length || 0, jobs: inserted || [] } })
  } catch (err) {
    console.error('HNDL remediation queue error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to queue HNDL remediation workflows' } })
  }
})

/**
 * GET /api/v1/dashboard/pqc-orchestration
 * Returns user-specific PQC orchestration telemetry derived from migration
 * jobs/events, assets, CBOM, scan sessions, compliance evidence, and runtime
 * security events.
 */
router.get('/pqc-orchestration', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const [assets, inventory, exposures, jobs, migrationEvents, scanSessions, securityEvents, complianceEvidence, scanResults] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, service_owner, criticality, status, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(750)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(300)),
      safeRows(client, 'migration_events', (q) => q.select('id, migration_id, event_type, message, severity, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(150)),
      safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, target_scope, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(50)),
      safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, resource_name, resource_type, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(100)),
      safeRows(client, 'compliance_evidence', (q) => q.select('id, framework, control_id, status, evidence_type, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(100)),
      safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
    ])

    const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
    const exposuresByAsset = new Map<string, any[]>()
    for (const exposure of exposures || []) {
      if (!exposure.asset_id) continue
      const list = exposuresByAsset.get(exposure.asset_id) || []
      list.push(exposure)
      exposuresByAsset.set(exposure.asset_id, list)
    }

    const eventsByMigration = new Map<string, any[]>()
    for (const event of migrationEvents || []) {
      if (!event.migration_id) continue
      const list = eventsByMigration.get(event.migration_id) || []
      list.push(event)
      eventsByMigration.set(event.migration_id, list)
    }

    const normalizedJobs = (jobs || []).map((job: any) => {
      const asset = assetMap.get(job.asset_id) || {}
      const status = normalizeJobStatus(job.status)
      const assetExposures = job.asset_id ? exposuresByAsset.get(job.asset_id) || [] : []
      const metadata = recordOf(job.metadata)
      const progress = clampPercent(Number(job.progress || 0))
      return {
        id: job.id,
        name: job.name || titleCase(job.job_type || 'PQC workflow'),
        subtitle: textValue(metadata.subtitle, titleCase(job.job_type || job.strategy || 'Post-quantum workflow')),
        assetName: textValue(asset.name, 'Unassigned asset'),
        environment: textValue(asset.environment, 'unknown'),
        assetType: textValue(asset.type, 'asset'),
        status,
        rawStatus: job.status || status,
        priority: priorityForJob(job, assetExposures),
        eta: etaForJob(job),
        progress,
        targetAlgorithm: textValue(job.target_algorithm, replacementForAlgorithm(textValue(metadata.fromAlgorithm, ''), job.job_type || '')),
        currentStep: status === 'completed'
          ? 'Deployment'
          : status === 'running'
            ? progress >= 75 ? 'Validation' : progress >= 45 ? 'Certificate Rotation' : 'Policy Validation'
            : status === 'failed' ? 'Exception Review' : 'Scheduled',
        startedAt: job.started_at || null,
        completedAt: job.completed_at || null,
        updatedAt: job.updated_at || job.completed_at || job.started_at || job.created_at,
        events: eventsByMigration.get(job.id) || [],
        source: textValue(metadata.source, 'migration_jobs'),
        sourceFindingId: linkedHndlFindingId(job),
        materialized: true,
      }
    })

    const hndlCandidates = buildHndlRemediationCandidates([...(scanResults || []), ...hndlRowsFromScanSessions(scanSessions || [])], assets || [], jobs || [])
    const hndlWorkflows = hndlCandidates.map(hndlWorkflowFromCandidate)
    const allWorkflows = [...normalizedJobs, ...hndlWorkflows]

    const runningJobs = allWorkflows.filter((job) => job.status === 'running')
    const failedJobs = allWorkflows.filter((job) => job.status === 'failed')
    const pendingJobs = allWorkflows.filter((job) => job.status === 'pending' || job.status === 'paused')
    const completedJobs = allWorkflows.filter((job) => job.status === 'completed')
    const activeJobs = allWorkflows.filter((job) => job.status !== 'completed')
    const linkedHndlJobs = normalizedJobs.filter((job) => job.source === 'harvest-now' || Boolean(job.sourceFindingId))
    const workflowQueue = allWorkflows
      .sort((a, b) => {
        const priorityDiff = severityRank(b.priority) - severityRank(a.priority)
        if (priorityDiff) return priorityDiff
        return dateMs(b.updatedAt) - dateMs(a.updatedAt)
      })
      .slice(0, 60)

    const pqcEnabled = (inventory || []).filter((item: any) => Boolean(item.is_quantum_safe) || isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`)).length
    const hybridMode = (inventory || []).filter((item: any) => {
      const text = `${item.algorithm || ''} ${item.protocol || ''} ${JSON.stringify(item.metadata || {})}`.toLowerCase()
      return text.includes('hybrid') || (text.includes('ml-') && (text.includes('rsa') || text.includes('ecdsa') || text.includes('x25519')))
    }).length
    const legacy = (inventory || []).filter((item: any) => item.is_vulnerable && !item.is_quantum_safe).length
    const totalAssets = (assets || []).length
    const notAssessed = Math.max(0, totalAssets - new Set((inventory || []).map((item: any) => item.asset_id).filter(Boolean)).size)
    const totalReadinessItems = pqcEnabled + hybridMode + legacy + notAssessed
    const pqcReadiness = totalReadinessItems
      ? clampPercent(((pqcEnabled + hybridMode * 0.75) / totalReadinessItems) * 100)
      : 0

    const criticalExposures = (exposures || []).filter((exposure: any) => severityRank(exposure.severity || '') >= 4).length
    const highExposures = (exposures || []).filter((exposure: any) => severityRank(exposure.severity || '') >= 3).length
    const failedTasks = failedJobs.length + (migrationEvents || []).filter((event: any) => ['error', 'failed', 'critical'].some((token) => `${event.event_type || ''} ${event.severity || ''}`.toLowerCase().includes(token))).length

    const liveJob = runningJobs[0] || pendingJobs[0] || normalizedJobs[0] || null
    const liveProgress = liveJob?.progress || 0
    const stages = [
      { key: 'discovery', label: 'Discovery & Inventory', threshold: 15 },
      { key: 'policy', label: 'Policy Validation', threshold: 35 },
      { key: 'rotation', label: 'Certificate Rotation', threshold: 60 },
      { key: 'validation', label: 'Validation', threshold: 80 },
      { key: 'deployment', label: 'Deployment', threshold: 100 },
    ].map((stage) => ({
      ...stage,
      state: liveJob ? stageState(liveProgress, stage.threshold, liveJob.status) : 'pending',
      timestamp: liveJob?.updatedAt || null,
    }))

    const telemetryLogs = [
      ...(liveJob?.events || []).map((event: any) => ({
        id: `migration-${event.id}`,
        timestamp: event.created_at,
        message: event.message,
        severity: event.severity || 'info',
      })),
      ...hndlWorkflows.slice(0, 12).map((workflow: any) => ({
        id: `hndl-${workflow.sourceFindingId}`,
        timestamp: workflow.updatedAt,
        message: `${workflow.name} staged from Harvest Now telemetry.`,
        severity: workflow.priority.toLowerCase() === 'critical' ? 'critical' : 'warning',
      })),
      ...(migrationEvents || []).slice(0, 12).map((event: any) => ({
        id: `migration-${event.id}`,
        timestamp: event.created_at,
        message: event.message,
        severity: event.severity || 'info',
      })),
      ...(securityEvents || []).slice(0, 8).map((event: any) => ({
        id: `security-${event.id}`,
        timestamp: event.created_at,
        message: event.message || titleCase(event.event_type || 'security event'),
        severity: event.severity || 'info',
      })),
    ]
      .filter((log, index, list) => list.findIndex((item) => item.id === log.id) === index)
      .sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp))
      .slice(0, 12)

    const complianceMetrics = {
      readiness: pqcReadiness,
      critical: criticalExposures,
      high: highExposures,
      failed: failedTasks,
      totalAssets,
    }
    const compliance = ['NIST SP 800-208', 'NIST SP 800-57 Rev. 5', 'NIST SP 800-131A Rev. 2', 'CNSA 2.0', 'FIPS 203 (ML-KEM)', 'FIPS 204 (ML-DSA)']
      .map((label) => ({
        label,
        status: complianceStatus(label, complianceEvidence || [], complianceMetrics),
      }))

    const taskQueue = [
      ...runningJobs.map((job) => ({
        id: `running-${job.id}`,
        title: job.name,
        priority: `${job.priority} Priority`,
        progress: job.progress,
        eta: job.eta,
        status: 'Running',
      })),
      ...pendingJobs.map((job) => ({
        id: `pending-${job.id}`,
        title: job.name,
        priority: `${job.priority} Priority`,
        progress: job.progress,
        eta: job.eta,
        status: job.rawStatus === 'hndl_pending' ? 'HNDL intake' : job.status === 'paused' ? 'Paused' : 'Pending',
      })),
      ...(exposures || []).filter((exposure: any) => severityRank(exposure.severity || '') >= 3).slice(0, 6).map((exposure: any) => ({
        id: `exposure-${exposure.id}`,
        title: `Resolve ${titleCase(exposure.exposure_type || 'crypto exposure')}`,
        priority: severityRank(exposure.severity || '') >= 4 ? 'Critical Priority' : 'High Priority',
        progress: 0,
        eta: 'Needs owner',
        status: 'Pending',
      })),
    ].slice(0, 12)

    return res.json({
      data: {
        generatedAt: new Date().toISOString(),
        metrics: {
          activeWorkflows: activeJobs.length,
          runningJobs: runningJobs.length,
          failedTasks,
          pqcReadiness,
          totalAssets,
          completedWorkflows: completedJobs.length,
          pendingWorkflows: pendingJobs.length,
          activeScans: (scanSessions || []).filter((scan: any) => ['pending', 'running', 'analyzing'].includes(String(scan.status || '').toLowerCase())).length,
          hndlPending: hndlWorkflows.length,
        },
        workflowQueue,
        liveExecution: liveJob ? {
          workflowId: liveJob.id,
          name: liveJob.name,
          currentStep: liveJob.currentStep,
          algorithmTransition: liveJob.targetAlgorithm,
          progress: liveJob.progress,
          startedAt: liveJob.startedAt,
          eta: liveJob.eta,
          status: liveJob.status,
          stages,
        } : null,
        telemetryLogs,
        readiness: {
          pqcEnabled,
          hybridMode,
          legacy,
          notAssessed,
          totalAssets,
          score: pqcReadiness,
        },
        compliance,
        taskQueue,
        hndlRemediation: {
          activeFindings: hndlWorkflows.length + linkedHndlJobs.filter((job) => job.status !== 'completed').length,
          pendingFindings: hndlWorkflows.length,
          linkedJobs: linkedHndlJobs.length,
          lastDetectedAt: hndlWorkflows[0]?.updatedAt || null,
        },
      },
    })
  } catch (err) {
    console.error('PQC orchestration dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch PQC orchestration telemetry' } })
  }
})

function sandboxTypeFor(job: any, asset: any) {
  const value = `${job?.job_type || ''} ${asset?.type || ''}`.toLowerCase()
  if (value.includes('cert') || value.includes('pki')) return 'PKI'
  if (value.includes('key') || value.includes('crypto') || value.includes('kem') || value.includes('sign')) return 'Crypto'
  if (value.includes('network') || value.includes('tls') || value.includes('protocol') || value.includes('vpn')) return 'Network'
  if (value.includes('database') || value.includes('data')) return 'Data'
  return 'Application'
}

function sandboxStatus(status: unknown) {
  const normalized = normalizeJobStatus(status)
  if (normalized === 'completed') return 'Completed'
  if (normalized === 'failed') return 'Failed'
  if (normalized === 'running') return 'Running'
  return 'Pending'
}

function sandboxName(source: string, index: number) {
  const normalized = source
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
    .slice(0, 34)
  return normalized ? `pqc-${normalized}` : `pqc-sandbox-${String(index + 1).padStart(2, '0')}`
}

function transitionType(value: string) {
  const lower = value.toLowerCase()
  if (lower.includes('sign') || lower.includes('dsa') || lower.includes('ecdsa') || lower.includes('jwt')) return 'Digital Signature'
  if (lower.includes('tls') || lower.includes('protocol') || lower.includes('vpn') || lower.includes('ssh')) return 'Protocol'
  if (lower.includes('hash') || lower.includes('sha')) return 'Hash'
  if (lower.includes('encrypt') || lower.includes('aes') || lower.includes('database')) return 'Encryption'
  return 'Key Exchange'
}

/**
 * GET /api/v1/dashboard/migration-sandbox
 * Returns user-specific sandbox telemetry derived from real migration jobs,
 * assets, CBOM, exposures, scan sessions, migration events, and runtime events.
 */
router.get('/migration-sandbox', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const [assets, inventory, exposures, jobs, migrationEvents, scanSessions, securityEvents, relationships] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(750)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(300)),
      safeRows(client, 'migration_events', (q) => q.select('id, migration_id, event_type, message, severity, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(200)),
      safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, target_scope, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(60)),
      safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, resource_name, resource_type, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(120)),
      safeRows(client, 'asset_relationships', (q) => q.select('id, source_asset_id, target_asset_id, relationship_type, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(400)),
    ])

    const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
    const inventoryByAsset = new Map<string, any[]>()
    for (const item of inventory || []) {
      if (!item.asset_id) continue
      const list = inventoryByAsset.get(item.asset_id) || []
      list.push(item)
      inventoryByAsset.set(item.asset_id, list)
    }

    const exposuresByAsset = new Map<string, any[]>()
    for (const exposure of exposures || []) {
      if (!exposure.asset_id) continue
      const list = exposuresByAsset.get(exposure.asset_id) || []
      list.push(exposure)
      exposuresByAsset.set(exposure.asset_id, list)
    }

    const eventsByMigration = new Map<string, any[]>()
    for (const event of migrationEvents || []) {
      if (!event.migration_id) continue
      const list = eventsByMigration.get(event.migration_id) || []
      list.push(event)
      eventsByMigration.set(event.migration_id, list)
    }

    const jobsByAsset = new Map<string, any[]>()
    for (const job of jobs || []) {
      if (!job.asset_id) continue
      const list = jobsByAsset.get(job.asset_id) || []
      list.push(job)
      jobsByAsset.set(job.asset_id, list)
    }

    const jobRows = (jobs || []).slice(0, 12).map((job: any, index: number) => {
      const asset = assetMap.get(job.asset_id) || {}
      const metadata = recordOf(job.metadata)
      const relatedEvents = eventsByMigration.get(job.id) || []
      const sourceAlgorithm = textValue(metadata.fromAlgorithm || metadata.from_algorithm, textValue((inventoryByAsset.get(job.asset_id) || [])[0]?.algorithm, textValue((exposuresByAsset.get(job.asset_id) || [])[0]?.detected_value, 'Detected crypto')))
      return {
        id: job.id,
        environment: textValue(metadata.sandboxName || metadata.sandbox_name, sandboxName(textValue(asset.name, textValue(job.name, 'sandbox')), index)),
        displayName: textValue(job.name, titleCase(job.job_type || 'Migration test')),
        type: sandboxTypeFor(job, asset),
        region: textValue(metadata.region, textValue(asset.region, 'unassigned')),
        status: sandboxStatus(job.status),
        tests: relatedEvents.length || (job.status ? 1 : 0),
        progress: clampPercent(Number(job.progress || 0)),
        lastActivityAt: latestDate(job.updated_at, job.completed_at, job.started_at, job.created_at),
        assetId: job.asset_id || null,
        from: sourceAlgorithm,
        to: textValue(job.target_algorithm, replacementForAlgorithm(sourceAlgorithm, job.job_type || '')),
        transitionType: transitionType(`${job.job_type || ''} ${sourceAlgorithm}`),
        success: normalizeJobStatus(job.status) === 'completed',
        failed: normalizeJobStatus(job.status) === 'failed',
      }
    })

    const jobAssetIds = new Set(jobRows.map((row) => row.assetId).filter(Boolean))
    const assetRows = (assets || [])
      .filter((asset: any) => !jobAssetIds.has(asset.id))
      .slice(0, Math.max(0, 8 - jobRows.length))
      .map((asset: any, index: number) => {
        const assetInventory = inventoryByAsset.get(asset.id) || []
        const assetExposures = exposuresByAsset.get(asset.id) || []
        const firstItem = assetInventory[0] || assetExposures[0] || {}
        const from = textValue(firstItem.algorithm, textValue(firstItem.detected_value, textValue(firstItem.exposure_type, 'Detected crypto')))
        const safeCount = assetInventory.filter((item) => item.is_quantum_safe || isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`)).length
        const progress = assetInventory.length ? percentOf(safeCount, assetInventory.length) : 0
        return {
          id: `asset-${asset.id}`,
          environment: sandboxName(textValue(asset.name, 'asset'), jobRows.length + index),
          displayName: textValue(asset.name, 'Discovered asset'),
          type: sandboxTypeFor(null, asset),
          region: textValue(asset.region, 'unassigned'),
          status: assetExposures.length ? 'Pending' : 'Completed',
          tests: 0,
          progress,
          lastActivityAt: latestDate(asset.updated_at, asset.created_at, firstItem.discovered_at, firstItem.created_at),
          assetId: asset.id,
          from,
          to: replacementForAlgorithm(from, `${asset.type || ''} ${firstItem.item_type || firstItem.exposure_type || ''}`),
          transitionType: transitionType(`${asset.type || ''} ${firstItem.item_type || firstItem.exposure_type || ''}`),
          success: !assetExposures.length && assetInventory.length > 0,
          failed: false,
        }
      })

    const environments = [...jobRows, ...assetRows].slice(0, 8)
    const completedJobs = jobRows.filter((row) => row.success).length
    const failedJobs = jobRows.filter((row) => row.failed).length
    const runningJobs = jobRows.filter((row) => row.status === 'Running').length
    const pendingJobs = jobRows.filter((row) => row.status === 'Pending').length
    const successEvents = (migrationEvents || []).filter((event: any) => ['success', 'completed', 'passed'].some((token) => `${event.event_type || ''} ${event.severity || ''} ${event.message || ''}`.toLowerCase().includes(token))).length
    const failureEvents = (migrationEvents || []).filter((event: any) => ['failed', 'failure', 'error', 'critical'].some((token) => `${event.event_type || ''} ${event.severity || ''} ${event.message || ''}`.toLowerCase().includes(token))).length
    const passedTests = completedJobs + successEvents
    const failedTests = failedJobs + failureEvents
    const runningTests = runningJobs + (scanSessions || []).filter((scan: any) => ['running', 'analyzing'].includes(String(scan.status || '').toLowerCase())).length
    const pendingTests = pendingJobs + (scanSessions || []).filter((scan: any) => ['pending', 'queued'].includes(String(scan.status || '').toLowerCase())).length
    const totalTests = passedTests + failedTests + runningTests + pendingTests
    const readinessScore = environments.length ? clampPercent(environments.reduce((sum, row) => sum + row.progress, 0) / environments.length) : 0
    const estimatedCost = Math.round(environments.length * 85 + (inventory || []).length * 6 + totalTests * 9 + (relationships || []).length * 2)

    const transitionGroups = new Map<string, any>()
    for (const row of jobRows) {
      const key = `${row.from}|${row.to}|${row.transitionType}`
      const current = transitionGroups.get(key) || { id: key, from: row.from, to: row.to, type: row.transitionType, tests: 0, passed: 0 }
      current.tests += Math.max(1, row.tests)
      current.passed += row.success ? Math.max(1, row.tests) : 0
      transitionGroups.set(key, current)
    }
    const transitions = Array.from(transitionGroups.values())
      .map((item) => ({ ...item, successRate: percentOf(item.passed, item.tests) }))
      .sort((a, b) => b.tests - a.tests)
      .slice(0, 6)

    const assetTypes = (assets || []).map((asset: any) => `${asset.type || ''}`.toLowerCase())
    const topology = {
      users: new Set((assets || []).map((asset: any) => textValue(asset.service_owner, '')).filter(Boolean)).size,
      loadGenerators: (scanSessions || []).filter((scan: any) => ['running', 'completed'].includes(String(scan.status || '').toLowerCase())).length,
      appServers: assetTypes.filter((type) => ['api', 'application', 'server', 'service'].some((token) => type.includes(token))).length,
      apiGateways: assetTypes.filter((type) => type.includes('api') || type.includes('gateway')).length,
      databases: assetTypes.filter((type) => type.includes('database') || type.includes('db')).length,
      keyVaults: assetTypes.filter((type) => type.includes('vault') || type.includes('key')).length,
      externalServices: assetTypes.filter((type) => ['dns', 'pki', 'certificate', 'external', 'monitor'].some((token) => type.includes(token))).length,
      kemServices: (inventory || []).filter((item: any) => `${item.algorithm || ''} ${item.protocol || ''}`.toLowerCase().includes('kem')).length,
      signServices: (inventory || []).filter((item: any) => `${item.algorithm || ''} ${item.item_type || ''}`.toLowerCase().includes('dsa') || `${item.item_type || ''}`.toLowerCase().includes('sign')).length,
      telemetryEvents: (migrationEvents || []).length + (securityEvents || []).length,
    }

    const activity = [
      ...(migrationEvents || []).map((event: any) => {
        const job = (jobs || []).find((item: any) => item.id === event.migration_id)
        const asset = job?.asset_id ? assetMap.get(job.asset_id) : null
        return {
          id: `migration-${event.id}`,
          timestamp: event.created_at,
          environment: job ? textValue(job.name, 'Migration job') : 'Migration event',
          event: titleCase(event.event_type || 'migration event'),
          details: event.message,
          status: severityRank(event.severity || '') >= 3 || `${event.event_type || ''}`.toLowerCase().includes('fail') ? 'Failed' : 'Success',
          user: textValue(asset?.service_owner, textValue(user.email, 'authenticated user')),
        }
      }),
      ...(securityEvents || []).map((event: any) => ({
        id: `security-${event.id}`,
        timestamp: event.created_at,
        environment: textValue(event.resource_name, textValue(event.resource_type, 'Runtime telemetry')),
        event: titleCase(event.event_type || 'security event'),
        details: event.message || titleCase(event.event_type || 'security event'),
        status: severityRank(event.severity || '') >= 3 ? 'Failed' : severityRank(event.severity || '') === 2 ? 'Warning' : 'Success',
        user: textValue(user.email, 'authenticated user'),
      })),
      ...(scanSessions || []).map((scan: any) => ({
        id: `scan-${scan.id}`,
        timestamp: scan.completed_at || scan.updated_at || scan.started_at || scan.created_at,
        environment: textValue(scan.target_scope, 'Scan session'),
        event: `Scan ${titleCase(scan.status || 'session')}`,
        details: `${Number(scan.scanned_assets || 0)} of ${Number(scan.total_assets || 0)} assets scanned; ${Number(scan.findings_count || 0)} findings`,
        status: String(scan.status || '').toLowerCase() === 'failed' ? 'Failed' : String(scan.status || '').toLowerCase() === 'completed' ? 'Success' : 'Warning',
        user: textValue(user.email, 'authenticated user'),
      })),
    ]
      .sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp))
      .slice(0, 8)

    const criticalExposures = (exposures || []).filter((exposure: any) => severityRank(exposure.severity || '') >= 4).length
    const highExposures = (exposures || []).filter((exposure: any) => severityRank(exposure.severity || '') >= 3).length
    const validation = [
      { label: 'Crypto Strength Validation', status: criticalExposures ? 'Failed' : 'Passed' },
      { label: 'Protocol Compatibility', status: highExposures ? 'Warning' : 'Passed' },
      { label: 'Performance Benchmark', status: failedTests ? 'Warning' : 'Passed' },
      { label: 'Interoperability Test', status: relationships?.length || environments.length > 1 ? 'Passed' : 'Warning' },
      { label: 'Rollback Test', status: failedJobs ? 'Warning' : jobRows.length ? 'Passed' : 'Pending' },
    ]

    return res.json({
      data: {
        generatedAt: new Date().toISOString(),
        metrics: {
          sandboxEnvironments: environments.length,
          activeEnvironments: environments.filter((row) => ['Running', 'Pending'].includes(row.status)).length,
          activeTests: runningTests + pendingTests,
          testsPassed: passedTests,
          testsFailed: failedTests,
          successRate: percentOf(passedTests, Math.max(1, passedTests + failedTests)),
          failureRate: percentOf(failedTests, Math.max(1, passedTests + failedTests)),
          readinessScore,
          costEstimate: estimatedCost,
        },
        environments,
        topology,
        executionSummary: {
          passed: passedTests,
          failed: failedTests,
          running: runningTests,
          pending: pendingTests,
          total: totalTests,
        },
        transitions,
        activity,
        validation,
      },
    })
  } catch (err) {
    console.error('Migration sandbox dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch migration sandbox telemetry' } })
  }
})

function normalizeDriftSeverity(value: unknown) {
  const lower = String(value || '').toLowerCase()
  if (lower === 'critical') return 'critical'
  if (lower === 'high' || lower === 'error' || lower === 'failed') return 'high'
  if (lower === 'medium' || lower === 'moderate' || lower === 'warning') return 'medium'
  return 'low'
}

function driftStatus(metadata: Record<string, unknown>, fallback = 'Unresolved') {
  const explicit = textValue(metadata.status || metadata.driftStatus || metadata.drift_status, '')
  const normalized = explicit.toLowerCase()
  if (['resolved', 'closed', 'fixed'].includes(normalized)) return 'Resolved'
  if (['auto-remediated', 'auto_remediated', 'remediated', 'auto fixed', 'autofixed'].includes(normalized)) return 'Auto-Remediated'
  if (['unresolved', 'open', 'active', 'pending'].includes(normalized)) return 'Unresolved'
  return fallback
}

function driftTypeFor(text: string) {
  const lower = text.toLowerCase()
  if (lower.includes('downgrade') || lower.includes('fallback') || lower.includes('rsa') || lower.includes('ecdsa')) return 'Algo Downgrade'
  if (lower.includes('unauthorized') || lower.includes('unapproved')) return 'Unauthorized Algo'
  if (lower.includes('config') || lower.includes('setting') || lower.includes('changed')) return 'Config Change'
  if (lower.includes('policy') || lower.includes('compliance') || lower.includes('exception')) return 'Policy Violation'
  if (lower.includes('outdated') || lower.includes('deprecated') || lower.includes('legacy')) return 'Outdated Component'
  if (lower.includes('random') || lower.includes('entropy') || lower.includes('rng')) return 'Weak Cryptography'
  if (lower.includes('rotation') || lower.includes('certificate') || lower.includes('cert')) return 'Policy Violation'
  return 'Drift Event'
}

function expectedForDrift(text: string, algorithm = '') {
  const lower = `${text} ${algorithm}`.toLowerCase()
  if (lower.includes('rsa') || lower.includes('tls') || lower.includes('key exchange')) return 'ML-KEM-768 + RSA-2048 (hybrid)'
  if (lower.includes('jwt') || lower.includes('rs256') || lower.includes('ecdsa') || lower.includes('sign')) return 'ML-DSA-44 or stronger'
  if (lower.includes('aes-128') || lower.includes('cbc') || lower.includes('redis') || lower.includes('database')) return 'AES-256-GCM'
  if (lower.includes('tls 1.2') || lower.includes('tls-1.2')) return 'TLS 1.3 only'
  if (lower.includes('random') || lower.includes('entropy') || lower.includes('rng')) return 'Cryptographically secure RNG'
  if (lower.includes('library') || lower.includes('outdated') || lower.includes('deprecated')) return 'Current approved component'
  return replacementForAlgorithm(algorithm || text, text)
}

function actualForDrift(row: any, fallback = 'Observed runtime state') {
  const metadata = recordOf(row?.metadata)
  return textValue(
    metadata.actual || metadata.observed || metadata.actualState || metadata.actual_state,
    textValue(row?.detected_value, textValue(row?.algorithm, textValue(row?.message, fallback)))
  )
}

function dateLabel(value: number) {
  return new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

/**
 * GET /api/v1/dashboard/drift
 * Returns user-specific drift telemetry derived from runtime events, crypto
 * exposures, scan results, compliance evidence, migration events, certificates,
 * and vulnerability records.
 */
router.get('/drift/stream', (req: Request, res: Response) => {
  openDashboardSyncStream(req, res, 'drift', 'dashboard.drift', 'tenant-drift-sync')
})

router.get('/vulnerabilities/stream', (req: Request, res: Response) => {
  openDashboardSyncStream(req, res, 'vulnerabilities', 'dashboard.vulnerabilities', 'tenant-vulnerability-sync')
})

router.get('/runtime-crypto-intel/stream', (req: Request, res: Response) => {
  openDashboardSyncStream(req, res, 'runtime-crypto-intel', 'dashboard.runtime-crypto-intel', 'tenant-runtime-crypto-sync')
})

router.get('/drift', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const [assets, inventory, exposures, scanResults, securityEvents, migrationEvents, complianceEvidence, vulnerabilities, certificates] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(750)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(500)),
      safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(300)),
      safeRows(client, 'migration_events', (q) => q.select('id, migration_id, event_type, message, severity, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(250)),
      safeRows(client, 'compliance_evidence', (q) => q.select('id, framework, control_id, evidence_type, description, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(200)),
      safeRows(client, 'vulnerabilities', (q) => q.select('id, asset_id, title, description, severity, status, source, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(300)),
      safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(300)),
    ])

    const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
    const events: any[] = []

    const addEvent = (event: any) => {
      if (!event.id || events.some((item) => item.id === event.id)) return
      events.push(event)
    }

    for (const exposure of exposures || []) {
      const asset = assetMap.get(exposure.asset_id) || {}
      const metadata = recordOf(exposure.metadata)
      const text = `${exposure.exposure_type || ''} ${exposure.description || ''} ${exposure.detected_value || ''}`
      const severity = normalizeDriftSeverity(exposure.severity)
      addEvent({
        id: `exposure-${exposure.id}`,
        severity,
        event: exposure.description || titleCase(exposure.exposure_type || 'Cryptographic drift detected'),
        resource: textValue(asset.name, 'Unassigned asset'),
        resourceRegion: textValue(asset.region, textValue(asset.environment, 'unassigned')),
        type: driftTypeFor(text),
        detectedAt: exposure.updated_at || exposure.created_at,
        status: driftStatus(metadata, 'Unresolved'),
        expected: textValue(metadata.expected || metadata.expectedState || metadata.expected_state, expectedForDrift(text, exposure.detected_value)),
        actual: actualForDrift(exposure, titleCase(exposure.exposure_type || 'Observed exposure')),
      })
    }

    for (const result of scanResults || []) {
      const asset = assetMap.get(result.asset_id) || {}
      const metadata = recordOf(result.metadata)
      const text = `${result.finding_type || ''} ${result.description || ''} ${result.algorithm || ''}`
      addEvent({
        id: `scan-${result.id}`,
        severity: normalizeDriftSeverity(result.threat_level),
        event: result.description || titleCase(result.finding_type || 'Scan drift finding'),
        resource: textValue(asset.name, 'Scan result'),
        resourceRegion: textValue(asset.region, textValue(asset.environment, 'unassigned')),
        type: driftTypeFor(text),
        detectedAt: result.created_at,
        status: driftStatus(metadata, 'Unresolved'),
        expected: textValue(result.remediation, expectedForDrift(text, result.algorithm)),
        actual: actualForDrift(result, textValue(result.algorithm, 'Scanner finding')),
      })
    }

    for (const event of securityEvents || []) {
      const text = `${event.event_type || ''} ${event.message || ''}`
      if (!/drift|downgrade|fallback|policy|config|unauthorized|deprecated|legacy|random|entropy|certificate|crypto/i.test(text)) continue
      const asset = event.asset_id ? assetMap.get(event.asset_id) : null
      const metadata = recordOf(event.metadata)
      const fallbackStatus = event.is_read ? 'Resolved' : 'Unresolved'
      addEvent({
        id: `security-${event.id}`,
        severity: normalizeDriftSeverity(event.severity),
        event: event.message || titleCase(event.event_type || 'Runtime drift event'),
        resource: textValue(asset?.name, textValue(event.resource_name, 'Runtime resource')),
        resourceRegion: textValue(asset?.region, textValue(asset?.environment, textValue(event.resource_type, 'runtime'))),
        type: driftTypeFor(text),
        detectedAt: event.created_at,
        status: driftStatus(metadata, fallbackStatus),
        expected: textValue(metadata.expected || metadata.expectedState || metadata.expected_state, expectedForDrift(text)),
        actual: actualForDrift(event, event.message || 'Runtime event'),
      })
    }

    for (const event of migrationEvents || []) {
      const text = `${event.event_type || ''} ${event.message || ''}`
      if (!/drift|fallback|downgrade|failed|policy|rollback|config|unauthorized/i.test(text)) continue
      const metadata = recordOf(event.metadata)
      const severity = normalizeDriftSeverity(event.severity)
      addEvent({
        id: `migration-${event.id}`,
        severity,
        event: event.message || titleCase(event.event_type || 'Migration drift event'),
        resource: textValue(metadata.resourceName || metadata.resource_name, 'Migration workflow'),
        resourceRegion: textValue(metadata.region, 'migration'),
        type: driftTypeFor(text),
        detectedAt: event.created_at,
        status: driftStatus(metadata, severityRank(severity) >= 3 ? 'Unresolved' : 'Resolved'),
        expected: textValue(metadata.expected || metadata.expectedState || metadata.expected_state, expectedForDrift(text)),
        actual: actualForDrift(event, event.message || 'Migration event'),
      })
    }

    for (const evidence of complianceEvidence || []) {
      const status = String(evidence.status || '').toLowerCase()
      if (!['failed', 'non-compliant', 'non_compliant', 'at risk', 'risk', 'pending'].includes(status)) continue
      const metadata = recordOf(evidence.metadata)
      const text = `${evidence.framework || ''} ${evidence.control_id || ''} ${evidence.description || ''} ${evidence.evidence_type || ''}`
      const fallbackStatus = status.includes('failed') || status.includes('non') || status.includes('risk') || status === 'pending' ? 'Unresolved' : 'Resolved'
      addEvent({
        id: `compliance-${evidence.id}`,
        severity: status.includes('failed') || status.includes('non') ? 'high' : 'medium',
        event: evidence.description || `Policy control ${evidence.control_id || ''} drift`,
        resource: textValue(metadata.resourceName || metadata.resource_name, textValue(evidence.framework, 'Compliance control')),
        resourceRegion: textValue(metadata.region, 'policy'),
        type: driftTypeFor(text),
        detectedAt: evidence.updated_at || evidence.created_at,
        status: driftStatus(metadata, fallbackStatus),
        expected: textValue(metadata.expected || metadata.expectedState || metadata.expected_state, `${evidence.framework || 'Policy'} compliant`),
        actual: textValue(evidence.status, 'Control drift'),
      })
    }

    for (const vuln of vulnerabilities || []) {
      if (['resolved', 'false_positive'].includes(String(vuln.status || '').toLowerCase())) continue
      const asset = assetMap.get(vuln.asset_id) || {}
      const metadata = recordOf(vuln.metadata)
      const text = `${vuln.title || ''} ${vuln.description || ''}`
      addEvent({
        id: `vulnerability-${vuln.id}`,
        severity: normalizeDriftSeverity(vuln.severity),
        event: vuln.title || 'New vulnerability drift',
        resource: textValue(asset.name, 'Vulnerable asset'),
        resourceRegion: textValue(asset.region, textValue(asset.environment, 'unassigned')),
        type: driftTypeFor(text) === 'Drift Event' ? 'Outdated Component' : driftTypeFor(text),
        detectedAt: vuln.updated_at || vuln.created_at,
        status: driftStatus(metadata, 'Unresolved'),
        expected: textValue(metadata.expected || metadata.expectedState || metadata.expected_state, 'No open vulnerability affecting approved cryptography'),
        actual: vuln.description || vuln.title || 'Open vulnerability',
      })
    }

    for (const cert of certificates || []) {
      if (!cert.is_expiring_soon && cert.is_quantum_safe && !/rsa|ecdsa|sha1/i.test(`${cert.algorithm || ''}`)) continue
      const asset = assetMap.get(cert.asset_id) || {}
      const metadata = recordOf(cert.metadata)
      const text = `${cert.name || ''} ${cert.algorithm || ''} certificate`
      addEvent({
        id: `certificate-${cert.id}`,
        severity: cert.is_expiring_soon ? 'medium' : normalizeDriftSeverity(cert.status === 'active' ? 'low' : cert.status),
        event: cert.is_expiring_soon ? `Certificate rotation drift: ${cert.name || cert.subject || 'certificate'}` : `Legacy certificate algorithm: ${cert.algorithm || 'unknown'}`,
        resource: textValue(asset.name, textValue(cert.name, 'Certificate')),
        resourceRegion: textValue(asset.region, textValue(asset.environment, 'certificate')),
        type: driftTypeFor(text),
        detectedAt: cert.updated_at || cert.created_at,
        status: driftStatus(metadata, cert.is_quantum_safe ? 'Resolved' : 'Unresolved'),
        expected: textValue(metadata.expected || metadata.expectedState || metadata.expected_state, 'PQC-ready certificate lifecycle'),
        actual: actualForDrift(cert, `${cert.algorithm || 'Unknown algorithm'} ${cert.key_size || ''}`.trim()),
      })
    }

    events.sort((a, b) => dateMs(b.detectedAt) - dateMs(a.detectedAt))

    const now = Date.now()
    const dayMs = 86400000
    const current24h = events.filter((event) => dateMs(event.detectedAt) >= now - dayMs)
    const previous24h = events.filter((event) => dateMs(event.detectedAt) < now - dayMs && dateMs(event.detectedAt) >= now - dayMs * 2)
    const unresolved = events.filter((event) => event.status === 'Unresolved')
    const critical = events.filter((event) => event.severity === 'critical' && event.status === 'Unresolved')
    const autoRemediated = events.filter((event) => event.status === 'Auto-Remediated')

    const driftDistribution = ['critical', 'high', 'medium', 'low'].map((severity) => {
      const count = events.filter((event) => event.severity === severity).length
      return {
        severity,
        count,
        percent: percentOf(count, Math.max(1, events.length)),
      }
    })

    const trend = Array.from({ length: 7 }, (_, index) => {
      const start = new Date()
      start.setHours(0, 0, 0, 0)
      start.setDate(start.getDate() - (6 - index))
      const end = new Date(start)
      end.setDate(start.getDate() + 1)
      const bucketEvents = events.filter((event) => {
        const time = dateMs(event.detectedAt)
        return time >= start.getTime() && time < end.getTime()
      })
      return {
        label: dateLabel(start.getTime()),
        critical: bucketEvents.filter((event) => event.severity === 'critical').length,
        high: bucketEvents.filter((event) => event.severity === 'high').length,
        medium: bucketEvents.filter((event) => event.severity === 'medium').length,
        low: bucketEvents.filter((event) => event.severity === 'low').length,
      }
    })

    const categories = Array.from(events.reduce((map, event) => {
      map.set(event.type, (map.get(event.type) || 0) + 1)
      return map
    }, new Map<string, number>()).entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)

    const unresolvedWeight = unresolved.reduce((sum, event) => sum + severityRank(event.severity), 0)
    const totalAssets = (assets || []).length
    const environmentRiskScore = Math.max(0, Math.min(100, Math.round((unresolvedWeight / Math.max(1, totalAssets * 4)) * 100)))
    const previousWeight = previous24h.reduce((sum, event) => sum + severityRank(event.severity), 0)
    const previousScore = Math.max(0, Math.min(100, Math.round((previousWeight / Math.max(1, totalAssets * 4)) * 100)))

    return res.json({
      data: {
        generatedAt: new Date().toISOString(),
        metrics: {
          unresolvedDrifts: unresolved.length,
          criticalDrifts: critical.length,
          autoRemediated: autoRemediated.length,
          totalEvents24h: current24h.length,
          unresolvedDelta: unresolved.length - previous24h.filter((event) => event.status === 'Unresolved').length,
          criticalDelta: critical.length - previous24h.filter((event) => event.severity === 'critical' && event.status === 'Unresolved').length,
          autoRemediatedDelta: autoRemediated.length - previous24h.filter((event) => event.status === 'Auto-Remediated').length,
          totalEventsDelta: current24h.length - previous24h.length,
          environmentRiskScore,
          environmentRiskDelta: environmentRiskScore - previousScore,
        },
        events,
        driftDistribution,
        trend,
        categories,
        recentActivity: events.slice(0, 6).map((event) => ({
          id: event.id,
          title: event.status === 'Auto-Remediated' ? `Auto-remediated ${event.type.toLowerCase()}` : event.event,
          resource: event.resource,
          timestamp: event.detectedAt,
          severity: event.severity,
          status: event.status,
        })),
      },
    })
  } catch (err) {
    console.error('Drift dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch drift telemetry' } })
  }
})

function vulnerabilityStatus(value: unknown) {
  const normalized = String(value || '').toLowerCase().replace(/\s+/g, '_')
  if (['resolved', 'remediated', 'fixed', 'closed', 'false_positive', 'accepted_risk'].includes(normalized)) return 'Remediated'
  if (['in_progress', 'investigating', 'triaged'].includes(normalized)) return 'In Progress'
  return 'Open'
}

function vulnerabilityType(text: string) {
  const lower = text.toLowerCase()
  if (lower.includes('tls') || lower.includes('protocol') || lower.includes('ssl')) return 'Protocol Weakness'
  if (lower.includes('rsa') || lower.includes('ecc') || lower.includes('ecdsa') || lower.includes('dh') || lower.includes('key exchange')) return 'Legacy Algorithm'
  if (lower.includes('sha1') || lower.includes('md5') || lower.includes('hash')) return 'Weak Hash'
  if (lower.includes('certificate') || lower.includes('cert') || lower.includes('pinning')) return 'Certificate Risk'
  if (lower.includes('library') || lower.includes('dependency') || lower.includes('component') || lower.includes('cve')) return 'Outdated Component'
  if (lower.includes('random') || lower.includes('rng') || lower.includes('entropy')) return 'Weak Cryptography'
  if (lower.includes('hybrid')) return 'No Hybrid Crypto'
  return 'Quantum Exposure'
}

function assetTypeLabel(value: string) {
  const lower = value.toLowerCase()
  if (lower.includes('web') || lower.includes('server')) return 'Web Server'
  if (lower.includes('app') || lower.includes('application')) return 'Web App'
  if (lower.includes('api') || lower.includes('gateway')) return 'API'
  if (lower.includes('mail') || lower.includes('smtp') || lower.includes('email')) return 'Mail Server'
  if (lower.includes('database') || lower.includes('db')) return 'Database'
  if (lower.includes('vpn')) return 'VPN Gateway'
  if (lower.includes('certificate') || lower.includes('pki')) return 'Certificate'
  return 'Other'
}

function vulnerabilityTitle(value: string) {
  const lower = value.toLowerCase()
  if (lower.includes('tls') && lower.includes('weak')) return 'Weak TLS Configuration Detected'
  if (lower.includes('information') || lower.includes('disclosure')) return 'Information Disclosure Detected'
  if (lower.includes('hybrid')) return 'No Hybrid Crypto Detected'
  if (lower.includes('pinning') || lower.includes('certificate')) return 'No Certificate Pinning Detected'
  if (lower.includes('key exchange') || lower.includes('dh') || lower.includes('rsa')) return 'Weak Key Exchange Algorithm'
  if (lower.includes('sha1') || lower.includes('md5')) return 'Weak Hash Algorithm'
  if (lower.includes('random') || lower.includes('entropy') || lower.includes('rng')) return 'Weak Random Number Generator'
  if (lower.includes('legacy')) return 'Legacy Algorithm Detected'
  return titleCase(value || 'Quantum Vulnerability Detected')
}

function vulnerabilityExposureLevel(severity: string) {
  if (severity === 'critical') return 'Critical'
  if (severity === 'high') return 'High'
  if (severity === 'medium') return 'Moderate'
  if (severity === 'low') return 'Low'
  return 'Informational'
}

function vulnerabilityRemediationBase(input: { title: string; description: string; algorithm?: string; type?: string; source?: string; remediation?: string }) {
  const text = [
    input.title,
    input.description,
    input.algorithm,
    input.type,
    input.source,
    input.remediation,
  ].map((value) => String(value || '').toLowerCase()).join(' ')

  if (/hndl|harvest|runtime|shadow|downgrade/.test(text)) return '/dashboard/live-migration'
  if (/certificate|cert|pki|x509|pinning|issuer|subject/.test(text)) return '/dashboard/certificate-telemetry'
  if (/tls|ssl|cipher|protocol|handshake/.test(text)) return '/dashboard/tls-orchestrator'
  if (/library|dependency|component|package|cve|repo|github|source/.test(text)) return '/dashboard/migration-planner'
  if (/random|rng|entropy/.test(text)) return '/dashboard/qrng'
  if (/api|gateway/.test(text)) return '/dashboard/api-encryption'
  if (/cloud|kms|bucket|storage/.test(text)) return '/dashboard/cloud'
  return '/dashboard/pqc-orchestration'
}

function vulnerabilityRemediationHref(input: {
  sourceId: string
  assetId?: string | null
  assetName: string
  title: string
  description: string
  severity: string
  algorithm?: string
  type?: string
  source?: string
  remediation?: string
}) {
  const params = new URLSearchParams({
    source: 'vulnerabilities',
    action: 'remediate',
    findingId: input.sourceId,
    asset: input.assetName,
    severity: input.severity,
  })
  if (input.assetId) params.set('assetId', input.assetId)
  if (input.algorithm) params.set('algorithm', input.algorithm)
  if (input.type) params.set('type', input.type)
  if (input.source) params.set('findingSource', input.source)
  return `${vulnerabilityRemediationBase(input)}?${params.toString()}`
}

function vulnerabilityScanTarget(asset: any, metadata: Record<string, unknown>) {
  const assetMetadata = recordOf(asset?.metadata)
  const candidates = [
    metadata.scanTarget,
    metadata.scan_target,
    metadata.authorizedTarget,
    metadata.authorized_target,
    metadata.target,
    metadata.url,
    metadata.endpoint,
    metadata.host,
    metadata.hostname,
    metadata.domain,
    assetMetadata.authorizedTarget,
    assetMetadata.authorized_target,
    assetMetadata.target,
    assetMetadata.url,
    assetMetadata.endpoint,
    assetMetadata.host,
    assetMetadata.hostname,
    assetMetadata.domain,
    asset?.name,
  ]
  for (const value of candidates) {
    const target = typeof value === 'string' ? value.trim() : ''
    if (target && !/^unassigned asset$/i.test(target)) return target
  }
  return null
}

function isLegacyAlgorithm(value: string) {
  return /rsa|rs256|ecdsa|ecdh|dh-|dsa|sha-1|sha1|md5|des|3des|rc4|aes-128-cbc|tls\s*1\.[012]|ssl/i.test(value)
}

function fingerprintPart(value: unknown) {
  return String(value || 'none').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'none'
}

function vulnerabilityRootCause(row: any) {
  const text = [
    row.title,
    row.description,
    row.algorithm,
    row.type,
    row.source,
    row.remediation,
  ].map((value) => String(value || '').toLowerCase()).join(' ')

  if (/no forward secrecy|forward secrecy|ephemeral key exchange|rsa key exchange|weak key exchange|diffie|dh-?\d|dhe|ecdh|tls_rsa|key exchange/.test(text)) {
    return {
      ruleId: 'weak-key-exchange',
      title: 'Weak Key Exchange Algorithm',
      type: 'Key Exchange Risk',
      description: 'No ephemeral key exchange - past traffic can be decrypted if the private key is compromised.',
      remediation: 'Disable RSA/static DH key exchange and require TLS 1.3 or ECDHE with a PQC/hybrid KEM migration path.',
    }
  }
  if (/tls\s*1\.[01]|tls-?1\.[01]|ssl|legacy protocol/.test(text)) {
    return {
      ruleId: 'legacy-tls-protocol',
      title: 'Legacy TLS Protocol',
      type: 'Protocol Risk',
      description: 'Legacy TLS or SSL protocol support was observed on this asset.',
      remediation: 'Disable SSL, TLS 1.0, and TLS 1.1; enforce TLS 1.2+ with TLS 1.3 preferred.',
    }
  }
  if (/sha-?1|md5|legacy mac|weak hash/.test(text)) {
    return {
      ruleId: 'weak-hash-or-mac',
      title: 'Weak Hash Or MAC Algorithm',
      type: 'Hash Risk',
      description: 'A weak hash or MAC primitive was observed in cryptographic telemetry.',
      remediation: 'Retire SHA-1/MD5 MAC usage and enforce SHA-384, SHA-3, or approved AEAD suites.',
    }
  }
  if (/cbc|3des|des|rc4|weak cipher|legacy cipher/.test(text)) {
    return {
      ruleId: 'weak-cipher-suite',
      title: 'Weak Cipher Suite',
      type: 'Cipher Suite Risk',
      description: 'A legacy or non-AEAD cipher suite was observed on this asset.',
      remediation: 'Disable CBC, RC4, DES, and 3DES suites; prefer AES-256-GCM or ChaCha20-Poly1305.',
    }
  }
  if (/certificate|cert|x509|issuer|subject|pki|pinning/.test(text)) {
    return {
      ruleId: 'certificate-risk',
      title: 'Certificate Risk',
      type: 'Certificate Risk',
      description: 'Certificate telemetry indicates a weak, expiring, or non-PQC-ready trust object.',
      remediation: 'Rotate the certificate and plan ML-DSA or hybrid certificate adoption.',
    }
  }
  if (/random|rng|entropy/.test(text)) {
    return {
      ruleId: 'weak-randomness',
      title: 'Weak Random Number Generator',
      type: 'Entropy Risk',
      description: 'Weak or insufficient entropy was observed in cryptographic telemetry.',
      remediation: 'Move key generation and nonce generation to approved QRNG or CSPRNG sources.',
    }
  }
  if (/hndl|harvest|shadow|downgrade|runtime/.test(text)) {
    return {
      ruleId: 'runtime-crypto-exposure',
      title: 'Runtime Crypto Exposure',
      type: 'Runtime Exposure',
      description: 'Runtime telemetry indicates a harvest-now or downgrade-sensitive cryptographic exposure.',
      remediation: 'Open live migration controls and migrate the affected flow to a PQC or hybrid profile.',
    }
  }

  const type = row.type || vulnerabilityType(`${row.title || ''} ${row.description || ''} ${row.algorithm || ''}`)
  const title = vulnerabilityTitle(row.title || type || row.description)
  return {
    ruleId: fingerprintPart(type || title),
    title,
    type,
    description: row.description || 'Cryptographic weakness detected in authenticated telemetry.',
    remediation: row.remediation || expectedForDrift(`${row.title || ''} ${row.description || ''}`, row.algorithm || ''),
  }
}

function vulnerabilityEvidenceLabel(row: any) {
  const algorithm = textValue(row.algorithm, '')
  if (algorithm) return algorithm
  const description = textValue(row.description, '')
  if (description) return description.replace(/\s+/g, ' ').slice(0, 140)
  return textValue(row.title, 'Telemetry observation')
}

function canonicalVulnerabilityRows(rawRows: any[]) {
  const groups = new Map<string, any>()

  for (const row of rawRows) {
    const root = vulnerabilityRootCause(row)
    const assetKey = row.assetId || fingerprintPart(row.asset)
    const key = `${assetKey}:${root.ruleId}`
    let group = groups.get(key)

    if (!group) {
      const id = `finding-${fingerprintPart(key)}`
      const severity = normalizeDriftSeverity(row.severity)
      group = {
        ...row,
        id,
        sourceId: row.sourceId || row.id,
        canonicalFingerprint: key,
        rootCause: root.ruleId,
        title: root.title,
        description: root.description,
        type: root.type,
        severity,
        exposureLevel: vulnerabilityExposureLevel(severity),
        remediation: root.remediation || row.remediation,
        evidenceMap: new Map<string, any>(),
        sourceIds: new Set<string>(),
        sources: new Set<string>(),
        algorithms: new Set<string>(),
      }
      groups.set(key, group)
    }

    group.sourceIds.add(row.sourceId || row.id)
    if (row.source) group.sources.add(row.source)
    if (row.algorithm) group.algorithms.add(row.algorithm)
    if (severityRank(row.severity) > severityRank(group.severity)) {
      group.severity = row.severity
      group.exposureLevel = vulnerabilityExposureLevel(row.severity)
    }
    if (row.status !== 'Remediated') group.status = row.status || 'Open'
    if (!group.detectedAt || (row.detectedAt && dateMs(row.detectedAt) < dateMs(group.detectedAt))) group.detectedAt = row.detectedAt
    if (row.scanTarget && !group.scanTarget) group.scanTarget = row.scanTarget
    if (row.assetId && !group.assetId) group.assetId = row.assetId

    const metadataEvidence = Array.isArray(row.metadataEvidence) ? row.metadataEvidence : []
    const evidenceSources = metadataEvidence.length ? metadataEvidence : [row]
    for (const evidenceSource of evidenceSources) {
      const evidenceRecord = recordOf(evidenceSource)
      const evidenceLabel = textValue(evidenceRecord.label, textValue(evidenceRecord.algorithm, vulnerabilityEvidenceLabel(row)))
      const evidenceDescription = textValue(evidenceRecord.description, row.description || '')
      const evidenceAlgorithm = textValue(evidenceRecord.algorithm, row.algorithm || '')
      const evidenceSourceName = textValue(evidenceRecord.source, row.source || 'telemetry')
      const evidenceDetectedAt = textValue(evidenceRecord.detectedAt, row.detectedAt || '')
      const evidenceKey = fingerprintPart(`${evidenceSourceName}:${evidenceLabel}:${evidenceDescription}:${evidenceRecord.location || ''}`)
      if (evidenceAlgorithm) group.algorithms.add(evidenceAlgorithm)
      if (!group.evidenceMap.has(evidenceKey)) {
        group.evidenceMap.set(evidenceKey, {
          id: textValue(evidenceRecord.id, row.sourceId || row.id),
          label: evidenceLabel,
          description: evidenceDescription,
          algorithm: evidenceAlgorithm,
          source: evidenceSourceName,
          severity: textValue(evidenceRecord.severity, row.severity),
          detectedAt: evidenceDetectedAt || row.detectedAt,
        })
      }
    }
  }

  return Array.from(groups.values()).map((group) => {
    const evidence = Array.from(group.evidenceMap.values())
      .sort((a: any, b: any) => severityRank(b.severity) - severityRank(a.severity) || String(a.label).localeCompare(String(b.label)))
    const sourceIds = Array.from(group.sourceIds)
    const sources = Array.from(group.sources)
    const algorithms = Array.from(group.algorithms)
    const primarySourceId = sourceIds[0] || group.sourceId || group.id
    const remediationHref = vulnerabilityRemediationHref({
      sourceId: primarySourceId,
      assetId: group.assetId,
      assetName: group.asset,
      title: group.title,
      description: group.description,
      severity: group.severity,
      algorithm: algorithms.join(', '),
      type: group.type,
      source: sources.join(', '),
      remediation: group.remediation,
    })

    return {
      ...group,
      sourceId: primarySourceId,
      source: sources.join(', ') || group.source,
      sourceIds,
      evidence: evidence.slice(0, 50),
      evidenceCount: evidence.length,
      algorithm: algorithms.slice(0, 12).join(', '),
      remediationHref,
      inspectHref: `/dashboard/crypto-exposure?${new URLSearchParams({
        source: 'vulnerabilities',
        findingId: primarySourceId,
        rootCause: group.rootCause,
        ...(group.assetId ? { assetId: group.assetId } : {}),
      }).toString()}`,
      metadataEvidence: undefined,
      evidenceMap: undefined,
      sources: undefined,
      algorithms: undefined,
    }
  })
}

function startOfDayMs(daysAgo: number) {
  const date = new Date()
  date.setHours(0, 0, 0, 0)
  date.setDate(date.getDate() - daysAgo)
  return date.getTime()
}

/**
 * GET /api/v1/dashboard/vulnerabilities
 * Returns user-specific vulnerability telemetry derived from vulnerability
 * records, crypto exposures, scan results, CBOM inventory, certificates,
 * migration remediation activity, and scanner sessions.
 */
router.get('/vulnerabilities', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const [assets, vulnerabilities, exposures, scanResults, inventory, certificates, migrationJobs, scanSessions, securityEvents] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'vulnerabilities', (q) => q.select('id, asset_id, title, description, severity, cvss_score, status, source, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(750)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(1000)),
      safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(80)),
      safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(300)),
    ])

    const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
    const rows: any[] = []
    const seen = new Set<string>()

    const addRow = (row: any) => {
      const key = `${row.assetId || 'none'}:${row.title}:${row.algorithm || ''}:${row.sourceId}`
      if (seen.has(key)) return
      seen.add(key)
      rows.push(row)
    }

    const buildRow = (input: {
      sourceId: string
      assetId?: string | null
      title: string
      description: string
      severity: string
      status?: string
      detectedAt?: string | null
      algorithm?: string
      type?: string
      metadata?: Record<string, unknown>
      source?: string
    }) => {
      const asset = input.assetId ? assetMap.get(input.assetId) || {} : {}
      const text = `${input.title} ${input.description} ${input.algorithm || ''} ${input.type || ''}`
      const severity = normalizeDriftSeverity(input.severity)
      const status = vulnerabilityStatus(input.status || input.metadata?.status)
      const title = vulnerabilityTitle(input.title || input.type || input.description)
      const assetName = textValue(asset.name, textValue(input.metadata?.resourceName || input.metadata?.resource_name, 'Unassigned asset'))
      const type = input.type || vulnerabilityType(text)
      const remediation = textValue(input.metadata?.remediation || input.metadata?.pqcReplacement || input.metadata?.pqc_replacement, expectedForDrift(text, input.algorithm || ''))
      return {
        id: input.sourceId,
        sourceId: input.sourceId,
        assetId: input.assetId || null,
        source: input.source || 'dashboard_vulnerability',
        scanTarget: vulnerabilityScanTarget(asset, input.metadata || {}),
        metadataEvidence: Array.isArray(input.metadata?.evidence) ? input.metadata.evidence : [],
        title,
        description: input.description || 'Cryptographic weakness detected in authenticated telemetry.',
        asset: assetName,
        assetType: assetTypeLabel(textValue(asset.type, textValue(input.metadata?.assetType || input.metadata?.asset_type, input.source || 'Other'))),
        environment: textValue(asset.environment, textValue(asset.region, textValue(input.metadata?.environment, 'unassigned'))),
        severity,
        exposureLevel: vulnerabilityExposureLevel(severity),
        type,
        detectedAt: input.detectedAt || null,
        status,
        algorithm: input.algorithm || '',
        remediation,
        remediationHref: vulnerabilityRemediationHref({
          sourceId: input.sourceId,
          assetId: input.assetId,
          assetName,
          title,
          description: input.description || '',
          severity,
          algorithm: input.algorithm || '',
          type,
          source: input.source,
          remediation,
        }),
        inspectHref: `/dashboard/crypto-exposure?${new URLSearchParams({
          source: 'vulnerabilities',
          findingId: input.sourceId,
          ...(input.assetId ? { assetId: input.assetId } : {}),
        }).toString()}`,
      }
    }

    for (const vuln of vulnerabilities || []) {
      const metadata = recordOf(vuln.metadata)
      addRow(buildRow({
        sourceId: `vulnerability-${vuln.id}`,
        assetId: vuln.asset_id,
        title: vuln.title || 'Quantum vulnerability detected',
        description: vuln.description || vuln.title || 'Vulnerability record detected.',
        severity: vuln.severity,
        status: vuln.status,
        detectedAt: vuln.updated_at || vuln.created_at,
        algorithm: textValue(metadata.algorithm, ''),
        type: textValue(metadata.vulnerabilityType || metadata.vulnerability_type, vulnerabilityType(`${vuln.title || ''} ${vuln.description || ''}`)),
        metadata,
        source: vuln.source,
      }))
    }

    for (const exposure of exposures || []) {
      const metadata = recordOf(exposure.metadata)
      addRow(buildRow({
        sourceId: `exposure-${exposure.id}`,
        assetId: exposure.asset_id,
        title: exposure.description || exposure.exposure_type || 'Crypto exposure detected',
        description: exposure.description || `Detected ${exposure.exposure_type || 'cryptographic exposure'} ${exposure.detected_value ? `(${exposure.detected_value})` : ''}`.trim(),
        severity: exposure.severity,
        status: textValue(metadata.status, ''),
        detectedAt: exposure.updated_at || exposure.created_at,
        algorithm: textValue(exposure.detected_value, ''),
        type: vulnerabilityType(`${exposure.exposure_type || ''} ${exposure.description || ''} ${exposure.detected_value || ''}`),
        metadata,
        source: 'crypto_exposure',
      }))
    }

    for (const result of scanResults || []) {
      const metadata = recordOf(result.metadata)
      addRow(buildRow({
        sourceId: `scan-${result.id}`,
        assetId: result.asset_id,
        title: result.description || result.finding_type || 'Scan vulnerability detected',
        description: result.description || `Scanner detected ${result.finding_type || 'quantum weakness'}`,
        severity: result.threat_level,
        status: textValue(metadata.status, ''),
        detectedAt: result.created_at,
        algorithm: result.algorithm || '',
        type: vulnerabilityType(`${result.finding_type || ''} ${result.description || ''} ${result.algorithm || ''}`),
        metadata: { ...metadata, remediation: result.remediation },
        source: 'scan_result',
      }))
    }

    for (const item of inventory || []) {
      if (!item.is_vulnerable || item.is_quantum_safe) continue
      const metadata = recordOf(item.metadata)
      const severity = textValue(item.exposure_level, isLegacyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`) ? 'high' : 'medium')
      addRow(buildRow({
        sourceId: `inventory-${item.id}`,
        assetId: item.asset_id,
        title: `${item.algorithm || item.name || item.item_type || 'Legacy algorithm'} detected`,
        description: `${item.name || item.item_type || 'Cryptographic inventory item'} uses ${item.algorithm || item.protocol || 'a quantum-vulnerable primitive'}.`,
        severity,
        status: textValue(metadata.status, ''),
        detectedAt: item.discovered_at || item.created_at,
        algorithm: textValue(item.algorithm, textValue(item.protocol, '')),
        type: vulnerabilityType(`${item.item_type || ''} ${item.algorithm || ''} ${item.protocol || ''}`),
        metadata,
        source: 'crypto_inventory',
      }))
    }

    for (const cert of certificates || []) {
      if (cert.is_quantum_safe && !cert.is_expiring_soon && !isLegacyAlgorithm(`${cert.algorithm || ''}`)) continue
      const metadata = recordOf(cert.metadata)
      addRow(buildRow({
        sourceId: `certificate-${cert.id}`,
        assetId: cert.asset_id,
        title: cert.is_expiring_soon ? 'Certificate Rotation Exposure' : `${cert.algorithm || 'Legacy certificate'} detected`,
        description: cert.is_expiring_soon ? `${cert.name || cert.subject || 'Certificate'} is expiring soon.` : `${cert.name || cert.subject || 'Certificate'} uses ${cert.algorithm || 'a non-PQC algorithm'}.`,
        severity: cert.is_expiring_soon ? 'medium' : isLegacyAlgorithm(`${cert.algorithm || ''}`) ? 'high' : 'low',
        status: cert.is_quantum_safe ? 'resolved' : cert.status,
        detectedAt: cert.updated_at || cert.created_at,
        algorithm: textValue(cert.algorithm, ''),
        type: 'Certificate Risk',
        metadata,
        source: 'certificate',
      }))
    }

    const canonicalRows = canonicalVulnerabilityRows(rows)
    const remediatedJobs = (migrationJobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'completed')
    const remediatedRows = canonicalRows.filter((row) => row.status === 'Remediated').length
    const remediated = remediatedRows + remediatedJobs.length
    const openRows = canonicalRows.filter((row) => row.status !== 'Remediated')
    const criticalExposure = openRows.filter((row) => row.severity === 'critical').length
    const legacyAlgorithms = canonicalRows.filter((row) => row.status !== 'Remediated' && isLegacyAlgorithm(`${row.algorithm || ''} ${row.description || ''} ${row.title || ''}`)).length

    const now = Date.now()
    const current7d = canonicalRows.filter((row) => dateMs(row.detectedAt) >= now - 7 * 86400000)
    const previous7d = canonicalRows.filter((row) => dateMs(row.detectedAt) < now - 7 * 86400000 && dateMs(row.detectedAt) >= now - 14 * 86400000)
    const previousCritical = previous7d.filter((row) => row.severity === 'critical' && row.status !== 'Remediated').length
    const previousLegacy = previous7d.filter((row) => isLegacyAlgorithm(`${row.algorithm || ''} ${row.description || ''} ${row.title || ''}`)).length
    const previousRemediated = (migrationJobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'completed' && dateMs(job.completed_at || job.updated_at) < now - 7 * 86400000 && dateMs(job.completed_at || job.updated_at) >= now - 14 * 86400000).length

    const severityBreakdown = ['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
      const count = canonicalRows.filter((row) => row.severity === severity || (severity === 'info' && !['critical', 'high', 'medium', 'low'].includes(row.severity))).length
      return { severity, count, percent: percentOf(count, Math.max(1, canonicalRows.length)) }
    })

    const assetTypeBreakdown = Array.from(canonicalRows.reduce((map, row) => {
      map.set(row.assetType, (map.get(row.assetType) || 0) + 1)
      return map
    }, new Map<string, number>()).entries())
      .map(([label, count]) => ({ label, count, percent: percentOf(count, Math.max(1, canonicalRows.length)) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6)

    const trend = Array.from({ length: 7 }, (_, index) => {
      const start = startOfDayMs(6 - index)
      const end = start + 86400000
      const bucket = canonicalRows.filter((row) => {
        const time = dateMs(row.detectedAt)
        return time >= start && time < end
      })
      return {
        label: new Date(start).toLocaleDateString('en-US', { month: 'short', day: '2-digit' }),
        critical: bucket.filter((row) => row.severity === 'critical').length,
        high: bucket.filter((row) => row.severity === 'high').length,
        medium: bucket.filter((row) => row.severity === 'medium').length,
        low: bucket.filter((row) => row.severity === 'low').length,
        info: bucket.filter((row) => !['critical', 'high', 'medium', 'low'].includes(row.severity)).length,
      }
    })

    type VulnerabilityTopAsset = { asset: string; severity: string; count: number }
    const topAssetMap = canonicalRows.reduce((map: Map<string, VulnerabilityTopAsset>, row) => {
      const current = map.get(row.asset) || { asset: row.asset, severity: row.severity, count: 0 }
      current.count += 1
      if (severityRank(row.severity) > severityRank(current.severity)) current.severity = row.severity
      map.set(row.asset, current)
      return map
    }, new Map<string, VulnerabilityTopAsset>())
    const topAssets = Array.from<VulnerabilityTopAsset>(topAssetMap.values())
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.count - a.count)
      .slice(0, 6)

    const latestScan = (scanSessions || [])[0] || null
    const nextScanAt = latestScan?.completed_at
      ? new Date(dateMs(latestScan.completed_at) + 24 * 86400000).toISOString()
      : latestScan?.started_at
        ? new Date(dateMs(latestScan.started_at) + 24 * 86400000).toISOString()
        : null

    return res.json({
      data: {
        generatedAt: new Date().toISOString(),
        metrics: {
          criticalExposure,
          criticalExposureDelta: criticalExposure - previousCritical,
          legacyAlgorithms,
          legacyAlgorithmsDelta: legacyAlgorithms - previousLegacy,
          remediated,
          remediatedDelta: remediated - previousRemediated,
          totalVulnerabilities: canonicalRows.length,
          current7d: current7d.length,
        },
        filters: {
          environments: Array.from(new Set(canonicalRows.map((row) => row.environment).filter(Boolean))).sort(),
          assetTypes: Array.from(new Set(canonicalRows.map((row) => row.assetType).filter(Boolean))).sort(),
          vulnerabilityTypes: Array.from(new Set(canonicalRows.map((row) => row.type).filter(Boolean))).sort(),
        },
        vulnerabilities: canonicalRows.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || dateMs(b.detectedAt) - dateMs(a.detectedAt)),
        severityBreakdown,
        assetTypeBreakdown,
        trend,
        topAssets,
        scanStatus: {
          latestScanAt: latestScan?.completed_at || latestScan?.updated_at || latestScan?.started_at || null,
          nextScanAt,
          activeScans: (scanSessions || []).filter((scan: any) => ['pending', 'running', 'analyzing'].includes(String(scan.status || '').toLowerCase())).length,
          latestStatus: latestScan?.status || 'not_started',
          telemetryEvents: (securityEvents || []).length,
        },
      },
    })
  } catch (err) {
    console.error('Vulnerabilities dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch vulnerability telemetry' } })
  }
})

/**
 * GET /api/v1/dashboard/runtime-crypto-intel
 * Returns user-specific runtime cryptographic intelligence derived from
 * authenticated telemetry, scan discoveries, cryptographic inventory,
 * security events, generated keys, audit trails, and migration activity.
 */
router.get('/runtime-crypto-intel', async (req: Request, res: Response) => {
  try {
    const user = (req as any).user
    const token = (req as any).token
    const client = createAuthClient(token)

    if (!client) {
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
    }

    const [
      assets,
      relationships,
      runtimeEvents,
      inventory,
      exposures,
      scanResults,
      scanSessions,
      securityEvents,
      migrationJobs,
      migrationEvents,
      certificates,
      qrngEvents,
      vaultAuditLogs,
      generatedKeys,
      scannerAgents,
      scannerAlerts,
    ] = await Promise.all([
      safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'asset_relationships', (q) => q.select('id, source_asset_id, target_asset_id, relationship_type, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(500)),
      safeRows(client, 'runtime_crypto_events', (q) => q.select('id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, certificate_fingerprint, package_name, package_version, process_name, process_id, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, event_hash, metadata, observed_at, created_at').eq('user_id', user.id).order('observed_at', { ascending: false }).limit(2000)),
      safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', user.id).order('discovered_at', { ascending: false }).limit(1000)),
      safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(1000)),
      safeRows(client, 'pqc_scan_results', (q) => q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
      safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(120)),
      safeRows(client, 'security_events', (q) => q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(500)),
      safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(500)),
      safeRows(client, 'migration_events', (q) => q.select('id, migration_id, event_type, message, severity, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(500)),
      safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, issuer, subject, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(750)),
      safeRows(client, 'qrng_events', (q) => q.select('id, event_type, key_type, algorithm, key_length, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(500)),
      safeRows(client, 'vault_audit_logs', (q) => q.select('id, event_type, metadata, created_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(500)),
      safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(1000)),
      safeRows(client, 'scanner_agents', (q) => q.select('id, name, status, hostname, platform, capabilities, last_seen_at, metadata, created_at, updated_at').eq('user_id', user.id).order('updated_at', { ascending: false }).limit(250)),
      safeRows(client, 'scanner_alerts', (q) => q.select('id, agent_id, connector_account_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', user.id).order('created_at', { ascending: false }).limit(500)),
    ])

    const now = Date.now()
    const oneDay = 86400000
    const current7dStart = now - 7 * oneDay
    const previous7dStart = now - 14 * oneDay
    const assetMap = new Map<string, any>((assets || []).map((asset: any) => [asset.id, asset]))
    const jobMap = new Map<string, any>((migrationJobs || []).map((job: any) => [job.id, job]))
    const hasRuntimeEvents = (runtimeEvents || []).length > 0

    const resourceName = (assetId: unknown, fallback = 'Runtime asset') => {
      const asset = typeof assetId === 'string' ? assetMap.get(assetId) : null
      return textValue(asset?.name, fallback)
    }

    const eventText = (row: any, ...fields: string[]) => {
      const metadata = recordOf(row?.metadata)
      return fields
        .map((field) => textValue(row?.[field], ''))
        .concat(Object.values(metadata).filter((value) => typeof value === 'string').map(String))
        .join(' ')
    }

    const normalizeProtocol = (value: unknown) => {
      const lower = String(value || '').toLowerCase()
      if (lower.includes('tls 1.3') || lower.includes('tls-1.3') || lower.includes('tlsv1.3') || lower === 'tls1.3') return 'TLS 1.3'
      if (lower.includes('tls 1.2') || lower.includes('tls-1.2') || lower.includes('tlsv1.2') || lower === 'tls1.2') return 'TLS 1.2'
      if (lower.includes('mtls') || lower.includes('mutual tls')) return 'mTLS'
      if (lower.includes('ssh')) return 'SSH'
      if (lower.includes('ipsec') || lower.includes('ip sec') || lower.includes('vpn')) return 'IPsec'
      return 'Other'
    }

    const normalizeAlgorithm = (value: unknown, fallback = 'Unknown') => {
      const text = textValue(value, fallback)
      return text
        .replace(/\s+/g, ' ')
        .replace(/kyber/ig, 'ML-KEM')
        .replace(/dilithium/ig, 'Dilithium')
        .trim() || fallback
    }

    const operationType = (text: string) => {
      const lower = text.toLowerCase()
      if (lower.includes('decrypt') || lower.includes('unwrap')) return 'decryption'
      if (lower.includes('verify') || lower.includes('validation')) return 'verification'
      if (lower.includes('sign') || lower.includes('jwt') || lower.includes('signature') || lower.includes('dsa')) return 'signing'
      if (lower.includes('handshake') || lower.includes('kem') || lower.includes('key exchange') || lower.includes('tls') || lower.includes('dh') || lower.includes('rsa')) return 'keyExchange'
      if (lower.includes('key') || lower.includes('rotate') || lower.includes('qrng') || lower.includes('entropy')) return 'keyUsage'
      if (lower.includes('encrypt') || lower.includes('cipher') || lower.includes('aes')) return 'encryption'
      return 'other'
    }

    const rateDelta = (current: number, previous: number) => {
      if (previous <= 0) return current > 0 ? 100 : 0
      return Math.round(((current - previous) / previous) * 100)
    }

    const operations: any[] = []
    const addOperation = (input: any) => {
      const timestamp = input.timestamp || input.createdAt || null
      operations.push({
        ...input,
        timestamp,
        ms: dateMs(timestamp),
        type: input.type || operationType(`${input.label || ''} ${input.text || ''} ${input.algorithm || ''} ${input.protocol || ''}`),
      })
    }

    for (const event of runtimeEvents || []) {
      const metadata = recordOf(event.metadata)
      addOperation({
        id: `runtime-${event.id}`,
        source: 'runtime_crypto_events',
        label: titleCase(event.event_type || 'Runtime Crypto Event'),
        text: `${event.operation_type || ''} ${event.algorithm || ''} ${event.key_exchange_algorithm || ''} ${event.cipher_suite || ''} ${event.tls_version || ''} ${event.protocol || ''} ${event.shadow_crypto ? 'shadow crypto' : ''} ${event.downgrade_detected ? 'downgrade' : ''} ${event.hndl_risk ? 'hndl risk' : ''}`,
        severity: normalizeDriftSeverity(event.severity),
        assetId: event.asset_id,
        resource: textValue(event.asset_name, resourceName(event.asset_id, textValue(event.host, 'Runtime asset'))),
        algorithm: textValue(event.algorithm, textValue(event.key_exchange_algorithm, textValue(event.cipher_suite, textValue(event.tls_version, '')))),
        protocol: textValue(event.protocol, textValue(event.tls_version, '')),
        metadata,
        timestamp: event.observed_at || event.created_at,
        tlsVersion: event.tls_version,
        cipherSuite: event.cipher_suite,
        keyExchangeAlgorithm: event.key_exchange_algorithm,
        packageName: event.package_name,
        riskScore: event.risk_score,
        type: event.operation_type === 'key_exchange'
          ? 'keyExchange'
          : event.operation_type === 'key_usage'
            ? 'keyUsage'
            : event.operation_type || undefined,
        flags: {
          isPqc: Boolean(event.is_pqc),
          isLegacy: Boolean(event.is_legacy),
          downgradeDetected: Boolean(event.downgrade_detected),
          shadowCrypto: Boolean(event.shadow_crypto),
          hndlRisk: Boolean(event.hndl_risk),
        },
      })
    }

    if (!hasRuntimeEvents) {
      for (const event of securityEvents || []) {
        addOperation({
          id: `security-${event.id}`,
          source: 'security_events',
          label: titleCase(event.event_type || 'Security Event'),
          text: event.message || '',
          severity: normalizeDriftSeverity(event.severity),
          assetId: event.asset_id,
          resource: event.resource_name || resourceName(event.asset_id, textValue(event.resource_type, 'Runtime asset')),
          timestamp: event.created_at,
        })
      }

      for (const event of migrationEvents || []) {
        const job = jobMap.get(event.migration_id) || {}
        addOperation({
          id: `migration-event-${event.id}`,
          source: 'migration_events',
          label: titleCase(event.event_type || 'Migration Event'),
          text: event.message || '',
          severity: normalizeDriftSeverity(event.severity),
          assetId: job.asset_id,
          resource: job.name || resourceName(job.asset_id, 'Migration workflow'),
          algorithm: job.target_algorithm,
          timestamp: event.created_at,
        })
      }

      for (const job of migrationJobs || []) {
        addOperation({
          id: `migration-job-${job.id}`,
          source: 'migration_jobs',
          label: job.name || titleCase(job.job_type || 'Migration Job'),
          text: `${job.job_type || ''} ${job.strategy || ''} ${job.target_algorithm || ''} ${job.status || ''}`,
          severity: normalizeJobStatus(job.status) === 'failed' ? 'high' : 'low',
          assetId: job.asset_id,
          resource: job.name || resourceName(job.asset_id, 'Migration workflow'),
          algorithm: job.target_algorithm,
          timestamp: job.updated_at || job.completed_at || job.started_at || job.created_at,
        })
      }

      for (const event of qrngEvents || []) {
        addOperation({
          id: `qrng-${event.id}`,
          source: 'qrng_events',
          label: titleCase(event.event_type || 'QRNG Event'),
          text: `${event.key_type || ''} ${event.algorithm || ''} ${event.key_length || ''}`,
          severity: 'low',
          resource: textValue(event.key_type, 'QRNG key material'),
          algorithm: event.algorithm,
          timestamp: event.created_at,
        })
      }

      for (const log of vaultAuditLogs || []) {
        const metadata = recordOf(log.metadata)
        addOperation({
          id: `vault-${log.id}`,
          source: 'vault_audit_logs',
          label: titleCase(log.event_type || 'Vault Audit'),
          text: eventText(log, 'event_type'),
          severity: normalizeDriftSeverity(metadata.severity || metadata.result || metadata.status),
          resource: textValue(metadata.resourceName || metadata.resource_name || metadata.fileName || metadata.file_name, 'Vault record'),
          timestamp: log.created_at,
        })
      }

      for (const key of generatedKeys || []) {
        addOperation({
          id: `key-${key.id}`,
          source: 'generated_keys',
          label: textValue(key.label, 'Generated Key'),
          text: `${key.algorithm || ''} ${key.entropy_source || ''} ${key.status || ''}`,
          severity: key.status === 'revoked' ? 'medium' : 'low',
          resource: textValue(key.label, 'Generated key'),
          algorithm: key.algorithm,
          timestamp: key.updated_at || key.created_at,
        })
      }

      for (const item of inventory || []) {
        addOperation({
          id: `inventory-${item.id}`,
          source: 'crypto_inventory',
          label: item.name || titleCase(item.item_type || 'Crypto Inventory'),
          text: `${item.item_type || ''} ${item.algorithm || ''} ${item.protocol || ''} ${item.exposure_level || ''}`,
          severity: item.is_vulnerable && !item.is_quantum_safe ? normalizeDriftSeverity(item.exposure_level || 'medium') : 'low',
          assetId: item.asset_id,
          resource: item.name || resourceName(item.asset_id, 'Discovered crypto'),
          algorithm: item.algorithm,
          protocol: item.protocol,
          timestamp: item.discovered_at || item.created_at,
        })
      }

      for (const cert of certificates || []) {
        addOperation({
          id: `certificate-${cert.id}`,
          source: 'certificates',
          label: cert.name || cert.subject || 'Certificate',
          text: `${cert.algorithm || ''} ${cert.status || ''} ${cert.is_expiring_soon ? 'expiring' : ''}`,
          severity: cert.is_expiring_soon || (!cert.is_quantum_safe && isLegacyAlgorithm(`${cert.algorithm || ''}`)) ? 'medium' : 'low',
          assetId: cert.asset_id,
          resource: cert.name || cert.subject || resourceName(cert.asset_id, 'Certificate'),
          algorithm: cert.algorithm,
          timestamp: cert.updated_at || cert.created_at,
        })
      }

      for (const exposure of exposures || []) {
        addOperation({
          id: `exposure-${exposure.id}`,
          source: 'crypto_exposures',
          label: titleCase(exposure.exposure_type || 'Crypto Exposure'),
          text: `${exposure.description || ''} ${exposure.detected_value || ''}`,
          severity: normalizeDriftSeverity(exposure.severity),
          assetId: exposure.asset_id,
          resource: resourceName(exposure.asset_id, 'Crypto exposure'),
          algorithm: exposure.detected_value,
          timestamp: exposure.updated_at || exposure.created_at,
        })
      }

      for (const result of scanResults || []) {
        addOperation({
          id: `scan-result-${result.id}`,
          source: 'pqc_scan_results',
          label: titleCase(result.finding_type || 'Scan Finding'),
          text: `${result.description || ''} ${result.algorithm || ''} ${result.threat_level || ''}`,
          severity: normalizeDriftSeverity(result.threat_level),
          assetId: result.asset_id,
          resource: resourceName(result.asset_id, 'Scan finding'),
          algorithm: result.algorithm,
          timestamp: result.created_at,
        })
      }
    }

    const recentOps = operations.filter((item) => item.ms >= now - oneDay)
    const currentOps7d = operations.filter((item) => item.ms >= current7dStart)
    const previousOps7d = operations.filter((item) => item.ms >= previous7dStart && item.ms < current7dStart)
    const countType = (items: any[], types: string[]) => items.filter((item) => types.includes(item.type)).length
    const ratePerSecond = (count: number) => Number((count / (24 * 60 * 60)).toFixed(count >= 864000 ? 0 : count >= 86400 ? 1 : 2))

    const encryptionCurrent = countType(recentOps, ['encryption'])
    const decryptionCurrent = countType(recentOps, ['decryption'])
    const keyUsageCurrent = countType(recentOps, ['keyUsage', 'keyExchange', 'signing', 'verification'])
    const pqcHandshakeCurrent = recentOps.filter((item) => isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.text || ''} ${item.protocol || ''}`) && ['keyExchange', 'keyUsage'].includes(item.type)).length
    const previousEncryption = countType(previousOps7d, ['encryption'])
    const previousDecryption = countType(previousOps7d, ['decryption'])
    const previousKeyUsage = countType(previousOps7d, ['keyUsage', 'keyExchange', 'signing', 'verification'])
    const previousPqcHandshake = previousOps7d.filter((item) => isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.text || ''} ${item.protocol || ''}`) && ['keyExchange', 'keyUsage'].includes(item.type)).length

    const buckets = Array.from({ length: 24 }, (_, index) => {
      const start = now - (23 - index) * 60 * 60 * 1000
      const end = start + 60 * 60 * 1000
      const bucketOps = operations.filter((item) => item.ms >= start && item.ms < end)
      return {
        label: new Date(start).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
        encryption: countType(bucketOps, ['encryption']),
        decryption: countType(bucketOps, ['decryption']),
        keyUsage: countType(bucketOps, ['keyUsage', 'keyExchange', 'signing', 'verification']),
        other: countType(bucketOps, ['other']),
      }
    })

    const algorithmCounts = new Map<string, { count: number; timestamps: number[] }>()
    const addAlgorithm = (value: unknown, timestamp: unknown) => {
      const algorithm = normalizeAlgorithm(value, '')
      if (!algorithm) return
      const existing = algorithmCounts.get(algorithm) || { count: 0, timestamps: [] }
      existing.count += 1
      existing.timestamps.push(dateMs(timestamp))
      algorithmCounts.set(algorithm, existing)
    }

    for (const event of runtimeEvents || []) addAlgorithm(event.algorithm || event.key_exchange_algorithm || event.cipher_suite || event.tls_version || event.protocol, event.observed_at || event.created_at)
    if (!hasRuntimeEvents) {
      for (const item of inventory || []) addAlgorithm(item.algorithm || item.protocol, item.discovered_at || item.created_at)
      for (const cert of certificates || []) addAlgorithm(cert.algorithm, cert.updated_at || cert.created_at)
      for (const result of scanResults || []) addAlgorithm(result.algorithm, result.created_at)
      for (const exposure of exposures || []) addAlgorithm(exposure.detected_value, exposure.updated_at || exposure.created_at)
      for (const key of generatedKeys || []) addAlgorithm(key.algorithm, key.created_at)
      for (const event of qrngEvents || []) addAlgorithm(event.algorithm, event.created_at)
    }

    const algorithmTotal = Array.from(algorithmCounts.values()).reduce((sum, row) => sum + row.count, 0)
    const algorithmUsage = Array.from(algorithmCounts.entries())
      .map(([algorithm, row]) => {
        const trend = Array.from({ length: 12 }, (_, index) => {
          const start = now - (11 - index) * 6 * 60 * 60 * 1000
          const end = start + 6 * 60 * 60 * 1000
          return row.timestamps.filter((time) => time >= start && time < end).length
        })
        return {
          algorithm,
          usage: row.count,
          percent: percentOf(row.count, Math.max(1, algorithmTotal)),
          trend,
        }
      })
      .sort((a, b) => b.usage - a.usage)
      .slice(0, 10)

    const protocolCounts = new Map<string, number>([
      ['TLS 1.3', 0],
      ['TLS 1.2', 0],
      ['mTLS', 0],
      ['SSH', 0],
      ['IPsec', 0],
      ['Other', 0],
    ])
    const addProtocol = (value: unknown) => {
      const protocol = normalizeProtocol(value)
      protocolCounts.set(protocol, (protocolCounts.get(protocol) || 0) + 1)
    }
    for (const event of runtimeEvents || []) addProtocol(event.protocol || event.tls_version || event.event_type || event.algorithm)
    if (!hasRuntimeEvents) {
      for (const item of inventory || []) addProtocol(item.protocol || `${item.name || ''} ${item.item_type || ''}`)
      for (const event of securityEvents || []) addProtocol(`${event.event_type || ''} ${event.message || ''}`)
      for (const result of scanResults || []) addProtocol(`${result.finding_type || ''} ${result.description || ''}`)
    }
    const protocolTotal = Array.from(protocolCounts.values()).reduce((sum, count) => sum + count, 0)
    const protocolUsage = Array.from(protocolCounts.entries())
      .map(([label, count]) => ({ label, count, percent: percentOf(count, Math.max(1, protocolTotal)) }))
      .filter((row) => row.count > 0 || row.label !== 'Other')

    const healthItems = [
      ...(runtimeEvents || []).map((event: any) => ({
        severity: event.is_pqc && !event.is_legacy && !event.downgrade_detected && !event.shadow_crypto && !event.hndl_risk ? 'strong' : normalizeDriftSeverity(event.severity || (event.risk_score >= 80 ? 'critical' : event.risk_score >= 60 ? 'high' : event.risk_score >= 40 ? 'medium' : 'low')),
      })),
      ...(inventory || []).map((item: any) => ({
        severity: item.is_quantum_safe || isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`) ? 'strong' : normalizeDriftSeverity(item.exposure_level || (item.is_vulnerable ? 'medium' : 'low')),
      })),
      ...(certificates || []).map((cert: any) => ({
        severity: cert.is_quantum_safe ? 'strong' : cert.is_expiring_soon || isLegacyAlgorithm(`${cert.algorithm || ''}`) ? 'medium' : 'low',
      })),
      ...(exposures || []).map((exposure: any) => ({ severity: normalizeDriftSeverity(exposure.severity) })),
    ]
    const healthTotal = Math.max(1, healthItems.length)
    const strong = healthItems.filter((item) => item.severity === 'strong' || item.severity === 'low').length
    const warning = healthItems.filter((item) => item.severity === 'medium').length
    const weak = healthItems.filter((item) => item.severity === 'high').length
    const critical = healthItems.filter((item) => item.severity === 'critical').length
    const healthScore = clampPercent((strong / healthTotal) * 100 - critical * 3 - weak)

    const openExposureCount = (exposures || []).filter((exposure: any) => severityRank(exposure.severity || '') >= 2).length
    const weakInventoryCount = (inventory || []).filter((item: any) => item.is_vulnerable && !item.is_quantum_safe).length
    const failedJobs = (migrationJobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'failed').length
    const runtimeRiskScore = hasRuntimeEvents
      ? Math.round((runtimeEvents || []).reduce((sum: number, event: any) => sum + Number(event.risk_score || 0), 0) / Math.max(1, runtimeEvents.length))
      : 0
    const quantumExposureScore = hasRuntimeEvents
      ? clampPercent(runtimeRiskScore)
      : clampPercent(openExposureCount * 6 + weakInventoryCount * 3 + failedJobs * 4 + critical * 5)

    const threatDefinitions = [
      { label: 'Anomalous Encryption Spike', test: (text: string) => /spike|burst|anomal|surge|entropy/i.test(text) },
      { label: 'Suspicious Decryption Activity', test: (text: string) => /decrypt|unwrap|unauthorized access|access denied/i.test(text) },
      { label: 'Rogue Certificate Detected', test: (text: string) => /rogue|self-signed|certificate|cert/i.test(text) },
      { label: 'Downgrade Attack Attempt', test: (text: string) => /downgrade|fallback|weak tls|tls 1\.[012]|ssl|rsa-1024/i.test(text) },
      { label: 'Crypto Miner Activity', test: (text: string) => /miner|mining|xmrig|pool|hashrate/i.test(text) },
    ]
    const threatHunting = threatDefinitions.map((definition) => ({
      label: definition.label,
      count: operations.filter((item) => definition.test(`${item.label || ''} ${item.text || ''} ${item.algorithm || ''}`)).length,
    }))

    const operationTypeCounts = [
      { label: 'Encryption', key: 'encryption' },
      { label: 'Decryption', key: 'decryption' },
      { label: 'Key Exchange', key: 'keyExchange' },
      { label: 'Signing', key: 'signing' },
      { label: 'Verification', key: 'verification' },
      { label: 'Other', key: 'other' },
    ].map((row) => ({
      label: row.label,
      count: operations.filter((item) => item.type === row.key || (row.key === 'keyExchange' && item.type === 'keyUsage')).length,
      percent: 0,
    }))
    const operationTypeTotal = Math.max(1, operationTypeCounts.reduce((sum, row) => sum + row.count, 0))
    for (const row of operationTypeCounts) row.percent = percentOf(row.count, operationTypeTotal)

    const operationAlerts = operations
      .filter((item) => ['critical', 'high', 'medium'].includes(item.severity) || /alert|detected|failed|fallback|downgrade|weak/i.test(`${item.label || ''} ${item.text || ''}`))
      .sort((a, b) => b.ms - a.ms)
      .map((item) => ({
        id: item.id,
        title: item.label,
        resource: item.resource,
        severity: item.severity,
        timestamp: item.timestamp,
      }))
    const scannerAlertRows = (scannerAlerts || [])
      .filter((alert: any) => !['resolved', 'suppressed'].includes(String(alert.status || '').toLowerCase()))
      .map((alert: any) => ({
        id: `scanner-alert-${alert.id}`,
        title: alert.title || titleCase(alert.category || 'Scanner Alert'),
        resource: textValue(recordOf(alert.metadata).assetName || recordOf(alert.metadata).resourceName, alert.category || 'runtime'),
        severity: normalizeDriftSeverity(alert.severity),
        timestamp: alert.updated_at || alert.created_at,
      }))
    const alertRows = [...operationAlerts, ...scannerAlertRows]
      .sort((a, b) => dateMs(b.timestamp) - dateMs(a.timestamp))
      .slice(0, 8)

    const pqcSessions = operations.filter((item) => isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.text || ''}`)).length
    const dilithiumValidations = operations.filter((item) => /dilithium|ml-dsa/i.test(`${item.algorithm || ''} ${item.text || ''}`)).length
    const hybridSessions = operations.filter((item) => /hybrid|x25519|ml-kem|kyber/i.test(`${item.algorithm || ''} ${item.text || ''}`)).length
    const pqcCertificates = (certificates || []).filter((cert: any) => cert.is_quantum_safe || isPqcReadyAlgorithm(`${cert.algorithm || ''}`)).length
    const fallbackEvents = operations.filter((item) => /fallback|downgrade|classical|legacy/i.test(`${item.label || ''} ${item.text || ''} ${item.algorithm || ''}`)).length

    const completedJobs = (migrationJobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'completed').length
    const runningJobs = (migrationJobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'running').length
    const pendingJobs = (migrationJobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'pending').length
    const blockedJobs = (migrationJobs || []).filter((job: any) => ['failed', 'paused'].includes(normalizeJobStatus(job.status))).length
    const averageMigrationProgress = (migrationJobs || []).length
      ? clampPercent((migrationJobs || []).reduce((sum: number, job: any) => sum + Number(job.progress || 0), 0) / migrationJobs.length)
      : 0

    const expiringKeys = (generatedKeys || []).filter((key: any) => dateMs(key.expires_at) > now && dateMs(key.expires_at) <= now + 30 * oneDay).length
    const compromisedKeys = (generatedKeys || []).filter((key: any) => String(key.status || '').toLowerCase().includes('revoked') || String(key.status || '').toLowerCase().includes('compromised')).length
    const entropyScores = (generatedKeys || []).map((key: any) => Number(key.quality_score || 0)).filter((value: number) => Number.isFinite(value) && value > 0)
    const entropyQuality = entropyScores.length
      ? Number(((entropyScores.reduce((sum: number, value: number) => sum + value, 0) / entropyScores.length) * 100).toFixed(1))
      : 0

    const currentKeys7d = (generatedKeys || []).filter((key: any) => dateMs(key.created_at) >= current7dStart)
    const previousKeys7d = (generatedKeys || []).filter((key: any) => dateMs(key.created_at) >= previous7dStart && dateMs(key.created_at) < current7dStart)

    const safeCryptoItems = (inventory || []).filter((item: any) => item.is_quantum_safe || isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`)).length
    const readinessPercent = percentOf(safeCryptoItems + pqcCertificates, Math.max(1, (inventory || []).length + (certificates || []).length))
    const hybridAdoption = percentOf(hybridSessions + (migrationJobs || []).filter((job: any) => /hybrid|ml-kem|ml-dsa|kyber|dilithium/i.test(`${job.target_algorithm || ''} ${job.strategy || ''}`)).length, Math.max(1, operations.length + migrationJobs.length))

    const latestScan = (scanSessions || [])[0] || null
    const tlsHandshakeRows = operations
      .filter((item) => /tls|handshake|certificate|cert|gateway|api|web|ssh|ipsec|mtls/i.test(`${item.label || ''} ${item.text || ''} ${item.protocol || ''}`))
      .sort((a, b) => b.ms - a.ms)
      .slice(0, 8)
      .map((item, index) => {
        const asset = item.assetId ? assetMap.get(item.assetId) : null
        const protocol = normalizeProtocol(`${item.protocol || ''} ${item.text || ''} ${item.label || ''}`)
        const pqc = isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.text || ''}`)
        return {
          id: item.id,
          time: item.timestamp,
          source: textValue(asset?.name, item.resource || `runtime-source-${index + 1}`),
          destination: textValue(asset?.environment, textValue(asset?.type, 'runtime-service')),
          tlsVersion: textValue(item.tlsVersion, protocol === 'Other' ? textValue(item.protocol, 'TLS observed') : protocol),
          cipherSuite: textValue(item.cipherSuite || recordOf(item.metadata).cipherSuite || recordOf(item.metadata).cipher_suite, 'Observed cipher'),
          keyExchange: normalizeAlgorithm(item.keyExchangeAlgorithm || item.algorithm || replacementForAlgorithm('', item.text || ''), pqc ? 'ML-KEM-768' : 'Classical'),
          pqc,
          status: ['critical', 'high'].includes(item.severity) ? 'Weak' : 'Success',
        }
      })

    const graphAssets = (assets || []).slice(0, 8).map((asset: any) => ({
      id: asset.id,
      label: asset.name,
      type: asset.type || 'asset',
      criticality: asset.criticality || 'medium',
    }))
    const graphAssetIds = new Set(graphAssets.map((asset: any) => asset.id))
    const graphEdges = (relationships || [])
      .filter((edge: any) => graphAssetIds.has(edge.source_asset_id) && graphAssetIds.has(edge.target_asset_id))
      .slice(0, 12)
      .map((edge: any) => ({
        id: edge.id,
        source: edge.source_asset_id,
        target: edge.target_asset_id,
        label: titleCase(edge.relationship_type || 'depends_on'),
      }))

    const activeAgentWindow = now - 15 * 60 * 1000
    const activeAgents = (scannerAgents || []).filter((agent: any) => String(agent.status || '').toLowerCase() === 'active' && dateMs(agent.last_seen_at) >= activeAgentWindow).length
    const staleAgents = (scannerAgents || []).filter((agent: any) => String(agent.status || '').toLowerCase() !== 'revoked' && (!dateMs(agent.last_seen_at) || dateMs(agent.last_seen_at) < activeAgentWindow)).length
    const runtimeAssets = new Set((runtimeEvents || []).map((event: any) => event.asset_id || event.asset_name || event.host).filter(Boolean))
    const sourceCoverage = Array.from((runtimeEvents || []).reduce((map: Map<string, number>, event: any) => {
      const key = textValue(event.source_type, textValue(event.event_type, 'runtime'))
      map.set(key, (map.get(key) || 0) + 1)
      return map
    }, new Map<string, number>()).entries())
      .map(([label, count]) => ({ label: titleCase(label), count, percent: percentOf(count, Math.max(1, (runtimeEvents || []).length)) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6)
    const enterpriseSignals = {
      shadowCrypto: (runtimeEvents || []).filter((event: any) => event.shadow_crypto).length,
      downgradeAttempts: (runtimeEvents || []).filter((event: any) => event.downgrade_detected).length,
      hndlExposure: (runtimeEvents || []).filter((event: any) => event.hndl_risk).length,
      weakCertificates: (runtimeEvents || []).filter((event: any) => /certificate|cert/i.test(`${event.event_type || ''} ${event.algorithm || ''}`) && (event.is_legacy || severityRank(event.severity || '') >= 3)).length,
      vendorPackageCrypto: (runtimeEvents || []).filter((event: any) => event.package_name || /package|library|vendor|config/i.test(`${event.event_type || ''} ${event.asset_type || ''}`)).length,
    }
    const topRisks = (runtimeEvents || [])
      .filter((event: any) => Number(event.risk_score || 0) > 0 || event.is_legacy || event.downgrade_detected || event.shadow_crypto || event.hndl_risk)
      .sort((a: any, b: any) => Number(b.risk_score || 0) - Number(a.risk_score || 0) || dateMs(b.observed_at) - dateMs(a.observed_at))
      .slice(0, 6)
      .map((event: any) => ({
        id: event.id,
        label: textValue(event.asset_name, textValue(event.host, titleCase(event.event_type || 'Runtime event'))),
        category: event.downgrade_detected ? 'Downgrade' : event.shadow_crypto ? 'Shadow Crypto' : event.hndl_risk ? 'HNDL' : event.is_legacy ? 'Legacy Crypto' : titleCase(event.event_type || 'Runtime'),
        severity: normalizeDriftSeverity(event.severity),
        riskScore: Number(event.risk_score || 0),
        observedAt: event.observed_at || event.created_at,
      }))
    const latestRuntimeEventAt = (runtimeEvents || []).reduce((latest: string | null, event: any) => latestDate(latest, event.observed_at, event.created_at), null)

    return res.json({
      data: {
        generatedAt: new Date().toISOString(),
        latestScanAt: latestScan?.completed_at || latestScan?.updated_at || latestScan?.started_at || null,
        filters: {
          environments: Array.from(new Set((assets || []).map((asset: any) => asset.environment).filter(Boolean))).sort(),
        },
        metrics: {
          cryptoOpsPerSec: ratePerSecond(recentOps.length),
          cryptoOpsDelta: rateDelta(currentOps7d.length, previousOps7d.length),
          encryptionOpsPerSec: ratePerSecond(encryptionCurrent),
          encryptionDelta: rateDelta(countType(currentOps7d, ['encryption']), previousEncryption),
          decryptionOpsPerSec: ratePerSecond(decryptionCurrent),
          decryptionDelta: rateDelta(countType(currentOps7d, ['decryption']), previousDecryption),
          keyUsageEventsPerSec: ratePerSecond(keyUsageCurrent),
          keyUsageDelta: rateDelta(countType(currentOps7d, ['keyUsage', 'keyExchange', 'signing', 'verification']), previousKeyUsage),
          pqcHandshakesPerSec: ratePerSecond(pqcHandshakeCurrent),
          pqcHandshakeDelta: rateDelta(currentOps7d.filter((item) => isPqcReadyAlgorithm(`${item.algorithm || ''} ${item.text || ''}`)).length, previousPqcHandshake),
          quantumExposureScore,
        },
        operationsTrend: buckets,
        cryptoHealth: {
          score: healthScore,
          total: healthItems.length,
          strong,
          warning,
          weak,
          critical,
          rows: [
            { label: 'Strong', count: strong, percent: percentOf(strong, healthTotal) },
            { label: 'Warning', count: warning, percent: percentOf(warning, healthTotal) },
            { label: 'Weak', count: weak, percent: percentOf(weak, healthTotal) },
            { label: 'Critical', count: critical, percent: percentOf(critical, healthTotal) },
          ],
        },
        threatHunting,
        operationsByType: operationTypeCounts,
        algorithmUsage,
        protocolUsage,
        liveAlerts: alertRows,
        pqcVerification: [
          { label: 'ML-KEM (Kyber)', status: pqcSessions > 0 ? 'Active' : 'Not Observed', count: pqcSessions, detail: 'Sessions' },
          { label: 'Dilithium Signatures', status: dilithiumValidations > 0 ? 'Active' : 'Not Observed', count: dilithiumValidations, detail: 'Validations' },
          { label: 'Hybrid TLS (Kyber + X25519)', status: hybridSessions > 0 ? 'Active' : 'Not Observed', count: hybridSessions, detail: 'Sessions' },
          { label: 'PQC Certificates', status: pqcCertificates > 0 ? 'Valid' : 'Not Observed', count: pqcCertificates, detail: 'Certificates' },
          { label: 'Fallback to Classical', status: fallbackEvents > 0 ? 'Detected' : 'Clear', count: fallbackEvents, detail: 'Events' },
        ],
        migrationValidation: {
          progress: averageMigrationProgress,
          migratedAssets: completedJobs,
          inProgress: runningJobs,
          pending: pendingJobs,
          failedBlocked: blockedJobs,
        },
        keyLifecycle: {
          generated7d: currentKeys7d.length,
          generatedDelta: rateDelta(currentKeys7d.length, previousKeys7d.length),
          rotated7d: (generatedKeys || []).filter((key: any) => key.rotated_from && dateMs(key.created_at) >= current7dStart).length,
          expiring30d: expiringKeys,
          compromisedKeys,
          entropyQuality,
        },
        quantumTelemetry: [
          { label: 'Harvest Now, Decrypt Later Risk', value: quantumExposureScore >= 70 ? 'HIGH' : quantumExposureScore >= 40 ? 'MEDIUM' : 'LOW', percent: quantumExposureScore },
          { label: 'Qubit Resilience Score', value: healthScore >= 80 ? 'STRONG' : healthScore >= 55 ? 'MODERATE' : 'LOW', percent: healthScore },
          { label: 'Post-Quantum Readiness', value: `${readinessPercent}%`, percent: readinessPercent },
          { label: 'Hybrid Crypto Adoption', value: `${hybridAdoption}%`, percent: hybridAdoption },
          { label: 'PQC Migration Progress', value: `${averageMigrationProgress}%`, percent: averageMigrationProgress },
        ],
        tlsHandshakes: tlsHandshakeRows,
        dependencyGraph: {
          nodes: graphAssets,
          edges: graphEdges,
        },
        runtimeCoverage: {
          source: hasRuntimeEvents ? 'runtime_crypto_events' : 'fallback_telemetry',
          totalRuntimeEvents: (runtimeEvents || []).length,
          runtimeEvents24h: recentOps.length,
          coveredAssets: runtimeAssets.size,
          activeAgents,
          staleAgents,
          totalAgents: (scannerAgents || []).length,
          sourceCoverage,
        },
        enterpriseSignals,
        eventPipeline: {
          status: hasRuntimeEvents ? 'active' : (scannerAgents || []).length ? 'waiting_for_runtime_events' : 'no_agents',
          latestRuntimeEventAt,
          openScannerAlerts: (scannerAlerts || []).filter((alert: any) => !['resolved', 'suppressed'].includes(String(alert.status || '').toLowerCase())).length,
          table: 'runtime_crypto_events',
        },
        topRisks,
      },
    })
  } catch (err) {
    console.error('Runtime crypto intelligence dashboard error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch runtime cryptographic intelligence telemetry' } })
  }
})

export default router
