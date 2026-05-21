import { Router, Request, Response } from 'express'
import { getToken, getServerUser, getServiceClient, createAuthClient } from '@/lib/supabase-server'

const router = Router()

/**
 * Middleware: require authentication on all dashboard routes.
 */
async function requireAuth(req: Request, res: Response, next: Function) {
  const token = getToken(req)
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

function isMissingRpc(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return text.includes('42883') || text.includes('pgrst202') || text.includes('could not find the function') || text.includes('does not exist')
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
  const [
    totalAssets,
    vulnerableAssetsCount,
    totalCbomItems,
    criticalExposures,
    highExposures,
    unresolvedVulns,
    expiringCerts,
    migrationProgress,
    lastScanAt,
  ] = await Promise.all([
    safeCount(client, 'assets', userId, (q) => q.eq('status', 'active')),
    safeCount(client, 'crypto_exposures', userId, (q) => q.in('severity', ['critical', 'high'])),
    safeCount(client, 'crypto_inventory', userId),
    safeCount(client, 'crypto_exposures', userId, (q) => q.eq('severity', 'critical')),
    safeCount(client, 'crypto_exposures', userId, (q) => q.eq('severity', 'high')),
    safeCount(client, 'vulnerabilities', userId, (q) => q.in('status', ['open', 'in_progress'])),
    safeCount(client, 'certificates', userId, (q) => q.eq('status', 'active').lt('not_after', new Date(Date.now() + 30 * 86400000).toISOString())),
    getMigrationProgress(client, userId),
    safeLatestScanAt(client, userId),
  ])

  const { activeMigrations, failedMigrations, completedMigrations, migrationCompletionRate } = migrationProgress
  const penalty = criticalExposures * 80 + highExposures * 35 + unresolvedVulns * 20 + expiringCerts * 10 + failedMigrations * 25
  const quantumRiskScore = Math.max(0, Math.min(1000, 1000 - penalty))
  const riskBand = quantumRiskScore >= 850
    ? 'Quantum Ready'
    : quantumRiskScore >= 650
      ? 'Moderate'
      : quantumRiskScore >= 400
        ? 'Vulnerable'
        : 'Critical'

  return {
    quantumRiskScore,
    riskBand,
    riskTrend: 0,
    vulnerableAssetsCount,
    newVulnerableAssets: 0,
    totalCbomItems,
    activeMigrations,
    failedMigrations,
    completedMigrations,
    migrationCompletionRate,
    criticalExposures,
    highExposures,
    unresolvedVulns,
    expiringCerts,
    totalAssets,
    lastScanAt,
    monitoringStatus: totalAssets > 0 ? 'active' : 'standby',
  }
}

async function buildEventsFallback(client: any, userId: string, limit: number) {
  try {
    const { data, error } = await client
      .from('security_events')
      .select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, is_read, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(limit)
    if (error) return []

    return (data || []).map((ev: any) => ({
      id: ev.id,
      timestamp: ev.created_at,
      severity: ev.severity,
      eventType: ev.event_type,
      message: ev.message,
      assetId: ev.asset_id,
      resourceName: ev.resource_name,
      resourceType: ev.resource_type,
      metadata: ev.metadata,
      isRead: ev.is_read,
    }))
  } catch {
    return []
  }
}

async function buildExposureMapFallback(client: any, userId: string) {
  try {
    const [{ data: assets }, { data: relationships }] = await Promise.all([
      client
        .from('assets')
        .select('id, name, type, environment, criticality, status')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(100),
      client
        .from('asset_relationships')
        .select('source_asset_id, target_asset_id, relationship_type')
        .eq('user_id', userId)
        .limit(200),
    ])

    const nodes = await Promise.all((assets || []).map(async (asset: any) => {
      const riskScore = await safeCount(client, 'crypto_exposures', userId, (q) => q.eq('asset_id', asset.id).eq('severity', 'critical'))
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
    }))

    const edges = (relationships || []).map((edge: any) => ({
      source: edge.source_asset_id,
      target: edge.target_asset_id,
      type: edge.relationship_type,
    }))

    return { nodes, edges }
  } catch {
    return { nodes: [], edges: [] }
  }
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

    // Use RPC function for atomic summary calculation
    const { data: summaryData, error: rpcError } = await client.rpc('get_dashboard_summary', {
      p_user_id: user.id
    })

    if (rpcError) {
      if (!isMissingRpc(rpcError)) {
        console.warn('Dashboard summary RPC error, using SQL fallback:', rpcError)
      }
      const summary = await buildDashboardSummaryFallback(client, user.id)
      return res.json({ data: summary })
    }

    // Fetch previous scan for trend comparison
    const { data: previousScans } = await client
      .from('pqc_scan_sessions')
      .select('completed_at, findings_count')
      .eq('user_id', user.id)
      .eq('status', 'completed')
      .order('completed_at', { ascending: false })
      .limit(2)

    let riskTrend = 0
    if (previousScans && previousScans.length >= 2) {
      const current = previousScans[0].findings_count || 0
      const previous = previousScans[1].findings_count || 0
      riskTrend = previous - current // positive = fewer findings = improving
    }

    // Count new vulnerable assets since last scan
    let newVulnerableAssets = 0
    if (previousScans && previousScans.length > 0) {
      const lastScanDate = previousScans[0].completed_at
      const { count } = await client
        .from('crypto_exposures')
        .select('*', { count: 'exact', head: true })
        .eq('user_id', user.id)
        .gt('created_at', lastScanDate)
      newVulnerableAssets = count || 0
    }

    const summary = summaryData || {}
    const migrationProgress = await getMigrationProgress(client, user.id)

    return res.json({
      data: {
        quantumRiskScore: summary.quantumRiskScore || 1000,
        riskBand: summary.riskBand || 'Quantum Ready',
        riskTrend,
        vulnerableAssetsCount: summary.vulnerableAssetsCount || 0,
        newVulnerableAssets,
        totalCbomItems: summary.totalCbomItems || 0,
        activeMigrations: migrationProgress.activeMigrations,
        failedMigrations: migrationProgress.failedMigrations,
        completedMigrations: migrationProgress.completedMigrations,
        migrationCompletionRate: migrationProgress.migrationCompletionRate,
        criticalExposures: summary.criticalExposures || 0,
        highExposures: summary.highExposures || 0,
        unresolvedVulns: summary.unresolvedVulns || 0,
        expiringCerts: summary.expiringCerts || 0,
        totalAssets: summary.totalAssets || 0,
        lastScanAt: summary.lastScanAt || null,
        monitoringStatus: summary.monitoringStatus || 'active',
      }
    })
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

    const { data: eventsData, error: rpcError } = await client.rpc('get_recent_security_events', {
      p_user_id: user.id,
      p_limit: limit
    })

    if (rpcError) {
      if (!isMissingRpc(rpcError)) {
        console.warn('Security events RPC error, using SQL fallback:', rpcError)
      }
      const events = await buildEventsFallback(client, user.id, limit)
      return res.json({ data: { events } })
    }

    const events = (eventsData || []).map((ev: any) => ({
      id: ev.id,
      timestamp: ev.createdAt,
      severity: ev.severity,
      eventType: ev.eventType,
      message: ev.message,
      assetId: ev.assetId,
      resourceName: ev.resourceName,
      resourceType: ev.resourceType,
      metadata: ev.metadata,
      isRead: ev.isRead,
    }))

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

    const { data: mapData, error: rpcError } = await client.rpc('get_exposure_map', {
      p_user_id: user.id
    })

    if (rpcError) {
      if (!isMissingRpc(rpcError)) {
        console.warn('Exposure map RPC error, using SQL fallback:', rpcError)
      }
      const mapData = await buildExposureMapFallback(client, user.id)
      return res.json({ data: mapData })
    }

    // Enrich nodes with latest crypto inventory and vulnerabilities
    const nodes = (mapData?.nodes || []).map((node: any) => ({
      ...node,
      color: getRiskColor(node.riskScore, node.status),
    }))

    return res.json({
      data: {
        nodes,
        edges: mapData?.edges || []
      }
    })
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

function isLegacyAlgorithm(value: string) {
  return /rsa|rs256|ecdsa|ecdh|dh-|dsa|sha-1|sha1|md5|des|3des|rc4|aes-128-cbc|tls\s*1\.[012]|ssl/i.test(value)
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
      return {
        id: input.sourceId,
        sourceId: input.sourceId,
        title: vulnerabilityTitle(input.title || input.type || input.description),
        description: input.description || 'Cryptographic weakness detected in authenticated telemetry.',
        asset: textValue(asset.name, textValue(input.metadata?.resourceName || input.metadata?.resource_name, 'Unassigned asset')),
        assetType: assetTypeLabel(textValue(asset.type, textValue(input.metadata?.assetType || input.metadata?.asset_type, input.source || 'Other'))),
        environment: textValue(asset.environment, textValue(asset.region, textValue(input.metadata?.environment, 'unassigned'))),
        severity,
        exposureLevel: severity === 'critical' || severity === 'high' ? 'Moderate' : 'Low',
        type: input.type || vulnerabilityType(text),
        detectedAt: input.detectedAt || null,
        status,
        algorithm: input.algorithm || '',
        remediation: textValue(input.metadata?.remediation || input.metadata?.pqcReplacement || input.metadata?.pqc_replacement, expectedForDrift(text, input.algorithm || '')),
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

    const remediatedJobs = (migrationJobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'completed')
    const remediatedRows = rows.filter((row) => row.status === 'Remediated').length
    const remediated = remediatedRows + remediatedJobs.length
    const openRows = rows.filter((row) => row.status !== 'Remediated')
    const criticalExposure = openRows.filter((row) => row.severity === 'critical').length
    const legacyAlgorithms = (inventory || []).filter((item: any) => item.is_vulnerable && !item.is_quantum_safe && isLegacyAlgorithm(`${item.algorithm || ''} ${item.protocol || ''}`)).length

    const now = Date.now()
    const current7d = rows.filter((row) => dateMs(row.detectedAt) >= now - 7 * 86400000)
    const previous7d = rows.filter((row) => dateMs(row.detectedAt) < now - 7 * 86400000 && dateMs(row.detectedAt) >= now - 14 * 86400000)
    const previousCritical = previous7d.filter((row) => row.severity === 'critical' && row.status !== 'Remediated').length
    const previousLegacy = previous7d.filter((row) => isLegacyAlgorithm(row.algorithm)).length
    const previousRemediated = (migrationJobs || []).filter((job: any) => normalizeJobStatus(job.status) === 'completed' && dateMs(job.completed_at || job.updated_at) < now - 7 * 86400000 && dateMs(job.completed_at || job.updated_at) >= now - 14 * 86400000).length

    const severityBreakdown = ['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
      const count = rows.filter((row) => row.severity === severity || (severity === 'info' && !['critical', 'high', 'medium', 'low'].includes(row.severity))).length
      return { severity, count, percent: percentOf(count, Math.max(1, rows.length)) }
    })

    const assetTypeBreakdown = Array.from(rows.reduce((map, row) => {
      map.set(row.assetType, (map.get(row.assetType) || 0) + 1)
      return map
    }, new Map<string, number>()).entries())
      .map(([label, count]) => ({ label, count, percent: percentOf(count, Math.max(1, rows.length)) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6)

    const trend = Array.from({ length: 7 }, (_, index) => {
      const start = startOfDayMs(6 - index)
      const end = start + 86400000
      const bucket = rows.filter((row) => {
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
    const topAssetMap = rows.reduce((map: Map<string, VulnerabilityTopAsset>, row) => {
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
          totalVulnerabilities: rows.length,
          current7d: current7d.length,
        },
        filters: {
          environments: Array.from(new Set(rows.map((row) => row.environment).filter(Boolean))).sort(),
          assetTypes: Array.from(new Set(rows.map((row) => row.assetType).filter(Boolean))).sort(),
          vulnerabilityTypes: Array.from(new Set(rows.map((row) => row.type).filter(Boolean))).sort(),
        },
        vulnerabilities: rows.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || dateMs(b.detectedAt) - dateMs(a.detectedAt)),
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
