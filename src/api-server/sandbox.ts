import { Router, type NextFunction, type Request, type Response } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'

type AuthenticatedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

const router = Router()

function tokenFromRequest(req: Request): string | null {
  const header = getToken(req)
  if (header) return header
  const q = req.query.token
  return typeof q === 'string' && q.length > 0 ? q : null
}

async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = tokenFromRequest(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  req.user = user
  req.token = token
  next()
}

function clientFor(req: AuthenticatedRequest) {
  return req.token ? createAuthClient(req.token) : null
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
  if (res.writableEnded) return
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
}

function isMissingTable(error: any) {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return text.includes('42p01') || text.includes('pgrst205') || text.includes('does not exist') || text.includes('could not find the table')
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return value as Record<string, unknown>
}

function pickStr(rec: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const v = rec[key]
    if (typeof v === 'string' && v.trim()) return v.trim()
  }
  return ''
}

function normalizeStatus(s: unknown): string {
  const v = String(s || '').toLowerCase().replace(/\s+/g, '_')
  if (['completed', 'complete', 'done', 'success'].includes(v)) return 'completed'
  if (['failed', 'error', 'errored'].includes(v)) return 'failed'
  if (['running', 'in_progress', 'executing', 'migrating'].includes(v)) return 'running'
  if (['paused', 'cancelled', 'canceled', 'rollback_requested', 'rolled_back'].includes(v)) return 'paused'
  return 'queued'
}

function clamp(v: number, lo = 0, hi = 100) {
  return Math.max(lo, Math.min(hi, Math.round(v)))
}

function severityRank(s: string) {
  const v = s.toLowerCase()
  if (v === 'critical') return 4
  if (v === 'high') return 3
  if (v === 'medium' || v === 'moderate' || v === 'warning') return 2
  return 1
}

function pqcAlgoRec(from: string, context = '') {
  const v = `${from} ${context}`.toLowerCase()
  if (v.includes('rsa') || v.includes('tls') || v.includes('key exchange')) return 'ML-KEM-768'
  if (v.includes('ecdsa') || v.includes('dsa') || v.includes('sign')) return 'ML-DSA-65'
  if (v.includes('aes-128') || v.includes('3des') || v.includes('des')) return 'AES-256-GCM'
  if (v.includes('dh') || v.includes('ecdh') || v.includes('x25519')) return 'X25519 + ML-KEM hybrid'
  if (v.includes('sha1') || v.includes('md5')) return 'SHA3-256'
  return 'ML-KEM-768 (hybrid)'
}

function quantumRisk(algo: string): 'critical' | 'high' | 'medium' | 'low' {
  const v = algo.toLowerCase()
  if (v.includes('rsa') || v.includes('ecdsa') || v.includes('dh ')) return 'critical'
  if (v.includes('sha1') || v.includes('md5') || v.includes('3des')) return 'high'
  if (v.includes('aes-128') || v.includes('tls 1.2')) return 'medium'
  return 'low'
}

async function safeRows(client: any, table: string, build: (q: any) => any) {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      if (!isMissingTable(error)) console.warn(`[sandbox] ${table}:`, error.message)
      return []
    }
    return data || []
  } catch {
    return []
  }
}

async function safeCount(client: any, table: string, userId: string, apply?: (q: any) => any): Promise<number> {
  try {
    let q = client.from(table).select('id', { count: 'exact', head: true }).eq('user_id', userId)
    if (apply) q = apply(q)
    const { count, error } = await q
    if (error) return 0
    return count || 0
  } catch { return 0 }
}

async function buildSandboxPayload(client: any, userId: string) {
  const [jobs, assets, inventory, exposures, events, scanSessions, certificates, vulns] = await Promise.all([
    safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(200)),
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(300)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe, discovered_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(500)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(500)),
    safeRows(client, 'migration_events', (q) => q.select('id, migration_id, event_type, message, severity, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(300)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, progress, total_assets, scanned_assets, findings_count, completed_at, started_at, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(30)),
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, algorithm, key_size, not_after, is_quantum_safe, is_expiring_soon, status').eq('user_id', userId).limit(200)),
    safeRows(client, 'vulnerabilities', (q) => q.select('id, asset_id, title, severity, status').eq('user_id', userId).not('status', 'eq', 'resolved').limit(200)),
  ])

  const assetMap = new Map<string, any>((assets || []).map((a: any) => [a.id, a]))
  const inventoryByAsset = new Map<string, any[]>()
  for (const item of inventory || []) {
    if (!item.asset_id) continue
    const list = inventoryByAsset.get(item.asset_id) || []
    list.push(item)
    inventoryByAsset.set(item.asset_id, list)
  }
  const exposuresByAsset = new Map<string, any[]>()
  for (const exp of exposures || []) {
    if (!exp.asset_id) continue
    const list = exposuresByAsset.get(exp.asset_id) || []
    list.push(exp)
    exposuresByAsset.set(exp.asset_id, list)
  }
  const eventsByJob = new Map<string, any[]>()
  for (const ev of events || []) {
    if (!ev.migration_id) continue
    const list = eventsByJob.get(ev.migration_id) || []
    list.push(ev)
    eventsByJob.set(ev.migration_id, list)
  }

  // ── Active Simulations ──────────────────────────────────────────────────────
  const simulations = (jobs || []).map((job: any) => {
    const asset = assetMap.get(job.asset_id) || {}
    const meta = asRecord(job.metadata)
    const invItems = inventoryByAsset.get(job.asset_id) || []
    const expItems = exposuresByAsset.get(job.asset_id) || []
    const jobEvents = eventsByJob.get(job.id) || []
    const status = normalizeStatus(job.status)
    const progress = status === 'completed' ? 100 : clamp(Number(job.progress || 0))
    const fromAlgo = pickStr(meta, ['sourceAlgorithm', 'source_algorithm', 'fromAlgorithm', 'from_algorithm', 'fromAlgo'])
      || (invItems[0]?.algorithm || '')
      || (expItems[0]?.detected_value || '')
      || 'Classical'
    const toAlgo = job.target_algorithm || pickStr(meta, ['targetAlgorithm', 'target_algorithm', 'toAlgo']) || pqcAlgoRec(fromAlgo, job.job_type || '')
    const riskLevel = quantumRisk(fromAlgo)
    const phase = status === 'completed' ? 'finalization'
      : status === 'failed' ? 'assessment'
        : status === 'running' ? (progress < 25 ? 'preparation' : progress < 50 ? 'assessment' : progress < 75 ? 'execution' : 'verification')
          : 'preparation'

    return {
      id: job.id,
      name: job.name || `Migration: ${asset.name || 'Asset'}`,
      assetId: job.asset_id || null,
      assetName: asset.name || 'Unknown Asset',
      assetType: asset.type || pickStr(meta, ['assetType', 'asset_type']) || 'service',
      environment: asset.environment || pickStr(meta, ['environment']) || 'unknown',
      owner: asset.service_owner || pickStr(meta, ['owner', 'serviceOwner']) || 'Unassigned',
      criticality: (asset.criticality || pickStr(meta, ['criticality']) || 'medium').toLowerCase(),
      fromAlgo,
      toAlgo,
      migrationType: pickStr(meta, ['migrationType', 'migration_type']) || job.job_type || 'PQC Migration',
      status,
      progress,
      riskLevel,
      phase,
      startedAt: job.started_at || null,
      completedAt: job.completed_at || null,
      updatedAt: job.updated_at || job.created_at,
      createdAt: job.created_at,
      eventCount: jobEvents.length,
      recentEvents: jobEvents.slice(-5).map((ev: any) => ({
        id: ev.id,
        type: ev.event_type || 'event',
        message: ev.message || '',
        severity: ev.severity || 'info',
        timestamp: ev.created_at,
      })),
      metadata: meta,
    }
  })

  // ── Risk Analysis ───────────────────────────────────────────────────────────
  const criticalExposures = (exposures || []).filter((e: any) => e.severity === 'critical').length
  const highExposures = (exposures || []).filter((e: any) => e.severity === 'high').length
  const vulnerableInventory = (inventory || []).filter((i: any) => i.is_vulnerable || i.is_quantum_safe === false).length
  const totalInventory = (inventory || []).length
  const expiringCerts = (certificates || []).filter((c: any) => c.is_expiring_soon || !c.is_quantum_safe).length
  const openVulns = (vulns || []).length
  const failedJobs = simulations.filter((s) => s.status === 'failed').length
  const completedJobs = simulations.filter((s) => s.status === 'completed').length
  const runningJobs = simulations.filter((s) => s.status === 'running').length
  const totalJobs = simulations.length

  const riskScore = Math.max(0, Math.min(100, Math.round(
    100 - (criticalExposures * 15 + highExposures * 8 + expiringCerts * 5 + openVulns * 3 + failedJobs * 10)
  )))
  const pqcReadiness = totalInventory > 0
    ? Math.round(((totalInventory - vulnerableInventory) / totalInventory) * 100)
    : totalJobs > 0 ? Math.round((completedJobs / totalJobs) * 100) : 0

  const riskFactors = [
    { label: 'Critical Crypto Exposures', count: criticalExposures, severity: 'critical' as const, impact: 'high' as const },
    { label: 'High-Risk Exposures', count: highExposures, severity: 'high' as const, impact: 'high' as const },
    { label: 'Vulnerable Inventory Items', count: vulnerableInventory, severity: 'high' as const, impact: 'medium' as const },
    { label: 'Expiring/Non-PQC Certs', count: expiringCerts, severity: 'medium' as const, impact: 'medium' as const },
    { label: 'Open Vulnerabilities', count: openVulns, severity: 'medium' as const, impact: 'medium' as const },
    { label: 'Failed Migration Jobs', count: failedJobs, severity: 'high' as const, impact: 'high' as const },
  ].filter((f) => f.count > 0)

  // ── AI Recommendations ──────────────────────────────────────────────────────
  const recommendations: any[] = []

  if (criticalExposures > 0) {
    const critExps = (exposures || []).filter((e: any) => e.severity === 'critical').slice(0, 3)
    for (const exp of critExps) {
      const asset = assetMap.get(exp.asset_id) || {}
      const from = exp.detected_value || exp.exposure_type || 'legacy algorithm'
      recommendations.push({
        id: `rec-critical-${exp.id}`,
        priority: 1,
        type: 'algorithm_migration',
        title: `Migrate ${from.toUpperCase()} on ${asset.name || 'asset'} immediately`,
        description: `Critical quantum vulnerability detected. This asset is at immediate risk from "Harvest Now, Decrypt Later" attacks.`,
        algorithm: pqcAlgoRec(from),
        asset: asset.name || 'Unknown',
        effort: 'high',
        timeEstimate: '2-4 weeks',
        compliance: ['NIST SP 800-208', 'CNSA 2.0'],
      })
    }
  }

  if (failedJobs > 0) {
    const failed = simulations.filter((s) => s.status === 'failed').slice(0, 3)
    for (const job of failed) {
      recommendations.push({
        id: `rec-failed-${job.id}`,
        priority: 2,
        type: 'remediation',
        title: `Retry failed migration: ${job.name}`,
        description: `This migration job failed. Review execution logs, validate dependencies, and retry with corrected configuration.`,
        algorithm: job.toAlgo,
        asset: job.assetName,
        effort: 'medium',
        timeEstimate: '1-3 days',
        compliance: ['NIST SP 800-57'],
      })
    }
  }

  if (expiringCerts > 0) {
    recommendations.push({
      id: 'rec-certs',
      priority: 2,
      type: 'certificate_rotation',
      title: `Rotate ${expiringCerts} non-PQC or expiring certificates`,
      description: 'Certificates using classical algorithms or nearing expiry must be replaced with PQC-compliant alternatives.',
      algorithm: 'ML-DSA-65',
      asset: 'Certificate Infrastructure',
      effort: 'medium',
      timeEstimate: '1-2 weeks',
      compliance: ['NIST SP 800-57', 'RFC 9162'],
    })
  }

  if (vulnerableInventory > 0 && recommendations.length < 5) {
    recommendations.push({
      id: 'rec-inventory',
      priority: 3,
      type: 'hybrid_deployment',
      title: `Deploy hybrid cryptography for ${vulnerableInventory} vulnerable assets`,
      description: 'Transition vulnerable crypto assets to hybrid classical+PQC mode to maintain backward compatibility while gaining quantum resistance.',
      algorithm: 'X25519 + ML-KEM-768',
      asset: 'Crypto Inventory',
      effort: 'medium',
      timeEstimate: '2-6 weeks',
      compliance: ['NIST SP 800-208', 'NIST SP 800-131A'],
    })
  }

  if (recommendations.length === 0) {
    recommendations.push({
      id: 'rec-baseline',
      priority: 3,
      type: 'assessment',
      title: 'Run comprehensive PQC discovery scan',
      description: 'Establish your cryptographic baseline by scanning all assets to identify quantum-vulnerable algorithms before planning migrations.',
      algorithm: 'N/A',
      asset: 'All Assets',
      effort: 'low',
      timeEstimate: '1-2 hours',
      compliance: ['NIST SP 800-208'],
    })
  }

  // ── Compliance Validation ───────────────────────────────────────────────────
  const nistReady = pqcReadiness >= 80 && criticalExposures === 0
  const agileReady = totalInventory > 0
  const auditAvailable = (events || []).length > 0
  const complianceItems = [
    { framework: 'NIST SP 800-208', control: 'PQC Algorithm Adoption', status: nistReady ? 'compliant' : criticalExposures > 0 ? 'non-compliant' : 'partial', score: pqcReadiness },
    { framework: 'NIST SP 800-57 Rev.5', control: 'Key Management Practices', status: expiringCerts === 0 && failedJobs === 0 ? 'compliant' : 'partial', score: Math.max(0, 100 - expiringCerts * 15 - failedJobs * 20) },
    { framework: 'CNSA 2.0', control: 'NSS Algorithm Suite', status: criticalExposures === 0 && highExposures < 3 ? 'compliant' : 'non-compliant', score: Math.max(0, 100 - criticalExposures * 20 - highExposures * 10) },
    { framework: 'Crypto Agility', control: 'Algorithm Replaceability', status: agileReady ? 'compliant' : 'pending', score: agileReady ? 85 : 0 },
    { framework: 'Audit Trail', control: 'Migration Evidence Collection', status: auditAvailable ? 'compliant' : 'pending', score: auditAvailable ? 100 : 0 },
    { framework: 'HNDL Posture', control: 'Harvest-Now-Decrypt-Later', status: criticalExposures === 0 ? 'compliant' : 'critical', score: Math.max(0, 100 - criticalExposures * 25) },
  ]
  const complianceScore = Math.round(complianceItems.reduce((sum, c) => sum + c.score, 0) / complianceItems.length)

  // ── Workflow Phases ─────────────────────────────────────────────────────────
  const workflowPhases = [
    { id: 'preparation', label: 'Preparation', description: 'Asset discovery, CBOM validation, dependency mapping', complete: totalJobs > 0, active: runningJobs === 0 && totalJobs === 0, progress: totalJobs > 0 ? 100 : 0 },
    { id: 'assessment', label: 'Risk Assessment', description: 'Quantum vulnerability scoring, HNDL exposure analysis', complete: (exposures || []).length > 0, active: (exposures || []).length > 0 && completedJobs === 0, progress: (exposures || []).length > 0 ? 100 : 0 },
    { id: 'planning', label: 'Migration Planning', description: 'Algorithm selection, hybrid deployment planning', complete: totalJobs > 0, active: totalJobs > 0 && runningJobs === 0, progress: totalJobs > 0 ? 100 : 0 },
    { id: 'execution', label: 'Sandbox Execution', description: 'Controlled simulation, automated validation', complete: completedJobs > 0, active: runningJobs > 0, progress: totalJobs > 0 ? Math.round((runningJobs + completedJobs) / totalJobs * 100) : 0 },
    { id: 'verification', label: 'Verification', description: 'Integrity check, compatibility testing, benchmarks', complete: completedJobs > 0 && criticalExposures === 0, active: completedJobs > 0, progress: completedJobs > 0 ? pqcReadiness : 0 },
    { id: 'finalization', label: 'Finalization', description: 'Readiness scoring, compliance validation, report export', complete: pqcReadiness >= 90, active: pqcReadiness >= 70, progress: pqcReadiness },
  ]

  // ── PQC Stack Status ────────────────────────────────────────────────────────
  const pqcStack = [
    { name: 'ML-KEM-768 (Kyber)', standard: 'NIST FIPS 203', status: 'available', usage: (inventory || []).filter((i: any) => /ml-kem|kyber/i.test(i.algorithm || '')).length },
    { name: 'ML-DSA-65 (Dilithium)', standard: 'NIST FIPS 204', status: 'available', usage: (inventory || []).filter((i: any) => /ml-dsa|dilithium/i.test(i.algorithm || '')).length },
    { name: 'SLH-DSA (SPHINCS+)', standard: 'NIST FIPS 205', status: 'available', usage: 0 },
    { name: 'AES-256-GCM', standard: 'NIST FIPS 197', status: 'active', usage: (inventory || []).filter((i: any) => /aes-256/i.test(i.algorithm || '')).length },
    { name: 'SHA3-256 / SHA3-512', standard: 'NIST FIPS 202', status: 'active', usage: (inventory || []).filter((i: any) => /sha3/i.test(i.algorithm || '')).length },
    { name: 'X25519 Hybrid KEX', standard: 'IETF RFC 9370', status: 'available', usage: 0 },
  ]

  // ── Summary Metrics ─────────────────────────────────────────────────────────
  const lastScan = (scanSessions || []).find((s: any) => s.status === 'completed')
  const summary = {
    totalSimulations: simulations.length,
    running: runningJobs,
    completed: completedJobs,
    failed: failedJobs,
    queued: simulations.filter((s) => s.status === 'queued').length,
    paused: simulations.filter((s) => s.status === 'paused').length,
    totalAssets: (assets || []).length,
    vulnerableAssets: new Set((exposures || []).map((e: any) => e.asset_id).filter(Boolean)).size,
    criticalExposures,
    highExposures,
    openVulnerabilities: openVulns,
    pqcReadiness,
    riskScore,
    complianceScore,
    expiringCerts,
    lastScanAt: lastScan?.completed_at || lastScan?.created_at || null,
    completionRate: totalJobs > 0 ? Math.round((completedJobs / totalJobs) * 100) : 0,
  }

  return {
    generatedAt: new Date().toISOString(),
    summary,
    simulations,
    riskFactors,
    recommendations: recommendations.slice(0, 8),
    complianceItems,
    complianceScore,
    workflowPhases,
    pqcStack,
    recentLogs: (events || []).slice(0, 50).map((ev: any) => ({
      id: ev.id,
      jobId: ev.migration_id,
      type: ev.event_type || 'event',
      message: ev.message || '',
      severity: ev.severity || 'info',
      timestamp: ev.created_at,
    })),
  }
}

// ── GET /api/v1/sandbox/snapshot ──────────────────────────────────────────────
router.get('/snapshot', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })
  try {
    const payload = await buildSandboxPayload(client, req.user!.id)
    return res.json({ data: payload })
  } catch (err) {
    console.error('[sandbox] snapshot error:', err)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to build sandbox snapshot' } })
  }
})

// ── GET /api/v1/sandbox/stream (SSE) ─────────────────────────────────────────
router.get('/stream', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  sseHeaders(res)
  writeSse(res, 'connected', { timestamp: new Date().toISOString(), userId: req.user!.id })

  const emit = async () => {
    try {
      const payload = await buildSandboxPayload(client, req.user!.id)
      writeSse(res, 'sandbox-update', payload)
    } catch { /* ignore */ }
  }

  await emit()
  const heartbeat = setInterval(() => writeSse(res, 'heartbeat', { ts: Date.now() }), 20000)
  const poll = setInterval(emit, 8000)

  req.on('close', () => {
    clearInterval(heartbeat)
    clearInterval(poll)
    res.end()
  })
})

// ── POST /api/v1/sandbox/jobs/:id/action ─────────────────────────────────────
router.post('/jobs/:id/action', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const action = String(req.body?.action || '').toLowerCase()
  const validActions = ['pause', 'resume', 'retry', 'rollback', 'stop', 'snapshot']
  if (!validActions.includes(action)) {
    return res.status(400).json({ error: { code: 'INVALID_ACTION', message: `Invalid action. Must be one of: ${validActions.join(', ')}` } })
  }

  const { data: job, error: readError } = await client
    .from('migration_jobs')
    .select('id, name, status, metadata, progress')
    .eq('id', req.params.id)
    .eq('user_id', req.user!.id)
    .single()

  if (readError || !job) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Simulation job not found' } })
  }

  const now = new Date().toISOString()
  const meta = asRecord(job.metadata)
  const nextMeta = { ...meta, lastOperatorAction: action, lastOperatorActionAt: now }

  let update: any = { updated_at: now, metadata: nextMeta }
  if (action === 'pause') update = { ...update, status: 'paused' }
  else if (action === 'resume') update = { ...update, status: 'running', started_at: now }
  else if (action === 'retry') update = { ...update, status: 'running', progress: 0, started_at: now }
  else if (action === 'rollback') update = { ...update, status: 'rollback_requested' }
  else if (action === 'stop') update = { ...update, status: 'paused' }
  else if (action === 'snapshot') {
    // Record snapshot in metadata
    const snapshots = (meta.snapshots as any[]) || []
    snapshots.push({ at: now, progress: job.progress, status: job.status })
    update = { ...update, metadata: { ...nextMeta, snapshots } }
  }

  const { error: updateError } = await client
    .from('migration_jobs')
    .update(update)
    .eq('id', job.id)
    .eq('user_id', req.user!.id)

  if (updateError) {
    return res.status(500).json({ error: { code: 'UPDATE_FAILED', message: 'Failed to execute action' } })
  }

  // Log the action as a migration event
  await client.from('migration_events').insert({
    user_id: req.user!.id,
    migration_id: job.id,
    event_type: `operator-${action}`,
    severity: action === 'rollback' || action === 'stop' ? 'warning' : 'info',
    message: `Operator ${action} action on sandbox job "${job.name || job.id}"`,
    metadata: { action, operator: req.user!.email },
    created_at: now,
  }).catch(() => undefined)

  return res.json({ data: { success: true, action, jobId: job.id } })
})

// ── POST /api/v1/sandbox/simulate ────────────────────────────────────────────
router.post('/simulate', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const { assetId, fromAlgo, toAlgo, migrationType, dryRun, environment } = req.body || {}
  if (!fromAlgo && !assetId) {
    return res.status(400).json({ error: { code: 'MISSING_PARAMS', message: 'Either assetId or fromAlgo is required' } })
  }

  const now = new Date().toISOString()
  const targetAlgo = toAlgo || pqcAlgoRec(fromAlgo || 'rsa', migrationType || '')
  const jobName = dryRun
    ? `[DRY RUN] ${fromAlgo || 'Crypto'} → ${targetAlgo}`
    : `Sandbox: ${fromAlgo || 'Crypto'} → ${targetAlgo}`

  const { data: newJob, error: insertError } = await client
    .from('migration_jobs')
    .insert({
      user_id: req.user!.id,
      asset_id: assetId || null,
      name: jobName,
      job_type: migrationType || 'pqc_migration',
      status: 'running',
      target_algorithm: targetAlgo,
      strategy: `${fromAlgo || 'Classical'} → ${targetAlgo}`,
      progress: 0,
      started_at: now,
      created_at: now,
      updated_at: now,
      metadata: {
        sourceAlgorithm: fromAlgo || 'Classical',
        targetAlgorithm: targetAlgo,
        environment: environment || 'sandbox',
        dryRun: !!dryRun,
        sandboxMode: true,
        initiatedBy: req.user!.email,
        initiatedAt: now,
      },
    })
    .select()
    .single()

  if (insertError || !newJob) {
    console.error('[sandbox] simulate insert error:', insertError)
    return res.status(500).json({ error: { code: 'INSERT_FAILED', message: 'Failed to create simulation job' } })
  }

  // Emit initial event
  await client.from('migration_events').insert({
    user_id: req.user!.id,
    migration_id: newJob.id,
    event_type: 'simulation-started',
    severity: 'info',
    message: `Sandbox simulation started: ${fromAlgo || 'Classical'} → ${targetAlgo}${dryRun ? ' (Dry Run)' : ''}`,
    metadata: { sourceAlgorithm: fromAlgo, targetAlgorithm: targetAlgo, dryRun: !!dryRun },
    created_at: now,
  }).catch(() => undefined)

  return res.json({ data: { success: true, jobId: newJob.id, jobName, status: 'running' } })
})

// ── POST /api/v1/sandbox/bulk-action ─────────────────────────────────────────
router.post('/bulk-action', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const action = String(req.body?.action || '').toLowerCase()
  const scopes: Record<string, string[]> = {
    pause: ['running', 'in_progress'],
    resume: ['paused', 'queued'],
    retry: ['failed'],
    rollback: ['running', 'paused', 'completed'],
  }

  if (!scopes[action]) {
    return res.status(400).json({ error: { code: 'INVALID_ACTION', message: 'Unsupported bulk action' } })
  }

  const { data: jobs, error: readError } = await client
    .from('migration_jobs')
    .select('id, name, status, metadata')
    .eq('user_id', req.user!.id)
    .in('status', scopes[action])

  if (readError) {
    return res.status(500).json({ error: { code: 'READ_FAILED', message: 'Failed to read jobs' } })
  }

  const now = new Date().toISOString()
  let affected = 0
  for (const job of jobs || []) {
    const meta = asRecord(job.metadata)
    const nextMeta = { ...meta, lastOperatorAction: action, lastOperatorActionAt: now }
    let update: any = { updated_at: now, metadata: nextMeta }
    if (action === 'pause') update.status = 'paused'
    else if (action === 'resume') { update.status = 'running'; update.started_at = now }
    else if (action === 'retry') { update.status = 'running'; update.progress = 0; update.started_at = now }
    else if (action === 'rollback') update.status = 'rollback_requested'

    const { error } = await client
      .from('migration_jobs')
      .update(update)
      .eq('id', job.id)
      .eq('user_id', req.user!.id)

    if (!error) affected++
  }

  return res.json({ data: { success: true, action, affected } })
})

// ── GET /api/v1/sandbox/risk ──────────────────────────────────────────────────
router.get('/risk', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  const [critCount, highCount, totalAssets, totalJobs, failedJobs, completedJobs, vulnCount, expiringCertCount] = await Promise.all([
    safeCount(client, 'crypto_exposures', req.user!.id, (q) => q.eq('severity', 'critical')),
    safeCount(client, 'crypto_exposures', req.user!.id, (q) => q.eq('severity', 'high')),
    safeCount(client, 'assets', req.user!.id),
    safeCount(client, 'migration_jobs', req.user!.id),
    safeCount(client, 'migration_jobs', req.user!.id, (q) => q.eq('status', 'failed')),
    safeCount(client, 'migration_jobs', req.user!.id, (q) => q.eq('status', 'completed')),
    safeCount(client, 'vulnerabilities', req.user!.id, (q) => q.neq('status', 'resolved')),
    safeCount(client, 'certificates', req.user!.id, (q) => q.eq('is_expiring_soon', true)),
  ])

  const riskScore = Math.max(0, Math.min(100, 100 - critCount * 15 - highCount * 8 - expiringCertCount * 5 - vulnCount * 2 - failedJobs * 10))
  const pqcReadiness = totalJobs > 0 ? Math.round((completedJobs / totalJobs) * 100) : 0
  const migrationHealth = totalJobs > 0
    ? (failedJobs / totalJobs > 0.3 ? 'critical' : failedJobs > 0 ? 'degraded' : 'healthy')
    : 'no-data'

  return res.json({
    data: {
      riskScore,
      pqcReadiness,
      migrationHealth,
      criticalExposures: critCount,
      highExposures: highCount,
      openVulnerabilities: vulnCount,
      expiringCertificates: expiringCertCount,
      failedMigrations: failedJobs,
      totalAssets,
      generatedAt: new Date().toISOString(),
    }
  })
})

// ── GET /api/v1/sandbox/export ────────────────────────────────────────────────
router.get('/export', requireAuth, async (req: AuthenticatedRequest, res) => {
  const client = clientFor(req)
  if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

  try {
    const payload = await buildSandboxPayload(client, req.user!.id)
    const format = String(req.query.format || 'json').toLowerCase()
    const baseName = `qguard-sandbox-${new Date().toISOString().slice(0, 10)}`

    if (format === 'csv') {
      const escape = (v: unknown) => {
        const t = String(v ?? '')
        return /[",\n\r]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t
      }
      const rows = [
        ['id', 'name', 'asset', 'status', 'fromAlgo', 'toAlgo', 'progress', 'riskLevel', 'phase', 'owner', 'environment'],
        ...payload.simulations.map((s) => [s.id, s.name, s.assetName, s.status, s.fromAlgo, s.toAlgo, s.progress, s.riskLevel, s.phase, s.owner, s.environment]),
      ]
      res.setHeader('Content-Type', 'text/csv')
      res.setHeader('Content-Disposition', `attachment; filename="${baseName}.csv"`)
      return res.send(rows.map((r) => r.map(escape).join(',')).join('\n'))
    }

    res.setHeader('Content-Type', 'application/json')
    res.setHeader('Content-Disposition', `attachment; filename="${baseName}.json"`)
    return res.send(JSON.stringify(payload, null, 2))
  } catch (err) {
    return res.status(500).json({ error: { code: 'EXPORT_FAILED', message: 'Export failed' } })
  }
})

export default router
