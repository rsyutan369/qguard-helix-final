/**
 * Real Time Scanning — `/api/v1/scanner/live`.
 *
 *   Scanner engines (executeWebScan + edge intelligence, unchanged)
 *     → Observation processor (src/lib/live-scan/observations.ts)
 *     → Append-only event log (in memory, flushed to pqc_scan_sessions.metadata)
 *     → SSE publisher (replay from any sequence, then live)
 *     → Browser canvas (same reducer as the server)
 *
 * The scan runs in a background worker owned by THIS process, not by the HTTP
 * request: refreshing the page re-subscribes to the same run instead of
 * starting a second one. Results are persisted through the PQC Scanner's own
 * helpers (`createSession` / `persistResult`), so every live scan also lands
 * in Assets, CBOM, Crypto Exposure and Reports exactly like a normal scan.
 *
 * Security: Authorization header only; every run is pinned to the creating
 * user and returns 404 to anyone else; targets go through the PQC Scanner's
 * `normalizeTarget` (private/internal hosts refused) AND a DNS-resolved
 * public-address check (`verifyPublicHost`), and the engines connect through
 * their own SSRF-safe resolver. Concurrency, target count and per-target
 * budgets are clamped server-side. Every control action is audit-logged.
 */

import { Router, type NextFunction, type Request, type Response } from 'express'
import { quotedCsvCell } from '@/lib/csv'
import { createHash, randomUUID } from 'node:crypto'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { verifyPublicHost } from '@/lib/scanner/public-scan/safe-dns'
import { executeWebScan } from '@/lib/scanner/web-scanner/scan-orchestrator'
import type { SSEEvent, WebScanCompleteResult, WebScanFinding, WebScanTargetType } from '@/lib/scanner/web-scanner/types'
import { applyEvents, emptyGraph, hasMeasuredSurface, summarize, type LiveGraphState } from '@/lib/live-scan/graph-reducer'
import { SCANNER_NODE_ID, TargetObserver, type InventoryContext, type ObserverSink } from '@/lib/live-scan/observations'
import {
  TERMINAL_STATUSES, type ActivityLine, type AssetAssessment, type AssetFindingObservation, type LiveEvent, type LiveEventPayload, type LiveEventType, type LiveNode,
  type LiveScanConfig, type RunListItem, type RunMeta,
} from '@/lib/live-scan/types'
import {
  buildSummary, createSession, normalizeTarget, normalizeWebResult, persistResult, updateSession,
  type AuthorizedTarget, type DefensiveResult, type PersistenceMode,
} from './scanner'

const router = Router()

const LIMITS = {
  maxTargets: 25,
  maxActiveRunsPerUser: 2,
  concurrency: { min: 1, max: 4, default: 2 },
  targetTimeoutSec: { min: 20, max: 90, default: 45 },
  expiringWithinDays: { min: 1, max: 120, default: 30 },
  storedEvents: 8000,
  retainFinishedRunsMs: 6 * 60 * 60_000,
  heartbeatMs: 15_000,
  flushMs: 4_000,
} as const

const SCANNER_MODE = 'live-real-time-workflow'

/* ------------------------------------------------------------------ */
/* Auth                                                                */
/* ------------------------------------------------------------------ */

type Authed = Request & { user?: { id: string; email?: string | null }; token?: string }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as Authed).user = user
  ;(req as Authed).token = token
  next()
}
router.use(requireAuth)

/* ------------------------------------------------------------------ */
/* Run registry                                                        */
/* ------------------------------------------------------------------ */

interface Run {
  meta: RunMeta
  userId: string
  email: string | null
  token: string
  events: LiveEvent[]
  state: LiveGraphState
  subscribers: Set<(event: LiveEvent) => void>
  queue: AuthorizedTarget[]
  paused: boolean
  cancelRequested: boolean
  resumeWaiters: Array<() => void>
  results: DefensiveResult[]
  errors: string[]
  linked: { assetIds: string[]; cbomIds: string[]; exposureIds: string[] }
  flushTimer: ReturnType<typeof setTimeout> | null
  workerAlive: boolean
  /** Hydrated from storage — read-only, no worker. */
  stored: boolean
  /** Called once, after the terminal record is persisted. */
  doneListeners: Array<() => void>
}

const g = globalThis as unknown as { __qguard_live_scan_runs__?: Map<string, Run> }
const runs: Map<string, Run> = g.__qguard_live_scan_runs__ ?? (g.__qguard_live_scan_runs__ = new Map())

function sha256(value: unknown): string {
  return createHash('sha256').update(typeof value === 'string' ? value : stableJson(value)).digest('hex')
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`).join(',')}}`
}

function emit(run: Run, type: LiveEventType, payload: LiveEventPayload, activity: ActivityLine | null, entityId: string | null): LiveEvent {
  const seq = run.events.length + 1
  const event: LiveEvent = {
    id: `${run.meta.id}:${seq}`,
    scanId: run.meta.id,
    tenantId: run.userId,
    seq,
    type,
    at: new Date().toISOString(),
    entityId,
    version: 1,
    payload,
    activity,
  }
  // Append to the log BEFORE publishing: a subscriber can never see an event
  // that a later replay would not also return.
  run.events.push(event)
  run.state = applyEvents(run.state, [event])
  if (payload.run) run.meta = { ...run.meta, ...payload.run }
  for (const subscriber of run.subscribers) {
    try { subscriber(event) } catch { /* a broken subscriber is dropped by its own close handler */ }
  }
  scheduleFlush(run)
  return event
}

function setMeta(run: Run, patch: Partial<RunMeta>, type: LiveEventType, activity: ActivityLine | null) {
  emit(run, type, { run: patch }, activity, null)
}

function sinkFor(run: Run): ObserverSink {
  return {
    emit: (type, payload, activity, entityId) => emit(run, type, payload, activity, entityId),
    hash: sha256,
    now: () => new Date().toISOString(),
    getNode: (id) => run.state.nodes[id],
    getEdge: (id) => run.state.edges[id],
    getFinding: (id) => run.state.findings[id],
  }
}

/* ------------------------------------------------------------------ */
/* Persistence — the PQC Scanner session row carries the event log     */
/* ------------------------------------------------------------------ */

function sessionMetadata(run: Run) {
  const events = run.events.length > LIMITS.storedEvents ? run.events.slice(0, LIMITS.storedEvents) : run.events
  return {
    authorization: 'explicit-user-acknowledgement',
    scannerMode: SCANNER_MODE,
    targets: run.meta.targets,
    telemetry: [],
    errors: run.errors,
    results: run.results,
    summary: run.results.length ? buildSummary(run.results) : undefined,
    linkedAssetIds: run.linked.assetIds,
    linkedCbomIds: run.linked.cbomIds,
    linkedExposureIds: run.linked.exposureIds,
    liveScan: {
      version: 1,
      meta: run.meta,
      graphSummary: summarize(run.state),
      eventCount: run.events.length,
      truncated: run.events.length > LIMITS.storedEvents,
      events,
    },
  }
}

/**
 * Flushes are SERIALIZED on one chain and each one snapshots the run when it
 * executes, not when it was scheduled. Without this, a debounced flush already
 * in flight could land after the final flush and overwrite the terminal record
 * with an older, still-"running" state (caught by live-scan-live-check).
 */
const flushChains = new WeakMap<Run, Promise<void>>()

function flush(run: Run): Promise<void> {
  if (run.flushTimer) { clearTimeout(run.flushTimer); run.flushTimer = null }
  const next = (flushChains.get(run) ?? Promise.resolve()).then(() => writeSession(run))
  flushChains.set(run, next)
  return next
}

async function writeSession(run: Run): Promise<void> {
  if (!run.meta.sessionId || run.stored) return
  const client = createAuthClient(run.token)
  const terminal = TERMINAL_STATUSES.includes(run.meta.status)
  const summary = summarize(run.state)
  await updateSession(client, run.meta.sessionId, run.userId, {
    status: terminal ? (run.meta.status === 'partial' ? 'completed' : run.meta.status) : 'running',
    progress: summary.progressPercent ?? 0,
    scanned_assets: summary.targetsDone,
    findings_count: summary.findingsTotal,
    ...(terminal ? { completed_at: run.meta.endedAt ?? new Date().toISOString() } : {}),
    metadata: sessionMetadata(run),
  }, run.meta.persistence as PersistenceMode).catch((error) => {
    console.warn('[live-scan] session flush failed:', (error as Error)?.message || error)
  })
}

function scheduleFlush(run: Run) {
  if (run.stored || run.flushTimer) return
  run.flushTimer = setTimeout(() => void flush(run), LIMITS.flushMs)
}

async function audit(run: Run | null, token: string, userId: string, email: string | null | undefined, action: string, detail: Record<string, unknown>) {
  try {
    const client = createAuthClient(token)
    if (!client) return
    await client.from('audit_logs').insert({
      user_id: userId,
      action,
      entity_type: 'live_scan',
      entity_id: run?.meta.sessionId && /^[0-9a-f-]{36}$/i.test(run.meta.sessionId) ? run.meta.sessionId : null,
      details: { ...detail, runId: run?.meta.id ?? null, actor: email || userId, module: 'real-time-scanning' },
    })
  } catch (error) {
    console.warn('[live-scan] audit write skipped:', (error as Error)?.message || error)
  }
}

/* ------------------------------------------------------------------ */
/* Worker                                                              */
/* ------------------------------------------------------------------ */

async function waitIfPaused(run: Run) {
  while (run.paused && !run.cancelRequested) {
    await new Promise<void>((resolve) => run.resumeWaiters.push(resolve))
  }
}

async function loadInventory(run: Run, targets: AuthorizedTarget[]): Promise<Map<string, InventoryContext>> {
  const out = new Map<string, InventoryContext>()
  try {
    const client = createAuthClient(run.token)
    if (!client) return out
    const names = [...new Set(targets.map((target) => target.displayName))]
    const { data } = await client.from('assets').select('id, name, criticality, metadata').eq('user_id', run.userId).in('name', names).limit(200)
    for (const row of (data ?? []) as Array<Record<string, any>>) {
      const metadata = (row.metadata ?? {}) as Record<string, unknown>
      out.set(String(row.name), {
        assetId: String(row.id),
        name: typeof metadata.display_name === 'string' ? metadata.display_name : null,
        owner: typeof metadata.owner === 'string' ? metadata.owner : null,
        environment: typeof metadata.environment === 'string' ? metadata.environment : null,
        criticality: typeof row.criticality === 'string' ? row.criticality : null,
      })
    }
  } catch {
    // Inventory enrichment is optional; its absence renders as "Unknown owner".
  }
  return out
}

function scannerInput(target: AuthorizedTarget): string {
  if (target.type === 'url') return target.normalized
  return target.port && target.port !== 443 ? `${target.host}:${target.port}` : target.host
}

async function scanTarget(run: Run, target: AuthorizedTarget, inventory: Map<string, InventoryContext>) {
  const key = target.normalized
  setMeta(run, { activeTargets: [...run.meta.activeTargets.filter((item) => item !== key), key], stage: `Resolving ${target.host}` }, 'scan.progress', null)
  const observer = new TargetObserver(sinkFor(run), {
    scanId: run.meta.id,
    target: key,
    host: target.host,
    port: target.port,
    expiringWithinDays: run.meta.config.expiringWithinDays,
    inventory: inventory.get(target.displayName) ?? null,
  })
  const startedAt = new Date().toISOString()
  let result: WebScanCompleteResult | null = null
  let failure: string | null = null
  let acceptingObservations = true

  const verdict = await verifyPublicHost(target.host)
  if (!verdict.ok) {
    failure = verdict.message || 'Target did not resolve to a public address'
    observer.discovered([])
  } else {
    observer.discovered(verdict.addresses ?? [])
    try {
      result = await executeWebScan(
        scannerInput(target),
        target.type as WebScanTargetType,
        (event: SSEEvent) => {
          if (!acceptingObservations) return
          if (event.type === 'finding' && event.finding) {
            observer.engineFinding(event.finding as WebScanFinding)
          } else if (event.type === 'error') {
            failure = String(event.message || 'Scanner engine reported an error')
            acceptingObservations = false
          } else if (event.type === 'phase-start') {
            setMeta(run, { stage: String(event.label ?? event.phase ?? 'Scanning') }, 'scan.progress', null)
          } else if (event.type === 'module-complete') {
            const count = typeof event.findingCount === 'number' ? event.findingCount : 0
            const error = typeof event.error === 'string' ? event.error : null
            const notApplicable = Boolean(error?.startsWith('not-applicable:'))
            emit(run, 'scan.progress', {
              progress: { stage: run.meta.stage, message: String(event.moduleName ?? event.moduleId), target: key, module: String(event.moduleId ?? '') },
            }, {
              title: `${String(event.moduleName ?? event.moduleId)} ${notApplicable ? 'not applicable' : error ? 'reported an error' : 'completed'}`,
              detail: notApplicable ? error!.replace('not-applicable:', '').trim() : error ? error : `${count} finding(s) · ${key}`,
              severity: error && !notApplicable ? 'medium' : undefined,
              target: key,
            }, null)
          }
        },
        run.meta.config.targetTimeoutSec * 1000,
        {
          onCertificateEvidence: (evidence) => { if (acceptingObservations) observer.certificateEvidence(evidence) },
          onHttpEvidence: (evidence) => { if (acceptingObservations) observer.httpEvidence(evidence) },
          onEdge: ({ intelligence, handshake, certificate, error }) => {
            if (acceptingObservations) observer.edgeEvidence(intelligence, handshake, error, certificate)
          },
          onTls: (tls) => {
            if (acceptingObservations) observer.tlsEvidence(tls)
          },
        },
      )
    } catch (error) {
      failure = (error as Error)?.message || 'Scanner engine failed'
    } finally {
      acceptingObservations = false
    }
  }

  if (result) {
    try {
      const normalized = normalizeWebResult(result, startedAt)
      normalized.metadata.partialAssessment = Boolean(failure || !(normalized.tlsVersion || result.edgeIntelligence?.transport.negotiatedProtocol))
      if (normalized.metadata.partialAssessment) normalized.status = 'failed'
      normalized.tlsVersion ??= result.edgeIntelligence?.transport.negotiatedProtocol ?? null
      const engineAlgorithms = new Set(normalized.findings.map((finding) => finding.algorithm.toLowerCase()))
      for (const component of observer.measuredComponents()) {
        if (engineAlgorithms.has(component.label.toLowerCase())) continue
        const vulnerable = component.status === 'exposure' || component.status === 'critical'
        const safe = component.status === 'validated'
        const role = String(component.data.role)
        normalized.findings.push({
          id: component.id, algorithm: component.label, category: role, location: key,
          threatLevel: component.status === 'critical' ? 'CRITICAL' : vulnerable ? 'HIGH' : safe ? 'SAFE' : 'LOW',
          status: vulnerable ? 'Quantum-vulnerable' : safe ? 'PQC-ready' : 'Unknown / requires manual review',
          description: String(component.data.quantumExposure),
          recommendation: typeof component.data.migrationTarget === 'string' ? component.data.migrationTarget : 'Review the measured cryptographic role and algorithm.',
          pqcReplacement: typeof component.data.migrationTarget === 'string' ? component.data.migrationTarget : null,
          keySize: typeof component.data.keySize === 'number' ? component.data.keySize : null,
          evidence: component.evidenceIds.join(', '), detectionMethod: 'real-time-scan-observation', source: 'web-scanner', inventoryOnly: true,
        })
      }
      const expiry = Object.values(run.state.findings).find((finding) => finding.type === 'CERTIFICATE_EXPIRED' && finding.affectedTargets.includes(key))
      if (expiry) {
        const matches = (finding: DefensiveResult['findings'][number]) => /expired certificate/i.test(finding.algorithm)
        normalized.findings = normalized.findings.filter((finding) => !matches(finding))
        normalized.findings.push({
          id: expiry.id, algorithm: 'Certificate expired', category: 'Certificate validity', location: key,
          threatLevel: 'CRITICAL', status: 'Legacy/deprecated', description: expiry.description, recommendation: expiry.remediation,
          pqcReplacement: null, keySize: null, evidence: expiry.evidenceIds.join(', '), detectionMethod: 'real-time-scan-observation', source: 'web-scanner',
        })
      }
      run.results.push(normalized)
      if (run.meta.sessionId) {
        const linked = await persistResult(createAuthClient(run.token), run.userId, run.meta.sessionId, target, normalized, run.meta.persistence as PersistenceMode)
        run.linked.assetIds.push(linked.assetId)
        run.linked.cbomIds.push(...linked.cbomIds)
        run.linked.exposureIds.push(...linked.exposureIds)
      }
    } catch (error) {
      run.errors.push(`${key}: persistence failed — ${(error as Error)?.message || error}`)
    }
  }
  if (failure) {
    run.errors.push(`${key}: ${failure}`)
  }

  observer.completed(result, failure)
  setMeta(run, {
    activeTargets: run.meta.activeTargets.filter((item) => item !== key),
    completedTargets: result && !failure ? [...run.meta.completedTargets, key] : run.meta.completedTargets,
    failedTargets: result && !failure ? run.meta.failedTargets : [...run.meta.failedTargets, key],
  }, 'scan.progress', null)
}

async function runWorker(run: Run) {
  run.workerAlive = true
  try {
    const client = createAuthClient(run.token)
    const session = await createSession(client, run.userId, run.queue, [])
    setMeta(run, { sessionId: session.id, persistence: session.mode, status: 'running', startedAt: new Date().toISOString(), stage: 'Loading inventory' }, 'scan.started', {
      title: 'Live scan started',
      detail: `${run.queue.length} authorized target(s) · ${run.meta.config.concurrency} parallel worker(s) · persisted as ${session.mode === 'database' ? 'PQC Scanner session' : 'in-memory session'}`,
      entityId: SCANNER_NODE_ID,
    })
    const scannerNode: LiveNode = {
      id: SCANNER_NODE_ID, kind: 'scanner', label: 'Helix Scanner', sublabel: 'Web · TLS · PKI · PQC engines', status: 'active',
      targets: [], observedAt: new Date().toISOString(), firstSeq: 0, lastSeq: 0, evidenceIds: [],
      data: { engines: ['Public Edge Intelligence', 'TLS Analyzer', 'Certificate Parser', 'Key Exchange Analyzer', 'Cipher Suite Analyzer', 'Detection Rules', 'Risk Scoring'] },
    }
    emit(run, 'asset.discovered', { node: scannerNode }, null, SCANNER_NODE_ID)

    const inventory = await loadInventory(run, run.queue)
    const workers = Array.from({ length: run.meta.config.concurrency }, async () => {
      for (;;) {
        await waitIfPaused(run)
        if (run.cancelRequested) return
        const target = run.queue.shift()
        if (!target) return
        await scanTarget(run, target, inventory)
      }
    })
    await Promise.all(workers)

    const cancelled = run.cancelRequested
    const summary = summarize(run.state)
    const nodes = Object.values(run.state.nodes)
    const anyMeasured = hasMeasuredSurface(run.state)
    const incomplete = run.meta.failedTargets.length > 0 || nodes.some((node) => node.kind === 'asset' && node.data.scanStatus === 'incomplete')
    const allFailed = !cancelled && incomplete && !anyMeasured
    const partial = !cancelled && incomplete && anyMeasured
    const finalStatus = cancelled ? 'cancelled' : allFailed ? 'failed' : partial ? 'partial' : 'completed'
    emit(run, 'asset.updated', { node: { ...run.state.nodes[SCANNER_NODE_ID], status: finalStatus === 'completed' ? 'validated' : finalStatus === 'failed' ? 'failed' : 'unknown' } }, null, SCANNER_NODE_ID)
    setMeta(run, {
      status: finalStatus,
      stage: cancelled ? 'Cancelled by operator' : allFailed ? 'Assessment failed' : partial ? 'Partial assessment · evidence retained' : 'Scan complete',
      endedAt: new Date().toISOString(),
      activeTargets: [],
      errorSummary: run.errors.length ? run.errors.slice(0, 5).join(' | ')
        : partial ? 'Some TLS or cryptographic measurements were unavailable. Recorded evidence remains available in the canvas and inventory.' : null,
    }, cancelled ? 'scan.cancelled' : allFailed ? 'scan.failed' : 'scan.completed', {
      title: cancelled ? 'Scan cancelled' : allFailed ? 'Scan failed' : partial ? 'Scan finished with partial coverage' : 'Scan completed',
      detail: `${summary.assetsDiscovered} asset(s) · ${summary.certificatesAnalyzed} certificate(s) · ${summary.findingsTotal} open finding(s)${cancelled ? ` · ${run.queue.length} target(s) not scanned` : ''}`,
      severity: allFailed ? 'high' : partial ? 'medium' : 'validated',
      entityId: SCANNER_NODE_ID,
    })
  } catch (error) {
    const message = (error as Error)?.message || 'Live scan worker failed'
    run.errors.push(message)
    setMeta(run, { status: 'failed', stage: 'Worker failed', endedAt: new Date().toISOString(), errorSummary: message, activeTargets: [] }, 'scan.failed', {
      title: 'Scan failed', detail: message, severity: 'high',
    })
  } finally {
    // The terminal record is written BEFORE the run is declared finished, so
    // a client that reopens the scan the moment its stream ends reads the
    // final stored state, never the last debounced snapshot.
    await flush(run)
    run.workerAlive = false
    for (const listener of run.doneListeners.splice(0)) {
      try { listener() } catch { /* listener owns its own cleanup */ }
    }
  }
}

/* ------------------------------------------------------------------ */
/* Loading a stored run (after restart / from history)                 */
/* ------------------------------------------------------------------ */

async function loadRun(id: string, userId: string, token: string): Promise<Run | null> {
  // The in-memory run is authoritative while this process holds it — by run
  // id OR by its database session id.
  const live = runs.get(id) ?? [...runs.values()].find((run) => run.meta.sessionId === id && !run.stored)
  if (live) return live.userId === userId ? live : null
  if (!/^[0-9a-f-]{36}$/i.test(id)) return null
  const client = createAuthClient(token)
  if (!client) return null
  const { data } = await client.from('pqc_scan_sessions').select('id, user_id, status, metadata').eq('id', id).eq('user_id', userId).maybeSingle()
  const stored = (data?.metadata as Record<string, any> | undefined)?.liveScan
  if (!data || !stored || !Array.isArray(stored.events)) return null
  const events = stored.events as LiveEvent[]
  const state = applyEvents(emptyGraph(), events)
  const meta: RunMeta = { ...(stored.meta as RunMeta), id: String(data.id) }
  // A run that was still running when its worker's process stopped cannot be
  // resumed from here; it is reported as interrupted, never as complete.
  if (!TERMINAL_STATUSES.includes(meta.status)) {
    meta.status = 'failed'
    meta.errorSummary = 'Interrupted: the scanner process stopped before this run finished. Rescan the targets to complete it.'
  }
  return {
    meta, userId, email: null, token, events, state: { ...state, meta }, subscribers: new Set(), queue: [], paused: false,
    cancelRequested: false, resumeWaiters: [], results: [], errors: [], linked: { assetIds: [], cbomIds: [], exposureIds: [] },
    flushTimer: null, workerAlive: false, stored: true, doneListeners: [],
  }
}

function sweep() {
  const now = Date.now()
  for (const [id, run] of runs) {
    if (run.workerAlive || run.subscribers.size) continue
    const ended = run.meta.endedAt ? new Date(run.meta.endedAt).getTime() : now
    if (now - ended > LIMITS.retainFinishedRunsMs) runs.delete(id)
  }
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */

function clampInt(value: unknown, range: { min: number; max: number; default: number }): number {
  const parsed = Math.round(Number(value))
  if (!Number.isFinite(parsed)) return range.default
  return Math.min(range.max, Math.max(range.min, parsed))
}

function publicMeta(run: Run) {
  return { ...run.meta, workerAlive: run.workerAlive, paused: run.paused }
}

router.post('/runs', async (req: Authed, res: Response) => {
  sweep()
  const user = req.user!
  const body = (req.body ?? {}) as Record<string, unknown>
  if (body.authorized !== true) {
    return res.status(403).json({ error: { code: 'AUTHORIZATION_ACK_REQUIRED', message: 'Confirm that every target belongs to you or is explicitly authorized for defensive scanning.' } })
  }
  const rawTargets = (Array.isArray(body.targets) ? body.targets : [])
    .map((item) => String(item ?? '').trim()).filter(Boolean)
  const unique = [...new Set(rawTargets)]
  if (!unique.length) return res.status(400).json({ error: { code: 'INVALID_TARGET', message: 'At least one authorized target is required.' } })
  if (unique.length > LIMITS.maxTargets) return res.status(400).json({ error: { code: 'TARGET_LIMIT_EXCEEDED', message: `Scan at most ${LIMITS.maxTargets} targets per live run.` } })

  const normalized: AuthorizedTarget[] = []
  for (const raw of unique) {
    const parsed = normalizeTarget(raw)
    if (parsed.ok === false) return res.status(400).json({ error: { code: 'INVALID_OR_UNAUTHORIZED_TARGET', message: parsed.message } })
    if (parsed.target.type === 'github' || parsed.target.type === 'ssh') {
      return res.status(400).json({ error: { code: 'UNSUPPORTED_TARGET', message: `"${raw}" is a ${parsed.target.type === 'ssh' ? 'SSH' : 'repository'} target. Real Time Scanning maps TLS/PKI endpoints; use the PQC Scanner for this target.` } })
    }
    if (!normalized.some((item) => item.normalized === parsed.target.normalized)) normalized.push(parsed.target)
  }

  const active = [...runs.values()].filter((run) => run.userId === user.id && run.workerAlive)
  if (active.length >= LIMITS.maxActiveRunsPerUser) {
    return res.status(429).json({ error: { code: 'TOO_MANY_ACTIVE_SCANS', message: `At most ${LIMITS.maxActiveRunsPerUser} live scans can run at once. Wait for one to finish or cancel it.` } })
  }

  const config: LiveScanConfig = {
    name: String(body.name ?? '').trim().slice(0, 80) || `Live scan · ${normalized[0].host}${normalized.length > 1 ? ` +${normalized.length - 1}` : ''}`,
    targets: normalized.map((target) => target.normalized),
    concurrency: clampInt(body.concurrency, LIMITS.concurrency),
    targetTimeoutSec: clampInt(body.targetTimeoutSec, LIMITS.targetTimeoutSec),
    expiringWithinDays: clampInt(body.expiringWithinDays, LIMITS.expiringWithinDays),
    trustStore: 'platform-default',
  }
  const now = new Date().toISOString()
  const id = randomUUID()
  const meta: RunMeta = {
    id, name: config.name, status: 'starting', stage: 'Creating scan session', createdAt: now, startedAt: null, endedAt: null,
    targets: config.targets, completedTargets: [], failedTargets: [], activeTargets: [], config,
    sessionId: null, persistence: 'none', errorSummary: null,
  }
  const run: Run = {
    meta, userId: user.id, email: user.email ?? null, token: req.token!, events: [], state: emptyGraph(),
    subscribers: new Set(), queue: normalized.slice(), paused: false, cancelRequested: false, resumeWaiters: [],
    results: [], errors: [], linked: { assetIds: [], cbomIds: [], exposureIds: [] }, flushTimer: null, workerAlive: false, stored: false, doneListeners: [],
  }
  runs.set(id, run)
  setMeta(run, meta, 'scan.progress', null)
  void audit(run, req.token!, user.id, user.email, 'live_scan.start', { targets: config.targets, concurrency: config.concurrency })
  void runWorker(run)
  res.status(202).json({ run: publicMeta(run) })
})

router.get('/runs', async (req: Authed, res: Response) => {
  sweep()
  const user = req.user!
  const items: RunListItem[] = [...runs.values()]
    .filter((run) => run.userId === user.id && !run.stored)
    .map((run) => ({
      id: run.meta.sessionId && run.meta.persistence === 'database' ? run.meta.sessionId : run.meta.id,
      name: run.meta.name, status: run.meta.status, createdAt: run.meta.createdAt, endedAt: run.meta.endedAt,
      targets: run.meta.targets, sessionId: run.meta.sessionId, findings: summarize(run.state).findingsTotal, source: 'live',
    }))
  try {
    const client = createAuthClient(req.token!)
    const { data } = await client!
      .from('pqc_scan_sessions')
      .select('id, status, started_at, completed_at, target_scope, findings_count, liveMeta:metadata->liveScan->meta, liveSummary:metadata->liveScan->graphSummary')
      .eq('user_id', user.id)
      .eq('metadata->>scannerMode', SCANNER_MODE)
      .order('started_at', { ascending: false })
      .limit(30)
    for (const row of (data ?? []) as Array<Record<string, any>>) {
      if (items.some((item) => item.id === row.id || item.sessionId === row.id)) continue
      const liveMeta = (row.liveMeta ?? {}) as Partial<RunMeta>
      items.push({
        id: String(row.id), name: liveMeta.name || String(row.target_scope || 'Live scan'),
        status: (TERMINAL_STATUSES.includes(liveMeta.status as never) ? liveMeta.status : 'failed') as RunListItem['status'],
        createdAt: liveMeta.createdAt || row.started_at, endedAt: liveMeta.endedAt || row.completed_at || null,
        targets: liveMeta.targets || String(row.target_scope || '').split(', ').filter(Boolean), sessionId: String(row.id),
        findings: (row.liveSummary as { findingsTotal?: number } | null)?.findingsTotal ?? null, source: 'stored',
      })
    }
  } catch {
    // History from storage is best-effort; in-memory runs are still listed.
  }
  items.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
  res.json({ runs: items, limits: { maxTargets: LIMITS.maxTargets, concurrency: LIMITS.concurrency, targetTimeoutSec: LIMITS.targetTimeoutSec, expiringWithinDays: LIMITS.expiringWithinDays } })
})

async function resolveRun(req: Authed, res: Response): Promise<Run | null> {
  const id = String(req.params.id)
  let run = await loadRun(id, req.user!.id, req.token!)
  if (!run) {
    // A database session id may name a run still held in memory.
    run = [...runs.values()].find((item) => item.meta.sessionId === id && item.userId === req.user!.id) ?? null
  }
  if (!run) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Live scan not found' } })
    return null
  }
  return run
}

// Asset Inventory reads the same finding records as the run inspector. Pick
// the latest *attempted* assessment of each target, including partial scans.
router.get('/asset-findings', async (req: Authed, res: Response) => {
  const userId = req.user!.id
  const client = createAuthClient(req.token!)
  type Source = { id: string; meta: RunMeta; state?: LiveGraphState }
  const sources = new Map<string, Source>()
  for (const run of runs.values()) {
    if (run.userId !== userId || run.stored) continue
    const id = run.meta.persistence === 'database' && run.meta.sessionId ? run.meta.sessionId : run.meta.id
    sources.set(id, { id, meta: run.meta, state: run.state })
  }
  res.setHeader('Cache-Control', 'private, no-store')
  try {
    if (!client) throw new Error('Scan history unavailable')
    const pageSize = 100
    for (let offset = 0; ; offset += pageSize) {
      const { data, error } = await client.from('pqc_scan_sessions')
        .select('id, liveMeta:metadata->liveScan->meta')
        .eq('user_id', userId)
        .eq('metadata->>scannerMode', SCANNER_MODE)
        .order('started_at', { ascending: false }).order('id')
        .range(offset, offset + pageSize - 1)
      if (error) throw error
      for (const row of data ?? []) {
        const meta = row.liveMeta as unknown as RunMeta | null
        if (meta && !sources.has(row.id)) sources.set(row.id, { id: row.id, meta })
      }
      if ((data?.length ?? 0) < pageSize) break
    }

    const latest = new Map<string, Source>()
    for (const source of [...sources.values()].sort((a, b) => b.meta.createdAt.localeCompare(a.meta.createdAt))) {
      for (const target of [...(source.meta.completedTargets ?? []), ...(source.meta.failedTargets ?? []), ...(source.meta.activeTargets ?? [])]) {
        if (!latest.has(target)) latest.set(target, source)
      }
    }
    const targetsBySource = new Map<Source, string[]>()
    for (const [target, source] of latest) {
      const targets = targetsBySource.get(source) ?? []
      targets.push(target)
      targetsBySource.set(source, targets)
    }
    const observations: AssetFindingObservation[] = []
    const assessments: AssetAssessment[] = []
    for (const [source, targets] of targetsBySource) {
      const stored = source.state ? null : await loadRun(source.id, userId, req.token!)
      const state = source.state ?? stored?.state
      if (!state) throw new Error('A scan record could not be loaded')
      const meta = stored?.meta ?? source.meta
      const findings = Object.values(state.findings)
      const assets = Object.values(state.nodes).filter((node) => node.kind === 'asset')
      for (const target of targets) {
        const asset = assets.find((node) => node.targets.includes(target))
        const assessment = meta.activeTargets.includes(target) && !TERMINAL_STATUSES.includes(meta.status) ? 'scanning'
          : meta.completedTargets.includes(target) && asset?.data.scanStatus === 'completed' ? 'completed' : 'incomplete'
        const record = { target, runId: source.id, scanStatus: meta.status, assessment } satisfies AssetAssessment
        assessments.push(record)
        for (const finding of findings) {
          if (!finding.affectedTargets.includes(target)) continue
          observations.push({ ...record, finding, observedAt: finding.lastSeen })
        }
      }
    }
    res.json({ assessments, observations })
  } catch {
    res.status(503).json({ error: { message: 'Live scan findings could not be loaded.' } })
  }
})

router.get('/runs/:id', async (req: Authed, res: Response) => {
  const run = await resolveRun(req, res)
  if (!run) return
  res.json({ run: publicMeta(run), events: run.events, summary: summarize(run.state), lastSeq: run.events.length })
})

router.get('/runs/:id/stream', async (req: Authed, res: Response) => {
  const run = await resolveRun(req, res)
  if (!run) return
  const header = Number(req.header('last-event-id'))
  const after = Number.isFinite(header) && header > 0 ? header : Math.max(0, Number(req.query.after) || 0)

  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  const send = (event: LiveEvent) => res.write(`id: ${event.seq}\nevent: live\ndata: ${JSON.stringify(event)}\n\n`)
  for (const event of run.events.slice(after)) send(event)

  if (!run.workerAlive) {
    res.write(`event: end\ndata: ${JSON.stringify({ lastSeq: run.events.length, status: run.meta.status })}\n\n`)
    res.end()
    return
  }
  run.subscribers.add(send)
  const heartbeat = setInterval(() => {
    // scan.heartbeat is transport-level: it proves the stream is alive and
    // carries the head sequence so the client can detect a gap.
    res.write(`event: heartbeat\ndata: ${JSON.stringify({ type: 'scan.heartbeat', lastSeq: run.events.length, status: run.meta.status, at: new Date().toISOString() })}\n\n`)
    if (!run.workerAlive) {
      res.write(`event: end\ndata: ${JSON.stringify({ lastSeq: run.events.length, status: run.meta.status })}\n\n`)
      cleanup()
      res.end()
    }
  }, LIMITS.heartbeatMs)
  const cleanup = () => {
    clearInterval(heartbeat)
    run.subscribers.delete(send)
  }
  // Close only once the worker has persisted its terminal record.
  let closed = false
  const finish = () => {
    if (closed) return
    closed = true
    res.write(`event: end\ndata: ${JSON.stringify({ lastSeq: run.events.length, status: run.meta.status })}\n\n`)
    cleanup()
    res.end()
  }
  run.doneListeners.push(finish)
  req.on('close', () => {
    closed = true
    cleanup()
    const index = run.doneListeners.indexOf(finish)
    if (index >= 0) run.doneListeners.splice(index, 1)
  })
})

function controlGuard(run: Run, res: Response): boolean {
  if (run.stored || !run.workerAlive) {
    res.status(409).json({ error: { code: 'RUN_NOT_ACTIVE', message: `This scan is ${run.meta.status}; it can no longer be controlled.` } })
    return false
  }
  return true
}

router.post('/runs/:id/pause', async (req: Authed, res: Response) => {
  const run = await resolveRun(req, res)
  if (!run || !controlGuard(run, res)) return
  if (!run.paused) {
    run.paused = true
    setMeta(run, { status: 'paused', stage: 'Paused — in-flight targets finish, no new target starts' }, 'scan.paused', {
      title: 'Scan paused', detail: `${run.meta.activeTargets.length} in-flight target(s) will finish; ${run.queue.length} queued target(s) wait.`,
    })
    void audit(run, req.token!, req.user!.id, req.user!.email, 'live_scan.pause', {})
  }
  res.json({ run: publicMeta(run) })
})

router.post('/runs/:id/resume', async (req: Authed, res: Response) => {
  const run = await resolveRun(req, res)
  if (!run || !controlGuard(run, res)) return
  if (run.paused) {
    run.paused = false
    const waiters = run.resumeWaiters.splice(0)
    waiters.forEach((resolve) => resolve())
    setMeta(run, { status: 'running', stage: 'Resumed' }, 'scan.resumed', { title: 'Scan resumed', detail: `${run.queue.length} target(s) queued` })
    void audit(run, req.token!, req.user!.id, req.user!.email, 'live_scan.resume', {})
  }
  res.json({ run: publicMeta(run) })
})

router.post('/runs/:id/cancel', async (req: Authed, res: Response) => {
  const run = await resolveRun(req, res)
  if (!run || !controlGuard(run, res)) return
  if (!run.cancelRequested) {
    run.cancelRequested = true
    run.paused = false
    run.resumeWaiters.splice(0).forEach((resolve) => resolve())
    setMeta(run, { status: 'cancelling', stage: 'Cancelling — waiting for in-flight targets' }, 'scan.progress', {
      title: 'Cancellation requested', detail: `${run.queue.length} queued target(s) dropped; ${run.meta.activeTargets.length} in-flight target(s) finish first.`,
    })
    void audit(run, req.token!, req.user!.id, req.user!.email, 'live_scan.cancel', { dropped: run.queue.map((target) => target.normalized) })
  }
  res.json({ run: publicMeta(run) })
})

router.post('/runs/:id/rescan', async (req: Authed, res: Response) => {
  const run = await resolveRun(req, res)
  if (!run) return
  const raw = String((req.body as Record<string, unknown>)?.target ?? '').trim()
  if (!run.meta.targets.includes(raw)) {
    return res.status(400).json({ error: { code: 'TARGET_NOT_IN_SCOPE', message: 'Only a target already authorized in this scan can be rescanned here.' } })
  }
  if (run.workerAlive && !run.cancelRequested) {
    // Keep each run's evidence tied to one attempt per target. The client
    // offers a new run for repeat assessments, preserving both observations.
    if ([...run.meta.activeTargets, ...run.meta.completedTargets, ...run.meta.failedTargets].includes(raw)) {
      return res.status(409).json({ error: { code: 'NEW_RUN_REQUIRED', message: 'Start a new live scan to reassess this target.' }, target: raw })
    }
    const parsed = normalizeTarget(raw)
    if (parsed.ok === false) return res.status(400).json({ error: { code: 'INVALID_TARGET', message: parsed.message } })
    if (!run.queue.some((target) => target.normalized === parsed.target.normalized)) run.queue.push(parsed.target)
    setMeta(run, {}, 'scan.progress', { title: 'Target queued', detail: raw, target: raw })
    void audit(run, req.token!, req.user!.id, req.user!.email, 'live_scan.rescan', { target: raw, mode: 'queued-in-run' })
    return res.json({ run: publicMeta(run), mode: 'queued' })
  }
  return res.status(409).json({ error: { code: 'RUN_FINISHED', message: 'This scan has finished. Start a new live scan for this target.' }, target: raw })
})

router.get('/runs/:id/findings', async (req: Authed, res: Response) => {
  const run = await resolveRun(req, res)
  if (!run) return
  res.json({ findings: Object.values(run.state.findings), summary: summarize(run.state) })
})

router.get('/runs/:id/entities/:entityId', async (req: Authed, res: Response) => {
  const run = await resolveRun(req, res)
  if (!run) return
  const entityId = String(req.params.entityId)
  const node = run.state.nodes[entityId] ?? null
  const edge = run.state.edges[entityId] ?? null
  const finding = run.state.findings[entityId] ?? null
  const evidence = run.state.evidence[entityId] ?? null
  if (!node && !edge && !finding && !evidence) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Entity not found in this scan' } })
  const edges = node ? Object.values(run.state.edges).filter((item) => item.source === entityId || item.target === entityId) : []
  const evidenceIds = new Set([...(node?.evidenceIds ?? []), ...(finding?.evidenceIds ?? []), ...(edge?.evidenceId ? [edge.evidenceId] : [])])
  res.json({
    node, edge, finding, evidence: evidence ?? undefined, edges,
    evidenceRecords: [...evidenceIds].map((id) => run.state.evidence[id]).filter(Boolean),
    history: run.events.filter((event) => event.entityId === entityId).map((event) => ({ seq: event.seq, type: event.type, at: event.at })),
  })
})

router.get('/runs/:id/export', async (req: Authed, res: Response) => {
  const run = await resolveRun(req, res)
  if (!run) return
  const format = String(req.query.format || 'json')
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  if (format === 'csv') {
    const rows = [['finding_id', 'rule_id', 'type', 'severity', 'exposure', 'status', 'title', 'affected_targets', 'evidence_count', 'first_seen', 'remediation'].join(',')]
    for (const finding of Object.values(run.state.findings)) {
      rows.push([finding.id, finding.ruleId, finding.type, finding.severity, finding.exposure, finding.status, finding.title,
        finding.affectedTargets.join(' '), finding.evidenceIds.length, finding.firstSeen, finding.remediation].map(quotedCsvCell).join(','))
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', `attachment; filename="live-scan-findings-${stamp}.csv"`)
    return res.send(rows.join('\n'))
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.setHeader('Content-Disposition', `attachment; filename="live-scan-graph-${stamp}.json"`)
  res.send(JSON.stringify({
    run: run.meta,
    summary: summarize(run.state),
    nodes: Object.values(run.state.nodes),
    edges: Object.values(run.state.edges),
    findings: Object.values(run.state.findings),
    evidence: Object.values(run.state.evidence),
    eventCount: run.events.length,
    exportedAt: new Date().toISOString(),
  }, null, 2))
})

export default router
