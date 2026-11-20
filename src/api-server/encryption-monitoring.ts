/**
 * Encryption Monitoring — `/api/v1/dashboard/encryption-monitoring`.
 *
 * Same contract as the TLS/PKI command center: one per-tenant model computed
 * once per 15s window, projected into a bounded payload, pushed over SSE, with
 * server-side filtering and paging for the deep tables.
 *
 * This replaces the `encryption` mode of `crypto-operations-dashboard.ts`,
 * which classified rows with a substring test broad enough to match nearly
 * every cryptographic record in the tenant, summed seven tables that are
 * storage views of the same observations, and consequently published figures
 * that contradicted the platform's own Quantum Readiness Engine.
 */

import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildPortfolio } from './migration-planner'
import { buildEncryptionIntelligence } from '@/lib/encryption/intelligence'
import { payloadFingerprint, streamLiveSnapshot } from './live-snapshot-stream'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { createSourceLedger, type SourceRead } from './source-ledger'
import { readTelemetrySource } from './telemetry-source-rows'
import type { AlgorithmRow, EncryptionFinding, EncryptionIntelligence, KeyRecord } from '@/lib/encryption/types'

type Row = Record<string, unknown>

/** The model as published: the intelligence plus the outcome of every source read. */
type EncryptionModel = EncryptionIntelligence & { reads: SourceRead[] }

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value === null || value === undefined ? '' : String(value).trim()
}

function num(value: unknown, fallback = 0): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

/**
 * Authorization header ONLY — a `?token=` fallback here served this Pro page
 * to BASIC tenants, because the subscription gateway reads only the header.
 */
function tokenFromRequest(req: Request): string | null {
  return getToken(req)
}

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = tokenFromRequest(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}

/* ------------------------------------------------------------------ */
/* Model + cache                                                       */
/* ------------------------------------------------------------------ */

const CAP = {
  cryptoInventory: 4000,
  runtimeEvents: 6000,
  scannerEvidence: 3000,
  generatedKeys: 2000,
  vaultFiles: 2000,
  cryptoExposures: 2500,
  scanResults: 2500,
  scannerAlerts: 1500,
  securityEvents: 1500,
  scanSessions: 400,
  scannerAgents: 400,
  connectorAccounts: 400,
} as const

const MODEL_TTL_MS = 15_000
const modelCache = createSingleFlightCache<EncryptionModel>(MODEL_TTL_MS)

async function computeModel(token: string, userId: string, force: boolean): Promise<EncryptionModel> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')
  // Failed reads degrade to [] but are recorded and published (common-issues #64).
  const ledger = createSourceLedger('encryption-monitoring')

  // Canonical estate truth first — both are per-tenant cached, so this is
  // nearly free and guarantees the page agrees with Quantum Readiness.
  const [snapshot, portfolio] = await Promise.all([buildSnapshot(token, userId, undefined, force), buildPortfolio(token, userId, force)])

  const [
    cryptoInventory,
    runtimeEvents,
    scannerEvidence,
    generatedKeys,
    vaultFiles,
    cryptoExposures,
    scanResults,
    scannerAlerts,
    securityEvents,
    scanSessions,
    scannerAgents,
    connectorAccounts,
  ] = await Promise.all([
    readTelemetrySource(
      ledger, client, 'crypto_inventory',
      'id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at',
      CAP.cryptoInventory, (q) => q
        .eq('user_id', userId)
        .order('discovered_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'runtime_crypto_events',
      'id, asset_id, source_type, event_type, operation_type, severity, asset_name, host, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, process_name, is_pqc, is_legacy, hndl_risk, metadata, observed_at, created_at',
      CAP.runtimeEvents, (q) => q
        .eq('user_id', userId)
        .order('observed_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'scanner_evidence',
      'id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, raw_evidence, processed_at, observed_at, created_at',
      CAP.scannerEvidence, (q) => q
        .eq('user_id', userId)
        .order('observed_at', { ascending: false }),
    ),
    // PKI-issued material lives in the same table under a `PKI-` prefix and is
    // the PKI page's subject, not this one's.
    readTelemetrySource(
      ledger, client, 'generated_keys',
      'id, algorithm, bit_length, entropy_source, quality_score, fingerprint, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at',
      CAP.generatedKeys, (q) => q
        .eq('user_id', userId)
        .not('algorithm', 'like', 'PKI-%')
        .order('created_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'vault_files',
      'id, encryption_status, encryption_algorithm, signature_status, original_size, encrypted_size, created_at, updated_at',
      CAP.vaultFiles, (q) => q
        .eq('user_id', userId)
        .eq('is_deleted', false)
        .order('updated_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'crypto_exposures',
      'id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at',
      CAP.cryptoExposures, (q) => q
        .eq('user_id', userId)
        .order('updated_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'pqc_scan_results',
      'id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at',
      CAP.scanResults, (q) => q
        .eq('user_id', userId)
        .order('created_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'scanner_alerts',
      'id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at',
      CAP.scannerAlerts, (q) => q
        .eq('user_id', userId)
        .order('created_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'security_events',
      'id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, created_at',
      CAP.securityEvents, (q) => q
        .eq('user_id', userId)
        .order('created_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'pqc_scan_sessions',
      'id, status, completed_at, created_at, updated_at',
      CAP.scanSessions, (q) => q.eq('user_id', userId).order('updated_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'scanner_agents',
      'id, name, status, hostname, last_seen_at, created_at, updated_at',
      CAP.scannerAgents, (q) => q.eq('user_id', userId),
    ),
    readTelemetrySource(
      ledger, client, 'connector_accounts',
      'id, provider, status, last_sync_at, created_at, updated_at',
      CAP.connectorAccounts, (q) => q.eq('user_id', userId),
    ),
  ])

  const truncated = ledger.reads.some((read) => read.state === 'truncated')

  const intelligence = buildEncryptionIntelligence({
    assets: portfolio.assets,
    snapshot: {
      quantumReadiness: snapshot.scores.quantumReadiness,
      quantumRisk: snapshot.scores.quantumRisk,
      quantumRiskLevel: snapshot.scores.quantumRiskLevel,
      hndlRisk: snapshot.scores.hndlRisk,
      hndlRiskLevel: snapshot.scores.hndlRiskLevel,
      assetsAssessed: snapshot.inventory.assetsAssessed,
    },
    cryptoInventory,
    runtimeEvents,
    scannerEvidence,
    generatedKeys,
    vaultFiles,
    cryptoExposures,
    scanResults,
    scannerAlerts,
    securityEvents,
    scanSessions,
    scannerAgents,
    connectorAccounts,
    truncated,
  })
  return Object.assign(intelligence, { reads: ledger.reads })
}

export async function buildEncryptionModel(token: string, userId: string, force = false): Promise<EncryptionModel> {
  return modelCache.get(userId, () => computeModel(token, userId, force), force)
}

/* ------------------------------------------------------------------ */
/* Projection                                                          */
/* ------------------------------------------------------------------ */

const PAGE = { findings: 40, keys: 40, atRest: 40 } as const

function projectView(model: EncryptionModel) {
  return {
    generatedAt: model.generatedAt,
    inventoryRevision: payloadFingerprint({ observations: model.observations, findings: model.findings, keys: model.keys.keys }),
    latestEvidenceAt: model.latestEvidenceAt,
    hasData: model.hasData,
    /** Outcome of every source read: `unavailable` means the query FAILED, not "none". */
    reads: model.reads,
    posture: model.posture,
    telemetry: model.telemetry,
    timeline: model.timeline,

    symmetric: model.symmetric,
    hashes: model.hashes,
    macs: model.macs,
    kdfs: model.kdfs,
    application: model.application.slice(0, 25),

    keys: { ...model.keys, keys: model.keys.keys.slice(0, PAGE.keys) },
    atRest: { ...model.atRest, records: model.atRest.records.slice(0, PAGE.atRest) },
    vault: model.vault,
    operations: model.operations,
    findings: model.findings.slice(0, PAGE.findings),

    totals: {
      observations: model.observations.length,
      algorithms: model.symmetric.length + model.hashes.length + model.macs.length + model.kdfs.length,
      applicationAlgorithms: model.application.length,
      findings: model.findings.length,
      keys: model.keys.total,
      atRestRecords: model.atRest.records.length,
      vaultFiles: model.vault.files,
    },
  }
}

/* ------------------------------------------------------------------ */
/* Filtering                                                           */
/* ------------------------------------------------------------------ */

function paginate<T>(rows: T[], req: Request) {
  const limit = Math.max(1, Math.min(200, num(req.query.limit) || 50))
  const offset = Math.max(0, num(req.query.offset))
  return { rows: rows.slice(offset, offset + limit), total: rows.length, limit, offset }
}

function filterAlgorithms(rows: AlgorithmRow[], req: Request): AlgorithmRow[] {
  const search = str(req.query.search).toLowerCase()
  const strength = str(req.query.strength).toLowerCase()
  const layer = str(req.query.layer).toLowerCase()
  const sort = str(req.query.sort) || 'observations'

  const filtered = rows.filter((row) => {
    if (strength && strength !== 'all' && row.strength.strength !== strength) return false
    if (layer && layer !== 'all' && row.layer !== layer) return false
    if (search) {
      const haystack = `${row.label} ${row.assetNames.join(' ')} ${row.operations.join(' ')}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })

  const direction = str(req.query.dir) === 'asc' ? 1 : -1
  filtered.sort((a, b) => {
    if (sort === 'label') return a.label.localeCompare(b.label) * (direction === -1 ? -1 : 1)
    if (sort === 'assets') return (a.assetIds.length - b.assetIds.length) * direction
    return (a.observations - b.observations) * direction
  })
  return filtered
}

function filterFindings(rows: EncryptionFinding[], req: Request): EncryptionFinding[] {
  const search = str(req.query.search).toLowerCase()
  const severity = str(req.query.severity).toLowerCase()
  const layer = str(req.query.layer).toLowerCase()

  return rows.filter((row) => {
    if (severity && severity !== 'all' && row.severity !== severity) return false
    if (layer && layer !== 'all' && row.layer !== layer) return false
    if (search) {
      const haystack = `${row.title} ${row.assetName} ${row.observed} ${row.remediation}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })
}

function filterKeys(rows: KeyRecord[], req: Request): KeyRecord[] {
  const search = str(req.query.search).toLowerCase()
  const lifecycle = str(req.query.lifecycle).toLowerCase()

  return rows.filter((row) => {
    if (lifecycle && lifecycle !== 'all' && row.lifecycle !== lifecycle) return false
    if (search) {
      const haystack = `${row.label} ${row.algorithm} ${row.entropySource} ${row.fingerprint || ''}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

const router = Router()
router.use(requireAuth)
router.use((_req, res, next) => { res.setHeader('Cache-Control', 'private, no-store'); next() })

const model = (req: AuthedRequest, force = false) => buildEncryptionModel(req.token!, req.user!.id, force)

router.get('/', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req, str(req.query.refresh) === '1')
    const projection = projectView(data)
    res.json({ data: { ...projection, fingerprint: payloadFingerprint(projection) } })
  } catch (error) {
    console.error('[encryption-monitoring] snapshot failed:', error)
    res.status(500).json({
      error: { code: 'ENCRYPTION_INTEL_ERROR', message: error instanceof Error ? error.message : 'Failed to compute encryption intelligence' },
    })
  }
})

/**
 * GET /stream — SSE carrying the whole view payload, so the client swaps state
 * atomically and the KPI strip can never disagree with the tables mid-update.
 * Fingerprinted: a full `encryption-intel` frame only when content changes,
 * otherwise `encryption-intel-unchanged`; failures are `encryption-intel-error`.
 */
const projectionMemo = new WeakMap<EncryptionModel, ReturnType<typeof projectView>>()
router.get('/stream', (req: AuthedRequest, res: Response) => {
  streamLiveSnapshot(req, res, {
    event: 'encryption-intel',
    build: async () => {
      const data = await model(req)
      let projected = projectionMemo.get(data)
      if (!projected) {
        projected = projectView(data)
        projectionMemo.set(data, projected)
      }
      return projected
    },
    intervalMs: 10_000,
  })
})

router.get('/algorithms', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const all = [...data.symmetric, ...data.hashes, ...data.macs, ...data.kdfs, ...data.application]
    const page = paginate(filterAlgorithms(all, req), req)
    res.json({ data: { algorithms: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
  } catch (error) {
    console.error('[encryption-monitoring] algorithms failed:', error)
    res.status(500).json({ error: { code: 'ENCRYPTION_INTEL_ERROR', message: 'Failed to load algorithms' } })
  }
})

/** GET /algorithms/:label — every observation behind one algorithm row. */
router.get('/algorithms/:label', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const label = decodeURIComponent(req.params.label)
    const all = [...data.symmetric, ...data.hashes, ...data.macs, ...data.kdfs, ...data.application]
    const row = all.find((entry) => entry.label === label)
    if (!row) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Algorithm not found' } })
    res.json({
      data: {
        algorithm: row,
        observations: data.observations.filter((observation) => observation.observed === label),
        findings: data.findings.filter((finding) => finding.observed === label),
      },
    })
  } catch (error) {
    console.error('[encryption-monitoring] algorithm detail failed:', error)
    res.status(500).json({ error: { code: 'ENCRYPTION_INTEL_ERROR', message: 'Failed to load algorithm detail' } })
  }
})

router.get('/findings', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const page = paginate(filterFindings(data.findings, req), req)
    res.json({ data: { findings: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
  } catch (error) {
    console.error('[encryption-monitoring] findings failed:', error)
    res.status(500).json({ error: { code: 'ENCRYPTION_INTEL_ERROR', message: 'Failed to load findings' } })
  }
})

router.get('/keys', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const page = paginate(filterKeys(data.keys.keys, req), req)
    res.json({ data: { keys: page.rows, total: page.total, limit: page.limit, offset: page.offset, measured: data.keys.measured } })
  } catch (error) {
    console.error('[encryption-monitoring] keys failed:', error)
    res.status(500).json({ error: { code: 'ENCRYPTION_INTEL_ERROR', message: 'Failed to load key material' } })
  }
})

export default router
