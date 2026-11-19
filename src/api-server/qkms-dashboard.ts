/**
 * QKMS Command Center — the one backend behind seven pages.
 *
 * `/api/v1/dashboard/qkms/overview`      `/inventory`   `/lifecycle`
 * `/governance`                          `/rotation`    `/readiness`
 * `/risk-analysis`
 *
 * All seven are projections of a single per-tenant model computed once per
 * window. Before this rewrite each request rebuilt 26 tenant queries from
 * scratch, the SSE endpoint re-ran that build every 8 seconds per connected
 * client, and the frontend held four EventSource connections per page — so a
 * single open dashboard cost roughly 200 tenant queries a minute and two pages
 * could still disagree because nothing collapsed them onto one computation.
 *
 * Caching contract, matching `buildSnapshot` / `buildTlsPkiModel`: only the
 * FETCH + derivation is cached, per tenant, for 15s. Every connected dashboard
 * and every SSE push of a tenant collapses onto that one computation, so N open
 * pages cost the same as one AND cannot disagree within the window. Failures
 * are never cached. A governed write invalidates the tenant's entry so the next
 * read reflects it immediately.
 *
 * ── What this file is NOT allowed to do ────────────────────────────────────
 * Derive. Every score, state, count and verdict comes from `@/lib/qkms`. If a
 * number is needed here that the model does not publish, the model is what has
 * to change — that rule is the only thing that keeps seven pages telling one
 * story.
 */

import { createHash } from 'node:crypto'
import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildQkmsIntelligence, normaliseJobStatus, toIndexEntry } from '@/lib/qkms/intelligence'
import { ROTATION_TRANSITIONS, QKMS_MODES } from '@/lib/qkms/types'
import type {
  KeyIndexEntry,
  ManagedKey,
  QkmsIntelligence,
  QkmsMode,
  RotationJobStatus,
} from '@/lib/qkms/types'

type Row = Record<string, unknown>

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

function num(value: unknown, fallback: number): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

/**
 * Raw private-key material must never reach this API.
 *
 * QKMS is a metadata and governance plane: it records where key material lives,
 * who owns it and when it was rotated. Accepting the material itself would make
 * the dashboard database a key escrow, which is the single worst outcome this
 * module could produce.
 */
const BLOCKED_SECRET_FIELDS = [
  'private_key', 'privateKey', 'secret', 'secretValue', 'secret_value',
  'raw_key', 'rawKey', 'plaintext', 'key_material', 'keyMaterial', 'pem', 'pkcs8', 'pkcs12',
]

function carriesSecretMaterial(body: Row): boolean {
  return Object.keys(body || {}).some((key) => BLOCKED_SECRET_FIELDS.includes(key))
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
/** Work-order states that close an order; anything else is open. */
const TERMINAL_JOB_STATUSES: RotationJobStatus[] = ['completed', 'failed', 'cancelled']
function isMissingTable(error: unknown): boolean {
  const text = `${(error as { code?: string })?.code || ''} ${(error as { message?: string })?.message || ''}`.toLowerCase()
  return text.includes('42p01') || text.includes('pgrst205') || text.includes('does not exist') || text.includes('could not find the table')
}

function isMissingColumn(error: unknown): boolean {
  const text = `${(error as { code?: string })?.code || ''} ${(error as { message?: string })?.message || ''}`.toLowerCase()
  return text.includes('42703') || text.includes('column') && text.includes('does not exist')
}

/**
 * Tables the key estate is BUILT from. If one of these fails, every page's key
 * list, posture and risk would be computed from a partial estate — so the
 * model refuses to build and the client keeps its last good view with an error,
 * instead of rendering "no keys" from a query that never returned.
 */
const CORE_TABLES = new Set([
  'assets', 'qkms_keys', 'qkms_key_versions', 'qkms_policies', 'qkms_rotation_jobs', 'qkms_audit_events',
  'generated_keys', 'crypto_inventory', 'certificates', 'scanner_evidence', 'runtime_crypto_events', 'migration_jobs',
])

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any, failures: string[], limited: string[], cap: number): Promise<Row[]> {
  try {
    const rows: Row[] = []
    // A project may enforce a lower limit than the one requested by QKMS.
    while (rows.length < cap) {
      const { data, error, count } = await build(client.from(table)).order('id')
        .range(rows.length, Math.min(cap, rows.length + 500) - 1)
      if (error) throw error
      const page = (data as Row[]) || []
      rows.push(...page)
      if (count != null && rows.length >= count) return rows
      if (!page.length || rows.length >= cap || count == null) {
        limited.push(table)
        return rows
      }
    }
    return rows
  } catch (error) {
    console.warn(`[qkms] ${table} query failed:`, (error as Error)?.message || error)
    failures.push(table)
    return []
  }
}

/* ------------------------------------------------------------------ */
/* Auth                                                                */
/* ------------------------------------------------------------------ */

/**
 * Header only. EventSource cannot set headers, which forced the original
 * stream to accept `?token=` — writing a bearer token into access logs,
 * proxies and browser history. The hook streams over fetch + ReadableStream
 * with an Authorization header, and nothing in the app still sends the query
 * form, so the fallback kept for one deploy has been removed.
 */
function tokenFromRequest(req: Request): string | null {
  return getToken(req)
}

/** Seconds-since-epoch expiry of a JWT, read without verifying it (verification happened at connect). */
function tokenExpiryMs(token: string): number | null {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1] || '', 'base64url').toString('utf8'))
    return typeof payload.exp === 'number' ? payload.exp * 1000 : null
  } catch {
    return null
  }
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

/* ------------------------------------------------------------------ */
/* Row caps                                                            */
/* ------------------------------------------------------------------ */

const CAP = {
  assets: 2000,
  qkmsKeys: 4000,
  qkmsKeyVersions: 4000,
  qkmsPolicies: 300,
  qkmsRotationJobs: 1500,
  qkmsAuditEvents: 2000,
  qkmsStorageBackends: 200,
  generatedKeys: 4000,
  cryptoInventory: 5000,
  certificates: 3000,
  runtimeEvents: 6000,
  scannerEvidence: 3000,
  migrationJobs: 1200,
  complianceEvidence: 800,
  vaultAuditLogs: 800,
  qrngEvents: 800,
  scannerAgents: 400,
  connectorAccounts: 400,
  agentHeartbeats: 600,
  scanSessions: 400,
} as const

/* ------------------------------------------------------------------ */
/* Model builder + single-flight cache                                 */
/* ------------------------------------------------------------------ */

const MODEL_TTL_MS = 15_000
const modelCache = new Map<string, { at: number; promise: Promise<QkmsIntelligence> }>()

async function computeModel(token: string, userId: string): Promise<QkmsIntelligence> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')
  const failures: string[] = []
  const limited: string[] = []

  /*
   * Every query is tenant-scoped in the query itself, on top of RLS. The
   * qkms_* tables key on `tenant_id`; the platform tables key on `user_id`.
   * Nothing here trusts a client-supplied scope.
   */
  const [
    assets,
    qkmsKeys,
    qkmsKeyVersions,
    qkmsPolicies,
    qkmsRotationJobs,
    qkmsAuditEvents,
    qkmsStorageBackends,
    generatedKeys,
    cryptoInventory,
    certificates,
    runtimeEvents,
    scannerEvidence,
    migrationJobs,
    complianceEvidence,
    vaultAuditLogs,
    qrngEvents,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    scanSessions,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, updated_at, created_at', { count: 'exact' }).eq('user_id', userId).order('updated_at', { ascending: false }), failures, limited, CAP.assets),
    /* qkms_* rows are read, and written, only where the caller is BOTH tenant and
       user. The deployed RLS predicate is "tenant OR user", which lets another
       signed-in user insert a row carrying this tenant's id under their own
       user_id; matching on user_id too keeps such a planted row out of this
       tenant's model whatever the database policy says. */
    safeRows(client, 'qkms_keys', (q) => q.select('*', { count: 'exact' }).eq('tenant_id', userId).eq('user_id', userId).order('updated_at', { ascending: false }), failures, limited, CAP.qkmsKeys),
    safeRows(client, 'qkms_key_versions', (q) => q.select('*', { count: 'exact' }).eq('tenant_id', userId).eq('user_id', userId).order('version', { ascending: false }), failures, limited, CAP.qkmsKeyVersions),
    safeRows(client, 'qkms_policies', (q) => q.select('*', { count: 'exact' }).eq('tenant_id', userId).eq('user_id', userId).order('updated_at', { ascending: false }), failures, limited, CAP.qkmsPolicies),
    safeRows(client, 'qkms_rotation_jobs', (q) => q.select('*', { count: 'exact' }).eq('tenant_id', userId).eq('user_id', userId).order('created_at', { ascending: false }), failures, limited, CAP.qkmsRotationJobs),
    safeRows(client, 'qkms_audit_events', (q) => q.select('*', { count: 'exact' }).eq('tenant_id', userId).eq('user_id', userId).order('created_at', { ascending: false }), failures, limited, CAP.qkmsAuditEvents),
    safeRows(client, 'qkms_storage_backends', (q) => q.select('*', { count: 'exact' }).eq('tenant_id', userId).eq('user_id', userId).order('updated_at', { ascending: false }), failures, limited, CAP.qkmsStorageBackends),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, entropy_source, quality_score, fingerprint, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at', { count: 'exact' }).eq('user_id', userId).order('created_at', { ascending: false }), failures, limited, CAP.generatedKeys),
    safeRows(client, 'crypto_inventory', (q) => q.select('*', { count: 'exact' }).eq('user_id', userId).order('discovered_at', { ascending: false }), failures, limited, CAP.cryptoInventory),
    safeRows(client, 'certificates', (q) => q.select('*', { count: 'exact' }).eq('user_id', userId).order('updated_at', { ascending: false }), failures, limited, CAP.certificates),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, asset_id, algorithm, key_exchange_algorithm, cipher_suite, operation_type, observed_at, created_at, is_pqc, is_legacy', { count: 'exact' }).eq('user_id', userId).order('observed_at', { ascending: false }), failures, limited, CAP.runtimeEvents),
    safeRows(client, 'scanner_evidence', (q) => q.select('*', { count: 'exact' }).eq('user_id', userId).order('observed_at', { ascending: false }), failures, limited, CAP.scannerEvidence),
    safeRows(client, 'migration_jobs', (q) => q.select('*', { count: 'exact' }).eq('user_id', userId).order('updated_at', { ascending: false }), failures, limited, CAP.migrationJobs),
    safeRows(client, 'compliance_evidence', (q) => q.select('*', { count: 'exact' }).eq('user_id', userId).order('updated_at', { ascending: false }), failures, limited, CAP.complianceEvidence),
    safeRows(client, 'vault_audit_logs', (q) => q.select('*', { count: 'exact' }).eq('user_id', userId).order('created_at', { ascending: false }), failures, limited, CAP.vaultAuditLogs),
    safeRows(client, 'qrng_events', (q) => q.select('*', { count: 'exact' }).eq('user_id', userId).order('created_at', { ascending: false }), failures, limited, CAP.qrngEvents),
    safeRows(client, 'scanner_agents', (q) => q.select('id, status, updated_at, last_seen_at', { count: 'exact' }).eq('user_id', userId).order('updated_at', { ascending: false }), failures, limited, CAP.scannerAgents),
    safeRows(client, 'connector_accounts', (q) => q.select('id, status, updated_at', { count: 'exact' }).eq('user_id', userId).order('updated_at', { ascending: false }), failures, limited, CAP.connectorAccounts),
    safeRows(client, 'agent_heartbeats', (q) => q.select('id, observed_at', { count: 'exact' }).eq('user_id', userId).order('observed_at', { ascending: false }), failures, limited, CAP.agentHeartbeats),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, completed_at, created_at, updated_at', { count: 'exact' }).eq('user_id', userId).order('created_at', { ascending: false }), failures, limited, CAP.scanSessions),
  ])

  const coreFailures = failures.filter((table) => CORE_TABLES.has(table)).sort()
  if (coreFailures.length) {
    // Thrown, so it is never cached and the client keeps its last good view.
    throw new Error(`Key evidence could not be read from ${coreFailures.join(', ')}. Figures are withheld rather than computed from a partial estate.`)
  }

  return buildQkmsIntelligence({
    assets,
    qkmsKeys,
    qkmsKeyVersions,
    qkmsPolicies,
    qkmsRotationJobs,
    qkmsAuditEvents,
    qkmsStorageBackends,
    generatedKeys,
    cryptoInventory,
    certificates,
    runtimeEvents,
    scannerEvidence,
    migrationJobs,
    complianceEvidence,
    vaultAuditLogs,
    qrngEvents,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    scanSessions,
    truncated: limited.length > 0,
    degradedSources: failures.sort(),
    limitedSources: limited.sort(),
  })
}

function buildModel(token: string, userId: string, force = false): Promise<QkmsIntelligence> {
  // Supabase supports two projects; the same subject is not a project or claim boundary.
  const cacheKey = `${userId}:${createHash('sha256').update(token).digest('hex')}`
  const cached = modelCache.get(cacheKey)
  if (cached && (cached.at === 0 || (!force && Date.now() - cached.at < MODEL_TTL_MS))) return cached.promise
  const promise: Promise<QkmsIntelligence> = computeModel(token, userId).then((data) => {
    const current = modelCache.get(cacheKey)
    // A write may invalidate while the queries are still in flight.
    if (current?.promise !== promise) return buildModel(token, userId)
    return data
  })
  const entry = { at: 0, promise }
  modelCache.set(cacheKey, entry)
  void promise.then(() => { entry.at = Date.now() }, () => {
    if (modelCache.get(cacheKey) === entry) modelCache.delete(cacheKey)
  })
  if (modelCache.size > 500) {
    const now = Date.now()
    for (const [key, value] of modelCache) if (value.at && now - value.at > MODEL_TTL_MS) modelCache.delete(key)
  }
  return promise
}

/** Open streams per tenant, woken when that tenant's model is invalidated. */
const streamWakers = new Map<string, Set<() => void>>()

/**
 * Drops the tenant's cached model so the next read reflects a just-made write,
 * and wakes that tenant's open streams — every tab and page sees a governed
 * write at once instead of on the next 10s tick.
 */
function invalidate(userId: string) {
  for (const key of modelCache.keys()) if (key.startsWith(`${userId}:`)) modelCache.delete(key)
  for (const wake of streamWakers.get(userId) || []) wake()
}

/* ------------------------------------------------------------------ */
/* Server-side filtering, sorting, pagination                          */
/* ------------------------------------------------------------------ */

const SORTABLE = {
  risk: (key: ManagedKey) => key.risk.score,
  label: (key: ManagedKey) => key.label.toLowerCase(),
  algorithm: (key: ManagedKey) => key.algorithm.toLowerCase(),
  owner: (key: ManagedKey) => (key.owner || '￿').toLowerCase(),
  asset: (key: ManagedKey) => (key.assetName || '￿').toLowerCase(),
  environment: (key: ManagedKey) => key.environment,
  created: (key: ManagedKey) => Date.parse(key.createdAt || '') || 0,
  rotated: (key: ManagedKey) => Date.parse(key.lastRotatedAt || '') || 0,
  // Keys with no expiry sort last under ascending order rather than first,
  // which is what an operator scanning for "what expires next" expects.
  expiry: (key: ManagedKey) => Date.parse(key.expiresAt || '') || Number.MAX_SAFE_INTEGER,
  version: (key: ManagedKey) => key.version,
  violations: (key: ManagedKey) => key.violationIds.length,
} as const

type SortKey = keyof typeof SORTABLE

function filterKeys(keys: ManagedKey[], req: Request): ManagedKey[] {
  const q = str(req.query.q).toLowerCase()
  const type = str(req.query.type)
  const algorithm = str(req.query.algorithm)
  const family = str(req.query.family)
  const owner = str(req.query.owner)
  const asset = str(req.query.asset)
  const environment = str(req.query.environment)
  const backend = str(req.query.backend)
  const custody = str(req.query.custody)
  const posture = str(req.query.posture)
  const lifecycle = str(req.query.lifecycle)
  const rotation = str(req.query.rotation)
  const risk = str(req.query.risk)
  const requirement = str(req.query.requirement)
  const compliance = str(req.query.compliance)
  const expiring = str(req.query.expiring)
  const ids = str(req.query.ids)
  const idSet = ids ? new Set(ids.split(',').map((value) => value.trim()).filter(Boolean)) : null

  return keys.filter((key) => {
    if (idSet && !idSet.has(key.id)) return false
    if (type && key.keyType !== type) return false
    if (algorithm && key.algorithm !== algorithm) return false
    if (family && key.family !== family) return false
    if (owner && (key.owner || 'Unassigned') !== owner) return false
    if (asset && (key.assetName || 'Unmapped') !== asset) return false
    if (environment && key.environment !== environment) return false
    if (backend && key.backend !== backend) return false
    if (custody && key.custody !== custody) return false
    if (posture && key.posture !== posture) return false
    if (lifecycle && key.lifecycle !== lifecycle) return false
    if (rotation && key.rotation !== rotation) return false
    if (risk && key.risk.level !== risk) return false
    if (requirement && key.migrationRequirement !== requirement) return false
    if (compliance && key.complianceStatus !== compliance) return false
    if (expiring) {
      const window = num(expiring, 0)
      if (window > 0 && (key.daysToExpiry === null || key.daysToExpiry < 0 || key.daysToExpiry > window)) return false
      if (window === 0 && key.daysToExpiry !== null && key.daysToExpiry >= 0) return false
    }
    if (q) {
      const haystack = [
        key.label, key.alias, key.algorithm, key.family, key.keyType, key.owner,
        key.assetName, key.backend, key.purpose, key.environment, key.fingerprint, key.id,
      ].filter(Boolean).join(' ').toLowerCase()
      if (!haystack.includes(q)) return false
    }
    return true
  })
}

function sortKeys(keys: ManagedKey[], req: Request): ManagedKey[] {
  const requested = str(req.query.sort) as SortKey
  const sortKey: SortKey = requested in SORTABLE ? requested : 'risk'
  const direction = str(req.query.dir) === 'asc' ? 1 : -1
  const accessor = SORTABLE[sortKey]

  return [...keys].sort((a, b) => {
    const left = accessor(a)
    const right = accessor(b)
    if (typeof left === 'string' && typeof right === 'string') return left.localeCompare(right) * direction
    return ((left as number) - (right as number)) * direction
  })
}

function paginate<T>(rows: T[], req: Request, fallbackLimit = 25) {
  const limit = Math.min(200, Math.max(1, num(req.query.limit, fallbackLimit)))
  const offset = Math.max(0, num(req.query.offset, 0))
  return { rows: rows.slice(offset, offset + limit), total: rows.length, limit, offset }
}

/** Facet values, computed from the whole estate so filters never dead-end. */
function buildFacets(keys: ManagedKey[]) {
  const collect = (accessor: (key: ManagedKey) => string | null) => {
    const counts = new Map<string, number>()
    for (const key of keys) {
      const value = accessor(key)
      if (!value) continue
      counts.set(value, (counts.get(value) || 0) + 1)
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([value, count]) => ({ value, count }))
  }

  return {
    types: collect((key) => key.keyType),
    algorithms: collect((key) => key.algorithm),
    families: collect((key) => key.family),
    owners: collect((key) => key.owner || 'Unassigned'),
    assets: collect((key) => key.assetName || 'Unmapped'),
    environments: collect((key) => key.environment),
    backends: collect((key) => key.backend),
    postures: collect((key) => key.posture),
    lifecycles: collect((key) => key.lifecycle),
    rotations: collect((key) => key.rotation),
    riskLevels: collect((key) => key.risk.level),
    requirements: collect((key) => key.migrationRequirement),
  }
}

/* ------------------------------------------------------------------ */
/* Projections — seven views of one model                              */
/* ------------------------------------------------------------------ */

interface CommonPayload extends Record<string, unknown> {
  mode: QkmsMode
  generatedAt: string
  latestEvidenceAt: string | null
  hasData: boolean
  metrics: QkmsIntelligence['metrics']
  telemetry: QkmsIntelligence['telemetry']
  gate: QkmsIntelligence['readiness']['gate']
  /** Cross-page counters so every page's nav shows the same badges. */
  nav: {
    keys: number
    violations: number
    rotationQueue: number
    criticalRisk: number
    migrationRequired: number
  }
}

function common(model: QkmsIntelligence, mode: QkmsMode): CommonPayload {
  return {
    mode,
    generatedAt: model.generatedAt,
    latestEvidenceAt: model.latestEvidenceAt,
    hasData: model.hasData,
    metrics: model.metrics,
    telemetry: model.telemetry,
    gate: model.readiness.gate,
    nav: {
      keys: model.metrics.totalKeys,
      violations: model.metrics.governanceViolations,
      rotationQueue: model.rotation.queue.length,
      criticalRisk: model.metrics.criticalRiskKeys,
      migrationRequired: model.metrics.keysRequiringMigration,
    },
  }
}

/** Top-N full keys for a page's primary table; the rest page in via `/keys`. */
function topKeys(model: QkmsIntelligence, ids: string[], limit = 25): KeyIndexEntry[] {
  const byId = new Map(model.keys.map((key) => [key.id, key]))
  return ids
    .map((id) => byId.get(id))
    .filter((key): key is ManagedKey => Boolean(key))
    .slice(0, limit)
    .map(toIndexEntry)
}

function projectView(model: QkmsIntelligence, mode: QkmsMode): Record<string, unknown> {
  const base = common(model, mode)

  switch (mode) {
    case 'overview':
      return {
        ...base,
        lifecycleFunnel: model.lifecycle.funnel,
        rotationPosture: model.rotation.posture,
        readiness: {
          overall: model.readiness.overall,
          verifiedReady: model.readiness.verifiedReady,
          declaredOnly: model.readiness.declaredOnly,
          decisionScope: model.readiness.decisionScope,
          bands: model.readiness.bands,
          postureCounts: model.readiness.postureCounts,
        },
        riskDistribution: model.risk.distribution,
        distributions: model.distributions,
        topRisks: topKeys(model, model.risk.ranked, 10),
        topViolations: model.governance.violations.slice(0, 8),
        entropy: model.governance.entropy,
        attention: {
          expired: model.lifecycle.attention.expired.length,
          expiringSoon: model.lifecycle.attention.expiringSoon.length,
          overdueRotation: model.lifecycle.attention.overdueRotation.length,
          orphaned: model.lifecycle.attention.orphaned.length,
        },
        recentAudit: model.audit.slice(0, 8),
      }

    case 'inventory':
      return {
        ...base,
        facets: buildFacets(model.keys),
        // First page only. The table pages through `/keys` server-side, so the
        // browser never holds an enterprise inventory it cannot render.
        keys: model.keys.slice(0, 25).map(toIndexEntry),
        total: model.keys.length,
        distributions: model.distributions,
      }

    case 'lifecycle':
      return {
        ...base,
        counts: model.lifecycle.counts,
        funnel: model.lifecycle.funnel,
        ageBuckets: model.lifecycle.ageBuckets,
        expiryBuckets: model.lifecycle.expiryBuckets,
        attentionCounts: {
          expired: model.lifecycle.attention.expired.length,
          expiringSoon: model.lifecycle.attention.expiringSoon.length,
          overdueRotation: model.lifecycle.attention.overdueRotation.length,
          neverRotated: model.lifecycle.attention.neverRotated.length,
          longLived: model.lifecycle.attention.longLived.length,
          orphaned: model.lifecycle.attention.orphaned.length,
          unused: model.lifecycle.attention.unused.length,
        },
        attention: {
          expired: topKeys(model, model.lifecycle.attention.expired, 10),
          expiringSoon: topKeys(model, model.lifecycle.attention.expiringSoon, 10),
          overdueRotation: topKeys(model, model.lifecycle.attention.overdueRotation, 10),
          neverRotated: topKeys(model, model.lifecycle.attention.neverRotated, 10),
          longLived: topKeys(model, model.lifecycle.attention.longLived, 10),
          orphaned: topKeys(model, model.lifecycle.attention.orphaned, 10),
        },
        keyTypes: model.distributions.keyClasses,
        facets: buildFacets(model.keys),
      }

    case 'governance':
      return {
        ...base,
        policies: model.governance.policies,
        violations: model.governance.violations.slice(0, 60),
        violationsTotal: model.governance.violations.length,
        violationsByRule: model.governance.violationsByRule,
        violationsBySeverity: model.governance.violationsBySeverity,
        backends: model.governance.backends,
        entropy: model.governance.entropy,
        audit: model.audit.slice(0, 30),
        custodyDistribution: model.distributions.custody,
      }

    case 'rotation':
      return {
        ...base,
        posture: model.rotation.posture,
        stateCounts: model.rotation.stateCounts,
        jobs: model.rotation.jobs.slice(0, 40),
        jobsTotal: model.rotation.jobs.length,
        queue: topKeys(model, model.rotation.queue, 25),
        queueTotal: model.rotation.queue.length,
        nextDueAt: model.rotation.posture.nextDueAt,
      }

    case 'readiness':
      return {
        ...base,
        readiness: model.readiness,
        migrationRequired: topKeys(
          model,
          model.keys.filter((key) => key.migrationRequirement === 'required').map((key) => key.id),
          25,
        ),
        migrationRequiredTotal: model.metrics.keysRequiringMigration,
        audit: model.audit.slice(0, 20),
        distributions: { postures: model.distributions.postures, families: model.distributions.families },
      }

    case 'risk-analysis':
      return {
        ...base,
        distribution: model.risk.distribution,
        factorAverages: model.risk.factorAverages,
        topRisks: topKeys(model, model.risk.ranked, 25),
        remediation: model.risk.remediation,
        violationsBySeverity: model.governance.violationsBySeverity,
        distributions: { families: model.distributions.families, postures: model.distributions.postures, custody: model.distributions.custody },
        facets: buildFacets(model.keys),
      }

    default:
      return base
  }
}

/* ------------------------------------------------------------------ */
/* Governed writes                                                     */
/* ------------------------------------------------------------------ */

/**
 * Every write goes through here so nothing can mutate a key without an audit
 * record. `key_ref` carries the canonical QKMS key id; the legacy `key_id` UUID
 * column is written only when the id happens to address a UUID row, because it
 * could never address a derived key at all.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function writeAudit(
  client: any,
  userId: string,
  keyRef: string | null,
  eventType: string,
  summary: string,
  before: unknown = null,
  after: unknown = null,
) {
  const uuidLike = keyRef && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(keyRef.split(':').pop() || '')
    ? keyRef.split(':').pop()!
    : null

  const payload: Row = {
    tenant_id: userId,
    user_id: userId,
    key_ref: keyRef,
    key_id: uuidLike,
    event_type: eventType,
    actor_id: userId,
    event_summary: summary,
    before_json: before ?? null,
    after_json: after ?? null,
  }

  const { error } = await client.from('qkms_audit_events').insert(payload)
  if (!error) return true

  if (isMissingColumn(error)) {
    // Schema extension not applied yet: fall back to the original shape so the
    // operation still leaves a trail rather than silently losing it.
    delete payload.key_ref
    const retry = await client.from('qkms_audit_events').insert(payload)
    if (retry.error && !isMissingTable(retry.error)) {
      console.warn('[qkms] audit persist failed:', retry.error.message || retry.error)
    }
    return !retry.error
  }
  if (!isMissingTable(error)) console.warn('[qkms] audit persist failed:', error.message || error)
  return false
}

/**
 * Resolve the registry row for a canonical key id, creating one when the key
 * was discovered by a scan and has no QKMS record yet.
 *
 * This is what lets an operator assign an owner to a scan-discovered key. The
 * alternative — greying the control out — would leave exactly the orphaned keys
 * the platform is telling them to fix as the ones they cannot fix.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function materialiseRegistryRow(client: any, userId: string, key: ManagedKey): Promise<string | null> {
  const existing = key.records.find((record) => record.table === 'qkms_keys')
  if (existing) return existing.recordId

  const { data, error } = await client
    .from('qkms_keys')
    .insert({
      tenant_id: userId,
      user_id: userId,
      key_ref: key.id,
      key_alias: key.alias || key.label,
      key_type: key.keyType,
      algorithm: key.algorithm,
      purpose: key.purpose,
      owner_id: key.owner,
      asset_id: key.assetId,
      certificate_id: key.certificateIds[0] || null,
      storage_backend: key.backend,
      storage_reference: key.storageReference,
      environment: key.environment,
      expires_at: key.expiresAt,
      status: key.lifecycle === 'discovered' ? 'active' : key.lifecycle,
      pqc_readiness: key.posture,
      exportable: key.exportable ?? false,
      hsm_backed: key.hsmBacked,
      entropy_source: key.entropySource,
      version: key.version,
      metadata_json: {
        adopted_from: key.records.map((record) => `${record.table}:${record.recordId}`),
        adopted_at: new Date().toISOString(),
        fingerprint: key.fingerprint,
      },
    })
    .select('id')
    .single()

  if (error) {
    if (isMissingColumn(error)) {
      // `key_ref` / `version` columns absent: retry without them.
      const retry = await client
        .from('qkms_keys')
        .insert({
          tenant_id: userId,
          user_id: userId,
          key_alias: key.alias || key.label,
          key_type: key.keyType,
          algorithm: key.algorithm,
          purpose: key.purpose,
          owner_id: key.owner,
          asset_id: key.assetId,
          storage_backend: key.backend,
          environment: key.environment,
          status: 'active',
          pqc_readiness: key.posture,
          hsm_backed: key.hsmBacked,
          metadata_json: { key_ref: key.id, fingerprint: key.fingerprint },
        })
        .select('id')
        .single()
      return retry.error ? null : str(retry.data?.id)
    }
    if (!isMissingTable(error)) console.warn('[qkms] registry materialisation failed:', error.message || error)
    return null
  }
  return str(data?.id)
}

/**
 * A write that returned no error but changed no row (RLS filtered it, or the
 * row no longer exists). Reported as a conflict so the client never shows a
 * success the database did not record.
 */
function notChanged(res: Response, message: string) {
  return res.status(409).json({ error: { code: 'NOT_CHANGED', message } })
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

const router = Router()
router.use(requireAuth)

router.use((_req, res, next) => {
  res.setHeader('Cache-Control', 'private, no-store')
  next()
})

router.use((req, res, next) => {
  if (['POST', 'PATCH'].includes(req.method) && req.body &&
      (carriesSecretMaterial(req.body) || /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i.test(JSON.stringify(req.body)))) {
    return res.status(400).json({ error: { code: 'RAW_KEY_REJECTED', message: 'QKMS accepts key metadata only. Do not submit key material.' } })
  }
  next()
})

const model = (req: AuthedRequest, force = false) => buildModel(req.token!, req.user!.id, force)

/** Re-resolve a client-supplied id against the tenant's own model. */
async function resolveKey(req: AuthedRequest, id: string): Promise<{ data: QkmsIntelligence; key: ManagedKey } | null> {
  const data = await model(req)
  const key = data.keys.find((row) => row.id === id)
  return key ? { data, key } : null
}

/* ---- Streams ---------------------------------------------------- */

/**
 * GET /stream — Server-Sent Events carrying the WHOLE view payload.
 *
 * The client replaces state atomically rather than patching, which is what
 * stops the KPI strip, the charts and the tables from disagreeing mid-update.
 * Streams send a whole snapshot on each new model and a heartbeat every 25s.
 * In each process, streams with the same auth scope share their model reads.
 */
router.get('/stream', async (req: AuthedRequest, res: Response) => {
  const mode = (str(req.query.mode) || 'overview') as QkmsMode
  if (!QKMS_MODES.includes(mode)) {
    return res.status(400).json({ error: { code: 'BAD_MODE', message: 'Unknown QKMS view' } })
  }

  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'private, no-store, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  const send = (event: string, data: unknown) => {
    if (closed) return
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }

  send('connected', { at: new Date().toISOString(), mode })

  /*
   * The stream authenticates once, at connect, but every push queries Supabase
   * with that same access token. Past its expiry those queries would fail, so
   * the stream ENDS at expiry with a reason; the client reconnects with the
   * refreshed session it already holds. Pushing on a dead token would at best
   * spam errors and, before failures were surfaced, render an empty estate.
   */
  const expiresAt = tokenExpiryMs(req.token!)
  let lastGeneratedAt = ''
  let pushing = false
  let pending = false
  const push = async () => {
    if (closed) return
    if (pushing) {
      pending = true
      return
    }
    if (expiresAt !== null && Date.now() >= expiresAt - 5_000) {
      if (!res.writableNeedDrain) send('qkms-error', { code: 'TOKEN_EXPIRED', message: 'Session token expired; reconnecting with a fresh session.' })
      end()
      return
    }
    if (res.writableNeedDrain) return
    pushing = true
    try {
      const data = await model(req)
      if (closed || pending || res.writableNeedDrain || data.generatedAt === lastGeneratedAt) return
      lastGeneratedAt = data.generatedAt
      // The filtered table or open drawer can change even when its summary does not.
      send('qkms', projectView(data, mode))
    } catch (error) {
      if (!res.writableNeedDrain) send('qkms-error', { message: error instanceof Error ? error.message : 'QKMS telemetry unavailable' })
    } finally {
      pushing = false
      if (pending) {
        pending = false
        void push()
      }
    }
  }

  const interval = setInterval(() => void push(), 10_000)
  const heartbeat = setInterval(() => {
    if (!closed && !res.writableNeedDrain) res.write(': heartbeat\n\n')
  }, 25_000)

  // A write invalidates the tenant's model; push shortly after (coalescing a
  // burst of writes into one rebuild) rather than waiting for the next tick.
  let wakeTimer: ReturnType<typeof setTimeout> | null = null
  const wake = () => {
    if (closed || wakeTimer) return
    wakeTimer = setTimeout(() => {
      wakeTimer = null
      void push()
    }, 250)
  }
  const userId = req.user!.id
  if (!streamWakers.has(userId)) streamWakers.set(userId, new Set())
  streamWakers.get(userId)!.add(wake)

  const release = () => {
    closed = true
    clearInterval(interval)
    clearInterval(heartbeat)
    if (wakeTimer) clearTimeout(wakeTimer)
    const wakers = streamWakers.get(userId)
    wakers?.delete(wake)
    if (wakers && !wakers.size) streamWakers.delete(userId)
  }
  function end() {
    if (closed) return
    release()
    res.end()
  }
  void push()

  res.once('close', release)
})

/* ---- Drill-down: keys ------------------------------------------- */

router.get('/keys', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const filtered = sortKeys(filterKeys(data.keys, req), req)
    const page = paginate(filtered, req)
    res.json({
      data: {
        keys: page.rows.map(toIndexEntry),
        total: page.total,
        limit: page.limit,
        offset: page.offset,
        facets: str(req.query.facets) === '1' ? buildFacets(data.keys) : undefined,
        generatedAt: data.generatedAt,
      },
    })
  } catch (error) {
    console.error('[qkms] keys failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: 'Failed to load key inventory' } })
  }
})

/**
 * GET /keys/:id — the full investigation record for one key.
 *
 * Shipped lazily: the dashboard payloads deliberately do not carry every
 * version, violation and audit event for every key, so the drawer fetches the
 * one the operator actually opened.
 */
router.get('/keys/:id', async (req: AuthedRequest, res: Response) => {
  try {
    const resolved = await resolveKey(req, req.params.id)
    if (!resolved) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Key not found in this tenant' } })
    const { data, key } = resolved

    res.json({
      data: {
        key,
        violations: data.governance.violations.filter((row) => row.keyId === key.id),
        rotationJobs: data.rotation.jobs.filter((job) => job.keyId === key.id),
        audit: data.audit.filter((row) => row.keyId === key.id).slice(0, 30),
        policies: data.governance.policies.filter((policy) =>
          policy.environmentScope === 'all' || policy.environmentScope === key.environment),
        relatedKeys: data.keys
          .filter((row) => row.id !== key.id && (row.assetId === key.assetId && key.assetId !== null))
          .slice(0, 10)
          .map(toIndexEntry),
      },
    })
  } catch (error) {
    console.error('[qkms] key detail failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: 'Failed to load key detail' } })
  }
})

/* ---- Drill-down: violations, jobs, audit ------------------------- */

router.get('/violations', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const severity = str(req.query.severity)
    const rule = str(req.query.rule)
    const keyId = str(req.query.keyId)
    const filtered = data.governance.violations.filter((row) =>
      (!severity || row.severity === severity)
      && (!rule || row.rule === rule)
      && (!keyId || row.keyId === keyId))
    const page = paginate(filtered, req, 50)
    res.json({ data: { violations: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
  } catch (error) {
    console.error('[qkms] violations failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: 'Failed to load governance violations' } })
  }
})

router.get('/rotation-jobs', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const status = str(req.query.status)
    const keyId = str(req.query.keyId)
    const filtered = data.rotation.jobs.filter((job) =>
      (!status || job.status === status) && (!keyId || job.keyId === keyId))
    const page = paginate(filtered, req, 50)
    res.json({ data: { jobs: page.rows, total: page.total, limit: page.limit, offset: page.offset, posture: data.rotation.posture } })
  } catch (error) {
    console.error('[qkms] rotation jobs failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: 'Failed to load rotation work orders' } })
  }
})

router.get('/audit', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    const keyId = str(req.query.keyId)
    const filtered = keyId ? data.audit.filter((row) => row.keyId === keyId) : data.audit
    const page = paginate(filtered, req, 50)
    res.json({ data: { audit: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
  } catch (error) {
    console.error('[qkms] audit failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: 'Failed to load audit evidence' } })
  }
})

/**
 * GET /export — the whole model, for the client-side report builder.
 *
 * The previous `/export` streamed a file body that the client discarded in
 * favour of a toast, so the operator never received anything. Exports are now
 * rendered in the browser by `services/reporting`, which is the same engine
 * behind the Assets and CBOM exports — one document pipeline, and a
 * reconciliation table proving the document matches the dashboard.
 */
router.get('/export', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    res.json({ data })
  } catch (error) {
    console.error('[qkms] export failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: 'Failed to build export payload' } })
  }
})

/* ---- Governed actions -------------------------------------------- */

/** POST /keys/:id/assign-owner */
router.post('/keys/:id/assign-owner', async (req: AuthedRequest, res: Response) => {
  try {
    const owner = str(req.body?.owner || req.body?.owner_id)
    if (!owner) return res.status(400).json({ error: { code: 'OWNER_REQUIRED', message: 'An owner is required' } })
    if (owner.length > 200) return res.status(400).json({ error: { code: 'OWNER_TOO_LONG', message: 'Owner must be 200 characters or fewer' } })

    const resolved = await resolveKey(req, req.params.id)
    if (!resolved) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Key not found in this tenant' } })
    const { key } = resolved
    if (!key.capabilities.assignOwner) {
      return res.status(409).json({ error: { code: 'NOT_PERMITTED', message: key.capabilities.reason } })
    }

    const client = createAuthClient(req.token!)
    if (!client) throw new Error('Database connection failed')

    const registryId = await materialiseRegistryRow(client, req.user!.id, key)
    if (!registryId) {
      return res.status(503).json({
        error: {
          code: 'REGISTRY_UNAVAILABLE',
          message: 'The QKMS registry table is not available. Apply supabase/qkms-command-center-schema.sql to enable governed key operations.',
        },
      })
    }

    const { data: updated, error } = await client
      .from('qkms_keys')
      .update({ owner_id: owner, updated_at: new Date().toISOString() })
      .eq('id', registryId)
      .eq('tenant_id', req.user!.id).eq('user_id', req.user!.id)
      .select('id')
    if (error) throw error
    // An update RLS filters out returns no error and no row; that is a failure,
    // not "Owner set".
    if (!updated?.length) return notChanged(res, 'The owner was not recorded: the registry row could not be updated for this tenant.')

    const auditRecorded = await writeAudit(client, req.user!.id, key.id, 'owner_assigned', `Owner of "${key.label}" set to ${owner}`, { owner: key.owner }, { owner })
    invalidate(req.user!.id)
    res.json({ data: { auditRecorded, keyId: key.id, owner, registryId } })
  } catch (error) {
    console.error('[qkms] assign owner failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: error instanceof Error ? error.message : 'Failed to assign owner' } })
  }
})

/** POST /keys/:id/revoke */
router.post('/keys/:id/revoke', async (req: AuthedRequest, res: Response) => {
  try {
    const reason = str(req.body?.reason) || 'Revoked from the QKMS console'
    const resolved = await resolveKey(req, req.params.id)
    if (!resolved) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Key not found in this tenant' } })
    const { key } = resolved
    if (!key.capabilities.revoke) {
      return res.status(409).json({ error: { code: 'NOT_PERMITTED', message: key.capabilities.reason } })
    }

    const client = createAuthClient(req.token!)
    if (!client) throw new Error('Database connection failed')
    const revokedAt = new Date().toISOString()

    /* Every write is checked. These results used to be discarded, so a revoke
       RLS refused still answered "Key marked revoked". */
    let changed = 0
    for (const record of key.records.filter((row) => row.writable)) {
      const result = record.table === 'generated_keys'
        ? await client.from('generated_keys')
          .update({ status: 'revoked', revoked_at: revokedAt })
          .eq('id', record.recordId).eq('user_id', req.user!.id).select('id')
        : record.table === 'qkms_keys'
          ? await client.from('qkms_keys')
            .update({ status: 'revoked', updated_at: revokedAt })
            .eq('id', record.recordId).eq('tenant_id', req.user!.id).eq('user_id', req.user!.id).select('id')
          : null
      if (!result) continue
      if (result.error) throw result.error
      changed += result.data?.length || 0
    }
    if (!changed) return notChanged(res, 'The key was not revoked: none of its records could be updated for this tenant.')

    const auditRecorded = await writeAudit(client, req.user!.id, key.id, 'key_revoked', `${key.label} revoked: ${reason}`, { status: key.lifecycle }, { status: 'revoked', revokedAt })
    invalidate(req.user!.id)
    res.json({ data: { auditRecorded, keyId: key.id, status: 'revoked', revokedAt } })
  } catch (error) {
    console.error('[qkms] revoke failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: error instanceof Error ? error.message : 'Failed to revoke key' } })
  }
})

/** POST /keys/:id/decommission */
router.post('/keys/:id/decommission', async (req: AuthedRequest, res: Response) => {
  try {
    const reason = str(req.body?.reason) || 'Decommissioned from the QKMS console'
    const resolved = await resolveKey(req, req.params.id)
    if (!resolved) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Key not found in this tenant' } })
    const { key } = resolved
    if (!key.capabilities.decommission) {
      return res.status(409).json({ error: { code: 'NOT_PERMITTED', message: key.capabilities.reason } })
    }

    const client = createAuthClient(req.token!)
    if (!client) throw new Error('Database connection failed')
    const at = new Date().toISOString()
    /* Decommission is recorded on the registry row. A key whose only writable
       record is a platform-generated key had none, so this route used to write
       nothing and still answer "decommissioned"; it now creates the row first,
       exactly as owner assignment does. */
    const registryId = await materialiseRegistryRow(client, req.user!.id, key)
    if (!registryId) {
      return res.status(503).json({
        error: { code: 'REGISTRY_UNAVAILABLE', message: 'The QKMS registry table is not available, so the decommission could not be recorded.' },
      })
    }

    let result = await client.from('qkms_keys')
      .update({ status: 'decommissioned', decommissioned_at: at, updated_at: at })
      .eq('id', registryId).eq('tenant_id', req.user!.id).eq('user_id', req.user!.id).select('id')
    if (result.error && isMissingColumn(result.error)) {
      result = await client.from('qkms_keys').update({ status: 'decommissioned', updated_at: at }).eq('id', registryId).eq('tenant_id', req.user!.id).eq('user_id', req.user!.id).select('id')
    }
    if (result.error) throw result.error
    if (!result.data?.length) return notChanged(res, 'The key was not decommissioned: its registry row could not be updated for this tenant.')

    const auditRecorded = await writeAudit(client, req.user!.id, key.id, 'key_decommissioned', `${key.label} decommissioned: ${reason}`, { status: key.lifecycle }, { status: 'decommissioned', at })
    invalidate(req.user!.id)
    res.json({ data: { auditRecorded, keyId: key.id, status: 'decommissioned', decommissionedAt: at } })
  } catch (error) {
    console.error('[qkms] decommission failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: error instanceof Error ? error.message : 'Failed to decommission key' } })
  }
})

/* ---- Rotation work orders ----------------------------------------- */

/**
 * POST /keys/:id/rotation — raise a rotation work order.
 *
 * This does NOT perform the cryptographic rotation. QKMS does not hold the
 * private material of a discovered key and will not pretend otherwise: the work
 * order governs the operation (request → approve → execute → validate) and
 * holds its evidence. Claiming a successful rotation the platform did not
 * perform is exactly the fake functionality the brief forbids.
 */
router.post('/keys/:id/rotation', async (req: AuthedRequest, res: Response) => {
  try {
    if (carriesSecretMaterial(req.body || {})) {
      return res.status(400).json({ error: { code: 'RAW_KEY_REJECTED', message: 'QKMS never accepts raw private keys or plaintext secret material.' } })
    }
    const resolved = await resolveKey(req, req.params.id)
    if (!resolved) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Key not found in this tenant' } })
    const { key } = resolved
    if (!key.capabilities.requestRotation) {
      return res.status(409).json({ error: { code: 'NOT_PERMITTED', message: key.capabilities.reason } })
    }

    const client = createAuthClient(req.token!)
    if (!client) throw new Error('Database connection failed')

    /* The capability above reads the cached model; a second click, or a second
       tab, inside its window would raise a duplicate order. The open-order
       check is repeated against the database itself. */
    const { data: existingJobs, error: existingError } = await client
      .from('qkms_rotation_jobs')
      .select('id, status')
      .eq('tenant_id', req.user!.id).eq('user_id', req.user!.id)
      .eq('key_ref', key.id)
      .limit(50)
    if (existingError && !isMissingTable(existingError) && !isMissingColumn(existingError)) throw existingError
    const open = (existingJobs || []).find((row: Row) => !TERMINAL_JOB_STATUSES.includes(normaliseJobStatus(str(row.status))))
    if (open) {
      return res.status(409).json({
        error: { code: 'ROTATION_ALREADY_OPEN', message: 'A rotation work order is already open for this key. Advance or close it before raising another.', detail: { jobId: `job:${str(open.id)}` } },
      })
    }

    const reason = str(req.body?.reason) || `Rotation required — ${key.risk.recommendedAction}`
    const priority = ['critical', 'high', 'medium', 'low'].includes(str(req.body?.priority))
      ? str(req.body?.priority)
      : key.risk.level === 'critical' ? 'critical' : key.risk.level === 'high' ? 'high' : 'medium'

    const payload: Row = {
      tenant_id: req.user!.id,
      user_id: req.user!.id,
      key_ref: key.id,
      status: 'requested',
      reason,
      requested_by: req.user!.email || req.user!.id,
      previous_version: key.version,
      validation_status: 'not-started',
      evidence_json: {
        priority,
        key_label: key.label,
        algorithm: key.algorithm,
        risk_score: key.risk.score,
        drivers: key.risk.drivers,
        blast_radius: key.blastRadius,
        requested_from: 'qkms-rotation-center',
      },
    }

    let { data, error } = await client.from('qkms_rotation_jobs').insert(payload).select('id, created_at').single()
    if (error && isMissingColumn(error)) {
      delete payload.key_ref
      delete payload.previous_version
      delete payload.validation_status
      ;(payload.evidence_json as Row).key_ref = key.id
      ;({ data, error } = await client.from('qkms_rotation_jobs').insert(payload).select('id, created_at').single())
    }
    if (error) {
      if (error.code === '23505') return notChanged(res, 'A rotation work order is already open for this key.')
      if (isMissingTable(error)) {
        return res.status(503).json({
          error: {
            code: 'ROTATION_UNAVAILABLE',
            message: 'The QKMS rotation table is not available. Apply supabase/qkms-command-center-schema.sql to enable rotation work orders.',
          },
        })
      }
      throw error
    }

    const auditRecorded = await writeAudit(client, req.user!.id, key.id, 'rotation_requested', `Rotation work order raised for ${key.label}: ${reason}`, null, { jobId: data?.id, priority })
    invalidate(req.user!.id)
    res.status(201).json({ data: { auditRecorded, jobId: `job:${data?.id}`, keyId: key.id, status: 'requested', createdAt: data?.created_at } })
  } catch (error) {
    console.error('[qkms] rotation request failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: error instanceof Error ? error.message : 'Failed to raise rotation work order' } })
  }
})

/**
 * POST /rotation-jobs/:id/transition — advance a work order.
 *
 * Transitions are validated against `ROTATION_TRANSITIONS`, so a job cannot
 * jump from `requested` to `completed` and manufacture a rotation that was
 * never executed or validated.
 *
 * The job is read from the database, not from the cached model, and the update
 * is conditional on the status that was read. Two clicks, or two tabs, racing
 * the same transition therefore produce one change and one 409 — never two
 * audit records or two minted versions.
 */
router.post('/rotation-jobs/:id/transition', async (req: AuthedRequest, res: Response) => {
  try {
    if (carriesSecretMaterial(req.body || {})) {
      return res.status(400).json({ error: { code: 'RAW_KEY_REJECTED', message: 'QKMS never accepts raw private keys or plaintext secret material.' } })
    }
    const target = str(req.body?.status) as RotationJobStatus
    if (!Object.prototype.hasOwnProperty.call(ROTATION_TRANSITIONS, target)) {
      return res.status(400).json({ error: { code: 'INVALID_STATUS', message: `Unknown work-order status "${target}".` } })
    }
    const jobId = req.params.id.replace(/^job:/, '')
    if (!UUID_PATTERN.test(jobId)) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Rotation work order not found in this tenant' } })

    const validationDetail = str(req.body?.validationDetail).slice(0, 2000)

    const client = createAuthClient(req.token!)
    if (!client) throw new Error('Database connection failed')

    const fresh = await client.from('qkms_rotation_jobs').select('*').eq('id', jobId).eq('tenant_id', req.user!.id).eq('user_id', req.user!.id).maybeSingle()
    if (fresh.error) {
      if (isMissingTable(fresh.error)) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Rotation work order not found in this tenant' } })
      throw fresh.error
    }
    const row = fresh.data as Row | null
    if (!row) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Rotation work order not found in this tenant' } })

    const rawStatus = str(row.status)
    const current = normaliseJobStatus(rawStatus)
    const allowed = ROTATION_TRANSITIONS[current] || []
    if (!allowed.includes(target)) {
      return res.status(409).json({
        error: {
          code: 'INVALID_TRANSITION',
          message: allowed.length
            ? `A work order in "${current}" can only move to: ${allowed.join(', ')}.`
            : `A work order in "${current}" is terminal and cannot be advanced.`,
        },
      })
    }

    const evidenceJson = (row.evidence_json && typeof row.evidence_json === 'object' ? row.evidence_json : {}) as Row
    const keyRef = str(row.key_ref) || str(evidenceJson.key_ref) || null
    const data = await model(req)
    const key = keyRef ? data.keys.find((entry) => entry.id === keyRef) || null : null
    const keyLabel = key?.label || str(evidenceJson.key_label) || keyRef || 'unresolved key'

    // Re-opening a failed order must not sit beside another open order for the same key.
    if (target === 'requested' && keyRef) {
      const siblings = await client.from('qkms_rotation_jobs').select('id, status').eq('tenant_id', req.user!.id).eq('user_id', req.user!.id).eq('key_ref', keyRef).neq('id', jobId).limit(50)
      if (siblings.error && !isMissingTable(siblings.error) && !isMissingColumn(siblings.error)) throw siblings.error
      const open = (siblings.data || []).find((sibling: Row) => !TERMINAL_JOB_STATUSES.includes(normaliseJobStatus(str(sibling.status))))
      if (open) {
        return res.status(409).json({
          error: { code: 'ROTATION_ALREADY_OPEN', message: 'Another rotation work order is already open for this key.', detail: { jobId: `job:${str(open.id)}` } },
        })
      }
    }

    const at = new Date().toISOString()
    const updates: Row = { status: target }
    if (target === 'requested') {
      // A re-opened order starts over: approval and validation do not carry across.
      Object.assign(updates, { approved_by: null, started_at: null, completed_at: null, failure_reason: null, validation_status: 'not-started', validation_detail: null })
    }
    if (target === 'approved') updates.approved_by = req.user!.email || req.user!.id
    if (target === 'in-progress') updates.started_at = at
    if (target === 'awaiting-validation') updates.validation_status = 'pending'
    if (target === 'completed') {
      updates.completed_at = at
      // An operator note does not prove provider execution or dependent service validation.
      updates.validation_status = 'pending'
      updates.validation_detail = validationDetail || null
    }
    if (target === 'failed') {
      updates.failure_reason = str(req.body?.failureReason).slice(0, 1000) || 'Rotation failed'
      updates.completed_at = at
      updates.validation_status = 'failed'
    }
    if (target === 'cancelled') updates.completed_at = at

    const conditional = (patch: Row) => client.from('qkms_rotation_jobs').update(patch)
      .eq('id', jobId).eq('tenant_id', req.user!.id).eq('user_id', req.user!.id).eq('status', rawStatus).select('id')
    let result = await conditional(updates)
    if (result.error && isMissingColumn(result.error)) {
      const minimal: Row = { status: target }
      if (target === 'completed' || target === 'failed' || target === 'cancelled') minimal.completed_at = at
      if (target === 'in-progress') minimal.started_at = at
      result = await conditional(minimal)
    }
    if (result.error?.code === '23505') return notChanged(res, 'Another rotation work order is already open for this key.')
    if (result.error) throw result.error
    if (!result.data?.length) {
      return res.status(409).json({
        error: { code: 'TRANSITION_CONFLICT', message: 'This work order changed while the request was in flight. The latest state has been reloaded; review it and try again.' },
      })
    }

    const auditRecorded = await writeAudit(client, req.user!.id, keyRef, `rotation_${target.replace(/-/g, '_')}`,
      `Rotation work order for ${keyLabel} moved ${current} → ${target}`,
      { status: current }, { status: target, at, ...(target === 'completed' ? { validationStatus: 'pending' } : {}) })
    invalidate(req.user!.id)
    res.json({ data: { auditRecorded, jobId: `job:${jobId}`, status: target, at, validationStatus: target === 'completed' ? 'pending' : undefined } })
  } catch (error) {
    console.error('[qkms] rotation transition failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: error instanceof Error ? error.message : 'Failed to advance work order' } })
  }
})

/* ---- Policies ------------------------------------------------------ */

router.get('/policies', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req)
    res.json({ data: { policies: data.governance.policies, total: data.governance.policies.length } })
  } catch (error) {
    console.error('[qkms] policies failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: 'Failed to load policies' } })
  }
})

router.post('/policies', async (req: AuthedRequest, res: Response) => {
  try {
    const body = (req.body || {}) as Row
    const name = str(body.name)
    if (!name) return res.status(400).json({ error: { code: 'NAME_REQUIRED', message: 'A policy name is required' } })

    const client = createAuthClient(req.token!)
    if (!client) throw new Error('Database connection failed')

    const toList = (value: unknown): string[] =>
      Array.isArray(value) ? value.map((entry) => str(entry)).filter(Boolean)
        : str(value) ? str(value).split(',').map((entry) => entry.trim()).filter(Boolean) : []

    const payload: Row = {
      tenant_id: req.user!.id,
      user_id: req.user!.id,
      name,
      description: str(body.description) || null,
      allowed_algorithms: toList(body.allowedAlgorithms ?? body.allowed_algorithms),
      blocked_algorithms: toList(body.blockedAlgorithms ?? body.blocked_algorithms),
      max_key_age_days: body.maxKeyAgeDays === null ? null : num(body.maxKeyAgeDays ?? body.max_key_age_days, 365),
      rotation_interval_days: body.rotationIntervalDays === null ? null : num(body.rotationIntervalDays ?? body.rotation_interval_days, 180),
      require_owner: body.requireOwner ?? body.require_owner ?? true,
      require_hsm: Boolean(body.requireHsm ?? body.require_hsm),
      allow_export: Boolean(body.allowExport ?? body.allow_export),
      require_pqc: Boolean(body.requirePqc ?? body.require_pqc),
      environment_scope: str(body.environmentScope ?? body.environment_scope) || 'all',
      severity: str(body.severity) || 'medium',
      enabled: body.enabled !== false,
    }

    let { data, error } = await client.from('qkms_policies').insert(payload).select('id, created_at').single()
    if (error) {
      if (isMissingTable(error)) {
        return res.status(503).json({
          error: { code: 'POLICIES_UNAVAILABLE', message: 'The QKMS policy table is not available. Apply supabase/qkms-command-center-schema.sql.' },
        })
      }
      throw error
    }

    const auditRecorded = await writeAudit(client, req.user!.id, null, 'policy_created', `Policy "${name}" created`, null, payload)
    invalidate(req.user!.id)
    res.status(201).json({ data: { auditRecorded, id: `policy:${data?.id}`, createdAt: data?.created_at } })
  } catch (error) {
    console.error('[qkms] policy create failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: error instanceof Error ? error.message : 'Failed to create policy' } })
  }
})

router.patch('/policies/:id', async (req: AuthedRequest, res: Response) => {
  try {
    const policyId = req.params.id.replace(/^policy:/, '')
    // Baseline policies are platform defaults, not tenant rows; editing one has
    // to create a tenant policy rather than silently mutate the platform's.
    if (policyId.startsWith('baseline-')) {
      return res.status(409).json({
        error: { code: 'BASELINE_IMMUTABLE', message: 'Baseline policies ship with QKMS. Create a tenant policy of the same name to override it.' },
      })
    }

    const client = createAuthClient(req.token!)
    if (!client) throw new Error('Database connection failed')

    const body = (req.body || {}) as Row
    const updates: Row = { updated_at: new Date().toISOString() }
    if ('enabled' in body) updates.enabled = Boolean(body.enabled)
    if ('severity' in body) updates.severity = str(body.severity) || 'medium'
    if ('name' in body && str(body.name)) updates.name = str(body.name)
    if ('description' in body) updates.description = str(body.description) || null
    if ('requireHsm' in body) updates.require_hsm = Boolean(body.requireHsm)
    if ('requireOwner' in body) updates.require_owner = Boolean(body.requireOwner)
    if ('allowExport' in body) updates.allow_export = Boolean(body.allowExport)
    if ('requirePqc' in body) updates.require_pqc = Boolean(body.requirePqc)
    for (const [field, column] of [['rotationIntervalDays', 'rotation_interval_days'], ['maxKeyAgeDays', 'max_key_age_days']]) {
      if (!(field in body)) continue
      const value = body[field]
      if (value !== null && (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0 || value > 36500)) {
        return res.status(400).json({ error: { code: 'INVALID_POLICY', message: `${field} must be null or a whole number of days from 1 to 36500.` } })
      }
      updates[column] = value
    }
    if ('environmentScope' in body) updates.environment_scope = str(body.environmentScope) || 'all'

    if (!UUID_PATTERN.test(policyId)) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Policy not found in this tenant' } })
    const { data: updated, error } = await client.from('qkms_policies').update(updates).eq('id', policyId).eq('tenant_id', req.user!.id).eq('user_id', req.user!.id).select('id')
    if (error) throw error
    if (!updated?.length) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Policy not found in this tenant' } })

    const auditRecorded = await writeAudit(client, req.user!.id, null, 'policy_updated', `Policy ${policyId} updated`, null, updates)
    invalidate(req.user!.id)
    res.json({ data: { auditRecorded, id: `policy:${policyId}`, updated: true } })
  } catch (error) {
    console.error('[qkms] policy update failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: error instanceof Error ? error.message : 'Failed to update policy' } })
  }
})

/* ---- Precheck ------------------------------------------------------ */

/**
 * POST /precheck — re-evaluate the migration gate against fresh data.
 *
 * `force` bypasses the cache because this is an explicit operator action whose
 * whole point is "tell me where I stand right now".
 */
router.post('/precheck', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await model(req, true)
    const client = createAuthClient(req.token!)
    const auditRecorded = client
      ? await writeAudit(client, req.user!.id, null, 'migration_precheck',
        `Migration gate evaluated: ${data.readiness.gate.state}`, null,
        { state: data.readiness.gate.state, score: data.readiness.gate.score, blockers: data.readiness.gate.blockers })
      : false
    if (auditRecorded) invalidate(req.user!.id)
    res.json({ data: data.readiness.gate, auditRecorded })
  } catch (error) {
    console.error('[qkms] precheck failed:', error)
    res.status(500).json({ error: { code: 'QKMS_ERROR', message: error instanceof Error ? error.message : 'Failed to evaluate the migration gate' } })
  }
})

/* ---- View payloads (must stay LAST: `/:mode` is a wildcard) -------- */

router.get('/:mode', async (req: AuthedRequest, res: Response) => {
  try {
    const mode = str(req.params.mode) as QkmsMode
    if (!QKMS_MODES.includes(mode)) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'QKMS view not found' } })
    }
    const data = await model(req, str(req.query.refresh) === '1')
    res.json({ data: projectView(data, mode) })
  } catch (error) {
    console.error('[qkms] view failed:', error)
    res.status(500).json({
      error: { code: 'QKMS_ERROR', message: error instanceof Error ? error.message : 'Failed to compute QKMS intelligence' },
    })
  }
})

export default router
export { buildModel as buildQkmsModel, invalidate as invalidateQkmsModel, projectView as projectQkmsView }
