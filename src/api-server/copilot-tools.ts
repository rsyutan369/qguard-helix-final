// Sophia — MCP-style typed tool layer.
//
// The copilot NEVER queries the database ad-hoc and NEVER receives raw SQL.
// Every data access goes through a strongly-typed tool in this registry:
//   • reads reuse the platform's shared per-tenant cached builders
//     (buildSnapshot / buildScannerIntelligence / buildExposureIntelligence /
//     remediation + certification engines / HNDL / workflow / snapshots), or
//     RLS-scoped table queries that ALWAYS apply .eq('user_id', ctx.userId)
//     (defense-in-depth on top of RLS — provable tenant isolation);
//   • operate-class tools (remediation approval, snapshots, rollback) are
//     HUMAN-IN-THE-LOOP: they run RBAC + real preflight checks, write an audit
//     entry, and hand back a deep link into the owning module — mutation
//     authority stays with the module and its existing validation/rollback
//     safeguards. Sophia never mutates production state autonomously.
//
// Builders are injectable (CopilotBuilders) so tools/copilot-check.ts can
// exercise RBAC + tenant scoping offline with a mock client.

import {
  buildSnapshot,
  isInternetFacing,
} from './quantum-readiness'
import { buildScannerIntelligence } from './scanner'
import { buildExposureIntelligence } from './exposure-graph'
import { assembleEvidence, buildRemediationPlan } from './quantum-remediation'
import { buildCertificationDashboard } from './quantum-certification'
import { buildHndlIntelligence } from './harvest-now'
import { buildWorkflowState } from './migration-workflow'
import { buildSnapshotDashboard } from './migration-snapshots'
import { buildAdjacency, computeBlastRadius } from '@/lib/exposure-graph-intel'
import { ROLE_CAPABILITIES, STANDARDS, algorithmFamily, algorithmFamilyLabel, involvesAlgorithmFamily, modulePath, moduleLabel } from './copilot-knowledge'
import type { AlgorithmFamily } from './copilot-knowledge'
import { namesCryptography } from '@/lib/scanner/finding-identity'
import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'
import { buildAssetRegister, type AssetRegisterRow, type RegisterQrInput, type RegisterSnapshotInput } from '@/lib/assets/asset-register'
import type { CopilotEvidence, CopilotRole, CopilotToolRun, CopilotToolStatus } from '@/types/copilot'
import type { ExposureIntelligence } from '@/types/exposure-graph'
import type { RemediationAction, RemediationPlan } from '@/types/quantum-remediation'
import type { CertificationDashboard } from '@/types/quantum-certification'
import type { MigrationWorkflowState } from '@/types/migration-workflow'
import type { SnapshotDashboard } from '@/types/migration-snapshot'

/* ------------------------------------------------------------------ */
/* Context + result contracts                                          */
/* ------------------------------------------------------------------ */

export interface ToolContext {
  token: string
  userId: string
  email: string
  role: CopilotRole
  tier: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  client: any
}

export interface ToolResult {
  status: CopilotToolStatus
  rows?: number
  data: Record<string, unknown>
  evidence: CopilotEvidence[]
  note?: string
}

export type ToolCapability = 'read' | 'operate' | 'executive' | 'audit'

export interface ToolDef {
  name: string
  module: string
  description: string
  capability: ToolCapability
  execute(ctx: ToolContext, args: Record<string, unknown>, deps: CopilotBuilders): Promise<ToolResult>
}

/*
 * The builders' REAL output types. They were previously erased to
 * `Record<string, unknown>`, which let every tool read a field by a guessed
 * name and compile cleanly when the guess was wrong. Five shipped defects were
 * exactly that: `eligibility.criteria` (the field is `checks`), `c.label` (it is
 * `criterion`), `nextAction.label/path` (they are `title/route`),
 * `banner.level/message` (they are `threatLevel/headline`) and a remediation
 * status of 'completed' (the engine emits open | in_progress | resolved). With
 * the types in place a wrong field is a compile error, not a silent blank.
 */
export type QrSnapshot = Awaited<ReturnType<typeof buildSnapshot>>
export type ScannerIntelSnapshot = Awaited<ReturnType<typeof buildScannerIntelligence>>
export type HndlIntelligence = Awaited<ReturnType<typeof buildHndlIntelligence>>

/** Injectable builder seam — production uses the live platform builders. */
export interface CopilotBuilders {
  snapshot(token: string, userId: string): Promise<QrSnapshot>
  scannerIntel(token: string, userId: string): Promise<ScannerIntelSnapshot>
  exposure(token: string, userId: string): Promise<ExposureIntelligence>
  remediationPlan(token: string, userId: string): Promise<RemediationPlan>
  certification(token: string, userId: string, email: string): Promise<CertificationDashboard>
  hndl(token: string, userId: string): Promise<HndlIntelligence>
  workflow(token: string, userId: string): Promise<MigrationWorkflowState>
  snapshotDashboard(token: string, userId: string, email: string): Promise<SnapshotDashboard>
}

export const liveBuilders: CopilotBuilders = {
  snapshot: (token, userId) => buildSnapshot(token, userId),
  scannerIntel: (token, userId) => buildScannerIntelligence(token, userId),
  exposure: (token, userId) => buildExposureIntelligence(token, userId),
  remediationPlan: async (token, userId) => buildRemediationPlan(await assembleEvidence(token, userId)),
  certification: (token, userId, email) => buildCertificationDashboard(token, userId, email),
  hndl: (token, userId) => buildHndlIntelligence(token, userId),
  workflow: (token, userId) => buildWorkflowState(token, userId),
  snapshotDashboard: (token, userId, email) => buildSnapshotDashboard(token, userId, email),
}

/* ------------------------------------------------------------------ */
/* Tenant-scoped access helpers                                        */
/* ------------------------------------------------------------------ */

function str(v: unknown): string { return typeof v === 'string' ? v : v == null ? '' : String(v) }
function num(v: unknown): number { const n = Number(v); return Number.isFinite(n) ? n : 0 }
function rec(v: unknown): Record<string, unknown> { return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {} }
function arr(v: unknown): unknown[] { return Array.isArray(v) ? v : [] }

/**
 * The ONLY direct table read path for copilot tools. Every query is pinned to
 * the authenticated tenant with an explicit .eq('user_id', ctx.userId) on top
 * of the RLS client — verified offline by tools/copilot-check.ts.
 */
/**
 * A table that does not exist in this deployment is a legitimate "no data"
 * answer — the platform ships optional subsystems. ANY other query error is a
 * bug, and must never be reported as an empty result.
 *
 * This distinction cost a real defect: `findAssetsUsingAlgorithm` selected an
 * `updated_at` column that `crypto_inventory` does not have (it has
 * `discovered_at`). PostgREST answered 42703 "column does not exist", the
 * blanket `if (error) return []` turned that into zero rows, and Sophia
 * confidently told the user "RSA: 0 cryptographic component(s)" on an estate
 * whose CBOM was full of TLS_RSA cipher suites. A silent empty is
 * indistinguishable from a true zero, which is the worst possible failure mode
 * for a tool whose entire job is reporting what the tenant actually has.
 */
function isMissingRelation(error: unknown): boolean {
  const err = error as { code?: string; message?: string } | null
  const code = String(err?.code || '')
  const message = String(err?.message || '')
  if (code === '42P01') return true
  return /relation .* does not exist|could not find the table|schema cache/i.test(message)
}

export async function tenantRows(
  ctx: ToolContext,
  table: string,
  select: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  apply?: (q: any) => any,
  limit = 200,
): Promise<Record<string, unknown>[]> {
  let query = ctx.client.from(table).select(select).eq('user_id', ctx.userId)
  if (apply) query = apply(query)
  const { data, error } = await query.limit(limit)
  if (error) {
    // Missing subsystem → honest empty. Anything else → surface it; runTool
    // turns a throw into an `error` status the answer reports as a failed
    // source rather than as a zero.
    if (isMissingRelation(error)) return []
    const err = error as { code?: string; message?: string }
    throw new Error(`${table} query failed${err?.code ? ` [${err.code}]` : ''}: ${String(err?.message || error).slice(0, 160)}`)
  }
  return (data as Record<string, unknown>[]) || []
}

async function tenantCount(
  ctx: ToolContext,
  table: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  apply?: (q: any) => any,
): Promise<number | null> {
  try {
    let query = ctx.client.from(table).select('id', { count: 'exact', head: true }).eq('user_id', ctx.userId)
    if (apply) query = apply(query)
    const { count, error } = await query
    if (error) return null
    return typeof count === 'number' ? count : null
  } catch {
    return null
  }
}

function ev(module: string, label: string, value: string, extra: Partial<CopilotEvidence> = {}): CopilotEvidence {
  return { module, label, value, deepLink: extra.deepLink ?? modulePath(moduleIdForLabel(module)), ...extra }
}

function moduleIdForLabel(moduleLabelOrId: string): string {
  return moduleLabelOrId.toLowerCase().replace(/[^a-z0-9]+/g, '_')
}

function ok(data: Record<string, unknown>, evidence: CopilotEvidence[], rows?: number, note?: string): ToolResult {
  return { status: rows === 0 ? 'empty' : 'ok', rows, data, evidence, note }
}

function empty(data: Record<string, unknown>, note: string): ToolResult {
  return { status: 'empty', rows: 0, data, evidence: [], note }
}

/** Audit hook — installed by the gateway so tool activity is centrally logged. */
let auditSink: ((entry: { userId: string; action: string; detail: Record<string, unknown> }) => void) | null = null
export function setToolAuditSink(sink: typeof auditSink) { auditSink = sink }
function audit(ctx: ToolContext, action: string, detail: Record<string, unknown>) {
  try { auditSink?.({ userId: ctx.userId, action, detail }) } catch { /* audit must never break the answer */ }
}

/** Human-in-the-loop action preparation (operate-class tools). */
function preparedAction(input: {
  action: string
  module: string
  deepLink: string
  summary: string
  preflight: Record<string, unknown>
  evidence: CopilotEvidence[]
}): ToolResult {
  return {
    status: 'ok',
    rows: 1,
    data: {
      prepared: true,
      action: input.action,
      executionModel: 'human-in-the-loop',
      summary: input.summary,
      deepLink: input.deepLink,
      preflight: input.preflight,
    },
    evidence: input.evidence,
    note: `${input.action} prepared — confirm in the owning module (${input.deepLink}); Sophia never executes state changes autonomously.`,
  }
}

/* ------------------------------------------------------------------ */
/* Tool registry                                                       */
/* ------------------------------------------------------------------ */

const ASSET_SELECT = 'id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at'

/*
 * `crypto_inventory` stores BOTH real cryptographic observations and scanner
 * FINDINGS, because the scan writer sets `algorithm: finding.algorithm` for
 * every rule it fires — so a policy finding lands with algorithm "No
 * Certificate Pinning" or "Regulatory Compliance Gap". Counting those as
 * cryptographic components inflates the component total and pollutes the
 * algorithm distribution. The platform already has the separator for this (the
 * same guard the migration snapshots use), so every tool uses it rather than
 * inventing a second rule.
 */
function isCryptographicRow(row: Record<string, unknown>): boolean {
  const name = str(row.name)
  // The scanner writes `${category}: ${algorithm}`; a real cryptographic
  // observation carries a cryptographic class prefix.
  if (name && !namesCryptography(name)) return false
  const anatomy = analyzeCryptoObservation({
    algorithm: str(row.algorithm),
    name,
    itemType: str(row.item_type),
    protocol: str(row.protocol),
  })
  return anatomy.kind !== 'policy'
}

function mapAsset(a: Record<string, unknown>) {
  return {
    id: str(a.id),
    name: str(a.name),
    type: str(a.type),
    environment: str(a.environment),
    region: str(a.region),
    owner: str(a.service_owner),
    criticality: str(a.criticality) || 'medium',
    status: str(a.status),
    internetFacing: isInternetFacing(a),
    updatedAt: str(a.updated_at),
  }
}

export const TOOL_REGISTRY: Record<string, ToolDef> = {}

function register(def: ToolDef) {
  TOOL_REGISTRY[def.name] = def
}

/* ---- Assets ------------------------------------------------------- */

register({
  name: 'getAssets',
  module: 'assets',
  description: 'List the tenant asset inventory with crypto-relevant attributes',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'assets', ASSET_SELECT, (q) => q.order('updated_at', { ascending: false }), 400)
    const total = (await tenantCount(ctx, 'assets')) ?? rows.length
    const assets = rows.map(mapAsset)
    const internetFacing = assets.filter((a) => a.internetFacing).length
    const byCriticality: Record<string, number> = {}
    for (const a of assets) byCriticality[a.criticality] = (byCriticality[a.criticality] || 0) + 1
    return ok(
      { total, sample: assets.slice(0, 50), internetFacing, byCriticality },
      [ev('Assets & CBOM', 'Assets in inventory', String(total), { deepLink: modulePath('assets') })],
      total,
    )
  },
})

register({
  name: 'getAssetById',
  module: 'assets',
  description: 'Fetch one asset (by id or name) with its crypto inventory and certificates',
  capability: 'read',
  async execute(ctx, args) {
    const ref = str(args.assetId || args.name || args.query)
    if (!ref) return empty({}, 'No asset reference provided')
    const rows = await tenantRows(ctx, 'assets', ASSET_SELECT, (q) => q.or(`id.eq.${ref.replace(/[,()]/g, '')},name.ilike.%${ref.replace(/[,%()]/g, '')}%`), 5)
    const asset = rows[0]
    if (!asset) return empty({ ref }, `Asset "${ref}" not found in this tenant`)
    const assetId = str(asset.id)
    const [inventory, certs] = await Promise.all([
      tenantRows(ctx, 'crypto_inventory', 'algorithm, item_type, protocol, is_vulnerable, is_quantum_safe', (q) => q.eq('asset_id', assetId), 100),
      tenantRows(ctx, 'certificates', 'name, algorithm, issuer, not_after, is_quantum_safe', (q) => q.eq('asset_id', assetId), 50),
    ])
    return ok(
      { asset: mapAsset(asset), cryptoInventory: inventory, certificates: certs },
      [ev('Assets & CBOM', 'Asset located', str(asset.name), { detail: `${inventory.length} crypto component(s), ${certs.length} certificate(s)`, deepLink: modulePath('assets') })],
      1,
    )
  },
})

register({
  name: 'searchAssets',
  module: 'assets',
  description: 'Search assets by name/type/environment; supports internet-facing filter',
  capability: 'read',
  async execute(ctx, args) {
    // args.query is a pre-extracted entity filter (extractAssetFilter) — never
    // the raw question. Tokens are OR-matched across name/type/environment so
    // "production server" finds environment=production OR type=server.
    const tokens = str(args.query).replace(/[,%()]/g, '').slice(0, 80).split(/\s+/).filter(Boolean).slice(0, 3)
    // Algorithms are resolved by findAssetsUsingAlgorithm against the crypto
    // inventory — they are NOT asset names and must never reach this ILIKE.

    const rows = await tenantRows(ctx, 'assets', ASSET_SELECT, (query) => {
      let built = query.order('updated_at', { ascending: false })
      if (tokens.length) {
        built = built.or(tokens.flatMap((t) => [`name.ilike.%${t}%`, `type.ilike.%${t}%`, `environment.ilike.%${t}%`]).join(','))
      }
      return built
    }, 200)
    let assets = rows.map(mapAsset)
    if (args.internetFacing === true) assets = assets.filter((a) => a.internetFacing)
    if (str(args.criticality)) assets = assets.filter((a) => a.criticality === str(args.criticality))
    const q = tokens.join(' ')
    const filtered = Boolean(tokens.length || args.internetFacing === true || str(args.criticality))
    return ok(
      { matches: assets.slice(0, 50), matched: assets.length, query: q, filtered },
      [ev('Assets & CBOM', 'Matching assets', String(assets.length), { detail: filtered ? `filter "${[q, args.internetFacing === true ? 'internet-facing' : '', str(args.criticality)].filter(Boolean).join(' + ')}"` : 'full inventory scan', deepLink: modulePath('assets') })],
      assets.length,
    )
  },
})

/** One register row, flattened for answers — every field is the Assets page's own. */
export interface AssetView {
  id: string
  name: string
  type: string
  host: string
  owner: string | null
  environment: string | null
  criticality: string | null
  internetFacing: boolean
  tlsVersion: string | null
  riskScore: number | null
  riskBand: string
  pqcStatus: AssetRegisterRow['pqcStatus']
  pqcStatusLabel: string
  pqcStatusReason: string
  components: AssetRegisterRow['components']
  worstSeverity: string | null
  algorithms: string[]
  vulnerableComponents: Array<{ name: string; riskBearing: string; severity: string; pqcReplacement: string | null; instances: number }>
  lastScanned: string | null
  freshness: string
  freshnessState: AssetRegisterRow['freshness']['state']
  lifecycle: AssetRegisterRow['lifecycle']
  scanning: boolean
}

function toAssetView(r: AssetRegisterRow): AssetView {
  return {
    id: r.id,
    name: r.name,
    type: r.typeLabel,
    host: r.host,
    owner: r.owner,
    environment: r.environment,
    criticality: r.criticality,
    internetFacing: r.internetFacing,
    tlsVersion: r.tlsVersion,
    riskScore: r.riskScore,
    riskBand: r.risk.label,
    pqcStatus: r.pqcStatus,
    pqcStatusLabel: r.pqcStatusLabel,
    pqcStatusReason: r.pqcStatusReason,
    components: r.components,
    worstSeverity: r.worstComponentSeverity,
    algorithms: r.algorithms.slice(0, 10),
    vulnerableComponents: r.componentList
      .filter((c) => c.posture === 'vulnerable')
      .slice(0, 10)
      .map((c) => ({ name: c.name, riskBearing: c.riskBearing, severity: String(c.severity), pqcReplacement: c.pqcReplacement, instances: c.instances })),
    lastScanned: r.lastScanned,
    freshness: r.freshness.label,
    freshnessState: r.freshness.state,
    lifecycle: r.lifecycle,
    scanning: r.scanning.active,
  }
}

const NAME_NOISE = /[^a-z0-9]+/g

/**
 * Link the words of a question to the tenant's REAL assets. A token only
 * becomes an asset reference when an asset in the register actually carries
 * that name or host — which is what stops question words ("pending",
 * "remediation") from ever being treated as asset filters.
 */
export function linkAssetMentions(rows: AssetRegisterRow[], question: string, mentions: string[]): AssetRegisterRow[] {
  const q = ` ${question.toLowerCase().replace(NAME_NOISE, ' ')} `
  const scored: Array<{ row: AssetRegisterRow; score: number }> = []
  for (const row of rows) {
    const name = row.name.toLowerCase()
    const flatName = name.replace(NAME_NOISE, ' ').trim()
    const host = (row.host || '').toLowerCase()
    let score = 0
    // The full asset name appears in the question ("status of orders-db").
    if (flatName.length >= 3 && q.includes(` ${flatName} `)) score = 100 + flatName.length
    for (const raw of mentions) {
      const m = raw.toLowerCase()
      if (m.length < 3) continue
      if (m === name || m === host) score = Math.max(score, 90 + m.length)
      else if (m.length >= 4 && (name.includes(m) || (host !== '' && host.includes(m)))) score = Math.max(score, 40 + m.length)
    }
    if (score > 0) scored.push({ row, score })
  }
  if (!scored.length) return []
  scored.sort((a, b) => b.score - a.score)
  // Keep only the best-scoring tier so "orders-db" never drags in every "*-db".
  const best = scored[0].score
  return scored.filter((s) => s.score >= best - 10).slice(0, 5).map((s) => s.row)
}

register({
  name: 'getAssetRegister',
  module: 'assets',
  description: 'The Assets page register — per-asset PQC status, risk, components, owner, exposure, freshness and lifecycle; resolves named assets',
  capability: 'read',
  async execute(ctx, args, deps) {
    /*
     * The exact derivation /dashboard/assets renders: `buildAssetRegister` over
     * the scanner-intelligence snapshot, the QR figures and the workflow asset
     * states. Sophia's statement about an asset is the Assets page's row for
     * it, by construction — not a second estimate that "should" agree.
     */
    const [intel, snapshot, workflow] = await Promise.all([
      deps.scannerIntel(ctx.token, ctx.userId),
      deps.snapshot(ctx.token, ctx.userId).catch(() => null),
      deps.workflow(ctx.token, ctx.userId).catch(() => null),
    ])
    const intelRec = rec(intel)
    if (!intelRec.summary || !Array.isArray(rec(intelRec.assets).assets)) {
      return empty({ rows: [], matched: [] }, 'The asset register has no scanner evidence yet — run a discovery scan.')
    }
    const has = Boolean(snapshot?.hasData)
    const qr: RegisterQrInput = {
      resolved: snapshot != null,
      hasData: has,
      readiness: has && snapshot ? snapshot.scores.quantumReadiness : null,
      readinessLevel: has && snapshot ? snapshot.scores.quantumReadinessLevel : null,
      risk: has && snapshot ? snapshot.scores.quantumRisk : null,
      components: has && snapshot ? snapshot.inventory.cryptoComponents : null,
      vulnerableComponents: has && snapshot ? snapshot.inventory.vulnerableComponents : null,
    }
    const register = buildAssetRegister({
      snapshot: intel as unknown as RegisterSnapshotInput,
      qr,
      workflowStates: workflow?.assetStates ?? null,
      now: Date.now(),
    })
    const mentions = Array.isArray(args.mentions) ? (args.mentions as unknown[]).map(String) : []
    const direct = str(args.asset || args.assetId)
    const matched = linkAssetMentions(register.rows, str(args.question), direct ? [direct, ...mentions] : mentions)
    const byRisk = [...register.rows].sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1))
    const totals = register.totals
    return ok(
      {
        rows: byRisk.slice(0, 60).map(toAssetView),
        matched: matched.map(toAssetView),
        totalAssets: register.headline.totalAssets,
        pqcStatus: totals.pqcStatus,
        internetFacing: totals.internetFacing,
        owners: totals.owners,
        freshness: totals.freshness,
        risk: totals.risk,
        components: totals.components,
        vulnerableAssets: register.headline.vulnerableAssets,
        unattributed: register.unattributed,
        measuredAt: register.measuredAt,
        activeScans: register.activeScans,
      },
      [ev('Assets & CBOM', 'Asset register', `${register.headline.totalAssets} asset(s)`, {
        detail: `${totals.pqcStatus['quantum-vulnerable']} quantum-vulnerable · ${totals.pqcStatus['pqc-ready']} PQC-ready · ${totals.pqcStatus['not-measured']} not measured · ${totals.internetFacing} internet-facing`,
        observedAt: register.measuredAt || undefined,
        deepLink: modulePath('assets'),
      })],
      register.rows.length,
    )
  },
})

register({
  name: 'findAssetsUsingAlgorithm',
  module: 'cbom',
  description: 'Resolve an algorithm family (RSA, ECDSA, SHA-1, 3DES, ML-KEM…) to the assets actually using it, with owner, criticality and exposure',
  capability: 'read',
  async execute(ctx, args) {
    /*
     * The question "which systems use RSA and who owns them?" is a JOIN, not a
     * name search. It was previously answered by an ILIKE over assets.name,
     * which can only match an asset literally CALLED "rsa" — so the answer was
     * always "no assets match that filter" no matter how much RSA the tenant
     * ran. Algorithms live in the cryptographic inventory and on certificates;
     * this tool reads them there and joins back to the owning asset.
     *
     * Classification uses the platform-canonical `algorithmFamily()`, so a row
     * Sophia calls RSA is the same row CBOM, Governance and the QR Engine call
     * RSA. Matching is by FAMILY, never by substring: a naive '%dsa%' matches
     * ECDSA and ML-DSA too, which would report post-quantum components as
     * classical DSA.
     */
    const families = (Array.isArray(args.algorithms) ? args.algorithms : [])
      .map((f) => String(f))
      .filter(Boolean) as AlgorithmFamily[]
    if (!families.length) {
      return ok({ families: [], assets: [], components: 0 }, [], 0, 'No algorithm was named in the question.')
    }
    const wanted = new Set<string>(families)

    const [inventory, certs, assets] = await Promise.all([
      // `crypto_inventory` has discovered_at/created_at — there is NO updated_at.
      tenantRows(ctx, 'crypto_inventory', 'id, asset_id, name, item_type, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, discovered_at, created_at', (q) => q, 2000),
      tenantRows(ctx, 'certificates', 'id, asset_id, name, algorithm, key_size, issuer, not_after, updated_at, created_at', (q) => q, 800),
      tenantRows(ctx, 'assets', ASSET_SELECT, (q) => q, 800),
    ])

    const assetById = new Map(assets.map((a) => [str(a.id), a]))

    /*
     * Whether a row INVOLVES a wanted family — not what its single canonical
     * family is. `algorithmFamily()` answers the latter, and for matching it
     * misses the forms a real certificate scan emits: `sha256WithRSAEncryption`
     * classifies as `unknown`, and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
     * classifies as `sha2` — so an estate full of RSA certificates reported
     * ZERO RSA components. Both the algorithm field and the scanner's
     * class-prefixed name are tested.
     */
    const matchedFamily = (row: Record<string, unknown>): AlgorithmFamily | null => {
      const haystack = `${str(row.algorithm)} ${str(row.name)} ${str(row.protocol)}`
      for (const family of families) {
        if (involvesAlgorithmFamily(haystack, family)) return family
      }
      return null
    }

    interface Hit { family: AlgorithmFamily; label: string; kind: 'component' | 'certificate'; assetId: string; detail: string; keySize: number }
    const hits: Hit[] = []
    // Newest observation across the rows actually read — this is what makes the
    // answer able to state how fresh its evidence is.
    let observedAtMs = 0
    const noteObserved = (row: Record<string, unknown>) => {
      // Field names differ per table: crypto_inventory records discovered_at,
      // certificates record updated_at. Try all, use whichever exists.
      for (const field of ['updated_at', 'discovered_at', 'created_at']) {
        const ms = new Date(str(row[field])).getTime()
        if (Number.isFinite(ms) && ms > observedAtMs) observedAtMs = ms
      }
    }
    let policyRowsSkipped = 0
    for (const row of inventory) {
      if (!isCryptographicRow(row)) { policyRowsSkipped += 1; continue }
      const family = matchedFamily(row)
      if (!family) continue
      noteObserved(row)
      hits.push({ family, label: str(row.algorithm) || str(row.name) || algorithmFamilyLabel(family), kind: 'component', assetId: str(row.asset_id), detail: str(row.item_type) || 'component', keySize: num(row.key_size) })
    }
    for (const row of certs) {
      const family = matchedFamily(row)
      if (!family) continue
      noteObserved(row)
      hits.push({ family, label: str(row.algorithm) || algorithmFamilyLabel(family), kind: 'certificate', assetId: str(row.asset_id), detail: `certificate${str(row.issuer) ? ` issued by ${str(row.issuer)}` : ''}`, keySize: num(row.key_size) })
    }

    // Group by owning asset. Components whose asset_id does not resolve are
    // reported as unattributed rather than silently dropped or attached to an
    // arbitrary asset — the count must reconcile with the CBOM total.
    const grouped = new Map<string, { asset: ReturnType<typeof mapAsset>; components: number; certificates: number; algorithms: Set<string> }>()
    let unattributed = 0
    for (const hit of hits) {
      const raw = hit.assetId ? assetById.get(hit.assetId) : undefined
      if (!raw) { unattributed += 1; continue }
      const key = str(raw.id)
      const entry = grouped.get(key) || { asset: mapAsset(raw), components: 0, certificates: 0, algorithms: new Set<string>() }
      if (hit.kind === 'certificate') entry.certificates += 1
      else entry.components += 1
      entry.algorithms.add(hit.label)
      grouped.set(key, entry)
    }

    let rows = [...grouped.values()].map((entry) => ({
      assetId: entry.asset.id,
      name: entry.asset.name,
      type: entry.asset.type,
      environment: entry.asset.environment,
      owner: entry.asset.owner || null,
      criticality: entry.asset.criticality,
      internetFacing: entry.asset.internetFacing,
      components: entry.components,
      certificates: entry.certificates,
      algorithms: [...entry.algorithms].slice(0, 6),
    }))

    // Scope filters are applied AFTER attribution so the answer can state both
    // "N assets overall" and "M of them internet-facing".
    const totalAssets = rows.length
    if (args.internetFacing === true) rows = rows.filter((r) => r.internetFacing)
    if (str(args.criticality)) rows = rows.filter((r) => r.criticality === str(args.criticality))
    rows.sort((a, b) => Number(b.internetFacing) - Number(a.internetFacing) || (b.components + b.certificates) - (a.components + a.certificates))

    const withOwner = rows.filter((r) => r.owner).length
    const labels = families.map(algorithmFamilyLabel)
    const scopeNote = args.internetFacing === true ? ' internet-facing' : ''

    return ok(
      {
        families,
        algorithmLabels: labels,
        assets: rows.slice(0, 50),
        matchedAssets: rows.length,
        assetsBeforeScope: totalAssets,
        components: hits.filter((h) => h.kind === 'component').length,
        certificates: hits.filter((h) => h.kind === 'certificate').length,
        unattributed,
        policyRowsSkipped,
        ownersKnown: withOwner,
        ownersUnknown: rows.length - withOwner,
        internetFacing: rows.filter((r) => r.internetFacing).length,
      },
      hits.length
        ? [ev('CBOM Explorer', `${labels.join(', ')} usage`, `${rows.length}${scopeNote} asset(s)`, {
            detail: `${hits.filter((h) => h.kind === 'component').length} component(s), ${hits.filter((h) => h.kind === 'certificate').length} certificate(s)${unattributed ? ` · ${unattributed} not linked to an asset` : ''}`,
            observedAt: observedAtMs ? new Date(observedAtMs).toISOString() : undefined,
            deepLink: modulePath('cbom'),
          })]
        : [ev('CBOM Explorer', `${labels.join(', ')} usage`, 'none found', { detail: `no ${labels.join('/')} component or certificate exists in the current inventory`, deepLink: modulePath('cbom') })],
      hits.length,
      hits.length ? undefined : `No ${labels.join(' or ')} usage is recorded in the cryptographic inventory.`,
    )
  },
})

register({
  name: 'getAssetRelationships',
  module: 'exposure_graph',
  description: 'Asset dependency / trust relationships',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'asset_relationships', '*', (q) => q, 300)
    const byType: Record<string, number> = {}
    for (const r of rows) {
      const t = str(r.relationship_type || r.type) || 'related'
      byType[t] = (byType[t] || 0) + 1
    }
    return ok(
      { total: rows.length, byType },
      [ev('Exposure Graph', 'Trust relationships', String(rows.length), { deepLink: modulePath('exposure_graph') })],
      rows.length,
    )
  },
})

/* ---- Scanner ------------------------------------------------------ */

register({
  name: 'getLatestScans',
  module: 'scanner',
  description: 'Most recent PQC discovery scan sessions',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'pqc_scan_sessions', 'id, status, progress, total_assets, scanned_assets, findings_count, started_at, completed_at, created_at', (q) => q.order('created_at', { ascending: false }), 15)
    const latest = rows[0]
    return ok(
      { sessions: rows, latest },
      latest
        ? [ev('Scanner', 'Latest scan', `${str(latest.status)} — ${num(latest.findings_count)} finding(s)`, { detail: `completed ${str(latest.completed_at) || 'in progress'}`, observedAt: str(latest.completed_at) || str(latest.created_at), deepLink: modulePath('scanner') })]
        : [],
      rows.length,
      rows.length ? undefined : 'No scans have been run yet — run a discovery scan from the PQC Scanner.',
    )
  },
})

register({
  name: 'getFindings',
  module: 'scanner',
  description: 'Scanner intelligence findings with severity distribution',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const intel = await deps.scannerIntel(ctx.token, ctx.userId)
    const findings = arr(intel.findings).slice(0, 30)
    const severity = rec(intel.severityCounts)
    const summary = rec(intel.summary)
    const total = arr(intel.findings).length
    return ok(
      { findings, severityCounts: severity, summary },
      [
        ev('Scanner', 'Findings', String(total), { detail: `critical ${num(severity.critical)} · high ${num(severity.high)} · medium ${num(severity.medium)}`, deepLink: modulePath('scanner') }),
      ],
      total,
    )
  },
})

register({
  name: 'explainFindingOwnership',
  module: 'migration_intelligence',
  description: 'Explain Shared Responsibility ownership for findings — who owns them, whether the customer can fix them, the migration dependency, and the recommended action. Answers "why can\'t I fix this?" style questions.',
  capability: 'read',
  async execute(ctx, args, deps) {
    const snapshot = await deps.snapshot(ctx.token, ctx.userId)
    const sr = rec(snapshot.sharedResponsibility)
    const totals = rec(sr.totals)
    const readiness = rec(sr.readiness)
    const widgets = rec(sr.widgets)
    const matrix = arr(sr.matrix)
    const findings = arr(sr.findings)
    const providerBreakdown = arr(sr.providerBreakdown)

    const readinessScore = (domain: string) => num(rec(readiness[domain]).score)

    // Optional targeted match against the caller's entity filter.
    const query = str(args.query || args.assetId || args.name).toLowerCase()
    const tokens = query.replace(/[,%()]/g, '').split(/\s+/).filter((t) => t.length > 2).slice(0, 4)
    const matchRow = (haystack: string) => (tokens.length ? tokens.some((t) => haystack.toLowerCase().includes(t)) : false)

    const matchedFindings = tokens.length
      ? findings.filter((f) => {
          const rc = rec(f)
          return matchRow(`${str(rc.title)} ${str(rc.asset)} ${str(rc.algorithm)} ${str(rc.ownerType)} ${str(rc.responsibleParty)}`)
        })
      : []

    const explain = matchedFindings.slice(0, 10).map((f) => {
      const rc = rec(f)
      const attribution = rec(rc.attribution)
      const chain = rec(rc.dependencyChain)
      return {
        title: str(rc.title),
        asset: str(rc.asset),
        domain: str(rc.domain),
        owner: str(rc.ownerType),
        responsibleParty: str(rc.responsibleParty),
        customerActionable: str(rc.customerActionable),
        migrationDependency: str(rc.migrationDependencyStatus),
        recommendedAction: str(rc.recommendedAction),
        estimatedCustomerEffort: str(rc.estimatedEffort),
        provider: str(attribution.providerName),
        providerPqRoadmap: str(attribution.pqRoadmapStatus),
        dependencySummary: str(chain.summary),
      }
    })

    const ownershipBreakdown = {
      customer: num(totals.customer),
      provider: num(totals.provider),
      ecosystem: num(totals.ecosystem),
      actionableNow: num(totals.actionable),
      waitingOnDependency: num(totals.waiting),
      migrationBlockers: num(widgets.migrationBlockers),
    }

    const triPartReadiness = {
      overall: readinessScore('overall'),
      customer: readinessScore('customer'),
      provider: readinessScore('provider'),
      ecosystem: readinessScore('ecosystem'),
    }

    const providers = providerBreakdown.slice(0, 8).map((p) => {
      const rc = rec(p)
      return { name: str(rc.name), domain: str(rc.domain), findings: num(rc.count), pqRoadmap: str(rc.pqRoadmapStatus), customerInfluence: str(rc.customerInfluence) }
    })

    // A filter that matched nothing is not a finding about ownership — keep the
    // real split visible rather than publishing "0 matched" as the headline.
    const split = `${ownershipBreakdown.customer} customer · ${ownershipBreakdown.provider} provider · ${ownershipBreakdown.ecosystem} ecosystem`
    const detail = tokens.length && explain.length
      ? `${explain.length} finding(s) matched "${tokens.join(' ')}" · ${split}`
      : split

    return ok(
      { ownershipBreakdown, triPartReadiness, matchedFindings: explain, providers, query: tokens.join(' '), filtered: tokens.length > 0 },
      [
        ev('Migration Intelligence™', 'Ownership classification', String(num(totals.findings)), { detail, deepLink: modulePath('migration_intelligence') }),
      ],
      num(totals.findings),
    )
  },
})

register({
  name: 'getCryptoInventory',
  module: 'cbom',
  description: 'Cryptographic inventory (CBOM source of truth) with posture counts',
  capability: 'read',
  async execute(ctx, _args, deps) {
    /*
     * The headline counts are the CBOM's own — read from the QR snapshot, the
     * figure CBOM Explorer and every dashboard publish. A raw head-count of
     * crypto_inventory also counts the scanner FINDINGS stored in that table,
     * so this tool used to report e.g. 178 "components" beside a CBOM of 77.
     */
    const [snapshot, rows] = await Promise.all([
      deps.snapshot(ctx.token, ctx.userId),
      tenantRows(ctx, 'crypto_inventory', 'id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, created_at', (q) => q.order('created_at', { ascending: false }), 300),
    ])
    const inventory = snapshot.inventory
    const total = num(inventory.cryptoComponents)
    const vulnerable = num(inventory.vulnerableComponents)
    const pqcReady = num(inventory.pqcReadyComponents)
    return ok(
      {
        total,
        vulnerable,
        quantumSafe: pqcReady,
        cryptoComponents: total,
        vulnerableComponents: vulnerable,
        pqcReadyComponents: pqcReady,
        findingRowsExcluded: num(inventory.findingRowsExcluded),
        inventoryRows: num(inventory.cryptoInventoryRows),
        sample: rows.filter(isCryptographicRow).slice(0, 40),
      },
      [ev('CBOM Explorer', 'Crypto components', String(total), { detail: `${vulnerable} quantum-vulnerable · ${pqcReady} PQC-ready`, observedAt: str(snapshot.lastAssessmentAt) || undefined, deepLink: modulePath('cbom') })],
      total,
    )
  },
})

/* ---- CBOM --------------------------------------------------------- */

register({
  name: 'getCBOM',
  module: 'cbom',
  description: 'Cryptographic bill of materials rollup',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const snapshot = await deps.snapshot(ctx.token, ctx.userId)
    const inventory = rec(snapshot.inventory)
    return ok(
      {
        cryptoComponents: num(inventory.cryptoComponents),
        vulnerableComponents: num(inventory.vulnerableComponents),
        pqcReadyComponents: num(inventory.pqcReadyComponents),
        certificates: num(inventory.certificatesAnalyzed),
        keys: num(inventory.keysDiscovered),
        // Provenance: scanner findings share crypto_inventory but are not
        // components. Carried so the answer can explain the difference.
        findingRowsExcluded: num(inventory.findingRowsExcluded),
        inventoryRows: num(inventory.cryptoInventoryRows),
      },
      [ev('CBOM Explorer', 'CBOM components', String(num(inventory.cryptoComponents)), { detail: `${num(inventory.vulnerableComponents)} vulnerable · ${num(inventory.pqcReadyComponents)} PQC-ready`, deepLink: modulePath('cbom') })],
      num(inventory.cryptoComponents),
    )
  },
})

register({
  name: 'getLibraries',
  module: 'cbom',
  description: 'Cryptographic libraries/components grouped from the CBOM',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'crypto_inventory', 'name, item_type, algorithm, is_vulnerable, is_quantum_safe', (q) => q, 500)
    const groups = new Map<string, { name: string; count: number; vulnerable: number }>()
    for (const r of rows) {
      const key = str(r.name) || str(r.item_type) || 'component'
      const g = groups.get(key) || { name: key, count: 0, vulnerable: 0 }
      g.count += 1
      if (r.is_vulnerable === true) g.vulnerable += 1
      groups.set(key, g)
    }
    const libraries = [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 25)
    return ok(
      { libraries },
      [ev('CBOM Explorer', 'Distinct crypto components', String(groups.size), { deepLink: modulePath('cbom') })],
      groups.size,
    )
  },
})

register({
  name: 'getAlgorithms',
  module: 'cbom',
  description: 'Algorithm distribution with quantum-vulnerability classification',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'crypto_inventory', 'algorithm, name, item_type, protocol, is_vulnerable, is_quantum_safe', (q) => q, 800)
    /*
     * Only rows that actually NAME cryptography become algorithms. The scan
     * writer stores `algorithm: finding.algorithm` for every rule it fires, so
     * policy findings land in this column too — which is why this card
     * previously published "NO CERTIFICATE PINNING", "INFORMATION DISCLOSURE"
     * and "REGULATORY COMPLIANCE GAP" as observed cryptographic algorithms.
     * They are findings about the estate, not algorithms in it.
     */
    const groups = new Map<string, { algorithm: string; count: number; vulnerable: number; quantumSafe: number }>()
    let policyRows = 0
    for (const r of rows) {
      const name = str(r.name)
      const isCrypto = (!name || namesCryptography(name))
        && analyzeCryptoObservation({ algorithm: str(r.algorithm), name, itemType: str(r.item_type), protocol: str(r.protocol) }).kind !== 'policy'
      if (!isCrypto) { policyRows += 1; continue }
      const key = (str(r.algorithm) || 'unknown').toUpperCase()
      const g = groups.get(key) || { algorithm: key, count: 0, vulnerable: 0, quantumSafe: 0 }
      g.count += 1
      if (r.is_vulnerable === true) g.vulnerable += 1
      if (r.is_quantum_safe === true) g.quantumSafe += 1
      groups.set(key, g)
    }
    const algorithms = [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 30)
    const vulnerableAlgos = algorithms.filter((a) => a.vulnerable > 0).map((a) => a.algorithm)
    return ok(
      { algorithms, vulnerableAlgorithms: vulnerableAlgos, policyRowsExcluded: policyRows, rowsScanned: rows.length },
      [ev('CBOM Explorer', 'Algorithms observed', String(groups.size), {
        detail: `${vulnerableAlgos.slice(0, 6).join(', ') || 'none vulnerable'}${policyRows ? ` · ${policyRows} finding row(s) excluded — they are findings, not algorithms` : ''}`,
        deepLink: modulePath('cbom'),
      })],
      groups.size,
      groups.size === 0 && policyRows > 0
        ? `No cryptographic algorithm is recorded in the inventory — all ${policyRows} row(s) are scanner findings rather than cryptographic observations.`
        : undefined,
    )
  },
})

/* ---- Exposure Graph ----------------------------------------------- */

register({
  name: 'getExposureGraph',
  module: 'exposure_graph',
  description: 'Quantum Exposure Graph™ summary — postures, trust edges, third parties',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const intel = await deps.exposure(ctx.token, ctx.userId)
    const s = intel.summary
    return ok(
      {
        summary: s,
        waves: intel.migrationOrder.waves.length,
        blockers: intel.migrationOrder.blockers.length,
        blockerList: intel.migrationOrder.blockers.slice(0, 12),
        thirdParty: intel.thirdParty.length,
      },
      [
        ev('Exposure Graph', 'Graph coverage', `${s.totalAssets} asset(s), ${s.trustRelationships} trust edge(s)`, { detail: `${s.quantumVulnerable} quantum-vulnerable · ${s.internetFacingAssets} internet-facing`, observedAt: intel.lastAssessmentAt || undefined, deepLink: modulePath('exposure_graph') }),
      ],
      s.totalAssets,
    )
  },
})

register({
  name: 'getBlastRadius',
  module: 'exposure_graph',
  description: 'Blast radius for an asset (or the riskiest asset when unspecified)',
  capability: 'read',
  async execute(ctx, args, deps) {
    const intel = await deps.exposure(ctx.token, ctx.userId)
    if (!intel.graph.nodes.length) return empty({}, 'No exposure graph data yet — run a discovery scan first.')
    const ref = str(args.asset || args.assetId || args.query).toLowerCase()
    const node = ref
      ? intel.graph.nodes.find((n) => n.id === ref || n.label.toLowerCase().includes(ref))
      : intel.graph.nodes
        .slice()
        .sort((a, b) => num((b as unknown as Record<string, unknown>).riskScore) - num((a as unknown as Record<string, unknown>).riskScore))[0]
    if (!node) return empty({ ref }, `Asset "${ref}" is not in the exposure graph`)
    const adjacency = buildAdjacency(intel.graph.edges)
    const blast = computeBlastRadius(intel.graph.nodes, intel.graph.edges, node.id, 6, adjacency)
    // The blast result carries node ids; answers name assets.
    const labelOf = new Map(intel.graph.nodes.map((n) => [n.id, n.label]))
    const names = (ids: string[]) => ids.map((id) => labelOf.get(id) || id).slice(0, 15)
    return ok(
      {
        asset: node.label,
        riskScore: num((node as unknown as Record<string, unknown>).riskScore),
        blast,
        directNames: names(blast.direct),
        indirectNames: names(blast.indirect),
        trustChainNames: names(blast.trustChain),
      },
      [ev('Exposure Graph', `Blast radius of ${node.label}`, `${blast.totalAffected} affected asset(s)`, { detail: `${blast.direct.length} direct · ${blast.indirect.length} indirect · ${blast.trustChain.length} via trust chains · ${blast.internetFacing} internet-facing`, deepLink: modulePath('exposure_graph') })],
      blast.totalAffected,
    )
  },
})

register({
  name: 'getTrustChains',
  module: 'exposure_graph',
  description: 'Certificate/identity/KMS trust chains across the graph',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const intel = await deps.exposure(ctx.token, ctx.userId)
    const trustClasses = new Set(['certificate-chain', 'mtls', 'identity', 'kms'])
    const trustEdges = intel.graph.edges.filter((e) => trustClasses.has(str((e as unknown as Record<string, unknown>).trustClass)))
    return ok(
      { trustEdges: trustEdges.length, critical: intel.summary.criticalTrustRelationships, certificateChains: intel.summary.certificateChains },
      [ev('Exposure Graph', 'Trust-chain edges', String(trustEdges.length), { detail: `${intel.summary.criticalTrustRelationships} critical`, deepLink: modulePath('exposure_graph') })],
      trustEdges.length,
    )
  },
})

register({
  name: 'getDependencies',
  module: 'exposure_graph',
  description: 'Internal + third-party dependencies of the tenant estate',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const intel = await deps.exposure(ctx.token, ctx.userId)
    return ok(
      { thirdParty: intel.thirdParty.slice(0, 20), trustRelationships: intel.summary.trustRelationships, thirdPartyCount: intel.thirdParty.length },
      [ev('Exposure Graph', 'Third-party dependencies', String(intel.thirdParty.length), { deepLink: modulePath('exposure_graph') })],
      intel.thirdParty.length + intel.summary.trustRelationships,
    )
  },
})

/* ---- Migration ---------------------------------------------------- */

register({
  name: 'getMigrationJobs',
  module: 'live_migration',
  description: 'Migration jobs grouped by status',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'migration_jobs', 'id, asset_id, name, job_type, status, target_algorithm, created_at, updated_at', (q) => q.order('created_at', { ascending: false }), 150)
    const byStatus: Record<string, number> = {}
    for (const r of rows) byStatus[str(r.status) || 'unknown'] = (byStatus[str(r.status) || 'unknown'] || 0) + 1
    const failed = rows.filter((r) => /fail|error|reject/i.test(str(r.status)))
    const active = rows.filter((r) => /queued|running|in_progress|executing|awaiting/i.test(str(r.status)))
    return ok(
      { total: rows.length, byStatus, active: active.slice(0, 20), failed: failed.slice(0, 20) },
      [ev('Live Migration Ops', 'Migration jobs', String(rows.length), { detail: `${active.length} active · ${failed.length} failed`, deepLink: modulePath('live_migration') })],
      rows.length,
    )
  },
})

register({
  name: 'getMigrationStatus',
  module: 'live_migration',
  description: 'Platform-wide migration workflow state (11-stage lifecycle)',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const wf = await deps.workflow(ctx.token, ctx.userId)
    const stages = Array.isArray(wf.stages) ? wf.stages : []
    const current = stages.find((s) => s.id === wf.currentStageId)
    // WorkflowNextAction is { title, detail, route }. Reading label/path (which
    // do not exist) silently dropped the "next migration step" from every answer.
    const next = wf.nextAction
    const nextAction = next ? { label: str(next.title), detail: str(next.detail), path: str(next.route), stageId: str(next.stageId) } : null
    return ok(
      {
        hasData: wf.hasData !== false,
        overallProgressPct: num(wf.overallProgressPct),
        currentStageId: str(wf.currentStageId),
        currentStageLabel: current ? current.label : str(wf.currentStageId),
        certificationReadinessPct: num(wf.certificationReadinessPct),
        certificationEligible: wf.certificationEligible === true,
        nextAction,
        stages: stages.slice(0, 12).map((s) => ({ id: s.id, label: s.label, status: s.status, progressPct: num(s.progressPct), kpi: s.kpi, detail: s.detail, route: s.route })),
        assetLifecycle: (wf.assetLifecycle || []).slice(0, 12),
      },
      [ev('Live Migration Ops', 'Migration progress', `${num(wf.overallProgressPct)}%`, {
        // No observedAt: generatedAt is when the workflow was computed (now).
        detail: `current stage: ${current ? current.label : str(wf.currentStageId) || 'not started'}${nextAction?.label ? ` · next: ${nextAction.label}` : ''}`,
        deepLink: modulePath('live_migration'),
      })],
      stages.length,
    )
  },
})

register({
  name: 'getMigrationTimeline',
  module: 'migration_timeline',
  description: 'Recent migration events and plans',
  capability: 'read',
  async execute(ctx) {
    const [events, plans] = await Promise.all([
      tenantRows(ctx, 'migration_events', '*', (q) => q.order('created_at', { ascending: false }), 50),
      tenantRows(ctx, 'migration_plans', 'id, status, created_at, updated_at', (q) => q.order('created_at', { ascending: false }), 25),
    ])
    return ok(
      { events: events.slice(0, 25), plans: plans.length },
      [ev('Migration Timeline', 'Recent migration events', String(events.length), { detail: `${plans.length} migration plan(s)`, deepLink: modulePath('migration_timeline') })],
      events.length + plans.length,
    )
  },
})

register({
  name: 'simulateMigration',
  module: 'migration_sandbox',
  description: 'Prepare a sandbox migration simulation seeded from real inventory',
  capability: 'read',
  async execute(ctx, args, deps) {
    const snapshot = await deps.snapshot(ctx.token, ctx.userId)
    const inventory = rec(snapshot.inventory)
    const vulnerable = num(inventory.quantumVulnerableAssets)
    const ref = str(args.asset || args.query)
    return preparedAction({
      action: 'simulateMigration',
      module: 'migration_sandbox',
      deepLink: modulePath('migration_sandbox'),
      summary: ref
        ? `Sandbox simulation prepared for "${ref}" — launch it in the Migration Sandbox (isolated, zero production impact).`
        : `Sandbox simulation prepared — ${vulnerable} quantum-vulnerable asset(s) are eligible candidates.`,
      preflight: { eligibleAssets: vulnerable, sandboxIsolated: true, productionImpact: 'none' },
      evidence: [ev('Migration Sandbox', 'Simulation-eligible assets', String(vulnerable), { deepLink: modulePath('migration_sandbox') })],
    })
  },
})

/* ---- Remediation -------------------------------------------------- */

/**
 * One remediation action, flattened to what an answer needs. Read from the
 * engine's typed RemediationAction — the Remediation page renders the same
 * object, so Sophia's row and the page's row cannot disagree.
 */
export interface PendingActionRow {
  id: string
  rank: number
  asset: string
  domain: string
  problem: string
  recommendation: string
  targetState: string
  priority: RemediationAction['priority']
  priorityScore: number
  status: RemediationAction['status']
  effort: string
  effortWeeks: number
  certificationGainPct: number
  projectedReadinessPct: number
  owner: string
  internetFacing: boolean
  quickWin: boolean
  requiresReplacement: boolean
  hndlRelevant: boolean
  standards: string[]
  breakingChangeWarning: string | null
  rollback: string
  route: string
}

function toActionRow(a: RemediationAction): PendingActionRow {
  return {
    id: a.id,
    rank: a.rank,
    asset: a.asset,
    domain: a.domainLabel,
    problem: a.problem,
    recommendation: a.recommendation,
    targetState: a.targetState,
    priority: a.priority,
    priorityScore: a.priorityScore,
    status: a.status,
    effort: a.effort,
    effortWeeks: a.effortWeeks,
    certificationGainPct: a.certificationGainPct,
    projectedReadinessPct: a.projectedReadinessPct,
    owner: a.owner,
    internetFacing: a.internetFacing,
    quickWin: a.quickWin,
    requiresReplacement: a.requiresReplacement,
    hndlRelevant: /harvest/i.test(a.risk) || (a.impact?.hndlReductionPts ?? 0) > 0,
    standards: a.standards || [],
    breakingChangeWarning: a.breakingChangeWarning,
    rollback: a.rollback,
    route: a.integration?.route || modulePath('remediation'),
  }
}

register({
  name: 'getPendingRemediation',
  module: 'remediation',
  description: 'Open remediation actions from the Quantum Remediation Engine™ — the same ranked queue the Remediation page shows',
  capability: 'read',
  async execute(ctx, _args, deps) {
    // The plan is computed on request, so its generatedAt is "now" — the age of
    // the EVIDENCE behind it is the assessment's, read from the same snapshot
    // the plan was assembled from.
    const [plan, snapshot] = await Promise.all([
      deps.remediationPlan(ctx.token, ctx.userId),
      deps.snapshot(ctx.token, ctx.userId).catch(() => null),
    ])
    const evidenceAt = str(snapshot?.lastAssessmentAt) || undefined
    const actions = Array.isArray(plan.actions) ? plan.actions : []
    // The engine's statuses are open | in_progress | resolved. Filtering on
    // 'completed' — a status it never emits — counted resolved work as pending.
    const pending = actions.filter((a) => a.status !== 'resolved')
    // Exact counts over the pending queue. `plan.criticalBlockers` is a display
    // head capped at six ids, so its length is not a count of anything.
    const byPriority: Record<RemediationAction['priority'], number> = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const a of pending) byPriority[a.priority] += 1
    const progress = plan.progress
    const rows = pending.map(toActionRow)
    const quickWins = rows.filter((r) => r.quickWin).length
    return ok(
      {
        hasData: plan.hasData !== false,
        pending: rows.slice(0, 40),
        pendingCount: pending.length,
        openCount: progress ? progress.openActions : rows.filter((r) => r.status === 'open').length,
        inProgressCount: progress ? progress.inProgressActions : rows.filter((r) => r.status === 'in_progress').length,
        resolvedCount: progress ? progress.resolvedActions : 0,
        completionPct: progress ? progress.completionPct : 0,
        byPriority,
        criticalBlockers: byPriority.critical,
        quickWins,
        replacementsRequired: rows.filter((r) => r.requiresReplacement).length,
        certificationReadinessPct: num(plan.certificationReadinessPct),
        certificationEligible: plan.certificationEligible === true,
        estimatedCompletionWeeks: num(plan.estimatedCompletionWeeks),
        parallelWorkstreams: num(plan.parallelWorkstreams) || 1,
        estimatedCertificationDate: plan.estimatedCertificationDate || null,
        totalEffortWeeks: Math.round(rows.reduce((s, r) => s + r.effortWeeks, 0) * 10) / 10,
        ladder: (plan.ladder || []).slice(0, 12),
        generatedAt: plan.generatedAt || null,
      },
      [ev('Quantum Remediation Engine™', 'Pending remediation actions', String(pending.length), {
        detail: `${byPriority.critical} critical · ${byPriority.high} high · ${byPriority.medium} medium · ${byPriority.low} low · ${quickWins} quick win(s)`,
        observedAt: evidenceAt,
        deepLink: modulePath('remediation'),
      })],
      pending.length,
      pending.length ? undefined : plan.hasData === false ? 'No assessment evidence yet — the remediation queue is built from scan evidence.' : 'The remediation queue is empty — no open action remains in the latest evidence.',
    )
  },
})

register({
  name: 'approveRemediation',
  module: 'remediation',
  description: 'Prepare approval of a remediation action (human-in-the-loop)',
  capability: 'operate',
  async execute(ctx, args, deps) {
    const plan = await deps.remediationPlan(ctx.token, ctx.userId)
    const actions = (Array.isArray(plan.actions) ? plan.actions : []).filter((a) => a.status !== 'resolved')
    const ref = str(args.actionId || args.action || args.query).toLowerCase()
    const action = ref
      ? actions.find((a) => matchesAction(a, ref))
      : actions.find((a) => a.priority === 'critical') || actions[0]
    if (!action) return empty({ ref }, 'No matching remediation action found for this tenant')
    const title = actionTitle(action)
    audit(ctx, 'copilot.remediation.approve_prepared', { actionId: action.id, title })
    return preparedAction({
      action: 'approveRemediation',
      module: 'remediation',
      deepLink: modulePath('remediation'),
      summary: `Approval prepared for "${title}" — confirm in the Remediation Center to execute with full validation checkpoints and rollback protection.`,
      preflight: { actionId: action.id, title, priority: action.priority, domain: action.domain },
      evidence: [ev('Quantum Remediation Engine™', 'Action ready for approval', title, { detail: `priority ${action.priority}`, deepLink: modulePath('remediation') })],
    })
  },
})

/** A remediation action has no title field — its identity is asset + fix. */
function actionTitle(a: RemediationAction): string {
  return `${a.asset}: ${a.recommendation}`
}

function matchesAction(a: RemediationAction, ref: string): boolean {
  return a.id.toLowerCase() === ref
    || a.asset.toLowerCase().includes(ref)
    || a.recommendation.toLowerCase().includes(ref)
    || a.problem.toLowerCase().includes(ref)
}

register({
  name: 'rejectRemediation',
  module: 'remediation',
  description: 'Prepare rejection of a remediation action (human-in-the-loop)',
  capability: 'operate',
  async execute(ctx, args, deps) {
    const plan = await deps.remediationPlan(ctx.token, ctx.userId)
    const actions = (Array.isArray(plan.actions) ? plan.actions : []).filter((a) => a.status !== 'resolved')
    const ref = str(args.actionId || args.action || args.query).toLowerCase()
    const action = ref ? actions.find((a) => matchesAction(a, ref)) : null
    if (!action) return empty({ ref }, 'Specify which remediation action to reject (its asset or recommended fix)')
    const title = actionTitle(action)
    audit(ctx, 'copilot.remediation.reject_prepared', { actionId: action.id, title })
    return preparedAction({
      action: 'rejectRemediation',
      module: 'remediation',
      deepLink: modulePath('remediation'),
      summary: `Rejection prepared for "${title}" — confirm in the Remediation Center (the decision is audited).`,
      preflight: { actionId: action.id, title },
      evidence: [ev('Quantum Remediation Engine™', 'Action ready for rejection', title, { deepLink: modulePath('remediation') })],
    })
  },
})

register({
  name: 'getRemediationHistory',
  module: 'remediation',
  description: 'Operator remediation decisions and completed work',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'remediation_operator_actions', '*', (q) => q.order('created_at', { ascending: false }), 50)
    return ok(
      { history: rows.slice(0, 30) },
      rows.length ? [ev('Quantum Remediation Engine™', 'Operator remediation records', String(rows.length), { deepLink: modulePath('remediation') })] : [],
      rows.length,
      rows.length ? undefined : 'No remediation history recorded yet.',
    )
  },
})

/* ---- Certificates / PKI ------------------------------------------- */

export interface CertificateView {
  name: string
  asset: string | null
  algorithm: string
  keySize: number | null
  issuer: string
  notAfter: string | null
  daysRemaining: number | null
  expired: boolean
  expiringSoon: boolean
  quantum: 'safe' | 'vulnerable' | 'unknown'
  weakReasons: string[]
}

const CLASSICAL_PUBLIC_KEY = new Set(['rsa', 'ecdsa', 'ecdh', 'dh', 'dsa'])
const POST_QUANTUM = new Set(['ml-dsa', 'slh-dsa', 'ml-kem', 'hybrid'])

function describeCertificate(r: Record<string, unknown>, assetName: Map<string, string>, nowMs: number, withinDays: number): CertificateView {
  const expiresMs = r.not_after ? new Date(str(r.not_after)).getTime() : NaN
  const daysRemaining = Number.isFinite(expiresMs) ? Math.floor((expiresMs - nowMs) / 86400000) : null
  const algorithm = str(r.algorithm)
  const family = algorithmFamily(algorithm)
  // The stored flag is the scanner's verdict. Only when it is absent is the
  // algorithm family consulted, and an unparseable algorithm stays unknown —
  // an absent flag used to be counted as quantum-vulnerable.
  const quantum: CertificateView['quantum'] = r.is_quantum_safe === true ? 'safe'
    : r.is_quantum_safe === false ? 'vulnerable'
    : CLASSICAL_PUBLIC_KEY.has(family) ? 'vulnerable'
    : POST_QUANTUM.has(family) ? 'safe'
    : 'unknown'
  const keySize = num(r.key_size)
  const weakReasons: string[] = []
  if (involvesAlgorithmFamily(algorithm, 'rsa') && keySize > 0 && keySize < 2048) weakReasons.push(`RSA-${keySize} is below the 2048-bit minimum`)
  if ((family === 'ecdsa' || family === 'ecdh') && keySize > 0 && keySize < 256) weakReasons.push(`${keySize}-bit elliptic curve is below 256 bits`)
  if (involvesAlgorithmFamily(algorithm, 'sha1')) weakReasons.push('SHA-1 signature (deprecated, collision-prone)')
  if (involvesAlgorithmFamily(algorithm, 'md5')) weakReasons.push('MD5 signature (broken)')
  return {
    name: str(r.name) || 'Unnamed certificate',
    asset: assetName.get(str(r.asset_id)) || null,
    algorithm: algorithm || 'unknown',
    keySize: keySize || null,
    issuer: str(r.issuer) || 'Unknown issuer',
    notAfter: str(r.not_after) || null,
    daysRemaining,
    expired: daysRemaining !== null && daysRemaining < 0,
    // A window the user named ("next 7 days") is applied exactly; otherwise the
    // stored flag — the PKI module's own expiring-soon window — decides.
    expiringSoon: withinDays > 0
      ? daysRemaining !== null && daysRemaining >= 0 && daysRemaining <= withinDays
      : r.is_expiring_soon === true,
    quantum,
    weakReasons,
  }
}

register({
  name: 'getCertificates',
  module: 'pki',
  description: 'Certificate inventory with quantum-safety and expiry posture',
  capability: 'read',
  async execute(ctx, args) {
    const [rows, total, assets] = await Promise.all([
      tenantRows(ctx, 'certificates', 'id, asset_id, name, algorithm, key_size, issuer, not_after, is_quantum_safe, is_expiring_soon, status, updated_at', (q) => q.order('not_after', { ascending: true }), 500),
      tenantCount(ctx, 'certificates'),
      tenantRows(ctx, 'assets', 'id, name', (q) => q, 800),
    ])
    const assetName = new Map(assets.map((a) => [str(a.id), str(a.name)]))
    const nowMs = Date.now()
    const withinDays = Math.max(0, Math.min(3650, num(args.withinDays)))
    const certs = rows.map((r) => describeCertificate(r, assetName, nowMs, withinDays))
    const expired = certs.filter((c) => c.expired)
    const expiring = certs.filter((c) => !c.expired && c.expiringSoon)
    const quantumVulnerable = certs.filter((c) => c.quantum === 'vulnerable')
    const weak = certs.filter((c) => c.weakReasons.length > 0)
    const issuers = new Map<string, { issuer: string; certificates: number; quantumSafe: number }>()
    for (const c of certs) {
      const g = issuers.get(c.issuer) || { issuer: c.issuer, certificates: 0, quantumSafe: 0 }
      g.certificates += 1
      if (c.quantum === 'safe') g.quantumSafe += 1
      issuers.set(c.issuer, g)
    }
    return ok(
      {
        total: total ?? rows.length,
        listed: certs.length,
        expired: expired.length,
        expiringSoon: expiring.length,
        withinDays: withinDays || null,
        quantumVulnerable: quantumVulnerable.length,
        quantumUnknown: certs.filter((c) => c.quantum === 'unknown').length,
        weak: weak.length,
        expiredList: expired.slice(0, 25),
        expiringList: expiring.sort((a, b) => (a.daysRemaining ?? 0) - (b.daysRemaining ?? 0)).slice(0, 25),
        vulnerableList: quantumVulnerable.slice(0, 25),
        weakList: weak.slice(0, 25),
        issuers: [...issuers.values()].sort((a, b) => b.certificates - a.certificates).slice(0, 20),
        sample: certs.slice(0, 30),
      },
      [ev('PKI Visibility', 'Certificates', String(total ?? rows.length), { detail: `${quantumVulnerable.length} quantum-vulnerable · ${expired.length} expired · ${expiring.length} expiring soon${weak.length ? ` · ${weak.length} weak` : ''}`, deepLink: modulePath('pki') })],
      total ?? rows.length,
    )
  },
})

register({
  name: 'getCertificateChains',
  module: 'pki',
  description: 'Certificates grouped by issuing authority',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'certificates', 'issuer, algorithm, is_quantum_safe', (q) => q, 500)
    const groups = new Map<string, { issuer: string; count: number; quantumSafe: number }>()
    for (const r of rows) {
      const issuer = str(r.issuer) || 'Unknown issuer'
      const g = groups.get(issuer) || { issuer, count: 0, quantumSafe: 0 }
      g.count += 1
      if (r.is_quantum_safe === true) g.quantumSafe += 1
      groups.set(issuer, g)
    }
    const chains = [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 20)
    return ok(
      { chains },
      [ev('PKI Visibility', 'Issuing authorities', String(groups.size), { deepLink: modulePath('pki') })],
      groups.size,
    )
  },
})

register({
  name: 'getQuantumCertificates',
  module: 'certification',
  description: 'Quantum Trust Certificates™ issued to this organization',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const dash = await deps.certification(ctx.token, ctx.userId, ctx.email)
    const current = rec(dash.certificate)
    const history = arr(dash.certificates)
    return ok(
      { current: dash.certificate ? current : null, history: history.slice(0, 10), renewal: rec(dash.renewal) },
      dash.certificate
        ? [ev('Quantum Trust Certification™', 'Active certificate', `${str(current.levelLabel) || str(current.level) || 'certified'}`, { detail: `trust score ${num(current.trustScore)}`, deepLink: modulePath('certification') })]
        : [],
      history.length,
      dash.certificate ? undefined : 'No Quantum Trust Certificate issued yet.',
    )
  },
})

register({
  name: 'getCertificateAuthorities',
  module: 'pki',
  description: 'Certificate authorities anchoring the tenant PKI',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'certificates', 'issuer, is_quantum_safe', (q) => q, 500)
    const issuers = new Map<string, number>()
    for (const r of rows) {
      const issuer = str(r.issuer) || 'Unknown issuer'
      issuers.set(issuer, (issuers.get(issuer) || 0) + 1)
    }
    const authorities = [...issuers.entries()].map(([issuer, count]) => ({ issuer, certificates: count })).sort((a, b) => b.certificates - a.certificates).slice(0, 20)
    return ok(
      { authorities },
      [ev('PKI Visibility', 'Certificate authorities', String(issuers.size), { deepLink: modulePath('pki') })],
      issuers.size,
    )
  },
})

register({
  name: 'getTrustStores',
  module: 'pki',
  description: 'Trust anchors observed across certificate chains and trust edges',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const intel = await deps.exposure(ctx.token, ctx.userId)
    const certEdges = intel.graph.edges.filter((e) => str((e as unknown as Record<string, unknown>).trustClass) === 'certificate-chain')
    const externalNodes = intel.graph.nodes.filter((n) => Boolean((n as unknown as Record<string, unknown>).external))
    return ok(
      { certificateChainEdges: certEdges.length, externalTrustAnchors: externalNodes.slice(0, 15).map((n) => n.label) },
      [ev('PKI Visibility', 'Trust anchors', String(externalNodes.length), { detail: `${certEdges.length} certificate-chain edge(s)`, deepLink: modulePath('pki') })],
      certEdges.length + externalNodes.length,
    )
  },
})

register({
  name: 'getKeyInventory',
  module: 'pki',
  description: 'Key inventory with algorithm distribution',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'generated_keys', 'id, algorithm, bit_length, quality_score, status, created_at', (q) => q.order('created_at', { ascending: false }), 200)
    const byAlgorithm: Record<string, number> = {}
    for (const r of rows) byAlgorithm[str(r.algorithm) || 'unknown'] = (byAlgorithm[str(r.algorithm) || 'unknown'] || 0) + 1
    return ok(
      { total: rows.length, byAlgorithm, sample: rows.slice(0, 20) },
      [ev('PKI Visibility', 'Keys in inventory', String(rows.length), { deepLink: modulePath('pki') })],
      rows.length,
    )
  },
})

/* ---- Harvest Now -------------------------------------------------- */

register({
  name: 'getHarvestNowExposure',
  module: 'harvest_now',
  description: 'Harvest-Now-Decrypt-Later exposure intelligence',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const hndl = await deps.hndl(ctx.token, ctx.userId)
    // The banner's fields are threatLevel / hndlExposureScore / headline. The
    // tool previously read `level || severity` and `message`, neither of which
    // exists, so every HNDL answer said "exposure: assessed".
    const banner = hndl.banner
    const fs = hndl.forwardSecrecy
    const future = hndl.futureDecryptable
    const topFindings = (hndl.topFindings || []).slice(0, 12)
    return ok(
      {
        hasData: hndl.hasData === true,
        threatLevel: banner.threatLevel,
        hndlScore: num(banner.hndlExposureScore),
        hndlLevel: str(banner.hndlExposureLevel),
        criticalExposures: num(banner.criticalFindings),
        exposureWindow: str(banner.quantumExposureWindow),
        migrationDeadlineYear: num(banner.migrationDeadlineYear),
        yearsToDeadline: num(banner.yearsToDeadline),
        headline: str(banner.headline),
        forwardSecrecy: {
          hasEvidence: fs.hasEvidence === true,
          coveragePct: num(fs.coveragePct),
          componentsMeasured: num(fs.componentsMeasured),
          componentsWithoutPfs: num(fs.assetsUnprotected),
          componentsNotApplicable: num(fs.componentsNotApplicable),
          assetsWithPfs: num(fs.assetsWithPfs),
          assetsWithoutPfs: num(fs.assetsWithoutPfs),
          nonPfsBreakdown: fs.nonPfsBreakdown || [],
          topUnprotected: fs.topUnprotected || [],
          basis: str(fs.basis),
        },
        // Terabyte figures are a MODEL (per-asset-class volume assumptions ×
        // the measured vulnerable share) — carried with that flag so an answer
        // can never present them as a measurement.
        futureDecryptable: {
          modelled: true,
          hasEvidence: future.hasEvidence === true,
          projectedDecryptableTb: num(future.projectedDecryptableTb),
          totalDataAtRiskTb: num(future.totalDataAtRiskTb),
          vulnerableSharePct: num(future.vulnerableSharePct),
        },
        topFindings,
        modelledActions: (hndl.remediationCenter || []).filter((a) => a.inScope).slice(0, 6),
        lastScanAt: hndl.lastScanAt || null,
      },
      [ev('Harvest Now (HNDL)', 'HNDL threat level', hndl.hasData ? `${banner.threatLevel} · ${num(banner.hndlExposureScore)}/100` : 'no evidence yet', {
        detail: str(banner.headline) || undefined,
        observedAt: hndl.lastScanAt || undefined,
        deepLink: modulePath('harvest_now'),
      })],
      hndl.hasData ? Math.max(1, topFindings.length) : 0,
      hndl.hasData ? undefined : 'No assessment evidence yet — HNDL exposure is derived from scan evidence.',
    )
  },
})

/* ---- Reports ------------------------------------------------------ */

register({
  name: 'getReports',
  module: 'reports',
  description: 'Report Center availability and report model freshness',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const snapshot = await deps.snapshot(ctx.token, ctx.userId)
    return ok(
      {
        reportModelReady: Boolean(snapshot.hasData),
        lastAssessmentAt: str(snapshot.lastAssessmentAt) || null,
        formats: ['PDF', 'DOCX', 'XLSX', 'CSV', 'JSON', 'HTML', 'Markdown'],
      },
      [ev('Report Center', 'Report model', snapshot.hasData ? 'ready' : 'awaiting first assessment', { observedAt: str(snapshot.lastAssessmentAt) || undefined, deepLink: modulePath('reports') })],
      snapshot.hasData ? 1 : 0,
    )
  },
})

register({
  name: 'generateExecutiveReport',
  module: 'reports',
  description: 'Compose an executive readiness report from live platform data',
  capability: 'executive',
  async execute(ctx, _args, deps) {
    const [snapshot, wf, cert] = await Promise.all([
      deps.snapshot(ctx.token, ctx.userId),
      deps.workflow(ctx.token, ctx.userId).catch(() => ({} as Record<string, unknown>)),
      deps.certification(ctx.token, ctx.userId, ctx.email).catch(() => ({} as Record<string, unknown>)),
    ])
    const scores = rec(snapshot.scores)
    const inventory = rec(snapshot.inventory)
    const estimates = rec(snapshot.estimates)
    audit(ctx, 'copilot.report.executive_generated', { readiness: num(scores.quantumReadiness) })
    return ok(
      {
        readiness: num(scores.quantumReadiness),
        risk: num(scores.quantumRisk),
        hndlRisk: num(scores.hndlRisk),
        pqcAdoption: num(scores.pqcAdoption),
        assets: num(inventory.assetsAssessed),
        vulnerableComponents: num(inventory.vulnerableComponents),
        migrationProgressPct: num(rec(wf).overallProgressPct),
        certification: rec(cert).certificate ? 'certified' : 'not yet certified',
        estimates,
        exportDeepLink: modulePath('reports'),
      },
      [ev('Report Center', 'Executive report composed', `readiness ${num(scores.quantumReadiness)} / risk ${num(scores.quantumRisk)}`, { detail: 'export as PDF/DOCX from the Report Center', deepLink: modulePath('reports') })],
      1,
    )
  },
})

/* ---- Telemetry / Collectors / Patchers ---------------------------- */

register({
  name: 'getLiveTelemetry',
  module: 'telemetry',
  description: 'Runtime cryptographic telemetry stream summary',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'runtime_crypto_events', 'id, algorithm, severity, is_pqc, is_legacy, hndl_risk, observed_at', (q) => q.order('observed_at', { ascending: false }), 300)
    const pqc = rows.filter((r) => r.is_pqc === true).length
    const legacy = rows.filter((r) => r.is_legacy === true).length
    const hndl = rows.filter((r) => r.hndl_risk === true).length
    return ok(
      {
        recentEvents: rows.length,
        pqcEvents: pqc,
        legacyEvents: legacy,
        hndlFlagged: hndl,
        latestAt: str(rows[0]?.observed_at) || null,
        recent: rows.slice(0, 40).map((r) => ({ algorithm: str(r.algorithm), severity: str(r.severity), is_legacy: r.is_legacy === true, is_pqc: r.is_pqc === true, hndl_risk: r.hndl_risk === true, observed_at: str(r.observed_at) })),
      },
      [ev('Runtime Telemetry', 'Recent runtime crypto events', String(rows.length), { detail: `${legacy} legacy · ${pqc} PQC · ${hndl} HNDL-flagged`, observedAt: str(rows[0]?.observed_at) || undefined, deepLink: modulePath('telemetry') })],
      rows.length,
    )
  },
})

const AGENT_SELECT = 'id, name, status, hostname, platform, version, capabilities, last_seen_at, revoked_at, created_at'
const ONLINE_WINDOW_MS = 5 * 60 * 1000

function agentOnline(a: Record<string, unknown>): boolean {
  const seen = str(a.last_seen_at)
  return Boolean(seen) && Date.now() - new Date(seen).getTime() < ONLINE_WINDOW_MS
}

register({
  name: 'getHeartbeat',
  module: 'collectors',
  description: 'Collector agent heartbeat recency',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'scanner_agents', AGENT_SELECT, (q) => q.is('revoked_at', null), 100)
    const online = rows.filter(agentOnline)
    return ok(
      { agents: rows.length, online: online.length, offline: rows.length - online.length, latestHeartbeat: rows.map((r) => str(r.last_seen_at)).filter(Boolean).sort().pop() || null },
      [ev('Agents Collector', 'Agent heartbeats', `${online.length}/${rows.length} online`, { deepLink: modulePath('collectors') })],
      rows.length,
    )
  },
})

register({
  name: 'getAgentHealth',
  module: 'collectors',
  description: 'Collector agent health/status distribution',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'scanner_agents', AGENT_SELECT, (q) => q, 100)
    const byStatus: Record<string, number> = {}
    for (const r of rows) byStatus[str(r.status) || 'unknown'] = (byStatus[str(r.status) || 'unknown'] || 0) + 1
    return ok(
      { total: rows.length, byStatus, online: rows.filter(agentOnline).length },
      [ev('Agents Collector', 'Agent health', Object.entries(byStatus).map(([k, v]) => `${k}:${v}`).join(' · ') || 'no agents', { deepLink: modulePath('collectors') })],
      rows.length,
    )
  },
})

register({
  name: 'getCollectors',
  module: 'collectors',
  description: 'Enrolled collector agents',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'scanner_agents', AGENT_SELECT, (q) => q.order('created_at', { ascending: false }), 100)
    return ok(
      { collectors: rows.map((r) => ({ id: str(r.id), name: str(r.name), status: str(r.status), platform: str(r.platform), online: agentOnline(r), lastSeenAt: str(r.last_seen_at) || null })) },
      [ev('Agents Collector', 'Enrolled collectors', String(rows.length), { deepLink: modulePath('collectors') })],
      rows.length,
    )
  },
})

register({
  name: 'getCollectorsStatus',
  module: 'collectors',
  description: 'Collector fleet status rollup',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'scanner_agents', AGENT_SELECT, (q) => q.is('revoked_at', null), 100)
    const online = rows.filter(agentOnline).length
    const agents = rows.map((r) => ({
      name: str(r.name) || str(r.hostname) || 'Unnamed agent',
      hostname: str(r.hostname) || null,
      platform: str(r.platform) || null,
      version: str(r.version) || null,
      online: agentOnline(r),
      lastSeenAt: str(r.last_seen_at) || null,
    }))
    return ok(
      {
        fleet: rows.length,
        online,
        offline: rows.length - online,
        healthy: online === rows.length && rows.length > 0,
        onlineWindowMinutes: ONLINE_WINDOW_MS / 60000,
        agents: agents.sort((a, b) => Number(a.online) - Number(b.online)).slice(0, 40),
      },
      [ev('Agents Collector', 'Fleet status', rows.length ? `${online}/${rows.length} online` : 'no collectors enrolled', { deepLink: modulePath('collectors') })],
      rows.length,
    )
  },
})

register({
  name: 'getPatchers',
  module: 'collectors',
  description: 'Patch-capable agents and recent operator patch activity',
  capability: 'read',
  async execute(ctx) {
    const [agents, actions] = await Promise.all([
      tenantRows(ctx, 'scanner_agents', AGENT_SELECT, (q) => q.is('revoked_at', null), 100),
      tenantRows(ctx, 'remediation_operator_actions', '*', (q) => q.order('created_at', { ascending: false }), 25),
    ])
    const patchers = agents.filter((a) => JSON.stringify(a.capabilities || '').toLowerCase().includes('patch'))
    return ok(
      { patchers: patchers.map((r) => ({ id: str(r.id), name: str(r.name), online: agentOnline(r) })), recentPatchActions: actions.length },
      [ev('Agents Collector', 'Patch-capable agents', String(patchers.length), { detail: `${actions.length} recent operator action(s)`, deepLink: modulePath('collectors') })],
      patchers.length + actions.length,
    )
  },
})

/* ---- Orchestrator / Connectors ------------------------------------ */

register({
  name: 'getRunningWorkflows',
  module: 'live_migration',
  description: 'Running orchestration workflows (active migration jobs)',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'migration_jobs', 'id, name, status, metadata, updated_at', (q) => q.in('status', ['queued', 'awaiting_agent', 'running', 'in_progress', 'executing']), 100)
    return ok(
      { running: rows.map((r) => ({ id: str(r.id), name: str(r.name), status: str(r.status), orchestration: rec(rec(r.metadata).orchestration) })) },
      [ev('Live Migration Ops', 'Active workflows', String(rows.length), { deepLink: modulePath('live_migration') })],
      rows.length,
    )
  },
})

register({
  name: 'getCloudConnectors',
  module: 'settings',
  description: 'Cloud connector accounts',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'connector_accounts', 'id, provider, status', (q) => q, 100)
    return ok(
      { connectors: rows.map((r) => ({ id: str(r.id), provider: str(r.provider), status: str(r.status) })) },
      [ev('Cloud Connectors', 'Connected accounts', String(rows.length), { deepLink: modulePath('settings') })],
      rows.length,
    )
  },
})

register({
  name: 'getConnectorStatus',
  module: 'settings',
  description: 'Cloud connector status rollup',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'connector_accounts', 'id, provider, status', (q) => q, 100)
    const byProvider: Record<string, number> = {}
    const unhealthy = rows.filter((r) => !/active|connected|healthy|ok/i.test(str(r.status)))
    for (const r of rows) byProvider[str(r.provider) || 'unknown'] = (byProvider[str(r.provider) || 'unknown'] || 0) + 1
    return ok(
      { total: rows.length, byProvider, unhealthy: unhealthy.length },
      [ev('Cloud Connectors', 'Connector health', rows.length ? `${rows.length - unhealthy.length}/${rows.length} healthy` : 'no connectors', { deepLink: modulePath('settings') })],
      rows.length,
    )
  },
})

/* ---- Compliance --------------------------------------------------- */

register({
  name: 'getComplianceStatus',
  module: 'compliance',
  description: 'Derived compliance posture across supported frameworks',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const [snapshot, cert] = await Promise.all([
      deps.snapshot(ctx.token, ctx.userId),
      deps.certification(ctx.token, ctx.userId, ctx.email).catch(() => ({} as Record<string, unknown>)),
    ])
    const scores = rec(snapshot.scores)
    const inventory = rec(snapshot.inventory)
    const pqcAdoption = num(scores.pqcAdoption)
    const vulnerable = num(inventory.vulnerableComponents)
    const frameworks = [
      { framework: STANDARDS.NIST_CSF, status: pqcAdoption >= 70 ? 'aligned' : vulnerable > 0 ? 'gaps identified' : 'partially aligned', signal: `PQC adoption ${pqcAdoption}%` },
      { framework: STANDARDS.SP_800_131A, status: vulnerable > 0 ? 'gaps identified' : 'aligned', signal: `${vulnerable} legacy component(s)` },
      { framework: STANDARDS.CNSA_2, status: pqcAdoption >= 90 ? 'aligned' : 'transition in progress', signal: `ML-KEM/ML-DSA adoption tracked` },
      { framework: STANDARDS.ISO_27001, status: rec(cert).certificate ? 'supported by certification evidence' : 'evidence collection ongoing', signal: 'crypto governance evidence' },
    ]
    return ok(
      { frameworks, methodology: 'Derived from the tenant’s live cryptographic posture (CBOM, scans, certification evidence) — not a formal audit.' },
      [ev('Compliance Center', 'Framework posture', `${frameworks.filter((f) => f.status === 'aligned').length}/${frameworks.length} aligned`, { detail: `PQC adoption ${pqcAdoption}% · ${vulnerable} vulnerable component(s)`, deepLink: modulePath('compliance') })],
      frameworks.length,
    )
  },
})

register({
  name: 'getNISTScore',
  module: 'compliance',
  description: 'NIST PQC alignment signals (FIPS 203/204/205)',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const snapshot = await deps.snapshot(ctx.token, ctx.userId)
    const scores = rec(snapshot.scores)
    const inventory = rec(snapshot.inventory)
    const rows = await tenantRows(ctx, 'crypto_inventory', 'algorithm, is_quantum_safe', (q) => q.eq('is_quantum_safe', true), 400)
    const algos = rows.map((r) => str(r.algorithm).toUpperCase())
    const mlkem = algos.filter((a) => /ML-KEM|KYBER/.test(a)).length
    const mldsa = algos.filter((a) => /ML-DSA|DILITHIUM/.test(a)).length
    const slhdsa = algos.filter((a) => /SLH-DSA|SPHINCS/.test(a)).length
    return ok(
      {
        readiness: num(scores.quantumReadiness),
        pqcAdoption: num(scores.pqcAdoption),
        fips203Components: mlkem,
        fips204Components: mldsa,
        fips205Components: slhdsa,
        vulnerableComponents: num(inventory.vulnerableComponents),
      },
      [ev('Compliance Center', 'NIST PQC alignment', `readiness ${num(scores.quantumReadiness)}/100`, { detail: `FIPS 203 ×${mlkem} · FIPS 204 ×${mldsa} · FIPS 205 ×${slhdsa}`, deepLink: modulePath('compliance') })],
      1,
    )
  },
})

register({
  name: 'getCNSACompliance',
  module: 'compliance',
  description: 'CNSA 2.0 transition posture from the live algorithm inventory',
  capability: 'read',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'crypto_inventory', 'algorithm, is_vulnerable, is_quantum_safe', (q) => q, 800)
    const algos = rows.map((r) => str(r.algorithm).toUpperCase())
    const checks = [
      { requirement: 'ML-KEM-1024 key establishment', met: algos.some((a) => /ML-KEM-1024|KYBER-?1024/.test(a)) },
      { requirement: 'ML-DSA-87 signatures', met: algos.some((a) => /ML-DSA-87|DILITHIUM-?5/.test(a)) },
      { requirement: 'AES-256 symmetric encryption', met: algos.some((a) => /AES[-_ ]?256/.test(a)) },
      { requirement: 'SHA-384 / SHA-512 / SHA3 hashing', met: algos.some((a) => /SHA[-_ ]?(384|512|3)/.test(a)) },
      { requirement: 'Legacy RSA/ECC eliminated', met: rows.length > 0 && !rows.some((r) => r.is_vulnerable === true) },
    ]
    const met = checks.filter((c) => c.met).length
    return ok(
      { checks, met, total: checks.length, dataAvailable: rows.length > 0 },
      [ev('Compliance Center', 'CNSA 2.0 checks met', `${met}/${checks.length}`, { deepLink: modulePath('compliance') })],
      rows.length,
      rows.length ? undefined : 'No crypto inventory yet — CNSA posture requires a discovery scan.',
    )
  },
})

/* ---- Quantum Readiness / Risk ------------------------------------- */

register({
  name: 'getQuantumReadiness',
  module: 'quantum_readiness',
  description: 'Quantum readiness scores + inventory rollup',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const snapshot = await deps.snapshot(ctx.token, ctx.userId)
    const scores = rec(snapshot.scores)
    const inventory = rec(snapshot.inventory)
    return ok(
      {
        scores,
        inventory,
        hasData: Boolean(snapshot.hasData),
        lastAssessmentAt: str(snapshot.lastAssessmentAt) || null,
        // The factor breakdown the QR Engine page renders — what "explain my
        // readiness score" is actually asking for.
        readinessFactors: (snapshot.readinessFactors || []).map((f) => ({ label: f.label, score: num(f.score) })),
        riskFactors: (snapshot.riskFactors || []).map((f) => ({ label: f.label, score: num(f.score), severity: str(f.severity) })),
      },
      [ev('Quantum Readiness', 'Quantum readiness', `${num(scores.quantumReadiness)}/100 (${str(scores.quantumReadinessLevel)})`, { detail: `risk ${num(scores.quantumRisk)} · HNDL ${num(scores.hndlRisk)} · PQC adoption ${num(scores.pqcAdoption)}%`, observedAt: str(snapshot.lastAssessmentAt) || undefined, deepLink: modulePath('quantum_readiness') })],
      Boolean(snapshot.hasData) ? 1 : 0,
      Boolean(snapshot.hasData) ? undefined : 'No assessment data yet — run a discovery scan to generate readiness scores.',
    )
  },
})

register({
  name: 'getReadinessHistory',
  module: 'quantum_readiness',
  description: 'Readiness / risk trend over time',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const snapshot = await deps.snapshot(ctx.token, ctx.userId)
    const trend = arr(snapshot.riskTrend)
    return ok(
      { trend },
      [ev('Quantum Readiness', 'Trend points', String(trend.length), { deepLink: modulePath('quantum_readiness') })],
      trend.length,
    )
  },
})

register({
  name: 'getRiskAnalysis',
  module: 'risk_analysis',
  description: 'Risk factors, distribution and top risk assets',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const snapshot = await deps.snapshot(ctx.token, ctx.userId)
    const distribution = rec(snapshot.riskDistribution)
    const top = arr(snapshot.topRiskAssets).slice(0, 10)
    return ok(
      { riskFactors: arr(snapshot.riskFactors).slice(0, 10), distribution, topRiskAssets: top, criticalFindings: arr(snapshot.criticalFindings).slice(0, 10) },
      [ev('Risk Analysis', 'Risk distribution', `critical ${num(distribution.critical)} · high ${num(distribution.high)} · medium ${num(distribution.medium)} · low ${num(distribution.low)}`, { deepLink: modulePath('risk_analysis') })],
      num(distribution.critical) + num(distribution.high) + num(distribution.medium) + num(distribution.low),
    )
  },
})

register({
  name: 'getRiskScore',
  module: 'risk_analysis',
  description: 'Headline quantum risk scores',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const snapshot = await deps.snapshot(ctx.token, ctx.userId)
    const scores = rec(snapshot.scores)
    return ok(
      { quantumRisk: num(scores.quantumRisk), hndlRisk: num(scores.hndlRisk), cryptoExposure: num(scores.cryptoExposure), levels: { risk: str(scores.quantumRiskLevel), hndl: str(scores.hndlRiskLevel) } },
      [ev('Risk Analysis', 'Quantum risk', `${num(scores.quantumRisk)}/100 (${str(scores.quantumRiskLevel)})`, { deepLink: modulePath('risk_analysis') })],
      1,
    )
  },
})

/* ---- Certification ------------------------------------------------ */

register({
  name: 'getCertificationStatus',
  module: 'certification',
  description: 'Quantum Trust Certification™ status',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const dash = await deps.certification(ctx.token, ctx.userId, ctx.email)
    const cert = dash.certificate
    const eligibility = dash.eligibility
    const requiredMet = num(eligibility?.requiredMet)
    const requiredTotal = num(eligibility?.requiredTotal)
    return ok(
      {
        certified: Boolean(cert),
        certificate: cert ? { level: cert.level, levelLabel: cert.levelLabel, trustScore: cert.trustScore, status: cert.status, issuedAt: cert.issuedAt, expiresAt: cert.expiresAt } : null,
        eligible: eligibility?.eligible === true,
        issuable: eligibility?.issuable === true,
        requiredMet,
        requiredTotal,
        currentLevelLabel: str(eligibility?.levelLabel),
        trustScore: num(eligibility?.trustScore),
        renewal: dash.renewal || null,
        schemaReady: dash.schemaReady === true,
      },
      [
        cert
          ? ev('Quantum Trust Certification™', 'Certification', `${cert.levelLabel || cert.level} — trust score ${num(cert.trustScore)}`, { deepLink: modulePath('certification') })
          : ev('Quantum Trust Certification™', 'Certification', 'not yet certified', { detail: requiredTotal ? `${requiredMet}/${requiredTotal} required criteria met` : undefined, deepLink: modulePath('certification') }),
      ],
      cert ? 1 : 0,
    )
  },
})

register({
  name: 'getCertificationEligibility',
  module: 'certification',
  description: 'Certification eligibility with unmet criteria',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const [dash, plan] = await Promise.all([
      deps.certification(ctx.token, ctx.userId, ctx.email),
      deps.remediationPlan(ctx.token, ctx.userId).catch(() => null as RemediationPlan | null),
    ])
    const eligibility = dash.eligibility
    // EligibilityResult carries its criteria in `checks`, each named by
    // `criterion`. Reading `criteria` / `label` (fields that do not exist)
    // made every tenant look "not eligible, 0 criteria unmet".
    const checks = Array.isArray(eligibility?.checks) ? eligibility.checks : []
    const toCriterion = (c: (typeof checks)[number]) => ({
      id: c.id,
      label: c.criterion,
      required: c.required,
      actual: c.actual,
      met: c.met === true,
      severity: c.severity,
      remediation: c.remediation,
      evidence: c.evidence,
    })
    const criteria = checks.map(toCriterion)
    const unmet = criteria.filter((c) => !c.met)
    const requiredUnmet = unmet.filter((c) => c.severity === 'required')
    // The Remediation Engine's requirement gaps name the assets and actions that
    // close each criterion, and its projection dates certification.
    const gaps = (plan?.requirements || []).filter((r) => r.status === 'unmet').map((r) => ({
      id: r.id,
      requirement: r.requirement,
      recommendedSolution: r.recommendedSolution,
      relatedAssets: r.relatedAssets.slice(0, 6),
      relatedActions: r.relatedActionIds.length,
      estimatedCompletionWeeks: r.estimatedCompletionWeeks,
      estimatedScoreIncreasePct: r.estimatedScoreIncreasePct,
      route: r.integration?.route || modulePath('remediation'),
    }))
    return ok(
      {
        eligible: eligibility?.eligible === true,
        issuable: eligibility?.issuable === true,
        hasData: eligibility?.hasData === true,
        levelLabel: str(eligibility?.levelLabel),
        trustScore: num(eligibility?.trustScore),
        requiredMet: num(eligibility?.requiredMet),
        requiredTotal: num(eligibility?.requiredTotal) || criteria.filter((c) => c.severity === 'required').length,
        criteria,
        unmet,
        requiredUnmet,
        gaps,
        certificationReadinessPct: num(plan?.certificationReadinessPct),
        estimatedCertificationDate: plan?.estimatedCertificationDate || null,
        estimatedCompletionWeeks: num(plan?.estimatedCompletionWeeks),
        ladder: (plan?.ladder || []).slice(0, 12),
      },
      [ev('Quantum Trust Certification™', 'Eligibility', eligibility?.eligible === true ? 'eligible' : `${requiredUnmet.length} required criteria unmet`, {
        // No observedAt: evaluatedAt is when the rules ran (now), not the age
        // of the evidence — stamping it would make stale evidence read fresh.
        detail: requiredUnmet.slice(0, 3).map((c) => c.label).join(', ') || undefined,
        deepLink: modulePath('certification'),
      })],
      criteria.length,
      criteria.length ? undefined : 'No certification criteria were evaluated — run an assessment first.',
    )
  },
})

/* ---- Snapshots / Rollback ----------------------------------------- */

register({
  name: 'getSnapshots',
  module: 'live_migration',
  description: 'Migration snapshots with integrity + restorability',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const dash = await deps.snapshotDashboard(ctx.token, ctx.userId, ctx.email)
    const summary = rec(dash.summary)
    return ok(
      { summary, snapshots: arr(dash.snapshots).slice(0, 15), schemaReady: Boolean(dash.schemaReady) },
      [ev('Live Migration Ops', 'Snapshots', `${num(summary.total)} total · ${num(summary.restorable)} restorable`, { detail: `${num(summary.automaticRollbacks)} automatic rollback(s)`, deepLink: modulePath('live_migration') })],
      num(summary.total),
    )
  },
})

register({
  name: 'createSnapshot',
  module: 'live_migration',
  description: 'Prepare a manual pre-migration snapshot (human-in-the-loop)',
  capability: 'operate',
  async execute(ctx, args, deps) {
    const dash = await deps.snapshotDashboard(ctx.token, ctx.userId, ctx.email)
    const summary = rec(dash.summary)
    audit(ctx, 'copilot.snapshot.create_prepared', { asset: str(args.asset || args.assetId) || null })
    return preparedAction({
      action: 'createSnapshot',
      module: 'live_migration',
      deepLink: modulePath('live_migration'),
      summary: 'Manual snapshot prepared — confirm in Live Migration Ops → Snapshots to capture an integrity-hashed crypto-state backup before changing anything.',
      preflight: { schemaReady: Boolean(dash.schemaReady), existingSnapshots: num(summary.total), integrity: 'SHA3-256 canonical state hash' },
      evidence: [ev('Live Migration Ops', 'Snapshot readiness', dash.schemaReady ? 'snapshot engine ready' : 'snapshot schema not applied yet', { deepLink: modulePath('live_migration') })],
    })
  },
})

register({
  name: 'restoreSnapshot',
  module: 'live_migration',
  description: 'Prepare a snapshot restore (human-in-the-loop)',
  capability: 'operate',
  async execute(ctx, args, deps) {
    const dash = await deps.snapshotDashboard(ctx.token, ctx.userId, ctx.email)
    const snapshots = arr(dash.snapshots) as Array<Record<string, unknown>>
    const ref = str(args.snapshotId || args.query).toLowerCase()
    const snap = ref
      ? snapshots.find((s) => str(s.snapshotId).toLowerCase().includes(ref) || str(s.id).toLowerCase() === ref || str(s.assetName).toLowerCase().includes(ref))
      : snapshots.find((s) => str(s.status) === 'restorable')
    if (!snap) return empty({ ref }, 'No restorable snapshot matches — check Live Migration Ops → Snapshots')
    audit(ctx, 'copilot.snapshot.restore_prepared', { snapshotId: str(snap.snapshotId) })
    return preparedAction({
      action: 'restoreSnapshot',
      module: 'live_migration',
      deepLink: modulePath('live_migration'),
      summary: `Restore prepared for snapshot ${str(snap.snapshotId)} (${str(snap.assetName)}) — confirm in Live Migration Ops; integrity is re-verified before restoration.`,
      preflight: { snapshotId: str(snap.snapshotId), asset: str(snap.assetName), status: str(snap.status), integrityVerified: snap.integrityVerified === true },
      evidence: [ev('Live Migration Ops', 'Restorable snapshot', str(snap.snapshotId), { detail: str(snap.assetName), deepLink: modulePath('live_migration') })],
    })
  },
})

register({
  name: 'rollbackMigration',
  module: 'live_migration',
  description: 'Prepare a migration rollback (human-in-the-loop)',
  capability: 'operate',
  async execute(ctx, args, deps) {
    const jobs = await tenantRows(ctx, 'migration_jobs', 'id, name, status, metadata, updated_at', (q) => q.order('updated_at', { ascending: false }), 100)
    const ref = str(args.jobId || args.migration || args.query).toLowerCase()
    const candidates = jobs.filter((j) => /fail|error|running|in_progress|executing/i.test(str(j.status)))
    const job = ref ? jobs.find((j) => str(j.id).toLowerCase() === ref || str(j.name).toLowerCase().includes(ref)) : candidates[0]
    if (!job) return empty({ ref }, 'No migration job eligible for rollback')
    const dash = await deps.snapshotDashboard(ctx.token, ctx.userId, ctx.email)
    const snapshots = arr(dash.snapshots) as Array<Record<string, unknown>>
    const snap = snapshots.find((s) => str(s.migrationJobId) === str(job.id) && str(s.status) === 'restorable')
    audit(ctx, 'copilot.migration.rollback_prepared', { jobId: str(job.id), hasSnapshot: Boolean(snap) })
    return preparedAction({
      action: 'rollbackMigration',
      module: 'live_migration',
      deepLink: modulePath('live_migration'),
      summary: snap
        ? `Rollback prepared for "${str(job.name)}" using pre-migration snapshot ${str(snap.snapshotId)} — confirm in Live Migration Ops.`
        : `Rollback prepared for "${str(job.name)}" — no restorable pre-migration snapshot found; Live Migration Ops will use its job-level rollback path.`,
      preflight: { jobId: str(job.id), jobStatus: str(job.status), snapshotAvailable: Boolean(snap), snapshotId: snap ? str(snap.snapshotId) : null },
      evidence: [ev('Live Migration Ops', 'Rollback candidate', str(job.name) || str(job.id), { detail: `status ${str(job.status)}`, deepLink: modulePath('live_migration') })],
    })
  },
})

register({
  name: 'rollbackAsset',
  module: 'live_migration',
  description: 'Prepare an asset-level rollback to its last snapshot (human-in-the-loop)',
  capability: 'operate',
  async execute(ctx, args, deps) {
    const ref = str(args.asset || args.assetId || args.query).toLowerCase()
    if (!ref) return empty({}, 'Specify which asset to roll back')
    const dash = await deps.snapshotDashboard(ctx.token, ctx.userId, ctx.email)
    const snapshots = arr(dash.snapshots) as Array<Record<string, unknown>>
    const snap = snapshots.find((s) => str(s.assetName).toLowerCase().includes(ref) && str(s.status) === 'restorable')
    if (!snap) return empty({ ref }, `No restorable snapshot found for asset "${ref}"`)
    audit(ctx, 'copilot.asset.rollback_prepared', { asset: str(snap.assetName), snapshotId: str(snap.snapshotId) })
    return preparedAction({
      action: 'rollbackAsset',
      module: 'live_migration',
      deepLink: modulePath('live_migration'),
      summary: `Asset rollback prepared: restore "${str(snap.assetName)}" from ${str(snap.snapshotId)} — confirm in Live Migration Ops.`,
      preflight: { asset: str(snap.assetName), snapshotId: str(snap.snapshotId), integrityVerified: snap.integrityVerified === true },
      evidence: [ev('Live Migration Ops', 'Asset snapshot', str(snap.snapshotId), { detail: str(snap.assetName), deepLink: modulePath('live_migration') })],
    })
  },
})

/* ---- Logs / Audit -------------------------------------------------- */

register({
  name: 'searchLogs',
  module: 'audit',
  description: 'Search tenant security events and audit logs',
  capability: 'audit',
  async execute(ctx, args) {
    const q = str(args.query).replace(/[,%()]/g, '').slice(0, 60)
    const [events, logs] = await Promise.all([
      tenantRows(ctx, 'security_events', 'id, event_type, severity, message, created_at', (query) => {
        let built = query.order('created_at', { ascending: false })
        if (q) built = built.or(`event_type.ilike.%${q}%,message.ilike.%${q}%`)
        return built
      }, 40),
      tenantRows(ctx, 'audit_logs', 'id, action, entity_type, details, created_at', (query) => {
        let built = query.order('created_at', { ascending: false })
        if (q) built = built.or(`action.ilike.%${q}%,entity_type.ilike.%${q}%`)
        return built
      }, 40),
    ])
    return ok(
      { securityEvents: events.slice(0, 20), auditLogs: logs.slice(0, 20), matched: events.length + logs.length },
      [ev('Audit Vault', 'Matching log records', String(events.length + logs.length), { detail: q ? `query "${q}"` : 'most recent', deepLink: modulePath('audit') })],
      events.length + logs.length,
    )
  },
})

register({
  name: 'getAuditTrail',
  module: 'audit',
  description: 'Recent tenant audit trail',
  capability: 'audit',
  async execute(ctx) {
    const rows = await tenantRows(ctx, 'audit_logs', 'id, action, entity_type, entity_id, details, created_at', (q) => q.order('created_at', { ascending: false }), 50)
    return ok(
      { entries: rows.slice(0, 30) },
      [ev('Audit Vault', 'Audit entries', String(rows.length), { deepLink: modulePath('audit') })],
      rows.length,
    )
  },
})

/* ---- Recommendations ---------------------------------------------- */

register({
  name: 'generateRecommendations',
  module: 'remediation',
  description: 'Prioritized, standards-aligned recommendations from live posture',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const [snapshot, plan] = await Promise.all([
      deps.snapshot(ctx.token, ctx.userId),
      deps.remediationPlan(ctx.token, ctx.userId).catch(() => ({} as Record<string, unknown>)),
    ])
    const snapshotActions = arr(snapshot.recommendedActions).slice(0, 8)
    const planActions = (Array.isArray(rec(plan).actions) ? (plan as RemediationPlan).actions : [])
      .filter((a) => a.status !== 'resolved')
    // Two different units: estate-level platform recommendations and
    // asset-level remediation actions. Summing them produced "9 prioritized
    // actions" beside "6 pending remediation actions" for the same queue.
    return ok(
      {
        snapshotRecommendations: snapshotActions,
        remediationActions: planActions.slice(0, 8).map(toActionRow),
        remediationActionCount: planActions.length,
        platformRecommendationCount: snapshotActions.length,
        certificationReadinessPct: num(rec(plan).certificationReadinessPct),
      },
      [ev('Quantum Remediation Engine™', 'Platform recommendations', String(snapshotActions.length), {
        detail: `estate-level guidance · the asset-level queue holds ${planActions.length} remediation action(s)`,
        deepLink: modulePath('remediation'),
      })],
      snapshotActions.length + planActions.length,
    )
  },
})

/* ------------------------------------------------------------------ */
/* Execution — RBAC-enforced, timed, audited                           */
/* ------------------------------------------------------------------ */

export interface ToolExecution {
  run: CopilotToolRun
  result: ToolResult | null
}

export function toolAllowedForRole(def: ToolDef, role: CopilotRole): boolean {
  const caps = ROLE_CAPABILITIES[role]
  if (!caps) return false
  if (def.capability === 'read') return caps.read
  if (def.capability === 'operate') return caps.operate
  if (def.capability === 'executive') return caps.executive
  // 'audit' surfaces are readable by audit-capable roles and operators.
  return caps.audit || caps.operate
}

export async function runTool(
  name: string,
  ctx: ToolContext,
  args: Record<string, unknown> = {},
  deps: CopilotBuilders = liveBuilders,
): Promise<ToolExecution> {
  const started = Date.now()
  const def = TOOL_REGISTRY[name]
  if (!def) {
    return { run: { tool: name, module: 'unknown', source: 'Platform', status: 'error', ms: 0, note: 'Unknown tool' }, result: null }
  }
  // `source` is the user-facing platform-module label — the only name the UI
  // renders; raw tool identifiers stay backend-internal.
  const source = moduleLabel(def.module)
  if (!toolAllowedForRole(def, ctx.role)) {
    audit(ctx, 'copilot.tool.denied', { tool: name, role: ctx.role })
    return {
      run: { tool: name, module: def.module, source, status: 'denied', ms: Date.now() - started, note: `Role "${ctx.role}" is not permitted to use ${name}` },
      result: null,
    }
  }
  try {
    const result = await def.execute(ctx, args, deps)
    return {
      run: { tool: name, module: def.module, source, status: result.status, ms: Date.now() - started, rows: result.rows, note: result.note },
      result,
    }
  } catch (error) {
    return {
      run: { tool: name, module: def.module, source, status: 'error', ms: Date.now() - started, note: (error as Error)?.message?.slice(0, 140) || 'Tool failed' },
      result: null,
    }
  }
}
