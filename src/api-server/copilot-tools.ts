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
import { ROLE_CAPABILITIES, STANDARDS, modulePath } from './copilot-knowledge'
import type { CopilotEvidence, CopilotRole, CopilotToolRun, CopilotToolStatus } from '@/types/copilot'
import type { ExposureIntelligence } from '@/types/exposure-graph'

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

/** Injectable builder seam — production uses the live platform builders. */
export interface CopilotBuilders {
  snapshot(token: string, userId: string): Promise<Record<string, unknown>>
  scannerIntel(token: string, userId: string): Promise<Record<string, unknown>>
  exposure(token: string, userId: string): Promise<ExposureIntelligence>
  remediationPlan(token: string, userId: string): Promise<Record<string, unknown>>
  certification(token: string, userId: string, email: string): Promise<Record<string, unknown>>
  hndl(token: string, userId: string): Promise<Record<string, unknown>>
  workflow(token: string, userId: string): Promise<Record<string, unknown>>
  snapshotDashboard(token: string, userId: string, email: string): Promise<Record<string, unknown>>
}

export const liveBuilders: CopilotBuilders = {
  snapshot: (token, userId) => buildSnapshot(token, userId) as Promise<Record<string, unknown>>,
  scannerIntel: (token, userId) => buildScannerIntelligence(token, userId) as Promise<Record<string, unknown>>,
  exposure: (token, userId) => buildExposureIntelligence(token, userId),
  remediationPlan: async (token, userId) => {
    const evidence = await assembleEvidence(token, userId)
    return buildRemediationPlan(evidence) as unknown as Record<string, unknown>
  },
  certification: (token, userId, email) => buildCertificationDashboard(token, userId, email) as unknown as Promise<Record<string, unknown>>,
  hndl: (token, userId) => buildHndlIntelligence(token, userId) as Promise<Record<string, unknown>>,
  workflow: (token, userId) => buildWorkflowState(token, userId) as unknown as Promise<Record<string, unknown>>,
  snapshotDashboard: (token, userId, email) => buildSnapshotDashboard(token, userId, email) as unknown as Promise<Record<string, unknown>>,
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
export async function tenantRows(
  ctx: ToolContext,
  table: string,
  select: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  apply?: (q: any) => any,
  limit = 200,
): Promise<Record<string, unknown>[]> {
  try {
    let query = ctx.client.from(table).select(select).eq('user_id', ctx.userId)
    if (apply) query = apply(query)
    const { data, error } = await query.limit(limit)
    if (error) return []
    return (data as Record<string, unknown>[]) || []
  } catch {
    return []
  }
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
    const q = str(args.query).replace(/[,%()]/g, '').slice(0, 80)
    const rows = await tenantRows(ctx, 'assets', ASSET_SELECT, (query) => {
      let built = query.order('updated_at', { ascending: false })
      if (q) built = built.or(`name.ilike.%${q}%,type.ilike.%${q}%,environment.ilike.%${q}%`)
      return built
    }, 200)
    let assets = rows.map(mapAsset)
    if (args.internetFacing === true) assets = assets.filter((a) => a.internetFacing)
    if (str(args.criticality)) assets = assets.filter((a) => a.criticality === str(args.criticality))
    return ok(
      { matches: assets.slice(0, 50), matched: assets.length },
      [ev('Assets & CBOM', 'Matching assets', String(assets.length), { detail: q ? `query "${q}"` : 'full inventory scan', deepLink: modulePath('assets') })],
      assets.length,
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
  name: 'getCryptoInventory',
  module: 'cbom',
  description: 'Cryptographic inventory (CBOM source of truth) with posture counts',
  capability: 'read',
  async execute(ctx) {
    const [rows, total, vulnerable, safe] = await Promise.all([
      tenantRows(ctx, 'crypto_inventory', 'id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, created_at', (q) => q.order('created_at', { ascending: false }), 300),
      tenantCount(ctx, 'crypto_inventory'),
      tenantCount(ctx, 'crypto_inventory', (q) => q.eq('is_vulnerable', true)),
      tenantCount(ctx, 'crypto_inventory', (q) => q.eq('is_quantum_safe', true)),
    ])
    const totalCount = total ?? rows.length
    return ok(
      { total: totalCount, vulnerable: vulnerable ?? 0, quantumSafe: safe ?? 0, sample: rows.slice(0, 40) },
      [ev('CBOM Explorer', 'Crypto components', String(totalCount), { detail: `${vulnerable ?? 0} quantum-vulnerable · ${safe ?? 0} quantum-safe`, deepLink: modulePath('cbom') })],
      totalCount,
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
    const rows = await tenantRows(ctx, 'crypto_inventory', 'algorithm, is_vulnerable, is_quantum_safe', (q) => q, 800)
    const groups = new Map<string, { algorithm: string; count: number; vulnerable: number; quantumSafe: number }>()
    for (const r of rows) {
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
      { algorithms, vulnerableAlgorithms: vulnerableAlgos },
      [ev('CBOM Explorer', 'Algorithms observed', String(groups.size), { detail: vulnerableAlgos.slice(0, 6).join(', ') || 'none vulnerable', deepLink: modulePath('cbom') })],
      groups.size,
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
        thirdParty: intel.thirdParty.length,
      },
      [
        ev('Exposure Graph', 'Graph coverage', `${s.totalAssets} asset(s), ${s.trustRelationships} trust edge(s)`, { detail: `${s.quantumVulnerable} quantum-vulnerable · ${s.internetFacingAssets} internet-facing`, observedAt: intel.generatedAt || undefined, deepLink: modulePath('exposure_graph') }),
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
    return ok(
      { asset: node.label, blast },
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
    const nextAction = rec(wf.nextAction)
    return ok(
      {
        overallProgressPct: num(wf.overallProgressPct),
        currentStageId: str(wf.currentStageId),
        certificationReadinessPct: num(wf.certificationReadinessPct),
        nextAction,
        stages: arr(wf.stages).slice(0, 12),
      },
      [ev('Live Migration Ops', 'Migration progress', `${num(wf.overallProgressPct)}%`, { detail: `current stage: ${str(wf.currentStageId)} · next: ${str(nextAction.label)}`, observedAt: str(wf.generatedAt) || undefined, deepLink: modulePath('live_migration') })],
      arr(wf.stages).length,
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

register({
  name: 'getPendingRemediation',
  module: 'remediation',
  description: 'Pending remediation actions from the Quantum Remediation Engine™',
  capability: 'read',
  async execute(ctx, _args, deps) {
    const plan = await deps.remediationPlan(ctx.token, ctx.userId)
    const actions = arr(plan.actions) as Array<Record<string, unknown>>
    const queues = rec(plan.queues)
    const pending = actions.filter((a) => str(a.status) !== 'completed')
    return ok(
      {
        pending: pending.slice(0, 25),
        pendingCount: pending.length,
        queues,
        certificationReadinessPct: num(plan.certificationReadinessPct),
        quickWins: arr(plan.quickWins).length,
        criticalBlockers: arr(plan.criticalBlockers).length,
      },
      [ev('Quantum Remediation Engine™', 'Pending remediation actions', String(pending.length), { detail: `${arr(plan.criticalBlockers).length} critical blocker(s) · ${arr(plan.quickWins).length} quick win(s)`, deepLink: modulePath('remediation') })],
      pending.length,
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
    const actions = arr(plan.actions) as Array<Record<string, unknown>>
    const ref = str(args.actionId || args.action || args.query).toLowerCase()
    const action = ref
      ? actions.find((a) => str(a.id).toLowerCase() === ref || str(a.title).toLowerCase().includes(ref))
      : actions.find((a) => str(a.priority) === 'critical') || actions[0]
    if (!action) return empty({ ref }, 'No matching remediation action found for this tenant')
    audit(ctx, 'copilot.remediation.approve_prepared', { actionId: str(action.id), title: str(action.title) })
    return preparedAction({
      action: 'approveRemediation',
      module: 'remediation',
      deepLink: modulePath('remediation'),
      summary: `Approval prepared for "${str(action.title)}" — confirm in the Remediation Center to execute with full validation checkpoints and rollback protection.`,
      preflight: { actionId: str(action.id), title: str(action.title), priority: str(action.priority), domain: str(action.domain) },
      evidence: [ev('Quantum Remediation Engine™', 'Action ready for approval', str(action.title), { detail: `priority ${str(action.priority)}`, deepLink: modulePath('remediation') })],
    })
  },
})

register({
  name: 'rejectRemediation',
  module: 'remediation',
  description: 'Prepare rejection of a remediation action (human-in-the-loop)',
  capability: 'operate',
  async execute(ctx, args, deps) {
    const plan = await deps.remediationPlan(ctx.token, ctx.userId)
    const actions = arr(plan.actions) as Array<Record<string, unknown>>
    const ref = str(args.actionId || args.action || args.query).toLowerCase()
    const action = ref ? actions.find((a) => str(a.id).toLowerCase() === ref || str(a.title).toLowerCase().includes(ref)) : null
    if (!action) return empty({ ref }, 'Specify which remediation action to reject (id or title)')
    audit(ctx, 'copilot.remediation.reject_prepared', { actionId: str(action.id), title: str(action.title) })
    return preparedAction({
      action: 'rejectRemediation',
      module: 'remediation',
      deepLink: modulePath('remediation'),
      summary: `Rejection prepared for "${str(action.title)}" — confirm in the Remediation Center (the decision is audited).`,
      preflight: { actionId: str(action.id), title: str(action.title) },
      evidence: [ev('Quantum Remediation Engine™', 'Action ready for rejection', str(action.title), { deepLink: modulePath('remediation') })],
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

register({
  name: 'getCertificates',
  module: 'pki',
  description: 'Certificate inventory with quantum-safety and expiry posture',
  capability: 'read',
  async execute(ctx) {
    const [rows, total] = await Promise.all([
      tenantRows(ctx, 'certificates', 'id, asset_id, name, algorithm, key_size, issuer, not_after, is_quantum_safe, is_expiring_soon, status', (q) => q.order('not_after', { ascending: true }), 300),
      tenantCount(ctx, 'certificates'),
    ])
    const nowMs = Date.now()
    const expired = rows.filter((r) => r.not_after && new Date(str(r.not_after)).getTime() < nowMs)
    const expiring = rows.filter((r) => r.is_expiring_soon === true)
    const quantumVulnerable = rows.filter((r) => r.is_quantum_safe !== true)
    return ok(
      { total: total ?? rows.length, expired: expired.length, expiringSoon: expiring.length, quantumVulnerable: quantumVulnerable.length, sample: rows.slice(0, 30) },
      [ev('PKI Visibility', 'Certificates', String(total ?? rows.length), { detail: `${quantumVulnerable.length} quantum-vulnerable · ${expired.length} expired · ${expiring.length} expiring soon`, deepLink: modulePath('pki') })],
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
    const banner = rec(hndl.banner)
    const future = rec(hndl.futureDecryptable)
    const fs = rec(hndl.forwardSecrecy)
    return ok(
      { banner, futureDecryptable: future, forwardSecrecy: fs, topFindings: arr(hndl.topFindings).slice(0, 10) },
      [ev('Harvest Now (HNDL)', 'HNDL exposure', str(banner.level || banner.severity) || 'assessed', { detail: str(banner.headline || banner.message) || undefined, deepLink: modulePath('harvest_now') })],
      arr(hndl.topFindings).length || 1,
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
      { recentEvents: rows.length, pqcEvents: pqc, legacyEvents: legacy, hndlFlagged: hndl, latestAt: str(rows[0]?.observed_at) || null },
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
      [ev('Agent Collectors', 'Agent heartbeats', `${online.length}/${rows.length} online`, { deepLink: modulePath('collectors') })],
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
      [ev('Agent Collectors', 'Agent health', Object.entries(byStatus).map(([k, v]) => `${k}:${v}`).join(' · ') || 'no agents', { deepLink: modulePath('collectors') })],
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
      [ev('Agent Collectors', 'Enrolled collectors', String(rows.length), { deepLink: modulePath('collectors') })],
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
    return ok(
      { fleet: rows.length, online, offline: rows.length - online, healthy: online === rows.length && rows.length > 0 },
      [ev('Agent Collectors', 'Fleet status', rows.length ? `${online}/${rows.length} online` : 'no collectors enrolled', { deepLink: modulePath('collectors') })],
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
      [ev('Agent Collectors', 'Patch-capable agents', String(patchers.length), { detail: `${actions.length} recent operator action(s)`, deepLink: modulePath('collectors') })],
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
      { scores, inventory, hasData: Boolean(snapshot.hasData), lastAssessmentAt: str(snapshot.lastAssessmentAt) || null },
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
    const cert = rec(dash.certificate)
    const eligibility = rec(dash.eligibility)
    return ok(
      { certified: Boolean(dash.certificate), certificate: dash.certificate ? cert : null, eligibility, renewal: rec(dash.renewal), schemaReady: Boolean(dash.schemaReady) },
      [
        dash.certificate
          ? ev('Quantum Trust Certification™', 'Certification', `${str(cert.levelLabel) || str(cert.level)} — trust score ${num(cert.trustScore)}`, { deepLink: modulePath('certification') })
          : ev('Quantum Trust Certification™', 'Certification', 'not yet certified', { detail: str(eligibility.summary) || undefined, deepLink: modulePath('certification') }),
      ],
      dash.certificate ? 1 : 0,
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
      deps.remediationPlan(ctx.token, ctx.userId).catch(() => ({} as Record<string, unknown>)),
    ])
    const eligibility = rec(dash.eligibility)
    const criteria = arr(eligibility.criteria) as Array<Record<string, unknown>>
    const unmet = criteria.filter((c) => c.met !== true)
    return ok(
      {
        eligible: eligibility.eligible === true,
        criteria: criteria.slice(0, 12),
        unmet: unmet.slice(0, 10),
        certificationReadinessPct: num(rec(plan).certificationReadinessPct),
      },
      [ev('Quantum Trust Certification™', 'Eligibility', eligibility.eligible === true ? 'eligible' : `${unmet.length} criteria unmet`, { detail: unmet.slice(0, 3).map((c) => str(c.label || c.id)).join(', ') || undefined, deepLink: modulePath('certification') })],
      criteria.length,
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
    const planActions = (arr(rec(plan).actions) as Array<Record<string, unknown>>)
      .filter((a) => str(a.status) !== 'completed')
      .slice(0, 8)
    return ok(
      { snapshotRecommendations: snapshotActions, remediationActions: planActions, certificationReadinessPct: num(rec(plan).certificationReadinessPct) },
      [ev('Quantum Remediation Engine™', 'Prioritized actions', String(snapshotActions.length + planActions.length), { deepLink: modulePath('remediation') })],
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
    return { run: { tool: name, module: 'unknown', status: 'error', ms: 0, note: 'Unknown tool' }, result: null }
  }
  if (!toolAllowedForRole(def, ctx.role)) {
    audit(ctx, 'copilot.tool.denied', { tool: name, role: ctx.role })
    return {
      run: { tool: name, module: def.module, status: 'denied', ms: Date.now() - started, note: `Role "${ctx.role}" is not permitted to use ${name}` },
      result: null,
    }
  }
  try {
    const result = await def.execute(ctx, args, deps)
    return {
      run: { tool: name, module: def.module, status: result.status, ms: Date.now() - started, rows: result.rows, note: result.note },
      result,
    }
  } catch (error) {
    return {
      run: { tool: name, module: def.module, status: 'error', ms: Date.now() - started, note: (error as Error)?.message?.slice(0, 140) || 'Tool failed' },
      result: null,
    }
  }
}
