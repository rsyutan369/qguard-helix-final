/**
 * Estate views — campaigns, estate map, heatmap, Sankey, burndown, ownership.
 * Every number is a count of real memberships produced by `buildClusters`.
 */
import {
  ENVIRONMENT_LABEL, ENVIRONMENT_ROLLOUT, OWNER_SOURCE_LABEL, SEVERITY_RANK, worstSeverity,
  type EnvironmentKey, type EstateAsset, type OwnerSource,
} from './model'
import { MEMBER_STATUS_LABEL, type AssetJob, type ClusterState, type FixKind, type MemberStatus } from './clusters'
import type { FindingSeverity } from '@/lib/scanner/exposure/types'

/* ------------------------------------------------------------------ */
/* Campaigns                                                           */
/* ------------------------------------------------------------------ */

export interface CampaignWave {
  index: number
  label: string
  environments: string[]
  /** Assets still needing work in this wave (open, failed or regressed). */
  assetIds: string[]
  assets: number
  canary: boolean
  /** True once every earlier wave has no exceptions and nothing left un-validated. */
  ready: boolean
  readinessNote: string
}

export interface CampaignStage { key: string; label: string; count: number; detail: string; status: MemberStatus | 'scope' }

export interface Campaign {
  clusterId: string
  stages: CampaignStage[]
  waves: CampaignWave[]
  waveSize: number
  gate: string
  completion: number
}

/** The planner queue accepts at most this many assets per request. */
export const MAX_WAVE = 200

export function buildCampaign(state: ClusterState, assets: Map<string, EstateAsset>): Campaign {
  const counts = state.cluster.progress
  const total = state.cluster.assets
  const exceptions = counts.failed + counts.regressed
  const stages: CampaignStage[] = [
    { key: 'scope', label: 'Scope', count: total, detail: `${total} asset(s) affected by this fix`, status: 'scope' },
    { key: 'open', label: 'Not started', count: counts.open, detail: 'No migration job yet', status: 'open' },
    { key: 'planned', label: 'Queued / planned', count: counts.planned, detail: 'Job created, waiting for approval or an agent', status: 'planned' },
    { key: 'running', label: 'Executing', count: counts.running, detail: 'Job running on the asset', status: 'running' },
    { key: 'awaiting-validation', label: 'Awaiting rescan', count: counts['awaiting-validation'], detail: 'Job completed; no scan recorded since', status: 'awaiting-validation' },
    { key: 'validated', label: 'Validated', count: counts.validated, detail: 'A scan after completion no longer shows the vulnerable component', status: 'validated' },
    { key: 'exceptions', label: 'Exceptions', count: exceptions, detail: `${counts.failed} failed / rolled back · ${counts.regressed} still vulnerable after rescan — re-planned in the next wave`, status: 'failed' },
  ]

  // Waves cover the work that still needs a job: not started, failed, or still vulnerable after rescan.
  const pending = [...state.members.entries()]
    .filter(([, member]) => member.status === 'open' || member.status === 'failed' || member.status === 'regressed')
    .map(([assetId, member]) => ({ assetId, member, asset: assets.get(assetId) }))
  const rank = (env: EnvironmentKey) => ENVIRONMENT_ROLLOUT.indexOf(env)
  pending.sort((a, b) =>
    rank(a.asset?.environment ?? 'unknown') - rank(b.asset?.environment ?? 'unknown')
    || b.member.weight - a.member.weight
    || a.assetId.localeCompare(b.assetId))

  const waveSize = Math.min(MAX_WAVE, Math.max(10, Math.ceil(pending.length / 6)))
  const canarySize = pending.length > 20 ? Math.max(1, Math.min(10, Math.ceil(pending.length * 0.05))) : pending.length
  const waves: CampaignWave[] = []
  let cursor = 0
  while (cursor < pending.length) {
    const size = waves.length === 0 ? canarySize : waveSize
    const slice = pending.slice(cursor, cursor + size)
    cursor += size
    const envs = [...new Set(slice.map((item) => ENVIRONMENT_LABEL[item.asset?.environment ?? 'unknown']))]
    waves.push({
      index: waves.length + 1,
      label: waves.length === 0 && pending.length > 20 ? 'Canary' : `Wave ${waves.length + 1}`,
      environments: envs,
      assetIds: slice.map((item) => item.assetId),
      assets: slice.length,
      canary: waves.length === 0 && pending.length > 20,
      ready: false,
      readinessNote: '',
    })
  }
  // Gate: only the first not-yet-queued wave may start, and only when nothing in flight has failed.
  const inFlight = counts.planned + counts.running + counts['awaiting-validation']
  waves.forEach((wave, index) => {
    if (index > 0) { wave.ready = false; wave.readinessNote = `Starts after wave ${index} is validated by rescan.`; return }
    if (exceptions > 0) { wave.ready = false; wave.readinessNote = `${exceptions} exception(s) must be resolved or rolled back first.`; return }
    if (inFlight > 0) { wave.ready = false; wave.readinessNote = `${inFlight} asset(s) still in flight — validate them first.`; return }
    wave.ready = true
    wave.readinessNote = 'Ready to queue in the Migration Planner.'
  })

  return {
    clusterId: state.cluster.id,
    stages,
    waves,
    waveSize,
    gate: 'Waves run least-critical environment first. The next wave is released only when the previous one has no failures and every completed asset is validated by a rescan.',
    completion: total ? Math.round((counts.validated / total) * 100) : 0,
  }
}

/* ------------------------------------------------------------------ */
/* Per-asset roll-up shared by the map and ownership views             */
/* ------------------------------------------------------------------ */

export interface AssetRollup { worst: FindingSeverity; fixes: number; open: number; validated: number }

export function rollupAssets(states: ClusterState[]): Map<string, AssetRollup> {
  const rollup = new Map<string, AssetRollup>()
  for (const state of states) {
    for (const [assetId, member] of state.members) {
      const current = rollup.get(assetId) ?? { worst: 'info' as FindingSeverity, fixes: 0, open: 0, validated: 0 }
      current.fixes += 1
      if (member.status === 'validated') current.validated += 1
      else current.open += 1
      if (SEVERITY_RANK[member.severity] > SEVERITY_RANK[current.worst] && member.status !== 'validated') current.worst = member.severity
      rollup.set(assetId, current)
    }
  }
  return rollup
}

/* ------------------------------------------------------------------ */
/* Estate map (level 0)                                                */
/* ------------------------------------------------------------------ */

export type MapDimension = 'owner' | 'service' | 'environment' | 'type'

export interface MapGroup {
  key: string
  label: string
  assets: number
  affectedAssets: number
  openFixes: number
  criticalAssets: number
  readiness: number
  worst: FindingSeverity
}

export function buildEstateMap(assets: EstateAsset[], rollup: Map<string, AssetRollup>, dimension: MapDimension): MapGroup[] {
  const groups = new Map<string, MapGroup>()
  for (const asset of assets) {
    const raw = dimension === 'owner' ? asset.owner
      : dimension === 'service' ? asset.service
        : dimension === 'environment' ? ENVIRONMENT_LABEL[asset.environment]
          : asset.type
    const label = raw || (dimension === 'owner' ? 'Unowned' : dimension === 'service' ? 'No business service recorded' : 'Unspecified')
    const key = label.toLowerCase()
    const group = groups.get(key) ?? { key, label, assets: 0, affectedAssets: 0, openFixes: 0, criticalAssets: 0, readiness: 0, worst: 'info' as FindingSeverity }
    group.assets += 1
    const asset_ = rollup.get(asset.id)
    if (asset_ && asset_.open > 0) {
      group.affectedAssets += 1
      group.openFixes += asset_.open
      if (asset_.worst === 'critical') group.criticalAssets += 1
      group.worst = worstSeverity([group.worst, asset_.worst])
    }
    groups.set(key, group)
  }
  for (const group of groups.values()) group.readiness = group.assets ? Math.round(((group.assets - group.affectedAssets) / group.assets) * 100) : 0
  return [...groups.values()].sort((a, b) => b.affectedAssets - a.affectedAssets || b.assets - a.assets)
}

/* ------------------------------------------------------------------ */
/* Algorithm × environment heatmap                                     */
/* ------------------------------------------------------------------ */

export interface Heatmap {
  rows: string[]
  columns: Array<{ key: EnvironmentKey; label: string }>
  /** cells[row][column] = distinct assets. */
  cells: number[][]
  max: number
  omittedRows: number
}

export function buildHeatmap(states: ClusterState[], assets: Map<string, EstateAsset>): Heatmap {
  const byAlgorithm = new Map<string, Map<EnvironmentKey, Set<string>>>()
  for (const state of states) {
    const algorithm = state.cluster.algorithms[0] ?? state.cluster.rootCause.label
    const row = byAlgorithm.get(algorithm) ?? new Map<EnvironmentKey, Set<string>>()
    for (const [assetId, member] of state.members) {
      if (member.status === 'validated') continue
      const env = assets.get(assetId)?.environment ?? 'unknown'
      const set = row.get(env) ?? new Set<string>()
      set.add(assetId)
      row.set(env, set)
    }
    byAlgorithm.set(algorithm, row)
  }
  const totals = [...byAlgorithm.entries()].map(([name, row]) => ({ name, row, total: new Set([...row.values()].flatMap((s) => [...s])).size }))
    .filter((entry) => entry.total > 0)
    .sort((a, b) => b.total - a.total)
  const shown = totals.slice(0, 12)
  const envs = (Object.keys(ENVIRONMENT_LABEL) as EnvironmentKey[]).filter((env) => shown.some((entry) => entry.row.has(env)))
  const cells = shown.map((entry) => envs.map((env) => entry.row.get(env)?.size ?? 0))
  return {
    rows: shown.map((entry) => entry.name),
    columns: envs.map((key) => ({ key, label: ENVIRONMENT_LABEL[key] })),
    cells,
    max: Math.max(0, ...cells.flat()),
    omittedRows: Math.max(0, totals.length - shown.length),
  }
}

/* ------------------------------------------------------------------ */
/* Sankey: current algorithm → replacement → status                    */
/* ------------------------------------------------------------------ */

export interface SankeyData {
  nodes: Array<{ name: string; column: 0 | 1 | 2 }>
  links: Array<{ source: number; target: number; value: number }>
  total: number
}

const TARGET_LABEL: Record<FixKind, string> = {
  'ca-reissue': 'ML-DSA / SLH-DSA certificates',
  'certificate-keys': 'ML-DSA / SLH-DSA certificates',
  'library-upgrade': 'PQC-capable library release',
  'key-exchange': 'Hybrid X25519 + ML-KEM',
  'signing-keys': 'ML-DSA / SLH-DSA signatures',
  'data-encryption': 'ML-KEM key wrap + AES-256-GCM',
  'classical-weakness': 'Retire (broken today)',
  'classify-usage': 'Classify role first',
}

const STATUS_BUCKET: Record<MemberStatus, string> = {
  open: 'Not started',
  planned: 'In flight',
  running: 'In flight',
  'awaiting-validation': 'Awaiting rescan',
  validated: 'Validated',
  failed: 'Exceptions',
  regressed: 'Exceptions',
}

export function buildSankey(states: ClusterState[]): SankeyData {
  const algorithmTotals = new Map<string, number>()
  for (const state of states) {
    const algorithm = state.cluster.algorithms[0] ?? state.cluster.rootCause.label
    algorithmTotals.set(algorithm, (algorithmTotals.get(algorithm) ?? 0) + state.members.size)
  }
  const keep = new Set([...algorithmTotals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name]) => name))
  const nodes: SankeyData['nodes'] = []
  const index = new Map<string, number>()
  const node = (name: string, column: 0 | 1 | 2) => {
    const key = `${column}:${name}`
    if (!index.has(key)) { index.set(key, nodes.length); nodes.push({ name, column }) }
    return index.get(key)!
  }
  const linkValues = new Map<string, number>()
  const add = (source: number, target: number, value: number) => {
    const key = `${source}>${target}`
    linkValues.set(key, (linkValues.get(key) ?? 0) + value)
  }
  let total = 0
  for (const state of states) {
    const primary = state.cluster.algorithms[0] ?? state.cluster.rootCause.label
    const algorithm = keep.has(primary) ? primary : 'Other algorithms'
    const source = node(algorithm, 0)
    const target = node(TARGET_LABEL[state.cluster.kind], 1)
    add(source, target, state.members.size)
    for (const member of state.members.values()) {
      add(target, node(STATUS_BUCKET[member.status], 2), 1)
      total += 1
    }
  }
  const links = [...linkValues.entries()].map(([key, value]) => {
    const [source, target] = key.split('>').map(Number)
    return { source, target, value }
  })
  return { nodes, links, total }
}

/* ------------------------------------------------------------------ */
/* Burndown against the NIST IR 8547 dates                             */
/* ------------------------------------------------------------------ */

export interface BurndownPoint { month: string; at: number; discovered: number; validated: number; open: number }

export interface Burndown {
  points: BurndownPoint[]
  openNow: number
  validatedLast90Days: number
  /** Validations per month needed to clear the open backlog by the end of 2030. */
  requiredPerMonth: number
  /** At the last-90-day pace; null when nothing was validated in that window. */
  projectedCompletion: string | null
  basis: string
}

const DEADLINE_2030 = Date.UTC(2030, 11, 31)

export function buildBurndown(states: ClusterState[], jobs: Map<string, AssetJob>, now: number): Burndown {
  const discoveredAt: number[] = []
  const validatedAt: number[] = []
  for (const state of states) {
    for (const [assetId, member] of state.members) {
      if (member.firstSeenAt > 0) discoveredAt.push(member.firstSeenAt)
      if (member.status === 'validated') validatedAt.push(jobs.get(assetId)?.updatedAt ?? now)
    }
  }
  discoveredAt.sort((a, b) => a - b)
  validatedAt.sort((a, b) => a - b)
  const points: BurndownPoint[] = []
  if (discoveredAt.length) {
    const startDate = new Date(Math.max(discoveredAt[0], now - 1000 * 60 * 60 * 24 * 365 * 3))
    let cursor = Date.UTC(startDate.getUTCFullYear(), startDate.getUTCMonth(), 1)
    const end = now
    let di = 0
    let vi = 0
    while (cursor <= end) {
      const next = new Date(cursor)
      next.setUTCMonth(next.getUTCMonth() + 1)
      const edge = Math.min(next.getTime() - 1, end)
      while (di < discoveredAt.length && discoveredAt[di] <= edge) di += 1
      while (vi < validatedAt.length && validatedAt[vi] <= edge) vi += 1
      // Memberships first seen before the window start are counted at the first point.
      points.push({ month: new Date(cursor).toISOString().slice(0, 7), at: edge, discovered: di, validated: vi, open: di - vi })
      cursor = next.getTime()
    }
  }
  const total = discoveredAt.length + states.reduce((sum, state) => sum + [...state.members.values()].filter((m) => m.firstSeenAt <= 0).length, 0)
  const openNow = total - validatedAt.length
  const validatedLast90Days = validatedAt.filter((at) => at >= now - 1000 * 60 * 60 * 24 * 90).length
  const monthsLeft = Math.max(1, (DEADLINE_2030 - now) / (1000 * 60 * 60 * 24 * 30.44))
  const pace = validatedLast90Days / 3
  const projectedCompletion = pace > 0 && openNow > 0
    ? new Date(now + (openNow / pace) * 30.44 * 24 * 60 * 60 * 1000).toISOString().slice(0, 7)
    : null
  return {
    points,
    openNow,
    validatedLast90Days,
    requiredPerMonth: Math.ceil(openNow / monthsLeft),
    projectedCompletion,
    basis: 'One unit = one asset × one fix. "Discovered" uses the first scan that recorded it; "validated" uses the completion time of the job a later rescan confirmed. Illustrative target: end of 2030, when the general NIST IR 8547 deprecation window begins. This burndown does not determine deadlines for individual systems.',
  }
}

/* ------------------------------------------------------------------ */
/* Ownership                                                           */
/* ------------------------------------------------------------------ */

export interface OwnershipRow {
  owner: string
  sources: string[]
  assets: number
  affectedAssets: number
  openFixes: number
  criticalAssets: number
}

export interface Ownership {
  rows: OwnershipRow[]
  unowned: OwnershipRow
  sourceBreakdown: Array<{ source: string; assets: number }>
  ownedShare: number
}

export function buildOwnership(assets: EstateAsset[], rollup: Map<string, AssetRollup>): Ownership {
  const rows = new Map<string, OwnershipRow & { sourceSet: Set<string> }>()
  const unowned: OwnershipRow = { owner: 'Unowned', sources: [], assets: 0, affectedAssets: 0, openFixes: 0, criticalAssets: 0 }
  const sources = new Map<OwnerSource, number>()
  for (const asset of assets) {
    const stats = rollup.get(asset.id)
    const target = asset.owner
      ? (rows.get(asset.owner.toLowerCase()) ?? (() => {
        const created = { owner: asset.owner!, sources: [], sourceSet: new Set<string>(), assets: 0, affectedAssets: 0, openFixes: 0, criticalAssets: 0 }
        rows.set(asset.owner!.toLowerCase(), created)
        return created
      })())
      : unowned
    target.assets += 1
    if (asset.ownerSource) {
      sources.set(asset.ownerSource, (sources.get(asset.ownerSource) ?? 0) + 1)
      ;(target as { sourceSet?: Set<string> }).sourceSet?.add(OWNER_SOURCE_LABEL[asset.ownerSource])
    }
    if (stats && stats.open > 0) {
      target.affectedAssets += 1
      target.openFixes += stats.open
      if (stats.worst === 'critical') target.criticalAssets += 1
    }
  }
  const list = [...rows.values()].map(({ sourceSet, ...row }) => ({ ...row, sources: [...sourceSet] }))
    .sort((a, b) => b.affectedAssets - a.affectedAssets || b.assets - a.assets)
  return {
    rows: list,
    unowned,
    sourceBreakdown: [...sources.entries()].map(([source, count]) => ({ source: OWNER_SOURCE_LABEL[source], assets: count })),
    ownedShare: assets.length ? Math.round(((assets.length - unowned.assets) / assets.length) * 100) : 0,
  }
}

export { MEMBER_STATUS_LABEL }
