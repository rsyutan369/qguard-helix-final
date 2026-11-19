/**
 * Estate intelligence — entry point.
 *
 * `EstateModel` is computed once per tenant (cached server-side) and answers
 * every slice the pages need: the fix plan, one fix's members and campaign, the
 * three map levels and the analytics views. Each answer is bounded, so a tenant
 * with 10,000 assets gets the same response sizes as one with 10.
 */
import { str } from '@/lib/migration/asset-intelligence'
import {
  ENVIRONMENT_LABEL, mergeCertificates, normaliseAsset, observationFromInventory,
  type CertificateIdentity, type EstateAsset, type EstateInputs, type Observation, type TableCoverage,
} from './model'
import { MEMBER_STATUS_LABEL, buildClusters, latestJobs, type AssetJob, type ClusterState, type FixCluster, type MemberStatus } from './clusters'
import {
  buildBurndown, buildCampaign, buildEstateMap, buildHeatmap, buildOwnership, buildSankey, rollupAssets,
  type AssetRollup, type Burndown, type Campaign, type Heatmap, type MapDimension, type MapGroup, type Ownership, type SankeyData,
} from './views'
import { assetNeighbourhood, campaignGraph, fixNeighbourhood, rootCauseGraph } from './graph'
import type { WorkflowGraph } from '@/components/trust-workflow/graph-model'
import type { FindingSeverity } from '@/lib/scanner/exposure/types'

export * from './model'
export * from './clusters'
export * from './views'
export { ROOT_CAUSE_LIMIT, NEIGHBOURHOOD_LIMIT } from './graph'

export interface EstateSummary {
  assets: number
  affectedAssets: number
  /** Assets with no open quantum or classical fix (includes assets with no crypto recorded). */
  assetsWithoutOpenFixes: number
  inventoryRows: number
  classifiedObservations: number
  unclassifiedObservations: number
  uniqueComponents: number
  certificateRecords: number
  uniqueCertificates: number
  reusedCertificates: number
  /** Raw records collapsed by fingerprint / component identity. */
  duplicatesMerged: number
  fixes: number
  /** Asset × fix pairs still open. */
  openWorkItems: number
  validatedWorkItems: number
  /** Share of affected assets touched by the five highest-priority fixes. */
  topFiveCoverage: number
  unownedAffectedAssets: number
  coveredByCertificate: number
}

export interface EstateOverview {
  generatedAt: string
  hasData: boolean
  coverage: TableCoverage[]
  summary: EstateSummary
  clusters: FixCluster[]
  maps: Record<MapDimension, MapGroup[]>
  heatmap: Heatmap
  sankey: SankeyData
  burndown: Burndown
  ownership: Ownership
}

export interface ClusterMemberRow {
  assetId: string
  name: string
  type: string
  environment: string
  owner: string | null
  service: string | null
  internetFacing: boolean
  severity: FindingSeverity
  observations: number
  status: MemberStatus
  statusLabel: string
  firstSeenAt: string | null
}

export interface ClusterDetail {
  cluster: FixCluster
  members: ClusterMemberRow[]
  total: number
  offset: number
  limit: number
  campaign: Campaign
}

export type GraphLevel = 'root-cause' | 'neighbourhood' | 'campaign'

export class EstateModel {
  readonly generatedAt: string
  readonly coverage: TableCoverage[]
  readonly assets: EstateAsset[]
  readonly assetById: Map<string, EstateAsset>
  readonly observations: Observation[]
  readonly certificates: CertificateIdentity[]
  readonly states: ClusterState[]
  readonly stateById: Map<string, ClusterState>
  readonly jobs: Map<string, AssetJob>
  readonly rollup: Map<string, AssetRollup>
  readonly relationships: Array<{ source: string; target: string; type: string }>
  private readonly now: number
  private readonly affected: Set<string>
  private readonly coveredByCertificate: number
  private readonly inventoryRows: number
  private overviewCache: EstateOverview | null = null

  constructor(inputs: EstateInputs) {
    this.now = inputs.now ?? Date.now()
    this.generatedAt = new Date(this.now).toISOString()
    this.coverage = inputs.coverage
    this.assets = inputs.assets.map(normaliseAsset).filter((asset) => asset.id)
    this.assetById = new Map(this.assets.map((asset) => [asset.id, asset]))
    this.inventoryRows = inputs.inventory.length
    this.observations = inputs.inventory.map(observationFromInventory)
    this.certificates = mergeCertificates(inputs.certificates)

    // Certificate subject OU is the weakest ownership signal: used only when nothing stored names an owner.
    for (const certificate of this.certificates) {
      if (!certificate.subjectOu) continue
      for (const assetId of certificate.assetIds) {
        const asset = this.assetById.get(assetId)
        if (asset && !asset.owner) { asset.owner = certificate.subjectOu; asset.ownerSource = 'certificate subject' }
      }
    }

    this.jobs = latestJobs(inputs.migrationJobs)
    const build = buildClusters(this.observations, this.certificates, this.assetById, this.jobs)
    this.states = build.states
    this.affected = build.affectedAssetIds
    this.coveredByCertificate = build.coveredByCertificate
    this.stateById = new Map(this.states.map((state) => [state.cluster.id, state]))
    this.rollup = rollupAssets(this.states)
    this.relationships = inputs.relationships.map((rel) => ({
      source: str(rel.source_asset_id || rel.parent_asset_id || rel.from_asset_id),
      target: str(rel.target_asset_id || rel.child_asset_id || rel.to_asset_id),
      type: str(rel.relationship_type),
    })).filter((rel) => rel.source && rel.target)
  }

  overview(): EstateOverview {
    if (this.overviewCache) return this.overviewCache
    const clusters = this.states.map((state) => state.cluster)
    const classified = this.observations.filter((o) => o.actionability !== 'unclassified').length
    const uniqueComponents = new Set(this.observations.filter((o) => o.actionability !== 'unclassified').map((o) => o.componentKey)).size
    const certificateRecords = this.certificates.reduce((sum, c) => sum + c.recordIds.length, 0)
    let open = 0
    let validated = 0
    for (const state of this.states) { open += state.cluster.assets - state.cluster.progress.validated; validated += state.cluster.progress.validated }
    const topFive = new Set<string>()
    for (const state of this.states.slice(0, 5)) for (const id of state.members.keys()) topFive.add(id)
    let unownedAffected = 0
    for (const id of this.affected) if (!this.assetById.get(id)?.owner) unownedAffected += 1
    const assetsWithOpen = [...this.rollup.values()].filter((r) => r.open > 0).length

    this.overviewCache = {
      generatedAt: this.generatedAt,
      hasData: this.assets.length > 0 || this.observations.length > 0 || this.certificates.length > 0,
      coverage: this.coverage,
      summary: {
        assets: this.assets.length,
        affectedAssets: this.affected.size,
        assetsWithoutOpenFixes: Math.max(0, this.assets.length - assetsWithOpen),
        inventoryRows: this.inventoryRows,
        classifiedObservations: classified,
        unclassifiedObservations: this.observations.length - classified,
        uniqueComponents,
        certificateRecords,
        uniqueCertificates: this.certificates.length,
        reusedCertificates: this.certificates.filter((c) => c.assetIds.size > 1).length,
        duplicatesMerged: Math.max(0, classified - uniqueComponents) + Math.max(0, certificateRecords - this.certificates.length),
        fixes: this.states.length,
        openWorkItems: open,
        validatedWorkItems: validated,
        topFiveCoverage: this.affected.size ? Math.round((topFive.size / this.affected.size) * 1000) / 10 : 0,
        unownedAffectedAssets: unownedAffected,
        coveredByCertificate: this.coveredByCertificate,
      },
      clusters,
      maps: {
        owner: buildEstateMap(this.assets, this.rollup, 'owner'),
        service: buildEstateMap(this.assets, this.rollup, 'service'),
        environment: buildEstateMap(this.assets, this.rollup, 'environment'),
        type: buildEstateMap(this.assets, this.rollup, 'type'),
      },
      heatmap: buildHeatmap(this.states, this.assetById),
      sankey: buildSankey(this.states),
      burndown: buildBurndown(this.states, this.jobs, this.now),
      ownership: buildOwnership(this.assets, this.rollup),
    }
    return this.overviewCache
  }

  clusterDetail(id: string, options: { offset?: number; limit?: number; status?: string; search?: string } = {}): ClusterDetail | null {
    const state = this.stateById.get(id)
    if (!state) return null
    const offset = Math.max(0, Math.floor(options.offset ?? 0))
    const limit = Math.min(500, Math.max(1, Math.floor(options.limit ?? 100)))
    const term = (options.search ?? '').trim().toLowerCase()
    const rows = [...state.members.entries()]
      .filter(([, member]) => !options.status || options.status === 'all' || member.status === options.status)
      .map(([assetId, member]): ClusterMemberRow => {
        const asset = this.assetById.get(assetId)
        return {
          assetId,
          name: asset?.name ?? assetId,
          type: asset?.type ?? 'asset',
          environment: asset ? asset.environmentRaw || ENVIRONMENT_LABEL[asset.environment] : ENVIRONMENT_LABEL.unknown,
          owner: asset?.owner ?? null,
          service: asset?.service ?? null,
          internetFacing: Boolean(asset?.internetFacing),
          severity: member.severity,
          observations: member.observations,
          status: member.status,
          statusLabel: MEMBER_STATUS_LABEL[member.status],
          firstSeenAt: member.firstSeenAt > 0 ? new Date(member.firstSeenAt).toISOString() : null,
        }
      })
      .filter((row) => !term || `${row.name} ${row.owner ?? ''} ${row.service ?? ''} ${row.environment}`.toLowerCase().includes(term))
      .sort((a, b) => (state.members.get(b.assetId)!.weight - state.members.get(a.assetId)!.weight) || a.name.localeCompare(b.name))
    return {
      cluster: state.cluster,
      members: rows.slice(offset, offset + limit),
      total: rows.length,
      offset,
      limit,
      campaign: buildCampaign(state, this.assetById),
    }
  }

  graph(level: GraphLevel, focus?: string | null): WorkflowGraph | null {
    if (level === 'root-cause') return rootCauseGraph(this.states)
    if (!focus) return null
    if (level === 'campaign') {
      const state = this.stateById.get(focus.replace(/^fix:/, ''))
      return state ? campaignGraph(state, buildCampaign(state, this.assetById)) : null
    }
    if (focus.startsWith('fix:')) {
      const state = this.stateById.get(focus.slice(4))
      return state ? fixNeighbourhood(state, this.assetById, this.certificates) : null
    }
    if (focus.startsWith('asset:')) {
      return assetNeighbourhood(focus.slice(6), this.assetById, this.observations, this.certificates, this.states, this.relationships)
    }
    return null
  }

  /** Asset search for "jump to" in the map. Bounded. */
  searchAssets(term: string, limit = 20) {
    const needle = term.trim().toLowerCase()
    if (!needle) return []
    const out: Array<{ id: string; name: string; owner: string | null; environment: string; openFixes: number }> = []
    for (const asset of this.assets) {
      if (!`${asset.name} ${asset.owner ?? ''} ${asset.service ?? ''}`.toLowerCase().includes(needle)) continue
      out.push({ id: asset.id, name: asset.name, owner: asset.owner, environment: asset.environmentRaw || ENVIRONMENT_LABEL[asset.environment], openFixes: this.rollup.get(asset.id)?.open ?? 0 })
      if (out.length >= limit) break
    }
    return out
  }
}

export function buildEstateModel(inputs: EstateInputs) {
  return new EstateModel(inputs)
}
