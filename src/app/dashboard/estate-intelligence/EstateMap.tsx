'use client'
import { useEffect, useId, useMemo, useState } from 'react'
import {
  ArrowDownRight, ArrowLeft, ArrowRight, Building2, ChevronLeft, ChevronRight, CircleHelp,
  Clock3, Layers3, Loader2, Network, Search, Server, Share2, ShieldAlert, Users, Workflow,
} from 'lucide-react'
import {
  DetailFacts, DetailLink, DetailSection, RelationshipList, VendorTrustWorkflowCanvas, type DetailContext,
} from '@/components/trust-workflow/VendorTrustWorkflowCanvas'
import { emptyGraph, type WorkflowNode } from '@/components/trust-workflow/graph-model'
import { OWNER_SOURCE_LABEL, type EstateOverview, type MapAsset, type MapDimension, type MapGroup } from '@/lib/estate'
import { useEstateGraph, useEstateMapAssets, useEstateSearch } from '@/hooks/use-estate-intelligence'

export type MapLevel = 'estate' | 'root-cause' | 'neighbourhood'

const DIMENSIONS = {
  owner: { label: 'Owner', icon: Users, missing: 'No owner recorded' },
  service: { label: 'Business service', icon: Workflow, missing: 'No business service recorded' },
  environment: { label: 'Environment', icon: Layers3, missing: 'No environment recorded' },
  type: { label: 'Asset type', icon: Server, missing: 'No asset type recorded' },
} satisfies Record<MapDimension, { label: string; icon: typeof Users; missing: string }>

const LEVELS = [
  { key: 'estate', label: 'Company map', icon: Building2 },
  { key: 'root-cause', label: 'Root causes', icon: Share2 },
  { key: 'neighbourhood', label: 'Neighbourhood', icon: Network },
] as const

const EMPTY_GRAPH = emptyGraph()
const GROUPS_PER_PAGE = 8
const number = new Intl.NumberFormat()
const date = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

function displayType(value: string | null) {
  return value?.replace(/[_-]+/g, ' ').replace(/^\p{Ll}/u, (letter) => letter.toUpperCase()) || 'Unspecified'
}

function assetStatus(asset: MapAsset) {
  if (asset.openFixes) return { tone: asset.severity ?? 'info', label: asset.openFixes + (asset.openFixes === 1 ? ' open fix' : ' open fixes') }
  if (!asset.evidence.classified && !asset.evidence.unclassified) return { tone: 'info', label: 'No crypto evidence loaded' }
  if (asset.evidence.unclassified) return { tone: 'medium', label: 'Unclassified evidence' }
  return { tone: 'info', label: 'No open fixes recorded' }
}

function groupStatus(group: MapGroup) {
  if (group.openFixes) return { tone: group.worst, label: group.worst[0].toUpperCase() + group.worst.slice(1) + ' exposure' }
  if (group.assetsWithoutEvidence === group.assets) return { tone: 'info', label: 'No crypto evidence loaded' }
  if (group.assetsWithUnclassifiedEvidence) return { tone: 'medium', label: 'Unclassified evidence' }
  return { tone: 'info', label: 'No open fixes recorded' }
}

function countLabel(value: number, singular: string, plural = singular + 's') {
  return number.format(value) + ' ' + (value === 1 ? singular : plural)
}

function AssetOption({ asset, onOpen }: { asset: MapAsset; onOpen: (id: string) => void }) {
  const status = assetStatus(asset)
  return (
    <button type="button" className="qe-map-asset" onClick={() => onOpen(asset.id)} aria-label={'Explore neighbourhood for ' + asset.name}>
      <Server aria-hidden="true" size={17} className="qe-map-asset-icon" />
      <span className="qe-map-asset-title">
        <strong>{asset.name}</strong>
        <span>{[displayType(asset.type), asset.environment ?? 'Environment unspecified', asset.status && displayType(asset.status)].filter(Boolean).join(' · ')}</span>
        <span>{(asset.owner ?? 'Owner unassigned') + ' · ' + (asset.service ?? 'Service unspecified')}</span>
      </span>
      <span className="qe-map-status" data-tone={status.tone}>{status.label}</span>
      <ArrowRight aria-hidden="true" size={15} className="qe-map-arrow" />
    </button>
  )
}

function AssetSearch({ onOpen, revision }: { onOpen: (id: string) => void; revision: string }) {
  const search = useEstateSearch()
  const searchId = useId()
  const [term, setTerm] = useState('')
  const [expanded, setExpanded] = useState(false)
  const query = term.trim()
  const [result, setResult] = useState<{ query: string; source: typeof search; hits: MapAsset[]; error: boolean } | null>(null)

  useEffect(() => {
    if (!expanded || query.length < 2) return
    const controller = new AbortController()
    const handle = window.setTimeout(async () => {
      try {
        const hits = await search(query, controller.signal)
        if (!controller.signal.aborted) setResult({ query, source: search, hits, error: false })
      } catch {
        if (!controller.signal.aborted) setResult({ query, source: search, hits: [], error: true })
      }
    }, 250)
    return () => { window.clearTimeout(handle); controller.abort() }
  }, [expanded, query, revision, search])

  const ready = result?.query === query && result.source === search ? result : null
  const show = expanded && query.length >= 2
  return (
    <div className="qe-map-search" onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setExpanded(false) }}
      onKeyDown={(event) => { if (event.key === 'Escape') { setExpanded(false); document.getElementById(searchId)?.focus() } }}>
      <label className="qe-map-search-field" htmlFor={searchId}>
        <Search aria-hidden="true" size={17} />
        <span className="sr-only">Find an asset by name, owner, service, environment or type</span>
        <input id={searchId} type="search" value={term} maxLength={120} autoComplete="off" placeholder="Find an asset…"
          onFocus={() => setExpanded(true)} onChange={(event) => { setTerm(event.target.value); setExpanded(true) }} />
      </label>
      {show && (
        <div className="qe-map-search-results">
          {!ready ? <p role="status">Searching asset records…</p>
            : ready.error ? <p role="status">Asset search is unavailable. Reopen the search to retry.</p>
              : !ready.hits.length ? <p role="status">No assets match “{query}”.</p>
                : <ul aria-label="Matching assets">{ready.hits.map((hit) => (
                  <li key={hit.id}><AssetOption asset={hit} onOpen={(id) => { setTerm(''); setExpanded(false); onOpen(id) }} /></li>
                ))}</ul>}
        </div>
      )}
    </div>
  )
}

function Pagination({ page, pages, label, onPage, disabled = false }: {
  page: number; pages: number; label: string; onPage: (page: number) => void; disabled?: boolean
}) {
  if (pages < 2) return null
  return (
    <nav className="qe-map-pager" aria-label={label}>
      <span>Page {page + 1} of {pages}</span>
      <div>
        <button type="button" aria-label={'Previous ' + label.toLowerCase() + ' page'} onClick={() => onPage(page - 1)} disabled={disabled || page === 0}><ChevronLeft aria-hidden="true" size={17} /></button>
        <button type="button" aria-label={'Next ' + label.toLowerCase() + ' page'} onClick={() => onPage(page + 1)} disabled={disabled || page + 1 >= pages}><ChevronRight aria-hidden="true" size={17} /></button>
      </div>
    </nav>
  )
}

function GroupInspector({ dimension, group, revision, onOpenAsset }: {
  dimension: MapDimension; group: MapGroup; revision: string; onOpenAsset: (id: string) => void
}) {
  const [page, setPage] = useState(0)
  const limit = 8
  const lastPage = Math.max(0, Math.ceil(group.assets / limit) - 1)
  const currentPage = Math.min(page, lastPage)
  const { data, error, refreshing, refresh } = useEstateMapAssets(dimension, group.key, currentPage * limit, revision)
  const title = group.metadataMissing ? DIMENSIONS[dimension].missing : dimension === 'type' ? displayType(group.label) : group.label
  const status = groupStatus(group)

  return (
    <section className="qe-map-inspector" aria-label="Selected group">
      <header>
        <span className="qe-map-label">{DIMENSIONS[dimension].label} group</span>
        <h3>{title}</h3>
        <span className="qe-map-status" data-tone={status.tone}>{status.label}</span>
      </header>

      <dl className="qe-map-stat-grid">
        <div><dt>Assets</dt><dd>{number.format(group.assets)}</dd></div>
        <div><dt>With open fixes</dt><dd>{number.format(group.affectedAssets)}</dd></div>
        <div><dt>Critical exposure</dt><dd>{number.format(group.criticalAssets)}</dd></div>
        <div><dt>Open fix items</dt><dd>{number.format(group.openFixes)}</dd></div>
      </dl>

      {(group.assetsWithoutEvidence > 0 || group.assetsWithUnclassifiedEvidence > 0) && (
        <div className="qe-map-coverage">
          <CircleHelp size={16} aria-hidden="true" />
          <span>{[
            group.assetsWithoutEvidence > 0 && countLabel(group.assetsWithoutEvidence, 'asset') + ' without crypto evidence',
            group.assetsWithUnclassifiedEvidence > 0 && countLabel(group.assetsWithUnclassifiedEvidence, 'asset') + ' with unclassified evidence',
          ].filter(Boolean).join(' · ')}</span>
        </div>
      )}

      <div className="qe-map-members">
        <div className="qe-map-section-title">
          <h4>Group assets</h4>
          <span>{data ? (data.offset + 1) + '–' + (data.offset + data.members.length) + ' of ' + number.format(data.total) : number.format(group.assets)}</span>
        </div>
        {error && <p className="qe-map-message" role="status">Group assets could not be refreshed. <button type="button" onClick={() => void refresh()}>Retry</button></p>}
        {data && data.revision !== revision && <p className="qe-map-message" role="status">Asset list as of {date.format(new Date(data.generatedAt))}{refreshing ? ' · Updating' : ''}</p>}
        {data ? (
          <ul>{data.members.map((asset) => <li key={asset.id}><AssetOption asset={asset} onOpen={onOpenAsset} /></li>)}</ul>
        ) : !error && <p className="qe-map-message" role="status"><Loader2 size={15} className="animate-spin" aria-hidden="true" /> Loading group assets…</p>}
        <Pagination page={currentPage} pages={lastPage + 1} label="Assets" onPage={setPage} disabled={refreshing} />
      </div>
    </section>
  )
}

function CompanyMap({ overview, dimension, setDimension, onOpenAsset }: {
  overview: EstateOverview; dimension: MapDimension; setDimension: (dimension: MapDimension) => void; onOpenAsset: (id: string) => void
}) {
  const [selection, setSelection] = useState<{ dimension: MapDimension; key: string } | null>(null)
  const [paging, setPaging] = useState({ dimension, page: 0 })
  const [tableView, setTableView] = useState(false)
  const groups = overview.maps[dimension]
  const pages = Math.ceil(groups.length / GROUPS_PER_PAGE)
  const page = Math.min(paging.dimension === dimension ? paging.page : 0, Math.max(0, pages - 1))
  const shown = groups.slice(page * GROUPS_PER_PAGE, (page + 1) * GROUPS_PER_PAGE)
  const selected = (selection?.dimension === dimension ? groups.find((group) => group.key === selection.key) : null) ?? shown[0]
  const assetTotal = overview.summary.assets
  const missing = groups.find((group) => group.metadataMissing)?.assets ?? 0
  const groupCount = groups.filter((group) => !group.metadataMissing).length
  const labelFor = (group: MapGroup) => group.metadataMissing ? DIMENSIONS[dimension].missing : dimension === 'type' ? displayType(group.label) : group.label
  const selectGroup = (key: string) => setSelection({ dimension, key })
  const selectDimension = (next: MapDimension) => {
    setDimension(next)
    setSelection(null)
    setPaging({ dimension: next, page: 0 })
  }

  return (
    <>
      <div className="qe-map-grouping" role="group" aria-label="Group assets by">
        {(Object.entries(DIMENSIONS) as Array<[MapDimension, typeof DIMENSIONS[MapDimension]]>).map(([key, { label, icon: Icon }]) => (
          <button key={key} type="button" aria-pressed={dimension === key} onClick={() => selectDimension(key)}>
            <Icon size={17} aria-hidden="true" /><span>{label}</span>
            <span className="qe-map-group-count" aria-label="recorded groups">{number.format(overview.maps[key].filter((group) => !group.metadataMissing).length)}</span>
          </button>
        ))}
      </div>
      {assetTotal ? (
        <div className="qe-map-board">
          <section className="qe-map-groups" aria-label="Estate groups">
            <div className="qe-map-section-title">
              <div>
                <h3>Inventory by {DIMENSIONS[dimension].label.toLowerCase()}</h3>
                <p>{countLabel(groupCount, 'recorded group')} · {countLabel(assetTotal, 'asset')}{missing > 0 && ' · ' + number.format(missing) + ' missing this field'}</p>
              </div>
              <button type="button" className="qe-map-view-toggle" aria-pressed={tableView} onClick={() => setTableView((current) => !current)}>Table view</button>
            </div>
            {tableView ? (
              <div className="qe-map-table" tabIndex={0} role="region" aria-label="Group totals">
                <table>
                  <thead><tr><th scope="col">Group</th><th scope="col">Assets</th><th scope="col">Affected</th><th scope="col">Critical</th><th scope="col">Fix items</th></tr></thead>
                  <tbody>{shown.map((group) => (
                    <tr key={group.key} data-selected={selected?.key === group.key}>
                      <th scope="row"><button type="button" aria-pressed={selected?.key === group.key} onClick={() => selectGroup(group.key)}>{labelFor(group)}</button></th>
                      <td>{number.format(group.assets)}</td><td>{number.format(group.affectedAssets)}</td>
                      <td>{number.format(group.criticalAssets)}</td><td>{number.format(group.openFixes)}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            ) : <div className="qe-map-tiles">
              {shown.map((group) => {
                const Icon = DIMENSIONS[dimension].icon
                const status = groupStatus(group)
                return (
                  <button key={group.key} type="button" className="qe-map-tile" aria-pressed={selected?.key === group.key}
                    onClick={() => selectGroup(group.key)}>
                    <span className="qe-map-tile-top"><Icon aria-hidden="true" size={18} /><span className="qe-map-status" data-tone={status.tone}>{status.label}</span></span>
                    <strong>{labelFor(group)}</strong>
                    <span className="qe-map-tile-count">{countLabel(group.assets, 'asset')}<ArrowDownRight size={17} aria-hidden="true" /></span>
                    <span className="qe-map-meter" aria-hidden="true"><i data-tone={status.tone} style={{ width: (group.affectedAssets / group.assets) * 100 + '%' }} /></span>
                    <span className="qe-map-tile-caption">{number.format(group.affectedAssets)} with open fixes <span>{countLabel(group.openFixes, 'fix item')}</span></span>
                  </button>
                )
              })}
            </div>}
            <Pagination page={page} pages={pages} label="Groups" onPage={(next) => { setSelection(null); setPaging({ dimension, page: next }) }} />
          </section>
          {selected && <GroupInspector key={dimension + ':' + selected.key} dimension={dimension} group={selected} revision={overview.revision} onOpenAsset={onOpenAsset} />}
        </div>
      ) : <div className="qe-map-empty"><Server aria-hidden="true" /><h3>No asset records loaded</h3><p>The company map groups assets in your inventory.</p><DetailLink href="/dashboard/assets">Open asset inventory</DetailLink></div>}
    </>
  )
}

function AssetDetail({ asset }: { asset: MapAsset }) {
  return (
    <div className="space-y-3">
      <DetailSection title="Asset record">
        <DetailFacts items={[
          ['Owner', asset.owner ?? 'Not recorded'],
          ['Ownership source', asset.ownerSource ? OWNER_SOURCE_LABEL[asset.ownerSource] : 'Not recorded'],
          ['Business service', asset.service ?? 'Not recorded'],
          ['Environment', asset.environment ?? 'Not recorded'],
          ['Asset type', displayType(asset.type)],
          ['Inventory status', asset.status ? displayType(asset.status) : 'Not recorded'],
          ['Criticality', asset.criticality === 'unknown' ? 'Not recorded' : displayType(asset.criticality)],
        ]} />
      </DetailSection>
      <DetailSection title="Scan evidence and remediation">
        <DetailFacts items={[
          ['Recorded scan', asset.recordedScanAt ? date.format(new Date(asset.recordedScanAt)) : 'No scan timestamp recorded'],
          ['Latest crypto inventory evidence', asset.evidence.latestInventoryEvidenceAt ? date.format(new Date(asset.evidence.latestInventoryEvidenceAt)) : 'No inventory timestamp recorded'],
          ['Latest live migration job', asset.migrationStatus?.replaceAll('_', ' ') || 'No job recorded'],
          ['Classified evidence', number.format(asset.evidence.classified)],
          ['Unclassified evidence', number.format(asset.evidence.unclassified)],
          ['Open fix items', number.format(asset.openFixes)],
          ['Validated fix items', number.format(asset.validatedFixes)],
        ]} />
      </DetailSection>
    </div>
  )
}

export function EstateMap({ overview, level, focus, onNavigate, onPlanCampaign }: {
  overview: EstateOverview
  level: MapLevel
  focus: string | null
  onNavigate: (level: MapLevel, target?: string) => void
  onPlanCampaign: (fixId: string) => void
}) {
  const [dimension, setDimension] = useState<MapDimension>('owner')
  const { data, state, error, refreshing, refresh } = useEstateGraph(level === 'estate' ? null : level, level === 'neighbourhood' ? focus : null, overview.revision)
  const assets = useMemo(() => new Map(data?.assets.map((asset) => [asset.id, asset])), [data])
  const fixById = useMemo(() => new Map(overview.clusters.map((fix) => [fix.id, fix])), [overview.clusters])
  const focusNode = level === 'neighbourhood' ? data?.graph.nodes.find((node) => node.id === focus) : null
  const openAsset = (id: string) => onNavigate('neighbourhood', 'asset:' + id)
  const renderNodeDetail = (node: WorkflowNode, context: DetailContext) => {
    const fixId = node.kind === 'fix' ? node.id.slice(4) : null
    const fix = fixId ? fixById.get(fixId) : null
    const asset = node.entity?.type === 'asset' ? assets.get(node.entity.id) : null
    return (
      <div className="space-y-3">
        {asset && <AssetDetail asset={asset} />}
        {fix && (
          <DetailSection title="Remediation scope">
            <DetailFacts items={[
              ['Assets with this fix open', number.format(fix.assets - fix.progress.validated) + ' of ' + number.format(fix.assets)],
              ['Validated assets', number.format(fix.progress.validated)],
              ['Priority', '#' + fix.priorityRank + ' (' + fix.priority + '/100)'],
              ['Deadline', fix.deadline.label],
              ['Estimated effort', fix.effort.days + ' engineer-days'],
              ['Replacement', fix.target ?? fix.targetNote ?? 'Review required', true],
            ]} />
          </DetailSection>
        )}
        {!asset && !fix && node.sublabel && <p className="text-[13px]">{node.sublabel}</p>}
        <div className="flex flex-wrap gap-2">
          {(fixId || asset) && (level !== 'neighbourhood' || focus !== node.id) && <DetailLink primary onClick={() => onNavigate('neighbourhood', node.id)}>Explore neighbourhood</DetailLink>}
          {fixId && <DetailLink onClick={() => onPlanCampaign(fixId)}>Plan campaign</DetailLink>}
          {asset && <DetailLink href={'/dashboard/assets?asset=' + encodeURIComponent(asset.id)}>Open asset record</DetailLink>}
        </div>
        <RelationshipList context={context} />
      </div>
    )
  }

  return (
    <div className="qe-map">
      <header className="qe-map-heading">
        <div className="qe-map-heading-copy">
          <span className="qe-map-emblem"><Network size={23} aria-hidden="true" /></span>
          <div><h2>Estate relationship map</h2><p>Explore asset ownership, remediation scope and recorded dependencies.</p></div>
        </div>
        <AssetSearch onOpen={openAsset} revision={overview.revision} />
      </header>
      <div className="qe-map-control-bar">
        <div className="qe-map-levels" role="group" aria-label="Map level">
          {LEVELS.map(({ key, label, icon: Icon }) => (
            <button key={key} type="button" aria-pressed={level === key} onClick={() => onNavigate(key)}><Icon size={16} aria-hidden="true" />{label}</button>
          ))}
        </div>
        <span className="qe-map-time"><Clock3 size={15} aria-hidden="true" />Snapshot <time dateTime={overview.generatedAt}>{date.format(new Date(overview.generatedAt))}</time></span>
      </div>

      {level === 'estate' ? <CompanyMap overview={overview} dimension={dimension} setDimension={setDimension} onOpenAsset={openAsset} />
        : level === 'neighbourhood' && !focus ? (
          <div className="qe-map-empty">
            <Network aria-hidden="true" /><h3>Choose an asset or a fix</h3>
            <p>Find an asset above, select an asset from a company group, or choose a fix in Root causes to see its connected records.</p>
            <div>
              <DetailLink primary onClick={() => onNavigate('estate')}>Browse company map</DetailLink>
              <DetailLink onClick={() => onNavigate('root-cause')}>Explore root causes</DetailLink>
            </div>
          </div>
        ) : (
          <section className="qe-map-graph" aria-label={level === 'root-cause' ? 'Remediation root causes' : 'Neighbourhood evidence'}>
            <div className="qe-map-graph-heading">
              <div>
                {level === 'neighbourhood' && <button type="button" className="qe-map-back" onClick={() => onNavigate(focus?.startsWith('fix:') ? 'root-cause' : 'estate')}><ArrowLeft aria-hidden="true" size={15} />{focus?.startsWith('fix:') ? 'Root causes' : 'Company map'}</button>}
                <h3>{level === 'root-cause' ? 'Root causes and fixes' : focusNode?.label ?? 'Asset or fix neighbourhood'}</h3>
                <p>{level === 'root-cause' ? 'Select a fix to review its scope or explore its neighbourhood.' : 'Select a node to inspect the evidence and connected records.'}</p>
              </div>
              {data && <span className="qe-map-time">{countLabel(data.graph.nodes.length, 'node')} · {countLabel(data.graph.edges.length, 'relationship')}</span>}
            </div>
            {data && data.revision !== overview.revision && <p className="qe-map-message" role="status">Graph snapshot as of {date.format(new Date(data.generatedAt))}{refreshing ? ' · Updating' : ''}</p>}
            {data && error && <p className="qe-map-message" role="status"><ShieldAlert size={15} aria-hidden="true" /> Showing the last available graph. <button type="button" onClick={() => void refresh()}>Retry</button></p>}
            <VendorTrustWorkflowCanvas key={level + ':' + (level === 'neighbourhood' ? focus : '')}
              graph={data?.graph ?? EMPTY_GRAPH}
              ariaLabel={level === 'root-cause' ? 'Root causes, fixes and owners' : 'Neighbourhood map'}
              searchPlaceholder={level === 'root-cause' ? 'Find a fix, cause, or owner…' : 'Find a connected record…'}
              status={state}
              error={error}
              onRetry={() => void refresh()}
              focusNodeId={focusNode?.id ?? null}
              empty={{ title: 'No remediation relationships recorded', detail: 'The current evidence does not contain a graph for this view.', cta: { label: 'Open asset inventory', href: '/dashboard/assets' } }}
              renderNodeDetail={renderNodeDetail}
              enableTrace
              autoCollapseAbove={14}
              height={590}
              exportName={level === 'root-cause' ? 'estate-root-causes' : 'estate-neighbourhood'}
            />
          </section>
        )}
    </div>
  )
}
