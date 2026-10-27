/**
 * Workflow graph model shared by the External Trust visualisations.
 *
 * A `WorkflowGraph` is a PRESENTATION projection of authoritative payloads —
 * the vendor register, the ecosystem map, the trust chains and the lab
 * experiments. Nothing here is fetched or persisted, and nothing here may
 * change a record: layout, grouping, isolation and path tracing all operate on
 * the projection only.
 *
 * Honesty rules carried into the picture:
 * • Every edge states its provenance. `inferred` edges render dashed and say so
 *   in the side panel, so a guessed relationship never looks like a stored one.
 * • `unknown` is never green. Status colour is always paired with a glyph and a
 *   word, so colour alone never carries meaning.
 */

/* ------------------------------------------------------------------ */
/* Status vocabulary                                                   */
/* ------------------------------------------------------------------ */

/**
 * verified  — green: measured good (PQC-ready, valid chain, measured pass)
 * hybrid    — blue: hybrid verified, or a pass derived from stored evidence
 * attention — amber: incomplete, migration required, expiring, weak
 * critical  — red: confirmed critical exposure / failure
 * unknown   — gray: unassessed, stale, not tested
 */
export type WorkflowStatus = 'verified' | 'hybrid' | 'attention' | 'critical' | 'unknown'

export const STATUS_META: Record<WorkflowStatus, { label: string; glyph: string; color: string }> = {
  verified: { label: 'Verified', glyph: '✓', color: '#16a34a' },
  hybrid: { label: 'Hybrid verified', glyph: '◐', color: '#2563eb' },
  attention: { label: 'Needs attention', glyph: '▲', color: '#d97706' },
  critical: { label: 'Critical exposure', glyph: '■', color: '#dc2626' },
  unknown: { label: 'Unknown / not assessed', glyph: '?', color: '#64748b' },
}

/** Severity order used for roll-ups: unknown ranks above the good states — unknown is not safe. */
const STATUS_RANK: Record<WorkflowStatus, number> = {
  verified: 0, hybrid: 1, unknown: 2, attention: 3, critical: 4,
}

export function worstStatus(statuses: WorkflowStatus[]): WorkflowStatus {
  return statuses.reduce<WorkflowStatus>(
    (worst, status) => (STATUS_RANK[status] > STATUS_RANK[worst] ? status : worst),
    statuses.length ? 'verified' : 'unknown',
  )
}

/* ------------------------------------------------------------------ */
/* Graph types                                                         */
/* ------------------------------------------------------------------ */

/** Icon keys resolved to Lucide components by the canvas (keeps this file UI-free). */
export type WorkflowIcon =
  | 'organization' | 'vendor' | 'application' | 'service' | 'infrastructure' | 'identity'
  | 'business' | 'surface' | 'algorithm' | 'certificate' | 'root-ca' | 'intermediate-ca'
  | 'anchor' | 'client' | 'handshake' | 'key-exchange' | 'kem' | 'signature' | 'secret'
  | 'kdf' | 'session' | 'cipher' | 'telemetry' | 'group' | 'chain'

/** Shape is the non-colour channel that separates node families. */
export type WorkflowShape = 'card' | 'pill' | 'shield' | 'document' | 'step' | 'stack'

export type EdgeProvenance = 'explicit' | 'observed' | 'inferred' | 'configured'

export const PROVENANCE_LABEL: Record<EdgeProvenance, string> = {
  explicit: 'Stored relationship',
  observed: 'Observed evidence',
  inferred: 'Inferred — not stored',
  configured: 'Protocol structure',
}

export interface WorkflowBadge {
  label: string
  status: WorkflowStatus
}

export interface WorkflowNode {
  id: string
  /** Domain kind key, e.g. `vendor`, `certificate`, `kem`. */
  kind: string
  kindLabel: string
  label: string
  sublabel?: string
  status: WorkflowStatus
  /** The word shown next to the status glyph — page-specific vocabulary. */
  statusLabel: string
  icon: WorkflowIcon
  shape: WorkflowShape
  /** Fixed column; omitted ⇒ longest-path rank. */
  layer?: number
  groupId?: string
  badges?: WorkflowBadge[]
  /** Short monospace facts (algorithm, protocol, counts). */
  meta?: string[]
  /** Initials for organisation/vendor nodes when no logo is available. */
  monogram?: string
  /** Data is older than its review window. */
  stale?: boolean
  /** The node itself is inferred rather than read from a record. */
  inferred?: boolean
  /** Stable entity reference used for cross-page navigation. */
  entity?: { type: 'vendor' | 'asset' | 'certificate' | 'ca' | 'anchor' | 'host' | 'algorithm' | 'step'; id: string }
  /** Lower-cased haystack used by "Find in map". */
  searchText: string
}

export interface WorkflowEdge {
  id: string
  source: string
  target: string
  /** Machine relation key, e.g. `consumes`, `issued`. */
  relation: string
  /** Human label, e.g. "Consumes", "Issued". */
  label: string
  provenance: EdgeProvenance
  status?: WorkflowStatus
  /** Why this edge exists — the record or rule that produced it. */
  basis: string
}

export interface WorkflowGroup {
  id: string
  label: string
  icon: WorkflowIcon
}

export interface WorkflowGraph {
  nodes: WorkflowNode[]
  edges: WorkflowEdge[]
  groups: WorkflowGroup[]
  /** Column titles indexed by layer. */
  lanes?: string[]
  /** Disclosed truncation, e.g. "Showing 40 of 112 vendors (highest risk first)". */
  notices: string[]
  /** Page-specific legend wording for each status colour. */
  legend: Partial<Record<WorkflowStatus, string>>
}

export function emptyGraph(): WorkflowGraph {
  return { nodes: [], edges: [], groups: [], notices: [], legend: {} }
}

/* ------------------------------------------------------------------ */
/* Group collapse                                                      */
/* ------------------------------------------------------------------ */

export const groupNodeId = (groupId: string) => `group:${groupId}`

/**
 * Replaces each collapsed group's members with a single aggregate node.
 *
 * The aggregate takes the WORST member status, so collapsing can never hide a
 * critical member behind a calmer colour. Edges are rewired and de-duplicated;
 * edges that become internal to the group are dropped.
 */
export function collapseGroups(graph: WorkflowGraph, collapsed: ReadonlySet<string>): WorkflowGraph {
  if (!collapsed.size) return graph
  const members = new Map<string, WorkflowNode[]>()
  for (const node of graph.nodes) {
    if (node.groupId && collapsed.has(node.groupId)) {
      const list = members.get(node.groupId) ?? []
      list.push(node)
      members.set(node.groupId, list)
    }
  }
  if (!members.size) return graph

  const remap = new Map<string, string>()
  const nodes: WorkflowNode[] = []
  for (const node of graph.nodes) {
    if (node.groupId && members.has(node.groupId)) {
      remap.set(node.id, groupNodeId(node.groupId))
      continue
    }
    nodes.push(node)
  }
  for (const [groupId, list] of members) {
    const group = graph.groups.find((candidate) => candidate.id === groupId)
    const status = worstStatus(list.map((node) => node.status))
    nodes.push({
      id: groupNodeId(groupId),
      kind: 'group',
      kindLabel: 'Collapsed group',
      label: group?.label ?? 'Group',
      sublabel: `${list.length} item${list.length === 1 ? '' : 's'} · click to expand`,
      status,
      statusLabel: list.length === 1 ? list[0].statusLabel : `Worst: ${STATUS_META[status].label}`,
      icon: group?.icon ?? 'group',
      shape: 'stack',
      layer: list[0].layer,
      groupId,
      meta: list.slice(0, 3).map((node) => node.label),
      searchText: list.map((node) => node.searchText).join(' '),
    })
  }

  const seen = new Set<string>()
  const edges: WorkflowEdge[] = []
  for (const edge of graph.edges) {
    const source = remap.get(edge.source) ?? edge.source
    const target = remap.get(edge.target) ?? edge.target
    if (source === target) continue
    const key = `${source}→${target}→${edge.relation}`
    if (seen.has(key)) continue
    seen.add(key)
    edges.push(source === edge.source && target === edge.target ? edge : { ...edge, id: key, source, target })
  }
  return { ...graph, nodes, edges }
}

/* ------------------------------------------------------------------ */
/* Traversal                                                           */
/* ------------------------------------------------------------------ */

export interface Adjacency {
  out: Map<string, WorkflowEdge[]>
  in: Map<string, WorkflowEdge[]>
}

export function buildAdjacency(edges: WorkflowEdge[]): Adjacency {
  const out = new Map<string, WorkflowEdge[]>()
  const inbound = new Map<string, WorkflowEdge[]>()
  for (const edge of edges) {
    out.set(edge.source, [...(out.get(edge.source) ?? []), edge])
    inbound.set(edge.target, [...(inbound.get(edge.target) ?? []), edge])
  }
  return { out, in: inbound }
}

export type Direction = 'upstream' | 'downstream' | 'both'

/**
 * Transitive neighbourhood of `start`. Upstream follows edges backwards,
 * downstream forwards. Cycle-safe.
 */
export function traverse(adjacency: Adjacency, start: string, direction: Direction): { nodeIds: Set<string>; edgeIds: Set<string> } {
  const nodeIds = new Set<string>([start])
  const edgeIds = new Set<string>()
  const walk = (dir: 'upstream' | 'downstream') => {
    const queue = [start]
    const visited = new Set<string>([start])
    while (queue.length) {
      const current = queue.shift()!
      const next = dir === 'downstream' ? adjacency.out.get(current) ?? [] : adjacency.in.get(current) ?? []
      for (const edge of next) {
        edgeIds.add(edge.id)
        const other = dir === 'downstream' ? edge.target : edge.source
        nodeIds.add(other)
        if (!visited.has(other)) {
          visited.add(other)
          queue.push(other)
        }
      }
    }
  }
  if (direction !== 'downstream') walk('upstream')
  if (direction !== 'upstream') walk('downstream')
  return { nodeIds, edgeIds }
}

export interface TracedPath {
  nodeIds: string[]
  edges: WorkflowEdge[]
  /** true when every hop follows its edge's direction. */
  directed: boolean
}

/**
 * Shortest known path between two nodes. A path that respects edge direction
 * is preferred; only when none exists is an undirected path returned, and it is
 * flagged so the explanation can say the relationship is not a trust flow.
 */
export function shortestPath(edges: WorkflowEdge[], from: string, to: string): TracedPath | null {
  if (from === to) return { nodeIds: [from], edges: [], directed: true }
  const attempt = (directed: boolean): TracedPath | null => {
    const neighbours = new Map<string, Array<{ edge: WorkflowEdge; next: string }>>()
    const add = (key: string, entry: { edge: WorkflowEdge; next: string }) =>
      neighbours.set(key, [...(neighbours.get(key) ?? []), entry])
    for (const edge of edges) {
      add(edge.source, { edge, next: edge.target })
      if (!directed) add(edge.target, { edge, next: edge.source })
    }
    const previous = new Map<string, { node: string; edge: WorkflowEdge }>()
    const visited = new Set([from])
    const queue = [from]
    while (queue.length) {
      const current = queue.shift()!
      if (current === to) break
      for (const { edge, next } of neighbours.get(current) ?? []) {
        if (visited.has(next)) continue
        visited.add(next)
        previous.set(next, { node: current, edge })
        queue.push(next)
      }
    }
    if (!previous.has(to)) return null
    const nodeIds = [to]
    const pathEdges: WorkflowEdge[] = []
    let cursor = to
    while (cursor !== from) {
      const step = previous.get(cursor)!
      pathEdges.unshift(step.edge)
      nodeIds.unshift(step.node)
      cursor = step.node
    }
    return { nodeIds, edges: pathEdges, directed }
  }
  return attempt(true) ?? attempt(false)
}

/* ------------------------------------------------------------------ */
/* Layered layout                                                      */
/* ------------------------------------------------------------------ */

export interface LayoutOptions {
  nodeWidth: number
  nodeHeight: number
  columnGap: number
  rowGap: number
}

export interface LayoutResult {
  positions: Map<string, { x: number; y: number }>
  /** x of each layer's column, for lane headers. */
  columns: Map<number, number>
  top: number
}

/**
 * Left-to-right layered layout (a small Sugiyama pass):
 *  1. rank — fixed `layer` when the builder set one, otherwise longest path
 *     from the sources (back edges of a cycle are ignored);
 *  2. order — connected components kept together, then four barycentre sweeps
 *     to reduce edge crossings;
 *  3. place — columns at fixed spacing, each column centred vertically.
 *
 * Pure and deterministic: the same graph always lays out the same way, so a
 * refresh that changes no data never shuffles the picture.
 */
export function layoutLayered(nodes: WorkflowNode[], edges: WorkflowEdge[], options: LayoutOptions): LayoutResult {
  const ids = new Set(nodes.map((node) => node.id))
  const usable = edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target) && edge.source !== edge.target)
  const adjacency = buildAdjacency(usable)

  /* 1 — rank */
  const rank = new Map<string, number>()
  const fixed = new Map(nodes.filter((node) => node.layer !== undefined).map((node) => [node.id, node.layer!]))
  const visiting = new Set<string>()
  const rankOf = (id: string): number => {
    if (fixed.has(id)) return fixed.get(id)!
    if (rank.has(id)) return rank.get(id)!
    if (visiting.has(id)) return 0
    visiting.add(id)
    const parents = adjacency.in.get(id) ?? []
    const value = parents.length ? Math.max(...parents.map((edge) => rankOf(edge.source) + 1)) : 0
    visiting.delete(id)
    rank.set(id, value)
    return value
  }
  for (const node of nodes) rank.set(node.id, rankOf(node.id))

  /* 2 — order */
  const component = new Map<string, number>()
  let componentIndex = 0
  for (const node of [...nodes].sort((a, b) => a.label.localeCompare(b.label))) {
    if (component.has(node.id)) continue
    const stack = [node.id]
    component.set(node.id, componentIndex)
    while (stack.length) {
      const current = stack.pop()!
      for (const edge of [...(adjacency.out.get(current) ?? []), ...(adjacency.in.get(current) ?? [])]) {
        const other = edge.source === current ? edge.target : edge.source
        if (!component.has(other)) {
          component.set(other, componentIndex)
          stack.push(other)
        }
      }
    }
    componentIndex += 1
  }

  const layers = new Map<number, string[]>()
  const byId = new Map(nodes.map((node) => [node.id, node]))
  for (const node of nodes) {
    const layer = rank.get(node.id)!
    layers.set(layer, [...(layers.get(layer) ?? []), node.id])
  }
  for (const list of layers.values()) {
    list.sort((a, b) => (component.get(a)! - component.get(b)!) || byId.get(a)!.label.localeCompare(byId.get(b)!.label))
  }

  const orderedLayers = [...layers.keys()].sort((a, b) => a - b)
  const indexOf = new Map<string, number>()
  const reindex = () => {
    for (const layer of orderedLayers) layers.get(layer)!.forEach((id, index) => indexOf.set(id, index))
  }
  reindex()
  const sweep = (downward: boolean) => {
    const sequence = downward ? orderedLayers.slice(1) : orderedLayers.slice(0, -1).reverse()
    for (const layer of sequence) {
      const list = layers.get(layer)!
      const score = new Map<string, number>()
      for (const id of list) {
        const neighbours = downward
          ? (adjacency.in.get(id) ?? []).map((edge) => edge.source)
          : (adjacency.out.get(id) ?? []).map((edge) => edge.target)
        const positions = neighbours.filter((other) => rank.get(other) !== layer).map((other) => indexOf.get(other) ?? 0)
        // Keep the component grouping dominant; barycentre orders within it.
        const base = component.get(id)! * 100000
        score.set(id, base + (positions.length ? positions.reduce((sum, value) => sum + value, 0) / positions.length : indexOf.get(id)!))
      }
      list.sort((a, b) => score.get(a)! - score.get(b)!)
      list.forEach((id, index) => indexOf.set(id, index))
    }
  }
  for (let pass = 0; pass < 4; pass += 1) sweep(pass % 2 === 0)

  /* 3 — place */
  const rowSpan = options.nodeHeight + options.rowGap
  const tallest = Math.max(1, ...orderedLayers.map((layer) => layers.get(layer)!.length))
  const positions = new Map<string, { x: number; y: number }>()
  const columns = new Map<number, number>()
  orderedLayers.forEach((layer, columnIndex) => {
    const list = layers.get(layer)!
    const x = columnIndex * (options.nodeWidth + options.columnGap)
    columns.set(layer, x)
    const offset = ((tallest - list.length) * rowSpan) / 2
    list.forEach((id, index) => positions.set(id, { x, y: offset + index * rowSpan }))
  })
  return { positions, columns, top: 0 }
}

/* ------------------------------------------------------------------ */
/* Helpers for builders                                                */
/* ------------------------------------------------------------------ */

export function monogramOf(name: string): string {
  const words = name.replace(/[^A-Za-z0-9 ]+/g, ' ').trim().split(/\s+/).filter(Boolean)
  if (!words.length) return '?'
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase()
  return (words[0][0] + words[1][0]).toUpperCase()
}

export function searchTextOf(...parts: Array<string | null | undefined | string[]>): string {
  return parts.flat().filter(Boolean).join(' ').toLowerCase()
}
